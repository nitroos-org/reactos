/*
 * PROJECT:     ReactOS Win32 Base API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SetFileInformationByHandle
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *              Information class mapping as in Wine's kernelbase/file.c
 */

#include "k32_vista.h"

#include <ndk/rtlfuncs.h>
#include <ndk/iofuncs.h>

#define NDEBUG
#include <debug.h>

static
NTSTATUS
SetFileRenameInfo(
    _In_ HANDLE hFile,
    _In_reads_bytes_(Size) PFILE_RENAME_INFO Info,
    _In_ DWORD Size)
{
    PFILE_RENAME_INFORMATION RenameInfo;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING NtName;
    BOOLEAN Converted;
    ULONG NameChars, MaxChars, InfoSize;
    NTSTATUS Status;

    if (Size < FIELD_OFFSET(FILE_RENAME_INFO, FileName) ||
        Info->FileNameLength > Size - FIELD_OFFSET(FILE_RENAME_INFO, FileName))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    /* Windows Server 2008 R2 and 10 refuse a root directory, take the name up to
     * its terminating NUL whatever FileNameLength says, and resolve every name but
     * a stream name (":name") or an NT path as a DOS path: a plain name is relative
     * to the current directory, not to the file's directory */
    if (Info->RootDirectory)
        return STATUS_INVALID_PARAMETER;

    /* A name without a NUL inside the buffer is refused rather than read past it */
    MaxChars = (Size - FIELD_OFFSET(FILE_RENAME_INFO, FileName)) / sizeof(WCHAR);
    for (NameChars = 0; NameChars < MaxChars && Info->FileName[NameChars]; NameChars++);
    if (NameChars == 0 || NameChars == MaxChars || NameChars > MAXUSHORT / sizeof(WCHAR))
        return STATUS_OBJECT_NAME_INVALID;

    /* RtlDosPathNameToNtPathName_U takes "\??\" for a rooted DOS path */
    Converted = !(Info->FileName[0] == L':' ||
                  (NameChars >= 4 && Info->FileName[0] == L'\\' && Info->FileName[1] == L'?' &&
                   Info->FileName[2] == L'?' && Info->FileName[3] == L'\\'));
    if (Converted)
    {
        Status = RtlDosPathNameToNtPathName_U_WithStatus(Info->FileName, &NtName, NULL, NULL);
        if (!NT_SUCCESS(Status))
            return Status;
    }
    else
    {
        NtName.Buffer = Info->FileName;
        NtName.Length = (USHORT)(NameChars * sizeof(WCHAR));
    }

    /* The I/O manager wants at least the whole structure, also for the 1-character ":" */
    InfoSize = max(sizeof(FILE_RENAME_INFORMATION), FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) + NtName.Length);
    RenameInfo = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, InfoSize);
    if (RenameInfo)
    {
        RenameInfo->ReplaceIfExists = Info->ReplaceIfExists;
        RenameInfo->RootDirectory = NULL;
        RenameInfo->FileNameLength = NtName.Length;
        RtlCopyMemory(RenameInfo->FileName, NtName.Buffer, NtName.Length);

        Status = NtSetInformationFile(hFile, &IoStatusBlock, RenameInfo, InfoSize, FileRenameInformation);
        RtlFreeHeap(RtlGetProcessHeap(), 0, RenameInfo);
    }
    else
    {
        Status = STATUS_NO_MEMORY;
    }

    if (Converted)
        RtlFreeUnicodeString(&NtName);
    return Status;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetFileInformationByHandle(
    _In_ HANDLE hFile,
    _In_ FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    _In_reads_bytes_(dwBufferSize) LPVOID lpFileInformation,
    _In_ DWORD dwBufferSize)
{
    FILE_INFORMATION_CLASS NtClass;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;

    switch (FileInformationClass)
    {
        case FileBasicInfo:
            NtClass = FileBasicInformation;
            break;

        case FileDispositionInfo:
            NtClass = FileDispositionInformation;
            break;

        case FileDispositionInfoEx:
            /* FILE_DISPOSITION_INFO_EX is the flags word of FileDispositionInformationEx (class 64) */
            NtClass = (FILE_INFORMATION_CLASS)64;
            break;

        case FileAllocationInfo:
            NtClass = FileAllocationInformation;
            break;

        case FileEndOfFileInfo:
            NtClass = FileEndOfFileInformation;
            break;

        case FileIoPriorityHintInfo:
            /* The hint is advisory: a valid one succeeds when the I/O manager has no such class */
            if (dwBufferSize < sizeof(FILE_IO_PRIORITY_HINT_INFO))
            {
                SetLastError(ERROR_BAD_LENGTH);
                return FALSE;
            }
            if ((ULONG)((FILE_IO_PRIORITY_HINT_INFO *)lpFileInformation)->PriorityHint >= MaximumIoPriorityHintType)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            NtClass = FileIoPriorityHintInformation;
            break;

        case FileRenameInfo:
            Status = SetFileRenameInfo(hFile, lpFileInformation, dwBufferSize);
            goto Done;

        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
    }

    Status = NtSetInformationFile(hFile, &IoStatusBlock, lpFileInformation, dwBufferSize, NtClass);
    if (FileInformationClass == FileDispositionInfoEx && dwBufferSize >= sizeof(ULONG) &&
        (Status == STATUS_INVALID_INFO_CLASS || Status == STATUS_INVALID_PARAMETER || Status == STATUS_NOT_SUPPORTED ||
         Status == STATUS_NOT_IMPLEMENTED || Status == STATUS_INVALID_DEVICE_REQUEST) &&
        !(*(PULONG)lpFileInformation & ~0x7UL))
    {
        FILE_DISPOSITION_INFORMATION Disposition;

        /* A file system that does not know the class (FAT) gets the classic request, as DeleteFile does: the file goes
         * when the handle is closed */
        Disposition.DeleteFile = (*(PULONG)lpFileInformation & 1) != 0;
        Status = NtSetInformationFile(hFile, &IoStatusBlock, &Disposition, sizeof(Disposition), FileDispositionInformation);
    }
    if (Status == STATUS_INVALID_INFO_CLASS && FileInformationClass == FileIoPriorityHintInfo)
    {
        FILE_FS_DEVICE_INFORMATION DeviceInfo;

        /* The I/O manager checks the class before the handle: have it check for a file handle */
        Status = NtQueryVolumeInformationFile(hFile,
                                              &IoStatusBlock,
                                              &DeviceInfo,
                                              sizeof(DeviceInfo),
                                              FileFsDeviceInformation);
    }

Done:
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}
