/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetDiskSpaceInformationA and GetDiskSpaceInformationW (Windows 10 1809 and later)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86, an NTFS volume). The result is an HRESULT. The path names a directory of the
 * volume (a drive root, a directory, "C:" for the current directory of the drive, "\" or "."); a NULL path is the
 * current directory. A failure sets the last error to the Win32 code and returns the NTSTATUS as an HRESULT with the
 * facility bit (0xD0000103 for a file: ERROR_DIRECTORY). A path that does not resolve (an empty one, or a name of 260
 * characters or more in the ANSI function) is HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) with that error. A missing name is
 * reported as ERROR_PATH_NOT_FOUND, never as ERROR_FILE_NOT_FOUND (0xD0000034, error 3). A NULL result structure gives
 * 0xD000000D with the NTSTATUS itself as the last error. The structure is left alone on failure, and the last error
 * on success.
 *
 * The 13 fields are those of the volume query FileFsFullSizeInformationEx. The file systems of this system answer the
 * plain FileFsFullSizeInformation: the pool and reserve fields are zero, "used" is the total minus the available units,
 * and the "available committed" field is, as measured, the available units minus the total units, as an unsigned number.
 */

#include "k32_vista.h"

#define NDEBUG
#include <debug.h>

typedef struct _BASE_DISK_SPACE_INFORMATION
{
    ULONGLONG ActualTotalAllocationUnits;
    ULONGLONG ActualAvailableAllocationUnits;
    ULONGLONG ActualPoolUnavailableAllocationUnits;
    ULONGLONG CallerTotalAllocationUnits;
    ULONGLONG CallerAvailableAllocationUnits;
    ULONGLONG CallerPoolUnavailableAllocationUnits;
    ULONGLONG UsedAllocationUnits;
    ULONGLONG TotalReservedAllocationUnits;
    ULONGLONG VolumeStorageReserveAllocationUnits;
    ULONGLONG AvailableCommittedAllocationUnits;
    ULONGLONG PoolAvailableAllocationUnits;
    DWORD SectorsPerAllocationUnit;
    DWORD BytesPerSector;
} BASE_DISK_SPACE_INFORMATION, *PBASE_DISK_SPACE_INFORMATION;

#define BASEP_HRESULT_FROM_NT(Status) ((HRESULT)((Status) | 0x10000000))

static
HRESULT
BasepFailWin32(
    _In_ ULONG Error)
{
    SetLastError(Error);
    return HRESULT_FROM_WIN32(Error);
}

HRESULT
WINAPI
GetDiskSpaceInformationW(
    _In_opt_ LPCWSTR RootPath,
    _Out_ PBASE_DISK_SPACE_INFORMATION Information)
{
    UNICODE_STRING NtPath;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_FS_FULL_SIZE_INFORMATION Size;
    HANDLE Handle;
    NTSTATUS Status;
    ULONG Error;
    BOOLEAN Result;

    if (!Information)
    {
        SetLastError(STATUS_INVALID_PARAMETER);
        return BASEP_HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);
    }

    Result = RtlDosPathNameToNtPathName_U(RootPath ? RootPath : L".", &NtPath, NULL, NULL);
    if (!Result)
        return BasepFailWin32(ERROR_PATH_NOT_FOUND);

    InitializeObjectAttributes(&ObjectAttributes, &NtPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Handle,
                        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    RtlFreeHeap(RtlGetProcessHeap(), 0, NtPath.Buffer);

    if (NT_SUCCESS(Status))
    {
        Status = NtQueryVolumeInformationFile(Handle, &IoStatusBlock, &Size, sizeof(Size), FileFsFullSizeInformation);
        NtClose(Handle);
    }

    if (!NT_SUCCESS(Status))
    {
        Error = RtlNtStatusToDosError(Status);
        SetLastError(Error == ERROR_FILE_NOT_FOUND ? ERROR_PATH_NOT_FOUND : Error);
        return BASEP_HRESULT_FROM_NT(Status);
    }

    RtlZeroMemory(Information, sizeof(*Information));
    Information->ActualTotalAllocationUnits = Size.TotalAllocationUnits.QuadPart;
    Information->ActualAvailableAllocationUnits = Size.ActualAvailableAllocationUnits.QuadPart;
    Information->CallerTotalAllocationUnits = Size.TotalAllocationUnits.QuadPart;
    Information->CallerAvailableAllocationUnits = Size.CallerAvailableAllocationUnits.QuadPart;
    Information->UsedAllocationUnits = Size.TotalAllocationUnits.QuadPart - Size.ActualAvailableAllocationUnits.QuadPart;
    Information->AvailableCommittedAllocationUnits = Size.ActualAvailableAllocationUnits.QuadPart - Size.TotalAllocationUnits.QuadPart;
    Information->SectorsPerAllocationUnit = Size.SectorsPerAllocationUnit;
    Information->BytesPerSector = Size.BytesPerSector;
    return S_OK;
}

HRESULT
WINAPI
GetDiskSpaceInformationA(
    _In_opt_ LPCSTR RootPath,
    _Out_ PBASE_DISK_SPACE_INFORMATION Information)
{
    WCHAR Path[MAX_PATH];
    INT Length;

    if (!RootPath)
        return GetDiskSpaceInformationW(NULL, Information);

    Length = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, RootPath, -1, Path, MAX_PATH);
    if (!Length)
        return BasepFailWin32(ERROR_PATH_NOT_FOUND);

    return GetDiskSpaceInformationW(Path, Information);
}
