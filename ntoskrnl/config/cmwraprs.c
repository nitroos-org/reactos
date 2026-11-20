/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/config/cmwraprs.c
 * PURPOSE:         Configuration Manager - Wrappers for Hive Operations
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include "ntoskrnl.h"
#define NDEBUG
#include "debug.h"

/* FUNCTIONS *****************************************************************/

NTSTATUS
NTAPI
CmpCreateEvent(IN EVENT_TYPE EventType,
               OUT PHANDLE EventHandle,
               OUT PKEVENT *Event)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;

    /* Create the event */
    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    Status = ZwCreateEvent(EventHandle,
                           EVENT_ALL_ACCESS,
                           &ObjectAttributes,
                           EventType,
                           FALSE);
    if (!NT_SUCCESS(Status)) return Status;

    /* Get a pointer to the object itself */
    Status = ObReferenceObjectByHandle(*EventHandle,
                                       EVENT_ALL_ACCESS,
                                       NULL,
                                       KernelMode,
                                       (PVOID*)Event,
                                       NULL);
    if (!NT_SUCCESS(Status)) ZwClose(*EventHandle);

    /* Return status */
    return Status;
}

PVOID
NTAPI
CmpAllocate(IN SIZE_T Size,
            IN BOOLEAN Paged,
            IN ULONG Tag)
{
    return ExAllocatePoolWithTag(Paged ? PagedPool : NonPagedPool,
                                 Size,
                                 Tag);
}

VOID
NTAPI
CmpFree(IN PVOID Ptr,
        IN ULONG Quota)
{
    ExFreePool(Ptr);
}

BOOLEAN
NTAPI
CmpFileRead(IN PHHIVE RegistryHive,
            IN ULONG FileType,
            IN PULONG FileOffset,
            OUT PVOID Buffer,
            IN SIZE_T BufferLength)
{
    PCMHIVE CmHive = (PCMHIVE)RegistryHive;
    HANDLE HiveHandle = CmHive->FileHandles[FileType];
    LARGE_INTEGER _FileOffset;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;

    /* Just return success if no file is associated with this hive */
    if (HiveHandle == NULL)
        return TRUE;

    _FileOffset.QuadPart = *FileOffset;
    Status = ZwReadFile(HiveHandle, NULL, NULL, NULL, &IoStatusBlock,
                        Buffer, (ULONG)BufferLength, &_FileOffset, NULL);
    /* We do synchronous I/O for simplicity - see CmpOpenHiveFiles. */
    ASSERT(Status != STATUS_PENDING);
    if (!NT_SUCCESS(Status))
        return FALSE;

    /* A read that returns fewer bytes than requested leaves the rest of the buffer unfilled */
    return (IoStatusBlock.Information == BufferLength);
}

BOOLEAN
NTAPI
CmpFileWrite(IN PHHIVE RegistryHive,
             IN ULONG FileType,
             IN PULONG FileOffset,
             IN PVOID Buffer,
             IN SIZE_T BufferLength)
{
    PCMHIVE CmHive = (PCMHIVE)RegistryHive;
    HANDLE HiveHandle = CmHive->FileHandles[FileType];
    LARGE_INTEGER _FileOffset;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;

    /* Just return success if no file is associated with this hive */
    if (HiveHandle == NULL)
        return TRUE;

    /* Don't do anything if we're not supposed to */
    if (CmpNoWrite)
        return TRUE;

    _FileOffset.QuadPart = *FileOffset;
    Status = ZwWriteFile(HiveHandle, NULL, NULL, NULL, &IoStatusBlock,
                         Buffer, (ULONG)BufferLength, &_FileOffset, NULL);
    /* We do synchronous I/O for simplicity - see CmpOpenHiveFiles.
     * Windows optimizes here by starting an async write for each 64k chunk,
     * then waiting for all writes to complete at once.
     */
    ASSERT(Status != STATUS_PENDING);
    return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN
NTAPI
CmpFileSetSize(
    _In_ PHHIVE RegistryHive,
    _In_ ULONG FileType,
    _In_ ULONG FileSize,
    _In_ ULONG OldFileSize)
{
    PCMHIVE CmHive = (PCMHIVE)RegistryHive;
    HANDLE HiveHandle = CmHive->FileHandles[FileType];
    FILE_END_OF_FILE_INFORMATION EndOfFileInfo;
    FILE_ALLOCATION_INFORMATION FileAllocationInfo;
    IO_STATUS_BLOCK IoStatusBlock;
    BOOLEAN HardErrors;
    NTSTATUS Status;

    /* Just return success if no file is associated with this hive */
    if (HiveHandle == NULL)
    {
        DPRINT1("No hive handle associated with the given hive\n");
        return TRUE;
    }

    /* Don't do anything if we're not supposed to */
    if (CmpNoWrite)
        return TRUE;

    /*
     * Disable hard errors so that we don't deadlock
     * when touching with the hive files.
     */
    HardErrors = IoSetThreadHardErrorMode(FALSE);

    EndOfFileInfo.EndOfFile.QuadPart = FileSize;
    Status = ZwSetInformationFile(HiveHandle,
                                  &IoStatusBlock,
                                  &EndOfFileInfo,
                                  sizeof(FILE_END_OF_FILE_INFORMATION),
                                  FileEndOfFileInformation);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ZwSetInformationFile failed to set new size of end of file (Status 0x%lx)\n", Status);
        IoSetThreadHardErrorMode(HardErrors);
        return FALSE;
    }

    FileAllocationInfo.AllocationSize.QuadPart = FileSize;
    Status = ZwSetInformationFile(HiveHandle,
                                  &IoStatusBlock,
                                  &FileAllocationInfo,
                                  sizeof(FILE_ALLOCATION_INFORMATION),
                                  FileAllocationInformation);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ZwSetInformationFile failed to set new of allocation file (Status 0x%lx)\n", Status);
        IoSetThreadHardErrorMode(HardErrors);
        return FALSE;
    }

    /* Reset the hard errors back */
    IoSetThreadHardErrorMode(HardErrors);
    return TRUE;
}

BOOLEAN
NTAPI
CmpFileFlush(IN PHHIVE RegistryHive,
             IN ULONG FileType,
             IN OUT PLARGE_INTEGER FileOffset,
             IN ULONG Length)
{
    PCMHIVE CmHive = (PCMHIVE)RegistryHive;
    HANDLE HiveHandle = CmHive->FileHandles[FileType];
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;

    /* Just return success if no file is associated with this hive */
    if (HiveHandle == NULL)
        return TRUE;

    /* Don't do anything if we're not supposed to */
    if (CmpNoWrite)
        return TRUE;

    Status = ZwFlushBuffersFile(HiveHandle, &IoStatusBlock);

    /* This operation is always synchronous. A failed flush need not fill the I/O status block. */
    ASSERT(Status != STATUS_PENDING);
    ASSERT(!NT_SUCCESS(Status) || Status == IoStatusBlock.Status);

    return NT_SUCCESS(Status) ? TRUE : FALSE;
}

/**
 * @brief
 * Overwrites with zeros and empties the log file of a hive that
 * is written without a log (the SYSTEM hive: its alternate file
 * mirrors it). Such a log was written when the hive was last
 * loaded with a log, by setup, and holds registry data of then.
 *
 * @param[in] HiveFileName
 * The full path of the hive file; the log is that path with ".LOG".
 *
 * @remarks
 * Called only once the hive file is known to be clean on disk: a log
 * is applied only to a hive whose last write was interrupted, and no
 * write of this hive goes through the log any more. An empty log is
 * refused by every reader. Best effort: a failure leaves the log as
 * it was, or partly zeroed, and is tried again at the next boot.
 */
VOID
NTAPI
CmpScrubUnusedHiveLog(
    _In_ PCUNICODE_STRING HiveFileName)
{
    static const UNICODE_STRING LogExtension = RTL_CONSTANT_STRING(L".LOG");
    UNICODE_STRING LogName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION Standard;
    FILE_END_OF_FILE_INFORMATION EndOfFile;
    FILE_ALLOCATION_INFORMATION Allocation;
    LARGE_INTEGER Offset;
    ULONG Length = 0;
    ULONGLONG Size;
    PVOID Zeros;
    HANDLE LogHandle;
    BOOLEAN HardErrors;
    NTSTATUS Status;
    PAGED_CODE();

    if (CmpNoWrite)
        return;

    LogName.Length = 0;
    LogName.MaximumLength = HiveFileName->Length + LogExtension.Length;
    LogName.Buffer = ExAllocatePoolWithTag(PagedPool, LogName.MaximumLength, TAG_CM);
    if (!LogName.Buffer)
        return;
    RtlCopyUnicodeString(&LogName, HiveFileName);
    RtlAppendUnicodeStringToString(&LogName, &LogExtension);

    InitializeObjectAttributes(&ObjectAttributes,
                               &LogName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    HardErrors = IoSetThreadHardErrorMode(FALSE);

    Status = ZwCreateFile(&LogHandle,
                          FILE_READ_ATTRIBUTES | FILE_WRITE_DATA | SYNCHRONIZE,
                          &ObjectAttributes,
                          &IoStatusBlock,
                          NULL,
                          0,
                          0,
                          FILE_OPEN,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE |
                          FILE_NO_INTERMEDIATE_BUFFERING,
                          NULL,
                          0);
    ExFreePoolWithTag(LogName.Buffer, TAG_CM);
    if (!NT_SUCCESS(Status))
    {
        /* No log: nothing to do */
        IoSetThreadHardErrorMode(HardErrors);
        return;
    }

    Status = ZwQueryInformationFile(LogHandle,
                                    &IoStatusBlock,
                                    &Standard,
                                    sizeof(Standard),
                                    FileStandardInformation);
    if (!NT_SUCCESS(Status) || Standard.EndOfFile.QuadPart == 0)
        goto Quit;

    Zeros = ExAllocatePoolWithTag(PagedPool, 16 * HBLOCK_SIZE, TAG_CM);
    if (!Zeros)
        goto Quit;
    RtlZeroMemory(Zeros, 16 * HBLOCK_SIZE);

    /* Whole sectors: the file is open without intermediate buffering */
    Size = ROUND_UP((ULONGLONG)Standard.EndOfFile.QuadPart, HSECTOR_SIZE);
    for (Offset.QuadPart = 0; (ULONGLONG)Offset.QuadPart < Size; Offset.QuadPart += Length)
    {
        Length = (ULONG)min(Size - Offset.QuadPart, 16 * HBLOCK_SIZE);
        Status = ZwWriteFile(LogHandle, NULL, NULL, NULL, &IoStatusBlock,
                             Zeros, Length, &Offset, NULL);
        if (!NT_SUCCESS(Status))
            break;
    }
    ExFreePoolWithTag(Zeros, TAG_CM);

    if (NT_SUCCESS(Status))
        Status = ZwFlushBuffersFile(LogHandle, &IoStatusBlock);

    /* The zeros are on the medium: now the file can be emptied */
    if (NT_SUCCESS(Status))
    {
        EndOfFile.EndOfFile.QuadPart = 0;
        Status = ZwSetInformationFile(LogHandle,
                                      &IoStatusBlock,
                                      &EndOfFile,
                                      sizeof(EndOfFile),
                                      FileEndOfFileInformation);
    }
    if (NT_SUCCESS(Status))
    {
        Allocation.AllocationSize.QuadPart = 0;
        Status = ZwSetInformationFile(LogHandle,
                                      &IoStatusBlock,
                                      &Allocation,
                                      sizeof(Allocation),
                                      FileAllocationInformation);
    }

    if (NT_SUCCESS(Status))
        DPRINT1("Overwrote and emptied the unused log of %wZ (%I64u bytes)\n", HiveFileName, Size);
    else
        DPRINT1("Failed to overwrite the unused log of %wZ (Status 0x%lx)\n", HiveFileName, Status);

Quit:
    ZwClose(LogHandle);
    IoSetThreadHardErrorMode(HardErrors);
}
