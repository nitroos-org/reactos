/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/file/copy.c
 * PURPOSE:         Copying files
 * PROGRAMMER:      Ariadne (ariadne@xs4all.nl)
 * UPDATE HISTORY:
 *                  01/11/98 Created
 *                  07/02/99 Moved to separate file
 */

/* INCLUDES ****************************************************************/

#include <k32.h>
#include "copystreams.h"
#define NDEBUG
#include <debug.h>

#if DBG
DEBUG_CHANNEL(kernel32file);
#endif

#ifndef FILE_NAMED_STREAMS
#define FILE_NAMED_STREAMS 0x00040000
#endif

/* FUNCTIONS ****************************************************************/


/* A stream is copied in chunks whose size grows with the stream (measured on Windows 10: 128 KB for streams up to
   512 KB, 256 KB up to 2 MB, 512 KB up to 8 MB, 1 MB above), and the progress routine is called after each one. */
static ULONG
BasepCopyChunkSize(
    ULONGLONG StreamSize)
{
    if (StreamSize <= 0x80000)
        return 0x20000;
    if (StreamSize <= 0x200000)
        return 0x40000;
    if (StreamSize <= 0x800000)
        return 0x80000;
    return 0x100000;
}

/* Streams up to this size are read through the file cache by BasepCopyFileExW, bigger ones without buffering */
#define BASEP_COPY_BUFFERED_MAX 0x400000

typedef struct _BASEP_COPY_STATE
{
    LPPROGRESS_ROUTINE ProgressRoutine;
    LPVOID Data;
    BOOL *Cancel;
    LARGE_INTEGER TotalSize;
    LARGE_INTEGER TotalTransferred;
    BOOL KeepDest;
} BASEP_COPY_STATE;

/* Calls the progress routine, if there is one, and turns its answer into a status */
static NTSTATUS
BasepCopyNotify(
    BASEP_COPY_STATE *State,
    LARGE_INTEGER StreamSize,
    LARGE_INTEGER StreamTransferred,
    DWORD StreamNumber,
    DWORD Reason,
    HANDLE Source,
    HANDLE Dest)
{
    DWORD ProgressResult;

    if (State->ProgressRoutine == NULL)
        return STATUS_SUCCESS;

    ProgressResult = State->ProgressRoutine(State->TotalSize,
                                            State->TotalTransferred,
                                            StreamSize,
                                            StreamTransferred,
                                            StreamNumber,
                                            Reason,
                                            Source,
                                            Dest,
                                            State->Data);
    switch (ProgressResult)
    {
        case PROGRESS_CANCEL:
            TRACE("Progress callback requested cancel\n");
            return STATUS_REQUEST_ABORTED;
        case PROGRESS_STOP:
            TRACE("Progress callback requested stop\n");
            State->KeepDest = TRUE;
            return STATUS_REQUEST_ABORTED;
        case PROGRESS_QUIET:
            State->ProgressRoutine = NULL;
            break;
        case PROGRESS_CONTINUE:
        default:
            break;
    }
    return STATUS_SUCCESS;
}

/* Copies one stream: a call of the progress routine for the switch to it, then one after each chunk */
static NTSTATUS
CopyLoop(
    BASEP_COPY_STATE *State,
    DWORD StreamNumber,
    HANDLE FileHandleSource,
    HANDLE FileHandleDest,
    LARGE_INTEGER StreamSize,
    UCHAR *lpBuffer,
    ULONG ChunkSize)
{
    NTSTATUS errCode;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER BytesCopied;

    BytesCopied.QuadPart = 0;
    errCode = BasepCopyNotify(State, StreamSize, BytesCopied, StreamNumber, CALLBACK_STREAM_SWITCH,
                              FileHandleSource, FileHandleDest);

    while (NT_SUCCESS(errCode))
    {
        if (State->Cancel != NULL && *State->Cancel)
        {
            TRACE("User requested cancel\n");
            errCode = STATUS_REQUEST_ABORTED;
            State->KeepDest = FALSE;
            break;
        }

        errCode = NtReadFile(FileHandleSource,
                             NULL,
                             NULL,
                             NULL,
                             &IoStatusBlock,
                             lpBuffer,
                             ChunkSize,
                             NULL,
                             NULL);
        /* With sync read, 0 length + status success mean EOF:
         * https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
         */
        if (NT_SUCCESS(errCode) && IoStatusBlock.Information == 0)
        {
            errCode = STATUS_END_OF_FILE;
        }
        if (!NT_SUCCESS(errCode))
        {
            if (STATUS_END_OF_FILE == errCode)
            {
                errCode = STATUS_SUCCESS;
            }
            else
            {
                WARN("Error 0x%08x reading from source\n", errCode);
            }
            break;
        }

        errCode = NtWriteFile(FileHandleDest,
                              NULL,
                              NULL,
                              NULL,
                              &IoStatusBlock,
                              lpBuffer,
                              IoStatusBlock.Information,
                              NULL,
                              NULL);
        if (!NT_SUCCESS(errCode))
        {
            WARN("Error 0x%08x reading writing to dest\n", errCode);
            break;
        }

        BytesCopied.QuadPart += IoStatusBlock.Information;
        State->TotalTransferred.QuadPart += IoStatusBlock.Information;
        errCode = BasepCopyNotify(State, StreamSize, BytesCopied, StreamNumber, CALLBACK_CHUNK_FINISHED,
                                  FileHandleSource, FileHandleDest);
    }

    return errCode;
}

/* Gives the new file the write time and the attributes of the source. The attributes come last: a read-only file
   takes no new stream, and the creation and access times of the copy are its own, as in Windows. */
static NTSTATUS
BasepCopySetBasicInformation(
    HANDLE FileHandle,
    const FILE_BASIC_INFORMATION *SourceBasic)
{
    NTSTATUS errCode;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_BASIC_INFORMATION FileBasic;

    RtlZeroMemory(&FileBasic, sizeof(FileBasic));
    FileBasic.LastWriteTime = SourceBasic->LastWriteTime;
    FileBasic.FileAttributes = SourceBasic->FileAttributes & FILE_ATTRIBUTE_VALID_SET_FLAGS;
    if (FileBasic.FileAttributes == 0)
        FileBasic.FileAttributes = FILE_ATTRIBUTE_NORMAL;

    errCode = NtSetInformationFile(FileHandle,
                                   &IoStatusBlock,
                                   &FileBasic,
                                   sizeof(FILE_BASIC_INFORMATION),
                                   FileBasicInformation);
    if (!NT_SUCCESS(errCode))
    {
        WARN("Error 0x%0x setting LastWriteTime\n", errCode);
    }

    return errCode;
}

/* Takes the name of the default stream off the end of a name: "file::$DATA" becomes "file" */
static VOID
BasepTrimDefaultStream(
    PWSTR FullPath)
{
    SIZE_T Length = wcslen(FullPath);

    if (Length > 7 && !_wcsicmp(FullPath + Length - 7, L"::$DATA"))
        FullPath[Length - 7] = UNICODE_NULL;
}

/* Whether the last part of a name is a named stream ("file:stream"); the name is without "::$DATA" */
static BOOL
BasepNameHasStream(
    PCWSTR FullPath)
{
    PCWSTR Leaf = wcsrchr(FullPath, L'\\');
    PCWSTR Colon;

    Leaf = Leaf ? Leaf + 1 : FullPath;
    Colon = wcschr(Leaf, L':');
    return Colon != NULL;
}

/* Whether the volume of the file keeps named streams. A volume that cannot tell is taken to keep none. */
static BOOL
BasepVolumeHasStreams(
    HANDLE FileHandle)
{
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_FS_ATTRIBUTE_INFORMATION *Info;
    UCHAR Buffer[sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 64 * sizeof(WCHAR)];
    NTSTATUS Status;

    Info = (FILE_FS_ATTRIBUTE_INFORMATION *)Buffer;
    Status = NtQueryVolumeInformationFile(FileHandle, &IoStatusBlock, Info, sizeof(Buffer),
                                          FileFsAttributeInformation);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
        return FALSE;

    return (Info->FileSystemAttributes & FILE_NAMED_STREAMS) != 0;
}

/* Whether the file has named streams. A file system that cannot list them has none to remove. */
static BOOL
BasepHasNamedStreams(
    HANDLE FileHandle)
{
    COPY2_STREAM *Streams = NULL;
    PVOID Buffer = NULL;
    ULONG Count = 0;

    if (!NT_SUCCESS(Copy2QueryNamedStreams(FileHandle, &Streams, &Count, &Buffer)))
        return FALSE;

    if (Streams)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Streams);
    if (Buffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    return Count != 0;
}

BOOL
BasepCopyFileExW(IN LPCWSTR lpExistingFileName,
                 IN LPCWSTR lpNewFileName,
                 IN LPPROGRESS_ROUTINE lpProgressRoutine OPTIONAL,
                 IN LPVOID lpData OPTIONAL,
                 IN LPBOOL pbCancel OPTIONAL,
                 IN DWORD dwCopyFlags,
                 IN DWORD dwBasepFlags,
                 OUT LPHANDLE lpExistingHandle,
                 OUT LPHANDLE lpNewHandle)
{
    NTSTATUS errCode;
    HANDLE FileHandleSource, FileHandleDest = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION FileStandard;
    FILE_BASIC_INFORMATION FileBasic;
    BASEP_COPY_STATE State;
    COPY2_STREAM *NamedStreams = NULL;
    PVOID StreamBuffer = NULL;
    PWSTR SourceFull = NULL, DestFull = NULL;
    UCHAR *lpBuffer = NULL;
    SIZE_T RegionSize = 0;
    ULONG NamedCount = 0, i, ChunkSize, MaxChunk;
    DWORD StreamError;
    BOOL RC = FALSE;
    BOOL DestIsStream, DestExisted, DestOnDisk, DestTouched, StreamFailed = FALSE;
    DWORD SystemError;

    RtlZeroMemory(&State, sizeof(State));
    State.ProgressRoutine = lpProgressRoutine;
    State.Data = lpData;
    State.Cancel = pbCancel;

    if (lpExistingFileName == NULL || lpNewFileName == NULL)
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        goto Quit;
    }

    /* The source is opened first: a name that is not there is reported before anything about the new one.
       It is read through the file cache (a file that was read or written recently is not read from the disk again, a
       tree copied twice reads its source once); a stream of more than BASEP_COPY_BUFFERED_MAX bytes is opened again
       without buffering below, so that a big file does not fill the cache. */
    FileHandleSource = CreateFileW(lpExistingFileName,
                                   GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL,
                                   OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,
                                   NULL);
    if (INVALID_HANDLE_VALUE == FileHandleSource)
    {
        WARN("Error %lu during opening of source file\n", GetLastError());
        goto Quit;
    }

    /* The names are made absolute once, for the names of the streams */
    StreamError = Copy2FullPath(lpExistingFileName, &SourceFull);
    if (StreamError == ERROR_SUCCESS)
        StreamError = Copy2FullPath(lpNewFileName, &DestFull);
    if (StreamError != ERROR_SUCCESS)
    {
        SetLastError(StreamError);
        goto CloseSource;
    }

    /* "file::$DATA" is the file; streams are named after "file" */
    BasepTrimDefaultStream(SourceFull);
    BasepTrimDefaultStream(DestFull);

    /* Windows copies a file, not one of its streams: a stream is no source, and no destination for a file that has
       streams of its own */
    DestIsStream = BasepNameHasStream(DestFull);
    if (BasepNameHasStream(SourceFull))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        goto CloseSource;
    }

    errCode = NtQueryInformationFile(FileHandleSource,
                                     &IoStatusBlock,
                                     &FileStandard,
                                     sizeof(FILE_STANDARD_INFORMATION),
                                     FileStandardInformation);
    if (!NT_SUCCESS(errCode))
    {
        TRACE("Status 0x%08x obtaining FileStandardInformation for source\n", errCode);
        BaseSetLastNTError(errCode);
        goto CloseSource;
    }

    if (FileStandard.EndOfFile.QuadPart > BASEP_COPY_BUFFERED_MAX)
    {
        /* Without buffering as before; if it cannot be opened that way the cached handle does the job */
        HANDLE Unbuffered = CreateFileW(lpExistingFileName,
                                        GENERIC_READ,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        NULL,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_NO_BUFFERING,
                                        NULL);
        if (Unbuffered != INVALID_HANDLE_VALUE)
        {
            errCode = NtQueryInformationFile(Unbuffered,
                                             &IoStatusBlock,
                                             &FileStandard,
                                             sizeof(FILE_STANDARD_INFORMATION),
                                             FileStandardInformation);
            if (NT_SUCCESS(errCode))
            {
                NtClose(FileHandleSource);
                FileHandleSource = Unbuffered;
            }
            else
            {
                NtClose(Unbuffered);
                errCode = NtQueryInformationFile(FileHandleSource,
                                                 &IoStatusBlock,
                                                 &FileStandard,
                                                 sizeof(FILE_STANDARD_INFORMATION),
                                                 FileStandardInformation);
            }
            if (!NT_SUCCESS(errCode))
            {
                BaseSetLastNTError(errCode);
                goto CloseSource;
            }
        }
    }

    errCode = NtQueryInformationFile(FileHandleSource,
                                     &IoStatusBlock,&FileBasic,
                                     sizeof(FILE_BASIC_INFORMATION),
                                     FileBasicInformation);
    if (!NT_SUCCESS(errCode))
    {
        TRACE("Status 0x%08x obtaining FileBasicInformation for source\n", errCode);
        BaseSetLastNTError(errCode);
        goto CloseSource;
    }

    /* The named streams of the source. A file system that cannot list them has none to copy. */
    errCode = Copy2QueryNamedStreams(FileHandleSource, &NamedStreams, &NamedCount, &StreamBuffer);
    if (errCode == STATUS_NO_MEMORY)
    {
        BaseSetLastNTError(errCode);
        goto CloseSource;
    }
    if (!NT_SUCCESS(errCode))
    {
        NamedCount = 0;
    }

    if (DestIsStream && NamedCount != 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        goto CloseSource;
    }

    /*
     * The new file is made with the attributes of the source but the read-only one, which is set at the end. A
     * file that is there is opened as it is and cut down only when it is known not to be the source (a copy of
     * a file onto itself, by whatever name, is a sharing violation and leaves it alone, as in Windows).
     */
    FileHandleDest = CreateFileW(lpNewFileName,
                                 GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_WRITE,
                                 NULL,
                                 (dwCopyFlags & COPY_FILE_FAIL_IF_EXISTS) ? CREATE_NEW : OPEN_ALWAYS,
                                 FileBasic.FileAttributes & ~FILE_ATTRIBUTE_READONLY,
                                 NULL);
    if (INVALID_HANDLE_VALUE == FileHandleDest)
    {
        WARN("Error %lu during opening of dest file\n", GetLastError());
        goto CloseSource;
    }

    DestExisted = (GetLastError() == ERROR_ALREADY_EXISTS);
    DestOnDisk = (GetFileType(FileHandleDest) == FILE_TYPE_DISK);
    DestTouched = !DestExisted;

    if (DestExisted && DestOnDisk)
    {
        FILE_BASIC_INFORMATION DestBasic;

        if (Copy2MaybeSameFile(FileHandleSource, FileHandleDest))
        {
            SetLastError(ERROR_SHARING_VIOLATION);
            goto CloseDest;
        }

        /* What CREATE_ALWAYS does with a file that is there: a hidden or system one has to be asked for as such */
        errCode = NtQueryInformationFile(FileHandleDest, &IoStatusBlock, &DestBasic, sizeof(DestBasic),
                                         FileBasicInformation);
        if (NT_SUCCESS(errCode) &&
            (DestBasic.FileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) & ~FileBasic.FileAttributes))
        {
            SetLastError(ERROR_ACCESS_DENIED);
            goto CloseDest;
        }

        DestTouched = TRUE;
        errCode = Copy2SetLength(FileHandleDest, 0);
        if (!NT_SUCCESS(errCode))
        {
            BaseSetLastNTError(errCode);
            goto CloseDest;
        }
    }
    if (!(dwCopyFlags & COPY_FILE_FAIL_IF_EXISTS) && DestExisted)
        SetLastError(ERROR_SUCCESS);

    /* Only a file on a disk is given streams, attributes and extended attributes (a copy to NUL is just data). A
       volume that cannot keep streams gets the file without them. A file that was overwritten has only the
       streams of its source. */
    if (!DestOnDisk || !BasepVolumeHasStreams(FileHandleDest))
    {
        NamedCount = 0;
    }
    else if (DestExisted && !DestIsStream && BasepHasNamedStreams(FileHandleDest))
    {
        StreamError = Copy2RemoveStreams(FileHandleDest, DestFull, NULL, 0);
        if (StreamError != ERROR_SUCCESS)
        {
            SetLastError(StreamError);
            goto CloseDest;
        }
    }

    /* The progress routine is told the size of all streams together */
    State.TotalSize.QuadPart = FileStandard.EndOfFile.QuadPart;
    MaxChunk = BasepCopyChunkSize(FileStandard.EndOfFile.QuadPart);
    for (i = 0; i < NamedCount; i++)
    {
        State.TotalSize.QuadPart += NamedStreams[i].Size;
        ChunkSize = BasepCopyChunkSize(NamedStreams[i].Size);
        if (ChunkSize > MaxChunk)
            MaxChunk = ChunkSize;
    }

    RegionSize = MaxChunk;
    errCode = NtAllocateVirtualMemory(NtCurrentProcess(),
                                      (PVOID *)&lpBuffer,
                                      0,
                                      &RegionSize,
                                      MEM_RESERVE | MEM_COMMIT,
                                      PAGE_READWRITE);
    if (!NT_SUCCESS(errCode))
    {
        TRACE("Error 0x%08x allocating buffer of %lu bytes\n", errCode, RegionSize);
        BaseSetLastNTError(errCode);
        goto CloseDest;
    }

    errCode = CopyLoop(&State, 1, FileHandleSource, FileHandleDest, FileStandard.EndOfFile, lpBuffer,
                       BasepCopyChunkSize(FileStandard.EndOfFile.QuadPart));

    for (i = 0; NT_SUCCESS(errCode) && i < NamedCount; i++)
    {
        HANDLE SourceStream, DestStream;
        LARGE_INTEGER StreamSize;

        DestStream = Copy2OpenStream(DestFull, NamedStreams[i].Name, GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_ALWAYS, FileHandleDest,
                                     0, &StreamError, NULL);
        if (DestStream == INVALID_HANDLE_VALUE)
        {
            StreamFailed = TRUE;
            break;
        }

        SourceStream = Copy2OpenStream(SourceFull, NamedStreams[i].Name, GENERIC_READ,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, FileHandleSource,
                                       0, &StreamError, NULL);
        if (SourceStream == INVALID_HANDLE_VALUE)
        {
            StreamFailed = TRUE;
            NtClose(DestStream);
            break;
        }

        errCode = Copy2SetLength(DestStream, 0);
        if (NT_SUCCESS(errCode))
        {
            StreamSize.QuadPart = NamedStreams[i].Size;
            errCode = CopyLoop(&State, i + 2, SourceStream, DestStream, StreamSize, lpBuffer,
                               BasepCopyChunkSize(NamedStreams[i].Size));
        }
        NtClose(SourceStream);
        NtClose(DestStream);
    }

    if (StreamFailed)
    {
        SetLastError(StreamError);
    }
    else if (!NT_SUCCESS(errCode))
    {
        BaseSetLastNTError(errCode);
    }
    else if (!DestOnDisk)
    {
        RC = TRUE;
    }
    else
    {
        Copy2CopyEas(FileHandleSource, FileHandleDest);

        errCode = BasepCopySetBasicInformation(FileHandleDest, &FileBasic);
        if (!NT_SUCCESS(errCode))
        {
            BaseSetLastNTError(errCode);
        }
        else
        {
            RC = TRUE;
        }
    }

    NtFreeVirtualMemory(NtCurrentProcess(),
                        (PVOID *)&lpBuffer,
                        &RegionSize,
                        MEM_RELEASE);

CloseDest:
    NtClose(FileHandleDest);
    if (! RC && ! State.KeepDest && DestTouched)
    {
        SystemError = GetLastError();
        SetFileAttributesW(lpNewFileName, FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(lpNewFileName);
        SetLastError(SystemError);
    }

CloseSource:
    NtClose(FileHandleSource);

Quit:
    if (NamedStreams)
        RtlFreeHeap(RtlGetProcessHeap(), 0, NamedStreams);
    if (StreamBuffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, StreamBuffer);
    if (SourceFull)
        RtlFreeHeap(RtlGetProcessHeap(), 0, SourceFull);
    if (DestFull)
        RtlFreeHeap(RtlGetProcessHeap(), 0, DestFull);

    return RC;
}

/*
 * @implemented
 */
BOOL
WINAPI
CopyFileExW(IN LPCWSTR lpExistingFileName,
            IN LPCWSTR lpNewFileName,
            IN LPPROGRESS_ROUTINE lpProgressRoutine OPTIONAL,
            IN LPVOID lpData OPTIONAL,
            IN LPBOOL pbCancel OPTIONAL,
            IN DWORD dwCopyFlags)
{
    BOOL Ret;
    HANDLE ExistingHandle, NewHandle;

    ExistingHandle = INVALID_HANDLE_VALUE;
    NewHandle = INVALID_HANDLE_VALUE;

    _SEH2_TRY
    {
        Ret = BasepCopyFileExW(lpExistingFileName,
                               lpNewFileName,
                               lpProgressRoutine,
                               lpData,
                               pbCancel,
                               dwCopyFlags,
                               0,
                               &ExistingHandle,
                               &NewHandle);
    }
    _SEH2_FINALLY
    {
        if (ExistingHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(ExistingHandle);
        }

        if (NewHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(NewHandle);
        }
    }
    _SEH2_END;

    return Ret;
}

/*
 * @implemented
 */
BOOL
WINAPI
CopyFileW(IN LPCWSTR lpExistingFileName,
          IN LPCWSTR lpNewFileName,
          IN BOOL bFailIfExists)
{
    return CopyFileExW(lpExistingFileName,
                       lpNewFileName,
                       NULL,
                       NULL,
                       NULL,
                       (bFailIfExists ? COPY_FILE_FAIL_IF_EXISTS : 0));
}


/*
 * @implemented
 */
BOOL
WINAPI
PrivCopyFileExW(IN LPCWSTR lpExistingFileName,
                IN LPCWSTR lpNewFileName,
                IN LPPROGRESS_ROUTINE lpProgressRoutine,
                IN LPVOID lpData,
                IN LPBOOL pbCancel,
                IN DWORD dwCopyFlags)
{
    BOOL Ret;
    HANDLE ExistingHandle, NewHandle;

    ExistingHandle = INVALID_HANDLE_VALUE;
    NewHandle = INVALID_HANDLE_VALUE;

    /* Check for incompatible flags */
    if (dwCopyFlags & COPY_FILE_FAIL_IF_EXISTS && dwCopyFlags & BASEP_COPY_REPLACE)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    _SEH2_TRY
    {
        Ret = BasepCopyFileExW(lpExistingFileName,
                               lpNewFileName,
                               lpProgressRoutine,
                               lpData,
                               pbCancel,
                               dwCopyFlags & BASEP_COPY_PUBLIC_MASK,
                               dwCopyFlags & BASEP_COPY_BASEP_MASK,
                               &ExistingHandle,
                               &NewHandle);
    }
    _SEH2_FINALLY
    {
        if (ExistingHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(ExistingHandle);
        }

        if (NewHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(NewHandle);
        }
    }
    _SEH2_END;

    return Ret;
}

/* EOF */
