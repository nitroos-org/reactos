/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CopyFile2, the Windows 8 file copy with a progress callback
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* INCLUDES *****************************************************************/

#include <k32.h>
#include "copystreams.h"

/* DEFINES ******************************************************************/

#ifndef COPY_FILE_COPY_SYMLINK
#define COPY_FILE_COPY_SYMLINK          0x00000800
#endif
#ifndef COPY_FILE_RESUME_FROM_PAUSE
#define COPY_FILE_RESUME_FROM_PAUSE     0x00004000
#endif
#ifndef MAXIMUM_REPARSE_DATA_BUFFER_SIZE
#define MAXIMUM_REPARSE_DATA_BUFFER_SIZE (16 * 1024)
#endif

#ifndef SE_CREATE_SYMBOLIC_LINK_PRIVILEGE
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE 35L
#endif

#define COPY2_CHUNK_SIZE        0x80000
#define COPY2_INVALID_FLAGS     0x80000000
#define COPY2_SHARE_ALL         (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define COPY2_NAME_CHARS        520

/* TYPES ********************************************************************/

typedef struct _COPY2_STATE
{
    PCOPYFILE2_PROGRESS_ROUTINE Progress;
    PVOID Context;
    BOOL *Cancel;
    ULARGE_INTEGER TotalSize;
    ULARGE_INTEGER TotalTransferred;
    BOOL Quiet;
    BOOL KeepDest;
    BOOL Resume;
} COPY2_STATE;

/* What tells one file from another: the volume and the file index; for a file that has no index (an empty one on
   FAT), the name the file system reports instead. Times are not used: they can be set by anyone at any time. */
typedef struct _COPY2_ID
{
    BOOL Valid;
    DWORD Volume;
    ULONGLONG Index;
    BOOL HasDevice;
    WCHAR Device[160];                  /* "\\Device\\HarddiskVolume2": two volumes can have the same serial number */
    BOOL HasName;
    WCHAR Name[COPY2_NAME_CHARS];       /* upper case */
    WCHAR Alias[16];                    /* the 8.3 name of the leaf, upper case, if there is one */
} COPY2_ID;

typedef enum _COPY2_SAME
{
    Copy2Different,
    Copy2Same,
    Copy2Unknown
} COPY2_SAME;

/* HELPERS ******************************************************************/

static HRESULT
Copy2Hresult(
    _In_ NTSTATUS Status)
{
    return HRESULT_FROM_WIN32(RtlNtStatusToDosError(Status));
}

static BOOL
Copy2Cancelled(
    _In_ COPY2_STATE *State)
{
    return State->Cancel && *State->Cancel;
}

/*
 * Sends a message and gives S_OK, or what ends the copy. The cancel flag is looked at after every message, also
 * after the last one. Final is for a message after the copy has failed: its answer changes nothing, except that
 * a cancel flag set in it still takes the new file.
 */
static HRESULT
Copy2Notify(
    _Inout_ COPY2_STATE *State,
    _In_ const COPYFILE2_MESSAGE *Message,
    _In_ DWORD Stream,
    _In_ BOOL Final)
{
    COPYFILE2_MESSAGE_ACTION Action = COPYFILE2_PROGRESS_CONTINUE;
    HRESULT Result = S_OK;

    if (State->Progress && !State->Quiet)
        Action = State->Progress(Message, State->Context);

    if (Final)
    {
        if (Copy2Cancelled(State))
            State->KeepDest = FALSE;
        return S_OK;
    }

    switch (Action)
    {
        case COPYFILE2_PROGRESS_QUIET:
            State->Quiet = TRUE;
            break;
        case COPYFILE2_PROGRESS_CANCEL:
            Result = HRESULT_FROM_WIN32(ERROR_REQUEST_ABORTED);
            break;
        case COPYFILE2_PROGRESS_STOP:
            /* Windows 10 keeps the new file only for a stop at the start or the end of the first stream */
            Result = HRESULT_FROM_WIN32(ERROR_REQUEST_ABORTED);
            State->KeepDest = (Stream == 1 && (Message->Type == COPYFILE2_CALLBACK_STREAM_STARTED ||
                                               Message->Type == COPYFILE2_CALLBACK_STREAM_FINISHED));
            break;
        case COPYFILE2_PROGRESS_PAUSE:
            /* Once all data is copied there is nothing left to pause */
            if (State->TotalTransferred.QuadPart < State->TotalSize.QuadPart)
            {
                Result = HRESULT_FROM_WIN32(ERROR_REQUEST_PAUSED);
                State->KeepDest = TRUE;
            }
            break;
        default:
            break;
    }

    /* The cancel flag wins over the answer and takes the new file; a pause is still reported as one */
    if (Copy2Cancelled(State))
    {
        if (Result != HRESULT_FROM_WIN32(ERROR_REQUEST_PAUSED))
            Result = HRESULT_FROM_WIN32(ERROR_REQUEST_ABORTED);
        State->KeepDest = FALSE;
    }

    return Result;
}

static VOID
Copy2NotifyError(
    _Inout_ COPY2_STATE *State,
    _In_ COPYFILE2_COPY_PHASE Phase,
    _In_ DWORD Stream,
    _In_ HRESULT Failure,
    _In_ ULONGLONG Chunk,
    _In_ ULONGLONG StreamSize,
    _In_ ULONGLONG StreamTransferred)
{
    COPYFILE2_MESSAGE Message;

    RtlZeroMemory(&Message, sizeof(Message));
    Message.Type = COPYFILE2_CALLBACK_ERROR;
    Message.Info.Error.CopyPhase = Phase;
    Message.Info.Error.dwStreamNumber = Stream;
    Message.Info.Error.hrFailure = Failure;
    Message.Info.Error.uliChunkNumber.QuadPart = Chunk;
    Message.Info.Error.uliStreamSize.QuadPart = StreamSize;
    Message.Info.Error.uliStreamBytesTransferred.QuadPart = StreamTransferred;
    Message.Info.Error.uliTotalFileSize = State->TotalSize;
    Message.Info.Error.uliTotalBytesTransferred = State->TotalTransferred;
    Copy2Notify(State, &Message, Stream, TRUE);
}

NTSTATUS
Copy2SetLength(
    _In_ HANDLE File,
    _In_ ULONGLONG Length)
{
    FILE_END_OF_FILE_INFORMATION EndOfFile;
    IO_STATUS_BLOCK IoStatusBlock;

    EndOfFile.EndOfFile.QuadPart = Length;
    return NtSetInformationFile(File, &IoStatusBlock, &EndOfFile, sizeof(EndOfFile), FileEndOfFileInformation);
}

NTSTATUS
Copy2DeleteByHandle(
    _In_ HANDLE File)
{
    FILE_DISPOSITION_INFORMATION Disposition;
    IO_STATUS_BLOCK IoStatusBlock;

    Disposition.DeleteFile = TRUE;
    return NtSetInformationFile(File, &IoStatusBlock, &Disposition, sizeof(Disposition), FileDispositionInformation);
}

/* FILE IDENTITY ************************************************************/

static VOID
Copy2UpperName(
    _Out_writes_(Count) PWSTR To,
    _In_ ULONG Count,
    _In_ const WCHAR *From,
    _In_ ULONG Length)
{
    ULONG i;

    if (Length > Count - 1)
        Length = Count - 1;
    for (i = 0; i < Length; i++)
        To[i] = RtlUpcaseUnicodeChar(From[i]);
    To[Length] = UNICODE_NULL;
}

/*
 * The device part of the name of the open file, which tells two mounted volumes apart whatever their serial numbers.
 * The name is read whole, however long the path is. FALSE when the device cannot be found: a file with no known
 * device is never told apart from another by its volume serial number and index alone, as volumes cloned from one
 * another have both.
 */
static BOOL
Copy2ReadDevice(
    _In_ HANDLE File,
    _Inout_ COPY2_ID *Id)
{
    OBJECT_NAME_INFORMATION *Name = NULL;
    ULONG Size = sizeof(*Name) + COPY2_NAME_CHARS * sizeof(WCHAR), Needed = 0, Length, Slashes = 0, i;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
    BOOL Found = FALSE;
    int Tries;

    for (Tries = 0; Tries < 4; Tries++)
    {
        Name = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
        if (!Name)
            return FALSE;

        Status = NtQueryObject(File, ObjectNameInformation, Name, Size, &Needed);
        if (NT_SUCCESS(Status))
            break;

        RtlFreeHeap(RtlGetProcessHeap(), 0, Name);
        Name = NULL;
        if (Status != STATUS_INFO_LENGTH_MISMATCH && Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
            return FALSE;
        Size = (Needed > Size) ? Needed : Size * 2;
    }
    if (!Name)
        return FALSE;

    if (Name->Name.Buffer && Name->Name.Length >= 2 * sizeof(WCHAR))
    {
        /* "\Device\HarddiskVolume2\dir\file": up to the third backslash; a volume opened itself has two */
        Length = Name->Name.Length / sizeof(WCHAR);
        for (i = 0; i < Length; i++)
        {
            if (Name->Name.Buffer[i] == L'\\' && ++Slashes == 3)
                break;
        }
        if (Slashes >= 2 && Name->Name.Buffer[0] == L'\\' && i < ARRAYSIZE(Id->Device))
        {
            Copy2UpperName(Id->Device, ARRAYSIZE(Id->Device), Name->Name.Buffer, i);
            Id->HasDevice = TRUE;
            Found = TRUE;
        }
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, Name);
    return Found;
}

static VOID
Copy2ReadId(
    _In_ HANDLE File,
    _Out_ COPY2_ID *Id)
{
    BY_HANDLE_FILE_INFORMATION Info;
    UCHAR Buffer[sizeof(FILE_NAME_INFORMATION) + COPY2_NAME_CHARS * sizeof(WCHAR)];
    FILE_NAME_INFORMATION *Name = (FILE_NAME_INFORMATION *)Buffer;
    IO_STATUS_BLOCK IoStatusBlock;

    RtlZeroMemory(Id, sizeof(*Id));
    if (!GetFileInformationByHandle(File, &Info))
        return;

    Id->Valid = TRUE;
    Id->Volume = Info.dwVolumeSerialNumber;
    Id->Index = ((ULONGLONG)Info.nFileIndexHigh << 32) | Info.nFileIndexLow;
    if (!Copy2ReadDevice(File, Id))
    {
        /* An identity without its device decides nothing */
        Id->Valid = FALSE;
        return;
    }
    if (Id->Index)
        return;

    /* No index: the names have to tell */
    if (NT_SUCCESS(NtQueryInformationFile(File, &IoStatusBlock, Buffer, sizeof(Buffer) - sizeof(WCHAR), FileNameInformation)) &&
        Name->FileNameLength && Name->FileNameLength < sizeof(Id->Name))
    {
        Id->HasName = TRUE;
        Copy2UpperName(Id->Name, ARRAYSIZE(Id->Name), Name->FileName, Name->FileNameLength / sizeof(WCHAR));
    }

    if (NT_SUCCESS(NtQueryInformationFile(File, &IoStatusBlock, Buffer, sizeof(Buffer) - sizeof(WCHAR), FileAlternateNameInformation)) &&
        Name->FileNameLength && Name->FileNameLength < sizeof(Id->Alias))
    {
        Copy2UpperName(Id->Alias, ARRAYSIZE(Id->Alias), Name->FileName, Name->FileNameLength / sizeof(WCHAR));
    }
}

static BOOL
Copy2IdUnchanged(
    _In_ const COPY2_ID *First,
    _In_ const COPY2_ID *Second)
{
    return First->Valid && Second->Valid && First->Volume == Second->Volume && First->Index == Second->Index &&
           First->HasDevice == Second->HasDevice && (!First->HasDevice || !wcscmp(First->Device, Second->Device));
}

static const WCHAR *
Copy2Leaf(
    _In_ const WCHAR *Name)
{
    const WCHAR *Slash = wcsrchr(Name, L'\\');

    return Slash ? Slash + 1 : Name;
}

static COPY2_SAME
Copy2SameFile(
    _In_ const COPY2_ID *First,
    _In_ const COPY2_ID *Second)
{
    const WCHAR *LeafFirst, *LeafSecond;

    if (!First->Valid || !Second->Valid)
        return Copy2Unknown;
    if (!First->HasDevice || !Second->HasDevice)
        return Copy2Unknown;
    if (First->Volume != Second->Volume || wcscmp(First->Device, Second->Device))
        return Copy2Different;
    if (First->Index || Second->Index)
        return First->Index == Second->Index ? Copy2Same : Copy2Different;

    /* Two files without an index: the parent directory and the leaf, or its 8.3 form, decide */
    if (!First->HasName || !Second->HasName)
        return Copy2Unknown;

    LeafFirst = Copy2Leaf(First->Name);
    LeafSecond = Copy2Leaf(Second->Name);
    if ((LeafFirst - First->Name) != (LeafSecond - Second->Name) ||
        wcsncmp(First->Name, Second->Name, LeafFirst - First->Name))
    {
        return Copy2Different;
    }

    if (!wcscmp(LeafFirst, LeafSecond) ||
        (Second->Alias[0] && !wcscmp(LeafFirst, Second->Alias)) ||
        (First->Alias[0] && !wcscmp(LeafSecond, First->Alias)) ||
        (First->Alias[0] && !wcscmp(First->Alias, Second->Alias)))
    {
        return Copy2Same;
    }
    return Copy2Different;
}

/*
 * Whether two open files are the same file. The index of a FAT file changes when an empty file gets its first
 * cluster, so the first file is read before and after the second one and the answer is only taken from a round in
 * which it did not change.
 */
static COPY2_SAME
Copy2CompareHandles(
    _In_ HANDLE First,
    _In_ HANDLE Second)
{
    COPY2_ID IdFirst, IdSecond, IdAgain;
    int Tries;

    for (Tries = 0; Tries < 4; Tries++)
    {
        Copy2ReadId(First, &IdFirst);
        Copy2ReadId(Second, &IdSecond);
        Copy2ReadId(First, &IdAgain);
        if (Copy2IdUnchanged(&IdFirst, &IdAgain))
            return Copy2SameFile(&IdFirst, &IdSecond);
    }
    return Copy2Unknown;
}

/* Whether two open files are, or cannot be told from being, the same file */
BOOL
Copy2MaybeSameFile(
    _In_ HANDLE First,
    _In_ HANDLE Second)
{
    return Copy2CompareHandles(First, Second) != Copy2Different;
}

/* NAMES AND STREAMS ********************************************************/

/*
 * A name made absolute once, so that a callback that changes the current directory cannot move the copy or its
 * cleanup. An extended name is used as it is. *Path is a heap block; the result is a Win32 error.
 */
DWORD
Copy2FullPath(
    _In_ PCWSTR Name,
    _Out_ PWSTR *Path)
{
    ULONG Length, Result;
    PWSTR Buffer;
    int Tries;

    *Path = NULL;
    if (!Name[0])
        return ERROR_PATH_NOT_FOUND;

    if (Name[0] == L'\\' && Name[1] == L'\\' && (Name[2] == L'?' || Name[2] == L'.') && Name[3] == L'\\')
    {
        Length = wcslen(Name) + 1;
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length * sizeof(WCHAR));
        if (!Buffer)
            return ERROR_NOT_ENOUGH_MEMORY;
        RtlCopyMemory(Buffer, Name, Length * sizeof(WCHAR));
        *Path = Buffer;
        return ERROR_SUCCESS;
    }

    /* The current directory can change between the two calls, so the length is checked on each */
    Length = GetFullPathNameW(Name, 0, NULL, NULL);
    if (!Length)
        return GetLastError() ? GetLastError() : ERROR_INVALID_NAME;

    for (Tries = 0; Tries < 4; Tries++)
    {
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length * sizeof(WCHAR));
        if (!Buffer)
            return ERROR_NOT_ENOUGH_MEMORY;

        Result = GetFullPathNameW(Name, Length, Buffer, NULL);
        if (Result && Result < Length)
        {
            *Path = Buffer;
            return ERROR_SUCCESS;
        }

        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        if (!Result)
            return GetLastError() ? GetLastError() : ERROR_INVALID_NAME;
        Length = Result + 1;
    }

    return ERROR_INVALID_NAME;
}

static PWSTR
Copy2StreamPath(
    _In_ PCWSTR FileName,
    _In_opt_ PCWSTR StreamName)
{
    SIZE_T Length = wcslen(FileName) + (StreamName ? wcslen(StreamName) : 0) + 1;
    PWSTR Path = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length * sizeof(WCHAR));

    if (Path)
    {
        wcscpy(Path, FileName);
        if (StreamName)
            wcscat(Path, StreamName);
    }
    return Path;
}

/*
 * Lists the named data streams of a file (the unnamed one is not in the list). A file system that has no streams
 * gives an empty list; any other failure is returned.
 */
NTSTATUS
Copy2QueryNamedStreams(
    _In_ HANDLE File,
    _Out_ COPY2_STREAM **Streams,
    _Out_ PULONG Count,
    _Out_ PVOID *BufferToFree)
{
    FILE_STREAM_INFORMATION *Info;
    IO_STATUS_BLOCK IoStatusBlock;
    ULONG Size = 0x1000, Entries, Index = 0;
    PUCHAR Buffer, End;
    NTSTATUS Status;

    *Streams = NULL;
    *Count = 0;
    *BufferToFree = NULL;

    for (;;)
    {
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
        if (!Buffer)
            return STATUS_NO_MEMORY;

        Status = NtQueryInformationFile(File, &IoStatusBlock, Buffer, Size, FileStreamInformation);
        if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
            break;

        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        Size *= 2;
        if (Size > 0x1000000)
            return Status;
    }

    if (!NT_SUCCESS(Status) || IoStatusBlock.Information < sizeof(FILE_STREAM_INFORMATION))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        switch (Status)
        {
            /* The file system does not know the information class */
            case STATUS_INVALID_PARAMETER:
            case STATUS_INVALID_INFO_CLASS:
            case STATUS_NOT_IMPLEMENTED:
            case STATUS_NOT_SUPPORTED:
            case STATUS_INVALID_DEVICE_REQUEST:
                return STATUS_SUCCESS;
            default:
                return NT_SUCCESS(Status) ? STATUS_SUCCESS : Status;
        }
    }

    End = Buffer + IoStatusBlock.Information;
    Entries = 1;
    for (Info = (FILE_STREAM_INFORMATION *)Buffer; Info->NextEntryOffset; Entries++)
    {
        Info = (FILE_STREAM_INFORMATION *)((PUCHAR)Info + Info->NextEntryOffset);
        if ((PUCHAR)Info + sizeof(*Info) > End)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
            return STATUS_INFO_LENGTH_MISMATCH;
        }
    }

    *Streams = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Entries * sizeof(COPY2_STREAM));
    if (!*Streams)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        return STATUS_NO_MEMORY;
    }

    for (Info = (FILE_STREAM_INFORMATION *)Buffer;;)
    {
        ULONG Chars = Info->StreamNameLength / sizeof(WCHAR);
        PWCHAR Name = Info->StreamName;

        if ((PUCHAR)Name + Info->StreamNameLength > End)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, *Streams);
            RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
            *Streams = NULL;
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        /* Names look like ":name:$DATA", and "::$DATA" is the unnamed stream */
        if (Chars > 7 && Name[0] == L':' && !_wcsnicmp(&Name[Chars - 6], L":$DATA", 6))
        {
            Name[Chars - 6] = UNICODE_NULL;
            (*Streams)[Index].Name = Name;
            (*Streams)[Index].Size = Info->StreamSize.QuadPart;
            (*Streams)[Index].Source = INVALID_HANDLE_VALUE;
            Index++;
        }

        if (!Info->NextEntryOffset)
            break;
        Info = (FILE_STREAM_INFORMATION *)((PUCHAR)Info + Info->NextEntryOffset);
    }

    *Count = Index;
    *BufferToFree = Buffer;
    return STATUS_SUCCESS;
}

/*
 * A stream of the file whose name is given, opened by name and checked to belong to the file that Owner is open
 * for: a name that points to another file by now is refused. A stream that this call made on another file is
 * deleted again (Access has to include DELETE for that).
 */
HANDLE
Copy2OpenStream(
    _In_ PCWSTR FileName,
    _In_ PCWSTR StreamName,
    _In_ DWORD Access,
    _In_ DWORD Share,
    _In_ DWORD Disposition,
    _In_ HANDLE Owner,
    _In_ DWORD Flags,
    _Out_ PDWORD Error,
    _Out_opt_ PBOOL Existed)
{
    PWSTR Path = Copy2StreamPath(FileName, StreamName);
    COPY2_ID OwnerId, StreamId;
    HANDLE Stream;
    BOOL Made;

    *Error = ERROR_SUCCESS;
    if (Existed)
        *Existed = FALSE;
    if (!Path)
    {
        *Error = ERROR_NOT_ENOUGH_MEMORY;
        return INVALID_HANDLE_VALUE;
    }

    Stream = CreateFileW(Path, Access, Share, NULL, Disposition, FILE_ATTRIBUTE_NORMAL | Flags, NULL);
    Made = (Stream != INVALID_HANDLE_VALUE && Disposition != OPEN_EXISTING && GetLastError() != ERROR_ALREADY_EXISTS);
    if (Existed && Stream != INVALID_HANDLE_VALUE)
        *Existed = !Made;
    RtlFreeHeap(RtlGetProcessHeap(), 0, Path);
    if (Stream == INVALID_HANDLE_VALUE)
    {
        *Error = GetLastError();
        return Stream;
    }

    Copy2ReadId(Owner, &OwnerId);
    Copy2ReadId(Stream, &StreamId);
    if (Copy2SameFile(&OwnerId, &StreamId) != Copy2Same)
    {
        if (Made && (Access & DELETE))
            Copy2DeleteByHandle(Stream);
        CloseHandle(Stream);
        *Error = ERROR_FILE_INVALID;
        return INVALID_HANDLE_VALUE;
    }

    return Stream;
}

/* Removes the named streams of the destination that an overwritten file had: Windows gives the copy only the
   streams of the source. Streams whose names are in Keep stay (a resumed copy goes on in them). The result is a
   Win32 error. */
DWORD
Copy2RemoveStreams(
    _In_ HANDLE Dest,
    _In_ PCWSTR DestName,
    _In_opt_ const COPY2_STREAM *Keep,
    _In_ ULONG KeepCount)
{
    COPY2_STREAM *Old;
    PVOID Buffer;
    ULONG Count, i, j;
    NTSTATUS Status;
    DWORD Error = ERROR_SUCCESS;

    Status = Copy2QueryNamedStreams(Dest, &Old, &Count, &Buffer);
    if (!NT_SUCCESS(Status))
        Error = RtlNtStatusToDosError(Status);

    for (i = 0; Error == ERROR_SUCCESS && i < Count; i++)
    {
        HANDLE Stream;

        for (j = 0; Keep && j < KeepCount; j++)
        {
            if (!_wcsicmp(Old[i].Name, Keep[j].Name))
                break;
        }
        if (Keep && j < KeepCount)
            continue;

        Stream = Copy2OpenStream(DestName, Old[i].Name, DELETE | FILE_READ_ATTRIBUTES, COPY2_SHARE_ALL,
                                 OPEN_EXISTING, Dest, 0, &Error, NULL);
        if (Stream == INVALID_HANDLE_VALUE)
            break;

        Status = Copy2DeleteByHandle(Stream);
        if (!NT_SUCCESS(Status))
            Error = RtlNtStatusToDosError(Status);
        CloseHandle(Stream);
    }

    if (Old)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Old);
    if (Buffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);

    /* A file system that takes the whole file with a stream (the ReactOS NTFS driver does) must not go unnoticed:
       the file has to be there still, under its name */
    if (Error == ERROR_SUCCESS && Count)
    {
        COPY2_ID Now, Before;
        HANDLE Check = CreateFileW(DestName, FILE_READ_ATTRIBUTES, COPY2_SHARE_ALL, NULL, OPEN_EXISTING,
                                   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);

        if (Check == INVALID_HANDLE_VALUE)
        {
            Error = GetLastError() ? GetLastError() : ERROR_FILE_NOT_FOUND;
        }
        else
        {
            Copy2ReadId(Check, &Now);
            Copy2ReadId(Dest, &Before);
            if (Copy2SameFile(&Now, &Before) != Copy2Same)
                Error = ERROR_FILE_INVALID;
            CloseHandle(Check);
        }
    }
    return Error;
}

/*
 * Gives the new file the extended attributes of the source, as Windows does. They are a bonus: a file system that
 * has none, or refuses them, is not a reason to fail a copy of the data.
 */
VOID
Copy2CopyEas(
    _In_ HANDLE Source,
    _In_ HANDLE Dest)
{
    IO_STATUS_BLOCK IoStatusBlock;
    PVOID Buffer;
    ULONG Size = 0x1000;
    NTSTATUS Status;

    for (;;)
    {
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
        if (!Buffer)
            return;

        Status = NtQueryEaFile(Source, &IoStatusBlock, Buffer, Size, FALSE, NULL, 0, NULL, TRUE);
        if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
            break;

        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        Size *= 2;
        if (Size > 0x100000)
            return;
    }

    if (NT_SUCCESS(Status) && IoStatusBlock.Information)
    {
        IO_STATUS_BLOCK SetStatusBlock;

        NtSetEaFile(Dest, &SetStatusBlock, Buffer, (ULONG)IoStatusBlock.Information);
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
}

/* Opens the new file for writing, with the right to delete it when the handles of others allow that: a file whose
   other handles do not share deleting still has to be written (Windows does), and then a failed copy cannot delete
   what it made, because only a handle that can delete is certain to delete the file it made and no other */
static HANDLE
Copy2OpenDest(
    _In_ PCWSTR Path,
    _In_ DWORD Disposition,
    _In_ DWORD Attributes,
    _Out_ PBOOL CanDelete)
{
    HANDLE File;
    DWORD Error;

    *CanDelete = TRUE;
    File = CreateFileW(Path, GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       Disposition, Attributes, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        if (Error == ERROR_SHARING_VIOLATION || Error == ERROR_ACCESS_DENIED)
        {
            *CanDelete = FALSE;
            File = CreateFileW(Path, GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               Disposition, Attributes, NULL);
        }
    }
    return File;
}

/* RESUME *******************************************************************/

/*
 * Whether a copy that was paused can go on in this stream, and where: when the stream in the destination is no
 * larger than the source and holds the first bytes of the source (an empty one does), the copy goes on at its size.
 * Windows 10 keeps a private record and refuses a file it did not pause; the bytes are compared here instead, so
 * a resumed copy of a stream is always a true copy of it.
 */
static BOOL
Copy2ResumePoint(
    _In_ HANDLE Source,
    _In_ PCWSTR DestPath,
    _In_ ULONGLONG SourceSize,
    _In_ HANDLE DestOwner,
    _Out_writes_bytes_(2 * COPY2_CHUNK_SIZE) PUCHAR Buffer,
    _Out_ PULONGLONG Offset)
{
    FILE_STANDARD_INFORMATION Standard;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER Position;
    ULONGLONG Length, Done = 0;
    HANDLE Dest;
    COPY2_ID OwnerId, DestId;

    *Offset = 0;
    Dest = CreateFileW(DestPath, GENERIC_READ, COPY2_SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (Dest == INVALID_HANDLE_VALUE)
        return FALSE;

    Copy2ReadId(DestOwner, &OwnerId);
    Copy2ReadId(Dest, &DestId);
    if (Copy2SameFile(&OwnerId, &DestId) != Copy2Same ||
        !NT_SUCCESS(NtQueryInformationFile(Dest, &IoStatusBlock, &Standard, sizeof(Standard), FileStandardInformation)))
    {
        CloseHandle(Dest);
        return FALSE;
    }

    Length = Standard.EndOfFile.QuadPart;
    if (Length > SourceSize)
    {
        CloseHandle(Dest);
        return FALSE;
    }

    while (Done < Length)
    {
        ULONG Chunk = (ULONG)min((ULONGLONG)COPY2_CHUNK_SIZE, Length - Done);

        Position.QuadPart = Done;
        if (!NT_SUCCESS(NtReadFile(Source, NULL, NULL, NULL, &IoStatusBlock, Buffer, Chunk, &Position, NULL)) ||
            IoStatusBlock.Information != Chunk ||
            !NT_SUCCESS(NtReadFile(Dest, NULL, NULL, NULL, &IoStatusBlock, Buffer + COPY2_CHUNK_SIZE, Chunk, &Position, NULL)) ||
            IoStatusBlock.Information != Chunk ||
            memcmp(Buffer, Buffer + COPY2_CHUNK_SIZE, Chunk))
        {
            CloseHandle(Dest);
            return FALSE;
        }
        Done += Chunk;
    }

    CloseHandle(Dest);
    *Offset = Length;
    return TRUE;
}

/* DATA *********************************************************************/

/*
 * Copies one stream from Offset on and sends its messages. The handles are for this stream only. A stop at the
 * start of the first stream leaves the new file as large as the source (Windows 10), so it gets that size then.
 */
static HRESULT
Copy2Stream(
    _Inout_ COPY2_STATE *State,
    _In_ DWORD StreamNumber,
    _In_ HANDLE Source,
    _In_ HANDLE Dest,
    _In_ ULONGLONG StreamSize,
    _In_ ULONGLONG Offset,
    _In_ BOOL Resumed,
    _In_ PUCHAR Buffer)
{
    COPYFILE2_MESSAGE Message;
    ULARGE_INTEGER StreamTransferred, ChunkNumber;
    HRESULT Result;
    NTSTATUS Status;

    StreamTransferred.QuadPart = Offset;
    ChunkNumber.QuadPart = Offset / COPY2_CHUNK_SIZE;
    State->TotalTransferred.QuadPart += Offset;

    /* A stream that a paused copy finished (an empty one too) is not copied again and sends no message (Windows 10) */
    if (Resumed && Offset == StreamSize)
    {
        if (!Copy2Cancelled(State))
            return S_OK;

        State->KeepDest = FALSE;
        return HRESULT_FROM_WIN32(ERROR_REQUEST_ABORTED);
    }

    RtlZeroMemory(&Message, sizeof(Message));
    Message.Type = COPYFILE2_CALLBACK_STREAM_STARTED;
    Message.Info.StreamStarted.dwStreamNumber = StreamNumber;
    Message.Info.StreamStarted.hSourceFile = Source;
    Message.Info.StreamStarted.hDestinationFile = Dest;
    Message.Info.StreamStarted.uliStreamSize.QuadPart = StreamSize;
    Message.Info.StreamStarted.uliTotalFileSize = State->TotalSize;
    Result = Copy2Notify(State, &Message, StreamNumber, FALSE);
    if (FAILED(Result) && State->KeepDest && StreamNumber == 1 && StreamTransferred.QuadPart == 0 &&
        Result == HRESULT_FROM_WIN32(ERROR_REQUEST_ABORTED))
    {
        Copy2SetLength(Dest, StreamSize);
    }

    while (SUCCEEDED(Result) && StreamTransferred.QuadPart < StreamSize)
    {
        ULARGE_INTEGER ChunkSize;
        IO_STATUS_BLOCK IoStatusBlock;
        LARGE_INTEGER Position;

        if (Copy2Cancelled(State))
        {
            Result = HRESULT_FROM_WIN32(ERROR_REQUEST_ABORTED);
            break;
        }

        ChunkSize.QuadPart = min((ULONGLONG)COPY2_CHUNK_SIZE, StreamSize - StreamTransferred.QuadPart);

        RtlZeroMemory(&Message, sizeof(Message));
        Message.Type = COPYFILE2_CALLBACK_CHUNK_STARTED;
        Message.Info.ChunkStarted.dwStreamNumber = StreamNumber;
        Message.Info.ChunkStarted.hSourceFile = Source;
        Message.Info.ChunkStarted.hDestinationFile = Dest;
        Message.Info.ChunkStarted.uliChunkNumber = ChunkNumber;
        Message.Info.ChunkStarted.uliChunkSize = ChunkSize;
        Message.Info.ChunkStarted.uliStreamSize.QuadPart = StreamSize;
        Message.Info.ChunkStarted.uliTotalFileSize = State->TotalSize;
        Result = Copy2Notify(State, &Message, StreamNumber, FALSE);
        if (FAILED(Result))
            break;

        Position.QuadPart = StreamTransferred.QuadPart;
        Status = NtReadFile(Source, NULL, NULL, NULL, &IoStatusBlock, Buffer, (ULONG)ChunkSize.QuadPart, &Position, NULL);
        if (Status == STATUS_END_OF_FILE || (NT_SUCCESS(Status) && IoStatusBlock.Information == 0))
        {
            /* The source shrank while it was copied: the stream ends where the data does, the new one has no more */
            State->TotalSize.QuadPart -= StreamSize - StreamTransferred.QuadPart;
            StreamSize = StreamTransferred.QuadPart;
            break;
        }
        if (!NT_SUCCESS(Status))
        {
            Result = Copy2Hresult(Status);
            Copy2NotifyError(State, COPYFILE2_PHASE_READ_SOURCE, StreamNumber, Result,
                             ChunkNumber.QuadPart, StreamSize, StreamTransferred.QuadPart);
            break;
        }

        ChunkSize.QuadPart = IoStatusBlock.Information;
        Status = NtWriteFile(Dest, NULL, NULL, NULL, &IoStatusBlock, Buffer, (ULONG)ChunkSize.QuadPart, &Position, NULL);
        if (!NT_SUCCESS(Status))
        {
            Result = Copy2Hresult(Status);
            Copy2NotifyError(State, COPYFILE2_PHASE_WRITE_DESTINATION, StreamNumber, Result,
                             ChunkNumber.QuadPart, StreamSize, StreamTransferred.QuadPart);
            break;
        }

        StreamTransferred.QuadPart += ChunkSize.QuadPart;
        State->TotalTransferred.QuadPart += ChunkSize.QuadPart;

        RtlZeroMemory(&Message, sizeof(Message));
        Message.Type = COPYFILE2_CALLBACK_CHUNK_FINISHED;
        Message.Info.ChunkFinished.dwStreamNumber = StreamNumber;
        Message.Info.ChunkFinished.hSourceFile = Source;
        Message.Info.ChunkFinished.hDestinationFile = Dest;
        Message.Info.ChunkFinished.uliChunkNumber = ChunkNumber;
        Message.Info.ChunkFinished.uliChunkSize = ChunkSize;
        Message.Info.ChunkFinished.uliStreamSize.QuadPart = StreamSize;
        Message.Info.ChunkFinished.uliStreamBytesTransferred = StreamTransferred;
        Message.Info.ChunkFinished.uliTotalFileSize = State->TotalSize;
        Message.Info.ChunkFinished.uliTotalBytesTransferred = State->TotalTransferred;
        Result = Copy2Notify(State, &Message, StreamNumber, FALSE);
        ChunkNumber.QuadPart++;
    }

    /* The end of a stream is sent whether it went well or not; after a failure its answer is not looked at */
    RtlZeroMemory(&Message, sizeof(Message));
    Message.Type = COPYFILE2_CALLBACK_STREAM_FINISHED;
    Message.Info.StreamFinished.dwStreamNumber = StreamNumber;
    Message.Info.StreamFinished.hSourceFile = Source;
    Message.Info.StreamFinished.hDestinationFile = Dest;
    Message.Info.StreamFinished.uliStreamSize.QuadPart = StreamSize;
    Message.Info.StreamFinished.uliStreamBytesTransferred = StreamTransferred;
    Message.Info.StreamFinished.uliTotalFileSize = State->TotalSize;
    Message.Info.StreamFinished.uliTotalBytesTransferred = State->TotalTransferred;
    if (SUCCEEDED(Result))
        Result = Copy2Notify(State, &Message, StreamNumber, FALSE);
    else
        Copy2Notify(State, &Message, StreamNumber, TRUE);

    return Result;
}

/* LINKS ********************************************************************/

/*
 * The source is a symbolic link and the link is what is copied: Windows 10 sends no message for it and ignores the
 * cancel flag. *Handled is FALSE only when the source was found not to be a symbolic link (the copy is then done
 * as for any file); a failure to look at the source is a failure of the copy.
 */
static HRESULT
Copy2CopyLink(
    _Inout_ COPY2_STATE *State,
    _In_ PCWSTR SourceName,
    _In_ PCWSTR DestName,
    _In_ DWORD CopyFlags,
    _Out_ PBOOL Handled)
{
    BY_HANDLE_FILE_INFORMATION SourceInfo, DestInfo;
    FILE_BASIC_INFORMATION Basic;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE Source, Dest = INVALID_HANDLE_VALUE;
    PUCHAR Reparse = NULL;
    NTSTATUS Status;
    DWORD SourceLength = 0, OldLength, Ignored, Error = ERROR_SUCCESS;
    BOOL Made = FALSE, CanDelete = FALSE, Set, Adjusted = FALSE, OnThread = FALSE;
    BOOLEAN WasEnabled = FALSE;
    COPYFILE2_COPY_PHASE Phase = COPYFILE2_PHASE_PREPARE_SOURCE;

    *Handled = FALSE;

    Source = CreateFileW(SourceName, FILE_READ_ATTRIBUTES, COPY2_SHARE_ALL, NULL, OPEN_EXISTING,
                         FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (Source == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        Copy2NotifyError(State, COPYFILE2_PHASE_PREPARE_SOURCE, 0, HRESULT_FROM_WIN32(Error), 0, 0, 0);
        *Handled = TRUE;
        return HRESULT_FROM_WIN32(Error);
    }

    if (!GetFileInformationByHandle(Source, &SourceInfo))
    {
        *Handled = TRUE;
        Error = GetLastError();
        goto Done;
    }

    /* Anything but a link is copied as usual */
    if (!(SourceInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        goto Done;

    Reparse = RtlAllocateHeap(RtlGetProcessHeap(), 0, 2 * MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    if (!Reparse)
    {
        *Handled = TRUE;
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto Done;
    }

    if (!DeviceIoControl(Source, FSCTL_GET_REPARSE_POINT, NULL, 0, Reparse, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &SourceLength, NULL))
    {
        *Handled = TRUE;
        Error = GetLastError();
        goto Done;
    }

    /* Another kind of reparse point is followed as usual */
    if (SourceLength < 8 || *(ULONG *)Reparse != IO_REPARSE_TAG_SYMLINK)
        goto Done;

    *Handled = TRUE;
    Phase = COPYFILE2_PHASE_PREPARE_DEST;
    Dest = Copy2OpenDest(DestName,
                         (CopyFlags & COPY_FILE_FAIL_IF_EXISTS) ? CREATE_NEW : OPEN_ALWAYS,
                         FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                         &CanDelete);
    if (Dest == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        goto Done;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        COPY2_SAME Same = Copy2CompareHandles(Source, Dest);

        /* A link copied onto itself stays as it is; a file that cannot be told from it is not touched */
        if (Same != Copy2Different)
        {
            if (Same == Copy2Unknown)
                Error = ERROR_SHARING_VIOLATION;
            goto Done;
        }

        if (!GetFileInformationByHandle(Dest, &DestInfo))
        {
            Error = GetLastError();
            goto Done;
        }

        /* Only a file is replaced by a link to a file and a link to a directory by one; a directory and any kind of
           reparse point but a symbolic link stay as they are */
        if (((DestInfo.dwFileAttributes ^ SourceInfo.dwFileAttributes) & FILE_ATTRIBUTE_DIRECTORY) ||
            ((DestInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(DestInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)))
        {
            Error = ERROR_ACCESS_DENIED;
            goto Done;
        }

        /* An old link has to lose its reparse data before the new data can be set */
        if (DestInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        {
            if (!DeviceIoControl(Dest, FSCTL_GET_REPARSE_POINT, NULL, 0, Reparse + MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
                                 MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &OldLength, NULL) || OldLength < 8)
            {
                Error = GetLastError() ? GetLastError() : ERROR_INVALID_REPARSE_DATA;
                goto Done;
            }
            if (*(ULONG *)(Reparse + MAXIMUM_REPARSE_DATA_BUFFER_SIZE) != IO_REPARSE_TAG_SYMLINK)
            {
                Error = ERROR_ACCESS_DENIED;
                goto Done;
            }

            /* the header of the data to delete: the tag of the old data and no length */
            ZeroMemory(Reparse + MAXIMUM_REPARSE_DATA_BUFFER_SIZE + 4, 4);
            if (!DeviceIoControl(Dest, FSCTL_DELETE_REPARSE_POINT, Reparse + MAXIMUM_REPARSE_DATA_BUFFER_SIZE, 8,
                                 NULL, 0, &Ignored, NULL))
            {
                Error = GetLastError();
                goto Done;
            }
        }

        /* From here on the file is this copy's; a directory has no data to cut down */
        Made = TRUE;
        if (!(DestInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            Status = Copy2SetLength(Dest, 0);
            if (!NT_SUCCESS(Status))
            {
                Error = RtlNtStatusToDosError(Status);
                goto Done;
            }
        }
    }

    Made = TRUE;

    /*
     * Creating a symbolic link takes SeCreateSymbolicLinkPrivilege. Administrators hold it, disabled in their
     * token until a program turns it on, as CreateSymbolicLink does around the same request. It is enabled for
     * the thread if it impersonates and for the process otherwise, and put back as it was. Without the privilege
     * the adjustment fails and the file system refuses the request.
     */
    Status = RtlAdjustPrivilege(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, TRUE, TRUE, &WasEnabled);
    if (NT_SUCCESS(Status))
    {
        Adjusted = OnThread = TRUE;
    }
    else if (Status == STATUS_NO_TOKEN)
    {
        Status = RtlAdjustPrivilege(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, TRUE, FALSE, &WasEnabled);
        if (NT_SUCCESS(Status))
            Adjusted = TRUE;
    }

    Set = DeviceIoControl(Dest, FSCTL_SET_REPARSE_POINT, Reparse, SourceLength, NULL, 0, &Ignored, NULL);
    if (!Set)
        Error = GetLastError();

    if (Adjusted && !WasEnabled)
        RtlAdjustPrivilege(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, FALSE, OnThread, &WasEnabled);

    if (!Set)
        goto Done;

    RtlZeroMemory(&Basic, sizeof(Basic));
    Basic.FileAttributes = SourceInfo.dwFileAttributes & FILE_ATTRIBUTE_VALID_SET_FLAGS;
    Status = NtSetInformationFile(Dest, &IoStatusBlock, &Basic, sizeof(Basic), FileBasicInformation);
    if (!NT_SUCCESS(Status))
        Error = RtlNtStatusToDosError(Status);

Done:
    /* a failed copy takes the new file with it, if the handle that made it can delete it */
    if (Dest != INVALID_HANDLE_VALUE)
    {
        if (Made && Error != ERROR_SUCCESS && CanDelete)
            Copy2DeleteByHandle(Dest);
        CloseHandle(Dest);
    }
    if (Reparse)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Reparse);
    CloseHandle(Source);

    if (Error == ERROR_SUCCESS)
        return S_OK;

    Copy2NotifyError(State, Phase, (Phase == COPYFILE2_PHASE_PREPARE_DEST) ? 1 : 0, HRESULT_FROM_WIN32(Error), 0, 0, 0);
    return HRESULT_FROM_WIN32(Error);
}

/* CopyFile2 ****************************************************************/

HRESULT
WINAPI
CopyFile2(
    _In_ PCWSTR pwszExistingFileName,
    _In_ PCWSTR pwszNewFileName,
    _In_opt_ COPYFILE2_EXTENDED_PARAMETERS *pExtendedParameters)
{
    COPY2_STATE State = { 0 };
    COPY2_STREAM *NamedStreams = NULL;
    FILE_STANDARD_INFORMATION Standard;
    FILE_BASIC_INFORMATION Basic;
    BY_HANDLE_FILE_INFORMATION DestInfo;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;
    HANDLE Source = INVALID_HANDLE_VALUE, Dest = INVALID_HANDLE_VALUE;
    ULONGLONG SourceSize, Offset;
    DWORD CopyFlags = 0, DestAttributes, StreamError;
    HRESULT Result = S_OK;
    BOOL Existed = FALSE, Touched = FALSE, Handled = FALSE, CanDelete = FALSE, Valid = FALSE, StreamExisted;
    PUCHAR Buffer = NULL;
    PVOID StreamBuffer = NULL;
    PWSTR SourceName = NULL, DestName = NULL;
    ULONG NamedCount = 0, i;

    if (!pwszExistingFileName || !pwszNewFileName)
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    }

    if (pExtendedParameters)
    {
        CopyFlags = pExtendedParameters->dwCopyFlags;
        if (pExtendedParameters->dwSize != sizeof(*pExtendedParameters) ||
            (CopyFlags & COPY2_INVALID_FLAGS) ||
            ((CopyFlags & COPY_FILE_RESTARTABLE) && (CopyFlags & COPY_FILE_RESUME_FROM_PAUSE)))
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return E_INVALIDARG;
        }

        State.Progress = pExtendedParameters->pProgressRoutine;
        State.Context = pExtendedParameters->pvCallbackContext;
        State.Cancel = pExtendedParameters->pfCancel;
    }
    State.Resume = (CopyFlags & COPY_FILE_RESUME_FROM_PAUSE) != 0;

    StreamError = Copy2FullPath(pwszExistingFileName, &SourceName);
    if (StreamError == ERROR_SUCCESS)
        StreamError = Copy2FullPath(pwszNewFileName, &DestName);
    if (StreamError != ERROR_SUCCESS)
    {
        Result = HRESULT_FROM_WIN32(StreamError);
        Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_SOURCE, 0, Result, 0, 0, 0);
        goto Done;
    }

    if (CopyFlags & COPY_FILE_COPY_SYMLINK)
    {
        Result = Copy2CopyLink(&State, SourceName, DestName, CopyFlags, &Handled);
        if (Handled)
            goto Done;
    }

    /* The source is opened first, with every kind of sharing */
    Source = CreateFileW(SourceName, GENERIC_READ, COPY2_SHARE_ALL, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (Source == INVALID_HANDLE_VALUE)
    {
        Result = HRESULT_FROM_WIN32(GetLastError());
        Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_SOURCE, 0, Result, 0, 0, 0);
        goto Done;
    }

    Status = NtQueryInformationFile(Source, &IoStatusBlock, &Standard, sizeof(Standard), FileStandardInformation);
    if (NT_SUCCESS(Status))
        Status = NtQueryInformationFile(Source, &IoStatusBlock, &Basic, sizeof(Basic), FileBasicInformation);
    if (NT_SUCCESS(Status))
        Status = Copy2QueryNamedStreams(Source, &NamedStreams, &NamedCount, &StreamBuffer);
    if (!NT_SUCCESS(Status))
    {
        Result = Copy2Hresult(Status);
        Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_SOURCE, 0, Result, 0, 0, 0);
        goto Done;
    }

    SourceSize = Standard.EndOfFile.QuadPart;
    State.TotalSize.QuadPart = SourceSize;

    /* All streams of the source are open before the first message: a callback that renames the source and puts
       another file in its place cannot change what is copied (Windows 10 copies the original) */
    for (i = 0; i < NamedCount; i++)
    {
        NamedStreams[i].Source = Copy2OpenStream(SourceName, NamedStreams[i].Name, GENERIC_READ, COPY2_SHARE_ALL,
                                                 OPEN_EXISTING, Source, 0, &StreamError, NULL);
        if (NamedStreams[i].Source == INVALID_HANDLE_VALUE)
        {
            Result = HRESULT_FROM_WIN32(StreamError);
            Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_SOURCE, i + 2, Result, 0, NamedStreams[i].Size, 0);
            goto Done;
        }
        State.TotalSize.QuadPart += NamedStreams[i].Size;
    }

    Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, 2 * COPY2_CHUNK_SIZE);
    if (!Buffer)
    {
        Result = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
        Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_DEST, 1, Result, 0, SourceSize, 0);
        goto Done;
    }

    /*
     * The new file is opened without cutting it down: it may be the source (a hard link, a short name or an
     * extended name), and then it must not be touched. What the open file is, is decided on the handles. The
     * access is for writing (and deleting, when others allow it), the sharing lets readers and writers in but not
     * deleting, as in Windows.
     */
    DestAttributes = Basic.FileAttributes & ~(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_REPARSE_POINT);
    Dest = Copy2OpenDest(DestName,
                         ((CopyFlags & COPY_FILE_FAIL_IF_EXISTS) && !State.Resume) ? CREATE_NEW : OPEN_ALWAYS,
                         DestAttributes,
                         &CanDelete);
    if (Dest == INVALID_HANDLE_VALUE)
    {
        Result = HRESULT_FROM_WIN32(GetLastError());
        Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_DEST, 1, Result, 0, SourceSize, 0);
        goto Done;
    }
    Existed = (GetLastError() == ERROR_ALREADY_EXISTS);
    Offset = 0;

    if (!Existed)
    {
        Touched = TRUE;
    }
    else
    {
        if (Copy2CompareHandles(Source, Dest) != Copy2Different)
        {
            /* It is the source, or cannot be told from it: nothing of it is changed or deleted */
            Result = HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION);
            Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_DEST, 1, Result, 0, SourceSize, 0);
            goto Done;
        }

        /* What CREATE_ALWAYS does with a file that exists: a hidden or system file has to be asked for as such */
        if (!GetFileInformationByHandle(Dest, &DestInfo))
        {
            Result = HRESULT_FROM_WIN32(GetLastError());
            Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_DEST, 1, Result, 0, SourceSize, 0);
            goto Done;
        }
        if (DestInfo.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) & ~DestAttributes)
        {
            Result = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
            Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_DEST, 1, Result, 0, SourceSize, 0);
            goto Done;
        }

        /* Whether the file holds the start of this source decides: if it does (an empty one does), the copy goes
           on after it; any other file is a conflict if the caller wants none */
        Valid = State.Resume && Copy2ResumePoint(Source, DestName, SourceSize, Dest, Buffer, &Offset);
        if (State.Resume && !Valid && (CopyFlags & COPY_FILE_FAIL_IF_EXISTS))
        {
            Result = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
            Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_DEST, 1, Result, 0, SourceSize, 0);
            goto Done;
        }

        /* A file that is not continued is replaced, with all its named streams; one that is continued keeps what
           it has and loses the streams the source has not */
        Touched = TRUE;
        StreamError = Copy2RemoveStreams(Dest, DestName, Valid ? NamedStreams : NULL, Valid ? NamedCount : 0);
        if (StreamError == ERROR_SUCCESS && !Valid)
        {
            Status = Copy2SetLength(Dest, 0);
            if (!NT_SUCCESS(Status))
                StreamError = RtlNtStatusToDosError(Status);
        }
        if (StreamError != ERROR_SUCCESS)
        {
            Result = HRESULT_FROM_WIN32(StreamError);
            Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_DEST, 1, Result, 0, SourceSize, 0);
            goto Done;
        }
    }

    Result = Copy2Stream(&State, 1, Source, Dest, SourceSize, Offset, Valid, Buffer);

    for (i = 0; SUCCEEDED(Result) && i < NamedCount; i++)
    {
        HANDLE DestStream;
        PWSTR DestStreamPath;

        DestStream = Copy2OpenStream(DestName, NamedStreams[i].Name, GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_ALWAYS, Dest, 0, &StreamError, &StreamExisted);
        if (DestStream == INVALID_HANDLE_VALUE)
        {
            Result = HRESULT_FROM_WIN32(StreamError);
            Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_DEST, i + 2, Result, 0, NamedStreams[i].Size, 0);
            break;
        }

        Offset = 0;
        Valid = FALSE;
        DestStreamPath = (State.Resume && StreamExisted) ? Copy2StreamPath(DestName, NamedStreams[i].Name) : NULL;
        if (DestStreamPath)
        {
            Valid = Copy2ResumePoint(NamedStreams[i].Source, DestStreamPath, NamedStreams[i].Size, DestStream, Buffer, &Offset);
            RtlFreeHeap(RtlGetProcessHeap(), 0, DestStreamPath);
        }
        if (!Valid)
        {
            Status = Copy2SetLength(DestStream, 0);
            if (!NT_SUCCESS(Status))
            {
                Result = Copy2Hresult(Status);
                Copy2NotifyError(&State, COPYFILE2_PHASE_PREPARE_DEST, i + 2, Result, 0, NamedStreams[i].Size, 0);
                CloseHandle(DestStream);
                break;
            }
        }

        Result = Copy2Stream(&State, i + 2, NamedStreams[i].Source, DestStream, NamedStreams[i].Size, Offset, Valid, Buffer);
        CloseHandle(DestStream);
    }

    if (SUCCEEDED(Result))
        Copy2CopyEas(Source, Dest);

    if (SUCCEEDED(Result))
    {
        /* The copy keeps the write time and the attributes of the source and has its own creation time; the
           read-only attribute comes last because a read-only file takes no new stream */
        Basic.CreationTime.QuadPart = 0;
        Basic.LastAccessTime.QuadPart = 0;
        Basic.ChangeTime.QuadPart = 0;
        Basic.FileAttributes &= FILE_ATTRIBUTE_VALID_SET_FLAGS;
        Status = NtSetInformationFile(Dest, &IoStatusBlock, &Basic, sizeof(Basic), FileBasicInformation);
        if (!NT_SUCCESS(Status))
        {
            Result = Copy2Hresult(Status);
            Copy2NotifyError(&State, COPYFILE2_PHASE_WRITE_DESTINATION, 1, Result, 0, SourceSize, SourceSize);
        }
    }

Done:
    /* A copy that failed takes the new file with it, through the handle that made it. Without the right to delete
       the file stays: deleting by name could take a file that is not the copy. */
    if (Dest != INVALID_HANDLE_VALUE)
    {
        if (Touched && FAILED(Result) && !State.KeepDest && CanDelete)
            Copy2DeleteByHandle(Dest);
        CloseHandle(Dest);
    }

    for (i = 0; i < NamedCount; i++)
    {
        if (NamedStreams[i].Source != INVALID_HANDLE_VALUE)
            CloseHandle(NamedStreams[i].Source);
    }
    if (Source != INVALID_HANDLE_VALUE)
        CloseHandle(Source);
    if (Buffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    if (NamedStreams)
        RtlFreeHeap(RtlGetProcessHeap(), 0, NamedStreams);
    if (StreamBuffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, StreamBuffer);
    if (SourceName)
        RtlFreeHeap(RtlGetProcessHeap(), 0, SourceName);
    if (DestName)
        RtlFreeHeap(RtlGetProcessHeap(), 0, DestName);

    SetLastError(SUCCEEDED(Result) ? ERROR_SUCCESS : HRESULT_CODE(Result));
    return Result;
}
