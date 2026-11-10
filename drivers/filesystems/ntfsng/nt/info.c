/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IRP_MJ_QUERY/SET_INFORMATION, IRP_MJ_QUERY_VOLUME_INFORMATION
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ntfsng.h"

ULONG NgFileAttributes(PNG_FCB Fcb, const struct ngc_stat *St)
{
    ULONG A = St->file_attributes & ~(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_DIRECTORY);
    UNREFERENCED_PARAMETER(Fcb);
    if (St->is_dir)
        A |= FILE_ATTRIBUTE_DIRECTORY;
    if (St->flags & NGC_ATTR_SPARSE)
        A |= FILE_ATTRIBUTE_SPARSE_FILE;
    if (St->flags & NGC_ATTR_COMPRESSED)
        A |= FILE_ATTRIBUTE_COMPRESSED;
    return A ? A : FILE_ATTRIBUTE_NORMAL;
}

static VOID NgBasic(PNG_FCB Fcb, PFILE_BASIC_INFORMATION B)
{
    B->CreationTime.QuadPart = Fcb->Stat.crtime;
    B->LastAccessTime.QuadPart = Fcb->Stat.atime;
    B->LastWriteTime.QuadPart = Fcb->Stat.mtime;
    B->ChangeTime.QuadPart = Fcb->Stat.ctime;
    B->FileAttributes = NgFileAttributes(Fcb, &Fcb->Stat);
}

/*
 * As NTFS on Windows 10 (measured on 22H2): a pending delete of a file takes its name out of the link count (a file
 * with one name whose delete is pending, or whose name a POSIX delete moved to $Extend\$Deleted, has 0; a named
 * stream's pending delete does not count), and a handle whose name a POSIX delete removed reports the delete
 * pending even when the file lives on under another name.
 */
static VOID NgStandard(PNG_FCB Fcb, PNG_CCB Ccb, PFILE_STANDARD_INFORMATION S)
{
    ULONG Links = Fcb->Stat.nlink ? Fcb->Stat.nlink : 1;
    S->AllocationSize.QuadPart = Fcb->IsDirectory ? 0 : Fcb->Stat.alloc;
    S->EndOfFile.QuadPart = Fcb->IsDirectory ? 0 : Fcb->Stat.size;
    S->NumberOfLinks = Fcb->DeletePending && !Fcb->Stream.Length ? Links - 1 : Links;   /* not for a named stream */
    S->DeletePending = Fcb->DeletePending || (Ccb && Ccb->Orphaned);
    S->Directory = Fcb->IsDirectory;
}

/*
 * Copies the open name (as a rename through any handle left it: FcbListLock); returns
 * STATUS_BUFFER_OVERFLOW with a truncated name if it does not fit.
 */
static NTSTATUS NgName(PNG_VCB Vcb, PNG_CCB Ccb, PFILE_NAME_INFORMATION N, ULONG Room, PULONG Used)
{
    ULONG Fixed = FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
    ULONG Len, Copy;
    if (Room < Fixed)
        return STATUS_BUFFER_TOO_SMALL;
    ExAcquireFastMutex(&Vcb->FcbListLock);
    Len = Ccb->Path.Length ? Ccb->Path.Length : sizeof(WCHAR);
    N->FileNameLength = Len;
    Copy = min(Len, Room - Fixed);
    if (Ccb->Path.Length)
        RtlCopyMemory(N->FileName, Ccb->Path.Buffer, Copy);
    else if (Copy)
        N->FileName[0] = L'\\';
    ExReleaseFastMutex(&Vcb->FcbListLock);
    *Used = Fixed + Copy;
    return Copy < Len ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

typedef struct _NG_STREAMS
{
    BOOLEAN NamedOnly;          /* a directory has no unnamed data stream */
    PUCHAR Buffer;
    ULONG Room;
    ULONG Used;
    ULONG Last;
    ULONG Count;
    NTSTATUS Status;
} NG_STREAMS;

static int NgStreamFill(void *Context, const unsigned short *Name, unsigned int Len,
                        unsigned long long Size, unsigned long long Alloc)
{
    NG_STREAMS *S = Context;
    static const WCHAR Suffix[] = L":$DATA";
    ULONG NameBytes = (1 + Len) * sizeof(WCHAR) + sizeof(Suffix) - sizeof(WCHAR);
    ULONG Offset = S->Count ? ALIGN_UP_BY(S->Used, 8) : 0;
    ULONG Need = FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName) + NameBytes;
    PFILE_STREAM_INFORMATION P;

    if (S->NamedOnly && Len == 0)
        return 0;
    if (Offset + Need > S->Room)
    {
        S->Status = STATUS_BUFFER_OVERFLOW;
        return 1;
    }
    P = (PVOID)(S->Buffer + Offset);
    P->NextEntryOffset = 0;
    P->StreamNameLength = NameBytes;
    P->StreamSize.QuadPart = Size;
    P->StreamAllocationSize.QuadPart = Alloc;
    P->StreamName[0] = L':';
    RtlCopyMemory(P->StreamName + 1, Name, Len * sizeof(WCHAR));
    RtlCopyMemory(P->StreamName + 1 + Len, Suffix, sizeof(Suffix) - sizeof(WCHAR));
    if (S->Count)
        ((PFILE_STREAM_INFORMATION)(S->Buffer + S->Last))->NextEntryOffset = Offset - S->Last;
    S->Last = Offset;
    S->Used = Offset + Need;
    S->Count++;
    return 0;
}

/* FileIdInformation (59, Windows 8+) is past the end of this DDK's FILE_INFORMATION_CLASS */
#define NG_FILE_ID_INFORMATION_CLASS 59
typedef struct _NG_FILE_ID_INFORMATION
{
    ULONGLONG VolumeSerialNumber;
    UCHAR FileId[16];               /* FILE_ID_128 */
} NG_FILE_ID_INFORMATION, *PNG_FILE_ID_INFORMATION;
C_ASSERT(sizeof(NG_FILE_ID_INFORMATION) == 24);

NTSTATUS NgQueryInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = Stack->FileObject;
    PNG_FCB Fcb = FileObject->FsContext;
    PNG_CCB Ccb = FileObject->FsContext2;
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    ULONG Length = Stack->Parameters.QueryFile.Length, Used = 0;
    PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS Status = STATUS_SUCCESS;

    if (!Fcb || !Ccb)
        return STATUS_INVALID_PARAMETER;
    if (Fcb->IsVolume)
        return STATUS_INVALID_PARAMETER;
    NgFillStat(Fcb);
    /* Zero the reply buffer so uninitialized pool padding never reaches user mode. */
    if (Buffer)
    {
        if (Stack->Parameters.QueryFile.FileInformationClass == FileAllInformation &&
            Length >= FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation))
        {
            /* The I/O manager fills in the access, mode and alignment parts of
               FileAllInformation before calling us (as for fastfat); keep them. */
            PFILE_ALL_INFORMATION A = Buffer;
            FILE_ACCESS_INFORMATION Access = A->AccessInformation;
            FILE_MODE_INFORMATION Mode = A->ModeInformation;
            FILE_ALIGNMENT_INFORMATION Alignment = A->AlignmentInformation;
            RtlZeroMemory(Buffer, Length);
            A->AccessInformation = Access;
            A->ModeInformation = Mode;
            A->AlignmentInformation = Alignment;
        }
        else
        {
            RtlZeroMemory(Buffer, Length);
        }
    }

#define NEED(t) do { if (Length < sizeof(t)) return STATUS_BUFFER_TOO_SMALL; Used = sizeof(t); } while (0)
    switch ((ULONG)Stack->Parameters.QueryFile.FileInformationClass)
    {
        case FileBasicInformation:
            NEED(FILE_BASIC_INFORMATION);
            NgBasic(Fcb, Buffer);
            break;
        case FileStandardInformation:
            NEED(FILE_STANDARD_INFORMATION);
            NgStandard(Fcb, Ccb, Buffer);
            break;
        case FileInternalInformation:
            NEED(FILE_INTERNAL_INFORMATION);
            ((PFILE_INTERNAL_INFORMATION)Buffer)->IndexNumber.QuadPart = Fcb->Stat.mft_ref;
            break;
        case NG_FILE_ID_INFORMATION_CLASS:
        {
            /* As NTFS on Windows: the whole 64-bit volume serial (FileFsVolumeInformation has its low half)
               and the file reference of FileInternalInformation, zero-extended to 128 bits. */
            PNG_FILE_ID_INFORMATION I = Buffer;
            ULONGLONG Ref = Fcb->Stat.mft_ref;
            NEED(NG_FILE_ID_INFORMATION);
            I->VolumeSerialNumber = Vcb->Serial;
            RtlCopyMemory(I->FileId, &Ref, sizeof(Ref));
            break;
        }
        case FileEaInformation:
            NEED(FILE_EA_INFORMATION);
            ((PFILE_EA_INFORMATION)Buffer)->EaSize = 0;
            break;
        case FilePositionInformation:
            NEED(FILE_POSITION_INFORMATION);
            ((PFILE_POSITION_INFORMATION)Buffer)->CurrentByteOffset = FileObject->CurrentByteOffset;
            break;
        case FileNameInformation:
            Status = NgName(Vcb, Ccb, Buffer, Length, &Used);
            break;
        case FileAlternateNameInformation:
        {
            /* The DOS name of the name this handle was opened by; none for a valid 8.3 name. */
            PFILE_NAME_INFORMATION N = Buffer;
            WCHAR Short[12];
            unsigned int Chars = 0;
            ULONG Fixed = FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
            ULONGLONG Dir;
            int Err;
            if (Length < Fixed)
                return STATUS_BUFFER_TOO_SMALL;
            if (Fcb->IsRoot || Fcb->Stream.Length)
                return STATUS_OBJECT_NAME_NOT_FOUND;
            ExAcquireFastMutex(&Vcb->FcbListLock);
            Dir = Ccb->ParentMftNo;
            ExReleaseFastMutex(&Vcb->FcbListLock);
            NgAcquireCore(Vcb);
            Err = NgEnsureNode(Fcb);
            if (!Err)
                Err = ngc_short_name(Fcb->Node, Dir, Short, &Chars);
            NgReleaseCore(Vcb);
            if (Err)
                return NgErrnoToStatus(Err);
            if (!Chars)
                return STATUS_OBJECT_NAME_NOT_FOUND;
            N->FileNameLength = Chars * sizeof(WCHAR);
            if (Length < Fixed + N->FileNameLength)
            {
                RtlCopyMemory(N->FileName, Short, Length - Fixed);
                Used = Length;
                Status = STATUS_BUFFER_OVERFLOW;
            }
            else
            {
                RtlCopyMemory(N->FileName, Short, N->FileNameLength);
                Used = Fixed + N->FileNameLength;
            }
            break;
        }
        case FileNetworkOpenInformation:
        {
            PFILE_NETWORK_OPEN_INFORMATION N = Buffer;
            FILE_BASIC_INFORMATION B;
            NEED(FILE_NETWORK_OPEN_INFORMATION);
            NgBasic(Fcb, &B);
            N->CreationTime = B.CreationTime;
            N->LastAccessTime = B.LastAccessTime;
            N->LastWriteTime = B.LastWriteTime;
            N->ChangeTime = B.ChangeTime;
            N->AllocationSize.QuadPart = Fcb->IsDirectory ? 0 : Fcb->Stat.alloc;
            N->EndOfFile.QuadPart = Fcb->IsDirectory ? 0 : Fcb->Stat.size;
            N->FileAttributes = B.FileAttributes;
            break;
        }
        case FileAttributeTagInformation:
            NEED(FILE_ATTRIBUTE_TAG_INFORMATION);
            ((PFILE_ATTRIBUTE_TAG_INFORMATION)Buffer)->FileAttributes = NgFileAttributes(Fcb, &Fcb->Stat);
            ((PFILE_ATTRIBUTE_TAG_INFORMATION)Buffer)->ReparseTag = 0;
            if (Fcb->Stat.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
            {
                void *Data;
                unsigned int Len;
                NgAcquireCore(Vcb);
                if (!NgEnsureNode(Fcb) && !ngc_get_reparse(Fcb->Node, &Data, &Len))
                {
                    ((PFILE_ATTRIBUTE_TAG_INFORMATION)Buffer)->ReparseTag = ((PREPARSE_DATA_BUFFER)Data)->ReparseTag;
                    ngc_free(Data);
                }
                NgReleaseCore(Vcb);
            }
            break;
        case FileAllInformation:
        {
            PFILE_ALL_INFORMATION A = Buffer;
            ULONG NameUsed = 0;
            if (Length < FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation.FileName))
                return STATUS_BUFFER_TOO_SMALL;
            NgBasic(Fcb, &A->BasicInformation);
            NgStandard(Fcb, Ccb, &A->StandardInformation);
            A->InternalInformation.IndexNumber.QuadPart = Fcb->Stat.mft_ref;
            A->EaInformation.EaSize = 0;
            A->PositionInformation.CurrentByteOffset = FileObject->CurrentByteOffset;
            Status = NgName(Vcb, Ccb, &A->NameInformation, Length - FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation), &NameUsed);
            Used = FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation) + NameUsed;
            break;
        }
        case FileStreamInformation:
        {
            NG_STREAMS S = { Fcb->IsDirectory, Buffer, Length, 0, 0, 0, STATUS_SUCCESS };
            int Err;
            NgAcquireCore(Vcb);
            Err = NgEnsureNode(Fcb);
            if (!Err)
                Err = ngc_streams(Fcb->Node, NgStreamFill, &S);
            NgReleaseCore(Vcb);
            if (Err)
                return NgErrnoToStatus(Err);
            /* No streams (a directory) is a success with nothing returned, as on Windows. */
            Status = S.Status;
            Used = S.Used;
            break;
        }
        default:
            return STATUS_INVALID_PARAMETER;
    }
#undef NEED
    Irp->IoStatus.Information = Used;
    return Status;
}

/*
 * HandleWrote: the handle wrote data (FO_FILE_MODIFIED).  Windows 10 (measured, 2026-11-10) sets the archive attribute
 * of a file when a basic-information request that sets no attributes arrives on such a handle, even after the attribute
 * was cleared before and whatever times the request sets (write, SetFileAttributes(NORMAL) through another handle,
 * SetFileTime on the writing handle: ARCHIVE, at once and after the close).  A handle that did not write leaves it alone
 * (SetFileAttributes(NORMAL) then SetFileTime on a fresh handle: NORMAL stays).
 */
static NTSTATUS NgSetBasic(PNG_FCB Fcb, PFILE_BASIC_INFORMATION B, BOOLEAN HandleWrote)
{
    PNG_VCB Vcb = Fcb->Vcb;
    long long Times[4];
    unsigned int Attrs = 0, Mask = 0;
    int Err;

    /* 0 leaves a time alone; -1 (stop automatic updates for this handle) is treated the same. */
    Times[0] = B->CreationTime.QuadPart > 0 ? B->CreationTime.QuadPart : 0;
    Times[1] = B->LastAccessTime.QuadPart > 0 ? B->LastAccessTime.QuadPart : 0;
    Times[2] = B->LastWriteTime.QuadPart > 0 ? B->LastWriteTime.QuadPart : 0;
    Times[3] = B->ChangeTime.QuadPart > 0 ? B->ChangeTime.QuadPart : 0;
    if (B->LastWriteTime.QuadPart)
        Fcb->UserSetWriteTime = TRUE;
    if (B->FileAttributes)
    {
        if (Fcb->IsDirectory && (B->FileAttributes & FILE_ATTRIBUTE_TEMPORARY))
            return STATUS_INVALID_PARAMETER;
        Attrs = B->FileAttributes & ~(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_DIRECTORY);
        Mask = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
               FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    }
    else if (HandleWrote && !Fcb->IsDirectory)
    {
        Attrs = FILE_ATTRIBUTE_ARCHIVE;
        Mask = FILE_ATTRIBUTE_ARCHIVE;
    }
    if (!Times[0] && !Times[1] && !Times[2] && !Times[3] && !Mask)
        return STATUS_SUCCESS;
    NgAcquireCore(Vcb);
    Err = NgEnsureNode(Fcb);
    if (!Err)
        Err = ngc_set_info(Vcb->Core, Fcb->Node, Times, Attrs, Mask);
    if (!Err)
    {
        ngc_stat(Fcb->Node, &Fcb->Stat);
        NgAfterChange(Vcb);
    }
    NgReleaseCore(Vcb);
    return Err ? NgErrnoToStatus(Err) : STATUS_SUCCESS;
}

static NTSTATUS NgSetDisposition(PNG_FCB Fcb, PNG_CCB Ccb, PFILE_OBJECT FileObject, PFILE_DISPOSITION_INFORMATION D,
                                 BOOLEAN IgnoreReadOnly)
{
    PNG_VCB Vcb = Fcb->Vcb;
    int Empty = 1;
    if (Fcb->IsRoot || !Ccb->NameLength || Fcb->MftNo < 16 || Ccb->ParentMftNo == 11)
        return STATUS_CANNOT_DELETE;   /* the metadata files and $Extend children are never deleted */
    if (!D->DeleteFile)
    {
        Fcb->DeletePending = FALSE;
        FileObject->DeletePending = FALSE;
        return STATUS_SUCCESS;
    }
    NgFillStat(Fcb);
    if (!IgnoreReadOnly && (Fcb->Stat.file_attributes & FILE_ATTRIBUTE_READONLY))
        return STATUS_CANNOT_DELETE;
    if (Fcb->IsDirectory)
    {
        NgAcquireCore(Vcb);
        Empty = NgEnsureNode(Fcb);
        if (!Empty)
            Empty = ngc_dir_empty(Vcb->Core, Fcb->Node);
        NgReleaseCore(Vcb);
        if (Empty != 1)
            return Empty < 0 ? NgErrnoToStatus(Empty) : STATUS_DIRECTORY_NOT_EMPTY;
    }
    else if (!MmFlushImageSection(&Fcb->SectionObjectPointers, MmFlushForDelete))
    {
        return STATUS_CANNOT_DELETE;
    }
    /* The last name of a file whose named stream is open is not deleted (the core cannot evict it). */
    if (!NgMarkDeletePending(Vcb, Fcb, !Fcb->Stream.Length && Fcb->Stat.nlink <= 1))
        return STATUS_SHARING_VIOLATION;
    NgSetDeletePending(Fcb, Ccb);
    FileObject->DeletePending = TRUE;
    return STATUS_SUCCESS;
}

static BOOLEAN NgSameName(const WCHAR *A, USHORT ALen, const WCHAR *B, USHORT BLen)
{
    return ALen == BLen && RtlCompareMemory(A, B, ALen * sizeof(WCHAR)) == ALen * sizeof(WCHAR);
}

/*
 * FileRenameInformation and FileLinkInformation.  A target given as a path arrives with the
 * target's directory already opened (SL_OPEN_TARGET_DIRECTORY) in SetFile.FileObject; a bare
 * name renames within the current directory.  The final component of FileName is the new name.
 */
/* TRUE if a file or directory anywhere below directory DirMftNo has an open handle or a create in
 * progress (64 levels). */
static BOOLEAN NgDirHasOpenFiles(PNG_VCB Vcb, ULONGLONG DirMftNo)
{
    ULONGLONG *Open = NULL;
    ULONG Count = 0, Cap = 0, i, Depth;
    PLIST_ENTRY Entry;
    BOOLEAN Found = FALSE;
    PWCHAR Name;

    /* Snapshot the MFT numbers of every open file and create in progress (the parent walk needs
     * CoreLock, which must not be taken under FcbListLock): size the array, then fill it. */
    ExAcquireFastMutex(&Vcb->FcbListLock);
    for (Entry = Vcb->FcbList.Flink; Entry != &Vcb->FcbList; Entry = Entry->Flink)
    {
        PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, VcbLinks);
        if ((F->OpenHandles || F->Opening) && !F->IsVolume && !F->IsRoot && F->MftNo != DirMftNo)
            Cap++;
    }
    if (Cap)
        Open = ExAllocatePoolWithTag(PagedPool, Cap * sizeof(ULONGLONG), TAG_NTFSNG);
    if (Open)
    {
        for (Entry = Vcb->FcbList.Flink; Entry != &Vcb->FcbList && Count < Cap; Entry = Entry->Flink)
        {
            PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, VcbLinks);
            if ((F->OpenHandles || F->Opening) && !F->IsVolume && !F->IsRoot && F->MftNo != DirMftNo)
                Open[Count++] = F->MftNo;
        }
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);
    if (!Cap)
        return FALSE;
    if (!Open)
        return TRUE;        /* out of memory: refuse rather than rename over open files */
    Name = ExAllocatePoolWithTag(PagedPool, 256 * sizeof(WCHAR), TAG_NTFSNG);
    if (!Name)
    {
        ExFreePoolWithTag(Open, TAG_NTFSNG);
        return TRUE;
    }
    NgAcquireCore(Vcb);
    for (i = 0; i < Count && !Found; i++)
    {
        ULONGLONG MftNo = Open[i], Parent;
        unsigned int Len;
        for (Depth = 0; Depth < 64 && MftNo != 5; Depth++)
        {
            ngc_node *N;
            int Err = ngc_iget(Vcb->Core, MftNo, &N);
            if (Err)
                break;
            Err = ngc_parent_name(N, &Parent, Name, &Len);
            ngc_put(N);
            if (Err)
                break;
            if (Parent == DirMftNo)
            {
                Found = TRUE;
                break;
            }
            MftNo = Parent;
        }
    }
    NgReleaseCore(Vcb);
    ExFreePoolWithTag(Name, TAG_NTFSNG);
    ExFreePoolWithTag(Open, TAG_NTFSNG);
    return Found;
}

/*
 * TRUE if directory DirMftNo is directory AncestorMftNo or lies below it (parents from the first
 * name).  A walk that cannot finish counts as TRUE: the caller refuses the move.
 */
static BOOLEAN NgIsInSubtree(PNG_VCB Vcb, ULONGLONG DirMftNo, ULONGLONG AncestorMftNo)
{
    ULONGLONG MftNo = DirMftNo, Parent;
    ULONG Depth;
    unsigned int Len;
    BOOLEAN In = TRUE;
    PWCHAR Name = ExAllocatePoolWithTag(PagedPool, 256 * sizeof(WCHAR), TAG_NTFSNG);

    if (!Name)
        return TRUE;
    NgAcquireCore(Vcb);
    for (Depth = 0; Depth < 4096; Depth++)
    {
        ngc_node *N;
        int Err;
        if (MftNo == AncestorMftNo)
            break;
        if (MftNo == 5)
        {
            In = FALSE;
            break;
        }
        Err = ngc_iget(Vcb->Core, MftNo, &N);
        if (Err)
            break;
        Err = ngc_parent_name(N, &Parent, Name, &Len);
        ngc_put(N);
        if (Err || Parent == MftNo)
            break;
        MftNo = Parent;
    }
    NgReleaseCore(Vcb);
    ExFreePoolWithTag(Name, TAG_NTFSNG);
    return In;
}

/* What one handle's new name needs, allocated before the rename: the path and a retired-path node. */
typedef struct _NG_RETITLE
{
    PWCHAR Buffer;
    PVOID *Old;
} NG_RETITLE;

/* Frees the parts of Spare[0..Count) not handed out. */
static VOID NgFreeRetitles(NG_RETITLE *Spare, ULONG Count)
{
    ULONG i;
    for (i = 0; Spare && i < Count; i++)
    {
        if (Spare[i].Buffer)
            ExFreePoolWithTag(Spare[i].Buffer, TAG_NTFSNG);
        if (Spare[i].Old)
            ExFreePoolWithTag(Spare[i].Old, TAG_NTFSNG);
    }
    if (Spare)
        ExFreePoolWithTag(Spare, TAG_NTFSNG);
}

/*
 * Gives handle C the name NewPath (NewName in directory NewDirMftNo), all of it or, without an
 * allocation R, none of it (FcbListLock and the file's main resource held).  The old path buffer
 * stays until close for the diagnostic log.  A change-notify registration shares the buffer of
 * the path: FsRtl reads it (length, then bytes, several times) while it reports a change, and
 * only under NotifyPathLock, so buffer and length change together there and a report sees the
 * old name or the new one, never a mix.  The old buffer is not freed, so a reader never lacks one.
 */
static VOID NgRetitleCcb(PNG_VCB Vcb, PNG_CCB C, NG_RETITLE *R, PCUNICODE_STRING NewPath, ULONGLONG NewDirMftNo, PCUNICODE_STRING NewName)
{
    if (!R || !R->Buffer || !R->Old)
    {
        DPRINT1("ntfsng: out of memory, a handle keeps its name from before the rename\n");
        return;
    }
    RtlCopyMemory(R->Buffer, NewPath->Buffer, NewPath->Length);
    R->Old[0] = C->RetiredPaths;
    R->Old[1] = C->Path.Buffer;
    C->RetiredPaths = R->Old;
    NgLockNotifyPath(Vcb);
    C->Path.Buffer = R->Buffer;
    C->Path.Length = NewPath->Length;
    C->Path.MaximumLength = NewPath->Length + sizeof(WCHAR);
    if (C->NotifyPath.Buffer)
        C->NotifyPath = C->Path;
    NgUnlockNotifyPath(Vcb);
    R->Buffer = NULL;
    R->Old = NULL;
    C->ParentMftNo = NewDirMftNo;
    C->NameLength = NewName->Length / sizeof(WCHAR);
    RtlCopyMemory(C->Name, NewName->Buffer, NewName->Length);
}

/* $Extend\$Deleted, looked up or created, its record number kept (CoreLock held). */
static int NgDeletedDirLocked(PNG_VCB Vcb, ngc_node **Out)
{
    struct ngc_stat St;
    int Err = ngc_deleted_dir(Vcb->Core, 1, Out);
    if (!Err)
    {
        ngc_stat(*Out, &St);
        Vcb->DeletedMftNo = St.mft_ref & 0xffffffffffffULL;
    }
    return Err;
}

/*
 * The POSIX delete (FileDispositionInformationEx) at the cleanup of the handle that asked for it, with other handles
 * of the file still open (caller holds the main resource exclusive and CreateGate shared).  As NTFS on Windows 10:
 * - the pending name is the file's last one: it moves to $Extend\$Deleted, named by the file reference and a
 *   sequence number ("\$Extend\$Deleted\00050000000080362B701F0C" is what Windows 10 22H2 names the handles of such
 *   a file).  The record, its data and the cache stay for the open handles; the FCB stays delete pending (Orphan),
 *   and its last cleanup deletes the $Deleted name the classic way, which frees record and clusters.  A crash
 *   before that leaves an ordinary file in $Deleted, which the next mount removes (ngc_purge_deleted), as Windows
 *   does; the metadata journal makes the move itself atomic.
 * - another name is left (a hard link): the name is removed; the file lives on, no longer delete pending.
 * The handles opened by the removed name are Orphaned: they name the file in $Deleted, and a rename or a
 * disposition through them fails.  On a failure the classic pending delete stays.
 */
VOID NgPosixUnlink(PNG_FCB Fcb)
{
    static const WCHAR Hex[] = L"0123456789ABCDEF";
    static const WCHAR DeletedDir[] = L"\\$Extend\\$Deleted\\";
    PNG_VCB Vcb = Fcb->Vcb;
    ngc_node *Dir = NULL, *DelDir = NULL;
    WCHAR Name[24], PathBuf[RTL_NUMBER_OF(DeletedDir) - 1 + RTL_NUMBER_OF(Name)];
    UNICODE_STRING NewName, NewPath;
    NG_RETITLE *Spare = NULL;
    ULONG Spares = 0, Used = 0, i, Seq;
    ULONGLONG Ref = Fcb->Stat.mft_ref;
    BOOLEAN LastName = FALSE;
    PLIST_ENTRY Entry;
    int Err;

    if (Fcb->Orphan || Fcb->Deleted || !Fcb->DeletePending || Fcb->Stream.Length || Fcb->IsRoot || Fcb->IsVolume ||
        Vcb->ReadOnly || !Fcb->HasNode)
        return;
    Seq = (ULONG)InterlockedIncrement(&Vcb->OrphanSeq);
    for (i = 0; i < 16; i++)
        Name[i] = Hex[(Ref >> (60 - 4 * i)) & 0xf];
    for (i = 0; i < 8; i++)
        Name[16 + i] = Hex[(Seq >> (28 - 4 * i)) & 0xf];
    RtlInitEmptyUnicodeString(&NewName, Name, sizeof(Name));
    NewName.Length = sizeof(Name);
    RtlCopyMemory(PathBuf, DeletedDir, sizeof(DeletedDir) - sizeof(WCHAR));
    RtlCopyMemory(PathBuf + RTL_NUMBER_OF(DeletedDir) - 1, Name, sizeof(Name));
    RtlInitEmptyUnicodeString(&NewPath, PathBuf, sizeof(PathBuf));
    NewPath.Length = sizeof(PathBuf);

    /* The handles' new names are allocated first: the move done on disk is not undone. */
    ExAcquireFastMutex(&Vcb->FcbListLock);
    for (Entry = Fcb->CcbList.Flink; Entry != &Fcb->CcbList; Entry = Entry->Flink)
        Spares++;
    ExReleaseFastMutex(&Vcb->FcbListLock);
    if (Spares)
    {
        Spare = ExAllocatePoolWithTag(PagedPool, Spares * sizeof(NG_RETITLE), TAG_NTFSNG);
        if (!Spare)
            return;
        RtlZeroMemory(Spare, Spares * sizeof(NG_RETITLE));
        for (i = 0; i < Spares; i++)
        {
            Spare[i].Buffer = ExAllocatePoolWithTag(PagedPool, NewPath.Length + sizeof(WCHAR), TAG_NTFSNG);
            Spare[i].Old = ExAllocatePoolWithTag(PagedPool, 2 * sizeof(PVOID), TAG_NTFSNG);
            if (!Spare[i].Buffer || !Spare[i].Old)
            {
                NgFreeRetitles(Spare, Spares);
                return;
            }
        }
    }

    NgAcquireCore(Vcb);
    Err = NgEnsureNode(Fcb);
    if (!Err)
        Err = ngc_iget(Vcb->Core, Fcb->DelParentMftNo, &Dir);
    if (!Err)
    {
        LastName = Fcb->IsDirectory || ngc_links(Fcb->Node) <= 1;
        if (!LastName)
            Err = ngc_unlink(Vcb->Core, Dir, Fcb->DelName, Fcb->DelNameLength, Fcb->Node);
        else if (Fcb->IsDirectory && ngc_dir_empty(Vcb->Core, Fcb->Node) != 1)
            Err = -NGC_ENOTEMPTY;   /* the last cleanup decides */
        else if (!(Err = NgDeletedDirLocked(Vcb, &DelDir)))
            Err = ngc_rename(Vcb->Core, Dir, Fcb->DelName, Fcb->DelNameLength, Fcb->Node, DelDir, Name,
                             RTL_NUMBER_OF(Name), NULL);
        if (!Err)
        {
            if (!Fcb->IsDirectory)
                NgTunnelAdd(Vcb, Fcb->DelParentMftNo, Fcb->DelName, Fcb->DelNameLength, Fcb->Stat.crtime);
            ngc_stat(Fcb->Node, &Fcb->Stat);
            NgAfterChange(Vcb);
        }
        ngc_put(Dir);
    }
    if (DelDir)
        ngc_put(DelDir);
    NgReleaseCore(Vcb);
    if (Err)
    {
        DPRINT1("ntfsng: POSIX delete of %I64x failed %d, the delete stays pending until the last close\n", Fcb->MftNo, Err);
        NgFreeRetitles(Spare, Spares);
        return;
    }
    if (Fcb->DelPath.Buffer)
        NgNotify(Vcb, &Fcb->DelPath, Fcb->IsDirectory ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME,
                 FILE_ACTION_REMOVED);
    ExAcquireFastMutex(&Vcb->FcbListLock);
    for (Entry = Fcb->CcbList.Flink; Entry != &Fcb->CcbList; Entry = Entry->Flink)
    {
        PNG_CCB C = CONTAINING_RECORD(Entry, NG_CCB, FcbLinks);
        if (C->Orphaned)
            continue;
        if (LastName || (C->ParentMftNo == Fcb->DelParentMftNo &&
                         NgSameName(C->Name, C->NameLength, Fcb->DelName, Fcb->DelNameLength)))
        {
            /* No create gets past a pending delete, so no handle came after the count; should one have, it keeps its
             * old name and is not marked (the Orphan FCB still refuses a rename or disposition through it). */
            if (Used < Spares)
            {
                NgRetitleCcb(Vcb, C, &Spare[Used++], &NewPath, Vcb->DeletedMftNo, &NewName);
                C->Orphaned = TRUE;
            }
            else
            {
                DPRINT1("ntfsng: a handle of %I64x opened after the POSIX delete began keeps its old name\n", Fcb->MftNo);
            }
        }
    }
    if (LastName)
    {
        /* The last cleanup deletes the $Deleted name (NgDeleteNow); nobody watches that directory. */
        Fcb->Orphan = TRUE;
        Fcb->DelParentMftNo = Vcb->DeletedMftNo;
        Fcb->DelNameLength = RTL_NUMBER_OF(Name);
        RtlCopyMemory(Fcb->DelName, Name, sizeof(Name));
    }
    else
    {
        Fcb->DeletePending = FALSE;
    }
    if (Fcb->DelPath.Buffer)
    {
        ExFreePoolWithTag(Fcb->DelPath.Buffer, TAG_NTFSNG);
        RtlZeroMemory(&Fcb->DelPath, sizeof(Fcb->DelPath));
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);
    NgFreeRetitles(Spare, Spares);
}

static NTSTATUS NgRenameOrLink(PNG_FCB Fcb, PNG_CCB Ccb, PIO_STACK_LOCATION Stack, PFILE_RENAME_INFORMATION R,
                               ULONG Length, BOOLEAN IsLink, BOOLEAN Check)
{
    PNG_VCB Vcb = Fcb->Vcb;
    PFILE_OBJECT TargetFo = Stack->Parameters.SetFile.FileObject;
    BOOLEAN Replace = Stack->Parameters.SetFile.ReplaceIfExists || R->ReplaceIfExists;
    BOOLEAN CaseOnly = FALSE;
    UNICODE_STRING NewName, NewDirPath, NewPath, OldPath;
    ULONGLONG NewDirMftNo;
    PNG_FCB TargetFcb = NULL;
    ngc_node *OldDir = NULL, *NewDir = NULL, *Target = NULL;
    struct ngc_stat TSt;
    PWCHAR RealT = NULL;
    unsigned int RealTLen = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    NG_RETITLE *Spare = NULL;
    PWCHAR DelPath = NULL;
    ULONG n, i, Spares = 0, Used = 0;
    int Err;

    if (Length < FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        R->FileNameLength > Length - FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName))
        return STATUS_INVALID_PARAMETER;
    if (Fcb->IsRoot || Fcb->IsVolume || Fcb->Stream.Length || !Ccb->NameLength)
        return STATUS_INVALID_PARAMETER;
    if (Fcb->MftNo < 16 || Ccb->ParentMftNo == 11)
        return STATUS_ACCESS_DENIED;   /* metadata files and $Extend children are never renamed or linked */
    if (Fcb->Orphan || Ccb->Orphaned)
        return STATUS_ACCESS_DENIED;   /* its name went with a POSIX delete (Windows 10: STATUS_ACCESS_DENIED) */
    if (IsLink && Fcb->IsDirectory)
        return STATUS_FILE_IS_A_DIRECTORY;
    n = R->FileNameLength / sizeof(WCHAR);
    for (i = n; i > 0 && R->FileName[i - 1] != L'\\'; i--)
        ;
    NewName.Buffer = R->FileName + i;
    NewName.Length = NewName.MaximumLength = (USHORT)((n - i) * sizeof(WCHAR));
    if (!NgValidName(&NewName))
        return STATUS_OBJECT_NAME_INVALID;
    if (TargetFo)
    {
        PNG_FCB Tf = TargetFo->FsContext;
        PNG_CCB Tc = TargetFo->FsContext2;
        if (!Tf || !Tc || !Tf->IsDirectory || Tf->Vcb != Vcb)
            return STATUS_INVALID_PARAMETER;
        NewDirMftNo = Tf->MftNo;
        if (Tf->Orphan)
            return STATUS_DELETE_PENDING;
    }
    else
    {
        if (i)
            return STATUS_INVALID_PARAMETER;
        NewDirMftNo = Ccb->ParentMftNo;
    }
    if (Vcb->DeletedMftNo && NewDirMftNo == Vcb->DeletedMftNo)
        return STATUS_ACCESS_DENIED;   /* $Extend\$Deleted holds only the files POSIX deletes put there */
    /* The new name, from the target directory handle's current name (FcbListLock: a rename of that
     * directory through another handle changes it). */
    RealT = ExAllocatePoolWithTag(PagedPool, 256 * sizeof(WCHAR), TAG_NTFSNG);
    ExAcquireFastMutex(&Vcb->FcbListLock);
    if (TargetFo)
    {
        NewDirPath = ((PNG_CCB)TargetFo->FsContext2)->Path;
    }
    else
    {
        NewDirPath = Ccb->Path;
        while (NewDirPath.Length > sizeof(WCHAR) && NewDirPath.Buffer[NewDirPath.Length / sizeof(WCHAR) - 1] != L'\\')
            NewDirPath.Length -= sizeof(WCHAR);
        if (NewDirPath.Length > sizeof(WCHAR))
            NewDirPath.Length -= sizeof(WCHAR);
    }
    NewPath.Buffer = NULL;
    if ((ULONG)NewDirPath.Length + NewName.Length + 2 * sizeof(WCHAR) <= MAXUSHORT)
    {
        NewPath.MaximumLength = NewDirPath.Length + NewName.Length + 2 * sizeof(WCHAR);
        NewPath.Buffer = ExAllocatePoolWithTag(PagedPool, NewPath.MaximumLength, TAG_NTFSNG);
    }
    if (NewPath.Buffer)
    {
        NewPath.Length = 0;
        RtlAppendUnicodeStringToString(&NewPath, &NewDirPath);
        if (NewPath.Length != sizeof(WCHAR))
            RtlAppendUnicodeToString(&NewPath, L"\\");
        RtlAppendUnicodeStringToString(&NewPath, &NewName);
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);
    if (!NewPath.Buffer || !RealT)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    /* Look the new name up first: a replaced file's caches are dealt with outside CoreLock. */
    NgAcquireCore(Vcb);
    Err = ngc_iget(Vcb->Core, NewDirMftNo, &NewDir);
    if (!Err)
    {
        Err = ngc_lookup(Vcb->Core, NewDir, NewName.Buffer, NewName.Length / sizeof(WCHAR), &Target, RealT, &RealTLen);
        if (!Err)
            ngc_stat(Target, &TSt);
        else if (Err == -NGC_ENOENT)
            Err = 0;
    }
    NgReleaseCore(Vcb);
    if (Err)
    {
        Status = NgErrnoToStatus(Err);
        goto out;
    }
    if (Target && (TSt.mft_ref & 0xffffffffffffULL) < 16)
    {
        Status = STATUS_ACCESS_DENIED;   /* never replace a metadata file */
        goto out;
    }
    if (Target)
    {
        if ((TSt.mft_ref & 0xffffffffffffULL) == Fcb->MftNo)
        {
            if (IsLink)
            {
                /* The name is already a link to this file: replacing it with itself changes nothing. */
                Status = Replace ? STATUS_SUCCESS : STATUS_OBJECT_NAME_COLLISION;
                goto out;
            }
            if (NewDirMftNo != Ccb->ParentMftNo)
            {
                Status = Replace ? STATUS_ACCESS_DENIED : STATUS_OBJECT_NAME_COLLISION;
                goto out;
            }
            if (NgSameName(NewName.Buffer, NewName.Length / sizeof(WCHAR), Ccb->Name, Ccb->NameLength))
                goto out;   /* renaming to itself */
            CaseOnly = TRUE;
        }
        else
        {
            if (!Replace)
            {
                Status = STATUS_OBJECT_NAME_COLLISION;
                goto out;
            }
            if (TSt.is_dir || (TSt.file_attributes & FILE_ATTRIBUTE_READONLY))
            {
                Status = STATUS_ACCESS_DENIED;
                goto out;
            }
            if (!NgRetireStreams(Vcb, TSt.mft_ref & 0xffffffffffffULL, NULL, FALSE))
            {
                Status = STATUS_ACCESS_DENIED;      /* a named stream of the target is open */
                goto out;
            }
            if (Check)
            {
                /* Replacing a file deletes it: DELETE on it or FILE_DELETE_CHILD on its directory. */
                PSECURITY_DESCRIPTOR TargetSd = NULL, DirSd = NULL;
                NG_SHARED_HOLD Hold;
                NgAcquireCoreShared(Vcb, &Hold);
                Status = NgReadSecurity(Vcb, Target, &TargetSd);
                if (NT_SUCCESS(Status))
                    Status = NgReadSecurity(Vcb, NewDir, &DirSd);
                NgReleaseCoreShared(Vcb, &Hold);
                if (NT_SUCCESS(Status))
                    Status = NgCheckDeleteEntry(TargetSd, DirSd);
                if (TargetSd)
                    ExFreePoolWithTag(TargetSd, TAG_NTFSNG);
                if (DirSd)
                    ExFreePoolWithTag(DirSd, TAG_NTFSNG);
                if (!NT_SUCCESS(Status))
                    goto out;
            }
            TargetFcb = NgFindFcb(Vcb, TSt.mft_ref & 0xffffffffffffULL);
            if (TargetFcb)
            {
                if (TargetFcb->OpenHandles || !MmFlushImageSection(&TargetFcb->SectionObjectPointers, MmFlushForDelete))
                {
                    Status = STATUS_ACCESS_DENIED;
                    goto out;
                }
                if ((TSt.nlink <= 1) &&
                    (TargetFcb->SectionObjectPointers.SharedCacheMap || TargetFcb->SectionObjectPointers.DataSectionObject))
                    NgPurgeFrom(TargetFcb, 0);
            }
        }
    }

    if (!IsLink && Fcb->IsDirectory && NgDirHasOpenFiles(Vcb, Fcb->MftNo))
    {
        /* As on Windows: a directory with open files below it is not renamed. */
        Status = STATUS_ACCESS_DENIED;
        goto out;
    }
    if (!IsLink)
    {
        /* The new names of the file's handles (and of a pending delete) are allocated first: a rename
         * done on disk is not undone. */
        PLIST_ENTRY Entry;
        ExAcquireFastMutex(&Vcb->FcbListLock);
        for (Entry = Fcb->CcbList.Flink; Entry != &Fcb->CcbList; Entry = Entry->Flink)
            Spares++;
        ExReleaseFastMutex(&Vcb->FcbListLock);
        Spares = max(Spares, 1);    /* this handle's is Spare[0] */
        Spare = ExAllocatePoolWithTag(PagedPool, Spares * sizeof(NG_RETITLE), TAG_NTFSNG);
        if (Spare)
            RtlZeroMemory(Spare, Spares * sizeof(NG_RETITLE));
        for (i = 0; Spare && i < Spares; i++)
        {
            Spare[i].Buffer = ExAllocatePoolWithTag(PagedPool, NewPath.Length + sizeof(WCHAR), TAG_NTFSNG);
            Spare[i].Old = ExAllocatePoolWithTag(PagedPool, 2 * sizeof(PVOID), TAG_NTFSNG);
            if (!Spare[i].Buffer || !Spare[i].Old)
                break;
        }
        if (Fcb->DeletePending)
            DelPath = ExAllocatePoolWithTag(PagedPool, NewPath.Length + sizeof(WCHAR), TAG_NTFSNG);
        if (!Spare || i < Spares || (Fcb->DeletePending && !DelPath))
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
    }
    NgAcquireCore(Vcb);
    /* A directory cannot move into itself or below itself; checked under the lock the move holds. */
    if (!IsLink && Fcb->IsDirectory && NgIsInSubtree(Vcb, NewDirMftNo, Fcb->MftNo))
    {
        NgReleaseCore(Vcb);
        Status = STATUS_INVALID_PARAMETER;
        goto out;
    }
    Err = NgEnsureNode(Fcb);
    if (!Err)
        Err = ngc_iget(Vcb->Core, Ccb->ParentMftNo, &OldDir);
    if (!Err && Target && !CaseOnly)
    {
        /* The replaced file's last name goes: not while its named stream is open or being opened. */
        struct ngc_stat Now;
        ngc_stat(Target, &Now);
        if (Now.nlink <= 1 && !NgRetireStreams(Vcb, TSt.mft_ref & 0xffffffffffffULL, NULL, TRUE))
            Err = -NGC_EBUSY;
    }
    if (!Err)
    {
        if (IsLink)
        {
            if (Target)
                Err = ngc_unlink(Vcb->Core, NewDir, RealT, RealTLen, Target);
            if (!Err)
                Err = ngc_link(Vcb->Core, Fcb->Node, NewDir, NewName.Buffer, NewName.Length / sizeof(WCHAR));
        }
        else if (CaseOnly)
        {
            /* The index collates case-insensitively: go through a temporary name. */
            WCHAR Tmp[24], HexBuf[12];
            UNICODE_STRING T, Hex;
            RtlInitEmptyUnicodeString(&T, Tmp, sizeof(Tmp));
            RtlInitEmptyUnicodeString(&Hex, HexBuf, sizeof(HexBuf));
            RtlAppendUnicodeToString(&T, L"~ngren.");
            RtlIntegerToUnicodeString((ULONG)Fcb->MftNo, 16, &Hex);
            RtlAppendUnicodeStringToString(&T, &Hex);
            Err = ngc_rename(Vcb->Core, OldDir, Ccb->Name, Ccb->NameLength, Fcb->Node, NewDir,
                             T.Buffer, T.Length / sizeof(WCHAR), NULL);
            if (!Err)
                Err = ngc_rename(Vcb->Core, NewDir, T.Buffer, T.Length / sizeof(WCHAR), Fcb->Node, NewDir,
                                 NewName.Buffer, NewName.Length / sizeof(WCHAR), NULL);
        }
        else if (Target && !NgSameName(NewName.Buffer, NewName.Length / sizeof(WCHAR), RealT, (USHORT)RealTLen))
        {
            /* The core unlinks a replaced target by the new name, which must then be its exact name:
             * when only the case differs, unlink the target by its own name first. */
            Err = ngc_unlink(Vcb->Core, NewDir, RealT, RealTLen, Target);
            if (!Err)
                Err = ngc_rename(Vcb->Core, OldDir, Ccb->Name, Ccb->NameLength, Fcb->Node, NewDir,
                                 NewName.Buffer, NewName.Length / sizeof(WCHAR), NULL);
        }
        else
        {
            Err = ngc_rename(Vcb->Core, OldDir, Ccb->Name, Ccb->NameLength, Fcb->Node, NewDir,
                             NewName.Buffer, NewName.Length / sizeof(WCHAR), CaseOnly ? NULL : Target);
        }
    }
    if (!Err && !IsLink)
    {
        NgMakeShortName(Vcb, NewDir, Fcb->Node, NewName.Buffer, NewName.Length / sizeof(WCHAR));
        if (!Fcb->IsDirectory)
        {
            /* Windows 10 (measured): renaming a file sets its archive attribute (also after SetFileAttributes(NORMAL)). */
            static const long long NoTimes[4] = { 0, 0, 0, 0 };
            ngc_set_info(Vcb->Core, Fcb->Node, NoTimes, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE);
            /* The old name leaves its creation time behind; the new name may take one over. */
            LONGLONG Crtime = Fcb->Stat.crtime;
            NgTunnelApply(Vcb, NewDir, Fcb->Node, &NewName);
            NgTunnelAdd(Vcb, Ccb->ParentMftNo, Ccb->Name, Ccb->NameLength, Crtime);
        }
    }
    if (Target && !CaseOnly && NgNodeGone(Target))
    {
        /* The replaced file's record is free (also when a later step failed): its FCBs go, a node
         * first (a referenced inode keeps the freed record and clusters in use).  With another
         * name left it stays as it is. */
        if (TargetFcb)
        {
            NgParkNode(TargetFcb);
            TargetFcb->Deleted = TRUE;
            NgUnlistFcb(TargetFcb);
        }
        NgDeleteStreams(Vcb, TSt.mft_ref & 0xffffffffffffULL, NULL);
    }
    if (!Err)
        ngc_stat(Fcb->Node, &Fcb->Stat);
    if (Target)
    {
        ngc_put(Target);
        Target = NULL;
    }
    if (OldDir)
        ngc_put(OldDir);
    NgAfterChange(Vcb);
    NgReleaseCore(Vcb);
    if (Err)
    {
        DPRINT1("ntfsng: %s of %I64x failed %d\n", IsLink ? "link" : "rename", Fcb->MftNo, Err);
        Status = NgErrnoToStatus(Err);
        goto out;
    }
    if (IsLink)
    {
        NgNotify(Vcb, &NewPath, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_ADDED);
    }
    else
    {
        /* Within one directory a rename is reported as old/new name; a move to another directory
         * as a removal from the old one and an addition to the new one (what Win32 watchers expect). */
        BOOLEAN Moved = NewDirMftNo != Ccb->ParentMftNo;
        ULONG Filter = Fcb->IsDirectory ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME;
        PLIST_ENTRY Entry;
        OldPath = Ccb->Path;
        NgNotify(Vcb, &OldPath, Filter, Moved ? FILE_ACTION_REMOVED : FILE_ACTION_RENAMED_OLD_NAME);
        /* Every handle opened by the old name takes the new one (a directory has a single name;
         * a file's other hard links keep theirs), this handle last: the others are matched
         * against its old name. */
        ExAcquireFastMutex(&Vcb->FcbListLock);
        Used = 1;   /* Spare[0] is this handle's */
        for (Entry = Fcb->CcbList.Flink; Entry != &Fcb->CcbList; Entry = Entry->Flink)
        {
            PNG_CCB C = CONTAINING_RECORD(Entry, NG_CCB, FcbLinks);
            if (C != Ccb && (Fcb->IsDirectory || (C->ParentMftNo == Ccb->ParentMftNo &&
                                                  NgSameName(C->Name, C->NameLength, Ccb->Name, Ccb->NameLength))))
            {
                /* No create runs (CreateGate), so no handle came after the count. */
                NgRetitleCcb(Vcb, C, Used < Spares ? &Spare[Used++] : NULL, &NewPath, NewDirMftNo, &NewName);
            }
        }
        if (DelPath && Fcb->DelParentMftNo == Ccb->ParentMftNo &&
            NgSameName(Fcb->DelName, Fcb->DelNameLength, Ccb->Name, Ccb->NameLength))
        {
            /* A pending delete of the old name removes the new one at the last cleanup. */
            RtlCopyMemory(DelPath, NewPath.Buffer, NewPath.Length);
            if (Fcb->DelPath.Buffer)
                ExFreePoolWithTag(Fcb->DelPath.Buffer, TAG_NTFSNG);
            Fcb->DelPath.Buffer = DelPath;
            Fcb->DelPath.Length = NewPath.Length;
            Fcb->DelPath.MaximumLength = NewPath.Length + sizeof(WCHAR);
            DelPath = NULL;
            Fcb->DelParentMftNo = NewDirMftNo;
            Fcb->DelNameLength = NewName.Length / sizeof(WCHAR);
            RtlCopyMemory(Fcb->DelName, NewName.Buffer, NewName.Length);
        }
        NgRetitleCcb(Vcb, Ccb, &Spare[0], &NewPath, NewDirMftNo, &NewName);
        ExReleaseFastMutex(&Vcb->FcbListLock);
        NgNotify(Vcb, &NewPath, Filter, Moved ? FILE_ACTION_ADDED : FILE_ACTION_RENAMED_NEW_NAME);
    }
out:
    if (Target || NewDir)
    {
        NgAcquireCore(Vcb);
        if (Target)
            ngc_put(Target);
        if (NewDir)
            ngc_put(NewDir);
        NgReleaseCore(Vcb);
    }
    if (TargetFcb)
        NgDereferenceFcb(TargetFcb);
    NgFreeRetitles(Spare, Spares);
    if (DelPath)
        ExFreePoolWithTag(DelPath, TAG_NTFSNG);
    if (NewPath.Buffer)
        ExFreePoolWithTag(NewPath.Buffer, TAG_NTFSNG);
    if (RealT)
        ExFreePoolWithTag(RealT, TAG_NTFSNG);
    return Status;
}

NTSTATUS NgSetInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = Stack->FileObject;
    PNG_FCB Fcb = FileObject->FsContext;
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    FILE_INFORMATION_CLASS Class = Stack->Parameters.SetFile.FileInformationClass;
    ULONG Length = Stack->Parameters.SetFile.Length;
    PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS Status;

    /* Moving the file pointer is the only change that does not touch the volume. */
    if (Class == FilePositionInformation)
    {
        PFILE_POSITION_INFORMATION P = Buffer;
        if (Length < sizeof(*P))
            return STATUS_INVALID_PARAMETER;
        FileObject->CurrentByteOffset = P->CurrentByteOffset;
        return STATUS_SUCCESS;
    }
    if (Vcb->ReadOnly)
        return STATUS_MEDIA_WRITE_PROTECTED;
    if (!Fcb || Fcb->IsVolume || !Fcb->HasNode)
        return STATUS_INVALID_PARAMETER;

    switch ((ULONG)Class)   /* an unnamed class (64) is a case below */
    {
        case FileBasicInformation:
            if (Length < sizeof(FILE_BASIC_INFORMATION))
                return STATUS_INVALID_PARAMETER;
            ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
            Status = NgSetBasic(Fcb, Buffer, (FileObject->Flags & FO_FILE_MODIFIED) != 0);
            ExReleaseResourceLite(Fcb->Header.Resource);
            return Status;
        case FileEndOfFileInformation:
        case FileAllocationInformation:
        {
            LONGLONG New = ((PLARGE_INTEGER)Buffer)->QuadPart;
            if (Length < sizeof(LARGE_INTEGER))
                return STATUS_INVALID_PARAMETER;
            if (Fcb->IsDirectory)
                return STATUS_INVALID_PARAMETER;
            ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
            if (Class == FileEndOfFileInformation && Stack->Parameters.SetFile.AdvanceOnly)
            {
                /* Cc advancing the on-disk EOF/VDL: the core's size is already current. */
                Status = STATUS_SUCCESS;
            }
            else if (Class == FileAllocationInformation && New >= Fcb->Header.FileSize.QuadPart)
            {
                /* Preallocation beyond EOF is not kept (allocation follows the file size). */
                Status = STATUS_SUCCESS;
            }
            else
            {
                Status = NgSetFileSize(Fcb, FileObject, New);
            }
            ExReleaseResourceLite(Fcb->Header.Resource);
            return Status;
        }
        case FileValidDataLengthInformation:
        {
            /*
             * SetFileValidData: needs SeManageVolumePrivilege; the new length may not go below the
             * current valid data length nor past the end of file.  The driver never exposes stale
             * clusters (unwritten ranges read as zeros), so accepting it changes nothing on disk;
             * only the logical valid data length is tracked for these checks.
             */
            LONGLONG New;
            if (Length < sizeof(FILE_VALID_DATA_LENGTH_INFORMATION))
                return STATUS_INVALID_PARAMETER;
            if (!SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_MANAGE_VOLUME_PRIVILEGE), Irp->RequestorMode))
                return STATUS_PRIVILEGE_NOT_HELD;
            New = ((PFILE_VALID_DATA_LENGTH_INFORMATION)Buffer)->ValidDataLength.QuadPart;
            if (Fcb->IsDirectory || New <= 0 || New < Fcb->LogicalVdl || New > Fcb->Header.FileSize.QuadPart)
                return STATUS_INVALID_PARAMETER;
            Fcb->LogicalVdl = New;
            return STATUS_SUCCESS;
        }
        case FileDispositionInformation:
            if (Length < sizeof(FILE_DISPOSITION_INFORMATION))
                return STATUS_INVALID_PARAMETER;
            if (Fcb->Orphan || ((PNG_CCB)FileObject->FsContext2)->Orphaned)
                return STATUS_FILE_DELETED;     /* Windows 10, after a POSIX delete removed the name */
            ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
            Status = NgSetDisposition(Fcb, FileObject->FsContext2, FileObject, Buffer, FALSE);
            if (NT_SUCCESS(Status))
                ((PNG_CCB)FileObject->FsContext2)->PosixDelete = FALSE;   /* the classic class replaces a POSIX request */
            ExReleaseResourceLite(Fcb->Header.Resource);
            return Status;
        case NG_FILE_DISPOSITION_INFORMATION_EX:
        {
            /*
             * Windows 10 (DeleteFile and RemoveDirectory use it).  Measured on Windows 10 22H2 NTFS:
             * - DELETE | POSIX_SEMANTICS marks the delete pending as the classic class does; at the cleanup of this
             *   handle a delete still pending removes the name at once, whatever other handles (opened with
             *   FILE_SHARE_DELETE) stay open: the directory can then be removed and the name created again, the
             *   other handles keep reading and writing the nameless file until the last one closes
             *   (NgPosixUnlink).  Until this handle's cleanup the name stays (delete pending).
             * - POSIX skips the user-mapped data section check, FORCE_IMAGE_SECTION_CHECK makes it (ReactOS's
             *   MmFlushImageSection checks image sections only, which both do: a mapped image cannot be deleted).
             * - FILE_DISPOSITION_ON_CLOSE sets or clears the FILE_DELETE_ON_CLOSE of this handle (POSIX: a POSIX
             *   delete at its cleanup), only on a handle opened with it: STATUS_NOT_SUPPORTED otherwise.
             * - Unknown flags: STATUS_NOT_SUPPORTED.  After a POSIX delete removed the name: STATUS_FILE_DELETED.
             * A named stream has no POSIX delete: its delete stays pending until its last handle closes.
             */
            PNG_CCB Ccb = FileObject->FsContext2;
            ULONG Flags;
            FILE_DISPOSITION_INFORMATION Disp;
            if (Length < sizeof(ULONG))
                return STATUS_INVALID_PARAMETER;
            Flags = *(PULONG)Buffer;
            if (Flags & ~NG_DISP_VALID_MASK)
                return STATUS_NOT_SUPPORTED;
            if (Fcb->Orphan || Ccb->Orphaned)
                return STATUS_FILE_DELETED;
            ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
            if (Flags & NG_DISP_ON_CLOSE)
            {
                if (!Ccb->OpenedDeleteOnClose)
                {
                    Status = STATUS_NOT_SUPPORTED;
                }
                else
                {
                    Ccb->DeleteOnClose = (Flags & NG_DISP_DELETE) != 0;
                    Ccb->PosixOnClose = (Flags & NG_DISP_DELETE) && (Flags & NG_DISP_POSIX_SEMANTICS);
                    Status = STATUS_SUCCESS;
                }
                ExReleaseResourceLite(Fcb->Header.Resource);
                return Status;
            }
            Disp.DeleteFile = (Flags & NG_DISP_DELETE) != 0;
            Status = NgSetDisposition(Fcb, Ccb, FileObject, &Disp, (Flags & NG_DISP_IGNORE_READONLY_ATTRIBUTE) != 0);
            if (NT_SUCCESS(Status))
                Ccb->PosixDelete = Disp.DeleteFile && (Flags & NG_DISP_POSIX_SEMANTICS) && !Fcb->Stream.Length;
            ExReleaseResourceLite(Fcb->Header.Resource);
            return Status;
        }
        case FileRenameInformation:
        case FileLinkInformation:
            /* A rename holds CreateGate exclusive (FastFAT holds the VCB): no create runs, so every
             * handle of the file exists to be renamed and none takes its name from one being renamed,
             * and renames do not overlap. */
            if (Class == FileRenameInformation)
                ExAcquireResourceExclusiveLite(&Fcb->Vcb->CreateGate, TRUE);
            ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
            Status = NgRenameOrLink(Fcb, FileObject->FsContext2, Stack, Buffer, Length, Class == FileLinkInformation,
                                    Irp->RequestorMode != KernelMode);
            ExReleaseResourceLite(Fcb->Header.Resource);
            if (Class == FileRenameInformation)
                ExReleaseResourceLite(&Fcb->Vcb->CreateGate);
            return Status;
        default:
            return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS NgQueryVolumeInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    ULONG Length = Stack->Parameters.QueryVolume.Length, Used = 0;
    PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG SectorsPerCluster = Vcb->Info.cluster_size / Vcb->SectorSize;

    if (DeviceObject == NgGlobal.ControlDevice)
        return STATUS_INVALID_DEVICE_REQUEST;
    /* Zero the reply buffer so uninitialized pool padding never reaches user mode. */
    if (Buffer)
        RtlZeroMemory(Buffer, Length);
    if (!Vcb->ReadOnly)
    {
        NgAcquireCore(Vcb);
        ngc_volinfo(Vcb->Core, &Vcb->Info);
        NgReleaseCore(Vcb);
    }
    switch (Stack->Parameters.QueryVolume.FsInformationClass)
    {
        case FileFsVolumeInformation:
        {
            PFILE_FS_VOLUME_INFORMATION V = Buffer;
            ULONG Fixed = FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel), Copy;
            WCHAR Label[MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
            KIRQL Irql;
            if (Length < Fixed)
                return STATUS_BUFFER_TOO_SMALL;
            if (Vcb->LabelStale)
            {
                /* Reading the label at mount ran out of memory: read it again, read-only volumes included. */
                NgAcquireCore(Vcb);
                if (Vcb->LabelStale)
                {
                    ngc_volinfo(Vcb->Core, &Vcb->Info);
                    if (Vcb->Info.label_valid)
                    {
                        IoAcquireVpbSpinLock(&Irql);
                        Vcb->Vpb->VolumeLabelLength = (USHORT)(Vcb->Info.label_len * sizeof(WCHAR));
                        RtlCopyMemory(Vcb->Vpb->VolumeLabel, Vcb->Info.label, Vcb->Vpb->VolumeLabelLength);
                        IoReleaseVpbSpinLock(Irql);
                        Vcb->LabelStale = FALSE;
                    }
                }
                NgReleaseCore(Vcb);
            }
            V->VolumeCreationTime.QuadPart = 0;
            V->VolumeSerialNumber = Vcb->Vpb->SerialNumber;
            V->SupportsObjects = FALSE;
            IoAcquireVpbSpinLock(&Irql);
            RtlCopyMemory(Label, Vcb->Vpb->VolumeLabel, Vcb->Vpb->VolumeLabelLength);
            V->VolumeLabelLength = Vcb->Vpb->VolumeLabelLength;
            IoReleaseVpbSpinLock(Irql);
            Copy = min(V->VolumeLabelLength, Length - Fixed);
            RtlCopyMemory(V->VolumeLabel, Label, Copy);
            Used = Fixed + Copy;
            if (Copy < V->VolumeLabelLength)
                Status = STATUS_BUFFER_OVERFLOW;
            break;
        }
        case FileFsSizeInformation:
        {
            PFILE_FS_SIZE_INFORMATION S = Buffer;
            if (Length < sizeof(*S))
                return STATUS_BUFFER_TOO_SMALL;
            S->TotalAllocationUnits.QuadPart = Vcb->Info.total_clusters;
            S->AvailableAllocationUnits.QuadPart = Vcb->Info.free_clusters;
            S->SectorsPerAllocationUnit = SectorsPerCluster;
            S->BytesPerSector = Vcb->SectorSize;
            Used = sizeof(*S);
            break;
        }
        case FileFsFullSizeInformation:
        {
            PFILE_FS_FULL_SIZE_INFORMATION S = Buffer;
            if (Length < sizeof(*S))
                return STATUS_BUFFER_TOO_SMALL;
            S->TotalAllocationUnits.QuadPart = Vcb->Info.total_clusters;
            S->CallerAvailableAllocationUnits.QuadPart = Vcb->Info.free_clusters;
            S->ActualAvailableAllocationUnits.QuadPart = Vcb->Info.free_clusters;
            S->SectorsPerAllocationUnit = SectorsPerCluster;
            S->BytesPerSector = Vcb->SectorSize;
            Used = sizeof(*S);
            break;
        }
        case FileFsDeviceInformation:
        {
            PFILE_FS_DEVICE_INFORMATION D = Buffer;
            if (Length < sizeof(*D))
                return STATUS_BUFFER_TOO_SMALL;
            D->DeviceType = FILE_DEVICE_DISK;
            D->Characteristics = Vcb->StorageDevice->Characteristics;
            Used = sizeof(*D);
            break;
        }
        case FileFsAttributeInformation:
        {
            PFILE_FS_ATTRIBUTE_INFORMATION A = Buffer;
            static const WCHAR Name[] = L"NTFS";
            ULONG Fixed = FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName), Copy;
            if (Length < Fixed)
                return STATUS_BUFFER_TOO_SMALL;
            /* What the driver implements of what Windows NTFS reports: no case-sensitive lookup,
             * compression, sparse files, quotas, object IDs, EAs, encryption or USN journal.
             * FILE_PERSISTENT_ACLS waits for per-user recycle bin ACLs in shell32.  Reparse
             * points need an NTFS 3.x volume ($Extend\$Reparse). */
            A->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK |
                                      FILE_NAMED_STREAMS | FILE_SUPPORTS_HARD_LINKS |
                                      FILE_SUPPORTS_OPEN_BY_FILE_ID |
                                      (Vcb->MajorVersion >= 3 ? FILE_SUPPORTS_REPARSE_POINTS : 0) |
                                      (Vcb->ReadOnly ? FILE_READ_ONLY_VOLUME : 0);
            A->MaximumComponentNameLength = 255;
            /* On a short buffer the length reports what was copied (as FAT and the apitest expect). */
            Copy = min(sizeof(Name) - sizeof(WCHAR), Length - Fixed);
            A->FileSystemNameLength = Copy;
            RtlCopyMemory(A->FileSystemName, Name, Copy);
            Used = Fixed + Copy;
            if (Copy < sizeof(Name) - sizeof(WCHAR))
                Status = STATUS_BUFFER_OVERFLOW;
            break;
        }
        default:
            return STATUS_INVALID_PARAMETER;
    }
    Irp->IoStatus.Information = Used;
    return Status;
}

/*
 * IRP_MJ_SET_VOLUME_INFORMATION.  Only the label can be set, and only through a volume handle (the
 * I/O manager has checked for write access).  As on Windows, the label is up to 32 characters of any
 * kind, stored as given; an odd byte count is refused, as Windows 10 does.  The change is a journaled
 * metadata update like any other.  A locked volume refuses it (the lock leaves the volume flushed and
 * quiet for its holder, who may write the disk directly).
 */
NTSTATUS NgSetVolumeInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    PNG_FCB Fcb = Stack->FileObject ? Stack->FileObject->FsContext : NULL;
    ULONG Length = Stack->Parameters.SetVolume.Length;
    PFILE_FS_LABEL_INFORMATION Info = Irp->AssociatedIrp.SystemBuffer;
    ULONG Fixed = FIELD_OFFSET(FILE_FS_LABEL_INFORMATION, VolumeLabel);
    KIRQL Irql;
    int Err;

    if (DeviceObject == NgGlobal.ControlDevice)
        return STATUS_INVALID_DEVICE_REQUEST;
    if (Stack->Parameters.SetVolume.FsInformationClass != FileFsLabelInformation)
        return Vcb->ReadOnly ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_INVALID_DEVICE_REQUEST;
    if (!Fcb || !Fcb->IsVolume)
        return STATUS_ACCESS_DENIED;
    if (Length < Fixed || Info->VolumeLabelLength > Length - Fixed)
        return STATUS_INVALID_PARAMETER;
    if ((Info->VolumeLabelLength & 1) || Info->VolumeLabelLength > NGC_LABEL_MAX * sizeof(WCHAR))
        return STATUS_INVALID_VOLUME_LABEL;
    if (Vcb->ReadOnly || Vcb->Damaged)
        return STATUS_MEDIA_WRITE_PROTECTED;

    NgAcquireCore(Vcb);
    /*
     * Not while the volume is locked, nor after its lock holder wrote the disk directly: the holder owns
     * the disk then, and nothing of the mounted state may be written over what it wrote.
     */
    if (Vcb->LockedBy || Vcb->RawWritten)
    {
        NgReleaseCore(Vcb);
        return STATUS_ACCESS_DENIED;
    }
    Err = ngc_set_label(Vcb->Core, (const unsigned short *)Info->VolumeLabel, Info->VolumeLabelLength / sizeof(WCHAR));
    if (!Err)
    {
        IoAcquireVpbSpinLock(&Irql);
        RtlCopyMemory(Vcb->Vpb->VolumeLabel, Info->VolumeLabel, Info->VolumeLabelLength);
        Vcb->Vpb->VolumeLabelLength = (USHORT)Info->VolumeLabelLength;
        IoReleaseVpbSpinLock(Irql);
        Vcb->LabelStale = FALSE;
        NgAfterChange(Vcb);
    }
    NgReleaseCore(Vcb);
    return NgErrnoToStatus(Err);
}
