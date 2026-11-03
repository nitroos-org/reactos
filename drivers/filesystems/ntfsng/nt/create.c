/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IRP_MJ_CREATE, IRP_MJ_CLEANUP (delete on last close), IRP_MJ_CLOSE
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ntfsng.h"

/* MFT records below this are the NTFS metadata files ($MFT, $LogFile, ...). */
#define NG_FIRST_USER_FILE 16

static PNG_CCB NgAllocateCcb(PCUNICODE_STRING Path)
{
    PNG_CCB Ccb = ExAllocatePoolWithTag(PagedPool, sizeof(NG_CCB), TAG_NTFSNG);
    if (!Ccb)
        return NULL;
    RtlZeroMemory(Ccb, sizeof(*Ccb));
    InitializeListHead(&Ccb->FcbLinks);
    Ccb->Path.Buffer = ExAllocatePoolWithTag(PagedPool, Path->Length + sizeof(WCHAR), TAG_NTFSNG);
    if (!Ccb->Path.Buffer)
    {
        ExFreePoolWithTag(Ccb, TAG_NTFSNG);
        return NULL;
    }
    RtlCopyMemory(Ccb->Path.Buffer, Path->Buffer, Path->Length);
    Ccb->Path.Length = Path->Length;
    Ccb->Path.MaximumLength = Path->Length + sizeof(WCHAR);
    return Ccb;
}

static VOID NgFreeCcb(PNG_CCB Ccb)
{
    NgFreeDirSnapshot(Ccb);
    while (Ccb->RetiredPaths)
    {
        PVOID *Node = Ccb->RetiredPaths;
        Ccb->RetiredPaths = Node[0];
        ExFreePoolWithTag(Node[1], TAG_NTFSNG);
        ExFreePoolWithTag(Node, TAG_NTFSNG);
    }
    if (Ccb->Pattern.Buffer)
        ExFreePoolWithTag(Ccb->Pattern.Buffer, TAG_NTFSNG);
    if (Ccb->Path.Buffer)
        ExFreePoolWithTag(Ccb->Path.Buffer, TAG_NTFSNG);
    /* NotifyPath shares a buffer of Path (current or retired): freed above */
    ExFreePoolWithTag(Ccb, TAG_NTFSNG);
}

/* The chain of Vcb->FcbHash that holds the FCBs of MFT record MftNo. */
static __inline PLIST_ENTRY NgFcbBucket(PNG_VCB Vcb, ULONGLONG MftNo)
{
    return &Vcb->FcbHash[(ULONG)((MftNo * 0x9E3779B97F4A7C15ULL) >> 54) & (NG_FCB_HASH - 1)];
}

/* Takes Fcb off FcbList and its hash chain when it is on them (caller holds FcbListLock). */
VOID NgFcbRemoveLocked(PNG_FCB Fcb)
{
    if (Fcb->IdleLinks.Flink)
    {
        RemoveEntryList(&Fcb->IdleLinks);
        Fcb->IdleLinks.Flink = Fcb->IdleLinks.Blink = NULL;
        Fcb->Vcb->IdleCount--;
    }
    if (Fcb->VcbLinks.Flink)
    {
        RemoveEntryList(&Fcb->VcbLinks);
        RemoveEntryList(&Fcb->HashLinks);
        Fcb->VcbLinks.Flink = Fcb->VcbLinks.Blink = NULL;
        Fcb->HashLinks.Flink = Fcb->HashLinks.Blink = NULL;
    }
}

/*
 * Finds the FCB for (MFT record, stream) or inserts Candidate; returns the FCB to use, counted in
 * Opening until the create counts its handle or fails, so a delete of the file's last name sees it.
 */
static PNG_FCB NgInsertOrFindFcb(PNG_VCB Vcb, PNG_FCB Candidate)
{
    PLIST_ENTRY Entry, Head = NgFcbBucket(Vcb, Candidate->MftNo);
    ExAcquireFastMutex(&Vcb->FcbListLock);
    for (Entry = Head->Flink; Entry != Head; Entry = Entry->Flink)
    {
        PNG_FCB Fcb = CONTAINING_RECORD(Entry, NG_FCB, HashLinks);
        if (Fcb->MftNo == Candidate->MftNo &&
            RtlEqualUnicodeString(&Fcb->Stream, &Candidate->Stream, TRUE))
        {
            if (Fcb->Deleted)
                DPRINT1("ntfsng: BUG: deleted FCB %p for %I64x still listed\n", Fcb, Fcb->MftNo);
            InterlockedIncrement(&Fcb->RefCount);
            Fcb->Opening++;
            /* In use again: not a candidate for the trim until its next last cleanup. */
            if (Fcb->IdleLinks.Flink)
            {
                RemoveEntryList(&Fcb->IdleLinks);
                Fcb->IdleLinks.Flink = Fcb->IdleLinks.Blink = NULL;
                Vcb->IdleCount--;
            }
            ExReleaseFastMutex(&Vcb->FcbListLock);
            return Fcb;
        }
    }
    InsertTailList(&Vcb->FcbList, &Candidate->VcbLinks);
    InsertTailList(Head, &Candidate->HashLinks);
    Candidate->Opening++;
    ExReleaseFastMutex(&Vcb->FcbListLock);
    return Candidate;
}

/* SeManageVolumePrivilege, enabled, in the security context of a user-mode open. */
static BOOLEAN NgHasManageVolumePrivilege(PACCESS_STATE As)
{
    PRIVILEGE_SET Privileges;

    Privileges.PrivilegeCount = 1;
    Privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Privileges.Privilege[0].Luid = SeExports->SeManageVolumePrivilege;
    Privileges.Privilege[0].Attributes = 0;
    return SePrivilegeCheck(&Privileges, &As->SubjectSecurityContext, UserMode);
}

/*
 * Whether the opener may manage the volume (read its bitmap, lock, unlock and dismount it) without the
 * privilege: as NTFS on Windows, when the volume device's ACL grants the opener's token both read and
 * write data access, whatever the handle itself was opened for.  An administrator's read-only or even
 * traverse-only volume handle may manage the volume; a non-administrator's handle that the default
 * device ACL lets open (traverse, read attributes, read control) may not, nor may one whose ACL entry
 * gives read or write access alone.  The descriptor is checked on the copy ObGetObjectSecurity makes,
 * not through DeviceObject->SecurityDescriptor, which a change of the device's security replaces.
 */
static BOOLEAN NgVolumeAclGrantsManage(PNG_VCB Vcb, PACCESS_STATE As)
{
    PSECURITY_DESCRIPTOR Sd;
    BOOLEAN Allocated, Granted;
    ACCESS_MASK GrantedAccess;
    NTSTATUS Status;

    if (!NT_SUCCESS(ObGetObjectSecurity(Vcb->Vpb->RealDevice, &Sd, &Allocated)))
        return FALSE;
    if (!Sd)
        return FALSE;
    SeLockSubjectContext(&As->SubjectSecurityContext);
    Granted = SeAccessCheck(Sd, &As->SubjectSecurityContext, TRUE, FILE_READ_DATA | FILE_WRITE_DATA, 0, NULL,
                            IoGetFileObjectGenericMapping(), UserMode, &GrantedAccess, &Status);
    SeUnlockSubjectContext(&As->SubjectSecurityContext);
    ObReleaseObjectSecurity(Sd, Allocated);
    return Granted;
}

/* Check: the create is checked for access (NgCreateChecksAccess); a kernel-mode open may manage the volume. */
static NTSTATUS NgOpenVolume(PNG_VCB Vcb, PFILE_OBJECT FileObject, PIO_STACK_LOCATION Stack, BOOLEAN Check)
{
    UNICODE_STRING Empty = RTL_CONSTANT_STRING(L"");
    PNG_FCB Fcb;
    PNG_CCB Ccb = NgAllocateCcb(&Empty);
    NTSTATUS Status;

    if (!Ccb)
        return STATUS_INSUFFICIENT_RESOURCES;
    ExAcquireFastMutex(&Vcb->FcbListLock);
    Fcb = Vcb->VolumeFcb;
    if (Fcb)
        InterlockedIncrement(&Fcb->RefCount);
    ExReleaseFastMutex(&Vcb->FcbListLock);
    if (!Fcb)
    {
        Fcb = NgAllocateFcb(Vcb);
        if (!Fcb)
        {
            NgFreeCcb(Ccb);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Fcb->IsVolume = TRUE;
        RtlInitEmptyUnicodeString(&Fcb->Stream, Fcb->StreamBuffer, sizeof(Fcb->StreamBuffer));
        ExAcquireFastMutex(&Vcb->FcbListLock);
        if (Vcb->VolumeFcb)
        {
            InterlockedIncrement(&Vcb->VolumeFcb->RefCount);
            ExReleaseFastMutex(&Vcb->FcbListLock);
            ExDeleteResourceLite(&Fcb->MainResource);
            ExDeleteResourceLite(&Fcb->PagingIoResource);
            ExDeleteResourceLite(&Fcb->PagingWriteLock);
            ExFreePoolWithTag(Fcb, TAG_NTFSNG);
            ExAcquireFastMutex(&Vcb->FcbListLock);
            Fcb = Vcb->VolumeFcb;
        }
        else
        {
            Vcb->VolumeFcb = Fcb;
        }
        ExReleaseFastMutex(&Vcb->FcbListLock);
    }
    ExAcquireFastMutex(&Vcb->FcbListLock);
    if (Fcb->OpenHandles)
    {
        Status = IoCheckShareAccess(Stack->Parameters.Create.SecurityContext->DesiredAccess,
                                    Stack->Parameters.Create.ShareAccess, FileObject, &Fcb->ShareAccess, TRUE);
    }
    else
    {
        IoSetShareAccess(Stack->Parameters.Create.SecurityContext->DesiredAccess,
                         Stack->Parameters.Create.ShareAccess, FileObject, &Fcb->ShareAccess);
        Status = STATUS_SUCCESS;
    }
    if (NT_SUCCESS(Status))
        Fcb->OpenHandles++;
    ExReleaseFastMutex(&Vcb->FcbListLock);
    if (!NT_SUCCESS(Status))
    {
        NgFreeCcb(Ccb);
        NgDereferenceFcb(Fcb);
        return Status;
    }
    {
        PACCESS_STATE As = Stack->Parameters.Create.SecurityContext->AccessState;
        BOOLEAN Privileged = !Check || NgHasManageVolumePrivilege(As);
        Ccb->ManageVolume = Privileged || NgVolumeAclGrantsManage(Vcb, As);
        /* Volume resize (shrink/extend) mutates the volume: require actual write access (not mere read/execute), or the privilege. */
        Ccb->ManageVolumeMutate = Privileged || (As->PreviouslyGrantedAccess & FILE_WRITE_DATA);
    }
    FileObject->FsContext = Fcb;
    FileObject->FsContext2 = Ccb;
    FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;
    FileObject->Vpb = Vcb->Vpb;
    return STATUS_SUCCESS;
}

/* Splits "name[:stream[:$DATA]]"; returns FALSE for an attribute type other than $DATA. */
static BOOLEAN NgSplitStream(PUNICODE_STRING Last, PUNICODE_STRING Stream)
{
    UNICODE_STRING Type, Data = RTL_CONSTANT_STRING(L"$DATA");
    USHORT i, n = Last->Length / sizeof(WCHAR);

    RtlInitEmptyUnicodeString(Stream, NULL, 0);
    for (i = 0; i < n && Last->Buffer[i] != L':'; i++)
        ;
    if (i == n)
        return TRUE;
    Stream->Buffer = Last->Buffer + i + 1;
    Stream->Length = Stream->MaximumLength = (n - i - 1) * sizeof(WCHAR);
    Last->Length = i * sizeof(WCHAR);
    if (Stream->Length == 0)
        return FALSE;   /* "name:" names no stream */
    for (i = 0; i < Stream->Length / sizeof(WCHAR) && Stream->Buffer[i] != L':'; i++)
        ;
    if (i < Stream->Length / sizeof(WCHAR))
    {
        Type.Buffer = Stream->Buffer + i + 1;
        Type.Length = Type.MaximumLength = Stream->Length - (i + 1) * sizeof(WCHAR);
        if (!RtlEqualUnicodeString(&Type, &Data, TRUE))
            return FALSE;
        Stream->Length = i * sizeof(WCHAR);
    }
    return TRUE;
}

/* The FCB of an MFT record's unnamed stream, referenced, or NULL. */
PNG_FCB NgFindFcb(PNG_VCB Vcb, ULONGLONG MftNo)
{
    PLIST_ENTRY Entry, Head = NgFcbBucket(Vcb, MftNo);
    PNG_FCB Found = NULL;
    ExAcquireFastMutex(&Vcb->FcbListLock);
    for (Entry = Head->Flink; Entry != Head; Entry = Entry->Flink)
    {
        PNG_FCB Fcb = CONTAINING_RECORD(Entry, NG_FCB, HashLinks);
        if (Fcb->MftNo == MftNo && Fcb->Stream.Length == 0)
        {
            InterlockedIncrement(&Fcb->RefCount);
            Found = Fcb;
            break;
        }
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);
    return Found;
}

/* TRUE when a named-stream FCB of record MftNo other than Self has a handle or a create in progress. */
static BOOLEAN NgStreamsInUseLocked(PNG_VCB Vcb, ULONGLONG MftNo, PNG_FCB Self)
{
    PLIST_ENTRY Entry, Head = NgFcbBucket(Vcb, MftNo);
    for (Entry = Head->Flink; Entry != Head; Entry = Entry->Flink)
    {
        PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, HashLinks);
        if (F != Self && F->MftNo == MftNo && F->Stream.Length && (F->OpenHandles || F->Opening))
            return TRUE;
    }
    return FALSE;
}

/*
 * The named-stream FCBs of record MftNo other than Self, before the record's last name goes: FALSE
 * when one has a handle or a create in progress (Opening).  Without Retire that is all.  With
 * Retire (caller holds CoreLock) the others give their core inode back, so the core can free the
 * record, and the check is made again after that: a create that found one of them meanwhile makes
 * it FALSE, and one that holds a stream inode it has not published yet makes the core refuse the
 * unlink.  Nothing is marked deleted here: a parked FCB gets its node again if the unlink fails or
 * does not happen, and NgDeleteStreams follows an unlink that freed the record.
 */
BOOLEAN NgRetireStreams(PNG_VCB Vcb, ULONGLONG MftNo, PNG_FCB Self, BOOLEAN Retire)
{
    PNG_FCB Found[32];
    ULONG Count, i;
    BOOLEAN Busy, More;
    PLIST_ENTRY Entry, Head = NgFcbBucket(Vcb, MftNo);

    do
    {
        /* A parked FCB has no node and is not collected again, so the batches end. */
        Count = 0;
        More = FALSE;
        ExAcquireFastMutex(&Vcb->FcbListLock);
        Busy = NgStreamsInUseLocked(Vcb, MftNo, Self);
        for (Entry = Head->Flink; Retire && !Busy && Entry != Head; Entry = Entry->Flink)
        {
            PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, HashLinks);
            if (F == Self || F->MftNo != MftNo || !F->Stream.Length || !F->Node)
                continue;
            if (Count == RTL_NUMBER_OF(Found))
            {
                More = TRUE;
                break;
            }
            InterlockedIncrement(&F->RefCount);
            Found[Count++] = F;
        }
        ExReleaseFastMutex(&Vcb->FcbListLock);
        for (i = 0; i < Count; i++)
        {
            NgParkNode(Found[i]);
            NgDereferenceFcb(Found[i]);
        }
    } while (More);
    if (Busy || !Retire)
        return !Busy;
    ExAcquireFastMutex(&Vcb->FcbListLock);
    Busy = NgStreamsInUseLocked(Vcb, MftNo, Self);
    ExReleaseFastMutex(&Vcb->FcbListLock);
    return !Busy;
}

/*
 * Sets Fcb's delete pending unless CheckStreams and a named stream of its record has a handle or a
 * create in progress: one FcbListLock hold, the one a stream create counts its handle under.
 */
BOOLEAN NgMarkDeletePending(PNG_VCB Vcb, PNG_FCB Fcb, BOOLEAN CheckStreams)
{
    BOOLEAN Ok;
    ExAcquireFastMutex(&Vcb->FcbListLock);
    Ok = !CheckStreams || !NgStreamsInUseLocked(Vcb, Fcb->MftNo, Fcb);
    if (Ok)
        Fcb->DeletePending = TRUE;
    ExReleaseFastMutex(&Vcb->FcbListLock);
    return Ok;
}

/* TRUE when the unnamed-stream FCB of record MftNo has a delete pending (caller holds FcbListLock). */
static BOOLEAN NgBaseDeletePendingLocked(PNG_VCB Vcb, ULONGLONG MftNo)
{
    PLIST_ENTRY Entry, Head = NgFcbBucket(Vcb, MftNo);
    for (Entry = Head->Flink; Entry != Head; Entry = Entry->Flink)
    {
        PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, HashLinks);
        if (F->MftNo == MftNo && !F->Stream.Length && F->DeletePending)
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN NgBaseDeletePending(PNG_VCB Vcb, ULONGLONG MftNo)
{
    BOOLEAN Pending;
    ExAcquireFastMutex(&Vcb->FcbListLock);
    Pending = NgBaseDeletePendingLocked(Vcb, MftNo);
    ExReleaseFastMutex(&Vcb->FcbListLock);
    return Pending;
}

/* After an unlink freed record MftNo: its named-stream FCBs (except Self) are deleted and leave the lookup list. */
VOID NgDeleteStreams(PNG_VCB Vcb, ULONGLONG MftNo, PNG_FCB Self)
{
    PNG_FCB Found[32];
    ULONG Count, i;
    PLIST_ENTRY Entry, Next, Head = NgFcbBucket(Vcb, MftNo);

    do
    {
        /* Marked and unlisted under the lock a create checks Deleted under. */
        Count = 0;
        ExAcquireFastMutex(&Vcb->FcbListLock);
        for (Entry = Head->Flink; Entry != Head && Count < RTL_NUMBER_OF(Found); Entry = Next)
        {
            PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, HashLinks);
            Next = Entry->Flink;
            if (F == Self || F->MftNo != MftNo || !F->Stream.Length)
                continue;
            F->Deleted = TRUE;
            NgFcbRemoveLocked(F);
            InterlockedIncrement(&F->RefCount);
            Found[Count++] = F;
        }
        ExReleaseFastMutex(&Vcb->FcbListLock);
        for (i = 0; i < Count; i++)
        {
            NgParkNode(Found[i]);
            NgDereferenceFcb(Found[i]);
        }
    } while (Count == RTL_NUMBER_OF(Found));
}

/* Takes a deleted FCB out of the lookup list: its MFT record number may be reused. */
VOID NgUnlistFcb(PNG_FCB Fcb)
{
    ExAcquireFastMutex(&Fcb->Vcb->FcbListLock);
    NgFcbRemoveLocked(Fcb);
    ExReleaseFastMutex(&Fcb->Vcb->FcbListLock);
}

BOOLEAN NgValidName(PCUNICODE_STRING Name)
{
    USHORT i, n = Name->Length / sizeof(WCHAR);
    if (n == 0 || n > 255)
        return FALSE;
    if ((n == 1 && Name->Buffer[0] == L'.') || (n == 2 && Name->Buffer[0] == L'.' && Name->Buffer[1] == L'.'))
        return FALSE;
    for (i = 0; i < n; i++)
    {
        WCHAR c = Name->Buffer[i];
        if (c < 0x20 || c == L'"' || c == L'*' || c == L'/' || c == L':' || c == L'<' || c == L'>' ||
            c == L'?' || c == L'\\' || c == L'|')
            return FALSE;
    }
    return TRUE;
}

/* Characters no path component may hold (after the stream suffix is split off). */
static BOOLEAN NgBadComponent(PCUNICODE_STRING Comp)
{
    USHORT i;
    for (i = 0; i < Comp->Length / sizeof(WCHAR); i++)
    {
        WCHAR c = Comp->Buffer[i];
        if (c < 0x20 || c == L'"' || c == L'*' || c == L'/' || c == L':' || c == L'<' || c == L'>' ||
            c == L'?' || c == L'|')
            return TRUE;
    }
    return FALSE;
}

/* Recursive: FsRtl may complete a watcher's IRP, and a completion routine below us can come back here. */
VOID NgLockNotifyPath(PNG_VCB Vcb)
{
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Vcb->NotifyPathLock, TRUE);
}

VOID NgUnlockNotifyPath(PNG_VCB Vcb)
{
    ExReleaseResourceLite(&Vcb->NotifyPathLock);
    KeLeaveCriticalRegion();
}

/* Reports a change of the object at Path ("\\dir\\name") to directory change notification. */
VOID NgNotify(PNG_VCB Vcb, PCUNICODE_STRING Path, ULONG Filter, ULONG Action)
{
    USHORT i = Path->Length / sizeof(WCHAR);
    if (!Vcb->NotifySync || !Path->Length)
        return;
    while (i > 0 && Path->Buffer[i - 1] != L'\\')
        i--;
    /* FsRtl compares Path with each watcher's NotifyPath, reading the latter's length again and again */
    NgLockNotifyPath(Vcb);
    FsRtlNotifyFullReportChange(Vcb->NotifySync, &Vcb->DirNotifyList, (PSTRING)Path, (USHORT)(i * sizeof(WCHAR)),
                                NULL, NULL, Filter, Action, NULL);
    NgUnlockNotifyPath(Vcb);
}

/* NgNotify with the name of Ccb's handle, taken under FcbListLock (a rename through another handle may change it). */
VOID NgNotifyCcb(PNG_VCB Vcb, PNG_CCB Ccb, ULONG Filter, ULONG Action)
{
    UNICODE_STRING Copy;
    if (!Vcb->NotifySync)
        return;
    ExAcquireFastMutex(&Vcb->FcbListLock);
    Copy.Length = Copy.MaximumLength = Ccb->Path.Length;
    Copy.Buffer = Copy.Length ? ExAllocatePoolWithTag(PagedPool, Copy.Length, TAG_NTFSNG) : NULL;
    if (Copy.Buffer)
        RtlCopyMemory(Copy.Buffer, Ccb->Path.Buffer, Copy.Length);
    ExReleaseFastMutex(&Vcb->FcbListLock);
    if (!Copy.Buffer)
        return;
    NgNotify(Vcb, &Copy, Filter, Action);
    ExFreePoolWithTag(Copy.Buffer, TAG_NTFSNG);
}

#define NG_SETTABLE_ATTRS (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | \
                           FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_OFFLINE | \
                           FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)

/*
 * Tunnel cache: a name that goes away (delete, rename) leaves its creation time for a few
 * seconds, and a file created under that name in the same directory takes it over, as on
 * Windows (programs that save by writing a new file and renaming keep the creation time).
 */
VOID NgTunnelAdd(PNG_VCB Vcb, ULONGLONG DirMftNo, PCWSTR Name, USHORT NameChars, LONGLONG CreationTime)
{
    UNICODE_STRING Long, Short;
    Long.Buffer = (PWSTR)Name;
    Long.Length = Long.MaximumLength = NameChars * sizeof(WCHAR);
    RtlInitEmptyUnicodeString(&Short, NULL, 0);
    FsRtlAddToTunnelCache(&Vcb->Tunnel, DirMftNo & 0xffffffffffffULL, &Short, &Long, FALSE,
                          sizeof(CreationTime), &CreationTime);
}

/* Caller holds CoreLock; Node was just created (or renamed) as Name in Parent. */
VOID NgTunnelApply(PNG_VCB Vcb, ngc_node *Parent, ngc_node *Node, PUNICODE_STRING Name)
{
    struct ngc_stat Dir;
    WCHAR ShortBuf[12], LongBuf[64];
    UNICODE_STRING Short, Long;
    LONGLONG Times[4] = { 0, 0, 0, 0 };
    ULONG Length = sizeof(Times[0]);

    ngc_stat(Parent, &Dir);
    RtlInitEmptyUnicodeString(&Short, ShortBuf, sizeof(ShortBuf));
    RtlInitEmptyUnicodeString(&Long, LongBuf, sizeof(LongBuf));
    if (FsRtlFindInTunnelCache(&Vcb->Tunnel, Dir.mft_ref & 0xffffffffffffULL, Name, &Short, &Long, &Length, &Times[0]) &&
        Length == sizeof(Times[0]))
        ngc_set_info(Vcb->Core, Node, Times, 0, 0);
    if (Long.Buffer && Long.Buffer != LongBuf)
        ExFreePool(Long.Buffer);
}

/*
 * A new long name that is not a valid 8.3 name gets a generated DOS name (LONGNA~1.EXT), unique in
 * its directory, as NTFS on Windows creates one unless NtfsDisable8dot3NameCreation is 1.  Caller
 * holds CoreLock.  A failure only leaves the file without a short name.
 */
VOID NgMakeShortName(PNG_VCB Vcb, ngc_node *Parent, ngc_node *Node, PCWSTR Name, USHORT NameChars)
{
    GENERATE_NAME_CONTEXT Ctx;
    UNICODE_STRING Long, Short;
    WCHAR ShortBuf[12];
    BOOLEAN Spaces = FALSE;
    ULONG i;
    int Err;

    if (NgGlobal.Disable8dot3 || !NameChars)
        return;
    Long.Buffer = (PWSTR)Name;
    Long.Length = Long.MaximumLength = NameChars * sizeof(WCHAR);
    if (RtlIsNameLegalDOS8Dot3(&Long, NULL, &Spaces) && !Spaces)
        return;
    RtlZeroMemory(&Ctx, sizeof(Ctx));
    RtlInitEmptyUnicodeString(&Short, ShortBuf, sizeof(ShortBuf));
    for (i = 0; i < 64; i++)
    {
        ngc_node *Other = NULL;
        RtlGenerate8dot3Name(&Long, FALSE, &Ctx, &Short);
        Err = ngc_lookup(Vcb->Core, Parent, Short.Buffer, Short.Length / sizeof(WCHAR), &Other, NULL, NULL);
        if (Err == -NGC_ENOENT)
            break;
        if (Other)
            ngc_put(Other);
        if (Err)
            return;
    }
    if (i == 64)
        return;
    Err = ngc_add_short_name(Vcb->Core, Parent, Node, Name, NameChars, Short.Buffer, Short.Length / sizeof(WCHAR));
    if (Err)
        DPRINT1("ntfsng: short name %wZ for %wZ failed %d\n", &Short, &Long, Err);
}

/*
 * The path from the volume root of the file a FILE_OPEN_BY_FILE_ID names (an 8-byte file
 * reference; a nonzero sequence number must match), following $FILE_NAME parents up to the root.
 */
static NTSTATUS NgPathFromId(PNG_VCB Vcb, PCUNICODE_STRING Id, PUNICODE_STRING Path)
{
    ULONGLONG Ref, MftNo, Parent;
    USHORT Seq;
    ngc_node *Node = NULL, *Up;
    struct ngc_stat St;
    PWCHAR Name;
    PWCHAR Buf;
    ULONG Used = 0, Cap = 0x8000, Depth;
    unsigned int Len;
    int Err;

    if (Id->Length != sizeof(ULONGLONG))
        return Id->Length == 16 ? STATUS_NOT_IMPLEMENTED : STATUS_INVALID_PARAMETER;  /* object IDs */
    RtlCopyMemory(&Ref, Id->Buffer, sizeof(Ref));
    MftNo = Ref & 0xffffffffffffULL;
    Seq = (USHORT)(Ref >> 48);
    if (MftNo < NG_FIRST_USER_FILE && MftNo != 5)
        return STATUS_INVALID_PARAMETER;   /* the metadata files are not opened by ID */
    Buf = ExAllocatePoolWithTag(PagedPool, Cap * sizeof(WCHAR), TAG_NTFSNG);
    Name = ExAllocatePoolWithTag(PagedPool, 256 * sizeof(WCHAR), TAG_NTFSNG);
    if (!Buf || !Name)
    {
        if (Buf) ExFreePoolWithTag(Buf, TAG_NTFSNG);
        if (Name) ExFreePoolWithTag(Name, TAG_NTFSNG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    NgAcquireCore(Vcb);
    Err = ngc_iget_by_id(Vcb->Core, MftNo, &Node);
    if (!Err)
    {
        ngc_stat(Node, &St);
        if (Seq && (USHORT)(St.mft_ref >> 48) != Seq)
            Err = -NGC_ENOENT;
    }
    /* Built backwards from the end of Buf. */
    for (Depth = 0; !Err && MftNo != 5 && Depth < 128; Depth++)
    {
        Err = ngc_parent_name(Node, &Parent, Name, &Len);
        if (!Err && (Used + Len + 1 > Cap || (Used + Len + 1) * sizeof(WCHAR) > MAXUSHORT - sizeof(WCHAR)))
            Err = -NGC_ENAMETOOLONG;
        if (!Err)
        {
            Used += Len + 1;
            RtlCopyMemory(Buf + Cap - Used + 1, Name, Len * sizeof(WCHAR));
            Buf[Cap - Used] = L'\\';
            Err = ngc_iget(Vcb->Core, Parent, &Up);
        }
        if (!Err)
        {
            ngc_put(Node);
            Node = Up;
            MftNo = Parent;
        }
    }
    if (Node)
        ngc_put(Node);
    NgReleaseCore(Vcb);
    ExFreePoolWithTag(Name, TAG_NTFSNG);
    if (!Err && MftNo != 5)
        Err = -NGC_ENOENT;
    if (Err)
    {
        ExFreePoolWithTag(Buf, TAG_NTFSNG);
        return Err == -NGC_ENOENT ? STATUS_INVALID_PARAMETER : NgErrnoToStatus(Err);
    }
    if (!Used)
    {
        Buf[Cap - 1] = L'\\';
        Used = 1;
    }
    RtlMoveMemory(Buf, Buf + Cap - Used, Used * sizeof(WCHAR));
    Path->Buffer = Buf;
    Path->Length = Path->MaximumLength = (USHORT)(Used * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

/*
 * A junction (mount point reparse point) on the path: the open goes back to the I/O manager with
 * STATUS_REPARSE and the reparse data, whose Reserved field counts the bytes at the end of the
 * file name that follow the junction.  Other reparse tags open the file itself.  Caller holds CoreLock.
 * As is given when the junction is the last component, which is opened through it: the junction's
 * own descriptor has to grant the access asked for first, as on Windows (a junction that denies
 * FILE_LIST_DIRECTORY cannot be listed, but a path below it still resolves on FILE_TRAVERSE).
 */
static NTSTATUS NgMountPointReparse(PNG_VCB Vcb, ngc_node *Node, PIRP Irp, PFILE_OBJECT FileObject, ULONG Tail,
                                    PACCESS_STATE As)
{
    PREPARSE_DATA_BUFFER Rp, Copy;
    void *Data;
    unsigned int Len;
    ULONG Path;

    if (!ngc_is_reparse(Node) || Tail > FileObject->FileName.Length)
        return STATUS_SUCCESS;
    if (ngc_get_reparse(Node, &Data, &Len))
        return STATUS_SUCCESS;
    Rp = Data;
    if (Rp->ReparseTag != IO_REPARSE_TAG_MOUNT_POINT)
    {
        ngc_free(Data);
        return STATUS_SUCCESS;
    }
    Path = Len - FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer);
    if (Len < FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) ||
        (ULONG)Rp->ReparseDataLength + REPARSE_DATA_BUFFER_HEADER_SIZE != Len ||
        (ULONG)Rp->MountPointReparseBuffer.SubstituteNameOffset + Rp->MountPointReparseBuffer.SubstituteNameLength > Path ||
        (ULONG)Rp->MountPointReparseBuffer.PrintNameOffset + Rp->MountPointReparseBuffer.PrintNameLength > Path ||
        !Rp->MountPointReparseBuffer.SubstituteNameLength)
    {
        ngc_free(Data);
        return STATUS_IO_REPARSE_DATA_INVALID;
    }
    if (As)
    {
        ACCESS_MASK Desired = As->RemainingDesiredAccess;
        PSECURITY_DESCRIPTOR Sd;
        NTSTATUS Status;

        RtlMapGenericMask(&Desired, IoGetFileObjectGenericMapping());
        Desired &= ~(As->PreviouslyGrantedAccess | MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);
        if (Desired)
        {
            Status = NgReadSecurity(Vcb, Node, &Sd);
            if (NT_SUCCESS(Status))
            {
                Status = NgCheckAccessRight(As, Sd, Desired);
                ExFreePoolWithTag(Sd, TAG_NTFSNG);
            }
            if (!NT_SUCCESS(Status))
            {
                ngc_free(Data);
                return Status;
            }
        }
    }
    Copy = ExAllocatePoolWithTag(PagedPool, Len, TAG_NTFSNG);
    if (!Copy)
    {
        ngc_free(Data);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(Copy, Data, Len);
    ngc_free(Data);
    Copy->Reserved = (USHORT)Tail;
    Irp->Tail.Overlay.AuxiliaryBuffer = (PCHAR)Copy;
    Irp->IoStatus.Information = IO_REPARSE_TAG_MOUNT_POINT;
    return STATUS_REPARSE;
}

/*
 * Access check of an open of an existing Node (Parent: the directory it was found in, or NULL);
 * Implied: rights the disposition needs beyond the desired access.  The directory's descriptor is
 * read only when it can grant something (MAXIMUM_ALLOWED, or a refused DELETE or
 * FILE_READ_ATTRIBUTES).  Node and Parent stay referenced by the caller.
 */
static NTSTATUS NgCheckOpen(PNG_VCB Vcb, PACCESS_STATE As, ngc_node *Node, ngc_node *Parent, ACCESS_MASK Implied)
{
    PSECURITY_DESCRIPTOR Sd = NULL, ParentSd = NULL;
    ACCESS_MASK Desired = As->RemainingDesiredAccess;
    NG_SHARED_HOLD Hold;
    NTSTATUS Status;

    NgAcquireCoreShared(Vcb, &Hold);
    Status = NgReadSecurity(Vcb, Node, &Sd);
    if (NT_SUCCESS(Status) && Parent && ((Desired & MAXIMUM_ALLOWED) || (Implied & DELETE)))
        Status = NgReadSecurity(Vcb, Parent, &ParentSd);
    NgReleaseCoreShared(Vcb, &Hold);
    if (NT_SUCCESS(Status))
        Status = NgCheckExistingAccess(As, Sd, ParentSd, Implied);
    if (Status == STATUS_ACCESS_DENIED && Parent && !ParentSd && (Desired & (DELETE | FILE_READ_ATTRIBUTES)))
    {
        NgAcquireCoreShared(Vcb, &Hold);
        Status = NgReadSecurity(Vcb, Parent, &ParentSd);
        NgReleaseCoreShared(Vcb, &Hold);
        if (NT_SUCCESS(Status))
            Status = NgCheckExistingAccess(As, Sd, ParentSd, Implied);
    }
    if (Sd)
        ExFreePoolWithTag(Sd, TAG_NTFSNG);
    if (ParentSd)
        ExFreePoolWithTag(ParentSd, TAG_NTFSNG);
    return Status;
}

/* FILE_TRAVERSE on directory Dir, for a caller without the traverse privilege; caller holds CoreLock. */
static NTSTATUS NgCheckTraverse(PNG_VCB Vcb, PACCESS_STATE As, ngc_node *Dir)
{
    PSECURITY_DESCRIPTOR Sd;
    NTSTATUS Status = NgReadSecurity(Vcb, Dir, &Sd);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = NgCheckAccessRight(As, Sd, FILE_TRAVERSE);
    ExFreePoolWithTag(Sd, TAG_NTFSNG);
    return Status;
}

/*
 * A relative open walks from the related handle's own file, found by its MFT record, as NTFS does
 * from the related SCB: never by the related handle's name, which a rename through another handle
 * may have moved away and a junction then taken over.  Caller holds CoreLock.
 */
static NTSTATUS NgRelatedNode(PNG_VCB Vcb, PNG_FCB Fcb, ngc_node **Out)
{
    struct ngc_stat St;
    *Out = NULL;
    if (Fcb->IsRoot)
    {
        *Out = ngc_root(Vcb->Core);
        return STATUS_SUCCESS;
    }
    if (Fcb->Orphan)
        return STATUS_DELETE_PENDING;   /* a directory a POSIX delete removed: nothing new inside (Windows 10) */
    if (Fcb->Deleted || !Fcb->HasNode || ngc_iget(Vcb->Core, Fcb->MftNo, Out))
        return STATUS_FILE_DELETED;
    ngc_stat(*Out, &St);
    if ((St.mft_ref >> 48) != (Fcb->Stat.mft_ref >> 48))
    {
        ngc_put(*Out);
        *Out = NULL;
        return STATUS_FILE_DELETED;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS NgCreateLocked(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = Stack->FileObject;
    PFILE_OBJECT Related = FileObject->RelatedFileObject;
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    ULONG Disposition = (Stack->Parameters.Create.Options >> 24) & 0xff;
    ULONG Options = Stack->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS;
    ULONG FileAttributes = Stack->Parameters.Create.FileAttributes;
    ACCESS_MASK Access = Stack->Parameters.Create.SecurityContext->DesiredAccess;
    BOOLEAN OpenTarget = (Stack->Flags & SL_OPEN_TARGET_DIRECTORY) != 0;
    UNICODE_STRING Full, Rest, Comp, Stream;
    PNG_FCB RelatedFcb = NULL, Fcb = NULL, Found;
    PNG_CCB RelatedCcb = NULL, Ccb = NULL;
    ngc_node *Node = NULL, *Parent = NULL, *Next;
    BOOLEAN Trailing = FALSE, IsDir, Missing = FALSE, TargetExists = FALSE, Created = FALSE, Shared = FALSE, Opening = FALSE;
    BOOLEAN CreatedNode = FALSE, StreamChecked = FALSE, SetPaging = FALSE;
    ACCESS_MASK Effective;
    BOOLEAN Exclusive = (Disposition == FILE_CREATE || Disposition == FILE_SUPERSEDE);
    NG_SHARED_HOLD Hold;
    ULONG_PTR Information = FILE_OPENED;
    struct ngc_stat St, PSt;
    PWCHAR Real = NULL;
    unsigned int RealLen = 0;
    UNICODE_STRING ById = { 0, 0, NULL };
    ULONGLONG ByIdRef = 0;
    PCUNICODE_STRING Name = &FileObject->FileName;
    PACCESS_STATE As = Stack->Parameters.Create.SecurityContext->AccessState;
    BOOLEAN Check = NgCreateChecksAccess(Irp, Stack), Traverse;
    PSECURITY_DESCRIPTOR ParentSd = NULL;
    ULONG RelatedChars = 0;
    ULONGLONG RelatedParent = 0;
    USHORT RelatedNameLength = 0;
    NTSTATUS Status;
    USHORT i, FullLength;
    int Err;

    if (Related)
    {
        RelatedFcb = Related->FsContext;
        RelatedCcb = Related->FsContext2;
    }
    if (Vcb->LockedBy)
        return STATUS_ACCESS_DENIED;
    Status = NgCheckMedium(Vcb);
    if (Status == STATUS_WRONG_VOLUME && !Related)
    {
        /* Another medium: the I/O manager mounted it, so parse the name again (there). */
        Irp->IoStatus.Information = IO_REMOUNT;
        return STATUS_REPARSE;
    }
    if (!NT_SUCCESS(Status))
        return Status;
    if (Options & FILE_OPEN_BY_FILE_ID)
    {
        /* Opened as the path of the file the ID names; such an open never creates anything. */
        if (Disposition != FILE_OPEN && Disposition != FILE_OPEN_IF && Disposition != FILE_OVERWRITE)
            return STATUS_INVALID_PARAMETER;
        if (FileObject->FileName.Length == sizeof(ULONGLONG))
            ByIdRef = *(ULONGLONG UNALIGNED *)FileObject->FileName.Buffer;
        Status = NgPathFromId(Vcb, &FileObject->FileName, &ById);
        if (!NT_SUCCESS(Status))
            return Status;
        if (Disposition == FILE_OPEN_IF)
            Disposition = FILE_OPEN;
        Name = &ById;
        RelatedFcb = NULL;
        RelatedCcb = NULL;
    }
    if (Disposition > FILE_MAXIMUM_DISPOSITION)
        return STATUS_INVALID_PARAMETER;
    if (Name->Length == 0 && (!RelatedFcb || RelatedFcb->IsVolume))
    {
        if (Disposition != FILE_OPEN && Disposition != FILE_OPEN_IF)
            return Vcb->ReadOnly ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_ACCESS_DENIED;
        if ((Access & NG_WRITE_ACCESS) && !(NgGlobal.PermissiveOpen || Vcb->Damaged) && Vcb->ReadOnly)
            return STATUS_MEDIA_WRITE_PROTECTED;
        return NgOpenVolume(Vcb, FileObject, Stack, Check);
    }

    Real = ExAllocatePoolWithTag(PagedPool, 256 * sizeof(WCHAR), TAG_NTFSNG);
    if (!Real)
    {
        if (ById.Buffer)
            ExFreePoolWithTag(ById.Buffer, TAG_NTFSNG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* A name below a stream handle: there is no such directory (the name used to be walked through
     * "file:stream" as a component). */
    if (RelatedCcb && !RelatedFcb->IsVolume && Name->Length && (Name->Buffer[0] == L'\\' || RelatedFcb->Stream.Length))
    {
        ExFreePoolWithTag(Real, TAG_NTFSNG);
        return STATUS_OBJECT_NAME_INVALID;
    }
    /* The path from the volume root, built from the related open's current name if any: the new
     * handle's name.  The related name is copied under FcbListLock (a rename may change it). */
    if (RelatedCcb)
        ExAcquireFastMutex(&Vcb->FcbListLock);
    {
        ULONG FullMax = (ULONG)Name->Length + sizeof(WCHAR) * 2 + (RelatedCcb ? RelatedCcb->Path.Length : 0);
        Full.Buffer = NULL;
        Status = STATUS_OBJECT_NAME_INVALID;
        if (FullMax <= MAXUSHORT)
        {
            Full.MaximumLength = (USHORT)FullMax;
            Full.Buffer = ExAllocatePoolWithTag(PagedPool, Full.MaximumLength, TAG_NTFSNG);
            Status = Full.Buffer ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    if (NT_SUCCESS(Status))
    {
        Full.Length = 0;
        if (RelatedCcb && !RelatedFcb->IsVolume)
        {
            RtlCopyUnicodeString(&Full, &RelatedCcb->Path);
            if (Name->Length &&
                (Full.Length == 0 || Full.Buffer[Full.Length / sizeof(WCHAR) - 1] != L'\\'))
                RtlAppendUnicodeToString(&Full, L"\\");
            RelatedChars = Full.Length / sizeof(WCHAR);
            /* An empty name opens the related file itself, by the name its handle has. */
            RelatedParent = RelatedCcb->ParentMftNo;
            RelatedNameLength = RelatedCcb->NameLength;
            RtlCopyMemory(Real, RelatedCcb->Name, RelatedNameLength * sizeof(WCHAR));
        }
    }
    if (RelatedCcb)
        ExReleaseFastMutex(&Vcb->FcbListLock);
    if (!NT_SUCCESS(Status))
    {
        if (Full.Buffer)
            ExFreePoolWithTag(Full.Buffer, TAG_NTFSNG);
        ExFreePoolWithTag(Real, TAG_NTFSNG);
        if (ById.Buffer)
            ExFreePoolWithTag(ById.Buffer, TAG_NTFSNG);
        return Status;
    }
    if (!NT_SUCCESS(RtlAppendUnicodeStringToString(&Full, Name)))
    {
        Status = STATUS_OBJECT_NAME_INVALID;
        goto out;
    }
    if (Full.Length == 0 || Full.Buffer[0] != L'\\')
    {
        Status = STATUS_OBJECT_NAME_INVALID;
        goto out;
    }
    FullLength = Full.Length;
    while (Full.Length > sizeof(WCHAR) && Full.Buffer[Full.Length / sizeof(WCHAR) - 1] == L'\\')
    {
        Full.Length -= sizeof(WCHAR);
        Trailing = TRUE;
    }
    if (OpenTarget && Full.Length == sizeof(WCHAR))
    {
        Status = STATUS_OBJECT_NAME_INVALID;
        goto out;
    }
    /* Directories on the path need FILE_TRAVERSE unless the caller holds SeChangeNotifyPrivilege;
     * an open by file ID has no path, a relative open starts below its directory. */
    Traverse = Check && !(As->Flags & TOKEN_HAS_TRAVERSE_PRIVILEGE) && Name == &FileObject->FileName;

    /*
     * Walk the path.  Parent keeps the directory of the last component.  The walk takes CoreLock
     * shared; when it finds that the open creates something, it starts again exclusive.
     */
walk:
    if (Exclusive)
        NgAcquireCore(Vcb);
    else
        NgAcquireCoreShared(Vcb, &Hold);
    RtlInitEmptyUnicodeString(&Stream, NULL, 0);
    RtlInitEmptyUnicodeString(&Comp, NULL, 0);
    Status = STATUS_SUCCESS;
    if (RelatedChars)
    {
        /* Only the components of the name are looked up (and junctions among them followed). */
        Status = NgRelatedNode(Vcb, RelatedFcb, &Node);
        Rest.Buffer = Full.Buffer + RelatedChars;
        Rest.Length = Rest.MaximumLength =
            Full.Length > RelatedChars * sizeof(WCHAR) ? (USHORT)(Full.Length - RelatedChars * sizeof(WCHAR)) : 0;
        if (NT_SUCCESS(Status) && !Rest.Length && !RelatedFcb->IsRoot)
        {
            /* The related file itself (or its stream), by its handle's name in its directory. */
            if (OpenTarget)
                Status = STATUS_OBJECT_NAME_INVALID;
            else if (RelatedNameLength && ngc_iget(Vcb->Core, RelatedParent, &Parent))
                Status = STATUS_OBJECT_PATH_NOT_FOUND;
            else
            {
                Stream = RelatedFcb->Stream;
                Comp.Buffer = Real;
                Comp.Length = Comp.MaximumLength = RelatedNameLength * sizeof(WCHAR);
                RealLen = RelatedNameLength;
                if (!(Options & FILE_OPEN_REPARSE_POINT) && Disposition != FILE_CREATE)
                    Status = NgMountPointReparse(Vcb, Node, Irp, FileObject, 0, Check ? As : NULL);
            }
        }
    }
    else
    {
        Node = ngc_root(Vcb->Core);
        Rest.Buffer = Full.Buffer + 1;
        Rest.Length = Rest.MaximumLength = Full.Length - sizeof(WCHAR);
    }
    while (NT_SUCCESS(Status) && Status != STATUS_REPARSE && Rest.Length)
    {
        BOOLEAN LastComp;
        for (i = 0; i < Rest.Length / sizeof(WCHAR) && Rest.Buffer[i] != L'\\'; i++)
            ;
        Comp.Buffer = Rest.Buffer;
        Comp.Length = Comp.MaximumLength = i * sizeof(WCHAR);
        LastComp = (i == Rest.Length / sizeof(WCHAR));
        if (LastComp)
        {
            Rest.Length = 0;
            if (!NgSplitStream(&Comp, &Stream))
            {
                Status = STATUS_OBJECT_NAME_INVALID;
                break;
            }
        }
        else
        {
            Rest.Buffer += i + 1;
            Rest.Length -= (i + 1) * sizeof(WCHAR);
        }
        if (Comp.Length == 0 || Comp.Length > 255 * sizeof(WCHAR) || NgBadComponent(&Comp))
        {
            Status = STATUS_OBJECT_NAME_INVALID;
            break;
        }
        if (Traverse && (ULONG)(Comp.Buffer - Full.Buffer) >= RelatedChars)
        {
            Status = NgCheckTraverse(Vcb, As, Node);
            if (!NT_SUCCESS(Status))
                break;
        }
        if (LastComp && OpenTarget)
        {
            /* Rename/link target: open the parent, report whether the final name exists. */
            if (!ngc_lookup(Vcb->Core, Node, Comp.Buffer, Comp.Length / sizeof(WCHAR), &Next, NULL, NULL))
            {
                TargetExists = TRUE;
                ngc_put(Next);
            }
            break;
        }
        Err = ngc_lookup(Vcb->Core, Node, Comp.Buffer, Comp.Length / sizeof(WCHAR), &Next,
                         LastComp ? Real : NULL, LastComp ? &RealLen : NULL);
        if (Err)
        {
            if (LastComp && Err == -NGC_ENOENT)
            {
                Missing = TRUE;
                Parent = Node;
                Node = NULL;
                RtlCopyMemory(Real, Comp.Buffer, Comp.Length);
                RealLen = Comp.Length / sizeof(WCHAR);
                break;
            }
            Status = NgErrnoToStatus(Err);
            if (Err == -NGC_ENOENT)
                Status = LastComp ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_OBJECT_PATH_NOT_FOUND;
            else if (Err == -NGC_ENOTDIR)
                Status = STATUS_OBJECT_PATH_NOT_FOUND;   /* a file used as a directory */
            break;
        }
        if (Name == &FileObject->FileName && (!LastComp || (!(Options & FILE_OPEN_REPARSE_POINT) &&
                                                           Disposition != FILE_CREATE)))
        {
            Status = NgMountPointReparse(Vcb, Next, Irp, FileObject,
                                         FullLength - (ULONG)(Comp.Buffer + Comp.Length / sizeof(WCHAR) - Full.Buffer) * sizeof(WCHAR),
                                         LastComp && Check ? As : NULL);
            if (Status != STATUS_SUCCESS)
            {
                ngc_put(Next);
                break;
            }
        }
        if (LastComp)
            Parent = Node;
        else
            ngc_put(Node);
        Node = Next;
    }
    if (Status == STATUS_REPARSE)
    {
        if (Exclusive)
            NgReleaseCore(Vcb);
        else
            NgReleaseCoreShared(Vcb, &Hold);
        goto out;
    }
    if (!Exclusive && NT_SUCCESS(Status) && !OpenTarget &&
        ((Missing && Disposition != FILE_OPEN && Disposition != FILE_OVERWRITE) || (!Missing && Stream.Length)))
    {
        /* Something may be created (a file, a directory or a named stream): again, exclusive. */
        if (Node)
            ngc_put(Node);
        if (Parent)
            ngc_put(Parent);
        Node = Parent = NULL;
        Missing = FALSE;
        NgReleaseCoreShared(Vcb, &Hold);
        Exclusive = TRUE;
        goto walk;
    }
    if (NT_SUCCESS(Status) && OpenTarget)
    {
        /* Node is the target's directory; the CCB path is the directory's. */
        while (Full.Length > sizeof(WCHAR) && Full.Buffer[Full.Length / sizeof(WCHAR) - 1] != L'\\')
            Full.Length -= sizeof(WCHAR);
        if (Full.Length > sizeof(WCHAR))
            Full.Length -= sizeof(WCHAR);
        Information = TargetExists ? FILE_EXISTS : FILE_DOES_NOT_EXIST;
        Stream.Length = 0;
        Disposition = FILE_OPEN;
        Options |= FILE_DIRECTORY_FILE;
    }
    if (NT_SUCCESS(Status) && !Missing && Stream.Length)
    {
        /* A stream of a file whose delete is pending is neither opened nor created. */
        struct ngc_stat Base;
        ngc_stat(Node, &Base);
        if (NgBaseDeletePending(Vcb, Base.mft_ref & 0xffffffffffffULL))
            Status = STATUS_DELETE_PENDING;
    }
    if (NT_SUCCESS(Status) && !Missing && Stream.Length)
    {
        Err = ngc_open_stream(Vcb->Core, Node, Stream.Buffer, Stream.Length / sizeof(WCHAR), &Next);
        if (Err == -NGC_ENOENT && Disposition != FILE_OPEN && Disposition != FILE_OVERWRITE)
        {
            /* A named stream of an existing file or directory is created on demand; it shares the
             * file's descriptor, so the whole requested access (including WRITE_DAC and DELETE,
             * which would otherwise rewrite or remove the base) is checked against it first. */
            PSECURITY_DESCRIPTOR FileSd = NULL;
            struct ngc_stat BSt, DirSt;
            ngc_stat(Node, &BSt);
            DirSt.mft_ref = 0;
            if (Parent)
                ngc_stat(Parent, &DirSt);
            if (Vcb->ReadOnly)
                Err = -NGC_EROFS;
            else if ((BSt.mft_ref & 0xffffffffffffULL) < NG_FIRST_USER_FILE || (DirSt.mft_ref & 0xffffffffffffULL) == 11)
            {
                Status = STATUS_ACCESS_DENIED;   /* no streams on the metadata files and the $Extend children */
                Err = 0;
            }
            else if (Check && (!NT_SUCCESS(Status = NgReadSecurity(Vcb, Node, &FileSd)) ||
                               !NT_SUCCESS(Status = NgCheckExistingAccess(As, FileSd, NULL, FILE_WRITE_DATA))))
                Err = 0;
            else if (!(Err = ngc_create_stream(Vcb->Core, Node, Stream.Buffer, Stream.Length / sizeof(WCHAR), &Next)))
            {
                Created = TRUE;
                StreamChecked = Check;   /* access already authorised against the base descriptor */
                Information = FILE_CREATED;
            }
            if (FileSd)
                ExFreePoolWithTag(FileSd, TAG_NTFSNG);
            if (!NT_SUCCESS(Status))
                goto walked;
        }
        if (Err)
        {
            Status = Err == -NGC_ENOENT ? STATUS_OBJECT_NAME_NOT_FOUND : NgErrnoToStatus(Err);
        }
        else
        {
            ngc_put(Node);
            Node = Next;
        }
    }
walked:
    if (NT_SUCCESS(Status) && Missing && Parent)
        ngc_stat(Parent, &PSt);
    if (NT_SUCCESS(Status) && Missing)
    {
        /* Create the missing last component. */
        BOOLEAN WantDir = (Options & FILE_DIRECTORY_FILE) != 0;
        if (Disposition == FILE_OPEN || Disposition == FILE_OVERWRITE)
            Status = STATUS_OBJECT_NAME_NOT_FOUND;
        else if (Vcb->ReadOnly)
            Status = STATUS_MEDIA_WRITE_PROTECTED;
        else if (Stack->Parameters.Create.EaLength)
            Status = STATUS_EAS_NOT_SUPPORTED;      /* extended attributes are not stored */
        else if (!NgValidName(&Comp))
            Status = STATUS_OBJECT_NAME_INVALID;
        else if (Trailing && !WantDir)
            Status = STATUS_OBJECT_NAME_INVALID;
        else if (WantDir && (FileAttributes & FILE_ATTRIBUTE_TEMPORARY))
            Status = STATUS_INVALID_PARAMETER;
        else if (((PSt.mft_ref & 0xffffffffffffULL) < NG_FIRST_USER_FILE &&
                  (PSt.mft_ref & 0xffffffffffffULL) != 5) ||
                 (Vcb->DeletedMftNo && (PSt.mft_ref & 0xffffffffffffULL) == Vcb->DeletedMftNo))
            Status = STATUS_ACCESS_DENIED;   /* no new entries inside the metadata directories and $Extend\$Deleted */
        else if (!NT_SUCCESS(Status = NgReadSecurity(Vcb, Parent, &ParentSd)))
            ;
        else if (Check && !NT_SUCCESS(Status = NgCheckCreateAccess(As, ParentSd, WantDir)))
            ;
        else
        {
            NTSTATUS SecStatus = STATUS_SUCCESS;
            Err = ngc_create(Vcb->Core, Parent, Comp.Buffer, Comp.Length / sizeof(WCHAR), WantDir, &Node);
            if (!Err)
            {
                NgMakeShortName(Vcb, Parent, Node, Comp.Buffer, Comp.Length / sizeof(WCHAR));
                if (!WantDir)
                    NgTunnelApply(Vcb, Parent, Node, &Comp);
            }
            if (!Err)
            {
                unsigned int Attrs = (FileAttributes & NG_SETTABLE_ATTRS) | (WantDir ? 0 : FILE_ATTRIBUTE_ARCHIVE);
                Created = TRUE;
                CreatedNode = TRUE;
                Information = FILE_CREATED;
                Err = ngc_set_info(Vcb->Core, Node, NULL, Attrs, NG_SETTABLE_ATTRS);
                /* Never the core's own default (Everyone full access): what the directory passes on. */
                if (!Err)
                    Err = NgAssignNewSecurity(Vcb, Node, ParentSd, As, WantDir, &SecStatus);
                if (Err)
                    ngc_unlink(Vcb->Core, Parent, Comp.Buffer, Comp.Length / sizeof(WCHAR), Node);
            }
            if (!Err && Stream.Length)
            {
                /* "file:stream" for a new file: the file, then the stream (or neither). */
                ngc_node *S = NULL;
                Err = ngc_create_stream(Vcb->Core, Node, Stream.Buffer, Stream.Length / sizeof(WCHAR), &S);
                if (!Err)
                {
                    ngc_put(Node);
                    Node = S;
                }
                else
                {
                    ngc_unlink(Vcb->Core, Parent, Comp.Buffer, Comp.Length / sizeof(WCHAR), Node);
                }
            }
            if (Err)
                Status = NT_SUCCESS(SecStatus) ? NgErrnoToStatus(Err) : SecStatus;
            else
                NgAfterChange(Vcb);
        }
    }
    if (NT_SUCCESS(Status))
        ngc_stat(Node, &St);
    if (NT_SUCCESS(Status) && ByIdRef)
    {
        /* The path was re-walked without the lock: a concurrent rename could have put another
         * file where the ID's path now leads.  Refuse unless it is still the record the ID named. */
        ULONGLONG Want = ByIdRef & 0xffffffffffffULL;
        USHORT WantSeq = (USHORT)(ByIdRef >> 48);
        if ((St.mft_ref & 0xffffffffffffULL) != Want || (WantSeq && (USHORT)(St.mft_ref >> 48) != WantSeq))
            Status = STATUS_INVALID_PARAMETER;
    }
    if (Parent)
        ngc_stat(Parent, &PSt);
    else
        PSt.mft_ref = 5;    /* the root is its own parent */
    if (Exclusive)
        NgReleaseCore(Vcb);
    else
        NgReleaseCoreShared(Vcb, &Hold);

    if (!NT_SUCCESS(Status))
    {
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND && Missing == FALSE && Disposition != FILE_OPEN &&
            Disposition != FILE_OVERWRITE && Vcb->ReadOnly)
            Status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }
    IsDir = St.is_dir ? TRUE : FALSE;
    if (!Created && !Stream.Length && !(Stack->Flags & SL_OPEN_PAGING_FILE))
    {
        /* The active paging file refuses every other open with a sharing violation, before the
         * attribute checks of an overwrite could answer access denied (as Windows does).  The
         * authoritative check is repeated under the FCB list lock below. */
        PNG_FCB Pf = NgFindFcb(Vcb, St.mft_ref & 0xffffffffffffULL);
        BOOLEAN Paging = Pf && Pf->IsPagingFile;
        if (Pf)
            NgDereferenceFcb(Pf);
        if (Paging)
        {
            Status = STATUS_SHARING_VIOLATION;
            goto out;
        }
    }
    if (!Created)
    {
        /* The type checks come first: CreateFile on a directory fails with access denied for any
         * disposition, and a directory request on a file reports that before anything else. */
        if ((Options & FILE_NON_DIRECTORY_FILE) && IsDir)
        {
            Status = STATUS_FILE_IS_A_DIRECTORY;
            goto out;
        }
        if ((Options & FILE_DIRECTORY_FILE) && !IsDir)
        {
            Status = STATUS_NOT_A_DIRECTORY;
            goto out;
        }
        if (Disposition == FILE_CREATE)
        {
            Status = STATUS_OBJECT_NAME_COLLISION;
            goto out;
        }
        if (Vcb->ReadOnly && ((Disposition != FILE_OPEN && Disposition != FILE_OPEN_IF) ||
                              (Options & FILE_DELETE_ON_CLOSE) || ((Access & NG_WRITE_ACCESS) && !(NgGlobal.PermissiveOpen || Vcb->Damaged))))
        {
            Status = STATUS_MEDIA_WRITE_PROTECTED;
            goto out;
        }
        if (!IsDir && (St.file_attributes & FILE_ATTRIBUTE_READONLY))
        {
            /* Supersede replaces the file and is allowed; overwrite keeps it and is not. */
            if ((Access & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL)) ||
                Disposition == FILE_OVERWRITE || Disposition == FILE_OVERWRITE_IF)
            {
                Status = STATUS_ACCESS_DENIED;
                goto out;
            }
            if (Options & FILE_DELETE_ON_CLOSE)
            {
                Status = STATUS_CANNOT_DELETE;
                goto out;
            }
        }
        if ((Disposition == FILE_OVERWRITE || Disposition == FILE_OVERWRITE_IF || Disposition == FILE_SUPERSEDE))
        {
            if (IsDir)
            {
                Status = STATUS_OBJECT_NAME_COLLISION;
                goto out;
            }
            /* Win32 CREATE_ALWAYS on a hidden or system file must carry those attributes. */
            if (((St.file_attributes & FILE_ATTRIBUTE_HIDDEN) && !(FileAttributes & FILE_ATTRIBUTE_HIDDEN)) ||
                ((St.file_attributes & FILE_ATTRIBUTE_SYSTEM) && !(FileAttributes & FILE_ATTRIBUTE_SYSTEM)))
            {
                Status = STATUS_ACCESS_DENIED;
                goto out;
            }
        }
    }
    if ((Options & FILE_DIRECTORY_FILE) && !IsDir)
    {
        Status = STATUS_NOT_A_DIRECTORY;
        goto out;
    }
    if ((Options & FILE_NON_DIRECTORY_FILE) && IsDir)
    {
        Status = STATUS_FILE_IS_A_DIRECTORY;
        goto out;
    }
    if (Trailing && !IsDir)
    {
        Status = STATUS_OBJECT_NAME_INVALID;
        goto out;
    }
    if (Check && CreatedNode)
    {
        /* The creator of a new file or directory gets what it asked for. */
        NgGrantNewFile(As);
    }
    else if (Check && !StreamChecked)
    {
        ACCESS_MASK Implied = 0;
        if (Disposition == FILE_SUPERSEDE)
            Implied = DELETE;
        else if (Disposition == FILE_OVERWRITE || Disposition == FILE_OVERWRITE_IF)
            Implied = FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
        Status = NgCheckOpen(Vcb, As, Node, Name == &FileObject->FileName ? Parent : NULL, Implied);
        if (!NT_SUCCESS(Status))
            goto out;
    }

    /* The access the handle actually holds, after the check: MAXIMUM_ALLOWED and backup/restore are
     * resolved here, so the sharing, read-only, image and metadata gates below see the real grant. */
    Effective = Access;
    RtlMapGenericMask(&Effective, IoGetFileObjectGenericMapping());
    if (Check)
        Effective = As->PreviouslyGrantedAccess;
    else
    {
        /* A trusted kernel open carries backup/restore-granted bits in PreviouslyGrantedAccess. */
        Effective |= As ? As->PreviouslyGrantedAccess : 0;
        if (Effective & MAXIMUM_ALLOWED)
            Effective = (Effective & ~MAXIMUM_ALLOWED) | FILE_ALL_ACCESS;
    }
    /* A read-only file, or a metadata file, resolves MAXIMUM_ALLOWED and generic rights to write
     * bits the caller did not explicitly request; drop them so the open reads rather than fails. */
    if (!CreatedNode && !IsDir &&
        !((Access | (As ? As->OriginalDesiredAccess : 0)) &
          (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                    WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD | GENERIC_WRITE | GENERIC_ALL)) &&
        Disposition != FILE_OVERWRITE && Disposition != FILE_OVERWRITE_IF && Disposition != FILE_SUPERSEDE &&
        !(Options & FILE_DELETE_ON_CLOSE) && !Stream.Length &&
        (((St.mft_ref & 0xffffffffffffULL) < NG_FIRST_USER_FILE) ||
         (St.file_attributes & FILE_ATTRIBUTE_READONLY)))
    {
        ACCESS_MASK W = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                        WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD;
        Effective &= ~W;
        if (Check)
            As->PreviouslyGrantedAccess &= ~W;
    }

    Ccb = NgAllocateCcb(&Full);
    Fcb = NgAllocateFcb(Vcb);
    if (!Ccb || !Fcb || Stream.Length > sizeof(Fcb->StreamBuffer))
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    if (!OpenTarget && Full.Length > sizeof(WCHAR))
    {
        Ccb->ParentMftNo = PSt.mft_ref & 0xffffffffffffULL;
        Ccb->NameLength = (USHORT)RealLen;
        RtlCopyMemory(Ccb->Name, Real, RealLen * sizeof(WCHAR));
    }
    Ccb->DeleteOnClose = Ccb->OpenedDeleteOnClose = (Options & FILE_DELETE_ON_CLOSE) != 0;
    Ccb->AppendOnly = (Effective & FILE_APPEND_DATA) && !(Effective & FILE_WRITE_DATA);
    Ccb->Granted = Effective;
    Fcb->Node = Node;
    Fcb->HasNode = TRUE;
    Node = NULL;
    Fcb->IsDirectory = IsDir;
    Fcb->IsRoot = (Full.Length == sizeof(WCHAR));
    RtlInitEmptyUnicodeString(&Fcb->Stream, Fcb->StreamBuffer, sizeof(Fcb->StreamBuffer));
    RtlCopyUnicodeString(&Fcb->Stream, &Stream);
    Fcb->Stat = St;
    NgFillStat(Fcb);
    Fcb->LogicalVdl = Fcb->Header.FileSize.QuadPart;
    Found = NgInsertOrFindFcb(Vcb, Fcb);
    Opening = TRUE;
    if (Found != Fcb)
    {
        NgDereferenceFcb(Fcb);
        Fcb = Found;
    }
    if (Fcb->DeletePending)
    {
        Status = STATUS_DELETE_PENDING;
        goto out;
    }
    if (!IsDir && (Fcb->Stat.flags & NGC_ATTR_NOWRITE))
    {
        /* Writes to compressed, encrypted, WOF and sparse streams are not implemented: refuse them here,
         * before Cc or a mapped view could accept data that a paging write would later drop. */
        const ACCESS_MASK W = FILE_WRITE_DATA | FILE_APPEND_DATA;
        ACCESS_MASK Original = As ? As->OriginalDesiredAccess : Access, Asked = Original & ~MAXIMUM_ALLOWED;
        RtlMapGenericMask(&Asked, IoGetFileObjectGenericMapping());
        if (!(Asked & W) && (Original & MAXIMUM_ALLOWED))
        {
            /* A maximum-allowed open gets everything but data writes (the object manager would turn an
             * unresolved MAXIMUM_ALLOWED into GENERIC_ALL), also when a backup privilege granted them. */
            Effective &= ~W;
            if (As)
            {
                As->PreviouslyGrantedAccess = (Check ? As->PreviouslyGrantedAccess : As->PreviouslyGrantedAccess | Effective) & ~W;
                As->RemainingDesiredAccess &= ~(MAXIMUM_ALLOWED | W);
            }
            Ccb->Granted = Effective;
        }
        if (((Effective | (As ? As->RemainingDesiredAccess : 0)) & W) ||
            (!Created && (Disposition == FILE_OVERWRITE || Disposition == FILE_OVERWRITE_IF || Disposition == FILE_SUPERSEDE)))
        {
            DPRINT1("ntfsng: write open of a compressed/encrypted/sparse stream %I64x refused\n", Fcb->MftNo);
            Status = STATUS_ACCESS_DENIED;
            goto out;
        }
    }
    if (((St.mft_ref & 0xffffffffffffULL) < NG_FIRST_USER_FILE || Ccb->ParentMftNo == 11) && !Fcb->IsRoot)
    {
        /* The NTFS metadata files ($MFT, $LogFile, $Bitmap, ...) and the $Extend children are never
         * opened for writing,
         * truncated, deleted, retitled or given a stream; as on Windows, only reads are allowed.
         * The granted access is tested, so MAXIMUM_ALLOWED and backup intent cannot slip a write in. */
        if ((Effective & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                          WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD)) ||
            Disposition == FILE_OVERWRITE || Disposition == FILE_OVERWRITE_IF || Disposition == FILE_SUPERSEDE ||
            (Options & FILE_DELETE_ON_CLOSE) || Stream.Length)
        {
            Status = STATUS_ACCESS_DENIED;
            goto out;
        }
    }
    if (!IsDir && Fcb->SectionObjectPointers.ImageSectionObject &&
        (Effective & FILE_WRITE_DATA) && !MmFlushImageSection(&Fcb->SectionObjectPointers, MmFlushForWrite))
    {
        /* A file mapped as an image (a running program) cannot be opened for writing. */
        Status = STATUS_SHARING_VIOLATION;
        goto out;
    }

    ExAcquireFastMutex(&Vcb->FcbListLock);
    if (Vcb->LockedBy)
    {
        /* The volume was locked after this open passed its first check. */
        ExReleaseFastMutex(&Vcb->FcbListLock);
        Status = STATUS_ACCESS_DENIED;
        goto out;
    }
    if (Fcb->Deleted || Fcb->DeletePending || (Fcb->Stream.Length && NgBaseDeletePendingLocked(Vcb, Fcb->MftNo)))
    {
        /* Its record went with the file's last name while this create ran, or that delete is pending now. */
        Status = STATUS_DELETE_PENDING;
    }
    else
    {
        /* Overwrite and supersede modify the file, so they are checked for sharing against the
         * access they imply (write, or DELETE for supersede) as FastFAT does, even when the caller
         * did not ask for it; the handle itself takes only the access it requested. */
        ACCESS_MASK Added = 0;
        if (!Created)
        {
            if (Disposition == FILE_SUPERSEDE)
                Added = DELETE & ~Effective;
            else if (Disposition == FILE_OVERWRITE || Disposition == FILE_OVERWRITE_IF)
                Added = (FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES) & ~Effective;
        }
        BOOLEAN Paging = (Stack->Flags & SL_OPEN_PAGING_FILE) != 0;
        Status = STATUS_SUCCESS;
        /* The active paging file is open to Mm only; both the guard and the promotion happen here,
         * under the lock, so an ordinary open cannot slip in while Mm promotes the FCB. */
        if (Fcb->IsPagingFile && !Paging)
            Status = STATUS_SHARING_VIOLATION;
        else if (Paging && Fcb->OpenHandles && !Fcb->IsPagingFile)
            Status = STATUS_SHARING_VIOLATION;
        if (NT_SUCCESS(Status) && Fcb->OpenHandles && Added)
            Status = IoCheckShareAccess(Effective | Added, Stack->Parameters.Create.ShareAccess, FileObject,
                                        &Fcb->ShareAccess, FALSE);
        if (NT_SUCCESS(Status))
        {
            if (Fcb->OpenHandles)
                Status = IoCheckShareAccess(Effective, Stack->Parameters.Create.ShareAccess, FileObject,
                                            &Fcb->ShareAccess, TRUE);
            else
                IoSetShareAccess(Effective, Stack->Parameters.Create.ShareAccess, FileObject, &Fcb->ShareAccess);
        }
        if (NT_SUCCESS(Status) && Paging && !Fcb->IsPagingFile)
        {
            Fcb->IsPagingFile = TRUE;
            Vcb->PagingFiles++;
            SetPaging = TRUE;   /* roll back if the paging open fails below */
        }
    }
    if (NT_SUCCESS(Status))
    {
        Fcb->OpenHandles++;
        Shared = TRUE;
        /* From here a rename through another handle of the file updates this one's name too. */
        InsertTailList(&Fcb->CcbList, &Ccb->FcbLinks);
    }
    Fcb->Opening--;
    Opening = FALSE;
    ExReleaseFastMutex(&Vcb->FcbListLock);
    if (!NT_SUCCESS(Status))
        goto out;

    FileObject->FsContext = Fcb;
    FileObject->FsContext2 = Ccb;
    FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;
    FileObject->Vpb = Vcb->Vpb;
    if (Stack->Flags & SL_OPEN_PAGING_FILE)
    {
        /* A paging file is a plain unnamed stream; its page I/O bypasses the core (pagefile.c).
         * IsPagingFile was published under the lock above; undo it here if this open is rejected. */
        if (IsDir || Stream.Length || Vcb->ReadOnly)
        {
            FileObject->FsContext = NULL;
            FileObject->FsContext2 = NULL;
            Status = STATUS_ACCESS_DENIED;
            goto out;
        }
    }

    if (!Created && (Disposition == FILE_OVERWRITE || Disposition == FILE_OVERWRITE_IF || Disposition == FILE_SUPERSEDE))
    {
        unsigned int Attrs = (FileAttributes & NG_SETTABLE_ATTRS) | FILE_ATTRIBUTE_ARCHIVE;
        ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
        Status = NgSetFileSize(Fcb, FileObject, 0);
        if (NT_SUCCESS(Status) && (Fcb->SectionObjectPointers.SharedCacheMap || Fcb->SectionObjectPointers.DataSectionObject))
            NgPurgeFrom(Fcb, 0);
        if (NT_SUCCESS(Status))
        {
            NgAcquireCore(Vcb);
            Err = NgEnsureNode(Fcb);
            if (!Err)
                Err = ngc_set_info(Vcb->Core, Fcb->Node, NULL, Attrs, Stream.Length ? 0 : NG_SETTABLE_ATTRS);
            if (!Err)
                ngc_stat(Fcb->Node, &Fcb->Stat);
            NgAfterChange(Vcb);
            NgReleaseCore(Vcb);
            if (Err)
                Status = NgErrnoToStatus(Err);
        }
        ExReleaseResourceLite(Fcb->Header.Resource);
        if (!NT_SUCCESS(Status))
        {
            FileObject->FsContext = NULL;
            FileObject->FsContext2 = NULL;
            goto out;
        }
        Information = Disposition == FILE_SUPERSEDE ? FILE_SUPERSEDED : FILE_OVERWRITTEN;
        NgNotify(Vcb, &Full, FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_ATTRIBUTES,
                 FILE_ACTION_MODIFIED);
    }
    if (Created && Stream.Length)
        NgNotify(Vcb, &Full, FILE_NOTIFY_CHANGE_STREAM_NAME, FILE_ACTION_ADDED_STREAM);
    else if (Created)
        NgNotify(Vcb, &Full, IsDir ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_ADDED);

    Irp->IoStatus.Information = Information;
    Shared = FALSE;
    Fcb = NULL;
    Ccb = NULL;
    if ((InterlockedIncrement(&NgGlobal.Opens) % 2000) == 0 && NgGlobal.Verbose)
    {
        DPRINT1("ntfsng: %ld opens, %ld FCBs live\n", NgGlobal.Opens, NgGlobal.FcbLive);
        NgAcquireCore(Vcb);
        ngc_debug_dump();
        NgReleaseCore(Vcb);
    }

out:
    if (Opening)
    {
        ExAcquireFastMutex(&Vcb->FcbListLock);
        Fcb->Opening--;
        ExReleaseFastMutex(&Vcb->FcbListLock);
    }
    if (Shared)
    {
        ExAcquireFastMutex(&Vcb->FcbListLock);
        IoRemoveShareAccess(FileObject, &Fcb->ShareAccess);
        Fcb->OpenHandles--;
        RemoveEntryList(&Ccb->FcbLinks);
        if (SetPaging && Fcb->OpenHandles == 0)
        {
            Fcb->IsPagingFile = FALSE;   /* this open promoted it, then failed, and holds the only ref */
            Vcb->PagingFiles--;
        }
        ExReleaseFastMutex(&Vcb->FcbListLock);
    }
    if (Node || Parent)
    {
        NgAcquireCore(Vcb);
        if (Node)
            ngc_put(Node);
        if (Parent)
            ngc_put(Parent);
        NgReleaseCore(Vcb);
    }
    if (Fcb)
        NgDereferenceFcb(Fcb);
    if (Ccb)
        NgFreeCcb(Ccb);
    if (ParentSd)
        ExFreePoolWithTag(ParentSd, TAG_NTFSNG);
    ExFreePoolWithTag(Real, TAG_NTFSNG);
    ExFreePoolWithTag(Full.Buffer, TAG_NTFSNG);
    if (ById.Buffer)
        ExFreePoolWithTag(ById.Buffer, TAG_NTFSNG);
    return Status;
}

static NTSTATUS NgCleanupGated(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/*
 * IRP_MJ_CLEANUP.  A volume handle is marked cleaned up and gives up the volume lock first (a holder
 * that wrote the disk directly dismounts the volume then, NgEndLock); the rest runs with the create
 * gate shared, so the metadata changes of a last cleanup (a delete, timestamps) never land after a
 * volume lock's flush or during a dismount.
 */
/*
 * Mm keeps a file's data section as long as one of its pages is resident: every page holds a reference on the segment,
 * the segment one on the file object, and the file object (whose close frees the FCB) one on the FCB.  Without a
 * handle a file whose data was read or written is therefore never closed, and every such file touched since boot
 * keeps its FCB, file object, CCB and segment.  The FCBs that went idle this way are listed, oldest first;
 * past NgGlobal.FcbCacheMax of them the oldest are flushed and purged, which lets Mm drop the segment, the file
 * object get closed and the FCB freed.  The newest stay: a file opened again soon finds its cached pages.
 * An FCB leaves the list when it is opened again (NgInsertOrFindFcb) or freed (NgFcbRemoveLocked).
 */
static VOID NgFcbTrimIdle(PNG_VCB Vcb);

VOID NgFcbIdle(PNG_FCB Fcb)
{
    PNG_VCB Vcb = Fcb->Vcb;

    if (Fcb->OpenHandles || !Fcb->HasNode || Fcb->IsDirectory || Fcb->IsVolume ||
        !Fcb->SectionObjectPointers.DataSectionObject || NgGlobal.FcbCacheMax == MAXULONG)
        return;
    ExAcquireFastMutex(&Vcb->FcbListLock);
    if (Fcb->VcbLinks.Flink && !Fcb->OpenHandles && !Fcb->Opening && !Fcb->Deleted && !Fcb->DeletePending &&
        !Fcb->IsPagingFile)
    {
        /* Again at the tail when it was listed already: the list is in order of last use. */
        if (Fcb->IdleLinks.Flink)
        {
            RemoveEntryList(&Fcb->IdleLinks);
            Vcb->IdleCount--;
        }
        InsertTailList(&Vcb->IdleList, &Fcb->IdleLinks);
        Vcb->IdleCount++;
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);
    NgFcbTrimIdle(Vcb);
}

/* Caller holds a counted reference, drops it here.  Nothing else is held: closing the file object runs NgClose. */
static VOID NgEvictFcb(PNG_FCB Fcb)
{
    PNG_VCB Vcb = Fcb->Vcb;

    /* Only an idle FCB nobody is working on; a writer that comes in meanwhile waits for the main resource. */
    if (ExAcquireResourceExclusiveLite(&Fcb->MainResource, FALSE))
    {
        BOOLEAN Idle;
        ExAcquireFastMutex(&Vcb->FcbListLock);
        Idle = !Fcb->OpenHandles && !Fcb->Opening && !Fcb->Deleted && !Fcb->DeletePending && !Fcb->IsPagingFile &&
               !Vcb->Dismounted && !Vcb->WrongMedia && !Vcb->LockedBy;
        ExReleaseFastMutex(&Vcb->FcbListLock);
        if (Idle && !Fcb->SectionObjectPointers.SharedCacheMap && Fcb->SectionObjectPointers.DataSectionObject)
        {
            IO_STATUS_BLOCK Iosb;
            NgFlushStream(Fcb, &Iosb);
            if (NT_SUCCESS(Iosb.Status))
                NgPurgeFrom(Fcb, 0);
        }
        ExReleaseResourceLite(&Fcb->MainResource);
    }
    NgDereferenceFcb(Fcb);
}

static VOID NgFcbTrimIdle(PNG_VCB Vcb)
{
    ULONG Round;

    /* A few per call keep a cleanup's latency bounded; one in, one out keeps up in a steady state. */
    for (Round = 0; Round < 8; Round++)
    {
        PNG_FCB Fcb;
        ExAcquireFastMutex(&Vcb->FcbListLock);
        if ((ULONG)Vcb->IdleCount <= NgGlobal.FcbCacheMax || IsListEmpty(&Vcb->IdleList))
        {
            ExReleaseFastMutex(&Vcb->FcbListLock);
            return;
        }
        Fcb = CONTAINING_RECORD(RemoveHeadList(&Vcb->IdleList), NG_FCB, IdleLinks);
        Fcb->IdleLinks.Flink = Fcb->IdleLinks.Blink = NULL;
        Vcb->IdleCount--;
        InterlockedIncrement(&Fcb->RefCount);   /* under the lock: a close cannot free it meanwhile */
        ExReleaseFastMutex(&Vcb->FcbListLock);
        NgEvictFcb(Fcb);
    }
}

NTSTATUS NgCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    PNG_FCB Fcb = FileObject->FsContext;
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    NTSTATUS Status;

    if (!Fcb)
        return STATUS_SUCCESS;
    if (Fcb->IsVolume)
    {
        NgEndLock(Vcb, FileObject, TRUE);
        /* A shrink this handle prepared and did not commit is forgotten (FSCTL_SHRINK_VOLUME). */
        NgAcquireCore(Vcb);
        if (Vcb->ShrinkOwner == FileObject)
        {
            Vcb->ShrinkOwner = NULL;
            Vcb->ShrinkSectors = 0;
        }
        NgReleaseCore(Vcb);
    }
    ExAcquireResourceSharedLite(&Vcb->CreateGate, TRUE);
    /* A dismount that ran while this cleanup waited for the gate left no core behind; a volume cut off
     * from its device (a replaced medium, a removal) may write nothing: only the handle's state goes. */
    Status = (Vcb->Dismounted || Vcb->WrongMedia) ? NgCleanupDismounted(Vcb, Irp) : NgCleanupGated(DeviceObject, Irp);
    ExReleaseResourceLite(&Vcb->CreateGate);
    /* The file object still holds the FCB (its close follows this cleanup). */
    if (NT_SUCCESS(Status))
        NgFcbIdle(Fcb);
    return Status;
}

/* ngc_streams callback: counts the named streams of a file. */
static int NgCountNamedStream(void *Ctx, const unsigned short *Name, unsigned int Len, unsigned long long Size,
                              unsigned long long Alloc)
{
    (void)Name; (void)Size; (void)Alloc;
    if (Len)
        (*(PULONG)Ctx)++;
    return 0;
}

/*
 * IRP_MJ_CREATE.  A create holds CreateGate shared from before its volume checks to its end, and
 * FSCTL_LOCK_VOLUME takes it exclusive to decide the lock, so a lock (and the dismount it allows)
 * never comes while a create runs; one that starts later sees the lock, or the dismount.  A rename
 * takes it exclusive too: no create builds a handle's name from a name that is being renamed.
 */
NTSTATUS NgCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    NTSTATUS Status;
    ExAcquireResourceSharedLite(&Vcb->CreateGate, TRUE);
    if (Vcb->Dismounted)
        Status = STATUS_VOLUME_DISMOUNTED;
    else if (Vcb->RemovePending)
        Status = STATUS_ACCESS_DENIED;
    else
        Status = NgCreateLocked(DeviceObject, Irp);
    ExReleaseResourceLite(&Vcb->CreateGate);
    return Status;
}

/*
 * Unlinks a delete-pending file or directory (caller holds MainResource exclusive and CreateGate, shared
 * at least) at its last cleanup: the name the delete was asked for, or, after a POSIX delete moved the
 * file to $Extend\$Deleted while other handles stayed open (NgPosixUnlink), that name.
 * KeepOpen: handles of the FCB are still open, so it stays listed (volume lock and dismount count its
 * handles) with its node held (the record cannot be reused); its last cleanup unlists it and parks the node.
 * On failure the delete is dropped (DeletePending cleared, except for a file in $Deleted, which the next
 * mount removes) and the status says why.
 */
NTSTATUS NgDeleteNow(PNG_FCB Fcb, BOOLEAN KeepOpen)
{
    PNG_VCB Vcb = Fcb->Vcb;
    ngc_node *Dir;
    int Err;

    NgAcquireCore(Vcb);
    Err = NgEnsureNode(Fcb);
    if (!Err)
        Err = ngc_iget(Vcb->Core, Fcb->DelParentMftNo, &Dir);
    if (!Err)
    {
        /* More than one name for a file: removing this one leaves the others, and the data the
         * cache holds belongs to them, so it is kept and the FCB stays listed and alive. */
        BOOLEAN Gone = TRUE;
        if (Fcb->Stream.Length)
            Err = ngc_delete_stream(Vcb->Core, Fcb->Node);
        else if (Fcb->IsDirectory && ngc_dir_empty(Vcb->Core, Fcb->Node) != 1)
            Err = -NGC_ENOTEMPTY;
        else
        {
            /* The last name of a file whose named stream is open or being opened stays. */
            struct ngc_stat Now;
            ngc_stat(Fcb->Node, &Now);
            if (Now.nlink <= 1 && !NgRetireStreams(Vcb, Fcb->MftNo, Fcb, TRUE))
                Err = -NGC_EBUSY;
            else
                Err = ngc_unlink(Vcb->Core, Dir, Fcb->DelName, Fcb->DelNameLength, Fcb->Node);
            if (!Err)
            {
                Gone = NgNodeGone(Fcb->Node);
                if (Gone)
                    NgDeleteStreams(Vcb, Fcb->MftNo, Fcb);
            }
        }
        ngc_put(Dir);
        if (!Err)
        {
            if (!Fcb->Stream.Length && !Fcb->IsDirectory && !Fcb->Orphan)
                NgTunnelAdd(Vcb, Fcb->DelParentMftNo, Fcb->DelName, Fcb->DelNameLength, Fcb->Stat.crtime);
            if (Gone)
            {
                Fcb->Deleted = TRUE;
                if (!KeepOpen)
                    NgUnlistFcb(Fcb);
            }
            else
            {
                /* The file lives on under another name: this FCB is not deleted, so opens of the
                 * surviving link through it must not see STATUS_DELETE_PENDING.  DelPath is kept for
                 * the removal notification below and freed with the FCB. */
                ngc_stat(Fcb->Node, &Fcb->Stat);   /* the link count dropped */
                Fcb->DeletePending = FALSE;
                Fcb->Orphan = FALSE;
            }
            if (!KeepOpen)
                NgParkNode(Fcb);
            NgAfterChange(Vcb);
        }
    }
    NgReleaseCore(Vcb);
    if (Err)
    {
        DPRINT1("ntfsng: delete of %I64x at last close failed %d\n", Fcb->MftNo, Err);
        /* A file a POSIX delete moved to $Extend\$Deleted stays there, for the next mount to remove. */
        if (!Fcb->Orphan)
            Fcb->DeletePending = FALSE;
    }
    else if (Fcb->DelPath.Buffer)
    {
        if (Fcb->Stream.Length)
            NgNotify(Vcb, &Fcb->DelPath, FILE_NOTIFY_CHANGE_STREAM_NAME, FILE_ACTION_REMOVED_STREAM);
        else
            NgNotify(Vcb, &Fcb->DelPath, Fcb->IsDirectory ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME,
                     FILE_ACTION_REMOVED);
    }
    return Err ? NgErrnoToStatus(Err) : STATUS_SUCCESS;
}

/* Records the name a delete will remove: the one this handle was opened by. */
VOID NgSetDeletePending(PNG_FCB Fcb, PNG_CCB Ccb)
{
    Fcb->DeletePending = TRUE;
    Fcb->DelParentMftNo = Ccb->ParentMftNo;
    Fcb->DelNameLength = Ccb->NameLength;
    RtlCopyMemory(Fcb->DelName, Ccb->Name, Ccb->NameLength * sizeof(WCHAR));
    if (Fcb->DelPath.Buffer)
        ExFreePoolWithTag(Fcb->DelPath.Buffer, TAG_NTFSNG);
    Fcb->DelPath.Buffer = ExAllocatePoolWithTag(PagedPool, Ccb->Path.Length + sizeof(WCHAR), TAG_NTFSNG);
    Fcb->DelPath.Length = Fcb->DelPath.MaximumLength = 0;
    if (Fcb->DelPath.Buffer)
    {
        RtlCopyMemory(Fcb->DelPath.Buffer, Ccb->Path.Buffer, Ccb->Path.Length);
        Fcb->DelPath.Length = Ccb->Path.Length;
        Fcb->DelPath.MaximumLength = Ccb->Path.Length + sizeof(WCHAR);
    }
}

static NTSTATUS NgCleanupGated(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    PNG_FCB Fcb = FileObject->FsContext;
    PNG_CCB Ccb = FileObject->FsContext2;
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    BOOLEAN Last, Delete, Posix = FALSE;

    if (Fcb->IsDirectory && Vcb->NotifySync && Ccb)
        FsRtlNotifyCleanup(Vcb->NotifySync, &Vcb->DirNotifyList, Ccb);
    if (!Fcb->IsDirectory && !Fcb->IsVolume)
        FsRtlFastUnlockAll(&Fcb->FileLock, FileObject, IoGetRequestorProcess(Irp), NULL);
    ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
    /*
     * FILE_DELETE_ON_CLOSE is a classic delete, or a POSIX one after FILE_DISPOSITION_ON_CLOSE | POSIX; without it, a
     * POSIX disposition set through this handle applies (Windows 10: on a handle opened with FILE_DELETE_ON_CLOSE, a
     * POSIX disposition without FILE_DISPOSITION_ON_CLOSE still leaves a classic delete at its cleanup).
     */
    if (Ccb && Ccb->DeleteOnClose && !Fcb->IsRoot && !Fcb->IsVolume && Ccb->NameLength && !Ccb->Orphaned && !Fcb->Orphan)
    {
        NgSetDeletePending(Fcb, Ccb);
        Posix = Ccb->PosixOnClose;
    }
    else if (Ccb && Ccb->PosixDelete && !Ccb->DeleteOnClose)
    {
        Posix = TRUE;
    }
    ExAcquireFastMutex(&Vcb->FcbListLock);
    IoRemoveShareAccess(FileObject, &Fcb->ShareAccess);
    Last = (--Fcb->OpenHandles == 0);
    ExReleaseFastMutex(&Vcb->FcbListLock);
    Delete = Last && Fcb->DeletePending && !Fcb->Deleted;
    /* Other handles stay open: the POSIX delete removes the name now (info.c); the last cleanup frees the file. */
    if (!Last && Posix && Fcb->DeletePending && !Fcb->Deleted && !Fcb->Orphan)
        NgPosixUnlink(Fcb);
    if (Delete && !Fcb->IsDirectory && Fcb->SectionObjectPointers.ImageSectionObject &&
        !MmFlushImageSection(&Fcb->SectionObjectPointers, MmFlushForDelete))
    {
        /* A running program's file is not deleted (FILE_DELETE_ON_CLOSE skipped this check). */
        Fcb->DeletePending = FALSE;
        Delete = FALSE;
    }
    if (!Fcb->IsDirectory && !Fcb->IsVolume)
    {
        BOOLEAN LastLink = FALSE;
        ULONG NamedStreams = 0;
        if (Delete && !Fcb->Stream.Length)
        {
            /* Discard the cache only when this is the file's last name; another hard link's data
             * (and its paging writes through this FCB) must survive the delete of one name. */
            NgAcquireCore(Vcb);
            if (!NgEnsureNode(Fcb))
            {
                LastLink = ngc_links(Fcb->Node) <= 1;
                /* A failed enumeration counts as having named streams (the safe side). */
                if (LastLink && ngc_streams(Fcb->Node, NgCountNamedStream, &NamedStreams))
                    NamedStreams = 1;
            }
            NgReleaseCore(Vcb);
            if (LastLink && !NgRetireStreams(Vcb, Fcb->MftNo, Fcb, FALSE))
            {
                /* A named stream is open: the delete would be refused, so the file and its cached data stay. */
                DPRINT1("ntfsng: delete of %I64x at last close refused, a named stream is open\n", Fcb->MftNo);
                Fcb->DeletePending = FALSE;
                Delete = FALSE;
                LastLink = FALSE;
            }
        }
        if (Delete && (Fcb->Stream.Length || LastLink))
        {
            LARGE_INTEGER Zero;
            IO_STATUS_BLOCK Iosb;
            Zero.QuadPart = 0;
            Iosb.Status = STATUS_SUCCESS;
            /* A stream being opened now can still make the delete fail: the data goes to disk first. */
            if (NamedStreams)
                NgFlushStream(Fcb, &Iosb);
            if (!NT_SUCCESS(Iosb.Status))
            {
                /* Not on disk: the delete is dropped and the cache kept. */
                DPRINT1("ntfsng: delete of %I64x at last close dropped, flush failed 0x%08lx\n", Fcb->MftNo, Iosb.Status);
                Fcb->DeletePending = FALSE;
                Delete = FALSE;
                CcUninitializeCacheMap(FileObject, NULL, NULL);
            }
            else
            {
                CcUninitializeCacheMap(FileObject, &Zero, NULL);
                if (Fcb->SectionObjectPointers.SharedCacheMap || Fcb->SectionObjectPointers.DataSectionObject)
                    NgPurgeFrom(Fcb, 0);
            }
        }
        else
        {
            CcUninitializeCacheMap(FileObject, NULL, NULL);
        }
    }
    /* A file in $Extend\$Deleted stays delete pending, whatever kept it there (the next mount removes it). */
    if (Fcb->Orphan)
        Fcb->DeletePending = TRUE;
    if (Delete)
    {
        NgDeleteNow(Fcb, FALSE);
    }
    else if (Fcb->Modified && Fcb->HasNode)
    {
        /* NTFS updates the last write time when a modified handle is cleaned up. */
        NgApplyModified(Fcb);
        if (Ccb && !Ccb->Orphaned)
            NgNotify(Vcb, &Ccb->Path, FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_ACTION_MODIFIED);
    }
    /* Mm may keep this FCB alive long after the last handle: park the core inode (see NgEnsureNode). */
    if (Last && Fcb->HasNode)
    {
        NgAcquireCore(Vcb);
        ExAcquireFastMutex(&Vcb->FcbListLock);
        Last = (Fcb->OpenHandles == 0);
        if (Last && Fcb->Deleted)
            NgFcbRemoveLocked(Fcb);     /* removed with POSIX semantics while handles were open (NgDeleteNow KeepOpen) */
        ExReleaseFastMutex(&Vcb->FcbListLock);
        if (Last)
        {
            /* The allocation ahead of the size (ngc_set_size) is given back once nobody has the stream open. */
            if (Fcb->Grown && !Fcb->Deleted && !NgEnsureNode(Fcb))
            {
                Fcb->Grown = FALSE;
                if (ngc_trim_alloc(Vcb->Core, Fcb->Node))
                    DPRINT1("ntfsng: trim of the allocation of %I64x failed\n", Fcb->MftNo);
            }
            NgParkNode(Fcb);
        }
        NgReleaseCore(Vcb);
    }
    ExReleaseResourceLite(Fcb->Header.Resource);
    FileObject->Flags |= FO_CLEANUP_COMPLETE;
    return STATUS_SUCCESS;
}

NTSTATUS NgClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    PNG_FCB Fcb = FileObject->FsContext;
    PNG_CCB Ccb = FileObject->FsContext2;
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Ccb)
    {
        /* A volume open's CCB is in no list. */
        if (Fcb && !IsListEmpty(&Ccb->FcbLinks))
        {
            ExAcquireFastMutex(&Fcb->Vcb->FcbListLock);
            RemoveEntryList(&Ccb->FcbLinks);
            ExReleaseFastMutex(&Fcb->Vcb->FcbListLock);
        }
        NgFreeCcb(Ccb);
    }
    if (Fcb)
        NgDereferenceFcb(Fcb);
    FileObject->FsContext = NULL;
    FileObject->FsContext2 = NULL;
    return STATUS_SUCCESS;
}

NTSTATUS NgLockControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    PNG_FCB Fcb = FileObject ? FileObject->FsContext : NULL;
    UNREFERENCED_PARAMETER(DeviceObject);
    if (!Fcb || Fcb->IsDirectory || Fcb->IsVolume)
    {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }
    /* FsRtlProcessFileLock completes the IRP. */
    return FsRtlProcessFileLock(&Fcb->FileLock, Irp, NULL);
}
