/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Loopback network mini-redirector on RDBSS: maps
 *              \\looprdr\share\... onto a local directory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * This driver exists to give every RDBSS path a deterministic test without a
 * network. It plays the part of both the mini-redirector and the "server":
 *
 * - every SRV_OPEN owns one backing handle on the local directory (opened with
 *   full sharing: RDBSS enforces share access per FCB, which is what is under
 *   test), used for non-paging I/O, queries, sets, directory enumeration,
 *   FSCTLs and security;
 * - paging I/O uses one per-FCB backing handle, opened on demand and closed
 *   when the last SRV_OPEN of the FCB closes (so a delete-pending backing file
 *   disappears with the last user handle);
 * - byte-range locks are kept in a small per-FCB lock table owned by
 *   SRV_OPENs ("server-side" locks); non-paging reads and writes from other
 *   SRV_OPENs into a locked range fail with STATUS_FILE_LOCK_CONFLICT like an
 *   SMB server, paging I/O is not checked (it carries cached data).
 *
 * Nothing here is shipped: the driver is built with the kernel-mode tests and
 * loaded by kmtest.exe as the service Kmtest-RdbssLoop.
 */

#include <ntifs.h>
#include <ndk/ketypes.h>
#include <rx.h>
#include <windef.h>

#include "RdbssLoop.h"

#define NDEBUG
#include <debug.h>

#define LOOP_TAG 'pLxN'

typedef struct _LOOP_LOCK
{
    LIST_ENTRY Links;
    PVOID Owner;            /* the SRV_OPEN */
    LONGLONG Offset;
    LONGLONG Length;
    BOOLEAN Exclusive;
} LOOP_LOCK, *PLOOP_LOCK;

typedef struct _LOOP_FCB
{
    BOOLEAN Inited;
    HANDLE PagingHandle;
    LONG OpenSrvOpens;
    LIST_ENTRY Locks;       /* LOOP_LOCK, protected by LoopLockMutex */
    LIST_ENTRY AllFcbs;     /* LoopFcbList, for IOCTL_LOOPRDR_DUMP */
    PMRX_FCB MrxFcb;
} LOOP_FCB, *PLOOP_FCB;

typedef struct _LOOP_SRV_OPEN
{
    HANDLE Handle;
    BOOLEAN IsDirectory;
} LOOP_SRV_OPEN, *PLOOP_SRV_OPEN;

typedef struct _LOOP_FOBX
{
    ULONG Unused;
} LOOP_FOBX, *PLOOP_FOBX;

typedef struct _LOOP_NET_ROOT
{
    BOOLEAN Counted;
} LOOP_NET_ROOT, *PLOOP_NET_ROOT;

typedef struct _LOOP_ASYNC_ITEM
{
    WORK_QUEUE_ITEM WorkItem;
    PRX_CONTEXT RxContext;
    KDPC Dpc;               /* LOOPRDR_OPT_DPC_COMPLETE */
    ULONG DelayMs;          /* LOOPRDR_OPT_LATE */
    BOOLEAN Late;
} LOOP_ASYNC_ITEM, *PLOOP_ASYNC_ITEM;

typedef struct _LOOP_BREAK_ITEM
{
    WORK_QUEUE_ITEM WorkItem;
    PMRX_SRV_CALL SrvCall;
    PMRX_SRV_OPEN SrvOpen;
    PVOID Key;
    ULONG NewState;
    BOOLEAN ForSrvOpen;
    KEVENT Done;
} LOOP_BREAK_ITEM, *PLOOP_BREAK_ITEM;

#define LoopFcb(F)      ((PLOOP_FCB)((PMRX_FCB)(F))->Context)
#define LoopSrvOpen(S)  ((PLOOP_SRV_OPEN)((PMRX_SRV_OPEN)(S))->Context)

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD LoopUnload;
static DRIVER_DISPATCH LoopDispatch;

static MINIRDR_DISPATCH LoopDispatchTable;
static PRDBSS_DEVICE_OBJECT LoopDeviceObject;
static LOOPRDR_COUNTERS LoopCounters;
static FAST_MUTEX LoopRootMutex;
static FAST_MUTEX LoopLockMutex;
static FAST_MUTEX LoopPagingMutex;
static UNICODE_STRING LoopRoot;
static WCHAR LoopRootBuffer[260];
static ULONG LoopBufferingFlags;
static ULONG LoopOptions;
static volatile LONG LoopNextKey;
/* Buffering state the next MRxComputeNewBufferingState answers with */
static volatile LONG LoopBreakNewState;
static KEVENT LoopBreakAckEvent;
/* Live FCBs, for the hang diagnostic (IOCTL_LOOPRDR_DUMP) */
static LIST_ENTRY LoopFcbList;
static FAST_MUTEX LoopFcbListMutex;

#define CountUp(F)   InterlockedIncrement(&LoopCounters.F)
#define CountDown(F) InterlockedDecrement(&LoopCounters.F)

/* ---------------------------------------------------------------------- */
/* Fault injection (LOOPRDR_OPT_FAULTS and friends)                       */
/* ---------------------------------------------------------------------- */

static volatile LONG LoopRandState = 0x2545F491;

static
ULONG
LoopRand(VOID)
{
    ULONG x = (ULONG)InterlockedIncrement(&LoopRandState) * 0x9E3779B1u;

    x ^= x >> 15;
    x *= 0x85EBCA77u;
    x ^= x >> 13;
    return x;
}

/* TRUE (and counted) for 1 call in OneIn when fault injection is on */
static
BOOLEAN
LoopFault(
    _In_ ULONG OneIn)
{
    if (!BooleanFlagOn(LoopOptions, LOOPRDR_OPT_FAULTS) || (LoopRand() % OneIn) != 0)
    {
        return FALSE;
    }
    CountUp(FaultsInjected);
    return TRUE;
}

/* A short random delay (a slow server), at PASSIVE_LEVEL only */
static
VOID
LoopMaybeDelay(VOID)
{
    LARGE_INTEGER Delay;

    if (!BooleanFlagOn(LoopOptions, LOOPRDR_OPT_FAULTS) || KeGetCurrentIrql() != PASSIVE_LEVEL ||
        (LoopRand() % 16) != 0)
    {
        return;
    }
    Delay.QuadPart = -10000LL * (1 + LoopRand() % 20);
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

/* ---------------------------------------------------------------------- */
/* Helpers                                                                */
/* ---------------------------------------------------------------------- */

/* Path of the object relative to the share, from a name that may or may not
 * carry the \server\share prefix */
static
VOID
LoopRelativeName(
    _In_ PMRX_NET_ROOT NetRoot,
    _In_ PUNICODE_STRING Name,
    _Out_ PUNICODE_STRING Relative)
{
    UNICODE_STRING Prefix;

    *Relative = *Name;
    Prefix = *NetRoot->pNetRootName;
    if (Relative->Length >= Prefix.Length)
    {
        UNICODE_STRING Head;

        Head.Buffer = Relative->Buffer;
        Head.Length = Prefix.Length;
        Head.MaximumLength = Prefix.Length;
        if (RtlEqualUnicodeString(&Head, &Prefix, TRUE) &&
            (Relative->Length == Prefix.Length ||
             Relative->Buffer[Prefix.Length / sizeof(WCHAR)] == L'\\'))
        {
            Relative->Buffer += Prefix.Length / sizeof(WCHAR);
            Relative->Length -= Prefix.Length;
            Relative->MaximumLength = Relative->Length;
        }
    }
}

/* Builds root + relative into a pool buffer the caller frees */
static
NTSTATUS
LoopBuildBackingPath(
    _In_ PUNICODE_STRING Relative,
    _Out_ PUNICODE_STRING Path)
{
    ULONG Length;

    ExAcquireFastMutex(&LoopRootMutex);
    Length = LoopRoot.Length + Relative->Length;
    if (LoopRoot.Length == 0 || Length > MAXUSHORT - sizeof(WCHAR))
    {
        ExReleaseFastMutex(&LoopRootMutex);
        return STATUS_BAD_NETWORK_PATH;
    }

    Path->Buffer = ExAllocatePoolWithTag(PagedPool, Length + sizeof(WCHAR), LOOP_TAG);
    if (Path->Buffer == NULL)
    {
        ExReleaseFastMutex(&LoopRootMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Path->Length = 0;
    Path->MaximumLength = (USHORT)(Length + sizeof(WCHAR));
    RtlAppendUnicodeStringToString(Path, &LoopRoot);
    ExReleaseFastMutex(&LoopRootMutex);
    RtlAppendUnicodeStringToString(Path, Relative);
    return STATUS_SUCCESS;
}

static
NTSTATUS
LoopOpenBacking(
    _In_ PUNICODE_STRING Relative,
    _In_ ACCESS_MASK Access,
    _In_ ULONG Attributes,
    _In_ ULONG Disposition,
    _In_ ULONG Options,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_opt_ PVOID EaBuffer,
    _In_ ULONG EaLength,
    _Out_ PHANDLE Handle,
    _Out_opt_ PULONG_PTR Information)
{
    NTSTATUS Status;
    UNICODE_STRING Path;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatus;

    Status = LoopBuildBackingPath(Relative, &Path);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes, &Path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    IoStatus.Information = 0;
    Status = ZwCreateFile(Handle, Access | SYNCHRONIZE | FILE_READ_ATTRIBUTES, &ObjectAttributes, &IoStatus,
                          AllocationSize, Attributes,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          Disposition, Options | FILE_SYNCHRONOUS_IO_NONALERT,
                          EaBuffer, EaLength);
    ExFreePoolWithTag(Path.Buffer, LOOP_TAG);
    if (NT_SUCCESS(Status))
    {
        CountUp(BackingHandles);
    }
    if (Information != NULL)
    {
        *Information = IoStatus.Information;
    }
    return Status;
}

static
VOID
LoopCloseBacking(
    _In_ HANDLE Handle)
{
    ZwClose(Handle);
    CountDown(BackingHandles);
}

static
HANDLE
LoopHandleFromContext(
    _In_ PRX_CONTEXT RxContext)
{
    PMRX_SRV_OPEN SrvOpen;

    SrvOpen = RxContext->pRelevantSrvOpen;
    if (SrvOpen == NULL && RxContext->pFobx != NULL)
    {
        SrvOpen = RxContext->pFobx->pSrvOpen;
    }
    if (SrvOpen == NULL || SrvOpen->Context == NULL)
    {
        return NULL;
    }
    return LoopSrvOpen(SrvOpen)->Handle;
}

/* Paging handle of the FCB, opened on demand */
static
NTSTATUS
LoopGetPagingHandle(
    _In_ PMRX_FCB Fcb,
    _In_ BOOLEAN Write,
    _Out_ PHANDLE Handle)
{
    NTSTATUS Status;
    UNICODE_STRING Relative;
    PLOOP_FCB Ext;

    Ext = LoopFcb(Fcb);
    ExAcquireFastMutex(&LoopPagingMutex);
    if (Ext->PagingHandle == NULL)
    {
        LoopRelativeName(Fcb->pNetRoot, &((PFCB)Fcb)->PrivateAlreadyPrefixedName, &Relative);
        Status = LoopOpenBacking(&Relative, FILE_READ_DATA | FILE_WRITE_DATA, 0, FILE_OPEN,
                                 FILE_NON_DIRECTORY_FILE, NULL, NULL, 0, &Ext->PagingHandle, NULL);
        if (Status == STATUS_ACCESS_DENIED && !Write)
        {
            Status = LoopOpenBacking(&Relative, FILE_READ_DATA, 0, FILE_OPEN,
                                     FILE_NON_DIRECTORY_FILE, NULL, NULL, 0, &Ext->PagingHandle, NULL);
        }
        if (!NT_SUCCESS(Status))
        {
            Ext->PagingHandle = NULL;
            ExReleaseFastMutex(&LoopPagingMutex);
            return Status;
        }
    }
    *Handle = Ext->PagingHandle;
    ExReleaseFastMutex(&LoopPagingMutex);
    return STATUS_SUCCESS;
}

static
VOID
LoopClosePagingHandle(
    _In_ PMRX_FCB Fcb)
{
    PLOOP_FCB Ext;
    HANDLE Handle;

    Ext = LoopFcb(Fcb);
    ExAcquireFastMutex(&LoopPagingMutex);
    Handle = Ext->PagingHandle;
    Ext->PagingHandle = NULL;
    ExReleaseFastMutex(&LoopPagingMutex);
    if (Handle != NULL)
    {
        LoopCloseBacking(Handle);
    }
}

/* ---------------------------------------------------------------------- */
/* "Server-side" byte-range locks                                         */
/* ---------------------------------------------------------------------- */

static
BOOLEAN
LoopRangesOverlap(
    _In_ LONGLONG Offset1,
    _In_ LONGLONG Length1,
    _In_ LONGLONG Offset2,
    _In_ LONGLONG Length2)
{
    /* Zero-length ranges never conflict (as on Windows) */
    if (Length1 == 0 || Length2 == 0)
    {
        return FALSE;
    }
    /* Offsets and lengths are unsigned on the wire; treat them so */
    return ((ULONGLONG)Offset1 < (ULONGLONG)Offset2 + (ULONGLONG)Length2 &&
            (ULONGLONG)Offset2 < (ULONGLONG)Offset1 + (ULONGLONG)Length1);
}

/* Call with LoopLockMutex held */
static
BOOLEAN
LoopLockConflicts(
    _In_ PLOOP_FCB Ext,
    _In_ PVOID Owner,
    _In_ LONGLONG Offset,
    _In_ LONGLONG Length,
    _In_ BOOLEAN ForWrite)
{
    PLIST_ENTRY Entry;

    for (Entry = Ext->Locks.Flink; Entry != &Ext->Locks; Entry = Entry->Flink)
    {
        PLOOP_LOCK Lock = CONTAINING_RECORD(Entry, LOOP_LOCK, Links);

        if (!LoopRangesOverlap(Lock->Offset, Lock->Length, Offset, Length))
        {
            continue;
        }
        if (Lock->Owner == Owner)
        {
            /* The owner may not write into its own shared lock */
            if (ForWrite && !Lock->Exclusive)
            {
                return TRUE;
            }
            continue;
        }
        if (ForWrite || Lock->Exclusive)
        {
            return TRUE;
        }
    }
    return FALSE;
}

static
NTSTATUS
LoopLockRange(
    _In_ PRX_CONTEXT RxContext,
    _In_ BOOLEAN Exclusive)
{
    PLOWIO_CONTEXT LowIo = &RxContext->LowIoContext;
    PLOOP_FCB Ext = LoopFcb(RxContext->pFcb);
    PVOID Owner = RxContext->pRelevantSrvOpen;
    BOOLEAN FailImmediately;
    LONGLONG Offset, Length;
    PLOOP_LOCK Lock;
    ULONG Tries;

    Offset = LowIo->ParamsFor.Locks.ByteOffset;
    Length = LowIo->ParamsFor.Locks.Length;
    /* Locks.Flags carries IrpSp->Flags (SL_FAIL_IMMEDIATELY, SL_EXCLUSIVE_LOCK) */
    FailImmediately = BooleanFlagOn(LowIo->ParamsFor.Locks.Flags, SL_FAIL_IMMEDIATELY);

    Lock = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Lock), LOOP_TAG);
    if (Lock == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Lock->Owner = Owner;
    Lock->Offset = Offset;
    Lock->Length = Length;
    Lock->Exclusive = Exclusive;

    for (Tries = 0; ; ++Tries)
    {
        BOOLEAN Conflict = FALSE;
        PLIST_ENTRY Entry;
        LARGE_INTEGER Delay;

        ExAcquireFastMutex(&LoopLockMutex);
        for (Entry = Ext->Locks.Flink; Entry != &Ext->Locks; Entry = Entry->Flink)
        {
            PLOOP_LOCK Other = CONTAINING_RECORD(Entry, LOOP_LOCK, Links);

            if (!LoopRangesOverlap(Other->Offset, Other->Length, Offset, Length))
            {
                continue;
            }
            /* Shared locks stack; anything exclusive conflicts, even for the
             * same owner (NT semantics) unless both are shared */
            if (Exclusive || Other->Exclusive)
            {
                Conflict = TRUE;
                break;
            }
        }
        /* The SRV_OPEN's server open may be gone while this lock waited (a
         * delete-on-close cleanup releases it): a server refuses locks on a
         * closed handle, and the lock would never be dropped */
        if (!Conflict && (Owner == NULL || ((PMRX_SRV_OPEN)Owner)->Context == NULL ||
                          LoopSrvOpen(Owner)->Handle == NULL))
        {
            ExReleaseFastMutex(&LoopLockMutex);
            ExFreePoolWithTag(Lock, LOOP_TAG);
            return STATUS_FILE_CLOSED;
        }
        if (!Conflict)
        {
            InsertTailList(&Ext->Locks, &Lock->Links);
            ExReleaseFastMutex(&LoopLockMutex);
            CountUp(Locks);
            return STATUS_SUCCESS;
        }
        ExReleaseFastMutex(&LoopLockMutex);

        if (FailImmediately || Tries > 600)
        {
            ExFreePoolWithTag(Lock, LOOP_TAG);
            return STATUS_LOCK_NOT_GRANTED;
        }

        /* A waiting lock: poll every 50 ms, for at most 30 s */
        Delay.QuadPart = -500000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }
}

static
NTSTATUS
LoopUnlockRange(
    _In_ PLOOP_FCB Ext,
    _In_ PVOID Owner,
    _In_ LONGLONG Offset,
    _In_ LONGLONG Length)
{
    PLIST_ENTRY Entry;

    ExAcquireFastMutex(&LoopLockMutex);
    for (Entry = Ext->Locks.Flink; Entry != &Ext->Locks; Entry = Entry->Flink)
    {
        PLOOP_LOCK Lock = CONTAINING_RECORD(Entry, LOOP_LOCK, Links);

        if (Lock->Owner == Owner && Lock->Offset == Offset && Lock->Length == Length)
        {
            RemoveEntryList(&Lock->Links);
            ExReleaseFastMutex(&LoopLockMutex);
            ExFreePoolWithTag(Lock, LOOP_TAG);
            CountUp(Unlocks);
            return STATUS_SUCCESS;
        }
    }
    ExReleaseFastMutex(&LoopLockMutex);
    return STATUS_RANGE_NOT_LOCKED;
}

static
VOID
LoopDropLocksOfOwner(
    _In_ PLOOP_FCB Ext,
    _In_ PVOID Owner)
{
    PLIST_ENTRY Entry, Next;
    LIST_ENTRY Dropped;

    InitializeListHead(&Dropped);
    ExAcquireFastMutex(&LoopLockMutex);
    for (Entry = Ext->Locks.Flink; Entry != &Ext->Locks; Entry = Next)
    {
        PLOOP_LOCK Lock = CONTAINING_RECORD(Entry, LOOP_LOCK, Links);

        Next = Entry->Flink;
        if (Lock->Owner == Owner)
        {
            RemoveEntryList(&Lock->Links);
            InsertTailList(&Dropped, &Lock->Links);
        }
    }
    ExReleaseFastMutex(&LoopLockMutex);

    while (!IsListEmpty(&Dropped))
    {
        Entry = RemoveHeadList(&Dropped);
        ExFreePoolWithTag(CONTAINING_RECORD(Entry, LOOP_LOCK, Links), LOOP_TAG);
    }
}

/* ---------------------------------------------------------------------- */
/* Start/stop, name resolution                                            */
/* ---------------------------------------------------------------------- */

static
NTSTATUS
NTAPI
LoopStart(
    _Inout_ PRX_CONTEXT RxContext,
    _Inout_ PRDBSS_DEVICE_OBJECT RxDeviceObject)
{
    InterlockedExchange(&LoopCounters.Started, 1);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopStop(
    _Inout_ PRX_CONTEXT RxContext,
    _Inout_ PRDBSS_DEVICE_OBJECT RxDeviceObject)
{
    InterlockedExchange(&LoopCounters.Started, 0);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopCreateSrvCall(
    _Inout_ PMRX_SRV_CALL SrvCall,
    _Inout_ PMRX_SRVCALL_CALLBACK_CONTEXT CallbackContext)
{
    UNICODE_STRING Server;
    PMRX_SRVCALLDOWN_STRUCTURE Calldown;

    Calldown = CallbackContext->SrvCalldownStructure;

    /* The name is "\server" */
    RtlInitUnicodeString(&Server, L"\\" LOOPRDR_SERVER);
    if (RtlEqualUnicodeString(SrvCall->pSrvCallName, &Server, TRUE))
    {
        CallbackContext->Status = STATUS_SUCCESS;
        CallbackContext->RecommunicateContext = NULL;
        SrvCall->Flags |= SRVCALL_FLAG_CASE_INSENSITIVE_NETROOTS | SRVCALL_FLAG_CASE_INSENSITIVE_FILENAMES;
        CountUp(SrvCalls);
    }
    else
    {
        CallbackContext->Status = STATUS_BAD_NETWORK_PATH;
    }

    Calldown->CallBack(CallbackContext);
    return STATUS_PENDING;
}

static
NTSTATUS
NTAPI
LoopSrvCallWinnerNotify(
    _Inout_ PMRX_SRV_CALL SrvCall,
    _In_ BOOLEAN ThisMinirdrIsTheWinner,
    _Inout_ PVOID RecommunicateContext)
{
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopFinalizeSrvCall(
    _Inout_ PMRX_SRV_CALL SrvCall,
    _In_ BOOLEAN Force)
{
    CountDown(SrvCalls);
    return STATUS_SUCCESS;
}

static
VOID
NTAPI
LoopExtractNetRootName(
    _In_ PUNICODE_STRING FilePathName,
    _In_ PMRX_SRV_CALL SrvCall,
    _Out_ PUNICODE_STRING NetRootName,
    _Out_opt_ PUNICODE_STRING RestOfName)
{
    PWCH Start, End, Limit;

    /* FilePathName is \server\share\rest: the net root name is \share */
    Start = FilePathName->Buffer + SrvCall->pSrvCallName->Length / sizeof(WCHAR);
    Limit = (PWCH)((PCHAR)FilePathName->Buffer + FilePathName->Length);
    if (Start > Limit)
    {
        Start = Limit;
    }
    End = Start;
    if (End < Limit && *End == L'\\')
    {
        ++End;
    }
    while (End < Limit && *End != L'\\')
    {
        ++End;
    }

    NetRootName->Buffer = Start;
    NetRootName->Length = (USHORT)((PCHAR)End - (PCHAR)Start);
    NetRootName->MaximumLength = NetRootName->Length;

    if (RestOfName != NULL)
    {
        RestOfName->Buffer = End;
        RestOfName->Length = (USHORT)((PCHAR)Limit - (PCHAR)End);
        RestOfName->MaximumLength = RestOfName->Length;
    }
}

static
NTSTATUS
NTAPI
LoopCreateVNetRoot(
    _Inout_ PMRX_CREATENETROOT_CONTEXT CreateNetRootContext)
{
    NTSTATUS Status;
    PMRX_V_NET_ROOT VNetRoot;
    PMRX_NET_ROOT NetRoot;
    UNICODE_STRING Share, Ipc, Name;

    VNetRoot = (PMRX_V_NET_ROOT)CreateNetRootContext->pVNetRoot;
    NetRoot = VNetRoot->pNetRoot;

    /* pNetRootName is \server\share */
    Name = *NetRoot->pNetRootName;
    if (Name.Length > NetRoot->pSrvCall->pSrvCallName->Length)
    {
        Name.Buffer += NetRoot->pSrvCall->pSrvCallName->Length / sizeof(WCHAR);
        Name.Length -= NetRoot->pSrvCall->pSrvCallName->Length;
    }

    RtlInitUnicodeString(&Share, L"\\" LOOPRDR_SHARE);
    RtlInitUnicodeString(&Ipc, L"\\" LOOPRDR_IPC_SHARE);
    if (RtlEqualUnicodeString(&Name, &Share, TRUE))
    {
        if (NetRoot->Type == NET_ROOT_WILD || NetRoot->Type == NET_ROOT_DISK)
        {
            NetRoot->Type = NET_ROOT_DISK;
            NetRoot->DeviceType = FILE_DEVICE_DISK;
            NetRoot->MRxNetRootState = MRX_NET_ROOT_STATE_GOOD;
            Status = STATUS_SUCCESS;
        }
        else
        {
            Status = STATUS_BAD_DEVICE_TYPE;
        }
    }
    else if (RtlEqualUnicodeString(&Name, &Ipc, TRUE))
    {
        /* Accept the connection when RDBSS classified it as a pipe share:
         * RDBSS itself must then refuse opens on it cleanly */
        if (NetRoot->Type == NET_ROOT_PIPE)
        {
            CountUp(PipeNetRoots);
            NetRoot->DeviceType = FILE_DEVICE_NAMED_PIPE;
            NetRoot->MRxNetRootState = MRX_NET_ROOT_STATE_GOOD;
            Status = STATUS_SUCCESS;
        }
        else
        {
            Status = STATUS_BAD_DEVICE_TYPE;
        }
    }
    else
    {
        Status = STATUS_BAD_NETWORK_NAME;
    }

    if (NT_SUCCESS(Status))
    {
        PLOOP_NET_ROOT NetRootExt = NetRoot->Context;

        /* RDBSS manages the net root extension (zeroed at allocation) */
        if (!NetRootExt->Counted)
        {
            NetRootExt->Counted = TRUE;
            CountUp(NetRoots);
        }
        CountUp(VNetRoots);
        VNetRoot->Context = VNetRoot;
    }

    CreateNetRootContext->VirtualNetRootStatus = Status;
    CreateNetRootContext->NetRootStatus = Status;
    CreateNetRootContext->Callback(CreateNetRootContext);
    return STATUS_PENDING;
}

static
NTSTATUS
NTAPI
LoopFinalizeVNetRoot(
    _Inout_ PMRX_V_NET_ROOT VirtualNetRoot,
    _In_ PBOOLEAN Force)
{
    if (VirtualNetRoot->Context != NULL)
    {
        VirtualNetRoot->Context = NULL;
        CountDown(VNetRoots);
    }
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopFinalizeNetRoot(
    _Inout_ PMRX_NET_ROOT NetRoot,
    _In_ PBOOLEAN Force)
{
    PLOOP_NET_ROOT NetRootExt = NetRoot->Context;

    if (NetRootExt != NULL && NetRootExt->Counted)
    {
        NetRootExt->Counted = FALSE;
        CountDown(NetRoots);
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------------- */
/* Create, close                                                          */
/* ---------------------------------------------------------------------- */

static
NTSTATUS
NTAPI
LoopCreate(
    _Inout_ PRX_CONTEXT RxContext)
{
    NTSTATUS Status;
    PMRX_FCB Fcb;
    PMRX_SRV_OPEN SrvOpen;
    PNT_CREATE_PARAMETERS Params;
    UNICODE_STRING Relative;
    HANDLE Handle;
    ULONG_PTR Information;
    ULONG Options;
    ACCESS_MASK Access;
    IO_STATUS_BLOCK IoStatus;
    FILE_BASIC_INFORMATION Basic;
    FILE_STANDARD_INFORMATION Standard;
    FCB_INIT_PACKET InitPacket;
    PLOOP_SRV_OPEN Ext;

    /* Injected failure before anything is set up, as a server refusing */
    if (LoopFault(16))
    {
        return STATUS_UNEXPECTED_NETWORK_ERROR;
    }
    LoopMaybeDelay();

    Fcb = RxContext->pFcb;
    SrvOpen = RxContext->pRelevantSrvOpen;
    Params = &RxContext->Create.NtCreateParameters;

    LoopRelativeName(Fcb->pNetRoot, &((PFCB)Fcb)->PrivateAlreadyPrefixedName, &Relative);
    DPRINT("LoopCreate %wZ -> %wZ disp %lu opts %lx\n", &((PFCB)Fcb)->PrivateAlreadyPrefixedName,
           &Relative, Params->Disposition, Params->CreateOptions);

    /* The backing open is a "server" open: buffering options are the
     * client's business, the rest is passed on */
    Options = Params->CreateOptions & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH |
                                       FILE_DELETE_ON_CLOSE | FILE_OPEN_FOR_BACKUP_INTENT |
                                       FILE_OPEN_REPARSE_POINT | FILE_RANDOM_ACCESS | FILE_SEQUENTIAL_ONLY);
    Access = Params->DesiredAccess;

    Status = LoopOpenBacking(&Relative, Access, Params->FileAttributes, Params->Disposition, Options,
                             Params->AllocationSize.QuadPart != 0 ? &Params->AllocationSize : NULL,
                             RxContext->Create.EaBuffer, RxContext->Create.EaLength, &Handle, &Information);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = ZwQueryInformationFile(Handle, &IoStatus, &Basic, sizeof(Basic), FileBasicInformation);
    if (NT_SUCCESS(Status))
    {
        Status = ZwQueryInformationFile(Handle, &IoStatus, &Standard, sizeof(Standard), FileStandardInformation);
    }
    if (!NT_SUCCESS(Status))
    {
        LoopCloseBacking(Handle);
        return Status;
    }

    /* The FCB is shared by all opens of the name: initialize it once */
    if (!LoopFcb(Fcb)->Inited)
    {
        LoopFcb(Fcb)->Inited = TRUE;
        LoopFcb(Fcb)->PagingHandle = NULL;
        LoopFcb(Fcb)->OpenSrvOpens = 0;
        InitializeListHead(&LoopFcb(Fcb)->Locks);
        LoopFcb(Fcb)->MrxFcb = Fcb;
        ExAcquireFastMutex(&LoopFcbListMutex);
        InsertTailList(&LoopFcbList, &LoopFcb(Fcb)->AllFcbs);
        ExReleaseFastMutex(&LoopFcbListMutex);
        CountUp(Fcbs);
    }
    if (Fcb->OpenCount == 0 || NodeType(Fcb) == RDBSS_STORAGE_NTC(FileTypeNotYetKnown))
    {
        LARGE_INTEGER Vdl = Standard.EndOfFile;

        RxFormInitPacket(InitPacket, &Basic.FileAttributes, &Standard.NumberOfLinks,
                         &Basic.CreationTime, &Basic.LastAccessTime, &Basic.LastWriteTime,
                         &Basic.ChangeTime, &Standard.AllocationSize, &Standard.EndOfFile, &Vdl);
        RxFinishFcbInitialization(Fcb,
                                  RDBSS_STORAGE_NTC(Standard.Directory ? FileTypeDirectory : FileTypeFile),
                                  &InitPacket);
    }

    Ext = LoopSrvOpen(SrvOpen);
    Ext->Handle = Handle;
    Ext->IsDirectory = Standard.Directory;
    InterlockedIncrement(&LoopFcb(Fcb)->OpenSrvOpens);
    CountUp(SrvOpens);

    /* The key buffering state change requests are matched against */
    SrvOpen->Key = UlongToPtr((ULONG)InterlockedIncrement(&LoopNextKey));
    if (!Standard.Directory)
    {
        SrvOpen->BufferingFlags = LoopBufferingFlags;
    }

    RxContext->pFobx = RxCreateNetFobx(RxContext, SrvOpen);
    if (RxContext->pFobx == NULL)
    {
        /* RDBSS closes the SRV_OPEN (MRxCloseSrvOpen) on failure */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    CountUp(Fobxs);

    RxContext->Create.ReturnedCreateInformation = (ULONG)Information;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopCollapseOpen(
    _Inout_ PRX_CONTEXT RxContext)
{
    /* Never asked: LoopShouldTryToCollapseThisOpen refuses collapsing */
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static
NTSTATUS
NTAPI
LoopShouldTryToCollapseThisOpen(
    _Inout_ PRX_CONTEXT RxContext)
{
    /* One backing open per user open */
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/* Closes the "server" open of a SRV_OPEN (once) */
static
VOID
LoopReleaseSrvOpen(
    _In_ PMRX_FCB Fcb,
    _In_ PMRX_SRV_OPEN SrvOpen)
{
    PLOOP_SRV_OPEN Ext;
    HANDLE Handle;

    if (SrvOpen->Context == NULL)
    {
        return;
    }

    Ext = LoopSrvOpen(SrvOpen);
    /* Take the handle away under the lock mutex first: a lock request that
     * waited for another owner sees it gone and is refused, instead of being
     * granted after its owner's locks were dropped */
    ExAcquireFastMutex(&LoopLockMutex);
    Handle = Ext->Handle;
    Ext->Handle = NULL;
    ExReleaseFastMutex(&LoopLockMutex);
    if (Handle != NULL)
    {
        LoopDropLocksOfOwner(LoopFcb(Fcb), SrvOpen);
        LoopCloseBacking(Handle);
        CountDown(SrvOpens);
        if (InterlockedDecrement(&LoopFcb(Fcb)->OpenSrvOpens) == 0)
        {
            LoopClosePagingHandle(Fcb);
        }
    }
}

static
NTSTATUS
NTAPI
LoopCleanupFobx(
    _Inout_ PRX_CONTEXT RxContext)
{
    PMRX_FCB Fcb = RxContext->pFcb;

    /* The last handle of a file being deleted: close the server opens now,
     * so that the server deletes it at cleanup like a local file system,
     * not when the last reference goes away (RDBSS holds the FCB
     * exclusive here) */
    if (Fcb->UncleanCount == 0 && BooleanFlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE))
    {
        PLIST_ENTRY Entry;

        for (Entry = Fcb->SrvOpenList.Flink; Entry != &Fcb->SrvOpenList; Entry = Entry->Flink)
        {
            LoopReleaseSrvOpen(Fcb, CONTAINING_RECORD(Entry, MRX_SRV_OPEN, SrvOpenQLinks));
        }
    }
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopCloseSrvOpen(
    _Inout_ PRX_CONTEXT RxContext)
{
    PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;

    /* LOOPRDR_OPT_BREAK_IN_CLOSE: the "server" breaks the oplock of a handle
     * the client is closing, the classic crossing. RDBSS holds the FCB
     * exclusive here: the buffering state handler has to wait for it, then
     * finds the SRV_OPEN closed and its request purged */
    if (SrvOpen != NULL && BooleanFlagOn(LoopOptions, LOOPRDR_OPT_BREAK_IN_CLOSE) &&
        SrvOpen->Key != NULL && SrvOpen->Key != (PVOID)-1)
    {
        LARGE_INTEGER Delay;

        CountUp(BreaksInClose);
        RxIndicateChangeOfBufferingState(RxContext->pFcb->pNetRoot->pSrvCall, SrvOpen->Key, ULongToPtr(0));
        Delay.QuadPart = -10000LL * 300;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    if (SrvOpen != NULL)
    {
        LoopReleaseSrvOpen(RxContext->pFcb, SrvOpen);
    }
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopGetConnectionId(
    _Inout_ PRX_CONTEXT RxContext,
    _Out_ PRX_CONNECTION_ID UniqueId)
{
    /* LOOPRDR_OPT_SLOW_CONNECT: a create that is past RDBSS's state check
     * but has not built any connection structure yet, for a while */
    if (BooleanFlagOn(LoopOptions, LOOPRDR_OPT_SLOW_CONNECT))
    {
        LARGE_INTEGER Delay;

        CountUp(SlowConnects);
        Delay.QuadPart = -10000LL * 1000;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    /* RDBSS zeroed the ID: one connection per server and share */
    return STATUS_NOT_IMPLEMENTED;
}

static
NTSTATUS
NTAPI
LoopDeallocateForFcb(
    _Inout_ PMRX_FCB Fcb)
{
    if (Fcb->Context != NULL && LoopFcb(Fcb)->Inited)
    {
        ExAcquireFastMutex(&LoopFcbListMutex);
        RemoveEntryList(&LoopFcb(Fcb)->AllFcbs);
        ExReleaseFastMutex(&LoopFcbListMutex);
        LoopClosePagingHandle(Fcb);
        /* Server locks nobody dropped: counted (the test fails on them) and
         * freed, rather than an assertion that stops the machine */
        while (!IsListEmpty(&LoopFcb(Fcb)->Locks))
        {
            PLOOP_LOCK Lock = CONTAINING_RECORD(RemoveHeadList(&LoopFcb(Fcb)->Locks), LOOP_LOCK, Links);

            DPRINT1("Server lock %I64x+%I64x of %p left on FCB %p\n", Lock->Offset, Lock->Length, Lock->Owner, Fcb);
            ExFreePoolWithTag(Lock, LOOP_TAG);
            CountUp(LeakedServerLocks);
        }
        LoopFcb(Fcb)->Inited = FALSE;
        CountDown(Fcbs);
    }
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopDeallocateForFobx(
    _Inout_ PMRX_FOBX Fobx)
{
    CountDown(Fobxs);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopForceClosed(
    _Inout_ PMRX_SRV_OPEN SrvOpen)
{
    /* Finalization of a SRV_OPEN RDBSS did not close (MRxCloseSrvOpen is
     * skipped for one that is not in good condition): release the server
     * open if it is still there */
    LoopReleaseSrvOpen(SrvOpen->pFcb, SrvOpen);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopAreFilesAliased(
    _In_ PFCB Fcb1,
    _In_ PFCB Fcb2)
{
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static
NTSTATUS
NTAPI
LoopIsValidDirectory(
    _Inout_ PRX_CONTEXT RxContext,
    _In_ PUNICODE_STRING DirectoryName)
{
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------------- */
/* Read/write                                                             */
/* ---------------------------------------------------------------------- */

static
NTSTATUS
LoopDoReadWrite(
    _Inout_ PRX_CONTEXT RxContext)
{
    NTSTATUS Status;
    PLOWIO_CONTEXT LowIo = &RxContext->LowIoContext;
    BOOLEAN Write, Paging;
    HANDLE Handle;
    PVOID Buffer;
    LARGE_INTEGER Offset;
    IO_STATUS_BLOCK IoStatus;

    Write = (LowIo->Operation == LOWIO_OP_WRITE);
    Paging = BooleanFlagOn(LowIo->ParamsFor.ReadWrite.Flags, LOWIO_READWRITEFLAG_PAGING_IO);

    if (Paging)
    {
        Status = LoopGetPagingHandle(RxContext->pFcb, Write, &Handle);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
        if (Write) CountUp(PagingWrites); else CountUp(PagingReads);
    }
    else
    {
        Handle = LoopHandleFromContext(RxContext);
        if (Handle == NULL)
        {
            return STATUS_INVALID_HANDLE;
        }
        if (Write) CountUp(Writes); else CountUp(Reads);

        /* Server-side lock enforcement for non-paging I/O */
        ExAcquireFastMutex(&LoopLockMutex);
        if (LoopLockConflicts(LoopFcb(RxContext->pFcb), RxContext->pRelevantSrvOpen,
                              LowIo->ParamsFor.ReadWrite.ByteOffset,
                              LowIo->ParamsFor.ReadWrite.ByteCount, Write))
        {
            ExReleaseFastMutex(&LoopLockMutex);
            return STATUS_FILE_LOCK_CONFLICT;
        }
        ExReleaseFastMutex(&LoopLockMutex);
    }

    Buffer = MmGetSystemAddressForMdlSafe(LowIo->ParamsFor.ReadWrite.Buffer, NormalPagePriority);
    if (Buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Offset.QuadPart = LowIo->ParamsFor.ReadWrite.ByteOffset;
    if (Write)
    {
        Status = ZwWriteFile(Handle, NULL, NULL, NULL, &IoStatus, Buffer,
                             LowIo->ParamsFor.ReadWrite.ByteCount, &Offset, NULL);
    }
    else
    {
        Status = ZwReadFile(Handle, NULL, NULL, NULL, &IoStatus, Buffer,
                            LowIo->ParamsFor.ReadWrite.ByteCount, &Offset, NULL);
    }

    RxContext->IoStatusBlock.Information = NT_SUCCESS(Status) ? IoStatus.Information : 0;
    return Status;
}

/* LOOPRDR_OPT_DPC_COMPLETE: the completion is signalled at DISPATCH_LEVEL,
 * which the RxLowIoCompletion contract allows (RDBSS posts the rest) */
static
VOID
NTAPI
LoopCompletionDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    PLOOP_ASYNC_ITEM Item = Context;
    PRX_CONTEXT RxContext = Item->RxContext;

    ExFreePoolWithTag(Item, LOOP_TAG);
    CountUp(AsyncCompletions);
    CountUp(DpcCompletions);
    CountDown(PendingAsync);
    RxLowIoCompletion(RxContext);
}

static
VOID
NTAPI
LoopAsyncWorker(
    _In_ PVOID Context)
{
    PLOOP_ASYNC_ITEM Item = Context;
    PRX_CONTEXT RxContext = Item->RxContext;

    if (Item->DelayMs != 0)
    {
        LARGE_INTEGER Delay;

        Delay.QuadPart = -10000LL * Item->DelayMs;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    RxContext->IoStatusBlock.Status = LoopDoReadWrite(RxContext);
    if (Item->Late)
    {
        CountUp(LateCompletions);
    }

    if (Item->Late && BooleanFlagOn(LoopOptions, LOOPRDR_OPT_DPC_COMPLETE) && (LoopRand() % 2) == 0)
    {
        KeInsertQueueDpc(&Item->Dpc, NULL, NULL);
        return;
    }

    if (Item->Late && BooleanFlagOn(LoopOptions, LOOPRDR_OPT_DUP_COMPLETE))
    {
        NTSTATUS Status;

        /* A buggy mini-redirector completing twice. Our reference keeps the
         * RX_CONTEXT memory valid for the second call; RDBSS must refuse it
         * (and stop a Debug build) instead of completing the IRP again */
        ExFreePoolWithTag(Item, LOOP_TAG);
        CountUp(AsyncCompletions);
        CountDown(PendingAsync);
        InterlockedIncrement((volatile long *)&RxContext->ReferenceCount);
        RxLowIoCompletion(RxContext);
        Status = RxLowIoCompletion(RxContext);
        if (Status == STATUS_INVALID_PARAMETER)
        {
            CountUp(DupRefused);
        }
        RxDereferenceAndDeleteRxContext(RxContext);
        return;
    }

    ExFreePoolWithTag(Item, LOOP_TAG);
    CountUp(AsyncCompletions);
    CountDown(PendingAsync);
    RxLowIoCompletion(RxContext);
}

static
NTSTATUS
NTAPI
LoopReadWrite(
    _Inout_ PRX_CONTEXT RxContext)
{
    BOOLEAN Async, Late, Paging;

    Paging = BooleanFlagOn(RxContext->LowIoContext.ParamsFor.ReadWrite.Flags, LOWIO_READWRITEFLAG_PAGING_IO);
    if (Paging ? (BooleanFlagOn(LoopOptions, LOOPRDR_OPT_PAGING_FAULTS) && LoopFault(64)) : LoopFault(16))
    {
        return STATUS_UNEXPECTED_NETWORK_ERROR;
    }
    LoopMaybeDelay();

    /* Asynchronous requests can be completed from a worker, as a network
     * mini-redirector completes them from its receive path. With
     * LOOPRDR_OPT_LATE, synchronous ones too (RDBSS waits), after a delay */
    Async = BooleanFlagOn(LoopOptions, LOOPRDR_OPT_ASYNC_LOWIO) &&
            BooleanFlagOn(RxContext->Flags, RX_CONTEXT_FLAG_ASYNC_OPERATION);
    Late = BooleanFlagOn(LoopOptions, LOOPRDR_OPT_LATE) && (LoopRand() % 2) == 0;
    if (Async || Late)
    {
        PLOOP_ASYNC_ITEM Item;

        Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Item), LOOP_TAG);
        if (Item != NULL)
        {
            Item->RxContext = RxContext;
            Item->Late = Late;
            Item->DelayMs = Late ? (LoopRand() % 20) : 0;
            KeInitializeDpc(&Item->Dpc, LoopCompletionDpc, Item);
            CountUp(PendingAsync);
            ExInitializeWorkItem(&Item->WorkItem, LoopAsyncWorker, Item);
            ExQueueWorkItem(&Item->WorkItem, DelayedWorkQueue);
            return STATUS_PENDING;
        }
    }

    return LoopDoReadWrite(RxContext);
}

static
ULONG
NTAPI
LoopExtendForCache(
    _Inout_ PRX_CONTEXT RxContext,
    _Inout_ PLARGE_INTEGER NewFileSize,
    _Out_ PLARGE_INTEGER NewAllocationSize)
{
    CountUp(ExtendForCache);
    /* The backing file grows with the writes */
    NewAllocationSize->QuadPart = NewFileSize->QuadPart;
    return STATUS_SUCCESS;
}

static
ULONG
NTAPI
LoopExtendForNonCache(
    _Inout_ PRX_CONTEXT RxContext,
    _Inout_ PLARGE_INTEGER NewFileSize,
    _Out_ PLARGE_INTEGER NewAllocationSize)
{
    CountUp(ExtendForNonCache);
    NewAllocationSize->QuadPart = NewFileSize->QuadPart;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopZeroExtend(
    _Inout_ PRX_CONTEXT RxContext)
{
    /* The backing file system zero-fills */
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopTruncate(
    _Inout_ PRX_CONTEXT RxContext)
{
    return STATUS_SUCCESS;
}

/* ZwFlushBuffersFile is not a kernel export: send the flush ourselves */
static
NTSTATUS
LoopFlushHandle(
    _In_ HANDLE Handle)
{
    NTSTATUS Status;
    PFILE_OBJECT FileObject;
    PDEVICE_OBJECT DeviceObject;
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;

    Status = ObReferenceObjectByHandle(Handle, 0, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, NULL);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    DeviceObject = IoGetRelatedDeviceObject(FileObject);
    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_FLUSH_BUFFERS, DeviceObject, NULL, 0, NULL, &Event, &IoStatus);
    if (Irp == NULL)
    {
        ObDereferenceObject(FileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IoGetNextIrpStackLocation(Irp)->FileObject = FileObject;

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

    ObDereferenceObject(FileObject);
    return Status;
}

static
NTSTATUS
NTAPI
LoopFlush(
    _Inout_ PRX_CONTEXT RxContext)
{
    HANDLE Handle;
    NTSTATUS Status = STATUS_SUCCESS;

    CountUp(Flushes);
    if (LoopFault(16))
    {
        return STATUS_UNEXPECTED_NETWORK_ERROR;
    }
    LoopMaybeDelay();
    if (BooleanFlagOn(LoopOptions, LOOPRDR_OPT_SLOW_FLUSH))
    {
        LARGE_INTEGER Delay;

        Delay.QuadPart = -10000LL * 500;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }
    Handle = LoopHandleFromContext(RxContext);
    if (Handle != NULL)
    {
        Status = LoopFlushHandle(Handle);
        /* A read-only backing handle cannot be flushed; nothing to flush */
        if (Status == STATUS_ACCESS_DENIED)
        {
            Status = STATUS_SUCCESS;
        }
    }
    return Status;
}

/* ---------------------------------------------------------------------- */
/* Locks, FSCTL, IOCTL                                                    */
/* ---------------------------------------------------------------------- */

static
NTSTATUS
NTAPI
LoopIsLockRealizable(
    _Inout_ PMRX_FCB Fcb,
    _In_ PLARGE_INTEGER ByteOffset,
    _In_ PLARGE_INTEGER Length,
    _In_ ULONG LowIoLockFlags)
{
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopLowIoLock(
    _Inout_ PRX_CONTEXT RxContext)
{
    if (LoopFault(16))
    {
        return STATUS_UNEXPECTED_NETWORK_ERROR;
    }
    LoopMaybeDelay();
    return LoopLockRange(RxContext, RxContext->LowIoContext.Operation == LOWIO_OP_EXCLUSIVELOCK);
}

static
NTSTATUS
NTAPI
LoopLowIoUnlock(
    _Inout_ PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIo = &RxContext->LowIoContext;
    PLOOP_FCB Ext = LoopFcb(RxContext->pFcb);

    if (LowIo->Operation == LOWIO_OP_UNLOCK)
    {
        return LoopUnlockRange(Ext, RxContext->pRelevantSrvOpen,
                               LowIo->ParamsFor.Locks.ByteOffset, LowIo->ParamsFor.Locks.Length);
    }
    else
    {
        PLOWIO_LOCK_LIST List;

        CountUp(UnlockMultiple);
        for (List = LowIo->ParamsFor.Locks.LockList; List != NULL; List = List->Next)
        {
            LoopUnlockRange(Ext, RxContext->pRelevantSrvOpen, List->ByteOffset, List->Length);
        }
        return STATUS_SUCCESS;
    }
}

static
NTSTATUS
LoopEcho(
    _In_ XXCTL_LOWIO_COMPONENT * Ctl,
    _Inout_ PRX_CONTEXT RxContext)
{
    ULONG i, Length;
    PUCHAR In, Out;
    UCHAR Temp[64];

    Length = min(Ctl->InputBufferLength, Ctl->OutputBufferLength);
    if (Length > sizeof(Temp))
    {
        return STATUS_INVALID_PARAMETER;
    }
    In = Ctl->pInputBuffer;
    Out = Ctl->pOutputBuffer;
    if (Length != 0 && (In == NULL || Out == NULL))
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* In and out may be the same buffer (METHOD_BUFFERED) */
    RtlCopyMemory(Temp, In, Length);
    for (i = 0; i < Length; ++i)
    {
        Out[i] = Temp[Length - 1 - i];
    }
    RxContext->IoStatusBlock.Information = Length;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopLowIoFsCtl(
    _Inout_ PRX_CONTEXT RxContext)
{
    XXCTL_LOWIO_COMPONENT * FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;

    CountUp(FsCtls);
    if (LoopFault(16))
    {
        return STATUS_UNEXPECTED_NETWORK_ERROR;
    }
    if (FsCtl->FsControlCode == FSCTL_LOOPRDR_ECHO || FsCtl->FsControlCode == FSCTL_LOOPRDR_ECHO_DIRECT)
    {
        return LoopEcho(FsCtl, RxContext);
    }

    /* Pass-through to the backing file only for buffered controls: the other
     * methods carry raw user pointers this driver will not hand to a
     * kernel-mode call */
    if (METHOD_FROM_CTL_CODE(FsCtl->FsControlCode) != METHOD_BUFFERED)
    {
        return STATUS_NOT_SUPPORTED;
    }
    Handle = LoopHandleFromContext(RxContext);
    if (Handle == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }
    Status = ZwFsControlFile(Handle, NULL, NULL, NULL, &IoStatus, FsCtl->FsControlCode,
                             FsCtl->pInputBuffer, FsCtl->InputBufferLength,
                             FsCtl->pOutputBuffer, FsCtl->OutputBufferLength);
    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
    {
        RxContext->IoStatusBlock.Information = IoStatus.Information;
    }
    return Status;
}

static
NTSTATUS
NTAPI
LoopLowIoIoCtl(
    _Inout_ PRX_CONTEXT RxContext)
{
    XXCTL_LOWIO_COMPONENT * IoCtl = &RxContext->LowIoContext.ParamsFor.IoCtl;

    CountUp(IoCtls);
    if (IoCtl->IoControlCode == IOCTL_LOOPRDR_FILE_ECHO)
    {
        return LoopEcho(IoCtl, RxContext);
    }
    return STATUS_INVALID_DEVICE_REQUEST;
}

static
NTSTATUS
NTAPI
LoopLowIoNotify(
    _Inout_ PRX_CONTEXT RxContext)
{
    /* Change notification is not provided by this mini-redirector */
    return STATUS_NOT_SUPPORTED;
}

/* ---------------------------------------------------------------------- */
/* Query/set                                                              */
/* ---------------------------------------------------------------------- */

/*
 * Directory query on the backing handle, by IRP: NtQueryDirectoryFile drops
 * the search pattern of kernel-mode callers (it only passes the pattern it
 * captured from user mode), so ZwQueryDirectoryFile cannot be used here.
 */
static
NTSTATUS
LoopQueryDirectoryIrp(
    _In_ HANDLE Handle,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS Class,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING Template,
    _In_ BOOLEAN RestartScan,
    _Out_ PIO_STATUS_BLOCK IoStatus)
{
    NTSTATUS Status;
    PFILE_OBJECT FileObject;
    PDEVICE_OBJECT DeviceObject;
    PIO_STACK_LOCATION Stack;
    PVOID Bounce = NULL;
    KEVENT Event;
    PIRP Irp;
    PMDL Mdl = NULL;

    Status = ObReferenceObjectByHandle(Handle, FILE_LIST_DIRECTORY, *IoFileObjectType, KernelMode,
                                       (PVOID *)&FileObject, NULL);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    DeviceObject = IoGetRelatedDeviceObject(FileObject);
    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if (Irp == NULL)
    {
        ObDereferenceObject(FileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp->UserBuffer = Buffer;
    Irp->UserIosb = IoStatus;
    Irp->UserEvent = &Event;
    Irp->RequestorMode = KernelMode;
    /* The I/O manager drops our file object reference when it completes the
     * IRP (it is the IRP's original file object) */
    Irp->Tail.Overlay.OriginalFileObject = FileObject;
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    Irp->Flags = IRP_SYNCHRONOUS_API;

    if (DeviceObject->Flags & DO_BUFFERED_IO)
    {
        Bounce = ExAllocatePoolWithTag(NonPagedPool, Length, LOOP_TAG);
        if (Bounce == NULL)
        {
            IoFreeIrp(Irp);
            ObDereferenceObject(FileObject);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Irp->AssociatedIrp.SystemBuffer = Bounce;
    }
    else if (DeviceObject->Flags & DO_DIRECT_IO)
    {
        Mdl = IoAllocateMdl(Buffer, Length, FALSE, FALSE, Irp);
        if (Mdl == NULL)
        {
            IoFreeIrp(Irp);
            ObDereferenceObject(FileObject);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        /* The buffer is RDBSS's system mapping of the locked user buffer */
        MmBuildMdlForNonPagedPool(Mdl);
    }

    Stack = IoGetNextIrpStackLocation(Irp);
    Stack->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
    Stack->MinorFunction = IRP_MN_QUERY_DIRECTORY;
    Stack->FileObject = FileObject;
    Stack->Parameters.QueryDirectory.Length = Length;
    Stack->Parameters.QueryDirectory.FileName = Template;
    Stack->Parameters.QueryDirectory.FileInformationClass = Class;
    Stack->Parameters.QueryDirectory.FileIndex = 0;
    Stack->Flags = (RestartScan ? SL_RESTART_SCAN : 0) | (ReturnSingleEntry ? SL_RETURN_SINGLE_ENTRY : 0);

    /* The backing handle is synchronous: one request at a time on it */
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus->Status;
    }

    if (Bounce != NULL)
    {
        if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
        {
            RtlCopyMemory(Buffer, Bounce, min(Length, (ULONG)IoStatus->Information));
        }
        ExFreePoolWithTag(Bounce, LOOP_TAG);
    }

    return Status;
}

static
NTSTATUS
NTAPI
LoopQueryDirectory(
    _Inout_ PRX_CONTEXT RxContext)
{
    NTSTATUS Status;
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatus;
    PUNICODE_STRING Template = NULL;
    BOOLEAN Restart;

    if (LoopFault(16))
    {
        return STATUS_UNEXPECTED_NETWORK_ERROR;
    }
    LoopMaybeDelay();

    Handle = LoopHandleFromContext(RxContext);
    if (Handle == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }

    Restart = RxContext->QueryDirectory.RestartScan;
    if (RxContext->QueryDirectory.InitialQuery || Restart)
    {
        Template = &RxContext->pFobx->UnicodeQueryTemplate;
        if (Template->Buffer == NULL || Template->Length == 0)
        {
            Template = NULL;
        }
    }

    IoStatus.Information = 0;
    Status = LoopQueryDirectoryIrp(Handle, RxContext->Info.Buffer, RxContext->Info.Length,
                                   RxContext->Info.FileInformationClass,
                                   RxContext->QueryDirectory.ReturnSingleEntry,
                                   Template, Restart, &IoStatus);
    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
    {
        RxContext->Info.LengthRemaining -= (LONG)IoStatus.Information;
    }
    return Status;
}

static
NTSTATUS
NTAPI
LoopQueryVolumeInfo(
    _Inout_ PRX_CONTEXT RxContext)
{
    NTSTATUS Status;
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatus;

    /* A network volume: remote characteristics, device type of the net root */
    if (RxContext->Info.FsInformationClass == FileFsDeviceInformation)
    {
        PFILE_FS_DEVICE_INFORMATION Device = RxContext->Info.Buffer;

        if (RxContext->Info.LengthRemaining < (LONG)sizeof(*Device))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        Device->DeviceType = RxContext->pFcb->pNetRoot->DeviceType;
        Device->Characteristics = FILE_REMOTE_DEVICE;
        RxContext->Info.LengthRemaining -= sizeof(*Device);
        return STATUS_SUCCESS;
    }

    Handle = LoopHandleFromContext(RxContext);
    if (Handle == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }
    Status = ZwQueryVolumeInformationFile(Handle, &IoStatus, RxContext->Info.Buffer,
                                          RxContext->Info.LengthRemaining, RxContext->Info.FsInformationClass);
    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
    {
        RxContext->Info.LengthRemaining -= (LONG)IoStatus.Information;
    }
    return Status;
}

static
NTSTATUS
NTAPI
LoopSetVolumeInfo(
    _Inout_ PRX_CONTEXT RxContext)
{
    /* A share's volume label is not the client's to change */
    return STATUS_ACCESS_DENIED;
}

static
NTSTATUS
NTAPI
LoopQueryFileInfo(
    _Inout_ PRX_CONTEXT RxContext)
{
    NTSTATUS Status;
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatus;
    PFCB Fcb = (PFCB)RxContext->pFcb;

    if (LoopFault(16))
    {
        return STATUS_UNEXPECTED_NETWORK_ERROR;
    }
    if (BooleanFlagOn(LoopOptions, LOOPRDR_OPT_NO_INTERNAL_INFO) &&
        RxContext->Info.FileInformationClass == FileInternalInformation)
    {
        /* A server without file IDs: RDBSS answers on its own */
        return STATUS_INVALID_PARAMETER;
    }
    LoopMaybeDelay();

    Handle = LoopHandleFromContext(RxContext);
    if (Handle == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }
    if (RxContext->Info.LengthRemaining < 0)
    {
        return STATUS_BUFFER_OVERFLOW;
    }

    Status = ZwQueryInformationFile(Handle, &IoStatus, RxContext->Info.Buffer,
                                    RxContext->Info.LengthRemaining, RxContext->Info.FileInformationClass);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
    {
        return Status;
    }

    /* While the client caches, its sizes are the truth */
    if (RxContext->Info.FileInformationClass == FileStandardInformation &&
        NodeType(Fcb) == RDBSS_NTC_STORAGE_TYPE_FILE &&
        IoStatus.Information >= sizeof(FILE_STANDARD_INFORMATION))
    {
        PFILE_STANDARD_INFORMATION Standard = RxContext->Info.Buffer;

        Standard->EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;
        if (Standard->AllocationSize.QuadPart < Fcb->Header.FileSize.QuadPart)
        {
            Standard->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
        }
        Standard->DeletePending = BooleanFlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
    }

    RxContext->Info.LengthRemaining -= (LONG)IoStatus.Information;
    return Status;
}

static
NTSTATUS
LoopSetRename(
    _Inout_ PRX_CONTEXT RxContext,
    _In_ HANDLE Handle)
{
    NTSTATUS Status;
    PFILE_RENAME_INFORMATION In, Out;
    UNICODE_STRING Name, Relative, Path;
    ULONG Length;
    IO_STATUS_BLOCK IoStatus;
    PFCB Fcb = (PFCB)RxContext->pFcb;

    In = RxContext->Info.Buffer;
    if (RxContext->Info.Length < (LONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        In->FileNameLength > (ULONG)RxContext->Info.Length - FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        In->FileNameLength > MAXUSHORT - sizeof(WCHAR) || (In->FileNameLength & 1) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Name.Buffer = In->FileName;
    Name.Length = (USHORT)In->FileNameLength;
    Name.MaximumLength = Name.Length;

    if (Name.Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (Name.Buffer[0] == L'\\')
    {
        /* A full name from the target directory open */
        LoopRelativeName(Fcb->pNetRoot, &Name, &Relative);
        Status = LoopBuildBackingPath(&Relative, &Path);
    }
    else
    {
        /* A simple name: rename within the current directory */
        UNICODE_STRING Parent;
        USHORT i;

        LoopRelativeName(Fcb->pNetRoot, &Fcb->PrivateAlreadyPrefixedName, &Parent);
        for (i = Parent.Length / sizeof(WCHAR); i > 0 && Parent.Buffer[i - 1] != L'\\'; --i);
        Parent.Length = i * sizeof(WCHAR);
        Status = LoopBuildBackingPath(&Parent, &Path);
        if (NT_SUCCESS(Status))
        {
            UNICODE_STRING Full;

            Full.MaximumLength = Path.Length + Name.Length + sizeof(WCHAR);
            Full.Length = 0;
            Full.Buffer = ExAllocatePoolWithTag(PagedPool, Full.MaximumLength, LOOP_TAG);
            if (Full.Buffer == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else
            {
                RtlAppendUnicodeStringToString(&Full, &Path);
                RtlAppendUnicodeStringToString(&Full, &Name);
            }
            ExFreePoolWithTag(Path.Buffer, LOOP_TAG);
            Path = Full;
        }
    }
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Length = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) + Path.Length;
    Out = ExAllocatePoolWithTag(PagedPool, Length, LOOP_TAG);
    if (Out == NULL)
    {
        ExFreePoolWithTag(Path.Buffer, LOOP_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Out->ReplaceIfExists = RxContext->Info.ReplaceIfExists || In->ReplaceIfExists;
    Out->RootDirectory = NULL;
    Out->FileNameLength = Path.Length;
    RtlCopyMemory(Out->FileName, Path.Buffer, Path.Length);
    ExFreePoolWithTag(Path.Buffer, LOOP_TAG);

    /* The paging handle pins the old name open: drop it first */
    LoopClosePagingHandle(RxContext->pFcb);
    Status = ZwSetInformationFile(Handle, &IoStatus, Out, Length, RxContext->Info.FileInformationClass);
    ExFreePoolWithTag(Out, LOOP_TAG);
    return Status;
}

static
NTSTATUS
LoopSetInfoCommon(
    _Inout_ PRX_CONTEXT RxContext,
    _In_ BOOLEAN AtCleanup)
{
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatus;
    FILE_INFORMATION_CLASS Class;

    Handle = LoopHandleFromContext(RxContext);
    if (Handle == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }

    Class = RxContext->Info.FileInformationClass;
    switch (Class)
    {
        case FileRenameInformation:
        case FileLinkInformation:
            return LoopSetRename(RxContext, Handle);

        case FileEndOfFileInformation:
            if (!AtCleanup) CountUp(SetEndOfFile);
            break;

        case FileAllocationInformation:
            CountUp(SetAllocation);
            break;

        case FileBasicInformation:
        case FileDispositionInformation:
        case FileValidDataLengthInformation:
        case FileShortNameInformation:
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    return ZwSetInformationFile(Handle, &IoStatus, RxContext->Info.Buffer, RxContext->Info.Length, Class);
}

static
NTSTATUS
NTAPI
LoopSetFileInfo(
    _Inout_ PRX_CONTEXT RxContext)
{
    if (LoopFault(16))
    {
        return STATUS_UNEXPECTED_NETWORK_ERROR;
    }
    LoopMaybeDelay();
    return LoopSetInfoCommon(RxContext, FALSE);
}

static
NTSTATUS
NTAPI
LoopSetFileInfoAtCleanup(
    _Inout_ PRX_CONTEXT RxContext)
{
    NTSTATUS Status;

    Status = LoopSetInfoCommon(RxContext, TRUE);
    /* Read-only opens cannot set times or sizes on the "server": fine */
    if (Status == STATUS_ACCESS_DENIED)
    {
        Status = STATUS_SUCCESS;
    }
    return Status;
}

static
NTSTATUS
NTAPI
LoopQuerySdInfo(
    _Inout_ PRX_CONTEXT RxContext)
{
    NTSTATUS Status;
    HANDLE Handle;
    ULONG Needed = 0;

    CountUp(QuerySd);
    Handle = LoopHandleFromContext(RxContext);
    if (Handle == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }
    /* Contract: Info.Buffer/Info.LengthRemaining in, InformationToReturn out
     * (the length returned, or the length needed with STATUS_BUFFER_TOO_SMALL) */
    Status = ZwQuerySecurityObject(Handle, RxContext->QuerySecurity.SecurityInformation,
                                   RxContext->Info.Buffer, RxContext->Info.LengthRemaining, &Needed);
    RxContext->InformationToReturn = (NT_SUCCESS(Status) || Status == STATUS_BUFFER_TOO_SMALL) ? Needed : 0;
    return Status;
}

static
NTSTATUS
NTAPI
LoopSetSdInfo(
    _Inout_ PRX_CONTEXT RxContext)
{
    HANDLE Handle;

    CountUp(SetSd);
    Handle = LoopHandleFromContext(RxContext);
    if (Handle == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }
    return ZwSetSecurityObject(Handle, RxContext->SetSecurity.SecurityInformation,
                               RxContext->SetSecurity.SecurityDescriptor);
}

static
NTSTATUS
NTAPI
LoopQueryEaInfo(
    _Inout_ PRX_CONTEXT RxContext)
{
    NTSTATUS Status;
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatus;

    CountUp(QueryEa);
    Handle = LoopHandleFromContext(RxContext);
    if (Handle == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }
    IoStatus.Information = 0;
    Status = ZwQueryEaFile(Handle, &IoStatus, RxContext->Info.Buffer, RxContext->Info.Length,
                           RxContext->QueryEa.ReturnSingleEntry,
                           RxContext->QueryEa.UserEaList, RxContext->QueryEa.UserEaListLength,
                           RxContext->QueryEa.IndexSpecified ? &RxContext->QueryEa.UserEaIndex : NULL,
                           RxContext->QueryEa.RestartScan);
    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
    {
        RxContext->Info.LengthRemaining -= (LONG)IoStatus.Information;
    }
    return Status;
}

static
NTSTATUS
NTAPI
LoopSetEaInfo(
    _Inout_ PRX_CONTEXT RxContext)
{
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatus;

    CountUp(SetEa);
    Handle = LoopHandleFromContext(RxContext);
    if (Handle == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }
    return ZwSetEaFile(Handle, &IoStatus, RxContext->Info.Buffer, RxContext->Info.Length);
}

/* ---------------------------------------------------------------------- */
/* Buffering state                                                        */
/* ---------------------------------------------------------------------- */

static
NTSTATUS
NTAPI
LoopComputeNewBufferingState(
    _Inout_ PMRX_SRV_OPEN SrvOpen,
    _In_ PVOID MRxContext,
    _Out_ PULONG NewBufferingState)
{
    CountUp(ComputeBufferingState);
    /* The "break" carries the new state in its context */
    *NewBufferingState = PtrToUlong(MRxContext) & FCB_STATE_BUFFERING_STATE_MASK;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
LoopCompleteBufferingStateChangeRequest(
    _Inout_ PRX_CONTEXT RxContext,
    _Inout_ PMRX_SRV_OPEN SrvOpen,
    _In_ PVOID MRxContext)
{
    /* The "acknowledgement" a real server waits for */
    CountUp(CompleteBufferingState);
    KeSetEvent(&LoopBreakAckEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

static
VOID
NTAPI
LoopBreakWorker(
    _In_ PVOID Context)
{
    PLOOP_BREAK_ITEM Item = Context;

    /* Called from a system worker, as a receive path would: no FCB locks */
    if (Item->ForSrvOpen)
    {
        RxIndicateChangeOfBufferingStateForSrvOpen(Item->SrvCall, Item->SrvOpen, Item->Key,
                                                   ULongToPtr(Item->NewState));
    }
    else
    {
        RxIndicateChangeOfBufferingState(Item->SrvCall, Item->Key, ULongToPtr(Item->NewState));
    }
    KeSetEvent(&Item->Done, IO_NO_INCREMENT, FALSE);
}

static
VOID
NTAPI
LoopBreakThread(
    _In_ PVOID Context)
{
    LoopBreakWorker(Context);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
NTSTATUS
LoopBreak(
    _In_ PRX_CONTEXT RxContext,
    _In_ PLOOPRDR_BREAK Break)
{
    NTSTATUS Status;
    PFILE_OBJECT FileObject;
    PMRX_FOBX Fobx;
    PMRX_SRV_OPEN SrvOpen;
    PLOOP_BREAK_ITEM Item;
    LARGE_INTEGER Timeout;

    /* The handle comes from user mode: resolve it with the caller's mode and
     * accept only file objects of our own device */
    Status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)Break->FileHandle, 0, *IoFileObjectType,
                                       RxContext->CurrentIrp->RequestorMode, (PVOID *)&FileObject, NULL);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    if (IoGetRelatedDeviceObject(FileObject) != &LoopDeviceObject->DeviceObject ||
        FileObject->FsContext == NULL || FileObject->FsContext2 == NULL ||
        NodeType(FileObject->FsContext2) != RDBSS_NTC_FOBX)
    {
        ObDereferenceObject(FileObject);
        return STATUS_INVALID_PARAMETER;
    }

    Fobx = FileObject->FsContext2;
    SrvOpen = Fobx->pSrvOpen;

    Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Item), LOOP_TAG);
    if (Item == NULL)
    {
        ObDereferenceObject(FileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Item->SrvCall = SrvOpen->pFcb->pNetRoot->pSrvCall;
    Item->SrvOpen = SrvOpen;
    Item->Key = SrvOpen->Key;
    Item->NewState = Break->NewBufferingState;
    Item->ForSrvOpen = BooleanFlagOn(Break->Flags, LOOPRDR_BREAK_FOR_SRVOPEN);
    KeInitializeEvent(&Item->Done, NotificationEvent, FALSE);
    KeClearEvent(&LoopBreakAckEvent);

    /* Its own thread, as a receive path would be: in a system worker it
     * could hold the FCB (RxIndicateChangeOfBufferingStateForSrvOpen
     * flushes under it) while the paging writes of that flush wait for
     * LOOPRDR_OPT_LATE completions queued behind it on the same queue */
    {
        HANDLE ThreadHandle;
        PVOID Thread = NULL;

        Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, LoopBreakThread, Item);
        if (!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(Item, LOOP_TAG);
            ObDereferenceObject(FileObject);
            return Status;
        }
        if (!NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, SYNCHRONIZE, *PsThreadType, KernelMode, &Thread, NULL)))
        {
            Thread = NULL;
        }
        ZwClose(ThreadHandle);
        /* The file object keeps the SRV_OPEN alive until the thread ran;
         * waiting for the thread itself keeps the image loaded under it */
        KeWaitForSingleObject(&Item->Done, Executive, KernelMode, FALSE, NULL);
        if (Thread != NULL)
        {
            KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(Thread);
        }
    }
    ExFreePoolWithTag(Item, LOOP_TAG);

    Status = STATUS_SUCCESS;
    if (BooleanFlagOn(Break->Flags, LOOPRDR_BREAK_WAIT))
    {
        Timeout.QuadPart = -10LL * 1000 * 1000 * 10;
        Status = KeWaitForSingleObject(&LoopBreakAckEvent, Executive, KernelMode, FALSE, &Timeout);
        if (Status == STATUS_TIMEOUT)
        {
            Status = STATUS_IO_TIMEOUT;
        }
    }

    ObDereferenceObject(FileObject);
    return Status;
}

/* ---------------------------------------------------------------------- */
/* Hang diagnostic                                                        */
/* ---------------------------------------------------------------------- */

extern RX_DISPATCHER RxDispatcher;

/* Exported by the kernel, not declared by the DDK headers */
NTKERNELAPI VOID NTAPI KeInitializeApc(PKAPC Apc, PKTHREAD Thread, ULONG Environment, PVOID KernelRoutine,
                                       PVOID RundownRoutine, PVOID NormalRoutine, KPROCESSOR_MODE Mode, PVOID Context);
NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(PKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment);

/* Special kernel APC run by a thread that holds an FCB exclusive while
 * others wait: stops in the kernel debugger in that thread, so that the
 * debugger's backtrace is its stack */
static
VOID
NTAPI
LoopOwnerApc(
    _In_ PKAPC Apc,
    _Inout_ PVOID *NormalRoutine,
    _Inout_ PVOID *NormalContext,
    _Inout_ PVOID *SystemArgument1,
    _Inout_ PVOID *SystemArgument2)
{
    DbgPrint("LOOPRDR-OWNER: thread %p (%p.%p) holds the FCB; its stack follows\n", KeGetCurrentThread(),
             PsGetCurrentProcessId(), PsGetCurrentThreadId());
    ExFreePoolWithTag(Apc, LOOP_TAG);
    DbgBreakPoint();
}

static ULONG_PTR LoopImageStart, LoopImageEnd;

/* Where a resource owner waits, for the debugger log: its wait state and the
 * return addresses on its kernel stack (into ntoskrnl or this driver), when
 * the owner cannot take the APC that would stop it in the debugger (special
 * kernel APCs disabled or a wait at APC_LEVEL) */
static
VOID
LoopDumpThread(
    _In_ PCSTR What,
    _In_ ULONG_PTR Owner)
{
    PKTHREAD Thread = (PKTHREAD)Owner;
    static ULONG_PTR NtStart, NtEnd;
    ULONG_PTR *Sp, *Top;
    ULONG Shown = 0;

    if (Owner == 0 || (Owner & 3) != 0 ||
        !NT_SUCCESS(ObReferenceObjectByPointer(Thread, 0, *PsThreadType, KernelMode)))
    {
        return;
    }
    _SEH2_TRY
    {
        if (NtStart == 0)
        {
            ULONG_PTR Base = (ULONG_PTR)KeBugCheckEx & ~(ULONG_PTR)(PAGE_SIZE - 1);
            ULONG i;

            /* Back to the image header ('MZ'); PE: e_lfanew at 0x3C, then
             * "PE\0\0", the file header (20 bytes) and SizeOfImage at 56 in
             * the optional header (PE32 and PE32+) */
            for (i = 0; i < 0x2000 && *(PUSHORT)Base != 0x5A4D; ++i)
            {
                Base -= PAGE_SIZE;
            }
            if (*(PUSHORT)Base == 0x5A4D && *(PULONG)(Base + *(PULONG)(Base + 0x3C)) == 0x4550)
            {
                NtEnd = Base + *(PULONG)(Base + *(PULONG)(Base + 0x3C) + 4 + 20 + 56);
                NtStart = Base;
            }
        }
        DbgPrint("LOOPRDR-THREAD: %s %p (%p.%p) state %u wait reason %u irql %u mode %u object %p\n", What, Thread,
                 PsGetThreadProcessId((PETHREAD)Thread), PsGetThreadId((PETHREAD)Thread), Thread->State,
                 Thread->WaitReason, Thread->WaitIrql, Thread->WaitMode,
                 Thread->WaitBlockList != NULL ? Thread->WaitBlockList->Object : NULL);
        DbgPrint("LOOPRDR-THREAD: ntoskrnl %p-%p, driver %p-%p, stack %p-%p\n", (PVOID)NtStart, (PVOID)NtEnd,
                 (PVOID)LoopImageStart, (PVOID)LoopImageEnd, Thread->KernelStack, Thread->InitialStack);
        Sp = (ULONG_PTR *)Thread->KernelStack;
        Top = (ULONG_PTR *)Thread->InitialStack;
        if (Thread->State != Running && Sp != NULL && Sp < Top && Top - Sp < 0x4000)
        {
            for (; Sp < Top && Shown < 64; ++Sp)
            {
                if ((*Sp >= NtStart && *Sp < NtEnd) || (*Sp >= LoopImageStart && *Sp < LoopImageEnd))
                {
                    DbgPrint("LOOPRDR-STACK: %p %s+%lx\n", (PVOID)*Sp, *Sp < NtEnd && *Sp >= NtStart ? "ntoskrnl" : "driver",
                             (ULONG)(*Sp - (*Sp >= NtStart && *Sp < NtEnd ? NtStart : LoopImageStart)));
                    ++Shown;
                }
            }
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("LOOPRDR-THREAD: exception %lx reading %p\n", _SEH2_GetExceptionCode(), Thread);
    }
    _SEH2_END;
    ObDereferenceObject(Thread);
}

static
VOID
LoopDumpResource(
    _In_ PCSTR What,
    _In_ PERESOURCE Resource)
{
    ULONG i, Size;

    if (Resource == NULL)
    {
        return;
    }
    /* Unlocked reads: a snapshot for the debugger log only */
    DbgPrint("  %s: active %d flag %x owner %p waiters shared %lu exclusive %lu\n", What,
             Resource->ActiveCount, Resource->Flag, (PVOID)Resource->OwnerEntry.OwnerThread,
             Resource->NumberOfSharedWaiters, Resource->NumberOfExclusiveWaiters);
    if (Resource->OwnerTable != NULL)
    {
        Size = Resource->OwnerTable[0].TableSize;
        for (i = 1; i < Size && i < 16; ++i)
        {
            if (Resource->OwnerTable[i].OwnerThread != 0)
            {
                DbgPrint("    shared owner %p x%lu\n", (PVOID)Resource->OwnerTable[i].OwnerThread,
                         Resource->OwnerTable[i].OwnerCount);
            }
        }
    }
    if (Resource->ActiveCount != 0 &&
        (Resource->NumberOfSharedWaiters != 0 || Resource->NumberOfExclusiveWaiters != 0))
    {
        LoopDumpThread("owner", Resource->OwnerEntry.OwnerThread);
        if (Resource->OwnerTable != NULL)
        {
            Size = Resource->OwnerTable[0].TableSize;
            for (i = 1; i < Size && i < 16; ++i)
            {
                LoopDumpThread("shared owner", Resource->OwnerTable[i].OwnerThread);
            }
        }
    }
}

/* IOCTL_LOOPRDR_DUMP: the RDBSS state a hang analysis needs, to the debugger
 * log (owners whose low bits are 3 are RX_CONTEXTs a posted request handed
 * its lock to) */
static
VOID
LoopDumpState(
    _In_ BOOLEAN BreakInOwner)
{
    PLIST_ENTRY Entry;
    ULONG q;

    DbgPrint("LOOPRDR-DUMP: posted requests %ld/%ld/%ld overflow %ld/%ld/%ld, pending async %ld\n",
             RxFileSystemDeviceObject->PostedRequestCount[0], RxFileSystemDeviceObject->PostedRequestCount[1],
             RxFileSystemDeviceObject->PostedRequestCount[2], RxFileSystemDeviceObject->OverflowQueueCount[0],
             RxFileSystemDeviceObject->OverflowQueueCount[1], RxFileSystemDeviceObject->OverflowQueueCount[2],
             LoopCounters.PendingAsync);
    if (RxDispatcher.pWorkQueueDispatcher != NULL)
    {
        for (q = 0; q < RxMaximumWorkQueue; ++q)
        {
            PRX_WORK_QUEUE Wq = &RxDispatcher.pWorkQueueDispatcher->WorkQueue[q];

            DbgPrint("LOOPRDR-DUMP: rx queue %lu: to dispatch %ld active %ld idle %ld max %lu\n", q,
                     Wq->NumberOfWorkItemsToBeDispatched, Wq->NumberOfActiveWorkerThreads,
                     Wq->NumberOfIdleWorkerThreads, Wq->MaximumNumberOfWorkerThreads);
        }
    }
    ExAcquireFastMutex(&LoopFcbListMutex);
    for (Entry = LoopFcbList.Flink; Entry != &LoopFcbList; Entry = Entry->Flink)
    {
        PLOOP_FCB Ext = CONTAINING_RECORD(Entry, LOOP_FCB, AllFcbs);
        PFCB Fcb = (PFCB)Ext->MrxFcb;

        DbgPrint("LOOPRDR-DUMP: FCB %p %wZ state %lx open %lu unclean %lu refs %ld async writes %lu\n", Fcb,
                 &Fcb->FcbTableEntry.Path, Fcb->FcbState, Fcb->OpenCount, Fcb->UncleanCount, Fcb->NodeReferenceCount,
                 Fcb->NonPaged->OutstandingAsyncWrites);
        LoopDumpResource("main", Fcb->Header.Resource);
        LoopDumpResource("paging", Fcb->Header.PagingIoResource);

        /* An exclusive owner that is a thread (not an RX_CONTEXT | 3) and
         * has waiters: show its stack */
        if (BreakInOwner && Fcb->Header.Resource->ActiveCount != 0 &&
            BooleanFlagOn(Fcb->Header.Resource->Flag, ResourceOwnedExclusive) &&
            Fcb->Header.Resource->NumberOfExclusiveWaiters != 0 &&
            (Fcb->Header.Resource->OwnerEntry.OwnerThread & 3) == 0 &&
            Fcb->Header.Resource->OwnerEntry.OwnerThread != 0)
        {
            PKAPC Apc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), LOOP_TAG);

            if (Apc != NULL)
            {
                DbgPrint("LOOPRDR-DUMP: asking owner %p of FCB %p for its stack\n",
                         (PVOID)Fcb->Header.Resource->OwnerEntry.OwnerThread, Fcb);
                KeInitializeApc(Apc, (PKTHREAD)Fcb->Header.Resource->OwnerEntry.OwnerThread, 0, (PVOID)LoopOwnerApc,
                                NULL, NULL, KernelMode, NULL);
                if (!KeInsertQueueApc(Apc, NULL, NULL, 0))
                {
                    ExFreePoolWithTag(Apc, LOOP_TAG);
                }
                BreakInOwner = FALSE;
            }
        }
    }
    ExReleaseFastMutex(&LoopFcbListMutex);
    DbgPrint("LOOPRDR-DUMP: end\n");
}

/* ---------------------------------------------------------------------- */
/* Device FCB controls                                                    */
/* ---------------------------------------------------------------------- */

static
NTSTATUS
NTAPI
LoopDevFcbXXXControlFile(
    _Inout_ PRX_CONTEXT RxContext)
{
    NTSTATUS Status;
    PLOWIO_CONTEXT LowIo = &RxContext->LowIoContext;
    PIO_STACK_LOCATION Stack = RxContext->CurrentIrpSp;
    ULONG Code, InLength, OutLength;
    PVOID Buffer;

    if (RxContext->MajorFunction != IRP_MJ_DEVICE_CONTROL)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    Code = Stack->Parameters.DeviceIoControl.IoControlCode;
    InLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    OutLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    Buffer = RxContext->CurrentIrp->AssociatedIrp.SystemBuffer;
    UNREFERENCED_PARAMETER(LowIo);

    /* Test controls: administrators only (the share is served with kernel
     * handles, so its root must not be chosen by just anyone) */
    if (RxContext->CurrentIrp->RequestorMode != KernelMode)
    {
        SECURITY_SUBJECT_CONTEXT Subject;
        BOOLEAN IsAdmin;

        SeCaptureSubjectContext(&Subject);
        SeLockSubjectContext(&Subject);
        IsAdmin = SeTokenIsAdmin(SeQuerySubjectContextToken(&Subject));
        SeUnlockSubjectContext(&Subject);
        SeReleaseSubjectContext(&Subject);
        if (!IsAdmin)
        {
            return STATUS_ACCESS_DENIED;
        }
    }

    switch (Code)
    {
        /* Start and stop run in the FSP: when RDBSS asks for that, it
         * returns STATUS_PENDING with PostRequest set, and the
         * mini-redirector answers STATUS_MORE_PROCESSING_REQUIRED so that
         * RDBSS posts the request (and calls us again from the FSP) */
        case IOCTL_LOOPRDR_START:
            Status = RxStartMinirdr(RxContext, &RxContext->PostRequest);
            if (Status == STATUS_REDIRECTOR_STARTED)
            {
                Status = STATUS_SUCCESS;
            }
            else if (Status == STATUS_PENDING && RxContext->PostRequest)
            {
                Status = STATUS_MORE_PROCESSING_REQUIRED;
            }
            break;

        case IOCTL_LOOPRDR_STOP:
            Status = RxStopMinirdr(RxContext, &RxContext->PostRequest);
            if (Status == STATUS_PENDING && RxContext->PostRequest)
            {
                Status = STATUS_MORE_PROCESSING_REQUIRED;
            }
            break;

        case IOCTL_LOOPRDR_SET_ROOT:
            if (InLength < sizeof(WCHAR) || InLength >= sizeof(LoopRootBuffer) || (InLength & 1) != 0 ||
                Buffer == NULL)
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            ExAcquireFastMutex(&LoopRootMutex);
            RtlCopyMemory(LoopRootBuffer, Buffer, InLength);
            LoopRoot.Buffer = LoopRootBuffer;
            LoopRoot.Length = (USHORT)InLength;
            /* A NUL-terminated input counts without its terminator */
            while (LoopRoot.Length != 0 && LoopRoot.Buffer[LoopRoot.Length / sizeof(WCHAR) - 1] == UNICODE_NULL)
            {
                LoopRoot.Length -= sizeof(WCHAR);
            }
            LoopRoot.MaximumLength = sizeof(LoopRootBuffer);
            ExReleaseFastMutex(&LoopRootMutex);
            Status = STATUS_SUCCESS;
            break;

        case IOCTL_LOOPRDR_SET_OPTIONS:
            if (InLength < sizeof(LOOPRDR_OPTIONS) || Buffer == NULL)
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            LoopBufferingFlags = ((PLOOPRDR_OPTIONS)Buffer)->BufferingFlags & FCB_STATE_BUFFERING_STATE_MASK;
            LoopOptions = ((PLOOPRDR_OPTIONS)Buffer)->Flags;
            Status = STATUS_SUCCESS;
            break;

        case IOCTL_LOOPRDR_GET_COUNTERS:
            if (OutLength < sizeof(LOOPRDR_COUNTERS) || Buffer == NULL)
            {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            RtlCopyMemory(Buffer, &LoopCounters, sizeof(LOOPRDR_COUNTERS));
            RxContext->CurrentIrp->IoStatus.Information = sizeof(LOOPRDR_COUNTERS);
            RxContext->InformationToReturn = sizeof(LOOPRDR_COUNTERS);
            Status = STATUS_SUCCESS;
            break;

        case IOCTL_LOOPRDR_DUMP:
            /* Input (optional): a ULONG, 1 = stop in the debugger in the
             * thread that holds a contended FCB exclusive */
            LoopDumpState(InLength >= sizeof(ULONG) && Buffer != NULL && *(PULONG)Buffer == 1);
            Status = STATUS_SUCCESS;
            break;

        case IOCTL_LOOPRDR_BREAK:
            if (InLength < sizeof(LOOPRDR_BREAK) || Buffer == NULL)
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            Status = LoopBreak(RxContext, Buffer);
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    return Status;
}

/* ---------------------------------------------------------------------- */
/* Driver entry/unload                                                    */
/* ---------------------------------------------------------------------- */

static
NTSTATUS
NTAPI
LoopDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    if (DeviceObject != &LoopDeviceObject->DeviceObject)
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    return RxFsdDispatch(LoopDeviceObject, Irp);
}

static
VOID
LoopInitDispatch(VOID)
{
    PMINIRDR_DISPATCH D = &LoopDispatchTable;

    RtlZeroMemory(D, sizeof(*D));
    D->NodeTypeCode = RDBSS_NTC_MINIRDR_DISPATCH;
    D->NodeByteSize = sizeof(*D);
    D->MRxFlags = RDBSS_MANAGE_NET_ROOT_EXTENSION | RDBSS_MANAGE_FCB_EXTENSION |
                  RDBSS_MANAGE_SRV_OPEN_EXTENSION | RDBSS_MANAGE_FOBX_EXTENSION;
    D->MRxNetRootSize = sizeof(LOOP_NET_ROOT);
    D->MRxFcbSize = sizeof(LOOP_FCB);
    D->MRxSrvOpenSize = sizeof(LOOP_SRV_OPEN);
    D->MRxFobxSize = sizeof(LOOP_FOBX);

    D->MRxStart = LoopStart;
    D->MRxStop = LoopStop;
    D->MRxDevFcbXXXControlFile = LoopDevFcbXXXControlFile;

    D->MRxCreateSrvCall = LoopCreateSrvCall;
    D->MRxSrvCallWinnerNotify = LoopSrvCallWinnerNotify;
    D->MRxFinalizeSrvCall = LoopFinalizeSrvCall;
    D->MRxCreateVNetRoot = LoopCreateVNetRoot;
    D->MRxFinalizeVNetRoot = LoopFinalizeVNetRoot;
    D->MRxFinalizeNetRoot = LoopFinalizeNetRoot;
    D->MRxExtractNetRootName = LoopExtractNetRootName;

    D->MRxCreate = LoopCreate;
    D->MRxCollapseOpen = LoopCollapseOpen;
    D->MRxShouldTryToCollapseThisOpen = LoopShouldTryToCollapseThisOpen;
    D->MRxCleanupFobx = LoopCleanupFobx;
    D->MRxCloseSrvOpen = LoopCloseSrvOpen;
    D->MRxGetConnectionId = LoopGetConnectionId;
    D->MRxDeallocateForFcb = LoopDeallocateForFcb;
    D->MRxDeallocateForFobx = LoopDeallocateForFobx;
    D->MRxForceClosed = LoopForceClosed;
    D->MRxAreFilesAliased = LoopAreFilesAliased;
    D->MRxIsValidDirectory = LoopIsValidDirectory;
    D->MRxIsLockRealizable = LoopIsLockRealizable;

    D->MRxFlush = LoopFlush;
    D->MRxZeroExtend = LoopZeroExtend;
    D->MRxTruncate = LoopTruncate;
    D->MRxExtendForCache = LoopExtendForCache;
    D->MRxExtendForNonCache = LoopExtendForNonCache;

    D->MRxQueryDirectory = LoopQueryDirectory;
    D->MRxQueryVolumeInfo = LoopQueryVolumeInfo;
    D->MRxSetVolumeInfo = LoopSetVolumeInfo;
    D->MRxQueryFileInfo = LoopQueryFileInfo;
    D->MRxSetFileInfo = LoopSetFileInfo;
    D->MRxSetFileInfoAtCleanup = LoopSetFileInfoAtCleanup;
    D->MRxQuerySdInfo = LoopQuerySdInfo;
    D->MRxSetSdInfo = LoopSetSdInfo;
    D->MRxQueryEaInfo = LoopQueryEaInfo;
    D->MRxSetEaInfo = LoopSetEaInfo;

    D->MRxComputeNewBufferingState = LoopComputeNewBufferingState;
    D->MRxCompleteBufferingStateChangeRequest = LoopCompleteBufferingStateChangeRequest;

    D->MRxLowIOSubmit[LOWIO_OP_READ] = LoopReadWrite;
    D->MRxLowIOSubmit[LOWIO_OP_WRITE] = LoopReadWrite;
    D->MRxLowIOSubmit[LOWIO_OP_SHAREDLOCK] = LoopLowIoLock;
    D->MRxLowIOSubmit[LOWIO_OP_EXCLUSIVELOCK] = LoopLowIoLock;
    D->MRxLowIOSubmit[LOWIO_OP_UNLOCK] = LoopLowIoUnlock;
    D->MRxLowIOSubmit[LOWIO_OP_UNLOCK_MULTIPLE] = LoopLowIoUnlock;
    D->MRxLowIOSubmit[LOWIO_OP_FSCTL] = LoopLowIoFsCtl;
    D->MRxLowIOSubmit[LOWIO_OP_IOCTL] = LoopLowIoIoCtl;
    D->MRxLowIOSubmit[LOWIO_OP_NOTIFY_CHANGE_DIRECTORY] = LoopLowIoNotify;

    /* Seconds before the scavenger finalizes unused structures */
    D->ScavengerTimeout = 2;
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    UNICODE_STRING DeviceName, DosName;
    ULONG i;

    LoopImageStart = (ULONG_PTR)DriverObject->DriverStart;
    LoopImageEnd = LoopImageStart + DriverObject->DriverSize;
    ExInitializeFastMutex(&LoopRootMutex);
    ExInitializeFastMutex(&LoopLockMutex);
    ExInitializeFastMutex(&LoopFcbListMutex);
    InitializeListHead(&LoopFcbList);
    ExInitializeFastMutex(&LoopPagingMutex);
    KeInitializeEvent(&LoopBreakAckEvent, NotificationEvent, FALSE);
    RtlZeroMemory(&LoopCounters, sizeof(LoopCounters));
    LoopRoot.Length = 0;
    LoopRoot.Buffer = LoopRootBuffer;
    LoopRoot.MaximumLength = sizeof(LoopRootBuffer);
    LoopBufferingFlags = FCB_STATE_READCACHING_ENABLED | FCB_STATE_READBUFFERING_ENABLED |
                         FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED;
    LoopOptions = 0;

    Status = RxDriverEntry(DriverObject, RegistryPath);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RxDriverEntry failed: %lx\n", Status);
        return Status;
    }

    LoopInitDispatch();

    RtlInitUnicodeString(&DeviceName, LOOPRDR_DEVICE_NAME);
    Status = RxRegisterMinirdr(&LoopDeviceObject, DriverObject, &LoopDispatchTable,
                               RX_REGISTERMINI_FLAG_DONT_PROVIDE_MAILSLOTS,
                               &DeviceName, 0, FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_REMOTE_DEVICE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RxRegisterMinirdr failed: %lx\n", Status);
        RxUnload(DriverObject);
        return Status;
    }

    RtlInitUnicodeString(&DosName, LOOPRDR_DOS_NAME);
    Status = IoCreateSymbolicLink(&DosName, &DeviceName);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IoCreateSymbolicLink failed: %lx\n", Status);
        RxUnregisterMinirdr(LoopDeviceObject);
        RxUnload(DriverObject);
        return Status;
    }

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        DriverObject->MajorFunction[i] = LoopDispatch;
    }
    DriverObject->DriverUnload = LoopUnload;

    return STATUS_SUCCESS;
}

static
VOID
NTAPI
LoopUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING DosName;
    PRX_CONTEXT RxContext;

    RtlInitUnicodeString(&DosName, LOOPRDR_DOS_NAME);
    IoDeleteSymbolicLink(&DosName);

    /* Stop if the test did not: RxStopMinirdr wants the FSP */
    RxContext = RxCreateRxContext(NULL, LoopDeviceObject, RX_CONTEXT_FLAG_IN_FSP | RX_CONTEXT_FLAG_WAIT);
    if (RxContext != NULL)
    {
        RxStopMinirdr(RxContext, &RxContext->PostRequest);
        RxDereferenceAndDeleteRxContext(RxContext);
    }

    DPRINT1("RdbssLoop unload: srvcalls %ld netroots %ld vnetroots %ld fcbs %ld srvopens %ld fobxs %ld handles %ld\n",
            LoopCounters.SrvCalls, LoopCounters.NetRoots, LoopCounters.VNetRoots, LoopCounters.Fcbs,
            LoopCounters.SrvOpens, LoopCounters.Fobxs, LoopCounters.BackingHandles);

    RxUnregisterMinirdr(LoopDeviceObject);
    LoopDeviceObject = NULL;
    RxUnload(DriverObject);
}
