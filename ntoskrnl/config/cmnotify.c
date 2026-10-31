/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/config/cmnotify.c
 * PURPOSE:         Configuration Manager - Registry change notification
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include "ntoskrnl.h"
#define NDEBUG
#include "debug.h"

/* GLOBALS *******************************************************************/

/*
 * Pending NtNotifyChangeKey requests.
 *
 * This is a deliberately small implementation: one global list of one-shot
 * requests instead of the per-key notify blocks and post lists of the NT
 * design. A request completes on the first matching change and is removed.
 * The list is only touched under CmpNotifyLock; completion work (event,
 * IOSB, APC) is done after the lock is dropped.
 */
#define TAG_CM_NOTIFY   'nNmC'

#ifndef REG_NOTIFY_THREAD_AGNOSTIC
#define REG_NOTIFY_THREAD_AGNOSTIC  0x10000000
#endif

typedef struct _CM_NOTIFY_REQUEST
{
    KAPC Apc;
    LIST_ENTRY Link;
    PCM_KEY_BODY KeyBody;
    PCM_KEY_CONTROL_BLOCK Kcb;
    PKEVENT Event;              /* Referenced, optional */
    PKEVENT WaitEvent;          /* Synchronous caller, on its kernel stack */
    PNTSTATUS WaitStatus;       /* Synchronous caller, on its kernel stack */
    PETHREAD Thread;            /* Referenced; NULL if thread agnostic */
    PIO_APC_ROUTINE ApcRoutine;
    PVOID ApcContext;
    PIO_STATUS_BLOCK UserIosb;  /* Only valid in the context of Thread */
    NTSTATUS Status;
    ULONG Filter;
    BOOLEAN WatchTree;
    BOOLEAN Wow64Iosb;          /* UserIosb is an 8-byte guest IO_STATUS_BLOCK32 */
} CM_NOTIFY_REQUEST, *PCM_NOTIFY_REQUEST;

static LIST_ENTRY CmpNotifyList = {&CmpNotifyList, &CmpNotifyList};
static KSPIN_LOCK CmpNotifyLock;

/* PRIVATE FUNCTIONS *********************************************************/

static
VOID
CmpNotifyDiscard(
    _In_ PCM_NOTIFY_REQUEST Request)
{
    /* May run under the registry and KCB locks: never let the last
     * reference delete an object here */
    if (Request->Event)
        ObDereferenceObjectDeferDelete(Request->Event);
    if (Request->Thread)
        ObDereferenceObjectDeferDelete(Request->Thread);
    ExFreePoolWithTag(Request, TAG_CM_NOTIFY);
}

static
VOID
CmpNotifyCancelWithThread(
    _In_ PCM_NOTIFY_REQUEST Request)
{
    /* The requesting thread is gone and cannot run the completion. The event
     * is still signaled, as for a thread that exits while waiting, so that
     * nobody keeps waiting for a notification that cannot arrive. */
    if (Request->Event)
        KeSetEvent(Request->Event, IO_NO_INCREMENT, FALSE);
    CmpNotifyDiscard(Request);
}

static
VOID
NTAPI
CmpNotifyRundownRoutine(
    _In_ PKAPC Apc)
{
    /* The thread died before it could run the completion */
    CmpNotifyCancelWithThread(CONTAINING_RECORD(Apc, CM_NOTIFY_REQUEST, Apc));
}

static
VOID
NTAPI
CmpNotifyUserKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ PVOID *NormalContext,
    _Inout_ PVOID *SystemArgument1,
    _Inout_ PVOID *SystemArgument2)
{
    /* Everything the user routine needs is in the arguments by now */
    CmpNotifyDiscard(CONTAINING_RECORD(Apc, CM_NOTIFY_REQUEST, Apc));
}

static
VOID
NTAPI
CmpNotifyKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ PVOID *NormalContext,
    _Inout_ PVOID *SystemArgument1,
    _Inout_ PVOID *SystemArgument2)
{
    PCM_NOTIFY_REQUEST Request = CONTAINING_RECORD(Apc, CM_NOTIFY_REQUEST, Apc);
    PKEVENT WaitEvent = Request->WaitEvent;
    PIO_STATUS_BLOCK UserIosb = Request->UserIosb;
    PIO_APC_ROUTINE ApcRoutine = Request->ApcRoutine;
    PVOID ApcContext = Request->ApcContext;

    /* We run as a special kernel APC in the context of the requesting thread */
    if (UserIosb)
    {
        _SEH2_TRY
        {
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
            if (Request->Wow64Iosb)
            {
                PIO_STATUS_BLOCK32 Iosb32 = (PIO_STATUS_BLOCK32)UserIosb;
                ProbeForWrite(Iosb32, sizeof(*Iosb32), sizeof(ULONG));
                Iosb32->Information = 0;
                KeMemoryBarrier();
                Iosb32->Status = Request->Status;
            }
            else
#endif
            {
                ProbeForWrite(UserIosb, sizeof(*UserIosb), sizeof(ULONG));
                UserIosb->Status = Request->Status;
                UserIosb->Information = 0;
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* The caller's buffer went away, nothing to report to */
        }
        _SEH2_END;
    }

    if (Request->WaitStatus)
        *Request->WaitStatus = Request->Status;

    if (Request->Event)
        KeSetEvent(Request->Event, IO_NO_INCREMENT, FALSE);

    if (ApcRoutine)
    {
        /* Hand the caller's routine over as a user APC; the request is freed
         * by its kernel routine, once the arguments are copied. */
        KeInitializeApc(Apc,
                        &Request->Thread->Tcb,
                        OriginalApcEnvironment,
                        CmpNotifyUserKernelRoutine,
                        CmpNotifyRundownRoutine,
                        (PKNORMAL_ROUTINE)ApcRoutine,
                        UserMode,
                        ApcContext);
        Request->WaitEvent = NULL;
        Request->WaitStatus = NULL;
        if (!KeInsertQueueApc(Apc, UserIosb, NULL, IO_NO_INCREMENT))
            CmpNotifyDiscard(Request);
    }
    else
    {
        CmpNotifyDiscard(Request);
    }

    /* Last: a synchronous caller may return and free what we pointed to */
    if (WaitEvent)
        KeSetEvent(WaitEvent, IO_NO_INCREMENT, FALSE);
}

static
VOID
CmpNotifyComplete(
    _In_ PCM_NOTIFY_REQUEST Request,
    _In_ NTSTATUS Status)
{
    Request->Status = Status;

    if (!Request->Thread)
    {
        /* Thread agnostic: only the event, there is no safe place for an IOSB */
        if (Request->Event)
            KeSetEvent(Request->Event, IO_NO_INCREMENT, FALSE);
        CmpNotifyDiscard(Request);
        return;
    }

    KeInitializeApc(&Request->Apc,
                    &Request->Thread->Tcb,
                    OriginalApcEnvironment,
                    CmpNotifyKernelRoutine,
                    CmpNotifyRundownRoutine,
                    NULL,
                    KernelMode,
                    NULL);
    if (!KeInsertQueueApc(&Request->Apc, NULL, NULL, IO_NO_INCREMENT))
    {
        /* The thread is gone: a request bound to it is cancelled with it */
        CmpNotifyCancelWithThread(Request);
    }
}

static
VOID
CmpNotifyCompleteList(
    _In_ PLIST_ENTRY List,
    _In_ NTSTATUS Status)
{
    PCM_NOTIFY_REQUEST Request;

    while (!IsListEmpty(List))
    {
        Request = CONTAINING_RECORD(RemoveHeadList(List), CM_NOTIFY_REQUEST, Link);
        CmpNotifyComplete(Request, Status);
    }
}

/* FUNCTIONS *****************************************************************/

NTSTATUS
NTAPI
CmpNotifyChangeKey(
    _In_ HANDLE KeyHandle,
    _In_opt_ HANDLE EventHandle,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG CompletionFilter,
    _In_ BOOLEAN WatchTree,
    _In_ BOOLEAN Asynchronous)
{
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    BOOLEAN Agnostic = !!(CompletionFilter & REG_NOTIFY_THREAD_AGNOSTIC);
    BOOLEAN Wow64Iosb = FALSE;
    PCM_NOTIFY_REQUEST Request;
    PCM_KEY_BODY KeyBody;
    PKEVENT Event = NULL;
    KEVENT WaitEvent;
    NTSTATUS Status, WaitStatus = STATUS_SUCCESS;
    KIRQL OldIrql;

    PAGED_CODE();

    /* Only the four change classes (plus thread agnostic) are legal */
    CompletionFilter &= ~REG_NOTIFY_THREAD_AGNOSTIC;
    if (!CompletionFilter || (CompletionFilter & ~REG_LEGAL_CHANGE_FILTER))
        return STATUS_INVALID_PARAMETER;

    /* A thread agnostic request has no thread to wait in or deliver an APC to */
    if (Agnostic && (!Asynchronous || !EventHandle || ApcRoutine))
        return STATUS_INVALID_PARAMETER;

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    /* Bit 63 marks an explicit eight-byte IOSB supplied by wow64.dll, the same
     * convention as NtReadFile and NtDeviceIoControlFile. */
    if (PreviousMode == UserMode && PsGetCurrentProcess()->Wow64Process &&
        ((ULONG64)IoStatusBlock >> 32) == 0x80000000)
    {
        Wow64Iosb = TRUE;
        IoStatusBlock = (PVOID)(ULONG_PTR)(ULONG)(ULONG_PTR)IoStatusBlock;
    }
#endif

    /* The status block is optional: completion is also reported through the
     * event, and a caller that cannot keep a block alive (RegNotifyChangeKeyValue
     * returns before the request completes) passes none. */
    if (PreviousMode != KernelMode && IoStatusBlock)
    {
        _SEH2_TRY
        {
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
            if (Wow64Iosb)
                ProbeForWrite(IoStatusBlock, sizeof(IO_STATUS_BLOCK32), sizeof(ULONG));
            else
#endif
                ProbeForWrite(IoStatusBlock, sizeof(*IoStatusBlock), sizeof(ULONG));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    Status = ObReferenceObjectByHandle(KeyHandle,
                                       KEY_NOTIFY,
                                       CmpKeyObjectType,
                                       PreviousMode,
                                       (PVOID*)&KeyBody,
                                       NULL);
    if (!NT_SUCCESS(Status))
        return Status;

    if (EventHandle)
    {
        Status = ObReferenceObjectByHandle(EventHandle,
                                           EVENT_MODIFY_STATE,
                                           ExEventObjectType,
                                           PreviousMode,
                                           (PVOID*)&Event,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            ObDereferenceObject(KeyBody);
            return Status;
        }
    }

    Request = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Request), TAG_CM_NOTIFY);
    if (!Request)
    {
        if (Event)
            ObDereferenceObject(Event);
        ObDereferenceObject(KeyBody);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Request, sizeof(*Request));
    Request->KeyBody = KeyBody;
    Request->Kcb = KeyBody->KeyControlBlock;
    Request->Event = Event;
    Request->ApcRoutine = ApcRoutine;
    Request->ApcContext = ApcContext;
    Request->Filter = CompletionFilter;
    Request->WatchTree = WatchTree;
    if (!Agnostic)
    {
        Request->Thread = PsGetCurrentThread();
        ObReferenceObject(Request->Thread);
        Request->UserIosb = IoStatusBlock;
        Request->Wow64Iosb = Wow64Iosb;
    }
    if (!Asynchronous)
    {
        KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);
        Request->WaitEvent = &WaitEvent;
        Request->WaitStatus = &WaitStatus;
    }

    /* Tell an asynchronous caller that the request is pending, before the
     * request can complete and write the final status */
    if (Asynchronous && Request->UserIosb)
    {
        _SEH2_TRY
        {
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
            if (Wow64Iosb)
                ((PIO_STATUS_BLOCK32)Request->UserIosb)->Status = STATUS_PENDING;
            else
#endif
                Request->UserIosb->Status = STATUS_PENDING;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Not worth failing the request over */
        }
        _SEH2_END;
    }

    /* Do not arm a watch on a key that is already gone. Deleting a key holds
     * its KCB lock exclusively, so checking and arming under it shared cannot
     * miss the deletion. */
    CmpLockRegistry();
    CmpAcquireKcbLockShared(Request->Kcb);
    if (Request->Kcb->Delete)
    {
        CmpReleaseKcbLock(Request->Kcb);
        CmpUnlockRegistry();
        CmpNotifyDiscard(Request);
        ObDereferenceObject(KeyBody);
        return STATUS_KEY_DELETED;
    }

    /* Arming a request resets its event, as for NtReadFile and friends. Callers
     * with a manual-reset event (Chrome re-arms its registry watchers on the one
     * event it waits on) rely on it: a left-over signal would complete the wait at
     * once, and the caller would re-arm in a tight loop, piling up requests. */
    if (Request->Event)
        KeClearEvent(Request->Event);

    KeAcquireSpinLock(&CmpNotifyLock, &OldIrql);
    InsertTailList(&CmpNotifyList, &Request->Link);
    KeReleaseSpinLock(&CmpNotifyLock, OldIrql);
    CmpReleaseKcbLock(Request->Kcb);
    CmpUnlockRegistry();

    /* Request may complete (and be freed) from here on. The key body is still
     * kept alive by our reference until we drop it, then CmpDeleteKeyObject or
     * CmpCloseKeyObject cancels what is left of it. */
    ObDereferenceObject(KeyBody);

    if (Asynchronous)
        return STATUS_PENDING;

    KeWaitForSingleObject(&WaitEvent, UserRequest, KernelMode, FALSE, NULL);
    return WaitStatus;
}

VOID
NTAPI
CmpReportNotify(IN PCM_KEY_CONTROL_BLOCK Kcb,
                IN PHHIVE Hive,
                IN HCELL_INDEX Cell,
                IN ULONG Filter)
{
    LIST_ENTRY Matched;
    PLIST_ENTRY Entry, Next;
    PCM_NOTIFY_REQUEST Request;
    PCM_KEY_CONTROL_BLOCK Parent;
    BOOLEAN Match;
    KIRQL OldIrql;

    /* Nearly every registry write ends up here, and nearly nobody is watching */
    if (IsListEmpty(&CmpNotifyList))
        return;

    InitializeListHead(&Matched);

    KeAcquireSpinLock(&CmpNotifyLock, &OldIrql);
    for (Entry = CmpNotifyList.Flink; Entry != &CmpNotifyList; Entry = Next)
    {
        Next = Entry->Flink;
        Request = CONTAINING_RECORD(Entry, CM_NOTIFY_REQUEST, Link);

        if (!(Request->Filter & Filter))
            continue;

        /* The key itself */
        Match = (Request->Kcb == Kcb);

        /* Creating or deleting a subkey changes the name list of its parent */
        if (!Match && (Filter & REG_NOTIFY_CHANGE_NAME) && Kcb->ParentKcb == Request->Kcb)
            Match = TRUE;

        /* Anything below the key, if the whole subtree is watched */
        if (!Match && Request->WatchTree)
        {
            for (Parent = Kcb->ParentKcb; Parent; Parent = Parent->ParentKcb)
            {
                if (Parent == Request->Kcb)
                {
                    Match = TRUE;
                    break;
                }
            }
        }

        if (Match)
        {
            RemoveEntryList(&Request->Link);
            InsertTailList(&Matched, &Request->Link);
        }
    }
    KeReleaseSpinLock(&CmpNotifyLock, OldIrql);

    CmpNotifyCompleteList(&Matched, STATUS_SUCCESS);
}

VOID
NTAPI
CmpReportNotifyRename(IN PCM_KEY_CONTROL_BLOCK Kcb)
{
    LIST_ENTRY Matched;
    PLIST_ENTRY Entry, Next;
    PCM_NOTIFY_REQUEST Request;
    PCM_KEY_CONTROL_BLOCK Parent;
    BOOLEAN Match;
    KIRQL OldIrql;

    /*
     * A renamed key, as measured on Windows: whatever waits on the key itself
     * completes, whatever its filter or subtree; the parent, and a watched
     * tree above it, see a name change.
     */
    if (IsListEmpty(&CmpNotifyList))
        return;

    InitializeListHead(&Matched);

    KeAcquireSpinLock(&CmpNotifyLock, &OldIrql);
    for (Entry = CmpNotifyList.Flink; Entry != &CmpNotifyList; Entry = Next)
    {
        Next = Entry->Flink;
        Request = CONTAINING_RECORD(Entry, CM_NOTIFY_REQUEST, Link);

        Match = (Request->Kcb == Kcb);
        if (!Match && (Request->Filter & REG_NOTIFY_CHANGE_NAME))
        {
            if (Kcb->ParentKcb == Request->Kcb)
            {
                Match = TRUE;
            }
            else if (Request->WatchTree)
            {
                for (Parent = Kcb->ParentKcb; Parent; Parent = Parent->ParentKcb)
                {
                    if (Parent == Request->Kcb)
                    {
                        Match = TRUE;
                        break;
                    }
                }
            }
        }

        if (Match)
        {
            RemoveEntryList(&Request->Link);
            InsertTailList(&Matched, &Request->Link);
        }
    }
    KeReleaseSpinLock(&CmpNotifyLock, OldIrql);

    CmpNotifyCompleteList(&Matched, STATUS_SUCCESS);
}

VOID
NTAPI
CmpFlushNotify(IN PCM_KEY_BODY KeyBody,
               IN BOOLEAN LockHeld)
{
    LIST_ENTRY Matched;
    PLIST_ENTRY Entry, Next;
    PCM_NOTIFY_REQUEST Request;
    KIRQL OldIrql;

    /* The key handle is going away: cancel what is pending on it */
    if (IsListEmpty(&CmpNotifyList))
        return;

    InitializeListHead(&Matched);

    KeAcquireSpinLock(&CmpNotifyLock, &OldIrql);
    for (Entry = CmpNotifyList.Flink; Entry != &CmpNotifyList; Entry = Next)
    {
        Next = Entry->Flink;
        Request = CONTAINING_RECORD(Entry, CM_NOTIFY_REQUEST, Link);
        if (Request->KeyBody == KeyBody)
        {
            RemoveEntryList(&Request->Link);
            InsertTailList(&Matched, &Request->Link);
        }
    }
    KeReleaseSpinLock(&CmpNotifyLock, OldIrql);

    CmpNotifyCompleteList(&Matched, STATUS_NOTIFY_CLEANUP);
}
