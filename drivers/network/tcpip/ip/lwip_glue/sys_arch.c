#include <debug.h>
#include <lwip/sys.h>
#include <lwip/timeouts.h>
#include <lwip/tcpip.h>
#include <lwip/priv/tcpip_priv.h>

#include "lwip_glue.h"

static LIST_ENTRY ThreadListHead;
static KSPIN_LOCK ThreadListLock;
static ERESOURCE GlobalLock;
static ULONG GlobalLockLevel = 0;

KEVENT TerminationEvent;
NPAGED_LOOKASIDE_LIST MessageLookasideList;
NPAGED_LOOKASIDE_LIST QueueEntryLookasideList;

static LARGE_INTEGER StartTime;

/* The lwIP core lock (LOCK_TCPIP_CORE). It is held for microseconds by several threads, so it
 * is not handed over to a waiter (that thread would first have to be scheduled, while the lock
 * stays unusable): a releasing thread frees it and wakes one waiter, which competes for it again.
 * A thread spins briefly before it waits */
static volatile LONG CoreLockHeld;
static volatile LONG CoreLockWaiters;
static KEVENT CoreLockReleased;
static PKTHREAD CoreLockOwner;

#define CORE_LOCK_SPIN 256

/* The tcpip thread, and when it next wakes up for a timeout (both under the core lock) */
static PKTHREAD TcpipThread;
static u32_t TcpipWakeTime;
static BOOLEAN TcpipWakeForever;

/* Wakes the tcpip thread early when another thread adds an earlier timeout */
static KEVENT TimeoutChanged;

/* What a wait without a timeout returns when woken that way: lwIP expects a message there */
static struct tcpip_msg TimeoutChangedMsg;

static void
TimeoutChangedCallback(void *ctx)
{
    /* Nothing to do: the tcpip thread looks at the timeouts again before it waits */
}

typedef struct _thread_t
{
    HANDLE Handle;
    void (* ThreadFunction)(void *arg);
    void *ThreadContext;
    LIST_ENTRY ListEntry;
    KEVENT Registered;
    PVOID Thread;
} *thread_t;

u32_t sys_now(void)
{
    LARGE_INTEGER CurrentTime;

    KeQuerySystemTime(&CurrentTime);

    return (CurrentTime.QuadPart - StartTime.QuadPart) / 10000;
}

void
sys_lock_tcpip_core(void)
{
    PKTHREAD Thread = KeGetCurrentThread();

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    ASSERT(CoreLockOwner != Thread);

    /* Suspension and termination are kernel APCs; a thread holding the lock must not stop for them */
    KeEnterCriticalRegion();

    for (;;)
    {
        ULONG Spin;

        for (Spin = (KeNumberProcessors > 1) ? CORE_LOCK_SPIN : 1; Spin > 0; Spin--)
        {
            if (!CoreLockHeld && !InterlockedCompareExchange(&CoreLockHeld, 1, 0))
                goto Acquired;
            YieldProcessor();
        }

        /* Counted before the last attempt, so a release either sees the waiter or is seen by it */
        InterlockedIncrement(&CoreLockWaiters);
        if (!InterlockedCompareExchange(&CoreLockHeld, 1, 0))
        {
            InterlockedDecrement(&CoreLockWaiters);
            goto Acquired;
        }
        KeWaitForSingleObject(&CoreLockReleased, Executive, KernelMode, FALSE, NULL);
        InterlockedDecrement(&CoreLockWaiters);
    }

Acquired:
    CoreLockOwner = Thread;
}

void
sys_unlock_tcpip_core(void)
{
    PKTHREAD Thread = KeGetCurrentThread();
    u32_t SleepTime;
    BOOLEAN Wake = FALSE;
    LIST_ENTRY Completions;
    BOOLEAN HaveCompletions;

    ASSERT(CoreLockOwner == Thread);

    /* The tcpip thread releases the lock only to wait for a message or its next timeout;
     * lwIP computes that wait from the timeout list before the release and does not look
     * at the list again until it wakes, so a timeout another thread adds meanwhile (the TCP
     * timer when a connection becomes active) must wake it if it is earlier */
    SleepTime = sys_timeouts_sleeptime();
    if (Thread == TcpipThread)
    {
        TcpipWakeForever = (SleepTime == SYS_TIMEOUTS_SLEEPTIME_INFINITE);
        TcpipWakeTime = sys_now() + SleepTime;
    }
    else if (SleepTime != SYS_TIMEOUTS_SLEEPTIME_INFINITE &&
             (TcpipWakeForever || (s32_t)(sys_now() + SleepTime - TcpipWakeTime) < 0))
    {
        Wake = TRUE;
    }

    /* TDI completions made under the lock wait until it is released */
    HaveCompletions = TCPTakeDeferredCompletions(&Completions);

    CoreLockOwner = NULL;
    InterlockedExchange(&CoreLockHeld, 0);
    if (CoreLockWaiters)
        KeSetEvent(&CoreLockReleased, IO_NO_INCREMENT, FALSE);

    /* After the release, so the woken thread does not wait for the lock */
    if (Wake)
        KeSetEvent(&TimeoutChanged, IO_NO_INCREMENT, FALSE);

    KeLeaveCriticalRegion();

    if (HaveCompletions)
        TCPRunDeferredCompletions(&Completions, Thread == TcpipThread);
}

BOOLEAN
sys_tcpip_core_locked(void)
{
    return CoreLockOwner == KeGetCurrentThread();
}

void
sys_arch_protect(sys_prot_t *lev)
{
    /* Acquire the global resource to prevent other CPUs from running */
    ExEnterCriticalRegionAndAcquireResourceExclusive(&GlobalLock);
    *lev = ++GlobalLockLevel;
}

void
sys_arch_unprotect(sys_prot_t lev)
{
    /* Release the global resource */
    ASSERT((GlobalLockLevel > 0) && (lev == GlobalLockLevel));
    GlobalLockLevel--;
    ExReleaseResourceAndLeaveCriticalRegion(&GlobalLock);
}

err_t
sys_sem_new(sys_sem_t *sem, u8_t count)
{
    ASSERT(count == 0 || count == 1);

    /* It seems lwIP uses the semaphore implementation as either a completion event or a lock
     * so I optimize for this case by using a synchronization event and setting its initial state
     * to signalled for a lock and non-signalled for a completion event */

    KeInitializeEvent(&sem->Event, SynchronizationEvent, count);

    sem->Valid = 1;

    return ERR_OK;
}

int sys_sem_valid(sys_sem_t *sem)
{
    return sem->Valid;
}

void sys_sem_set_invalid(sys_sem_t *sem)
{
    sem->Valid = 0;
}

void
sys_sem_free(sys_sem_t* sem)
{
    /* No op (allocated in stack) */

    sys_sem_set_invalid(sem);
}

void
sys_sem_signal(sys_sem_t* sem)
{
    KeSetEvent(&sem->Event, IO_NO_INCREMENT, FALSE);
}

u32_t
sys_arch_sem_wait(sys_sem_t* sem, u32_t timeout)
{
    LARGE_INTEGER LargeTimeout, PreWaitTime, PostWaitTime;
    UINT64 TimeDiff;
    NTSTATUS Status;
    PVOID WaitObjects[] = {&sem->Event, &TerminationEvent};

    LargeTimeout.QuadPart = Int32x32To64(timeout, -10000);

    KeQuerySystemTime(&PreWaitTime);

    Status = KeWaitForMultipleObjects(2,
                                      WaitObjects,
                                      WaitAny,
                                      Executive,
                                      KernelMode,
                                      FALSE,
                                      timeout != 0 ? &LargeTimeout : NULL,
                                      NULL);
    if (Status == STATUS_WAIT_0)
    {
        KeQuerySystemTime(&PostWaitTime);
        TimeDiff = PostWaitTime.QuadPart - PreWaitTime.QuadPart;
        TimeDiff /= 10000;

        return TimeDiff;
    }
    else if (Status == STATUS_WAIT_1)
    {
        /* DON'T remove ourselves from the thread list! */
        PsTerminateSystemThread(STATUS_SUCCESS);

        /* We should never get here! */
        ASSERT(FALSE);

        return 0;
    }

    return SYS_ARCH_TIMEOUT;
}

err_t
sys_mbox_new(sys_mbox_t *mbox, int size)
{
    KeInitializeSpinLock(&mbox->Lock);

    InitializeListHead(&mbox->ListHead);

    KeInitializeSemaphore(&mbox->Semaphore, 0, MAXLONG);

    mbox->Valid = 1;

    return ERR_OK;
}

int sys_mbox_valid(sys_mbox_t *mbox)
{
    return mbox->Valid;
}

void sys_mbox_set_invalid(sys_mbox_t *mbox)
{
    mbox->Valid = 0;
}

void
sys_mbox_free(sys_mbox_t *mbox)
{
    ASSERT(IsListEmpty(&mbox->ListHead));

    sys_mbox_set_invalid(mbox);
}

void
sys_mbox_post(sys_mbox_t *mbox, void *msg)
{
    PLWIP_MESSAGE_CONTAINER Container;

    Container = ExAllocatePool(NonPagedPool, sizeof(*Container));
    ASSERT(Container);

    Container->Message = msg;

    ExInterlockedInsertTailList(&mbox->ListHead,
                                &Container->ListEntry,
                                &mbox->Lock);

    KeReleaseSemaphore(&mbox->Semaphore, IO_NO_INCREMENT, 1, FALSE);
}

u32_t
sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout)
{
    LARGE_INTEGER LargeTimeout, PreWaitTime, PostWaitTime;
    UINT64 TimeDiff;
    NTSTATUS Status;
    PVOID Message;
    PLWIP_MESSAGE_CONTAINER Container;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    PVOID WaitObjects[] = {&mbox->Semaphore, &TerminationEvent, &TimeoutChanged};
    ULONG WaitCount = 2;

    LargeTimeout.QuadPart = Int32x32To64(timeout, -10000);

    /* The tcpip thread also wakes when another thread adds an earlier timeout. A timed wait then
     * ends as if it had timed out; a wait without timeout (no timer pending: the IP reassembly
     * timer keeps one pending unless its allocation failed) returns a callback that does nothing */
    if (KeGetCurrentThread() == TcpipThread)
        WaitCount = 3;

    KeQuerySystemTime(&PreWaitTime);

    Status = KeWaitForMultipleObjects(WaitCount,
                                      WaitObjects,
                                      WaitAny,
                                      Executive,
                                      KernelMode,
                                      FALSE,
                                      timeout != 0 ? &LargeTimeout : NULL,
                                      NULL);

    if (Status == STATUS_WAIT_0)
    {
        KeAcquireSpinLock(&mbox->Lock, &OldIrql);
        ASSERT(!IsListEmpty(&mbox->ListHead));
        Entry = RemoveHeadList(&mbox->ListHead);
        KeReleaseSpinLock(&mbox->Lock, OldIrql);

        Container = CONTAINING_RECORD(Entry, LWIP_MESSAGE_CONTAINER, ListEntry);
        Message = Container->Message;
        ExFreePool(Container);

        if (msg)
            *msg = Message;

        KeQuerySystemTime(&PostWaitTime);
        TimeDiff = PostWaitTime.QuadPart - PreWaitTime.QuadPart;
        TimeDiff /= 10000;

        return TimeDiff;
    }
    else if (Status == STATUS_WAIT_1)
    {
        /* DON'T remove ourselves from the thread list! */
        PsTerminateSystemThread(STATUS_SUCCESS);

        /* We should never get here! */
        ASSERT(FALSE);

        return 0;
    }
    else if (Status == STATUS_WAIT_2 && timeout == 0)
    {
        if (msg)
            *msg = &TimeoutChangedMsg;

        return 0;
    }

    return SYS_ARCH_TIMEOUT;
}

u32_t
sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg)
{
    if (sys_arch_mbox_fetch(mbox, msg, 1) != SYS_ARCH_TIMEOUT)
        return 0;
    else
        return SYS_MBOX_EMPTY;
}

err_t
sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
    sys_mbox_post(mbox, msg);

    return ERR_OK;
}

VOID
NTAPI
LwipThreadMain(PVOID Context)
{
    thread_t Container = (thread_t)Context;
    KIRQL OldIrql;

    /* tcpip_thread is the only lwIP thread */
    ASSERT(TcpipThread == NULL);
    TcpipThread = KeGetCurrentThread();

    ExInterlockedInsertHeadList(&ThreadListHead, &Container->ListEntry, &ThreadListLock);
    KeSetEvent(&Container->Registered, IO_NO_INCREMENT, FALSE);

    Container->ThreadFunction(Container->ThreadContext);

    KeAcquireSpinLock(&ThreadListLock, &OldIrql);
    RemoveEntryList(&Container->ListEntry);
    KeReleaseSpinLock(&ThreadListLock, OldIrql);

    ExFreePool(Container);

    PsTerminateSystemThread(STATUS_SUCCESS);
}

sys_thread_t
sys_thread_new(const char *name, lwip_thread_fn thread, void *arg, int stacksize, int prio)
{
    thread_t Container;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;

    Container = ExAllocatePool(NonPagedPool, sizeof(*Container));
    if (!Container)
        return 0;

    Container->ThreadFunction = thread;
    Container->ThreadContext = arg;
    KeInitializeEvent(&Container->Registered, NotificationEvent, FALSE);

    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = PsCreateSystemThread(&Container->Handle,
                                  THREAD_ALL_ACCESS,
                                  &ObjectAttributes,
                                  NULL,
                                  NULL,
                                  LwipThreadMain,
                                  Container);

    if (!NT_SUCCESS(Status))
    {
        ExFreePool(Container);
        return 0;
    }

    /* sys_shutdown waits on the thread object; a kernel handle never fails this lookup */
    Status = ObReferenceObjectByHandle(Container->Handle, SYNCHRONIZE, *PsThreadType,
                                       KernelMode, &Container->Thread, NULL);
    ASSERT(NT_SUCCESS(Status));
    if (!NT_SUCCESS(Status))
        Container->Thread = NULL;

    /* A shutdown after startup returns must find the thread in the list */
    KeWaitForSingleObject(&Container->Registered, Executive, KernelMode, FALSE, NULL);

    return 0;
}

void
sys_init(void)
{
    KeInitializeSpinLock(&ThreadListLock);
    InitializeListHead(&ThreadListHead);

    KeQuerySystemTime(&StartTime);

    KeInitializeEvent(&TerminationEvent, NotificationEvent, FALSE);

    TCPInitDeferredCompletions();

    KeInitializeEvent(&CoreLockReleased, SynchronizationEvent, FALSE);
    KeInitializeEvent(&TimeoutChanged, SynchronizationEvent, FALSE);

    /* Never freed: lwIP leaves a static callback message alone after the call */
    TimeoutChangedMsg.type = TCPIP_MSG_CALLBACK_STATIC;
    TimeoutChangedMsg.msg.cb.function = TimeoutChangedCallback;
    TimeoutChangedMsg.msg.cb.ctx = NULL;

    ExInitializeNPagedLookasideList(&MessageLookasideList,
                                    NULL,
                                    NULL,
                                    0,
                                    sizeof(struct lwip_callback_msg),
                                    LWIP_MESSAGE_TAG,
                                    0);

    ExInitializeNPagedLookasideList(&QueueEntryLookasideList,
                                    NULL,
                                    NULL,
                                    0,
                                    sizeof(QUEUE_ENTRY),
                                    LWIP_QUEUE_TAG,
                                    0);
}

void
sys_shutdown(void)
{
    PLIST_ENTRY CurrentEntry;
    thread_t Container;

    /* Set the termination event */
    KeSetEvent(&TerminationEvent, IO_NO_INCREMENT, FALSE);

    /* Loop through the thread list and wait for each to die */
    while ((CurrentEntry = ExInterlockedRemoveHeadList(&ThreadListHead, &ThreadListLock)))
    {
        Container = CONTAINING_RECORD(CurrentEntry, struct _thread_t, ListEntry);

        if (Container->ThreadFunction)
        {
            if (Container->Thread)
            {
                KeWaitForSingleObject(Container->Thread, Executive, KernelMode, FALSE, NULL);
                ObDereferenceObject(Container->Thread);
            }
            ZwClose(Container->Handle);

            /* The thread ended in a wait for the termination event, so it did not free this */
            ExFreePool(Container);
        }
    }

    ExDeleteNPagedLookasideList(&MessageLookasideList);
    ExDeleteNPagedLookasideList(&QueueEntryLookasideList);
}
