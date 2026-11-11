/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * PURPOSE:           Work Item implementation
 * FILE:              lib/rtl/workitem.c
 * PROGRAMMER:
 */

/* INCLUDES *****************************************************************/

#include <rtl.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ***************************************************************/

NTSTATUS
NTAPI
RtlpStartThread(IN PTHREAD_START_ROUTINE Function,
                IN PVOID Parameter,
                OUT PHANDLE ThreadHandle)
{
    /* Create a native worker thread -- used for SMSS, CSRSS, etc... */
    return RtlCreateUserThread(NtCurrentProcess(),
                               NULL,
                               TRUE,
                               0,
                               0,
                               0,
                               Function,
                               Parameter,
                               ThreadHandle,
                               NULL);
}

NTSTATUS
NTAPI
RtlpExitThread(IN NTSTATUS ExitStatus)
{
    /* Kill a native worker thread -- used for SMSS, CSRSS, etc... */
    return NtTerminateThread(NtCurrentThread(), ExitStatus);
}

PRTL_START_POOL_THREAD RtlpStartThreadFunc = RtlpStartThread;
PRTL_EXIT_POOL_THREAD RtlpExitThreadFunc = RtlpExitThread;

/*
 * Thread injection, after Windows 10 (measured with QueueUserWorkItem floods on 4 CPUs):
 * - as many workers as there are processors are created as soon as work is queued;
 * - beyond that, a thread is added only while work items wait in the queue and none was
 *   dequeued for about a timer tick, checked every ~160 ms: a pool whose callbacks all
 *   block grows by about 6 threads a second, a pool of short callbacks barely grows;
 * - a WT_EXECUTELONGFUNCTION item that finds no free worker gets a new thread at once;
 * - I/O worker threads were removed in Vista: WT_EXECUTEINIOTHREAD items run in the
 *   same pool (its threads wait alertably, so APCs of I/O they issued are delivered);
 * - WT_EXECUTEINPERSISTENTTHREAD items run one after another on a single thread that
 *   never exits.
 * Blocked callbacks keep the queue from draining, so the injection keeps adding threads
 * up to MAX_WORKERTHREADS: items that wait for other items still get a thread.
 *
 * Work items wait in a list under ThreadPoolLock, in the order they were queued, and the
 * workers take them from it. The completion port is where idle workers sleep: queuing an
 * item posts a wake-up there only when a worker sleeps that no wake-up is on its way to
 * (a worker that is running looks at the list before it sleeps again), so a stream of
 * items costs the queuer no system call and no inter-processor interrupt while the
 * workers keep up. Completions of files bound to the pool (RtlSetIoCompletionCallback)
 * arrive in the same port and wake a sleeping worker as before.
 */
#define MAX_WORKERTHREADS           0x100
#define WORKER_INJECT_INTERVAL_MS   160
#define WORKER_STALL_MS             15
#define WORKER_MONITOR_IDLE_CHECKS  16  /* checks without backlog before the monitor exits */
#define WORKER_SPIN_COUNT           1000 /* polls of the queue by the spinning worker before it sleeps */

typedef struct _RTLP_WORKITEM
{
    LIST_ENTRY ListEntry;
    WORKERCALLBACKFUNC Function;
    PVOID Context;
    ULONG Flags;
    HANDLE TokenHandle;
} RTLP_WORKITEM, *PRTLP_WORKITEM;

static LONG ThreadPoolInitialized = 0;
static RTL_CRITICAL_SECTION ThreadPoolLock;
static HANDLE ThreadPoolCompletionPort;
static LONG ThreadPoolMinThreads;
static LONG ThreadPoolWorkerThreads;            /* worker threads started and not exited */
static LONG ThreadPoolWorkerThreadsRequests;    /* work items queued or running */
static LONG ThreadPoolWorkerThreadsLongRequests;
static LONG ThreadPoolWorkerThreadsQueued;      /* work items in ThreadPoolQueue, not taken yet */
static LIST_ENTRY ThreadPoolQueue;              /* the work items waiting for a worker, oldest first */
static LONG ThreadPoolIdleWorkers;              /* workers that sleep in the port or are about to */
static LONG ThreadPoolWakeups;                  /* wake-ups posted to the port and not yet taken */
static volatile LONG ThreadPoolSpinners;        /* 1 while a worker polls the queue before it sleeps */
static BOOLEAN ThreadPoolSpinEnabled;           /* more than one processor */
static LONG ThreadPoolWorkerThreadsBusy;        /* workers running a callback */
static volatile ULONG ThreadPoolLastDequeue;    /* interrupt time in ms */
static BOOLEAN ThreadPoolMonitorRunning;

static LIST_ENTRY PersistentThreadQueue;
static HANDLE PersistentThreadEvent;
static BOOLEAN PersistentThreadStarted;

/* Spare work items: a stream of items would otherwise allocate in the queuer and free in a worker,
   two threads on two processors using the heap lock and its free lists for every item */
#define WORKITEM_CACHE_DEPTH 256
static SLIST_HEADER WorkItemCache;

#define IsThreadPoolInitialized() (*((volatile LONG*)&ThreadPoolInitialized) == 1)

static ULONG
RtlpPoolTimeMs(VOID)
{
    ULARGE_INTEGER Time;

    do
    {
        Time.HighPart = SharedUserData->InterruptTime.High1Time;
        Time.LowPart = SharedUserData->InterruptTime.LowPart;
    } while (Time.HighPart != (ULONG)SharedUserData->InterruptTime.High2Time);

    return (ULONG)(Time.QuadPart / 10000);
}

static PRTLP_WORKITEM
RtlpAllocateWorkItem(VOID)
{
    PSLIST_ENTRY Entry = RtlInterlockedPopEntrySList(&WorkItemCache);

    if (Entry != NULL)
        return CONTAINING_RECORD(Entry, RTLP_WORKITEM, ListEntry);

    return RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(RTLP_WORKITEM));
}

static VOID
RtlpFreeWorkItem(IN PRTLP_WORKITEM WorkItem)
{
    if (RtlQueryDepthSList(&WorkItemCache) < WORKITEM_CACHE_DEPTH)
        RtlInterlockedPushEntrySList(&WorkItemCache, (PSLIST_ENTRY)&WorkItem->ListEntry);
    else
        RtlFreeHeap(RtlGetProcessHeap(), 0, WorkItem);
}

static NTSTATUS
RtlpInitializeThreadPool(VOID)
{
    NTSTATUS Status = STATUS_SUCCESS;
    LONG InitStatus;

    do
    {
        InitStatus = InterlockedCompareExchange(&ThreadPoolInitialized,
                                                 2,
                                                 0);
        if (InitStatus == 0)
        {
            /* We're the first thread to initialize the thread pool */

            RtlInitializeSListHead(&WorkItemCache);
            InitializeListHead(&PersistentThreadQueue);
            InitializeListHead(&ThreadPoolQueue);
            ThreadPoolIdleWorkers = 0;
            ThreadPoolWakeups = 0;
            ThreadPoolSpinners = 0;
            ThreadPoolSpinEnabled = (NtCurrentPeb()->NumberOfProcessors > 1);
            PersistentThreadEvent = NULL;
            PersistentThreadStarted = FALSE;

            ThreadPoolWorkerThreads = 0;
            ThreadPoolWorkerThreadsRequests = 0;
            ThreadPoolWorkerThreadsLongRequests = 0;
            ThreadPoolWorkerThreadsQueued = 0;
            ThreadPoolWorkerThreadsBusy = 0;
            ThreadPoolMonitorRunning = FALSE;

            ThreadPoolMinThreads = NtCurrentPeb()->NumberOfProcessors;
            if (ThreadPoolMinThreads < 1)
                ThreadPoolMinThreads = 1;
            else if (ThreadPoolMinThreads > MAX_WORKERTHREADS)
                ThreadPoolMinThreads = MAX_WORKERTHREADS;

            /* Initialize the lock */
            Status = RtlInitializeCriticalSectionAndSpinCount(&ThreadPoolLock, 4000);
            if (!NT_SUCCESS(Status))
                goto Finish;

            /* Create the complection port */
            Status = NtCreateIoCompletion(&ThreadPoolCompletionPort,
                                          IO_COMPLETION_ALL_ACCESS,
                                          NULL,
                                          0);
            if (!NT_SUCCESS(Status))
            {
                RtlDeleteCriticalSection(&ThreadPoolLock);
                goto Finish;
            }

Finish:
            /* Initialization done. On failure, let a later call try again. */
            InterlockedExchange(&ThreadPoolInitialized,
                                NT_SUCCESS(Status) ? 1 : 0);
            break;
        }
        else if (InitStatus == 2)
        {
            LARGE_INTEGER Timeout;

            /* Another thread is currently initializing the thread pool!
               Poll after a short period of time to see if the initialization
               was completed */

            Timeout.QuadPart = -10000000LL; /* Wait for a second */
            NtDelayExecution(FALSE,
                             &Timeout);
        }
    } while (InitStatus != 1);

    return Status;
}

static NTSTATUS
RtlpGetImpersonationToken(OUT PHANDLE TokenHandle)
{
    NTSTATUS Status;

    Status = NtOpenThreadToken(NtCurrentThread(),
                               TOKEN_IMPERSONATE,
                               TRUE,
                               TokenHandle);
    if (Status == STATUS_NO_TOKEN || Status == STATUS_CANT_OPEN_ANONYMOUS)
    {
        *TokenHandle = NULL;
        Status = STATUS_SUCCESS;
    }

    return Status;
}

/* Start a pool thread. Do not wait for it to run: the caller holds ThreadPoolLock,
   and the new thread can be held up by the loader lock in its DLL notifications. */
static NTSTATUS
RtlpStartPoolThread(PTHREAD_START_ROUTINE StartRoutine)
{
    NTSTATUS Status;
    HANDLE ThreadHandle;

    Status = RtlpStartThreadFunc(StartRoutine, NULL, &ThreadHandle);
    if (NT_SUCCESS(Status))
    {
        NtResumeThread(ThreadHandle, NULL);
        NtClose(ThreadHandle);
    }

    return Status;
}

static ULONG NTAPI RtlpWorkerThreadProc(IN PVOID Parameter);
static ULONG NTAPI RtlpWorkerMonitorThreadProc(IN PVOID Parameter);

/* Called with ThreadPoolLock held */
static NTSTATUS
RtlpStartWorkerThread(VOID)
{
    NTSTATUS Status;

    if (ThreadPoolWorkerThreads >= MAX_WORKERTHREADS)
        return STATUS_TOO_MANY_THREADS;

    /* Count the thread from now on: it is a free worker even before it runs */
    InterlockedIncrement(&ThreadPoolWorkerThreads);

    Status = RtlpStartPoolThread(RtlpWorkerThreadProc);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to start a worker thread, Status 0x%lx\n", Status);
        InterlockedDecrement(&ThreadPoolWorkerThreads);
    }

    return Status;
}

/* Called with ThreadPoolLock held */
static VOID
RtlpStartWorkerMonitor(VOID)
{
    NTSTATUS Status;

    if (ThreadPoolMonitorRunning)
        return;

    ThreadPoolMonitorRunning = TRUE;
    Status = RtlpStartPoolThread(RtlpWorkerMonitorThreadProc);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to start the worker monitor, Status 0x%lx\n", Status);
        ThreadPoolMonitorRunning = FALSE;
    }
}

/* Run a work item and free it. Returns the flags it was queued with. */
static ULONG
RtlpRunWorkItem(IN PRTLP_WORKITEM QueuedItem)
{
    NTSTATUS Status;
    BOOLEAN Impersonated = FALSE;
    RTLP_WORKITEM WorkItem = *(volatile RTLP_WORKITEM *)QueuedItem;

    RtlpFreeWorkItem(QueuedItem);

    if (WorkItem.TokenHandle != NULL)
    {
        Status = NtSetInformationThread(NtCurrentThread(),
                                        ThreadImpersonationToken,
                                        &WorkItem.TokenHandle,
                                        sizeof(HANDLE));

        NtClose(WorkItem.TokenHandle);

        if (NT_SUCCESS(Status))
        {
            Impersonated = TRUE;
        }
    }

    _SEH2_TRY
    {
        DPRINT("RtlpRunWorkItem: Function: 0x%p Context: 0x%p ImpersonationToken: 0x%p\n", WorkItem.Function, WorkItem.Context, WorkItem.TokenHandle);

        /* Execute the function */
        WorkItem.Function(WorkItem.Context);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT1("Exception 0x%x while executing work item 0x%p\n", _SEH2_GetExceptionCode(), WorkItem.Function);
    }
    _SEH2_END;

    if (Impersonated)
    {
        WorkItem.TokenHandle = NULL;
        Status = NtSetInformationThread(NtCurrentThread(),
                                        ThreadImpersonationToken,
                                        &WorkItem.TokenHandle,
                                        sizeof(HANDLE));
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed to revert worker thread to self!!! Status: 0x%x\n", Status);
        }
    }

    return WorkItem.Flags;
}

/* Posted to the port to wake a sleeping worker; the address marks the completion */
static VOID
NTAPI
RtlpWorkerWakeup(IN OUT PVOID NormalContext,
                 IN OUT PVOID SystemArgument1,
                 IN OUT PVOID SystemArgument2)
{
}

/* Called with ThreadPoolLock held: wake a worker that sleeps in the port if items wait and no
   wake-up is on its way to it. A worker that polls the queue (ThreadPoolSpinners) is awake and
   takes the item itself; the worker that takes an item does this again for the items left. */
static NTSTATUS
RtlpWakeIdleWorker(VOID)
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (ThreadPoolSpinners == 0 && ThreadPoolIdleWorkers > ThreadPoolWakeups)
    {
        Status = NtSetIoCompletion(ThreadPoolCompletionPort,
                                   RtlpWorkerWakeup,
                                   NULL,
                                   STATUS_SUCCESS,
                                   0);
        if (NT_SUCCESS(Status))
            ThreadPoolWakeups++;
    }

    return Status;
}

/* Called with ThreadPoolLock held */
static NTSTATUS
RtlpQueueWorkerThread(IN OUT PRTLP_WORKITEM WorkItem)
{
    NTSTATUS Status = STATUS_SUCCESS;

    ThreadPoolWorkerThreadsRequests++;
    ThreadPoolWorkerThreadsQueued++;

    if (WorkItem->Flags & WT_EXECUTELONGFUNCTION)
    {
        ThreadPoolWorkerThreadsLongRequests++;
    }

    InsertTailList(&ThreadPoolQueue, &WorkItem->ListEntry);

    /* The workers that are running look at the queue before they sleep */
    Status = RtlpWakeIdleWorker();

    if (!NT_SUCCESS(Status))
    {
        /* The item is the last in the queue: take it out again */
        RemoveEntryList(&WorkItem->ListEntry);

        ThreadPoolWorkerThreadsRequests--;
        ThreadPoolWorkerThreadsQueued--;

        if (WorkItem->Flags & WT_EXECUTELONGFUNCTION)
        {
            ThreadPoolWorkerThreadsLongRequests--;
        }
    }

    return Status;
}

static ULONG
NTAPI
RtlpPersistentThreadProc(IN PVOID Parameter)
{
    PLIST_ENTRY Entry;

    for (;;)
    {
        RtlEnterCriticalSection(&ThreadPoolLock);

        if (IsListEmpty(&PersistentThreadQueue))
        {
            RtlLeaveCriticalSection(&ThreadPoolLock);

            /* Wait alertably: the APCs of I/O started by the work items are delivered here */
            NtWaitForSingleObject(PersistentThreadEvent, TRUE, NULL);
            continue;
        }

        Entry = RemoveHeadList(&PersistentThreadQueue);
        RtlLeaveCriticalSection(&ThreadPoolLock);

        /* The items run one after another, never nested in each other */
        RtlpRunWorkItem(CONTAINING_RECORD(Entry, RTLP_WORKITEM, ListEntry));
    }

    return 0;
}

/* Called with ThreadPoolLock held */
static NTSTATUS
RtlpQueuePersistentWorkItem(IN OUT PRTLP_WORKITEM WorkItem)
{
    NTSTATUS Status;

    if (!PersistentThreadStarted)
    {
        if (PersistentThreadEvent == NULL)
        {
            Status = NtCreateEvent(&PersistentThreadEvent,
                                   EVENT_ALL_ACCESS,
                                   NULL,
                                   SynchronizationEvent,
                                   FALSE);
            if (!NT_SUCCESS(Status))
            {
                PersistentThreadEvent = NULL;
                return Status;
            }
        }

        Status = RtlpStartPoolThread(RtlpPersistentThreadProc);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed to start the persistent thread, Status 0x%lx\n", Status);
            return Status;
        }

        PersistentThreadStarted = TRUE;
    }

    InsertTailList(&PersistentThreadQueue, &WorkItem->ListEntry);
    NtSetEvent(PersistentThreadEvent, NULL);

    return STATUS_SUCCESS;
}

static BOOLEAN
RtlpIsIoPending(IN HANDLE ThreadHandle  OPTIONAL)
{
    NTSTATUS Status;
    ULONG IoPending;
    BOOLEAN CreatedHandle = FALSE;
    BOOLEAN IsIoPending = TRUE;

    if (ThreadHandle == NULL)
    {
        Status = NtDuplicateObject(NtCurrentProcess(),
                                   NtCurrentThread(),
                                   NtCurrentProcess(),
                                   &ThreadHandle,
                                   0,
                                   0,
                                   DUPLICATE_SAME_ACCESS);
        if (!NT_SUCCESS(Status))
        {
            return IsIoPending;
        }

        CreatedHandle = TRUE;
    }

    Status = NtQueryInformationThread(ThreadHandle,
                                      ThreadIsIoPending,
                                      &IoPending,
                                      sizeof(IoPending),
                                      NULL);
    if (NT_SUCCESS(Status) && IoPending == 0)
    {
        IsIoPending = FALSE;
    }

    if (CreatedHandle)
    {
        NtClose(ThreadHandle);
    }

    return IsIoPending;
}

/* Adds a worker while queued work makes no progress; exits once the queue stays empty */
static ULONG
NTAPI
RtlpWorkerMonitorThreadProc(IN PVOID Parameter)
{
    LARGE_INTEGER Interval;
    IO_COMPLETION_BASIC_INFORMATION Info;
    ULONG IdleChecks = 0;
    NTSTATUS Status;

    Interval.QuadPart = -10000LL * WORKER_INJECT_INTERVAL_MS;

    for (;;)
    {
        NtDelayExecution(FALSE, &Interval);

        if (!NT_SUCCESS(RtlEnterCriticalSection(&ThreadPoolLock)))
            continue;

        /* Work items waiting in the queue, and completions of bound files waiting in the port
           (wake-ups posted to the port are not work) */
        Status = NtQueryIoCompletion(ThreadPoolCompletionPort,
                                     IoCompletionBasicInformation,
                                     &Info,
                                     sizeof(Info),
                                     NULL);
        if (!NT_SUCCESS(Status))
            Info.Depth = ThreadPoolWakeups;

        if (ThreadPoolWorkerThreadsQueued > 0 || (LONG)Info.Depth > ThreadPoolWakeups)
        {
            IdleChecks = 0;

            /* Every worker is busy and nothing was dequeued for a while: add one.
               (A worker that is not busy is starting, or the port holds it back
               because enough threads run: another thread would not help.) */
            if (ThreadPoolWorkerThreads - *((volatile LONG*)&ThreadPoolWorkerThreadsBusy) <= 0 &&
                (ULONG)(RtlpPoolTimeMs() - ThreadPoolLastDequeue) >= WORKER_STALL_MS)
            {
                RtlpStartWorkerThread();
            }
        }
        else if (++IdleChecks >= WORKER_MONITOR_IDLE_CHECKS)
        {
            ThreadPoolMonitorRunning = FALSE;
            RtlLeaveCriticalSection(&ThreadPoolLock);
            break;
        }

        RtlLeaveCriticalSection(&ThreadPoolLock);
    }

    RtlpExitThreadFunc(STATUS_SUCCESS);
    return 0;
}

static ULONG
NTAPI
RtlpWorkerThreadProc(IN PVOID Parameter)
{
    LARGE_INTEGER Timeout;
    BOOLEAN Terminate;
    BOOLEAN Idle = FALSE;       /* counted in ThreadPoolIdleWorkers */
    FILE_IO_COMPLETION_INFORMATION Completion;
    ULONG Removed;
    ULONG TimeoutCount = 0;
    PKNORMAL_ROUTINE ApcRoutine;
    PRTLP_WORKITEM WorkItem;
    BOOLEAN Spun = FALSE;               /* this worker polled the queue since it last ran an item */
    ULONG Spin;
    volatile BOOLEAN Running = FALSE;   /* an item ran whose counters are not settled yet */
    volatile ULONG RunFlags = 0;
    BOOLEAN Counted;                    /* a bound file's callback is counted in ThreadPoolWorkerThreadsBusy */
    NTSTATUS Status = STATUS_SUCCESS;

    /* ThreadPoolWorkerThreads was incremented by RtlpStartWorkerThread */

    for (;;)
    {
        /* Run the queued work items before sleeping. The queuer wakes only a worker that
           sleeps (is counted idle), so this worker leaves the idle count in the same
           critical section that takes the item, and joins it in the one that finds none.
           The counters of the item that just ran are settled in that critical section
           too: they change only with the lock held. */
        for (;;)
        {
            if (!NT_SUCCESS(RtlEnterCriticalSection(&ThreadPoolLock)))
                break;

            if (Running)
            {
                Running = FALSE;
                ThreadPoolWorkerThreadsBusy--;
                ThreadPoolWorkerThreadsRequests--;
                if (RunFlags & WT_EXECUTELONGFUNCTION)
                    ThreadPoolWorkerThreadsLongRequests--;
            }

            if (IsListEmpty(&ThreadPoolQueue))
            {
                if (ThreadPoolSpinEnabled && !Idle && !Spun && ThreadPoolSpinners == 0)
                {
                    /* Poll for the next item a moment, one worker at a time: in a stream of items
                       this keeps the queuer from waking a sleeping worker for each of them, and
                       keeps the other workers asleep and off the lock */
                    ThreadPoolSpinners = 1;
                    RtlLeaveCriticalSection(&ThreadPoolLock);

                    for (Spin = 0;
                         Spin < WORKER_SPIN_COUNT && *((volatile LONG*)&ThreadPoolWorkerThreadsQueued) == 0;
                         Spin++)
                    {
                        YieldProcessor();
                    }

                    /* Not a spinner any more before the queue is looked at again: an item queued
                       from here on wakes a sleeper, one queued before is seen by this worker */
                    InterlockedDecrement(&ThreadPoolSpinners);
                    Spun = TRUE;
                    continue;
                }

                if (!Idle)
                {
                    Idle = TRUE;
                    ThreadPoolIdleWorkers++;
                }
                RtlLeaveCriticalSection(&ThreadPoolLock);
                break;
            }

            WorkItem = CONTAINING_RECORD(RemoveHeadList(&ThreadPoolQueue), RTLP_WORKITEM, ListEntry);
            ThreadPoolWorkerThreadsQueued--;
            if (Idle)
            {
                Idle = FALSE;
                ThreadPoolIdleWorkers--;
            }
            TimeoutCount = 0;
            ThreadPoolLastDequeue = RtlpPoolTimeMs();

            /* The last free worker takes a callback: have the monitor watch the queue */
            if (++ThreadPoolWorkerThreadsBusy >= ThreadPoolWorkerThreads)
                RtlpStartWorkerMonitor();

            /* Items are left: wake another worker for them */
            if (!IsListEmpty(&ThreadPoolQueue))
                RtlpWakeIdleWorker();

            RtlLeaveCriticalSection(&ThreadPoolLock);

            Spun = FALSE;
            Running = TRUE;
            RunFlags = WorkItem->Flags;
            _SEH2_TRY
            {
                RtlpRunWorkItem(WorkItem);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                (void)0;
            }
            _SEH2_END;
        }

        Timeout.QuadPart = -50000000LL; /* Wait for 5 seconds by default */

        /* Dequeue a completion message. Wait alertably, as the I/O worker threads
           did: a work item may have started I/O that completes with an APC */
        Removed = 0;
        Status = NtRemoveIoCompletionEx(ThreadPoolCompletionPort,
                                        &Completion,
                                        1,
                                        &Removed,
                                        &Timeout,
                                        TRUE);

        if (Status == STATUS_SUCCESS && Removed == 1)
        {
            TimeoutCount = 0;

            ApcRoutine = (PKNORMAL_ROUTINE)Completion.KeyContext;
            Counted = FALSE;

            /* Awake: leave the idle count, and settle the wake-up this was. A completion
               of a bound file counts as a running callback; the last free worker taking
               one has the monitor watch the queue. */
            if (NT_SUCCESS(RtlEnterCriticalSection(&ThreadPoolLock)))
            {
                if (Idle)
                {
                    Idle = FALSE;
                    ThreadPoolIdleWorkers--;
                }
                if (ApcRoutine == (PKNORMAL_ROUTINE)RtlpWorkerWakeup)
                {
                    ThreadPoolWakeups--;
                }
                else
                {
                    ThreadPoolLastDequeue = RtlpPoolTimeMs();
                    if (++ThreadPoolWorkerThreadsBusy >= ThreadPoolWorkerThreads)
                        RtlpStartWorkerMonitor();
                    Counted = TRUE;
                }
                RtlLeaveCriticalSection(&ThreadPoolLock);
            }

            /* A wake-up: the queue is looked at on the next round */
            if (ApcRoutine == (PKNORMAL_ROUTINE)RtlpWorkerWakeup)
                continue;

            _SEH2_TRY
            {
                /* Call the APC routine of a completion of a bound file: it takes the
                   Win32 error code of the I/O as its first argument. */
                ApcRoutine((PVOID)(ULONG_PTR)RtlNtStatusToDosErrorNoTeb(Completion.IoStatusBlock.Status),
                           (PVOID)Completion.IoStatusBlock.Information,
                           Completion.ApcContext);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                (void)0;
            }
            _SEH2_END;

            if (Counted && NT_SUCCESS(RtlEnterCriticalSection(&ThreadPoolLock)))
            {
                ThreadPoolWorkerThreadsBusy--;
                RtlLeaveCriticalSection(&ThreadPoolLock);
            }
        }
        else if (Status == STATUS_USER_APC || Status == STATUS_ALERTED ||
                 Status == STATUS_SUCCESS)
        {
            /* An APC ran, look at the queue and wait again */
            continue;
        }
        else
        {
            Terminate = FALSE;

            if (!NT_SUCCESS(RtlEnterCriticalSection(&ThreadPoolLock)))
                continue;

            if (Status == STATUS_TIMEOUT)
            {
                /* Idle for a while: keep the minimum and the threads running long functions.
                   Do not leave while items are queued: their queuer counted this worker as
                   free and may have started neither a thread nor the monitor. */
                if (TimeoutCount++ > 2 &&
                    *((volatile LONG*)&ThreadPoolWorkerThreadsQueued) == 0 &&
                    *((volatile LONG*)&ThreadPoolWorkerThreads) - *((volatile LONG*)&ThreadPoolWorkerThreadsLongRequests) > ThreadPoolMinThreads)
                {
                    Terminate = TRUE;
                }
            }
            else
                Terminate = TRUE;

            if (Terminate)
            {
                /* Prevent termination as long as IO is pending */
                Terminate = !RtlpIsIoPending(NULL);
            }

            /* Leave the pool under the lock that guards the check above */
            if (Terminate)
            {
                InterlockedDecrement(&ThreadPoolWorkerThreads);
                if (Idle)
                {
                    Idle = FALSE;
                    ThreadPoolIdleWorkers--;
                }
            }

            RtlLeaveCriticalSection(&ThreadPoolLock);

            if (Terminate)
            {
                Status = STATUS_SUCCESS;
                break;
            }
        }
    }

    RtlpExitThreadFunc(Status);
    return 0;

}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlQueueWorkItem(IN WORKERCALLBACKFUNC Function,
                 IN PVOID Context  OPTIONAL,
                 IN ULONG Flags)
{
    LONG FreeWorkers;
    NTSTATUS Status;
    PRTLP_WORKITEM WorkItem;

    DPRINT("RtlQueueWorkItem(0x%p, 0x%p, 0x%x)\n", Function, Context, Flags);

    /* Initialize the thread pool if not already initialized */
    if (!IsThreadPoolInitialized())
    {
        Status = RtlpInitializeThreadPool();

        if (!NT_SUCCESS(Status))
            return Status;
    }

    /* Allocate a work item */
    WorkItem = RtlpAllocateWorkItem();
    if (WorkItem == NULL)
        return STATUS_NO_MEMORY;

    WorkItem->Function = Function;
    WorkItem->Context = Context;
    WorkItem->Flags = Flags;

    if (Flags & WT_TRANSFER_IMPERSONATION)
    {
        Status = RtlpGetImpersonationToken(&WorkItem->TokenHandle);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed to get impersonation token! Status: 0x%x\n", Status);
            goto Cleanup;
        }
    }
    else
        WorkItem->TokenHandle = NULL;

    Status = RtlEnterCriticalSection(&ThreadPoolLock);
    if (NT_SUCCESS(Status))
    {
        if (Flags & (WT_EXECUTEINPERSISTENTTHREAD | WT_EXECUTEINPERSISTENTIOTHREAD))
        {
            Status = RtlpQueuePersistentWorkItem(WorkItem);
        }
        else
        {
            /* WT_EXECUTEINIOTHREAD and WT_EXECUTEINUITHREAD items run in the worker
               pool too, as on Vista and later */

            FreeWorkers = ThreadPoolWorkerThreads - ThreadPoolWorkerThreadsBusy - ThreadPoolWorkerThreadsQueued;

            /* Start the minimum at once, and a thread for a long function if no worker is free */
            if (FreeWorkers <= 0 &&
                (ThreadPoolWorkerThreads < ThreadPoolMinThreads || (Flags & WT_EXECUTELONGFUNCTION)))
            {
                if (NT_SUCCESS(RtlpStartWorkerThread()))
                    FreeWorkers++;
            }

            if (ThreadPoolWorkerThreads == 0)
            {
                /* No worker, and none could be started */
                Status = STATUS_NO_MEMORY;
            }
            else
            {
                /* Queue a normal worker thread */
                Status = RtlpQueueWorkerThread(WorkItem);

                /* The item waits for a worker: add threads while the queue makes no progress */
                if (NT_SUCCESS(Status) && FreeWorkers <= 0)
                    RtlpStartWorkerMonitor();
            }
        }

        RtlLeaveCriticalSection(&ThreadPoolLock);
    }

    if (!NT_SUCCESS(Status))
    {
        if (WorkItem->TokenHandle != NULL)
        {
            NtClose(WorkItem->TokenHandle);
        }

Cleanup:
        RtlpFreeWorkItem(WorkItem);
    }

    return Status;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
RtlSetIoCompletionCallback(IN HANDLE FileHandle,
                           IN PIO_APC_ROUTINE Callback,
                           IN ULONG Flags)
{
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_COMPLETION_INFORMATION FileCompletionInfo;
    NTSTATUS Status;

    DPRINT("RtlSetIoCompletionCallback(0x%p, 0x%p, 0x%x)\n", FileHandle, Callback, Flags);

    /* Initialize the thread pool if not already initialized */
    if (!IsThreadPoolInitialized())
    {
        Status = RtlpInitializeThreadPool();
        if (!NT_SUCCESS(Status))
            return Status;
    }

    /* The callbacks run in the worker threads, make sure one exists. When all
       workers are busy, the monitor adds more if completions queue up. */
    Status = RtlEnterCriticalSection(&ThreadPoolLock);
    if (!NT_SUCCESS(Status))
        return Status;

    if (ThreadPoolWorkerThreads < ThreadPoolMinThreads)
        RtlpStartWorkerThread();

    if (ThreadPoolWorkerThreads == 0)
        Status = STATUS_NO_MEMORY;

    RtlLeaveCriticalSection(&ThreadPoolLock);

    if (!NT_SUCCESS(Status))
        return Status;

    FileCompletionInfo.Port = ThreadPoolCompletionPort;
    FileCompletionInfo.Key = (PVOID)Callback;

    Status = NtSetInformationFile(FileHandle,
                                  &IoStatusBlock,
                                  &FileCompletionInfo,
                                  sizeof(FileCompletionInfo),
                                  FileCompletionInformation);

    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlSetThreadPoolStartFunc(IN PRTL_START_POOL_THREAD StartPoolThread,
                          IN PRTL_EXIT_POOL_THREAD ExitPoolThread)
{
    RtlpStartThreadFunc = StartPoolThread;
    RtlpExitThreadFunc = ExitPoolThread;
    return STATUS_SUCCESS;
}
