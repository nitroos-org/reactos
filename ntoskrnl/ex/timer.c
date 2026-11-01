/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ex/timer.c
 * PURPOSE:         Executive Timer Implementation
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

/* Timer Object Type */
POBJECT_TYPE ExTimerType = NULL;

/* Object type of the timers NtCreateTimer2 creates; Windows 10 names it IRTimer */
POBJECT_TYPE ExpIRTimerType = NULL;

KSPIN_LOCK ExpWakeListLock;
LIST_ENTRY ExpWakeList;

/*
 * High resolution timers (NtCreateTimer2 with TIMER2_ATTRIBUTE_HIGH_RESOLUTION, which is what
 * CreateWaitableTimerExW(CREATE_WAITABLE_TIMER_HIGH_RESOLUTION) creates). Windows 10 fires them
 * within a few tens of microseconds of their due time without the process raising the timer
 * resolution, and reports the raised rate through NtQueryTimerResolution only while such a timer
 * is about to expire. Here the clock interrupt is raised (ExSetTimerResolution) while at least
 * one high resolution timer is periodic or due within ExpHighResWindow, and dropped again
 * EXP_HR_LINGER after the last one has gone. A timer due later arms HighResPreTimer, which marks
 * it "near" ExpHighResWindow before its due time. The rate is changed at PASSIVE_LEVEL: by the
 * thread that sets the timer, or by ExpHighResWorkItem when a DPC finds a change is needed.
 */
static LONG ExpHighResNearCount;            /* high resolution timers in the ETIMER_HR_NEAR state */
static BOOLEAN ExpHighResHeld;              /* the raised rate is requested; time refresh lock */
static KTIMER ExpHighResLingerTimer;
static KDPC ExpHighResLingerDpc;
static WORK_QUEUE_ITEM ExpHighResWorkItem;
static LONG ExpHighResWorkQueued;

/* Requested clock increment: 1 ms (the HALs here go down to 1 ms / 0.98 ms) */
#define EXP_HR_INCREMENT        10000
/* How long the clock stays fast after the last near high resolution timer has gone */
#define EXP_HR_LINGER           (-100LL * 10000)
/* A timer due within this time of being set (or of its pre-timer) needs the fast clock */
#define ExpHighResWindow()      (4LL * KeMaximumIncrement)
/* NtSetTimer2: shorter periods run at 0.5 ms on Windows 10 */
#define EXP_TIMER2_MIN_PERIOD   5000
/* NtCreateTimer2: this attribute is in the valid mask but refused for every caller (measured) */
#define EXP_TIMER2_ATTRIBUTE_REFUSED 0x00000002
#define EXP_TIMER2_VALID_ATTRIBUTES (TIMER2_ATTRIBUTE_NOTIFICATION | TIMER2_ATTRIBUTE_NO_WAKE | \
                                     TIMER2_ATTRIBUTE_HIGH_RESOLUTION | EXP_TIMER2_ATTRIBUTE_REFUSED)

/* Timer Mapping */
static GENERIC_MAPPING ExpTimerMapping =
{
    STANDARD_RIGHTS_READ    | TIMER_QUERY_STATE,
    STANDARD_RIGHTS_WRITE   | TIMER_MODIFY_STATE,
    STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    TIMER_ALL_ACCESS
};

/* Timer Information Classes */
static const INFORMATION_CLASS_INFO ExTimerInfoClass[] =
{
    /* TimerBasicInformation */
    IQS_SAME(TIMER_BASIC_INFORMATION, ULONG, ICIF_QUERY),
};

/* PRIVATE FUNCTIONS *********************************************************/

KDEFERRED_ROUTINE ExpTimerDpcRoutine;

/* Make the clock rate match the high resolution timers. PASSIVE_LEVEL. */
static
VOID
ExpHighResUpdate(VOID)
{
    LONG NearCount;

    ExAcquireTimeRefreshLock(TRUE);
    NearCount = *(volatile LONG *)&ExpHighResNearCount;
    if ((NearCount > 0) && !ExpHighResHeld)
    {
        ExSetTimerResolution(EXP_HR_INCREMENT, TRUE);
        ExpHighResHeld = TRUE;
    }
    else if ((NearCount == 0) && ExpHighResHeld && KeReadStateTimer(&ExpHighResLingerTimer))
    {
        /* None has been near for EXP_HR_LINGER */
        ExSetTimerResolution(0, FALSE);
        ExpHighResHeld = FALSE;
    }
    ExReleaseTimeRefreshLock();
}

_Function_class_(WORKER_THREAD_ROUTINE)
static
VOID
NTAPI
ExpHighResWorker(IN PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    InterlockedExchange(&ExpHighResWorkQueued, 0);
    ExpHighResUpdate();
}

/* Have ExpHighResUpdate run soon. Any IRQL up to DISPATCH_LEVEL. */
static
VOID
ExpHighResQueueUpdate(VOID)
{
    if (!InterlockedExchange(&ExpHighResWorkQueued, 1))
    {
        ExQueueWorkItem(&ExpHighResWorkItem, CriticalWorkQueue);
    }
}

_Function_class_(KDEFERRED_ROUTINE)
static
VOID
NTAPI
ExpHighResLingerDpcRoutine(IN PKDPC Dpc,
                           IN PVOID DeferredContext,
                           IN PVOID SystemArgument1,
                           IN PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExpHighResQueueUpdate();
}

/*
 * The timer needs the fast clock now. Timer lock held. Returns TRUE when the caller has to call
 * ExpHighResUpdate (or queue it): the raised rate is not requested yet.
 */
static
BOOLEAN
ExpHighResSetNear(IN PETIMER Timer)
{
    if (Timer->HighResState == ETIMER_HR_NEAR) return FALSE;
    if (Timer->HighResState == ETIMER_HR_FAR) KeCancelTimer(&Timer->HighResPreTimer);
    Timer->HighResState = ETIMER_HR_NEAR;

    /*
     * The first one always updates: ExpHighResHeld may still read TRUE while the worker is
     * dropping the rate because it saw no near timer a moment ago.
     */
    return (InterlockedIncrement(&ExpHighResNearCount) == 1) || !ExpHighResHeld;
}

/* The timer no longer needs the fast clock (expired, cancelled, deleted). Timer lock held. */
static
VOID
ExpHighResSetIdle(IN PETIMER Timer)
{
    if (Timer->HighResState == ETIMER_HR_FAR)
    {
        KeCancelTimer(&Timer->HighResPreTimer);
    }
    else if (Timer->HighResState == ETIMER_HR_NEAR)
    {
        /* The last one: drop the rate after EXP_HR_LINGER unless another one comes */
        if (!InterlockedDecrement(&ExpHighResNearCount))
        {
            LARGE_INTEGER Linger;

            Linger.QuadPart = EXP_HR_LINGER;
            KeSetTimer(&ExpHighResLingerTimer, Linger, &ExpHighResLingerDpc);
        }
    }
    Timer->HighResState = ETIMER_HR_IDLE;
}

/* A high resolution timer was just set. Timer lock held. Returns TRUE as ExpHighResSetNear. */
static
BOOLEAN
ExpHighResArm(IN PETIMER Timer,
              IN LARGE_INTEGER DueTime,
              IN LONG Period)
{
    LONGLONG Window = ExpHighResWindow();
    LONGLONG Remaining;
    LARGE_INTEGER Now, PreDueTime;

    if (!(Timer->Flags & ETIMER_HIGH_RESOLUTION)) return FALSE;

    /* Negative: relative interval. Otherwise: absolute system time. */
    if (DueTime.QuadPart < 0)
    {
        Remaining = -DueTime.QuadPart;
    }
    else
    {
        KeQuerySystemTime(&Now);
        Remaining = DueTime.QuadPart - Now.QuadPart;
    }

    /* Periodic timers keep the fast clock as long as they are set */
    if ((Period != 0) || (Remaining <= Window)) return ExpHighResSetNear(Timer);

    /* Due later: come back ExpHighResWindow before the due time */
    ExpHighResSetIdle(Timer);
    if (DueTime.QuadPart < 0)
        PreDueTime.QuadPart = DueTime.QuadPart + Window;
    else
        PreDueTime.QuadPart = DueTime.QuadPart - Window;
    Timer->HighResState = ETIMER_HR_FAR;
    KeSetTimer(&Timer->HighResPreTimer, PreDueTime, &Timer->HighResPreDpc);
    return FALSE;
}

_Function_class_(KDEFERRED_ROUTINE)
static
VOID
NTAPI
ExpHighResPreDpcRoutine(IN PKDPC Dpc,
                        IN PVOID DeferredContext,
                        IN PVOID SystemArgument1,
                        IN PVOID SystemArgument2)
{
    PETIMER Timer = DeferredContext;
    BOOLEAN Update = FALSE;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    /*
     * No reference is taken: ExpDeleteTimer cancels the pre-timer and flushes the DPCs before
     * the object goes away. A pre-timer that has been set again since it expired is inserted.
     */
    KeAcquireSpinLockAtDpcLevel(&Timer->Lock);
    if ((Timer->HighResState == ETIMER_HR_FAR) && !Timer->HighResPreTimer.Header.Inserted)
    {
        Update = ExpHighResSetNear(Timer);
    }
    KeReleaseSpinLockFromDpcLevel(&Timer->Lock);

    if (Update) ExpHighResQueueUpdate();
}

static
VOID
ExpInitializeTimerObject(IN PETIMER Timer,
                         IN TIMER_TYPE TimerType,
                         IN UCHAR Flags)
{
    /* Initialize the DPC */
    KeInitializeDpc(&Timer->TimerDpc, ExpTimerDpcRoutine, Timer);

    /* Initialize the Kernel Timer */
    KeInitializeTimerEx(&Timer->KeTimer, TimerType);

    /* Initialize the timer fields */
    KeInitializeSpinLock(&Timer->Lock);
    Timer->ApcAssociated = FALSE;
    Timer->WakeTimer = FALSE;
    Timer->WakeTimerListEntry.Flink = NULL;
    Timer->Period = 0;

    /* High resolution state */
    Timer->Flags = Flags;
    Timer->HighResState = ETIMER_HR_IDLE;
    KeInitializeTimer(&Timer->HighResPreTimer);
    KeInitializeDpc(&Timer->HighResPreDpc, ExpHighResPreDpcRoutine, Timer);
}

/* Reference a Timer or an IRTimer object */
static
NTSTATUS
ExpReferenceTimerByHandle(IN HANDLE TimerHandle,
                          IN ACCESS_MASK DesiredAccess,
                          IN KPROCESSOR_MODE PreviousMode,
                          OUT PETIMER *Timer)
{
    NTSTATUS Status;

    Status = ObReferenceObjectByHandle(TimerHandle,
                                       DesiredAccess,
                                       ExTimerType,
                                       PreviousMode,
                                       (PVOID*)Timer,
                                       NULL);
    if (Status == STATUS_OBJECT_TYPE_MISMATCH)
    {
        Status = ObReferenceObjectByHandle(TimerHandle,
                                           DesiredAccess,
                                           ExpIRTimerType,
                                           PreviousMode,
                                           (PVOID*)Timer,
                                           NULL);
    }
    return Status;
}

/*
 * SetWaitableTimerEx / NtSetTimerEx tolerable delay: the timer may expire up to TolerableDelay ms
 * late. With a delay of at least twice a grid step, a relative due time is moved up to the next
 * multiple of that step of the interrupt time, so timers with a tolerance expire together (as
 * Windows coalesces them). It never expires earlier than asked, nor more than half the tolerance
 * later. Absolute due times are left alone.
 */
static
LARGE_INTEGER
ExpCoalesceDueTime(IN LARGE_INTEGER DueTime,
                   IN ULONG TolerableDelay)
{
    static const ULONG GridMs[] = { 1000, 500, 250, 100 };
    ULONGLONG Now, Expiry, Step;
    ULONG i;

    if (DueTime.QuadPart >= 0) return DueTime;

    for (i = 0; i < RTL_NUMBER_OF(GridMs); i++)
    {
        if (TolerableDelay / 2 >= GridMs[i])
        {
            Now = KeQueryInterruptTime();
            Expiry = Now + (ULONGLONG)(-DueTime.QuadPart);
            Step = (ULONGLONG)GridMs[i] * 10000;
            Expiry = ((Expiry + Step - 1) / Step) * Step;
            DueTime.QuadPart = -(LONGLONG)(Expiry - Now);
            break;
        }
    }
    return DueTime;
}

VOID
NTAPI
ExTimerRundown(VOID)
{
    PETHREAD Thread = PsGetCurrentThread();
    KIRQL OldIrql;
    PLIST_ENTRY CurrentEntry;
    PETIMER Timer;
    ULONG DerefsToDo;

    /* Lock the Thread's Active Timer List and loop it */
    KeAcquireSpinLock(&Thread->ActiveTimerListLock, &OldIrql);
    CurrentEntry = Thread->ActiveTimerListHead.Flink;
    while (CurrentEntry != &Thread->ActiveTimerListHead)
    {
        /* Get the timer */
        Timer = CONTAINING_RECORD(CurrentEntry, ETIMER, ActiveTimerListEntry);

        /* Reference it */
        ObReferenceObject(Timer);
        DerefsToDo = 1;

        /* Unlock the list */
        KeReleaseSpinLock(&Thread->ActiveTimerListLock, OldIrql);

        /* Lock the Timer */
        KeAcquireSpinLock(&Timer->Lock, &OldIrql);

        /* Lock the list again */
        KeAcquireSpinLockAtDpcLevel(&Thread->ActiveTimerListLock);

        /* Make sure that the timer is valid */
        if ((Timer->ApcAssociated) && (&Thread->Tcb == Timer->TimerApc.Thread))
        {
            /* Remove it from the list */
            RemoveEntryList(&Timer->ActiveTimerListEntry);
            Timer->ApcAssociated = FALSE;

            /* Cancel the timer and remove its DPC and APC */
            KeCancelTimer(&Timer->KeTimer);
            KeRemoveQueueDpc(&Timer->TimerDpc);
            if (KeRemoveQueueApc(&Timer->TimerApc)) DerefsToDo++;

            /* Add another dereference to do */
            DerefsToDo++;
        }

        /* Unlock the list */
        KeReleaseSpinLockFromDpcLevel(&Thread->ActiveTimerListLock);

        /* Unlock the Timer */
        KeReleaseSpinLock(&Timer->Lock, OldIrql);

        /* Dereference it */
        ObDereferenceObjectEx(Timer, DerefsToDo);

        /* Loop again */
        KeAcquireSpinLock(&Thread->ActiveTimerListLock, &OldIrql);
        CurrentEntry = Thread->ActiveTimerListHead.Flink;
    }

    /* Release lock and return */
    KeReleaseSpinLock(&Thread->ActiveTimerListLock, OldIrql);
}

VOID
NTAPI
ExpDeleteTimer(IN PVOID ObjectBody)
{
    KIRQL OldIrql;
    PETIMER Timer = ObjectBody;

    /* Check if it has a Wait List */
    if (Timer->WakeTimerListEntry.Flink)
    {
        /* Lock the Wake List */
        KeAcquireSpinLock(&ExpWakeListLock, &OldIrql);

        /* Check again, since it might've changed before we locked */
        if (Timer->WakeTimerListEntry.Flink)
        {
            /* Remove it from the Wait List */
            RemoveEntryList(&Timer->WakeTimerListEntry);
            Timer->WakeTimerListEntry.Flink = NULL;
        }

        /* Release the Wake List */
        KeReleaseSpinLock(&ExpWakeListLock, OldIrql);
    }

    /* Tell the Kernel to cancel the Timer and flush all queued DPCs */
    KeCancelTimer(&Timer->KeTimer);
    KeCancelTimer(&Timer->HighResPreTimer);
    KeFlushQueuedDpcs();

    /* A high resolution timer that was still due no longer needs the fast clock */
    KeAcquireSpinLock(&Timer->Lock, &OldIrql);
    ExpHighResSetIdle(Timer);
    KeReleaseSpinLock(&Timer->Lock, OldIrql);
}

_Function_class_(KDEFERRED_ROUTINE)
VOID
NTAPI
ExpTimerDpcRoutine(IN PKDPC Dpc,
                   IN PVOID DeferredContext,
                   IN PVOID SystemArgument1,
                   IN PVOID SystemArgument2)
{
    PETIMER Timer = DeferredContext;
    BOOLEAN Inserted = FALSE;

    /* Reference the timer */
    if (!ObReferenceObjectSafe(Timer)) return;

    /* Lock the Timer */
    KeAcquireSpinLockAtDpcLevel(&Timer->Lock);

    /* A one-shot high resolution timer that expired (and was not set again) is done */
    if ((Timer->HighResState == ETIMER_HR_NEAR) && !Timer->Period &&
        !Timer->KeTimer.Header.Inserted)
    {
        ExpHighResSetIdle(Timer);
    }

    /* Check if the timer is associated */
    if (Timer->ApcAssociated)
    {
        /* Queue the APC */
        Inserted = KeInsertQueueApc(&Timer->TimerApc,
                                    SystemArgument1,
                                    SystemArgument2,
                                    IO_NO_INCREMENT);
    }

    /* Release the Timer */
    KeReleaseSpinLockFromDpcLevel(&Timer->Lock);

    /* Dereference it if we couldn't queue the APC */
    if (!Inserted) ObDereferenceObject(Timer);
}

VOID
NTAPI
ExpTimerApcKernelRoutine(IN PKAPC Apc,
                         IN OUT PKNORMAL_ROUTINE* NormalRoutine,
                         IN OUT PVOID* NormalContext,
                         IN OUT PVOID* SystemArgument1,
                         IN OUT PVOID* SystemArguemnt2)
{
    PETIMER Timer;
    KIRQL OldIrql;
    ULONG DerefsToDo = 1;
    PETHREAD Thread = PsGetCurrentThread();

    /* We need to find out which Timer we are */
    Timer = CONTAINING_RECORD(Apc, ETIMER, TimerApc);

    /* Lock the Timer */
    KeAcquireSpinLock(&Timer->Lock, &OldIrql);

    /* Lock the Thread's Active Timer List*/
    KeAcquireSpinLockAtDpcLevel(&Thread->ActiveTimerListLock);

    /* Make sure that the Timer is valid, and that it belongs to this thread */
    if ((Timer->ApcAssociated) && (&Thread->Tcb == Timer->TimerApc.Thread))
    {
        /* Check if it's not periodic */
        if (!Timer->Period)
        {
            /* Remove it from the Active Timers List */
            RemoveEntryList(&Timer->ActiveTimerListEntry);

            /* Disable it */
            Timer->ApcAssociated = FALSE;
            DerefsToDo++;
        }
    }
    else
    {
        /* Clear the normal routine */
        *NormalRoutine = NULL;
    }

    /* Release locks */
    KeReleaseSpinLockFromDpcLevel(&Thread->ActiveTimerListLock);
    KeReleaseSpinLock(&Timer->Lock, OldIrql);

    /* Dereference as needed */
    ObDereferenceObjectEx(Timer, DerefsToDo);
}

CODE_SEG("INIT")
BOOLEAN
NTAPI
ExpInitializeTimerImplementation(VOID)
{
    OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
    UNICODE_STRING Name;
    NTSTATUS Status;

    /* Create the Timer Object Type */
    RtlZeroMemory(&ObjectTypeInitializer, sizeof(ObjectTypeInitializer));
    RtlInitUnicodeString(&Name, L"Timer");
    ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
    ObjectTypeInitializer.InvalidAttributes = OBJ_OPENLINK;
    ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(ETIMER);
    ObjectTypeInitializer.GenericMapping = ExpTimerMapping;
    ObjectTypeInitializer.PoolType = NonPagedPool;
    ObjectTypeInitializer.ValidAccessMask = TIMER_ALL_ACCESS;
    ObjectTypeInitializer.DeleteProcedure = ExpDeleteTimer;
    Status = ObCreateObjectType(&Name, &ObjectTypeInitializer, NULL, &ExTimerType);
    if (!NT_SUCCESS(Status)) return FALSE;

    /* NtCreateTimer2 timers: the same object body, unnamed, a type of their own */
    RtlInitUnicodeString(&Name, L"IRTimer");
    Status = ObCreateObjectType(&Name, &ObjectTypeInitializer, NULL, &ExpIRTimerType);
    if (!NT_SUCCESS(Status)) return FALSE;

    /* Initialize the Wait List and Lock */
    KeInitializeSpinLock(&ExpWakeListLock);
    InitializeListHead(&ExpWakeList);

    /* High resolution timer support */
    KeInitializeTimer(&ExpHighResLingerTimer);
    KeInitializeDpc(&ExpHighResLingerDpc, ExpHighResLingerDpcRoutine, NULL);
    ExInitializeWorkItem(&ExpHighResWorkItem, ExpHighResWorker, NULL);
    return TRUE;
}

/* Cancel a referenced timer and return its signal state */
static
BOOLEAN
ExpCancelTimer(IN PETIMER Timer)
{
    KIRQL OldIrql;
    PETHREAD TimerThread;
    ULONG DerefsToDo = 0;
    BOOLEAN State;

    /* Lock the Timer */
    KeAcquireSpinLock(&Timer->Lock, &OldIrql);

    /* Check if it's enabled */
    if (Timer->ApcAssociated)
    {
        /* Get the Thread. */
        TimerThread = CONTAINING_RECORD(Timer->TimerApc.Thread,
                                        ETHREAD,
                                        Tcb);

        /* Lock its active list */
        KeAcquireSpinLockAtDpcLevel(&TimerThread->ActiveTimerListLock);

        /* Remove it */
        RemoveEntryList(&Timer->ActiveTimerListEntry);
        Timer->ApcAssociated = FALSE;

        /* Unlock the list */
        KeReleaseSpinLockFromDpcLevel(&TimerThread->ActiveTimerListLock);

        /* Cancel the Timer */
        KeCancelTimer(&Timer->KeTimer);
        KeRemoveQueueDpc(&Timer->TimerDpc);
        if (KeRemoveQueueApc(&Timer->TimerApc)) DerefsToDo++;
        DerefsToDo++;
    }
    else
    {
        /* If timer was disabled, we still need to cancel it */
        KeCancelTimer(&Timer->KeTimer);
    }

    /* A high resolution timer no longer needs the fast clock */
    ExpHighResSetIdle(Timer);

    /* Handle a Wake Timer */
    if (Timer->WakeTimerListEntry.Flink)
    {
        /* Lock the Wake List */
        KeAcquireSpinLockAtDpcLevel(&ExpWakeListLock);

        /* Check again, since it might've changed before we locked */
        if (Timer->WakeTimerListEntry.Flink)
        {
            /* Remove it from the Wait List */
            RemoveEntryList(&Timer->WakeTimerListEntry);
            Timer->WakeTimerListEntry.Flink = NULL;
        }

        /* Release the Wake List */
        KeReleaseSpinLockFromDpcLevel(&ExpWakeListLock);
    }

    /* Unlock the Timer */
    KeReleaseSpinLock(&Timer->Lock, OldIrql);

    /* Read the old State */
    State = KeReadStateTimer(&Timer->KeTimer);

    /* Dereference what the APC held */
    if (DerefsToDo) ObDereferenceObjectEx(Timer, DerefsToDo);
    return State;
}

/* Set a referenced timer (the caller keeps its reference) and return its previous signal state */
static
BOOLEAN
ExpSetTimer(IN PETIMER Timer,
            IN LARGE_INTEGER TimerDueTime,
            IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
            IN PVOID TimerContext OPTIONAL,
            IN BOOLEAN WakeTimer,
            IN LONG Period,
            IN KPROCESSOR_MODE PreviousMode)
{
    KIRQL OldIrql;
    BOOLEAN State, HighResUpdate;
    PETHREAD Thread = PsGetCurrentThread();
    PETHREAD TimerThread;
    ULONG DerefsToDo = 0;

    /* Lock the Timer */
    KeAcquireSpinLock(&Timer->Lock, &OldIrql);

    /* Cancel Running Timer */
    if (Timer->ApcAssociated)
    {
        /* Get the Thread. */
        TimerThread = CONTAINING_RECORD(Timer->TimerApc.Thread,
                                        ETHREAD,
                                        Tcb);

        /* Lock its active list */
        KeAcquireSpinLockAtDpcLevel(&TimerThread->ActiveTimerListLock);

        /* Remove it */
        RemoveEntryList(&Timer->ActiveTimerListEntry);
        Timer->ApcAssociated = FALSE;

        /* Unlock the list */
        KeReleaseSpinLockFromDpcLevel(&TimerThread->ActiveTimerListLock);

        /* Cancel the Timer */
        KeCancelTimer(&Timer->KeTimer);
        KeRemoveQueueDpc(&Timer->TimerDpc);
        if (KeRemoveQueueApc(&Timer->TimerApc)) DerefsToDo++;
        DerefsToDo++;
    }
    else
    {
        /* If timer was disabled, we still need to cancel it */
        KeCancelTimer(&Timer->KeTimer);
    }

    /* Read the State */
    State = KeReadStateTimer(&Timer->KeTimer);

    /* Handle Wake Timers */
    Timer->WakeTimer = WakeTimer;
    KeAcquireSpinLockAtDpcLevel(&ExpWakeListLock);
    if ((WakeTimer) && !(Timer->WakeTimerListEntry.Flink))
    {
        /* Insert it into the list */
        InsertTailList(&ExpWakeList, &Timer->WakeTimerListEntry);
    }
    else if (!(WakeTimer) && (Timer->WakeTimerListEntry.Flink))
    {
        /* Remove it from the list */
        RemoveEntryList(&Timer->WakeTimerListEntry);
        Timer->WakeTimerListEntry.Flink = NULL;
    }
    KeReleaseSpinLockFromDpcLevel(&ExpWakeListLock);

    /* Set up the APC Routine if specified */
    Timer->Period = Period;
    if (TimerApcRoutine)
    {
        /* Initialize the APC */
        KeInitializeApc(&Timer->TimerApc,
                        &Thread->Tcb,
                        CurrentApcEnvironment,
                        ExpTimerApcKernelRoutine,
                        (PKRUNDOWN_ROUTINE)NULL,
                        (PKNORMAL_ROUTINE)TimerApcRoutine,
                        PreviousMode,
                        TimerContext);

        /* Lock the Thread's Active List and Insert */
        KeAcquireSpinLockAtDpcLevel(&Thread->ActiveTimerListLock);
        InsertTailList(&Thread->ActiveTimerListHead,
                       &Timer->ActiveTimerListEntry);
        Timer->ApcAssociated = TRUE;
        KeReleaseSpinLockFromDpcLevel(&Thread->ActiveTimerListLock);

        /* The APC holds the caller's reference now */
        ObReferenceObject(Timer);
    }

    /*
     * Enable and Set the Timer. A high resolution timer always gets the DPC: it tells when a
     * one-shot timer has expired and no longer needs the fast clock.
     */
    KeSetTimerEx(&Timer->KeTimer,
                 TimerDueTime,
                 Period,
                 (TimerApcRoutine || (Timer->Flags & ETIMER_HIGH_RESOLUTION)) ?
                 &Timer->TimerDpc : NULL);
    HighResUpdate = ExpHighResArm(Timer, TimerDueTime, Period);

    /* Unlock the Timer */
    KeReleaseSpinLock(&Timer->Lock, OldIrql);

    /* Dereference if it was previously enabled */
    if (DerefsToDo) ObDereferenceObjectEx(Timer, DerefsToDo);

    /* Raise the clock rate now; the timer may be due within a few clock ticks */
    if (HighResUpdate) ExpHighResUpdate();

    return State;
}

/* PUBLIC FUNCTIONS **********************************************************/

NTSTATUS
NTAPI
NtCancelTimer(IN HANDLE TimerHandle,
              OUT PBOOLEAN CurrentState OPTIONAL)
{
    PETIMER Timer;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    BOOLEAN State;
    NTSTATUS Status;
    PAGED_CODE();

    /* Check if we need to probe */
    if ((CurrentState) && (PreviousMode != KernelMode))
    {
        _SEH2_TRY
        {
            /* Make sure the pointer is valid */
            ProbeForWriteBoolean(CurrentState);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Get the Timer Object */
    Status = ExpReferenceTimerByHandle(TimerHandle,
                                       TIMER_MODIFY_STATE,
                                       PreviousMode,
                                       &Timer);
    if (NT_SUCCESS(Status))
    {
        /* NtCreateTimer2 timers do not report their state (Windows 10: invalid parameter) */
        if ((CurrentState) && (OBJECT_TO_OBJECT_HEADER(Timer)->Type == ExpIRTimerType))
        {
            ObDereferenceObject(Timer);
            return STATUS_INVALID_PARAMETER;
        }

        /* Cancel it */
        State = ExpCancelTimer(Timer);

        /* Dereference the Object */
        ObDereferenceObject(Timer);

        /* Check if caller wants the state */
        if (CurrentState)
        {
            _SEH2_TRY
            {
                /* Return the Timer State */
                *CurrentState = State;
            }
            _SEH2_EXCEPT(ExSystemExceptionFilter())
            {
                /* Do nothing */
                (void)0;
            }
            _SEH2_END;
        }
    }

    /* Return to Caller */
    return Status;
}

NTSTATUS
NTAPI
NtCancelTimer2(IN HANDLE TimerHandle,
               IN PT2_CANCEL_PARAMETERS Parameters)
{
    PETIMER Timer;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    PAGED_CODE();

    /* The parameter block has no defined contents; Windows 10 accepts NULL and any pointer */
    UNREFERENCED_PARAMETER(Parameters);

    /* Only timers made by NtCreateTimer2 (a Timer is STATUS_OBJECT_TYPE_MISMATCH) */
    Status = ObReferenceObjectByHandle(TimerHandle,
                                       TIMER_MODIFY_STATE,
                                       ExpIRTimerType,
                                       PreviousMode,
                                       (PVOID*)&Timer,
                                       NULL);
    if (NT_SUCCESS(Status))
    {
        ExpCancelTimer(Timer);
        ObDereferenceObject(Timer);
    }

    return Status;
}

NTSTATUS
NTAPI
NtCreateTimer(OUT PHANDLE TimerHandle,
              IN ACCESS_MASK DesiredAccess,
              IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
              IN TIMER_TYPE TimerType)
{
    PETIMER Timer;
    HANDLE hTimer;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    PAGED_CODE();

    /* Check for correct timer type */
    if ((TimerType != NotificationTimer) &&
        (TimerType != SynchronizationTimer))
    {
        /* Fail */
        return STATUS_INVALID_PARAMETER_4;
    }

    /* Check if we need to probe */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            /* Make sure the pointer is valid */
            ProbeForWriteHandle(TimerHandle);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Create the Object */
    Status = ObCreateObject(PreviousMode,
                            ExTimerType,
                            ObjectAttributes,
                            PreviousMode,
                            NULL,
                            sizeof(ETIMER),
                            0,
                            0,
                            (PVOID*)&Timer);
    if (NT_SUCCESS(Status))
    {
        /* Initialize the timer */
        ExpInitializeTimerObject(Timer, TimerType, 0);

        /* Insert the Timer */
        Status = ObInsertObject((PVOID)Timer,
                                NULL,
                                DesiredAccess,
                                0,
                                NULL,
                                &hTimer);

        /* Check for success */
        if (NT_SUCCESS(Status))
        {
            /* Enter SEH */
            _SEH2_TRY
            {
                /* Return the Timer Handle */
                *TimerHandle = hTimer;
            }
            _SEH2_EXCEPT(ExSystemExceptionFilter())
            {
                /* Do nothing */
                (void)0;
            }
            _SEH2_END;
        }
    }

    /* Return to Caller */
    return Status;
}

/*
 * Windows 10 (1803+) timer creation, behind CreateWaitableTimerExW with
 * CREATE_WAITABLE_TIMER_HIGH_RESOLUTION. Measured on Windows 10 22H2 (x64 and WOW64):
 * - Attributes: TIMER2_ATTRIBUTE_NOTIFICATION (else a synchronization timer),
 *   TIMER2_ATTRIBUTE_HIGH_RESOLUTION, TIMER2_ATTRIBUTE_NO_WAKE. Unknown bits, and NO_WAKE with
 *   HIGH_RESOLUTION or 0x2, are STATUS_INVALID_PARAMETER_4; 0x2 on its own (or with
 *   HIGH_RESOLUTION / NOTIFICATION) is STATUS_INVALID_PARAMETER, checked after the object
 *   attributes.
 * - Any object attributes (a name, OBJ_INHERIT, a security descriptor, even all zero) are
 *   STATUS_INVALID_PARAMETER_3: these timers are unnamed and not inheritable.
 * - A non-NULL Reserved is STATUS_INVALID_PARAMETER_2.
 * - The object type is IRTimer; the handle has the access asked for (MAXIMUM_ALLOWED: all).
 */
NTSTATUS
NTAPI
NtCreateTimer2(OUT PHANDLE TimerHandle,
               IN PVOID Reserved OPTIONAL,
               IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
               IN ULONG Attributes,
               IN ACCESS_MASK DesiredAccess)
{
    PETIMER Timer;
    HANDLE hTimer;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    PAGED_CODE();

    if (Reserved) return STATUS_INVALID_PARAMETER_2;

    if ((Attributes & ~EXP_TIMER2_VALID_ATTRIBUTES) ||
        ((Attributes & TIMER2_ATTRIBUTE_NO_WAKE) &&
         (Attributes & (TIMER2_ATTRIBUTE_HIGH_RESOLUTION | EXP_TIMER2_ATTRIBUTE_REFUSED))))
    {
        return STATUS_INVALID_PARAMETER_4;
    }

    if (ObjectAttributes) return STATUS_INVALID_PARAMETER_3;

    if (Attributes & EXP_TIMER2_ATTRIBUTE_REFUSED) return STATUS_INVALID_PARAMETER;

    /* Check if we need to probe */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            /* Make sure the pointer is valid */
            ProbeForWriteHandle(TimerHandle);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Create the Object */
    Status = ObCreateObject(PreviousMode,
                            ExpIRTimerType,
                            NULL,
                            PreviousMode,
                            NULL,
                            sizeof(ETIMER),
                            0,
                            0,
                            (PVOID*)&Timer);
    if (!NT_SUCCESS(Status)) return Status;

    /* No-wake has no meaning here: wake timers are not supported */
    ExpInitializeTimerObject(Timer,
                             (Attributes & TIMER2_ATTRIBUTE_NOTIFICATION) ?
                             NotificationTimer : SynchronizationTimer,
                             (Attributes & TIMER2_ATTRIBUTE_HIGH_RESOLUTION) ?
                             ETIMER_HIGH_RESOLUTION : 0);

    /* Insert the Timer */
    Status = ObInsertObject((PVOID)Timer,
                            NULL,
                            DesiredAccess,
                            0,
                            NULL,
                            &hTimer);
    if (NT_SUCCESS(Status))
    {
        _SEH2_TRY
        {
            /* Return the Timer Handle */
            *TimerHandle = hTimer;
        }
        _SEH2_EXCEPT(ExSystemExceptionFilter())
        {
            /* Do nothing */
            (void)0;
        }
        _SEH2_END;
    }

    return Status;
}
NTSTATUS
NTAPI
NtOpenTimer(OUT PHANDLE TimerHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes)
{
    HANDLE hTimer;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    PAGED_CODE();

    /* Check Parameter Validity */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            /* Make sure the pointer is valid */
            ProbeForWriteHandle(TimerHandle);
        }
        _SEH2_EXCEPT(ExSystemExceptionFilter())
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Open the Timer */
    Status = ObOpenObjectByName(ObjectAttributes,
                                ExTimerType,
                                PreviousMode,
                                NULL,
                                DesiredAccess,
                                NULL,
                                &hTimer);
    if (NT_SUCCESS(Status))
    {
        /* Enter SEH */
        _SEH2_TRY
        {
            /* Return the Timer Handle */
            *TimerHandle = hTimer;
        }
        _SEH2_EXCEPT(ExSystemExceptionFilter())
        {
            /* Do nothing */
            (void)0;
        }
        _SEH2_END;
    }

    /* Return to Caller */
    return Status;
}

NTSTATUS
NTAPI
NtQueryTimer(IN HANDLE TimerHandle,
             IN TIMER_INFORMATION_CLASS TimerInformationClass,
             OUT PVOID TimerInformation,
             IN ULONG TimerInformationLength,
             OUT PULONG ReturnLength OPTIONAL)
{
    PETIMER Timer;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    PTIMER_BASIC_INFORMATION BasicInfo = TimerInformation;
    PAGED_CODE();

    /* Check Validity */
    Status = DefaultQueryInfoBufferCheck(TimerInformationClass,
                                         ExTimerInfoClass,
                                         sizeof(ExTimerInfoClass) /
                                         sizeof(ExTimerInfoClass[0]),
                                         ICIF_PROBE_READ_WRITE,
                                         TimerInformation,
                                         TimerInformationLength,
                                         ReturnLength,
                                         NULL,
                                         PreviousMode);
    if (!NT_SUCCESS(Status)) return Status;

    /* Get the Timer Object */
    Status = ObReferenceObjectByHandle(TimerHandle,
                                       TIMER_QUERY_STATE,
                                       ExTimerType,
                                       PreviousMode,
                                       (PVOID*)&Timer,
                                       NULL);
    if (NT_SUCCESS(Status))
    {
        /* Return the Basic Information */
        _SEH2_TRY
        {
            /* Return the remaining time, corrected */
            BasicInfo->TimeRemaining.QuadPart = Timer->
                                                KeTimer.DueTime.QuadPart -
                                                KeQueryInterruptTime();

            /* Return the current state */
            BasicInfo->SignalState = KeReadStateTimer(&Timer->KeTimer);

            /* Return the buffer length if requested */
            if (ReturnLength) *ReturnLength = sizeof(TIMER_BASIC_INFORMATION);
        }
        _SEH2_EXCEPT(ExSystemExceptionFilter())
        {
            /* Get the exception code */
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;

        /* Dereference Object */
        ObDereferenceObject(Timer);
    }

    /* Return Status */
    return Status;
}


NTSTATUS
NTAPI
NtSetTimer(IN HANDLE TimerHandle,
           IN PLARGE_INTEGER DueTime,
           IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
           IN PVOID TimerContext OPTIONAL,
           IN BOOLEAN WakeTimer,
           IN LONG Period OPTIONAL,
           OUT PBOOLEAN PreviousState OPTIONAL)
{
    PETIMER Timer;
    BOOLEAN State;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    LARGE_INTEGER TimerDueTime;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();

    /* Check for a valid Period */
    if (Period < 0) return STATUS_INVALID_PARAMETER_6;

    /* Check if we need to probe */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            /* Probe and capture the due time */
            TimerDueTime = ProbeForReadLargeInteger(DueTime);

            /* Probe the state pointer if one was passed */
            if (PreviousState) ProbeForWriteBoolean(PreviousState);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        /* Capture the time directly */
        TimerDueTime = *DueTime;
    }

    /* Get the Timer Object */
    Status = ExpReferenceTimerByHandle(TimerHandle,
                                       TIMER_MODIFY_STATE,
                                       PreviousMode,
                                       &Timer);
    if (!NT_SUCCESS(Status)) return Status;

    /*
     * NtCreateTimer2 timers can be set here too (kernel32's SetWaitableTimer does it), but
     * without an APC, a wake request or the previous state (Windows 10: invalid parameter)
     */
    if ((OBJECT_TO_OBJECT_HEADER(Timer)->Type == ExpIRTimerType) &&
        (TimerApcRoutine || WakeTimer || PreviousState))
    {
        ObDereferenceObject(Timer);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Tell the user we don't support Wake Timers...
     * when we have the ability to use/detect the Power Management
     * functionality required to support them, make this check dependent
     * on the actual PM capabilities
     */
    if (WakeTimer)
    {
        Status = STATUS_TIMER_RESUME_IGNORED;
    }

    /* Set it */
    State = ExpSetTimer(Timer,
                        TimerDueTime,
                        TimerApcRoutine,
                        TimerContext,
                        WakeTimer,
                        Period,
                        PreviousMode);
    ObDereferenceObject(Timer);

    /* Check if we need to return the State */
    if (PreviousState)
    {
        /* Enter SEH */
        _SEH2_TRY
        {
            /* Return the Timer State */
            *PreviousState = State;
        }
        _SEH2_EXCEPT(ExSystemExceptionFilter())
        {
            /* Do nothing */
            (void)0;
        }
        _SEH2_END;
    }

    /* Return to Caller */
    return Status;
}

/*
 * Windows 7 timer set with a tolerable delay (SetWaitableTimerEx). Measured on Windows 10 22H2:
 * an unknown class is STATUS_INVALID_INFO_CLASS, a length other than the structure's is
 * STATUS_INFO_LENGTH_MISMATCH, a period above MAXLONG is STATUS_INVALID_PARAMETER_3; on an
 * NtCreateTimer2 timer a tolerable delay, a previous-state pointer (or an APC) is
 * STATUS_INVALID_PARAMETER. The wake context is not used: wake timers are not supported.
 */
NTSTATUS
NTAPI
NtSetTimerEx(IN HANDLE TimerHandle,
             IN TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
             IN OUT PVOID TimerSetInformation OPTIONAL,
             IN ULONG TimerSetInformationLength)
{
    TIMER_SET_COALESCABLE_TIMER_INFO Info;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PETIMER Timer;
    BOOLEAN State;
    NTSTATUS Status;
    PAGED_CODE();

    if (TimerSetInformationClass != TimerSetCoalescableTimer) return STATUS_INVALID_INFO_CLASS;
    if (TimerSetInformationLength != sizeof(Info)) return STATUS_INFO_LENGTH_MISMATCH;

    /* Capture the parameters */
    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
        {
            ProbeForRead(TimerSetInformation, sizeof(Info), sizeof(ULONG));
        }
        RtlCopyMemory(&Info, TimerSetInformation, sizeof(Info));
        if ((PreviousMode != KernelMode) && Info.PreviousState)
        {
            ProbeForWriteBoolean(Info.PreviousState);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    if (Info.Period > MAXLONG) return STATUS_INVALID_PARAMETER_3;

    Status = ExpReferenceTimerByHandle(TimerHandle,
                                       TIMER_MODIFY_STATE,
                                       PreviousMode,
                                       &Timer);
    if (!NT_SUCCESS(Status)) return Status;

    if ((OBJECT_TO_OBJECT_HEADER(Timer)->Type == ExpIRTimerType) &&
        (Info.TolerableDelay || Info.PreviousState || Info.TimerApcRoutine))
    {
        ObDereferenceObject(Timer);
        return STATUS_INVALID_PARAMETER;
    }

    State = ExpSetTimer(Timer,
                        ExpCoalesceDueTime(Info.DueTime, Info.TolerableDelay),
                        Info.TimerApcRoutine,
                        Info.TimerContext,
                        FALSE,
                        (LONG)Info.Period,
                        PreviousMode);
    ObDereferenceObject(Timer);

    if (Info.PreviousState)
    {
        _SEH2_TRY
        {
            *Info.PreviousState = State;
        }
        _SEH2_EXCEPT(ExSystemExceptionFilter())
        {
            /* Do nothing */
            (void)0;
        }
        _SEH2_END;
    }

    return STATUS_SUCCESS;
}

/*
 * Windows 10 timer set, for NtCreateTimer2 timers only (a Timer is STATUS_OBJECT_TYPE_MISMATCH).
 * Measured on Windows 10 22H2: Parameters->Version other than 0 is STATUS_INVALID_PARAMETER_3;
 * Reserved and NoWakeTolerance are not checked. DueTime as NtSetTimer (0 or a past absolute
 * time: signaled at once). Period is in 100 ns units: NULL or 0 is a one-shot timer, anything
 * else (also negative) is a periodic timer of at least 0.5 ms. Here periods are kept in whole
 * milliseconds (KTIMER): rounded to the nearest, at least 1 ms.
 */
NTSTATUS
NTAPI
NtSetTimer2(IN HANDLE TimerHandle,
            IN PLARGE_INTEGER DueTime,
            IN PLARGE_INTEGER Period OPTIONAL,
            IN PT2_SET_PARAMETERS Parameters)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    LARGE_INTEGER TimerDueTime, TimerPeriod;
    T2_SET_PARAMETERS SetParameters;
    LONGLONG PeriodMs;
    PETIMER Timer;
    NTSTATUS Status;
    PAGED_CODE();

    TimerPeriod.QuadPart = 0;
    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
        {
            TimerDueTime = ProbeForReadLargeInteger(DueTime);
            if (Period) TimerPeriod = ProbeForReadLargeInteger(Period);
            ProbeForRead(Parameters, sizeof(SetParameters), sizeof(ULONG));
        }
        else
        {
            TimerDueTime = *DueTime;
            if (Period) TimerPeriod = *Period;
        }
        RtlCopyMemory(&SetParameters, Parameters, sizeof(SetParameters));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    if (SetParameters.Version != 0) return STATUS_INVALID_PARAMETER_3;

    PeriodMs = 0;
    if (TimerPeriod.QuadPart != 0)
    {
        if (TimerPeriod.QuadPart < EXP_TIMER2_MIN_PERIOD) TimerPeriod.QuadPart = EXP_TIMER2_MIN_PERIOD;
        PeriodMs = (TimerPeriod.QuadPart + 5000) / 10000;
        if (PeriodMs > MAXLONG) PeriodMs = MAXLONG;
    }

    Status = ObReferenceObjectByHandle(TimerHandle,
                                       TIMER_MODIFY_STATE,
                                       ExpIRTimerType,
                                       PreviousMode,
                                       (PVOID*)&Timer,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    ExpSetTimer(Timer, TimerDueTime, NULL, NULL, FALSE, (LONG)PeriodMs, PreviousMode);
    ObDereferenceObject(Timer);
    return STATUS_SUCCESS;
}

/* EOF */
