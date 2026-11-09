/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * PURPOSE:           Condition Variable Routines
 * PROGRAMMERS:       Thomas Weidenmueller <w3seek@reactos.com>
 *                    Stephan A. Rüger
 *                    Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* NOTE: A sleeping thread puts a wait entry on its stack into a FIFO list that hangs off the
   condition variable, and gives up the caller's lock only afterwards. It then sleeps on a keyed
   event whose key is an address inside its own entry, so a wake-up is addressed to one thread.

   A waker takes the entries it wants to wake off the list, under the list lock, and marks them as
   claimed. Only then does it release the keyed event for each entry, with no timeout: the release
   returns when that sleeper has arrived at the keyed event, which a sleeper that registered itself
   under the caller's lock does within a few instructions. A wake-up is not lost when the sleeper
   has not arrived yet, which is where the former release with a zero timeout dropped it.

   A sleeper whose wait ended in a timeout cannot tell from the keyed event alone whether a waker
   claimed it in the meantime: the kernel can report the timeout although a release already paired
   with it. It therefore checks its entry under the list lock. An unclaimed entry is taken off the
   list; a claimed one means that a waker has used a wake-up on this thread, which then reports
   success. The waker's last access to an entry is a flag that it sets when its release has
   returned, and a claimed sleeper does not return, and so does not free its entry, before that.

   Wine's condition variables (a count of sleepers in the variable and one key for all of them) were
   considered and not used: a broadcast then releases the key as often as there were sleepers, and
   a thread that sleeps again at once can take a release that belongs to a sleeper that has not
   arrived yet, which leaves that sleeper asleep. */

/* INCLUDES ******************************************************************/

#include <rtl_vista.h>

#define NDEBUG
#include <debug.h>

/* INTERNAL TYPES ************************************************************/

#define COND_VAR_LOCKED_FLAG         ((ULONG_PTR)1)
#define COND_VAR_ADDRESS_MASK        (~COND_VAR_LOCKED_FLAG)

typedef struct _COND_VAR_WAIT_ENTRY
{
    /* ListEntry must have an alignment of at least 16 bits, since the lock flag of the
       condition variable lives in the lowest bit of the address of the first entry. */
    LIST_ENTRY ListEntry;
    /* Set under the list lock, by the waker that takes the entry off the list */
    BOOLEAN Claimed;
    /* The keyed event key of this sleeper */
    LONG WaitKey;
    /* Set by the waker as its last access, after its release of the keyed event has returned */
    volatile LONG ReleaseDone;
} COND_VAR_WAIT_ENTRY, * PCOND_VAR_WAIT_ENTRY;

/* GLOBALS *******************************************************************/

/* Condition variables wait on the system's default keyed event: the NULL handle of NtWaitForKeyedEvent/NtReleaseKeyedEvent, as Windows
   and the critical sections here do.  It needs no per-process object, so a wake or a wait works before RtlpInitializeKeyedEvent ran: a
   program's own code can run inside the loader (hooks on NtMapViewOfSection, TLS callbacks) before ntdll finished initializing.  The
   kernel pairs the two sides by the calling process and the key, so no other process sees these keys. */
#define CondVarKeyedEventHandle ((HANDLE)NULL)

/* INTERNAL FUNCTIONS ********************************************************/

static
VOID
InternalSpinWait(IN OUT PULONG Spins)
{
    LARGE_INTEGER Delay;

    /* The holder of the list lock, or a waker that is about to set a flag, is running unless it
       was preempted: spin, then give the processor away, then sleep so that it can finish. */
    if (*Spins < 128)
    {
        (*Spins)++;
        YieldProcessor();
    }
    else if (*Spins < 192)
    {
        (*Spins)++;
        ZwYieldExecution();
    }
    else
    {
        Delay.QuadPart = -10 * 1000;
        ZwDelayExecution(FALSE, &Delay);
    }
}

/* Takes the list lock and returns the first (oldest) entry, or NULL if the list is empty. The
   list is a ring of entries, linked through ListEntry; the condition variable holds the address
   of the first entry and, in its lowest bit, the lock flag. */
static
PLIST_ENTRY
InternalLockCondVar(IN OUT PRTL_CONDITION_VARIABLE ConditionVariable)
{
    ULONG_PTR OldVal;
    ULONG Spins = 0;

    for (;;)
    {
        OldVal = (ULONG_PTR)ConditionVariable->Ptr;

        if (OldVal & COND_VAR_LOCKED_FLAG)
        {
            InternalSpinWait(&Spins);
            continue;
        }

        if ((ULONG_PTR)InterlockedCompareExchangePointerAcquire(&ConditionVariable->Ptr,
                                                                (PVOID)(OldVal | COND_VAR_LOCKED_FLAG),
                                                                (PVOID)OldVal) == OldVal)
        {
            return (PLIST_ENTRY)(OldVal & COND_VAR_ADDRESS_MASK);
        }
    }
}

/* Drops the list lock; First is the first entry of the list afterwards, or NULL */
FORCEINLINE
VOID
InternalUnlockCondVar(IN OUT PRTL_CONDITION_VARIABLE ConditionVariable,
                      IN PLIST_ENTRY First OPTIONAL)
{
    (void)InterlockedExchangePointer(&ConditionVariable->Ptr, First);
}

/* Takes the first entry off the list (list lock held) and returns the new first entry or NULL */
static
PLIST_ENTRY
InternalRemoveFirst(IN PLIST_ENTRY First)
{
    PLIST_ENTRY NewFirst;

    if (IsListEmpty(First))
        return NULL;

    NewFirst = First->Flink;
    RemoveEntryList(First);
    return NewFirst;
}

static
VOID
InternalWake(IN OUT PRTL_CONDITION_VARIABLE ConditionVariable,
             IN BOOLEAN ReleaseAll)
{
    /* If ReleaseAll is zero on entry, one thread at most will be woken. Otherwise all waiting
       threads are woken. Wakeups happen in FIFO order. */
    PLIST_ENTRY First, Last, Cursor, Next;
    PCOND_VAR_WAIT_ENTRY Entry;
    NTSTATUS Status;

    /* There is noone there to wake up if the list is empty. In this case do nothing and
       return immediately. We don't stockpile wake-ups. */
    if (((ULONG_PTR)ConditionVariable->Ptr & COND_VAR_ADDRESS_MASK) == 0)
        return;

    First = InternalLockCondVar(ConditionVariable);
    if (First == NULL)
    {
        InternalUnlockCondVar(ConditionVariable, NULL);
        return;
    }

    if (!ReleaseAll)
    {
        /* Take the oldest entry and keep the others */
        CONTAINING_RECORD(First, COND_VAR_WAIT_ENTRY, ListEntry)->Claimed = TRUE;
        Cursor = InternalRemoveFirst(First);
        InternalUnlockCondVar(ConditionVariable, Cursor);
        First->Flink = NULL;
    }
    else
    {
        /* Take the whole list and turn the ring into a chain, from the oldest entry to the newest */
        Last = First->Blink;
        for (Cursor = First; ; Cursor = Cursor->Flink)
        {
            CONTAINING_RECORD(Cursor, COND_VAR_WAIT_ENTRY, ListEntry)->Claimed = TRUE;
            if (Cursor == Last)
                break;
        }
        Last->Flink = NULL;
        InternalUnlockCondVar(ConditionVariable, NULL);
    }

    /* The entries are claimed, and belong to this thread until each of them has been released.
       The list lock is not held while this waits for a sleeper to arrive. Entry is not used after
       its release but for the flag, and Next is read before the release, since the entry's thread
       may continue and free it as soon as the flag is set. */
    for (Cursor = First; Cursor != NULL; Cursor = Next)
    {
        Next = Cursor->Flink;
        Entry = CONTAINING_RECORD(Cursor, COND_VAR_WAIT_ENTRY, ListEntry);

        Status = NtReleaseKeyedEvent(CondVarKeyedEventHandle,
                                     &Entry->WaitKey,
                                     FALSE,
                                     NULL);
        ASSERT(STATUS_INVALID_HANDLE != Status);
        UNREFERENCED_PARAMETER(Status);

        (void)InterlockedExchange(&Entry->ReleaseDone, 1);
    }
}

VOID
NTAPI
RtlAcquireSRWLockExclusive(IN OUT PRTL_SRWLOCK SRWLock);
VOID
NTAPI
RtlAcquireSRWLockShared(IN OUT PRTL_SRWLOCK SRWLock);
VOID
NTAPI
RtlReleaseSRWLockExclusive(IN OUT PRTL_SRWLOCK SRWLock);
VOID
NTAPI
RtlReleaseSRWLockShared(IN OUT PRTL_SRWLOCK SRWLock);

static
NTSTATUS
InternalSleep(IN OUT PRTL_CONDITION_VARIABLE ConditionVariable,
              IN OUT PRTL_CRITICAL_SECTION CriticalSection OPTIONAL,
              IN OUT PRTL_SRWLOCK SRWLock OPTIONAL,
              IN ULONG SRWFlags,
              IN const LARGE_INTEGER * TimeOut OPTIONAL)
{
    /* Either CriticalSection or SRWLock must be NULL, but not both.
       These caller provided lock must be held on entry and will be
       held again on return. */

    COND_VAR_WAIT_ENTRY OwnEntry;
    PLIST_ENTRY First;
    LARGE_INTEGER ZeroTimeout;
    NTSTATUS Status;
    ULONG Spins;
    BOOLEAN Claimed;

    ASSERT((CriticalSection == NULL) != (SRWLock == NULL));

    RtlZeroMemory(&OwnEntry, sizeof(OwnEntry));

    /* Put OwnEntry at the end of the list, while the caller's lock is still held: a waker that
       gets that lock after this thread has given it up finds the entry. */
    First = InternalLockCondVar(ConditionVariable);
    if (First == NULL)
    {
        InitializeListHead(&OwnEntry.ListEntry);
        First = &OwnEntry.ListEntry;
    }
    else
    {
        InsertTailList(First, &OwnEntry.ListEntry);
    }
    InternalUnlockCondVar(ConditionVariable, First);

    /* We can now drop the caller provided lock as a preparation for
       going to sleep. */
    if (CriticalSection == NULL)
    {
        if (0 == (RTL_CONDITION_VARIABLE_LOCKMODE_SHARED & SRWFlags))
        {
            RtlReleaseSRWLockExclusive(SRWLock);
        }
        else
        {
            RtlReleaseSRWLockShared(SRWLock);
        }
    }
    else
    {
        RtlLeaveCriticalSection(CriticalSection);
    }

    /* Now sleep using the caller provided timeout. */
    Status = NtWaitForKeyedEvent(CondVarKeyedEventHandle,
                                 &OwnEntry.WaitKey,
                                 FALSE,
                                 (PLARGE_INTEGER)TimeOut);

    ASSERT(STATUS_INVALID_HANDLE != Status);

    Claimed = TRUE;
    if (Status != STATUS_SUCCESS)
    {
        /* The wait timed out, or failed. If no waker has taken the entry yet, take it off the list. */
        First = InternalLockCondVar(ConditionVariable);
        Claimed = OwnEntry.Claimed;
        if (!Claimed)
        {
            ASSERT(First != NULL);
            if (First == &OwnEntry.ListEntry)
                First = InternalRemoveFirst(First);
            else
                RemoveEntryList(&OwnEntry.ListEntry);
        }
        InternalUnlockCondVar(ConditionVariable, First);

        if (Claimed)
        {
            /* A waker has used a wake-up on this thread. Its release is either waiting for this
               thread to arrive, or the kernel has paired it with the wait that just ended in the
               timeout. Only a thread that has not been paired can be released again, so try, and
               stop as soon as the waker reports that its release has returned. */
            ZeroTimeout.QuadPart = 0;
            Spins = 0;
            while (!OwnEntry.ReleaseDone)
            {
                if (NtWaitForKeyedEvent(CondVarKeyedEventHandle,
                                        &OwnEntry.WaitKey,
                                        FALSE,
                                        &ZeroTimeout) == STATUS_SUCCESS)
                {
                    break;
                }
                InternalSpinWait(&Spins);
            }
            Status = STATUS_SUCCESS;
        }
    }

    if (Claimed)
    {
        /* The waker's last access to OwnEntry is the flag, so this entry stays valid until then */
        Spins = 0;
        while (!OwnEntry.ReleaseDone)
            InternalSpinWait(&Spins);
    }

#ifdef _DEBUG
    /* Clear OwnEntry to aid in detecting bugs. */
    RtlZeroMemory(&OwnEntry, sizeof(OwnEntry));
#endif

    /* Reacquire the caller provided lock, as we are about to return. */
    if (CriticalSection == NULL)
    {
        if (0 == (RTL_CONDITION_VARIABLE_LOCKMODE_SHARED & SRWFlags))
        {
            RtlAcquireSRWLockExclusive(SRWLock);
        }
        else
        {
            RtlAcquireSRWLockShared(SRWLock);
        }
    }
    else
    {
        RtlEnterCriticalSection(CriticalSection);
    }

    /* Return whatever NtWaitForKeyedEvent returned, a wake-up that came with the timeout counted */
    return Status;
}

VOID
NTAPI
RtlpInitializeKeyedEvent(VOID)
{
    /* Nothing to create: see CondVarKeyedEventHandle */
}

VOID
NTAPI
RtlpCloseKeyedEvent(VOID)
{
    /* Nothing to close: see CondVarKeyedEventHandle */
}

/* EXPORTED FUNCTIONS ********************************************************/

VOID
NTAPI
RtlInitializeConditionVariable(OUT PRTL_CONDITION_VARIABLE ConditionVariable)
{
    ConditionVariable->Ptr = NULL;
}

VOID
NTAPI
RtlWakeConditionVariable(IN OUT PRTL_CONDITION_VARIABLE ConditionVariable)
{
    InternalWake(ConditionVariable, FALSE);
}

VOID
NTAPI
RtlWakeAllConditionVariable(IN OUT PRTL_CONDITION_VARIABLE ConditionVariable)
{
    InternalWake(ConditionVariable, TRUE);
}

NTSTATUS
NTAPI
RtlSleepConditionVariableCS(IN OUT PRTL_CONDITION_VARIABLE ConditionVariable,
                            IN OUT PRTL_CRITICAL_SECTION CriticalSection,
                            IN PLARGE_INTEGER TimeOut OPTIONAL)
{
    return InternalSleep(ConditionVariable,
                         CriticalSection,
                         (PRTL_SRWLOCK)NULL,
                         0,
                         TimeOut);
}

NTSTATUS
NTAPI
RtlSleepConditionVariableSRW(IN OUT PRTL_CONDITION_VARIABLE ConditionVariable,
                             IN OUT PRTL_SRWLOCK SRWLock,
                             IN PLARGE_INTEGER TimeOut OPTIONAL,
                             IN ULONG Flags)
{
    return InternalSleep(ConditionVariable,
                         (PRTL_CRITICAL_SECTION)NULL,
                         SRWLock,
                         Flags,
                         TimeOut);
}

/* EOF */
