/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ke/spinlock.c
 * PURPOSE:         Spinlock and Queued Spinlock Support
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* PRIVATE FUNCTIONS *********************************************************/

//
// HACK: queued locks (the dispatcher lock included) fall back to acting like
// plain test-and-set spinlocks.
//

_IRQL_requires_min_(DISPATCH_LEVEL)
_Acquires_nonreentrant_lock_(*LockHandle->Lock)
_Acquires_exclusive_lock_(*LockHandle->Lock)
VOID
FASTCALL
KeAcquireQueuedSpinLockAtDpcLevel(_Inout_ PKSPIN_LOCK_QUEUE LockHandle)
{
#if defined(CONFIG_SMP) || DBG
    /* Make sure we are at DPC or above! */
    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        /* We aren't -- bugcheck */
        KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL,
                     (ULONG_PTR)LockHandle->Lock,
                     KeGetCurrentIrql(),
                     0,
                     0);
    }
#endif

    /* Do the inlined function */
    KxAcquireSpinLock(LockHandle->Lock);
}

_IRQL_requires_min_(DISPATCH_LEVEL)
_Releases_nonreentrant_lock_(*LockHandle->Lock)
_Releases_exclusive_lock_(*LockHandle->Lock)
VOID
FASTCALL
KeReleaseQueuedSpinLockFromDpcLevel(_Inout_ PKSPIN_LOCK_QUEUE LockHandle)
{
#if defined(CONFIG_SMP) || DBG
    /* Make sure we are at DPC or above! */
    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        /* We aren't -- bugcheck */
        KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL,
                     (ULONG_PTR)LockHandle->Lock,
                     KeGetCurrentIrql(),
                     0,
                     0);
    }
#endif

    /* Do the inlined function */
    KxReleaseSpinLock(LockHandle->Lock);
}

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @implemented
 */
KIRQL
NTAPI
KeAcquireInterruptSpinLock(IN PKINTERRUPT Interrupt)
{
    KIRQL OldIrql;

    /* Raise IRQL */
    KeRaiseIrql(Interrupt->SynchronizeIrql, &OldIrql);

    /* Acquire spinlock on MP */
    KeAcquireSpinLockAtDpcLevel(Interrupt->ActualLock);
    return OldIrql;
}

/*
 * @implemented
 */
VOID
NTAPI
KeReleaseInterruptSpinLock(IN PKINTERRUPT Interrupt,
                           IN KIRQL OldIrql)
{
    /* Release lock on MP */
    KeReleaseSpinLockFromDpcLevel(Interrupt->ActualLock);

    /* Lower IRQL */
    KeLowerIrql(OldIrql);
}

/*
 * @implemented
 */
VOID
NTAPI
_KeInitializeSpinLock(IN PKSPIN_LOCK SpinLock)
{
    /* Clear it */
    *SpinLock = 0;
}

/*
 * @implemented
 */
#undef KeAcquireSpinLockAtDpcLevel
VOID
NTAPI
KeAcquireSpinLockAtDpcLevel(IN PKSPIN_LOCK SpinLock)
{
#if DBG
    /*
     * Make sure we are at DPC or above!
     * Like Windows, only checked builds validate the IRQL here; a free build
     * performs the plain lock operation (kmtest KeSpinLock relies on this).
     */
    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        /* We aren't -- bugcheck */
        KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL,
                     (ULONG_PTR)SpinLock,
                     KeGetCurrentIrql(),
                     0,
                     0);
    }
#endif

    /* Do the inlined function */
    KxAcquireSpinLock(SpinLock);
}

/*
 * @implemented
 */
#undef KeReleaseSpinLockFromDpcLevel
VOID
NTAPI
KeReleaseSpinLockFromDpcLevel(IN PKSPIN_LOCK SpinLock)
{
#if DBG
    /*
     * Make sure we are at DPC or above!
     * Like Windows, only checked builds validate the IRQL here; a free build
     * performs the plain lock operation (kmtest KeSpinLock relies on this).
     */
    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        /* We aren't -- bugcheck */
        KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL,
                     (ULONG_PTR)SpinLock,
                     KeGetCurrentIrql(),
                     0,
                     0);
    }
#endif

    /* Do the inlined function */
    KxReleaseSpinLock(SpinLock);
}

/*
 * @implemented
 */
VOID
FASTCALL
KefAcquireSpinLockAtDpcLevel(IN PKSPIN_LOCK SpinLock)
{
#if DBG
    /*
     * Make sure we are at DPC or above!
     * Like Windows, only checked builds validate the IRQL here; a free build
     * performs the plain lock operation (kmtest KeSpinLock relies on this).
     */
    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        /* We aren't -- bugcheck */
        KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL,
                     (ULONG_PTR)SpinLock,
                     KeGetCurrentIrql(),
                     0,
                     0);
    }
#endif

    /* Do the inlined function */
    KxAcquireSpinLock(SpinLock);
}

/*
 * @implemented
 */
VOID
FASTCALL
KefReleaseSpinLockFromDpcLevel(IN PKSPIN_LOCK SpinLock)
{
#if DBG
    /*
     * Make sure we are at DPC or above!
     * Like Windows, only checked builds validate the IRQL here; a free build
     * performs the plain lock operation (kmtest KeSpinLock relies on this).
     */
    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        /* We aren't -- bugcheck */
        KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL,
                     (ULONG_PTR)SpinLock,
                     KeGetCurrentIrql(),
                     0,
                     0);
    }
#endif

    /* Do the inlined function */
    KxReleaseSpinLock(SpinLock);
}

/*
 * @implemented
 */
VOID
FASTCALL
KiAcquireSpinLock(IN PKSPIN_LOCK SpinLock)
{
    /* Do the inlined function */
    KxAcquireSpinLock(SpinLock);
}

/*
 * @implemented
 */
VOID
FASTCALL
KiReleaseSpinLock(IN PKSPIN_LOCK SpinLock)
{
    /* Do the inlined function */
    KxReleaseSpinLock(SpinLock);
}

/*
 * @implemented
 */
BOOLEAN
FASTCALL
KeTryToAcquireSpinLockAtDpcLevel(IN OUT PKSPIN_LOCK SpinLock)
{
#if DBG
    /* Make sure we are at DPC or above! */
    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        /* We aren't -- bugcheck */
        KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL,
                     (ULONG_PTR)SpinLock,
                     KeGetCurrentIrql(),
                     0,
                     0);
    }

    /* Make sure that we don't own the lock already */
    if (((KSPIN_LOCK)KeGetCurrentThread() | 1) == *SpinLock)
    {
        /* We do, bugcheck! */
        KeBugCheckEx(SPIN_LOCK_ALREADY_OWNED, (ULONG_PTR)SpinLock, 0, 0, 0);
    }
#endif

#ifdef CONFIG_SMP
    /* Check if it's already acquired */
    if (!(*SpinLock))
    {
        /* Try to acquire it */
        if (InterlockedBitTestAndSet((PLONG)SpinLock, 0))
        {
            /* Someone else acquired it */
            return FALSE;
        }
    }
    else
    {
        /* It was already acquired */
        return FALSE;
    }
#endif

#if DBG
    /* On debug builds, we OR in the KTHREAD */
    *SpinLock = (ULONG_PTR)KeGetCurrentThread() | 1;
#endif

    /* All is well, return TRUE */
    return TRUE;
}

/*
 * @implemented
 */
VOID
FASTCALL
KeAcquireInStackQueuedSpinLockAtDpcLevel(IN PKSPIN_LOCK SpinLock,
                                         IN PKLOCK_QUEUE_HANDLE LockHandle)
{
    /* Set it up properly */
    LockHandle->LockQueue.Next = NULL;
    LockHandle->LockQueue.Lock = SpinLock;
#if 0
    KeAcquireQueuedSpinLockAtDpcLevel(LockHandle->LockQueue.Next);
#elif DBG
    /*
     * Make sure we are at DPC or above!
     * Like Windows, only checked builds validate the IRQL here.
     */
    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        /* We aren't -- bugcheck */
        KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL,
                     (ULONG_PTR)LockHandle->LockQueue.Lock,
                     KeGetCurrentIrql(),
                     0,
                     0);
    }
#endif

    /* Acquire the lock */
    KxAcquireSpinLock(LockHandle->LockQueue.Lock); // HACK
}

/*
 * @implemented
 */
VOID
FASTCALL
KeReleaseInStackQueuedSpinLockFromDpcLevel(IN PKLOCK_QUEUE_HANDLE LockHandle)
{
#if 0
    /* Call the internal function */
    KeReleaseQueuedSpinLockFromDpcLevel(LockHandle->LockQueue.Next);
#elif DBG
    /*
     * Make sure we are at DPC or above!
     * Like Windows, only checked builds validate the IRQL here.
     */
    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
    {
        /* We aren't -- bugcheck */
        KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL,
                     (ULONG_PTR)LockHandle->LockQueue.Lock,
                     KeGetCurrentIrql(),
                     0,
                     0);
    }
#endif

    /* Release the lock */
    KxReleaseSpinLock(LockHandle->LockQueue.Lock); // HACK
}

/*
 * @unimplemented
 */
KIRQL
FASTCALL
KeAcquireSpinLockForDpc(IN PKSPIN_LOCK SpinLock)
{
    UNIMPLEMENTED;
    return 0;
}

/*
 * @unimplemented
 */
VOID
FASTCALL
KeReleaseSpinLockForDpc(IN PKSPIN_LOCK SpinLock,
                        IN KIRQL OldIrql)
{
    UNIMPLEMENTED;
}

/*
 * @implemented
 */
VOID
FASTCALL
KeAcquireInStackQueuedSpinLockForDpc(IN PKSPIN_LOCK SpinLock,
                                     IN PKLOCK_QUEUE_HANDLE LockHandle)
{
    LockHandle->OldIrql = KeGetCurrentIrql();
    if (LockHandle->OldIrql >= DISPATCH_LEVEL)
        KeAcquireInStackQueuedSpinLockAtDpcLevel(SpinLock, LockHandle);
    else
        KeAcquireInStackQueuedSpinLock(SpinLock, LockHandle);
}

/*
 * @implemented
 */
VOID
FASTCALL
KeReleaseInStackQueuedSpinLockForDpc(IN PKLOCK_QUEUE_HANDLE LockHandle)
{
    if (LockHandle->OldIrql >= DISPATCH_LEVEL)
        KeReleaseInStackQueuedSpinLockFromDpcLevel(LockHandle);
    else
        KeReleaseInStackQueuedSpinLock(LockHandle);

}

/*
 * @implemented
 */
BOOLEAN
FASTCALL
KeTestSpinLock(IN PKSPIN_LOCK SpinLock)
{
    /* Test this spinlock */
    if (*SpinLock)
    {
        /* Spinlock is busy, yield execution */
        YieldProcessor();

        /* Return busy flag */
        return FALSE;
    }

    /* Spinlock appears to be free */
    return TRUE;
}

#ifdef _M_IX86
VOID
NTAPI
Kii386SpinOnSpinLock(PKSPIN_LOCK SpinLock, ULONG Flags)
{
    // FIXME: Handle flags
    UNREFERENCED_PARAMETER(Flags);

    /* Spin until it's unlocked */
    while (*(volatile KSPIN_LOCK *)SpinLock & 1)
    {
        // FIXME: Check for timeout

        /* Yield and keep looping */
        YieldProcessor();
    }
}
#endif
