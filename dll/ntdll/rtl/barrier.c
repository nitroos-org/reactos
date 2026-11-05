/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RtlInitBarrier, RtlBarrier and RtlDeleteBarrier: the synchronization barrier of Windows 8 and later
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Behaviour measured on Windows 10 22H2 (x64 and x86), as seen through EnterSynchronizationBarrier:
 *  - the thread that arrives last gets TRUE, every other thread FALSE, and the barrier is ready for the next phase;
 *  - flags other than SPIN_ONLY (1), BLOCK_ONLY (2) and NO_DELETE (4) raise STATUS_INVALID_PARAMETER;
 *  - a NULL or an uninitialized barrier gives FALSE.
 * The state of the barrier is kept in the opaque RTL_BARRIER of the caller, which is 24 bytes on x86 and 32 on amd64.
 * Waiters park with RtlWaitOnAddress on the generation counter.
 */

#include <ntdll.h>

/* the ndk declares them for newer headers only */
NTSYSAPI NTSTATUS NTAPI RtlWaitOnAddress(_In_ const volatile VOID *Address, _In_ PVOID CompareAddress, _In_ SIZE_T AddressSize, _In_opt_ PLARGE_INTEGER Timeout);
NTSYSAPI VOID NTAPI RtlWakeAddressAll(_In_ const volatile VOID *Address);

#define NDEBUG
#include <debug.h>

#define BARRIER_MAGIC           0x52425A4B
#define BARRIER_DEFAULT_SPIN    2000

#define BARRIER_FLAGS_SPIN_ONLY 0x1
#define BARRIER_FLAGS_BLOCK_ONLY 0x2
#define BARRIER_FLAGS_NO_DELETE 0x4
#define BARRIER_FLAGS_ALL       0x7

typedef struct _BASE_BARRIER
{
    LONG Magic;
    LONG TotalThreads;
    LONG SpinCount;
    volatile LONG Arrived;
    volatile LONG Generation;
    volatile LONG Inside;
} BASE_BARRIER, *PBASE_BARRIER;

C_ASSERT(sizeof(BASE_BARRIER) <= 6 * sizeof(ULONG));

NTSTATUS
NTAPI
RtlInitBarrier(
    _Out_ PVOID Barrier,
    _In_ ULONG TotalThreads,
    _In_ ULONG SpinCount)
{
    PBASE_BARRIER Base = Barrier;

    if (!Base)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Base, 6 * sizeof(ULONG));
    Base->TotalThreads = (LONG)TotalThreads;
    Base->SpinCount = (LONG)SpinCount;
    Base->Magic = BARRIER_MAGIC;
    return STATUS_SUCCESS;
}

static
VOID
RtlpBarrierLeave(
    _Inout_ PBASE_BARRIER Base)
{
    /* The address is only hashed from here on: the caller may free the barrier as soon as Inside is zero */
    if (InterlockedDecrement(&Base->Inside) == 0)
        RtlWakeAddressAll((PVOID)&Base->Inside);
}

BOOLEAN
NTAPI
RtlBarrier(
    _Inout_ PVOID Barrier,
    _In_ ULONG Flags)
{
    PBASE_BARRIER Base = Barrier;
    BOOLEAN Last = FALSE;
    LONG Generation, Spin;

    if (!Base)
        return FALSE;

    if (Flags & ~BARRIER_FLAGS_ALL)
        RtlRaiseStatus(STATUS_INVALID_PARAMETER);

    if (Base->Magic != BARRIER_MAGIC)
        return FALSE;

    /* A deleter waits for the threads that can still touch the barrier; NO_DELETE promises that nobody deletes it */
    if (!(Flags & BARRIER_FLAGS_NO_DELETE))
        InterlockedIncrement(&Base->Inside);

    Generation = Base->Generation;

    if (InterlockedIncrement(&Base->Arrived) == Base->TotalThreads)
    {
        /* The last thread opens the next phase and lets the others go */
        Base->Arrived = 0;
        InterlockedIncrement(&Base->Generation);
        RtlWakeAddressAll((PVOID)&Base->Generation);
        Last = TRUE;
    }
    else
    {
        if (!(Flags & BARRIER_FLAGS_BLOCK_ONLY))
        {
            Spin = Base->SpinCount == -1 ? BARRIER_DEFAULT_SPIN : Base->SpinCount;
            while (Base->Generation == Generation)
            {
                if (!(Flags & BARRIER_FLAGS_SPIN_ONLY) && Spin-- <= 0)
                    break;
                YieldProcessor();
            }
        }

        if (!(Flags & BARRIER_FLAGS_SPIN_ONLY))
        {
            while (Base->Generation == Generation)
            {
                LONG Compare = Generation;
                RtlWaitOnAddress((PVOID)&Base->Generation, &Compare, sizeof(Compare), NULL);
            }
        }
    }

    if (!(Flags & BARRIER_FLAGS_NO_DELETE))
        RtlpBarrierLeave(Base);

    return Last;
}

BOOLEAN
NTAPI
RtlDeleteBarrier(
    _Inout_ PVOID Barrier)
{
    PBASE_BARRIER Base = Barrier;
    LONG Inside;

    if (!Base)
        return TRUE;

    /* The threads that are still leaving the last phase finish with the memory first */
    while ((Inside = Base->Inside) != 0)
        RtlWaitOnAddress((PVOID)&Base->Inside, &Inside, sizeof(Inside), NULL);

    Base->Magic = 0;
    return TRUE;
}
