/*
 * COPYRIGHT:       See COPYING in the top directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/mm/mmfault.c
 * PURPOSE:         Kernel memory management functions
 * PROGRAMMERS:     David Welch (welch@cwcom.net)
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include <cache/section/newmm.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include "ARM3/miarm.h"

extern MM_AVL_TABLE MiRosKernelVadRoot;

/* PRIVATE FUNCTIONS **********************************************************/

NTSTATUS
NTAPI
MmpAccessFault(KPROCESSOR_MODE Mode,
               ULONG_PTR Address,
               BOOLEAN FromMdl,
               ULONG FaultCode)
{
    PMMSUPPORT AddressSpace;
    MEMORY_AREA* MemoryArea;
    NTSTATUS Status;

    DPRINT("MmAccessFault(Mode %d, Address %x)\n", Mode, Address);

    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        DPRINT1("Page fault at high IRQL was %u\n", KeGetCurrentIrql());
        return(STATUS_UNSUCCESSFUL);
    }

    /* Instruction fetch and the page is present.
       This means the page is NX and we cannot do anything to "fix" it. */
    if (MI_IS_INSTRUCTION_FETCH(FaultCode))
    {
        DPRINT1("Page fault instruction fetch at %p\n", Address);
        return STATUS_ACCESS_VIOLATION;
    }

    /*
     * Find the memory area for the faulting address
     */
    if (Address >= (ULONG_PTR)MmSystemRangeStart)
    {
        /*
         * Check permissions
         */
        if (Mode != KernelMode)
        {
            DPRINT1("MmAccessFault(Mode %d, Address %x)\n", Mode, Address);
            return(STATUS_ACCESS_VIOLATION);
        }
        AddressSpace = MmGetKernelAddressSpace();
    }
    else
    {
        AddressSpace = &PsGetCurrentProcess()->Vm;
    }

    if (!FromMdl)
    {
        MmLockAddressSpace(AddressSpace);
    }
    do
    {
        MemoryArea = MmLocateMemoryAreaByAddress(AddressSpace, (PVOID)Address);
        if (MemoryArea == NULL || MemoryArea->DeleteInProgress)
        {
            if (!FromMdl)
            {
                MmUnlockAddressSpace(AddressSpace);
            }
            return (STATUS_ACCESS_VIOLATION);
        }

        switch (MemoryArea->Type)
        {
        case MEMORY_AREA_SECTION_VIEW:
            Status = MmAccessFaultSectionView(AddressSpace,
                                              MemoryArea,
                                              (PVOID)Address,
                                              !FromMdl);
            break;
#ifdef NEWCC
        case MEMORY_AREA_CACHE:
            // This code locks for itself to keep from having to break a lock
            // passed in.
            if (!FromMdl)
                MmUnlockAddressSpace(AddressSpace);
            Status = MmAccessFaultCacheSection(Mode, Address, FromMdl);
            if (!FromMdl)
                MmLockAddressSpace(AddressSpace);
            break;
#endif
        default:
            Status = STATUS_ACCESS_VIOLATION;
            break;
        }
    }
    while (Status == STATUS_MM_RESTART_OPERATION);

    DPRINT("Completed page fault handling\n");
    if (!FromMdl)
    {
        MmUnlockAddressSpace(AddressSpace);
    }
    return(Status);
}

NTSTATUS
NTAPI
MmNotPresentFault(KPROCESSOR_MODE Mode,
                  ULONG_PTR Address,
                  BOOLEAN FromMdl)
{
    PMMSUPPORT AddressSpace;
    MEMORY_AREA* MemoryArea;
    NTSTATUS Status;

    DPRINT("MmNotPresentFault(Mode %d, Address %x)\n", Mode, Address);

    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        DPRINT1("Page fault at high IRQL was %u, address %x\n", KeGetCurrentIrql(), Address);
        return(STATUS_UNSUCCESSFUL);
    }

    /*
     * Find the memory area for the faulting address
     */
    if (Address >= (ULONG_PTR)MmSystemRangeStart)
    {
        /*
         * Check permissions
         */
        if (Mode != KernelMode)
        {
            DPRINT1("Address: %x\n", Address);
            return(STATUS_ACCESS_VIOLATION);
        }
        AddressSpace = MmGetKernelAddressSpace();
    }
    else
    {
        AddressSpace = &PsGetCurrentProcess()->Vm;
    }

    if (!FromMdl)
    {
        MmLockAddressSpace(AddressSpace);
    }

    /*
     * Call the memory area specific fault handler
     */
    do
    {
        MemoryArea = MmLocateMemoryAreaByAddress(AddressSpace, (PVOID)Address);
        if (MemoryArea == NULL || MemoryArea->DeleteInProgress)
        {
            if (!FromMdl)
            {
                MmUnlockAddressSpace(AddressSpace);
            }
            return (STATUS_ACCESS_VIOLATION);
        }

        switch (MemoryArea->Type)
        {
        case MEMORY_AREA_SECTION_VIEW:
            Status = MmNotPresentFaultSectionView(AddressSpace,
                                                  MemoryArea,
                                                  (PVOID)Address,
                                                  !FromMdl);
            break;
#ifdef NEWCC
        case MEMORY_AREA_CACHE:
            // This code locks for itself to keep from having to break a lock
            // passed in.
            if (!FromMdl)
                MmUnlockAddressSpace(AddressSpace);
            Status = MmNotPresentFaultCacheSection(Mode, Address, FromMdl);
            if (!FromMdl)
                MmLockAddressSpace(AddressSpace);
            break;
#endif
        default:
            Status = STATUS_ACCESS_VIOLATION;
            break;
        }
    }
    while (Status == STATUS_MM_RESTART_OPERATION);

    DPRINT("Completed page fault handling\n");
    if (!FromMdl)
    {
        MmUnlockAddressSpace(AddressSpace);
    }
    return(Status);
}

extern BOOLEAN Mmi386MakeKernelPageTableGlobal(PVOID Address);

BOOLEAN
NTAPI
MmRebalanceMemoryConsumersAndWait(VOID);

/*
 * Out of pages: let the balancer run and report whether a real, progress-making
 * wait happened.
 *
 * A thread that holds its process's AddressCreationLock must not wait for the
 * balancer, which may itself need that lock to page out (CORE-20761). In that
 * state we can only nudge the balancer and briefly yield - a spin that
 * guarantees no progress. Return FALSE for that case so the caller can bound the
 * retries (see MiRetryOutOfMemoryFault); return TRUE when a genuine balancer
 * wait ran and the caller may retry freely.
 */
static
BOOLEAN
MiWaitForFreePages(VOID)
{
    static LARGE_INTEGER TinyTime = {{-1L, -1L}};

    if (PsGetCurrentProcess()->AddressCreationLock.Owner == KeGetCurrentThread())
    {
        MmRebalanceMemoryConsumers();
        KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
        return FALSE;
    }

    return MmRebalanceMemoryConsumersAndWait();
}

/*
 * Maximum number of consecutive out-of-memory fault retries allowed while the
 * faulting thread can only spin (it holds a lock the balancer may need, so no
 * wait can free memory). Past this many no-progress spins the fault fails with
 * STATUS_NO_MEMORY: the faulting operation then unwinds and releases its lock
 * instead of spinning forever and freezing every thread blocked behind it (T16,
 * defense-in-depth for the invariant "a lock holder's OOM wait is bounded").
 * The common recovery path - a thread that holds no such lock and waits for a
 * real balancer pass - is never capped, so success behaviour is unchanged.
 * Writable so the kernel-mode robustness test can drive the bound.
 */
ULONG MiMaxOomSpinRetries = 1024;

/*
 * Longest a user thread waits, in total, for a fault on a user address to get
 * a page (100 ns units). Each balancer pass resets the no-progress count, so
 * with nothing the balancer can free a thread that cannot get a page waits
 * for ever. After this the fault fails with STATUS_NO_MEMORY, which the trap
 * handler turns into an in-page error exception in that process: it dies or
 * handles the error, the system goes on. A bugcheck is the alternative:
 * giving it the reserved pages starves page tables and lock holders (0x7A),
 * and exhaustion of the balancer's floor can bugcheck it (0x4D). Critical
 * processes and the System process are not bounded: failing them is fatal.
 */
#define MI_MAX_FAULT_WAIT (30LL * 10000000LL)

/*
 * Decide how to handle STATUS_NO_MEMORY from a page fault. A real balancer wait
 * (progress possible) resets the no-progress counter and always retries, exactly
 * as the fault path always did. A no-progress spin (a lock we hold blocks the
 * balancer) is counted and bounded. Returns TRUE to retry the fault, FALSE to
 * give up and propagate STATUS_NO_MEMORY.
 */
static
BOOLEAN
MiRetryOutOfMemoryFault(PULONG NoProgressSpins, PLONGLONG WaitStart, PVOID Address)
{
    BOOLEAN Bounded;
    LONGLONG Now;

    Bounded = ((ULONG_PTR)Address <= (ULONG_PTR)MM_HIGHEST_USER_ADDRESS) &&
              !MiIsCriticalProcess(PsGetCurrentProcess());
    if (Bounded)
    {
        Now = (LONGLONG)KeQueryInterruptTime();
        if (*WaitStart == 0)
            *WaitStart = Now;
        else if ((Now - *WaitStart) > MI_MAX_FAULT_WAIT)
        {
            DPRINT1("MM: fault at %p in %.16s waited %I64d s for memory, failing it\n", Address,
                    PsGetCurrentProcess()->ImageFileName, (Now - *WaitStart) / 10000000LL);
            return FALSE;
        }
    }

    if (MiWaitForFreePages())
    {
        *NoProgressSpins = 0;

        /* A balancer pass that freed nothing returns at once: do not spin through the pass until the bound */
        if (Bounded && (MmAvailablePages < 256))
        {
            LARGE_INTEGER Delay;

            Delay.QuadPart = -10 * 10000;
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        }
        return TRUE;
    }

    return (++(*NoProgressSpins) < MiMaxOomSpinRetries);
}

#if DBG
/*
 * Robustness test hook (T16). Drives the out-of-memory fault retry bound exactly
 * as MmAccessFault does, while this thread owns its process AddressCreationLock -
 * the no-progress, lock-held state the bound guards. SimulatedMax temporarily
 * overrides the live cap (so a single build can show both the unbounded pre-fix
 * spin and the bounded one); Ceiling caps the test's own loop so an unbounded
 * case cannot hang the machine. Returns the number of retries performed: with the
 * cap active this equals the cap (bounded, below Ceiling); with the cap disabled
 * it equals Ceiling (would otherwise spin forever). The guarded mutex is always
 * released before returning, so repeated calls prove the lock is never held
 * across the bound.
 *
 * Debug/test only (T61): compiled out of Release, and its export in ntoskrnl.spec
 * is -dbg, so shipped kernels carry neither the code nor the export.
 */
ULONG
NTAPI
MmDbgTestOomRetryBound(IN ULONG SimulatedMax,
                       IN ULONG Ceiling)
{
    ULONG SavedMax = MiMaxOomSpinRetries;
    ULONG NoProgressSpins = 0;
    LONGLONG WaitStart = 0;
    ULONG Iterations = 0;
    PMMSUPPORT AddressSpace = &PsGetCurrentProcess()->Vm;
    BOOLEAN KeepGoing;

    MiMaxOomSpinRetries = SimulatedMax;

    MmLockAddressSpace(AddressSpace);
    ASSERT(PsGetCurrentProcess()->AddressCreationLock.Owner == KeGetCurrentThread());

    do
    {
        KeepGoing = MiRetryOutOfMemoryFault(&NoProgressSpins, &WaitStart, (PVOID)MmSystemRangeStart);
        Iterations++;
    }
    while (KeepGoing && (Iterations < Ceiling));

    MmUnlockAddressSpace(AddressSpace);
    ASSERT(PsGetCurrentProcess()->AddressCreationLock.Owner != KeGetCurrentThread());

    MiMaxOomSpinRetries = SavedMax;
    return Iterations;
}
#endif /* DBG */

NTSTATUS
NTAPI
MmAccessFault(IN ULONG FaultCode,
              IN PVOID Address,
              IN KPROCESSOR_MODE Mode,
              IN PVOID TrapInformation)
{
    PMMVAD Vad = NULL;
    NTSTATUS Status;
    BOOLEAN IsArm3Fault = FALSE;
    ULONG NoProgressSpins = 0;
    LONGLONG WaitStart = 0;

    /* One fault: a retry through Again is the same fault */
    MI_PRCB_COUNT_ADD(MmPageFaultCount, 1);

    /* Before any lock: the fault may come from DISPATCH_LEVEL or above. User mode keeps its access violation. */
    if (MmSpecialPoolEnabled && (Mode == KernelMode) && ((ULONG_PTR)Address >= (ULONG_PTR)MmSystemRangeStart))
    {
        MmCheckSpecialPoolFault(FaultCode, Address, TrapInformation);
    }

Again:
    Vad = NULL;
    IsArm3Fault = FALSE;

    /* Cute little hack for ROS */
    if ((ULONG_PTR)Address >= (ULONG_PTR)MmSystemRangeStart)
    {
#ifdef _M_IX86
        /* Check for an invalid page directory in kernel mode */
        if (Mmi386MakeKernelPageTableGlobal(Address))
        {
            /* All is well with the world */
            return STATUS_SUCCESS;
        }
#endif
    }

    /* Handle shared user page / page table, which don't have a VAD / MemoryArea */
    if ((PAGE_ALIGN(Address) == (PVOID)MM_SHARED_USER_DATA_VA) ||
        MI_IS_PAGE_TABLE_ADDRESS(Address))
    {
        /* This is an ARM3 fault */
        DPRINT("ARM3 fault %p\n", Address);
        Status = MmArmAccessFault(FaultCode, Address, Mode, TrapInformation);
        goto Arm3Done;
    }

    /* Is there a ReactOS address space yet? */
    if (MmGetKernelAddressSpace())
    {
        if (Address > MM_HIGHEST_USER_ADDRESS)
        {
            /* Check if this is an ARM3 memory area */
            MiLockWorkingSetShared(PsGetCurrentThread(), &MmSystemCacheWs);
            Vad = MiLocateVad(&MiRosKernelVadRoot, Address);

            if ((Vad != NULL) && !MI_IS_ROSMM_VAD(Vad))
            {
                IsArm3Fault = TRUE;
            }

            MiUnlockWorkingSetShared(PsGetCurrentThread(), &MmSystemCacheWs);
        }
        else
        {
            /* Could this be a VAD fault from user-mode? */
            MiLockProcessWorkingSetShared(PsGetCurrentProcess(), PsGetCurrentThread());
            Vad = MiLocateVad(&PsGetCurrentProcess()->VadRoot, Address);

            if ((Vad != NULL) && !MI_IS_ROSMM_VAD(Vad))
            {
                IsArm3Fault = TRUE;
            }

            MiUnlockProcessWorkingSetShared(PsGetCurrentProcess(), PsGetCurrentThread());
        }
    }

    /* Is this an ARM3 VAD, or is there no address space yet? */
    if (IsArm3Fault ||
        ((Vad == NULL) &&
         ((ULONG_PTR)Address >= (ULONG_PTR)MmPagedPoolStart) &&
         ((ULONG_PTR)Address < (ULONG_PTR)MmPagedPoolEnd)) ||
        (!MmGetKernelAddressSpace()))
    {
        /* This is an ARM3 fault */
        DPRINT("ARM3 fault %p\n", Vad);
        Status = MmArmAccessFault(FaultCode, Address, Mode, TrapInformation);
        goto Arm3Done;
    }

    /* Keep same old ReactOS Behaviour */
    if (!MI_IS_NOT_PRESENT_FAULT(FaultCode))
    {
        /* Call access fault */
        Status = MmpAccessFault(Mode, (ULONG_PTR)Address, TrapInformation ? FALSE : TRUE, FaultCode);
    }
    else if ((Mode == UserMode) && (Address <= MM_HIGHEST_USER_ADDRESS) &&
             MiUserFaultMustLeavePages() && MiCanFaultWaitForPages())
    {
        /*
         * A fault of user mode code on a page of a section (a mapped file, an image, shared memory) takes a
         * page frame as well. Below the reserve it waits for the balancer like a demand zero fault
         * (MiResolveDemandZeroFault), before the address space lock. The reserve is what the requests that
         * cannot wait take their pages from (pool, the stack of a thread, the structures of win32k): without
         * it, processes that map files take every free page between two balancer passes, and a new process
         * fails to start (0xC0000142: its first call into win32k cannot get its stack or its thread
         * information). A fault of kernel code on a user buffer does not wait: the file system that reads
         * it may hold what the balancer or the lazy writer needs. Retried below.
         */
        MmRebalanceMemoryConsumers();
        Status = STATUS_NO_MEMORY;
    }
    else
    {
        /* Call not present */
        Status = MmNotPresentFault(Mode, (ULONG_PTR)Address, TrapInformation ? FALSE : TRUE);
    }

    if (Status == STATUS_NO_MEMORY)
    {
        if (MiRetryOutOfMemoryFault(&NoProgressSpins, &WaitStart, Address))
            goto Again;
        return Status;
    }

    return Status;

Arm3Done:
    /*
     * Out of pages: wait for the balancer, then start over. The mapping may
     * have changed meanwhile, also to one the other memory manager owns.
     */
    if (Status == STATUS_NO_MEMORY)
    {
        if (MiRetryOutOfMemoryFault(&NoProgressSpins, &WaitStart, Address))
            goto Again;
        return Status;
    }

    /* The address became a ReactOS Mm view after the choice above */
    if (Status == STATUS_MM_RESTART_OPERATION)
        goto Again;

    return Status;
}

