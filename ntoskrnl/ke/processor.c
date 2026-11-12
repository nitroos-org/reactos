/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Portable processor related routines
 * COPYRIGHT:   Copyright 2025 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

KAFFINITY KeActiveProcessors = 0;

/* Started processors that are not active yet; they take TLB flushes */
KAFFINITY KiStartingProcessors = 0;

/* Number of processors */
CCHAR KeNumberProcessors = 0;

#ifdef CONFIG_SMP

/* Theoretical maximum number of processors that can be handled.
 * Set once at run-time. Returned by KeQueryMaximumProcessorCount(). */
ULONG KeMaximumProcessors = MAXIMUM_PROCESSORS;

/* Maximum number of logical processors that can be started
 * (including dynamically) at run-time. If 0: do not perform checks. */
ULONG KeNumprocSpecified = 0;

/* Maximum number of logical processors that can be started
 * at boot-time. If 0: do not perform checks. */
ULONG KeBootprocSpecified = 0;

#endif // CONFIG_SMP

/* FUNCTIONS *****************************************************************/

/* Minimal NT6 processor-count exports (KMDF probes these on 6.x) */
ULONG NTAPI KeQueryMaximumProcessorCount(VOID) { return KeNumberProcessors; }
ULONG NTAPI KeQueryMaximumProcessorCountEx(USHORT GroupNumber) { return (GroupNumber == 0 || GroupNumber == 0xFFFF) ? KeNumberProcessors : 0; }
ULONG NTAPI KeQueryActiveProcessorCount(PKAFFINITY ActiveProcessors)
{ if (ActiveProcessors) *ActiveProcessors = KeActiveProcessors; return KeNumberProcessors; }
ULONG NTAPI KeQueryActiveProcessorCountEx(USHORT GroupNumber) { return (GroupNumber == 0 || GroupNumber == 0xFFFF) ? KeNumberProcessors : 0; }

KAFFINITY
NTAPI
KeQueryActiveProcessors(VOID)
{
    return KeActiveProcessors;
}

/**
 * Retrieves the number of the current processor.
 *
 * \param ProcessorNumber Pointer to a PROCESSOR_NUMBER structure that receives the processor number.
 *
 * \return NTSTATUS The status of the operation.
 */
NTSTATUS
NTAPI
NtGetCurrentProcessorNumberEx(
    _Out_ PPROCESSOR_NUMBER ProcessorNumber)
{
    _SEH2_TRY
    {
        ProbeForWrite(ProcessorNumber, sizeof(PROCESSOR_NUMBER), __alignof(PROCESSOR_NUMBER));
        ProcessorNumber->Group = 0; // TODO: Support processor groups
        ProcessorNumber->Number = (UCHAR)KeGetCurrentProcessorNumber();
        ProcessorNumber->Reserved = 0;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        return _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return STATUS_SUCCESS;
}

/*
 * Processor group and time helpers drivers use on Windows 7 and later,
 * from the public WDK documentation. This kernel has a single processor
 * group (group 0, up to the machine's active processors).
 */

ULONG
NTAPI
KeGetCurrentProcessorNumberEx(
    _Out_opt_ PPROCESSOR_NUMBER ProcNumber)
{
    ULONG Index = KeGetCurrentProcessorNumber();

    if (ProcNumber)
    {
        ProcNumber->Group = 0;
        ProcNumber->Number = (UCHAR)Index;
        ProcNumber->Reserved = 0;
    }
    return Index;
}

USHORT
NTAPI
KeQueryActiveGroupCount(VOID)
{
    return 1;
}

USHORT
NTAPI
KeQueryMaximumGroupCount(VOID)
{
    return 1;
}

KAFFINITY
NTAPI
KeQueryGroupAffinity(
    _In_ USHORT GroupNumber)
{
    /* An out-of-range group has no processors */
    return (GroupNumber == 0) ? KeActiveProcessors : 0;
}

/* Returns the previous system affinity (0 if none was active) */
KAFFINITY
NTAPI
KeSetSystemAffinityThreadEx(
    _In_ KAFFINITY Affinity)
{
    PKTHREAD CurrentThread = KeGetCurrentThread();
    KAFFINITY Previous = CurrentThread->SystemAffinityActive ? CurrentThread->Affinity : 0;

    KeSetSystemAffinityThread(Affinity);
    return Previous;
}

VOID
NTAPI
KeRevertToUserAffinityThreadEx(
    _In_ KAFFINITY Affinity)
{
    if (Affinity == 0)
        KeRevertToUserAffinityThread();
    else
        KeSetSystemAffinityThread(Affinity);
}

VOID
NTAPI
KeSetSystemGroupAffinityThread(
    _In_ PGROUP_AFFINITY Affinity,
    _Out_opt_ PGROUP_AFFINITY PreviousAffinity)
{
    KAFFINITY Previous;

    /* FIXME: VERIFY ON ORACLE: an invalid group or an empty mask is a
       caller bug (a bugcheck on Windows); here it leaves the affinity alone. */
    if (Affinity->Group != 0 || (Affinity->Mask & KeActiveProcessors) == 0)
    {
        if (PreviousAffinity)
        {
            PKTHREAD Thread = KeGetCurrentThread();
            PreviousAffinity->Group = 0;
            PreviousAffinity->Mask = Thread->SystemAffinityActive ? Thread->Affinity : 0;
            RtlZeroMemory(PreviousAffinity->Reserved, sizeof(PreviousAffinity->Reserved));
        }
        return;
    }

    Previous = KeSetSystemAffinityThreadEx(Affinity->Mask & KeActiveProcessors);
    if (PreviousAffinity)
    {
        PreviousAffinity->Group = 0;
        PreviousAffinity->Mask = Previous;
        RtlZeroMemory(PreviousAffinity->Reserved, sizeof(PreviousAffinity->Reserved));
    }
}

VOID
NTAPI
KeRevertToUserGroupAffinityThread(
    _In_ PGROUP_AFFINITY PreviousAffinity)
{
    KeRevertToUserAffinityThreadEx(PreviousAffinity->Mask);
}

ULONGLONG
NTAPI
KeQueryUnbiasedInterruptTime(VOID)
{
    LARGE_INTEGER Time;

    /* No sleep or hibernate states here: nothing to subtract from the interrupt time */
    do
    {
        Time.HighPart = SharedUserData->InterruptTime.High1Time;
        Time.LowPart = SharedUserData->InterruptTime.LowPart;
    } while (Time.HighPart != SharedUserData->InterruptTime.High2Time);

    return (ULONGLONG)Time.QuadPart;
}
