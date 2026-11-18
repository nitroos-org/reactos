/*
 * COPYRIGHT:            See COPYING in the top level directory
 * PROJECT:              ReactOS Win32 Base API
 * FILE:                 dll/win32/kernel32/client/perfcnt.c
 * PURPOSE:              Performance Counter
 * PROGRAMMER:           Eric Kohl
 */

/* INCLUDES *******************************************************************/

#include <k32.h>
#include <reactos/rosqpc.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

/*
 * @implemented
 */
BOOL
WINAPI
QueryPerformanceCounter(OUT PLARGE_INTEGER lpPerformanceCount)
{
    LARGE_INTEGER Frequency;
    NTSTATUS Status;

#if defined(_M_IX86) || defined(_M_AMD64)
    /* The kernel's own TSC read and scaling, without the system call when the
       kernel enabled that (a speed choice: the counter is the same either way) */
    if (RosQpcQueryBypass(lpPerformanceCount))
        return TRUE;
#endif

    Status = NtQueryPerformanceCounter(lpPerformanceCount, &Frequency);
    if (Frequency.QuadPart == 0) Status = STATUS_NOT_IMPLEMENTED;

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
QueryPerformanceFrequency(OUT PLARGE_INTEGER lpFrequency)
{
    LARGE_INTEGER Count;
    NTSTATUS Status;

#if defined(_M_IX86) || defined(_M_AMD64)
    /* The HAL publishes the frequency when the counter is the TSC */
    if (SharedUserData->QpcFrequency)
    {
        lpFrequency->QuadPart = (LONGLONG)SharedUserData->QpcFrequency;
        return TRUE;
    }
#endif

    Status = NtQueryPerformanceCounter(&Count, lpFrequency);
    if (lpFrequency->QuadPart == 0) Status = STATUS_NOT_IMPLEMENTED;

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/* EOF */

/*
 * @implemented
 *
 * Windows 7 implements this in kernel32 (ntdll exports RtlQueryUnbiasedInterruptTime from Windows 8 on).
 */
BOOL
WINAPI
QueryUnbiasedInterruptTime(
    _Out_ PULONGLONG UnbiasedTime)
{
    LARGE_INTEGER InterruptTime;
    ULONGLONG Bias = 0;

    if (!UnbiasedTime)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

#if (NTDDI_VERSION >= NTDDI_VISTA)
    /* The bias is the time spent in sleep and hibernation; it must not change while the time is read */
    do
    {
        Bias = SharedUserData->InterruptTimeBias;
        InterruptTime = KiReadSystemTime(&SharedUserData->InterruptTime);
    } while (Bias != SharedUserData->InterruptTimeBias);
#else
    /* Shared user data of this NT version has no bias: the kernel does not take time spent asleep out */
    InterruptTime = KiReadSystemTime(&SharedUserData->InterruptTime);
#endif

    *UnbiasedTime = InterruptTime.QuadPart - Bias;
    return TRUE;
}
