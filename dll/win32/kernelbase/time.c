/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Interrupt time functions that Windows exports from kernelbase and not from kernel32
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The MSYS2 and Cygwin runtimes load these three at start (clock_gettime) and abort with a fatal error when
 * KernelBase.dll does not provide them.
 */

#include <stdarg.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>

/* Layout of the shared user data that has not changed since NT 4: the interrupt time is at 0x08 */
typedef struct _BASEP_KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} BASEP_KSYSTEM_TIME;

#define BASEP_INTERRUPT_TIME ((volatile BASEP_KSYSTEM_TIME *)0x7ffe0008)

static
LONGLONG
BasepReadInterruptTime(VOID)
{
    LONG High;
    ULONG Low;

    do
    {
        High = BASEP_INTERRUPT_TIME->High1Time;
        Low = BASEP_INTERRUPT_TIME->LowPart;
    } while (High != BASEP_INTERRUPT_TIME->High2Time);

    return ((LONGLONG)High << 32) | Low;
}

VOID
WINAPI
QueryInterruptTime(
    _Out_ PULONGLONG InterruptTime)
{
    *InterruptTime = BasepReadInterruptTime();
}

/*
 * The precise interrupt time lives in kernel32 (QueryUnbiasedInterruptTimePrecise): programs reach it through
 * api-ms-win-core-realtime-l1-1-1, which resolves to kernel32 here, and a sandboxed process must not have to load
 * another DLL to resolve it. Both precise functions are forwarded there (kernelbase_ros.spec): kernel32 has
 * QueryUnbiasedInterruptTimePrecise (the interrupt time minus the sleep bias) and QueryInterruptTimePrecise (the
 * interrupt time, bias included, as Windows). kernel32 exports QueryInterruptTime too, for the same api set.
 */
