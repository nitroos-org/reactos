/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     InitializeSynchronizationBarrier (Windows 8 and later)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86): a thread count below 1 or a spin count below -1 gives FALSE and leaves
 * the last error alone; a NULL barrier gives FALSE with ERROR_INVALID_PARAMETER. -1 asks for the default spin count.
 * EnterSynchronizationBarrier and DeleteSynchronizationBarrier are forwarded to ntdll (RtlBarrier, RtlDeleteBarrier).
 */

#include "k32_vista.h"

#define NDEBUG
#include <debug.h>

NTSYSAPI
NTSTATUS
NTAPI
RtlInitBarrier(
    _Out_ PVOID Barrier,
    _In_ ULONG TotalThreads,
    _In_ ULONG SpinCount);

BOOL
WINAPI
InitializeSynchronizationBarrier(
    _Out_ PVOID Barrier,
    _In_ LONG TotalThreads,
    _In_ LONG SpinCount)
{
    NTSTATUS Status;

    if (TotalThreads < 1 || SpinCount < -1)
        return FALSE;

    Status = RtlInitBarrier(Barrier, (ULONG)TotalThreads, (ULONG)SpinCount);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}
