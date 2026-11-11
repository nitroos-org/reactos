/*
 * PROJECT:     ReactOS kernel tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test image loaded as a session image by the MmSessionImage test
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <ntddk.h>

/* One per session: the image has its own pages in each session */
static volatile LONG Counter;

LONG
NTAPI
SessTestIncrement(VOID)
{
    return InterlockedIncrement(&Counter);
}

LONG
NTAPI
SessTestGetCounter(VOID)
{
    return Counter;
}

PVOID
NTAPI
SessTestCounterAddress(VOID)
{
    return (PVOID)&Counter;
}

/* Stops the system from inside the session image (debugger symbol check) */
VOID
NTAPI
SessTestBugCheck(VOID)
{
    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x5E551, (ULONG_PTR)&Counter, 0, 0);
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    return STATUS_SUCCESS;
}
