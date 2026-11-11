/*
 * PROJECT:     ReactOS kernel tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test image importing a routine that sesstst_a does not export (its load fails)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <ntddk.h>

__declspec(dllimport) LONG NTAPI SessTestIncrement(VOID);
__declspec(dllimport) LONG NTAPI SessTestMissing(VOID);

LONG
NTAPI
SessTestCIncrement(VOID)
{
    return SessTestIncrement() + SessTestMissing();
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
