/*
 * PROJECT:     ReactOS kernel tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test image importing a session image, for the MmSessionImage test
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <ntddk.h>

__declspec(dllimport) LONG NTAPI SessTestIncrement(VOID);

/* Increments the counter of the copy of sesstst_a in the same session */
LONG
NTAPI
SessTestBIncrement(VOID)
{
    return SessTestIncrement();
}

/* Where the import of sesstst_a points */
PVOID
NTAPI
SessTestBImportTarget(VOID)
{
    return (PVOID)SessTestIncrement;
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
