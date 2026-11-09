/*
 * PROJECT:     ReactOS Kernel-Mode Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Test driver for the missing driver import log. It imports two
 *              real ntoskrnl functions; patchimports.py renames both in the
 *              built file to names no module exports, so loading it fails and
 *              the loader must report BOTH names (and not the third, resolved
 *              import, DbgPrint). The driver never gets to run.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include <ntddk.h>

/* Names are renamed in the built file, keep them long (the patch cannot grow a name) */
static PVOID volatile Keep[2];

NTSTATUS
NTAPI
DriverEntry(IN PDRIVER_OBJECT DriverObject,
            IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    Keep[0] = (PVOID)IoWMISuggestInstanceName;
    Keep[1] = (PVOID)KeRegisterBugCheckReasonCallback;
    DbgPrint("missimp: loaded (the import patch was not applied)\n");
    return STATUS_SUCCESS;
}
