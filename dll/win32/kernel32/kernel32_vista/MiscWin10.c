/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IsNativeVhdBoot and GetMemoryErrorHandlingCapabilities
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86), a machine that boots from a physical disk and has no memory error handling:
 *  - IsNativeVhdBoot gives TRUE and *NativeVhdBoot FALSE. This system never boots from a virtual disk.
 *  - GetMemoryErrorHandlingCapabilities gives TRUE with no capability bit (the machine check handling of bad memory is
 *    not there), and leaves ERROR_NOT_FOUND as the last error although it succeeds. Windows does the same.
 */

#include "k32_vista.h"

#define NDEBUG
#include <debug.h>

BOOL
WINAPI
IsNativeVhdBoot(
    _Out_ PBOOL NativeVhdBoot)
{
    *NativeVhdBoot = FALSE;
    return TRUE;
}

BOOL
WINAPI
GetMemoryErrorHandlingCapabilities(
    _Out_ PULONG Capabilities)
{
    *Capabilities = 0;
    SetLastError(ERROR_NOT_FOUND);
    return TRUE;
}
