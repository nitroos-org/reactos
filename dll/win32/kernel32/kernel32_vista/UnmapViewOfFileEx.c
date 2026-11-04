/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     UnmapViewOfFileEx (Windows 10 version 1703 and later; the flags came with UnmapViewOfFile2)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2: the flags are checked before the address, a flag outside the two known ones is
 * ERROR_INVALID_PARAMETER, and the flag that keeps a placeholder is ERROR_INVALID_ADDRESS for a view that did
 * not replace one, which then stays mapped. NtUnmapViewOfSectionEx makes these checks.
 */

#include "k32_vista.h"

#define NDEBUG
#include <debug.h>

#include <ndk/mmfuncs.h>

BOOL
WINAPI
UnmapViewOfFileEx(
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags)
{
    NTSTATUS Status;

    Status = NtUnmapViewOfSectionEx(NtCurrentProcess(), BaseAddress, UnmapFlags);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }
    return TRUE;
}
