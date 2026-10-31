/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for GetPointerDeviceOrientation and GetPointerDeviceInputSpace
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86) on a machine without touch screen or pen: whatever the
 * handle and the buffer, the answer is ERROR_INVALID_HANDLE. Skipped where a pointer device exists.
 */

#include "precomp.h"

typedef BOOL (WINAPI *PFN_Query)(HANDLE, PVOID);
typedef BOOL (WINAPI *PFN_GetPointerDevices)(UINT32 *, PVOID);

#define PENDING_ERROR 0xdeadbeef

START_TEST(PointerDeviceFunctions)
{
    HMODULE User32 = GetModuleHandleW(L"user32.dll");
    PFN_Query pOrientation = (PFN_Query)GetProcAddress(User32, "GetPointerDeviceOrientation");
    PFN_Query pInputSpace = (PFN_Query)GetProcAddress(User32, "GetPointerDeviceInputSpace");
    PFN_GetPointerDevices pDevices = (PFN_GetPointerDevices)GetProcAddress(User32, "GetPointerDevices");
    static const ULONG_PTR Handles[] = { 0, 1, 0x1234 };
    DWORD Buffer[4];
    UINT32 Count = 0;
    ULONG i;

    if (!pOrientation || !pInputSpace)
    {
        skip("the pointer device functions are not exported\n");
        return;
    }

    if (pDevices && pDevices(&Count, NULL) && Count != 0)
    {
        skip("this machine has pointer devices\n");
        return;
    }

    for (i = 0; i < sizeof(Handles) / sizeof(Handles[0]); i++)
    {
        SetLastError(PENDING_ERROR);
        ok(pOrientation((HANDLE)Handles[i], Buffer) == FALSE, "GetPointerDeviceOrientation(%p) succeeded\n", (PVOID)Handles[i]);
        ok(GetLastError() == ERROR_INVALID_HANDLE, "GetPointerDeviceOrientation(%p): last error %lu\n", (PVOID)Handles[i], GetLastError());
        SetLastError(PENDING_ERROR);
        ok(pInputSpace((HANDLE)Handles[i], Buffer) == FALSE, "GetPointerDeviceInputSpace(%p) succeeded\n", (PVOID)Handles[i]);
        ok(GetLastError() == ERROR_INVALID_HANDLE, "GetPointerDeviceInputSpace(%p): last error %lu\n", (PVOID)Handles[i], GetLastError());
    }

    SetLastError(PENDING_ERROR);
    ok(pOrientation((HANDLE)1, NULL) == FALSE, "GetPointerDeviceOrientation(1, NULL) succeeded\n");
    ok(GetLastError() == ERROR_INVALID_HANDLE, "GetPointerDeviceOrientation(1, NULL): last error %lu\n", GetLastError());
    SetLastError(PENDING_ERROR);
    ok(pInputSpace(NULL, NULL) == FALSE, "GetPointerDeviceInputSpace(NULL, NULL) succeeded\n");
    ok(GetLastError() == ERROR_INVALID_HANDLE, "GetPointerDeviceInputSpace(NULL, NULL): last error %lu\n", GetLastError());
}
