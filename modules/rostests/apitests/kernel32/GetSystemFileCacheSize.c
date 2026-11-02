/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for GetSystemFileCacheSize
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#include <ndk/exfuncs.h>

typedef BOOL (WINAPI *FN_GetSystemFileCacheSize)(PSIZE_T, PSIZE_T, PDWORD);

START_TEST(GetSystemFileCacheSize)
{
    FN_GetSystemFileCacheSize pGetSystemFileCacheSize =
        (FN_GetSystemFileCacheSize)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetSystemFileCacheSize");
    SIZE_T Minimum = 1, Maximum = 2;
    DWORD Flags = 3, Error;
    BOOL Ret;
    SYSTEM_FILECACHE_INFORMATION Info;
    NTSTATUS Status;
    ULONG Length = 0;

    if (!pGetSystemFileCacheSize)
    {
        skip("GetSystemFileCacheSize is not available\n");
        return;
    }

    SetLastError(0xdeadbeef);
    Ret = pGetSystemFileCacheSize(&Minimum, &Maximum, &Flags);
    Error = GetLastError();
    if (Ret)
    {
        ok(Minimum <= Maximum, "Minimum %Iu above maximum %Iu\n", Minimum, Maximum);
        ok((Minimum % 4096) == 0, "Minimum %Iu is not a number of pages\n", Minimum);
        ok((Flags & ~0xF) == 0, "Flags 0x%lx\n", Flags);
    }
    else
    {
        /* A 32-bit process on a 64-bit Windows: the 16 TB maximum does not fit. Nothing is stored. */
        ok(Error == ERROR_ARITHMETIC_OVERFLOW, "Error %lu\n", Error);
        ok(Minimum == 1 && Maximum == 2 && Flags == 3, "Outputs changed on failure: %Iu %Iu %lu\n", Minimum, Maximum, Flags);
    }
    trace("GetSystemFileCacheSize: %d error %lu min %Iu max %Iu flags 0x%lx\n", Ret, Error, Minimum, Maximum, Flags);

    /* The native query behind it, in both classes the kernel offers */
    Status = NtQuerySystemInformation(SystemFileCacheInformationEx, &Info, sizeof(Info), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Length == sizeof(Info), "Length %lu\n", Length);
    ok(Info.MinimumWorkingSet != 0, "MinimumWorkingSet is 0\n");
    ok(Info.MinimumWorkingSet <= Info.MaximumWorkingSet, "Minimum %Iu maximum %Iu\n",
       Info.MinimumWorkingSet, Info.MaximumWorkingSet);

    Status = NtQuerySystemInformation(SystemFileCacheInformation, &Info, sizeof(Info), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Info.MinimumWorkingSet != 0, "MinimumWorkingSet is 0\n");

    Length = 0;
    Status = NtQuerySystemInformation(SystemFileCacheInformationEx, &Info, sizeof(Info) - 1, &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok(Length == sizeof(Info), "Length %lu\n", Length);
}
