/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for CveEventWrite of advapi32
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results are those of Windows 10 22H2 (x64 and x86): any identifier but NULL is a success and the last
 * error is not touched.
 */

#include "precomp.h"

typedef ULONG (WINAPI *FN_CVE)(PCWSTR, PCWSTR);

#define PENDING 0xdeadf00d

START_TEST(CveEventWrite)
{
    FN_CVE pCve = (FN_CVE)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "CveEventWrite");
    ULONG Ret;

    if (!pCve && is_reactos() && !GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount64"))
    {
        skip("No NT 6 exports\n");
        return;
    }
    ok(pCve != NULL, "CveEventWrite is not exported\n");
    if (!pCve)
        return;

    SetLastError(PENDING);
    Ret = pCve(L"CVE-2020-0601", L"details");
    ok(Ret == ERROR_SUCCESS && GetLastError() == PENDING, "valid: %lu, error %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pCve(L"CVE-2020-0601", NULL);
    ok(Ret == ERROR_SUCCESS && GetLastError() == PENDING, "no details: %lu, error %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pCve(L"nonsense", L"x");
    ok(Ret == ERROR_SUCCESS && GetLastError() == PENDING, "unusual identifier: %lu, error %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pCve(L"", L"x");
    ok(Ret == ERROR_SUCCESS && GetLastError() == PENDING, "empty identifier: %lu, error %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pCve(NULL, L"x");
    ok(Ret == ERROR_INVALID_PARAMETER && GetLastError() == PENDING, "NULL identifier: %lu, error %lu\n", Ret, GetLastError());
}
