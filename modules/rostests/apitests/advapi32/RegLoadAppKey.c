/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test the result of RegLoadAppKeyA/W
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Application hives are not implemented. Whatever a system answers, a call
 * must never report success and hand back no key: a caller that gets success
 * uses the key. Where the call is not implemented it fails with
 * ERROR_CALL_NOT_IMPLEMENTED and the result is cleared (the clearing on a
 * failure is this system's contract, not a measured Windows result).
 */

static LSTATUS (WINAPI *pRegLoadAppKeyA)(LPCSTR, PHKEY, REGSAM, DWORD, DWORD);
static LSTATUS (WINAPI *pRegLoadAppKeyW)(LPCWSTR, PHKEY, REGSAM, DWORD, DWORD);

#define SENTINEL ((HKEY)(ULONG_PTR)0x12345670)

static
VOID
CheckResult(PCSTR Name, LSTATUS Error, HKEY Key)
{
    if (Error != ERROR_SUCCESS)
    {
        ok(Key == NULL, "%s failed with %lu and left key %p\n", Name, Error, Key);
    }
    else if (Key == NULL || Key == SENTINEL)
    {
        ok(0, "%s returned success and no key (%p)\n", Name, Key);
    }
    else
    {
        RegCloseKey(Key);
    }
}

START_TEST(RegLoadAppKey)
{
    WCHAR TempPath[MAX_PATH], FileW[MAX_PATH];
    CHAR FileA[MAX_PATH];
    HKEY Key;
    LSTATUS Error;
    HMODULE Advapi32 = GetModuleHandleW(L"advapi32.dll");

    pRegLoadAppKeyA = (PVOID)GetProcAddress(Advapi32, "RegLoadAppKeyA");
    pRegLoadAppKeyW = (PVOID)GetProcAddress(Advapi32, "RegLoadAppKeyW");
    if (!pRegLoadAppKeyA || !pRegLoadAppKeyW)
    {
        skip("RegLoadAppKey is not exported\n");
        return;
    }

    GetTempPathW(RTL_NUMBER_OF(TempPath), TempPath);
    StringCbPrintfW(FileW, sizeof(FileW), L"%sReactOS-RegLoadAppKey-%lu.hiv", TempPath, GetCurrentProcessId());
    WideCharToMultiByte(CP_ACP, 0, FileW, -1, FileA, sizeof(FileA), NULL, NULL);

    Key = SENTINEL;
    Error = pRegLoadAppKeyW(FileW, &Key, KEY_READ | KEY_WRITE, 0, 0);
    CheckResult("RegLoadAppKeyW", Error, Key);
    if (Error == ERROR_SUCCESS)
        goto Cleanup;
    ok_dec(Error, ERROR_CALL_NOT_IMPLEMENTED);

    Key = SENTINEL;
    Error = pRegLoadAppKeyA(FileA, &Key, KEY_READ, 0, 0);
    CheckResult("RegLoadAppKeyA", Error, Key);
    ok_dec(Error, ERROR_CALL_NOT_IMPLEMENTED);

Cleanup:
    /* A system that does implement it may have made the file */
    DeleteFileW(FileW);
    StringCbCatW(FileW, sizeof(FileW), L".LOG1");
    DeleteFileW(FileW);
    FileW[wcslen(FileW) - 1] = L'2';
    DeleteFileW(FileW);
}
