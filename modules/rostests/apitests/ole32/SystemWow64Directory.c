/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for CoGetSystemWow64DirectoryW of ole32.dll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86 callers): CoGetSystemWow64DirectoryW(buffer, 260) fills the
 * buffer and returns 19, the length of "C:\Windows\SysWOW64", like GetSystemWow64DirectoryW.
 */

#include <wine/test.h>
#include <windef.h>
#include <winbase.h>

typedef UINT (WINAPI *CoGetSystemWow64DirectoryW_t)(LPWSTR, UINT);

START_TEST(SystemWow64Directory)
{
    HMODULE ole32 = LoadLibraryA("ole32.dll");
    CoGetSystemWow64DirectoryW_t pCoGetSystemWow64DirectoryW;
    WCHAR expected[MAX_PATH], actual[MAX_PATH];
    UINT expected_len, actual_len;

    pCoGetSystemWow64DirectoryW = (CoGetSystemWow64DirectoryW_t)GetProcAddress(ole32, "CoGetSystemWow64DirectoryW");
    ok(pCoGetSystemWow64DirectoryW != NULL, "CoGetSystemWow64DirectoryW is not exported\n");
    if (!pCoGetSystemWow64DirectoryW)
        return;

    memset(expected, 0, sizeof(expected));
    memset(actual, 0, sizeof(actual));
    expected_len = GetSystemWow64DirectoryW(expected, MAX_PATH);
    actual_len = pCoGetSystemWow64DirectoryW(actual, MAX_PATH);
    ok(actual_len == expected_len, "got %u, expected %u\n", actual_len, expected_len);
    ok(!lstrcmpW(actual, expected), "got %ls, expected %ls\n", actual, expected);
    if (expected_len)
        ok(actual_len == lstrlenW(actual), "length %u does not match the string %ls\n", actual_len, actual);
}
