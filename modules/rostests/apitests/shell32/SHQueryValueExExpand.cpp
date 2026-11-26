/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for a REG_EXPAND_SZ association command that expands to a long string
 *              (SHQueryValueExW sizes are bytes; AssocQueryStringW gives the whole command)
 */

#include "shelltest.h"
#include <shlwapi.h>

#define SCRATCH_KEY  L"Software\\RosTestShQueryValueExExpand"
#define SCRATCH_EXT  L".rostestexpand"
#define SCRATCH_PID  L"RosTestExpandFile"
#define VARIABLE     L"RTXLONG"

static void TestSHQueryValueExW(UINT cchVariable)
{
    static const WCHAR raw[] = L"%" VARIABLE L"%";
    WCHAR *value = (WCHAR *)malloc((cchVariable + 1) * sizeof(WCHAR));
    WCHAR *buf = (WCHAR *)malloc((cchVariable + 64) * sizeof(WCHAR));
    DWORD size, type, ret, expandedBytes;
    HKEY hKey;
    UINT i;

    for (i = 0; i < cchVariable; ++i)
        value[i] = L'a' + (i % 26);
    value[cchVariable] = UNICODE_NULL;
    SetEnvironmentVariableW(VARIABLE, value);
    expandedBytes = (cchVariable + 1) * sizeof(WCHAR);

    ret = RegCreateKeyExW(HKEY_CURRENT_USER, SCRATCH_KEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    ok_dec(ret, ERROR_SUCCESS);
    ret = RegSetValueExW(hKey, L"x", 0, REG_EXPAND_SZ, (const BYTE *)raw, sizeof(raw));
    ok_dec(ret, ERROR_SUCCESS);

    /* the size: bytes of the expanded string */
    size = 0;
    type = 99;
    ret = SHQueryValueExW(hKey, L"x", NULL, &type, NULL, &size);
    ok_dec(ret, ERROR_SUCCESS);
    ok_dec(type, REG_SZ);
    ok(size >= expandedBytes, "%u characters: size %lu, expected at least %lu bytes\n", cchVariable, size, expandedBytes);

    /* a buffer of that size takes the whole string */
    memset(buf, 0x7e, (cchVariable + 64) * sizeof(WCHAR));
    size = expandedBytes;
    type = 99;
    ret = SHQueryValueExW(hKey, L"x", NULL, &type, buf, &size);
    ok_dec(ret, ERROR_SUCCESS);
    ok_dec(type, REG_SZ);
    ok(lstrcmpW(buf, value) == 0, "%u characters: expanded string is %u characters long\n", cchVariable, (UINT)lstrlenW(buf));

    /* one character short: more data, and the size says how much */
    memset(buf, 0x7e, (cchVariable + 64) * sizeof(WCHAR));
    size = expandedBytes - sizeof(WCHAR);
    ret = SHQueryValueExW(hKey, L"x", NULL, &type, buf, &size);
    ok_dec(ret, ERROR_MORE_DATA);
    ok(size >= expandedBytes, "%u characters: size %lu, expected at least %lu bytes\n", cchVariable, size, expandedBytes);

    RegCloseKey(hKey);
    SHDeleteKeyW(HKEY_CURRENT_USER, SCRATCH_KEY);
    SetEnvironmentVariableW(VARIABLE, NULL);
    free(buf);
    free(value);
}

static void TestAssocCommand(UINT cchVariable)
{
    static const WCHAR raw[] = L"%" VARIABLE L"%";
    WCHAR *value = (WCHAR *)malloc((cchVariable + 1) * sizeof(WCHAR));
    WCHAR *out = (WCHAR *)malloc((cchVariable + 4096) * sizeof(WCHAR));
    DWORD cch;
    HRESULT hr;
    HKEY hKey;
    UINT i;

    for (i = 0; i < cchVariable; ++i)
        value[i] = L'a' + (i % 26);
    value[cchVariable] = UNICODE_NULL;
    SetEnvironmentVariableW(VARIABLE, value);

    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\" SCRATCH_EXT, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL))
    {
        skip("cannot create the scratch association\n");
        goto Quit;
    }
    RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE *)SCRATCH_PID, sizeof(SCRATCH_PID));
    RegCloseKey(hKey);
    RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\" SCRATCH_PID L"\\shell\\open\\command", 0, NULL, 0,
                    KEY_ALL_ACCESS, NULL, &hKey, NULL);
    RegSetValueExW(hKey, NULL, 0, REG_EXPAND_SZ, (const BYTE *)raw, sizeof(raw));
    RegCloseKey(hKey);

    memset(out, 0, (cchVariable + 4096) * sizeof(WCHAR));
    cch = cchVariable + 4096;
    hr = AssocQueryStringW(ASSOCF_NOTRUNCATE, ASSOCSTR_COMMAND, SCRATCH_EXT, L"open", out, &cch);
    ok_hex(hr, S_OK);
    ok(lstrcmpW(out, value) == 0, "%u characters: command is %u characters long\n", cchVariable, (UINT)lstrlenW(out));

    SHDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\" SCRATCH_PID);
    SHDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\" SCRATCH_EXT);
Quit:
    SetEnvironmentVariableW(VARIABLE, NULL);
    free(out);
    free(value);
}

START_TEST(SHQueryValueExExpand)
{
    static const UINT lengths[] = { 20, 300, 700, 1200 };
    UINT i;

    for (i = 0; i < _countof(lengths); ++i)
    {
        TestSHQueryValueExW(lengths[i]);
        TestAssocCommand(lengths[i]);
    }
}
