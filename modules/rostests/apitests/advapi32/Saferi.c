/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for SaferiIsExecutableFileType and SaferiSearchMatchingHashRules
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86) with no policy values: the JDK imports the first function, PowerShell
 * 7 the second one (delay loaded).
 */

#include "precomp.h"

#include <winsafer.h>

typedef BOOL (WINAPI *IsExecutableFileType_t)(PCWSTR, BOOLEAN);
typedef BOOL (WINAPI *SearchMatchingHashRules_t)(ALG_ID, PBYTE, DWORD, DWORD, PDWORD, PDWORD);

static void test_executable_types(void)
{
    static const struct
    {
        PCWSTR path;
        BOOL expected;          /* started as a program */
        BOOL expected_shell;    /* started through ShellExecute */
    } names[] =
    {
        { L"C:\\x\\a.exe", TRUE, FALSE },
        { L"C:\\x\\a.EXE", TRUE, FALSE },
        { L"a.exe", TRUE, FALSE },
        { L".exe", TRUE, FALSE },
        { L"\\\\srv\\sh\\a.exe", TRUE, FALSE },
        { L"C:\\x\\a.bat", TRUE, TRUE },
        { L"C:\\x\\a.Bat", TRUE, TRUE },
        { L"C:\\x\\a.cmd", TRUE, TRUE },
        { L"C:\\x\\a.com", TRUE, TRUE },
        { L"C:\\x\\a.lnk", TRUE, TRUE },
        { L"C:\\x\\a.msi", TRUE, TRUE },
        { L"C:\\x\\a.scr", TRUE, TRUE },
        { L"C:\\x\\a.reg", TRUE, TRUE },
        { L"C:\\x\\a.url", TRUE, TRUE },
        { L"C:\\x\\a.hta", TRUE, TRUE },
        { L"C:\\x\\a.pif", TRUE, TRUE },
        { L"C:\\x\\a.cpl", TRUE, TRUE },
        { L"C:\\x\\a.inf", TRUE, TRUE },
        { L"C:\\x\\a.msc", TRUE, TRUE },
        { L"C:\\x\\a.chm", TRUE, TRUE },
        { L"C:\\x\\a.hlp", TRUE, TRUE },
        { L"C:\\x\\a.mdb", TRUE, TRUE },
        { L"C:\\x\\a.ocx", TRUE, TRUE },
        { L"C:\\x\\a.crt", TRUE, TRUE },
        { L"C:\\x\\a.bas", TRUE, TRUE },
        { L"C:\\x\\a.shs", TRUE, TRUE },
        { L"C:\\x\\a.ins", TRUE, TRUE },
        { L"C:\\x\\a.isp", TRUE, TRUE },
        { L"C:\\x\\a.mst", TRUE, TRUE },
        { L"C:\\x\\a.msp", TRUE, TRUE },
        { L"C:\\x\\a.pcd", TRUE, TRUE },
        { L"C:\\x\\a.vb", TRUE, TRUE },
        { L"C:\\x\\a.wsc", TRUE, TRUE },
        { L"C:\\x\\a.ade", TRUE, TRUE },
        { L"C:\\x\\a.adp", TRUE, TRUE },
        { L"C:\\x\\a.mde", TRUE, TRUE },
        /* not in the default list */
        { L"C:\\x\\a.txt", FALSE, FALSE },
        { L"C:\\x\\a.dll", FALSE, FALSE },
        { L"C:\\x\\a.sys", FALSE, FALSE },
        { L"C:\\x\\a.js", FALSE, FALSE },
        { L"C:\\x\\a.vbs", FALSE, FALSE },
        { L"C:\\x\\a.vbe", FALSE, FALSE },
        { L"C:\\x\\a.wsf", FALSE, FALSE },
        { L"C:\\x\\a.wsh", FALSE, FALSE },
        { L"C:\\x\\a.ps1", FALSE, FALSE },
        { L"C:\\x\\a.jar", FALSE, FALSE },
        { L"C:\\x\\a.msix", FALSE, FALSE },
        { L"C:\\x\\a.zip", FALSE, FALSE },
        /* the extension is the whole of what follows the last dot of the name */
        { L"a.", FALSE, FALSE },
        { L"a", FALSE, FALSE },
        { L"C:\\x.exe\\a", FALSE, FALSE },
        { L"C:\\x\\a.exe ", FALSE, FALSE },
        { L"C:\\x\\a.exe.txt", FALSE, FALSE },
        { L"C:\\x\\a.vbs.x", FALSE, FALSE },
    };
    IsExecutableFileType_t pIsExecutableFileType =
        (IsExecutableFileType_t)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "SaferiIsExecutableFileType");
    BOOL ret;
    DWORD error;
    size_t i;

    ok(pIsExecutableFileType != NULL, "SaferiIsExecutableFileType is not exported\n");
    if (!pIsExecutableFileType)
        return;

    for (i = 0; i < ARRAYSIZE(names); i++)
    {
        SetLastError(0xbadbad00);
        ret = pIsExecutableFileType(names[i].path, FALSE) != 0;
        error = GetLastError();
        ok(ret == names[i].expected, "%ls: returned %d\n", names[i].path, ret);
        if (names[i].expected)
            ok(error == 0xbadbad00, "%ls: error %lu\n", names[i].path, error);
        else
            ok(error == ERROR_NOT_FOUND, "%ls: error %lu\n", names[i].path, error);

        SetLastError(0xbadbad00);
        ret = pIsExecutableFileType(names[i].path, TRUE) != 0;
        error = GetLastError();
        ok(ret == names[i].expected_shell, "%ls (shell): returned %d\n", names[i].path, ret);
        if (names[i].expected_shell)
            ok(error == 0xbadbad00, "%ls (shell): error %lu\n", names[i].path, error);
        else
            ok(error == ERROR_NOT_FOUND, "%ls (shell): error %lu\n", names[i].path, error);
    }

    SetLastError(0xbadbad00);
    ret = pIsExecutableFileType(L"", FALSE) != 0;
    error = GetLastError();
    ok(ret == FALSE, "empty name: returned %d\n", ret);
    ok(error == ERROR_INVALID_PARAMETER, "empty name: error %lu\n", error);
}

static void test_hash_rules(void)
{
    SearchMatchingHashRules_t pSearchMatchingHashRules =
        (SearchMatchingHashRules_t)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "SaferiSearchMatchingHashRules");
    BYTE hash[64] = { 1, 2, 3 };
    DWORD level, flags, error;
    BOOL ret;

    ok(pSearchMatchingHashRules != NULL, "SaferiSearchMatchingHashRules is not exported\n");
    if (!pSearchMatchingHashRules)
        return;

    /* MD5 and SHA-256, with the size of the hash, are the hashes that a rule can have: nothing matches here */
    level = flags = 0x77;
    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(CALG_MD5, hash, 16, 100, &level, &flags);
    error = GetLastError();
    ok(ret == FALSE, "MD5: returned %d\n", ret);
    ok(error == ERROR_NOT_FOUND, "MD5: error %lu\n", error);
    ok(level == 0x77 && flags == 0x77, "MD5: outputs %lx %lx\n", level, flags);

    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(CALG_SHA_256, hash, 32, 100, &level, &flags);
    error = GetLastError();
    ok(ret == FALSE, "SHA-256: returned %d\n", ret);
    ok(error == ERROR_NOT_FOUND, "SHA-256: error %lu\n", error);

    /* the size of the file does not matter */
    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(CALG_MD5, hash, 16, 0, &level, &flags);
    ok(ret == FALSE && GetLastError() == ERROR_NOT_FOUND, "empty file: %d %lu\n", ret, GetLastError());

    /* any other algorithm, or a size that is not the one of the algorithm, is an invalid parameter */
    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(CALG_SHA1, hash, 20, 100, &level, &flags);
    ok(ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "SHA-1: %d %lu\n", ret, GetLastError());
    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(CALG_MD5, hash, 20, 100, &level, &flags);
    ok(ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "MD5 of 20 bytes: %d %lu\n", ret, GetLastError());
    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(CALG_SHA_256, hash, 16, 100, &level, &flags);
    ok(ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "SHA-256 of 16 bytes: %d %lu\n", ret, GetLastError());
    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(CALG_SHA_384, hash, 48, 100, &level, &flags);
    ok(ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "SHA-384: %d %lu\n", ret, GetLastError());
    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(0, NULL, 0, 0, &level, &flags);
    ok(ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "no hash: %d %lu\n", ret, GetLastError());
    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(CALG_MD5, NULL, 16, 100, &level, &flags);
    ok(ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "NULL hash: %d %lu\n", ret, GetLastError());

    /* the outputs are written to, a missing one is no access */
    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(CALG_MD5, hash, 16, 100, NULL, &flags);
    ok(ret == FALSE && GetLastError() == ERROR_NOACCESS, "NULL level: %d %lu\n", ret, GetLastError());
    SetLastError(0xbadbad00);
    ret = pSearchMatchingHashRules(CALG_MD5, hash, 16, 100, &level, NULL);
    ok(ret == FALSE && GetLastError() == ERROR_NOACCESS, "NULL flags: %d %lu\n", ret, GetLastError());
}

START_TEST(Saferi)
{
    test_executable_types();
    test_hash_rules();
}
