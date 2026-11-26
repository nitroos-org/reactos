/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A key is opened for CREATE_SUB_KEY by callers below its mandatory label only when Windows allows it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The rows are those of Windows Server 2022: the key's DACL grants Everyone everything, its label is none, Low,
 * Medium or High (no-write-up), and the caller is a thread impersonating a copy of the process token with the
 * integrity level Untrusted, Low, Medium or High. A key without a label counts as Medium.
 */

#include "precomp.h"
#include <sddl.h>
#include <aclapi.h>

/* the declaration needs a newer header version than these tests are compiled with */
LONG WINAPI RegDeleteTreeW(HKEY, LPCWSTR);

static HANDLE ImpersonationAtLevel(PCWSTR LevelSid)
{
    HANDLE Process, Copy = NULL;
    PSID Sid = NULL;
    TOKEN_MANDATORY_LABEL Tml;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &Process))
        return NULL;
    if (!DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Copy))
        Copy = NULL;
    CloseHandle(Process);
    if (!Copy)
        return NULL;

    ConvertStringSidToSidW(LevelSid, &Sid);
    Tml.Label.Sid = Sid;
    Tml.Label.Attributes = SE_GROUP_INTEGRITY;
    if (!SetTokenInformation(Copy, TokenIntegrityLevel, &Tml, sizeof(Tml) + GetLengthSid(Sid)))
    {
        CloseHandle(Copy);
        Copy = NULL;
    }
    LocalFree(Sid);
    return Copy;
}

START_TEST(KeyCreateIntegrity)
{
    static const PCWSTR Labels[] = { L"", L"S:(ML;;NW;;;LW)", L"S:(ML;;NW;;;ME)", L"S:(ML;;NW;;;HI)" };
    static const PCWSTR Levels[] = { L"S-1-16-0", L"S-1-16-4096", L"S-1-16-8192", L"S-1-16-12288" };
    /* [label][level]: ERROR_SUCCESS or ERROR_ACCESS_DENIED for RegOpenKeyEx(KEY_CREATE_SUB_KEY) */
    static const DWORD Expected[4][4] =
    {
        { ERROR_ACCESS_DENIED, ERROR_ACCESS_DENIED, ERROR_SUCCESS, ERROR_SUCCESS },
        { ERROR_ACCESS_DENIED, ERROR_SUCCESS,       ERROR_SUCCESS, ERROR_SUCCESS },
        { ERROR_ACCESS_DENIED, ERROR_ACCESS_DENIED, ERROR_SUCCESS, ERROR_SUCCESS },
        { ERROR_ACCESS_DENIED, ERROR_ACCESS_DENIED, ERROR_ACCESS_DENIED, ERROR_SUCCESS },
    };
    HKEY Root = NULL;
    DWORD Disp;
    int i, j;

    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\KeyCreateIntegrity");
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\KeyCreateIntegrity", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Root, &Disp) != ERROR_SUCCESS)
    {
        skip("No administrator rights\n");
        return;
    }

    for (i = 0; i < 4; i++)
    {
        WCHAR Sddl[64], Path[96];
        PSECURITY_DESCRIPTOR Sd;
        SECURITY_ATTRIBUTES Sa;
        HKEY Parent;
        HANDLE Token;

        wsprintfW(Sddl, L"D:(A;;KA;;;WD)%ls", Labels[i]);
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
        {
            skip("SDDL\n");
            continue;
        }
        Sa.nLength = sizeof(Sa);
        Sa.lpSecurityDescriptor = Sd;
        Sa.bInheritHandle = FALSE;
        wsprintfW(Path, L"l%d", i);
        ok_long(RegCreateKeyExW(Root, Path, 0, NULL, 0, KEY_ALL_ACCESS, &Sa, &Parent, &Disp), ERROR_SUCCESS);
        LocalFree(Sd);
        RegCloseKey(Parent);

        wsprintfW(Path, L"SOFTWARE\\KeyCreateIntegrity\\l%d", i);
        for (j = 0; j < 4; j++)
        {
            HKEY Open = NULL, Child = NULL;
            LONG Error, Created;

            Token = ImpersonationAtLevel(Levels[j]);
            if (!Token)
            {
                skip("No token at level %d\n", j);
                continue;
            }
            ok(SetThreadToken(NULL, Token), "SetThreadToken failed: %lu\n", GetLastError());
            Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_CREATE_SUB_KEY, &Open);
            ok(Error == (LONG)Expected[i][j], "label %d, level %d: open %ld, expected %lu\n", i, j, Error, Expected[i][j]);
            if (Error == ERROR_SUCCESS)
            {
                Created = RegCreateKeyExW(Open, L"c", 0, NULL, 0, KEY_READ, NULL, &Child, &Disp);
                ok(Created == ERROR_SUCCESS, "label %d, level %d: create %ld\n", i, j, Created);
                if (Created == ERROR_SUCCESS)
                    RegCloseKey(Child);
                RegCloseKey(Open);
            }
            SetThreadToken(NULL, NULL);
            CloseHandle(Token);
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\KeyCreateIntegrity\\l0\\c");
            wsprintfW(Path, L"SOFTWARE\\KeyCreateIntegrity\\l%d", i);
        }
    }

    RegCloseKey(Root);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\KeyCreateIntegrity");
}
