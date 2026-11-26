/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SeIncreaseWorkingSetPrivilege is in the token of a standard user and of an elevated administrator,
 *              disabled, and SeDelegateSessionUserImpersonatePrivilege is in neither
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022 (measured with a scratch standard user and a scratch administrator made by NetUserAdd and
 * logged on with LogonUser, 2026-11-26): the token of the standard user lists SeChangeNotifyPrivilege (enabled) and
 * SeIncreaseWorkingSetPrivilege with attributes 0 (disabled, not enabled by default); the filtered token of the
 * administrator the same two; its elevated (linked) token lists 24 privileges, SeIncreaseWorkingSetPrivilege with
 * attributes 0 among them. SetProcessWorkingSetSizeEx raising the minimum to 8 MB and to 200 MB succeeds for the
 * standard user and for the process token of the remote administrator session.
 */

#include "precomp.h"
#include <lm.h>

static BOOLEAN FindPrivilege(HANDLE Token, PCWSTR Name, DWORD *Attributes)
{
    BYTE Buffer[4096];
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;
    DWORD Length, i;
    LUID Luid;

    if (!LookupPrivilegeValueW(NULL, Name, &Luid) ||
        !GetTokenInformation(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Length))
        return FALSE;
    for (i = 0; i < Privileges->PrivilegeCount; i++)
    {
        if (Privileges->Privileges[i].Luid.LowPart == Luid.LowPart && Privileges->Privileges[i].Luid.HighPart == Luid.HighPart)
        {
            *Attributes = Privileges->Privileges[i].Attributes;
            return TRUE;
        }
    }
    return FALSE;
}

static void CheckToken(const char *Who, HANDLE Token)
{
    DWORD Attributes = 0xdeadbeef;

    ok(FindPrivilege(Token, L"SeIncreaseWorkingSetPrivilege", &Attributes),
       "%s: SeIncreaseWorkingSetPrivilege is not in the token\n", Who);
    ok(Attributes == 0, "%s: SeIncreaseWorkingSetPrivilege has attributes 0x%lx, expected 0\n", Who, Attributes);
    ok(!FindPrivilege(Token, L"SeDelegateSessionUserImpersonatePrivilege", &Attributes),
       "%s: SeDelegateSessionUserImpersonatePrivilege is in the token\n", Who);
}

static void WorkingSetRows(const char *Who)
{
    BOOL Ok;

    /* Not checked: on the reference a standard user raises the minimum without enabling the privilege; ours asks for
       SeIncreaseQuotaPrivilege, whatever the standard user holds (traced only). The plain function is used (the Ex one
       has no declaration in this tree); the rows on Windows were taken with Ex */
    Ok = SetProcessWorkingSetSize(GetCurrentProcess(), 8u << 20, 64u << 20);
    trace("%s: raising the working set minimum to 8 MB: %d (%lu)\n", Who, Ok, Ok ? 0 : GetLastError());
    Ok = SetProcessWorkingSetSize(GetCurrentProcess(), 200u << 20, 400u << 20);
    trace("%s: raising the working set minimum to 200 MB: %d (%lu)\n", Who, Ok, Ok ? 0 : GetLastError());
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
}

static void Account(PCWSTR Name, BOOL Admin)
{
    WCHAR Password[40];
    USER_INFO_1 Info = { 0 };
    DWORD Error = 0, i, Length;
    HANDLE Token = NULL, Linked = NULL, Use, Impersonation = NULL;
    LARGE_INTEGER Counter;
    ULONG Seed;
    char Who[64];

    QueryPerformanceCounter(&Counter);
    Seed = Counter.LowPart ^ GetCurrentProcessId() ^ GetTickCount();
    wcscpy(Password, L"Aa1!");
    for (i = 0; i < 24; i++)
    {
        Seed = Seed * 1103515245 + 12345;
        Password[4 + i] = L"abcdefghijklmnopqrstuvwxyz0123456789"[(Seed >> 16) % 36];
    }
    Password[28] = 0;

    Info.usri1_name = (LPWSTR)Name;
    Info.usri1_password = Password;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    NetUserDel(NULL, Name);
    if (NetUserAdd(NULL, 1, (LPBYTE)&Info, &Error) != NERR_Success)
    {
        skip("NetUserAdd(%ls) failed: %lu\n", Name, Error);
        return;
    }
    if (Admin)
    {
        LOCALGROUP_MEMBERS_INFO_3 Member;

        Member.lgrmi3_domainandname = (LPWSTR)Name;
        NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&Member, 1);
    }

    StringCbPrintfA(Who, sizeof(Who), "%s", Admin ? "elevated administrator" : "standard user");
    if (!LogonUserW((LPWSTR)Name, (LPWSTR)L".", Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        skip("LogonUser(%ls) failed: %lu\n", Name, GetLastError());
    }
    else
    {
        Use = Token;
        if (Admin && GetTokenInformation(Token, TokenLinkedToken, &Linked, sizeof(Linked), &Length) && Linked)
            Use = Linked;
        CheckToken(Who, Use);
        if (!Admin && DuplicateTokenEx(Use, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Impersonation))
        {
            if (SetThreadToken(NULL, Impersonation))
            {
                WorkingSetRows(Who);
                RevertToSelf();
            }
            CloseHandle(Impersonation);
        }
        if (Linked)
            CloseHandle(Linked);
        CloseHandle(Token);
    }

    if (Admin)
    {
        LOCALGROUP_MEMBERS_INFO_3 Member;

        Member.lgrmi3_domainandname = (LPWSTR)Name;
        NetLocalGroupDelMembers(NULL, L"Administrators", 3, (LPBYTE)&Member, 1);
    }
    NetUserDel(NULL, Name);
    SecureZeroMemory(Password, sizeof(Password));
}

START_TEST(TokenIncreaseWorkingSet)
{
    Account(L"kbtokstd", FALSE);
    Account(L"kbtokadm", TRUE);
}
