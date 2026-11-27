/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     CreateEnvironmentBlock adds the values of the user's 'Volatile Environment\<session id>' key, the
 *              session being the one of the token: this is where SESSIONNAME (Console for the console session)
 *              comes from for a program started by the logon.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected rows are what Windows Server 2022 does (measured with a throw-away copy of the system, values written
 * under HKCU\Volatile Environment of the console user): a REG_SZ value of the key of the token's session is a variable of
 * the block, a REG_EXPAND_SZ value is expanded against the block, an empty value is no variable (CLIENTNAME is
 * written empty and is not in the environment of the shell), a value of the key of another session is not in it.
 */

#include "precomp.h"
#include <userenv.h>

static PCWSTR FindVariable(PCWSTR Env, PCWSTR Name)
{
    SIZE_T Length = wcslen(Name);

    for (; *Env; Env += wcslen(Env) + 1)
    {
        if (!_wcsnicmp(Env, Name, Length) && Env[Length] == L'=')
            return Env + Length + 1;
    }
    return NULL;
}

static void CheckBlock(HANDLE Token, PCWSTR Row, BOOL Present)
{
    WCHAR Expected[128];
    LPVOID Env = NULL;
    PCWSTR Value, User;
    BOOL Ok = CreateEnvironmentBlock(&Env, Token, FALSE);

    ok(Ok, "%ls: CreateEnvironmentBlock failed: %lu\n", Row, GetLastError());
    if (!Ok)
        return;

    Value = FindVariable(Env, L"KBSESSIONSZ");
    if (Present)
        ok(Value && !wcscmp(Value, L"abc"), "%ls: KBSESSIONSZ is %ls, wanted abc\n", Row, Value ? Value : L"(none)");
    else
        ok(Value == NULL, "%ls: KBSESSIONSZ is %ls, wanted none\n", Row, Value ? Value : L"(none)");

    User = FindVariable(Env, L"USERNAME");
    Value = FindVariable(Env, L"KBSESSIONEXP");
    if (!Present)
    {
        ok(Value == NULL, "%ls: KBSESSIONEXP is %ls, wanted none\n", Row, Value ? Value : L"(none)");
    }
    else if (User)
    {
        StringCchPrintfW(Expected, RTL_NUMBER_OF(Expected), L"%ls-x", User);
        ok(Value && !wcscmp(Value, Expected), "%ls: KBSESSIONEXP is %ls, wanted %ls\n", Row, Value ? Value : L"(none)", Expected);
    }

    ok(FindVariable(Env, L"KBSESSIONEMPTY") == NULL, "%ls: an empty value made a variable\n", Row);
    ok(FindVariable(Env, L"KBSESSIONOTHER") == NULL, "%ls: a value of another session's key is in the block\n", Row);
    DestroyEnvironmentBlock(Env);
}

START_TEST(CreateEnvironmentBlockSession)
{
    static const WCHAR Abc[] = L"abc";
    static const WCHAR Exp[] = L"%USERNAME%-x";
    static const WCHAR Empty[] = L"";
    static const WCHAR Zzz[] = L"zzz";
    HANDLE Token = NULL;
    HKEY hUser = NULL, hVolatile = NULL, hSession = NULL, hOther = NULL;
    WCHAR Name[16], OtherName[16];
    DWORD SessionId = 0, Length, Disposition = 0, OtherDisposition = 0;
    LONG Error;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &Token) ||
        !GetTokenInformation(Token, TokenSessionId, &SessionId, sizeof(SessionId), &Length))
    {
        skip("no token: %lu\n", GetLastError());
        return;
    }

    Error = RegOpenCurrentUser(KEY_ALL_ACCESS, &hUser);
    if (Error != ERROR_SUCCESS)
    {
        skip("no user hive: %lu\n", Error);
        goto done;
    }

    Error = RegCreateKeyExW(hUser, L"Volatile Environment", 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &hVolatile, NULL);
    if (Error != ERROR_SUCCESS)
    {
        skip("cannot create the volatile environment key: %lu\n", Error);
        goto done;
    }

    StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"%lu", SessionId);
    StringCchPrintfW(OtherName, RTL_NUMBER_OF(OtherName), L"%lu", SessionId + 77);
    Error = RegCreateKeyExW(hVolatile, Name, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &hSession, &Disposition);
    ok(Error == ERROR_SUCCESS, "cannot create the key of the session: %lu\n", Error);
    Error = RegCreateKeyExW(hVolatile, OtherName, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &hOther, &OtherDisposition);
    ok(Error == ERROR_SUCCESS, "cannot create the key of another session: %lu\n", Error);
    if (!hSession || !hOther)
        goto done;

    CheckBlock(Token, L"before", FALSE);

    RegSetValueExW(hSession, L"KBSESSIONSZ", 0, REG_SZ, (const BYTE *)Abc, sizeof(Abc));
    RegSetValueExW(hSession, L"KBSESSIONEXP", 0, REG_EXPAND_SZ, (const BYTE *)Exp, sizeof(Exp));
    RegSetValueExW(hSession, L"KBSESSIONEMPTY", 0, REG_SZ, (const BYTE *)Empty, sizeof(Empty));
    RegSetValueExW(hOther, L"KBSESSIONOTHER", 0, REG_SZ, (const BYTE *)Zzz, sizeof(Zzz));
    CheckBlock(Token, L"values set", TRUE);

    RegDeleteValueW(hSession, L"KBSESSIONSZ");
    RegDeleteValueW(hSession, L"KBSESSIONEXP");
    RegDeleteValueW(hSession, L"KBSESSIONEMPTY");
    RegDeleteValueW(hOther, L"KBSESSIONOTHER");
    CheckBlock(Token, L"values deleted", FALSE);

done:
    if (hOther)
    {
        RegCloseKey(hOther);
        if (OtherDisposition == REG_CREATED_NEW_KEY)
            RegDeleteKeyW(hVolatile, OtherName);
    }
    if (hSession)
    {
        RegCloseKey(hSession);
        if (Disposition == REG_CREATED_NEW_KEY)
            RegDeleteKeyW(hVolatile, Name);
    }
    if (hVolatile)
        RegCloseKey(hVolatile);
    if (hUser)
        RegCloseKey(hUser);
    if (Token)
        CloseHandle(Token);
}
