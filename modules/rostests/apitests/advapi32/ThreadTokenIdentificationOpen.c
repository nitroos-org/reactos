/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     OpenThreadToken without OpenAsSelf from a thread that impersonates at the identification level
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022 (a Low child that impersonates a higher token of its user: the impersonation comes out at the
 * identification level): OpenThreadToken(OpenAsSelf FALSE) of the thread's own token fails with
 * ERROR_BAD_IMPERSONATION_LEVEL (1346), the access check is made as the identification-level client; with
 * OpenAsSelf TRUE it succeeds. At the impersonation level both succeed. The Low child is made as in MandatoryLabelOpen
 * (a lowered duplicate of the parent's token, CreateProcessAsUser); it opens the parent's token.
 */

#include "precomp.h"

static void Rows(HANDLE Source, SECURITY_IMPERSONATION_LEVEL Level, BOOL ExpectNoSelf, PCSTR Name)
{
    HANDLE Imp = NULL, Token;
    BOOL Ret;
    DWORD Error;

    ok(DuplicateTokenEx(Source, TOKEN_IMPERSONATE | TOKEN_QUERY, NULL, Level, TokenImpersonation, &Imp),
       "%s: DuplicateTokenEx failed (%lu)\n", Name, GetLastError());
    if (!Imp)
        return;
    ok(SetThreadToken(NULL, Imp), "%s: SetThreadToken failed (%lu)\n", Name, GetLastError());

    Token = NULL;
    SetLastError(0);
    Ret = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &Token);
    Error = GetLastError();
    if (ExpectNoSelf)
    {
        ok(!Ret, "%s: OpenThreadToken(OpenAsSelf FALSE) succeeded\n", Name);
        ok(Error == ERROR_BAD_IMPERSONATION_LEVEL, "%s: error %lu, expected 1346\n", Name, Error);
    }
    else
    {
        ok(Ret, "%s: OpenThreadToken(OpenAsSelf FALSE) failed (%lu)\n", Name, Error);
    }
    if (Token)
        CloseHandle(Token);

    Token = NULL;
    Ret = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &Token);
    ok(Ret, "%s: OpenThreadToken(OpenAsSelf TRUE) failed (%lu)\n", Name, GetLastError());
    if (Token)
        CloseHandle(Token);

    RevertToSelf();
    CloseHandle(Imp);
}

static void ChildRows(DWORD ParentPid)
{
    HANDLE Process, Token = NULL;

    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ParentPid);
    ok(Process != NULL, "child: OpenProcess of the parent failed (%lu)\n", GetLastError());
    if (!Process)
        return;
    ok(OpenProcessToken(Process, TOKEN_QUERY | TOKEN_DUPLICATE, &Token), "child: OpenProcessToken of the parent failed (%lu)\n", GetLastError());
    CloseHandle(Process);
    if (!Token)
        return;
    /* the parent's token is of a higher level: the impersonation comes out at the identification level, whatever level was asked */
    Rows(Token, SecurityImpersonation, TRUE, "low child, parent's token at Impersonation");
    Rows(Token, SecurityIdentification, TRUE, "low child, parent's token at Identification");
    CloseHandle(Token);
}

static BOOL LoweredToken(PHANDLE Out)
{
    SID_IDENTIFIER_AUTHORITY LabelAuth = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    TOKEN_MANDATORY_LABEL Label;
    HANDLE Token;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
        return FALSE;
    Ret = DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, Out);
    CloseHandle(Token);
    if (!Ret)
        return FALSE;
    InitializeSid((PSID)Sid, &LabelAuth, 1);
    *GetSidSubAuthority((PSID)Sid, 0) = SECURITY_MANDATORY_LOW_RID;
    Label.Label.Sid = (PSID)Sid;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    Ret = SetTokenInformation(*Out, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid((PSID)Sid));
    if (!Ret)
        CloseHandle(*Out);
    return Ret;
}

START_TEST(ThreadTokenIdentificationOpen)
{
    char **Argv;
    HANDLE Self, Low;
    WCHAR Path[MAX_PATH], Command[MAX_PATH * 2];
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Pi;

    if (winetest_get_mainargs(&Argv) >= 4 && !strcmp(Argv[2], "child"))
    {
        ChildRows(strtoul(Argv[3], NULL, 10));
        return;
    }

    /* A thread that impersonates its own token at the identification level (measured on Windows Server 2022: Identification 1346 / ok, Impersonation ok / ok, rows imp2) */
    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Self), "OpenProcessToken failed\n");
    Rows(Self, SecurityIdentification, TRUE, "own token at Identification");
    Rows(Self, SecurityImpersonation, FALSE, "own token at Impersonation");
    CloseHandle(Self);

    /* A Low child with the parent's higher token */
    if (!LoweredToken(&Low))
    {
        skip("no lowered token (%lu)\n", GetLastError());
        return;
    }
    GetModuleFileNameW(NULL, Path, _countof(Path));
    StringCchPrintfW(Command, _countof(Command), L"\"%s\" ThreadTokenIdentificationOpen child %lu", Path, GetCurrentProcessId());
    Startup.dwFlags = STARTF_USESTDHANDLES;
    Startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    Startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    Startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessAsUserW(Low, Path, Command, NULL, NULL, TRUE, 0, NULL, NULL, &Startup, &Pi))
    {
        skip("CreateProcessAsUser failed (%lu)\n", GetLastError());
        CloseHandle(Low);
        return;
    }
    CloseHandle(Low);
    winetest_wait_child_process(&Pi);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
}
