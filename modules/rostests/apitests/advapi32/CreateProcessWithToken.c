/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     CreateProcessWithTokenW starts the process with the token it is given, not as the caller
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (10.0.20348.587), from an administrator and from a standard user:
 * - dwLogonFlags other than LOGON_WITH_PROFILE (1) and LOGON_NETCREDENTIALS_ONLY (2): FALSE, 87, before anything else;
 * - a NULL token: FALSE, 1326 (ERROR_LOGON_FAILURE), before the privilege is looked at;
 * - a caller without SeImpersonatePrivilege enabled (a standard user): FALSE, 1314, also for a handle that is none;
 * - a duplicated primary token of the caller (also with 1, 2, 3 as flags), an impersonation token (it is made a
 *   primary one): the child runs with that token; a token restricted with DISABLE_MAX_PRIVILEGE: the child has
 *   its 1 privilege, not the caller's 24;
 * - with no environment the child has the environment of the token's user (a variable of the caller's is not
 *   there), with no directory it starts in the system directory.
 */

#include "precomp.h"

static WCHAR g_ChildFile[MAX_PATH];

static BOOL IsChild(PWSTR *File)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, g_ChildFile, _countof(g_ChildFile));
        *File = g_ChildFile;
        return TRUE;
    }
    return FALSE;
}

static void ChildReport(PCWSTR File)
{
    HANDLE Token, Out;
    BYTE Buffer[4096];
    WCHAR Text[1024], Env[64], Dir[MAX_PATH];
    DWORD Length, Written;

    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token);
    Length = 0;
    if (!GetTokenInformation(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Length))
        Buffer[0] = 0;
    if (!GetEnvironmentVariableW(L"CPWT_MARK", Env, _countof(Env)))
        wcscpy(Env, L"(none)");
    GetCurrentDirectoryW(_countof(Dir), Dir);
    _snwprintf(Text, _countof(Text), L"privs=%lu\r\nmark=%ls\r\ncwd=%ls\r\n", ((PTOKEN_PRIVILEGES)Buffer)->PrivilegeCount, Env, Dir);
    Out = CreateFileW(File, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (Out != INVALID_HANDLE_VALUE)
    {
        WriteFile(Out, Text, (DWORD)wcslen(Text) * sizeof(WCHAR), &Written, NULL);
        CloseHandle(Out);
    }
    CloseHandle(Token);
}

typedef struct _REPORT
{
    ULONG Privileges;
    WCHAR Mark[64];
    WCHAR Cwd[MAX_PATH];
} REPORT;

static BOOL ReadReport(PCWSTR File, REPORT *Report)
{
    HANDLE In = CreateFileW(File, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    WCHAR Text[1024] = { 0 };
    DWORD Read;
    PWCHAR p;

    if (In == INVALID_HANDLE_VALUE)
        return FALSE;
    ReadFile(In, Text, sizeof(Text) - sizeof(WCHAR), &Read, NULL);
    CloseHandle(In);
    ZeroMemory(Report, sizeof(*Report));
    p = wcsstr(Text, L"privs=");
    if (p) Report->Privileges = wcstoul(p + 6, NULL, 10);
    p = wcsstr(Text, L"mark=");
    if (p) { wcsncpy(Report->Mark, p + 5, _countof(Report->Mark) - 1); p = wcschr(Report->Mark, L'\r'); if (p) *p = 0; }
    p = wcsstr(Text, L"cwd=");
    if (p) { wcsncpy(Report->Cwd, p + 4, _countof(Report->Cwd) - 1); p = wcschr(Report->Cwd, L'\r'); if (p) *p = 0; }
    return TRUE;
}

static BOOL RunWithToken(HANDLE Token, DWORD LogonFlags, PVOID Environment, PCWSTR Directory, DWORD *Error, REPORT *Report)
{
    WCHAR Exe[MAX_PATH], File[MAX_PATH], Command[2 * MAX_PATH + 64];
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    static int Counter;
    BOOL Ret;

    GetModuleFileNameW(NULL, Exe, _countof(Exe));
    wcscpy(File, Exe);
    _snwprintf(wcsrchr(File, L'\\'), 40, L"\\cpwt-%d.txt", ++Counter);
    DeleteFileW(File);
    _snwprintf(Command, _countof(Command), L"\"%ls\" CreateProcessWithToken child \"%ls\"", Exe, File);

    SetLastError(0xDEADBEEF);
    Ret = CreateProcessWithTokenW(Token, LogonFlags, NULL, Command, Environment ? CREATE_UNICODE_ENVIRONMENT : 0,
                                  Environment, Directory, &Si, &Pi);
    *Error = GetLastError();
    ZeroMemory(Report, sizeof(*Report));
    if (Ret)
    {
        WaitForSingleObject(Pi.hProcess, 30000);
        CloseHandle(Pi.hProcess);
        CloseHandle(Pi.hThread);
        ReadReport(File, Report);
        DeleteFileW(File);
    }
    return Ret;
}

START_TEST(CreateProcessWithToken)
{
    HANDLE Self, Dup, Imp, Restricted, Empty;
    PWSTR ChildFile;
    REPORT Mine, R;
    BYTE Buffer[4096];
    DWORD Length, Error;
    WCHAR SystemDir[MAX_PATH];
    BOOL Ret;

    if (IsChild(&ChildFile))
    {
        ChildReport(ChildFile);
        return;
    }

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &Self), "OpenProcessToken failed %lu\n", GetLastError());
    if (!Self)
        return;
    if (!GetTokenInformation(Self, TokenPrivileges, Buffer, sizeof(Buffer), &Length))
        return;
    Mine.Privileges = ((PTOKEN_PRIVILEGES)Buffer)->PrivilegeCount;
    ok(DuplicateTokenEx(Self, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &Dup), "DuplicateTokenEx failed %lu\n", GetLastError());
    ok(DuplicateTokenEx(Self, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Imp), "DuplicateTokenEx failed %lu\n", GetLastError());
    /* A restricted token of the process's own token: the caller may assign it to a process (a token made from a
     * copy is no child of the process token: Windows starts that through the secondary logon service, which
     * NitroOS has no path for yet: ERROR_PRIVILEGE_NOT_HELD) */
    ok(CreateRestrictedToken(Self, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &Restricted), "CreateRestrictedToken failed %lu\n", GetLastError());
    GetSystemDirectoryW(SystemDir, _countof(SystemDir));

    /* Argument rows */
    Ret = RunWithToken(Dup, 4, NULL, NULL, &Error, &R);
    ok(!Ret && Error == ERROR_INVALID_PARAMETER, "flags 4: %d, error %lu\n", Ret, Error);
    Ret = RunWithToken(NULL, 0, NULL, NULL, &Error, &R);
    ok(!Ret && Error == ERROR_LOGON_FAILURE, "NULL token: %d, error %lu\n", Ret, Error);

    /* The caller's own token, all three flag values, and an impersonation token */
    Ret = RunWithToken(Dup, 0, NULL, NULL, &Error, &R);
    ok(Ret, "primary token: error %lu\n", Error);
    ok(R.Privileges == Mine.Privileges, "the child has %lu privileges, the caller %lu\n", R.Privileges, Mine.Privileges);
    Ret = RunWithToken(Dup, LOGON_WITH_PROFILE, NULL, NULL, &Error, &R);
    ok(Ret, "LOGON_WITH_PROFILE: error %lu\n", Error);
    Ret = RunWithToken(Dup, LOGON_NETCREDENTIALS_ONLY, NULL, NULL, &Error, &R);
    ok(Ret, "LOGON_NETCREDENTIALS_ONLY: error %lu\n", Error);
    Ret = RunWithToken(Imp, 0, NULL, NULL, &Error, &R);
    ok(Ret, "impersonation token: error %lu\n", Error);

    /* A token with fewer rights: the child has them, not the caller's */
    Ret = RunWithToken(Restricted, 0, NULL, NULL, &Error, &R);
    ok(Ret, "restricted token: error %lu\n", Error);
    ok(R.Privileges == 1, "the child of a restricted token has %lu privileges, expected 1 (the caller has %lu)\n", R.Privileges, Mine.Privileges);

    /* Environment and directory of a caller that gives none */
    SetEnvironmentVariableW(L"CPWT_MARK", L"caller");
    SetCurrentDirectoryW(L"C:\\");
    Ret = RunWithToken(Dup, 0, NULL, NULL, &Error, &R);
    ok(Ret, "environment: error %lu\n", Error);
    ok(!wcscmp(R.Mark, L"(none)"), "the child has the caller's variable: %ls\n", R.Mark);
    ok(!_wcsicmp(R.Cwd, SystemDir), "the child starts in \"%ls\", expected \"%ls\"\n", R.Cwd, SystemDir);

    /* A caller without the privilege (a thread with a token that has none enabled) */
    Empty = NULL;
    ok(DuplicateTokenEx(Restricted, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Empty), "DuplicateTokenEx failed\n");
    ok(SetThreadToken(NULL, Empty), "SetThreadToken failed %lu\n", GetLastError());
    Ret = RunWithToken(Dup, 0, NULL, NULL, &Error, &R);
    ok(!Ret && Error == ERROR_PRIVILEGE_NOT_HELD, "without SeImpersonatePrivilege: %d, error %lu\n", Ret, Error);
    Ret = RunWithToken((HANDLE)(ULONG_PTR)0x1234, 0, NULL, NULL, &Error, &R);
    ok(!Ret && Error == ERROR_PRIVILEGE_NOT_HELD, "a handle that is none, without the privilege: %d, error %lu\n", Ret, Error);
    RevertToSelf();
    Ret = RunWithToken((HANDLE)(ULONG_PTR)0x1234, 0, NULL, NULL, &Error, &R);
    ok(!Ret && Error == ERROR_INVALID_HANDLE, "a handle that is none: %d, error %lu\n", Ret, Error);

    CloseHandle(Empty);
    CloseHandle(Restricted);
    CloseHandle(Imp);
    CloseHandle(Dup);
    CloseHandle(Self);
}
