/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ShellExecuteEx with the "runas" verb, without UAC
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values are what Windows 10 22H2 with UAC off (EnableLUA = 0) does, measured with the
 * caller's own token and a filtered copy of it: "runas" starts the target directly with the caller's
 * token, ShellExecuteEx returns TRUE with a valid hProcess and no UI, with or without
 * SEE_MASK_FLAG_NO_UI. The target is never more elevated than the caller.
 *
 * ReactOS shows no Run As dialog either: a caller that is not elevated gets its target started
 * unelevated, with its own token, as on Windows with UAC off.
 *
 * ShellExecuteRunAs              tests with the caller's token, then runs the step below
 * ShellExecuteRunAs restricted   tests with a filtered, medium-integrity copy of it
 * ShellExecuteRunAs sleep        the target: waits a little, exits with CHILD_EXIT
 */

#include "shelltest.h"
#include <strsafe.h>

/* The target exits with CHILD_EXIT(its TokenIsElevated), or CHILD_EXIT(9) when it cannot tell */
#define CHILD_EXIT(Elevated) (70 + (Elevated))

#ifndef LUA_TOKEN
#define LUA_TOKEN 0x4
#endif

static LONG s_Dialogs;
static HWND s_LastDialog;
static WCHAR s_DialogTitle[2][128];
static volatile BOOL s_Watch;

static BOOL CALLBACK CancelOwnDialogs(HWND hwnd, LPARAM lParam)
{
    DWORD Pid;
    WCHAR Class[64];

    GetWindowThreadProcessId(hwnd, &Pid);
    if (Pid != GetCurrentProcessId())
        return TRUE;
    if (GetClassNameW(hwnd, Class, _countof(Class)) && !wcscmp(Class, L"#32770"))
    {
        if (hwnd != s_LastDialog)
        {
            s_LastDialog = hwnd;
            if (s_Dialogs < 2)
                GetWindowTextW(hwnd, s_DialogTitle[s_Dialogs], _countof(s_DialogTitle[0]));
            InterlockedIncrement(&s_Dialogs);
        }
        PostMessageW(hwnd, WM_COMMAND, IDCANCEL, 0);
    }
    return TRUE;
}

static DWORD WINAPI Watcher(LPVOID Param)
{
    while (s_Watch)
    {
        EnumWindows(CancelOwnDialogs, 0);
        Sleep(100);
    }
    return 0;
}

static BOOL QueryElevation(HANDLE Token, PDWORD Elevated, TOKEN_ELEVATION_TYPE *Type)
{
    TOKEN_ELEVATION Elevation;
    DWORD Length;

    if (!GetTokenInformation(Token, TokenElevation, &Elevation, sizeof(Elevation), &Length) ||
        !GetTokenInformation(Token, TokenElevationType, Type, sizeof(*Type), &Length))
        return FALSE;
    *Elevated = Elevation.TokenIsElevated;
    return TRUE;
}

/* ShellExecuteEx("runas", self sleep), with Mask SEE_MASK_CLASSNAME through the exefile class as the
 * shell's context menu does; returns what ShellExecuteEx did, with the error and the dialogs shown */
static BOOL RunAs(ULONG Mask, LPSHELLEXECUTEINFOW Sei, PDWORD Error, PLONG Dialogs)
{
    static WCHAR Self[MAX_PATH];
    HANDLE hThread;
    BOOL Ret;

    GetModuleFileNameW(NULL, Self, _countof(Self));
    ZeroMemory(Sei, sizeof(*Sei));
    Sei->cbSize = sizeof(*Sei);
    Sei->fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | Mask;
    Sei->lpVerb = L"runas";
    Sei->lpFile = Self;
    Sei->lpParameters = L"ShellExecuteRunAs sleep";
    Sei->nShow = SW_HIDE;
    if (Mask & SEE_MASK_CLASSNAME)
        Sei->lpClass = L"exefile";

    s_Dialogs = 0;
    s_LastDialog = NULL;
    s_DialogTitle[0][0] = s_DialogTitle[1][0] = UNICODE_NULL;
    s_Watch = TRUE;
    hThread = CreateThread(NULL, 0, Watcher, NULL, 0, NULL);
    SetLastError(0xdeadbeef);
    Ret = ShellExecuteExW(Sei);
    *Error = GetLastError();
    s_Watch = FALSE;
    if (hThread)
    {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    *Dialogs = s_Dialogs;
    if (s_Dialogs)
        trace("dialogs shown: %ld, \"%ls\" \"%ls\"\n", s_Dialogs, s_DialogTitle[0], s_DialogTitle[1]);
    return Ret;
}

static BOOL QueryIdentity(HANDLE Token, PSID Sid, DWORD cbSid, PLUID AuthId)
{
    BYTE UserBuffer[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER)];
    TOKEN_STATISTICS Stats;
    DWORD Length;

    if (!GetTokenInformation(Token, TokenUser, UserBuffer, sizeof(UserBuffer), &Length) ||
        !GetTokenInformation(Token, TokenStatistics, &Stats, sizeof(Stats), &Length) ||
        !CopySid(cbSid, Sid, ((PTOKEN_USER)UserBuffer)->User.Sid))
        return FALSE;
    *AuthId = Stats.AuthenticationId;
    return TRUE;
}

/* The target started: its token must be the caller's (same user, same logon session, as elevated, never more) */
static void CheckChild(PCSTR What, HANDLE hProcess, DWORD CallerElevated, TOKEN_ELEVATION_TYPE CallerType)
{
    HANDLE Token;
    DWORD Elevated = 0xdeadbeef, Exit = 0;
    TOKEN_ELEVATION_TYPE Type = (TOKEN_ELEVATION_TYPE)0;
    BOOL TokenChecked = FALSE;

    if (OpenProcessToken(hProcess, TOKEN_QUERY, &Token))
    {
        TokenChecked = QueryElevation(Token, &Elevated, &Type);
        ok(TokenChecked, "%s: child token elevation query failed: %lu\n", What, GetLastError());
        ok((Elevated != 0) == (CallerElevated != 0), "%s: child TokenIsElevated %lu, caller %lu\n", What, Elevated,
           CallerElevated);
        ok(Type == CallerType, "%s: child elevation type %d, caller %d\n", What, Type, CallerType);
        {
            BYTE ChildSid[SECURITY_MAX_SID_SIZE], CallerSid[SECURITY_MAX_SID_SIZE];
            LUID ChildAuth, CallerAuth;
            HANDLE CallerToken;

            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &CallerToken))
            {
                BOOL Both = QueryIdentity(Token, ChildSid, sizeof(ChildSid), &ChildAuth) &&
                            QueryIdentity(CallerToken, CallerSid, sizeof(CallerSid), &CallerAuth);
                ok(Both, "%s: token identity query failed: %lu\n", What, GetLastError());
                if (Both)
                {
                    ok(EqualSid(ChildSid, CallerSid), "%s: the child runs as another user\n", What);
                    ok(ChildAuth.LowPart == CallerAuth.LowPart && ChildAuth.HighPart == CallerAuth.HighPart,
                       "%s: the child is in another logon session: %lx:%lx, caller %lx:%lx\n", What,
                       ChildAuth.HighPart, ChildAuth.LowPart, CallerAuth.HighPart, CallerAuth.LowPart);
                }
                CloseHandle(CallerToken);
            }
        }
        CloseHandle(Token);
    }
    else
    {
        /* A filtered caller may not be allowed to query the token (ReactOS); the child reports it then */
        ok(!CallerElevated, "%s: OpenProcessToken(child) failed: %lu\n", What, GetLastError());
    }
    if (WaitForSingleObject(hProcess, 30000) != WAIT_OBJECT_0)
    {
        ok(0, "%s: the child did not exit\n", What);
        TerminateProcess(hProcess, 1);
        WaitForSingleObject(hProcess, 5000);
    }
    GetExitCodeProcess(hProcess, &Exit);
    if (!CallerElevated && Exit == (DWORD)STATUS_DLL_INIT_FAILED)
    {
        /* Windows: a filtered token may lack access to the window station the child's user32 needs */
        ok(TokenChecked, "%s: the child neither started nor could its token be checked\n", What);
    }
    else
    {
        ok(Exit == CHILD_EXIT(CallerElevated != 0), "%s: child exit code %lu, expected %lu\n", What, Exit,
           CHILD_EXIT(CallerElevated != 0));
    }
}

static void TestRunAs(PCSTR What, ULONG Mask, DWORD CallerElevated, TOKEN_ELEVATION_TYPE CallerType)
{
    SHELLEXECUTEINFOW Sei;
    DWORD Error;
    LONG Dialogs;
    BOOL Ret;

    Ret = RunAs(Mask, &Sei, &Error, &Dialogs);
    ok(Ret, "%s: ShellExecuteEx failed: %lu\n", What, Error);
    ok(Dialogs == 0, "%s: %ld dialogs shown\n", What, Dialogs);
    ok((ULONG_PTR)Sei.hInstApp > 32, "%s: hInstApp %Iu\n", What, (ULONG_PTR)Sei.hInstApp);
    ok(Sei.hProcess != NULL, "%s: no hProcess\n", What);
    if (Sei.hProcess)
    {
        CheckChild(What, Sei.hProcess, CallerElevated, CallerType);
        CloseHandle(Sei.hProcess);
    }
}

/* The no-association failures and the other plain failures. Windows 10 22H2, measured with ShellExecuteEx
 * and SEE_MASK_FLAG_NO_UI (x64 and x86) and with ShellExecute (which implies NO_UI):
 *   a verb the file type does not have, a class that does not exist (with or without a verb):
 *                               FALSE, ERROR_NO_ASSOCIATION (1155), hInstApp SE_ERR_NOASSOC (31)
 *   a file that does not exist, with or without a directory that does, with "open" or any verb:
 *                               FALSE, ERROR_FILE_NOT_FOUND (2), hInstApp SE_ERR_FNF (2)
 * An unassociated extension is not used: Windows 10 starts OpenWith.exe for "open" even with
 * SEE_MASK_FLAG_NO_UI. A stale ERROR_CANCELLED last error is set before each call: a failure that has
 * nothing to do with "runas" is not taken for a cancelled Run As dialog. */
static void NoAssocCase(PCSTR What, PCWSTR Verb, PCWSTR Path, PCWSTR Class, DWORD ExpError, UINT_PTR ExpInst)
{
    SHELLEXECUTEINFOW Sei;
    DWORD Error;
    BOOL Ret;

    ZeroMemory(&Sei, sizeof(Sei));
    Sei.cbSize = sizeof(Sei);
    Sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI | (Class ? SEE_MASK_CLASSNAME : 0);
    Sei.lpVerb = Verb;
    Sei.lpFile = Path;
    Sei.lpClass = Class;
    Sei.nShow = SW_HIDE;
    SetLastError(ERROR_CANCELLED);
    Ret = ShellExecuteExW(&Sei);
    Error = GetLastError();
    ok(!Ret, "%s: ShellExecuteEx succeeded\n", What);
    ok(Error != ERROR_CANCELLED, "%s: error ERROR_CANCELLED\n", What);
    ok((ULONG_PTR)Sei.hInstApp != SE_ERR_ACCESSDENIED, "%s: hInstApp SE_ERR_ACCESSDENIED\n", What);
    ok(Error == ExpError, "%s: error %lu, expected %lu\n", What, Error, ExpError);
    ok((ULONG_PTR)Sei.hInstApp == ExpInst, "%s: hInstApp %Iu, expected %Iu\n", What, (ULONG_PTR)Sei.hInstApp, ExpInst);
    ok(Sei.hProcess == NULL, "%s: hProcess %p\n", What, Sei.hProcess);
    if (Sei.hProcess)
    {
        TerminateProcess(Sei.hProcess, 1);
        CloseHandle(Sei.hProcess);
    }
}

/* ShellExecute returns hInstApp and leaves the error (the same cases, no class) */
static void NoAssocPlainCase(PCSTR What, PCWSTR Verb, PCWSTR Path, DWORD ExpError, UINT_PTR ExpInst)
{
    HINSTANCE Inst;
    DWORD Error;

    SetLastError(ERROR_CANCELLED);
    Inst = ShellExecuteW(NULL, Verb, Path, NULL, NULL, SW_HIDE);
    Error = GetLastError();
    ok((ULONG_PTR)Inst == ExpInst, "ShellExecute %s: returned %Iu, expected %Iu\n", What, (ULONG_PTR)Inst, ExpInst);
    ok(Error == ExpError, "ShellExecute %s: error %lu, expected %lu\n", What, Error, ExpError);
}

static void TestNoAssocCodes(void)
{
    static const WCHAR NoVerb[] = L"zzShellExecuteRunAsNoVerb";
    static const WCHAR NoClass[] = L"zzShellExecuteRunAsNoClass";
    WCHAR Path[MAX_PATH], Missing[MAX_PATH], NoDir[MAX_PATH], NoDirExe[MAX_PATH];
    HANDLE hFile;

    GetTempPathW(_countof(Path), Path);
    StringCchCopyW(Missing, _countof(Missing), Path);
    StringCchCatW(Missing, _countof(Missing), L"ShellExecuteRunAs-missing.txt");
    StringCchCopyW(NoDir, _countof(NoDir), Path);
    StringCchCatW(NoDir, _countof(NoDir), L"ShellExecuteRunAs-nodir\\missing.txt");
    StringCchCopyW(NoDirExe, _countof(NoDirExe), Path);
    StringCchCatW(NoDirExe, _countof(NoDirExe), L"ShellExecuteRunAs-nodir\\missing.exe");
    StringCchCatW(Path, _countof(Path), L"ShellExecuteRunAs.txt");
    hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "CreateFile(%ls) failed: %lu\n", Path, GetLastError());
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    CloseHandle(hFile);
    DeleteFileW(Missing);

    NoAssocCase("unknown verb", NoVerb, Path, NULL, ERROR_NO_ASSOCIATION, SE_ERR_NOASSOC);
    NoAssocCase("unknown class", L"open", Path, NoClass, ERROR_NO_ASSOCIATION, SE_ERR_NOASSOC);
    NoAssocCase("unknown class, no verb", NULL, Path, NoClass, ERROR_NO_ASSOCIATION, SE_ERR_NOASSOC);
    NoAssocCase("unknown class and verb", NoVerb, Path, NoClass, ERROR_NO_ASSOCIATION, SE_ERR_NOASSOC);
    NoAssocCase("missing file", L"open", Missing, NULL, ERROR_FILE_NOT_FOUND, SE_ERR_FNF);
    NoAssocCase("missing file, unknown verb", NoVerb, Missing, NULL, ERROR_FILE_NOT_FOUND, SE_ERR_FNF);
    NoAssocCase("missing directory", L"open", NoDir, NULL, ERROR_FILE_NOT_FOUND, SE_ERR_FNF);
    NoAssocCase("missing directory, exe", L"open", NoDirExe, NULL, ERROR_FILE_NOT_FOUND, SE_ERR_FNF);
    NoAssocPlainCase("unknown verb", NoVerb, Path, ERROR_NO_ASSOCIATION, SE_ERR_NOASSOC);
    NoAssocPlainCase("missing file", L"open", Missing, ERROR_FILE_NOT_FOUND, SE_ERR_FNF);
    NoAssocPlainCase("missing file, unknown verb", NoVerb, Missing, ERROR_FILE_NOT_FOUND, SE_ERR_FNF);
    NoAssocPlainCase("missing directory", L"open", NoDir, ERROR_FILE_NOT_FOUND, SE_ERR_FNF);
    NoAssocPlainCase("missing directory, exe", L"open", NoDirExe, ERROR_FILE_NOT_FOUND, SE_ERR_FNF);
    DeleteFileW(Path);
}

static BOOL OwnElevation(PDWORD Elevated, TOKEN_ELEVATION_TYPE *Type)
{
    HANDLE Token;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    Ret = QueryElevation(Token, Elevated, Type);
    CloseHandle(Token);
    return Ret;
}

static void TestRestrictedStep(void)
{
    DWORD Elevated;
    TOKEN_ELEVATION_TYPE Type;

    if (!OwnElevation(&Elevated, &Type))
    {
        skip("No TokenElevation\n");
        return;
    }
    ok(!Elevated, "The filtered token is elevated\n");
    if (Elevated)
        return;
    /* UI allowed or not: no dialog, the target runs with the filtered token */
    TestRunAs("filtered, NO_UI", SEE_MASK_FLAG_NO_UI, Elevated, Type);
    TestRunAs("filtered, UI allowed", 0, Elevated, Type);
    TestRunAs("filtered, UI allowed, exefile class", SEE_MASK_CLASSNAME, Elevated, Type);
}

/* Run "ShellExecuteRunAs restricted" with a filtered, medium-integrity copy of the own token */
static void RunRestricted(void)
{
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    static SID_IDENTIFIER_AUTHORITY LabelAuthority = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    HANDLE Token, Restricted;
    PSID AdminSid, MediumSid;
    SID_AND_ATTRIBUTES Disable;
    TOKEN_MANDATORY_LABEL Label;
    WCHAR Self[MAX_PATH], Command[MAX_PATH + 64];
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Token))
    {
        skip("OpenProcessToken failed: %lu\n", GetLastError());
        return;
    }
    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                             0, 0, 0, 0, 0, 0, &AdminSid);
    AllocateAndInitializeSid(&LabelAuthority, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &MediumSid);
    Disable.Sid = AdminSid;
    Disable.Attributes = 0;
    if (!CreateRestrictedToken(Token, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, 1, &Disable, 0, NULL, 0, NULL,
                               &Restricted))
    {
        ok(0, "CreateRestrictedToken failed: %lu\n", GetLastError());
        goto Cleanup;
    }
    /* Let the filtered user open the tokens of the processes it starts, as LUA_TOKEN does on Windows */
    {
        BYTE UserBuffer[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER)];
        BYTE AclBuffer[256];
        PACL Acl = (PACL)AclBuffer;
        TOKEN_DEFAULT_DACL DefaultDacl;
        DWORD Length;

        if (GetTokenInformation(Restricted, TokenUser, UserBuffer, sizeof(UserBuffer), &Length) &&
            InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION) &&
            AddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, ((PTOKEN_USER)UserBuffer)->User.Sid))
        {
            DefaultDacl.DefaultDacl = Acl;
            ok(SetTokenInformation(Restricted, TokenDefaultDacl, &DefaultDacl, sizeof(DefaultDacl)),
               "Setting the default DACL failed: %lu\n", GetLastError());
        }
        else
        {
            ok(0, "Building the default DACL failed: %lu\n", GetLastError());
        }
    }
    Label.Label.Sid = MediumSid;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    ok(SetTokenInformation(Restricted, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid(MediumSid)),
       "Setting the medium label failed: %lu\n", GetLastError());

    GetModuleFileNameW(NULL, Self, _countof(Self));
    StringCchPrintfW(Command, _countof(Command), L"\"%s\" ShellExecuteRunAs restricted", Self);
    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    if (CreateProcessAsUserW(Restricted, NULL, Command, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
    {
        wait_child_process(Pi.hProcess);
        CloseHandle(Pi.hProcess);
        CloseHandle(Pi.hThread);
    }
    else
    {
        ok(0, "CreateProcessAsUser(filtered) failed: %lu\n", GetLastError());
    }
    CloseHandle(Restricted);

Cleanup:
    FreeSid(MediumSid);
    FreeSid(AdminSid);
    CloseHandle(Token);
}

START_TEST(ShellExecuteRunAs)
{
    DWORD Elevated;
    TOKEN_ELEVATION_TYPE Type;
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    if (argc >= 3 && !strcmp(argv[2], "sleep"))
    {
        Sleep(1000);
        ExitProcess(OwnElevation(&Elevated, &Type) ? CHILD_EXIT(Elevated != 0) : CHILD_EXIT(9));
    }

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (argc >= 3 && !strcmp(argv[2], "restricted"))
    {
        TestRestrictedStep();
        CoUninitialize();
        return;
    }

    if (!OwnElevation(&Elevated, &Type))
    {
        skip("No TokenElevation\n");
        CoUninitialize();
        return;
    }
    if (Elevated)
    {
        /* No prompt: the target runs with the caller's full token */
        TestRunAs("elevated", 0, Elevated, Type);
        TestRunAs("elevated, NO_UI", SEE_MASK_FLAG_NO_UI, Elevated, Type);
        TestRunAs("elevated, exefile class", SEE_MASK_CLASSNAME, Elevated, Type);
    }
    else
    {
        skip("Not elevated, the elevated caller cases need an administrator\n");
    }
    RunRestricted();
    TestNoAssocCodes();
    CoUninitialize();
}
