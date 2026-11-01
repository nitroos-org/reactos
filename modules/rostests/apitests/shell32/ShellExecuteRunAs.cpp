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
 * ReactOS keeps its Run As dialog for a caller that is not elevated and allows UI; cancelling it
 * fails with ERROR_CANCELLED.
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

/* The target started: its token must be as elevated as the caller's, never more */
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

static void TestRunAs(PCSTR What, ULONG Mask, DWORD CallerElevated, TOKEN_ELEVATION_TYPE CallerType,
                      BOOL MayPrompt)
{
    SHELLEXECUTEINFOW Sei;
    DWORD Error;
    LONG Dialogs;
    BOOL Ret;

    Ret = RunAs(Mask, &Sei, &Error, &Dialogs);
    if (MayPrompt && Dialogs)
    {
        /* The Run As dialog, cancelled by the watcher */
        ok(!Ret, "%s: ShellExecuteEx succeeded after cancel\n", What);
        ok(Error == ERROR_CANCELLED, "%s: error %lu after cancel, expected ERROR_CANCELLED\n", What, Error);
        ok(Sei.hProcess == NULL, "%s: hProcess %p after cancel\n", What, Sei.hProcess);
        ok((ULONG_PTR)Sei.hInstApp <= 32, "%s: hInstApp %Iu after cancel\n", What, (ULONG_PTR)Sei.hInstApp);
    }
    else
    {
        ok(Ret, "%s: ShellExecuteEx failed: %lu\n", What, Error);
        ok(Dialogs == 0, "%s: %ld dialogs shown\n", What, Dialogs);
        ok((ULONG_PTR)Sei.hInstApp > 32, "%s: hInstApp %Iu\n", What, (ULONG_PTR)Sei.hInstApp);
        ok(Sei.hProcess != NULL, "%s: no hProcess\n", What);
    }
    if (MayPrompt && is_reactos())
        ok(Dialogs == 1, "%s: %ld dialogs, ReactOS should show its Run As dialog once to a caller that is not "
           "elevated\n", What, Dialogs);
    if (Sei.hProcess)
    {
        CheckChild(What, Sei.hProcess, CallerElevated, CallerType);
        CloseHandle(Sei.hProcess);
    }
}

/* A failure that has nothing to do with "runas" is not taken for a cancel because the last error
 * happened to be ERROR_CANCELLED before the call. Windows 10: FALSE, ERROR_NO_ASSOCIATION, SE_ERR_NOASSOC
 * for a verb the file type does not have and for a class that does not exist. (An unassociated extension
 * is not used: Windows 10 starts OpenWith.exe for it even with SEE_MASK_FLAG_NO_UI.) */
static void StaleCancelCase(PCSTR What, PCWSTR Verb, PCWSTR Path, PCWSTR Class)
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
    /* What matters here: the failure is not reported as a cancelled Run As dialog */
    ok(Error != ERROR_CANCELLED, "%s: error ERROR_CANCELLED\n", What);
    ok((ULONG_PTR)Sei.hInstApp != SE_ERR_ACCESSDENIED, "%s: hInstApp SE_ERR_ACCESSDENIED\n", What);
    /* ReactOS reports these failures with other codes (ERROR_FILE_NOT_FOUND; hInstApp 0 for the class) */
    todo_if(is_reactos())
    ok(Error == ERROR_NO_ASSOCIATION, "%s: error %lu\n", What, Error);
    todo_if(is_reactos() && Class != NULL)
    ok((ULONG_PTR)Sei.hInstApp == SE_ERR_NOASSOC, "%s: hInstApp %Iu\n", What, (ULONG_PTR)Sei.hInstApp);
    if (Sei.hProcess)
    {
        TerminateProcess(Sei.hProcess, 1);
        CloseHandle(Sei.hProcess);
    }
}

static void TestStaleCancelError(void)
{
    WCHAR Path[MAX_PATH];
    HANDLE hFile;

    GetTempPathW(_countof(Path), Path);
    StringCchCatW(Path, _countof(Path), L"ShellExecuteRunAs.txt");
    hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "CreateFile(%ls) failed: %lu\n", Path, GetLastError());
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    CloseHandle(hFile);
    StaleCancelCase("stale ERROR_CANCELLED, unknown verb", L"zzShellExecuteRunAsNoVerb", Path, NULL);
    StaleCancelCase("stale ERROR_CANCELLED, unknown class", L"open", Path, L"zzShellExecuteRunAsNoClass");
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
    TestRunAs("filtered, NO_UI", SEE_MASK_FLAG_NO_UI, Elevated, Type, FALSE);
    TestRunAs("filtered, UI allowed", 0, Elevated, Type, TRUE);
    TestRunAs("filtered, UI allowed, exefile class", SEE_MASK_CLASSNAME, Elevated, Type, TRUE);
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
        TestRunAs("elevated", 0, Elevated, Type, FALSE);
        TestRunAs("elevated, NO_UI", SEE_MASK_FLAG_NO_UI, Elevated, Type, FALSE);
        TestRunAs("elevated, exefile class", SEE_MASK_CLASSNAME, Elevated, Type, FALSE);
    }
    else
    {
        skip("Not elevated, the elevated caller cases need an administrator\n");
    }
    RunRestricted();
    TestStaleCancelError();
    CoUninitialize();
}
