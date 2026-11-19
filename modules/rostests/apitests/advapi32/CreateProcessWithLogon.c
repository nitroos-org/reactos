/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     CreateProcessWithLogonW (the secondary logon behind runas.exe): a GUI program started for
 *              another user gets a window on the interactive desktop (WinSta0\Default), a console program
 *              runs, with LOGON_WITH_PROFILE the child's HKEY_CURRENT_USER is its own loaded hive, a wrong
 *              password fails with ERROR_LOGON_FAILURE
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The test is run by an administrator from the interactive desktop. The child is this program with
 * "child gui" or "child console"; it reports through its exit code: 0 for the GUI child when everything
 * worked, else (GetLastError() << 8) | step.
 */

#include "precomp.h"
#include <wingdi.h>
#include <winuser.h>
#include <lm.h>
#include <sddl.h>
#include <ndk/cmfuncs.h>

#define STEP_WINSTA     1   /* no window station                */
#define STEP_WINSTANAME 2   /* not WinSta0                      */
#define STEP_DESKTOP    3   /* no desktop                       */
#define STEP_DESKNAME   4   /* not Default                      */
#define STEP_WINDOW     5   /* CreateWindowEx failed            */
#define STEP_VISIBLE    6   /* the window is not visible        */
#define STEP_OPENDESK   7   /* OpenInputDesktop-free check: OpenDesktop(Default) failed */
#define STEP_SID        8   /* the child cannot read its own user SID */
#define STEP_HIVE       9   /* HKEY_USERS\<own SID> is not loaded while the child runs */
#define STEP_HKCU       10  /* RegOpenCurrentUser failed */
#define STEP_HKCUNAME   11  /* HKEY_CURRENT_USER is not \REGISTRY\USER\<own SID> */
#define STEP_HKCUWRITE  12  /* a key cannot be created under HKEY_CURRENT_USER\Software */
#define CONSOLE_EXIT    42

static WCHAR TestPassword[] = L"RunAsGui-Test-2026!";

static BOOL CreateTestUser(PWSTR Name, SIZE_T NameLength)
{
    USER_INFO_1 Info;
    NET_API_STATUS Status = NERR_UserExists;
    DWORD Err, Try;

    for (Try = 0; Try < 5 && Status == NERR_UserExists; Try++)
    {
        StringCchPrintfW(Name, NameLength, L"rgui%lx", (GetTickCount() + Try * 7919) & 0xffffff);
        ZeroMemory(&Info, sizeof(Info));
        Info.usri1_name = Name;
        Info.usri1_password = TestPassword;
        Info.usri1_priv = USER_PRIV_USER;
        Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
        Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    }
    if (Status == ERROR_ACCESS_DENIED)
    {
        skip("NetUserAdd needs an elevated administrator\n");
        return FALSE;
    }
    ok(Status == NERR_Success, "NetUserAdd(%ls) failed: %lu\n", Name, Status);
    return Status == NERR_Success;
}

static BOOL ObjectName(HANDLE Object, WCHAR *Buffer, DWORD Count)
{
    DWORD Needed;

    return GetUserObjectInformationW(Object, UOI_NAME, Buffer, Count * sizeof(WCHAR), &Needed);
}

/* The number of ACEs in the DACL of a window station or desktop, MAXDWORD if it cannot be read */
static DWORD AceCount(HANDLE Object)
{
    SECURITY_INFORMATION Info = DACL_SECURITY_INFORMATION;
    ACL_SIZE_INFORMATION Size;
    PSECURITY_DESCRIPTOR Sd;
    PACL Dacl;
    BOOL Present, Defaulted;
    DWORD Length = 0, Count = MAXDWORD;

    GetUserObjectSecurity(Object, &Info, NULL, 0, &Length);
    if (Length == 0)
        return MAXDWORD;
    Sd = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Sd == NULL)
        return MAXDWORD;
    if (GetUserObjectSecurity(Object, &Info, Sd, Length, &Length) &&
        GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted) &&
        Present && Dacl != NULL &&
        GetAclInformation(Dacl, &Size, sizeof(Size), AclSizeInformation))
    {
        Count = Size.AceCount;
    }
    HeapFree(GetProcessHeap(), 0, Sd);
    return Count;
}

static DWORD Fail(DWORD Step)
{
    return (GetLastError() << 8) | Step;
}

static DWORD ChildGui(PCWSTR ExpectWinSta, PCWSTR ExpectDesktop)
{
    WCHAR Name[64];
    HWINSTA WinSta;
    HDESK Desk, Open;
    HWND Window;

    WinSta = GetProcessWindowStation();
    if (!WinSta || !ObjectName(WinSta, Name, RTL_NUMBER_OF(Name)))
        return Fail(STEP_WINSTA);
    if (_wcsicmp(Name, ExpectWinSta))
        return STEP_WINSTANAME;

    Desk = GetThreadDesktop(GetCurrentThreadId());
    if (!Desk || !ObjectName(Desk, Name, RTL_NUMBER_OF(Name)))
        return Fail(STEP_DESKTOP);
    if (_wcsicmp(Name, ExpectDesktop))
        return STEP_DESKNAME;

    Window = CreateWindowExW(0, L"STATIC", L"runas gui test", WS_POPUP | WS_VISIBLE,
                             0, 0, 200, 100, NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (!Window)
        return Fail(STEP_WINDOW);
    ShowWindow(Window, SW_SHOWNORMAL);
    /* visibility is only checked on the interactive window station (not a window station the test created) */
    if (!_wcsicmp(ExpectWinSta, L"WinSta0") && !IsWindowVisible(Window))
    {
        DestroyWindow(Window);
        return STEP_VISIBLE;
    }
    DestroyWindow(Window);

    /* the desktop can be opened by name for the access a window needs */
    Open = OpenDesktopW(ExpectDesktop, 0, FALSE, DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS);
    if (!Open)
        return Fail(STEP_OPENDESK);
    CloseDesktop(Open);
    return 0;
}

/* The string SID of this process's user, LocalFree it */
static PWSTR OwnSidString(VOID)
{
    BYTE Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    PTOKEN_USER User = (PTOKEN_USER)Buffer;
    HANDLE Token;
    DWORD Length;
    PWSTR Sid = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return NULL;
    if (GetTokenInformation(Token, TokenUser, User, sizeof(Buffer), &Length))
        ConvertSidToStringSidW(User->User.Sid, &Sid);
    CloseHandle(Token);
    return Sid;
}

/*
 * LOGON_WITH_PROFILE: the child's HKEY_CURRENT_USER is its own hive, loaded under HKEY_USERS\<SID>
 * for as long as the child runs (CreateProcessWithLogonW documents that the profile is loaded), and
 * the child can create keys in it.
 */
static DWORD ChildProfile(VOID)
{
    BYTE Buffer[sizeof(KEY_NAME_INFORMATION) + 512 * sizeof(WCHAR)];
    PKEY_NAME_INFORMATION Name = (PKEY_NAME_INFORMATION)Buffer;
    WCHAR Expected[256];
    HKEY Users, Current, Key;
    ULONG Length;
    NTSTATUS Status;
    LONG Error;
    PWSTR Sid;
    DWORD Result = 0;

    Sid = OwnSidString();
    if (Sid == NULL)
        return Fail(STEP_SID);

    Error = RegOpenKeyExW(HKEY_USERS, Sid, 0, KEY_QUERY_VALUE, &Users);
    if (Error != ERROR_SUCCESS)
    {
        LocalFree(Sid);
        return (Error << 8) | STEP_HIVE;
    }
    RegCloseKey(Users);

    Error = RegOpenCurrentUser(KEY_READ | KEY_CREATE_SUB_KEY, &Current);
    if (Error != ERROR_SUCCESS)
    {
        LocalFree(Sid);
        return (Error << 8) | STEP_HKCU;
    }

    StringCchPrintfW(Expected, RTL_NUMBER_OF(Expected), L"\\REGISTRY\\USER\\%ls", Sid);
    Status = NtQueryKey(Current, KeyNameInformation, Name, sizeof(Buffer) - sizeof(WCHAR), &Length);
    if (!NT_SUCCESS(Status))
    {
        Result = (RtlNtStatusToDosError(Status) << 8) | STEP_HKCUNAME;
    }
    else
    {
        Name->Name[Name->NameLength / sizeof(WCHAR)] = UNICODE_NULL;
        if (_wcsicmp(Name->Name, Expected))
            Result = STEP_HKCUNAME;
    }

    if (Result == 0)
    {
        Error = RegCreateKeyExW(Current, L"Software\\RunAsProfileTest", 0, NULL, REG_OPTION_VOLATILE,
                                KEY_ALL_ACCESS, NULL, &Key, NULL);
        if (Error != ERROR_SUCCESS)
        {
            Result = (Error << 8) | STEP_HKCUWRITE;
        }
        else
        {
            RegDeleteKeyW(Key, L"");
            RegCloseKey(Key);
        }
    }

    RegCloseKey(Current);
    LocalFree(Sid);
    return Result;
}

/* The string SID of a local account, LocalFree it */
static PWSTR AccountSidString(PCWSTR Account)
{
    BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
    WCHAR Domain[64];
    DWORD SidLength = sizeof(SidBuffer), DomainLength = RTL_NUMBER_OF(Domain);
    SID_NAME_USE Use;
    PWSTR Sid = NULL;

    if (LookupAccountNameW(NULL, Account, SidBuffer, &SidLength, Domain, &DomainLength, &Use))
        ConvertSidToStringSidW(SidBuffer, &Sid);
    return Sid;
}

static DWORD RunChildFlags(PCWSTR User, PCWSTR Password, DWORD LogonFlags, PCSTR ModeA, PCWSTR Desktop,
                           BOOL *Started, DWORD *Error);

static DWORD RunChild(PCWSTR User, PCWSTR Password, PCSTR ModeA, PCWSTR Desktop, BOOL *Started, DWORD *Error)
{
    return RunChildFlags(User, Password, 0, ModeA, Desktop, Started, Error);
}

static DWORD RunChildFlags(PCWSTR User, PCWSTR Password, DWORD LogonFlags, PCSTR ModeA, PCWSTR Desktop,
                           BOOL *Started, DWORD *Error)
{
    WCHAR Exe[MAX_PATH], Command[MAX_PATH + 128], Mode[96];
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    DWORD Exit = MAXDWORD, Wait;
    BOOL Ok;

    MultiByteToWideChar(CP_ACP, 0, ModeA, -1, Mode, RTL_NUMBER_OF(Mode));
    GetModuleFileNameW(NULL, Exe, RTL_NUMBER_OF(Exe));
    StringCchPrintfW(Command, RTL_NUMBER_OF(Command), L"\"%ls\" CreateProcessWithLogon child %ls", Exe, Mode);
    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    Si.lpDesktop = (LPWSTR)Desktop;
    SetLastError(0xdeadbeef);
    Ok = CreateProcessWithLogonW(User, L".", Password, LogonFlags, NULL, Command, 0, NULL, NULL, &Si, &Pi);
    *Error = GetLastError();
    *Started = Ok;
    if (!Ok)
        return MAXDWORD;
    CloseHandle(Pi.hThread);
    SetLastError(0xdeadbeef);
    Wait = WaitForSingleObject(Pi.hProcess, 60000);
    ok(Wait == WAIT_OBJECT_0, "the child (%s) did not exit: %lu, error %lu, process %p pid %lu\n",
       ModeA, Wait, GetLastError(), Pi.hProcess, Pi.dwProcessId);
    if (Wait != WAIT_OBJECT_0)
        TerminateProcess(Pi.hProcess, 1);
    else if (!GetExitCodeProcess(Pi.hProcess, &Exit))
        Exit = MAXDWORD;
    CloseHandle(Pi.hProcess);
    return Exit;
}

START_TEST(CreateProcessWithLogon)
{
    static WCHAR User[32];
    NET_API_STATUS NetStatus;
    BOOL Started;
    DWORD Exit, Error, WinStaAces, DesktopAces, i;
    HANDLE hWinSta, hDesktop;
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        if (!strcmp(argv[3], "gui"))
        {
            WCHAR WinSta[64] = L"WinSta0", Desktop[64] = L"Default";

            if (argc >= 6)
            {
                MultiByteToWideChar(CP_ACP, 0, argv[4], -1, WinSta, RTL_NUMBER_OF(WinSta));
                MultiByteToWideChar(CP_ACP, 0, argv[5], -1, Desktop, RTL_NUMBER_OF(Desktop));
            }
            ExitProcess(ChildGui(WinSta, Desktop));
        }
        if (!strcmp(argv[3], "profile"))
            ExitProcess(ChildProfile());
        ExitProcess(CONSOLE_EXIT);
    }

    if (!CreateTestUser(User, RTL_NUMBER_OF(User)))
        return;

    hWinSta = GetProcessWindowStation();
    hDesktop = GetThreadDesktop(GetCurrentThreadId());
    WinStaAces = AceCount(hWinSta);
    DesktopAces = AceCount(hDesktop);

    /* A GUI program: no desktop given, the process must land on WinSta0\Default and open a window */
    Exit = RunChild(User, TestPassword, "gui", NULL, &Started, &Error);
    ok(Started, "CreateProcessWithLogonW (gui, no desktop) failed: %lu\n", Error);
    if (Started)
        ok(Exit == 0, "gui child, no desktop: step %lu, error %lu (exit 0x%lx)\n", Exit & 0xff, Exit >> 8, Exit);

    /*
     * A caller on a window station that is not interactive: with no desktop named the child gets the
     * caller's window station and desktop, never WinSta0
     */
    {
        WCHAR WsName[40];
        CHAR Mode[96], WsNameA[40];
        HWINSTA hOldWs = GetProcessWindowStation(), hWs;
        HDESK hOldDesk = hDesktop, hDesk = NULL;

        StringCchPrintfW(WsName, RTL_NUMBER_OF(WsName), L"rguiws%lx", GetCurrentProcessId());
        WideCharToMultiByte(CP_ACP, 0, WsName, -1, WsNameA, sizeof(WsNameA), NULL, NULL);
        StringCchPrintfA(Mode, RTL_NUMBER_OF(Mode), "gui %s Default", WsNameA);
        hWs = CreateWindowStationW(WsName, 0, GENERIC_ALL, NULL);
        if (hWs == NULL)
        {
            skip("CreateWindowStation failed: %lu\n", GetLastError());
        }
        else
        {
            if (SetProcessWindowStation(hWs))
            {
                hDesk = CreateDesktopW(L"Default", NULL, NULL, 0, GENERIC_ALL, NULL);
                if (hDesk != NULL && SetThreadDesktop(hDesk))
                {
                    Exit = RunChild(User, TestPassword, Mode, NULL, &Started, &Error);
                    ok(Started, "CreateProcessWithLogonW (gui, non-interactive caller) failed: %lu\n", Error);
                    if (Started)
                        ok(Exit == 0, "gui child, caller on %ls\\Default: step %lu, error %lu (exit 0x%lx)\n",
                           WsName, Exit & 0xff, Exit >> 8, Exit);
                }
                else
                {
                    skip("CreateDesktop/SetThreadDesktop failed: %lu\n", GetLastError());
                }
                SetThreadDesktop(hOldDesk);
                SetProcessWindowStation(hOldWs);
            }
            if (hDesk != NULL)
                CloseDesktop(hDesk);
            CloseWindowStation(hWs);
        }
    }

    /* The same with the desktop named */
    Exit = RunChild(User, TestPassword, "gui", L"WinSta0\\Default", &Started, &Error);
    ok(Started, "CreateProcessWithLogonW (gui, WinSta0\\Default) failed: %lu\n", Error);
    if (Started)
        ok(Exit == 0, "gui child, WinSta0\\Default: step %lu, error %lu (exit 0x%lx)\n", Exit & 0xff, Exit >> 8, Exit);

    /* A console program still runs */
    Exit = RunChild(User, TestPassword, "console", NULL, &Started, &Error);
    ok(Started, "CreateProcessWithLogonW (console) failed: %lu\n", Error);
    if (Started)
        ok(Exit == CONSOLE_EXIT, "console child: exit code %lu\n", Exit);

    /*
     * LOGON_WITH_PROFILE (runas' default): the child runs with its own hive loaded as HKEY_CURRENT_USER
     * and can write it; the profile is unloaded again once the child has exited (CreateProcessWithLogonW
     * documents this for LOGON_WITH_PROFILE; the time it takes is not measured, so a few seconds are allowed).
     */
    {
        PWSTR Sid = AccountSidString(User);
        HKEY Loaded;
        LONG Open = ERROR_SUCCESS;

        ok(Sid != NULL, "LookupAccountName(%ls) failed: %lu\n", User, GetLastError());
        Exit = RunChildFlags(User, TestPassword, LOGON_WITH_PROFILE, "profile", NULL, &Started, &Error);
        ok(Started, "CreateProcessWithLogonW (LOGON_WITH_PROFILE) failed: %lu\n", Error);
        if (Started)
            ok(Exit == 0, "profile child: step %lu, error %lu (exit 0x%lx)\n", Exit & 0xff, Exit >> 8, Exit);
        if (Started && Sid != NULL)
        {
            for (i = 0; i < 100; i++)
            {
                Open = RegOpenKeyExW(HKEY_USERS, Sid, 0, KEY_QUERY_VALUE, &Loaded);
                if (Open != ERROR_SUCCESS)
                    break;
                RegCloseKey(Loaded);
                Sleep(100);
            }
            ok(Open == ERROR_FILE_NOT_FOUND, "the hive of %ls is still loaded after the child exited: %ld\n", User, Open);
        }

        /* The same again: the profile exists now and is loaded a second time */
        Exit = RunChildFlags(User, TestPassword, LOGON_WITH_PROFILE, "profile", NULL, &Started, &Error);
        ok(Started, "CreateProcessWithLogonW (LOGON_WITH_PROFILE, existing profile) failed: %lu\n", Error);
        if (Started)
            ok(Exit == 0, "profile child, existing profile: step %lu, error %lu (exit 0x%lx)\n",
               Exit & 0xff, Exit >> 8, Exit);
        if (Sid != NULL)
            LocalFree(Sid);
    }

    /* A wrong password */
    Exit = RunChild(User, L"not-the-password", "console", NULL, &Started, &Error);
    ok(!Started, "CreateProcessWithLogonW with a wrong password succeeded\n");
    ok(Error == ERROR_LOGON_FAILURE, "wrong password: error %lu, expected %d\n", Error, ERROR_LOGON_FAILURE);

    /* The logon of the children is taken out of the window station and the desktop again when they have exited
     * (this is how the service of ReactOS does it, Windows was not measured) */
    for (i = 0; i < 50; i++)
    {
        if (AceCount(hWinSta) == WinStaAces && AceCount(hDesktop) == DesktopAces)
            break;
        Sleep(100);
    }
    if (is_reactos())
    {
        ok(AceCount(hWinSta) == WinStaAces, "window station DACL: %lu ACEs, was %lu\n", AceCount(hWinSta), WinStaAces);
        ok(AceCount(hDesktop) == DesktopAces, "desktop DACL: %lu ACEs, was %lu\n", AceCount(hDesktop), DesktopAces);
    }
    else
    {
        trace("window station DACL: %lu ACEs, was %lu; desktop DACL: %lu, was %lu\n",
              AceCount(hWinSta), WinStaAces, AceCount(hDesktop), DesktopAces);
    }

    NetStatus = NetUserDel(NULL, User);
    ok(NetStatus == NERR_Success, "NetUserDel(%ls) failed: %lu\n", User, NetStatus);
}
