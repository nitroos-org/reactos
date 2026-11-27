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
#include <ndk/exfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>

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
#define STEP_NAMED      20  /* 20 + n: named object n (see ChildNamed) could not be created */
#define STEP_LAUNCH     30  /* the launcher could not start its own child */
#define STEP_RESULT     31  /* the grandchild cannot report through the caller's section and event */
#define STEP_WSDIR      44  /* the WindowStations directory of the session cannot be opened */
#define STEP_WSDIRMASK  45  /* ... grants other rights than traverse */
#define STEP_WSDIREVENT 46  /* ... an event could be created in it */
#define STEP_WSCREATE   47  /* a named window station could not be created */
#define STEP_WSEXCLUSIVE 48 /* OBJ_KERNEL_EXCLUSIVE of a program was honoured (its window station cannot be opened) */
#ifndef OBJ_KERNEL_EXCLUSIVE
#define OBJ_KERNEL_EXCLUSIVE 0x00010000L /* kernel-mode only (ndk/obtypes.h) */
#endif
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
/*
 * The program of the secondary logon creates named objects in the namespace of its session: an event, a mutex
 * and a section with a plain and with a Local\ name, and an event with a Global\ name (measured on Windows
 * Server 2022: all succeed for a standard user started by a standard user; a Global\ section needs
 * SeCreateGlobalPrivilege and is not tried)
 */
static DWORD ChildNamed(VOID)
{
    static const PCWSTR Prefixes[] = { L"", L"Local\\" };
    WCHAR Name[64];
    HANDLE Objects[7] = { NULL };
    DWORD i, n = 0, Result = 0;

    for (i = 0; i < RTL_NUMBER_OF(Prefixes) && !Result; i++)
    {
        StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"%lsrgui-ev-%lx", Prefixes[i], GetCurrentProcessId());
        if (!(Objects[n++] = CreateEventW(NULL, TRUE, FALSE, Name)))
            Result = Fail(STEP_NAMED + n);
        StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"%lsrgui-mx-%lx", Prefixes[i], GetCurrentProcessId());
        if (!Result && !(Objects[n++] = CreateMutexW(NULL, FALSE, Name)))
            Result = Fail(STEP_NAMED + n);
        StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"%lsrgui-sc-%lx", Prefixes[i], GetCurrentProcessId());
        if (!Result && !(Objects[n++] = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, Name)))
            Result = Fail(STEP_NAMED + n);
    }
    StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"Global\\rgui-ev-%lx", GetCurrentProcessId());
    if (!Result && !(Objects[n++] = CreateEventW(NULL, TRUE, FALSE, Name)))
        Result = Fail(STEP_NAMED + n);
    for (i = 0; i < n; i++)
    {
        if (Objects[i])
            CloseHandle(Objects[i]);
    }
    return Result;
}

/*
 * A launcher: the program of the secondary logon starts the real program and exits at once. The real program
 * (ChildGrand) waits 5 s, then creates its named objects and opens the desktop and makes a window there, and
 * reports through the caller's section and event (their names carry Tag).
 */
static DWORD ChildLaunch(PCSTR Tag)
{
    WCHAR Exe[MAX_PATH], Command[MAX_PATH + 128];
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;

    GetModuleFileNameW(NULL, Exe, RTL_NUMBER_OF(Exe));
    StringCchPrintfW(Command, RTL_NUMBER_OF(Command), L"\"%ls\" CreateProcessWithLogon child grand %hs", Exe, Tag);
    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    if (!CreateProcessW(NULL, Command, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
        return Fail(STEP_LAUNCH);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    return 0;
}

static DWORD ChildGrand(PCSTR Tag)
{
    WCHAR Name[64];
    HANDLE Section, Event;
    DWORD *Result, Value;

    Sleep(5000);
    Value = ChildNamed();
    if (Value == 0)
        Value = ChildGui(L"WinSta0", L"Default");

    StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"rgui-res-%hs", Tag);
    Section = OpenFileMappingW(FILE_MAP_WRITE, FALSE, Name);
    StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"rgui-done-%hs", Tag);
    Event = OpenEventW(EVENT_MODIFY_STATE, FALSE, Name);
    if (!Section || !Event)
        return Fail(STEP_RESULT);
    Result = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, sizeof(DWORD));
    if (!Result)
        return Fail(STEP_RESULT);
    *Result = Value;
    UnmapViewOfFile(Result);
    SetEvent(Event);
    CloseHandle(Event);
    CloseHandle(Section);
    return Value;
}

/*
 * The WindowStations directory of the program's session gives it what Windows Server 2022 gives a standard user
 * there (measured: traverse, 0x2): no object of its own can be put into it. A window station is still created
 * through the window manager, which puts it there (not measured on Windows: no CreateWindowStation on the
 * reference; ReactOS keeps what programs could do before).
 */
static DWORD ChildWinStaDir(VOID)
{
    WCHAR Path[80];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    OBJECT_BASIC_INFORMATION Info;
    HANDLE Directory, Event;
    HWINSTA WinSta;
    DWORD Session = 0;
    NTSTATUS Status;

    ProcessIdToSessionId(GetCurrentProcessId(), &Session);
    if (Session == 0)
        return 0;
    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"\\Sessions\\%lu\\Windows\\WindowStations", Session);
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenDirectoryObject(&Directory, MAXIMUM_ALLOWED, &Attributes);
    if (!NT_SUCCESS(Status))
        return (RtlNtStatusToDosError(Status) << 8) | STEP_WSDIR;
    Status = NtQueryObject(Directory, ObjectBasicInformation, &Info, sizeof(Info), NULL);
    NtClose(Directory);
    if (!NT_SUCCESS(Status) || Info.GrantedAccess != DIRECTORY_TRAVERSE)
        return (Info.GrantedAccess << 8) | STEP_WSDIRMASK;

    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"\\Sessions\\%lu\\Windows\\WindowStations\\rgui-ev-%lx",
                     Session, GetCurrentProcessId());
    RtlInitUnicodeString(&Name, Path);
    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, &Attributes, NotificationEvent, FALSE);
    if (NT_SUCCESS(Status))
    {
        NtClose(Event);
        return STEP_WSDIREVENT;
    }
    if (Status != STATUS_ACCESS_DENIED)
        return (RtlNtStatusToDosError(Status) << 8) | STEP_WSDIREVENT;

    if (is_reactos())
    {
        StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"rguiws-%lx", GetCurrentProcessId());
        WinSta = CreateWindowStationW(Path, 0, WINSTA_ALL_ACCESS, NULL);
        if (!WinSta)
            return Fail(STEP_WSCREATE);
        CloseWindowStation(WinSta);

        /*
         * The window station is created for the program, not for the kernel: OBJ_KERNEL_EXCLUSIVE, which only kernel
         * callers may set, is not honoured (else nobody could open the window station from user mode)
         */
        {
            typedef HWINSTA (NTAPI *PNTUSERCREATEWINDOWSTATION)(POBJECT_ATTRIBUTES, ACCESS_MASK, DWORD, DWORD, DWORD,
                                                                DWORD, DWORD);
            PNTUSERCREATEWINDOWSTATION pNtUserCreateWindowStation;
            HWINSTA Open;

            pNtUserCreateWindowStation = (PNTUSERCREATEWINDOWSTATION)
                GetProcAddress(LoadLibraryW(L"win32u.dll"), "NtUserCreateWindowStation");
            if (!pNtUserCreateWindowStation)
                return STEP_WSEXCLUSIVE;
            StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"\\Sessions\\%lu\\Windows\\WindowStations\\rguiex-%lx",
                             Session, GetCurrentProcessId());
            RtlInitUnicodeString(&Name, Path);
            InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_EXCLUSIVE, NULL, NULL);
            WinSta = pNtUserCreateWindowStation(&Attributes, WINSTA_ALL_ACCESS, 0, 0, 0, 0, 0);
            if (!WinSta)
                return Fail(STEP_WSEXCLUSIVE);
            StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"rguiex-%lx", GetCurrentProcessId());
            Open = OpenWindowStationW(Path, FALSE, WINSTA_ENUMDESKTOPS);
            if (!Open)
            {
                CloseWindowStation(WinSta);
                return Fail(STEP_WSEXCLUSIVE);
            }
            CloseWindowStation(Open);
            CloseWindowStation(WinSta);
        }
    }
    return 0;
}

/*
 * A copy of the security descriptor (DACL only) of a window station or desktop (User) or of an object of the
 * object manager, for a byte-for-byte comparison; HeapFree it
 */
static PSECURITY_DESCRIPTOR DaclCopy(HANDLE Object, BOOL User, DWORD *Length)
{
    SECURITY_INFORMATION Info = DACL_SECURITY_INFORMATION;
    PSECURITY_DESCRIPTOR Sd;
    ULONG Needed = 0;

    *Length = 0;
    if (User)
        GetUserObjectSecurity(Object, &Info, NULL, 0, &Needed);
    else
        NtQuerySecurityObject(Object, Info, NULL, 0, &Needed);
    if (Needed == 0)
        return NULL;
    Sd = HeapAlloc(GetProcessHeap(), 0, Needed);
    if (Sd == NULL)
        return NULL;
    if (User ? !GetUserObjectSecurity(Object, &Info, Sd, Needed, &Needed)
             : !NT_SUCCESS(NtQuerySecurityObject(Object, Info, Sd, Needed, &Needed)))
    {
        HeapFree(GetProcessHeap(), 0, Sd);
        return NULL;
    }
    *Length = Needed;
    return Sd;
}

/* The descriptors that a secondary logon changes for a while: the session's named-object directories, the window
   station and the desktop of the caller */
#define SNAP_COUNT 4
typedef struct _SNAPSHOT
{
    PSECURITY_DESCRIPTOR Sd[SNAP_COUNT];
    DWORD Length[SNAP_COUNT];
} SNAPSHOT;

static VOID TakeSnapshot(SNAPSHOT *Snap, HANDLE hWinSta, HANDLE hDesktop)
{
    static const PCWSTR Directories[] = { L"BaseNamedObjects", L"AppContainerNamedObjects" };
    WCHAR Path[64];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Directory;
    DWORD Session = 0, i;

    ZeroMemory(Snap, sizeof(*Snap));
    ProcessIdToSessionId(GetCurrentProcessId(), &Session);
    for (i = 0; i < RTL_NUMBER_OF(Directories); i++)
    {
        if (Session)
            StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"\\Sessions\\%lu\\%ls", Session, Directories[i]);
        else
            StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"\\%ls", Directories[i]);
        RtlInitUnicodeString(&Name, Path);
        InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(NtOpenDirectoryObject(&Directory, READ_CONTROL, &Attributes)))
        {
            Snap->Sd[i] = DaclCopy(Directory, FALSE, &Snap->Length[i]);
            NtClose(Directory);
        }
    }
    Snap->Sd[2] = DaclCopy(hWinSta, TRUE, &Snap->Length[2]);
    Snap->Sd[3] = DaclCopy(hDesktop, TRUE, &Snap->Length[3]);
}

static VOID FreeSnapshot(SNAPSHOT *Snap)
{
    DWORD i;

    for (i = 0; i < SNAP_COUNT; i++)
    {
        if (Snap->Sd[i])
            HeapFree(GetProcessHeap(), 0, Snap->Sd[i]);
    }
}

/* The index of the first descriptor that differs, SNAP_COUNT if all are equal byte for byte */
static DWORD CompareSnapshots(const SNAPSHOT *A, const SNAPSHOT *B)
{
    DWORD i;

    for (i = 0; i < SNAP_COUNT; i++)
    {
        if (A->Length[i] != B->Length[i] || (A->Sd[i] && B->Sd[i] && memcmp(A->Sd[i], B->Sd[i], A->Length[i])))
            return i;
    }
    return SNAP_COUNT;
}

/* Waits up to 20 s for the descriptors to be as in Before again; the index of the first that differs, or SNAP_COUNT */
static DWORD WaitForSnapshot(const SNAPSHOT *Before, HANDLE hWinSta, HANDLE hDesktop)
{
    SNAPSHOT Now;
    DWORD i, Diff = 0;

    for (i = 0; i < 200; i++)
    {
        TakeSnapshot(&Now, hWinSta, hDesktop);
        Diff = CompareSnapshots(Before, &Now);
        FreeSnapshot(&Now);
        if (Diff == SNAP_COUNT)
            break;
        Sleep(100);
    }
    return Diff;
}

/*
 * The number of ACEs in the DACL of the named-object directory of the caller's session and the size of that
 * DACL (the size the list was given, used and free), MAXDWORD if unknown
 */
static DWORD NamespaceAceCount(DWORD *AclBytes)
{
    WCHAR Path[64];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Directory;
    UCHAR Buffer[4096];
    PSECURITY_DESCRIPTOR Sd = (PSECURITY_DESCRIPTOR)Buffer;
    ACL_SIZE_INFORMATION Size;
    PACL Dacl;
    BOOL Present, Defaulted;
    DWORD Session = 0, Count = MAXDWORD;
    ULONG Length;

    *AclBytes = MAXDWORD;
    ProcessIdToSessionId(GetCurrentProcessId(), &Session);
    if (Session)
        StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"\\Sessions\\%lu\\BaseNamedObjects", Session);
    else
        StringCchCopyW(Path, RTL_NUMBER_OF(Path), L"\\BaseNamedObjects");
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(NtOpenDirectoryObject(&Directory, READ_CONTROL, &Attributes)))
        return MAXDWORD;
    if (NT_SUCCESS(NtQuerySecurityObject(Directory, DACL_SECURITY_INFORMATION, Sd, sizeof(Buffer), &Length)) &&
        GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted) && Present && Dacl != NULL &&
        GetAclInformation(Dacl, &Size, sizeof(Size), AclSizeInformation))
    {
        Count = Size.AceCount;
        *AclBytes = Size.AclBytesInUse + Size.AclBytesFree;
    }
    NtClose(Directory);
    return Count;
}

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
    DWORD Exit, Error, WinStaAces, DesktopAces, i, NamespaceAces, NamespaceBytes;
    HANDLE hWinSta, hDesktop;
    SNAPSHOT Before;
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
        if (!strcmp(argv[3], "named"))
            ExitProcess(ChildNamed());
        if (!strcmp(argv[3], "launch") && argc >= 5)
            ExitProcess(ChildLaunch(argv[4]));
        if (!strcmp(argv[3], "grand") && argc >= 5)
            ExitProcess(ChildGrand(argv[4]));
        if (!strcmp(argv[3], "winstadir"))
            ExitProcess(ChildWinStaDir());
        ExitProcess(CONSOLE_EXIT);
    }

    if (!CreateTestUser(User, RTL_NUMBER_OF(User)))
        return;
    NamespaceAces = NamespaceAceCount(&NamespaceBytes);

    hWinSta = GetProcessWindowStation();
    hDesktop = GetThreadDesktop(GetCurrentThreadId());
    WinStaAces = AceCount(hWinSta);
    DesktopAces = AceCount(hDesktop);
    TakeSnapshot(&Before, hWinSta, hDesktop);

    /*
     * A launcher: the program starts the real one and exits at once. The real one creates named objects and
     * opens the desktop 5 s later, when the program that the secondary logon started is long gone (Windows: the
     * logon carries the caller's logon SID, so nothing ever changes; here the entries of the logon stay until its
     * last process is gone). Then every descriptor is as it was before, byte for byte.
     */
    {
        SECURITY_ATTRIBUTES Sa;
        SECURITY_DESCRIPTOR OpenSd;
        CHAR Tag[16], Mode[32];
        WCHAR Name[64];
        HANDLE Section, Done;
        DWORD *Result, Diff;

        InitializeSecurityDescriptor(&OpenSd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&OpenSd, TRUE, NULL, FALSE);
        Sa.nLength = sizeof(Sa);
        Sa.lpSecurityDescriptor = &OpenSd;
        Sa.bInheritHandle = FALSE;
        StringCchPrintfA(Tag, RTL_NUMBER_OF(Tag), "%lx", GetCurrentProcessId());
        StringCchPrintfA(Mode, RTL_NUMBER_OF(Mode), "launch %s", Tag);
        StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"rgui-res-%hs", Tag);
        Section = CreateFileMappingW(INVALID_HANDLE_VALUE, &Sa, PAGE_READWRITE, 0, 4096, Name);
        StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"rgui-done-%hs", Tag);
        Done = CreateEventW(&Sa, TRUE, FALSE, Name);
        Result = Section ? MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, sizeof(DWORD)) : NULL;
        ok(Result != NULL && Done != NULL, "no section or event for the grandchild: %lu\n", GetLastError());
        if (Result != NULL && Done != NULL)
        {
            *Result = MAXDWORD;
            Exit = RunChild(User, TestPassword, Mode, NULL, &Started, &Error);
            ok(Started, "CreateProcessWithLogonW (launcher) failed: %lu\n", Error);
            if (Started)
            {
                ok(Exit == 0, "launcher child: step %lu, error %lu (exit 0x%lx)\n", Exit & 0xff, Exit >> 8, Exit);
                ok(WaitForSingleObject(Done, 30000) == WAIT_OBJECT_0, "the grandchild did not report\n");
                ok(*Result == 0, "grandchild, 5 s after the launcher exited: step %lu, error %lu (0x%lx)\n",
                   *Result & 0xff, *Result >> 8, *Result);
                Diff = WaitForSnapshot(&Before, hWinSta, hDesktop);
                ok(Diff == SNAP_COUNT, "descriptor %lu (0 BaseNamedObjects, 1 AppContainerNamedObjects, 2 window "
                   "station, 3 desktop) differs after the launcher's logon ended\n", Diff);
            }
        }
        if (Result) UnmapViewOfFile(Result);
        if (Section) CloseHandle(Section);
        if (Done) CloseHandle(Done);
    }

    /* The program's rights on the WindowStations directory of its session */
    Exit = RunChild(User, TestPassword, "winstadir", NULL, &Started, &Error);
    ok(Started, "CreateProcessWithLogonW (winstadir) failed: %lu\n", Error);
    if (Started)
        ok(Exit == 0, "WindowStations directory: step %lu, value 0x%lx (exit 0x%lx)\n", Exit & 0xff, Exit >> 8, Exit);

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
     * The program creates named objects in its session's namespace (single-instance checks, shared memory);
     * once it and the programs before it have exited the directory has the DACL it had before the first one,
     * also in size (Windows Server 2022: its DACL never changes; here the entry each program got is taken out
     * again when it has exited, which may come a moment after the exit)
     */
    {
        DWORD Now = MAXDWORD, Bytes = MAXDWORD;

        Exit = RunChild(User, TestPassword, "named", NULL, &Started, &Error);
        ok(Started, "CreateProcessWithLogonW (named) failed: %lu\n", Error);
        if (Started)
            ok(Exit == 0, "named-object child: object %lu, error %lu (exit 0x%lx)\n",
               (Exit & 0xff) - STEP_NAMED, Exit >> 8, Exit);
        for (i = 0; i < 50; i++)
        {
            Now = NamespaceAceCount(&Bytes);
            if (Now == NamespaceAces && Bytes == NamespaceBytes)
                break;
            Sleep(100);
        }
        ok(Now == NamespaceAces, "named-object directory DACL: %lu ACEs after the children, %lu before\n",
           Now, NamespaceAces);
        ok(Bytes == NamespaceBytes, "named-object directory DACL: %lu bytes after the children, %lu before\n",
           Bytes, NamespaceBytes);
    }

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

    /*
     * The program runs in the session of the calling process, whatever token the calling thread
     * impersonates: a token from LogonUser has the session id its creator set (0 here), not the caller's
     */
    {
        HANDLE hLogon = NULL;
        DWORD OwnSession = MAXDWORD, TokenSession = MAXDWORD, ChildSession = MAXDWORD, Length;
        WCHAR Exe[MAX_PATH], Command[MAX_PATH + 64];
        STARTUPINFOW Si;
        PROCESS_INFORMATION Pi;
        BOOL Ok;

        ProcessIdToSessionId(GetCurrentProcessId(), &OwnSession);
        if (!LogonUserW(User, L".", TestPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hLogon))
        {
            skip("LogonUser(%ls) failed: %lu\n", User, GetLastError());
        }
        else
        {
            GetTokenInformation(hLogon, TokenSessionId, &TokenSession, sizeof(TokenSession), &Length);
            GetModuleFileNameW(NULL, Exe, RTL_NUMBER_OF(Exe));
            StringCchPrintfW(Command, RTL_NUMBER_OF(Command), L"\"%ls\" CreateProcessWithLogon child console", Exe);
            ZeroMemory(&Si, sizeof(Si));
            Si.cb = sizeof(Si);
            ok(ImpersonateLoggedOnUser(hLogon), "ImpersonateLoggedOnUser failed: %lu\n", GetLastError());
            SetLastError(0xdeadbeef);
            Ok = CreateProcessWithLogonW(User, L".", TestPassword, 0, NULL, Command, 0, NULL, NULL, &Si, &Pi);
            Error = GetLastError();
            RevertToSelf();
            ok(Ok, "CreateProcessWithLogonW impersonating a token of session %lu (own session %lu) failed: %lu\n",
               TokenSession, OwnSession, Error);
            if (Ok)
            {
                PROCESS_SESSION_INFORMATION Info;

                /* By the handle: the account of the child gives the caller no access to it by its id */
                if (NT_SUCCESS(NtQueryInformationProcess(Pi.hProcess, ProcessSessionInformation, &Info, sizeof(Info), NULL)))
                    ChildSession = Info.SessionId;
                ok(ChildSession == OwnSession, "the child is in session %lu, the caller in %lu (token: %lu)\n",
                   ChildSession, OwnSession, TokenSession);
                WaitForSingleObject(Pi.hProcess, 60000);
                CloseHandle(Pi.hThread);
                CloseHandle(Pi.hProcess);
            }
            CloseHandle(hLogon);
        }
    }

    /* A wrong password */
    Exit = RunChild(User, L"not-the-password", "console", NULL, &Started, &Error);
    ok(!Started, "CreateProcessWithLogonW with a wrong password succeeded\n");
    ok(Error == ERROR_LOGON_FAILURE, "wrong password: error %lu, expected %d\n", Error, ERROR_LOGON_FAILURE);

    /*
     * The logon of the children is taken out of the window station, the desktop and the named-object directories
     * again when it has no process left (this is how the service of ReactOS does it; Windows Server 2022 changes
     * none of them): every descriptor is as before the first child, byte for byte
     */
    {
        DWORD Diff = WaitForSnapshot(&Before, hWinSta, hDesktop);

        ok(Diff == SNAP_COUNT, "descriptor %lu (0 BaseNamedObjects, 1 AppContainerNamedObjects, 2 window station, "
           "3 desktop) differs after all children\n", Diff);
        ok(AceCount(hWinSta) == WinStaAces, "window station DACL: %lu ACEs, was %lu\n", AceCount(hWinSta), WinStaAces);
        ok(AceCount(hDesktop) == DesktopAces, "desktop DACL: %lu ACEs, was %lu\n", AceCount(hDesktop), DesktopAces);
    }
    FreeSnapshot(&Before);

    NetStatus = NetUserDel(NULL, User);
    ok(NetStatus == NERR_Success, "NetUserDel(%ls) failed: %lu\n", User, NetStatus);
}
