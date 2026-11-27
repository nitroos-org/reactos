/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Which owner a caller may give a new object, or set on an existing one
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <wingdi.h>
#include <winuser.h>
#include <sddl.h>

/*
 * A security descriptor that names an owner, given to the create of an event (named and unnamed),
 * a mutex, a section, a named pipe, a file and a directory (on a volume with persistent ACLs), a
 * registry key, a token duplicate, a job, a window station and a desktop, and the same owner set
 * on an existing object of each type with SetKernelObjectSecurity / SetUserObjectSecurity.
 *
 * Measured on Windows Server 2022 (an elevated administrator with SeRestorePrivilege and
 * SeTakeOwnershipPrivilege each enabled and not, and a standard user, for every type above but the
 * job, the window station and the desktop): the owner may be the caller's user or one of its
 * groups that has SE_GROUP_OWNER; any other SID (SYSTEM, the Administrators of a token where
 * they are deny-only or not an owner group, a plain group of the caller, the logon SID, another
 * user, TrustedInstaller, an unknown SID) fails with ERROR_INVALID_OWNER unless
 * SeRestorePrivilege is enabled; SeTakeOwnershipPrivilege does not help. The primary group is not
 * checked. The job, window station and desktop rows expect the same rule.
 *
 * Principals: the caller's token as it is (the harness runs as an administrator), and a
 * restricted copy of it, impersonated, without privileges and with the Administrators deny-only
 * (what a standard user's token is to the rule). The test checks the rule's outcome against the
 * token's own groups, and the fixed rows: deny-only Administrators, SYSTEM, a plain group, an
 * unknown SID refused without SeRestorePrivilege; the user always accepted.
 *
 * OBJOWNER_NO_WINDOW_OBJECTS=1 in the environment skips the job, window station and desktop rows
 * (they were not probed on the Windows reference).
 */

enum { O_EVENT, O_EVENTU, O_MUTEX, O_SECTION, O_PIPE, O_FILE, O_DIR, O_KEY, O_TOKEN, O_JOB, O_WINSTA, O_DESKTOP, O_COUNT };
static const char *ObjName[O_COUNT] = { "event", "unnamed event", "mutex", "section", "pipe", "file", "directory",
                                        "key", "token", "job", "window station", "desktop" };

static HANDLE EffToken;
static HWINSTA Container, OldStation;
static HKEY BaseKey;
static WCHAR Dir[MAX_PATH];
static BOOL HaveAcls, NoWindowObjects;
static DWORD Seq;

typedef struct
{
    const char *Name;
    PSID Sid;
} SIDROW;

static BOOL SetPrivileges(BOOL Restore, BOOL TakeOwnership, BOOL *Held)
{
    struct { DWORD Count; LUID_AND_ATTRIBUTES P[2]; } Tp;

    Tp.Count = 2;
    LookupPrivilegeValueW(NULL, L"SeRestorePrivilege", &Tp.P[0].Luid);
    LookupPrivilegeValueW(NULL, L"SeTakeOwnershipPrivilege", &Tp.P[1].Luid);
    Tp.P[0].Attributes = Restore ? SE_PRIVILEGE_ENABLED : 0;
    Tp.P[1].Attributes = TakeOwnership ? SE_PRIVILEGE_ENABLED : 0;
    SetLastError(0xdeadbeef);
    if (!AdjustTokenPrivileges(EffToken, FALSE, (PTOKEN_PRIVILEGES)&Tp, 0, NULL, NULL))
        return FALSE;
    *Held = (GetLastError() == ERROR_SUCCESS);
    return TRUE;
}

/* Whether the token lets its holder name the SID as owner without a privilege */
static BOOL OwnerAllowed(HANDLE Token, PSID Sid)
{
    BYTE Buffer[8192];
    TOKEN_USER *User = (TOKEN_USER *)Buffer;
    TOKEN_GROUPS *Groups = (TOKEN_GROUPS *)Buffer;
    DWORD Length, i;

    if (GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Length) && EqualSid(User->User.Sid, Sid))
        return TRUE;
    if (!GetTokenInformation(Token, TokenGroups, Buffer, sizeof(Buffer), &Length))
        return FALSE;
    for (i = 0; i < Groups->GroupCount; i++)
    {
        if (EqualSid(Groups->Groups[i].Sid, Sid) &&
            (Groups->Groups[i].Attributes & SE_GROUP_OWNER) &&
            !(Groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static HANDLE CreateOne(int Object, PSECURITY_DESCRIPTOR Sd, WCHAR *Path, DWORD *Error)
{
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), Sd, FALSE };
    LPSECURITY_ATTRIBUTES pSa = Sd ? &Sa : NULL;
    WCHAR Name[MAX_PATH];
    HANDLE Handle = NULL;

    Path[0] = 0;
    StringCchPrintfW(Name, _countof(Name), L"ObjectOwner_%lu_%lu", GetCurrentProcessId(), ++Seq);
    SetLastError(0xdeadbeef);
    switch (Object)
    {
    case O_EVENT: Handle = CreateEventW(pSa, TRUE, FALSE, Name); break;
    case O_EVENTU: Handle = CreateEventW(pSa, TRUE, FALSE, NULL); break;
    case O_MUTEX: Handle = CreateMutexW(pSa, FALSE, Name); break;
    case O_SECTION: Handle = CreateFileMappingW(INVALID_HANDLE_VALUE, pSa, PAGE_READWRITE, 0, 4096, Name); break;
    case O_PIPE:
        StringCchPrintfW(Path, MAX_PATH, L"\\\\.\\pipe\\%s", Name);
        Handle = CreateNamedPipeW(Path, PIPE_ACCESS_DUPLEX | WRITE_DAC | WRITE_OWNER, PIPE_TYPE_BYTE, 1, 512, 512, 0, pSa);
        Path[0] = 0;
        if (Handle == INVALID_HANDLE_VALUE)
            Handle = NULL;
        break;
    case O_FILE:
        StringCchPrintfW(Path, MAX_PATH, L"%s\\%s", Dir, Name);
        Handle = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | DELETE, 0, pSa,
                             CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
        Path[0] = 0;
        if (Handle == INVALID_HANDLE_VALUE)
            Handle = NULL;
        break;
    case O_DIR:
        StringCchPrintfW(Path, MAX_PATH, L"%s\\%s", Dir, Name);
        if (!CreateDirectoryW(Path, pSa))
        {
            Path[0] = 0;
            break;
        }
        Handle = CreateFileW(Path, READ_CONTROL | WRITE_DAC | WRITE_OWNER | DELETE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (Handle == INVALID_HANDLE_VALUE)
            Handle = NULL;
        break;
    case O_KEY:
    {
        HKEY Key;
        LONG Result = RegCreateKeyExW(BaseKey, Name, 0, NULL, 0, KEY_ALL_ACCESS, pSa, &Key, NULL);
        if (Result != ERROR_SUCCESS)
            SetLastError(Result);
        else
        {
            Handle = (HANDLE)Key;
            StringCchCopyW(Path, MAX_PATH, Name);
        }
        break;
    }
    case O_TOKEN:
        if (!DuplicateTokenEx(EffToken, TOKEN_ALL_ACCESS, pSa, SecurityImpersonation, TokenImpersonation, &Handle))
            Handle = NULL;
        break;
    case O_JOB: Handle = CreateJobObjectW(pSa, Name); break;
    case O_WINSTA:
        Handle = CreateWindowStationW(Name, 0, WINSTA_ALL_ACCESS | READ_CONTROL | WRITE_DAC | WRITE_OWNER, pSa);
        break;
    case O_DESKTOP:
    {
        DWORD Saved;
        if (!Container || !SetProcessWindowStation(Container))
            break;
        Handle = CreateDesktopW(Name, NULL, NULL, 0,
                                DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | READ_CONTROL | WRITE_DAC | WRITE_OWNER, pSa);
        Saved = GetLastError();
        SetProcessWindowStation(OldStation);
        SetLastError(Saved);
        break;
    }
    }
    *Error = Handle ? ERROR_SUCCESS : GetLastError();
    return Handle;
}

static void CloseOne(int Object, HANDLE Handle, const WCHAR *Path)
{
    if (!Handle)
        return;
    if (Object == O_KEY)
    {
        RegCloseKey((HKEY)Handle);
        RegDeleteKeyW(BaseKey, Path);
    }
    else if (Object == O_WINSTA)
        CloseWindowStation((HWINSTA)Handle);
    else if (Object == O_DESKTOP)
        CloseDesktop((HDESK)Handle);
    else
    {
        CloseHandle(Handle);
        if (Object == O_DIR && Path[0])
            RemoveDirectoryW(Path);
    }
}

static BOOL IsUserObject(int Object)
{
    return Object == O_WINSTA || Object == O_DESKTOP;
}

/* The owner (or group) of the object, compared with the SID */
static BOOL HasSid(int Object, HANDLE Handle, BOOL Group, PSID Sid)
{
    BYTE Buffer[2048];
    SECURITY_INFORMATION Info = Group ? GROUP_SECURITY_INFORMATION : OWNER_SECURITY_INFORMATION;
    DWORD Length;
    PSID Got = NULL;
    BOOL Defaulted;

    if (IsUserObject(Object) ? !GetUserObjectSecurity(Handle, &Info, Buffer, sizeof(Buffer), &Length)
                             : !GetKernelObjectSecurity(Handle, Info, Buffer, sizeof(Buffer), &Length))
    {
        return FALSE;
    }
    if (Group)
        GetSecurityDescriptorGroup(Buffer, &Got, &Defaulted);
    else
        GetSecurityDescriptorOwner(Buffer, &Got, &Defaulted);
    return Got && EqualSid(Got, Sid);
}

static void TestRow(const char *Who, const char *Privs, int Object, const SIDROW *Row, BOOL Group, BOOL Expected)
{
    SECURITY_DESCRIPTOR Sd;
    SECURITY_INFORMATION Info = Group ? GROUP_SECURITY_INFORMATION : OWNER_SECURITY_INFORMATION;
    HANDLE Handle;
    WCHAR Path[MAX_PATH];
    DWORD Error;
    BOOL Ok;
    const char *What = Group ? "group" : "owner";

    InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    if (Group)
        SetSecurityDescriptorGroup(&Sd, Row->Sid, FALSE);
    else
        SetSecurityDescriptorOwner(&Sd, Row->Sid, FALSE);

    /* Created with it (Windows denies a window station to the restricted token whatever its descriptor) */
    Handle = CreateOne(Object, &Sd, Path, &Error);
    if (!Handle && Object == O_WINSTA && Error == ERROR_ACCESS_DENIED)
    {
        skip("%s: no window station may be created\n", Who);
        return;
    }
    if (Expected)
    {
        ok(Handle != NULL, "%s %s: create %s with %s %s: error %lu\n", Who, Privs, ObjName[Object], What, Row->Name, Error);
        if (Handle)
        {
            ok(HasSid(Object, Handle, Group, Row->Sid), "%s %s: %s created with %s %s has another\n",
               Who, Privs, ObjName[Object], What, Row->Name);
        }
    }
    else
    {
        ok(Handle == NULL && Error == ERROR_INVALID_OWNER, "%s %s: create %s with %s %s: %s, error %lu\n",
           Who, Privs, ObjName[Object], What, Row->Name, Handle ? "created" : "failed", Error);
    }
    CloseOne(Object, Handle, Path);

    /* Set on one made without it (an unnamed event has no security descriptor to set on Windows) */
    if (Object == O_EVENTU)
        return;
    Handle = CreateOne(Object, NULL, Path, &Error);
    if (!Handle)
    {
        skip("%s: create %s failed, error %lu\n", Who, ObjName[Object], Error);
        return;
    }
    SetLastError(0xdeadbeef);
    Ok = IsUserObject(Object) ? SetUserObjectSecurity(Handle, &Info, &Sd) : SetKernelObjectSecurity(Handle, Info, &Sd);
    Error = GetLastError();
    if (Expected)
    {
        ok(Ok, "%s %s: set %s %s on %s: error %lu\n", Who, Privs, What, Row->Name, ObjName[Object], Error);
        if (Ok)
            ok(HasSid(Object, Handle, Group, Row->Sid), "%s %s: %s of %s not set\n", Who, Privs, What, ObjName[Object]);
    }
    else
    {
        ok(!Ok && Error == ERROR_INVALID_OWNER, "%s %s: set %s %s on %s: %s, error %lu\n",
           Who, Privs, What, Row->Name, ObjName[Object], Ok ? "set" : "failed", Error);
    }
    CloseOne(Object, Handle, Path);
}

static void TestToken(const char *Who, HANDLE Token, PSID Plain, PSID Logon)
{
    BYTE UserBuffer[256];
    TOKEN_USER *User = (TOKEN_USER *)UserBuffer;
    DWORD Length;
    PSID Admins = NULL, System = NULL, Unknown = NULL, Installer = NULL;
    SIDROW Rows[7];
    int RowCount = 0, State, Object, i;
    BOOL Held = FALSE;
    static const char *StateName[] = { "no privilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "both" };

    ok(GetTokenInformation(Token, TokenUser, UserBuffer, sizeof(UserBuffer), &Length), "TokenUser: %lu\n", GetLastError());
    ConvertStringSidToSidW(L"S-1-5-32-544", &Admins);
    ConvertStringSidToSidW(L"S-1-5-18", &System);
    ConvertStringSidToSidW(L"S-1-5-21-1111111111-2222222222-3333333333-4242", &Unknown);
    ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &Installer);
    Rows[RowCount].Name = "user"; Rows[RowCount++].Sid = User->User.Sid;
    Rows[RowCount].Name = "Administrators"; Rows[RowCount++].Sid = Admins;
    Rows[RowCount].Name = "SYSTEM"; Rows[RowCount++].Sid = System;
    Rows[RowCount].Name = "unknown"; Rows[RowCount++].Sid = Unknown;
    Rows[RowCount].Name = "TrustedInstaller"; Rows[RowCount++].Sid = Installer;
    if (Plain)
    {
        Rows[RowCount].Name = "plain group"; Rows[RowCount++].Sid = Plain;
    }
    if (Logon)
    {
        Rows[RowCount].Name = "logon SID"; Rows[RowCount++].Sid = Logon;
    }

    /* The rule's fixed rows, whatever the token */
    ok(OwnerAllowed(Token, User->User.Sid), "%s: the user is not an allowed owner\n", Who);
    ok(!OwnerAllowed(Token, System), "%s: SYSTEM is an owner group of the token\n", Who);
    ok(!OwnerAllowed(Token, Unknown), "%s: the unknown SID is an owner group of the token\n", Who);

    for (State = 0; State < 4; State++)
    {
        BOOL Restore;

        Held = FALSE;
        if (!SetPrivileges(State & 1, State & 2, &Held))
        {
            skip("%s: AdjustTokenPrivileges failed: %lu\n", Who, GetLastError());
            continue;
        }
        if (State != 0 && !Held)
        {
            trace("%s: %s not held, rows as without\n", Who, StateName[State]);
            continue;
        }
        Restore = (State & 1) != 0;
        for (Object = 0; Object < O_COUNT; Object++)
        {
            if ((Object == O_FILE || Object == O_DIR) && !HaveAcls)
                continue;
            if (NoWindowObjects && (Object == O_JOB || Object == O_WINSTA || Object == O_DESKTOP))
                continue;
            for (i = 0; i < RowCount; i++)
            {
                TestRow(Who, StateName[State], Object, &Rows[i], FALSE, Restore || OwnerAllowed(Token, Rows[i].Sid));
                TestRow(Who, StateName[State], Object, &Rows[i], TRUE, TRUE);
            }
        }
    }
    SetPrivileges(FALSE, FALSE, &Held);

    LocalFree(Admins);
    LocalFree(System);
    LocalFree(Unknown);
    LocalFree(Installer);
}

/* An enabled group of the token without SE_GROUP_OWNER (Users, else any), and its logon SID */
static void PlainAndLogon(HANDLE Token, PSID *Plain, PSID *Logon)
{
    static BYTE Buffer[8192];
    TOKEN_GROUPS *Groups = (TOKEN_GROUPS *)Buffer;
    PSID Users = NULL;
    DWORD Length, i;

    *Plain = *Logon = NULL;
    if (!GetTokenInformation(Token, TokenGroups, Buffer, sizeof(Buffer), &Length))
        return;
    ConvertStringSidToSidW(L"S-1-5-32-545", &Users);
    for (i = 0; i < Groups->GroupCount; i++)
    {
        DWORD Attributes = Groups->Groups[i].Attributes;
        if ((Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
        {
            if (!*Logon)
                *Logon = Groups->Groups[i].Sid;
            continue;
        }
        if ((Attributes & (SE_GROUP_OWNER | SE_GROUP_USE_FOR_DENY_ONLY)) || !(Attributes & SE_GROUP_ENABLED) ||
            GetSidIdentifierAuthority(Groups->Groups[i].Sid)->Value[5] == 16)
        {
            continue;
        }
        if (!*Plain || (Users && EqualSid(Users, Groups->Groups[i].Sid)))
            *Plain = Groups->Groups[i].Sid;
    }
    LocalFree(Users);
}

START_TEST(ObjectOwner)
{
    HANDLE Process, Restricted = NULL, Impersonation = NULL;
    PSECURITY_DESCRIPTOR Everyone = NULL;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, FALSE };
    SID_AND_ATTRIBUTES Disable;
    WCHAR Root[4], Env[8];
    DWORD Flags = 0;
    PSID Admins = NULL, Plain, Logon;

    NoWindowObjects = GetEnvironmentVariableW(L"OBJOWNER_NO_WINDOW_OBJECTS", Env, _countof(Env)) && Env[0] == L'1';

    /* Scratch places a restricted token may create in */
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;WD)(A;OICI;GA;;;RC)", SDDL_REVISION_1,
                                                            &Everyone, NULL), "SDDL: %lu\n", GetLastError());
    Sa.lpSecurityDescriptor = Everyone;
    GetTempPathW(_countof(Dir), Dir);
    StringCchCatW(Dir, _countof(Dir), L"ObjectOwnerTest");
    CreateDirectoryW(Dir, &Sa);
    StringCchCopyNW(Root, _countof(Root), Dir, 3);
    HaveAcls = GetVolumeInformationW(Root, NULL, 0, NULL, NULL, &Flags, NULL, 0) && (Flags & FS_PERSISTENT_ACLS);
    if (!HaveAcls)
        skip("%S has no persistent ACLs: no file rows\n", Root);
    ok(RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ObjectOwnerTest", 0, NULL, 0, KEY_ALL_ACCESS, &Sa, &BaseKey, NULL) ==
       ERROR_SUCCESS, "key\n");
    if (!NoWindowObjects)
    {
        OldStation = GetProcessWindowStation();
        Container = CreateWindowStationW(L"ObjectOwnerTest", 0, WINSTA_ALL_ACCESS | READ_CONTROL, &Sa);
        ok(Container != NULL, "container window station: %lu\n", GetLastError());
    }

    /* 1. The caller's token as it is */
    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Process), "OpenProcessToken: %lu\n", GetLastError());
    EffToken = Process;
    PlainAndLogon(Process, &Plain, &Logon);
    TestToken("caller", Process, Plain, Logon);

    /* 2. No privileges, Administrators deny-only, impersonated */
    ConvertStringSidToSidW(L"S-1-5-32-544", &Admins);
    Disable.Sid = Admins;
    Disable.Attributes = 0;
    ok(CreateRestrictedToken(Process, DISABLE_MAX_PRIVILEGE, 1, &Disable, 0, NULL, 0, NULL, &Restricted),
       "CreateRestrictedToken: %lu\n", GetLastError());
    if (Restricted &&
        DuplicateTokenEx(Restricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Impersonation) &&
        SetThreadToken(NULL, Impersonation))
    {
        EffToken = Impersonation;
        ok(!OwnerAllowed(Impersonation, Admins), "deny-only Administrators are an allowed owner\n");
        PlainAndLogon(Impersonation, &Plain, &Logon);
        TestToken("restricted", Impersonation, Plain, Logon);
        RevertToSelf();
    }
    else
        skip("no restricted impersonation: %lu\n", GetLastError());

    if (Impersonation)
        CloseHandle(Impersonation);
    if (Restricted)
        CloseHandle(Restricted);
    CloseHandle(Process);
    LocalFree(Admins);
    if (Container)
        CloseWindowStation(Container);
    RegCloseKey(BaseKey);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\ObjectOwnerTest");
    RemoveDirectoryW(Dir);
    LocalFree(Everyone);
}
