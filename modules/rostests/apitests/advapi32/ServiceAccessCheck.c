/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The service controller checks the caller's token against the descriptor of the
 *              manager or of the service when a handle is opened, and every operation checks the
 *              right it needs against what the handle was granted.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected results were measured on Windows Server 2022 (build 20348) with the same callers
 * (LogonUser of a scratch standard user and a scratch administrator, LocalService, NetworkService,
 * an anonymous token, a token with restricting SIDs, the caller's own token with Administrators
 * deny-only) and the same scratch services. Run as LocalSystem or as an administrator.
 */

#include "precomp.h"
#include <lm.h>
#include <sddl.h>
#include <winsvc_undoc.h>

#ifndef LOGON32_LOGON_SERVICE
#define LOGON32_LOGON_SERVICE 5
#endif
#ifndef LOGON32_LOGON_NETWORK_CLEARTEXT
#define LOGON32_LOGON_NETWORK_CLEARTEXT 8
#endif

typedef struct
{
    DWORD Mask;
    PCSTR Name;
} RIGHT;

static const RIGHT MgrRights[] =
{
    { SC_MANAGER_CONNECT, "CONNECT" }, { SC_MANAGER_CREATE_SERVICE, "CREATE_SERVICE" },
    { SC_MANAGER_ENUMERATE_SERVICE, "ENUMERATE_SERVICE" }, { SC_MANAGER_LOCK, "LOCK" },
    { SC_MANAGER_QUERY_LOCK_STATUS, "QUERY_LOCK_STATUS" }, { SC_MANAGER_MODIFY_BOOT_CONFIG, "MODIFY_BOOT_CONFIG" },
    { DELETE, "DELETE" }, { READ_CONTROL, "READ_CONTROL" }, { WRITE_DAC, "WRITE_DAC" },
    { MAXIMUM_ALLOWED, "MAXIMUM_ALLOWED" }, { GENERIC_READ, "GENERIC_READ" }, { GENERIC_WRITE, "GENERIC_WRITE" },
    { GENERIC_EXECUTE, "GENERIC_EXECUTE" }, { GENERIC_ALL, "GENERIC_ALL" }, { SC_MANAGER_ALL_ACCESS, "ALL_ACCESS" },
};

static const RIGHT SvcRights[] =
{
    { SERVICE_QUERY_CONFIG, "QUERY_CONFIG" }, { SERVICE_CHANGE_CONFIG, "CHANGE_CONFIG" },
    { SERVICE_QUERY_STATUS, "QUERY_STATUS" }, { SERVICE_ENUMERATE_DEPENDENTS, "ENUMERATE_DEPENDENTS" },
    { SERVICE_START, "START" }, { SERVICE_STOP, "STOP" }, { SERVICE_PAUSE_CONTINUE, "PAUSE_CONTINUE" },
    { SERVICE_INTERROGATE, "INTERROGATE" }, { SERVICE_USER_DEFINED_CONTROL, "USER_DEFINED_CONTROL" },
    { DELETE, "DELETE" }, { READ_CONTROL, "READ_CONTROL" }, { WRITE_DAC, "WRITE_DAC" },
    { MAXIMUM_ALLOWED, "MAXIMUM_ALLOWED" }, { GENERIC_READ, "GENERIC_READ" }, { GENERIC_WRITE, "GENERIC_WRITE" },
    { GENERIC_EXECUTE, "GENERIC_EXECUTE" }, { GENERIC_ALL, "GENERIC_ALL" }, { SERVICE_ALL_ACCESS, "ALL_ACCESS" },
};

/* The opens that succeed, per caller and object (Windows Server 2022); every other one fails with 5 */
static const struct
{
    PCSTR Caller;
    PCSTR Object;
    PCSTR Granted;
} Expected[] =
{
#include "ServiceAccessCheck.inc"
};

/* The descriptors measured on Windows Server 2022 */
static const WCHAR ScmDaclSddl[] =
    L"D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)"
    L"(A;;CC;;;S-1-15-3-1024-528118966-3876874398-709513571-1907873084-3598227634-3698730060-278077788-3990600205)";
static const WCHAR DefaultServiceDaclSddl[] =
    L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

#define BA_ALL L"CCDCLCSWRPWPDTLOCRSDRCWDWO"
#define SY_DEF L"CCLCSWRPWPDTLOCRRC"

static WCHAR g_Password[40];
static WCHAR g_StdUser[24], g_AdmUser[24];
static WCHAR g_StdSid[128];
static WCHAR g_ExePath[MAX_PATH];
static BOOL g_SelfIsSystem;

/* ---------------------------------------------------------------- the scratch service process */

static SERVICE_STATUS_HANDLE g_Ssh;
static SERVICE_STATUS g_St;
static HANDLE g_Stop;

static DWORD WINAPI SvcHandler(DWORD Control, DWORD Type, LPVOID Data, LPVOID Context)
{
    switch (Control)
    {
        case SERVICE_CONTROL_STOP:
            g_St.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_Ssh, &g_St);
            SetEvent(g_Stop);
            return NO_ERROR;
        case SERVICE_CONTROL_PAUSE:
            g_St.dwCurrentState = SERVICE_PAUSED;
            break;
        case SERVICE_CONTROL_CONTINUE:
            g_St.dwCurrentState = SERVICE_RUNNING;
            break;
        case SERVICE_CONTROL_INTERROGATE:
        case SERVICE_CONTROL_PARAMCHANGE:
            break;
        default:
            if (Control < 128 || Control > 255)
                return ERROR_CALL_NOT_IMPLEMENTED;
            break;
    }
    SetServiceStatus(g_Ssh, &g_St);
    return NO_ERROR;
}

static void WINAPI SvcMain(DWORD Argc, LPWSTR *Argv)
{
    g_Ssh = RegisterServiceCtrlHandlerExW(Argv[0], SvcHandler, NULL);
    g_Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_St.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_St.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_PARAMCHANGE;
    g_St.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_Ssh, &g_St);
    WaitForSingleObject(g_Stop, 60000);
    g_St.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_Ssh, &g_St);
}

/* ---------------------------------------------------------------- helpers */

static BOOL HasRight(PCSTR List, PCSTR Name)
{
    size_t Len = strlen(Name);
    PCSTR p = List;

    while ((p = strstr(p, Name)) != NULL)
    {
        if ((p == List || p[-1] == ' ') && (p[Len] == ' ' || p[Len] == 0))
            return TRUE;
        p += Len;
    }
    return FALSE;
}

static VOID WaitState(SC_HANDLE Observer, DWORD State)
{
    SERVICE_STATUS St;
    DWORD Start = GetTickCount();

    while (GetTickCount() - Start < 15000)
    {
        if (!QueryServiceStatus(Observer, &St) || St.dwCurrentState == State)
            return;
        Sleep(50);
    }
}

static VOID EnsureStopped(SC_HANDLE Observer)
{
    SERVICE_STATUS St;

    if (QueryServiceStatus(Observer, &St) && St.dwCurrentState != SERVICE_STOPPED)
    {
        ControlService(Observer, SERVICE_CONTROL_STOP, &St);
        WaitState(Observer, SERVICE_STOPPED);
    }
}

static VOID EnsureRunning(SC_HANDLE Observer)
{
    SERVICE_STATUS St;

    if (QueryServiceStatus(Observer, &St) && St.dwCurrentState == SERVICE_STOPPED)
        StartServiceW(Observer, 0, NULL);
    WaitState(Observer, SERVICE_RUNNING);
}

static BOOL SetPrivilege(HANDLE Token, PCWSTR Name, BOOL Enable)
{
    TOKEN_PRIVILEGES Tp;

    Tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, Name, &Tp.Privileges[0].Luid))
        return FALSE;
    Tp.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;
    return AdjustTokenPrivileges(Token, FALSE, &Tp, sizeof(Tp), NULL, NULL) && GetLastError() == ERROR_SUCCESS;
}

/* Scratch service running this program as LocalService; Sddl (optional) is applied after creation */
static BOOL MakeService(SC_HANDLE Scm, PCWSTR Name, PCWSTR Sddl)
{
    WCHAR Bin[MAX_PATH + 64];
    SC_HANDLE Svc;
    PSECURITY_DESCRIPTOR Sd = NULL;
    SECURITY_INFORMATION Si = 0;
    PSID Sid;
    PACL Acl;
    BOOL Present, Defaulted, Ok = TRUE;

    StringCchPrintfW(Bin, ARRAYSIZE(Bin), L"\"%s\" ServiceAccessCheck service", g_ExePath);
    Svc = CreateServiceW(Scm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                         SERVICE_ERROR_IGNORE, Bin, NULL, NULL, NULL, L"NT AUTHORITY\\LocalService", NULL);
    if (!Svc && GetLastError() == ERROR_SERVICE_EXISTS)
        Svc = OpenServiceW(Scm, Name, SERVICE_ALL_ACCESS);
    ok(Svc != NULL, "CreateService(%S) failed with %lu\n", Name, GetLastError());
    if (!Svc)
        return FALSE;
    if (Sddl && !wcscmp(Sddl, L"D:NO_ACCESS_CONTROL"))
    {
        /* A NULL DACL, built directly (the test is about the service controller, not the SDDL parser) */
        SECURITY_DESCRIPTOR Abs;
        InitializeSecurityDescriptor(&Abs, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&Abs, TRUE, NULL, FALSE);
        Ok = SetServiceObjectSecurity(Svc, DACL_SECURITY_INFORMATION, &Abs);
        ok(Ok, "SetServiceObjectSecurity(%S, NULL DACL) failed with %lu\n", Name, GetLastError());
    }
    else if (Sddl)
    {
        ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL),
           "SDDL %S failed with %lu\n", Sddl, GetLastError());
        if (Sd)
        {
            if (GetSecurityDescriptorOwner(Sd, &Sid, &Defaulted) && Sid) Si |= OWNER_SECURITY_INFORMATION;
            if (GetSecurityDescriptorGroup(Sd, &Sid, &Defaulted) && Sid) Si |= GROUP_SECURITY_INFORMATION;
            if (GetSecurityDescriptorDacl(Sd, &Present, &Acl, &Defaulted) && Present) Si |= DACL_SECURITY_INFORMATION;
            Ok = SetServiceObjectSecurity(Svc, Si, Sd);
            ok(Ok, "SetServiceObjectSecurity(%S) failed with %lu\n", Name, GetLastError());
            LocalFree(Sd);
        }
    }
    CloseServiceHandle(Svc);
    return Ok;
}

static VOID RemoveService(SC_HANDLE Scm, PCWSTR Name)
{
    SC_HANDLE Svc = OpenServiceW(Scm, Name, SERVICE_ALL_ACCESS);
    PSECURITY_DESCRIPTOR Sd;

    if (!Svc && GetLastError() == ERROR_ACCESS_DENIED)
    {
        /* A DACL that locks everybody out: the owner (LocalSystem) or an administrator taking ownership resets it */
        SC_HANDLE W = OpenServiceW(Scm, Name, WRITE_DAC);
        if (W && ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;BA)(A;;GA;;;SY)", SDDL_REVISION_1, &Sd, NULL))
        {
            SetServiceObjectSecurity(W, DACL_SECURITY_INFORMATION, Sd);
            LocalFree(Sd);
        }
        if (W)
            CloseServiceHandle(W);
        Svc = OpenServiceW(Scm, Name, SERVICE_ALL_ACCESS);
    }
    if (Svc)
    {
        EnsureStopped(Svc);
        DeleteService(Svc);
        CloseServiceHandle(Svc);
    }
}

static BOOL AddUser(PWSTR Name, DWORD Priv)
{
    USER_INFO_1 Info;
    DWORD Err;
    NET_API_STATUS Status;
    LOCALGROUP_MEMBERS_INFO_3 Member;

    ZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = Name;
    Info.usri1_password = g_Password;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    if (Status != NERR_Success)
        return FALSE;
    if (Priv == USER_PRIV_ADMIN)
    {
        Member.lgrmi3_domainandname = Name;
        Status = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (PBYTE)&Member, 1);
        ok(Status == NERR_Success, "NetLocalGroupAddMembers failed with %lu\n", Status);
    }
    return TRUE;
}

/* A token for the caller tag (impersonation follows); NULL when the caller is not available here */
static HANDLE CallerToken(PCSTR Caller, BOOL *Anonymous)
{
    HANDLE Token = NULL, Self = NULL, Restricted = NULL;
    SID_AND_ATTRIBUTES Sa[2];
    BYTE Sid1[SECURITY_MAX_SID_SIZE], Sid2[SECURITY_MAX_SID_SIZE];
    DWORD Len1 = sizeof(Sid1), Len2 = sizeof(Sid2);

    *Anonymous = FALSE;
    if (!strcmp(Caller, "anon"))
    {
        *Anonymous = TRUE;
        return INVALID_HANDLE_VALUE;
    }
    if (!strcmp(Caller, "system") || !strcmp(Caller, "admin0"))
        return INVALID_HANDLE_VALUE;
    if (!strcmp(Caller, "std"))
        LogonUserW(g_StdUser, L".", g_Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token);
    else if (!strcmp(Caller, "stdnet"))
    {
        /* Both give a token with NETWORK and without INTERACTIVE */
        if (!LogonUserW(g_StdUser, L".", g_Password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &Token))
            LogonUserW(g_StdUser, L".", g_Password, LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, &Token);
    }
    else if (!strcmp(Caller, "admin"))
        LogonUserW(g_AdmUser, L".", g_Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token);
    else if (!strcmp(Caller, "lsvc"))
        LogonUserW(L"LocalService", L"NT AUTHORITY", NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &Token);
    else if (!strcmp(Caller, "nsvc"))
        LogonUserW(L"NetworkService", L"NT AUTHORITY", NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &Token);
    else if (!strcmp(Caller, "restr"))
    {
        if (LogonUserW(g_StdUser, L".", g_Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Self))
        {
            CreateWellKnownSid(WinWorldSid, NULL, Sid1, &Len1);
            CreateWellKnownSid(WinBuiltinUsersSid, NULL, Sid2, &Len2);
            Sa[0].Sid = Sid1; Sa[0].Attributes = 0;
            Sa[1].Sid = Sid2; Sa[1].Attributes = 0;
            if (CreateRestrictedToken(Self, 0, 0, NULL, 0, NULL, 2, Sa, &Restricted))
                Token = Restricted;
            CloseHandle(Self);
        }
    }
    else if (!strcmp(Caller, "nobadmin"))
    {
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Self))
        {
            CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Sid1, &Len1);
            Sa[0].Sid = Sid1; Sa[0].Attributes = 0;
            if (CreateRestrictedToken(Self, 0, 1, Sa, 0, NULL, 0, NULL, &Restricted))
                Token = Restricted;
            CloseHandle(Self);
        }
    }
    return Token;
}

static BOOL Enter(PCSTR Caller, PHANDLE Token)
{
    BOOL Anonymous;
    HANDLE T = CallerToken(Caller, &Anonymous);

    *Token = NULL;
    if (Anonymous)
        return ImpersonateAnonymousToken(GetCurrentThread());
    if (T == INVALID_HANDLE_VALUE)
        return TRUE;
    if (T == NULL)
        return FALSE;
    if (!ImpersonateLoggedOnUser(T))
    {
        CloseHandle(T);
        return FALSE;
    }
    *Token = T;
    return TRUE;
}

static VOID Leave(HANDLE Token)
{
    RevertToSelf();
    if (Token)
        CloseHandle(Token);
}

/* ---------------------------------------------------------------- the tests */

static VOID TestOpens(PCSTR Caller)
{
    HANDLE Token;
    SC_HANDLE Scm, H;
    WCHAR Name[64];
    ULONG i, j;
    DWORD Err;
    BOOL Want;

    if (!Enter(Caller, &Token))
    {
        skip("caller %s not available (%lu)\n", Caller, GetLastError());
        return;
    }
    for (i = 0; i < ARRAYSIZE(Expected); i++)
    {
        if (strcmp(Expected[i].Caller, Caller))
            continue;
        MultiByteToWideChar(CP_ACP, 0, Expected[i].Object, -1, Name, ARRAYSIZE(Name));
        if (!strcmp(Expected[i].Object, "SCM"))
        {
            for (j = 0; j < ARRAYSIZE(MgrRights); j++)
            {
                Want = HasRight(Expected[i].Granted, MgrRights[j].Name);
                SetLastError(0xdeadbeef);
                H = OpenSCManagerW(NULL, NULL, MgrRights[j].Mask);
                Err = H ? 0 : GetLastError();
                if (Want)
                    ok(H != NULL, "%s: OpenSCManager(%s) failed with %lu\n", Caller, MgrRights[j].Name, Err);
                else
                    ok(H == NULL && Err == ERROR_ACCESS_DENIED, "%s: OpenSCManager(%s) gave %p, error %lu, expected 5\n",
                       Caller, MgrRights[j].Name, H, Err);
                if (H)
                    CloseServiceHandle(H);
            }
            continue;
        }
        Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (!Scm)
        {
            skip("%s: no connection (%lu)\n", Caller, GetLastError());
            continue;
        }
        H = OpenServiceW(Scm, Name, SERVICE_QUERY_STATUS);
        if (!H && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            CloseServiceHandle(Scm);
            continue;
        }
        if (H)
            CloseServiceHandle(H);
        for (j = 0; j < ARRAYSIZE(SvcRights); j++)
        {
            Want = HasRight(Expected[i].Granted, SvcRights[j].Name);
            SetLastError(0xdeadbeef);
            H = OpenServiceW(Scm, Name, SvcRights[j].Mask);
            Err = H ? 0 : GetLastError();
            if (Want)
                ok(H != NULL, "%s: OpenService(%S, %s) failed with %lu\n", Caller, Name, SvcRights[j].Name, Err);
            else
                ok(H == NULL && Err == ERROR_ACCESS_DENIED, "%s: OpenService(%S, %s) gave %p, error %lu, expected 5\n",
                   Caller, Name, SvcRights[j].Name, H, Err);
            if (H)
                CloseServiceHandle(H);
        }
        CloseServiceHandle(Scm);
    }
    Leave(Token);
}

/* What a standard user may do with a MAXIMUM_ALLOWED handle to services with the default and custom descriptors */
static VOID TestStandardUserOperations(SC_HANDLE Admin)
{
    HANDLE Token;
    SC_HANDLE Scm, H, Obs;
    SERVICE_STATUS St;
    BYTE Buf[8192];
    DWORD Need, Count, Resume = 0;
    SC_LOCK Lock;
    PSECURITY_DESCRIPTOR Sd;
    BOOL Ret, SawDef = FALSE, SawHidden = FALSE;
    ENUM_SERVICE_STATUS_PROCESSW *E;
    static BYTE Big[128 * 1024];

    Obs = OpenServiceW(Admin, L"scmp_def", SERVICE_ALL_ACCESS);
    if (!Enter("std", &Token))
    {
        skip("no standard user logon\n");
        return;
    }
    Scm = OpenSCManagerW(NULL, NULL, MAXIMUM_ALLOWED);
    ok(Scm != NULL, "OpenSCManager(MAXIMUM_ALLOWED) failed with %lu\n", GetLastError());
    if (!Scm)
        goto done;

    /* The manager */
    Lock = LockServiceDatabase(Scm);
    ok(Lock == NULL && GetLastError() == ERROR_ACCESS_DENIED, "LockServiceDatabase gave %p, error %lu\n", Lock, GetLastError());
    if (Lock)
        UnlockServiceDatabase(Lock);
    Ret = QueryServiceLockStatusW(Scm, (LPQUERY_SERVICE_LOCK_STATUSW)Buf, 4096, &Need);
    ok(Ret, "QueryServiceLockStatus failed with %lu\n", GetLastError());
    Ret = QueryServiceObjectSecurity(Scm, DACL_SECURITY_INFORMATION, Buf, sizeof(Buf), &Need);
    ok(Ret, "QueryServiceObjectSecurity(manager) failed with %lu\n", GetLastError());
    H = CreateServiceW(Scm, L"scmp_c_std", L"scmp_c_std", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                       SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, L"C:\\nonexistent.exe", NULL, NULL, NULL, NULL, NULL);
    ok(H == NULL && GetLastError() == ERROR_ACCESS_DENIED, "CreateService gave %p, error %lu\n", H, GetLastError());
    if (H)
    {
        DeleteService(H);
        CloseServiceHandle(H);
    }
    SetLastError(0xdeadbeef);
    Ret = NotifyBootConfigStatus(TRUE);
    ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "NotifyBootConfigStatus gave %d, error %lu\n", Ret, GetLastError());

    /* Enumeration leaves out the services the caller may not query */
    Ret = EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, Big, sizeof(Big),
                                &Need, &Count, &Resume, NULL);
    ok(Ret, "EnumServicesStatusEx failed with %lu\n", GetLastError());
    E = (ENUM_SERVICE_STATUS_PROCESSW *)Big;
    for (Need = 0; Ret && Need < Count; Need++)
    {
        if (!_wcsicmp(E[Need].lpServiceName, L"scmp_def")) SawDef = TRUE;
        if (!_wcsicmp(E[Need].lpServiceName, L"scmp_hidden")) SawHidden = TRUE;
    }
    ok(SawDef, "scmp_def not listed\n");
    ok(!SawHidden, "scmp_hidden (no rights for users) listed\n");

    /* A service with the default descriptor */
    H = OpenServiceW(Scm, L"scmp_def", MAXIMUM_ALLOWED);
    ok(H != NULL, "OpenService(scmp_def, MAXIMUM_ALLOWED) failed with %lu\n", GetLastError());
    if (H)
    {
        ok(QueryServiceStatus(H, &St), "QueryServiceStatus failed with %lu\n", GetLastError());
        ok(QueryServiceConfigW(H, (LPQUERY_SERVICE_CONFIGW)Buf, sizeof(Buf), &Need), "QueryServiceConfig failed with %lu\n", GetLastError());
        SetLastError(0xdeadbeef);
        Ret = ChangeServiceConfigW(H, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, L"C:\\Windows\\notepad.exe",
                                   NULL, NULL, NULL, NULL, NULL, NULL);
        ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "ChangeServiceConfig(binary path) gave %d, error %lu\n", Ret, GetLastError());
        SetLastError(0xdeadbeef);
        Ret = StartServiceW(H, 0, NULL);
        ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "StartService gave %d, error %lu\n", Ret, GetLastError());
        SetLastError(0xdeadbeef);
        Ret = DeleteService(H);
        ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "DeleteService gave %d, error %lu\n", Ret, GetLastError());
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;WD)", SDDL_REVISION_1, &Sd, NULL))
        {
            SetLastError(0xdeadbeef);
            Ret = SetServiceObjectSecurity(H, DACL_SECURITY_INFORMATION, Sd);
            ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "SetServiceObjectSecurity gave %d, error %lu\n", Ret, GetLastError());
            LocalFree(Sd);
        }
        RevertToSelf();
        if (Obs)
            EnsureRunning(Obs);
        ImpersonateLoggedOnUser(Token);
        ok(ControlService(H, SERVICE_CONTROL_INTERROGATE, &St), "INTERROGATE failed with %lu\n", GetLastError());
        ok(ControlService(H, 128, &St), "user-defined control failed with %lu\n", GetLastError());
        SetLastError(0xdeadbeef);
        Ret = ControlService(H, SERVICE_CONTROL_PAUSE, &St);
        ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "PAUSE gave %d, error %lu\n", Ret, GetLastError());
        SetLastError(0xdeadbeef);
        Ret = ControlService(H, SERVICE_CONTROL_STOP, &St);
        ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "STOP gave %d, error %lu\n", Ret, GetLastError());
        CloseServiceHandle(H);
    }

    /* START granted to this user alone */
    H = OpenServiceW(Scm, L"scmp_ustart", MAXIMUM_ALLOWED);
    ok(H != NULL, "OpenService(scmp_ustart) failed with %lu\n", GetLastError());
    if (H)
    {
        Ret = StartServiceW(H, 0, NULL);
        ok(Ret || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING, "StartService(scmp_ustart) failed with %lu\n", GetLastError());
        SetLastError(0xdeadbeef);
        Ret = ControlService(H, SERVICE_CONTROL_STOP, &St);
        ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "STOP(scmp_ustart) gave %d, error %lu\n", Ret, GetLastError());
        CloseServiceHandle(H);
    }
    CloseServiceHandle(Scm);
done:
    Leave(Token);
    if (Obs)
    {
        EnsureStopped(Obs);
        CloseServiceHandle(Obs);
    }
    H = OpenServiceW(Admin, L"scmp_ustart", SERVICE_ALL_ACCESS);
    if (H)
    {
        EnsureStopped(H);
        CloseServiceHandle(H);
    }
}

/* Each operation with a handle that has every right but the one it needs (documented per function) */
static VOID TestOperationRights(SC_HANDLE Admin)
{
    SC_HANDLE Obs = OpenServiceW(Admin, L"scmp_def", SERVICE_ALL_ACCESS), H;
    SERVICE_STATUS St;
    BYTE Buf[8192];
    DWORD Need, Count;
    SERVICE_DESCRIPTIONW Desc = { L"scratch" };
    BOOL Ret;

    if (!Obs)
        return;
#define WITHOUT(Right) (H = OpenServiceW(Admin, L"scmp_def", SERVICE_ALL_ACCESS & ~(Right)))
#define DENIED(Call, What) do { SetLastError(0xdeadbeef); Ret = (Call); \
        ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "%s gave %d, error %lu\n", What, Ret, GetLastError()); } while (0)
    if (WITHOUT(SERVICE_QUERY_STATUS)) { DENIED(QueryServiceStatus(H, &St), "QueryServiceStatus without QUERY_STATUS"); CloseServiceHandle(H); }
    if (WITHOUT(SERVICE_QUERY_CONFIG)) { DENIED(QueryServiceConfigW(H, (LPQUERY_SERVICE_CONFIGW)Buf, sizeof(Buf), &Need), "QueryServiceConfig without QUERY_CONFIG");
                                         DENIED(QueryServiceConfig2W(H, SERVICE_CONFIG_DESCRIPTION, Buf, sizeof(Buf), &Need), "QueryServiceConfig2 without QUERY_CONFIG"); CloseServiceHandle(H); }
    if (WITHOUT(SERVICE_CHANGE_CONFIG)) { DENIED(ChangeServiceConfigW(H, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL), "ChangeServiceConfig without CHANGE_CONFIG");
                                          DENIED(ChangeServiceConfig2W(H, SERVICE_CONFIG_DESCRIPTION, &Desc), "ChangeServiceConfig2 without CHANGE_CONFIG"); CloseServiceHandle(H); }
    if (WITHOUT(SERVICE_ENUMERATE_DEPENDENTS)) { DENIED(EnumDependentServicesW(H, SERVICE_STATE_ALL, (LPENUM_SERVICE_STATUSW)Buf, sizeof(Buf), &Need, &Count), "EnumDependentServices without ENUMERATE_DEPENDENTS"); CloseServiceHandle(H); }
    if (WITHOUT(READ_CONTROL)) { DENIED(QueryServiceObjectSecurity(H, DACL_SECURITY_INFORMATION, Buf, sizeof(Buf), &Need), "QueryServiceObjectSecurity without READ_CONTROL"); CloseServiceHandle(H); }
    if (WITHOUT(WRITE_DAC))
    {
        QueryServiceObjectSecurity(Obs, DACL_SECURITY_INFORMATION, Buf, sizeof(Buf), &Need);
        DENIED(SetServiceObjectSecurity(H, DACL_SECURITY_INFORMATION, Buf), "SetServiceObjectSecurity(DACL) without WRITE_DAC");
        CloseServiceHandle(H);
    }
    EnsureStopped(Obs);
    if (WITHOUT(SERVICE_START)) { DENIED(StartServiceW(H, 0, NULL), "StartService without START"); CloseServiceHandle(H); }
    EnsureRunning(Obs);
    if (WITHOUT(SERVICE_INTERROGATE)) { DENIED(ControlService(H, SERVICE_CONTROL_INTERROGATE, &St), "INTERROGATE without INTERROGATE"); CloseServiceHandle(H); }
    if (WITHOUT(SERVICE_PAUSE_CONTINUE)) { DENIED(ControlService(H, SERVICE_CONTROL_PAUSE, &St), "PAUSE without PAUSE_CONTINUE");
                                           DENIED(ControlService(H, SERVICE_CONTROL_PARAMCHANGE, &St), "PARAMCHANGE without PAUSE_CONTINUE"); CloseServiceHandle(H); }
    if (WITHOUT(SERVICE_USER_DEFINED_CONTROL)) { DENIED(ControlService(H, 128, &St), "control 128 without USER_DEFINED_CONTROL"); CloseServiceHandle(H); }
    if (WITHOUT(SERVICE_STOP)) { DENIED(ControlService(H, SERVICE_CONTROL_STOP, &St), "STOP without STOP"); CloseServiceHandle(H); }
    EnsureStopped(Obs);
    if (WITHOUT(DELETE)) { DENIED(DeleteService(H), "DeleteService without DELETE"); CloseServiceHandle(H); }
#undef WITHOUT
    H = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS & ~SC_MANAGER_LOCK);
    if (H) { SC_LOCK L = LockServiceDatabase(H); ok(!L && GetLastError() == ERROR_ACCESS_DENIED, "LockServiceDatabase without LOCK gave %p, %lu\n", L, GetLastError()); if (L) UnlockServiceDatabase(L); CloseServiceHandle(H); }
    H = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS & ~SC_MANAGER_QUERY_LOCK_STATUS);
    if (H) { DENIED(QueryServiceLockStatusW(H, (LPQUERY_SERVICE_LOCK_STATUSW)Buf, 4096, &Need), "QueryServiceLockStatus without QUERY_LOCK_STATUS"); CloseServiceHandle(H); }
    H = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS & ~READ_CONTROL);
    if (H) { DENIED(QueryServiceObjectSecurity(H, DACL_SECURITY_INFORMATION, Buf, sizeof(Buf), &Need), "QueryServiceObjectSecurity(manager) without READ_CONTROL"); CloseServiceHandle(H); }
    H = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS & ~SC_MANAGER_CREATE_SERVICE);
    if (H)
    {
        SC_HANDLE C = CreateServiceW(H, L"scmp_c_oc", L"scmp_c_oc", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                                     SERVICE_ERROR_IGNORE, L"C:\\nonexistent.exe", NULL, NULL, NULL, NULL, NULL);
        ok(!C && GetLastError() == ERROR_ACCESS_DENIED, "CreateService without CREATE_SERVICE gave %p, %lu\n", C, GetLastError());
        if (C) { DeleteService(C); CloseServiceHandle(C); }
        CloseServiceHandle(H);
    }
#undef DENIED
    /* OpenService without any right: denied, also for administrators */
    SetLastError(0xdeadbeef);
    H = OpenServiceW(Admin, L"scmp_def", 0);
    ok(H == NULL && GetLastError() == ERROR_ACCESS_DENIED, "OpenService(0) gave %p, error %lu\n", H, GetLastError());
    if (H)
        CloseServiceHandle(H);
    CloseServiceHandle(Obs);
}

static BOOL SameDacl(PSECURITY_DESCRIPTOR Sd, PCWSTR ExpectedSddl)
{
    PSECURITY_DESCRIPTOR Exp = NULL;
    PACL A = NULL, B = NULL;
    BOOL P1 = FALSE, P2 = FALSE, D, Same;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(ExpectedSddl, SDDL_REVISION_1, &Exp, NULL))
        return FALSE;
    GetSecurityDescriptorDacl(Sd, &P1, &A, &D);
    GetSecurityDescriptorDacl(Exp, &P2, &B, &D);
    Same = P1 && P2 && A && B && A->AceCount == B->AceCount && A->AclSize >= sizeof(ACL) &&
           !memcmp(A + 1, B + 1, min(A->AclSize, B->AclSize) - sizeof(ACL));
    LocalFree(Exp);
    return Same;
}

static VOID TestDescriptors(SC_HANDLE Admin)
{
    BYTE Buf[8192];
    DWORD Need;
    SC_HANDLE H;
    PSECURITY_DESCRIPTOR Sd;
    LPWSTR Str = NULL;
    HANDLE Proc;
    BOOL Ret;

    /* The manager's own descriptor and the default descriptor of a new service, as on Windows */
    ok(QueryServiceObjectSecurity(Admin, DACL_SECURITY_INFORMATION, Buf, sizeof(Buf), &Need),
       "QueryServiceObjectSecurity(manager) failed with %lu\n", GetLastError());
    ConvertSecurityDescriptorToStringSecurityDescriptorW(Buf, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &Str, NULL);
    ok(SameDacl(Buf, ScmDaclSddl), "manager DACL %S\n", Str ? Str : L"?");
    if (Str) { LocalFree(Str); Str = NULL; }

    H = OpenServiceW(Admin, L"scmp_def", READ_CONTROL | WRITE_DAC | WRITE_OWNER);
    ok(H != NULL, "OpenService(scmp_def) failed with %lu\n", GetLastError());
    if (!H)
        return;
    ok(QueryServiceObjectSecurity(H, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, Buf, sizeof(Buf), &Need),
       "QueryServiceObjectSecurity failed with %lu\n", GetLastError());
    ConvertSecurityDescriptorToStringSecurityDescriptorW(Buf, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Str, NULL);
    ok(SameDacl(Buf, DefaultServiceDaclSddl), "default service descriptor %S\n", Str ? Str : L"?");
    ok(Str && !wcsncmp(Str, L"O:SYG:SY", 8), "default owner/group %S\n", Str ? Str : L"?");
    if (Str) { LocalFree(Str); Str = NULL; }

    /* SetServiceObjectSecurity / QueryServiceObjectSecurity round trip: DACL, owner and group, generic rights mapped */
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:(A;;GR;;;IU)(A;;GA;;;BA)(A;;GA;;;SY)", SDDL_REVISION_1, &Sd, NULL))
    {
        ok(SetServiceObjectSecurity(H, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, Sd),
           "SetServiceObjectSecurity failed with %lu\n", GetLastError());
        LocalFree(Sd);
        ok(QueryServiceObjectSecurity(H, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, Buf, sizeof(Buf), &Need),
           "QueryServiceObjectSecurity failed with %lu\n", GetLastError());
        ConvertSecurityDescriptorToStringSecurityDescriptorW(Buf, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Str, NULL);
        ok(Str && !wcsncmp(Str, L"O:BAG:BA", 8), "owner/group after set: %S\n", Str ? Str : L"?");
        ok(SameDacl(Buf, L"D:(A;;CCLCSWLORC;;;IU)(A;;" BA_ALL L";;;BA)(A;;" BA_ALL L";;;SY)"), "DACL after set (generic rights mapped): %S\n", Str ? Str : L"?");
        if (Str) { LocalFree(Str); Str = NULL; }
    }
    /* Back to the measured default */
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SY" L"D:(A;;" SY_DEF L";;;SY)(A;;" BA_ALL L";;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)", SDDL_REVISION_1, &Sd, NULL))
    {
        ok(SetServiceObjectSecurity(H, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, Sd),
           "SetServiceObjectSecurity(restore) failed with %lu\n", GetLastError());
        LocalFree(Sd);
    }
    CloseServiceHandle(H);

    /* The SACL: ACCESS_SYSTEM_SECURITY needs SeSecurityPrivilege enabled at open time (1314 without it) */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Proc))
    {
        SetPrivilege(Proc, L"SeSecurityPrivilege",FALSE);
        SetLastError(0xdeadbeef);
        H = OpenServiceW(Admin, L"scmp_def", ACCESS_SYSTEM_SECURITY);
        ok(H == NULL && GetLastError() == ERROR_PRIVILEGE_NOT_HELD, "ACCESS_SYSTEM_SECURITY without the privilege gave %p, error %lu\n", H, GetLastError());
        if (H)
            CloseServiceHandle(H);
        if (SetPrivilege(Proc, L"SeSecurityPrivilege",TRUE))
        {
            H = OpenServiceW(Admin, L"scmp_def", ACCESS_SYSTEM_SECURITY | READ_CONTROL);
            SetPrivilege(Proc, L"SeSecurityPrivilege",FALSE);
            ok(H != NULL, "ACCESS_SYSTEM_SECURITY with the privilege failed with %lu\n", GetLastError());
            if (H)
            {
                Ret = QueryServiceObjectSecurity(H, SACL_SECURITY_INFORMATION, Buf, sizeof(Buf), &Need);
                ok(Ret, "QueryServiceObjectSecurity(SACL) failed with %lu\n", GetLastError());
                if (Ret && ConvertSecurityDescriptorToStringSecurityDescriptorW(Buf, SDDL_REVISION_1, SACL_SECURITY_INFORMATION, &Str, NULL))
                {
                    ok(!wcscmp(Str, L"S:(AU;FA;" BA_ALL L";;;WD)"), "default SACL %S\n", Str);
                    LocalFree(Str);
                    Str = NULL;
                }
                CloseServiceHandle(H);
            }
        }
        else
            skip("SeSecurityPrivilege not available\n");
        CloseHandle(Proc);
    }
}

/* The status calls name a service by a small status handle: only the service's process may use it */
static VOID TestStatusHandle(SC_HANDLE Admin)
{
    SERVICE_STATUS_HANDLE Status = NULL;
    SERVICE_STATUS St;
    SC_HANDLE H;
    DWORD Err;
    BOOL Ret;

    Err = I_ScValidatePnpService(NULL, L"scmp_def", &Status);
    if (Err != ERROR_SUCCESS || !Status)
    {
        skip("I_ScValidatePnpService failed with %lu\n", Err);
        return;
    }
    H = OpenServiceW(Admin, L"scmp_def", SERVICE_ALL_ACCESS);
    if (H)
        EnsureStopped(H);
    ZeroMemory(&St, sizeof(St));
    St.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    St.dwCurrentState = SERVICE_RUNNING;
    SetLastError(0xdeadbeef);
    Ret = SetServiceStatus(Status, &St);
    ok(!Ret && GetLastError() == ERROR_INVALID_HANDLE, "SetServiceStatus from another process gave %d, error %lu\n", Ret, GetLastError());
    if (H)
    {
        ok(QueryServiceStatus(H, &St) && St.dwCurrentState == SERVICE_STOPPED, "state %lu after the foreign status\n", St.dwCurrentState);
        CloseServiceHandle(H);
    }
}

/* The number of the control pipe the service controller made last (HKLM\...\Control\ServiceCurrent) */
static DWORD CurrentControlPipe(VOID)
{
    DWORD Value = 0, Size = sizeof(Value);
    HKEY Key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ServiceCurrent", 0, KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS)
    {
        RegQueryValueExW(Key, L"", NULL, NULL, (LPBYTE)&Value, &Size);
        RegCloseKey(Key);
    }
    return Value;
}

/*
 * The control pipe of a service has a predictable name and every user may open it. A pipe a standard user
 * created under the next name must not become the service's pipe (the service still starts and connects to
 * the service controller), and nobody can add a server end to a service's pipe.
 */
static VOID TestControlPipe(SC_HANDLE Admin)
{
    WCHAR Name[64];
    HANDLE Token, Squat = INVALID_HANDLE_VALUE, Extra = INVALID_HANDLE_VALUE;
    SERVICE_STATUS St;
    SC_HANDLE Svc;
    DWORD Err;
    BOOL Connected;

    Svc = OpenServiceW(Admin, L"scmp_def", SERVICE_ALL_ACCESS);
    ok(Svc != NULL, "OpenService(scmp_def) failed with %lu\n", GetLastError());
    if (!Svc)
        return;
    EnsureStopped(Svc);

    if (Enter("std", &Token))
    {
        StringCchPrintfW(Name, ARRAYSIZE(Name), L"\\\\.\\pipe\\net\\NtControlPipe%lu", CurrentControlPipe() + 1);
        Squat = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
                                 PIPE_UNLIMITED_INSTANCES, 512, 512, 0, NULL);
        Leave(Token);
    }
    if (Squat == INVALID_HANDLE_VALUE)
    {
        skip("The standard user could not create %S (%lu)\n", Name, GetLastError());
        CloseServiceHandle(Svc);
        return;
    }
    /* Listening (a non-blocking pipe answers at once) */
    ConnectNamedPipe(Squat, NULL);

    ok(StartServiceW(Svc, 0, NULL), "StartService with a squatted control pipe name failed with %lu\n", GetLastError());
    WaitState(Svc, SERVICE_RUNNING);
    ok(QueryServiceStatus(Svc, &St) && St.dwCurrentState == SERVICE_RUNNING, "state %lu\n", St.dwCurrentState);

    SetLastError(0xdeadbeef);
    Connected = ConnectNamedPipe(Squat, NULL);
    Err = GetLastError();
    ok(!Connected && Err == ERROR_PIPE_LISTENING, "the squatted pipe got a client (%d, error %lu)\n", Connected, Err);
    CloseHandle(Squat);

    /* The running service's own pipe takes no second server end, not even from an administrator */
    StringCchPrintfW(Name, ARRAYSIZE(Name), L"\\\\.\\pipe\\net\\NtControlPipe%lu", CurrentControlPipe());
    SetLastError(0xdeadbeef);
    Extra = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
                             PIPE_UNLIMITED_INSTANCES, 512, 512, 0, NULL);
    Err = GetLastError();
    ok(Extra == INVALID_HANDLE_VALUE, "a second server end of %S was created\n", Name);
    ok(Extra != INVALID_HANDLE_VALUE || Err == ERROR_PIPE_BUSY || Err == ERROR_ACCESS_DENIED, "error %lu\n", Err);
    if (Extra != INVALID_HANDLE_VALUE)
        CloseHandle(Extra);

    EnsureStopped(Svc);
    CloseServiceHandle(Svc);
}

START_TEST(ServiceAccessCheck)
{
    static const PCSTR Callers[] = { "system", "admin", "nobadmin", "std", "stdnet", "restr", "anon", "lsvc", "nsvc" };
    static const WCHAR *Scratch[] = { L"scmp_def", L"scmp_ustart", L"scmp_deny", L"scmp_owner", L"scmp_ownrt", L"scmp_null",
                                      L"scmp_empty", L"scmp_lsvc", L"scmp_gx", L"scmp_gr", L"scmp_hidden" };
    WCHAR Sddl[512], Domain[64];
    BYTE Sid[SECURITY_MAX_SID_SIZE], UserBuf[256];
    DWORD SidLen = sizeof(Sid), DomLen = ARRAYSIZE(Domain), Len;
    SID_NAME_USE Use;
    LPWSTR SidStr;
    SC_HANDLE Admin;
    HANDLE Proc;
    ULONG i;
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "service"))
    {
        SERVICE_TABLE_ENTRYW Table[] = { { L"", SvcMain }, { NULL, NULL } };
        StartServiceCtrlDispatcherW(Table);
        return;
    }

    Admin = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Admin)
    {
        skip("Run as LocalSystem or as an administrator (OpenSCManager failed with %lu)\n", GetLastError());
        return;
    }
    GetModuleFileNameW(NULL, g_ExePath, ARRAYSIZE(g_ExePath));
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Proc))
    {
        if (GetTokenInformation(Proc, TokenUser, UserBuf, sizeof(UserBuf), &Len))
            g_SelfIsSystem = IsWellKnownSid(((PTOKEN_USER)UserBuf)->User.Sid, WinLocalSystemSid);
        CloseHandle(Proc);
    }
    trace("running as %s\n", g_SelfIsSystem ? "LocalSystem" : "an administrator");

    /* Scratch accounts with a throw-away password made here */
    StringCchPrintfW(g_Password, ARRAYSIZE(g_Password), L"Sa1!%08lx%04lx", GetTickCount() ^ 0x5a5a5a5a, GetCurrentProcessId() & 0xffff);
    StringCchPrintfW(g_StdUser, ARRAYSIZE(g_StdUser), L"scmstd%lx", GetTickCount() & 0xfffff);
    StringCchPrintfW(g_AdmUser, ARRAYSIZE(g_AdmUser), L"scmadm%lx", GetTickCount() & 0xfffff);
    ok(AddUser(g_StdUser, USER_PRIV_USER), "NetUserAdd(standard user) failed\n");
    ok(AddUser(g_AdmUser, USER_PRIV_ADMIN), "NetUserAdd(administrator) failed\n");
    if (LookupAccountNameW(NULL, g_StdUser, Sid, &SidLen, Domain, &DomLen, &Use) && ConvertSidToStringSidW(Sid, &SidStr))
    {
        StringCchCopyW(g_StdSid, ARRAYSIZE(g_StdSid), SidStr);
        LocalFree(SidStr);
    }

    /* Scratch services with the default descriptor and with custom ones */
    MakeService(Admin, L"scmp_def", NULL);
    StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"D:(A;;" SY_DEF L";;;SY)(A;;" BA_ALL L";;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;%s)", g_StdSid);
    MakeService(Admin, L"scmp_ustart", Sddl);
    StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"D:(D;;RPWP;;;%s)(A;;" SY_DEF L";;;AU)(A;;" BA_ALL L";;;BA)(A;;" SY_DEF L";;;SY)", g_StdSid);
    MakeService(Admin, L"scmp_deny", Sddl);
    StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"O:%sG:SYD:(A;;" SY_DEF L";;;SY)(A;;" BA_ALL L";;;BA)", g_StdSid);
    MakeService(Admin, L"scmp_owner", Sddl);
    StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"O:%sG:SYD:(A;;" SY_DEF L";;;SY)(A;;" BA_ALL L";;;BA)(A;;LC;;;OW)", g_StdSid);
    MakeService(Admin, L"scmp_ownrt", Sddl);
    MakeService(Admin, L"scmp_null", L"D:NO_ACCESS_CONTROL");
    MakeService(Admin, L"scmp_empty", L"D:");
    MakeService(Admin, L"scmp_lsvc", L"D:(A;;" SY_DEF L";;;SY)(A;;" BA_ALL L";;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RPWP;;;LS)");
    StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"D:(A;;" SY_DEF L";;;SY)(A;;" BA_ALL L";;;BA)(A;;GX;;;%s)", g_StdSid);
    MakeService(Admin, L"scmp_gx", Sddl);
    StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"D:(A;;" SY_DEF L";;;SY)(A;;" BA_ALL L";;;BA)(A;;GR;;;%s)", g_StdSid);
    MakeService(Admin, L"scmp_gr", Sddl);
    MakeService(Admin, L"scmp_hidden", L"D:(A;;" BA_ALL L";;;BA)(A;;" BA_ALL L";;;SY)");

    for (i = 0; i < ARRAYSIZE(Callers); i++)
    {
        /* LocalSystem rows need LocalSystem; the "nobadmin" rows were measured from LocalSystem */
        if ((!strcmp(Callers[i], "system") || !strcmp(Callers[i], "nobadmin")) && !g_SelfIsSystem)
            continue;
        TestOpens(Callers[i]);
    }
    /* The Windows Installer service: an administrator's OpenService(SERVICE_ALL_ACCESS) succeeds (measured) */
    {
        SC_HANDLE Msi = OpenServiceW(Admin, L"MSIServer", SERVICE_ALL_ACCESS);
        ok(Msi != NULL || GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST, "OpenService(MSIServer, ALL_ACCESS) failed with %lu\n", GetLastError());
        if (Msi)
            CloseServiceHandle(Msi);
    }
    TestStandardUserOperations(Admin);
    TestOperationRights(Admin);
    TestDescriptors(Admin);
    TestStatusHandle(Admin);
    TestControlPipe(Admin);

    for (i = 0; i < ARRAYSIZE(Scratch); i++)
        RemoveService(Admin, Scratch[i]);
    CloseServiceHandle(Admin);
    NetUserDel(NULL, g_StdUser);
    NetUserDel(NULL, g_AdmUser);
    SecureZeroMemory(g_Password, sizeof(g_Password));
}
