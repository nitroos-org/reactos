/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A service that runs as its virtual account, NT SERVICE\<service>
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>
#include <lm.h>
#include <ntsecapi.h>
#include <tlhelp32.h>

/*
 * On Windows a service whose start name is NT SERVICE\<its own name> starts without a password and
 * runs with the service SID S-1-5-80-... as the user of its token. QueryServiceConfig returns the
 * start name as it was given. The process of the service looks at its own token, because the token of
 * a service is not open to an administrator's TOKEN_QUERY on every system.
 *
 * The logon of the virtual account has no password, so a service logon of NT SERVICE\<service> must work
 * only for a caller that holds SeTcbPrivilege (the SCM): a standard user, an administrator without
 * SeTcbPrivilege and an untrusted LSA connection are refused.
 */

/* Service process side */
static WCHAR ServiceName[64];
static SERVICE_STATUS_HANDLE StatusHandle;
static HANDLE StopEvent;

#define EXIT_TOKEN_MATCHES 100
#define EXIT_TOKEN_DIFFERS 200

/* Does the user of this process's token equal what LookupAccountName gives for NT SERVICE\<name>? */
static DWORD
TokenUserMatches(PCWSTR Name)
{
    BYTE Expected[SECURITY_MAX_SID_SIZE], Buffer[SECURITY_MAX_SID_SIZE + 16];
    WCHAR Account[96], Domain[128];
    DWORD cbSid = sizeof(Expected), cchDomain = _countof(Domain), Length = 0;
    SID_NAME_USE Use;
    HANDLE hToken;
    DWORD Ret = EXIT_TOKEN_DIFFERS;

    StringCbPrintfW(Account, sizeof(Account), L"NT SERVICE\\%s", Name);
    if (LookupAccountNameW(NULL, Account, Expected, &cbSid, Domain, &cchDomain, &Use) &&
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        if (GetTokenInformation(hToken, TokenUser, Buffer, sizeof(Buffer), &Length) &&
            EqualSid(((PTOKEN_USER)Buffer)->User.Sid, Expected))
            Ret = EXIT_TOKEN_MATCHES;
        CloseHandle(hToken);
    }
    return Ret;
}

#define NT_STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006D)

typedef NTSTATUS (NTAPI *LSACONNECTUNTRUSTED)(PHANDLE);
typedef NTSTATUS (NTAPI *LSAREGISTERLOGONPROCESS)(PLSA_STRING, PHANDLE, PLSA_OPERATIONAL_MODE);
typedef NTSTATUS (NTAPI *LSADEREGISTERLOGONPROCESS)(HANDLE);
typedef NTSTATUS (NTAPI *LSALOOKUPAUTHENTICATIONPACKAGE)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS (NTAPI *LSALOGONUSER)(HANDLE, PLSA_STRING, SECURITY_LOGON_TYPE, ULONG, PVOID, ULONG,
                                       PTOKEN_GROUPS, PTOKEN_SOURCE, PVOID *, PULONG, PLUID, PHANDLE,
                                       PQUOTA_LIMITS, PNTSTATUS);
typedef NTSTATUS (NTAPI *LSAFREERETURNBUFFER)(PVOID);

static LSACONNECTUNTRUSTED pLsaConnectUntrusted;
static LSAREGISTERLOGONPROCESS pLsaRegisterLogonProcess;
static LSADEREGISTERLOGONPROCESS pLsaDeregisterLogonProcess;
static LSALOOKUPAUTHENTICATIONPACKAGE pLsaLookupAuthenticationPackage;
static LSALOGONUSER pLsaLogonUser;
static LSAFREERETURNBUFFER pLsaFreeReturnBuffer;

/* The service logon of NT SERVICE\<Name> without a password over an LSA handle */
static NTSTATUS
ServiceLogon(HANDLE Lsa, PCWSTR Name, PHANDLE Token)
{
    static const WCHAR Domain[] = L"NT SERVICE";
    BYTE Buffer[sizeof(MSV1_0_INTERACTIVE_LOGON) + 256 * sizeof(WCHAR)];
    PMSV1_0_INTERACTIVE_LOGON Logon = (PMSV1_0_INTERACTIVE_LOGON)Buffer;
    PWCHAR Ptr = (PWCHAR)(Logon + 1);
    LSA_STRING PackageName, Origin;
    TOKEN_SOURCE Source;
    PVOID Profile = NULL;
    ULONG ProfileLength = 0, Package = 0;
    LUID LogonId;
    QUOTA_LIMITS Quotas;
    NTSTATUS Status, SubStatus = 0;

    *Token = NULL;
    RtlZeroMemory(Buffer, sizeof(Buffer));
    Logon->MessageType = MsV1_0InteractiveLogon;
    Logon->LogonDomainName.Buffer = Ptr;
    Logon->LogonDomainName.Length = sizeof(Domain) - sizeof(WCHAR);
    Logon->LogonDomainName.MaximumLength = sizeof(Domain);
    RtlCopyMemory(Ptr, Domain, sizeof(Domain));
    Ptr += _countof(Domain);
    Logon->UserName.Buffer = Ptr;
    Logon->UserName.Length = (USHORT)(wcslen(Name) * sizeof(WCHAR));
    Logon->UserName.MaximumLength = Logon->UserName.Length + sizeof(WCHAR);
    RtlCopyMemory(Ptr, Name, Logon->UserName.MaximumLength);
    Ptr += wcslen(Name) + 1;
    Logon->Password.Buffer = Ptr;
    Logon->Password.Length = 0;
    Logon->Password.MaximumLength = sizeof(WCHAR);

    RtlInitString((PSTRING)&PackageName, MSV1_0_PACKAGE_NAME);
    Status = pLsaLookupAuthenticationPackage(Lsa, &PackageName, &Package);
    if (Status != STATUS_SUCCESS)
        return Status;

    RtlInitString((PSTRING)&Origin, "SvcVAcct");
    RtlCopyMemory(Source.SourceName, "SvcVAcct", 8);
    AllocateLocallyUniqueId(&Source.SourceIdentifier);
    Status = pLsaLogonUser(Lsa, &Origin, Service, Package, Logon, (ULONG)((PBYTE)Ptr - Buffer + sizeof(WCHAR)),
                           NULL, &Source, &Profile, &ProfileLength, &LogonId, Token, &Quotas, &SubStatus);
    if (Profile)
        pLsaFreeReturnBuffer(Profile);
    return Status;
}

/* The thread impersonates the SYSTEM token of winlogon, the caller that holds SeTcbPrivilege */
static BOOL
ImpersonateSystem(VOID)
{
    PROCESSENTRY32W Entry;
    HANDLE Snapshot, Process, Token, Duplicate, Self;
    TOKEN_PRIVILEGES Privileges;
    BOOL Done = FALSE, More;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Self))
    {
        Privileges.PrivilegeCount = 1;
        Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &Privileges.Privileges[0].Luid))
            AdjustTokenPrivileges(Self, FALSE, &Privileges, 0, NULL, NULL);
        CloseHandle(Self);
    }
    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
        return FALSE;
    Entry.dwSize = sizeof(Entry);
    for (More = Process32FirstW(Snapshot, &Entry); More && !Done; More = Process32NextW(Snapshot, &Entry))
    {
        if (_wcsicmp(Entry.szExeFile, L"winlogon.exe") != 0)
            continue;
        Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Entry.th32ProcessID);
        if (!Process)
            continue;
        if (OpenProcessToken(Process, TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
        {
            if (DuplicateTokenEx(Token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Duplicate))
            {
                Done = SetThreadToken(NULL, Duplicate);
                CloseHandle(Duplicate);
            }
            CloseHandle(Token);
        }
        CloseHandle(Process);
    }
    CloseHandle(Snapshot);
    return Done;
}

/* The thread impersonates this process's token without SeTcbPrivilege (an administrator without it) */
static BOOL
ImpersonateWithoutTcb(VOID)
{
    HANDLE Self, Restricted, Duplicate;
    TOKEN_PRIVILEGES NoTcb;
    BOOL Done = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Self))
        return FALSE;
    NoTcb.PrivilegeCount = 1;
    NoTcb.Privileges[0].Attributes = 0;
    if (LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &NoTcb.Privileges[0].Luid) &&
        CreateRestrictedToken(Self, 0, 0, NULL, 1, NoTcb.Privileges, 0, NULL, &Restricted))
    {
        if (DuplicateTokenEx(Restricted, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Duplicate))
        {
            Done = SetThreadToken(NULL, Duplicate);
            CloseHandle(Duplicate);
        }
        CloseHandle(Restricted);
    }
    CloseHandle(Self);
    return Done;
}

/* The logon (over a registered logon process, as winlogon or the SCM have it) of the virtual account must
 * fail for a thread that does not hold SeTcbPrivilege. A refused registration is fine as well (Windows). */
static VOID
CheckRefusedAsLogonProcess(PCSTR What, PCWSTR Name)
{
    LSA_STRING ProcessName;
    LSA_OPERATIONAL_MODE Mode;
    HANDLE Lsa = NULL, Token = NULL;
    NTSTATUS Status;

    RtlInitString((PSTRING)&ProcessName, "SvcVAcctLogonProcess");
    Status = pLsaRegisterLogonProcess(&ProcessName, &Lsa, &Mode);
    if (Status != STATUS_SUCCESS)
    {
        trace("%s: LsaRegisterLogonProcess refused: 0x%08lx\n", What, Status);
        return;
    }
    Status = ServiceLogon(Lsa, Name, &Token);
    ok(Status == NT_STATUS_LOGON_FAILURE, "%s: service logon of NT SERVICE\\%ls returned 0x%08lx, expected 0x%08lx\n",
       What, Name, Status, NT_STATUS_LOGON_FAILURE);
    if (Token)
        CloseHandle(Token);
    pLsaDeregisterLogonProcess(Lsa);
}

static VOID
TestVirtualAccountLogon(PCWSTR Name)
{
    static WCHAR UserPassword[] = L"Svc-Acct-Logon-2026!";
    WCHAR UserName[32];
    HMODULE Sspicli = LoadLibraryW(L"sspicli.dll");
    HANDLE Lsa = NULL, Token = NULL, hUser = NULL;
    LSA_STRING ProcessName;
    LSA_OPERATIONAL_MODE Mode;
    NET_API_STATUS NetStatus = NERR_UserExists;
    NTSTATUS Status;
    DWORD Err, Try;

    if (Sspicli)
    {
        pLsaConnectUntrusted = (LSACONNECTUNTRUSTED)GetProcAddress(Sspicli, "LsaConnectUntrusted");
        pLsaRegisterLogonProcess = (LSAREGISTERLOGONPROCESS)GetProcAddress(Sspicli, "LsaRegisterLogonProcess");
        pLsaDeregisterLogonProcess = (LSADEREGISTERLOGONPROCESS)GetProcAddress(Sspicli, "LsaDeregisterLogonProcess");
        pLsaLookupAuthenticationPackage = (LSALOOKUPAUTHENTICATIONPACKAGE)GetProcAddress(Sspicli, "LsaLookupAuthenticationPackage");
        pLsaLogonUser = (LSALOGONUSER)GetProcAddress(Sspicli, "LsaLogonUser");
        pLsaFreeReturnBuffer = (LSAFREERETURNBUFFER)GetProcAddress(Sspicli, "LsaFreeReturnBuffer");
    }
    if (!pLsaConnectUntrusted || !pLsaRegisterLogonProcess || !pLsaDeregisterLogonProcess ||
        !pLsaLookupAuthenticationPackage || !pLsaLogonUser || !pLsaFreeReturnBuffer)
    {
        skip("an LSA function is missing\n");
        return;
    }

    /* A standard user: LogonUser (advapi32 connects as the caller is; its handle is kept, so this is the first
     * LogonUser of the process) and the LSA directly */
    for (Try = 0; Try < 5 && NetStatus == NERR_UserExists; Try++)
    {
        USER_INFO_1 Info;

        StringCchPrintfW(UserName, _countof(UserName), L"svcvauser%lx", (GetTickCount() + Try * 7919) & 0xffffff);
        RtlZeroMemory(&Info, sizeof(Info));
        Info.usri1_name = UserName;
        Info.usri1_password = UserPassword;
        Info.usri1_priv = USER_PRIV_USER;
        Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
        NetStatus = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    }
    if (NetStatus != NERR_Success)
    {
        skip("NetUserAdd failed with %lu, the standard user is not tested\n", NetStatus);
    }
    else if (!LogonUserW(UserName, L".", UserPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hUser) ||
             !ImpersonateLoggedOnUser(hUser))
    {
        skip("the standard user cannot be impersonated (%lu)\n", GetLastError());
    }
    else
    {
        BOOL Ret = LogonUserW((PWSTR)Name, L"NT SERVICE", L"", LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &Token);

        Err = GetLastError();
        ok(!Ret, "LogonUser of NT SERVICE\\%ls as a standard user succeeded\n", Name);
        if (!Ret)
            ok(Err == ERROR_LOGON_FAILURE, "LogonUser as a standard user failed with %lu, expected %d\n", Err, ERROR_LOGON_FAILURE);
        if (Ret)
            CloseHandle(Token);
        Token = NULL;
        CheckRefusedAsLogonProcess("standard user", Name);
        RevertToSelf();
    }
    if (hUser)
        CloseHandle(hUser);
    if (NetStatus == NERR_Success)
        NetUserDel(NULL, UserName);

    /* No SeTcbPrivilege: an untrusted connection (a standard user's) */
    Status = pLsaConnectUntrusted(&Lsa);
    ok(Status == STATUS_SUCCESS, "LsaConnectUntrusted failed: 0x%08lx\n", Status);
    if (Status == STATUS_SUCCESS)
    {
        Status = ServiceLogon(Lsa, Name, &Token);
        ok(Status == NT_STATUS_LOGON_FAILURE, "untrusted: service logon of NT SERVICE\\%ls returned 0x%08lx, expected 0x%08lx\n",
           Name, Status, NT_STATUS_LOGON_FAILURE);
        if (Token)
            CloseHandle(Token);
        pLsaDeregisterLogonProcess(Lsa);
    }

    /* An administrator without SeTcbPrivilege */
    if (ImpersonateWithoutTcb())
    {
        CheckRefusedAsLogonProcess("administrator without SeTcbPrivilege", Name);
        RevertToSelf();
    }
    else
    {
        skip("no token without SeTcbPrivilege (%lu)\n", GetLastError());
    }

    /* A caller with SeTcbPrivilege: the logon works, the token user is the service SID */
    if (ImpersonateSystem())
    {
        RtlInitString((PSTRING)&ProcessName, "SvcVAcctLogonProcess");
        Status = pLsaRegisterLogonProcess(&ProcessName, &Lsa, &Mode);
        ok(Status == STATUS_SUCCESS, "LsaRegisterLogonProcess failed: 0x%08lx\n", Status);
        if (Status == STATUS_SUCCESS)
        {
            Token = NULL;
            Status = ServiceLogon(Lsa, Name, &Token);
            ok(Status == STATUS_SUCCESS, "SeTcbPrivilege: service logon of NT SERVICE\\%ls returned 0x%08lx\n", Name, Status);
            if (Token)
                CloseHandle(Token);
            pLsaDeregisterLogonProcess(Lsa);
        }
        RevertToSelf();
    }
    else
    {
        skip("the thread cannot impersonate SYSTEM, the trusted caller is not tested\n");
    }
}

static VOID
ReportState(DWORD State)
{
    SERVICE_STATUS Status;

    RtlZeroMemory(&Status, sizeof(Status));
    Status.dwServiceType = SERVICE_WIN32;
    Status.dwCurrentState = State;
    if (State == SERVICE_STOPPED)
    {
        Status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        Status.dwServiceSpecificExitCode = TokenUserMatches(ServiceName);
    }
    Status.dwControlsAccepted = (State == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    Status.dwWaitHint = (State == SERVICE_RUNNING || State == SERVICE_STOPPED) ? 0 : 5000;
    SetServiceStatus(StatusHandle, &Status);
}

static DWORD WINAPI
ServiceHandler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    if (Control == SERVICE_CONTROL_STOP)
    {
        ReportState(SERVICE_STOP_PENDING);
        SetEvent(StopEvent);
    }
    return NO_ERROR;
}

static VOID WINAPI
ServiceMain(DWORD argc, LPWSTR *argv)
{
    StatusHandle = RegisterServiceCtrlHandlerExW(ServiceName, ServiceHandler, NULL);
    if (!StatusHandle)
        return;
    ReportState(SERVICE_RUNNING);
    WaitForSingleObject(StopEvent, 60000);
    ReportState(SERVICE_STOPPED);
}

static VOID
ServiceProcess(PCSTR Name)
{
    SERVICE_TABLE_ENTRYW Table[2];

    MultiByteToWideChar(CP_ACP, 0, Name, -1, ServiceName, _countof(ServiceName));
    StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    Table[0].lpServiceName = ServiceName;
    Table[0].lpServiceProc = ServiceMain;
    Table[1].lpServiceName = NULL;
    Table[1].lpServiceProc = NULL;
    StartServiceCtrlDispatcherW(Table);
}

/* Tester side */
static BOOL
WaitForState(SC_HANDLE hService, DWORD State, LPSERVICE_STATUS_PROCESS Status)
{
    DWORD Needed, Waited;

    RtlZeroMemory(Status, sizeof(*Status));
    for (Waited = 0; Waited <= 15000; Waited += 100)
    {
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)Status, sizeof(*Status), &Needed))
            return FALSE;
        if (Status->dwCurrentState == State)
            return TRUE;
        Sleep(100);
    }
    return FALSE;
}

START_TEST(ServiceVirtualAccount)
{
    CHAR FileName[MAX_PATH], Command[MAX_PATH + 128], Name[64];
    WCHAR Account[96];
    SC_HANDLE hScm, hService;
    SERVICE_STATUS_PROCESS Status;
    SERVICE_STATUS StopStatus;
    LPQUERY_SERVICE_CONFIGW Config;
    DWORD Needed = 0;
    int argc;
    char **argv;
    BOOL Ret;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "service"))
    {
        ServiceProcess(argv[3]);
        return;
    }

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm)
    {
        skip("OpenSCManager failed with %lu\n", GetLastError());
        return;
    }

    GetModuleFileNameA(NULL, FileName, _countof(FileName));
    StringCbPrintfA(Name, sizeof(Name), "RosSvcVAcct%lu", GetTickCount());
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" ServiceVirtualAccount service %s", FileName, Name);
    StringCbPrintfW(Account, sizeof(Account), L"NT SERVICE\\%S", Name);

    {
        WCHAR CommandW[MAX_PATH + 128];
        MultiByteToWideChar(CP_ACP, 0, Command, -1, CommandW, _countof(CommandW));
        hService = CreateServiceW(hScm, Account + 11, Account + 11, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                  SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, CommandW, NULL, NULL, NULL, Account, NULL);
    }
    ok(hService != NULL, "CreateService with start name %ls failed with %lu\n", Account, GetLastError());
    if (!hService)
    {
        CloseServiceHandle(hScm);
        return;
    }

    Ret = StartServiceA(hService, 0, NULL);
    ok(Ret, "StartService as %ls failed with %lu\n", Account, GetLastError());
    Ret = WaitForState(hService, SERVICE_RUNNING, &Status);
    ok(Ret, "service state %lu, expected running\n", Status.dwCurrentState);

    QueryServiceConfigW(hService, NULL, 0, &Needed);
    Config = HeapAlloc(GetProcessHeap(), 0, Needed);
    if (Config && QueryServiceConfigW(hService, Config, Needed, &Needed))
        ok(!_wcsicmp(Config->lpServiceStartName, Account), "start name %ls, expected %ls\n",
           Config->lpServiceStartName, Account);
    HeapFree(GetProcessHeap(), 0, Config);

    ControlService(hService, SERVICE_CONTROL_STOP, &StopStatus);
    Ret = WaitForState(hService, SERVICE_STOPPED, &Status);
    if (Ret)
    {
        SERVICE_STATUS Plain;

        /* the service process reports whether the user of its token is the service SID */
        ok(QueryServiceStatus(hService, &Plain), "QueryServiceStatus failed with %lu\n", GetLastError());
        ok(Plain.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR && Plain.dwServiceSpecificExitCode == EXIT_TOKEN_MATCHES,
           "exit code %lu / %lu, expected the service SID as the token user (%d)\n",
           Plain.dwWin32ExitCode, Plain.dwServiceSpecificExitCode, EXIT_TOKEN_MATCHES);
    }
    if (!Ret && Status.dwProcessId)
    {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, Status.dwProcessId);

        if (hProcess)
        {
            TerminateProcess(hProcess, 1);
            CloseHandle(hProcess);
        }
    }
    TestVirtualAccountLogon(Account + 11);
    DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);
}
