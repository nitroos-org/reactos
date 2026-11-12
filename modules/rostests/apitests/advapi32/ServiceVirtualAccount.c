/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A service that runs as its virtual account, NT SERVICE\<service>
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>

/*
 * On Windows a service whose start name is NT SERVICE\<its own name> starts without a password and
 * runs with the service SID S-1-5-80-... as the user of its token. QueryServiceConfig returns the
 * start name as it was given. The process of the service looks at its own token, because the token of
 * a service is not open to an administrator's TOKEN_QUERY on every system.
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
    DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);
}
