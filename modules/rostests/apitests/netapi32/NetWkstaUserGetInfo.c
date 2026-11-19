/*
 * PROJECT:     ReactOS netapi32.dll API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for NetWkstaUserGetInfo: a user logon gets its names, a service logon gets none
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022: NetWkstaUserGetInfo (level 0 and 1) fails with
 * ERROR_NO_SUCH_LOGON_SESSION (1312) in a service that runs as a virtual account, as
 * LocalService and as LocalSystem.
 *
 * The service rows run this executable as a scratch own-process service ("--service" as the
 * second argument), which reports the two results through its specific exit code.
 * The caller must be able to create services; the executable must be readable by the accounts.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winsvc.h>
#include <ntsecapi.h>
#include <lmcons.h>
#include <lmerr.h>
#include <lmapibuf.h>
#include <lmwksta.h>

#define SERVICE_NAME    L"netapi32_apitest_WkstaUser"

/* ------------------------------------------------------------------ the service side */

static SERVICE_STATUS_HANDLE StatusHandle;

static DWORD WINAPI ServiceHandler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    return NO_ERROR;
}

static VOID WINAPI ServiceMain(DWORD Argc, LPWSTR *Argv)
{
    SERVICE_STATUS Status;
    PBYTE Buffer = NULL;
    DWORD Result0, Result1;

    StatusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceHandler, NULL);
    if (StatusHandle == NULL)
        return;

    Result0 = NetWkstaUserGetInfo(NULL, 0, &Buffer);
    if (Result0 == NERR_Success)
        NetApiBufferFree(Buffer);
    Buffer = NULL;
    Result1 = NetWkstaUserGetInfo(NULL, 1, &Buffer);
    if (Result1 == NERR_Success)
        NetApiBufferFree(Buffer);

    ZeroMemory(&Status, sizeof(Status));
    Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    Status.dwCurrentState = SERVICE_STOPPED;
    Status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
    Status.dwServiceSpecificExitCode = (Result0 & 0xffff) | (Result1 << 16);
    SetServiceStatus(StatusHandle, &Status);
}

/* ------------------------------------------------------------------ the test side */

static BOOL CallerIsUser(void)
{
    HANDLE Token;
    TOKEN_STATISTICS Statistics;
    DWORD Length;
    PSECURITY_LOGON_SESSION_DATA Data = NULL;
    BOOL Ret = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    if (GetTokenInformation(Token, TokenStatistics, &Statistics, sizeof(Statistics), &Length) &&
        LsaGetLogonSessionData(&Statistics.AuthenticationId, &Data) == 0 && Data != NULL)
    {
        /* LocalSystem has no user logon, a service logon is one of a service */
        Ret = (Data->LogonType != Service && Data->LogonType != 0);
        LsaFreeReturnBuffer(Data);
    }
    CloseHandle(Token);
    return Ret;
}

static void TestCaller(void)
{
    PWKSTA_USER_INFO_0 Info0 = NULL;
    PWKSTA_USER_INFO_1 Info1 = NULL;
    WCHAR UserName[UNLEN + 1];
    DWORD Size = ARRAYSIZE(UserName);
    NET_API_STATUS Status;

    if (!CallerIsUser())
    {
        skip("The test process is not a user logon\n");
        return;
    }

    GetUserNameW(UserName, &Size);

    Status = NetWkstaUserGetInfo(NULL, 0, (PBYTE *)&Info0);
    ok(Status == NERR_Success, "Level 0: Status %lu\n", Status);
    if (Status == NERR_Success)
    {
        ok(Info0->wkui0_username != NULL && Info0->wkui0_username[0] != UNICODE_NULL,
           "Level 0: empty user name\n");
        ok(Info0->wkui0_username != NULL && !_wcsicmp(Info0->wkui0_username, UserName),
           "Level 0: user name %ls, expected %ls\n", Info0->wkui0_username, UserName);
        NetApiBufferFree(Info0);
    }

    Status = NetWkstaUserGetInfo(NULL, 1, (PBYTE *)&Info1);
    ok(Status == NERR_Success, "Level 1: Status %lu\n", Status);
    if (Status == NERR_Success)
    {
        ok(Info1->wkui1_username != NULL && !_wcsicmp(Info1->wkui1_username, UserName),
           "Level 1: user name %ls, expected %ls\n", Info1->wkui1_username, UserName);
        ok(Info1->wkui1_logon_domain != NULL && Info1->wkui1_logon_domain[0] != UNICODE_NULL,
           "Level 1: empty logon domain\n");
        ok(Info1->wkui1_logon_server != NULL && Info1->wkui1_logon_server[0] != UNICODE_NULL,
           "Level 1: empty logon server\n");
        /* Windows Server 2022: the other domains are the empty string, and a logon as "." names the machine */
        ok(Info1->wkui1_oth_domains != NULL && Info1->wkui1_oth_domains[0] == UNICODE_NULL,
           "Level 1: other domains %ls, expected the empty string\n",
           Info1->wkui1_oth_domains ? Info1->wkui1_oth_domains : L"(null)");
        ok(Info1->wkui1_logon_domain != NULL && wcscmp(Info1->wkui1_logon_domain, L"."),
           "Level 1: logon domain %ls\n", Info1->wkui1_logon_domain ? Info1->wkui1_logon_domain : L"(null)");
        NetApiBufferFree(Info1);
    }

    {
        LPWKSTA_USER_INFO_1101 Info1101 = NULL;

        Status = NetWkstaUserGetInfo(NULL, 1101, (PBYTE *)&Info1101);
        ok(Status == NERR_Success, "Level 1101: Status %lu\n", Status);
        if (Status == NERR_Success)
        {
            ok(Info1101->wkui1101_oth_domains != NULL && Info1101->wkui1101_oth_domains[0] == UNICODE_NULL,
               "Level 1101: other domains %ls, expected the empty string\n",
               Info1101->wkui1101_oth_domains ? Info1101->wkui1101_oth_domains : L"(null)");
            NetApiBufferFree(Info1101);
        }
    }

    Status = NetWkstaUserGetInfo(NULL, 2, (PBYTE *)&Info1);
    ok(Status == ERROR_INVALID_LEVEL, "Level 2: Status %lu\n", Status);
}

/* Runs this executable as a service of the account; returns FALSE when it cannot be tried */
static BOOL RunAsService(SC_HANDLE Manager, PCWSTR Account, PCWSTR Row, BOOL SkipOnCreateError)
{
    WCHAR Path[MAX_PATH + 64];
    SC_HANDLE Service;
    SERVICE_STATUS_PROCESS Process;
    DWORD Needed, i;

    GetModuleFileNameW(NULL, Path, MAX_PATH);
    wcscat(Path, L" NetWkstaUserGetInfo --service");

    Service = OpenServiceW(Manager, SERVICE_NAME, DELETE);
    if (Service)
    {
        DeleteService(Service);
        CloseServiceHandle(Service);
    }

    Service = CreateServiceW(Manager, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                             SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, Path, NULL, NULL, NULL, Account, NULL);
    if (Service == NULL)
    {
        DWORD Error = GetLastError();

        if (SkipOnCreateError)
            skip("%ls: cannot create the service (error %lu)\n", Row, Error);
        else
            ok(0, "%ls: CreateService failed (error %lu)\n", Row, Error);
        return FALSE;
    }

    if (!StartServiceW(Service, 0, NULL))
    {
        DWORD Error = GetLastError();

        /* The service may have stopped itself already */
        ok(Error == ERROR_SERVICE_ALREADY_RUNNING || Error == ERROR_SERVICE_SPECIFIC_ERROR,
           "%ls: StartService failed (error %lu)\n", Row, Error);
    }

    ZeroMemory(&Process, sizeof(Process));
    for (i = 0; i < 300; i++)
    {
        if (!QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO, (PBYTE)&Process, sizeof(Process), &Needed) ||
            Process.dwCurrentState == SERVICE_STOPPED)
            break;
        Sleep(100);
    }

    ok(Process.dwCurrentState == SERVICE_STOPPED, "%ls: state %lu\n", Row, Process.dwCurrentState);
    ok(Process.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR, "%ls: exit code %lu\n", Row, Process.dwWin32ExitCode);
    ok((Process.dwServiceSpecificExitCode & 0xffff) == ERROR_NO_SUCH_LOGON_SESSION,
       "%ls: level 0 returned %lu, expected %d\n", Row, Process.dwServiceSpecificExitCode & 0xffff,
       ERROR_NO_SUCH_LOGON_SESSION);
    ok((Process.dwServiceSpecificExitCode >> 16) == ERROR_NO_SUCH_LOGON_SESSION,
       "%ls: level 1 returned %lu, expected %d\n", Row, Process.dwServiceSpecificExitCode >> 16,
       ERROR_NO_SUCH_LOGON_SESSION);

    DeleteService(Service);
    CloseServiceHandle(Service);
    return TRUE;
}

START_TEST(NetWkstaUserGetInfo)
{
    SC_HANDLE Manager;
    char **argv;
    int argc;
    SERVICE_TABLE_ENTRYW Table[] = { { (PWSTR)SERVICE_NAME, ServiceMain }, { NULL, NULL } };

    argc = winetest_get_mainargs(&argv);
    if (argc > 2 && !strcmp(argv[2], "--service"))
    {
        StartServiceCtrlDispatcherW(Table);
        return;
    }

    TestCaller();

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (Manager == NULL)
    {
        skip("Cannot open the service manager (error %lu)\n", GetLastError());
        return;
    }

    RunAsService(Manager, NULL, L"LocalSystem", FALSE);
    RunAsService(Manager, L"NT AUTHORITY\\LocalService", L"LocalService", FALSE);
    /* NetworkService was not measured on Windows: it is expected to behave like LocalService (verify on peer) */
    RunAsService(Manager, L"NT AUTHORITY\\NetworkService", L"NetworkService", TRUE);
    /* A virtual account needs a service controller that supports one */
    RunAsService(Manager, L"NT SERVICE\\" SERVICE_NAME, L"virtual account", TRUE);

    CloseServiceHandle(Manager);
}
