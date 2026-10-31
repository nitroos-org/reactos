/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for advapi32!ControlServiceExW (information level 1, with SERVICE_CONTROL_INTERROGATE)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The errors and the results are those of Windows 10 22H2 (x64 and x86). Only the interrogate control is sent, which
 * changes nothing of the service.
 */

#include "precomp.h"

typedef BOOL (WINAPI *FN_CSEX)(SC_HANDLE, DWORD, DWORD, PVOID);

typedef struct _REASON_PARAMS
{
    DWORD dwReason;
    PVOID pszComment;
    SERVICE_STATUS_PROCESS ServiceStatus;
} REASON_PARAMS;

#define PENDING 0xdeadf00d

#ifndef SERVICE_STOP_REASON_FLAG_PLANNED
#define SERVICE_STOP_REASON_FLAG_PLANNED 0x40000000
#endif

START_TEST(ControlServiceEx)
{
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    FN_CSEX pControlServiceEx = (FN_CSEX)GetProcAddress(hAdvapi32, "ControlServiceExW");
    FN_CSEX pControlServiceExA = (FN_CSEX)GetProcAddress(hAdvapi32, "ControlServiceExA");
    SC_HANDLE hScm, hService, hQueryOnly;
    SERVICE_STATUS Status;
    REASON_PARAMS Params;
    BOOL Ret;
    ULONG Level;

    if (!pControlServiceEx || !pControlServiceExA)
    {
        ok(!is_reactos(), "ControlServiceExW/A are not exported by advapi32.dll\n");
        skip("ControlServiceEx is not available\n");
        return;
    }

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    ok(hScm != NULL, "OpenSCManager failed: %lu\n", GetLastError());
    if (!hScm)
        return;

    hService = OpenServiceW(hScm, L"EventLog", SERVICE_INTERROGATE | SERVICE_QUERY_STATUS);
    ok(hService != NULL, "OpenService failed: %lu\n", GetLastError());
    if (!hService)
    {
        CloseServiceHandle(hScm);
        return;
    }

    /* The reference: what ControlService answers */
    ok(ControlService(hService, SERVICE_CONTROL_INTERROGATE, &Status), "ControlService failed: %lu\n", GetLastError());

    /* Level 1 gives the status of the service, with its process */
    memset(&Params, 0xcc, sizeof(Params));
    Params.dwReason = 0;
    Params.pszComment = NULL;
    SetLastError(PENDING);
    Ret = pControlServiceEx(hService, SERVICE_CONTROL_INTERROGATE, 1, &Params);
    ok(Ret == TRUE, "level 1: %d, error %lu\n", Ret, GetLastError());
    ok(GetLastError() == PENDING || GetLastError() == ERROR_SUCCESS, "level 1: last error %lu\n", GetLastError());
    ok(Params.ServiceStatus.dwCurrentState == Status.dwCurrentState, "state %lu, ControlService says %lu\n",
       Params.ServiceStatus.dwCurrentState, Status.dwCurrentState);
    ok(Params.ServiceStatus.dwServiceType == Status.dwServiceType, "type %lx, ControlService says %lx\n",
       Params.ServiceStatus.dwServiceType, Status.dwServiceType);
    ok(Params.ServiceStatus.dwControlsAccepted == Status.dwControlsAccepted, "controls %lx, ControlService says %lx\n",
       Params.ServiceStatus.dwControlsAccepted, Status.dwControlsAccepted);
    ok(Params.ServiceStatus.dwProcessId != 0, "no process ID of a running service\n");

    /* A reason does not change that, and the ANSI form is the same call */
    memset(&Params, 0, sizeof(Params));
    Params.dwReason = SERVICE_STOP_REASON_FLAG_PLANNED;
    Ret = pControlServiceEx(hService, SERVICE_CONTROL_INTERROGATE, 1, &Params);
    ok(Ret == TRUE && Params.ServiceStatus.dwCurrentState == Status.dwCurrentState, "with a reason: %d, state %lu\n", Ret,
       Params.ServiceStatus.dwCurrentState);
    memset(&Params, 0, sizeof(Params));
    Ret = pControlServiceExA(hService, SERVICE_CONTROL_INTERROGATE, 1, &Params);
    ok(Ret == TRUE && Params.ServiceStatus.dwCurrentState == Status.dwCurrentState, "ANSI: %d, state %lu\n", Ret,
       Params.ServiceStatus.dwCurrentState);

    /* Other levels are invalid and write nothing */
    for (Level = 0; Level < 4; Level += (Level == 0 ? 2 : 1))
    {
        memset(&Params, 0xcc, sizeof(Params));
        SetLastError(PENDING);
        Ret = pControlServiceEx(hService, SERVICE_CONTROL_INTERROGATE, Level, &Params);
        ok(Ret == FALSE && GetLastError() == ERROR_INVALID_LEVEL, "level %lu: %d, error %lu\n", Level, Ret, GetLastError());
        ok(Params.ServiceStatus.dwCurrentState == 0xcccccccc, "level %lu: the status was written\n", Level);
    }
    memset(&Params, 0xcc, sizeof(Params));
    Ret = pControlServiceEx(hService, SERVICE_CONTROL_INTERROGATE, 0, &Params);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_LEVEL, "level 0: %d, error %lu\n", Ret, GetLastError());

    /* The comment of the reason is sent to the service control manager at level 1: it must be valid from here on */
    memset(&Params, 0, sizeof(Params));

    /* No parameters */
    SetLastError(PENDING);
    Ret = pControlServiceEx(hService, SERVICE_CONTROL_INTERROGATE, 1, NULL);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "no parameters: %d, error %lu\n", Ret, GetLastError());

    /* Handles: none, a bad one, and the one of the service control manager */
    SetLastError(PENDING);
    Ret = pControlServiceEx(NULL, SERVICE_CONTROL_INTERROGATE, 1, &Params);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_HANDLE, "NULL handle: %d, error %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pControlServiceEx((SC_HANDLE)(ULONG_PTR)0x1234, SERVICE_CONTROL_INTERROGATE, 1, &Params);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_HANDLE, "bad handle: %d, error %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pControlServiceEx(hScm, SERVICE_CONTROL_INTERROGATE, 1, &Params);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_HANDLE, "manager handle: %d, error %lu\n", Ret, GetLastError());

    /* A control the service does not take, and a handle without the right to send it */
    SetLastError(PENDING);
    Ret = pControlServiceEx(hService, 0x99, 1, &Params);
    ok(Ret == FALSE && GetLastError() == ERROR_ACCESS_DENIED, "control 0x99: %d, error %lu\n", Ret, GetLastError());
    hQueryOnly = OpenServiceW(hScm, L"EventLog", SERVICE_QUERY_STATUS);
    if (hQueryOnly)
    {
        SetLastError(PENDING);
        Ret = pControlServiceEx(hQueryOnly, SERVICE_CONTROL_INTERROGATE, 1, &Params);
        ok(Ret == FALSE && GetLastError() == ERROR_ACCESS_DENIED, "no interrogate right: %d, error %lu\n", Ret, GetLastError());
        CloseServiceHandle(hQueryOnly);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);
}
