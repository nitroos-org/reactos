/*
 * PROJECT:     ReactOS IP Helper Service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     iphlpsvc service entry (hosted by svchost, -k netsvcs)
 */

#include "precomp.h"

static SERVICE_STATUS_HANDLE g_hStatus;
static SERVICE_STATUS g_Status;
static HANDLE g_hStopEvent;

static
VOID
SetState(DWORD dwState, DWORD dwError)
{
    g_Status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    g_Status.dwCurrentState = dwState;
    g_Status.dwControlsAccepted = (dwState == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    g_Status.dwWin32ExitCode = dwError;
    g_Status.dwWaitHint = (dwState == SERVICE_RUNNING || dwState == SERVICE_STOPPED) ? 0 : 3000;
    g_Status.dwCheckPoint = (dwState == SERVICE_RUNNING || dwState == SERVICE_STOPPED) ? 0 : g_Status.dwCheckPoint + 1;
    SetServiceStatus(g_hStatus, &g_Status);
}

static
DWORD
WINAPI
HandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    switch (dwControl)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            SetState(SERVICE_STOP_PENDING, NO_ERROR);
            SetEvent(g_hStopEvent);
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(g_hStatus, &g_Status);
            return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

VOID
WINAPI
ServiceMain(DWORD dwArgc, LPWSTR *lpszArgv)
{
    DWORD dwError;

    g_hStatus = RegisterServiceCtrlHandlerExW(L"iphlpsvc", HandlerEx, NULL);
    if (!g_hStatus)
        return;

    g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_hStopEvent)
    {
        SetState(SERVICE_STOPPED, GetLastError());
        return;
    }

    SetState(SERVICE_START_PENDING, NO_ERROR);

    dwError = PortProxyStart();
    if (dwError != NO_ERROR)
    {
        CloseHandle(g_hStopEvent);
        SetState(SERVICE_STOPPED, dwError);
        return;
    }

    SetState(SERVICE_RUNNING, NO_ERROR);

    WaitForSingleObject(g_hStopEvent, INFINITE);

    PortProxyStop();
    CloseHandle(g_hStopEvent);
    SetState(SERVICE_STOPPED, NO_ERROR);
}

BOOL
WINAPI
DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hinstDLL);
    return TRUE;
}
