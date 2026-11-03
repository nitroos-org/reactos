/*
 * PROJECT:     ReactOS Smart Card service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SCardSvr skeleton (svchost, -k LocalServiceAndNoImpersonation): runs and announces itself
 *
 * On Windows 10 SCardSvr is a trigger-start service: it is stopped while no reader is attached and starts when
 * one arrives. Here nothing starts it (services.exe has no trigger engine), it runs when started by hand
 * (sc start SCardSvr). While it runs it signals the started event, which makes winscard.dll accept contexts;
 * there is no reader stack behind it (USB CCID), so every context sees no readers.
 */

#include <stdarg.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winsvc.h>
#include <sddl.h>

/* The same name as SCARD_STARTED_EVENT_NAME of dll/win32/winscard */
#define SCARD_STARTED_EVENT_NAME L"Global\\Microsoft Smart Card Resource Manager Started"

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

/* Everyone may wait on the event, the service and the system own it */
static
HANDLE
CreateStartedEvent(VOID)
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR pSd = NULL;
    HANDLE hEvent;

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = NULL;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;0x00100000;;;WD)(A;;GA;;;SY)(A;;GA;;;LS)",
                                                             SDDL_REVISION_1, &pSd, NULL))
        sa.lpSecurityDescriptor = pSd;
    hEvent = CreateEventW(&sa, TRUE, FALSE, SCARD_STARTED_EVENT_NAME);
    if (pSd)
        LocalFree(pSd);
    return hEvent;
}

VOID
WINAPI
CalaisMain(DWORD dwArgc, LPWSTR *lpszArgv)
{
    HANDLE hStarted;

    g_hStatus = RegisterServiceCtrlHandlerExW(L"SCardSvr", HandlerEx, NULL);
    if (!g_hStatus)
        return;

    g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    hStarted = CreateStartedEvent();
    if (!g_hStopEvent || !hStarted)
    {
        DWORD dwError = GetLastError();

        if (g_hStopEvent)
            CloseHandle(g_hStopEvent);
        if (hStarted)
            CloseHandle(hStarted);
        SetState(SERVICE_STOPPED, dwError);
        return;
    }

    SetState(SERVICE_START_PENDING, NO_ERROR);
    SetEvent(hStarted);
    SetState(SERVICE_RUNNING, NO_ERROR);

    WaitForSingleObject(g_hStopEvent, INFINITE);

    ResetEvent(hStarted);
    CloseHandle(hStarted);
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
