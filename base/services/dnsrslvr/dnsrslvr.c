/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS DNS Resolver
 * FILE:        base/services/dnsrslvr/dnsrslvr.c
 * PURPOSE:     DNS Resolver Service
 * PROGRAMMER:  Christoph von Wittich
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ******************************************************************/

HINSTANCE hDllInstance;
SERVICE_STATUS_HANDLE ServiceStatusHandle;
SERVICE_STATUS SvcStatus;
static WCHAR ServiceName[] = L"Dnscache";
static volatile LONG StopStarted = 0;

VOID StartRpcServer(VOID);
VOID StopRpcServer(VOID);

/* FUNCTIONS *****************************************************************/

static
VOID
UpdateServiceStatus(
    HANDLE hServiceStatus,
    DWORD NewStatus,
    DWORD Increment)
{
    if (Increment > 0)
        SvcStatus.dwCheckPoint += Increment;
    else
        SvcStatus.dwCheckPoint = 0;

    SvcStatus.dwCurrentState = NewStatus;
    SetServiceStatus(hServiceStatus, &SvcStatus);
}

static
DWORD
WINAPI
StopThread(
    LPVOID lpParameter)
{
    UNREFERENCED_PARAMETER(lpParameter);

    /* Unregister the RPC interface and wait for its calls to return (the process keeps listening: it can
       host other services), then free what the calls used */
    StopRpcServer();
    DnsIntCacheFree();
    UpdateServiceStatus(ServiceStatusHandle, SERVICE_STOPPED, 0);
    return 0;
}

/*
 * The control handler runs on the one control thread of the host process, shared with the other services
 * of it: the wait for the calls in flight must not block it.
 */
static
VOID
BeginStop(VOID)
{
    HANDLE hThread;

    if (InterlockedExchange(&StopStarted, 1) != 0)
        return;

    SvcStatus.dwControlsAccepted = 0;
    UpdateServiceStatus(ServiceStatusHandle, SERVICE_STOP_PENDING, 1);

    hThread = CreateThread(NULL, 0, StopThread, NULL, 0, NULL);
    if (hThread != NULL)
    {
        CloseHandle(hThread);
    }
    else
    {
        StopThread(NULL);
    }
}

static
DWORD
WINAPI
ServiceControlHandler(
    DWORD dwControl,
    DWORD dwEventType,
    LPVOID lpEventData,
    LPVOID lpContext)
{
    switch (dwControl)
    {
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_STOP:
            BeginStop();
            break;

        case SERVICE_CONTROL_PARAMCHANGE:
            /* MaxCacheTtl and MaxNegativeCacheTtl (the cache is going away at a stop) */
            if (!StopStarted)
                DnsIntCacheReadParameters();
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
    return NO_ERROR;
}

VOID
WINAPI
ServiceMain(
    DWORD argc,
    LPWSTR *argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    DPRINT("ServiceMain() called\n");

    InterlockedExchange(&StopStarted, 0);
    SvcStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    SvcStatus.dwCurrentState            = SERVICE_START_PENDING;
    SvcStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE;
    SvcStatus.dwCheckPoint              = 0;
    SvcStatus.dwWin32ExitCode           = NO_ERROR;
    SvcStatus.dwServiceSpecificExitCode = 0;
    SvcStatus.dwWaitHint                = 4000;

    ServiceStatusHandle = RegisterServiceCtrlHandlerExW(ServiceName,
                                                        ServiceControlHandler,
                                                        NULL);

    if (!ServiceStatusHandle)
    {
        DPRINT1("DNSRSLVR: Unable to register service control handler (%lx)\n", GetLastError());
        return; // FALSE
    }

    DnsIntCacheInitialize();

    HostsFileInitialize();

    StartRpcServer();

    DPRINT("ServiceMain() done\n");
    UpdateServiceStatus(ServiceStatusHandle, SERVICE_RUNNING, 0);
}

BOOL
WINAPI
DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ PVOID pvReserved)
{
    UNREFERENCED_PARAMETER(pvReserved);

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            hDllInstance = hinstDLL;
            break;

        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}

/* EOF */
