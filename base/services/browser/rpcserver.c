/*
 * PROJECT:     ReactOS Browser Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Browser service RPC server
 * COPYRIGHT:   Eric Kohl 2020 <eric.kohl@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"

//#include "lmerr.h"

WINE_DEFAULT_DEBUG_CHANNEL(browser);

/* FUNCTIONS *****************************************************************/

static BOOL RpcRegistered = FALSE;

/* The service shares its process (svchost -k netsvcs) with other services: its interface listens on its own
   (auto-listen), so no service of the process starts or stops the listening of the others. It is registered before
   the service reports that it runs. */
VOID
StartRpcServer(VOID)
{
    RPC_STATUS Status;

    Status = RpcServerUseProtseqEpW(L"ncacn_np", 20, L"\\pipe\\browser", NULL);
    if (Status != RPC_S_OK)
    {
        ERR("RpcServerUseProtseqEpW() failed (Status %lx)\n", Status);
        return;
    }

    Status = RpcServerRegisterIfEx(browser_v0_0_s_ifspec, NULL, NULL, RPC_IF_AUTOLISTEN,
                                   RPC_C_LISTEN_MAX_CALLS_DEFAULT, NULL);
    if (Status != RPC_S_OK)
    {
        ERR("RpcServerRegisterIfEx() failed (Status %lx)\n", Status);
        return;
    }

    RpcRegistered = TRUE;
}


/* The service stops: only its interface goes, once the calls in it have returned; the other services of the
   process keep listening */
VOID
StopRpcServer(VOID)
{
    if (RpcRegistered)
    {
        RpcServerUnregisterIf(browser_v0_0_s_ifspec, NULL, TRUE);
        RpcRegistered = FALSE;
    }
}


void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
}


void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}


/* Function 0 */
NET_API_STATUS
__stdcall
I_BrowserrServerEnum(
    BROWSER_IDENTIFY_HANDLE ServerName,
    LPWSTR Transport,
    LPWSTR ClientName,
    LPSERVER_ENUM_STRUCT EnumStruct,
    DWORD PreferedMaximumLength,
    LPDWORD TotalEntries,
    DWORD ServerType,
    LPWSTR Domain,
    LPDWORD ResumeHandle)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 1 (BrowserrDebugCall) */
NET_API_STATUS
__stdcall
BrowserOpnum1NotUsedOnWire(VOID)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 2 */
NET_API_STATUS
__stdcall
I_BrowserrQueryOtherDomains(
    BROWSER_IDENTIFY_HANDLE ServerName,
    LPSERVER_ENUM_STRUCT EnumStruct,
    LPDWORD TotalEntries)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 3 */
NET_API_STATUS
__stdcall
I_BrowserrResetNetlogonState(
    BROWSER_IDENTIFY_HANDLE ServerName)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 4 */
NET_API_STATUS
__stdcall
I_BrowserrDebugTrace(
    BROWSER_IDENTIFY_HANDLE ServerName,
    LPSTR String)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 5 */
NET_API_STATUS
__stdcall
I_BrowserrQueryStatistics(
    BROWSER_IDENTIFY_HANDLE ServerName,
    LPBROWSER_STATISTICS *Statistics)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 6 */
NET_API_STATUS
__stdcall
I_BrowserrResetStatistics(
    BROWSER_IDENTIFY_HANDLE ServerName)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 7 - Not used on wire */
NET_API_STATUS
__stdcall
NetrBrowserStatisticsClear(
    BROWSER_IDENTIFY_HANDLE ServerName)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 8 */
NET_API_STATUS
__stdcall
NetrBrowserStatisticsGet(
    BROWSER_IDENTIFY_HANDLE ServerName,
    DWORD Level,
    LPBROWSER_STATISTICS_STRUCT StatisticsStruct)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 9 */
NET_API_STATUS
__stdcall
I_BrowserrSetNetlogonState(
    BROWSER_IDENTIFY_HANDLE ServerName,
    LPWSTR DomainName,
    LPWSTR EmulatedComputerName,
    DWORD Role)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 10 */
NET_API_STATUS
__stdcall
I_BrowserrQueryEmulatedDomains(
    BROWSER_IDENTIFY_HANDLE ServerName,
    PBROWSER_EMULATED_DOMAIN_CONTAINER EmulatedDomains)
{
    UNIMPLEMENTED;
    return 0;
}


/* Function 11 (BrowserrServerEnumEx) */
NET_API_STATUS
__stdcall
BrowserOpnum11NotUsedOnWire(void)
{
    UNIMPLEMENTED;
    return 0;
}

/* EOF */
