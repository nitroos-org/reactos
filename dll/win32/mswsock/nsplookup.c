#include "precomp.h"

#include <stdlib.h>
#include <ws2spi.h>
#include <ws2tcpip.h>
#include <nspapi.h>
#include <winuser.h>
#include <windns.h>
#include <guiddef.h>
#include <svcguid.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <strsafe.h>
#include <winnls.h>
#include <winreg.h>

#include "mswhelper.h"

#define NDEBUG
#include <debug.h>

#define NSP_CALLID_DNS 0x0001
#define NSP_CALLID_HOSTNAME 0x0002
#define NSP_CALLID_HOSTBYNAME 0x0003
#define NSP_CALLID_SERVICEBYNAME 0x0004
#define NSP_CALLID_NLA 0x0005
#define NSP_CALLID_PTR 0x0006
#define NSP_CALLID_HOSTBYADDR 0x0007

/* NLA (Network Location Awareness) blob constants (from mswsock.h).
 * Defined locally so we don't have to pull the whole mswsock.h into the
 * provider implementation. */
#ifndef NLA_CONNECTIVITY
#define NLA_RAW_DATA           0
#define NLA_INTERFACE          1
#define NLA_802_1X_LOCATION    2
#define NLA_CONNECTIVITY       3
#define NLA_ICS                4

#define NLA_NETWORK_AD_HOC     0
#define NLA_NETWORK_MANAGED    1
#define NLA_NETWORK_UNMANAGED  2
#define NLA_NETWORK_UNKNOWN    3

#define NLA_INTERNET_UNKNOWN   0
#define NLA_INTERNET_NO        1
#define NLA_INTERNET_YES       2
#endif

#ifndef BUFSIZ
#define BUFSIZ 1024
#endif // BUFSIZ
#ifndef WS2_INTERNAL_MAX_ALIAS
#define WS2_INTERNAL_MAX_ALIAS 512
#endif // WS2_INTERNAL_MAX_ALIAS

//#define IP_LOCALHOST 0x0100007F

//#define NSP_REDIRECT

/* the biggest result of one lookup that is sized by building it (a DNS answer is at most 64 KB) */
#define MSW_MAX_RESULT (4 * 1024 * 1024)

typedef struct {
  WCHAR* hostnameW;
  DWORD addr4; /* the first address (or the only one) */
  DWORD* addrs4; /* every IPv4 address of a name lookup (heap, addrCount entries), NULL: just addr4 */
  DWORD addrCount;
  WCHAR* servnameW;
  WCHAR* servprotoW;
  CHAR** servaliasesA; /* array */
  WORD servport;
  BOOLEAN isV6; /* gethostbyaddr of an IPv6 address: addr6 is the address the name was asked for */
  BYTE addr6[16];
} WSHOSTINFOINTERN, *PWSHOSTINFOINTERN;

typedef struct {
  GUID providerId; /* Provider-ID */
  DWORD dwControlFlags; /* dwControlFlags (WSALookupServiceBegin) */
  DWORD CallID; /* List for LookupServiceNext-Calls */
  DWORD CallIDCounter; /* call-count of the current CallID. */
  WCHAR* hostnameW; /* hostbyname */
  /* NLA (SIO_NSP_NOTIFY_CHANGE) connectivity-change notification state */
  HANDLE hNotifyThread;               /* poll thread signalling on change */
  HANDLE hNotifyStop;                 /* manual-reset event used to stop it */
  LPWSAOVERLAPPED lpNotifyOverlapped; /* caller overlapped signalled on change */
#ifdef NSP_REDIRECT
  HANDLE rdrLookup;
  NSP_ROUTINE rdrproc;
#endif
} WSHANDLEINTERN, *PWSHANDLEINTERN;

static const GUID guid_NULL = {0};
static const GUID guid_HOSTNAME = SVCID_HOSTNAME;
static const GUID guid_INET_HOSTADDRBYINETSTRING = SVCID_INET_HOSTADDRBYINETSTRING;
static const GUID guid_INET_HOSTADDRBYNAME = SVCID_INET_HOSTADDRBYNAME;
static const GUID guid_INET_SERVICEBYNAME = SVCID_INET_SERVICEBYNAME;
static const GUID guid_DNS_TYPE_PTR = SVCID_DNS_TYPE_PTR;

/* GUIDs - maybe they should be loaded from registry? */
/* Namespace: 32 */
static const GUID guid_mswsock_TcpIp = {/*Data1:*/ 0x22059D40,
                                        /*Data2:*/ 0x7E9E,
                                        /*Data3:*/ 0x11CF,
                                        /*Data4:*/ {0xAE, 0x5A, 0x00, 0xAA, 0x00, 0xA7, 0x11, 0x2B}};

/* {6642243A-3BA8-4AA6-BAA5-2E0BD71FDD83} */
/* Namespace: 15 */
static const GUID guid_mswsock_NLA = {/*Data1:*/ 0x6642243A,
                                      /*Data2:*/ 0x3BA8,
                                      /*Data3:*/ 0x4AA6,
                                      /*Data4:*/ {0xBA, 0xA5, 0x2E, 0x0B, 0xD7, 0x1F, 0xDD, 0x83}};

/* {0037E515-B5C9-4A43-BADA-8B48A87AD239} - NLA_SERVICE_CLASS_GUID */
/* Service class queried by NLA-aware clients (e.g. Chrome's
 * NetworkChangeNotifierWin) via WSALookupServiceBegin on the NLA namespace. */
static const GUID guid_NLA_ServiceClass = {/*Data1:*/ 0x0037E515,
                                           /*Data2:*/ 0xB5C9,
                                           /*Data3:*/ 0x4A43,
                                           /*Data4:*/ {0xBA, 0xDA, 0x8B, 0x48, 0xA8, 0x7A, 0xD2, 0x39}};

#ifdef NSP_REDIRECT

typedef INT
(CALLBACK *lpRdrNSPStartup)(
  LPGUID lpProviderId,
  LPNSP_ROUTINE lpRout);

const rdrLib = "mswsock.dll-original";
lpRdrNSPStartup rdrNSPStartup;
HANDLE hLib;
NSP_ROUTINE rdrproc_tcpip;
NSP_ROUTINE rdrproc_nla;

#endif /* NSP_REDIRECT */

/* Forwards */
INT
WINAPI
mswNSPStartup(
  LPGUID lpProviderId,
  LPNSP_ROUTINE lpRout);

INT
NSP_LookupServiceBeginW(
  PWSHANDLEINTERN data,
  CHAR* hostnameA,
  WCHAR* hostnameW,
  DWORD CallID);

INT
NSP_LookupServiceNextW(
  _In_ PWSHANDLEINTERN data,
  _In_ DWORD dwControlFlags,
  _Inout_ LPWSAQUERYSETW lpRes,
  _Inout_ LPDWORD lpResLen);

INT
NSP_GetHostNameHeapAllocW(
  _Out_ WCHAR** hostname);

INT
NSP_GetHostByNameHeapAllocW(
  _In_ PWSHANDLEINTERN data,
  _In_ DWORD dwControlFlags,
  _Out_ PWSHOSTINFOINTERN hostinfo);

INT
NSP_GetServiceByNameHeapAllocW(
  _In_ PWSHANDLEINTERN data,
  _In_ DWORD dwControlFlags,
  _Out_ PWSHOSTINFOINTERN hostinfo);

INT
NSP_GetHostByPtrHeapAllocW(
  _In_ PCWSTR ReverseName,
  _Out_ PWSHOSTINFOINTERN hostinfo);

INT
NSP_BuildNLAResultW(
  _In_ PWSHANDLEINTERN data,
  _Inout_ PMSW_BUFFER buf,
  _Inout_ LPWSAQUERYSETW lpRes,
  _Inout_ LPDWORD lpResLen);

/* Implementations - Internal */

#define NLA_POLL_INTERVAL_MS 2000

/* Compute a cheap signature of the current connectivity state (non-loopback
 * adapters, their addresses/gateways/DHCP). When it changes the network went
 * up/down or an address changed - which is what NLA change notification
 * reports. Also returns whether any connected adapter exists via *pConnected,
 * and (optionally) the description of the first connected adapter. */
static
DWORD
NlaConnectivitySignature(_Out_opt_ BOOL* pConnected,
                         _Out_opt_ BOOL* pInternet,
                         _Out_writes_opt_z_(cchName) WCHAR* pNameW,
                         _In_ DWORD cchName)
{
    IP_ADAPTER_INFO* info = NULL;
    IP_ADAPTER_INFO* p;
    ULONG len = 0;
    DWORD ret;
    DWORD sig = 0;
    BOOL connected = FALSE;
    BOOL internet = FALSE;
    const CHAR* pc;

    if (pConnected)
        *pConnected = FALSE;
    if (pInternet)
        *pInternet = FALSE;
    if (pNameW && cchName)
        pNameW[0] = L'\0';

    ret = GetAdaptersInfo(NULL, &len);
    if ((ret != ERROR_BUFFER_OVERFLOW) || (len == 0))
        return 0;

    info = HeapAlloc(GetProcessHeap(), 0, len);
    if (!info)
        return 0;

    if (GetAdaptersInfo(info, &len) == NO_ERROR)
    {
        for (p = info; p != NULL; p = p->Next)
        {
            BOOL hasAddr;
            BOOL hasGw;
            BOOL isApipa;

            if (p->Type == MIB_IF_TYPE_LOOPBACK)
                continue;

            hasAddr = (p->IpAddressList.IpAddress.String[0] != '\0') &&
                      (strcmp(p->IpAddressList.IpAddress.String, "0.0.0.0") != 0);
            hasGw = (p->GatewayList.IpAddress.String[0] != '\0') &&
                    (strcmp(p->GatewayList.IpAddress.String, "0.0.0.0") != 0);
            /* APIPA / link-local 169.254.0.0/16 means no real connectivity. */
            isApipa = (strncmp(p->IpAddressList.IpAddress.String, "169.254.", 8) == 0);

            /* fold adapter identity + addressing into the signature */
            sig = (sig * 131) + p->Index;
            for (pc = p->IpAddressList.IpAddress.String; *pc; pc++)
                sig = (sig * 131) + (BYTE)*pc;
            for (pc = p->GatewayList.IpAddress.String; *pc; pc++)
                sig = (sig * 131) + (BYTE)*pc;
            sig = (sig * 131) + (p->DhcpEnabled ? 1u : 0u);

            /* A non-loopback adapter with a routable address counts as a
             * connected network. "Internet" is only claimed when it also has a
             * default gateway and is not an APIPA self-assigned (169.254.x)
             * address - we must not overclaim NLA_INTERNET_YES. */
            if (hasAddr && !connected)
            {
                connected = TRUE;
                internet = hasGw && !isApipa;
                if (pNameW && cchName)
                {
                    MultiByteToWideChar(CP_ACP, 0, p->Description, -1,
                                        pNameW, cchName);
                    pNameW[cchName - 1] = L'\0';
                }
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, info);

    if (pConnected)
        *pConnected = connected;
    if (pInternet)
        *pInternet = internet;

    /* keep sig non-zero when connected so a 0<->connected transition is visible */
    if (connected && sig == 0)
        sig = 1;

    return sig;
}

/* Poll thread: watches for a connectivity-signature change and then signals the
 * caller-supplied overlapped event (one-shot; the client re-arms by issuing a
 * fresh WSALookupServiceBegin + SIO_NSP_NOTIFY_CHANGE). */
static
DWORD
WINAPI
NlaNotifyThreadProc(_In_ LPVOID lpParam)
{
    PWSHANDLEINTERN pLook = (PWSHANDLEINTERN)lpParam;
    DWORD baseline;

    baseline = NlaConnectivitySignature(NULL, NULL, NULL, 0);

    for (;;)
    {
        DWORD cur;

        if (WaitForSingleObject(pLook->hNotifyStop, NLA_POLL_INTERVAL_MS) == WAIT_OBJECT_0)
            return 0; /* stopped from mwsNSPLookupServiceEnd */

        cur = NlaConnectivitySignature(NULL, NULL, NULL, 0);
        if (cur != baseline)
        {
            LPWSAOVERLAPPED ov = pLook->lpNotifyOverlapped;
            if (ov)
            {
                ov->Internal = 0;     /* STATUS_SUCCESS */
                ov->InternalHigh = 0;
                if (ov->hEvent)
                    SetEvent(ov->hEvent);
            }
            return 0;
        }
    }
}

INT
WSAAPI
mwsNSPCleanUp(_In_ LPGUID lpProviderId)
{
    //WSASetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    //return ERROR_CALL_NOT_IMPLEMENTED;
    return ERROR_SUCCESS;
}

INT
mwsNSPInit(VOID)
{
    return ERROR_SUCCESS;
}

INT
WSAAPI
mwsNSPLookupServiceBegin(_In_ LPGUID lpProviderId,
                         _In_ LPWSAQUERYSETW lpqsRestrictions,
                         _In_ LPWSASERVICECLASSINFOW lpServiceClassInfo,
                         _In_ DWORD dwControlFlags,
                         _Out_ LPHANDLE lphLookup)
{
    PWSHANDLEINTERN pLook;
    int wsaErr;

    if (IsEqualGUID(lpProviderId, &guid_mswsock_TcpIp))
    {
        /* The DNS (TcpIp) provider needs a concrete service class. A NULL class
         * (e.g. an NS_NLA query that also matched this entry) is not ours - fail
         * before allocating so ws2_32 drops us and uses the NLA provider. This
         * also avoids dereferencing a NULL class id in the IsEqualGUID chain
         * below now that ws2_32 forwards NULL service-class ids. */
        if (lpqsRestrictions->lpServiceClassId == NULL)
        {
            WSASetLastError(WSASERVICE_NOT_FOUND);
            return SOCKET_ERROR;
        }
    }
    else if (IsEqualGUID(lpProviderId, &guid_mswsock_NLA))
    {
        /* The NLA namespace provider answers NLA connectivity queries. NLA-aware
         * clients pass either the NLA service class or (commonly) a NULL service
         * class to enumerate the current networks; reject any other explicit
         * class so ws2_32 drops this provider cleanly for non-NLA queries. */
        if ((lpqsRestrictions->lpServiceClassId != NULL) &&
            !IsEqualGUID(lpqsRestrictions->lpServiceClassId, &guid_NLA_ServiceClass))
        {
            WSASetLastError(WSASERVICE_NOT_FOUND);
            return SOCKET_ERROR;
        }
        /* OK - handled as an NLA connectivity lookup below */
    }
    else
    {
        return ERROR_CALL_NOT_IMPLEMENTED;
    }

    /* allocate internal structure */
    pLook = HeapAlloc(GetProcessHeap(), 0, sizeof(WSHANDLEINTERN));
    if (!pLook)
    {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    *lphLookup = (HANDLE)pLook;

    RtlZeroMemory(pLook, sizeof(*pLook));

    /* Anyway the ControlFlags "should" be needed
       in NSPLookupServiceNext. (see doku) But
       thats not the fact ATM. */
    pLook->dwControlFlags = dwControlFlags;
    pLook->providerId = *lpProviderId;

#ifdef NSP_REDIRECT

    if (IsEqualGUID(lpProviderId, &guid_mswsock_TcpIp))
    {
        pLook->rdrproc = rdrproc_tcpip;
    }
    else if (IsEqualGUID(lpProviderId, &guid_mswsock_NLA))
    {
        pLook->rdrproc = rdrproc_nla;
    }
    else
    {
        return ERROR_CALL_NOT_IMPLEMENTED;
    }

    if (pLook->rdrproc.NSPLookupServiceBegin(lpProviderId,
                                             lpqsRestrictions,
                                             lpServiceClassInfo,
                                             dwControlFlags,
                                             &pLook->rdrLookup) == NO_ERROR)
    {
        wsaErr = NO_ERROR;
    }
    else
    {
        wsaErr = WSAGetLastError();
    }

    /*
    if (res)
        res = WSAGetLastError();
    */

#else /* NSP_REDIRECT */

    wsaErr = ERROR_CALL_NOT_IMPLEMENTED;
    if (IsEqualGUID(lpProviderId, &guid_mswsock_NLA))
    {
        /* NLA connectivity lookup (service class already validated above). */
        pLook->CallID = NSP_CALLID_NLA;
        wsaErr = NO_ERROR;
    }
    else if (IsEqualGUID(lpqsRestrictions->lpServiceClassId, &guid_NULL))
    {
        wsaErr = ERROR_CALL_NOT_IMPLEMENTED;
    }
    else if (IsEqualGUID(lpqsRestrictions->lpServiceClassId, &guid_HOSTNAME))
    {
        wsaErr = NSP_LookupServiceBeginW(pLook,
                                         NULL,
                                         NULL,
                                         NSP_CALLID_HOSTNAME);
    }
    else if (IsEqualGUID(lpqsRestrictions->lpServiceClassId,
                         &guid_INET_HOSTADDRBYNAME))
    {
       wsaErr = NSP_LookupServiceBeginW(pLook,
                                        NULL,
                                        lpqsRestrictions->lpszServiceInstanceName,
                                        NSP_CALLID_HOSTBYNAME);
    }
    else if (IsEqualGUID(lpqsRestrictions->lpServiceClassId,
                         &guid_INET_SERVICEBYNAME))
    {
       wsaErr = NSP_LookupServiceBeginW(pLook,
                                        NULL,
                                        lpqsRestrictions->lpszServiceInstanceName,
                                        NSP_CALLID_SERVICEBYNAME);
    }
    else if (IsEqualGUID(lpqsRestrictions->lpServiceClassId,
                         &guid_INET_HOSTADDRBYINETSTRING))
    {
        /* gethostbyaddr: the instance name is the address in text form */
        wsaErr = NSP_LookupServiceBeginW(pLook,
                                         NULL,
                                         lpqsRestrictions->lpszServiceInstanceName,
                                         NSP_CALLID_HOSTBYADDR);
    }
    else if (IsEqualGUID(lpqsRestrictions->lpServiceClassId,
                         &guid_DNS_TYPE_PTR))
    {
        /* getnameinfo: the instance name is the reverse (in-addr.arpa) name */
        wsaErr = NSP_LookupServiceBeginW(pLook,
                                         NULL,
                                         lpqsRestrictions->lpszServiceInstanceName,
                                         NSP_CALLID_PTR);
    }

#endif /* NSP_REDIRECT */

    if (wsaErr != NO_ERROR)
    {
        /* Begin failed: ws2_32 deletes the provider without calling
         * NSPLookupServiceEnd, so free our handle here to avoid a leak. */
        HeapFree(GetProcessHeap(), 0, pLook);
        *lphLookup = NULL;
        WSASetLastError(wsaErr);
        return SOCKET_ERROR;
    }
    return NO_ERROR;
}

INT
WSAAPI
mwsNSPLookupServiceNext(_In_ HANDLE hLookup,
                        _In_ DWORD dwControlFlags,
                        _Inout_ LPDWORD lpdwBufferLength,
                        //_Out_writes_bytes_to_(*lpdwBufferLength, *lpdwBufferLength)
                        LPWSAQUERYSETW lpqsResults)
{
    PWSHANDLEINTERN pLook = hLookup;
    int wsaErr = 0;

#ifdef NSP_REDIRECT

    INT res = pLook->rdrproc.NSPLookupServiceNext(pLook->rdrLookup,
                                                  dwControlFlags,
                                                  lpdwBufferLength,
                                                  lpqsResults);
    wsaErr = WSAGetLastError();
    if (res != ERROR_SUCCESS)
    {
        wsaErr = WSAGetLastError();

        if (wsaErr == 0)
            wsaErr = 0xFFFFFFFF;
    }

#else /* NSP_REDIRECT */

    if ((lpdwBufferLength == NULL) || (*lpdwBufferLength == 0))
    {
        wsaErr = WSA_NOT_ENOUGH_MEMORY;
        goto End;
    }

    RtlZeroMemory(lpqsResults, *lpdwBufferLength);
    lpqsResults->dwSize = sizeof(*lpqsResults);

    wsaErr = NSP_LookupServiceNextW(pLook,
                                    dwControlFlags,
                                    lpqsResults,
                                    lpdwBufferLength);


#endif /* NSP_REDIRECT */

End:
    if (wsaErr != 0)
    {
        WSASetLastError(wsaErr);
        return SOCKET_ERROR;
    }
    return NO_ERROR;
}

INT
WSAAPI
mwsNSPIoCtl(_In_ HANDLE hLookup,
            _In_ DWORD dwControlCode,
            _In_reads_bytes_(cbInBuffer) LPVOID lpvInBuffer,
            _In_ DWORD cbInBuffer,
            _Out_writes_bytes_to_(cbOutBuffer, *lpcbBytesReturned) LPVOID lpvOutBuffer,
            _In_ DWORD cbOutBuffer,
            _Out_ LPDWORD lpcbBytesReturned,
            _In_opt_ LPWSACOMPLETION lpCompletion,
            _In_ LPWSATHREADID lpThreadId)
{
    PWSHANDLEINTERN pLook = (PWSHANDLEINTERN)hLookup;
    LPWSAOVERLAPPED lpOverlapped;
    DWORD threadId;

    UNREFERENCED_PARAMETER(lpvInBuffer);
    UNREFERENCED_PARAMETER(cbInBuffer);
    UNREFERENCED_PARAMETER(lpvOutBuffer);
    UNREFERENCED_PARAMETER(cbOutBuffer);
    UNREFERENCED_PARAMETER(lpThreadId);

    if (lpcbBytesReturned)
        *lpcbBytesReturned = 0;

    /* The only control code we support is the NLA connectivity-change
     * notification used by NLA-aware clients to be woken on network up/down. */
    if (dwControlCode != SIO_NSP_NOTIFY_CHANGE)
    {
        WSASetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }

    if ((pLook == NULL) || (pLook->CallID != NSP_CALLID_NLA))
    {
        WSASetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }

    /* We implement the overlapped/event completion form: the caller supplies an
     * OVERLAPPED whose hEvent is signalled when connectivity changes - exactly
     * the semantics NetworkChangeNotifierWin relies on to recover.
     *
     * Note: iphlpapi's NotifyAddrChange is a non-signalling stub here, so we
     * drive the notification ourselves from a connectivity poll thread rather
     * than depend on it. */
    if ((lpCompletion == NULL) || (lpCompletion->Type != NSP_NOTIFY_EVENT))
    {
        /* Only the event form is implemented for now. */
        WSASetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }

    lpOverlapped = lpCompletion->Parameters.Event.lpOverlapped;
    if (lpOverlapped == NULL)
    {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    /* Re-arm: stop any previously running notification on this handle. */
    if (pLook->hNotifyThread != NULL)
    {
        SetEvent(pLook->hNotifyStop);
        WaitForSingleObject(pLook->hNotifyThread, INFINITE);
        CloseHandle(pLook->hNotifyThread);
        pLook->hNotifyThread = NULL;
    }

    if (pLook->hNotifyStop == NULL)
    {
        pLook->hNotifyStop = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (pLook->hNotifyStop == NULL)
        {
            WSASetLastError(WSA_NOT_ENOUGH_MEMORY);
            return SOCKET_ERROR;
        }
    }
    else
    {
        ResetEvent(pLook->hNotifyStop);
    }

    /* Make sure the overlapped is in the pending state before we arm.
     * (STATUS_PENDING; ntstatus.h is excluded via WIN32_NO_STATUS.) */
    lpOverlapped->Internal = (ULONG_PTR)0x00000103L;
    pLook->lpNotifyOverlapped = lpOverlapped;

    pLook->hNotifyThread = CreateThread(NULL, 0, NlaNotifyThreadProc,
                                        pLook, 0, &threadId);
    if (pLook->hNotifyThread == NULL)
    {
        pLook->lpNotifyOverlapped = NULL;
        WSASetLastError(WSA_NOT_ENOUGH_MEMORY);
        return SOCKET_ERROR;
    }

    /* Change notification armed; completion will signal asynchronously. */
    WSASetLastError(WSA_IO_PENDING);
    return SOCKET_ERROR;
}

INT
WSAAPI
mwsNSPLookupServiceEnd(_In_ HANDLE hLookup)
{
    PWSHANDLEINTERN pLook;
    HANDLE hHeap;
    INT res;

    res = NO_ERROR;
    pLook = (PWSHANDLEINTERN)hLookup;
    hHeap = GetProcessHeap();

#ifdef NSP_REDIRECT
    res = pLook->rdrproc.NSPLookupServiceEnd(pLook->rdrLookup);
#endif

    /* Tear down any armed NLA change notification. Stop and join the poll
     * thread BEFORE freeing pLook so the thread can't touch freed memory. */
    if (pLook->hNotifyThread != NULL)
    {
        SetEvent(pLook->hNotifyStop);
        WaitForSingleObject(pLook->hNotifyThread, INFINITE);
        CloseHandle(pLook->hNotifyThread);
        pLook->hNotifyThread = NULL;
    }
    if (pLook->hNotifyStop != NULL)
    {
        CloseHandle(pLook->hNotifyStop);
        pLook->hNotifyStop = NULL;
    }

    if (pLook->hostnameW != NULL)
        HeapFree(hHeap, 0, pLook->hostnameW);

    HeapFree(hHeap, 0, pLook);
    return res;
}

INT
WSAAPI
mwsNSPSetService(_In_ LPGUID lpProviderId,
                 _In_ LPWSASERVICECLASSINFOW lpServiceClassInfo,
                 _In_ LPWSAQUERYSETW lpqsRegInfo,
                 _In_ WSAESETSERVICEOP essOperation,
                 _In_ DWORD dwControlFlags)
{
    WSASetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

INT
WSAAPI
mwsNSPInstallServiceClass(_In_ LPGUID lpProviderId,
                          _In_ LPWSASERVICECLASSINFOW lpServiceClassInfo)
{
    WSASetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

INT
WSAAPI
mwsNSPRemoveServiceClass(_In_ LPGUID lpProviderId,
                         _In_ LPGUID lpServiceClassId)
{
    WSASetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

INT
WSAAPI
mwsNSPGetServiceClassInfo(_In_ LPGUID lpProviderId,
                          _In_ LPDWORD lpdwBufSize,
                          _In_ LPWSASERVICECLASSINFOW lpServiceClassInfo)
{
    WSASetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/*
    hostnameA / hostnameW
    * only used by HOSTBYNAME
    * only one should be set

*/
INT
NSP_LookupServiceBeginW(PWSHANDLEINTERN data,
                        CHAR* hostnameA,
                        WCHAR* hostnameW,
                        DWORD CallID)
{
    HANDLE hHeap;

    if (data->CallID != 0)
        return WSAEFAULT;

    data->CallID = CallID;

    if ((CallID == NSP_CALLID_HOSTBYNAME) ||
        (CallID == NSP_CALLID_SERVICEBYNAME) ||
        (CallID == NSP_CALLID_PTR) ||
        (CallID == NSP_CALLID_HOSTBYADDR))
    {
        if ((CallID == NSP_CALLID_PTR || CallID == NSP_CALLID_HOSTBYADDR) &&
            hostnameW == NULL && hostnameA == NULL)
            return WSAEFAULT;

        hHeap = GetProcessHeap();

        if (data->hostnameW != NULL)
            HeapFree(hHeap, 0, data->hostnameW);

        if (hostnameA != NULL)
        {
            data->hostnameW = StrA2WHeapAlloc(hHeap, hostnameA);
        }
        else
        {
            data->hostnameW = StrCpyHeapAllocW(hHeap, hostnameW);
        }
    }

    WSASetLastError(0);

    return ERROR_SUCCESS;
}

INT
NSP_GetHostNameHeapAllocW(_Out_ WCHAR** hostname)
{
    WCHAR* name;
    HANDLE hHeap = GetProcessHeap();
    DWORD bufCharLen = MAX_COMPUTERNAME_LENGTH + 1;
    DWORD tries;

    /* A DNS host name can be longer than a computer name: retry with the size asked for.
     * The caller takes the result as a Winsock error code. */
    for (tries = 0; tries < 2; tries++)
    {
        name = HeapAlloc(hHeap, 0, (bufCharLen + 1) * sizeof(WCHAR));
        if (!name)
            return WSA_NOT_ENOUGH_MEMORY;

        if (GetComputerNameExW(ComputerNameDnsHostname, name, &bufCharLen))
        {
            *hostname = name;
            return ERROR_SUCCESS;
        }

        HeapFree(hHeap, 0, name);
        if (GetLastError() != ERROR_MORE_DATA)
            break;
    }

    return WSAEFAULT;
}

INT
NSP_GetHostByNameHeapAllocW(_In_ PWSHANDLEINTERN data,
                            _In_ DWORD dwControlFlags,
                            _Out_ PWSHOSTINFOINTERN hostinfo)
{
    HANDLE hHeap = GetProcessHeap();
    DNS_STATUS dns_status = { 0 };
    /* include/WinDNS.h -- look up DNS_RECORD on MSDN */
    PDNS_RECORDW dp;
    PDNS_RECORDW curr;
    INT result = ERROR_SUCCESS;
    DWORD dwQueryFlags = DNS_QUERY_STANDARD;
    PWCHAR Aliases[WS2_INTERNAL_MAX_ALIAS] = { 0 };
    int AliasIndex = 0;

    /* needed to be cleaned up if != NULL */
    dp = NULL;

    if (data->hostnameW == NULL)
    {
        result = ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((data->dwControlFlags & LUP_DEEP) == 0)
    {
        dwQueryFlags |= DNS_QUERY_NO_RECURSION;
    }

    /* DNS_TYPE_A: include/WinDNS.h */
    /* DnsQuery -- lib/dnsapi/dnsapi/query.c */
    dns_status = DnsQuery_W(data->hostnameW,
                            DNS_TYPE_A,
                            dwQueryFlags,
                            NULL /* extra dns servers */,
                            &dp,
                            NULL);
    if (dns_status == ERROR_INVALID_NAME)
    {
        WSASetLastError(WSAEFAULT);
        result = ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dns_status != 0) || (dp == NULL))
    {
        result = WSAHOST_NOT_FOUND;
        goto cleanup;
    }

    //ASSERT(dp->wType == DNS_TYPE_A);
    //ASSERT(dp->wDataLength == sizeof(DNS_A_DATA));

    /* The answer: the CNAME records of the chain of an alias, then every A record, in the order of the answer. The
       owners of the CNAME records are the aliases (h_aliases); the owner of the A records, the end of the chain, is
       the canonical name (h_name) */
    {
        DWORD Count = 0;

        for (curr = dp; curr != NULL; curr = curr->pNext)
        {
            if (curr->wType == DNS_TYPE_A)
                Count++;
        }

        if (Count == 0)
        {
            result = WSASERVICE_NOT_FOUND;
            goto cleanup;
        }

        hostinfo->addrs4 = HeapAlloc(hHeap, 0, Count * sizeof(DWORD));
        if (hostinfo->addrs4 == NULL)
        {
            result = WSA_NOT_ENOUGH_MEMORY;
            goto cleanup;
        }

        for (curr = dp; curr != NULL; curr = curr->pNext)
        {
            if (curr->wType == DNS_TYPE_CNAME)
            {
                if (AliasIndex < WS2_INTERNAL_MAX_ALIAS - 1)
                    Aliases[AliasIndex++] = curr->pName;
            }
            else if (curr->wType == DNS_TYPE_A)
            {
                if (hostinfo->addrCount == 0)
                    hostinfo->hostnameW = StrCpyHeapAllocW(hHeap, curr->pName);
                hostinfo->addrs4[hostinfo->addrCount++] = curr->Data.A.IpAddress;
            }
        }
    }

    hostinfo->addr4 = hostinfo->addrs4[0];
    if (AliasIndex)
    {
        hostinfo->servaliasesA = StrAryCpyHeapAllocWToA(hHeap, (WCHAR**)&Aliases);
    }
    result = ERROR_SUCCESS;

cleanup:
    if (dp != NULL)
        DnsRecordListFree(dp, DnsFreeRecordList);

    return result;
}

/* Parse a dotted-decimal IPv4 address; the result has its bytes in network order */
static
BOOLEAN
NSP_ParseIp4W(_In_ PCWSTR Text,
              _Out_ PDWORD Addr)
{
    BYTE Bytes[4];
    ULONG Part, Digits;
    INT i;

    for (i = 0; i < 4; i++)
    {
        Part = 0;
        Digits = 0;
        while (*Text >= L'0' && *Text <= L'9')
        {
            Part = Part * 10 + (*Text - L'0');
            if (++Digits > 3 || Part > 255)
                return FALSE;
            Text++;
        }
        if (Digits == 0)
            return FALSE;
        Bytes[i] = (BYTE)Part;
        if (i < 3)
        {
            if (*Text != L'.')
                return FALSE;
            Text++;
        }
    }
    if (*Text != UNICODE_NULL)
        return FALSE;

    RtlCopyMemory(Addr, Bytes, sizeof(Bytes));
    return TRUE;
}

/* Parse an IPv6 address in text form (a scope id is accepted and dropped); fails for an address no name is asked
   for: unspecified, link-local, multicast (a link-local address is only meaningful with its scope) */
static
BOOLEAN
NSP_ParseIp6W(_In_ PCWSTR Text,
              _Out_writes_bytes_(16) PBYTE Addr)
{
    SOCKADDR_IN6 Sa;
    INT Length = sizeof(Sa);
    static const BYTE Unspecified[16] = {0};

    RtlZeroMemory(&Sa, sizeof(Sa));
    if (WSAStringToAddressW((LPWSTR)Text, AF_INET6, NULL, (LPSOCKADDR)&Sa, &Length) != 0)
        return FALSE;
    RtlCopyMemory(Addr, &Sa.sin6_addr, 16);
    if (RtlEqualMemory(Addr, Unspecified, 16) ||
        (Addr[0] == 0xFE && (Addr[1] & 0xC0) == 0x80) ||
        Addr[0] == 0xFF)
        return FALSE;
    return TRUE;
}

/*
 * Look up the PTR record of a reverse name (e.g. "8.8.8.8.in-addr.arpa") and return the
 * name it points to in hostinfo->hostnameW. The query is recursive: the name servers a client is configured
 * with are resolvers, which are asked to do the work.
 */
INT
NSP_GetHostByPtrHeapAllocW(_In_ PCWSTR ReverseName,
                           _Out_ PWSHOSTINFOINTERN hostinfo)
{
    DNS_STATUS dns_status;
    PDNS_RECORDW dp = NULL;
    PDNS_RECORDW curr;
    INT result = WSAHOST_NOT_FOUND;

    dns_status = DnsQuery_W(ReverseName,
                            DNS_TYPE_PTR,
                            DNS_QUERY_STANDARD,
                            NULL,
                            &dp,
                            NULL);
    if (dns_status == ERROR_INVALID_NAME)
    {
        result = WSAEFAULT;
        goto cleanup;
    }

    if ((dns_status != 0) || (dp == NULL))
        goto cleanup;

    for (curr = dp; curr != NULL; curr = curr->pNext)
    {
        if (curr->wType == DNS_TYPE_PTR && curr->Data.PTR.pNameHost != NULL)
        {
            hostinfo->hostnameW = StrCpyHeapAllocW(GetProcessHeap(), curr->Data.PTR.pNameHost);
            result = hostinfo->hostnameW ? ERROR_SUCCESS : WSA_NOT_ENOUGH_MEMORY;
            break;
        }
    }

cleanup:
    if (dp != NULL)
        DnsRecordListFree(dp, DnsFreeRecordList);

    return result;
}

#define SKIPWS(ptr, act) \
{while(*ptr && isspace(*ptr)) ptr++; if(!*ptr) act;}

#define SKIPANDMARKSTR(ptr, act) \
{while(*ptr && !isspace(*ptr)) ptr++; \
 if(!*ptr) {act;} else { *ptr = 0; ptr++; }}

static
BOOL
DecodeServEntFromString(IN PCHAR ServiceString,
                        OUT PCHAR *ServiceName,
                        OUT PCHAR *PortNumberStr,
                        OUT PCHAR *ProtocolStr,
                        IN PCHAR *Aliases,
                        IN DWORD MaxAlias)
{
    UINT NAliases = 0;

    //WS_DbgPrint(MAX_TRACE, ("Parsing service ent [%s]\n", ServiceString));

    SKIPWS(ServiceString, return FALSE);
    *ServiceName = ServiceString;
    SKIPANDMARKSTR(ServiceString, return FALSE);
    SKIPWS(ServiceString, return FALSE);
    *PortNumberStr = ServiceString;
    SKIPANDMARKSTR(ServiceString, ;);

    while (*ServiceString && NAliases < MaxAlias - 1)
    {
        SKIPWS(ServiceString, break);
        if (*ServiceString)
        {
            SKIPWS(ServiceString, ;);
            if (strlen(ServiceString))
            {
                //WS_DbgPrint(MAX_TRACE, ("Alias: %s\n", ServiceString));
                *Aliases++ = ServiceString;
                NAliases++;
            }
            SKIPANDMARKSTR(ServiceString, ;);
        }
    }
    *Aliases = NULL;

    *ProtocolStr = strchr(*PortNumberStr, '/');

    if (!*ProtocolStr)
        return FALSE;

    **ProtocolStr = 0;
    (*ProtocolStr)++;

    //WS_DbgPrint(MAX_TRACE, ("Parsing done: %s %s %s %d\n",
    //           *ServiceName, *ProtocolStr, *PortNumberStr,
    //            NAliases));

    return TRUE;
}

HANDLE
WSAAPI
OpenNetworkDatabase(_In_ LPCWSTR Name)
{
    PWSTR ExpandedPath;
    PWSTR DatabasePath;
    INT ErrorCode;
    HKEY DatabaseKey;
    DWORD RegType;
    DWORD RegSize = 0;
    size_t StringLength;
    HANDLE ret;

    ExpandedPath = HeapAlloc(GetProcessHeap(), 0, MAX_PATH*sizeof(WCHAR));
    if (!ExpandedPath)
        return INVALID_HANDLE_VALUE;

    /* Open the database path key */
    ErrorCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                             L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                             0,
                             KEY_READ,
                             &DatabaseKey);
    if (ErrorCode == NO_ERROR)
    {
        /* Read the actual path */
        ErrorCode = RegQueryValueEx(DatabaseKey,
                                    L"DatabasePath",
                                    NULL,
                                    &RegType,
                                    NULL,
                                    &RegSize);

        DatabasePath = HeapAlloc(GetProcessHeap(), 0, RegSize);
        if (!DatabasePath)
        {
            HeapFree(GetProcessHeap(), 0, ExpandedPath);
            return INVALID_HANDLE_VALUE;
        }

        /* Read the actual path */
        ErrorCode = RegQueryValueEx(DatabaseKey,
                                    L"DatabasePath",
                                    NULL,
                                    &RegType,
                                    (LPBYTE)DatabasePath,
                                    &RegSize);

        /* Close the key */
        RegCloseKey(DatabaseKey);

        /* Expand the name */
        ExpandEnvironmentStrings(DatabasePath, ExpandedPath, MAX_PATH);

        HeapFree(GetProcessHeap(), 0, DatabasePath);
    }
    else
    {
        /* Use defalt path */
        GetSystemDirectory(ExpandedPath, MAX_PATH);
        StringCchLength(ExpandedPath, MAX_PATH, &StringLength);
        if (ExpandedPath[StringLength - 1] != L'\\')
        {
            /* It isn't, so add it ourselves */
            StringCchCat(ExpandedPath, MAX_PATH, L"\\");
        }
        StringCchCat(ExpandedPath, MAX_PATH, L"DRIVERS\\ETC\\");
    }

    /* Make sure that the path is backslash-terminated */
    StringCchLength(ExpandedPath, MAX_PATH, &StringLength);
    if (ExpandedPath[StringLength - 1] != L'\\')
    {
        /* It isn't, so add it ourselves */
        StringCchCat(ExpandedPath, MAX_PATH, L"\\");
    }

    /* Add the database name */
    StringCchCat(ExpandedPath, MAX_PATH, Name);

    /* Return a handle to the file */
    ret = CreateFile(ExpandedPath,
                      FILE_READ_DATA,
                      FILE_SHARE_READ,
                      NULL,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL);

    HeapFree(GetProcessHeap(), 0, ExpandedPath);
    return ret;
}

INT
NSP_GetServiceByNameHeapAllocW(_In_ PWSHANDLEINTERN data,
                               _In_ DWORD dwControlFlags,
                               _Out_ PWSHOSTINFOINTERN hostinfo)
{
    BOOL Found = FALSE;
    HANDLE ServicesFile;
    CHAR ServiceDBData[BUFSIZ * sizeof(WCHAR)] = {0};
    PCHAR ThisLine = 0, NextLine = 0, ServiceName = 0, PortNumberStr = 0,
    ProtocolStr = 0, Comment = 0, EndValid;
    PCHAR Aliases[WS2_INTERNAL_MAX_ALIAS] = {0};
    PCHAR* AliasPtr;
    UINT i = 0;
    DWORD ReadSize = 0;
    HANDLE hHeap;
    PCHAR nameA = NULL;
    PCHAR nameServiceA = NULL;
    PCHAR nameProtoA = NULL;
    INT res = WSANO_RECOVERY;

    if (!data->hostnameW)
    {
        res = WSANO_RECOVERY;
        goto End;
    }

    hHeap = GetProcessHeap();
    nameA = StrW2AHeapAlloc(hHeap, data->hostnameW);

    /* nameA has the form <service-name>/<protocol>
       we split these now */
    nameProtoA = strchr(nameA, '/');
    if (nameProtoA == NULL)
    {
        res = WSANO_RECOVERY;
        goto End;
    }

    nameProtoA++;
    i = (DWORD)(nameProtoA - nameA - 1);
    nameServiceA = (PCHAR)HeapAlloc(hHeap, 0, i + 1);
    StringCbCopyA(nameServiceA, i + 1, nameA);
    nameServiceA[i] = '\0';

    ServicesFile = OpenNetworkDatabase(L"services");
    if (ServicesFile == INVALID_HANDLE_VALUE)
    {
        return WSANO_RECOVERY;
    }

    /* Scan the services file ...
    *
    * We will be share the buffer on the lines. If the line does not fit in
    * the buffer, then moving it to the beginning of the buffer and read
    * the remnants of line from file.
    */

    /* Initial Read */
    ReadFile(ServicesFile,
             ServiceDBData,
             sizeof( ServiceDBData ) - 1,
             &ReadSize,
             NULL);

    ThisLine = NextLine = ServiceDBData;
    EndValid = ServiceDBData + ReadSize;
    ServiceDBData[sizeof(ServiceDBData) - 1] = '\0';

    while (ReadSize)
    {
        for (; *NextLine != '\r' && *NextLine != '\n'; NextLine++)
        {
            if (NextLine == EndValid)
            {
                int LineLen = NextLine - ThisLine;

                if (ThisLine == ServiceDBData)
                {
                    //WS_DbgPrint(MIN_TRACE,("Line too long"));
                    return WSANO_RECOVERY;
                }

                memmove(ServiceDBData, ThisLine, LineLen);

                ReadFile(ServicesFile,
                         ServiceDBData + LineLen,
                         sizeof( ServiceDBData )-1 - LineLen,
                         &ReadSize,
                         NULL);

                EndValid = ServiceDBData + LineLen + ReadSize;
                NextLine = ServiceDBData + LineLen;
                ThisLine = ServiceDBData;

                if (!ReadSize) break;
            }
        }

        *NextLine = '\0';
        Comment = strchr(ThisLine, '#');

        if (Comment)
            *Comment = '\0'; /* Terminate at comment start */

        if (DecodeServEntFromString(ThisLine,
                                    &ServiceName,
                                    &PortNumberStr,
                                    &ProtocolStr,
                                    Aliases,
                                    WS2_INTERNAL_MAX_ALIAS) &&
            (strlen(nameProtoA) == 0 || strcmp(ProtocolStr, nameProtoA) == 0))
        {
            Found = (strcmp(ServiceName, nameServiceA) == 0 || strcmp(PortNumberStr, nameServiceA) == 0);
            AliasPtr = Aliases;
            while ((!Found) && (*AliasPtr != NULL))
            {
                Found = (strcmp(*AliasPtr, nameServiceA) == 0);
                AliasPtr++;
            }
            if (Found)
                break;
        }
        NextLine++;
        ThisLine = NextLine;
    }

    /* This we'll do no matter what */
    CloseHandle(ServicesFile);

    if (!Found)
    {
        return WSANO_DATA;
    }

    hostinfo->addr4 = 0;
    hostinfo->servnameW = StrA2WHeapAlloc(hHeap, ServiceName);
    hostinfo->servprotoW = StrA2WHeapAlloc(hHeap, ProtocolStr);
    hostinfo->servaliasesA = StrAryCpyHeapAllocA(hHeap, (char**)&Aliases);
    hostinfo->servport = atoi(PortNumberStr);

    res = NO_ERROR;

End:
    if (nameA != NULL)
        HeapFree(hHeap, 0, nameA);

    if (nameServiceA != NULL)
        HeapFree(hHeap, 0, nameServiceA);

    return res;
}

/* Build the WSAQUERYSET describing current network connectivity for an NLA
 * query. On success the result carries the NLA service class, the connected
 * network's friendly name (LUP_RETURN_NAME) and an NLA_CONNECTIVITY blob
 * (LUP_RETURN_BLOB). When no network is connected we report WSA_E_NO_MORE (no
 * networks) rather than an error, which NLA-aware clients read as "offline". */
INT
NSP_BuildNLAResultW(_In_ PWSHANDLEINTERN data,
                    _Inout_ PMSW_BUFFER buf,
                    _Inout_ LPWSAQUERYSETW lpRes,
                    _Inout_ LPDWORD lpResLen)
{
    BOOL connected = FALSE;
    BOOL internet = FALSE;
    WCHAR nameW[256];
    struct
    {
        DWORD type;        /* NLA_CONNECTIVITY */
        DWORD dwSize;      /* size of the data payload */
        DWORD nextOffset;  /* 0 == last blob */
        DWORD connType;    /* NLA_NETWORK_* */
        DWORD internet;    /* NLA_INTERNET_* */
    } connBlob;

    lpRes->dwNameSpace = NS_NLA;

    (void)NlaConnectivitySignature(&connected, &internet, nameW, ARRAYSIZE(nameW));
    if (!connected)
    {
        /* No connected network -> no NLA entries to return. */
        return WSA_E_NO_MORE;
    }

    if (nameW[0] == L'\0')
        StringCchCopyW(nameW, ARRAYSIZE(nameW), L"Network");

    /* Service class id (placed into the caller buffer). */
    lpRes->lpServiceClassId = (LPGUID)mswBufferEndPtr(buf);
    if (!mswBufferAppend(buf, (void*)&guid_NLA_ServiceClass, sizeof(GUID)))
    {
        lpRes->lpServiceClassId = NULL;
        *lpResLen = buf->bytesUsed;
        return WSAEFAULT;
    }

    /* Network (friendly) name. */
    if (data->dwControlFlags & (LUP_RETURN_NAME | LUP_RETURN_ALL))
    {
        lpRes->lpszServiceInstanceName = (LPWSTR)mswBufferEndPtr(buf);
        if (!mswBufferAppendStrW(buf, nameW))
        {
            lpRes->lpszServiceInstanceName = NULL;
            *lpResLen = buf->bytesUsed;
            return WSAEFAULT;
        }
    }

    /* Connectivity blob. */
    if (data->dwControlFlags & (LUP_RETURN_BLOB | LUP_RETURN_ALL))
    {
        lpRes->lpBlob = (LPBLOB)mswBufferEndPtr(buf);
        if (!mswBufferIncUsed(buf, sizeof(*lpRes->lpBlob)))
        {
            lpRes->lpBlob = NULL;
            *lpResLen = buf->bytesUsed;
            return WSAEFAULT;
        }

        connBlob.type = NLA_CONNECTIVITY;
        connBlob.dwSize = 2 * sizeof(DWORD); /* connType + internet */
        connBlob.nextOffset = 0;
        /* Only claim internet when a default gateway (non-APIPA) is present. */
        connBlob.connType = internet ? NLA_NETWORK_MANAGED : NLA_NETWORK_UNMANAGED;
        connBlob.internet = internet ? NLA_INTERNET_YES : NLA_INTERNET_NO;

        lpRes->lpBlob->pBlobData = mswBufferEndPtr(buf);
        if (!mswBufferAppend(buf, &connBlob, sizeof(connBlob)))
        {
            lpRes->lpBlob = NULL;
            *lpResLen = buf->bytesUsed;
            return WSAEFAULT;
        }
        lpRes->lpBlob->cbSize = sizeof(connBlob);
    }

    *lpResLen = buf->bytesUsed;
    return ERROR_SUCCESS;
}

/* One attempt to build the result in the buffer given. *Overflow tells that the buffer was too small. */
static
INT
NSP_LookupServiceNextOnce(_In_ PWSHANDLEINTERN data,
                          _In_ DWORD dwControlFlags,
                          _Inout_ LPWSAQUERYSETW lpRes,
                          _Inout_ LPDWORD lpResLen,
                          _Out_ PBOOL Overflow)
{
    MSW_BUFFER buf;
    WSHOSTINFOINTERN hostinfo;
    INT result;
    HANDLE hHeap = GetProcessHeap();
    WCHAR* ServiceInstanceNameW = NULL;
    /* cleanup-vars */
    CHAR* ServiceInstanceNameA = NULL;
    CHAR* ServiceProtocolNameA = NULL;

    RtlZeroMemory(&hostinfo, sizeof(hostinfo));
    *Overflow = FALSE;

    /* init and build result-buffer */
    mswBufferInit(&buf, (BYTE*)lpRes, *lpResLen);
    mswBufferIncUsed(&buf, sizeof(*lpRes));

    /* QueryDataSet-Size without "blob-data"-size! */
    lpRes->dwSize = sizeof(*lpRes);
    lpRes->dwNameSpace = NS_DNS;

    if ((data->CallID == NSP_CALLID_HOSTNAME) ||
        (data->CallID == NSP_CALLID_HOSTBYNAME) ||
        (data->CallID == NSP_CALLID_SERVICEBYNAME) ||
        (data->CallID == NSP_CALLID_PTR) ||
        (data->CallID == NSP_CALLID_HOSTBYADDR) ||
        (data->CallID == NSP_CALLID_NLA))
    {
        if (data->CallIDCounter >= 1)
        {
            /* Windows ends a lookup with WSA_E_NO_MORE (10110), not the
             * Winsock 1 WSAENOMORE (10102) */
            result = WSA_E_NO_MORE;
            goto End;
        }
    }
    else
    {
        result = WSANO_RECOVERY;
        goto End;
    }
    data->CallIDCounter++;

    if (data->CallID == NSP_CALLID_NLA)
    {
        /* NLA connectivity result is self-contained; build it and return. */
        result = NSP_BuildNLAResultW(data, &buf, lpRes, lpResLen);
        goto End;
    }

    if (data->CallID == NSP_CALLID_HOSTNAME)
    {
        result = NSP_GetHostNameHeapAllocW(&hostinfo.hostnameW);

        if (result != ERROR_SUCCESS)
            goto End;

        hostinfo.addr4 = 0;
    }
    else if (data->CallID == NSP_CALLID_HOSTBYNAME)
    {
        result = NSP_GetHostByNameHeapAllocW(data,
                                             dwControlFlags,
                                             &hostinfo);
        if (result != ERROR_SUCCESS)
            goto End;
    }
    else if (data->CallID == NSP_CALLID_PTR)
    {
        result = NSP_GetHostByPtrHeapAllocW(data->hostnameW, &hostinfo);
        if (result != ERROR_SUCCESS)
            goto End;
    }
    else if (data->CallID == NSP_CALLID_HOSTBYADDR)
    {
        WCHAR ReverseName[80];

        /* The address in text form, as gethostbyaddr passes it */
        if (NSP_ParseIp4W(data->hostnameW, &hostinfo.addr4))
        {
            StringCchPrintfW(ReverseName, ARRAYSIZE(ReverseName), L"%u.%u.%u.%u.in-addr.arpa",
                             ((PBYTE)&hostinfo.addr4)[3], ((PBYTE)&hostinfo.addr4)[2],
                             ((PBYTE)&hostinfo.addr4)[1], ((PBYTE)&hostinfo.addr4)[0]);
        }
        else if (NSP_ParseIp6W(data->hostnameW, hostinfo.addr6))
        {
            /* nibbles, least significant first, under ip6.arpa */
            PWCHAR Out = ReverseName;
            INT n;

            hostinfo.isV6 = TRUE;
            for (n = 15; n >= 0; n--)
            {
                *Out++ = L"0123456789abcdef"[hostinfo.addr6[n] & 0xF];
                *Out++ = L'.';
                *Out++ = L"0123456789abcdef"[hostinfo.addr6[n] >> 4];
                *Out++ = L'.';
            }
            wcscpy(Out, L"ip6.arpa");
        }
        else
        {
            result = WSANO_DATA;
            goto End;
        }
        result = NSP_GetHostByPtrHeapAllocW(ReverseName, &hostinfo);
        if (result != ERROR_SUCCESS)
        {
            /* gethostbyaddr reports a missing record as WSANO_DATA */
            if (result == WSAHOST_NOT_FOUND)
                result = WSANO_DATA;
            goto End;
        }
    }
    else
    {
        ASSERT(data->CallID == NSP_CALLID_SERVICEBYNAME);
        result = NSP_GetServiceByNameHeapAllocW(data,
                                                dwControlFlags,
                                                &hostinfo);
        if (result != ERROR_SUCCESS)
            goto End;
    }

    if (((LUP_RETURN_BLOB & data->dwControlFlags) != 0) ||
        ((LUP_RETURN_NAME & data->dwControlFlags) != 0))
    {
        if (data->CallID == NSP_CALLID_HOSTNAME || data->CallID == NSP_CALLID_HOSTBYNAME ||
            data->CallID == NSP_CALLID_PTR || data->CallID == NSP_CALLID_HOSTBYADDR)
        {
            ServiceInstanceNameW = hostinfo.hostnameW;
            ServiceInstanceNameA = StrW2AHeapAlloc(hHeap, ServiceInstanceNameW);
            if (ServiceInstanceNameA == NULL)
            {
                result = WSAEFAULT;
                goto End;

            }
        }
        if (data->CallID == NSP_CALLID_SERVICEBYNAME)
        {
            ServiceInstanceNameW = hostinfo.servnameW;
            ServiceInstanceNameA = StrW2AHeapAlloc(hHeap, ServiceInstanceNameW);
            if (ServiceInstanceNameA == NULL)
            {
                result = WSAEFAULT;
                goto End;

            }
            ServiceProtocolNameA = StrW2AHeapAlloc(hHeap, hostinfo.servprotoW);
            if (ServiceProtocolNameA == NULL)
            {
                result = WSAEFAULT;
                goto End;

            }
        }
    }

    if ((LUP_RETURN_ADDR & data->dwControlFlags) != 0)
    {
        if (!mswBufferAppendAddr_AddrInfoW(&buf,
                                           lpRes,
                                           hostinfo.addrs4 ? hostinfo.addrs4 : &hostinfo.addr4,
                                           hostinfo.addrs4 ? hostinfo.addrCount : 1))
        {
            *lpResLen = buf.bytesUsed;
            result = WSAEFAULT;
            goto End;
        }
    }

    if ((LUP_RETURN_BLOB & data->dwControlFlags) != 0)
    {
        if (data->CallID == NSP_CALLID_HOSTBYNAME || data->CallID == NSP_CALLID_HOSTBYADDR)
        {
            /* Write data for PBLOB (hostent) */
            if (hostinfo.isV6 ?
                !mswBufferAppendBlob_HostentEx(&buf,
                                               lpRes,
                                               NULL,
                                               ServiceInstanceNameA,
                                               AF_INET6,
                                               sizeof(hostinfo.addr6),
                                               hostinfo.addr6,
                                               1) :
                !mswBufferAppendBlob_Hostent(&buf,
                                             lpRes,
                                             (LUP_RETURN_ALIASES & data->dwControlFlags) != 0 ? hostinfo.servaliasesA : NULL,
                                             ServiceInstanceNameA,
                                             hostinfo.addrs4 ? hostinfo.addrs4 : &hostinfo.addr4,
                                             hostinfo.addrs4 ? hostinfo.addrCount : 1))
            {
                *lpResLen = buf.bytesUsed;
                result = WSAEFAULT;
                goto End;
            }
        }
        else if (data->CallID == NSP_CALLID_SERVICEBYNAME)
        {
            /* Write data for PBLOB (servent) */
            if (!mswBufferAppendBlob_Servent(&buf,
                                             lpRes,
                                             ServiceInstanceNameA,/* ServiceName */
                                             (LUP_RETURN_ALIASES & data->dwControlFlags) != 0 ? hostinfo.servaliasesA : NULL,
                                             ServiceProtocolNameA,
                                             hostinfo.servport))
            {
                *lpResLen = buf.bytesUsed;
                result = WSAEFAULT;
                goto End;
            }
        }
        else
        {
            result = WSANO_RECOVERY;
            goto End;
        }
    }

    if ((LUP_RETURN_NAME & data->dwControlFlags) != 0)
    {
        /* HostByName sets the ServiceInstanceName to a
           (UNICODE)copy of hostent.h_name */
        lpRes->lpszServiceInstanceName = (LPWSTR)mswBufferEndPtr(&buf);
        if (!mswBufferAppendStrW(&buf, ServiceInstanceNameW))
        {
            lpRes->lpszServiceInstanceName = NULL;
            *lpResLen = buf.bytesUsed;
            result = WSAEFAULT;
            goto End;
        }
    }

    *lpResLen = buf.bytesUsed;

    result = ERROR_SUCCESS;
End:
    *Overflow = !buf.bufok;

    /* cleanup */
    if (ServiceInstanceNameA != NULL)
        HeapFree(hHeap, 0, ServiceInstanceNameA);

    if (ServiceProtocolNameA != NULL)
        HeapFree(hHeap, 0, ServiceProtocolNameA);

    if (hostinfo.hostnameW != NULL)
        HeapFree(hHeap, 0, hostinfo.hostnameW);

    if (hostinfo.addrs4 != NULL)
        HeapFree(hHeap, 0, hostinfo.addrs4);

    if (hostinfo.servnameW != NULL)
        HeapFree(hHeap, 0, hostinfo.servnameW);

    if (hostinfo.servprotoW != NULL)
        HeapFree(hHeap, 0, hostinfo.servprotoW);

    return result;
}

/* A result that did not fit the buffer is reported with the size it needs (and does not count as the one
   result of the lookup: the caller asks again with a bigger buffer). The size is found by building the result
   in scratch buffers of growing size. */
INT
NSP_LookupServiceNextW(_In_ PWSHANDLEINTERN data,
                       _In_ DWORD dwControlFlags,
                       _Inout_ LPWSAQUERYSETW lpRes,
                       _Inout_ LPDWORD lpResLen)
{
    DWORD Saved = data->CallIDCounter;
    DWORD Size, Used;
    BOOL Overflow;
    INT result;

    result = NSP_LookupServiceNextOnce(data, dwControlFlags, lpRes, lpResLen, &Overflow);
    if (result != WSAEFAULT || !Overflow)
        return result;

    data->CallIDCounter = Saved;
    Size = *lpResLen < 1024 ? 1024 : *lpResLen * 2;
    while (Size <= MSW_MAX_RESULT)
    {
        LPWSAQUERYSETW Scratch = HeapAlloc(GetProcessHeap(), 0, Size);
        INT Again;

        if (Scratch == NULL)
            break;

        Used = Size;
        Again = NSP_LookupServiceNextOnce(data, dwControlFlags, Scratch, &Used, &Overflow);
        HeapFree(GetProcessHeap(), 0, Scratch);
        data->CallIDCounter = Saved;

        if (Again == ERROR_SUCCESS)
        {
            *lpResLen = Used;
            return WSAEFAULT;
        }
        if (Again != WSAEFAULT || !Overflow)
            break;
        Size *= 2;
    }

    return WSAEFAULT;
}

/* Implementations - Exports */
/*
 * @implemented
 */
int
WINAPI
NSPStartup(_In_ LPGUID lpProviderId,
           _Out_ LPNSP_ROUTINE lpRout)
{
    INT ret;

    if ((lpRout == NULL) ||
        (lpRout->cbSize != sizeof(NSP_ROUTINE)))
    {
        WSASetLastError(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER;
    }

    mwsNSPInit();

    /* set own Provider GUID - maybe we need
       here to set the original mswsock-GUID?! */

    /* Win2k3 returns
       - Version 1.1
       - no NSPIoctl
       - sets cbSize to 44! */
    lpRout->dwMajorVersion = 1;
    lpRout->dwMinorVersion = 1;
    lpRout->cbSize = sizeof(*lpRout) - sizeof(lpRout->NSPIoctl);
    lpRout->NSPCleanup = &mwsNSPCleanUp;
    lpRout->NSPLookupServiceBegin = &mwsNSPLookupServiceBegin;
    lpRout->NSPLookupServiceNext = &mwsNSPLookupServiceNext;
    lpRout->NSPLookupServiceEnd = &mwsNSPLookupServiceEnd;
    lpRout->NSPSetService = &mwsNSPSetService;
    lpRout->NSPInstallServiceClass = &mwsNSPInstallServiceClass;
    lpRout->NSPRemoveServiceClass = &mwsNSPRemoveServiceClass;
    lpRout->NSPGetServiceClassInfo = &mwsNSPGetServiceClassInfo;
    lpRout->NSPIoctl = NULL;// &mwsNSPIoCtl;

    /* The NLA provider additionally supports SIO_NSP_NOTIFY_CHANGE (used by
     * NLA-aware clients to be woken on connectivity change). Advertise the full
     * routine table incl. NSPIoctl only for it, so the DNS (TcpIp) provider's
     * v1 behaviour is unchanged. */
    if ((lpProviderId != NULL) && IsEqualGUID(lpProviderId, &guid_mswsock_NLA))
    {
        lpRout->cbSize = sizeof(*lpRout);
        lpRout->NSPIoctl = &mwsNSPIoCtl;
    }

    ret = NO_ERROR;

    return ret;
}
