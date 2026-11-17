/*
 * PROJECT:     ReactOS Shell
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     What the TCP/IP stack does on a connection (the TCP/IPv4 and TCP/IPv6 rows of its component list)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Its own file: GetAdaptersAddresses needs winsock2.h, and the precompiled header of netshell has winsock.h.
 */

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <objbase.h>
#include <iphlpapi.h>

/*
 * TCP/IPv4 is there when the stack has an interface for the adapter (NDIS bound it: Tcpip\Linkage), TCP/IPv6 when
 * that interface has IPv6 (IP_ADAPTER_IPV6_ENABLED: off with Tcpip6\Parameters\DisabledComponents 0x10 or
 * Tcpip\Parameters\Ipv6Enable = 0). S_FALSE: the stack has no interface for the adapter (not started, disabled), so
 * nothing is known.
 */
HRESULT
GetStackProtocols(
    const GUID *pAdapter,
    BOOL *pbIpv4,
    BOOL *pbIpv6)
{
    WCHAR szGuid[40];
    CHAR szName[40];
    PIP_ADAPTER_ADDRESSES pList = NULL, pEntry;
    ULONG Size = 16 * 1024, Error = ERROR_BUFFER_OVERFLOW, Try;
    HRESULT hr = S_FALSE;

    *pbIpv4 = *pbIpv6 = FALSE;
    if (!StringFromGUID2(pAdapter, szGuid, ARRAYSIZE(szGuid)) ||
        !WideCharToMultiByte(CP_ACP, 0, szGuid, -1, szName, sizeof(szName), NULL, NULL))
        return E_FAIL;

    for (Try = 0; Try < 4 && Error == ERROR_BUFFER_OVERFLOW; Try++)
    {
        if (pList)
            HeapFree(GetProcessHeap(), 0, pList);
        pList = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!pList)
            return E_OUTOFMEMORY;
        Error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                     GAA_FLAG_SKIP_DNS_SERVER, NULL, pList, &Size);
    }

    if (Error == ERROR_SUCCESS)
    {
        for (pEntry = pList; pEntry; pEntry = pEntry->Next)
        {
            if (pEntry->AdapterName && !lstrcmpiA(pEntry->AdapterName, szName))
            {
                *pbIpv4 = TRUE;
                *pbIpv6 = (pEntry->Flags & IP_ADAPTER_IPV6_ENABLED) ? TRUE : FALSE;
                hr = S_OK;
                break;
            }
        }
    }
    else if (Error != ERROR_NO_DATA)
    {
        hr = HRESULT_FROM_WIN32(Error);
    }

    if (pList)
        HeapFree(GetProcessHeap(), 0, pList);
    return hr;
}
