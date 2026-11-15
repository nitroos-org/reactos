/*
 * PROJECT:     ReactOS DNS Resolver
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/services/dnsrslvr/rpcserver.c
 * PURPOSE:     RPC server interface
 * COPYRIGHT:   Copyright 2016 Christoph von Wittich
 */

#include "precomp.h"

#define NDEBUG
#include <debug.h>

DWORD
WINAPI
RpcThreadRoutine(LPVOID lpParameter)
{
    RPC_STATUS Status;

    Status = RpcServerUseProtseqEpW(L"ncalrpc", 20, L"DNSResolver", NULL);
    if (Status != RPC_S_OK)
    {
        DPRINT("RpcServerUseProtseqEpW() failed (Status %lx)\n", Status);
        return 0;
    }

    Status = RpcServerRegisterIf(DnsResolver_v2_0_s_ifspec, NULL, NULL);
    if (Status != RPC_S_OK)
    {
        DPRINT("RpcServerRegisterIf() failed (Status %lx)\n", Status);
        return 0;
    }

    Status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, 0);
    if (Status != RPC_S_OK)
    {
        DPRINT("RpcServerListen() failed (Status %lx)\n", Status);
    }

    DPRINT("RpcServerListen finished\n");
    return 0;
}


/* Function: 0x00 */
DWORD
__stdcall
CRrReadCache(
    _In_ DNSRSLVR_HANDLE pwszServerName,
    _Out_ DNS_CACHE_ENTRY **ppCacheEntries)
{
    DPRINT("CRrReadCache(%S %p)\n",
           pwszServerName, ppCacheEntries);

    return DnsIntCacheGetEntries(ppCacheEntries);
}


/* Function: 0x04 */
DWORD
__stdcall
R_ResolverFlushCache(
    _In_ DNSRSLVR_HANDLE pszServerName)
{
    DPRINT("R_ResolverFlushCache(%S)\n",
           pszServerName);

    return DnsIntCacheFlush(CACHE_FLUSH_NON_HOSTS_FILE_ENTRIES);
}


/* Function: 0x05 */
DWORD
__stdcall
R_ResolverFlushCacheEntry(
    _In_ DNSRSLVR_HANDLE pszServerName,
    _In_ LPCWSTR pszName,
    _In_ WORD wType)
{
    DPRINT("R_ResolverFlushCacheEntry(%S %S %x)\n",
           pszServerName, pszName, wType);

    if (pszName == NULL)
        return ERROR_INVALID_PARAMETER;

    return DnsIntFlushCacheEntry(pszName, wType);
}


/* The arm of a text record in the union of the RPC (DNS_TXT_WIRE_DATAW of windns.h in the MIDL view) */
typedef struct
{
    DWORD dwStringCount;
    PWSTR *pStringArray;
} TEXT_WIRE_DATA;

/*
 * A text record holds the pointers to its strings in an array inside the record (sized by the string count); a union
 * arm of the RPC cannot describe that, so the wire layout has a pointer to a separate array in the first slot. Every
 * text record of the list is switched to it, just before the stub marshals the list (and frees it, the array and the
 * strings with it). Returns ERROR_OUTOFMEMORY, with the list as it was, when an array cannot be allocated.
 */
static
DWORD
TextRecordsToWire(
    _In_ PDNS_RECORDW List)
{
    PDNS_RECORDW Record, Undo;
    TEXT_WIRE_DATA *Wire;
    PWSTR *Array;
    DWORD Count;

    for (Record = List; Record; Record = Record->pNext)
    {
        if (Record->wType != DNS_TYPE_TEXT)
            continue;

        Count = Record->Data.TXT.dwStringCount;
        Array = NULL;
        if (Count != 0)
        {
            Array = midl_user_allocate(Count * sizeof(PWSTR));
            if (Array == NULL)
            {
                /* switch the records back */
                for (Undo = List; Undo != Record; Undo = Undo->pNext)
                {
                    if (Undo->wType != DNS_TYPE_TEXT)
                        continue;
                    Wire = (TEXT_WIRE_DATA *)&Undo->Data;
                    Array = Wire->pStringArray;
                    if (Array)
                    {
                        Undo->Data.TXT.pStringArray[0] = Array[0];
                        midl_user_free(Array);
                    }
                }
                return ERROR_OUTOFMEMORY;
            }
            CopyMemory(Array, Record->Data.TXT.pStringArray, Count * sizeof(PWSTR));
        }

        Wire = (TEXT_WIRE_DATA *)&Record->Data;
        Wire->pStringArray = Array;
    }

    return ERROR_SUCCESS;
}

/* Function: 0x07 */
DWORD
__stdcall
R_ResolverQuery(
    _In_ DNSRSLVR_HANDLE pszServerName,
    _In_ LPCWSTR pszName,
    _In_ WORD wType,
    _In_ DWORD dwFlags,
    _Inout_ DWORD *dwRecords,
    _Out_ DNS_RECORDW **ppResultRecords)
{
    PDNS_RECORDW Record;
    DNS_STATUS Status = ERROR_SUCCESS;

    DPRINT("R_ResolverQuery(%S %S %x %lx %p %p)\n",
           pszServerName, pszName, wType, dwFlags, dwRecords, ppResultRecords);

    if (pszName == NULL || wType == 0 || ppResultRecords == NULL)
        return ERROR_INVALID_PARAMETER;

    if ((dwFlags & DNS_QUERY_WIRE_ONLY) != 0 && (dwFlags & DNS_QUERY_NO_WIRE_QUERY) != 0)
        return ERROR_INVALID_PARAMETER;

    /* The hosts file may have been edited since the last query */
    HostsFileReloadIfChanged();

    if (dwFlags & DNS_QUERY_WIRE_ONLY)
    {
        DPRINT("DNS query!\n");
        Status = Query_Main(pszName,
                            wType,
                            dwFlags,
                            ppResultRecords);
    }
    else if (dwFlags & DNS_QUERY_NO_WIRE_QUERY)
    {
        DPRINT("DNS cache query!\n");
        Status = DnsIntCacheGetEntryByName(pszName,
                                           wType,
                                           dwFlags,
                                           ppResultRecords);
        /* The names that need no server (localhost, this machine) have an IPv6 answer that is not in the cache */
        if (Status == DNS_INFO_NO_RECORDS && wType == DNS_TYPE_AAAA)
        {
            if (Query_Main(pszName,
                           wType,
                           dwFlags,
                           ppResultRecords) != ERROR_SUCCESS)
            {
                *ppResultRecords = NULL;
            }
            else
            {
                Status = ERROR_SUCCESS;
            }
        }
    }
    else
    {
        DPRINT("DNS cache query!\n");
        Status = DnsIntCacheGetEntryByName(pszName,
                                           wType,
                                           dwFlags,
                                           ppResultRecords);
        /*
         * A name of the hosts file is answered from it alone: a DNS server is not asked for another type
         * of it (the machine's own answer for the AAAA of "localhost" is the exception, see Query_Main).
         */
        if (Status == DNS_INFO_NO_RECORDS &&
            (_wcsicmp(pszName, L"localhost") == 0 ||
             _wcsicmp(pszName, L"localhost.") == 0 ||
             !DnsIntCacheHasHostsName(pszName)))
        {
            DPRINT("DNS query!\n");
            Status = Query_Main(pszName,
                                wType,
                                dwFlags,
                                ppResultRecords);
            if (Status == ERROR_SUCCESS)
            {
                DPRINT("DNS query successful!\n");
                DnsIntCacheAddEntry(*ppResultRecords, FALSE);
            }
        }
    }

    if (dwRecords)
    {
        *dwRecords = 0;

        if (Status == ERROR_SUCCESS)
        {
            Record = *ppResultRecords;
            while (Record)
            {
                DPRINT("Record: %S\n", Record->pName);
                (*dwRecords)++;
                Record = Record->pNext;
            }
        }
    }

    /* The text records go over the RPC in their wire layout (the caller of this function has the API layout) */
    if (Status == ERROR_SUCCESS && *ppResultRecords != NULL)
    {
        Status = TextRecordsToWire(*ppResultRecords);
        if (Status != ERROR_SUCCESS)
        {
            DnsRecordListFree(*ppResultRecords, DnsFreeRecordList);
            *ppResultRecords = NULL;
            if (dwRecords)
                *dwRecords = 0;
        }
    }

    DPRINT("R_ResolverQuery result %ld %ld\n", Status, dwRecords ? *dwRecords : 0);

    return Status;
}

void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
}

void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

void __RPC_USER DNSRSLVR_RPC_HANDLE_rundown(DNSRSLVR_HANDLE hClientHandle)
{
}
