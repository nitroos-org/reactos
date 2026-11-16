/*
 * PROJECT:     ReactOS DNS Resolver
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/services/dnsrslvr/rpcserver.c
 * PURPOSE:     RPC server interface
 * COPYRIGHT:   Copyright 2016 Christoph von Wittich
 */

#include "precomp.h"
#include <iphlpapi.h>

#define NDEBUG
#include <debug.h>

static BOOL RpcRegistered = FALSE;

/* The service can share its process (svchost -k NetworkService) with other services: its interface listens on its
   own (auto-listen), so no service of the process starts or stops the listening of the others. It is registered
   before the service reports that it runs. */
VOID
StartRpcServer(VOID)
{
    RPC_STATUS Status;

    Status = RpcServerUseProtseqEpW(L"ncalrpc", 20, L"DNSResolver", NULL);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcServerUseProtseqEpW() failed (Status %lx)\n", Status);
        return;
    }

    Status = RpcServerRegisterIfEx(DnsResolver_v2_0_s_ifspec, NULL, NULL, RPC_IF_AUTOLISTEN,
                                   RPC_C_LISTEN_MAX_CALLS_DEFAULT, NULL);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcServerRegisterIfEx() failed (Status %lx)\n", Status);
        return;
    }

    RpcRegistered = TRUE;
}

/* The service stops: only its interface goes, once the calls in it have returned (the cache is freed next) */
VOID
StopRpcServer(VOID)
{
    if (RpcRegistered)
    {
        RpcServerUnregisterIf(DnsResolver_v2_0_s_ifspec, NULL, TRUE);
        RpcRegistered = FALSE;
    }
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

/*
 * Does the name belong to this machine (localhost, the host name, the host name with the DNS domain, with or
 * without the dot of the root label)? Dnsapi answers such a name itself, and what it answers changes with the
 * network (an address that comes, an adapter that goes): it is not kept as a negative answer.
 */
static
BOOL
IsOwnName(
    _In_ LPCWSTR Name)
{
    CHAR Ansi[512], Local[sizeof(((PFIXED_INFO)0)->HostName) + sizeof(((PFIXED_INFO)0)->DomainName) + 2];
    PFIXED_INFO Info;
    ULONG Size = 0;
    size_t Len;
    BOOL Ret = FALSE;

    if (WideCharToMultiByte(CP_ACP, 0, Name, -1, Ansi, sizeof(Ansi), NULL, NULL) == 0)
        return FALSE;
    Len = strlen(Ansi);
    if (Len > 1 && Ansi[Len - 1] == '.')
        Ansi[Len - 1] = '\0';
    if (Ansi[0] == '\0' || _stricmp(Ansi, "localhost") == 0)
        return TRUE;

    GetNetworkParams(NULL, &Size);
    Info = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Info == NULL)
        return TRUE; /* out of memory: keep nothing */
    if (GetNetworkParams(Info, &Size) == ERROR_SUCCESS)
    {
        if (_stricmp(Ansi, Info->HostName) == 0)
        {
            Ret = TRUE;
        }
        else if (Info->DomainName[0])
        {
            StringCchPrintfA(Local, sizeof(Local), "%s.%s", Info->HostName, Info->DomainName);
            Ret = _stricmp(Ansi, Local) == 0;
        }
    }
    HeapFree(GetProcessHeap(), 0, Info);
    return Ret;
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
        if (Status == DNSRSLVR_CACHE_MISS)
        {
            Status = DNS_INFO_NO_RECORDS;

            /* The names that need no server (localhost, this machine) have an IPv6 answer that is not in the cache */
            if (wType == DNS_TYPE_AAAA)
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
    }
    else
    {
        DPRINT("DNS cache query!\n");
        Status = DnsIntCacheGetEntryByName(pszName,
                                           wType,
                                           dwFlags,
                                           ppResultRecords);
        if (Status == DNSRSLVR_CACHE_MISS)
        {
            /*
             * A name of the hosts file is answered from it alone: a DNS server is not asked for another type
             * of it (the machine's own answer for the AAAA of "localhost" is the exception, see Query_Main).
             */
            if (_wcsicmp(pszName, L"localhost") == 0 ||
                _wcsicmp(pszName, L"localhost.") == 0 ||
                !DnsIntCacheHasHostsName(pszName))
            {
                DPRINT("DNS query!\n");
                Status = Query_Main(pszName,
                                    wType,
                                    dwFlags,
                                    ppResultRecords);
                if (Status == ERROR_SUCCESS)
                {
                    DPRINT("DNS query successful!\n");
                    /* kept for the time its records say (not at all with a TTL of 0) */
                    DnsIntCacheAddResult(*ppResultRecords);
                }
                else if (!IsOwnName(pszName))
                {
                    /* a name that is not there (or has no record of the type) is kept for a while, other
                       failures (no server, no answer) are asked again */
                    DnsIntCacheAddNegative(pszName,
                                           wType,
                                           Status,
                                           (dwFlags & (DNS_QUERY_NO_RECURSION | DNS_QUERY_TREAT_AS_FQDN)) != 0);
                }
            }
            else
            {
                Status = DNS_INFO_NO_RECORDS;
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
