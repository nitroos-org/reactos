/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS system libraries
 * FILE:        lib/dnsapi/dnsapi/query.c
 * PURPOSE:     DNSAPI functions built on the ADNS library.
 * PROGRAMER:   Art Yerkes
 * UPDATE HISTORY:
 *              12/15/03 -- Created
 */

#include "precomp.h"
#include <winreg.h>
#include <iphlpapi.h>
#include <strsafe.h>
#include <time.h>
#include <winioctl.h>
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <tcpioctl.h>

#define NDEBUG
#include <debug.h>

static
BOOL
ParseIpv4Address(
    _In_ PCWSTR AddressString,
    _Out_ PIN_ADDR pAddress)
{
    PCWSTR pTerminator = NULL;
    NTSTATUS Status;

    Status = RtlIpv4StringToAddressW(AddressString,
                                     TRUE,
                                     &pTerminator,
                                     pAddress);
    if (NT_SUCCESS(Status) && pTerminator != NULL && *pTerminator == L'\0')
        return TRUE;

    return FALSE;
}


static
BOOL
ParseIpv6Address(
    _In_ PCWSTR AddressString,
    _Out_ PIN6_ADDR pAddress)
{
    PCWSTR pTerminator = NULL;
    NTSTATUS Status;

    Status = RtlIpv6StringToAddressW(AddressString,
                                     &pTerminator,
                                     pAddress);
    if (NT_SUCCESS(Status) && pTerminator != NULL && *pTerminator == L'\0')
        return TRUE;

    return FALSE;
}


static
PDNS_RECORDW
CreateRecordForIpAddress(
    _In_ PCWSTR Name,
    _In_ WORD Type)
{
    IN_ADDR Ip4Address;
    IN6_ADDR Ip6Address;
    PDNS_RECORDW pRecord = NULL;

    if (Type == DNS_TYPE_A)
    {
        if (ParseIpv4Address(Name, &Ip4Address))
        {
            pRecord = RtlAllocateHeap(RtlGetProcessHeap(),
                                      HEAP_ZERO_MEMORY,
                                      sizeof(DNS_RECORDW));
            if (pRecord == NULL)
                return NULL;

            pRecord->pName = RtlAllocateHeap(RtlGetProcessHeap(),
                                             0,
                                             (wcslen(Name) + 1) * sizeof(WCHAR));
            if (pRecord == NULL)
            {
                RtlFreeHeap(RtlGetProcessHeap(), 0, pRecord);
                return NULL;
            }

            wcscpy(pRecord->pName, Name);
            pRecord->wType = DNS_TYPE_A;
            pRecord->wDataLength = sizeof(DNS_A_DATA);
            pRecord->Flags.S.Section = DnsSectionQuestion;
            pRecord->Flags.S.CharSet = DnsCharSetUnicode;
            pRecord->dwTtl = 7 * 24 * 60 * 60;

            pRecord->Data.A.IpAddress = Ip4Address.S_un.S_addr;

            return pRecord;
        }
    }
    else if (Type == DNS_TYPE_AAAA)
    {
        if (ParseIpv6Address(Name, &Ip6Address))
        {
            pRecord = RtlAllocateHeap(RtlGetProcessHeap(),
                                      HEAP_ZERO_MEMORY,
                                      sizeof(DNS_RECORDW));
            if (pRecord == NULL)
                return NULL;

            pRecord->pName = RtlAllocateHeap(RtlGetProcessHeap(),
                                             0,
                                             (wcslen(Name) + 1) * sizeof(WCHAR));
            if (pRecord == NULL)
            {
                RtlFreeHeap(RtlGetProcessHeap(), 0, pRecord);
                return NULL;
            }

            wcscpy(pRecord->pName, Name);
            pRecord->wType = DNS_TYPE_AAAA;
            pRecord->wDataLength = sizeof(DNS_AAAA_DATA);
            pRecord->Flags.S.Section = DnsSectionQuestion;
            pRecord->Flags.S.CharSet = DnsCharSetUnicode;
            pRecord->dwTtl = 7 * 24 * 60 * 60;

            CopyMemory(&pRecord->Data.AAAA.Ip6Address,
                       &Ip6Address.u.Byte,
                       sizeof(IN6_ADDR));

            return pRecord;
        }
    }

    return NULL;
}


/* The domains of a space separated search list, as GetAdaptersAddresses gives them for an adapter */
typedef struct _DNSAPI_ADAPTER_ADDRESSES_W7
{
    IP_ADAPTER_ADDRESSES_LH Lh;
    PIP_ADAPTER_DNS_SUFFIX FirstDnsSuffix;
} DNSAPI_ADAPTER_ADDRESSES_W7;

static
BOOL
DomainInList(PCSTR List, PCSTR Domain)
{
    SIZE_T Length = strlen(Domain);

    while (*List)
    {
        SIZE_T Part = strcspn(List, " ");

        if (Part == Length && _strnicmp(List, Domain, Length) == 0)
            return TRUE;
        List += Part;
        while (*List == ' ')
            List++;
    }
    return FALSE;
}

#define V6CFG_MAX_SERVERS   16
#define V6CFG_SUFFIX_SIZE   1024
/* A change notification can miss what a router advertisement alone changes: the cache expires anyway */
#define V6CFG_MAX_AGE_MS    10000

/* The IPv6 name servers and search domains of the adapters, as of one GetAdaptersAddresses call */
typedef struct _V6CONFIG
{
    ULONG ServerCount;
    struct
    {
        IN6_ADDR Address;
        ULONG ScopeId;
    } Servers[V6CFG_MAX_SERVERS];
    CHAR Suffixes[V6CFG_SUFFIX_SIZE];   /* space separated, each once */
} V6CONFIG, *PV6CONFIG;

static CRITICAL_SECTION g_V6Lock;
static BOOL g_V6LockInit;
static V6CONFIG g_V6Cache;
static BOOL g_V6CacheValid;
static DWORD g_V6CacheTick;
static HANDLE g_V6ChangeEvent;      /* signalled by the address change notification */
static HANDLE g_V6ChangeFile;       /* \Device\Tcp, which the notification is asked of */
static IO_STATUS_BLOCK g_V6ChangeIosb;
static BOOL g_V6ChangeArmed;

VOID DnsapiV6CacheInit(VOID);
VOID DnsapiV6CacheCleanup(VOID);

VOID
DnsapiV6CacheInit(VOID)
{
    InitializeCriticalSection(&g_V6Lock);
    g_V6LockInit = TRUE;
}

/* The DLL is unloaded: end the pending notification request, which a later address change would complete into
   memory of the DLL */
VOID
DnsapiV6CacheCleanup(VOID)
{
    if (!g_V6LockInit)
        return;

    if (g_V6ChangeArmed)
    {
        IO_STATUS_BLOCK Iosb;

        /* the request completes with STATUS_CANCELLED and signals the event */
        if (NT_SUCCESS(NtDeviceIoControlFile(g_V6ChangeFile, NULL, NULL, NULL, &Iosb, IOCTL_IP_ADDCHANGE_CANCEL_REQUEST,
                                             NULL, 0, NULL, 0)) && g_V6ChangeEvent)
            WaitForSingleObject(g_V6ChangeEvent, 1000);
        g_V6ChangeArmed = FALSE;
    }
    if (g_V6ChangeFile)
    {
        NtClose(g_V6ChangeFile);
        g_V6ChangeFile = NULL;
    }
    if (g_V6ChangeEvent)
    {
        CloseHandle(g_V6ChangeEvent);
        g_V6ChangeEvent = NULL;
    }
    DeleteCriticalSection(&g_V6Lock);
    g_V6LockInit = FALSE;
}

/*
 * The IPv6 name servers of the adapters (configured ones and those of router advertisements: iphlpapi's
 * GetAdaptersAddresses lists them with the IPv6 family) and the search domains of their router advertisements.
 * Without IPv6 (the switch off) GetAdaptersAddresses has nothing for the IPv6 family and the result is empty.
 */
static
VOID
CollectIpv6Config(PV6CONFIG Config)
{
    PIP_ADAPTER_ADDRESSES Addresses = NULL, Adapter;
    PIP_ADAPTER_DNS_SERVER_ADDRESS Server;
    ULONG Size = 16 * 1024, Pass;
    DWORD Error = ERROR_BUFFER_OVERFLOW;

    RtlZeroMemory(Config, sizeof(*Config));

    for (Pass = 0; Pass < 3 && Error == ERROR_BUFFER_OVERFLOW; Pass++)
    {
        if (Addresses)
            RtlFreeHeap(RtlGetProcessHeap(), 0, Addresses);
        Addresses = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
        if (!Addresses)
            return;
        Error = GetAdaptersAddresses(AF_INET6,
                                     GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                     NULL, Addresses, &Size);
    }

    for (Adapter = (Error == ERROR_SUCCESS) ? Addresses : NULL; Adapter; Adapter = Adapter->Next)
    {
        if (Adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || Adapter->OperStatus != IfOperStatusUp)
            continue;

        for (Server = Adapter->FirstDnsServerAddress; Server; Server = Server->Next)
        {
            const SOCKADDR_IN6 *Sa = (const SOCKADDR_IN6 *)Server->Address.lpSockaddr;

            if (Sa && Sa->sin6_family == AF_INET6 && Config->ServerCount < V6CFG_MAX_SERVERS)
            {
                Config->Servers[Config->ServerCount].Address = Sa->sin6_addr;
                Config->Servers[Config->ServerCount].ScopeId = Sa->sin6_scope_id;
                Config->ServerCount++;
            }
        }

        /* the DNS search domains its router advertisements gave (DNSSL): FirstDnsSuffix follows the last member
           of IP_ADAPTER_ADDRESSES_LH, which the headers of this tree stop before */
        if (Adapter->Length >= sizeof(DNSAPI_ADAPTER_ADDRESSES_W7))
        {
            PIP_ADAPTER_DNS_SUFFIX Suffix;

            for (Suffix = ((DNSAPI_ADAPTER_ADDRESSES_W7 *)Adapter)->FirstDnsSuffix; Suffix; Suffix = Suffix->Next)
            {
                CHAR Text[MAX_DNS_SUFFIX_STRING_LENGTH];
                SIZE_T Length;

                if (!WideCharToMultiByte(CP_ACP, 0, Suffix->String, -1, Text, sizeof(Text), NULL, NULL) || !Text[0])
                    continue;
                Length = strlen(Config->Suffixes);
                if (DomainInList(Config->Suffixes, Text) ||
                    Length + (Length ? 1 : 0) + strlen(Text) + 1 > sizeof(Config->Suffixes))
                    continue;
                if (Length)
                    Config->Suffixes[Length++] = ' ';
                strcpy(Config->Suffixes + Length, Text);
            }
        }
    }

    if (Addresses)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Addresses);
}

/*
 * Lock held. Ask the stack to signal g_V6ChangeEvent at the next change of the IPv4 or the IPv6 address table.
 * NotifyAddrChange waits for IPv4 changes alone (as on Windows), so the request is made here with both families:
 * the IPv6 name servers come and go with the IPv6 configuration of the adapters. FALSE: no request is pending.
 */
static
BOOL
ArmV6Change(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(DD_TCP_DEVICE_NAME);
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    ULONG Families = TCP_CHANGE_FAMILY_IPV4 | TCP_CHANGE_FAMILY_IPV6;
    NTSTATUS Status;

    if (!g_V6ChangeFile)
    {
        /* an asynchronous handle: the request stays pending in the driver */
        InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtOpenFile(&g_V6ChangeFile, FILE_READ_DATA | SYNCHRONIZE, &Attributes, &Iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
        if (!NT_SUCCESS(Status))
        {
            g_V6ChangeFile = NULL;
            return FALSE;
        }
    }

    Status = NtDeviceIoControlFile(g_V6ChangeFile, g_V6ChangeEvent, NULL, NULL, &g_V6ChangeIosb,
                                   IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST, &Families, sizeof(Families), NULL, 0);
    return Status == STATUS_PENDING;
}

/*
 * Copy the IPv6 configuration into Config: from the cache while no address change was signalled and it is
 * young, else collected again (the notification is armed before the collection so that no change in between
 * is lost). Where the notification cannot be had every call collects, as before the cache.
 */
static
VOID
GetIpv6Config(PV6CONFIG Config)
{
    DWORD Now = GetTickCount();
    BOOL Changed;

    if (!g_V6LockInit)
    {
        CollectIpv6Config(Config);
        return;
    }

    EnterCriticalSection(&g_V6Lock);

    if (!g_V6ChangeEvent)
        g_V6ChangeEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    Changed = !g_V6ChangeEvent || WaitForSingleObject(g_V6ChangeEvent, 0) != WAIT_TIMEOUT;

    if (g_V6CacheValid && g_V6ChangeArmed && !Changed && (DWORD)(Now - g_V6CacheTick) < V6CFG_MAX_AGE_MS)
    {
        *Config = g_V6Cache;
        LeaveCriticalSection(&g_V6Lock);
        return;
    }

    if (g_V6ChangeEvent && (!g_V6ChangeArmed || Changed))
    {
        ResetEvent(g_V6ChangeEvent);
        g_V6ChangeArmed = ArmV6Change();
    }

    CollectIpv6Config(&g_V6Cache);
    g_V6CacheValid = TRUE;
    g_V6CacheTick = Now;
    *Config = g_V6Cache;

    LeaveCriticalSection(&g_V6Lock);
}

/*
 * Add the IPv6 name servers of the adapters after the IPv4 servers that GetNetworkParams gave, so that they are
 * asked first and the IPv6 ones only when there is no IPv4 server or it does not answer, and the search domains
 * of their router advertisements to Search.
 */
static
VOID
AddIpv6Servers(adns_state astate, PCHAR Search, SIZE_T SearchSize)
{
    V6CONFIG Config;
    ULONG i;

    GetIpv6Config(&Config);

    for (i = 0; i < Config.ServerCount; i++)
        adns_addserver6(astate, &Config.Servers[i].Address, Config.Servers[i].ScopeId);

    if (Search && Config.Suffixes[0])
    {
        PCHAR Token = Config.Suffixes;

        while (*Token)
        {
            SIZE_T Part = strcspn(Token, " "), Length;
            CHAR Text[MAX_DNS_SUFFIX_STRING_LENGTH];

            if (Part < sizeof(Text))
            {
                memcpy(Text, Token, Part);
                Text[Part] = 0;
                Length = strlen(Search);
                /* each domain once (the list is searched in order), and only while it fits */
                if (!DomainInList(Search, Text) && Length + (Length ? 1 : 0) + Part + 1 <= SearchSize)
                {
                    if (Length)
                        Search[Length++] = ' ';
                    strcpy(Search + Length, Text);
                }
            }
            Token += Part;
            while (*Token == ' ')
                Token++;
        }
    }
}

/* DnsQuery ****************************
 * Begin a DNS query, and allow the result to be placed in the application
 * supplied result pointer.  The result can be manipulated with the record
 * functions.
 *
 * Name                 -- The DNS object to be queried.
 * Type                 -- The type of records to be returned.  These are
 *                          listed in windns.h
 * Options              -- Query options.  DNS_QUERY_STANDARD is the base
 *                          state, and every other option takes precedence.
 *                          multiple options can be combined.  Listed in
 *                          windns.h
 * Servers              -- List of alternate servers (optional)
 * QueryResultSet       -- Pointer to the result pointer that will be filled
 *                          when the response is available.
 * Reserved             -- Response as it appears on the wire.  Optional.
 */

static PWCHAR
DnsCToW(const CHAR *NarrowString)
{
    PWCHAR WideString;
    int WideLen = MultiByteToWideChar(CP_ACP,
                                      0,
                                      NarrowString,
                                      -1,
                                      NULL,
                                      0);
    if (WideLen == 0)
        return NULL;
    WideString = RtlAllocateHeap(RtlGetProcessHeap(), 0, WideLen * sizeof(WCHAR));
    if (WideString == NULL)
    {
        return NULL;
    }
    MultiByteToWideChar(CP_ACP,
                        0,
                        NarrowString,
                        -1,
                        WideString,
                        WideLen);

    return WideString;
}

static PWCHAR
DnsUTF8ToW(const CHAR *NarrowString)
{
    PWCHAR WideString;
    int WideLen = MultiByteToWideChar(CP_UTF8,
                                      0,
                                      NarrowString,
                                      -1,
                                      NULL,
                                      0);
    if (WideLen == 0)
        return NULL;
    WideString = RtlAllocateHeap(RtlGetProcessHeap(), 0, WideLen * sizeof(WCHAR));
    if (WideString == NULL)
    {
        return NULL;
    }
    MultiByteToWideChar(CP_UTF8,
                        0,
                        NarrowString,
                        -1,
                        WideString,
                        WideLen);

    return WideString;
}

DNS_STATUS WINAPI
DnsQuery_CodePage(UINT CodePage,
           LPCSTR Name,
           WORD Type,
           DWORD Options,
           PVOID Extra,
           PDNS_RECORD *QueryResultSet,
           PVOID *Reserved)
{
    PWCHAR Buffer;
    DNS_STATUS Status;
    DNS_CHARSET OutCharSet;
    PDNS_RECORD QueryResultWide = NULL, WideRecord;
    PDNS_RECORD ConvertedRecord, FirstRecord = NULL, LastRecord = NULL;

    if (Name == NULL)
        return ERROR_INVALID_PARAMETER;
    if (QueryResultSet == NULL)
        return ERROR_INVALID_PARAMETER;

    switch (CodePage)
    {
    case CP_ACP:
        Buffer = DnsCToW(Name);
        OutCharSet = DnsCharSetAnsi;
        break;

    case CP_UTF8:
        Buffer = DnsUTF8ToW(Name);
        OutCharSet = DnsCharSetUtf8;
        break;

    default:
        return ERROR_INVALID_PARAMETER;
    }

    *QueryResultSet = NULL;

    Status = DnsQuery_W(Buffer, Type, Options, Extra, &QueryResultWide, Reserved);

    /* The name */
    if (Buffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);

    if (Status != ERROR_SUCCESS)
        return Status;

    /*
     * Every record of the wide result is deep-copied into the requested
     * character set, whatever its type (DnsRecordCopyEx knows the layout of
     * every record type that holds strings).
     */
    for (WideRecord = QueryResultWide; WideRecord; WideRecord = WideRecord->pNext)
    {
        ConvertedRecord = DnsRecordCopyEx(WideRecord, DnsCharSetUnicode, OutCharSet);
        if (ConvertedRecord == NULL)
        {
            Status = ERROR_OUTOFMEMORY;
            break;
        }

        ConvertedRecord->pNext = NULL;
        ConvertedRecord->dwReserved = 0;

        if (LastRecord)
            LastRecord->pNext = ConvertedRecord;
        else
            FirstRecord = ConvertedRecord;
        LastRecord = ConvertedRecord;
    }

    /* The wide result: all of it, from its first record */
    if (QueryResultWide)
        DnsRecordListFree(QueryResultWide, DnsFreeRecordList);

    if (Status != ERROR_SUCCESS)
    {
        /* Nothing is returned on failure */
        if (FirstRecord)
            DnsRecordListFree(FirstRecord, DnsFreeRecordList);
        return Status;
    }

    *QueryResultSet = FirstRecord;
    return ERROR_SUCCESS;
}

DNS_STATUS WINAPI
DnsQuery_A(LPCSTR Name,
           WORD Type,
           DWORD Options,
           PVOID Extra,
           PDNS_RECORD *QueryResultSet,
           PVOID *Reserved)
{
    return DnsQuery_CodePage(CP_ACP, Name, Type, Options, Extra, QueryResultSet, Reserved);
}

DNS_STATUS WINAPI
DnsQuery_UTF8(LPCSTR Name,
              WORD Type,
              DWORD Options,
              PVOID Extra,
              PDNS_RECORD *QueryResultSet,
              PVOID *Reserved)
{
    return DnsQuery_CodePage(CP_UTF8, Name, Type, Options, Extra, QueryResultSet, Reserved);
}

/* The arm of a text record in the union of the dnsrslvr RPC (DNS_TXT_WIRE_DATAW of windns.h in the MIDL view) */
typedef struct
{
    DWORD dwStringCount;
    PWSTR *pStringArray;
} TEXT_WIRE_DATA;

/*
 * The text records that came through the RPC hold a pointer to a separate array of strings (the wire layout);
 * a record of the API holds the array inside itself. Each such record is replaced by one that does. On failure
 * the whole list is freed.
 */
/* The number of strings of a wire text record that its array (allocated by the stub) really holds */
static
DWORD
WireStringCount(const TEXT_WIRE_DATA *Wire)
{
    SIZE_T Slots;

    if (Wire->pStringArray == NULL || Wire->dwStringCount == 0)
        return 0;
    Slots = RtlSizeHeap(RtlGetProcessHeap(), 0, Wire->pStringArray);
    if (Slots == (SIZE_T)-1)
        return 0;
    Slots /= sizeof(PWSTR);
    return (Wire->dwStringCount < Slots) ? Wire->dwStringCount : (DWORD)Slots;
}

static
DNS_STATUS
TextFromWire(PDNS_RECORDW *List)
{
    PDNS_RECORDW *Link, Record, New;
    TEXT_WIRE_DATA *Wire;
    PWSTR *Strings;
    DWORD Count, i, DataLength;
    SIZE_T Size;
    DNS_STATUS Status;

    for (Link = List; (Record = *Link) != NULL; Link = &(*Link)->pNext)
    {
        if (Record->wType != DNS_TYPE_TEXT)
            continue;

        Wire = (TEXT_WIRE_DATA *)&Record->Data;
        Strings = Wire->pStringArray;
        Count = WireStringCount(Wire);

        /*
         * The count must describe the array that arrived (the stub does not check it against the array's size) and
         * fit the WORD data length (the resolver makes no larger record); else the reply is not used
         */
        New = NULL;
        Status = DNS_ERROR_BAD_PACKET;
        if (Count == Wire->dwStringCount &&
            Count <= (MAXWORD - FIELD_OFFSET(DNS_TXT_DATAW, pStringArray)) / sizeof(PWSTR))
        {
            DataLength = FIELD_OFFSET(DNS_TXT_DATAW, pStringArray) + Count * sizeof(PWSTR);
            Size = FIELD_OFFSET(DNS_RECORDW, Data) + DataLength;
            if (Size < sizeof(DNS_RECORDW))
                Size = sizeof(DNS_RECORDW);
            New = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
            Status = ERROR_OUTOFMEMORY;
        }
        if (New == NULL)
        {
            /*
             * The records before this one are done; this one and the rest are in the wire layout: free their
             * strings here and make the list freeing see no strings in them.
             */
            for (New = Record; New; New = New->pNext)
            {
                if (New->wType != DNS_TYPE_TEXT)
                    continue;
                Wire = (TEXT_WIRE_DATA *)&New->Data;
                Strings = Wire->pStringArray;
                Count = WireStringCount(Wire);
                for (i = 0; i < Count; i++)
                    RtlFreeHeap(RtlGetProcessHeap(), 0, Strings[i]);
                if (Strings)
                    RtlFreeHeap(RtlGetProcessHeap(), 0, Strings);
                Wire->pStringArray = NULL;
                Wire->dwStringCount = 0;
            }
            DnsIntFreeRecordList((PDNS_RECORD)*List);
            *List = NULL;
            return Status;
        }

        RtlCopyMemory(New, Record, FIELD_OFFSET(DNS_RECORDW, Data));
        New->wDataLength = (WORD)DataLength;
        New->Data.TXT.dwStringCount = Count;
        for (i = 0; i < Count; i++)
            New->Data.TXT.pStringArray[i] = Strings[i];

        if (Strings)
            RtlFreeHeap(RtlGetProcessHeap(), 0, Strings);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Record);
        *Link = New;
    }

    return ERROR_SUCCESS;
}

static
VOID
SetLocalDataLengths(PDNS_RECORD Record)
{
    for (; Record; Record = Record->pNext)
    {
        switch (Record->wType)
        {
        case DNS_TYPE_CNAME:
        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_MB:
        case DNS_TYPE_MD:
        case DNS_TYPE_MF:
        case DNS_TYPE_MG:
        case DNS_TYPE_MR:
            Record->wDataLength = sizeof(DNS_PTR_DATAW);
            break;

        case DNS_TYPE_MX:
        case DNS_TYPE_AFSDB:
        case DNS_TYPE_RT:
            Record->wDataLength = sizeof(DNS_MX_DATAW);
            break;

        case DNS_TYPE_MINFO:
        case DNS_TYPE_RP:
            Record->wDataLength = sizeof(DNS_MINFO_DATAW);
            break;

        case DNS_TYPE_SOA:
            Record->wDataLength = sizeof(DNS_SOA_DATAW);
            break;

        case DNS_TYPE_SRV:
            Record->wDataLength = sizeof(DNS_SRV_DATAW);
            break;
        }
    }
}

DNS_STATUS
WINAPI
DnsQuery_W(LPCWSTR Name,
           WORD Type,
           DWORD Options,
           PVOID Extra,
           PDNS_RECORD *QueryResultSet,
           PVOID *Reserved)
{
    DWORD dwRecords = 0;
    PDNS_RECORDW pRecord = NULL;
    size_t NameLen, i;
    DNS_STATUS Status = ERROR_SUCCESS;

    DPRINT("DnsQuery_W()\n");

    if ((Name == NULL) ||
        (QueryResultSet == NULL))
        return ERROR_INVALID_PARAMETER;

    *QueryResultSet = NULL;

    /* Create an A or AAAA record for an IP4 or IP6 address */
    pRecord = CreateRecordForIpAddress(Name,
                                       Type);
    if (pRecord != NULL)
    {
        *QueryResultSet = (PDNS_RECORD)pRecord;
        return ERROR_SUCCESS;
    }

    /*
     * Check allowed characters
     * According to RFC a-z,A-Z,0-9,-,_, but can't start or end with - or _
     */
    NameLen = wcslen(Name);
    if (NameLen != 0 &&
        (Name[0] == L'-' || Name[NameLen - 1] == L'-' || wcsstr(Name, L"..") != NULL))
    {
        return ERROR_INVALID_NAME;
    }
    /* The names of services (SRV: _ldap._tcp.example.com) and of other typed records start with an underscore */
    if (NameLen != 0 && Type != DNS_TYPE_SRV && Type != DNS_TYPE_TEXT && Type != DNS_TYPE_CNAME &&
        Type != DNS_TYPE_NS && Type != DNS_TYPE_SOA && Type != DNS_TYPE_MX &&
        (Name[0] == L'_' || Name[NameLen - 1] == L'_'))
    {
        return ERROR_INVALID_NAME;
    }

    i = 0;
    while (i < NameLen)
    {
        if (!((Name[i] >= L'a' && Name[i] <= L'z') ||
              (Name[i] >= L'A' && Name[i] <= L'Z') ||
              (Name[i] >= L'0' && Name[i] <= L'9') ||
              Name[i] == L'-' || Name[i] == L'_' || Name[i] == L'.'))
        {
            return DNS_ERROR_INVALID_NAME_CHAR;
        }

        i++;
    }

    RpcTryExcept
    {
        Status = R_ResolverQuery(NULL,
                                 Name,
                                 Type,
                                 Options,
                                 &dwRecords,
                                 (DNS_RECORDW **)QueryResultSet);
        DPRINT("R_ResolverQuery() returned %lu\n", Status);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = RpcExceptionCode();
        DPRINT("Exception returned %lu\n", Status);
    }
    RpcEndExcept;

    /* The resolver service may be a 64-bit process answering a 32-bit client: the data lengths of the
       records that hold pointers are those of the service's structures, not of this process's */
    if (Status == ERROR_SUCCESS)
    {
        Status = TextFromWire((PDNS_RECORDW *)QueryResultSet);
        if (Status == ERROR_SUCCESS)
            SetLocalDataLengths(*QueryResultSet);
    }

    return Status;
}

WCHAR
*xstrsave(const WCHAR *str)
{
    WCHAR *p;
    size_t len;

    /* The whole string: a name of 130 characters or more used to get an empty copy (the length was capped at
       MAX_PATH bytes and the failed measurement left 0) */
    len = (wcslen(str) + 1) * sizeof(WCHAR);

    p = RtlAllocateHeap(RtlGetProcessHeap(), 0, len);

    if (p)
        RtlCopyMemory(p, str, len);

    return p;
}

CHAR
*xstrsaveA(const CHAR *str)
{
    CHAR *p;
    size_t len;

    /* The whole string, as xstrsave does */
    len = strlen(str) + 1;

    p = RtlAllocateHeap(RtlGetProcessHeap(), 0, len);

    if (p)
        RtlCopyMemory(p, str, len);

    return p;
}


/*
 * Is Name the name of this machine (host name or host name + DNS domain, with or without the root
 * label's trailing dot)? Windows answers such a query itself, without asking a DNS server: with the
 * addresses the machine has, or with the loopback address when it has none (no adapter up, DHCP not
 * answered yet). Returns the address (network order) or 0 when Name is not the machine's name.
 */
static
BOOL
IsCurrentHostname(CONST CHAR * Name, PFIXED_INFO network_info)
{
    CHAR LocalName[sizeof(network_info->HostName) + sizeof(network_info->DomainName) + 2];
    CHAR Query[sizeof(LocalName)];
    size_t Len;

    /* The name without the trailing dot */
    if (FAILED(StringCchCopyA(Query, sizeof(Query), Name)))
        return FALSE;
    Len = strlen(Query);
    if (Len > 1 && Query[Len - 1] == '.')
        Query[Len - 1] = '\0';

    /* The host name alone, or qualified with the DNS domain */
    if (_stricmp(Query, network_info->HostName) != 0)
    {
        if (!network_info->DomainName[0])
            return FALSE;
        StringCchCopyA(LocalName, sizeof(LocalName), network_info->HostName);
        StringCchCatA(LocalName, sizeof(LocalName), ".");
        StringCchCatA(LocalName, sizeof(LocalName), network_info->DomainName);
        if (_stricmp(Query, LocalName) != 0)
            return FALSE;
    }

    return TRUE;
}

IP4_ADDRESS
CheckForCurrentHostname(CONST CHAR * Name, PFIXED_INFO network_info)
{
    DWORD AdapterAddressesSize = 0;
    IP4_ADDRESS ret = 0, Address;
    PIP_ADAPTER_ADDRESSES Addresses = NULL, pip;
    PIP_ADAPTER_UNICAST_ADDRESS pua;

    if (!IsCurrentHostname(Name, network_info))
        return 0;

    /* Take the first address of the first adapter that has a usable one */
    GetAdaptersAddresses(AF_INET,
                         GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_SKIP_DNS_SERVER |
                         GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                         NULL,
                         NULL,
                         &AdapterAddressesSize);
    if (AdapterAddressesSize)
    {
        Addresses = RtlAllocateHeap(RtlGetProcessHeap(), 0, AdapterAddressesSize);
        if (Addresses && GetAdaptersAddresses(AF_INET,
                                              GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_SKIP_DNS_SERVER |
                                              GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                              NULL,
                                              Addresses,
                                              &AdapterAddressesSize) == ERROR_SUCCESS)
        {
            for (pip = Addresses; pip != NULL && ret == 0; pip = pip->Next)
            {
                for (pua = pip->FirstUnicastAddress; pua != NULL; pua = pua->Next)
                {
                    if (!pua->Address.lpSockaddr || pua->Address.lpSockaddr->sa_family != AF_INET)
                        continue;
                    Address = ((LPSOCKADDR_IN)pua->Address.lpSockaddr)->sin_addr.S_un.S_addr;
                    if (Address != 0 && Address != htonl(INADDR_LOOPBACK))
                    {
                        ret = Address;
                        break;
                    }
                }
            }
        }
        if (Addresses)
            RtlFreeHeap(RtlGetProcessHeap(), 0, Addresses);
    }

    /* Nothing but loopback (or 0.0.0.0): the machine is still reachable at itself */
    return ret ? ret : htonl(INADDR_LOOPBACK);
}


/*
 * The time that an answer of adns is good for, in seconds (adns knows the end of the lifetime, which is that of
 * the shortest record, not the TTL). The resolver service keeps the answer for this long.
 */
static
DWORD
AnswerTtl(
    _In_ const adns_answer *Answer)
{
    time_t Now = time(NULL);

    if (Answer->expires > Now)
        return (Answer->expires - Now > 0x7fffffff) ? 0x7fffffff : (DWORD)(Answer->expires - Now);
    return 0;
}

/*
 * A chain of CNAME records (alias -> alias -> name) is asked one link at a time (adns follows one CNAME itself):
 * the answer of the last link is only good for as long as every link before it. Chain is the earliest end of the
 * links asked so far (0 before the first one); Answer is the answer of the current link.
 */
static
VOID
KeepChainExpiry(
    _Inout_ time_t *Chain,
    _In_ const adns_answer *Answer)
{
    if (*Chain == 0 || Answer->expires < *Chain)
        *Chain = Answer->expires;
}

/* The final answer of a chain ends no later than the links before it */
static
VOID
ApplyChainExpiry(
    _Inout_ adns_answer *Answer,
    _In_ time_t Chain)
{
    if (Chain != 0 && Chain < Answer->expires)
        Answer->expires = Chain;
}

/* Sets the TTL of every record of the list */
static
VOID
SetListTtl(
    _In_opt_ PDNS_RECORDW List,
    _In_ DWORD Ttl)
{
    for (; List; List = List->pNext)
        List->dwTtl = Ttl;
}

static
PDNS_RECORDW
AppendTypedRecord(
    _In_ PCWSTR Name,
    _In_ WORD Type,
    _In_ WORD DataLength,
    _In_ DWORD Ttl,
    _Inout_ PDNS_RECORDW *First,
    _Inout_ PDNS_RECORDW *Last);

/*
 * The CNAME records of an answer that came through a chain of aliases. Windows' DnsQuery answers an A or AAAA query
 * of an alias with the CNAME records of the chain, in order (the first one is owned by the name asked for), then the
 * records of the type, owned by the end of the chain; the canonical name of getaddrinfo and the h_name of
 * gethostbyname are the owner of the first address record. A link (Owner -> Target) is appended to the list
 * (First, Last); the owner of the next link, and of the address records, is ChainOwner(Name, Last).
 */
static
BOOL
AppendChainLink(
    _In_ PCWSTR Owner,
    _In_ PCSTR Target,
    _Inout_ PDNS_RECORDW *First,
    _Inout_ PDNS_RECORDW *Last)
{
    PDNS_RECORDW Record;

    Record = AppendTypedRecord(Owner, DNS_TYPE_CNAME, sizeof(DNS_PTR_DATAW), 0, First, Last);
    if (Record == NULL)
        return FALSE;
    Record->Data.CNAME.pNameHost = DnsCToW(Target);
    return Record->Data.CNAME.pNameHost != NULL;
}

/* The name the next records of the answer are owned by: the target of the last link of the chain, else the name */
static
PCWSTR
ChainOwner(
    _In_ PCWSTR Name,
    _In_opt_ PDNS_RECORDW Last)
{
    return Last ? Last->Data.CNAME.pNameHost : Name;
}

/* The answer: the links of the chain (if any) followed by the records of the type */
static
PDNS_RECORDW
JoinChain(
    _In_opt_ PDNS_RECORDW ChainFirst,
    _In_opt_ PDNS_RECORDW ChainLast,
    _In_opt_ PDNS_RECORDW Records)
{
    if (ChainFirst == NULL)
        return Records;
    ChainLast->pNext = Records;
    return ChainFirst;
}

/*
 * PTR query: Name is a reverse name (like 8.8.8.8.in-addr.arpa); every PTR record in the answer is returned.
 * The name servers of the machine are asked, recursively.
 */
static
DNS_STATUS
QueryPtr(LPCWSTR Name,
         DWORD Options,
         PDNS_RECORD *QueryResultSet)
{
    adns_state astate;
    adns_answer *answer;
    int adns_error;
    PFIXED_INFO network_info;
    ULONG network_info_blen = 0;
    PIP_ADDR_STRING pip;
    struct in_addr addr;
    CHAR AnsiName[MAX_PATH];
    DNS_STATUS Status;
    DWORD Ttl;
    PDNS_RECORDW Record, Last = NULL;
    int i, Len;

    if ((Options & DNS_QUERY_NO_WIRE_QUERY) != 0)
        return ERROR_FILE_NOT_FOUND;

    /* The name without the root label's dot */
    Len = WideCharToMultiByte(CP_ACP, 0, Name, -1, AnsiName, sizeof(AnsiName), NULL, NULL);
    if (Len == 0)
        return ERROR_INVALID_NAME;
    Len--;
    if (Len > 1 && AnsiName[Len - 1] == '.')
        AnsiName[Len - 1] = '\0';

    GetNetworkParams(NULL, &network_info_blen);
    network_info = (PFIXED_INFO)RtlAllocateHeap(RtlGetProcessHeap(), 0, network_info_blen);
    if (network_info == NULL)
        return ERROR_OUTOFMEMORY;
    Status = GetNetworkParams(network_info, &network_info_blen);
    if (Status != ERROR_SUCCESS)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
        return Status;
    }

    adns_error = adns_init(&astate, adns_if_noenv | adns_if_noerrprint | adns_if_noserverwarn, 0);
    if (adns_error != adns_s_ok)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
        return DnsIntTranslateAdnsToDNS_STATUS(adns_error);
    }
    for (pip = &(network_info->DnsServerList); pip; pip = pip->Next)
    {
        addr.s_addr = inet_addr(pip->IpAddress.String);
        if ((addr.s_addr != INADDR_ANY) && (addr.s_addr != INADDR_NONE))
            adns_addserver(astate, addr);
    }
    AddIpv6Servers(astate, NULL, 0);
    RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);

    if (!adns_numservers(astate))
    {
        adns_finish(astate);
        return ERROR_FILE_NOT_FOUND;
    }

    /* The name is complete: no search list */
    adns_error = adns_synchronous(astate, AnsiName, adns_r_ptr_raw, 0, &answer);
    if (adns_error != adns_s_ok || answer == NULL)
    {
        adns_finish(astate);
        return adns_error != adns_s_ok ? DnsIntTranslateAdnsToDNS_STATUS(adns_error) : ERROR_OUTOFMEMORY;
    }

    if (answer->status == adns_s_nxdomain)
        Status = DNS_ERROR_RCODE_NAME_ERROR;
    else if (answer->status == adns_s_nodata)
        Status = DNS_INFO_NO_RECORDS;
    else if (answer->status != adns_s_ok || answer->nrrs <= 0)
        Status = DNS_ERROR_RCODE_SERVER_FAILURE;
    else
        Status = ERROR_SUCCESS;
    Ttl = AnswerTtl(answer);

    for (i = 0; Status == ERROR_SUCCESS && i < answer->nrrs; i++)
    {
        Record = (PDNS_RECORDW)RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DNS_RECORD));
        if (Record == NULL)
        {
            Status = ERROR_OUTOFMEMORY;
            break;
        }
        if (Last)
            Last->pNext = Record;
        else
            *QueryResultSet = (PDNS_RECORD)Record;
        Last = Record;

        Record->wType = DNS_TYPE_PTR;
        Record->wDataLength = sizeof(DNS_PTR_DATA);
        Record->Flags.S.Section = DnsSectionAnswer;
        Record->Flags.S.CharSet = DnsCharSetUnicode;
        Record->dwTtl = Ttl;
        Record->pName = xstrsave(Name);
        Record->Data.PTR.pNameHost = (PWSTR)DnsCToW(answer->rrs.str[i]);
        if (Record->pName == NULL || Record->Data.PTR.pNameHost == NULL)
            Status = ERROR_OUTOFMEMORY;
    }

    free(answer);
    adns_finish(astate);

    if (Status != ERROR_SUCCESS && *QueryResultSet)
    {
        DnsIntFreeRecordList(*QueryResultSet);
        *QueryResultSet = NULL;
    }

    return Status;
}


static
PDNS_RECORDW
CreateAaaaRecord(
    _In_ PCWSTR Name,
    _In_ const VOID *Address)
{
    PDNS_RECORDW Record;

    Record = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DNS_RECORDW));
    if (Record == NULL)
        return NULL;

    Record->pName = xstrsave(Name);
    if (Record->pName == NULL)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Record);
        return NULL;
    }

    Record->wType = DNS_TYPE_AAAA;
    Record->wDataLength = sizeof(DNS_AAAA_DATA);
    Record->Flags.S.Section = DnsSectionAnswer;
    Record->Flags.S.CharSet = DnsCharSetUnicode;
    CopyMemory(&Record->Data.AAAA.Ip6Address, Address, sizeof(IN6_ADDR));
    return Record;
}

/* Appends a record for Address to the list (First, Last); FALSE when out of memory */
static
BOOL
AppendAaaaRecord(
    _In_ PCWSTR Name,
    _In_ const VOID *Address,
    _Inout_ PDNS_RECORDW *First,
    _Inout_ PDNS_RECORDW *Last)
{
    PDNS_RECORDW Record = CreateAaaaRecord(Name, Address);

    if (Record == NULL)
        return FALSE;
    if (*Last)
        (*Last)->pNext = Record;
    else
        *First = Record;
    *Last = Record;
    return TRUE;
}

/* The A record of an address (network order) appended to the list (First, Last); FALSE when out of memory */
static
BOOL
AppendARecord(
    _In_ PCWSTR Name,
    _In_ DWORD Address,
    _Inout_ PDNS_RECORDW *First,
    _Inout_ PDNS_RECORDW *Last)
{
    PDNS_RECORDW Record;

    Record = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DNS_RECORDW));
    if (Record == NULL)
        return FALSE;

    Record->pName = xstrsave(Name);
    if (Record->pName == NULL)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Record);
        return FALSE;
    }

    Record->wType = DNS_TYPE_A;
    Record->wDataLength = sizeof(DNS_A_DATA);
    Record->Flags.S.Section = DnsSectionAnswer;
    Record->Flags.S.CharSet = DnsCharSetUnicode;
    Record->Data.A.IpAddress = Address;

    if (*Last)
        (*Last)->pNext = Record;
    else
        *First = Record;
    *Last = Record;
    return TRUE;
}

/*
 * The AAAA records of this machine's own name: the IPv6 addresses its adapters have (not the loopback one),
 * as Windows answers it without asking a server (measured: the link-local address of the adapter, without its
 * scope). Without any (no IPv6, or none usable yet) there is no record.
 */
static
DNS_STATUS
QueryOwnIpv6(
    _In_ PCWSTR RecordName,
    _Out_ PDNS_RECORD *QueryResultSet)
{
    PIP_ADAPTER_ADDRESSES Addresses = NULL, Adapter;
    PIP_ADAPTER_UNICAST_ADDRESS Unicast;
    PDNS_RECORDW First = NULL, Last = NULL;
    ULONG Size = 16 * 1024, Pass;
    DWORD Error = ERROR_BUFFER_OVERFLOW;
    DNS_STATUS Status = ERROR_SUCCESS;

    *QueryResultSet = NULL;

    for (Pass = 0; Pass < 3 && Error == ERROR_BUFFER_OVERFLOW; Pass++)
    {
        if (Addresses)
            RtlFreeHeap(RtlGetProcessHeap(), 0, Addresses);
        Addresses = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
        if (!Addresses)
            return ERROR_OUTOFMEMORY;
        Error = GetAdaptersAddresses(AF_INET6,
                                     GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                     GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
                                     NULL, Addresses, &Size);
    }

    for (Adapter = (Error == ERROR_SUCCESS) ? Addresses : NULL; Adapter && Status == ERROR_SUCCESS;
         Adapter = Adapter->Next)
    {
        if (Adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || Adapter->OperStatus != IfOperStatusUp)
            continue;

        for (Unicast = Adapter->FirstUnicastAddress; Unicast; Unicast = Unicast->Next)
        {
            const SOCKADDR_IN6 *Sa = (const SOCKADDR_IN6 *)Unicast->Address.lpSockaddr;

            /* usable as a source: preferred or deprecated */
            if (!Sa || Sa->sin6_family != AF_INET6 ||
                (Unicast->DadState != IpDadStatePreferred && Unicast->DadState != IpDadStateDeprecated))
                continue;
            if (!AppendAaaaRecord(RecordName, &Sa->sin6_addr, &First, &Last))
            {
                Status = ERROR_OUTOFMEMORY;
                break;
            }
        }
    }

    if (Addresses)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Addresses);

    if (Status != ERROR_SUCCESS)
    {
        if (First)
            DnsIntFreeRecordList((PDNS_RECORD)First);
        return Status;
    }
    if (First == NULL)
        return DNS_INFO_NO_RECORDS;

    *QueryResultSet = (PDNS_RECORD)First;
    return ERROR_SUCCESS;
}

/*
 * AAAA query. The name of this machine and "localhost" are answered locally (as for A); anything else is asked
 * of the name servers, every AAAA record of the answer is returned (CNAME chains are followed here, as for A).
 * No record of the type is DNS_INFO_NO_RECORDS, a name that does not exist DNS_ERROR_RCODE_NAME_ERROR.
 */
static
DNS_STATUS
QueryAaaa(LPCWSTR Name,
          DWORD Options,
          PDNS_RECORD *QueryResultSet)
{
    adns_state astate;
    adns_answer *answer;
    int quflags = (Options & (DNS_QUERY_NO_RECURSION | DNS_QUERY_TREAT_AS_FQDN)) == 0 ? adns_qf_search : 0;
    int adns_error, i;
    unsigned CNameLoop;
    time_t ChainExpires = 0;
    CHAR Search[512];
    PFIXED_INFO network_info;
    ULONG network_info_blen = 0;
    PIP_ADDR_STRING pip;
    struct in_addr addr;
    PCHAR AnsiName, CurrentName, NextName;
    PDNS_RECORDW First, Last, ChainFirst = NULL, ChainLast = NULL;
    DNS_STATUS Status;
    size_t NameLen;
    BOOL IsOwn;

    *QueryResultSet = NULL;

    NameLen = WideCharToMultiByte(CP_ACP, 0, Name, -1, NULL, 0, NULL, NULL);
    if (NameLen == 0)
        return ERROR_INVALID_NAME;
    AnsiName = RtlAllocateHeap(RtlGetProcessHeap(), 0, NameLen);
    if (AnsiName == NULL)
        return ERROR_OUTOFMEMORY;
    WideCharToMultiByte(CP_ACP, 0, Name, -1, AnsiName, NameLen, NULL, NULL);
    NameLen--;

    /* "localhost", with or without the root label's dot: the IPv6 loopback address */
    if (_stricmp(AnsiName, "localhost") == 0 || _stricmp(AnsiName, "localhost.") == 0)
    {
        static const IN6_ADDR Loopback = {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};

        RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
        First = Last = NULL;
        if (!AppendAaaaRecord(Name, &Loopback, &First, &Last))
            return ERROR_OUTOFMEMORY;
        *QueryResultSet = (PDNS_RECORD)First;
        return ERROR_SUCCESS;
    }

    GetNetworkParams(NULL, &network_info_blen);
    network_info = (PFIXED_INFO)RtlAllocateHeap(RtlGetProcessHeap(), 0, network_info_blen);
    if (network_info == NULL)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
        return ERROR_OUTOFMEMORY;
    }
    Status = GetNetworkParams(network_info, &network_info_blen);
    if (Status != ERROR_SUCCESS)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
        return Status;
    }

    /* The name of this machine (the empty name is it too, as for A) */
    IsOwn = IsCurrentHostname(NameLen != 0 ? AnsiName : network_info->HostName, network_info);
    if (IsOwn)
    {
        PCHAR HostWithDomainName;
        PWCHAR RecordName;
        size_t TempLen = 2, StringLength = 0;

        StringCchLengthA(network_info->HostName, sizeof(network_info->HostName), &StringLength);
        TempLen += StringLength;
        StringCchLengthA(network_info->DomainName, sizeof(network_info->DomainName), &StringLength);
        TempLen += StringLength;
        HostWithDomainName = (PCHAR)RtlAllocateHeap(RtlGetProcessHeap(), 0, TempLen);
        RecordName = NULL;
        if (HostWithDomainName)
        {
            StringCchCopyA(HostWithDomainName, TempLen, network_info->HostName);
            if (network_info->DomainName[0])
            {
                StringCchCatA(HostWithDomainName, TempLen, ".");
                StringCchCatA(HostWithDomainName, TempLen, network_info->DomainName);
            }
            RecordName = DnsCToW(HostWithDomainName);
            RtlFreeHeap(RtlGetProcessHeap(), 0, HostWithDomainName);
        }
        RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
        if (RecordName == NULL)
            return ERROR_OUTOFMEMORY;
        Status = QueryOwnIpv6(RecordName, QueryResultSet);
        RtlFreeHeap(RtlGetProcessHeap(), 0, RecordName);
        return Status;
    }

    if ((Options & DNS_QUERY_NO_WIRE_QUERY) != 0)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
        RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
        return ERROR_FILE_NOT_FOUND;
    }

    adns_error = adns_init(&astate, adns_if_noenv | adns_if_noerrprint | adns_if_noserverwarn, 0);
    if (adns_error != adns_s_ok)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
        RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
        return DnsIntTranslateAdnsToDNS_STATUS(adns_error);
    }
    for (pip = &(network_info->DnsServerList); pip; pip = pip->Next)
    {
        addr.s_addr = inet_addr(pip->IpAddress.String);
        if ((addr.s_addr != INADDR_ANY) && (addr.s_addr != INADDR_NONE))
            adns_addserver(astate, addr);
    }
    StringCchCopyA(Search, sizeof(Search), network_info->DomainName);
    AddIpv6Servers(astate, Search, sizeof(Search));
    if (Search[0])
    {
        adns_ccf_search(astate, "LOCALDOMAIN", -1, Search);
        /* a name of one label is looked up in the search domains even where the caller asked for no recursion:
           that flag has meant no search list for the other names (the callers of this tree set it for what they
           cannot search), but a short name is what a search list is for. DNS_QUERY_TREAT_AS_FQDN is the flag that
           asks for no suffix (Windows SDK: "prevents ... attaching suffixes to the submitted name") */
        if (strchr(AnsiName, '.') == NULL && !(Options & DNS_QUERY_TREAT_AS_FQDN))
            quflags |= adns_qf_search;
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);

    if (!adns_numservers(astate))
    {
        adns_finish(astate);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
        return ERROR_FILE_NOT_FOUND;
    }

    CurrentName = AnsiName;
    Status = ERROR_FILE_NOT_FOUND;
    for (CNameLoop = 0; CNameLoop < 16; CNameLoop++)
    {
        adns_error = adns_synchronous(astate, CurrentName, adns_r_aaaa, quflags, &answer);
        if (adns_error != adns_s_ok || answer == NULL)
        {
            Status = adns_error != adns_s_ok ? DnsIntTranslateAdnsToDNS_STATUS(adns_error) : ERROR_OUTOFMEMORY;
            break;
        }

        if (answer->status == adns_s_ok && answer->nrrs > 0)
        {
            First = Last = NULL;
            Status = ERROR_SUCCESS;

            /* the CNAME record that adns followed itself (the last link of the chain), then the addresses, owned
               by the end of the chain (see AppendChainLink) */
            if (answer->cname && !AppendChainLink(ChainOwner(Name, ChainLast), answer->cname, &ChainFirst, &ChainLast))
                Status = ERROR_OUTOFMEMORY;
            for (i = 0; i < answer->nrrs && Status == ERROR_SUCCESS; i++)
            {
                if (!AppendAaaaRecord(ChainOwner(Name, ChainLast), &answer->rrs.in6addr[i], &First, &Last))
                {
                    Status = ERROR_OUTOFMEMORY;
                    break;
                }
            }
            First = JoinChain(ChainFirst, ChainLast, First);
            ChainFirst = ChainLast = NULL;
            if (Status == ERROR_SUCCESS)
            {
                ApplyChainExpiry(answer, ChainExpires);
                SetListTtl(First, AnswerTtl(answer));
                *QueryResultSet = (PDNS_RECORD)First;
            }
            else if (First)
                DnsIntFreeRecordList((PDNS_RECORD)First);
            free(answer);
            break;
        }

        if (answer->status == adns_s_prohibitedcname && answer->cname)
        {
            KeepChainExpiry(&ChainExpires, answer);
            /* a link of the chain: CurrentName is an alias of answer->cname, which is an alias too */
            if (AppendChainLink(ChainOwner(Name, ChainLast), answer->cname, &ChainFirst, &ChainLast))
                NextName = (PCHAR)xstrsaveA(answer->cname);
            else
                NextName = NULL;
            free(answer);
            if (CurrentName != AnsiName)
                RtlFreeHeap(RtlGetProcessHeap(), 0, CurrentName);
            if (!NextName)
            {
                CurrentName = AnsiName;
                Status = ERROR_OUTOFMEMORY;
                break;
            }
            CurrentName = NextName;
            continue;
        }

        if (answer->status == adns_s_nxdomain)
            Status = DNS_ERROR_RCODE_NAME_ERROR;
        else if (answer->status == adns_s_nodata)
            Status = DNS_INFO_NO_RECORDS;
        else if (answer->status < adns_s_max_tempfail)
            Status = ERROR_TIMEOUT;
        else
            Status = DNS_ERROR_RCODE_SERVER_FAILURE;
        free(answer);
        break;
    }

    /* no answer: the links found so far are not returned */
    if (ChainFirst)
        DnsIntFreeRecordList((PDNS_RECORD)ChainFirst);
    adns_finish(astate);
    if (CurrentName != AnsiName)
        RtlFreeHeap(RtlGetProcessHeap(), 0, CurrentName);
    RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
    return Status;
}


/*
 * A resolver (adns) with the name servers of the machine (IPv4 ones of GetNetworkParams, then IPv6 ones) and the
 * search list of the A and AAAA queries (the DNS domain, then the router advertisement search domains). A name of
 * one label is searched unless the caller said it is fully qualified, as there (*QueryFlags gets adns_qf_search).
 */
static
DNS_STATUS
OpenResolver(
    _In_ PCSTR AnsiName,
    _In_ DWORD Options,
    _Out_ adns_state *State,
    _Inout_ int *QueryFlags)
{
    PFIXED_INFO network_info;
    ULONG network_info_blen = 0;
    PIP_ADDR_STRING pip;
    struct in_addr addr;
    adns_state astate;
    DNS_STATUS Status;
    int adns_error;
    CHAR Search[512];

    *State = NULL;

    GetNetworkParams(NULL, &network_info_blen);
    network_info = (PFIXED_INFO)RtlAllocateHeap(RtlGetProcessHeap(), 0, network_info_blen);
    if (network_info == NULL)
        return ERROR_OUTOFMEMORY;
    Status = GetNetworkParams(network_info, &network_info_blen);
    if (Status != ERROR_SUCCESS)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
        return Status;
    }

    adns_error = adns_init(&astate, adns_if_noenv | adns_if_noerrprint | adns_if_noserverwarn, 0);
    if (adns_error != adns_s_ok)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
        return DnsIntTranslateAdnsToDNS_STATUS(adns_error);
    }
    for (pip = &(network_info->DnsServerList); pip; pip = pip->Next)
    {
        addr.s_addr = inet_addr(pip->IpAddress.String);
        if ((addr.s_addr != INADDR_ANY) && (addr.s_addr != INADDR_NONE))
            adns_addserver(astate, addr);
    }
    StringCchCopyA(Search, sizeof(Search), network_info->DomainName);
    AddIpv6Servers(astate, Search, sizeof(Search));
    if (Search[0])
    {
        adns_ccf_search(astate, "LOCALDOMAIN", -1, Search);
        /* see QueryAaaa: a name of one label is searched unless the caller said it is fully qualified */
        if (strchr(AnsiName, '.') == NULL && !(Options & DNS_QUERY_TREAT_AS_FQDN))
            *QueryFlags |= adns_qf_search;
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);

    if (!adns_numservers(astate))
    {
        adns_finish(astate);
        return ERROR_FILE_NOT_FOUND;
    }

    *State = astate;
    return ERROR_SUCCESS;
}

/* The wide copy of Length bytes of a text of a record (UTF-8, else the ANSI code page), with a terminating zero */
static
PWSTR
TextToWide(
    _In_ const CHAR *Text,
    _In_ int Length)
{
    UINT CodePage = CP_UTF8;
    int WideLength;
    PWSTR Wide;

    WideLength = Length ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, Text, Length, NULL, 0) : 0;
    if (Length && WideLength == 0)
    {
        CodePage = CP_ACP;
        WideLength = MultiByteToWideChar(CP_ACP, 0, Text, Length, NULL, 0);
    }
    Wide = RtlAllocateHeap(RtlGetProcessHeap(), 0, (WideLength + 1) * sizeof(WCHAR));
    if (Wide == NULL)
        return NULL;
    if (WideLength)
        MultiByteToWideChar(CodePage, 0, Text, Length, Wide, WideLength);
    Wide[WideLength] = L'\0';
    return Wide;
}

/*
 * A record of the answer of a typed query, appended to the list (First, Last). Its data is zeroed; the caller
 * fills it in, each pointer as soon as it is allocated (the list is freed with the record type's layout).
 */
static
PDNS_RECORDW
AppendTypedRecord(
    _In_ PCWSTR Name,
    _In_ WORD Type,
    _In_ WORD DataLength,
    _In_ DWORD Ttl,
    _Inout_ PDNS_RECORDW *First,
    _Inout_ PDNS_RECORDW *Last)
{
    PDNS_RECORDW Record;
    SIZE_T Size = FIELD_OFFSET(DNS_RECORDW, Data) + DataLength;

    if (Size < sizeof(DNS_RECORDW))
        Size = sizeof(DNS_RECORDW);
    Record = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (Record == NULL)
        return NULL;

    Record->wType = Type;
    Record->wDataLength = DataLength;
    Record->Flags.S.Section = DnsSectionAnswer;
    Record->Flags.S.CharSet = DnsCharSetUnicode;
    Record->dwTtl = Ttl;

    if (*Last)
        (*Last)->pNext = Record;
    else
        *First = Record;
    *Last = Record;

    Record->pName = xstrsave(Name);
    return Record->pName ? Record : NULL;
}

/* Records of the other types (CNAME, NS, SOA, MX, TXT, SRV) of an answer of adns */
static
DNS_STATUS
BuildTypedRecords(
    _In_ PCWSTR Name,
    _In_ WORD Type,
    _In_ const adns_answer *Answer,
    _Out_ PDNS_RECORDW *Result)
{
    PDNS_RECORDW First = NULL, Last = NULL, Record;
    DNS_STATUS Status = ERROR_SUCCESS;
    DWORD Ttl = AnswerTtl(Answer);
    int i;

    for (i = 0; i < Answer->nrrs && Status == ERROR_SUCCESS; i++)
    {
        switch (Type)
        {
        case DNS_TYPE_CNAME:
        case DNS_TYPE_NS:
            Record = AppendTypedRecord(Name, Type, sizeof(DNS_PTR_DATAW), Ttl, &First, &Last);
            if (Record)
                Record->Data.PTR.pNameHost = DnsCToW(Answer->rrs.str[i]);
            if (Record == NULL || Record->Data.PTR.pNameHost == NULL)
                Status = ERROR_OUTOFMEMORY;
            break;

        case DNS_TYPE_MX:
            Record = AppendTypedRecord(Name, Type, sizeof(DNS_MX_DATAW), Ttl, &First, &Last);
            if (Record)
            {
                Record->Data.MX.wPreference = (WORD)Answer->rrs.intstr[i].i;
                Record->Data.MX.pNameExchange = DnsCToW(Answer->rrs.intstr[i].str);
            }
            if (Record == NULL || Record->Data.MX.pNameExchange == NULL)
                Status = ERROR_OUTOFMEMORY;
            break;

        case DNS_TYPE_SOA:
            Record = AppendTypedRecord(Name, Type, sizeof(DNS_SOA_DATAW), Ttl, &First, &Last);
            if (Record)
            {
                Record->Data.SOA.dwSerialNo = Answer->rrs.soa[i].serial;
                Record->Data.SOA.dwRefresh = Answer->rrs.soa[i].refresh;
                Record->Data.SOA.dwRetry = Answer->rrs.soa[i].retry;
                Record->Data.SOA.dwExpire = Answer->rrs.soa[i].expire;
                Record->Data.SOA.dwDefaultTtl = Answer->rrs.soa[i].minimum;
                Record->Data.SOA.pNamePrimaryServer = DnsCToW(Answer->rrs.soa[i].mname);
                Record->Data.SOA.pNameAdministrator = DnsCToW(Answer->rrs.soa[i].rname);
            }
            if (Record == NULL || Record->Data.SOA.pNamePrimaryServer == NULL ||
                Record->Data.SOA.pNameAdministrator == NULL)
                Status = ERROR_OUTOFMEMORY;
            break;

        case DNS_TYPE_SRV:
            Record = AppendTypedRecord(Name, Type, sizeof(DNS_SRV_DATAW), Ttl, &First, &Last);
            if (Record)
            {
                Record->Data.SRV.wPriority = (WORD)Answer->rrs.srv[i].priority;
                Record->Data.SRV.wWeight = (WORD)Answer->rrs.srv[i].weight;
                Record->Data.SRV.wPort = (WORD)Answer->rrs.srv[i].port;
                Record->Data.SRV.pNameTarget = DnsCToW(Answer->rrs.srv[i].host);
            }
            if (Record == NULL || Record->Data.SRV.pNameTarget == NULL)
                Status = ERROR_OUTOFMEMORY;
            break;

        case DNS_TYPE_TEXT:
        {
            /* the strings of one record, one entry each; the list ends with a length of -1 */
            const adns_rr_intstr *Strings = Answer->rrs.manyistr[i];
            DWORD Count = 0, n;

            while (Strings[Count].i >= 0)
                Count++;

            /*
             * The data length is a WORD and DnsRecordCopyEx sizes its copy by it: a record of more strings than
             * that can describe (one byte each in a reply of up to 64 KB over TCP) is not a record of the API
             */
            if (Count > (MAXWORD - FIELD_OFFSET(DNS_TXT_DATAW, pStringArray)) / sizeof(PWSTR))
            {
                Status = DNS_ERROR_BAD_PACKET;
                break;
            }

            Record = AppendTypedRecord(Name,
                                       Type,
                                       (WORD)(FIELD_OFFSET(DNS_TXT_DATAW, pStringArray) + Count * sizeof(PWSTR)),
                                       Ttl, &First, &Last);
            if (Record == NULL)
            {
                Status = ERROR_OUTOFMEMORY;
                break;
            }
            for (n = 0; n < Count; n++)
            {
                Record->Data.TXT.pStringArray[n] = TextToWide(Strings[n].str, Strings[n].i);
                if (Record->Data.TXT.pStringArray[n] == NULL)
                {
                    Status = ERROR_OUTOFMEMORY;
                    break;
                }
                Record->Data.TXT.dwStringCount = n + 1;
            }
            break;
        }

        default:
            Status = ERROR_INVALID_PARAMETER;
            break;
        }
    }

    if (Status != ERROR_SUCCESS)
    {
        if (First)
            DnsIntFreeRecordList((PDNS_RECORD)First);
        return Status;
    }

    *Result = First;
    return ERROR_SUCCESS;
}

/*
 * CNAME, NS, SOA, MX, TXT and SRV queries: asked of the name servers of the machine, every record of the type in the
 * answer is returned, as for A (a name that is an alias is followed to its target, as there). No record of the type
 * is DNS_INFO_NO_RECORDS, a name that does not exist DNS_ERROR_RCODE_NAME_ERROR.
 */
static
DNS_STATUS
QueryTyped(LPCWSTR Name,
           WORD Type,
           DWORD Options,
           PDNS_RECORD *QueryResultSet)
{
    adns_state astate;
    adns_answer *answer;
    adns_rrtype Rrtype;
    int quflags = adns_qf_quoteok_query | adns_qf_quoteok_anshost;
    int adns_error, Len;
    unsigned CNameLoop;
    time_t ChainExpires = 0;
    PCHAR AnsiName, CurrentName, NextName;
    PDNS_RECORDW Records;
    DNS_STATUS Status;

    switch (Type)
    {
    case DNS_TYPE_CNAME: Rrtype = adns_r_cname; break;
    case DNS_TYPE_NS:    Rrtype = adns_r_ns_raw; break;
    case DNS_TYPE_SOA:   Rrtype = adns_r_soa_raw; break;
    case DNS_TYPE_MX:    Rrtype = adns_r_mx_raw; break;
    case DNS_TYPE_TEXT:  Rrtype = adns_r_txt; break;
    case DNS_TYPE_SRV:   Rrtype = adns_r_srv_raw; break;
    default:             return ERROR_INVALID_PARAMETER;
    }

    *QueryResultSet = NULL;

    if ((Options & DNS_QUERY_NO_WIRE_QUERY) != 0)
        return ERROR_FILE_NOT_FOUND;

    Len = WideCharToMultiByte(CP_ACP, 0, Name, -1, NULL, 0, NULL, NULL);
    if (Len == 0)
        return ERROR_INVALID_NAME;
    AnsiName = RtlAllocateHeap(RtlGetProcessHeap(), 0, Len);
    if (AnsiName == NULL)
        return ERROR_OUTOFMEMORY;
    WideCharToMultiByte(CP_ACP, 0, Name, -1, AnsiName, Len, NULL, NULL);
    /* without the root label's dot (a name with it is fully qualified: no search suffix) */
    if (Len > 2 && AnsiName[Len - 2] == '.')
    {
        AnsiName[Len - 2] = '\0';
        Options |= DNS_QUERY_TREAT_AS_FQDN;
    }
    if ((Options & (DNS_QUERY_NO_RECURSION | DNS_QUERY_TREAT_AS_FQDN)) == 0)
        quflags |= adns_qf_search;

    Status = OpenResolver(AnsiName, Options, &astate, &quflags);
    if (Status != ERROR_SUCCESS)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
        return Status;
    }

    CurrentName = AnsiName;
    Status = ERROR_FILE_NOT_FOUND;
    for (CNameLoop = 0; CNameLoop < 16; CNameLoop++)
    {
        adns_error = adns_synchronous(astate, CurrentName, Rrtype, quflags, &answer);
        if (adns_error != adns_s_ok || answer == NULL)
        {
            Status = adns_error != adns_s_ok ? DnsIntTranslateAdnsToDNS_STATUS(adns_error) : ERROR_OUTOFMEMORY;
            break;
        }

        if (answer->status == adns_s_ok && answer->nrrs > 0)
        {
            Records = NULL;
            ApplyChainExpiry(answer, ChainExpires);
            Status = BuildTypedRecords(Name, Type, answer, &Records);
            if (Status == ERROR_SUCCESS)
                *QueryResultSet = (PDNS_RECORD)Records;
            free(answer);
            break;
        }

        if (answer->status == adns_s_prohibitedcname && answer->cname)
        {
            KeepChainExpiry(&ChainExpires, answer);
            NextName = (PCHAR)xstrsaveA(answer->cname);
            free(answer);
            if (CurrentName != AnsiName)
                RtlFreeHeap(RtlGetProcessHeap(), 0, CurrentName);
            if (!NextName)
            {
                CurrentName = AnsiName;
                Status = ERROR_OUTOFMEMORY;
                break;
            }
            CurrentName = NextName;
            continue;
        }

        if (answer->status == adns_s_nxdomain)
            Status = DNS_ERROR_RCODE_NAME_ERROR;
        else if (answer->status == adns_s_nodata)
            Status = DNS_INFO_NO_RECORDS;
        else if (answer->status < adns_s_max_tempfail)
            Status = ERROR_TIMEOUT;
        else
            Status = DNS_ERROR_RCODE_SERVER_FAILURE;
        free(answer);
        break;
    }

    adns_finish(astate);
    if (CurrentName != AnsiName)
        RtlFreeHeap(RtlGetProcessHeap(), 0, CurrentName);
    RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
    return Status;
}


DNS_STATUS
WINAPI
Query_Main(LPCWSTR Name,
           WORD Type,
           DWORD Options,
           PDNS_RECORD *QueryResultSet)
{
    adns_state astate;
    int quflags = (Options & (DNS_QUERY_NO_RECURSION | DNS_QUERY_TREAT_AS_FQDN)) == 0 ? adns_qf_search : 0;
    int adns_error;
    CHAR Search[512];
    adns_answer *answer;
    LPSTR CurrentName;
    unsigned CNameLoop;
    time_t ChainExpires = 0;
    PDNS_RECORDW ChainFirst = NULL, ChainLast = NULL;
    PFIXED_INFO network_info;
    ULONG network_info_blen = 0;
    DWORD network_info_result;
    PIP_ADDR_STRING pip;
    IP4_ADDRESS Address;
    struct in_addr addr;
    PCHAR HostWithDomainName;
    PCHAR AnsiName;
    size_t NameLen = 0;

    if (Name == NULL)
        return ERROR_INVALID_PARAMETER;
    if (QueryResultSet == NULL)
        return ERROR_INVALID_PARAMETER;

    *QueryResultSet = NULL;

    switch (Type)
    {
    case DNS_TYPE_A:
        /* FIXME: how much instead of MAX_PATH? */
        NameLen = WideCharToMultiByte(CP_ACP,
                                      0,
                                      Name,
                                      -1,
                                      NULL,
                                      0,
                                      NULL,
                                      0);
        AnsiName = RtlAllocateHeap(RtlGetProcessHeap(), 0, NameLen);
        if (NULL == AnsiName)
        {
            return ERROR_OUTOFMEMORY;
        }
        WideCharToMultiByte(CP_ACP,
                            0,
                            Name,
                            -1,
                            AnsiName,
                            NameLen,
                            NULL,
                            0);
        NameLen--;

        network_info_result = GetNetworkParams(NULL, &network_info_blen);
        network_info = (PFIXED_INFO)RtlAllocateHeap(RtlGetProcessHeap(), 0, (size_t)network_info_blen);
        if (NULL == network_info)
        {
            return ERROR_OUTOFMEMORY;
        }

        network_info_result = GetNetworkParams(network_info, &network_info_blen);
        if (network_info_result != ERROR_SUCCESS)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
            return network_info_result;
        }

        if ((Address = CheckForCurrentHostname(NameLen != 0 ? AnsiName : network_info->HostName, network_info)) != 0)
        {
            size_t TempLen = 2, StringLength = 0;
            RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
            StringCchLengthA(network_info->HostName, sizeof(network_info->HostName), &StringLength);
            TempLen += StringLength;
            StringCchLengthA(network_info->DomainName, sizeof(network_info->DomainName), &StringLength);
            TempLen += StringLength;
            HostWithDomainName = (PCHAR)RtlAllocateHeap(RtlGetProcessHeap(), 0, TempLen);
            StringCchCopyA(HostWithDomainName, TempLen, network_info->HostName);
            if (network_info->DomainName[0])
            {
                StringCchCatA(HostWithDomainName, TempLen, ".");
                StringCchCatA(HostWithDomainName, TempLen, network_info->DomainName);
            }
            RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
            *QueryResultSet = (PDNS_RECORD)RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DNS_RECORD));

            if (NULL == *QueryResultSet)
            {
                RtlFreeHeap(RtlGetProcessHeap(), 0, HostWithDomainName);
                return ERROR_OUTOFMEMORY;
            }

            (*QueryResultSet)->pNext = NULL;
            (*QueryResultSet)->wType = Type;
            (*QueryResultSet)->wDataLength = sizeof(DNS_A_DATA);
            (*QueryResultSet)->Flags.S.Section = DnsSectionAnswer;
            (*QueryResultSet)->Flags.S.CharSet = DnsCharSetUnicode;
            (*QueryResultSet)->Data.A.IpAddress = Address;

            (*QueryResultSet)->pName = (LPSTR)DnsCToW(HostWithDomainName);

            RtlFreeHeap(RtlGetProcessHeap(), 0, HostWithDomainName);
            return (*QueryResultSet)->pName ? ERROR_SUCCESS : ERROR_OUTOFMEMORY;
        }

        if ((Options & DNS_QUERY_NO_WIRE_QUERY) != 0)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
            RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
            return ERROR_FILE_NOT_FOUND;
        }

        adns_error = adns_init(&astate, adns_if_noenv | adns_if_noerrprint | adns_if_noserverwarn, 0);
        if (adns_error != adns_s_ok)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
            RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);
            return DnsIntTranslateAdnsToDNS_STATUS(adns_error);
        }
        for (pip = &(network_info->DnsServerList); pip; pip = pip->Next)
        {
            addr.s_addr = inet_addr(pip->IpAddress.String);
            if ((addr.s_addr != INADDR_ANY) && (addr.s_addr != INADDR_NONE))
                adns_addserver(astate, addr);
        }
        StringCchCopyA(Search, sizeof(Search), network_info->DomainName);
        AddIpv6Servers(astate, Search, sizeof(Search));
        if (Search[0])
        {
            adns_ccf_search(astate, "LOCALDOMAIN", -1, Search);
            /* see QueryAaaa: a name of one label is searched unless the caller said it is fully qualified */
            if (strchr(AnsiName, '.') == NULL && !(Options & DNS_QUERY_TREAT_AS_FQDN))
                quflags |= adns_qf_search;
        }
        RtlFreeHeap(RtlGetProcessHeap(), 0, network_info);

        if (!adns_numservers(astate))
        {
            /* There are no servers to query so bail out */
            adns_finish(astate);
            RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
            return ERROR_FILE_NOT_FOUND;
        }

        /*
        * adns doesn't resolve chained CNAME records (a CNAME which points to
        * another CNAME pointing to another... pointing to an A record), according
        * to a mailing list thread the authors believe that chained CNAME records
        * are invalid and the DNS entries should be fixed. That's a nice academic
        * standpoint, but there certainly are chained CNAME records out there,
        * even some fairly major ones (at the time of this writing
        * download.mozilla.org is a chained CNAME). Everyone else seems to resolve
        * these fine, so we should too. So we loop here to try to resolve CNAME
        * chains ourselves. Of course, there must be a limit to protect against
        * CNAME loops.
        */

#define CNAME_LOOP_MAX 16

        CurrentName = AnsiName;

        for (CNameLoop = 0; CNameLoop < CNAME_LOOP_MAX; CNameLoop++)
        {
            adns_error = adns_synchronous(astate, CurrentName, adns_r_addr, quflags, &answer);

            if (adns_error != adns_s_ok)
            {
                adns_finish(astate);

                if (CurrentName != AnsiName)
                    RtlFreeHeap(RtlGetProcessHeap(), 0, CurrentName);

                RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
                if (ChainFirst)
                    DnsIntFreeRecordList((PDNS_RECORD)ChainFirst);
                return DnsIntTranslateAdnsToDNS_STATUS(adns_error);
            }

            if (answer && answer->rrs.addr && answer->nrrs > 0)
            {
                PDNS_RECORDW First = NULL, Last = NULL;
                DNS_STATUS Result = ERROR_SUCCESS;
                int n;

                if (CurrentName != AnsiName)
                    RtlFreeHeap(RtlGetProcessHeap(), 0, CurrentName);

                RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);

                /* the CNAME record that adns followed itself (the last link of the chain) */
                if (answer->cname && !AppendChainLink(ChainOwner(Name, ChainLast), answer->cname, &ChainFirst, &ChainLast))
                    Result = ERROR_OUTOFMEMORY;

                /* one record for every address of the answer, in the order of the answer, owned by the end of the
                   chain (the name asked for when it is no alias) */
                for (n = 0; n < answer->nrrs && Result == ERROR_SUCCESS; n++)
                {
                    if (!AppendARecord(ChainOwner(Name, ChainLast),
                                       answer->rrs.addr[n].addr.inet.sin_addr.s_addr, &First, &Last))
                    {
                        Result = ERROR_OUTOFMEMORY;
                        break;
                    }
                }

                First = JoinChain(ChainFirst, ChainLast, First);
                ApplyChainExpiry(answer, ChainExpires);
                SetListTtl(First, AnswerTtl(answer));
                free(answer);
                adns_finish(astate);

                if (Result != ERROR_SUCCESS)
                {
                    if (First)
                        DnsIntFreeRecordList((PDNS_RECORD)First);
                    return Result;
                }

                *QueryResultSet = (PDNS_RECORD)First;
                return ERROR_SUCCESS;
            }

            if (NULL == answer || adns_s_prohibitedcname != answer->status || NULL == answer->cname)
            {
                /* The name servers said that the name (or the type) is not there: that is a status of its
                   own (the resolver service keeps it for a while), a failure to ask is not */
                DNS_STATUS Negative = ERROR_FILE_NOT_FOUND;

                if (answer && answer->status == adns_s_nxdomain)
                    Negative = DNS_ERROR_RCODE_NAME_ERROR;
                else if (answer && answer->status == adns_s_nodata)
                    Negative = DNS_INFO_NO_RECORDS;

                free(answer);
                adns_finish(astate);

                if (CurrentName != AnsiName)
                    RtlFreeHeap(RtlGetProcessHeap(), 0, CurrentName);

                RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
                if (ChainFirst)
                    DnsIntFreeRecordList((PDNS_RECORD)ChainFirst);
                return Negative;
            }

            if (CurrentName != AnsiName)
                RtlFreeHeap(RtlGetProcessHeap(), 0, CurrentName);

            /* a link of the chain: CurrentName is an alias of answer->cname, which is an alias too */
            KeepChainExpiry(&ChainExpires, answer);
            if (!AppendChainLink(ChainOwner(Name, ChainLast), answer->cname, &ChainFirst, &ChainLast))
                CurrentName = NULL;
            else
                CurrentName = (LPSTR)xstrsaveA(answer->cname);
            free(answer);

            if (!CurrentName)
            {
                RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
                adns_finish(astate);
                if (ChainFirst)
                    DnsIntFreeRecordList((PDNS_RECORD)ChainFirst);
                return ERROR_OUTOFMEMORY;
            }
        }

        adns_finish(astate);
        RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiName);
        RtlFreeHeap(RtlGetProcessHeap(), 0, CurrentName);
        if (ChainFirst)
            DnsIntFreeRecordList((PDNS_RECORD)ChainFirst);
        return ERROR_FILE_NOT_FOUND;

    case DNS_TYPE_PTR:
        return QueryPtr(Name, Options, QueryResultSet);

    case DNS_TYPE_AAAA:
        return QueryAaaa(Name, Options, QueryResultSet);

    case DNS_TYPE_CNAME:
    case DNS_TYPE_NS:
    case DNS_TYPE_SOA:
    case DNS_TYPE_MX:
    case DNS_TYPE_TEXT:
    case DNS_TYPE_SRV:
        return QueryTyped(Name, Type, Options, QueryResultSet);

    default:
        return ERROR_OUTOFMEMORY; /* XXX arty: find a better error code. */
    }
}

void
DnsIntFreeRecordList(PDNS_RECORD ToDelete)
{
    /* One implementation for every record type (the string arrays of the text types are part of the record) */
    DnsRecordListFree(ToDelete, DnsFreeRecordList);
}

BOOL
WINAPI
DnsFlushResolverCache(VOID)
{
    DNS_STATUS Status = ERROR_SUCCESS;

    DPRINT("DnsFlushResolverCache()\n");

    RpcTryExcept
    {
        Status = R_ResolverFlushCache(NULL);
        DPRINT("R_ResolverFlushCache() returned %lu\n", Status);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = RpcExceptionCode();
        DPRINT("Exception returned %lu\n", Status);
    }
    RpcEndExcept;

    return (Status == ERROR_SUCCESS);
}


BOOL
WINAPI
DnsFlushResolverCacheEntry_A(
    _In_ LPCSTR pszEntry)
{
    DNS_STATUS Status = ERROR_SUCCESS;
    LPWSTR pszUnicodeEntry;

    DPRINT1("DnsFlushResolverCacheEntry_A(%s)\n", pszEntry);

    if (pszEntry == NULL)
        return FALSE;

    pszUnicodeEntry = DnsCToW(pszEntry);
    if (pszUnicodeEntry == NULL)
        return FALSE;

    RpcTryExcept
    {
        Status = R_ResolverFlushCacheEntry(NULL, pszUnicodeEntry, DNS_TYPE_ANY);
        DPRINT("R_ResolverFlushCacheEntry() returned %lu\n", Status);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = RpcExceptionCode();
        DPRINT("Exception returned %lu\n", Status);
    }
    RpcEndExcept;

    RtlFreeHeap(RtlGetProcessHeap(), 0, pszUnicodeEntry);

    return (Status == ERROR_SUCCESS);
}


BOOL
WINAPI
DnsFlushResolverCacheEntry_UTF8(
    _In_ LPCSTR pszEntry)
{
    DNS_STATUS Status = ERROR_SUCCESS;
    LPWSTR pszUnicodeEntry;

    DPRINT1("DnsFlushResolverCacheEntry_UTF8(%s)\n", pszEntry);

    if (pszEntry == NULL)
        return FALSE;

    pszUnicodeEntry = DnsCToW(pszEntry);
    if (pszUnicodeEntry == NULL)
        return FALSE;

    RpcTryExcept
    {
        Status = R_ResolverFlushCacheEntry(NULL, pszUnicodeEntry, DNS_TYPE_ANY);
        DPRINT("R_ResolverFlushCacheEntry() returned %lu\n", Status);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = RpcExceptionCode();
        DPRINT("Exception returned %lu\n", Status);
    }
    RpcEndExcept;

    RtlFreeHeap(RtlGetProcessHeap(), 0, pszUnicodeEntry);

    return (Status == ERROR_SUCCESS);
}


BOOL
WINAPI
DnsFlushResolverCacheEntry_W(
    _In_ LPCWSTR pszEntry)
{
    DNS_STATUS Status = ERROR_SUCCESS;

    DPRINT1("DnsFlushResolverCacheEntry_W(%S)\n", pszEntry);

    if (pszEntry == NULL)
        return FALSE;

    RpcTryExcept
    {
        Status = R_ResolverFlushCacheEntry(NULL, pszEntry, DNS_TYPE_ANY);
        DPRINT("R_ResolverFlushCacheEntry() returned %lu\n", Status);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = RpcExceptionCode();
        DPRINT("Exception returned %lu\n", Status);
    }
    RpcEndExcept;

    return (Status == ERROR_SUCCESS);
}


/* The entries of a page, which the RPC allocated entry by entry, are freed the same way */
static
VOID
FreeCacheEntries(
    _In_ PDNS_CACHE_ENTRY Entry)
{
    PDNS_CACHE_ENTRY Next;

    for (; Entry; Entry = Next)
    {
        Next = Entry->pNext;
        if (Entry->pszName)
            midl_user_free(Entry->pszName);
        midl_user_free(Entry);
    }
}

/* The most entries of one page: the marshalling of a linked list takes about half a kilobyte of the stack of the
   caller for every element, so the pages are short enough for the smallest stacks and the list as a whole is not
   limited by the stack */
#define CACHE_PAGE_ENTRIES  200

BOOL
WINAPI
DnsGetCacheDataTable(
    _Out_ PDNS_CACHE_ENTRY *DnsCache)
{
    DNS_STATUS Status = ERROR_SUCCESS;
    PDNS_CACHE_ENTRY CacheEntries = NULL, Page, Tail = NULL;
    ULONGLONG After = 0, Next;
    BOOL bFirst = TRUE;

    if (DnsCache == NULL)
        return FALSE;

    for (;;)
    {
        Page = NULL;
        Next = After;

        RpcTryExcept
        {
            Status = NitroReadCachePage(NULL, After, CACHE_PAGE_ENTRIES, &Page, &Next);
            DPRINT("NitroReadCachePage() returned %lu\n", Status);
        }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = RpcExceptionCode();
            DPRINT("Exception returned %lu\n", Status);
        }
        RpcEndExcept;

        /* A service of an older build has no paged call: its whole list (cut at a few thousand entries) */
        if (bFirst && (Status == RPC_S_PROCNUM_OUT_OF_RANGE || Status == RPC_S_UNKNOWN_IF))
        {
            Page = NULL;
            RpcTryExcept
            {
                Status = CRrReadCache(NULL, &Page);
                DPRINT("CRrReadCache() returned %lu\n", Status);
            }
            RpcExcept(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = RpcExceptionCode();
                DPRINT1("Exception returned %lu\n", Status);
            }
            RpcEndExcept;

            if (Status != ERROR_SUCCESS)
            {
                FreeCacheEntries(Page);
                return FALSE;
            }
            CacheEntries = Page;
            break;
        }
        bFirst = FALSE;

        if (Status != ERROR_SUCCESS)
        {
            FreeCacheEntries(Page);
            FreeCacheEntries(CacheEntries);
            return FALSE;
        }

        /* an empty page is the end of the list (and a key that does not move would never end) */
        if (Page == NULL || Next <= After)
        {
            FreeCacheEntries(Page);
            break;
        }

        if (Tail)
            Tail->pNext = Page;
        else
            CacheEntries = Page;
        for (Tail = Page; Tail->pNext; Tail = Tail->pNext)
            ;
        After = Next;
    }

    if (CacheEntries == NULL)
        return FALSE;

    *DnsCache = CacheEntries;

    return TRUE;
}

DWORD
WINAPI
GetCurrentTimeInSeconds(VOID)
{
    FILETIME Time;
    FILETIME Adjustment;
    ULARGE_INTEGER lTime, lAdj;
    SYSTEMTIME st = {1970, 1, 0, 1, 0, 0, 0};

    SystemTimeToFileTime(&st, &Adjustment);
    memcpy(&lAdj, &Adjustment, sizeof(lAdj));
    GetSystemTimeAsFileTime(&Time);
    memcpy(&lTime, &Time, sizeof(lTime));
    lTime.QuadPart -= lAdj.QuadPart;
    return (DWORD)(lTime.QuadPart/10000000ULL);
}
