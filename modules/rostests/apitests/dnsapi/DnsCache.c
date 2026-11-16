/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The cache of the DNS resolver service (Dnscache): the TTL of an answer is honoured (counted down,
 *              capped by MaxCacheTtl, expired), negative answers are kept for MaxNegativeCacheTtl, DNS_QUERY_BYPASS_CACHE,
 *              the flush calls, the size bound with least-recently-used eviction, the memory of the service under
 *              many distinct names, and the cost of a lookup with a full cache
 *
 * Needs the DNS server of the harness that the machine uses as its name server (dnscache_srv.py: names under
 * cache.test, TTL in the first label, a counter of the queries per name that the test reads with a query of its own
 * to the same server); without it the test is skipped (the first query is the probe). The name of every check is
 * unique (the tick count), so a second run does not meet the entries of the first.
 *
 * Environment: DNSCACHE_BIG=N, the number of distinct names of the size test (default 50000); DNSCACHE_TAG=text,
 * used instead of the tick count in every name (runs that share one server at the same time need different ones).
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <windns.h>
#include <windns_undoc.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <winsvc.h>
#include <apitest.h>

BOOL WINAPI DnsFlushResolverCache(VOID);
BOOL WINAPI DnsFlushResolverCacheEntry_W(LPCWSTR);
BOOL WINAPI DnsGetCacheDataTable(PDNS_CACHE_ENTRY *);

#define PARAMS_KEY "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters"

static char Uniq[32];
static struct sockaddr_in ServerAddr;

/* The first name server of the machine */
static
void
FindServer(void)
{
    PFIXED_INFO Info;
    ULONG Size = 0;

    ServerAddr.sin_family = AF_INET;
    ServerAddr.sin_port = htons(53);
    ServerAddr.sin_addr.s_addr = inet_addr("10.0.2.2");

    GetNetworkParams(NULL, &Size);
    Info = malloc(Size ? Size : 1);
    if (Info && GetNetworkParams(Info, &Size) == ERROR_SUCCESS &&
        Info->DnsServerList.IpAddress.String[0] &&
        inet_addr(Info->DnsServerList.IpAddress.String) != INADDR_NONE &&
        inet_addr(Info->DnsServerList.IpAddress.String) != 0)
    {
        ServerAddr.sin_addr.s_addr = inet_addr(Info->DnsServerList.IpAddress.String);
    }
    free(Info);
}

static
int
BuildQuery(UCHAR *Packet, const char *Name, USHORT Type)
{
    int Pos = 12;
    const char *Dot;

    memset(Packet, 0, 12);
    Packet[0] = 0x4d;
    Packet[1] = 0x31;
    Packet[2] = 0x01;
    Packet[5] = 1;
    while (*Name)
    {
        Dot = strchr(Name, '.');
        if (!Dot)
            Dot = Name + strlen(Name);
        Packet[Pos++] = (UCHAR)(Dot - Name);
        memcpy(Packet + Pos, Name, Dot - Name);
        Pos += (int)(Dot - Name);
        Name = *Dot ? Dot + 1 : Dot;
    }
    Packet[Pos++] = 0;
    Packet[Pos++] = (UCHAR)(Type >> 8);
    Packet[Pos++] = (UCHAR)Type;
    Packet[Pos++] = 0;
    Packet[Pos++] = 1;
    return Pos;
}

/* How many times the server has been asked for the name (any type); -1 when it does not answer */
static
int
ServerCount(const char *Name)
{
    UCHAR Packet[600], Reply[600];
    char Control[300];
    SOCKET s;
    int Len, Got, Pos;
    DWORD Timeout = 3000;

    _snprintf(Control, sizeof(Control), "c.%s.ctl.test", Name);
    Len = BuildQuery(Packet, Control, 1);
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return -1;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
    if (sendto(s, (const char *)Packet, Len, 0, (struct sockaddr *)&ServerAddr, sizeof(ServerAddr)) != Len)
    {
        closesocket(s);
        return -1;
    }
    Got = recv(s, (char *)Reply, sizeof(Reply), 0);
    closesocket(s);
    if (Got < Len + 16)
        return -1;
    /* header, question, then the answer: owner (pointer), type, class, ttl, rdlength, rdata */
    Pos = Len + 2 + 2 + 2 + 4 + 2;
    return (Reply[Pos + 2] << 8) | Reply[Pos + 3];
}

typedef struct
{
    DNS_STATUS Status;
    DWORD Ttl;
    int Last;       /* last octet of the A record, last 16-bit group of the AAAA record, 0 when none */
} QRESULT;

static
QRESULT
Query(const char *Name, WORD Type, DWORD Flags)
{
    WCHAR NameW[300];
    PDNS_RECORD Record = NULL;
    QRESULT R;

    MultiByteToWideChar(CP_ACP, 0, Name, -1, NameW, ARRAYSIZE(NameW));
    R.Ttl = 0;
    R.Last = 0;
    R.Status = DnsQuery_W(NameW, Type, Flags, NULL, &Record, NULL);
    if (R.Status == ERROR_SUCCESS && Record)
    {
        R.Ttl = Record->dwTtl;
        if (Record->wType == DNS_TYPE_A)
            R.Last = ((PUCHAR)&Record->Data.A.IpAddress)[3];
        else if (Record->wType == DNS_TYPE_AAAA)
            R.Last = ((PUCHAR)&Record->Data.AAAA.Ip6Address)[15];
        DnsRecordListFree(Record, DnsFreeRecordList);
    }
    return R;
}

static
const char *
MakeName(const char *Prefix, const char *Tag)
{
    static char Buffer[8][128];
    static int Index;
    char *Out = Buffer[Index++ & 7];

    _snprintf(Out, 128, "%s-%s-%s.cache.test", Prefix, Tag, Uniq);
    return Out;
}

/* Sets (Value != -1) or removes (-1) a value of the Dnscache parameters and tells the service */
static
void
SetParam(const char *ValueName, LONG Value)
{
    HKEY Key;
    SC_HANDLE Scm, Svc;
    SERVICE_STATUS Status;

    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, PARAMS_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &Key, NULL) == ERROR_SUCCESS)
    {
        if (Value == -1)
            RegDeleteValueA(Key, ValueName);
        else
            RegSetValueExA(Key, ValueName, 0, REG_DWORD, (const BYTE *)&Value, sizeof(Value));
        RegCloseKey(Key);
    }
    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (Scm)
    {
        Svc = OpenServiceW(Scm, L"Dnscache", SERVICE_PAUSE_CONTINUE);
        if (Svc)
        {
            ControlService(Svc, SERVICE_CONTROL_PARAMCHANGE, &Status);
            CloseServiceHandle(Svc);
        }
        CloseServiceHandle(Scm);
    }
    Sleep(300);
}

static
void
EnableDebugPrivilege(void)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Tp;

    /* the service runs under another account: its process is opened with this privilege */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
    {
        Tp.PrivilegeCount = 1;
        Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &Tp.Privileges[0].Luid))
            AdjustTokenPrivileges(Token, FALSE, &Tp, sizeof(Tp), NULL, NULL);
        CloseHandle(Token);
    }
}

static
ULONG_PTR
ServicePrivateBytes(void)
{
    typedef BOOL (WINAPI *PGMI)(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
    SC_HANDLE Scm, Svc;
    SERVICE_STATUS_PROCESS Ssp;
    DWORD Needed;
    HANDLE Process;
    PROCESS_MEMORY_COUNTERS_EX Counters;
    ULONG_PTR Result = 0;
    HMODULE Psapi = LoadLibraryW(L"psapi.dll");
    PGMI GetInfo = Psapi ? (PGMI)GetProcAddress(Psapi, "GetProcessMemoryInfo") : NULL;

    if (!GetInfo)
        return 0;
    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!Scm)
        return 0;
    Svc = OpenServiceW(Scm, L"Dnscache", SERVICE_QUERY_STATUS);
    if (Svc)
    {
        if (QueryServiceStatusEx(Svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&Ssp, sizeof(Ssp), &Needed) && Ssp.dwProcessId)
        {
            Process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Ssp.dwProcessId);
            if (Process)
            {
                Counters.cb = sizeof(Counters);
                if (GetInfo(Process, (PPROCESS_MEMORY_COUNTERS)&Counters, sizeof(Counters)))
                    Result = Counters.PrivateUsage;
                CloseHandle(Process);
            }
        }
        CloseServiceHandle(Svc);
    }
    CloseServiceHandle(Scm);
    return Result;
}

static
int
CacheEntryCount(void)
{
    PDNS_CACHE_ENTRY Table = NULL, Entry;
    int Count = 0;

    if (!DnsGetCacheDataTable(&Table))
        return 0;
    for (Entry = Table; Entry; Entry = Entry->pNext)
        Count++;
    return Count;
}

static
void
TestTtl(void)
{
    QRESULT R1, R2, R3, R4;
    const char *N;

    /* the answer is kept for its TTL: one query to the server, the TTL counts down, then a new query */
    N = MakeName("ttl4", "life");
    R1 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R1.Status == ERROR_SUCCESS, "first query: %lu\n", R1.Status);
    ok(R1.Last == 1, "first answer is #%d\n", R1.Last);
    ok(R1.Ttl >= 1 && R1.Ttl <= 4, "first TTL %lu\n", R1.Ttl);
    Sleep(1200);
    R2 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R2.Status == ERROR_SUCCESS && R2.Last == 1, "second query from the cache: %lu #%d\n", R2.Status, R2.Last);
    ok(ServerCount(N) == 1, "the server was asked %d times, expected 1\n", ServerCount(N));
    ok(R2.Ttl >= 1 && R2.Ttl <= 3, "TTL after 1.2 s of 4: %lu\n", R2.Ttl);
    Sleep(4000);
    R3 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R3.Status == ERROR_SUCCESS && R3.Last == 2, "after the TTL: %lu #%d (expected a new answer, #2)\n", R3.Status, R3.Last);
    ok(ServerCount(N) == 2, "the server was asked %d times, expected 2\n", ServerCount(N));

    /* the cache-only query (what ipconfig /displaydns does) gives the time that is left */
    N = MakeName("ttl100", "left");
    R1 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R1.Status == ERROR_SUCCESS, "query: %lu\n", R1.Status);
    Sleep(3000);
    R4 = Query(N, DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY);
    ok(R4.Status == ERROR_SUCCESS, "cache-only query: %lu\n", R4.Status);
    ok(R4.Ttl >= 90 && R4.Ttl <= 97, "TTL left after 3 s of 100: %lu\n", R4.Ttl);
    ok(ServerCount(N) == 1, "the server was asked %d times\n", ServerCount(N));

    /* a name that is not in the cache: nothing, and no query */
    R4 = Query(MakeName("ttl100", "never"), DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY);
    ok(R4.Status == DNS_INFO_NO_RECORDS, "cache-only query of an unknown name: %lu\n", R4.Status);
    ok(ServerCount(MakeName("ttl100", "never")) == 0, "the server was asked for it\n");

    /* DNS_QUERY_BYPASS_CACHE asks again and keeps the new answer */
    N = MakeName("ttl300", "bypass");
    R1 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    R2 = Query(N, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE);
    R3 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R1.Last == 1 && R2.Last == 2 && R3.Last == 2, "bypass: #%d #%d #%d, expected 1 2 2\n", R1.Last, R2.Last, R3.Last);
    ok(ServerCount(N) == 2, "bypass: the server was asked %d times, expected 2\n", ServerCount(N));
}

static
void
TestMaxCacheTtl(void)
{
    QRESULT R1, R2, R3;
    const char *N = MakeName("ttl300", "cap");

    SetParam("MaxCacheTtl", 3);
    R1 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    R2 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R1.Status == ERROR_SUCCESS && R1.Last == 1, "query: %lu #%d\n", R1.Status, R1.Last);
    ok(R2.Status == ERROR_SUCCESS && R2.Last == 1 && R2.Ttl >= 1 && R2.Ttl <= 3,
       "capped entry: %lu #%d TTL %lu (TTL 300, MaxCacheTtl 3)\n", R2.Status, R2.Last, R2.Ttl);
    Sleep(4500);
    R3 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R3.Status == ERROR_SUCCESS && R3.Last == 2, "after MaxCacheTtl: %lu #%d, expected #2\n", R3.Status, R3.Last);
    SetParam("MaxCacheTtl", -1);
}

static
void
TestNegative(void)
{
    QRESULT R1, R2, R3, R4;
    const char *N;

    SetParam("MaxNegativeCacheTtl", 3);

    /* a name that does not exist: kept, for every type, and gone after the negative TTL */
    N = MakeName("nx", "a");
    R1 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    R2 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R1.Status == DNS_ERROR_RCODE_NAME_ERROR, "NXDOMAIN: %lu\n", R1.Status);
    ok(R2.Status == DNS_ERROR_RCODE_NAME_ERROR, "NXDOMAIN again: %lu\n", R2.Status);
    ok(ServerCount(N) == 1, "NXDOMAIN: the server was asked %d times, expected 1\n", ServerCount(N));
    R3 = Query(N, DNS_TYPE_AAAA, DNS_QUERY_STANDARD);
    ok(R3.Status == DNS_ERROR_RCODE_NAME_ERROR, "AAAA of a name that does not exist: %lu\n", R3.Status);
    ok(ServerCount(N) == 1, "AAAA of a name that does not exist: the server was asked %d times, expected 1\n", ServerCount(N));
    R3 = Query(N, DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY);
    ok(R3.Status == DNS_ERROR_RCODE_NAME_ERROR, "cache-only query of the negative entry: %lu\n", R3.Status);
    Sleep(4500);
    R4 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R4.Status == DNS_ERROR_RCODE_NAME_ERROR, "NXDOMAIN after the negative TTL: %lu\n", R4.Status);
    ok(ServerCount(N) == 2, "NXDOMAIN after the negative TTL: the server was asked %d times, expected 2\n", ServerCount(N));

    /* a name without a record of the type: kept for that type only */
    N = MakeName("nodata", "a");
    R1 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    R2 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R1.Status == DNS_INFO_NO_RECORDS && R2.Status == DNS_INFO_NO_RECORDS, "NODATA: %lu %lu\n", R1.Status, R2.Status);
    ok(ServerCount(N) == 1, "NODATA: the server was asked %d times, expected 1\n", ServerCount(N));
    R3 = Query(N, DNS_TYPE_AAAA, DNS_QUERY_STANDARD);
    ok(R3.Status == DNS_INFO_NO_RECORDS, "NODATA of another type: %lu\n", R3.Status);
    ok(ServerCount(N) == 2, "NODATA of another type: the server was asked %d times, expected 2\n", ServerCount(N));

    /* a positive answer replaces the negative one of the name (the name exists now) */
    DnsFlushResolverCache();
    N = MakeName("ttl300", "pos");
    R1 = Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(R1.Status == ERROR_SUCCESS, "positive answer: %lu\n", R1.Status);

    /* MaxNegativeCacheTtl 0: no negative caching */
    SetParam("MaxNegativeCacheTtl", 0);
    N = MakeName("nx", "off");
    Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(ServerCount(N) == 2, "negative cache off: the server was asked %d times, expected 2\n", ServerCount(N));

    SetParam("MaxNegativeCacheTtl", -1);

    /* the default (900 s): an entry is still there after a few seconds */
    N = MakeName("nx", "default");
    Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    Sleep(4500);
    Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(ServerCount(N) == 1, "default negative TTL: the server was asked %d times, expected 1\n", ServerCount(N));
}

static
void
TestFlush(void)
{
    QRESULT R, Hosts;
    const char *N, *M;
    WCHAR NameW[300];

    N = MakeName("ttl300", "flush");
    Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(ServerCount(N) == 1, "before the flush: asked %d times\n", ServerCount(N));
    Hosts = Query("localhost", DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY);
    ok(DnsFlushResolverCache(), "DnsFlushResolverCache failed\n");
    if (Hosts.Status == ERROR_SUCCESS)
    {
        /* the rows of the hosts file are not part of what the flush drops */
        R = Query("localhost", DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY);
        ok(R.Status == ERROR_SUCCESS, "hosts row of localhost after the flush: %lu\n", R.Status);
    }
    R = Query(N, DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY);
    ok(R.Status == DNS_INFO_NO_RECORDS, "cache-only query after the flush: %lu\n", R.Status);
    Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    ok(ServerCount(N) == 2, "after the flush: asked %d times, expected 2\n", ServerCount(N));

    /* one name: every entry of it goes (A and AAAA), whatever the case */
    N = MakeName("multi", "flushname");
    Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    Query(N, DNS_TYPE_AAAA, DNS_QUERY_STANDARD);
    Query(N, DNS_TYPE_A, DNS_QUERY_STANDARD);
    Query(N, DNS_TYPE_AAAA, DNS_QUERY_STANDARD);
    ok(ServerCount(N) == 2, "A and AAAA cached: asked %d times, expected 2\n", ServerCount(N));
    {
        char Upper[200];
        int i;

        for (i = 0; N[i]; i++)
            Upper[i] = (char)toupper((unsigned char)N[i]);
        Upper[i] = 0;
        MultiByteToWideChar(CP_ACP, 0, Upper, -1, NameW, ARRAYSIZE(NameW));
    }
    ok(DnsFlushResolverCacheEntry_W(NameW), "DnsFlushResolverCacheEntry_W failed\n");
    R = Query(N, DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY);
    ok(R.Status == DNS_INFO_NO_RECORDS, "A after the flush of the name: %lu\n", R.Status);
    R = Query(N, DNS_TYPE_AAAA, DNS_QUERY_NO_WIRE_QUERY);
    ok(R.Status == DNS_INFO_NO_RECORDS, "AAAA after the flush of the name: %lu\n", R.Status);

    /* a reverse name flushed with the dot of the root label (and without) */
    M = "7.2.0.192.in-addr.arpa";
    Query(M, DNS_TYPE_PTR, DNS_QUERY_STANDARD);
    Query(M, DNS_TYPE_PTR, DNS_QUERY_STANDARD);
    ok(ServerCount(M) >= 1, "reverse name: server not asked\n");
    MultiByteToWideChar(CP_ACP, 0, "7.2.0.192.IN-ADDR.ARPA.", -1, NameW, ARRAYSIZE(NameW));
    ok(DnsFlushResolverCacheEntry_W(NameW), "flush of the reverse name failed\n");
    R = Query(M, DNS_TYPE_PTR, DNS_QUERY_NO_WIRE_QUERY);
    ok(R.Status == DNS_INFO_NO_RECORDS, "reverse entry after a flush of the name with the dot: %lu\n", R.Status);
}

/* The average time of Iterations lookups of the name (microseconds) */
static
double
LookupCost(const char *N, WORD Type, DWORD Flags, int Iterations)
{
    LARGE_INTEGER Freq, T0, T1;
    int i;

    QueryPerformanceFrequency(&Freq);
    QueryPerformanceCounter(&T0);
    for (i = 0; i < Iterations; i++)
        Query(N, Type, Flags);
    QueryPerformanceCounter(&T1);
    return (double)(T1.QuadPart - T0.QuadPart) * 1000000.0 / (double)Freq.QuadPart / Iterations;
}

/*
 * Size bound, memory, LRU, lookup cost.
 *
 * The memory of the service grows with every query that goes to a DNS server, cache or not (a few hundred bytes of
 * the socket layer per query, measured separately: not the subject here). So the bound is measured against that:
 * the growth over the last Window distinct names must not be more than the growth over Window queries of one name
 * that replace one entry (the cache does not grow) plus a margin.
 */
static
void
TestSize(int Names)
{
    char Buffer[160];
    const char *Hot = MakeName("big", "hot"), *Same = MakeName("ttl300", "same");
    ULONG_PTR MemA = 0, MemB, MemC, Fixed;
    int i, k, Window = Names / 2 > 20000 ? 20000 : Names / 2, Cached = 0, Evicted = 0;
    DWORD Start = GetTickCount();
    double Us;

    DnsFlushResolverCache();
    Query(Hot, DNS_TYPE_A, DNS_QUERY_STANDARD);

    for (i = 0; i < Names; i++)
    {
        _snprintf(Buffer, sizeof(Buffer), "big-%s-%d.cache.test", Uniq, i);
        Query(Buffer, DNS_TYPE_A, DNS_QUERY_STANDARD);
        if (i % 50 == 0)
            Query(Hot, DNS_TYPE_A, DNS_QUERY_STANDARD);
        if (i == Names - Window)
            MemA = ServicePrivateBytes();
        if (i == 9999)
        {
            /* what a lookup costs with 10000 names asked: the newest entry (the end of a list), a name that is not there */
            trace("10000 names asked: lookup of the newest name %.1f us, of an unknown name %.1f us (cache only, 1000 queries each)\n",
                  LookupCost(Buffer, DNS_TYPE_A, DNS_QUERY_STANDARD, 1000),
                  LookupCost(MakeName("ttl100", "unknown"), DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY, 1000));
        }
    }
    MemB = ServicePrivateBytes();
    trace("%d distinct names in %lu ms; service private bytes %lu KB at name %d, %lu KB at the end\n",
          Names, GetTickCount() - Start, (unsigned long)(MemA / 1024), Names - Window, (unsigned long)(MemB / 1024));

    /* the control: the same number of queries that replace one entry */
    Query(Same, DNS_TYPE_A, DNS_QUERY_STANDARD);
    for (i = 0; i < Window; i++)
        Query(Same, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE);
    MemC = ServicePrivateBytes();
    Fixed = MemC - MemB;
    trace("service growth over %d new names: %ld KB; over %d queries of one name that replace one entry: %ld KB\n",
          Window, (long)((MemB - MemA) / 1024), Window, (long)(Fixed / 1024));
    ok(MemA == 0 || (long)(MemB - MemA) <= (long)Fixed + 2 * 1024 * 1024,
       "the cache grew the service by %ld KB over the last %d names (a bounded cache: about the %ld KB of %d queries that replace one entry)\n",
       (long)((MemB - MemA) / 1024) - (long)(Fixed / 1024), Window, (long)(Fixed / 1024), Window);

    /* the newest names are in the cache, the oldest are gone (the cache-only query tells without asking a server) */
    for (k = 1; k <= 200; k++)
    {
        _snprintf(Buffer, sizeof(Buffer), "big-%s-%d.cache.test", Uniq, Names - 1 - k * 10);
        if (Query(Buffer, DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY).Status == ERROR_SUCCESS)
            Cached++;
    }
    ok(Cached == 200, "of the 200 newest names %d were still cached\n", Cached);
    if (Names > 12000)
    {
        for (k = 0; k < 200; k++)
        {
            _snprintf(Buffer, sizeof(Buffer), "big-%s-%d.cache.test", Uniq, k * 10);
            if (Query(Buffer, DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY).Status != ERROR_SUCCESS)
                Evicted++;
        }
        ok(Evicted == 200, "of 200 of the oldest names %d were gone from the cache, expected all\n", Evicted);
    }
    k = CacheEntryCount();
    trace("entries listed by DnsGetCacheDataTable (ipconfig /displaydns): %d\n", k);
    ok(k > 1000 && k <= 3000, "DnsGetCacheDataTable listed %d entries with a full cache, expected a list of some thousand at most\n", k);

    /* the name in use stays (the least recently used goes first) */
    ok(Query(Hot, DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY).Status == ERROR_SUCCESS, "the name in use is not in the cache\n");

    /* lookups with a full cache: the newest entry (the end of a list), a name that is not there */
    _snprintf(Buffer, sizeof(Buffer), "big-%s-%d.cache.test", Uniq, Names - 1);
    Query(Buffer, DNS_TYPE_A, DNS_QUERY_STANDARD);
    Us = LookupCost(Buffer, DNS_TYPE_A, DNS_QUERY_STANDARD, 2000);
    trace("lookup of the newest name: %.1f us per query (2000 queries)\n", Us);
    ok(Us < 5000.0, "a cached lookup took %.1f us\n", Us);
    Us = LookupCost(MakeName("ttl100", "unknown2"), DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY, 2000);
    trace("lookup of an unknown name: %.1f us per query (cache only, 2000 queries)\n", Us);
}

START_TEST(DnsCache)
{
    WSADATA Wsa;
    QRESULT Probe;
    int Names = 50000;
    char Probename[128];

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    EnableDebugPrivilege();
    {
        /* concurrent runs on one test server must not meet the names of each other: DNSCACHE_TAG tells them apart */
        const char *Tag = getenv("DNSCACHE_TAG");

        if (Tag && Tag[0])
            _snprintf(Uniq, sizeof(Uniq), "%s", Tag);
        else
            _snprintf(Uniq, sizeof(Uniq), "%lx", (unsigned long)GetTickCount());
    }
    FindServer();
    {
        const char *Env = getenv("DNSCACHE_BIG");

        if (Env && atoi(Env) > 0)
            Names = atoi(Env);
    }

    /* the probe: a query of a name of the test server */
    _snprintf(Probename, sizeof(Probename), "ttl30-probe-%s.cache.test", Uniq);
    Probe = Query(Probename, DNS_TYPE_A, DNS_QUERY_STANDARD);
    if (Probe.Status != ERROR_SUCCESS || ServerCount(Probename) != 1)
    {
        skip("no test DNS server (probe: status %lu, server count %d)\n", Probe.Status, ServerCount(Probename));
        WSACleanup();
        return;
    }
    TestTtl();
    TestMaxCacheTtl();
    TestNegative();
    TestFlush();
    TestSize(Names);

    SetParam("MaxCacheTtl", -1);
    SetParam("MaxNegativeCacheTtl", -1);
    WSACleanup();
}
