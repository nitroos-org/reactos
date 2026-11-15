/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DnsQuery_A / DnsQuery_UTF8 / DnsQuery_W for every record type, field by field, and the
 *              wide-to-narrow record conversion that DnsQuery_A / DnsQuery_UTF8 use
 *
 * The query part needs a DNS server that answers the test names (the "dnscp" test server of the harness:
 * names ending in .dnscp.test, fixed data per type, TTL 300) and that the machine uses as its DNS server.
 * Without it the query part is skipped (the first query is the probe). The conversion part needs nothing.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windns.h>
#include <apitest.h>

/* A narrow copy (ASCII only) of a record string in the given character set */
static
const char *
Narrow(DNS_CHARSET CharSet, const void *String, char *Buffer, size_t Size)
{
    size_t i;

    if (String == NULL)
        return "(null)";
    if (CharSet == DnsCharSetUnicode)
    {
        const WCHAR *W = String;
        for (i = 0; W[i] && i + 1 < Size; i++)
            Buffer[i] = (char)W[i];
        Buffer[i] = 0;
        return Buffer;
    }
    return String;
}

#define STR_IS(cs, p, expected, what) \
    do { char buf_[256]; \
         ok(strcmp(Narrow(cs, p, buf_, sizeof(buf_)), expected) == 0, \
            "%s: " what " is '%s', expected '%s'\n", Label, Narrow(cs, p, buf_, sizeof(buf_)), expected); } while (0)

static
void
CheckHeader(const char *Label, PDNS_RECORD R, DNS_CHARSET CharSet, WORD Type, const char *Name)
{
    ok(R->wType == Type, "%s: type %u, expected %u\n", Label, R->wType, Type);
    ok(R->Flags.S.CharSet == CharSet, "%s: charset %u, expected %u\n", Label, (unsigned)R->Flags.S.CharSet, (unsigned)CharSet);
    ok(R->Flags.S.Section == DnsSectionAnswer, "%s: section %u\n", Label, (unsigned)R->Flags.S.Section);
    ok(R->dwReserved == 0, "%s: reserved %lu\n", Label, R->dwReserved);
    ok(R->dwTtl <= 300, "%s: ttl %lu (the server sends 300)\n", Label, R->dwTtl);
    if (Name)
        STR_IS(CharSet, R->pName, Name, "owner name");
}

/* The data of the typed answers of the test server (see dnscp.py) */
static
void
CheckData(const char *Label, PDNS_RECORD R, DNS_CHARSET CharSet)
{
    static const BYTE Aaaa[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };

    switch (R->wType)
    {
    case DNS_TYPE_A:
        ok(R->wDataLength == sizeof(DNS_A_DATA), "%s: data length %u\n", Label, R->wDataLength);
        ok(R->Data.A.IpAddress == inet_addr("192.0.2.10"), "%s: address %08lx\n", Label, R->Data.A.IpAddress);
        break;
    case DNS_TYPE_AAAA:
        ok(R->wDataLength == sizeof(DNS_AAAA_DATA), "%s: data length %u\n", Label, R->wDataLength);
        ok(memcmp(&R->Data.AAAA.Ip6Address, Aaaa, 16) == 0, "%s: AAAA address differs\n", Label);
        break;
    case DNS_TYPE_CNAME:
        ok(R->wDataLength == sizeof(DNS_PTR_DATA), "%s: data length %u\n", Label, R->wDataLength);
        STR_IS(CharSet, R->Data.CNAME.pNameHost, "target.dnscp.test", "target");
        break;
    case DNS_TYPE_PTR:
        ok(R->wDataLength == sizeof(DNS_PTR_DATA), "%s: data length %u\n", Label, R->wDataLength);
        STR_IS(CharSet, R->Data.PTR.pNameHost, "host-ptr.dnscp.test", "host");
        break;
    case DNS_TYPE_NS:
        STR_IS(CharSet, R->Data.NS.pNameHost, "ns1.dnscp.test", "name server");
        break;
    case DNS_TYPE_MX:
        ok(R->wDataLength == sizeof(DNS_MX_DATA), "%s: data length %u\n", Label, R->wDataLength);
        ok(R->Data.MX.wPreference == 10, "%s: preference %u\n", Label, R->Data.MX.wPreference);
        STR_IS(CharSet, R->Data.MX.pNameExchange, "mail.dnscp.test", "exchange");
        break;
    case DNS_TYPE_TEXT:
        ok(R->Data.TXT.dwStringCount == 2, "%s: %lu strings\n", Label, R->Data.TXT.dwStringCount);
        if (R->Data.TXT.dwStringCount == 2)
        {
            STR_IS(CharSet, R->Data.TXT.pStringArray[0], "hello", "string 0");
            STR_IS(CharSet, R->Data.TXT.pStringArray[1], "world", "string 1");
        }
        break;
    case DNS_TYPE_HINFO:
        ok(R->Data.HINFO.dwStringCount == 2, "%s: %lu strings\n", Label, R->Data.HINFO.dwStringCount);
        if (R->Data.HINFO.dwStringCount == 2)
        {
            STR_IS(CharSet, R->Data.HINFO.pStringArray[0], "cpu", "cpu");
            STR_IS(CharSet, R->Data.HINFO.pStringArray[1], "os", "os");
        }
        break;
    case DNS_TYPE_SRV:
        ok(R->wDataLength == sizeof(DNS_SRV_DATAA), "%s: data length %u\n", Label, R->wDataLength);
        ok(R->Data.SRV.wPriority == 5, "%s: priority %u\n", Label, R->Data.SRV.wPriority);
        ok(R->Data.SRV.wWeight == 10, "%s: weight %u\n", Label, R->Data.SRV.wWeight);
        ok(R->Data.SRV.wPort == 5060, "%s: port %u\n", Label, R->Data.SRV.wPort);
        STR_IS(CharSet, R->Data.SRV.pNameTarget, "sip.dnscp.test", "target");
        break;
    case DNS_TYPE_SOA:
        ok(R->wDataLength == sizeof(DNS_SOA_DATA), "%s: data length %u\n", Label, R->wDataLength);
        STR_IS(CharSet, R->Data.SOA.pNamePrimaryServer, "ns1.dnscp.test", "primary server");
        STR_IS(CharSet, R->Data.SOA.pNameAdministrator, "hostmaster.dnscp.test", "administrator");
        ok(R->Data.SOA.dwSerialNo == 2026111501, "%s: serial %lu\n", Label, R->Data.SOA.dwSerialNo);
        ok(R->Data.SOA.dwRefresh == 3600, "%s: refresh %lu\n", Label, R->Data.SOA.dwRefresh);
        ok(R->Data.SOA.dwRetry == 600, "%s: retry %lu\n", Label, R->Data.SOA.dwRetry);
        ok(R->Data.SOA.dwExpire == 86400, "%s: expire %lu\n", Label, R->Data.SOA.dwExpire);
        ok(R->Data.SOA.dwDefaultTtl == 300, "%s: default ttl %lu\n", Label, R->Data.SOA.dwDefaultTtl);
        break;
    case DNS_TYPE_MINFO:
        ok(R->wDataLength == sizeof(DNS_MINFO_DATA), "%s: data length %u\n", Label, R->wDataLength);
        STR_IS(CharSet, R->Data.MINFO.pNameMailbox, "rmailbx.dnscp.test", "mailbox");
        STR_IS(CharSet, R->Data.MINFO.pNameErrorsMailbox, "emailbx.dnscp.test", "errors mailbox");
        break;
    case DNS_TYPE_NULL:
        ok(R->Data.Null.dwByteCount == 5, "%s: %lu bytes\n", Label, R->Data.Null.dwByteCount);
        if (R->Data.Null.dwByteCount == 5)
        {
            static const BYTE Expected[5] = { 1, 2, 3, 4, 5 };
            ok(memcmp(R->Data.Null.Data, Expected, 5) == 0, "%s: data differ\n", Label);
        }
        break;
    default:
        ok(0, "%s: unexpected type %u\n", Label, R->wType);
    }
}

static const struct
{
    WORD Type;
    const char *Name;
    const char *Tag;
} g_Types[] =
{
    { DNS_TYPE_A,     "t-a.dnscp.test",     "A" },
    { DNS_TYPE_AAAA,  "t-aaaa.dnscp.test",  "AAAA" },
    { DNS_TYPE_CNAME, "t-cname.dnscp.test", "CNAME" },
    { DNS_TYPE_NS,    "t-ns.dnscp.test",    "NS" },
    { DNS_TYPE_PTR,   "10.2.0.192.in-addr.arpa", "PTR" },
    { DNS_TYPE_MX,    "t-mx.dnscp.test",    "MX" },
    { DNS_TYPE_TEXT,  "t-txt.dnscp.test",   "TXT" },
    { DNS_TYPE_SRV,   "t-srv.dnscp.test",   "SRV" },
    { DNS_TYPE_SRV,   "_sip._tcp.dnscp.test", "SRV service name" },
    { DNS_TYPE_SOA,   "t-soa.dnscp.test",   "SOA" },
    { DNS_TYPE_MINFO, "t-minfo.dnscp.test", "MINFO" },
    { DNS_TYPE_NULL,  "t-null.dnscp.test",  "NULL" },
};

static
void
CheckQuery(unsigned Index, int Variant /* 0 = DnsQuery_A, 1 = DnsQuery_UTF8, 2 = DnsQuery_W */)
{
    static const char *const VariantName[] = { "DnsQuery_A", "DnsQuery_UTF8", "DnsQuery_W" };
    static const DNS_CHARSET VariantSet[] = { DnsCharSetAnsi, DnsCharSetUtf8, DnsCharSetUnicode };
    char Label[64];
    WCHAR WideName[128];
    PDNS_RECORD Record = (PDNS_RECORD)(ULONG_PTR)0x1;
    DNS_STATUS Status;
    const char *Name = g_Types[Index].Name;
    WORD Type = g_Types[Index].Type;

    sprintf(Label, "%s %s", VariantName[Variant], g_Types[Index].Tag);

    if (Variant == 0)
        Status = DnsQuery_A(Name, Type, DNS_QUERY_STANDARD, NULL, &Record, NULL);
    else if (Variant == 1)
        Status = DnsQuery_UTF8(Name, Type, DNS_QUERY_STANDARD, NULL, &Record, NULL);
    else
    {
        MultiByteToWideChar(CP_ACP, 0, Name, -1, WideName, ARRAYSIZE(WideName));
        Status = DnsQuery_W(WideName, Type, DNS_QUERY_STANDARD, NULL, &Record, NULL);
    }

    if (Status != ERROR_SUCCESS)
    {
        /* A failure returns no record */
        ok(Record == NULL || Record == (PDNS_RECORD)(ULONG_PTR)0x1, "%s: record %p with status %lu\n", Label, Record, Status);
        /* MINFO and NULL records are the only types that the resolver does not answer (its DNS client has no parser for them) */
        if (Type == DNS_TYPE_MINFO || Type == DNS_TYPE_NULL)
            skip("%s: the resolver does not answer this type (status %lu)\n", Label, Status);
        else
            ok(0, "%s: status %lu\n", Label, Status);
        return;
    }

    ok(Record != NULL && Record != (PDNS_RECORD)(ULONG_PTR)0x1, "%s: no record\n", Label);
    if (Record == NULL || Record == (PDNS_RECORD)(ULONG_PTR)0x1)
        return;

    CheckHeader(Label, Record, VariantSet[Variant], Type, Name);
    CheckData(Label, Record, VariantSet[Variant]);
    ok(Record->pNext == NULL, "%s: more than one record\n", Label);
    DnsRecordListFree(Record, DnsFreeRecordList);
}

static
SIZE_T
HeapBusyBytes(void)
{
    PROCESS_HEAP_ENTRY Entry;
    SIZE_T Total = 0;
    HANDLE Heap = GetProcessHeap();

    Entry.lpData = NULL;
    HeapLock(Heap);
    while (HeapWalk(Heap, &Entry))
    {
        if (Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
            Total += Entry.cbData;
    }
    HeapUnlock(Heap);
    return Total;
}

/*
 * Heap growth of 2000 queries by name. The caller frees everything a query returns, so what the heap still grows by
 * comes from the layers below (the RPC to the resolver service, the resolver): there is none. DnsQuery_A, which
 * converts the wide result, must not grow more than DnsQuery_W (it used to leak the whole wide result of every call).
 */
static
SIZE_T
QueryGrowth(BOOL Wide, WORD Type, const char *Name)
{
    WCHAR NameW[128];
    PDNS_RECORD Record;
    SIZE_T Before = 0;
    int i;

    MultiByteToWideChar(CP_ACP, 0, Name, -1, NameW, ARRAYSIZE(NameW));
    for (i = 0; i < 2100; i++)
    {
        Record = NULL;
        if (i == 100)
            Before = HeapBusyBytes();
        if (Wide)
        {
            if (DnsQuery_W(NameW, Type, DNS_QUERY_STANDARD, NULL, &Record, NULL) == ERROR_SUCCESS)
                DnsRecordListFree(Record, DnsFreeRecordList);
        }
        else
        {
            if (DnsQuery_A(Name, Type, DNS_QUERY_STANDARD, NULL, &Record, NULL) == ERROR_SUCCESS)
                DnsRecordListFree(Record, DnsFreeRecordList);
        }
    }
    return HeapBusyBytes() - Before;
}

static
void
CheckNoLeak(void)
{
    unsigned i;
    SIZE_T GrowthW, GrowthA;

    for (i = 0; i < ARRAYSIZE(g_Types); i++)
    {
        if (g_Types[i].Type == DNS_TYPE_MINFO || g_Types[i].Type == DNS_TYPE_NULL)
            continue;
        GrowthW = QueryGrowth(TRUE, g_Types[i].Type, g_Types[i].Name);
        GrowthA = QueryGrowth(FALSE, g_Types[i].Type, g_Types[i].Name);
        trace("%s: heap growth in 2000 queries: DnsQuery_W %lu, DnsQuery_A %lu bytes\n",
              g_Types[i].Tag, (ULONG)GrowthW, (ULONG)GrowthA);
        ok(GrowthW <= 16 * 1024, "%s: DnsQuery_W grew the heap by %lu bytes in 2000 queries\n",
           g_Types[i].Tag, (ULONG)GrowthW);
        ok(GrowthA <= 16 * 1024, "%s: DnsQuery_A grew the heap by %lu bytes in 2000 queries\n",
           g_Types[i].Tag, (ULONG)GrowthA);
    }
}

/*
 * Several records of a type, an alias, a name that does not exist and one that has no record of the type (test
 * server names multi-1, alias-1, nxd-1 and plain-1).
 */
static
void
CheckMulti(DNS_CHARSET CharSet)
{
    PDNS_RECORD List, R;
    DNS_STATUS Status;
    unsigned n;
    char Label[48];
    static const char *const MxHosts[] = { "mail1.dnscp.test", "mail2.dnscp.test", "mail3.dnscp.test" };
    static const char *const NsHosts[] = { "ns1.dnscp.test", "ns2.dnscp.test", "ns3.dnscp.test" };
    static const char *const SrvHosts[] = { "srv1.dnscp.test", "srv2.dnscp.test" };
    const char *const Prefix = CharSet == DnsCharSetUnicode ? "W" : CharSet == DnsCharSetAnsi ? "A" : "UTF8";
    WCHAR WideName[64];

#define QUERY(name, type) \
    do { \
        if (CharSet == DnsCharSetUnicode) \
        { \
            MultiByteToWideChar(CP_ACP, 0, name, -1, WideName, ARRAYSIZE(WideName)); \
            Status = DnsQuery_W(WideName, type, DNS_QUERY_STANDARD, NULL, &List, NULL); \
        } \
        else if (CharSet == DnsCharSetAnsi) \
            Status = DnsQuery_A(name, type, DNS_QUERY_STANDARD, NULL, &List, NULL); \
        else \
            Status = DnsQuery_UTF8(name, type, DNS_QUERY_STANDARD, NULL, &List, NULL); \
    } while (0)

    /* MX: three records, in the order of the answer */
    sprintf(Label, "%s multi MX", Prefix);
    List = NULL;
    QUERY("multi-1.dnscp.test", DNS_TYPE_MX);
    ok(Status == ERROR_SUCCESS, "%s: status %lu\n", Label, Status);
    for (n = 0, R = Status == ERROR_SUCCESS ? List : NULL; R; R = R->pNext, n++)
    {
        ok(R->wType == DNS_TYPE_MX, "%s: type %u\n", Label, R->wType);
        if (n < 3)
        {
            ok(R->Data.MX.wPreference == 10 * (n + 1), "%s: preference %u\n", Label, R->Data.MX.wPreference);
            STR_IS(CharSet, R->Data.MX.pNameExchange, MxHosts[n], "exchange");
            STR_IS(CharSet, R->pName, "multi-1.dnscp.test", "owner");
        }
    }
    ok(n == 3, "%s: %u records\n", Label, n);
    if (List && Status == ERROR_SUCCESS)
        DnsRecordListFree(List, DnsFreeRecordList);

    /* NS */
    sprintf(Label, "%s multi NS", Prefix);
    List = NULL;
    QUERY("multi-1.dnscp.test", DNS_TYPE_NS);
    ok(Status == ERROR_SUCCESS, "%s: status %lu\n", Label, Status);
    for (n = 0, R = Status == ERROR_SUCCESS ? List : NULL; R; R = R->pNext, n++)
        if (n < 3)
            STR_IS(CharSet, R->Data.NS.pNameHost, NsHosts[n], "name server");
    ok(n == 3, "%s: %u records\n", Label, n);
    if (List && Status == ERROR_SUCCESS)
        DnsRecordListFree(List, DnsFreeRecordList);

    /* SRV */
    sprintf(Label, "%s multi SRV", Prefix);
    List = NULL;
    QUERY("multi-1.dnscp.test", DNS_TYPE_SRV);
    ok(Status == ERROR_SUCCESS, "%s: status %lu\n", Label, Status);
    for (n = 0, R = Status == ERROR_SUCCESS ? List : NULL; R; R = R->pNext, n++)
    {
        if (n < 2)
        {
            ok(R->Data.SRV.wPriority == 1 + 3 * n, "%s: priority %u\n", Label, R->Data.SRV.wPriority);
            ok(R->Data.SRV.wWeight == 2 + 3 * n, "%s: weight %u\n", Label, R->Data.SRV.wWeight);
            ok(R->Data.SRV.wPort == 3 + 3 * n, "%s: port %u\n", Label, R->Data.SRV.wPort);
            STR_IS(CharSet, R->Data.SRV.pNameTarget, SrvHosts[n], "target");
        }
    }
    ok(n == 2, "%s: %u records\n", Label, n);
    if (List && Status == ERROR_SUCCESS)
        DnsRecordListFree(List, DnsFreeRecordList);

    /* TXT: four records, the strings of each */
    sprintf(Label, "%s multi TXT", Prefix);
    List = NULL;
    QUERY("multi-1.dnscp.test", DNS_TYPE_TEXT);
    ok(Status == ERROR_SUCCESS, "%s: status %lu\n", Label, Status);
    for (n = 0, R = Status == ERROR_SUCCESS ? List : NULL; R; R = R->pNext, n++)
    {
        ok(R->wType == DNS_TYPE_TEXT, "%s: type %u\n", Label, R->wType);
        if (n == 0)
        {
            ok(R->Data.TXT.dwStringCount == 2, "%s: record 0 has %lu strings\n", Label, R->Data.TXT.dwStringCount);
            if (R->Data.TXT.dwStringCount == 2)
            {
                STR_IS(CharSet, R->Data.TXT.pStringArray[0], "one", "string 0");
                STR_IS(CharSet, R->Data.TXT.pStringArray[1], "two", "string 1");
            }
        }
        else if (n == 1)
        {
            ok(R->Data.TXT.dwStringCount == 1, "%s: record 1 has %lu strings\n", Label, R->Data.TXT.dwStringCount);
            if (R->Data.TXT.dwStringCount == 1)
                STR_IS(CharSet, R->Data.TXT.pStringArray[0], "", "empty string");
        }
        else if (n == 2)
        {
            ok(R->Data.TXT.dwStringCount == 1, "%s: record 2 has %lu strings\n", Label, R->Data.TXT.dwStringCount);
            if (R->Data.TXT.dwStringCount == 1)
            {
                char Expected[201];

                memset(Expected, 'x', 200);
                Expected[200] = 0;
                STR_IS(CharSet, R->Data.TXT.pStringArray[0], Expected, "long string");
            }
        }
        else if (n == 3)
        {
            ok(R->Data.TXT.dwStringCount == 1, "%s: record 3 has %lu strings\n", Label, R->Data.TXT.dwStringCount);
            if (R->Data.TXT.dwStringCount == 1)
                STR_IS(CharSet, R->Data.TXT.pStringArray[0], "a\"b\\c", "quoted string");
        }
    }
    ok(n == 4, "%s: %u records\n", Label, n);
    if (List && Status == ERROR_SUCCESS)
        DnsRecordListFree(List, DnsFreeRecordList);

    /* An alias: the records of the type at its target, under the name that was asked */
    sprintf(Label, "%s alias MX", Prefix);
    List = NULL;
    QUERY("alias-1.dnscp.test", DNS_TYPE_MX);
    ok(Status == ERROR_SUCCESS, "%s: status %lu\n", Label, Status);
    if (Status == ERROR_SUCCESS && List)
    {
        ok(List->wType == DNS_TYPE_MX, "%s: type %u\n", Label, List->wType);
        STR_IS(CharSet, List->Data.MX.pNameExchange, "mail.dnscp.test", "exchange");
        STR_IS(CharSet, List->pName, "alias-1.dnscp.test", "owner");
        DnsRecordListFree(List, DnsFreeRecordList);
    }

    /* A name that does not exist, and a name without a record of the type */
    sprintf(Label, "%s NXDOMAIN MX", Prefix);
    List = NULL;
    QUERY("nxd-1.dnscp.test", DNS_TYPE_MX);
    ok(Status == DNS_ERROR_RCODE_NAME_ERROR, "%s: status %lu\n", Label, Status);
    ok(List == NULL, "%s: record %p\n", Label, List);

    sprintf(Label, "%s no data MX", Prefix);
    List = NULL;
    QUERY("plain-1.dnscp.test", DNS_TYPE_MX);
    ok(Status == DNS_INFO_NO_RECORDS, "%s: status %lu\n", Label, Status);
    ok(List == NULL, "%s: record %p\n", Label, List);
#undef QUERY
}

static
void
QueryPart(void)
{
    PDNS_RECORD Record = NULL;
    DNS_STATUS Status;
    unsigned i;
    int v;

    /* The probe: the test server answers this name */
    Status = DnsQuery_A("t-a.dnscp.test", DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &Record, NULL);
    if (Status != ERROR_SUCCESS || Record == NULL || Record->Data.A.IpAddress != inet_addr("192.0.2.10"))
    {
        if (Status == ERROR_SUCCESS && Record)
            DnsRecordListFree(Record, DnsFreeRecordList);
        skip("the dnscp test DNS server does not answer (status %lu): query part skipped\n", Status);
        return;
    }
    DnsRecordListFree(Record, DnsFreeRecordList);

    for (i = 0; i < ARRAYSIZE(g_Types); i++)
        for (v = 0; v < 3; v++)
            CheckQuery(i, v);

    CheckMulti(DnsCharSetUnicode);
    CheckMulti(DnsCharSetAnsi);
    CheckMulti(DnsCharSetUtf8);

    CheckNoLeak();
}

/* ---- the conversion part: wide records built here, converted to ANSI and UTF-8 ---- */

static WCHAR g_Owner[] = L"owner.dnscp.test";
static WCHAR g_Name1[] = L"one.dnscp.test";
static WCHAR g_Name2[] = L"two.dnscp.test";
static WCHAR g_Str0[] = L"hello";
static WCHAR g_Str1[] = L"world";

static
PDNS_RECORD
MakeWide(WORD Type, SIZE_T Extra)
{
    PDNS_RECORD R = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DNS_RECORD) + Extra);

    if (!R)
        return NULL;
    R->pName = (PSTR)g_Owner;
    R->wType = Type;
    R->dwTtl = 123;
    R->dwReserved = 0x55;
    R->Flags.S.Section = DnsSectionAnswer;
    R->Flags.S.CharSet = DnsCharSetUnicode;
    return R;
}

static
void
ConvertCheck(PDNS_RECORD Wide, const char *Tag, void (*Check)(const char *, PDNS_RECORD, DNS_CHARSET))
{
    DNS_CHARSET Out[2] = { DnsCharSetAnsi, DnsCharSetUtf8 };
    int i;
    char Label[64];

    for (i = 0; i < 2; i++)
    {
        PDNS_RECORD C = DnsRecordCopyEx(Wide, DnsCharSetUnicode, Out[i]);

        sprintf(Label, "convert %s to %s", Tag, i ? "UTF-8" : "ANSI");
        ok(C != NULL, "%s: no copy\n", Label);
        if (!C)
            continue;
        ok(C != Wide, "%s: same record\n", Label);
        ok(C->pName != Wide->pName, "%s: owner name is shared with the wide record\n", Label);
        STR_IS(Out[i], C->pName, "owner.dnscp.test", "owner");
        ok(C->wType == Wide->wType, "%s: type %u\n", Label, C->wType);
        ok(C->Flags.S.CharSet == Out[i], "%s: charset %u\n", Label, (unsigned)C->Flags.S.CharSet);
        ok(C->Flags.S.Section == DnsSectionAnswer, "%s: section %u\n", Label, (unsigned)C->Flags.S.Section);
        ok(C->dwTtl == 123, "%s: ttl %lu\n", Label, C->dwTtl);
        ok(C->wDataLength == Wide->wDataLength, "%s: data length %u, wide %u\n", Label, C->wDataLength, Wide->wDataLength);
        Check(Label, C, Out[i]);
        DnsRecordListFree(C, DnsFreeRecordList);
    }
}

static
void
CheckPtr(const char *Label, PDNS_RECORD C, DNS_CHARSET Cs)
{
    STR_IS(Cs, C->Data.PTR.pNameHost, "one.dnscp.test", "host");
    ok(C->Data.PTR.pNameHost != (PVOID)g_Name1, "%s: host shared\n", Label);
}

static
void
CheckMx(const char *Label, PDNS_RECORD C, DNS_CHARSET Cs)
{
    ok(C->Data.MX.wPreference == 7, "%s: preference %u\n", Label, C->Data.MX.wPreference);
    STR_IS(Cs, C->Data.MX.pNameExchange, "one.dnscp.test", "exchange");
}

static
void
CheckMinfo(const char *Label, PDNS_RECORD C, DNS_CHARSET Cs)
{
    STR_IS(Cs, C->Data.MINFO.pNameMailbox, "one.dnscp.test", "mailbox");
    STR_IS(Cs, C->Data.MINFO.pNameErrorsMailbox, "two.dnscp.test", "errors mailbox");
}

static
void
CheckSoa(const char *Label, PDNS_RECORD C, DNS_CHARSET Cs)
{
    STR_IS(Cs, C->Data.SOA.pNamePrimaryServer, "one.dnscp.test", "primary");
    STR_IS(Cs, C->Data.SOA.pNameAdministrator, "two.dnscp.test", "administrator");
    ok(C->Data.SOA.dwSerialNo == 11 && C->Data.SOA.dwRefresh == 22 && C->Data.SOA.dwRetry == 33 &&
       C->Data.SOA.dwExpire == 44 && C->Data.SOA.dwDefaultTtl == 55, "%s: SOA numbers\n", Label);
}

static
void
CheckSrv(const char *Label, PDNS_RECORD C, DNS_CHARSET Cs)
{
    STR_IS(Cs, C->Data.SRV.pNameTarget, "one.dnscp.test", "target");
    ok(C->Data.SRV.wPriority == 1 && C->Data.SRV.wWeight == 2 && C->Data.SRV.wPort == 3, "%s: SRV numbers\n", Label);
}

static
void
CheckTxt(const char *Label, PDNS_RECORD C, DNS_CHARSET Cs)
{
    ok(C->Data.TXT.dwStringCount == 2, "%s: %lu strings\n", Label, C->Data.TXT.dwStringCount);
    if (C->Data.TXT.dwStringCount == 2)
    {
        STR_IS(Cs, C->Data.TXT.pStringArray[0], "hello", "string 0");
        STR_IS(Cs, C->Data.TXT.pStringArray[1], "world", "string 1");
    }
}

static
void
CheckNull(const char *Label, PDNS_RECORD C, DNS_CHARSET Cs)
{
    static const BYTE Expected[6] = { 9, 8, 7, 6, 5, 4 };

    ok(C->Data.Null.dwByteCount == 6, "%s: %lu bytes\n", Label, C->Data.Null.dwByteCount);
    ok(memcmp(C->Data.Null.Data, Expected, 6) == 0, "%s: data differ\n", Label);
}

static
void
CheckA(const char *Label, PDNS_RECORD C, DNS_CHARSET Cs)
{
    ok(C->Data.A.IpAddress == 0x0a0b0c0d, "%s: address %08lx\n", Label, C->Data.A.IpAddress);
}

static
void
CheckAaaa(const char *Label, PDNS_RECORD C, DNS_CHARSET Cs)
{
    ok(C->Data.AAAA.Ip6Address.IP6Dword[0] == 1 && C->Data.AAAA.Ip6Address.IP6Dword[3] == 4, "%s: address\n", Label);
}

static
void
ConversionPart(void)
{
    PDNS_RECORD R;
    static const WORD PtrTypes[] = { DNS_TYPE_CNAME, DNS_TYPE_PTR, DNS_TYPE_NS, DNS_TYPE_MB, DNS_TYPE_MD,
                                     DNS_TYPE_MF, DNS_TYPE_MG, DNS_TYPE_MR };
    unsigned i;
    char Tag[16];

    R = MakeWide(DNS_TYPE_A, 0);
    R->wDataLength = sizeof(DNS_A_DATA);
    R->Data.A.IpAddress = 0x0a0b0c0d;
    ConvertCheck(R, "A", CheckA);
    HeapFree(GetProcessHeap(), 0, R);

    R = MakeWide(DNS_TYPE_AAAA, 0);
    R->wDataLength = sizeof(DNS_AAAA_DATA);
    R->Data.AAAA.Ip6Address.IP6Dword[0] = 1;
    R->Data.AAAA.Ip6Address.IP6Dword[3] = 4;
    ConvertCheck(R, "AAAA", CheckAaaa);
    HeapFree(GetProcessHeap(), 0, R);

    for (i = 0; i < ARRAYSIZE(PtrTypes); i++)
    {
        R = MakeWide(PtrTypes[i], 0);
        R->wDataLength = sizeof(DNS_PTR_DATA);
        R->Data.PTR.pNameHost = (PSTR)g_Name1;
        sprintf(Tag, "type %u", PtrTypes[i]);
        ConvertCheck(R, Tag, CheckPtr);
        HeapFree(GetProcessHeap(), 0, R);
    }

    R = MakeWide(DNS_TYPE_MX, 0);
    R->wDataLength = sizeof(DNS_MX_DATA);
    R->Data.MX.wPreference = 7;
    R->Data.MX.pNameExchange = (PSTR)g_Name1;
    ConvertCheck(R, "MX", CheckMx);
    HeapFree(GetProcessHeap(), 0, R);

    R = MakeWide(DNS_TYPE_MINFO, 0);
    R->wDataLength = sizeof(DNS_MINFO_DATA);
    R->Data.MINFO.pNameMailbox = (PSTR)g_Name1;
    R->Data.MINFO.pNameErrorsMailbox = (PSTR)g_Name2;
    ConvertCheck(R, "MINFO", CheckMinfo);
    HeapFree(GetProcessHeap(), 0, R);

    R = MakeWide(DNS_TYPE_SOA, 0);
    R->wDataLength = sizeof(DNS_SOA_DATA);
    R->Data.SOA.pNamePrimaryServer = (PSTR)g_Name1;
    R->Data.SOA.pNameAdministrator = (PSTR)g_Name2;
    R->Data.SOA.dwSerialNo = 11;
    R->Data.SOA.dwRefresh = 22;
    R->Data.SOA.dwRetry = 33;
    R->Data.SOA.dwExpire = 44;
    R->Data.SOA.dwDefaultTtl = 55;
    ConvertCheck(R, "SOA", CheckSoa);
    HeapFree(GetProcessHeap(), 0, R);

    R = MakeWide(DNS_TYPE_SRV, 0);
    R->wDataLength = sizeof(DNS_SRV_DATAA);
    R->Data.SRV.pNameTarget = (PSTR)g_Name1;
    R->Data.SRV.wPriority = 1;
    R->Data.SRV.wWeight = 2;
    R->Data.SRV.wPort = 3;
    ConvertCheck(R, "SRV", CheckSrv);
    HeapFree(GetProcessHeap(), 0, R);

    {
        static const WORD TxtTypes[] = { DNS_TYPE_TEXT, DNS_TYPE_HINFO, DNS_TYPE_ISDN, DNS_TYPE_X25 };

        for (i = 0; i < ARRAYSIZE(TxtTypes); i++)
        {
            R = MakeWide(TxtTypes[i], 2 * sizeof(PSTR));
            R->wDataLength = (WORD)(FIELD_OFFSET(DNS_TXT_DATA, pStringArray) + 2 * sizeof(PSTR));
            R->Data.TXT.dwStringCount = 2;
            R->Data.TXT.pStringArray[0] = (PSTR)g_Str0;
            R->Data.TXT.pStringArray[1] = (PSTR)g_Str1;
            sprintf(Tag, "type %u", TxtTypes[i]);
            ConvertCheck(R, Tag, CheckTxt);
            HeapFree(GetProcessHeap(), 0, R);
        }
    }

    R = MakeWide(DNS_TYPE_NULL, 8);
    R->wDataLength = (WORD)(FIELD_OFFSET(DNS_NULL_DATA, Data) + 6);
    R->Data.Null.dwByteCount = 6;
    R->Data.Null.Data[0] = 9; R->Data.Null.Data[1] = 8; R->Data.Null.Data[2] = 7;
    R->Data.Null.Data[3] = 6; R->Data.Null.Data[4] = 5; R->Data.Null.Data[5] = 4;
    ConvertCheck(R, "NULL", CheckNull);
    HeapFree(GetProcessHeap(), 0, R);
}

START_TEST(DnsQueryTypes)
{
    ConversionPart();
    QueryPart();
}
