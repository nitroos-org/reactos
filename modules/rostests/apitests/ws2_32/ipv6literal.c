/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Names of the "<address>.ipv6-literal.net" form: which APIs turn them into the IPv6 address, the forms
 *              that are accepted and the ones that are not, the answers of the families and flags. Every expectation
 *              was measured on Windows Server 2022 (21H2, build 20348); the same rows pass on it. No answer of a
 *              name of this form depends on the network (nothing is asked for it).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* The Vista+ address info types are hidden from the 0x502 headers this module is built with */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#undef WINVER
#define WINVER 0x0600

#include "ws2_32.h"
#include <winnls.h>
#include <windns.h>

#ifndef AI_FQDN
#define AI_FQDN 0x00020000
#endif

typedef struct
{
    PCWSTR Name;
    PCWSTR Address;     /* the numeric form */
    ULONG Scope;
} LITERAL;

static const LITERAL Accepted[] =
{
    { L"0--1.ipv6-literal.net",                                   L"::1",             0 },
    { L"2001-db8--1.ipv6-literal.net",                            L"2001:db8::1",     0 },
    { L"2001-0db8-0000-0000-0000-0000-0000-0001.ipv6-literal.net", L"2001:db8::1",     0 },
    { L"1-2-3-4-5-6-7-8.ipv6-literal.net",                        L"1:2:3:4:5:6:7:8", 0 },
    { L"2001-DB8--A.ipv6-literal.net",                            L"2001:db8::a",     0 },
    { L"2001-db8--a.ipv6-literal.net",                            L"2001:db8::a",     0 },
    { L"2001-db8--1.ipv6-literal.net.",                           L"2001:db8::1",     0 },
    { L"fe80--1s4.ipv6-literal.net",                              L"fe80::1",         4 },
    { L"fe80--1s3.ipv6-literal.net",                              L"fe80::1",         3 },
    { L"fe80--1s0.ipv6-literal.net",                              L"fe80::1",         0 },
    { L"fe80--1s03.ipv6-literal.net",                             L"fe80::1",         3 },
    { L"fe80--1s4294967295.ipv6-literal.net",                     L"fe80::1",         0xFFFFFFFF },
    { L"fe80--1s4.ipv6-literal.net.",                             L"fe80::1",         4 },
    { L"0--ffff-1.2.3.4.ipv6-literal.net",                        L"::ffff:1.2.3.4",  0 },
    { L"0--ffff-102-304.ipv6-literal.net",                        L"::ffff:1.2.3.4",  0 },
    { L"64-ff9b--1.2.3.4.ipv6-literal.net",                       L"64:ff9b::102:304", 0 },
    { L"0--.ipv6-literal.net",                                    L"::",              0 },
    { L"--.ipv6-literal.net",                                     L"::",              0 },
    { L"--1.ipv6-literal.net",                                    L"::1",             0 },
    { L"1--.ipv6-literal.net",                                    L"1::",             0 },
    /* what the text form allows is allowed in front of the suffix: a scope with '%', brackets, ':' */
    { L"0--1%4.ipv6-literal.net",                                 L"::1",             4 },
    { L"[0--1].ipv6-literal.net",                                 L"::1",             0 },
    { L"0:0::1.ipv6-literal.net",                                 L"::1",             0 },
};

/* Forms that are not a literal name. What they resolve to is the business of the network: only "not the address" */
static const PCWSTR Rejected[] =
{
    L"2001-db8--1.IPV6-LITERAL.NET",        /* the suffix is case sensitive */
    L"2001-db8--1.Ipv6-Literal.Net",
    L"fe80--1S4.ipv6-literal.net",          /* so is the 's' of the scope */
    L"fe80--1s4294967296.ipv6-literal.net", /* a scope of more than 32 bits */
    L"fe80--1s.ipv6-literal.net",
    L"fe80--1sx.ipv6-literal.net",
    L"fe80--1s-4.ipv6-literal.net",
    L"fe80--1s4s5.ipv6-literal.net",
    L"1--2--3.ipv6-literal.net",
    L"1-2-3-4-5-6-7-8-9.ipv6-literal.net",
    L"gggg--1.ipv6-literal.net",
    L"12345--1.ipv6-literal.net",
    L"xyz.ipv6-literal.net",
    L".ipv6-literal.net",
    L"foo.0--1.ipv6-literal.net",
    L"0--1.sub.ipv6-literal.net",
    L"0--1.ipv6-literal.net.evil",
    L"0--1.ipv6-literal.net..",
    L"0--1.ipv6-literal.com",
    L"0--1.ipv6-literal",
    L"-0--1.ipv6-literal.net",
    L"0--1-.ipv6-literal.net",
    L"0--1.ipv6-literal.net:445",
};

/* Is Bytes the address of the numeric text? */
static BOOL IsAddress(const void *Bytes, PCWSTR Address)
{
    IN6_ADDR Expected;
    PCWSTR Terminator = NULL;

    if (!NT_SUCCESS(RtlIpv6StringToAddressW(Address, &Terminator, &Expected)))
        return FALSE;
    return !memcmp(&Expected, Bytes, sizeof(Expected));
}

static BOOL SameAddress(const SOCKADDR *Sa, PCWSTR Address, ULONG Scope, int Port)
{
    const SOCKADDR_IN6 *S6 = (const SOCKADDR_IN6 *)Sa;

    if (Sa->sa_family != AF_INET6)
        return FALSE;
    return IsAddress(&S6->sin6_addr, Address) && S6->sin6_scope_id == Scope && ntohs(S6->sin6_port) == Port &&
           S6->sin6_flowinfo == 0;
}

static void CheckResultW(PCWSTR Name, const char *Api, int Error, const ADDRINFOW *Info, const LITERAL *Case, int Port)
{
    ok(Error == 0, "%ls: %s returned %d\n", Name, Api, Error);
    if (Error != 0)
        return;
    ok(Info != NULL, "%ls: %s gave no result\n", Name, Api);
    if (!Info)
        return;
    ok(Info->ai_family == AF_INET6, "%ls: %s family %d\n", Name, Api, Info->ai_family);
    ok(Info->ai_addrlen == sizeof(SOCKADDR_IN6), "%ls: %s addrlen %u\n", Name, Api, (unsigned)Info->ai_addrlen);
    ok(SameAddress(Info->ai_addr, Case->Address, Case->Scope, Port), "%ls: %s gave another address\n", Name, Api);
    ok(Info->ai_next == NULL, "%ls: %s gave more than one entry\n", Name, Api);
}

static void TestGetAddrInfoW(const LITERAL *Case)
{
    static const struct
    {
        int Family;
        int Flags;
        const char *Label;
    } Hints[] =
    {
        { AF_UNSPEC, 0, "AF_UNSPEC" },
        { AF_INET6, 0, "AF_INET6" },
        { AF_UNSPEC, AI_NUMERICHOST, "AF_UNSPEC|AI_NUMERICHOST" },
        { AF_INET6, AI_NUMERICHOST, "AF_INET6|AI_NUMERICHOST" },
        { AF_INET6, AI_ADDRCONFIG, "AF_INET6|AI_ADDRCONFIG" },
        { AF_UNSPEC, AI_PASSIVE, "AF_UNSPEC|AI_PASSIVE" },
    };
    ADDRINFOW Hint, *Result;
    unsigned i;
    int Error;

    /* no hints */
    Result = NULL;
    Error = GetAddrInfoW(Case->Name, L"445", NULL, &Result);
    CheckResultW(Case->Name, "GetAddrInfoW(no hints)", Error, Result, Case, 445);
    if (Result)
    {
        /* the result of the name carries the flag of an address */
        ok(Result->ai_flags == AI_NUMERICHOST, "%ls: ai_flags 0x%x\n", Case->Name, Result->ai_flags);
        ok(Result->ai_socktype == 0 && Result->ai_protocol == 0, "%ls: type %d protocol %d\n", Case->Name,
           Result->ai_socktype, Result->ai_protocol);
        FreeAddrInfoW(Result);
    }

    for (i = 0; i < ARRAYSIZE(Hints); i++)
    {
        ZeroMemory(&Hint, sizeof(Hint));
        Hint.ai_family = Hints[i].Family;
        Hint.ai_flags = Hints[i].Flags;
        Result = NULL;
        Error = GetAddrInfoW(Case->Name, L"445", &Hint, &Result);
        CheckResultW(Case->Name, Hints[i].Label, Error, Result, Case, 445);
        if (Result)
            FreeAddrInfoW(Result);
    }

    /* no service: port 0 */
    ZeroMemory(&Hint, sizeof(Hint));
    Hint.ai_family = AF_INET6;
    Result = NULL;
    Error = GetAddrInfoW(Case->Name, NULL, &Hint, &Result);
    CheckResultW(Case->Name, "GetAddrInfoW(no service)", Error, Result, Case, 0);
    if (Result)
        FreeAddrInfoW(Result);

    /* socket type and protocol are the caller's */
    ZeroMemory(&Hint, sizeof(Hint));
    Hint.ai_socktype = SOCK_STREAM;
    Hint.ai_protocol = IPPROTO_TCP;
    Result = NULL;
    Error = GetAddrInfoW(Case->Name, L"445", &Hint, &Result);
    CheckResultW(Case->Name, "GetAddrInfoW(stream)", Error, Result, Case, 445);
    if (Result)
    {
        ok(Result->ai_socktype == SOCK_STREAM && Result->ai_protocol == IPPROTO_TCP, "%ls: type %d protocol %d\n",
           Case->Name, Result->ai_socktype, Result->ai_protocol);
        FreeAddrInfoW(Result);
    }

    /* the IPv4 family has no answer for it, and asks nobody */
    ZeroMemory(&Hint, sizeof(Hint));
    Hint.ai_family = AF_INET;
    Result = NULL;
    Error = GetAddrInfoW(Case->Name, L"445", &Hint, &Result);
    ok(Error == WSAHOST_NOT_FOUND, "%ls: AF_INET gave %d\n", Case->Name, Error);
    ok(Result == NULL, "%ls: AF_INET gave a result\n", Case->Name);

    ZeroMemory(&Hint, sizeof(Hint));
    Hint.ai_family = AF_INET;
    Hint.ai_flags = AI_NUMERICHOST;
    Result = NULL;
    Error = GetAddrInfoW(Case->Name, L"445", &Hint, &Result);
    ok(Error == WSAHOST_NOT_FOUND, "%ls: AF_INET|AI_NUMERICHOST gave %d\n", Case->Name, Error);
    ok(Result == NULL, "%ls: AF_INET|AI_NUMERICHOST gave a result\n", Case->Name);
}

static void TestOtherApis(const LITERAL *Case)
{
    ADDRINFOEXW HintEx, *ResultEx;
    ADDRINFOA HintA, *ResultA;
    char Name[128];
    SOCKADDR_IN6 Sin6;
    int Error, Length;
    struct hostent *Host;

    /* GetAddrInfoExW, synchronous */
    ZeroMemory(&HintEx, sizeof(HintEx));
    HintEx.ai_family = AF_UNSPEC;
    ResultEx = NULL;
    Error = GetAddrInfoExW(Case->Name, L"445", NS_DNS, NULL, &HintEx, &ResultEx, NULL, NULL, NULL, NULL);
    ok(Error == 0, "%ls: GetAddrInfoExW returned %d\n", Case->Name, Error);
    if (Error == 0 && ResultEx)
    {
        ok(ResultEx->ai_family == AF_INET6, "%ls: GetAddrInfoExW family %d\n", Case->Name, ResultEx->ai_family);
        ok(SameAddress(ResultEx->ai_addr, Case->Address, Case->Scope, 445), "%ls: GetAddrInfoExW address\n",
           Case->Name);
        ok(ResultEx->ai_next == NULL, "%ls: GetAddrInfoExW gave more than one entry\n", Case->Name);
        FreeAddrInfoExW(ResultEx);
    }

    /* getaddrinfo (the ANSI form) */
    WideCharToMultiByte(CP_ACP, 0, Case->Name, -1, Name, sizeof(Name), NULL, NULL);
    ZeroMemory(&HintA, sizeof(HintA));
    ResultA = NULL;
    Error = getaddrinfo(Name, "445", &HintA, &ResultA);
    ok(Error == 0, "%s: getaddrinfo returned %d\n", Name, Error);
    if (Error == 0 && ResultA)
    {
        ok(ResultA->ai_family == AF_INET6, "%s: getaddrinfo family %d\n", Name, ResultA->ai_family);
        ok(SameAddress(ResultA->ai_addr, Case->Address, Case->Scope, 445), "%s: getaddrinfo address\n", Name);
        freeaddrinfo(ResultA);
    }

    /* gethostbyname is the IPv4 lookup: no host, no query */
    WSASetLastError(0);
    Host = gethostbyname(Name);
    ok(Host == NULL, "%s: gethostbyname found a host\n", Name);
    ok(WSAGetLastError() == WSAHOST_NOT_FOUND, "%s: gethostbyname error %d\n", Name, WSAGetLastError());

    /* the plain conversions do not know the form */
    ZeroMemory(&Sin6, sizeof(Sin6));
    Length = sizeof(Sin6);
    WSASetLastError(0);
    Error = WSAStringToAddressW((LPWSTR)Case->Name, AF_INET6, NULL, (LPSOCKADDR)&Sin6, &Length);
    ok(Error == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "%ls: WSAStringToAddress %d, error %d\n",
       Case->Name, Error, WSAGetLastError());
    {
        IN6_ADDR Address;
        ULONG Scope;
        USHORT Port;

        ok(RtlIpv6StringToAddressExW(Case->Name, &Address, &Scope, &Port) == STATUS_INVALID_PARAMETER,
           "%ls: RtlIpv6StringToAddressEx accepted it\n", Case->Name);
    }
}

static void TestDnsQuery(const LITERAL *Case)
{
    PDNS_RECORDW Record;
    DNS_STATUS Status;
    static const WORD Others[] = { DNS_TYPE_A, DNS_TYPE_ANY, DNS_TYPE_PTR };
    static const DWORD Options[] = { DNS_QUERY_STANDARD, DNS_QUERY_NO_WIRE_QUERY, DNS_QUERY_BYPASS_CACHE,
                                     DNS_QUERY_NO_HOSTS_FILE, DNS_QUERY_NO_RECURSION };
    unsigned i;

    for (i = 0; i < ARRAYSIZE(Options); i++)
    {
        Record = NULL;
        Status = DnsQuery_W(Case->Name, DNS_TYPE_AAAA, Options[i], NULL, (PDNS_RECORD *)&Record, NULL);
        ok(Status == ERROR_SUCCESS, "%ls: DnsQuery_W(AAAA, 0x%lx) returned %lu\n", Case->Name, Options[i], Status);
        if (Status != ERROR_SUCCESS || !Record)
            continue;

        ok(Record->wType == DNS_TYPE_AAAA, "%ls: record type %u\n", Case->Name, Record->wType);
        ok(Record->pNext == NULL, "%ls: more than one record\n", Case->Name);
        ok(Record->pName && !wcscmp(Record->pName, Case->Name), "%ls: record name %ls\n", Case->Name,
           Record->pName ? Record->pName : L"(null)");
        ok(Record->wDataLength == sizeof(DNS_AAAA_DATA), "%ls: record data length %u\n", Case->Name,
           Record->wDataLength);
        ok(IsAddress(&Record->Data.AAAA.Ip6Address, Case->Address), "%ls: record address\n", Case->Name);
        DnsRecordListFree((PDNS_RECORD)Record, DnsFreeRecordList);
    }

    /* no other record type exists for the name */
    for (i = 0; i < ARRAYSIZE(Others); i++)
    {
        Record = NULL;
        Status = DnsQuery_W(Case->Name, Others[i], DNS_QUERY_STANDARD, NULL, (PDNS_RECORD *)&Record, NULL);
        ok(Status == DNS_ERROR_RCODE_NAME_ERROR, "%ls: DnsQuery_W(type %u) returned %lu\n", Case->Name, Others[i],
           Status);
        ok(Record == NULL, "%ls: DnsQuery_W(type %u) gave a record\n", Case->Name, Others[i]);
        if (Record)
            DnsRecordListFree((PDNS_RECORD)Record, DnsFreeRecordList);
    }
}

static void TestCanonicalNames(void)
{
    static const struct
    {
        PCWSTR Name;
        PCWSTR WithService;     /* AI_CANONNAME with the service 445 */
        PCWSTR NoService;       /* AI_CANONNAME without a service */
    } Cases[] =
    {
        { L"0--1.ipv6-literal.net",         L"[::1]:445",         L"::1" },
        { L"2001-db8--1.ipv6-literal.net",  L"[2001:db8::1]:445", L"2001:db8::1" },
        { L"fe80--1s4.ipv6-literal.net",    L"[fe80::1%4]:445",   L"fe80::1%4" },
        { L"fe80--1s0.ipv6-literal.net",    L"[fe80::1]:445",     L"fe80::1" },
    };
    static const PCWSTR Fqdn[] =
    {
        L"2001-db8--1.ipv6-literal.net",
        L"2001-db8--1.ipv6-literal.net.",
        L"fe80--1s4.ipv6-literal.net",
    };
    ADDRINFOW Hint, *Result;
    unsigned i;
    int Error;

    for (i = 0; i < ARRAYSIZE(Cases); i++)
    {
        ZeroMemory(&Hint, sizeof(Hint));
        Hint.ai_flags = AI_CANONNAME;
        Result = NULL;
        Error = GetAddrInfoW(Cases[i].Name, L"445", &Hint, &Result);
        ok(Error == 0, "%ls: AI_CANONNAME returned %d\n", Cases[i].Name, Error);
        if (Error == 0 && Result)
        {
            ok(Result->ai_canonname && !wcscmp(Result->ai_canonname, Cases[i].WithService),
               "%ls: canonical name %ls\n", Cases[i].Name, Result->ai_canonname ? Result->ai_canonname : L"(null)");
            FreeAddrInfoW(Result);
        }

        ZeroMemory(&Hint, sizeof(Hint));
        Hint.ai_flags = AI_CANONNAME;
        Result = NULL;
        Error = GetAddrInfoW(Cases[i].Name, NULL, &Hint, &Result);
        ok(Error == 0, "%ls: AI_CANONNAME without a service returned %d\n", Cases[i].Name, Error);
        if (Error == 0 && Result)
        {
            ok(Result->ai_canonname && !wcscmp(Result->ai_canonname, Cases[i].NoService),
               "%ls: canonical name without a service %ls\n", Cases[i].Name,
               Result->ai_canonname ? Result->ai_canonname : L"(null)");
            FreeAddrInfoW(Result);
        }
    }

    /* AI_FQDN: the name as the caller gave it */
    for (i = 0; i < ARRAYSIZE(Fqdn); i++)
    {
        ZeroMemory(&Hint, sizeof(Hint));
        Hint.ai_flags = AI_FQDN;
        Result = NULL;
        Error = GetAddrInfoW(Fqdn[i], L"445", &Hint, &Result);
        ok(Error == 0, "%ls: AI_FQDN returned %d\n", Fqdn[i], Error);
        if (Error == 0 && Result)
        {
            ok(Result->ai_canonname && !wcscmp(Result->ai_canonname, Fqdn[i]), "%ls: AI_FQDN name %ls\n", Fqdn[i],
               Result->ai_canonname ? Result->ai_canonname : L"(null)");
            FreeAddrInfoW(Result);
        }
    }
}

/* The scope of an address in text form is 32 bits at most (the same limit as in the literal names) */
static void TestNumericScope(void)
{
    static const struct
    {
        PCWSTR Name;
        int Error;
        ULONG Scope;
    } Cases[] =
    {
        { L"fe80::1%4",          0,                  4 },
        { L"fe80::1%0",          0,                  0 },
        { L"fe80::1%4294967295", 0,                  0xFFFFFFFF },
        { L"fe80::1%4294967296", WSAHOST_NOT_FOUND,  0 },
    };
    ADDRINFOW Hint, *Result;
    unsigned i;
    int Error;

    for (i = 0; i < ARRAYSIZE(Cases); i++)
    {
        ZeroMemory(&Hint, sizeof(Hint));
        Hint.ai_flags = AI_NUMERICHOST;
        Result = NULL;
        Error = GetAddrInfoW(Cases[i].Name, L"445", &Hint, &Result);
        ok(Error == Cases[i].Error, "%ls: returned %d\n", Cases[i].Name, Error);
        if (Error == 0 && Result)
        {
            ok(SameAddress(Result->ai_addr, L"fe80::1", Cases[i].Scope, 445), "%ls: scope\n", Cases[i].Name);
            FreeAddrInfoW(Result);
        }
        else
        {
            ok(Result == NULL, "%ls: gave a result\n", Cases[i].Name);
        }
    }
}

static void TestRejected(PCWSTR Name)
{
    ADDRINFOW Hint, *Result = NULL;
    PDNS_RECORDW Record = NULL;
    DNS_STATUS Status;
    int Error;

    /* with AI_NUMERICHOST nothing is asked for: the name is not an address */
    ZeroMemory(&Hint, sizeof(Hint));
    Hint.ai_flags = AI_NUMERICHOST;
    Error = GetAddrInfoW(Name, L"445", &Hint, &Result);
    ok(Error == WSAHOST_NOT_FOUND, "%ls: AI_NUMERICHOST returned %d\n", Name, Error);
    ok(Result == NULL, "%ls: AI_NUMERICHOST gave a result\n", Name);
    if (Result)
        FreeAddrInfoW(Result);

    /* the cached/local forms of DnsQuery_W do not make an address of it either */
    Status = DnsQuery_W(Name, DNS_TYPE_AAAA, DNS_QUERY_NO_WIRE_QUERY, NULL, (PDNS_RECORD *)&Record, NULL);
    ok(Status != ERROR_SUCCESS, "%ls: DnsQuery_W(AAAA, no wire) returned success\n", Name);
    if (Record)
        DnsRecordListFree((PDNS_RECORD)Record, DnsFreeRecordList);
}

START_TEST(ipv6literal)
{
    WSADATA WsaData;
    unsigned i;

    ok(WSAStartup(MAKEWORD(2, 2), &WsaData) == 0, "WSAStartup failed\n");

    for (i = 0; i < ARRAYSIZE(Accepted); i++)
    {
        TestGetAddrInfoW(&Accepted[i]);
        TestOtherApis(&Accepted[i]);
        TestDnsQuery(&Accepted[i]);
    }

    TestCanonicalNames();
    TestNumericScope();

    for (i = 0; i < ARRAYSIZE(Rejected); i++)
        TestRejected(Rejected[i]);

    WSACleanup();
}
