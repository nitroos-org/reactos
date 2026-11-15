/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Names with many A and AAAA records: DnsQuery_A / DnsQuery_W, getaddrinfo, gethostbyname and
 *              GetAddrInfoExW return every address of the answer, in the order of the answer, whether the answer
 *              came in one UDP datagram or (truncated) over TCP
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Needs a DNS server that the machine uses and that answers names of the form cnt<A>x<B>.<anything> with A
 * records 192.0.2.1 ... (the n-th is 192.0.2.n, last byte modulo 250) and B AAAA records 2001:db8::1 ... (the
 * n-th is 2001:db8::n), over UDP (truncated, TC set, when the answer does not fit 512 bytes) and over TCP (the
 * "dnstc" test server of the harness). Without it the test is skipped (the first query is the probe).
 */

/* The Vista+ address info types are hidden from the 0x502 headers this module is built with */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#undef WINVER
#define WINVER 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windns.h>
#include <apitest.h>

typedef struct
{
    const char *Name;
    int A;
    int Aaaa;
} MANY_CASE;

static const MANY_CASE Cases[] =
{
    { "cnt1x1.many.test", 1, 1 },
    { "cnt2x2.many.test", 2, 2 },
    { "cnt10x10.many.test", 10, 10 },
    { "cnt20x20.many.test", 20, 20 },
    { "cnt40x20.many.test", 40, 20 },     /* both do not fit a UDP answer: TC, then TCP */
    { "cnt300x3.many.test", 300, 3 },     /* an answer of a few KB */
};

static
BOOL
Is4(DWORD Address, int N)
{
    BYTE Expect[4] = { 192, 0, 2, (BYTE)((N - 1) % 250 + 1) };

    return memcmp(&Address, Expect, 4) == 0;
}

static
BOOL
Is6(const BYTE *Address, int N)
{
    BYTE Expect[16] = { 0x20, 0x01, 0x0d, 0xb8 };

    Expect[14] = (BYTE)(N >> 8);
    Expect[15] = (BYTE)N;
    return memcmp(Address, Expect, 16) == 0;
}

static
void
CheckDnsQuery(const MANY_CASE *C, BOOL Wide)
{
    WCHAR WideName[100];
    PDNS_RECORD Rec = NULL, R;
    DNS_STATUS Status;
    int Type;

    MultiByteToWideChar(CP_ACP, 0, C->Name, -1, WideName, ARRAYSIZE(WideName));

    for (Type = 0; Type < 2; Type++)
    {
        int Expect = Type ? C->Aaaa : C->A, Count = 0, InOrder = 1;

        Rec = NULL;
        if (Wide)
            Status = DnsQuery_W(WideName, Type ? DNS_TYPE_AAAA : DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &Rec, NULL);
        else
            Status = DnsQuery_A(C->Name, Type ? DNS_TYPE_AAAA : DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &Rec, NULL);
        ok(Status == ERROR_SUCCESS, "%s DnsQuery_%c(%s): %ld\n", Type ? "AAAA" : "A", Wide ? 'W' : 'A', C->Name, (long)Status);
        for (R = (Status == ERROR_SUCCESS) ? Rec : NULL; R; R = R->pNext)
        {
            if (R->wType == (Type ? DNS_TYPE_AAAA : DNS_TYPE_A))
            {
                Count++;
                if (Type ? !Is6((const BYTE *)&R->Data.AAAA.Ip6Address, Count) : !Is4(R->Data.A.IpAddress, Count))
                    InOrder = 0;
            }
        }
        ok(Count == Expect, "%s DnsQuery_%c(%s): %d records, expected %d\n", Type ? "AAAA" : "A", Wide ? 'W' : 'A', C->Name, Count, Expect);
        ok(InOrder, "%s DnsQuery_%c(%s): the addresses are not the ones of the answer in its order\n", Type ? "AAAA" : "A", Wide ? 'W' : 'A', C->Name);
        if (Rec)
            DnsRecordListFree(Rec, DnsFreeRecordList);
    }
}

static
void
CheckGetAddrInfo(const MANY_CASE *C)
{
    static const int Families[3] = { AF_INET, AF_INET6, AF_UNSPEC };
    static const char *const FamilyNames[3] = { "AF_INET", "AF_INET6", "AF_UNSPEC" };
    int F, Count4, Count6, Six = 0;

    for (F = 0; F < 3; F++)
    {
        struct addrinfo Hints, *Res = NULL, *P;
        int Rc, In4Order = 1, In6Order = 1;

        ZeroMemory(&Hints, sizeof(Hints));
        Hints.ai_family = Families[F];
        Hints.ai_socktype = SOCK_STREAM;
        Rc = getaddrinfo(C->Name, "80", &Hints, &Res);
        Count4 = Count6 = 0;
        for (P = (Rc == 0) ? Res : NULL; P; P = P->ai_next)
        {
            if (P->ai_family == AF_INET)
            {
                Count4++;
                if (!Is4(((struct sockaddr_in *)P->ai_addr)->sin_addr.s_addr, Count4))
                    In4Order = 0;
            }
            else if (P->ai_family == AF_INET6)
            {
                Count6++;
                if (!Is6((const BYTE *)&((struct sockaddr_in6 *)P->ai_addr)->sin6_addr, Count6))
                    In6Order = 0;
            }
        }
        if (Families[F] == AF_INET6)
            Six = (Rc == 0 && Count6 > 0);

        ok(Rc == 0, "getaddrinfo(%s, %s): %d\n", C->Name, FamilyNames[F], Rc);
        ok(Count4 == (Families[F] == AF_INET6 ? 0 : C->A),
           "getaddrinfo(%s, %s): %d IPv4 addresses, expected %d\n", C->Name, FamilyNames[F], Count4,
           Families[F] == AF_INET6 ? 0 : C->A);
        if (Families[F] == AF_INET6)
            ok(Count6 == C->Aaaa, "getaddrinfo(%s, AF_INET6): %d IPv6 addresses, expected %d\n", C->Name, Count6, C->Aaaa);
        else if (Families[F] == AF_INET)
            ok(Count6 == 0, "getaddrinfo(%s, AF_INET): %d IPv6 addresses\n", C->Name, Count6);
        else
            /* with IPv6 on the AAAA records are in the answer, off they are not asked for */
            ok(Count6 == (Six ? C->Aaaa : 0), "getaddrinfo(%s, AF_UNSPEC): %d IPv6 addresses, expected %d\n", C->Name, Count6,
               Six ? C->Aaaa : 0);
        ok(In4Order && In6Order, "getaddrinfo(%s, %s): the addresses are not the ones of the answer in its order\n", C->Name,
           FamilyNames[F]);
        if (Res)
            freeaddrinfo(Res);
    }
}

static
void
CheckHostent(const MANY_CASE *C)
{
    struct hostent *H = gethostbyname(C->Name);
    int N = 0, InOrder = 1;

    ok(H != NULL, "gethostbyname(%s) failed: %d\n", C->Name, WSAGetLastError());
    if (!H)
        return;
    ok(H->h_addrtype == AF_INET && H->h_length == 4, "gethostbyname(%s): type %d length %d\n", C->Name, H->h_addrtype, H->h_length);
    while (H->h_addr_list[N])
    {
        N++;
        if (!Is4(*(DWORD *)H->h_addr_list[N - 1], N))
            InOrder = 0;
    }
    ok(N == C->A, "gethostbyname(%s): %d addresses, expected %d\n", C->Name, N, C->A);
    ok(InOrder, "gethostbyname(%s): the addresses are not the ones of the answer in its order\n", C->Name);
}

static
void
CheckGetAddrInfoEx(const MANY_CASE *C)
{
    WCHAR Name[100];
    ADDRINFOEXW Hints, *Res = NULL, *P;
    INT Rc;
    int Count4 = 0;

    MultiByteToWideChar(CP_ACP, 0, C->Name, -1, Name, ARRAYSIZE(Name));
    ZeroMemory(&Hints, sizeof(Hints));
    Hints.ai_family = AF_INET;
    Rc = GetAddrInfoExW(Name, NULL, NS_DNS, NULL, &Hints, &Res, NULL, NULL, NULL, NULL);
    ok(Rc == 0, "GetAddrInfoExW(%s): %d\n", C->Name, Rc);
    for (P = (Rc == 0) ? Res : NULL; P; P = P->ai_next)
        if (P->ai_family == AF_INET)
            Count4++;
    ok(Count4 == C->A, "GetAddrInfoExW(%s): %d IPv4 addresses, expected %d\n", C->Name, Count4, C->A);
    if (Res)
        FreeAddrInfoExW(Res);
}

START_TEST(DnsQueryMany)
{
    WSADATA Data;
    PDNS_RECORD Rec = NULL;
    DNS_STATUS Status;
    int i;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");

    /* the probe: the test server answers it with one A record 192.0.2.1 */
    Status = DnsQuery_A(Cases[0].Name, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &Rec, NULL);
    if (Status != ERROR_SUCCESS || Rec == NULL || Rec->wType != DNS_TYPE_A || !Is4(Rec->Data.A.IpAddress, 1))
    {
        skip("no DNS server that answers %s (DnsQuery_A: %ld)\n", Cases[0].Name, (long)Status);
        if (Rec)
            DnsRecordListFree(Rec, DnsFreeRecordList);
        WSACleanup();
        return;
    }
    DnsRecordListFree(Rec, DnsFreeRecordList);

    for (i = 0; i < (int)ARRAYSIZE(Cases); i++)
    {
        CheckDnsQuery(&Cases[i], FALSE);
        CheckDnsQuery(&Cases[i], TRUE);
        CheckGetAddrInfo(&Cases[i]);
        CheckHostent(&Cases[i]);
        CheckGetAddrInfoEx(&Cases[i]);
    }

    WSACleanup();
}
