/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DnsQuery_A / DnsQuery_UTF8 give the records of DnsQuery_W with the header fields (section,
 *              TTL, reserved) set, not left as the heap had them; repeated queries (the IPv6 name server
 *              list of dnsapi is kept between them) keep giving the same answer
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windns.h>
#include <apitest.h>

static
void
CheckFields(const char *What, PDNS_RECORD Wide, PDNS_RECORD Other)
{
    ok(Other != NULL, "%s: no record\n", What);
    if (!Wide || !Other)
        return;

    ok(Other->wType == Wide->wType, "%s: type %u, wide %u\n", What, Other->wType, Wide->wType);
    ok(Other->Flags.S.Section == Wide->Flags.S.Section, "%s: section %u, wide %u\n",
       What, (unsigned)Other->Flags.S.Section, (unsigned)Wide->Flags.S.Section);
    ok(Other->dwTtl == Wide->dwTtl, "%s: ttl %lu, wide %lu\n", What, Other->dwTtl, Wide->dwTtl);
    ok(Other->dwReserved == 0, "%s: reserved %lu\n", What, Other->dwReserved);
    ok(Other->wDataLength == Wide->wDataLength, "%s: data length %u, wide %u\n",
       What, Other->wDataLength, Wide->wDataLength);
    ok(Other->Data.A.IpAddress == Wide->Data.A.IpAddress, "%s: address %08lx, wide %08lx\n",
       What, Other->Data.A.IpAddress, Wide->Data.A.IpAddress);
}

START_TEST(DnsRecordFields)
{
    static const char *Names[] = { "localhost", "127.0.0.1" };
    static const WCHAR *NamesW[] = { L"localhost", L"127.0.0.1" };
    WSADATA Data;
    ULONG i, Round;

    WSAStartup(MAKEWORD(2, 2), &Data);

    for (i = 0; i < _countof(Names); i++)
    {
        PDNS_RECORD Wide = NULL, A = NULL, Utf8 = NULL;
        DNS_STATUS Status;

        Status = DnsQuery_W(NamesW[i], DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &Wide, NULL);
        ok(Status == NO_ERROR, "DnsQuery_W(%s) %lu\n", Names[i], Status);
        if (Status != NO_ERROR || !Wide)
            continue;

        Status = DnsQuery_A(Names[i], DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &A, NULL);
        ok(Status == NO_ERROR, "DnsQuery_A(%s) %lu\n", Names[i], Status);
        CheckFields(Names[i], Wide, A);

        Status = DnsQuery_UTF8(Names[i], DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &Utf8, NULL);
        ok(Status == NO_ERROR, "DnsQuery_UTF8(%s) %lu\n", Names[i], Status);
        CheckFields(Names[i], Wide, Utf8);

        if (A)
            DnsRecordListFree(A, DnsFreeRecordList);
        if (Utf8)
            DnsRecordListFree(Utf8, DnsFreeRecordList);

        /* the converted record is a zeroed allocation: the whole header outside the converted fields is clean */
        if (Wide)
        {
            ok(Wide->pNext == NULL || Wide->pNext->dwReserved == 0, "wide chain\n");
            DnsRecordListFree(Wide, DnsFreeRecordList);
        }
    }

    /* many queries in a row: the answer does not change */
    for (Round = 0; Round < 200; Round++)
    {
        PDNS_RECORD Rec = NULL;
        DNS_STATUS Status = DnsQuery_A("localhost", DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &Rec, NULL);

        if (Status != NO_ERROR || !Rec || Rec->Data.A.IpAddress != htonl(INADDR_LOOPBACK))
        {
            ok(0, "round %lu: status %lu, record %p\n", Round, Status, Rec);
            if (Rec)
                DnsRecordListFree(Rec, DnsFreeRecordList);
            break;
        }
        DnsRecordListFree(Rec, DnsFreeRecordList);
    }
    ok(Round == 200, "stopped at round %lu\n", Round);

    WSACleanup();
}
