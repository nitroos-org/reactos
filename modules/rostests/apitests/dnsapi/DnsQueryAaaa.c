/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DnsQuery with DNS_TYPE_AAAA for the names that need no name server
 *              (the expected values are what Windows 10 answers, measured)
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windns.h>
#include <apitest.h>

static
void
CheckLoopback(PDNS_RECORD Record, const char *What)
{
    static const BYTE Expected[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    ok(Record != NULL, "%s: no record\n", What);
    if (!Record)
        return;
    ok(Record->wType == DNS_TYPE_AAAA, "%s: type %u\n", What, Record->wType);
    ok(Record->wDataLength == sizeof(DNS_AAAA_DATA), "%s: data length %u\n", What, Record->wDataLength);
    ok(memcmp(&Record->Data.AAAA.Ip6Address, Expected, 16) == 0, "%s: not ::1\n", What);
    ok(Record->pNext == NULL, "%s: more than one record\n", What);
}

START_TEST(DnsQueryAaaa)
{
    PDNS_RECORD Record;
    DNS_STATUS Status;
    char Host[256];
    DWORD Size;
    BYTE Literal[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99 };

    /* "localhost" answers ::1 whatever the options (Windows 10 measured, also with DNS_QUERY_NO_WIRE_QUERY) */
    Record = NULL;
    Status = DnsQuery_A("localhost", DNS_TYPE_AAAA, DNS_QUERY_STANDARD, NULL, &Record, NULL);
    ok(Status == ERROR_SUCCESS, "DnsQuery_A localhost AAAA: %lu\n", Status);
    CheckLoopback(Record, "DnsQuery_A");
    if (Record) DnsRecordListFree(Record, DnsFreeRecordList);

    Record = NULL;
    Status = DnsQuery_A("localhost", DNS_TYPE_AAAA, DNS_QUERY_NO_WIRE_QUERY, NULL, &Record, NULL);
    ok(Status == ERROR_SUCCESS, "DnsQuery_A localhost AAAA no wire: %lu\n", Status);
    CheckLoopback(Record, "DnsQuery_A no wire");
    if (Record) DnsRecordListFree(Record, DnsFreeRecordList);

    Record = NULL;
    Status = DnsQuery_UTF8("localhost", DNS_TYPE_AAAA, DNS_QUERY_STANDARD, NULL, &Record, NULL);
    ok(Status == ERROR_SUCCESS, "DnsQuery_UTF8 localhost AAAA: %lu\n", Status);
    CheckLoopback(Record, "DnsQuery_UTF8");
    if (Record) DnsRecordListFree(Record, DnsFreeRecordList);

    Record = NULL;
    Status = DnsQuery_W(L"LocalHost.", DNS_TYPE_AAAA, DNS_QUERY_STANDARD, NULL, &Record, NULL);
    ok(Status == ERROR_SUCCESS, "DnsQuery_W LocalHost. AAAA: %lu\n", Status);
    if (Record)
    {
        ok(Record->wType == DNS_TYPE_AAAA, "type %u\n", Record->wType);
        DnsRecordListFree(Record, DnsFreeRecordList);
    }

    /* An IPv6 literal is its own AAAA record */
    {
        char Text[64];
        sprintf(Text, "2001:db8::%x", Literal[15]);
        Record = NULL;
        Status = DnsQuery_A(Text, DNS_TYPE_AAAA, DNS_QUERY_STANDARD, NULL, &Record, NULL);
        ok(Status == ERROR_SUCCESS, "DnsQuery_A literal AAAA: %lu\n", Status);
        if (Status == ERROR_SUCCESS && Record)
        {
            ok(Record->wType == DNS_TYPE_AAAA, "literal type %u\n", Record->wType);
            ok(memcmp(&Record->Data.AAAA.Ip6Address, Literal, 16) == 0, "literal differs\n");
        }
        if (Record) DnsRecordListFree(Record, DnsFreeRecordList);
    }

    /* The name of this machine: its IPv6 addresses (Windows 10 measured: the link-local address, no ::1), or no
       record while the machine has none */
    Size = sizeof(Host);
    if (GetComputerNameExA(ComputerNameDnsFullyQualified, Host, &Size))
    {
        Record = NULL;
        Status = DnsQuery_A(Host, DNS_TYPE_AAAA, DNS_QUERY_STANDARD, NULL, &Record, NULL);
        ok(Status == ERROR_SUCCESS || Status == DNS_INFO_NO_RECORDS, "own name AAAA: %lu\n", Status);
        if (Status == ERROR_SUCCESS)
        {
            PDNS_RECORD R;
            static const BYTE Zero[16] = { 0 };
            BYTE Loop[16] = { 0 };

            Loop[15] = 1;
            ok(Record != NULL, "own name: success without a record\n");
            for (R = Record; R; R = R->pNext)
            {
                ok(R->wType == DNS_TYPE_AAAA, "own name: type %u\n", R->wType);
                ok(memcmp(&R->Data.AAAA.Ip6Address, Loop, 16) != 0, "own name: ::1\n");
                ok(memcmp(&R->Data.AAAA.Ip6Address, Zero, 16) != 0, "own name: ::\n");
            }
        }
        else
        {
            ok(Record == NULL, "own name: record with an error\n");
        }
        if (Record) DnsRecordListFree(Record, DnsFreeRecordList);
    }

    /* Nothing to ask without wire: not an answer, and no crash */
    Record = NULL;
    Status = DnsQuery_A("no-such-name.invalid", DNS_TYPE_AAAA, DNS_QUERY_NO_WIRE_QUERY, NULL, &Record, NULL);
    ok(Status != ERROR_SUCCESS, "no wire query of an unknown name succeeded\n");
    if (Status == ERROR_SUCCESS && Record) DnsRecordListFree(Record, DnsFreeRecordList);
}
