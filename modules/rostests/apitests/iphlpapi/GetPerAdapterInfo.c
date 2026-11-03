/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for GetPerAdapterInfo, including the loopback adapter (no per-interface registry key)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>

static void TestIndex(ULONG Index, BOOL IsLoopback)
{
    IP_PER_ADAPTER_INFO *Info;
    ULONG Size = 0, Need;
    DWORD Error;

    Error = GetPerAdapterInfo(Index, NULL, &Size);
    ok(Error == ERROR_BUFFER_OVERFLOW, "index %lu: size query returned %lu\n", Index, Error);
    ok(Size >= sizeof(IP_PER_ADAPTER_INFO), "index %lu: size %lu\n", Index, Size);
    if (Error != ERROR_BUFFER_OVERFLOW)
        return;
    Need = Size;

    /* Windows 10 measured: the size is sizeof + one IP_ADDR_STRING, for the loopback too */
    ok(Need == sizeof(IP_PER_ADAPTER_INFO) + sizeof(IP_ADDR_STRING) || !IsLoopback, "index %lu: size %lu\n", Index, Need);

    Info = malloc(Need + 64);
    Size = Need - 1;
    Error = GetPerAdapterInfo(Index, Info, &Size);
    ok(Error == ERROR_BUFFER_OVERFLOW, "index %lu: short buffer returned %lu\n", Index, Error);
    ok(Size == Need, "index %lu: short buffer, size %lu, expected %lu\n", Index, Size, Need);

    memset(Info, 0xcc, Need + 64);
    Size = Need;
    Error = GetPerAdapterInfo(Index, Info, &Size);
    ok(Error == NO_ERROR, "index %lu: GetPerAdapterInfo returned %lu (the loopback has no registry key)\n", Index, Error);
    if (Error == NO_ERROR)
    {
        ok(Info->AutoconfigEnabled == 1, "index %lu: AutoconfigEnabled %lu\n", Index, Info->AutoconfigEnabled);
        ok(Info->AutoconfigActive == 0, "index %lu: AutoconfigActive %lu\n", Index, Info->AutoconfigActive);
        ok(Info->CurrentDnsServer == NULL, "index %lu: CurrentDnsServer %p\n", Index, Info->CurrentDnsServer);
        if (IsLoopback)
        {
            ok(Info->DnsServerList.IpAddress.String[0] == 0, "loopback: DNS server \"%s\"\n",
               Info->DnsServerList.IpAddress.String);
            ok(Info->DnsServerList.Next == NULL, "loopback: DNS list not empty\n");
        }
    }
    free(Info);
}

START_TEST(GetPerAdapterInfo)
{
    IP_ADAPTER_ADDRESSES *Adapters = NULL, *A;
    ULONG Size = 0, Tries, Count = 0;
    DWORD Error = ERROR_BUFFER_OVERFLOW;
    IP_PER_ADAPTER_INFO Dummy[4];

    for (Tries = 0; Tries < 5 && Error == ERROR_BUFFER_OVERFLOW; Tries++)
    {
        free(Adapters);
        Adapters = Size ? malloc(Size) : NULL;
        Error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                     NULL, Adapters, &Size);
    }
    ok(Error == NO_ERROR, "GetAdaptersAddresses: %lu\n", Error);
    if (Error != NO_ERROR)
    {
        free(Adapters);
        return;
    }

    for (A = Adapters; A; A = A->Next)
    {
        Count++;
        TestIndex(A->IfIndex, A->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
    }
    ok(Count != 0, "no adapters\n");
    free(Adapters);

    /* Windows checks the index first, then the buffer */
    Size = 0;
    Error = GetPerAdapterInfo(0xdead, NULL, &Size);
    ok(Error == ERROR_NO_DATA, "bogus index: %lu\n", Error);
    ok(Size == 0, "bogus index: size %lu\n", Size);
    Size = sizeof(Dummy);
    Error = GetPerAdapterInfo(0xdead, Dummy, &Size);
    ok(Error == ERROR_NO_DATA, "bogus index with buffer: %lu\n", Error);
    Error = GetPerAdapterInfo(1, Dummy, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "NULL size: %lu\n", Error);
}
