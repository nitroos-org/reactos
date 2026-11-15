/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IPv6 name servers and gateways in GetAdaptersAddresses
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static IP_ADAPTER_ADDRESSES_LH *GetAdapters(ULONG Family, ULONG Flags)
{
    IP_ADAPTER_ADDRESSES_LH *Adapters = NULL;
    ULONG Size = 0, Tries;
    DWORD Error = ERROR_BUFFER_OVERFLOW;

    for (Tries = 0; Tries < 5 && Error == ERROR_BUFFER_OVERFLOW; Tries++)
    {
        free(Adapters);
        Adapters = Size ? malloc(Size) : NULL;
        Error = GetAdaptersAddresses(Family, Flags, NULL, (PIP_ADAPTER_ADDRESSES)Adapters, &Size);
    }
    if (Error != NO_ERROR)
    {
        free(Adapters);
        return NULL;
    }
    return Adapters;
}

static ULONG CountFamily(PIP_ADAPTER_DNS_SERVER_ADDRESS List, ULONG Family)
{
    ULONG Count = 0;

    for (; List; List = List->Next)
    {
        if (List->Address.lpSockaddr && List->Address.lpSockaddr->sa_family == Family)
            Count++;
    }
    return Count;
}

static ULONG CountGatewayFamily(PIP_ADAPTER_GATEWAY_ADDRESS_LH List, ULONG Family)
{
    ULONG Count = 0;

    for (; List; List = List->Next)
    {
        if (List->Address.lpSockaddr && List->Address.lpSockaddr->sa_family == Family)
            Count++;
    }
    return Count;
}

/* The address of the n-th IPv6 entry of a DNS list, NULL when there is none */
static const SOCKADDR_IN6 *NthServer6(PIP_ADAPTER_DNS_SERVER_ADDRESS List, ULONG n)
{
    for (; List; List = List->Next)
    {
        if (List->Address.lpSockaddr && List->Address.lpSockaddr->sa_family == AF_INET6 && n-- == 0)
            return (const SOCKADDR_IN6 *)List->Address.lpSockaddr;
    }
    return NULL;
}

START_TEST(Ipv6Dns)
{
    static const UCHAR Global[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0x53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const UCHAR LinkLocal[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 };
    IP_ADAPTER_ADDRESSES_LH *All, *A, *V6Adapter = NULL, *Result;
    char KeyName[512];
    HKEY Key;
    WSADATA Data;
    DWORD Error, Type, Size, HadValue;
    char Old[512];
    ULONG Family;

    WSAStartup(MAKEWORD(2, 2), &Data);

    All = GetAdapters(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS);
    ok(All != NULL, "GetAdaptersAddresses(AF_UNSPEC)\n");
    if (!All)
        return;

    for (A = All; A; A = A->Next)
    {
        if (A->IfType != IF_TYPE_SOFTWARE_LOOPBACK && (A->Flags & IP_ADAPTER_IPV6_ENABLED) && !V6Adapter)
            V6Adapter = A;
    }

    if (!V6Adapter)
    {
        /* without IPv6 nothing IPv6 is in any list, and the IPv6 family has no adapter */
        for (A = All; A; A = A->Next)
        {
            ok(CountFamily(A->FirstDnsServerAddress, AF_INET6) == 0, "adapter %lu: IPv6 DNS server without IPv6\n", A->IfIndex);
            ok(CountGatewayFamily(A->FirstGatewayAddress, AF_INET6) == 0, "adapter %lu: IPv6 gateway without IPv6\n", A->IfIndex);
        }
        /* The IPv6 loopback pseudo interface is an IPv6 adapter of its own: a machine with IPv6 on but no network
         * adapter (a VM started without a NIC) lists it. Only an adapter that is not the loopback is a defect here. */
        Result = GetAdapters(AF_INET6, 0);
        for (A = Result; A; A = A->Next)
            ok(A->IfType == IF_TYPE_SOFTWARE_LOOPBACK, "GetAdaptersAddresses(AF_INET6) without IPv6 lists adapter %lu\n", A->IfIndex);
        free(Result);
        free(All);
        skip("no adapter with IPv6 (no network adapter, or IPv6 is off): the IPv6 name server and gateway lists are empty, nothing more to check\n");
        return;
    }

    /* the IPv4 family never carries an IPv6 entry */
    Result = GetAdapters(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS);
    ok(Result != NULL, "GetAdaptersAddresses(AF_INET)\n");
    for (A = Result; A; A = A->Next)
    {
        ok(CountFamily(A->FirstDnsServerAddress, AF_INET6) == 0, "AF_INET: IPv6 DNS server on adapter %lu\n", A->IfIndex);
        ok(CountGatewayFamily(A->FirstGatewayAddress, AF_INET6) == 0, "AF_INET: IPv6 gateway on adapter %lu\n", A->IfIndex);
    }
    free(Result);

    /* the IPv6 family never carries an IPv4 one */
    Result = GetAdapters(AF_INET6, GAA_FLAG_INCLUDE_GATEWAYS);
    ok(Result != NULL, "GetAdaptersAddresses(AF_INET6)\n");
    for (A = Result; A; A = A->Next)
    {
        ok(CountFamily(A->FirstDnsServerAddress, AF_INET) == 0, "AF_INET6: IPv4 DNS server on adapter %lu\n", A->IfIndex);
        ok(CountGatewayFamily(A->FirstGatewayAddress, AF_INET) == 0, "AF_INET6: IPv4 gateway on adapter %lu\n", A->IfIndex);
    }
    free(Result);

    if (!is_reactos())
    {
        skip("the name servers configured for IPv6 are ReactOS's registry values\n");
        free(All);
        return;
    }

    /* a configured IPv6 name server list (registry, as for IPv4): a global address and a link-local one, whose zone
       is the interface of the adapter */
    snprintf(KeyName, sizeof(KeyName), "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\%s",
             V6Adapter->AdapterName);
    Error = RegCreateKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyEx(%s): %lu\n", KeyName, Error);
    if (Error != ERROR_SUCCESS)
    {
        free(All);
        return;
    }
    Size = sizeof(Old) - 1;
    HadValue = (RegQueryValueExA(Key, "NameServer", NULL, &Type, (LPBYTE)Old, &Size) == ERROR_SUCCESS && Type == REG_SZ);
    if (HadValue)
        Old[Size] = '\0';

    Error = RegSetValueExA(Key, "NameServer", 0, REG_SZ, (const BYTE *)"2001:db8:53::1,fe80::53 garbage", 32);
    ok(Error == ERROR_SUCCESS, "RegSetValueEx: %lu\n", Error);

    for (Family = 0; Family < 2; Family++)
    {
        const SOCKADDR_IN6 *S0, *S1;

        Result = GetAdapters(Family ? AF_UNSPEC : AF_INET6, 0);
        ok(Result != NULL, "GetAdaptersAddresses family %lu\n", Family);
        for (A = Result; A; A = A->Next)
        {
            if (A->IfIndex == V6Adapter->IfIndex)
                break;
        }
        ok(A != NULL, "family %lu: adapter %lu not listed\n", Family, V6Adapter->IfIndex);
        if (A)
        {
            S0 = NthServer6(A->FirstDnsServerAddress, 0);
            S1 = NthServer6(A->FirstDnsServerAddress, 1);
            ok(S0 && S1, "family %lu: both configured servers listed (%p %p)\n", Family, S0, S1);
            if (S0 && S1)
            {
                ok(!memcmp(&S0->sin6_addr, Global, 16), "family %lu: first server is 2001:db8:53::1\n", Family);
                ok(S0->sin6_scope_id == 0, "family %lu: global server has scope %lu\n", Family, S0->sin6_scope_id);
                ok(!memcmp(&S1->sin6_addr, LinkLocal, 16), "family %lu: second server is fe80::53\n", Family);
                ok(S1->sin6_scope_id == A->IfIndex, "family %lu: link-local server scope %lu, expected %lu\n", Family,
                   S1->sin6_scope_id, A->IfIndex);
                ok(S0->sin6_port == 0 && S1->sin6_port == 0, "family %lu: ports %u %u\n", Family, S0->sin6_port, S1->sin6_port);
            }
            /* the configured ones come first; router advertisements may add theirs (QEMU's user network has one) after them */
            ok(CountFamily(A->FirstDnsServerAddress, AF_INET6) >= 2, "family %lu: %lu IPv6 servers, expected 2 or more (the text after the blank is not an address)\n",
               Family, CountFamily(A->FirstDnsServerAddress, AF_INET6));
        }
        free(Result);
    }

    /* the flag that skips the name servers skips these too */
    Result = GetAdapters(AF_INET6, GAA_FLAG_SKIP_DNS_SERVER);
    for (A = Result; A; A = A->Next)
        ok(A->FirstDnsServerAddress == NULL, "GAA_FLAG_SKIP_DNS_SERVER: servers on adapter %lu\n", A->IfIndex);
    free(Result);

    /* restore */
    if (HadValue)
        RegSetValueExA(Key, "NameServer", 0, REG_SZ, (const BYTE *)Old, (DWORD)strlen(Old) + 1);
    else
        RegDeleteValueA(Key, "NameServer");
    RegCloseKey(Key);

    /* the value is gone again */
    Result = GetAdapters(AF_INET6, 0);
    for (A = Result; A; A = A->Next)
    {
        if (A->IfIndex == V6Adapter->IfIndex && !HadValue)
        {
            const SOCKADDR_IN6 *S = NthServer6(A->FirstDnsServerAddress, 0);

            ok(!S || memcmp(&S->sin6_addr, Global, 16), "the configured server is still listed after it was removed\n");
        }
    }
    free(Result);
    free(All);
}
