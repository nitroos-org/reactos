/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SIO_ADDRESS_LIST_CHANGE on an AF_INET6 socket: one change of the IPv6 address list wakes a waiter once
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

#include <mswsock.h>
#include <iphlpapi.h>
#include <wine/netioapi.h>
#include <stdlib.h>

/*
 * A waiter that queues the request again at once after each completion counts how often one change wakes it. Windows
 * Server 2022 (measured on a peer): adding a manual IPv6 address completes it once (when the address becomes
 * preferred), deleting it once. NitroOS completes it when the address is added and when duplicate address detection
 * ends: at most two. Adding the address needs an administrator and IPv6 on an adapter; otherwise the test is skipped.
 */

#ifndef SIO_ADDRESS_LIST_CHANGE
#define SIO_ADDRESS_LIST_CHANGE _WSAIOW(IOC_WS2, 23)
#endif

static DWORD (WINAPI *pCreateUnicastIpAddressEntry)(const MIB_UNICASTIPADDRESS_ROW *);
static DWORD (WINAPI *pDeleteUnicastIpAddressEntry)(const MIB_UNICASTIPADDRESS_ROW *);

static volatile LONG g_Count;
static volatile LONG g_Stop;

static DWORD WINAPI
waiter(LPVOID p)
{
    SOCKET s = (SOCKET)(ULONG_PTR)p;
    WSAOVERLAPPED ov;
    DWORD n;

    while (!g_Stop)
    {
        memset(&ov, 0, sizeof(ov));
        ov.hEvent = WSACreateEvent();
        if (WSAIoctl(s, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &n, &ov, NULL) == SOCKET_ERROR &&
            WSAGetLastError() != WSA_IO_PENDING)
        {
            WSACloseEvent(ov.hEvent);
            break;
        }
        while (!g_Stop && WaitForSingleObject(ov.hEvent, 100) == WAIT_TIMEOUT)
            ;
        if (g_Stop)
        {
            /* the socket is closed: the request completes, aborted */
            WaitForSingleObject(ov.hEvent, 2000);
            WSACloseEvent(ov.hEvent);
            break;
        }
        InterlockedIncrement(&g_Count);
        WSACloseEvent(ov.hEvent);
    }
    return 0;
}

static ULONG
ipv6_interface(void)
{
    ULONG size = 0, index = 0;
    IP_ADAPTER_ADDRESSES *aa, *a;

    GetAdaptersAddresses(AF_INET6, 0, NULL, NULL, &size);
    aa = malloc(size);
    if (!aa || GetAdaptersAddresses(AF_INET6, 0, NULL, aa, &size))
    {
        free(aa);
        return 0;
    }
    for (a = aa; a && !index; a = a->Next)
        if (a->IfType != IF_TYPE_SOFTWARE_LOOPBACK && a->OperStatus == IfOperStatusUp && a->Ipv6IfIndex)
            index = a->Ipv6IfIndex;
    free(aa);
    return index;
}

START_TEST(addrchange6)
{
    WSADATA wd;
    SOCKET s;
    HANDLE thread;
    MIB_UNICASTIPADDRESS_ROW row;
    ULONG index;
    DWORD err;
    LONG added, deleted;
    int quiet;
    PCSTR end;

    ok(WSAStartup(MAKEWORD(2, 2), &wd) == 0, "WSAStartup\n");
    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    index = ipv6_interface();
    if (s == INVALID_SOCKET || !index)
    {
        skip("no IPv6 on an adapter (socket %d, interface %lu)\n", s != INVALID_SOCKET, index);
        WSACleanup();
        return;
    }

    {
        HMODULE iphlpapi = GetModuleHandleA("iphlpapi.dll");

        pCreateUnicastIpAddressEntry = (void *)GetProcAddress(iphlpapi, "CreateUnicastIpAddressEntry");
        pDeleteUnicastIpAddressEntry = (void *)GetProcAddress(iphlpapi, "DeleteUnicastIpAddressEntry");
    }
    if (!pCreateUnicastIpAddressEntry || !pDeleteUnicastIpAddressEntry)
    {
        skip("no CreateUnicastIpAddressEntry\n");
        closesocket(s);
        WSACleanup();
        return;
    }

    /* as InitializeUnicastIpAddressEntry leaves it: infinite lifetimes, the stack's choices for the rest */
    memset(&row, 0, sizeof(row));
    row.PrefixOrigin = IpPrefixOriginUnchanged;
    row.SuffixOrigin = IpSuffixOriginUnchanged;
    row.ValidLifetime = 0xffffffff;
    row.PreferredLifetime = 0xffffffff;
    row.InterfaceIndex = index;
    row.Address.Ipv6.sin6_family = AF_INET6;
    RtlIpv6StringToAddressA("2001:db8:77:6::61", &end, &row.Address.Ipv6.sin6_addr);
    row.OnLinkPrefixLength = 64;

    thread = CreateThread(NULL, 0, waiter, (LPVOID)(ULONG_PTR)s, 0, NULL);
    /* the waiter is queued; then wait for the stack to be quiet (3 s without a change, at most 30 s): right after boot
       the link-local address, router advertisements and temporary addresses still change the table, and each of those
       would count below */
    Sleep(1500);
    for (quiet = 0; quiet < 10; quiet++)
    {
        InterlockedExchange(&g_Count, 0);
        Sleep(3000);
        if (g_Count == 0)
            break;
    }
    ok(quiet < 10, "the IPv6 table kept changing for 30 s before the test\n");
    InterlockedExchange(&g_Count, 0);

    err = pCreateUnicastIpAddressEntry(&row);
    if (err == ERROR_ACCESS_DENIED)
    {
        skip("not an administrator\n");
        g_Stop = 1;
        closesocket(s);
        WaitForSingleObject(thread, 5000);
        WSACleanup();
        return;
    }
    ok(err == NO_ERROR, "CreateUnicastIpAddressEntry: %lu\n", err);
    Sleep(4000);
    added = InterlockedExchange(&g_Count, 0);

    err = pDeleteUnicastIpAddressEntry(&row);
    ok(err == NO_ERROR, "DeleteUnicastIpAddressEntry: %lu\n", err);
    Sleep(3000);
    deleted = InterlockedExchange(&g_Count, 0);

    trace("completions: add %ld, delete %ld\n", added, deleted);
    ok(added >= 1 && added <= 2, "adding one IPv6 address woke the waiter %ld times (Windows: 1)\n", added);
    ok(deleted >= 1 && deleted <= 2, "deleting it woke the waiter %ld times (Windows: 1)\n", deleted);

    g_Stop = 1;
    closesocket(s);
    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);
    WSACleanup();
}
