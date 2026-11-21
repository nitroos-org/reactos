/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A DHCP renewal that confirms the address keeps it: no address change, TCP connections on it live on
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>

/*
 * Windows keeps a DHCP address in place when the server confirms it (a renewal, or the check of the lease after a
 * link drop): the stack sees no change and connections that use the address go on. The test holds a TCP connection
 * between two sockets of this computer on the DHCP address, renews the lease and checks that both ends still work and
 * that NotifyUnicastIpAddressChange reported no deletion of the address.
 */

/* the head of MIB_UNICASTIPADDRESS_ROW, and the notification types (MibAddInstance 1, MibDeleteInstance 2) */
typedef struct
{
    SOCKADDR_INET Address;
} UNICAST_ROW_HEAD;

typedef VOID (WINAPI *FN_UNICAST_CALLBACK)(PVOID, UNICAST_ROW_HEAD *, ULONG);
typedef DWORD (WINAPI *FN_NOTIFY_UNICAST)(ADDRESS_FAMILY, FN_UNICAST_CALLBACK, PVOID, BOOLEAN, HANDLE *);
typedef DWORD (WINAPI *FN_CANCEL)(HANDLE);

static volatile LONG Deleted, Added;
static IN_ADDR Watched;

static VOID WINAPI UnicastCallback(PVOID Context, UNICAST_ROW_HEAD *Row, ULONG Type)
{
    if (!Row || Row->Address.si_family != AF_INET || Row->Address.Ipv4.sin_addr.s_addr != Watched.s_addr)
        return;
    if (Type == 2)
        InterlockedIncrement(&Deleted);
    else if (Type == 1)
        InterlockedIncrement(&Added);
}

static BOOL FindDhcpAdapter(DWORD *Index, IN_ADDR *Address)
{
    PIP_ADAPTER_INFO Info, Cur;
    ULONG Size = 0;
    BOOL Found = FALSE;

    if (GetAdaptersInfo(NULL, &Size) != ERROR_BUFFER_OVERFLOW)
        return FALSE;
    Info = malloc(Size);
    if (!Info)
        return FALSE;
    if (GetAdaptersInfo(Info, &Size) == NO_ERROR)
    {
        for (Cur = Info; Cur && !Found; Cur = Cur->Next)
        {
            ULONG A = inet_addr(Cur->IpAddressList.IpAddress.String);

            if (Cur->DhcpEnabled && A != INADDR_NONE && A != 0 && (ntohl(A) & 0xFFFF0000) != 0xA9FE0000)
            {
                *Index = Cur->Index;
                Address->s_addr = A;
                Found = TRUE;
            }
        }
    }
    free(Info);
    return Found;
}

static BOOL MapFor(DWORD Index, IP_ADAPTER_INDEX_MAP *Map)
{
    PIP_INTERFACE_INFO Info;
    ULONG Size = 0, i;
    BOOL Found = FALSE;

    if (GetInterfaceInfo(NULL, &Size) != ERROR_INSUFFICIENT_BUFFER)
        return FALSE;
    Info = malloc(Size);
    if (!Info)
        return FALSE;
    if (GetInterfaceInfo(Info, &Size) == NO_ERROR)
    {
        for (i = 0; i < (ULONG)Info->NumAdapters; i++)
        {
            if (Info->Adapter[i].Index == Index)
            {
                *Map = Info->Adapter[i];
                Found = TRUE;
                break;
            }
        }
    }
    free(Info);
    return Found;
}

static BOOL Exchange(SOCKET From, SOCKET To, char Byte)
{
    char Got = 0;
    DWORD Timeout = 5000;

    setsockopt(To, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
    if (send(From, &Byte, 1, 0) != 1)
        return FALSE;
    return recv(To, &Got, 1, 0) == 1 && Got == Byte;
}

START_TEST(LeaseRenew)
{
    WSADATA Wsa;
    DWORD Index = 0, Error;
    IP_ADAPTER_INDEX_MAP Map;
    SOCKADDR_IN Sa;
    int Len = sizeof(Sa);
    SOCKET Listener, Client, Server;
    HANDLE Notify = NULL;
    DWORD Start;
    HMODULE Module = GetModuleHandleW(L"iphlpapi.dll");
    FN_NOTIFY_UNICAST pNotify = (FN_NOTIFY_UNICAST)GetProcAddress(Module, "NotifyUnicastIpAddressChange");
    FN_CANCEL pCancel = (FN_CANCEL)GetProcAddress(Module, "CancelMibChangeNotify2");

    if (!FindDhcpAdapter(&Index, &Watched))
    {
        skip("no adapter with an address from DHCP\n");
        return;
    }
    if (!MapFor(Index, &Map))
    {
        skip("adapter %lu is not in GetInterfaceInfo\n", Index);
        return;
    }
    ok(WSAStartup(MAKEWORD(2, 2), &Wsa) == 0, "WSAStartup failed\n");

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&Sa, 0, sizeof(Sa));
    Sa.sin_family = AF_INET;
    Sa.sin_addr = Watched;
    ok(bind(Listener, (SOCKADDR *)&Sa, sizeof(Sa)) == 0, "bind to %s failed: %d\n", inet_ntoa(Watched), WSAGetLastError());
    ok(listen(Listener, 1) == 0, "listen failed: %d\n", WSAGetLastError());
    getsockname(Listener, (SOCKADDR *)&Sa, &Len);
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(connect(Client, (SOCKADDR *)&Sa, sizeof(Sa)) == 0, "connect to %s failed: %d\n", inet_ntoa(Watched), WSAGetLastError());
    Server = accept(Listener, NULL, NULL);
    ok(Server != INVALID_SOCKET, "accept failed: %d\n", WSAGetLastError());
    if (Server == INVALID_SOCKET)
        goto done;
    ok(Exchange(Client, Server, 'a') && Exchange(Server, Client, 'b'), "the connection does not work before the renewal\n");

    if (pNotify && pCancel)
    {
        Error = pNotify(AF_INET, UnicastCallback, NULL, FALSE, &Notify);
        ok(Error == NO_ERROR, "NotifyUnicastIpAddressChange returned %lu\n", Error);
    }

    Error = IpRenewAddress(&Map);
    if (Error == ERROR_PROC_NOT_FOUND || Error == ERROR_FILE_NOT_FOUND)
    {
        skip("the DHCP client cannot renew adapter %lu (%lu)\n", Index, Error);
        goto done;
    }
    ok(Error == NO_ERROR, "IpRenewAddress returned %lu\n", Error);

    /* the answer of the server and the configuration that follows it */
    Start = GetTickCount();
    while (GetTickCount() - Start < 4000)
        Sleep(200);

    ok(Deleted == 0, "the address %s was deleted %ld times by the renewal\n", inet_ntoa(Watched), Deleted);
    ok(Added == 0, "the address %s was added %ld times by the renewal\n", inet_ntoa(Watched), Added);
    ok(Exchange(Client, Server, 'c'), "client to server after the renewal failed (%d)\n", WSAGetLastError());
    ok(Exchange(Server, Client, 'd'), "server to client after the renewal failed (%d)\n", WSAGetLastError());

done:
    if (Notify)
        pCancel(Notify);
    if (Server != INVALID_SOCKET)
        closesocket(Server);
    closesocket(Client);
    closesocket(Listener);
    WSACleanup();
}
