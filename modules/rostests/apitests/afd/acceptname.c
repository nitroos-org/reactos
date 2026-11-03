/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     IOCTL_AFD_GET_SOCK_NAME on a socket returned by accept() reports the
 *              connection's own local address (the one the client connected to),
 *              not the wildcard address the listener is bound to; a listener bound
 *              to a concrete address and the listener itself are unchanged.
 *              (ws2_32_apitest acceptname checks the same through Winsock, with
 *              values recorded on Windows 10 22H2; this IOCTL is ReactOS-specific.)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"

static
NTSTATUS
GetSockName(
    _In_ HANDLE Socket,
    _Out_ PTDI_ADDRESS_INFO Info,
    _In_ ULONG InfoLength)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    HANDLE Event;
    LARGE_INTEGER Timeout;

    RtlFillMemory(Info, InfoLength, 0x55);
    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (!NT_SUCCESS(Status))
        return Status;

    IoStatus.Status = STATUS_PENDING;
    Status = NtDeviceIoControlFile(Socket, Event, NULL, NULL, &IoStatus,
                                   IOCTL_AFD_GET_SOCK_NAME, NULL, 0, Info, InfoLength);
    if (Status == STATUS_PENDING)
    {
        Timeout.QuadPart = -10000000LL * 10;
        if (NtWaitForSingleObject(Event, FALSE, &Timeout) != STATUS_WAIT_0)
        {
            NtCancelIoFile(Socket, &IoStatus);
            NtWaitForSingleObject(Event, FALSE, NULL);
        }
        Status = IoStatus.Status;
    }
    NtClose(Event);
    return Status;
}

static
void
CheckAfdName(
    _In_ PCSTR What,
    _In_ SOCKET Socket,
    _In_ ULONG Address,
    _In_ USHORT Port)
{
    UCHAR Buffer[sizeof(TDI_ADDRESS_INFO) + 64];
    PTDI_ADDRESS_INFO Info = (PTDI_ADDRESS_INFO)Buffer;
    PTDI_ADDRESS_IP Ip;
    NTSTATUS Status;

    Status = GetSockName((HANDLE)Socket, Info, sizeof(Buffer));
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    ok(Info->Address.TAAddressCount == 1, "%s: TAAddressCount %ld\n", What, Info->Address.TAAddressCount);
    ok(Info->Address.Address[0].AddressType == TDI_ADDRESS_TYPE_IP,
       "%s: AddressType %u\n", What, Info->Address.Address[0].AddressType);
    ok(Info->Address.Address[0].AddressLength == TDI_ADDRESS_LENGTH_IP,
       "%s: AddressLength %u\n", What, Info->Address.Address[0].AddressLength);
    Ip = (PTDI_ADDRESS_IP)Info->Address.Address[0].Address;
    ok(Ip->in_addr == Address, "%s: address 0x%08lx, expected 0x%08lx\n", What, Ip->in_addr, Address);
    ok(Ip->sin_port == Port, "%s: port %u, expected %u\n", What, ntohs(Ip->sin_port), ntohs(Port));
}

static
void
TestAcceptedName(
    _In_ ULONG Target,
    _In_ ULONG BindAddress)
{
    struct sockaddr_in Address;
    SOCKET Listener, Client, Accepted;
    USHORT Port;
    int Length;
    char What[64];

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Listener != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());
    if (Listener == INVALID_SOCKET)
        return;
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = BindAddress;
    ok(bind(Listener, (struct sockaddr *)&Address, sizeof(Address)) == 0, "bind failed %d\n", WSAGetLastError());
    ok(listen(Listener, 5) == 0, "listen failed %d\n", WSAGetLastError());
    Length = sizeof(Address);
    getsockname(Listener, (struct sockaddr *)&Address, &Length);
    Port = Address.sin_port;

    sprintf(What, "bind 0x%08lx, connect to 0x%08lx", BindAddress, Target);
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = Target;
    Address.sin_port = Port;
    ok(connect(Client, (struct sockaddr *)&Address, sizeof(Address)) == 0,
       "%s: connect failed %d\n", What, WSAGetLastError());
    Accepted = accept(Listener, NULL, NULL);
    ok(Accepted != INVALID_SOCKET, "%s: accept failed %d\n", What, WSAGetLastError());
    if (Accepted != INVALID_SOCKET)
    {
        CheckAfdName(What, Accepted, Target, Port);
        /* the connection's name does not depend on how often it is asked for */
        CheckAfdName(What, Accepted, Target, Port);
        closesocket(Accepted);
    }
    CheckAfdName("listener", Listener, BindAddress, Port);
    closesocket(Client);
    closesocket(Listener);
}

static
ULONG
FindInterfaceAddress(void)
{
    struct sockaddr_in Address;
    int Length;
    SOCKET Socket;
    ULONG Result = 0;
    int Tries;

    /* A freshly booted machine may still be waiting for its address */
    for (Tries = 0; Tries < 30 && Result == 0; Tries++)
    {
        Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (Socket == INVALID_SOCKET)
            return 0;
        ZeroMemory(&Address, sizeof(Address));
        Address.sin_family = AF_INET;
        Address.sin_port = htons(9);
        Address.sin_addr.s_addr = inet_addr("203.0.113.9");
        Length = sizeof(Address);
        /* connect() on a datagram socket sends nothing */
        if (connect(Socket, (struct sockaddr *)&Address, sizeof(Address)) == 0 &&
            getsockname(Socket, (struct sockaddr *)&Address, &Length) == 0)
            Result = Address.sin_addr.s_addr;
        closesocket(Socket);
        if (Result == 0)
            Sleep(500);
    }
    return Result;
}

START_TEST(acceptname)
{
    WSADATA WsaData;
    ULONG Interface;
    INT Error;

    Error = WSAStartup(MAKEWORD(2, 2), &WsaData);
    ok(Error == 0, "WSAStartup failed with %d\n", Error);
    if (Error != 0)
        return;

    TestAcceptedName(htonl(INADDR_LOOPBACK), htonl(INADDR_ANY));
    Interface = FindInterfaceAddress();
    if (Interface != 0 && Interface != htonl(INADDR_LOOPBACK))
        TestAcceptedName(Interface, htonl(INADDR_ANY));
    else
        skip("no interface address to connect through\n");
    TestAcceptedName(htonl(INADDR_LOOPBACK), htonl(INADDR_LOOPBACK));

    WSACleanup();
}
