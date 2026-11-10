/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Contract tests of the network stack under bad input, cancellation and volume:
 *              - IOCTL_NDIS_QUERY_GLOBAL_STATS with a short input or no output pages is refused,
 *                a valid query is answered as before
 *              - datagrams without data that nobody reads are bounded
 *              - a receive cancelled or closed while pending, with datagrams arriving, completes
 *              - ICMP echo requests from many threads, timed out or answered, all complete
 *              - SendARP from many threads all complete, the system stays usable
 *              - the TCP and UDP tables answer for any entity instance while sockets come and go
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"
#include <ws2tcpip.h>
#include <tdiinfo.h>
#include <iphlpapi.h>
#include <ntddndis.h>
#include <icmpapi.h>

static
NTSTATUS
G8Ioctl(
    _In_ HANDLE File,
    _In_ ULONG Code,
    _In_opt_ PVOID In,
    _In_ ULONG InLen,
    _In_opt_ PVOID Out,
    _In_ ULONG OutLen,
    _Out_opt_ PULONG_PTR Information)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK Iosb;
    HANDLE Event;
    LARGE_INTEGER Timeout;

    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (!NT_SUCCESS(Status))
        return Status;
    Iosb.Status = STATUS_PENDING;
    Iosb.Information = 0;
    Status = NtDeviceIoControlFile(File, Event, NULL, NULL, &Iosb, Code, In, InLen, Out, OutLen);
    if (Status == STATUS_PENDING)
    {
        Timeout.QuadPart = -10000000LL * 20;
        if (NtWaitForSingleObject(Event, FALSE, &Timeout) != STATUS_WAIT_0)
        {
            NtCancelIoFile(File, &Iosb);
            NtWaitForSingleObject(Event, FALSE, NULL);
        }
        Status = Iosb.Status;
    }
    if (Information)
        *Information = Iosb.Information;
    NtClose(Event);
    return Status;
}

static
NTSTATUS
G8OpenDevice(
    _In_ PCWSTR Name,
    _Out_ PHANDLE Handle)
{
    UNICODE_STRING Us;
    OBJECT_ATTRIBUTES Oa;
    IO_STATUS_BLOCK Iosb;

    RtlInitUnicodeString(&Us, Name);
    InitializeObjectAttributes(&Oa, &Us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateFile(Handle, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &Oa, &Iosb,
                        NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
}

static
BOOL
G8StartWinsock(void)
{
    WSADATA Data;

    return WSAStartup(MAKEWORD(2, 2), &Data) == 0;
}

/* A UDP socket bound to the loopback address and a port of the system's choosing */
static
SOCKET
G8BoundUdp(_Out_ struct sockaddr_in *Address)
{
    SOCKET Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int Length = sizeof(*Address);

    if (Socket == INVALID_SOCKET)
        return INVALID_SOCKET;
    memset(Address, 0, sizeof(*Address));
    Address->sin_family = AF_INET;
    Address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Socket, (struct sockaddr *)Address, sizeof(*Address)) != 0 ||
        getsockname(Socket, (struct sockaddr *)Address, &Length) != 0)
    {
        closesocket(Socket);
        return INVALID_SOCKET;
    }
    return Socket;
}

/* ------------------------------------------------------------------ NDIS */

static
BOOL
G8FindAdapterDevice(_Out_writes_(64) PWCHAR Name)
{
    typedef ULONG (WINAPI *PGETADAPTERSINFO)(PIP_ADAPTER_INFO, PULONG);
    PGETADAPTERSINFO pGetAdaptersInfo;
    PIP_ADAPTER_INFO Adapters, Adapter;
    HMODULE Iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    ULONG Size = 0;
    BOOL Found = FALSE;

    pGetAdaptersInfo = Iphlpapi ? (PGETADAPTERSINFO)GetProcAddress(Iphlpapi, "GetAdaptersInfo") : NULL;
    if (!pGetAdaptersInfo || pGetAdaptersInfo(NULL, &Size) != ERROR_BUFFER_OVERFLOW)
        return FALSE;
    Adapters = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Adapters && pGetAdaptersInfo(Adapters, &Size) == ERROR_SUCCESS)
    {
        for (Adapter = Adapters; Adapter && !Found; Adapter = Adapter->Next)
        {
            if (Adapter->AdapterName[0] == '{' && strlen(Adapter->AdapterName) < 50)
            {
                _snwprintf(Name, 64, L"\\Device\\%S", Adapter->AdapterName);
                Found = TRUE;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Adapters);
    return Found;
}

START_TEST(g8ndisstats)
{
    WCHAR Name[64];
    HANDLE Device;
    NTSTATUS Status;
    ULONG Oid, Out[4], Tries;
    ULONG_PTR Info;

    /* The adapter appears a little after the start */
    Status = STATUS_NO_SUCH_DEVICE;
    for (Tries = 0; Tries < 60; Tries++)
    {
        if (G8FindAdapterDevice(Name))
        {
            Status = G8OpenDevice(Name, &Device);
            if (NT_SUCCESS(Status))
                break;
        }
        Sleep(1000);
    }
    if (!NT_SUCCESS(Status))
    {
        skip("no adapter device to open: 0x%lx\n", Status);
        return;
    }

    /* A valid query is answered */
    Oid = OID_GEN_MEDIA_CONNECT_STATUS;
    Out[0] = 0x77777777;
    Info = 0xdeadbeef;
    Status = G8Ioctl(Device, IOCTL_NDIS_QUERY_GLOBAL_STATS, &Oid, sizeof(Oid), Out, sizeof(ULONG), &Info);
    ok(Status == STATUS_SUCCESS, "query of OID_GEN_MEDIA_CONNECT_STATUS gave 0x%lx\n", Status);
    if (Status == STATUS_SUCCESS)
        ok(Info == sizeof(ULONG), "query returned %Iu bytes\n", Info);

    /* An input shorter than the OID, or none, is refused before anything is read from it */
    Status = G8Ioctl(Device, IOCTL_NDIS_QUERY_GLOBAL_STATS, NULL, 0, Out, sizeof(ULONG), NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "query with no input gave 0x%lx\n", Status);
    Status = G8Ioctl(Device, IOCTL_NDIS_QUERY_GLOBAL_STATS, &Oid, 2, Out, sizeof(ULONG), NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "query with a 2 byte input gave 0x%lx\n", Status);

    /* No output pages: the answer has nowhere to go, and the call does not touch any */
    Status = G8Ioctl(Device, IOCTL_NDIS_QUERY_GLOBAL_STATS, &Oid, sizeof(Oid), NULL, 0, &Info);
    ok(Status != STATUS_ACCESS_VIOLATION, "query with no output gave 0x%lx\n", Status);
    Status = G8Ioctl(Device, IOCTL_NDIS_QUERY_GLOBAL_STATS, &Oid, sizeof(Oid), Out, 1, &Info);
    ok(Status != STATUS_SUCCESS || Info <= 1, "query with a 1 byte output returned %Iu bytes\n", Info);

    /* The device still answers */
    Status = G8Ioctl(Device, IOCTL_NDIS_QUERY_GLOBAL_STATS, &Oid, sizeof(Oid), Out, sizeof(ULONG), &Info);
    ok(Status == STATUS_SUCCESS, "query after the bad ones gave 0x%lx\n", Status);
    NtClose(Device);
}

/* ------------------------------------------------------- datagram queue */

START_TEST(g8dgramqueue)
{
    struct sockaddr_in Address, From;
    SOCKET Receiver, Sender;
    ULONG Nonblocking = 1;
    int Count = 0, Sent, i, FromLength;
    char Buffer[16];

    if (!G8StartWinsock())
    {
        skip("no winsock\n");
        return;
    }
    Receiver = G8BoundUdp(&Address);
    Sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(Receiver != INVALID_SOCKET && Sender != INVALID_SOCKET, "sockets\n");
    if (Receiver == INVALID_SOCKET || Sender == INVALID_SOCKET)
        return;

    /* Datagrams without data that nobody reads: the queue they make is bounded (they fill no window) */
    for (Sent = 0, i = 0; i < 5000; i++)
        if (sendto(Sender, Buffer, 0, 0, (struct sockaddr *)&Address, sizeof(Address)) == 0)
            Sent++;
    ok(Sent > 0, "no empty datagram was sent: %d\n", WSAGetLastError());
    Sleep(500);

    ioctlsocket(Receiver, FIONBIO, &Nonblocking);
    for (;;)
    {
        FromLength = sizeof(From);
        if (recvfrom(Receiver, Buffer, sizeof(Buffer), 0, (struct sockaddr *)&From, &FromLength) != 0)
            break;
        Count++;
        if (Count > 4500)
            break;
    }
    trace("sent %d empty datagrams, read %d\n", Sent, Count);
    ok(Count <= 2048, "%d empty datagrams were kept for a socket that does not read\n", Count);

    /* The socket works as before: data arrives and is read */
    ok(sendto(Sender, "abc", 3, 0, (struct sockaddr *)&Address, sizeof(Address)) == 3, "send\n");
    Sleep(300);
    FromLength = sizeof(From);
    i = recvfrom(Receiver, Buffer, sizeof(Buffer), 0, (struct sockaddr *)&From, &FromLength);
    ok(i == 3, "recvfrom after the empty ones gave %d (%d)\n", i, WSAGetLastError());
    closesocket(Sender);
    closesocket(Receiver);
}

/* ---------------------------------------------- receive cancel and close */

typedef struct _G8SENDER
{
    struct sockaddr_in To;
    volatile LONG Stop;
} G8SENDER;

static
DWORD
WINAPI
G8SenderThread(PVOID Context)
{
    G8SENDER *Sender = Context;
    SOCKET Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    while (Socket != INVALID_SOCKET && !Sender->Stop)
        sendto(Socket, "x", 1, 0, (struct sockaddr *)&Sender->To, sizeof(Sender->To));
    if (Socket != INVALID_SOCKET)
        closesocket(Socket);
    return 0;
}

START_TEST(g8dgramcancel)
{
    HANDLE Thread;
    G8SENDER Sender;
    int Round;

    if (!G8StartWinsock())
    {
        skip("no winsock\n");
        return;
    }

    for (Round = 0; Round < 40; Round++)
    {
        struct sockaddr_in Address;
        SOCKET Receiver = G8BoundUdp(&Address);
        WSAOVERLAPPED Overlapped[4];
        WSABUF Wsabuf;
        char Buffer[64][4];
        DWORD Flags, Bytes;
        int i, Pending = 0;
        struct sockaddr_in From[4];
        int FromLength[4];

        if (Receiver == INVALID_SOCKET)
        {
            skip("bind\n");
            return;
        }

        Sender.To = Address;
        Sender.Stop = 0;
        Thread = CreateThread(NULL, 0, G8SenderThread, &Sender, 0, NULL);

        memset(Overlapped, 0, sizeof(Overlapped));
        for (i = 0; i < 4; i++)
        {
            Overlapped[i].hEvent = WSACreateEvent();
            Wsabuf.buf = Buffer[i * 16];
            Wsabuf.len = 16;
            Flags = 0;
            FromLength[i] = sizeof(From[i]);
            if (WSARecvFrom(Receiver, &Wsabuf, 1, &Bytes, &Flags, (struct sockaddr *)&From[i], &FromLength[i],
                            &Overlapped[i], NULL) == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING)
                Pending++;
        }

        /* Cancelled or closed with receives pending while datagrams arrive */
        if (Round & 1)
            CancelIo((HANDLE)Receiver);
        closesocket(Receiver);

        for (i = 0; i < 4; i++)
        {
            DWORD Wait = WaitForSingleObject(Overlapped[i].hEvent, 10000);
            ok(Wait == WAIT_OBJECT_0, "round %d: receive %d of the closed socket did not complete\n", Round, i);
            WSACloseEvent(Overlapped[i].hEvent);
        }
        Sender.Stop = 1;
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
        (void)Pending;
    }

    /* The stack still takes a datagram through */
    {
        struct sockaddr_in Address;
        SOCKET Receiver = G8BoundUdp(&Address), Send = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        char Buffer[8];
        int Length;
        DWORD Timeout = 5000;

        setsockopt(Receiver, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));
        sendto(Send, "ping", 4, 0, (struct sockaddr *)&Address, sizeof(Address));
        Length = recv(Receiver, Buffer, sizeof(Buffer), 0);
        ok(Length == 4, "datagram after the rounds: %d (%d)\n", Length, WSAGetLastError());
        closesocket(Send);
        closesocket(Receiver);
    }
}

/* ------------------------------------------------------------------ ICMP */

typedef HANDLE (WINAPI *PICMPCREATEFILE)(void);
typedef BOOL (WINAPI *PICMPCLOSEHANDLE)(HANDLE);
typedef DWORD (WINAPI *PICMPSENDECHO)(HANDLE, ULONG, LPVOID, WORD, PVOID, LPVOID, DWORD, DWORD);

typedef struct _G8ICMP
{
    PICMPCREATEFILE Create;
    PICMPCLOSEHANDLE Close;
    PICMPSENDECHO Send;
    ULONG Address;
    DWORD Timeout;
    volatile LONG Failures;
    volatile LONG Replies;
} G8ICMP;

static
DWORD
WINAPI
G8IcmpThread(PVOID Context)
{
    G8ICMP *Test = Context;
    int i;

    for (i = 0; i < 25; i++)
    {
        HANDLE Icmp = Test->Create();
        char Request[32] = "contract test";
        char Reply[sizeof(ICMP_ECHO_REPLY) + 32 + 8 + 64];
        DWORD Count;

        if (Icmp == INVALID_HANDLE_VALUE)
        {
            InterlockedIncrement(&Test->Failures);
            continue;
        }
        Count = Test->Send(Icmp, Test->Address, Request, sizeof(Request), NULL, Reply, sizeof(Reply), Test->Timeout);
        if (Count != 0)
            InterlockedIncrement(&Test->Replies);
        Test->Close(Icmp);
    }
    return 0;
}

START_TEST(g8icmp)
{
    HMODULE Iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    G8ICMP Test;
    HANDLE Threads[8];
    int i;

    memset(&Test, 0, sizeof(Test));
    Test.Create = Iphlpapi ? (PICMPCREATEFILE)GetProcAddress(Iphlpapi, "IcmpCreateFile") : NULL;
    Test.Close = Iphlpapi ? (PICMPCLOSEHANDLE)GetProcAddress(Iphlpapi, "IcmpCloseHandle") : NULL;
    Test.Send = Iphlpapi ? (PICMPSENDECHO)GetProcAddress(Iphlpapi, "IcmpSendEcho") : NULL;
    if (!Test.Create || !Test.Close || !Test.Send)
    {
        skip("no icmp api\n");
        return;
    }

    /* Answered by the host itself, from several threads at once */
    Test.Address = htonl(INADDR_LOOPBACK);
    Test.Timeout = 2000;
    for (i = 0; i < 8; i++)
        Threads[i] = CreateThread(NULL, 0, G8IcmpThread, &Test, 0, NULL);
    for (i = 0; i < 8; i++)
    {
        ok(WaitForSingleObject(Threads[i], 120000) == WAIT_OBJECT_0, "echo thread %d did not finish\n", i);
        CloseHandle(Threads[i]);
    }
    ok(Test.Failures == 0, "%ld handles could not be created\n", Test.Failures);
    ok(Test.Replies == 8 * 25, "%ld of %d echoes to the loopback address were answered\n", Test.Replies, 8 * 25);

    /* An address nobody answers (TEST-NET-1): the requests run into their timeout and finish, many at once */
    Test.Address = htonl(0xC0000201);
    Test.Timeout = 100;
    Test.Replies = 0;
    for (i = 0; i < 8; i++)
        Threads[i] = CreateThread(NULL, 0, G8IcmpThread, &Test, 0, NULL);
    for (i = 0; i < 8; i++)
    {
        ok(WaitForSingleObject(Threads[i], 180000) == WAIT_OBJECT_0, "timed out echo thread %d did not finish\n", i);
        CloseHandle(Threads[i]);
    }
    ok(Test.Failures == 0, "%ld handles could not be created\n", Test.Failures);

    /* Bad request sizes are refused */
    {
        HANDLE Ip;
        NTSTATUS Status;
        UCHAR Small[4] = { 0 };
        UCHAR Out[128];

        Status = G8OpenDevice(L"\\Device\\Ip", &Ip);
        if (NT_SUCCESS(Status))
        {
            Status = G8Ioctl(Ip, IOCTL_ICMP_ECHO_REQUEST, Small, sizeof(Small), Out, sizeof(Out), NULL);
            ok(Status == STATUS_INVALID_PARAMETER, "echo request with a 4 byte input gave 0x%lx\n", Status);
            Status = G8Ioctl(Ip, IOCTL_ICMP_ECHO_REQUEST, NULL, 0, NULL, 0, NULL);
            ok(Status == STATUS_INVALID_PARAMETER, "echo request with no input gave 0x%lx\n", Status);
            NtClose(Ip);
        }
    }
}

/* -------------------------------------------------------------- SendARP */

typedef DWORD (WINAPI *PSENDARP)(ULONG, ULONG, PVOID, PULONG);

typedef struct _G8ARP
{
    PSENDARP SendArp;
    ULONG Address;
    volatile LONG *Done;
} G8ARP;

static
DWORD
WINAPI
G8ArpThread(PVOID Context)
{
    G8ARP *Test = Context;
    ULONG Mac[2], Length = 6;

    Test->SendArp(Test->Address, 0, Mac, &Length);
    InterlockedIncrement(Test->Done);
    return 0;
}

START_TEST(g8hwquery)
{
    typedef ULONG (WINAPI *PGETADAPTERSINFO)(PIP_ADAPTER_INFO, PULONG);
    HMODULE Iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    PGETADAPTERSINFO pGetAdaptersInfo;
    PIP_ADAPTER_INFO Adapters, Adapter;
    G8ARP Test, Tests[24];
    volatile LONG Done = 0;
    ULONG Size = 0, Ip = 0, Mask = 0, Mac[2], Length = 6;
    HANDLE Threads[24];
    int i;

    pGetAdaptersInfo = Iphlpapi ? (PGETADAPTERSINFO)GetProcAddress(Iphlpapi, "GetAdaptersInfo") : NULL;
    Test.SendArp = Iphlpapi ? (PSENDARP)GetProcAddress(Iphlpapi, "SendARP") : NULL;
    if (!pGetAdaptersInfo || !Test.SendArp || pGetAdaptersInfo(NULL, &Size) != ERROR_BUFFER_OVERFLOW)
    {
        skip("no adapter list\n");
        return;
    }
    /* The address comes from DHCP a little after the start */
    for (i = 0; i < 90 && !Ip; i++)
    {
        Size = 0;
        if (pGetAdaptersInfo(NULL, &Size) == ERROR_BUFFER_OVERFLOW &&
            (Adapters = HeapAlloc(GetProcessHeap(), 0, Size)) != NULL)
        {
            if (pGetAdaptersInfo(Adapters, &Size) == ERROR_SUCCESS)
            {
                for (Adapter = Adapters; Adapter; Adapter = Adapter->Next)
                {
                    ULONG A = inet_addr(Adapter->IpAddressList.IpAddress.String);
                    ULONG M = inet_addr(Adapter->IpAddressList.IpMask.String);

                    if (A && A != INADDR_NONE && M && M != INADDR_NONE)
                    {
                        Ip = A;
                        Mask = M;
                        break;
                    }
                }
            }
            HeapFree(GetProcessHeap(), 0, Adapters);
        }
        if (!Ip)
            Sleep(1000);
    }
    if (!Ip)
    {
        skip("no adapter with an address\n");
        return;
    }

    /* Many queries for addresses that do not answer: each one waits for the network, and all of them end
       (the ones past the limit are refused at once, the others time out) */
    for (i = 0; i < 24; i++)
    {
        Tests[i].SendArp = Test.SendArp;
        Tests[i].Done = &Done;
        Tests[i].Address = (Ip & Mask) | (~Mask & htonl(0x000000F0 + i));
        if (Tests[i].Address == Ip)
            Tests[i].Address ^= htonl(1);
        Threads[i] = CreateThread(NULL, 0, G8ArpThread, &Tests[i], 0, NULL);
        Sleep(10);
    }
    for (i = 0; i < 24; i++)
    {
        ok(WaitForSingleObject(Threads[i], 120000) == WAIT_OBJECT_0, "SendARP thread %d did not finish\n", i);
        CloseHandle(Threads[i]);
    }

    /* A query for an address of this host is still answered at once */
    Length = 6;
    ok(Test.SendArp(Ip, 0, Mac, &Length) == NO_ERROR, "SendARP for the host's own address failed\n");
}

/* ---------------------------------------------- provider tables by entity */

typedef struct _G8TABLE
{
    volatile LONG Stop;
} G8TABLE;

static
DWORD
WINAPI
G8SocketChurn(PVOID Context)
{
    G8TABLE *Test = Context;

    while (!Test->Stop)
    {
        SOCKET Tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        SOCKET Udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        struct sockaddr_in Address;

        memset(&Address, 0, sizeof(Address));
        Address.sin_family = AF_INET;
        Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (Tcp != INVALID_SOCKET)
        {
            bind(Tcp, (struct sockaddr *)&Address, sizeof(Address));
            listen(Tcp, 1);
            closesocket(Tcp);
        }
        if (Udp != INVALID_SOCKET)
        {
            bind(Udp, (struct sockaddr *)&Address, sizeof(Address));
            closesocket(Udp);
        }
    }
    return 0;
}

START_TEST(g8tableinfo)
{
    HANDLE Tcp, Thread;
    G8TABLE Test;
    NTSTATUS Status;
    TCP_REQUEST_QUERY_INFORMATION_EX Query;
    UCHAR Out[256];
    ULONG Entity, Instance, Id, IdIndex, Round, Valid = 0;
    static const ULONG Ids[4] = { 0x101, 0x102, 0x103, 0x110 };

    if (!G8StartWinsock())
    {
        skip("no winsock\n");
        return;
    }
    Status = G8OpenDevice(L"\\Device\\Tcp", &Tcp);
    ok(Status == STATUS_SUCCESS, "open \\Device\\Tcp gave 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    Test.Stop = 0;
    Thread = CreateThread(NULL, 0, G8SocketChurn, &Test, 0, NULL);

    /* The TCP and UDP tables answer, or are refused, for every entity and instance the caller names, while
       the address files they could name are created and closed */
    for (Round = 0; Round < 20; Round++)
    {
        for (Entity = 0x3fe; Entity <= 0x402; Entity += 1)
        {
            for (Instance = 0; Instance < 40; Instance++)
            {
                for (IdIndex = 0; IdIndex < 4; IdIndex++)
                {
                    Id = Ids[IdIndex];
                    memset(&Query, 0, sizeof(Query));
                    Query.ID.toi_entity.tei_entity = Entity;
                    Query.ID.toi_entity.tei_instance = Instance;
                    Query.ID.toi_class = INFO_CLASS_PROTOCOL;
                    Query.ID.toi_type = INFO_TYPE_PROVIDER;
                    Query.ID.toi_id = Id;
                    Status = G8Ioctl(Tcp, IOCTL_TCP_QUERY_INFORMATION_EX, &Query, sizeof(Query), Out, sizeof(Out), NULL);
                    if (Status == STATUS_SUCCESS)
                        Valid++;
                }
            }
        }
    }
    trace("%lu queries answered\n", Valid);
    Test.Stop = 1;
    WaitForSingleObject(Thread, 20000);
    CloseHandle(Thread);

    /* A query with a short input is refused as before */
    Status = G8Ioctl(Tcp, IOCTL_TCP_QUERY_INFORMATION_EX, &Query, 4, Out, sizeof(Out), NULL);
    ok(Status != STATUS_SUCCESS, "query with a 4 byte input gave 0x%lx\n", Status);
    NtClose(Tcp);
}
