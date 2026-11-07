/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Contract tests: a stream send with a length and no buffer, or whose second buffer cannot be
 *              locked, fails with STATUS_ACCESS_VIOLATION; nothing is sent and the pages locked for the
 *              first buffer are given back; a send of several valid buffers arrives whole. Bind and
 *              connect (stream and datagram) with an address shorter than its type needs fail and
 *              leave the socket usable.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"

#define STATUS_ACCESS_VIOLATION_G7 ((NTSTATUS)0xC0000005)

static
NTSTATUS
G7Ioctl(
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
        Timeout.QuadPart = -10000000LL * 10;
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
G7SendBuffers(
    _In_ SOCKET Socket,
    _In_ AFD_WSABUF *Buffers,
    _In_ ULONG Count,
    _Out_opt_ PULONG_PTR Sent)
{
    AFD_SEND_INFO SendInfo;

    SendInfo.BufferArray = Buffers;
    SendInfo.BufferCount = Count;
    SendInfo.TdiFlags = 0;
    SendInfo.AfdFlags = 0;
    return G7Ioctl((HANDLE)Socket, IOCTL_AFD_SEND, &SendInfo, sizeof(SendInfo), NULL, 0, Sent);
}

static
BOOL
G7ConnectedPair(
    _Out_ SOCKET *Client,
    _Out_ SOCKET *Server)
{
    SOCKET Listener;
    struct sockaddr_in Addr = { 0 };
    int Len = sizeof(Addr);

    *Client = *Server = INVALID_SOCKET;
    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    *Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (Listener == INVALID_SOCKET || *Client == INVALID_SOCKET ||
        bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) || listen(Listener, 1) ||
        getsockname(Listener, (struct sockaddr *)&Addr, &Len) ||
        connect(*Client, (struct sockaddr *)&Addr, sizeof(Addr)))
        goto Fail;
    *Server = accept(Listener, NULL, NULL);
    closesocket(Listener);
    if (*Server != INVALID_SOCKET)
        return TRUE;
    Listener = INVALID_SOCKET;
Fail:
    if (Listener != INVALID_SOCKET)
        closesocket(Listener);
    if (*Client != INVALID_SOCKET)
        closesocket(*Client);
    *Client = INVALID_SOCKET;
    return FALSE;
}

static
ULONG
G7AvailablePages(void)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;

    RtlZeroMemory(&Info, sizeof(Info));
    if (!NT_SUCCESS(NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL)))
        return 0;
    return Info.AvailablePages;
}

START_TEST(g7lockbuffers)
{
    WSADATA WsaData;
    SOCKET Client, Server;
    AFD_WSABUF Buffers[2];
    char First[] = "hello", Second[] = " world", Received[64];
    PVOID Reserved, Big;
    ULONG_PTR Sent;
    NTSTATUS Status;
    DWORD Timeout = 400;
    ULONG Before, After, i;
    SIZE_T BigSize = 8 * 1024 * 1024;
    int Result, Argc;
    char **Argv;

    Argc = winetest_get_mainargs(&Argv);
    WSAStartup(MAKEWORD(2, 2), &WsaData);
    if (!G7ConnectedPair(&Client, &Server))
    {
        skip("no loopback connection\n");
        WSACleanup();
        return;
    }
    setsockopt(Server, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));

    /* Several valid buffers arrive whole, in order */
    Buffers[0].buf = First;
    Buffers[0].len = sizeof(First) - 1;
    Buffers[1].buf = Second;
    Buffers[1].len = sizeof(Second) - 1;
    Sent = 0;
    Status = G7SendBuffers(Client, Buffers, 2, &Sent);
    ok(Status == STATUS_SUCCESS, "send of two buffers gave 0x%lx\n", Status);
    ok(Sent == 11, "sent %Iu\n", Sent);
    RtlZeroMemory(Received, sizeof(Received));
    Result = recv(Server, Received, sizeof(Received), 0);
    ok(Result == 11 && !memcmp(Received, "hello world", 11), "received %d '%s'\n", Result, Received);

    /* A length with no buffer names memory that does not exist ("nonull" on the command line leaves
     * this case out: a driver without the check faults in the kernel here, ending the run) */
    if (Argc < 3 || strcmp(Argv[2], "nonull"))
    {
        Buffers[0].buf = NULL;
        Buffers[0].len = 16;
        Status = G7SendBuffers(Client, Buffers, 1, NULL);
        ok(Status == STATUS_ACCESS_VIOLATION_G7, "send of a NULL buffer gave 0x%lx\n", Status);
        Result = recv(Server, Received, sizeof(Received), 0);
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT, "NULL buffer sent data: %d (%d)\n", Result, WSAGetLastError());
    }

    /* A valid buffer followed by one that cannot be locked: refused, nothing sent */
    Reserved = VirtualAlloc(NULL, 0x4000, MEM_RESERVE, PAGE_NOACCESS);
    ok(Reserved != NULL, "VirtualAlloc failed %lu\n", GetLastError());
    Buffers[0].buf = First;
    Buffers[0].len = sizeof(First) - 1;
    Buffers[1].buf = Reserved;
    Buffers[1].len = 0x1000;
    Status = G7SendBuffers(Client, Buffers, 2, NULL);
    ok(Status == STATUS_ACCESS_VIOLATION_G7, "send with an unmapped second buffer gave 0x%lx\n", Status);
    Result = recv(Server, Received, sizeof(Received), 0);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT, "refused send sent data: %d\n", Result);

    /* The pages locked for the first buffer of a refused request are released: memory of that size,
     * freed after each refusal, comes back (locked pages would stay allocated) */
    Before = G7AvailablePages();
    for (i = 0; i < 8; i++)
    {
        Big = VirtualAlloc(NULL, BigSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ok(Big != NULL, "VirtualAlloc of %Iu failed %lu\n", BigSize, GetLastError());
        if (!Big)
            break;
        memset(Big, 0x5a, BigSize);
        Buffers[0].buf = Big;
        Buffers[0].len = (ULONG)BigSize;
        Buffers[1].buf = Reserved;
        Buffers[1].len = 0x1000;
        Status = G7SendBuffers(Client, Buffers, 2, NULL);
        ok(Status == STATUS_ACCESS_VIOLATION_G7, "refused send %lu gave 0x%lx\n", i, Status);
        VirtualFree(Big, 0, MEM_RELEASE);
    }
    Sleep(500);
    After = G7AvailablePages();
    trace("available pages before %lu, after %lu\n", Before, After);
    ok(Before == 0 || After + 2048 >= Before, "available pages fell from %lu to %lu: pages stay locked\n", Before, After);

    /* The socket still sends */
    Buffers[0].buf = First;
    Buffers[0].len = sizeof(First) - 1;
    Status = G7SendBuffers(Client, Buffers, 1, &Sent);
    ok(Status == STATUS_SUCCESS && Sent == 5, "send after the refusals gave 0x%lx, %Iu\n", Status, Sent);
    Result = recv(Server, Received, sizeof(Received), 0);
    ok(Result == 5, "received %d\n", Result);

    if (Reserved)
        VirtualFree(Reserved, 0, MEM_RELEASE);
    closesocket(Client);
    closesocket(Server);
    WSACleanup();
}

static
void
G7SetAddr(struct sockaddr_in *Addr, USHORT Port)
{
    RtlZeroMemory(Addr, sizeof(*Addr));
    Addr->sin_family = AF_INET;
    Addr->sin_port = Port;
    Addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

START_TEST(g7shortaddr)
{
    WSADATA WsaData;
    HANDLE Sock;
    SOCKET Listener, Accepted;
    struct sockaddr_in Addr, Peer;
    int Len = sizeof(Addr);
    NTSTATUS Status;
    ULONG Short;

    WSAStartup(MAKEWORD(2, 2), &WsaData);

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    G7SetAddr(&Addr, 0);
    ok(Listener != INVALID_SOCKET && !bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) &&
       !listen(Listener, 4) && !getsockname(Listener, (struct sockaddr *)&Addr, &Len), "listener setup failed\n");

    for (Short = 8; Short < 16; Short += 4)
    {
        /* bind */
        Status = AfdCreateSocket(&Sock, AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok(Status == STATUS_SUCCESS, "AfdCreateSocket gave 0x%lx\n", Status);
        if (!NT_SUCCESS(Status))
            continue;
        G7SetAddr(&Peer, 0);
        Status = AfdBind(Sock, (struct sockaddr *)&Peer, Short);
        ok(!NT_SUCCESS(Status), "bind with %lu address bytes gave 0x%lx\n", Short, Status);
        Status = AfdBind(Sock, (struct sockaddr *)&Peer, sizeof(Peer));
        ok(Status == STATUS_SUCCESS, "bind of the full address after the refusal gave 0x%lx\n", Status);
        NtClose(Sock);

        /* connect */
        Status = AfdCreateSocket(&Sock, AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok(Status == STATUS_SUCCESS, "AfdCreateSocket gave 0x%lx\n", Status);
        if (!NT_SUCCESS(Status))
            continue;
        Status = AfdBind(Sock, (struct sockaddr *)&Peer, sizeof(Peer));
        ok(Status == STATUS_SUCCESS, "bind gave 0x%lx\n", Status);
        Status = AfdConnect(Sock, (struct sockaddr *)&Addr, Short);
        ok(!NT_SUCCESS(Status), "connect with %lu address bytes gave 0x%lx\n", Short, Status);
        Status = AfdConnect(Sock, (struct sockaddr *)&Addr, sizeof(Addr));
        ok(Status == STATUS_SUCCESS, "connect of the full address after the refusal gave 0x%lx\n", Status);
        if (NT_SUCCESS(Status))
        {
            Accepted = accept(Listener, NULL, NULL);
            ok(Accepted != INVALID_SOCKET, "accept failed %d\n", WSAGetLastError());
            if (Accepted != INVALID_SOCKET)
                closesocket(Accepted);
        }
        NtClose(Sock);

        /* connected datagram socket */
        Status = AfdCreateSocket(&Sock, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        ok(Status == STATUS_SUCCESS, "AfdCreateSocket gave 0x%lx\n", Status);
        if (!NT_SUCCESS(Status))
            continue;
        Status = AfdBind(Sock, (struct sockaddr *)&Peer, sizeof(Peer));
        ok(Status == STATUS_SUCCESS, "UDP bind gave 0x%lx\n", Status);
        Status = AfdConnect(Sock, (struct sockaddr *)&Addr, Short);
        ok(!NT_SUCCESS(Status), "UDP connect with %lu address bytes gave 0x%lx\n", Short, Status);
        Status = AfdSendTo(Sock, "x", 1, (struct sockaddr *)&Addr, Short);
        ok(!NT_SUCCESS(Status), "UDP send to %lu address bytes gave 0x%lx\n", Short, Status);
        Status = AfdConnect(Sock, (struct sockaddr *)&Addr, sizeof(Addr));
        ok(Status == STATUS_SUCCESS, "UDP connect of the full address gave 0x%lx\n", Status);
        NtClose(Sock);
    }

    closesocket(Listener);
    WSACleanup();
}

