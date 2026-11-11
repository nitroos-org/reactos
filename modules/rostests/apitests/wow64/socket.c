/* Cross-bitness socket I/O. SPDX-License-Identifier: LGPL-2.1-or-later */
#define WIN32_NO_STATUS
#include <winsock2.h>
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ndk/ntndk.h>
#include <winioctl.h>
#include <tdi.h>
#include <tdiinfo.h>
#include <tcpioctl.h>
#include <drivers/afd/shared.h>
#include <stdio.h>
#include <string.h>

static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%d\n", __LINE__, #x, WSAGetLastError()); } } while (0)

static DWORD WINAPI Watchdog(void *Done)
{
    if (WaitForSingleObject(Done, 15000) != WAIT_OBJECT_0)
    {
        puts("FAIL socket test timed out");
        ExitProcess(124);
    }
    return 0;
}

/* ReactOS's private AFD contract; enabled explicitly, never on Windows. */
static void CheckHandleReply(SOCKET Socket, ULONG Flags)
{
    typedef LONG (WINAPI *IOCTL)(HANDLE, HANDLE, PVOID, PVOID, PVOID, ULONG, PVOID, ULONG, PVOID, ULONG);
    IOCTL Ioctl = (IOCTL)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDeviceIoControlFile");
    struct { ULONG_PTR Status, Information; ULONG Guard; } Io = {0, 0, 0x12345678};
    ULONG Words[4] = {0xabcdef01, 0, 0x76543210, 0xabcdef01};
    ULONG Connection;
    LONG Status;
    BOOL Wow = FALSE;

    CHECK(Ioctl != NULL && IsWow64Process(GetCurrentProcess(), &Wow));
    if (!Ioctl || !Wow) return;
    Status = Ioctl((HANDLE)Socket, NULL, NULL, NULL, &Io, IOCTL_AFD_GET_TDI_HANDLES,
                   &Flags, sizeof(Flags), &Words[1], 2 * sizeof(ULONG));
    CHECK(Status == 0 && Io.Status == 0 && Words[1] != 0);
    Connection = Words[2];
    CHECK(Words[0] == 0xabcdef01 && Words[3] == 0xabcdef01);
    CHECK((Flags & AFD_CONNECTION_HANDLE) ? Connection != 0 : Connection == 0x76543210);
    CHECK(Io.Guard == 0x12345678);
    Status = Ioctl((HANDLE)Socket, NULL, NULL, NULL, &Io, IOCTL_AFD_GET_TDI_HANDLES,
                   &Flags, sizeof(Flags), &Words[1], 2 * sizeof(ULONG) - 1);
    CHECK(Status == (LONG)0xc0000023); /* STATUS_BUFFER_TOO_SMALL */
    Status = Ioctl((HANDLE)Socket, NULL, NULL, NULL, &Io, IOCTL_AFD_GET_TDI_HANDLES,
                   &Flags, 0, &Words[1], 2 * sizeof(ULONG));
    CHECK(Status == (LONG)0xc0000023);
    Status = Ioctl((HANDLE)Socket, NULL, NULL, NULL, &Io, IOCTL_AFD_GET_TDI_HANDLES,
                   &Flags, sizeof(Flags), NULL, 2 * sizeof(ULONG));
    CHECK(Status == (LONG)0xc0000005); /* STATUS_ACCESS_VIOLATION */
    CHECK(Words[0] == 0xabcdef01 && Words[2] == Connection && Words[3] == 0xabcdef01);
    CHECK(Io.Guard == 0x12345678);
}

static void CheckTcpQuery(void)
{
    typedef NTSTATUS (NTAPI *OPEN)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
    typedef NTSTATUS (NTAPI *IOCTL)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    OPEN Open = (OPEN)GetProcAddress(Ntdll, "NtOpenFile");
    IOCTL Ioctl = (IOCTL)GetProcAddress(Ntdll, "NtDeviceIoControlFile");
    WCHAR Path[] = L"\\Device\\Tcp";
    UNICODE_STRING Name = {sizeof(Path) - sizeof(WCHAR), sizeof(Path), Path};
    OBJECT_ATTRIBUTES Attributes;
    struct { IO_STATUS_BLOCK Io; ULONG Guard; } Result = {{{0}}, 0x12345678};
    struct { ULONG Before; TCP_REQUEST_QUERY_INFORMATION_EX Query; ULONG After; } Input;
    struct { TDIEntityID Entities[128]; ULONG Guard; } Output;
    HANDLE Handle = NULL;
    NTSTATUS Status;

    CHECK(Open && Ioctl);
    if (!Open || !Ioctl) return;
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = Open(&Handle, GENERIC_READ | SYNCHRONIZE, &Attributes, &Result.Io,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
    CHECK(Status == 0);
    if (Status) return;
    memset(&Input, 0, sizeof(Input));
    Input.Before = Input.After = Output.Guard = 0xabcdef01;
    Input.Query.ID.toi_entity.tei_entity = GENERIC_ENTITY;
    Input.Query.ID.toi_class = INFO_CLASS_GENERIC;
    Input.Query.ID.toi_type = INFO_TYPE_PROVIDER;
    Input.Query.ID.toi_id = ENTITY_LIST_ID;
    memset(Input.Query.Context, 0x5a, sizeof(Input.Query.Context));
    Status = Ioctl(Handle, NULL, NULL, NULL, &Result.Io, IOCTL_TCP_QUERY_INFORMATION_EX,
                   &Input.Query, sizeof(Input.Query), Output.Entities, sizeof(Output.Entities));
    CHECK(Status == 0 && Result.Io.Status == 0 && Result.Io.Information >= sizeof(TDIEntityID));
    CHECK(Result.Io.Information <= sizeof(Output.Entities) && Result.Io.Information % sizeof(TDIEntityID) == 0);
    CHECK(Input.Before == 0xabcdef01 && Input.After == 0xabcdef01 && Output.Guard == 0xabcdef01);
    CHECK(Result.Guard == 0x12345678);
    CHECK(((BYTE *)Input.Query.Context)[0] == 0x5a && ((BYTE *)Input.Query.Context)[15] == 0x5a);
    Status = Ioctl(Handle, NULL, NULL, NULL, &Result.Io, IOCTL_TCP_QUERY_INFORMATION_EX,
                   &Input.Query, sizeof(Input.Query) - 1, Output.Entities, sizeof(Output.Entities));
    CHECK(Status == STATUS_INVALID_PARAMETER);
    CHECK(Input.After == 0xabcdef01 && Output.Guard == 0xabcdef01 && Result.Guard == 0x12345678);
    CloseHandle(Handle);
}

/* A fresh socket of each type bound to each loopback/wildcard address, then a UDP exchange.
 * The 32-bit WSHNotify(WSH_NOTIFY_BIND) of wshtcpip asks the TCP driver for its entity list
 * through the WoW64 query path, so a TCP/IP driver that does not know the 32-bit layout
 * makes every bind fail with WSAEINVAL while 64-bit callers still work. */
static void CheckDatagram(void)
{
    static const ULONG Addresses[2] = {INADDR_ANY, INADDR_LOOPBACK};
    static const int Types[2] = {SOCK_STREAM, SOCK_DGRAM};
    struct sockaddr_in Address, Local, From;
    SOCKET Receiver, Sender, Connected;
    char Buffer[16] = {0};
    DWORD Timeout = 2000;
    int Length, FromLength, Count, i, j;

    for (i = 0; i < 2; i++)
    {
        for (j = 0; j < 2; j++)
        {
            SOCKET Socket = socket(AF_INET, Types[i], 0);
            CHECK(Socket != INVALID_SOCKET);
            if (Socket == INVALID_SOCKET) continue;
            memset(&Address, 0, sizeof(Address));
            Address.sin_family = AF_INET;
            Address.sin_addr.s_addr = htonl(Addresses[j]);
            CHECK(bind(Socket, (struct sockaddr *)&Address, sizeof(Address)) == 0);
            Length = sizeof(Local);
            CHECK(getsockname(Socket, (struct sockaddr *)&Local, &Length) == 0 && Local.sin_port != 0);
            CHECK(closesocket(Socket) == 0);
        }
    }

    Receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    Sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    Connected = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(Receiver != INVALID_SOCKET && Sender != INVALID_SOCKET && Connected != INVALID_SOCKET);
    if (Receiver == INVALID_SOCKET || Sender == INVALID_SOCKET || Connected == INVALID_SOCKET) goto Done;
    memset(&Address, 0, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(Receiver, (struct sockaddr *)&Address, sizeof(Address)) == 0);
    Length = sizeof(Address);
    CHECK(getsockname(Receiver, (struct sockaddr *)&Address, &Length) == 0 && Address.sin_port != 0);
    CHECK(setsockopt(Receiver, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout)) == 0);
    /* sendto binds the sender implicitly */
    CHECK(sendto(Sender, "WoW64", 5, 0, (struct sockaddr *)&Address, sizeof(Address)) == 5);
    FromLength = sizeof(From);
    Count = recvfrom(Receiver, Buffer, sizeof(Buffer), 0, (struct sockaddr *)&From, &FromLength);
    CHECK(Count == 5 && !memcmp(Buffer, "WoW64", 5));
    CHECK(FromLength == sizeof(From) && From.sin_family == AF_INET && From.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    /* a connected datagram socket (connect binds implicitly) and the reply */
    CHECK(connect(Connected, (struct sockaddr *)&Address, sizeof(Address)) == 0);
    CHECK(send(Connected, "again", 5, 0) == 5);
    FromLength = sizeof(From);
    memset(Buffer, 0, sizeof(Buffer));
    Count = recvfrom(Receiver, Buffer, sizeof(Buffer), 0, (struct sockaddr *)&From, &FromLength);
    CHECK(Count == 5 && !memcmp(Buffer, "again", 5));
    CHECK(sendto(Receiver, "reply", 5, 0, (struct sockaddr *)&From, FromLength) == 5);
    CHECK(setsockopt(Connected, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout)) == 0);
    memset(Buffer, 0, sizeof(Buffer));
    CHECK(recv(Connected, Buffer, sizeof(Buffer), 0) == 5 && !memcmp(Buffer, "reply", 5));
Done:
    if (Receiver != INVALID_SOCKET) closesocket(Receiver);
    if (Sender != INVALID_SOCKET) closesocket(Sender);
    if (Connected != INVALID_SOCKET) closesocket(Connected);
}

static void CheckHttp(void)
{
    static const char Request[] = "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    struct sockaddr_in Address = {0};
    char Response[4096];
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int Used = 0, Count = -1;
    DWORD Timeout = 5000;

    CHECK(Socket != INVALID_SOCKET);
    if (Socket == INVALID_SOCKET) return;
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = inet_addr("10.0.2.2");
    Address.sin_port = htons(18463);
    CHECK(setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout)) == 0);
    if (connect(Socket, (struct sockaddr *)&Address, sizeof(Address)))
    {
        CHECK(FALSE);
        closesocket(Socket);
        return;
    }
    CHECK(send(Socket, Request, sizeof(Request) - 1, 0) == sizeof(Request) - 1);
    while (Used < sizeof(Response) - 1)
    {
        Count = recv(Socket, Response + Used, sizeof(Response) - 1 - Used, 0);
        if (Count <= 0) break;
        Used += Count;
    }
    Response[Used] = 0;
    CHECK(Count == 0);
    CHECK(!strncmp(Response, "HTTP/1.0 200 ", 13) || !strncmp(Response, "HTTP/1.1 200 ", 13));
    CHECK(strstr(Response, "Local HTTP page loaded.") != NULL);
    printf("HTTP bytes=%d status=%.12s\n", Used, Response);
    CHECK(closesocket(Socket) == 0);
}

static void CheckPendingReceive(SOCKET Client, SOCKET Server)
{
    struct { char Text[8]; ULONG Guard; } Reply = {{0}, 0xabcdef01};
    struct { WSAOVERLAPPED Io; ULONG Guard; } Pending = {{0}, 0x12345678};
    WSABUF Buffers[2] = {{2, Reply.Text}, {3, Reply.Text + 2}};
    DWORD Count = 0, Flags = 0;
    int Result;

    Pending.Io.hEvent = WSACreateEvent();
    CHECK(Pending.Io.hEvent != WSA_INVALID_EVENT);
    Result = WSARecv(Server, Buffers, 2, &Count, &Flags, &Pending.Io, NULL);
    CHECK(Result == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING);
    CHECK(WaitForSingleObject(Pending.Io.hEvent, 0) == WAIT_TIMEOUT);
    /* Descriptors are captured before WSARecv returns; only their data and
     * the OVERLAPPED must remain live until completion. */
    memset(Buffers, 0, sizeof(Buffers));
    CHECK(send(Client, "async", 5, 0) == 5);
    CHECK(WaitForSingleObject(Pending.Io.hEvent, 2000) == WAIT_OBJECT_0);
    CHECK(WSAGetOverlappedResult(Server, &Pending.Io, &Count, FALSE, &Flags) && Count == 5);
    CHECK(!memcmp(Reply.Text, "async", 5) && Reply.Guard == 0xabcdef01);
    CHECK(Pending.Guard == 0x12345678);
    WSACloseEvent(Pending.Io.hEvent);
}

static void CheckTransferCapture(SOCKET Socket)
{
    typedef NTSTATUS (NTAPI *IOCTL)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
    IOCTL Ioctl = (IOCTL)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDeviceIoControlFile");
    struct { IO_STATUS_BLOCK Io; ULONG Guard; } Result = {{{0}}, 0x12345678};
    AFD_RECV_INFO Request = {NULL, 1, AFD_OVERLAPPED, 0};
    ULONG Codes[] = {IOCTL_AFD_SEND, IOCTL_AFD_RECV};
    NTSTATUS Status;
    BOOL Wow = FALSE;
    unsigned i;

    CHECK(Ioctl && IsWow64Process(GetCurrentProcess(), &Wow));
    if (!Ioctl || !Wow) return;
    for (i = 0; i < sizeof(Codes) / sizeof(Codes[0]); ++i)
    {
        Status = Ioctl((HANDLE)Socket, NULL, NULL, NULL, &Result.Io, Codes[i],
                       &Request, sizeof(Request) - 1, NULL, 0);
        CHECK(Status == STATUS_BUFFER_TOO_SMALL);
        Request.BufferCount = 0;
        Status = Ioctl((HANDLE)Socket, NULL, NULL, NULL, &Result.Io, Codes[i],
                       &Request, sizeof(Request), NULL, 0);
        CHECK(Status == STATUS_INVALID_PARAMETER);
        /* Native WSABUF bytes fit in ULONG, but AFD's appended map does not. */
        Request.BufferCount = 0x08000000;
        Status = Ioctl((HANDLE)Socket, NULL, NULL, NULL, &Result.Io, Codes[i],
                       &Request, sizeof(Request), NULL, 0);
        CHECK(Status == STATUS_INVALID_PARAMETER);
        Request.BufferCount = 1;
        Status = Ioctl((HANDLE)Socket, NULL, NULL, NULL, &Result.Io, Codes[i],
                       &Request, sizeof(Request), NULL, 0);
        CHECK(Status == STATUS_ACCESS_VIOLATION);
        CHECK(Result.Guard == 0x12345678);
    }
}

static void CheckPollReply(SOCKET Server, SOCKET Listener, SOCKET Client)
{
    typedef NTSTATUS (NTAPI *IOCTL)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
    typedef NTSTATUS (NTAPI *CANCEL)(HANDLE, PIO_STATUS_BLOCK);
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    IOCTL Ioctl = (IOCTL)GetProcAddress(Ntdll, "NtDeviceIoControlFile");
    CANCEL Cancel = (CANCEL)GetProcAddress(Ntdll, "NtCancelIoFile");
    typedef struct
    {
        LARGE_INTEGER Timeout;
        ULONG HandleCount;
        ULONG_PTR Exclusive;
        AFD_HANDLE Handles[2];
        ULONG Guard;
    } POLL_REPLY;
    POLL_REPLY Poll = {0};
    struct { IO_STATUS_BLOCK Io; ULONG Guard; } Result = {{{0}}, 0x12345678};
    IO_STATUS_BLOCK CancelIo;
    HANDLE Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ULONG Length = FIELD_OFFSET(POLL_REPLY, Guard);
    NTSTATUS Status;
    BOOL Wow = FALSE;

    CHECK(Ioctl && Cancel && Event && IsWow64Process(GetCurrentProcess(), &Wow));
    if (!Ioctl || !Cancel || !Event) return;
    Poll.HandleCount = 2;
    Poll.Exclusive = 1;
    Poll.Handles[0].Handle = Server;
    Poll.Handles[0].Events = AFD_EVENT_RECEIVE;
    Poll.Handles[1].Handle = Listener;
    Poll.Handles[1].Events = AFD_EVENT_ACCEPT;
    Poll.Timeout.QuadPart = -500000;
    Poll.Guard = 0xabcdef01;
    Status = Ioctl((HANDLE)Server, Event, NULL, NULL, &Result.Io, IOCTL_AFD_SELECT,
                   &Poll, Length, &Poll, Length);
    CHECK(Status == STATUS_PENDING || Status == STATUS_TIMEOUT);
    CHECK(WaitForSingleObject(Event, 2000) == WAIT_OBJECT_0);
    CHECK(Result.Io.Status == STATUS_TIMEOUT && Result.Io.Information == Length);
    CHECK(Poll.HandleCount == 2 && Poll.Handles[0].Events == 0 && Poll.Handles[1].Events == 0);
    CHECK(Poll.Handles[0].Handle == Server && Poll.Handles[1].Handle == Listener);
    CHECK(Poll.Guard == 0xabcdef01 && Result.Guard == 0x12345678);
    if (Wow) CHECK(Poll.Exclusive == 1);

    ResetEvent(Event);
    Poll.Timeout.QuadPart = -100000000;
    Poll.Exclusive = 1;
    Poll.Handles[0].Events = AFD_EVENT_RECEIVE;
    Poll.Handles[1].Events = AFD_EVENT_ACCEPT;
    Status = Ioctl((HANDLE)Server, Event, NULL, NULL, &Result.Io, IOCTL_AFD_SELECT,
                   &Poll, Length, &Poll, Length);
    CHECK(Status == STATUS_PENDING && WaitForSingleObject(Event, 0) == WAIT_TIMEOUT);
    CHECK(send(Client, "poll", 4, 0) == 4);
    CHECK(WaitForSingleObject(Event, 2000) == WAIT_OBJECT_0);
    CHECK(Result.Io.Status == STATUS_SUCCESS && Result.Io.Information == Length);
    CHECK(Poll.Handles[0].Events == AFD_EVENT_RECEIVE && Poll.Handles[1].Events == 0);
    CHECK(Poll.Handles[0].Handle == Server && Poll.Handles[1].Handle == Listener);
    CHECK(Poll.Guard == 0xabcdef01 && Result.Guard == 0x12345678);
    if (Wow) CHECK(Poll.Exclusive == 1);
    {
        char Text[4];
        CHECK(recv(Server, Text, sizeof(Text), MSG_WAITALL) == sizeof(Text) &&
              !memcmp(Text, "poll", sizeof(Text)));
    }

    ResetEvent(Event);
    Poll.Timeout.QuadPart = -1000000000;
    Poll.Exclusive = 1;
    Poll.Handles[0].Events = AFD_EVENT_RECEIVE;
    Poll.Handles[1].Events = AFD_EVENT_ACCEPT;
    Status = Ioctl((HANDLE)Server, Event, NULL, NULL, &Result.Io, IOCTL_AFD_SELECT,
                   &Poll, Length, &Poll, Length);
    CHECK(Status == STATUS_PENDING);
    CHECK(Cancel((HANDLE)Server, &CancelIo) == 0);
    CHECK(WaitForSingleObject(Event, 2000) == WAIT_OBJECT_0 && Result.Io.Status == STATUS_CANCELLED);
    CHECK(Poll.Guard == 0xabcdef01 && Result.Guard == 0x12345678);
    if (Wow)
    {
        Poll.Exclusive = 1;
        Status = Ioctl((HANDLE)Server, Event, NULL, NULL, &Result.Io, IOCTL_AFD_SELECT,
                       &Poll, Length - 1, &Poll, Length);
        CHECK(Status == STATUS_BUFFER_TOO_SMALL);
        Status = Ioctl((HANDLE)Server, Event, NULL, NULL, &Result.Io, IOCTL_AFD_SELECT,
                       &Poll, Length, &Poll, Length - 1);
        CHECK(Status == STATUS_BUFFER_TOO_SMALL);
        Poll.HandleCount = MAXULONG;
        Status = Ioctl((HANDLE)Server, Event, NULL, NULL, &Result.Io, IOCTL_AFD_SELECT,
                       &Poll, Length, &Poll, Length);
        CHECK(Status == STATUS_INVALID_PARAMETER);
        CHECK(Poll.Guard == 0xabcdef01 && Result.Guard == 0x12345678);
    }
    CloseHandle(Event);
}

int main(int argc, char **argv)
{
    WSADATA Data;
    SOCKET Listener = INVALID_SOCKET, Client = INVALID_SOCKET, Server = INVALID_SOCKET;
    struct sockaddr_in Address = {0};
    struct { char Text[8]; DWORD Guard; } Reply = {{0}, 0x12345678};
    WSABUF Buffers[2] = {{2, "Wo"}, {3, "W64"}};
    DWORD Count = 0, Timeout = 2000;
    u_long Mode;
    int Length = sizeof(Address);
    HANDLE Done, Thread;
    fd_set Read;
    struct timeval Wait = {2, 0};

    setvbuf(stdout, NULL, _IONBF, 0);
    Done = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, Watchdog, Done, 0, NULL);
    CHECK(Done && Thread);
    if (!Done || !Thread) return 1;
    CHECK(WSAStartup(MAKEWORD(2, 2), &Data) == 0);
    if (argc == 2 && !strcmp(argv[1], "--http"))
    {
        CheckHttp();
        goto End;
    }
    if (argc == 2 && !strcmp(argv[1], "--datagram"))
    {
        CheckDatagram();
        goto End;
    }
    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(Listener != INVALID_SOCKET);
    if (Listener == INVALID_SOCKET) goto End;
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(Listener, (struct sockaddr *)&Address, sizeof(Address)) == 0);
    CHECK(listen(Listener, 1) == 0);
    CHECK(getsockname(Listener, (struct sockaddr *)&Address, &Length) == 0);
    CHECK(Length == sizeof(Address) && Address.sin_port != 0);
    if (Failures) goto End;
    if (argc == 2 && !strcmp(argv[1], "--bind-abi"))
    {
        CheckHandleReply(Listener, AFD_ADDRESS_HANDLE);
        CheckTcpQuery();
        goto End;
    }
    if (argc == 2 && !strcmp(argv[1], "--bind-only")) goto End;
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(Client != INVALID_SOCKET);
    if (Client == INVALID_SOCKET) goto End;
    CHECK(connect(Client, (struct sockaddr *)&Address, sizeof(Address)) == 0);
    if (Failures) goto End;
    Server = accept(Listener, NULL, NULL);
    CHECK(Server != INVALID_SOCKET);
    if (Server == INVALID_SOCKET) goto End;
    CHECK(setsockopt(Server, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout)) == 0);
    CHECK(setsockopt(Client, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout)) == 0);
    Mode = 1;
    CHECK(ioctlsocket(Server, FIONBIO, &Mode) == 0);
    CHECK(recv(Server, Reply.Text, 1, 0) == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
    Mode = 0;
    CHECK(ioctlsocket(Server, FIONBIO, &Mode) == 0);
    if (argc == 2 && !strcmp(argv[1], "--afd-abi"))
    {
        CheckHandleReply(Server, AFD_ADDRESS_HANDLE | AFD_CONNECTION_HANDLE);
        CheckTransferCapture(Server);
        CheckPollReply(Server, Listener, Client);
    }
    FD_ZERO(&Read);
    FD_SET(Server, &Read);
    FD_SET(Listener, &Read);
    Wait.tv_sec = 0; Wait.tv_usec = 50000;
    CHECK(select(0, &Read, NULL, NULL, &Wait) == 0 && Read.fd_count == 0);
    CheckPendingReceive(Client, Server);
    CHECK(WSASend(Client, Buffers, 2, &Count, 0, NULL, NULL) == 0 && Count == 5);
    FD_ZERO(&Read);
    FD_SET(Server, &Read);
    FD_SET(Listener, &Read);
    Wait.tv_sec = 2; Wait.tv_usec = 0;
    CHECK(select(0, &Read, NULL, NULL, &Wait) == 1 && FD_ISSET(Server, &Read) && !FD_ISSET(Listener, &Read));
    Mode = 0;
    CHECK(ioctlsocket(Server, FIONREAD, &Mode) == 0 && Mode == 5);
    CHECK(recv(Server, Reply.Text, 5, MSG_WAITALL) == 5);
    CHECK(!memcmp(Reply.Text, "WoW64", 5) && Reply.Guard == 0x12345678);
    CHECK(send(Server, Reply.Text, 5, 0) == 5);
    memset(Reply.Text, 0, sizeof(Reply.Text));
    CHECK(recv(Client, Reply.Text, 5, MSG_WAITALL) == 5);
    CHECK(!memcmp(Reply.Text, "WoW64", 5) && Reply.Guard == 0x12345678);
    CHECK(shutdown(Client, SD_SEND) == 0);
    CHECK(recv(Server, Reply.Text, sizeof(Reply.Text), 0) == 0);
End:
    if (Server != INVALID_SOCKET) CHECK(closesocket(Server) == 0);
    if (Client != INVALID_SOCKET) CHECK(closesocket(Client) == 0);
    if (Listener != INVALID_SOCKET) CHECK(closesocket(Listener) == 0);
    CHECK(WSACleanup() == 0);
    SetEvent(Done);
    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);
    CloseHandle(Done);
    printf("SOCKET checks=%u failures=%u\n", Checks, Failures);
    return Failures != 0;
}
