/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     TransmitFile and TransmitPackets (WSAID_TRANSMITFILE, WSAID_TRANSMITPACKETS):
 *              the pointers, a transfer over the loopback, head and tail buffers, the start in
 *              the file, overlapped completion (event, completion port), TF_DISCONNECT
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

#include <mswsock.h>

/* The expected values were recorded on Windows 10 22H2. The tests that print "probe:" record
 * what a system does and check nothing. */

#define FILE_SIZE   200000
#define WAIT_TIME   30000

static LPFN_TRANSMITFILE pTransmitFile;
static LPFN_TRANSMITPACKETS pTransmitPackets;
static WCHAR g_FileName[MAX_PATH];
static HANDLE g_File = INVALID_HANDLE_VALUE;
static BYTE g_Data[FILE_SIZE];

static const char g_Head[] = "HEAD-0123456789";
static const char g_Tail[] = "TAIL-abcdefghijklmnopqrstuvwxyz";

typedef struct _RECEIVER
{
    SOCKET Socket;
    BYTE *Buffer;
    DWORD Capacity;
    DWORD Want;         /* stop after that many bytes; 0xFFFFFFFF: until the end of the stream */
    DWORD Got;
    BOOL Eof;
} RECEIVER;

static
DWORD
WINAPI
ReceiverThread(PVOID Param)
{
    RECEIVER *Receiver = Param;

    while (Receiver->Got < Receiver->Want)
    {
        int Result = recv(Receiver->Socket, (char *)Receiver->Buffer + Receiver->Got,
                          Receiver->Capacity - Receiver->Got, 0);
        if (Result == 0)
        {
            Receiver->Eof = TRUE;
            break;
        }
        if (Result < 0)
            break;
        Receiver->Got += Result;
    }
    return 0;
}

static
HANDLE
StartReceiver(RECEIVER *Receiver, SOCKET Socket, DWORD Want)
{
    ZeroMemory(Receiver, sizeof(*Receiver));
    Receiver->Socket = Socket;
    Receiver->Capacity = FILE_SIZE + 4096;
    Receiver->Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Receiver->Capacity);
    Receiver->Want = Want;
    return CreateThread(NULL, 0, ReceiverThread, Receiver, 0, NULL);
}

static
void
FinishReceiver(HANDLE Thread, RECEIVER *Receiver)
{
    if (WaitForSingleObject(Thread, WAIT_TIME) != WAIT_OBJECT_0)
    {
        ok(0, "the receiver is stuck at %lu of %lu bytes\n", Receiver->Got, Receiver->Want);
        closesocket(Receiver->Socket);
        WaitForSingleObject(Thread, 5000);
    }
    CloseHandle(Thread);
}

/* A connected pair on the loopback: Sender is the client, Peer the accepted socket */
static
BOOL
MakePair(SOCKET *Sender, SOCKET *Peer)
{
    SOCKET Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in Address;
    int Length = sizeof(Address);

    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Listener, (struct sockaddr *)&Address, sizeof(Address)) != 0 ||
        getsockname(Listener, (struct sockaddr *)&Address, &Length) != 0 ||
        listen(Listener, 1) != 0)
    {
        closesocket(Listener);
        return FALSE;
    }

    *Sender = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connect(*Sender, (struct sockaddr *)&Address, sizeof(Address)) != 0)
    {
        closesocket(*Sender);
        closesocket(Listener);
        return FALSE;
    }
    *Peer = accept(Listener, NULL, NULL);
    closesocket(Listener);
    return *Peer != INVALID_SOCKET;
}

static
BOOL
CreateData(void)
{
    DWORD i, Written;
    WCHAR Dir[MAX_PATH];

    for (i = 0; i < FILE_SIZE; i++)
        g_Data[i] = (BYTE)((i * 7 + (i >> 8)) & 0xFF);

    GetTempPathW(RTL_NUMBER_OF(Dir), Dir);
    _snwprintf(g_FileName, RTL_NUMBER_OF(g_FileName), L"%stfile-%lu.tmp", Dir, GetCurrentProcessId());
    g_File = CreateFileW(g_FileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (g_File == INVALID_HANDLE_VALUE)
        return FALSE;
    return WriteFile(g_File, g_Data, FILE_SIZE, &Written, NULL) && Written == FILE_SIZE;
}

static
void
Rewind(HANDLE File, LONG Position)
{
    SetFilePointer(File, Position, NULL, FILE_BEGIN);
}

static
void
TestPointers(void)
{
    GUID File = WSAID_TRANSMITFILE, Packets = WSAID_TRANSMITPACKETS;
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    DWORD Returned;
    int Result;

    Returned = 0;
    Result = WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &File, sizeof(File),
                      &pTransmitFile, sizeof(pTransmitFile), &Returned, NULL, NULL);
    ok(Result == 0, "TransmitFile: Result = %d, error %d\n", Result, WSAGetLastError());
    ok(Returned == sizeof(PVOID), "Returned = %lu\n", Returned);
    ok(pTransmitFile != NULL, "no TransmitFile\n");

    Returned = 0;
    Result = WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &Packets, sizeof(Packets),
                      &pTransmitPackets, sizeof(pTransmitPackets), &Returned, NULL, NULL);
    ok(Result == 0, "TransmitPackets: Result = %d, error %d\n", Result, WSAGetLastError());
    ok(Returned == sizeof(PVOID), "Returned = %lu\n", Returned);
    ok(pTransmitPackets != NULL, "no TransmitPackets\n");

    closesocket(Socket);
}

/* Compares what the receiver got with the head, the file part and the tail that were sent */
static
void
CheckData(const RECEIVER *Receiver, BOOL Head, DWORD Start, DWORD Length, BOOL Tail, const char *Name)
{
    DWORD Total = (Head ? sizeof(g_Head) : 0) + Length + (Tail ? sizeof(g_Tail) : 0), At = 0;

    ok(Receiver->Got == Total, "%s: received %lu bytes, expected %lu\n", Name, Receiver->Got, Total);
    if (Receiver->Got < Total)
        return;
    if (Head)
    {
        ok(memcmp(Receiver->Buffer, g_Head, sizeof(g_Head)) == 0, "%s: wrong head\n", Name);
        At += sizeof(g_Head);
    }
    ok(memcmp(Receiver->Buffer + At, g_Data + Start, Length) == 0, "%s: wrong file data\n", Name);
    At += Length;
    if (Tail)
        ok(memcmp(Receiver->Buffer + At, g_Tail, sizeof(g_Tail)) == 0, "%s: wrong tail\n", Name);
}

static
void
TestBlocking(void)
{
    SOCKET Sender, Peer;
    RECEIVER Receiver;
    HANDLE Thread;
    TRANSMIT_FILE_BUFFERS Buffers;
    BOOL Result;

    /* the whole file */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    Thread = StartReceiver(&Receiver, Peer, FILE_SIZE);
    Rewind(g_File, 0);
    Result = pTransmitFile(Sender, g_File, 0, 0, NULL, NULL, 0);
    ok(Result == TRUE, "Result = %d, error %d\n", Result, WSAGetLastError());
    FinishReceiver(Thread, &Receiver);
    CheckData(&Receiver, FALSE, 0, FILE_SIZE, FALSE, "whole file");
    closesocket(Sender);
    closesocket(Peer);

    /* the export of mswsock goes to the same function */
    {
        HMODULE Mswsock = LoadLibraryW(L"mswsock.dll");
        LPFN_TRANSMITFILE pExport = Mswsock ? (LPFN_TRANSMITFILE)GetProcAddress(Mswsock, "TransmitFile") : NULL;

        ok(pExport != NULL, "no mswsock!TransmitFile\n");
        if (pExport)
        {
            ok(MakePair(&Sender, &Peer), "no connection\n");
            Thread = StartReceiver(&Receiver, Peer, 3000);
            Rewind(g_File, 0);
            Result = pExport(Sender, g_File, 3000, 0, NULL, NULL, 0);
            ok(Result == TRUE, "mswsock!TransmitFile: %d, error %d\n", Result, WSAGetLastError());
            FinishReceiver(Thread, &Receiver);
            CheckData(&Receiver, FALSE, 0, 3000, FALSE, "mswsock export");
            closesocket(Sender);
            closesocket(Peer);
        }
    }

    /* head and tail around the file, a send size that does not divide it */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    Buffers.Head = (PVOID)g_Head;
    Buffers.HeadLength = sizeof(g_Head);
    Buffers.Tail = (PVOID)g_Tail;
    Buffers.TailLength = sizeof(g_Tail);
    Thread = StartReceiver(&Receiver, Peer, sizeof(g_Head) + FILE_SIZE + sizeof(g_Tail));
    Rewind(g_File, 0);
    Result = pTransmitFile(Sender, g_File, 0, 4097, NULL, &Buffers, 0);
    ok(Result == TRUE, "Result = %d, error %d\n", Result, WSAGetLastError());
    FinishReceiver(Thread, &Receiver);
    CheckData(&Receiver, TRUE, 0, FILE_SIZE, TRUE, "head, file, tail");
    closesocket(Sender);
    closesocket(Peer);

    /* a part of the file, from the file pointer (no OVERLAPPED) */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    Thread = StartReceiver(&Receiver, Peer, 1000);
    Rewind(g_File, 12345);
    Result = pTransmitFile(Sender, g_File, 1000, 100, NULL, NULL, 0);
    ok(Result == TRUE, "Result = %d, error %d\n", Result, WSAGetLastError());
    FinishReceiver(Thread, &Receiver);
    CheckData(&Receiver, FALSE, 12345, 1000, FALSE, "part of the file");
    closesocket(Sender);
    closesocket(Peer);

    /* no file: the head and the tail only */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    Thread = StartReceiver(&Receiver, Peer, sizeof(g_Head) + sizeof(g_Tail));
    Result = pTransmitFile(Sender, NULL, 0, 0, NULL, &Buffers, 0);
    ok(Result == TRUE, "Result = %d, error %d\n", Result, WSAGetLastError());
    FinishReceiver(Thread, &Receiver);
    CheckData(&Receiver, TRUE, 0, 0, TRUE, "buffers only");
    closesocket(Sender);
    closesocket(Peer);
}

static
void
TestOverlappedEvent(void)
{
    SOCKET Sender, Peer;
    RECEIVER Receiver;
    HANDLE Thread;
    TRANSMIT_FILE_BUFFERS Buffers;
    WSAOVERLAPPED Overlapped;
    DWORD Returned, Flags;
    BOOL Result;

    Buffers.Head = (PVOID)g_Head;
    Buffers.HeadLength = sizeof(g_Head);
    Buffers.Tail = (PVOID)g_Tail;
    Buffers.TailLength = sizeof(g_Tail);

    ok(MakePair(&Sender, &Peer), "no connection\n");
    Thread = StartReceiver(&Receiver, Peer, sizeof(g_Head) + FILE_SIZE - 777 + sizeof(g_Tail));

    /* an OVERLAPPED with offset 0 starts at the file pointer (measured on Windows 10) */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = WSACreateEvent();
    Rewind(g_File, 777);
    Result = pTransmitFile(Sender, g_File, 0, 0, &Overlapped, &Buffers, 0);
    ok(Result == FALSE && WSAGetLastError() == WSA_IO_PENDING, "Result = %d, error %d\n", Result, WSAGetLastError());
    ok(WaitForSingleObject(Overlapped.hEvent, WAIT_TIME) == WAIT_OBJECT_0, "no completion\n");
    Returned = 0;
    Result = WSAGetOverlappedResult(Sender, &Overlapped, &Returned, FALSE, &Flags);
    ok(Result == TRUE, "WSAGetOverlappedResult: %d, error %d\n", Result, WSAGetLastError());
    ok(Returned == sizeof(g_Head) + FILE_SIZE - 777 + sizeof(g_Tail), "transferred %lu\n", Returned);
    FinishReceiver(Thread, &Receiver);
    CheckData(&Receiver, TRUE, 777, FILE_SIZE - 777, TRUE, "overlapped");
    WSACloseEvent(Overlapped.hEvent);
    closesocket(Sender);
    closesocket(Peer);

    /* a non-zero offset of the OVERLAPPED wins over the file pointer (still at 777) */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    Thread = StartReceiver(&Receiver, Peer, 5000);
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = WSACreateEvent();
    Overlapped.Offset = 3000;
    Result = pTransmitFile(Sender, g_File, 5000, 0, &Overlapped, NULL, 0);
    ok(Result == FALSE && WSAGetLastError() == WSA_IO_PENDING, "Result = %d, error %d\n", Result, WSAGetLastError());
    ok(WaitForSingleObject(Overlapped.hEvent, WAIT_TIME) == WAIT_OBJECT_0, "no completion\n");
    Returned = 0;
    Result = WSAGetOverlappedResult(Sender, &Overlapped, &Returned, FALSE, &Flags);
    ok(Result == TRUE && Returned == 5000, "WSAGetOverlappedResult: %d, error %d, transferred %lu\n",
       Result, WSAGetLastError(), Returned);
    FinishReceiver(Thread, &Receiver);
    CheckData(&Receiver, FALSE, 3000, 5000, FALSE, "overlapped offset");
    WSACloseEvent(Overlapped.hEvent);
    closesocket(Sender);
    closesocket(Peer);
}

static
void
TestCompletionPort(void)
{
    SOCKET Sender, Peer;
    RECEIVER Receiver;
    HANDLE Thread, Port;
    WSAOVERLAPPED Overlapped;
    LPOVERLAPPED Completed;
    ULONG_PTR Key;
    DWORD Returned, Flags;
    BOOL Result;

    ok(MakePair(&Sender, &Peer), "no connection\n");
    Rewind(g_File, 0);
    Port = CreateIoCompletionPort((HANDLE)Sender, NULL, 0x77, 0);
    ok(Port != NULL, "no port: %lu\n", GetLastError());
    Thread = StartReceiver(&Receiver, Peer, FILE_SIZE);

    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Result = pTransmitFile(Sender, g_File, 0, 0, &Overlapped, NULL, 0);
    ok(Result == FALSE && WSAGetLastError() == WSA_IO_PENDING, "Result = %d, error %d\n", Result, WSAGetLastError());

    Returned = 0xDEAD;
    Key = 0;
    Completed = NULL;
    Result = GetQueuedCompletionStatus(Port, &Returned, &Key, &Completed, WAIT_TIME);
    ok(Completed == &Overlapped, "the packet is for %p, expected %p (error %lu)\n", Completed, &Overlapped, GetLastError());
    ok(Key == 0x77, "key %lx\n", (ULONG)Key);
    /* Windows: the packet says TRUE and the bytes of the transfer. Here the packet is only the notice,
     * the transfer's result is read with GetOverlappedResult */
    trace("probe: the packet: result %d, %lu bytes\n", Result, Returned);
    if (Completed == &Overlapped)
    {
        Returned = 0;
        Result = WSAGetOverlappedResult(Sender, &Overlapped, &Returned, FALSE, &Flags);
        ok(Result == TRUE, "WSAGetOverlappedResult: %d, error %d\n", Result, WSAGetLastError());
        ok(Returned == FILE_SIZE, "transferred %lu\n", Returned);
    }
    FinishReceiver(Thread, &Receiver);
    CheckData(&Receiver, FALSE, 0, FILE_SIZE, FALSE, "completion port");

    /* no second packet */
    Completed = NULL;
    Result = GetQueuedCompletionStatus(Port, &Returned, &Key, &Completed, 200);
    ok(Result == FALSE && Completed == NULL, "a second packet: %d, %p\n", Result, Completed);

    /* the low bit of hEvent: no packet, the event still signals */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = (HANDLE)((ULONG_PTR)WSACreateEvent() | 1);
    Thread = StartReceiver(&Receiver, Peer, 2000);
    Result = pTransmitFile(Sender, g_File, 2000, 0, &Overlapped, NULL, 0);
    ok(Result == FALSE && WSAGetLastError() == WSA_IO_PENDING, "Result = %d, error %d\n", Result, WSAGetLastError());
    ok(WaitForSingleObject((HANDLE)((ULONG_PTR)Overlapped.hEvent & ~1), WAIT_TIME) == WAIT_OBJECT_0, "no completion\n");
    FinishReceiver(Thread, &Receiver);
    Completed = NULL;
    Result = GetQueuedCompletionStatus(Port, &Returned, &Key, &Completed, 200);
    ok(Result == FALSE && Completed == NULL, "a packet with the low bit set: %d, %p\n", Result, Completed);
    WSACloseEvent((HANDLE)((ULONG_PTR)Overlapped.hEvent & ~1));

    closesocket(Sender);
    closesocket(Peer);
    CloseHandle(Port);
}

static
void
TestDisconnect(void)
{
    SOCKET Sender, Peer;
    RECEIVER Receiver;
    HANDLE Thread;
    WSAOVERLAPPED Overlapped;
    DWORD Returned, Flags;
    BOOL Result;
    char Byte = 'x';
    int Length;
    struct sockaddr_in Name;

    /* the peer sees the end of the stream after the data, without a close */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    Thread = StartReceiver(&Receiver, Peer, 0xFFFFFFFF);
    Rewind(g_File, 0);
    Result = pTransmitFile(Sender, g_File, 0, 0, NULL, NULL, TF_DISCONNECT);
    ok(Result == TRUE, "Result = %d, error %d\n", Result, WSAGetLastError());
    FinishReceiver(Thread, &Receiver);
    ok(Receiver.Eof, "no end of stream\n");
    CheckData(&Receiver, FALSE, 0, FILE_SIZE, FALSE, "TF_DISCONNECT");
    Result = send(Sender, &Byte, 1, 0);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAESHUTDOWN, "send after TF_DISCONNECT: %d, error %d\n",
       Result, WSAGetLastError());
    Length = sizeof(Name);
    Result = getpeername(Sender, (struct sockaddr *)&Name, &Length);
    trace("probe: getpeername after TF_DISCONNECT: %d, error %d\n", Result, WSAGetLastError());
    closesocket(Sender);
    closesocket(Peer);

    /* overlapped, TF_DISCONNECT | TF_REUSE_SOCKET */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    Thread = StartReceiver(&Receiver, Peer, 0xFFFFFFFF);
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = WSACreateEvent();
    Rewind(g_File, 0);
    Result = pTransmitFile(Sender, g_File, 30000, 0, &Overlapped, NULL, TF_DISCONNECT | TF_REUSE_SOCKET);
    ok(Result == FALSE && WSAGetLastError() == WSA_IO_PENDING, "Result = %d, error %d\n", Result, WSAGetLastError());
    /* Windows 10: with TF_REUSE_SOCKET the request does not complete while the peer keeps its end open
     * (nothing completed in 30 s). Here it completes when the connection is closed on our side; the
     * peer is closed first so that both behave the same */
    FinishReceiver(Thread, &Receiver);
    ok(Receiver.Eof, "no end of stream\n");
    CheckData(&Receiver, FALSE, 0, 30000, FALSE, "overlapped TF_DISCONNECT");
    closesocket(Peer);
    Peer = INVALID_SOCKET;
    ok(WaitForSingleObject(Overlapped.hEvent, WAIT_TIME) == WAIT_OBJECT_0, "no completion\n");
    Returned = 0;
    Result = WSAGetOverlappedResult(Sender, &Overlapped, &Returned, FALSE, &Flags);
    ok(Result == TRUE && Returned == 30000, "WSAGetOverlappedResult: %d, error %d, transferred %lu\n",
       Result, WSAGetLastError(), Returned);
    WSACloseEvent(Overlapped.hEvent);
    closesocket(Sender);
    closesocket(Peer);
}

static
void
TestPackets(void)
{
    SOCKET Sender, Peer;
    RECEIVER Receiver;
    HANDLE Thread;
    TRANSMIT_PACKETS_ELEMENT Elements[4];
    WSAOVERLAPPED Overlapped;
    DWORD Returned, Flags, Total = sizeof(g_Head) + 1500 + sizeof(g_Tail) + 100;
    BOOL Result;

    ZeroMemory(Elements, sizeof(Elements));
    Elements[0].dwElFlags = TP_ELEMENT_MEMORY;
    Elements[0].cLength = sizeof(g_Head);
    Elements[0].pBuffer = (PVOID)g_Head;
    Elements[1].dwElFlags = TP_ELEMENT_FILE;
    Elements[1].cLength = 1500;
    Elements[1].nFileOffset.QuadPart = 10000;
    Elements[1].hFile = g_File;
    Elements[2].dwElFlags = TP_ELEMENT_MEMORY;
    Elements[2].cLength = sizeof(g_Tail);
    Elements[2].pBuffer = (PVOID)g_Tail;
    Elements[3].dwElFlags = TP_ELEMENT_FILE | TP_ELEMENT_EOP;
    Elements[3].cLength = 100;
    Elements[3].nFileOffset.QuadPart = 0;
    Elements[3].hFile = g_File;

    ok(MakePair(&Sender, &Peer), "no connection\n");
    Thread = StartReceiver(&Receiver, Peer, Total);
    Result = pTransmitPackets(Sender, Elements, 4, 0, NULL, 0);
    ok(Result == TRUE, "Result = %d, error %d\n", Result, WSAGetLastError());
    FinishReceiver(Thread, &Receiver);
    ok(Receiver.Got == Total, "received %lu, expected %lu\n", Receiver.Got, Total);
    if (Receiver.Got == Total)
    {
        DWORD At = 0;

        ok(memcmp(Receiver.Buffer + At, g_Head, sizeof(g_Head)) == 0, "packets: wrong first element\n");
        At += sizeof(g_Head);
        ok(memcmp(Receiver.Buffer + At, g_Data + 10000, 1500) == 0, "packets: wrong second element\n");
        At += 1500;
        ok(memcmp(Receiver.Buffer + At, g_Tail, sizeof(g_Tail)) == 0, "packets: wrong third element\n");
        At += sizeof(g_Tail);
        ok(memcmp(Receiver.Buffer + At, g_Data, 100) == 0, "packets: wrong fourth element\n");
    }
    closesocket(Sender);
    closesocket(Peer);

    /* overlapped */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    Thread = StartReceiver(&Receiver, Peer, Total);
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = WSACreateEvent();
    Result = pTransmitPackets(Sender, Elements, 4, 0, &Overlapped, 0);
    ok(Result == FALSE && WSAGetLastError() == WSA_IO_PENDING, "Result = %d, error %d\n", Result, WSAGetLastError());
    ok(WaitForSingleObject(Overlapped.hEvent, WAIT_TIME) == WAIT_OBJECT_0, "no completion\n");
    Returned = 0;
    Result = WSAGetOverlappedResult(Sender, &Overlapped, &Returned, FALSE, &Flags);
    ok(Result == TRUE && Returned == Total, "WSAGetOverlappedResult: %d, error %d, transferred %lu\n",
       Result, WSAGetLastError(), Returned);
    FinishReceiver(Thread, &Receiver);
    ok(Receiver.Got == Total, "received %lu, expected %lu\n", Receiver.Got, Total);
    WSACloseEvent(Overlapped.hEvent);
    closesocket(Sender);
    closesocket(Peer);
}

static
void
TestErrors(void)
{
    SOCKET Sender, Peer, Udp, Unconnected;
    WSAOVERLAPPED Overlapped;
    BOOL Result;
    u_long Mode = 1;
    DWORD Returned, Flags;
    int Error;

    /* a socket that is not connected */
    Unconnected = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Rewind(g_File, 0);
    Result = pTransmitFile(Unconnected, g_File, 0, 0, NULL, NULL, 0);
    Error = WSAGetLastError();
    ok(Result == FALSE && Error == WSAENOTCONN, "not connected: %d, error %d\n", Result, Error);
    closesocket(Unconnected);

    /* a datagram socket */
    Udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    Result = pTransmitFile(Udp, g_File, 0, 0, NULL, NULL, 0);
    Error = WSAGetLastError();
    ok(Result == FALSE && Error == WSAENOTCONN, "datagram socket: %d, error %d\n", Result, Error);
    closesocket(Udp);

    /* not a socket */
    Result = pTransmitFile((SOCKET)g_File, g_File, 0, 0, NULL, NULL, 0);
    Error = WSAGetLastError();
    ok(Result == FALSE && Error == WSAEINVAL, "not a socket: %d, error %d\n", Result, Error);

    ok(MakePair(&Sender, &Peer), "no connection\n");

    /* not a file */
    Result = pTransmitFile(Sender, (HANDLE)(ULONG_PTR)0x7FFF0, 0, 0, NULL, NULL, 0);
    ok(Result == FALSE && GetLastError() == ERROR_INVALID_HANDLE, "invalid file handle: %d, error %lu\n", Result, GetLastError());

    /* more than the file has */
    {
        RECEIVER Receiver;
        HANDLE Thread = StartReceiver(&Receiver, Peer, 0xFFFFFFFF);

        Rewind(g_File, FILE_SIZE - 100);
        Result = pTransmitFile(Sender, g_File, 300, 0, NULL, NULL, 0);
        Error = WSAGetLastError();
        ok(Result == FALSE && Error == WSAEINVAL, "300 bytes of 100 left: %d, error %d\n", Result, Error);
        shutdown(Sender, SD_SEND);
        FinishReceiver(Thread, &Receiver);
        ok(Receiver.Got == 0, "300 bytes of 100 left: the peer received %lu bytes\n", Receiver.Got);
    }
    closesocket(Sender);
    closesocket(Peer);

    /* a non-blocking socket, no OVERLAPPED */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    ioctlsocket(Sender, FIONBIO, &Mode);
    Rewind(g_File, 0);
    Result = pTransmitFile(Sender, g_File, 100, 0, NULL, NULL, 0);
    Error = WSAGetLastError();
    ok(Result == TRUE, "non-blocking, no OVERLAPPED: %d, error %d\n", Result, Error);
    closesocket(Sender);
    closesocket(Peer);

    /* TF_REUSE_SOCKET without TF_DISCONNECT, and flags that are not defined */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    Rewind(g_File, 0);
    Result = pTransmitFile(Sender, g_File, 100, 0, NULL, NULL, TF_REUSE_SOCKET);
    Error = WSAGetLastError();
    ok(Result == TRUE, "TF_REUSE_SOCKET alone: %d, error %d\n", Result, Error);
    Rewind(g_File, 0);
    Result = pTransmitFile(Sender, g_File, 100, 0, NULL, NULL, 0x80000000);
    Error = WSAGetLastError();
    ok(Result == FALSE && Error == WSAEINVAL, "undefined flag: %d, error %d\n", Result, Error);
    /* nothing to send at all */
    Result = pTransmitFile(Sender, NULL, 0, 0, NULL, NULL, 0);
    Error = WSAGetLastError();
    ok(Result == FALSE && Error == WSAENOTCONN, "no file, no buffers, after TF_REUSE_SOCKET: %d, error %d\n", Result, Error);
    closesocket(Sender);
    closesocket(Peer);

    /* closesocket while a transfer waits for a peer that does not read: the request completes with an error
     * (not run on Windows: the error code is not recorded) */
    ok(MakePair(&Sender, &Peer), "no connection\n");
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = WSACreateEvent();
    {
        WCHAR Dir[MAX_PATH], Name[MAX_PATH];
        HANDLE Big;
        LARGE_INTEGER Size;
        int SendBuffer = 8192;

        GetTempPathW(RTL_NUMBER_OF(Dir), Dir);
        _snwprintf(Name, RTL_NUMBER_OF(Name), L"%stfile-big-%lu.tmp", Dir, GetCurrentProcessId());
        Big = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                          CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
        Size.QuadPart = 256 * 1024 * 1024;
        if (Big == INVALID_HANDLE_VALUE || !SetFilePointerEx(Big, Size, NULL, FILE_BEGIN) || !SetEndOfFile(Big))
        {
            skip("cannot create the big file: %lu\n", GetLastError());
        }
        else
        {
            setsockopt(Sender, SOL_SOCKET, SO_SNDBUF, (char *)&SendBuffer, sizeof(SendBuffer));
            setsockopt(Peer, SOL_SOCKET, SO_RCVBUF, (char *)&SendBuffer, sizeof(SendBuffer));
            Rewind(Big, 0);
            Result = pTransmitFile(Sender, Big, 0, 0, &Overlapped, NULL, 0);
            Error = WSAGetLastError();
            ok(Result == FALSE && Error == WSA_IO_PENDING, "Result = %d, error %d\n", Result, Error);
            ok(WaitForSingleObject(Overlapped.hEvent, 1000) == WAIT_TIMEOUT, "completed although nobody reads\n");
            closesocket(Sender);
            ok(WaitForSingleObject(Overlapped.hEvent, WAIT_TIME) == WAIT_OBJECT_0, "no completion after closesocket\n");
            Returned = 0;
            Result = GetOverlappedResult(Big, &Overlapped, &Returned, FALSE);
            Error = GetLastError();
            ok(Result == FALSE, "the transfer succeeded after closesocket\n");
            trace("probe: transfer after closesocket: error %d, %lu bytes\n", Error, Returned);
        }
        if (Big != INVALID_HANDLE_VALUE)
            CloseHandle(Big);
        (void)Flags;
    }
    WSACloseEvent(Overlapped.hEvent);
    closesocket(Peer);
}

/* A transfer that fails still queues its packet on the completion port (as a success: here the packet is only
 * the notice), and GetOverlappedResult has the error */
static
void
TestFailedOnPort(void)
{
    SOCKET Sender, Peer;
    HANDLE Port, Big;
    WSAOVERLAPPED Overlapped;
    LPOVERLAPPED Completed;
    ULONG_PTR Key;
    DWORD Returned;
    BOOL Result;
    WCHAR Dir[MAX_PATH], Name[MAX_PATH];
    LARGE_INTEGER Size;

    GetTempPathW(RTL_NUMBER_OF(Dir), Dir);
    _snwprintf(Name, RTL_NUMBER_OF(Name), L"%stfile-big2-%lu.tmp", Dir, GetCurrentProcessId());
    Big = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    Size.QuadPart = 256 * 1024 * 1024;
    if (Big == INVALID_HANDLE_VALUE || !SetFilePointerEx(Big, Size, NULL, FILE_BEGIN) || !SetEndOfFile(Big))
    {
        skip("cannot create the big file: %lu\n", GetLastError());
        if (Big != INVALID_HANDLE_VALUE)
            CloseHandle(Big);
        return;
    }
    Rewind(Big, 0);

    ok(MakePair(&Sender, &Peer), "no connection\n");
    Port = CreateIoCompletionPort((HANDLE)Sender, NULL, 0x78, 0);
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Result = pTransmitFile(Sender, Big, 0, 0, &Overlapped, NULL, 0);
    ok(Result == FALSE && WSAGetLastError() == WSA_IO_PENDING, "Result = %d, error %d\n", Result, WSAGetLastError());
    Sleep(500);
    closesocket(Sender);

    Completed = NULL;
    Key = 0;
    Returned = 0;
    Result = GetQueuedCompletionStatus(Port, &Returned, &Key, &Completed, WAIT_TIME);
    ok(Completed == &Overlapped, "the packet is for %p, expected %p (error %lu)\n", Completed, &Overlapped, GetLastError());
    /* Windows: FALSE with the error. Here: TRUE, the error is in GetOverlappedResult */
    trace("probe: packet of a failed transfer: result %d, error %lu\n", Result, GetLastError());
    if (Completed == &Overlapped)
    {
        Returned = 0;
        Result = GetOverlappedResult(Big, &Overlapped, &Returned, FALSE);
        ok(Result == FALSE, "the transfer succeeded after closesocket\n");
    }

    CloseHandle(Port);
    closesocket(Peer);
    CloseHandle(Big);
}

START_TEST(transmitfile)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    TestPointers();
    if (!pTransmitFile || !pTransmitPackets)
    {
        skip("no TransmitFile or TransmitPackets\n");
        WSACleanup();
        return;
    }

    if (!CreateData())
    {
        skip("cannot create the file\n");
        WSACleanup();
        return;
    }

    TestBlocking();
    TestOverlappedEvent();
    TestCompletionPort();
    TestDisconnect();
    TestPackets();
    TestErrors();
    TestFailedOnPort();

    CloseHandle(g_File);
    DeleteFileW(g_FileName);
    ok(GetFileAttributesW(g_FileName) == INVALID_FILE_ATTRIBUTES, "the temporary file is still there\n");
    WSACleanup();
}
