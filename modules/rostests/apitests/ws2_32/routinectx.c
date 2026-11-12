/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     With a completion routine the hEvent member of the WSAOVERLAPPED is ignored by
 *              WSASend, WSARecv, WSASendTo and WSARecvFrom: it is free for the application to carry
 *              context to the routine (documented behaviour of the Winsock overlapped functions).
 *              The TNS listener of Oracle Database keeps a pointer there, and its first send on an
 *              accepted connection failed (TNS-12571) because the value was used as an event handle.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values are what the Winsock documentation states for Windows.
 */

#include "ws2_32.h"

/* Not a handle: a pointer-like value as an application keeps in it */
#define CONTEXT_VALUE ((HANDLE)(ULONG_PTR)0x08223ee0)

static volatile LONG Completed;
static DWORD CompletedBytes, CompletedError;
static LPWSAOVERLAPPED CompletedOverlapped;

static void CALLBACK Done(DWORD Error, DWORD Bytes, LPWSAOVERLAPPED Overlapped, DWORD Flags)
{
    CompletedError = Error;
    CompletedBytes = Bytes;
    CompletedOverlapped = Overlapped;
    Completed = 1;
}

static void Wait(void)
{
    DWORD Start = GetTickCount();

    while (!Completed && GetTickCount() - Start < 10000)
        SleepEx(20, TRUE);
}

static void Check(const char *What, int Result, int Error, LPWSAOVERLAPPED Overlapped, DWORD Expected)
{
    ok(Result == 0 || Error == WSA_IO_PENDING, "%s: failed, error %d\n", What, Error);
    Wait();
    ok(Completed == 1, "%s: the completion routine was not called\n", What);
    ok(CompletedError == 0, "%s: routine error %lu\n", What, CompletedError);
    ok(CompletedBytes == Expected, "%s: routine got %lu bytes, expected %lu\n", What, CompletedBytes, Expected);
    ok(CompletedOverlapped == Overlapped, "%s: routine got another overlapped\n", What);
    ok(Overlapped->hEvent == CONTEXT_VALUE, "%s: hEvent changed to %p\n", What, Overlapped->hEvent);
}

static void StreamCase(void)
{
    SOCKET Listener = socket(AF_INET, SOCK_STREAM, 0), Client, Server;
    struct sockaddr_in Addr;
    int Length = sizeof(Addr), Result, Error;
    WSAOVERLAPPED Overlapped;
    WSABUF Buf;
    char Out[16] = "oracle tns", In[64];
    DWORD Bytes, Flags;

    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "bind failed\n");
    ok(getsockname(Listener, (struct sockaddr *)&Addr, &Length) == 0, "getsockname failed\n");
    ok(listen(Listener, 1) == 0, "listen failed\n");
    Client = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    ok(connect(Client, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "connect failed: %d\n", WSAGetLastError());
    Server = accept(Listener, NULL, NULL);
    ok(Server != INVALID_SOCKET, "accept failed\n");
    closesocket(Listener);

    /* WSASend */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CONTEXT_VALUE;
    Buf.buf = Out;
    Buf.len = sizeof(Out);
    Completed = 0;
    Bytes = 0;
    Result = WSASend(Client, &Buf, 1, &Bytes, 0, &Overlapped, Done);
    Error = Result ? WSAGetLastError() : 0;
    Check("WSASend", Result, Error, &Overlapped, sizeof(Out));

    /* WSARecv of what was sent */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CONTEXT_VALUE;
    Buf.buf = In;
    Buf.len = sizeof(In);
    Completed = 0;
    Flags = 0;
    Result = WSARecv(Server, &Buf, 1, &Bytes, &Flags, &Overlapped, Done);
    Error = Result ? WSAGetLastError() : 0;
    Check("WSARecv", Result, Error, &Overlapped, sizeof(Out));
    ok(!memcmp(In, Out, sizeof(Out)), "received other data\n");

    /* A receive that has to wait for the data */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CONTEXT_VALUE;
    Completed = 0;
    Flags = 0;
    Result = WSARecv(Client, &Buf, 1, &Bytes, &Flags, &Overlapped, Done);
    Error = Result ? WSAGetLastError() : 0;
    ok(Result == SOCKET_ERROR && Error == WSA_IO_PENDING, "pending WSARecv: %d, %d\n", Result, Error);
    ok(send(Server, Out, 5, 0) == 5, "send failed\n");
    Check("pending WSARecv", 0, 0, &Overlapped, 5);

    closesocket(Client);
    closesocket(Server);
}

static void DatagramCase(void)
{
    SOCKET A = socket(AF_INET, SOCK_DGRAM, 0), B = WSASocketW(AF_INET, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_in AddrA, AddrB, From;
    int Length = sizeof(AddrA), FromLength = sizeof(From), Result, Error;
    WSAOVERLAPPED Overlapped;
    WSABUF Buf;
    char Out[8] = "datagrm", In[64];
    DWORD Bytes, Flags;

    ZeroMemory(&AddrA, sizeof(AddrA));
    AddrA.sin_family = AF_INET;
    AddrA.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    AddrB = AddrA;
    ok(bind(A, (struct sockaddr *)&AddrA, sizeof(AddrA)) == 0, "bind failed\n");
    ok(getsockname(A, (struct sockaddr *)&AddrA, &Length) == 0, "getsockname failed\n");
    ok(bind(B, (struct sockaddr *)&AddrB, sizeof(AddrB)) == 0, "bind failed\n");

    /* WSASendTo */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CONTEXT_VALUE;
    Buf.buf = Out;
    Buf.len = sizeof(Out);
    Completed = 0;
    Result = WSASendTo(B, &Buf, 1, &Bytes, 0, (struct sockaddr *)&AddrA, sizeof(AddrA), &Overlapped, Done);
    Error = Result ? WSAGetLastError() : 0;
    Check("WSASendTo", Result, Error, &Overlapped, sizeof(Out));

    /* WSARecvFrom */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CONTEXT_VALUE;
    Buf.buf = In;
    Buf.len = sizeof(In);
    Completed = 0;
    Flags = 0;
    Result = WSARecvFrom(A, &Buf, 1, &Bytes, &Flags, (struct sockaddr *)&From, &FromLength, &Overlapped, Done);
    Error = Result ? WSAGetLastError() : 0;
    Check("WSARecvFrom", Result, Error, &Overlapped, sizeof(Out));

    closesocket(A);
    closesocket(B);
}

START_TEST(routinectx)
{
    WSADATA Data;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");
    StreamCase();
    DatagramCase();
    WSACleanup();
}
