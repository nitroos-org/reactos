/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     Cancelling an overlapped stream send
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows 10 22H2 (loopback, SO_SNDBUF 0, a receiver that does not read, 32 MB sends that stay pending):
 * CancelIoEx on the pending send completes it with WSA_OPERATION_ABORTED and 0 bytes, and the transport
 * aborts the connection: the sends queued behind it complete with WSAECONNABORTED and 0 bytes, and the
 * receiver gets nothing but the reset.
 *
 * ReactOS does not abort the connection (a send that Windows would have completed when it buffered it is
 * pending in AFD until the transport takes it, and a thread that exits cancels such sends): what was copied into
 * the send window of AFD before the cancel is still sent, the sends behind complete with their whole length
 * once the transport takes them, and the stream keeps its order.
 */

#include "ws2_32.h"

#define BIG_LEN (32 * 1024 * 1024)

static BOOL (WINAPI *pCancelIoEx)(HANDLE, LPOVERLAPPED);

typedef struct _SEND
{
    WSAOVERLAPPED Overlapped;
    WSABUF Buf;
} SEND;

typedef struct _STREAM
{
    LONG64 Total;
    LONG64 Count[256];
    int Last;
    int OrderViolations;
    int Error;
} STREAM;

static void MakePair(SOCKET *Client, SOCKET *Server, int SendBuf)
{
    SOCKET Listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in Addr;
    int Length = sizeof(Addr);

    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "bind failed\n");
    ok(getsockname(Listener, (struct sockaddr *)&Addr, &Length) == 0, "getsockname failed\n");
    ok(listen(Listener, 1) == 0, "listen failed\n");
    *Client = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (SendBuf >= 0)
        ok(setsockopt(*Client, SOL_SOCKET, SO_SNDBUF, (char *)&SendBuf, sizeof(SendBuf)) == 0,
           "SO_SNDBUF failed: %d\n", WSAGetLastError());
    ok(connect(*Client, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "connect failed: %d\n", WSAGetLastError());
    *Server = accept(Listener, NULL, NULL);
    ok(*Server != INVALID_SOCKET, "accept failed\n");
    closesocket(Listener);
}

static void Post(SOCKET Client, SEND *Send, ULONG Length, BYTE Value)
{
    DWORD Sent = 0;
    int Result, Error;

    ZeroMemory(Send, sizeof(*Send));
    Send->Buf.len = Length;
    Send->Buf.buf = HeapAlloc(GetProcessHeap(), 0, Length);
    ok(Send->Buf.buf != NULL, "out of memory\n");
    if (!Send->Buf.buf)
        return;
    memset(Send->Buf.buf, Value, Length);
    Send->Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    Result = WSASend(Client, &Send->Buf, 1, &Sent, 0, &Send->Overlapped, NULL);
    Error = Result ? WSAGetLastError() : 0;
    ok(Result == 0 || Error == WSA_IO_PENDING, "WSASend(%lu) failed: %d\n", Length, Error);
}

static BOOL IsDone(SEND *Send)
{
    return WaitForSingleObject(Send->Overlapped.hEvent, 0) == WAIT_OBJECT_0;
}

static BOOL WaitDone(SEND *Send, DWORD Timeout)
{
    return WaitForSingleObject(Send->Overlapped.hEvent, Timeout) == WAIT_OBJECT_0;
}

/* The outcome of a completed send */
static BOOL Outcome(SOCKET Client, SEND *Send, DWORD *Bytes, int *Error)
{
    DWORD Flags;
    BOOL Ok;

    *Bytes = 0xdeadbeef;
    Ok = WSAGetOverlappedResult(Client, &Send->Overlapped, Bytes, FALSE, &Flags);
    *Error = Ok ? 0 : WSAGetLastError();
    return Ok;
}

static void Release(SEND *Send)
{
    CloseHandle(Send->Overlapped.hEvent);
    HeapFree(GetProcessHeap(), 0, Send->Buf.buf);
}

/* Reads what is there until nothing comes for IdleMs; notes the run of each byte value in the stream */
static void Drain(SOCKET Server, STREAM *Stream, DWORD IdleMs, LONG64 Limit)
{
    static char Buffer[65536];
    int Count = 1, i;

    setsockopt(Server, SOL_SOCKET, SO_RCVTIMEO, (char *)&IdleMs, sizeof(IdleMs));
    while (Stream->Total < Limit && (Count = recv(Server, Buffer, (int)min((LONG64)sizeof(Buffer), Limit - Stream->Total), 0)) > 0)
    {
        for (i = 0; i < Count; i++)
        {
            BYTE Value = (BYTE)Buffer[i];

            if (Value != Stream->Last)
            {
                if (Stream->Count[Value])
                    Stream->OrderViolations++;
                Stream->Last = Value;
            }
            Stream->Count[Value]++;
        }
        Stream->Total += Count;
    }
    if (Count <= 0)
        Stream->Error = Count ? WSAGetLastError() : 0;
}

static void FreeStream(STREAM *Stream)
{
    ZeroMemory(Stream, sizeof(*Stream));
    Stream->Last = -1;
}

/* Three overlapped sends of 32 MB, 1000 and 4000 bytes that cannot complete while nobody reads (the first one has
 * as much as the send window of AFD holds in the window), then one of them is cancelled. Only the cancel of the
 * first is what Windows was measured with. */
static void TestCancelStalled(int Victim)
{
    static const BYTE Values[3] = { 0xA1, 0xB2, 0xC3 };
    static const ULONG Lengths[3] = { BIG_LEN, 1000, 4000 };
    SOCKET Client, Server;
    SEND Sends[3];
    STREAM Stream;
    DWORD Bytes;
    int Error, i;
    BOOL Ok;

    trace("send %d of 3 stalled sends is cancelled\n", Victim);
    FreeStream(&Stream);
    MakePair(&Client, &Server, 0);
    for (i = 0; i < 3; i++)
        Post(Client, &Sends[i], Lengths[i], Values[i]);
    Sleep(500);
    ok(!IsDone(&Sends[0]), "the send of %d bytes completed with nobody reading\n", BIG_LEN);
    ok(!IsDone(&Sends[1]) && !IsDone(&Sends[2]), "a send behind a stalled one completed\n");

    ok(pCancelIoEx((HANDLE)Client, &Sends[Victim].Overlapped), "CancelIoEx failed: %lu\n", GetLastError());
    ok(WaitDone(&Sends[Victim], 10000), "the cancelled send did not complete\n");
    Ok = Outcome(Client, &Sends[Victim], &Bytes, &Error);
    ok(!Ok && Error == WSA_OPERATION_ABORTED, "cancelled send: ok %d, error %d\n", Ok, Error);
    ok(Bytes == 0, "cancelled send completed with %lu bytes\n", Bytes);

    if (is_reactos())
    {
        /* Nothing was read, so the sends that are left are still waiting for the transport */
        Sleep(500);
        for (i = 0; i < 3; i++)
            ok(i == Victim || !IsDone(&Sends[i]), "send %d completed with nobody reading\n", i);
        Drain(Server, &Stream, 1500, 0x7fffffffffffffffLL);
        for (i = 0; i < 3; i++)
        {
            if (i == Victim)
                continue;
            ok(WaitDone(&Sends[i], 20000), "send %d did not complete\n", i);
            Ok = Outcome(Client, &Sends[i], &Bytes, &Error);
            ok(Ok && Bytes == Lengths[i], "send %d: ok %d, %lu bytes, error %d\n", i, Ok, Bytes, Error);
            ok(Stream.Count[Values[i]] == Lengths[i], "the receiver got %I64d bytes of send %d\n", Stream.Count[Values[i]], i);
        }
        /* What of the cancelled one was in the send window is still sent */
        ok(Stream.Count[Values[Victim]] < Lengths[Victim], "the receiver got %I64d bytes of the cancelled send\n",
           Stream.Count[Values[Victim]]);
        ok(Stream.OrderViolations == 0, "the stream is out of order\n");
    }
    else
    {
        /* The connection is gone */
        for (i = 1; i < 3; i++)
        {
            ok(WaitDone(&Sends[i], 10000), "send %d did not complete\n", i);
            Ok = Outcome(Client, &Sends[i], &Bytes, &Error);
            ok(!Ok && Error == WSAECONNABORTED && Bytes == 0, "send %d: ok %d, %lu bytes, error %d\n", i, Ok, Bytes, Error);
        }
        Drain(Server, &Stream, 1500, 0x7fffffffffffffffLL);
        ok(Stream.Total == 0, "the receiver got %I64d bytes of an aborted connection\n", Stream.Total);
    }
    for (i = 0; i < 3; i++)
        Release(&Sends[i]);
    closesocket(Client);
    closesocket(Server);
}

START_TEST(sendcancel)
{
    WSADATA Data;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");
    pCancelIoEx = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CancelIoEx");
    if (!pCancelIoEx)
    {
        skip("CancelIoEx is not available\n");
        WSACleanup();
        return;
    }

    TestCancelStalled(0);
    /* The sends behind: ReactOS only, Windows was measured with the first one */
    if (is_reactos())
    {
        TestCancelStalled(1);
        TestCancelStalled(2);
    }

    WSACleanup();
}
