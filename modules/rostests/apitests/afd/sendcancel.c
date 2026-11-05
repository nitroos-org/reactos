/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     IOCTL_AFD_SEND cancelled while it waits for the transport
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Three whole (AFD_SEND_WHOLE) overlapped sends of 16 MB, 3000 and 4000 bytes on a connection whose receiver does
 * not read: none can complete. One of them is cancelled. It completes with STATUS_CANCELLED and no bytes; the bytes of
 * it that were in the send window of AFD are sent, once, and are not counted against the requests behind it, which stay
 * pending until their own bytes are sent and then complete with their whole length, in order.
 */

#include "precomp.h"

#if DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA

#define SENDS 3

typedef struct _REQ
{
    IO_STATUS_BLOCK IoStatus;
    AFD_SEND_INFO Info;
    AFD_WSABUF Buffer;
    HANDLE Event;
    PUCHAR Data;
    NTSTATUS Status;
} REQ;

static
SOCKET
MakePair(
    _Out_ SOCKET *Server)
{
    SOCKET Listener = socket(AF_INET, SOCK_STREAM, 0), Client = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in Addr;
    int Length = sizeof(Addr);

    memset(&Addr, 0, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "bind failed\n");
    ok(getsockname(Listener, (struct sockaddr *)&Addr, &Length) == 0, "getsockname failed\n");
    ok(listen(Listener, 1) == 0, "listen failed\n");
    ok(connect(Client, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "connect failed %d\n", WSAGetLastError());
    *Server = accept(Listener, NULL, NULL);
    ok(*Server != INVALID_SOCKET, "accept failed\n");
    closesocket(Listener);
    return Client;
}

typedef struct _STREAM
{
    LONGLONG Count[256];
    LONGLONG Total;
    int Last, Violations;
} STREAM;

static
void
Drain(
    _In_ SOCKET Server,
    _Inout_ STREAM *Stream,
    _In_ ULONG IdleMs,
    _In_ LONGLONG Limit)
{
    static char Buffer[65536];
    int Count = 1, i;

    setsockopt(Server, SOL_SOCKET, SO_RCVTIMEO, (char *)&IdleMs, sizeof(IdleMs));
    while (Stream->Total < Limit && (Count = recv(Server, Buffer, (int)min((LONGLONG)sizeof(Buffer), Limit - Stream->Total), 0)) > 0)
    {
        for (i = 0; i < Count; i++)
        {
            UCHAR Value = (UCHAR)Buffer[i];

            if (Value != Stream->Last)
            {
                if (Stream->Count[Value])
                    Stream->Violations++;
                Stream->Last = Value;
            }
            Stream->Count[Value]++;
        }
        Stream->Total += Count;
    }
}

static
void
Post(
    _In_ HANDLE Socket,
    _Out_ REQ *Req,
    _In_ ULONG Length,
    _In_ UCHAR Value)
{
    NTSTATUS Status;

    memset(Req, 0, sizeof(*Req));
    Req->Data = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
    memset(Req->Data, Value, Length);
    Status = NtCreateEvent(&Req->Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(Status == STATUS_SUCCESS, "NtCreateEvent failed with %lx\n", Status);
    Req->Buffer.buf = (PVOID)Req->Data;
    Req->Buffer.len = Length;
    Req->Info.BufferArray = &Req->Buffer;
    Req->Info.BufferCount = 1;
    Req->Info.TdiFlags = 0;
    Req->Info.AfdFlags = AFD_OVERLAPPED | AFD_SEND_WHOLE;
    Req->IoStatus.Status = STATUS_PENDING;
    Status = NtDeviceIoControlFile(Socket, Req->Event, NULL, NULL, &Req->IoStatus, IOCTL_AFD_SEND,
                                   &Req->Info, sizeof(Req->Info), NULL, 0);
    ok(Status == STATUS_PENDING || Status == STATUS_SUCCESS, "IOCTL_AFD_SEND failed with %lx\n", Status);
}

static
BOOLEAN
Done(
    _In_ REQ *Req,
    _In_ ULONG Ms)
{
    LARGE_INTEGER Timeout;

    Timeout.QuadPart = -(LONGLONG)Ms * 10000;
    return NtWaitForSingleObject(Req->Event, FALSE, &Timeout) == STATUS_WAIT_0;
}

static
void
TestCancel(
    _In_ int Victim)
{
    static const UCHAR Values[SENDS] = { 0xA1, 0xB2, 0xC3 };
    static const ULONG Lengths[SENDS] = { 16000000, 3000, 4000 };
    SOCKET Server, Client = MakePair(&Server);
    HANDLE Handle = (HANDLE)Client;
    IO_STATUS_BLOCK CancelStatus;
    NTSTATUS Status;
    REQ Reqs[SENDS];
    STREAM Stream;
    int i;

    memset(&Stream, 0, sizeof(Stream));
    Stream.Last = -1;
    for (i = 0; i < SENDS; i++)
        Post(Handle, &Reqs[i], Lengths[i], Values[i]);
    Sleep(500);
    for (i = 0; i < SENDS; i++)
        ok(!Done(&Reqs[i], 0), "request %d completed with nobody reading\n", i);

    Status = NtCancelIoFileEx(Handle, &Reqs[Victim].IoStatus, &CancelStatus);
    ok(Status == STATUS_SUCCESS, "victim %d: NtCancelIoFileEx failed with %lx\n", Victim, Status);
    ok(Done(&Reqs[Victim], 10000), "the cancelled request did not complete\n");
    ok(Reqs[Victim].IoStatus.Status == STATUS_CANCELLED, "cancelled request: %lx\n", Reqs[Victim].IoStatus.Status);
    ok(Reqs[Victim].IoStatus.Information == 0, "cancelled request: %Iu bytes\n", Reqs[Victim].IoStatus.Information);

    /* The others stay pending: the cancelled one's bytes are not counted against them */
    Sleep(500);
    for (i = 0; i < SENDS; i++)
        ok(i == Victim || !Done(&Reqs[i], 0), "victim %d: request %d completed with nobody reading\n", Victim, i);

    Drain(Server, &Stream, 1500, 0x7fffffffffffffffLL);
    for (i = 0; i < SENDS; i++)
    {
        if (i == Victim)
            continue;
        ok(Done(&Reqs[i], 20000), "victim %d: request %d did not complete\n", Victim, i);
        ok(Reqs[i].IoStatus.Status == STATUS_SUCCESS && Reqs[i].IoStatus.Information == Lengths[i],
           "victim %d: request %d: %lx, %Iu bytes\n", Victim, i, Reqs[i].IoStatus.Status, Reqs[i].IoStatus.Information);
        ok(Stream.Count[Values[i]] == Lengths[i], "victim %d: %I64d bytes of request %d\n",
           Victim, Stream.Count[Values[i]], i);
    }
    ok(Stream.Count[Values[Victim]] < Lengths[Victim], "%I64d bytes of the cancelled request\n", Stream.Count[Values[Victim]]);
    ok(Stream.Violations == 0, "the stream is out of order\n");

    for (i = 0; i < SENDS; i++)
    {
        NtClose(Reqs[i].Event);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Reqs[i].Data);
    }
    closesocket(Client);
    closesocket(Server);
}

#endif /* DLL_EXPORT_VERSION */

START_TEST(sendcancel)
{
#if DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA
    WSADATA Data;
    int Victim;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");
    for (Victim = 0; Victim < SENDS; Victim++)
        TestCancel(Victim);
    WSACleanup();
#else
    skip("NtCancelIoFileEx is not available\n");
#endif
}
