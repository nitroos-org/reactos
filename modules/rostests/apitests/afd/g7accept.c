/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Contract test: a super accept (AcceptEx) request on a socket that is not listening is
 *              refused at once (STATUS_INVALID_PARAMETER, WSAEINVAL through AcceptEx, as on Windows)
 *              instead of waiting for ever; a listening socket still accepts.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"
#include <mswsock.h>

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
void
G7SetAddr(struct sockaddr_in *Addr, USHORT Port)
{
    RtlZeroMemory(Addr, sizeof(*Addr));
    Addr->sin_family = AF_INET;
    Addr->sin_port = Port;
    Addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

START_TEST(g7acceptlistening)
{
    WSADATA WsaData;
    GUID AcceptExGuid = WSAID_ACCEPTEX;
    LPFN_ACCEPTEX pAcceptEx = NULL;
    SOCKET Fresh, Bound, Connected, Peer, Accepted, Listener;
    struct sockaddr_in Addr;
    int Len = sizeof(Addr), Pass;
    DWORD Bytes = 0, Out;
    char Buffer[128];
    OVERLAPPED Overlapped;
    BOOL Result;

    WSAStartup(MAKEWORD(2, 2), &WsaData);

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    G7SetAddr(&Addr, 0);
    ok(Listener != INVALID_SOCKET && !bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) &&
       !listen(Listener, 4) && !getsockname(Listener, (struct sockaddr *)&Addr, &Len), "listener setup failed\n");
    WSAIoctl(Listener, SIO_GET_EXTENSION_FUNCTION_POINTER, &AcceptExGuid, sizeof(AcceptExGuid),
             &pAcceptEx, sizeof(pAcceptEx), &Bytes, NULL, NULL);
    if (!pAcceptEx)
    {
        skip("AcceptEx is not available\n");
        closesocket(Listener);
        WSACleanup();
        return;
    }

    /* A socket that is not listening: fresh, bound, connected */
    Fresh = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Bound = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    G7SetAddr(&Addr, 0);
    {
        struct sockaddr_in Local;
        G7SetAddr(&Local, 0);
        ok(!bind(Bound, (struct sockaddr *)&Local, sizeof(Local)), "bind failed %d\n", WSAGetLastError());
    }
    Connected = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    G7SetAddr(&Addr, 0);
    Len = sizeof(Addr);
    getsockname(Listener, (struct sockaddr *)&Addr, &Len);
    ok(!connect(Connected, (struct sockaddr *)&Addr, sizeof(Addr)), "connect failed %d\n", WSAGetLastError());
    Accepted = accept(Listener, NULL, NULL);
    if (Accepted != INVALID_SOCKET)
        closesocket(Accepted);

    for (Pass = 0; Pass < 3; Pass++)
    {
        SOCKET NotListening = Pass == 0 ? Fresh : Pass == 1 ? Bound : Connected;
        static const char *Names[] = { "fresh", "bound", "connected" };

        Peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        RtlZeroMemory(&Overlapped, sizeof(Overlapped));
        Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        SetLastError(0xdeadbeef);
        Result = pAcceptEx(NotListening, Peer, Buffer, 0, 32, 32, &Out, &Overlapped);
        ok(!Result && WSAGetLastError() == WSAEINVAL, "AcceptEx on a %s socket: %d, error %d\n",
           Names[Pass], Result, WSAGetLastError());
        if (!Result && WSAGetLastError() == WSA_IO_PENDING)
        {
            /* Waiting for a connection that cannot come: do not wait for ever */
            CancelIo((HANDLE)NotListening);
            WaitForSingleObject(Overlapped.hEvent, 2000);
        }
        CloseHandle(Overlapped.hEvent);
        closesocket(Peer);

        /* The request AcceptEx makes of AFD, sent directly: refused at once, not queued */
        {
            AFD_SUPER_ACCEPT_INFO Info;
            char Output[64];
            NTSTATUS Status;

            Peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            RtlZeroMemory(&Info, sizeof(Info));
            Info.AcceptHandle = (HANDLE)Peer;
            Info.LocalAddressLength = 32;
            Info.RemoteAddressLength = 32;
            Status = G7Ioctl((HANDLE)NotListening, IOCTL_AFD_SUPER_ACCEPT, &Info, sizeof(Info),
                             Output, sizeof(Output), NULL);
            ok(Status == STATUS_INVALID_PARAMETER, "AFD_SUPER_ACCEPT on a %s socket gave 0x%lx\n", Names[Pass], Status);
            closesocket(Peer);
        }
    }

    /* A listening socket still accepts */
    Peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    RtlZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    Result = pAcceptEx(Listener, Peer, Buffer, 0, 32, 32, &Out, &Overlapped);
    ok(!Result && WSAGetLastError() == WSA_IO_PENDING, "AcceptEx on the listener: %d, error %d\n", Result, WSAGetLastError());
    {
        SOCKET Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok(!connect(Client, (struct sockaddr *)&Addr, sizeof(Addr)), "connect failed %d\n", WSAGetLastError());
        ok(WaitForSingleObject(Overlapped.hEvent, 5000) == WAIT_OBJECT_0, "AcceptEx did not complete\n");
        closesocket(Client);
    }
    CloseHandle(Overlapped.hEvent);
    closesocket(Peer);

    closesocket(Fresh);
    closesocket(Bound);
    closesocket(Connected);
    closesocket(Listener);
    WSACleanup();
}

