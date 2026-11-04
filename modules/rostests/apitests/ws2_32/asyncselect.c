/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     WSAAsyncSelect read loop of the kind Qt runs: a message for FD_READ, one read, the selection
 *              cancelled with (0, 0) and made again when the program gets to it. Whatever the server sent has
 *              to arrive: an FD_READ that is lost while data waits stalls the program for good.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <winuser.h>

#define WM_SOCK     (WM_USER)
#define WM_REARM (WM_USER + 2)
#define TOTAL       (6 * 1024 * 1024)

typedef struct
{
    HWND Window;
    SOCKET Socket;
    ULONG Chunk;
    ULONGLONG Received;
    BOOL Closed, Corrupt;
    ULONG ReadMessages;
} READER;

static READER *g_Reader;

static
void
Drain(READER *Reader, ULONG Chunk)
{
    static char Buffer[65536];
    int Count;

    Count = recv(Reader->Socket, Buffer, Chunk, 0);
    if (Count > 0)
    {
        int i;

        for (i = 0; i < Count; i++)
        {
            if ((UCHAR)Buffer[i] != (UCHAR)((Reader->Received + i) * 7 + ((Reader->Received + i) >> 8)))
            {
                Reader->Corrupt = TRUE;
                break;
            }
        }
        Reader->Received += Count;
    }
    else if (Count == 0 || WSAGetLastError() != WSAEWOULDBLOCK)
    {
        Reader->Closed = TRUE;
    }
}

static
LRESULT
CALLBACK
WindowProc(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
    READER *Reader = g_Reader;

    if (Message == WM_SOCK)
    {
        /* What the Qt event dispatcher does with a socket message: cancel, ask itself to select again, act */
        WSAAsyncSelect(Reader->Socket, Window, 0, 0);
        PostMessageW(Window, WM_REARM, 0, 0);
        if (WSAGETSELECTEVENT(lParam) == FD_READ)
        {
            Reader->ReadMessages++;
            Drain(Reader, Reader->Chunk);
        }
        else if (WSAGETSELECTEVENT(lParam) == FD_CLOSE)
        {
            /* The peer closed: what it sent before is still to be read */
            while (!Reader->Closed)
                Drain(Reader, sizeof(char) * 65536);
        }
        return 0;
    }
    if (Message == WM_REARM)
    {
        if (!Reader->Closed)
            WSAAsyncSelect(Reader->Socket, Window, WM_SOCK, FD_READ | FD_CLOSE | FD_ACCEPT);
        return 0;
    }
    return DefWindowProcW(Window, Message, wParam, lParam);
}

static
DWORD
WINAPI
SendThread(LPVOID Parameter)
{
    SOCKET Listener = (SOCKET)(ULONG_PTR)Parameter, Peer;
    static char Block[16384];
    ULONGLONG Sent = 0;
    int Count, i;

    Peer = accept(Listener, NULL, NULL);
    if (Peer == INVALID_SOCKET)
        return 1;
    while (Sent < TOTAL)
    {
        for (i = 0; i < (int)sizeof(Block); i++)
            Block[i] = (char)((Sent + i) * 7 + ((Sent + i) >> 8));
        Count = send(Peer, Block, sizeof(Block), 0);
        if (Count <= 0)
            break;
        Sent += Count;
    }
    closesocket(Peer);
    return 0;
}

static
void
RunRead(ULONG Chunk)
{
    static READER Reader;
    WNDCLASSW Class = { 0 };
    SOCKET Listener;
    struct sockaddr_in Address;
    int Length = sizeof(Address);
    ULONG NonBlocking = 1;
    HANDLE Thread;
    MSG Message;
    ULONGLONG LastReceived = (ULONGLONG)-1;
    ULONG LastProgress;
    BOOL Stalled = FALSE;

    ZeroMemory(&Reader, sizeof(Reader));
    Reader.Chunk = Chunk;
    g_Reader = &Reader;

    Class.lpfnWndProc = WindowProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"AsyncSelectRead";
    RegisterClassW(&Class);
    Reader.Window = CreateWindowW(L"AsyncSelectRead", L"", 0, 0, 0, 1, 1, HWND_MESSAGE, NULL, Class.hInstance, NULL);
    ok(Reader.Window != NULL, "CreateWindow failed %lu\n", GetLastError());

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok_int(bind(Listener, (struct sockaddr *)&Address, sizeof(Address)), 0);
    ok_int(listen(Listener, 1), 0);
    ok_int(getsockname(Listener, (struct sockaddr *)&Address, &Length), 0);
    Thread = CreateThread(NULL, 0, SendThread, (LPVOID)(ULONG_PTR)Listener, 0, NULL);

    Reader.Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok_int(connect(Reader.Socket, (struct sockaddr *)&Address, sizeof(Address)), 0);
    ok_int(ioctlsocket(Reader.Socket, FIONBIO, &NonBlocking), 0);
    ok_int(WSAAsyncSelect(Reader.Socket, Reader.Window, WM_SOCK, FD_READ | FD_CLOSE), 0);

    LastProgress = GetTickCount();
    while (!Reader.Closed)
    {
        while (PeekMessageW(&Message, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&Message);
        if (Reader.Received != LastReceived)
        {
            LastReceived = Reader.Received;
            LastProgress = GetTickCount();
        }
        else if (GetTickCount() - LastProgress > 10000)
        {
            Stalled = TRUE;
            break;
        }
        MsgWaitForMultipleObjectsEx(0, NULL, 100, QS_ALLINPUT | QS_ALLPOSTMESSAGE, MWMO_INPUTAVAILABLE);
    }

    ok(!Stalled, "chunk %lu: no FD_READ for 10 s with %I64u of %u bytes received (%lu read messages)\n", Chunk,
       Reader.Received, TOTAL, Reader.ReadMessages);
    ok(!Reader.Corrupt, "chunk %lu: the data are not the data sent\n", Chunk);
    if (!Stalled)
        ok(Reader.Received == TOTAL, "chunk %lu: received %I64u of %u bytes\n", Chunk, Reader.Received, TOTAL);

    closesocket(Reader.Socket);
    closesocket(Listener);
    WaitForSingleObject(Thread, 10000);
    CloseHandle(Thread);
    DestroyWindow(Reader.Window);
    UnregisterClassW(L"AsyncSelectRead", Class.hInstance);
}

/*
 * FD_CONNECT reports a connect that completes while the socket is selected. A socket whose connect was
 * over before WSAAsyncSelect (or that was accepted) gets FD_WRITE only: measured on Windows 10.
 */
#define WM_EVENTS (WM_USER + 1)

static ULONG g_EventCount;
static LONG g_Events[8];

static
LRESULT
CALLBACK
EventWindowProc(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
    if (Message == WM_EVENTS)
    {
        if (g_EventCount < RTL_NUMBER_OF(g_Events))
            g_Events[g_EventCount] = WSAGETSELECTEVENT(lParam);
        g_EventCount++;
        return 0;
    }
    return DefWindowProcW(Window, Message, wParam, lParam);
}

static
void
PumpFor(ULONG Milliseconds)
{
    ULONG Start = GetTickCount();
    MSG Message;

    while (GetTickCount() - Start < Milliseconds)
    {
        while (PeekMessageW(&Message, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&Message);
        MsgWaitForMultipleObjectsEx(0, NULL, 20, QS_ALLINPUT | QS_ALLPOSTMESSAGE, MWMO_INPUTAVAILABLE);
    }
}

static
void
RunConnectEvents(void)
{
    WNDCLASSW Class = { 0 };
    HWND Window;
    SOCKET Listener, Client, Accepted;
    struct sockaddr_in Address;
    int Length = sizeof(Address), Result, Error;

    Class.lpfnWndProc = EventWindowProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"AsyncSelectEvents";
    RegisterClassW(&Class);
    Window = CreateWindowW(L"AsyncSelectEvents", L"", 0, 0, 0, 1, 1, HWND_MESSAGE, NULL, Class.hInstance, NULL);
    ok(Window != NULL, "CreateWindow failed %lu\n", GetLastError());

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok_int(bind(Listener, (struct sockaddr *)&Address, sizeof(Address)), 0);
    ok_int(listen(Listener, 4), 0);
    ok_int(getsockname(Listener, (struct sockaddr *)&Address, &Length), 0);

    /* Selected first, then the connect completes: FD_CONNECT, then FD_WRITE */
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok_int(WSAAsyncSelect(Client, Window, WM_EVENTS, FD_CONNECT | FD_WRITE), 0);
    g_EventCount = 0;
    Result = connect(Client, (struct sockaddr *)&Address, sizeof(Address));
    Error = WSAGetLastError();
    ok(Result == 0 || Error == WSAEWOULDBLOCK, "connect returned %d, error %d\n", Result, Error);
    PumpFor(500);
    ok(g_EventCount == 2, "selected before the connect: %lu events\n", g_EventCount);
    if (g_EventCount == 2)
    {
        ok(g_Events[0] == FD_CONNECT, "first event is 0x%lx, expected FD_CONNECT\n", g_Events[0]);
        ok(g_Events[1] == FD_WRITE, "second event is 0x%lx, expected FD_WRITE\n", g_Events[1]);
    }
    Accepted = accept(Listener, NULL, NULL);
    ok(Accepted != INVALID_SOCKET, "accept failed %d\n", WSAGetLastError());

    /* The connect is over already: selecting again gives FD_WRITE only */
    g_EventCount = 0;
    ok_int(WSAAsyncSelect(Client, Window, WM_EVENTS, FD_CONNECT | FD_WRITE), 0);
    PumpFor(500);
    ok(g_EventCount == 1, "selected after the connect: %lu events\n", g_EventCount);
    if (g_EventCount >= 1)
        ok(g_Events[0] == FD_WRITE, "event is 0x%lx, expected FD_WRITE only\n", g_Events[0]);
    closesocket(Client);

    /* A blocking connect, then the selection */
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok_int(connect(Client, (struct sockaddr *)&Address, sizeof(Address)), 0);
    g_EventCount = 0;
    ok_int(WSAAsyncSelect(Client, Window, WM_EVENTS, FD_CONNECT | FD_WRITE | FD_CLOSE), 0);
    PumpFor(500);
    ok(g_EventCount == 1, "blocking connect, then the selection: %lu events\n", g_EventCount);
    if (g_EventCount >= 1)
        ok(g_Events[0] == FD_WRITE, "event is 0x%lx, expected FD_WRITE only\n", g_Events[0]);
    closesocket(Client);
    closesocket(Accepted);

    /* An accepted socket was never connecting */
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok_int(connect(Client, (struct sockaddr *)&Address, sizeof(Address)), 0);
    Accepted = accept(Listener, NULL, NULL);
    ok(Accepted != INVALID_SOCKET, "accept failed %d\n", WSAGetLastError());
    g_EventCount = 0;
    ok_int(WSAAsyncSelect(Accepted, Window, WM_EVENTS, FD_CONNECT | FD_WRITE), 0);
    PumpFor(500);
    ok(g_EventCount == 1, "accepted socket: %lu events\n", g_EventCount);
    if (g_EventCount >= 1)
        ok(g_Events[0] == FD_WRITE, "event is 0x%lx, expected FD_WRITE only\n", g_Events[0]);
    closesocket(Client);
    closesocket(Accepted);

    closesocket(Listener);
    DestroyWindow(Window);
    UnregisterClassW(L"AsyncSelectEvents", Class.hInstance);
}

START_TEST(asyncselect)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }
    RunRead(8192);
    RunRead(1024);
    RunRead(65536);
    RunConnectEvents();
    WSACleanup();
}
