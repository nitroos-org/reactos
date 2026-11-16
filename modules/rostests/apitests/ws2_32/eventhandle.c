/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test the errors of WSAEventSelect and WSAEnumNetworkEvents for event handles that are not events
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Windows 10: a handle that is not an event (a mutex, INVALID_HANDLE_VALUE, a handle that is not open) gives
 * WSAENOTSOCK from both. A NULL event with events to report gives WSAEINVAL from WSAEventSelect, and
 * WSAEnumNetworkEvents accepts a NULL event.
 */

#include "ws2_32.h"

static void
CheckHandle(SOCKET Socket, const char *Name, HANDLE Event, int SelectError)
{
    WSANETWORKEVENTS Events;
    int Result;

    Result = WSAEventSelect(Socket, (WSAEVENT)Event, FD_READ);
    if (SelectError)
        ok(Result == SOCKET_ERROR && WSAGetLastError() == SelectError,
           "%s: WSAEventSelect returned %d, error %d, expected %d\n", Name, Result,
           Result ? WSAGetLastError() : 0, SelectError);
    else
        ok(Result == 0, "%s: WSAEventSelect returned %d, error %d\n", Name, Result, WSAGetLastError());
    WSAEventSelect(Socket, NULL, 0);

    ZeroMemory(&Events, sizeof(Events));
    Result = WSAEnumNetworkEvents(Socket, (WSAEVENT)Event, &Events);
    if (Event)
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK,
           "%s: WSAEnumNetworkEvents returned %d, error %d, expected WSAENOTSOCK\n", Name, Result,
           Result ? WSAGetLastError() : 0);
    else
        ok(Result == 0, "%s: WSAEnumNetworkEvents returned %d, error %d\n", Name, Result, WSAGetLastError());
}

START_TEST(eventhandle)
{
    WSADATA WsaData;
    SOCKET Socket;
    HANDLE Mutex, Event;
    int Result;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }
    Socket = socket(AF_INET, SOCK_STREAM, 0);
    ok(Socket != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Socket == INVALID_SOCKET)
        return;

    Mutex = CreateMutexW(NULL, FALSE, NULL);
    ok(Mutex != NULL, "CreateMutex failed: %lu\n", GetLastError());
    CheckHandle(Socket, "mutex", Mutex, WSAENOTSOCK);
    CheckHandle(Socket, "INVALID_HANDLE_VALUE", INVALID_HANDLE_VALUE, WSAENOTSOCK);
    CheckHandle(Socket, "NULL", NULL, WSAEINVAL);

    /* An event handle that was closed (its value is free, and the next handle made may take it) */
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(Event != NULL, "CreateEvent failed: %lu\n", GetLastError());
    CloseHandle(Event);
    CheckHandle(Socket, "closed event", Event, WSAENOTSOCK);

    /* A NULL event with no events to report switches the selection off */
    Result = WSAEventSelect(Socket, NULL, 0);
    ok(Result == 0, "WSAEventSelect(NULL, 0) returned %d, error %d\n", Result, WSAGetLastError());

    /* A real event still works after the errors */
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(Event != NULL, "CreateEvent failed: %lu\n", GetLastError());
    Result = WSAEventSelect(Socket, (WSAEVENT)Event, FD_READ);
    ok(Result == 0, "WSAEventSelect(event) returned %d, error %d\n", Result, WSAGetLastError());
    {
        WSANETWORKEVENTS Events;

        Result = WSAEnumNetworkEvents(Socket, (WSAEVENT)Event, &Events);
        ok(Result == 0, "WSAEnumNetworkEvents(event) returned %d, error %d\n", Result, WSAGetLastError());
    }
    WSAEventSelect(Socket, NULL, 0);

    CloseHandle(Event);
    CloseHandle(Mutex);
    closesocket(Socket);
    WSACleanup();
}
