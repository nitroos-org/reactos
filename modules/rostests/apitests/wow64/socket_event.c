/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     WSAEventSelect/EnumNetworkEvents: event handle, reset, rearm and close
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* WSAEventSelect/EnumNetworkEvents: event handle, reset, rearm and close. */
#define WIN32_NO_STATUS
#include <winsock2.h>
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ndk/ntndk.h>
#include <winioctl.h>
#include <tdi.h>
#include <drivers/afd/shared.h>
#include <stdio.h>
#include <string.h>
static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%d\n", __LINE__, #x, WSAGetLastError()); } } while (0)
static DWORD WINAPI Watchdog(PVOID Done)
{
    if (WaitForSingleObject(Done, 30000) != WAIT_OBJECT_0) ExitProcess(124);
    return 0;
}
int main(void)
{
    WSADATA Wsa;
    SOCKET Listener = INVALID_SOCKET, Client = INVALID_SOCKET, Server = INVALID_SOCKET;
    WSAEVENT Event = WSA_INVALID_EVENT;
    HANDLE Done, Thread;
    struct sockaddr_in Address = {0};
    struct { DWORD Before; WSANETWORKEVENTS Events; DWORD After; } Result;
    int Size = sizeof(Address), i;
    char Byte;
    BOOL Wow = FALSE;
    setvbuf(stdout, NULL, _IONBF, 0);
    Done = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, Watchdog, Done, 0, NULL);
    CHECK(WSAStartup(MAKEWORD(2,2), &Wsa) == 0);
    Listener = socket(AF_INET, SOCK_STREAM, 0);
    Client = socket(AF_INET, SOCK_STREAM, 0);
    Address.sin_family = AF_INET; Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(Listener != INVALID_SOCKET && Client != INVALID_SOCKET);
    CHECK(bind(Listener, (struct sockaddr *)&Address, sizeof(Address)) == 0);
    CHECK(getsockname(Listener, (struct sockaddr *)&Address, &Size) == 0);
    CHECK(listen(Listener, 1) == 0);
    CHECK(connect(Client, (struct sockaddr *)&Address, sizeof(Address)) == 0);
    Server = accept(Listener, NULL, NULL);
    CHECK(Server != INVALID_SOCKET);
    Event = WSACreateEvent(); CHECK(Event != WSA_INVALID_EVENT);
    CHECK(WSAEventSelect(Client, Event, FD_READ | FD_WRITE | FD_CLOSE) == 0);
    if (Failures) goto done;
    CHECK(WSAWaitForMultipleEvents(1, &Event, FALSE, 5000, FALSE) == WSA_WAIT_EVENT_0);
    memset(&Result, 0xa5, sizeof(Result));
    CHECK(WSAEnumNetworkEvents(Client, Event, &Result.Events) == 0);
    CHECK((Result.Events.lNetworkEvents & FD_WRITE) && Result.Events.iErrorCode[FD_WRITE_BIT] == 0);
    CHECK(Result.Before == 0xa5a5a5a5 && Result.After == 0xa5a5a5a5);
    CHECK(WSAWaitForMultipleEvents(1, &Event, FALSE, 0, FALSE) == WSA_WAIT_TIMEOUT);
    for (i = 0; i < 2; ++i)
    {
        CHECK(send(Server, "x", 1, 0) == 1);
        CHECK(WSAWaitForMultipleEvents(1, &Event, FALSE, 5000, FALSE) == WSA_WAIT_EVENT_0);
        CHECK(WSAEnumNetworkEvents(Client, Event, &Result.Events) == 0);
        CHECK((Result.Events.lNetworkEvents & FD_READ) && Result.Events.iErrorCode[FD_READ_BIT] == 0);
        CHECK(recv(Client, &Byte, 1, 0) == 1 && Byte == 'x');
        CHECK(WSAWaitForMultipleEvents(1, &Event, FALSE, 0, FALSE) == WSA_WAIT_TIMEOUT);
    }
    CHECK(shutdown(Server, SD_SEND) == 0);
    CHECK(WSAWaitForMultipleEvents(1, &Event, FALSE, 5000, FALSE) == WSA_WAIT_EVENT_0);
    CHECK(WSAEnumNetworkEvents(Client, Event, &Result.Events) == 0);
    CHECK((Result.Events.lNetworkEvents & FD_CLOSE) && Result.Events.iErrorCode[FD_CLOSE_BIT] == 0);
    CHECK(recv(Client, &Byte, 1, 0) == 0);
    CHECK(WSAEventSelect(Client, NULL, 0) == 0);
    CHECK(Result.Before == 0xa5a5a5a5 && Result.After == 0xa5a5a5a5);
    IsWow64Process(GetCurrentProcess(), &Wow);
    if (Wow)
    {
        IO_STATUS_BLOCK Io;
        ULONG Input[2] = {HandleToUlong(Event), 0};
        /* ReactOS private ABI: reject absent/truncated guest records. */
        CHECK(NtDeviceIoControlFile((HANDLE)Client, NULL, NULL, NULL, &Io,
              IOCTL_AFD_EVENT_SELECT, NULL, sizeof(Input), NULL, 0) == STATUS_INVALID_PARAMETER);
        CHECK(NtDeviceIoControlFile((HANDLE)Client, NULL, NULL, NULL, &Io,
              IOCTL_AFD_ENUM_NETWORK_EVENTS, NULL, (2 + AFD_MAX_EVENTS) * sizeof(ULONG), NULL, 0) == STATUS_INVALID_PARAMETER);
        CHECK(NtDeviceIoControlFile((HANDLE)Client, NULL, NULL, NULL, &Io,
              IOCTL_AFD_EVENT_SELECT, Input, sizeof(ULONG), NULL, 0) == STATUS_BUFFER_TOO_SMALL);
        CHECK(NtDeviceIoControlFile((HANDLE)Client, NULL, NULL, NULL, &Io,
              IOCTL_AFD_ENUM_NETWORK_EVENTS, Input, sizeof(Input), NULL, 0) == STATUS_BUFFER_TOO_SMALL);
    }
done:
    if (Event != WSA_INVALID_EVENT) WSACloseEvent(Event);
    if (Server != INVALID_SOCKET) closesocket(Server);
    if (Client != INVALID_SOCKET) closesocket(Client);
    if (Listener != INVALID_SOCKET) closesocket(Listener);
    WSACleanup(); SetEvent(Done); WaitForSingleObject(Thread, 1000); CloseHandle(Thread); CloseHandle(Done);
    printf("SOCKET EVENT: %u checks, %u failures\n", Checks, Failures);
    return Failures ? 1 : 0;
}
