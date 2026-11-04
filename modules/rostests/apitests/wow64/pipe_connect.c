/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     MSI custom-action transport: pending listen, wait, transceive and disconnect
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* MSI custom-action transport: pending listen, wait, transceive and disconnect. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
static WCHAR Name[100];
static HANDLE Begin;
static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)
static DWORD WINAPI Client(PVOID Context)
{
    HANDLE Pipe;
    DWORD Mode = PIPE_READMODE_MESSAGE, Bytes;
    CHAR Reply[8];
    BOOL Ok;
    if (WaitForSingleObject(Begin, 10000) != WAIT_OBJECT_0 || !WaitNamedPipeW(Name, 10000)) return 1;
    Pipe = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (Pipe == INVALID_HANDLE_VALUE) return 2;
    Ok = SetNamedPipeHandleState(Pipe, &Mode, NULL, NULL) &&
         TransactNamedPipe(Pipe, "ping", 4, Reply, sizeof(Reply), &Bytes, NULL) &&
         Bytes == 4 && !memcmp(Reply, "pong", 4);
    CloseHandle(Pipe);
    return Ok ? 0 : 3;
}
int main(void)
{
    HANDLE Pipe, Event, Thread = NULL;
    DWORD Bytes = 0, Available = 0, Code, i;
    struct { DWORD Before; OVERLAPPED Io; DWORD After; } Over = {0};
    CHAR Data[8];
    BOOL Ok;
    _snwprintf(Name, 100, L"\\\\.\\pipe\\w643c-connect-%lu", GetCurrentProcessId());
    Pipe = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                           PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                           1, 1024, 1024, 1000, NULL);
    Begin = CreateEventW(NULL, TRUE, FALSE, NULL);
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(Pipe != INVALID_HANDLE_VALUE && Begin && Event);
    if (Pipe == INVALID_HANDLE_VALUE || !Begin || !Event) goto done;
    Over.Before = 0x12345678; Over.After = 0xabcdef01; Over.Io.hEvent = Event;
    Ok = ConnectNamedPipe(Pipe, &Over.Io);
    CHECK(!Ok && GetLastError() == ERROR_IO_PENDING);
    if (Ok || GetLastError() != ERROR_IO_PENDING) goto done;
    CHECK(WaitForSingleObject(Event, 0) == WAIT_TIMEOUT);
    Thread = CreateThread(NULL, 0, Client, NULL, 0, NULL);
    CHECK(Thread != NULL);
    if (!Thread) goto done;
    SetEvent(Begin);
    CHECK(WaitForSingleObject(Event, 10000) == WAIT_OBJECT_0);
    CHECK(GetOverlappedResult(Pipe, &Over.Io, &Bytes, FALSE));
    CHECK(Over.Before == 0x12345678 && Over.After == 0xabcdef01);
    for (i = 0; i < 100 && !Available; ++i)
    {
        if (!PeekNamedPipe(Pipe, NULL, 0, NULL, &Available, NULL)) break;
        if (!Available) Sleep(10);
    }
    CHECK(Available == 4);
    ResetEvent(Event);
    Ok = ReadFile(Pipe, Data, sizeof(Data), &Bytes, &Over.Io);
    CHECK(Ok || GetLastError() == ERROR_IO_PENDING);
    CHECK(WaitForSingleObject(Event, 10000) == WAIT_OBJECT_0);
    CHECK(GetOverlappedResult(Pipe, &Over.Io, &Bytes, FALSE) && Bytes == 4 && !memcmp(Data, "ping", 4));
    ResetEvent(Event);
    Ok = WriteFile(Pipe, "pong", 4, &Bytes, &Over.Io);
    CHECK(Ok || GetLastError() == ERROR_IO_PENDING);
    CHECK(WaitForSingleObject(Event, 10000) == WAIT_OBJECT_0);
    CHECK(GetOverlappedResult(Pipe, &Over.Io, &Bytes, FALSE) && Bytes == 4);
    CHECK(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0);
    CHECK(GetExitCodeThread(Thread, &Code) && Code == 0);
    CHECK(DisconnectNamedPipe(Pipe));
    CHECK(Over.Before == 0x12345678 && Over.After == 0xabcdef01);
done:
    if (Pipe != INVALID_HANDLE_VALUE) CloseHandle(Pipe);
    if (Thread) { WaitForSingleObject(Thread, 10000); CloseHandle(Thread); }
    if (Begin) CloseHandle(Begin);
    if (Event) CloseHandle(Event);
    printf("PIPE CONNECT: %u checks, %u failures\n", Checks, Failures);
    return Failures ? 1 : 0;
}
