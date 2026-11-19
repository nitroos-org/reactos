/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for CancelIo: the request is gone when it returns, and it does not sleep for it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define CANCEL_ROUNDS   20

static
BOOL
CreatePipePair(_In_ ULONG Index, _Out_ PHANDLE Server, _Out_ PHANDLE Client)
{
    WCHAR Name[64];

    _snwprintf(Name, RTL_NUMBER_OF(Name), L"\\\\.\\pipe\\rostest_cancelio_%lu_%lu", GetCurrentProcessId(), Index);
    *Server = CreateNamedPipeW(Name,
                               PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                               PIPE_TYPE_BYTE | PIPE_WAIT,
                               1, 512, 512, 0, NULL);
    if (*Server == INVALID_HANDLE_VALUE)
        return FALSE;

    *Client = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                          OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (*Client == INVALID_HANDLE_VALUE)
    {
        CloseHandle(*Server);
        return FALSE;
    }

    return TRUE;
}

START_TEST(CancelIo)
{
    LARGE_INTEGER Freq, Start, End;
    HANDLE Server, Client, Event;
    OVERLAPPED Ov;
    CHAR Buffer[16];
    DWORD Bytes;
    BOOL Ret;
    ULONG i;
    ULONGLONG Us, Worst = 0, Total = 0;

    QueryPerformanceFrequency(&Freq);
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(Event != NULL, "CreateEvent failed with %lu\n", GetLastError());

    /* The request is canceled: it is complete, with the aborted status, when CancelIo returns */
    if (!CreatePipePair(0, &Server, &Client))
    {
        skip("Pipe creation failed with %lu\n", GetLastError());
        return;
    }
    ZeroMemory(&Ov, sizeof(Ov));
    Ov.hEvent = Event;
    Ret = ReadFile(Client, Buffer, sizeof(Buffer), NULL, &Ov);
    ok(!Ret && GetLastError() == ERROR_IO_PENDING, "ReadFile returned %d, error %lu\n", Ret, GetLastError());
    Ret = CancelIo(Client);
    ok(Ret, "CancelIo failed with %lu\n", GetLastError());
    ok(HasOverlappedIoCompleted(&Ov), "The request is still pending after CancelIo\n");
    Bytes = 0;
    Ret = GetOverlappedResult(Client, &Ov, &Bytes, FALSE);
    ok(!Ret && GetLastError() == ERROR_OPERATION_ABORTED, "GetOverlappedResult returned %d, error %lu\n", Ret, GetLastError());
    CloseHandle(Client);
    CloseHandle(Server);

    /* Nothing pending: nothing to cancel, nothing to wait for */
    if (!CreatePipePair(1, &Server, &Client))
    {
        skip("Pipe creation failed with %lu\n", GetLastError());
        return;
    }
    Ret = CancelIo(Client);
    ok(Ret, "CancelIo with no request failed with %lu\n", GetLastError());
    CloseHandle(Client);
    CloseHandle(Server);

    /* Cancelling a request that its driver completes at once does not wait for a clock tick (15 ms) per call:
     * CANCEL_ROUNDS calls take far less than the 300 ms they took when every call slept */
    for (i = 0; i < CANCEL_ROUNDS; i++)
    {
        if (!CreatePipePair(2 + i, &Server, &Client))
        {
            skip("Pipe creation failed with %lu\n", GetLastError());
            return;
        }
        ZeroMemory(&Ov, sizeof(Ov));
        Ov.hEvent = Event;
        Ret = ReadFile(Client, Buffer, sizeof(Buffer), NULL, &Ov);
        ok(!Ret && GetLastError() == ERROR_IO_PENDING, "ReadFile returned %d, error %lu\n", Ret, GetLastError());

        QueryPerformanceCounter(&Start);
        Ret = CancelIo(Client);
        QueryPerformanceCounter(&End);
        ok(Ret, "CancelIo failed with %lu\n", GetLastError());

        Us = (End.QuadPart - Start.QuadPart) * 1000000 / Freq.QuadPart;
        Total += Us;
        if (Us > Worst)
            Worst = Us;
        CloseHandle(Client);
        CloseHandle(Server);
    }
    trace("CancelIo x %d: total %I64u us, worst %I64u us\n", CANCEL_ROUNDS, Total, Worst);
    ok(Total < 100000, "%d CancelIo calls took %I64u us\n", CANCEL_ROUNDS, Total);

    CloseHandle(Event);
}
