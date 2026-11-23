/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Test for IOCTL_AFD_SELECT parameter and handle checks
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"

/* The request layout Windows uses for this control code */
typedef struct _TEST_POLL_HANDLE
{
    HANDLE Handle;
    ULONG Events;
    NTSTATUS Status;
} TEST_POLL_HANDLE;

typedef struct _TEST_POLL_INFO
{
    LARGE_INTEGER Timeout;
    ULONG HandleCount;
    ULONG Exclusive;
    TEST_POLL_HANDLE Handles[3];
} TEST_POLL_INFO;

C_ASSERT(FIELD_OFFSET(TEST_POLL_INFO, Handles) == 16);
C_ASSERT(FIELD_OFFSET(TEST_POLL_INFO, Handles) == FIELD_OFFSET(AFD_POLL_INFO, Handles));
C_ASSERT(sizeof(TEST_POLL_HANDLE) == sizeof(AFD_HANDLE));

#define POLL_SIZE(n) (FIELD_OFFSET(TEST_POLL_INFO, Handles) + (n) * sizeof(TEST_POLL_HANDLE))
#define POLL_EVENTS (AFD_EVENT_RECEIVE | AFD_EVENT_SEND | AFD_EVENT_DISCONNECT | AFD_EVENT_ABORT | AFD_EVENT_CLOSE)

static HANDLE Event;

static
NTSTATUS
DoPoll(
    _In_ HANDLE Device,
    _In_opt_ TEST_POLL_INFO *In,
    _In_ ULONG InLength,
    _In_opt_ TEST_POLL_INFO *Out,
    _In_ ULONG OutLength,
    _In_ DWORD WaitMs,
    _Out_ NTSTATUS *Final)
{
    IO_STATUS_BLOCK Io;
    NTSTATUS Status;

    ResetEvent(Event);
    Io.Status = 0x0badf00d;
    Io.Information = 0x0badf00d;
    Status = NtDeviceIoControlFile(Device, Event, NULL, NULL, &Io, IOCTL_AFD_SELECT,
                                   In, InLength, Out, OutLength);
    *Final = Status;
    if (Status == STATUS_PENDING)
    {
        if (WaitForSingleObject(Event, WaitMs) == WAIT_OBJECT_0)
            *Final = Io.Status;
        else
            *Final = STATUS_PENDING;
    }
    return Status;
}

static
BOOL
TcpPair(
    _Out_ SOCKET *Client,
    _Out_ SOCKET *Server)
{
    struct sockaddr_in addr;
    int len = sizeof(addr);
    SOCKET listener;

    *Client = *Server = INVALID_SOCKET;
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
        return FALSE;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) ||
        listen(listener, 1) ||
        getsockname(listener, (struct sockaddr *)&addr, &len))
    {
        closesocket(listener);
        return FALSE;
    }
    *Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*Client != INVALID_SOCKET && !connect(*Client, (struct sockaddr *)&addr, sizeof(addr)))
        *Server = accept(listener, NULL, NULL);
    closesocket(listener);
    if (*Server == INVALID_SOCKET)
    {
        if (*Client != INVALID_SOCKET)
            closesocket(*Client);
        *Client = INVALID_SOCKET;
        return FALSE;
    }
    return TRUE;
}

static
void
InitPoll(
    _Out_ TEST_POLL_INFO *Poll,
    _In_ ULONG Count,
    _In_opt_ HANDLE First,
    _In_opt_ HANDLE Second)
{
    memset(Poll, 0, sizeof(*Poll));
    /* 200 ms, relative */
    Poll->Timeout.QuadPart = -200 * 10000;
    Poll->HandleCount = Count;
    Poll->Handles[0].Handle = First;
    Poll->Handles[0].Events = POLL_EVENTS;
    Poll->Handles[1].Handle = Second;
    Poll->Handles[1].Events = POLL_EVENTS;
}

static
void
TestParameters(
    _In_ SOCKET Client)
{
    TEST_POLL_INFO In, Out;
    NTSTATUS Status, Final;

    /* The input must cover HandleCount entries */
    InitPoll(&In, 1, (HANDLE)Client, NULL);
    Status = DoPoll((HANDLE)Client, &In, POLL_SIZE(1) - 1, &Out, POLL_SIZE(1) - 1, 1000, &Final);
    ok(Status == STATUS_INVALID_PARAMETER, "short input: got %lx\n", Status);

    InitPoll(&In, 2, (HANDLE)Client, (HANDLE)Client);
    Status = DoPoll((HANDLE)Client, &In, POLL_SIZE(1), &Out, POLL_SIZE(2), 1000, &Final);
    ok(Status == STATUS_INVALID_PARAMETER, "input for one of two handles: got %lx\n", Status);

    /* The output must be at least as large as the input */
    InitPoll(&In, 1, (HANDLE)Client, NULL);
    Status = DoPoll((HANDLE)Client, &In, POLL_SIZE(1), &Out, POLL_SIZE(1) - 1, 1000, &Final);
    ok(Status == STATUS_INVALID_PARAMETER, "short output: got %lx\n", Status);

    /* No handles */
    InitPoll(&In, 0, NULL, NULL);
    Status = DoPoll((HANDLE)Client, &In, POLL_SIZE(1), &Out, POLL_SIZE(1), 1000, &Final);
    ok(Status == STATUS_INVALID_PARAMETER, "no handles: got %lx\n", Status);

    /* A well-formed request on a connected socket completes */
    InitPoll(&In, 1, (HANDLE)Client, NULL);
    Status = DoPoll((HANDLE)Client, &In, POLL_SIZE(1), &Out, POLL_SIZE(1), 2000, &Final);
    ok(Status == STATUS_SUCCESS, "valid request: got %lx\n", Status);
    ok(Final == STATUS_SUCCESS, "valid request: final %lx\n", Final);
}

/* The most a poll takes is 65535 sockets (as select() on Windows): one more is refused before any handle is
 * looked at, with the buffers as large as the request needs them */
static
void
TestMaximumCount(
    _In_ SOCKET Client)
{
    ULONG Count, i;
    TEST_POLL_INFO *Poll;
    NTSTATUS Status, Final;

    for (Count = 0xFFFF; Count <= 0x10000; Count++)
    {
        Poll = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, POLL_SIZE(Count));
        if (!Poll)
        {
            skip("out of memory\n");
            return;
        }
        Poll->Timeout.QuadPart = -200 * 10000;
        Poll->HandleCount = Count;
        for (i = 0; i < Count; i++)
        {
            Poll->Handles[i].Handle = (HANDLE)Client;
            Poll->Handles[i].Events = POLL_EVENTS;
        }
        Status = DoPoll((HANDLE)Client, Poll, POLL_SIZE(Count), Poll, POLL_SIZE(Count), 2000, &Final);
        if (Count == 0xFFFF)
            ok(Status == STATUS_SUCCESS || (Status == STATUS_PENDING && Final == STATUS_SUCCESS),
               "65535 handles: got %lx, final %lx\n", Status, Final);
        else
            ok(Status == STATUS_INVALID_PARAMETER, "65536 handles: got %lx\n", Status);
        HeapFree(GetProcessHeap(), 0, Poll);
    }
}

/* Requests that overran kernel memory before the checks; last, so a failure ends nothing else */
static
void
TestUnsafeRequests(
    _In_ SOCKET Client)
{
    TEST_POLL_INFO In, Out;
    NTSTATUS Status, Final;
    HANDLE KernelHandle = (HANDLE)(LONG_PTR)(LONG)0x80000004;

    InitPoll(&In, 1, (HANDLE)Client, NULL);
    Status = DoPoll((HANDLE)Client, &In, POLL_SIZE(1), NULL, 0, 1000, &Final);
    ok(Status == STATUS_INVALID_PARAMETER, "no output: got %lx\n", Status);

    Status = DoPoll((HANDLE)Client, NULL, 0, &Out, POLL_SIZE(1), 1000, &Final);
    ok(Status == STATUS_INVALID_PARAMETER, "no input: got %lx\n", Status);

    /* A count whose size overflows */
    InitPoll(&In, 0x80000001, (HANDLE)Client, NULL);
    Status = DoPoll((HANDLE)Client, &In, POLL_SIZE(1), &Out, POLL_SIZE(1), 1000, &Final);
    ok(Status == STATUS_INVALID_PARAMETER, "huge count: got %lx\n", Status);

    /* A kernel handle value is not the caller's */
    InitPoll(&In, 2, KernelHandle, (HANDLE)Client);
    Status = DoPoll((HANDLE)Client, &In, POLL_SIZE(2), &Out, POLL_SIZE(2), 2000, &Final);
    ok(Status == STATUS_INVALID_HANDLE, "kernel handle: got %lx\n", Status);
}

static
void
TestHandle(
    _In_ SOCKET Client,
    _In_opt_ HANDLE Bad,
    _In_ NTSTATUS Expected,
    _In_ PCSTR What)
{
    TEST_POLL_INFO In, Out;
    NTSTATUS Status, Final;
    ULONG i;

    /* The bad handle in either position, next to a socket that is writable */
    for (i = 0; i < 2; i++)
    {
        if (i == 0)
            InitPoll(&In, 2, Bad, (HANDLE)Client);
        else
            InitPoll(&In, 2, (HANDLE)Client, Bad);
        memset(&Out, 0x55, sizeof(Out));
        Status = DoPoll((HANDLE)Client, &In, POLL_SIZE(2), &Out, POLL_SIZE(2), 2000, &Final);
        ok(Status == Expected, "%s at %lu: got %lx\n", What, i, Status);
        ok(Final == Expected, "%s at %lu: final %lx\n", What, i, Final);
        if (Status != STATUS_PENDING && Status != STATUS_SUCCESS)
            ok(Out.HandleCount == 0x55555555, "%s at %lu: output written (%lx)\n", What, i, Out.HandleCount);
    }
}

static
void
TestHandles(
    _In_ SOCKET Client)
{
    HANDLE File, Dup, Event2;
    CHAR Path[MAX_PATH];
    TEST_POLL_INFO In, Out;
    NTSTATUS Status, Final;

    TestHandle(Client, (HANDLE)(ULONG_PTR)0xabacab, STATUS_INVALID_HANDLE, "invalid value");

    Event2 = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(Event2 != NULL, "CreateEvent failed %lu\n", GetLastError());
    TestHandle(Client, Event2, STATUS_OBJECT_TYPE_MISMATCH, "event");
    CloseHandle(Event2);

    GetSystemWindowsDirectoryA(Path, sizeof(Path));
    strcat(Path, "\\system.ini");
    File = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFile(%s) failed %lu\n", Path, GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        TestHandle(Client, File, STATUS_INVALID_HANDLE, "file");
        CloseHandle(File);
    }

    TestHandle(Client, NULL, STATUS_INVALID_HANDLE, "NULL");

    /* A duplicate of a socket handle is a socket */
    ok(DuplicateHandle(GetCurrentProcess(), (HANDLE)Client, GetCurrentProcess(), &Dup, 0, FALSE, DUPLICATE_SAME_ACCESS),
       "DuplicateHandle failed %lu\n", GetLastError());
    InitPoll(&In, 1, Dup, NULL);
    Status = DoPoll((HANDLE)Client, &In, POLL_SIZE(1), &Out, POLL_SIZE(1), 2000, &Final);
    ok(Status == STATUS_SUCCESS, "duplicate: got %lx\n", Status);
    ok(Final == STATUS_SUCCESS, "duplicate: final %lx\n", Final);
    CloseHandle(Dup);
}

typedef struct _CLOSE_CONTEXT
{
    SOCKET Socket;
    DWORD Delay;
} CLOSE_CONTEXT;

static
DWORD
WINAPI
CloseThread(
    _In_ LPVOID Parameter)
{
    CLOSE_CONTEXT *Context = Parameter;

    Sleep(Context->Delay);
    closesocket(Context->Socket);
    return 0;
}

/* Poll on one handle of a socket while another thread closes the same or another handle of it */
static
void
TestCloseDuringPoll(
    _In_ BOOL Duplicate,
    _In_ BOOL PollOnDuplicate)
{
    SOCKET Client, Server;
    HANDLE Dup = NULL, Thread;
    CLOSE_CONTEXT Context;
    TEST_POLL_INFO In, Out;
    NTSTATUS Status, Final;
    DWORD Start, Elapsed;

    if (!TcpPair(&Client, &Server))
    {
        skip("no TCP pair: %d\n", WSAGetLastError());
        return;
    }
    if (Duplicate)
        ok(DuplicateHandle(GetCurrentProcess(), (HANDLE)Client, GetCurrentProcess(), &Dup, 0, FALSE, DUPLICATE_SAME_ACCESS),
           "DuplicateHandle failed %lu\n", GetLastError());

    InitPoll(&In, 1, PollOnDuplicate ? Dup : (HANDLE)Client, NULL);
    In.Handles[0].Events = AFD_EVENT_RECEIVE;
    In.Timeout.QuadPart = -3000 * 10000;

    Context.Socket = Client;
    Context.Delay = 300;
    Thread = CreateThread(NULL, 0, CloseThread, &Context, 0, NULL);
    Start = GetTickCount();
    Status = DoPoll(PollOnDuplicate ? Dup : (HANDLE)Server, &In, POLL_SIZE(1), &Out, POLL_SIZE(1), 5000, &Final);
    Elapsed = GetTickCount() - Start;
    trace("close during poll (duplicate %d, poll on duplicate %d): status %lx final %lx after %lu ms\n",
          Duplicate, PollOnDuplicate, Status, Final, Elapsed);
    ok(Status == STATUS_PENDING, "status %lx\n", Status);
    if (!Duplicate)
    {
        /* The last handle went away. Windows completes with success, ReactOS cancels */
        ok(Final != STATUS_PENDING && Final != STATUS_TIMEOUT, "final %lx\n", Final);
        ok(Elapsed < 2000, "poll took %lu ms\n", Elapsed);
    }
    else
    {
        /* The socket stays open through the other handle, so the poll waits for its timeout */
        ok(Final == STATUS_TIMEOUT, "final %lx\n", Final);
        ok(Elapsed >= 2500, "poll took %lu ms\n", Elapsed);
    }
    WaitForSingleObject(Thread, 5000);
    CloseHandle(Thread);
    if (Dup)
        CloseHandle(Dup);
    closesocket(Server);
}

START_TEST(select)
{
    WSADATA WsaData;
    SOCKET Client, Server;

    ok(WSAStartup(MAKEWORD(2, 2), &WsaData) == 0, "WSAStartup failed\n");
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (!TcpPair(&Client, &Server))
    {
        skip("no TCP pair: %d\n", WSAGetLastError());
    }
    else
    {
        TestParameters(Client);
        TestMaximumCount(Client);
        TestHandles(Client);
        closesocket(Client);
        closesocket(Server);
    }

    TestCloseDuringPoll(FALSE, FALSE);
    TestCloseDuringPoll(TRUE, FALSE);
    TestCloseDuringPoll(TRUE, TRUE);

    if (TcpPair(&Client, &Server))
    {
        TestUnsafeRequests(Client);
        closesocket(Client);
        closesocket(Server);
    }

    CloseHandle(Event);
    WSACleanup();
}
