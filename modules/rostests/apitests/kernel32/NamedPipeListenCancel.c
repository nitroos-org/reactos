/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for pending ConnectNamedPipe requests that end while clients connect
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A pending ConnectNamedPipe (FSCTL_PIPE_LISTEN) ends in one of several ways: a client
 * connects, the server disconnects or closes the instance, the request is cancelled,
 * or the thread that issued it exits. The first part checks the outcome of each. The
 * second part runs them against each other: threads with pending listens on many
 * instances exit or are terminated while clients connect, handles are closed and
 * requests cancelled, in this process and in a child process that is killed.
 * NAMEDPIPE_LISTEN_ROUNDS sets the number of rounds (default 4).
 */

#include "precomp.h"

#define INSTANCES_PER_THREAD 6
#define LISTEN_THREADS 6
#define CLIENT_THREADS 3
#define INSTANCES (INSTANCES_PER_THREAD * LISTEN_THREADS)

typedef struct _LISTEN_SLOT
{
    HANDLE Pipe;            /* owned by whoever swaps it to NULL */
    OVERLAPPED Overlapped;
    BOOL Port;              /* bound to the completion port, no event */
    BOOL Pending;
} LISTEN_SLOT, *PLISTEN_SLOT;

typedef struct _ROUND
{
    WCHAR Name[64];
    LISTEN_SLOT Slot[INSTANCES];
    HANDLE Port;
    HANDLE Ready[LISTEN_THREADS];
    HANDLE Go;
    volatile LONG Stop;
    ULONG Seed;
} ROUND, *PROUND;

typedef struct _LISTEN_THREAD
{
    PROUND Round;
    ULONG Index;
} LISTEN_THREAD, *PLISTEN_THREAD;

typedef BOOL WINAPI FN_CancelIoEx(_In_ HANDLE hFile, _In_opt_ LPOVERLAPPED lpOverlapped);

static FN_CancelIoEx *pCancelIoEx;
static ULONG g_Counter;

static
ULONG
NextRandom(PULONG Seed)
{
    *Seed = *Seed * 1103515245 + 12345;
    return (*Seed >> 16) & 0x7fff;
}

static
VOID
NewName(PWSTR Name, SIZE_T Count, PCWSTR Kind)
{
    StringCchPrintfW(Name, Count, L"\\\\.\\pipe\\rostest_lcancel_%ls_%lu_%lu",
                     Kind, GetCurrentProcessId(), InterlockedIncrement((PLONG)&g_Counter));
}

static
HANDLE
CreateInstance(PCWSTR Name)
{
    return CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                            PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
                            256, 256, 0, NULL);
}

/* Starts a ConnectNamedPipe that has to stay pending */
static
BOOL
StartListen(HANDLE Pipe, LPOVERLAPPED Overlapped)
{
    BOOL Ret;

    SetLastError(0xdeadbeef);
    Ret = ConnectNamedPipe(Pipe, Overlapped);
    return !Ret && GetLastError() == ERROR_IO_PENDING;
}

static
DWORD
ListenResult(HANDLE Pipe, LPOVERLAPPED Overlapped)
{
    DWORD Bytes;

    if (WaitForSingleObject(Overlapped->hEvent, 5000) != WAIT_OBJECT_0)
        return WAIT_TIMEOUT;
    if (GetOverlappedResult(Pipe, Overlapped, &Bytes, FALSE))
        return ERROR_SUCCESS;
    return GetLastError();
}

/* Issues one listen from a thread that then returns */
typedef struct _ONE_LISTEN
{
    HANDLE Pipe;
    LPOVERLAPPED Overlapped;
    BOOL Started;
    HANDLE Wait;
} ONE_LISTEN, *PONE_LISTEN;

static
DWORD
WINAPI
OneListenThread(PVOID Param)
{
    PONE_LISTEN Listen = Param;

    Listen->Started = StartListen(Listen->Pipe, Listen->Overlapped);
    if (Listen->Wait)
        WaitForSingleObject(Listen->Wait, INFINITE);
    return 0;
}

static
VOID
TestSingle(VOID)
{
    WCHAR Name[64];
    HANDLE Pipe, Client, Thread;
    OVERLAPPED Overlapped;
    ONE_LISTEN Listen;
    DWORD Result;

    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(Overlapped.hEvent != NULL, "CreateEvent failed with %lu\n", GetLastError());
    if (!Overlapped.hEvent) return;

    /* The thread that issued the listen exits: the request is cancelled */
    NewName(Name, _countof(Name), L"single");
    Pipe = CreateInstance(Name);
    ok(Pipe != INVALID_HANDLE_VALUE, "CreateNamedPipe failed with %lu\n", GetLastError());
    if (Pipe == INVALID_HANDLE_VALUE) goto Done;
    Listen.Pipe = Pipe;
    Listen.Overlapped = &Overlapped;
    Listen.Started = FALSE;
    Listen.Wait = NULL;
    Thread = CreateThread(NULL, 0, OneListenThread, &Listen, 0, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Thread)
    {
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
        ok(Listen.Started, "listen did not pend\n");
        Result = ListenResult(Pipe, &Overlapped);
        ok(Result == ERROR_OPERATION_ABORTED, "after thread exit: %lu\n", Result);

        /* The instance listens again and takes a client */
        ResetEvent(Overlapped.hEvent);
        ok(StartListen(Pipe, &Overlapped), "second listen did not pend: %lu\n", GetLastError());
        Client = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        ok(Client != INVALID_HANDLE_VALUE, "CreateFile failed with %lu\n", GetLastError());
        Result = ListenResult(Pipe, &Overlapped);
        ok(Result == ERROR_SUCCESS, "after connect: %lu\n", Result);
        if (Client != INVALID_HANDLE_VALUE) CloseHandle(Client);
    }
    CloseHandle(Pipe);

    /* The thread is terminated while its listen is pending */
    NewName(Name, _countof(Name), L"single");
    Pipe = CreateInstance(Name);
    ok(Pipe != INVALID_HANDLE_VALUE, "CreateNamedPipe failed with %lu\n", GetLastError());
    if (Pipe == INVALID_HANDLE_VALUE) goto Done;
    ResetEvent(Overlapped.hEvent);
    Listen.Started = FALSE;
    Listen.Pipe = Pipe;
    Listen.Wait = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, OneListenThread, &Listen, 0, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Thread)
    {
        while (!Listen.Started && WaitForSingleObject(Thread, 10) == WAIT_TIMEOUT);
        ok(Listen.Started, "listen did not pend\n");
        TerminateThread(Thread, 1);
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
        Result = ListenResult(Pipe, &Overlapped);
        ok(Result == ERROR_OPERATION_ABORTED, "after TerminateThread: %lu\n", Result);
    }
    if (Listen.Wait) CloseHandle(Listen.Wait);
    CloseHandle(Pipe);

    /* DisconnectNamedPipe ends a pending listen */
    NewName(Name, _countof(Name), L"single");
    Pipe = CreateInstance(Name);
    ok(Pipe != INVALID_HANDLE_VALUE, "CreateNamedPipe failed with %lu\n", GetLastError());
    if (Pipe == INVALID_HANDLE_VALUE) goto Done;
    ResetEvent(Overlapped.hEvent);
    ok(StartListen(Pipe, &Overlapped), "listen did not pend: %lu\n", GetLastError());
    ok(DisconnectNamedPipe(Pipe), "DisconnectNamedPipe failed with %lu\n", GetLastError());
    Result = ListenResult(Pipe, &Overlapped);
    ok(Result == ERROR_PIPE_NOT_CONNECTED, "after disconnect: %lu\n", Result);

    /* CancelIo ends it */
    ResetEvent(Overlapped.hEvent);
    ok(StartListen(Pipe, &Overlapped), "listen did not pend: %lu\n", GetLastError());
    ok(CancelIo(Pipe), "CancelIo failed with %lu\n", GetLastError());
    Result = ListenResult(Pipe, &Overlapped);
    ok(Result == ERROR_OPERATION_ABORTED, "after CancelIo: %lu\n", Result);

    /* Closing the instance ends it; the event is still ours */
    ResetEvent(Overlapped.hEvent);
    ok(StartListen(Pipe, &Overlapped), "listen did not pend: %lu\n", GetLastError());
    CloseHandle(Pipe);
    Result = WaitForSingleObject(Overlapped.hEvent, 5000);
    ok(Result == WAIT_OBJECT_0, "listen still pending after close: %lu\n", Result);
    /* Internal holds the NTSTATUS in its low 32 bits */
    ok((NTSTATUS)Overlapped.Internal == STATUS_PIPE_BROKEN ||
       (NTSTATUS)Overlapped.Internal == STATUS_CANCELLED,
       "after close: 0x%lx\n", (ULONG)Overlapped.Internal);

Done:
    CloseHandle(Overlapped.hEvent);
}

static
PLISTEN_SLOT
TakeSlot(PROUND Round, ULONG Index, HANDLE *Pipe)
{
    *Pipe = InterlockedExchangePointer(&Round->Slot[Index].Pipe, NULL);
    return *Pipe ? &Round->Slot[Index] : NULL;
}

static
DWORD
WINAPI
StressListenThread(PVOID Param)
{
    PLISTEN_THREAD Listen = Param;
    PROUND Round = Listen->Round;
    ULONG i, First = Listen->Index * INSTANCES_PER_THREAD;
    PLISTEN_SLOT Slot;

    for (i = First; i < First + INSTANCES_PER_THREAD; i++)
    {
        Slot = &Round->Slot[i];
        Slot->Pending = StartListen(Slot->Pipe, &Slot->Overlapped);
    }
    SetEvent(Round->Ready[Listen->Index]);
    WaitForSingleObject(Round->Go, INFINITE);

    /* Some threads exit at once, some after a moment; the others are terminated */
    if (Listen->Index % 3 == 1)
        Sleep(NextRandom(&Round->Seed) % 4);
    else if (Listen->Index % 3 == 2)
        Sleep(INFINITE);
    return 0;
}

static
DWORD
WINAPI
StressClientThread(PVOID Param)
{
    PROUND Round = Param;
    HANDLE Client;

    while (!Round->Stop)
    {
        Client = CreateFileW(Round->Name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                             OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (Client != INVALID_HANDLE_VALUE)
            CloseHandle(Client);
        else
            YieldProcessor();
    }
    return 0;
}

/* Closes, disconnects and cancels instances while the listeners go away */
static
DWORD
WINAPI
StressCloserThread(PVOID Param)
{
    PROUND Round = Param;
    ULONG i, n;
    HANDLE Pipe;

    for (n = 0; n < INSTANCES; n++)
    {
        i = NextRandom(&Round->Seed) % INSTANCES;
        switch (NextRandom(&Round->Seed) % 4)
        {
            case 0:
                if (TakeSlot(Round, i, &Pipe)) CloseHandle(Pipe);
                break;
            case 1:
                Pipe = Round->Slot[i].Pipe;
                if (Pipe) DisconnectNamedPipe(Pipe);
                break;
            case 2:
                Pipe = Round->Slot[i].Pipe;
                if (Pipe && pCancelIoEx) pCancelIoEx(Pipe, NULL);
                break;
            default:
                Sleep(0);
                break;
        }
    }
    return 0;
}

/* One round: returns FALSE if the setup failed */
static
BOOL
StressRound(PROUND Round, BOOL Child)
{
    LISTEN_THREAD Listen[LISTEN_THREADS];
    HANDLE ListenThread[LISTEN_THREADS], ClientThread[CLIENT_THREADS], Closer = NULL;
    ULONG i, Packets = 0, Expected = 0;
    PLISTEN_SLOT Slot;
    HANDLE Pipe;
    DWORD Bytes;
    ULONG_PTR Key;
    LPOVERLAPPED Overlapped;

    NewName(Round->Name, _countof(Round->Name), Child ? L"child" : L"stress");
    Round->Port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    Round->Go = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!Round->Port || !Round->Go) return FALSE;

    for (i = 0; i < INSTANCES; i++)
    {
        Slot = &Round->Slot[i];
        Slot->Pipe = CreateInstance(Round->Name);
        if (Slot->Pipe == INVALID_HANDLE_VALUE) return FALSE;
        /* Every third instance only reports to the completion port */
        Slot->Port = (i % 3 == 0);
        if (Slot->Port)
        {
            if (!CreateIoCompletionPort(Slot->Pipe, Round->Port, i, 0)) return FALSE;
        }
        else
        {
            Slot->Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (!Slot->Overlapped.hEvent) return FALSE;
        }
    }

    for (i = 0; i < LISTEN_THREADS; i++)
    {
        Round->Ready[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        Listen[i].Round = Round;
        Listen[i].Index = i;
        ListenThread[i] = CreateThread(NULL, 0, StressListenThread, &Listen[i], 0, NULL);
        if (!ListenThread[i]) return FALSE;
    }
    WaitForMultipleObjects(LISTEN_THREADS, Round->Ready, TRUE, INFINITE);

    for (i = 0; i < CLIENT_THREADS; i++)
        ClientThread[i] = CreateThread(NULL, 0, StressClientThread, Round, 0, NULL);
    if (Round->Seed & 1)
        Closer = CreateThread(NULL, 0, StressCloserThread, Round, 0, NULL);

    /* Everything at once */
    SetEvent(Round->Go);
    for (i = 0; i < LISTEN_THREADS; i++)
    {
        if (i % 3 == 2) TerminateThread(ListenThread[i], 1);
    }

    /* A child just sits there until it is killed */
    if (Child) return TRUE;

    WaitForMultipleObjects(LISTEN_THREADS, ListenThread, TRUE, INFINITE);
    if (Closer)
    {
        WaitForSingleObject(Closer, INFINITE);
        CloseHandle(Closer);
    }
    Round->Stop = TRUE;
    for (i = 0; i < CLIENT_THREADS; i++)
    {
        if (!ClientThread[i]) continue;
        WaitForSingleObject(ClientThread[i], INFINITE);
        CloseHandle(ClientThread[i]);
    }

    /* Close the rest: every request that was pending has to end, none twice */
    for (i = 0; i < INSTANCES; i++)
    {
        Slot = TakeSlot(Round, i, &Pipe);
        if (Slot) CloseHandle(Pipe);
        Slot = &Round->Slot[i];
        if (!Slot->Pending) continue;
        if (Slot->Port)
        {
            Expected++;
            continue;
        }
        ok(WaitForSingleObject(Slot->Overlapped.hEvent, 5000) == WAIT_OBJECT_0,
           "instance %lu: listen still pending\n", i);
    }
    while (Packets < Expected &&
           (GetQueuedCompletionStatus(Round->Port, &Bytes, &Key, &Overlapped, 5000) || Overlapped))
    {
        ok(Key < INSTANCES && Overlapped == &Round->Slot[Key].Overlapped,
           "packet for key %Iu, overlapped %p\n", Key, Overlapped);
        Packets++;
    }
    ok(Packets == Expected, "%lu of %lu port-only listens completed\n", Packets, Expected);
    ok(!GetQueuedCompletionStatus(Round->Port, &Bytes, &Key, &Overlapped, 0) && !Overlapped,
       "extra packet for key %Iu\n", Key);

    for (i = 0; i < LISTEN_THREADS; i++)
    {
        CloseHandle(ListenThread[i]);
        CloseHandle(Round->Ready[i]);
    }
    for (i = 0; i < INSTANCES; i++)
    {
        if (Round->Slot[i].Overlapped.hEvent) CloseHandle(Round->Slot[i].Overlapped.hEvent);
    }
    CloseHandle(Round->Go);
    CloseHandle(Round->Port);
    return TRUE;
}

static
VOID
RunChild(PCSTR ReadyName)
{
    PROUND Round;
    HANDLE Ready;

    Ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, ReadyName);
    Round = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Round));
    if (!Ready || !Round) ExitProcess(2);
    Round->Seed = GetTickCount() ^ GetCurrentProcessId();
    if (!StressRound(Round, TRUE)) ExitProcess(3);
    SetEvent(Ready);
    /* Some children leave by themselves with everything pending */
    if (Round->Seed & 2)
    {
        Sleep(NextRandom(&Round->Seed) % 8);
        ExitProcess(0);
    }
    Sleep(INFINITE);
}

static
VOID
KillChild(ULONG *Seed)
{
    WCHAR FileName[MAX_PATH];
    WCHAR CommandLine[MAX_PATH + 96];
    CHAR ReadyName[64];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    HANDLE Ready, Wait[2];
    DWORD Result;

    StringCbPrintfA(ReadyName, sizeof(ReadyName), "rostest_lcancel_ready_%lu_%lu",
                    GetCurrentProcessId(), InterlockedIncrement((PLONG)&g_Counter));
    Ready = CreateEventA(NULL, TRUE, FALSE, ReadyName);
    ok(Ready != NULL, "CreateEvent failed with %lu\n", GetLastError());
    if (!Ready) return;

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine),
                    L"\"%ls\" NamedPipeListenCancel child %hs", FileName, ReadyName);
    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, 0,
                        NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        CloseHandle(Ready);
        return;
    }
    CloseHandle(ProcessInfo.hThread);

    Wait[0] = Ready;
    Wait[1] = ProcessInfo.hProcess;
    Result = WaitForMultipleObjects(2, Wait, FALSE, 30000);
    ok(Result == WAIT_OBJECT_0, "child not ready: %lu\n", Result);
    if (Result == WAIT_OBJECT_0)
    {
        Sleep(NextRandom(Seed) % 6);
        TerminateProcess(ProcessInfo.hProcess, 1);
    }
    else if (Result != WAIT_OBJECT_0 + 1)
    {
        TerminateProcess(ProcessInfo.hProcess, 1);
    }
    Result = WaitForSingleObject(ProcessInfo.hProcess, 60000);
    ok(Result == WAIT_OBJECT_0, "child did not exit: %lu\n", Result);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(Ready);
}

START_TEST(NamedPipeListenCancel)
{
    int argc;
    char **argv;
    CHAR Value[16];
    ULONG Rounds = 4, i, Seed;
    PROUND Round;

    pCancelIoEx = (FN_CancelIoEx *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CancelIoEx");

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        RunChild(argv[3]);
        return;
    }

    TestSingle();

    if (GetEnvironmentVariableA("NAMEDPIPE_LISTEN_ROUNDS", Value, sizeof(Value)))
        Rounds = strtoul(Value, NULL, 10);
    Seed = GetTickCount();
    for (i = 0; i < Rounds; i++)
    {
        /* Terminated listener threads leave their round behind: never reused */
        Round = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Round));
        if (!Round) break;
        Round->Seed = Seed + i;
        if (!StressRound(Round, FALSE))
        {
            skip("round %lu: setup failed with %lu\n", i, GetLastError());
            break;
        }
        KillChild(&Seed);
    }
    trace("%lu rounds\n", i);
}
