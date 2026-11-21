/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for waiting on an I/O completion port handle (measured on Windows Server 2022)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A completion port handle can be waited on with the generic wait functions: it is signalled while the port
 * holds at least one packet, and a wait never takes a packet away.
 * https://learn.microsoft.com/windows/win32/fileio/i-o-completion-ports
 */

#include "precomp.h"

typedef struct { LONG Depth; } PORT_BASIC;
typedef NTSTATUS (NTAPI *PFN_QueryIoCompletion)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_WaitMultiple)(ULONG, HANDLE *, ULONG, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *PFN_SignalAndWait)(HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER);

typedef BOOL (WINAPI *PFN_GetQueuedCompletionStatusEx)(HANDLE, LPOVERLAPPED_ENTRY, ULONG, PULONG, DWORD, BOOL);
typedef BOOL (WINAPI *PFN_SetFileCompletionNotificationModes)(HANDLE, UCHAR);

#ifndef FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#endif

static PFN_GetQueuedCompletionStatusEx pGetQueuedCompletionStatusEx;
static PFN_SetFileCompletionNotificationModes pSetFileCompletionNotificationModes;
static PFN_QueryIoCompletion pQueryIoCompletion;
static PFN_WaitMultiple pWaitMultiple;
static PFN_SignalAndWait pSignalAndWait;

typedef struct
{
    HANDLE Handles[2];
    DWORD Count;
    DWORD Timeout;
    HANDLE Ready;
    volatile DWORD Result;
    volatile LONG Done;
    BOOL UseGqcs;
} WAITER;

static LONG Depth(HANDLE Port)
{
    PORT_BASIC Info = { -99 };
    ULONG Length = 0;
    NTSTATUS Status = pQueryIoCompletion(Port, 0, &Info, sizeof(Info), &Length);
    ok(Status == STATUS_SUCCESS, "NtQueryIoCompletion returned %lx\n", Status);
    return Info.Depth;
}

/* returns the key of the removed packet, or -1 */
static LONG_PTR Take(HANDLE Port, DWORD Timeout)
{
    DWORD Bytes;
    ULONG_PTR Key = 0;
    OVERLAPPED *Overlapped;

    if (!GetQueuedCompletionStatus(Port, &Bytes, &Key, &Overlapped, Timeout))
        return -1;
    return (LONG_PTR)Key;
}

static void Drain(HANDLE Port)
{
    while (Take(Port, 0) != -1)
        ;
}

static DWORD WINAPI WaiterThread(void *Param)
{
    WAITER *Waiter = Param;

    SetEvent(Waiter->Ready);
    if (Waiter->UseGqcs)
    {
        DWORD Bytes;
        ULONG_PTR Key;
        OVERLAPPED *Overlapped;

        Waiter->Result = GetQueuedCompletionStatus(Waiter->Handles[0], &Bytes, &Key, &Overlapped, Waiter->Timeout);
    }
    else
    {
        Waiter->Result = WaitForMultipleObjects(Waiter->Count, Waiter->Handles, FALSE, Waiter->Timeout);
    }
    InterlockedExchange(&Waiter->Done, 1);
    return 0;
}

static HANDLE StartWaiter(WAITER *Waiter, BOOL UseGqcs, DWORD Count, HANDLE First, HANDLE Second)
{
    HANDLE Thread;

    Waiter->Handles[0] = First;
    Waiter->Handles[1] = Second;
    Waiter->Count = Count;
    Waiter->Timeout = 4000;
    Waiter->Done = 0;
    Waiter->Result = 0xdeadbeef;
    Waiter->UseGqcs = UseGqcs;
    Waiter->Ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, WaiterThread, Waiter, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    WaitForSingleObject(Waiter->Ready, 5000);
    Sleep(150); /* let it block */
    return Thread;
}

static void FinishWaiter(WAITER *Waiter, HANDLE Thread)
{
    WaitForSingleObject(Thread, 6000);
    CloseHandle(Thread);
    CloseHandle(Waiter->Ready);
}

static void TestEmpty(HANDLE Port)
{
    HANDLE Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE Handles[2] = { Port, Event };
    LARGE_INTEGER Zero = { { 0 } };
    DWORD Start, Elapsed, Ret;
    NTSTATUS Status;

    ok_dec(WaitForSingleObject(Port, 0), WAIT_TIMEOUT);
    Start = GetTickCount();
    Ret = WaitForSingleObject(Port, 300);
    Elapsed = GetTickCount() - Start;
    ok_dec(Ret, WAIT_TIMEOUT);
    ok(Elapsed >= 250, "empty port: the wait lasted %lu ms\n", Elapsed);
    ok_dec(Depth(Port), 0);
    ok_dec(WaitForMultipleObjects(2, Handles, FALSE, 0), WAIT_TIMEOUT);

    /* waiting for all objects is refused when a port is among them */
    SetLastError(0xdeadbeef);
    ok_dec(WaitForMultipleObjects(2, Handles, TRUE, 0), WAIT_FAILED);
    ok_dec(GetLastError(), ERROR_INVALID_HANDLE);
    Status = pWaitMultiple(2, Handles, 0 /* WaitAll */, FALSE, &Zero);
    ok_hex(Status, STATUS_INVALID_HANDLE);
    Status = pWaitMultiple(2, Handles, 1 /* WaitAny */, FALSE, &Zero);
    ok_hex(Status, STATUS_TIMEOUT);

    SetLastError(0xdeadbeef);
    ok(Take(Port, 0) == -1, "an empty port returned a packet\n");
    ok_dec(GetLastError(), WAIT_TIMEOUT);
    CloseHandle(Event);
}

static void TestPackets(HANDLE Port)
{
    HANDLE Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    HANDLE Pair[2];
    HANDLE Other = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    LARGE_INTEGER Zero = { { 0 } };
    NTSTATUS Status;

    /* one packet: signalled, and the wait leaves it in the port */
    ok(PostQueuedCompletionStatus(Port, 5, 11, NULL), "post failed: %lu\n", GetLastError());
    ok_dec(Depth(Port), 1);
    ok_dec(WaitForSingleObject(Port, 0), WAIT_OBJECT_0);
    ok_dec(WaitForSingleObject(Port, 0), WAIT_OBJECT_0);
    ok_dec(Depth(Port), 1);
    ok_hex(pWaitMultiple(1, &Port, 1, TRUE, &Zero), STATUS_SUCCESS);
    ok_dec(WaitForSingleObjectEx(Port, 50, TRUE), WAIT_OBJECT_0);
    ok_dec(Take(Port, 0), 11);
    ok_dec(WaitForSingleObject(Port, 0), WAIT_TIMEOUT);
    ok_dec(Depth(Port), 0);

    /* two packets: signalled until the last one is taken */
    PostQueuedCompletionStatus(Port, 1, 21, NULL);
    PostQueuedCompletionStatus(Port, 2, 22, NULL);
    ok_dec(Depth(Port), 2);
    ok_dec(WaitForSingleObject(Port, 0), WAIT_OBJECT_0);
    ok_dec(Take(Port, 0), 21);
    ok_dec(WaitForSingleObject(Port, 0), WAIT_OBJECT_0);
    ok_dec(Take(Port, 0), 22);
    ok_dec(WaitForSingleObject(Port, 0), WAIT_TIMEOUT);

    /* the index of the first signalled object, in handle order */
    PostQueuedCompletionStatus(Port, 0, 31, NULL);
    Pair[0] = Event;
    Pair[1] = Port;
    ok_dec(WaitForMultipleObjects(2, Pair, FALSE, 0), WAIT_OBJECT_0 + 1);
    SetEvent(Event);
    ok_dec(WaitForMultipleObjects(2, Pair, FALSE, 0), WAIT_OBJECT_0);
    ResetEvent(Event);
    Pair[0] = Other;
    ok_dec(WaitForMultipleObjects(2, Pair, FALSE, 0), WAIT_OBJECT_0 + 1);

    /* SignalObjectAndWait: the port can be waited on, not signalled */
    ok_dec(SignalObjectAndWait(Event, Port, 0, FALSE), WAIT_OBJECT_0);
    ok_dec(WaitForSingleObject(Event, 0), WAIT_OBJECT_0); /* the event was set (auto-reset: now clear) */
    Status = pSignalAndWait(Port, Event, FALSE, &Zero);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    SetLastError(0xdeadbeef);
    ok_dec(SignalObjectAndWait(Port, Event, 0, FALSE), WAIT_FAILED);
    ok_dec(GetLastError(), ERROR_INVALID_HANDLE);
    Drain(Port);
    ok_dec(SignalObjectAndWait(Event, Port, 150, FALSE), WAIT_TIMEOUT);

    CloseHandle(Other);
    CloseHandle(Event);
}

static void TestWaiters(HANDLE Port)
{
    WAITER Waiter[3];
    HANDLE Thread[3];
    HANDLE Other = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    int i, Finished;

    /* three waiters, one packet: all are released, the packet stays */
    for (i = 0; i < 3; i++)
        Thread[i] = StartWaiter(&Waiter[i], FALSE, 1, Port, NULL);
    Finished = 0;
    for (i = 0; i < 3; i++)
        Finished += Waiter[i].Done;
    ok_dec(Finished, 0);
    PostQueuedCompletionStatus(Port, 0, 41, NULL);
    for (i = 0; i < 3; i++)
    {
        FinishWaiter(&Waiter[i], Thread[i]);
        ok_dec(Waiter[i].Done, 1);
        ok_dec(Waiter[i].Result, WAIT_OBJECT_0);
    }
    ok_dec(Depth(Port), 1);
    ok_dec(Take(Port, 0), 41);

    /* a thread that waits for a packet takes it before a thread that waits for the handle, in either start order */
    for (i = 0; i < 2; i++)
    {
        WAITER Wait, Gqcs;
        HANDLE ThreadWait, ThreadGqcs;

        if (i == 0)
        {
            ThreadGqcs = StartWaiter(&Gqcs, TRUE, 1, Port, NULL);
            ThreadWait = StartWaiter(&Wait, FALSE, 1, Port, NULL);
        }
        else
        {
            ThreadWait = StartWaiter(&Wait, FALSE, 1, Port, NULL);
            ThreadGqcs = StartWaiter(&Gqcs, TRUE, 1, Port, NULL);
        }
        PostQueuedCompletionStatus(Port, 0, 51, NULL);
        WaitForSingleObject(ThreadGqcs, 3000);
        Sleep(200);
        ok_dec(Gqcs.Done, 1);
        ok_dec(Gqcs.Result, 1);
        ok_dec(Wait.Done, 0);
        ok_dec(Depth(Port), 0);
        /* the next packet is not wanted by anyone but the waiter on the handle: it is released, the packet stays */
        PostQueuedCompletionStatus(Port, 0, 52, NULL);
        FinishWaiter(&Wait, ThreadWait);
        ok_dec(Wait.Done, 1);
        ok_dec(Wait.Result, WAIT_OBJECT_0);
        ok_dec(Depth(Port), 1);
        FinishWaiter(&Gqcs, ThreadGqcs);
        Drain(Port);
    }

    /* a blocked wait on two ports ends with the index of the one that got the packet */
    {
        WAITER Wait;
        HANDLE ThreadWait = StartWaiter(&Wait, FALSE, 2, Port, Other);

        PostQueuedCompletionStatus(Other, 0, 61, NULL);
        FinishWaiter(&Wait, ThreadWait);
        ok_dec(Wait.Done, 1);
        ok_dec(Wait.Result, WAIT_OBJECT_0 + 1);
        Drain(Other);
    }
    CloseHandle(Other);
}

static void TestFile(HANDLE Port)
{
    WCHAR Path[MAX_PATH];
    HANDLE File;
    OVERLAPPED Overlapped = { 0 };
    DWORD Written;
    OVERLAPPED *Completed;
    ULONG_PTR Key;
    DWORD Bytes;
    BOOL Ok;

    GetTempPathW(MAX_PATH, Path);
    StringCchCatW(Path, MAX_PATH, L"iocpwait-test.bin");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFile failed: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    ok(CreateIoCompletionPort(File, Port, 77, 0) == Port, "associate failed: %lu\n", GetLastError());
    ok_dec(WaitForSingleObject(Port, 0), WAIT_TIMEOUT);
    Ok = WriteFile(File, "abcdefgh", 8, &Written, &Overlapped);
    ok(Ok || GetLastError() == ERROR_IO_PENDING, "WriteFile: %d, %lu\n", Ok, GetLastError());
    ok_dec(WaitForSingleObject(Port, 2000), WAIT_OBJECT_0);
    ok_dec(Depth(Port), 1);
    Ok = GetQueuedCompletionStatus(Port, &Bytes, &Key, &Completed, 0);
    ok(Ok, "GetQueuedCompletionStatus failed: %lu\n", GetLastError());
    ok_dec(Bytes, 8);
    ok_dec(Key, 77);
    ok(Completed == &Overlapped, "wrong OVERLAPPED %p\n", Completed);
    ok_dec(WaitForSingleObject(Port, 0), WAIT_TIMEOUT);

    /* a completion that skips the port leaves it unsignalled */
    ok(pSetFileCompletionNotificationModes(File, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS), "SFCNM failed: %lu\n", GetLastError());
    Ok = WriteFile(File, "abcdefgh", 8, &Written, &Overlapped);
    if (Ok)
        ok_dec(WaitForSingleObject(Port, 100), WAIT_TIMEOUT);
    else
        skip("the write did not complete at once\n");
    Drain(Port);
    CloseHandle(File);
}

static void TestHandles(HANDLE Port)
{
    HANDLE Dup;
    HANDLE Port1 = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    OVERLAPPED_ENTRY Entries[4];
    ULONG Removed;
    BOOL Ok;

    /* SYNCHRONIZE is required for the wait */
    PostQueuedCompletionStatus(Port, 0, 71, NULL);
    ok(DuplicateHandle(GetCurrentProcess(), Port, GetCurrentProcess(), &Dup, 0x3, FALSE, 0), "duplicate failed\n");
    SetLastError(0xdeadbeef);
    ok_dec(WaitForSingleObject(Dup, 0), WAIT_FAILED);
    ok_dec(GetLastError(), ERROR_ACCESS_DENIED);
    CloseHandle(Dup);
    Drain(Port);

    /* a limit of one running thread does not change the signalled state */
    PostQueuedCompletionStatus(Port1, 0, 1, NULL);
    PostQueuedCompletionStatus(Port1, 0, 2, NULL);
    ok_dec(WaitForSingleObject(Port1, 0), WAIT_OBJECT_0);
    ok_dec(Take(Port1, 0), 1);
    ok_dec(WaitForSingleObject(Port1, 0), WAIT_OBJECT_0);
    ok_dec(Depth(Port1), 1);
    ok_dec(Take(Port1, 0), 2);
    ok_dec(WaitForSingleObject(Port1, 0), WAIT_TIMEOUT);
    CloseHandle(Port1);

    /* a batch removal leaves the port signalled while packets remain */
    PostQueuedCompletionStatus(Port, 0, 91, NULL);
    PostQueuedCompletionStatus(Port, 0, 92, NULL);
    PostQueuedCompletionStatus(Port, 0, 93, NULL);
    Removed = 0;
    Ok = pGetQueuedCompletionStatusEx(Port, Entries, 2, &Removed, 0, FALSE);
    ok(Ok, "GetQueuedCompletionStatusEx failed: %lu\n", GetLastError());
    ok_dec(Removed, 2);
    ok_dec(WaitForSingleObject(Port, 0), WAIT_OBJECT_0);
    Ok = pGetQueuedCompletionStatusEx(Port, Entries, 4, &Removed, 0, FALSE);
    ok(Ok, "GetQueuedCompletionStatusEx failed: %lu\n", GetLastError());
    ok_dec(Removed, 1);
    ok_dec(WaitForSingleObject(Port, 0), WAIT_TIMEOUT);
}

START_TEST(IoCompletionWait)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    HANDLE Port;

    pQueryIoCompletion = (PVOID)GetProcAddress(Ntdll, "NtQueryIoCompletion");
    pWaitMultiple = (PVOID)GetProcAddress(Ntdll, "NtWaitForMultipleObjects");
    pSignalAndWait = (PVOID)GetProcAddress(Ntdll, "NtSignalAndWaitForSingleObject");
    pGetQueuedCompletionStatusEx = (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetQueuedCompletionStatusEx");
    pSetFileCompletionNotificationModes = (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetFileCompletionNotificationModes");
    if (!pQueryIoCompletion || !pWaitMultiple || !pSignalAndWait ||
        !pGetQueuedCompletionStatusEx || !pSetFileCompletionNotificationModes)
    {
        skip("ntdll functions are missing\n");
        return;
    }

    /*
     * Above the processor count: this thread takes packets with GetQueuedCompletionStatus, which makes it a running thread of the
     * port. With the default limit (the processor count) a single processor is then full when this thread posts, the packet is
     * queued instead of handed to the waiting GetQueuedCompletionStatus thread, and the handle waiters are released. The rows here
     * are about the order between the two kinds of waiter, not about the limit (TestHandles has a port with a limit of one).
     */
    Port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 64);
    ok(Port != NULL, "CreateIoCompletionPort failed: %lu\n", GetLastError());
    if (!Port)
        return;

    TestEmpty(Port);
    TestPackets(Port);
    TestWaiters(Port);
    TestFile(Port);
    TestHandles(Port);

    CloseHandle(Port);
}
