/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for CancelSynchronousIo and NtCancelSynchronousIoFile
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#include <ndk/iofuncs.h>

typedef NTSTATUS (NTAPI *PFN_NtCancelSynchronousIoFile)(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
typedef BOOL (WINAPI *PFN_CancelSynchronousIo)(HANDLE);

static PFN_CancelSynchronousIo pCancelSynchronousIo;

typedef struct
{
    HANDLE Pipe;
    HANDLE Ready;
    BOOL Ret;
    DWORD Error;
    DWORD Read;
} READER;

static DWORD WINAPI ReaderThread(LPVOID Param)
{
    READER *Reader = Param;
    char Buffer[16];

    SetEvent(Reader->Ready);
    Reader->Ret = ReadFile(Reader->Pipe, Buffer, sizeof(Buffer), &Reader->Read, NULL);
    Reader->Error = GetLastError();
    return 0;
}

static HANDLE StartReader(HANDLE Pipe, READER *Reader, DWORD *ThreadId)
{
    HANDLE Thread;

    Reader->Pipe = Pipe;
    Reader->Ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    Reader->Ret = TRUE;
    Reader->Error = 0;
    Reader->Read = 0;
    Thread = CreateThread(NULL, 0, ReaderThread, Reader, 0, ThreadId);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Thread)
    {
        WaitForSingleObject(Reader->Ready, 5000);
        /* let it block inside ReadFile */
        Sleep(300);
    }
    return Thread;
}

static DWORD WINAPI SleepThread(LPVOID Param)
{
    Sleep(1500);
    return 0;
}


/* Nonpaged pool the allocations tagged "Io  " hold, in bytes, or (SIZE_T)-1 when the tags cannot be read */
static SIZE_T GetIoTagNonPagedBytes(void)
{
    ULONG Size = 0x40000, Length;
    PSYSTEM_POOLTAG_INFORMATION Info;
    SIZE_T Bytes = (SIZE_T)-1;
    NTSTATUS Status;
    ULONG i;

    for (;;)
    {
        Info = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Info)
            return Bytes;
        Status = NtQuerySystemInformation(SystemPoolTagInformation, Info, Size, &Length);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;
        HeapFree(GetProcessHeap(), 0, Info);
        Size = Length + 0x10000;
    }
    if (NT_SUCCESS(Status))
    {
        Bytes = 0;
        for (i = 0; i < Info->Count; i++)
        {
            if (Info->TagInfo[i].TagUlong == 0x20206F49) /* "Io  " */
                Bytes += Info->TagInfo[i].NonPagedUsed;
        }
    }
    HeapFree(GetProcessHeap(), 0, Info);
    return Bytes;
}

/*
 * A thread that cannot run its normal kernel APCs (here: suspended, so the suspend APC holds it at APC_LEVEL
 * inside the system call) keeps every cancel request queued. A caller that cancels in a loop must not queue
 * one nonpaged APC per call: Node's libuv did that, hundreds of megabytes in seconds. The request that is
 * queued still cancels the read when the thread runs again.
 */
static void TestCancelFlood(void)
{
    HANDLE Read, Write, Thread;
    READER Reader;
    DWORD ThreadId, i;
    SIZE_T Before, After;
    BOOL Ret;
    const DWORD Calls = 200000;

    ok(CreatePipe(&Read, &Write, NULL, 0), "CreatePipe failed with %lu\n", GetLastError());
    Thread = StartReader(Read, &Reader, &ThreadId);
    if (!Thread)
        return;

    ok(SuspendThread(Thread) != (DWORD)-1, "SuspendThread failed with %lu\n", GetLastError());
    Sleep(200);

    Before = GetIoTagNonPagedBytes();
    for (i = 0; i < Calls; i++)
    {
        Ret = pCancelSynchronousIo(Thread);
        if (!Ret)
            break;
    }
    ok(i == Calls, "CancelSynchronousIo failed after %lu calls, error %lu\n", i, GetLastError());
    After = GetIoTagNonPagedBytes();
    if (Before == (SIZE_T)-1 || After == (SIZE_T)-1)
        skip("the pool tags cannot be read\n");
    else
        ok(After < Before + 2 * 1024 * 1024, "%lu cancel requests of a suspended reader queued %Iu bytes of nonpaged pool\n",
           Calls, After - Before);

    ok(ResumeThread(Thread) != (DWORD)-1, "ResumeThread failed with %lu\n", GetLastError());
    ok(WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0, "the reader did not return\n");
    ok(!Reader.Ret && Reader.Error == ERROR_OPERATION_ABORTED, "flooded reader: ret %d, error %lu\n", Reader.Ret, Reader.Error);
    CloseHandle(Thread);
    CloseHandle(Read);
    CloseHandle(Write);
}

START_TEST(CancelSynchronousIo)
{
    PFN_NtCancelSynchronousIoFile pNtCancel;
    HANDLE Read, Write, Thread, NoTerminate, Event;
    READER Reader;
    DWORD ThreadId, Written, Count;
    IO_STATUS_BLOCK Wrong = { { 0 }, 0 }, Iosb;
    NTSTATUS Status;
    BOOL Ret;
    char Buffer[8];

    pNtCancel = (PFN_NtCancelSynchronousIoFile)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCancelSynchronousIoFile");
    pCancelSynchronousIo = (PFN_CancelSynchronousIo)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CancelSynchronousIo");
    if (!pNtCancel || !pCancelSynchronousIo)
    {
        ok(!is_reactos(), "CancelSynchronousIo or NtCancelSynchronousIoFile is not exported\n");
        skip("CancelSynchronousIo is not available\n");
        return;
    }

    /* an anonymous pipe has synchronous handles */
    ok(CreatePipe(&Read, &Write, NULL, 0), "CreatePipe failed with %lu\n", GetLastError());

    /* a thread blocked in ReadFile: its read fails with ERROR_OPERATION_ABORTED */
    Thread = StartReader(Read, &Reader, &ThreadId);
    if (!Thread)
        return;
    SetLastError(0xdeadbeef);
    Ret = pCancelSynchronousIo(Thread);
    ok(Ret, "CancelSynchronousIo failed with %lu\n", GetLastError());
    ok(WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0, "the reader did not return\n");
    ok(!Reader.Ret && Reader.Error == ERROR_OPERATION_ABORTED, "reader: ret %d, error %lu, %lu bytes\n",
       Reader.Ret, Reader.Error, Reader.Read);
    CloseHandle(Thread);

    /* nothing is left to cancel, also in a thread that exited */
    SetLastError(0xdeadbeef);
    Thread = CreateThread(NULL, 0, SleepThread, NULL, 0, NULL);
    Sleep(200);
    Ret = pCancelSynchronousIo(Thread);
    ok(!Ret && GetLastError() == ERROR_NOT_FOUND, "sleeping thread: ret %d, error %lu\n", Ret, GetLastError());
    WaitForSingleObject(Thread, 5000);
    SetLastError(0xdeadbeef);
    Ret = pCancelSynchronousIo(Thread);
    ok(!Ret && GetLastError() == ERROR_NOT_FOUND, "exited thread: ret %d, error %lu\n", Ret, GetLastError());
    CloseHandle(Thread);

    SetLastError(0xdeadbeef);
    Ret = pCancelSynchronousIo(GetCurrentThread());
    ok(!Ret && GetLastError() == ERROR_NOT_FOUND, "own thread: ret %d, error %lu\n", Ret, GetLastError());

    /* the handle needs THREAD_TERMINATE */
    Thread = StartReader(Read, &Reader, &ThreadId);
    if (!Thread)
        return;
    NoTerminate = OpenThread(THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, ThreadId);
    ok(NoTerminate != NULL, "OpenThread failed with %lu\n", GetLastError());
    if (NoTerminate)
    {
        SetLastError(0xdeadbeef);
        Ret = pCancelSynchronousIo(NoTerminate);
        ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "without THREAD_TERMINATE: ret %d, error %lu\n", Ret, GetLastError());
        CloseHandle(NoTerminate);
    }

    /* not a thread handle */
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    SetLastError(0xdeadbeef);
    Ret = pCancelSynchronousIo(Event);
    ok(!Ret && GetLastError() == ERROR_INVALID_HANDLE, "event handle: ret %d, error %lu\n", Ret, GetLastError());
    CloseHandle(Event);
    SetLastError(0xdeadbeef);
    Ret = pCancelSynchronousIo((HANDLE)(ULONG_PTR)0xdeadbeef);
    ok(!Ret && GetLastError() == ERROR_INVALID_HANDLE, "invalid handle: ret %d, error %lu\n", Ret, GetLastError());
    SetLastError(0xdeadbeef);
    Ret = pCancelSynchronousIo(NULL);
    ok(!Ret && GetLastError() == ERROR_INVALID_HANDLE, "NULL handle: ret %d, error %lu\n", Ret, GetLastError());

    /* the native call: a request that is not the thread's, then any request */
    Iosb.Status = 0x77;
    Iosb.Information = 0x88;
    Status = pNtCancel(Thread, &Wrong, &Iosb);
    ok(Status == STATUS_NOT_FOUND, "other request: status %lx\n", Status);
    ok(Iosb.Status == STATUS_NOT_FOUND && Iosb.Information == 0, "other request: block %lx %Ix\n", Iosb.Status, Iosb.Information);

    Iosb.Status = 0x77;
    Iosb.Information = 0x88;
    Status = pNtCancel(Thread, NULL, &Iosb);
    ok(Status == STATUS_SUCCESS, "status %lx\n", Status);
    ok(Iosb.Status == STATUS_SUCCESS && Iosb.Information == 0, "block %lx %Ix\n", Iosb.Status, Iosb.Information);
    ok(WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0, "the reader did not return\n");
    ok(!Reader.Ret && Reader.Error == ERROR_OPERATION_ABORTED, "reader: ret %d, error %lu\n", Reader.Ret, Reader.Error);
    CloseHandle(Thread);

    Iosb.Status = 0x77;
    Status = pNtCancel(GetCurrentThread(), NULL, &Iosb);
    ok(Status == STATUS_NOT_FOUND, "own thread: status %lx\n", Status);
    Status = pNtCancel(GetCurrentProcess(), NULL, &Iosb);
    ok(Status == STATUS_OBJECT_TYPE_MISMATCH, "process handle: status %lx\n", Status);

    /* the pipe is still usable after a cancelled read */
    Thread = StartReader(Read, &Reader, &ThreadId);
    if (Thread)
    {
        Ret = pCancelSynchronousIo(Thread);
        ok(Ret, "CancelSynchronousIo failed with %lu\n", GetLastError());
        WaitForSingleObject(Thread, 5000);
        ok(!Reader.Ret && Reader.Error == ERROR_OPERATION_ABORTED, "second reader: ret %d, error %lu\n", Reader.Ret, Reader.Error);
        CloseHandle(Thread);
    }
    ok(WriteFile(Write, "xy", 2, &Written, NULL), "WriteFile failed with %lu\n", GetLastError());
    Count = 0;
    Ret = ReadFile(Read, Buffer, sizeof(Buffer), &Count, NULL);
    ok(Ret && Count == 2, "read after the cancel: ret %d, %lu bytes\n", Ret, Count);

    /* a reader that a failed cancel left blocked must not keep the process from exiting */
    WriteFile(Write, "zzzzzzzz", 8, &Written, NULL);
    WriteFile(Write, "zzzzzzzz", 8, &Written, NULL);
    Sleep(200);

    CloseHandle(Read);
    CloseHandle(Write);

    TestCancelFlood();
}
