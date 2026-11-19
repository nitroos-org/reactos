/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     CancelIoEx on a console input handle ends a read another thread has blocked on it
 *              (the OpenSSH client's stdin reader thread: it calls CancelIoEx and then waits 1 s for it)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define PENDING_WAIT_MS     300     /* time the reader gets to block */
#define END_LIMIT_MS        1000    /* a cancelled read must be over within this (a wake-up takes well under 100 ms) */

typedef BOOL WINAPI FN_CancelIoEx(_In_ HANDLE hFile, _In_opt_ LPOVERLAPPED lpOverlapped);

static FN_CancelIoEx *pCancelIoEx;

typedef struct _READER
{
    HANDLE Handle;
    BOOL Ok;
    DWORD Error;
    DWORD Bytes;
} READER;

static
DWORD
WINAPI
ReaderThread(_In_ LPVOID Param)
{
    READER *Reader = Param;
    CHAR Buffer[16];

    Reader->Ok = ReadFile(Reader->Handle, Buffer, sizeof(Buffer), &Reader->Bytes, NULL);
    Reader->Error = Reader->Ok ? 0 : GetLastError();
    return 0;
}

static
HANDLE
OpenConIn(VOID)
{
    return CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
}

START_TEST(ConsoleCancelIo)
{
    HANDLE In, Other, Thread;
    READER Reader;
    DWORD Wait;
    BOOL Ret;
    DWORD Start, Elapsed;

    pCancelIoEx = (FN_CancelIoEx *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CancelIoEx");
    if (!pCancelIoEx)
    {
        skip("CancelIoEx is not available\n");
        return;
    }

    In = OpenConIn();
    Other = OpenConIn();
    if (In == INVALID_HANDLE_VALUE || Other == INVALID_HANDLE_VALUE)
    {
        skip("No console input (error %lu)\n", GetLastError());
        return;
    }

    /* A read blocked on the handle ends when CancelIoEx is called on it from another thread */
    ZeroMemory(&Reader, sizeof(Reader));
    Reader.Handle = In;
    Thread = CreateThread(NULL, 0, ReaderThread, &Reader, 0, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (!Thread)
        return;
    Wait = WaitForSingleObject(Thread, PENDING_WAIT_MS);
    ok(Wait == WAIT_TIMEOUT, "The read returned at once (wait %lu, ok %d, error %lu)\n", Wait, Reader.Ok, Reader.Error);

    /* Another handle of the same console is not the one the read waits on */
    SetLastError(0xdeadbeef);
    Ret = pCancelIoEx(Other, NULL);
    (void)Ret;
    Wait = WaitForSingleObject(Thread, PENDING_WAIT_MS);
    ok(Wait == WAIT_TIMEOUT, "CancelIoEx on another handle ended the read (wait %lu)\n", Wait);

    SetLastError(0xdeadbeef);
    Start = GetTickCount();
    Ret = pCancelIoEx(In, NULL);
    ok(Ret, "CancelIoEx failed with %lu\n", GetLastError());
    Wait = WaitForSingleObject(Thread, 2 * END_LIMIT_MS);
    Elapsed = GetTickCount() - Start;
    ok(Wait == WAIT_OBJECT_0, "The read did not end after CancelIoEx (wait %lu)\n", Wait);
    if (Wait == WAIT_OBJECT_0)
    {
        ok(!Reader.Ok, "The cancelled read succeeded (%lu bytes)\n", Reader.Bytes);
        ok(Reader.Error == ERROR_OPERATION_ABORTED, "The cancelled read failed with %lu\n", Reader.Error);
        ok(Elapsed < END_LIMIT_MS, "The read took %lu ms to end after CancelIoEx\n", Elapsed);
    }
    else
    {
        /* closing the handle ends a blocked read as well: do not leave the thread behind */
        CloseHandle(In);
        In = INVALID_HANDLE_VALUE;
        WaitForSingleObject(Thread, 2 * END_LIMIT_MS);
    }
    CloseHandle(Thread);

    /* The handle is usable after the cancel: a new read blocks again and can be cancelled again */
    if (In != INVALID_HANDLE_VALUE)
    {
        ZeroMemory(&Reader, sizeof(Reader));
        Reader.Handle = In;
        Thread = CreateThread(NULL, 0, ReaderThread, &Reader, 0, NULL);
        ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
        if (Thread)
        {
            Wait = WaitForSingleObject(Thread, PENDING_WAIT_MS);
            ok(Wait == WAIT_TIMEOUT, "The second read returned at once (wait %lu, error %lu)\n", Wait, Reader.Error);
            Ret = pCancelIoEx(In, NULL);
            ok(Ret, "CancelIoEx failed with %lu\n", GetLastError());
            Wait = WaitForSingleObject(Thread, 2 * END_LIMIT_MS);
            ok(Wait == WAIT_OBJECT_0, "The second read did not end after CancelIoEx (wait %lu)\n", Wait);
            if (Wait != WAIT_OBJECT_0)
                CloseHandle(In);
            WaitForSingleObject(Thread, 2 * END_LIMIT_MS);
            CloseHandle(Thread);
        }
        CloseHandle(In);
    }
    CloseHandle(Other);
}
