/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for NtAlertThreadByThreadId and NtWaitForAlertByThreadId of ntdll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (19045), x64:
 *  - NtAlertThreadByThreadId(tid of a thread of the process) is STATUS_SUCCESS and sets a flag for that thread. The
 *    flag does not count: two alerts and two waits give STATUS_ALERTED and then STATUS_TIMEOUT.
 *  - NtWaitForAlertByThreadId(Address, Timeout) returns STATUS_ALERTED at once when the flag is set (and clears it),
 *    otherwise it waits for the alert: STATUS_ALERTED, or STATUS_TIMEOUT when the timeout (relative if negative, in
 *    100 ns; NULL waits for ever) is over. A zero timeout polls. (The Address is passed as NULL here.)
 *  - A thread id that does not exist (0, 4, 0xFFFFFFF0, a process id) or a handle value that is not a thread id (-2) is
 *    STATUS_INVALID_CID.
 *  - A user APC queued to a thread that waits is not delivered by the wait (it is not alertable) and does not end it;
 *    the APC runs at the next alertable wait. A pending APC does not end a poll either.
 * Not measured (the probe could not read the answer): the alert of a thread of another process.
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PFN_ALERT)(HANDLE);
typedef NTSTATUS (NTAPI *PFN_WAIT)(PVOID, PLARGE_INTEGER);

static PFN_ALERT pAlert;
static PFN_WAIT pWait;

static volatile LONG g_ApcRan;
static volatile LONG g_WaiterStatus;
static volatile LONG g_WaiterTid;
static HANDLE g_WaiterReady;

static VOID CALLBACK ApcProc(ULONG_PTR Param)
{
    InterlockedIncrement(&g_ApcRan);
}

static DWORD WINAPI Waiter(LPVOID Param)
{
    LARGE_INTEGER Timeout;

    g_WaiterTid = (LONG)GetCurrentThreadId();
    SetEvent(g_WaiterReady);
    if (Param)
    {
        Timeout.QuadPart = -(LONGLONG)10 * 1000 * 10000; /* 10 s: the test must not get there */
        g_WaiterStatus = (LONG)pWait(NULL, &Timeout);
    }
    else
    {
        g_WaiterStatus = (LONG)pWait(NULL, NULL);
    }
    return 0;
}

static void Test_Flag(void)
{
    LARGE_INTEGER Zero;
    NTSTATUS Status;
    HANDLE Self = (HANDLE)(ULONG_PTR)GetCurrentThreadId();

    Zero.QuadPart = 0;

    /* nothing pending */
    Status = pWait(NULL, &Zero);
    ok_hex(Status, STATUS_TIMEOUT);

    /* an alert before the wait is kept; one wait takes it */
    Status = pAlert(Self);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pWait(NULL, &Zero);
    ok_hex(Status, STATUS_ALERTED);
    Status = pWait(NULL, &Zero);
    ok_hex(Status, STATUS_TIMEOUT);

    /* the flag does not count */
    pAlert(Self);
    pAlert(Self);
    Status = pWait(NULL, &Zero);
    ok_hex(Status, STATUS_ALERTED);
    Status = pWait(NULL, &Zero);
    ok_hex(Status, STATUS_TIMEOUT);
}

static void Test_Timeout(void)
{
    LARGE_INTEGER Timeout;
    NTSTATUS Status;
    DWORD Start, Elapsed;

    /* relative, 200 ms */
    Timeout.QuadPart = -(LONGLONG)200 * 10000;
    Start = GetTickCount();
    Status = pWait(NULL, &Timeout);
    Elapsed = GetTickCount() - Start;
    ok_hex(Status, STATUS_TIMEOUT);
    ok(Elapsed >= 180, "waited only %lu ms\n", Elapsed);
    ok(Elapsed < 3000, "waited %lu ms\n", Elapsed);
}

static void Test_InvalidIds(void)
{
    NTSTATUS Status;
    LARGE_INTEGER Zero;

    Zero.QuadPart = 0;

    Status = pAlert((HANDLE)(ULONG_PTR)0);
    ok_hex(Status, STATUS_INVALID_CID);
    Status = pAlert((HANDLE)(ULONG_PTR)4);
    ok_hex(Status, STATUS_INVALID_CID);
    Status = pAlert((HANDLE)(ULONG_PTR)0xFFFFFFF0u);
    ok_hex(Status, STATUS_INVALID_CID);
    Status = pAlert((HANDLE)(ULONG_PTR)GetCurrentProcessId());
    ok_hex(Status, STATUS_INVALID_CID);
    Status = pAlert(GetCurrentThread());
    ok_hex(Status, STATUS_INVALID_CID);

    /* none of them set the flag of this thread */
    Status = pWait(NULL, &Zero);
    ok_hex(Status, STATUS_TIMEOUT);
}

static void Test_Waiter(void)
{
    HANDLE Thread;
    NTSTATUS Status;
    DWORD Wait;

    g_WaiterReady = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(g_WaiterReady != NULL, "CreateEvent failed\n");

    /* another thread blocks in the wait; the alert ends it */
    g_WaiterStatus = -1;
    Thread = CreateThread(NULL, 0, Waiter, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed\n");
    Wait = WaitForSingleObject(g_WaiterReady, 10000);
    ok(Wait == WAIT_OBJECT_0, "waiter did not start: %lu\n", Wait);
    Sleep(200);
    ok(WaitForSingleObject(Thread, 0) == WAIT_TIMEOUT, "the waiter ended without an alert\n");
    Status = pAlert((HANDLE)(ULONG_PTR)g_WaiterTid);
    ok_hex(Status, STATUS_SUCCESS);
    Wait = WaitForSingleObject(Thread, 10000);
    ok(Wait == WAIT_OBJECT_0, "the waiter did not end after the alert: %lu\n", Wait);
    ok_hex((NTSTATUS)g_WaiterStatus, STATUS_ALERTED);
    CloseHandle(Thread);

    /* a user APC does not end the wait; only the alert does, and the APC stays queued for an alertable wait */
    g_WaiterStatus = -1;
    g_ApcRan = 0;
    Thread = CreateThread(NULL, 0, Waiter, (LPVOID)1, 0, NULL);
    ok(Thread != NULL, "CreateThread failed\n");
    Wait = WaitForSingleObject(g_WaiterReady, 10000);
    ok(Wait == WAIT_OBJECT_0, "waiter did not start: %lu\n", Wait);
    Sleep(200);
    ok(QueueUserAPC(ApcProc, Thread, 0) != 0, "QueueUserAPC failed\n");
    Sleep(400);
    ok(g_ApcRan == 0, "the APC ran during a wait that is not alertable\n");
    ok(g_WaiterStatus == -1, "the APC ended the wait: %#lx\n", (ULONG)g_WaiterStatus);
    Status = pAlert((HANDLE)(ULONG_PTR)g_WaiterTid);
    ok_hex(Status, STATUS_SUCCESS);
    Wait = WaitForSingleObject(Thread, 10000);
    ok(Wait == WAIT_OBJECT_0, "the waiter did not end after the alert: %lu\n", Wait);
    ok_hex((NTSTATUS)g_WaiterStatus, STATUS_ALERTED);
    CloseHandle(Thread);

    CloseHandle(g_WaiterReady);
}

static void Test_PendingApc(void)
{
    LARGE_INTEGER Zero;
    NTSTATUS Status;

    Zero.QuadPart = 0;
    g_ApcRan = 0;
    ok(QueueUserAPC(ApcProc, GetCurrentThread(), 0) != 0, "QueueUserAPC failed\n");
    Status = pWait(NULL, &Zero);
    ok_hex(Status, STATUS_TIMEOUT);
    ok(g_ApcRan == 0, "the APC ran in a wait that is not alertable\n");
    SleepEx(0, TRUE);
    ok(g_ApcRan == 1, "the APC did not run in an alertable wait: %ld\n", g_ApcRan);
}

START_TEST(NtAlertThreadByThreadId)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

    pAlert = (PFN_ALERT)GetProcAddress(hNtdll, "NtAlertThreadByThreadId");
    pWait = (PFN_WAIT)GetProcAddress(hNtdll, "NtWaitForAlertByThreadId");
    if (!pAlert || !pWait)
    {
        skip("NtAlertThreadByThreadId or NtWaitForAlertByThreadId not available\n");
        return;
    }

    Test_Flag();
    Test_Timeout();
    Test_InvalidIds();
    Test_Waiter();
    Test_PendingApc();
}
