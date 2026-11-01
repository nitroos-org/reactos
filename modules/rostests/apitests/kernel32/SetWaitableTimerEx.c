/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for SetWaitableTimerEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

typedef struct _TEST_REASON_CONTEXT
{
    ULONG Version;
    DWORD Flags;
    LPWSTR SimpleReasonString;
} TEST_REASON_CONTEXT;

static BOOL (WINAPI *pSetWaitableTimerEx)(HANDLE, const LARGE_INTEGER *, LONG, PTIMERAPCROUTINE,
                                          LPVOID, void *, ULONG);

static LONG s_Apc;
static LPVOID s_ApcArg;

static VOID CALLBACK TimerApc(LPVOID Arg, DWORD LowValue, DWORD HighValue)
{
    s_ApcArg = Arg;
    InterlockedIncrement(&s_Apc);
}

START_TEST(SetWaitableTimerEx)
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    TEST_REASON_CONTEXT Reason;
    LARGE_INTEGER Due;
    HANDLE hTimer;
    DWORD Ret;
    BOOL Ok;

    /* GetActiveProcessorGroupCount marks the Windows 7 level of the exports */
    if (!GetProcAddress(hKernel32, "GetActiveProcessorGroupCount"))
    {
        skip("The Windows 7 exports are not enabled\n");
        return;
    }

    pSetWaitableTimerEx = (void *)GetProcAddress(hKernel32, "SetWaitableTimerEx");
    ok(pSetWaitableTimerEx != NULL, "SetWaitableTimerEx is missing\n");
    if (!pSetWaitableTimerEx)
        return;

    /* A manual reset timer that fires once, 50 ms from now */
    hTimer = CreateWaitableTimerW(NULL, TRUE, NULL);
    ok(hTimer != NULL, "CreateWaitableTimerW failed with %lu\n", GetLastError());
    if (!hTimer)
        return;

    Due.QuadPart = -500000;
    Ok = pSetWaitableTimerEx(hTimer, &Due, 0, NULL, NULL, NULL, 0);
    ok(Ok == TRUE, "Ok = %d, GetLastError() = %lu\n", Ok, GetLastError());
    Ret = WaitForSingleObject(hTimer, 5000);
    ok(Ret == WAIT_OBJECT_0, "Ret = %lu\n", Ret);
    /* manual reset: still signaled */
    Ret = WaitForSingleObject(hTimer, 0);
    ok(Ret == WAIT_OBJECT_0, "Ret = %lu\n", Ret);

    /* Rearming resets the signal state */
    Due.QuadPart = -100000000;
    Ok = pSetWaitableTimerEx(hTimer, &Due, 0, NULL, NULL, NULL, 0);
    ok(Ok == TRUE, "Ok = %d, GetLastError() = %lu\n", Ok, GetLastError());
    Ret = WaitForSingleObject(hTimer, 0);
    ok(Ret == WAIT_TIMEOUT, "Ret = %lu\n", Ret);
    ok(CancelWaitableTimer(hTimer), "CancelWaitableTimer failed with %lu\n", GetLastError());

    /* A wake context and a tolerable delay are accepted */
    Reason.Version = 0;
    Reason.Flags = 1; /* POWER_REQUEST_CONTEXT_SIMPLE_STRING */
    Reason.SimpleReasonString = (LPWSTR)L"apitest";
    Due.QuadPart = -500000;
    Ok = pSetWaitableTimerEx(hTimer, &Due, 0, NULL, NULL, &Reason, 100);
    ok(Ok == TRUE, "Ok = %d, GetLastError() = %lu\n", Ok, GetLastError());
    Ret = WaitForSingleObject(hTimer, 5000);
    ok(Ret == WAIT_OBJECT_0, "Ret = %lu\n", Ret);
    CloseHandle(hTimer);

    /* The completion routine runs in an alertable wait */
    hTimer = CreateWaitableTimerW(NULL, FALSE, NULL);
    ok(hTimer != NULL, "CreateWaitableTimerW failed with %lu\n", GetLastError());
    if (!hTimer)
        return;

    s_Apc = 0;
    s_ApcArg = NULL;
    Due.QuadPart = -500000;
    Ok = pSetWaitableTimerEx(hTimer, &Due, 0, TimerApc, (LPVOID)0x1234, NULL, 0);
    ok(Ok == TRUE, "Ok = %d, GetLastError() = %lu\n", Ok, GetLastError());
    Ret = SleepEx(5000, TRUE);
    ok(Ret == WAIT_IO_COMPLETION, "Ret = %lu\n", Ret);
    ok(s_Apc == 1, "s_Apc = %ld\n", s_Apc);
    ok(s_ApcArg == (LPVOID)0x1234, "s_ApcArg = %p\n", s_ApcArg);
    CloseHandle(hTimer);

    /*
     * A tolerable delay lets the timer expire up to that much later (Windows 10, 2 ms due time with
     * 1000 ms tolerance: 0.36-0.56 s), never earlier
     */
    hTimer = CreateWaitableTimerW(NULL, FALSE, NULL);
    ok(hTimer != NULL, "CreateWaitableTimerW failed with %lu\n", GetLastError());
    if (hTimer)
    {
        DWORD Start, Elapsed;

        Start = GetTickCount();
        Due.QuadPart = -20000;
        Ok = pSetWaitableTimerEx(hTimer, &Due, 0, NULL, NULL, NULL, 1000);
        ok(Ok == TRUE, "Ok = %d, GetLastError() = %lu\n", Ok, GetLastError());
        Ret = WaitForSingleObject(hTimer, 5000);
        Elapsed = GetTickCount() - Start;
        ok(Ret == WAIT_OBJECT_0, "Ret = %lu\n", Ret);
        ok(Elapsed <= 1000 + 100, "Elapsed = %lu ms\n", Elapsed);

        /* A due time too far away to represent, with a tolerance: accepted, never expires */
        Due.QuadPart = MINLONGLONG;
        Ok = pSetWaitableTimerEx(hTimer, &Due, 0, NULL, NULL, NULL, 1000);
        ok(Ok == TRUE, "Ok = %d, GetLastError() = %lu\n", Ok, GetLastError());
        Ret = WaitForSingleObject(hTimer, 200);
        ok(Ret == WAIT_TIMEOUT, "Ret = %lu\n", Ret);
        CancelWaitableTimer(hTimer);

        /* No due time: ERROR_INVALID_PARAMETER (Windows 10 does not fault) */
        SetLastError(0xdeadbeef);
        Ok = pSetWaitableTimerEx(hTimer, NULL, 0, NULL, NULL, NULL, 0);
        ok(Ok == FALSE, "Ok = %d\n", Ok);
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());

        /* A negative period is invalid */
        Due.QuadPart = -20000;
        SetLastError(0xdeadbeef);
        Ok = pSetWaitableTimerEx(hTimer, &Due, -1, NULL, NULL, NULL, 30);
        ok(Ok == FALSE, "Ok = %d\n", Ok);
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());

        /* A resume (wake) timer is not supported: set, with ERROR_NOT_SUPPORTED */
        SetLastError(0xdeadbeef);
        Due.QuadPart = -10000;
        Ok = SetWaitableTimer(hTimer, &Due, 0, NULL, NULL, TRUE);
        ok(Ok == TRUE, "Ok = %d\n", Ok);
        ok(GetLastError() == ERROR_NOT_SUPPORTED, "GetLastError() = %lu\n", GetLastError());
        Ret = WaitForSingleObject(hTimer, 5000);
        ok(Ret == WAIT_OBJECT_0, "Ret = %lu\n", Ret);
        CloseHandle(hTimer);
    }

    /* A bad handle */
    SetLastError(0xdeadbeef);
    Ok = pSetWaitableTimerEx((HANDLE)(ULONG_PTR)0x1234, &Due, 0, NULL, NULL, NULL, 0);
    ok(Ok == FALSE, "Ok = %d\n", Ok);
    ok(GetLastError() == ERROR_INVALID_HANDLE, "GetLastError() = %lu\n", GetLastError());

    /* An event is not a timer */
    hTimer = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(hTimer != NULL, "CreateEventW failed with %lu\n", GetLastError());
    if (hTimer)
    {
        SetLastError(0xdeadbeef);
        Ok = pSetWaitableTimerEx(hTimer, &Due, 0, NULL, NULL, NULL, 0);
        ok(Ok == FALSE, "Ok = %d\n", Ok);
        ok(GetLastError() == ERROR_INVALID_HANDLE, "GetLastError() = %lu\n", GetLastError());
        CloseHandle(hTimer);
    }
}
