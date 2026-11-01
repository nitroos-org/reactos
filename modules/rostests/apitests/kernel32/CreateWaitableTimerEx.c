/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for CreateWaitableTimerExA/W
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#include <ndk/obfuncs.h>

#ifndef CREATE_WAITABLE_TIMER_MANUAL_RESET
#define CREATE_WAITABLE_TIMER_MANUAL_RESET 0x00000001
#endif
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

typedef HANDLE WINAPI FN_CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD);
typedef HANDLE WINAPI FN_CreateWaitableTimerExA(LPSECURITY_ATTRIBUTES, LPCSTR, DWORD, DWORD);

static FN_CreateWaitableTimerExW *pCreateWaitableTimerExW;
static FN_CreateWaitableTimerExA *pCreateWaitableTimerExA;

static
VOID
TestReset(_In_ HANDLE Timer, _In_ BOOL ManualReset)
{
    LARGE_INTEGER Due;

    Due.QuadPart = -1;
    ok(SetWaitableTimer(Timer, &Due, 0, NULL, NULL, FALSE), "SetWaitableTimer failed: %lu\n", GetLastError());
    ok(WaitForSingleObject(Timer, 5000) == WAIT_OBJECT_0, "Timer did not fire\n");

    /* A satisfied wait resets a synchronization timer only */
    ok(WaitForSingleObject(Timer, 0) == (ManualReset ? WAIT_OBJECT_0 : WAIT_TIMEOUT),
       "Unexpected state, manual reset %d\n", ManualReset);
}

static
VOID
CheckTypeName(_In_ HANDLE Handle, _In_ PCWSTR Expected)
{
    UCHAR Buffer[256];
    POBJECT_TYPE_INFORMATION Info = (POBJECT_TYPE_INFORMATION)Buffer;
    NTSTATUS Status;

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryObject(Handle, ObjectTypeInformation, Info, sizeof(Buffer), NULL);
    ok(NT_SUCCESS(Status), "NtQueryObject failed: 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        ok(Info->TypeName.Length == wcslen(Expected) * sizeof(WCHAR) &&
           !_wcsnicmp(Info->TypeName.Buffer, Expected, Info->TypeName.Length / sizeof(WCHAR)),
           "Type %.*ls, expected %ls\n", Info->TypeName.Length / (int)sizeof(WCHAR), Info->TypeName.Buffer, Expected);
    }
}

static VOID CALLBACK TimerApc(LPVOID Arg, DWORD Low, DWORD High)
{
}

static int __cdecl CompareDouble(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x < y) ? -1 : (x > y);
}

/*
 * CREATE_WAITABLE_TIMER_HIGH_RESOLUTION (Windows 10 1803+). Measured on Windows 10 22H2, x64 and
 * WOW64: the flag is accepted alone and with CREATE_WAITABLE_TIMER_MANUAL_RESET; the object type is
 * IRTimer; a name (also "") or security attributes are ERROR_INVALID_PARAMETER; SetWaitableTimer with
 * a completion routine, fResume or a negative period, and SetWaitableTimerEx with a tolerable delay,
 * fail with ERROR_INVALID_PARAMETER. Windows fires such a timer 30-80 us after its due time
 * (1 ms one-shot: 1.03-1.07 ms) without timeBeginPeriod; an ordinary timer fires on the 15.6 ms tick.
 * ReactOS raises the clock to about 1 ms while one is due; the bound (median under 8 ms) leaves room
 * for a loaded machine and rules out the 15.6 ms tick.
 */
static
VOID
TestHighResolution(VOID)
{
    static const DWORD BadFlags[] = { 4, 6, 8, 0x10, 0x100, 0x80000000, 0xFFFFFFFF };
    BOOL (WINAPI *pSetWaitableTimerEx)(HANDLE, const LARGE_INTEGER *, LONG, PTIMERAPCROUTINE, LPVOID, PVOID, ULONG);
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, FALSE };
    LARGE_INTEGER Due, Frequency, Start, End;
    double Samples[40];
    HANDLE Timer;
    ULONG i;
    BOOL Ret;

    for (i = 0; i < 2; i++)
    {
        DWORD Flags = CREATE_WAITABLE_TIMER_HIGH_RESOLUTION | (i ? CREATE_WAITABLE_TIMER_MANUAL_RESET : 0);

        SetLastError(0xdeadbeef);
        Timer = pCreateWaitableTimerExW(NULL, NULL, Flags, TIMER_ALL_ACCESS);
        ok(Timer != NULL, "Flags 0x%lx: CreateWaitableTimerExW failed: %lu\n", Flags, GetLastError());
        if (!Timer) continue;
        ok_err(ERROR_SUCCESS);
        CheckTypeName(Timer, L"IRTimer");
        TestReset(Timer, i != 0);
        CloseHandle(Timer);
    }

    for (i = 0; i < RTL_NUMBER_OF(BadFlags); i++)
    {
        SetLastError(0xdeadbeef);
        Timer = pCreateWaitableTimerExW(NULL, NULL, BadFlags[i], TIMER_ALL_ACCESS);
        ok(Timer == NULL && GetLastError() == ERROR_INVALID_PARAMETER,
           "Flags 0x%lx: timer %p, error %lu\n", BadFlags[i], Timer, GetLastError());
        if (Timer) CloseHandle(Timer);
    }

    /* No name, security attributes or inheritance */
    SetLastError(0xdeadbeef);
    Timer = pCreateWaitableTimerExW(NULL, L"rostest_timer_hr", CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok(Timer == NULL && GetLastError() == ERROR_INVALID_PARAMETER, "Named: timer %p, error %lu\n", Timer, GetLastError());
    if (Timer) CloseHandle(Timer);
    SetLastError(0xdeadbeef);
    Timer = pCreateWaitableTimerExW(NULL, L"", CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok(Timer == NULL && GetLastError() == ERROR_INVALID_PARAMETER, "Empty name: timer %p, error %lu\n", Timer, GetLastError());
    if (Timer) CloseHandle(Timer);
    SetLastError(0xdeadbeef);
    Timer = pCreateWaitableTimerExW(&Sa, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok(Timer == NULL && GetLastError() == ERROR_INVALID_PARAMETER, "Security attributes: timer %p, error %lu\n", Timer, GetLastError());
    if (Timer) CloseHandle(Timer);
    /* The same security attributes are fine for an ordinary timer */
    Timer = pCreateWaitableTimerExW(&Sa, NULL, 0, TIMER_ALL_ACCESS);
    ok(Timer != NULL, "CreateWaitableTimerExW failed: %lu\n", GetLastError());
    if (Timer) CloseHandle(Timer);

    Timer = pCreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok(Timer != NULL, "CreateWaitableTimerExW failed: %lu\n", GetLastError());
    if (!Timer) return;

    /* What SetWaitableTimer(Ex) take on such a timer */
    Due.QuadPart = -10000;
    SetLastError(0xdeadbeef);
    Ret = SetWaitableTimer(Timer, &Due, 0, TimerApc, NULL, FALSE);
    ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "Completion routine: %d, error %lu\n", Ret, GetLastError());
    SetLastError(0xdeadbeef);
    Ret = SetWaitableTimer(Timer, &Due, 0, NULL, NULL, TRUE);
    ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "fResume: %d, error %lu\n", Ret, GetLastError());
    SetLastError(0xdeadbeef);
    Ret = SetWaitableTimer(Timer, &Due, -1, NULL, NULL, FALSE);
    ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "Period -1: %d, error %lu\n", Ret, GetLastError());
    pSetWaitableTimerEx = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetWaitableTimerEx");
    if (pSetWaitableTimerEx)
    {
        SetLastError(0xdeadbeef);
        Ret = pSetWaitableTimerEx(Timer, &Due, 0, NULL, NULL, NULL, 1);
        ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "Tolerable delay: %d, error %lu\n", Ret, GetLastError());
        Ret = pSetWaitableTimerEx(Timer, &Due, 0, NULL, NULL, NULL, 0);
        ok(Ret, "SetWaitableTimerEx failed: %lu\n", GetLastError());
        ok_dec(WaitForSingleObject(Timer, 5000), WAIT_OBJECT_0);
    }
    ok(CancelWaitableTimer(Timer), "CancelWaitableTimer failed: %lu\n", GetLastError());

    /* A due time too far away to represent: accepted, never expires (Windows 10) */
    Due.QuadPart = MINLONGLONG;
    ok(SetWaitableTimer(Timer, &Due, 0, NULL, NULL, FALSE), "SetWaitableTimer failed: %lu\n", GetLastError());
    ok_dec(WaitForSingleObject(Timer, 200), WAIT_TIMEOUT);
    CancelWaitableTimer(Timer);

    /* No due time: ERROR_INVALID_PARAMETER (Windows 10 does not fault) */
    SetLastError(0xdeadbeef);
    Ret = SetWaitableTimer(Timer, NULL, 0, NULL, NULL, FALSE);
    ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "NULL due time: %d, error %lu\n", Ret, GetLastError());

    /* Firing period of 1 ms one-shot timers */
    QueryPerformanceFrequency(&Frequency);
    for (i = 0; i < RTL_NUMBER_OF(Samples); i++)
    {
        QueryPerformanceCounter(&Start);
        Due.QuadPart = -10000;
        SetWaitableTimer(Timer, &Due, 0, NULL, NULL, FALSE);
        WaitForSingleObject(Timer, INFINITE);
        QueryPerformanceCounter(&End);
        Samples[i] = (double)(End.QuadPart - Start.QuadPart) * 1000.0 / (double)Frequency.QuadPart;
    }
    qsort(Samples, RTL_NUMBER_OF(Samples), sizeof(double), CompareDouble);
    trace("high resolution one-shot 1 ms: min %.3f median %.3f max %.3f ms\n",
          Samples[0], Samples[RTL_NUMBER_OF(Samples) / 2], Samples[RTL_NUMBER_OF(Samples) - 1]);
    ok(Samples[0] >= 0.5, "1 ms timer fired after %.3f ms\n", Samples[0]);
    ok(Samples[RTL_NUMBER_OF(Samples) / 2] < 8.0, "1 ms timer: median %.3f ms\n", Samples[RTL_NUMBER_OF(Samples) / 2]);

    /* Periodic 1 ms */
    Due.QuadPart = -10000;
    ok(SetWaitableTimer(Timer, &Due, 1, NULL, NULL, FALSE), "SetWaitableTimer failed: %lu\n", GetLastError());
    WaitForSingleObject(Timer, 1000);
    QueryPerformanceCounter(&Start);
    for (i = 0; i < 50; i++)
    {
        if (WaitForSingleObject(Timer, 1000) != WAIT_OBJECT_0) break;
    }
    QueryPerformanceCounter(&End);
    CancelWaitableTimer(Timer);
    ok_dec(i, 50);
    trace("high resolution periodic 1 ms: mean %.3f ms\n",
          (double)(End.QuadPart - Start.QuadPart) * 1000.0 / (double)Frequency.QuadPart / 50);
    ok((double)(End.QuadPart - Start.QuadPart) * 1000.0 / (double)Frequency.QuadPart / 50 < 8.0,
       "periodic 1 ms: mean %.3f ms\n", (double)(End.QuadPart - Start.QuadPart) * 1000.0 / (double)Frequency.QuadPart / 50);

    CloseHandle(Timer);
}

START_TEST(CreateWaitableTimerEx)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    LARGE_INTEGER Due;
    HANDLE Timer, Timer2;

    pCreateWaitableTimerExW = (FN_CreateWaitableTimerExW *)GetProcAddress(Kernel32, "CreateWaitableTimerExW");
    pCreateWaitableTimerExA = (FN_CreateWaitableTimerExA *)GetProcAddress(Kernel32, "CreateWaitableTimerExA");
    if (!pCreateWaitableTimerExW || !pCreateWaitableTimerExA)
    {
        skip("CreateWaitableTimerExA/W are not available\n");
        return;
    }

    Timer = pCreateWaitableTimerExW(NULL, NULL, 0, TIMER_ALL_ACCESS);
    ok(Timer != NULL, "CreateWaitableTimerExW failed: %lu\n", GetLastError());
    if (Timer)
    {
        TestReset(Timer, FALSE);
        CloseHandle(Timer);
    }

    Timer = pCreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_MANUAL_RESET, TIMER_ALL_ACCESS);
    ok(Timer != NULL, "CreateWaitableTimerExW failed: %lu\n", GetLastError());
    if (Timer)
    {
        TestReset(Timer, TRUE);
        CloseHandle(Timer);
    }

    SetLastError(0xdeadbeef);
    Timer = pCreateWaitableTimerExW(NULL, NULL, 0x80000000, TIMER_ALL_ACCESS);
    ok(Timer == NULL && GetLastError() == ERROR_INVALID_PARAMETER,
       "Timer %p, error %lu\n", Timer, GetLastError());
    if (Timer) CloseHandle(Timer);

    /* The requested access is the access of the handle */
    Timer = pCreateWaitableTimerExW(NULL, NULL, 0, SYNCHRONIZE);
    ok(Timer != NULL, "CreateWaitableTimerExW failed: %lu\n", GetLastError());
    if (Timer)
    {
        Due.QuadPart = -1;
        SetLastError(0xdeadbeef);
        ok(!SetWaitableTimer(Timer, &Due, 0, NULL, NULL, FALSE) && GetLastError() == ERROR_ACCESS_DENIED,
           "SetWaitableTimer error %lu\n", GetLastError());
        CloseHandle(Timer);
    }

    /* The ANSI version creates the named object */
    Timer = pCreateWaitableTimerExA(NULL, "rostest_timer_ex", 0, TIMER_ALL_ACCESS);
    ok(Timer != NULL, "CreateWaitableTimerExA failed: %lu\n", GetLastError());
    Timer2 = OpenWaitableTimerW(TIMER_ALL_ACCESS, FALSE, L"rostest_timer_ex");
    ok(Timer2 != NULL, "OpenWaitableTimerW failed: %lu\n", GetLastError());
    if (Timer2) CloseHandle(Timer2);
    if (Timer) CloseHandle(Timer);

    TestHighResolution();
}
