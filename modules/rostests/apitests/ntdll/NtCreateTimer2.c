/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for NtCreateTimer2, NtSetTimer2, NtCancelTimer2 and NtSetTimerEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows 10 22H2 (x64 and WOW64).
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *FN_NtCreateTimer2)(PHANDLE, PVOID, POBJECT_ATTRIBUTES, ULONG, ACCESS_MASK);
typedef NTSTATUS (NTAPI *FN_NtSetTimer2)(HANDLE, PLARGE_INTEGER, PLARGE_INTEGER, PT2_SET_PARAMETERS);
typedef NTSTATUS (NTAPI *FN_NtCancelTimer2)(HANDLE, PT2_CANCEL_PARAMETERS);
typedef NTSTATUS (NTAPI *FN_NtSetTimerEx)(HANDLE, TIMER_SET_INFORMATION_CLASS, PVOID, ULONG);

static FN_NtCreateTimer2 pNtCreateTimer2;
static FN_NtSetTimer2 pNtSetTimer2;
static FN_NtCancelTimer2 pNtCancelTimer2;
static FN_NtSetTimerEx pNtSetTimerEx;

static VOID NTAPI TimerApc(PVOID Context, ULONG Low, LONG High)
{
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
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(Info->TypeName.Length == wcslen(Expected) * sizeof(WCHAR) &&
           !_wcsnicmp(Info->TypeName.Buffer, Expected, Info->TypeName.Length / sizeof(WCHAR)),
           "Type %.*ls, expected %ls\n", Info->TypeName.Length / (int)sizeof(WCHAR), Info->TypeName.Buffer, Expected);
    }
}

static
ACCESS_MASK
GrantedAccess(_In_ HANDLE Handle)
{
    OBJECT_BASIC_INFORMATION Info;

    RtlZeroMemory(&Info, sizeof(Info));
    NtQueryObject(Handle, ObjectBasicInformation, &Info, sizeof(Info), NULL);
    return Info.GrantedAccess;
}

static
VOID
TestAttributes(VOID)
{
    static const struct { ULONG Attributes; NTSTATUS Status; } Tests[] =
    {
        { 0, STATUS_SUCCESS },
        { TIMER2_ATTRIBUTE_HIGH_RESOLUTION, STATUS_SUCCESS },
        { TIMER2_ATTRIBUTE_NO_WAKE, STATUS_SUCCESS },
        { TIMER2_ATTRIBUTE_NOTIFICATION, STATUS_SUCCESS },
        { TIMER2_ATTRIBUTE_NOTIFICATION | TIMER2_ATTRIBUTE_HIGH_RESOLUTION, STATUS_SUCCESS },
        { TIMER2_ATTRIBUTE_NOTIFICATION | TIMER2_ATTRIBUTE_NO_WAKE, STATUS_SUCCESS },
        { 0x00000001, STATUS_INVALID_PARAMETER_4 },
        { 0x00000002, STATUS_INVALID_PARAMETER },
        { 0x00000003, STATUS_INVALID_PARAMETER_4 },
        { 0x00000006, STATUS_INVALID_PARAMETER },
        { 0x80000002, STATUS_INVALID_PARAMETER },
        { 0x80000006, STATUS_INVALID_PARAMETER },
        { 0x00000007, STATUS_INVALID_PARAMETER_4 },
        { 0x0000000A, STATUS_INVALID_PARAMETER_4 },
        { 0x0000000C, STATUS_INVALID_PARAMETER_4 },
        { 0x0000000E, STATUS_INVALID_PARAMETER_4 },
        { 0x8000000C, STATUS_INVALID_PARAMETER_4 },
        { 0x00000010, STATUS_INVALID_PARAMETER_4 },
        { 0x00000012, STATUS_INVALID_PARAMETER_4 },
        { 0x00000020, STATUS_INVALID_PARAMETER_4 },
        { 0x00010000, STATUS_INVALID_PARAMETER_4 },
        { 0x40000000, STATUS_INVALID_PARAMETER_4 },
        { 0x80000001, STATUS_INVALID_PARAMETER_4 },
    };
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"rostest_timer2");
    ULONG Reserved[4] = { 0 };
    HANDLE Handle;
    NTSTATUS Status;
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Tests); i++)
    {
        Handle = NULL;
        Status = pNtCreateTimer2(&Handle, NULL, NULL, Tests[i].Attributes, TIMER_ALL_ACCESS);
        ok(Status == Tests[i].Status, "Attributes 0x%08lx: status 0x%08lx, expected 0x%08lx\n",
           Tests[i].Attributes, Status, Tests[i].Status);
        if (NT_SUCCESS(Status))
        {
            CheckTypeName(Handle, L"IRTimer");
            ok_hex(GrantedAccess(Handle), TIMER_ALL_ACCESS);
            NtClose(Handle);
        }
    }

    /* Any object attributes are refused, also without a name */
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = pNtCreateTimer2(&Handle, NULL, &ObjectAttributes, TIMER2_ATTRIBUTE_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER_3);
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_INHERIT, NULL, NULL);
    Status = pNtCreateTimer2(&Handle, NULL, &ObjectAttributes, TIMER2_ATTRIBUTE_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER_3);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = pNtCreateTimer2(&Handle, NULL, &ObjectAttributes, TIMER2_ATTRIBUTE_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER_3);

    /* Order of the checks: attributes, object attributes, the refused attribute */
    Status = pNtCreateTimer2(&Handle, NULL, &ObjectAttributes, 0x10, TIMER_ALL_ACCESS);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER_4);
    Status = pNtCreateTimer2(&Handle, NULL, &ObjectAttributes, 0x2, TIMER_ALL_ACCESS);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER_3);

    /* The reserved parameter */
    Status = pNtCreateTimer2(&Handle, Reserved, NULL, TIMER2_ATTRIBUTE_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER_2);

    /* The handle has the access asked for */
    Status = pNtCreateTimer2(&Handle, NULL, NULL, TIMER2_ATTRIBUTE_HIGH_RESOLUTION, MAXIMUM_ALLOWED);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_hex(GrantedAccess(Handle), TIMER_ALL_ACCESS);
        NtClose(Handle);
    }
    Status = pNtCreateTimer2(&Handle, NULL, NULL, TIMER2_ATTRIBUTE_HIGH_RESOLUTION, SYNCHRONIZE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        T2_SET_PARAMETERS Parameters = { 0 };
        LARGE_INTEGER Due;

        ok_hex(GrantedAccess(Handle), SYNCHRONIZE);
        Due.QuadPart = -10000;
        Status = pNtSetTimer2(Handle, &Due, NULL, &Parameters);
        ok_ntstatus(Status, STATUS_ACCESS_DENIED);
        NtClose(Handle);
    }
}

/* Notification or synchronization: a second wait after the first one */
static
VOID
TestSemantics(VOID)
{
    static const ULONG Attributes[] = { 0, TIMER2_ATTRIBUTE_HIGH_RESOLUTION, TIMER2_ATTRIBUTE_NO_WAKE,
                                        TIMER2_ATTRIBUTE_NOTIFICATION, TIMER2_ATTRIBUTE_NOTIFICATION | TIMER2_ATTRIBUTE_HIGH_RESOLUTION };
    T2_SET_PARAMETERS Parameters = { 0 };
    LARGE_INTEGER Due, Zero;
    HANDLE Handle;
    NTSTATUS Status;
    BOOLEAN Notification;
    ULONG i;

    Zero.QuadPart = 0;
    for (i = 0; i < RTL_NUMBER_OF(Attributes); i++)
    {
        Status = pNtCreateTimer2(&Handle, NULL, NULL, Attributes[i], TIMER_ALL_ACCESS);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status)) continue;
        Notification = (Attributes[i] & TIMER2_ATTRIBUTE_NOTIFICATION) != 0;

        /* Not set: not signaled */
        Status = NtWaitForSingleObject(Handle, FALSE, &Zero);
        ok_ntstatus(Status, STATUS_TIMEOUT);

        Due.QuadPart = -10000;
        Status = pNtSetTimer2(Handle, &Due, NULL, &Parameters);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_dec(WaitForSingleObject(Handle, 5000), WAIT_OBJECT_0);
        ok(WaitForSingleObject(Handle, 0) == (Notification ? WAIT_OBJECT_0 : WAIT_TIMEOUT),
           "Attributes 0x%lx: second wait\n", Attributes[i]);

        /* NtSetTimer works on these timers too, without the previous state */
        Status = NtSetTimer(Handle, &Due, NULL, NULL, FALSE, 0, NULL);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_dec(WaitForSingleObject(Handle, 5000), WAIT_OBJECT_0);
        ok(WaitForSingleObject(Handle, 0) == (Notification ? WAIT_OBJECT_0 : WAIT_TIMEOUT),
           "Attributes 0x%lx: second wait after NtSetTimer\n", Attributes[i]);

        /* Due now: signaled at once */
        Status = pNtSetTimer2(Handle, &Zero, NULL, &Parameters);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_dec(WaitForSingleObject(Handle, 1000), WAIT_OBJECT_0);

        NtClose(Handle);
    }
}

static
VOID
TestSetAndCancel(VOID)
{
    T2_SET_PARAMETERS Parameters;
    LARGE_INTEGER Due, Period;
    HANDLE Timer2, Timer;
    BOOLEAN State;
    TIMER_BASIC_INFORMATION Basic;
    NTSTATUS Status;
    ULONG Version;

    Status = pNtCreateTimer2(&Timer2, NULL, NULL, TIMER2_ATTRIBUTE_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = NtCreateTimer(&Timer, TIMER_ALL_ACCESS, NULL, SynchronizationTimer);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!Timer2 || !Timer) return;
    CheckTypeName(Timer, L"Timer");

    Due.QuadPart = -10000;

    /* Only version 0 of the parameters; the other fields are not checked */
    for (Version = 0; Version < 4; Version++)
    {
        RtlZeroMemory(&Parameters, sizeof(Parameters));
        Parameters.Version = Version;
        Status = pNtSetTimer2(Timer2, &Due, NULL, &Parameters);
        ok(Status == (Version ? STATUS_INVALID_PARAMETER_3 : STATUS_SUCCESS), "Version %lu: 0x%08lx\n", Version, Status);
        pNtCancelTimer2(Timer2, NULL);
    }
    RtlZeroMemory(&Parameters, sizeof(Parameters));
    Parameters.Reserved = 1;
    ok_ntstatus(pNtSetTimer2(Timer2, &Due, NULL, &Parameters), STATUS_SUCCESS);
    Parameters.Reserved = 0;
    Parameters.NoWakeTolerance = -1;
    ok_ntstatus(pNtSetTimer2(Timer2, &Due, NULL, &Parameters), STATUS_SUCCESS);
    Parameters.NoWakeTolerance = 0;
    Period.QuadPart = 0;
    ok_ntstatus(pNtSetTimer2(Timer2, &Due, &Period, &Parameters), STATUS_SUCCESS);
    Period.QuadPart = -10000;
    ok_ntstatus(pNtSetTimer2(Timer2, &Due, &Period, &Parameters), STATUS_SUCCESS);
    ok_ntstatus(pNtCancelTimer2(Timer2, NULL), STATUS_SUCCESS);

    /* Each kind of timer has its own set of calls */
    ok_ntstatus(pNtSetTimer2(Timer, &Due, NULL, &Parameters), STATUS_OBJECT_TYPE_MISMATCH);
    ok_ntstatus(pNtCancelTimer2(Timer, NULL), STATUS_OBJECT_TYPE_MISMATCH);
    ok_ntstatus(NtQueryTimer(Timer2, TimerBasicInformation, &Basic, sizeof(Basic), NULL), STATUS_OBJECT_TYPE_MISMATCH);

    /* NtSetTimer / NtCancelTimer on an NtCreateTimer2 timer: no state, APC or wake request */
    State = 7;
    ok_ntstatus(NtSetTimer(Timer2, &Due, NULL, NULL, FALSE, 0, &State), STATUS_INVALID_PARAMETER);
    ok_int(State, 7);
    ok_ntstatus(NtSetTimer(Timer2, &Due, TimerApc, NULL, FALSE, 0, NULL), STATUS_INVALID_PARAMETER);
    ok_ntstatus(NtSetTimer(Timer2, &Due, NULL, NULL, TRUE, 0, NULL), STATUS_INVALID_PARAMETER);
    ok_ntstatus(NtSetTimer(Timer2, &Due, NULL, NULL, FALSE, -1, NULL), STATUS_INVALID_PARAMETER_6);
    ok_ntstatus(NtSetTimer(Timer2, &Due, NULL, NULL, FALSE, -1, &State), STATUS_INVALID_PARAMETER_6);
    ok_ntstatus(NtSetTimer(Timer2, &Due, NULL, NULL, FALSE, 1, NULL), STATUS_SUCCESS);
    ok_ntstatus(NtCancelTimer(Timer2, &State), STATUS_INVALID_PARAMETER);
    ok_ntstatus(NtCancelTimer(Timer2, NULL), STATUS_SUCCESS);

    /* A wake request on a Timer is ignored with a warning */
    ok_ntstatus(NtSetTimer(Timer, &Due, NULL, NULL, TRUE, 0, NULL), STATUS_TIMER_RESUME_IGNORED);
    NtCancelTimer(Timer, NULL);

    /* Cancelled before its due time: does not fire */
    Due.QuadPart = -500000;
    ok_ntstatus(pNtSetTimer2(Timer2, &Due, NULL, &Parameters), STATUS_SUCCESS);
    ok_ntstatus(pNtCancelTimer2(Timer2, &Parameters), STATUS_SUCCESS);
    ok_dec(WaitForSingleObject(Timer2, 200), WAIT_TIMEOUT);

    NtClose(Timer);
    NtClose(Timer2);
}

static
VOID
TestSetTimerEx(VOID)
{
    TIMER_SET_COALESCABLE_TIMER_INFO Info;
    HANDLE Timer, Timer2;
    BOOLEAN State;
    NTSTATUS Status;
    BOOL IsWow64 = FALSE;

    Status = NtCreateTimer(&Timer, TIMER_ALL_ACCESS, NULL, SynchronizationTimer);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = pNtCreateTimer2(&Timer2, NULL, NULL, TIMER2_ATTRIBUTE_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!Timer || !Timer2) return;

    RtlZeroMemory(&Info, sizeof(Info));
    Info.DueTime.QuadPart = -10000;
    ok_ntstatus(pNtSetTimerEx(Timer, TimerSetCoalescableTimer, &Info, sizeof(Info)), STATUS_SUCCESS);
    ok_dec(WaitForSingleObject(Timer, 5000), WAIT_OBJECT_0);
    Info.TolerableDelay = 50;
    ok_ntstatus(pNtSetTimerEx(Timer, TimerSetCoalescableTimer, &Info, sizeof(Info)), STATUS_SUCCESS);
    ok_dec(WaitForSingleObject(Timer, 5000), WAIT_OBJECT_0);
    Info.TolerableDelay = 0x80000000;
    ok_ntstatus(pNtSetTimerEx(Timer, TimerSetCoalescableTimer, &Info, sizeof(Info)), STATUS_SUCCESS);
    NtCancelTimer(Timer, NULL);
    Info.TolerableDelay = 0;
    State = 7;
    Info.PreviousState = &State;
    ok_ntstatus(pNtSetTimerEx(Timer, TimerSetCoalescableTimer, &Info, sizeof(Info)), STATUS_SUCCESS);
    ok_int(State, 0);
    ok_dec(WaitForSingleObject(Timer, 5000), WAIT_OBJECT_0);
    Info.PreviousState = NULL;

    /* Checks */
    Info.Period = 0x80000000;
    ok_ntstatus(pNtSetTimerEx(Timer, TimerSetCoalescableTimer, &Info, sizeof(Info)), STATUS_INVALID_PARAMETER_3);
    Info.Period = 0;
    ok_ntstatus(pNtSetTimerEx(Timer, (TIMER_SET_INFORMATION_CLASS)1, &Info, sizeof(Info)), STATUS_INVALID_INFO_CLASS);
    ok_ntstatus(pNtSetTimerEx(Timer, TimerSetCoalescableTimer, &Info, sizeof(Info) - 1), STATUS_INFO_LENGTH_MISMATCH);
    /* WOW64 takes a 32-bit structure of at least its size */
    IsWow64Process(GetCurrentProcess(), &IsWow64);
    Status = pNtSetTimerEx(Timer, TimerSetCoalescableTimer, &Info, sizeof(Info) + 8);
    ok(Status == (IsWow64 ? STATUS_SUCCESS : STATUS_INFO_LENGTH_MISMATCH), "Length + 8: 0x%08lx\n", Status);
    NtCancelTimer(Timer, NULL);

    /* An NtCreateTimer2 timer: no tolerable delay, previous state or APC */
    ok_ntstatus(pNtSetTimerEx(Timer2, TimerSetCoalescableTimer, &Info, sizeof(Info)), STATUS_SUCCESS);
    ok_dec(WaitForSingleObject(Timer2, 5000), WAIT_OBJECT_0);
    Info.TolerableDelay = 1;
    ok_ntstatus(pNtSetTimerEx(Timer2, TimerSetCoalescableTimer, &Info, sizeof(Info)), STATUS_INVALID_PARAMETER);
    Info.TolerableDelay = 0;
    Info.PreviousState = &State;
    ok_ntstatus(pNtSetTimerEx(Timer2, TimerSetCoalescableTimer, &Info, sizeof(Info)), STATUS_INVALID_PARAMETER);
    Info.PreviousState = NULL;
    Info.TimerApcRoutine = TimerApc;
    ok_ntstatus(pNtSetTimerEx(Timer2, TimerSetCoalescableTimer, &Info, sizeof(Info)), STATUS_INVALID_PARAMETER);

    NtClose(Timer);
    NtClose(Timer2);
}

static double s_Freq;

static double NowMs(VOID)
{
    LARGE_INTEGER Counter;

    QueryPerformanceCounter(&Counter);
    return (double)Counter.QuadPart * 1000.0 / s_Freq;
}

static int __cdecl CompareDouble(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x < y) ? -1 : (x > y);
}

/*
 * Firing period. Windows 10 fires a high resolution timer 30-80 us after its due time (1 ms
 * one-shot: 1.03-1.07 ms; 0.5 ms periodic: 0.53 ms) without anybody raising the timer resolution;
 * an ordinary timer fires on the 15.6 ms clock tick. ReactOS raises the clock interrupt to its
 * finest rate (about 1 ms) while a high resolution timer is due, so a due time is met within one
 * millisecond tick. The bound below (median under due + 3 ms) holds for both and rules out the
 * 15.6 ms tick.
 */
static
VOID
TestFiringPeriod(VOID)
{
    T2_SET_PARAMETERS Parameters = { 0 };
    LARGE_INTEGER Due, Period, Frequency;
    double Samples[40], Last;
    HANDLE Timer2;
    NTSTATUS Status;
    ULONG i, Min, Max, Current, Idle;

    QueryPerformanceFrequency(&Frequency);
    s_Freq = (double)Frequency.QuadPart;
    Status = pNtCreateTimer2(&Timer2, NULL, NULL, TIMER2_ATTRIBUTE_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;

    /* One-shot, 2 ms */
    for (i = 0; i < RTL_NUMBER_OF(Samples); i++)
    {
        double Start = NowMs();
        Due.QuadPart = -20000;
        pNtSetTimer2(Timer2, &Due, NULL, &Parameters);
        WaitForSingleObject(Timer2, INFINITE);
        Samples[i] = NowMs() - Start;
    }
    qsort(Samples, RTL_NUMBER_OF(Samples), sizeof(double), CompareDouble);
    trace("one-shot 2 ms: min %.3f median %.3f max %.3f ms\n", Samples[0], Samples[RTL_NUMBER_OF(Samples) / 2], Samples[RTL_NUMBER_OF(Samples) - 1]);
    ok(Samples[0] >= 1.5, "one-shot 2 ms fired after %.3f ms\n", Samples[0]);
    ok(Samples[RTL_NUMBER_OF(Samples) / 2] < 5.0, "one-shot 2 ms: median %.3f ms\n", Samples[RTL_NUMBER_OF(Samples) / 2]);

    /* Periodic, 0.5 ms (the shortest period on Windows; whole milliseconds here) */
    Due.QuadPart = -5000;
    Period.QuadPart = 5000;
    Status = pNtSetTimer2(Timer2, &Due, &Period, &Parameters);
    ok_ntstatus(Status, STATUS_SUCCESS);
    WaitForSingleObject(Timer2, 1000);
    Last = NowMs();
    for (i = 0; i < RTL_NUMBER_OF(Samples); i++)
    {
        double Now;
        if (WaitForSingleObject(Timer2, 1000) != WAIT_OBJECT_0) break;
        Now = NowMs();
        Samples[i] = Now - Last;
        Last = Now;
    }
    pNtCancelTimer2(Timer2, NULL);
    ok_dec(i, RTL_NUMBER_OF(Samples));
    if (i == RTL_NUMBER_OF(Samples))
    {
        qsort(Samples, RTL_NUMBER_OF(Samples), sizeof(double), CompareDouble);
        trace("periodic 0.5 ms: median %.3f ms\n", Samples[RTL_NUMBER_OF(Samples) / 2]);
        ok(Samples[RTL_NUMBER_OF(Samples) / 2] < 3.0, "periodic 0.5 ms: median %.3f ms\n", Samples[RTL_NUMBER_OF(Samples) / 2]);
    }

    /*
     * The clock runs fast only while a high resolution timer is due soon: a timer due in 10 s does
     * not change the reported resolution (Windows 10 neither). Wait for the rate to drop first.
     */
    Sleep(500);
    NtQueryTimerResolution(&Min, &Max, &Idle);
    Due.QuadPart = -100000000;
    pNtSetTimer2(Timer2, &Due, NULL, &Parameters);
    Sleep(50);
    NtQueryTimerResolution(&Min, &Max, &Current);
    ok(Current == Idle, "Resolution %lu with a timer due in 10 s, %lu before\n", Current, Idle);
    pNtCancelTimer2(Timer2, NULL);

    /* While one is due in 2 ms, it is at most 2 ms (Windows 10: exactly the 2 ms) */
    Due.QuadPart = -20000;
    pNtSetTimer2(Timer2, &Due, NULL, &Parameters);
    NtQueryTimerResolution(&Min, &Max, &Current);
    ok(Current <= 20000, "Resolution %lu with a timer due in 2 ms\n", Current);
    WaitForSingleObject(Timer2, INFINITE);

    NtClose(Timer2);
}

START_TEST(NtCreateTimer2)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");

    pNtCreateTimer2 = (FN_NtCreateTimer2)GetProcAddress(Ntdll, "NtCreateTimer2");
    pNtSetTimer2 = (FN_NtSetTimer2)GetProcAddress(Ntdll, "NtSetTimer2");
    pNtCancelTimer2 = (FN_NtCancelTimer2)GetProcAddress(Ntdll, "NtCancelTimer2");
    pNtSetTimerEx = (FN_NtSetTimerEx)GetProcAddress(Ntdll, "NtSetTimerEx");
    if (!pNtCreateTimer2 || !pNtSetTimer2 || !pNtCancelTimer2 || !pNtSetTimerEx)
    {
        skip("NtCreateTimer2/NtSetTimer2/NtCancelTimer2/NtSetTimerEx not available\n");
        return;
    }

    TestAttributes();
    TestSemantics();
    TestSetAndCancel();
    TestSetTimerEx();
    TestFiringPeriod();
}
