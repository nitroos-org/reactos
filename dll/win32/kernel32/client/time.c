/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/time.c
 * PURPOSE:         Time conversion functions
 * PROGRAMMER:      Ariadne
 *                  DOSDATE and DOSTIME structures from Onno Hovers
 * UPDATE HISTORY:
 *                  Created 19/01/99
 */

/* INCLUDES *******************************************************************/

#include <k32.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

/*
 * @implemented
 */
BOOL
WINAPI
IsTimeZoneRedirectionEnabled(VOID)
{
    /* Return if a TS Timezone ID is active */
    return (BaseStaticServerData->TermsrvClientTimeZoneId != TIME_ZONE_ID_INVALID);
}

/*
 * @implemented
 */
BOOL
WINAPI
FileTimeToDosDateTime(IN CONST FILETIME *lpFileTime,
                      OUT LPWORD lpFatDate,
                      OUT LPWORD lpFatTime)
{
    LARGE_INTEGER FileTime;
    TIME_FIELDS TimeFields;

    FileTime.HighPart = lpFileTime->dwHighDateTime;
    FileTime.LowPart = lpFileTime->dwLowDateTime;

    if (FileTime.QuadPart < 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    RtlTimeToTimeFields(&FileTime, &TimeFields);
    if ((TimeFields.Year < 1980) || (TimeFields.Year > 2107))
    {
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    *lpFatDate = (TimeFields.Day) |
                 (TimeFields.Month << 5) |
                 ((TimeFields.Year - 1980) << 9);
    *lpFatTime = (TimeFields.Second >> 1) |
                 (TimeFields.Minute << 5) |
                 (TimeFields.Hour << 11);

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
DosDateTimeToFileTime(IN WORD wFatDate,
                      IN WORD wFatTime,
                      OUT LPFILETIME lpFileTime)
{
    TIME_FIELDS TimeFields;
    LARGE_INTEGER SystemTime;

    TimeFields.Year = (wFatDate >> 9) + 1980;
    TimeFields.Month = (wFatDate >> 5) & 0xF;
    TimeFields.Day = (wFatDate & 0x1F);
    TimeFields.Hour = (wFatTime >> 11);
    TimeFields.Minute = (wFatTime >> 5) & 0x3F;
    TimeFields.Second = (wFatTime & 0x1F) << 1;
    TimeFields.Milliseconds = 0;

    if (RtlTimeFieldsToTime(&TimeFields, &SystemTime))
    {
        lpFileTime->dwLowDateTime = SystemTime.LowPart;
        lpFileTime->dwHighDateTime = SystemTime.HighPart;
        return TRUE;
    }

    BaseSetLastNTError(STATUS_INVALID_PARAMETER);
    return FALSE;
}

/*
 * @implemented
 */
LONG
WINAPI
CompareFileTime(IN CONST FILETIME *lpFileTime1,
                IN CONST FILETIME *lpFileTime2)
{
    LARGE_INTEGER Time1, Time2, Diff;

    Time1.LowPart = lpFileTime1->dwLowDateTime;
    Time2.LowPart = lpFileTime2->dwLowDateTime;
    Time1.HighPart = lpFileTime1->dwHighDateTime;
    Time2.HighPart = lpFileTime2->dwHighDateTime;

    Diff.QuadPart = Time1.QuadPart - Time2.QuadPart;

    if (Diff.HighPart < 0) return -1;
    if (Diff.QuadPart == 0) return 0;
    return 1;
}

/*
 * @implemented
 */
VOID
WINAPI
GetSystemTimeAsFileTime(OUT PFILETIME lpFileTime)
{
    LARGE_INTEGER SystemTime;

    SystemTime = KiReadSystemTime(&SharedUserData->SystemTime);

    lpFileTime->dwLowDateTime = SystemTime.LowPart;
    lpFileTime->dwHighDateTime = SystemTime.HighPart;
}

/*
 * The system time in the shared user data only changes at a clock tick (15.6 ms, whatever shorter interval the timer
 * interrupts have been set to). GetSystemTimePreciseAsFileTime interpolates between ticks with the performance
 * counter: it keeps one anchor (a counter value and the system time that belongs to it) per process and predicts the
 * time from it. The first anchor is taken at a tick edge, where the system time and the counter agree. Every later
 * prediction has to lie in the band the coarse system time allows: not before the coarse time read first, and not
 * later than the coarse time read last plus one tick. A prediction outside the band moves the anchor into it, so a
 * counter that runs at another rate than the tick clock (as in a virtual machine that loses ticks), and a change of
 * the system time, are followed without waiting for another tick edge. The result never goes back by less than a tick.
 *
 * The anchor is read and written without a lock that a caller could wait on: two slots, the version selects the
 * one to read, a writer fills the other one and then publishes the next version, and a writer that finds another
 * one at work, or a version that is no longer the one the anchor was read at, does not write. A caller reads the
 * anchor before it takes its samples of the clocks, so a correction made from samples that are older than the anchor
 * that is current cannot be published.
 */
#define PRECISE_SLACK           20000LL     /* 2 ms in 100 ns: jitter of the tick interrupt */
#define PRECISE_DEFAULT_TICK    156250LL

typedef struct _PRECISE_ANCHOR
{
    LONGLONG Counter;
    LONGLONG Time;
    LONGLONG Tick;
} PRECISE_ANCHOR;

typedef struct _PRECISE_SLOT
{
    volatile LONGLONG Counter;
    volatile LONGLONG Time;
    volatile LONGLONG Tick;
} PRECISE_SLOT;

static PRECISE_SLOT BasepPreciseSlots[2];
static volatile LONGLONG BasepPreciseVersion;   /* 0: no anchor yet; else the slot is Version & 1; never wraps */
static volatile LONG BasepPreciseWriter;
static volatile LONGLONG BasepPreciseLast;

static
LONGLONG
BasepReadCoarseTime(VOID)
{
    LARGE_INTEGER SystemTime;

    SystemTime = KiReadSystemTime(&SharedUserData->SystemTime);
    return SystemTime.QuadPart;
}

/* The system time moves by the biggest increment of the timer (the "minimum resolution"), not by the current one */
static
LONGLONG
BasepQueryTick(VOID)
{
    ULONG Minimum, Maximum, Current;

    if (NT_SUCCESS(NtQueryTimerResolution(&Minimum, &Maximum, &Current)) && Minimum != 0)
        return Minimum;

    return PRECISE_DEFAULT_TICK;
}

static
LONGLONG
BasepPredictPreciseTime(
    _In_ const PRECISE_ANCHOR *Anchor,
    _In_ LONGLONG Counter,
    _In_ LONGLONG Frequency)
{
    LONGLONG Delta = Counter - Anchor->Counter;

    /* Whole seconds first, so that the multiplication cannot overflow after a long time */
    return Anchor->Time + (Delta / Frequency) * 10000000LL + (Delta % Frequency) * 10000000LL / Frequency;
}

/* 1: read the anchor and its version, 0: there is none, -1: it changed all the time */
static
LONG
BasepReadPreciseAnchor(
    _Out_ PRECISE_ANCHOR *Anchor,
    _Out_ PLONGLONG Version)
{
    PRECISE_SLOT *Slot;
    LONGLONG Current;
    ULONG Tries;

    for (Tries = 0; Tries < 16; Tries++)
    {
        Current = InterlockedCompareExchange64(&BasepPreciseVersion, 0, 0);
        *Version = Current;
        if (Current == 0)
            return 0;

        Slot = &BasepPreciseSlots[Current & 1];
        Anchor->Counter = Slot->Counter;
        Anchor->Time = Slot->Time;
        Anchor->Tick = Slot->Tick;
        if (Current == InterlockedCompareExchange64(&BasepPreciseVersion, 0, 0))
            return 1;
    }

    return -1;
}

static
VOID
BasepPublishPreciseAnchor(
    _In_ const PRECISE_ANCHOR *Anchor,
    _In_ LONGLONG ReadVersion)
{
    PRECISE_SLOT *Slot;

    if (InterlockedCompareExchange(&BasepPreciseWriter, 1, 0) != 0)
        return;

    /* Only the successor of the version that the anchor was made from */
    if (InterlockedCompareExchange64(&BasepPreciseVersion, 0, 0) == ReadVersion)
    {
        Slot = &BasepPreciseSlots[(ReadVersion + 1) & 1];
        Slot->Counter = Anchor->Counter;
        Slot->Time = Anchor->Time;
        Slot->Tick = Anchor->Tick;
        InterlockedCompareExchange64(&BasepPreciseVersion, ReadVersion + 1, ReadVersion);
    }

    InterlockedExchange(&BasepPreciseWriter, 0);
}

static
VOID
BasepTakePreciseAnchor(
    _Out_ PRECISE_ANCHOR *Anchor,
    _In_ LONGLONG Frequency)
{
    LARGE_INTEGER Before, After;
    LONGLONG First, Current, PreviousBefore, Limit, MaxWidth = Frequency / 5000;

    /*
     * Wait for the next tick (at most two of them): the tick happened between the reads of the system time of two
     * rounds, so between the counter read before the one and the counter read after the other. A sample over a
     * long time (the thread was preempted) does not say when it was, and the wait goes on for the next tick.
     */
    QueryPerformanceCounter(&Before);
    Limit = Before.QuadPart + Frequency / 25;
    First = BasepReadCoarseTime();
    PreviousBefore = Before.QuadPart;
    QueryPerformanceCounter(&After);
    for (;;)
    {
        QueryPerformanceCounter(&Before);
        Current = BasepReadCoarseTime();
        QueryPerformanceCounter(&After);

        if (Current != First)
        {
            if (After.QuadPart - PreviousBefore <= MaxWidth)
            {
                Anchor->Time = Current;
                Anchor->Counter = PreviousBefore + (After.QuadPart - PreviousBefore) / 2;
                Anchor->Tick = BasepQueryTick();
                return;
            }

            First = Current;
        }

        if (After.QuadPart > Limit)
            break;

        PreviousBefore = Before.QuadPart;
        YieldProcessor();
    }

    /* No tick in time: the system time as it is now, it is moved into place by the calls that follow */
    Anchor->Time = Current;
    Anchor->Counter = Before.QuadPart + (After.QuadPart - Before.QuadPart) / 2;
    Anchor->Tick = BasepQueryTick();
}

/*
 * @implemented
 */
VOID
WINAPI
GetSystemTimePreciseAsFileTime(OUT PFILETIME lpFileTime)
{
    PRECISE_ANCHOR Anchor;
    LARGE_INTEGER Counter, Frequency;
    LONGLONG First, Last, Time, Lower, Upper, Seen, Old, Fresh, Version = 0;
    LONG State;
    ULONG Attempt;

    for (Attempt = 0;; Attempt++)
    {
        /* The anchor first, then the samples that are to be compared to it */
        State = BasepReadPreciseAnchor(&Anchor, &Version);
        if (State == 0 && Attempt < 8)
        {
            /* The first call of the process: take the anchor, then start again so that the samples come after it */
            Frequency.QuadPart = 0;
            QueryPerformanceFrequency(&Frequency);
            if (Frequency.QuadPart > 0)
            {
                BasepTakePreciseAnchor(&Anchor, Frequency.QuadPart);
                BasepPublishPreciseAnchor(&Anchor, 0);
            }
            continue;
        }

        First = BasepReadCoarseTime();
        /* In user mode when the kernel allows (no system call), as Windows does */
        Frequency.QuadPart = 0;
        if (!QueryPerformanceCounter(&Counter) || !QueryPerformanceFrequency(&Frequency) || Frequency.QuadPart <= 0)
        {
            /* No counter: the coarse time is all there is */
            Time = First;
            goto Done;
        }
        Last = BasepReadCoarseTime();

        if (State <= 0)
        {
            /* The anchor is being replaced all the time: the coarse time for this call */
            Time = Last;
            Anchor.Tick = PRECISE_DEFAULT_TICK;
            goto Clamp;
        }

        break;
    }

    Time = BasepPredictPreciseTime(&Anchor, Counter.QuadPart, Frequency.QuadPart);
    Lower = First;
    Upper = Last + Anchor.Tick;

    if (Time < Lower)
    {
        /* The counter runs slower than the tick clock, or the system time was set forward */
        Anchor.Time += Lower - Time;
        Time = Lower;
        BasepPublishPreciseAnchor(&Anchor, Version);
    }
    else if (Time > Upper)
    {
        /* The counter runs faster than the tick clock, or the system time was set back */
        Anchor.Time -= Time - Upper;
        Time = Upper;
        BasepPublishPreciseAnchor(&Anchor, Version);
    }

Clamp:
    /*
     * Never go back. A caller that was preempted after it sampled has an old value and returns the newest one;
     * only a newest value that the system time cannot have reached by now (it was set back) is dropped.
     */
    Seen = InterlockedCompareExchange64(&BasepPreciseLast, 0, 0);
    for (;;)
    {
        if (Time < Seen)
        {
            Fresh = BasepReadCoarseTime();
            if (Seen <= Fresh + Anchor.Tick + 2 * PRECISE_SLACK)
            {
                Time = Seen;
                break;
            }
        }
        else if (Time == Seen)
        {
            break;
        }

        Old = InterlockedCompareExchange64(&BasepPreciseLast, Time, Seen);
        if (Old == Seen)
            break;

        Seen = Old;
    }

Done:
    lpFileTime->dwLowDateTime = (DWORD)Time;
    lpFileTime->dwHighDateTime = (DWORD)(Time >> 32);
}

/*
 * @implemented
 */
BOOL
WINAPI
SystemTimeToFileTime(IN CONST SYSTEMTIME *lpSystemTime,
                     OUT LPFILETIME lpFileTime)
{
    TIME_FIELDS TimeFields;
    LARGE_INTEGER liTime;

    TimeFields.Year = lpSystemTime->wYear;
    TimeFields.Month = lpSystemTime->wMonth;
    TimeFields.Day = lpSystemTime->wDay;
    TimeFields.Hour = lpSystemTime->wHour;
    TimeFields.Minute = lpSystemTime->wMinute;
    TimeFields.Second = lpSystemTime->wSecond;
    TimeFields.Milliseconds = lpSystemTime->wMilliseconds;

    if (RtlTimeFieldsToTime(&TimeFields, &liTime))
    {
        lpFileTime->dwLowDateTime = liTime.u.LowPart;
        lpFileTime->dwHighDateTime = liTime.u.HighPart;
        return TRUE;
    }

    BaseSetLastNTError(STATUS_INVALID_PARAMETER);
    return FALSE;
}

/*
 * @implemented
 */
BOOL
WINAPI
FileTimeToSystemTime(IN CONST FILETIME *lpFileTime,
                     OUT LPSYSTEMTIME lpSystemTime)
{
    TIME_FIELDS TimeFields;
    LARGE_INTEGER liTime;

    liTime.u.LowPart = lpFileTime->dwLowDateTime;
    liTime.u.HighPart = lpFileTime->dwHighDateTime;
    if (liTime.QuadPart < 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    RtlTimeToTimeFields(&liTime, &TimeFields);

    lpSystemTime->wYear = TimeFields.Year;
    lpSystemTime->wMonth = TimeFields.Month;
    lpSystemTime->wDay = TimeFields.Day;
    lpSystemTime->wHour = TimeFields.Hour;
    lpSystemTime->wMinute = TimeFields.Minute;
    lpSystemTime->wSecond = TimeFields.Second;
    lpSystemTime->wMilliseconds = TimeFields.Milliseconds;
    lpSystemTime->wDayOfWeek = TimeFields.Weekday;

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
FileTimeToLocalFileTime(IN CONST FILETIME *lpFileTime,
                        OUT LPFILETIME lpLocalFileTime)
{
    LARGE_INTEGER TimeZoneBias, FileTime;
    volatile KSYSTEM_TIME *TimePtr;

    TimePtr = IsTimeZoneRedirectionEnabled() ?
              &BaseStaticServerData->ktTermsrvClientBias :
              &SharedUserData->TimeZoneBias;

    TimeZoneBias = KiReadSystemTime(TimePtr);

    FileTime.LowPart = lpFileTime->dwLowDateTime;
    FileTime.HighPart = lpFileTime->dwHighDateTime;

    FileTime.QuadPart -= TimeZoneBias.QuadPart;

    lpLocalFileTime->dwLowDateTime = FileTime.LowPart;
    lpLocalFileTime->dwHighDateTime = FileTime.HighPart;

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
LocalFileTimeToFileTime(IN CONST FILETIME *lpLocalFileTime,
                        OUT LPFILETIME lpFileTime)
{
    LARGE_INTEGER TimeZoneBias, FileTime;
    volatile KSYSTEM_TIME *TimePtr;

    TimePtr = IsTimeZoneRedirectionEnabled() ?
              &BaseStaticServerData->ktTermsrvClientBias :
              &SharedUserData->TimeZoneBias;

    TimeZoneBias = KiReadSystemTime(TimePtr);

    FileTime.LowPart = lpLocalFileTime->dwLowDateTime;
    FileTime.HighPart = lpLocalFileTime->dwHighDateTime;

    FileTime.QuadPart += TimeZoneBias.QuadPart;

    lpFileTime->dwLowDateTime = FileTime.LowPart;
    lpFileTime->dwHighDateTime = FileTime.HighPart;

    return TRUE;
}

/*
 * @implemented
 */
VOID
WINAPI
GetLocalTime(OUT LPSYSTEMTIME lpSystemTime)
{
    LARGE_INTEGER SystemTime, TimeZoneBias;
    TIME_FIELDS TimeFields;
    volatile KSYSTEM_TIME *TimePtr;

    SystemTime = KiReadSystemTime(&SharedUserData->SystemTime);

    TimePtr = IsTimeZoneRedirectionEnabled() ?
              &BaseStaticServerData->ktTermsrvClientBias :
              &SharedUserData->TimeZoneBias;

    TimeZoneBias = KiReadSystemTime(TimePtr);

    SystemTime.QuadPart -= TimeZoneBias.QuadPart;
    RtlTimeToTimeFields(&SystemTime, &TimeFields);

    lpSystemTime->wYear = TimeFields.Year;
    lpSystemTime->wMonth = TimeFields.Month;
    lpSystemTime->wDay = TimeFields.Day;
    lpSystemTime->wHour = TimeFields.Hour;
    lpSystemTime->wMinute = TimeFields.Minute;
    lpSystemTime->wSecond = TimeFields.Second;
    lpSystemTime->wMilliseconds = TimeFields.Milliseconds;
    lpSystemTime->wDayOfWeek = TimeFields.Weekday;
}

/*
 * @implemented
 */
VOID
WINAPI
GetSystemTime(OUT LPSYSTEMTIME lpSystemTime)
{
    LARGE_INTEGER SystemTime;
    TIME_FIELDS TimeFields;

    SystemTime = KiReadSystemTime(&SharedUserData->SystemTime);

    RtlTimeToTimeFields(&SystemTime, &TimeFields);

    lpSystemTime->wYear = TimeFields.Year;
    lpSystemTime->wMonth = TimeFields.Month;
    lpSystemTime->wDay = TimeFields.Day;
    lpSystemTime->wHour = TimeFields.Hour;
    lpSystemTime->wMinute = TimeFields.Minute;
    lpSystemTime->wSecond = TimeFields.Second;
    lpSystemTime->wMilliseconds = TimeFields.Milliseconds;
    lpSystemTime->wDayOfWeek = TimeFields.Weekday;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetLocalTime(IN CONST SYSTEMTIME *lpSystemTime)
{
    LARGE_INTEGER NewSystemTime, TimeZoneBias;
    NTSTATUS Status;
    ULONG Privilege = SE_SYSTEMTIME_PRIVILEGE;
    TIME_FIELDS TimeFields;
    PVOID State;
    volatile KSYSTEM_TIME *TimePtr;

    TimePtr = IsTimeZoneRedirectionEnabled() ?
              &BaseStaticServerData->ktTermsrvClientBias :
              &SharedUserData->TimeZoneBias;

    TimeZoneBias = KiReadSystemTime(TimePtr);

    TimeFields.Year = lpSystemTime->wYear;
    TimeFields.Month = lpSystemTime->wMonth;
    TimeFields.Day = lpSystemTime->wDay;
    TimeFields.Hour = lpSystemTime->wHour;
    TimeFields.Minute = lpSystemTime->wMinute;
    TimeFields.Second = lpSystemTime->wSecond;
    TimeFields.Milliseconds = lpSystemTime->wMilliseconds;

    if (!RtlTimeFieldsToTime(&TimeFields, &NewSystemTime))
    {
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    NewSystemTime.QuadPart += TimeZoneBias.QuadPart;

    Status = RtlAcquirePrivilege(&Privilege, 1, 0, &State);
    if (NT_SUCCESS(Status))
    {
        Status = NtSetSystemTime(&NewSystemTime, NULL);
        RtlReleasePrivilege(State);
    }

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetSystemTime(IN CONST SYSTEMTIME *lpSystemTime)
{
    LARGE_INTEGER NewSystemTime;
    NTSTATUS Status;
    ULONG Privilege = SE_SYSTEMTIME_PRIVILEGE;
    TIME_FIELDS TimeFields;
    PVOID State;

    TimeFields.Year = lpSystemTime->wYear;
    TimeFields.Month = lpSystemTime->wMonth;
    TimeFields.Day = lpSystemTime->wDay;
    TimeFields.Hour = lpSystemTime->wHour;
    TimeFields.Minute = lpSystemTime->wMinute;
    TimeFields.Second = lpSystemTime->wSecond;
    TimeFields.Milliseconds = lpSystemTime->wMilliseconds;

    if (!RtlTimeFieldsToTime(&TimeFields, &NewSystemTime))
    {
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    Status = RtlAcquirePrivilege(&Privilege, 1, 0, &State);
    if (NT_SUCCESS(Status))
    {
        Status = NtSetSystemTime(&NewSystemTime, NULL);
        RtlReleasePrivilege(State);
    }

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
DWORD
WINAPI
GetTickCount(VOID)
{
    LARGE_INTEGER TickCount;

    TickCount = KiReadSystemTime(&SharedUserData->TickCount);

    /* Convert to milliseconds */
    return (DWORD)KiTickCountToMs(TickCount);
}

/*
 * @implemented
 */
BOOL
WINAPI
GetSystemTimeAdjustment(OUT PDWORD lpTimeAdjustment,
                        OUT PDWORD lpTimeIncrement,
                        OUT PBOOL lpTimeAdjustmentDisabled)
{
    SYSTEM_QUERY_TIME_ADJUST_INFORMATION TimeInfo;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemTimeAdjustmentInformation,
                                      &TimeInfo,
                                      sizeof(TimeInfo),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    *lpTimeAdjustment = (DWORD)TimeInfo.TimeAdjustment;
    *lpTimeIncrement = (DWORD)TimeInfo.TimeIncrement;
    *lpTimeAdjustmentDisabled = (BOOL)TimeInfo.Enable;

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetSystemTimeAdjustment(IN DWORD dwTimeAdjustment,
                        IN BOOL bTimeAdjustmentDisabled)
{
    NTSTATUS Status;
    SYSTEM_SET_TIME_ADJUST_INFORMATION TimeInfo;

    TimeInfo.TimeAdjustment = (ULONG)dwTimeAdjustment;
    TimeInfo.Enable = (BOOLEAN)bTimeAdjustmentDisabled;

    Status = NtSetSystemInformation(SystemTimeAdjustmentInformation,
                                    &TimeInfo,
                                    sizeof(TimeInfo));
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetSystemTimes(OUT LPFILETIME lpIdleTime OPTIONAL,
               OUT LPFILETIME lpKernelTime OPTIONAL,
               OUT LPFILETIME lpUserTime OPTIONAL)
{
    PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION ProcPerfInfo;
    LARGE_INTEGER TotalUserTime, TotalKernTime, TotalIdleTime;
    ULONG BufferSize, ReturnLength;
    CCHAR i;
    NTSTATUS Status;

    TotalUserTime.QuadPart = TotalKernTime.QuadPart = TotalIdleTime.QuadPart = 0;

    BufferSize = sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) *
                 BaseStaticServerData->SysInfo.NumberOfProcessors;

    ProcPerfInfo = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferSize);
    if (!ProcPerfInfo)
    {
        BaseSetLastNTError(STATUS_NO_MEMORY);
        return FALSE;
    }

    Status = NtQuerySystemInformation(SystemProcessorPerformanceInformation,
                                      ProcPerfInfo,
                                      BufferSize,
                                      &ReturnLength);
    if ((NT_SUCCESS(Status)) && (ReturnLength == BufferSize))
    {
        if (lpIdleTime)
        {
            for (i = 0; i < BaseStaticServerData->SysInfo.NumberOfProcessors; i++)
            {
                TotalIdleTime.QuadPart += ProcPerfInfo[i].IdleTime.QuadPart;
            }

            lpIdleTime->dwLowDateTime = TotalIdleTime.LowPart;
            lpIdleTime->dwHighDateTime = TotalIdleTime.HighPart;
        }

        if (lpKernelTime)
        {
            for (i = 0; i < BaseStaticServerData->SysInfo.NumberOfProcessors; i++)
            {
                TotalKernTime.QuadPart += ProcPerfInfo[i].KernelTime.QuadPart;
            }

            lpKernelTime->dwLowDateTime = TotalKernTime.LowPart;
            lpKernelTime->dwHighDateTime = TotalKernTime.HighPart;
        }

        if (lpUserTime)
        {
            for (i = 0; i < BaseStaticServerData->SysInfo.NumberOfProcessors; i++)
            {
                TotalUserTime.QuadPart += ProcPerfInfo[i].UserTime.QuadPart;
            }

            lpUserTime->dwLowDateTime = TotalUserTime.LowPart;
            lpUserTime->dwHighDateTime = TotalUserTime.HighPart;
        }
    }
    else if (NT_SUCCESS(Status))
    {
         Status = STATUS_INTERNAL_ERROR;
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, ProcPerfInfo);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
SetClientTimeZoneInformation(IN CONST TIME_ZONE_INFORMATION *lpTimeZoneInformation)
{
    STUB;
    return 0;
}

/* EOF */
