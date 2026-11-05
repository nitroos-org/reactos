/* -*- tab-width: 8; c-basic-offset: 4 -*- */

/*
 * MMSYSTEM time functions
 *
 * Copyright 1993 Martin Ayotte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "winemm.h"
#include <winternl.h>

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

WINE_DEFAULT_DEBUG_CHANNEL(mmtime);

typedef struct tagWINE_TIMERENTRY {
    UINT			wDelay;
    UINT			wResol;
    LPTIMECALLBACK              lpFunc; /* can be lots of things */
    DWORD			dwUser;
    UINT16			wFlags;
    UINT16			wTimerID;
    DWORD			dwTriggerTime;
    struct tagWINE_TIMERENTRY*	lpNext;
} WINE_TIMERENTRY, *LPWINE_TIMERENTRY;

static    HANDLE                TIME_hMMTimer;
static    LPWINE_TIMERENTRY 	TIME_TimersList;
static    HANDLE                TIME_hKillEvent;
static    HANDLE                TIME_hWakeEvent;
static    BOOL                  TIME_TimeToDie = TRUE;
/* The start of KUSER_SHARED_DATA, the page every process maps at 0x7ffe0000: InterruptTime is the time since boot
   in 100 ns units, written by the clock interrupt as High2Time, LowPart, High1Time and read in the opposite order */
typedef struct
{
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    volatile ULONG InterruptTimeLow;
    volatile LONG InterruptTimeHigh1;
    volatile LONG InterruptTimeHigh2;
} TIME_SHARED_DATA;
static const TIME_SHARED_DATA * const TIME_SharedData = (const TIME_SHARED_DATA *)0x7ffe0000;

/*
 * Some observations on the behavior of winmm on Windows.
 *
 * A survey of Event behaviors shows that
 * if we request a Periodic event every 50 ms, then Windows
 * makes sure to trigger that event 20 times in the next
 * second.  If delays prevent that from happening on exact
 * schedule, Windows will trigger the events as close
 * to the original schedule as is possible, and will eventually
 * bring the event triggers back onto a schedule that is
 * consistent with what would have happened if there were
 * no delays.
 *
 *   Jeremy White, October 2004
 */
#define MMSYSTIME_MININTERVAL (1)
#define MMSYSTIME_MAXINTERVAL (1000000)

/* Periods of 1 to 15 ms are counted; a longer one is no finer than the default resolution, so nothing holds it */
#define TIME_MAXHELDPERIOD    (15)

static    UINT                  TIME_PeriodCount[TIME_MAXHELDPERIOD + 1];  /* WINMM_cs */
static    UINT                  TIME_HeldPeriod;  /* period of this process's kernel request, 0 for none; WINMM_cs */


static	void	TIME_TriggerCallBack(LPWINE_TIMERENTRY lpTimer)
{
    TRACE("%04lx:CallBack => lpFunc=%p wTimerID=%04X dwUser=%08lX dwTriggerTime %ld(delta %ld)\n",
	  GetCurrentThreadId(), lpTimer->lpFunc, lpTimer->wTimerID, lpTimer->dwUser,
          lpTimer->dwTriggerTime, GetTickCount() - lpTimer->dwTriggerTime);

    /* - TimeProc callback that is called here is something strange, under Windows 3.1x it is called
     * 		during interrupt time,  is allowed to execute very limited number of API calls (like
     *	    	PostMessage), and must reside in DLL (therefore uses stack of active application). So I
     *       guess current implementation via SetTimer has to be improved upon.
     */
    switch (lpTimer->wFlags & 0x30) {
    case TIME_CALLBACK_FUNCTION:
	    (lpTimer->lpFunc)(lpTimer->wTimerID, 0, lpTimer->dwUser, 0, 0);
	break;
    case TIME_CALLBACK_EVENT_SET:
	SetEvent((HANDLE)lpTimer->lpFunc);
	break;
    case TIME_CALLBACK_EVENT_PULSE:
	PulseEvent((HANDLE)lpTimer->lpFunc);
	break;
    default:
	FIXME("Unknown callback type 0x%04x for mmtime callback (%p), ignored.\n",
	      lpTimer->wFlags, lpTimer->lpFunc);
	break;
    }
}

/**************************************************************************
 *           TIME_MMSysTimeCallback
 */
static DWORD CALLBACK TIME_MMSysTimeCallback()
{
static    int				nSizeLpTimers;
static    LPWINE_TIMERENTRY		lpTimers;

    LPWINE_TIMERENTRY   timer, *ptimer, *next_ptimer;
    int			idx;
    DWORD               cur_time;
    DWORD               delta_time;
    DWORD               ret_time = INFINITE;
    DWORD               adjust_time;


    /* optimize for the most frequent case  - no events */
    if (! TIME_TimersList)
        return(ret_time);

    /* since timeSetEvent() and timeKillEvent() can be called
     * from 16 bit code, there are cases where win16 lock is
     * locked upon entering timeSetEvent(), and then the mm timer
     * critical section is locked. This function cannot call the
     * timer callback with the crit sect locked (because callback
     * may need to acquire Win16 lock, thus providing a deadlock
     * situation).
     * To cope with that, we just copy the WINE_TIMERENTRY struct
     * that need to trigger the callback, and call it without the
     * mm timer crit sect locked.
     * the hKillTimeEvent is used to mark the section where we
     * handle the callbacks so we can do synchronous kills.
     * EPP 99/07/13, updated 04/01/10
     */
    idx = 0;
    cur_time = GetTickCount();

    EnterCriticalSection(&WINMM_cs);
    for (ptimer = &TIME_TimersList; *ptimer != NULL; ) {
        timer = *ptimer;
        next_ptimer = &timer->lpNext;
        /* a signed difference keeps working when the tick count wraps with a long delay pending */
        if ((LONG)(cur_time - timer->dwTriggerTime) >= 0)
        {
            if (timer->lpFunc) {
                if (idx == nSizeLpTimers) {
                    if (lpTimers)
                        lpTimers = (LPWINE_TIMERENTRY)
                            HeapReAlloc(GetProcessHeap(), 0, lpTimers,
                                        ++nSizeLpTimers * sizeof(WINE_TIMERENTRY));
                    else
                        lpTimers = (LPWINE_TIMERENTRY)
                        HeapAlloc(GetProcessHeap(), 0,
                                  ++nSizeLpTimers * sizeof(WINE_TIMERENTRY));
                }
                lpTimers[idx++] = *timer;

            }

            /* Update the time after we make the copy to preserve
               the original trigger time    */
            timer->dwTriggerTime += timer->wDelay;

            /* TIME_ONESHOT is defined as 0 */
            if (!(timer->wFlags & TIME_PERIODIC))
            {
                /* unlink timer from timers list */
                *ptimer = *next_ptimer;
                HeapFree(GetProcessHeap(), 0, timer);

                /* We don't need to trigger oneshots again */
                delta_time = INFINITE;
            }
            else
            {
                /* Compute when this event needs this function
                    to be called again */
                if ((LONG)(timer->dwTriggerTime - cur_time) <= 0)
                    delta_time = 0;
                else
                    delta_time = timer->dwTriggerTime - cur_time;
            }
        }
        else
            delta_time = timer->dwTriggerTime - cur_time;

        /* Determine when we need to return to this function */
        ret_time = min(ret_time, delta_time);

        ptimer = next_ptimer;
    }
    if (TIME_hKillEvent) ResetEvent(TIME_hKillEvent);
    LeaveCriticalSection(&WINMM_cs);

    while (idx > 0) TIME_TriggerCallBack(&lpTimers[--idx]);
    if (TIME_hKillEvent) SetEvent(TIME_hKillEvent);

    /* Finally, adjust the recommended wait time downward
       by the amount of time the processing routines
       actually took */
    adjust_time = GetTickCount() - cur_time;
    if (adjust_time > ret_time)
        ret_time = 0;
    else
        ret_time -= adjust_time;

    /* We return the amount of time our caller should sleep
       before needing to check in on us again       */
    return(ret_time);
}

/**************************************************************************
 *           TIME_MMSysTimeThread
 */
static DWORD CALLBACK TIME_MMSysTimeThread(LPVOID arg)
{
    DWORD sleep_time;
    DWORD rc;

    TRACE("Starting main winmm thread\n");

    /* FIXME:  As an optimization, we could have
               this thread die when there are no more requests
               pending, and then get recreated on the first
               new event; it's not clear if that would be worth
               it or not.                 */

    while (! TIME_TimeToDie)
    {
	sleep_time = TIME_MMSysTimeCallback();

        if (sleep_time == 0)
            continue;

        rc = WaitForSingleObject(TIME_hWakeEvent, sleep_time);
        if (rc != WAIT_TIMEOUT && rc != WAIT_OBJECT_0)
        {
            FIXME("Unexpected error %ld(%ld) in timer thread\n", rc, GetLastError());
            break;
        }
    }
    TRACE("Exiting main winmm thread\n");
    return 0;
}

/**************************************************************************
 * 				TIME_MMTimeStart
 */
void	TIME_MMTimeStart(void)
{
    if (!TIME_hMMTimer) {
	TIME_TimersList = NULL;
        TIME_hWakeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        TIME_TimeToDie = FALSE;
	TIME_hMMTimer = CreateThread(NULL, 0, TIME_MMSysTimeThread, NULL, 0, NULL);
        SetThreadPriority(TIME_hMMTimer, THREAD_PRIORITY_TIME_CRITICAL);
    }
}

/**************************************************************************
 * 				TIME_MMTimeStop
 */
void	TIME_MMTimeStop(void)
{
    if (TIME_hMMTimer) {

        TIME_TimeToDie = TRUE;
        SetEvent(TIME_hWakeEvent);

        /* FIXME: in the worst case, we're going to wait 65 seconds here :-( */
	WaitForSingleObject(TIME_hMMTimer, INFINITE);

	CloseHandle(TIME_hMMTimer);
	CloseHandle(TIME_hWakeEvent);
	TIME_hMMTimer = 0;
        TIME_TimersList = NULL;
    }
}

/**************************************************************************
 * 				timeGetSystemTime	[WINMM.@]
 */
MMRESULT WINAPI timeGetSystemTime(LPMMTIME lpTime, UINT wSize)
{

    /* Windows 10: a size below sizeof(MMTIME) is TIMERR_STRUCT (129), nothing is written */
    if (wSize < sizeof(*lpTime))
        return TIMERR_STRUCT;

    lpTime->wType = TIME_MS;
    lpTime->u.ms = GetTickCount();

    return 0;
}

/**************************************************************************
 * 				TIME_SetEventInternal	[internal]
 */
WORD	TIME_SetEventInternal(UINT wDelay, UINT wResol,
                              LPTIMECALLBACK lpFunc, DWORD dwUser, UINT wFlags)
{
    WORD 		wNewID = 0;
    LPWINE_TIMERENTRY	lpNewTimer;
    LPWINE_TIMERENTRY	lpTimer;

    TRACE("(%u, %u, %p, %08lX, %04X);\n", wDelay, wResol, lpFunc, dwUser, wFlags);

    if (wDelay < MMSYSTIME_MININTERVAL || wDelay > MMSYSTIME_MAXINTERVAL)
	return 0;

    lpNewTimer = HeapAlloc(GetProcessHeap(), 0, sizeof(WINE_TIMERENTRY));
    if (lpNewTimer == NULL)
	return 0;

    TIME_MMTimeStart();

    lpNewTimer->wDelay = wDelay;
    lpNewTimer->dwTriggerTime = GetTickCount() + wDelay;

    /* FIXME - wResol is not respected, although it is not clear
               that we could change our precision meaningfully  */
    lpNewTimer->wResol = wResol;
    lpNewTimer->lpFunc = lpFunc;
    lpNewTimer->dwUser = dwUser;
    lpNewTimer->wFlags = wFlags;

    EnterCriticalSection(&WINMM_cs);

    if ((wFlags & TIME_KILL_SYNCHRONOUS) && !TIME_hKillEvent)
        TIME_hKillEvent = CreateEventW(NULL, TRUE, TRUE, NULL);

    for (lpTimer = TIME_TimersList; lpTimer != NULL; lpTimer = lpTimer->lpNext) {
	wNewID = max(wNewID, lpTimer->wTimerID);
    }

    lpNewTimer->lpNext = TIME_TimersList;
    TIME_TimersList = lpNewTimer;
    lpNewTimer->wTimerID = wNewID + 1;

    LeaveCriticalSection(&WINMM_cs);

    /* Wake the service thread in case there is work to be done */
    SetEvent(TIME_hWakeEvent);

    TRACE("=> %u\n", wNewID + 1);

    return wNewID + 1;
}

/**************************************************************************
 * 				timeSetEvent		[WINMM.@]
 */
MMRESULT WINAPI timeSetEvent(UINT wDelay, UINT wResol, LPTIMECALLBACK lpFunc,
                            DWORD_PTR dwUser, UINT wFlags)
{
    return TIME_SetEventInternal(wDelay, wResol, lpFunc,
                                 dwUser, wFlags);
}

/**************************************************************************
 * 				timeKillEvent		[WINMM.@]
 */
MMRESULT WINAPI timeKillEvent(UINT wID)
{
    LPWINE_TIMERENTRY   lpSelf = NULL, *lpTimer;

    TRACE("(%u)\n", wID);
    EnterCriticalSection(&WINMM_cs);
    /* remove WINE_TIMERENTRY from list */
    for (lpTimer = &TIME_TimersList; *lpTimer; lpTimer = &(*lpTimer)->lpNext) {
	if (wID == (*lpTimer)->wTimerID) {
            lpSelf = *lpTimer;
            /* unlink timer of id 'wID' */
            *lpTimer = (*lpTimer)->lpNext;
	    break;
	}
    }
    LeaveCriticalSection(&WINMM_cs);

    if (!lpSelf)
    {
        WARN("wID=%u is not a valid timer ID\n", wID);
        return MMSYSERR_INVALPARAM;
    }
    if (lpSelf->wFlags & TIME_KILL_SYNCHRONOUS)
        WaitForSingleObject(TIME_hKillEvent, INFINITE);
    HeapFree(GetProcessHeap(), 0, lpSelf);
    return TIMERR_NOERROR;
}

/**************************************************************************
 * 				timeGetDevCaps		[WINMM.@]
 */
MMRESULT WINAPI timeGetDevCaps(LPTIMECAPS lpCaps, UINT wSize)
{
    TRACE("(%p, %u)\n", lpCaps, wSize);

    if (lpCaps == 0) {
        WARN("invalid lpCaps\n");
        return TIMERR_NOCANDO;
    }

    if (wSize < sizeof(TIMECAPS)) {
        WARN("invalid wSize\n");
        return TIMERR_NOCANDO;
    }

    lpCaps->wPeriodMin = MMSYSTIME_MININTERVAL;
    lpCaps->wPeriodMax = MMSYSTIME_MAXINTERVAL;
    return TIMERR_NOERROR;
}

/* The kernel does not coarsen a request by a later one, so a request that gets coarser is released first; WINMM_cs held */
static void TIME_UpdateResolution(void)
{
    UINT finest = 0, i;
    ULONG current;

    for (i = 1; i <= TIME_MAXHELDPERIOD; i++)
    {
        if (TIME_PeriodCount[i])
        {
            finest = i;
            break;
        }
    }

    if (finest != TIME_HeldPeriod)
    {
        if (TIME_HeldPeriod != 0 && (finest == 0 || finest > TIME_HeldPeriod))
        {
            NtSetTimerResolution(0, FALSE, &current);
            TIME_HeldPeriod = 0;
        }
        if (finest != 0 && NtSetTimerResolution(finest * 10000, TRUE, &current) >= 0)
            TIME_HeldPeriod = finest;
    }
}

/**************************************************************************
 * 				TIME_ReleaseResolution	[internal]
 */
void TIME_ReleaseResolution(void)
{
    ULONG current;

    EnterCriticalSection(&WINMM_cs);
    memset(TIME_PeriodCount, 0, sizeof(TIME_PeriodCount));
    if (TIME_HeldPeriod != 0)
    {
        NtSetTimerResolution(0, FALSE, &current);
        TIME_HeldPeriod = 0;
    }
    LeaveCriticalSection(&WINMM_cs);
}

/**************************************************************************
 * 				timeBeginPeriod		[WINMM.@]
 */
MMRESULT WINAPI timeBeginPeriod(UINT wPeriod)
{
    TRACE("(%u)\n", wPeriod);

    if (wPeriod < MMSYSTIME_MININTERVAL)
        return TIMERR_NOCANDO;

    if (wPeriod > TIME_MAXHELDPERIOD)
        return TIMERR_NOERROR;

    EnterCriticalSection(&WINMM_cs);
    if (TIME_PeriodCount[wPeriod] == ~0U)
    {
        LeaveCriticalSection(&WINMM_cs);
        return TIMERR_NOCANDO;
    }
    TIME_PeriodCount[wPeriod]++;
    TIME_UpdateResolution();
    LeaveCriticalSection(&WINMM_cs);

    return TIMERR_NOERROR;
}

/**************************************************************************
 * 				timeEndPeriod		[WINMM.@]
 */
MMRESULT WINAPI timeEndPeriod(UINT wPeriod)
{
    MMRESULT ret = TIMERR_NOERROR;

    TRACE("(%u)\n", wPeriod);

    if (wPeriod < MMSYSTIME_MININTERVAL)
        return TIMERR_NOCANDO;

    if (wPeriod > TIME_MAXHELDPERIOD)
        return TIMERR_NOERROR;

    EnterCriticalSection(&WINMM_cs);
    if (TIME_PeriodCount[wPeriod] == 0)
    {
        ret = TIMERR_NOCANDO;
    }
    else
    {
        TIME_PeriodCount[wPeriod]--;
        TIME_UpdateResolution();
    }
    LeaveCriticalSection(&WINMM_cs);

    return ret;
}

/**************************************************************************
 * 				timeGetTime    [MMSYSTEM.607]
 * 				timeGetTime    [WINMM.@]
 */
DWORD WINAPI timeGetTime(void)
{
    ULONG High, Low;

    /* As on Windows, the interrupt time is the only clock: timeBeginPeriod makes the clock interrupt, and so this
       value, finer, but never switches to another clock. The performance counter (used while a period of 5 ms or
       less was held) and the tick count start at different times, so every timeEndPeriod made the value jump back,
       by seconds on a virtual machine, and Chromium, which builds TimeTicks on it, stopped on a CHECK that its
       timestamps never decrease. */
    do
    {
        High = TIME_SharedData->InterruptTimeHigh1;
        Low = TIME_SharedData->InterruptTimeLow;
    }
    while (High != (ULONG)TIME_SharedData->InterruptTimeHigh2);

    return (DWORD)((((ULONGLONG)High << 32) | Low) / 10000);
}
