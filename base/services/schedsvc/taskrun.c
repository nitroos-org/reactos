/*
 * PROJECT:     ReactOS Services
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Task Scheduler 2.0: run the actions of registered tasks when their triggers fire
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The ITaskSchedulerService server (schrpc.c, from Wine) stores the task XML under
 * %SystemRoot%\System32\Tasks. When a task is registered, the service also records it in
 * HKLM\SYSTEM\CurrentControlSet\Services\Schedule\TaskCache, together with the SID of the
 * caller that registered it and whether that caller was LocalSystem or an administrator.
 * The trigger thread below only runs tasks from that record, never from the files.
 *
 * Identity: a task runs as its principal (Principal/UserId), or as the registering user when
 * it has none. LocalSystem tasks run only when an administrator or LocalSystem registered
 * them; a task registered by anybody else runs only as that same user. A user task needs the
 * user to be logged on: its process gets the token of the user's shell (no stored passwords).
 *
 * Known issue (registry ACLs): the TaskCache record is trusted because only this service is
 * supposed to write it. This kernel does not enforce registry ACLs (every key is effectively
 * Everyone:GENERIC_ALL), so the record protects against callers of the RPC interface, not
 * against a local user who writes the registry directly. Until key ACLs are enforced, a local
 * user can still forge a "Privileged" record.
 *
 * The RPC interface is local only (ncalrpc): remote and anonymous callers are refused, a task can
 * be updated, deleted or read only by whoever registered it or by an administrator, and the
 * request size, the path shape and the number of tasks per user are limited.
 *
 * Triggers: TimeTrigger and CalendarTrigger (ScheduleByDay, ScheduleByWeek, ScheduleByMonth and
 * ScheduleByMonthDayOfWeek, with Repetition, StartBoundary and EndBoundary), LogonTrigger and
 * BootTrigger (with Delay). A calendar trigger runs at the time of day of its StartBoundary on the
 * days its schedule picks, counted on the calendar of the zone of the StartBoundary: the machine's
 * local time, daylight saving included, when the StartBoundary has no zone. The other trigger types
 * (idle, event, session state change, registration) are kept in the task as registered and never
 * run: as on Windows for a trigger that has no time, the task has no next run time.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#define COBJMACROS

#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <objbase.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <rpc.h>
#include <lm.h>
#include <pseh/pseh2.h>
#include <xmllite.h>
#include <taskschd.h>

#include <wine/debug.h>
#include <wine/list.h>

#include "schedsvc_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(schedsvc);

DWORD TaskSchedulerStart(VOID);
VOID TaskSchedulerStop(VOID);

#define TASKCACHE_KEY L"SYSTEM\\CurrentControlSet\\Services\\Schedule\\TaskCache"

#define TICKS_PER_SECOND 10000000ULL
#define NO_TIME (~0ULL)
#define MAX_TRIGGERS 32
#define MAX_ACTIONS 32
#define MAX_DEPTH 16
/* boot triggers, and logons that predate the service, only count this soon after boot */
/* limits on what a caller may register */
#define MAX_XML_BYTES (64 * 1024)
#define MAX_TASK_PATH 238
#define MAX_COMPONENT 255
#define MAX_PATH_DEPTH 16
#define MAX_TASKS_PER_USER 64
#define MAX_TASKS_TOTAL 1024
#define MAX_FOLDERS_PER_USER 32
#define MAX_FOLDERS_TOTAL 256
#define FOLDERS_KEY L"SYSTEM\\CurrentControlSet\\Services\\Schedule\\TaskFolders"
#define MAX_INSTANCES 64
/* the longest period, delay or repetition kept; longer ones are clamped */
#define MAX_SECONDS (100ULL * 365 * 86400)
#define MIN_REPETITION_SECONDS 60
#define MAX_DAYS_INTERVAL 36500
#define BOOT_WINDOW_MS (10 * 60 * 1000)
#define LOGON_POLL_MS 5000
#define MAX_WAIT_MS 60000

struct trigger
{
    TASK_TRIGGER_TYPE2 type;
    BOOL supported;
    BOOL enabled;
    ULONGLONG start;        /* UTC, 0 if absent */
    ULONGLONG end;          /* UTC, 0 if absent */
    ULONGLONG period;       /* CalendarTrigger/ScheduleByDay */
    /* the StartBoundary as its own zone reads it, for the calendar triggers */
    BOOL start_local;       /* no zone: the local time of the machine */
    LONGLONG start_offset;  /* with a zone: its offset east of UTC, in 100 ns */
    LONGLONG start_day;     /* days since 1970-01-01 */
    LONG start_secs;        /* time of day */
    /* ScheduleByWeek, ScheduleByMonth, ScheduleByMonthDayOfWeek */
    unsigned int days_of_week;      /* bit 0 = Sunday */
    unsigned int weeks_interval;
    unsigned int months;            /* bit 0 = January */
    unsigned int days_of_month;     /* bit 0 = day 1 */
    unsigned int weeks;             /* bit 0 = first week */
    BOOL run_last;                  /* the last day, or the last week, of the month */
    ULONGLONG rep_interval;
    ULONGLONG rep_duration;
    ULONGLONG delay;
    WCHAR *user_id;         /* LogonTrigger */
};

struct action
{
    WCHAR *command;
    WCHAR *arguments;
    WCHAR *directory;
};

struct task
{
    struct list entry;
    WCHAR *path;
    PSID registrant;        /* NULL if unknown */
    BOOL privileged;        /* registered by LocalSystem or an administrator */
    BOOL enabled;
    BOOL s4u;               /* Principal/LogonType S4U: no logged-on user needed, no password */
    WCHAR *user_id;         /* Principal/UserId */
    unsigned int n_triggers;
    unsigned int n_actions;
    struct trigger triggers[MAX_TRIGGERS];
    struct action actions[MAX_ACTIONS];
    ULONGLONG pending;      /* a delayed logon or boot start, NO_TIME if none */
    HANDLE process;         /* the last instance, to skip a start while it still runs */
};

struct logon
{
    LUID id;
    BOOL alive;
};

static struct list tasks = LIST_INIT(tasks);
static struct logon logons[64];
static unsigned int n_logons;
static HANDLE stop_event, update_event, scheduler_thread;
static CRITICAL_SECTION *store_cs, *changes_cs;
static CRITICAL_SECTION *get_cs(CRITICAL_SECTION **slot);

static ULONGLONG get_time(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

static WCHAR *strdupW(const WCHAR *str)
{
    return str ? wcsdup(str) : NULL;
}

/* the date and time of a boundary as they are written, for the calendar triggers */
struct boundary
{
    BOOL local;
    LONGLONG offset;
    LONGLONG day;
    LONG secs;
};

static LONGLONG days_from_civil(int y, int m, int d);

/* "YYYY-MM-DDTHH:MM:SS[.fff][Z|+HH:MM|-HH:MM]"; no zone means local time */
static BOOL parse_datetime(const WCHAR *str, ULONGLONG *time, struct boundary *fields)
{
    SYSTEMTIME st = {0}, utc;
    FILETIME ft;
    int year, month, day, hour = 0, minute = 0, second = 0, n = 0;
    LONGLONG offset = 0;
    BOOL zone = FALSE;
    const WCHAR *p;

    if (swscanf(str, L"%4d-%2d-%2dT%2d:%2d:%2d%n", &year, &month, &day, &hour, &minute, &second, &n) < 6 ||
        !n)
    {
        WARN("unsupported date %s\n", debugstr_w(str));
        return FALSE;
    }
    p = str + n;
    if (*p == '.')
        for (p++; *p >= '0' && *p <= '9'; p++);
    if (*p == 'Z')
        zone = TRUE;
    else if (*p == '+' || *p == '-')
    {
        int oh = 0, om = 0;
        if (swscanf(p + 1, L"%2d:%2d", &oh, &om) < 1) return FALSE;
        offset = (LONGLONG)(oh * 60 + om) * 60 * TICKS_PER_SECOND;
        if (*p == '-') offset = -offset;
        zone = TRUE;
    }

    st.wYear = year;
    st.wMonth = month;
    st.wDay = day;
    st.wHour = hour;
    st.wMinute = minute;
    st.wSecond = second;
    if (fields)
    {
        fields->local = !zone;
        fields->offset = offset;
        fields->secs = hour * 3600 + minute * 60 + second;
        fields->day = days_from_civil(year, month, day);
    }
    if (!zone)
    {
        if (!TzSpecificLocalTimeToSystemTime(NULL, &st, &utc)) return FALSE;
        st = utc;
    }
    if (!SystemTimeToFileTime(&st, &ft)) return FALSE;
    *time = (((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime) - offset;
    return TRUE;
}

/* seconds + n * unit, saturating at MAX_SECONDS */
static ULONGLONG add_seconds(ULONGLONG seconds, ULONGLONG n, ULONGLONG unit)
{
    if (n > MAX_SECONDS / unit) return MAX_SECONDS;
    seconds += n * unit;
    return seconds > MAX_SECONDS ? MAX_SECONDS : seconds;
}

/* ISO 8601 duration "PnYnMnWnDTnHnMnS", in 100 ns units; 0 if invalid; clamped to MAX_SECONDS */
static ULONGLONG parse_duration(const WCHAR *str)
{
    ULONGLONG seconds = 0, n;
    BOOL time_part = FALSE;
    WCHAR *end;

    if (*str++ != 'P') return 0;
    while (*str)
    {
        if (*str == 'T')
        {
            time_part = TRUE;
            str++;
            continue;
        }
        /* digits only: wcstoul takes a sign, and a negative number must not wrap */
        if (*str < '0' || *str > '9') return 0;
        n = wcstoul(str, &end, 10);
        if (end == str) return 0;
        str = end;
        switch (*str++)
        {
        case 'Y': seconds = add_seconds(seconds, n, 365 * 86400); break;
        case 'M': seconds = add_seconds(seconds, n, time_part ? 60 : 30 * 86400); break;
        case 'W': seconds = add_seconds(seconds, n, 7 * 86400); break;
        case 'D': seconds = add_seconds(seconds, n, 86400); break;
        case 'H': seconds = add_seconds(seconds, n, 3600); break;
        case 'S': seconds = add_seconds(seconds, n, 1); break;
        default: return 0;
        }
    }
    return seconds * TICKS_PER_SECOND;
}

static BOOL parse_bool(const WCHAR *str)
{
    return !wcscmp(str, L"true") || !wcscmp(str, L"1");
}

/* Calendar arithmetic for the calendar triggers: days are counted since 1970-01-01 on the
 * calendar of the zone of the trigger's StartBoundary. */

/* the proleptic Gregorian calendar, after H. Hinnant's days_from_civil */
static LONGLONG days_from_civil(int y, int m, int d)
{
    LONGLONG era, yoe, doy, doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static void civil_from_days(LONGLONG z, int *year, int *month, int *day)
{
    LONGLONG era, doe, yoe, y, doy, mp;

    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    *day = (int)(doy - (153 * mp + 2) / 5 + 1);
    *month = (int)(mp < 10 ? mp + 3 : mp - 9);
    *year = (int)(y + (*month <= 2));
}

static int days_in_month(int year, int month)
{
    static const int days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    if (month == 2 && ((year % 4 == 0 && year % 100) || year % 400 == 0)) return 29;
    return days[(month - 1) % 12];
}

/* 0 = Sunday; 1970-01-01 was a Thursday */
static int weekday_of(LONGLONG day)
{
    LONGLONG w = (day + 4) % 7;

    return (int)(w < 0 ? w + 7 : w);
}

#define EPOCH_DIFF_SECONDS 11644473600LL
#define MIN_CALENDAR_YEAR 1601
#define MAX_CALENDAR_YEAR 30000
/* a calendar trigger looks this far ahead of its start (a 29th of February, and then some) */
#define MAX_CALENDAR_DAYS 40000

/* the day of a time in the zone of the trigger's StartBoundary */
static BOOL calendar_day_of(const struct trigger *trigger, ULONGLONG time, LONGLONG *day)
{
    FILETIME ft;
    SYSTEMTIME utc, local;
    LONGLONG secs;

    if (!trigger->start_local)
    {
        secs = (LONGLONG)(time / TICKS_PER_SECOND) - EPOCH_DIFF_SECONDS + trigger->start_offset / (LONGLONG)TICKS_PER_SECOND;
        *day = secs >= 0 ? secs / 86400 : -((-secs + 86399) / 86400);
        return TRUE;
    }
    ft.dwLowDateTime = (DWORD)time;
    ft.dwHighDateTime = (DWORD)(time >> 32);
    if (!FileTimeToSystemTime(&ft, &utc) || !SystemTimeToTzSpecificLocalTime(NULL, &utc, &local)) return FALSE;
    *day = days_from_civil(local.wYear, local.wMonth, local.wDay);
    return TRUE;
}

/* the time (UTC) at which a day of the trigger's calendar has the time of day of its StartBoundary;
 * a local time that the clock skips or repeats at a daylight saving change is what the system makes of it */
static ULONGLONG calendar_time_of(const struct trigger *trigger, LONGLONG day)
{
    SYSTEMTIME local, utc;
    FILETIME ft;
    LONGLONG secs;
    int y, m, d;

    civil_from_days(day, &y, &m, &d);
    if (y < MIN_CALENDAR_YEAR || y > MAX_CALENDAR_YEAR) return NO_TIME;

    if (!trigger->start_local)
    {
        secs = day * 86400 + trigger->start_secs + EPOCH_DIFF_SECONDS - trigger->start_offset / (LONGLONG)TICKS_PER_SECOND;
        return secs <= 0 ? NO_TIME : (ULONGLONG)secs * TICKS_PER_SECOND;
    }

    memset(&local, 0, sizeof(local));
    local.wYear = y;
    local.wMonth = m;
    local.wDay = d;
    local.wHour = trigger->start_secs / 3600;
    local.wMinute = trigger->start_secs / 60 % 60;
    local.wSecond = trigger->start_secs % 60;
    if (!TzSpecificLocalTimeToSystemTime(NULL, &local, &utc) || !SystemTimeToFileTime(&utc, &ft)) return NO_TIME;
    return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

/* does the schedule of a calendar trigger pick this day of its calendar */
static BOOL calendar_day_matches(const struct trigger *trigger, LONGLONG day)
{
    int year, month, mday, dim, wday = weekday_of(day);
    unsigned int interval;
    LONGLONG weeks;

    if (day < trigger->start_day) return FALSE;
    civil_from_days(day, &year, &month, &mday);
    dim = days_in_month(year, month);

    switch (trigger->type)
    {
    case TASK_TRIGGER_DAILY:
        return !((day - trigger->start_day) % (LONGLONG)(trigger->period / (86400 * TICKS_PER_SECOND)));

    case TASK_TRIGGER_WEEKLY:
        if (!(trigger->days_of_week & (1u << wday))) return FALSE;
        /* the weeks count from the one the StartBoundary is in, a week starts on Sunday */
        interval = trigger->weeks_interval ? trigger->weeks_interval : 1;
        weeks = ((day - wday) - (trigger->start_day - weekday_of(trigger->start_day))) / 7;
        return !(weeks % interval);

    case TASK_TRIGGER_MONTHLY:
        if (!(trigger->months & (1u << (month - 1)))) return FALSE;
        if (trigger->days_of_month & (1u << (mday - 1))) return TRUE;
        return trigger->run_last && mday == dim;

    case TASK_TRIGGER_MONTHLYDOW:
        if (!(trigger->months & (1u << (month - 1))) || !(trigger->days_of_week & (1u << wday))) return FALSE;
        if ((mday - 1) / 7 < 4 && (trigger->weeks & (1u << ((mday - 1) / 7)))) return TRUE;
        return trigger->run_last && mday + 7 > dim;

    default:
        return FALSE;
    }
}

/* the first run of a calendar trigger strictly after 'after', NO_TIME if none: the first day of the
 * schedule after it, and the repetition of the day before, which may reach past midnight */
static ULONGLONG calendar_next_run(const struct trigger *trigger, ULONGLONG after)
{
    ULONGLONG prev = NO_TIME, base, next = NO_TIME, rep, j;
    LONGLONG day, first, limit, today;

    first = trigger->start_day;
    limit = first + MAX_CALENDAR_DAYS;
    /* without a repetition nothing before the day of 'after' (less a day of zone) matters */
    if (!trigger->rep_interval && calendar_day_of(trigger, after, &today) && today - 1 > first)
        first = today - 1;
    else if (trigger->rep_interval && trigger->rep_duration && calendar_day_of(trigger, after, &today) &&
             today - 2 - (LONGLONG)(trigger->rep_duration / (86400 * TICKS_PER_SECOND)) > first)
        first = today - 2 - (LONGLONG)(trigger->rep_duration / (86400 * TICKS_PER_SECOND));
    if (limit < first + MAX_CALENDAR_DAYS) limit = first + MAX_CALENDAR_DAYS;

    for (day = first; day <= limit; day++)
    {
        if (!calendar_day_matches(trigger, day)) continue;
        if ((base = calendar_time_of(trigger, day)) == NO_TIME) continue;
        if (trigger->end && base > trigger->end) break;
        if (base <= after) { prev = base; continue; }
        next = base;
        break;
    }

    if (prev != NO_TIME && trigger->rep_interval)
    {
        j = (after - prev) / trigger->rep_interval + 1;
        if (!trigger->rep_duration || j * trigger->rep_interval < trigger->rep_duration)
        {
            rep = prev + j * trigger->rep_interval;
            if (rep < next) next = rep;
        }
    }
    if (trigger->end && next != NO_TIME && next > trigger->end) return NO_TIME;
    return next;
}

/* the first run of a time-based trigger strictly after 'after', NO_TIME if none */
static ULONGLONG trigger_next_run(const struct trigger *trigger, ULONGLONG after)
{
    ULONGLONG base, next, j;

    if (!trigger->supported || !trigger->enabled || !trigger->start) return NO_TIME;
    if (trigger->type == TASK_TRIGGER_WEEKLY || trigger->type == TASK_TRIGGER_MONTHLY ||
        trigger->type == TASK_TRIGGER_MONTHLYDOW)
        return calendar_next_run(trigger, after);
    if (trigger->type != TASK_TRIGGER_TIME && trigger->type != TASK_TRIGGER_DAILY) return NO_TIME;
    /* the period and the interval divide below: a task must never get a zero one */
    if (trigger->type == TASK_TRIGGER_DAILY && !trigger->period) return NO_TIME;
    /* a daily trigger on the local clock keeps its time of day through a daylight saving change */
    if (trigger->type == TASK_TRIGGER_DAILY && trigger->start_local) return calendar_next_run(trigger, after);

    if (after < trigger->start)
        next = trigger->start;
    else
    {
        base = trigger->start;
        if (trigger->type == TASK_TRIGGER_DAILY)
            base += (after - trigger->start) / trigger->period * trigger->period;

        next = NO_TIME;
        if (trigger->rep_interval)
        {
            j = (after - base) / trigger->rep_interval + 1;
            if (!trigger->rep_duration || j * trigger->rep_interval < trigger->rep_duration)
                next = base + j * trigger->rep_interval;
        }
        if (trigger->type == TASK_TRIGGER_DAILY && base + trigger->period < next)
            next = base + trigger->period;
    }

    if (trigger->end && next != NO_TIME && next > trigger->end) return NO_TIME;
    return next;
}

static void free_task(struct task *task)
{
    unsigned int i;

    for (i = 0; i < task->n_triggers; i++)
        free(task->triggers[i].user_id);
    for (i = 0; i < task->n_actions; i++)
    {
        free(task->actions[i].command);
        free(task->actions[i].arguments);
        free(task->actions[i].directory);
    }
    free(task->path);
    free(task->user_id);
    LocalFree(task->registrant);
    if (task->process) CloseHandle(task->process);
    free(task);
}

static struct trigger *current_trigger(struct task *task)
{
    return task->n_triggers ? &task->triggers[task->n_triggers - 1] : NULL;
}

static struct action *current_action(struct task *task)
{
    return task->n_actions ? &task->actions[task->n_actions - 1] : NULL;
}

/* an element opened; names[] is its path below the document, names[0] = "Task" */
static void begin_element(struct task *task, const WCHAR **names, unsigned int depth)
{
    static const struct { const WCHAR *name; TASK_TRIGGER_TYPE2 type; BOOL supported; } trigger_types[] =
    {
        { L"TimeTrigger", TASK_TRIGGER_TIME, TRUE },
        { L"CalendarTrigger", TASK_TRIGGER_DAILY, TRUE },
        { L"LogonTrigger", TASK_TRIGGER_LOGON, TRUE },
        { L"BootTrigger", TASK_TRIGGER_BOOT, TRUE },
        { L"IdleTrigger", TASK_TRIGGER_IDLE, FALSE },
        { L"RegistrationTrigger", TASK_TRIGGER_REGISTRATION, FALSE },
        { L"EventTrigger", TASK_TRIGGER_EVENT, FALSE },
        { L"SessionStateChangeTrigger", TASK_TRIGGER_SESSION_STATE_CHANGE, FALSE },
    };
    struct trigger *trigger;
    unsigned int i;

    if (depth == 3 && !wcscmp(names[1], L"Triggers"))
    {
        if (task->n_triggers >= MAX_TRIGGERS)
        {
            FIXME("too many triggers in %s\n", debugstr_w(task->path));
            return;
        }
        trigger = &task->triggers[task->n_triggers++];
        memset(trigger, 0, sizeof(*trigger));
        trigger->enabled = TRUE;
        trigger->type = TASK_TRIGGER_TIME;
        trigger->period = 86400 * TICKS_PER_SECOND;
        for (i = 0; i < ARRAYSIZE(trigger_types); i++)
        {
            if (wcscmp(names[2], trigger_types[i].name)) continue;
            trigger->type = trigger_types[i].type;
            trigger->supported = trigger_types[i].supported;
            break;
        }
        if (!trigger->supported)
            FIXME("%s: %s is not supported\n", debugstr_w(task->path), debugstr_w(names[2]));
    }
    else if (depth == 4 && !wcscmp(names[1], L"Triggers") && !wcscmp(names[2], L"CalendarTrigger") &&
             wcscmp(names[3], L"ScheduleByDay") && !wcsncmp(names[3], L"ScheduleBy", 10))
    {
        if (!(trigger = current_trigger(task))) return;
        if (!wcscmp(names[3], L"ScheduleByWeek"))
        {
            trigger->type = TASK_TRIGGER_WEEKLY;
            trigger->weeks_interval = 1;
        }
        else if (!wcscmp(names[3], L"ScheduleByMonth")) trigger->type = TASK_TRIGGER_MONTHLY;
        else if (!wcscmp(names[3], L"ScheduleByMonthDayOfWeek")) trigger->type = TASK_TRIGGER_MONTHLYDOW;
        else
        {
            FIXME("%s: CalendarTrigger/%s is not supported\n", debugstr_w(task->path), debugstr_w(names[3]));
            trigger->supported = FALSE;
        }
    }
    else if (depth == 6 && !wcscmp(names[1], L"Triggers") && !wcscmp(names[2], L"CalendarTrigger") &&
             (trigger = current_trigger(task)) &&
             ((trigger->type == TASK_TRIGGER_WEEKLY && !wcscmp(names[4], L"DaysOfWeek")) ||
              (trigger->type == TASK_TRIGGER_MONTHLYDOW && !wcscmp(names[4], L"DaysOfWeek")) ||
              (trigger->type != TASK_TRIGGER_WEEKLY && !wcscmp(names[4], L"Months"))))
    {
        static const WCHAR *const days[7] = { L"Sunday", L"Monday", L"Tuesday", L"Wednesday", L"Thursday", L"Friday", L"Saturday" };
        static const WCHAR *const months[12] = { L"January", L"February", L"March", L"April", L"May", L"June", L"July",
                                                 L"August", L"September", L"October", L"November", L"December" };
        BOOL is_day = !wcscmp(names[4], L"DaysOfWeek");
        const WCHAR *const *list = is_day ? days : months;
        unsigned int n = is_day ? 7 : 12;

        for (i = 0; i < n; i++)
        {
            if (wcscmp(names[5], list[i])) continue;
            if (is_day) trigger->days_of_week |= 1u << i;
            else trigger->months |= 1u << i;
            return;
        }
        FIXME("%s: unknown name %s\n", debugstr_w(task->path), debugstr_w(names[5]));
        trigger->supported = FALSE;
    }
    else if (depth == 3 && !wcscmp(names[1], L"Actions"))
    {
        if (wcscmp(names[2], L"Exec"))
        {
            FIXME("%s: action %s is not supported\n", debugstr_w(task->path), debugstr_w(names[2]));
            return;
        }
        if (task->n_actions >= MAX_ACTIONS)
        {
            FIXME("too many actions in %s\n", debugstr_w(task->path));
            return;
        }
        memset(&task->actions[task->n_actions++], 0, sizeof(task->actions[0]));
    }
}

static void element_text(struct task *task, const WCHAR **names, unsigned int depth, const WCHAR *value)
{
    struct trigger *trigger;
    struct action *action;
    const WCHAR *name = names[depth - 1];

    if (depth == 3 && !wcscmp(names[1], L"Settings"))
    {
        if (!wcscmp(name, L"Enabled")) task->enabled = parse_bool(value);
    }
    else if (depth == 4 && !wcscmp(names[1], L"Principals") && !wcscmp(names[2], L"Principal"))
    {
        if (!wcscmp(name, L"UserId"))
        {
            free(task->user_id);
            task->user_id = strdupW(value);
        }
        else if (!wcscmp(name, L"LogonType"))
            task->s4u = !wcsicmp(value, L"S4U");
    }
    else if (depth >= 4 && !wcscmp(names[1], L"Triggers") && (trigger = current_trigger(task)))
    {
        if (depth == 4)
        {
            if (!wcscmp(name, L"Enabled")) trigger->enabled = parse_bool(value);
            else if (!wcscmp(name, L"StartBoundary"))
            {
                struct boundary b;

                if (!parse_datetime(value, &trigger->start, &b)) trigger->supported = FALSE;
                else
                {
                    trigger->start_local = b.local;
                    trigger->start_offset = b.offset;
                    trigger->start_day = b.day;
                    trigger->start_secs = b.secs;
                }
            }
            else if (!wcscmp(name, L"EndBoundary"))
            {
                /* an end that cannot be read must not leave the trigger without one */
                if (!parse_datetime(value, &trigger->end, NULL)) trigger->supported = FALSE;
            }
            else if (!wcscmp(name, L"Delay")) trigger->delay = parse_duration(value);
            else if (!wcscmp(name, L"UserId"))
            {
                free(trigger->user_id);
                trigger->user_id = strdupW(value);
            }
        }
        else if (depth == 5 && !wcscmp(names[3], L"Repetition"))
        {
            if (!wcscmp(name, L"Interval"))
            {
                trigger->rep_interval = parse_duration(value);
                /* Windows refuses an interval below one minute */
                if (trigger->rep_interval && trigger->rep_interval < MIN_REPETITION_SECONDS * TICKS_PER_SECOND)
                    trigger->rep_interval = MIN_REPETITION_SECONDS * TICKS_PER_SECOND;
            }
            else if (!wcscmp(name, L"Duration")) trigger->rep_duration = parse_duration(value);
        }
        else if (depth == 5 && !wcscmp(names[3], L"ScheduleByWeek") && !wcscmp(name, L"WeeksInterval"))
        {
            LONGLONG weeks = _wtoi64(value);

            if (weeks < 1 || weeks > 52) trigger->supported = FALSE;
            else trigger->weeks_interval = (unsigned int)weeks;
        }
        else if (depth == 6 && !wcscmp(names[3], L"ScheduleByMonth") && !wcscmp(names[4], L"DaysOfMonth") &&
                 !wcscmp(name, L"Day"))
        {
            LONGLONG day = _wtoi64(value);

            if (!wcscmp(value, L"Last")) trigger->run_last = TRUE;
            else if (day >= 1 && day <= 31) trigger->days_of_month |= 1u << (day - 1);
            else trigger->supported = FALSE;
        }
        else if (depth == 6 && !wcscmp(names[3], L"ScheduleByMonthDayOfWeek") && !wcscmp(names[4], L"Weeks") &&
                 !wcscmp(name, L"Week"))
        {
            LONGLONG week = _wtoi64(value);

            if (!wcscmp(value, L"Last")) trigger->run_last = TRUE;
            else if (week >= 1 && week <= 4) trigger->weeks |= 1u << (week - 1);
            else trigger->supported = FALSE;
        }
        else if (depth == 5 && !wcscmp(names[3], L"ScheduleByDay") && !wcscmp(name, L"DaysInterval"))
        {
            /* 64-bit math: days * 86400 wrapped an int to 0 and the period divided by it */
            LONGLONG days = _wtoi64(value);
            if (days > MAX_DAYS_INTERVAL) days = MAX_DAYS_INTERVAL;
            if (days > 0) trigger->period = (ULONGLONG)days * 86400 * TICKS_PER_SECOND;
        }
    }
    else if (depth == 4 && !wcscmp(names[1], L"Actions") && !wcscmp(names[2], L"Exec") &&
             (action = current_action(task)))
    {
        if (!wcscmp(name, L"Command"))
        {
            free(action->command);
            action->command = strdupW(value);
        }
        else if (!wcscmp(name, L"Arguments"))
        {
            free(action->arguments);
            action->arguments = strdupW(value);
        }
        else if (!wcscmp(name, L"WorkingDirectory"))
        {
            free(action->directory);
            action->directory = strdupW(value);
        }
    }
}

/* the filter of the guards around the XML parser: log where it faulted, then fail the parse */
LONG schedsvc_log_fault(EXCEPTION_POINTERS *info)
{
    const EXCEPTION_RECORD *rec = info->ExceptionRecord;
    WCHAR module[MAX_PATH] = L"?";
    HMODULE base = NULL;

    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           rec->ExceptionAddress, &base))
        GetModuleFileNameW(base, module, ARRAYSIZE(module));
    ERR("the XML parser faulted: %#lx at %p in %s, offset %#lx (%lu %p)\n", rec->ExceptionCode, rec->ExceptionAddress,
        debugstr_w(module), (DWORD)((char *)rec->ExceptionAddress - (char *)base),
        rec->NumberParameters > 0 ? (DWORD)rec->ExceptionInformation[0] : 0,
        rec->NumberParameters > 1 ? (void *)rec->ExceptionInformation[1] : NULL);
    return EXCEPTION_EXECUTE_HANDLER;
}

struct parse_state
{
    WCHAR *names[MAX_DEPTH];
    unsigned int depth, skip;
    BOOL root;
};

/* reads every node; the elements go to begin_element and element_text */
static HRESULT parse_nodes(struct task *task, IXmlReader *reader, struct parse_state *state)
{
    XmlNodeType type;
    const WCHAR *name, *value;
    HRESULT hr = S_OK, read = S_OK;

    while (SUCCEEDED(hr) && (read = IXmlReader_Read(reader, &type)) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_Element:
        {
            BOOL empty = IXmlReader_IsEmptyElement(reader);

            if (FAILED(hr = IXmlReader_GetLocalName(reader, &name, NULL))) break;
            if (state->skip || state->depth >= MAX_DEPTH)
            {
                if (!empty) state->skip++;
                break;
            }
            if (!(state->names[state->depth] = wcsdup(name)))
            {
                hr = E_OUTOFMEMORY;
                break;
            }
            state->depth++;
            state->root = TRUE;
            if (wcscmp(state->names[0], L"Task"))
            {
                hr = SCHED_E_MALFORMEDXML;
                break;
            }
            begin_element(task, (const WCHAR **)state->names, state->depth);
            if (empty) free(state->names[--state->depth]);
            break;
        }
        case XmlNodeType_EndElement:
            if (state->skip) state->skip--;
            else if (state->depth) free(state->names[--state->depth]);
            break;

        case XmlNodeType_Text:
        case XmlNodeType_CDATA:
            if (state->skip || !state->depth) break;
            if (FAILED(hr = IXmlReader_GetValue(reader, &value, NULL))) break;
            element_text(task, (const WCHAR **)state->names, state->depth, value);
            break;

        default:
            break;
        }
    }
    /* the document has to end where a document ends, and have a root element */
    if (SUCCEEDED(hr) && (read != S_FALSE || state->depth || !state->root)) hr = SCHED_E_MALFORMEDXML;
    return hr;
}

/*
 * An in-memory stream of the XML as UTF-8, without its XML declaration. xmllite reads UTF-8 in
 * chunks reliably; its UTF-16 input keeps the raw chunks and copies them again with every read,
 * which breaks a document longer than one chunk (and wrote past its buffer on 60 KB of comment).
 */
HRESULT schedsvc_open_xml(const WCHAR *xml, IStream **stream)
{
    HGLOBAL hmem;
    ULARGE_INTEGER len;
    int size;
    char *utf8;
    HRESULT hr;

    if (*xml == 0xfeff) xml++;
    if (!wcsncmp(xml, L"<?xml", 5))
    {
        const WCHAR *end = wcsstr(xml, L"?>");
        if (end) xml = end + 2;
    }

    size = WideCharToMultiByte(CP_UTF8, 0, xml, -1, NULL, 0, NULL, NULL);
    if (size <= 0) return HRESULT_FROM_WIN32(GetLastError());
    if (!(hmem = GlobalAlloc(GMEM_MOVEABLE, size))) return E_OUTOFMEMORY;
    if (!(utf8 = GlobalLock(hmem)))
    {
        GlobalFree(hmem);
        return E_OUTOFMEMORY;
    }
    WideCharToMultiByte(CP_UTF8, 0, xml, -1, utf8, size, NULL, NULL);
    GlobalUnlock(hmem);

    hr = CreateStreamOnHGlobal(hmem, TRUE, stream);
    if (FAILED(hr))
    {
        GlobalFree(hmem);
        return hr;
    }
    /* without the terminator, and not as long as the buffer GlobalAlloc may have rounded up to */
    len.QuadPart = size - 1;
    IStream_SetSize(*stream, len);
    return S_OK;
}

static HRESULT parse_task_xml(struct task *task, const WCHAR *xml)
{
    struct parse_state state = { { 0 } };
    IXmlReader *reader = NULL;
    IStream *stream = NULL;
    volatile HRESULT hr;
    volatile BOOL crashed = FALSE;
    unsigned int i;

    task->enabled = TRUE;

    hr = schedsvc_open_xml(xml, &stream);
    if (FAILED(hr)) return hr;

    hr = CreateXmlReader(&IID_IXmlReader, (void **)&reader, NULL);
    if (SUCCEEDED(hr)) hr = IXmlReader_SetInput(reader, (IUnknown *)stream);

    /* a task XML is whatever a user registered: a fault in the parser fails that task, not the service */
    _SEH2_TRY
    {
        if (SUCCEEDED(hr)) hr = parse_nodes(task, reader, &state);
    }
    _SEH2_EXCEPT(schedsvc_log_fault(_SEH2_GetExceptionInformation()))
    {
        ERR("task %s did not parse\n", debugstr_w(task->path));
        crashed = TRUE;
        hr = SCHED_E_MALFORMEDXML;
    }
    _SEH2_END;

    for (i = 0; i < state.depth; i++) free(state.names[i]);
    /* after a fault the reader's state is not to be trusted: leak it */
    if (!crashed)
    {
        if (reader) IXmlReader_Release(reader);
        IStream_Release(stream);
    }
    if (FAILED(hr)) WARN("%s: failed to parse the task, hr %#lx\n", debugstr_w(task->path), hr);
    return FAILED(hr) ? hr : S_OK;
}

/* SCHED_E_MALFORMEDXML unless the service can read the task XML */
HRESULT schedsvc_validate_xml(const WCHAR *xml)
{
    struct task *task = calloc(1, sizeof(*task));
    HRESULT hr;

    if (!task) return E_OUTOFMEMORY;
    hr = parse_task_xml(task, xml);
    free_task(task);
    return hr == E_OUTOFMEMORY ? hr : (hr == S_OK ? S_OK : SCHED_E_MALFORMEDXML);
}

/* the TaskCache key name of a task path: no leading separator, '\' and '/' become '|' */
static WCHAR *cache_name(const WCHAR *path)
{
    WCHAR *name, *p;

    while (*path == '\\' || *path == '/') path++;
    if (!*path || !(name = wcsdup(path))) return NULL;
    for (p = name + wcslen(name); p > name && (p[-1] == '\\' || p[-1] == '/'); p--) p[-1] = 0;
    for (p = name; *p; p++)
        if (*p == '\\' || *p == '/') *p = '|';
    return name;
}

static WCHAR *reg_get_string(HKEY key, const WCHAR *value)
{
    DWORD type, size = 0;
    WCHAR *str;

    if (RegQueryValueExW(key, value, NULL, &type, NULL, &size) || type != REG_SZ) return NULL;
    if (!(str = calloc(1, size + sizeof(WCHAR)))) return NULL;
    if (RegQueryValueExW(key, value, NULL, NULL, (BYTE *)str, &size))
    {
        free(str);
        return NULL;
    }
    return str;
}

static struct task *load_task(HKEY cache, const WCHAR *name)
{
    struct task *task;
    WCHAR *xml, *sid, *p;
    DWORD privileged = 0, size = sizeof(privileged);
    HKEY key;

    if (RegOpenKeyExW(cache, name, 0, KEY_READ, &key)) return NULL;
    if (!(task = calloc(1, sizeof(*task))))
    {
        RegCloseKey(key);
        return NULL;
    }
    task->pending = NO_TIME;
    task->path = wcsdup(name);
    if (task->path)
        for (p = task->path; *p; p++)
            if (*p == '|') *p = '\\';

    xml = reg_get_string(key, L"Xml");
    if ((sid = reg_get_string(key, L"Registrant")))
    {
        if (!ConvertStringSidToSidW(sid, &task->registrant)) task->registrant = NULL;
        free(sid);
    }
    if (!RegQueryValueExW(key, L"Privileged", NULL, NULL, (BYTE *)&privileged, &size))
        task->privileged = privileged != 0;
    RegCloseKey(key);

    if (!task->path || !xml || parse_task_xml(task, xml) != S_OK)
    {
        free(xml);
        free_task(task);
        return NULL;
    }
    free(xml);
    return task;
}

static BOOL task_registrant_is(const struct task *task, const WCHAR *sid_str)
{
    WCHAR *str;
    BOOL same;

    if (!task->registrant || !ConvertSidToStringSidW(task->registrant, &str)) return FALSE;
    same = !wcsicmp(str, sid_str);
    LocalFree(str);
    return same;
}

static void load_tasks(void)
{
    struct list old = LIST_INIT(old);
    struct task *task, *prev, *next;
    WCHAR name[256];
    DWORD index, len;
    HKEY cache;

    list_move_tail(&old, &tasks);

    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache))
    {
        for (index = 0; len = ARRAYSIZE(name), !RegEnumKeyExW(cache, index, name, &len, NULL, NULL, NULL, NULL); index++)
        {
            if (!(task = load_task(cache, name))) continue;
            /* keep what the previous copy of the task was doing */
            LIST_FOR_EACH_ENTRY(prev, &old, struct task, entry)
            {
                if (wcsicmp(prev->path, task->path)) continue;
                task->process = prev->process;
                task->pending = prev->pending;
                prev->process = NULL;
                break;
            }
            TRACE("task %s: %u triggers, %u actions, enabled %d\n", debugstr_w(task->path),
                  task->n_triggers, task->n_actions, task->enabled);
            list_add_tail(&tasks, &task->entry);
        }
        RegCloseKey(cache);
    }

    LIST_FOR_EACH_ENTRY_SAFE(prev, next, &old, struct task, entry)
    {
        list_remove(&prev->entry);
        free_task(prev);
    }
}

static PSID resolve_account(const WCHAR *name)
{
    static const WCHAR *system_names[] = { L"SYSTEM", L"NT AUTHORITY\\SYSTEM", L"LocalSystem", L".\\LocalSystem" };
    WCHAR domain[256];
    DWORD size = 0, domain_size = ARRAYSIZE(domain);
    SID_NAME_USE use;
    PSID sid = NULL;
    unsigned int i;

    if (!name || !*name) return NULL;

    if (!wcsnicmp(name, L"S-1-", 4))
    {
        if (!ConvertStringSidToSidW(name, &sid)) return NULL;
        return sid;
    }

    for (i = 0; i < ARRAYSIZE(system_names); i++)
    {
        if (wcsicmp(name, system_names[i])) continue;
        size = SECURITY_MAX_SID_SIZE;
        if (!(sid = LocalAlloc(LPTR, size))) return NULL;
        if (!CreateWellKnownSid(WinLocalSystemSid, NULL, sid, &size))
        {
            LocalFree(sid);
            return NULL;
        }
        return sid;
    }

    LookupAccountNameW(NULL, name, NULL, &size, domain, &domain_size, &use);
    if (!size || !(sid = LocalAlloc(LPTR, size))) return NULL;
    domain_size = ARRAYSIZE(domain);
    if (!LookupAccountNameW(NULL, name, sid, &size, domain, &domain_size, &use))
    {
        WARN("unknown account %s (%lu)\n", debugstr_w(name), GetLastError());
        LocalFree(sid);
        return NULL;
    }
    return sid;
}

static PSID copy_sid(PSID sid)
{
    DWORD size;
    PSID copy;

    if (!sid) return NULL;
    size = GetLengthSid(sid);
    if ((copy = LocalAlloc(LPTR, size))) CopySid(size, copy, sid);
    return copy;
}

typedef BOOL (*shell_token_callback)(HANDLE token, const LUID *logon, PSID user, void *context);

/* calls 'callback' with the token of every running shell (explorer.exe) until it returns FALSE */
static void enum_shell_tokens(shell_token_callback callback, void *context)
{
    PROCESSENTRY32W entry;
    HANDLE snapshot, process, token;
    TOKEN_STATISTICS stats;
    BYTE buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    TOKEN_USER *user = (TOKEN_USER *)buffer;
    DWORD size;
    BOOL more = TRUE;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (wcsicmp(entry.szExeFile, L"explorer.exe")) continue;
            if (!(process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID))) continue;
            if (OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &token))
            {
                if (GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &size) &&
                    GetTokenInformation(token, TokenUser, user, sizeof(buffer), &size))
                    more = callback(token, &stats.AuthenticationId, user->User.Sid, context);
                CloseHandle(token);
            }
            CloseHandle(process);
        } while (more && Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

struct find_token
{
    PSID sid;
    HANDLE token;
};

static BOOL find_token_callback(HANDLE token, const LUID *logon, PSID user, void *context)
{
    struct find_token *find = context;

    if (!EqualSid(user, find->sid)) return TRUE;
    if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &find->token))
        find->token = NULL;
    return find->token == NULL;
}

/* a primary token of a logged-on user, NULL if the user has no shell running */
static HANDLE get_user_token(PSID sid)
{
    struct find_token find = { sid, NULL };
    enum_shell_tokens(find_token_callback, &find);
    return find.token;
}

#define MAX_EXPANDED 32768

/* the string with its environment variables expanded; NULL if it is too long or on failure */
static WCHAR *expand_string(HANDLE token, const WCHAR *str)
{
    WCHAR *buffer;
    DWORD size, needed;

    if (!str) return NULL;
    if (!token)
    {
        needed = ExpandEnvironmentStringsW(str, NULL, 0);
        if (!needed || needed > MAX_EXPANDED) return NULL;
        if (!(buffer = malloc(needed * sizeof(WCHAR)))) return NULL;
        if (ExpandEnvironmentStringsW(str, buffer, needed) != needed)
        {
            free(buffer);
            return NULL;
        }
        return buffer;
    }

    for (size = 1024; size <= MAX_EXPANDED; size *= 2)
    {
        if (!(buffer = malloc(size * sizeof(WCHAR)))) return NULL;
        if (ExpandEnvironmentStringsForUserW(token, str, buffer, size)) return buffer;
        free(buffer);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) break;
    }
    /* no expansion for that user: use the text as it is, never a truncated copy */
    return wcslen(str) < MAX_EXPANDED ? wcsdup(str) : NULL;
}

static HANDLE start_action(const struct task *task, const struct action *action, HANDLE token, BOOL interactive)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    WCHAR *command, *arguments, *directory, *cmdline;
    void *env = NULL;
    SIZE_T len;
    BOOL ret;

    if (!action->command || !*action->command) return NULL;

    command = expand_string(token, action->command);
    arguments = expand_string(token, action->arguments);
    directory = expand_string(token, action->directory);
    len = (command ? wcslen(command) : 0) + (arguments ? wcslen(arguments) : 0) + 4;
    cmdline = malloc(len * sizeof(WCHAR));
    if (!command || !cmdline || (action->arguments && !arguments) || (action->directory && !directory))
    {
        free(command);
        free(arguments);
        free(directory);
        free(cmdline);
        return NULL;
    }

    if (command[0] == '"')
        wcscpy(cmdline, command);
    else
    {
        wcscpy(cmdline, L"\"");
        wcscat(cmdline, command);
        wcscat(cmdline, L"\"");
    }
    if (arguments && *arguments)
    {
        wcscat(cmdline, L" ");
        wcscat(cmdline, arguments);
    }

    /* a task of a user never gets the environment of this service */
    if (!CreateEnvironmentBlock(&env, token, FALSE) && token)
    {
        ERR("task %s: no environment for its user (%lu), not starting it\n", debugstr_w(task->path), GetLastError());
        free(command);
        free(arguments);
        free(directory);
        free(cmdline);
        return NULL;
    }
    if (token && interactive)
    {
        si.lpDesktop = L"winsta0\\default";
        ret = CreateProcessAsUserW(token, NULL, cmdline, NULL, NULL, FALSE,
                                   CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, env,
                                   directory && *directory ? directory : NULL, &si, &pi);
    }
    else if (token)
    {
        /* an S4U token has no session of its own to show a window in */
        ret = CreateProcessAsUserW(token, NULL, cmdline, NULL, NULL, FALSE,
                                   CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, env,
                                   directory && *directory ? directory : NULL, &si, &pi);
    }
    else
    {
        ret = CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                             CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, env,
                             directory && *directory ? directory : NULL, &si, &pi);
    }
    if (env) DestroyEnvironmentBlock(env);

    if (ret)
    {
        TRACE("task %s: started %s, pid %lu\n", debugstr_w(task->path), debugstr_w(cmdline), pi.dwProcessId);
        CloseHandle(pi.hThread);
    }
    else
        ERR("task %s: failed to start %s (%lu)\n", debugstr_w(task->path), debugstr_w(cmdline), GetLastError());

    free(command);
    free(arguments);
    free(directory);
    free(cmdline);
    return ret ? pi.hProcess : NULL;
}

/*
 * TRUE if the account is LocalSystem or a member of BUILTIN\\Administrators right now, from the SAM
 * (NetUserGetLocalGroups; NetLocalGroupGetMembers faults after a few calls on this system)
 */
static BOOL sid_is_admin_now(PSID sid)
{
    BYTE admins[SECURITY_MAX_SID_SIZE];
    WCHAR group[256], user[256], domain[256];
    DWORD size = sizeof(admins), glen = ARRAYSIZE(group), ulen = ARRAYSIZE(user), dlen = ARRAYSIZE(domain);
    SID_NAME_USE use;
    LOCALGROUP_USERS_INFO_0 *groups = NULL;
    DWORD read = 0, total = 0, i;
    NET_API_STATUS status;
    BOOL found = FALSE;

    if (IsWellKnownSid(sid, WinLocalSystemSid)) return TRUE;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admins, &size) ||
        !LookupAccountSidW(NULL, admins, group, &glen, domain, &dlen, &use))
        return FALSE;
    dlen = ARRAYSIZE(domain);
    if (!LookupAccountSidW(NULL, sid, user, &ulen, domain, &dlen, &use) || use != SidTypeUser) return FALSE;

    status = NetUserGetLocalGroups(NULL, user, 0, 0, (BYTE **)&groups, MAX_PREFERRED_LENGTH, &read, &total);
    if (status != NERR_Success)
    {
        WARN("cannot list the groups of %s (%lu)\n", debugstr_w(user), status);
        return FALSE;
    }
    for (i = 0; i < read; i++)
        if (!wcsicmp(groups[i].lgrui0_name, group)) found = TRUE;
    NetApiBufferFree(groups);
    return found;
}

/* the account a task runs as: its principal, else the registering user */
static PSID task_identity(const struct task *task)
{
    PSID sid = resolve_account(task->user_id);
    return sid ? sid : copy_sid(task->registrant);
}

/* starts the actions of a task; returns the process of its last action, or NULL */
static HANDLE run_task(struct task *task)
{
    HANDLE token = NULL, process = NULL, last = NULL;
    PSID sid;
    unsigned int i;
    BOOL interactive = TRUE;

    if (!task->enabled || !task->n_actions) return NULL;

    if (!(sid = task_identity(task)))
    {
        WARN("task %s: no account to run as\n", debugstr_w(task->path));
        return NULL;
    }

    /*
     * A task of any account but the registrant's own runs only if the registrant was an administrator
     * when registering it and still is: the flag recorded then is not enough, an administrator that
     * was demoted since must not keep running tasks as others.
     */
    if (!IsWellKnownSid(sid, WinLocalServiceSid) && !IsWellKnownSid(sid, WinNetworkServiceSid) &&
        !(task->registrant && EqualSid(sid, task->registrant)) &&
        (!task->privileged || !task->registrant || !sid_is_admin_now(task->registrant)))
    {
        WARN("task %s: its registrant is not an administrator (any more), not running it as another account\n",
             debugstr_w(task->path));
        goto done;
    }

    if (IsWellKnownSid(sid, WinLocalSystemSid))
    {
        if (!task->privileged)
        {
            WARN("task %s: not registered by an administrator, not running it as LocalSystem\n",
                 debugstr_w(task->path));
            goto done;
        }
    }
    else if (IsWellKnownSid(sid, WinLocalServiceSid) || IsWellKnownSid(sid, WinNetworkServiceSid))
    {
        FIXME("task %s: service accounts other than LocalSystem are not supported\n", debugstr_w(task->path));
        goto done;
    }
    else
    {
        if (!task->privileged && (!task->registrant || !EqualSid(sid, task->registrant)))
        {
            WARN("task %s: registered by another user, not running it\n", debugstr_w(task->path));
            goto done;
        }
        if (task->s4u)
        {
            /* LogonType S4U: the user need not be logged on; the same rules above decide who it may be */
            interactive = FALSE;
            if (!(token = schedsvc_s4u_token(sid)))
            {
                WARN("task %s: no S4U logon for its user\n", debugstr_w(task->path));
                goto done;
            }
        }
        else if (!(token = get_user_token(sid)))
        {
            TRACE("task %s: its user is not logged on\n", debugstr_w(task->path));
            goto done;
        }
    }

    for (i = 0; i < task->n_actions; i++)
    {
        if (!(process = start_action(task, &task->actions[i], token, interactive))) continue;
        if (last) CloseHandle(last);
        last = process;
    }

done:
    if (token) CloseHandle(token);
    LocalFree(sid);
    return last;
}

static void track_instance(const struct task *task, HANDLE process, GUID *guid);

/* the scheduled start of a task, respecting a still running instance */
static void start_task(struct task *task)
{
    HANDLE process;

    if (task->process)
    {
        if (WaitForSingleObject(task->process, 0) == WAIT_TIMEOUT)
        {
            TRACE("task %s: still running, not starting another instance\n", debugstr_w(task->path));
            return;
        }
        CloseHandle(task->process);
        task->process = NULL;
    }
    if ((process = run_task(task)))
    {
        task->process = process;
        track_instance(task, process, NULL);
    }
}

static void schedule_event_trigger(struct task *task, const struct trigger *trigger, ULONGLONG now)
{
    ULONGLONG when = now + trigger->delay;
    if (when < task->pending) task->pending = when;
}

static BOOL is_boot_window(void)
{
    return GetTickCount64() < BOOT_WINDOW_MS;
}

static void on_boot(ULONGLONG now)
{
    struct task *task;
    unsigned int i;

    LIST_FOR_EACH_ENTRY(task, &tasks, struct task, entry)
        for (i = 0; i < task->n_triggers; i++)
            if (task->triggers[i].type == TASK_TRIGGER_BOOT && task->triggers[i].supported &&
                task->triggers[i].enabled)
                schedule_event_trigger(task, &task->triggers[i], now);
}

static void on_logon(PSID user, ULONGLONG now)
{
    struct task *task;
    unsigned int i;
    PSID sid, trigger_sid;

    LIST_FOR_EACH_ENTRY(task, &tasks, struct task, entry)
    {
        /* a user task runs only at its own user's logon */
        sid = task_identity(task);
        if (sid && !IsWellKnownSid(sid, WinLocalSystemSid) && !EqualSid(sid, user))
        {
            LocalFree(sid);
            continue;
        }
        LocalFree(sid);

        for (i = 0; i < task->n_triggers; i++)
        {
            const struct trigger *trigger = &task->triggers[i];

            if (trigger->type != TASK_TRIGGER_LOGON || !trigger->supported || !trigger->enabled) continue;
            if (trigger->user_id && *trigger->user_id)
            {
                BOOL match = (trigger_sid = resolve_account(trigger->user_id)) && EqualSid(trigger_sid, user);
                LocalFree(trigger_sid);
                if (!match) continue;
            }
            TRACE("task %s: logon trigger\n", debugstr_w(task->path));
            schedule_event_trigger(task, trigger, now);
        }
    }
}

struct logon_scan
{
    ULONGLONG now;
    BOOL fire;
};

static BOOL logon_scan_callback(HANDLE token, const LUID *id, PSID user, void *context)
{
    struct logon_scan *scan = context;
    unsigned int i;

    for (i = 0; i < n_logons; i++)
    {
        if (logons[i].id.LowPart == id->LowPart && logons[i].id.HighPart == id->HighPart)
        {
            logons[i].alive = TRUE;
            return TRUE;
        }
    }
    if (n_logons < ARRAYSIZE(logons))
    {
        logons[n_logons].id = *id;
        logons[n_logons].alive = TRUE;
        n_logons++;
    }
    if (scan->fire) on_logon(user, scan->now);
    return TRUE;
}

/* new logon sessions with a shell fire the logon triggers */
static void scan_logons(ULONGLONG now, BOOL fire)
{
    struct logon_scan scan = { now, fire };
    unsigned int i, j;

    for (i = 0; i < n_logons; i++) logons[i].alive = FALSE;
    enum_shell_tokens(logon_scan_callback, &scan);
    for (i = j = 0; i < n_logons; i++)
        if (logons[i].alive) logons[j++] = logons[i];
    n_logons = j;
}

static BOOL have_logon_triggers(void)
{
    struct task *task;
    unsigned int i;

    LIST_FOR_EACH_ENTRY(task, &tasks, struct task, entry)
        for (i = 0; i < task->n_triggers; i++)
            if (task->triggers[i].type == TASK_TRIGGER_LOGON && task->triggers[i].supported)
                return TRUE;
    return FALSE;
}

/* starts every task with a start in (last, now]; returns the next start after now */
static ULONGLONG run_due_tasks(ULONGLONG last, ULONGLONG now)
{
    ULONGLONG next = NO_TIME, t;
    struct task *task;
    unsigned int i;
    BOOL due;

    LIST_FOR_EACH_ENTRY(task, &tasks, struct task, entry)
    {
        due = FALSE;
        if (task->pending <= now)
        {
            due = TRUE;
            task->pending = NO_TIME;
        }
        for (i = 0; i < task->n_triggers; i++)
            if (trigger_next_run(&task->triggers[i], last) <= now) due = TRUE;

        if (due && task->enabled)
        {
            TRACE("task %s is due\n", debugstr_w(task->path));
            start_task(task);
        }

        if (task->pending < next) next = task->pending;
        for (i = 0; i < task->n_triggers; i++)
            if ((t = trigger_next_run(&task->triggers[i], now)) < next) next = t;
    }
    return next;
}

/* the tasks registered or deleted since the scheduler last looked: it reloads those only */
struct change
{
    struct list entry;
    WCHAR *name;    /* TaskCache key name */
};

static struct list changes = LIST_INIT(changes);

static void queue_change(const WCHAR *name)
{
    struct change *change = malloc(sizeof(*change));

    if (change && (change->name = wcsdup(name)))
    {
        EnterCriticalSection(get_cs(&changes_cs));
        list_add_tail(&changes, &change->entry);
        LeaveCriticalSection(get_cs(&changes_cs));
    }
    else free(change);
    if (update_event) SetEvent(update_event);
}

static void apply_changes(void)
{
    struct list local = LIST_INIT(local);
    struct change *change, *next;
    struct task *task, *old, *old_next;
    WCHAR *path, *p;
    HKEY cache;
    BOOL have_cache;

    EnterCriticalSection(get_cs(&changes_cs));
    list_move_tail(&local, &changes);
    LeaveCriticalSection(get_cs(&changes_cs));

    have_cache = !RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache);
    LIST_FOR_EACH_ENTRY_SAFE(change, next, &local, struct change, entry)
    {
        list_remove(&change->entry);
        task = have_cache ? load_task(cache, change->name) : NULL;
        if ((path = wcsdup(change->name)))
        {
            for (p = path; *p; p++) if (*p == '|') *p = '\\';
            LIST_FOR_EACH_ENTRY_SAFE(old, old_next, &tasks, struct task, entry)
            {
                if (wcsicmp(old->path, path)) continue;
                /* keep what the previous copy of the task was doing */
                if (task)
                {
                    task->process = old->process;
                    task->pending = old->pending;
                    old->process = NULL;
                }
                list_remove(&old->entry);
                free_task(old);
            }
            free(path);
        }
        if (task) list_add_tail(&tasks, &task->entry);
        free(change->name);
        free(change);
    }
    if (have_cache) RegCloseKey(cache);
}

static DWORD WINAPI scheduler_thread_proc(void *arg)
{
    ULONGLONG last, now, next;
    HANDLE events[2] = { stop_event, update_event };
    DWORD timeout, ret;
    BOOL boot = is_boot_window();

    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    load_tasks();
    last = now = get_time();
    if (boot) on_boot(now);
    /* logons that predate the service count only at boot (autologon can win the race) */
    scan_logons(now, boot);
    next = run_due_tasks(last, now);

    for (;;)
    {
        timeout = MAX_WAIT_MS;
        now = get_time();
        if (next != NO_TIME)
            timeout = next <= now ? 0 : (DWORD)min((next - now + 9999) / 10000, MAX_WAIT_MS);
        if (have_logon_triggers() && timeout > LOGON_POLL_MS) timeout = LOGON_POLL_MS;

        ret = WaitForMultipleObjects(2, events, FALSE, timeout);
        if (ret == WAIT_OBJECT_0) break;

        now = get_time();
        if (now < last) last = now; /* the clock went back */
        if (ret == WAIT_OBJECT_0 + 1)
        {
            /* finish the old schedule up to now, then switch to the new one */
            run_due_tasks(last, now);
            last = now;
            apply_changes();
        }
        scan_logons(now, TRUE);
        next = run_due_tasks(last, now);
        last = now;
    }

    while (!list_empty(&tasks))
    {
        struct task *task = LIST_ENTRY(list_head(&tasks), struct task, entry);
        list_remove(&task->entry);
        free_task(task);
    }
    CoUninitialize();
    return 0;
}

static CRITICAL_SECTION *get_cs(CRITICAL_SECTION **slot)
{
    CRITICAL_SECTION *new;

    if (!*slot && (new = malloc(sizeof(*new))))
    {
        InitializeCriticalSection(new);
        if (InterlockedCompareExchangePointer((void **)slot, new, NULL))
        {
            DeleteCriticalSection(new);
            free(new);
        }
    }
    return *slot;
}

/* one writer at a time: the check that a task may be replaced or deleted and the change itself */
void schedsvc_lock(void)
{
    EnterCriticalSection(get_cs(&store_cs));
}

void schedsvc_unlock(void)
{
    LeaveCriticalSection(get_cs(&store_cs));
}

/* TRUE if the binding of a call came in over ncalrpc: no other transport, so no remote caller */
BOOL schedsvc_binding_is_local(RPC_BINDING_HANDLE binding)
{
    RPC_WSTR str = NULL;
    BOOL local;

    if (!binding || RpcBindingToStringBindingW(binding, &str) != RPC_S_OK || !str) return FALSE;
    local = !wcsnicmp((const WCHAR *)str, L"ncalrpc:", 8);
    RpcStringFreeW(&str);
    return local;
}

/* the security callback of the interface (every call checks the transport as well) */
RPC_STATUS CALLBACK schedsvc_if_callback(RPC_IF_HANDLE iface, void *context)
{
    return schedsvc_binding_is_local(context) ? RPC_S_OK : RPC_S_ACCESS_DENIED;
}

/* who is calling the RPC server: their SID and whether they are LocalSystem or an administrator */
static void get_caller(WCHAR **sid_str, BOOL *privileged)
{
    BYTE buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    TOKEN_USER *user = (TOKEN_USER *)buffer;
    BYTE admins[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(admins);
    HANDLE token;
    BOOL member = FALSE;

    *sid_str = NULL;
    *privileged = FALSE;

    if (RpcImpersonateClient(NULL) != RPC_S_OK)
    {
        WARN("cannot impersonate the caller\n");
        return;
    }
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
    {
        if (GetTokenInformation(token, TokenUser, user, sizeof(buffer), &size))
        {
            ConvertSidToStringSidW(user->User.Sid, sid_str);
            if (IsWellKnownSid(user->User.Sid, WinLocalSystemSid))
                *privileged = TRUE;
        }
        size = sizeof(admins);
        if (!*privileged && CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admins, &size) &&
            CheckTokenMembership(token, admins, &member) && member)
            *privileged = TRUE;
        CloseHandle(token);
    }
    else
        WARN("cannot open the caller's token (%lu)\n", GetLastError());
    RpcRevertToSelf();
}

/* every RPC entry point starts here: local, identified callers only */
HRESULT schedsvc_begin_call(struct caller *caller)
{
    caller->sid = NULL;
    caller->privileged = FALSE;

    if (!schedsvc_binding_is_local(I_RpcGetCurrentCallHandle()))
    {
        WARN("refusing a call that did not come in over ncalrpc\n");
        return E_ACCESSDENIED;
    }
    get_caller(&caller->sid, &caller->privileged);
    if (!caller->sid || !wcscmp(caller->sid, L"S-1-5-7"))
    {
        WARN("refusing an anonymous or unidentified caller\n");
        schedsvc_end_call(caller);
        return E_ACCESSDENIED;
    }
    return S_OK;
}

void schedsvc_end_call(struct caller *caller)
{
    LocalFree(caller->sid);
    caller->sid = NULL;
    caller->privileged = FALSE;
}

/* S_OK if the caller is an administrator or registered the task; a task with no record is theirs alone */
HRESULT schedsvc_check_owner(const struct caller *caller, const WCHAR *path)
{
    WCHAR *name, *registrant = NULL;
    HRESULT hr = E_ACCESSDENIED;
    HKEY cache, key;

    if (caller->privileged) return S_OK;
    if (!caller->sid || !(name = cache_name(path))) return E_ACCESSDENIED;
    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache))
    {
        if (!RegOpenKeyExW(cache, name, 0, KEY_READ, &key))
        {
            registrant = reg_get_string(key, L"Registrant");
            RegCloseKey(key);
        }
        RegCloseKey(cache);
    }
    if (registrant && !wcsicmp(registrant, caller->sid)) hr = S_OK;
    else WARN("%s belongs to %s, not to %s\n", debugstr_w(path), debugstr_w(registrant), debugstr_w(caller->sid));
    free(registrant);
    free(name);
    return hr;
}

/* a new task is refused when the caller has too many, or the store is full */
HRESULT schedsvc_check_quota(const struct caller *caller)
{
    WCHAR name[256], *registrant;
    DWORD index, len, mine = 0, total = 0;
    HKEY cache, key;

    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache)) 
    {
        for (index = 0; len = ARRAYSIZE(name), !RegEnumKeyExW(cache, index, name, &len, NULL, NULL, NULL, NULL); index++)
        {
            total++;
            if (caller->privileged || RegOpenKeyExW(cache, name, 0, KEY_READ, &key)) continue;
            if ((registrant = reg_get_string(key, L"Registrant")))
            {
                if (caller->sid && !wcsicmp(registrant, caller->sid)) mine++;
                free(registrant);
            }
            RegCloseKey(key);
        }
        RegCloseKey(cache);
    }
    if (total >= MAX_TASKS_TOTAL || (!caller->privileged && mine >= MAX_TASKS_PER_USER))
    {
        WARN("too many tasks (%lu, %lu of %s)\n", total, mine, debugstr_w(caller->sid));
        return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA);
    }
    return S_OK;
}

/* who created the folders of the task store: a key per folder, the SID of its creator */
HRESULT schedsvc_check_folder_quota(const struct caller *caller, unsigned int n_new)
{
    WCHAR name[256], *registrant;
    DWORD index, len, mine = 0, total = 0;
    HKEY folders, key;

    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, FOLDERS_KEY, 0, KEY_READ, &folders))
    {
        for (index = 0; len = ARRAYSIZE(name), !RegEnumKeyExW(folders, index, name, &len, NULL, NULL, NULL, NULL); index++)
        {
            total++;
            if (caller->privileged || RegOpenKeyExW(folders, name, 0, KEY_READ, &key)) continue;
            if ((registrant = reg_get_string(key, L"Registrant")))
            {
                if (caller->sid && !wcsicmp(registrant, caller->sid)) mine++;
                free(registrant);
            }
            RegCloseKey(key);
        }
        RegCloseKey(folders);
    }
    if (total + n_new > MAX_FOLDERS_TOTAL || (!caller->privileged && mine + n_new > MAX_FOLDERS_PER_USER))
    {
        WARN("too many folders (%lu, %lu of %s, %u new)\n", total, mine, debugstr_w(caller->sid), n_new);
        return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA);
    }
    return S_OK;
}

HRESULT schedsvc_folder_recorded(const struct caller *caller, const WCHAR *path)
{
    WCHAR *name = cache_name(path);
    HKEY folders, key;
    LONG ret;

    if (!name) return E_INVALIDARG;
    ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, FOLDERS_KEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &folders, NULL);
    if (!ret)
    {
        ret = RegCreateKeyExW(folders, name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL);
        if (!ret)
        {
            ret = RegSetValueExW(key, L"Registrant", 0, REG_SZ, (const BYTE *)caller->sid,
                                 (wcslen(caller->sid) + 1) * sizeof(WCHAR));
            RegCloseKey(key);
            if (ret) RegDeleteKeyW(folders, name);
        }
        RegCloseKey(folders);
    }
    free(name);
    return ret ? HRESULT_FROM_WIN32(ret) : S_OK;
}

void schedsvc_folder_forgotten(const WCHAR *path)
{
    WCHAR *name = cache_name(path);
    HKEY folders;

    if (!name) return;
    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, FOLDERS_KEY, 0, KEY_ALL_ACCESS, &folders))
    {
        RegDeleteKeyW(folders, name);
        RegCloseKey(folders);
    }
    free(name);
}

HRESULT schedsvc_task_registered(const struct caller *caller, const WCHAR *path, const WCHAR *xml)
{
    WCHAR *name;
    DWORD value, size, last_result = 0;
    ULONGLONG last_run = 0;
    HKEY cache, key;
    LONG ret;

    if (!(name = cache_name(path))) return E_INVALIDARG;
    TRACE("%s registered by %s, privileged %d\n", debugstr_w(path), debugstr_w(caller->sid), caller->privileged);

    ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &cache, NULL);
    if (!ret)
    {
        /* an update keeps the last run of the task */
        if (!RegOpenKeyExW(cache, name, 0, KEY_READ, &key))
        {
            size = sizeof(last_run);
            if (RegQueryValueExW(key, L"LastRun", NULL, NULL, (BYTE *)&last_run, &size)) last_run = 0;
            size = sizeof(last_result);
            if (RegQueryValueExW(key, L"LastResult", NULL, NULL, (BYTE *)&last_result, &size)) last_run = 0;
            RegCloseKey(key);
        }
        RegDeleteKeyW(cache, name);
        ret = RegCreateKeyExW(cache, name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL);
        if (!ret)
        {
            if (last_run)
            {
                RegSetValueExW(key, L"LastRun", 0, REG_QWORD, (const BYTE *)&last_run, sizeof(last_run));
                RegSetValueExW(key, L"LastResult", 0, REG_DWORD, (const BYTE *)&last_result, sizeof(last_result));
            }
            value = caller->privileged;
            ret = RegSetValueExW(key, L"Xml", 0, REG_SZ, (const BYTE *)xml, (wcslen(xml) + 1) * sizeof(WCHAR));
            if (!ret)
                ret = RegSetValueExW(key, L"Registrant", 0, REG_SZ, (const BYTE *)caller->sid,
                                     (wcslen(caller->sid) + 1) * sizeof(WCHAR));
            if (!ret)
                ret = RegSetValueExW(key, L"Privileged", 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
            RegCloseKey(key);
            /* a half written record would run with a wrong owner: drop it */
            if (ret) RegDeleteKeyW(cache, name);
        }
        RegCloseKey(cache);
    }
    /* even a failed record changed or dropped what the scheduler has */
    queue_change(name);
    free(name);
    if (ret)
    {
        ERR("failed to record task %s (%ld)\n", debugstr_w(path), ret);
        return HRESULT_FROM_WIN32(ret);
    }
    schedsvc_mirror_registered(path, xml);
    return S_OK;
}

/* the XML of a recorded task as the record has it; the record, never the file, is what the service trusts */
HRESULT schedsvc_task_get_xml(const WCHAR *path, WCHAR **xml)
{
    WCHAR *name;
    HKEY cache, key;
    LONG ret;

    *xml = NULL;
    if (!(name = cache_name(path))) return E_INVALIDARG;
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache);
    if (!ret)
    {
        ret = RegOpenKeyExW(cache, name, 0, KEY_READ, &key);
        if (!ret)
        {
            if (!(*xml = reg_get_string(key, L"Xml"))) ret = ERROR_FILE_NOT_FOUND;
            RegCloseKey(key);
        }
        RegCloseKey(cache);
    }
    free(name);
    return ret ? HRESULT_FROM_WIN32(ret) : S_OK;
}

/*
 * Replaces the XML of a recorded task and nothing else: the registrant and the Privileged flag stay
 * those of whoever registered the task, so that an administrator who only enables or disables a
 * user's task does not become the one who may run it as LocalSystem.
 */
HRESULT schedsvc_task_update_xml(const WCHAR *path, const WCHAR *xml)
{
    WCHAR *name;
    HKEY cache, key;
    LONG ret;

    if (!(name = cache_name(path))) return E_INVALIDARG;
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache);
    if (!ret)
    {
        ret = RegOpenKeyExW(cache, name, 0, KEY_SET_VALUE, &key);
        if (!ret)
        {
            ret = RegSetValueExW(key, L"Xml", 0, REG_SZ, (const BYTE *)xml, (wcslen(xml) + 1) * sizeof(WCHAR));
            RegCloseKey(key);
        }
        RegCloseKey(cache);
    }
    if (!ret) queue_change(name);
    free(name);
    return ret ? HRESULT_FROM_WIN32(ret) : S_OK;
}

HRESULT schedsvc_task_deleted(const WCHAR *path)
{
    WCHAR *name;
    HKEY cache;
    LONG ret;

    if (!(name = cache_name(path))) return E_INVALIDARG;
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_ALL_ACCESS, &cache);
    if (!ret)
    {
        ret = RegDeleteKeyW(cache, name);
        RegCloseKey(cache);
    }
    if (ret == ERROR_FILE_NOT_FOUND || ret == ERROR_PATH_NOT_FOUND) ret = ERROR_SUCCESS;
    if (!ret)
    {
        queue_change(name);
        schedsvc_mirror_deleted(path);
    }
    free(name);
    if (ret)
    {
        ERR("failed to remove the record of %s (%ld)\n", debugstr_w(path), ret);
        return HRESULT_FROM_WIN32(ret);
    }
    return S_OK;
}

/*
 * Running instances. Every start of a task, by a trigger or by IRegisteredTask::Run, is tracked until
 * its process ends. That gives Run its overlap guard, the Running state, the instances of a task
 * (SchRpcEnumInstances, SchRpcGetInstanceInfo, SchRpcStop, SchRpcStopInstance) and the last run time
 * and result of the task, which are kept in its TaskCache record (LastRun, LastResult) so that they
 * outlive the instance. An instance is dropped when its process is seen to have ended, the next time
 * anybody looks, so the result is never older than the question.
 */
struct instance
{
    WCHAR *name;        /* TaskCache key name */
    WCHAR *command;
    HANDLE process;
    DWORD pid;
    GUID guid;
    FILETIME start;
};

static struct instance instances[MAX_INSTANCES];

static void free_instance(struct instance *inst)
{
    free(inst->name);
    free(inst->command);
    if (inst->process) CloseHandle(inst->process);
    memset(inst, 0, sizeof(*inst));
}

static void set_last_run(const WCHAR *name, const FILETIME *start, DWORD result)
{
    HKEY cache, key;
    ULONGLONG time = ((ULONGLONG)start->dwHighDateTime << 32) | start->dwLowDateTime;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache)) return;
    if (!RegOpenKeyExW(cache, name, 0, KEY_SET_VALUE, &key))
    {
        RegSetValueExW(key, L"LastRun", 0, REG_QWORD, (const BYTE *)&time, sizeof(time));
        RegSetValueExW(key, L"LastResult", 0, REG_DWORD, (const BYTE *)&result, sizeof(result));
        RegCloseKey(key);
    }
    RegCloseKey(cache);
}

/* drops the instances whose process ended, recording their exit code; the store lock is held */
static void reap_instances(void)
{
    DWORD i, code;

    for (i = 0; i < MAX_INSTANCES; i++)
    {
        struct instance *inst = &instances[i];

        if (!inst->name || WaitForSingleObject(inst->process, 0) == WAIT_TIMEOUT) continue;
        if (!GetExitCodeProcess(inst->process, &code)) code = HRESULT_FROM_WIN32(GetLastError());
        set_last_run(inst->name, &inst->start, code);
        free_instance(inst);
    }
}

/* a live instance of the task, or NULL; the store lock is held */
static struct instance *find_instance(const WCHAR *name)
{
    DWORD i;

    reap_instances();
    for (i = 0; i < MAX_INSTANCES; i++)
        if (instances[i].name && !wcsicmp(instances[i].name, name)) return &instances[i];
    return NULL;
}

static struct instance *find_instance_by_guid(const GUID *guid)
{
    DWORD i;

    reap_instances();
    for (i = 0; i < MAX_INSTANCES; i++)
        if (instances[i].name && IsEqualGUID(&instances[i].guid, guid)) return &instances[i];
    return NULL;
}

static BOOL have_free_instance_slot(void)
{
    DWORD i;

    reap_instances();
    for (i = 0; i < MAX_INSTANCES; i++)
        if (!instances[i].name) return TRUE;
    return FALSE;
}

/* the store lock is held; NULL if all slots are in use (the start then goes untracked) */
static struct instance *add_instance(const WCHAR *name, const struct task *task, HANDLE process)
{
    struct instance *inst = NULL;
    DWORD i;

    reap_instances();
    for (i = 0; i < MAX_INSTANCES; i++)
        if (!instances[i].name) { inst = &instances[i]; break; }
    if (!inst) return NULL;

    memset(inst, 0, sizeof(*inst));
    if (!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &inst->process, 0, FALSE,
                         DUPLICATE_SAME_ACCESS))
        return NULL;
    inst->name = wcsdup(name);
    if (task->n_actions && task->actions[task->n_actions - 1].command)
        inst->command = wcsdup(task->actions[task->n_actions - 1].command);
    if (!inst->name)
    {
        free_instance(inst);
        return NULL;
    }
    inst->pid = GetProcessId(process);
    UuidCreate(&inst->guid);
    GetSystemTimeAsFileTime(&inst->start);
    set_last_run(name, &inst->start, SCHED_S_TASK_RUNNING);
    return inst;
}

static void track_instance(const struct task *task, HANDLE process, GUID *guid)
{
    WCHAR *name = cache_name(task->path);
    struct instance *inst;

    if (guid) memset(guid, 0, sizeof(*guid));
    if (!name) return;
    schedsvc_lock();
    if ((inst = add_instance(name, task, process)) && guid) *guid = inst->guid;
    schedsvc_unlock();
    free(name);
}

static void clear_instances(void)
{
    int i;

    for (i = 0; i < MAX_INSTANCES; i++) free_instance(&instances[i]);
}

/* the task path ("\Folder\Task") of a TaskCache key name; the caller frees it */
static WCHAR *name_to_path(const WCHAR *name)
{
    WCHAR *path = malloc((wcslen(name) + 2) * sizeof(WCHAR)), *p;

    if (!path) return NULL;
    path[0] = '\\';
    wcscpy(path + 1, name);
    for (p = path; *p; p++) if (*p == '|') *p = '\\';
    return path;
}

BOOL schedsvc_task_running(const WCHAR *path)
{
    WCHAR *name = cache_name(path);
    BOOL running;

    if (!name) return FALSE;
    schedsvc_lock();
    running = find_instance(name) != NULL;
    schedsvc_unlock();
    free(name);
    return running;
}

static BOOL task_record_exists(const WCHAR *name)
{
    HKEY cache, key;
    BOOL found = FALSE;

    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache))
    {
        if (!RegOpenKeyExW(cache, name, 0, KEY_READ, &key))
        {
            found = TRUE;
            RegCloseKey(key);
        }
        RegCloseKey(cache);
    }
    return found;
}

static void filetime_to_local(ULONGLONG time, SYSTEMTIME *local)
{
    FILETIME ft;
    SYSTEMTIME utc;

    ft.dwLowDateTime = (DWORD)time;
    ft.dwHighDateTime = (DWORD)(time >> 32);
    if (!FileTimeToSystemTime(&ft, &utc) || !SystemTimeToTzSpecificLocalTime(NULL, &utc, local))
        memset(local, 0, sizeof(*local));
}

static BOOL local_to_filetime(const SYSTEMTIME *local, ULONGLONG *time)
{
    SYSTEMTIME utc;
    FILETIME ft;

    if (!TzSpecificLocalTimeToSystemTime(NULL, (SYSTEMTIME *)local, &utc) || !SystemTimeToFileTime(&utc, &ft))
        return FALSE;
    *time = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return TRUE;
}

/* the last start of a task (local time) and its result; a task that never ran has a zero time and SCHED_S_TASK_HAS_NOT_RUN */
HRESULT schedsvc_get_last_run(const struct caller *caller, const WCHAR *path, SYSTEMTIME *last, DWORD *result)
{
    WCHAR *name;
    HKEY cache, key;
    ULONGLONG time = 0;
    DWORD size, code = SCHED_S_TASK_HAS_NOT_RUN;
    HRESULT hr;

    memset(last, 0, sizeof(*last));
    *result = SCHED_S_TASK_HAS_NOT_RUN;
    if (!(name = cache_name(path))) return E_INVALIDARG;

    schedsvc_lock();
    hr = schedsvc_check_owner(caller, path);
    if (hr == S_OK && !task_record_exists(name)) hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    if (hr == S_OK)
    {
        reap_instances();
        if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache))
        {
            if (!RegOpenKeyExW(cache, name, 0, KEY_READ, &key))
            {
                size = sizeof(time);
                if (RegQueryValueExW(key, L"LastRun", NULL, NULL, (BYTE *)&time, &size)) time = 0;
                size = sizeof(code);
                if (!time || RegQueryValueExW(key, L"LastResult", NULL, NULL, (BYTE *)&code, &size))
                    code = SCHED_S_TASK_HAS_NOT_RUN;
                RegCloseKey(key);
            }
            RegCloseKey(cache);
        }
        if (time) filetime_to_local(time, last);
        *result = time ? code : SCHED_S_TASK_HAS_NOT_RUN;
    }
    schedsvc_unlock();
    free(name);
    return hr;
}

#define MAX_RUNTIMES 256

/* the next start times of the triggers in [start, end] (local times), at most n_requested of them */
HRESULT schedsvc_scheduled_runtimes(const struct caller *caller, const WCHAR *path, const SYSTEMTIME *start,
                                    const SYSTEMTIME *end, DWORD n_requested, DWORD *n_runtimes,
                                    SYSTEMTIME **runtimes)
{
    struct task *task = NULL;
    SYSTEMTIME *list;
    ULONGLONG after, limit = NO_TIME, next, t;
    WCHAR *name;
    HKEY cache;
    DWORD n = 0, i;
    HRESULT hr;

    *n_runtimes = 0;
    *runtimes = NULL;
    if (!(name = cache_name(path))) return E_INVALIDARG;

    schedsvc_lock();
    hr = schedsvc_check_owner(caller, path);
    if (hr == S_OK && !RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache))
    {
        task = load_task(cache, name);
        RegCloseKey(cache);
    }
    schedsvc_unlock();
    free(name);
    if (hr != S_OK) return hr;
    if (!task) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    if (!n_requested || n_requested > MAX_RUNTIMES) n_requested = MAX_RUNTIMES;
    after = get_time();
    if (start)
    {
        if (!local_to_filetime(start, &after)) after = get_time();
        else if (after) after--;    /* the start itself counts */
    }
    if (end && (!local_to_filetime(end, &limit))) limit = NO_TIME;

    if (task->enabled && (list = malloc(n_requested * sizeof(*list))))
    {
        while (n < n_requested)
        {
            next = NO_TIME;
            for (i = 0; i < task->n_triggers; i++)
                if ((t = trigger_next_run(&task->triggers[i], after)) < next) next = t;
            if (next == NO_TIME || next > limit) break;
            filetime_to_local(next, &list[n++]);
            after = next;
        }
        if (n) *runtimes = list;
        else free(list);
        *n_runtimes = n;
    }
    free_task(task);
    return S_OK;
}

/* the instances of one task, or of all tasks the caller may see (path NULL) */
HRESULT schedsvc_enum_instances(const struct caller *caller, const WCHAR *path, DWORD *n_guids, GUID **guids)
{
    WCHAR *name = NULL, *task_path;
    GUID *list;
    DWORD i, n = 0;
    HRESULT hr = S_OK;

    *n_guids = 0;
    *guids = NULL;
    if (path && !(name = cache_name(path))) return E_INVALIDARG;
    if (!(list = malloc(MAX_INSTANCES * sizeof(*list)))) { free(name); return E_OUTOFMEMORY; }

    schedsvc_lock();
    if (path) hr = schedsvc_check_owner(caller, path);
    if (hr == S_OK)
    {
        reap_instances();
        for (i = 0; i < MAX_INSTANCES; i++)
        {
            if (!instances[i].name) continue;
            if (name && wcsicmp(instances[i].name, name)) continue;
            if (!name)
            {
                if (!(task_path = name_to_path(instances[i].name))) continue;
                hr = schedsvc_check_owner(caller, task_path);
                free(task_path);
                if (hr != S_OK) { hr = S_OK; continue; }
            }
            list[n++] = instances[i].guid;
        }
    }
    schedsvc_unlock();
    free(name);
    if (hr != S_OK || !n) free(list);
    else
    {
        *guids = list;
        *n_guids = n;
    }
    return hr;
}

HRESULT schedsvc_instance_info(const struct caller *caller, const GUID *guid, WCHAR **path, DWORD *state,
                               WCHAR **action, WCHAR **info, DWORD *n_guids, GUID **guids, DWORD *pid)
{
    struct instance *inst;
    WCHAR *task_path;
    HRESULT hr = S_OK;
    DWORD i, n = 0;

    *path = *action = *info = NULL;
    *n_guids = 0;
    *guids = NULL;
    *state = TASK_STATE_UNKNOWN;
    *pid = 0;

    schedsvc_lock();
    if (!(inst = find_instance_by_guid(guid))) hr = SCHED_E_TASK_NOT_RUNNING;
    else if (!(task_path = name_to_path(inst->name))) hr = E_OUTOFMEMORY;
    else
    {
        if ((hr = schedsvc_check_owner(caller, task_path)) == S_OK)
        {
            *path = task_path;
            *action = wcsdup(inst->command ? inst->command : L"");
            *info = wcsdup(L"");
            *guids = malloc(MAX_INSTANCES * sizeof(GUID));
            if (!*action || !*info || !*guids) hr = E_OUTOFMEMORY;
            else
            {
                for (i = 0; i < MAX_INSTANCES; i++)
                    if (instances[i].name && !wcsicmp(instances[i].name, inst->name))
                        (*guids)[n++] = instances[i].guid;
                *n_guids = n;
                *state = TASK_STATE_RUNNING;
                *pid = inst->pid;
            }
        }
        else free(task_path);
    }
    schedsvc_unlock();
    if (hr != S_OK)
    {
        free(*path);
        free(*action);
        free(*info);
        free(*guids);
        *path = *action = *info = NULL;
        *guids = NULL;
        *n_guids = 0;
    }
    return hr;
}

/*
 * Ends the instances of a task (or the one with the GUID), only the registrant's or an administrator's.
 * The process is terminated, as Windows does for a task that does not end by itself.
 */
HRESULT schedsvc_stop(const struct caller *caller, const WCHAR *path, const GUID *guid)
{
    HANDLE processes[MAX_INSTANCES];
    WCHAR *name = NULL, *task_path;
    DWORD i, n = 0;
    HRESULT hr = S_OK;

    if (path && !(name = cache_name(path))) return E_INVALIDARG;

    schedsvc_lock();
    if (name && (hr = schedsvc_check_owner(caller, path)) != S_OK) goto done;
    reap_instances();
    for (i = 0; i < MAX_INSTANCES; i++)
    {
        struct instance *inst = &instances[i];

        if (!inst->name) continue;
        if (name && wcsicmp(inst->name, name)) continue;
        if (guid && !IsEqualGUID(&inst->guid, guid)) continue;
        if (!name)
        {
            /* all of them (or the one by GUID): only those the caller may touch */
            if (!(task_path = name_to_path(inst->name))) continue;
            hr = schedsvc_check_owner(caller, task_path);
            free(task_path);
            if (hr != S_OK) { hr = guid ? E_ACCESSDENIED : S_OK; continue; }
        }
        if (DuplicateHandle(GetCurrentProcess(), inst->process, GetCurrentProcess(), &processes[n], 0, FALSE,
                            DUPLICATE_SAME_ACCESS))
            n++;
    }
    if (hr == S_OK && !n) hr = SCHED_E_TASK_NOT_RUNNING;
    for (i = 0; i < n; i++)
    {
        TerminateProcess(processes[i], ERROR_PROCESS_ABORTED);
        WaitForSingleObject(processes[i], 5000);
        CloseHandle(processes[i]);
    }
    if (n) reap_instances();
done:
    schedsvc_unlock();
    free(name);
    return hr;
}

/* IRegisteredTask::Run: only the registering user or an administrator may start a task */
HRESULT schedsvc_run_task(const struct caller *caller, const WCHAR *path, GUID *guid)
{
    struct task *task = NULL;
    WCHAR *name;
    HANDLE process;
    HKEY cache;
    HRESULT hr;

    memset(guid, 0, sizeof(*guid));
    if (!(name = cache_name(path))) return E_INVALIDARG;
    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKCACHE_KEY, 0, KEY_READ, &cache))
    {
        task = load_task(cache, name);
        RegCloseKey(cache);
    }
    if (!task)
    {
        free(name);
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    }

    if (!caller->privileged && (!caller->sid || !task->registrant || !task_registrant_is(task, caller->sid)))
    {
        hr = E_ACCESSDENIED;
        goto done;
    }
    if (!task->enabled)
    {
        hr = SCHED_E_TASK_DISABLED;
        goto done;
    }

    schedsvc_lock();
    if (find_instance(name))
        hr = SCHED_E_ALREADY_RUNNING;
    else if (!have_free_instance_slot())
        hr = HRESULT_FROM_WIN32(ERROR_BUSY);
    else if (!(process = run_task(task)))
        hr = E_FAIL;
    else
    {
        add_instance(name, task, process);
        CloseHandle(process);
        UuidCreate(guid);
        hr = S_OK;
        /* the GUID the caller gets names the instance */
        {
            struct instance *inst = find_instance(name);
            if (inst) *guid = inst->guid;
        }
    }
    schedsvc_unlock();

done:
    free(name);
    free_task(task);
    return hr;
}

static BOOL is_separator(WCHAR c)
{
    return c == '\\' || c == '/';
}

/* CON, PRN, AUX, NUL, COM1-9, LPT1-9, CONIN$ and CONOUT$, with or without an extension */
static BOOL is_device_name(const WCHAR *name, SIZE_T len)
{
    SIZE_T n = 0;

    while (n < len && name[n] != '.') n++;
    while (n && name[n - 1] == ' ') n--;
    if (n == 3)
        return !wcsnicmp(name, L"CON", 3) || !wcsnicmp(name, L"PRN", 3) ||
               !wcsnicmp(name, L"AUX", 3) || !wcsnicmp(name, L"NUL", 3);
    if (n == 4)
        return (!wcsnicmp(name, L"COM", 3) || !wcsnicmp(name, L"LPT", 3)) && name[3] >= '1' && name[3] <= '9';
    if (n == 6) return !wcsnicmp(name, L"CONIN$", 6);
    if (n == 7) return !wcsnicmp(name, L"CONOUT$", 7);
    return FALSE;
}

/*
 * A task or folder path stays inside the task store: at most MAX_PATH_DEPTH components of
 * 1 to MAX_COMPONENT characters, no "." or ".." (nor any component ending in a dot or a space,
 * which Win32 strips), no empty components, streams, wildcards, control characters, '|' (the
 * TaskCache separator) or device names. Leading and one trailing separator are fine.
 */
BOOL schedsvc_valid_path(const WCHAR *path)
{
    const WCHAR *p, *start;
    SIZE_T len, depth = 0;

    if (!path) return TRUE;
    if (wcslen(path) > MAX_TASK_PATH) return FALSE;

    p = path;
    while (is_separator(*p)) p++;
    while (*p)
    {
        for (start = p; *p && !is_separator(*p); p++)
            if (*p < 32 || wcschr(L":*?\"<>|", *p)) return FALSE;
        len = p - start;
        if (!len || len > MAX_COMPONENT) return FALSE;
        if (start[len - 1] == '.' || start[len - 1] == ' ') return FALSE;
        if (is_device_name(start, len)) return FALSE;
        if (++depth > MAX_PATH_DEPTH) return FALSE;
        if (*p) p++;
    }
    return TRUE;
}

void schedsvc_auto_start(void)
{
    /* the Schedule service is an auto-start service already */
}

DWORD TaskSchedulerStart(VOID)
{
    WCHAR path[MAX_PATH];

    /* the task store, %SystemRoot%\System32\Tasks */
    if (GetSystemDirectoryW(path, MAX_PATH - 6))
    {
        wcscat(path, L"\\Tasks");
        if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
            ERR("cannot create %s (%lu)\n", debugstr_w(path), GetLastError());
    }

    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    update_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!stop_event || !update_event) return GetLastError();

    scheduler_thread = CreateThread(NULL, 0, scheduler_thread_proc, NULL, 0, NULL);
    if (!scheduler_thread) return GetLastError();
    return ERROR_SUCCESS;
}

VOID TaskSchedulerStop(VOID)
{
    if (scheduler_thread)
    {
        SetEvent(stop_event);
        WaitForSingleObject(scheduler_thread, 10000);
        CloseHandle(scheduler_thread);
        scheduler_thread = NULL;
    }
    schedsvc_lock();
    clear_instances();
    schedsvc_unlock();
}
