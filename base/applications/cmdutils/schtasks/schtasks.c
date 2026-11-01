/*
 * PROJECT:     ReactOS Scheduled tasks command
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     schtasks /create /delete /run /end /change /query on the Task Scheduler 2.0 COM API
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The output formats of /query (TABLE, LIST, CSV, with and without /v and /nh) and the messages
 * follow what Windows 10 22H2 prints, measured with read-only queries.
 * Not done (reported as such): remote machines (/s /u /p), idle and event schedules (the service
 * stores such triggers from an XML file and never runs them, so /create refuses them),
 * tasks that run with a stored password (/ru user /rp password), changing /tr.
 */

#define COBJMACROS
#define WIN32_NO_STATUS

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <winuser.h>
#include <objbase.h>
#include <sddl.h>
#include <oleauto.h>
#include <initguid.h>
#include <taskschd.h>
#include <conutils.h>

#include "resource.h"

#define MAX_FIELD 2048

/* ---------- output ---------- */

struct sb
{
    WCHAR *buf;
    size_t len, cap;
};

static void sb_add_n(struct sb *sb, const WCHAR *str, size_t n)
{
    if (sb->len + n + 1 > sb->cap)
    {
        size_t cap = max(sb->cap * 2, sb->len + n + 256);
        WCHAR *buf = realloc(sb->buf, cap * sizeof(WCHAR));
        if (!buf) return;
        sb->buf = buf;
        sb->cap = cap;
    }
    memcpy(sb->buf + sb->len, str, n * sizeof(WCHAR));
    sb->len += n;
    sb->buf[sb->len] = 0;
}

static void sb_add(struct sb *sb, const WCHAR *str)
{
    sb_add_n(sb, str, wcslen(str));
}

static void sb_pad(struct sb *sb, size_t n, WCHAR ch)
{
    while (n--) sb_add_n(sb, &ch, 1);
}

static void sb_flush(struct sb *sb)
{
    if (sb->len) ConPuts(StdOut, sb->buf);
    sb->len = 0;
    if (sb->buf) sb->buf[0] = 0;
}

static void out(const WCHAR *str)
{
    ConPuts(StdOut, str);
}

static void err(const WCHAR *str)
{
    ConPuts(StdErr, str);
}

/* "ERROR: <text>" and the usage hint, on stderr */
static void error_text(const WCHAR *text)
{
    err(L"ERROR: ");
    err(text);
    err(L"\n");
}

static void error_usage(const WCHAR *text, const WCHAR *command)
{
    WCHAR line[256];

    error_text(text);
    _snwprintf(line, ARRAYSIZE(line), L"Type \"SCHTASKS /%s /?\" for usage.\n", command);
    err(line);
}

static void error_hr(HRESULT hr)
{
    WCHAR text[512] = L"";
    DWORD code = 0, len;

    if (HRESULT_FACILITY(hr) == FACILITY_WIN32) code = HRESULT_CODE(hr);
    else if (hr == E_ACCESSDENIED) code = ERROR_ACCESS_DENIED;
    else if (hr == E_OUTOFMEMORY) code = ERROR_NOT_ENOUGH_MEMORY;
    else if (hr == E_INVALIDARG) code = ERROR_INVALID_PARAMETER;

    switch (hr)
    {
    case SCHED_E_MALFORMEDXML: wcscpy(text, L"The task XML is malformed."); break;
    case SCHED_E_TASK_NOT_RUNNING: wcscpy(text, L"There is no running instance of the task."); break;
    case SCHED_E_ALREADY_RUNNING: wcscpy(text, L"An instance of this task is already running."); break;
    case SCHED_E_TASK_DISABLED: wcscpy(text, L"The task is disabled."); break;
    case SCHED_E_SERVICE_NOT_RUNNING: wcscpy(text, L"The Task Scheduler service is not running."); break;
    default:
        if (code && (len = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code, 0,
                                          text, ARRAYSIZE(text), NULL)))
        {
            /* the message ends with a line break */
            while (len && (text[len - 1] == '\r' || text[len - 1] == '\n' || text[len - 1] == ' ')) text[--len] = 0;
        }
        else
            _snwprintf(text, ARRAYSIZE(text), L"The Task Scheduler call failed (0x%08lx).", (ULONG)hr);
    }
    error_text(text);
}

static void success(const WCHAR *fmt, const WCHAR *name)
{
    WCHAR line[MAX_PATH * 2];

    _snwprintf(line, ARRAYSIZE(line), fmt, name);
    out(line);
}

/* ---------- connection and names ---------- */

static ITaskService *service;

static HRESULT connect_service(void)
{
    VARIANT empty;
    HRESULT hr;

    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void **)&service);
    if (FAILED(hr)) return hr;
    VariantInit(&empty);
    hr = ITaskService_Connect(service, empty, empty, empty, empty);
    if (FAILED(hr))
    {
        ITaskService_Release(service);
        service = NULL;
    }
    return hr;
}

/* "\Folder\Task" for any spelling of a task name */
static WCHAR *full_task_name(const WCHAR *name)
{
    WCHAR *full = malloc((wcslen(name) + 2) * sizeof(WCHAR)), *p;

    if (!full) return NULL;
    if (name[0] == '\\' || name[0] == '/') wcscpy(full, name);
    else
    {
        full[0] = '\\';
        wcscpy(full + 1, name);
    }
    for (p = full; *p; p++) if (*p == '/') *p = '\\';
    return full;
}

static HRESULT get_task(const WCHAR *name, IRegisteredTask **task)
{
    ITaskFolder *root;
    WCHAR *full = full_task_name(name);
    BSTR str;
    HRESULT hr;

    *task = NULL;
    if (!full) return E_OUTOFMEMORY;
    if (FAILED(hr = ITaskService_GetFolder(service, (BSTR)L"\\", &root)))
    {
        free(full);
        return hr;
    }
    str = SysAllocString(full);
    hr = ITaskFolder_GetTask(root, str, task);
    SysFreeString(str);
    ITaskFolder_Release(root);
    free(full);
    return hr;
}

/* ---------- option parsing ---------- */

struct options
{
    const WCHAR *tn, *tr, *sc, *st, *sd, *ed, *mo, *ri, *du, *ru, *rp, *rl, *xml, *fo, *s, *d, *m, *i;
    BOOL f, nh, v, enable, disable, it, help;
    BOOL have_xml_switch;
};

/* the option name without its '/' or '-', or NULL if the argument is not an option */
static const WCHAR *option_name(const WCHAR *arg)
{
    return (arg[0] == '/' || arg[0] == '-') && arg[1] ? arg + 1 : NULL;
}

/* fills 'opt' from argv; the names with a value are taken, the names without are flags. FALSE on a bad option */
static BOOL parse_options(int argc, WCHAR **argv, struct options *opt, const WCHAR *command)
{
    static const struct { const WCHAR *name; size_t offset; } values[] =
    {
        { L"tn", offsetof(struct options, tn) }, { L"tr", offsetof(struct options, tr) },
        { L"sc", offsetof(struct options, sc) }, { L"st", offsetof(struct options, st) },
        { L"sd", offsetof(struct options, sd) }, { L"ed", offsetof(struct options, ed) },
        { L"mo", offsetof(struct options, mo) }, { L"ri", offsetof(struct options, ri) },
        { L"du", offsetof(struct options, du) }, { L"ru", offsetof(struct options, ru) },
        { L"rp", offsetof(struct options, rp) }, { L"rl", offsetof(struct options, rl) },
        { L"xml", offsetof(struct options, xml) }, { L"fo", offsetof(struct options, fo) },
        { L"s", offsetof(struct options, s) }, { L"d", offsetof(struct options, d) },
        { L"m", offsetof(struct options, m) }, { L"i", offsetof(struct options, i) },
    };
    int i;
    unsigned int j;

    memset(opt, 0, sizeof(*opt));
    for (i = 0; i < argc; i++)
    {
        const WCHAR *name = option_name(argv[i]);
        WCHAR line[256];

        if (!name)
        {
            _snwprintf(line, ARRAYSIZE(line), L"Invalid argument/option - '%s'.", argv[i]);
            error_usage(line, command);
            return FALSE;
        }
        if (!wcscmp(name, L"?")) { opt->help = TRUE; continue; }
        if (!wcsicmp(name, L"f")) { opt->f = TRUE; continue; }
        if (!wcsicmp(name, L"nh")) { opt->nh = TRUE; continue; }
        if (!wcsicmp(name, L"v")) { opt->v = TRUE; continue; }
        if (!wcsicmp(name, L"enable")) { opt->enable = TRUE; continue; }
        if (!wcsicmp(name, L"disable")) { opt->disable = TRUE; continue; }
        if (!wcsicmp(name, L"it")) { opt->it = TRUE; continue; }
        if (!wcsicmp(name, L"z") || !wcsicmp(name, L"k") || !wcsicmp(name, L"ec") || !wcsicmp(name, L"v1"))
            continue;

        for (j = 0; j < ARRAYSIZE(values); j++)
            if (!wcsicmp(name, values[j].name)) break;
        if (j == ARRAYSIZE(values))
        {
            _snwprintf(line, ARRAYSIZE(line), L"Invalid argument/option - '%s'.", argv[i]);
            error_usage(line, command);
            return FALSE;
        }
        /* /xml takes a file name, except for /query where it takes an optional word */
        if (!wcsicmp(name, L"xml") && !wcsicmp(command, L"QUERY"))
        {
            opt->have_xml_switch = TRUE;
            if (i + 1 < argc && !option_name(argv[i + 1])) i++;
            continue;
        }
        if (i + 1 >= argc)
        {
            _snwprintf(line, ARRAYSIZE(line), L"Invalid syntax. Value expected for '%s'.", argv[i]);
            error_usage(line, command);
            return FALSE;
        }
        *(const WCHAR **)((BYTE *)opt + values[j].offset) = argv[++i];
    }
    return TRUE;
}

/* the Y/N prompt: TRUE for yes */
static BOOL ask(const WCHAR *question)
{
    WCHAR line[32];

    out(question);
    out(L" (Y/N)? ");
    if (!fgetws(line, ARRAYSIZE(line), stdin)) return FALSE;
    return line[0] == 'Y' || line[0] == 'y';
}

/* ---------- time and date text ---------- */

static BOOL parse_time_arg(const WCHAR *str, SYSTEMTIME *st)
{
    unsigned int h, m, s = 0;
    int n = swscanf(str, L"%u:%u:%u", &h, &m, &s);

    if (n < 2 || h > 23 || m > 59 || s > 59) return FALSE;
    st->wHour = h;
    st->wMinute = m;
    st->wSecond = s;
    return TRUE;
}

/* MM/DD/YYYY (Windows' default for en-US), DD/MM/YYYY is not guessed, or YYYY-MM-DD */
static BOOL parse_date_arg(const WCHAR *str, SYSTEMTIME *st)
{
    unsigned int a, b, c;

    if (swscanf(str, L"%u-%u-%u", &a, &b, &c) == 3 && a > 999)
    {
        st->wYear = a;
        st->wMonth = b;
        st->wDay = c;
    }
    else if (swscanf(str, L"%u/%u/%u", &a, &b, &c) == 3)
    {
        st->wMonth = a;
        st->wDay = b;
        st->wYear = c < 100 ? 2000 + c : c;
    }
    else return FALSE;
    return st->wMonth >= 1 && st->wMonth <= 12 && st->wDay >= 1 && st->wDay <= 31;
}

static void format_boundary(const SYSTEMTIME *st, WCHAR *str, size_t size)
{
    _snwprintf(str, size, L"%04u-%02u-%02uT%02u:%02u:%02u", st->wYear, st->wMonth, st->wDay,
               st->wHour, st->wMinute, st->wSecond);
}

/* the date and the time of an ISO "YYYY-MM-DDTHH:MM:SS" boundary, formatted for the user's locale */
static BOOL format_boundary_date_time(const WCHAR *iso, WCHAR *date, size_t date_size, WCHAR *time, size_t time_size)
{
    SYSTEMTIME st = {0};
    unsigned int y, mo, d, h = 0, mi = 0, s = 0;

    if (swscanf(iso, L"%u-%u-%uT%u:%u:%u", &y, &mo, &d, &h, &mi, &s) < 3) return FALSE;
    st.wYear = y; st.wMonth = mo; st.wDay = d; st.wHour = h; st.wMinute = mi; st.wSecond = s;
    if (date && !GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &st, NULL, date, date_size)) return FALSE;
    if (time && !GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &st, NULL, time, time_size)) return FALSE;
    return TRUE;
}

/* a DATE (local time) as "date time"; "N/A" for no date */
static void format_date(DATE date, BOOL always, WCHAR *text, size_t size)
{
    SYSTEMTIME st;
    WCHAR d[64], t[64];

    if (date == 0 && !always)
    {
        wcscpy(text, L"N/A");
        return;
    }
    if (date == 0)
    {
        /* what Windows prints for a task that never ran */
        st.wYear = 1999; st.wMonth = 11; st.wDay = 30; st.wHour = st.wMinute = st.wSecond = 0;
        st.wMilliseconds = 0; st.wDayOfWeek = 2;
    }
    else if (!VariantTimeToSystemTime(date, &st))
    {
        wcscpy(text, L"N/A");
        return;
    }
    if (!GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &st, NULL, d, ARRAYSIZE(d)) ||
        !GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &st, NULL, t, ARRAYSIZE(t)))
    {
        wcscpy(text, L"N/A");
        return;
    }
    _snwprintf(text, size, L"%s %s", d, t);
}

/* PnDTnHnMnS in whole seconds; -1 if it does not parse */
static LONGLONG duration_seconds(const WCHAR *str)
{
    LONGLONG total = 0, n;
    BOOL time_part = FALSE;
    WCHAR *end;

    if (!str || *str++ != 'P') return -1;
    while (*str)
    {
        if (*str == 'T') { time_part = TRUE; str++; continue; }
        if (*str < '0' || *str > '9') return -1;
        n = wcstol(str, &end, 10);
        str = end;
        switch (*str++)
        {
        case 'W': total += n * 7 * 86400; break;
        case 'D': total += n * 86400; break;
        case 'H': total += n * 3600; break;
        case 'M': total += time_part ? n * 60 : n * 30 * 86400; break;
        case 'S': total += n; break;
        default: return -1;
        }
    }
    return total;
}

/* "H Hour(s), M Minute(s)" */
static void format_hours_minutes(LONGLONG seconds, WCHAR *text, size_t size)
{
    _snwprintf(text, size, L"%I64d Hour(s), %I64d Minute(s)", seconds / 3600, seconds % 3600 / 60);
}

/* ---------- query ---------- */

enum column
{
    C_HOST, C_NAME, C_NEXT, C_STATUS, C_LOGON, C_LASTRUN, C_LASTRES, C_AUTHOR, C_RUN, C_STARTIN, C_COMMENT,
    C_STATE, C_IDLE, C_POWER, C_RUNAS, C_DELETE, C_STOP, C_SCHEDULE, C_STYPE, C_STIME, C_SDATE, C_EDATE,
    C_DAYS, C_MONTHS, C_REPEVERY, C_REPUNTIL, C_REPDUR, C_REPSTOP, C_COUNT
};

static const struct { const WCHAR *title; int width; BOOL right; } columns[C_COUNT] =
{
    { L"HostName", 16 }, { L"TaskName", 40 }, { L"Next Run Time", 22 }, { L"Status", 15 },
    { L"Logon Mode", 23 }, { L"Last Run Time", 22 }, { L"Last Result", 11, TRUE }, { L"Author", 16 },
    { L"Task To Run", 50 }, { L"Start In", 40 }, { L"Comment", 80 }, { L"Scheduled Task State", 22 },
    { L"Idle Time", 40 }, { L"Power Management", 48 }, { L"Run As User", 40 },
    { L"Delete Task If Not Rescheduled", 30 }, { L"Stop Task If Runs X Hours and X Mins", 40 },
    { L"Schedule", 80 }, { L"Schedule Type", 28 }, { L"Start Time", 12 }, { L"Start Date", 10 },
    { L"End Date", 10 }, { L"Days", 43 }, { L"Months", 43 }, { L"Repeat: Every", 24 },
    { L"Repeat: Until: Time", 20 }, { L"Repeat: Until: Duration", 30 }, { L"Repeat: Stop If Still Running", 35 },
};

struct record
{
    WCHAR *f[C_COUNT];
};

static void set_field(struct record *rec, enum column col, const WCHAR *text)
{
    free(rec->f[col]);
    rec->f[col] = wcsdup(text ? text : L"");
}

static void free_record(struct record *rec)
{
    int i;

    for (i = 0; i < C_COUNT; i++) free(rec->f[i]);
    memset(rec, 0, sizeof(*rec));
}

static const WCHAR *state_text(TASK_STATE state)
{
    switch (state)
    {
    case TASK_STATE_DISABLED: return L"Disabled";
    case TASK_STATE_QUEUED: return L"Queued";
    case TASK_STATE_READY: return L"Ready";
    case TASK_STATE_RUNNING: return L"Running";
    default: return L"Unknown";
    }
}

/* the account name of a SID or name, without the domain: "SYSTEM", "winref" */
static void account_name(const WCHAR *id, WCHAR *text, size_t size)
{
    WCHAR name[256], domain[256];
    DWORD name_len = ARRAYSIZE(name), domain_len = ARRAYSIZE(domain);
    SID_NAME_USE use;
    PSID sid;
    const WCHAR *slash;

    wcsncpy(text, id, size - 1);
    text[size - 1] = 0;
    if (!wcsncmp(id, L"S-1-", 4))
    {
        if (ConvertStringSidToSidW(id, &sid))
        {
            if (LookupAccountSidW(NULL, sid, name, &name_len, domain, &domain_len, &use))
                _snwprintf(text, size, L"%s", name);
            LocalFree(sid);
        }
    }
    else if ((slash = wcsrchr(id, '\\')))
        _snwprintf(text, size, L"%s", slash + 1);
}

static const WCHAR *const day_words[7] = { L"SUNDAY", L"MONDAY", L"TUESDAY", L"WEDNESDAY", L"THURSDAY", L"FRIDAY", L"SATURDAY" };
static const WCHAR *const month_words[12] = { L"JANUARY", L"FEBRUARY", L"MARCH", L"APRIL", L"MAY", L"JUNE", L"JULY",
                                              L"AUGUST", L"SEPTEMBER", L"OCTOBER", L"NOVEMBER", L"DECEMBER" };

/* "MONDAY, FRIDAY" */
static void list_set(WCHAR *text, size_t size, const WCHAR *const *words, unsigned int count, unsigned int mask)
{
    unsigned int i;
    size_t n = 0;

    text[0] = 0;
    for (i = 0; i < count; i++)
    {
        if (!(mask & (1u << i))) continue;
        n += _snwprintf(text + n, size - n, L"%s%s", n ? L", " : L"", words[i]);
    }
}

/* the schedule fields of a weekly, monthly or monthly day-of-week trigger */
static void fill_calendar_fields(struct record *rec, ITrigger *trigger, TASK_TRIGGER_TYPE2 type)
{
    WCHAR text[256], more[128];

    if (type == TASK_TRIGGER_WEEKLY)
    {
        IWeeklyTrigger *weekly;
        SHORT days = 0, weeks = 1;

        if (SUCCEEDED(ITrigger_QueryInterface(trigger, &IID_IWeeklyTrigger, (void **)&weekly)))
        {
            IWeeklyTrigger_get_DaysOfWeek(weekly, &days);
            IWeeklyTrigger_get_WeeksInterval(weekly, &weeks);
            IWeeklyTrigger_Release(weekly);
        }
        list_set(text, ARRAYSIZE(text), day_words, 7, days);
        if (weeks > 1)
        {
            _snwprintf(more, ARRAYSIZE(more), L"Every %d week(s) on: %s", weeks, text);
            set_field(rec, C_DAYS, more);
        }
        else set_field(rec, C_DAYS, text);
        set_field(rec, C_STYPE, L"Weekly");
    }
    else if (type == TASK_TRIGGER_MONTHLY)
    {
        IMonthlyTrigger *monthly;
        LONG days = 0;
        SHORT months = 0;
        VARIANT_BOOL last = VARIANT_FALSE;
        unsigned int i;
        size_t n = 0;

        if (SUCCEEDED(ITrigger_QueryInterface(trigger, &IID_IMonthlyTrigger, (void **)&monthly)))
        {
            IMonthlyTrigger_get_DaysOfMonth(monthly, &days);
            IMonthlyTrigger_get_MonthsOfYear(monthly, &months);
            IMonthlyTrigger_get_RunOnLastDayOfMonth(monthly, &last);
            IMonthlyTrigger_Release(monthly);
        }
        text[0] = 0;
        for (i = 0; i < 31; i++)
            if (days & (1 << i)) n += _snwprintf(text + n, ARRAYSIZE(text) - n, L"%s%u", n ? L", " : L"", i + 1);
        if (last) n += _snwprintf(text + n, ARRAYSIZE(text) - n, L"%sLAST", n ? L", " : L"");
        set_field(rec, C_DAYS, text);
        list_set(text, ARRAYSIZE(text), month_words, 12, months);
        set_field(rec, C_MONTHS, text);
        set_field(rec, C_STYPE, L"Monthly");
    }
    else
    {
        IMonthlyDOWTrigger *dow;
        SHORT days = 0, weeks = 0, months = 0;
        VARIANT_BOOL last = VARIANT_FALSE;
        static const WCHAR *const nth[4] = { L"FIRST", L"SECOND", L"THIRD", L"FOURTH" };
        unsigned int i;
        size_t n = 0;

        if (SUCCEEDED(ITrigger_QueryInterface(trigger, &IID_IMonthlyDOWTrigger, (void **)&dow)))
        {
            IMonthlyDOWTrigger_get_DaysOfWeek(dow, &days);
            IMonthlyDOWTrigger_get_WeeksOfMonth(dow, &weeks);
            IMonthlyDOWTrigger_get_MonthsOfYear(dow, &months);
            IMonthlyDOWTrigger_get_RunOnLastWeekOfMonth(dow, &last);
            IMonthlyDOWTrigger_Release(dow);
        }
        more[0] = 0;
        for (i = 0; i < 4; i++)
            if (weeks & (1 << i)) n += _snwprintf(more + n, ARRAYSIZE(more) - n, L"%s%s", n ? L", " : L"", nth[i]);
        if (last) n += _snwprintf(more + n, ARRAYSIZE(more) - n, L"%sLAST", n ? L", " : L"");
        list_set(text, ARRAYSIZE(text), day_words, 7, days);
        _snwprintf(text + wcslen(text), ARRAYSIZE(text) - wcslen(text), L" (%s)", more);
        set_field(rec, C_DAYS, text);
        list_set(text, ARRAYSIZE(text), month_words, 12, months);
        set_field(rec, C_MONTHS, text);
        set_field(rec, C_STYPE, L"Monthly");
    }
}

/* the fields that come from one trigger of the task (or none: on demand only) */
static void fill_trigger_fields(struct record *rec, ITrigger *trigger)
{
    TASK_TRIGGER_TYPE2 type;
    BSTR start = NULL, end = NULL, interval = NULL, duration = NULL;
    IRepetitionPattern *repetition = NULL;
    VARIANT_BOOL stop = VARIANT_FALSE;
    WCHAR date[64], time[64], text[128];
    LONG days = 0;
    LONGLONG secs;

    if (!trigger)
    {
        set_field(rec, C_STYPE, L"On demand only");
        return;
    }
    if (FAILED(ITrigger_get_Type(trigger, &type))) type = TASK_TRIGGER_EVENT;

    switch (type)
    {
    case TASK_TRIGGER_LOGON: set_field(rec, C_STYPE, L"At logon time"); return;
    case TASK_TRIGGER_BOOT: set_field(rec, C_STYPE, L"At system start up"); return;
    case TASK_TRIGGER_EVENT: set_field(rec, C_STYPE, L"When an event occurs"); return;
    case TASK_TRIGGER_IDLE: set_field(rec, C_STYPE, L"On idle"); return;
    case TASK_TRIGGER_SESSION_STATE_CHANGE: set_field(rec, C_STYPE, L"On session state change"); return;
    case TASK_TRIGGER_TIME:
    case TASK_TRIGGER_DAILY:
    case TASK_TRIGGER_WEEKLY:
    case TASK_TRIGGER_MONTHLY:
    case TASK_TRIGGER_MONTHLYDOW: break;
    default: set_field(rec, C_STYPE, L"Undefined"); return;
    }

    ITrigger_get_StartBoundary(trigger, &start);
    ITrigger_get_EndBoundary(trigger, &end);
    if (start && *start && format_boundary_date_time(start, date, ARRAYSIZE(date), time, ARRAYSIZE(time)))
    {
        set_field(rec, C_STIME, time);
        set_field(rec, C_SDATE, date);
    }
    if (end && *end && format_boundary_date_time(end, date, ARRAYSIZE(date), NULL, 0))
        set_field(rec, C_EDATE, date);

    if (SUCCEEDED(ITrigger_get_Repetition(trigger, &repetition)) && repetition)
    {
        IRepetitionPattern_get_Interval(repetition, &interval);
        IRepetitionPattern_get_Duration(repetition, &duration);
        IRepetitionPattern_get_StopAtDurationEnd(repetition, &stop);
        IRepetitionPattern_Release(repetition);
    }
    secs = interval && *interval ? duration_seconds(interval) : 0;
    set_field(rec, C_REPSTOP, stop != VARIANT_FALSE ? L"Enabled" : L"Disabled");
    if (secs > 0)
    {
        format_hours_minutes(secs, text, ARRAYSIZE(text));
        set_field(rec, C_REPEVERY, text);
        set_field(rec, C_REPUNTIL, L"None");
        secs = duration && *duration ? duration_seconds(duration) : 0;
        if (secs > 0)
        {
            format_hours_minutes(secs, text, ARRAYSIZE(text));
            set_field(rec, C_REPDUR, text);
        }
        else set_field(rec, C_REPDUR, L"Disabled");
    }
    else
    {
        set_field(rec, C_REPEVERY, L"Disabled");
        set_field(rec, C_REPUNTIL, L"Disabled");
        set_field(rec, C_REPDUR, L"Disabled");
    }

    if (type == TASK_TRIGGER_DAILY)
    {
        IDailyTrigger *daily;

        if (SUCCEEDED(ITrigger_QueryInterface(trigger, &IID_IDailyTrigger, (void **)&daily)))
        {
            SHORT interval_days = 1;
            IDailyTrigger_get_DaysInterval(daily, &interval_days);
            days = interval_days;
            IDailyTrigger_Release(daily);
        }
        _snwprintf(text, ARRAYSIZE(text), L"Every %ld day(s)", days ? days : 1);
        set_field(rec, C_DAYS, text);
        set_field(rec, C_STYPE, L"Daily ");
    }
    else if (type == TASK_TRIGGER_WEEKLY || type == TASK_TRIGGER_MONTHLY || type == TASK_TRIGGER_MONTHLYDOW)
        fill_calendar_fields(rec, trigger, type);
    else
    {
        if (secs > 0)
            set_field(rec, C_STYPE, secs % 3600 ? L"One Time Only, Minute " : L"One Time Only, Hourly ");
        else
            set_field(rec, C_STYPE, L"One Time Only");
    }
    SysFreeString(start);
    SysFreeString(end);
    SysFreeString(interval);
    SysFreeString(duration);
}

/* the fields that come from the definition of the task, all but the schedule */
static void fill_definition_fields(struct record *rec, ITaskDefinition *def)
{
    IRegistrationInfo *info = NULL;
    IPrincipal *principal = NULL;
    ITaskSettings *settings = NULL;
    IActionCollection *actions = NULL;
    BSTR text = NULL, user = NULL;
    TASK_LOGON_TYPE logon = TASK_LOGON_INTERACTIVE_TOKEN;
    WCHAR line[MAX_FIELD];
    VARIANT_BOOL on_batteries = VARIANT_TRUE, stop_batteries = VARIANT_TRUE, run_if_idle = VARIANT_FALSE;
    LONG count = 0;

    if (SUCCEEDED(ITaskDefinition_get_RegistrationInfo(def, &info)) && info)
    {
        if (SUCCEEDED(IRegistrationInfo_get_Author(info, &text)) && text && *text) set_field(rec, C_AUTHOR, text);
        SysFreeString(text);
        text = NULL;
        if (SUCCEEDED(IRegistrationInfo_get_Description(info, &text)) && text && *text)
            set_field(rec, C_COMMENT, text);
        SysFreeString(text);
        text = NULL;
        if (!rec->f[C_AUTHOR] || !*rec->f[C_AUTHOR]) set_field(rec, C_AUTHOR, L"N/A");
        IRegistrationInfo_Release(info);
    }

    if (SUCCEEDED(ITaskDefinition_get_Principal(def, &principal)) && principal)
    {
        IPrincipal_get_LogonType(principal, &logon);
        if (SUCCEEDED(IPrincipal_get_UserId(principal, &user)) && user && *user)
        {
            account_name(user, line, ARRAYSIZE(line));
            set_field(rec, C_RUNAS, line);
        }
        SysFreeString(user);
        IPrincipal_Release(principal);
    }
    if (!rec->f[C_RUNAS] || !*rec->f[C_RUNAS])
    {
        /* no principal: the user that registered it */
        if (rec->f[C_AUTHOR] && wcscmp(rec->f[C_AUTHOR], L"N/A"))
        {
            account_name(rec->f[C_AUTHOR], line, ARRAYSIZE(line));
            set_field(rec, C_RUNAS, line);
        }
        else set_field(rec, C_RUNAS, L"N/A");
    }
    set_field(rec, C_LOGON, logon == TASK_LOGON_INTERACTIVE_TOKEN || logon == TASK_LOGON_NONE ?
              L"Interactive only" : L"Interactive/Background");

    if (SUCCEEDED(ITaskDefinition_get_Settings(def, &settings)) && settings)
    {
        ITaskSettings_get_DisallowStartIfOnBatteries(settings, &on_batteries);
        ITaskSettings_get_StopIfGoingOnBatteries(settings, &stop_batteries);
        ITaskSettings_get_RunOnlyIfIdle(settings, &run_if_idle);
        if (SUCCEEDED(ITaskSettings_get_ExecutionTimeLimit(settings, &text)) && text && *text)
        {
            LONGLONG secs = duration_seconds(text);

            if (secs > 0)
            {
                _snwprintf(line, ARRAYSIZE(line), L"%02I64d:%02I64d:%02I64d", secs / 3600, secs % 3600 / 60, secs % 60);
                set_field(rec, C_STOP, line);
            }
            else if (secs == 0) set_field(rec, C_STOP, L"Disabled");
        }
        SysFreeString(text);
        ITaskSettings_Release(settings);
    }
    if (!rec->f[C_STOP]) set_field(rec, C_STOP, L"72:00:00");
    set_field(rec, C_IDLE, run_if_idle != VARIANT_FALSE ? L"Only Start If Idle" : L"Disabled");
    line[0] = 0;
    if (stop_batteries != VARIANT_FALSE) wcscpy(line, L"Stop On Battery Mode");
    if (on_batteries != VARIANT_FALSE)
    {
        if (line[0]) wcscat(line, L", ");
        wcscat(line, L"No Start On Batteries");
    }
    set_field(rec, C_POWER, line);

    if (SUCCEEDED(ITaskDefinition_get_Actions(def, &actions)) && actions)
    {
        IAction *action = NULL;
        IExecAction *exec = NULL;

        if (SUCCEEDED(IActionCollection_get_Count(actions, &count)) && count > 0 &&
            SUCCEEDED(IActionCollection_get_Item(actions, 1, &action)) &&
            SUCCEEDED(IAction_QueryInterface(action, &IID_IExecAction, (void **)&exec)))
        {
            BSTR path = NULL, args = NULL, dir = NULL;

            IExecAction_get_Path(exec, &path);
            IExecAction_get_Arguments(exec, &args);
            IExecAction_get_WorkingDirectory(exec, &dir);
            _snwprintf(line, ARRAYSIZE(line), L"%s%s%s", path ? path : L"", args && *args ? L" " : L"",
                       args ? args : L"");
            set_field(rec, C_RUN, line);
            if (dir && *dir) set_field(rec, C_STARTIN, dir);
            SysFreeString(path);
            SysFreeString(args);
            SysFreeString(dir);
            IExecAction_Release(exec);
        }
        if (action) IAction_Release(action);
        IActionCollection_Release(actions);
    }
}

/* the records of one task: one per trigger, or one when verbose is off or there are none */
static BOOL build_records(IRegisteredTask *task, const WCHAR *host, BOOL per_trigger, struct record **list, int *n)
{
    struct record base;
    ITaskDefinition *def = NULL;
    ITriggerCollection *triggers = NULL;
    BSTR path = NULL;
    TASK_STATE state = TASK_STATE_UNKNOWN;
    VARIANT_BOOL enabled = VARIANT_TRUE;
    DATE next = 0, last = 0;
    LONG result = 0, count = 0, i;
    HRESULT hr;
    WCHAR text[MAX_FIELD];
    struct record *recs;

    memset(&base, 0, sizeof(base));
    set_field(&base, C_HOST, host);
    IRegisteredTask_get_Path(task, &path);
    set_field(&base, C_NAME, path);
    IRegisteredTask_get_State(task, &state);
    IRegisteredTask_get_Enabled(task, &enabled);
    set_field(&base, C_STATUS, state_text(state));
    set_field(&base, C_STATE, enabled != VARIANT_FALSE ? L"Enabled" : L"Disabled");
    set_field(&base, C_SCHEDULE, L"Scheduling data is not available in this format.");
    set_field(&base, C_DELETE, L"Disabled");

    hr = IRegisteredTask_get_NextRunTime(task, &next);
    format_date(SUCCEEDED(hr) && hr == S_OK ? next : 0, FALSE, text, ARRAYSIZE(text));
    set_field(&base, C_NEXT, text);
    IRegisteredTask_get_LastRunTime(task, &last);
    format_date(last, TRUE, text, ARRAYSIZE(text));
    set_field(&base, C_LASTRUN, text);
    IRegisteredTask_get_LastTaskResult(task, &result);
    _snwprintf(text, ARRAYSIZE(text), L"%ld", result);
    set_field(&base, C_LASTRES, text);
    set_field(&base, C_STARTIN, L"N/A");
    set_field(&base, C_COMMENT, L"N/A");
    set_field(&base, C_STIME, L"N/A");
    set_field(&base, C_SDATE, L"N/A");
    set_field(&base, C_EDATE, L"N/A");
    set_field(&base, C_DAYS, L"N/A");
    set_field(&base, C_MONTHS, L"N/A");
    set_field(&base, C_REPEVERY, L"N/A");
    set_field(&base, C_REPUNTIL, L"N/A");
    set_field(&base, C_REPDUR, L"N/A");
    set_field(&base, C_REPSTOP, L"N/A");
    SysFreeString(path);

    if (SUCCEEDED(IRegisteredTask_get_Definition(task, &def)) && def)
    {
        fill_definition_fields(&base, def);
        if (SUCCEEDED(ITaskDefinition_get_Triggers(def, &triggers)) && triggers)
            ITriggerCollection_get_Count(triggers, &count);
    }
    if (!base.f[C_LOGON]) set_field(&base, C_LOGON, L"Interactive only");
    if (!base.f[C_AUTHOR]) set_field(&base, C_AUTHOR, L"N/A");
    if (!base.f[C_RUN]) set_field(&base, C_RUN, L"N/A");
    if (!base.f[C_RUNAS]) set_field(&base, C_RUNAS, L"N/A");
    if (!base.f[C_STOP]) set_field(&base, C_STOP, L"72:00:00");
    if (!base.f[C_IDLE]) set_field(&base, C_IDLE, L"Disabled");
    if (!base.f[C_POWER]) set_field(&base, C_POWER, L"");

    *n = per_trigger && count > 1 ? count : 1;
    if (!(recs = calloc(*n, sizeof(*recs))))
    {
        free_record(&base);
        if (triggers) ITriggerCollection_Release(triggers);
        if (def) ITaskDefinition_Release(def);
        return FALSE;
    }
    for (i = 0; i < *n; i++)
    {
        ITrigger *trigger = NULL;
        int c;

        for (c = 0; c < C_COUNT; c++)
            if (base.f[c]) recs[i].f[c] = wcsdup(base.f[c]);
        if (count && triggers) ITriggerCollection_get_Item(triggers, i + 1, &trigger);
        fill_trigger_fields(&recs[i], trigger);
        if (trigger) ITrigger_Release(trigger);
        if (!recs[i].f[C_STYPE]) set_field(&recs[i], C_STYPE, L"Undefined");
    }
    free_record(&base);
    if (triggers) ITriggerCollection_Release(triggers);
    if (def) ITaskDefinition_Release(def);
    *list = recs;
    return TRUE;
}

enum format { FMT_TABLE, FMT_LIST, FMT_CSV };

static void print_table_row(struct sb *sb, const struct record *rec, const enum column *cols, int ncols,
                            BOOL short_name)
{
    int i;

    for (i = 0; i < ncols; i++)
    {
        enum column c = cols[i];
        const WCHAR *value = rec->f[c] ? rec->f[c] : L"";
        int width = columns[c].width;
        size_t len;

        if (c == C_NAME && short_name && wcsrchr(value, '\\')) value = wcsrchr(value, '\\') + 1;
        len = min((size_t)width, wcslen(value));
        if (columns[c].right) sb_pad(sb, width - len, ' ');
        sb_add_n(sb, value, len);
        if (!columns[c].right) sb_pad(sb, width - len, ' ');
        if (i + 1 < ncols) sb_add(sb, L" ");
    }
    sb_add(sb, L"\n");
}

static void print_table_header(struct sb *sb, const enum column *cols, int ncols)
{
    int i;

    for (i = 0; i < ncols; i++)
    {
        size_t len = min((size_t)columns[cols[i]].width, wcslen(columns[cols[i]].title));

        sb_add_n(sb, columns[cols[i]].title, len);
        sb_pad(sb, columns[cols[i]].width - len, ' ');
        if (i + 1 < ncols) sb_add(sb, L" ");
    }
    sb_add(sb, L"\n");
    for (i = 0; i < ncols; i++)
    {
        sb_pad(sb, columns[cols[i]].width, '=');
        if (i + 1 < ncols) sb_add(sb, L" ");
    }
    sb_add(sb, L"\n");
}

static void print_csv_row(struct sb *sb, const struct record *rec, const enum column *cols, int ncols)
{
    int i;
    const WCHAR *p;

    for (i = 0; i < ncols; i++)
    {
        sb_add(sb, L"\"");
        for (p = rec->f[cols[i]] ? rec->f[cols[i]] : L""; *p; p++)
        {
            if (*p == '"') sb_add(sb, L"\"");
            sb_add_n(sb, p, 1);
        }
        sb_add(sb, i + 1 < ncols ? L"\"," : L"\"");
    }
    sb_add(sb, L"\n");
}

static void print_list_record(struct sb *sb, const struct record *rec, const enum column *cols, int ncols, BOOL verbose)
{
    int i, width = verbose ? 38 : 15;

    for (i = 0; i < ncols; i++)
    {
        size_t len = wcslen(columns[cols[i]].title) + 1;

        sb_add(sb, columns[cols[i]].title);
        sb_add(sb, L":");
        sb_pad(sb, width - len, ' ');
        sb_add(sb, rec->f[cols[i]] ? rec->f[cols[i]] : L"");
        sb_add(sb, L"\n");
    }
}

struct query
{
    enum format format;
    BOOL verbose, no_header;
    const WCHAR *match;     /* full name of the one task, or NULL */
    WCHAR host[MAX_COMPUTERNAME_LENGTH + 1];
    int found;
    HRESULT error;
};

static const enum column all_columns[C_COUNT] =
{
    C_HOST, C_NAME, C_NEXT, C_STATUS, C_LOGON, C_LASTRUN, C_LASTRES, C_AUTHOR, C_RUN, C_STARTIN, C_COMMENT, C_STATE,
    C_IDLE, C_POWER, C_RUNAS, C_DELETE, C_STOP, C_SCHEDULE, C_STYPE, C_STIME, C_SDATE, C_EDATE, C_DAYS, C_MONTHS,
    C_REPEVERY, C_REPUNTIL, C_REPDUR, C_REPSTOP
};
static const enum column table_columns[] = { C_NAME, C_NEXT, C_STATUS };
static const enum column list_columns[] = { C_HOST, C_NAME, C_NEXT, C_STATUS, C_LOGON };

static void sort_names(WCHAR **names, void **objects, LONG count)
{
    LONG i;

    /* an insertion sort of names and their objects: the lists are short */
    for (i = 1; i < count; i++)
    {
        WCHAR *name = names[i];
        void *object = objects[i];
        LONG j = i - 1;

        while (j >= 0 && (!names[j] || (name && wcsicmp(names[j], name) > 0)))
        {
            names[j + 1] = names[j];
            objects[j + 1] = objects[j];
            j--;
        }
        names[j + 1] = name;
        objects[j + 1] = object;
    }
}

static void print_csv_header(struct sb *sb, const enum column *cols, int ncols)
{
    struct record titles;
    int c;

    memset(&titles, 0, sizeof(titles));
    for (c = 0; c < ncols; c++) titles.f[cols[c]] = wcsdup(columns[cols[c]].title);
    print_csv_row(sb, &titles, cols, ncols);
    free_record(&titles);
}

static void query_tasks(struct query *q, ITaskFolder *folder, BSTR folder_path)
{
    IRegisteredTaskCollection *tasks = NULL;
    struct sb sb = {0};
    WCHAR **names = NULL;
    IRegisteredTask **objects = NULL;
    LONG count = 0, i;
    int printed = 0;
    HRESULT hr;
    const enum column *cols;
    int ncols;

    if (q->verbose) { cols = all_columns; ncols = C_COUNT; }
    else if (q->format == FMT_LIST) { cols = list_columns; ncols = ARRAYSIZE(list_columns); }
    else { cols = table_columns; ncols = q->format == FMT_CSV ? 3 : ARRAYSIZE(table_columns); }

    hr = ITaskFolder_GetTasks(folder, TASK_ENUM_HIDDEN, &tasks);
    if (SUCCEEDED(hr) && tasks) hr = IRegisteredTaskCollection_get_Count(tasks, &count);
    if (FAILED(hr))
    {
        q->error = hr;
        if (tasks) IRegisteredTaskCollection_Release(tasks);
        return;
    }

    names = calloc(count + 1, sizeof(*names));
    objects = calloc(count + 1, sizeof(*objects));
    for (i = 0; i < count && names && objects; i++)
    {
        VARIANT index;
        BSTR path = NULL;

        V_VT(&index) = VT_I4;
        V_I4(&index) = i + 1;
        if (FAILED(IRegisteredTaskCollection_get_Item(tasks, index, &objects[i])) || !objects[i]) continue;
        IRegisteredTask_get_Path(objects[i], &path);
        names[i] = wcsdup(path ? path : L"");
        SysFreeString(path);
    }
    if (names && objects) sort_names(names, (void **)objects, count);

    /* the heading of the folder: CSV has a header line, the others "Folder: name" */
    if (q->format == FMT_CSV)
    {
        if (!q->no_header) print_csv_header(&sb, cols, ncols);
    }
    else
    {
        sb_add(&sb, L"\nFolder: ");
        sb_add(&sb, folder_path);
        sb_add(&sb, L"\n");
    }

    for (i = 0; i < count && names && objects; i++)
    {
        struct record *recs;
        int n, k;

        if (!objects[i] || !names[i]) continue;
        if (q->match && wcsicmp(q->match, names[i])) continue;
        if (!build_records(objects[i], q->host, q->format != FMT_TABLE, &recs, &n)) continue;

        for (k = 0; k < n; k++)
        {
            if (q->format == FMT_TABLE)
            {
                if (!printed && !q->no_header) print_table_header(&sb, cols, ncols);
                print_table_row(&sb, &recs[k], cols, ncols, TRUE);
            }
            else if (q->format == FMT_CSV)
                print_csv_row(&sb, &recs[k], cols, ncols);
            else
            {
                if (printed) sb_add(&sb, L"\n");
                print_list_record(&sb, &recs[k], cols, ncols, q->verbose);
            }
            printed++;
            free_record(&recs[k]);
        }
        free(recs);
        q->found++;
    }

    if (!printed && q->format != FMT_CSV)
    {
        if (q->format == FMT_TABLE && !q->no_header) print_table_header(&sb, cols, ncols);
        sb_add(&sb, L"INFO: There are no scheduled tasks presently available at your access level.\n");
    }
    sb_flush(&sb);

    for (i = 0; i < count; i++)
    {
        if (names) free(names[i]);
        if (objects && objects[i]) IRegisteredTask_Release(objects[i]);
    }
    free(names);
    free(objects);
    free(sb.buf);
    IRegisteredTaskCollection_Release(tasks);
}

static void query_folder(struct query *q, ITaskFolder *folder)
{
    ITaskFolderCollection *folders = NULL;
    BSTR path = NULL;
    LONG count = 0, i;
    WCHAR **names = NULL;
    ITaskFolder **objects = NULL;
    BOOL wanted = TRUE;

    ITaskFolder_get_Path(folder, &path);
    if (q->match)
    {
        /* one task: only the folder it is in */
        const WCHAR *slash = wcsrchr(q->match, '\\');
        size_t dir_len = slash == q->match ? 1 : (size_t)(slash - q->match);

        wanted = wcslen(path) == dir_len && !wcsnicmp(path, q->match, dir_len);
    }
    if (wanted) query_tasks(q, folder, path);

    if (SUCCEEDED(ITaskFolder_GetFolders(folder, 0, &folders)) && folders &&
        SUCCEEDED(ITaskFolderCollection_get_Count(folders, &count)) && count)
    {
        names = calloc(count, sizeof(*names));
        objects = calloc(count, sizeof(*objects));
        for (i = 0; i < count && names && objects; i++)
        {
            VARIANT index;
            BSTR sub = NULL;

            V_VT(&index) = VT_I4;
            V_I4(&index) = i + 1;
            if (FAILED(ITaskFolderCollection_get_Item(folders, index, &objects[i])) || !objects[i]) continue;
            ITaskFolder_get_Path(objects[i], &sub);
            names[i] = wcsdup(sub ? sub : L"");
            SysFreeString(sub);
        }
        if (names && objects)
        {
            sort_names(names, (void **)objects, count);
            for (i = 0; i < count; i++)
                if (objects[i]) query_folder(q, objects[i]);
        }
        for (i = 0; i < count; i++)
        {
            if (names) free(names[i]);
            if (objects && objects[i]) ITaskFolder_Release(objects[i]);
        }
        free(names);
        free(objects);
    }
    if (folders) ITaskFolderCollection_Release(folders);
    SysFreeString(path);
}

static int query_command(int argc, WCHAR **argv)
{
    struct options opt;
    struct query q;
    ITaskFolder *root = NULL;
    WCHAR *match = NULL;
    DWORD size = ARRAYSIZE(q.host);
    HRESULT hr;

    if (!parse_options(argc, argv, &opt, L"QUERY")) return 1;
    if (opt.help)
    {
        out(L"\nSCHTASKS /Query [/FO format] [/NH] [/V] [/TN taskname] [/XML]\n\n"
            L"Description:\n    Displays the scheduled tasks.\n\n"
            L"Parameter List:\n"
            L"    /FO   format    The output format: TABLE, LIST, CSV (default TABLE).\n"
            L"    /NH             Do not print the column headers (TABLE and CSV).\n"
            L"    /V              Verbose output.\n"
            L"    /TN   taskname  Only this task.\n"
            L"    /XML            Print the XML of the task given with /TN.\n");
        return 0;
    }
    memset(&q, 0, sizeof(q));
    q.format = FMT_TABLE;
    if (opt.fo)
    {
        if (!wcsicmp(opt.fo, L"TABLE")) q.format = FMT_TABLE;
        else if (!wcsicmp(opt.fo, L"LIST")) q.format = FMT_LIST;
        else if (!wcsicmp(opt.fo, L"CSV")) q.format = FMT_CSV;
        else
        {
            error_usage(L"Improper display format type specified.", L"QUERY");
            return 1;
        }
    }
    if (opt.nh && q.format == FMT_LIST)
    {
        error_usage(L"/NH switch cannot be used with the LIST format.", L"QUERY");
        return 1;
    }
    if (opt.s)
    {
        error_text(L"Querying a remote system is not supported.");
        return 1;
    }
    q.verbose = opt.v;
    q.no_header = opt.nh;
    GetComputerNameW(q.host, &size);

    if (FAILED(hr = connect_service()))
    {
        error_text(L"The Task Scheduler is not available on this system.");
        return 1;
    }

    if (opt.have_xml_switch)
    {
        IRegisteredTask *task;
        BSTR xml = NULL;

        if (!opt.tn)
        {
            error_usage(L"Invalid syntax. Mandatory option '/tn' is missing.", L"QUERY");
            return 1;
        }
        if (FAILED(hr = get_task(opt.tn, &task)))
        {
            error_hr(hr);
            return 1;
        }
        hr = IRegisteredTask_get_Xml(task, &xml);
        IRegisteredTask_Release(task);
        if (FAILED(hr))
        {
            error_hr(hr);
            return 1;
        }
        out(xml);
        out(L"\n");
        SysFreeString(xml);
        return 0;
    }

    if (opt.tn)
    {
        IRegisteredTask *task;

        /* the task must exist: Windows reports a missing file, not an empty list */
        if (FAILED(hr = get_task(opt.tn, &task)))
        {
            error_hr(hr);
            return 1;
        }
        IRegisteredTask_Release(task);
        match = full_task_name(opt.tn);
        q.match = match;
    }

    if (FAILED(hr = ITaskService_GetFolder(service, (BSTR)L"\\", &root)))
    {
        error_hr(hr);
        free(match);
        return 1;
    }
    query_folder(&q, root);
    ITaskFolder_Release(root);
    free(match);
    if (FAILED(q.error))
    {
        error_hr(q.error);
        return 1;
    }
    return 0;
}

/* ---------- run, end, delete, change ---------- */

static int run_command(int argc, WCHAR **argv)
{
    struct options opt;
    IRegisteredTask *task;
    IRunningTask *running = NULL;
    VARIANT empty;
    WCHAR *full;
    HRESULT hr;

    if (!parse_options(argc, argv, &opt, L"RUN")) return 1;
    if (opt.help)
    {
        out(L"\nSCHTASKS /Run /TN taskname\n\nDescription:\n    Runs a scheduled task on demand.\n");
        return 0;
    }
    if (!opt.tn)
    {
        error_usage(L"Invalid syntax. Mandatory option '/tn' is missing.", L"RUN");
        return 1;
    }
    if (opt.s)
    {
        error_text(L"Running a task on a remote system is not supported.");
        return 1;
    }
    if (FAILED(hr = connect_service()))
    {
        error_text(L"The Task Scheduler is not available on this system.");
        return 1;
    }
    if (FAILED(hr = get_task(opt.tn, &task)))
    {
        error_hr(hr);
        return 1;
    }
    VariantInit(&empty);
    hr = IRegisteredTask_Run(task, empty, &running);
    if (running) IRunningTask_Release(running);
    IRegisteredTask_Release(task);
    if (FAILED(hr))
    {
        error_hr(hr);
        return 1;
    }
    full = full_task_name(opt.tn);
    success(L"SUCCESS: Attempted to run the scheduled task \"%s\".\n", opt.tn);
    free(full);
    return 0;
}

static int end_command(int argc, WCHAR **argv)
{
    struct options opt;
    IRegisteredTask *task;
    HRESULT hr;

    if (!parse_options(argc, argv, &opt, L"END")) return 1;
    if (opt.help)
    {
        out(L"\nSCHTASKS /End /TN taskname\n\nDescription:\n    Stops the programs started by a scheduled task.\n");
        return 0;
    }
    if (!opt.tn)
    {
        error_usage(L"Invalid syntax. Mandatory option '/tn' is missing.", L"END");
        return 1;
    }
    if (FAILED(hr = connect_service()))
    {
        error_text(L"The Task Scheduler is not available on this system.");
        return 1;
    }
    if (FAILED(hr = get_task(opt.tn, &task)))
    {
        error_hr(hr);
        return 1;
    }
    hr = IRegisteredTask_Stop(task, 0);
    IRegisteredTask_Release(task);
    if (FAILED(hr))
    {
        error_hr(hr);
        return 1;
    }
    success(L"SUCCESS: The scheduled task \"%s\" was successfully terminated.\n", opt.tn);
    return 0;
}

static int delete_command(int argc, WCHAR **argv)
{
    struct options opt;
    ITaskFolder *root;
    WCHAR *full;
    BSTR str;
    WCHAR question[MAX_PATH * 2];
    HRESULT hr;

    if (!parse_options(argc, argv, &opt, L"DELETE")) return 1;
    if (opt.help)
    {
        out(L"\nSCHTASKS /Delete /TN taskname [/F]\n\nDescription:\n    Deletes a scheduled task.\n\n"
            L"Parameter List:\n    /TN   taskname  The task to delete.\n    /F              Do not ask for confirmation.\n");
        return 0;
    }
    if (!opt.tn)
    {
        error_usage(L"Invalid syntax. Mandatory option '/tn' is missing.", L"DELETE");
        return 1;
    }
    if (FAILED(hr = connect_service()))
    {
        error_text(L"The Task Scheduler is not available on this system.");
        return 1;
    }
    if (!opt.f)
    {
        IRegisteredTask *task;

        /* without /F a missing task is reported by name, and an existing one is confirmed */
        if (FAILED(hr = get_task(opt.tn, &task)))
        {
            if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND))
            {
                _snwprintf(question, ARRAYSIZE(question), L"The specified task name \"%s\" does not exist in the system.",
                           opt.tn);
                error_text(question);
            }
            else error_hr(hr);
            return 1;
        }
        IRegisteredTask_Release(task);
        _snwprintf(question, ARRAYSIZE(question), L"WARNING: Are you sure you want to remove the task \"%s\"", opt.tn);
        if (!ask(question)) return 0;
    }

    if (FAILED(hr = ITaskService_GetFolder(service, (BSTR)L"\\", &root)))
    {
        error_hr(hr);
        return 1;
    }
    full = full_task_name(opt.tn);
    str = SysAllocString(full);
    hr = ITaskFolder_DeleteTask(root, str, 0);
    SysFreeString(str);
    free(full);
    ITaskFolder_Release(root);
    if (FAILED(hr))
    {
        error_hr(hr);
        return 1;
    }
    success(L"SUCCESS: The scheduled task \"%s\" was successfully deleted.\n", opt.tn);
    return 0;
}

static int change_command(int argc, WCHAR **argv)
{
    struct options opt;
    IRegisteredTask *task;
    HRESULT hr;

    if (!parse_options(argc, argv, &opt, L"CHANGE")) return 1;
    if (opt.help)
    {
        out(L"\nSCHTASKS /Change /TN taskname [/ENABLE | /DISABLE]\n\nDescription:\n"
            L"    Enables or disables a scheduled task.\n");
        return 0;
    }
    if (!opt.tn)
    {
        error_usage(L"Invalid syntax. Mandatory option '/tn' is missing.", L"CHANGE");
        return 1;
    }
    if (opt.tr || opt.ru || opt.rp || opt.st || opt.sd || opt.ed || opt.ri || opt.du)
    {
        error_text(L"Changing the command, the account or the schedule of a task is not supported.");
        return 1;
    }
    if (!opt.enable && !opt.disable)
    {
        error_usage(L"Invalid syntax. At least one change option is required.", L"CHANGE");
        return 1;
    }
    if (opt.enable && opt.disable)
    {
        error_usage(L"Invalid syntax. /ENABLE and /DISABLE cannot be used together.", L"CHANGE");
        return 1;
    }
    if (FAILED(hr = connect_service()))
    {
        error_text(L"The Task Scheduler is not available on this system.");
        return 1;
    }
    if (FAILED(hr = get_task(opt.tn, &task)))
    {
        error_hr(hr);
        return 1;
    }
    hr = IRegisteredTask_put_Enabled(task, opt.enable ? VARIANT_TRUE : VARIANT_FALSE);
    IRegisteredTask_Release(task);
    if (FAILED(hr))
    {
        error_hr(hr);
        return 1;
    }
    success(L"SUCCESS: The parameters of scheduled task \"%s\" have been changed.\n", opt.tn);
    return 0;
}

/* ---------- create ---------- */

static BSTR read_file_to_bstr(const WCHAR *file_name)
{
    LARGE_INTEGER file_size;
    DWORD read_size = 0, size;
    unsigned char *data;
    HANDLE file;
    BOOL ok = FALSE;
    BSTR ret = NULL;

    file = CreateFileW(file_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        error_hr(HRESULT_FROM_WIN32(GetLastError()));
        return NULL;
    }
    if (!GetFileSizeEx(file, &file_size) || !file_size.QuadPart || file_size.QuadPart > 1024 * 1024)
    {
        CloseHandle(file);
        error_text(L"The XML file is empty or too large.");
        return NULL;
    }
    data = malloc(file_size.QuadPart);
    if (data) ok = ReadFile(file, data, file_size.QuadPart, &read_size, NULL);
    CloseHandle(file);
    if (!ok)
    {
        free(data);
        error_text(L"The XML file cannot be read.");
        return NULL;
    }
    if (read_size > 2 && data[0] == 0xff && data[1] == 0xfe)    /* UTF-16 BOM */
        ret = SysAllocStringLen((const WCHAR *)(data + 2), (read_size - 2) / sizeof(WCHAR));
    else
    {
        unsigned char *text = data;
        DWORD cp = CP_ACP;

        if (read_size > 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf)
        {
            text += 3;
            read_size -= 3;
            cp = CP_UTF8;
        }
        size = MultiByteToWideChar(cp, 0, (const char *)text, read_size, NULL, 0);
        ret = SysAllocStringLen(NULL, size);
        if (ret) MultiByteToWideChar(cp, 0, (const char *)text, read_size, ret, size);
    }
    free(data);
    return ret;
}

/* splits a command line as Windows does for /tr: the program (quotes kept when quoted) and the rest */
static void split_command(const WCHAR *tr, WCHAR **program, WCHAR **arguments)
{
    const WCHAR *p = tr, *end;

    while (*p == ' ') p++;
    if (*p == '"')
    {
        end = wcschr(p + 1, '"');
        end = end ? end + 1 : p + wcslen(p);
    }
    else
    {
        end = wcschr(p, ' ');
        if (!end) end = p + wcslen(p);
    }
    *program = calloc(end - p + 1, sizeof(WCHAR));
    if (*program) memcpy(*program, p, (end - p) * sizeof(WCHAR));
    while (*end == ' ') end++;
    *arguments = wcsdup(end);
}

static BOOL set_exec_action(ITaskDefinition *def, const WCHAR *tr)
{
    IActionCollection *actions = NULL;
    IAction *action = NULL;
    IExecAction *exec = NULL;
    WCHAR *program, *arguments;
    BOOL ok = FALSE;

    split_command(tr, &program, &arguments);
    if (program && arguments && SUCCEEDED(ITaskDefinition_get_Actions(def, &actions)) &&
        SUCCEEDED(IActionCollection_Create(actions, TASK_ACTION_EXEC, &action)) &&
        SUCCEEDED(IAction_QueryInterface(action, &IID_IExecAction, (void **)&exec)))
    {
        ok = SUCCEEDED(IExecAction_put_Path(exec, program)) && SUCCEEDED(IExecAction_put_Arguments(exec, arguments));
    }
    if (exec) IExecAction_Release(exec);
    if (action) IAction_Release(action);
    if (actions) IActionCollection_Release(actions);
    free(program);
    free(arguments);
    return ok;
}

/* the current user as DOMAIN\name for the Author of a task */
static void current_user(WCHAR *text, size_t size)
{
    WCHAR host[MAX_COMPUTERNAME_LENGTH + 1], user[256];
    DWORD host_size = ARRAYSIZE(host), user_size = ARRAYSIZE(user);

    if (!GetComputerNameW(host, &host_size)) host[0] = 0;
    if (!GetUserNameW(user, &user_size)) user[0] = 0;
    _snwprintf(text, size, L"%s\\%s", host, user);
}

static BOOL is_system_account(const WCHAR *ru)
{
    return !wcsicmp(ru, L"SYSTEM") || !wcsicmp(ru, L"NT AUTHORITY\\SYSTEM") || !wcsicmp(ru, L"LocalSystem");
}

static BOOL is_current_user(const WCHAR *ru)
{
    WCHAR user[256], full[600];
    DWORD size = ARRAYSIZE(user);
    const WCHAR *slash = wcsrchr(ru, '\\');

    if (!GetUserNameW(user, &size)) return FALSE;
    current_user(full, ARRAYSIZE(full));
    return !wcsicmp(slash ? slash + 1 : ru, user) && (!slash || !wcsnicmp(ru, full, slash - ru) ||
           !wcsnicmp(ru, L".", slash - ru));
}

/* a list of names or numbers separated by commas, "*" for all: the bits of the ones the words give */
static BOOL parse_word_list(const WCHAR *str, const WCHAR *const *words, unsigned int count, unsigned int *mask)
{
    WCHAR item[32];
    const WCHAR *p = str;
    unsigned int i, n;

    *mask = 0;
    if (!wcscmp(str, L"*"))
    {
        *mask = (1u << count) - 1;
        return TRUE;
    }
    while (*p)
    {
        for (n = 0; *p && *p != ',' && n + 1 < ARRAYSIZE(item); p++) item[n++] = *p;
        item[n] = 0;
        if (*p == ',') p++;
        else if (*p) return FALSE;
        for (i = 0; i < count; i++)
            if (!wcsnicmp(item, words[i], 3) && (n == 3 || !wcsicmp(item, words[i]))) break;
        if (i == count) return FALSE;
        *mask |= 1u << i;
    }
    return *mask != 0;
}

/* SCHTASKS /Create /SC WEEKLY [/MO weeks] [/D MON,TUE,...|*]: Monday when /D is not given */
static BOOL set_weekly(ITrigger *trigger, const struct options *opt, long weeks)
{
    IWeeklyTrigger *weekly;
    unsigned int days = 2;

    if (weeks < 1 || weeks > 52)
    {
        error_usage(L"Invalid syntax. Invalid /MO value for the WEEKLY schedule; use 1 to 52.", L"CREATE");
        return FALSE;
    }
    if (opt->d && !parse_word_list(opt->d, day_words, 7, &days))
    {
        error_usage(L"Invalid syntax. Invalid /D value for the WEEKLY schedule; use MON, TUE, ... or *.", L"CREATE");
        return FALSE;
    }
    if (FAILED(ITrigger_QueryInterface(trigger, &IID_IWeeklyTrigger, (void **)&weekly))) return FALSE;
    IWeeklyTrigger_put_DaysOfWeek(weekly, (SHORT)days);
    IWeeklyTrigger_put_WeeksInterval(weekly, (SHORT)weeks);
    IWeeklyTrigger_Release(weekly);
    return TRUE;
}

/* SCHTASKS /Create /SC MONTHLY [/MO 1-12|FIRST|SECOND|THIRD|FOURTH|LAST|LASTDAY] [/D day|weekday] [/M months]:
 * every month on day 1 when nothing is given; 'nth' is the week of a /MO FIRST..LAST (1..5) */
static BOOL set_monthly(ITrigger *trigger, const struct options *opt, TASK_TRIGGER_TYPE2 type, int nth,
                        const SYSTEMTIME *start)
{
    unsigned int months = 0xfff, days = 0, k;
    BOOL lastday = opt->mo && !wcsicmp(opt->mo, L"LASTDAY");
    long every = 1;

    if (opt->m && !parse_word_list(opt->m, month_words, 12, &months))
    {
        error_usage(L"Invalid syntax. Invalid /M value for the MONTHLY schedule; use JAN, FEB, ... or *.", L"CREATE");
        return FALSE;
    }
    if (opt->mo && !nth && !lastday)
    {
        every = wcstol(opt->mo, NULL, 10);
        if (every < 1 || every > 12)
        {
            error_usage(L"Invalid syntax. Invalid /MO value for the MONTHLY schedule.", L"CREATE");
            return FALSE;
        }
        if (every > 1)
        {
            /* every N months, counted from the month of the start: the months of that pattern */
            if (opt->m)
            {
                error_usage(L"Invalid syntax. /M cannot be combined with /MO for a number of months.", L"CREATE");
                return FALSE;
            }
            months = 0;
            for (k = start->wMonth - 1; !(months & (1u << (k % 12))); k += every)
                months |= 1u << (k % 12);
        }
    }

    if (type == TASK_TRIGGER_MONTHLYDOW)
    {
        IMonthlyDOWTrigger *dow;

        if (!opt->d || !parse_word_list(opt->d, day_words, 7, &days))
        {
            error_usage(L"Invalid syntax. /D with MON, TUE, ... is required for FIRST, SECOND, THIRD, FOURTH and LAST.",
                        L"CREATE");
            return FALSE;
        }
        if (FAILED(ITrigger_QueryInterface(trigger, &IID_IMonthlyDOWTrigger, (void **)&dow))) return FALSE;
        IMonthlyDOWTrigger_put_DaysOfWeek(dow, (SHORT)days);
        IMonthlyDOWTrigger_put_MonthsOfYear(dow, (SHORT)months);
        /* a new trigger has the first week: the week asked for replaces it */
        IMonthlyDOWTrigger_put_WeeksOfMonth(dow, nth == 5 ? 0 : (SHORT)(1 << (nth - 1)));
        if (nth == 5) IMonthlyDOWTrigger_put_RunOnLastWeekOfMonth(dow, VARIANT_TRUE);
        IMonthlyDOWTrigger_Release(dow);
    }
    else
    {
        IMonthlyTrigger *monthly;
        long day = 1;

        if (!lastday && opt->d)
        {
            WCHAR *end;

            day = wcstol(opt->d, &end, 10);
            if (*end || day < 1 || day > 31)
            {
                error_usage(L"Invalid syntax. Invalid /D value for the MONTHLY schedule; use 1 to 31.", L"CREATE");
                return FALSE;
            }
        }
        if (FAILED(ITrigger_QueryInterface(trigger, &IID_IMonthlyTrigger, (void **)&monthly))) return FALSE;
        if (lastday) IMonthlyTrigger_put_RunOnLastDayOfMonth(monthly, VARIANT_TRUE);
        else IMonthlyTrigger_put_DaysOfMonth(monthly, 1L << (day - 1));
        IMonthlyTrigger_put_MonthsOfYear(monthly, (SHORT)months);
        IMonthlyTrigger_Release(monthly);
    }
    return TRUE;
}

static int create_command(int argc, WCHAR **argv)
{
    struct options opt;
    ITaskFolder *root = NULL;
    IRegisteredTask *registered = NULL;
    ITaskDefinition *def = NULL;
    ITriggerCollection *triggers = NULL;
    ITrigger *trigger = NULL;
    IRegistrationInfo *info = NULL;
    IPrincipal *principal = NULL;
    ITaskSettings *settings = NULL;
    VARIANT empty, user_v, password_v;
    TASK_LOGON_TYPE logon = TASK_LOGON_INTERACTIVE_TOKEN;
    LONG flags = TASK_CREATE;
    WCHAR *full = NULL, text[MAX_PATH * 2];
    BSTR name = NULL, xml = NULL;
    HRESULT hr;
    BOOL system_account = FALSE;
    SYSTEMTIME now, start;
    long interval = 1;

    if (!parse_options(argc, argv, &opt, L"CREATE")) return 1;
    if (opt.help)
    {
        out(L"\nSCHTASKS /Create /TN taskname /TR taskrun /SC schedule [/MO modifier] [/ST starttime]\n"
            L"         [/SD startdate] [/ED enddate] [/RI minutes] [/DU duration] [/RU username] [/RL level] [/F]\n"
            L"SCHTASKS /Create /TN taskname /XML xmlfile [/RU username] [/F]\n\n"
            L"Description:\n    Creates a scheduled task. Schedules: ONCE, DAILY, MINUTE, HOURLY, ONLOGON, ONSTART.\n"
            L"    /RU may be SYSTEM (administrators only); a task of another user with a password is not supported.\n");
        return 0;
    }
    if (!opt.tn)
    {
        error_usage(L"Invalid syntax. Mandatory option '/tn' is missing.", L"CREATE");
        return 1;
    }
    if (opt.s)
    {
        error_text(L"Creating a task on a remote system is not supported.");
        return 1;
    }
    if (opt.rp)
    {
        error_text(L"Tasks that run with a stored password are not supported. Use /RU SYSTEM, or omit /RU for the current user.");
        return 1;
    }
    if (opt.ru && is_system_account(opt.ru)) system_account = TRUE;
    else if (opt.ru && !is_current_user(opt.ru))
    {
        error_text(L"Tasks that run as another user need a password, which is not supported.");
        return 1;
    }
    if (opt.xml && (opt.tr || opt.sc))
    {
        error_usage(L"Invalid syntax. /XML cannot be combined with /TR or /SC.", L"CREATE");
        return 1;
    }
    if (!opt.xml && !opt.tr)
    {
        error_usage(L"Invalid syntax. Mandatory option '/tr' is missing.", L"CREATE");
        return 1;
    }
    if (!opt.xml && !opt.sc)
    {
        error_usage(L"Invalid syntax. Mandatory option '/sc' is missing.", L"CREATE");
        return 1;
    }

    GetLocalTime(&now);
    start = now;
    start.wMilliseconds = 0;
    start.wSecond = 0;
    if (opt.st && !parse_time_arg(opt.st, &start))
    {
        error_usage(L"Invalid syntax. Invalid /ST value; use HH:mm or HH:mm:ss.", L"CREATE");
        return 1;
    }
    if (opt.sd && !parse_date_arg(opt.sd, &start))
    {
        error_usage(L"Invalid syntax. Invalid /SD value; use MM/DD/YYYY.", L"CREATE");
        return 1;
    }
    /* for MONTHLY, /MO is a number of months or a word (FIRST..LAST, LASTDAY), read with the schedule */
    if (opt.mo && !(opt.sc && !wcsicmp(opt.sc, L"MONTHLY")))
    {
        interval = wcstol(opt.mo, NULL, 10);
        if (interval < 1 || interval > 32767)
        {
            error_usage(L"Invalid syntax. Invalid /MO value.", L"CREATE");
            return 1;
        }
    }

    if (FAILED(hr = connect_service()))
    {
        error_text(L"The Task Scheduler is not available on this system.");
        return 1;
    }
    if (FAILED(hr = ITaskService_GetFolder(service, (BSTR)L"\\", &root)))
    {
        error_hr(hr);
        return 1;
    }
    full = full_task_name(opt.tn);
    name = SysAllocString(full);
    if (opt.f) flags = TASK_CREATE_OR_UPDATE;
    VariantInit(&empty);
    VariantInit(&user_v);
    VariantInit(&password_v);
    if (system_account)
    {
        V_VT(&user_v) = VT_BSTR;
        V_BSTR(&user_v) = SysAllocString(L"SYSTEM");
        logon = TASK_LOGON_SERVICE_ACCOUNT;
    }

    if (opt.xml)
    {
        xml = read_file_to_bstr(opt.xml);
        if (!xml) goto fail;
        hr = ITaskFolder_RegisterTask(root, name, xml, flags, user_v, password_v,
                                      system_account ? TASK_LOGON_SERVICE_ACCOUNT : TASK_LOGON_NONE, empty,
                                      &registered);
    }
    else
    {
        const WCHAR *sc = opt.sc;
        TASK_TRIGGER_TYPE2 type;
        BOOL repeat = FALSE;
        WCHAR boundary[64], period[32];
        int nth = 0;

        if (!wcsicmp(sc, L"ONCE")) type = TASK_TRIGGER_TIME;
        else if (!wcsicmp(sc, L"DAILY")) type = TASK_TRIGGER_DAILY;
        else if (!wcsicmp(sc, L"MINUTE") || !wcsicmp(sc, L"HOURLY")) { type = TASK_TRIGGER_TIME; repeat = TRUE; }
        else if (!wcsicmp(sc, L"ONLOGON")) type = TASK_TRIGGER_LOGON;
        else if (!wcsicmp(sc, L"ONSTART")) type = TASK_TRIGGER_BOOT;
        else if (!wcsicmp(sc, L"WEEKLY")) type = TASK_TRIGGER_WEEKLY;
        else if (!wcsicmp(sc, L"MONTHLY")) type = TASK_TRIGGER_MONTHLY;
        else if (!wcsicmp(sc, L"ONIDLE") || !wcsicmp(sc, L"ONEVENT"))
        {
            error_text(L"The ONIDLE and ONEVENT schedules are not supported: this system never runs such a task.");
            goto fail;
        }
        else
        {
            error_text(L"The schedule type is not supported; use ONCE, DAILY, WEEKLY, MONTHLY, MINUTE, HOURLY, ONLOGON or ONSTART.");
            goto fail;
        }
        if (type == TASK_TRIGGER_TIME && !repeat && !opt.st)
        {
            error_usage(L"Invalid syntax. /ST is required for the ONCE schedule.", L"CREATE");
            goto fail;
        }

        if (FAILED(hr = ITaskService_NewTask(service, 0, &def))) goto fail;
        if (SUCCEEDED(ITaskDefinition_get_RegistrationInfo(def, &info)))
        {
            BSTR author;

            current_user(text, ARRAYSIZE(text));
            author = SysAllocString(text);
            IRegistrationInfo_put_Author(info, author);
            SysFreeString(author);
            format_boundary(&now, text, ARRAYSIZE(text));
            IRegistrationInfo_put_Date(info, text);
            IRegistrationInfo_Release(info);
        }
        if (SUCCEEDED(ITaskDefinition_get_Principal(def, &principal)))
        {
            IPrincipal_put_LogonType(principal, logon);
            if (system_account)
            {
                IPrincipal_put_UserId(principal, (BSTR)L"S-1-5-18");
                IPrincipal_put_RunLevel(principal, TASK_RUNLEVEL_HIGHEST);
            }
            if (opt.rl && !wcsicmp(opt.rl, L"HIGHEST")) IPrincipal_put_RunLevel(principal, TASK_RUNLEVEL_HIGHEST);
            IPrincipal_Release(principal);
        }
        if (SUCCEEDED(ITaskDefinition_get_Settings(def, &settings)))
        {
            ITaskSettings_put_Enabled(settings, VARIANT_TRUE);
            ITaskSettings_put_ExecutionTimeLimit(settings, (BSTR)L"PT72H");
            ITaskSettings_put_StartWhenAvailable(settings, VARIANT_FALSE);
            ITaskSettings_Release(settings);
        }
        if (type == TASK_TRIGGER_MONTHLY)
        {
            static const WCHAR *const nth_words[] = { L"FIRST", L"SECOND", L"THIRD", L"FOURTH", L"LAST" };
            unsigned int k;

            /* /MO FIRST..LAST with /D weekday: a day of the week of the month */
            for (k = 0; opt.mo && k < ARRAYSIZE(nth_words); k++)
                if (!wcsicmp(opt.mo, nth_words[k])) { nth = k + 1; break; }
            if (nth) type = TASK_TRIGGER_MONTHLYDOW;
        }

        if (FAILED(hr = ITaskDefinition_get_Triggers(def, &triggers)) ||
            FAILED(hr = ITriggerCollection_Create(triggers, type, &trigger)))
            goto fail;

        if (type == TASK_TRIGGER_TIME || type == TASK_TRIGGER_DAILY || type == TASK_TRIGGER_WEEKLY ||
            type == TASK_TRIGGER_MONTHLY || type == TASK_TRIGGER_MONTHLYDOW)
        {
            format_boundary(&start, boundary, ARRAYSIZE(boundary));
            ITrigger_put_StartBoundary(trigger, boundary);
            if (opt.ed)
            {
                SYSTEMTIME end = start;

                if (!parse_date_arg(opt.ed, &end))
                {
                    error_usage(L"Invalid syntax. Invalid /ED value; use MM/DD/YYYY.", L"CREATE");
                    goto fail;
                }
                end.wHour = 23; end.wMinute = 59; end.wSecond = 59;
                format_boundary(&end, boundary, ARRAYSIZE(boundary));
                ITrigger_put_EndBoundary(trigger, boundary);
            }
        }
        if (type == TASK_TRIGGER_DAILY)
        {
            IDailyTrigger *daily;

            if (SUCCEEDED(ITrigger_QueryInterface(trigger, &IID_IDailyTrigger, (void **)&daily)))
            {
                IDailyTrigger_put_DaysInterval(daily, (SHORT)interval);
                IDailyTrigger_Release(daily);
            }
        }
        if (type == TASK_TRIGGER_WEEKLY && !set_weekly(trigger, &opt, interval)) goto fail;
        if ((type == TASK_TRIGGER_MONTHLY || type == TASK_TRIGGER_MONTHLYDOW) && !set_monthly(trigger, &opt, type, nth, &start))
            goto fail;
        if (repeat || opt.ri)
        {
            IRepetitionPattern *repetition = NULL;
            long minutes;

            if (repeat) minutes = !wcsicmp(sc, L"MINUTE") ? interval : interval * 60;
            else minutes = wcstol(opt.ri, NULL, 10);
            if (minutes < 1 || minutes > 599999)
            {
                error_usage(L"Invalid syntax. Invalid repetition interval.", L"CREATE");
                goto fail;
            }
            if (SUCCEEDED(ITrigger_get_Repetition(trigger, &repetition)))
            {
                _snwprintf(period, ARRAYSIZE(period), L"PT%ldM", minutes);
                IRepetitionPattern_put_Interval(repetition, period);
                if (opt.du)
                {
                    unsigned int h = 0, m = 0;

                    if (swscanf(opt.du, L"%u:%u", &h, &m) == 2)
                    {
                        _snwprintf(period, ARRAYSIZE(period), L"PT%uH%uM", h, m);
                        IRepetitionPattern_put_Duration(repetition, period);
                    }
                }
                IRepetitionPattern_Release(repetition);
            }
        }
        if (!set_exec_action(def, opt.tr))
        {
            error_text(L"The task action could not be set.");
            goto fail;
        }

        /* a start in the past is accepted, with the warning Windows gives for ONCE */
        if (type == TASK_TRIGGER_TIME && !repeat)
        {
            FILETIME a, b;
            SystemTimeToFileTime(&start, &a);
            SystemTimeToFileTime(&now, &b);
            if (CompareFileTime(&a, &b) < 0)
                err(L"WARNING: Task may not run because /ST is earlier than current time.\n");
        }

        hr = ITaskFolder_RegisterTaskDefinition(root, name, def, flags, user_v, password_v, logon, empty, &registered);
    }

    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) && !opt.f)
    {
        _snwprintf(text, ARRAYSIZE(text), L"WARNING: The task name \"%s\" already exists. Do you want to replace it", opt.tn);
        if (!ask(text)) goto done;
        flags = TASK_CREATE_OR_UPDATE;
        if (opt.xml)
            hr = ITaskFolder_RegisterTask(root, name, xml, flags, user_v, password_v,
                                          system_account ? TASK_LOGON_SERVICE_ACCOUNT : TASK_LOGON_NONE, empty,
                                          &registered);
        else
            hr = ITaskFolder_RegisterTaskDefinition(root, name, def, flags, user_v, password_v, logon, empty,
                                                    &registered);
    }
    if (FAILED(hr)) goto fail;
    success(L"SUCCESS: The scheduled task \"%s\" has successfully been created.\n", opt.tn);
    hr = S_OK;
    goto done;

fail:
    if (FAILED(hr)) error_hr(hr);
    hr = E_FAIL;
done:
    if (registered) IRegisteredTask_Release(registered);
    if (trigger) ITrigger_Release(trigger);
    if (triggers) ITriggerCollection_Release(triggers);
    if (def) ITaskDefinition_Release(def);
    VariantClear(&user_v);
    SysFreeString(xml);
    SysFreeString(name);
    free(full);
    if (root) ITaskFolder_Release(root);
    return hr == S_OK ? 0 : 1;
}

/* ---------- main ---------- */

static void usage(void)
{
    out(L"\nSCHTASKS /parameter [arguments]\n\n"
        L"Description:\n    Enables an administrator to create, delete, query, change, run and end scheduled\n"
        L"    tasks on the local system.\n\n"
        L"Parameter List:\n"
        L"    /Create         Creates a new scheduled task.\n"
        L"    /Delete         Deletes the scheduled task(s).\n"
        L"    /Query          Displays all scheduled tasks.\n"
        L"    /Change         Changes the properties of a scheduled task (/ENABLE, /DISABLE).\n"
        L"    /Run            Runs the scheduled task immediately.\n"
        L"    /End            Stops the currently running scheduled task.\n"
        L"    /?              Displays this help message.\n\n"
        L"Examples:\n"
        L"    SCHTASKS\n"
        L"    SCHTASKS /?\n"
        L"    SCHTASKS /Run /?\n"
        L"    SCHTASKS /End /?\n"
        L"    SCHTASKS /Create /?\n"
        L"    SCHTASKS /Delete /?\n"
        L"    SCHTASKS /Query  /?\n"
        L"    SCHTASKS /Change /?\n");
}

int wmain(int argc, WCHAR *argv[])
{
    int ret;

    ConInitStdStreams();
    CoInitialize(NULL);

    if (argc < 2)
        ret = query_command(0, NULL);
    else if (!wcscmp(argv[1], L"/?") || !wcscmp(argv[1], L"-?"))
    {
        usage();
        ret = 0;
    }
    else if (!wcsicmp(argv[1], L"/query")) ret = query_command(argc - 2, argv + 2);
    else if (!wcsicmp(argv[1], L"/create")) ret = create_command(argc - 2, argv + 2);
    else if (!wcsicmp(argv[1], L"/delete")) ret = delete_command(argc - 2, argv + 2);
    else if (!wcsicmp(argv[1], L"/run")) ret = run_command(argc - 2, argv + 2);
    else if (!wcsicmp(argv[1], L"/end")) ret = end_command(argc - 2, argv + 2);
    else if (!wcsicmp(argv[1], L"/change")) ret = change_command(argc - 2, argv + 2);
    else
    {
        WCHAR line[256];

        _snwprintf(line, ARRAYSIZE(line), L"Invalid argument/option - '%s'.", argv[1]);
        error_text(line);
        err(L"Type \"SCHTASKS /?\" for usage.\n");
        ret = 1;
    }

    if (service) ITaskService_Release(service);
    CoUninitialize();
    return ret;
}
