/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Task Scheduler 2.0: weekly, monthly and monthly day-of-week triggers (stored as
 *              registered, next run times, firing) and the triggers it keeps but never runs
 *              (idle, event, session state change)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected run times are those the schedule gives by the calendar (start boundaries on the
 * local clock, weeks counted from the Sunday of the start's week), worked out on the side.
 */

#include <apitest.h>

#define COBJMACROS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <objbase.h>
#include <oleauto.h>
#include <initguid.h>
#include <taskschd.h>
#include <stdio.h>

#define CAL_FOLDER L"\\ReactOS ApiTest Cal"
#define CAL_FOLDER_NAME L"ReactOS ApiTest Cal"
#define WAIT_MS 240000

static ITaskService *service;
static ITaskFolder *folder;
static WCHAR marker_dir[MAX_PATH];

struct when
{
    int y, m, d, h, mi;
};

static const WCHAR *const week_days_xml[7] = { L"Sunday", L"Monday", L"Tuesday", L"Wednesday", L"Thursday", L"Friday", L"Saturday" };

/* the XML of a task whose action is "cmd.exe /c <command>" and whose triggers are 'triggers' */
static void task_xml(WCHAR *xml, size_t size, const WCHAR *triggers, const WCHAR *command)
{
    _snwprintf(xml, size,
               L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
               L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
               L"  <RegistrationInfo><Description>calendar apitest</Description></RegistrationInfo>\n"
               L"  <Triggers>%s</Triggers>\n"
               L"  <Settings><Enabled>true</Enabled></Settings>\n"
               L"  <Actions><Exec><Command>cmd.exe</Command><Arguments>/c %s</Arguments></Exec></Actions>\n"
               L"</Task>\n", triggers, command);
}

static IRegisteredTask *register_xml(const WCHAR *name, const WCHAR *triggers, const WCHAR *command)
{
    WCHAR xml[8192];
    IRegisteredTask *task = NULL;
    VARIANT empty;
    BSTR bname = SysAllocString(name), bxml;
    HRESULT hr;

    task_xml(xml, ARRAYSIZE(xml), triggers, command);
    bxml = SysAllocString(xml);
    VariantInit(&empty);
    hr = ITaskFolder_RegisterTask(folder, bname, bxml, TASK_CREATE_OR_UPDATE, empty, empty,
                                  TASK_LOGON_INTERACTIVE_TOKEN, empty, &task);
    ok(hr == S_OK, "RegisterTask(%ls) failed: 0x%lx\n", name, hr);
    SysFreeString(bname);
    SysFreeString(bxml);
    return hr == S_OK ? task : NULL;
}

static void delete_task(const WCHAR *name)
{
    BSTR bname = SysAllocString(name);
    HRESULT hr = ITaskFolder_DeleteTask(folder, bname, 0);

    ok(hr == S_OK, "DeleteTask(%ls) failed: 0x%lx\n", name, hr);
    SysFreeString(bname);
}

/* the text between <Triggers> and </Triggers>, without the layout between the tags and with <x /> as <x/> */
static WCHAR *normalized_triggers(const WCHAR *xml, WCHAR *out, size_t size)
{
    const WCHAR *start = wcsstr(xml, L"<Triggers>"), *end = wcsstr(xml, L"</Triggers>"), *p;
    size_t n = 0;

    out[0] = 0;
    if (!start || !end) return out;
    for (p = start + wcslen(L"<Triggers>"); p < end && n + 2 < size; p++)
    {
        if (*p == ' ' && p[1] == '/' && p[2] == '>') continue;
        if ((*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') && ((n && out[n - 1] == '>') || !n))
        {
            const WCHAR *q = p;

            while (q < end && (*q == ' ' || *q == '\n' || *q == '\r' || *q == '\t')) q++;
            if (*q == '<')
            {
                p = q - 1;
                continue;
            }
        }
        out[n++] = *p;
    }
    out[n] = 0;
    return out;
}

/* the XML of the task as the service has it, fetched again by name, has these triggers as they were registered */
static void check_stored(IRegisteredTask *task, const WCHAR *triggers)
{
    WCHAR got[8192];
    IRegisteredTask *again = NULL;
    BSTR name = NULL, xml = NULL;
    HRESULT hr = IRegisteredTask_get_Name(task, &name);

    ok(hr == S_OK && name, "get_Name failed: 0x%lx\n", hr);
    if (!name) return;
    hr = ITaskFolder_GetTask(folder, name, &again);
    ok(hr == S_OK, "GetTask(%ls) failed: 0x%lx\n", name, hr);
    SysFreeString(name);
    if (hr != S_OK) return;
    hr = IRegisteredTask_get_Xml(again, &xml);
    ok(hr == S_OK && xml, "get_Xml failed: 0x%lx\n", hr);
    IRegisteredTask_Release(again);
    if (!xml) return;
    normalized_triggers(xml, got, ARRAYSIZE(got));
    ok(!wcscmp(got, triggers), "stored triggers:\n%ls\nregistered:\n%ls\n", got, triggers);
    SysFreeString(xml);
}

static void to_systemtime(const struct when *w, SYSTEMTIME *st)
{
    memset(st, 0, sizeof(*st));
    st->wYear = w->y;
    st->wMonth = w->m;
    st->wDay = w->d;
    st->wHour = w->h;
    st->wMinute = w->mi;
}

/* GetRunTimes(from, to) is exactly the 'expected' list (local wall clock) */
static void check_times(IRegisteredTask *task, const char *label, const struct when *from, const struct when *to,
                        const struct when *expected, unsigned int n_expected)
{
    SYSTEMTIME start, end, *times = NULL;
    DWORD count = 100, i;
    HRESULT hr;

    to_systemtime(from, &start);
    to_systemtime(to, &end);
    hr = IRegisteredTask_GetRunTimes(task, &start, &end, &count, &times);
    ok(hr == S_OK, "%s: GetRunTimes failed: 0x%lx\n", label, hr);
    if (hr != S_OK) return;
    ok(count == n_expected, "%s: %lu run times, expected %u\n", label, count, n_expected);
    for (i = 0; i < count && i < n_expected; i++)
        ok(times[i].wYear == expected[i].y && times[i].wMonth == expected[i].m && times[i].wDay == expected[i].d &&
           times[i].wHour == expected[i].h && times[i].wMinute == expected[i].mi && times[i].wSecond == 0,
           "%s: run time %lu is %04u-%02u-%02u %02u:%02u:%02u, expected %04d-%02d-%02d %02d:%02d\n", label, i,
           times[i].wYear, times[i].wMonth, times[i].wDay, times[i].wHour, times[i].wMinute, times[i].wSecond,
           expected[i].y, expected[i].m, expected[i].d, expected[i].h, expected[i].mi);
    if (times) CoTaskMemFree(times);
}

#define CHECK_TIMES(task, label, from, to, list) \
    check_times(task, label, &(from), &(to), list, ARRAYSIZE(list))

/* the weekly, monthly and monthly day-of-week triggers: stored as registered, and their run times */
static void test_calendar_schedules(void)
{
    static const WCHAR weekly_two[] =
        L"<CalendarTrigger><StartBoundary>2031-03-05T09:30:00</StartBoundary><Enabled>true</Enabled>"
        L"<ScheduleByWeek><DaysOfWeek><Monday/><Thursday/></DaysOfWeek><WeeksInterval>2</WeeksInterval></ScheduleByWeek>"
        L"</CalendarTrigger>";
    static const WCHAR weekly_full[] =
        L"<CalendarTrigger id=\"wk1\"><Repetition><Interval>PT1H</Interval><Duration>PT12H</Duration>"
        L"<StopAtDurationEnd>false</StopAtDurationEnd></Repetition>"
        L"<StartBoundary>2031-03-05T09:30:00</StartBoundary><EndBoundary>2032-01-01T00:00:00</EndBoundary>"
        L"<ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Enabled>false</Enabled><RandomDelay>PT5M</RandomDelay>"
        L"<ScheduleByWeek><DaysOfWeek><Sunday/></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>"
        L"</CalendarTrigger>";
    static const WCHAR weekly_year_end[] =
        L"<CalendarTrigger><StartBoundary>2031-12-29T23:30:00</StartBoundary><Enabled>true</Enabled>"
        L"<ScheduleByWeek><DaysOfWeek><Tuesday/><Friday/></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>"
        L"</CalendarTrigger>";
    static const WCHAR monthly_end[] =
        L"<CalendarTrigger><StartBoundary>2032-01-15T08:00:00</StartBoundary><Enabled>true</Enabled>"
        L"<ScheduleByMonth><DaysOfMonth><Day>29</Day><Day>30</Day><Day>31</Day><Day>Last</Day></DaysOfMonth>"
        L"<Months><January/><February/><March/><April/><May/><June/><July/><August/><September/><October/><November/>"
        L"<December/></Months></ScheduleByMonth></CalendarTrigger>";
    static const WCHAR monthly_leap[] =
        L"<CalendarTrigger><StartBoundary>2031-02-01T06:00:00</StartBoundary><Enabled>true</Enabled>"
        L"<ScheduleByMonth><DaysOfMonth><Day>Last</Day></DaysOfMonth><Months><February/></Months></ScheduleByMonth>"
        L"</CalendarTrigger>";
    static const WCHAR monthly_31[] =
        L"<CalendarTrigger><StartBoundary>2031-03-01T06:00:00</StartBoundary><Enabled>true</Enabled>"
        L"<ScheduleByMonth><DaysOfMonth><Day>31</Day></DaysOfMonth>"
        L"<Months><March/><April/><May/><June/></Months></ScheduleByMonth></CalendarTrigger>";
    static const WCHAR monthly_dow[] =
        L"<CalendarTrigger><StartBoundary>2031-01-01T10:00:00</StartBoundary><Enabled>true</Enabled>"
        L"<ScheduleByMonthDayOfWeek><Weeks><Week>1</Week><Week>Last</Week></Weeks>"
        L"<DaysOfWeek><Tuesday/><Friday/></DaysOfWeek><Months><February/><March/></Months>"
        L"</ScheduleByMonthDayOfWeek></CalendarTrigger>";
    static const WCHAR weekly_repeat[] =
        L"<CalendarTrigger><Repetition><Interval>PT6H</Interval><Duration>PT12H</Duration>"
        L"<StopAtDurationEnd>false</StopAtDurationEnd></Repetition>"
        L"<StartBoundary>2031-03-03T09:30:00</StartBoundary><Enabled>true</Enabled>"
        L"<ScheduleByWeek><DaysOfWeek><Monday/></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>"
        L"</CalendarTrigger>";
    static const WCHAR weekly_ended[] =
        L"<CalendarTrigger><StartBoundary>2031-03-03T09:30:00</StartBoundary><EndBoundary>2031-03-20T00:00:00</EndBoundary>"
        L"<Enabled>true</Enabled>"
        L"<ScheduleByWeek><DaysOfWeek><Monday/></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>"
        L"</CalendarTrigger>";

    static const struct when w_two[] = { {2031,3,6,9,30}, {2031,3,17,9,30}, {2031,3,20,9,30}, {2031,3,31,9,30},
                                         {2031,4,3,9,30}, {2031,4,14,9,30}, {2031,4,17,9,30}, {2031,4,28,9,30},
                                         {2031,5,1,9,30} };
    static const struct when w_year_end[] = { {2031,12,30,23,30}, {2032,1,2,23,30} };
    static const struct when m_end[] = { {2032,1,29,8,0}, {2032,1,30,8,0}, {2032,1,31,8,0}, {2032,2,29,8,0},
                                         {2032,3,29,8,0}, {2032,3,30,8,0}, {2032,3,31,8,0}, {2032,4,29,8,0},
                                         {2032,4,30,8,0} };
    static const struct when m_leap[] = { {2031,2,28,6,0}, {2032,2,29,6,0}, {2033,2,28,6,0} };
    static const struct when m_31[] = { {2031,3,31,6,0}, {2031,5,31,6,0} };
    static const struct when m_dow[] = { {2031,2,4,10,0}, {2031,2,7,10,0}, {2031,2,25,10,0}, {2031,2,28,10,0},
                                         {2031,3,4,10,0}, {2031,3,7,10,0}, {2031,3,25,10,0}, {2031,3,28,10,0} };
    static const struct when w_repeat[] = { {2031,3,3,9,30}, {2031,3,3,15,30}, {2031,3,10,9,30}, {2031,3,10,15,30} };
    static const struct when w_ended[] = { {2031,3,3,9,30}, {2031,3,10,9,30}, {2031,3,17,9,30} };

    static const struct when from_a = {2031,3,1,0,0}, to_a = {2031,5,1,23,59};
    static const struct when from_b = {2031,12,29,0,0}, to_b = {2032,1,3,23,59};
    static const struct when from_c = {2032,1,1,0,0}, to_c = {2032,5,1,0,0};
    static const struct when from_d = {2031,1,1,0,0}, to_d = {2033,12,31,0,0};
    static const struct when from_e = {2031,1,1,0,0}, to_e = {2031,4,1,0,0};
    static const struct when from_f = {2031,3,1,0,0}, to_f = {2031,7,1,0,0};
    static const struct when from_g = {2031,3,1,0,0}, to_g = {2031,3,11,0,0};
    static const struct when from_h = {2031,3,1,0,0}, to_h = {2031,5,1,0,0};
    IRegisteredTask *task;
    SYSTEMTIME st;
    DATE date, expect;
    HRESULT hr;

    task = register_xml(L"WeeklyTwo", weekly_two, L"exit");
    if (task)
    {
        check_stored(task, weekly_two);
        CHECK_TIMES(task, "weekly Mon+Thu every 2 weeks", from_a, to_a, w_two);

        /* the next run of a task whose start is far ahead is the first day of its schedule after the start */
        date = 0;
        hr = IRegisteredTask_get_NextRunTime(task, &date);
        ok(hr == S_OK, "NextRunTime: 0x%lx\n", hr);
        memset(&st, 0, sizeof(st));
        st.wYear = 2031; st.wMonth = 3; st.wDay = 6; st.wHour = 9; st.wMinute = 30;
        SystemTimeToVariantTime(&st, &expect);
        ok(date == expect, "NextRunTime %f, expected %f (2031-03-06 09:30)\n", date, expect);
        IRegisteredTask_Release(task);
        delete_task(L"WeeklyTwo");
    }

    task = register_xml(L"WeeklyFull", weekly_full, L"exit");
    if (task)
    {
        check_stored(task, weekly_full);
        /* disabled trigger: no run times, and no valid next run */
        date = 1;
        hr = IRegisteredTask_get_NextRunTime(task, &date);
        ok(hr == SCHED_S_TASK_NOT_SCHEDULED && date == 0, "NextRunTime of a disabled trigger: 0x%lx %f\n", hr, date);
        IRegisteredTask_Release(task);
        delete_task(L"WeeklyFull");
    }

    task = register_xml(L"WeeklyYearEnd", weekly_year_end, L"exit");
    if (task)
    {
        check_stored(task, weekly_year_end);
        CHECK_TIMES(task, "weekly Tue+Fri over a year end", from_b, to_b, w_year_end);
        IRegisteredTask_Release(task);
        delete_task(L"WeeklyYearEnd");
    }

    task = register_xml(L"MonthlyEnd", monthly_end, L"exit");
    if (task)
    {
        check_stored(task, monthly_end);
        CHECK_TIMES(task, "monthly 29-31 and last, 2032", from_c, to_c, m_end);
        IRegisteredTask_Release(task);
        delete_task(L"MonthlyEnd");
    }

    task = register_xml(L"MonthlyLeap", monthly_leap, L"exit");
    if (task)
    {
        check_stored(task, monthly_leap);
        CHECK_TIMES(task, "last day of February across leap years", from_d, to_d, m_leap);
        IRegisteredTask_Release(task);
        delete_task(L"MonthlyLeap");
    }

    task = register_xml(L"Monthly31", monthly_31, L"exit");
    if (task)
    {
        check_stored(task, monthly_31);
        CHECK_TIMES(task, "the 31st skips the short months", from_f, to_f, m_31);
        IRegisteredTask_Release(task);
        delete_task(L"Monthly31");
    }

    task = register_xml(L"MonthlyDow", monthly_dow, L"exit");
    if (task)
    {
        check_stored(task, monthly_dow);
        CHECK_TIMES(task, "first and last Tuesday and Friday", from_e, to_e, m_dow);
        IRegisteredTask_Release(task);
        delete_task(L"MonthlyDow");
    }

    task = register_xml(L"WeeklyRepeat", weekly_repeat, L"exit");
    if (task)
    {
        check_stored(task, weekly_repeat);
        CHECK_TIMES(task, "weekly with a repetition", from_g, to_g, w_repeat);
        IRegisteredTask_Release(task);
        delete_task(L"WeeklyRepeat");
    }

    task = register_xml(L"WeeklyEnded", weekly_ended, L"exit");
    if (task)
    {
        check_stored(task, weekly_ended);
        CHECK_TIMES(task, "weekly with an end boundary", from_h, to_h, w_ended);
        IRegisteredTask_Release(task);
        delete_task(L"WeeklyEnded");
    }
}

/* a boundary with a zone: Monday 23:30 UTC, counted on the UTC calendar */
static void test_zoned_boundary(void)
{
    static const WCHAR utc_weekly[] =
        L"<CalendarTrigger><StartBoundary>2031-03-03T23:30:00Z</StartBoundary><Enabled>true</Enabled>"
        L"<ScheduleByWeek><DaysOfWeek><Monday/></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>"
        L"</CalendarTrigger>";
    static const struct when utc[2] = { {2031,3,3,23,30}, {2031,3,10,23,30} };
    IRegisteredTask *task = register_xml(L"WeeklyUtc", utc_weekly, L"exit");
    SYSTEMTIME from, to, *times = NULL, expect;
    DWORD count = 10, i;
    HRESULT hr;

    if (!task) return;
    check_stored(task, utc_weekly);

    /* the window is wide: the answers are local times, the expected ones the same instants */
    memset(&from, 0, sizeof(from));
    from.wYear = 2031; from.wMonth = 3; from.wDay = 1;
    to = from;
    to.wDay = 12;
    hr = IRegisteredTask_GetRunTimes(task, &from, &to, &count, &times);
    ok(hr == S_OK && count == 2, "GetRunTimes: 0x%lx, %lu times\n", hr, count);
    for (i = 0; hr == S_OK && i < count && i < 2; i++)
    {
        SYSTEMTIME at;

        to_systemtime(&utc[i], &at);
        ok(SystemTimeToTzSpecificLocalTime(NULL, &at, &expect), "no local time\n");
        ok(times[i].wYear == expect.wYear && times[i].wMonth == expect.wMonth && times[i].wDay == expect.wDay &&
           times[i].wHour == expect.wHour && times[i].wMinute == expect.wMinute,
           "run %lu: %04u-%02u-%02u %02u:%02u, expected %04u-%02u-%02u %02u:%02u local\n", i, times[i].wYear,
           times[i].wMonth, times[i].wDay, times[i].wHour, times[i].wMinute, expect.wYear, expect.wMonth,
           expect.wDay, expect.wHour, expect.wMinute);
    }
    if (times) CoTaskMemFree(times);
    IRegisteredTask_Release(task);
    delete_task(L"WeeklyUtc");
}

/* the triggers the service stores and never runs */
static void test_unrun_triggers(void)
{
    static const WCHAR idle[] = L"<IdleTrigger><Enabled>true</Enabled></IdleTrigger>";
    static const WCHAR session[] =
        L"<SessionStateChangeTrigger><Enabled>true</Enabled><Delay>PT1M</Delay><StateChange>SessionLock</StateChange>"
        L"</SessionStateChangeTrigger>";
    static const WCHAR event[] =
        L"<EventTrigger><Enabled>true</Enabled>"
        L"<Subscription>&lt;QueryList&gt;&lt;Query Id='0'&gt;&lt;Select Path='System'&gt;*[System[EventID=1]]"
        L"&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription><Delay>PT30S</Delay>"
        L"<PeriodOfOccurrence>PT5M</PeriodOfOccurrence><NumberOfOccurrences>2</NumberOfOccurrences>"
        L"<ValueQueries><Value name=\"id\">Event/System/EventID</Value></ValueQueries></EventTrigger>";
    static const struct { const WCHAR *name, *xml; } cases[] =
    {
        { L"Idle", idle }, { L"Session", session }, { L"Event", event },
    };
    unsigned int i;

    for (i = 0; i < ARRAYSIZE(cases); i++)
    {
        IRegisteredTask *task = register_xml(cases[i].name, cases[i].xml, L"exit");
        SYSTEMTIME from, to, *times = NULL;
        DWORD count = 5;
        DATE date = 1;
        TASK_STATE state;
        HRESULT hr;

        if (!task) continue;
        check_stored(task, cases[i].xml);

        /* kept, enabled, and without a time: no next run, none in any range */
        hr = IRegisteredTask_get_NextRunTime(task, &date);
        ok(hr == SCHED_S_TASK_NOT_SCHEDULED && date == 0, "%ls: NextRunTime: 0x%lx %f\n", cases[i].name, hr, date);
        GetLocalTime(&from);
        to = from;
        to.wYear += 5;
        hr = IRegisteredTask_GetRunTimes(task, &from, &to, &count, &times);
        ok(hr == S_OK && !count, "%ls: GetRunTimes: 0x%lx, %lu times\n", cases[i].name, hr, count);
        if (times) CoTaskMemFree(times);
        state = TASK_STATE_UNKNOWN;
        hr = IRegisteredTask_get_State(task, &state);
        ok(hr == S_OK && state == TASK_STATE_READY, "%ls: state 0x%lx %d is not Ready\n", cases[i].name, hr, state);
        IRegisteredTask_Release(task);
        delete_task(cases[i].name);
    }
}

/* the objects: the defaults of a new trigger, the values, and the XML they give */
static ITaskDefinition *new_definition(ITrigger **trigger, TASK_TRIGGER_TYPE2 type)
{
    ITaskDefinition *def = NULL;
    ITriggerCollection *triggers = NULL;
    HRESULT hr = ITaskService_NewTask(service, 0, &def);

    ok(hr == S_OK, "NewTask failed: 0x%lx\n", hr);
    if (hr != S_OK) return NULL;
    hr = ITaskDefinition_get_Triggers(def, &triggers);
    ok(hr == S_OK, "get_Triggers failed: 0x%lx\n", hr);
    hr = ITriggerCollection_Create(triggers, type, trigger);
    ok(hr == S_OK, "Create(%d) failed: 0x%lx\n", type, hr);
    ITriggerCollection_Release(triggers);
    if (hr != S_OK)
    {
        ITaskDefinition_Release(def);
        return NULL;
    }
    return def;
}

static void check_definition_triggers(ITaskDefinition *def, const char *label, const WCHAR *expected)
{
    WCHAR got[4096];
    BSTR xml = NULL;
    HRESULT hr = ITaskDefinition_get_XmlText(def, &xml);

    ok(hr == S_OK && xml, "%s: get_XmlText failed: 0x%lx\n", label, hr);
    if (!xml) return;
    normalized_triggers(xml, got, ARRAYSIZE(got));
    ok(!wcscmp(got, expected), "%s: triggers\n%ls\nexpected\n%ls\n", label, got, expected);
    SysFreeString(xml);
}

static void test_trigger_objects(void)
{
    ITaskDefinition *def;
    ITrigger *trigger;
    IWeeklyTrigger *weekly;
    IMonthlyTrigger *monthly;
    IMonthlyDOWTrigger *dow;
    ISessionStateChangeTrigger *session;
    IEventTrigger *event;
    TASK_TRIGGER_TYPE2 type;
    TASK_SESSION_STATE_CHANGE_TYPE change;
    VARIANT_BOOL last;
    short days, weeks, months;
    LONG dom;
    BSTR bstr;
    HRESULT hr;

    /* the defaults Windows gives (measured on Windows 10): weekly no days and every week, monthly no days and
       every month, monthly day-of-week the first Sunday of January */
    if ((def = new_definition(&trigger, TASK_TRIGGER_WEEKLY)))
    {
        hr = ITrigger_get_Type(trigger, &type);
        ok(hr == S_OK && type == TASK_TRIGGER_WEEKLY, "type: 0x%lx %d\n", hr, type);
        hr = ITrigger_QueryInterface(trigger, &IID_IWeeklyTrigger, (void **)&weekly);
        ok(hr == S_OK, "QueryInterface(IWeeklyTrigger): 0x%lx\n", hr);
        if (hr == S_OK)
        {
            days = weeks = -1;
            IWeeklyTrigger_get_DaysOfWeek(weekly, &days);
            IWeeklyTrigger_get_WeeksInterval(weekly, &weeks);
            ok(days == 0 && weeks == 1, "weekly defaults: days %d, weeks %d\n", days, weeks);
            hr = IWeeklyTrigger_put_DaysOfWeek(weekly, 2 + 16);
            ok(hr == S_OK, "put_DaysOfWeek: 0x%lx\n", hr);
            hr = IWeeklyTrigger_put_WeeksInterval(weekly, 2);
            ok(hr == S_OK, "put_WeeksInterval: 0x%lx\n", hr);
            hr = IWeeklyTrigger_put_RandomDelay(weekly, (BSTR)L"PT5M");
            ok(hr == S_OK, "put_RandomDelay: 0x%lx\n", hr);
            IWeeklyTrigger_Release(weekly);
        }
        ok(ITrigger_QueryInterface(trigger, &IID_IDailyTrigger, (void **)&weekly) == E_NOINTERFACE,
           "a weekly trigger is a daily one\n");
        ITrigger_put_StartBoundary(trigger, (BSTR)L"2031-03-05T09:30:00");
        check_definition_triggers(def, "weekly object",
            L"<CalendarTrigger><StartBoundary>2031-03-05T09:30:00</StartBoundary><Enabled>true</Enabled>"
            L"<RandomDelay>PT5M</RandomDelay><ScheduleByWeek><DaysOfWeek><Monday/><Thursday/></DaysOfWeek>"
            L"<WeeksInterval>2</WeeksInterval></ScheduleByWeek></CalendarTrigger>");
        ITrigger_Release(trigger);
        ITaskDefinition_Release(def);
    }

    if ((def = new_definition(&trigger, TASK_TRIGGER_MONTHLY)))
    {
        hr = ITrigger_QueryInterface(trigger, &IID_IMonthlyTrigger, (void **)&monthly);
        ok(hr == S_OK, "QueryInterface(IMonthlyTrigger): 0x%lx\n", hr);
        if (hr == S_OK)
        {
            dom = -1; months = -1; last = VARIANT_TRUE;
            IMonthlyTrigger_get_DaysOfMonth(monthly, &dom);
            IMonthlyTrigger_get_MonthsOfYear(monthly, &months);
            IMonthlyTrigger_get_RunOnLastDayOfMonth(monthly, &last);
            ok(dom == 0 && months == 0xfff && last == VARIANT_FALSE, "monthly defaults: %ld, %d, %d\n", dom, months,
               last);
            /* days 1, 3 and 31 are the bits 0, 2 and 30: more than a short holds */
            hr = IMonthlyTrigger_put_DaysOfMonth(monthly, 1 + 4 + (1 << 30));
            ok(hr == S_OK, "put_DaysOfMonth: 0x%lx\n", hr);
            dom = 0;
            IMonthlyTrigger_get_DaysOfMonth(monthly, &dom);
            ok(dom == 1073741829, "DaysOfMonth %ld\n", dom);
            IMonthlyTrigger_put_MonthsOfYear(monthly, 1 + 4 + 2048);
            IMonthlyTrigger_put_RunOnLastDayOfMonth(monthly, VARIANT_TRUE);
            IMonthlyTrigger_Release(monthly);
        }
        ITrigger_put_StartBoundary(trigger, (BSTR)L"2031-03-05T09:30:00");
        check_definition_triggers(def, "monthly object",
            L"<CalendarTrigger><StartBoundary>2031-03-05T09:30:00</StartBoundary><Enabled>true</Enabled>"
            L"<ScheduleByMonth><DaysOfMonth><Day>1</Day><Day>3</Day><Day>31</Day><Day>Last</Day></DaysOfMonth>"
            L"<Months><January/><March/><December/></Months></ScheduleByMonth></CalendarTrigger>");
        ITrigger_Release(trigger);
        ITaskDefinition_Release(def);
    }

    if ((def = new_definition(&trigger, TASK_TRIGGER_MONTHLYDOW)))
    {
        hr = ITrigger_QueryInterface(trigger, &IID_IMonthlyDOWTrigger, (void **)&dow);
        ok(hr == S_OK, "QueryInterface(IMonthlyDOWTrigger): 0x%lx\n", hr);
        if (hr == S_OK)
        {
            days = weeks = months = -1; last = VARIANT_TRUE;
            IMonthlyDOWTrigger_get_DaysOfWeek(dow, &days);
            IMonthlyDOWTrigger_get_WeeksOfMonth(dow, &weeks);
            IMonthlyDOWTrigger_get_MonthsOfYear(dow, &months);
            IMonthlyDOWTrigger_get_RunOnLastWeekOfMonth(dow, &last);
            ok(days == 1 && weeks == 1 && months == 1 && last == VARIANT_FALSE, "monthly dow defaults: %d %d %d %d\n",
               days, weeks, months, last);
            IMonthlyDOWTrigger_put_DaysOfWeek(dow, 2);
            IMonthlyDOWTrigger_put_WeeksOfMonth(dow, 1 + 8);
            IMonthlyDOWTrigger_put_MonthsOfYear(dow, 4095);
            IMonthlyDOWTrigger_put_RunOnLastWeekOfMonth(dow, VARIANT_TRUE);
            IMonthlyDOWTrigger_Release(dow);
        }
        ITrigger_put_StartBoundary(trigger, (BSTR)L"2031-03-05T09:30:00");
        check_definition_triggers(def, "monthly day-of-week object",
            L"<CalendarTrigger><StartBoundary>2031-03-05T09:30:00</StartBoundary><Enabled>true</Enabled>"
            L"<ScheduleByMonthDayOfWeek><Weeks><Week>1</Week><Week>4</Week><Week>Last</Week></Weeks>"
            L"<DaysOfWeek><Monday/></DaysOfWeek><Months><January/><February/><March/><April/><May/><June/><July/>"
            L"<August/><September/><October/><November/><December/></Months></ScheduleByMonthDayOfWeek>"
            L"</CalendarTrigger>");
        ITrigger_Release(trigger);
        ITaskDefinition_Release(def);
    }

    if ((def = new_definition(&trigger, TASK_TRIGGER_IDLE)))
    {
        hr = ITrigger_get_Type(trigger, &type);
        ok(hr == S_OK && type == TASK_TRIGGER_IDLE, "idle type: 0x%lx %d\n", hr, type);
        check_definition_triggers(def, "idle object", L"<IdleTrigger><Enabled>true</Enabled></IdleTrigger>");
        ITrigger_Release(trigger);
        ITaskDefinition_Release(def);
    }

    if ((def = new_definition(&trigger, TASK_TRIGGER_SESSION_STATE_CHANGE)))
    {
        hr = ITrigger_QueryInterface(trigger, &IID_ISessionStateChangeTrigger, (void **)&session);
        ok(hr == S_OK, "QueryInterface(ISessionStateChangeTrigger): 0x%lx\n", hr);
        if (hr == S_OK)
        {
            change = 0;
            ISessionStateChangeTrigger_get_StateChange(session, &change);
            ISessionStateChangeTrigger_put_StateChange(session, TASK_SESSION_LOCK);
            ISessionStateChangeTrigger_get_StateChange(session, &change);
            ok(change == TASK_SESSION_LOCK, "StateChange %d\n", change);
            ISessionStateChangeTrigger_Release(session);
        }
        check_definition_triggers(def, "session object",
            L"<SessionStateChangeTrigger><Enabled>true</Enabled><StateChange>SessionLock</StateChange>"
            L"</SessionStateChangeTrigger>");
        ITrigger_Release(trigger);
        ITaskDefinition_Release(def);
    }

    if ((def = new_definition(&trigger, TASK_TRIGGER_EVENT)))
    {
        hr = ITrigger_QueryInterface(trigger, &IID_IEventTrigger, (void **)&event);
        ok(hr == S_OK, "QueryInterface(IEventTrigger): 0x%lx\n", hr);
        if (hr == S_OK)
        {
            hr = IEventTrigger_put_Subscription(event, (BSTR)L"<QueryList/>");
            ok(hr == S_OK, "put_Subscription: 0x%lx\n", hr);
            bstr = NULL;
            hr = IEventTrigger_get_Subscription(event, &bstr);
            ok(hr == S_OK && bstr && !wcscmp(bstr, L"<QueryList/>"), "Subscription: 0x%lx %ls\n", hr, bstr);
            SysFreeString(bstr);
            IEventTrigger_Release(event);
        }
        check_definition_triggers(def, "event object",
            L"<EventTrigger><Enabled>true</Enabled><Subscription>&lt;QueryList/&gt;</Subscription></EventTrigger>");
        ITrigger_Release(trigger);
        ITaskDefinition_Release(def);
    }
}


/* the same objects through IDispatch, as a script reaches them: the type library describes the new interfaces */
static HRESULT disp_put(IDispatch *disp, const WCHAR *name, VARIANT *value)
{
    DISPID id, put = DISPID_PROPERTYPUT;
    DISPPARAMS params = { value, &put, 1, 1 };
    LPOLESTR names[1] = { (LPOLESTR)name };
    HRESULT hr = IDispatch_GetIDsOfNames(disp, &IID_NULL, names, 1, LOCALE_USER_DEFAULT, &id);

    if (hr != S_OK) return hr;
    return IDispatch_Invoke(disp, id, &IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYPUT, &params, NULL, NULL, NULL);
}

static HRESULT disp_get(IDispatch *disp, const WCHAR *name, VARIANT *value)
{
    DISPID id;
    DISPPARAMS params = { NULL, NULL, 0, 0 };
    LPOLESTR names[1] = { (LPOLESTR)name };
    HRESULT hr = IDispatch_GetIDsOfNames(disp, &IID_NULL, names, 1, LOCALE_USER_DEFAULT, &id);

    VariantInit(value);
    if (hr != S_OK) return hr;
    return IDispatch_Invoke(disp, id, &IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET, &params, value, NULL, NULL);
}

static void test_late_binding(void)
{
    ITaskDefinition *def;
    ITrigger *trigger;
    IDispatch *disp;
    VARIANT v;
    HRESULT hr;

    if ((def = new_definition(&trigger, TASK_TRIGGER_WEEKLY)))
    {
        hr = ITrigger_QueryInterface(trigger, &IID_IDispatch, (void **)&disp);
        ok(hr == S_OK, "QueryInterface(IDispatch): 0x%lx\n", hr);
        V_VT(&v) = VT_I4;
        V_I4(&v) = 18;
        hr = disp_put(disp, L"DaysOfWeek", &v);
        ok(hr == S_OK, "put DaysOfWeek: 0x%lx\n", hr);
        V_VT(&v) = VT_I4;
        V_I4(&v) = 3;
        hr = disp_put(disp, L"WeeksInterval", &v);
        ok(hr == S_OK, "put WeeksInterval: 0x%lx\n", hr);
        hr = disp_get(disp, L"DaysOfWeek", &v);
        ok(hr == S_OK && V_VT(&v) == VT_I2 && V_I2(&v) == 18, "get DaysOfWeek: 0x%lx %d %d\n", hr, V_VT(&v), V_I2(&v));
        hr = disp_get(disp, L"Type", &v);
        ok(hr == S_OK && V_I4(&v) == TASK_TRIGGER_WEEKLY, "get Type: 0x%lx %ld\n", hr, V_I4(&v));
        V_VT(&v) = VT_BSTR;
        V_BSTR(&v) = SysAllocString(L"2031-03-05T09:30:00");
        hr = disp_put(disp, L"StartBoundary", &v);
        ok(hr == S_OK, "put StartBoundary: 0x%lx\n", hr);
        VariantClear(&v);
        check_definition_triggers(def, "weekly late bound",
            L"<CalendarTrigger><StartBoundary>2031-03-05T09:30:00</StartBoundary><Enabled>true</Enabled>"
            L"<ScheduleByWeek><DaysOfWeek><Monday/><Thursday/></DaysOfWeek><WeeksInterval>3</WeeksInterval>"
            L"</ScheduleByWeek></CalendarTrigger>");
        IDispatch_Release(disp);
        ITrigger_Release(trigger);
        ITaskDefinition_Release(def);
    }

    if ((def = new_definition(&trigger, TASK_TRIGGER_MONTHLY)))
    {
        ITrigger_QueryInterface(trigger, &IID_IDispatch, (void **)&disp);
        /* a LONG: the days 1, 3 and 31 are more than 16 bits */
        V_VT(&v) = VT_I4;
        V_I4(&v) = 1073741829;
        hr = disp_put(disp, L"DaysOfMonth", &v);
        ok(hr == S_OK, "put DaysOfMonth: 0x%lx\n", hr);
        hr = disp_get(disp, L"DaysOfMonth", &v);
        ok(hr == S_OK && V_VT(&v) == VT_I4 && V_I4(&v) == 1073741829, "get DaysOfMonth: 0x%lx %d %ld\n", hr,
           V_VT(&v), V_I4(&v));
        V_VT(&v) = VT_BOOL;
        V_BOOL(&v) = VARIANT_TRUE;
        hr = disp_put(disp, L"RunOnLastDayOfMonth", &v);
        ok(hr == S_OK, "put RunOnLastDayOfMonth: 0x%lx\n", hr);
        V_VT(&v) = VT_I4;
        V_I4(&v) = 2048;
        hr = disp_put(disp, L"MonthsOfYear", &v);
        ok(hr == S_OK, "put MonthsOfYear: 0x%lx\n", hr);
        check_definition_triggers(def, "monthly late bound",
            L"<CalendarTrigger><Enabled>true</Enabled><ScheduleByMonth><DaysOfMonth><Day>1</Day><Day>3</Day>"
            L"<Day>31</Day><Day>Last</Day></DaysOfMonth><Months><December/></Months></ScheduleByMonth>"
            L"</CalendarTrigger>");
        IDispatch_Release(disp);
        ITrigger_Release(trigger);
        ITaskDefinition_Release(def);
    }

    if ((def = new_definition(&trigger, TASK_TRIGGER_MONTHLYDOW)))
    {
        ITrigger_QueryInterface(trigger, &IID_IDispatch, (void **)&disp);
        V_VT(&v) = VT_I4;
        V_I4(&v) = 4;
        hr = disp_put(disp, L"DaysOfWeek", &v);
        ok(hr == S_OK, "put DaysOfWeek: 0x%lx\n", hr);
        V_I4(&v) = 8;
        hr = disp_put(disp, L"WeeksOfMonth", &v);
        ok(hr == S_OK, "put WeeksOfMonth: 0x%lx\n", hr);
        hr = disp_get(disp, L"RunOnLastWeekOfMonth", &v);
        ok(hr == S_OK && V_VT(&v) == VT_BOOL && V_BOOL(&v) == VARIANT_FALSE, "get RunOnLastWeekOfMonth: 0x%lx\n", hr);
        check_definition_triggers(def, "monthly day-of-week late bound",
            L"<CalendarTrigger><Enabled>true</Enabled><ScheduleByMonthDayOfWeek><Weeks><Week>4</Week></Weeks>"
            L"<DaysOfWeek><Tuesday/></DaysOfWeek><Months><January/></Months></ScheduleByMonthDayOfWeek>"
            L"</CalendarTrigger>");
        IDispatch_Release(disp);
        ITrigger_Release(trigger);
        ITaskDefinition_Release(def);
    }

    if ((def = new_definition(&trigger, TASK_TRIGGER_IDLE)))
    {
        ITrigger_QueryInterface(trigger, &IID_IDispatch, (void **)&disp);
        hr = disp_get(disp, L"Type", &v);
        ok(hr == S_OK && V_I4(&v) == TASK_TRIGGER_IDLE, "get Type of idle: 0x%lx\n", hr);
        IDispatch_Release(disp);
        ITrigger_Release(trigger);
        ITaskDefinition_Release(def);
    }
}

/* run times and the next run across a daylight saving change, on a time zone this test sets */
static BOOL enable_time_zone_privilege(void)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    BOOL ret = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, L"SeTimeZonePrivilege", &tp.Privileges[0].Luid))
        ret = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ret;
}

static void test_daylight_saving(void)
{
    /* a zone five hours behind UTC whose daylight time starts the second Sunday of March at 02:00 (2031-03-09)
       and ends the first Sunday of November at 02:00 (2031-11-02) */
    static const WCHAR daily[] =
        L"<CalendarTrigger><StartBoundary>2031-03-05T09:30:00</StartBoundary><Enabled>true</Enabled>"
        L"<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>";
    static const WCHAR weekly[] =
        L"<CalendarTrigger><StartBoundary>2031-03-05T09:30:00</StartBoundary><Enabled>true</Enabled>"
        L"<ScheduleByWeek><DaysOfWeek><Wednesday/></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>"
        L"</CalendarTrigger>";
    static const struct when daily_runs[] = { {2031,3,7,9,30}, {2031,3,8,9,30}, {2031,3,9,9,30}, {2031,3,10,9,30} };
    static const struct when weekly_runs[] = { {2031,3,5,9,30}, {2031,3,12,9,30}, {2031,3,19,9,30} };
    static const struct when from_d = {2031,3,7,0,0}, to_d = {2031,3,10,23,59};
    static const struct when from_w = {2031,3,1,0,0}, to_w = {2031,3,20,0,0};
    TIME_ZONE_INFORMATION old, zone;
    IRegisteredTask *task;
    DWORD ret;

    ret = GetTimeZoneInformation(&old);
    if (ret == TIME_ZONE_ID_INVALID || !enable_time_zone_privilege())
    {
        skip("cannot read or set the time zone\n");
        return;
    }
    memset(&zone, 0, sizeof(zone));
    zone.Bias = 300;
    zone.DaylightBias = -60;
    wcscpy(zone.StandardName, L"Apitest Standard Time");
    wcscpy(zone.DaylightName, L"Apitest Daylight Time");
    zone.StandardDate.wMonth = 11;
    zone.StandardDate.wDayOfWeek = 0;
    zone.StandardDate.wDay = 1;
    zone.StandardDate.wHour = 2;
    zone.DaylightDate.wMonth = 3;
    zone.DaylightDate.wDayOfWeek = 0;
    zone.DaylightDate.wDay = 2;
    zone.DaylightDate.wHour = 2;
    if (!SetTimeZoneInformation(&zone))
    {
        skip("SetTimeZoneInformation failed: %lu\n", GetLastError());
        return;
    }

    /* the zone is in force, for the service too: a fixed UTC time of day moves on the wall clock at the change */
    {
        static const WCHAR utc_daily[] =
            L"<CalendarTrigger><StartBoundary>2031-03-05T14:30:00Z</StartBoundary><Enabled>true</Enabled>"
            L"<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>";
        static const struct when utc_runs[] = { {2031,3,7,9,30}, {2031,3,8,9,30}, {2031,3,9,10,30}, {2031,3,10,10,30} };

        task = register_xml(L"DailyUtcDst", utc_daily, L"exit");
        if (task)
        {
            CHECK_TIMES(task, "daily at a fixed UTC time across the start of daylight time", from_d, to_d, utc_runs);
            IRegisteredTask_Release(task);
            delete_task(L"DailyUtcDst");
        }
    }

    task = register_xml(L"DailyDst", daily, L"exit");
    if (task)
    {
        /* 09:30 on the wall clock on both sides of the change */
        CHECK_TIMES(task, "daily across the start of daylight time", from_d, to_d, daily_runs);
        IRegisteredTask_Release(task);
        delete_task(L"DailyDst");
    }
    task = register_xml(L"WeeklyDst", weekly, L"exit");
    if (task)
    {
        CHECK_TIMES(task, "weekly across the start of daylight time", from_w, to_w, weekly_runs);
        IRegisteredTask_Release(task);
        delete_task(L"WeeklyDst");
    }

    ok(SetTimeZoneInformation(&old), "could not restore the time zone: %lu\n", GetLastError());
}

/* a local "YYYY-MM-DDTHH:MM:SS" and the calendar facts of now + seconds */
static void now_plus(int seconds, SYSTEMTIME *st)
{
    FILETIME ft, local;
    ULARGE_INTEGER t;

    GetSystemTimeAsFileTime(&ft);
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    t.QuadPart += (LONGLONG)seconds * 10000000;
    ft.dwLowDateTime = t.LowPart;
    ft.dwHighDateTime = t.HighPart;
    FileTimeToLocalFileTime(&ft, &local);
    FileTimeToSystemTime(&local, st);
}

static DWORD file_size(const WCHAR *path)
{
    WIN32_FILE_ATTRIBUTE_DATA data;

    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &data)) return ~0u;
    return data.nFileSizeLow;
}

/* weekly, monthly and monthly day-of-week triggers set for a minute from now run once, and not again */
static void test_fire(void)
{
    static const WCHAR *const names[] = { L"FireWeekly", L"FireMonthly", L"FireMonthlyDow", L"FireIdle" };
    WCHAR markers[4][MAX_PATH], triggers[4][2048], command[MAX_PATH + 32], start[64];
    IRegisteredTask *tasks[4] = { 0 };
    SYSTEMTIME st;
    DWORD begin;
    unsigned int i;
    BOOL all;
    int dow;

    now_plus(75, &st);
    _snwprintf(start, ARRAYSIZE(start), L"%04u-%02u-%02uT%02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour,
               st.wMinute, st.wSecond);
    dow = st.wDayOfWeek;

    _snwprintf(triggers[0], ARRAYSIZE(triggers[0]),
               L"<CalendarTrigger><StartBoundary>%s</StartBoundary><Enabled>true</Enabled><ScheduleByWeek>"
               L"<DaysOfWeek><%s/></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger>",
               start, week_days_xml[dow]);
    _snwprintf(triggers[1], ARRAYSIZE(triggers[1]),
               L"<CalendarTrigger><StartBoundary>%s</StartBoundary><Enabled>true</Enabled><ScheduleByMonth>"
               L"<DaysOfMonth><Day>%u</Day></DaysOfMonth><Months><January/><February/><March/><April/><May/><June/>"
               L"<July/><August/><September/><October/><November/><December/></Months></ScheduleByMonth></CalendarTrigger>",
               start, st.wDay);
    _snwprintf(triggers[2], ARRAYSIZE(triggers[2]),
               L"<CalendarTrigger><StartBoundary>%s</StartBoundary><Enabled>true</Enabled><ScheduleByMonthDayOfWeek>"
               L"<Weeks><Week>%u</Week><Week>Last</Week></Weeks><DaysOfWeek><%s/></DaysOfWeek><Months><January/>"
               L"<February/><March/><April/><May/><June/><July/><August/><September/><October/><November/>"
               L"<December/></Months></ScheduleByMonthDayOfWeek></CalendarTrigger>",
               start, (st.wDay - 1) / 7 + 1 > 4 ? 4 : (st.wDay - 1) / 7 + 1, week_days_xml[dow]);
    _snwprintf(triggers[3], ARRAYSIZE(triggers[3]), L"<IdleTrigger><Enabled>true</Enabled></IdleTrigger>");

    for (i = 0; i < 4; i++)
    {
        _snwprintf(markers[i], ARRAYSIZE(markers[i]), L"%s\\cal-fire-%u.txt", marker_dir, i);
        DeleteFileW(markers[i]);
        _snwprintf(command, ARRAYSIZE(command), L"echo x>> \"%s\"", markers[i]);
        tasks[i] = register_xml(names[i], triggers[i], command);
    }

    begin = GetTickCount();
    do
    {
        all = TRUE;
        for (i = 0; i < 3; i++)
            if (tasks[i] && file_size(markers[i]) == ~0u) all = FALSE;
        if (!all) Sleep(1000);
    } while (!all && GetTickCount() - begin < WAIT_MS);

    for (i = 0; i < 3; i++)
        if (tasks[i]) ok(file_size(markers[i]) != ~0u, "%ls did not run\n", names[i]);

    /* and not again: nothing runs these within the next while, the schedule says a week, a month, a month */
    Sleep(25000);
    for (i = 0; i < 3; i++)
    {
        if (!tasks[i]) continue;
        ok(file_size(markers[i]) == 3, "%ls ran %lu bytes of output, expected one run\n", names[i], file_size(markers[i]));
        if (file_size(markers[i]) == 3)
        {
            DATE next = 0, now;
            SYSTEMTIME local;
            HRESULT hr = IRegisteredTask_get_NextRunTime(tasks[i], &next);

            GetLocalTime(&local);
            SystemTimeToVariantTime(&local, &now);
            ok(hr == S_OK && next > now + 5, "%ls: NextRunTime 0x%lx %f, now %f\n", names[i], hr, next, now);
        }
    }
    /* the idle trigger is kept and never fires */
    ok(file_size(markers[3]) == ~0u, "the idle task ran\n");

    for (i = 0; i < 4; i++)
    {
        if (tasks[i]) IRegisteredTask_Release(tasks[i]);
        if (tasks[i]) delete_task(names[i]);
        DeleteFileW(markers[i]);
    }
}

START_TEST(TaskSchedulerCalendar)
{
    ITaskFolder *root;
    VARIANT empty;
    HRESULT hr;
    DWORD n;

    GetTempPathW(ARRAYSIZE(marker_dir), marker_dir);
    n = wcslen(marker_dir);
    if (n && marker_dir[n - 1] == '\\') marker_dir[n - 1] = 0;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void **)&service);
    ok(hr == S_OK, "CoCreateInstance(CLSID_TaskScheduler) failed: 0x%lx\n", hr);
    if (hr != S_OK)
    {
        skip("no Task Scheduler\n");
        return;
    }
    VariantInit(&empty);
    hr = ITaskService_Connect(service, empty, empty, empty, empty);
    ok(hr == S_OK, "Connect failed: 0x%lx\n", hr);
    if (hr != S_OK) goto out;

    hr = ITaskService_GetFolder(service, (BSTR)L"\\", &root);
    ok(hr == S_OK, "GetFolder failed: 0x%lx\n", hr);
    if (hr != S_OK) goto out;
    hr = ITaskFolder_CreateFolder(root, (BSTR)CAL_FOLDER, empty, &folder);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) hr = ITaskService_GetFolder(service, (BSTR)CAL_FOLDER, &folder);
    ok(hr == S_OK, "CreateFolder failed: 0x%lx\n", hr);
    ITaskFolder_Release(root);
    if (hr != S_OK) goto out;

    test_trigger_objects();
    test_late_binding();
    test_calendar_schedules();
    test_zoned_boundary();
    test_unrun_triggers();
    test_daylight_saving();
    test_fire();

    ITaskFolder_Release(folder);
    folder = NULL;
    if (SUCCEEDED(ITaskService_GetFolder(service, (BSTR)L"\\", &root)))
    {
        hr = ITaskFolder_DeleteFolder(root, (BSTR)CAL_FOLDER_NAME, 0);
        ok(hr == S_OK, "DeleteFolder failed: 0x%lx\n", hr);
        ITaskFolder_Release(root);
    }

out:
    ITaskService_Release(service);
}
