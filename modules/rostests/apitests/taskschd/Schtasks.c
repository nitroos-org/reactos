/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     schtasks.exe round trips: /create, /query, /run, /change, /delete
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>

#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <stdio.h>

#define TASK1 L"ReactOS ApiTest Sch\\One"
#define TASK2 L"ReactOS ApiTest Sch\\Two"
#define TASK3 L"ReactOS ApiTest Sch\\Three"
#define TASK_XML L"ReactOS ApiTest Sch\\Xml"
#define WAIT_MS 60000

static WCHAR marker_dir[MAX_PATH];

typedef BOOL (WINAPI *WOW64DISABLE)(void **);
typedef BOOL (WINAPI *WOW64REVERT)(void *);

/*
 * Runs a command line with its standard input empty and its output collected (stdout and stderr together,
 * CRLF as LF). schtasks.exe is the one of the system directory, not of SysWOW64, for a 32-bit test.
 */
static DWORD run_command(const WCHAR *cmdline, char *output, size_t size)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HANDLE read_pipe, write_pipe, nul;
    WOW64DISABLE disable = (WOW64DISABLE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Wow64DisableWow64FsRedirection");
    WOW64REVERT revert = (WOW64REVERT)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Wow64RevertWow64FsRedirection");
    void *old = NULL;
    BOOL redirected = FALSE, ok_create;
    WCHAR *copy;
    DWORD code = ~0u, got;
    size_t used = 0;

    output[0] = 0;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) return code;
    nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul;
    si.hStdOutput = write_pipe;
    si.hStdError = write_pipe;

    copy = _wcsdup(cmdline);
    if (disable && revert) redirected = disable(&old);
    ok_create = CreateProcessW(NULL, copy, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (redirected) revert(old);
    free(copy);
    CloseHandle(write_pipe);
    CloseHandle(nul);
    if (!ok_create)
    {
        CloseHandle(read_pipe);
        return code;
    }
    CloseHandle(pi.hThread);

    while (used + 1 < size && ReadFile(read_pipe, output + used, size - used - 1, &got, NULL) && got) used += got;
    output[used] = 0;
    WaitForSingleObject(pi.hProcess, 60000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(read_pipe);

    /* CRLF to LF */
    {
        char *src = output, *dst = output;

        for (; *src; src++)
            if (*src != '\r') *dst++ = *src;
        *dst = 0;
    }
    return code;
}

/* schtasks.exe <args>, with the output in 'output' */
static DWORD schtasks(char *output, size_t size, const WCHAR *fmt, ...)
{
    WCHAR args[1024], cmdline[1200], dir[MAX_PATH];
    va_list list;

    va_start(list, fmt);
    _vsnwprintf(args, ARRAYSIZE(args), fmt, list);
    va_end(list);
    GetSystemDirectoryW(dir, ARRAYSIZE(dir));
    _snwprintf(cmdline, ARRAYSIZE(cmdline), L"\"%s\\schtasks.exe\" %s", dir, args);
    return run_command(cmdline, output, size);
}

static BOOL wait_for_file(const WCHAR *path, DWORD timeout)
{
    DWORD start = GetTickCount();

    while (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
    {
        if (GetTickCount() - start > timeout) return FALSE;
        Sleep(250);
    }
    return TRUE;
}

/* HH:MM of now + minutes, local time */
static void time_text(int minutes, WCHAR *text)
{
    FILETIME ft, local;
    ULARGE_INTEGER t;
    SYSTEMTIME st;

    GetSystemTimeAsFileTime(&ft);
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    t.QuadPart += (ULONGLONG)minutes * 60 * 10000000;
    ft.dwLowDateTime = t.LowPart;
    ft.dwHighDateTime = t.HighPart;
    FileTimeToLocalFileTime(&ft, &local);
    FileTimeToSystemTime(&local, &st);
    _snwprintf(text, 16, L"%02u:%02u", st.wHour, st.wMinute);
}

#define EXPECT_RC(rc, expected, out) \
    ok((rc) == (expected), "exit code %lu, expected %lu, output:\n%s\n", (DWORD)(rc), (DWORD)(expected), out)
#define EXPECT_HAS(out, text) ok(strstr(out, text) != NULL, "output has no \"%s\":\n%s\n", text, out)
#define EXPECT_HAS_NOT(out, text) ok(strstr(out, text) == NULL, "output has \"%s\":\n%s\n", text, out)

static void test_usage_errors(void)
{
    char out[4096];
    DWORD rc;

    rc = schtasks(out, sizeof(out), L"/query /fo XYZ");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR: Improper display format type specified.");
    EXPECT_HAS(out, "Type \"SCHTASKS /QUERY /?\" for usage.");

    rc = schtasks(out, sizeof(out), L"/run");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR: Invalid syntax. Mandatory option '/tn' is missing.");
    EXPECT_HAS(out, "Type \"SCHTASKS /RUN /?\" for usage.");

    rc = schtasks(out, sizeof(out), L"/query /fo LIST /nh");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR: /NH switch cannot be used with the LIST format.");

    /* a task that is not there, as Windows words it */
    rc = schtasks(out, sizeof(out), L"/run /tn \"ReactOS ApiTest NoSuchTask\"");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR: The system cannot find the file specified.");
    rc = schtasks(out, sizeof(out), L"/query /tn \"ReactOS ApiTest NoSuchTask\"");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR: The system cannot find the file specified.");
    rc = schtasks(out, sizeof(out), L"/delete /tn \"ReactOS ApiTest NoSuchTask\" /f");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR: The system cannot find the file specified.");
    rc = schtasks(out, sizeof(out), L"/delete /tn \"ReactOS ApiTest NoSuchTask\"");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR: The specified task name \"ReactOS ApiTest NoSuchTask\" does not exist in the system.");

    /* a task cannot name a place outside the task store */
    rc = schtasks(out, sizeof(out), L"/create /tn \"..\\..\\schtasks_apitest_escape\" /tr cmd.exe /sc once /st 23:59 /f");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR:");
}

/* the layout between two tags removed, so that a piece of XML is found whatever the indentation */
static void squash_xml(char *text)
{
    char *src = text, *dst = text;

    while (*src)
    {
        if (src > text && src[-1] == '>' && (*src == ' ' || *src == '\n'))
        {
            char *p = src;

            while (*p == ' ' || *p == '\n') p++;
            if (*p == '<')
            {
                src = p;
                continue;
            }
        }
        *dst++ = *src++;
    }
    *dst = 0;
}

/* /create /sc weekly and monthly with /mo /d /m: the schedule they make, stored and listed */
static void test_calendar_schedules(void)
{
    static const WCHAR *const names[] =
    {
        L"ReactOS ApiTest Sch\\Weekly", L"ReactOS ApiTest Sch\\WeeklyDefault", L"ReactOS ApiTest Sch\\MonthDay",
        L"ReactOS ApiTest Sch\\MonthWeek", L"ReactOS ApiTest Sch\\MonthLast", L"ReactOS ApiTest Sch\\MonthLastDay",
        L"ReactOS ApiTest Sch\\MonthEvery",
    };
    char out[16384];
    DWORD rc;
    unsigned int i;

    rc = schtasks(out, sizeof(out), L"/create /tn \"%s\" /tr \"cmd.exe /c exit\" /sc weekly /mo 2 /d MON,THU /st 09:30 "
                  L"/sd 03/05/2031 /f", names[0]);
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "SUCCESS: The scheduled task \"ReactOS ApiTest Sch\\Weekly\" has successfully been created.");
    rc = schtasks(out, sizeof(out), L"/query /xml /tn \"%s\"", names[0]);
    EXPECT_RC(rc, 0, out);
    squash_xml(out);
    EXPECT_HAS(out, "<StartBoundary>2031-03-05T09:30:00</StartBoundary>");
    EXPECT_HAS(out, "<ScheduleByWeek>");
    EXPECT_HAS(out, "<DaysOfWeek><Monday/><Thursday/></DaysOfWeek>"
                    "<WeeksInterval>2</WeeksInterval></ScheduleByWeek>");
    rc = schtasks(out, sizeof(out), L"/query /v /fo LIST /tn \"%s\"", names[0]);
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "\nSchedule Type:                        Weekly\n");
    EXPECT_HAS(out, "\nDays:                                 Every 2 week(s) on: MONDAY, THURSDAY\n");
    EXPECT_HAS(out, "\nNext Run Time:                        3/6/2031 9:30:00 AM\n");

    rc = schtasks(out, sizeof(out), L"/create /tn \"%s\" /tr \"cmd.exe /c exit\" /sc weekly /st 04:15 /sd 03/05/2031 /f",
                  names[1]);
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/query /xml /tn \"%s\"", names[1]);
    squash_xml(out);
    EXPECT_HAS(out, "<DaysOfWeek><Monday/></DaysOfWeek><WeeksInterval>1</WeeksInterval>");
    rc = schtasks(out, sizeof(out), L"/query /fo LIST /tn \"%s\"", names[1]);
    EXPECT_HAS(out, "\nNext Run Time: 3/10/2031 4:15:00 AM\n");

    rc = schtasks(out, sizeof(out), L"/create /tn \"%s\" /tr \"cmd.exe /c exit\" /sc monthly /d 15 /m JAN,JUL /st 08:00 "
                  L"/sd 03/05/2031 /f", names[2]);
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/query /xml /tn \"%s\"", names[2]);
    squash_xml(out);
    EXPECT_HAS(out, "<ScheduleByMonth><DaysOfMonth><Day>15</Day></DaysOfMonth><Months><January/><July/></Months>"
                    "</ScheduleByMonth>");
    rc = schtasks(out, sizeof(out), L"/query /v /fo LIST /tn \"%s\"", names[2]);
    EXPECT_HAS(out, "\nSchedule Type:                        Monthly\n");
    EXPECT_HAS(out, "\nDays:                                 15\n");
    EXPECT_HAS(out, "\nMonths:                               JANUARY, JULY\n");
    EXPECT_HAS(out, "\nNext Run Time:                        7/15/2031 8:00:00 AM\n");

    rc = schtasks(out, sizeof(out), L"/create /tn \"%s\" /tr \"cmd.exe /c exit\" /sc monthly /mo second /d TUE /st 08:00 "
                  L"/sd 03/05/2031 /f", names[3]);
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/query /xml /tn \"%s\"", names[3]);
    squash_xml(out);
    EXPECT_HAS(out, "<ScheduleByMonthDayOfWeek><Weeks><Week>2</Week></Weeks><DaysOfWeek><Tuesday/></DaysOfWeek>"
                    "<Months><January/><February/><March/><April/><May/><June/><July/><August/><September/>"
                    "<October/><November/><December/></Months></ScheduleByMonthDayOfWeek>");
    rc = schtasks(out, sizeof(out), L"/query /fo LIST /tn \"%s\"", names[3]);
    EXPECT_HAS(out, "\nNext Run Time: 3/11/2031 8:00:00 AM\n");

    rc = schtasks(out, sizeof(out), L"/create /tn \"%s\" /tr \"cmd.exe /c exit\" /sc monthly /mo last /d FRI /m FEB /st 08:00 "
                  L"/sd 03/05/2031 /f", names[4]);
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/query /xml /tn \"%s\"", names[4]);
    squash_xml(out);
    EXPECT_HAS(out, "<Weeks><Week>Last</Week></Weeks><DaysOfWeek><Friday/></DaysOfWeek><Months><February/></Months>");
    rc = schtasks(out, sizeof(out), L"/query /fo LIST /tn \"%s\"", names[4]);
    EXPECT_HAS(out, "\nNext Run Time: 2/27/2032 8:00:00 AM\n");

    rc = schtasks(out, sizeof(out), L"/create /tn \"%s\" /tr \"cmd.exe /c exit\" /sc monthly /mo lastday /m FEB /st 08:00 "
                  L"/sd 03/05/2031 /f", names[5]);
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/query /xml /tn \"%s\"", names[5]);
    squash_xml(out);
    EXPECT_HAS(out, "<DaysOfMonth><Day>Last</Day></DaysOfMonth><Months><February/></Months>");
    rc = schtasks(out, sizeof(out), L"/query /fo LIST /tn \"%s\"", names[5]);
    EXPECT_HAS(out, "\nNext Run Time: 2/29/2032 8:00:00 AM\n");

    rc = schtasks(out, sizeof(out), L"/create /tn \"%s\" /tr \"cmd.exe /c exit\" /sc monthly /mo 3 /st 04:00 /sd 02/10/2031 /f",
                  names[6]);
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/query /xml /tn \"%s\"", names[6]);
    squash_xml(out);
    EXPECT_HAS(out, "<DaysOfMonth><Day>1</Day></DaysOfMonth><Months><February/><May/><August/><November/></Months>");

    /* the schedules the service would not run are refused, and so are the values that make no schedule */
    rc = schtasks(out, sizeof(out), L"/create /tn \"ReactOS ApiTest Sch\\Bad\" /tr cmd.exe /sc onidle /i 10 /f");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR:");
    rc = schtasks(out, sizeof(out), L"/create /tn \"ReactOS ApiTest Sch\\Bad\" /tr cmd.exe /sc weekly /d XYZ /f");
    EXPECT_RC(rc, 1, out);
    rc = schtasks(out, sizeof(out), L"/create /tn \"ReactOS ApiTest Sch\\Bad\" /tr cmd.exe /sc weekly /mo 60 /f");
    EXPECT_RC(rc, 1, out);
    rc = schtasks(out, sizeof(out), L"/create /tn \"ReactOS ApiTest Sch\\Bad\" /tr cmd.exe /sc monthly /mo second /f");
    EXPECT_RC(rc, 1, out);
    rc = schtasks(out, sizeof(out), L"/create /tn \"ReactOS ApiTest Sch\\Bad\" /tr cmd.exe /sc monthly /d 32 /f");
    EXPECT_RC(rc, 1, out);
    rc = schtasks(out, sizeof(out), L"/query /tn \"ReactOS ApiTest Sch\\Bad\"");
    EXPECT_RC(rc, 1, out);

    for (i = 0; i < ARRAYSIZE(names); i++)
    {
        rc = schtasks(out, sizeof(out), L"/delete /tn \"%s\" /f", names[i]);
        EXPECT_RC(rc, 0, out);
    }
}

START_TEST(Schtasks)
{
    WCHAR marker[MAX_PATH], st[16], xml_path[MAX_PATH], xml_text[2048];
    char out[16384];
    DWORD rc, i, n;
    HANDLE file;

    GetTempPathW(ARRAYSIZE(marker_dir), marker_dir);
    n = wcslen(marker_dir);
    if (n && marker_dir[n - 1] == '\\') marker_dir[n - 1] = 0;

    rc = schtasks(out, sizeof(out), L"/query /tn \"\\nonexistent\"");
    if (rc == ~0u)
    {
        skip("schtasks.exe cannot be run\n");
        return;
    }

    test_usage_errors();

    /* clean up what an earlier run may have left */
    schtasks(out, sizeof(out), L"/delete /tn \"" TASK1 L"\" /f");
    schtasks(out, sizeof(out), L"/delete /tn \"" TASK2 L"\" /f");
    schtasks(out, sizeof(out), L"/delete /tn \"" TASK3 L"\" /f");
    schtasks(out, sizeof(out), L"/delete /tn \"" TASK_XML L"\" /f");

    test_calendar_schedules();

    /* /create /sc once: a task a day away, whose action writes a marker */
    _snwprintf(marker, ARRAYSIZE(marker), L"%s\\sch-one.txt", marker_dir);
    DeleteFileW(marker);
    time_text(24 * 60 - 1, st);
    rc = schtasks(out, sizeof(out),
                  L"/create /tn \"" TASK1 L"\" /tr \"cmd.exe /c echo one> \\\"%s\\\"\" /sc once /st %s /sd 12/31/2099 /f",
                  marker, st);
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "SUCCESS: The scheduled task \"ReactOS ApiTest Sch\\One\" has successfully been created.");

    /* /query: LIST, CSV, TABLE, with the task selected */
    rc = schtasks(out, sizeof(out), L"/query /fo LIST /tn \"" TASK1 L"\"");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "\nFolder: \\ReactOS ApiTest Sch\n");
    EXPECT_HAS(out, "\nHostName:      ");
    EXPECT_HAS(out, "\nTaskName:      \\ReactOS ApiTest Sch\\One\n");
    EXPECT_HAS(out, "\nNext Run Time: ");
    EXPECT_HAS_NOT(out, "\nNext Run Time: N/A");
    EXPECT_HAS(out, "\nStatus:        Ready\n");
    EXPECT_HAS(out, "\nLogon Mode:    Interactive only\n");

    rc = schtasks(out, sizeof(out), L"/query /fo CSV /tn \"" TASK1 L"\"");
    EXPECT_RC(rc, 0, out);
    ok(!strncmp(out, "\"TaskName\",\"Next Run Time\",\"Status\"\n", 36), "CSV header:\n%s\n", out);
    EXPECT_HAS(out, "\n\"\\ReactOS ApiTest Sch\\One\",\"");
    EXPECT_HAS(out, "\",\"Ready\"\n");

    rc = schtasks(out, sizeof(out), L"/query /fo CSV /nh /tn \"" TASK1 L"\"");
    EXPECT_RC(rc, 0, out);
    ok(!strncmp(out, "\"\\ReactOS ApiTest Sch\\One\",\"", 28), "CSV /nh output:\n%s\n", out);
    EXPECT_HAS_NOT(out, "TaskName\"");

    rc = schtasks(out, sizeof(out), L"/query /tn \"" TASK1 L"\"");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "\nFolder: \\ReactOS ApiTest Sch\n");
    EXPECT_HAS(out, "TaskName                                 Next Run Time          Status         \n");
    EXPECT_HAS(out, "======================================== ====================== ===============\n");
    EXPECT_HAS(out, "\nOne                                      ");

    /* verbose */
    rc = schtasks(out, sizeof(out), L"/query /v /fo LIST /tn \"" TASK1 L"\"");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "\nLast Run Time:                        11/30/1999 12:00:00 AM\n");
    EXPECT_HAS(out, "\nLast Result:                          267011\n");
    EXPECT_HAS(out, "\nTask To Run:                          cmd.exe /c echo one> ");
    EXPECT_HAS(out, "\nScheduled Task State:                 Enabled\n");
    EXPECT_HAS(out, "\nSchedule Type:                        One Time Only\n");
    EXPECT_HAS(out, "\nStart Date:                           12/31/2099\n");
    EXPECT_HAS(out, "\nRepeat: Every:                        Disabled\n");
    rc = schtasks(out, sizeof(out), L"/query /v /fo CSV /tn \"" TASK1 L"\"");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Logon Mode\",\"Last Run Time\",\"Last Result\",");
    EXPECT_HAS(out, "\"Repeat: Stop If Still Running\"\n");

    /* the whole store lists the task under its folder, and the root as a heading */
    rc = schtasks(out, sizeof(out), L"/query /fo LIST");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "\nFolder: \\\n");
    EXPECT_HAS(out, "\nTaskName:      \\ReactOS ApiTest Sch\\One\n");

    /* /run: the marker appears, and the task has a last run and result */
    rc = schtasks(out, sizeof(out), L"/run /tn \"" TASK1 L"\"");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "SUCCESS: Attempted to run the scheduled task \"ReactOS ApiTest Sch\\One\".");
    ok(wait_for_file(marker, WAIT_MS), "the task did not write %ls\n", marker);
    for (i = 0; i < 60; i++)
    {
        rc = schtasks(out, sizeof(out), L"/query /v /fo LIST /tn \"" TASK1 L"\"");
        if (strstr(out, "\nStatus:                               Ready\n") &&
            !strstr(out, "11/30/1999 12:00:00 AM\nLast Result:                          267011")) break;
        Sleep(500);
    }
    EXPECT_HAS(out, "\nLast Result:                          0\n");
    EXPECT_HAS_NOT(out, "\nLast Run Time:                        11/30/1999");

    /* /change /disable and /enable */
    rc = schtasks(out, sizeof(out), L"/change /tn \"" TASK1 L"\" /disable");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "SUCCESS: The parameters of scheduled task \"ReactOS ApiTest Sch\\One\" have been changed.");
    rc = schtasks(out, sizeof(out), L"/query /fo LIST /tn \"" TASK1 L"\"");
    EXPECT_HAS(out, "\nStatus:        Disabled\n");
    EXPECT_HAS(out, "\nNext Run Time: N/A\n");
    rc = schtasks(out, sizeof(out), L"/run /tn \"" TASK1 L"\"");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR:");
    rc = schtasks(out, sizeof(out), L"/change /tn \"" TASK1 L"\" /enable");
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/query /fo LIST /tn \"" TASK1 L"\"");
    EXPECT_HAS(out, "\nStatus:        Ready\n");

    /* creating it again needs /f (or an answer, which an empty input does not give) */
    rc = schtasks(out, sizeof(out), L"/create /tn \"" TASK1 L"\" /tr cmd.exe /sc once /st %s", st);
    EXPECT_RC(rc, 1, out);

    /* /create /sc daily and /sc onlogon, then the schedule types */
    rc = schtasks(out, sizeof(out), L"/create /tn \"" TASK2 L"\" /tr \"cmd.exe /c exit\" /sc daily /mo 3 /st 04:30 /f");
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/create /tn \"" TASK3 L"\" /tr \"cmd.exe /c exit\" /sc onlogon /f");
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/query /v /fo LIST /tn \"" TASK2 L"\"");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "\nSchedule Type:                        Daily \n");
    EXPECT_HAS(out, "\nStart Time:                           4:30:00 AM\n");
    EXPECT_HAS(out, "\nDays:                                 Every 3 day(s)\n");
    rc = schtasks(out, sizeof(out), L"/query /v /fo LIST /tn \"" TASK3 L"\"");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "\nSchedule Type:                        At logon time\n");
    EXPECT_HAS(out, "\nStart Time:                           N/A\n");
    rc = schtasks(out, sizeof(out), L"/query /fo CSV /nh /tn \"" TASK3 L"\"");
    EXPECT_HAS(out, ",\"N/A\",\"Ready\"\n");

    /* /create /xml, and /query /xml */
    _snwprintf(xml_path, ARRAYSIZE(xml_path), L"%s\\sch-task.xml", marker_dir);
    _snwprintf(xml_text, ARRAYSIZE(xml_text),
               L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
               L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
               L"  <RegistrationInfo><Author>apitest</Author><Description>from xml</Description></RegistrationInfo>\n"
               L"  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>\n"
               L"  <Settings><Enabled>true</Enabled></Settings>\n"
               L"  <Actions><Exec><Command>cmd.exe</Command><Arguments>/c exit</Arguments></Exec></Actions>\n"
               L"</Task>\n");
    file = CreateFileW(xml_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (file != INVALID_HANDLE_VALUE)
    {
        WORD bom = 0xfeff;
        DWORD written;

        WriteFile(file, &bom, sizeof(bom), &written, NULL);
        WriteFile(file, xml_text, wcslen(xml_text) * sizeof(WCHAR), &written, NULL);
        CloseHandle(file);
    }
    rc = schtasks(out, sizeof(out), L"/create /tn \"" TASK_XML L"\" /xml \"%s\" /f", xml_path);
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "SUCCESS: The scheduled task \"ReactOS ApiTest Sch\\Xml\" has successfully been created.");
    rc = schtasks(out, sizeof(out), L"/query /v /fo LIST /tn \"" TASK_XML L"\"");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "\nComment:                              from xml\n");
    EXPECT_HAS(out, "\nSchedule Type:                        At logon time\n");
    rc = schtasks(out, sizeof(out), L"/query /xml /tn \"" TASK_XML L"\"");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "<LogonTrigger>");
    DeleteFileW(xml_path);

    /* /delete: the answer without /f is not given, the task stays; with /f it goes */
    rc = schtasks(out, sizeof(out), L"/delete /tn \"" TASK2 L"\"");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "WARNING: Are you sure you want to remove the task \"ReactOS ApiTest Sch\\Two\" (Y/N)? ");
    rc = schtasks(out, sizeof(out), L"/query /fo LIST /tn \"" TASK2 L"\"");
    EXPECT_RC(rc, 0, out);

    rc = schtasks(out, sizeof(out), L"/delete /tn \"" TASK1 L"\" /f");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS(out, "SUCCESS: The scheduled task \"ReactOS ApiTest Sch\\One\" was successfully deleted.");
    rc = schtasks(out, sizeof(out), L"/query /tn \"" TASK1 L"\"");
    EXPECT_RC(rc, 1, out);
    EXPECT_HAS(out, "ERROR: The system cannot find the file specified.");
    rc = schtasks(out, sizeof(out), L"/delete /tn \"" TASK2 L"\" /f");
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/delete /tn \"" TASK3 L"\" /f");
    EXPECT_RC(rc, 0, out);
    rc = schtasks(out, sizeof(out), L"/delete /tn \"" TASK_XML L"\" /f");
    EXPECT_RC(rc, 0, out);

    /* the folder is empty now: it lists nothing */
    rc = schtasks(out, sizeof(out), L"/query /fo CSV");
    EXPECT_RC(rc, 0, out);
    EXPECT_HAS_NOT(out, "ReactOS ApiTest Sch\\");

    /* the folder goes with /delete, when it is empty */
    rc = schtasks(out, sizeof(out), L"/delete /tn \"ReactOS ApiTest Sch\" /f");
    EXPECT_RC(rc, 0, out);
    DeleteFileW(marker);
}
