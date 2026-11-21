/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Task Scheduler 2.0 service: who may do what, and what it refuses
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The tests talk to the Schedule service with the RPC stubs, as taskschd.dll does, so that
 * the checks of the service are tested and not the ones of the client library. The cases:
 * path validation, oversized XML, an overflowing DaysInterval (the service must survive it),
 * a replaced task XML that is shorter than the old one, Run of a task that still runs, calls
 * that do not come in over ncalrpc, and two non-administrator users that must not touch each
 * other's tasks. A user's calls run in a child process that logs the user on and impersonates it.
 */

#define COBJMACROS
#include <apitest.h>

#include <windef.h>
#include <winbase.h>
#include <winsvc.h>
#include <rpc.h>
#include <objbase.h>
#include <taskschd.h>
#include <schrpc.h>
#include <lm.h>
#include <stdio.h>

#define FOLDER L"\\ReactOS Sec"
/* the service limits; see MAX_TASKS_PER_USER in base/services/schedsvc/taskrun.c */
#define TASKS_PER_USER 64
#define FOLDERS_PER_USER 32
#define PASSWORD L"Task-Sched-Test-2026!"

void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return malloc(len);
}

void __RPC_USER midl_user_free(void __RPC_FAR *ptr)
{
    free(ptr);
}

static const WCHAR xml_head[] =
    L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">";
static const WCHAR xml_actions[] =
    L"<Actions><Exec><Command>cmd.exe</Command><Arguments>/c exit</Arguments></Exec></Actions></Task>";

/* a task that never fires */
static void far_xml(WCHAR *xml)
{
    _snwprintf(xml, 600, L"%s<Triggers><TimeTrigger><StartBoundary>2099-01-01T00:00:00</StartBoundary>"
             L"</TimeTrigger></Triggers>%s", xml_head, xml_actions);
}

/*
 * A task that fires at "start" (UTC, YYYY-MM-DDTHH:MM:SSZ), as the principal (NULL for none), and whose
 * action writes C:\ts_<tag>.txt: if the file appears, the task ran.
 */
static void prin_xml(WCHAR *xml, const WCHAR *principal, const WCHAR *tag, const WCHAR *start)
{
    WCHAR prin[200] = L"";

    if (principal && wcscmp(principal, L"-"))
        _snwprintf(prin, ARRAYSIZE(prin), L"<Principals><Principal id=\"Author\"><UserId>%s</UserId></Principal></Principals>",
                   principal);
    _snwprintf(xml, 1500, L"%s<Triggers><TimeTrigger><StartBoundary>%s</StartBoundary></TimeTrigger></Triggers>%s"
               L"<Actions Context=\"Author\"><Exec><Command>%%SystemRoot%%\\system32\\cmd.exe</Command>"
               L"<Arguments>/c echo x&gt; C:\\ts_%s.txt</Arguments></Exec></Actions></Task>", xml_head, start, prin, tag);
}

static BOOL marker_exists(const WCHAR *tag)
{
    WCHAR path[100];

    _snwprintf(path, ARRAYSIZE(path), L"C:\\ts_%s.txt", tag);
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static void marker_delete(const WCHAR *tag)
{
    WCHAR path[100];

    _snwprintf(path, ARRAYSIZE(path), L"C:\\ts_%s.txt", tag);
    DeleteFileW(path);
}

static BOOL bind_to(const WCHAR *protseq, const WCHAR *endpoint)
{
    extern handle_t schrpc_handle;
    RPC_WSTR str;
    RPC_STATUS status;

    if (schrpc_handle)
    {
        RpcBindingFree(&schrpc_handle);
        schrpc_handle = NULL;
    }
    status = RpcStringBindingComposeW(NULL, (RPC_WSTR)protseq, NULL, (RPC_WSTR)endpoint, NULL, &str);
    ok(status == RPC_S_OK, "RpcStringBindingCompose failed: %ld\n", status);
    if (status != RPC_S_OK) return FALSE;
    status = RpcBindingFromStringBindingW(str, &schrpc_handle);
    RpcStringFreeW(&str);
    ok(status == RPC_S_OK, "RpcBindingFromStringBinding failed: %ld\n", status);
    return status == RPC_S_OK;
}

static BOOL bind_local(void)
{
    return bind_to(L"ncalrpc", NULL);
}

#define RPC_CALL(call) \
    do { \
        hr = RPC_E_FAULT; \
        _SEH2_TRY { hr = (call); } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { hr = HRESULT_FROM_WIN32(RpcExceptionCode()); } _SEH2_END; \
    } while (0)

static HRESULT register_task(const WCHAR *path, const WCHAR *xml, DWORD flags)
{
    WCHAR *actual = NULL;
    TASK_XML_ERROR_INFO *info = NULL;
    HRESULT hr;

    RPC_CALL(SchRpcRegisterTask(path, xml, flags, NULL, TASK_LOGON_INTERACTIVE_TOKEN, 0, NULL, &actual, &info));
    if (hr == S_OK) ok(actual != NULL, "no actual path\n");
    free(actual);
    return hr;
}

static HRESULT delete_task(const WCHAR *path)
{
    HRESULT hr;

    RPC_CALL(SchRpcDelete(path, 0));
    return hr;
}

static HRESULT retrieve_task(const WCHAR *path, WCHAR **xml)
{
    ULONG languages = 0;
    HRESULT hr;

    *xml = NULL;
    RPC_CALL(SchRpcRetrieveTask(path, L"", &languages, xml));
    return hr;
}

static HRESULT run_task(const WCHAR *path)
{
    GUID guid;
    HRESULT hr;

    RPC_CALL(SchRpcRun(path, 0, NULL, 0, 0, NULL, &guid));
    return hr;
}

/* a path below the task store; the store is in System32 itself, not in SysWOW64, for a 32-bit test under WoW64 */
static BOOL file_exists(const WCHAR *relative)
{
    BOOL (WINAPI *pWow64DisableWow64FsRedirection)(void **);
    BOOL (WINAPI *pWow64RevertWow64FsRedirection)(void *);
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    WCHAR path[MAX_PATH];
    void *old = NULL;
    BOOL ret, disabled = FALSE;

    GetSystemDirectoryW(path, MAX_PATH);
    wcscat(path, L"\\Tasks");
    wcscat(path, relative);

    pWow64DisableWow64FsRedirection = (void *)GetProcAddress(kernel32, "Wow64DisableWow64FsRedirection");
    pWow64RevertWow64FsRedirection = (void *)GetProcAddress(kernel32, "Wow64RevertWow64FsRedirection");
    if (pWow64DisableWow64FsRedirection && pWow64RevertWow64FsRedirection)
        disabled = pWow64DisableWow64FsRedirection(&old);
    ret = GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
    if (disabled) pWow64RevertWow64FsRedirection(old);
    return ret;
}

static DWORD schedule_pid(void)
{
    SC_HANDLE scm, service;
    SERVICE_STATUS_PROCESS status = { 0 };
    DWORD size, pid = 0;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    service = OpenServiceW(scm, L"Schedule", SERVICE_QUERY_STATUS);
    if (service)
    {
        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &size) &&
            status.dwCurrentState == SERVICE_RUNNING)
            pid = status.dwProcessId;
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);
    return pid;
}

/* ---- path validation -------------------------------------------------------------------- */

static void test_paths(void)
{
    static const WCHAR *bad[] =
    {
        L"\\ReactOS Sec\\..\\escape", L"..\\escape", L"\\ReactOS Sec\\..", L"\\ReactOS Sec\\.", L"\\ReactOS Sec/../escape",
        L"\\ReactOS Sec\\dot.", L"\\ReactOS Sec\\dots...", L"\\ReactOS Sec\\space ", L"\\ReactOS Sec\\dir.\\x",
        L"\\ReactOS Sec\\CON", L"\\ReactOS Sec\\nul", L"\\ReactOS Sec\\Nul.txt", L"\\ReactOS Sec\\PRN", L"\\ReactOS Sec\\aux",
        L"\\ReactOS Sec\\COM1", L"\\ReactOS Sec\\com9.log", L"\\ReactOS Sec\\LPT1", L"\\ReactOS Sec\\lpt9.x",
        L"\\ReactOS Sec\\CONIN$", L"\\ReactOS Sec\\CONOUT$", L"\\ReactOS Sec\\NUL .txt", L"\\CON\\x", L"\\ReactOS Sec\\AUX\\x",
        L"\\ReactOS Sec\\a:b", L"\\ReactOS Sec\\a::$DATA", L"\\ReactOS Sec\\a*", L"\\ReactOS Sec\\a?", L"\\ReactOS Sec\\a|b",
        L"\\ReactOS Sec\\a<b", L"\\ReactOS Sec\\\\x", L"\\ReactOS Sec\\a\x01" L"b", L"",
    };
    static const WCHAR *good[] =
    {
        L"\\ReactOS Sec\\COM10", L"\\ReactOS Sec\\CONSOLE", L"\\ReactOS Sec\\a.b", L"\\ReactOS Sec\\.hidden",
        L"\\ReactOS Sec\\two  spaces", L"\\ReactOS Sec\\NULL", L"\\ReactOS Sec\\...x",
    };
    WCHAR xml[600], path[1024], *p, *tail = NULL;
    HRESULT hr;
    unsigned int i;

    far_xml(xml);
    if (!bind_local()) return;

    /* a task name does not end with a separator (a folder path may) */
    hr = register_task(FOLDER L"\\x\\", xml, TASK_CREATE);
    ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_NAME), "RegisterTask(trailing separator): 0x%lx\n", hr);

    for (i = 0; i < ARRAYSIZE(bad); i++)
    {
        hr = register_task(bad[i], xml, TASK_CREATE);
        ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_NAME), "RegisterTask(%ls): 0x%lx\n", bad[i], hr);
        if (bad[i][0])
        {
            hr = retrieve_task(bad[i], &tail);
            ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_NAME), "RetrieveTask(%ls): 0x%lx\n", bad[i], hr);
            hr = delete_task(bad[i]);
            ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_NAME) || hr == E_ACCESSDENIED, "Delete(%ls): 0x%lx\n", bad[i], hr);
        }
    }
    ok(!file_exists(L"\\..\\escape") && !file_exists(L"\\ReactOS Sec\\dot") && !file_exists(L"\\ReactOS Sec\\space"),
       "a refused task was created\n");

    /* too long: a path, a component, too deep */
    wcscpy(path, FOLDER L"\\");
    for (p = path + wcslen(path), i = 0; i < 300; i++) *p++ = 'a';
    *p = 0;
    hr = register_task(path, xml, TASK_CREATE);
    ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_NAME), "RegisterTask(300 characters): 0x%lx\n", hr);
    wcscpy(path, L"\\");
    for (p = path + 1, i = 0; i < 256; i++) *p++ = 'b';
    *p = 0;
    hr = register_task(path, xml, TASK_CREATE);
    ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_NAME), "RegisterTask(a component of 256 characters): 0x%lx\n", hr);
    wcscpy(path, L"\\d1\\d2\\d3\\d4\\d5\\d6\\d7\\d8\\d9\\d10\\d11\\d12\\d13\\d14\\d15\\d16\\d17\\task");
    hr = register_task(path, xml, TASK_CREATE);
    ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_NAME), "RegisterTask(17 components): 0x%lx\n", hr);
    ok(!file_exists(L"\\d1"), "the folders of a refused task were created\n");

    /* folders, enumeration and Run take the same names */
    RPC_CALL(SchRpcCreateFolder(L"\\ReactOS Sec\\..\\x", NULL, 0));
    ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_NAME), "CreateFolder(..): 0x%lx\n", hr);
    RPC_CALL(SchRpcCreateFolder(L"\\NUL", NULL, 0));
    ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_NAME), "CreateFolder(NUL): 0x%lx\n", hr);
    hr = run_task(L"\\ReactOS Sec\\..\\x");
    ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_NAME), "Run(..): 0x%lx\n", hr);

    for (i = 0; i < ARRAYSIZE(good); i++)
    {
        hr = register_task(good[i], xml, TASK_CREATE);
        ok(hr == S_OK, "RegisterTask(%ls): 0x%lx\n", good[i], hr);
        if (hr == S_OK)
        {
            hr = delete_task(good[i]);
            ok(hr == S_OK, "DeleteTask(%ls): 0x%lx\n", good[i], hr);
        }
    }

    /* '/' and '\' mixed: one folder, and the task is where it was asked for */
    hr = register_task(FOLDER L"/mixed\\task", xml, TASK_CREATE);
    ok(hr == S_OK, "RegisterTask(mixed separators): 0x%lx\n", hr);
    ok(file_exists(L"\\ReactOS Sec\\mixed\\task"), "the mixed separator task is not in its folder\n");
    hr = retrieve_task(FOLDER L"\\mixed/task", &tail);
    ok(hr == S_OK && tail, "RetrieveTask(mixed): 0x%lx\n", hr);
    free(tail);
    hr = delete_task(FOLDER L"\\mixed\\task");
    ok(hr == S_OK, "DeleteTask(mixed): 0x%lx\n", hr);
    hr = delete_task(FOLDER L"\\mixed");
    ok(hr == S_OK, "DeleteTask(folder): 0x%lx\n", hr);
}

/* ---- XML size, update, Run -------------------------------------------------------------- */

static WCHAR *padded_xml(unsigned int chars)
{
    WCHAR *xml = malloc((chars + 1024) * sizeof(WCHAR)), *p;
    unsigned int i;

    far_xml(xml);
    /* the comment goes inside the root element */
    p = wcsstr(xml, L"<Triggers>");
    memmove(p + chars + 9, p, (wcslen(p) + 1) * sizeof(WCHAR));
    memcpy(p, L"<!-- ", 5 * sizeof(WCHAR));
    for (i = 0; i < chars; i++) p[5 + i] = 'P';
    memcpy(p + 5 + chars, L" -->", 4 * sizeof(WCHAR));
    /* something to read after the comment: the task is disabled */
    p = wcsstr(xml, L"<Actions>");
    memmove(p + 45, p, (wcslen(p) + 1) * sizeof(WCHAR));
    memcpy(p, L"<Settings><Enabled>false</Enabled></Settings>", 45 * sizeof(WCHAR));
    return xml;
}

static void test_xml_size(void)
{
    WCHAR *xml, *got = NULL;
    DWORD pid = schedule_pid();
    HRESULT hr;

    if (!bind_local()) return;

    xml = padded_xml(40000);
    hr = register_task(FOLDER L"\\Huge", xml, TASK_CREATE);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE), "RegisterTask(80 KB): 0x%lx\n", hr);
    ok(!file_exists(L"\\ReactOS Sec\\Huge"), "the oversized task was stored\n");
    free(xml);

    xml = padded_xml(1000000);
    hr = register_task(FOLDER L"\\Huge", xml, TASK_CREATE);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE), "RegisterTask(2 MB): 0x%lx\n", hr);
    free(xml);

    /* a big task below the limit still works; an update that is shorter leaves nothing of the old file */
    xml = padded_xml(30000);
    hr = register_task(FOLDER L"\\Big", xml, TASK_CREATE);
    ok(hr == S_OK, "RegisterTask(60 KB): 0x%lx\n", hr);
    free(xml);
    hr = retrieve_task(FOLDER L"\\Big", &got);
    ok(hr == S_OK && got && wcslen(got) > 30000, "RetrieveTask(big): 0x%lx\n", hr);
    free(got);

    /* the service reads a setting that follows the long comment (xmllite read a stale buffer there) */
    {
        DWORD enabled = 1, state = 0;

        RPC_CALL(SchRpcGetTaskInfo(FOLDER L"\\Big", SCH_FLAG_STATE, &enabled, &state));
        ok(hr == S_OK && !enabled && state == TASK_STATE_DISABLED, "GetTaskInfo(Big): 0x%lx, enabled %lu, state %lu\n",
           hr, enabled, state);
    }

    /* the service parses it in the background (xmllite once read a stale buffer past a long comment) */
    Sleep(4000);
    ok(schedule_pid() == pid, "the Schedule service was %lu and is now %lu after a long comment\n", pid, schedule_pid());

    far_xml((xml = malloc(1200)));
    hr = register_task(FOLDER L"\\Big", xml, TASK_UPDATE);
    ok(hr == S_OK, "update to a short XML: 0x%lx\n", hr);
    free(xml);
    hr = retrieve_task(FOLDER L"\\Big", &got);
    ok(hr == S_OK && got && wcslen(got) < 2000 && !wcsstr(got, L"PPPPP"), "the update left old data: 0x%lx, %u characters\n",
       hr, got ? (unsigned)wcslen(got) : 0);
    ok(got && wcsstr(got, L"</Task>") && !wcsstr(wcsstr(got, L"</Task>") + 7, L"<"), "garbage after </Task>\n");
    free(got);
    hr = delete_task(FOLDER L"\\Big");
    ok(hr == S_OK, "DeleteTask(Big): 0x%lx\n", hr);
}

/* a task the service cannot read is refused, and a refused or update-only call leaves no folder behind */
static void test_registration_failures(void)
{
    WCHAR xml[600];
    HRESULT hr;
    static const WCHAR *broken[] = { L"<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions>",
                                     L"not xml at all", L"<Other><Actions/></Other>", L"" };
    unsigned int i;

    if (!bind_local()) return;
    for (i = 0; i < ARRAYSIZE(broken); i++)
    {
        hr = register_task(FOLDER L"\\NewFolder\\Broken", broken[i], TASK_CREATE);
        ok(hr == SCHED_E_MALFORMEDXML, "RegisterTask(broken XML %u): 0x%lx\n", i, hr);
    }
    ok(!file_exists(L"\\ReactOS Sec\\NewFolder"), "a refused XML created its folder\n");

    far_xml(xml);
    hr = register_task(FOLDER L"\\NewFolder\\Update", xml, TASK_UPDATE);
    ok(FAILED(hr), "an update of a task that is not there succeeded: 0x%lx\n", hr);
    ok(!file_exists(L"\\ReactOS Sec\\NewFolder"), "an update created a folder\n");

    hr = register_task(FOLDER L"\\NewFolder\\Sub\\Task", xml, TASK_CREATE);
    ok(hr == S_OK, "RegisterTask(two new folders): 0x%lx\n", hr);
    ok(file_exists(L"\\ReactOS Sec\\NewFolder\\Sub\\Task"), "the task is not in its folders\n");
    delete_task(FOLDER L"\\NewFolder\\Sub\\Task");
    delete_task(FOLDER L"\\NewFolder\\Sub");
    hr = delete_task(FOLDER L"\\NewFolder");
    ok(hr == S_OK, "DeleteTask(NewFolder): 0x%lx\n", hr);
}

static void test_run_overlap(void)
{
    static const WCHAR long_actions[] =
        L"<Actions><Exec><Command>cmd.exe</Command><Arguments>/c ping -n 12 127.0.0.1 &gt; nul</Arguments></Exec></Actions></Task>";
    WCHAR xml[800];
    HRESULT hr;

    if (!bind_local()) return;
    _snwprintf(xml, 800, L"%s<Triggers><TimeTrigger><StartBoundary>2099-01-01T00:00:00</StartBoundary>"
             L"</TimeTrigger></Triggers>%s", xml_head, long_actions);
    hr = register_task(FOLDER L"\\Overlap", xml, TASK_CREATE);
    ok(hr == S_OK, "RegisterTask(Overlap): 0x%lx\n", hr);
    hr = run_task(FOLDER L"\\Overlap");
    ok(hr == S_OK, "Run: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        hr = run_task(FOLDER L"\\Overlap");
        ok(hr == SCHED_E_ALREADY_RUNNING, "Run while it still runs: 0x%lx\n", hr);
    }
    hr = delete_task(FOLDER L"\\Overlap");
    ok(hr == S_OK, "DeleteTask(Overlap): 0x%lx\n", hr);
}

/* ---- a DaysInterval that wrapped the period to zero must not take the service down ---------- */

static void test_survives_overflow(void)
{
    static const struct { const WCHAR *name; const WCHAR *trigger; } cases[] =
    {
        { L"Days1", L"<CalendarTrigger><StartBoundary>2020-01-01T00:00:00Z</StartBoundary>"
                    L"<ScheduleByDay><DaysInterval>33554432</DaysInterval></ScheduleByDay></CalendarTrigger>" },
        { L"Days2", L"<CalendarTrigger><StartBoundary>2020-01-01T00:00:00Z</StartBoundary>"
                    L"<ScheduleByDay><DaysInterval>67108864</DaysInterval></ScheduleByDay></CalendarTrigger>" },
        { L"Days3", L"<CalendarTrigger><StartBoundary>2020-01-01T00:00:00Z</StartBoundary>"
                    L"<ScheduleByDay><DaysInterval>2147483647</DaysInterval></ScheduleByDay></CalendarTrigger>" },
        { L"Days4", L"<CalendarTrigger><StartBoundary>2020-01-01T00:00:00Z</StartBoundary>"
                    L"<ScheduleByDay><DaysInterval>99999999999999999999</DaysInterval></ScheduleByDay></CalendarTrigger>" },
        { L"Rep1", L"<TimeTrigger><StartBoundary>2020-01-01T00:00:00Z</StartBoundary><Repetition>"
                   L"<Interval>P99999999999D</Interval><Duration>P99999999999D</Duration></Repetition></TimeTrigger>" },
        { L"Rep2", L"<TimeTrigger><StartBoundary>2020-01-01T00:00:00Z</StartBoundary><Repetition>"
                   L"<Interval>PT0S</Interval><Duration>PT0S</Duration></Repetition></TimeTrigger>" },
        { L"Rep3", L"<TimeTrigger><StartBoundary>2020-01-01T00:00:00Z</StartBoundary><Repetition>"
                   L"<Interval>P-1D</Interval><Duration>PT1S</Duration></Repetition></TimeTrigger>" },
    };
    WCHAR xml[1200], path[100], *got = NULL;
    DWORD pid, now;
    HRESULT hr;
    unsigned int i;

    pid = schedule_pid();
    ok(pid != 0, "the Schedule service is not running\n");
    if (!bind_local()) return;

    for (i = 0; i < ARRAYSIZE(cases); i++)
    {
        /* a start in the past, so that the next run is worked out; no action that could run it */
        _snwprintf(xml, 1200, L"%s<Triggers>%s</Triggers><Actions><Exec><Command>cmd.exe</Command>"
                 L"<Arguments>/c exit</Arguments></Exec></Actions></Task>", xml_head, cases[i].trigger);
        _snwprintf(path, 100, FOLDER L"\\%s", cases[i].name);
        hr = register_task(path, xml, TASK_CREATE_OR_UPDATE);
        ok(hr == S_OK, "RegisterTask(%ls): 0x%lx\n", cases[i].name, hr);
    }

    /* the service loads the new tasks at once; a crash would show within a few seconds */
    Sleep(6000);
    now = schedule_pid();
    ok(now == pid, "the Schedule service was %lu and is now %lu\n", pid, now);
    hr = retrieve_task(FOLDER L"\\Days1", &got);
    ok(hr == S_OK && got, "the service does not answer: 0x%lx\n", hr);
    free(got);

    for (i = 0; i < ARRAYSIZE(cases); i++)
    {
        _snwprintf(path, 100, FOLDER L"\\%s", cases[i].name);
        hr = delete_task(path);
        ok(hr == S_OK, "DeleteTask(%ls): 0x%lx\n", cases[i].name, hr);
    }
    Sleep(1000);
    ok(schedule_pid() == pid, "the Schedule service restarted\n");
}

/* ---- callers that are not local ----------------------------------------------------------- */

static void test_not_local(void)
{
    WCHAR xml[600];
    DWORD version = 0;
    HRESULT hr;

    far_xml(xml);

    /* control: ncalrpc */
    if (!bind_local()) return;
    RPC_CALL(SchRpcHighestVersion(&version));
    ok(hr == S_OK && version, "HighestVersion over ncalrpc: 0x%lx, %#lx\n", hr, version);

    /* the interface is also reachable on the at service's named pipe: refused there */
    if (!bind_to(L"ncacn_np", L"\\pipe\\atsvc")) return;
    RPC_CALL(SchRpcHighestVersion(&version));
    ok(hr == E_ACCESSDENIED, "HighestVersion over ncacn_np: 0x%lx\n", hr);
    hr = register_task(FOLDER L"\\Remote", xml, TASK_CREATE);
    ok(hr == E_ACCESSDENIED, "RegisterTask over ncacn_np: 0x%lx\n", hr);
    ok(!file_exists(L"\\ReactOS Sec\\Remote"), "a task came in over ncacn_np\n");
    hr = delete_task(FOLDER L"\\Remote");
    ok(hr == E_ACCESSDENIED, "DeleteTask over ncacn_np: 0x%lx\n", hr);
    hr = run_task(FOLDER L"\\Remote");
    ok(hr == E_ACCESSDENIED, "Run over ncacn_np: 0x%lx\n", hr);
    {
        WCHAR *got = NULL;
        DWORD start = 0, count = 0;
        TASK_NAMES names = NULL;

        hr = retrieve_task(FOLDER L"\\Remote", &got);
        ok(hr == E_ACCESSDENIED && !got, "RetrieveTask over ncacn_np: 0x%lx\n", hr);
        RPC_CALL(SchRpcEnumTasks(L"\\", 0, &start, 0, &count, &names));
        ok(hr == E_ACCESSDENIED && !count && !names, "EnumTasks over ncacn_np: 0x%lx, %lu names\n", hr, count);
        start = 0;
        RPC_CALL(SchRpcEnumFolders(L"\\", 0, &start, 0, &count, &names));
        ok(hr == E_ACCESSDENIED && !count && !names, "EnumFolders over ncacn_np: 0x%lx, %lu names\n", hr, count);
        RPC_CALL(SchRpcCreateFolder(FOLDER L"\\RemoteFolder", NULL, 0));
        ok(hr == E_ACCESSDENIED, "CreateFolder over ncacn_np: 0x%lx\n", hr);
        ok(!file_exists(L"\\ReactOS Sec\\RemoteFolder"), "a folder came in over ncacn_np\n");
    }

    /* and it still works locally */
    if (!bind_local()) return;
    RPC_CALL(SchRpcHighestVersion(&version));
    ok(hr == S_OK, "HighestVersion over ncalrpc again: 0x%lx\n", hr);
}

/* ---- two users ---------------------------------------------------------------------------- */

static char **main_argv;
static int main_argc;

typedef struct _NET_CALL
{
    BOOL Add;
    PWSTR Name;
    NET_API_STATUS Status;
} NET_CALL;

static DWORD WINAPI net_call_thread(PVOID param)
{
    NET_CALL *call = param;
    USER_INFO_1 info;
    DWORD err;

    if (!call->Add)
    {
        call->Status = NetUserDel(NULL, call->Name);
        return 0;
    }
    memset(&info, 0, sizeof(info));
    info.usri1_name = call->Name;
    info.usri1_password = (PWSTR)PASSWORD;
    info.usri1_priv = USER_PRIV_USER;
    info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    call->Status = NetUserAdd(NULL, 1, (PBYTE)&info, &err);
    return 0;
}

/* a SAM call that does not return is a failure; the call must outlive a thread that does not return */
static BOOL timed_net_call(NET_CALL *call)
{
    HANDLE thread = CreateThread(NULL, 0, net_call_thread, call, 0, NULL);
    DWORD wait;

    ok(thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!thread) return FALSE;
    wait = WaitForSingleObject(thread, 120000);
    CloseHandle(thread);
    ok(wait == WAIT_OBJECT_0, "the user call did not return: %lu\n", wait);
    return wait == WAIT_OBJECT_0;
}

static BOOL create_user(NET_CALL *call, WCHAR *name, const WCHAR *prefix, DWORD salt)
{
    _snwprintf(name, 32, L"%s%lx", prefix, (GetTickCount() + salt) & 0xffffff);
    call->Add = TRUE;
    call->Name = name;
    if (!timed_net_call(call)) return FALSE;
    if (call->Status == ERROR_ACCESS_DENIED)
    {
        skip("NetUserAdd needs an elevated administrator\n");
        return FALSE;
    }
    ok(call->Status == NERR_Success, "NetUserAdd(%ls) failed: %lu\n", name, call->Status);
    return call->Status == NERR_Success;
}

static HRESULT as_user_ex(char **argv, const char *op, const WCHAR *user, const char *name, int count, DWORD flags,
                          const char *extra);

/*
 * The users are left in place unless TASKSCHD_TEST_DELETE_USERS is set: NetUserDel fails on this system for
 * a user that logged on (SAM: no Members key) and heap errors follow in the processes around it.
 */
static void delete_user(const WCHAR *name)
{
    if (getenv("TASKSCHD_TEST_DELETE_USERS"))
    {
        HRESULT status = as_user_ex(main_argv, "deluser", name, "-", 0, 0, "");

        if (status != NERR_Success) trace("NetUserDel(%ls) failed: %lu\n", name, (DWORD)status);
    }
}

/* the child: log the user on, impersonate it, make one kind of call, exit with its HRESULT or count */
static void child_main(int argc, char **argv)
{
    WCHAR user[64], name[256], path[300], xml[600];
    HANDLE token;
    const char *op = argv[3];
    HRESULT hr = E_FAIL;
    int i, n = 0, count = atoi(argv[6]);
    DWORD flags = atoi(argv[7]);
    WCHAR *got = NULL;

    MultiByteToWideChar(CP_ACP, 0, argv[4], -1, user, ARRAYSIZE(user));
    MultiByteToWideChar(CP_ACP, 0, argv[5], -1, name, ARRAYSIZE(name));
    if (!strcmp(op, "deluser"))
        ExitProcess(NetUserDel(NULL, user));
    if (!LogonUserW(user, L".", PASSWORD, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token))
        ExitProcess(0x10000000 | GetLastError());
    if (!ImpersonateLoggedOnUser(token))
        ExitProcess(0x20000000 | GetLastError());
    if (!bind_local())
        ExitProcess(0x30000000);

    far_xml(xml);
    _snwprintf(path, ARRAYSIZE(path), FOLDER L"\\%s", name);
    if (!strcmp(op, "regprin") && argc >= 11)
    {
        WCHAR principal[100], tag[50], start[50];

        MultiByteToWideChar(CP_ACP, 0, argv[8], -1, principal, ARRAYSIZE(principal));
        MultiByteToWideChar(CP_ACP, 0, argv[9], -1, tag, ARRAYSIZE(tag));
        MultiByteToWideChar(CP_ACP, 0, argv[10], -1, start, ARRAYSIZE(start));
        prin_xml(xml, principal, tag, start);
        hr = register_task(path, xml, TASK_CREATE);
    }
    else if (!strcmp(op, "connect"))
    {
        /* what schtasks.exe and every scheduler client does first: ITaskService::Connect as this user */
        ITaskService *service = NULL;
        VARIANT empty;

        VariantInit(&empty);
        hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (SUCCEEDED(hr))
        {
            hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void **)&service);
            if (hr == S_OK)
            {
                hr = ITaskService_Connect(service, empty, empty, empty, empty);
                ITaskService_Release(service);
            }
            CoUninitialize();
        }
    }
    else if (!strcmp(op, "folders"))
    {
        for (i = 0; i < count; i++)
        {
            _snwprintf(path, ARRAYSIZE(path), FOLDER L"\\%s%d", name, i);
            RPC_CALL(SchRpcCreateFolder(path, NULL, 0));
            if (hr == S_OK) n++;
        }
        hr = n;
    }
    else if (!strcmp(op, "register"))
        hr = register_task(path, xml, flags);
    else if (!strcmp(op, "delete"))
        hr = delete_task(path);
    else if (!strcmp(op, "retrieve"))
    {
        hr = retrieve_task(path, &got);
        free(got);
    }
    else if (!strcmp(op, "run"))
        hr = run_task(path);
    else if (!strcmp(op, "many"))
    {
        for (i = 0; i < count; i++)
        {
            _snwprintf(path, ARRAYSIZE(path), FOLDER L"\\%s%d", name, i);
            if (register_task(path, xml, TASK_CREATE) == S_OK) n++;
        }
        hr = n;
    }
    RevertToSelf();
    ExitProcess(hr);
}

/*
 * The program that runs as the other user. LogonUser fails in a 32-bit process under WoW64
 * (ERROR_INVALID_FUNCTION), so a 32-bit test lets the 64-bit program of the same name do it.
 */
static const char *child_exe(const char *self)
{
    static char native[MAX_PATH];
    BOOL (WINAPI *pIsWow64Process)(HANDLE, BOOL *);
    BOOL wow64 = FALSE;

    pIsWow64Process = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
    if (!pIsWow64Process || !pIsWow64Process(GetCurrentProcess(), &wow64) || !wow64) return self;
    if (!GetEnvironmentVariableA("SystemRoot", native, sizeof(native))) return self;
    strcat(native, "\\bin\\taskschd_apitest.exe");
    return native;
}

static HRESULT as_user_ex(char **argv, const char *op, const WCHAR *user, const char *name, int count, DWORD flags,
                          const char *extra)
{
    char cmd[MAX_PATH + 300], userA[64];
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD code = 0xffffffff, wait;

    WideCharToMultiByte(CP_ACP, 0, user, -1, userA, sizeof(userA), NULL, NULL);
    snprintf(cmd, sizeof(cmd), "\"%s\" TaskSchedulerSecurity child %s %s %s %d %lu %s", child_exe(argv[0]), op, userA, name,
             count, flags, extra);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        ok(0, "CreateProcess(%s) failed: %lu\n", cmd, GetLastError());
        return E_FAIL;
    }
    CloseHandle(pi.hThread);
    wait = WaitForSingleObject(pi.hProcess, 300000);
    ok(wait == WAIT_OBJECT_0, "the child did not finish: %lu\n", wait);
    if (wait != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 1);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return code;
}

static HRESULT as_user(char **argv, const char *op, const WCHAR *user, const char *name, int count, DWORD flags)
{
    return as_user_ex(argv, op, user, name, count, flags, "");
}

static void test_users(char **argv)
{
    static WCHAR alice[32], bob[32];
    static NET_CALL alice_call, bob_call;
    WCHAR xml[600];
    HRESULT hr;
    WCHAR *got = NULL;
    int i, made;

    if (!create_user(&alice_call, alice, L"tsA", 0)) return;
    if (!create_user(&bob_call, bob, L"tsB", 7919))
    {
        delete_user(alice);
        return;
    }

    far_xml(xml);
    if (!bind_local()) goto done;

    /* alice registers her task; the child must really run as her */
    hr = as_user(argv, "register", alice, "Alice", 0, TASK_CREATE);
    ok(hr == S_OK, "alice: RegisterTask: 0x%lx\n", hr);
    if (hr != S_OK) goto done;
    ok(file_exists(L"\\ReactOS Sec\\Alice"), "alice's task file is missing\n");

    /* bob cannot replace, create over, read, run or delete it */
    hr = as_user(argv, "register", bob, "Alice", 0, TASK_UPDATE);
    ok(hr == E_ACCESSDENIED, "bob: update of alice's task: 0x%lx\n", hr);
    hr = as_user(argv, "register", bob, "Alice", 0, TASK_CREATE_OR_UPDATE);
    ok(hr == E_ACCESSDENIED, "bob: create-or-update of alice's task: 0x%lx\n", hr);
    hr = as_user(argv, "register", bob, "Alice", 0, TASK_CREATE);
    ok(hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), "bob: create over alice's task: 0x%lx\n", hr);
    hr = as_user(argv, "retrieve", bob, "Alice", 0, 0);
    ok(hr == E_ACCESSDENIED, "bob: RetrieveTask of alice's task: 0x%lx\n", hr);
    hr = as_user(argv, "run", bob, "Alice", 0, 0);
    ok(hr == E_ACCESSDENIED, "bob: Run of alice's task: 0x%lx\n", hr);
    hr = as_user(argv, "delete", bob, "Alice", 0, 0);
    ok(hr == E_ACCESSDENIED, "bob: DeleteTask of alice's task: 0x%lx\n", hr);
    ok(file_exists(L"\\ReactOS Sec\\Alice"), "bob removed alice's task\n");

    /* her task is unchanged (still the far trigger) */
    hr = retrieve_task(FOLDER L"\\Alice", &got);
    ok(hr == S_OK && got && wcsstr(got, L"2099-01-01"), "alice's task changed: 0x%lx\n", hr);
    free(got);

    /* alice can */
    hr = as_user(argv, "retrieve", alice, "Alice", 0, 0);
    ok(hr == S_OK, "alice: RetrieveTask: 0x%lx\n", hr);
    hr = as_user(argv, "register", alice, "Alice", 0, TASK_UPDATE);
    ok(hr == S_OK, "alice: update of her own task: 0x%lx\n", hr);

    /* an administrator can, and then it is the administrator's */
    hr = register_task(FOLDER L"\\Alice", xml, TASK_UPDATE);
    ok(hr == S_OK, "administrator: update of alice's task: 0x%lx\n", hr);
    hr = as_user(argv, "delete", alice, "Alice", 0, 0);
    ok(hr == E_ACCESSDENIED, "alice: delete of a task an administrator took over: 0x%lx\n", hr);
    hr = delete_task(FOLDER L"\\Alice");
    ok(hr == S_OK, "administrator: DeleteTask: 0x%lx\n", hr);
    ok(!file_exists(L"\\ReactOS Sec\\Alice"), "alice's task is still there\n");

    /* a task of her own goes away by her hand */
    hr = as_user(argv, "register", alice, "Own", 0, TASK_CREATE);
    ok(hr == S_OK, "alice: RegisterTask(Own): 0x%lx\n", hr);
    hr = as_user(argv, "delete", alice, "Own", 0, 0);
    ok(hr == S_OK, "alice: DeleteTask(Own): 0x%lx\n", hr);
    hr = as_user(argv, "delete", alice, "Own", 0, 0);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND),
       "alice: DeleteTask of a task that is gone: 0x%lx\n", hr);

    /* the number of tasks of one user is limited; bob is not affected */
    made = as_user(argv, "many", alice, "Q", TASKS_PER_USER + 10, 0);
    ok(made == TASKS_PER_USER, "alice registered %d tasks, the limit is %d\n", made, TASKS_PER_USER);
    hr = as_user(argv, "register", bob, "Bob", 0, TASK_CREATE);
    ok(hr == S_OK, "bob: RegisterTask after alice reached her limit: 0x%lx\n", hr);
    hr = as_user(argv, "register", alice, "Q0", 0, TASK_UPDATE);
    ok(hr == S_OK, "alice: update at her limit: 0x%lx\n", hr);
    for (i = 0; i < TASKS_PER_USER + 10; i++)
    {
        WCHAR path[100];

        _snwprintf(path, 100, FOLDER L"\\Q%d", i);
        delete_task(path);
    }
    hr = delete_task(FOLDER L"\\Bob");
    ok(hr == S_OK, "administrator: DeleteTask(Bob): 0x%lx\n", hr);

    /* so is the number of folders */
    made = as_user(argv, "folders", alice, "F", FOLDERS_PER_USER + 8, 0);
    ok(made == FOLDERS_PER_USER, "alice created %d folders, the limit is %d\n", made, FOLDERS_PER_USER);
    made = as_user(argv, "folders", bob, "G", 1, 0);
    ok(made == 1, "bob created %d folders after alice reached her limit\n", made);
    for (i = 0; i < FOLDERS_PER_USER + 8; i++)
    {
        WCHAR path[100];

        _snwprintf(path, 100, FOLDER L"\\F%d", i);
        delete_task(path);
    }
    delete_task(FOLDER L"\\G0");
    ok(!file_exists(L"\\ReactOS Sec\\F0"), "an alice folder is still there\n");

done:
    delete_user(alice);
    delete_user(bob);
}

/* A standard user connects to the scheduler: the Schedule service is running, and a standard user may query it
 * but not start it, so the connection must not depend on the right to start */
static void test_standard_user_connect(char **argv)
{
    static WCHAR dave[32];
    static NET_CALL dave_call;
    HRESULT hr;

    if (!create_user(&dave_call, dave, L"tsD", 104729)) return;

    hr = as_user(argv, "connect", dave, "-", 0, 0);
    ok(hr == S_OK, "standard user: ITaskService::Connect: 0x%lx\n", hr);

    delete_user(dave);
}

/* the SID of an account, or NULL */
static PSID account_sid(const WCHAR *name)
{
    DWORD size = 0, domain_size = 0;
    SID_NAME_USE use;
    PSID sid;

    LookupAccountNameW(NULL, name, NULL, &size, NULL, &domain_size, &use);
    if (!size || !(sid = malloc(size))) return NULL;
    domain_size = 256;
    {
        WCHAR *domain = malloc(domain_size * sizeof(WCHAR));
        BOOL ret = LookupAccountNameW(NULL, name, sid, &size, domain, &domain_size, &use);

        free(domain);
        if (ret) return sid;
    }
    free(sid);
    return NULL;
}

static NET_API_STATUS admins_member(PSID sid, BOOL add)
{
    BYTE admins[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(admins), glen = 256, dlen = 256;
    WCHAR group[256], domain[256];
    SID_NAME_USE use;
    LOCALGROUP_MEMBERS_INFO_0 member;

    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admins, &size);
    if (!LookupAccountSidW(NULL, admins, group, &glen, domain, &dlen, &use)) return GetLastError();
    member.lgrmi0_sid = sid;
    return add ? NetLocalGroupAddMembers(NULL, group, 0, (BYTE *)&member, 1)
               : NetLocalGroupDelMembers(NULL, group, 0, (BYTE *)&member, 1);
}

/*
 * Nobody makes the service run a task as an account that is not theirs unless they are an administrator
 * right now. Markers (C:\ts_<tag>.txt) show what ran at the start time of the tasks.
 */
static void test_principals(char **argv)
{
    static WCHAR pat[32], carol[32], self[100];
    static NET_CALL pat_call, carol_call;
    static const WCHAR *never[] = { L"patsys", L"patadm", L"carsys", L"caradm" };
    static const WCHAR *always[] = { L"ctlsys", L"ctladm" };
    char principal[120], extra[300], startA[50];
    WCHAR xml[1500], start[50];
    SYSTEMTIME st;
    FILETIME ft;
    ULARGE_INTEGER t;
    DWORD len = ARRAYSIZE(self), wait;
    PSID carol_sid;
    HRESULT hr;
    unsigned int i;

    GetUserNameW(self, &len);
    for (i = 0; i < ARRAYSIZE(never); i++) marker_delete(never[i]);
    for (i = 0; i < ARRAYSIZE(always); i++) marker_delete(always[i]);
    marker_delete(L"carrun");

    if (!create_user(&pat_call, pat, L"tsP", 0)) return;
    if (!create_user(&carol_call, carol, L"tsC", 7919))
    {
        delete_user(pat);
        return;
    }
    carol_sid = account_sid(carol);
    ok(carol_sid != NULL, "no SID for %ls\n", carol);
    if (!carol_sid || !bind_local()) goto done;

    hr = admins_member(carol_sid, TRUE);
    ok(hr == NERR_Success, "adding %ls to the administrators: %lu\n", carol, hr);
    if (hr != NERR_Success) goto done;

    /* every task fires 100 s from now */
    GetSystemTimeAsFileTime(&ft);
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    t.QuadPart += 100 * 10000000ULL;
    ft.dwLowDateTime = t.LowPart;
    ft.dwHighDateTime = t.HighPart;
    FileTimeToSystemTime(&ft, &st);
    _snwprintf(start, 50, L"%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    WideCharToMultiByte(CP_ACP, 0, start, -1, startA, sizeof(startA), NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, self, -1, principal, sizeof(principal), NULL, NULL);

    /* controls: an administrator's tasks, as LocalSystem and as the user that is logged on, run */
    prin_xml(xml, L"S-1-5-18", L"ctlsys", start);
    hr = register_task(FOLDER L"\\CtlSys", xml, TASK_CREATE);
    ok(hr == S_OK, "administrator: RegisterTask(CtlSys): 0x%lx\n", hr);
    prin_xml(xml, self, L"ctladm", start);
    hr = register_task(FOLDER L"\\CtlAdm", xml, TASK_CREATE);
    ok(hr == S_OK, "administrator: RegisterTask(CtlAdm): 0x%lx\n", hr);

    /* a user that is not an administrator: LocalSystem, and the user that is logged on */
    snprintf(extra, sizeof(extra), "S-1-5-18 patsys %s", startA);
    hr = as_user_ex(argv, "regprin", pat, "PatSys", 0, 0, extra);
    ok(hr == S_OK, "user: RegisterTask(PatSys): 0x%lx\n", hr);
    snprintf(extra, sizeof(extra), "%s patadm %s", principal, startA);
    hr = as_user_ex(argv, "regprin", pat, "PatAdm", 0, 0, extra);
    ok(hr == S_OK, "user: RegisterTask(PatAdm): 0x%lx\n", hr);
    hr = as_user(argv, "run", pat, "PatSys", 0, 0);
    ok(FAILED(hr), "user: Run of the LocalSystem task succeeded: 0x%lx\n", hr);
    hr = as_user(argv, "run", pat, "PatAdm", 0, 0);
    ok(FAILED(hr), "user: Run of the task of another account succeeded: 0x%lx\n", hr);

    /* an administrator, who registers the same two kinds and is then demoted */
    snprintf(extra, sizeof(extra), "S-1-5-18 carsys %s", startA);
    hr = as_user_ex(argv, "regprin", carol, "CarSys", 0, 0, extra);
    ok(hr == S_OK, "administrator: RegisterTask(CarSys): 0x%lx\n", hr);
    snprintf(extra, sizeof(extra), "%s caradm %s", principal, startA);
    hr = as_user_ex(argv, "regprin", carol, "CarAdm", 0, 0, extra);
    ok(hr == S_OK, "administrator: RegisterTask(CarAdm): 0x%lx\n", hr);
    hr = as_user(argv, "run", carol, "CarSys", 0, 0);
    ok(hr == S_OK, "administrator: Run of her LocalSystem task: 0x%lx\n", hr);
    for (wait = 0; wait < 20 && !marker_exists(L"carsys"); wait++) Sleep(1000);
    ok(marker_exists(L"carsys"), "the LocalSystem task of an administrator did not run\n");
    marker_delete(L"carsys");

    hr = admins_member(carol_sid, FALSE);
    ok(hr == NERR_Success, "removing %ls from the administrators: %lu\n", carol, hr);
    hr = as_user(argv, "run", carol, "CarSys", 0, 0);
    ok(FAILED(hr), "demoted: Run of the LocalSystem task succeeded: 0x%lx\n", hr);
    hr = as_user(argv, "run", carol, "CarAdm", 0, 0);
    ok(FAILED(hr), "demoted: Run of the task of another account succeeded: 0x%lx\n", hr);

    /* the start time and a margin for the tasks to run */
    GetSystemTimeAsFileTime(&ft);
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    {
        ULARGE_INTEGER end;
        SystemTimeToFileTime(&st, &ft);
        end.LowPart = ft.dwLowDateTime;
        end.HighPart = ft.dwHighDateTime;
        end.QuadPart += 25 * 10000000ULL;
        if (end.QuadPart > t.QuadPart) Sleep((DWORD)((end.QuadPart - t.QuadPart) / 10000));
    }

    for (i = 0; i < ARRAYSIZE(always); i++)
        ok(marker_exists(always[i]), "the task %ls of an administrator did not run\n", always[i]);
    for (i = 0; i < ARRAYSIZE(never); i++)
        ok(!marker_exists(never[i]), "the task %ls ran as an account that is not its registrant's\n", never[i]);

    delete_task(FOLDER L"\\CtlSys");
    delete_task(FOLDER L"\\CtlAdm");
    delete_task(FOLDER L"\\PatSys");
    delete_task(FOLDER L"\\PatAdm");
    delete_task(FOLDER L"\\CarSys");
    delete_task(FOLDER L"\\CarAdm");
    for (i = 0; i < ARRAYSIZE(never); i++) marker_delete(never[i]);
    for (i = 0; i < ARRAYSIZE(always); i++) marker_delete(always[i]);

done:
    if (carol_sid)
    {
        admins_member(carol_sid, FALSE);
        free(carol_sid);
    }
    delete_user(pat);
    delete_user(carol);
}

static BOOL section(const char *name)
{
    return main_argc < 3 || !strcmp(main_argv[2], name);
}

START_TEST(TaskSchedulerSecurity)
{
    char **argv;
    HRESULT hr;
    int argc = winetest_get_mainargs(&argv);

    main_argc = argc;
    main_argv = argv;

    if (argc >= 8)
    {
        child_main(argc, argv);
        return;
    }

    if (!bind_local()) return;
    RPC_CALL(SchRpcCreateFolder(FOLDER, NULL, 0));
    ok(hr == S_OK || hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), "CreateFolder: 0x%lx\n", hr);
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
    {
        skip("no Task Scheduler\n");
        return;
    }

    /* "TaskSchedulerSecurity <name>" runs one part only */
    if (section("paths")) test_paths();
    if (section("xml")) test_xml_size();
    if (section("failures")) test_registration_failures();
    if (section("overlap")) test_run_overlap();
    if (section("local")) test_not_local();
    if (section("overflow")) test_survives_overflow();
    if (section("connect")) test_standard_user_connect(argv);
    if (section("users")) test_users(argv);
    if (section("principals")) test_principals(argv);

    if (bind_local())
    {
        RPC_CALL(SchRpcDelete(FOLDER, 0));
        ok(hr == S_OK, "DeleteFolder: 0x%lx\n", hr);
    }
}
