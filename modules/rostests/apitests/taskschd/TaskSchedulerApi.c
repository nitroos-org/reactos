/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Task Scheduler 2.0 through ITaskService: register, enumerate, get, run on demand,
 *              enable and disable, stop, delete; the registry copy of the task store
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
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
#include <ntsecapi.h>
#include <stdio.h>

#define API_FOLDER L"\\ReactOS ApiTest Api"
#define API_FOLDER_NAME L"ReactOS ApiTest Api"
#define TASKCACHE_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"
#define WAIT_MS 60000

static ITaskService *service;
static ITaskFolder *folder;
static WCHAR marker_dir[MAX_PATH];
static WCHAR test_exe[MAX_PATH];

static BOOL file_exists(const WCHAR *path)
{
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static BOOL wait_for_file(const WCHAR *path, DWORD timeout)
{
    DWORD start = GetTickCount();

    while (!file_exists(path))
    {
        if (GetTickCount() - start > timeout) return FALSE;
        Sleep(250);
    }
    return TRUE;
}

/* "YYYY-MM-DDTHH:MM:SS" for now + seconds, local time */
static void boundary(int seconds, WCHAR *str)
{
    FILETIME ft, local;
    ULARGE_INTEGER t;
    SYSTEMTIME st;

    GetSystemTimeAsFileTime(&ft);
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    t.QuadPart += (LONGLONG)seconds * 10000000;
    ft.dwLowDateTime = t.LowPart;
    ft.dwHighDateTime = t.HighPart;
    FileTimeToLocalFileTime(&ft, &local);
    FileTimeToSystemTime(&local, &st);
    _swprintf(str, L"%04u-%02u-%02uT%02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

/* a definition whose only action is cmd.exe /c echo > marker (or the sleeping child of this test), with a time trigger a month away */
static ITaskDefinition *new_definition(const WCHAR *program, const WCHAR *args, int trigger_seconds)
{
    ITaskDefinition *def = NULL;
    IActionCollection *actions = NULL;
    ITriggerCollection *triggers = NULL;
    ITrigger *trigger = NULL;
    IAction *action = NULL;
    IExecAction *exec = NULL;
    WCHAR start[64];
    HRESULT hr;

    hr = ITaskService_NewTask(service, 0, &def);
    ok(hr == S_OK, "NewTask failed: 0x%lx\n", hr);
    if (hr != S_OK) return NULL;

    hr = ITaskDefinition_get_Actions(def, &actions);
    ok(hr == S_OK, "get_Actions failed: 0x%lx\n", hr);
    hr = IActionCollection_Create(actions, TASK_ACTION_EXEC, &action);
    ok(hr == S_OK, "Create(TASK_ACTION_EXEC) failed: 0x%lx\n", hr);
    hr = IAction_QueryInterface(action, &IID_IExecAction, (void **)&exec);
    ok(hr == S_OK, "QueryInterface(IExecAction) failed: 0x%lx\n", hr);
    IExecAction_put_Path(exec, (BSTR)program);
    IExecAction_put_Arguments(exec, (BSTR)args);
    IExecAction_Release(exec);
    IAction_Release(action);
    IActionCollection_Release(actions);

    hr = ITaskDefinition_get_Triggers(def, &triggers);
    ok(hr == S_OK, "get_Triggers failed: 0x%lx\n", hr);
    hr = ITriggerCollection_Create(triggers, TASK_TRIGGER_TIME, &trigger);
    ok(hr == S_OK, "Create(TASK_TRIGGER_TIME) failed: 0x%lx\n", hr);
    boundary(trigger_seconds, start);
    ITrigger_put_StartBoundary(trigger, start);
    ITrigger_Release(trigger);
    ITriggerCollection_Release(triggers);
    return def;
}

static IRegisteredTask *register_task(const WCHAR *name, ITaskDefinition *def)
{
    IRegisteredTask *task = NULL;
    VARIANT empty;
    BSTR bname = SysAllocString(name);
    HRESULT hr;

    VariantInit(&empty);
    hr = ITaskFolder_RegisterTaskDefinition(folder, bname, def, TASK_CREATE_OR_UPDATE, empty, empty,
                                            TASK_LOGON_INTERACTIVE_TOKEN, empty, &task);
    ok(hr == S_OK, "RegisterTaskDefinition(%ls) failed: 0x%lx\n", name, hr);
    SysFreeString(bname);
    return task;
}

static TASK_STATE task_state(IRegisteredTask *task)
{
    TASK_STATE state = TASK_STATE_UNKNOWN;
    HRESULT hr = IRegisteredTask_get_State(task, &state);

    ok(hr == S_OK, "get_State failed: 0x%lx\n", hr);
    return state;
}

static LONG instance_count(IRegisteredTask *task)
{
    IRunningTaskCollection *instances = NULL;
    LONG count = -1;
    HRESULT hr = IRegisteredTask_GetInstances(task, 0, &instances);

    ok(hr == S_OK, "GetInstances failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        hr = IRunningTaskCollection_get_Count(instances, &count);
        ok(hr == S_OK, "get_Count failed: 0x%lx\n", hr);
        IRunningTaskCollection_Release(instances);
    }
    return count;
}

/* waits until the task is no longer running */
static BOOL wait_not_running(IRegisteredTask *task, DWORD timeout)
{
    DWORD start = GetTickCount();
    TASK_STATE state;

    while ((state = task_state(task)) == TASK_STATE_RUNNING)
    {
        if (GetTickCount() - start > timeout) return FALSE;
        Sleep(250);
    }
    return TRUE;
}

static BOOL name_in_tasks(ITaskFolder *f, const WCHAR *name)
{
    IRegisteredTaskCollection *tasks = NULL;
    LONG count = 0, i;
    BOOL found = FALSE;
    HRESULT hr = ITaskFolder_GetTasks(f, 0, &tasks);

    ok(hr == S_OK, "GetTasks failed: 0x%lx\n", hr);
    if (hr != S_OK) return FALSE;
    hr = IRegisteredTaskCollection_get_Count(tasks, &count);
    ok(hr == S_OK, "get_Count failed: 0x%lx\n", hr);
    for (i = 1; i <= count; i++)
    {
        IRegisteredTask *task = NULL;
        VARIANT index;
        BSTR task_name = NULL;

        V_VT(&index) = VT_I4;
        V_I4(&index) = i;
        if (IRegisteredTaskCollection_get_Item(tasks, index, &task) != S_OK) continue;
        IRegisteredTask_get_Name(task, &task_name);
        if (task_name && !wcsicmp(task_name, name)) found = TRUE;
        SysFreeString(task_name);
        IRegisteredTask_Release(task);
    }
    IRegisteredTaskCollection_Release(tasks);
    return found;
}

static BOOL folder_in_root(const WCHAR *name)
{
    ITaskFolder *root = NULL;
    ITaskFolderCollection *folders = NULL;
    LONG count = 0, i;
    BOOL found = FALSE;
    HRESULT hr = ITaskService_GetFolder(service, (BSTR)L"\\", &root);

    ok(hr == S_OK, "GetFolder(\\) failed: 0x%lx\n", hr);
    if (hr != S_OK) return FALSE;
    hr = ITaskFolder_GetFolders(root, 0, &folders);
    ok(hr == S_OK, "GetFolders failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ITaskFolderCollection_get_Count(folders, &count);
        for (i = 1; i <= count; i++)
        {
            ITaskFolder *sub = NULL;
            VARIANT index;
            BSTR sub_name = NULL;

            V_VT(&index) = VT_I4;
            V_I4(&index) = i;
            if (ITaskFolderCollection_get_Item(folders, index, &sub) != S_OK) continue;
            ITaskFolder_get_Name(sub, &sub_name);
            if (sub_name && !wcsicmp(sub_name, name)) found = TRUE;
            SysFreeString(sub_name);
            ITaskFolder_Release(sub);
        }
        ITaskFolderCollection_Release(folders);
    }
    ITaskFolder_Release(root);
    return found;
}

/* the 64-bit registry view: a 32-bit test must see what the 64-bit service wrote */
static BOOL open_cache_key(const WCHAR *sub, HKEY *key)
{
    WCHAR path[512];

    _swprintf(path, L"%s\\%s", TASKCACHE_KEY, sub);
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_WOW64_64KEY, key) == ERROR_SUCCESS;
}

/* the Windows-shaped copy of the store: Tree\<folder>\<task> has an Id, Tasks\<Id> has the Path */
static void test_registry_copy(const WCHAR *task_name, BOOL expect)
{
    WCHAR sub[512], id[64] = L"", path[512] = L"";
    HKEY key;
    DWORD size, index = 0;
    LONG ret;

    _swprintf(sub, L"Tree\\%s\\%s", API_FOLDER_NAME, task_name);
    if (!expect)
    {
        ok(!open_cache_key(sub, &key), "Tree key of %ls still exists\n", task_name);
        return;
    }
    if (!open_cache_key(sub, &key))
    {
        ok(0, "no Tree key for %ls\n", task_name);
        return;
    }
    size = sizeof(id) - sizeof(WCHAR);
    ret = RegQueryValueExW(key, L"Id", NULL, NULL, (BYTE *)id, &size);
    ok(ret == ERROR_SUCCESS && id[0] == '{', "Id: %ld %ls\n", ret, id);
    size = sizeof(index);
    ret = RegQueryValueExW(key, L"Index", NULL, NULL, (BYTE *)&index, &size);
    ok(ret == ERROR_SUCCESS && index == 3, "Index: %ld %lu\n", ret, index);
    RegCloseKey(key);

    _swprintf(sub, L"Tasks\\%s", id);
    if (!open_cache_key(sub, &key))
    {
        ok(0, "no Tasks key %ls\n", id);
        return;
    }
    size = sizeof(path) - sizeof(WCHAR);
    ret = RegQueryValueExW(key, L"Path", NULL, NULL, (BYTE *)path, &size);
    _swprintf(sub, L"%s\\%s", API_FOLDER, task_name);
    ok(ret == ERROR_SUCCESS && !wcscmp(path, sub), "Path: %ld %ls, expected %ls\n", ret, path, sub);
    size = sizeof(index);
    ret = RegQueryValueExW(key, L"Schema", NULL, NULL, (BYTE *)&index, &size);
    ok(ret == ERROR_SUCCESS && (index >> 16) == 1, "Schema: %ld 0x%lx\n", ret, index);
    RegCloseKey(key);

    /* one of Plain, Boot, Logon lists the task */
    _swprintf(sub, L"Plain\\%s", id);
    ok(open_cache_key(sub, &key), "no Plain\\%ls\n", id);
    if (key) RegCloseKey(key);
}

static void test_enumerate_and_get(IRegisteredTask *task)
{
    IRegisteredTask *again = NULL;
    BSTR name = NULL, path = NULL, xml = NULL;
    VARIANT_BOOL enabled = VARIANT_FALSE;
    HRESULT hr;
    WCHAR expect[MAX_PATH];

    ok(folder_in_root(API_FOLDER_NAME), "folder %ls is not listed in the root\n", API_FOLDER_NAME);
    ok(name_in_tasks(folder, L"Api"), "task Api is not listed\n");

    hr = ITaskFolder_GetTask(folder, (BSTR)L"Api", &again);
    ok(hr == S_OK, "GetTask failed: 0x%lx\n", hr);
    if (hr != S_OK) return;
    hr = IRegisteredTask_get_Name(again, &name);
    ok(hr == S_OK && name && !wcscmp(name, L"Api"), "Name: 0x%lx %ls\n", hr, name);
    hr = IRegisteredTask_get_Path(again, &path);
    _swprintf(expect, L"%s\\Api", API_FOLDER);
    ok(hr == S_OK && path && !wcscmp(path, expect), "Path: 0x%lx %ls\n", hr, path);
    hr = IRegisteredTask_get_Enabled(again, &enabled);
    ok(hr == S_OK && enabled == VARIANT_TRUE, "Enabled: 0x%lx %d\n", hr, enabled);
    ok(task_state(again) == TASK_STATE_READY, "state of a new task is not Ready\n");
    hr = IRegisteredTask_get_Xml(again, &xml);
    ok(hr == S_OK && xml && wcsstr(xml, L"<Exec>"), "Xml: 0x%lx %ls\n", hr, xml);
    SysFreeString(name);
    SysFreeString(path);
    SysFreeString(xml);
    IRegisteredTask_Release(again);

    hr = ITaskFolder_GetTask(folder, (BSTR)L"NoSuchTask", &again);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "GetTask(NoSuchTask): 0x%lx\n", hr);
}

static void test_run_info(IRegisteredTask *task)
{
    DATE date = 1;
    LONG result = 0;
    HRESULT hr;
    LONG missed = -1;
    SYSTEMTIME start, end, *times = NULL;
    DWORD count = 3;

    /* never run: a zero date, and the code Windows uses */
    hr = IRegisteredTask_get_LastRunTime(task, &date);
    ok(hr == SCHED_S_TASK_HAS_NOT_RUN && date == 0, "LastRunTime of a new task: 0x%lx %f\n", hr, date);
    hr = IRegisteredTask_get_LastTaskResult(task, &result);
    ok(hr == S_OK && result == SCHED_S_TASK_HAS_NOT_RUN, "LastTaskResult of a new task: 0x%lx 0x%lx\n", hr, result);
    hr = IRegisteredTask_get_NumberOfMissedRuns(task, &missed);
    ok(hr == S_OK && missed == 0, "NumberOfMissedRuns: 0x%lx %ld\n", hr, missed);

    /* the trigger is a month away: that is the next run, and the only one */
    date = 0;
    hr = IRegisteredTask_get_NextRunTime(task, &date);
    ok(hr == S_OK && date > 0, "NextRunTime: 0x%lx %f\n", hr, date);
    if (hr == S_OK && date > 0)
    {
        SYSTEMTIME now;
        DATE today;

        GetLocalTime(&now);
        SystemTimeToVariantTime(&now, &today);
        ok(date > today + 25 && date < today + 35, "NextRunTime %f is not about a month after %f\n", date, today);
    }

    GetLocalTime(&start);
    end = start;
    end.wYear += 1;
    hr = IRegisteredTask_GetRunTimes(task, &start, &end, &count, &times);
    ok(hr == S_OK && count == 1 && times, "GetRunTimes: 0x%lx, %lu times\n", hr, count);
    if (times) CoTaskMemFree(times);
}

static void test_enable_disable(IRegisteredTask *task)
{
    VARIANT_BOOL enabled;
    VARIANT empty;
    IRunningTask *running = NULL;
    BSTR xml = NULL;
    DATE date;
    HRESULT hr;

    VariantInit(&empty);
    hr = IRegisteredTask_put_Enabled(task, VARIANT_FALSE);
    ok(hr == S_OK, "put_Enabled(FALSE) failed: 0x%lx\n", hr);
    enabled = VARIANT_TRUE;
    hr = IRegisteredTask_get_Enabled(task, &enabled);
    ok(hr == S_OK && enabled == VARIANT_FALSE, "Enabled after disabling: 0x%lx %d\n", hr, enabled);
    ok(task_state(task) == TASK_STATE_DISABLED, "state after disabling is not Disabled\n");

    /* the stored XML says so too, and a disabled task neither runs nor has a next run */
    hr = IRegisteredTask_get_Xml(task, &xml);
    ok(hr == S_OK, "get_Xml: 0x%lx\n", hr);
    SysFreeString(xml);
    hr = IRegisteredTask_Run(task, empty, &running);
    ok(hr == SCHED_E_TASK_DISABLED, "Run of a disabled task: 0x%lx\n", hr);
    if (running) IRunningTask_Release(running);
    date = 1;
    hr = IRegisteredTask_get_NextRunTime(task, &date);
    ok(hr == SCHED_S_TASK_NOT_SCHEDULED && date == 0, "NextRunTime of a disabled task: 0x%lx %f\n", hr, date);

    hr = IRegisteredTask_put_Enabled(task, VARIANT_TRUE);
    ok(hr == S_OK, "put_Enabled(TRUE) failed: 0x%lx\n", hr);
    ok(task_state(task) == TASK_STATE_READY, "state after enabling is not Ready\n");
    hr = IRegisteredTask_get_NextRunTime(task, &date);
    ok(hr == S_OK && date > 0, "NextRunTime after enabling: 0x%lx %f\n", hr, date);
}

static void test_run_on_demand(IRegisteredTask *task, const WCHAR *marker)
{
    IRunningTask *running = NULL;
    VARIANT empty;
    DATE date = 0;
    LONG result = -1;
    HRESULT hr;

    VariantInit(&empty);
    DeleteFileW(marker);
    hr = IRegisteredTask_Run(task, empty, &running);
    ok(hr == S_OK, "Run failed: 0x%lx\n", hr);
    if (running) IRunningTask_Release(running);
    ok(wait_for_file(marker, WAIT_MS), "the task did not write %ls\n", marker);
    ok(wait_not_running(task, WAIT_MS), "the task still runs\n");

    hr = IRegisteredTask_get_LastRunTime(task, &date);
    ok(hr == S_OK && date > 0, "LastRunTime after a run: 0x%lx %f\n", hr, date);
    hr = IRegisteredTask_get_LastTaskResult(task, &result);
    ok(hr == S_OK && result == 0, "LastTaskResult after a run: 0x%lx 0x%lx\n", hr, result);
    ok(instance_count(task) == 0, "an instance is left after the run\n");
}

static void test_stop(IRegisteredTask *task)
{
    IRunningTask *running = NULL;
    VARIANT empty;
    LONG result = -1;
    HRESULT hr;
    DWORD start;

    VariantInit(&empty);
    hr = IRegisteredTask_Stop(task, 0);
    ok(hr == SCHED_E_TASK_NOT_RUNNING, "Stop of a task that does not run: 0x%lx\n", hr);

    hr = IRegisteredTask_Run(task, empty, &running);
    ok(hr == S_OK, "Run of the sleeping task failed: 0x%lx\n", hr);
    if (running) IRunningTask_Release(running);

    start = GetTickCount();
    while (task_state(task) != TASK_STATE_RUNNING && GetTickCount() - start < 10000) Sleep(100);
    ok(task_state(task) == TASK_STATE_RUNNING, "the sleeping task is not Running\n");
    ok(instance_count(task) == 1, "instance count of the running task is not 1\n");

    /* a second Run while it runs is refused */
    hr = IRegisteredTask_Run(task, empty, &running);
    ok(hr == SCHED_E_ALREADY_RUNNING, "second Run: 0x%lx\n", hr);
    if (running) IRunningTask_Release(running);

    hr = IRegisteredTask_get_LastTaskResult(task, &result);
    ok(hr == S_OK && result == SCHED_S_TASK_RUNNING, "LastTaskResult while running: 0x%lx 0x%lx\n", hr, result);

    hr = IRegisteredTask_Stop(task, 0);
    ok(hr == S_OK, "Stop failed: 0x%lx\n", hr);
    ok(task_state(task) == TASK_STATE_READY, "state after Stop is not Ready\n");
    ok(instance_count(task) == 0, "instances after Stop\n");
    hr = IRegisteredTask_get_LastTaskResult(task, &result);
    ok(hr == S_OK && result == ERROR_PROCESS_ABORTED, "LastTaskResult after Stop: 0x%lx %ld\n", hr, result);
}

/* the logon type of the logon session of this process, written to a file: the child of the S4U test */
static void write_logon_type(const WCHAR *path)
{
    TOKEN_STATISTICS stats;
    SECURITY_LOGON_SESSION_DATA *data = NULL;
    HANDLE token, file;
    DWORD size, written;
    char text[32];

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return;
    if (GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &size) &&
        LsaGetLogonSessionData(&stats.AuthenticationId, &data) == 0 && data)
    {
        sprintf(text, "%lu", (ULONG)data->LogonType);
        file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (file != INVALID_HANDLE_VALUE)
        {
            WriteFile(file, text, strlen(text), &written, NULL);
            CloseHandle(file);
        }
        LsaFreeReturnBuffer(data);
    }
    CloseHandle(token);
}

static int read_number(const WCHAR *path)
{
    char text[32] = "";
    DWORD got = 0;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (file == INVALID_HANDLE_VALUE) return -1;
    ReadFile(file, text, sizeof(text) - 1, &got, NULL);
    CloseHandle(file);
    text[got] = 0;
    return got ? atoi(text) : -1;
}

/* a LogonType S4U task of the registering user: it runs in a network logon session, not the user's shell */
static void test_s4u(void)
{
    static const WCHAR fmt[] =
        L"<?xml version=\"1.0\"?>\n"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
        L"  <Principals><Principal id=\"Author\"><LogonType>%s</LogonType></Principal></Principals>\n"
        L"  <Settings><Enabled>true</Enabled></Settings>\n"
        L"  <Actions Context=\"Author\"><Exec><Command>%s</Command><Arguments>TaskSchedulerApi logontype &quot;%s&quot;</Arguments></Exec></Actions>\n"
        L"</Task>\n";
    static const struct { const WCHAR *name, *logon; const WCHAR *file; } cases[] =
    {
        { L"ApiS4U", L"S4U", L"api-s4u.txt" },
        { L"ApiToken", L"InteractiveToken", L"api-token.txt" },
    };
    WCHAR marker[MAX_PATH], xml[4096];
    IRegisteredTask *task;
    IRunningTask *running = NULL;
    VARIANT empty;
    int logon_type[2] = { -1, -1 }, i;
    HRESULT hr;

    VariantInit(&empty);
    for (i = 0; i < 2; i++)
    {
        _swprintf(marker, L"%s\\%s", marker_dir, cases[i].file);
        DeleteFileW(marker);
        _swprintf(xml, fmt, cases[i].logon, test_exe, marker);
        task = NULL;
        hr = ITaskFolder_RegisterTask(folder, (BSTR)cases[i].name, xml, TASK_CREATE_OR_UPDATE, empty, empty,
                                      i ? TASK_LOGON_INTERACTIVE_TOKEN : TASK_LOGON_S4U, empty, &task);
        ok(hr == S_OK, "RegisterTask(%ls) failed: 0x%lx\n", cases[i].name, hr);
        if (hr != S_OK) continue;
        hr = IRegisteredTask_Run(task, empty, &running);
        ok(hr == S_OK, "Run(%ls) failed: 0x%lx\n", cases[i].name, hr);
        if (running) IRunningTask_Release(running);
        if (hr == S_OK)
        {
            ok(wait_for_file(marker, WAIT_MS), "%ls did not write %ls\n", cases[i].name, marker);
            Sleep(500);
            logon_type[i] = read_number(marker);
        }
        IRegisteredTask_Release(task);
        hr = ITaskFolder_DeleteTask(folder, (BSTR)cases[i].name, 0);
        ok(hr == S_OK, "DeleteTask(%ls) failed: 0x%lx\n", cases[i].name, hr);
        DeleteFileW(marker);
    }
    trace("logon type of the S4U task: %d, of the InteractiveToken task: %d\n", logon_type[0], logon_type[1]);
    ok(logon_type[0] == Network, "an S4U task ran in logon type %d, expected Network (%d)\n", logon_type[0], Network);
    ok(logon_type[1] != Network && logon_type[1] > 0, "an InteractiveToken task ran in logon type %d\n", logon_type[1]);
}

START_TEST(TaskSchedulerApi)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    IRegisteredTask *echo_task, *sleep_task;
    ITaskFolder *root = NULL;
    WCHAR marker[MAX_PATH], args[MAX_PATH * 2], sleep_args[MAX_PATH];
    VARIANT empty;
    ITaskDefinition *def;
    HRESULT hr;
    DWORD i;

    /* the child of test_stop: a process that lives a minute */
    if (argc >= 3 && !strcmp(argv[2], "sleep"))
    {
        Sleep(60000);
        return;
    }
    /* the child of test_s4u */
    if (argc >= 4 && !strcmp(argv[2], "logontype"))
    {
        WCHAR path[MAX_PATH];

        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, path, ARRAYSIZE(path));
        write_logon_type(path);
        return;
    }

    GetTempPathW(ARRAYSIZE(marker_dir), marker_dir);
    i = wcslen(marker_dir);
    if (i && marker_dir[i - 1] == '\\') marker_dir[i - 1] = 0;
    GetModuleFileNameW(NULL, test_exe, ARRAYSIZE(test_exe));

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
    hr = ITaskFolder_CreateFolder(root, (BSTR)API_FOLDER, empty, &folder);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) hr = ITaskService_GetFolder(service, (BSTR)API_FOLDER, &folder);
    ok(hr == S_OK, "CreateFolder failed: 0x%lx\n", hr);
    ITaskFolder_Release(root);
    if (hr != S_OK) goto out;

    /* the task that writes a marker */
    _swprintf(marker, L"%s\\api-run.txt", marker_dir);
    DeleteFileW(marker);
    _swprintf(args, L"/c echo api> \"%s\"", marker);
    def = new_definition(L"%SystemRoot%\\system32\\cmd.exe", args, 86400 * 30);
    echo_task = def ? register_task(L"Api", def) : NULL;
    if (def) ITaskDefinition_Release(def);

    /* the task that sleeps: this very executable with the argument "sleep" */
    _swprintf(sleep_args, L"TaskSchedulerApi sleep");
    def = new_definition(test_exe, sleep_args, 86400 * 30);
    sleep_task = def ? register_task(L"ApiSleep", def) : NULL;
    if (def) ITaskDefinition_Release(def);

    if (echo_task)
    {
        test_registry_copy(L"Api", TRUE);
        test_enumerate_and_get(echo_task);
        test_run_info(echo_task);
        test_enable_disable(echo_task);
        test_run_on_demand(echo_task, marker);
    }
    if (sleep_task) test_stop(sleep_task);
    test_s4u();

    if (echo_task)
    {
        hr = ITaskFolder_DeleteTask(folder, (BSTR)L"Api", 0);
        ok(hr == S_OK, "DeleteTask(Api) failed: 0x%lx\n", hr);
        IRegisteredTask_Release(echo_task);
        ok(!name_in_tasks(folder, L"Api"), "task Api is still listed after DeleteTask\n");
        test_registry_copy(L"Api", FALSE);
        hr = ITaskFolder_DeleteTask(folder, (BSTR)L"Api", 0);
        ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "second DeleteTask: 0x%lx\n", hr);
    }
    if (sleep_task)
    {
        hr = ITaskFolder_DeleteTask(folder, (BSTR)L"ApiSleep", 0);
        ok(hr == S_OK, "DeleteTask(ApiSleep) failed: 0x%lx\n", hr);
        IRegisteredTask_Release(sleep_task);
    }
    DeleteFileW(marker);

    /* the folder goes when it is empty */
    ITaskFolder_Release(folder);
    folder = NULL;
    if (SUCCEEDED(ITaskService_GetFolder(service, (BSTR)L"\\", &root)))
    {
        hr = ITaskFolder_DeleteFolder(root, (BSTR)API_FOLDER_NAME, 0);
        ok(hr == S_OK, "DeleteFolder failed: 0x%lx\n", hr);
        ITaskFolder_Release(root);
    }

out:
    ITaskService_Release(service);
}
