/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPLv2+ - See COPYING in the top level directory
 * PURPOSE:         StartService starts the stopped services (and group members) a service depends on first
 */

#include "precomp.h"

#include "svchlp.h"

/*
 * Public documentation, CreateService (lpDependencies): "[...] names of services or load ordering groups that the
 * system must start before this service. [...] Dependency on a group means that this service can run if at least one
 * member of the group is running after an attempt to start all members of the group. You must prefix group names
 * with SC_GROUP_IDENTIFIER [...]"
 * System error codes: ERROR_SERVICE_DEPENDENCY_FAIL 1068 "The dependency service or group failed to start."
 * ERROR_SERVICE_DEPENDENCY_DELETED 1075 "The dependency service does not exist or has been marked for deletion."
 * https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-createservicew
 * https://learn.microsoft.com/windows/win32/debug/system-error-codes--1000-1299-
 *
 * The behaviour of a dependency that is disabled or whose process stops at once is not measured on Windows here:
 * the rows for it (marked) keep the behaviour of this implementation (ERROR_SERVICE_DEPENDENCY_FAIL).
 */

/*** Service part of the test ***/

static SERVICE_STATUS_HANDLE status_handle;
static HANDLE stop_event;
static char service_mode[16];
static WCHAR service_target[100];

/* What a service of the test saw is kept in its own key: the tester reads it back */
static void
record_dword(PCWSTR service, PCWSTR value, DWORD data)
{
    WCHAR path[200];
    HKEY key;

    StringCchPrintfW(path, _countof(path), L"SYSTEM\\CurrentControlSet\\Services\\%ls", service);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS)
    {
        RegSetValueExW(key, value, 0, REG_DWORD, (const BYTE *)&data, sizeof(data));
        RegCloseKey(key);
    }
}

static DWORD
read_dword(PCWSTR service, PCWSTR value, DWORD default_value)
{
    WCHAR path[200];
    DWORD data = default_value, size = sizeof(data);
    HKEY key;

    StringCchPrintfW(path, _countof(path), L"SYSTEM\\CurrentControlSet\\Services\\%ls", service);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(key, value, NULL, NULL, (BYTE *)&data, &size) != ERROR_SUCCESS)
            data = default_value;
        RegCloseKey(key);
    }
    return data;
}

static void
report_service_status(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwCheckPoint, DWORD dwWaitHint)
{
    SERVICE_STATUS status;

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = dwCurrentState;
    status.dwWin32ExitCode = dwWin32ExitCode;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = dwCheckPoint;
    status.dwWaitHint = dwWaitHint;
    status.dwControlsAccepted = (dwCurrentState == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    SetServiceStatus(status_handle, &status);
}

static VOID WINAPI
service_handler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP)
    {
        report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 1, 3000);
        SetEvent(stop_event);
    }
}

static void WINAPI
service_main(DWORD dwArgc, LPWSTR *lpszArgv)
{
    status_handle = RegisterServiceCtrlHandlerW(lpszArgv[0], service_handler);
    if (!status_handle)
        return;

    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* How often the service was started, and with how many arguments (its name is the first) */
    record_dword(lpszArgv[0], L"RosStarts", read_dword(lpszArgv[0], L"RosStarts", 0) + 1);
    record_dword(lpszArgv[0], L"RosArgc", dwArgc);

    if (!strcmp(service_mode, "hang"))
    {
        /* A start that never gets anywhere: pending, the checkpoint does not move; it gives up after 40 s */
        report_service_status(SERVICE_START_PENDING, NO_ERROR, 1, 1000);
        Sleep(40000);
        report_service_status(SERVICE_STOPPED, ERROR_GEN_FAILURE, 0, 0);
        return;
    }

    if (!strcmp(service_mode, "startdep"))
    {
        /* Its start code starts a service that depends on it, before it reports running (the documentation
           says not to: the call blocks). What the call returned and how long it took are recorded. */
        SC_HANDLE scm, target;
        DWORD start = GetTickCount(), error = 0xdeadbeef;

        report_service_status(SERVICE_START_PENDING, NO_ERROR, 1, 3000);
        scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        target = scm ? OpenServiceW(scm, service_target, SERVICE_START) : NULL;
        if (target)
        {
            error = StartServiceW(target, 0, NULL) ? ERROR_SUCCESS : GetLastError();
            CloseServiceHandle(target);
        }
        if (scm)
            CloseServiceHandle(scm);
        record_dword(lpszArgv[0], L"RosInnerError", error);
        record_dword(lpszArgv[0], L"RosInnerMs", GetTickCount() - start);
    }

    if (!strcmp(service_mode, "fail"))
    {
        /* The service cannot start: its process reports it stopped with an error */
        report_service_status(SERVICE_STOPPED, ERROR_GEN_FAILURE, 0, 0);
        return;
    }

    if (!strcmp(service_mode, "slow"))
    {
        /* A start that takes a while: pending first, running a second later */
        report_service_status(SERVICE_START_PENDING, NO_ERROR, 1, 3000);
        Sleep(1000);
    }

    report_service_status(SERVICE_RUNNING, NO_ERROR, 0, 0);
    WaitForSingleObject(stop_event, INFINITE);
    report_service_status(SERVICE_STOPPED, NO_ERROR, 0, 0);
}

static BOOL
start_service_dispatcher(PCSTR service_nameA, PCWSTR service_nameW)
{
    SERVICE_TABLE_ENTRYW servtbl[] =
    {
        { (PWSTR)service_nameW, service_main },
        { NULL, NULL }
    };

    return StartServiceCtrlDispatcherW(servtbl);
}


/*** Tester part of the test ***/

static SC_HANDLE hSC;
static WCHAR test_suffix[32];

static SC_HANDLE
create_test_service(PCWSTR base, PCSTR mode, PCWSTR dependencies, PCWSTR group, DWORD start_type)
{
    WCHAR name[64], args[160];

    StringCchPrintfW(name, _countof(name), L"RosDep%ls%ls", base, test_suffix);
    StringCchPrintfW(args, _countof(args), L"%S", mode);
    return register_service_exW(hSC, L"ServiceDependency", name, args,
                                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, start_type,
                                SERVICE_ERROR_IGNORE, group, NULL, dependencies, NULL, NULL);
}

static void
build_name(PWSTR buffer, SIZE_T cch, PCWSTR base)
{
    StringCchPrintfW(buffer, cch, L"RosDep%ls%ls", base, test_suffix);
}

static DWORD
get_state(SC_HANDLE service)
{
    SERVICE_STATUS status;

    if (!QueryServiceStatus(service, &status))
        return 0;
    return status.dwCurrentState;
}

static BOOL
wait_for_state(SC_HANDLE service, DWORD state)
{
    int i;

    for (i = 0; i < 100; i++)
    {
        if (get_state(service) == state)
            return TRUE;
        Sleep(100);
    }
    return FALSE;
}

static void
remove_test_service(SC_HANDLE service)
{
    SERVICE_STATUS status;

    if (!service)
        return;
    if (get_state(service) != SERVICE_STOPPED)
    {
        ControlService(service, SERVICE_CONTROL_STOP, &status);
        wait_for_state(service, SERVICE_STOPPED);
    }
    DeleteService(service);
    CloseServiceHandle(service);
}

/* Dependencies are given as a list of base names, the multi-string is built here */
static SC_HANDLE
create_dependent(PCWSTR base, PCSTR mode, PCWSTR dep1, PCWSTR dep2, BOOL group_dep)
{
    WCHAR deps[160] = L"";
    SIZE_T len = 0;

    if (dep1)
    {
        if (group_dep)
            deps[len++] = SC_GROUP_IDENTIFIERW;
        build_name(deps + len, _countof(deps) - len, dep1);
        len += wcslen(deps + len) + 1;
    }
    if (dep2)
    {
        build_name(deps + len, _countof(deps) - len, dep2);
        len += wcslen(deps + len) + 1;
    }
    deps[len] = UNICODE_NULL;
    return create_test_service(base, mode, dep1 ? deps : NULL, NULL, SERVICE_DEMAND_START);
}

static void
test_start_order(void)
{
    SC_HANDLE dep, top;
    BOOL ret;

    /* A dependency that needs a second to come up: the start of the service returns after it is running */
    dep = create_test_service(L"Dep", "slow", NULL, NULL, SERVICE_DEMAND_START);
    top = create_dependent(L"Top", "run", L"Dep", NULL, FALSE);
    if (!dep || !top)
        goto cleanup;

    ok(get_state(dep) == SERVICE_STOPPED, "dependency state %lu\n", get_state(dep));
    ret = StartServiceW(top, 0, NULL);
    ok(ret, "StartService failed: %lu\n", GetLastError());
    ok(get_state(dep) == SERVICE_RUNNING, "dependency state %lu, expected running\n", get_state(dep));
    ok(get_state(top) == SERVICE_RUNNING || wait_for_state(top, SERVICE_RUNNING), "service state %lu\n", get_state(top));

cleanup:
    remove_test_service(top);
    remove_test_service(dep);
}

static void
test_chain_and_running(void)
{
    SC_HANDLE c, b, a;
    BOOL ret;

    /* a depends on b, b on c: starting a starts both */
    c = create_test_service(L"C", "run", NULL, NULL, SERVICE_DEMAND_START);
    b = create_dependent(L"B", "run", L"C", NULL, FALSE);
    a = create_dependent(L"A", "run", L"B", NULL, FALSE);
    if (!a || !b || !c)
        goto cleanup;

    ret = StartServiceW(a, 0, NULL);
    ok(ret, "StartService failed: %lu\n", GetLastError());
    ok(get_state(c) == SERVICE_RUNNING, "c state %lu\n", get_state(c));
    ok(get_state(b) == SERVICE_RUNNING, "b state %lu\n", get_state(b));

    /* The services are running already: a second start only reports that, dependencies stay as they are */
    SetLastError(0xdeadbeef);
    ret = StartServiceW(a, 0, NULL);
    ok(!ret && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING, "second start: %d, error %lu\n", ret, GetLastError());
    ok(get_state(b) == SERVICE_RUNNING && get_state(c) == SERVICE_RUNNING, "b %lu, c %lu\n", get_state(b), get_state(c));

cleanup:
    remove_test_service(a);
    remove_test_service(b);
    remove_test_service(c);
}

static void
test_dependency_running_already(void)
{
    SC_HANDLE dep, top;
    BOOL ret;

    dep = create_test_service(L"DepR", "run", NULL, NULL, SERVICE_DEMAND_START);
    top = create_dependent(L"TopR", "run", L"DepR", NULL, FALSE);
    if (!dep || !top)
        goto cleanup;

    ret = StartServiceW(dep, 0, NULL);
    ok(ret, "StartService(dependency) failed: %lu\n", GetLastError());
    ret = StartServiceW(top, 0, NULL);
    ok(ret, "StartService failed: %lu\n", GetLastError());
    ok(get_state(dep) == SERVICE_RUNNING, "dependency state %lu\n", get_state(dep));

cleanup:
    remove_test_service(top);
    remove_test_service(dep);
}

static void
test_failing_dependency(void)
{
    SC_HANDLE dep, top;
    SERVICE_STATUS status;
    BOOL ret;

    /* A dependency whose process stops with an error: the service does not start (1068) */
    dep = create_test_service(L"DepF", "fail", NULL, NULL, SERVICE_DEMAND_START);
    top = create_dependent(L"TopF", "run", L"DepF", NULL, FALSE);
    if (!dep || !top)
        goto cleanup;

    SetLastError(0xdeadbeef);
    ret = StartServiceW(top, 0, NULL);
    ok(!ret && GetLastError() == ERROR_SERVICE_DEPENDENCY_FAIL, "start: %d, error %lu\n", ret, GetLastError());
    ok(get_state(top) == SERVICE_STOPPED, "service state %lu\n", get_state(top));
    ret = QueryServiceStatus(top, &status);
    ok(ret, "QueryServiceStatus failed: %lu\n", GetLastError());

cleanup:
    remove_test_service(top);
    remove_test_service(dep);
}

static void
test_disabled_dependency(void)
{
    SC_HANDLE dep, top;
    BOOL ret;

    /* Not measured on Windows: the service does not start (ERROR_SERVICE_DEPENDENCY_FAIL) */
    dep = create_test_service(L"DepD", "run", NULL, NULL, SERVICE_DISABLED);
    top = create_dependent(L"TopD", "run", L"DepD", NULL, FALSE);
    if (!dep || !top)
        goto cleanup;

    SetLastError(0xdeadbeef);
    ret = StartServiceW(top, 0, NULL);
    ok(!ret && GetLastError() == ERROR_SERVICE_DEPENDENCY_FAIL, "start: %d, error %lu\n", ret, GetLastError());
    ok(get_state(dep) == SERVICE_STOPPED, "dependency state %lu\n", get_state(dep));
    ok(get_state(top) == SERVICE_STOPPED, "service state %lu\n", get_state(top));

cleanup:
    remove_test_service(top);
    remove_test_service(dep);
}

static void
test_group_dependency(void)
{
    WCHAR group[64];
    SC_HANDLE m1, m2, top, topf, f1;
    BOOL ret;

    StringCchPrintfW(group, _countof(group), L"RosDepGroup%ls", test_suffix);

    /* One member comes up, one does not: the group is satisfied; both members were tried */
    m1 = create_test_service(L"M1", "run", NULL, group, SERVICE_DEMAND_START);
    m2 = create_test_service(L"M2", "fail", NULL, group, SERVICE_DEMAND_START);
    top = create_test_service(L"TopG", "run", NULL, NULL, SERVICE_DEMAND_START);
    if (m1 && m2 && top)
    {
        WCHAR deps[80];
        SIZE_T len = 0;

        deps[len++] = SC_GROUP_IDENTIFIERW;
        StringCchCopyW(deps + len, _countof(deps) - len, group);
        len += wcslen(deps + len) + 1;
        deps[len] = UNICODE_NULL;
        ret = ChangeServiceConfigW(top, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                   NULL, NULL, NULL, deps, NULL, NULL, NULL);
        ok(ret, "ChangeServiceConfig failed: %lu\n", GetLastError());

        ret = StartServiceW(top, 0, NULL);
        ok(ret, "StartService failed: %lu\n", GetLastError());
        ok(get_state(m1) == SERVICE_RUNNING, "member state %lu\n", get_state(m1));
        ok(get_state(top) == SERVICE_RUNNING || wait_for_state(top, SERVICE_RUNNING), "service state %lu\n", get_state(top));
    }
    remove_test_service(top);
    remove_test_service(m2);
    remove_test_service(m1);

    /* No member comes up: the service does not start */
    f1 = create_test_service(L"F1", "fail", NULL, group, SERVICE_DEMAND_START);
    topf = create_test_service(L"TopGF", "run", NULL, NULL, SERVICE_DEMAND_START);
    if (f1 && topf)
    {
        WCHAR deps[80];
        SIZE_T len = 0;

        deps[len++] = SC_GROUP_IDENTIFIERW;
        StringCchCopyW(deps + len, _countof(deps) - len, group);
        len += wcslen(deps + len) + 1;
        deps[len] = UNICODE_NULL;
        ret = ChangeServiceConfigW(topf, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                   NULL, NULL, NULL, deps, NULL, NULL, NULL);
        ok(ret, "ChangeServiceConfig failed: %lu\n", GetLastError());

        SetLastError(0xdeadbeef);
        ret = StartServiceW(topf, 0, NULL);
        ok(!ret && GetLastError() == ERROR_SERVICE_DEPENDENCY_FAIL, "start: %d, error %lu\n", ret, GetLastError());
        ok(get_state(topf) == SERVICE_STOPPED, "service state %lu\n", get_state(topf));
    }
    remove_test_service(topf);
    remove_test_service(f1);
}

static BOOL
wait_for_state_ms(SC_HANDLE service, DWORD state, DWORD ms)
{
    DWORD start = GetTickCount();

    while (GetTickCount() - start < ms)
    {
        if (get_state(service) == state)
            return TRUE;
        Sleep(100);
    }
    return get_state(service) == state;
}

static BOOL
set_dependencies(SC_HANDLE service, PCWSTR base, BOOL group)
{
    WCHAR deps[80];
    SIZE_T len = 0;

    if (group)
    {
        deps[len++] = SC_GROUP_IDENTIFIERW;
        StringCchPrintfW(deps + len, _countof(deps) - len, L"RosDepGroup%ls%ls", base, test_suffix);
    }
    else
    {
        build_name(deps + len, _countof(deps) - len, base);
    }
    len += wcslen(deps + len) + 1;
    deps[len] = UNICODE_NULL;
    return ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                NULL, NULL, NULL, deps, NULL, NULL, NULL);
}

static void
test_missing_dependency(void)
{
    SC_HANDLE top;
    BOOL ret;

    /* The dependency is not installed: ERROR_SERVICE_DEPENDENCY_DELETED (1075) */
    top = create_dependent(L"TopM", "run", L"Missing", NULL, FALSE);
    if (!top)
        return;

    SetLastError(0xdeadbeef);
    ret = StartServiceW(top, 0, NULL);
    ok(!ret && GetLastError() == ERROR_SERVICE_DEPENDENCY_DELETED, "start: %d, error %lu\n", ret, GetLastError());
    ok(get_state(top) == SERVICE_STOPPED, "service state %lu\n", get_state(top));
    remove_test_service(top);
}

static void
test_start_parameters(void)
{
    static PCWSTR args[] = { L"one", L"two" };
    WCHAR depname[64], topname[64];
    SC_HANDLE dep, top;
    BOOL ret;

    /* Only the named service gets the arguments; its dependency is started with its name alone */
    dep = create_test_service(L"DepP", "run", NULL, NULL, SERVICE_DEMAND_START);
    top = create_dependent(L"TopP", "run", L"DepP", NULL, FALSE);
    if (!dep || !top)
        goto cleanup;
    build_name(depname, _countof(depname), L"DepP");
    build_name(topname, _countof(topname), L"TopP");

    ret = StartServiceW(top, _countof(args), args);
    ok(ret, "StartService failed: %lu\n", GetLastError());
    ok(wait_for_state(top, SERVICE_RUNNING), "service state %lu\n", get_state(top));
    ok(read_dword(depname, L"RosArgc", 0) == 1, "dependency argc %lu\n", read_dword(depname, L"RosArgc", 0));
    ok(read_dword(topname, L"RosArgc", 0) == 3, "service argc %lu\n", read_dword(topname, L"RosArgc", 0));

cleanup:
    remove_test_service(top);
    remove_test_service(dep);
}

static void
test_disabled_group(void)
{
    WCHAR group[64];
    SC_HANDLE m, top;
    BOOL ret;

    /* The only member of the group is disabled: no member is running after the attempt, the service does not start */
    StringCchPrintfW(group, _countof(group), L"RosDepGroupDis%ls", test_suffix);
    m = create_test_service(L"MDis", "run", NULL, group, SERVICE_DISABLED);
    top = create_test_service(L"TopGD", "run", NULL, NULL, SERVICE_DEMAND_START);
    if (!m || !top)
        goto cleanup;
    ok(set_dependencies(top, L"Dis", TRUE), "ChangeServiceConfig failed: %lu\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = StartServiceW(top, 0, NULL);
    ok(!ret && GetLastError() == ERROR_SERVICE_DEPENDENCY_FAIL, "start: %d, error %lu\n", ret, GetLastError());
    ok(get_state(m) == SERVICE_STOPPED, "member state %lu\n", get_state(m));

cleanup:
    remove_test_service(top);
    remove_test_service(m);
}

static void
test_cycles(void)
{
    WCHAR aname[64], bname[64], group[64];
    SC_HANDLE a, b;
    DWORD start, error;
    BOOL ret;

    /* a depends on b, b on a. Windows documents ERROR_CIRCULAR_DEPENDENCY for ChangeServiceConfig; where the
       configuration is taken, the start fails with that code at once and starts neither */
    a = create_test_service(L"CycA", "run", NULL, NULL, SERVICE_DEMAND_START);
    b = create_test_service(L"CycB", "run", NULL, NULL, SERVICE_DEMAND_START);
    if (!a || !b)
        goto cleanup;
    build_name(aname, _countof(aname), L"CycA");
    build_name(bname, _countof(bname), L"CycB");

    ok(set_dependencies(a, L"CycB", FALSE), "ChangeServiceConfig(a) failed: %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = set_dependencies(b, L"CycA", FALSE);
    error = GetLastError();
    if (!ret)
    {
        ok(error == ERROR_CIRCULAR_DEPENDENCY, "ChangeServiceConfig(b) error %lu\n", error);
    }
    else
    {
        start = GetTickCount();
        SetLastError(0xdeadbeef);
        ret = StartServiceW(a, 0, NULL);
        error = GetLastError();
        ok(!ret && error == ERROR_CIRCULAR_DEPENDENCY, "start: %d, error %lu\n", ret, error);
        ok(GetTickCount() - start < 5000, "the start took %lu ms\n", GetTickCount() - start);
        ok(get_state(a) == SERVICE_STOPPED && get_state(b) == SERVICE_STOPPED, "a %lu, b %lu\n", get_state(a), get_state(b));
        ok(read_dword(aname, L"RosStarts", 0) == 0 && read_dword(bname, L"RosStarts", 0) == 0,
           "starts a %lu, b %lu\n", read_dword(aname, L"RosStarts", 0), read_dword(bname, L"RosStarts", 0));

        /* a service that depends on itself */
        ok(set_dependencies(b, L"CycB", FALSE) || GetLastError() == ERROR_CIRCULAR_DEPENDENCY,
           "ChangeServiceConfig(b, b) failed: %lu\n", GetLastError());
        SetLastError(0xdeadbeef);
        ret = StartServiceW(b, 0, NULL);
        ok(!ret && GetLastError() == ERROR_CIRCULAR_DEPENDENCY, "self: %d, error %lu\n", ret, GetLastError());
    }
    remove_test_service(a);
    remove_test_service(b);

    /* Through a group: a depends on the group of b, b depends on a */
    StringCchPrintfW(group, _countof(group), L"RosDepGroupCyc%ls", test_suffix);
    a = create_test_service(L"CycGA", "run", NULL, NULL, SERVICE_DEMAND_START);
    b = create_test_service(L"CycGB", "run", NULL, group, SERVICE_DEMAND_START);
    if (!a || !b)
        goto cleanup;
    ok(set_dependencies(a, L"Cyc", TRUE), "ChangeServiceConfig(a) failed: %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = set_dependencies(b, L"CycGA", FALSE);
    error = GetLastError();
    if (!ret)
    {
        ok(error == ERROR_CIRCULAR_DEPENDENCY, "ChangeServiceConfig(b) error %lu\n", error);
    }
    else
    {
        start = GetTickCount();
        SetLastError(0xdeadbeef);
        ret = StartServiceW(a, 0, NULL);
        error = GetLastError();
        ok(!ret && error == ERROR_CIRCULAR_DEPENDENCY, "group: %d, error %lu\n", ret, error);
        ok(GetTickCount() - start < 5000, "the start took %lu ms\n", GetTickCount() - start);
        ok(get_state(a) == SERVICE_STOPPED && get_state(b) == SERVICE_STOPPED, "a %lu, b %lu\n", get_state(a), get_state(b));
    }

cleanup:
    remove_test_service(a);
    remove_test_service(b);
}

static void
test_reentrant_start(void)
{
    WCHAR aname[64], bname[64], mode[100];
    SC_HANDLE a = NULL, b = NULL;
    DWORD start, elapsed, inner_ms, inner_error;
    BOOL ret;

    /* a depends on b; b's start code starts a before b reports running. The documentation says such a call blocks;
       here it must come back in bounded time, b must still start, and a must end up running */
    build_name(aname, _countof(aname), L"ReA");
    build_name(bname, _countof(bname), L"ReB");
    StringCchPrintfW(mode, _countof(mode), L"startdep %ls", aname);
    {
        char modeA[100];

        WideCharToMultiByte(CP_ACP, 0, mode, -1, modeA, sizeof(modeA), NULL, NULL);
        b = create_test_service(L"ReB", modeA, NULL, NULL, SERVICE_DEMAND_START);
    }
    a = create_dependent(L"ReA", "run", L"ReB", NULL, FALSE);
    if (!a || !b)
        goto cleanup;

    start = GetTickCount();
    SetLastError(0xdeadbeef);
    ret = StartServiceW(a, 0, NULL);
    elapsed = GetTickCount() - start;
    ok(ret || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING, "start: %d, error %lu\n", ret, GetLastError());
    ok(elapsed < 75000, "the start took %lu ms\n", elapsed);
    ok(wait_for_state(b, SERVICE_RUNNING), "b state %lu\n", get_state(b));
    ok(wait_for_state(a, SERVICE_RUNNING), "a state %lu\n", get_state(a));

    inner_ms = read_dword(bname, L"RosInnerMs", 0xffffffff);
    inner_error = read_dword(bname, L"RosInnerError", 0xffffffff);
    ok(inner_ms < 45000, "the inner start took %lu ms\n", inner_ms);
    trace("re-entrant start: outer %lu ms, inner error %lu after %lu ms\n", elapsed, inner_error, inner_ms);

cleanup:
    remove_test_service(a);
    remove_test_service(b);
}

typedef struct _START_THREAD
{
    HANDLE go;
    SC_HANDLE service;
    BOOL ret;
    DWORD error;
    DWORD ms;
} START_THREAD;

static DWORD WINAPI
start_thread(PVOID param)
{
    START_THREAD *st = param;
    DWORD start;

    WaitForSingleObject(st->go, INFINITE);
    start = GetTickCount();
    SetLastError(0xdeadbeef);
    st->ret = StartServiceW(st->service, 0, NULL);
    st->error = st->ret ? ERROR_SUCCESS : GetLastError();
    st->ms = GetTickCount() - start;
    return 0;
}

static void
test_concurrent_starts(void)
{
    WCHAR depname[64], base[16], topnames[4][64];
    SC_HANDLE dep, tops[4] = { NULL };
    START_THREAD st[8];
    HANDLE threads[8], go = NULL;
    DWORD soak_ms = 0, begin, starts, iteration = 0, i, wait;
    char env[16];
    BOOL all_ok;

    /* 8 threads start 4 services (two threads each) that depend on one slow service, at the same moment: the
       dependency is started exactly once, every call comes back, each service is started by exactly one of its
       two callers (the other is told it runs). SERVICEDEPENDENCY_SOAK=<seconds> repeats it. */
    if (GetEnvironmentVariableA("SERVICEDEPENDENCY_SOAK", env, sizeof(env)) && atoi(env) > 0)
        soak_ms = atoi(env) * 1000;

    dep = create_test_service(L"DepC", "slow", NULL, NULL, SERVICE_DEMAND_START);
    for (i = 0; i < 4; i++)
    {
        StringCchPrintfW(base, _countof(base), L"TopC%lu", i);
        tops[i] = create_dependent(base, "run", L"DepC", NULL, FALSE);
        build_name(topnames[i], _countof(topnames[i]), base);
    }
    if (!dep || !tops[0] || !tops[1] || !tops[2] || !tops[3])
        goto cleanup;
    build_name(depname, _countof(depname), L"DepC");
    go = CreateEventW(NULL, TRUE, FALSE, NULL);

    begin = GetTickCount();
    do
    {
        starts = read_dword(depname, L"RosStarts", 0);
        ResetEvent(go);
        for (i = 0; i < 8; i++)
        {
            /* A handle of its own per thread: RPC serializes the calls made on one context handle */
            st[i].go = go;
            st[i].service = OpenServiceW(hSC, topnames[i % 4], SERVICE_START);
            threads[i] = CreateThread(NULL, 0, start_thread, &st[i], 0, NULL);
        }
        SetEvent(go);
        wait = WaitForMultipleObjects(8, threads, TRUE, 90000);
        ok(wait != WAIT_TIMEOUT, "iteration %lu: a StartService call did not come back\n", iteration);
        for (i = 0; i < 8; i++)
        {
            CloseHandle(threads[i]);
            if (wait != WAIT_TIMEOUT && st[i].service)
                CloseServiceHandle(st[i].service);
        }
        if (wait == WAIT_TIMEOUT)
            break;

        all_ok = TRUE;
        for (i = 0; i < 4; i++)
        {
            START_THREAD *x = &st[i], *y = &st[i + 4];
            BOOL one = (x->ret && !y->ret && y->error == ERROR_SERVICE_ALREADY_RUNNING) ||
                       (y->ret && !x->ret && x->error == ERROR_SERVICE_ALREADY_RUNNING);

            ok(one, "iteration %lu, service %lu: %d/%lu, %d/%lu\n", iteration, i, x->ret, x->error, y->ret, y->error);
            all_ok = all_ok && one;
        }
        ok(read_dword(depname, L"RosStarts", 0) == starts + 1, "iteration %lu: dependency started %lu times\n",
           iteration, read_dword(depname, L"RosStarts", 0) - starts);
        for (i = 0; i < 8; i++)
            ok(st[i].ms < 60000, "iteration %lu, thread %lu: %lu ms\n", iteration, i, st[i].ms);

        /* Stop the dependents, then the dependency, for the next round */
        for (i = 0; i < 4; i++)
        {
            SERVICE_STATUS status;

            wait_for_state(tops[i], SERVICE_RUNNING);
            ControlService(tops[i], SERVICE_CONTROL_STOP, &status);
        }
        for (i = 0; i < 4; i++)
            ok(wait_for_state(tops[i], SERVICE_STOPPED), "iteration %lu: service %lu does not stop\n", iteration, i);
        {
            SERVICE_STATUS status;

            ControlService(dep, SERVICE_CONTROL_STOP, &status);
            ok(wait_for_state(dep, SERVICE_STOPPED), "iteration %lu: the dependency does not stop\n", iteration);
        }
        iteration++;
        if (!all_ok)
            break;
    } while (GetTickCount() - begin < soak_ms);
    trace("concurrent starts: %lu iterations in %lu ms\n", iteration, GetTickCount() - begin);

cleanup:
    if (go)
        CloseHandle(go);
    for (i = 0; i < 4; i++)
        remove_test_service(tops[i]);
    remove_test_service(dep);
}

typedef struct _MEASURE
{
    SC_HANDLE service;
    BOOL ret;
    DWORD error;
    DWORD ms;
} MEASURE;

static DWORD WINAPI
start_measure_thread(PVOID param)
{
    MEASURE *m = param;
    DWORD start = GetTickCount();

    SetLastError(0xdeadbeef);
    m->ret = StartServiceW(m->service, 0, NULL);
    m->error = m->ret ? ERROR_SUCCESS : GetLastError();
    m->ms = GetTickCount() - start;
    return 0;
}

static void
test_dependency_never_running(void)
{
    SC_HANDLE hang, top, other, unrelated, query = NULL;
    WCHAR topname[64];
    SERVICE_STATUS status;
    MEASURE m = { 0 };
    HANDLE thread;
    DWORD t, d, max_query = 0, max_control = 0, n = 0, locks = 0, start_ms = 0;
    SC_LOCK lock;
    BOOL ret;

    /* The dependency stays START_PENDING and its checkpoint never moves. The caller comes back in bounded time
       with ERROR_SERVICE_DEPENDENCY_FAIL, and the controller answers other requests meanwhile: status queries,
       controls of another service, the start of an unrelated service, the database lock */
    hang = create_test_service(L"DepH", "hang", NULL, NULL, SERVICE_DEMAND_START);
    top = create_dependent(L"TopH", "run", L"DepH", NULL, FALSE);
    other = create_test_service(L"OtherH", "run", NULL, NULL, SERVICE_DEMAND_START);
    unrelated = create_test_service(L"UnrelH", "run", NULL, NULL, SERVICE_DEMAND_START);
    if (!hang || !top || !other || !unrelated)
        goto cleanup;

    /* The queries use a handle of their own: RPC serializes the calls made on one context handle, so a query on
       the handle the waiting StartService uses waits for it on Windows too */
    build_name(topname, _countof(topname), L"TopH");
    query = OpenServiceW(hSC, topname, SERVICE_QUERY_STATUS);
    ok(query != NULL, "OpenService failed: %lu\n", GetLastError());

    ret = StartServiceW(other, 0, NULL);
    ok(ret, "StartService(other) failed: %lu\n", GetLastError());
    ok(wait_for_state(other, SERVICE_RUNNING), "other state %lu\n", get_state(other));

    m.service = top;
    thread = CreateThread(NULL, 0, start_measure_thread, &m, 0, NULL);
    ok(wait_for_state(hang, SERVICE_START_PENDING), "dependency state %lu\n", get_state(hang));

    /* 20 s of requests while the start waits */
    t = GetTickCount();
    while (GetTickCount() - t < 20000 && WaitForSingleObject(thread, 0) == WAIT_TIMEOUT)
    {
        d = GetTickCount();
        QueryServiceStatus(query, &status);
        max_query = max(max_query, GetTickCount() - d);

        d = GetTickCount();
        ControlService(other, SERVICE_CONTROL_INTERROGATE, &status);
        max_control = max(max_control, GetTickCount() - d);

        lock = LockServiceDatabase(hSC);
        if (lock)
        {
            locks++;
            UnlockServiceDatabase(lock);
        }

        if (n == 10)
        {
            d = GetTickCount();
            ret = StartServiceW(unrelated, 0, NULL);
            start_ms = GetTickCount() - d;
            ok(ret, "StartService(unrelated) during the wait failed: %lu\n", GetLastError());
        }
        n++;
        Sleep(200);
    }
    ok(max_query < 1000, "QueryServiceStatus took up to %lu ms during the wait\n", max_query);
    ok(max_control < 3000, "ControlService(INTERROGATE) of another service took up to %lu ms during the wait\n", max_control);
    ok(start_ms < 5000, "the start of an unrelated service took %lu ms during the wait\n", start_ms);
    trace("during the wait: %lu rounds, query max %lu ms, control max %lu ms, unrelated start %lu ms, %lu locks taken\n",
          n, max_query, max_control, start_ms, locks);

    ok(WaitForSingleObject(thread, 60000) == WAIT_OBJECT_0, "StartService did not come back\n");
    CloseHandle(thread);
    ok(!m.ret && m.error == ERROR_SERVICE_DEPENDENCY_FAIL, "start: %d, error %lu\n", m.ret, m.error);
    ok(m.ms < 50000, "the start took %lu ms\n", m.ms);
    trace("start with a dependency that never runs: %lu ms\n", m.ms);
    ok(get_state(top) == SERVICE_STOPPED, "service state %lu\n", get_state(top));

cleanup:
    if (query)
        CloseServiceHandle(query);
    if (hang)
        wait_for_state_ms(hang, SERVICE_STOPPED, 60000);
    remove_test_service(unrelated);
    remove_test_service(other);
    remove_test_service(top);
    remove_test_service(hang);
}

START_TEST(ServiceDependency)
{
    int argc;
    char **argv;

    /* Started as one of the services of the test: argv[2] is its name, argv[3] what it does */
    argc = winetest_get_mainargs(&argv);
    if (argc >= 4)
    {
        WCHAR nameW[100];

        StringCchCopyA(service_mode, sizeof(service_mode), argv[3]);
        if (argc >= 5)
            MultiByteToWideChar(CP_ACP, 0, argv[4], -1, service_target, _countof(service_target));
        MultiByteToWideChar(CP_ACP, 0, argv[2], -1, nameW, _countof(nameW));
        start_service_dispatcher(argv[2], nameW);
        return;
    }

    hSC = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSC)
    {
        skip("OpenSCManager failed: %lu\n", GetLastError());
        return;
    }

    StringCchPrintfW(test_suffix, _countof(test_suffix), L"%lu", GetTickCount());

    test_start_order();
    test_chain_and_running();
    test_dependency_running_already();
    test_failing_dependency();
    test_disabled_dependency();
    test_group_dependency();
    test_missing_dependency();
    test_start_parameters();
    test_disabled_group();
    test_cycles();
    test_concurrent_starts();
    test_reentrant_start();
    test_dependency_never_running();

    CloseServiceHandle(hSC);
}
