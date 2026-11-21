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
    WCHAR name[64], args[32];

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

    CloseServiceHandle(hSC);
}
