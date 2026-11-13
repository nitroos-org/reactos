/*
 * PROJECT:     ReactOS net.exe Tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     NET START hands the service its own name and the arguments typed after it, nothing else
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The test registers a service whose image is this executable. The service records the vector it
 * gets in ServiceMain into a file; the test starts it with net.exe and checks the vector: the service name
 * as argv[0], the typed arguments after it. (A program that takes its configuration from the start
 * arguments, such as a database listener that treats argv[1] as the name of the listener, sees the
 * difference.)
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <winsvc.h>
#include <stdio.h>
#include <string.h>

static char **argv;
static int argc;

/* Service process */
static SERVICE_STATUS_HANDLE g_hStatus;
static HANDLE g_hStop;
static char g_Name[100];
static WCHAR g_NameW[100];

static void SetState(DWORD state)
{
    SERVICE_STATUS st = { SERVICE_WIN32_OWN_PROCESS, state, state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0, 0, 0, 0, 0 };

    SetServiceStatus(g_hStatus, &st);
}

static VOID WINAPI Handler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP)
    {
        SetState(SERVICE_STOP_PENDING);
        SetEvent(g_hStop);
    }
}

/* The result file sits next to the executable: the service runs as another account than the test, with another temp directory */
static void ResultPath(const char *name, char *path)
{
    char *slash;

    GetModuleFileNameA(NULL, path, MAX_PATH);
    slash = strrchr(path, 92);
    if (slash)
        slash[1] = 0;
    strcat(path, name);
    strcat(path, ".txt");
}

static void WINAPI ServiceMainW(DWORD n, WCHAR **v)
{
    char path[MAX_PATH], line[256];
    DWORD i, cb;
    HANDLE h;

    g_hStatus = RegisterServiceCtrlHandlerW(g_NameW, Handler);
    if (!g_hStatus)
        return;
    g_hStop = CreateEventW(NULL, TRUE, FALSE, NULL);

    ResultPath(g_Name, path);
    h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        sprintf(line, "argc=%lu\n", n);
        WriteFile(h, line, (DWORD)strlen(line), &cb, NULL);
        for (i = 0; i < n; i++)
        {
            sprintf(line, "argv%lu=%ls\n", i, v[i]);
            WriteFile(h, line, (DWORD)strlen(line), &cb, NULL);
        }
        CloseHandle(h);
    }
    SetState(SERVICE_RUNNING);
    WaitForSingleObject(g_hStop, 60000);
    SetState(SERVICE_STOPPED);
}

static void ServiceProcess(void)
{
    SERVICE_TABLE_ENTRYW tbl[] = { { g_NameW, ServiceMainW }, { NULL, NULL } };

    StartServiceCtrlDispatcherW(tbl);
}

/* Test process */
static BOOL RunNetStart(const char *args, DWORD *code)
{
    char cmd[512];
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HANDLE hNul;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

    hNul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = hNul;
    sprintf(cmd, "net.exe start %s", args);
    *code = 99;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        CloseHandle(hNul);
        return FALSE;
    }
    if (WaitForSingleObject(pi.hProcess, 60000) != WAIT_OBJECT_0)
        TerminateProcess(pi.hProcess, 98);
    GetExitCodeProcess(pi.hProcess, code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hNul);
    return TRUE;
}

static void StopAndWait(SC_HANDLE svc)
{
    SERVICE_STATUS st;
    DWORD i;

    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    for (i = 0; i < 100; i++)
    {
        if (!QueryServiceStatus(svc, &st) || st.dwCurrentState == SERVICE_STOPPED)
            break;
        Sleep(100);
    }
}

static void Case(SC_HANDLE scm, const char *extra, int expected_argc, const char *a1, const char *a2)
{
    char name[100], args[256], path[MAX_PATH], text[1024], exp[100];
    WCHAR nameW[100], cmdW[MAX_PATH + 200], modW[MAX_PATH];
    SC_HANDLE svc;
    DWORD code, cb = 0;
    HANDLE h;

    sprintf(name, "NetStartArgs%lu", GetTickCount());
    MultiByteToWideChar(CP_ACP, 0, name, -1, nameW, 100);
    GetModuleFileNameW(NULL, modW, MAX_PATH);
    _snwprintf(cmdW, sizeof(cmdW) / sizeof(WCHAR), L"\"%ls\" NetStartArgs %ls", modW, nameW);
    svc = CreateServiceW(scm, nameW, nameW, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                         SERVICE_ERROR_IGNORE, cmdW, NULL, NULL, NULL, NULL, NULL);
    if (!svc)
    {
        skip("CreateService failed: %lu\n", GetLastError());
        return;
    }

    sprintf(args, "%s %s", name, extra);
    ResultPath(name, path);
    DeleteFileA(path);
    ok(RunNetStart(args, &code), "net.exe did not start\n");
    ok(code == 0, "net start %s: exit code %lu\n", args, code);

    text[0] = 0;
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(h != INVALID_HANDLE_VALUE, "no result file of the service, net start %s\n", args);
    if (h != INVALID_HANDLE_VALUE)
    {
        ReadFile(h, text, sizeof(text) - 1, &cb, NULL);
        CloseHandle(h);
        text[cb] = 0;
    }
    sprintf(exp, "argc=%d\n", expected_argc);
    ok(strncmp(text, exp, strlen(exp)) == 0, "net start %s: service got %.200s, expected %s", args, text, exp);
    sprintf(exp, "argv0=%s\n", name);
    ok(strstr(text, exp) != NULL, "net start %s: argv0 is not the service name: %.200s\n", args, text);
    if (a1)
    {
        sprintf(exp, "argv1=%s\n", a1);
        ok(strstr(text, exp) != NULL, "net start %s: no argv1=%s: %.200s\n", args, a1, text);
    }
    if (a2)
    {
        sprintf(exp, "argv2=%s\n", a2);
        ok(strstr(text, exp) != NULL, "net start %s: no argv2=%s: %.200s\n", args, a2, text);
    }

    StopAndWait(svc);
    DeleteService(svc);
    CloseServiceHandle(svc);
    DeleteFileA(path);
}

START_TEST(NetStartArgs)
{
    SC_HANDLE scm;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3)
    {
        strcpy(g_Name, argv[2]);
        MultiByteToWideChar(CP_ACP, 0, g_Name, -1, g_NameW, 100);
        ServiceProcess();
        return;
    }

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        skip("OpenSCManager failed: %lu\n", GetLastError());
        return;
    }

    /* No arguments: the vector is the service name alone */
    Case(scm, "", 1, NULL, NULL);
    /* Typed arguments follow the name */
    Case(scm, "x", 2, "x", NULL);
    Case(scm, "LISTENER y", 3, "LISTENER", "y");

    CloseServiceHandle(scm);
}
