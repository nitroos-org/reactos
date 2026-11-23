/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The service control manager sends controls to a service through the control pipe of the
 *              service's image; the process of the service may end while a control is on its way.
 *
 *                svcimage svc NAME FILE [die]      a service that accepts stop, parameter change and
 *                                                  shutdown, logs every control with the tick count and
 *                                                  answers them; "die": ends its process at once on a
 *                                                  shutdown control, without an answer
 *                svcimage stress NAME ROUNDS       start the service NAME (installed with "svc"), send
 *                                                  controls from four threads and end its process with
 *                                                  TerminateProcess, ROUNDS times; services.exe must stay
 *                                                  alive and every round must end with the service stopped
 *
 *              Output: the file of "svc" (one line per event, flushed at once), stdout for "stress"
 *              (STRESS-PASS or STRESS-FAIL).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#ifndef SC_STATUS_PROCESS_INFO
#define SC_STATUS_PROCESS_INFO 0
#endif

static SERVICE_STATUS_HANDLE g_Status;
static SERVICE_STATUS g_State;
static char g_File[MAX_PATH] = "svcimage.txt";
static char g_Name[256] = "svcimg";
static BOOL g_Die;
static HANDLE g_Stop;

static void
Log(const char *Format, ...)
{
    char Line[300];
    DWORD Written;
    HANDLE File;
    va_list Args;
    int Length;

    Length = _snprintf(Line, sizeof(Line) - 2, "%lu ", GetTickCount());
    va_start(Args, Format);
    Length += _vsnprintf(Line + Length, sizeof(Line) - 2 - Length, Format, Args);
    va_end(Args);
    Line[Length++] = '\r';
    Line[Length++] = '\n';

    File = CreateFileA(g_File, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return;
    WriteFile(File, Line, Length, &Written, NULL);
    FlushFileBuffers(File);
    CloseHandle(File);
}

static DWORD WINAPI
Handler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    (void)EventType; (void)EventData; (void)Context;

    if (Control == SERVICE_CONTROL_SHUTDOWN || Control == SERVICE_CONTROL_STOP)
        Log("CONTROL %lu", Control);

    switch (Control)
    {
        case SERVICE_CONTROL_SHUTDOWN:
            if (g_Die)
                ExitProcess(1);
            /* fall through */
        case SERVICE_CONTROL_STOP:
            g_State.dwCurrentState = SERVICE_STOPPED;
            g_State.dwControlsAccepted = 0;
            SetServiceStatus(g_Status, &g_State);
            SetEvent(g_Stop);
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(g_Status, &g_State);
            return NO_ERROR;
    }
    return NO_ERROR;
}

static VOID WINAPI
ServiceMain(DWORD Argc, LPSTR *Argv)
{
    (void)Argc; (void)Argv;

    g_Stop = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_Status = RegisterServiceCtrlHandlerExA(g_Name, Handler, NULL);
    if (!g_Status)
        return;

    g_State.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_State.dwCurrentState = SERVICE_RUNNING;
    g_State.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE;
    SetServiceStatus(g_Status, &g_State);
    Log("START die=%d", g_Die);

    WaitForSingleObject(g_Stop, INFINITE);
}

/* ---- stress ---- */

static volatile LONG g_Quit;
static char g_Target[256];
static volatile LONG g_Sent;

static DWORD WINAPI
Sender(LPVOID Param)
{
    SC_HANDLE Scm, Svc;
    SERVICE_STATUS St;
    DWORD Which = (DWORD)(ULONG_PTR)Param;

    Scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!Scm)
        return 1;
    while (!g_Quit)
    {
        Svc = OpenServiceA(Scm, g_Target, SERVICE_INTERROGATE | SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS);
        if (Svc)
        {
            ControlService(Svc, (Which & 1) ? SERVICE_CONTROL_PARAMCHANGE : SERVICE_CONTROL_INTERROGATE, &St);
            InterlockedIncrement(&g_Sent);
            CloseServiceHandle(Svc);
        }
    }
    CloseServiceHandle(Scm);
    return 0;
}

static DWORD
FindProcess(const char *Exe)
{
    PROCESSENTRY32 Pe;
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD Pid = 0;

    Pe.dwSize = sizeof(Pe);
    if (Snap != INVALID_HANDLE_VALUE && Process32First(Snap, &Pe))
    {
        do
        {
            if (!_stricmp(Pe.szExeFile, Exe))
            {
                Pid = Pe.th32ProcessID;
                break;
            }
        } while (Process32Next(Snap, &Pe));
    }
    if (Snap != INVALID_HANDLE_VALUE)
        CloseHandle(Snap);
    return Pid;
}

static int
Stress(const char *Name, int Rounds)
{
    SC_HANDLE Scm, Svc;
    SERVICE_STATUS_PROCESS Ssp;
    DWORD Needed, Pid, i, Round, Waits, ScmPid;
    HANDLE Threads[4], Proc;
    int Started = 0, Killed = 0, NotStarted = 0, Bad = 0;

    strncpy(g_Target, Name, sizeof(g_Target) - 1);
    ScmPid = FindProcess("services.exe");
    printf("STRESS services.exe pid %lu\n", ScmPid);

    Scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    Svc = Scm ? OpenServiceA(Scm, Name, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP) : NULL;
    if (!Svc)
    {
        printf("STRESS open %s failed %lu\n", Name, GetLastError());
        return 2;
    }

    for (Round = 0; Round < (DWORD)Rounds; Round++)
    {
        if (!StartServiceA(Svc, 0, NULL))
        {
            NotStarted++;
            Sleep(50);
            continue;
        }
        Started++;

        /* wait until it runs, then read its process id */
        Pid = 0;
        for (Waits = 0; Waits < 200; Waits++)
        {
            if (QueryServiceStatusEx(Svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&Ssp, sizeof(Ssp), &Needed) &&
                Ssp.dwCurrentState == SERVICE_RUNNING)
            {
                Pid = Ssp.dwProcessId;
                break;
            }
            Sleep(25);
        }

        g_Quit = 0;
        for (i = 0; i < 4; i++)
            Threads[i] = CreateThread(NULL, 0, Sender, (LPVOID)(ULONG_PTR)i, 0, NULL);

        /* let the controls start, then end the process under them */
        Sleep(20 + (Round % 7) * 10);
        if (Pid != 0)
        {
            Proc = OpenProcess(PROCESS_TERMINATE, FALSE, Pid);
            if (Proc)
            {
                if (TerminateProcess(Proc, 1))
                    Killed++;
                CloseHandle(Proc);
            }
        }
        Sleep(30);
        g_Quit = 1;
        WaitForMultipleObjects(4, Threads, TRUE, 20000);
        for (i = 0; i < 4; i++)
            CloseHandle(Threads[i]);

        /* the SCM sees the service stopped */
        for (Waits = 0; Waits < 400; Waits++)
        {
            if (QueryServiceStatusEx(Svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&Ssp, sizeof(Ssp), &Needed) &&
                Ssp.dwCurrentState == SERVICE_STOPPED)
                break;
            Sleep(25);
        }
        if (FindProcess("services.exe") != ScmPid)
        {
            printf("STRESS services.exe ENDED in round %lu\n", Round);
            printf("STRESS-FAIL\n");
            return 1;
        }
        if (Ssp.dwCurrentState != SERVICE_STOPPED)
        {
            printf("STRESS round %lu: service not stopped (state %lu)\n", Round, Ssp.dwCurrentState);
            Bad++;
        }
    }

    printf("STRESS rounds=%d started=%d not-started=%d killed=%d controls=%ld not-stopped=%d services.exe %s\n",
           Rounds, Started, NotStarted, Killed, g_Sent, Bad,
           (ScmPid != 0 && FindProcess("services.exe") == ScmPid) ? "ALIVE" : "GONE");
    printf("STRESS-%s\n", (ScmPid != 0 && FindProcess("services.exe") == ScmPid && Started == Killed && Bad == 0) ? "PASS" : "FAIL");
    return 0;
}

int
main(int argc, char **argv)
{
    SERVICE_TABLE_ENTRYA Table[2];

    if (argc >= 4 && !strcmp(argv[1], "svc"))
    {
        strncpy(g_Name, argv[2], sizeof(g_Name) - 1);
        strncpy(g_File, argv[3], sizeof(g_File) - 1);
        g_Die = argc >= 5 && !strcmp(argv[4], "die");
        Table[0].lpServiceName = g_Name;
        Table[0].lpServiceProc = ServiceMain;
        Table[1].lpServiceName = NULL;
        Table[1].lpServiceProc = NULL;
        if (!StartServiceCtrlDispatcherA(Table))
            Log("StartServiceCtrlDispatcher failed %lu", GetLastError());
        return 0;
    }
    if (argc >= 4 && !strcmp(argv[1], "stress"))
        return Stress(argv[2], atoi(argv[3]));

    printf("usage: svcimage svc NAME FILE [die] | svcimage stress NAME ROUNDS\n");
    return 1;
}
