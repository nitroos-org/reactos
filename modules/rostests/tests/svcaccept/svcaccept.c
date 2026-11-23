/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Own probe of the service control manager: which accepted-controls bits SetServiceStatus
 *              takes, which controls a service gets at a shutdown and a restart, and the preshutdown
 *              timeout of a service.
 *
 *                svcaccept svc NAME FILE bits               one row per accepted-controls value: the
 *                                                           SetServiceStatus result and error and the state
 *                                                           the SCM shows (QueryServiceStatusEx on itself)
 *                svcaccept svc NAME FILE ctl MASK DELAYMS [keep]
 *                                                           accepts MASK, logs every control with the tick
 *                                                           count, answers a stop, shutdown or preshutdown
 *                                                           with STOP_PENDING for DELAYMS milliseconds and
 *                                                           then STOPPED; "keep": a preshutdown control is
 *                                                           only logged, the service keeps running;
 *                                                           "hang": it is logged and the handler never returns
 *                svcaccept cfg NAME                         SERVICE_CONFIG_PRESHUTDOWN_INFO of a service
 *                svcaccept setcfg NAME MS                   sets the preshutdown timeout of a service
 *
 *              Output: the file of "svc" (one line per event, flushed at once), stdout for "cfg".
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <windows.h>

#ifndef SERVICE_CONTROL_PRESHUTDOWN
#define SERVICE_CONTROL_PRESHUTDOWN 0x0000000F
#endif
#ifndef SERVICE_CONFIG_PRESHUTDOWN_INFO
#define SERVICE_CONFIG_PRESHUTDOWN_INFO 7
#endif
#ifndef SC_STATUS_PROCESS_INFO
#define SC_STATUS_PROCESS_INFO 0
#endif

typedef struct _MY_PRESHUTDOWN_INFO
{
    DWORD dwPreshutdownTimeout;
} MY_PRESHUTDOWN_INFO;

static SERVICE_STATUS_HANDLE g_Status;
static SERVICE_STATUS g_State;
static char g_File[MAX_PATH] = "svcaccept.txt";
static char g_Name[256] = "svcacc";
static char g_Mode[16] = "";
static DWORD g_Mask = SERVICE_ACCEPT_STOP;
static DWORD g_Delay;
static BOOL g_Keep;     /* a preshutdown control is logged and the service keeps running */
static BOOL g_Hang;     /* a preshutdown control is logged and the handler never returns */
static HANDLE g_Stop;

static void
Log(const char *Format, ...)
{
    char Line[400];
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

static const char *
ControlName(DWORD Control)
{
    switch (Control)
    {
        case SERVICE_CONTROL_STOP: return "STOP";
        case SERVICE_CONTROL_PAUSE: return "PAUSE";
        case SERVICE_CONTROL_CONTINUE: return "CONTINUE";
        case SERVICE_CONTROL_INTERROGATE: return "INTERROGATE";
        case SERVICE_CONTROL_SHUTDOWN: return "SHUTDOWN";
        case SERVICE_CONTROL_PARAMCHANGE: return "PARAMCHANGE";
        case SERVICE_CONTROL_PRESHUTDOWN: return "PRESHUTDOWN";
    }
    return "other";
}

static DWORD WINAPI
CtlHandler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    DWORD Waited;

    (void)EventType; (void)EventData; (void)Context;

    Log("CONTROL %lu %s", Control, ControlName(Control));

    switch (Control)
    {
        case SERVICE_CONTROL_PRESHUTDOWN:
            if (g_Keep)
                return NO_ERROR;
            if (g_Hang)
            {
                Sleep(INFINITE);
                return NO_ERROR;
            }
            /* fall through */
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_STOP:
            if (g_Delay != 0)
            {
                g_State.dwCurrentState = SERVICE_STOP_PENDING;
                g_State.dwControlsAccepted = 0;
                for (Waited = 0; Waited < g_Delay; Waited += 1000)
                {
                    g_State.dwCheckPoint++;
                    g_State.dwWaitHint = 5000;
                    SetServiceStatus(g_Status, &g_State);
                    Sleep(g_Delay - Waited < 1000 ? g_Delay - Waited : 1000);
                }
            }
            g_State.dwCurrentState = SERVICE_STOPPED;
            g_State.dwControlsAccepted = 0;
            g_State.dwCheckPoint = 0;
            g_State.dwWaitHint = 0;
            SetServiceStatus(g_Status, &g_State);
            Log("STOPPED after %s", ControlName(Control));
            SetEvent(g_Stop);
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(g_Status, &g_State);
            return NO_ERROR;
    }
    return NO_ERROR;
}

static DWORD WINAPI
BitsHandler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    (void)EventType; (void)EventData; (void)Context;

    if (Control == SERVICE_CONTROL_STOP)
    {
        g_State.dwCurrentState = SERVICE_STOPPED;
        g_State.dwControlsAccepted = 0;
        SetServiceStatus(g_Status, &g_State);
        SetEvent(g_Stop);
    }
    else if (Control == SERVICE_CONTROL_INTERROGATE)
        SetServiceStatus(g_Status, &g_State);
    return NO_ERROR;
}

/* What the SCM shows for this service: state and accepted controls */
static void
Query(DWORD *State, DWORD *Accepted)
{
    SC_HANDLE Scm, Svc;
    SERVICE_STATUS_PROCESS Ssp;
    DWORD Needed;

    *State = 0xFFFFFFFF;
    *Accepted = 0xFFFFFFFF;
    Scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!Scm)
        return;
    Svc = OpenServiceA(Scm, g_Name, SERVICE_QUERY_STATUS);
    if (Svc)
    {
        if (QueryServiceStatusEx(Svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&Ssp, sizeof(Ssp), &Needed))
        {
            *State = Ssp.dwCurrentState;
            *Accepted = Ssp.dwControlsAccepted;
        }
        CloseServiceHandle(Svc);
    }
    CloseServiceHandle(Scm);
}

static void
BitsRows(void)
{
    static const DWORD Masks[] =
    {
        0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080,
        0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00002000, 0x00004000, 0x00008000,
        0x00010000, 0x00100000, 0x80000000, 0x00000104, 0x000007FF, 0x00000FFF, 0x0000FFFF, 0xFFFFFFFF, 0x00000000
    };
    DWORD i, State, Accepted, Err;
    BOOL Ok;

    for (i = 0; i < sizeof(Masks) / sizeof(Masks[0]); i++)
    {
        /* every row starts from the same reported state */
        g_State.dwCurrentState = SERVICE_RUNNING;
        g_State.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        Ok = SetServiceStatus(g_Status, &g_State);
        Err = Ok ? 0 : GetLastError();
        Query(&State, &Accepted);
        Log("RESET set=%d err=%lu state=%lu accepted=0x%lx", Ok, Err, State, Accepted);

        g_State.dwControlsAccepted = Masks[i];
        SetLastError(0);
        Ok = SetServiceStatus(g_Status, &g_State);
        Err = Ok ? 0 : GetLastError();
        Query(&State, &Accepted);
        Log("ROW mask=0x%lx set=%d err=%lu state=%lu accepted=0x%lx", Masks[i], Ok, Err, State, Accepted);
    }

    /* the same with a pending state: does the accepted mask matter there? */
    g_State.dwCurrentState = SERVICE_START_PENDING;
    g_State.dwControlsAccepted = SERVICE_ACCEPT_PRESHUTDOWN;
    g_State.dwCheckPoint = 5;
    g_State.dwWaitHint = 5000;
    Ok = SetServiceStatus(g_Status, &g_State);
    Err = Ok ? 0 : GetLastError();
    Query(&State, &Accepted);
    Log("ROW START_PENDING mask=0x100 set=%d err=%lu state=%lu accepted=0x%lx", Ok, Err, State, Accepted);
}

static VOID WINAPI
ServiceMain(DWORD Argc, LPSTR *Argv)
{
    (void)Argc; (void)Argv;

    g_Stop = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_Status = RegisterServiceCtrlHandlerExA(g_Name, strcmp(g_Mode, "bits") ? CtlHandler : BitsHandler, NULL);
    if (!g_Status)
    {
        Log("RegisterServiceCtrlHandlerEx failed %lu", GetLastError());
        return;
    }

    g_State.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_State.dwCurrentState = SERVICE_START_PENDING;
    g_State.dwControlsAccepted = 0;
    g_State.dwCheckPoint = 1;
    g_State.dwWaitHint = 3000;
    SetServiceStatus(g_Status, &g_State);

    if (!strcmp(g_Mode, "bits"))
    {
        Log("START bits");
        BitsRows();
        g_State.dwCurrentState = SERVICE_RUNNING;
        g_State.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        g_State.dwCheckPoint = 0;
        g_State.dwWaitHint = 0;
        SetServiceStatus(g_Status, &g_State);
    }
    else
    {
        g_State.dwCurrentState = SERVICE_RUNNING;
        g_State.dwControlsAccepted = g_Mask;
        g_State.dwCheckPoint = 0;
        g_State.dwWaitHint = 0;
        SetLastError(0);
        if (SetServiceStatus(g_Status, &g_State))
            Log("START mask=0x%lx delay=%lu", g_Mask, g_Delay);
        else
            Log("START mask=0x%lx SetServiceStatus failed %lu", g_Mask, GetLastError());
    }

    WaitForSingleObject(g_Stop, INFINITE);
}

static void
ShowConfig(const char *Name)
{
    SC_HANDLE Scm, Svc;
    MY_PRESHUTDOWN_INFO Info;
    DWORD Needed;

    Scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    Svc = Scm ? OpenServiceA(Scm, Name, SERVICE_QUERY_CONFIG) : NULL;
    if (!Svc)
    {
        printf("CFG %s open failed %lu\n", Name, GetLastError());
        return;
    }
    Info.dwPreshutdownTimeout = 0xDEADBEEF;
    if (QueryServiceConfig2A(Svc, SERVICE_CONFIG_PRESHUTDOWN_INFO, (LPBYTE)&Info, sizeof(Info), &Needed))
        printf("CFG %s preshutdown timeout %lu ms\n", Name, Info.dwPreshutdownTimeout);
    else
        printf("CFG %s QueryServiceConfig2 failed %lu\n", Name, GetLastError());
    CloseServiceHandle(Svc);
    CloseServiceHandle(Scm);
}

static void
SetConfig(const char *Name, DWORD Timeout)
{
    SC_HANDLE Scm, Svc;
    MY_PRESHUTDOWN_INFO Info;

    Scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    Svc = Scm ? OpenServiceA(Scm, Name, SERVICE_CHANGE_CONFIG) : NULL;
    if (!Svc)
    {
        printf("SETCFG %s open failed %lu\n", Name, GetLastError());
        return;
    }
    Info.dwPreshutdownTimeout = Timeout;
    if (ChangeServiceConfig2A(Svc, SERVICE_CONFIG_PRESHUTDOWN_INFO, &Info))
        printf("SETCFG %s preshutdown timeout %lu ms ok\n", Name, Timeout);
    else
        printf("SETCFG %s ChangeServiceConfig2 failed %lu\n", Name, GetLastError());
    CloseServiceHandle(Svc);
    CloseServiceHandle(Scm);
}

int
main(int argc, char **argv)
{
    SERVICE_TABLE_ENTRYA Table[2];

    if (argc >= 5 && !strcmp(argv[1], "svc"))
    {
        strncpy(g_Name, argv[2], sizeof(g_Name) - 1);
        strncpy(g_File, argv[3], sizeof(g_File) - 1);
        strncpy(g_Mode, argv[4], sizeof(g_Mode) - 1);
        if (argc >= 6)
            g_Mask = strtoul(argv[5], NULL, 16);
        if (argc >= 7)
            g_Delay = strtoul(argv[6], NULL, 10);
        g_Keep = argc >= 8 && !strcmp(argv[7], "keep");
        g_Hang = argc >= 8 && !strcmp(argv[7], "hang");
        Table[0].lpServiceName = g_Name;
        Table[0].lpServiceProc = ServiceMain;
        Table[1].lpServiceName = NULL;
        Table[1].lpServiceProc = NULL;
        if (!StartServiceCtrlDispatcherA(Table))
            Log("StartServiceCtrlDispatcher failed %lu", GetLastError());
        return 0;
    }
    if (argc >= 3 && !strcmp(argv[1], "cfg"))
    {
        ShowConfig(argv[2]);
        return 0;
    }
    if (argc >= 4 && !strcmp(argv[1], "setcfg"))
    {
        SetConfig(argv[2], strtoul(argv[3], NULL, 10));
        return 0;
    }

    printf("usage: svcaccept svc NAME FILE bits | svcaccept svc NAME FILE ctl MASK DELAYMS | svcaccept cfg NAME\n");
    return 1;
}
