/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A service that writes the controls it receives to a file, to see
 *              from the next boot whether the service control manager told it
 *              about a shutdown or a restart.
 *
 *                sc create svcsd binPath= "C:\harness\svcshutdown.exe svc C:\harness\out\svcsd.txt [pre]" start= auto
 *
 *              One line per event, flushed to the disk at once: START, CONTROL <n> (<name>), STOPPED.
 *              Accepts stop and shutdown; "pre" also accepts preshutdown, and reports
 *              what it gets.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <windows.h>

#ifndef SERVICE_CONTROL_PRESHUTDOWN
#define SERVICE_CONTROL_PRESHUTDOWN 0x0000000F
#endif

static SERVICE_STATUS_HANDLE g_Status;
static SERVICE_STATUS g_State;
static char g_File[MAX_PATH] = "C:\\harness\\out\\svcsd.txt";
static BOOL g_Pre;
static HANDLE g_Stop;

static void
Log(const char *Format, ...)
{
    char Line[256];
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
    /* The file must survive the restart that follows */
    FlushFileBuffers(File);
    CloseHandle(File);
}

static const char *
ControlName(DWORD Control)
{
    switch (Control)
    {
        case SERVICE_CONTROL_STOP: return "STOP";
        case SERVICE_CONTROL_SHUTDOWN: return "SHUTDOWN";
        case SERVICE_CONTROL_PRESHUTDOWN: return "PRESHUTDOWN";
        case SERVICE_CONTROL_INTERROGATE: return "INTERROGATE";
    }
    return "other";
}

static DWORD WINAPI
Handler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    (void)EventType; (void)EventData; (void)Context;

    Log("CONTROL %lu %s", Control, ControlName(Control));

    switch (Control)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_PRESHUTDOWN:
            g_State.dwCurrentState = SERVICE_STOPPED;
            g_State.dwControlsAccepted = 0;
            SetServiceStatus(g_Status, &g_State);
            Log("STOPPED after %s", ControlName(Control));
            SetEvent(g_Stop);
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(g_Status, &g_State);
            return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static VOID WINAPI
ServiceMain(DWORD Argc, LPSTR *Argv)
{
    (void)Argc; (void)Argv;

    g_Stop = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_Status = RegisterServiceCtrlHandlerExA("svcsd", Handler, NULL);
    if (!g_Status)
    {
        Log("RegisterServiceCtrlHandlerEx failed %lu", GetLastError());
        return;
    }

    g_State.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_State.dwCurrentState = SERVICE_RUNNING;
    g_State.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN |
                                 (g_Pre ? SERVICE_ACCEPT_PRESHUTDOWN : 0);
    SetServiceStatus(g_Status, &g_State);
    Log("START pre=%d", g_Pre);

    WaitForSingleObject(g_Stop, INFINITE);
}

int
main(int argc, char **argv)
{
    static SERVICE_TABLE_ENTRYA Table[] = { { "svcsd", ServiceMain }, { NULL, NULL } };

    if (argc >= 3 && !strcmp(argv[1], "svc"))
    {
        strncpy(g_File, argv[2], sizeof(g_File) - 1);
        g_Pre = argc >= 4 && !strcmp(argv[3], "pre");
        if (!StartServiceCtrlDispatcherA(Table))
            Log("StartServiceCtrlDispatcher failed %lu", GetLastError());
        return 0;
    }

    printf("usage: svcshutdown svc <file> [pre]\n");
    return 1;
}
