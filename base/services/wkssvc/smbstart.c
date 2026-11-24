/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Workstation service: demand start of the SMB client
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

/*
 * This service loads the SMB mini-redirector (mrxsmb) when it starts, so that MUP can hand UNC
 * paths to it, then waits on the engine device for the redirector to need an engine (a user's
 * first UNC path or net use) and starts the engine service then. Nothing of the client connects
 * or listens before that. Users need no right to start services (Windows grants interactive users
 * no SERVICE_START on LanmanWorkstation either): the starting is done here, as SYSTEM, and only
 * the two services named in the code are started.
 */

#include "precomp.h"
#include <winioctl.h>
#include <drivers/smbrdr/smbupcall.h>

WINE_DEFAULT_DEBUG_CHANNEL(wkssvc);

static HANDLE StarterThread;
static volatile LONG StarterStop;

/*
 * Earlier builds kept the client off unless smbengine\Parameters\ClientEnabled was 1. The client
 * is always available now; an installation that still has the value (whatever it says) loses it.
 */
static
VOID
RemoveObsoleteSwitch(VOID)
{
    HKEY Key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services\\smbengine\\Parameters",
                      0, KEY_SET_VALUE, &Key) != ERROR_SUCCESS)
        return;
    RegDeleteValueW(Key, L"ClientEnabled");
    RegCloseKey(Key);
}

static
DWORD
StartNamedService(SC_HANDLE Manager, LPCWSTR Name)
{
    SC_HANDLE Service = OpenServiceW(Manager, Name, SERVICE_START);
    DWORD Error = ERROR_SUCCESS;

    if (Service == NULL)
        return GetLastError();
    if (!StartServiceW(Service, 0, NULL))
    {
        Error = GetLastError();
        if (Error == ERROR_SERVICE_ALREADY_RUNNING)
            Error = ERROR_SUCCESS;
    }
    CloseServiceHandle(Service);
    return Error;
}

static
VOID
CALLBACK
StarterWake(ULONG_PTR Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
}

static
DWORD
WINAPI
StarterMain(LPVOID Parameter)
{
    SC_HANDLE Manager;
    HANDLE Device = INVALID_HANDLE_VALUE;
    DWORD Error, Got;

    UNREFERENCED_PARAMETER(Parameter);

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (Manager == NULL)
    {
        ERR("SMB client: no service manager (%lu)\n", GetLastError());
        return 1;
    }
    Error = StartNamedService(Manager, L"mrxsmb");
    if (Error != ERROR_SUCCESS)
    {
        ERR("SMB client: mrxsmb not started (%lu)\n", Error);
        CloseServiceHandle(Manager);
        return 1;
    }

    while (!StarterStop)
    {
        if (Device == INVALID_HANDLE_VALUE)
        {
            Device = CreateFileW(NITRO_SMBRDR_ENGINE_DOS_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                 OPEN_EXISTING, 0, NULL);
            if (Device == INVALID_HANDLE_VALUE)
            {
                ERR("SMB client: engine device not opened (%lu)\n", GetLastError());
                SleepEx(5000, TRUE);
                continue;
            }
        }
        /* Returns when a request needs an engine, after 5 minutes, or when woken for the stop */
        if (DeviceIoControl(Device, IOCTL_SMBRDR_WAIT_ENGINE_NEEDED, NULL, 0, NULL, 0, &Got, NULL))
        {
            Error = StartNamedService(Manager, L"smbengine");
            TRACE("SMB client: engine started on demand (%lu)\n", Error);
            if (Error != ERROR_SUCCESS)
            {
                ERR("SMB client: smbengine not started (%lu)\n", Error);
                /* Tell the redirector: its waiting requests fail at once, later ones without waiting */
                DeviceIoControl(Device, IOCTL_SMBRDR_ENGINE_START_FAILED, &Error, sizeof(Error), NULL, 0, &Got, NULL);
                SleepEx(1000, TRUE);
            }
            continue;
        }
        Error = GetLastError();
        if (Error != ERROR_SEM_TIMEOUT && Error != ERROR_TIMEOUT && Error != ERROR_SERVICE_ALREADY_RUNNING &&
            !StarterStop)
        {
            /* ERROR_SERVICE_ALREADY_RUNNING: an engine attached meanwhile; anything else: wait a little */
            SleepEx(1000, TRUE);
        }
    }
    if (Device != INVALID_HANDLE_VALUE)
    {
        /* Going away (the Workstation service stops): a request that was waiting for this starter fails now */
        Error = ERROR_SERVICE_NOT_ACTIVE;
        DeviceIoControl(Device, IOCTL_SMBRDR_ENGINE_START_FAILED, &Error, sizeof(Error), NULL, 0, &Got, NULL);
        CloseHandle(Device);
    }
    CloseServiceHandle(Manager);
    return 0;
}

VOID
StartSmbClientStarter(VOID)
{
    RemoveObsoleteSwitch();
    InterlockedExchange(&StarterStop, 0);
    StarterThread = CreateThread(NULL, 0, StarterMain, NULL, 0, NULL);
    if (StarterThread == NULL)
        ERR("SMB client: starter thread not created (%lu)\n", GetLastError());
}

VOID
StopSmbClientStarter(VOID)
{
    if (StarterThread == NULL)
        return;
    InterlockedExchange(&StarterStop, 1);
    /* The wait in the driver is alertable */
    QueueUserAPC(StarterWake, StarterThread, 0);
    WaitForSingleObject(StarterThread, 10000);
    CloseHandle(StarterThread);
    StarterThread = NULL;
}
