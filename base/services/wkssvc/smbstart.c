/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Workstation service: demand start of the SMB client
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

/*
 * With the machine switch on (smbconn.h: smbengine\Parameters\ClientEnabled = 1) this service loads
 * the SMB mini-redirector (mrxsmb) when it starts, then waits on the engine device for the
 * redirector to need an engine (a user's first UNC path or net use) and starts the engine service
 * then. Users need no right to start services (Windows grants interactive users no SERVICE_START
 * on LanmanWorkstation either): the starting is done here, as SYSTEM, and only the two services
 * named in the code are started. With the switch off nothing of the SMB client is loaded.
 */

#include "precomp.h"
#include <winioctl.h>
#include <drivers/smbrdr/smbupcall.h>
#include <drivers/smbrdr/smbconn.h>

WINE_DEFAULT_DEBUG_CHANNEL(wkssvc);

static HANDLE StarterThread;
static volatile LONG StarterStop;

static
BOOL
ClientEnabled(VOID)
{
    DWORD Value = 0, Size = sizeof(Value), Type;
    HKEY Key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SMBCONN_SWITCH_KEY, 0, KEY_READ, &Key) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(Key, SMBCONN_SWITCH_VALUE, NULL, &Type, (LPBYTE)&Value, &Size) != ERROR_SUCCESS ||
        Type != REG_DWORD)
        Value = 0;
    RegCloseKey(Key);
    return Value == 1;
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
        CloseHandle(Device);
    CloseServiceHandle(Manager);
    return 0;
}

VOID
StartSmbClientStarter(VOID)
{
    if (!ClientEnabled())
        return;
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
