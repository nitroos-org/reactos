/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for RegisterDeviceNotification with a window
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <dbt.h>

START_TEST(RegisterDeviceNotification)
{
    DEV_BROADCAST_DEVICEINTERFACE_W Filter;
    HDEVNOTIFY hNotify;
    HWND hWnd;

    hWnd = CreateWindowExW(0, L"STATIC", L"notify", WS_OVERLAPPED, 0, 0, 10, 10, NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (!hWnd)
    {
        skip("No window (%lu)\n", GetLastError());
        return;
    }

    /* A 32-bit process on 64-bit Windows registers with the 64-bit plug and play service */
    ZeroMemory(&Filter, sizeof(Filter));
    Filter.dbcc_size = sizeof(Filter);
    Filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    SetLastError(0xDEADBEEF);
    hNotify = RegisterDeviceNotificationW(hWnd, &Filter, DEVICE_NOTIFY_WINDOW_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);
    ok(hNotify != NULL, "RegisterDeviceNotification failed, error %lu\n", GetLastError());
    if (hNotify)
        ok_int(UnregisterDeviceNotification(hNotify), TRUE);

    DestroyWindow(hWnd);
}
