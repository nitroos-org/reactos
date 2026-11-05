/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     RegisterPowerSettingNotification sends the present value of the setting to the window
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Windows 10 22H2: a window that registers for a power setting gets, once per registration, WM_POWERBROADCAST
 * with PBT_POWERSETTINGCHANGE and the value of the setting, after the registration has returned. Settings that
 * only report a change, and unknown ones, send nothing. */

#ifndef PBT_POWERSETTINGCHANGE
#define PBT_POWERSETTINGCHANGE 0x8013
#endif

typedef struct
{
    GUID PowerSetting;
    DWORD DataLength;
    UCHAR Data[1];
} PWR_SETTING;

typedef PVOID (WINAPI *PFN_REGISTER)(HANDLE, const GUID *, DWORD);
typedef BOOL (WINAPI *PFN_UNREGISTER)(PVOID);

static const GUID GuidAcDc = { 0x5d3e9a59, 0xe9d5, 0x4b00, { 0xa6, 0xbd, 0xff, 0x34, 0xff, 0x51, 0x65, 0x48 } };
static const GUID GuidPersonality = { 0x245d8541, 0x3943, 0x4422, { 0xb0, 0x25, 0x13, 0xa7, 0x84, 0xf6, 0x79, 0xb7 } };
static const GUID GuidBatteryPercent = { 0xa7ad8041, 0xb45a, 0x4cae, { 0x87, 0xa3, 0xee, 0xcb, 0xb4, 0x68, 0xa9, 0xe1 } };
static const GUID GuidAwayMode = { 0x98a7f580, 0x01f7, 0x48aa, { 0x9c, 0x0f, 0x44, 0x35, 0x2c, 0x29, 0xe5, 0xc0 } };
static const GUID GuidMonitorOn = { 0x02731015, 0x4510, 0x4526, { 0x99, 0xe6, 0xe5, 0xa1, 0x7e, 0xbd, 0x1a, 0xea } };
static const GUID GuidUserPresence = { 0x3c0f4548, 0xc03f, 0x4c4d, { 0xb9, 0xf2, 0x23, 0x7e, 0xde, 0x68, 0x63, 0x76 } };
static const GUID GuidConsoleDisplay = { 0x6fe69556, 0x704a, 0x47a0, { 0x8f, 0x24, 0xc2, 0x8d, 0x93, 0x6f, 0xda, 0x47 } };
static const GUID GuidUnknown = { 0x12345678, 0x1234, 0x1234, { 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34 } };

static INT g_cMessages;
static GUID g_Guid;
static DWORD g_DataLength;
static DWORD g_Value;
static WPARAM g_wParam;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_POWERBROADCAST && wParam == PBT_POWERSETTINGCHANGE)
    {
        PWR_SETTING *s = (PWR_SETTING *)lParam;
        g_cMessages++;
        g_wParam = wParam;
        g_Guid = s->PowerSetting;
        g_DataLength = s->DataLength;
        g_Value = 0;
        if (s->DataLength >= sizeof(DWORD))
            memcpy(&g_Value, s->Data, sizeof(DWORD));
        return TRUE;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static void Pump(DWORD Ms)
{
    MSG Msg;
    DWORD Start = GetTickCount();

    while (GetTickCount() - Start < Ms)
    {
        while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&Msg);
        Sleep(10);
    }
}

static void Reset(void)
{
    g_cMessages = 0;
    ZeroMemory(&g_Guid, sizeof(g_Guid));
    g_DataLength = 0;
    g_Value = 0xdeadbeef;
}

START_TEST(PowerSettingNotification)
{
    WNDCLASSW wc = { 0 };
    HWND hwnd;
    HMODULE hUser = GetModuleHandleW(L"user32.dll");
    PFN_REGISTER pRegister = (PFN_REGISTER)GetProcAddress(hUser, "RegisterPowerSettingNotification");
    PFN_UNREGISTER pUnregister = (PFN_UNREGISTER)GetProcAddress(hUser, "UnregisterPowerSettingNotification");
    PVOID h1, h2, h3;

    if (!pRegister || !pUnregister)
    {
        skip("RegisterPowerSettingNotification is not available\n");
        return;
    }

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"PowerSettingNotificationTest";
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed\n");
    hwnd = CreateWindowExW(0, wc.lpszClassName, L"power", WS_POPUP, 0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);
    ok(hwnd != NULL, "window not created\n");
    if (!hwnd)
        return;

    /* A setting with a value: the AC/DC power source (0 is AC), once, after the call */
    Reset();
    h1 = pRegister(hwnd, &GuidAcDc, DEVICE_NOTIFY_WINDOW_HANDLE);
    ok(h1 != NULL, "RegisterPowerSettingNotification failed, error %lu\n", GetLastError());
    ok_int(g_cMessages, 0);   /* nothing inside the call, the notification follows */
    Pump(300);
    ok_int(g_cMessages, 1);
    ok(IsEqualGUID(&g_Guid, &GuidAcDc), "setting %08lx\n", g_Guid.Data1);
    ok_int(g_wParam == PBT_POWERSETTINGCHANGE, 1);
    ok_int(g_DataLength, 4);
    ok(g_Value <= 2, "AC/DC value %lu\n", g_Value);

    /* The scheme type is a GUID */
    Reset();
    h2 = pRegister(hwnd, &GuidPersonality, DEVICE_NOTIFY_WINDOW_HANDLE);
    ok(h2 != NULL, "RegisterPowerSettingNotification failed\n");
    Pump(300);
    ok_int(g_cMessages, 1);
    ok(IsEqualGUID(&g_Guid, &GuidPersonality), "setting %08lx\n", g_Guid.Data1);
    ok_int(g_DataLength, 16);
    if (h2)
        ok(pUnregister(h2), "UnregisterPowerSettingNotification failed\n");

    /* The monitor is on */
    Reset();
    h2 = pRegister(hwnd, &GuidMonitorOn, DEVICE_NOTIFY_WINDOW_HANDLE);
    Pump(300);
    ok_int(g_cMessages, 1);
    ok(IsEqualGUID(&g_Guid, &GuidMonitorOn), "setting %08lx\n", g_Guid.Data1);
    ok_int(g_DataLength, 4);
    ok_int(g_Value, 1);
    if (h2)
        pUnregister(h2);

    Reset();
    h2 = pRegister(hwnd, &GuidConsoleDisplay, DEVICE_NOTIFY_WINDOW_HANDLE);
    Pump(300);
    ok_int(g_cMessages, 1);
    ok_int(g_DataLength, 4);
    ok_int(g_Value, 1);
    if (h2)
        pUnregister(h2);

    /* The user presence: 0 present, 1 not present, 2 inactive */
    Reset();
    h2 = pRegister(hwnd, &GuidUserPresence, DEVICE_NOTIFY_WINDOW_HANDLE);
    Pump(300);
    ok_int(g_cMessages, 1);
    ok_int(g_DataLength, 4);
    ok(g_Value <= 2, "presence %lu\n", g_Value);
    if (h2)
        pUnregister(h2);

    /* Settings that only report a change, and an unknown one: a handle, no message */
    Reset();
    h2 = pRegister(hwnd, &GuidBatteryPercent, DEVICE_NOTIFY_WINDOW_HANDLE);
    h3 = pRegister(hwnd, &GuidAwayMode, DEVICE_NOTIFY_WINDOW_HANDLE);
    ok(h2 != NULL && h3 != NULL, "no handle for a setting without a value\n");
    if (h2)
        pUnregister(h2);
    if (h3)
        pUnregister(h3);
    h2 = pRegister(hwnd, &GuidUnknown, DEVICE_NOTIFY_WINDOW_HANDLE);
    ok(h2 != NULL, "no handle for an unknown setting\n");
    Pump(300);
    ok_int(g_cMessages, 0);
    if (h2)
        pUnregister(h2);

    /* The same setting again is told again, also after the first registration ended */
    Reset();
    h2 = pRegister(hwnd, &GuidAcDc, DEVICE_NOTIFY_WINDOW_HANDLE);
    Pump(300);
    ok_int(g_cMessages, 1);
    if (h2)
        pUnregister(h2);
    ok(pUnregister(h1), "UnregisterPowerSettingNotification failed\n");
    Reset();
    h1 = pRegister(hwnd, &GuidAcDc, DEVICE_NOTIFY_WINDOW_HANDLE);
    Pump(300);
    ok_int(g_cMessages, 1);
    if (h1)
        pUnregister(h1);

    /* A NULL recipient and the desktop window: a handle all the same */
    h1 = pRegister(NULL, &GuidAcDc, DEVICE_NOTIFY_WINDOW_HANDLE);
    ok(h1 != NULL, "no handle for a NULL recipient\n");
    if (h1)
        pUnregister(h1);
    h1 = pRegister(GetDesktopWindow(), &GuidAcDc, DEVICE_NOTIFY_WINDOW_HANDLE);
    ok(h1 != NULL, "no handle for the desktop window\n");
    if (h1)
        pUnregister(h1);

    /* Nothing arrives after the window is gone */
    DestroyWindow(hwnd);
    Pump(50);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
