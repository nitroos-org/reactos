/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Every display mode the adapters list can be set and left again, while windows are drawn
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A mode change creates a new device for the display driver, sets the new mode, maps the frame buffer,
 * and then asserts the mode once more on the device that stays. A miniport that moves its frame buffer
 * on the second mode set leaves the display driver drawing through the old mapping into memory that is
 * no longer the frame buffer (virtio-gpu did, and the system stopped with pool corruption).
 * For each display attached to the desktop, the primary first, the test sets every listed mode of the
 * current colour depth, forces a reset of the same mode, draws from a second thread the whole time,
 * and checks that each mode is the current one afterwards.
 */

#include "precomp.h"

#define MAX_MODES 128

typedef struct _MODE_ENTRY
{
    DWORD Width;
    DWORD Height;
    DWORD Bpp;
} MODE_ENTRY;

static MODE_ENTRY g_Modes[MAX_MODES];
static ULONG g_ModeCount;
static volatile LONG g_StopDrawing;
static volatile LONG g_DrawCount;
static HWND g_hWnd;

static DWORD WINAPI
DrawThread(LPVOID Param)
{
    HDC hdc;
    RECT rc;
    HBRUSH hbr;
    ULONG n = 0;
    WCHAR Text[32];

    UNREFERENCED_PARAMETER(Param);

    while (!g_StopDrawing)
    {
        hdc = GetDC(g_hWnd);
        if (hdc)
        {
            GetClientRect(g_hWnd, &rc);
            hbr = CreateSolidBrush(RGB(n * 37, n * 11, 255 - n * 23));
            FillRect(hdc, &rc, hbr);
            DeleteObject(hbr);
            TextOutW(hdc, 4, 4, Text, wsprintfW(Text, L"draw %lu", n));
            MoveToEx(hdc, 0, 0, NULL);
            LineTo(hdc, rc.right, rc.bottom);
            BitBlt(hdc, rc.right / 2, rc.bottom / 2, rc.right / 2, rc.bottom / 2, hdc, 0, 0, SRCCOPY);
            ReleaseDC(g_hWnd, hdc);
            InterlockedIncrement(&g_DrawCount);
        }
        n++;
        Sleep(1);
    }
    return 0;
}

static BOOL
IsListed(DWORD Width, DWORD Height, DWORD Bpp)
{
    ULONG i;
    for (i = 0; i < g_ModeCount; i++)
    {
        if (g_Modes[i].Width == Width && g_Modes[i].Height == Height && g_Modes[i].Bpp == Bpp)
            return TRUE;
    }
    return FALSE;
}

static VOID
PumpMessages(VOID)
{
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

static BOOL
SetMode(PCWSTR Device, const MODE_ENTRY *Mode, DWORD Flags)
{
    DEVMODEW dm;
    LONG ret;

    ZeroMemory(&dm, sizeof(dm));
    dm.dmSize = sizeof(dm);
    dm.dmPelsWidth = Mode->Width;
    dm.dmPelsHeight = Mode->Height;
    dm.dmBitsPerPel = Mode->Bpp;
    dm.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL;
    ret = ChangeDisplaySettingsExW(Device, &dm, NULL, Flags, NULL);
    ok(ret == DISP_CHANGE_SUCCESSFUL, "%ls %lux%lux%lu (flags 0x%lx): ChangeDisplaySettingsEx returned %ld\n",
       Device, Mode->Width, Mode->Height, Mode->Bpp, Flags, ret);
    PumpMessages();
    return (ret == DISP_CHANGE_SUCCESSFUL);
}

static VOID
CheckCurrent(PCWSTR Device, BOOL Primary, const MODE_ENTRY *Mode)
{
    DEVMODEW dm;
    HDC hdc;

    ZeroMemory(&dm, sizeof(dm));
    dm.dmSize = sizeof(dm);
    ok(EnumDisplaySettingsW(Device, ENUM_CURRENT_SETTINGS, &dm), "%ls: EnumDisplaySettings(current) failed\n", Device);
    ok(dm.dmPelsWidth == Mode->Width && dm.dmPelsHeight == Mode->Height && dm.dmBitsPerPel == Mode->Bpp,
       "%ls: current mode %lux%lux%lu, expected %lux%lux%lu\n", Device,
       dm.dmPelsWidth, dm.dmPelsHeight, dm.dmBitsPerPel, Mode->Width, Mode->Height, Mode->Bpp);

    if (Primary)
    {
        ok_long(GetSystemMetrics(SM_CXSCREEN), (LONG)Mode->Width);
        ok_long(GetSystemMetrics(SM_CYSCREEN), (LONG)Mode->Height);
    }

    hdc = CreateDCW(L"DISPLAY", Device, NULL, NULL);
    ok(hdc != NULL, "%ls: CreateDC failed\n", Device);
    if (hdc)
    {
        ok_long(GetDeviceCaps(hdc, HORZRES), (LONG)Mode->Width);
        ok_long(GetDeviceCaps(hdc, VERTRES), (LONG)Mode->Height);
        DeleteDC(hdc);
    }
}

static ULONG
CycleDevice(PCWSTR Device, BOOL Primary)
{
    DEVMODEW dm;
    MODE_ENTRY Original;
    ULONG i, Changes = 0;
    DWORD iMode;
    LONG ret;

    ZeroMemory(&dm, sizeof(dm));
    dm.dmSize = sizeof(dm);
    if (!EnumDisplaySettingsW(Device, ENUM_CURRENT_SETTINGS, &dm))
    {
        skip("%ls: no current display mode\n", Device);
        return 0;
    }
    Original.Width = dm.dmPelsWidth;
    Original.Height = dm.dmPelsHeight;
    Original.Bpp = dm.dmBitsPerPel;

    /* The modes of the current colour depth, each size once */
    g_ModeCount = 0;
    for (iMode = 0; g_ModeCount < MAX_MODES; iMode++)
    {
        ZeroMemory(&dm, sizeof(dm));
        dm.dmSize = sizeof(dm);
        if (!EnumDisplaySettingsW(Device, iMode, &dm))
            break;
        if (dm.dmBitsPerPel != Original.Bpp)
            continue;
        if (IsListed(dm.dmPelsWidth, dm.dmPelsHeight, dm.dmBitsPerPel))
            continue;
        g_Modes[g_ModeCount].Width = dm.dmPelsWidth;
        g_Modes[g_ModeCount].Height = dm.dmPelsHeight;
        g_Modes[g_ModeCount].Bpp = dm.dmBitsPerPel;
        g_ModeCount++;
    }
    ok(IsListed(Original.Width, Original.Height, Original.Bpp),
       "%ls: the current mode %lux%lux%lu is not in the mode list\n", Device, Original.Width, Original.Height, Original.Bpp);
    trace("%ls: %lu modes at %lu bpp, current %lux%lu\n", Device, g_ModeCount, Original.Bpp, Original.Width, Original.Height);
    if (g_ModeCount < 2)
    {
        skip("%ls lists only one mode at %lu bpp\n", Device, Original.Bpp);
        return 0;
    }

    for (i = 0; i < g_ModeCount; i++)
    {
        if (!SetMode(Device, &g_Modes[i], CDS_FULLSCREEN))
            continue;
        Changes++;
        CheckCurrent(Device, Primary, &g_Modes[i]);

        /* Move the window and let the drawing thread work in the new mode */
        SetWindowPos(g_hWnd, NULL, (int)(i * 17) % 200, (int)(i * 13) % 150, 0, 0,
                     SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        PumpMessages();
        Sleep(50);
        PumpMessages();
    }

    /* The same mode once more, forced: the driver sets it again on the device it already drives */
    if (SetMode(Device, &Original, CDS_FULLSCREEN | CDS_RESET))
    {
        Changes++;
        CheckCurrent(Device, Primary, &Original);
    }
    Sleep(50);

    /* Back to the registry mode */
    ret = ChangeDisplaySettingsExW(Device, NULL, NULL, 0, NULL);
    ok(ret == DISP_CHANGE_SUCCESSFUL, "%ls: restoring the registry mode returned %ld\n", Device, ret);
    PumpMessages();
    CheckCurrent(Device, Primary, &Original);
    return Changes;
}

START_TEST(DisplayModeCycle)
{
    DISPLAY_DEVICEW dd;
    HANDLE hThread;
    ULONG Changes = 0, Devices = 0;
    DWORD iDev;
    WCHAR Primary[32] = L"";

    /* The primary display first, then the other displays of the desktop */
    for (iDev = 0; ; iDev++)
    {
        ZeroMemory(&dd, sizeof(dd));
        dd.cb = sizeof(dd);
        if (!EnumDisplayDevicesW(NULL, iDev, &dd, 0))
            break;
        if (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE)
        {
            lstrcpynW(Primary, dd.DeviceName, ARRAYSIZE(Primary));
            break;
        }
    }
    ok(Primary[0] != UNICODE_NULL, "no primary display device\n");
    if (!Primary[0])
        return;

    g_hWnd = CreateWindowExW(WS_EX_TOPMOST, L"STATIC", L"DisplayModeCycle", WS_POPUP | WS_VISIBLE | WS_BORDER,
                             10, 10, 320, 200, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(g_hWnd != NULL, "CreateWindowEx failed: %lu\n", GetLastError());
    if (!g_hWnd)
        return;
    PumpMessages();

    g_StopDrawing = FALSE;
    hThread = CreateThread(NULL, 0, DrawThread, NULL, 0, NULL);
    ok(hThread != NULL, "CreateThread failed: %lu\n", GetLastError());

    Changes += CycleDevice(Primary, TRUE);
    Devices++;
    for (iDev = 0; ; iDev++)
    {
        ZeroMemory(&dd, sizeof(dd));
        dd.cb = sizeof(dd);
        if (!EnumDisplayDevicesW(NULL, iDev, &dd, 0))
            break;
        if ((dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) ||
            !(dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP))
            continue;
        Changes += CycleDevice(dd.DeviceName, FALSE);
        Devices++;
    }

    /* Let the drawing thread draw at least once, also when no display had modes to cycle */
    for (iDev = 0; g_DrawCount == 0 && iDev < 100; iDev++)
        Sleep(100);

    InterlockedExchange(&g_StopDrawing, TRUE);
    if (hThread)
    {
        ok(WaitForSingleObject(hThread, 10000) == WAIT_OBJECT_0, "the drawing thread did not stop\n");
        CloseHandle(hThread);
    }
    ok(g_DrawCount > 0, "the drawing thread never drew\n");

    DestroyWindow(g_hWnd);
    trace("%lu displays, %lu mode changes, %ld draws\n", Devices, Changes, g_DrawCount);
}
