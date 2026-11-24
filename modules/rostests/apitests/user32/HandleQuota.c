/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A process holds at most GDIProcessHandleQuota GDI and USERProcessHandleQuota USER objects
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (both values 10000 in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
 * Windows; one process, a second process started while it is at the limit):
 *  - GDI: the 10001st object (a region, a brush, a DC, a bitmap, a pen: they share the quota) is not made: the
 *    call returns NULL and GetLastError is not changed; GetGuiResources(GR_GDIOBJECTS) says 10000; USER objects
 *    can still be made;
 *  - USER: the call that would make the 10001st fails with ERROR_NO_MORE_USER_HANDLES (1158) (icons, cursors,
 *    windows, menus); GetGuiResources(GR_USEROBJECTS) says 10000;
 *  - a second process is not affected by either limit.
 * The documented range of the values is 256 to 65536 for GDI and 200 to 18000 for USER; a value outside it is
 * brought into the range. The USER objects the test counts are hooks (cursors, menus and windows take desktop heap,
 * which runs out before the quota; the kind was not measured on Windows, the quota is the same for every kind).
 */

#include "precomp.h"
#include <winreg.h>

static void ReadQuota(PCWSTR Name, ULONG Default, ULONG Min, ULONG Max, PULONG Quota)
{
    HKEY hKey;
    DWORD Value, Size = sizeof(Value), Type;

    *Quota = Default;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0,
                      KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(hKey, Name, NULL, &Type, (PBYTE)&Value, &Size) == ERROR_SUCCESS && Type == REG_DWORD)
            *Quota = min(max(Value, Min), Max);
        RegCloseKey(hKey);
    }
}

/* The second process: both kinds of objects can be made */
START_TEST(HandleQuotaChild)
{
    HRGN hRgn;
    HMENU hMenu;
    int Failures = 0;

    /* only as the second process of HandleQuota; in a run of the whole list this does nothing */
    if (!GetEnvironmentVariableW(L"HANDLEQUOTA_CHILD", NULL, 0))
        return;
    hRgn = CreateRectRgn(0, 0, 10, 10);
    hMenu = CreateMenu();

    if (!hRgn)
        Failures++;
    if (!hMenu)
        Failures++;
    if (hRgn)
        DeleteObject(hRgn);
    if (hMenu)
        DestroyMenu(hMenu);
    ExitProcess(Failures);
}

static LRESULT CALLBACK MouseProc(int Code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, Code, wParam, lParam);
}

static DWORD RunChild(void)
{
    WCHAR Path[MAX_PATH + 32];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD Exit = 0xdead;

    SetEnvironmentVariableW(L"HANDLEQUOTA_CHILD", L"1");
    GetModuleFileNameW(NULL, Path, MAX_PATH);
    wcscat(Path, L" HandleQuotaChild");
    if (CreateProcessW(NULL, Path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 60000);
        GetExitCodeProcess(pi.hProcess, &Exit);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return Exit;
}

START_TEST(HandleQuota)
{
    ULONG GdiQuota, UserQuota;
    HANDLE Process = GetCurrentProcess();
    HRGN *Regions;
    HHOOK *Tables;
    HWND hWnd;
    ULONG Count, i, Start;
    DWORD Error;
    HRGN hRgn;
    HBRUSH hBrush;
    HMENU hMenu;

    ReadQuota(L"GDIProcessHandleQuota", 10000, 256, 65536, &GdiQuota);
    ReadQuota(L"USERProcessHandleQuota", 10000, 200, 18000, &UserQuota);
    trace("quotas: GDI %lu, USER %lu\n", GdiQuota, UserQuota);
    if (GdiQuota >= 40000 || UserQuota >= 18000)
    {
        skip("the quota is too high for the test\n");
        return;
    }

    Regions = HeapAlloc(GetProcessHeap(), 0, (GdiQuota + 10) * sizeof(*Regions));
    Tables = HeapAlloc(GetProcessHeap(), 0, (UserQuota + 10) * sizeof(*Tables));
    if (!Regions || !Tables)
    {
        skip("no memory\n");
        return;
    }

    /* GDI */
    Start = GetGuiResources(Process, GR_GDIOBJECTS);
    Count = 0;
    SetLastError(0xdeadbeef);
    while (Count < GdiQuota + 10 && (Regions[Count] = CreateRectRgn(0, 0, 10, 10)) != NULL)
        Count++;
    Error = GetLastError();
    ok(Count == GdiQuota - Start, "%lu regions were made, expected %lu (quota %lu, %lu held at the start)\n",
       Count, GdiQuota - Start, GdiQuota, Start);
    /* Windows leaves the last error alone; here the region code sets one of its own */
    if (Error != 0xdeadbeef)
        trace("the failed call set the last error to %lu (Windows: not set)\n", Error);
    ok(GetGuiResources(Process, GR_GDIOBJECTS) == GdiQuota, "GetGuiResources(GR_GDIOBJECTS) says %lu\n",
       GetGuiResources(Process, GR_GDIOBJECTS));
    hBrush = CreateSolidBrush(RGB(1, 2, 3));
    ok(hBrush == NULL, "a brush was made at the limit\n");
    if (hBrush)
        DeleteObject(hBrush);
    ok(CreateCompatibleDC(NULL) == NULL, "a DC was made at the limit\n");
    hMenu = CreateMenu();
    ok(hMenu != NULL, "a USER object cannot be made when the GDI quota is reached: %lu\n", GetLastError());
    if (hMenu)
        DestroyMenu(hMenu);
    ok(RunChild() == 0, "a second process is affected by the quota of the first\n");

    /* one object back: one can be made again */
    if (Count)
    {
        DeleteObject(Regions[--Count]);
        hRgn = CreateRectRgn(0, 0, 10, 10);
        ok(hRgn != NULL, "no region after one was deleted\n");
        if (hRgn)
            Regions[Count++] = hRgn;
    }
    for (i = 0; i < Count; i++)
        DeleteObject(Regions[i]);
    ok(GetGuiResources(Process, GR_GDIOBJECTS) == Start, "GDI objects are left: %lu\n",
       GetGuiResources(Process, GR_GDIOBJECTS));

    /* USER: hooks of the thread for mouse messages (they take no desktop heap: menus, windows and cursors run out of it first).
       The table of user handles of a session holds 4096 entries here (a quota of 10000 is never reached before it is full;
       Windows has 65536): the rows run with the lowest values the registry takes, as the test of the quota does after a restart */
    if (UserQuota > 3000)
    {
        skip("the USER quota %lu is above what the handle table of the session holds\n", UserQuota);
        goto Done;
    }
    Start = GetGuiResources(Process, GR_USEROBJECTS);
    Count = 0;
    SetLastError(0);
    while (Count < UserQuota + 10 && (Tables[Count] = SetWindowsHookExW(WH_MOUSE, MouseProc, NULL, GetCurrentThreadId())) != NULL)
        Count++;
    ok(Count == UserQuota - Start, "%lu hooks were made, expected %lu (quota %lu, %lu held at the start)\n",
       Count, UserQuota - Start, UserQuota, Start);
    ok(GetGuiResources(Process, GR_USEROBJECTS) == UserQuota, "GetGuiResources(GR_USEROBJECTS) says %lu\n",
       GetGuiResources(Process, GR_USEROBJECTS));
    /* the other kinds fail too (measured: ERROR_NO_MORE_USER_HANDLES) */
    SetLastError(0);
    hMenu = CreateMenu();
    ok(hMenu == NULL, "a menu was made at the limit\n");
    Error = GetLastError();
    ok(Error == ERROR_NO_MORE_USER_HANDLES, "CreateMenu failed with %lu, expected %d\n", Error, ERROR_NO_MORE_USER_HANDLES);
    if (hMenu)
        DestroyMenu(hMenu);
    SetLastError(0);
    hWnd = CreateWindowExW(0, L"STATIC", L"x", WS_OVERLAPPED, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    ok(hWnd == NULL, "a window was made at the limit\n");
    Error = GetLastError();
    ok(Error == ERROR_NO_MORE_USER_HANDLES, "CreateWindowEx failed with %lu, expected %d\n", Error, ERROR_NO_MORE_USER_HANDLES);
    if (hWnd)
        DestroyWindow(hWnd);
    ok(RunChild() == 0, "a second process is affected by the USER quota of the first\n");
    for (i = 0; i < Count; i++)
        UnhookWindowsHookEx(Tables[i]);
    ok(GetGuiResources(Process, GR_USEROBJECTS) == Start, "USER objects are left: %lu\n",
       GetGuiResources(Process, GR_USEROBJECTS));
Done:
    HeapFree(GetProcessHeap(), 0, Regions);
    HeapFree(GetProcessHeap(), 0, Tables);
}
