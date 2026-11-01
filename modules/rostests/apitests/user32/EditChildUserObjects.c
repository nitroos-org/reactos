/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Creating and destroying windows with an EDIT or COMBOBOX child does not leak USER objects
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The per-process quota is 10000 USER objects. Windows returns every object of a window to
 * the pool when the window is destroyed. ReactOS added a CallProc to the EDIT class for every
 * EDIT window created and kept all of them until the class went away, one lost USER object
 * per EDIT window, and per COMBOBOX window, which contains an EDIT.
 */

#include "precomp.h"

#define WINDOW_COUNT 200
#define TOLERANCE 4

static void
PumpMessages(void)
{
    MSG msg;

    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

static BOOL
CreateAndDestroyOne(PCSTR ClassA, PCWSTR ClassW, DWORD ChildStyle, BOOL Ansi)
{
    HWND hwndTop, hwndChild;

    if (Ansi)
    {
        hwndTop = CreateWindowExA(0, "STATIC", "top", WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, NULL, NULL, NULL, NULL);
        hwndChild = hwndTop ? CreateWindowExA(0, ClassA, "child", WS_CHILD | WS_VISIBLE | ChildStyle, 0, 0, 100, 100,
                                              hwndTop, (HMENU)1, NULL, NULL) : NULL;
    }
    else
    {
        hwndTop = CreateWindowExW(0, L"STATIC", L"top", WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, NULL, NULL, NULL, NULL);
        hwndChild = hwndTop ? CreateWindowExW(0, ClassW, L"child", WS_CHILD | WS_VISIBLE | ChildStyle, 0, 0, 100, 100,
                                              hwndTop, (HMENU)1, NULL, NULL) : NULL;
    }
    if (!hwndTop || !hwndChild)
    {
        ok(0, "CreateWindowEx(%s) failed, top %p child %p error %lu\n", ClassA, hwndTop, hwndChild, GetLastError());
        if (hwndTop)
            DestroyWindow(hwndTop);
        return FALSE;
    }
    ShowWindow(hwndTop, SW_SHOWNA);
    PumpMessages();
    DestroyWindow(hwndTop);
    PumpMessages();
    return TRUE;
}

static void
TestClass(PCSTR ClassA, PCWSTR ClassW, DWORD ChildStyle, BOOL Ansi)
{
    HANDLE hProcess = GetCurrentProcess();
    DWORD Before, After, Gdi0, Gdi1;
    int i;

    /* The first window of a class may set up per-class state, which stays: take it out of the count */
    if (!CreateAndDestroyOne(ClassA, ClassW, ChildStyle, Ansi))
        return;
    CreateAndDestroyOne(ClassA, ClassW, ChildStyle, Ansi);

    Before = GetGuiResources(hProcess, GR_USEROBJECTS);
    Gdi0 = GetGuiResources(hProcess, GR_GDIOBJECTS);
    for (i = 0; i < WINDOW_COUNT; i++)
    {
        if (!CreateAndDestroyOne(ClassA, ClassW, ChildStyle, Ansi))
            return;
    }
    After = GetGuiResources(hProcess, GR_USEROBJECTS);
    Gdi1 = GetGuiResources(hProcess, GR_GDIOBJECTS);

    ok(After <= Before + TOLERANCE,
       "%s (%s): %d windows changed the USER object count from %lu to %lu\n",
       ClassA, Ansi ? "ANSI" : "Unicode", WINDOW_COUNT, Before, After);
    ok(Gdi1 <= Gdi0 + TOLERANCE,
       "%s (%s): %d windows changed the GDI object count from %lu to %lu\n",
       ClassA, Ansi ? "ANSI" : "Unicode", WINDOW_COUNT, Gdi0, Gdi1);
}

START_TEST(EditChildUserObjects)
{
    HWND hwnd;

    /* A process without a GUI session (for example a service window station) reports 0 */
    hwnd = CreateWindowExW(0, L"STATIC", L"probe", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, NULL, NULL);
    if (!hwnd || GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS) == 0)
    {
        skip("GetGuiResources does not count USER objects here (window %p)\n", hwnd);
        if (hwnd)
            DestroyWindow(hwnd);
        return;
    }
    DestroyWindow(hwnd);
    PumpMessages();

    TestClass("BUTTON", L"BUTTON", 0, FALSE);   /* control: never leaked */
    TestClass("EDIT", L"EDIT", 0, FALSE);
    TestClass("EDIT", L"EDIT", 0, TRUE);
    TestClass("COMBOBOX", L"COMBOBOX", CBS_DROPDOWN, FALSE);
    TestClass("COMBOBOX", L"COMBOBOX", CBS_DROPDOWNLIST, FALSE);
    TestClass("COMBOBOX", L"COMBOBOX", CBS_DROPDOWN, TRUE);
}
