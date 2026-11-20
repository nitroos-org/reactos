/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Window regions and window DCs leave no GDI handle of the caller behind
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * MSDN (SetWindowRgn): after a successful call the system owns the region. A
 * themed window took a different path through user32 (the theme's UserApiHook)
 * that left the caller's region behind on every call; a program that changed
 * a window's shape in a loop filled the system's GDI handle table and with it
 * the whole desktop. MSDN (GetDCEx): the system takes the region passed with
 * DCX_INTERSECTRGN or DCX_EXCLUDERGN, and frees it when the DC is released.
 *
 * Each row repeats a call and compares the GDI object count of the process
 * before and after: none of them may keep anything.
 */

#include "precomp.h"

#define ROUNDS 200

static DWORD GdiCount(void)
{
    return GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
}

static void Pump(void)
{
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageW(&msg);
}

#define CHECK_FLAT(what, body) do { \
    DWORD Before, After; int i; \
    Pump(); Before = GdiCount(); \
    for (i = 0; i < ROUNDS; i++) { body; } \
    Pump(); After = GdiCount(); \
    ok(After == Before, "%s: %lu GDI objects before, %lu after %d rounds\n", what, Before, After, ROUNDS); \
} while (0)

START_TEST(WindowRgnHandles)
{
    HWND hTop, hHidden, hChild;
    HRGN hRgn, hQuery;
    RECT rc;
    int Ret;

    hTop = CreateWindowExW(0, L"STATIC", L"top", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           10, 10, 200, 200, NULL, NULL, NULL, NULL);
    hHidden = CreateWindowExW(0, L"STATIC", L"hidden", WS_OVERLAPPEDWINDOW,
                              10, 10, 200, 200, NULL, NULL, NULL, NULL);
    ok(hTop != NULL && hHidden != NULL, "CreateWindowEx failed with %lu\n", GetLastError());
    if (!hTop || !hHidden)
        return;
    hChild = CreateWindowExW(0, L"STATIC", L"child", WS_CHILD | WS_VISIBLE, 5, 5, 60, 60, hTop, NULL, NULL, NULL);
    ok(hChild != NULL, "CreateWindowEx(child) failed with %lu\n", GetLastError());
    Pump();

    /* The region set is the region read back */
    hRgn = CreateRectRgn(3, 4, 77, 33);
    Ret = SetWindowRgn(hTop, hRgn, TRUE);
    ok(Ret != 0, "SetWindowRgn failed with %lu\n", GetLastError());
    hQuery = CreateRectRgn(0, 0, 0, 0);
    ok(GetWindowRgn(hTop, hQuery) == SIMPLEREGION, "GetWindowRgn did not give a simple region\n");
    ok(GetRgnBox(hQuery, &rc) == SIMPLEREGION && rc.left == 3 && rc.top == 4 && rc.right == 77 && rc.bottom == 33,
       "GetWindowRgn box (%ld,%ld,%ld,%ld)\n", rc.left, rc.top, rc.right, rc.bottom);
    ok(GetWindowRgnBox(hTop, &rc) == SIMPLEREGION && rc.right == 77 && rc.bottom == 33,
       "GetWindowRgnBox (%ld,%ld,%ld,%ld)\n", rc.left, rc.top, rc.right, rc.bottom);
    DeleteObject(hQuery);

    /* The system owns what it was given: nothing of the caller stays */
    CHECK_FLAT("SetWindowRgn visible", SetWindowRgn(hTop, CreateRectRgn(0, 0, 50 + i % 50, 50), TRUE));
    CHECK_FLAT("SetWindowRgn without redraw", SetWindowRgn(hTop, CreateEllipticRgn(0, 0, 60, 40 + i % 30), FALSE));
    CHECK_FLAT("SetWindowRgn hidden", SetWindowRgn(hHidden, CreateRectRgn(0, 0, 20 + i % 20, 20), TRUE));
    if (hChild)
        CHECK_FLAT("SetWindowRgn child", SetWindowRgn(hChild, CreateRectRgn(0, 0, 10 + i % 30, 30), TRUE));
    CHECK_FLAT("SetWindowRgn region and none", SetWindowRgn(hTop, (i & 1) ? NULL : CreateRectRgn(0, 0, 70, 70), TRUE));
    CHECK_FLAT("SetWindowRgn on a window destroyed next",
               {
                   HWND hTemp = CreateWindowExW(0, L"STATIC", L"t", WS_POPUP | WS_VISIBLE, 0, 0, 80, 80,
                                                NULL, NULL, NULL, NULL);
                   SetWindowRgn(hTemp, CreateRectRgn(0, 0, 40, 40), TRUE);
                   DestroyWindow(hTemp);
               });

    /* GetDCEx takes the region and frees it when the DC is released */
    CHECK_FLAT("GetDCEx DCX_INTERSECTRGN", ReleaseDC(hTop, GetDCEx(hTop, CreateRectRgn(0, 0, 30, 30),
                                                                   DCX_CACHE | DCX_INTERSECTRGN)));
    CHECK_FLAT("GetDCEx DCX_WINDOW | DCX_EXCLUDERGN",
               ReleaseDC(hTop, GetDCEx(hTop, CreateRectRgn(0, 0, 30, 30), DCX_CACHE | DCX_WINDOW | DCX_EXCLUDERGN)));
    CHECK_FLAT("GetWindowDC across SetWindowRgn",
               {
                   HDC hdc = GetWindowDC(hTop);
                   SetWindowRgn(hTop, CreateRectRgn(0, 0, 90, 60 + i % 10), TRUE);
                   ReleaseDC(hTop, hdc);
               });

    DestroyWindow(hHidden);
    DestroyWindow(hTop);
}
