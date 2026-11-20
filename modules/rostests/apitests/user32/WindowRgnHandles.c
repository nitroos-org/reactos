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
 *
 * test_DestroyedDuringSetWindowRgn took the whole system down before the fix
 * (bugcheck in win32k: SetWindowPos went on with the window its thread had
 * destroyed in the message the call sent it).
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

/*
 * Another thread sets the region of a window, and the window's own thread
 * destroys the window in a message that this SetWindowRgn sends it
 * (WM_WINDOWPOSCHANGING, WM_NCCALCSIZE, WM_WINDOWPOSCHANGED). win32k went on
 * with the freed window: a bugcheck in win32k (0x50 on a Debug build) within
 * seconds. The call must return and the window be gone.
 */
#define TEST_CLASS L"WindowRgnHandlesClass"

static HWND g_hVictim;
static UINT g_uDestroyIn;
static HANDLE g_hGo, g_hDone;
static volatile LONG g_bQuit;

static LRESULT CALLBACK DestroyingProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (hWnd == g_hVictim && uMsg == g_uDestroyIn && InSendMessage())
    {
        g_uDestroyIn = 0;
        DestroyWindow(hWnd);
        return 0;
    }
    return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}

static DWORD WINAPI SetRgnThread(LPVOID Param)
{
    UNREFERENCED_PARAMETER(Param);
    while (WaitForSingleObject(g_hGo, 30000) == WAIT_OBJECT_0 && !g_bQuit)
    {
        HRGN hRgn = CreateEllipticRgn(0, 0, 90, 70);
        if (!SetWindowRgn(g_hVictim, hRgn, TRUE))
            DeleteObject(hRgn);
        SetEvent(g_hDone);
    }
    return 0;
}

static void WaitPumping(HANDLE hEvent)
{
    while (MsgWaitForMultipleObjects(1, &hEvent, FALSE, 10000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
        Pump();
}

static void test_DestroyedDuringSetWindowRgn(void)
{
    static const UINT Messages[] = { WM_WINDOWPOSCHANGING, WM_NCCALCSIZE, WM_WINDOWPOSCHANGED };
    WNDCLASSW wc;
    HANDLE hThread;
    DWORD Before, After;
    ULONG i, Gone = 0;

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = DestroyingProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = TEST_CLASS;
    RegisterClassW(&wc);

    g_hGo = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_hDone = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_bQuit = FALSE;
    hThread = CreateThread(NULL, 0, SetRgnThread, NULL, 0, NULL);
    ok(g_hGo && g_hDone && hThread, "Setup failed with %lu\n", GetLastError());
    if (!g_hGo || !g_hDone || !hThread)
        return;

    /* The first rounds (one per message) only warm up what windows of this
       class create once per process; counting starts after them */
    Before = 0;
    for (i = 0; i < 3 * 101; i++)
    {
        HWND hWnd;

        if (i == 3)
        {
            Pump();
            Before = GdiCount();
        }
        hWnd = CreateWindowExW(0, TEST_CLASS, L"victim", WS_POPUP | WS_VISIBLE | WS_CAPTION,
                               20, 20, 150, 120, NULL, NULL, NULL, NULL);
        if (!hWnd)
            continue;
        g_hVictim = hWnd;
        g_uDestroyIn = Messages[i % _countof(Messages)];
        SetEvent(g_hGo);
        WaitPumping(g_hDone);
        if (!IsWindow(hWnd))
            Gone++;
        else
            DestroyWindow(hWnd);
        g_uDestroyIn = 0;
    }
    Pump();
    After = GdiCount();
    ok(Gone > 0, "The window was never destroyed during SetWindowRgn\n");
    ok(After == Before, "Destroyed during SetWindowRgn: %lu GDI objects before, %lu after\n", Before, After);

    g_bQuit = TRUE;
    SetEvent(g_hGo);
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    CloseHandle(g_hGo);
    CloseHandle(g_hDone);
    UnregisterClassW(TEST_CLASS, GetModuleHandleW(NULL));
}

/* Two threads set the region of the same window: none of the regions stays behind */
static HWND g_hShared;

static DWORD WINAPI SetRgnLoopThread(LPVOID Param)
{
    int i;
    UNREFERENCED_PARAMETER(Param);
    for (i = 0; i < ROUNDS; i++)
    {
        HRGN hRgn = CreateRectRgn(0, 0, 40 + i % 40, 60);
        if (!SetWindowRgn(g_hShared, hRgn, TRUE))
            DeleteObject(hRgn);
    }
    return 0;
}

static void test_TwoThreads(void)
{
    HANDLE hThread;
    DWORD Before, After;
    int i;

    g_hShared = CreateWindowExW(0, L"STATIC", L"shared", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                40, 40, 200, 160, NULL, NULL, NULL, NULL);
    ok(g_hShared != NULL, "CreateWindowEx failed with %lu\n", GetLastError());
    if (!g_hShared)
        return;
    Pump();
    Before = GdiCount();
    hThread = CreateThread(NULL, 0, SetRgnLoopThread, NULL, 0, NULL);
    for (i = 0; i < ROUNDS; i++)
    {
        HRGN hRgn = CreateEllipticRgn(0, 0, 50 + i % 30, 50);
        if (!SetWindowRgn(g_hShared, hRgn, TRUE))
            DeleteObject(hRgn);
        Pump();
    }
    if (hThread)
    {
        while (MsgWaitForMultipleObjects(1, &hThread, FALSE, 30000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
            Pump();
        CloseHandle(hThread);
    }
    SetWindowRgn(g_hShared, NULL, TRUE);
    Pump();
    After = GdiCount();
    ok(After == Before, "Two threads: %lu GDI objects before, %lu after\n", Before, After);
    DestroyWindow(g_hShared);
}

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

    test_TwoThreads();
    test_DestroyedDuringSetWindowRgn();
}
