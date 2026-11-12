/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Sizing a window with the mouse when it answers WM_GETMINMAXINFO with no maximum
 *              (ptMaxTrackSize = MAXLONG, as Chromium and Electron do): the limits of the mouse in the
 *              size loop add the track size to the window rectangle and must not wrap, or the window gets
 *              a rectangle of about MAXLONG and disappears (MongoDB Compass, VS Code).
 */

#include "precomp.h"

#define CLASS_NAME L"SizeNoMaxTrackWnd"

static LONG g_maxTrack;     /* what WM_GETMINMAXINFO answers: 0 = leave the defaults, else ptMaxTrackSize */
static LONG g_sizing, g_getMinMax;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_GETMINMAXINFO:
            g_getMinMax++;
            if (g_maxTrack)
            {
                MINMAXINFO *mmi = (MINMAXINFO *)lParam;
                mmi->ptMaxTrackSize.x = g_maxTrack;
                mmi->ptMaxTrackSize.y = g_maxTrack;
            }
            return 0;

        case WM_SIZING:
            g_sizing++;
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void Pump(DWORD ms)
{
    DWORD end = GetTickCount() + ms;
    MSG msg;

    for (;;)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if ((LONG)(end - GetTickCount()) <= 0)
            break;
        MsgWaitForMultipleObjects(0, NULL, FALSE, 10, QS_ALLINPUT);
    }
}

static void MouseTo(LONG x, LONG y)
{
    INPUT in;

    ZeroMemory(&in, sizeof(in));
    in.type = INPUT_MOUSE;
    in.mi.dx = (x * 65535 + GetSystemMetrics(SM_CXSCREEN) / 2) / (GetSystemMetrics(SM_CXSCREEN) - 1);
    in.mi.dy = (y * 65535 + GetSystemMetrics(SM_CYSCREEN) / 2) / (GetSystemMetrics(SM_CYSCREEN) - 1);
    in.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
    SendInput(1, &in, sizeof(in));
}

static void MouseBtn(DWORD flag)
{
    INPUT in;

    ZeroMemory(&in, sizeof(in));
    in.type = INPUT_MOUSE;
    in.mi.dwFlags = flag;
    SendInput(1, &in, sizeof(in));
}

typedef struct { POINT from, to; } DRAG;

/* the window thread is inside the size loop while this runs, so the input comes from another thread */
static DWORD WINAPI DragThread(LPVOID param)
{
    DRAG *d = param;
    int i;

    MouseTo(d->from.x, d->from.y);
    Sleep(300);
    MouseBtn(MOUSEEVENTF_LEFTDOWN);
    Sleep(300);
    for (i = 1; i <= 10; i++)
    {
        MouseTo(d->from.x + (d->to.x - d->from.x) * i / 10, d->from.y + (d->to.y - d->from.y) * i / 10);
        Sleep(50);
    }
    Sleep(300);
    MouseBtn(MOUSEEVENTF_LEFTUP);
    Sleep(300);
    return 0;
}

static void RunDrag(DRAG *d)
{
    HANDLE th = CreateThread(NULL, 0, DragThread, d, 0, NULL);

    while (MsgWaitForMultipleObjects(1, &th, FALSE, 20000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
        Pump(0);
    CloseHandle(th);
    Pump(300);
}

/* Drag the bottom right corner by dx,dy and then the top left corner by -dx,-dy (or the other way round) */
static void TestSize(const char *what, LONG maxTrack, LONG dx, LONG dy)
{
    HWND hwnd;
    RECT before, after;
    DRAG d;
    POINT saved;
    const LONG x = 200, y = 150, cx = 500, cy = 400;
    LONG w, h;

    g_maxTrack = maxTrack;
    GetCursorPos(&saved);
    hwnd = CreateWindowExW(0, CLASS_NAME, L"SizeNoMaxTrack", WS_OVERLAPPEDWINDOW, x, y, cx, cy, NULL, NULL,
                           GetModuleHandleW(NULL), NULL);
    ok(hwnd != NULL, "%s: CreateWindow failed %lu\n", what, GetLastError());
    if (!hwnd)
        return;
    SetWindowPos(hwnd, HWND_TOPMOST, x, y, cx, cy, SWP_SHOWWINDOW);
    SetForegroundWindow(hwnd);
    Pump(500);

    /* bottom right corner (the thick frame: two pixels inside the window) */
    GetWindowRect(hwnd, &before);
    d.from.x = before.right - 2;
    d.from.y = before.bottom - 2;
    d.to.x = d.from.x + dx;
    d.to.y = d.from.y + dy;
    g_sizing = 0;
    RunDrag(&d);
    GetWindowRect(hwnd, &after);
    ok(g_sizing > 0, "%s: no WM_SIZING, the drag did not start a size loop\n", what);
    ok(after.left == before.left && after.top == before.top, "%s: the origin moved to %ld,%ld\n", what, after.left, after.top);
    w = after.right - after.left;
    h = after.bottom - after.top;
    ok(w == cx + dx && h == cy + dy, "%s: bottom right drag %ldx%ld, expected %ldx%ld (rect %ld,%ld-%ld,%ld)\n", what,
       w, h, cx + dx, cy + dy, after.left, after.top, after.right, after.bottom);

    /* top left corner */
    before = after;
    d.from.x = before.left + 1;
    d.from.y = before.top + 1;
    d.to.x = d.from.x + dx;
    d.to.y = d.from.y + dy;
    g_sizing = 0;
    RunDrag(&d);
    GetWindowRect(hwnd, &after);
    ok(g_sizing > 0, "%s: no WM_SIZING for the top left corner\n", what);
    ok(after.right == before.right && after.bottom == before.bottom, "%s: the far corner moved to %ld,%ld\n", what,
       after.right, after.bottom);
    w = after.right - after.left;
    h = after.bottom - after.top;
    ok(w == cx + dx - dx && h == cy + dy - dy, "%s: top left drag %ldx%ld, expected %ldx%ld (rect %ld,%ld-%ld,%ld)\n", what,
       w, h, cx, cy, after.left, after.top, after.right, after.bottom);

    ok(IsWindowVisible(hwnd), "%s: the window is not visible\n", what);
    DestroyWindow(hwnd);
    SetCursorPos(saved.x, saved.y);
}

START_TEST(SizeNoMaxTrack)
{
    WNDCLASSW wc;

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = CLASS_NAME;
    ok(RegisterClassW(&wc) != 0, "RegisterClass failed %lu\n", GetLastError());

    /* the defaults */
    TestSize("default track sizes, shrink", 0, -60, -40);
    TestSize("default track sizes, grow", 0, 40, 30);
    /* "no maximum", as Chromium and Electron answer it */
    TestSize("MAXLONG, shrink", MAXLONG, -60, -40);
    TestSize("MAXLONG, grow", MAXLONG, 40, 30);
    TestSize("MAXLONG - 1, shrink", MAXLONG - 1, -60, -40);
    TestSize("a track size beyond the screen, shrink", 100000, -60, -40);

    UnregisterClassW(CLASS_NAME, GetModuleHandleW(NULL));
}
