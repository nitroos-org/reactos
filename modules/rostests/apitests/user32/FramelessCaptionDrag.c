/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Dragging a window by a caption the application draws itself (Chromium, Electron, VS Code):
 *              WM_NCHITTEST answers HTCAPTION for a strip of a window without a caption of its own, and
 *              a mouse drag that starts there moves the window through DefWindowProc (WM_NCLBUTTONDOWN,
 *              WM_SYSCOMMAND SC_MOVE+HTCAPTION, the size-move loop). Two windows: a frameless WS_POPUP,
 *              and a WS_OVERLAPPEDWINDOW whose WM_NCCALCSIZE gives the whole window to the client area.
 */

#include "precomp.h"

#define CLASS_NAME L"FramelessCaptionDragWnd"
#define STRIP_HEIGHT 32

static HWND g_nclDownWnd, g_scMoveWnd;
static LONG g_hitCaption, g_hitOther, g_nclDown, g_scMove, g_enter, g_exit, g_moving, g_clientDown;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    /* Chromium's render widget window hands the non-client mouse messages of its parent to the default
     * procedure of the parent, so that WM_SYSCOMMAND is generated for the top-level window */
    if (GetParent(hwnd) && msg >= WM_NCMOUSEMOVE && msg <= WM_NCXBUTTONDBLCLK)
    {
        if (msg == WM_NCLBUTTONDOWN && wParam == HTCAPTION)
            g_nclDown++;
        return DefWindowProcW(GetParent(hwnd), msg, wParam, lParam);
    }

    switch (msg)
    {
        case WM_NCCALCSIZE:
            /* the application takes the whole window, as Chromium does for its own frame */
            if (GetWindowLongPtrW(hwnd, GWLP_USERDATA))
                return 0;
            break;

        case WM_NCHITTEST:
        {
            RECT rc;
            POINT pt;

            pt.x = (short)LOWORD(lParam);
            pt.y = (short)HIWORD(lParam);
            GetWindowRect(hwnd, &rc);
            if (PtInRect(&rc, pt))
            {
                if (pt.y < rc.top + STRIP_HEIGHT)
                {
                    g_hitCaption++;
                    return HTCAPTION;
                }
                g_hitOther++;
                return HTCLIENT;
            }
            break;
        }

        case WM_NCLBUTTONDOWN:
            if (wParam == HTCAPTION)
            {
                g_nclDown++;
                g_nclDownWnd = hwnd;
            }
            break;

        case WM_LBUTTONDOWN:
            g_clientDown++;
            break;

        case WM_SYSCOMMAND:
            if (wParam == (SC_MOVE | HTCAPTION))
            {
                g_scMove++;
                g_scMoveWnd = hwnd;
            }
            break;

        case WM_ENTERSIZEMOVE:
            g_enter++;
            break;

        case WM_EXITSIZEMOVE:
            g_exit++;
            break;

        case WM_MOVING:
            g_moving++;
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

/* the window thread is inside the size-move loop while this runs, so the input comes from another thread */
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

static void ResetCounters(void)
{
    g_hitCaption = g_hitOther = g_nclDown = g_scMove = g_enter = g_exit = g_moving = g_clientDown = 0;
}

static void RunDrag(DRAG *d)
{
    HANDLE th = CreateThread(NULL, 0, DragThread, d, 0, NULL);

    while (MsgWaitForMultipleObjects(1, &th, FALSE, 20000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
        Pump(0);
    CloseHandle(th);
    Pump(300);
}

static void TestDrag(const char *what, DWORD style, LONG noCaptionArea, BOOL withChild)
{
    HWND hwnd, child = NULL;
    RECT before, after;
    DRAG d;
    DWORD_PTR res = 0;
    POINT saved;
    const int dx = 90, dy = 60;

    GetCursorPos(&saved);
    hwnd = CreateWindowExW(0, CLASS_NAME, L"Frameless", style, 100, 100, 400, 300, NULL, NULL,
                           GetModuleHandleW(NULL), NULL);
    ok(hwnd != NULL, "%s: CreateWindow failed %lu\n", what, GetLastError());
    if (!hwnd)
        return;
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, noCaptionArea);
    SetWindowPos(hwnd, HWND_TOPMOST, 100, 100, 400, 300, SWP_FRAMECHANGED | SWP_SHOWWINDOW);
    if (withChild)
    {
        /* Chromium's render widget window: a child over the whole client area that answers WM_NCHITTEST itself */
        child = CreateWindowExW(WS_EX_TRANSPARENT, CLASS_NAME, NULL, WS_CHILD | WS_VISIBLE, 0, 0, 400, 300, hwnd,
                                NULL, GetModuleHandleW(NULL), NULL);
        ok(child != NULL, "%s: child CreateWindow failed %lu\n", what, GetLastError());
    }
    SetForegroundWindow(hwnd);
    Pump(500);

    GetWindowRect(hwnd, &before);
    ok(before.left == 100 && before.top == 100 && before.right == 500 && before.bottom == 400,
       "%s: window at %ld,%ld-%ld,%ld\n", what, before.left, before.top, before.right, before.bottom);

    d.from.x = before.left + 150;
    d.from.y = before.top + STRIP_HEIGHT / 2;
    d.to.x = d.from.x + dx;
    d.to.y = d.from.y + dy;

    /* a window that takes the whole window area as its client area has no frame of its own */
    if (noCaptionArea)
    {
        RECT cl;
        GetClientRect(hwnd, &cl);
        ok(cl.right == before.right - before.left && cl.bottom == before.bottom - before.top,
           "%s: client %ld x %ld\n", what, cl.right, cl.bottom);
    }

    ok(SendMessageTimeoutW(hwnd, WM_NCHITTEST, 0, MAKELPARAM(d.from.x, d.from.y), SMTO_ABORTIFHUNG, 2000, &res),
       "%s: WM_NCHITTEST not answered\n", what);
    ok((LONG)res == HTCAPTION, "%s: WM_NCHITTEST in the strip returned %ld\n", what, (LONG)res);

    ResetCounters();
    RunDrag(&d);

    GetWindowRect(hwnd, &after);
    ok(g_nclDown == 1, "%s: %ld WM_NCLBUTTONDOWN with HTCAPTION, expected 1\n", what, g_nclDown);
    ok(g_clientDown == 0, "%s: %ld WM_LBUTTONDOWN in the client area\n", what, g_clientDown);
    ok(g_scMove == 1, "%s: %ld WM_SYSCOMMAND SC_MOVE+HTCAPTION, expected 1\n", what, g_scMove);
    ok(g_scMoveWnd == hwnd, "%s: WM_SYSCOMMAND went to %p (%s), not to the top-level window %p\n", what, g_scMoveWnd,
       g_scMoveWnd == child ? "the child" : "?", hwnd);
    ok(g_enter == 1 && g_exit == 1, "%s: WM_ENTERSIZEMOVE %ld, WM_EXITSIZEMOVE %ld\n", what, g_enter, g_exit);
    ok(g_moving > 0, "%s: no WM_MOVING\n", what);
    ok(after.left == before.left + dx && after.top == before.top + dy &&
       after.right - after.left == 400 && after.bottom - after.top == 300,
       "%s: window moved from %ld,%ld to %ld,%ld (%ldx%ld), expected %ld,%ld\n", what,
       before.left, before.top, after.left, after.top, after.right - after.left, after.bottom - after.top,
       before.left + dx, before.top + dy);

    /* a drag that starts below the strip is a client drag: the window stays */
    d.from.x = after.left + 150;
    d.from.y = after.top + STRIP_HEIGHT + 60;
    d.to.x = d.from.x + dx;
    d.to.y = d.from.y + dy;
    ResetCounters();
    before = after;
    RunDrag(&d);
    GetWindowRect(hwnd, &after);
    ok(g_clientDown == 1 && g_nclDown == 0, "%s: client drag: %ld WM_LBUTTONDOWN, %ld WM_NCLBUTTONDOWN\n",
       what, g_clientDown, g_nclDown);
    ok(after.left == before.left && after.top == before.top, "%s: the window moved by a client drag to %ld,%ld\n",
       what, after.left, after.top);

    DestroyWindow(hwnd);
    SetCursorPos(saved.x, saved.y);
}

START_TEST(FramelessCaptionDrag)
{
    WNDCLASSW wc;

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = CLASS_NAME;
    ok(RegisterClassW(&wc) != 0, "RegisterClass failed %lu\n", GetLastError());

    /* Chromium's frameless window */
    TestDrag("WS_POPUP", WS_POPUP, 0, FALSE);
    /* a window with a caption style whose caption WM_NCCALCSIZE removes (Electron with a hidden title bar) */
    TestDrag("WS_OVERLAPPEDWINDOW + WM_NCCALCSIZE", WS_OVERLAPPEDWINDOW, 1, FALSE);
    /* and the child window over its client area that returns HTCAPTION itself */
    TestDrag("WS_POPUP + child", WS_POPUP, 0, TRUE);
    TestDrag("WS_OVERLAPPEDWINDOW + WM_NCCALCSIZE + child", WS_OVERLAPPEDWINDOW, 1, TRUE);

    UnregisterClassW(CLASS_NAME, GetModuleHandleW(NULL));
}
