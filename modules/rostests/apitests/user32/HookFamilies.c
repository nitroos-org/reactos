/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Hooks of every family set by the calling thread: SetWindowsHookEx succeeds, each
 *              procedure runs with its documented parameters, CallNextHookEx chains them and the
 *              CBT HCBT_CREATEWND changes reach the window. The same PE32 file also runs under WoW64,
 *              where 32-bit MFC programs depend on the thread-local WH_CBT hook.
 */

#include "precomp.h"

#define CLASS_NAME L"HookFamiliesWnd"
#define TEST_MESSAGE (WM_USER + 0x77)
#define FILTER_CODE 0x4321
#define EXTRA_INFO 0x5A5A1234
#define CREATE_PARAMS ((LPVOID)(ULONG_PTR)0x1234ABCD)

static HHOOK g_hook[16];
static HWND g_main, g_child;

/* WH_CBT */
static LONG g_cbtCreate, g_cbtDestroy, g_cbtActivate, g_cbtFocus, g_cbtMinMax, g_cbtSysCommand, g_cbtKeySkipped;
static BOOL g_createOk, g_activateMouse;
static HWND g_createHwnd, g_destroyHwnd, g_activateHwnd, g_focusHwnd, g_focusPrev, g_minMaxHwnd;
static LPARAM g_minMaxShow;
static WPARAM g_sysCommand, g_keySkipped;
static LONG g_innerCreate, g_innerCreateOk;
static LRESULT g_chainResult;
/* WH_MSGFILTER */
static LONG g_filter, g_innerFilter;
static BOOL g_filterOk;
static LRESULT g_filterChain;
/* WH_KEYBOARD and WH_KEYBOARD_LL */
static LONG g_keyDown, g_keyUp, g_llKeyDown, g_llKeyUp;
static BOOL g_llKeyOk = TRUE;
static UINT g_skipVk;
/* WH_MOUSE and WH_MOUSE_LL */
static LONG g_mouse, g_mouseOurs, g_llMouse;
static BOOL g_llMouseOk;
/* WH_SHELL, WH_FOREGROUNDIDLE, WH_DEBUG */
static LONG g_shellCreated, g_shellDestroyed, g_idle, g_debug;
/* WH_GETMESSAGE, WH_CALLWNDPROC(RET) */
static LONG g_getMessage, g_callWnd, g_callWndRet;
static BOOL g_getMessageOk, g_callWndOk, g_callWndRetOk;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == TEST_MESSAGE)
        return 0x7654;
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

static LRESULT CALLBACK CbtProc(int code, WPARAM wParam, LPARAM lParam)
{
    switch (code)
    {
        case HCBT_CREATEWND:
        {
            CBT_CREATEWNDW *create = (CBT_CREATEWNDW *)lParam;
            CREATESTRUCTW *cs = create->lpcs;

            if (IS_INTRESOURCE(cs->lpszClass) || wcscmp(cs->lpszClass, CLASS_NAME))
                break;
            g_cbtCreate++;
            g_createHwnd = (HWND)wParam;
            if (cs->lpszName && !wcscmp(cs->lpszName, L"deny"))
                return 1;
            if (cs->lpszName && !wcscmp(cs->lpszName, L"chain"))
            {
                g_chainResult = CallNextHookEx(NULL, code, wParam, lParam);
                return 0;
            }
            g_createOk = cs->lpszName && !wcscmp(cs->lpszName, L"main") &&
                         cs->lpCreateParams == CREATE_PARAMS &&
                         cs->hInstance == GetModuleHandleW(NULL) &&
                         cs->hwndParent == NULL &&
                         cs->x == 20 && cs->y == 30 && cs->cx == 200 && cs->cy == 100 &&
                         (cs->style & WS_OVERLAPPEDWINDOW) == WS_OVERLAPPEDWINDOW;
            cs->cx = 321;
            cs->cy = 211;
            break;
        }
        case HCBT_DESTROYWND:
            g_cbtDestroy++;
            g_destroyHwnd = (HWND)wParam;
            break;
        case HCBT_ACTIVATE:
            if ((HWND)wParam == g_main)
            {
                g_cbtActivate++;
                g_activateHwnd = (HWND)wParam;
                g_activateMouse = ((CBTACTIVATESTRUCT *)lParam)->fMouse;
            }
            break;
        case HCBT_SETFOCUS:
            if ((HWND)wParam == g_child)
            {
                g_cbtFocus++;
                g_focusHwnd = (HWND)wParam;
                g_focusPrev = (HWND)lParam;
            }
            break;
        case HCBT_MINMAX:
            g_cbtMinMax++;
            g_minMaxHwnd = (HWND)wParam;
            g_minMaxShow = lParam;
            break;
        case HCBT_SYSCOMMAND:
            g_cbtSysCommand++;
            g_sysCommand = wParam;
            break;
        case HCBT_KEYSKIPPED:
            g_cbtKeySkipped++;
            g_keySkipped = wParam;
            break;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

/* Installed before CbtProc, so it runs when CbtProc chains */
static LRESULT CALLBACK InnerCbtProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HCBT_CREATEWND)
    {
        CREATESTRUCTW *cs = ((CBT_CREATEWNDW *)lParam)->lpcs;

        if (!IS_INTRESOURCE(cs->lpszClass) && !wcscmp(cs->lpszClass, CLASS_NAME) &&
            cs->lpszName && !wcscmp(cs->lpszName, L"chain"))
        {
            g_innerCreate++;
            g_innerCreateOk = cs->x == 40 && cs->y == 50 && cs->cx == 210 && cs->cy == 110 &&
                              cs->lpCreateParams == CREATE_PARAMS;
            return 0;
        }
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK FilterProc(int code, WPARAM wParam, LPARAM lParam)
{
    MSG *msg = (MSG *)lParam;

    if (code == FILTER_CODE && msg->message == TEST_MESSAGE)
    {
        g_filter++;
        g_filterOk = msg->hwnd == g_main && msg->wParam == 0x87654321 &&
                     msg->lParam == (LPARAM)(LONG)0x81234567 && msg->time == 0x11223344 &&
                     msg->pt.x == -5 && msg->pt.y == 7;
        g_filterChain = CallNextHookEx(NULL, code, wParam, lParam);
        return 5;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK InnerFilterProc(int code, WPARAM wParam, LPARAM lParam)
{
    MSG *msg = (MSG *)lParam;

    if (code == FILTER_CODE && msg->message == TEST_MESSAGE)
    {
        g_innerFilter++;
        return msg->wParam == 0x87654321 && msg->lParam == (LPARAM)(LONG)0x81234567 ? 9 : 8;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK KeyboardProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HC_ACTION && wParam == VK_F14)
    {
        if (lParam & 0x80000000)
            g_keyUp++;
        else
            g_keyDown++;
        if (wParam == g_skipVk)
            return 1;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK KeyboardLlProc(int code, WPARAM wParam, LPARAM lParam)
{
    KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lParam;

    if (code == HC_ACTION && k->vkCode == VK_F14)
    {
        if (wParam == WM_KEYDOWN)
            g_llKeyDown++;
        else if (wParam == WM_KEYUP)
            g_llKeyUp++;
        if (k->dwExtraInfo != EXTRA_INFO || !(k->flags & LLKHF_INJECTED) ||
            ((wParam == WM_KEYUP) != !!(k->flags & LLKHF_UP)))
            g_llKeyOk = FALSE;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK MouseProc(int code, WPARAM wParam, LPARAM lParam)
{
    MOUSEHOOKSTRUCT *m = (MOUSEHOOKSTRUCT *)lParam;
    RECT rc;

    if (code == HC_ACTION)
    {
        g_mouse++;
        GetWindowRect(g_main, &rc);
        if (m->hwnd == g_main && wParam == WM_MOUSEMOVE && PtInRect(&rc, m->pt))
            g_mouseOurs++;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK MouseLlProc(int code, WPARAM wParam, LPARAM lParam)
{
    MSLLHOOKSTRUCT *m = (MSLLHOOKSTRUCT *)lParam;

    if (code == HC_ACTION && wParam == WM_MOUSEMOVE && m->dwExtraInfo == EXTRA_INFO)
    {
        g_llMouse++;
        g_llMouseOk = (m->flags & LLMHF_INJECTED) != 0;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK ShellProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HSHELL_WINDOWCREATED && (HWND)wParam == g_main)
        g_shellCreated++;
    if (code == HSHELL_WINDOWDESTROYED && (HWND)wParam == g_main)
        g_shellDestroyed++;
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK IdleProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HC_ACTION)
        g_idle++;
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK DebugProc(int code, WPARAM wParam, LPARAM lParam)
{
    g_debug++;
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK GetMessageProc(int code, WPARAM wParam, LPARAM lParam)
{
    MSG *msg = (MSG *)lParam;

    if (code == HC_ACTION && msg->message == TEST_MESSAGE && wParam == PM_REMOVE)
    {
        g_getMessage++;
        g_getMessageOk = msg->hwnd == g_main && msg->wParam == 0x31 && msg->lParam == (LPARAM)(LONG)0x82345678;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK CallWndProc(int code, WPARAM wParam, LPARAM lParam)
{
    CWPSTRUCT *cwp = (CWPSTRUCT *)lParam;

    if (code == HC_ACTION && cwp->message == TEST_MESSAGE)
    {
        g_callWnd++;
        g_callWndOk = cwp->hwnd == g_main && cwp->wParam == 0x32 && cwp->lParam == (LPARAM)(LONG)0x82345678;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK CallWndRetProc(int code, WPARAM wParam, LPARAM lParam)
{
    CWPRETSTRUCT *cwpr = (CWPRETSTRUCT *)lParam;

    if (code == HC_ACTION && cwpr->message == TEST_MESSAGE)
    {
        g_callWndRet++;
        g_callWndRetOk = cwpr->hwnd == g_main && cwpr->lResult == 0x7654 && cwpr->wParam == 0x32;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static void SendKey(WORD vk)
{
    INPUT in[2];

    ZeroMemory(in, sizeof(in));
    in[0].type = in[1].type = INPUT_KEYBOARD;
    in[0].ki.wVk = in[1].ki.wVk = vk;
    in[0].ki.dwExtraInfo = in[1].ki.dwExtraInfo = EXTRA_INFO;
    in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, in, sizeof(INPUT));
    Pump(300);
}

static const struct
{
    int id;
    HOOKPROC proc;
    const char *name;
} g_families[] =
{
    { WH_MSGFILTER, FilterProc, "WH_MSGFILTER" },
    { WH_KEYBOARD, KeyboardProc, "WH_KEYBOARD" },
    { WH_GETMESSAGE, GetMessageProc, "WH_GETMESSAGE" },
    { WH_CALLWNDPROC, CallWndProc, "WH_CALLWNDPROC" },
    { WH_CBT, CbtProc, "WH_CBT" },
    { WH_MOUSE, MouseProc, "WH_MOUSE" },
    { WH_DEBUG, DebugProc, "WH_DEBUG" },
    { WH_SHELL, ShellProc, "WH_SHELL" },
    { WH_FOREGROUNDIDLE, IdleProc, "WH_FOREGROUNDIDLE" },
    { WH_CALLWNDPROCRET, CallWndRetProc, "WH_CALLWNDPROCRET" },
    { WH_KEYBOARD_LL, KeyboardLlProc, "WH_KEYBOARD_LL" },
    { WH_MOUSE_LL, MouseLlProc, "WH_MOUSE_LL" },
};

START_TEST(HookFamilies)
{
    WNDCLASSW wc;
    HHOOK innerCbt, innerFilter;
    HWND hwnd;
    RECT rc;
    MSG msg;
    POINT saved;
    INPUT in;
    BOOL foreground;
    size_t i;

    trace("%u-bit process\n", (UINT)(sizeof(void *) * 8));
    GetCursorPos(&saved);

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed, error %lu\n", GetLastError());

    /* Hooks run in reverse order of installation: the inner ones first */
    innerCbt = SetWindowsHookExW(WH_CBT, InnerCbtProc, NULL, GetCurrentThreadId());
    ok(innerCbt != NULL, "inner WH_CBT: error %lu\n", GetLastError());
    innerFilter = SetWindowsHookExW(WH_MSGFILTER, InnerFilterProc, NULL, GetCurrentThreadId());
    ok(innerFilter != NULL, "inner WH_MSGFILTER: error %lu\n", GetLastError());
    for (i = 0; i < ARRAYSIZE(g_families); i++)
    {
        BOOL ll = g_families[i].id == WH_KEYBOARD_LL || g_families[i].id == WH_MOUSE_LL;

        SetLastError(0xdeadbeef);
        g_hook[i] = SetWindowsHookExW(g_families[i].id, g_families[i].proc,
                                      ll ? GetModuleHandleW(NULL) : NULL, ll ? 0 : GetCurrentThreadId());
        ok(g_hook[i] != NULL, "%s: SetWindowsHookExW failed, error %lu\n", g_families[i].name, GetLastError());
    }

    /* HCBT_CREATEWND: the parameters, the size the hook sets, and a refusal */
    g_main = CreateWindowExW(0, CLASS_NAME, L"main", WS_OVERLAPPEDWINDOW, 20, 30, 200, 100,
                             NULL, NULL, wc.hInstance, CREATE_PARAMS);
    ok(g_main != NULL, "CreateWindowExW failed, error %lu\n", GetLastError());
    if (!g_main)
        goto cleanup;
    ok(g_cbtCreate == 1, "HCBT_CREATEWND: %ld calls\n", g_cbtCreate);
    ok(g_createHwnd == g_main, "HCBT_CREATEWND: wParam %p, window %p\n", g_createHwnd, g_main);
    ok(g_createOk, "HCBT_CREATEWND: wrong CREATESTRUCT\n");
    GetWindowRect(g_main, &rc);
    ok(rc.right - rc.left == 321 && rc.bottom - rc.top == 211, "HCBT_CREATEWND: window is %ldx%ld, the hook set 321x211\n",
       rc.right - rc.left, rc.bottom - rc.top);
    ok(g_innerCreate == 0, "inner WH_CBT ran %ld times without chaining\n", g_innerCreate);

    hwnd = CreateWindowExW(0, CLASS_NAME, L"deny", WS_OVERLAPPEDWINDOW, 0, 0, 50, 50, NULL, NULL, wc.hInstance, NULL);
    ok(hwnd == NULL, "HCBT_CREATEWND returned 1, the window was still created\n");
    if (hwnd)
        DestroyWindow(hwnd);

    g_chainResult = 0xbad;
    hwnd = CreateWindowExW(0, CLASS_NAME, L"chain", WS_OVERLAPPEDWINDOW, 40, 50, 210, 110, NULL, NULL,
                           wc.hInstance, CREATE_PARAMS);
    ok(hwnd != NULL, "chained HCBT_CREATEWND: no window, error %lu\n", GetLastError());
    ok(g_innerCreate == 1, "chained HCBT_CREATEWND: inner hook ran %ld times\n", g_innerCreate);
    ok(g_innerCreateOk, "chained HCBT_CREATEWND: wrong CREATESTRUCT in the inner hook\n");
    ok(g_chainResult == 0, "chained HCBT_CREATEWND: CallNextHookEx returned %Id\n", g_chainResult);
    if (hwnd)
    {
        g_cbtDestroy = 0;
        DestroyWindow(hwnd);
        ok(g_cbtDestroy == 1 && g_destroyHwnd == hwnd, "HCBT_DESTROYWND: %ld calls, wParam %p, window %p\n",
           g_cbtDestroy, g_destroyHwnd, hwnd);
    }

    /* WH_SHELL, HCBT_ACTIVATE, HCBT_SETFOCUS */
    ShowWindow(g_main, SW_SHOW);
    SetForegroundWindow(g_main);
    SetActiveWindow(g_main);
    Pump(300);
    foreground = GetForegroundWindow() == g_main;
    ok(g_shellCreated >= 1, "HSHELL_WINDOWCREATED: %ld calls\n", g_shellCreated);
    ok(g_cbtActivate >= 1, "HCBT_ACTIVATE: %ld calls\n", g_cbtActivate);
    ok(!g_activateMouse, "HCBT_ACTIVATE: fMouse is TRUE\n");
    g_child = CreateWindowExW(0, L"EDIT", NULL, WS_CHILD | WS_VISIBLE, 0, 0, 50, 20, g_main, NULL, wc.hInstance, NULL);
    ok(g_child != NULL, "child window: error %lu\n", GetLastError());
    SetFocus(g_main);
    SetFocus(g_child);
    ok(g_cbtFocus == 1, "HCBT_SETFOCUS: %ld calls\n", g_cbtFocus);
    ok(g_focusHwnd == g_child && g_focusPrev == g_main, "HCBT_SETFOCUS: wParam %p lParam %p, child %p main %p\n",
       g_focusHwnd, g_focusPrev, g_child, g_main);
    SetFocus(g_main);

    /* WH_GETMESSAGE, WH_CALLWNDPROC, WH_CALLWNDPROCRET */
    PostMessageW(g_main, TEST_MESSAGE, 0x31, (LPARAM)(LONG)0x82345678);
    ok(PeekMessageW(&msg, g_main, TEST_MESSAGE, TEST_MESSAGE, PM_REMOVE), "no posted message\n");
    ok(g_getMessage == 1 && g_getMessageOk, "WH_GETMESSAGE: %ld calls, ok %d\n", g_getMessage, g_getMessageOk);
    ok(SendMessageW(g_main, TEST_MESSAGE, 0x32, (LPARAM)(LONG)0x82345678) == 0x7654, "wrong SendMessage result\n");
    ok(g_callWnd == 1 && g_callWndOk, "WH_CALLWNDPROC: %ld calls, ok %d\n", g_callWnd, g_callWndOk);
    ok(g_callWndRet == 1 && g_callWndRetOk, "WH_CALLWNDPROCRET: %ld calls, ok %d\n", g_callWndRet, g_callWndRetOk);

    /* WH_MSGFILTER through CallMsgFilter, chained */
    msg.hwnd = g_main;
    msg.message = TEST_MESSAGE;
    msg.wParam = 0x87654321;
    msg.lParam = (LPARAM)(LONG)0x81234567;
    msg.time = 0x11223344;
    msg.pt.x = -5;
    msg.pt.y = 7;
    ok(CallMsgFilterW(&msg, FILTER_CODE), "CallMsgFilterW returned FALSE\n");
    ok(g_filter == 1 && g_filterOk, "WH_MSGFILTER: %ld calls, ok %d\n", g_filter, g_filterOk);
    ok(g_innerFilter == 1 && g_filterChain == 9, "chained WH_MSGFILTER: %ld calls, CallNextHookEx returned %Id\n",
       g_innerFilter, g_filterChain);

    /* WH_KEYBOARD, WH_KEYBOARD_LL, HCBT_KEYSKIPPED */
    if (foreground)
    {
        SendKey(VK_F14);
        ok(g_llKeyDown == 1 && g_llKeyUp == 1, "WH_KEYBOARD_LL: %ld down, %ld up\n", g_llKeyDown, g_llKeyUp);
        ok(g_llKeyOk, "WH_KEYBOARD_LL: wrong KBDLLHOOKSTRUCT\n");
        ok(g_keyDown == 1 && g_keyUp == 1, "WH_KEYBOARD: %ld down, %ld up\n", g_keyDown, g_keyUp);
        /* A WH_KEYBOARD hook that returns nonzero discards the key */
        g_skipVk = VK_F14;
        g_cbtKeySkipped = 0;
        SendKey(VK_F14);
        g_skipVk = 0;
        ok(g_keyDown == 2 && g_keyUp == 2, "WH_KEYBOARD: %ld down, %ld up\n", g_keyDown, g_keyUp);
        /* ReactOS: a global WH_KEYBOARD hook of another process (kbswitch) replaces the
         * result of the thread hook chain in co_HOOK_CallHooks */
        todo_ros ok(g_cbtKeySkipped >= 1 && g_keySkipped == VK_F14, "HCBT_KEYSKIPPED: %ld calls, wParam %Iu\n",
           g_cbtKeySkipped, g_keySkipped);
    }
    else
    {
        skip("the test window is not in the foreground, no keyboard input\n");
    }

    /* WH_MOUSE, WH_MOUSE_LL */
    GetWindowRect(g_main, &rc);
    SetCursorPos((rc.left + rc.right) / 2, (rc.top + rc.bottom) / 2);
    Pump(100);
    ZeroMemory(&in, sizeof(in));
    in.type = INPUT_MOUSE;
    in.mi.dx = 1;
    in.mi.dwFlags = MOUSEEVENTF_MOVE;
    in.mi.dwExtraInfo = EXTRA_INFO;
    SendInput(1, &in, sizeof(in));
    Pump(300);
    ok(g_llMouse >= 1 && g_llMouseOk, "WH_MOUSE_LL: %ld calls, ok %d\n", g_llMouse, g_llMouseOk);
    if (foreground)
        ok(g_mouseOurs >= 1, "WH_MOUSE: %ld calls, %ld for the window\n", g_mouse, g_mouseOurs);
    SetCursorPos(saved.x, saved.y);

    /* HCBT_SYSCOMMAND, HCBT_MINMAX */
    SendMessageW(g_main, WM_SYSCOMMAND, SC_MINIMIZE, 0);
    ok(g_cbtSysCommand >= 1 && g_sysCommand == SC_MINIMIZE, "HCBT_SYSCOMMAND: %ld calls, wParam %Ix\n",
       g_cbtSysCommand, g_sysCommand);
    ok(g_cbtMinMax >= 1 && g_minMaxHwnd == g_main && LOWORD(g_minMaxShow) == SW_MINIMIZE,
       "HCBT_MINMAX: %ld calls, wParam %p, lParam %Ix\n", g_cbtMinMax, g_minMaxHwnd, g_minMaxShow);
    ShowWindow(g_main, SW_RESTORE);
    SetForegroundWindow(g_main);
    Pump(200);
    foreground = GetForegroundWindow() == g_main;

    /* WH_FOREGROUNDIDLE runs when the foreground thread waits for input */
    g_idle = 0;
    SetTimer(g_main, 1, 50, NULL);
    for (i = 0; i < 3 && GetMessageW(&msg, NULL, 0, 0); )
    {
        if (msg.message == WM_TIMER)
            i++;
        DispatchMessageW(&msg);
    }
    KillTimer(g_main, 1);
    /* ReactOS calls the idle hook from PeekMessage and MsgWaitForMultipleObjects, not
     * before GetMessage waits */
    if (foreground)
        todo_ros ok(g_idle >= 1, "WH_FOREGROUNDIDLE: %ld calls\n", g_idle);
    else
        skip("the test window is not in the foreground, no idle hook\n");

    /* Windows calls WH_DEBUG before each other hook */
    todo_ros ok(g_debug > 0, "WH_DEBUG: %ld calls\n", g_debug);

    DestroyWindow(g_main);
    ok(g_shellDestroyed >= 1, "HSHELL_WINDOWDESTROYED: %ld calls\n", g_shellDestroyed);
    trace("calls: debug %ld idle %ld mouse %ld/%ld keyskipped %ld activate %ld\n",
          g_debug, g_idle, g_mouse, g_mouseOurs, g_cbtKeySkipped, g_cbtActivate);

cleanup:
    for (i = 0; i < ARRAYSIZE(g_families); i++)
    {
        if (g_hook[i])
            ok(UnhookWindowsHookEx(g_hook[i]), "%s: UnhookWindowsHookEx failed\n", g_families[i].name);
    }
    if (innerFilter)
        UnhookWindowsHookEx(innerFilter);
    if (innerCbt)
        UnhookWindowsHookEx(innerCbt);
    UnregisterClassW(CLASS_NAME, wc.hInstance);
}
