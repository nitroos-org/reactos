/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Hooks of every family set by the calling thread: SetWindowsHookEx succeeds, each
 *              procedure runs with its documented parameters, CallNextHookEx chains them (an inner
 *              hook sees what the outer one passes on) and the changes a CBT hook makes to
 *              HCBT_CREATEWND and HCBT_MOVESIZE reach the window. The same PE32 file also runs under
 *              WoW64, where 32-bit MFC programs depend on the thread-local WH_CBT hook.
 */

#include "precomp.h"

#include <string.h>

#define CLASS_NAME L"HookFamiliesWnd"
#define TEST_MESSAGE (WM_USER + 0x77)
#define TEST_MESSAGE2 (WM_USER + 0x78)
#define FILTER_CODE 0x4321
#define EXTRA_INFO 0x5A5A1234
#define CREATE_PARAMS ((LPVOID)(ULONG_PTR)0x1234ABCD)

static HHOOK g_hook[16];
static HWND g_main, g_child, g_other;

/* WH_CBT */
static LONG g_cbtCreate, g_cbtDestroy, g_cbtActivate, g_cbtFocus, g_cbtMinMax, g_cbtSysCommand, g_cbtKeySkipped;
static BOOL g_createOk, g_activateMouse;
static HWND g_createHwnd, g_destroyHwnd, g_activateHwnd, g_focusHwnd, g_focusPrev, g_minMaxHwnd;
/* HCBT_ACTIVATE of g_main as the outer and the inner hook saw it, first call after g_activateTrack is set */
static BOOL g_activateTrack;
static LONG g_innerActivate;
static BOOL g_innerActivateMouse;
static HWND g_activateActive, g_innerActivateHwnd, g_innerActivateActive, g_activateLog[8];
static LONG g_cbtActivateLog;
/* HCBT_MOVESIZE of g_main: what the outer hook got, what it passed on, what the inner hook got and returned */
enum { MOVE_NONE, MOVE_PASS, MOVE_OUTER, MOVE_INNER, MOVE_CANCEL };
static int g_moveMode;
static LONG g_cbtMoveSize, g_innerMoveSize;
static RECT g_moveRect, g_moveSent, g_moveInner, g_moveAfterChain;
static LRESULT g_moveChain;
/* the events of the move loop after the last HCBT_MOVESIZE: 'P' WM_WINDOWPOSCHANGING, 'X' WM_EXITSIZEMOVE (the
 * log starts over with the hook, 'H') */
static char g_moveSeq[64];
/* the arrow keys of the keyboard move or size, zero ends them */
static const WORD *g_keySeq;
static LPARAM g_minMaxShow;
static WPARAM g_sysCommand, g_keySkipped;
static LONG g_innerCreate, g_innerCreateOk;
static LRESULT g_chainResult;
/* WH_MSGFILTER */
static LONG g_filter, g_innerFilter;
static BOOL g_filterOk;
static LRESULT g_filterChain;
/* WH_KEYBOARD and WH_KEYBOARD_LL */
static LONG g_keyDown, g_keyUp, g_llKeyDown, g_llKeyUp, g_wmKeyF14;
static BOOL g_llKeyOk = TRUE;
static UINT g_skipVk;
/* the KBDLLHOOKSTRUCT the outer hook got, per direction, and the inner hook's calls and mismatches */
static KBDLLHOOKSTRUCT g_llKeyCopy[2];
static LONG g_innerLlKey[2], g_innerLlKeyBad;
/* WH_MOUSE and WH_MOUSE_LL */
static LONG g_mouse, g_mouseOurs, g_llMouse;
static BOOL g_llMouseOk;
/* the record the outer WH_MOUSE hook got for g_main and the inner hook's calls and mismatches */
static MOUSEHOOKSTRUCT g_mouseCopy;
static LONG g_innerMouse, g_innerMouseBad, g_plainChains;
static BOOL g_ignoreInner;
static BYTE *g_guardPage;
/* WH_MOUSE_LL: the wheel record the outer hook got (copy), the inner hook's calls and mismatches */
static LONG g_llWheel, g_innerLlMouse[2], g_innerLlMouseBad;
static MSLLHOOKSTRUCT g_llMouseCopy[2], g_llWheelRecord;
static POINT g_wheelPoint;
#define WHEEL_TIME 0x1234567
/* GetMessageTime of the mouse messages in the window procedure: the last one seen for each message */
static DWORD g_msgTime[4];
enum { MT_MOVE, MT_DOWN, MT_UP, MT_WHEEL };
/* WH_SHELL, WH_FOREGROUNDIDLE, WH_DEBUG */
static LONG g_shellCreated, g_shellDestroyed, g_idle, g_debug;
/* WH_DEBUG: bit (id + 1) of g_debugIds is set for each hook it was called for, the calls whose DEBUGHOOKINFO is
 * wrong, and the hook whose call the debug hook stops (g_debugBlock, its id) */
static ULONG g_debugIds;
static LONG g_debugBad, g_debugBlocked;
static int g_debugBlock = -100;
/* WH_GETMESSAGE, WH_CALLWNDPROC(RET) */
static LONG g_getMessage, g_callWnd, g_callWndRet;
static BOOL g_getMessageOk, g_callWndOk, g_callWndRetOk;
/* WH_DEBUG for the hooks CallNextHookEx reaches: the events of a SendMessage(TEST_MESSAGE2) in order, 'D' for a
 * call of the debug hook for WH_CALLWNDPROC, 'a', 'b', 'c' for the three hooks of that, and what the debug hook
 * may do: block the calls whose number is a bit of g_dbgBlockMask. What it got for CALLWNDPROC(RET) and CBT_CREATEWND */
static BOOL g_dbgSeqOn;
static char g_dbgSeq[32];
static ULONG g_dbgBlockMask;
static LONG g_dbgCwpCalls, g_dbgCwpBad, g_dbgRetCalls, g_dbgRetBad;
static BOOL g_dbgCbtTrack;
static LONG g_dbgCbtCalls, g_dbgCbtBad, g_dbgCbtBlock;

static void MoveEvent(char c)
{
    size_t n = strlen(g_moveSeq);

    if (g_moveMode == MOVE_NONE)
        return;
    if (c == 'H')
        n = 0;
    if (n + 2 < sizeof(g_moveSeq))
    {
        g_moveSeq[n] = c;
        g_moveSeq[n + 1] = 0;
    }
}

/* the events after the hook start with expect */
static BOOL MoveSeqIs(const char *expect)
{
    return g_moveSeq[0] == 'H' && !strncmp(g_moveSeq + 1, expect, strlen(expect));
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == TEST_MESSAGE || msg == TEST_MESSAGE2)
        return 0x7654;
    if (msg == WM_KEYDOWN && wParam == VK_F14)
        g_wmKeyF14++;
    if (hwnd == g_main)
    {
        switch (msg)
        {
            case WM_WINDOWPOSCHANGING: MoveEvent('P'); break;
            case WM_EXITSIZEMOVE: MoveEvent('X'); break;
            /* a move of the real mouse or of the system can come in between: the one SendInput gave is looked for */
            case WM_MOUSEMOVE:
                if ((DWORD)GetMessageTime() == WHEEL_TIME + 1 || !g_msgTime[MT_MOVE])
                    g_msgTime[MT_MOVE] = (DWORD)GetMessageTime();
                break;
            case WM_LBUTTONDOWN: g_msgTime[MT_DOWN] = (DWORD)GetMessageTime(); break;
            case WM_LBUTTONUP: g_msgTime[MT_UP] = (DWORD)GetMessageTime(); break;
            case WM_MOUSEWHEEL: g_msgTime[MT_WHEEL] = (DWORD)GetMessageTime(); break;
        }
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
                if (g_activateTrack && g_cbtActivateLog < 8)
                    g_activateLog[g_cbtActivateLog++] = ((CBTACTIVATESTRUCT *)lParam)->hWndActive;
            }
            break;
        case HCBT_MOVESIZE:
            if ((HWND)wParam == g_main && g_moveMode != MOVE_NONE)
            {
                RECT *rc = (RECT *)lParam;
                LRESULT res;

                MoveEvent('H');
                g_cbtMoveSize++;
                g_moveRect = *rc;
                if (g_moveMode == MOVE_CANCEL)
                    return 1;
                if (g_moveMode == MOVE_OUTER)
                    OffsetRect(rc, 13, 17);
                g_moveSent = *rc;
                res = CallNextHookEx(NULL, code, wParam, lParam);
                g_moveAfterChain = *rc;
                g_moveChain = res;
                return res;
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
    else if (code == HCBT_ACTIVATE && (HWND)wParam == g_main && g_activateTrack)
    {
        CBTACTIVATESTRUCT *act = (CBTACTIVATESTRUCT *)lParam;

        if (!g_innerActivate++)
        {
            g_innerActivateHwnd = (HWND)wParam;
            g_innerActivateMouse = act->fMouse;
            g_innerActivateActive = act->hWndActive;
        }
    }
    else if (code == HCBT_MOVESIZE && (HWND)wParam == g_main && g_moveMode != MOVE_NONE)
    {
        RECT *rc = (RECT *)lParam;

        g_innerMoveSize++;
        g_moveInner = *rc;
        if (g_moveMode == MOVE_INNER)
            OffsetRect(rc, 5, 7);
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
        g_llKeyCopy[wParam == WM_KEYUP] = *k;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK InnerKeyboardLlProc(int code, WPARAM wParam, LPARAM lParam)
{
    KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lParam;

    if (code == HC_ACTION && k->vkCode == VK_F14 && (wParam == WM_KEYDOWN || wParam == WM_KEYUP))
    {
        const KBDLLHOOKSTRUCT *o = &g_llKeyCopy[wParam == WM_KEYUP];

        g_innerLlKey[wParam == WM_KEYUP]++;
        if (k->vkCode != o->vkCode || k->scanCode != o->scanCode || k->flags != o->flags ||
            k->time != o->time || k->dwExtraInfo != o->dwExtraInfo)
            g_innerLlKeyBad++;
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
        {
            g_mouseOurs++;
            g_mouseCopy = *m;
            if (g_guardPage && !g_plainChains)
            {
                /* A caller may chain the plain 20-byte record: here it ends where the next page is
                 * inaccessible. Windows reads the MOUSEHOOKSTRUCTEX that follows and fails the call;
                 * the hook procedures are not run again, whatever happens, no fault may escape. */
                MOUSEHOOKSTRUCT *plain = (MOUSEHOOKSTRUCT *)(g_guardPage + 4096 - sizeof(*plain));

                *plain = *m;
                g_plainChains++;
                g_ignoreInner = TRUE;
                CallNextHookEx(NULL, code, wParam, (LPARAM)plain);
                g_ignoreInner = FALSE;
            }
        }
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK InnerMouseProc(int code, WPARAM wParam, LPARAM lParam)
{
    MOUSEHOOKSTRUCT *m = (MOUSEHOOKSTRUCT *)lParam;

    if (code == HC_ACTION && !g_ignoreInner && wParam == WM_MOUSEMOVE && m->hwnd == g_main)
    {
        g_innerMouse++;
        if (m->pt.x != g_mouseCopy.pt.x || m->pt.y != g_mouseCopy.pt.y || m->hwnd != g_mouseCopy.hwnd ||
            m->wHitTestCode != g_mouseCopy.wHitTestCode || m->dwExtraInfo != g_mouseCopy.dwExtraInfo)
            g_innerMouseBad++;
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
        g_llMouseCopy[0] = *m;
    }
    if (code == HC_ACTION && wParam == WM_MOUSEWHEEL && m->dwExtraInfo == EXTRA_INFO)
    {
        g_llWheel++;
        g_llMouseCopy[1] = g_llWheelRecord = *m;
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK InnerMouseLlProc(int code, WPARAM wParam, LPARAM lParam)
{
    MSLLHOOKSTRUCT *m = (MSLLHOOKSTRUCT *)lParam;

    if (code == HC_ACTION && m->dwExtraInfo == EXTRA_INFO && (wParam == WM_MOUSEMOVE || wParam == WM_MOUSEWHEEL))
    {
        const MSLLHOOKSTRUCT *o = &g_llMouseCopy[wParam == WM_MOUSEWHEEL];

        g_innerLlMouse[wParam == WM_MOUSEWHEEL]++;
        if (m->pt.x != o->pt.x || m->pt.y != o->pt.y || m->mouseData != o->mouseData || m->flags != o->flags ||
            m->time != o->time || m->dwExtraInfo != o->dwExtraInfo)
            g_innerLlMouseBad++;
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

static void DbgSeq(char c)
{
    size_t n = strlen(g_dbgSeq);

    if (n + 2 < sizeof(g_dbgSeq))
    {
        g_dbgSeq[n] = c;
        g_dbgSeq[n + 1] = 0;
    }
}

static LRESULT CALLBACK DebugProc(int code, WPARAM wParam, LPARAM lParam)
{
    DEBUGHOOKINFO *info = (DEBUGHOOKINFO *)lParam;
    int id = (int)wParam;

    if (code == HC_ACTION)
    {
        g_debug++;
        if (id >= WH_MIN && id <= WH_MAX)
            g_debugIds |= 1UL << (id - WH_MIN);
        /* the thread of the hook that is about to run; a global WH_KEYBOARD hook of another process (ReactOS
         * has one in kbswitch) runs in its own */
        if (info->idThread != GetCurrentThreadId() && id != WH_KEYBOARD)
            g_debugBad++;
        if (id == g_debugBlock)
        {
            g_debugBlocked++;
            return 1;
        }
        if (id == WH_CALLWNDPROC && g_dbgSeqOn)
        {
            /* a real CWPSTRUCT: Windows passes the record the hook gets, not zero */
            const CWPSTRUCT *cwp = (const CWPSTRUCT *)info->lParam;
            BOOL real = info->lParam && !IsBadReadPtr(cwp, sizeof(*cwp));

            if (!real || cwp->message == TEST_MESSAGE2)
            {
                DbgSeq('D');
                if (!real || cwp->hwnd != g_main || cwp->wParam != 0x33 || cwp->lParam != (LPARAM)(LONG)0x83456789)
                    g_dbgCwpBad++;
                if (g_dbgBlockMask & (1UL << g_dbgCwpCalls++))
                    return 1;
            }
        }
        else if (id == WH_CALLWNDPROCRET && g_dbgSeqOn)
        {
            const CWPRETSTRUCT *cwpr = (const CWPRETSTRUCT *)info->lParam;
            BOOL real = info->lParam && !IsBadReadPtr(cwpr, sizeof(*cwpr));

            if (!real || cwpr->message == TEST_MESSAGE2)
            {
                g_dbgRetCalls++;
                if (!real || cwpr->hwnd != g_main || cwpr->wParam != 0x33 || cwpr->lResult != 0x7654)
                    g_dbgRetBad++;
            }
        }
        else if (id == WH_CBT && g_dbgCbtTrack && info->code == HCBT_CREATEWND)
        {
            /* a CBT_CREATEWND of the hook's lParam is readable; what its lpcs points to is not told: Windows
             * gives a pointer that cannot be read in user mode */
            if (!info->lParam || IsBadReadPtr((const void *)info->lParam, sizeof(CBT_CREATEWNDW)))
                g_dbgCbtBad++;
            if (g_dbgCbtBlock & (1L << g_dbgCbtCalls++))
                return 1;
        }
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK CallWndProcA(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HC_ACTION && g_dbgSeqOn && ((CWPSTRUCT *)lParam)->message == TEST_MESSAGE2)
        DbgSeq('a');
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK CallWndProcB(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HC_ACTION && g_dbgSeqOn && ((CWPSTRUCT *)lParam)->message == TEST_MESSAGE2)
        DbgSeq('b');
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
    else if (code == HC_ACTION && g_dbgSeqOn && cwp->message == TEST_MESSAGE2)
        DbgSeq('c');
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

static void SendKeyNoPump(WORD vk)
{
    INPUT in[2];

    ZeroMemory(in, sizeof(in));
    in[0].type = in[1].type = INPUT_KEYBOARD;
    in[0].ki.wVk = in[1].ki.wVk = vk;
    in[0].ki.dwExtraInfo = in[1].ki.dwExtraInfo = EXTRA_INFO;
    in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, in, sizeof(INPUT));
}

static void SendKey(WORD vk)
{
    SendKeyNoPump(vk);
    Pump(300);
}

static void SendMouseButton(DWORD flag)
{
    INPUT in;

    ZeroMemory(&in, sizeof(in));
    in.type = INPUT_MOUSE;
    in.mi.dwFlags = flag;
    SendInput(1, &in, sizeof(in));
}

static void SendMouseTo(LONG x, LONG y)
{
    INPUT in;

    ZeroMemory(&in, sizeof(in));
    in.type = INPUT_MOUSE;
    in.mi.dx = (x * 65535 + GetSystemMetrics(SM_CXSCREEN) / 2) / (GetSystemMetrics(SM_CXSCREEN) - 1);
    in.mi.dy = (y * 65535 + GetSystemMetrics(SM_CYSCREEN) / 2) / (GetSystemMetrics(SM_CYSCREEN) - 1);
    in.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
    SendInput(1, &in, sizeof(in));
}

/* Presses the left button on the caption, drags 40 pixels right and 32 down and releases it. The window
 * thread is inside the move loop of its DefWindowProc for that time */
static DWORD WINAPI DragThread(LPVOID param)
{
    const POINT *start = param;
    int i;

    SendMouseTo(start->x, start->y);
    Sleep(200);
    SendMouseButton(MOUSEEVENTF_LEFTDOWN);
    Sleep(300);
    for (i = 1; i <= 8; i++)
    {
        SendMouseTo(start->x + 5 * i, start->y + 4 * i);
        Sleep(80);
    }
    Sleep(200);
    SendMouseButton(MOUSEEVENTF_LEFTUP);
    return 0;
}

static void SendVirtualKey(WORD vk, DWORD flags)
{
    INPUT in;

    ZeroMemory(&in, sizeof(in));
    in.type = INPUT_KEYBOARD;
    in.ki.wVk = vk;
    in.ki.wScan = (WORD)MapVirtualKeyW(vk, 0);
    in.ki.dwFlags = flags;
    if (vk >= VK_LEFT && vk <= VK_DOWN)
        in.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
    SendInput(1, &in, sizeof(in));
}

static void TapVirtualKey(WORD vk)
{
    SendVirtualKey(vk, 0);
    Sleep(40);
    SendVirtualKey(vk, KEYEVENTF_KEYUP);
    Sleep(150);
}

/* Alt+Space, the menu key for Move or Size, the arrow keys of g_keySeq, Return. The window thread is in the system
 * menu and then in the move loop of its DefWindowProc for that time */
static DWORD WINAPI KeyMoveThread(LPVOID param)
{
    WORD menuKey = (WORD)(ULONG_PTR)param;
    int i;

    SendVirtualKey(VK_MENU, 0);
    Sleep(40);
    SendVirtualKey(VK_SPACE, 0);
    Sleep(40);
    SendVirtualKey(VK_SPACE, KEYEVENTF_KEYUP);
    Sleep(40);
    SendVirtualKey(VK_MENU, KEYEVENTF_KEYUP);
    Sleep(500);
    TapVirtualKey(menuKey);
    Sleep(400);
    for (i = 0; g_keySeq[i]; i++)
        TapVirtualKey(g_keySeq[i]);
    Sleep(200);
    TapVirtualKey(VK_RETURN);
    return 0;
}

/* Moves (menuKey 'M') or sizes ('S') g_main with the keyboard */
static void MoveWithKeyboard(int mode, WORD menuKey, RECT *before, RECT *after)
{
    HANDLE thread;

    SetWindowPos(g_main, NULL, 100, 100, 321, 211, SWP_NOZORDER | SWP_NOACTIVATE);
    SetForegroundWindow(g_main);
    SetActiveWindow(g_main);
    Pump(200);
    GetWindowRect(g_main, before);
    g_moveMode = mode;
    g_cbtMoveSize = g_innerMoveSize = 0;
    ZeroMemory(&g_moveRect, sizeof(RECT));
    ZeroMemory(&g_moveSent, sizeof(RECT));
    ZeroMemory(&g_moveInner, sizeof(RECT));
    ZeroMemory(&g_moveAfterChain, sizeof(RECT));
    g_moveChain = 0xbad;
    g_moveSeq[0] = 0;
    thread = CreateThread(NULL, 0, KeyMoveThread, (LPVOID)(ULONG_PTR)menuKey, 0, NULL);
    Pump(3300);
    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);
    Pump(200);
    g_moveMode = MOVE_NONE;
    GetWindowRect(g_main, after);
}

/* Moves g_main by its caption. Returns FALSE when the caption cannot be hit */
static BOOL MoveWithMouse(int mode, RECT *before, RECT *after)
{
    HANDLE thread;
    POINT start;

    SetWindowPos(g_main, NULL, 100, 100, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    SetForegroundWindow(g_main);
    Pump(200);
    GetWindowRect(g_main, before);
    start.x = before->left + 100;
    start.y = before->top + GetSystemMetrics(SM_CYSIZEFRAME) + GetSystemMetrics(SM_CYCAPTION) / 2;
    if (SendMessageW(g_main, WM_NCHITTEST, 0, MAKELPARAM(start.x, start.y)) != HTCAPTION)
        return FALSE;
    g_moveMode = mode;
    g_cbtMoveSize = g_innerMoveSize = 0;
    ZeroMemory(&g_moveRect, sizeof(RECT));
    ZeroMemory(&g_moveSent, sizeof(RECT));
    ZeroMemory(&g_moveInner, sizeof(RECT));
    ZeroMemory(&g_moveAfterChain, sizeof(RECT));
    g_moveChain = 0xbad;
    g_moveSeq[0] = 0;
    thread = CreateThread(NULL, 0, DragThread, &start, 0, NULL);
    /* the button press starts the move loop inside DispatchMessage */
    Pump(1800);
    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);
    Pump(200);
    g_moveMode = MOVE_NONE;
    GetWindowRect(g_main, after);
    return TRUE;
}

#define RECT_FMT "%ld,%ld-%ld,%ld"
#define RECT_ARGS(r) (r).left, (r).top, (r).right, (r).bottom

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
    HHOOK innerCbt, innerFilter, innerMouse, innerKeyLl, innerMouseLl;
    HWND hwnd;
    RECT rc, before, after, expect;
    MSG msg;
    POINT saved, pt;
    INPUT in;
    BOOL foreground, mouseOver = FALSE, moved = FALSE;
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
    innerMouse = SetWindowsHookExW(WH_MOUSE, InnerMouseProc, NULL, GetCurrentThreadId());
    ok(innerMouse != NULL, "inner WH_MOUSE: error %lu\n", GetLastError());
    innerKeyLl = SetWindowsHookExW(WH_KEYBOARD_LL, InnerKeyboardLlProc, GetModuleHandleW(NULL), 0);
    ok(innerKeyLl != NULL, "inner WH_KEYBOARD_LL: error %lu\n", GetLastError());
    innerMouseLl = SetWindowsHookExW(WH_MOUSE_LL, InnerMouseLlProc, GetModuleHandleW(NULL), 0);
    ok(innerMouseLl != NULL, "inner WH_MOUSE_LL: error %lu\n", GetLastError());
    g_guardPage = VirtualAlloc(NULL, 2 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (g_guardPage)
    {
        DWORD old;

        if (!VirtualProtect(g_guardPage + 4096, 4096, PAGE_NOACCESS, &old))
        {
            VirtualFree(g_guardPage, 0, MEM_RELEASE);
            g_guardPage = NULL;
        }
    }
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
    g_dbgCbtTrack = TRUE;
    g_dbgCbtCalls = g_dbgCbtBad = 0;
    hwnd = CreateWindowExW(0, CLASS_NAME, L"chain", WS_OVERLAPPEDWINDOW, 40, 50, 210, 110, NULL, NULL,
                           wc.hInstance, CREATE_PARAMS);
    g_dbgCbtTrack = FALSE;
    /* WH_DEBUG runs before each of the two WH_CBT hooks, the second one reached through CallNextHookEx, with a
     * CBT_CREATEWND that can be read */
    ok(g_dbgCbtCalls == 2 && g_dbgCbtBad == 0, "WH_DEBUG for HCBT_CREATEWND: %ld calls, %ld without a CBT_CREATEWND\n",
       g_dbgCbtCalls, g_dbgCbtBad);
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

    /* the debug hook blocks the first WH_CBT hook: the next one of the chain runs (and is debugged) */
    {
        LONG outer = g_cbtCreate, inner = g_innerCreate;

        g_dbgCbtTrack = TRUE;
        g_dbgCbtCalls = g_dbgCbtBad = 0;
        g_dbgCbtBlock = 1;
        g_chainResult = 0xbad;
        hwnd = CreateWindowExW(0, CLASS_NAME, L"chain", WS_OVERLAPPEDWINDOW, 40, 50, 210, 110, NULL, NULL,
                               wc.hInstance, CREATE_PARAMS);
        g_dbgCbtTrack = FALSE;
        g_dbgCbtBlock = 0;
        ok(hwnd != NULL, "HCBT_CREATEWND with the first hook blocked: no window\n");
        ok(g_dbgCbtCalls == 2 && g_cbtCreate == outer && g_innerCreate == inner + 1,
           "WH_DEBUG blocked the first WH_CBT hook: %ld debug calls, the outer hook ran %ld times, the inner %ld\n",
           g_dbgCbtCalls, g_cbtCreate - outer, g_innerCreate - inner);
        if (hwnd)
            DestroyWindow(hwnd);

        /* and the second one, reached through CallNextHookEx, is skipped: CallNextHookEx returns 0 */
        outer = g_cbtCreate;
        inner = g_innerCreate;
        g_dbgCbtTrack = TRUE;
        g_dbgCbtCalls = g_dbgCbtBad = 0;
        g_dbgCbtBlock = 2;
        g_chainResult = 0xbad;
        hwnd = CreateWindowExW(0, CLASS_NAME, L"chain", WS_OVERLAPPEDWINDOW, 40, 50, 210, 110, NULL, NULL,
                               wc.hInstance, CREATE_PARAMS);
        g_dbgCbtTrack = FALSE;
        g_dbgCbtBlock = 0;
        ok(hwnd != NULL, "HCBT_CREATEWND with the second hook blocked: no window\n");
        ok(g_dbgCbtCalls == 2 && g_cbtCreate == outer + 1 && g_innerCreate == inner && g_chainResult == 0,
           "WH_DEBUG blocked the second WH_CBT hook: %ld debug calls, the outer hook ran %ld times, the inner %ld, CallNextHookEx %Id\n",
           g_dbgCbtCalls, g_cbtCreate - outer, g_innerCreate - inner, g_chainResult);
        if (hwnd)
            DestroyWindow(hwnd);
    }

    /* WH_SHELL, HCBT_ACTIVATE, HCBT_SETFOCUS. Another window is active first, to know hWndActive */
    g_other = CreateWindowExW(0, L"STATIC", L"other", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 400, 300, 150, 100,
                              NULL, NULL, wc.hInstance, NULL);
    ok(g_other != NULL, "second window: error %lu\n", GetLastError());
    if (g_other)
    {
        SetForegroundWindow(g_other);
        SetActiveWindow(g_other);
        Pump(200);
    }
    g_activateTrack = TRUE;
    trace("main %p other %p active %p foreground %p\n", g_main, g_other, GetActiveWindow(), GetForegroundWindow());
    ShowWindow(g_main, SW_SHOW);
    SetForegroundWindow(g_main);
    SetActiveWindow(g_main);
    Pump(300);
    g_activateTrack = FALSE;
    foreground = GetForegroundWindow() == g_main;
    ok(g_shellCreated >= 1, "HSHELL_WINDOWCREATED: %ld calls\n", g_shellCreated);
    ok(g_cbtActivate >= 1, "HCBT_ACTIVATE: %ld calls\n", g_cbtActivate);
    ok(!g_activateMouse, "HCBT_ACTIVATE: fMouse is TRUE\n");
    for (i = 0; i < (size_t)g_cbtActivateLog; i++)
        trace("HCBT_ACTIVATE call %u: hWndActive %p\n", (UINT)i, g_activateLog[i]);
    g_activateActive = g_activateLog[0];
    trace("HCBT_ACTIVATE: hWndActive %p, other %p, inner %p, active now %p\n", g_activateActive, g_other, g_innerActivateActive, GetActiveWindow());
    /* the outer hook chains: the inner one gets the same CBTACTIVATESTRUCT */
    ok(g_innerActivate >= 1, "chained HCBT_ACTIVATE: inner hook ran %ld times\n", g_innerActivate);
    ok(g_innerActivateHwnd == g_main && g_innerActivateMouse == g_activateMouse,
       "chained HCBT_ACTIVATE: inner hook got wParam %p, fMouse %d\n", g_innerActivateHwnd, g_innerActivateMouse);
    ok(g_innerActivateActive == g_activateActive, "chained HCBT_ACTIVATE: hWndActive %p in the inner hook, %p in the outer\n",
       g_innerActivateActive, g_activateActive);
    /* Windows passes the window that is being activated, not the one that was active (g_other) */
    ok(g_activateActive == g_main && g_activateActive != g_other, "HCBT_ACTIVATE: hWndActive %p, the window is %p\n",
       g_activateActive, g_main);
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
        /* the outer WH_KEYBOARD_LL hook chains: the inner one gets the same record */
        ok(g_innerLlKey[0] == 1 && g_innerLlKey[1] == 1, "chained WH_KEYBOARD_LL: inner hook ran %ld times for the key down, %ld for the key up\n",
           g_innerLlKey[0], g_innerLlKey[1]);
        ok(g_innerLlKeyBad == 0, "chained WH_KEYBOARD_LL: %ld wrong KBDLLHOOKSTRUCT in the inner hook\n", g_innerLlKeyBad);
        trace("WH_KEYBOARD_LL: vk %lx scan %lx flags %lx time %lu\n", g_llKeyCopy[0].vkCode, g_llKeyCopy[0].scanCode,
              g_llKeyCopy[0].flags, g_llKeyCopy[0].time);
        /* A WH_KEYBOARD hook that returns nonzero discards the key */
        g_skipVk = VK_F14;
        g_cbtKeySkipped = 0;
        g_wmKeyF14 = 0;
        SendKey(VK_F14);
        g_skipVk = 0;
        ok(g_keyDown == 2 && g_keyUp == 2, "WH_KEYBOARD: %ld down, %ld up\n", g_keyDown, g_keyUp);
        /* ReactOS: a global WH_KEYBOARD hook of another process (kbswitch) replaces the result of the
         * thread hook chain in co_HOOK_CallHooks, the key is delivered and HCBT_KEYSKIPPED not called.
         * A delivered key tells that this is the case here, the row cannot be met then. */
        if (g_wmKeyF14)
            skip("the key was delivered to the window, a global WH_KEYBOARD hook replaced the result of the thread hook\n");
        else
            ok(g_cbtKeySkipped >= 1 && g_keySkipped == VK_F14, "HCBT_KEYSKIPPED: %ld calls, wParam %Iu\n",
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
    /* the messages of the mouse reach the window only if nothing else is over its middle */
    pt.x = (rc.left + rc.right) / 2;
    pt.y = (rc.top + rc.bottom) / 2;
    hwnd = WindowFromPoint(pt);
    mouseOver = foreground && hwnd == g_main;
    if (foreground && !mouseOver)
        trace("the window at %ld,%ld is %p, not the test window %p\n", pt.x, pt.y, hwnd, g_main);
    ZeroMemory(&in, sizeof(in));
    in.type = INPUT_MOUSE;
    /* Windows scales a small relative move by the speed of the pointer, 1 can end in no move and no message */
    in.mi.dx = 8;
    in.mi.dwFlags = MOUSEEVENTF_MOVE;
    in.mi.time = WHEEL_TIME + 1;
    in.mi.dwExtraInfo = EXTRA_INFO;
    g_msgTime[MT_MOVE] = 0;
    SendInput(1, &in, sizeof(in));
    Pump(300);
    /* another mouse on the desktop can move the cursor meanwhile, and the queue joins moves: send it again */
    for (i = 0; mouseOver && i < 4 && g_msgTime[MT_MOVE] != WHEEL_TIME + 1; i++)
    {
        in.mi.dx = (i & 1) ? 8 : -8;
        SendInput(1, &in, sizeof(in));
        Pump(300);
    }
    ok(g_llMouse >= 1 && g_llMouseOk, "WH_MOUSE_LL: %ld calls, ok %d\n", g_llMouse, g_llMouseOk);
    ok(g_llMouseCopy[0].time == WHEEL_TIME + 1, "WH_MOUSE_LL move: time %lx\n", g_llMouseCopy[0].time);
    /* GetMessageTime of the injected move is the time SendInput was given */
    if (mouseOver)
        ok(g_msgTime[MT_MOVE] == WHEEL_TIME + 1, "WM_MOUSEMOVE: GetMessageTime %lx\n", g_msgTime[MT_MOVE]);
    else
        skip("another window is over the middle of the test window, no mouse messages for it\n");
    ok(g_innerLlMouse[0] == g_llMouse, "chained WH_MOUSE_LL: inner hook ran %ld times, the outer one %ld\n",
       g_innerLlMouse[0], g_llMouse);
    if (foreground)
    {
        ok(g_mouseOurs >= 1, "WH_MOUSE: %ld calls, %ld for the window\n", g_mouse, g_mouseOurs);
        /* the outer WH_MOUSE hook chains: the inner one gets the same MOUSEHOOKSTRUCT */
        ok(g_innerMouse == g_mouseOurs, "chained WH_MOUSE: inner hook ran %ld times, the outer one %ld\n",
           g_innerMouse, g_mouseOurs);
        ok(g_innerMouseBad == 0, "chained WH_MOUSE: %ld wrong MOUSEHOOKSTRUCT in the inner hook\n", g_innerMouseBad);
        if (g_guardPage)
            ok(g_plainChains == 1, "WH_MOUSE: the plain record was chained %ld times\n", g_plainChains);
    }

    /* WH_MOUSE_LL wheel record: point, wheel delta, time */
    SetCursorPos((rc.left + rc.right) / 2, (rc.top + rc.bottom) / 2);
    Pump(100);
    GetCursorPos(&g_wheelPoint);
    ZeroMemory(&in, sizeof(in));
    in.type = INPUT_MOUSE;
    in.mi.mouseData = 120;
    in.mi.dwFlags = MOUSEEVENTF_WHEEL;
    in.mi.time = WHEEL_TIME;
    in.mi.dwExtraInfo = EXTRA_INFO;
    SendInput(1, &in, sizeof(in));
    Pump(300);
    ok(g_llWheel == 1, "WH_MOUSE_LL: %ld wheel calls\n", g_llWheel);
    trace("WH_MOUSE_LL wheel: pt %ld,%ld (cursor %ld,%ld) mouseData %lx flags %lx time %lx\n", g_llWheelRecord.pt.x,
          g_llWheelRecord.pt.y, g_wheelPoint.x, g_wheelPoint.y, g_llWheelRecord.mouseData, g_llWheelRecord.flags,
          g_llWheelRecord.time);
    ok(g_llWheelRecord.pt.x == g_wheelPoint.x && g_llWheelRecord.pt.y == g_wheelPoint.y,
       "WH_MOUSE_LL wheel: pt %ld,%ld, the cursor is at %ld,%ld\n", g_llWheelRecord.pt.x, g_llWheelRecord.pt.y,
       g_wheelPoint.x, g_wheelPoint.y);
    ok((SHORT)HIWORD(g_llWheelRecord.mouseData) == 120, "WH_MOUSE_LL wheel: mouseData %lx\n", g_llWheelRecord.mouseData);
    ok((g_llWheelRecord.flags & LLMHF_INJECTED) != 0, "WH_MOUSE_LL wheel: flags %lx\n", g_llWheelRecord.flags);
    /* the time SendInput was given */
    ok(g_llWheelRecord.time == WHEEL_TIME, "WH_MOUSE_LL wheel: time %lx\n", g_llWheelRecord.time);
    ok(g_innerLlMouse[1] == g_llWheel, "chained WH_MOUSE_LL: inner hook ran %ld times for the wheel, the outer one %ld\n",
       g_innerLlMouse[1], g_llWheel);
    ok(g_innerLlMouseBad == 0, "chained WH_MOUSE_LL: %ld wrong MSLLHOOKSTRUCT in the inner hook\n", g_innerLlMouseBad);
    if (mouseOver)
    {
        ok(g_msgTime[MT_WHEEL] == WHEEL_TIME, "WM_MOUSEWHEEL: GetMessageTime %lx\n", g_msgTime[MT_WHEEL]);

        /* the same for the buttons: a click in the client area of the window */
        in.mi.mouseData = 0;
        in.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
        in.mi.time = WHEEL_TIME + 2;
        SendInput(1, &in, sizeof(in));
        Pump(200);
        in.mi.dwFlags = MOUSEEVENTF_LEFTUP;
        in.mi.time = WHEEL_TIME + 3;
        SendInput(1, &in, sizeof(in));
        Pump(200);
        ok(g_msgTime[MT_DOWN] == WHEEL_TIME + 2, "WM_LBUTTONDOWN: GetMessageTime %lx\n", g_msgTime[MT_DOWN]);
        ok(g_msgTime[MT_UP] == WHEEL_TIME + 3, "WM_LBUTTONUP: GetMessageTime %lx\n", g_msgTime[MT_UP]);
    }
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

    /* HCBT_MOVESIZE when the window is moved by its caption: the hook gets the new rectangle of the
     * window, what it changes is where the window ends up, and a nonzero result cancels the move */
    if (foreground)
    {
        moved = MoveWithMouse(MOVE_PASS, &before, &after);
        if (!moved)
            skip("the caption of the test window cannot be hit\n");
    }
    if (foreground && moved)
    {
        trace("HCBT_MOVESIZE pass: before " RECT_FMT " hook " RECT_FMT " inner " RECT_FMT " after " RECT_FMT "\n",
              RECT_ARGS(before), RECT_ARGS(g_moveRect), RECT_ARGS(g_moveInner), RECT_ARGS(after));
        ok(g_cbtMoveSize == 1, "HCBT_MOVESIZE: %ld calls\n", g_cbtMoveSize);
        ok(after.left > before.left && after.top > before.top &&
           after.right - after.left == before.right - before.left && after.bottom - after.top == before.bottom - before.top,
           "HCBT_MOVESIZE: the window moved from " RECT_FMT " to " RECT_FMT "\n", RECT_ARGS(before), RECT_ARGS(after));
        ok(EqualRect(&g_moveRect, &after), "HCBT_MOVESIZE: the hook got " RECT_FMT ", the window is at " RECT_FMT "\n",
           RECT_ARGS(g_moveRect), RECT_ARGS(after));
        ok(g_innerMoveSize == 1 && EqualRect(&g_moveInner, &g_moveRect),
           "chained HCBT_MOVESIZE: inner hook ran %ld times with " RECT_FMT ", the outer one got " RECT_FMT "\n",
           g_innerMoveSize, RECT_ARGS(g_moveInner), RECT_ARGS(g_moveRect));
        ok(g_moveChain == 0, "chained HCBT_MOVESIZE: CallNextHookEx returned %Id\n", g_moveChain);
        /* the hook comes before the end of the loop */
        ok(strchr(g_moveSeq, 'X') != NULL, "HCBT_MOVESIZE pass: events after the hook '%s', no WM_EXITSIZEMOVE\n", g_moveSeq + 1);

        /* the outer hook changes the rectangle and chains: the inner hook sees the change, the window follows */
        MoveWithMouse(MOVE_OUTER, &before, &after);
        expect = g_moveRect;
        OffsetRect(&expect, 13, 17);
        trace("HCBT_MOVESIZE outer: hook " RECT_FMT " sent " RECT_FMT " inner " RECT_FMT " after " RECT_FMT "\n",
              RECT_ARGS(g_moveRect), RECT_ARGS(g_moveSent), RECT_ARGS(g_moveInner), RECT_ARGS(after));
        ok(g_cbtMoveSize == 1 && g_innerMoveSize == 1, "HCBT_MOVESIZE: %ld calls, %ld in the inner hook\n",
           g_cbtMoveSize, g_innerMoveSize);
        ok(EqualRect(&g_moveInner, &expect), "chained HCBT_MOVESIZE: inner hook got " RECT_FMT ", expected " RECT_FMT "\n",
           RECT_ARGS(g_moveInner), RECT_ARGS(expect));
        ok(EqualRect(&after, &expect), "HCBT_MOVESIZE: the hook set " RECT_FMT ", the window is at " RECT_FMT "\n",
           RECT_ARGS(expect), RECT_ARGS(after));
        /* the order is the hook, the window position change it causes, and then WM_EXITSIZEMOVE */
        ok(MoveSeqIs("PX"), "HCBT_MOVESIZE changed rectangle: events after the hook '%s', expected 'PX'\n", g_moveSeq + 1);

        /* the inner hook changes its copy: the outer hook does not see it and the window is not affected */
        MoveWithMouse(MOVE_INNER, &before, &after);
        trace("HCBT_MOVESIZE inner: hook " RECT_FMT " inner " RECT_FMT " after chain " RECT_FMT " after " RECT_FMT "\n",
              RECT_ARGS(g_moveRect), RECT_ARGS(g_moveInner), RECT_ARGS(g_moveAfterChain), RECT_ARGS(after));
        ok(g_cbtMoveSize == 1 && g_innerMoveSize == 1, "HCBT_MOVESIZE: %ld calls, %ld in the inner hook\n",
           g_cbtMoveSize, g_innerMoveSize);
        ok(EqualRect(&g_moveInner, &g_moveRect), "chained HCBT_MOVESIZE: inner hook got " RECT_FMT ", the outer one " RECT_FMT "\n",
           RECT_ARGS(g_moveInner), RECT_ARGS(g_moveRect));
        ok(EqualRect(&g_moveAfterChain, &g_moveRect), "chained HCBT_MOVESIZE: after CallNextHookEx " RECT_FMT ", before " RECT_FMT "\n",
           RECT_ARGS(g_moveAfterChain), RECT_ARGS(g_moveRect));
        ok(EqualRect(&after, &g_moveRect), "HCBT_MOVESIZE: the window is at " RECT_FMT ", the hook got " RECT_FMT "\n",
           RECT_ARGS(after), RECT_ARGS(g_moveRect));

        /* a nonzero result cancels the move */
        MoveWithMouse(MOVE_CANCEL, &before, &after);
        trace("HCBT_MOVESIZE cancel: before " RECT_FMT " hook " RECT_FMT " after " RECT_FMT "\n",
              RECT_ARGS(before), RECT_ARGS(g_moveRect), RECT_ARGS(after));
        ok(g_cbtMoveSize == 1 && g_innerMoveSize == 0, "HCBT_MOVESIZE: %ld calls, %ld in the inner hook\n",
           g_cbtMoveSize, g_innerMoveSize);
        ok(EqualRect(&after, &before), "HCBT_MOVESIZE: the hook returned 1, the window moved from " RECT_FMT " to " RECT_FMT "\n",
           RECT_ARGS(before), RECT_ARGS(after));
        ok(MoveSeqIs("PX"), "HCBT_MOVESIZE canceled: events after the hook '%s', expected 'PX'\n", g_moveSeq + 1);
    }
    else if (!foreground)
    {
        skip("the test window is not in the foreground, no mouse input for the move\n");
    }

    /* The same with the keyboard: Alt+Space, M, the arrow keys, Return moves the window, one HCBT_MOVESIZE at the end
     * with the final rectangle. An arrow key moves half the height of the caption buttons: 11 pixels at the metrics of
     * Windows 10 (SM_CYSIZE 22; SM_CYCAPTION is 23, which of the two is halved is not told apart there) */
    if (foreground)
    {
        static const WORD rrrdd[] = { VK_RIGHT, VK_RIGHT, VK_RIGHT, VK_DOWN, VK_DOWN, 0 };
        static const WORD rrlll[] = { VK_RIGHT, VK_RIGHT, VK_LEFT, VK_LEFT, VK_LEFT, 0 };
        static const WORD dddrr[] = { VK_DOWN, VK_DOWN, VK_DOWN, VK_RIGHT, VK_RIGHT, 0 };
        static const WORD lllr[] = { VK_LEFT, VK_LEFT, VK_LEFT, VK_RIGHT, 0 };
        LONG step = GetSystemMetrics(SM_CYSIZE) / 2;

        trace("arrow key step %ld (SM_CYSIZE %d, SM_CYCAPTION %d)\n", step, GetSystemMetrics(SM_CYSIZE), GetSystemMetrics(SM_CYCAPTION));
        g_keySeq = rrrdd;
        MoveWithKeyboard(MOVE_PASS, 'M', &before, &after);
        trace("keyboard move pass: before " RECT_FMT " hook " RECT_FMT " after " RECT_FMT "\n", RECT_ARGS(before),
              RECT_ARGS(g_moveRect), RECT_ARGS(after));
        ok(after.left - before.left == 3 * step && after.top - before.top == 2 * step &&
           after.right - after.left == before.right - before.left && after.bottom - after.top == before.bottom - before.top,
           "keyboard move: the window moved from " RECT_FMT " to " RECT_FMT ", the step is %ld\n", RECT_ARGS(before), RECT_ARGS(after), step);
        ok(g_cbtMoveSize == 1 && g_innerMoveSize == 1, "keyboard move: HCBT_MOVESIZE %ld calls, %ld in the inner hook\n",
           g_cbtMoveSize, g_innerMoveSize);
        ok(EqualRect(&g_moveRect, &after), "keyboard move: the hook got " RECT_FMT ", the window is at " RECT_FMT "\n",
           RECT_ARGS(g_moveRect), RECT_ARGS(after));
        ok(strchr(g_moveSeq, 'X') != NULL, "keyboard move pass: events after the hook '%s', no WM_EXITSIZEMOVE\n", g_moveSeq + 1);

        MoveWithKeyboard(MOVE_OUTER, 'M', &before, &after);
        expect = g_moveRect;
        OffsetRect(&expect, 13, 17);
        ok(g_cbtMoveSize == 1 && EqualRect(&after, &expect), "keyboard move: the hook set " RECT_FMT ", the window is at " RECT_FMT "\n",
           RECT_ARGS(expect), RECT_ARGS(after));
        ok(MoveSeqIs("PX"), "keyboard move changed rectangle: events after the hook '%s', expected 'PX'\n", g_moveSeq + 1);

        MoveWithKeyboard(MOVE_CANCEL, 'M', &before, &after);
        ok(g_cbtMoveSize == 1 && EqualRect(&after, &before), "keyboard move: the hook returned 1, the window moved from " RECT_FMT " to " RECT_FMT "\n",
           RECT_ARGS(before), RECT_ARGS(after));
        ok(MoveSeqIs("PX"), "keyboard move canceled: events after the hook '%s', expected 'PX'\n", g_moveSeq + 1);

        /* Alt+Space, S sizes it: the first arrow key of an axis picks the edge that axis moves and takes no step.
         * Right x3 and Down x2: the right edge moves two steps, the bottom edge one */
        MoveWithKeyboard(MOVE_PASS, 'S', &before, &after);
        trace("keyboard size: before " RECT_FMT " hook " RECT_FMT " after " RECT_FMT "\n", RECT_ARGS(before),
              RECT_ARGS(g_moveRect), RECT_ARGS(after));
        ok(g_cbtMoveSize == 1 && EqualRect(&g_moveRect, &after), "keyboard size: HCBT_MOVESIZE %ld calls, the hook got " RECT_FMT ", the window is at " RECT_FMT "\n",
           g_cbtMoveSize, RECT_ARGS(g_moveRect), RECT_ARGS(after));
        ok(after.left == before.left && after.top == before.top && after.right == before.right + 2 * step &&
           after.bottom == before.bottom + step,
           "keyboard size right, right, right, down, down: the window went from " RECT_FMT " to " RECT_FMT ", the step is %ld\n",
           RECT_ARGS(before), RECT_ARGS(after), step);

        /* the opposite key of the axis moves the same edge back: Right x2 and Left x3 leave the right edge two steps in */
        g_keySeq = rrlll;
        MoveWithKeyboard(MOVE_PASS, 'S', &before, &after);
        ok(after.left == before.left && after.top == before.top && after.right == before.right - 2 * step &&
           after.bottom == before.bottom,
           "keyboard size right, right, left, left, left: the window went from " RECT_FMT " to " RECT_FMT ", the step is %ld\n",
           RECT_ARGS(before), RECT_ARGS(after), step);

        /* the second axis is picked the same way after the first: Down x3, Right x2 */
        g_keySeq = dddrr;
        MoveWithKeyboard(MOVE_PASS, 'S', &before, &after);
        ok(after.left == before.left && after.top == before.top && after.right == before.right + step &&
           after.bottom == before.bottom + 2 * step,
           "keyboard size down, down, down, right, right: the window went from " RECT_FMT " to " RECT_FMT ", the step is %ld\n",
           RECT_ARGS(before), RECT_ARGS(after), step);

        /* the left edge: it moves out with Left and in with Right */
        g_keySeq = lllr;
        MoveWithKeyboard(MOVE_PASS, 'S', &before, &after);
        ok(after.left == before.left - step && after.top == before.top && after.right == before.right &&
           after.bottom == before.bottom,
           "keyboard size left, left, left, right: the window went from " RECT_FMT " to " RECT_FMT ", the step is %ld\n",
           RECT_ARGS(before), RECT_ARGS(after), step);
        g_keySeq = rrrdd;
    }

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
    if (foreground)
        ok(g_idle >= 1, "WH_FOREGROUNDIDLE: %ld calls\n", g_idle);
    else
        skip("the test window is not in the foreground, no idle hook\n");

    /* Windows calls WH_DEBUG before each other hook of the thread: wParam is the id of that hook and the
     * DEBUGHOOKINFO tells the thread it runs in. Not for itself and not for the low-level hooks */
    ok(g_debug > 0, "WH_DEBUG: %ld calls\n", g_debug);
    ok(g_debugBad == 0, "WH_DEBUG: %ld calls with the wrong idThread\n", g_debugBad);
    ok((g_debugIds & (1UL << (WH_CBT - WH_MIN))) && (g_debugIds & (1UL << (WH_GETMESSAGE - WH_MIN))) &&
       (g_debugIds & (1UL << (WH_CALLWNDPROC - WH_MIN))) && (g_debugIds & (1UL << (WH_CALLWNDPROCRET - WH_MIN))) &&
       (g_debugIds & (1UL << (WH_SHELL - WH_MIN))),
       "WH_DEBUG: called for the hooks %lx\n", g_debugIds);
    ok(!(g_debugIds & ((1UL << (WH_DEBUG - WH_MIN)) | (1UL << (WH_KEYBOARD_LL - WH_MIN)) | (1UL << (WH_MOUSE_LL - WH_MIN)))),
       "WH_DEBUG: called for itself or a low-level hook: %lx\n", g_debugIds);

    /* a nonzero result keeps the hook that was about to run from running, the message still arrives */
    g_debugBlock = WH_CALLWNDPROC;
    g_debugBlocked = 0;
    g_callWnd = 0;
    ok(SendMessageW(g_main, TEST_MESSAGE, 0x32, (LPARAM)(LONG)0x82345678) == 0x7654, "wrong SendMessage result\n");
    g_debugBlock = -100;
    ok(g_debugBlocked >= 1 && g_callWnd == 0, "WH_DEBUG returned 1: %ld calls, WH_CALLWNDPROC ran %ld times\n",
       g_debugBlocked, g_callWnd);
    ok(SendMessageW(g_main, TEST_MESSAGE, 0x32, (LPARAM)(LONG)0x82345678) == 0x7654, "wrong SendMessage result\n");
    ok(g_callWnd == 1, "WH_CALLWNDPROC: %ld calls after the debug hook stopped blocking\n", g_callWnd);

    /* WH_DEBUG is called before every hook of the chain, those reached through CallNextHookEx too, and a hook it
     * blocks is skipped for the next one, which is called, after the debug hook. Three WH_CALLWNDPROC hooks, 'a'
     * runs first and calls on 'b', which calls on 'c'; 'D' is a call of the debug hook for one of them */
    {
        static const struct { ULONG mask; const char *events; } cwpCases[] =
        {
            { 0, "DaDbDc" },
            { 1, "DDbDc" },
            { 2, "DaDDc" },
            { 4, "DaDbD" },
            { 3, "DDDc" },
            { 7, "DDD" },
        };
        HHOOK hookA, hookB;
        size_t k;

        hookB = SetWindowsHookExW(WH_CALLWNDPROC, CallWndProcB, NULL, GetCurrentThreadId());
        hookA = SetWindowsHookExW(WH_CALLWNDPROC, CallWndProcA, NULL, GetCurrentThreadId());
        ok(hookA && hookB, "WH_CALLWNDPROC: SetWindowsHookExW failed, error %lu\n", GetLastError());
        for (k = 0; k < ARRAYSIZE(cwpCases); k++)
        {
            LRESULT res;

            g_dbgSeq[0] = 0;
            g_dbgCwpCalls = g_dbgCwpBad = g_dbgRetCalls = g_dbgRetBad = 0;
            g_dbgBlockMask = cwpCases[k].mask;
            g_dbgSeqOn = TRUE;
            res = SendMessageW(g_main, TEST_MESSAGE2, 0x33, (LPARAM)(LONG)0x83456789);
            g_dbgSeqOn = FALSE;
            g_dbgBlockMask = 0;
            ok(res == 0x7654, "WH_DEBUG case %u: SendMessage returned %Ix\n", (UINT)k, res);
            ok(!strcmp(g_dbgSeq, cwpCases[k].events), "WH_DEBUG blocks calls %lx of WH_CALLWNDPROC: events '%s', expected '%s'\n",
               cwpCases[k].mask, g_dbgSeq, cwpCases[k].events);
            /* what it gets for WH_CALLWNDPROC and WH_CALLWNDPROCRET is the record the hook gets */
            ok(g_dbgCwpBad == 0, "WH_DEBUG case %u: %ld of %ld calls for WH_CALLWNDPROC without the CWPSTRUCT\n", (UINT)k,
               g_dbgCwpBad, g_dbgCwpCalls);
            ok(g_dbgRetCalls == 1 && g_dbgRetBad == 0, "WH_DEBUG case %u: %ld calls for WH_CALLWNDPROCRET, %ld without the CWPRETSTRUCT\n",
               (UINT)k, g_dbgRetCalls, g_dbgRetBad);
        }
        if (hookA)
            UnhookWindowsHookEx(hookA);
        if (hookB)
            UnhookWindowsHookEx(hookB);
    }

    if (g_other)
        DestroyWindow(g_other);
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
    if (innerMouseLl)
        UnhookWindowsHookEx(innerMouseLl);
    if (innerKeyLl)
        UnhookWindowsHookEx(innerKeyLl);
    if (innerMouse)
        UnhookWindowsHookEx(innerMouse);
    if (innerFilter)
        UnhookWindowsHookEx(innerFilter);
    if (innerCbt)
        UnhookWindowsHookEx(innerCbt);
    if (g_guardPage)
        VirtualFree(g_guardPage, 0, MEM_RELEASE);
    UnregisterClassW(CLASS_NAME, wc.hInstance);
}
