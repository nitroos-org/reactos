/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     System messages whose lParam points to a structure that a 32-bit process under WoW64 could not send
 *              through win32k (ERROR_CALL_NOT_IMPLEMENTED): WM_NEXTMENU (MDINEXTMENU, written back), the list box
 *              drag messages (DROPSTRUCT), WM_IME_CONTROL / WM_IME_REQUEST / WM_IME_NOTIFY / WM_IME_SYSTEM and
 *              WM_COPYGLOBALDATA (a global block of wParam bytes). Each arrives at a window procedure with its
 *              record intact, in every process flavour, and a record the procedure changes comes back.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <undocuser.h>
#include <imm.h>

#define MSG_DROPOBJECT      0x022a
#define MSG_QUERYDROPOBJECT 0x022b
#define MSG_BEGINDRAG       0x022c
#define MSG_DRAGLOOP        0x022d
#define MSG_DRAGSELECT      0x022e
#define MSG_DRAGMOVE        0x022f
#define MSG_IME_NOTIFY      0x0282
#define MSG_IME_CONTROL     0x0283
#define MSG_IME_SYSTEM      0x0287
#define MSG_IME_REQUEST     0x0288

#define IMC_GETCANDIDATEPOS_    0x0007
#define IMC_SETCOMPOSITIONFONT_ 0x000a
#define IMC_GETCOMPOSITIONFONT_ 0x0009
#define IMC_SETCOMPOSITIONWINDOW_ 0x000c
#define IMC_GETCOMPOSITIONWINDOW_ 0x000b
#define IMC_SETOPENSTATUS_      0x0006
#define IMC_SETSTATUSWINDOWPOS_ 0x0010
#define IMR_COMPOSITIONWINDOW_  0x0001
#define IMR_CANDIDATEWINDOW_    0x0002
#define IMR_COMPOSITIONFONT_    0x0003
#define IMR_RECONVERTSTRING_    0x0004
#define IMR_QUERYCHARPOSITION_  0x0006

static HINSTANCE g_hinst;
static HWND g_frame, g_other;
static HMENU g_menu_in, g_menu_next;
static int g_bad;
static int g_seen[0x400];
static BOOL g_forward_to_def;
static DWORD g_main_tid;

#define BAD(...) do { g_bad++; trace("BAD: " __VA_ARGS__); } while (0)

#define DROP_DATA ((ULONG_PTR)0x5a5a5a5a)

static LRESULT CALLBACK RecProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_NEXTMENU: case MSG_DROPOBJECT: case MSG_QUERYDROPOBJECT: case MSG_BEGINDRAG: case MSG_DRAGLOOP:
    case MSG_DRAGSELECT: case MSG_DRAGMOVE: case MSG_IME_NOTIFY: case MSG_IME_CONTROL: case MSG_IME_SYSTEM:
    case MSG_IME_REQUEST: case WM_COPYGLOBALDATA:
        if (g_forward_to_def)
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        g_seen[msg]++;
        break;
    }

    switch (msg)
    {
    case WM_NEXTMENU:
    {
        MDINEXTMENU *nm = (MDINEXTMENU *)lParam;

        if (nm->hmenuIn != g_menu_in || nm->hmenuNext != NULL || nm->hwndNext != NULL)
            BAD("WM_NEXTMENU record in %p next %p wnd %p (wParam %lx)\n", nm->hmenuIn, nm->hmenuNext, nm->hwndNext,
                (ULONG)wParam);
        nm->hmenuNext = g_menu_next;
        nm->hwndNext = hwnd;
        return 0x3456;
    }
    case MSG_DROPOBJECT: case MSG_QUERYDROPOBJECT: case MSG_DRAGLOOP: case MSG_DRAGSELECT: case MSG_DRAGMOVE:
    {
        DROPSTRUCT *ds = (DROPSTRUCT *)lParam;

        if (ds->hwndSource != hwnd || ds->hwndSink != g_frame || ds->wFmt != 0x1234 || ds->dwData != DROP_DATA ||
            ds->ptDrop.x != -7 || ds->ptDrop.y != 99 || ds->dwControlData != 0x77777777)
            BAD("DROPSTRUCT of %#x: src %p sink %p fmt %x data %lx pt %ld,%ld ctl %lx\n", msg, ds->hwndSource,
                ds->hwndSink, ds->wFmt, (ULONG)ds->dwData, ds->ptDrop.x, ds->ptDrop.y, (ULONG)ds->dwControlData);
        return msg + wParam;
    }
    case MSG_BEGINDRAG:
        return lParam == 0 ? 0x4141 : -1;
    case MSG_IME_CONTROL:
        switch (wParam)
        {
        case IMC_SETCOMPOSITIONWINDOW_:
        {
            COMPOSITIONFORM *cf = (COMPOSITIONFORM *)lParam;
            if (cf->dwStyle != CFS_RECT || cf->ptCurrentPos.x != 11 || cf->ptCurrentPos.y != -12 ||
                cf->rcArea.left != 1 || cf->rcArea.bottom != 4)
                BAD("COMPOSITIONFORM record\n");
            return 1;
        }
        case IMC_GETCANDIDATEPOS_:
        {
            CANDIDATEFORM *cf = (CANDIDATEFORM *)lParam;
            if (cf->dwIndex != 3)
                BAD("CANDIDATEFORM index %lu\n", cf->dwIndex);
            cf->dwStyle = CFS_EXCLUDE; cf->ptCurrentPos.x = 21; cf->ptCurrentPos.y = 22;
            SetRect(&cf->rcArea, 5, 6, 7, 8);
            return 2;
        }
        case IMC_GETCOMPOSITIONFONT_:
        {
            LOGFONTW *lf = (LOGFONTW *)lParam;
            lf->lfHeight = -33; lf->lfWeight = 700; lstrcpyW(lf->lfFaceName, L"ProbeFace");
            return 3;
        }
        case IMC_SETOPENSTATUS_:
            /* a scalar */
            if (lParam != 1)
                BAD("IMC_SETOPENSTATUS lParam %lx\n", (ULONG)lParam);
            return 4;
        case IMC_SETSTATUSWINDOWPOS_:
            if (lParam != MAKELPARAM(30, 40))
                BAD("IMC_SETSTATUSWINDOWPOS lParam %lx\n", (ULONG)lParam);
            return 5;
        }
        return 0;
    case MSG_IME_REQUEST:
        switch (wParam)
        {
        case IMR_COMPOSITIONWINDOW_:
        {
            COMPOSITIONFORM *cf = (COMPOSITIONFORM *)lParam;
            cf->dwStyle = CFS_POINT; cf->ptCurrentPos.x = 8; cf->ptCurrentPos.y = 9;
            return 1;
        }
        case IMR_RECONVERTSTRING_:
        {
            RECONVERTSTRING *rs = (RECONVERTSTRING *)lParam;
            static const WCHAR str[] = L"reconvert";
            DWORD need = sizeof(*rs) + sizeof(str);

            if (!rs)
                return need;
            if (rs->dwSize < need)
                return 0;
            rs->dwStrLen = 9; rs->dwStrOffset = sizeof(*rs); rs->dwCompStrLen = 3; rs->dwCompStrOffset = 2;
            rs->dwTargetStrLen = 3; rs->dwTargetStrOffset = 2;
            memcpy(rs + 1, str, sizeof(str));
            return need;
        }
        case IMR_QUERYCHARPOSITION_:
        {
            IMECHARPOSITION *cp = (IMECHARPOSITION *)lParam;
            if (cp->dwSize != sizeof(*cp) || cp->dwCharPos != 2)
                BAD("IMECHARPOSITION record: size %lu pos %lu\n", cp->dwSize, cp->dwCharPos);
            cp->pt.x = 100; cp->pt.y = 101; cp->cLineHeight = 16; SetRect(&cp->rcDocument, 0, 0, 640, 480);
            return 1;
        }
        }
        return 0;
    case MSG_IME_NOTIFY:
        if (wParam != 0x10 || lParam != 0x20)
            BAD("WM_IME_NOTIFY %lx %lx\n", (ULONG)wParam, (ULONG)lParam);
        return 6;
    case MSG_IME_SYSTEM:
        if (wParam != 0x1e || lParam != 0x30)
            BAD("WM_IME_SYSTEM %lx %lx\n", (ULONG)wParam, (ULONG)lParam);
        return 7;
    case WM_COPYGLOBALDATA:
    {
        /* the receiver gets a new global block with the sender's wParam bytes */
        BYTE *p = GlobalLock((HGLOBAL)lParam);
        SIZE_T i, size = GlobalSize((HGLOBAL)lParam);
        BOOL good = p != NULL && wParam == 200 && size >= 200;

        for (i = 0; good && i < 200; i++)
            good = p[i] == (BYTE)(i * 7 + 3);
        if (!good)
            BAD("WM_COPYGLOBALDATA block %p size %lu wParam %lu\n", p, (ULONG)size, (ULONG)wParam);
        if (p)
            GlobalUnlock((HGLOBAL)lParam);
        return 0x7777;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

typedef struct
{
    MDINEXTMENU nm;
    DROPSTRUCT ds;
    COMPOSITIONFORM comp, comp2;
    CANDIDATEFORM cand;
    LOGFONTW font;
    struct { RECONVERTSTRING rs; WCHAR text[16]; } reconv;
    IMECHARPOSITION pos;
    HGLOBAL global;
    BOOL sent[40];
    DWORD err[40];
    LRESULT ret[40];
    int n;
    BOOL timeout;
} RESULTS;

static HGLOBAL make_global(void)
{
    HGLOBAL h = GlobalAlloc(GHND | GMEM_SHARE, 200);
    BYTE *p = h ? GlobalLock(h) : NULL;
    int i;

    for (i = 0; p && i < 200; i++)
        p[i] = (BYTE)(i * 7 + 3);
    if (p)
        GlobalUnlock(h);
    return h;
}

static void do_send(RESULTS *r, HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    DWORD_PTR res = 0;
    int i = r->n++;

    SetLastError(0xDEADBEEF);
    if (r->timeout)
    {
        r->sent[i] = SendMessageTimeoutW(hwnd, msg, wp, lp, SMTO_NORMAL, 10000, &res) != 0;
        r->ret[i] = (LRESULT)res;
    }
    else
    {
        r->ret[i] = SendMessageW(hwnd, msg, wp, lp);
        r->sent[i] = TRUE;
    }
    r->err[i] = GetLastError();
}

/* Everything in a fixed order: check_results relies on it. */
static void send_all(HWND hwnd, BOOL timeout, RESULTS *r)
{
    memset(r, 0, sizeof(*r));
    r->timeout = timeout;
    r->nm.hmenuIn = g_menu_in;
    do_send(r, hwnd, WM_NEXTMENU, VK_RIGHT, (LPARAM)&r->nm);                      /* 0 */
    r->ds.hwndSource = hwnd; r->ds.hwndSink = g_frame; r->ds.wFmt = 0x1234; r->ds.dwData = DROP_DATA;
    r->ds.ptDrop.x = -7; r->ds.ptDrop.y = 99; r->ds.dwControlData = 0x77777777;
    do_send(r, hwnd, MSG_DROPOBJECT, 1, (LPARAM)&r->ds);                          /* 1 */
    do_send(r, hwnd, MSG_QUERYDROPOBJECT, 2, (LPARAM)&r->ds);                     /* 2 */
    do_send(r, hwnd, MSG_BEGINDRAG, 0, 0);                                        /* 3 */
    do_send(r, hwnd, MSG_DRAGLOOP, 3, (LPARAM)&r->ds);                            /* 4 */
    do_send(r, hwnd, MSG_DRAGSELECT, 4, (LPARAM)&r->ds);                          /* 5 */
    do_send(r, hwnd, MSG_DRAGMOVE, 5, (LPARAM)&r->ds);                            /* 6 */
    r->comp.dwStyle = CFS_RECT; r->comp.ptCurrentPos.x = 11; r->comp.ptCurrentPos.y = -12;
    SetRect(&r->comp.rcArea, 1, 2, 3, 4);
    do_send(r, hwnd, MSG_IME_CONTROL, IMC_SETCOMPOSITIONWINDOW_, (LPARAM)&r->comp); /* 7 */
    r->cand.dwIndex = 3;
    do_send(r, hwnd, MSG_IME_CONTROL, IMC_GETCANDIDATEPOS_, (LPARAM)&r->cand);    /* 8 */
    do_send(r, hwnd, MSG_IME_CONTROL, IMC_GETCOMPOSITIONFONT_, (LPARAM)&r->font); /* 9 */
    do_send(r, hwnd, MSG_IME_CONTROL, IMC_SETOPENSTATUS_, 1);                     /* 10 */
    do_send(r, hwnd, MSG_IME_CONTROL, IMC_SETSTATUSWINDOWPOS_, MAKELPARAM(30, 40)); /* 11 */
    do_send(r, hwnd, MSG_IME_REQUEST, IMR_COMPOSITIONWINDOW_, (LPARAM)&r->comp2); /* 12 */
    do_send(r, hwnd, MSG_IME_REQUEST, IMR_RECONVERTSTRING_, 0);                   /* 13: the size */
    r->reconv.rs.dwSize = sizeof(r->reconv); r->reconv.rs.dwVersion = 0;
    do_send(r, hwnd, MSG_IME_REQUEST, IMR_RECONVERTSTRING_, (LPARAM)&r->reconv);  /* 14 */
    r->pos.dwSize = sizeof(r->pos); r->pos.dwCharPos = 2;
    do_send(r, hwnd, MSG_IME_REQUEST, IMR_QUERYCHARPOSITION_, (LPARAM)&r->pos);   /* 15 */
    do_send(r, hwnd, MSG_IME_NOTIFY, 0x10, 0x20);                                 /* 16 */
    do_send(r, hwnd, MSG_IME_SYSTEM, 0x1e, 0x30);                                 /* 17 */
    r->global = make_global();
    do_send(r, hwnd, WM_COPYGLOBALDATA, 200, (LPARAM)r->global);                  /* 18 (user32 frees the block) */
}

static void check_results(const char *what, HWND hwnd, const RESULTS *r)
{
    static const LRESULT expect[19] = { 0x3456, 0, 0, 0x4141, 0, 0, 0, 1, 2, 3, 4, 5, 1, 0, 0, 1, 6, 7, 0x7777 };
    int i;

    for (i = 0; i < 19; i++)
    {
        LRESULT want = expect[i];
        if (i == 1) want = MSG_DROPOBJECT + 1;
        if (i == 2) want = MSG_QUERYDROPOBJECT + 2;
        if (i == 4) want = MSG_DRAGLOOP + 3;
        if (i == 5) want = MSG_DRAGSELECT + 4;
        if (i == 6) want = MSG_DRAGMOVE + 5;
        if (i == 13) want = sizeof(RECONVERTSTRING) + sizeof(L"reconvert");
        if (i == 14) want = sizeof(RECONVERTSTRING) + sizeof(L"reconvert");
        ok(r->sent[i], "%s: message %d failed: %lu\n", what, i, r->err[i]);
        ok(r->ret[i] == want, "%s: message %d returned %lx, expected %lx\n", what, i, (long)r->ret[i], (long)want);
        /* user32 allocates and frees the global block, which leaves its own last error behind */
        ok(i == 18 || r->err[i] == 0xDEADBEEF, "%s: message %d set the last error to %lu\n", what, i, r->err[i]);
    }
    ok(r->nm.hmenuIn == g_menu_in && r->nm.hmenuNext == g_menu_next && r->nm.hwndNext == hwnd,
       "%s: WM_NEXTMENU record came back as %p %p %p\n", what, r->nm.hmenuIn, r->nm.hmenuNext, r->nm.hwndNext);
    ok(r->ds.hwndSource == hwnd && r->ds.dwData == DROP_DATA && r->ds.ptDrop.x == -7 && r->ds.wFmt == 0x1234,
       "%s: DROPSTRUCT changed\n", what);
    ok(r->comp.dwStyle == CFS_RECT && r->comp.ptCurrentPos.x == 11 && r->comp.rcArea.bottom == 4,
       "%s: COMPOSITIONFORM changed\n", what);
    ok(r->cand.dwStyle == CFS_EXCLUDE && r->cand.ptCurrentPos.x == 21 && r->cand.ptCurrentPos.y == 22 &&
       r->cand.rcArea.left == 5 && r->cand.rcArea.bottom == 8 && r->cand.dwIndex == 3,
       "%s: CANDIDATEFORM came back as %lu %ld %ld\n", what, r->cand.dwStyle, r->cand.ptCurrentPos.x,
       r->cand.ptCurrentPos.y);
    ok(r->font.lfHeight == -33 && r->font.lfWeight == 700 && !lstrcmpW(r->font.lfFaceName, L"ProbeFace"),
       "%s: LOGFONTW came back as %ld %ld\n", what, r->font.lfHeight, r->font.lfWeight);
    ok(r->comp2.dwStyle == CFS_POINT && r->comp2.ptCurrentPos.x == 8 && r->comp2.ptCurrentPos.y == 9,
       "%s: IMR_COMPOSITIONWINDOW came back as %lu %ld\n", what, r->comp2.dwStyle, r->comp2.ptCurrentPos.x);
    ok(r->reconv.rs.dwStrLen == 9 && r->reconv.rs.dwStrOffset == sizeof(RECONVERTSTRING) &&
       r->reconv.rs.dwCompStrLen == 3 && r->reconv.rs.dwTargetStrOffset == 2 &&
       !memcmp(r->reconv.text, L"reconvert", sizeof(L"reconvert")),
       "%s: RECONVERTSTRING came back as %lu %lu\n", what, r->reconv.rs.dwStrLen, r->reconv.rs.dwStrOffset);
    ok(r->pos.pt.x == 100 && r->pos.pt.y == 101 && r->pos.cLineHeight == 16 && r->pos.rcDocument.right == 640,
       "%s: IMECHARPOSITION came back as %ld %ld\n", what, r->pos.pt.x, r->pos.pt.y);
}

static DWORD WINAPI send_thread(void *param)
{
    RESULTS *r = param;
    send_all(g_frame, FALSE, r);
    return 0;
}

static void pump_until(HANDLE thread)
{
    MSG msg;

    while (MsgWaitForMultipleObjects(1, &thread, FALSE, 20000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
}

static HANDLE g_owner_ready, g_owner_quit;

static DWORD WINAPI owner_thread(void *param)
{
    MSG msg;

    g_other = CreateWindowExW(0, L"WmMenuDragImeFrame", L"o", WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, NULL, NULL,
                              g_hinst, NULL);
    SetEvent(g_owner_ready);
    while (MsgWaitForMultipleObjects(1, &g_owner_quit, FALSE, 30000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    DestroyWindow(g_other);
    return 0;
}

static void test_def_window_proc(void)
{
    RESULTS r;
    int i;

    /* the same records handed down to DefWindowProc (through win32k): the send succeeds and the records stay */
    g_forward_to_def = TRUE;
    send_all(g_frame, TRUE, &r);
    g_forward_to_def = FALSE;
    for (i = 0; i < 19; i++)
        ok(r.sent[i], "DefWindowProc: message %d failed: %lu\n", i, r.err[i]);
    ok(r.nm.hmenuNext == NULL && r.nm.hwndNext == NULL, "DefWindowProc: WM_NEXTMENU record changed\n");
    ok(r.ds.dwData == DROP_DATA && r.comp.dwStyle == CFS_RECT, "DefWindowProc: records changed\n");
    ok(r.cand.dwStyle == 0 && r.pos.pt.x == 0, "DefWindowProc: a record was written\n");
}

/* The menu loop of the kernel sends WM_NEXTMENU to the owner window when the arrow key leaves a menu */
static int g_menu_stage, g_next_seen, g_next_ok, g_init2;
static HMENU g_bar;
static LRESULT CALLBACK MenuOwnerProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_NEXTMENU:
    {
        MDINEXTMENU *nm = (MDINEXTMENU *)lParam;

        g_next_seen++;
        if ((nm->hmenuIn == g_bar || nm->hmenuIn == g_menu_in) && (wParam == VK_RIGHT || wParam == VK_LEFT) &&
            nm->hmenuNext == NULL)
            g_next_ok++;
        nm->hmenuNext = g_menu_next;
        nm->hwndNext = hwnd;
        return 0;
    }
    case WM_INITMENUPOPUP:
        if ((HMENU)wParam == g_menu_next)
            g_init2++;
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void CALLBACK menu_timer(HWND hwnd, UINT msg, UINT_PTR id, DWORD time)
{
    g_menu_stage++;
    if (g_menu_stage == 1 || g_menu_stage == 2)
        PostMessageW(hwnd, WM_KEYDOWN, VK_RIGHT, 0x14d0001);
    else if (g_menu_stage == 3)
        PostMessageW(hwnd, WM_KEYDOWN, VK_LEFT, 0x14b0001);
    else if (g_menu_stage > 5)
    {
        KillTimer(hwnd, id);
        EndMenu();
    }
}

static void test_menu_loop(void)
{
    WNDCLASSW wc = { 0 };
    HWND wnd;
    HMENU menu_bar;
    BOOL ret;

    wc.lpfnWndProc = MenuOwnerProc;
    wc.hInstance = g_hinst;
    wc.lpszClassName = L"WmMenuDragImeOwner";
    RegisterClassW(&wc);
    wnd = CreateWindowExW(0, wc.lpszClassName, L"menu", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 0, 0, 300, 200, NULL, NULL,
                          g_hinst, NULL);
    ok(wnd != NULL, "owner window creation failed: %lu\n", GetLastError());
    if (wnd)
    {
        /* g_menu_in is a popup with one item, g_menu_next another popup; VK_RIGHT in the first has no submenu to
         * enter, so the loop asks the owner (WM_NEXTMENU) and switches to the menu the owner names. */
        SetForegroundWindow(wnd);
        SetFocus(wnd);
        g_menu_stage = g_next_seen = g_next_ok = g_init2 = 0;
        g_bar = CreateMenu();
        AppendMenuW(g_bar, MF_POPUP, (UINT_PTR)g_menu_in, L"one");
        SetMenu(wnd, g_bar);
        SetTimer(wnd, 1, 150, menu_timer);
        /* the keyboard menu loop on the menu bar */
        ret = (BOOL)SendMessageW(wnd, WM_SYSCOMMAND, SC_KEYMENU, 0);
        trace("keyboard menu loop returned %d, WM_NEXTMENU seen %d ok %d, next menu initialised %d\n", ret, g_next_seen,
              g_next_ok, g_init2);
        KillTimer(wnd, 1);
        ok(g_next_seen >= 1, "the menu loop did not send WM_NEXTMENU\n");
        ok(g_next_ok == g_next_seen, "WM_NEXTMENU record was wrong %d of %d times\n", g_next_seen - g_next_ok,
           g_next_seen);
        trace("menu named by the owner entered %d times\n", g_init2);
        SetMenu(wnd, NULL);
        DestroyMenu(g_bar);
        DestroyWindow(wnd);
    }
    (void)menu_bar;
    UnregisterClassW(wc.lpszClassName, g_hinst);
}

static void test_default_ime_window(void)
{
    HWND ime;
    COMPOSITIONFORM cf;
    DWORD_PTR res = 0;
    LRESULT ret;

    ime = ImmGetDefaultIMEWnd(g_frame);
    if (!ime)
    {
        skip("no default IME window\n");
        return;
    }
    memset(&cf, 0, sizeof(cf));
    SetLastError(0xDEADBEEF);
    ret = SendMessageTimeoutW(ime, MSG_IME_CONTROL, IMC_GETCOMPOSITIONWINDOW_, (LPARAM)&cf, SMTO_NORMAL, 10000, &res);
    ok(ret != 0 && GetLastError() != ERROR_CALL_NOT_IMPLEMENTED, "default IME window: failed (%lu)\n", GetLastError());
    SetLastError(0xDEADBEEF);
    ret = SendMessageTimeoutW(ime, MSG_IME_CONTROL, IMC_SETOPENSTATUS_, 0, SMTO_NORMAL, 10000, &res);
    ok(ret != 0 && GetLastError() != ERROR_CALL_NOT_IMPLEMENTED, "default IME window, scalar: failed (%lu)\n",
       GetLastError());
}

START_TEST(WmMenuDragIme)
{
    WNDCLASSW wc = { 0 };
    RESULTS r;
    HANDLE thread;
    DWORD tid;

    g_hinst = GetModuleHandleW(NULL);
    g_main_tid = GetCurrentThreadId();
    g_menu_in = CreatePopupMenu();
    AppendMenuW(g_menu_in, MF_STRING, 1, L"one");
    g_menu_next = CreatePopupMenu();
    AppendMenuW(g_menu_next, MF_STRING, 2, L"two");
    wc.lpfnWndProc = RecProc;
    wc.hInstance = g_hinst;
    wc.lpszClassName = L"WmMenuDragImeFrame";
    RegisterClassW(&wc);
    g_frame = CreateWindowExW(0, wc.lpszClassName, L"f", WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, NULL, NULL, g_hinst, NULL);
    ok(g_frame != NULL, "CreateWindowEx failed: %lu\n", GetLastError());
    if (!g_frame)
        return;

    send_all(g_frame, FALSE, &r);
    check_results("SendMessage, same thread", g_frame, &r);
    send_all(g_frame, TRUE, &r);
    check_results("SendMessageTimeout, same thread", g_frame, &r);

    memset(&r, 0, sizeof(r));
    thread = CreateThread(NULL, 0, send_thread, &r, 0, &tid);
    ok(thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (thread)
    {
        pump_until(thread);
        CloseHandle(thread);
        check_results("SendMessage, other thread", g_frame, &r);
    }

    g_owner_ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_owner_quit = CreateEventW(NULL, FALSE, FALSE, NULL);
    thread = CreateThread(NULL, 0, owner_thread, NULL, 0, &tid);
    ok(thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (thread)
    {
        WaitForSingleObject(g_owner_ready, 20000);
        ok(g_other != NULL, "the owner thread has no window\n");
        if (g_other)
        {
            send_all(g_other, FALSE, &r);
            check_results("SendMessage to another thread", g_other, &r);
            send_all(g_other, TRUE, &r);
            check_results("SendMessageTimeout to another thread", g_other, &r);
        }
        SetEvent(g_owner_quit);
        WaitForSingleObject(thread, 20000);
        CloseHandle(thread);
    }
    CloseHandle(g_owner_ready);
    CloseHandle(g_owner_quit);

    test_def_window_proc();
    test_default_ime_window();
    test_menu_loop();

    ok(g_bad == 0, "%d records did not arrive as sent\n", g_bad);
    ok(g_seen[WM_NEXTMENU] >= 4 && g_seen[MSG_DROPOBJECT] >= 4 && g_seen[MSG_BEGINDRAG] >= 4 &&
       g_seen[MSG_IME_CONTROL] >= 20 && g_seen[MSG_IME_REQUEST] >= 16 && g_seen[MSG_IME_NOTIFY] >= 4 &&
       g_seen[MSG_IME_SYSTEM] >= 4 && g_seen[WM_COPYGLOBALDATA] >= 4,
       "messages seen: nextmenu %d drop %d begin %d imec %d imer %d imen %d imes %d global %d\n",
       g_seen[WM_NEXTMENU], g_seen[MSG_DROPOBJECT], g_seen[MSG_BEGINDRAG], g_seen[MSG_IME_CONTROL],
       g_seen[MSG_IME_REQUEST], g_seen[MSG_IME_NOTIFY], g_seen[MSG_IME_SYSTEM], g_seen[WM_COPYGLOBALDATA]);

    DestroyWindow(g_frame);
    DestroyMenu(g_menu_in);
    DestroyMenu(g_menu_next);
    UnregisterClassW(wc.lpszClassName, g_hinst);
}
