/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Windows, queues and threads that a callback (a hook, a WinEvent procedure, a window
 *              procedure) destroys, detaches or ends while win32k still uses them after the callback.
 *              Each test drives one such interleaving with plain API calls and checks that the call
 *              comes back and that what is left (focus, active window, capture, owner, hook chain)
 *              names no window that is gone. Before the fixes win32k read or wrote freed memory there.
 */

#include "precomp.h"
#include <imm.h>

#define CL_CLASS L"CbLifeClass"

static HINSTANCE ghInst;

static LRESULT CALLBACK ClWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void ClRegister(void)
{
    WNDCLASSW wc = { 0 };

    ghInst = GetModuleHandleW(NULL);
    wc.lpfnWndProc = ClWndProc;
    wc.hInstance = ghInst;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = CL_CLASS;
    RegisterClassW(&wc);
}

static HWND ClCreate(LPCWSTR Title, DWORD Style, HWND hwndParent, int x)
{
    return CreateWindowExW(0, CL_CLASS, Title, Style, x, 50, 160, 120, hwndParent, NULL, ghInst, NULL);
}

static void ClPump(void)
{
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

static BOOL ClWait(HANDLE h, DWORD Ms)
{
    DWORD Start = GetTickCount(), r;
    for (;;)
    {
        DWORD Elapsed = GetTickCount() - Start;
        if (Elapsed >= Ms)
            return FALSE;
        r = MsgWaitForMultipleObjects(1, &h, FALSE, Ms - Elapsed, QS_ALLINPUT);
        if (r == WAIT_OBJECT_0)
            return TRUE;
        if (r != WAIT_OBJECT_0 + 1)
            return FALSE;
        ClPump();
    }
}

static void ClSleepPump(DWORD Ms)
{
    DWORD Start = GetTickCount();
    while (GetTickCount() - Start < Ms)
    {
        MsgWaitForMultipleObjects(0, NULL, FALSE, 10, QS_ALLINPUT);
        ClPump();
    }
}

#define CHECK_WND(h, what) ok((h) == NULL || IsWindow(h), "%s: %p is not a window\n", what, (h))

/* A GUI thread with a window and a message loop, to attach to or to give the foreground to */
typedef struct
{
    HANDLE hThread, hReady, hQuit;
    DWORD tid;
    HWND hwnd;
    BOOL Visible;
} OTHER;

static DWORD WINAPI OtherProc(LPVOID Param)
{
    OTHER *o = Param;

    o->hwnd = ClCreate(L"other", WS_OVERLAPPEDWINDOW | (o->Visible ? WS_VISIBLE : 0), NULL, 500);
    ClPump();
    SetEvent(o->hReady);
    while (MsgWaitForMultipleObjects(1, &o->hQuit, FALSE, INFINITE, QS_ALLINPUT) != WAIT_OBJECT_0)
        ClPump();
    DestroyWindow(o->hwnd);
    return 0;
}

static BOOL OtherStart(OTHER *o, BOOL Visible)
{
    ZeroMemory(o, sizeof(*o));
    o->Visible = Visible;
    o->hReady = CreateEventW(NULL, FALSE, FALSE, NULL);
    o->hQuit = CreateEventW(NULL, TRUE, FALSE, NULL);
    o->hThread = CreateThread(NULL, 0, OtherProc, o, 0, &o->tid);
    if (!o->hThread)
        return FALSE;
    return ClWait(o->hReady, 10000);
}

static void OtherStop(OTHER *o)
{
    if (o->hThread)
    {
        SetEvent(o->hQuit);
        ok(ClWait(o->hThread, 10000), "the other thread did not end\n");
        CloseHandle(o->hThread);
    }
    if (o->hReady) CloseHandle(o->hReady);
    if (o->hQuit) CloseHandle(o->hQuit);
    ZeroMemory(o, sizeof(*o));
}

/*
 * AttachSharedQueue: Z (this thread) attaches to X, so both use one queue Q. The foreground goes to a
 * third thread T. X focuses its window W, then attaches to T: X leaves Q, which Z keeps. X destroys W.
 * Q must not name W any more: Z's SetFocus and GetFocus must not see it.
 */
static struct
{
    HANDLE hXReady, hGo, hXDone, hQuit;
    DWORD tidT;
    HWND hwndW;
    BOOL Attached;
} gAsq;

static DWORD WINAPI AsqThreadX(LPVOID Param)
{
    HWND hwnd = ClCreate(L"asq-X", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 50);

    ClPump();
    gAsq.hwndW = hwnd;
    SetEvent(gAsq.hXReady);
    ClWait(gAsq.hGo, 10000);
    SetActiveWindow(hwnd);
    SetFocus(hwnd);
    gAsq.Attached = AttachThreadInput(GetCurrentThreadId(), gAsq.tidT, TRUE);
    DestroyWindow(hwnd);
    SetEvent(gAsq.hXDone);
    while (MsgWaitForMultipleObjects(1, &gAsq.hQuit, FALSE, INFINITE, QS_ALLINPUT) != WAIT_OBJECT_0)
        ClPump();
    if (gAsq.Attached)
        AttachThreadInput(GetCurrentThreadId(), gAsq.tidT, FALSE);
    return 0;
}

START_TEST(LifetimeAttachSharedQueue)
{
    OTHER t;
    HANDLE hX;
    DWORD tidX;
    HWND hwndZ, hwndRet, hwndFocus;
    BOOL ZAttached;
    int Round;

    ClRegister();
    for (Round = 0; Round < 3; Round++)
    {
        ZeroMemory(&gAsq, sizeof(gAsq));
        gAsq.hXReady = CreateEventW(NULL, FALSE, FALSE, NULL);
        gAsq.hGo = CreateEventW(NULL, TRUE, FALSE, NULL);
        gAsq.hXDone = CreateEventW(NULL, TRUE, FALSE, NULL);
        gAsq.hQuit = CreateEventW(NULL, TRUE, FALSE, NULL);
        hwndZ = ClCreate(L"asq-Z", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 250);
        ok(OtherStart(&t, TRUE), "no thread T\n");
        gAsq.tidT = t.tid;
        hX = CreateThread(NULL, 0, AsqThreadX, NULL, 0, &tidX);
        ok(hX != NULL && ClWait(gAsq.hXReady, 10000), "no thread X\n");

        ZAttached = AttachThreadInput(GetCurrentThreadId(), tidX, TRUE);
        ok(ZAttached, "Z could not attach to X (%lu)\n", GetLastError());
        /* The shared queue is not the foreground queue when X leaves it */
        SetForegroundWindow(t.hwnd);
        ClSleepPump(300);
        SetEvent(gAsq.hGo);
        ok(ClWait(gAsq.hXDone, 10000), "X did not finish\n");
        ok(!IsWindow(gAsq.hwndW), "W still exists\n");

        /* The queue X left is Z's queue: it must still take messages for Z */
        {
            MSG msg;
            BOOL Posted = PostMessageW(hwndZ, WM_APP + 1, 0x77, 0);
            ok(Posted, "round %d: PostMessage to Z failed (%lu)\n", Round, GetLastError());
            ok(PeekMessageW(&msg, hwndZ, WM_APP + 1, WM_APP + 1, PM_REMOVE) && msg.wParam == 0x77,
               "round %d: the posted message did not arrive\n", Round);
        }

        hwndFocus = GetFocus();
        CHECK_WND(hwndFocus, "GetFocus before SetFocus");
        hwndRet = SetFocus(hwndZ);
        trace("round %d: attached X->T %d, SetFocus(Z) returned %p (W was %p), focus %p\n",
              Round, gAsq.Attached, hwndRet, gAsq.hwndW, GetFocus());
        ok(hwndRet == NULL || IsWindow(hwndRet), "SetFocus returned %p, not a window\n", hwndRet);
        hwndFocus = GetFocus();
        CHECK_WND(hwndFocus, "GetFocus after SetFocus");
        CHECK_WND(GetActiveWindow(), "GetActiveWindow");

        /* X ends while Z still uses the queue X created: the keyboard of that queue (when it is the
           foreground queue) must not go to X any more */
        SetEvent(gAsq.hQuit);
        ok(hX && ClWait(hX, 10000), "X did not end\n");
        SetForegroundWindow(hwndZ);
        SetFocus(hwndZ);
        ClPump();
        {
            INPUT in[2] = { { 0 } };
            in[0].type = in[1].type = INPUT_KEYBOARD;
            in[0].ki.wVk = in[1].ki.wVk = VK_SHIFT;
            in[1].ki.dwFlags = KEYEVENTF_KEYUP;
            SendInput(2, in, sizeof(INPUT));
        }
        ClSleepPump(200);
        GetKeyboardLayout(0);
        CHECK_WND(GetFocus(), "GetFocus after X ended");
        if (ZAttached)
            AttachThreadInput(GetCurrentThreadId(), tidX, FALSE);
        if (hX) CloseHandle(hX);
        OtherStop(&t);
        DestroyWindow(hwndZ);
        CloseHandle(gAsq.hXReady); CloseHandle(gAsq.hGo); CloseHandle(gAsq.hXDone); CloseHandle(gAsq.hQuit);
        ClPump();
    }
}

/*
 * SetActiveHookAttach: SetActiveWindow whose CBT hook attaches the input of this thread to another
 * thread on HCBT_ACTIVATE (the queue the activation started with is freed by the attach).
 */
static DWORD gSahTid;
static BOOL gSahFired, gSahAttached;

static LRESULT CALLBACK SahCbt(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HCBT_ACTIVATE && !gSahFired)
    {
        gSahFired = TRUE;
        gSahAttached = AttachThreadInput(GetCurrentThreadId(), gSahTid, TRUE);
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

START_TEST(LifetimeSetActiveHookAttach)
{
    int Round;

    ClRegister();
    for (Round = 0; Round < 3; Round++)
    {
        OTHER o;
        HWND w1, w2, hwndRet;
        HHOOK hHook;

        w1 = ClCreate(L"sah-1", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 50);
        w2 = ClCreate(L"sah-2", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 250);
        ok(OtherStart(&o, FALSE), "no other thread\n");
        gSahTid = o.tid;
        SetForegroundWindow(w1);
        SetActiveWindow(w1);
        ClPump();
        gSahFired = gSahAttached = FALSE;
        hHook = SetWindowsHookExW(WH_CBT, SahCbt, NULL, GetCurrentThreadId());
        hwndRet = SetActiveWindow(w2);
        UnhookWindowsHookEx(hHook);
        trace("round %d: fired %d attached %d, SetActiveWindow returned %p (w1 %p), active %p, focus %p\n",
              Round, gSahFired, gSahAttached, hwndRet, w1, GetActiveWindow(), GetFocus());
        ok(gSahFired, "the hook was not called\n");
        CHECK_WND(GetActiveWindow(), "GetActiveWindow");
        CHECK_WND(GetFocus(), "GetFocus");
        if (gSahAttached)
            AttachThreadInput(GetCurrentThreadId(), o.tid, FALSE);
        /* The thread and its queue must still work */
        SetActiveWindow(w1);
        SetFocus(w1);
        ClPump();
        ok(GetFocus() == w1, "the focus is %p, not w1 %p\n", GetFocus(), w1);
        OtherStop(&o);
        DestroyWindow(w1);
        DestroyWindow(w2);
        ClPump();
    }
}

/*
 * SetFocusTopDestroy: SetFocus on the child of a top-level window that is not active. SetFocus has to
 * activate the top-level window first; the CBT hook destroys it on HCBT_ACTIVATE and creates new windows
 * of the same class (which can take the freed memory). None of them may become the active window.
 */
#define BAIT_COUNT 6
static struct
{
    HWND hwndTop, Bait[BAIT_COUNT];
    BOOL Fired;
} gSft;

static LRESULT CALLBACK SftCbt(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HCBT_ACTIVATE && !gSft.Fired && (HWND)wParam == gSft.hwndTop)
    {
        int i;
        gSft.Fired = TRUE;
        DestroyWindow(gSft.hwndTop);
        for (i = 0; i < BAIT_COUNT; i++)
            gSft.Bait[i] = ClCreate(L"bait", WS_OVERLAPPEDWINDOW, NULL, 300);
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

START_TEST(LifetimeSetFocusTopDestroy)
{
    int Round, i;

    ClRegister();
    for (Round = 0; Round < 4; Round++)
    {
        HWND hwndOther, hwndChild, hwndRet, hwndActive;
        HHOOK hHook;

        ZeroMemory(&gSft, sizeof(gSft));
        hwndOther = ClCreate(L"sft-active", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 400);
        gSft.hwndTop = ClCreate(L"sft-top", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 50);
        hwndChild = ClCreate(L"sft-child", WS_CHILD | WS_VISIBLE, gSft.hwndTop, 10);
        SetForegroundWindow(hwndOther);
        SetActiveWindow(hwndOther);
        ClPump();
        ok(GetActiveWindow() == hwndOther, "round %d: the active window is %p, not %p\n", Round, GetActiveWindow(), hwndOther);

        hHook = SetWindowsHookExW(WH_CBT, SftCbt, NULL, GetCurrentThreadId());
        hwndRet = SetFocus(hwndChild);
        UnhookWindowsHookEx(hHook);
        hwndActive = GetActiveWindow();
        trace("round %d: fired %d, SetFocus returned %p, active %p, focus %p\n",
              Round, gSft.Fired, hwndRet, hwndActive, GetFocus());
        ok(gSft.Fired, "round %d: the hook was not called\n", Round);
        ok(!IsWindow(gSft.hwndTop) && !IsWindow(hwndChild), "round %d: the windows are still there\n", Round);
        CHECK_WND(hwndActive, "GetActiveWindow");
        CHECK_WND(GetFocus(), "GetFocus");
        for (i = 0; i < BAIT_COUNT; i++)
        {
            ok(hwndActive == NULL || hwndActive != gSft.Bait[i],
               "round %d: window %d (%p), created in the hook and never shown, became the active window\n",
               Round, i, gSft.Bait[i]);
        }
        /* The queue must still work */
        SetActiveWindow(hwndOther);
        SetFocus(hwndOther);
        ClPump();
        ok(GetFocus() == hwndOther, "round %d: focus %p, not %p\n", Round, GetFocus(), hwndOther);
        for (i = 0; i < BAIT_COUNT; i++)
            DestroyWindow(gSft.Bait[i]);
        DestroyWindow(hwndOther);
        ClPump();
    }
}

/*
 * ActivePrevFreed: A was active before B (A is the queue's previous active window). A becomes a child of
 * C through SetParent, and C is destroyed with it. Then B goes away and the activation looks for another
 * window: the previous active window must not be A's freed storage.
 */
START_TEST(LifetimeActivePrevFreed)
{
    int Round, i;

    ClRegister();
    for (Round = 0; Round < 4; Round++)
    {
        HWND a, b, c, d, Bait[BAIT_COUNT], hwndActive;

        d = ClCreate(L"apf-D", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 600);
        a = ClCreate(L"apf-A", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 50);
        b = ClCreate(L"apf-B", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 250);
        c = ClCreate(L"apf-C", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 450);
        SetForegroundWindow(a);
        SetActiveWindow(a);
        SetActiveWindow(b);
        ClPump();
        ok(GetActiveWindow() == b, "round %d: active %p, not B %p\n", Round, GetActiveWindow(), b);
        ok(SetParent(a, c) != NULL, "round %d: SetParent failed (%lu)\n", Round, GetLastError());
        DestroyWindow(c);
        ok(!IsWindow(a), "round %d: A survived its new parent\n", Round);
        for (i = 0; i < BAIT_COUNT; i++)
            Bait[i] = ClCreate(L"bait", WS_POPUP | WS_VISIBLE | WS_DISABLED, NULL, 300);
        DestroyWindow(b);
        ClPump();
        hwndActive = GetActiveWindow();
        trace("round %d: after B: active %p, focus %p\n", Round, hwndActive, GetFocus());
        CHECK_WND(hwndActive, "GetActiveWindow");
        CHECK_WND(GetFocus(), "GetFocus");
        SetActiveWindow(d);
        SetActiveWindow(NULL);
        CHECK_WND(GetActiveWindow(), "GetActiveWindow after SetActiveWindow(NULL)");
        for (i = 0; i < BAIT_COUNT; i++)
            DestroyWindow(Bait[i]);
        DestroyWindow(d);
        ClPump();
    }
}

/*
 * WinEventUnhook: three in-context WinEvent hooks on the same event. The first one unhooks the second
 * (or itself, or both) from inside its procedure. The walk of the hook list must go on with the hooks
 * that are left; an unhooked hook is not called again.
 */
static HWINEVENTHOOK gWeh[3];
static LONG gWehCalls[3];
static int gWehMode;

static void CALLBACK WehProc(int Index, HWINEVENTHOOK hHook)
{
    gWehCalls[Index]++;
    if (Index == 0 && gWehCalls[0] == 1)
    {
        if (gWehMode == 0 || gWehMode == 1)
        {
            UnhookWinEvent(gWeh[1]);
            gWeh[1] = NULL;
        }
        if (gWehMode == 1 || gWehMode == 2)
        {
            UnhookWinEvent(gWeh[0]);
            gWeh[0] = NULL;
        }
    }
}

static void CALLBACK WehProc0(HWINEVENTHOOK h, DWORD e, HWND w, LONG o, LONG c, DWORD t, DWORD ms) { WehProc(0, h); }
static void CALLBACK WehProc1(HWINEVENTHOOK h, DWORD e, HWND w, LONG o, LONG c, DWORD t, DWORD ms) { WehProc(1, h); }
static void CALLBACK WehProc2(HWINEVENTHOOK h, DWORD e, HWND w, LONG o, LONG c, DWORD t, DWORD ms) { WehProc(2, h); }

START_TEST(LifetimeWinEventUnhook)
{
    static const WINEVENTPROC Procs[3] = { WehProc0, WehProc1, WehProc2 };
    static const char *ModeName[] = { "unhook next", "unhook next and self", "unhook self" };
    HWND hwnd;
    int Mode, i, Round;

    ClRegister();
    hwnd = ClCreate(L"weh", WS_OVERLAPPEDWINDOW, NULL, 50);
    for (Round = 0; Round < 5; Round++)
    {
        for (Mode = 0; Mode < 3; Mode++)
        {
            gWehMode = Mode;
            for (i = 0; i < 3; i++)
            {
                gWehCalls[i] = 0;
                gWeh[i] = SetWinEventHook(EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE, ghInst, Procs[i],
                                          GetCurrentProcessId(), GetCurrentThreadId(), WINEVENT_INCONTEXT);
                ok(gWeh[i] != NULL, "%s: hook %d not set (%lu)\n", ModeName[Mode], i, GetLastError());
            }
            NotifyWinEvent(EVENT_OBJECT_NAMECHANGE, hwnd, OBJID_WINDOW, CHILDID_SELF);
            ok(gWehCalls[0] == 1, "%s: hook 0 called %ld times\n", ModeName[Mode], gWehCalls[0]);
            if (Mode == 2)
                ok(gWehCalls[1] == 1, "%s: hook 1 called %ld times\n", ModeName[Mode], gWehCalls[1]);
            else
                ok(gWehCalls[1] == 0, "%s: hook 1 called %ld times after it was unhooked\n", ModeName[Mode], gWehCalls[1]);
            ok(gWehCalls[2] == 1, "%s: hook 2 called %ld times\n", ModeName[Mode], gWehCalls[2]);
            /* Once more: only the hooks that are left */
            NotifyWinEvent(EVENT_OBJECT_NAMECHANGE, hwnd, OBJID_WINDOW, CHILDID_SELF);
            ok(gWehCalls[2] == 2, "%s: hook 2 called %ld times after the second event\n", ModeName[Mode], gWehCalls[2]);
            for (i = 0; i < 3; i++)
            {
                if (gWeh[i])
                    UnhookWinEvent(gWeh[i]);
                gWeh[i] = NULL;
            }
        }
    }
    DestroyWindow(hwnd);
}

/*
 * CaptureWinEvent: SetCapture moves the capture from W1 to W2. An in-context WinEvent procedure for
 * EVENT_SYSTEM_CAPTUREEND (of W1) destroys W2, or attaches the input of the thread to another thread.
 */
static struct
{
    HWND hwndNew;
    DWORD tidOther;
    int Mode;
    BOOL Fired, Attached;
} gCwe;

static void CALLBACK CweProc(HWINEVENTHOOK h, DWORD Event, HWND hwnd, LONG idObject, LONG idChild, DWORD tid, DWORD ms)
{
    if (gCwe.Fired)
        return;
    gCwe.Fired = TRUE;
    if (gCwe.Mode == 0)
        DestroyWindow(gCwe.hwndNew);
    else
        gCwe.Attached = AttachThreadInput(GetCurrentThreadId(), gCwe.tidOther, TRUE);
}

START_TEST(LifetimeCaptureWinEvent)
{
    static const char *ModeName[] = { "destroy", "attach" };
    int Mode, Round;

    ClRegister();
    for (Round = 0; Round < 3; Round++)
    {
        for (Mode = 0; Mode < 2; Mode++)
        {
            OTHER o;
            HWND w1, hwndRet;
            HWINEVENTHOOK hHook;

            ZeroMemory(&gCwe, sizeof(gCwe));
            gCwe.Mode = Mode;
            w1 = ClCreate(L"cwe-1", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 50);
            gCwe.hwndNew = ClCreate(L"cwe-2", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 250);
            if (Mode == 1)
            {
                ok(OtherStart(&o, FALSE), "no other thread\n");
                gCwe.tidOther = o.tid;
            }
            SetForegroundWindow(w1);
            ClPump();
            SetCapture(w1);
            hHook = SetWinEventHook(EVENT_SYSTEM_CAPTUREEND, EVENT_SYSTEM_CAPTUREEND, ghInst, CweProc,
                                    GetCurrentProcessId(), GetCurrentThreadId(), WINEVENT_INCONTEXT);
            ok(hHook != NULL, "no hook (%lu)\n", GetLastError());
            hwndRet = SetCapture(gCwe.hwndNew);
            UnhookWinEvent(hHook);
            trace("%s round %d: fired %d attached %d, SetCapture returned %p (w1 %p), capture %p\n",
                  ModeName[Mode], Round, gCwe.Fired, gCwe.Attached, hwndRet, w1, GetCapture());
            ok(gCwe.Fired, "%s: the event procedure was not called\n", ModeName[Mode]);
            CHECK_WND(GetCapture(), "GetCapture");
            CHECK_WND(GetFocus(), "GetFocus");
            ReleaseCapture();
            CHECK_WND(GetCapture(), "GetCapture after ReleaseCapture");
            if (Mode == 1)
            {
                if (gCwe.Attached)
                    AttachThreadInput(GetCurrentThreadId(), o.tid, FALSE);
                OtherStop(&o);
            }
            SetCapture(w1);
            ok(GetCapture() == w1, "%s: the capture is %p, not w1\n", ModeName[Mode], GetCapture());
            ReleaseCapture();
            if (IsWindow(gCwe.hwndNew))
                DestroyWindow(gCwe.hwndNew);
            DestroyWindow(w1);
            ClPump();
        }
    }
}

/*
 * ForegroundWinEvent: SetActiveWindow; an in-context WinEvent procedure for EVENT_SYSTEM_FOREGROUND (sent
 * while the activation runs) attaches the input of the thread to another thread, or destroys the window
 * being activated.
 */
static struct
{
    HWND hwndTarget;
    DWORD tidOther;
    int Mode;
    BOOL Fired, Attached;
} gFwe;

static void CALLBACK FweProc(HWINEVENTHOOK h, DWORD Event, HWND hwnd, LONG idObject, LONG idChild, DWORD tid, DWORD ms)
{
    if (gFwe.Fired || hwnd != gFwe.hwndTarget)
        return;
    gFwe.Fired = TRUE;
    if (gFwe.Mode == 0)
        gFwe.Attached = AttachThreadInput(GetCurrentThreadId(), gFwe.tidOther, TRUE);
    else
        DestroyWindow(gFwe.hwndTarget);
}

START_TEST(LifetimeForegroundWinEvent)
{
    static const char *ModeName[] = { "attach", "destroy" };
    int Mode, Round;

    ClRegister();
    for (Round = 0; Round < 3; Round++)
    {
        for (Mode = 0; Mode < 2; Mode++)
        {
            OTHER o;
            HWND w1, hwndRet;
            HWINEVENTHOOK hHook;

            ZeroMemory(&gFwe, sizeof(gFwe));
            gFwe.Mode = Mode;
            w1 = ClCreate(L"fwe-1", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 50);
            gFwe.hwndTarget = ClCreate(L"fwe-2", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 250);
            ok(OtherStart(&o, FALSE), "no other thread\n");
            gFwe.tidOther = o.tid;
            SetForegroundWindow(w1);
            SetActiveWindow(w1);
            ClPump();
            hHook = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, ghInst, FweProc,
                                    GetCurrentProcessId(), GetCurrentThreadId(), WINEVENT_INCONTEXT);
            ok(hHook != NULL, "no hook (%lu)\n", GetLastError());
            hwndRet = SetActiveWindow(gFwe.hwndTarget);
            UnhookWinEvent(hHook);
            trace("%s round %d: fired %d attached %d, SetActiveWindow returned %p (w1 %p), active %p, focus %p\n",
                  ModeName[Mode], Round, gFwe.Fired, gFwe.Attached, hwndRet, w1, GetActiveWindow(), GetFocus());
            CHECK_WND(GetActiveWindow(), "GetActiveWindow");
            CHECK_WND(GetFocus(), "GetFocus");
            if (gFwe.Attached)
                AttachThreadInput(GetCurrentThreadId(), o.tid, FALSE);
            OtherStop(&o);
            SetActiveWindow(w1);
            SetFocus(w1);
            ClPump();
            ok(GetFocus() == w1, "%s: focus %p, not w1 %p\n", ModeName[Mode], GetFocus(), w1);
            if (IsWindow(gFwe.hwndTarget))
                DestroyWindow(gFwe.hwndTarget);
            DestroyWindow(w1);
            ClPump();
        }
    }
}

/*
 * CbtActivateRecursion: the CBT hook calls SetFocus on a child of the window it is told about on
 * HCBT_ACTIVATE. That activates the same window again from inside its own activation. The activation
 * must not call the hook again for it, level after level, until the kernel stack is used up.
 */
static struct
{
    HWND hwndTop, hwndChild;
    LONG Calls;
} gCar;

static LRESULT CALLBACK CarCbt(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HCBT_ACTIVATE && (HWND)wParam == gCar.hwndTop)
    {
        if (++gCar.Calls < 200)
            SetFocus(gCar.hwndChild);
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

START_TEST(LifetimeCbtActivateRecursion)
{
    int Round;

    ClRegister();
    for (Round = 0; Round < 3; Round++)
    {
        HWND hwndOther, hwndRet;
        HHOOK hHook;

        ZeroMemory(&gCar, sizeof(gCar));
        hwndOther = ClCreate(L"car-active", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 400);
        gCar.hwndTop = ClCreate(L"car-top", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 50);
        gCar.hwndChild = ClCreate(L"car-child", WS_CHILD | WS_VISIBLE, gCar.hwndTop, 10);
        SetForegroundWindow(hwndOther);
        SetActiveWindow(hwndOther);
        ClPump();
        hHook = SetWindowsHookExW(WH_CBT, CarCbt, NULL, GetCurrentThreadId());
        hwndRet = SetActiveWindow(gCar.hwndTop);
        UnhookWindowsHookEx(hHook);
        trace("round %d: HCBT_ACTIVATE calls %ld, SetActiveWindow returned %p, active %p, focus %p\n",
              Round, gCar.Calls, hwndRet, GetActiveWindow(), GetFocus());
        ok(gCar.Calls >= 1, "round %d: the hook was not called\n", Round);
        ok(gCar.Calls <= 2, "round %d: HCBT_ACTIVATE called %ld times for one activation\n", Round, gCar.Calls);
        ok(GetActiveWindow() == gCar.hwndTop, "round %d: active %p, not %p\n", Round, GetActiveWindow(), gCar.hwndTop);
        CHECK_WND(GetFocus(), "GetFocus");
        DestroyWindow(gCar.hwndTop);
        DestroyWindow(hwndOther);
        ClPump();
    }
}

/*
 * InfoCallbacks: NtUser calls that send a message to the window and may look at it afterwards; the window
 * destroys itself inside the message (GetListBoxInfo, GetComboBoxInfo of a window that is not a list or
 * combo box; the clipboard viewer chain).
 */
static BOOL gIcDestroy;

static LRESULT CALLBACK IcWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case LB_GETLISTBOXINFO:
        case CB_GETCOMBOBOXINFO:
        case WM_CHANGECBCHAIN:
        case WM_DRAWCLIPBOARD:
            if (gIcDestroy)
            {
                gIcDestroy = FALSE;
                DestroyWindow(hwnd);
            }
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

START_TEST(LifetimeInfoCallbacks)
{
    WNDCLASSW wc = { 0 };
    int Round;

    ghInst = GetModuleHandleW(NULL);
    wc.lpfnWndProc = IcWndProc;
    wc.hInstance = ghInst;
    wc.lpszClassName = L"CbLifeInfo";
    RegisterClassW(&wc);

    for (Round = 0; Round < 3; Round++)
    {
        HWND hwnd, v1, v2, v3, hwndNext;
        COMBOBOXINFO cbi;

        hwnd = CreateWindowExW(0, L"CbLifeInfo", L"lb", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, ghInst, NULL);
        gIcDestroy = TRUE;
        GetListBoxInfo(hwnd);
        ok(!IsWindow(hwnd), "GetListBoxInfo: the window is still there\n");

        hwnd = CreateWindowExW(0, L"CbLifeInfo", L"cb", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, ghInst, NULL);
        gIcDestroy = TRUE;
        cbi.cbSize = sizeof(cbi);
        GetComboBoxInfo(hwnd, &cbi);
        ok(!IsWindow(hwnd), "GetComboBoxInfo: the window is still there\n");

        /* Clipboard viewers: v2 heads the chain (next v1); removing v1 sends WM_CHANGECBCHAIN to v2 */
        v1 = CreateWindowExW(0, L"CbLifeInfo", L"v1", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, ghInst, NULL);
        v2 = CreateWindowExW(0, L"CbLifeInfo", L"v2", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, ghInst, NULL);
        hwndNext = SetClipboardViewer(v1);
        SetClipboardViewer(v2);
        gIcDestroy = TRUE;
        ChangeClipboardChain(v1, NULL);
        ok(!IsWindow(v2), "ChangeClipboardChain: the head of the chain is still there\n");
        CHECK_WND(GetClipboardViewer(), "GetClipboardViewer after ChangeClipboardChain");

        /* A new viewer is told WM_DRAWCLIPBOARD and destroys itself */
        v3 = CreateWindowExW(0, L"CbLifeInfo", L"v3", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, ghInst, NULL);
        gIcDestroy = TRUE;
        SetClipboardViewer(v3);
        CHECK_WND(GetClipboardViewer(), "GetClipboardViewer after SetClipboardViewer");
        gIcDestroy = FALSE;
        if (IsWindow(v3))
            ChangeClipboardChain(v3, hwndNext);
        if (IsWindow(v3)) DestroyWindow(v3);
        if (IsWindow(v1)) DestroyWindow(v1);
        CHECK_WND(GetClipboardViewer(), "GetClipboardViewer at the end");
        ClPump();
    }
}

/*
 * OwnerDestroyRace: thread A creates and destroys an owner window in a loop, while thread B creates
 * popups owned by it. A window may outlive its owner only with no owner: GetWindow(GW_OWNER) must be
 * NULL or a window.
 */
static struct
{
    volatile HWND hwndOwner;
    volatile LONG Stop;
    LONG Created, BadOwner;
} gOdr;

static LRESULT CALLBACK OdrOwnerProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_DESTROY)
    {
        /* Give the other thread time to create a window with this owner while it is destroyed */
        Sleep(1);
        SwitchToThread();
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI OdrOwnerThread(LPVOID Param)
{
    while (!gOdr.Stop)
    {
        HWND hwnd = CreateWindowExW(0, L"CbLifeOwner", L"owner", WS_POPUP, 0, 0, 50, 50, NULL, NULL, ghInst, NULL);
        gOdr.hwndOwner = hwnd;
        ClPump();
        Sleep(GetTickCount() % 3);
        DestroyWindow(hwnd);
        gOdr.hwndOwner = NULL;
        ClPump();
    }
    return 0;
}

static DWORD WINAPI OdrOwnedThread(LPVOID Param)
{
    HWND Owned[8] = { 0 };
    int i = 0, j;

    while (!gOdr.Stop)
    {
        HWND hwndOwner = gOdr.hwndOwner, hwnd;
        if (!hwndOwner)
        {
            SwitchToThread();
            continue;
        }
        if (Owned[i])
            DestroyWindow(Owned[i]);
        hwnd = CreateWindowExW(0, CL_CLASS, L"owned", WS_POPUP, 0, 0, 20, 20, hwndOwner, NULL, ghInst, NULL);
        Owned[i] = hwnd;
        if (hwnd)
            InterlockedIncrement(&gOdr.Created);
        i = (i + 1) % 8;
        ClPump();
        for (j = 0; j < 8; j++)
        {
            HWND o;
            if (!Owned[j])
                continue;
            o = GetWindow(Owned[j], GW_OWNER);
            /* The owner can go between the two calls: only an owner that is still named after it is
               gone counts */
            if (o && !IsWindow(o) && GetWindow(Owned[j], GW_OWNER) == o)
                InterlockedIncrement(&gOdr.BadOwner);
        }
    }
    for (j = 0; j < 8; j++)
        if (Owned[j]) DestroyWindow(Owned[j]);
    return 0;
}

START_TEST(LifetimeOwnerDestroyRace)
{
    WNDCLASSW wc = { 0 };
    HANDLE h[3];

    ClRegister();
    wc.lpfnWndProc = OdrOwnerProc;
    wc.hInstance = ghInst;
    wc.lpszClassName = L"CbLifeOwner";
    RegisterClassW(&wc);
    ZeroMemory(&gOdr, sizeof(gOdr));
    h[0] = CreateThread(NULL, 0, OdrOwnerThread, NULL, 0, NULL);
    h[1] = CreateThread(NULL, 0, OdrOwnedThread, NULL, 0, NULL);
    h[2] = CreateThread(NULL, 0, OdrOwnedThread, NULL, 0, NULL);
    Sleep(20000);
    gOdr.Stop = 1;
    ok(WaitForMultipleObjects(3, h, TRUE, 30000) == WAIT_OBJECT_0, "the threads did not end\n");
    trace("%ld owned windows created, %ld with an owner that is not a window\n", gOdr.Created, gOdr.BadOwner);
    ok(gOdr.Created > 0, "no owned window was created\n");
    ok(gOdr.BadOwner == 0, "%ld times an owner that is not a window\n", gOdr.BadOwner);
    CloseHandle(h[0]); CloseHandle(h[1]); CloseHandle(h[2]);
}

/*
 * HookExitLeak: a thread ends inside its own hook procedure (ExitThread from WH_CALLWNDPROC, WH_CBT and
 * WH_GETMESSAGE procedures), or inside WM_INPUTLANGCHANGE of its own ActivateKeyboardLayout. Once it is
 * gone and its handle is closed, nothing may keep the thread object: OpenThread on its id must fail (or
 * find another thread that reuses the id).
 */
static LRESULT CALLBACK HelExitHook(int code, WPARAM wParam, LPARAM lParam)
{
    ExitThread(0x77);
}

static LRESULT CALLBACK HelKlWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_INPUTLANGCHANGE)
        ExitThread(0x77);
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI HelThread(LPVOID Param)
{
    int Kind = (int)(INT_PTR)Param;
    HWND hwnd = ClCreate(L"hel", WS_OVERLAPPEDWINDOW, NULL, 50);
    MSG msg;

    if (Kind == 3)
    {
        /* ActivateKeyboardLayout sends WM_INPUTLANGCHANGE to the focus window of the thread */
        HKL hklOld = GetKeyboardLayout(0), hklNew;
        HWND hwndKl = CreateWindowExW(0, L"CbLifeKl", L"kl", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 0, 0, 100, 100,
                                      NULL, NULL, ghInst, NULL);
        SetForegroundWindow(hwndKl);
        SetFocus(hwndKl);
        hklNew = LoadKeyboardLayoutW(LOWORD(hklOld) == 0x0407 ? L"00000409" : L"00000407", 0);
        if (hklNew && hklNew != hklOld)
            ActivateKeyboardLayout(hklNew, 0);
        DestroyWindow(hwndKl);
        DestroyWindow(hwnd);
        return 1;
    }

    switch (Kind)
    {
        case 0:
            SetWindowsHookExW(WH_CALLWNDPROC, HelExitHook, NULL, GetCurrentThreadId());
            SendMessageW(hwnd, WM_USER, 0, 0);
            break;
        case 1:
            SetWindowsHookExW(WH_CBT, HelExitHook, NULL, GetCurrentThreadId());
            ShowWindow(hwnd, SW_SHOW);
            break;
        default:
            SetWindowsHookExW(WH_GETMESSAGE, HelExitHook, NULL, GetCurrentThreadId());
            PostMessageW(hwnd, WM_USER, 0, 0);
            GetMessageW(&msg, NULL, 0, 0);
            break;
    }
    DestroyWindow(hwnd);
    return 1;
}

START_TEST(LifetimeHookExitLeak)
{
    enum { N = 40 };
    DWORD Tid[N];
    FILETIME Created[N];
    int i, Left = 0, Ended = 0;
    WNDCLASSW wc = { 0 };

    ClRegister();
    wc.lpfnWndProc = HelKlWndProc;
    wc.hInstance = ghInst;
    wc.lpszClassName = L"CbLifeKl";
    RegisterClassW(&wc);
    for (i = 0; i < N; i++)
    {
        FILETIME e, k, u;
        DWORD Code = 0;
        HANDLE h = CreateThread(NULL, 0, HelThread, (LPVOID)(INT_PTR)(i % 4), 0, &Tid[i]);
        ok(h != NULL, "thread %d not created\n", i);
        if (!h)
        {
            Tid[i] = 0;
            continue;
        }
        ok(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0, "thread %d did not end\n", i);
        GetThreadTimes(h, &Created[i], &e, &k, &u);
        GetExitCodeThread(h, &Code);
        if (Code == 0x77)
            Ended++;
        CloseHandle(h);
    }
    ok(Ended == N, "%d of %d threads ended inside their hook or WM_INPUTLANGCHANGE\n", Ended, N);
    Sleep(1000);
    for (i = 0; i < N; i++)
    {
        HANDLE h;
        FILETIME c, e, k, u;
        if (!Tid[i])
            continue;
        h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, Tid[i]);
        if (!h)
            continue;
        /* The same creation time: the very thread that ended */
        if (GetThreadTimes(h, &c, &e, &k, &u) && !memcmp(&c, &Created[i], sizeof(c)))
            Left++;
        CloseHandle(h);
    }
    trace("%d threads ended inside their hook, %d of them still exist as thread objects\n", Ended, Left);
    ok(Left == 0, "%d of %d threads that ended inside their hook procedure are kept\n", Left, N);
}

/*
 * CallbackExitLeak: threads end inside window messages that win32k sends while it holds pool memory of
 * its own (WM_NCCREATE / WM_CREATE under a CBT hook: the CREATESTRUCT for the hook; WM_ACTIVATEAPP: the
 * window list of the activation). The win32k pool must not grow by one block per thread.
 */
typedef struct
{
    ULONG Tag;
    ULONG PagedAllocs, PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs, NonPagedFrees;
    SIZE_T NonPagedUsed;
} CL_POOLTAG;

typedef LONG (WINAPI *PNTQSI)(ULONG, PVOID, ULONG, PULONG);

static LONG ClPoolLive(ULONG Tag)
{
    static PNTQSI pNtQsi;
    static BYTE *Info;
    ULONG Size = 1 << 20, Ret, Count, i;
    CL_POOLTAG *t;

    if (!pNtQsi)
        pNtQsi = (PNTQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!Info)
        Info = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!pNtQsi || !Info || pNtQsi(22 /* SystemPoolTagInformation */, Info, Size, &Ret) != 0)
        return -1;
    Count = *(ULONG *)Info;
    t = (CL_POOLTAG *)(Info + sizeof(SIZE_T));
    for (i = 0; i < Count; i++)
    {
        if (t[i].Tag == Tag)
            return (LONG)(t[i].PagedAllocs - t[i].PagedFrees + t[i].NonPagedAllocs - t[i].NonPagedFrees);
    }
    return 0;
}

#define TAG4(s) ((ULONG)(s)[0] | ((ULONG)(s)[1] << 8) | ((ULONG)(s)[2] << 16) | ((ULONG)(s)[3] << 24))

static UINT gCelExitMsg;
static HANDLE gCelActivated;

static LRESULT CALLBACK CelWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == gCelExitMsg && (msg != WM_ACTIVATEAPP || wParam))
    {
        if (gCelActivated)
            SetEvent(gCelActivated);
        ExitThread(0x77);
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK CelCbt(int code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static DWORD WINAPI CelThread(LPVOID Param)
{
    HWND hwnd;
    SetWindowsHookExW(WH_CBT, CelCbt, NULL, GetCurrentThreadId());
    hwnd = CreateWindowExW(0, L"CbLifeExit", L"cel", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 0, 0, 100, 100, NULL, NULL, ghInst, NULL);
    SetForegroundWindow(hwnd);
    ClSleepPump(2000);
    DestroyWindow(hwnd);
    return 1;
}

static void CelRun(UINT Msg, const char *Name, const char *TagName)
{
    enum { N = 40 };
    LONG Before, After;
    int i, Ended = 0;
    ULONG Tag = TAG4(TagName);
    HWND hwndMine = ClCreate(L"cel-main", WS_OVERLAPPEDWINDOW | WS_VISIBLE, NULL, 300);

    gCelExitMsg = Msg;
    Before = ClPoolLive(Tag);
    for (i = 0; i < N; i++)
    {
        DWORD Code = 0;
        HANDLE h;
        SetForegroundWindow(hwndMine);
        ClPump();
        h = CreateThread(NULL, 0, CelThread, NULL, 0, NULL);
        if (!h)
            continue;
        ClWait(h, 10000);
        GetExitCodeThread(h, &Code);
        if (Code == 0x77)
            Ended++;
        CloseHandle(h);
    }
    ClSleepPump(500);
    After = ClPoolLive(Tag);
    trace("%s: %d of %d threads ended inside the message, %s live blocks %ld -> %ld\n", Name, Ended, N, TagName, Before, After);
    if (Before < 0 || After < 0)
        skip("%s: no pool tag information\n", Name);
    else
        ok(After - Before < N / 2, "%s: %s grew by %ld blocks for %d threads\n", Name, TagName, After - Before, Ended);
    DestroyWindow(hwndMine);
    ClPump();
}

START_TEST(LifetimeCallbackExitLeak)
{
    WNDCLASSW wc = { 0 };

    ClRegister();
    wc.lpfnWndProc = CelWndProc;
    wc.hInstance = ghInst;
    wc.lpszClassName = L"CbLifeExit";
    RegisterClassW(&wc);
    CelRun(WM_NCCREATE, "WM_NCCREATE", "Usho");
    CelRun(WM_CREATE, "WM_CREATE", "Usho");
    CelRun(WM_ACTIVATEAPP, "WM_ACTIVATEAPP", "Uswl");
}

/*
 * WindowListExitLeak: threads end inside the messages that win32k sends to each window of a window list it
 * holds (owned popups shown or hidden, children and owned windows destroyed, the owner group and the owned
 * popups z-ordered). The window-list pool (Uswl) must not grow by one block per thread.
 */
enum { WLEL_SHOWPOPUPS, WLEL_CHILDDESTROY, WLEL_CHILDNCDESTROY, WLEL_OWNEDDESTROY, WLEL_OWNERGROUP, WLEL_OWNEDZORDER };
static volatile LONG gWlelCase, gWlelArmed;

static LRESULT CALLBACK WlelWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LONG_PTR Role = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    BOOL Exit = FALSE;

    if (gWlelArmed)
    {
        switch (gWlelCase)
        {
        case WLEL_SHOWPOPUPS: Exit = (Role == 2 && msg == WM_SHOWWINDOW && lParam == SW_PARENTCLOSING); break;
        case WLEL_CHILDDESTROY: Exit = (Role == 2 && msg == WM_DESTROY); break;
        case WLEL_CHILDNCDESTROY: Exit = (Role == 2 && msg == WM_NCDESTROY); break;
        case WLEL_OWNEDDESTROY: Exit = (Role == 2 && msg == WM_DESTROY); break;
        case WLEL_OWNERGROUP: Exit = (Role == 1 && msg == WM_WINDOWPOSCHANGING); break;
        case WLEL_OWNEDZORDER: Exit = (Role == 2 && msg == WM_WINDOWPOSCHANGED); break;
        }
    }
    if (Exit)
        ExitThread(0x77);
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI WlelThread(LPVOID Param)
{
    BOOL Child = (gWlelCase == WLEL_CHILDDESTROY || gWlelCase == WLEL_CHILDNCDESTROY);
    HWND hwnd1, hwnd2;

    hwnd1 = CreateWindowExW(0, L"WlelClass", L"wlel-1", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 40, 200, 150, NULL, NULL,
                            ghInst, NULL);
    hwnd2 = CreateWindowExW(0, L"WlelClass", L"wlel-2", (Child ? WS_CHILD : WS_POPUP | WS_CAPTION) | WS_VISIBLE,
                            Child ? 5 : 80, Child ? 5 : 80, 80, 60, hwnd1, NULL, ghInst, NULL);
    SetWindowLongPtrW(hwnd1, GWLP_USERDATA, 1);
    SetWindowLongPtrW(hwnd2, GWLP_USERDATA, 2);
    ClPump();
    if (gWlelCase == WLEL_OWNEDZORDER)
        SetWindowPos(hwnd1, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    ClPump();
    InterlockedExchange(&gWlelArmed, 1);
    switch (gWlelCase)
    {
    case WLEL_SHOWPOPUPS: ShowOwnedPopups(hwnd1, FALSE); break;
    case WLEL_OWNERGROUP: SetWindowPos(hwnd2, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE); break;
    case WLEL_OWNEDZORDER:
        SetWindowPos(hwnd2, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
        SetWindowPos(hwnd1, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        break;
    default: DestroyWindow(hwnd1); break;
    }
    InterlockedExchange(&gWlelArmed, 0);
    DestroyWindow(hwnd1);
    return 1;
}

START_TEST(LifetimeWindowListExitLeak)
{
    static const struct { LONG Case; const char *Name; BOOL MustEnd; } Cases[] =
    {
        { WLEL_SHOWPOPUPS, "ShowOwnedPopups / WM_SHOWWINDOW", TRUE },
        { WLEL_CHILDDESTROY, "DestroyWindow / WM_DESTROY of a child", TRUE },
        { WLEL_CHILDNCDESTROY, "DestroyWindow / WM_NCDESTROY of a child", TRUE },
        { WLEL_OWNEDDESTROY, "DestroyWindow / WM_DESTROY of an owned window", TRUE },
        { WLEL_OWNERGROUP, "SetWindowPos of a popup / WM_WINDOWPOSCHANGING of its owner", FALSE },
        { WLEL_OWNEDZORDER, "SetWindowPos of an owner / WM_WINDOWPOSCHANGED of its popup", FALSE },
    };
    enum { N = 40 };
    WNDCLASSW wc = { 0 };
    ULONG Tag = TAG4("Uswl");
    unsigned c;
    int i, Ended;
    LONG Before, After;

    ClRegister();
    wc.lpfnWndProc = WlelWndProc;
    wc.hInstance = ghInst;
    wc.lpszClassName = L"WlelClass";
    RegisterClassW(&wc);
    for (c = 0; c < ARRAYSIZE(Cases); c++)
    {
        gWlelCase = Cases[c].Case;
        Ended = 0;
        Before = ClPoolLive(Tag);
        for (i = 0; i < N; i++)
        {
            DWORD Code = 0;
            HANDLE h = CreateThread(NULL, 0, WlelThread, NULL, 0, NULL);
            if (!h)
                continue;
            ok(ClWait(h, 10000), "%s: thread %d did not end\n", Cases[c].Name, i);
            GetExitCodeThread(h, &Code);
            if (Code == 0x77)
                Ended++;
            CloseHandle(h);
        }
        ClSleepPump(300);
        After = ClPoolLive(Tag);
        trace("%s: %d of %d threads ended inside the message, Uswl live blocks %ld -> %ld\n", Cases[c].Name, Ended, N,
              Before, After);
        if (Cases[c].MustEnd)
            ok(Ended == N, "%s: only %d of %d threads ended inside the message\n", Cases[c].Name, Ended, N);
        if (Before < 0 || After < 0)
            skip("%s: no pool tag information\n", Cases[c].Name);
        else
            ok(After - Before < N / 2, "%s: Uswl grew by %ld blocks for %d threads\n", Cases[c].Name, After - Before,
               Ended);
    }
    UnregisterClassW(L"WlelClass", ghInst);
}

/*
 * BroadcastDesktops: BroadcastSystemMessage to all desktops while another thread creates and closes
 * desktops (the desktop list changes while the broadcast waits for the windows of a desktop).
 */
static volatile LONG gBdStop;

static DWORD WINAPI BdDesktopThread(LPVOID Param)
{
    int i = 0;
    while (!gBdStop)
    {
        WCHAR Name[32];
        HDESK hDesk;
        wsprintfW(Name, L"CbLife%lu_%d", GetCurrentThreadId(), i++ % 4);
        hDesk = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
        Sleep(GetTickCount() % 5);
        if (hDesk)
            CloseDesktop(hDesk);
    }
    return 0;
}

START_TEST(LifetimeBroadcastDesktops)
{
    HANDLE h[2];
    DWORD Start;
    int Count = 0;

    ClRegister();
    gBdStop = 0;
    h[0] = CreateThread(NULL, 0, BdDesktopThread, NULL, 0, NULL);
    h[1] = CreateThread(NULL, 0, BdDesktopThread, NULL, 0, NULL);
    Start = GetTickCount();
    while (GetTickCount() - Start < 15000)
    {
        DWORD Recipients = BSM_ALLDESKTOPS | BSM_APPLICATIONS;
        BroadcastSystemMessageW(BSF_FORCEIFHUNG | BSF_IGNORECURRENTTASK, &Recipients, WM_NULL, 0, 0);
        Recipients = BSM_ALLDESKTOPS | BSM_APPLICATIONS;
        BroadcastSystemMessageW(BSF_QUERY | BSF_IGNORECURRENTTASK, &Recipients, WM_NULL, 0, 0);
        Count++;
    }
    gBdStop = 1;
    ok(WaitForMultipleObjects(2, h, TRUE, 30000) == WAIT_OBJECT_0, "the desktop threads did not end\n");
    trace("%d broadcasts\n", Count);
    ok(Count > 0, "no broadcast\n");
    CloseHandle(h[0]); CloseHandle(h[1]);
}

/*
 * KeyboardLayoutWalk: ActivateKeyboardLayout(KLF_SETFORPROCESS) tells the default IME window of every thread
 * of the process (IMS_ACTIVATELAYOUT). The IME windows are subclassed: while one of them handles the message,
 * the next thread of the process ends. The walk over the threads must go on without the thread that ended.
 */
#define KLW_THREADS 6
static struct
{
    HANDLE hThread[KLW_THREADS], hQuit[KLW_THREADS], hReady;
    WNDPROC OrigProc[KLW_THREADS];
    HWND hwndIme[KLW_THREADS];
    LONG Notified[KLW_THREADS];
} gKlw;

static int KlwIndex(HWND hwnd)
{
    int i;
    for (i = 0; i < KLW_THREADS; i++)
        if (gKlw.hwndIme[i] == hwnd) return i;
    return -1;
}

static LRESULT CALLBACK KlwImeProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int i = KlwIndex(hwnd);
    if (i < 0)
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    if (msg == 0x287 /* WM_IME_SYSTEM */ && wParam == 0x19 /* IMS_ACTIVATELAYOUT */)
    {
        InterlockedIncrement(&gKlw.Notified[i]);
        /* The threads were created in order and the newest comes first in the process's list: thread i - 1 is
           the next one the walk takes. It ends now, while this message is handled */
        if ((i & 1) && gKlw.hThread[i - 1])
        {
            SetEvent(gKlw.hQuit[i - 1]);
            WaitForSingleObject(gKlw.hThread[i - 1], 5000);
        }
    }
    return CallWindowProcW(gKlw.OrigProc[i], hwnd, msg, wParam, lParam);
}

static DWORD WINAPI KlwThread(LPVOID Param)
{
    int i = (int)(INT_PTR)Param;
    HWND hwnd = ClCreate(L"klw", WS_OVERLAPPEDWINDOW, NULL, 50);
    HWND hwndIme = hwnd ? ImmGetDefaultIMEWnd(hwnd) : NULL;
    if (hwndIme)
    {
        gKlw.hwndIme[i] = hwndIme;
        gKlw.OrigProc[i] = (WNDPROC)SetWindowLongPtrW(hwndIme, GWLP_WNDPROC, (LONG_PTR)KlwImeProc);
    }
    SetEvent(gKlw.hReady);
    while (MsgWaitForMultipleObjects(1, &gKlw.hQuit[i], FALSE, INFINITE, QS_ALLINPUT) != WAIT_OBJECT_0)
        ClPump();
    if (hwndIme && gKlw.OrigProc[i] && IsWindow(hwndIme))
        SetWindowLongPtrW(hwndIme, GWLP_WNDPROC, (LONG_PTR)gKlw.OrigProc[i]);
    DestroyWindow(hwnd);
    return 0;
}

/*
 * SendSenderEnds: thread S calls SetWindowPos on a window of this thread, so win32k sends WM_WINDOWPOSCHANGING
 * from S with a WINDOWPOS on S's kernel stack. While the window procedure runs, thread K terminates S and
 * waits until it is gone; then the procedure changes the WINDOWPOS and returns. The change must not be written
 * to the stack of S, which is freed. A second part checks that a sender that still waits gets the change.
 */
#define SSE_ROUNDS 20
static struct
{
    HANDLE hInProc, hSenderGone, hSender;
    HWND hwnd;
    BOOL Hold;
    LONG Calls;
} gSse;

static LRESULT CALLBACK SseWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_WINDOWPOSCHANGING && gSse.hwnd == hwnd && !(((WINDOWPOS *)lParam)->flags & SWP_NOSIZE))
    {
        WINDOWPOS *Pos = (WINDOWPOS *)lParam;

        InterlockedIncrement(&gSse.Calls);
        if (gSse.Hold)
        {
            SetEvent(gSse.hInProc);
            WaitForSingleObject(gSse.hSenderGone, 10000);
        }
        Pos->cx = 177;
        Pos->cy = 133;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI SseSender(LPVOID Param)
{
    SetWindowPos(gSse.hwnd, NULL, 0, 0, 100 + (int)(INT_PTR)Param, 90, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    return 0;
}

static DWORD WINAPI SseKiller(LPVOID Param)
{
    if (WaitForSingleObject(gSse.hInProc, 10000) == WAIT_OBJECT_0)
    {
        TerminateThread(gSse.hSender, 1);
        WaitForSingleObject(gSse.hSender, 10000);
        /* the kernel stack goes with the thread object's last reference and the reaper */
        Sleep(200);
    }
    SetEvent(gSse.hSenderGone);
    return 0;
}

START_TEST(LifetimeSendSenderEnds)
{
    WNDCLASSW wc = { 0 };
    HANDLE hKiller;
    RECT rc;
    int Round;
    DWORD r;

    wc.lpfnWndProc = SseWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"SseClass";
    RegisterClassW(&wc);
    gSse.hwnd = CreateWindowExW(0, L"SseClass", L"sse", WS_OVERLAPPEDWINDOW, 50, 50, 120, 100, NULL, NULL,
                                wc.hInstance, NULL);
    ok(gSse.hwnd != NULL, "no window\n");
    if (!gSse.hwnd)
        return;
    gSse.hInProc = CreateEventW(NULL, FALSE, FALSE, NULL);
    gSse.hSenderGone = CreateEventW(NULL, FALSE, FALSE, NULL);

    /* the sender ends inside the send */
    gSse.Hold = TRUE;
    for (Round = 0; Round < SSE_ROUNDS; Round++)
    {
        gSse.Calls = 0;
        gSse.hSender = CreateThread(NULL, 0, SseSender, (LPVOID)(INT_PTR)Round, 0, NULL);
        hKiller = CreateThread(NULL, 0, SseKiller, NULL, 0, NULL);
        ok(gSse.hSender && hKiller, "round %d: no threads\n", Round);
        if (!gSse.hSender || !hKiller)
            break;
        r = ClWait(gSse.hSender, 10000);
        ok(r, "round %d: the sender did not end\n", Round);
        ok(ClWait(hKiller, 10000), "round %d: the killer did not end\n", Round);
        ok(gSse.Calls == 1, "round %d: %ld WM_WINDOWPOSCHANGING\n", Round, gSse.Calls);
        CloseHandle(gSse.hSender);
        CloseHandle(hKiller);
        ClPump();
    }
    ok(IsWindow(gSse.hwnd), "the window is gone\n");

    /* a sender that waits gets what the procedure wrote */
    gSse.Hold = FALSE;
    gSse.Calls = 0;
    gSse.hSender = CreateThread(NULL, 0, SseSender, (LPVOID)(INT_PTR)5, 0, NULL);
    ok(ClWait(gSse.hSender, 10000), "the sender did not end\n");
    CloseHandle(gSse.hSender);
    ok(gSse.Calls == 1, "%ld WM_WINDOWPOSCHANGING\n", gSse.Calls);
    GetWindowRect(gSse.hwnd, &rc);
    ok(rc.right - rc.left == 177 && rc.bottom - rc.top == 133, "size %ld x %ld, expected 177 x 133\n",
       rc.right - rc.left, rc.bottom - rc.top);

    DestroyWindow(gSse.hwnd);
    CloseHandle(gSse.hInProc);
    CloseHandle(gSse.hSenderGone);
    UnregisterClassW(L"SseClass", wc.hInstance);
}

/*
 * FreeExitClass: a thread destroys its window and ends inside the window's WM_NCDESTROY (or WM_DESTROY of a
 * child). The window must be gone after the thread, and its class must have no window left: UnregisterClass
 * succeeds. Before the fix the free of the window stopped with the thread, and the thread cleanup did not finish
 * it (the window kept its handle and its class).
 */
#define FEC_ROUNDS 10
static UINT gFecMsg;

static LRESULT CALLBACK FecWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == gFecMsg && !(GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_CHILD) == (gFecMsg == WM_NCDESTROY))
        ExitThread(0x77);
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI FecThread(LPVOID Param)
{
    HWND *phwnd = Param;
    HWND hwnd = CreateWindowExW(0, L"FecClass", L"fec", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 60, 60, 150, 100, NULL,
                                NULL, GetModuleHandleW(NULL), NULL);

    phwnd[0] = hwnd;
    phwnd[1] = CreateWindowExW(0, L"FecClass", L"fec-child", WS_CHILD | WS_VISIBLE, 5, 5, 50, 40, hwnd, NULL,
                               GetModuleHandleW(NULL), NULL);
    ClPump();
    DestroyWindow(hwnd);
    return 0;
}

START_TEST(LifetimeFreeExitClass)
{
    static const UINT Msgs[] = { WM_NCDESTROY, WM_DESTROY };
    WNDCLASSW wc = { 0 };
    HWND hwnd[2];
    HANDLE hThread;
    DWORD Code;
    int m, Round;

    for (m = 0; m < 2; m++)
    {
        gFecMsg = Msgs[m];
        wc.lpfnWndProc = FecWndProc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.lpszClassName = L"FecClass";
        ok(RegisterClassW(&wc) != 0, "msg %u: RegisterClass failed (%lu)\n", gFecMsg, GetLastError());
        for (Round = 0; Round < FEC_ROUNDS; Round++)
        {
            hwnd[0] = hwnd[1] = NULL;
            hThread = CreateThread(NULL, 0, FecThread, hwnd, 0, NULL);
            ok(hThread != NULL, "no thread\n");
            if (!hThread)
                break;
            ok(ClWait(hThread, 10000), "msg %u round %d: the thread did not end\n", gFecMsg, Round);
            Code = 0;
            GetExitCodeThread(hThread, &Code);
            ok(Code == 0x77, "msg %u round %d: exit code 0x%lx, the thread did not end in the message\n",
               gFecMsg, Round, Code);
            CloseHandle(hThread);
            ok(!IsWindow(hwnd[0]), "msg %u round %d: the window %p is still there\n", gFecMsg, Round, hwnd[0]);
            ok(!IsWindow(hwnd[1]), "msg %u round %d: the child %p is still there\n", gFecMsg, Round, hwnd[1]);
        }
        SetLastError(0xdeadbeef);
        ok(UnregisterClassW(L"FecClass", wc.hInstance), "msg %u: UnregisterClass failed (%lu)\n", gFecMsg,
           GetLastError());
    }
}

START_TEST(LifetimeKeyboardLayoutWalk)
{
    HKL hklOld, hklNew, hklRet;
    int i, Round, Ime = 0, Ended = 0;

    ClRegister();
    hklOld = GetKeyboardLayout(0);
    hklNew = LoadKeyboardLayoutW(LOWORD(hklOld) == 0x0407 ? L"00000409" : L"00000407", 0);
    if (!hklNew || hklNew == hklOld)
    {
        skip("no second keyboard layout\n");
        return;
    }
    for (Round = 0; Round < 3; Round++)
    {
        ZeroMemory(&gKlw, sizeof(gKlw));
        gKlw.hReady = CreateEventW(NULL, FALSE, FALSE, NULL);
        for (i = 0; i < KLW_THREADS; i++)
        {
            gKlw.hQuit[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
            gKlw.hThread[i] = CreateThread(NULL, 0, KlwThread, (LPVOID)(INT_PTR)i, 0, NULL);
            ClWait(gKlw.hReady, 10000);
        }
        for (i = 0; i < KLW_THREADS; i++)
            if (gKlw.hwndIme[i]) Ime++;
        hklRet = ActivateKeyboardLayout((Round & 1) ? hklOld : hklNew, KLF_SETFORPROCESS);
        ok(hklRet != NULL, "round %d: ActivateKeyboardLayout failed (%lu)\n", Round, GetLastError());
        for (i = 0; i < KLW_THREADS; i++)
        {
            if (WaitForSingleObject(gKlw.hThread[i], 0) == WAIT_OBJECT_0)
                Ended++;
        }
        trace("round %d: %d IME windows, notified %ld %ld %ld %ld %ld %ld, %d threads ended\n", Round, Ime,
              gKlw.Notified[0], gKlw.Notified[1], gKlw.Notified[2], gKlw.Notified[3], gKlw.Notified[4], gKlw.Notified[5], Ended);
        for (i = 0; i < KLW_THREADS; i++)
        {
            SetEvent(gKlw.hQuit[i]);
            ok(ClWait(gKlw.hThread[i], 10000), "round %d: thread %d did not end\n", Round, i);
            CloseHandle(gKlw.hThread[i]);
            CloseHandle(gKlw.hQuit[i]);
        }
        CloseHandle(gKlw.hReady);
        Ime = Ended = 0;
    }
    ActivateKeyboardLayout(hklOld, KLF_SETFORPROCESS);
}
