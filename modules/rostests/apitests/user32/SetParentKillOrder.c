/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Robustness test for a window that is a child of a window of ANOTHER process (SetParent across
 *              processes, as WebView2 hosting does) when one of the two processes ends before the other.
 *              Two cooperating helper processes of this test build the pair, with attached input queues, a
 *              focused child and a captured child. The driver ends one of them (terminate or normal exit), in
 *              both orders, many iterations. The system must survive and the surviving window must behave as
 *              Windows does (measured on Windows 10 22H2, 2026-11-04): after the PARENT's process ended the
 *              child is alive until its thread looks at its messages and hidden, GetParent and GetAncestor
 *              still return the destroyed parent, SetWindowPos, SetFocus, SetParent(,NULL) and CreateWindow
 *              with that parent fail with ERROR_INVALID_PARAMETER, MoveWindow works, GetFocus is NULL and
 *              GetCapture is still the child; after the CHILD's process ended the parent works normally and
 *              the capture is gone.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Usage: user32_apitest SetParentKillOrder [iterations [order]]   order: 0 parent first, 1 child first, 2 both
 */

#include "precomp.h"

enum
{
    EV_HOSTUP, EV_BROWSERUP, EV_ADOPTED, EV_BFOCUSED, EV_SETTLED,
    EV_CHECK_H, EV_CHECK_B, EV_CHECKED_H, EV_CHECKED_B, EV_EXIT_H, EV_EXIT_B,
    EV_COUNT
};

enum
{
    CK_B_ALIVE, CK_B_HIDDEN, CK_B_PARENT, CK_B_ANCESTOR, CK_B_SWP87, CK_B_SETFOCUS87, CK_B_SETPARENT87,
    CK_B_CREATE87, CK_B_MOVE_OK, CK_B_CAPTURE, CK_B_GETFOCUS, CK_B_FINAL_GONE, CK_B_FINAL_NOCAPTURE,
    CK_H_CHILD_GONE, CK_H_CAPTURE_GONE, CK_H_FOCUS_VALID, CK_H_PARENT_OK, CK_H_SETFOCUS, CK_H_DESTROY,
    CK_COUNT
};

static const char *const CheckNames[CK_COUNT] =
{
    "parent died: child alive before it reads its messages",
    "parent died: child hidden",
    "parent died: GetParent returns the destroyed parent",
    "parent died: GetAncestor(GA_PARENT/GA_ROOT) return the destroyed parent",
    "parent died: SetWindowPos fails with 87",
    "parent died: SetFocus fails with 87",
    "parent died: SetParent(child, NULL) fails with 87",
    "parent died: CreateWindow below the destroyed parent fails (87 or 1400)",
    "parent died: MoveWindow still works",
    "parent died: GetCapture is still the child",
    "parent died: GetFocus is NULL",
    "parent died: child gone after its thread read its messages / was destroyed",
    "parent died: no capture left after the child is destroyed",
    "child died: child window is gone",
    "child died: no capture left (not a stale handle)",
    "child died: GetFocus is NULL or a live window of this thread",
    "child died: the parent is alive and answers",
    "child died: SetFocus on the parent works",
    "child died: the parent can be destroyed"
};

typedef struct
{
    ULONG_PTR hwndP, hwndW, hwndG, hwndC;
    LONG pass[CK_COUNT];
    LONG fail[CK_COUNT];
    LONG variant;
} SHARED;

typedef struct
{
    SHARED *Sh;
    HANDLE Ev[EV_COUNT];
} CTX;

static void Pump(void)
{
    MSG Msg;

    while (PeekMessageA(&Msg, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&Msg);
        DispatchMessageA(&Msg);
    }
}

/* wait for an event, answering messages meanwhile; FALSE on timeout */
static BOOL WaitPump(HANDLE h, DWORD ms)
{
    DWORD Start = GetTickCount(), El, w;

    for (;;)
    {
        El = GetTickCount() - Start;
        if (El >= ms)
            return FALSE;
        w = MsgWaitForMultipleObjects(1, &h, FALSE, ms - El, QS_ALLINPUT);
        if (w == WAIT_OBJECT_0)
            return TRUE;
        if (w == WAIT_OBJECT_0 + 1)
            Pump();
        else
            return FALSE;
    }
}

static void Rec(CTX *c, int Id, BOOL Cond)
{
    InterlockedIncrement(Cond ? &c->Sh->pass[Id] : &c->Sh->fail[Id]);
}

static BOOL OpenCtx(CTX *c, const char *Tag)
{
    char Name[80];
    HANDLE Map;
    int i;

    sprintf(Name, "Local\\SPKO_%s_map", Tag);
    Map = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, Name);
    if (!Map)
        return FALSE;
    c->Sh = MapViewOfFile(Map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SHARED));
    if (!c->Sh)
        return FALSE;
    for (i = 0; i < EV_COUNT; i++)
    {
        sprintf(Name, "Local\\SPKO_%s_ev%d", Tag, i);
        c->Ev[i] = OpenEventA(EVENT_ALL_ACCESS, FALSE, Name);
        if (!c->Ev[i])
            return FALSE;
    }
    return TRUE;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static BOOL RegisterOurClass(void)
{
    WNDCLASSA wc = { 0 };

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = "SetParentKillOrderClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    return RegisterClassA(&wc) || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

/* the process that owns the parent window */
static int HostProcess(const char *Tag)
{
    CTX c;
    HWND P, C, W;

    if (!OpenCtx(&c, Tag) || !RegisterOurClass())
        return 10;
    P = CreateWindowExA(0, "SetParentKillOrderClass", "host", WS_POPUP | WS_CLIPCHILDREN, 0, 0, 200, 200,
                        NULL, NULL, GetModuleHandleW(NULL), NULL);
    C = P ? CreateWindowExA(0, "SetParentKillOrderClass", "hostchild", WS_CHILD | WS_VISIBLE, 0, 0, 20, 20,
                            P, NULL, GetModuleHandleW(NULL), NULL) : NULL;
    if (!P || !C)
        return 11;
    c.Sh->hwndP = (ULONG_PTR)P;
    c.Sh->hwndC = (ULONG_PTR)C;
    ShowWindow(P, SW_SHOWNOACTIVATE);
    SetEvent(c.Ev[EV_HOSTUP]);

    if (!WaitPump(c.Ev[EV_BROWSERUP], 20000))
        return 12;
    W = (HWND)c.Sh->hwndW;
    if (!SetParent(W, P))
        return 13;
    SetEvent(c.Ev[EV_ADOPTED]);
    if (!WaitPump(c.Ev[EV_BFOCUSED], 20000))
        return 14;
    ShowWindow(W, SW_SHOWNOACTIVATE);
    SetFocus(c.Sh->variant & 1 ? C : P);
    SetEvent(c.Ev[EV_SETTLED]);
    /* idle, answering messages, until the driver ends this process or asks for the check */
    for (;;)
    {
        HANDLE h[2] = { c.Ev[EV_CHECK_H], c.Ev[EV_EXIT_H] };
        DWORD w = MsgWaitForMultipleObjects(2, h, FALSE, 60000, QS_ALLINPUT);

        if (w == WAIT_OBJECT_0 + 2)
        {
            Pump();
            continue;
        }
        if (w == WAIT_OBJECT_0)
            break;
        if (w == WAIT_OBJECT_0 + 1)
            ExitProcess(0); /* leave with the windows alive: the system destroys them */
        return 15;
    }

    /* the process of the child window ended */
    {
        HWND Cap, Foc;
        BOOL ok1;

        Rec(&c, CK_H_CHILD_GONE, !IsWindow(W));
        Cap = GetCapture();
        Rec(&c, CK_H_CAPTURE_GONE, Cap == NULL || (IsWindow(Cap) && GetWindowThreadProcessId(Cap, NULL) == GetCurrentThreadId()));
        Foc = GetFocus();
        Rec(&c, CK_H_FOCUS_VALID, Foc == NULL || (IsWindow(Foc) && GetWindowThreadProcessId(Foc, NULL) == GetCurrentThreadId()));
        ok1 = IsWindow(P) && IsWindow(C) && GetParent(C) == P && GetAncestor(C, GA_ROOT) == P;
        MoveWindow(P, 5, 5, 150, 150, TRUE);
        ok1 = ok1 && IsWindowVisible(P);
        Rec(&c, CK_H_PARENT_OK, ok1);
        SetLastError(0xdeadbeef);
        SetFocus(P);
        Rec(&c, CK_H_SETFOCUS, GetFocus() == P);
        Pump();
        Rec(&c, CK_H_DESTROY, DestroyWindow(P));
    }
    SetEvent(c.Ev[EV_CHECKED_H]);
    WaitPump(c.Ev[EV_EXIT_H], 20000);
    return 0;
}

/* the process that owns the child window */
static int BrowserProcess(const char *Tag)
{
    CTX c;
    HWND W, G = NULL, P;

    if (!OpenCtx(&c, Tag) || !RegisterOurClass())
        return 20;
    if (!WaitPump(c.Ev[EV_HOSTUP], 20000))
        return 21;
    P = (HWND)c.Sh->hwndP;
    W = CreateWindowExA(0, "SetParentKillOrderClass", "browser", WS_POPUP, 0, 0, 100, 100, NULL, NULL,
                        GetModuleHandleW(NULL), NULL);
    if (!W)
        return 22;
    SetWindowLongPtrA(W, GWL_STYLE, WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);
    if (c.Sh->variant & 1)
    {
        G = CreateWindowExA(0, "SetParentKillOrderClass", "grand", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, W, NULL,
                            GetModuleHandleW(NULL), NULL);
        if (!G)
            return 23;
        c.Sh->hwndG = (ULONG_PTR)G;
    }
    c.Sh->hwndW = (ULONG_PTR)W;
    SetEvent(c.Ev[EV_BROWSERUP]);
    if (!WaitPump(c.Ev[EV_ADOPTED], 20000))
        return 24;
    /* focus and capture on the child (the input queues of the two threads are shared now) */
    SetFocus(G ? G : W);
    SetCapture(W);
    SetEvent(c.Ev[EV_BFOCUSED]);
    if (!WaitPump(c.Ev[EV_SETTLED], 20000))
        return 26;

    {
        HANDLE h[2] = { c.Ev[EV_CHECK_B], c.Ev[EV_EXIT_B] };
        DWORD w;

        /* idle in a plain wait, reading no messages: the state right after the parent's process ended is what is checked */
        w = WaitForMultipleObjects(2, h, FALSE, 60000);
        if (w == WAIT_OBJECT_0 + 1)
            ExitProcess(0);
        if (w != WAIT_OBJECT_0)
            return 25;
    }

    /* the process of the parent window ended */
    {
        LONG_PTR Style;
        HWND Cp, ChildOfDead;
        DWORD Err;

        Rec(&c, CK_B_ALIVE, IsWindow(W));
        Style = GetWindowLongPtrA(W, GWL_STYLE);
        Rec(&c, CK_B_HIDDEN, !(Style & WS_VISIBLE) && !IsWindowVisible(W));
        Rec(&c, CK_B_PARENT, GetParent(W) == P);
        Rec(&c, CK_B_ANCESTOR, GetAncestor(W, GA_PARENT) == P && GetAncestor(W, GA_ROOT) == P);

        SetLastError(0xdeadbeef);
        Err = !SetWindowPos(W, NULL, 1, 1, 50, 50, SWP_NOZORDER | SWP_NOACTIVATE) ? GetLastError() : 0;
        Rec(&c, CK_B_SWP87, Err == ERROR_INVALID_PARAMETER);
        SetLastError(0xdeadbeef);
        Err = SetFocus(W) == NULL ? GetLastError() : 0;
        Rec(&c, CK_B_SETFOCUS87, Err == ERROR_INVALID_PARAMETER);
        SetLastError(0xdeadbeef);
        Err = SetParent(W, NULL) == NULL ? GetLastError() : 0;
        Rec(&c, CK_B_SETPARENT87, Err == ERROR_INVALID_PARAMETER);
        SetLastError(0xdeadbeef);
        ChildOfDead = CreateWindowExA(0, "SetParentKillOrderClass", "x", WS_CHILD, 0, 0, 10, 10, P, NULL,
                                      GetModuleHandleW(NULL), NULL);
        Err = ChildOfDead == NULL ? GetLastError() : 0;
        if (ChildOfDead)
            DestroyWindow(ChildOfDead);
        /* Windows still resolves the destroyed parent and reports 87. Here the handle of a destroyed window no
           longer resolves, so the same call reports ERROR_INVALID_WINDOW_HANDLE: both are a refusal, no window */
        Rec(&c, CK_B_CREATE87, ChildOfDead == NULL && (Err == ERROR_INVALID_PARAMETER || Err == ERROR_INVALID_WINDOW_HANDLE));
        Rec(&c, CK_B_MOVE_OK, MoveWindow(W, 2, 2, 60, 60, TRUE));
        Cp = GetCapture();
        Rec(&c, CK_B_CAPTURE, Cp == W);
        Rec(&c, CK_B_GETFOCUS, GetFocus() == NULL);

        /* now read the messages: the window of the dead parent goes away, as on Windows */
        Pump();
        Sleep(20);
        Pump();
        Rec(&c, CK_B_FINAL_GONE, !IsWindow(W) || (DestroyWindow(W), !IsWindow(W)));
        Cp = GetCapture();
        Rec(&c, CK_B_FINAL_NOCAPTURE, Cp == NULL);
    }
    SetEvent(c.Ev[EV_CHECKED_B]);
    WaitPump(c.Ev[EV_EXIT_B], 20000);
    return 0;
}

static BOOL StartHelper(const char *Role, const char *Tag, PROCESS_INFORMATION *Pi)
{
    char Path[MAX_PATH], CmdLine[MAX_PATH + 160];
    STARTUPINFOA Si = { sizeof(Si) };

    GetModuleFileNameA(NULL, Path, sizeof(Path));
    sprintf(CmdLine, "\"%s\" SetParentKillOrder %s %s", Path, Role, Tag);
    return CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &Si, Pi);
}

/* end a helper: terminate (variant 0) or ask it to exit normally with its windows alive (variant 1) */
static BOOL EndHelper(PROCESS_INFORMATION *Pi, HANDLE ExitEv, BOOL Terminate)
{
    BOOL Clean = TRUE;

    if (Terminate)
        TerminateProcess(Pi->hProcess, 77);
    else
        SetEvent(ExitEv);
    if (WaitForSingleObject(Pi->hProcess, 10000) != WAIT_OBJECT_0)
    {
        Clean = FALSE; /* it did not end by itself: a hang while its windows were being destroyed */
        TerminateProcess(Pi->hProcess, 78);
        WaitForSingleObject(Pi->hProcess, 10000);
    }
    return Clean;
}

/* one iteration; Order 0: the parent's process ends first, 1: the child's. Returns FALSE when it could not run. */
static BOOL RunOnce(int Iter, int Order, SHARED *Tot, LONG *Hangs)
{
    char Tag[48], Name[80];
    HANDLE Map, Ev[EV_COUNT];
    SHARED *Sh;
    PROCESS_INFORMATION PiH, PiB;
    int i;
    BOOL Terminate = (Iter & 2) == 0, Ok = TRUE, GotH, GotB;
    HWND W, P;

    sprintf(Tag, "%lu_%d_%d", GetCurrentProcessId(), Order, Iter);
    sprintf(Name, "Local\\SPKO_%s_map", Tag);
    Map = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(SHARED), Name);
    Sh = Map ? MapViewOfFile(Map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SHARED)) : NULL;
    if (!Sh)
        return FALSE;
    memset(Sh, 0, sizeof(*Sh));
    Sh->variant = Iter & 1;
    for (i = 0; i < EV_COUNT; i++)
    {
        sprintf(Name, "Local\\SPKO_%s_ev%d", Tag, i);
        Ev[i] = CreateEventA(NULL, TRUE, FALSE, Name);
    }

    if (!StartHelper("host", Tag, &PiH))
        return FALSE;
    if (!StartHelper("browser", Tag, &PiB))
    {
        TerminateProcess(PiH.hProcess, 1);
        return FALSE;
    }

    GotB = WaitForSingleObject(Ev[EV_BFOCUSED], 30000) == WAIT_OBJECT_0;
    GotH = GotB && WaitForSingleObject(Ev[EV_ADOPTED], 1000) == WAIT_OBJECT_0;
    if (GotB && GotH)
    {
        if (WaitForSingleObject(Ev[EV_SETTLED], 20000) != WAIT_OBJECT_0)
            Ok = FALSE;
        P = (HWND)Sh->hwndP;
        W = (HWND)Sh->hwndW;
        if (Order == 0)
        {
            if (!EndHelper(&PiH, Ev[EV_EXIT_H], Terminate))
            {
                InterlockedIncrement(Hangs);
                Ok = FALSE;
            }
            Sleep(40);
            SetEvent(Ev[EV_CHECK_B]);
            if (WaitForSingleObject(Ev[EV_CHECKED_B], 20000) != WAIT_OBJECT_0)
            {
                InterlockedIncrement(Hangs);
                Ok = FALSE;
            }
            EndHelper(&PiB, Ev[EV_EXIT_B], TRUE);
        }
        else
        {
            if (!EndHelper(&PiB, Ev[EV_EXIT_B], Terminate))
            {
                InterlockedIncrement(Hangs);
                Ok = FALSE;
            }
            Sleep(40);
            SetEvent(Ev[EV_CHECK_H]);
            if (WaitForSingleObject(Ev[EV_CHECKED_H], 20000) != WAIT_OBJECT_0)
            {
                InterlockedIncrement(Hangs);
                Ok = FALSE;
            }
            EndHelper(&PiH, Ev[EV_EXIT_H], TRUE);
        }
        /* nothing of the pair is left, and the system still answers */
        Sleep(20);
        if (IsWindow(W) || IsWindow(P))
        {
            /* a leaked window of a dead process */
            Tot->variant++;
            Ok = FALSE;
        }
    }
    else
    {
        InterlockedIncrement(Hangs);
        Ok = FALSE;
        EndHelper(&PiH, Ev[EV_EXIT_H], TRUE);
        EndHelper(&PiB, Ev[EV_EXIT_B], TRUE);
    }

    for (i = 0; i < CK_COUNT; i++)
    {
        Tot->pass[i] += Sh->pass[i];
        Tot->fail[i] += Sh->fail[i];
    }
    CloseHandle(PiH.hProcess);
    CloseHandle(PiH.hThread);
    CloseHandle(PiB.hProcess);
    CloseHandle(PiB.hThread);
    for (i = 0; i < EV_COUNT; i++)
        CloseHandle(Ev[i]);
    UnmapViewOfFile(Sh);
    CloseHandle(Map);
    return Ok;
}

START_TEST(SetParentKillOrder)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    int Iters = 10, OrderSel = 2, Order, Iter, i;
    SHARED Tot[2];
    LONG Hangs = 0, BadIter[2] = { 0, 0 };
    HWND Probe;

    if (argc >= 4 && !strcmp(argv[2], "host"))
        ExitProcess(HostProcess(argv[3]));
    if (argc >= 4 && !strcmp(argv[2], "browser"))
        ExitProcess(BrowserProcess(argv[3]));
    if (argc >= 3)
        Iters = atoi(argv[2]);
    if (argc >= 4)
        OrderSel = atoi(argv[3]);
    if (Iters <= 0)
        Iters = 10;

    memset(Tot, 0, sizeof(Tot));
    for (Order = 0; Order < 2; Order++)
    {
        if (OrderSel != 2 && OrderSel != Order)
            continue;
        for (Iter = 0; Iter < Iters; Iter++)
        {
            if (!RunOnce(Iter, Order, &Tot[Order], &Hangs))
                BadIter[Order]++;
            if (Iter % 25 == 24)
                trace("order %d: %d iterations done\n", Order, Iter + 1);
        }
        ok(Tot[Order].variant == 0, "order %d: %ld iterations left a window of a dead process behind\n", Order, Tot[Order].variant);
        trace("order %d (%s first): %d iterations, %ld not clean\n", Order, Order ? "child" : "parent",
              Iters, BadIter[Order]);
        for (i = 0; i < CK_COUNT; i++)
        {
            if ((Order == 0 && i >= CK_H_CHILD_GONE) || (Order == 1 && i < CK_H_CHILD_GONE))
                continue;
            ok(Tot[Order].fail[i] == 0, "order %d: %s: %ld failed, %ld passed\n", Order, CheckNames[i],
               Tot[Order].fail[i], Tot[Order].pass[i]);
        }
    }
    ok(Hangs == 0, "%ld iterations did not complete (a helper hung or did not start)\n", Hangs);

    /* the system still answers: a window can be created, focused and destroyed */
    Probe = CreateWindowExA(0, "STATIC", "probe", WS_POPUP | WS_VISIBLE, 0, 0, 10, 10, NULL, NULL,
                            GetModuleHandleW(NULL), NULL);
    ok(Probe != NULL, "CreateWindowEx failed: %lu\n", GetLastError());
    if (Probe)
    {
        SetFocus(Probe);
        SetCapture(Probe);
        ok(GetCapture() == Probe, "GetCapture is %p, expected %p\n", GetCapture(), Probe);
        ReleaseCapture();
        DestroyWindow(Probe);
    }
}
