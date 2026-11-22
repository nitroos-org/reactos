/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Keyboard, foreground and key state stay with the desktop that has the input
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Two desktops of the interactive window station: the one the test starts on (A) and a second
 * one made here (B, an ordinary desktop). A thread of the test sits on B with a window; the test
 * switches the input to B. A child process on A then tries every way to the keyboard, and the
 * parent's own thread on A asks for what the desktop with the input has. Keys are injected on B
 * by the thread there (SendInput from the input desktop).
 *
 * Every row asserts what Windows Server 2022 does (the rows V1..V7 and W-* measured on the
 * reference, row id in the comment). With an ordinary second desktop Windows separates key
 * messages, key state, low-level hooks, GetGUIThreadInfo / GetCursorPos and the foreground, but
 * lets the hot keys of a process that has a thread on the desktop with the input fire (and take the
 * key), lets the foreground process keep its raw input at a window on the other desktop, and gives a
 * new thread the state of the modifiers and lock keys. The logon desktops (lock, Security screen,
 * saver) are stricter and cannot be made by a test: they are covered by lock rows run outside it.
 */

#include "precomp.h"

/* user32 export, not in the SDK header */
BOOL WINAPI BlockInput(BOOL fBlockIt);

#define IDR_DESKTOP_NAME  "InputDesktopRoutingB"
#define WM_APP_INJECT     (WM_APP + 1)   /* wParam vk, lParam 1 = key up only, 2 = down only, 0 = both */
#define WM_APP_SETFG      (WM_APP + 2)
#define WM_APP_GETFG      (WM_APP + 3)
#define WM_APP_QUIT       (WM_APP + 4)
#define WM_APP_CURSOR     (WM_APP + 5)
#define HOTKEY_VK         VK_F9          /* window hot key of the child */
#define THREAD_HOTKEY_VK  VK_F8          /* thread hot key of the child */
#define CHILD_VK_TRY      'Z'

typedef struct _IDR_SHARED
{
    LONG Phase;
    LONG ChildKeys;         /* WM_KEYDOWN / WM_SYSKEYDOWN / WM_CHAR at any window of the child */
    LONG ChildHotKeys;      /* WM_HOTKEY at the child's window */
    LONG ChildThreadHotKeys;/* WM_HOTKEY to the child's thread */
    LONG ChildRawInput;     /* WM_INPUT */
    LONG ChildHookCalls;    /* WH_KEYBOARD_LL calls */
    LONG ChildForeground;   /* the child's window was the foreground window before the switch */
    LONG CapsBefore;        /* GetKeyState(VK_CAPITAL) & 1 of the child before the switch */
    HWND hwndChild;
    HWND hwndB;             /* the window of the parent's thread on desktop B */
} IDR_SHARED, *PIDR_SHARED;

/* Parent side */
static HWND g_hwndB;
static HANDLE g_hThreadB;
static DWORD g_tidB;
static HANDLE g_hReadyB, g_hAckB;
static volatile LONG g_KeysB[256];
static volatile LONG g_KeysUpB[256];
static LONG_PTR g_ResultB;
static HDESK g_hDeskB;
static volatile LONG g_RawA;        /* WM_INPUT at the parent's window on A */
static LONG g_HotA;                 /* WM_HOTKEY at the parent's window on A */
static LONG g_ThreadHotA;     /* WM_HOTKEY to the parent's thread on A */
static POINT g_CursorB;

/* Child side */
static PIDR_SHARED g_Shared;

static BOOL WaitPumping(HANDLE hEvent, DWORD Ms);

static
BOOL
IsWow64(void)
{
    BOOL Wow64 = FALSE;
    typedef BOOL (WINAPI *PISWOW64)(HANDLE, PBOOL);
    PISWOW64 p = (PISWOW64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");
    if (p && !p(GetCurrentProcess(), &Wow64))
        Wow64 = FALSE;
    return Wow64;
}

/* Make the window the foreground window also when the process has no right to (a program started by a
   scheduled task on Windows): attached to the foreground thread, SetForegroundWindow is allowed */
static
void
TakeForeground(HWND hWnd)
{
    HWND hwndFg;
    DWORD tid;

    if (SetForegroundWindow(hWnd) && GetForegroundWindow() == hWnd)
        return;
    hwndFg = GetForegroundWindow();
    tid = hwndFg ? GetWindowThreadProcessId(hwndFg, NULL) : 0;
    if (tid && tid != GetCurrentThreadId() && AttachThreadInput(GetCurrentThreadId(), tid, TRUE))
    {
        SetForegroundWindow(hWnd);
        AttachThreadInput(GetCurrentThreadId(), tid, FALSE);
    }
    if (GetForegroundWindow() != hWnd)
        SetForegroundWindow(hWnd);
}

static
LRESULT
CALLBACK
WndProcB(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (Msg == WM_KEYDOWN || Msg == WM_SYSKEYDOWN)
        InterlockedIncrement(&g_KeysB[wParam & 0xFF]);
    if (Msg == WM_KEYUP || Msg == WM_SYSKEYUP)
        InterlockedIncrement(&g_KeysUpB[wParam & 0xFF]);
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

static
LRESULT
CALLBACK
WndProcA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (Msg == WM_INPUT)
        InterlockedIncrement(&g_RawA);
    if (Msg == WM_HOTKEY)
        InterlockedIncrement(&g_HotA);
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

static
void
PumpFor(DWORD Ms)
{
    DWORD Start = GetTickCount();
    MSG msg;

    do
    {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_HOTKEY && !msg.hwnd)
                InterlockedIncrement(g_Shared ? &g_Shared->ChildThreadHotKeys : &g_ThreadHotA);
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        MsgWaitForMultipleObjects(0, NULL, FALSE, 10, QS_ALLINPUT);
    } while (GetTickCount() - Start < Ms);
}

static
void
Inject(WORD Vk, DWORD Flags)
{
    INPUT Input = { 0 };

    Input.type = INPUT_KEYBOARD;
    Input.ki.wVk = Vk;
    Input.ki.wScan = (WORD)MapVirtualKeyA(Vk, MAPVK_VK_TO_VSC);
    Input.ki.dwFlags = Flags;
    SendInput(1, &Input, sizeof(Input));
}

/* The thread on desktop B: its window, and the actions that must be done from the input desktop */
static
DWORD
WINAPI
ThreadB(LPVOID Param)
{
    WNDCLASSA wc = { 0 };
    MSG msg;

    UNREFERENCED_PARAMETER(Param);

    if (!SetThreadDesktop(g_hDeskB))
    {
        trace("SetThreadDesktop(B) failed: %lu\n", GetLastError());
        SetEvent(g_hReadyB);
        return 1;
    }

    wc.lpfnWndProc = WndProcB;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "InputDesktopRoutingB";
    RegisterClassA(&wc);
    g_hwndB = CreateWindowExA(0, wc.lpszClassName, "B", WS_OVERLAPPEDWINDOW,
                              10, 10, 200, 200, NULL, NULL, wc.hInstance, NULL);
    ShowWindow(g_hwndB, SW_SHOWNOACTIVATE);
    PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE);
    SetEvent(g_hReadyB);

    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        switch (msg.message)
        {
            case WM_APP_INJECT:
                if (msg.lParam != 1)
                    Inject((WORD)msg.wParam, 0);
                if (msg.lParam != 2)
                    Inject((WORD)msg.wParam, KEYEVENTF_KEYUP);
                PumpFor(300);
                SetEvent(g_hAckB);
                break;
            case WM_APP_SETFG:
                g_ResultB = SetForegroundWindow(g_hwndB);
                PumpFor(200);
                SetEvent(g_hAckB);
                break;
            case WM_APP_GETFG:
                g_ResultB = (LONG_PTR)GetForegroundWindow();
                SetEvent(g_hAckB);
                break;
            case WM_APP_CURSOR:
                g_ResultB = GetCursorPos(&g_CursorB);
                SetEvent(g_hAckB);
                break;
            case WM_APP_QUIT:
                DestroyWindow(g_hwndB);
                g_hwndB = NULL;
                PostQuitMessage(0);
                break;
            default:
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
                break;
        }
    }
    return 0;
}

static
LONG_PTR
DoB(UINT Msg, WPARAM wParam, LPARAM lParam)
{
    g_ResultB = 0;
    ResetEvent(g_hAckB);
    PostThreadMessageA(g_tidB, Msg, wParam, lParam);
    ok(WaitPumping(g_hAckB, 10000), "thread on desktop B did not answer %u\n", Msg);
    return g_ResultB;
}

static
BOOL
WaitPumping(HANDLE hEvent, DWORD Ms)
{
    DWORD Start = GetTickCount();
    MSG msg;

    do
    {
        if (MsgWaitForMultipleObjects(1, &hEvent, FALSE, 50, QS_ALLINPUT) == WAIT_OBJECT_0)
            return TRUE;
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_HOTKEY && !msg.hwnd)
                InterlockedIncrement(g_Shared ? &g_Shared->ChildThreadHotKeys : &g_ThreadHotA);
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    } while (GetTickCount() - Start < Ms);
    return FALSE;
}

/* W-T1: a thread whose input is attached to another thread (no windows, no hooks of its own) moves to
   another desktop: SetThreadDesktop returns TRUE, the attachment is gone afterwards */
typedef struct _STD_CTX
{
    DWORD tidTo;
    BOOL Attached, Moved, Detached;
    DWORD ErrMoved;
} STD_CTX;

static
DWORD
WINAPI
AttachedThreadSetDesktop(LPVOID Param)
{
    STD_CTX *c = Param;
    MSG msg;

    PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE);
    c->Attached = AttachThreadInput(GetCurrentThreadId(), c->tidTo, TRUE);
    SetLastError(0xdeadbeef);
    c->Moved = SetThreadDesktop(g_hDeskB);
    c->ErrMoved = GetLastError();
    c->Detached = AttachThreadInput(GetCurrentThreadId(), c->tidTo, FALSE);
    return 0;
}

static
void
TestAttachedThreadSetDesktop(PCSTR When)
{
    STD_CTX c = { 0 };
    HANDLE hThread;

    c.tidTo = GetCurrentThreadId();
    hThread = CreateThread(NULL, 0, AttachedThreadSetDesktop, &c, 0, NULL);
    ok(hThread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!hThread)
        return;
    ok(WaitPumping(hThread, 10000), "W-T1 %s: the thread did not end\n", When);
    CloseHandle(hThread);
    ok(c.Attached, "W-T1 %s: AttachThreadInput failed\n", When);
    ok(c.Moved, "W-T1 %s: SetThreadDesktop of an attached thread = FALSE, last error %lu (Windows: TRUE)\n", When, c.ErrMoved);
    if (c.Moved)
        ok(c.ErrMoved == 0xdeadbeef, "W-T1 %s: SetThreadDesktop set last error %lu\n", When, c.ErrMoved);
    ok(!c.Detached, "W-T1 %s: AttachThreadInput(FALSE) after the move = TRUE: the attachment was kept\n", When);
}

/* ---- child process (on desktop A, the desktop without the input) ---- */

static
LRESULT
CALLBACK
WndProcChild(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    switch (Msg)
    {
        case WM_KEYDOWN:
        case WM_SYSKEYDOWN:
        case WM_CHAR:
            InterlockedIncrement(&g_Shared->ChildKeys);
            trace("child window %p got message 0x%x key 0x%lx\n", hWnd, Msg, (ULONG)wParam);
            break;
        case WM_HOTKEY:
            InterlockedIncrement(&g_Shared->ChildHotKeys);
            break;
        case WM_INPUT:
            InterlockedIncrement(&g_Shared->ChildRawInput);
            break;
    }
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

static
LRESULT
CALLBACK
ChildLLHook(int Code, WPARAM wParam, LPARAM lParam)
{
    if (Code == HC_ACTION)
        InterlockedIncrement(&g_Shared->ChildHookCalls);
    return CallNextHookEx(NULL, Code, wParam, lParam);
}

static
HWND
MakeChildWindow(PCSTR Title, int Show, int Offset)
{
    HWND hWnd = CreateWindowExA(0, "InputDesktopRoutingA", Title, WS_OVERLAPPEDWINDOW,
                                300 + Offset, 300 + Offset, 200, 150, NULL, NULL, GetModuleHandleA(NULL), NULL);
    ShowWindow(hWnd, Show);
    return hWnd;
}

static HWND g_hwndChild2;
static HANDLE g_hChild2Ready, g_hChild2Quit;

static
DWORD
WINAPI
ChildThread2(LPVOID Param)
{
    MSG msg;
    UNREFERENCED_PARAMETER(Param);
    g_hwndChild2 = MakeChildWindow("child2", SW_SHOWNOACTIVATE, 40);
    SetEvent(g_hChild2Ready);
    while (MsgWaitForMultipleObjects(1, &g_hChild2Quit, FALSE, INFINITE, QS_ALLINPUT) != WAIT_OBJECT_0)
    {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    DestroyWindow(g_hwndChild2);
    return 0;
}

static SHORT g_NewShift, g_NewControl, g_NewZ, g_NewCaps;
static BYTE g_NewKs[256];

static
DWORD
WINAPI
NewThreadKeyState(LPVOID Param)
{
    UNREFERENCED_PARAMETER(Param);
    g_NewShift = GetKeyState(VK_SHIFT);
    g_NewControl = GetKeyState(VK_CONTROL);
    g_NewZ = GetKeyState('Z');
    g_NewCaps = GetKeyState(VK_CAPITAL);
    GetKeyboardState(g_NewKs);
    return 0;
}

static
void
NewThreadLooks(void)
{
    HANDLE hThread;

    g_NewShift = g_NewControl = g_NewZ = g_NewCaps = 0x7fff;
    hThread = CreateThread(NULL, 0, NewThreadKeyState, NULL, 0, NULL);
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
}

/* A thread of the child that moves to desktop B (no window) */
static HANDLE g_hOnBReady;
static
DWORD
WINAPI
ChildThreadOnB(LPVOID Param)
{
    HDESK hDesk = OpenDesktopA(IDR_DESKTOP_NAME, 0, FALSE, GENERIC_ALL);
    MSG msg;
    BOOL Ret = hDesk && SetThreadDesktop(hDesk);

    UNREFERENCED_PARAMETER(Param);
    trace("child: a thread moved to desktop B: %d (%lu)\n", Ret, GetLastError());
    PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE);
    SetEvent(g_hOnBReady);
    WaitForSingleObject(g_hChild2Quit, 60000);
    return 0;
}

/* Wait for the parent to start the next phase, keeping the windows (and the hook) served */
static
BOOL
ChildWaitPhase(HANDLE hGo, LONG Phase)
{
    DWORD Start = GetTickCount();
    MSG msg;

    while (GetTickCount() - Start < 60000)
    {
        if (MsgWaitForMultipleObjects(1, &hGo, FALSE, 50, QS_ALLINPUT) == WAIT_OBJECT_0 &&
            g_Shared->Phase >= Phase)
        {
            return TRUE;
        }
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_HOTKEY && !msg.hwnd)
                InterlockedIncrement(&g_Shared->ChildThreadHotKeys);
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    ok(0, "child: phase %ld did not come\n", Phase);
    return FALSE;
}

#define CHECK_ACTIVE(row, expect) do { \
    HWND a_ = GetActiveWindow(), f_ = GetFocus(); \
    ok(a_ == (expect), "%s child: active window %p, expected %p\n", row, a_, (expect)); \
    ok(f_ == (expect), "%s child: focus %p, expected %p\n", row, f_, (expect)); \
    ok(GetForegroundWindow() == NULL, "%s child: GetForegroundWindow() = %p\n", row, GetForegroundWindow()); \
} while (0)

/* V1 / V2: activation calls of a thread of the desktop without the input change only its own
   queue's active and focus window; no foreground */
static
void
ChildActivationRows(HWND hwndMain, HWND hwnd3, HWND hwnd4, HWND hwnd5)
{
    HWND Prev, Ret, Active;
    BOOL b;

    /* V1: SetActiveWindow returns the previous active window, the window is active and has the focus */
    Prev = GetActiveWindow();
    Ret = SetActiveWindow(hwnd3);
    ok(Ret == Prev, "V1 child: SetActiveWindow returned %p, previous active %p\n", Ret, Prev);
    CHECK_ACTIVE("V1 SetActiveWindow", hwnd3);
    /* V1: SetFocus on another top-level window activates it too */
    SetFocus(hwnd4);
    CHECK_ACTIVE("V1 SetFocus", hwnd4);
    /* V1: ShowWindow(SW_SHOWNORMAL) of a visible window: nonzero, the active window stays */
    b = ShowWindow(hwndMain, SW_SHOWNORMAL);
    ok(b != 0, "V1 child: ShowWindow(SW_SHOWNORMAL) returned 0\n");
    CHECK_ACTIVE("V1 ShowWindow", hwnd4);
    /* V1: SetWindowPos(HWND_TOP) activates */
    b = SetWindowPos(hwnd3, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    ok(b, "V1 child: SetWindowPos(HWND_TOP) failed\n");
    CHECK_ACTIVE("V1 SetWindowPos", hwnd3);
    /* V1: BringWindowToTop activates */
    b = BringWindowToTop(hwnd4);
    ok(b, "V1 child: BringWindowToTop failed\n");
    CHECK_ACTIVE("V1 BringWindowToTop", hwnd4);
    /* V1: SetForegroundWindow returns 0 with last error 0 (whether the queue activates the window
       depends on the foreground rights of the process on Windows: not asserted) */
    SetLastError(0);
    b = SetForegroundWindow(hwndMain);
    ok(!b, "V1 child: SetForegroundWindow returned TRUE while the other desktop has the input\n");
    ok(GetLastError() == 0, "V1 child: SetForegroundWindow last error %lu\n", GetLastError());
    ok(GetForegroundWindow() == NULL, "V1 child: GetForegroundWindow() = %p after SetForegroundWindow\n", GetForegroundWindow());
    SwitchToThisWindow(hwnd3, TRUE);
    ok(GetForegroundWindow() == NULL, "V1 child: GetForegroundWindow() = %p after SwitchToThisWindow\n", GetForegroundWindow());
    /* V1: SetCapture works on the queue */
    SetCapture(hwnd3);
    ok(GetCapture() == hwnd3, "V1 child: GetCapture() = %p, expected %p\n", GetCapture(), hwnd3);
    ReleaseCapture();

    /* V2: destroying the active window activates another top-level window of this desktop */
    SetActiveWindow(hwnd5);
    CHECK_ACTIVE("V2 before", hwnd5);
    DestroyWindow(hwnd5);
    Active = GetActiveWindow();
    ok(Active == hwndMain || Active == hwnd3 || Active == hwnd4,
       "V2 child: active window after destroying the active one is %p (main %p, 3 %p, 4 %p)\n", Active, hwndMain, hwnd3, hwnd4);
    ok(GetFocus() == Active, "V2 child: focus %p, active %p\n", GetFocus(), Active);
    ok(GetForegroundWindow() == NULL, "V2 child: GetForegroundWindow() = %p\n", GetForegroundWindow());

    /* V2: hiding the active window leaves it active, the focus goes */
    if (Active != hwnd4)
        SetActiveWindow(hwnd4);
    ShowWindow(hwnd4, SW_HIDE);
    ok(GetActiveWindow() == hwnd4, "V2 child: active window after hiding it is %p, expected %p\n", GetActiveWindow(), hwnd4);
    ok(GetFocus() == NULL, "V2 child: focus after hiding the active window is %p, expected NULL\n", GetFocus());
    /* V2: destroying that one activates the next one */
    DestroyWindow(hwnd4);
    Active = GetActiveWindow();
    ok(Active == hwndMain || Active == hwnd3, "V2 child: active window after destroying the hidden active one is %p\n", Active);
    ok(GetFocus() == Active, "V2 child: focus %p, active %p\n", GetFocus(), Active);

    /* The child's window is the active one again, as it was the foreground window before the switch */
    SetActiveWindow(hwndMain);
    DestroyWindow(hwnd3);
    SetActiveWindow(hwndMain);
}

static
void
ChildProcess(DWORD ParentPid)
{
    CHAR Name[64];
    HANDLE hMap, hGo, hAck, hThread2;
    WNDCLASSA wc = { 0 };
    RAWINPUTDEVICE Rid;
    HHOOK hHook;
    HWND hwndMain, hwnd3, hwnd4, hwnd5;
    DWORD tid2;
    INPUT Input[2];
    UINT Sent;
    SHORT Async;
    BOOL Ret, Wow64 = IsWow64();
    LASTINPUTINFO lii = { sizeof(lii) }, lii2 = { sizeof(lii2) };
    SHORT CapsExisting;

    sprintf(Name, "InputDesktopRoutingMap%lu", ParentPid);
    hMap = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, Name);
    sprintf(Name, "InputDesktopRoutingGo%lu", ParentPid);
    hGo = OpenEventA(EVENT_ALL_ACCESS, FALSE, Name);
    sprintf(Name, "InputDesktopRoutingAck%lu", ParentPid);
    hAck = OpenEventA(EVENT_ALL_ACCESS, FALSE, Name);
    if (!hMap || !hGo || !hAck)
    {
        ok(0, "child: shared objects not found (%lu)\n", GetLastError());
        return;
    }
    g_Shared = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(IDR_SHARED));

    /* Phase 0, while A still has the input: a window that is the foreground window, hot keys,
       a low-level keyboard hook, a raw input sink, a second thread with a window */
    wc.lpfnWndProc = WndProcChild;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "InputDesktopRoutingA";
    RegisterClassA(&wc);
    hwndMain = MakeChildWindow("child", SW_SHOW, 0);
    hwnd3 = MakeChildWindow("child3", SW_SHOWNOACTIVATE, 10);
    hwnd4 = MakeChildWindow("child4", SW_SHOWNOACTIVATE, 20);
    hwnd5 = MakeChildWindow("child5", SW_SHOWNOACTIVATE, 30);
    g_Shared->hwndChild = hwndMain;
    TakeForeground(hwndMain);
    PumpFor(300);
    g_Shared->ChildForeground = (GetForegroundWindow() == hwndMain);
    g_Shared->CapsBefore = GetKeyState(VK_CAPITAL) & 1;

    ok(RegisterHotKey(hwndMain, 1, 0, HOTKEY_VK), "child: RegisterHotKey failed: %lu\n", GetLastError());
    ok(RegisterHotKey(NULL, 2, 0, THREAD_HOTKEY_VK), "child: RegisterHotKey(NULL) failed: %lu\n", GetLastError());
    hHook = SetWindowsHookExA(WH_KEYBOARD_LL, ChildLLHook, GetModuleHandleA(NULL), 0);
    ok(hHook != NULL, "child: WH_KEYBOARD_LL hook failed: %lu\n", GetLastError());
    /* A background process: its sink hears nothing of the other desktop (RawInput apitest, measured on
       Windows 7 and 10: "INPUTSINK on another desktop: 0 packets") */
    Rid.usUsagePage = 1;
    Rid.usUsage = 6;
    Rid.dwFlags = RIDEV_INPUTSINK;
    Rid.hwndTarget = hwndMain;
    ok(RegisterRawInputDevices(&Rid, 1, sizeof(Rid)), "child: RegisterRawInputDevices failed: %lu\n", GetLastError());

    g_hChild2Ready = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_hChild2Quit = CreateEventA(NULL, TRUE, FALSE, NULL);
    hThread2 = CreateThread(NULL, 0, ChildThread2, NULL, 0, &tid2);
    WaitForSingleObject(g_hChild2Ready, 10000);

    g_Shared->ChildHookCalls = 0;
    SetEvent(hAck);

    /* Phase 1: B has the input */
    if (!ChildWaitPhase(hGo, 1)) goto Quit;
    g_Shared->ChildHookCalls = 0;
    g_Shared->ChildRawInput = 0;
    g_Shared->ChildKeys = 0;
    g_Shared->ChildHotKeys = 0;
    g_Shared->ChildThreadHotKeys = 0;
    GetLastInputInfo(&lii);
    /* Extras row: GetForegroundWindow from a thread of the desktop without the input is NULL */
    ok(GetForegroundWindow() == NULL, "P1 child: GetForegroundWindow() = %p, expected NULL (the foreground is on the other desktop)\n",
       GetForegroundWindow());
    /* V3: AttachThreadInput between two threads of this desktop works */
    Ret = AttachThreadInput(GetCurrentThreadId(), tid2, TRUE);
    ok(Ret, "V3 child: AttachThreadInput (same desktop) failed: %lu\n", GetLastError());
    SetEvent(hAck);

    /* Phase 2: the foreground window of B is the parent's. Every activation call from A (V1, V2). */
    if (!ChildWaitPhase(hGo, 2)) goto Quit;
    ChildActivationRows(hwndMain, hwnd3, hwnd4, hwnd5);

    /* V7: SendInput / keybd_event from the desktop without the input: refused with ERROR_ACCESS_DENIED;
       a 64-bit (and native 32-bit) program gets 0, a 32-bit program under WOW64 the number of inputs */
    ZeroMemory(Input, sizeof(Input));
    Input[0].type = INPUT_KEYBOARD;
    Input[0].ki.wVk = CHILD_VK_TRY;
    Input[1] = Input[0];
    Input[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SetLastError(0xdeadbeef);
    Sent = SendInput(2, Input, sizeof(INPUT));
    ok(Sent == (Wow64 ? 2u : 0u), "V7 child: SendInput from the desktop without the input returned %u (WOW64 %d)\n", Sent, Wow64);
    ok(GetLastError() == ERROR_ACCESS_DENIED, "V7 child: SendInput last error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    keybd_event(CHILD_VK_TRY, 0, 0, 0);
    ok(GetLastError() == ERROR_ACCESS_DENIED, "V7 child: keybd_event last error %lu\n", GetLastError());
    keybd_event(CHILD_VK_TRY, 0, KEYEVENTF_KEYUP, 0);
    /* Messages to a window of another desktop are delivered on Windows (extras row): not an ok row */
    PostMessageA(g_Shared->hwndB, WM_KEYDOWN, 'Y', 0);
    SetEvent(hAck);

    /* Phase 3: the parent holds Shift, Control and Z down on B and has turned Caps Lock over */
    if (!ChildWaitPhase(hGo, 3)) goto Quit;
    Async = GetAsyncKeyState(VK_SHIFT);
    ok(Async == 0, "V5/W-S1 child: GetAsyncKeyState(VK_SHIFT) = 0x%x while Shift is held on the other desktop\n", (USHORT)Async);
    Async = GetAsyncKeyState('C');
    ok(Async == 0, "V5/W-S1 child: GetAsyncKeyState('C') = 0x%x, a key typed on the other desktop\n", (USHORT)Async);
    Async = GetAsyncKeyState('Z');
    ok(Async == 0, "V6 child: GetAsyncKeyState('Z') = 0x%x while Z is held on the other desktop\n", (USHORT)Async);
    /* V6: the existing thread keeps its own key state */
    CapsExisting = GetKeyState(VK_CAPITAL);
    ok((CapsExisting & 1) == g_Shared->CapsBefore, "V6 child: GetKeyState(VK_CAPITAL) of an existing thread = 0x%x, before 0x%lx\n",
       (USHORT)CapsExisting, g_Shared->CapsBefore);
    ok(!(GetKeyState('Z') & 0x8000), "V6 child: an existing thread sees Z down\n");
    /* V6 / W-S1 NEWTHREAD: a new thread takes the lock-key toggles and the modifiers, not a held letter */
    NewThreadLooks();
    ok((g_NewCaps & 1) == !g_Shared->CapsBefore, "V6 child: a new thread's GetKeyState(VK_CAPITAL) = 0x%x, Caps Lock was turned %s\n",
       (USHORT)g_NewCaps, g_Shared->CapsBefore ? "off" : "on");
    ok(g_NewZ == 0, "V6 child: a new thread's GetKeyState('Z') = 0x%x while Z is held on the other desktop\n", (USHORT)g_NewZ);
    ok(!(g_NewKs['Z'] & 0x81), "V6 child: a new thread's GetKeyboardState Z = 0x%x\n", g_NewKs['Z']);
    ok((g_NewShift & 0x8000) != 0, "W-S1 child: a new thread's GetKeyState(VK_SHIFT) = 0x%x while Shift is held on the other desktop (Windows: down)\n",
       (USHORT)g_NewShift);
    ok((g_NewControl & 0x8000) != 0, "W-S1 child: a new thread's GetKeyState(VK_CONTROL) = 0x%x while Control is held on the other desktop (Windows: down)\n",
       (USHORT)g_NewControl);
    /* For the next row: a thread of this process on the desktop that has the input */
    g_hOnBReady = CreateEventA(NULL, TRUE, FALSE, NULL);
    CloseHandle(CreateThread(NULL, 0, ChildThreadOnB, NULL, 0, NULL));
    WaitForSingleObject(g_hOnBReady, 10000);
    SetEvent(hAck);

    /* Phase 4: everything typed on B is typed; what reached the child? */
    if (!ChildWaitPhase(hGo, 4)) goto Quit;
    PumpFor(300);
    ok(g_Shared->ChildKeys == 0, "V3 child: %ld keys of the other desktop reached a window of this one\n", g_Shared->ChildKeys);
    /* V4 / W-H2: the hot keys of this desktop fire for keys typed on an ordinary second desktop */
    /* V4: fired once, for the key typed after a thread of this process moved to B; not before */
    ok(g_Shared->ChildHotKeys == 1, "V4 child: the window hot key fired %ld times (Windows: 1)\n", g_Shared->ChildHotKeys);
    ok(g_Shared->ChildThreadHotKeys == 0, "V4 child: the thread hot key fired %ld times (Windows: 0)\n", g_Shared->ChildThreadHotKeys);
    ok(g_Shared->ChildHookCalls == 0, "W-S1 child: the WH_KEYBOARD_LL hook was called %ld times for keys typed on the other desktop\n",
       g_Shared->ChildHookCalls);
    ok(g_Shared->ChildRawInput == 0, "child: the raw input sink of a background process got %ld WM_INPUT for keys typed on the other desktop\n",
       g_Shared->ChildRawInput);
    /* Extras row: GetLastInputInfo is global; here the keys of B are SendInput keys, which ReactOS does not count
       as input for GetLastInputInfo (only the keyboard and mouse themselves), Windows does */
    GetLastInputInfo(&lii2);
    todo_ros ok(lii2.dwTime != lii.dwTime, "extras child: GetLastInputInfo did not change while keys were typed on the other desktop\n");
    SetEvent(hAck);

    /* Phase 5: A has the input again */
    ChildWaitPhase(hGo, 5);
    /* V5 / W-A2: 'D' was typed on B and not read here meanwhile: its "pressed since the last call" bit is 0 */
    Async = GetAsyncKeyState('D');
    ok(!(Async & 1), "V5 child: GetAsyncKeyState('D') = 0x%x after the switch back, a key typed on the other desktop\n", (USHORT)Async);
    AttachThreadInput(GetCurrentThreadId(), tid2, FALSE);

Quit:
    UnregisterHotKey(hwndMain, 1);
    UnregisterHotKey(NULL, 2);
    if (hHook) UnhookWindowsHookEx(hHook);
    SetEvent(g_hChild2Quit);
    WaitForSingleObject(hThread2, 10000);
    DestroyWindow(hwndMain);
    SetEvent(hAck);
}

/* ---- parent ---- */

static HANDLE g_hGo, g_hAck;
static PIDR_SHARED g_ParentShared;

static
BOOL
NextPhase(LONG Phase)
{
    DWORD Start = GetTickCount(), Wait;

    g_ParentShared->Phase = Phase;
    SetEvent(g_hGo);
    do
    {
        Wait = MsgWaitForMultipleObjects(1, &g_hAck, FALSE, 100, QS_ALLINPUT);
        if (Wait == WAIT_OBJECT_0)
            return TRUE;
        PumpFor(0);
    } while (GetTickCount() - Start < 30000);
    ok(0, "child did not finish phase %ld\n", Phase);
    return FALSE;
}

/* The foreground window of a desktop is its own: switched away from and back, it is the foreground window again;
   the desktop switched to does not show the foreground window of the other one */
static
void
TestForegroundFollowsDesktop(HDESK hDeskA, HWND hwndA)
{
    HWND hwndFg;
    LONG KeysA = g_KeysB['Q'];

    TakeForeground(hwndA);
    PumpFor(200);
    hwndFg = GetForegroundWindow();
    if (hwndFg != hwndA)
    {
        skip("the test window is not the foreground window (%p, %p): the row needs it\n", hwndFg, hwndA);
        return;
    }

    ok(SwitchDesktop(g_hDeskB), "SwitchDesktop(B) failed: %lu\n", GetLastError());
    PumpFor(200);
    ok(GetForegroundWindow() == NULL, "R0: the thread of desktop A sees %p as the foreground window while B has the input\n",
       GetForegroundWindow());
    /* Windows Server 2022: the only window of the desktop switched to is its foreground window (activated by
       the switch), never A's */
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == g_hwndB, "R0: the thread of desktop B sees %p as its foreground window, expected its own %p (A's is %p)\n", hwndFg, g_hwndB, hwndA);
    ok(DoB(WM_APP_SETFG, 0, 0) != 0, "R0: SetForegroundWindow on desktop B failed\n");
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == g_hwndB, "R0: foreground window of B is %p, expected %p\n", hwndFg, g_hwndB);
    DoB(WM_APP_INJECT, 'Q', 0);
    ok(g_KeysB['Q'] == KeysA + 1, "R0: the key typed on B reached B's window %ld times\n", g_KeysB['Q'] - KeysA);

    ok(SwitchDesktop(hDeskA), "SwitchDesktop(A) failed: %lu\n", GetLastError());
    PumpFor(200);
    hwndFg = GetForegroundWindow();
    ok(hwndFg == hwndA, "R0: switched back, the foreground window is %p, expected A's %p again\n", hwndFg, hwndA);
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == NULL, "R0: switched back, the thread of B sees %p as the foreground window\n", hwndFg);
    /* B's own foreground is kept for the next switch to it */
    ok(SwitchDesktop(g_hDeskB), "SwitchDesktop(B) failed: %lu\n", GetLastError());
    PumpFor(200);
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == g_hwndB, "R0: switched to B again, its foreground window is %p, expected %p\n", hwndFg, g_hwndB);
    ok(SwitchDesktop(hDeskA), "SwitchDesktop(A) failed: %lu\n", GetLastError());
    PumpFor(200);
}

/* Rows of the parent's own thread on A while B has the input and B's window is the foreground window */
static
void
TestParentRowsWhileBHasInput(HWND hwndA)
{
    GUITHREADINFO gti;
    POINT pt, ptB1, ptB2;
    INPUT Input[2];
    RAWINPUTDEVICE Rid;
    UINT Sent;
    BOOL Ret;
    DWORD Err;
    LONG Before;

    /* W-G2: GetGUIThreadInfo(0) from a desktop without the input: FALSE, ERROR_ACCESS_DENIED, nothing filled in */
    ZeroMemory(&gti, sizeof(gti));
    gti.cbSize = sizeof(gti);
    SetLastError(0xdeadbeef);
    Ret = GetGUIThreadInfo(0, &gti);
    Err = GetLastError();
    ok(!Ret, "W-G2: GetGUIThreadInfo(0) = TRUE from a desktop without the input (focus %p, caret %p)\n", gti.hwndFocus, gti.hwndCaret);
    ok(Err == ERROR_ACCESS_DENIED, "W-G2: GetGUIThreadInfo(0) last error %lu\n", Err);
    ok(!gti.hwndActive && !gti.hwndFocus && !gti.hwndCaret && !gti.hwndCapture && !gti.flags &&
       !gti.rcCaret.left && !gti.rcCaret.right, "W-G2: GetGUIThreadInfo(0) filled in the structure\n");

    /* W-C1: GetCursorPos: FALSE, ERROR_ACCESS_DENIED, the point untouched */
    pt.x = pt.y = -1;
    SetLastError(0xdeadbeef);
    Ret = GetCursorPos(&pt);
    Err = GetLastError();
    ok(!Ret, "W-C1: GetCursorPos = TRUE from a desktop without the input (%ld,%ld)\n", pt.x, pt.y);
    ok(Err == ERROR_ACCESS_DENIED, "W-C1: GetCursorPos last error %lu\n", Err);
    ok(pt.x == -1 && pt.y == -1, "W-C1: GetCursorPos wrote %ld,%ld\n", pt.x, pt.y);

    /* W-C2: SetCursorPos: FALSE, the last error not set, the cursor does not move */
    ok(DoB(WM_APP_CURSOR, 0, 0) != 0, "W-C2: GetCursorPos on B failed\n");
    ptB1 = g_CursorB;
    SetLastError(0);
    Ret = SetCursorPos(ptB1.x == 10 ? 20 : 10, 10);
    Err = GetLastError();
    ok(!Ret, "W-C2: SetCursorPos = TRUE from a desktop without the input\n");
    ok(Err == 0, "W-C2: SetCursorPos last error %lu (Windows: 0)\n", Err);
    DoB(WM_APP_CURSOR, 0, 0);
    ptB2 = g_CursorB;
    ok(ptB1.x == ptB2.x && ptB1.y == ptB2.y, "W-C2: the cursor moved from %ld,%ld to %ld,%ld\n", ptB1.x, ptB1.y, ptB2.x, ptB2.y);

    /* V7: SendInput / keybd_event / BlockInput from a desktop without the input */
    Before = g_KeysB['X'];
    ZeroMemory(Input, sizeof(Input));
    Input[0].type = INPUT_KEYBOARD;
    Input[0].ki.wVk = 'X';
    Input[1] = Input[0];
    Input[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SetLastError(0xdeadbeef);
    Sent = SendInput(2, Input, sizeof(INPUT));
    Err = GetLastError();
    ok(Sent == (IsWow64() ? 2u : 0u), "V7: SendInput(2 keys) from a desktop without the input returned %u (WOW64 %d)\n", Sent, IsWow64());
    ok(Err == ERROR_ACCESS_DENIED, "V7: SendInput last error %lu\n", Err);
    SetLastError(0xdeadbeef);
    keybd_event('X', 0, 0, 0);
    Err = GetLastError();
    keybd_event('X', 0, KEYEVENTF_KEYUP, 0);
    ok(Err == ERROR_ACCESS_DENIED, "V7: keybd_event last error %lu\n", Err);
    SetLastError(0xdeadbeef);
    Ret = BlockInput(FALSE);
    Err = GetLastError();
    ok(!Ret, "V7: BlockInput(FALSE) = TRUE from a desktop without the input\n");
    /* Windows Server 2022: left as it was or ERROR_ACCESS_DENIED, depending on the run */
    ok(Err == 0xdeadbeef || Err == ERROR_ACCESS_DENIED, "V7: BlockInput(FALSE) last error %lu\n", Err);
    PumpFor(200);
    DoB(WM_APP_INJECT, VK_SPACE, 0);   /* B's queue is served up to here */
    ok(g_KeysB['X'] == Before, "V7: the keys of SendInput / keybd_event reached B's window %ld times\n", g_KeysB['X'] - Before);

    /* V4 / W-H2 with the hot keys in the foreground process (the process of B's foreground window), as in the
       measured rows: a window hot key and a thread hot key of this thread on A */
    ok(RegisterHotKey(hwndA, 11, 0, VK_F6), "V4: RegisterHotKey(hwndA) failed: %lu\n", GetLastError());
    ok(RegisterHotKey(NULL, 12, 0, VK_F7), "V4: RegisterHotKey(NULL) failed: %lu\n", GetLastError());
    g_HotA = g_ThreadHotA = 0;
    Before = g_KeysB[VK_F6] + g_KeysB[VK_F7];
    DoB(WM_APP_INJECT, VK_F6, 0);
    DoB(WM_APP_INJECT, VK_F7, 0);
    PumpFor(200);
    ok(g_HotA == 1, "V4: the window hot key of the foreground process's thread on A fired %ld times for its key typed on B (Windows: 1)\n", g_HotA);
    ok(g_ThreadHotA == 1, "V4: the thread hot key of the foreground process's thread on A fired %ld times for its key typed on B (Windows: 1)\n", g_ThreadHotA);
    ok(g_KeysB[VK_F6] + g_KeysB[VK_F7] == Before, "V4: the key downs of the hot keys reached B's window %ld times (Windows: taken)\n",
       g_KeysB[VK_F6] + g_KeysB[VK_F7] - Before);
    UnregisterHotKey(hwndA, 11);
    UnregisterHotKey(NULL, 12);

    /* W-S1 RAWINPUT: this process is the foreground process (its window on B has the input): its keyboard sink
       at a window on A receives the keys typed on B */
    Rid.usUsagePage = 1;
    Rid.usUsage = 6;
    Rid.dwFlags = RIDEV_INPUTSINK;
    Rid.hwndTarget = hwndA;
    ok(RegisterRawInputDevices(&Rid, 1, sizeof(Rid)), "W-S1: RegisterRawInputDevices failed: %lu\n", GetLastError());
    g_RawA = 0;
    Before = g_KeysB['R'];
    DoB(WM_APP_INJECT, 'R', 0);
    PumpFor(200);
    ok(g_RawA >= 1, "W-S1: the foreground process's raw input sink on A got %ld WM_INPUT for a key typed on B (Windows: receives)\n", g_RawA);
    ok(g_KeysB['R'] == Before + 1, "W-S1: the key reached B's window %ld times\n", g_KeysB['R'] - Before);
    Rid.dwFlags = RIDEV_REMOVE;
    Rid.hwndTarget = NULL;
    RegisterRawInputDevices(&Rid, 1, sizeof(Rid));

    /* W-T1 (deskwatch STDATTACHED): an attached thread moves to the desktop that has the input */
    TestAttachedThreadSetDesktop("while B has the input");
}

static
void
TestChildOnOtherDesktop(HDESK hDeskA, HWND hwndA)
{
    CHAR Path[MAX_PATH], CmdLine[MAX_PATH + 64], Name[64];
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HANDLE hMap;
    HWND hwndFg;
    LONG Before, BeforeUp;
    SHORT Caps;

    sprintf(Name, "InputDesktopRoutingMap%lu", GetCurrentProcessId());
    hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(IDR_SHARED), Name);
    g_ParentShared = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(IDR_SHARED));
    ZeroMemory(g_ParentShared, sizeof(*g_ParentShared));
    sprintf(Name, "InputDesktopRoutingGo%lu", GetCurrentProcessId());
    g_hGo = CreateEventA(NULL, FALSE, FALSE, Name);
    sprintf(Name, "InputDesktopRoutingAck%lu", GetCurrentProcessId());
    g_hAck = CreateEventA(NULL, FALSE, FALSE, Name);

    /* The child is started by the foreground process: it may take the foreground on A */
    TakeForeground(hwndA);
    PumpFor(100);
    GetModuleFileNameA(NULL, Path, ARRAYSIZE(Path));
    sprintf(CmdLine, "\"%s\" InputDesktopRouting child %lu", Path, GetCurrentProcessId());
    if (!CreateProcessA(NULL, CmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        skip("CreateProcess failed: %lu\n", GetLastError());
        return;
    }
    if (!WaitPumping(g_hAck, 30000))
    {
        ok(0, "child did not start\n");
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        goto Done;
    }
    PumpFor(100);
    trace("child window was the foreground window before the switch: %ld\n", g_ParentShared->ChildForeground);
    g_ParentShared->hwndB = g_hwndB;

    /* B gets the input; nothing on B is the foreground window yet */
    ok(SwitchDesktop(g_hDeskB), "SwitchDesktop(B) failed: %lu\n", GetLastError());
    PumpFor(200);
    if (!NextPhase(1)) goto Kill;
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == NULL || hwndFg == g_hwndB, "P1: foreground window seen on B is %p (the child's is %p)\n", hwndFg, g_ParentShared->hwndChild);
    DoB(WM_APP_INJECT, 'A', 0);   /* must reach no window on A */

    /* B's window becomes the foreground window, keys reach it */
    ok(DoB(WM_APP_SETFG, 0, 0) != 0, "P1: SetForegroundWindow on B failed\n");
    Before = g_KeysB['B'];
    DoB(WM_APP_INJECT, 'B', 0);
    ok(g_KeysB['B'] == Before + 1, "P1: key typed on B reached B's window %ld times, expected 1\n", g_KeysB['B'] - Before);

    TestParentRowsWhileBHasInput(hwndA);

    if (!NextPhase(2)) goto Kill;
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == g_hwndB, "V1: after the child's activation calls the foreground window of B is %p, expected %p\n", hwndFg, g_hwndB);
    trace("P2: a WM_KEYDOWN posted from the other desktop reached B's window %ld times\n", g_KeysB['Y']);
    ok(g_KeysB[CHILD_VK_TRY] == 0, "V7: SendInput / keybd_event of the desktop without the input reached B's window %ld times\n",
       g_KeysB[CHILD_VK_TRY]);
    Before = g_KeysB['C'];
    DoB(WM_APP_INJECT, 'C', 0);
    ok(g_KeysB['C'] == Before + 1, "P2: key typed on B reached B's window %ld times, expected 1\n", g_KeysB['C'] - Before);
    /* V4: the hot keys of a process with no thread on B (the child) do not fire: the key reaches B's window
       (measured on Windows Server 2022 with this test) */
    Before = g_KeysB[HOTKEY_VK];
    BeforeUp = g_KeysUpB[HOTKEY_VK];
    DoB(WM_APP_INJECT, HOTKEY_VK, 0);
    ok(g_KeysB[HOTKEY_VK] == Before + 1, "V4: the key down of the window hot key of a process without a thread on B reached B's window %ld times (Windows: 1)\n",
       g_KeysB[HOTKEY_VK] - Before);
    ok(g_KeysUpB[HOTKEY_VK] == BeforeUp + 1, "V4: the key up reached B's window %ld times, expected 1\n",
       g_KeysUpB[HOTKEY_VK] - BeforeUp);
    Before = g_KeysB[THREAD_HOTKEY_VK];
    DoB(WM_APP_INJECT, THREAD_HOTKEY_VK, 0);
    ok(g_KeysB[THREAD_HOTKEY_VK] == Before + 1, "V4: the key down of the thread hot key of a process without a thread on B reached B's window %ld times (Windows: 1)\n",
       g_KeysB[THREAD_HOTKEY_VK] - Before);

    /* Caps Lock turned over, Z, Shift and Control held down on B, while the child looks */
    DoB(WM_APP_INJECT, VK_CAPITAL, 0);
    DoB(WM_APP_INJECT, 'Z', 2);
    DoB(WM_APP_INJECT, VK_SHIFT, 2);
    DoB(WM_APP_INJECT, VK_CONTROL, 2);
    if (!NextPhase(3)) goto Kill;
    DoB(WM_APP_INJECT, 'Z', 1);
    DoB(WM_APP_INJECT, VK_CONTROL, 1);
    DoB(WM_APP_INJECT, VK_SHIFT, 1);

    /* V4 / W-H2: the child's hot keys again, now that the child has a thread (without windows) on B: they
       fire and take the key down, the key up still reaches B's window */
    Before = g_KeysB[HOTKEY_VK];
    BeforeUp = g_KeysUpB[HOTKEY_VK];
    DoB(WM_APP_INJECT, HOTKEY_VK, 0);
    ok(g_KeysB[HOTKEY_VK] == Before, "V4: the key down of the window hot key of a process with a thread on B reached B's window %ld times (Windows: taken)\n",
       g_KeysB[HOTKEY_VK] - Before);
    ok(g_KeysUpB[HOTKEY_VK] == BeforeUp + 1, "V4: the key up reached B's window %ld times, expected 1\n", g_KeysUpB[HOTKEY_VK] - BeforeUp);

    DoB(WM_APP_INJECT, 'D', 0);   /* typed on B, looked at by the child after the switch back */
    if (!NextPhase(4)) goto Kill;

    ok(SwitchDesktop(hDeskA), "SwitchDesktop(A) failed: %lu\n", GetLastError());
    PumpFor(300);
    hwndFg = GetForegroundWindow();
    trace("switched back to A, foreground window %p (child %p, test %p)\n", hwndFg, g_ParentShared->hwndChild, hwndA);
    ok(hwndFg == g_ParentShared->hwndChild, "switched back to A, the foreground window is %p, expected the child's window %p\n",
       hwndFg, g_ParentShared->hwndChild);
    /* V6: switched back, an existing thread of A has the Caps Lock toggle turned over on B */
    Caps = GetKeyState(VK_CAPITAL);
    ok((Caps & 1) == !g_ParentShared->CapsBefore, "V6: switched back, GetKeyState(VK_CAPITAL) = 0x%x, Caps Lock was turned %s on B\n",
       (USHORT)Caps, g_ParentShared->CapsBefore ? "off" : "on");
    ok(!(GetKeyState('Z') & 0x8001), "V6: switched back, GetKeyState('Z') = 0x%x\n", (USHORT)GetKeyState('Z'));
    NextPhase(5);
    winetest_wait_child_process(pi.hProcess);
    /* Caps Lock as it was */
    keybd_event(VK_CAPITAL, 0, 0, 0);
    keybd_event(VK_CAPITAL, 0, KEYEVENTF_KEYUP, 0);
    PumpFor(100);
    goto Done;

Kill:
    SwitchDesktop(hDeskA);
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 10000);
Done:
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    UnmapViewOfFile(g_ParentShared);
    CloseHandle(hMap);
    CloseHandle(g_hGo);
    CloseHandle(g_hAck);
}

START_TEST(InputDesktopRouting)
{
    char **argv;
    int argc;
    HDESK hDeskA, hDeskInput;
    WNDCLASSA wc = { 0 };
    HWND hwndA;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        ChildProcess(strtoul(argv[3], NULL, 10));
        return;
    }

    /* The handle to switch back with: the input desktop, which must be the test's own */
    hDeskA = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP | DESKTOP_READOBJECTS);
    if (!hDeskA)
    {
        skip("OpenInputDesktop failed (%lu)\n", GetLastError());
        return;
    }
    hDeskInput = GetThreadDesktop(GetCurrentThreadId());
    {
        CHAR NameA[64] = "", NameInput[64] = "";
        DWORD Len;
        GetUserObjectInformationA(hDeskA, UOI_NAME, NameInput, sizeof(NameInput), &Len);
        GetUserObjectInformationA(hDeskInput, UOI_NAME, NameA, sizeof(NameA), &Len);
        if (lstrcmpiA(NameA, NameInput))
        {
            skip("the test does not run on the input desktop (%s, input %s)\n", NameA, NameInput);
            CloseDesktop(hDeskA);
            return;
        }
    }

    g_hDeskB = CreateDesktopA(IDR_DESKTOP_NAME, NULL, NULL, 0, GENERIC_ALL, NULL);
    if (!g_hDeskB)
    {
        skip("CreateDesktop failed: %lu\n", GetLastError());
        return;
    }

    wc.lpfnWndProc = WndProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "InputDesktopRoutingParent";
    RegisterClassA(&wc);
    hwndA = CreateWindowExA(0, wc.lpszClassName, "A", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                            50, 50, 200, 200, NULL, NULL, wc.hInstance, NULL);
    PumpFor(200);

    /* W-T1 (= V10): on one desktop, before any switch */
    TestAttachedThreadSetDesktop("before the switch");

    g_hReadyB = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_hAckB = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_hThreadB = CreateThread(NULL, 0, ThreadB, NULL, 0, &g_tidB);
    WaitForSingleObject(g_hReadyB, 10000);
    if (!g_hwndB)
    {
        skip("no window on desktop B\n");
        goto Cleanup;
    }

    TestForegroundFollowsDesktop(hDeskA, hwndA);
    TestChildOnOtherDesktop(hDeskA, hwndA);

Cleanup:
    /* Never leave the input on B */
    SwitchDesktop(hDeskA);
    PostThreadMessageA(g_tidB, WM_APP_QUIT, 0, 0);
    WaitForSingleObject(g_hThreadB, 10000);
    CloseHandle(g_hThreadB);
    DestroyWindow(hwndA);
    CloseDesktop(g_hDeskB);
    CloseDesktop(hDeskA);
    CloseHandle(g_hReadyB);
    CloseHandle(g_hAckB);
}
