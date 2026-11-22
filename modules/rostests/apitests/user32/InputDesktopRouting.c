/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Keyboard, foreground and key state stay with the desktop that has the input
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Two desktops of the interactive window station: the one the test starts on (A) and a second
 * one made here (B). A thread of the test sits on B with a window; the test switches the input
 * to B. A child process on A then tries every way to the keyboard: SetForegroundWindow,
 * SetActiveWindow, SetFocus, ShowWindow / SetWindowPos / BringWindowToTop / SwitchToThisWindow,
 * destroying its active window, AttachThreadInput, a hot key without modifiers, a low-level
 * keyboard hook, a raw input sink, GetAsyncKeyState and the key state of a new thread, SendInput
 * and keybd_event. Keys are injected on B by the thread there (SendInput from the input desktop).
 * Nothing typed on B may reach A, nothing done on A may move the keyboard of B. Switched back,
 * the foreground window of A is the one it had.
 *
 * The rows follow the Windows documentation where it says something (GetAsyncKeyState: "The return
 * value is zero ... The current desktop is not the active desktop"; Desktops: "the hook procedure of
 * a process running on a particular desktop can only receive messages intended for windows created
 * in the same desktop"); the others choose the behaviour that leaks nothing.
 */

#include "precomp.h"

#define IDR_DESKTOP_NAME  "InputDesktopRoutingB"
#define WM_APP_INJECT     (WM_APP + 1)   /* wParam vk, lParam TRUE = key up only, 2 = down only, 0 = both */
#define WM_APP_SETFG      (WM_APP + 2)
#define WM_APP_GETFG      (WM_APP + 3)
#define WM_APP_QUIT       (WM_APP + 4)
#define HOTKEY_VK         VK_F9
#define CHILD_VK_TRY      'Z'

typedef struct _IDR_SHARED
{
    LONG Phase;
    LONG ChildKeys;         /* WM_KEYDOWN / WM_SYSKEYDOWN / WM_CHAR at any window of the child */
    LONG ChildHotKeys;      /* WM_HOTKEY */
    LONG ChildRawInput;     /* WM_INPUT */
    LONG ChildHookCalls;    /* WH_KEYBOARD_LL calls */
    LONG ChildForeground;   /* the child's window was the foreground window before the switch */
    HWND hwndChild;
    HWND hwndB;             /* the window of the parent's thread on desktop B */
} IDR_SHARED, *PIDR_SHARED;

/* Parent side */
static HWND g_hwndB;
static HANDLE g_hThreadB;
static DWORD g_tidB;
static HANDLE g_hReadyB, g_hAckB;
static volatile LONG g_KeysB[256];
static LONG_PTR g_ResultB;
static HDESK g_hDeskB;

/* Child side */
static PIDR_SHARED g_Shared;

static BOOL WaitPumping(HANDLE hEvent, DWORD Ms);

static
LRESULT
CALLBACK
WndProcB(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (Msg == WM_KEYDOWN || Msg == WM_SYSKEYDOWN)
        InterlockedIncrement(&g_KeysB[wParam & 0xFF]);
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
void
PumpParent(DWORD Ms)
{
    PumpFor(Ms);
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
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    } while (GetTickCount() - Start < Ms);
    return FALSE;
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
            trace("child window %p got message 0x%x key 0x%Ix\n", hWnd, Msg, wParam);
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
MakeChildWindow(PCSTR Title, int Show)
{
    HWND hWnd = CreateWindowExA(0, "InputDesktopRoutingA", Title, WS_OVERLAPPEDWINDOW,
                                300, 300, 200, 150, NULL, NULL, GetModuleHandleA(NULL), NULL);
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
    g_hwndChild2 = MakeChildWindow("child2", SW_SHOWNOACTIVATE);
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

static SHORT g_NewThreadShift;

static
DWORD
WINAPI
NewThreadKeyState(LPVOID Param)
{
    UNREFERENCED_PARAMETER(Param);
    g_NewThreadShift = GetKeyState(VK_SHIFT);
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
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    ok(0, "child: phase %ld did not come\n", Phase);
    return FALSE;
}

static
void
ChildProcess(DWORD ParentPid)
{
    CHAR Name[64];
    HANDLE hMap, hGo, hAck, hThread2, hThread;
    WNDCLASSA wc = { 0 };
    RAWINPUTDEVICE Rid;
    HHOOK hHook;
    HWND hwndMain, hwnd3;
    DWORD tid2;
    INPUT Input = { 0 };
    UINT Sent;
    SHORT Async;
    BOOL Ret;

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

    /* Phase 0, while A still has the input: a window that is the foreground window, a hot key,
       a low-level keyboard hook, a raw input sink, a second thread with a window */
    wc.lpfnWndProc = WndProcChild;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "InputDesktopRoutingA";
    RegisterClassA(&wc);
    hwndMain = MakeChildWindow("child", SW_SHOW);
    g_Shared->hwndChild = hwndMain;
    SetForegroundWindow(hwndMain);
    PumpFor(300);
    g_Shared->ChildForeground = (GetForegroundWindow() == hwndMain);

    ok(RegisterHotKey(hwndMain, 1, 0, HOTKEY_VK), "child: RegisterHotKey failed: %lu\n", GetLastError());
    hHook = SetWindowsHookExA(WH_KEYBOARD_LL, ChildLLHook, GetModuleHandleA(NULL), 0);
    ok(hHook != NULL, "child: WH_KEYBOARD_LL hook failed: %lu\n", GetLastError());
    Rid.usUsagePage = 1;
    Rid.usUsage = 6;
    Rid.dwFlags = RIDEV_INPUTSINK;
    Rid.hwndTarget = hwndMain;
    ok(RegisterRawInputDevices(&Rid, 1, sizeof(Rid)), "child: RegisterRawInputDevices failed: %lu\n", GetLastError());

    g_hChild2Ready = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_hChild2Quit = CreateEventA(NULL, TRUE, FALSE, NULL);
    hThread2 = CreateThread(NULL, 0, ChildThread2, NULL, 0, &tid2);
    WaitForSingleObject(g_hChild2Ready, 10000);

    /* Keys typed on A now still reach the child: the hook and the sink work (controls) */
    g_Shared->ChildHookCalls = 0;
    SetEvent(hAck);

    /* Phase 1: B has the input, nothing is the foreground window there yet.
       AttachThreadInput of the thread whose queue was the foreground queue of A must not make that queue
       the foreground queue of B (base: it did, the keys typed on B went to this process). */
    if (!ChildWaitPhase(hGo, 1)) goto Quit;
    g_Shared->ChildHookCalls = 0;
    g_Shared->ChildRawInput = 0;
    g_Shared->ChildKeys = 0;
    ok(GetForegroundWindow() == NULL, "P1 child: GetForegroundWindow() = %p, expected NULL (the foreground is on the other desktop)\n",
       GetForegroundWindow());
    Ret = AttachThreadInput(GetCurrentThreadId(), tid2, TRUE);
    ok(Ret, "P1 child: AttachThreadInput (same desktop) failed: %lu\n", GetLastError());
    SetEvent(hAck);

    /* Phase 2: the foreground window of B is the parent's. Every way to activation from A. */
    if (!ChildWaitPhase(hGo, 2)) goto Quit;
    Ret = SetForegroundWindow(hwndMain);
    ok(!Ret, "P2 child: SetForegroundWindow(own window) = TRUE while the other desktop has the input\n");
    Ret = SetForegroundWindow(g_hwndChild2);
    ok(!Ret, "P2 child: SetForegroundWindow(attached thread's window) = TRUE\n");
#define CHILD_STEP(x) do { x; trace("P2 child: %-60s active %p focus %p\n", #x, GetActiveWindow(), GetFocus()); } while (0)
    CHILD_STEP(SetActiveWindow(g_hwndChild2));
    CHILD_STEP(SetFocus(hwndMain));
    CHILD_STEP(hwnd3 = MakeChildWindow("child3", SW_SHOW));
    CHILD_STEP(SetWindowPos(hwnd3, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW));
    CHILD_STEP(BringWindowToTop(hwndMain));
    CHILD_STEP(SwitchToThisWindow(hwnd3, TRUE));
    CHILD_STEP(SetActiveWindow(hwnd3));
    CHILD_STEP(PumpFor(100));
    /* the active window goes away: activation is handed on (co_WinPosActivateOtherWindow) */
    CHILD_STEP(DestroyWindow(hwnd3));
    CHILD_STEP(PumpFor(100));
    trace("P2 child: hwnd3 was %p\n", hwnd3);
    /* The activation is handed on inside the desktop's own state, as with one desktop */
    ok(GetActiveWindow() == hwndMain, "P2 child: active window after destroying the active one is %p, expected %p\n",
       GetActiveWindow(), hwndMain);
    ok(GetForegroundWindow() == NULL, "P2 child: GetForegroundWindow() = %p after the activation attempts\n", GetForegroundWindow());
    trace("P2 child: active window %p, focus %p (main %p, child2 %p)\n", GetActiveWindow(), GetFocus(), hwndMain, g_hwndChild2);

    Input.type = INPUT_KEYBOARD;
    Input.ki.wVk = CHILD_VK_TRY;
    SetLastError(0xdeadbeef);
    Sent = SendInput(1, &Input, sizeof(Input));
    ok(Sent == 0, "P2 child: SendInput from the desktop without the input sent %u\n", Sent);
    Input.ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(1, &Input, sizeof(Input));
    keybd_event(CHILD_VK_TRY, 0, 0, 0);
    keybd_event(CHILD_VK_TRY, 0, KEYEVENTF_KEYUP, 0);
    /* A message posted to a window of the other desktop (the Desktops documentation: "Window messages can be
       sent only between processes that are on the same desktop"): recorded by the parent, not changed here */
    PostMessageA(g_Shared->hwndB, WM_KEYDOWN, 'Y', 0);
    SetEvent(hAck);

    /* Phase 3: the parent holds Shift down on B */
    if (!ChildWaitPhase(hGo, 3)) goto Quit;
    Async = GetAsyncKeyState(VK_SHIFT);
    ok(Async == 0, "P3 child: GetAsyncKeyState(VK_SHIFT) = 0x%x while Shift is held on the other desktop\n", (USHORT)Async);
    Async = GetAsyncKeyState('C');
    ok(Async == 0, "P3 child: GetAsyncKeyState('C') = 0x%x, a key typed on the other desktop\n", (USHORT)Async);
    g_NewThreadShift = 0x7fff;
    hThread = CreateThread(NULL, 0, NewThreadKeyState, NULL, 0, NULL);
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    ok(!(g_NewThreadShift & 0x8000), "P3 child: a new thread sees Shift down (GetKeyState 0x%x) while it is held on the other desktop\n",
       (USHORT)g_NewThreadShift);
    SetEvent(hAck);

    /* Phase 4: everything typed on B is typed; what reached the child? */
    if (!ChildWaitPhase(hGo, 4)) goto Quit;
    PumpFor(300);
    trace("P4 child: active window %p, focus %p\n", GetActiveWindow(), GetFocus());
    ok(g_Shared->ChildKeys == 0, "P4 child: %ld keys of the other desktop reached a window of this one\n", g_Shared->ChildKeys);
    ok(g_Shared->ChildHotKeys == 0, "P4 child: the hot key fired %ld times for keys typed on the other desktop\n", g_Shared->ChildHotKeys);
    ok(g_Shared->ChildHookCalls == 0, "P4 child: the WH_KEYBOARD_LL hook was called %ld times for keys typed on the other desktop\n",
       g_Shared->ChildHookCalls);
    ok(g_Shared->ChildRawInput == 0, "P4 child: the raw input sink got %ld WM_INPUT for keys typed on the other desktop\n",
       g_Shared->ChildRawInput);
    SetEvent(hAck);

    /* Phase 5: A has the input again: wait until the parent is done looking at the foreground
       (still attached: the detach moves the active window out of the foreground queue, with one
       desktop too) */
    ChildWaitPhase(hGo, 5);
    /* 'D' was typed on B and not read here meanwhile: its "pressed since the last call" bit must not show
       on this desktop once it has the input again */
    Async = GetAsyncKeyState('D');
    ok(!(Async & 1), "P5 child: GetAsyncKeyState('D') = 0x%x after the switch back, a key typed on the other desktop\n", (USHORT)Async);
    AttachThreadInput(GetCurrentThreadId(), tid2, FALSE);

Quit:
    UnregisterHotKey(hwndMain, 1);
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
        PumpParent(0);
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

    SetForegroundWindow(hwndA);
    PumpParent(200);
    hwndFg = GetForegroundWindow();
    if (hwndFg != hwndA)
    {
        skip("the test window is not the foreground window (%p, %p): the row needs it\n", hwndFg, hwndA);
        return;
    }

    ok(SwitchDesktop(g_hDeskB), "SwitchDesktop(B) failed: %lu\n", GetLastError());
    PumpParent(200);
    ok(GetForegroundWindow() == NULL, "R0: the thread of desktop A sees %p as the foreground window while B has the input\n",
       GetForegroundWindow());
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == NULL, "R0: the thread of desktop B sees %p (A's window %p) as its foreground window\n", hwndFg, hwndA);
    ok(DoB(WM_APP_SETFG, 0, 0) != 0, "R0: SetForegroundWindow on desktop B failed\n");
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == g_hwndB, "R0: foreground window of B is %p, expected %p\n", hwndFg, g_hwndB);
    DoB(WM_APP_INJECT, 'Q', 0);
    ok(g_KeysB['Q'] == KeysA + 1, "R0: the key typed on B reached B's window %ld times\n", g_KeysB['Q'] - KeysA);

    ok(SwitchDesktop(hDeskA), "SwitchDesktop(A) failed: %lu\n", GetLastError());
    PumpParent(200);
    hwndFg = GetForegroundWindow();
    ok(hwndFg == hwndA, "R0: switched back, the foreground window is %p, expected A's %p again\n", hwndFg, hwndA);
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == NULL, "R0: switched back, the thread of B sees %p as the foreground window\n", hwndFg);
    /* B's own foreground is kept for the next switch to it */
    ok(SwitchDesktop(g_hDeskB), "SwitchDesktop(B) failed: %lu\n", GetLastError());
    PumpParent(200);
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == g_hwndB, "R0: switched to B again, its foreground window is %p, expected %p\n", hwndFg, g_hwndB);
    ok(SwitchDesktop(hDeskA), "SwitchDesktop(A) failed: %lu\n", GetLastError());
    PumpParent(200);
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
    LONG Before;

    sprintf(Name, "InputDesktopRoutingMap%lu", GetCurrentProcessId());
    hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(IDR_SHARED), Name);
    g_ParentShared = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(IDR_SHARED));
    ZeroMemory(g_ParentShared, sizeof(*g_ParentShared));
    sprintf(Name, "InputDesktopRoutingGo%lu", GetCurrentProcessId());
    g_hGo = CreateEventA(NULL, FALSE, FALSE, Name);
    sprintf(Name, "InputDesktopRoutingAck%lu", GetCurrentProcessId());
    g_hAck = CreateEventA(NULL, FALSE, FALSE, Name);

    /* The child is started by the foreground process: it may take the foreground on A */
    SetForegroundWindow(hwndA);
    PumpParent(100);
    GetModuleFileNameA(NULL, Path, ARRAYSIZE(Path));
    sprintf(CmdLine, "\"%s\" InputDesktopRouting child %lu", Path, GetCurrentProcessId());
    if (!CreateProcessA(NULL, CmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        skip("CreateProcess failed: %lu\n", GetLastError());
        return;
    }
    /* Phase 0 is done by the child as soon as it runs (the test window is served meanwhile: the child
       takes the foreground from it) */
    if (!WaitPumping(g_hAck, 30000))
    {
        ok(0, "child did not start\n");
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        goto Done;
    }
    PumpParent(100);
    trace("child window was the foreground window before the switch: %ld\n", g_ParentShared->ChildForeground);
    g_ParentShared->hwndB = g_hwndB;

    /* B gets the input; nothing on B is the foreground window yet */
    ok(SwitchDesktop(g_hDeskB), "SwitchDesktop(B) failed: %lu\n", GetLastError());
    PumpParent(200);
    if (!NextPhase(1)) goto Kill;
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == NULL || hwndFg == g_hwndB, "P1: foreground window seen on B is %p (the child's is %p)\n", hwndFg, g_ParentShared->hwndChild);
    DoB(WM_APP_INJECT, 'A', 0);   /* must reach nobody on A */

    /* B's window becomes the foreground window, keys reach it */
    ok(DoB(WM_APP_SETFG, 0, 0) != 0, "P1: SetForegroundWindow on B failed\n");
    Before = g_KeysB['B'];
    DoB(WM_APP_INJECT, 'B', 0);
    ok(g_KeysB['B'] == Before + 1, "P1: key typed on B reached B's window %ld times, expected 1\n", g_KeysB['B'] - Before);

    if (!NextPhase(2)) goto Kill;
    hwndFg = (HWND)DoB(WM_APP_GETFG, 0, 0);
    ok(hwndFg == g_hwndB, "P2: after the child's activation attempts the foreground window of B is %p, expected %p\n", hwndFg, g_hwndB);
    trace("P2: a WM_KEYDOWN posted from the other desktop reached B's window %ld times\n", g_KeysB['Y']);
    ok(g_KeysB[CHILD_VK_TRY] == 0, "P2: SendInput / keybd_event of the desktop without the input reached B's window %ld times\n",
       g_KeysB[CHILD_VK_TRY]);
    Before = g_KeysB['C'];
    DoB(WM_APP_INJECT, 'C', 0);
    ok(g_KeysB['C'] == Before + 1, "P2: key typed on B reached B's window %ld times, expected 1\n", g_KeysB['C'] - Before);
    Before = g_KeysB[HOTKEY_VK];
    DoB(WM_APP_INJECT, HOTKEY_VK, 0);
    ok(g_KeysB[HOTKEY_VK] == Before + 1, "P2: the hot key of the other desktop's program took the key typed on B (%ld)\n",
       g_KeysB[HOTKEY_VK] - Before);

    /* Shift held down on B while the child looks */
    DoB(WM_APP_INJECT, VK_SHIFT, 2);
    if (!NextPhase(3)) goto Kill;
    DoB(WM_APP_INJECT, VK_SHIFT, 1);

    DoB(WM_APP_INJECT, 'D', 0);   /* typed on B, looked at by the child after the switch back */
    if (!NextPhase(4)) goto Kill;

    ok(SwitchDesktop(hDeskA), "SwitchDesktop(A) failed: %lu\n", GetLastError());
    PumpParent(300);
    hwndFg = GetForegroundWindow();
    trace("switched back to A, foreground window %p (child %p, test %p)\n", hwndFg, g_ParentShared->hwndChild, hwndA);
    ok(hwndFg == g_ParentShared->hwndChild, "switched back to A, the foreground window is %p, expected the child's active window %p\n",
       hwndFg, g_ParentShared->hwndChild);
    NextPhase(5);
    winetest_wait_child_process(pi.hProcess);
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

    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "InputDesktopRoutingParent";
    RegisterClassA(&wc);
    hwndA = CreateWindowExA(0, wc.lpszClassName, "A", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                            50, 50, 200, 200, NULL, NULL, wc.hInstance, NULL);
    PumpParent(200);

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
