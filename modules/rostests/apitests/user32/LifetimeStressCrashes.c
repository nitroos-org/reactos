/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Interleavings of window, desktop and activation lifetimes that a multi-threaded program
 *              reaches with plain API calls: an owner that goes while its owned window is linked below
 *              another window, a desktop that goes while a thread of another desktop holds one of its
 *              windows, and a thread that ends inside an activation of a window of another thread. Before
 *              the fixes win32k read freed or unmapped memory there (the machine stopped), or a window could
 *              never be activated again.
 */

#include "precomp.h"
#include <imm.h>
#include <immdev.h>

/* imm32 export (sdk/include/reactos/imm32_undoc.h) */
BOOL WINAPI ImmSetActiveContext(HWND hwnd, HIMC hIMC, BOOL fFlag);

#define LS_CLASS L"LsLifeClass"

static HINSTANCE ghLsInst;

static LRESULT CALLBACK LsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void LsRegister(void)
{
    WNDCLASSW wc = { 0 };

    ghLsInst = GetModuleHandleW(NULL);
    wc.lpfnWndProc = LsWndProc;
    wc.hInstance = ghLsInst;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.lpszClassName = LS_CLASS;
    RegisterClassW(&wc);
}

static void LsPump(void)
{
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

/* Wait for an object while the messages of the thread are dispatched */
static BOOL LsWait(HANDLE h, DWORD Ms)
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
        LsPump();
    }
}

/*
 * OwnerReparentedFreed: thread B owns a popup W whose owner O belongs to thread A, and SetParent links W below
 * another popup P of B (W stays a popup: not a child, its owner is kept). A destroys O: W is linked neither
 * below the desktop window nor below the message window, where the free of O looked for the windows it owns.
 * Before the fix W kept O as its owner after O's storage was freed; GW_OWNER named a window that is gone, and
 * destroying W walked into O (the IME owner walk of DestroyWindow: page fault at 0x32).
 */
static struct
{
    HWND hwndOwner;
    HANDLE hOwnerReady, hDestroyOwner, hOwnerGone;
} gOrf;

static DWORD WINAPI OrfOwnerThread(LPVOID Param)
{
    UNREFERENCED_PARAMETER(Param);
    gOrf.hwndOwner = CreateWindowExW(0, LS_CLASS, L"owner", WS_POPUP | WS_VISIBLE, 10, 10, 60, 60, NULL, NULL,
                                     ghLsInst, NULL);
    SetEvent(gOrf.hOwnerReady);
    LsWait(gOrf.hDestroyOwner, 20000);
    DestroyWindow(gOrf.hwndOwner);
    LsPump();
    SetEvent(gOrf.hOwnerGone);
    return 0;
}

START_TEST(LifetimeOwnerReparentedFreed)
{
    HANDLE hThread;
    HWND hwndOwned, hwndParent, hwndOwnerAfter;
    int Round, Bad = 0, Done = 0;

    LsRegister();
    for (Round = 0; Round < 10; Round++)
    {
        ZeroMemory(&gOrf, sizeof(gOrf));
        gOrf.hOwnerReady = CreateEventW(NULL, FALSE, FALSE, NULL);
        gOrf.hDestroyOwner = CreateEventW(NULL, FALSE, FALSE, NULL);
        gOrf.hOwnerGone = CreateEventW(NULL, FALSE, FALSE, NULL);
        hThread = CreateThread(NULL, 0, OrfOwnerThread, NULL, 0, NULL);
        ok(hThread != NULL, "CreateThread failed\n");
        if (!hThread)
            break;
        ok(LsWait(gOrf.hOwnerReady, 10000), "the owner thread is not ready\n");
        ok(gOrf.hwndOwner != NULL, "no owner window\n");

        hwndParent = CreateWindowExW(0, LS_CLASS, L"parent", WS_POPUP | WS_VISIBLE, 100, 100, 200, 200, NULL,
                                     NULL, ghLsInst, NULL);
        hwndOwned = CreateWindowExW(0, LS_CLASS, L"owned", WS_POPUP | WS_VISIBLE, 120, 120, 50, 50,
                                    gOrf.hwndOwner, NULL, ghLsInst, NULL);
        ok(hwndParent != NULL && hwndOwned != NULL, "CreateWindowExW failed\n");
        ok(GetWindow(hwndOwned, GW_OWNER) == gOrf.hwndOwner, "the owner is not set\n");
        SetParent(hwndOwned, hwndParent);
        LsPump();

        SetEvent(gOrf.hDestroyOwner);
        ok(LsWait(gOrf.hOwnerGone, 10000), "the owner was not destroyed\n");
        ok(!IsWindow(gOrf.hwndOwner), "the owner is still a window\n");

        /* No owner, or one that is a window */
        hwndOwnerAfter = GetWindow(hwndOwned, GW_OWNER);
        if (hwndOwnerAfter && !IsWindow(hwndOwnerAfter))
            Bad++;

        /* The IME owner walk of DestroyWindow goes up the owner chain of hwndOwned */
        ok(DestroyWindow(hwndOwned), "DestroyWindow of the owned window failed\n");
        ok(DestroyWindow(hwndParent), "DestroyWindow of the parent failed\n");
        Done++;

        LsWait(hThread, 10000);
        CloseHandle(hThread);
        CloseHandle(gOrf.hOwnerReady);
        CloseHandle(gOrf.hDestroyOwner);
        CloseHandle(gOrf.hOwnerGone);
    }
    ok(Done == 10, "%d of 10 rounds done\n", Done);
    ok(Bad == 0, "%d times the owned window named an owner that is gone\n", Bad);
}

/*
 * DesktopSenderHeld: a thread S of the test's desktop sends a message to a window W of another desktop D and
 * holds W while it waits for the answer. The thread of W ends inside the message, the last handle of D is
 * closed, and S is suspended inside the wait meanwhile: D goes while S still holds W. Before the fix the heap
 * of D was unmapped with W in it, and S read it when it came back (page fault in UserDereferenceObject).
 * Now W keeps D, and D goes with W once S gives it back.
 * The second part makes 60 desktops with a window, a hook and an input context each, held by a sender in the
 * same way: their heaps go with them, desktops can be created afterwards.
 */
static struct
{
    HDESK hDesk;
    HWND hwnd;
    HANDLE hReady, hInMessage;
    LRESULT SendResult;
} gDsh;

static LRESULT CALLBACK DshWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_USER + 7)
    {
        SetEvent(gDsh.hInMessage);
        Sleep(200);
        ExitThread(7);
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK DshHook(int code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static DWORD WINAPI DshDeskThread(LPVOID Param)
{
    MSG msg;

    UNREFERENCED_PARAMETER(Param);
    if (SetThreadDesktop(gDsh.hDesk))
    {
        gDsh.hwnd = CreateWindowExW(0, L"LsDshClass", L"d", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL,
                                    ghLsInst, NULL);
        SetWindowsHookExW(WH_GETMESSAGE, DshHook, NULL, GetCurrentThreadId());
    }
    SetEvent(gDsh.hReady);
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
        DispatchMessageW(&msg);
    return 0;
}

static DWORD WINAPI DshSendThread(LPVOID Param)
{
    DWORD_PTR Result = 0;

    UNREFERENCED_PARAMETER(Param);
    gDsh.SendResult = SendMessageTimeoutW(gDsh.hwnd, WM_USER + 7, 0, 0, SMTO_NORMAL, 30000, &Result);
    return 0;
}

/* One round: FALSE if the desktop could not be made */
static BOOL DshRound(int Round, BOOL bSuspend)
{
    WCHAR Name[32];
    HANDLE hDeskThread, hSend;

    wsprintfW(Name, L"LsDsh%d", Round % 4);
    ZeroMemory(&gDsh, sizeof(gDsh));
    gDsh.hReady = CreateEventW(NULL, FALSE, FALSE, NULL);
    gDsh.hInMessage = CreateEventW(NULL, FALSE, FALSE, NULL);
    gDsh.hDesk = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
    if (!gDsh.hDesk)
    {
        CloseHandle(gDsh.hReady);
        CloseHandle(gDsh.hInMessage);
        return FALSE;
    }

    hDeskThread = CreateThread(NULL, 0, DshDeskThread, NULL, 0, NULL);
    WaitForSingleObject(gDsh.hReady, 10000);
    ok(gDsh.hwnd != NULL, "round %d: no window on the other desktop\n", Round);

    hSend = CreateThread(NULL, 0, DshSendThread, NULL, 0, NULL);
    ok(WaitForSingleObject(gDsh.hInMessage, 10000) == WAIT_OBJECT_0, "round %d: the message did not arrive\n", Round);
    /* S waits for the answer inside win32k, holding W */
    if (bSuspend)
        SuspendThread(hSend);
    /* The last handle of D goes (the desktop thread still uses D until it ends in the message) */
    CloseDesktop(gDsh.hDesk);
    ok(WaitForSingleObject(hDeskThread, 10000) == WAIT_OBJECT_0, "round %d: the desktop thread did not end\n", Round);
    if (bSuspend)
    {
        /* Let D's delete run (the thread's reference went with it) */
        Sleep(300);
        ResumeThread(hSend);
    }
    /* What the send returns for a receiver that ended inside the message is not looked at (verify on the
       Windows reference): only that the sender comes back */
    ok(WaitForSingleObject(hSend, 40000) == WAIT_OBJECT_0, "round %d: the sender did not come back\n", Round);

    CloseHandle(hSend);
    CloseHandle(hDeskThread);
    CloseHandle(gDsh.hReady);
    CloseHandle(gDsh.hInMessage);
    return TRUE;
}

START_TEST(LifetimeDesktopSenderHeld)
{
    WNDCLASSW wc = { 0 };
    int i, Made = 0;

    LsRegister();
    wc.lpfnWndProc = DshWndProc;
    wc.hInstance = ghLsInst;
    wc.lpszClassName = L"LsDshClass";
    RegisterClassW(&wc);

    /* The sender held inside the wait while the desktop goes */
    for (i = 0; i < 8; i++)
        ok(DshRound(i, TRUE), "round %d: CreateDesktopW failed %lu\n", i, GetLastError());

    /* Many desktops held that way, one after the other: their heaps go with their last object */
    for (i = 0; i < 60; i++)
    {
        if (!DshRound(i, (i % 4) == 0))
            break;
        Made++;
    }
    ok(Made == 60, "only %d of 60 desktops could be made\n", Made);

    for (i = 0; i < 8; i++)
    {
        HDESK hDesk = CreateDesktopW(L"LsDshAfter", NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
        ok(hDesk != NULL, "CreateDesktopW %d after the rounds failed %lu\n", i, GetLastError());
        if (hDesk)
            CloseDesktop(hDesk);
    }
}

/*
 * DesktopKeptByMenus: a process makes a menu on each of 6 desktops from a thread there and leaves the menus
 * alive when the thread ends and the desktop is closed: each desktop (and its heap) is kept by its menu while
 * the process lives, as a handle to it would keep it, and goes when the process ends. A child process does it;
 * afterwards the parent can still make as many desktops.
 */
static HDESK gKmDesk;
static HMENU gKmMenu;

static DWORD WINAPI KmThread(LPVOID Param)
{
    UNREFERENCED_PARAMETER(Param);
    if (SetThreadDesktop(gKmDesk))
    {
        gKmMenu = CreateMenu();
        AppendMenuW(gKmMenu, MF_STRING, 1, L"kept");
    }
    return 0;
}

static void KmChild(void)
{
    int i, Made = 0;

    for (i = 0; i < 6; i++)
    {
        WCHAR Name[32];
        HANDLE hThread;

        wsprintfW(Name, L"LsKm%d", i);
        gKmDesk = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
        if (!gKmDesk)
            break;
        gKmMenu = NULL;
        hThread = CreateThread(NULL, 0, KmThread, NULL, 0, NULL);
        WaitForSingleObject(hThread, 10000);
        CloseHandle(hThread);
        /* The menu lives on in the heap of the closed desktop until the process ends (user32 would read it
           through the heap mapping of this thread's desktop: it is not looked at from here) */
        CloseDesktop(gKmDesk);
        if (gKmMenu)
            Made++;
    }
    ok(Made == 6, "%d of 6 menus were made on their own desktop\n", Made);
}

START_TEST(LifetimeDesktopKeptByMenus)
{
    char **argv;
    char CmdLine[MAX_PATH * 2];
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD ExitCode = 0;
    int argc, i, Made = 0;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !lstrcmpA(argv[2], "child"))
    {
        KmChild();
        return;
    }

    sprintf(CmdLine, "\"%s\" LifetimeDesktopKeptByMenus child", argv[0]);
    for (i = 0; i < 3; i++)
    {
        ok(CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi), "CreateProcessA failed %lu\n",
           GetLastError());
        if (!pi.hProcess)
            break;
        ok(WaitForSingleObject(pi.hProcess, 60000) == WAIT_OBJECT_0, "the child did not end\n");
        GetExitCodeProcess(pi.hProcess, &ExitCode);
        ok(ExitCode == 0, "the child ended with %lu\n", ExitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        pi.hProcess = NULL;
    }

    /* The menus went with the children, and the desktops with their menus */
    Sleep(300);
    for (i = 0; i < 24; i++)
    {
        HDESK hDesk = CreateDesktopW(L"LsKmAfter", NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
        if (!hDesk)
            break;
        CloseDesktop(hDesk);
        Made++;
    }
    ok(Made == 24, "only %d of 24 desktops could be made after the children\n", Made);
}

/*
 * BeingActivatedExit: thread A attaches its input to the test's thread B and activates B's window W1; A's
 * WH_CBT procedure ends A at HCBT_ACTIVATE. W1 was marked as being activated for the hook and the mark stayed
 * (A never came back): SetActiveWindow(W1) from B then returned at once without activating W1, for the rest of
 * its life. W1 must be activatable afterwards.
 */
static HWND gBaeWnd1;

static LRESULT CALLBACK BaeCbtHook(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HCBT_ACTIVATE && (HWND)wParam == gBaeWnd1)
        ExitThread(3);
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static DWORD WINAPI BaeThread(LPVOID Param)
{
    DWORD tidB = (DWORD)(DWORD_PTR)Param;
    HHOOK hHook;

    /* A GUI thread with a queue of its own first, then the queue of B */
    GetDesktopWindow();
    IsWindow(gBaeWnd1);
    if (!AttachThreadInput(GetCurrentThreadId(), tidB, TRUE))
        return 1;
    hHook = SetWindowsHookExW(WH_CBT, BaeCbtHook, NULL, GetCurrentThreadId());
    if (!hHook)
        return 2;
    SetActiveWindow(gBaeWnd1);
    /* Not reached when the hook ran */
    UnhookWindowsHookEx(hHook);
    return 4;
}

START_TEST(LifetimeBeingActivatedExit)
{
    HWND hwnd2;
    HANDLE hThread;
    DWORD ExitCode = 0;
    int Round, Fails = 0;

    LsRegister();
    for (Round = 0; Round < 3; Round++)
    {
        gBaeWnd1 = CreateWindowExW(0, LS_CLASS, L"w1", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 10, 10, 200, 150, NULL,
                                   NULL, ghLsInst, NULL);
        hwnd2 = CreateWindowExW(0, LS_CLASS, L"w2", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 250, 10, 200, 150, NULL,
                                NULL, ghLsInst, NULL);
        ok(gBaeWnd1 && hwnd2, "CreateWindowExW failed\n");
        SetForegroundWindow(hwnd2);
        SetActiveWindow(hwnd2);
        LsPump();
        ok(GetActiveWindow() == hwnd2, "round %d: w2 is not active\n", Round);

        hThread = CreateThread(NULL, 0, BaeThread, (LPVOID)(DWORD_PTR)GetCurrentThreadId(), 0, NULL);
        ok(LsWait(hThread, 10000), "round %d: the activating thread did not end\n", Round);
        GetExitCodeThread(hThread, &ExitCode);
        ok(ExitCode == 3, "round %d: the activating thread ended with %lu, not in its hook\n", Round, ExitCode);
        CloseHandle(hThread);
        LsPump();

        SetActiveWindow(hwnd2);
        SetActiveWindow(gBaeWnd1);
        LsPump();
        if (GetActiveWindow() != gBaeWnd1)
            Fails++;
        ok(GetActiveWindow() == gBaeWnd1, "round %d: w1 cannot be activated (active %p, w1 %p)\n", Round,
           GetActiveWindow(), gBaeWnd1);

        DestroyWindow(hwnd2);
        DestroyWindow(gBaeWnd1);
        LsPump();
    }
    ok(Fails == 0, "%d of 3 rounds left w1 not activatable\n", Fails);
}

/*
 * ImcOtherThreadEnds: a thread of the process uses the input context of another thread of it (ImmGetContext
 * of that thread's window, ImmLockIMC, ImmGetOpenStatus, ImmSetActiveContext) while that thread ends and its
 * cleanup frees the client data of the context. imm32 used client data that was freed meanwhile, or read
 * through a freed input context object. A child process runs 300 such threads; it must end normally.
 */
static volatile HWND gIoeWnd;
static volatile LONG gIoeStop;

static DWORD WINAPI IoeOwnerThread(LPVOID Param)
{
    HWND hwnd = CreateWindowExW(0, LS_CLASS, L"ioe", WS_OVERLAPPEDWINDOW, 0, 0, 50, 50, NULL, NULL, ghLsInst, NULL);
    HIMC hIMC = ImmGetContext(hwnd);

    UNREFERENCED_PARAMETER(Param);
    if (hIMC)
    {
        ImmSetOpenStatus(hIMC, TRUE);
        ImmReleaseContext(hwnd, hIMC);
    }
    gIoeWnd = hwnd;
    LsPump();
    Sleep(GetTickCount() % 3);
    /* Ends with its window and its input context */
    return 0;
}

static DWORD WINAPI IoeUserThread(LPVOID Param)
{
    UNREFERENCED_PARAMETER(Param);
    while (!gIoeStop)
    {
        HWND hwnd = gIoeWnd;
        HIMC hIMC;
        LPINPUTCONTEXT pIC;

        if (!hwnd)
        {
            SwitchToThread();
            continue;
        }
        hIMC = ImmGetContext(hwnd);
        if (!hIMC)
            continue;
        pIC = ImmLockIMC(hIMC);
        if (pIC)
            ImmUnlockIMC(hIMC);
        ImmGetOpenStatus(hIMC);
        ImmSetActiveContext(hwnd, hIMC, FALSE);
        ImmReleaseContext(hwnd, hIMC);
    }
    return 0;
}

static void IoeChild(void)
{
    HANDLE hUsers[2], hOwner;
    int i;

    LsRegister();
    hUsers[0] = CreateThread(NULL, 0, IoeUserThread, NULL, 0, NULL);
    hUsers[1] = CreateThread(NULL, 0, IoeUserThread, NULL, 0, NULL);
    for (i = 0; i < 300; i++)
    {
        hOwner = CreateThread(NULL, 0, IoeOwnerThread, NULL, 0, NULL);
        WaitForSingleObject(hOwner, 10000);
        CloseHandle(hOwner);
        gIoeWnd = NULL;
    }
    gIoeStop = 1;
    WaitForMultipleObjects(2, hUsers, TRUE, 10000);
    CloseHandle(hUsers[0]);
    CloseHandle(hUsers[1]);
}

START_TEST(LifetimeImcOtherThreadEnds)
{
    char **argv;
    char CmdLine[MAX_PATH * 2];
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    DWORD ExitCode = 0, Wait;
    int argc, Run;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !lstrcmpA(argv[2], "child"))
    {
        IoeChild();
        return;
    }

    sprintf(CmdLine, "\"%s\" LifetimeImcOtherThreadEnds child", argv[0]);
    for (Run = 0; Run < 3; Run++)
    {
        ok(CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi), "CreateProcessA failed %lu\n",
           GetLastError());
        if (!pi.hProcess)
            return;
        Wait = WaitForSingleObject(pi.hProcess, 60000);
        ok(Wait == WAIT_OBJECT_0, "run %d: the child did not end (it faulted and is held, or it hangs)\n", Run);
        if (Wait != WAIT_OBJECT_0)
            TerminateProcess(pi.hProcess, 0xdead);
        WaitForSingleObject(pi.hProcess, 10000);
        GetExitCodeProcess(pi.hProcess, &ExitCode);
        ok(ExitCode == 0, "run %d: the child ended with 0x%lx\n", Run, ExitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        pi.hProcess = NULL;
    }
}

/*
 * ImeWindowGoneInNotify: the default IME window of a thread gets WM_IME_SETCONTEXT and tells the focus window
 * that its status window opens (WM_IME_NOTIFY); the focus window destroys itself there, the thread's only
 * top-level window, and the default IME window goes with it. The IME window procedure went on with the data of
 * the window it had freed (an access violation in user32 in the program). A child process does it, so that a
 * fault does not end the suite; it must end normally.
 */
static HWND gIgnIme;
static LONG gIgnNotified;

static LRESULT CALLBACK IgnWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_IME_NOTIFY && wParam == IMN_OPENSTATUSWINDOW && !gIgnNotified)
    {
        gIgnNotified = 1;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void IgnChild(void)
{
    WNDCLASSW wc = { 0 };
    HWND hwnd;
    int Round, Sent = 0;

    wc.lpfnWndProc = IgnWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"LsIgnClass";
    RegisterClassW(&wc);
    for (Round = 0; Round < 5; Round++)
    {
        gIgnNotified = 0;
        hwnd = CreateWindowExW(0, L"LsIgnClass", L"ign", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 0, 0, 200, 100, NULL,
                               NULL, wc.hInstance, NULL);
        if (!hwnd)
            break;
        SetForegroundWindow(hwnd);
        SetFocus(hwnd);
        LsPump();
        gIgnIme = ImmGetDefaultIMEWnd(hwnd);
        if (gIgnIme)
        {
            SendMessageW(gIgnIme, WM_IME_SETCONTEXT, TRUE, ISC_SHOWUIALL);
            Sent++;
        }
        LsPump();
        if (IsWindow(hwnd))
            DestroyWindow(hwnd);
        LsPump();
    }
    trace("%d rounds sent, the focus window was told %ld times\n", Sent, gIgnNotified);
}

START_TEST(LifetimeImeWindowGoneInNotify)
{
    char **argv;
    char CmdLine[MAX_PATH * 2];
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    DWORD ExitCode = 0, Wait;
    int argc;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !lstrcmpA(argv[2], "child"))
    {
        IgnChild();
        return;
    }

    sprintf(CmdLine, "\"%s\" LifetimeImeWindowGoneInNotify child", argv[0]);
    ok(CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi), "CreateProcessA failed %lu\n",
       GetLastError());
    if (!pi.hProcess)
        return;
    Wait = WaitForSingleObject(pi.hProcess, 30000);
    ok(Wait == WAIT_OBJECT_0, "the child did not end (it faulted and is held, or it hangs)\n");
    if (Wait != WAIT_OBJECT_0)
        TerminateProcess(pi.hProcess, 0xdead);
    WaitForSingleObject(pi.hProcess, 10000);
    GetExitCodeProcess(pi.hProcess, &ExitCode);
    ok(ExitCode == 0, "the child ended with 0x%lx\n", ExitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
