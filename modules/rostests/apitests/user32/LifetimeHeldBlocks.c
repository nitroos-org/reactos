/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Memory that win32k keeps for a callback (the names of a hook's CREATESTRUCT in the global
 *              USER heap, the receiver's copy of a sent message's buffer) is given back when the thread
 *              ends inside the callback.
 */

#include "precomp.h"
#include <imm.h>
#include <ndk/exfuncs.h>

#define HB_CLASS L"HeldBlocksClass"
#define HB_TITLE_CHARS 30000

static WCHAR HbTitle[HB_TITLE_CHARS + 1];
static LONG HbHookNameLength;

static LRESULT CALLBACK HbWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    /* The receiver ends inside its window procedure, while the sender's copy is in use */
    if (msg == WM_GETTEXT && wParam > 1000)
        ExitThread(0);
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void HbRegister(void)
{
    WNDCLASSW wc = { 0 };
    int i;

    for (i = 0; i < HB_TITLE_CHARS; i++)
        HbTitle[i] = (WCHAR)(L'A' + i % 26);
    HbTitle[HB_TITLE_CHARS] = UNICODE_NULL;
    wc.lpfnWndProc = HbWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = HB_CLASS;
    RegisterClassW(&wc);
}

static LRESULT CALLBACK HbCbtExitProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HCBT_CREATEWND)
        ExitThread(0);
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

static LRESULT CALLBACK HbCallWndExitProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    CWPSTRUCT *cwp = (CWPSTRUCT *)lParam;

    if (nCode == HC_ACTION && cwp->message == WM_NCCREATE)
        ExitThread(0);
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

static LRESULT CALLBACK HbCbtCheckProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HCBT_CREATEWND)
    {
        CBT_CREATEWNDW *cbt = (CBT_CREATEWNDW *)lParam;
        /* The longest name: the hook also sees the windows the system creates for the thread (its IME window) */
        if (cbt->lpcs && cbt->lpcs->lpszName && lstrlenW(cbt->lpcs->lpszName) > HbHookNameLength)
            HbHookNameLength = lstrlenW(cbt->lpcs->lpszName);
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/* Creates a window with a long title from inside a thread hook; ExitHook ends the thread in the hook */
static DWORD WINAPI HbHookThread(LPVOID Param)
{
    int Kind = (int)(INT_PTR)Param;
    HOOKPROC Proc = (Kind == 0) ? HbCbtExitProc : (Kind == 1) ? HbCallWndExitProc : HbCbtCheckProc;
    HHOOK hHook;
    HWND hwnd;

    hHook = SetWindowsHookExW((Kind == 1) ? WH_CALLWNDPROC : WH_CBT, Proc, NULL, GetCurrentThreadId());
    if (!hHook)
        return 1;
    hwnd = CreateWindowExW(0, HB_CLASS, HbTitle, WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL,
                           GetModuleHandleW(NULL), NULL);
    UnhookWindowsHookEx(hHook);
    if (!hwnd)
        return 2;
    DestroyWindow(hwnd);
    return 0;
}

static DWORD HbRunHookThread(int Kind)
{
    HANDLE hThread;
    DWORD dwExit = 0xFFFF;

    hThread = CreateThread(NULL, 0, HbHookThread, (LPVOID)(INT_PTR)Kind, 0, NULL);
    ok(hThread != NULL, "CreateThread failed %lu\n", GetLastError());
    if (!hThread)
        return dwExit;
    ok(WaitForSingleObject(hThread, 20000) == WAIT_OBJECT_0, "the thread did not end\n");
    GetExitCodeThread(hThread, &dwExit);
    CloseHandle(hThread);
    return dwExit;
}

/*
 * 80 threads end inside a WH_CBT (HCBT_CREATEWND) or WH_CALLWNDPROC (WM_NCCREATE) procedure of a window
 * whose title is 30000 characters long: the names the hook structure points to are in the global USER heap
 * (1 MB for the whole system). Before the fix every thread left them there: after about 16 threads the
 * heap was full, and a window with a CBT hook could no longer be created (nor, soon, a class registered,
 * by any process). Afterwards a thread with a CBT hook still creates such a window and its hook sees the
 * whole title.
 */
START_TEST(LifetimeHookNamesExitLeak)
{
    DWORD dwExit;
    int i;

    HbRegister();

    for (i = 0; i < 80; i++)
    {
        dwExit = HbRunHookThread(i & 1);
        ok(dwExit == 0, "round %d: exit code %lu, expected 0 (the thread ends in the hook)\n", i, dwExit);
    }

    HbHookNameLength = 0;
    dwExit = HbRunHookThread(2);
    ok(dwExit == 0, "a window with a CBT hook and a long title was not created (%lu)\n", dwExit);
    ok(HbHookNameLength == HB_TITLE_CHARS, "the hook saw a title of %ld characters, expected %d\n",
       HbHookNameLength, HB_TITLE_CHARS);
}

/* The paged pool in use, in pages (SystemPerformanceInformation) */
static ULONG HbPagedPoolPages(void)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;
    NTSTATUS Status;

    ZeroMemory(&Info, sizeof(Info));
    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL);
    ok(NT_SUCCESS(Status), "NtQuerySystemInformation failed 0x%lx\n", Status);
    return Info.PagedPoolPages;
}

static DWORD WINAPI HbReceiverThread(LPVOID Param)
{
    HWND *phwnd = Param;
    MSG msg;

    *phwnd = CreateWindowExW(0, HB_CLASS, L"r", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL,
                             GetModuleHandleW(NULL), NULL);
    if (!*phwnd)
        return 1;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
        DispatchMessageW(&msg);
    return 0;
}

/*
 * The receiver of a WM_GETTEXT for 1 000 000 characters, sent by another thread, ends inside its window
 * procedure, 30 times. The receiver works on a copy of the sender's buffer (2 MB here): before the fix it
 * stayed in paged pool each time (60 MB in all).
 */
START_TEST(LifetimeSentCopyExitLeak)
{
    const WPARAM cch = 1000000;
    ULONG Before, After;
    PWCHAR Buffer;
    int i;

    HbRegister();
    Buffer = VirtualAlloc(NULL, cch * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok(Buffer != NULL, "VirtualAlloc failed\n");
    if (!Buffer)
        return;

    Before = HbPagedPoolPages();
    for (i = 0; i < 30; i++)
    {
        HWND hwnd = NULL;
        DWORD_PTR Result = 0;
        HANDLE hThread = CreateThread(NULL, 0, HbReceiverThread, &hwnd, 0, NULL);

        ok(hThread != NULL, "CreateThread failed %lu\n", GetLastError());
        if (!hThread)
            break;
        while (!hwnd && WaitForSingleObject(hThread, 10) == WAIT_TIMEOUT)
            ;
        ok(hwnd != NULL, "round %d: no receiver window\n", i);
        if (hwnd)
            SendMessageTimeoutW(hwnd, WM_GETTEXT, cch, (LPARAM)Buffer, SMTO_NORMAL, 10000, &Result);
        ok(WaitForSingleObject(hThread, 10000) == WAIT_OBJECT_0, "round %d: the receiver did not end\n", i);
        CloseHandle(hThread);
    }
    After = HbPagedPoolPages();

    /* 30 copies of 2 MB are 15 000 pages */
    ok(After < Before + 3000, "paged pool grew from %lu to %lu pages\n", Before, After);
    trace("paged pool: %lu -> %lu pages\n", Before, After);
    VirtualFree(Buffer, 0, MEM_RELEASE);
}

static struct
{
    HANDLE hReady, hQuit;
    HWND hwnd, hwndIme;
    HKL hkl;
} gHbl;

/* Has a window (and so an IME window), then waits without answering messages until it is told to end */
static DWORD WINAPI HbLayoutTargetThread(LPVOID Param)
{
    UNREFERENCED_PARAMETER(Param);
    gHbl.hwnd = CreateWindowExW(0, HB_CLASS, L"t", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL,
                                GetModuleHandleW(NULL), NULL);
    gHbl.hwndIme = gHbl.hwnd ? ImmGetDefaultIMEWnd(gHbl.hwnd) : NULL;
    SetEvent(gHbl.hReady);
    WaitForSingleObject(gHbl.hQuit, 20000);
    if (gHbl.hwnd)
        DestroyWindow(gHbl.hwnd);
    return 0;
}

static DWORD WINAPI HbLayoutCallerThread(LPVOID Param)
{
    UNREFERENCED_PARAMETER(Param);
    /* Sends IMS_ACTIVATELAYOUT to the IME window of every thread of the process and waits for the answer */
    ActivateKeyboardLayout(gHbl.hkl, KLF_SETFORPROCESS);
    return 0;
}

/*
 * A thread that sets the keyboard layout of its process is terminated while it waits for the IME window of
 * another thread of the process (which does not answer). Before the fix that thread's THREADINFO was
 * referenced across the message and the reference was never given back: the thread object of the other
 * thread stayed after it ended (OpenThread found it). 5 rounds.
 */
START_TEST(LifetimeLayoutSenderEnds)
{
    HKL hklOld, hklNew;
    HANDLE hTarget, hCaller, hOpen;
    DWORD Tid;
    int Round, Kept = 0, Done = 0;

    HbRegister();
    hklOld = GetKeyboardLayout(0);
    hklNew = LoadKeyboardLayoutW(LOWORD(hklOld) == 0x0407 ? L"00000409" : L"00000407", 0);
    if (!hklNew || hklNew == hklOld)
    {
        skip("no second keyboard layout\n");
        return;
    }

    for (Round = 0; Round < 5; Round++)
    {
        ZeroMemory(&gHbl, sizeof(gHbl));
        gHbl.hReady = CreateEventW(NULL, FALSE, FALSE, NULL);
        gHbl.hQuit = CreateEventW(NULL, TRUE, FALSE, NULL);
        hTarget = CreateThread(NULL, 0, HbLayoutTargetThread, NULL, 0, &Tid);
        ok(hTarget != NULL, "CreateThread failed %lu\n", GetLastError());
        if (!hTarget)
            break;
        WaitForSingleObject(gHbl.hReady, 10000);
        if (!gHbl.hwndIme)
        {
            skip("the thread has no IME window\n");
            SetEvent(gHbl.hQuit);
            WaitForSingleObject(hTarget, 10000);
            CloseHandle(hTarget);
            break;
        }

        /* A layout the target does not have yet, so that it is sent the message */
        gHbl.hkl = (GetKeyboardLayout(Tid) == hklNew) ? hklOld : hklNew;
        hCaller = CreateThread(NULL, 0, HbLayoutCallerThread, NULL, 0, NULL);
        ok(hCaller != NULL, "CreateThread failed %lu\n", GetLastError());
        if (hCaller)
        {
            /* The caller is waiting for the target's IME window now */
            ok(WaitForSingleObject(hCaller, 500) == WAIT_TIMEOUT, "round %d: the caller did not wait\n", Round);
            TerminateThread(hCaller, 0x55);
            WaitForSingleObject(hCaller, 10000);
            CloseHandle(hCaller);
        }

        SetEvent(gHbl.hQuit);
        ok(WaitForSingleObject(hTarget, 10000) == WAIT_OBJECT_0, "round %d: the target did not end\n", Round);
        CloseHandle(hTarget);
        CloseHandle(gHbl.hReady);
        CloseHandle(gHbl.hQuit);
        Sleep(200);

        hOpen = OpenThread(THREAD_QUERY_INFORMATION, FALSE, Tid);
        if (hOpen)
        {
            Kept++;
            CloseHandle(hOpen);
        }
        Done++;
    }
    ActivateKeyboardLayout(hklOld, KLF_SETFORPROCESS);
    ok(Kept == 0, "%d of %d ended threads were kept\n", Kept, Done);
}

static struct
{
    HDESK hDesk;
    HWND hwndDesktop, hwndMessageRoot;
    volatile LONG Stop, SendStop;
} gHdd;

/* On the new desktop: its desktop window and the root of its message windows */
static DWORD WINAPI HbDeskThread(LPVOID Param)
{
    HWND hMsg;

    UNREFERENCED_PARAMETER(Param);
    if (!SetThreadDesktop(gHdd.hDesk))
        return 1;
    gHdd.hwndDesktop = GetDesktopWindow();
    hMsg = CreateWindowExW(0, HB_CLASS, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, GetModuleHandleW(NULL), NULL);
    if (hMsg)
    {
        gHdd.hwndMessageRoot = GetAncestor(hMsg, GA_PARENT);
        DestroyWindow(hMsg);
    }
    return 0;
}

/* Keeps a message to the desktop window of the new desktop in flight while that desktop goes */
static DWORD WINAPI HbDeskSendThread(LPVOID Param)
{
    HWND hwnd = (HWND)Param;
    DWORD_PTR Result;

    while (!gHdd.SendStop)
        SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_BLOCK, 200, &Result);
    return 0;
}

/* Keeps the desktop thread (which serves the desktop windows of all desktops) busy */
static DWORD WINAPI HbDeskFloodThread(LPVOID Param)
{
    HWND hwnd = GetDesktopWindow();
    DWORD_PTR Result;

    UNREFERENCED_PARAMETER(Param);
    while (!gHdd.Stop)
        SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_BLOCK, 1000, &Result);
    return 0;
}

/*
 * Desktops are created and closed while another thread keeps sending to their desktop window from the
 * desktop of the test. A desktop window still held by such a sender when its desktop is deleted is freed
 * when that sender lets it go; the message window of the desktop is freed with the desktop all the same.
 * Before the fix it was left as a live window (IsWindow found it) naming the freed desktop object.
 */
START_TEST(LifetimeDesktopHeldDelete)
{
    HWND Roots[400];
    HANDLE hFlood[3], hThread, hSend;
    DWORD Start;
    int i, Count = 0, Left = 0, Known;

    HbRegister();
    for (i = 0; i < 3; i++)
        hFlood[i] = CreateThread(NULL, 0, HbDeskFloodThread, NULL, 0, NULL);

    Start = GetTickCount();
    while (GetTickCount() - Start < 30000 && Count < (int)ARRAYSIZE(Roots))
    {
        WCHAR Name[32];

        wsprintfW(Name, L"HeldDesk%d", Count % 8);
        gHdd.hDesk = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
        ok(gHdd.hDesk != NULL, "CreateDesktopW failed %lu\n", GetLastError());
        if (!gHdd.hDesk)
            break;
        gHdd.hwndDesktop = gHdd.hwndMessageRoot = NULL;
        hThread = CreateThread(NULL, 0, HbDeskThread, NULL, 0, NULL);
        if (hThread)
        {
            WaitForSingleObject(hThread, 10000);
            CloseHandle(hThread);
        }
        hSend = NULL;
        gHdd.SendStop = 0;
        if (gHdd.hwndDesktop)
            hSend = CreateThread(NULL, 0, HbDeskSendThread, gHdd.hwndDesktop, 0, NULL);
        Sleep(Count % 3);
        CloseDesktop(gHdd.hDesk);
        gHdd.SendStop = 1;
        if (hSend)
        {
            WaitForSingleObject(hSend, 10000);
            CloseHandle(hSend);
        }
        Roots[Count++] = gHdd.hwndMessageRoot;
    }

    gHdd.Stop = 1;
    WaitForMultipleObjects(3, hFlood, TRUE, 10000);
    for (i = 0; i < 3; i++)
        CloseHandle(hFlood[i]);
    Sleep(500);

    for (i = 0; i < Count; i++)
    {
        /* Asked of win32k (the window is not on the desktop of the test: IsWindow and GetWindowThreadProcessId
           look at it in user mode, through the desktop heap of the caller) */
        if (Roots[i] && PostMessageW(Roots[i], WM_NULL, 0, 0))
            Left++;
    }
    for (i = 0, Known = 0; i < Count; i++)
    {
        if (Roots[i])
            Known++;
    }
    trace("%d desktops, %d message roots known\n", Count, Known);
    ok(Count > 0, "no desktop\n");
    ok(Known > 0, "no message root\n");
    ok(Left == 0, "the message window of %d of %d deleted desktops is still a window\n", Left, Count);

    /* The heaps of those desktops went with their last window: desktops can still be created */
    for (i = 0; i < 8; i++)
    {
        HDESK hDesk = CreateDesktopW(L"HeldDeskAfter", NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
        ok(hDesk != NULL, "CreateDesktopW %d after the rounds failed %lu\n", i, GetLastError());
        if (hDesk)
            CloseDesktop(hDesk);
    }
}

static struct
{
    HDESK hDesk;
    HWND hwnd;
    HANDLE hReady, hQuit;
} gHod;

/* A window on another desktop, kept until it is told to go */
static DWORD WINAPI HbOtherDeskThread(LPVOID Param)
{
    MSG msg;

    UNREFERENCED_PARAMETER(Param);
    if (SetThreadDesktop(gHod.hDesk))
        gHod.hwnd = CreateWindowExW(0, HB_CLASS, L"o", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL,
                                    GetModuleHandleW(NULL), NULL);
    SetEvent(gHod.hReady);
    while (MsgWaitForMultipleObjects(1, &gHod.hQuit, FALSE, 10000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    }
    if (gHod.hwnd)
        DestroyWindow(gHod.hwnd);
    return 0;
}

/*
 * A window of the test's desktop cannot get a parent or an owner on another desktop (CreateWindowEx, and
 * SetWindowLongPtr GWLP_HWNDPARENT): it would reference a window in the heap of that desktop, which is freed
 * when that desktop goes. Before the fix both were accepted, and the owned window's destruction after the
 * other desktop was closed read the freed heap.
 */
START_TEST(LifetimeOtherDesktopOwner)
{
    HANDLE hThread;
    HWND hwnd, hwndOwn;

    HbRegister();
    gHod.hDesk = CreateDesktopW(L"HeldOtherDesk", NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
    ok(gHod.hDesk != NULL, "CreateDesktopW failed %lu\n", GetLastError());
    if (!gHod.hDesk)
        return;
    gHod.hReady = CreateEventW(NULL, FALSE, FALSE, NULL);
    gHod.hQuit = CreateEventW(NULL, TRUE, FALSE, NULL);
    hThread = CreateThread(NULL, 0, HbOtherDeskThread, NULL, 0, NULL);
    ok(hThread != NULL, "CreateThread failed %lu\n", GetLastError());
    WaitForSingleObject(gHod.hReady, 10000);
    ok(gHod.hwnd != NULL, "no window on the other desktop\n");

    if (gHod.hwnd)
    {
        SetLastError(0xdeadbeef);
        hwnd = CreateWindowExW(0, HB_CLASS, L"owned", WS_POPUP, 0, 0, 50, 50, gHod.hwnd, NULL,
                               GetModuleHandleW(NULL), NULL);
        ok(hwnd == NULL, "a window with an owner on another desktop was created\n");
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "error %lu\n", GetLastError());
        if (hwnd)
            DestroyWindow(hwnd);

        SetLastError(0xdeadbeef);
        hwnd = CreateWindowExW(0, HB_CLASS, L"child", WS_CHILD, 0, 0, 50, 50, gHod.hwnd, NULL,
                               GetModuleHandleW(NULL), NULL);
        ok(hwnd == NULL, "a child of a window on another desktop was created\n");
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "error %lu\n", GetLastError());
        if (hwnd)
            DestroyWindow(hwnd);

        hwndOwn = CreateWindowExW(0, HB_CLASS, L"own", WS_POPUP, 0, 0, 50, 50, NULL, NULL,
                                  GetModuleHandleW(NULL), NULL);
        ok(hwndOwn != NULL, "CreateWindowExW failed %lu\n", GetLastError());
        if (hwndOwn)
        {
            SetWindowLongPtrW(hwndOwn, GWLP_HWNDPARENT, (LONG_PTR)gHod.hwnd);
            ok(GetWindow(hwndOwn, GW_OWNER) == NULL, "the window got an owner on another desktop\n");
            DestroyWindow(hwndOwn);
        }
    }

    /* The window of the other desktop goes before that desktop */
    SetEvent(gHod.hQuit);
    if (hThread)
    {
        ok(WaitForSingleObject(hThread, 10000) == WAIT_OBJECT_0, "the thread did not end\n");
        CloseHandle(hThread);
    }
    CloseDesktop(gHod.hDesk);
    CloseHandle(gHod.hReady);
    CloseHandle(gHod.hQuit);
}
