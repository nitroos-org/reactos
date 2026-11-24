/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Memory that win32k keeps for a callback (the names of a hook's CREATESTRUCT in the global
 *              USER heap, the receiver's copy of a sent message's buffer) is given back when the thread
 *              ends inside the callback.
 */

#include "precomp.h"
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
        if (cbt->lpcs && cbt->lpcs->lpszName)
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
