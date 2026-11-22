/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SetFocus whose CBT hook (HCBT_SETFOCUS) destroys the window that is to get the focus,
 *              or attaches the input of the calling thread to another thread. The call must come
 *              back and the focus must afterwards be no window or a live one. Before the fix win32k
 *              made the destroyed window the focus window of the queue, kept the pointer after the
 *              window was freed, and read the queue of the thread after AttachThreadInput had freed it.
 */

#include "precomp.h"

enum
{
    ROW_DESTROY,          /* the hook destroys the child; its top-level window is active */
    ROW_DESTROY_INACTIVE, /* the same, the top-level window has to be activated first */
    ROW_ATTACH,           /* the hook attaches the input of this thread to another thread */
    ROW_COUNT
};

static const char *RowName[ROW_COUNT] = { "destroy", "destroy-inactive", "attach" };

static struct
{
    int Row;
    HWND hwndTarget;
    DWORD tidOther;
    BOOL Fired, Attached;
    HANDLE hReady, hQuit;
} g;

static LRESULT CALLBACK SfcWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void Pump(void)
{
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

static LRESULT CALLBACK SfcCbtHook(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HCBT_SETFOCUS && !g.Fired && (HWND)wParam == g.hwndTarget)
    {
        g.Fired = TRUE;
        if (g.Row == ROW_ATTACH)
            g.Attached = AttachThreadInput(GetCurrentThreadId(), g.tidOther, TRUE);
        else
            DestroyWindow(g.hwndTarget);
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

/* A GUI thread with a window and a message loop, to attach to */
static DWORD WINAPI OtherThread(LPVOID Param)
{
    HWND hwnd;
    MSG msg;

    hwnd = CreateWindowExW(0, L"SfcClass", L"other", WS_OVERLAPPEDWINDOW, 300, 300, 100, 100,
                           NULL, NULL, GetModuleHandleW(NULL), NULL);
    PeekMessageW(&msg, NULL, 0, 0, PM_NOREMOVE);
    SetEvent(g.hReady);
    while (MsgWaitForMultipleObjects(1, &g.hQuit, FALSE, INFINITE, QS_ALLINPUT) != WAIT_OBJECT_0)
        Pump();
    DestroyWindow(hwnd);
    return 0;
}

static void CheckFocus(const char *When)
{
    HWND hwndFocus = GetFocus();
    ok(hwndFocus == NULL || IsWindow(hwndFocus), "%s %s: the focus %p is not a window\n",
       RowName[g.Row], When, hwndFocus);
}

static void RunRow(int Row)
{
    HWND hwndTop, hwndChild, hwndOther = NULL, hwndRet;
    HANDLE hThread = NULL;
    HHOOK hHook;

    ZeroMemory(&g, sizeof(g));
    g.Row = Row;

    hwndTop = CreateWindowExW(0, L"SfcClass", L"top", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 50, 50, 200, 200,
                              NULL, NULL, GetModuleHandleW(NULL), NULL);
    hwndChild = CreateWindowExW(0, L"SfcClass", L"child", WS_CHILD | WS_VISIBLE, 10, 10, 50, 50,
                                hwndTop, NULL, GetModuleHandleW(NULL), NULL);
    ok(hwndTop && hwndChild, "%s: windows not created\n", RowName[Row]);
    if (!hwndTop || !hwndChild)
        return;
    SetForegroundWindow(hwndTop);
    SetActiveWindow(hwndTop);
    SetFocus(hwndTop);
    Pump();

    if (Row == ROW_DESTROY_INACTIVE)
    {
        /* Another window of this thread is active: SetFocus has to activate hwndTop */
        hwndOther = CreateWindowExW(0, L"SfcClass", L"active", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 400, 50, 200, 200,
                                    NULL, NULL, GetModuleHandleW(NULL), NULL);
        SetActiveWindow(hwndOther);
        Pump();
    }
    else if (Row == ROW_ATTACH)
    {
        g.hReady = CreateEventW(NULL, FALSE, FALSE, NULL);
        g.hQuit = CreateEventW(NULL, TRUE, FALSE, NULL);
        hThread = CreateThread(NULL, 0, OtherThread, NULL, 0, &g.tidOther);
        ok(hThread != NULL, "attach: no thread\n");
        if (!hThread)
            goto done;
        WaitForSingleObject(g.hReady, 10000);
    }

    g.hwndTarget = hwndChild;
    hHook = SetWindowsHookExW(WH_CBT, SfcCbtHook, NULL, GetCurrentThreadId());
    ok(hHook != NULL, "%s: no hook\n", RowName[Row]);
    hwndRet = SetFocus(hwndChild);
    if (hHook)
        UnhookWindowsHookEx(hHook);
    trace("%s: hook fired %d, SetFocus returned %p (top %p), focus %p, attached %d\n",
          RowName[Row], g.Fired, hwndRet, hwndTop, GetFocus(), g.Attached);
    ok(g.Fired, "%s: the hook was not called\n", RowName[Row]);
    CheckFocus("after SetFocus");

    if (Row == ROW_ATTACH)
    {
        ok(IsWindow(hwndChild), "attach: the child is gone\n");
        if (g.Attached)
            AttachThreadInput(GetCurrentThreadId(), g.tidOther, FALSE);
        CheckFocus("after the detach");
    }
    else
    {
        ok(!IsWindow(hwndChild), "%s: the child is still there\n", RowName[Row]);
    }

    /* The queue must still be usable: focus the top-level window, then nothing, then it again */
    Pump();
    SetActiveWindow(hwndTop);
    SetFocus(hwndTop);
    CheckFocus("after SetFocus(top)");
    SetFocus(NULL);
    ok(GetFocus() == NULL, "%s: SetFocus(NULL) left the focus at %p\n", RowName[Row], GetFocus());
    SetFocus(hwndTop);
    CheckFocus("at the end");
    Pump();

done:
    if (hThread)
    {
        SetEvent(g.hQuit);
        ok(WaitForSingleObject(hThread, 10000) == WAIT_OBJECT_0, "attach: the other thread did not end\n");
        CloseHandle(hThread);
    }
    if (g.hReady) CloseHandle(g.hReady);
    if (g.hQuit) CloseHandle(g.hQuit);
    if (hwndOther) DestroyWindow(hwndOther);
    DestroyWindow(hwndTop);
    Pump();
}

START_TEST(SetFocusCallbacks)
{
    WNDCLASSW wc = { 0 };
    int Round, Row;

    wc.lpfnWndProc = SfcWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"SfcClass";
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed\n");

    for (Round = 0; Round < 3; Round++)
    {
        for (Row = 0; Row < ROW_COUNT; Row++)
            RunRow(Row);
    }

    UnregisterClassW(L"SfcClass", GetModuleHandleW(NULL));
}
