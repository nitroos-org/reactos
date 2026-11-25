/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     How deep child windows nest: CreateWindowEx and SetParent at the limit, moved subtrees, a tree at
 *              the limit moved, redrawn and destroyed, windows of two threads in one chain
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (64 and 32 bit alike): a window is at most 50 levels below the desktop (a top-level
 * window is level 1). The 50th child created below each other (level 51) fails with ERROR_INVALID_PARAMETER, and so
 * does the 50th SetParent of a chain of top-level windows. SetParent counts the moved subtree: a chain of 30 windows
 * goes below the 20th window of another chain of 30 (level 50) but not below the 21st (51), so a tree never gets
 * deeper than 50 levels; a nested window below the deepest one of such a tree is still created when it stays at 50.
 * Nested sends across threads end too (measured: SendMessage returns 0 at a depth of 62), not tested here.
 */

#include "precomp.h"

#define LIMIT 50

static LRESULT CALLBACK NestProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

/* A top-level window and children below each other: N windows in all (the last is at level N) */
static HWND Chain(INT N, HWND *Last, INT *Made)
{
    HWND Top, Prev, Wnd;
    INT i;

    Top = CreateWindowExW(WS_EX_NOPARENTNOTIFY, L"NestLimit", L"top", WS_OVERLAPPED, 0, 0, 400, 400,
                          NULL, NULL, NULL, NULL);
    Prev = Top;
    for (i = 1; Prev && i < N; i++)
    {
        Wnd = CreateWindowExW(WS_EX_NOPARENTNOTIFY, L"NestLimit", L"c", WS_CHILD | WS_VISIBLE, 1, 1, 300, 300,
                              Prev, NULL, NULL, NULL);
        if (!Wnd) break;
        Prev = Wnd;
    }
    if (Last) *Last = Prev;
    if (Made) *Made = i;
    return Top;
}

static HWND Nth(HWND Top, INT N)
{
    HWND Wnd = Top;
    while (--N > 0 && Wnd) Wnd = GetWindow(Wnd, GW_CHILD);
    return Wnd;
}

static INT Level(HWND Wnd)
{
    INT Level = 1;
    while ((GetWindowLongPtrW(Wnd, GWL_STYLE) & WS_CHILD) && (Wnd = GetParent(Wnd))) Level++;
    return Level;
}

static HWND Deepest(HWND Top)
{
    HWND Wnd = Top, Child;
    while ((Child = GetWindow(Wnd, GW_CHILD))) Wnd = Child;
    return Wnd;
}

static void TestCreate(void)
{
    HWND Top, Last, Wnd;
    INT Made;

    SetLastError(0xdeadbeef);
    Top = Chain(LIMIT + 10, &Last, &Made);
    ok(Top != NULL, "no top-level window: %lu\n", GetLastError());
    ok(Made == LIMIT, "children made below each other: %d windows, expected %d\n", Made, LIMIT);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "the child below level %d: error %lu\n", LIMIT, GetLastError());
    ok(Level(Last) == LIMIT, "the deepest window is at level %d\n", Level(Last));

    /* a sibling at the deepest level is still taken, a child of it is not */
    Wnd = CreateWindowExW(WS_EX_NOPARENTNOTIFY, L"NestLimit", L"s", WS_CHILD, 0, 0, 10, 10, GetParent(Last),
                          NULL, NULL, NULL);
    ok(Wnd != NULL, "a second window at level %d: %lu\n", LIMIT, GetLastError());
    SetLastError(0xdeadbeef);
    ok(!CreateWindowExW(0, L"NestLimit", L"x", WS_CHILD, 0, 0, 10, 10, Wnd ? Wnd : Last, NULL, NULL, NULL),
       "a window at level %d was created\n", LIMIT + 1);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "error %lu\n", GetLastError());
    ok(DestroyWindow(Top), "DestroyWindow: %lu\n", GetLastError());
}

static void TestSetParentChain(void)
{
    HWND Wnd[LIMIT + 5];
    INT i;

    for (i = 0; i < LIMIT + 5; i++)
        Wnd[i] = CreateWindowExW(WS_EX_NOPARENTNOTIFY, L"NestLimit", L"t", WS_OVERLAPPED, 0, 0, 50, 50,
                                 NULL, NULL, NULL, NULL);
    for (i = 1; i < LIMIT + 5; i++)
    {
        SetLastError(0xdeadbeef);
        if (!SetParent(Wnd[i], Wnd[i - 1])) break;
    }
    ok(i == LIMIT, "SetParent stopped at window %d, expected %d\n", i, LIMIT);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "error %lu\n", GetLastError());
    ok(GetParent(Wnd[LIMIT]) == NULL, "the window that did not fit got a parent\n");
    for (i = LIMIT + 4; i >= 0; i--) DestroyWindow(Wnd[i]);
}

static void TestSubtree(INT Under, BOOL Taken)
{
    HWND A, B, ALast, BLast, Ret;

    A = Chain(30, &ALast, NULL);
    B = Chain(30, &BLast, NULL);
    SetWindowLongPtrW(B, GWL_STYLE, WS_CHILD | WS_VISIBLE);
    SetLastError(0xdeadbeef);
    Ret = SetParent(B, Nth(A, Under));
    ok((Ret != NULL) == Taken, "a chain of 30 below the window at level %d: taken %d\n", Under, Ret != NULL);
    if (!Taken)
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "below level %d: error %lu\n", Under, GetLastError());
    ok(Level(Deepest(A)) == (Taken ? Under + 30 : 30), "deepest level %d\n", Level(Deepest(A)));
    DestroyWindow(A);
    DestroyWindow(B);
}

/* A deep chain is attempted (on a system without the limit, moving it overflowed the kernel stack); the tree at the
   limit is moved, redrawn and destroyed */
static void TestDeepAttempt(void)
{
    HWND Top, Last;
    INT Made;

    Top = Chain(2000, &Last, &Made);
    ok(Made == LIMIT, "a chain of 2000: %d windows made\n", Made);
    ok(SetWindowPos(Top, NULL, 37, 41, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos: %lu\n", GetLastError());
    ok(RedrawWindow(Top, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW | RDW_ERASENOW),
       "RedrawWindow: %lu\n", GetLastError());
    ShowWindow(Top, SW_SHOW);
    ShowWindow(Top, SW_MINIMIZE);
    ShowWindow(Top, SW_RESTORE);
    ok(DestroyWindow(Top), "DestroyWindow: %lu\n", GetLastError());
}

/* windows of two threads in one chain: the limit counts every window of the chain */
static HWND g_Parent;
static HANDLE g_Made, g_Done;
static HWND g_Child;

static DWORD WINAPI OtherThread(PVOID Param)
{
    MSG Msg;
    (void)Param;
    g_Child = CreateWindowExW(WS_EX_NOPARENTNOTIFY, L"NestLimit", L"o", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, g_Parent,
                              NULL, NULL, NULL);
    SetEvent(g_Made);
    while (WaitForSingleObject(g_Done, 0) != WAIT_OBJECT_0)
    {
        while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&Msg);
        Sleep(10);
    }
    if (g_Child) DestroyWindow(g_Child);
    return 0;
}

static void TestTwoThreads(void)
{
    HWND Top, Last, Ret;
    HANDLE Thread;
    INT Made;

    Top = Chain(LIMIT - 1, &Last, &Made);
    ok(Made == LIMIT - 1, "made %d\n", Made);
    g_Parent = Last;
    g_Made = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_Done = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, OtherThread, NULL, 0, NULL);
    WaitForSingleObject(g_Made, 10000);
    ok(g_Child != NULL, "the other thread's window at level %d\n", LIMIT);
    if (g_Child)
    {
        MSG Msg;
        SetLastError(0xdeadbeef);
        ok(!CreateWindowExW(0, L"NestLimit", L"x", WS_CHILD, 0, 0, 10, 10, g_Child, NULL, NULL, NULL),
           "a window below the other thread's window at level %d\n", LIMIT);
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "error %lu\n", GetLastError());
        /* a window of this thread moved below it */
        Ret = CreateWindowExW(WS_EX_NOPARENTNOTIFY, L"NestLimit", L"m", WS_OVERLAPPED, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
        SetLastError(0xdeadbeef);
        ok(!SetParent(Ret, g_Child), "SetParent below the other thread's window at level %d\n", LIMIT);
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "error %lu\n", GetLastError());
        DestroyWindow(Ret);
        ok(SetWindowPos(Top, NULL, 5, 5, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos\n");
        while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&Msg);
    }
    SetEvent(g_Done);
    while (MsgWaitForMultipleObjects(1, &Thread, FALSE, 10000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
    {
        MSG Msg;
        while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&Msg);
    }
    CloseHandle(Thread);
    DestroyWindow(Top);
    CloseHandle(g_Made);
    CloseHandle(g_Done);
}

START_TEST(WindowNestingLimit)
{
    WNDCLASSW Class = { 0 };

    Class.lpfnWndProc = NestProc;
    Class.lpszClassName = L"NestLimit";
    Class.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&Class);

    TestCreate();
    TestSetParentChain();
    TestSubtree(30, FALSE);
    TestSubtree(20, TRUE);
    TestSubtree(21, FALSE);
    TestTwoThreads();
    TestDeepAttempt();

    UnregisterClassW(L"NestLimit", NULL);
}
