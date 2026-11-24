/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The posted messages of one thread are limited (USERPostMessageLimit)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (value USERPostMessageLimit = 10000 in HKLM\SOFTWARE\Microsoft\Windows NT\
 * CurrentVersion\Windows): a thread that does not read its queue takes 10000 posted messages; the next
 * PostThreadMessage and the next PostMessage to a window of the thread fail with ERROR_NOT_ENOUGH_QUOTA (1816);
 * after the messages are read, posting works again. Without a limit a program or a shell that falls behind
 * (every window that is shown notifies the shell's hook window) takes paged pool without bound.
 */

#include "precomp.h"

#define POST_LIMIT 10000

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static LONG Drain(UINT First, UINT Last)
{
    MSG Msg;
    LONG Count = 0;

    while (PeekMessageW(&Msg, NULL, First, Last, PM_REMOVE))
        Count++;
    return Count;
}

START_TEST(PostMessageLimit)
{
    WNDCLASSW Class = { 0 };
    HWND hWnd;
    LONG Posted = 0, Drained;
    DWORD Error;
    MSG Msg;

    Class.lpfnWndProc = WndProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"PostLimitClass";
    RegisterClassW(&Class);
    hWnd = CreateWindowExW(0, L"PostLimitClass", L"limit", WS_OVERLAPPED, 0, 0, 10, 10, NULL, NULL, Class.hInstance, NULL);
    ok(hWnd != NULL, "CreateWindowEx failed: %lu\n", GetLastError());
    if (!hWnd)
        return;

    /* an empty queue */
    while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
        ;

    SetLastError(0);
    while (Posted < POST_LIMIT + 100 && PostThreadMessageW(GetCurrentThreadId(), WM_USER + 1, 0, 0))
        Posted++;
    Error = GetLastError();
    ok(Posted == POST_LIMIT, "%ld messages could be posted to the thread, expected %d\n", Posted, POST_LIMIT);
    ok(Error == ERROR_NOT_ENOUGH_QUOTA, "PostThreadMessage failed with %lu, expected %d\n", Error, ERROR_NOT_ENOUGH_QUOTA);

    SetLastError(0);
    ok(!PostMessageW(hWnd, WM_USER + 2, 0, 0), "PostMessage to a window of the thread succeeded at the limit\n");
    Error = GetLastError();
    ok(Error == ERROR_NOT_ENOUGH_QUOTA, "PostMessage failed with %lu, expected %d\n", Error, ERROR_NOT_ENOUGH_QUOTA);

    Drained = Drain(WM_USER + 1, WM_USER + 1);
    ok(Drained == POST_LIMIT, "%ld messages were read back, expected %d\n", Drained, POST_LIMIT);
    ok(Drain(WM_USER + 2, WM_USER + 2) == 0, "the refused message is in the queue\n");

    /* the queue takes messages again */
    ok(PostThreadMessageW(GetCurrentThreadId(), WM_USER + 1, 0, 0), "PostThreadMessage after the drain: %lu\n", GetLastError());
    ok(PostMessageW(hWnd, WM_USER + 2, 0, 0), "PostMessage after the drain: %lu\n", GetLastError());
    ok(Drain(WM_USER + 1, WM_USER + 2) == 2, "messages posted after the drain were lost\n");

    DestroyWindow(hWnd);
    UnregisterClassW(L"PostLimitClass", Class.hInstance);
}
