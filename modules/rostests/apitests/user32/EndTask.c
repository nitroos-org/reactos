/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test EndTask on a window of another thread
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * EndTask sends WM_CLOSE to the window through the user server (UserpEndTask): the window of a
 * thread that closes it is gone when the call returns, and the call succeeds. Measured on
 * Windows 10 22H2, a 32-bit and a 64-bit process alike: TRUE, the window is gone, and the last
 * error is not touched. A 32-bit process under WoW64 on ReactOS used to get FALSE with error
 * 50 (ERROR_NOT_SUPPORTED): the request was not passed to the server.
 *
 * A window that ignores WM_CLOSE is not tested: Windows waits for it for good, and with fForce
 * it ends the process.
 */

#define ERR_KEEP 0xdeadbeef

static HWND g_hWnd;
static HANDLE g_hReady;

static
LRESULT
CALLBACK
WndProc(
    _In_ HWND hWnd,
    _In_ UINT Msg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam)
{
    switch (Msg)
    {
        case WM_CLOSE:
            DestroyWindow(hWnd);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

static
DWORD
WINAPI
WindowThread(
    _In_ PVOID Parameter)
{
    WNDCLASSW Class = { 0 };
    MSG Msg;

    Class.lpfnWndProc = WndProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"EndTaskTestWindow";
    RegisterClassW(&Class);
    g_hWnd = CreateWindowExW(0, Class.lpszClassName, L"EndTask", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100,
                             NULL, NULL, Class.hInstance, NULL);
    SetEvent(g_hReady);
    while (GetMessageW(&Msg, NULL, 0, 0) > 0)
        DispatchMessageW(&Msg);
    UnregisterClassW(Class.lpszClassName, Class.hInstance);
    return 0;
}

START_TEST(EndTask)
{
    HANDLE hThread;
    DWORD Wait;
    BOOL Ret;

    g_hReady = CreateEventW(NULL, TRUE, FALSE, NULL);
    hThread = CreateThread(NULL, 0, WindowThread, NULL, 0, NULL);
    ok(hThread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (!hThread)
        return;
    Wait = WaitForSingleObject(g_hReady, 10000);
    ok(Wait == WAIT_OBJECT_0, "The window thread did not start: %lu\n", Wait);
    ok(IsWindow(g_hWnd), "The test window was not created\n");

    SetLastError(ERR_KEEP);
    Ret = EndTask(g_hWnd, FALSE, FALSE);
    ok(Ret, "EndTask failed with %lu\n", GetLastError());
    ok(GetLastError() == ERR_KEEP, "EndTask changed the last error to %lu\n", GetLastError());
    ok(!IsWindow(g_hWnd), "The window is still there\n");

    Wait = WaitForSingleObject(hThread, 10000);
    ok(Wait == WAIT_OBJECT_0, "The window thread did not end: %lu\n", Wait);
    CloseHandle(hThread);
    CloseHandle(g_hReady);
}
