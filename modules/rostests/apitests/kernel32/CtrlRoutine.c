/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for the kernel32 export CtrlRoutine, the thread routine that dispatches a console control event
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The MSYS2 and Cygwin runtimes look it up with GetProcAddress and start it in another process with
 * CreateRemoteThread to deliver Ctrl+C there; the parameter is the control event.
 */

#include "precomp.h"

static volatile LONG g_Event = -1;
static HANDLE g_Called;

static BOOL WINAPI Handler(DWORD CtrlType)
{
    InterlockedExchange(&g_Event, (LONG)CtrlType);
    SetEvent(g_Called);
    return TRUE;
}

START_TEST(CtrlRoutine)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pCtrlRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32, "CtrlRoutine");
    HMODULE Kernelbase = LoadLibraryW(L"kernelbase.dll");
    HANDLE Thread;
    DWORD Id;

    if (!pCtrlRoutine)
    {
        ok(!is_reactos(), "CtrlRoutine is not exported by kernel32\n");
        skip("CtrlRoutine is not available\n");
        return;
    }

    ok(Kernelbase && GetProcAddress(Kernelbase, "CtrlRoutine") != NULL, "CtrlRoutine is not exported by kernelbase\n");

    g_Called = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(g_Called != NULL, "CreateEvent failed\n");

    if (!GetConsoleWindow() && GetStdHandle(STD_OUTPUT_HANDLE) == INVALID_HANDLE_VALUE)
    {
        skip("no console\n");
        return;
    }

    ok(SetConsoleCtrlHandler(Handler, TRUE), "SetConsoleCtrlHandler failed with %lu\n", GetLastError());

    /* Ctrl+Break: the handler runs with the event of the thread parameter */
    Thread = CreateThread(NULL, 0, pCtrlRoutine, (LPVOID)(ULONG_PTR)CTRL_BREAK_EVENT, 0, &Id);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Thread)
    {
        ok(WaitForSingleObject(g_Called, 10000) == WAIT_OBJECT_0, "the handler was not called\n");
        ok(g_Event == CTRL_BREAK_EVENT, "handler event %ld\n", g_Event);
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
    }

    SetConsoleCtrlHandler(Handler, FALSE);
    CloseHandle(g_Called);
}
