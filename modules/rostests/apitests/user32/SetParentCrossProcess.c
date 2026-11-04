/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SetParent on a window that belongs to another process. WebView2 hosting does this: the host
 *              process re-parents the window of the browser process into its own window.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Not verified on a Windows oracle: it follows the documented behaviour (SetParent returns the previous
 * parent and re-parents the window, whichever process owns it).
 */

#include "precomp.h"

static
int
ChildProcess(
    _In_ const char *Title,
    _In_ const char *EventName)
{
    HWND Child;
    HANDLE Event;
    DWORD Wait;

    Event = OpenEventA(SYNCHRONIZE, FALSE, EventName);
    Child = CreateWindowExA(0, "STATIC", Title, WS_POPUP, 0, 0, 10, 10, NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (!Event || !Child)
        return 12;

    /* the other process re-parents this window and sends messages to this thread: keep pumping */
    for (;;)
    {
        MSG Msg;

        Wait = MsgWaitForMultipleObjects(1, &Event, FALSE, 30000, QS_ALLINPUT);
        while (PeekMessageA(&Msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&Msg);
            DispatchMessageA(&Msg);
        }
        if (Wait != WAIT_OBJECT_0 + 1)
            break;
    }
    DestroyWindow(Child);
    return Wait == WAIT_OBJECT_0 ? 0 : 13;
}

START_TEST(SetParentCrossProcess)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    char Path[MAX_PATH], CmdLine[MAX_PATH + 160], Title[64], EventName[64];
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    HWND Parent, Child = NULL, Old;
    HANDLE Event;
    DWORD ExitCode = 0xffffffff, Tick, Wait;

    if (argc >= 5 && !strcmp(argv[2], "child"))
    {
        ExitProcess(ChildProcess(argv[3], argv[4]));
    }

    Parent = CreateWindowExA(0, "STATIC", "parent", WS_POPUP, 0, 0, 100, 100, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(Parent != NULL, "CreateWindowExA failed: %lu\n", GetLastError());
    sprintf(Title, "SetParentCrossProcessChild%lu", GetCurrentProcessId());
    sprintf(EventName, "Local\\SetParentCrossProcess%lu", GetCurrentProcessId());
    Event = CreateEventA(NULL, TRUE, FALSE, EventName);
    ok(Event != NULL, "CreateEventA failed: %lu\n", GetLastError());
    if (!Parent || !Event)
        return;

    GetModuleFileNameA(NULL, Path, sizeof(Path));
    sprintf(CmdLine, "\"%s\" SetParentCrossProcess child %s %s", Path, Title, EventName);
    if (!CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        DestroyWindow(Parent);
        CloseHandle(Event);
        return;
    }

    Tick = GetTickCount();
    while (!Child && GetTickCount() - Tick < 15000)
    {
        Child = FindWindowA("STATIC", Title);
        if (!Child)
            Sleep(50);
    }
    ok(Child != NULL, "the window of the other process was not found\n");
    if (Child)
    {
        ok(GetWindowThreadProcessId(Child, NULL) != GetCurrentThreadId(), "the window is ours\n");

        SetWindowLongPtrW(Child, GWL_STYLE, (LONG_PTR)(WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN));
        SetLastError(0xdeadbeef);
        Old = SetParent(Child, Parent);
        ok(Old != NULL, "SetParent on a window of another process failed: %lu\n", GetLastError());
        ok(GetAncestor(Child, GA_PARENT) == Parent, "the window was not re-parented: %p, expected %p\n",
           GetAncestor(Child, GA_PARENT), Parent);
        ok(GetParent(Child) == Parent, "GetParent returned %p, expected %p\n", GetParent(Child), Parent);
    }

    SetEvent(Event);
    Wait = WaitForSingleObject(Pi.hProcess, 15000);
    if (Wait != WAIT_OBJECT_0)
    {
        ok(0, "the child did not finish\n");
        TerminateProcess(Pi.hProcess, 99);
        WaitForSingleObject(Pi.hProcess, 5000);
    }
    GetExitCodeProcess(Pi.hProcess, &ExitCode);
    ok(ExitCode == 0, "the child process returned %lu\n", ExitCode);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    CloseHandle(Event);
    DestroyWindow(Parent);
}
