/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test SendMessageTimeout (also as a broadcast) and IsHungAppWindow against a
 *              window of another process whose thread has stopped reading messages
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <winnls.h>

/*
 * Measured on Windows 10 22H2, 64-bit and 32-bit callers alike, in the interactive session,
 * against a child process that shows a window, reads its messages for half a second and then
 * waits for ever on an event:
 *
 * - IsHungAppWindow is FALSE for the first five seconds after the last read and TRUE from then on.
 * - SendMessageTimeout(SMTO_ABORTIFHUNG) to the window, before it counts as hung, waits the
 *   whole timeout (FALSE, ERROR_TIMEOUT); once it is hung, fails at once and leaves the last
 *   error alone. SMTO_NORMAL always waits the timeout.
 * - A broadcast of WM_SETTINGCHANGE ("Environment") with SMTO_ABORTIFHUNG and 5000 ms skips the
 *   hung windows: it takes no longer with one or three hung processes than with none. With
 *   SMTO_NORMAL every window of a hung thread costs the whole timeout, one after the other.
 *   A thread that hangs just before the broadcast costs one timeout: it is hung by then.
 *
 * Not measured on Windows (documented): the timeout of a call covers the whole call, also when
 * the caller's thread gets posted messages while it waits.
 */

#define CHILD_LIFETIME 60000
#define MARK 0xdead

typedef struct
{
    PROCESS_INFORMATION pi;
    HWND hWnd;
    DWORD LastRead;   /* about when the child stopped reading its messages */
} CHILD;

static
LRESULT
CALLBACK
ChildWndProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

/* The child: a visible window, half a second of reading messages, then no reads at all */
static
void
ChildProcess(
    _In_ PCSTR Title)
{
    WCHAR wTitle[64];
    WNDCLASSW Class = { 0 };
    HWND hWnd;
    MSG Msg;
    DWORD Start;

    MultiByteToWideChar(CP_ACP, 0, Title, -1, wTitle, ARRAYSIZE(wTitle));
    Class.lpfnWndProc = ChildWndProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"BroadcastHungChild";
    RegisterClassW(&Class);
    hWnd = CreateWindowExW(0, Class.lpszClassName, wTitle, WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           50, 50, 200, 100, NULL, NULL, Class.hInstance, NULL);
    if (!hWnd)
        return;
    Start = GetTickCount();
    while (GetTickCount() - Start < 500)
    {
        while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&Msg);
        Sleep(10);
    }
    Sleep(CHILD_LIFETIME);
}

static
BOOL
StartChild(
    _Out_ CHILD *Child)
{
    CHAR Path[MAX_PATH], CmdLine[MAX_PATH + 100], Title[64];
    WCHAR wTitle[64];
    STARTUPINFOA si = { sizeof(si) };
    static LONG Serial;
    DWORD Start;

    ZeroMemory(Child, sizeof(*Child));
    GetModuleFileNameA(NULL, Path, ARRAYSIZE(Path));
    sprintf(Title, "BroadcastHungChild_%lu_%ld", GetCurrentProcessId(), InterlockedIncrement(&Serial));
    sprintf(CmdLine, "\"%s\" BroadcastHung child %s", Path, Title);
    MultiByteToWideChar(CP_ACP, 0, Title, -1, wTitle, ARRAYSIZE(wTitle));
    if (!CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &Child->pi))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        return FALSE;
    }
    Start = GetTickCount();
    while (!Child->hWnd && GetTickCount() - Start < 15000)
    {
        Child->hWnd = FindWindowW(L"BroadcastHungChild", wTitle);
        if (!Child->hWnd)
            Sleep(20);
    }
    ok(Child->hWnd != NULL, "child window not found\n");
    if (!Child->hWnd)
    {
        TerminateProcess(Child->pi.hProcess, 1);
        WaitForSingleObject(Child->pi.hProcess, 10000);
        CloseHandle(Child->pi.hThread);
        CloseHandle(Child->pi.hProcess);
        return FALSE;
    }
    /* the window shows up before the half second of reads ends */
    Sleep(600);
    Child->LastRead = GetTickCount();
    return TRUE;
}

static
void
EndChild(
    _In_ CHILD *Child)
{
    if (!Child->pi.hProcess)
        return;
    TerminateProcess(Child->pi.hProcess, 1);
    WaitForSingleObject(Child->pi.hProcess, 10000);
    CloseHandle(Child->pi.hThread);
    CloseHandle(Child->pi.hProcess);
    Child->pi.hProcess = NULL;
}

static
void
WaitHung(
    _In_ CHILD *Child)
{
    while (GetTickCount() - Child->LastRead < 6500)
        Sleep(50);
}

typedef struct
{
    LRESULT Ret;
    DWORD Error;
    DWORD Ticks;
} SMTO_RESULT;

static
void
Broadcast(
    _In_ UINT Flags,
    _In_ UINT Timeout,
    _Out_ SMTO_RESULT *r)
{
    DWORD_PTR Result = 0;
    DWORD Start = GetTickCount();

    SetLastError(MARK);
    r->Ret = SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment",
                                 Flags, Timeout, &Result);
    r->Error = GetLastError();
    r->Ticks = GetTickCount() - Start;
}

static
void
Direct(
    _In_ HWND hWnd,
    _In_ UINT Flags,
    _In_ UINT Timeout,
    _Out_ SMTO_RESULT *r)
{
    DWORD_PTR Result = 0;
    DWORD Start = GetTickCount();

    SetLastError(MARK);
    r->Ret = SendMessageTimeoutW(hWnd, WM_NULL, 0, 0, Flags, Timeout, &Result);
    r->Error = GetLastError();
    r->Ticks = GetTickCount() - Start;
}

/* IsHungAppWindow over time, and SendMessageTimeout to the window before and after it is hung */
static
void
TestDirect(void)
{
    CHILD Child;
    SMTO_RESULT r;

    if (!StartChild(&Child))
        return;

    ok(!IsHungAppWindow(Child.hWnd), "IsHungAppWindow is TRUE right after the last read\n");
    Direct(Child.hWnd, SMTO_ABORTIFHUNG, 1000, &r);
    ok(!r.Ret, "SMTO_ABORTIFHUNG before hung: succeeded\n");
    ok(r.Error == ERROR_TIMEOUT, "SMTO_ABORTIFHUNG before hung: error %lu\n", r.Error);
    ok(r.Ticks >= 900 && r.Ticks < 3000, "SMTO_ABORTIFHUNG before hung: %lu ms\n", r.Ticks);

    while (GetTickCount() - Child.LastRead < 3500)
        Sleep(50);
    ok(!IsHungAppWindow(Child.hWnd), "IsHungAppWindow is TRUE 3.5 s after the last read\n");

    WaitHung(&Child);
    ok(IsHungAppWindow(Child.hWnd), "IsHungAppWindow is FALSE 6.5 s after the last read\n");
    Direct(Child.hWnd, SMTO_ABORTIFHUNG, 1000, &r);
    ok(!r.Ret, "SMTO_ABORTIFHUNG when hung: succeeded\n");
    ok(r.Error == MARK, "SMTO_ABORTIFHUNG when hung: error %lu\n", r.Error);
    ok(r.Ticks < 500, "SMTO_ABORTIFHUNG when hung: %lu ms\n", r.Ticks);
    Direct(Child.hWnd, SMTO_NORMAL, 1000, &r);
    ok(!r.Ret, "SMTO_NORMAL when hung: succeeded\n");
    ok(r.Error == ERROR_TIMEOUT, "SMTO_NORMAL when hung: error %lu\n", r.Error);
    ok(r.Ticks >= 900 && r.Ticks < 3000, "SMTO_NORMAL when hung: %lu ms\n", r.Ticks);

    EndChild(&Child);
}

/* A broadcast with SMTO_ABORTIFHUNG does not wait for hung windows: 0, 1 and 3 hung processes */
static
void
TestBroadcast(void)
{
    CHILD Child[3];
    SMTO_RESULT Base, r;
    int i, n = 0;

    Broadcast(SMTO_ABORTIFHUNG, 5000, &Base);
    ok(Base.Ret, "broadcast without hung windows failed with %lu\n", Base.Error);
    trace("broadcast without hung windows: %lu ms\n", Base.Ticks);

    for (i = 0; i < 3; i++)
        n += StartChild(&Child[i]);
    if (n != 3)
        goto Cleanup;

    WaitHung(&Child[0]);
    Broadcast(SMTO_ABORTIFHUNG, 5000, &r);
    ok(r.Ret, "broadcast with 3 hung processes failed with %lu\n", r.Error);
    ok(r.Error == MARK, "broadcast with 3 hung processes: error %lu\n", r.Error);
    ok(r.Ticks < Base.Ticks + 2500, "broadcast with 3 hung processes: %lu ms (%lu ms without)\n", r.Ticks, Base.Ticks);

    /* SMTO_NORMAL waits for each window of a hung thread */
    EndChild(&Child[1]);
    EndChild(&Child[2]);
    Broadcast(SMTO_NORMAL, 1000, &r);
    ok(r.Ret, "SMTO_NORMAL broadcast with 1 hung process failed with %lu\n", r.Error);
    ok(r.Ticks >= 900, "SMTO_NORMAL broadcast with 1 hung process: %lu ms\n", r.Ticks);

Cleanup:
    for (i = 0; i < 3; i++)
        EndChild(&Child[i]);
}

/* The timeout is the whole call, even for a caller whose thread gets posted messages meanwhile */
typedef struct
{
    HWND hWnd;
    BOOL Bcast;
    UINT Flags;
    UINT Timeout;
    SMTO_RESULT r;
    volatile LONG Done;
} POSTED_SEND;

static
DWORD
WINAPI
PostedSendThread(
    _In_ PVOID Parameter)
{
    POSTED_SEND *t = Parameter;

    if (t->Bcast)
        Broadcast(t->Flags, t->Timeout, &t->r);
    else
        Direct(t->hWnd, t->Flags, t->Timeout, &t->r);
    InterlockedExchange(&t->Done, 1);
    return 0;
}

static
void
TestPostedSender(
    _In_ BOOL Bcast,
    _In_ UINT Flags,
    _In_ UINT Timeout,
    _In_ DWORD MaxTicks)
{
    CHILD Child;
    POSTED_SEND t = { 0 };
    HANDLE hThread;
    DWORD Wait, ThreadId, Start;

    /* a window that is not hung yet, so that SMTO_ABORTIFHUNG waits too */
    if (!StartChild(&Child))
        return;
    t.hWnd = Child.hWnd;
    t.Bcast = Bcast;
    t.Flags = Flags;
    t.Timeout = Timeout;
    hThread = CreateThread(NULL, 0, PostedSendThread, &t, 0, &ThreadId);
    ok(hThread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (!hThread)
    {
        EndChild(&Child);
        return;
    }
    /* wake the waiting thread every 200 ms with a posted message */
    Start = GetTickCount();
    do
    {
        PostThreadMessageW(ThreadId, WM_USER, 0, 0);
        Wait = WaitForSingleObject(hThread, 200);
    } while (Wait == WAIT_TIMEOUT && GetTickCount() - Start < MaxTicks + 5000);
    ok(Wait == WAIT_OBJECT_0, "%s flags %#x timeout %u: no return after %lu ms\n",
       Bcast ? "broadcast" : "send", Flags, Timeout, MaxTicks + 5000);
    /* ending the child frees a call that is still waiting */
    EndChild(&Child);
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    if (Wait != WAIT_OBJECT_0)
        return;
    if (Bcast)
    {
        ok(t.r.Ret, "broadcast flags %#x: failed with %lu\n", Flags, t.r.Error);
    }
    else
    {
        ok(!t.r.Ret, "send flags %#x: succeeded\n", Flags);
        ok(t.r.Error == ERROR_TIMEOUT, "send flags %#x: error %lu\n", Flags, t.r.Error);
    }
    ok(t.r.Ticks >= Timeout - 100 && t.r.Ticks <= MaxTicks, "%s flags %#x timeout %u: %lu ms\n",
       Bcast ? "broadcast" : "send", Flags, Timeout, t.r.Ticks);
}

START_TEST(BroadcastHung)
{
    char **argv;
    int argc;
    SMTO_RESULT Base;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        ChildProcess(argv[3]);
        return;
    }

    TestDirect();
    TestBroadcast();
    TestPostedSender(FALSE, SMTO_NORMAL, 2000, 4000);
    TestPostedSender(FALSE, SMTO_ABORTIFHUNG, 2000, 4000);
    Broadcast(SMTO_ABORTIFHUNG, 5000, &Base);
    TestPostedSender(TRUE, SMTO_ABORTIFHUNG, 5000, Base.Ticks + 7500);
}
