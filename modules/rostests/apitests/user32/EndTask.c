/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test EndTask: which windows it refuses, and what it does to the others
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <winnls.h>

/*
 * Measured on Windows 10 22H2, a 64-bit and a 32-bit process alike, in the interactive session:
 *
 * - A window that is not valid for the caller is refused with FALSE and ERROR_INVALID_HANDLE
 *   (6), whatever fForce says: a NULL, bogus or destroyed handle, and any window when the
 *   calling thread has not made a user32 call yet (any call does: GetDesktopWindow, IsWindow,
 *   GetKeyState, PeekMessage...). The window gets no message. A window of another session is
 *   not valid either (IsWindow is FALSE there).
 * - Otherwise a window of the calling process (on another thread) or of another process of the
 *   same user is ended, whatever the integrity level of the caller and of the process (Low can
 *   end High): TRUE, and the last error is left alone. Without fForce the window gets WM_CLOSE and
 *   the call returns when the window is gone: after about 0.1 s for a window that closes, as late
 *   as the window closes for one that waits (3.1 s for a window that closes 3 s after WM_CLOSE),
 *   and never for one that ignores WM_CLOSE or does not pump messages. fShutDown makes no
 *   difference.
 * - With fForce the process of the window is ended at once (TRUE, 0 ms, exit code 0), without
 *   a WM_CLOSE, whether the window closes, ignores WM_CLOSE or hangs.
 *
 * Not measured: a window of another user, or of a SYSTEM process (the oracle has no second
 * account and no such window on the desktop).
 */

#define ERR_KEEP 0xdeadbeef
#define CHILD_LIFETIME 60000

/* ---------- the window (own thread, and the helper process) ---------- */

typedef enum { MODE_CLOSE, MODE_IGNORE, MODE_HUNG, MODE_DELAYED } MODE;

static MODE g_Mode;
static volatile LONG g_CloseCount;

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
            InterlockedIncrement(&g_CloseCount);
            if (g_Mode == MODE_CLOSE)
                DestroyWindow(hWnd);
            else if (g_Mode == MODE_DELAYED)
                SetTimer(hWnd, 1, 1000, NULL);
            return 0;
        case WM_TIMER:
            KillTimer(hWnd, 1);
            DestroyWindow(hWnd);
            return 0;
        case WM_DESTROY:
            if (g_Mode == MODE_CLOSE || g_Mode == MODE_DELAYED)
                PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

static
HWND
CreateTestWindow(
    _In_ PCWSTR Title,
    _In_ BOOL Visible)
{
    WNDCLASSW Class = { 0 };

    Class.lpfnWndProc = WndProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"EndTaskTestWindow";
    RegisterClassW(&Class);
    return CreateWindowExW(0, Class.lpszClassName, Title,
                           WS_OVERLAPPEDWINDOW | (Visible ? WS_VISIBLE : 0),
                           0, 0, 100, 100, NULL, NULL, Class.hInstance, NULL);
}

/* The helper process: a window titled Title, behaving as Mode says; it ends by itself. */
static
void
ChildProcess(
    _In_ PCSTR ModeName,
    _In_ PCSTR Title)
{
    WCHAR wTitle[64];
    HWND hWnd;
    MSG Msg;

    MultiByteToWideChar(CP_ACP, 0, Title, -1, wTitle, ARRAYSIZE(wTitle));
    g_Mode = !strcmp(ModeName, "ignore") ? MODE_IGNORE :
             !strcmp(ModeName, "hung") ? MODE_HUNG :
             !strcmp(ModeName, "delayed") ? MODE_DELAYED : MODE_CLOSE;
    hWnd = CreateTestWindow(wTitle, TRUE);
    if (!hWnd)
        return;
    if (g_Mode == MODE_HUNG)
    {
        /* no message loop at all */
        Sleep(CHILD_LIFETIME);
        return;
    }
    SetTimer(hWnd, 2, CHILD_LIFETIME, NULL);
    while (GetMessageW(&Msg, NULL, 0, 0) > 0)
    {
        if (Msg.message == WM_TIMER && Msg.wParam == 2 && Msg.hwnd == hWnd)
            break;
        DispatchMessageW(&Msg);
    }
}

static HWND g_hOwnWnd;
static HANDLE g_hOwnReady;

static
DWORD
WINAPI
OwnWindowThread(
    _In_ PVOID Parameter)
{
    MSG Msg;

    g_hOwnWnd = CreateTestWindow(L"EndTask own", (BOOL)(ULONG_PTR)Parameter);
    SetEvent(g_hOwnReady);
    while (GetMessageW(&Msg, NULL, 0, 0) > 0)
        DispatchMessageW(&Msg);
    return 0;
}

/* ---------- calls ---------- */

typedef struct
{
    HWND hWnd;
    BOOL Shut;
    BOOL Force;
    BOOL Prime; /* make a user32 call first, so that the thread is a GUI thread */
    BOOL Ret;
    DWORD Error;
    DWORD Ticks;
} CALL;

static
DWORD
WINAPI
CallThread(
    _In_ PVOID Parameter)
{
    CALL *Call = Parameter;
    DWORD Start;

    if (Call->Prime)
    {
        MSG Msg;
        PeekMessageW(&Msg, NULL, 0, 0, PM_NOREMOVE);
    }
    SetLastError(ERR_KEEP);
    Start = GetTickCount();
    Call->Ret = EndTask(Call->hWnd, Call->Shut, Call->Force);
    Call->Error = GetLastError();
    Call->Ticks = GetTickCount() - Start;
    return 0;
}

static
void
DoCall(
    _Out_ CALL *Call,
    _In_ HWND hWnd,
    _In_ BOOL Shut,
    _In_ BOOL Force)
{
    Call->hWnd = hWnd;
    Call->Shut = Shut;
    Call->Force = Force;
    Call->Prime = FALSE; /* the main thread is a GUI thread */
    CallThread(Call);
}

static
void
ExpectRefused(
    _In_ PCSTR Name,
    _In_ HWND hWnd,
    _In_ BOOL Shut,
    _In_ BOOL Force)
{
    CALL Call;

    DoCall(&Call, hWnd, Shut, Force);
    ok(!Call.Ret, "%s (shut %d, force %d): EndTask succeeded\n", Name, Shut, Force);
    ok(Call.Error == ERROR_INVALID_HANDLE, "%s (shut %d, force %d): error %lu\n", Name, Shut, Force, Call.Error);
}

static
BOOL
StartChild(
    _In_ PCSTR ModeName,
    _Out_ PROCESS_INFORMATION *pi,
    _Out_ HWND *phWnd)
{
    CHAR Path[MAX_PATH], CmdLine[MAX_PATH + 100], Title[64];
    WCHAR wTitle[64];
    STARTUPINFOA si = { sizeof(si) };
    static LONG Serial;
    DWORD Start;

    *phWnd = NULL;
    GetModuleFileNameA(NULL, Path, ARRAYSIZE(Path));
    sprintf(Title, "EndTaskChild_%s_%lu_%ld", ModeName, GetCurrentProcessId(), InterlockedIncrement(&Serial));
    sprintf(CmdLine, "\"%s\" EndTask child %s %s", Path, ModeName, Title);
    MultiByteToWideChar(CP_ACP, 0, Title, -1, wTitle, ARRAYSIZE(wTitle));
    if (!CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, pi))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        return FALSE;
    }
    Start = GetTickCount();
    while (!*phWnd && GetTickCount() - Start < 15000)
    {
        *phWnd = FindWindowW(L"EndTaskTestWindow", wTitle);
        if (!*phWnd)
            Sleep(20);
    }
    ok(*phWnd != NULL, "%s child: window not found\n", ModeName);
    if (!*phWnd)
        TerminateProcess(pi->hProcess, 1);
    return *phWnd != NULL;
}

static
void
EndChild(
    _In_ PROCESS_INFORMATION *pi)
{
    if (WaitForSingleObject(pi->hProcess, 0) != WAIT_OBJECT_0)
    {
        TerminateProcess(pi->hProcess, 1);
        WaitForSingleObject(pi->hProcess, 10000);
    }
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
}

/* TRUE, the last error not touched, the window gone, and for Ended the process ended with exit code 0. */
static
void
TestChild(
    _In_ PCSTR ModeName,
    _In_ BOOL Shut,
    _In_ BOOL Force,
    _In_ DWORD MinTicks)
{
    PROCESS_INFORMATION pi;
    HWND hWnd;
    CALL Call;
    DWORD Exit = 1;

    if (!StartChild(ModeName, &pi, &hWnd))
        return;
    DoCall(&Call, hWnd, Shut, Force);
    ok(Call.Ret, "%s (shut %d, force %d): EndTask failed with %lu\n", ModeName, Shut, Force, Call.Error);
    ok(Call.Error == ERR_KEEP, "%s (shut %d, force %d): the last error is %lu\n", ModeName, Shut, Force, Call.Error);
    ok(Call.Ticks >= MinTicks, "%s (shut %d, force %d): returned after %lu ms\n", ModeName, Shut, Force, Call.Ticks);
    ok(WaitForSingleObject(pi.hProcess, 10000) == WAIT_OBJECT_0, "%s (shut %d, force %d): the process did not end\n", ModeName, Shut, Force);
    ok(!IsWindow(hWnd), "%s (shut %d, force %d): the window is still there\n", ModeName, Shut, Force);
    GetExitCodeProcess(pi.hProcess, &Exit);
    ok(Exit == 0, "%s (shut %d, force %d): exit code %lu\n", ModeName, Shut, Force, Exit);
    EndChild(&pi);
}

/* Without fForce, a window that ignores WM_CLOSE (or hangs) keeps the call waiting. */
static
void
TestChildBlocks(
    _In_ PCSTR ModeName)
{
    PROCESS_INFORMATION pi;
    HWND hWnd;
    CALL Call = { 0 };
    HANDLE hThread;
    DWORD Wait;

    if (!StartChild(ModeName, &pi, &hWnd))
        return;
    Call.hWnd = hWnd;
    Call.Prime = TRUE;
    hThread = CreateThread(NULL, 0, CallThread, &Call, 0, NULL);
    Wait = WaitForSingleObject(hThread, 2000);
    ok(Wait == WAIT_TIMEOUT, "%s: EndTask returned (%d, error %lu) for a window that does not close\n", ModeName, Call.Ret, Call.Error);
    ok(IsWindow(hWnd), "%s: the window is gone\n", ModeName);
    /* free the waiting call: ending the process destroys the window */
    TerminateProcess(pi.hProcess, 1);
    Wait = WaitForSingleObject(hThread, 15000);
    ok(Wait == WAIT_OBJECT_0, "%s: EndTask did not return after the process ended\n", ModeName);
    CloseHandle(hThread);
    EndChild(&pi);
}

/* A worker thread that has made no user32 call is refused, for a window that it could end otherwise. */
static
void
TestNonGuiThread(void)
{
    PROCESS_INFORMATION pi;
    HWND hWnd;
    CALL Call = { 0 };
    HANDLE hThread;

    if (!StartChild("close", &pi, &hWnd))
        return;
    Call.hWnd = hWnd;
    hThread = CreateThread(NULL, 0, CallThread, &Call, 0, NULL);
    ok(WaitForSingleObject(hThread, 15000) == WAIT_OBJECT_0, "The call did not return\n");
    CloseHandle(hThread);
    ok(!Call.Ret, "EndTask from a thread without a user32 call succeeded\n");
    ok(Call.Error == ERROR_INVALID_HANDLE, "error %lu\n", Call.Error);
    ok(IsWindow(hWnd), "The window is gone\n");

    /* the same thread kind, after a user32 call, ends it */
    Call.Prime = TRUE;
    Call.Force = FALSE;
    hThread = CreateThread(NULL, 0, CallThread, &Call, 0, NULL);
    ok(WaitForSingleObject(hThread, 15000) == WAIT_OBJECT_0, "The second call did not return\n");
    CloseHandle(hThread);
    ok(Call.Ret, "EndTask from a thread after a user32 call failed with %lu\n", Call.Error);
    ok(Call.Error == ERR_KEEP, "the last error is %lu\n", Call.Error);
    ok(WaitForSingleObject(pi.hProcess, 10000) == WAIT_OBJECT_0, "The process did not end\n");
    EndChild(&pi);
}

START_TEST(EndTask)
{
    static const HWND Bogus[] = { NULL, (HWND)(ULONG_PTR)0x7fff0, (HWND)(ULONG_PTR)0xdeadbeef };
    char **argv;
    int argc, i;
    HANDLE hThread;
    HWND hWnd;
    CALL Call;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "child"))
    {
        ChildProcess(argv[3], argv[4]);
        return;
    }

    /* Invalid handles: FALSE and ERROR_INVALID_HANDLE, with and without fForce */
    for (i = 0; i < ARRAYSIZE(Bogus); i++)
    {
        ExpectRefused("invalid handle", Bogus[i], FALSE, FALSE);
        ExpectRefused("invalid handle", Bogus[i], FALSE, TRUE);
    }

    /* A window of the calling process, on another thread: ended, with WM_CLOSE */
    g_hOwnReady = CreateEventW(NULL, TRUE, FALSE, NULL);
    hThread = CreateThread(NULL, 0, OwnWindowThread, (PVOID)TRUE, 0, NULL);
    ok(hThread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (!hThread)
        return;
    ok(WaitForSingleObject(g_hOwnReady, 10000) == WAIT_OBJECT_0, "The window thread did not start\n");
    hWnd = g_hOwnWnd;
    ok(IsWindow(hWnd), "The test window was not created\n");
    g_Mode = MODE_CLOSE;
    DoCall(&Call, hWnd, TRUE, FALSE);
    ok(Call.Ret, "EndTask on an own window failed with %lu\n", Call.Error);
    ok(Call.Error == ERR_KEEP, "EndTask on an own window changed the last error to %lu\n", Call.Error);
    ok(g_CloseCount == 1, "The own window got %ld WM_CLOSE\n", g_CloseCount);
    ok(!IsWindow(hWnd), "The own window is still there\n");

    /* A destroyed window is an invalid handle too */
    ExpectRefused("destroyed window", hWnd, FALSE, FALSE);
    ExpectRefused("destroyed window", hWnd, FALSE, TRUE);
    ok(WaitForSingleObject(hThread, 10000) == WAIT_OBJECT_0, "The window thread did not end\n");
    CloseHandle(hThread);
    CloseHandle(g_hOwnReady);

    /* Windows of another process */
    TestChild("close", FALSE, FALSE, 0);
    TestChild("close", TRUE, FALSE, 0);
    TestChild("close", FALSE, TRUE, 0);
    TestChild("ignore", FALSE, TRUE, 0);
    TestChild("hung", FALSE, TRUE, 0);
    TestChild("delayed", FALSE, FALSE, 800);
    TestChildBlocks("ignore");
    TestChildBlocks("hung");
    TestNonGuiThread();

}
