/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test destroying a CS_OWNDC / CS_CLASSDC window while another thread draws through its DC
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * A child process makes a window of a class with its own (or the class) DC, a second thread draws through
 * that DC without pause, and the window is destroyed while it draws; then the child ends, by itself or
 * terminated by this process. The drawing thread's calls fail once the DC is gone, the child ends at once,
 * and the system goes on.
 */
#define CHILDREN 16

static HDC hdcShared;
static volatile LONG Busy;

static DWORD WINAPI DrawThread(PVOID Parameter)
{
    HDC hdcMem = CreateCompatibleDC(hdcShared);
    HBITMAP hbm = CreateCompatibleBitmap(hdcShared, 512, 384);
    ULONG n = 0;

    SelectObject(hdcMem, hbm);
    PatBlt(hdcMem, 0, 0, 512, 384, WHITENESS);
    while (Busy)
    {
        SetStretchBltMode(hdcShared, (n & 1) ? HALFTONE : COLORONCOLOR);
        StretchBlt(hdcShared, 0, 0, 160, 120, hdcMem, n % 32, 0, 500, 350, SRCCOPY);
        Rectangle(hdcShared, n % 40, n % 30, 120, 100);
        n++;
    }
    DeleteDC(hdcMem);
    DeleteObject(hbm);
    return 0;
}

static int Child(const char *Style, const char *EventName)
{
    WNDCLASSA wc = { 0 };
    HWND hwnd;
    HANDLE Thread, Event;
    char ClassName[64];
    MSG msg;

    sprintf(ClassName, "OwnDcDestroy%s%lu", Style, GetCurrentProcessId());
    wc.style = !strcmp(Style, "classdc") ? CS_CLASSDC : CS_OWNDC;
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = ClassName;
    if (!RegisterClassA(&wc))
        return 2;
    hwnd = CreateWindowExA(WS_EX_TOOLWINDOW, ClassName, ClassName, WS_POPUP | WS_VISIBLE,
                           100, 100, 160, 120, NULL, NULL, wc.hInstance, NULL);
    if (!hwnd)
        return 3;
    hdcShared = GetDC(hwnd);
    Busy = 1;
    Thread = CreateThread(NULL, 0, DrawThread, NULL, 0, NULL);
    if (Thread)
        CloseHandle(Thread);
    Sleep(150);
    while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageA(&msg);

    /* The window and its DC go while the other thread draws through the DC */
    DestroyWindow(hwnd);

    /* Terminated by the parent, or ends by itself while that thread still runs */
    Event = OpenEventA(EVENT_MODIFY_STATE, FALSE, EventName);
    if (Event)
    {
        SetEvent(Event);
        Sleep(INFINITE);
    }
    Sleep(50);
    ExitProcess(0);
    return 0;
}

START_TEST(OwnDcDestroy)
{
    char **argv, Self[MAX_PATH], Command[MAX_PATH + 96], EventName[64];
    int argc = winetest_get_mainargs(&argv);
    ULONG i, Ended = 0;
    HWND hwnd;
    HDC hdc;

    if (argc > 4 && !strcmp(argv[2], "child"))
    {
        ExitProcess(Child(argv[3], argv[4]));
        return;
    }

    GetModuleFileNameA(NULL, Self, sizeof(Self));
    for (i = 0; i < CHILDREN; i++)
    {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        BOOL Terminate = (i % 2) == 0;
        HANDLE Event = NULL;
        DWORD Wait;

        if (Terminate)
        {
            sprintf(EventName, "OwnDcDestroy%lu_%lu", GetCurrentProcessId(), i);
            Event = CreateEventA(NULL, TRUE, FALSE, EventName);
        }
        else
        {
            strcpy(EventName, "none");
        }
        sprintf(Command, "\"%s\" OwnDcDestroy child %s %s", Self, (i / 2) % 2 ? "classdc" : "owndc", EventName);
        if (!CreateProcessA(NULL, Command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            skip("CreateProcess failed: %lu\n", GetLastError());
            if (Event)
                CloseHandle(Event);
            continue;
        }
        if (Event)
        {
            ok(WaitForSingleObject(Event, 15000) == WAIT_OBJECT_0, "child %lu did not destroy its window\n", i);
            TerminateProcess(pi.hProcess, 7);
            CloseHandle(Event);
        }
        Wait = WaitForSingleObject(pi.hProcess, 10000);
        ok(Wait == WAIT_OBJECT_0, "child %lu (%s, %s) did not end within 10 s\n", i,
           (i / 2) % 2 ? "class DC" : "own DC", Terminate ? "terminated" : "exited");
        if (Wait == WAIT_OBJECT_0)
            Ended++;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    ok(Ended == CHILDREN, "%lu of %u children ended\n", Ended, CHILDREN);

    /* Window DCs still work */
    hwnd = CreateWindowExA(0, "static", "OwnDcDestroy", WS_POPUP | WS_VISIBLE, 0, 0, 50, 50, NULL, NULL, NULL, NULL);
    hdc = hwnd ? GetDC(hwnd) : NULL;
    ok(hdc != NULL, "GetDC failed after the children\n");
    if (hdc)
    {
        ok(PatBlt(hdc, 0, 0, 50, 50, BLACKNESS), "PatBlt failed after the children\n");
        ReleaseDC(hwnd, hdc);
    }
    if (hwnd)
        DestroyWindow(hwnd);
}
