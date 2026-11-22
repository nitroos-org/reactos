/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A popup owned by a window of another thread, whose thread ends while the owner's
 *              thread has a message pending for it (activation of the owner, the foreground
 *              switch, SetWindowPos, SendMessage), ends inside its window procedure, or whose
 *              owner is destroyed. Every call must come back, the thread must end and the popup
 *              must be gone. Before the fix win32k kept using the popup after it was freed when
 *              the owner was activated (co_IntSendActivateMessages).
 */

#include "precomp.h"

enum
{
    ROW_SENDEXIT,       /* SendMessage to the popup, its thread ends without reading it */
    ROW_SENDTIMEOUT,    /* the same with SendMessageTimeout */
    ROW_SETPOS,         /* SetWindowPos of the popup from the owner's thread */
    ROW_OWNERDESTROY,   /* the owner is destroyed while the popup is up */
    ROW_ATTACHED,       /* input attached, the popup is active; its thread ends in WM_ACTIVATEAPP */
    ROW_ACTIVATE,       /* SetActiveWindow(owner): the owned popup is brought up with it */
    ROW_FOREGROUND,     /* the popup's thread makes the owner the foreground window */
    ROW_INFLIGHT,       /* the popup's thread ends inside WM_WINDOWPOSCHANGING */
    ROW_COUNT
};

static const char *RowName[ROW_COUNT] =
{
    "sendexit", "sendtimeout", "setpos", "ownerdestroy", "attached", "activate", "foreground", "inflight"
};

static struct
{
    int Row;
    HWND hwndOwner, hwndOther, hwndPopup;
    HANDLE hReady, hArm, hArmed, hDone;
    DWORD tidOwner, tidPopup;
    volatile LONG SawSend, ExitedInProc, Armed;
} g;

static LRESULT CALLBACK OwnedExitWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (g.Armed && GetCurrentThreadId() == g.tidPopup)
    {
        if ((g.Row == ROW_INFLIGHT && msg == WM_WINDOWPOSCHANGING) ||
            (g.Row == ROW_ATTACHED && msg == WM_ACTIVATEAPP && !wParam))
        {
            InterlockedExchange(&g.ExitedInProc, 1);
            ExitThread(0);
        }
    }
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

/* Waits for hObject while it reads the messages of the thread */
static BOOL WaitPump(HANDLE hObject, DWORD dwMilliseconds)
{
    DWORD dwStart = GetTickCount();

    for (;;)
    {
        DWORD dwElapsed = GetTickCount() - dwStart, dwRet;

        if (dwElapsed >= dwMilliseconds)
            return WaitForSingleObject(hObject, 0) == WAIT_OBJECT_0;
        dwRet = MsgWaitForMultipleObjects(1, &hObject, FALSE, dwMilliseconds - dwElapsed, QS_ALLINPUT);
        if (dwRet == WAIT_OBJECT_0)
            return TRUE;
        Pump();
    }
}

static DWORD WINAPI PopupThread(LPVOID lpParam)
{
    DWORD i;

    UNREFERENCED_PARAMETER(lpParam);

    g.hwndPopup = CreateWindowExW(0, L"OwnedExitClass", L"popup", WS_POPUP | WS_CAPTION, 200, 200, 200, 120,
                                  g.hwndOwner, NULL, GetModuleHandleW(NULL), NULL);
    if (!g.hwndPopup)
    {
        SetEvent(g.hReady);
        return 1;
    }
    if (g.Row == ROW_ATTACHED)
        AttachThreadInput(GetCurrentThreadId(), g.tidOwner, TRUE);
    ShowWindow(g.hwndPopup, (g.Row == ROW_ATTACHED) ? SW_SHOW : SW_SHOWNOACTIVATE);
    SetEvent(g.hReady);

    WaitPump(g.hArm, 10000);
    if (g.Row == ROW_ATTACHED)
        SetActiveWindow(g.hwndPopup);
    Pump();
    InterlockedExchange(&g.Armed, 1);
    if (g.Row == ROW_FOREGROUND)
        SetForegroundWindow(g.hwndOwner);
    SetEvent(g.hArmed);

    if (g.Row == ROW_INFLIGHT || g.Row == ROW_ATTACHED || g.Row == ROW_OWNERDESTROY)
    {
        /* Reads its messages: the window procedure ends the thread, or the owner's thread is done */
        WaitPump(g.hDone, 10000);
        return 0;
    }

    /* Waits until a message is sent to it, without reading it, then ends with the message unread */
    for (i = 0; i < 3000; i++)
    {
        if (GetQueueStatus(QS_SENDMESSAGE) & ((QS_SENDMESSAGE << 16) | QS_SENDMESSAGE))
        {
            InterlockedExchange(&g.SawSend, 1);
            break;
        }
        if (WaitForSingleObject(g.hDone, 1) == WAIT_OBJECT_0)
            break;
    }
    return 0;
}

static void RunRow(int Row)
{
    HANDLE hThread;
    BOOL bEnded;
    LRESULT lResult = 0;
    DWORD_PTR dwResult = 0;

    ZeroMemory(&g, sizeof(g));
    g.Row = Row;
    g.tidOwner = GetCurrentThreadId();
    g.hReady = CreateEventW(NULL, TRUE, FALSE, NULL);
    g.hArm = CreateEventW(NULL, TRUE, FALSE, NULL);
    g.hArmed = CreateEventW(NULL, TRUE, FALSE, NULL);
    g.hDone = CreateEventW(NULL, TRUE, FALSE, NULL);
    g.hwndOwner = CreateWindowExW(0, L"OwnedExitClass", L"owner", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                  100, 100, 300, 200, NULL, NULL, GetModuleHandleW(NULL), NULL);
    g.hwndOther = CreateWindowExW(0, L"OwnedExitClass", L"other", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                  150, 150, 300, 200, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(g.hwndOwner != NULL && g.hwndOther != NULL, "%s: CreateWindowEx failed\n", RowName[Row]);

    hThread = CreateThread(NULL, 0, PopupThread, NULL, 0, &g.tidPopup);
    ok(hThread != NULL, "%s: CreateThread failed\n", RowName[Row]);
    if (!hThread)
        goto Cleanup;
    WaitPump(g.hReady, 10000);
    ok(g.hwndPopup != NULL, "%s: no popup\n", RowName[Row]);
    if (!g.hwndPopup)
    {
        SetEvent(g.hArm);
        SetEvent(g.hDone);
        WaitPump(hThread, 10000);
        CloseHandle(hThread);
        goto Cleanup;
    }
    ok(GetWindow(g.hwndPopup, GW_OWNER) == g.hwndOwner, "%s: owner %p\n", RowName[Row], GetWindow(g.hwndPopup, GW_OWNER));

    /* The owner is not the active window */
    Pump();
    SetActiveWindow(g.hwndOther);
    Pump();
    SetEvent(g.hArm);
    WaitPump(g.hArmed, 10000);

    switch (Row)
    {
        case ROW_ACTIVATE:
        case ROW_INFLIGHT:
        case ROW_ATTACHED:
            SetActiveWindow(g.hwndOwner);
            break;
        case ROW_FOREGROUND:
            /* The activation comes to this thread as an event; WaitPump below reads it */
            break;
        case ROW_SETPOS:
            SetWindowPos(g.hwndPopup, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            break;
        case ROW_OWNERDESTROY:
            ok(DestroyWindow(g.hwndOwner), "%s: DestroyWindow failed\n", RowName[Row]);
            g.hwndOwner = NULL;
            break;
        case ROW_SENDEXIT:
            lResult = SendMessageW(g.hwndPopup, WM_APP + 1, 0, 0);
            break;
        case ROW_SENDTIMEOUT:
            lResult = SendMessageTimeoutW(g.hwndPopup, WM_APP + 1, 0, 0, SMTO_NORMAL, 8000, &dwResult);
            break;
    }
    /* (foreground: the popup's thread waits for the send that the activation event of this thread causes) */
    if (Row != ROW_FOREGROUND)
        SetEvent(g.hDone);

    bEnded = WaitPump(hThread, 15000);
    SetEvent(g.hDone);
    Pump();
    ok(bEnded, "%s: the popup's thread did not end\n", RowName[Row]);
    if (bEnded)
        ok(!IsWindow(g.hwndPopup), "%s: the popup of the ended thread is still a window\n", RowName[Row]);
    if (g.hwndOwner)
        ok(IsWindow(g.hwndOwner), "%s: the owner is gone\n", RowName[Row]);
    if (Row == ROW_ACTIVATE || Row == ROW_INFLIGHT)
        ok(GetActiveWindow() == g.hwndOwner, "%s: active window %p, expected the owner %p\n",
           RowName[Row], GetActiveWindow(), g.hwndOwner);
    trace("%s: send seen %ld, ended in the window procedure %ld, result %Id/%Iu\n",
          RowName[Row], g.SawSend, g.ExitedInProc, lResult, dwResult);

    if (!bEnded)
    {
        TerminateThread(hThread, 1);
        WaitForSingleObject(hThread, 5000);
    }
    CloseHandle(hThread);

Cleanup:
    if (g.hwndOwner)
        DestroyWindow(g.hwndOwner);
    if (g.hwndOther)
        DestroyWindow(g.hwndOther);
    Pump();
    CloseHandle(g.hReady);
    CloseHandle(g.hArm);
    CloseHandle(g.hArmed);
    CloseHandle(g.hDone);
}

START_TEST(OwnedWindowThreadExit)
{
    WNDCLASSW wc;
    int Row, Round;

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = OwnedExitWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"OwnedExitClass";
    ok(RegisterClassW(&wc) != 0, "RegisterClass failed\n");

    for (Round = 0; Round < 3; Round++)
    {
        for (Row = 0; Row < ROW_COUNT; Row++)
            RunRow(Row);
    }

    UnregisterClassW(L"OwnedExitClass", GetModuleHandleW(NULL));
}
