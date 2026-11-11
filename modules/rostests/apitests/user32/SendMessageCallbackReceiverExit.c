/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         The receiver of a SendMessageCallback exits while the callback runs on the sender
 */

#include "precomp.h"

static const WCHAR g_class[] = L"CallbackReceiverExitClass";
static HWND g_hwndReceiver;
static HANDLE g_ready, g_exit, g_receiverThread;
static LONG g_callbacks;

static LRESULT CALLBACK ReceiverProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI ReceiverThread(LPVOID arg)
{
    MSG msg;
    DWORD ret;

    g_hwndReceiver = CreateWindowExW(0, g_class, L"receiver", 0, 0, 0, 10, 10, NULL, NULL, GetModuleHandleW(NULL), NULL);
    SetEvent(g_ready);
    for (;;)
    {
        ret = MsgWaitForMultipleObjects(1, &g_exit, FALSE, INFINITE, QS_ALLINPUT);
        if (ret == WAIT_OBJECT_0)
            break;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    }
    return 0;
}

/* The receiver thread exits while this callback runs: its cleanup must not free the message
   that the dispatch of the callback still holds (a second free crashed the system) */
static void CALLBACK ResultCallback(HWND hwnd, UINT msg, ULONG_PTR data, LRESULT result)
{
    InterlockedIncrement(&g_callbacks);
    SetEvent(g_exit);
    ok(WaitForSingleObject(g_receiverThread, 5000) == WAIT_OBJECT_0, "the receiver did not exit\n");
    Sleep(50);
}

START_TEST(SendMessageCallbackReceiverExit)
{
    WNDCLASSW wc = {0};
    MSG msg;
    int i;

    wc.lpfnWndProc = ReceiverProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = g_class;
    ok(RegisterClassW(&wc) != 0, "RegisterClass failed: %lu\n", GetLastError());

    g_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_exit = CreateEventW(NULL, TRUE, FALSE, NULL);

    for (i = 0; i < 10; i++)
    {
        DWORD start;

        ResetEvent(g_ready);
        ResetEvent(g_exit);
        g_receiverThread = CreateThread(NULL, 0, ReceiverThread, NULL, 0, NULL);
        ok(WaitForSingleObject(g_ready, 5000) == WAIT_OBJECT_0, "the receiver did not start\n");

        ok(SendMessageCallbackW(g_hwndReceiver, WM_USER, 0, 0, ResultCallback, 0),
           "SendMessageCallback failed: %lu\n", GetLastError());

        /* the callback runs when this thread dispatches messages */
        start = GetTickCount();
        while (g_callbacks <= i && GetTickCount() - start < 3000)
        {
            if (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
                DispatchMessageW(&msg);
            else
                Sleep(1);
        }
        ok(g_callbacks == i + 1, "round %d: %ld callbacks\n", i, g_callbacks);

        WaitForSingleObject(g_receiverThread, 5000);
        CloseHandle(g_receiverThread);
    }

    CloseHandle(g_ready);
    CloseHandle(g_exit);
    UnregisterClassW(g_class, GetModuleHandleW(NULL));
}
