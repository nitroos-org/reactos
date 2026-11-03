/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Desktop window APIs and window classes of threads on a desktop that is not the input desktop
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * "The desktop window" (NULL parent, top-level tests, EnumWindows, HWND_MESSAGE) means the
 * desktop of the calling thread or of the window, not the desktop on the screen. ReactOS used
 * the input desktop: from a thread on another desktop EnumWindows listed the input desktop,
 * SetParent(hwnd, NULL) linked the window into the input desktop's window list,
 * SetWindowLongPtr(GWLP_HWNDPARENT) re-parented a top-level window instead of setting its owner,
 * FindWindowEx(HWND_MESSAGE) did not find the thread's message-only windows.
 * The second part creates windows of one class (BUTTON, own class) on two desktops from one
 * process and lets the thread that holds the class base leave its desktop while the copy on
 * the other desktop is in use (win32k asserted pclsClone == NULL; the clones were left with
 * a freed base).
 */

#include "precomp.h"

static const CHAR g_ClassName[] = "DesktopOtherThreadApisClass";
static HWND g_hTop, g_hChild, g_hOwned, g_hMsg, g_hChild2, g_hTray, g_hProgman;
static BOOL g_SeenTop, g_SeenShell, g_SeenChild;
static HANDLE g_hReady, g_hGo;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lParam)
{
    if (hwnd == g_hTop) g_SeenTop = TRUE;
    if (hwnd == g_hChild) g_SeenChild = TRUE;
    if ((g_hTray && hwnd == g_hTray) || (g_hProgman && hwnd == g_hProgman)) g_SeenShell = TRUE;
    return TRUE;
}

static BOOL CALLBACK EnumThreadProc(HWND hwnd, LPARAM lParam)
{
    if (hwnd == g_hTop) *(BOOL *)lParam = TRUE;
    return TRUE;
}

static DWORD WINAPI ApiThread(LPVOID Param)
{
    HWND hDesk, hOld;

    if (!SetThreadDesktop((HDESK)Param))
    {
        skip("SetThreadDesktop failed (%lu)\n", GetLastError());
        SetEvent(g_hReady);
        return 1;
    }
    g_hTop = CreateWindowExA(0, g_ClassName, "top", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, NULL, NULL);
    g_hChild = CreateWindowExA(0, g_ClassName, "child", WS_CHILD, 0, 0, 10, 10, g_hTop, NULL, NULL, NULL);
    g_hOwned = CreateWindowExA(0, g_ClassName, "owned", WS_POPUP, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    g_hMsg = CreateWindowExA(0, g_ClassName, "msgonly", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
    g_hChild2 = CreateWindowExA(0, g_ClassName, "child2", WS_CHILD, 0, 0, 10, 10, g_hTop, NULL, NULL, NULL);
    ok(g_hTop && g_hChild && g_hOwned && g_hMsg && g_hChild2, "CreateWindowEx failed (%lu)\n", GetLastError());
    hDesk = GetDesktopWindow();

    g_SeenTop = g_SeenShell = g_SeenChild = FALSE;
    EnumWindows(EnumProc, 0);
    ok(g_SeenTop, "EnumWindows did not list the window of the thread's desktop\n");
    ok(!g_SeenShell, "EnumWindows listed a window of the input desktop\n");

    SetEvent(g_hReady);
    WaitForSingleObject(g_hGo, 30000);

    hOld = SetParent(g_hChild, NULL);
    ok(hOld == g_hTop, "SetParent returned %p, expected %p\n", hOld, g_hTop);
    ok(GetAncestor(g_hChild, GA_PARENT) == hDesk, "parent %p, expected the desktop window %p\n",
       GetAncestor(g_hChild, GA_PARENT), hDesk);

    SetWindowLongPtrA(g_hOwned, GWLP_HWNDPARENT, (LONG_PTR)g_hTop);
    ok(GetWindow(g_hOwned, GW_OWNER) == g_hTop, "owner %p, expected %p\n", GetWindow(g_hOwned, GW_OWNER), g_hTop);
    ok(GetAncestor(g_hOwned, GA_PARENT) == hDesk, "parent %p, expected the desktop window %p\n",
       GetAncestor(g_hOwned, GA_PARENT), hDesk);

    ok(FindWindowExA(HWND_MESSAGE, NULL, g_ClassName, "msgonly") == g_hMsg,
       "FindWindowEx(HWND_MESSAGE) did not find the message-only window of the thread's desktop\n");
    SetParent(g_hChild2, HWND_MESSAGE);
    ok(FindWindowExA(HWND_MESSAGE, NULL, g_ClassName, "child2") == g_hChild2,
       "SetParent(HWND_MESSAGE) did not make the window message-only on the thread's desktop\n");

    DestroyWindow(g_hChild2);
    DestroyWindow(g_hMsg);
    DestroyWindow(g_hOwned);
    DestroyWindow(g_hChild);
    DestroyWindow(g_hTop);
    return 0;
}

static void Test_DesktopApis(void)
{
    HDESK hDesk;
    HANDLE hThread;
    BOOL Found = FALSE;

    g_hTray = FindWindowA("Shell_TrayWnd", NULL);
    g_hProgman = FindWindowA("Progman", NULL);
    hDesk = CreateDesktopA("DesktopOtherThreadApis", NULL, NULL, 0, GENERIC_ALL, NULL);
    if (!hDesk)
    {
        skip("CreateDesktop failed (%lu)\n", GetLastError());
        return;
    }
    g_hReady = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_hGo = CreateEventA(NULL, TRUE, FALSE, NULL);
    hThread = CreateThread(NULL, 0, ApiThread, hDesk, 0, NULL);
    WaitForSingleObject(g_hReady, 30000);
    EnumThreadWindows(GetThreadId(hThread), EnumThreadProc, (LPARAM)&Found);
    ok(Found, "EnumThreadWindows did not find the window of a thread on another desktop\n");
    SetEvent(g_hGo);
    ok(WaitForSingleObject(hThread, 30000) == WAIT_OBJECT_0, "thread hung\n");
    CloseHandle(hThread);
    CloseHandle(g_hReady);
    CloseHandle(g_hGo);
    CloseDesktop(hDesk);
}

/* Class part: a helper on hDesk creates a BUTTON and a window of the own class, checks them,
   optionally destroys them right away, then waits for g_hGo before using them again and exiting */
typedef struct _CLS_HELPER
{
    HDESK hDesk;
    BOOL bDestroyFirst;
    HANDLE hReady, hGo;
} CLS_HELPER;

static void CheckButton(HWND hButton)
{
    CHAR Text[16] = "";

    SendMessageA(hButton, BM_SETCHECK, BST_CHECKED, 0);
    ok(SendMessageA(hButton, BM_GETCHECK, 0, 0) == BST_CHECKED, "BM_GETCHECK failed\n");
    SetWindowTextA(hButton, "xyz");
    GetWindowTextA(hButton, Text, sizeof(Text));
    ok(!strcmp(Text, "xyz"), "text '%s'\n", Text);
}

static DWORD WINAPI ClassThread(LPVOID Param)
{
    CLS_HELPER *h = Param;
    HWND hButton = NULL, hOwn = NULL;

    if (h->hDesk && !SetThreadDesktop(h->hDesk))
    {
        ok(0, "SetThreadDesktop failed (%lu)\n", GetLastError());
        SetEvent(h->hReady);
        return 1;
    }
    hButton = CreateWindowExA(0, "BUTTON", "b", WS_POPUP | BS_AUTOCHECKBOX, 0, 0, 50, 20, NULL, NULL, NULL, NULL);
    hOwn = CreateWindowExA(0, g_ClassName, "o", WS_POPUP, 0, 0, 50, 20, NULL, NULL, NULL, NULL);
    ok(hButton && hOwn, "CreateWindowEx failed (%lu)\n", GetLastError());
    if (hButton)
        CheckButton(hButton);
    if (h->bDestroyFirst)
    {
        DestroyWindow(hButton);
        DestroyWindow(hOwn);
        hButton = hOwn = NULL;
    }
    SetEvent(h->hReady);
    WaitForSingleObject(h->hGo, 30000);
    if (hButton)
    {
        CheckButton(hButton);
        DestroyWindow(hButton);
    }
    if (hOwn)
        DestroyWindow(hOwn);
    return 0;
}

static HANDLE StartClassThread(CLS_HELPER *h, HDESK hDesk, BOOL bDestroyFirst)
{
    h->hDesk = hDesk;
    h->bDestroyFirst = bDestroyFirst;
    h->hReady = CreateEventA(NULL, TRUE, FALSE, NULL);
    h->hGo = CreateEventA(NULL, TRUE, FALSE, NULL);
    return CreateThread(NULL, 0, ClassThread, h, 0, NULL);
}

static void FinishClassThread(CLS_HELPER *h, HANDLE hThread)
{
    SetEvent(h->hGo);
    ok(WaitForSingleObject(hThread, 30000) == WAIT_OBJECT_0, "class thread hung\n");
    CloseHandle(hThread);
    CloseHandle(h->hReady);
    CloseHandle(h->hGo);
}

static void Test_ClassOnTwoDesktops(void)
{
    UINT i;

    for (i = 0; i < 10; i++)
    {
        HDESK hDesk1, hDesk2;
        CLS_HELPER h1, h2, h3;
        HANDLE t1, t2, t3;

        hDesk1 = CreateDesktopA("DesktopOtherThreadApis1", NULL, NULL, 0, GENERIC_ALL, NULL);
        hDesk2 = CreateDesktopA("DesktopOtherThreadApis2", NULL, NULL, 0, GENERIC_ALL, NULL);
        if (!hDesk1 || !hDesk2)
        {
            skip("CreateDesktop failed (%lu)\n", GetLastError());
            if (hDesk1) CloseDesktop(hDesk1);
            if (hDesk2) CloseDesktop(hDesk2);
            return;
        }

        /* The base of the class ends up on desktop 1 without a window, a copy on desktop 2
           is in use, then the thread on desktop 1 leaves it */
        t1 = StartClassThread(&h1, hDesk1, TRUE);
        WaitForSingleObject(h1.hReady, 30000);
        t2 = StartClassThread(&h2, hDesk2, FALSE);
        WaitForSingleObject(h2.hReady, 30000);
        FinishClassThread(&h1, t1);
        FinishClassThread(&h2, t2);

        /* Windows of the class on three desktops at once, released in turn */
        t1 = StartClassThread(&h1, hDesk1, FALSE);
        t2 = StartClassThread(&h2, hDesk2, FALSE);
        t3 = StartClassThread(&h3, NULL, FALSE);
        WaitForSingleObject(h1.hReady, 30000);
        WaitForSingleObject(h2.hReady, 30000);
        WaitForSingleObject(h3.hReady, 30000);
        FinishClassThread(&h3, t3);
        FinishClassThread(&h1, t1);
        FinishClassThread(&h2, t2);

        CloseDesktop(hDesk1);
        CloseDesktop(hDesk2);
    }
}

START_TEST(DesktopOtherThreadApis)
{
    WNDCLASSA wc = { 0 };

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = g_ClassName;
    if (!RegisterClassA(&wc))
    {
        skip("RegisterClass failed (%lu)\n", GetLastError());
        return;
    }

    Test_DesktopApis();
    Test_ClassOnTwoDesktops();

    UnregisterClassA(g_ClassName, GetModuleHandleA(NULL));
}
