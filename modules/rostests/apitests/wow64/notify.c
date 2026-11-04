/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     notify
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Opaque NMHDR extensions must survive current-thread CALLWND hooks. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

static unsigned Checks, Failures, Notices, BeforeCalls, AfterCalls;
static HWND Window;
static struct { NMHDR Header; const char *Text; DWORD Reply, Tail; } Notice;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)

static void CheckNotice(LPARAM Param)
{
    CHECK(Param == (LPARAM)&Notice);
    if (Param != (LPARAM)&Notice) return;
    CHECK(Notice.Header.hwndFrom == Window);
    CHECK(Notice.Header.idFrom == (UINT_PTR)0xfedcba98);
    CHECK(Notice.Header.code == (UINT)-200);
    CHECK(!strcmp(Notice.Text, "guest notification"));
    CHECK(Notice.Tail == 0x87654321);
}

static LRESULT CALLBACK WindowProc(HWND Wnd, UINT Msg, WPARAM Wparam, LPARAM Lparam)
{
    if (Msg == WM_NOTIFY)
    {
        ++Notices;
        CHECK(Wparam == (WPARAM)0xfedcba98);
        CheckNotice(Lparam);
        if (Lparam == (LPARAM)&Notice) Notice.Reply = 0xaabbccdd;
        return -57;
    }
    return DefWindowProcW(Wnd, Msg, Wparam, Lparam);
}

static LRESULT CALLBACK Before(int Code, WPARAM Wparam, LPARAM Lparam)
{
    const CWPSTRUCT *Message = (const CWPSTRUCT *)Lparam;
    if (Code == HC_ACTION && Message->hwnd == Window && Message->message == WM_NOTIFY)
    {
        ++BeforeCalls;
        CHECK(Message->wParam == (WPARAM)0xfedcba98);
        CheckNotice(Message->lParam);
    }
    return CallNextHookEx(NULL, Code, Wparam, Lparam);
}

static LRESULT CALLBACK After(int Code, WPARAM Wparam, LPARAM Lparam)
{
    const CWPRETSTRUCT *Message = (const CWPRETSTRUCT *)Lparam;
    if (Code == HC_ACTION && Message->hwnd == Window && Message->message == WM_NOTIFY)
    {
        ++AfterCalls;
        CHECK(Message->lResult == -57);
        CheckNotice(Message->lParam);
    }
    return CallNextHookEx(NULL, Code, Wparam, Lparam);
}

int main(void)
{
    WNDCLASSW Class = {0};
    HHOOK First, Last;
    Class.lpfnWndProc = WindowProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"wow64_notify";
    CHECK(RegisterClassW(&Class));
    Window = CreateWindowW(Class.lpszClassName, L"notify", 0, 0, 0, 100, 100,
                           NULL, NULL, Class.hInstance, NULL);
    CHECK(Window != NULL);
    Notice.Header.hwndFrom = Window;
    Notice.Header.idFrom = 0xfedcba98;
    Notice.Header.code = (UINT)-200;
    Notice.Text = "guest notification";
    Notice.Tail = 0x87654321;
    CHECK(SendMessageW(Window, WM_NOTIFY, Notice.Header.idFrom, (LPARAM)&Notice) == -57);
    CHECK(Notices == 1 && Notice.Reply == 0xaabbccdd);
    Notice.Reply = 0;
    First = SetWindowsHookExW(WH_CALLWNDPROC, Before, NULL, GetCurrentThreadId());
    Last = SetWindowsHookExW(WH_CALLWNDPROCRET, After, NULL, GetCurrentThreadId());
    CHECK(First != NULL && Last != NULL);
    CHECK(SendMessageA(Window, WM_NOTIFY, Notice.Header.idFrom, (LPARAM)&Notice) == -57);
    CHECK(Notices == 2 && BeforeCalls == 1 && AfterCalls == 1);
    CHECK(Notice.Reply == 0xaabbccdd);
    if (First) CHECK(UnhookWindowsHookEx(First));
    if (Last) CHECK(UnhookWindowsHookEx(Last));
    CHECK(DestroyWindow(Window));
    CHECK(UnregisterClassW(Class.lpszClassName, Class.hInstance));
    printf("NOTIFY checks=%u failures=%u notices=%u before=%u after=%u\n", Checks, Failures, Notices, BeforeCalls, AfterCalls);
    return Failures ? 1 : 0;
}
