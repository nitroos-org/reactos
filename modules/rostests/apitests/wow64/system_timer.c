/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     system_timer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* MSG32 must preserve the identity of kernel-owned caret timers. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static unsigned Checks, Failures, UserCalls;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)
static VOID CALLBACK TimerProc(HWND Window, UINT Message, UINT_PTR Id, DWORD Time) { ++UserCalls; }
static LRESULT CALLBACK WindowProc(HWND Window, UINT Message, WPARAM Wparam, LPARAM Lparam)
{
    return DefWindowProcW(Window, Message, Wparam, Lparam);
}

int main(void)
{
    WNDCLASSW Class = {0};
    HWND Window;
    HDC Dc;
    MSG Message, SystemMessage = {0};
    DWORD Start;
    UINT OldBlink = GetCaretBlinkTime();
    unsigned SystemCalls = 0, PixelChanges = 0, Before;
    COLORREF Pixel = CLR_INVALID;
    BOOL Wow = FALSE;
    Class.lpfnWndProc = WindowProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    Class.lpszClassName = L"wow64_system_timer";
    CHECK(RegisterClassW(&Class));
    Window = CreateWindowW(Class.lpszClassName, L"Caret timer", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           20, 20, 240, 180, NULL, NULL, Class.hInstance, NULL);
    CHECK(Window != NULL);
    UpdateWindow(Window);
    SetFocus(Window);
    Dc = GetDC(Window);
    CHECK(Dc != NULL);
    CHECK(SetCaretBlinkTime(50));
    CHECK(CreateCaret(Window, NULL, 2, 12));
    CHECK(SetCaretPos(10, 10));
    CHECK(ShowCaret(Window));
    CHECK(SetTimer(Window, 77, 70, TimerProc) == 77);
    Start = GetTickCount();
    while (GetTickCount() - Start < 1000)
    {
        while (PeekMessageW(&Message, NULL, 0, 0, PM_REMOVE))
        {
            if (Message.message == 0x118)
            {
                ++SystemCalls;
                SystemMessage = Message;
                Pixel = GetPixel(Dc, 10, 11);
            }
            DispatchMessageW(&Message);
            if (Message.message == 0x118 && Pixel != CLR_INVALID && GetPixel(Dc, 10, 11) != Pixel)
                ++PixelChanges;
        }
        Sleep(5);
    }
    CHECK(SystemCalls >= 2);
    CHECK(PixelChanges >= 2);
    CHECK(UserCalls >= 2);
    CHECK(IsWow64Process(GetCurrentProcess(), &Wow));
    if (SystemCalls)
    {
        /* Keep an unrelated user callback at the tail of the kernel list.
         * A failed system-token lookup must not dispatch that callback. */
        CHECK(SetTimer(Window, 78, 60000, TimerProc) == 78);
        Before = UserCalls;
        DispatchMessageW(&SystemMessage);
        CHECK(UserCalls == Before);
        CHECK(KillTimer(Window, 78));
    }
    if (Wow && SystemCalls)
    {
        Before = UserCalls;
        SystemMessage.lParam = (LPARAM)TimerProc;
        DispatchMessageW(&SystemMessage);
        CHECK(UserCalls == Before);
    }
    CHECK(KillTimer(Window, 77));
    CHECK(HideCaret(Window));
    CHECK(DestroyCaret());
    CHECK(SetCaretBlinkTime(OldBlink));
    ReleaseDC(Window, Dc);
    CHECK(DestroyWindow(Window));
    CHECK(UnregisterClassW(Class.lpszClassName, Class.hInstance));
    printf("SYSTEM TIMER checks=%u failures=%u system=%u user=%u pixels=%u\n", Checks, Failures, SystemCalls, UserCalls, PixelChanges);
    return Failures ? 1 : 0;
}
