/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Current-thread WH_GETMESSAGE capture, chaining and message writeback
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Current-thread WH_GETMESSAGE capture, chaining and message writeback. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

static unsigned Checks, Failures, FirstCalls, LastCalls;
static WPARAM Removal;
static HWND Window;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)
#define INPUT_MESSAGE (WM_APP + 40)
#define OUTPUT_MESSAGE (WM_APP + 41)

static LRESULT CALLBACK LastHook(int Code, WPARAM Wparam, LPARAM Lparam)
{
    MSG *Message = (MSG *)Lparam;
    if (Code == HC_ACTION && Message->message == INPUT_MESSAGE)
    {
        ++LastCalls;
        CHECK(Wparam == Removal);
        CHECK(Message->hwnd == Window);
        CHECK(Message->wParam == 0xabcdef01);
        CHECK(Message->lParam == (LPARAM)(LONG)0x81234567);
        Message->message = OUTPUT_MESSAGE;
        Message->wParam = 0xfedcba98;
        Message->lParam = (LPARAM)(LONG)0xf1234567;
        Message->time = 0x99887766;
        Message->pt.x = -123;
        Message->pt.y = 456;
        return -37;
    }
    return CallNextHookEx(NULL, Code, Wparam, Lparam);
}

static LRESULT CALLBACK FirstHook(int Code, WPARAM Wparam, LPARAM Lparam)
{
    MSG *Message = (MSG *)Lparam;
    if (Code == HC_ACTION && Message->message == INPUT_MESSAGE)
    {
        ++FirstCalls;
        CHECK(Wparam == Removal);
        CHECK(Message->hwnd == Window);
        CHECK(Message->wParam == 0x87654321);
        CHECK(Message->lParam == (LPARAM)(LONG)0x81234567);
        Message->wParam = 0xabcdef01;
        CHECK(CallNextHookEx(NULL, Code, Wparam, Lparam) == -37);
        CHECK(Message->message == OUTPUT_MESSAGE);
        CHECK(Message->wParam == 0xfedcba98);
        return -17;
    }
    return CallNextHookEx(NULL, Code, Wparam, Lparam);
}

int main(void)
{
    WNDCLASSW Class = {0};
    HHOOK First, Last;
    struct { DWORD Before; MSG Message; DWORD After; } Buffer;
    unsigned i;
    Class.lpfnWndProc = DefWindowProcW;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"wow64_message_hook";
    CHECK(RegisterClassW(&Class));
    Window = CreateWindowW(Class.lpszClassName, L"message hook", 0,
                           0, 0, 100, 100, NULL, NULL, Class.hInstance, NULL);
    CHECK(Window != NULL);
    Last = SetWindowsHookExW(WH_GETMESSAGE, LastHook, NULL, GetCurrentThreadId());
    First = SetWindowsHookExA(WH_GETMESSAGE, FirstHook, NULL, GetCurrentThreadId());
    CHECK(Last != NULL);
    CHECK(First != NULL);
    if (First && Last)
    {
        CHECK(PostMessageW(Window, INPUT_MESSAGE, 0x87654321, (LPARAM)(LONG)0x81234567));
        for (i = 0; i < 2; ++i)
        {
            Removal = i ? PM_REMOVE : PM_NOREMOVE;
            memset(&Buffer, 0xa5, sizeof(Buffer));
            CHECK(PeekMessageW(&Buffer.Message, Window, INPUT_MESSAGE, INPUT_MESSAGE, Removal));
            CHECK(Buffer.Before == 0xa5a5a5a5 && Buffer.After == 0xa5a5a5a5);
            CHECK(Buffer.Message.hwnd == Window);
            CHECK(Buffer.Message.message == OUTPUT_MESSAGE);
            CHECK(Buffer.Message.wParam == 0xfedcba98);
            CHECK(Buffer.Message.lParam == (LPARAM)(LONG)0xf1234567);
            CHECK(Buffer.Message.time == 0x99887766);
            CHECK(Buffer.Message.pt.x == -123 && Buffer.Message.pt.y == 456);
        }
        CHECK(FirstCalls == 2 && LastCalls == 2);
        CHECK(PostMessageW(Window, INPUT_MESSAGE, 0x87654321, (LPARAM)(LONG)0x81234567));
        CHECK(GetMessageW(&Buffer.Message, Window, INPUT_MESSAGE, INPUT_MESSAGE) > 0);
        CHECK(Buffer.Message.message == OUTPUT_MESSAGE && Buffer.Message.wParam == 0xfedcba98);
        CHECK(Buffer.Before == 0xa5a5a5a5 && Buffer.After == 0xa5a5a5a5);
        CHECK(FirstCalls == 3 && LastCalls == 3);
    }
    if (First) CHECK(UnhookWindowsHookEx(First));
    if (Last) CHECK(UnhookWindowsHookEx(Last));
    CHECK(PostMessageW(Window, INPUT_MESSAGE, 0x87654321, (LPARAM)(LONG)0x81234567));
    CHECK(PeekMessageW(&Buffer.Message, Window, INPUT_MESSAGE, INPUT_MESSAGE, PM_REMOVE));
    CHECK(Buffer.Message.message == INPUT_MESSAGE && Buffer.Message.wParam == 0x87654321);
    CHECK(DestroyWindow(Window));
    CHECK(UnregisterClassW(Class.lpszClassName, Class.hInstance));
    printf("MESSAGE HOOK checks=%u failures=%u first=%u last=%u\n", Checks, Failures, FirstCalls, LastCalls);
    return Failures ? 1 : 0;
}
