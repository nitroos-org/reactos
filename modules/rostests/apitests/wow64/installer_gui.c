/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Font offsets and input contexts exercised by installed GUI applications
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Font offsets and input contexts exercised by installed GUI applications. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <imm.h>
#include <stdio.h>

static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)
static UINT MonitorCount;
static BOOL CALLBACK MonitorProc(HMONITOR Monitor, HDC Dc, LPRECT Rect, LPARAM Cookie)
{
    MONITORINFO Info = {sizeof(Info)};
    ++MonitorCount;
    CHECK(Cookie == (LPARAM)(LONG)0x87654321);
    CHECK(Dc == NULL);
    CHECK(GetMonitorInfoW(Monitor, &Info));
    CHECK(EqualRect(Rect, &Info.rcMonitor));
    CHECK(Rect->right > Rect->left && Rect->bottom > Rect->top);
    return TRUE;
}
static UINT HookCalls, ReturnCalls;
static HWND HookWindow;

static LRESULT CALLBACK MessageHook(int Code, WPARAM Wparam, LPARAM Lparam)
{
    const CWPSTRUCT *Message = (PVOID)Lparam;
    if (Code == HC_ACTION && Message->hwnd == HookWindow)
    {
        if (Message->message == WM_APP + 7)
        {
            ++HookCalls;
            CHECK(Message->wParam == 0x87654321);
            CHECK(Message->lParam == (LPARAM)(LONG)0x81234567);
        }
        else if (Message->message == WM_SETTEXT)
        {
            ++HookCalls;
            CHECK(!wcscmp((PCWSTR)Message->lParam, L"hook payload"));
        }
    }
    return CallNextHookEx(NULL, Code, Wparam, Lparam);
}

static LRESULT CALLBACK ReturnHook(int Code, WPARAM Wparam, LPARAM Lparam)
{
    const CWPRETSTRUCT *Message = (PVOID)Lparam;
    if (Code == HC_ACTION && Message->hwnd == HookWindow && Message->message == WM_APP + 7)
    {
        ++ReturnCalls;
        CHECK(Message->wParam == 0x87654321);
        CHECK(Message->lParam == (LPARAM)(LONG)0x81234567);
        CHECK(Message->lResult == -17);
    }
    return CallNextHookEx(NULL, Code, Wparam, Lparam);
}

static LRESULT CALLBACK HookWindowProc(HWND Window, UINT Msg, WPARAM Wparam, LPARAM Lparam)
{
    if (Msg == WM_APP + 7) return -17;
    return DefWindowProcW(Window, Msg, Wparam, Lparam);
}

static void TestHooks(void)
{
    WNDCLASSW Class = {0};
    HHOOK Hook, After;
    Class.lpfnWndProc = HookWindowProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"wow64_installer_hook";
    CHECK(RegisterClassW(&Class));
    HookWindow = CreateWindowW(Class.lpszClassName, L"before", WS_OVERLAPPEDWINDOW,
                               0, 0, 100, 100, NULL, NULL, Class.hInstance, NULL);
    CHECK(HookWindow != NULL);
    Hook = SetWindowsHookExW(WH_CALLWNDPROC, MessageHook, NULL, GetCurrentThreadId());
    After = SetWindowsHookExW(WH_CALLWNDPROCRET, ReturnHook, NULL, GetCurrentThreadId());
    CHECK(Hook != NULL);
    CHECK(After != NULL);
    CHECK(SendMessageW(HookWindow, WM_APP + 7, 0x87654321, (LPARAM)(LONG)0x81234567) == -17);
    CHECK(SetWindowTextW(HookWindow, L"hook payload"));
    CHECK(HookCalls == 2);
    CHECK(ReturnCalls == 1);
    if (Hook) CHECK(UnhookWindowsHookEx(Hook));
    if (After) CHECK(UnhookWindowsHookEx(After));
    SendMessageW(HookWindow, WM_APP + 7, 0x87654321, (LPARAM)(LONG)0x81234567);
    CHECK(HookCalls == 2 && ReturnCalls == 1);
    DestroyWindow(HookWindow);
    CHECK(UnregisterClassW(Class.lpszClassName, Class.hInstance));
}

BOOL WINAPI ImmGetHotKey(DWORD Id, LPUINT Modifiers, LPUINT Key, LPHKL Layout);
BOOL WINAPI ImmSetHotKey(DWORD Id, UINT Modifiers, UINT Key, HKL Layout);

#define GUARD_HOTKEY (IME_HOTKEY_PRIVATE_FIRST + 0x1d)
#define GUARD_MODIFIERS (MOD_LEFT | MOD_ALT | MOD_CONTROL | MOD_SHIFT)

/* Out-params on a not-yet-touched stack guard page must grow the stack, as the kernel probe does. */
static DWORD WINAPI GuardHotKeyThread(PVOID Unused)
{
    MEMORY_BASIC_INFORMATION Info;
    BYTE *Limit = ((NT_TIB *)NtCurrentTeb())->StackLimit, *Guard = Limit - 0x1000, *Here = (BYTE *)&Info;
    UINT *Out = (UINT *)(Guard + 0x800), Modifiers, Key;
    HKL Layout;
    BOOL Ret;
    (void)Unused;
    /* Without a wide margin the call frames could reach the guard page before the service probes it. */
    if (Here - Limit < 0x8000 || !VirtualQuery(Guard, &Info, sizeof(Info)) || !(Info.Protect & PAGE_GUARD))
    {
        printf("FAIL guard hotkey prerequisite: limit=%p here=%p\n", Limit, Here);
        return 2;
    }
    Ret = ImmGetHotKey(GUARD_HOTKEY, &Out[0], &Out[1], (LPHKL)&Out[2]);
    Modifiers = Out[0]; Key = Out[1]; Layout = *(HKL *)&Out[2];
    CHECK(Ret);
    CHECK(Modifiers == GUARD_MODIFIERS && Key == VK_F24 && Layout == NULL);
    CHECK(VirtualQuery(Guard, &Info, sizeof(Info)) && !(Info.Protect & PAGE_GUARD));
    CHECK(((NT_TIB *)NtCurrentTeb())->StackLimit <= (PVOID)Guard);
    return 0;
}

static void TestGuardHotKey(void)
{
    UINT Modifiers = 0, Key = 0, OldModifiers = 0, OldKey = 0;
    HKL Layout = (HKL)1, OldLayout = NULL;
    HANDLE Thread;
    DWORD Code = 1;
    /* The ID may already be bound in this profile; put that binding back afterwards. */
    BOOL Had = ImmGetHotKey(GUARD_HOTKEY, &OldModifiers, &OldKey, &OldLayout);
    BOOL Set = ImmSetHotKey(GUARD_HOTKEY, GUARD_MODIFIERS, VK_F24, NULL);
    CHECK(Set);
    if (!Set) return;
    CHECK(ImmGetHotKey(GUARD_HOTKEY, &Modifiers, &Key, &Layout));
    CHECK(Modifiers == GUARD_MODIFIERS && Key == VK_F24 && Layout == NULL);
    /* A committed size well above the margin keeps the guard page away from the call frames. */
    Thread = CreateThread(NULL, 0x40000, GuardHotKeyThread, NULL, 0, NULL);
    CHECK(Thread != NULL);
    if (Thread)
    {
        CHECK(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0);
        /* An unusable stack layout is a failed prerequisite, not a pass. */
        CHECK(GetExitCodeThread(Thread, &Code) && Code == 0);
        CloseHandle(Thread);
    }
    if (Had && OldKey) CHECK(ImmSetHotKey(GUARD_HOTKEY, OldModifiers, OldKey, OldLayout));
    else CHECK(ImmSetHotKey(GUARD_HOTKEY, 0, 0, NULL));
}

int main(void)
{
    HDC Dc = CreateCompatibleDC(NULL);
    HFONT Font = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, 0, 0, 0, 0, L"Arial");
    HGDIOBJ Old;
    OUTLINETEXTMETRICW *Metrics;
    UINT Size, i, j;
    BYTE *Bytes;
    HWND Window;
    HIMC Context;
    HDESK Desktop;
    WCHAR DesktopName[128];
    DWORD Needed;
    Desktop = GetThreadDesktop(GetCurrentThreadId());
    CHECK(Desktop != NULL);
    if (Desktop)
    {
        CHECK(GetUserObjectInformationW(Desktop, UOI_NAME, DesktopName, sizeof(DesktopName), &Needed));
        CHECK(DesktopName[0] != 0 && Needed <= sizeof(DesktopName));
    }
    CHECK(Dc && Font);
    if (Dc && Font)
    {
        Old = SelectObject(Dc, Font);
        Size = GetOutlineTextMetricsW(Dc, 0, NULL);
        CHECK(Size > sizeof(*Metrics));
        if (Size > sizeof(*Metrics) && Size < 65536)
        {
            Bytes = HeapAlloc(GetProcessHeap(), 0, Size + 16);
            memset(Bytes, 0xa5, Size + 16);
            Metrics = (PVOID)Bytes;
            CHECK(GetOutlineTextMetricsW(Dc, Size, Metrics) == Size);
            CHECK(Metrics->otmSize == Size);
            CHECK(Metrics->otmEMSquare > 0 && Metrics->otmTextMetrics.tmHeight > 0);
            for (i = 0; i < 4; ++i)
            {
                ULONG_PTR Offset = (ULONG_PTR)(&Metrics->otmpFamilyName)[i];
                CHECK(Offset >= sizeof(*Metrics) && Offset < Size && !(Offset & 1));
                if (Offset < Size)
                {
                    for (j = Offset; j + sizeof(WCHAR) <= Size; j += sizeof(WCHAR))
                        if (!*(WCHAR *)(Bytes + j)) break;
                    CHECK(j + sizeof(WCHAR) <= Size);
                }
            }
            for (i = Size; i < Size + 16; ++i) CHECK(Bytes[i] == 0xa5);
            HeapFree(GetProcessHeap(), 0, Bytes);
        }
        SelectObject(Dc, Old);
    }
    if (Font) DeleteObject(Font);
    if (Dc) DeleteDC(Dc);

    Window = CreateWindowExW(0, L"EDIT", L"input context", WS_OVERLAPPEDWINDOW,
                              0, 0, 240, 120, NULL, NULL, GetModuleHandleW(NULL), NULL);
    CHECK(Window != NULL);
    if (Window)
    {
        Context = ImmGetContext(Window);
        CHECK(Context != NULL);
        if (Context) CHECK(ImmReleaseContext(Window, Context));
        Context = ImmCreateContext();
        CHECK(Context != NULL);
        if (Context) CHECK(ImmDestroyContext(Context));
        DestroyWindow(Window);
    }
    TestHooks();
    TestGuardHotKey();
    CHECK(EnumDisplayMonitors(NULL, NULL, MonitorProc, (LPARAM)(LONG)0x87654321));
    CHECK(MonitorCount > 0);
    printf("INSTALLER GUI checks=%u failures=%u\n", Checks, Failures);
    return Failures ? 1 : 0;
}
