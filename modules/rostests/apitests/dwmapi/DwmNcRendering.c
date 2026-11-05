/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DWMWA_NCRENDERING_POLICY and WM_DWMNCRENDERINGCHANGED
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <dwmapi.h>

/*
 * Measured on Windows 10 22H2 (interactive session): a captioned top-level window is told with
 * WM_DWMNCRENDERINGCHANGED (wParam TRUE) once, soon after it is created, whether it is shown or not; hiding and
 * showing it again says nothing more. Setting DWMNCRP_DISABLED (1) on a window that was told turns the rendering
 * off: a frame change (WM_WINDOWPOSCHANGING with SWP_FRAMECHANGED, for a visible window) and
 * WM_DWMNCRENDERINGCHANGED with wParam FALSE; DWMNCRP_ENABLED (2) turns it on again, also for a window without
 * a caption; DWMNCRP_USEWINDOWSTYLE (0) and a value that changes nothing say nothing. A window whose policy was
 * disabled before the first message is never told. DWMWA_NCRENDERING_ENABLED and the caption button bounds
 * follow the policy (no rendering: 0 and an empty RECT). Value 3 is accepted, a size other than 4 or a NULL
 * pointer is E_INVALIDARG.
 */

#define DWMWA_NCRENDERING_ENABLED_ 1
#define DWMWA_NCRENDERING_POLICY_ 2
#define DWMWA_CAPTION_BUTTON_BOUNDS_ 5

typedef HRESULT (WINAPI *PFN_SET)(HWND, DWORD, LPCVOID, DWORD);
typedef HRESULT (WINAPI *PFN_GET)(HWND, DWORD, PVOID, DWORD);
static PFN_SET pDwmSetWindowAttribute;
static PFN_GET pDwmGetWindowAttribute;

static INT g_cNcMessages;
static INT g_NcState;
static INT g_cFrameChanged;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_DWMNCRENDERINGCHANGED)
    {
        g_cNcMessages++;
        g_NcState = (INT)wParam;
    }
    else if (msg == WM_WINDOWPOSCHANGING && (((WINDOWPOS *)lParam)->flags & SWP_FRAMECHANGED))
    {
        g_cFrameChanged++;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void Pump(DWORD ms)
{
    DWORD end = GetTickCount() + ms;
    MSG msg;

    while ((LONG)(end - GetTickCount()) > 0)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
}

static void Reset(void)
{
    g_cNcMessages = 0;
    g_NcState = -1;
    g_cFrameChanged = 0;
}

static HWND Make(DWORD style)
{
    HWND hwnd = CreateWindowExW(0, L"DwmNcRenderingTest", L"t", style, 20, 20, 300, 200,
                                NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowEx failed %lu\n", GetLastError());
    return hwnd;
}

static HRESULT SetPolicy(HWND hwnd, DWORD policy)
{
    return pDwmSetWindowAttribute(hwnd, DWMWA_NCRENDERING_POLICY_, &policy, sizeof(policy));
}

#define CHECK_ENABLED(hwnd, expected) CheckEnabled(__LINE__, hwnd, expected)
static void CheckEnabled(int line, HWND hwnd, DWORD expected)
{
    DWORD value = 7;
    HRESULT hr = pDwmGetWindowAttribute(hwnd, DWMWA_NCRENDERING_ENABLED_, &value, sizeof(value));

    ok_(__FILE__, line)(hr == S_OK, "DWMWA_NCRENDERING_ENABLED hr %08lx\n", hr);
    ok_(__FILE__, line)(value == expected, "DWMWA_NCRENDERING_ENABLED %lu, expected %lu\n", value, expected);
}

#define CHECK_BOUNDS_EMPTY(hwnd, empty) CheckBounds(__LINE__, hwnd, empty)
static void CheckBounds(int line, HWND hwnd, BOOL empty)
{
    RECT rc = { 1, 2, 3, 4 };
    HRESULT hr = pDwmGetWindowAttribute(hwnd, DWMWA_CAPTION_BUTTON_BOUNDS_, &rc, sizeof(rc));

    ok_(__FILE__, line)(hr == S_OK, "CAPTION_BUTTON_BOUNDS hr %08lx\n", hr);
    if (empty)
        ok_(__FILE__, line)(rc.left == 0 && rc.top == 0 && rc.right == 0 && rc.bottom == 0,
                            "bounds (%ld,%ld,%ld,%ld), expected empty\n", rc.left, rc.top, rc.right, rc.bottom);
    else
        ok_(__FILE__, line)(rc.right > rc.left && rc.bottom > rc.top,
                            "bounds (%ld,%ld,%ld,%ld), expected the caption buttons\n", rc.left, rc.top, rc.right, rc.bottom);
}

START_TEST(DwmNcRendering)
{
    WNDCLASSW wc = { 0 };
    HMODULE hDwm = LoadLibraryW(L"dwmapi.dll");
    HWND hwnd;
    DWORD value;
    HRESULT hr;

    if (!hDwm)
    {
        skip("dwmapi.dll is not available\n");
        return;
    }
    pDwmSetWindowAttribute = (PFN_SET)GetProcAddress(hDwm, "DwmSetWindowAttribute");
    pDwmGetWindowAttribute = (PFN_GET)GetProcAddress(hDwm, "DwmGetWindowAttribute");
    if (!pDwmSetWindowAttribute || !pDwmGetWindowAttribute)
    {
        skip("DwmSetWindowAttribute is not available\n");
        return;
    }

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"DwmNcRenderingTest";
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed\n");

    /* A captioned window, shown: told once, TRUE */
    Reset();
    hwnd = Make(WS_OVERLAPPEDWINDOW);
    ShowWindow(hwnd, SW_SHOW);
    Pump(500);
    ok_int(g_cNcMessages, 1);
    ok_int(g_NcState, 1);
    CHECK_ENABLED(hwnd, 1);
    CHECK_BOUNDS_EMPTY(hwnd, FALSE);

    /* Hidden and shown again: nothing more */
    Reset();
    ShowWindow(hwnd, SW_HIDE);
    ShowWindow(hwnd, SW_SHOW);
    Pump(300);
    ok_int(g_cNcMessages, 0);

    /* Disabled: a frame change, then the message with FALSE (G7: the button bounds are empty) */
    Reset();
    hr = SetPolicy(hwnd, 1);
    ok_hex(hr, S_OK);
    Pump(500);
    ok_int(g_cNcMessages, 1);
    ok_int(g_NcState, 0);
    ok(g_cFrameChanged >= 1, "no frame change (%d)\n", g_cFrameChanged);
    CHECK_ENABLED(hwnd, 0);
    CHECK_BOUNDS_EMPTY(hwnd, TRUE);

    /* The same value again: nothing */
    Reset();
    hr = SetPolicy(hwnd, 1);
    ok_hex(hr, S_OK);
    Pump(300);
    ok_int(g_cNcMessages, 0);
    ok_int(g_cFrameChanged, 0);

    /* Hidden and shown with the policy disabled: nothing, still disabled */
    Reset();
    ShowWindow(hwnd, SW_HIDE);
    ShowWindow(hwnd, SW_SHOW);
    Pump(300);
    ok_int(g_cNcMessages, 0);
    CHECK_ENABLED(hwnd, 0);
    CHECK_BOUNDS_EMPTY(hwnd, TRUE);

    /* Enabled again */
    Reset();
    hr = SetPolicy(hwnd, 2);
    ok_hex(hr, S_OK);
    Pump(500);
    ok_int(g_cNcMessages, 1);
    ok_int(g_NcState, 1);
    ok(g_cFrameChanged >= 1, "no frame change (%d)\n", g_cFrameChanged);
    CHECK_ENABLED(hwnd, 1);
    CHECK_BOUNDS_EMPTY(hwnd, FALSE);

    /* USEWINDOWSTYLE of a window with a caption changes nothing */
    Reset();
    hr = SetPolicy(hwnd, 0);
    ok_hex(hr, S_OK);
    Pump(300);
    ok_int(g_cNcMessages, 0);
    CHECK_ENABLED(hwnd, 1);

    /* Invalid arguments; the value 3 is accepted */
    value = 1;
    hr = pDwmSetWindowAttribute(hwnd, DWMWA_NCRENDERING_POLICY_, &value, 2);
    ok_hex(hr, E_INVALIDARG);
    hr = pDwmSetWindowAttribute(hwnd, DWMWA_NCRENDERING_POLICY_, NULL, sizeof(value));
    ok_hex(hr, E_INVALIDARG);
    value = 7;
    hr = pDwmGetWindowAttribute(hwnd, DWMWA_NCRENDERING_POLICY_, &value, sizeof(value));
    ok_hex(hr, E_INVALIDARG);
    hr = SetPolicy(hwnd, 3);
    ok_hex(hr, S_OK);
    DestroyWindow(hwnd);
    Pump(50);

    /* A window whose policy is disabled before it was looked at is never told */
    Reset();
    hwnd = Make(WS_OVERLAPPEDWINDOW);
    hr = SetPolicy(hwnd, 1);
    ok_hex(hr, S_OK);
    CHECK_ENABLED(hwnd, 0);
    CHECK_BOUNDS_EMPTY(hwnd, TRUE);
    ShowWindow(hwnd, SW_SHOW);
    Pump(500);
    ok_int(g_cNcMessages, 0);
    CHECK_ENABLED(hwnd, 0);
    CHECK_BOUNDS_EMPTY(hwnd, TRUE);
    DestroyWindow(hwnd);
    Pump(50);

    /* A window without a caption: not told; the policy ENABLED turns it on, with the frame change */
    Reset();
    hwnd = Make(WS_POPUP);
    ShowWindow(hwnd, SW_SHOW);
    Pump(500);
    ok_int(g_cNcMessages, 0);
    CHECK_ENABLED(hwnd, 0);
    CHECK_BOUNDS_EMPTY(hwnd, TRUE);
    Reset();
    hr = SetPolicy(hwnd, 2);
    ok_hex(hr, S_OK);
    Pump(500);
    ok_int(g_cNcMessages, 1);
    ok_int(g_NcState, 1);
    ok(g_cFrameChanged >= 1, "no frame change (%d)\n", g_cFrameChanged);
    CHECK_ENABLED(hwnd, 1);
    DestroyWindow(hwnd);
    Pump(50);

    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
