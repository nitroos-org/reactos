/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for DwmGetWindowAttribute (caption button bounds, extended frame bounds, flags)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <dwmapi.h>

/*
 * The expectations were measured on Windows 10 22H2 (interactive session, 96 DPI, 1280x800), see the comment
 * above DwmGetWindowAttribute in dwmapi_main.c. They are written in terms of the system metrics, so that the
 * same test holds on ReactOS, whose frame and caption metrics differ from Windows 10's. What differs by
 * design is EXTENDED_FRAME_BOUNDS of a window that is not maximized: Windows 10 cuts the 7 invisible pixels of
 * its sizing frame off, ReactOS draws no invisible border.
 */
#define ERR_INSUFFICIENT HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)
#define ERR_HANDLE HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)

#ifndef SM_CXPADDEDBORDER
#define SM_CXPADDEDBORDER 92
#endif

typedef HRESULT (WINAPI *PFN_DWMGETWINDOWATTRIBUTE)(HWND, DWORD, PVOID, DWORD);
static PFN_DWMGETWINDOWATTRIBUTE pDwmGetWindowAttribute;
typedef HRESULT (WINAPI *PFN_DWMSETWINDOWATTRIBUTE)(HWND, DWORD, LPCVOID, DWORD);

static UINT SystemDpi(void)
{
    typedef UINT (WINAPI *PFN_GETDPIFORSYSTEM)(void);
    PFN_GETDPIFORSYSTEM pGetDpiForSystem = (PFN_GETDPIFORSYSTEM)GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForSystem");

    return pGetDpiForSystem ? pGetDpiForSystem() : 96;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
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

static HWND Make(DWORD ex, DWORD style, int x, int y, int cx, int cy)
{
    HWND hwnd = CreateWindowExW(ex, L"DwmWindowAttributeTest", L"t", style, x, y, cx, cy,
                                NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowEx failed %lu\n", GetLastError());
    if (hwnd && (style & WS_VISIBLE))
        Pump(300);
    return hwnd;
}

static void TestInvalidArguments(HWND hwnd)
{
    RECT rect;
    DWORD flag, attr;
    HRESULT hr;

    hr = pDwmGetWindowAttribute(NULL, 5, &rect, sizeof(rect));
    ok(hr == ERR_HANDLE, "NULL hwnd: 0x%08lx\n", hr);
    hr = pDwmGetWindowAttribute((HWND)(ULONG_PTR)0x12345, 5, &rect, sizeof(rect));
    ok(hr == ERR_HANDLE, "bad hwnd: 0x%08lx\n", hr);
    hr = pDwmGetWindowAttribute(hwnd, 5, NULL, sizeof(rect));
    ok(hr == E_INVALIDARG, "NULL buffer: 0x%08lx\n", hr);

    /* RECT attributes: 0 and 1 bytes invalid, 4 and 8 too small, 16 fine */
    for (attr = 5; attr <= 9; attr += 4)
    {
        hr = pDwmGetWindowAttribute(hwnd, attr, &rect, 0);
        ok(hr == E_INVALIDARG, "attr %lu size 0: 0x%08lx\n", attr, hr);
        hr = pDwmGetWindowAttribute(hwnd, attr, &rect, 1);
        ok(hr == E_INVALIDARG, "attr %lu size 1: 0x%08lx\n", attr, hr);
        hr = pDwmGetWindowAttribute(hwnd, attr, &rect, 4);
        ok(hr == ERR_INSUFFICIENT, "attr %lu size 4: 0x%08lx\n", attr, hr);
        hr = pDwmGetWindowAttribute(hwnd, attr, &rect, 8);
        ok(hr == ERR_INSUFFICIENT, "attr %lu size 8: 0x%08lx\n", attr, hr);
        hr = pDwmGetWindowAttribute(hwnd, attr, &rect, sizeof(rect));
        ok(hr == S_OK, "attr %lu size 16: 0x%08lx\n", attr, hr);
    }

    /* DWORD attributes: NCRENDERING_ENABLED, CLOAKED, FREEZE_REPRESENTATION, PASSIVE_UPDATE_MODE, USE_IMMERSIVE_DARK_MODE */
    {
        static const DWORD Attrs[] = { 1, 14, 15, 16, 20 };
        int i;

        for (i = 0; i < 5; i++)
        {
            flag = 0xcdcdcdcd;
            hr = pDwmGetWindowAttribute(hwnd, Attrs[i], &flag, 0);
            ok(hr == E_INVALIDARG, "attr %lu size 0: 0x%08lx\n", Attrs[i], hr);
            hr = pDwmGetWindowAttribute(hwnd, Attrs[i], &flag, 1);
            ok(hr == E_INVALIDARG, "attr %lu size 1: 0x%08lx\n", Attrs[i], hr);
            flag = 0xcdcdcdcd;
            hr = pDwmGetWindowAttribute(hwnd, Attrs[i], &flag, 4);
            ok(hr == S_OK, "attr %lu size 4: 0x%08lx\n", Attrs[i], hr);
            ok(flag <= 1, "attr %lu value 0x%08lx\n", Attrs[i], flag);
        }
    }

    /* the attributes that cannot be read */
    {
        static const DWORD Bad[] = { 0, 2, 3, 4, 6, 7, 8, 10, 11, 12, 13, 17, 18, 19, 21, 22, 33, 34, 35, 36, 40 };
        BYTE buf[16];
        int i;

        for (i = 0; i < (int)(sizeof(Bad) / sizeof(Bad[0])); i++)
        {
            hr = pDwmGetWindowAttribute(hwnd, Bad[i], buf, sizeof(buf));
            ok(hr == E_INVALIDARG, "attr %lu: 0x%08lx\n", Bad[i], hr);
        }
    }
}

/* Measured on Windows 10 22H2 build 19045: border (34), caption (35) colour fail, immersive dark mode (20) succeeds.
 * 36 (text colour) was not measured, it is treated like 34 and 35. */
static void TestSetColorAttributes(HWND hwnd)
{
    PFN_DWMSETWINDOWATTRIBUTE pSet = (PFN_DWMSETWINDOWATTRIBUTE)GetProcAddress(GetModuleHandleW(L"dwmapi.dll"), "DwmSetWindowAttribute");
    static const DWORD Attrs[] = { 34, 35, 36 };
    DWORD value;
    HRESULT hr;
    int i;

    ok(pSet != NULL, "DwmSetWindowAttribute missing\n");
    if (!pSet)
        return;

    for (i = 0; i < 3; i++)
    {
        value = 0x00ff8000;
        hr = pSet(hwnd, Attrs[i], &value, sizeof(value));
        ok(hr == E_INVALIDARG, "set attr %lu: 0x%08lx\n", Attrs[i], hr);
        value = 0xFFFFFFFF; /* DWMWA_COLOR_DEFAULT */
        hr = pSet(hwnd, Attrs[i], &value, sizeof(value));
        ok(hr == E_INVALIDARG, "set attr %lu default: 0x%08lx\n", Attrs[i], hr);
    }
    value = 1;
    hr = pSet(hwnd, 20, &value, sizeof(value));
    ok(hr == S_OK, "set immersive dark mode: 0x%08lx\n", hr);
    value = 0;
    hr = pSet(hwnd, 20, &value, sizeof(value));
    ok(hr == S_OK, "set immersive dark mode off: 0x%08lx\n", hr);
}

static void TestFlags(HWND hwnd, DWORD expectedNc, const char *name)
{
    DWORD flag;
    HRESULT hr;
    DWORD attr;

    flag = 0xcdcdcdcd;
    hr = pDwmGetWindowAttribute(hwnd, 1, &flag, sizeof(flag));
    ok(hr == S_OK && flag == expectedNc, "%s: NCRENDERING_ENABLED 0x%08lx hr 0x%08lx, expected %lu\n", name, flag, hr, expectedNc);
    for (attr = 14; attr <= 20; attr++)
    {
        if (attr == 17 || attr == 18 || attr == 19)
            continue;
        flag = 0xcdcdcdcd;
        hr = pDwmGetWindowAttribute(hwnd, attr, &flag, sizeof(flag));
        ok(hr == S_OK && flag == 0, "%s: attribute %lu 0x%08lx hr 0x%08lx\n", name, attr, flag, hr);
    }
}

/* count = number of system buttons expected (0, 1 or 3) */
static void TestCaptionButtons(HWND hwnd, int count, const char *name)
{
    RECT wr, cb = { 1, 2, 3, 4 }, fb = { 1, 2, 3, 4 };
    LONG fw, width, right;
    HRESULT hr;
    BOOL zoomed = IsZoomed(hwnd);

    GetWindowRect(hwnd, &wr);
    hr = pDwmGetWindowAttribute(hwnd, 5, &cb, sizeof(cb));
    ok(hr == S_OK, "%s: caption button bounds hr 0x%08lx\n", name, hr);
    hr = pDwmGetWindowAttribute(hwnd, 9, &fb, sizeof(fb));
    ok(hr == S_OK, "%s: extended frame bounds hr 0x%08lx\n", name, hr);
    trace("%s: wnd (%ld,%ld,%ld,%ld) buttons (%ld,%ld,%ld,%ld) bounds (%ld,%ld,%ld,%ld)\n", name,
          wr.left, wr.top, wr.right, wr.bottom, cb.left, cb.top, cb.right, cb.bottom, fb.left, fb.top, fb.right, fb.bottom);

    ok(fb.left >= wr.left && fb.top >= wr.top && fb.right <= wr.right && fb.bottom <= wr.bottom,
       "%s: frame bounds outside the window\n", name);
    ok(fb.top == wr.top + (zoomed ? GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER) : 0),
       "%s: frame bounds top %ld, window top %ld\n", name, fb.top, wr.top);

    if (count == 0)
    {
        ok(cb.left == 0 && cb.top == 0 && cb.right == 0 && cb.bottom == 0, "%s: expected an empty RECT\n", name);
        return;
    }

    fw = (GetWindowLongW(hwnd, GWL_STYLE) & WS_THICKFRAME)
         ? GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER) : GetSystemMetrics(SM_CXFIXEDFRAME);
    ok(cb.top == 0, "%s: top %ld\n", name, cb.top);
    ok(cb.bottom == fw + GetSystemMetrics(SM_CYCAPTION) - 1, "%s: bottom %ld, frame %ld, caption %d\n", name, cb.bottom, fw, GetSystemMetrics(SM_CYCAPTION));
    if (SystemDpi() == 96)
    {
        width = cb.right - cb.left;
        ok(width == count * 46 + fw, "%s: width %ld for %d buttons, frame %ld\n", name, width, count, fw);
    }
    right = fb.right - wr.left - (zoomed ? 1 : 0);
    ok(cb.right == right, "%s: right %ld, expected %ld\n", name, cb.right, right);
}

START_TEST(DwmWindowAttribute)
{
    HMODULE hDwmapi;
    WNDCLASSW cls = { 0 };
    HWND hwnd, popup, tool, plain, hidden;
    RECT wr, fb, work;
    HRESULT hr;

    hDwmapi = LoadLibraryW(L"dwmapi.dll");
    if (!hDwmapi)
    {
        skip("dwmapi.dll not available\n");
        return;
    }
    pDwmGetWindowAttribute = (PFN_DWMGETWINDOWATTRIBUTE)GetProcAddress(hDwmapi, "DwmGetWindowAttribute");
    ok(pDwmGetWindowAttribute != NULL, "DwmGetWindowAttribute missing\n");
    if (!pDwmGetWindowAttribute)
        return;

    cls.lpfnWndProc = WndProc;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = L"DwmWindowAttributeTest";
    cls.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    RegisterClassW(&cls);

    hwnd = Make(0, WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 500, 400);
    if (!hwnd)
        return;
    TestInvalidArguments(hwnd);
    TestSetColorAttributes(hwnd);
    TestFlags(hwnd, 1, "overlapped");
    TestCaptionButtons(hwnd, 3, "overlapped");

    ShowWindow(hwnd, SW_MAXIMIZE);
    Pump(500);
    TestFlags(hwnd, 1, "maximized");
    TestCaptionButtons(hwnd, 3, "maximized");
    /* the frame bounds of a maximized window are its work area (Windows 10: 0,0,1280,760) */
    hr = pDwmGetWindowAttribute(hwnd, 9, &fb, sizeof(fb));
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    ok(hr == S_OK && EqualRect(&fb, &work), "maximized frame bounds (%ld,%ld,%ld,%ld), work area (%ld,%ld,%ld,%ld)\n",
       fb.left, fb.top, fb.right, fb.bottom, work.left, work.top, work.right, work.bottom);
    DestroyWindow(hwnd);

    popup = Make(0, WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 200, 150, 375, 188);
    TestFlags(popup, 1, "popup with caption");
    TestCaptionButtons(popup, 1, "popup with caption");
    DestroyWindow(popup);

    popup = Make(WS_EX_DLGMODALFRAME, WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 220, 170, 375, 188);
    TestCaptionButtons(popup, 1, "dialog modal frame");
    DestroyWindow(popup);

    tool = Make(WS_EX_TOOLWINDOW, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 240, 190, 300, 200);
    TestCaptionButtons(tool, 1, "tool window");
    DestroyWindow(tool);

    plain = Make(0, WS_POPUP | WS_VISIBLE, 260, 210, 300, 200);
    TestFlags(plain, 0, "popup without caption");
    TestCaptionButtons(plain, 0, "popup without caption");
    GetWindowRect(plain, &wr);
    hr = pDwmGetWindowAttribute(plain, 9, &fb, sizeof(fb));
    ok(hr == S_OK && EqualRect(&fb, &wr), "caption-less popup frame bounds are its window rectangle\n");
    DestroyWindow(plain);

    /* a window that was never shown answers as a shown one for the buttons; its frame bounds are the window rectangle */
    hidden = Make(0, WS_OVERLAPPEDWINDOW, 100, 100, 500, 400);
    GetWindowRect(hidden, &wr);
    hr = pDwmGetWindowAttribute(hidden, 9, &fb, sizeof(fb));
    ok(hr == S_OK && EqualRect(&fb, &wr), "hidden window frame bounds (%ld,%ld,%ld,%ld), window (%ld,%ld,%ld,%ld)\n",
       fb.left, fb.top, fb.right, fb.bottom, wr.left, wr.top, wr.right, wr.bottom);
    TestFlags(hidden, 1, "hidden");
    DestroyWindow(hidden);

    /* the shell's windows have no caption */
    hwnd = FindWindowW(L"Progman", NULL);
    if (hwnd)
        TestFlags(hwnd, 0, "Progman");

    FreeLibrary(hDwmapi);
}
