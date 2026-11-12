/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for DrawThemeParentBackgroundEx
 *
 * The function is exported by uxtheme since Windows Vista. It used to be a stub that raised an
 * exception, which aborted applications (WinDirStat 2.x lost its drive list) that call it while painting.
 */

#include <apitest.h>
#include <windows.h>
#include <uxtheme.h>
#include <msgtrace.h>
#include <user32testhelpers.h>

#ifndef DTPB_USEERASEBKGND
#define DTPB_WINDOWDC           0x00000001
#define DTPB_USECTLCOLORSTATIC  0x00000002
#define DTPB_USEERASEBKGND      0x00000004
#endif

typedef HRESULT (WINAPI *DRAWPARENTEX)(HWND, HDC, DWORD, const RECT *);

static HWND hParent, hChild;

static int GetIwnd(HWND hwnd)
{
    if (hwnd == hParent) return 1;
    if (hwnd == hChild) return 2;
    return 0;
}

static LRESULT CALLBACK ExProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    int iwnd = GetIwnd(hwnd);

    if (message > WM_USER || !iwnd || message == WM_GETICON)
        return DefWindowProcW(hwnd, message, wParam, lParam);

    RECORD_MESSAGE(iwnd, message, SENT, 0, 0);
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

static void FlushMsgs(void)
{
    MSG msg;

    while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE))
    {
        int iwnd = GetIwnd(msg.hwnd);
        if (iwnd && msg.message <= WM_USER)
            RECORD_MESSAGE(iwnd, msg.message, POST, 0, 0);
        DispatchMessageW(&msg);
    }
}

static MSG_ENTRY erase_chain[] = { {1, WM_ERASEBKGND}, {1, WM_PRINTCLIENT}, {0, 0} };
static MSG_ENTRY ctlcolor_chain[] = { {1, WM_CTLCOLORSTATIC}, {1, WM_PRINTCLIENT}, {0, 0} };

START_TEST(DrawThemeParentBackgroundEx)
{
    HMODULE hUx = GetModuleHandleW(L"uxtheme.dll");
    DRAWPARENTEX pDrawEx = hUx ? (DRAWPARENTEX)GetProcAddress(hUx, "DrawThemeParentBackgroundEx") : NULL;
    HRESULT hr;
    HDC hdc;
    RECT rc = { 0, 0, 10, 10 };

    if (!pDrawEx)
    {
        skip("DrawThemeParentBackgroundEx is not exported\n");
        return;
    }

    RegisterSimpleClass(ExProc, L"testClassEx");
    hParent = CreateWindowW(L"testClassEx", L"parent", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 200, 200, 0, NULL, NULL, NULL);
    hChild = CreateWindowW(L"testClassEx", L"child", WS_CHILD | WS_VISIBLE, 0, 0, 100, 100, hParent, NULL, NULL, NULL);
    ok(hParent && hChild, "windows not created\n");
    FlushMsgs();
    EMPTY_CACHE();

    hdc = GetDC(hParent);

    /* The call must return, not raise an exception */
    hr = pDrawEx(hChild, hdc, DTPB_USEERASEBKGND, NULL);
    ok(hr == S_OK, "hr = 0x%08lx\n", hr);
    FlushMsgs();
    COMPARE_CACHE(erase_chain);

    hr = pDrawEx(hChild, hdc, DTPB_USEERASEBKGND, &rc);
    ok(hr == S_OK, "hr = 0x%08lx\n", hr);
    FlushMsgs();
    EMPTY_CACHE();

    hr = pDrawEx(hChild, hdc, DTPB_USECTLCOLORSTATIC, NULL);
    ok(hr == S_OK, "hr = 0x%08lx\n", hr);
    FlushMsgs();
    COMPARE_CACHE(ctlcolor_chain);

    hr = pDrawEx(hChild, hdc, 0, NULL);
    ok(hr == S_OK, "hr = 0x%08lx\n", hr);
    FlushMsgs();
    EMPTY_CACHE();

    /* A window without a parent: nothing to draw */
    hr = pDrawEx(hParent, hdc, DTPB_USEERASEBKGND, NULL);
    ok(hr == S_OK, "hr = 0x%08lx\n", hr);
    FlushMsgs();
    COMPARE_CACHE(empty_chain);

    hr = pDrawEx((HWND)(ULONG_PTR)0x7777, hdc, DTPB_USEERASEBKGND, NULL);
    ok(hr == E_HANDLE, "hr = 0x%08lx\n", hr);
    hr = pDrawEx(hChild, NULL, DTPB_USEERASEBKGND, NULL);
    ok(hr == E_HANDLE, "hr = 0x%08lx\n", hr);

    ReleaseDC(hParent, hdc);
    DestroyWindow(hParent);
    UnregisterClassW(L"testClassEx", NULL);
}
