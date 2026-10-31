/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Direct2D render targets reach the screen: window targets present through the
 *              swap chain, DC targets copy to the DC they are bound to
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <windows.h>
#include <d2d1.h>

#include "wine/test.h"

#define WND_X 100
#define WND_Y 100
#define WND_SIZE 96

static ID2D1Factory *factory;

static void pump(DWORD ms)
{
    DWORD end = GetTickCount() + ms;
    MSG msg;

    do
    {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        Sleep(10);
    } while ((LONG)(GetTickCount() - end) < 0);
}

static HWND create_window(void)
{
    HWND hwnd = CreateWindowExA(WS_EX_TOPMOST, "STATIC", "d2d1_present", WS_POPUP | WS_VISIBLE,
                                WND_X, WND_Y, WND_SIZE, WND_SIZE, NULL, NULL, GetModuleHandleA(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowEx failed, error %lu\n", GetLastError());
    pump(300);
    return hwnd;
}

static void fill(ID2D1RenderTarget *rt, float r, float g, float b)
{
    D2D1_COLOR_F color;
    D2D1_RECT_F rect;
    ID2D1SolidColorBrush *brush;
    D2D1_COLOR_F white = {1.0f, 1.0f, 1.0f, 1.0f};
    HRESULT hr;

    color.r = r; color.g = g; color.b = b; color.a = 1.0f;
    rect.left = 16.0f; rect.top = 16.0f; rect.right = 48.0f; rect.bottom = 48.0f;

    ID2D1RenderTarget_BeginDraw(rt);
    ID2D1RenderTarget_Clear(rt, &white);
    hr = ID2D1RenderTarget_CreateSolidColorBrush(rt, &color, NULL, &brush);
    ok(hr == S_OK, "CreateSolidColorBrush failed, hr %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        ID2D1RenderTarget_FillRectangle(rt, &rect, (ID2D1Brush *)brush);
        ID2D1SolidColorBrush_Release(brush);
    }
    hr = ID2D1RenderTarget_EndDraw(rt, NULL, NULL);
    ok(hr == S_OK, "EndDraw failed, hr %#lx\n", hr);
}

/* A process in a non-interactive window station (a service, a remote shell) has no screen to draw on:
 * window render targets cannot be created there, and GetPixel on the screen DC fails */
static BOOL screen_readable(void)
{
    HDC screen = GetDC(NULL);
    BOOL ret = screen && GetPixel(screen, 0, 0) != CLR_INVALID;

    if (screen)
        ReleaseDC(NULL, screen);
    return ret;
}

static void check_screen(const char *what)
{
    HDC screen = GetDC(NULL);
    COLORREF inside = GetPixel(screen, WND_X + 32, WND_Y + 32);
    COLORREF outside = GetPixel(screen, WND_X + 80, WND_Y + 80);

    ReleaseDC(NULL, screen);
    ok(inside == RGB(0, 0, 255), "%s: the rectangle is %06lx on the screen, expected 0000ff\n", what, inside);
    ok(outside == RGB(255, 255, 255), "%s: the cleared area is %06lx on the screen, expected ffffff\n", what, outside);
}

static void test_hwnd_target_present(void)
{
    D2D1_RENDER_TARGET_PROPERTIES desc;
    D2D1_HWND_RENDER_TARGET_PROPERTIES hwnd_desc;
    ID2D1HwndRenderTarget *rt;
    HWND hwnd;
    HRESULT hr;
    int frame;

    if (!screen_readable())
    {
        skip("The screen is not accessible\n");
        return;
    }

    hwnd = create_window();
    if (!hwnd)
        return;

    memset(&desc, 0, sizeof(desc));
    desc.type = D2D1_RENDER_TARGET_TYPE_DEFAULT;
    desc.pixelFormat.format = DXGI_FORMAT_UNKNOWN;
    desc.pixelFormat.alphaMode = D2D1_ALPHA_MODE_UNKNOWN;
    memset(&hwnd_desc, 0, sizeof(hwnd_desc));
    hwnd_desc.hwnd = hwnd;
    hwnd_desc.pixelSize.width = WND_SIZE;
    hwnd_desc.pixelSize.height = WND_SIZE;
    hwnd_desc.presentOptions = D2D1_PRESENT_OPTIONS_NONE;

    hr = ID2D1Factory_CreateHwndRenderTarget(factory, &desc, &hwnd_desc, &rt);
    if (FAILED(hr))
    {
        skip("Cannot create a window render target, hr %#lx\n", hr);
        DestroyWindow(hwnd);
        return;
    }

    for (frame = 0; frame < 2; ++frame)
    {
        fill((ID2D1RenderTarget *)rt, 0.0f, 0.0f, 1.0f);
        /* The first frame of a window target is on screen when EndDraw returns, on Windows, whatever
         * the window target did before: no waiting before reading it back */
        if (frame)
            pump(300);
        check_screen(frame ? "window target, second frame" : "window target, first frame");
    }

    ID2D1HwndRenderTarget_Release(rt);
    DestroyWindow(hwnd);
}

/* One frame on a window target and nothing else: the process's first window present on a fresh Direct3D
 * device. The rectangle has to be on the screen when EndDraw returns: no pump, no sleep (Windows shows it
 * at once: the first screen read after EndDraw already sees it). It used to show up 270 ms to over a second
 * later, while the command stream thread compiled the shaders of the first frame. */
static void test_hwnd_target_single_frame(void)
{
    D2D1_RENDER_TARGET_PROPERTIES desc;
    D2D1_HWND_RENDER_TARGET_PROPERTIES hwnd_desc;
    ID2D1HwndRenderTarget *rt;
    HWND hwnd;
    HRESULT hr;

    if (!screen_readable())
    {
        skip("The screen is not accessible\n");
        return;
    }

    hwnd = create_window();
    if (!hwnd)
        return;

    memset(&desc, 0, sizeof(desc));
    desc.type = D2D1_RENDER_TARGET_TYPE_DEFAULT;
    desc.pixelFormat.format = DXGI_FORMAT_UNKNOWN;
    desc.pixelFormat.alphaMode = D2D1_ALPHA_MODE_UNKNOWN;
    memset(&hwnd_desc, 0, sizeof(hwnd_desc));
    hwnd_desc.hwnd = hwnd;
    hwnd_desc.pixelSize.width = WND_SIZE;
    hwnd_desc.pixelSize.height = WND_SIZE;
    hwnd_desc.presentOptions = D2D1_PRESENT_OPTIONS_NONE;

    hr = ID2D1Factory_CreateHwndRenderTarget(factory, &desc, &hwnd_desc, &rt);
    if (FAILED(hr))
    {
        skip("Cannot create a window render target, hr %#lx\n", hr);
        DestroyWindow(hwnd);
        return;
    }

    fill((ID2D1RenderTarget *)rt, 0.0f, 0.0f, 1.0f);
    check_screen("window target, single frame");

    ID2D1HwndRenderTarget_Release(rt);
    DestroyWindow(hwnd);
}

static void test_dc_target_screen(void)
{
    D2D1_RENDER_TARGET_PROPERTIES desc;
    ID2D1DCRenderTarget *rt;
    HWND hwnd;
    HDC dc;
    RECT rect;
    HRESULT hr;

    if (!screen_readable())
    {
        skip("The screen is not accessible\n");
        return;
    }

    hwnd = create_window();
    if (!hwnd)
        return;

    memset(&desc, 0, sizeof(desc));
    desc.type = D2D1_RENDER_TARGET_TYPE_DEFAULT;
    desc.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.pixelFormat.alphaMode = D2D1_ALPHA_MODE_IGNORE;

    hr = ID2D1Factory_CreateDCRenderTarget(factory, &desc, &rt);
    if (FAILED(hr))
    {
        skip("Cannot create a DC render target, hr %#lx\n", hr);
        DestroyWindow(hwnd);
        return;
    }

    dc = GetDC(hwnd);
    SetRect(&rect, 0, 0, WND_SIZE, WND_SIZE);
    hr = ID2D1DCRenderTarget_BindDC(rt, dc, &rect);
    ok(hr == S_OK, "BindDC failed, hr %#lx\n", hr);
    fill((ID2D1RenderTarget *)rt, 0.0f, 0.0f, 1.0f);
    GdiFlush();
    pump(100);
    check_screen("DC target on a window DC");

    ReleaseDC(hwnd, dc);
    ID2D1DCRenderTarget_Release(rt);
    DestroyWindow(hwnd);
}

static void test_dc_target_dib(void)
{
    D2D1_RENDER_TARGET_PROPERTIES desc;
    ID2D1DCRenderTarget *rt;
    BITMAPINFO bi;
    HBITMAP bitmap;
    DWORD *bits;
    HDC screen, dc;
    RECT rect;
    HRESULT hr;

    memset(&desc, 0, sizeof(desc));
    desc.type = D2D1_RENDER_TARGET_TYPE_DEFAULT;
    desc.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.pixelFormat.alphaMode = D2D1_ALPHA_MODE_IGNORE;

    hr = ID2D1Factory_CreateDCRenderTarget(factory, &desc, &rt);
    if (FAILED(hr))
    {
        skip("Cannot create a DC render target, hr %#lx\n", hr);
        return;
    }

    memset(&bi, 0, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth = WND_SIZE;
    bi.bmiHeader.biHeight = -WND_SIZE;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    screen = GetDC(NULL);
    bitmap = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, (void **)&bits, NULL, 0);
    dc = CreateCompatibleDC(screen);
    ReleaseDC(NULL, screen);
    ok(bitmap != NULL && dc != NULL, "Cannot create the DIB, error %lu\n", GetLastError());
    if (bitmap && dc)
    {
        SelectObject(dc, bitmap);
        memset(bits, 0x7f, WND_SIZE * WND_SIZE * 4);

        SetRect(&rect, 0, 0, WND_SIZE, WND_SIZE);
        hr = ID2D1DCRenderTarget_BindDC(rt, dc, &rect);
        ok(hr == S_OK, "BindDC failed, hr %#lx\n", hr);
        fill((ID2D1RenderTarget *)rt, 0.0f, 0.0f, 1.0f);
        GdiFlush();

        ok((bits[32 * WND_SIZE + 32] & 0xffffff) == 0x0000ff, "DC target on a DIB: the rectangle is %06lx, expected 0000ff\n",
           bits[32 * WND_SIZE + 32] & 0xffffff);
        ok((bits[80 * WND_SIZE + 80] & 0xffffff) == 0xffffff, "DC target on a DIB: the cleared area is %06lx, expected ffffff\n",
           bits[80 * WND_SIZE + 80] & 0xffffff);
    }
    if (dc) DeleteDC(dc);
    if (bitmap) DeleteObject(bitmap);
    ID2D1DCRenderTarget_Release(rt);
}

START_TEST(d2d1_present)
{
    HRESULT hr;
    int i;

    hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &IID_ID2D1Factory, NULL, (void **)&factory);
    ok(hr == S_OK, "D2D1CreateFactory failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;

    test_hwnd_target_single_frame();
    test_dc_target_dib();
    test_dc_target_screen();
    test_hwnd_target_present();
    /* The window target and the DC targets share the factory's Direct3D device. Destroying the window
     * target's swap chain used to leave the device's GL context pointing at the freed swap chain, and the
     * DC targets then read back zeros, a few draws later than the first one: repeat */
    for (i = 0; i < 4; i++)
    {
        test_dc_target_dib();
        test_dc_target_screen();
    }

    ID2D1Factory_Release(factory);
}
