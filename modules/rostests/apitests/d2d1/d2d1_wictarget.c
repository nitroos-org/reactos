/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A Direct2D render target on a WIC bitmap draws over the pixels that the bitmap
 *              already holds: pixels a draw does not cover stay as they were, and changes made to
 *              the bitmap between two draws are kept
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <windows.h>
#include <d2d1.h>
#include <initguid.h>
#include <wincodec.h>

#include "wine/test.h"

#define BMP_SIZE 64

#define BACKGROUND 0xff336699u
#define RED        0xffff0000u
#define GREEN      0xff00ff00u
#define BLUE       0xff0000ffu

static void fill_bitmap(IWICBitmap *bitmap, DWORD color)
{
    IWICBitmapLock *lock;
    WICRect rect = {0, 0, BMP_SIZE, BMP_SIZE};
    UINT size, stride, x, y;
    BYTE *data;
    HRESULT hr;

    hr = IWICBitmap_Lock(bitmap, &rect, WICBitmapLockWrite, &lock);
    ok(hr == S_OK, "Lock failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;
    IWICBitmapLock_GetDataPointer(lock, &size, &data);
    IWICBitmapLock_GetStride(lock, &stride);
    for (y = 0; y < BMP_SIZE; ++y)
        for (x = 0; x < BMP_SIZE; ++x)
            ((DWORD *)(data + y * stride))[x] = color;
    IWICBitmapLock_Release(lock);
}

static void set_pixel(IWICBitmap *bitmap, UINT x, UINT y, DWORD color)
{
    IWICBitmapLock *lock;
    WICRect rect = {0, 0, BMP_SIZE, BMP_SIZE};
    UINT size, stride;
    BYTE *data;
    HRESULT hr;

    hr = IWICBitmap_Lock(bitmap, &rect, WICBitmapLockWrite, &lock);
    ok(hr == S_OK, "Lock failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;
    IWICBitmapLock_GetDataPointer(lock, &size, &data);
    IWICBitmapLock_GetStride(lock, &stride);
    ((DWORD *)(data + y * stride))[x] = color;
    IWICBitmapLock_Release(lock);
}

static DWORD get_pixel(IWICBitmap *bitmap, UINT x, UINT y)
{
    IWICBitmapLock *lock;
    WICRect rect = {0, 0, BMP_SIZE, BMP_SIZE};
    UINT size, stride;
    BYTE *data;
    DWORD ret;
    HRESULT hr;

    hr = IWICBitmap_Lock(bitmap, &rect, WICBitmapLockRead, &lock);
    ok(hr == S_OK, "Lock failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return 0;
    IWICBitmapLock_GetDataPointer(lock, &size, &data);
    IWICBitmapLock_GetStride(lock, &stride);
    ret = ((DWORD *)(data + y * stride))[x];
    IWICBitmapLock_Release(lock);
    return ret;
}

/* Fills (8,8)-(24,24) */
static void draw_square(ID2D1RenderTarget *rt, float r, float g, float b)
{
    D2D1_COLOR_F color = {r, g, b, 1.0f};
    D2D1_RECT_F rect = {8.0f, 8.0f, 24.0f, 24.0f};
    ID2D1SolidColorBrush *brush;
    HRESULT hr;

    ID2D1RenderTarget_BeginDraw(rt);
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

static void test_wic_target_keeps_pixels(ID2D1Factory *factory, IWICImagingFactory *wic)
{
    D2D1_RENDER_TARGET_PROPERTIES desc;
    ID2D1RenderTarget *rt;
    IWICBitmap *bitmap;
    DWORD pixel;
    HRESULT hr;

    hr = IWICImagingFactory_CreateBitmap(wic, BMP_SIZE, BMP_SIZE, &GUID_WICPixelFormat32bppPBGRA,
                                         WICBitmapCacheOnDemand, &bitmap);
    ok(hr == S_OK, "CreateBitmap failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;
    fill_bitmap(bitmap, BACKGROUND);

    memset(&desc, 0, sizeof(desc));
    desc.type = D2D1_RENDER_TARGET_TYPE_DEFAULT;
    desc.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.pixelFormat.alphaMode = D2D1_ALPHA_MODE_PREMULTIPLIED;
    hr = ID2D1Factory_CreateWicBitmapRenderTarget(factory, (IWICBitmap *)bitmap, &desc, &rt);
    if (FAILED(hr))
    {
        skip("Cannot create a WIC bitmap render target, hr %#lx\n", hr);
        IWICBitmap_Release(bitmap);
        return;
    }

    /* A draw that covers a part of the target */
    draw_square(rt, 1.0f, 0.0f, 0.0f);
    pixel = get_pixel(bitmap, 16, 16);
    ok(pixel == RED, "The square is %08lx, expected %08x\n", pixel, RED);
    pixel = get_pixel(bitmap, 40, 40);
    ok(pixel == BACKGROUND, "Outside of the square the bitmap is %08lx, expected %08x\n", pixel, BACKGROUND);
    pixel = get_pixel(bitmap, 0, 0);
    ok(pixel == BACKGROUND, "The corner of the bitmap is %08lx, expected %08x\n", pixel, BACKGROUND);

    /* Pixels the application wrote into the bitmap between two draws are drawn over, not discarded */
    set_pixel(bitmap, 50, 50, GREEN);
    set_pixel(bitmap, 16, 16, GREEN);
    draw_square(rt, 0.0f, 0.0f, 1.0f);
    pixel = get_pixel(bitmap, 16, 16);
    ok(pixel == BLUE, "The second square is %08lx, expected %08x\n", pixel, BLUE);
    pixel = get_pixel(bitmap, 50, 50);
    ok(pixel == GREEN, "A pixel written between the draws is %08lx, expected %08x\n", pixel, GREEN);
    pixel = get_pixel(bitmap, 40, 40);
    ok(pixel == BACKGROUND, "Outside of the square the bitmap is %08lx, expected %08x\n", pixel, BACKGROUND);

    /* A draw of nothing leaves the bitmap alone */
    ID2D1RenderTarget_BeginDraw(rt);
    hr = ID2D1RenderTarget_EndDraw(rt, NULL, NULL);
    ok(hr == S_OK, "EndDraw failed, hr %#lx\n", hr);
    pixel = get_pixel(bitmap, 16, 16);
    ok(pixel == BLUE, "After an empty draw the square is %08lx, expected %08x\n", pixel, BLUE);
    pixel = get_pixel(bitmap, 50, 50);
    ok(pixel == GREEN, "After an empty draw the written pixel is %08lx, expected %08x\n", pixel, GREEN);

    /* The whole bitmap replaced between draws */
    fill_bitmap(bitmap, GREEN);
    draw_square(rt, 1.0f, 0.0f, 0.0f);
    pixel = get_pixel(bitmap, 16, 16);
    ok(pixel == RED, "The square is %08lx, expected %08x\n", pixel, RED);
    pixel = get_pixel(bitmap, 40, 40);
    ok(pixel == GREEN, "Outside of the square the bitmap is %08lx, expected %08x\n", pixel, GREEN);

    ID2D1RenderTarget_Release(rt);
    IWICBitmap_Release(bitmap);
}

START_TEST(d2d1_wictarget)
{
    ID2D1Factory *factory;
    IWICImagingFactory *wic;
    HRESULT hr;

    CoInitialize(NULL);

    hr = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, &IID_IWICImagingFactory, (void **)&wic);
    if (FAILED(hr))
    {
        skip("Cannot create the WIC imaging factory, hr %#lx\n", hr);
        CoUninitialize();
        return;
    }

    hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &IID_ID2D1Factory, NULL, (void **)&factory);
    ok(hr == S_OK, "D2D1CreateFactory failed, hr %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        test_wic_target_keeps_pixels(factory, wic);
        ID2D1Factory_Release(factory);
    }

    IWICImagingFactory_Release(wic);
    CoUninitialize();
}
