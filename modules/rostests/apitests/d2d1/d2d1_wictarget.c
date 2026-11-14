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
#include <d2d1_1.h>
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

/* Reads a pixel of a Direct2D bitmap through a CPU readable copy */
static BOOL read_d2d_pixel(ID2D1DeviceContext *dc, ID2D1Bitmap1 *bitmap, UINT x, UINT y, DWORD *pixel)
{
    D2D1_BITMAP_PROPERTIES1 props;
    D2D1_SIZE_U size = {BMP_SIZE, BMP_SIZE};
    D2D1_MAPPED_RECT mapped;
    ID2D1Bitmap1 *cpu;
    HRESULT hr;

    memset(&props, 0, sizeof(props));
    props.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    props.pixelFormat.alphaMode = D2D1_ALPHA_MODE_PREMULTIPLIED;
    props.dpiX = props.dpiY = 96.0f;
    props.bitmapOptions = D2D1_BITMAP_OPTIONS_CPU_READ | D2D1_BITMAP_OPTIONS_CANNOT_DRAW;
    if (FAILED(hr = ID2D1DeviceContext_CreateBitmap(dc, size, NULL, 0, &props, &cpu)))
        return FALSE;
    hr = ID2D1Bitmap1_CopyFromBitmap(cpu, NULL, (ID2D1Bitmap *)bitmap, NULL);
    ok(hr == S_OK, "CopyFromBitmap failed, hr %#lx\n", hr);
    if (SUCCEEDED(hr) && SUCCEEDED(hr = ID2D1Bitmap1_Map(cpu, D2D1_MAP_OPTIONS_READ, &mapped)))
    {
        *pixel = ((DWORD *)(mapped.bits + y * mapped.pitch))[x];
        ID2D1Bitmap1_Unmap(cpu);
    }
    ID2D1Bitmap1_Release(cpu);
    return SUCCEEDED(hr);
}

/* Measured on Windows 10 22H2 (x64 and x86): the device context of a WIC bitmap render target has a
 * target bitmap, and SetTarget moves the drawing to another bitmap. The WIC bitmap is only written
 * from the render target's own surface, whatever the current target is when EndDraw runs. */
static void test_wic_target_settarget(ID2D1Factory *factory, IWICImagingFactory *wic)
{
    D2D1_BITMAP_PROPERTIES1 bprops;
    D2D1_RENDER_TARGET_PROPERTIES desc;
    D2D1_SIZE_U size = {BMP_SIZE, BMP_SIZE};
    ID2D1Bitmap1 *bmp2, *orig_bitmap;
    ID2D1DeviceContext *dc;
    ID2D1RenderTarget *rt;
    ID2D1Image *orig, *cur;
    IWICBitmap *bitmap;
    unsigned int i;
    DWORD pixel;
    HRESULT hr;

    hr = IWICImagingFactory_CreateBitmap(wic, BMP_SIZE, BMP_SIZE, &GUID_WICPixelFormat32bppPBGRA,
                                         WICBitmapCacheOnDemand, &bitmap);
    ok(hr == S_OK, "CreateBitmap failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;

    memset(&desc, 0, sizeof(desc));
    desc.type = D2D1_RENDER_TARGET_TYPE_DEFAULT;
    desc.pixelFormat.format = DXGI_FORMAT_UNKNOWN;
    desc.pixelFormat.alphaMode = D2D1_ALPHA_MODE_UNKNOWN;
    hr = ID2D1Factory_CreateWicBitmapRenderTarget(factory, bitmap, &desc, &rt);
    if (FAILED(hr))
    {
        skip("Cannot create a WIC bitmap render target, hr %#lx\n", hr);
        IWICBitmap_Release(bitmap);
        return;
    }

    hr = ID2D1RenderTarget_QueryInterface(rt, &IID_ID2D1DeviceContext, (void **)&dc);
    ok(hr == S_OK, "QueryInterface(ID2D1DeviceContext) failed, hr %#lx\n", hr);
    if (FAILED(hr))
    {
        ID2D1RenderTarget_Release(rt);
        IWICBitmap_Release(bitmap);
        return;
    }

    ID2D1DeviceContext_GetTarget(dc, &orig);
    ok(!!orig, "The device context has no target.\n");
    if (orig)
    {
        D2D1_PIXEL_FORMAT format;
        D2D1_SIZE_U osize;

        hr = ID2D1Image_QueryInterface(orig, &IID_ID2D1Bitmap1, (void **)&orig_bitmap);
        ok(hr == S_OK, "QueryInterface(ID2D1Bitmap1) failed, hr %#lx\n", hr);
        if (SUCCEEDED(hr))
        {
            orig_bitmap->lpVtbl->GetPixelSize(orig_bitmap, &osize);
            ok(osize.width == BMP_SIZE && osize.height == BMP_SIZE, "Got target size %ux%u\n", osize.width, osize.height);
            ok(ID2D1Bitmap1_GetOptions(orig_bitmap) == (D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW),
               "Got target options %#x\n", ID2D1Bitmap1_GetOptions(orig_bitmap));
            orig_bitmap->lpVtbl->GetPixelFormat(orig_bitmap, &format);
            ok(format.format == DXGI_FORMAT_B8G8R8A8_UNORM, "Got target format %#x\n", format.format);
            ok(format.alphaMode == D2D1_ALPHA_MODE_PREMULTIPLIED, "Got target alpha mode %u\n", format.alphaMode);
            ID2D1Bitmap1_Release(orig_bitmap);
        }
    }

    memset(&bprops, 0, sizeof(bprops));
    bprops.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    bprops.pixelFormat.alphaMode = D2D1_ALPHA_MODE_PREMULTIPLIED;
    bprops.dpiX = bprops.dpiY = 96.0f;
    bprops.bitmapOptions = D2D1_BITMAP_OPTIONS_TARGET;

    /* 0: restore the original target; 1: EndDraw with the other target; 2: SetTarget before BeginDraw;
     * 3: SetTarget(NULL) before EndDraw */
    for (i = 0; i < 4; ++i)
    {
        D2D1_COLOR_F color = {1.0f, 0.0f, 0.0f, 1.0f};
        D2D1_RECT_F rect = {8.0f, 8.0f, 24.0f, 24.0f};
        ID2D1SolidColorBrush *brush;
        DWORD expected;

        fill_bitmap(bitmap, BACKGROUND);
        hr = ID2D1DeviceContext_CreateBitmap(dc, size, NULL, 0, &bprops, &bmp2);
        if (FAILED(hr))
        {
            skip("Cannot create a target bitmap, hr %#lx\n", hr);
            break;
        }
        if (i == 1)
            color.r = 0.0f, color.b = 1.0f;
        expected = i == 1 ? BLUE : RED;

        if (i == 2)
            ID2D1DeviceContext_SetTarget(dc, (ID2D1Image *)bmp2);
        ID2D1DeviceContext_BeginDraw(dc);
        if (i != 2)
            ID2D1DeviceContext_SetTarget(dc, (ID2D1Image *)bmp2);
        hr = ID2D1DeviceContext_CreateSolidColorBrush(dc, &color, NULL, &brush);
        ok(hr == S_OK, "CreateSolidColorBrush failed, hr %#lx\n", hr);
        ID2D1DeviceContext_FillRectangle(dc, &rect, (ID2D1Brush *)brush);
        ID2D1SolidColorBrush_Release(brush);
        if (i == 0)
            ID2D1DeviceContext_SetTarget(dc, orig);
        else if (i == 3)
            ID2D1DeviceContext_SetTarget(dc, NULL);

        ID2D1DeviceContext_GetTarget(dc, &cur);
        if (i == 3)
            ok(!cur, "Test %u: got a target after SetTarget(NULL).\n", i);
        else if (i == 0)
            ok(cur == orig, "Test %u: got target %p, expected %p.\n", i, cur, orig);
        else
            ok(cur == (ID2D1Image *)bmp2, "Test %u: got target %p, expected %p.\n", i, cur, bmp2);
        if (cur)
            ID2D1Image_Release(cur);

        hr = ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
        ok(hr == S_OK, "Test %u: EndDraw failed, hr %#lx\n", i, hr);

        /* The WIC bitmap keeps what it held: nothing was drawn on the target's own surface */
        pixel = get_pixel(bitmap, 16, 16);
        ok(pixel == BACKGROUND, "Test %u: the WIC bitmap is %08lx inside the square, expected %08x\n", i, pixel, BACKGROUND);
        pixel = get_pixel(bitmap, 40, 40);
        ok(pixel == BACKGROUND, "Test %u: the WIC bitmap is %08lx outside the square, expected %08x\n", i, pixel, BACKGROUND);

        /* The other bitmap received the drawing */
        if (read_d2d_pixel(dc, bmp2, 16, 16, &pixel))
            ok(pixel == expected, "Test %u: the target bitmap is %08lx inside the square, expected %08lx\n", i, pixel, expected);
        if (read_d2d_pixel(dc, bmp2, 40, 40, &pixel))
            ok(pixel == 0, "Test %u: the target bitmap is %08lx outside the square, expected 0\n", i, pixel);

        ID2D1Bitmap1_Release(bmp2);
        /* Back to the original target for the next round */
        if (i != 0)
            ID2D1DeviceContext_SetTarget(dc, orig);
    }

    if (orig)
        ID2D1Image_Release(orig);
    ID2D1DeviceContext_Release(dc);
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
        test_wic_target_settarget(factory, wic);
        ID2D1Factory_Release(factory);
    }

    IWICImagingFactory_Release(wic);
    CoUninitialize();
}
