/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A Direct2D bitmap made with D2D1_BITMAP_OPTIONS_CANNOT_DRAW over a texture that can be
 *              sampled still gives a bitmap brush that draws what the texture holds
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <d3d11.h>
#include <d2d1_1.h>

#include "wine/test.h"

#define SIZE 64

static ID2D1DeviceContext *context;
static ID2D1Bitmap1 *target;

static DWORD read_pixel(int x, int y)
{
    D2D1_BITMAP_PROPERTIES1 props = {{DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_CANNOT_DRAW | D2D1_BITMAP_OPTIONS_CPU_READ, NULL};
    D2D1_SIZE_U size = {SIZE, SIZE};
    ID2D1Bitmap1 *staging = NULL;
    D2D1_MAPPED_RECT mapped;
    DWORD value = 0xdeadbeef;

    if (SUCCEEDED(ID2D1DeviceContext_CreateBitmap(context, size, NULL, 0, &props, &staging)))
    {
        ID2D1Bitmap1_CopyFromBitmap(staging, NULL, (ID2D1Bitmap *)target, NULL);
        if (SUCCEEDED(ID2D1Bitmap1_Map(staging, D2D1_MAP_OPTIONS_READ, &mapped)))
        {
            value = ((DWORD *)(mapped.bits + y * mapped.pitch))[x];
            ID2D1Bitmap1_Unmap(staging);
        }
        ID2D1Bitmap1_Release(staging);
    }
    return value;
}

static void test_cannot_draw_brush(ID3D11Device *d3d_device, D2D1_ALPHA_MODE alpha, DWORD expected)
{
    D2D1_BRUSH_PROPERTIES brush_props = {1.0f, {{{1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f}}}};
    D2D1_BITMAP_BRUSH_PROPERTIES1 bitmap_brush_props =
            {D2D1_EXTEND_MODE_CLAMP, D2D1_EXTEND_MODE_CLAMP, D2D1_INTERPOLATION_MODE_NEAREST_NEIGHBOR};
    D2D1_BITMAP_PROPERTIES1 bitmap_props = {{DXGI_FORMAT_B8G8R8A8_UNORM, alpha}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW, NULL};
    D2D1_COLOR_F clear = {0.0f, 0.0f, 0.0f, 0.0f};
    D2D1_RECT_F rect = {0.0f, 0.0f, SIZE, SIZE};
    D3D11_TEXTURE2D_DESC desc = {0};
    D3D11_SUBRESOURCE_DATA data;
    ID2D1BitmapBrush1 *brush;
    ID2D1Bitmap1 *bitmap;
    IDXGISurface *surface;
    ID3D11Texture2D *texture;
    DWORD pixels[SIZE * SIZE], value;
    unsigned int i;
    HRESULT hr;

    for (i = 0; i < ARRAY_SIZE(pixels); ++i)
        pixels[i] = 0xffffffff;

    desc.Width = SIZE;
    desc.Height = SIZE;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
    data.pSysMem = pixels;
    data.SysMemPitch = SIZE * 4;
    data.SysMemSlicePitch = 0;
    hr = ID3D11Device_CreateTexture2D(d3d_device, &desc, &data, &texture);
    ok(hr == S_OK, "CreateTexture2D failed, hr %#lx.\n", hr);
    if (FAILED(hr))
        return;
    hr = ID3D11Texture2D_QueryInterface(texture, &IID_IDXGISurface, (void **)&surface);
    ok(hr == S_OK, "QueryInterface failed, hr %#lx.\n", hr);
    ID3D11Texture2D_Release(texture);
    if (FAILED(hr))
        return;

    hr = ID2D1DeviceContext_CreateBitmapFromDxgiSurface(context, surface, &bitmap_props, &bitmap);
    IDXGISurface_Release(surface);
    ok(hr == S_OK, "CreateBitmapFromDxgiSurface failed, hr %#lx.\n", hr);
    if (FAILED(hr))
        return;

    hr = ID2D1DeviceContext_CreateBitmapBrush(context, (ID2D1Bitmap *)bitmap, &bitmap_brush_props, &brush_props, &brush);
    if (FAILED(hr))
    {
        skip("A bitmap brush cannot be made from a bitmap that cannot be drawn, hr %#lx.\n", hr);
        ID2D1Bitmap1_Release(bitmap);
        return;
    }

    ID2D1DeviceContext_BeginDraw(context);
    ID2D1DeviceContext_Clear(context, &clear);
    ID2D1DeviceContext_FillRectangle(context, &rect, (ID2D1Brush *)brush);
    hr = ID2D1DeviceContext_EndDraw(context, NULL, NULL);
    ok(hr == S_OK, "EndDraw failed, hr %#lx.\n", hr);

    value = read_pixel(10, 10);
    ok(value == expected, "alpha mode %u: the pixel is %08lx, expected %08lx.\n", alpha, value, expected);

    ID2D1BitmapBrush1_Release(brush);
    ID2D1Bitmap1_Release(bitmap);
}

START_TEST(d2d1_cannotdraw)
{
    static const D3D_DRIVER_TYPE types[] = {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
    D2D1_BITMAP_PROPERTIES1 target_props = {{DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_TARGET, NULL};
    D2D1_SIZE_U size = {SIZE, SIZE};
    ID3D11Device *d3d_device = NULL;
    IDXGIDevice *dxgi_device;
    ID2D1Device *device;
    unsigned int i;
    HRESULT hr = E_FAIL;

    for (i = 0; i < ARRAY_SIZE(types) && FAILED(hr); ++i)
        hr = D3D11CreateDevice(NULL, types[i], NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                D3D11_SDK_VERSION, &d3d_device, NULL, NULL);
    if (FAILED(hr))
    {
        skip("Cannot create a Direct3D 11 device.\n");
        return;
    }

    hr = ID3D11Device_QueryInterface(d3d_device, &IID_IDXGIDevice, (void **)&dxgi_device);
    ok(hr == S_OK, "QueryInterface failed, hr %#lx.\n", hr);
    hr = D2D1CreateDevice(dxgi_device, NULL, &device);
    IDXGIDevice_Release(dxgi_device);
    if (FAILED(hr))
    {
        skip("Cannot create a Direct2D device, hr %#lx.\n", hr);
        ID3D11Device_Release(d3d_device);
        return;
    }

    hr = ID2D1Device_CreateDeviceContext(device, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &context);
    if (FAILED(hr))
    {
        skip("Cannot create a Direct2D device context, hr %#lx.\n", hr);
        ID2D1Device_Release(device);
        ID3D11Device_Release(d3d_device);
        return;
    }

    hr = ID2D1DeviceContext_CreateBitmap(context, size, NULL, 0, &target_props, &target);
    ok(hr == S_OK, "CreateBitmap failed, hr %#lx.\n", hr);
    ID2D1DeviceContext_SetTarget(context, (ID2D1Image *)target);

    /* A bitmap without alpha is opaque wherever it is sampled: white where the texture is white, and black
     * (the whole rectangle) where nothing is sampled. */
    test_cannot_draw_brush(d3d_device, D2D1_ALPHA_MODE_IGNORE, 0xffffffff);
    test_cannot_draw_brush(d3d_device, D2D1_ALPHA_MODE_PREMULTIPLIED, 0xffffffff);

    ID2D1Bitmap1_Release(target);
    ID2D1DeviceContext_Release(context);
    ID2D1Device_Release(device);
    ID3D11Device_Release(d3d_device);
}
