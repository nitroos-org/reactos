/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Direct2D built-in effects can be created, and an effect input can be cleared with SetInput(NULL)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <d3d11.h>
#include <d2d1_1.h>
#include <d2d1effects.h>
#include <d2d1effects_2.h>

#include "wine/test.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const struct
{
    const CLSID *clsid;
    const char *name;
    UINT32 inputs;
}
effects[] =
{
    { &CLSID_D2D12DAffineTransform, "2DAffineTransform", 1 },
    { &CLSID_D2D13DPerspectiveTransform, "3DPerspectiveTransform", 1 },
    { &CLSID_D2D13DTransform, "3DTransform", 1 },
    { &CLSID_D2D1ArithmeticComposite, "ArithmeticComposite", 2 },
    { &CLSID_D2D1Atlas, "Atlas", 1 },
    { &CLSID_D2D1BitmapSource, "BitmapSource", 0 },
    { &CLSID_D2D1Blend, "Blend", 2 },
    { &CLSID_D2D1Border, "Border", 1 },
    { &CLSID_D2D1Brightness, "Brightness", 1 },
    { &CLSID_D2D1ColorMatrix, "ColorMatrix", 1 },
    { &CLSID_D2D1Crop, "Crop", 1 },
    { &CLSID_D2D1DirectionalBlur, "DirectionalBlur", 1 },
    { &CLSID_D2D1DisplacementMap, "DisplacementMap", 2 },
    { &CLSID_D2D1Flood, "Flood", 0 },
    { &CLSID_D2D1GaussianBlur, "GaussianBlur", 1 },
    { &CLSID_D2D1Grayscale, "Grayscale", 1 },
    { &CLSID_D2D1Morphology, "Morphology", 1 },
    { &CLSID_D2D1Saturation, "Saturation", 1 },
    { &CLSID_D2D1Scale, "Scale", 1 },
    { &CLSID_D2D1Shadow, "Shadow", 1 },
    { &CLSID_D2D1Tile, "Tile", 1 },
    { &CLSID_D2D1Turbulence, "Turbulence", 0 },
};

static ID2D1DeviceContext *create_context(ID3D11Device **d3d_device, ID2D1Device **d2d_device)
{
    static const D3D_DRIVER_TYPE types[] = {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
    ID2D1DeviceContext *context = NULL;
    IDXGIDevice *dxgi_device;
    unsigned int i;
    HRESULT hr = E_FAIL;

    *d3d_device = NULL;
    *d2d_device = NULL;
    for (i = 0; i < ARRAY_SIZE(types) && FAILED(hr); ++i)
        hr = D3D11CreateDevice(NULL, types[i], NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                D3D11_SDK_VERSION, d3d_device, NULL, NULL);
    if (FAILED(hr))
        return NULL;

    hr = ID3D11Device_QueryInterface(*d3d_device, &IID_IDXGIDevice, (void **)&dxgi_device);
    ok(hr == S_OK, "QueryInterface failed, hr %#lx\n", hr);
    hr = D2D1CreateDevice(dxgi_device, NULL, d2d_device);
    IDXGIDevice_Release(dxgi_device);
    if (FAILED(hr))
        trace("D2D1CreateDevice failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return NULL;

    /* No device context where the renderer cannot draw (no OpenGL), as for the window targets of d2d1_present. */
    hr = ID2D1Device_CreateDeviceContext(*d2d_device, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &context);
    if (FAILED(hr))
        trace("CreateDeviceContext failed, hr %#lx\n", hr);
    return context;
}

START_TEST(d2d1_effects)
{
    ID2D1DeviceContext *context;
    ID3D11Device *d3d_device;
    ID2D1Device *d2d_device;
    ID2D1Effect *effect;
    unsigned int i;
    HRESULT hr;

    if (!(context = create_context(&d3d_device, &d2d_device)))
    {
        skip("Cannot create a Direct2D device context\n");
        if (d2d_device)
            ID2D1Device_Release(d2d_device);
        if (d3d_device)
            ID3D11Device_Release(d3d_device);
        return;
    }

    for (i = 0; i < ARRAY_SIZE(effects); ++i)
    {
        effect = NULL;
        hr = ID2D1DeviceContext_CreateEffect(context, effects[i].clsid, &effect);
        ok(hr == S_OK, "%s: CreateEffect failed, hr %#lx\n", effects[i].name, hr);
        if (FAILED(hr))
            continue;

        ok(ID2D1Effect_GetInputCount(effect) == effects[i].inputs, "%s: got %u inputs, expected %u\n",
                effects[i].name, ID2D1Effect_GetInputCount(effect), effects[i].inputs);

        /* A NULL input clears the input. */
        if (effects[i].inputs)
        {
            ID2D1Image *input = (ID2D1Image *)0xdeadbeef;

            ID2D1Effect_SetInput(effect, 0, NULL, TRUE);
            ID2D1Effect_GetInput(effect, 0, &input);
            ok(!input, "%s: got input %p after SetInput(NULL)\n", effects[i].name, input);
        }
        ID2D1Effect_Release(effect);
    }

    ID2D1DeviceContext_Release(context);
    ID2D1Device_Release(d2d_device);
    ID3D11Device_Release(d3d_device);
}
