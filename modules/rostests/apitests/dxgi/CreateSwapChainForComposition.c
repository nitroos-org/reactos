/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for IDXGIFactory2::CreateSwapChainForComposition
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A composition swap chain has no window: GetHwnd fails, the description holds no output window, and
 * ResizeBuffers cannot take the size of a window (E_INVALIDARG). Only the flip model and stretching are
 * accepted. Measured on Windows 10 22H2 (x64, Microsoft Basic Render Driver).
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#define COBJMACROS
#include <d3d11.h>
#include <dxgi1_6.h>
#include "composition_common.h"

START_TEST(CreateSwapChainForComposition)
{
    DXGI_SWAP_CHAIN_DESC1 Desc, Got;
    DXGI_SWAP_CHAIN_DESC Got0;
    IDXGISwapChain1 *SwapChain;
    IDXGIFactory2 *Factory;
    ID3D11Texture2D *Buffer;
    ID3D11Device *Device;
    HWND Window;
    HRESULT hr;

    Device = CreateD3D11Device();
    if (!Device)
    {
        skip("no Direct3D 11 device\n");
        return;
    }
    hr = CreateDXGIFactory1(&IID_IDXGIFactory2, (void **)&Factory);
    ok(hr == S_OK, "CreateDXGIFactory1 returned %08lx\n", hr);
    if (FAILED(hr))
    {
        ID3D11Device_Release(Device);
        return;
    }

    /* what is refused */
    FillCompositionDesc(&Desc, 64, 32);
    SwapChain = (IDXGISwapChain1 *)(ULONG_PTR)0xdeadbeef;
    hr = IDXGIFactory2_CreateSwapChainForComposition(Factory, (IUnknown *)Device, NULL, NULL, &SwapChain);
    ok(hr == DXGI_ERROR_INVALID_CALL, "NULL desc: %08lx\n", hr);
    hr = IDXGIFactory2_CreateSwapChainForComposition(Factory, NULL, &Desc, NULL, &SwapChain);
    ok(hr == DXGI_ERROR_INVALID_CALL, "NULL device: %08lx\n", hr);

    FillCompositionDesc(&Desc, 64, 32);
    Desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    Desc.BufferCount = 1;
    SwapChain = NULL;
    hr = IDXGIFactory2_CreateSwapChainForComposition(Factory, (IUnknown *)Device, &Desc, NULL, &SwapChain);
    ok(hr == DXGI_ERROR_INVALID_CALL, "DISCARD: %08lx\n", hr);
    ok(SwapChain == NULL, "DISCARD gave %p\n", SwapChain);

    FillCompositionDesc(&Desc, 64, 32);
    Desc.Scaling = DXGI_SCALING_NONE;
    SwapChain = NULL;
    hr = IDXGIFactory2_CreateSwapChainForComposition(Factory, (IUnknown *)Device, &Desc, NULL, &SwapChain);
    ok(hr == DXGI_ERROR_INVALID_CALL, "DXGI_SCALING_NONE: %08lx\n", hr);
    ok(SwapChain == NULL, "DXGI_SCALING_NONE gave %p\n", SwapChain);

    FillCompositionDesc(&Desc, 0, 32);
    SwapChain = NULL;
    hr = IDXGIFactory2_CreateSwapChainForComposition(Factory, (IUnknown *)Device, &Desc, NULL, &SwapChain);
    ok(hr == DXGI_ERROR_INVALID_CALL, "width 0: %08lx\n", hr);
    ok(SwapChain == NULL, "width 0 gave %p\n", SwapChain);

    /* a valid one */
    FillCompositionDesc(&Desc, 64, 32);
    Desc.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED;
    SwapChain = NULL;
    hr = IDXGIFactory2_CreateSwapChainForComposition(Factory, (IUnknown *)Device, &Desc, NULL, &SwapChain);
    ok(hr == S_OK, "CreateSwapChainForComposition returned %08lx\n", hr);
    if (SUCCEEDED(hr))
    {
        Window = (HWND)(ULONG_PTR)0xdeadbeef;
        hr = IDXGISwapChain1_GetHwnd(SwapChain, &Window);
        ok(hr == DXGI_ERROR_INVALID_CALL, "GetHwnd returned %08lx\n", hr);

        memset(&Got, 0xcc, sizeof(Got));
        hr = IDXGISwapChain1_GetDesc1(SwapChain, &Got);
        ok(hr == S_OK, "GetDesc1 returned %08lx\n", hr);
        ok(Got.Width == 64 && Got.Height == 32, "size %ux%u\n", Got.Width, Got.Height);
        ok(Got.Format == DXGI_FORMAT_B8G8R8A8_UNORM, "format %#x\n", Got.Format);
        ok(Got.BufferCount == 2, "buffer count %u\n", Got.BufferCount);
        ok(Got.SwapEffect == DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL, "swap effect %#x\n", Got.SwapEffect);
        ok(Got.Scaling == DXGI_SCALING_STRETCH, "scaling %#x\n", Got.Scaling);
        ok(Got.Flags == 0, "flags %#x\n", Got.Flags);

        memset(&Got0, 0xcc, sizeof(Got0));
        hr = IDXGISwapChain1_GetDesc(SwapChain, &Got0);
        ok(hr == S_OK, "GetDesc returned %08lx\n", hr);
        ok(Got0.OutputWindow == NULL, "output window %p\n", Got0.OutputWindow);
        ok(Got0.Windowed == TRUE, "windowed %d\n", Got0.Windowed);

        hr = IDXGISwapChain1_GetBuffer(SwapChain, 0, &IID_ID3D11Texture2D, (void **)&Buffer);
        ok(hr == S_OK, "GetBuffer returned %08lx\n", hr);
        if (SUCCEEDED(hr))
            ID3D11Texture2D_Release(Buffer);

        /* not shown anywhere yet: presenting still works */
        hr = IDXGISwapChain1_Present(SwapChain, 0, 0);
        ok(hr == S_OK, "Present returned %08lx\n", hr);

        hr = IDXGISwapChain1_ResizeBuffers(SwapChain, 0, 0, 0, DXGI_FORMAT_UNKNOWN, 0);
        ok(hr == E_INVALIDARG, "ResizeBuffers to size 0 returned %08lx\n", hr);
        hr = IDXGISwapChain1_ResizeBuffers(SwapChain, 2, 80, 48, DXGI_FORMAT_B8G8R8A8_UNORM, 0);
        ok(hr == S_OK, "ResizeBuffers returned %08lx\n", hr);
        hr = IDXGISwapChain1_GetDesc1(SwapChain, &Got);
        ok(hr == S_OK, "GetDesc1 returned %08lx\n", hr);
        ok(Got.Width == 80 && Got.Height == 48, "size after resize %ux%u\n", Got.Width, Got.Height);
        ok(Got.Flags == 0, "flags after resize %#x\n", Got.Flags);

        IDXGISwapChain1_Release(SwapChain);
    }

    IDXGIFactory2_Release(Factory);
    ID3D11Device_Release(Device);
}
