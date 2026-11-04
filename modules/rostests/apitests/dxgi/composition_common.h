/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Helpers shared by the composition swap chain tests
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

/* a Direct3D 11 device: hardware, else WARP; NULL when neither exists */
static ID3D11Device *CreateD3D11Device(void)
{
    static const D3D_DRIVER_TYPE Types[] = { D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP };
    ID3D11Device *Device = NULL;
    UINT i;

    for (i = 0; i < ARRAYSIZE(Types); i++)
    {
        if (SUCCEEDED(D3D11CreateDevice(NULL, Types[i], NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                                        D3D11_SDK_VERSION, &Device, NULL, NULL)))
            return Device;
    }
    return NULL;
}

static void FillCompositionDesc(DXGI_SWAP_CHAIN_DESC1 *Desc, UINT Width, UINT Height)
{
    ZeroMemory(Desc, sizeof(*Desc));
    Desc->Width = Width;
    Desc->Height = Height;
    Desc->Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    Desc->SampleDesc.Count = 1;
    Desc->BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    Desc->BufferCount = 2;
    Desc->Scaling = DXGI_SCALING_STRETCH;
    Desc->SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    Desc->AlphaMode = DXGI_ALPHA_MODE_IGNORE;
}
