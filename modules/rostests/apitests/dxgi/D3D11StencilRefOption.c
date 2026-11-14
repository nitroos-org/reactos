/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A device that reports PSSpecifiedStencilRefSupported can create a shader that writes SV_StencilRef
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A pixel shader that writes SV_StencilRef is shader model 5, so a device below feature level 11_0 cannot
 * create it. ID3D11Device::CheckFeatureSupport(D3D11_FEATURE_D3D11_OPTIONS2) used to report the driver's
 * stencil export alone, so on a driver without a level 11 device (here softpipe, which lacks the extensions
 * that give level 11) a program that trusted the option got E_INVALIDARG from CreatePixelShader, and
 * d3d11_winetest test_stencil_export then used the NULL shader and crashed.
 * The test checks only that the option is consistent with what the device can create; it does not assert what
 * Windows reports at a given feature level.
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#define COBJMACROS
#include <d3d11.h>

/* ps_5_0: uint main() : SV_StencilRef { return stencil_ref; } with a constant buffer "uint stencil_ref"
 * (the shader of d3d11_winetest test_stencil_export) */
static const DWORD g_PsStencilRef[] =
{
    0x43425844, 0x3980cb16, 0xbbe87d38, 0xb93f7c61, 0x200c41ed, 0x00000001, 0x000000cc, 0x00000004,
    0x00000030, 0x00000040, 0x00000078, 0x000000bc, 0x4e475349, 0x00000008, 0x00000000, 0x00000008,
    0x4e47534f, 0x00000030, 0x00000001, 0x00000008, 0x00000020, 0x00000000, 0x00000000, 0x00000001,
    0xffffffff, 0x00000e01, 0x535f5653, 0x636e6574, 0x65526c69, 0xabab0066, 0x58454853, 0x0000003c,
    0x00000050, 0x0000000f, 0x0100086a, 0x04000059, 0x00208e46, 0x00000000, 0x00000001, 0x02000065,
    0x00029001, 0x05000036, 0x00029001, 0x0020800a, 0x00000000, 0x00000000, 0x0100003e, 0x30494653,
    0x00000008, 0x00000200, 0x00000000,
};

static const D3D_FEATURE_LEVEL g_Levels[] =
{
    D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0,
    D3D_FEATURE_LEVEL_9_3, D3D_FEATURE_LEVEL_9_2, D3D_FEATURE_LEVEL_9_1,
};

static void TestLevel(D3D_DRIVER_TYPE Type, D3D_FEATURE_LEVEL Requested)
{
    D3D11_FEATURE_DATA_D3D11_OPTIONS2 Options = {0};
    D3D_FEATURE_LEVEL Got = 0;
    ID3D11PixelShader *Ps = NULL;
    ID3D11Device *Dev = NULL;
    HRESULT hr, hrOptions, hrPs;

    hr = D3D11CreateDevice(NULL, Type, NULL, 0, &Requested, 1, D3D11_SDK_VERSION, &Dev, &Got, NULL);
    if (FAILED(hr))
        return;
    ok(Got == Requested, "type %d: level %#x requested, got %#x\n", Type, Requested, Got);

    hrOptions = ID3D11Device_CheckFeatureSupport(Dev, D3D11_FEATURE_D3D11_OPTIONS2, &Options, sizeof(Options));
    if (SUCCEEDED(hrOptions) && Options.PSSpecifiedStencilRefSupported)
    {
        hrPs = ID3D11Device_CreatePixelShader(Dev, g_PsStencilRef, sizeof(g_PsStencilRef), NULL, &Ps);
        ok(hrPs == S_OK, "type %d level %#x: PSSpecifiedStencilRefSupported, but CreatePixelShader returned %#lx\n",
           Type, Got, hrPs);
        if (Ps)
            ID3D11PixelShader_Release(Ps);
    }
    ID3D11Device_Release(Dev);
}

START_TEST(D3D11StencilRefOption)
{
    static const D3D_DRIVER_TYPE Types[] = { D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP };
    unsigned int t, i;

    for (t = 0; t < ARRAYSIZE(Types); t++)
        for (i = 0; i < ARRAYSIZE(g_Levels); i++)
            TestLevel(Types[t], g_Levels[i]);
}
