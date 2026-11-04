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

/* The helper window of a composition swap chain lives until the swap chain is released, whichever thread
 * does it. On Windows there is no such window, so the count stays the same. */
static BOOL CALLBACK CountCompositionWindowProc(HWND Window, LPARAM Param)
{
    WCHAR Class[64];

    if (GetClassNameW(Window, Class, ARRAYSIZE(Class)) && !lstrcmpW(Class, L"WineDXGICompositionWindow"))
        ++*(int *)Param;
    return TRUE;
}

static int CountCompositionWindows(void)
{
    int Count = 0;

    EnumWindows(CountCompositionWindowProc, (LPARAM)&Count);
    return Count;
}

/* no message is pumped here: the window must go without help from this thread */
static BOOL WaitForCompositionWindows(int Expected)
{
    DWORD Start = GetTickCount();

    while (CountCompositionWindows() != Expected)
    {
        if (GetTickCount() - Start > 5000)
            return FALSE;
        Sleep(20);
    }
    return TRUE;
}

static DWORD WINAPI ReleaseThreadProc(void *Param)
{
    IUnknown_Release((IUnknown *)Param);
    return 0;
}

static void ReleaseOnOtherThread(IUnknown *Object)
{
    HANDLE Thread = CreateThread(NULL, 0, ReleaseThreadProc, Object, 0, NULL);

    if (Thread)
    {
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
    }
    else
    {
        IUnknown_Release(Object);
    }
}
