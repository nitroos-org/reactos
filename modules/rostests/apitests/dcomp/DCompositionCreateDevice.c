/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for DCompositionCreateDevice and the IDCompositionDevice it makes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The device of DCompositionCreateDevice (with no DXGI device, as a software renderer calls it) makes one
 * target per window and layer, visuals that form a tree, and shows a composition swap chain set as content
 * of a committed visual in the target window. The pixel is read from the screen, where Windows composes it.
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
#define COBJMACROS
#include <initguid.h>
#include <d3d11.h>
#include <dxgi1_6.h>
#include "../../../../dll/win32/dcomp/dcomp_private.h"
#include "../dxgi/composition_common.h"

#define MY_DCOMPOSITION_ERROR_WINDOW_ALREADY_COMPOSED ((HRESULT)0x88980800)

#define Device_Commit(p) (p)->lpVtbl->Commit(p)
#define Device_CreateTargetForHwnd(p, a, b, c) (p)->lpVtbl->CreateTargetForHwnd(p, a, b, c)
#define Device_CreateVisual(p, a) (p)->lpVtbl->CreateVisual(p, a)
#define Device_CheckDeviceState(p, a) (p)->lpVtbl->CheckDeviceState(p, a)
#define Device_GetFrameStatistics(p, a) (p)->lpVtbl->GetFrameStatistics(p, a)
#define Target_SetRoot(p, a) (p)->lpVtbl->SetRoot(p, a)
#define Visual_SetContent(p, a) (p)->lpVtbl->SetContent(p, a)
#define Visual_SetOffsetX(p, a) (p)->lpVtbl->SetOffsetX(p, a)
#define Visual_SetOffsetY(p, a) (p)->lpVtbl->SetOffsetY(p, a)
#define Visual_AddVisual(p, a, b, c) (p)->lpVtbl->AddVisual(p, a, b, c)
#define Visual_RemoveVisual(p, a) (p)->lpVtbl->RemoveVisual(p, a)

typedef HRESULT (WINAPI *PFN_CREATE_DEVICE)(IDXGIDevice *, REFIID, void **);

static PFN_CREATE_DEVICE s_pCreateDevice;

static HWND CreateTestWindow(void)
{
    HWND Window = CreateWindowExW(WS_EX_TOPMOST, L"static", L"dcomp", WS_POPUP | WS_VISIBLE, 40, 40, 200, 120,
                                  NULL, NULL, NULL, NULL);
    MSG Msg;

    UpdateWindow(Window);
    while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageW(&Msg);
    return Window;
}

static void Pump(DWORD Ms)
{
    DWORD Start = GetTickCount();
    MSG Msg;

    do
    {
        while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&Msg);
        Sleep(10);
    } while (GetTickCount() - Start < Ms);
}

static COLORREF ScreenPixel(HWND Window, int X, int Y)
{
    POINT Pt = { X, Y };
    COLORREF Color;
    HDC Dc;

    ClientToScreen(Window, &Pt);
    Dc = GetDC(NULL);
    Color = GetPixel(Dc, Pt.x, Pt.y);
    ReleaseDC(NULL, Dc);
    return Color;
}

static void TestObjects(IDCompositionDevice *Device)
{
    IDCompositionTarget *Target, *Target2, *Target3;
    IDCompositionVisual *Visual, *Child;
    DCOMPOSITION_FRAME_STATISTICS Stats;
    LARGE_INTEGER Frequency;
    IUnknown *Unk;
    BOOL Valid;
    HWND Window;
    HRESULT hr;

    Unk = (IUnknown *)(ULONG_PTR)0xdeadbeef;
    hr = IDCompositionDevice_QueryInterface(Device, &IID_IDCompositionTarget, (void **)&Unk);
    ok(hr == E_NOINTERFACE, "QueryInterface(IDCompositionTarget) returned %08lx\n", hr);
    ok(Unk == NULL, "QueryInterface left %p\n", Unk);

    Valid = FALSE;
    hr = Device_CheckDeviceState(Device, &Valid);
    ok(hr == S_OK, "CheckDeviceState returned %08lx\n", hr);
    ok(Valid == TRUE, "device not valid\n");

    QueryPerformanceFrequency(&Frequency);
    memset(&Stats, 0, sizeof(Stats));
    hr = Device_GetFrameStatistics(Device, &Stats);
    ok(hr == S_OK, "GetFrameStatistics returned %08lx\n", hr);
    ok(Stats.timeFrequency.QuadPart == Frequency.QuadPart, "time frequency %I64d, QPC %I64d\n",
       Stats.timeFrequency.QuadPart, Frequency.QuadPart);
    ok(Stats.currentTime.QuadPart != 0, "current time is 0\n");

    Window = CreateTestWindow();
    hr = Device_CreateTargetForHwnd(Device, Window, TRUE, &Target);
    ok(hr == S_OK, "CreateTargetForHwnd returned %08lx\n", hr);
    if (FAILED(hr))
    {
        DestroyWindow(Window);
        return;
    }
    /* one target per window and layer */
    Target2 = (IDCompositionTarget *)(ULONG_PTR)0xdeadbeef;
    hr = Device_CreateTargetForHwnd(Device, Window, TRUE, &Target2);
    ok(hr == MY_DCOMPOSITION_ERROR_WINDOW_ALREADY_COMPOSED, "second topmost target: %08lx\n", hr);
    hr = Device_CreateTargetForHwnd(Device, Window, FALSE, &Target3);
    ok(hr == S_OK, "bottom target: %08lx\n", hr);
    if (SUCCEEDED(hr))
        IDCompositionTarget_Release(Target3);

    hr = Device_CreateVisual(Device, &Visual);
    ok(hr == S_OK, "CreateVisual returned %08lx\n", hr);
    hr = Device_CreateVisual(Device, &Child);
    ok(hr == S_OK, "CreateVisual returned %08lx\n", hr);
    if (Visual && Child)
    {
        hr = Visual_AddVisual(Visual, Child, TRUE, NULL);
        ok(hr == S_OK, "AddVisual returned %08lx\n", hr);
        hr = Visual_RemoveVisual(Visual, Child);
        ok(hr == S_OK, "RemoveVisual returned %08lx\n", hr);

        hr = Target_SetRoot(Target, Visual);
        ok(hr == S_OK, "SetRoot returned %08lx\n", hr);
        hr = Target_SetRoot(Target, NULL);
        ok(hr == S_OK, "SetRoot(NULL) returned %08lx\n", hr);
        hr = Device_Commit(Device);
        ok(hr == S_OK, "Commit returned %08lx\n", hr);

        IDCompositionVisual_Release(Child);
        IDCompositionVisual_Release(Visual);
    }

    IDCompositionTarget_Release(Target);
    DestroyWindow(Window);
}

static void TestShowSwapChain(IDCompositionDevice *Device)
{
    static const float Red[4] = { 1.0f, 0.0f, 0.0f, 1.0f };
    static const float Blue[4] = { 0.0f, 0.0f, 1.0f, 1.0f };
    ID3D11RenderTargetView *View;
    ID3D11DeviceContext *Context;
    IDXGISwapChain1 *SwapChain;
    IDCompositionTarget *Target;
    IDCompositionVisual *Visual;
    DXGI_SWAP_CHAIN_DESC1 Desc;
    ID3D11Texture2D *Buffer;
    IDXGIFactory2 *Factory;
    ID3D11Device *D3D;
    COLORREF Color;
    HWND Window;
    HRESULT hr;

    D3D = CreateD3D11Device();
    if (!D3D)
    {
        skip("no Direct3D 11 device\n");
        return;
    }
    hr = CreateDXGIFactory1(&IID_IDXGIFactory2, (void **)&Factory);
    ok(hr == S_OK, "CreateDXGIFactory1 returned %08lx\n", hr);
    if (FAILED(hr))
    {
        ID3D11Device_Release(D3D);
        return;
    }
    FillCompositionDesc(&Desc, 100, 60);
    hr = IDXGIFactory2_CreateSwapChainForComposition(Factory, (IUnknown *)D3D, &Desc, NULL, &SwapChain);
    ok(hr == S_OK, "CreateSwapChainForComposition returned %08lx\n", hr);
    if (FAILED(hr))
    {
        IDXGIFactory2_Release(Factory);
        ID3D11Device_Release(D3D);
        return;
    }

    Window = CreateTestWindow();
    hr = Device_CreateTargetForHwnd(Device, Window, TRUE, &Target);
    ok(hr == S_OK, "CreateTargetForHwnd returned %08lx\n", hr);
    hr = Device_CreateVisual(Device, &Visual);
    ok(hr == S_OK, "CreateVisual returned %08lx\n", hr);
    if (SUCCEEDED(hr) && Target)
    {
        hr = Visual_SetOffsetX(Visual, 20.0f);
        ok(hr == S_OK, "SetOffsetX returned %08lx\n", hr);
        hr = Visual_SetOffsetY(Visual, 10.0f);
        ok(hr == S_OK, "SetOffsetY returned %08lx\n", hr);
        hr = Visual_SetContent(Visual, (IUnknown *)SwapChain);
        ok(hr == S_OK, "SetContent returned %08lx\n", hr);
        hr = Target_SetRoot(Target, Visual);
        ok(hr == S_OK, "SetRoot returned %08lx\n", hr);
        hr = Device_Commit(Device);
        ok(hr == S_OK, "Commit returned %08lx\n", hr);

        ID3D11Device_GetImmediateContext(D3D, &Context);
        hr = IDXGISwapChain1_GetBuffer(SwapChain, 0, &IID_ID3D11Texture2D, (void **)&Buffer);
        ok(hr == S_OK, "GetBuffer returned %08lx\n", hr);
        if (SUCCEEDED(hr))
        {
            hr = ID3D11Device_CreateRenderTargetView(D3D, (ID3D11Resource *)Buffer, NULL, &View);
            ok(hr == S_OK, "CreateRenderTargetView returned %08lx\n", hr);
            if (SUCCEEDED(hr))
            {
                ID3D11DeviceContext_ClearRenderTargetView(Context, View, Red);
                ID3D11RenderTargetView_Release(View);
            }
            ID3D11Texture2D_Release(Buffer);
        }
        hr = IDXGISwapChain1_Present(SwapChain, 0, 0);
        ok(hr == S_OK, "Present returned %08lx\n", hr);
        Pump(500);

        /* the content sits at the offset of its visual, and is not stretched to the window */
        Color = ScreenPixel(Window, 25, 15);
        ok(Color == RGB(255, 0, 0), "pixel in the content is %06lx\n", Color);
        Color = ScreenPixel(Window, 5, 5);
        ok(Color != RGB(255, 0, 0), "pixel left of the content is red\n");
        Color = ScreenPixel(Window, 150, 100);
        ok(Color != RGB(255, 0, 0), "pixel right of the content is red\n");

        /* a new frame */
        hr = IDXGISwapChain1_GetBuffer(SwapChain, 0, &IID_ID3D11Texture2D, (void **)&Buffer);
        ok(hr == S_OK, "GetBuffer returned %08lx\n", hr);
        if (SUCCEEDED(hr))
        {
            hr = ID3D11Device_CreateRenderTargetView(D3D, (ID3D11Resource *)Buffer, NULL, &View);
            if (SUCCEEDED(hr))
            {
                ID3D11DeviceContext_ClearRenderTargetView(Context, View, Blue);
                ID3D11RenderTargetView_Release(View);
            }
            ID3D11Texture2D_Release(Buffer);
        }
        hr = IDXGISwapChain1_Present(SwapChain, 0, 0);
        ok(hr == S_OK, "Present returned %08lx\n", hr);
        Pump(500);
        Color = ScreenPixel(Window, 25, 15);
        ok(Color == RGB(0, 0, 255), "pixel after the second frame is %06lx\n", Color);

        ID3D11DeviceContext_Release(Context);
        IDCompositionVisual_Release(Visual);
    }
    if (Target)
        IDCompositionTarget_Release(Target);
    DestroyWindow(Window);
    IDXGISwapChain1_Release(SwapChain);
    IDXGIFactory2_Release(Factory);
    ID3D11Device_Release(D3D);
}

/* Clear buffer 0 of the swap chain to a colour and present it. */
static void PaintAndPresent(ID3D11Device *D3D, IDXGISwapChain1 *SwapChain, const float Color[4])
{
    ID3D11RenderTargetView *View;
    ID3D11DeviceContext *Context;
    ID3D11Texture2D *Buffer;
    HRESULT hr;

    ID3D11Device_GetImmediateContext(D3D, &Context);
    hr = IDXGISwapChain1_GetBuffer(SwapChain, 0, &IID_ID3D11Texture2D, (void **)&Buffer);
    ok(hr == S_OK, "GetBuffer returned %08lx\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = ID3D11Device_CreateRenderTargetView(D3D, (ID3D11Resource *)Buffer, NULL, &View);
        ok(hr == S_OK, "CreateRenderTargetView returned %08lx\n", hr);
        if (SUCCEEDED(hr))
        {
            ID3D11DeviceContext_ClearRenderTargetView(Context, View, Color);
            ID3D11RenderTargetView_Release(View);
        }
        ID3D11Texture2D_Release(Buffer);
    }
    ID3D11DeviceContext_Release(Context);
    hr = IDXGISwapChain1_Present(SwapChain, 0, 0);
    ok(hr == S_OK, "Present returned %08lx\n", hr);
}

/* The target goes before the swap chain: once it is released, presenting must not paint into its window.
 * Then the swap chain is released with no buffer reference outstanding, on this thread and on another one
 * that never pumps messages, and its helper window must be gone. */
static void TestReleaseOrder(IDCompositionDevice *Device)
{
    static const float Red[4] = { 1.0f, 0.0f, 0.0f, 1.0f };
    static const float Blue[4] = { 0.0f, 0.0f, 1.0f, 1.0f };
    IDXGISwapChain1 *SwapChain;
    IDCompositionTarget *Target;
    IDCompositionVisual *Visual;
    DXGI_SWAP_CHAIN_DESC1 Desc;
    IDXGIFactory2 *Factory;
    ID3D11Device *D3D;
    int Baseline, Pass;
    COLORREF Color;
    HWND Window;
    HRESULT hr;

    D3D = CreateD3D11Device();
    if (!D3D)
    {
        skip("no Direct3D 11 device\n");
        return;
    }
    hr = CreateDXGIFactory1(&IID_IDXGIFactory2, (void **)&Factory);
    ok(hr == S_OK, "CreateDXGIFactory1 returned %08lx\n", hr);
    if (FAILED(hr))
    {
        ID3D11Device_Release(D3D);
        return;
    }

    /* windows of swap chains released earlier go away on their own */
    ok(WaitForCompositionWindows(0), "%d helper windows before the test\n", CountCompositionWindows());
    Baseline = 0;
    for (Pass = 0; Pass < 3; Pass++)
    {
        FillCompositionDesc(&Desc, 100, 60);
        hr = IDXGIFactory2_CreateSwapChainForComposition(Factory, (IUnknown *)D3D, &Desc, NULL, &SwapChain);
        ok(hr == S_OK, "CreateSwapChainForComposition returned %08lx\n", hr);
        if (FAILED(hr))
            break;

        Window = CreateTestWindow();
        hr = Device_CreateTargetForHwnd(Device, Window, TRUE, &Target);
        ok(hr == S_OK, "CreateTargetForHwnd returned %08lx\n", hr);
        hr = Device_CreateVisual(Device, &Visual);
        ok(hr == S_OK, "CreateVisual returned %08lx\n", hr);
        if (FAILED(hr) || !Target)
        {
            IDXGISwapChain1_Release(SwapChain);
            DestroyWindow(Window);
            break;
        }
        Visual_SetContent(Visual, (IUnknown *)SwapChain);
        Target_SetRoot(Target, Visual);
        hr = Device_Commit(Device);
        ok(hr == S_OK, "Commit returned %08lx\n", hr);

        PaintAndPresent(D3D, SwapChain, Red);
        Pump(300);
        Color = ScreenPixel(Window, 25, 15);
        ok(Color == RGB(255, 0, 0), "pass %d: pixel in the content is %06lx\n", Pass, Color);

        /* the target first, while the visual still holds the swap chain */
        IDCompositionTarget_Release(Target);
        PaintAndPresent(D3D, SwapChain, Blue);
        Pump(300);
        Color = ScreenPixel(Window, 25, 15);
        ok(Color != RGB(0, 0, 255), "pass %d: swap chain painted into the window of a released target\n", Pass);

        IDCompositionVisual_Release(Visual);
        /* the last reference, none of the buffers is held */
        if (Pass == 2)
            ReleaseOnOtherThread((IUnknown *)SwapChain);
        else
            IDXGISwapChain1_Release(SwapChain);
        ok(WaitForCompositionWindows(Baseline), "pass %d: %d helper windows left, expected %d\n",
           Pass, CountCompositionWindows(), Baseline);
        DestroyWindow(Window);
    }

    IDXGIFactory2_Release(Factory);
    ID3D11Device_Release(D3D);
}

START_TEST(DCompositionCreateDevice)
{
    IDCompositionDevice *Device;
    HMODULE Module;
    void *Obj;
    HRESULT hr;

    Module = LoadLibraryW(L"dcomp.dll");
    s_pCreateDevice = Module ? (PFN_CREATE_DEVICE)GetProcAddress(Module, "DCompositionCreateDevice") : NULL;
    if (!s_pCreateDevice)
    {
        skip("no DCompositionCreateDevice\n");
        return;
    }

    Obj = (void *)(ULONG_PTR)0xdeadbeef;
    hr = s_pCreateDevice(NULL, &IID_IDCompositionVisual, &Obj);
    ok(hr == E_NOINTERFACE, "IDCompositionVisual: %08lx\n", hr);
    ok(Obj == NULL, "IDCompositionVisual gave %p\n", Obj);

    Device = NULL;
    hr = s_pCreateDevice(NULL, &IID_IDCompositionDevice, (void **)&Device);
    ok(hr == S_OK, "DCompositionCreateDevice returned %08lx\n", hr);
    if (FAILED(hr) || !Device)
        return;

    TestObjects(Device);
    TestShowSwapChain(Device);
    TestReleaseOrder(Device);
    IDCompositionDevice_Release(Device);
}
