/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for IDXGIFactory4::EnumWarpAdapter
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and WOW64) without a graphics driver. There DXGI lists two adapters,
 * both the Microsoft Basic Render Driver (1414:008c): the first has flags 0, the second is WARP, with a
 * LUID of its own and DXGI_ADAPTER_FLAG_SOFTWARE. EnumWarpAdapter returns a new object for the second
 * one on every call, never the first adapter, whatever the interface asked for (IDXGIAdapter, 1, 4).
 * EnumAdapters, EnumAdapters1 and EnumAdapterByGpuPreference list WARP last, after the display adapter(s):
 * the same identity as EnumWarpAdapter returns (LUID, flags), and no other listed adapter is software.
 * Programs that want WARP walk that list for DXGI_ADAPTER_FLAG_SOFTWARE (Microsoft Office does).
 * No adapter of that machine has an output (EnumOutputs fails with DXGI_ERROR_NOT_CURRENTLY_AVAILABLE).
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#define COBJMACROS
#include <dxgi1_6.h>

/* what the adapters of the Windows machine answer: it has no display, and no output to list */
#define MY_DXGI_ERROR_NOT_CURRENTLY_AVAILABLE ((HRESULT)0x887A0022)

static const GUID s_Bogus = { 0x11223344, 0x5566, 0x7788, { 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01 } };
static const WCHAR s_Brd[] = L"Microsoft Basic Render Driver";

typedef HRESULT (WINAPI *PFN_D3D11_CREATE_DEVICE)(IDXGIAdapter *, UINT, HMODULE, UINT, const UINT *, UINT, UINT,
                                                  void **, UINT *, void **);

static BOOL SameLuid(LUID A, LUID B)
{
    return A.LowPart == B.LowPart && A.HighPart == B.HighPart;
}

static void TestWarpAdapter(IDXGIFactory4 *Factory, IDXGIFactory1 *Factory1)
{
    IDXGIAdapter1 *Warp = NULL, *Warp2 = NULL, *Adapter, *ByLuid = NULL;
    IDXGIAdapter *Plain = NULL;
    IDXGIAdapter2 *Warp2If = NULL;
    IDXGIAdapter4 *Warp4 = NULL;
    IDXGIFactory *Parent = NULL;
    IDXGIOutput *Output = NULL;
    IUnknown *Unk = NULL, *Unk2 = NULL, *Junk;
    DXGI_ADAPTER_DESC1 Desc1, OtherDesc;
    DXGI_ADAPTER_DESC2 Desc2;
    DXGI_ADAPTER_DESC3 Desc3;
    DXGI_ADAPTER_DESC Desc0;
    LARGE_INTEGER Umd;
    HRESULT hr;
    UINT i;

    hr = IDXGIFactory4_EnumWarpAdapter(Factory, &IID_IDXGIAdapter1, (void **)&Warp);
    ok(hr == S_OK, "EnumWarpAdapter returned %08lx\n", hr);
    if (hr != S_OK || !Warp)
    {
        skip("no WARP adapter\n");
        return;
    }

    memset(&Desc1, 0xcc, sizeof(Desc1));
    hr = IDXGIAdapter1_GetDesc1(Warp, &Desc1);
    ok(hr == S_OK, "GetDesc1 returned %08lx\n", hr);
    ok(wcscmp(Desc1.Description, s_Brd) == 0, "Description is '%ls'\n", Desc1.Description);
    ok(Desc1.VendorId == 0x1414, "VendorId is %04x\n", Desc1.VendorId);
    ok(Desc1.DeviceId == 0x008c, "DeviceId is %04x\n", Desc1.DeviceId);
    ok(Desc1.SubSysId == 0, "SubSysId is %08x\n", Desc1.SubSysId);
    ok(Desc1.Revision == 0, "Revision is %u\n", Desc1.Revision);
    ok(Desc1.DedicatedVideoMemory == 0, "DedicatedVideoMemory is %Iu\n", (SIZE_T)Desc1.DedicatedVideoMemory);
    ok(Desc1.DedicatedSystemMemory == 0, "DedicatedSystemMemory is %Iu\n", (SIZE_T)Desc1.DedicatedSystemMemory);
    ok(Desc1.SharedSystemMemory != 0, "SharedSystemMemory is 0\n");
    ok(Desc1.Flags == DXGI_ADAPTER_FLAG_SOFTWARE, "Flags are %#x\n", Desc1.Flags);
    ok(Desc1.AdapterLuid.LowPart != 0 || Desc1.AdapterLuid.HighPart != 0, "the LUID is empty\n");

    hr = IDXGIAdapter1_GetDesc(Warp, &Desc0);
    ok(hr == S_OK, "GetDesc returned %08lx\n", hr);
    ok(wcscmp(Desc0.Description, s_Brd) == 0, "Description of GetDesc is '%ls'\n", Desc0.Description);
    ok(Desc0.VendorId == 0x1414 && Desc0.DeviceId == 0x008c, "GetDesc ids are %04x:%04x\n",
       Desc0.VendorId, Desc0.DeviceId);
    ok(SameLuid(Desc0.AdapterLuid, Desc1.AdapterLuid), "GetDesc LUID differs from GetDesc1\n");

    hr = IDXGIAdapter1_QueryInterface(Warp, &IID_IDXGIAdapter2, (void **)&Warp2If);
    ok(hr == S_OK, "QueryInterface(IDXGIAdapter2) returned %08lx\n", hr);
    if (Warp2If)
    {
        memset(&Desc2, 0xcc, sizeof(Desc2));
        hr = IDXGIAdapter2_GetDesc2(Warp2If, &Desc2);
        ok(hr == S_OK, "GetDesc2 returned %08lx\n", hr);
        ok(Desc2.Flags == DXGI_ADAPTER_FLAG_SOFTWARE, "GetDesc2 flags are %#x\n", Desc2.Flags);
        ok(Desc2.GraphicsPreemptionGranularity == DXGI_GRAPHICS_PREEMPTION_INSTRUCTION_BOUNDARY,
           "graphics preemption is %d\n", Desc2.GraphicsPreemptionGranularity);
        ok(Desc2.ComputePreemptionGranularity == DXGI_COMPUTE_PREEMPTION_INSTRUCTION_BOUNDARY,
           "compute preemption is %d\n", Desc2.ComputePreemptionGranularity);
        ok(SameLuid(Desc2.AdapterLuid, Desc1.AdapterLuid), "GetDesc2 LUID differs from GetDesc1\n");
        IDXGIAdapter2_Release(Warp2If);
    }

    hr = IDXGIAdapter1_QueryInterface(Warp, &IID_IDXGIAdapter4, (void **)&Warp4);
    ok(hr == S_OK, "QueryInterface(IDXGIAdapter4) returned %08lx\n", hr);
    if (Warp4)
    {
        memset(&Desc3, 0xcc, sizeof(Desc3));
        hr = IDXGIAdapter4_GetDesc3(Warp4, &Desc3);
        ok(hr == S_OK, "GetDesc3 returned %08lx\n", hr);
        /* Windows adds the Direct3D 12 capabilities (0x2e), which ReactOS does not claim */
        ok(Desc3.Flags & DXGI_ADAPTER_FLAG3_SOFTWARE, "GetDesc3 flags are %#x\n", Desc3.Flags);
        ok(Desc3.GraphicsPreemptionGranularity == DXGI_GRAPHICS_PREEMPTION_INSTRUCTION_BOUNDARY,
           "graphics preemption is %d\n", Desc3.GraphicsPreemptionGranularity);
        ok(SameLuid(Desc3.AdapterLuid, Desc1.AdapterLuid), "GetDesc3 LUID differs from GetDesc1\n");
        IDXGIAdapter4_Release(Warp4);
    }

    /* it is not any adapter of the list, neither in object nor in LUID */
    for (i = 0; IDXGIFactory1_EnumAdapters1(Factory1, i, &Adapter) == S_OK; i++)
    {
        ok(Adapter != Warp, "adapter %u is the object of EnumWarpAdapter\n", i);
        hr = IDXGIAdapter1_GetDesc1(Adapter, &OtherDesc);
        ok(hr == S_OK, "GetDesc1 of adapter %u returned %08lx\n", i, hr);
        if (!(OtherDesc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE))
            ok(!SameLuid(OtherDesc.AdapterLuid, Desc1.AdapterLuid), "adapter %u has the LUID of WARP\n", i);
        IDXGIAdapter1_Release(Adapter);
    }
    ok(i >= 1, "no adapter listed\n");

    /* a new object on every call, with the same identity */
    hr = IDXGIFactory4_EnumWarpAdapter(Factory, &IID_IDXGIAdapter1, (void **)&Warp2);
    ok(hr == S_OK, "second EnumWarpAdapter returned %08lx\n", hr);
    ok(Warp2 != Warp, "EnumWarpAdapter returned the same object twice\n");
    if (Warp2)
    {
        hr = IDXGIAdapter1_GetDesc1(Warp2, &OtherDesc);
        ok(hr == S_OK && SameLuid(OtherDesc.AdapterLuid, Desc1.AdapterLuid), "the second object has another LUID\n");
        IDXGIAdapter1_Release(Warp2);
    }

    /* other interfaces */
    hr = IDXGIFactory4_EnumWarpAdapter(Factory, &IID_IDXGIAdapter, (void **)&Plain);
    ok(hr == S_OK, "EnumWarpAdapter(IDXGIAdapter) returned %08lx\n", hr);
    if (Plain)
    {
        hr = IDXGIAdapter_GetDesc(Plain, &Desc0);
        ok(hr == S_OK && SameLuid(Desc0.AdapterLuid, Desc1.AdapterLuid), "IDXGIAdapter has another LUID\n");
        IDXGIAdapter_Release(Plain);
    }
    hr = IDXGIFactory4_EnumWarpAdapter(Factory, &IID_IUnknown, (void **)&Unk);
    ok(hr == S_OK && Unk != NULL, "EnumWarpAdapter(IUnknown) returned %08lx\n", hr);
    hr = IDXGIAdapter1_QueryInterface(Warp, &IID_IUnknown, (void **)&Unk2);
    ok(hr == S_OK && Unk2 != NULL, "QueryInterface(IUnknown) returned %08lx\n", hr);
    ok(Unk2 == (IUnknown *)Warp, "the identity differs from the interface\n");
    if (Unk)
        IUnknown_Release(Unk);
    if (Unk2)
        IUnknown_Release(Unk2);

    /* the factory is the parent */
    hr = IDXGIAdapter1_GetParent(Warp, &IID_IDXGIFactory, (void **)&Parent);
    ok(hr == S_OK, "GetParent returned %08lx\n", hr);
    ok(Parent == (IDXGIFactory *)Factory1, "the parent is not the factory\n");
    if (Parent)
        IDXGIFactory_Release(Parent);

    /* it drives no output, and it can be asked what an adapter is asked */
    hr = IDXGIAdapter1_EnumOutputs(Warp, 0, &Output);
    ok(hr == DXGI_ERROR_NOT_FOUND || hr == MY_DXGI_ERROR_NOT_CURRENTLY_AVAILABLE, "EnumOutputs returned %08lx\n", hr);
    /* what a device can be asked of the first adapter is asked of WARP */
    hr = IDXGIAdapter1_CheckInterfaceSupport(Warp, &IID_IDXGIDevice, &Umd);
    if (IDXGIFactory1_EnumAdapters1(Factory1, 0, &Adapter) == S_OK)
    {
        HRESULT hrFirst = IDXGIAdapter1_CheckInterfaceSupport(Adapter, &IID_IDXGIDevice, &Umd);
        ok(hr == hrFirst, "CheckInterfaceSupport returned %08lx, %08lx for the first adapter\n", hr, hrFirst);
        IDXGIAdapter1_Release(Adapter);
    }

    /* it is found by its LUID */
    hr = IDXGIFactory4_EnumAdapterByLuid(Factory, Desc1.AdapterLuid, &IID_IDXGIAdapter1, (void **)&ByLuid);
    ok(hr == S_OK, "EnumAdapterByLuid(WARP) returned %08lx\n", hr);
    if (ByLuid)
    {
        hr = IDXGIAdapter1_GetDesc1(ByLuid, &OtherDesc);
        ok(hr == S_OK && SameLuid(OtherDesc.AdapterLuid, Desc1.AdapterLuid), "EnumAdapterByLuid found another adapter\n");
        ok(wcscmp(OtherDesc.Description, s_Brd) == 0, "found '%ls'\n", OtherDesc.Description);
        IDXGIAdapter1_Release(ByLuid);
    }

    /* failures */
    Junk = (IUnknown *)(ULONG_PTR)0x1234;
    hr = IDXGIFactory4_EnumWarpAdapter(Factory, &IID_IDXGIFactory, (void **)&Junk);
    ok(hr == E_NOINTERFACE, "EnumWarpAdapter(IDXGIFactory) returned %08lx\n", hr);
    ok(Junk == NULL, "the output is %p\n", Junk);
    Junk = (IUnknown *)(ULONG_PTR)0x1234;
    hr = IDXGIFactory4_EnumWarpAdapter(Factory, &s_Bogus, (void **)&Junk);
    ok(hr == E_NOINTERFACE, "EnumWarpAdapter(bogus) returned %08lx\n", hr);
    ok(Junk == NULL, "the output is %p\n", Junk);
    hr = IDXGIFactory4_EnumWarpAdapter(Factory, &IID_IDXGIAdapter1, NULL);
    ok(hr == DXGI_ERROR_INVALID_CALL, "EnumWarpAdapter(NULL) returned %08lx\n", hr);

    /* a device on it belongs to it */
    {
        HMODULE D3d11 = LoadLibraryW(L"d3d11.dll");
        PFN_D3D11_CREATE_DEVICE pCreateDevice = D3d11 ? (PFN_D3D11_CREATE_DEVICE)GetProcAddress(D3d11, "D3D11CreateDevice") : NULL;
        IUnknown *Device = NULL;
        IDXGIDevice *DxgiDevice = NULL;
        IDXGIAdapter *DevAdapter = NULL;

        if (!pCreateDevice)
            skip("no d3d11.dll\n");
        else
        {
            /* D3D_DRIVER_TYPE_UNKNOWN, D3D11_SDK_VERSION */
            hr = pCreateDevice((IDXGIAdapter *)Warp, 0, NULL, 0, NULL, 0, 7, (void **)&Device, NULL, NULL);
            ok(hr == S_OK, "D3D11CreateDevice on WARP returned %08lx\n", hr);
            if (Device)
            {
                hr = IUnknown_QueryInterface(Device, &IID_IDXGIDevice, (void **)&DxgiDevice);
                ok(hr == S_OK, "QueryInterface(IDXGIDevice) returned %08lx\n", hr);
                if (DxgiDevice)
                {
                    hr = IDXGIDevice_GetAdapter(DxgiDevice, &DevAdapter);
                    ok(hr == S_OK, "GetAdapter returned %08lx\n", hr);
                    if (DevAdapter)
                    {
                        hr = IDXGIAdapter_GetDesc(DevAdapter, &Desc0);
                        ok(hr == S_OK && SameLuid(Desc0.AdapterLuid, Desc1.AdapterLuid),
                           "the device is on another adapter (LUID %08lx:%08lx)\n",
                           Desc0.AdapterLuid.HighPart, Desc0.AdapterLuid.LowPart);
                        ok(DevAdapter == (IDXGIAdapter *)Warp, "the device adapter is not the adapter it was made on\n");
                        IDXGIAdapter_Release(DevAdapter);
                    }
                    IDXGIDevice_Release(DxgiDevice);
                }
                IUnknown_Release(Device);
            }
        }
    }

    IDXGIAdapter1_Release(Warp);
}

/* the adapter the factory lists first is usable: a device made on it reports it back, with the same identity */
static void TestAdapterZeroDevice(IDXGIFactory1 *Factory1)
{
    HMODULE D3d11 = LoadLibraryW(L"d3d11.dll");
    PFN_D3D11_CREATE_DEVICE pCreateDevice = D3d11 ? (PFN_D3D11_CREATE_DEVICE)GetProcAddress(D3d11, "D3D11CreateDevice") : NULL;
    IDXGIAdapter1 *Adapter = NULL;
    IDXGIAdapter *DevAdapter = NULL;
    IDXGIDevice *DxgiDevice = NULL;
    IUnknown *Device = NULL;
    DXGI_ADAPTER_DESC1 Desc1;
    DXGI_ADAPTER_DESC Desc0;
    HRESULT hr;

    hr = IDXGIFactory1_EnumAdapters1(Factory1, 0, &Adapter);
    ok(hr == S_OK, "EnumAdapters1(0) returned %08lx\n", hr);
    if (!Adapter)
        return;

    hr = IDXGIAdapter1_GetDesc1(Adapter, &Desc1);
    ok(hr == S_OK, "GetDesc1 returned %08lx\n", hr);
    ok(Desc1.VendorId != 0 || Desc1.Description[0] != 0, "adapter 0 has no identity\n");

    if (!pCreateDevice)
    {
        skip("no d3d11.dll\n");
        IDXGIAdapter1_Release(Adapter);
        return;
    }

    /* D3D_DRIVER_TYPE_UNKNOWN, D3D11_SDK_VERSION */
    hr = pCreateDevice((IDXGIAdapter *)Adapter, 0, NULL, 0, NULL, 0, 7, (void **)&Device, NULL, NULL);
    ok(hr == S_OK, "D3D11CreateDevice on adapter 0 returned %08lx\n", hr);
    if (Device)
    {
        hr = IUnknown_QueryInterface(Device, &IID_IDXGIDevice, (void **)&DxgiDevice);
        ok(hr == S_OK, "QueryInterface(IDXGIDevice) returned %08lx\n", hr);
        if (DxgiDevice)
        {
            hr = IDXGIDevice_GetAdapter(DxgiDevice, &DevAdapter);
            ok(hr == S_OK, "GetAdapter returned %08lx\n", hr);
            if (DevAdapter)
            {
                hr = IDXGIAdapter_GetDesc(DevAdapter, &Desc0);
                ok(hr == S_OK && SameLuid(Desc0.AdapterLuid, Desc1.AdapterLuid),
                   "the device is on another adapter (LUID %08lx:%08lx)\n",
                   Desc0.AdapterLuid.HighPart, Desc0.AdapterLuid.LowPart);
                ok(Desc0.VendorId == Desc1.VendorId && Desc0.DeviceId == Desc1.DeviceId,
                   "the device adapter is %04x:%04x, not %04x:%04x\n",
                   Desc0.VendorId, Desc0.DeviceId, Desc1.VendorId, Desc1.DeviceId);
                IDXGIAdapter_Release(DevAdapter);
            }
            IDXGIDevice_Release(DxgiDevice);
        }
        IUnknown_Release(Device);
    }
    IDXGIAdapter1_Release(Adapter);
}

/* the list ends with WARP: one software adapter, the last one, with the identity of EnumWarpAdapter */
static void TestAdapterList(IDXGIFactory4 *Factory, IDXGIFactory1 *Factory1)
{
    IDXGIAdapter1 *Warp = NULL, *Adapter = NULL;
    IDXGIAdapter *Plain = NULL;
    IDXGIFactory6 *Factory6 = NULL;
    DXGI_ADAPTER_DESC1 WarpDesc, Desc;
    DXGI_ADAPTER_DESC Desc0;
    UINT Count, Software = 0, LastFlags = 0, i, Pref;
    LUID LastLuid = { 0, 0 };
    HRESULT hr;

    hr = IDXGIFactory4_EnumWarpAdapter(Factory, &IID_IDXGIAdapter1, (void **)&Warp);
    ok(hr == S_OK, "EnumWarpAdapter returned %08lx\n", hr);
    if (!Warp)
        return;
    hr = IDXGIAdapter1_GetDesc1(Warp, &WarpDesc);
    ok(hr == S_OK, "GetDesc1 returned %08lx\n", hr);
    IDXGIAdapter1_Release(Warp);

    for (Count = 0; (hr = IDXGIFactory1_EnumAdapters1(Factory1, Count, &Adapter)) == S_OK; Count++)
    {
        memset(&Desc, 0xcc, sizeof(Desc));
        hr = IDXGIAdapter1_GetDesc1(Adapter, &Desc);
        ok(hr == S_OK, "GetDesc1 of adapter %u returned %08lx\n", Count, hr);
        trace("adapter %u: '%ls' %04x:%04x flags %#x LUID %08lx:%08lx\n", Count, Desc.Description, Desc.VendorId,
              Desc.DeviceId, Desc.Flags, Desc.AdapterLuid.HighPart, Desc.AdapterLuid.LowPart);
        if (Desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)
            Software++;
        LastFlags = Desc.Flags;
        LastLuid = Desc.AdapterLuid;
        IDXGIAdapter1_Release(Adapter);
        if (Count > 16)
            break;
    }
    ok(hr == DXGI_ERROR_NOT_FOUND, "EnumAdapters1(%u) returned %08lx\n", Count, hr);
    ok(Count >= 2, "%u adapters listed, expected the display adapter and WARP\n", Count);
    ok(Software == 1, "%u software adapters listed\n", Software);
    ok(LastFlags & DXGI_ADAPTER_FLAG_SOFTWARE, "the last adapter has flags %#x\n", LastFlags);
    ok(SameLuid(LastLuid, WarpDesc.AdapterLuid), "the last adapter is not WARP (LUID %08lx:%08lx)\n",
       LastLuid.HighPart, LastLuid.LowPart);
    Adapter = (IDXGIAdapter1 *)(ULONG_PTR)0x1234;
    hr = IDXGIFactory1_EnumAdapters1(Factory1, Count + 1, &Adapter);
    ok(hr == DXGI_ERROR_NOT_FOUND, "EnumAdapters1(%u) returned %08lx\n", Count + 1, hr);
    ok(Adapter == NULL, "the output is %p\n", Adapter);
    if (Count < 2)
        return;

    /* the last one is WARP in every respect a program checks */
    hr = IDXGIFactory1_EnumAdapters1(Factory1, Count - 1, &Adapter);
    ok(hr == S_OK, "EnumAdapters1(%u) returned %08lx\n", Count - 1, hr);
    if (hr == S_OK && Adapter)
    {
        IDXGIOutput *Output = NULL;

        hr = IDXGIAdapter1_GetDesc1(Adapter, &Desc);
        ok(hr == S_OK, "GetDesc1 returned %08lx\n", hr);
        ok(wcscmp(Desc.Description, s_Brd) == 0, "the last adapter is '%ls'\n", Desc.Description);
        ok(Desc.VendorId == 0x1414 && Desc.DeviceId == 0x8c, "the last adapter is %04x:%04x\n", Desc.VendorId, Desc.DeviceId);
        ok(Desc.DedicatedVideoMemory == WarpDesc.DedicatedVideoMemory, "dedicated memory %Iu, WARP %Iu\n",
           Desc.DedicatedVideoMemory, WarpDesc.DedicatedVideoMemory);
        hr = IDXGIAdapter1_EnumOutputs(Adapter, 0, &Output);
        ok(hr == DXGI_ERROR_NOT_FOUND || hr == MY_DXGI_ERROR_NOT_CURRENTLY_AVAILABLE, "EnumOutputs returned %08lx\n", hr);
        if (hr == S_OK && Output)
            IDXGIOutput_Release(Output);
        IDXGIAdapter1_Release(Adapter);
    }

    /* the first one is the display adapter, never software */
    hr = IDXGIFactory1_EnumAdapters1(Factory1, 0, &Adapter);
    ok(hr == S_OK, "EnumAdapters1(0) returned %08lx\n", hr);
    if (hr == S_OK && Adapter)
    {
        hr = IDXGIAdapter1_GetDesc1(Adapter, &Desc);
        ok(hr == S_OK && !(Desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE), "adapter 0 has flags %#x\n", Desc.Flags);
        ok(!SameLuid(Desc.AdapterLuid, WarpDesc.AdapterLuid), "adapter 0 has the LUID of WARP\n");
        IDXGIAdapter1_Release(Adapter);
    }

    /* IDXGIFactory::EnumAdapters lists the same */
    hr = IDXGIFactory1_EnumAdapters(Factory1, Count - 1, &Plain);
    ok(hr == S_OK, "EnumAdapters(%u) returned %08lx\n", Count - 1, hr);
    if (hr == S_OK && Plain)
    {
        hr = IDXGIAdapter_GetDesc(Plain, &Desc0);
        ok(hr == S_OK && SameLuid(Desc0.AdapterLuid, WarpDesc.AdapterLuid), "EnumAdapters(%u) is not WARP\n", Count - 1);
        IDXGIAdapter_Release(Plain);
    }
    Plain = NULL;
    hr = IDXGIFactory1_EnumAdapters(Factory1, Count, &Plain);
    ok(hr == DXGI_ERROR_NOT_FOUND, "EnumAdapters(%u) returned %08lx\n", Count, hr);
    if (hr == S_OK && Plain)
        IDXGIAdapter_Release(Plain);

    /* and so does EnumAdapterByGpuPreference, whatever the preference */
    hr = IDXGIFactory1_QueryInterface(Factory1, &IID_IDXGIFactory6, (void **)&Factory6);
    ok(hr == S_OK, "QueryInterface(IDXGIFactory6) returned %08lx\n", hr);
    if (hr != S_OK || !Factory6)
        return;
    for (Pref = DXGI_GPU_PREFERENCE_UNSPECIFIED; Pref <= DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE; Pref++)
    {
        LastFlags = 0;
        for (i = 0; (hr = IDXGIFactory6_EnumAdapterByGpuPreference(Factory6, i, Pref, &IID_IDXGIAdapter1,
                                                                     (void **)&Adapter)) == S_OK; i++)
        {
            hr = IDXGIAdapter1_GetDesc1(Adapter, &Desc);
            ok(hr == S_OK, "GetDesc1 returned %08lx\n", hr);
            trace("preference %u adapter %u: flags %#x LUID %08lx:%08lx\n", Pref, i, Desc.Flags,
                  Desc.AdapterLuid.HighPart, Desc.AdapterLuid.LowPart);
            LastFlags = Desc.Flags;
            LastLuid = Desc.AdapterLuid;
            IDXGIAdapter1_Release(Adapter);
            if (i > 16)
                break;
        }
        ok(hr == DXGI_ERROR_NOT_FOUND, "preference %u: EnumAdapterByGpuPreference(%u) returned %08lx\n", Pref, i, hr);
        ok(i == Count, "preference %u: %u adapters, EnumAdapters1 lists %u\n", Pref, i, Count);
        ok((LastFlags & DXGI_ADAPTER_FLAG_SOFTWARE) && SameLuid(LastLuid, WarpDesc.AdapterLuid),
           "preference %u: the last adapter is not WARP\n", Pref);
    }
    IDXGIFactory6_Release(Factory6);
}

/* a 32-bit process on 64-bit ReactOS has the same 3D stack as a 64-bit one */
static BOOL IsWow64(void)
{
    BOOL (WINAPI *pIsWow64Process)(HANDLE, PBOOL) =
        (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
    BOOL Wow64 = FALSE;

    return pIsWow64Process && pIsWow64Process(GetCurrentProcess(), &Wow64) && Wow64;
}

START_TEST(EnumWarpAdapter)
{
    HMODULE Dxgi = LoadLibraryW(L"dxgi.dll");
    HRESULT (WINAPI *pCreateFactory1)(REFIID, void **);
    HRESULT (WINAPI *pCreateFactory)(REFIID, void **);
    IDXGIFactory1 *Factory1 = NULL;
    IDXGIFactory *Factory = NULL;
    IDXGIFactory4 *Factory4 = NULL;
    HRESULT hr;

    ok(Dxgi != NULL, "dxgi.dll does not load, error %lu\n", GetLastError());
    if (!Dxgi)
        return;

    pCreateFactory1 = (void *)GetProcAddress(Dxgi, "CreateDXGIFactory1");
    pCreateFactory = (void *)GetProcAddress(Dxgi, "CreateDXGIFactory");
    ok(pCreateFactory1 != NULL, "CreateDXGIFactory1 is not exported\n");
    if (!pCreateFactory1)
        return;

    hr = pCreateFactory1(&IID_IDXGIFactory1, (void **)&Factory1);
    if (hr == DXGI_ERROR_UNSUPPORTED && !IsWow64())
    {
        /* ReactOS: no 3D adapter. Not acceptable under WoW64, where SysWOW64 ships its own GL driver */
        skip("no DXGI factory, CreateDXGIFactory1 returned %08lx\n", hr);
        return;
    }
    ok(hr == S_OK, "CreateDXGIFactory1 returned %08lx\n", hr);
    if (!Factory1)
        return;

    hr = IDXGIFactory1_QueryInterface(Factory1, &IID_IDXGIFactory4, (void **)&Factory4);
    ok(hr == S_OK, "QueryInterface(IDXGIFactory4) returned %08lx\n", hr);
    if (Factory4)
    {
        TestWarpAdapter(Factory4, Factory1);
        TestAdapterList(Factory4, Factory1);
        IDXGIFactory4_Release(Factory4);
    }
    TestAdapterZeroDevice(Factory1);
    IDXGIFactory1_Release(Factory1);

    /* the factory of CreateDXGIFactory is the same */
    if (pCreateFactory)
    {
        IDXGIAdapter1 *Warp = NULL;

        hr = pCreateFactory(&IID_IDXGIFactory, (void **)&Factory);
        ok(hr == S_OK, "CreateDXGIFactory returned %08lx\n", hr);
        if (Factory)
        {
            hr = IDXGIFactory_QueryInterface(Factory, &IID_IDXGIFactory4, (void **)&Factory4);
            ok(hr == S_OK, "QueryInterface(IDXGIFactory4) returned %08lx\n", hr);
            if (Factory4)
            {
                hr = IDXGIFactory4_EnumWarpAdapter(Factory4, &IID_IDXGIAdapter1, (void **)&Warp);
                ok(hr == S_OK, "EnumWarpAdapter returned %08lx\n", hr);
                if (Warp)
                    IDXGIAdapter1_Release(Warp);
                IDXGIFactory4_Release(Factory4);
            }
            IDXGIFactory_Release(Factory);
        }
    }
}
