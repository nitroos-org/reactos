/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for D3D11 shared resources: legacy handles, NT handles, IDXGIKeyedMutex, two processes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * "Measured" below means measured on Windows 10 22H2 (19045), device from D3D11CreateDevice(HARDWARE) on the
 * Basic Render Driver, with a probe of our own (evidence d3dshare-20261110):
 *  - D3D11_RESOURCE_MISC_SHARED or SHARED_KEYEDMUTEX alone give a legacy handle (0x40000xxx); SHARED_NTHANDLE
 *    needs SHARED or SHARED_KEYEDMUTEX with it; SHARED together with SHARED_KEYEDMUTEX is E_INVALIDARG.
 *  - IDXGIResource::GetSharedHandle on an unshared texture returns S_OK and a NULL handle, on an NT-handle
 *    texture E_INVALIDARG; CreateSharedHandle on anything but an NT-handle texture is E_INVALIDARG and clears
 *    the output. IDXGIResource1 is available on every texture, IDXGIKeyedMutex only with KEYEDMUTEX.
 *  - A shared texture cannot be D3D11_USAGE_DYNAMIC; mip chains, arrays and multisampled textures can be shared.
 *  - OpenSharedResource / OpenSharedResource1 / OpenSharedResourceByName with a NULL handle, a handle to some
 *    other object, or a name that does not exist all return E_INVALIDARG.
 * The keyed-mutex and two-process parts follow learn.microsoft.com (AcquireSync: S_OK, WAIT_TIMEOUT and
 * WAIT_ABANDONED; a fresh mutex is free with key 0; ReleaseSync of a mutex the caller does not hold fails with
 * E_FAIL); they were NOT measured (the one oracle probe of the lane used the wrong flag combination for them).
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#define COBJMACROS
#include <d3d11_1.h>
#include <dxgi1_2.h>

#define BLUE_PIXEL  0xff0000ffu
#define RED_PIXEL   0xffff0000u
#define GREEN_PIXEL 0xff00ff00u

static ID3D11Device *Dev;
static ID3D11Device1 *Dev1;
static ID3D11DeviceContext *Ctx;

static BOOL CreateDev(void)
{
    D3D_FEATURE_LEVEL Level;
    HRESULT hr;

    hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                           D3D11_SDK_VERSION, &Dev, &Level, &Ctx);
    if (FAILED(hr))
        hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_WARP, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                               D3D11_SDK_VERSION, &Dev, &Level, &Ctx);
    if (FAILED(hr))
        return FALSE;
    if (FAILED(ID3D11Device_QueryInterface(Dev, &IID_ID3D11Device1, (void **)&Dev1)))
        Dev1 = NULL;
    return TRUE;
}

static void DestroyDev(void)
{
    if (Dev1)
        ID3D11Device1_Release(Dev1);
    ID3D11DeviceContext_Release(Ctx);
    ID3D11Device_Release(Dev);
    Dev = NULL;
    Dev1 = NULL;
    Ctx = NULL;
}

static HRESULT MakeTexture(UINT Misc, UINT Bind, D3D11_USAGE Usage, UINT W, UINT H, UINT Mips, UINT Array,
                           UINT Samples, ID3D11Texture2D **Out)
{
    D3D11_TEXTURE2D_DESC Desc = {0};

    Desc.Width = W;
    Desc.Height = H;
    Desc.MipLevels = Mips;
    Desc.ArraySize = Array;
    Desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    Desc.SampleDesc.Count = Samples;
    Desc.Usage = Usage;
    Desc.BindFlags = Bind;
    Desc.MiscFlags = Misc;
    if (Usage == D3D11_USAGE_STAGING)
        Desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ | D3D11_CPU_ACCESS_WRITE;
    return ID3D11Device_CreateTexture2D(Dev, &Desc, NULL, Out);
}

#define RT_SRV (D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE)

static HANDLE LegacyHandle(ID3D11Texture2D *Tex, HRESULT *Hr)
{
    IDXGIResource *Res = NULL;
    HANDLE Handle = (HANDLE)(ULONG_PTR)0xdeadbeef;

    *Hr = ID3D11Texture2D_QueryInterface(Tex, &IID_IDXGIResource, (void **)&Res);
    if (FAILED(*Hr))
        return NULL;
    *Hr = IDXGIResource_GetSharedHandle(Res, &Handle);
    IDXGIResource_Release(Res);
    return Handle;
}

static HRESULT NtHandle(ID3D11Texture2D *Tex, SECURITY_ATTRIBUTES *Sa, const WCHAR *Name, HANDLE *Out)
{
    IDXGIResource1 *Res = NULL;
    HRESULT hr;

    *Out = (HANDLE)(ULONG_PTR)0xdeadbeef;
    hr = ID3D11Texture2D_QueryInterface(Tex, &IID_IDXGIResource1, (void **)&Res);
    if (FAILED(hr))
        return hr;
    hr = IDXGIResource1_CreateSharedHandle(Res, Sa, DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE, Name, Out);
    IDXGIResource1_Release(Res);
    return hr;
}

static HRESULT Acquire(ID3D11Texture2D *Tex, UINT64 Key, DWORD Ms)
{
    IDXGIKeyedMutex *Mutex = NULL;
    HRESULT hr = ID3D11Texture2D_QueryInterface(Tex, &IID_IDXGIKeyedMutex, (void **)&Mutex);

    if (FAILED(hr))
        return hr;
    hr = IDXGIKeyedMutex_AcquireSync(Mutex, Key, Ms);
    IDXGIKeyedMutex_Release(Mutex);
    return hr;
}

static HRESULT Release(ID3D11Texture2D *Tex, UINT64 Key)
{
    IDXGIKeyedMutex *Mutex = NULL;
    HRESULT hr = ID3D11Texture2D_QueryInterface(Tex, &IID_IDXGIKeyedMutex, (void **)&Mutex);

    if (FAILED(hr))
        return hr;
    hr = IDXGIKeyedMutex_ReleaseSync(Mutex, Key);
    IDXGIKeyedMutex_Release(Mutex);
    return hr;
}

static void Clear(ID3D11Texture2D *Tex, float R, float G, float B)
{
    ID3D11RenderTargetView *View = NULL;
    float Color[4] = { R, G, B, 1.0f };

    if (SUCCEEDED(ID3D11Device_CreateRenderTargetView(Dev, (ID3D11Resource *)Tex, NULL, &View)))
    {
        ID3D11DeviceContext_ClearRenderTargetView(Ctx, View, Color);
        ID3D11RenderTargetView_Release(View);
    }
}

static void FlushWait(void)
{
    D3D11_QUERY_DESC Desc = { D3D11_QUERY_EVENT, 0 };
    ID3D11Query *Query = NULL;
    BOOL Done = FALSE;
    int i;

    ID3D11DeviceContext_Flush(Ctx);
    if (FAILED(ID3D11Device_CreateQuery(Dev, &Desc, &Query)))
        return;
    ID3D11DeviceContext_End(Ctx, (ID3D11Asynchronous *)Query);
    for (i = 0; i < 3000; i++)
    {
        if (ID3D11DeviceContext_GetData(Ctx, (ID3D11Asynchronous *)Query, &Done, sizeof(Done), 0) == S_OK && Done)
            break;
        Sleep(1);
    }
    ID3D11Query_Release(Query);
}

/* first and last pixel of a texture */
static BOOL ReadPixels(ID3D11Texture2D *Tex, UINT *First, UINT *Last)
{
    D3D11_TEXTURE2D_DESC Desc;
    ID3D11Texture2D *Staging = NULL;
    D3D11_MAPPED_SUBRESOURCE Map;

    ID3D11Texture2D_GetDesc(Tex, &Desc);
    if (FAILED(MakeTexture(0, 0, D3D11_USAGE_STAGING, Desc.Width, Desc.Height, 1, 1, 1, &Staging)))
        return FALSE;
    ID3D11DeviceContext_CopySubresourceRegion(Ctx, (ID3D11Resource *)Staging, 0, 0, 0, 0, (ID3D11Resource *)Tex, 0, NULL);
    if (FAILED(ID3D11DeviceContext_Map(Ctx, (ID3D11Resource *)Staging, 0, D3D11_MAP_READ, 0, &Map)))
    {
        ID3D11Texture2D_Release(Staging);
        return FALSE;
    }
    *First = ((UINT *)Map.pData)[0];
    *Last = *(UINT *)((BYTE *)Map.pData + (Desc.Height - 1) * Map.RowPitch + (Desc.Width - 1) * 4);
    ID3D11DeviceContext_Unmap(Ctx, (ID3D11Resource *)Staging, 0);
    ID3D11Texture2D_Release(Staging);
    return TRUE;
}

static HRESULT OpenLegacy(HANDLE Handle, ID3D11Texture2D **Out)
{
    return ID3D11Device_OpenSharedResource(Dev, Handle, &IID_ID3D11Texture2D, (void **)Out);
}

static HRESULT OpenNt(HANDLE Handle, ID3D11Texture2D **Out)
{
    return ID3D11Device1_OpenSharedResource1(Dev1, Handle, &IID_ID3D11Texture2D, (void **)Out);
}

static HRESULT OpenName(const WCHAR *Name, ID3D11Texture2D **Out)
{
    return ID3D11Device1_OpenSharedResourceByName(Dev1, Name, DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE,
                                                  &IID_ID3D11Texture2D, (void **)Out);
}

/* ------------------------------------------------------------------ measured on Windows */

static const struct
{
    const char *Name;
    UINT Misc, Bind;
    D3D11_USAGE Usage;
    UINT Mips, Array, Samples;
    BOOL Ok;
    BOOL Legacy, Nt, Keyed;
} Combos[] =
{
    { "none",                   0,                                                               RT_SRV, D3D11_USAGE_DEFAULT, 1, 1, 1, TRUE,  FALSE, FALSE, FALSE },
    { "SHARED",                 D3D11_RESOURCE_MISC_SHARED,                                      RT_SRV, D3D11_USAGE_DEFAULT, 1, 1, 1, TRUE,  TRUE,  FALSE, FALSE },
    { "KEYEDMUTEX",             D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX,                           RT_SRV, D3D11_USAGE_DEFAULT, 1, 1, 1, TRUE,  TRUE,  FALSE, TRUE  },
    { "NTHANDLE only",          D3D11_RESOURCE_MISC_SHARED_NTHANDLE,                             RT_SRV, D3D11_USAGE_DEFAULT, 1, 1, 1, FALSE },
    { "SHARED|KEYEDMUTEX",      D3D11_RESOURCE_MISC_SHARED | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX, RT_SRV, D3D11_USAGE_DEFAULT, 1, 1, 1, FALSE },
    { "SHARED|NTHANDLE",        D3D11_RESOURCE_MISC_SHARED | D3D11_RESOURCE_MISC_SHARED_NTHANDLE, RT_SRV, D3D11_USAGE_DEFAULT, 1, 1, 1, TRUE,  FALSE, TRUE,  FALSE },
    { "KEYEDMUTEX|NTHANDLE",    D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX | D3D11_RESOURCE_MISC_SHARED_NTHANDLE, RT_SRV, D3D11_USAGE_DEFAULT, 1, 1, 1, TRUE, FALSE, TRUE, TRUE },
    { "all three",              D3D11_RESOURCE_MISC_SHARED | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX | D3D11_RESOURCE_MISC_SHARED_NTHANDLE, RT_SRV, D3D11_USAGE_DEFAULT, 1, 1, 1, FALSE },
    { "SHARED mips=4",          D3D11_RESOURCE_MISC_SHARED,                                      RT_SRV, D3D11_USAGE_DEFAULT, 4, 1, 1, TRUE,  TRUE,  FALSE, FALSE },
    { "SHARED array=3",         D3D11_RESOURCE_MISC_SHARED,                                      RT_SRV, D3D11_USAGE_DEFAULT, 1, 3, 1, TRUE,  TRUE,  FALSE, FALSE },
    { "SHARED msaa4",           D3D11_RESOURCE_MISC_SHARED,                                      D3D11_BIND_RENDER_TARGET, D3D11_USAGE_DEFAULT, 1, 1, 4, TRUE, TRUE, FALSE, FALSE },
    { "SHARED staging",         D3D11_RESOURCE_MISC_SHARED,                                      0,      D3D11_USAGE_STAGING, 1, 1, 1, TRUE,  TRUE,  FALSE, FALSE },
    { "SHARED dynamic",         D3D11_RESOURCE_MISC_SHARED,                                      D3D11_BIND_SHADER_RESOURCE, D3D11_USAGE_DYNAMIC, 1, 1, 1, FALSE },
};

static void TestCreationTable(void)
{
    UINT i;

    for (i = 0; i < ARRAY_SIZE(Combos); i++)
    {
        ID3D11Texture2D *Tex = NULL;
        IDXGIKeyedMutex *Mutex = NULL;
        IDXGIResource1 *Res1 = NULL;
        D3D11_TEXTURE2D_DESC Desc;
        HANDLE Legacy, Nt = NULL;
        HRESULT hr, hrLegacy, hrNt;

        if (Combos[i].Samples > 1)
        {
            /* not every renderer has multisampling: only test what an unshared texture can do */
            hr = MakeTexture(0, Combos[i].Bind, Combos[i].Usage, 64, 64, 1, 1, Combos[i].Samples, &Tex);
            if (FAILED(hr))
            {
                skip("%s: no multisampled textures\n", Combos[i].Name);
                continue;
            }
            ID3D11Texture2D_Release(Tex);
            Tex = NULL;
        }
        hr = MakeTexture(Combos[i].Misc, Combos[i].Bind, Combos[i].Usage, 64, 64, Combos[i].Mips, Combos[i].Array,
                         Combos[i].Samples, &Tex);
        if (!Combos[i].Ok)
        {
            ok(hr == E_INVALIDARG, "%s: CreateTexture2D returned %08lx\n", Combos[i].Name, hr);
            if (SUCCEEDED(hr))
                ID3D11Texture2D_Release(Tex);
            continue;
        }
        ok(hr == S_OK, "%s: CreateTexture2D returned %08lx\n", Combos[i].Name, hr);
        if (FAILED(hr))
            continue;

        ID3D11Texture2D_GetDesc(Tex, &Desc);
        ok(Desc.MiscFlags == Combos[i].Misc, "%s: MiscFlags %#x, expected %#x\n", Combos[i].Name, Desc.MiscFlags, Combos[i].Misc);

        Legacy = LegacyHandle(Tex, &hrLegacy);
        if (Combos[i].Legacy)
        {
            ok(hrLegacy == S_OK, "%s: GetSharedHandle returned %08lx\n", Combos[i].Name, hrLegacy);
            ok(Legacy != NULL && Legacy != (HANDLE)(ULONG_PTR)0xdeadbeef, "%s: legacy handle %p\n", Combos[i].Name, Legacy);
        }
        else if (Combos[i].Nt)
        {
            ok(hrLegacy == E_INVALIDARG, "%s: GetSharedHandle returned %08lx\n", Combos[i].Name, hrLegacy);
            ok(Legacy == (HANDLE)(ULONG_PTR)0xdeadbeef, "%s: handle changed to %p\n", Combos[i].Name, Legacy);
        }
        else
        {
            ok(hrLegacy == S_OK, "%s: GetSharedHandle returned %08lx\n", Combos[i].Name, hrLegacy);
            ok(Legacy == NULL, "%s: handle %p for an unshared texture\n", Combos[i].Name, Legacy);
        }

        hrNt = NtHandle(Tex, NULL, NULL, &Nt);
        if (Combos[i].Nt)
        {
            ok(hrNt == S_OK, "%s: CreateSharedHandle returned %08lx\n", Combos[i].Name, hrNt);
            ok(Nt != NULL && Nt != (HANDLE)(ULONG_PTR)0xdeadbeef, "%s: NT handle %p\n", Combos[i].Name, Nt);
            if (SUCCEEDED(hrNt) && Nt)
                CloseHandle(Nt);
        }
        else
        {
            ok(hrNt == E_INVALIDARG, "%s: CreateSharedHandle returned %08lx\n", Combos[i].Name, hrNt);
            ok(Nt == NULL, "%s: CreateSharedHandle left %p in the output\n", Combos[i].Name, Nt);
        }

        hr = ID3D11Texture2D_QueryInterface(Tex, &IID_IDXGIKeyedMutex, (void **)&Mutex);
        if (Combos[i].Keyed)
        {
            ok(hr == S_OK, "%s: QueryInterface(IDXGIKeyedMutex) returned %08lx\n", Combos[i].Name, hr);
            if (Mutex)
                IDXGIKeyedMutex_Release(Mutex);
        }
        else
            ok(hr == E_NOINTERFACE, "%s: QueryInterface(IDXGIKeyedMutex) returned %08lx\n", Combos[i].Name, hr);

        hr = ID3D11Texture2D_QueryInterface(Tex, &IID_IDXGIResource1, (void **)&Res1);
        ok(hr == S_OK, "%s: QueryInterface(IDXGIResource1) returned %08lx\n", Combos[i].Name, hr);
        if (Res1)
            IDXGIResource1_Release(Res1);

        ID3D11Texture2D_Release(Tex);
    }
}

static void TestOpenErrors(void)
{
    ID3D11Texture2D *Tex;
    HANDLE Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE Section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
    HRESULT hr;

    Tex = (ID3D11Texture2D *)1;
    hr = OpenLegacy(NULL, &Tex);
    ok(hr == E_INVALIDARG, "OpenSharedResource(NULL) returned %08lx\n", hr);
    ok(Tex == NULL, "output %p\n", Tex);
    Tex = (ID3D11Texture2D *)1;
    hr = OpenLegacy(Event, &Tex);
    ok(hr == E_INVALIDARG, "OpenSharedResource(event) returned %08lx\n", hr);
    ok(Tex == NULL, "output %p\n", Tex);

    if (Dev1)
    {
        Tex = (ID3D11Texture2D *)1;
        hr = OpenNt(NULL, &Tex);
        ok(hr == E_INVALIDARG, "OpenSharedResource1(NULL) returned %08lx\n", hr);
        ok(Tex == NULL, "output %p\n", Tex);
        Tex = (ID3D11Texture2D *)1;
        hr = OpenNt(Event, &Tex);
        ok(hr == E_INVALIDARG, "OpenSharedResource1(event) returned %08lx\n", hr);
        ok(Tex == NULL, "output %p\n", Tex);
        Tex = (ID3D11Texture2D *)1;
        hr = OpenNt(Section, &Tex);
        ok(hr == E_INVALIDARG, "OpenSharedResource1(foreign section) returned %08lx\n", hr);
        ok(Tex == NULL, "output %p\n", Tex);
        Tex = (ID3D11Texture2D *)1;
        hr = OpenName(L"Local\\d3d11-shared-apitest-no-such-resource", &Tex);
        ok(hr == E_INVALIDARG, "OpenSharedResourceByName(missing) returned %08lx\n", hr);
        ok(Tex == NULL, "output %p\n", Tex);
    }
    CloseHandle(Section);
    CloseHandle(Event);
}

/* ------------------------------------------------------------------ from the documentation */

static void TestKeyedMutexOneProcess(void)
{
    ID3D11Texture2D *Tex = NULL, *Opened = NULL;
    D3D11_TEXTURE2D_DESC Desc;
    HANDLE Handle;
    HRESULT hr, hrHandle;

    hr = MakeTexture(D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX, RT_SRV, D3D11_USAGE_DEFAULT, 32, 24, 1, 1, 1, &Tex);
    ok(hr == S_OK, "CreateTexture2D returned %08lx\n", hr);
    if (FAILED(hr))
        return;

    hr = Release(Tex, 0);
    ok(hr == E_FAIL, "ReleaseSync of an unheld mutex returned %08lx\n", hr);
    hr = Acquire(Tex, 0, 0);
    ok(hr == S_OK, "AcquireSync(0) on a fresh mutex returned %08lx\n", hr);
    hr = Acquire(Tex, 0, 20);
    ok(hr == (HRESULT)WAIT_TIMEOUT, "AcquireSync on a held mutex returned %08lx\n", hr);
    hr = Release(Tex, 1);
    ok(hr == S_OK, "ReleaseSync(1) returned %08lx\n", hr);
    hr = Acquire(Tex, 0, 20);
    ok(hr == (HRESULT)WAIT_TIMEOUT, "AcquireSync(0) after ReleaseSync(1) returned %08lx\n", hr);
    hr = Acquire(Tex, 1, 0);
    ok(hr == S_OK, "AcquireSync(1) after ReleaseSync(1) returned %08lx\n", hr);
    hr = Release(Tex, 0xffffffffffffffffull);
    ok(hr == S_OK, "ReleaseSync(max key) returned %08lx\n", hr);
    hr = Acquire(Tex, 0xffffffffffffffffull, 0);
    ok(hr == S_OK, "AcquireSync(max key) returned %08lx\n", hr);
    hr = Release(Tex, 5);
    ok(hr == S_OK, "ReleaseSync(5) returned %08lx\n", hr);

    Handle = LegacyHandle(Tex, &hrHandle);
    ok(hrHandle == S_OK && Handle, "GetSharedHandle returned %08lx, %p\n", hrHandle, Handle);
    hr = OpenLegacy(Handle, &Opened);
    ok(hr == S_OK, "OpenSharedResource returned %08lx\n", hr);
    if (SUCCEEDED(hr))
    {
        ID3D11Texture2D_GetDesc(Opened, &Desc);
        ok(Desc.Width == 32 && Desc.Height == 24, "opened texture is %ux%u\n", Desc.Width, Desc.Height);
        ok(Desc.Format == DXGI_FORMAT_B8G8R8A8_UNORM, "opened format %u\n", Desc.Format);
        ok(Desc.MiscFlags & D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX, "opened MiscFlags %#x\n", Desc.MiscFlags);
        LegacyHandle(Opened, &hrHandle);
        ok(hrHandle == S_OK, "GetSharedHandle of the opened texture returned %08lx\n", hrHandle);

        /* the two objects are one mutex */
        hr = Acquire(Opened, 5, 0);
        ok(hr == S_OK, "AcquireSync on the opened texture returned %08lx\n", hr);
        hr = Acquire(Tex, 5, 20);
        ok(hr == (HRESULT)WAIT_TIMEOUT, "AcquireSync on the original while the opened one holds it: %08lx\n", hr);
        hr = Release(Opened, 6);
        ok(hr == S_OK, "ReleaseSync returned %08lx\n", hr);
        hr = Acquire(Tex, 6, 0);
        ok(hr == S_OK, "AcquireSync(6) returned %08lx\n", hr);
        hr = Release(Tex, 7);
        ok(hr == S_OK, "ReleaseSync returned %08lx\n", hr);
        ID3D11Texture2D_Release(Opened);

        /* the interface the handle is opened as */
        {
            IDXGIResource *Res = NULL;
            ID3D11Buffer *Buf = NULL;

            hr = ID3D11Device_OpenSharedResource(Dev, Handle, &IID_IDXGIResource, (void **)&Res);
            ok(hr == S_OK, "OpenSharedResource(IDXGIResource) returned %08lx\n", hr);
            if (Res)
                IDXGIResource_Release(Res);
            hr = ID3D11Device_OpenSharedResource(Dev, Handle, &IID_ID3D11Buffer, (void **)&Buf);
            ok(hr == E_NOINTERFACE, "OpenSharedResource(ID3D11Buffer) returned %08lx\n", hr);
        }
    }
    ID3D11Texture2D_Release(Tex);
}

static void TestNtHandleOneProcess(void)
{
    ID3D11Texture2D *Tex = NULL, *Opened = NULL;
    D3D11_TEXTURE2D_DESC Desc;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    HANDLE Handle = NULL, Handle2 = NULL;
    WCHAR Name[96];
    HRESULT hr;

    hr = MakeTexture(D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX | D3D11_RESOURCE_MISC_SHARED_NTHANDLE, RT_SRV,
                     D3D11_USAGE_DEFAULT, 48, 40, 1, 1, 1, &Tex);
    ok(hr == S_OK, "CreateTexture2D returned %08lx\n", hr);
    if (FAILED(hr))
        return;

    hr = NtHandle(Tex, &Sa, NULL, &Handle);
    ok(hr == S_OK && Handle, "CreateSharedHandle returned %08lx, %p\n", hr, Handle);
    if (SUCCEEDED(hr) && Handle)
    {
        DWORD Flags = 0;

        GetHandleInformation(Handle, &Flags);
        ok(Flags & HANDLE_FLAG_INHERIT, "the handle is not inheritable (flags %#lx)\n", Flags);
        hr = NtHandle(Tex, NULL, NULL, &Handle2);
        ok(hr == S_OK && Handle2 && Handle2 != Handle, "second CreateSharedHandle: %08lx, %p, %p\n", hr, Handle2, Handle);

        hr = OpenNt(Handle, &Opened);
        ok(hr == S_OK, "OpenSharedResource1 returned %08lx\n", hr);
        if (SUCCEEDED(hr))
        {
            ID3D11Texture2D_GetDesc(Opened, &Desc);
            ok(Desc.Width == 48 && Desc.Height == 40, "opened texture is %ux%u\n", Desc.Width, Desc.Height);
            ok(Desc.MiscFlags == (D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX | D3D11_RESOURCE_MISC_SHARED_NTHANDLE),
               "opened MiscFlags %#x\n", Desc.MiscFlags);
            ID3D11Texture2D_Release(Opened);
        }
        if (Handle2)
            CloseHandle(Handle2);
        CloseHandle(Handle);
    }

    /* a name given to the first CreateSharedHandle */
    swprintf(Name, ARRAY_SIZE(Name), L"Local\\d3d11-shared-apitest-%lu", GetCurrentProcessId());
    ID3D11Texture2D_Release(Tex);
    hr = MakeTexture(D3D11_RESOURCE_MISC_SHARED | D3D11_RESOURCE_MISC_SHARED_NTHANDLE, RT_SRV, D3D11_USAGE_DEFAULT,
                     16, 16, 1, 1, 1, &Tex);
    ok(hr == S_OK, "CreateTexture2D returned %08lx\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = NtHandle(Tex, NULL, Name, &Handle);
        ok(hr == S_OK && Handle, "CreateSharedHandle(name) returned %08lx, %p\n", hr, Handle);
        if (SUCCEEDED(hr) && Handle)
        {
            hr = OpenName(Name, &Opened);
            ok(hr == S_OK, "OpenSharedResourceByName returned %08lx\n", hr);
            if (SUCCEEDED(hr))
                ID3D11Texture2D_Release(Opened);
            CloseHandle(Handle);
        }
        ID3D11Texture2D_Release(Tex);
    }
}

/* ------------------------------------------------------------------ two processes */

enum { MODE_CONTENT = 1, MODE_TIMEOUT, MODE_GRAB, MODE_ABANDON, MODE_PLAIN };
enum { VIA_LEGACY = 1, VIA_NT, VIA_NAME };

/* the child reports through its exit code: 0 = all as expected, else the number of the check that failed */
static void Child(void)
{
    char **Argv;
    int Argc = winetest_get_mainargs(&Argv);
    int Mode, Via, Code = 0;
    HANDLE Handle;
    WCHAR Name[96];
    ID3D11Texture2D *Tex = NULL;
    UINT First, Last;
    HRESULT hr;

    if (Argc < 5)
    {
        skip("SharedResourceChild is started by SharedResource\n");
        return;
    }
    Mode = atoi(Argv[2]);
    Via = atoi(Argv[3]);
    Handle = (HANDLE)(ULONG_PTR)_strtoui64(Argv[4], NULL, 16);
    if (Argc > 5)
        MultiByteToWideChar(CP_ACP, 0, Argv[5], -1, Name, ARRAY_SIZE(Name));

    if (!CreateDev())
        ExitProcess(101);
    if (Via == VIA_LEGACY)
        hr = OpenLegacy(Handle, &Tex);
    else if (Via == VIA_NT)
        hr = OpenNt(Handle, &Tex);
    else
        hr = OpenName(Name, &Tex);
    if (FAILED(hr))
        ExitProcess(102);

    switch (Mode)
    {
        case MODE_CONTENT:
            if (Acquire(Tex, 1, 10000) != S_OK) { Code = 1; break; }
            if (!ReadPixels(Tex, &First, &Last) || First != RED_PIXEL || Last != RED_PIXEL) { Code = 2; }
            Clear(Tex, 0, 1, 0);
            if (Release(Tex, 2) != S_OK) { Code = 3; }
            break;
        case MODE_TIMEOUT:
            if (Acquire(Tex, 0, 100) != (HRESULT)WAIT_TIMEOUT) { Code = 1; break; }
            if (Acquire(Tex, 7, 0) != (HRESULT)WAIT_TIMEOUT) { Code = 2; break; }
            if (Acquire(Tex, 1, 0) != (HRESULT)WAIT_TIMEOUT) { Code = 3; break; }
            break;
        case MODE_GRAB:
            if (Acquire(Tex, 7, 10000) != S_OK) { Code = 1; break; }
            if (Release(Tex, 8) != S_OK) { Code = 2; }
            break;
        case MODE_ABANDON:
            if (Acquire(Tex, 9, 10000) != S_OK) { Code = 1; break; }
            ExitProcess(0); /* without ReleaseSync */
            break;
        case MODE_PLAIN:
            if (!ReadPixels(Tex, &First, &Last) || First != RED_PIXEL || Last != RED_PIXEL) { Code = 1; }
            Clear(Tex, 0, 1, 0);
            FlushWait();
            break;
    }
    ID3D11Texture2D_Release(Tex);
    DestroyDev();
    ExitProcess(Code);
}

static DWORD RunChild(int Mode, int Via, HANDLE Handle, const char *Name)
{
    char Exe[MAX_PATH], Cmd[1024];
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    DWORD Code = 999;

    GetModuleFileNameA(NULL, Exe, MAX_PATH);
    sprintf(Cmd, "\"%s\" SharedResourceChild %d %d %I64x%s%s", Exe, Mode, Via, (unsigned long long)(ULONG_PTR)Handle,
            Name ? " " : "", Name ? Name : "");
    if (!CreateProcessA(NULL, Cmd, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
    {
        skip("cannot start the child process (%lu)\n", GetLastError());
        return 998;
    }
    if (WaitForSingleObject(Pi.hProcess, 120000) != WAIT_OBJECT_0)
    {
        TerminateProcess(Pi.hProcess, 997);
        Code = 997;
    }
    else
        GetExitCodeProcess(Pi.hProcess, &Code);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    return Code;
}

static void TestCrossProcess(void)
{
    ID3D11Texture2D *Tex = NULL;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    WCHAR Name[96];
    char NameA[96];
    HANDLE Legacy, Nt = NULL;
    UINT First, Last;
    HRESULT hr, hrHandle;
    DWORD Code;

    /* legacy handle, keyed mutex: the parent paints red, the child sees it and paints green */
    hr = MakeTexture(D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX, RT_SRV, D3D11_USAGE_DEFAULT, 64, 48, 1, 1, 1, &Tex);
    ok(hr == S_OK, "CreateTexture2D returned %08lx\n", hr);
    if (FAILED(hr))
        return;
    Legacy = LegacyHandle(Tex, &hrHandle);
    ok(hrHandle == S_OK && Legacy, "GetSharedHandle returned %08lx, %p\n", hrHandle, Legacy);

    hr = Acquire(Tex, 0, 0);
    ok(hr == S_OK, "AcquireSync(0) returned %08lx\n", hr);
    Clear(Tex, 1, 0, 0);
    hr = Release(Tex, 1);
    ok(hr == S_OK, "ReleaseSync(1) returned %08lx\n", hr);
    Code = RunChild(MODE_CONTENT, VIA_LEGACY, Legacy, NULL);
    ok(Code == 0, "child (content, legacy handle) failed at check %lu\n", Code);
    hr = Acquire(Tex, 2, 10000);
    ok(hr == S_OK, "AcquireSync(2) returned %08lx\n", hr);
    ok(ReadPixels(Tex, &First, &Last), "cannot read the texture\n");
    ok(First == GREEN_PIXEL && Last == GREEN_PIXEL, "pixels after the child: %08x %08x, expected %08x\n", First, Last, GREEN_PIXEL);
    hr = Release(Tex, 3);
    ok(hr == S_OK, "ReleaseSync(3) returned %08lx\n", hr);

    /* waiting with the wrong key and the right key */
    hr = Acquire(Tex, 3, 0);
    ok(hr == S_OK, "AcquireSync(3) returned %08lx\n", hr);
    Code = RunChild(MODE_TIMEOUT, VIA_LEGACY, Legacy, NULL);
    ok(Code == 0, "child (timeout) failed at check %lu\n", Code);
    hr = Release(Tex, 7);
    ok(hr == S_OK, "ReleaseSync(7) returned %08lx\n", hr);
    Code = RunChild(MODE_GRAB, VIA_LEGACY, Legacy, NULL);
    ok(Code == 0, "child (grab) failed at check %lu\n", Code);
    hr = Acquire(Tex, 8, 0);
    ok(hr == S_OK, "AcquireSync(8) after the child released with 8 returned %08lx\n", hr);
    hr = Release(Tex, 9);
    ok(hr == S_OK, "ReleaseSync(9) returned %08lx\n", hr);

    /* a holder that exits without releasing */
    Code = RunChild(MODE_ABANDON, VIA_LEGACY, Legacy, NULL);
    ok(Code == 0, "child (abandon) failed at check %lu\n", Code);
    hr = Acquire(Tex, 9, 5000);
    ok(hr == (HRESULT)WAIT_ABANDONED, "AcquireSync after the holder exited returned %08lx\n", hr);
    hr = Release(Tex, 10);
    ok(hr == S_OK, "ReleaseSync(10) returned %08lx\n", hr);
    ID3D11Texture2D_Release(Tex);

    /* NT handle (inherited by the child) and by name */
    if (!Dev1)
        return;
    hr = MakeTexture(D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX | D3D11_RESOURCE_MISC_SHARED_NTHANDLE, RT_SRV,
                     D3D11_USAGE_DEFAULT, 64, 48, 1, 1, 1, &Tex);
    ok(hr == S_OK, "CreateTexture2D returned %08lx\n", hr);
    if (FAILED(hr))
        return;
    swprintf(Name, ARRAY_SIZE(Name), L"Local\\d3d11-shared-apitest2-%lu", GetCurrentProcessId());
    WideCharToMultiByte(CP_ACP, 0, Name, -1, NameA, sizeof(NameA), NULL, NULL);
    hr = NtHandle(Tex, &Sa, Name, &Nt);
    ok(hr == S_OK && Nt, "CreateSharedHandle returned %08lx, %p\n", hr, Nt);
    if (SUCCEEDED(hr) && Nt)
    {
        hr = Acquire(Tex, 0, 0);
        ok(hr == S_OK, "AcquireSync(0) returned %08lx\n", hr);
        Clear(Tex, 1, 0, 0);
        hr = Release(Tex, 1);
        ok(hr == S_OK, "ReleaseSync(1) returned %08lx\n", hr);
        Code = RunChild(MODE_CONTENT, VIA_NT, Nt, NULL);
        ok(Code == 0, "child (content, NT handle) failed at check %lu\n", Code);
        hr = Acquire(Tex, 2, 10000);
        ok(hr == S_OK, "AcquireSync(2) returned %08lx\n", hr);
        ok(ReadPixels(Tex, &First, &Last), "cannot read the texture\n");
        ok(First == GREEN_PIXEL && Last == GREEN_PIXEL, "pixels after the child (NT): %08x %08x\n", First, Last);
        Clear(Tex, 1, 0, 0);
        hr = Release(Tex, 1);
        ok(hr == S_OK, "ReleaseSync(1) returned %08lx\n", hr);
        Code = RunChild(MODE_CONTENT, VIA_NAME, NULL, NameA);
        ok(Code == 0, "child (content, by name) failed at check %lu\n", Code);
        hr = Acquire(Tex, 2, 10000);
        ok(hr == S_OK, "AcquireSync(2) returned %08lx\n", hr);
        ok(ReadPixels(Tex, &First, &Last), "cannot read the texture\n");
        ok(First == GREEN_PIXEL && Last == GREEN_PIXEL, "pixels after the child (name): %08x %08x\n", First, Last);
        Release(Tex, 3);
        CloseHandle(Nt);
    }
    ID3D11Texture2D_Release(Tex);

    /* no keyed mutex: Flush is the hand-over */
    hr = MakeTexture(D3D11_RESOURCE_MISC_SHARED, RT_SRV, D3D11_USAGE_DEFAULT, 64, 48, 1, 1, 1, &Tex);
    ok(hr == S_OK, "CreateTexture2D returned %08lx\n", hr);
    if (FAILED(hr))
        return;
    Legacy = LegacyHandle(Tex, &hrHandle);
    Clear(Tex, 1, 0, 0);
    FlushWait();
    Code = RunChild(MODE_PLAIN, VIA_LEGACY, Legacy, NULL);
    ok(Code == 0, "child (plain shared) failed at check %lu\n", Code);
    ID3D11DeviceContext_Flush(Ctx);
    ok(ReadPixels(Tex, &First, &Last), "cannot read the texture\n");
    ok(First == GREEN_PIXEL && Last == GREEN_PIXEL, "pixels after the child (plain): %08x %08x\n", First, Last);
    ID3D11Texture2D_Release(Tex);
}

/* NitroOS only: the section of a shared texture is another process's data and must be treated as untrusted. The
 * layout is private (DWORD fields: magic, version, total size, sync, width, height, mips, array, format ...), so the
 * test skips when the NT handle is not a section with our magic (Windows). */
static void TestCorruptedHeader(void)
{
    static const struct { const char *Name; UINT Index; DWORD Value; } Cases[] =
    {
        { "width 0",            4, 0 },
        { "width 0xffffffff",   4, 0xffffffff },
        { "height 100000",      5, 100000 },
        { "mips 0",             6, 0 },
        { "mips 200",           6, 200 },
        { "array 0x7fffffff",   7, 0x7fffffff },
        { "array 0",            7, 0 },
        { "format 0xfffffff",   8, 0xfffffff },
        { "total size 4096",    2, 4096 },
        { "total size huge",    2, 0xfffffff0 },
    };
    ID3D11Texture2D *Tex = NULL, *Opened;
    HANDLE Handle = NULL;
    DWORD *Header;
    HRESULT hr;
    UINT i;

    if (!Dev1)
        return;
    hr = MakeTexture(D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX | D3D11_RESOURCE_MISC_SHARED_NTHANDLE, RT_SRV,
                     D3D11_USAGE_DEFAULT, 64, 48, 1, 1, 1, &Tex);
    ok(hr == S_OK, "CreateTexture2D returned %08lx\n", hr);
    if (FAILED(hr))
        return;
    hr = NtHandle(Tex, NULL, NULL, &Handle);
    ok(hr == S_OK && Handle, "CreateSharedHandle returned %08lx\n", hr);
    Header = (hr == S_OK && Handle) ? MapViewOfFile(Handle, FILE_MAP_ALL_ACCESS, 0, 0, 0) : NULL;
    if (!Header || Header[0] != 0x4853334e)
    {
        skip("the shared handle is not a NitroOS section\n");
    }
    else
    {
        for (i = 0; i < ARRAY_SIZE(Cases); i++)
        {
            DWORD Old = Header[Cases[i].Index];

            Header[Cases[i].Index] = Cases[i].Value;
            Opened = (ID3D11Texture2D *)1;
            hr = OpenNt(Handle, &Opened);
            ok(hr == E_INVALIDARG, "%s: OpenSharedResource1 returned %08lx\n", Cases[i].Name, hr);
            ok(Opened == NULL, "%s: output %p\n", Cases[i].Name, Opened);
            if (SUCCEEDED(hr) && Opened)
                ID3D11Texture2D_Release(Opened);
            Header[Cases[i].Index] = Old;
        }
        hr = OpenNt(Handle, &Opened);
        ok(hr == S_OK, "OpenSharedResource1 after restoring the header returned %08lx\n", hr);
        if (SUCCEEDED(hr))
            ID3D11Texture2D_Release(Opened);
    }
    if (Header)
        UnmapViewOfFile(Header);
    if (Handle)
        CloseHandle(Handle);
    ID3D11Texture2D_Release(Tex);
}

START_TEST(SharedResourceChild)
{
    Child();
}

START_TEST(SharedResource)
{
    if (!CreateDev())
    {
        skip("no D3D11 device\n");
        return;
    }
    TestCreationTable();
    TestOpenErrors();
    TestKeyedMutexOneProcess();
    TestNtHandleOneProcess();
    TestCrossProcess();
    TestCorruptedHeader();
    DestroyDev();
}
