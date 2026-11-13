/*
 * PROJECT:     ReactOS DirectComposition
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows.UI.Composition graphics device and drawing surfaces (stage 3): D3D11 textures drawn by D2D
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A CompositionGraphicsDevice wraps the app's ID3D11Device (or an IDXGIDevice of it) and an ID2D1Device made
 * from it. A CompositionDrawingSurface is a BGRA premultiplied D3D11 texture. BeginDraw hands the caller what
 * it asks for (ID2D1DeviceContext, IDXGISurface, ID3D11Texture2D ...); the D2D context is returned in the drawing
 * state with the update rectangle as a clip and EndDraw ends it.
 *
 * The six ICompositionDrawingSurfaceInterop methods are exposed through the real interface (IID and member order
 * from microsoft/windows-rs, see dcomp_nitro.h) and through the Nitro-private INitroDrawingSurfaceInterop, one vtable.
 * A rendering device that is only an ID2D1Device (Office passes one) is accepted too: the D3D11 / DXGI device
 * under it comes from ID2D1Device2::GetDxgiDevice, and the app's own ID2D1Device is the one the surfaces draw with.
 * Interface id and member order of ID2D1Device2: microsoft/windows-rs commit cd03f9369a89, file
 * crates/libs/windows/src/Windows/Win32/d2d/mod.rs (IID a44472e1-8dfb-4e60-8492-6e2861c9ca8b; GetDxgiDevice is the
 * last member after CreateDeviceContext and FlushDeviceContexts).
 * FIXME: not implemented here: DirectXPixelFormat other than B8G8R8A8UIntNormalized and R8G8B8A8UIntNormalized,
 * device-lost handling and RenderingDeviceReplaced, ICompositionDrawingSurface2
 * (SizeInt32, Resize, Scroll as WinRT members), Trim.
 */

#include <stdarg.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "objbase.h"
#include "inspectable.h"
#include "activation.h"
#include "winstring.h"
#include <windows.foundation.h>
#include <windows.ui.composition.h>
#include <windows.ui.composition.interop.h>
#include "comp_private.h"
#include <initguid.h>
#include <d3d11.h>
#include <d2d1_1.h>
#include <d2d1_3.h>
#include <dxgi.h>
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

#ifndef RO_E_CLOSED
#define RO_E_CLOSED ((HRESULT)0x80000013)
#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif

#define DXGI_FMT_BGRA 87
#define DXGI_FMT_RGBA 28

typedef HRESULT (WINAPI *PFN_D2D1CreateDevice)(IDXGIDevice *, const D2D1_CREATION_PROPERTIES *, ID2D1Device **);

HRESULT gfx_device_init(struct cobj *dev, IUnknown *device)
{
    ID3D11Device *d3d = NULL;
    IDXGIDevice *dxgi = NULL;
    ID2D1Device *d2d = NULL;
    ID2D1Device2 *d2d2 = NULL;
    PFN_D2D1CreateDevice create;
    HMODULE d2d1;
    HRESULT hr;

    if (!device) return E_INVALIDARG;
    if (FAILED(IUnknown_QueryInterface(device, &IID_ID3D11Device, (void **)&d3d)))
    {
        if (SUCCEEDED(IUnknown_QueryInterface(device, &IID_IDXGIDevice, (void **)&dxgi)))
            IDXGIDevice_QueryInterface(dxgi, &IID_ID3D11Device, (void **)&d3d);
    }
    if (!d3d && SUCCEEDED(IUnknown_QueryInterface(device, &IID_ID2D1Device, (void **)&d2d)))
    {
        /* only a Direct2D device: take the DXGI device it was made from */
        if (dxgi) { IDXGIDevice_Release(dxgi); dxgi = NULL; }
        if (SUCCEEDED(IUnknown_QueryInterface(device, &IID_ID2D1Device2, (void **)&d2d2)))
        {
            if (SUCCEEDED(ID2D1Device2_GetDxgiDevice(d2d2, &dxgi)))
            {
                if (FAILED(IDXGIDevice_QueryInterface(dxgi, &IID_ID3D11Device, (void **)&d3d)))
                    WARN("the DXGI device %p of the D2D device is not a D3D11 device\n", dxgi);
            }
            else
                WARN("ID2D1Device2::GetDxgiDevice failed\n");
            ID2D1Device2_Release(d2d2);
        }
        if (!d3d)
        {
            ID2D1Device_Release(d2d); d2d = NULL;
            if (dxgi) { IDXGIDevice_Release(dxgi); dxgi = NULL; }
        }
    }
    if (!d3d)
    {
        FIXME("CreateGraphicsDevice: %p is not an ID3D11Device, an IDXGIDevice of one or an ID2D1Device on one\n", device);
        if (dxgi) IDXGIDevice_Release(dxgi);
        return E_INVALIDARG;
    }
    if (!dxgi && FAILED(ID3D11Device_QueryInterface(d3d, &IID_IDXGIDevice, (void **)&dxgi)))
    {
        ID3D11Device_Release(d3d);
        return E_INVALIDARG;
    }
    if (d2d || SUCCEEDED(IUnknown_QueryInterface(device, &IID_ID2D1Device, (void **)&d2d)))
        hr = S_OK;
    else if (!(d2d1 = LoadLibraryW(L"d2d1.dll")) || !(create = (PFN_D2D1CreateDevice)GetProcAddress(d2d1, "D2D1CreateDevice")))
        hr = HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
    else
        hr = create(dxgi, NULL, &d2d);
    IDXGIDevice_Release(dxgi);
    if (FAILED(hr))
    {
        WARN("D2D device creation failed: %#lx\n", hr);
        ID3D11Device_Release(d3d);
        return hr;
    }
    dev->d3d = (IUnknown *)d3d;
    dev->d2d = (IUnknown *)d2d;
    return S_OK;
}

void gfx_device_free(struct cobj *dev)
{
    IUnknown *d3d, *d2d;

    comp_lock();
    d3d = dev->d3d; dev->d3d = NULL;
    d2d = dev->d2d; dev->d2d = NULL;
    comp_unlock();
    if (d2d) IUnknown_Release(d2d);
    if (d3d) IUnknown_Release(d3d);
}

static HRESULT make_texture(ID3D11Device *d3d, UINT w, UINT h, int fmt, ID3D11Texture2D **tex)
{
    D3D11_TEXTURE2D_DESC desc = { 0 };

    desc.Width = w; desc.Height = h; desc.MipLevels = 1; desc.ArraySize = 1;
    desc.Format = (DXGI_FORMAT)fmt;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
    return ID3D11Device_CreateTexture2D(d3d, &desc, NULL, tex);
}

HRESULT gfx_surface_create(struct cobj *dev, Vec2 size, int format, int alpha, struct cobj **out)
{
    struct cobj *s;
    ID3D11Texture2D *tex;
    ID3D11Device *d3d;
    HRESULT hr;
    UINT w, h;

    comp_lock();
    d3d = (ID3D11Device *)dev->d3d;
    if (d3d) ID3D11Device_AddRef(d3d);
    comp_unlock();
    if (!d3d) return RO_E_CLOSED;

    if (!(size.X >= 1.0f && size.Y >= 1.0f && size.X <= 16384.0f && size.Y <= 16384.0f))
    {
        ID3D11Device_Release(d3d);
        return E_INVALIDARG;
    }
    if (format != DXGI_FMT_BGRA && format != DXGI_FMT_RGBA)
    {
        FIXME("CreateDrawingSurface: pixel format %d not supported\n", format);
        ID3D11Device_Release(d3d);
        return E_INVALIDARG;
    }
    if (alpha < 0 || alpha > 3)
    {
        ID3D11Device_Release(d3d);
        return E_INVALIDARG;
    }
    w = (UINT)size.X; h = (UINT)size.Y;
    hr = make_texture(d3d, w, h, format, &tex);
    ID3D11Device_Release(d3d);
    if (FAILED(hr))
    {
        WARN("CreateTexture2D %ux%u failed: %#lx\n", w, h, hr);
        return hr;
    }
    if (FAILED(hr = comp_create(dev->compositor, K_DSURFACE, &s)))
    {
        ID3D11Texture2D_Release(tex);
        return hr;
    }
    s->tex = (IUnknown *)tex; s->width = w; s->height = h; s->pixfmt = format; s->alphamode = alpha;
    s->gfxdev = dev;
    InterlockedIncrement(&dev->ref);
    *out = s;
    return S_OK;
}

void gfx_surface_free(struct cobj *s)
{
    ID2D1DeviceContext *dc;
    IUnknown *bmp, *tex;

    comp_lock();
    dc = (ID2D1DeviceContext *)s->dc; s->dc = NULL;
    bmp = s->dcbitmap; s->dcbitmap = NULL;
    tex = s->tex; s->tex = NULL;
    s->drawing = FALSE;
    comp_unlock();
    if (dc) { ID2D1DeviceContext_SetTarget(dc, NULL); ID2D1DeviceContext_Release(dc); }
    if (bmp) IUnknown_Release(bmp);
    if (tex) IUnknown_Release(tex);
}

/* BGRA premultiplied copy of the texture contents; free with HeapFree */
HRESULT gfx_surface_snapshot(struct cobj *s, BYTE **pixels, UINT *w, UINT *h)
{
    ID3D11Device *d3d = s->gfxdev ? (ID3D11Device *)s->gfxdev->d3d : NULL;
    ID3D11Texture2D *src_tex = (ID3D11Texture2D *)s->tex;
    ID3D11DeviceContext *ctx;
    ID3D11Texture2D *stage;
    D3D11_TEXTURE2D_DESC desc;
    D3D11_MAPPED_SUBRESOURCE map;
    BYTE *out;
    UINT y, x;
    HRESULT hr;

    *pixels = NULL;
    if (!s->tex || !d3d) return RO_E_CLOSED;
    ID3D11Texture2D_GetDesc(src_tex, &desc);
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    desc.MiscFlags = 0;
    if (FAILED(hr = ID3D11Device_CreateTexture2D(d3d, &desc, NULL, &stage))) return hr;
    ID3D11Device_GetImmediateContext(d3d, &ctx);
    ID3D11DeviceContext_CopyResource(ctx, (ID3D11Resource *)stage, (ID3D11Resource *)src_tex);
    if (SUCCEEDED(hr = ID3D11DeviceContext_Map(ctx, (ID3D11Resource *)stage, 0, D3D11_MAP_READ, 0, &map)))
    {
        if ((out = HeapAlloc(GetProcessHeap(), 0, (size_t)desc.Width * desc.Height * 4)))
        {
            for (y = 0; y < desc.Height; y++)
            {
                const BYTE *src = (const BYTE *)map.pData + (size_t)y * map.RowPitch;
                BYTE *dst = out + (size_t)y * desc.Width * 4;
                if (s->pixfmt == DXGI_FMT_RGBA)
                    for (x = 0; x < desc.Width; x++)
                    { dst[x * 4] = src[x * 4 + 2]; dst[x * 4 + 1] = src[x * 4 + 1]; dst[x * 4 + 2] = src[x * 4]; dst[x * 4 + 3] = src[x * 4 + 3]; }
                else
                    memcpy(dst, src, (size_t)desc.Width * 4);
            }
            *pixels = out; *w = desc.Width; *h = desc.Height;
        }
        else hr = E_OUTOFMEMORY;
        ID3D11DeviceContext_Unmap(ctx, (ID3D11Resource *)stage, 0);
    }
    ID3D11DeviceContext_Release(ctx);
    ID3D11Texture2D_Release(stage);
    return hr;
}

/* ---- INitroDrawingSurfaceInterop ---- */

#define DSI(i) CONTAINING_RECORD(i, struct cobj, dsinterop)

static HRESULT STDMETHODCALLTYPE dsi_QueryInterface(INitroDrawingSurfaceInterop *i, REFIID iid, void **o)
{ return IInspectable_QueryInterface(&DSI(i)->identity, iid, o); }
static ULONG STDMETHODCALLTYPE dsi_AddRef(INitroDrawingSurfaceInterop *i)
{ return IInspectable_AddRef(&DSI(i)->identity); }
static ULONG STDMETHODCALLTYPE dsi_Release(INitroDrawingSurfaceInterop *i)
{ return IInspectable_Release(&DSI(i)->identity); }

static BOOL rect_valid(const RECT *r, UINT w, UINT h)
{
    return r->left >= 0 && r->top >= 0 && r->right <= (LONG)w && r->bottom <= (LONG)h &&
           r->left < r->right && r->top < r->bottom;
}

static HRESULT STDMETHODCALLTYPE dsi_BeginDraw(INitroDrawingSurfaceInterop *i, const RECT *updateRect, REFIID iid,
        void **updateObject, POINT *updateOffset)
{
    struct cobj *s = DSI(i);
    ID2D1DeviceContext *dc = NULL;
    ID2D1Bitmap1 *bmp = NULL;
    IDXGISurface *dxgi = NULL;
    ID3D11Texture2D *tex;
    ID2D1Device *d2d;
    RECT rc;
    HRESULT hr;

    if (!updateObject || !updateOffset) return E_POINTER;
    *updateObject = NULL;
    comp_lock();
    tex = (ID3D11Texture2D *)s->tex;
    d2d = s->gfxdev ? (ID2D1Device *)s->gfxdev->d2d : NULL;
    if (!tex || !d2d) { comp_unlock(); return RO_E_CLOSED; }
    if (s->drawing) { comp_unlock(); return E_FAIL; }
    if (updateRect)
    {
        rc = *updateRect;
        if (!rect_valid(&rc, s->width, s->height)) { comp_unlock(); return E_INVALIDARG; }
    }
    else
    {
        rc.left = rc.top = 0; rc.right = s->width; rc.bottom = s->height;
    }
    ID3D11Texture2D_AddRef(tex);
    ID2D1Device_AddRef(d2d);
    s->drawing = TRUE;                  /* claimed; undone on failure */
    comp_unlock();

    /* plain DXGI / D3D requests: hand out the texture itself */
    if (SUCCEEDED(hr = ID3D11Texture2D_QueryInterface(tex, iid, updateObject)))
        goto done;

    hr = ID3D11Texture2D_QueryInterface(tex, &IID_IDXGISurface, (void **)&dxgi);
    if (FAILED(hr)) FIXME("BeginDraw: the texture has no IDXGISurface: %#lx\n", hr);
    if (SUCCEEDED(hr) && FAILED(hr = ID2D1Device_CreateDeviceContext(d2d, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &dc)))
        FIXME("BeginDraw: ID2D1Device::CreateDeviceContext failed: %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        D2D1_BITMAP_PROPERTIES1 props = { 0 };

        props.pixelFormat.format = (DXGI_FORMAT)s->pixfmt;
        props.pixelFormat.alphaMode = s->alphamode == 3 ? D2D1_ALPHA_MODE_IGNORE : D2D1_ALPHA_MODE_PREMULTIPLIED;
        props.dpiX = props.dpiY = 96.0f;
        props.bitmapOptions = D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW;
        if (FAILED(hr = ID2D1DeviceContext_CreateBitmapFromDxgiSurface(dc, dxgi, &props, &bmp)))
            FIXME("BeginDraw: CreateBitmapFromDxgiSurface failed: %#lx (format %d)\n", hr, s->pixfmt);
    }
    if (SUCCEEDED(hr))
    {
        D2D1_RECT_F clip;
        void *obj = NULL;

        /* the context must give the requested interface before it starts drawing */
        if (FAILED(hr = ID2D1DeviceContext_QueryInterface(dc, iid, &obj)))
        {
            WARN("BeginDraw: interface %s is not available\n", debugstr_guid(iid));
        }
        else
        {
            ID2D1DeviceContext_SetTarget(dc, (ID2D1Image *)bmp);
            ID2D1DeviceContext_BeginDraw(dc);
            clip.left = (float)rc.left; clip.top = (float)rc.top; clip.right = (float)rc.right; clip.bottom = (float)rc.bottom;
            ID2D1DeviceContext_PushAxisAlignedClip(dc, &clip, D2D1_ANTIALIAS_MODE_ALIASED);
            *updateObject = obj;
            comp_lock(); s->dc = (IUnknown *)dc; s->dcbitmap = (IUnknown *)bmp; comp_unlock();
            dc = NULL; bmp = NULL;
        }
    }
done:
    if (dxgi) IDXGISurface_Release(dxgi);
    if (bmp) ID2D1Bitmap1_Release(bmp);
    if (dc) ID2D1DeviceContext_Release(dc);
    ID2D1Device_Release(d2d);
    ID3D11Texture2D_Release(tex);
    if (SUCCEEDED(hr))
    {
        updateOffset->x = rc.left;
        updateOffset->y = rc.top;
    }
    else
    {
        comp_lock(); s->drawing = FALSE; comp_unlock();
    }
    return hr;
}

static HRESULT STDMETHODCALLTYPE dsi_EndDraw(INitroDrawingSurfaceInterop *i)
{
    struct cobj *s = DSI(i);
    ID2D1DeviceContext *dc;
    IUnknown *bmp;
    HRESULT hr = S_OK;

    comp_lock();
    if (!s->drawing) { comp_unlock(); return E_FAIL; }
    dc = (ID2D1DeviceContext *)s->dc; s->dc = NULL;
    bmp = s->dcbitmap; s->dcbitmap = NULL;
    s->drawing = FALSE;
    s->suspended = FALSE;
    comp_unlock();
    if (dc)
    {
        ID2D1DeviceContext_PopAxisAlignedClip(dc);
        hr = ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
        ID2D1DeviceContext_SetTarget(dc, NULL);
        ID2D1DeviceContext_Release(dc);
    }
    if (bmp) IUnknown_Release(bmp);
    return hr;
}

static HRESULT STDMETHODCALLTYPE dsi_Resize(INitroDrawingSurfaceInterop *i, SIZE size)
{
    struct cobj *s = DSI(i);
    ID3D11Device *d3d;
    ID3D11Texture2D *tex, *old;
    ID3D11DeviceContext *ctx;
    D3D11_BOX box;
    HRESULT hr;

    if (size.cx < 1 || size.cy < 1 || size.cx > 16384 || size.cy > 16384) return E_INVALIDARG;
    comp_lock();
    d3d = s->gfxdev ? (ID3D11Device *)s->gfxdev->d3d : NULL;
    if (!s->tex || !d3d) { comp_unlock(); return RO_E_CLOSED; }
    if (s->drawing) { comp_unlock(); return E_FAIL; }
    if (FAILED(hr = make_texture(d3d, size.cx, size.cy, s->pixfmt, &tex))) { comp_unlock(); return hr; }
    /* the overlapping part keeps its pixels */
    ID3D11Device_GetImmediateContext(d3d, &ctx);
    box.left = box.top = box.front = 0;
    box.right = min((UINT)size.cx, s->width); box.bottom = min((UINT)size.cy, s->height); box.back = 1;
    ID3D11DeviceContext_CopySubresourceRegion(ctx, (ID3D11Resource *)tex, 0, 0, 0, 0, (ID3D11Resource *)s->tex, 0, &box);
    ID3D11DeviceContext_Release(ctx);
    old = (ID3D11Texture2D *)s->tex; s->tex = (IUnknown *)tex;
    s->width = size.cx; s->height = size.cy;
    comp_unlock();
    ID3D11Texture2D_Release(old);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dsi_Scroll(INitroDrawingSurfaceInterop *i, const RECT *scrollRect, const RECT *clipRect,
        int offsetX, int offsetY)
{
    struct cobj *s = DSI(i);
    ID3D11Device *d3d;
    ID3D11Texture2D *tmp;
    ID3D11DeviceContext *ctx;
    RECT src, dst, clip;
    D3D11_BOX box;
    HRESULT hr;

    comp_lock();
    d3d = s->gfxdev ? (ID3D11Device *)s->gfxdev->d3d : NULL;
    if (!s->tex || !d3d) { comp_unlock(); return RO_E_CLOSED; }
    if (s->drawing) { comp_unlock(); return E_FAIL; }
    if (scrollRect) src = *scrollRect; else { src.left = src.top = 0; src.right = s->width; src.bottom = s->height; }
    if (clipRect) clip = *clipRect; else { clip.left = clip.top = 0; clip.right = s->width; clip.bottom = s->height; }
    if (!rect_valid(&src, s->width, s->height)) { comp_unlock(); return E_INVALIDARG; }
    /* destination = scrollRect moved, clipped by clipRect and the surface */
    dst.left = max(max(src.left + offsetX, clip.left), 0);
    dst.top = max(max(src.top + offsetY, clip.top), 0);
    dst.right = min(min(src.right + offsetX, clip.right), (LONG)s->width);
    dst.bottom = min(min(src.bottom + offsetY, clip.bottom), (LONG)s->height);
    if (dst.left >= dst.right || dst.top >= dst.bottom) { comp_unlock(); return S_OK; }
    if (FAILED(hr = make_texture(d3d, s->width, s->height, s->pixfmt, &tmp))) { comp_unlock(); return hr; }
    ID3D11Device_GetImmediateContext(d3d, &ctx);
    ID3D11DeviceContext_CopyResource(ctx, (ID3D11Resource *)tmp, (ID3D11Resource *)s->tex);
    box.left = dst.left - offsetX; box.top = dst.top - offsetY;
    box.right = dst.right - offsetX; box.bottom = dst.bottom - offsetY;
    box.front = 0; box.back = 1;
    ID3D11DeviceContext_CopySubresourceRegion(ctx, (ID3D11Resource *)s->tex, 0, dst.left, dst.top, 0, (ID3D11Resource *)tmp, 0, &box);
    ID3D11DeviceContext_Release(ctx);
    comp_unlock();
    ID3D11Texture2D_Release(tmp);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dsi_ResumeDraw(INitroDrawingSurfaceInterop *i)
{
    struct cobj *s = DSI(i);
    HRESULT hr = E_FAIL;

    comp_lock();
    if (s->drawing && s->suspended) { s->suspended = FALSE; hr = S_OK; }
    comp_unlock();
    return hr;
}

static HRESULT STDMETHODCALLTYPE dsi_SuspendDraw(INitroDrawingSurfaceInterop *i)
{
    struct cobj *s = DSI(i);
    HRESULT hr = E_FAIL;

    comp_lock();
    if (s->drawing && !s->suspended) { s->suspended = TRUE; hr = S_OK; }
    comp_unlock();
    return hr;
}

const INitroDrawingSurfaceInteropVtbl nitro_dsinterop_vtbl =
{
    dsi_QueryInterface, dsi_AddRef, dsi_Release,
    dsi_BeginDraw, dsi_EndDraw, dsi_Resize, dsi_Scroll, dsi_ResumeDraw, dsi_SuspendDraw
};
