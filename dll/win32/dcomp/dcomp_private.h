/*
 * PROJECT:     ReactOS DirectComposition
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     C declarations of the DirectComposition interfaces dcomp.dll implements
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The SDK has no dcomp.h. The vtables follow the documented interfaces in the order a C++ compiler for
 * Windows lays them out: of an overloaded pair, the one declared second in the C++ header comes first.
 */

#pragma once

typedef struct IDCompositionDevice IDCompositionDevice;
typedef struct IDCompositionTarget IDCompositionTarget;
typedef struct IDCompositionVisual IDCompositionVisual;

typedef struct tagDCOMPOSITION_FRAME_STATISTICS
{
    LARGE_INTEGER lastFrameTime;
    DXGI_RATIONAL currentCompositionRate;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER timeFrequency;
    LARGE_INTEGER nextEstimatedFrameTime;
} DCOMPOSITION_FRAME_STATISTICS;

typedef struct IDCompositionDeviceVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDCompositionDevice *iface, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDCompositionDevice *iface);
    ULONG (STDMETHODCALLTYPE *Release)(IDCompositionDevice *iface);
    HRESULT (STDMETHODCALLTYPE *Commit)(IDCompositionDevice *iface);
    HRESULT (STDMETHODCALLTYPE *WaitForCommitCompletion)(IDCompositionDevice *iface);
    HRESULT (STDMETHODCALLTYPE *GetFrameStatistics)(IDCompositionDevice *iface, DCOMPOSITION_FRAME_STATISTICS *stats);
    HRESULT (STDMETHODCALLTYPE *CreateTargetForHwnd)(IDCompositionDevice *iface, HWND window, BOOL topmost,
            IDCompositionTarget **target);
    HRESULT (STDMETHODCALLTYPE *CreateVisual)(IDCompositionDevice *iface, IDCompositionVisual **visual);
    HRESULT (STDMETHODCALLTYPE *CreateSurface)(IDCompositionDevice *iface, UINT width, UINT height,
            DXGI_FORMAT format, DXGI_ALPHA_MODE alpha_mode, IUnknown **surface);
    HRESULT (STDMETHODCALLTYPE *CreateVirtualSurface)(IDCompositionDevice *iface, UINT width, UINT height,
            DXGI_FORMAT format, DXGI_ALPHA_MODE alpha_mode, IUnknown **surface);
    HRESULT (STDMETHODCALLTYPE *CreateSurfaceFromHandle)(IDCompositionDevice *iface, HANDLE handle, IUnknown **surface);
    HRESULT (STDMETHODCALLTYPE *CreateSurfaceFromHwnd)(IDCompositionDevice *iface, HWND window, IUnknown **surface);
    HRESULT (STDMETHODCALLTYPE *CreateTranslateTransform)(IDCompositionDevice *iface, IUnknown **transform);
    HRESULT (STDMETHODCALLTYPE *CreateScaleTransform)(IDCompositionDevice *iface, IUnknown **transform);
    HRESULT (STDMETHODCALLTYPE *CreateRotateTransform)(IDCompositionDevice *iface, IUnknown **transform);
    HRESULT (STDMETHODCALLTYPE *CreateSkewTransform)(IDCompositionDevice *iface, IUnknown **transform);
    HRESULT (STDMETHODCALLTYPE *CreateMatrixTransform)(IDCompositionDevice *iface, IUnknown **transform);
    HRESULT (STDMETHODCALLTYPE *CreateTransformGroup)(IDCompositionDevice *iface, IUnknown **transforms,
            UINT count, IUnknown **group);
    HRESULT (STDMETHODCALLTYPE *CreateTranslateTransform3D)(IDCompositionDevice *iface, IUnknown **transform);
    HRESULT (STDMETHODCALLTYPE *CreateScaleTransform3D)(IDCompositionDevice *iface, IUnknown **transform);
    HRESULT (STDMETHODCALLTYPE *CreateRotateTransform3D)(IDCompositionDevice *iface, IUnknown **transform);
    HRESULT (STDMETHODCALLTYPE *CreateMatrixTransform3D)(IDCompositionDevice *iface, IUnknown **transform);
    HRESULT (STDMETHODCALLTYPE *CreateTransform3DGroup)(IDCompositionDevice *iface, IUnknown **transforms,
            UINT count, IUnknown **group);
    HRESULT (STDMETHODCALLTYPE *CreateEffectGroup)(IDCompositionDevice *iface, IUnknown **group);
    HRESULT (STDMETHODCALLTYPE *CreateRectangleClip)(IDCompositionDevice *iface, IUnknown **clip);
    HRESULT (STDMETHODCALLTYPE *CreateAnimation)(IDCompositionDevice *iface, IUnknown **animation);
    HRESULT (STDMETHODCALLTYPE *CheckDeviceState)(IDCompositionDevice *iface, BOOL *valid);
} IDCompositionDeviceVtbl;

struct IDCompositionDevice
{
    const IDCompositionDeviceVtbl *lpVtbl;
};

typedef struct IDCompositionTargetVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDCompositionTarget *iface, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDCompositionTarget *iface);
    ULONG (STDMETHODCALLTYPE *Release)(IDCompositionTarget *iface);
    HRESULT (STDMETHODCALLTYPE *SetRoot)(IDCompositionTarget *iface, IDCompositionVisual *visual);
} IDCompositionTargetVtbl;

struct IDCompositionTarget
{
    const IDCompositionTargetVtbl *lpVtbl;
};

typedef struct IDCompositionVisualVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDCompositionVisual *iface, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDCompositionVisual *iface);
    ULONG (STDMETHODCALLTYPE *Release)(IDCompositionVisual *iface);
    HRESULT (STDMETHODCALLTYPE *SetOffsetXAnimation)(IDCompositionVisual *iface, IUnknown *animation);
    HRESULT (STDMETHODCALLTYPE *SetOffsetX)(IDCompositionVisual *iface, float offset);
    HRESULT (STDMETHODCALLTYPE *SetOffsetYAnimation)(IDCompositionVisual *iface, IUnknown *animation);
    HRESULT (STDMETHODCALLTYPE *SetOffsetY)(IDCompositionVisual *iface, float offset);
    HRESULT (STDMETHODCALLTYPE *SetTransformObject)(IDCompositionVisual *iface, IUnknown *transform);
    HRESULT (STDMETHODCALLTYPE *SetTransform)(IDCompositionVisual *iface, const void *matrix);
    HRESULT (STDMETHODCALLTYPE *SetTransformParent)(IDCompositionVisual *iface, IDCompositionVisual *visual);
    HRESULT (STDMETHODCALLTYPE *SetEffect)(IDCompositionVisual *iface, IUnknown *effect);
    HRESULT (STDMETHODCALLTYPE *SetBitmapInterpolationMode)(IDCompositionVisual *iface, int mode);
    HRESULT (STDMETHODCALLTYPE *SetBorderMode)(IDCompositionVisual *iface, int mode);
    HRESULT (STDMETHODCALLTYPE *SetClipObject)(IDCompositionVisual *iface, IUnknown *clip);
    HRESULT (STDMETHODCALLTYPE *SetClip)(IDCompositionVisual *iface, const void *rect);
    HRESULT (STDMETHODCALLTYPE *SetContent)(IDCompositionVisual *iface, IUnknown *content);
    HRESULT (STDMETHODCALLTYPE *AddVisual)(IDCompositionVisual *iface, IDCompositionVisual *visual,
            BOOL insert_above, IDCompositionVisual *reference);
    HRESULT (STDMETHODCALLTYPE *RemoveVisual)(IDCompositionVisual *iface, IDCompositionVisual *visual);
    HRESULT (STDMETHODCALLTYPE *RemoveAllVisuals)(IDCompositionVisual *iface);
    HRESULT (STDMETHODCALLTYPE *SetCompositeMode)(IDCompositionVisual *iface, int mode);
} IDCompositionVisualVtbl;

struct IDCompositionVisual
{
    const IDCompositionVisualVtbl *lpVtbl;
};

DEFINE_GUID(IID_IDCompositionDevice, 0xc37ea93a, 0xe7aa, 0x450d, 0xb1, 0x6f, 0x97, 0x46, 0xcb, 0x04, 0x07, 0xf3);
DEFINE_GUID(IID_IDCompositionTarget, 0xeacdd04c, 0x117e, 0x4e17, 0x88, 0xf4, 0xd1, 0xb1, 0x2b, 0x0e, 0x3d, 0x89);
DEFINE_GUID(IID_IDCompositionVisual, 0x4d93059d, 0x097b, 0x4651, 0x9a, 0x60, 0xf0, 0xf2, 0x51, 0x16, 0xe2, 0xf3);

#define IDCompositionDevice_QueryInterface(p, a, b) (p)->lpVtbl->QueryInterface(p, a, b)
#define IDCompositionDevice_AddRef(p) (p)->lpVtbl->AddRef(p)
#define IDCompositionDevice_Release(p) (p)->lpVtbl->Release(p)
#define IDCompositionTarget_AddRef(p) (p)->lpVtbl->AddRef(p)
#define IDCompositionTarget_Release(p) (p)->lpVtbl->Release(p)
#define IDCompositionVisual_AddRef(p) (p)->lpVtbl->AddRef(p)
#define IDCompositionVisual_Release(p) (p)->lpVtbl->Release(p)
