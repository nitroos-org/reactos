/*
 * PROJECT:     ReactOS DirectComposition
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows.UI.Composition object model: shared declarations (stages 2 and 3)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

/* include the windows.ui.composition headers first */

#include "dcomp_nitro.h"

#define WUC(n) __x_ABI_CWindows_CUI_CComposition_C##n
#define WIFACE(n) typedef WUC(n) W##n; typedef WUC(n##Vtbl) W##n##Vtbl;
WIFACE(ICompositionObject)
WIFACE(IVisual)
WIFACE(IContainerVisual)
WIFACE(ISpriteVisual)
WIFACE(IVisualCollection)
WIFACE(ICompositionBrush)
WIFACE(ICompositionColorBrush)
WIFACE(ICompositionSurfaceBrush)
WIFACE(ICompositionClip)
WIFACE(IInsetClip)
WIFACE(ICompositionGraphicsDevice)
WIFACE(ICompositionSurface)
WIFACE(ICompositionDrawingSurface)
WIFACE(ICompositor)
WIFACE(ICompositionTarget)

typedef __x_ABI_CWindows_CFoundation_CIClosable WIClosable;
typedef __x_ABI_CWindows_CFoundation_CIClosableVtbl WIClosableVtbl;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CVector2 Vec2;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CVector3 Vec3;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CQuaternion Quat;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CMatrix4x4 Mat4;

/*
 * Windows.UI.Composition.Desktop.IDesktopWindowTarget and Windows.Win32 IDesktopWindowTargetInterop.
 * Source: microsoft/windows-rs (MIT OR Apache-2.0) at commit 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0:
 *   metadata/winrt/Windows.UI.Composition.Desktop.rdl  interface IDesktopWindowTarget
 *       guid 6329d6ca-3366-490e-9db3-25312929ac51, one member: get IsTopmost: bool (slot 6, after IInspectable);
 *   metadata/win32/windowsuicompositioninterop.rdl  interface IDesktopWindowTargetInterop: IUnknown
 *       guid 35dbf59e-e3f9-45b0-81e7-fe75f4145dc9, one member: get_Hwnd(HWND *value) (slot 3).
 * Only the GUIDs, the slot order and the signatures were taken, no code.
 */
typedef struct WIDesktopWindowTarget WIDesktopWindowTarget;
typedef struct WIDesktopWindowTargetVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIDesktopWindowTarget *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIDesktopWindowTarget *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIDesktopWindowTarget *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIDesktopWindowTarget *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIDesktopWindowTarget *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIDesktopWindowTarget *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_IsTopmost)(WIDesktopWindowTarget *This, BOOLEAN *value);
} WIDesktopWindowTargetVtbl;
struct WIDesktopWindowTarget { const WIDesktopWindowTargetVtbl *lpVtbl; };

typedef struct WIDesktopWindowTargetInterop WIDesktopWindowTargetInterop;
typedef struct WIDesktopWindowTargetInteropVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIDesktopWindowTargetInterop *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIDesktopWindowTargetInterop *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIDesktopWindowTargetInterop *This);
    HRESULT (STDMETHODCALLTYPE *get_Hwnd)(WIDesktopWindowTargetInterop *This, HWND *value);
} WIDesktopWindowTargetInteropVtbl;
struct WIDesktopWindowTargetInterop { const WIDesktopWindowTargetInteropVtbl *lpVtbl; };

DEFINE_GUID(IID_IDesktopWindowTarget, 0x6329d6ca, 0x3366, 0x490e, 0x9d, 0xb3, 0x25, 0x31, 0x29, 0x29, 0xac, 0x51);
DEFINE_GUID(IID_IDesktopWindowTargetInterop, 0x35dbf59e, 0xe3f9, 0x45b0, 0x81, 0xe7, 0xfe, 0x75, 0xf4, 0x14, 0x5d, 0xc9);

enum cobj_kind
{
    K_CONTAINER, K_SPRITE, K_VCOLL, K_COLORBRUSH, K_SURFBRUSH, K_INSETCLIP, K_GDEVICE, K_DSURFACE, K_TARGET
};
#define KM(k) (1u << (k))
#define KM_VISUAL (KM(K_CONTAINER) | KM(K_SPRITE))
#define KM_BRUSH  (KM(K_COLORBRUSH) | KM(K_SURFBRUSH))
#define KM_ALL    0xffffffffu

struct cobj
{
    IInspectable identity;
    WICompositionObject objbase;
    WIVisual visual;
    WIContainerVisual container;
    WISpriteVisual sprite;
    WIVisualCollection vcoll;
    WICompositionBrush brush;
    WICompositionColorBrush colorbrush;
    WICompositionSurfaceBrush surfbrush;
    WICompositionClip clip;
    WIInsetClip inset;
    WICompositionGraphicsDevice gdev;
    WICompositionSurface surface;
    WICompositionDrawingSurface dsurf;
    WICompositionTarget target;
    WIDesktopWindowTarget dwt;
    WIDesktopWindowTargetInterop dwtinterop;
    INitroDrawingSurfaceInterop dsinterop;
    INitroCompositionTest test;
    WIClosable closable;
    IAgileObject agile;

    LONG ref;
    enum cobj_kind kind;
    BOOL closed;
    IUnknown *marshal;
    IUnknown *compositor;           /* identity of the Compositor, referenced */

    /* visuals */
    Vec2 anchor, size;
    Vec3 center, offset, axis, scale;
    Quat orientation;
    float opacity, rotation;
    Mat4 xform;
    BOOL visible;
    int backface, border, composite;
    struct cobj *vclip;             /* referenced */
    struct cobj *parent;            /* weak */
    struct cobj **kids;             /* referenced, bottom to top */
    int nkids, capkids;
    struct cobj *collection;        /* ContainerVisual.Children: weak, the object lives as long as someone holds it */
    struct cobj *sbrush;            /* SpriteVisual.Brush, referenced */

    /* VisualCollection */
    struct cobj *owner;             /* weak, cleared when the owner is destroyed */

    /* color brush */
    __x_ABI_CWindows_CUI_CColor color;

    /* surface brush */
    int bitmap_interp, stretch;
    float halign, valign;
    IUnknown *bsurface;             /* the ICompositionSurface identity, referenced */

    /* inset clip */
    float inset_l, inset_t, inset_r, inset_b;

    /* graphics device and drawing surface (compgfx.c) */
    IUnknown *d3d;                  /* ID3D11Device */
    IUnknown *d2d;                  /* ID2D1Device */
    struct cobj *gfxdev;            /* drawing surface: its device, referenced */
    IUnknown *tex;                  /* ID3D11Texture2D */
    UINT width, height;
    int pixfmt, alphamode;
    IUnknown *dc;                   /* ID2D1DeviceContext between BeginDraw and EndDraw */
    IUnknown *dcbitmap;             /* ID2D1Bitmap1 */
    BOOL drawing, suspended;

    /* DesktopWindowTarget */
    HWND hwnd;                      /* the window it was created for; nothing is presented to it yet */
    BOOL topmost;                   /* IDesktopWindowTarget.IsTopmost */
    struct cobj *root;              /* CompositionTarget.Root, referenced */
};

void comp_lock(void);
void comp_unlock(void);
struct cobj *comp_alloc_obj(enum cobj_kind kind, IUnknown *compositor);
extern LONG comp_object_count;

/* compgfx.c */
HRESULT gfx_device_init(struct cobj *dev, IUnknown *device);
void gfx_device_free(struct cobj *dev);
HRESULT gfx_surface_create(struct cobj *dev, Vec2 size, int format, int alpha, struct cobj **out);
void gfx_surface_free(struct cobj *s);
HRESULT gfx_surface_snapshot(struct cobj *s, BYTE **pixels, UINT *w, UINT *h);
EXTERN_C const INitroDrawingSurfaceInteropVtbl nitro_dsinterop_vtbl;

/* winrt.c <-> composition.c */
HRESULT comp_new_object(IUnknown *compositor, enum cobj_kind kind, REFIID want, void **out);
HRESULT comp_new_graphics_device(IUnknown *compositor, IUnknown *device, WICompositionGraphicsDevice **out);
struct cobj *cobj_from_iface(void *iface, size_t offset);
HRESULT comp_surface_brush_set_surface(struct cobj *brush, WICompositionSurface *surface);
HRESULT comp_create(IUnknown *compositor, enum cobj_kind kind, struct cobj **out);
/* *out: the IDesktopWindowTarget interface of the new object (one reference) */
HRESULT comp_new_desktop_target(IUnknown *compositor, HWND hwnd, BOOL topmost, WIDesktopWindowTarget **out);
