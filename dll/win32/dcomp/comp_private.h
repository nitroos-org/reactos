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

typedef __x_ABI_CWindows_CFoundation_CIClosable WIClosable;
typedef __x_ABI_CWindows_CFoundation_CIClosableVtbl WIClosableVtbl;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CVector2 Vec2;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CVector3 Vec3;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CQuaternion Quat;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CMatrix4x4 Mat4;

enum cobj_kind
{
    K_CONTAINER, K_SPRITE, K_VCOLL, K_COLORBRUSH, K_SURFBRUSH, K_INSETCLIP, K_GDEVICE, K_DSURFACE
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
