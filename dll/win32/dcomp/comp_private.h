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


/*
 * Windows.UI.Composition.Interactions.VisualInteractionSource and its interfaces.
 * Source: microsoft/windows-rs (MIT OR Apache-2.0), the published `windows` crate 0.62.2 (cargo vcs info: repository
 * microsoft/windows-rs, commit 32c3144490c016fe496a0aed769bce60987a2e9d, path crates/libs/windows), file
 * src/Windows/UI/Composition/Interactions/mod.rs (structs *_Vtbl give the slot order), cross-checked against
 * metadata/winrt/Windows.UI.Composition.Interactions.rdl of microsoft/windows-rs at commit
 * 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0 (guids, enum values, class layout). Only GUIDs, slot order, signatures and
 * enum values were taken, no code. Slots count from 6 (after IInspectable):
 *   IVisualInteractionSource  ca0e8a86-d8d6-4111-b088-70347bd2b0ed:
 *     6/7 get/put IsPositionXRailsEnabled, 8/9 ..YRails.., 10/11 ManipulationRedirectionMode,
 *     12/13 PositionXChainingMode, 14/15 PositionXSourceMode, 16/17 PositionYChainingMode, 18/19 PositionYSourceMode,
 *     20/21 ScaleChainingMode, 22/23 ScaleSourceMode, 24 get Source, 25 TryRedirectForManipulation(PointerPoint)
 *   IVisualInteractionSource2 aa914893-a73c-414d-80d0-249bad2fbd93:
 *     6 get DeltaPosition, 7 DeltaScale, 8 Position, 9 PositionVelocity, 10 Scale, 11 ScaleVelocity (Vector3/float),
 *     12 ConfigureCenterPointXModifiers, 13 ..CenterPointY.., 14 ..DeltaPositionX.., 15 ..DeltaPositionY.., 16 ..DeltaScale..
 *     (IIterable<CompositionConditionalValue>)
 *   IVisualInteractionSource3 d941ef2a-0d5c-4057-92d7-c9711533204f: 6 get PointerWheelConfig (InteractionSourceConfiguration)
 *   IVisualInteractionSourceObjectFactory b2ca917c-e98a-41f2-b3c9-891c9266c8f6: no members
 *   IVisualInteractionSourceStatics 369965e1-8645-4f75-ba00-6479cd10c8e6: 6 Create(Visual) -> VisualInteractionSource
 *   IVisualInteractionSourceStatics2 a979c032-5764-55e0-bc1f-0778786dcfde: 6 CreateFromIVisualElement(IVisualElement)
 *   ICompositionInteractionSource 043b2431-06e3-495a-ba54-409f0017fac0: no members
 *   enums (int32): InteractionChainingMode Auto 0, Always 1, Never 2; InteractionSourceMode Disabled 0, EnabledWithInertia 1,
 *   EnabledWithoutInertia 2; VisualInteractionSourceRedirectionMode Off 0, CapableTouchpadOnly 1, PointerWheelOnly 2,
 *   CapableTouchpadAndPointerWheel 3.
 */
typedef struct WIVisualInteractionSource WIVisualInteractionSource;
typedef struct WIVisualInteractionSourceVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIVisualInteractionSource *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIVisualInteractionSource *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIVisualInteractionSource *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIVisualInteractionSource *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIVisualInteractionSource *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIVisualInteractionSource *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_IsPositionXRailsEnabled)(WIVisualInteractionSource *This, BOOLEAN *value);
    HRESULT (STDMETHODCALLTYPE *put_IsPositionXRailsEnabled)(WIVisualInteractionSource *This, BOOLEAN value);
    HRESULT (STDMETHODCALLTYPE *get_IsPositionYRailsEnabled)(WIVisualInteractionSource *This, BOOLEAN *value);
    HRESULT (STDMETHODCALLTYPE *put_IsPositionYRailsEnabled)(WIVisualInteractionSource *This, BOOLEAN value);
    HRESULT (STDMETHODCALLTYPE *get_ManipulationRedirectionMode)(WIVisualInteractionSource *This, INT32 *value);
    HRESULT (STDMETHODCALLTYPE *put_ManipulationRedirectionMode)(WIVisualInteractionSource *This, INT32 value);
    HRESULT (STDMETHODCALLTYPE *get_PositionXChainingMode)(WIVisualInteractionSource *This, INT32 *value);
    HRESULT (STDMETHODCALLTYPE *put_PositionXChainingMode)(WIVisualInteractionSource *This, INT32 value);
    HRESULT (STDMETHODCALLTYPE *get_PositionXSourceMode)(WIVisualInteractionSource *This, INT32 *value);
    HRESULT (STDMETHODCALLTYPE *put_PositionXSourceMode)(WIVisualInteractionSource *This, INT32 value);
    HRESULT (STDMETHODCALLTYPE *get_PositionYChainingMode)(WIVisualInteractionSource *This, INT32 *value);
    HRESULT (STDMETHODCALLTYPE *put_PositionYChainingMode)(WIVisualInteractionSource *This, INT32 value);
    HRESULT (STDMETHODCALLTYPE *get_PositionYSourceMode)(WIVisualInteractionSource *This, INT32 *value);
    HRESULT (STDMETHODCALLTYPE *put_PositionYSourceMode)(WIVisualInteractionSource *This, INT32 value);
    HRESULT (STDMETHODCALLTYPE *get_ScaleChainingMode)(WIVisualInteractionSource *This, INT32 *value);
    HRESULT (STDMETHODCALLTYPE *put_ScaleChainingMode)(WIVisualInteractionSource *This, INT32 value);
    HRESULT (STDMETHODCALLTYPE *get_ScaleSourceMode)(WIVisualInteractionSource *This, INT32 *value);
    HRESULT (STDMETHODCALLTYPE *put_ScaleSourceMode)(WIVisualInteractionSource *This, INT32 value);
    HRESULT (STDMETHODCALLTYPE *get_Source)(WIVisualInteractionSource *This, WIVisual **value);
    HRESULT (STDMETHODCALLTYPE *TryRedirectForManipulation)(WIVisualInteractionSource *This, void *pointer_point);
} WIVisualInteractionSourceVtbl;
struct WIVisualInteractionSource { const WIVisualInteractionSourceVtbl *lpVtbl; };

typedef struct WIVisualInteractionSource2 WIVisualInteractionSource2;
typedef struct WIVisualInteractionSource2Vtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIVisualInteractionSource2 *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIVisualInteractionSource2 *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIVisualInteractionSource2 *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIVisualInteractionSource2 *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIVisualInteractionSource2 *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIVisualInteractionSource2 *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_DeltaPosition)(WIVisualInteractionSource2 *This, Vec3 *value);
    HRESULT (STDMETHODCALLTYPE *get_DeltaScale)(WIVisualInteractionSource2 *This, float *value);
    HRESULT (STDMETHODCALLTYPE *get_Position)(WIVisualInteractionSource2 *This, Vec3 *value);
    HRESULT (STDMETHODCALLTYPE *get_PositionVelocity)(WIVisualInteractionSource2 *This, Vec3 *value);
    HRESULT (STDMETHODCALLTYPE *get_Scale)(WIVisualInteractionSource2 *This, float *value);
    HRESULT (STDMETHODCALLTYPE *get_ScaleVelocity)(WIVisualInteractionSource2 *This, float *value);
    HRESULT (STDMETHODCALLTYPE *ConfigureCenterPointXModifiers)(WIVisualInteractionSource2 *This, void *values);
    HRESULT (STDMETHODCALLTYPE *ConfigureCenterPointYModifiers)(WIVisualInteractionSource2 *This, void *values);
    HRESULT (STDMETHODCALLTYPE *ConfigureDeltaPositionXModifiers)(WIVisualInteractionSource2 *This, void *values);
    HRESULT (STDMETHODCALLTYPE *ConfigureDeltaPositionYModifiers)(WIVisualInteractionSource2 *This, void *values);
    HRESULT (STDMETHODCALLTYPE *ConfigureDeltaScaleModifiers)(WIVisualInteractionSource2 *This, void *values);
} WIVisualInteractionSource2Vtbl;
struct WIVisualInteractionSource2 { const WIVisualInteractionSource2Vtbl *lpVtbl; };

typedef struct WIVisualInteractionSource3 WIVisualInteractionSource3;
typedef struct WIVisualInteractionSource3Vtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIVisualInteractionSource3 *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIVisualInteractionSource3 *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIVisualInteractionSource3 *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIVisualInteractionSource3 *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIVisualInteractionSource3 *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIVisualInteractionSource3 *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_PointerWheelConfig)(WIVisualInteractionSource3 *This, void **value);
} WIVisualInteractionSource3Vtbl;
struct WIVisualInteractionSource3 { const WIVisualInteractionSource3Vtbl *lpVtbl; };

/* ICompositionInteractionSource has no members: a plain IInspectable */
typedef struct WICompositionInteractionSource WICompositionInteractionSource;
typedef struct WICompositionInteractionSourceVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WICompositionInteractionSource *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WICompositionInteractionSource *This);
    ULONG (STDMETHODCALLTYPE *Release)(WICompositionInteractionSource *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WICompositionInteractionSource *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WICompositionInteractionSource *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WICompositionInteractionSource *This, TrustLevel *level);
} WICompositionInteractionSourceVtbl;
struct WICompositionInteractionSource { const WICompositionInteractionSourceVtbl *lpVtbl; };

DEFINE_GUID(IID_IVisualInteractionSource, 0xca0e8a86, 0xd8d6, 0x4111, 0xb0, 0x88, 0x70, 0x34, 0x7b, 0x2b, 0xd0, 0xed);
DEFINE_GUID(IID_IVisualInteractionSource2, 0xaa914893, 0xa73c, 0x414d, 0x80, 0xd0, 0x24, 0x9b, 0xad, 0x2f, 0xbd, 0x93);
DEFINE_GUID(IID_IVisualInteractionSource3, 0xd941ef2a, 0x0d5c, 0x4057, 0x92, 0xd7, 0xc9, 0x71, 0x15, 0x33, 0x20, 0x4f);
DEFINE_GUID(IID_IVisualInteractionSourceObjectFactory, 0xb2ca917c, 0xe98a, 0x41f2, 0xb3, 0xc9, 0x89, 0x1c, 0x92, 0x66, 0xc8, 0xf6);
DEFINE_GUID(IID_IVisualInteractionSourceStatics, 0x369965e1, 0x8645, 0x4f75, 0xba, 0x00, 0x64, 0x79, 0xcd, 0x10, 0xc8, 0xe6);
DEFINE_GUID(IID_IVisualInteractionSourceStatics2, 0xa979c032, 0x5764, 0x55e0, 0xbc, 0x1f, 0x07, 0x78, 0x78, 0x6d, 0xcf, 0xde);
DEFINE_GUID(IID_ICompositionInteractionSource, 0x043b2431, 0x06e3, 0x495a, 0xba, 0x54, 0x40, 0x9f, 0x00, 0x17, 0xfa, 0xc0);

enum cobj_kind
{
    K_CONTAINER, K_SPRITE, K_VCOLL, K_COLORBRUSH, K_SURFBRUSH, K_INSETCLIP, K_GDEVICE, K_DSURFACE, K_TARGET, K_VISRC
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
    WIVisualInteractionSource visrc;
    WIVisualInteractionSource2 visrc2;
    WIVisualInteractionSource3 visrc3;
    WICompositionInteractionSource intsrc;
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

    /* VisualInteractionSource (nothing is routed to it yet: no input redirection, no InteractionTracker) */
    struct cobj *isource;           /* VisualInteractionSource.Source, referenced */
    BOOLEAN rails_x, rails_y;
    INT32 redirect_mode;
    INT32 chain_px, chain_py, chain_s;
    INT32 mode_px, mode_py, mode_s;
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
/* *out: the IVisualInteractionSource interface of the new object (one reference); source is a visual of this object model */
HRESULT comp_new_visual_interaction_source(WIVisual *source, WIVisualInteractionSource **out);
