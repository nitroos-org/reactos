/*
 * PROJECT:     ReactOS DirectComposition
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows.UI.Composition WinRT classes: activation, Compositor and CompositorController (stages 1-3)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows registers Windows.UI.Composition.Compositor and Windows.UI.Composition.Core.CompositorController
 * with dcomp.dll as their server (measured in the registry of Windows 10 22H2), so the classes live here.
 * Interface definitions come from the IDLs in sdk/include/psdk (Wine, LGPL; the ICompositorInterop IID is also
 * in the mingw-w64 headers). Both classes are agile and free-threaded (documented: marshaling_behavior(agile),
 * threading(both)).
 *
 * The Compositor creates the stage 2 object model (composition.c: ContainerVisual, SpriteVisual, brushes, InsetClip)
 * and, through ICompositorInterop::CreateGraphicsDevice, the stage 3 graphics device and drawing surfaces
 * (compgfx.c). Every other member of ICompositor and ICompositorInterop returns E_NOTIMPL and logs a FIXME
 * naming interface and member. ICompositorDesktopInterop::CreateDesktopWindowTarget creates a
 * Windows.UI.Composition.Desktop.DesktopWindowTarget (composition.c) that keeps CompositionTarget.Root but does
 * not present anything yet (stage 4). An interface that has no clean public source for its IID stays a FIXME as
 * well: QueryInterface for an IID the object does not know logs it by value, so the log shows which interface a
 * caller asks for next. Known gaps (no IID or vtable from learn.microsoft.com, Wine or mingw-w64):
 *   ICompositorController (Compositor, Commit, EnsurePreviousCommitCompletedAsync, CommitNeeded),
 *   ICompositorDesktopInterop methods after CreateDesktopWindowTarget, IDesktopWindowTarget (IsTopmost),
 *   ICompositor2 .. ICompositor7 and the other ICompositorWith* interfaces, ICompositorStatics.
 */

#include <stdarg.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "objbase.h"
#include "initguid.h"
#include "inspectable.h"
#include "activation.h"
#include "winstring.h"
#include <wchar.h>
#include <windows.foundation.h>
#include <windows.ui.composition.h>
#include <windows.ui.composition.interop.h>
#include "comp_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

typedef __x_ABI_CWindows_CUI_CComposition_CICompositor ICompositor;
typedef __x_ABI_CWindows_CUI_CComposition_CICompositorVtbl ICompositorVtbl;
typedef __x_ABI_CWindows_CUI_CComposition_CICompositorInterop ICompositorInterop;
typedef __x_ABI_CWindows_CUI_CComposition_CICompositorInteropVtbl ICompositorInteropVtbl;
typedef __x_ABI_CWindows_CFoundation_CIClosable IClosable;
typedef __x_ABI_CWindows_CFoundation_CIClosableVtbl IClosableVtbl;

/*
 * ICompositorDesktopInterop (windows.ui.composition.interop.h). Source: the C# declaration of the interface on
 * learn.microsoft.com, "Using the Visual layer with Windows Forms" (MicrosoftDocs/windows-dev-docs-pr,
 * uwp/composition/using-the-visual-layer-with-windows-forms.md, page git_commit_id
 * 6b6b4abfd0405ca8dc14905fd4aa4ab21ca74fee; the WPF page carries the same declaration):
 * [Guid("29E691FA-4567-4DCA-B319-D0F207EB6807")], InterfaceIsIUnknown, first method
 * CreateDesktopWindowTarget(HWND hwndTarget, BOOL isTopmost, IDesktopWindowTarget **result). That page declares no
 * further method, so this vtable ends there: a later method has no public source for its slot.
 * The result is documented as a DesktopWindowTarget; the page's sample only queries it for ICompositionTarget.
 * IDesktopWindowTarget itself has no public IID, so the pointer returned is the object's IInspectable identity.
 */
typedef struct ICompositorDesktopInterop ICompositorDesktopInterop;
typedef struct ICompositorDesktopInteropVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICompositorDesktopInterop *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICompositorDesktopInterop *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICompositorDesktopInterop *This);
    HRESULT (STDMETHODCALLTYPE *CreateDesktopWindowTarget)(ICompositorDesktopInterop *This, HWND hwnd, BOOL topmost,
            IInspectable **result);
} ICompositorDesktopInteropVtbl;
struct ICompositorDesktopInterop { const ICompositorDesktopInteropVtbl *lpVtbl; };

DEFINE_GUID(IID_ICompositorDesktopInterop, 0x29e691fa, 0x4567, 0x4dca, 0xb3, 0x19, 0xd0, 0xf2, 0x07, 0xeb, 0x68, 0x07);

static const WCHAR name_compositor[] = L"Windows.UI.Composition.Compositor";
static const WCHAR name_controller[] = L"Windows.UI.Composition.Core.CompositorController";

static IUnknown *comp_identity(ICompositor *i);
static IUnknown *interop_identity(ICompositorInterop *i);
/* ---- ICompositor: the object model members are real (stage 2), the rest E_NOTIMPL ---- */

static HRESULT STDMETHODCALLTYPE compositor_CreateColorKeyFrameAnimation(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CIColorKeyFrameAnimation **result)
{
    FIXME("ICompositor::CreateColorKeyFrameAnimation: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateColorBrush(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CICompositionColorBrush **result)
{
    return comp_new_object(comp_identity(This), K_COLORBRUSH, &IID___x_ABI_CWindows_CUI_CComposition_CICompositionColorBrush, (void **)result);
}

static HRESULT STDMETHODCALLTYPE compositor_CreateColorBrushWithColor(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CColor color, __x_ABI_CWindows_CUI_CComposition_CICompositionColorBrush **result)
{
    HRESULT hr = comp_new_object(comp_identity(This), K_COLORBRUSH,
            &IID___x_ABI_CWindows_CUI_CComposition_CICompositionColorBrush, (void **)result);
    if (SUCCEEDED(hr)) CONTAINING_RECORD(*result, struct cobj, colorbrush)->color = color;
    return hr;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateContainerVisual(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CIContainerVisual **result)
{
    return comp_new_object(comp_identity(This), K_CONTAINER, &IID___x_ABI_CWindows_CUI_CComposition_CIContainerVisual, (void **)result);
}

static HRESULT STDMETHODCALLTYPE compositor_CreateCubicBezierEasingFunction(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CFoundation_CNumerics_CVector2 point1, __x_ABI_CWindows_CFoundation_CNumerics_CVector2 point2, __x_ABI_CWindows_CUI_CComposition_CICubicBezierEasingFunction **result)
{
    FIXME("ICompositor::CreateCubicBezierEasingFunction: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateEffectFactory(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CGraphics_CEffects_CIGraphicsEffect *effect, __x_ABI_CWindows_CUI_CComposition_CICompositionEffectFactory **result)
{
    FIXME("ICompositor::CreateEffectFactory: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateEffectFactoryWithProperties(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CGraphics_CEffects_CIGraphicsEffect *effect, __FIIterable_1_HSTRING *animatable, __x_ABI_CWindows_CUI_CComposition_CICompositionEffectFactory **result)
{
    FIXME("ICompositor::CreateEffectFactoryWithProperties: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateExpressionAnimation(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation **result)
{
    FIXME("ICompositor::CreateExpressionAnimation: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateExpressionAnimationWithExpression(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, HSTRING expression, __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation **result)
{
    FIXME("ICompositor::CreateExpressionAnimationWithExpression: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateInsetClip(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CIInsetClip **result)
{
    return comp_new_object(comp_identity(This), K_INSETCLIP, &IID___x_ABI_CWindows_CUI_CComposition_CIInsetClip, (void **)result);
}

static HRESULT STDMETHODCALLTYPE compositor_CreateInsetClipWithInsets(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, FLOAT left, FLOAT top, FLOAT right, FLOAT bottom, __x_ABI_CWindows_CUI_CComposition_CIInsetClip **result)
{
    HRESULT hr = comp_new_object(comp_identity(This), K_INSETCLIP,
            &IID___x_ABI_CWindows_CUI_CComposition_CIInsetClip, (void **)result);
    if (SUCCEEDED(hr))
    {
        struct cobj *c = CONTAINING_RECORD(*result, struct cobj, inset);
        c->inset_l = left; c->inset_t = top; c->inset_r = right; c->inset_b = bottom;
    }
    return hr;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateLinearEasingFunction(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CILinearEasingFunction **result)
{
    FIXME("ICompositor::CreateLinearEasingFunction: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreatePropertySet(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CICompositionPropertySet **result)
{
    FIXME("ICompositor::CreatePropertySet: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateQuaternionKeyFrameAnimation(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CIQuaternionKeyFrameAnimation **result)
{
    FIXME("ICompositor::CreateQuaternionKeyFrameAnimation: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateScalarKeyFrameAnimation(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CIScalarKeyFrameAnimation **result)
{
    FIXME("ICompositor::CreateScalarKeyFrameAnimation: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateScopedBatch(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CCompositionBatchTypes type, __x_ABI_CWindows_CUI_CComposition_CICompositionScopedBatch **result)
{
    FIXME("ICompositor::CreateScopedBatch: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateSpriteVisual(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CISpriteVisual **result)
{
    return comp_new_object(comp_identity(This), K_SPRITE, &IID___x_ABI_CWindows_CUI_CComposition_CISpriteVisual, (void **)result);
}

static HRESULT STDMETHODCALLTYPE compositor_CreateSurfaceBrush(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CICompositionSurfaceBrush **result)
{
    return comp_new_object(comp_identity(This), K_SURFBRUSH, &IID___x_ABI_CWindows_CUI_CComposition_CICompositionSurfaceBrush, (void **)result);
}

static HRESULT STDMETHODCALLTYPE compositor_CreateSurfaceBrushWithSurface(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CICompositionSurface *surface, __x_ABI_CWindows_CUI_CComposition_CICompositionSurfaceBrush **result)
{
    HRESULT hr = comp_new_object(comp_identity(This), K_SURFBRUSH,
            &IID___x_ABI_CWindows_CUI_CComposition_CICompositionSurfaceBrush, (void **)result);
    if (SUCCEEDED(hr) && FAILED(hr = comp_surface_brush_set_surface(CONTAINING_RECORD(*result, struct cobj, surfbrush), surface)))
    {
        __x_ABI_CWindows_CUI_CComposition_CICompositionSurfaceBrush_Release(*result);
        *result = NULL;
    }
    return hr;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateTargetForCurrentView(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CICompositionTarget **result)
{
    FIXME("ICompositor::CreateTargetForCurrentView: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateVector2KeyFrameAnimation(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CIVector2KeyFrameAnimation **result)
{
    FIXME("ICompositor::CreateVector2KeyFrameAnimation: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateVector3KeyFrameAnimation(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CIVector3KeyFrameAnimation **result)
{
    FIXME("ICompositor::CreateVector3KeyFrameAnimation: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_CreateVector4KeyFrameAnimation(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CIVector4KeyFrameAnimation **result)
{
    FIXME("ICompositor::CreateVector4KeyFrameAnimation: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE compositor_GetCommitBatch(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CCompositionBatchTypes type, __x_ABI_CWindows_CUI_CComposition_CICompositionCommitBatch **result)
{
    FIXME("ICompositor::GetCommitBatch: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}


/* ---- ICompositorInterop shell ---- */

static HRESULT STDMETHODCALLTYPE interop_CreateCompositionSurfaceForHandle(__x_ABI_CWindows_CUI_CComposition_CICompositorInterop *This, HANDLE swapchain, __x_ABI_CWindows_CUI_CComposition_CICompositionSurface **result)
{
    FIXME("ICompositorInterop::CreateCompositionSurfaceForHandle: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE interop_CreateCompositionSurfaceForSwapChain(__x_ABI_CWindows_CUI_CComposition_CICompositorInterop *This, IUnknown *swapchain, __x_ABI_CWindows_CUI_CComposition_CICompositionSurface **result)
{
    FIXME("ICompositorInterop::CreateCompositionSurfaceForSwapChain: not implemented\n");
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE interop_CreateGraphicsDevice(__x_ABI_CWindows_CUI_CComposition_CICompositorInterop *This, IUnknown *device, __x_ABI_CWindows_CUI_CComposition_CICompositionGraphicsDevice **result)
{
    TRACE("%p, %p, %p\n", This, device, result);
    return comp_new_graphics_device(interop_identity(This), device, result);
}


struct compositor
{
    IInspectable IInspectable_iface;    /* identity */
    ICompositor ICompositor_iface;
    ICompositorInterop ICompositorInterop_iface;
    ICompositorDesktopInterop ICompositorDesktopInterop_iface;
    IClosable IClosable_iface;
    IAgileObject IAgileObject_iface;
    IUnknown *marshal;                  /* free-threaded marshaler */
    LONG ref;
    BOOL closed;
};

struct controller
{
    IInspectable IInspectable_iface;
    IClosable IClosable_iface;
    IAgileObject IAgileObject_iface;
    IUnknown *marshal;
    LONG ref;
    BOOL closed;
    struct compositor *compositor;      /* ICompositorController::Compositor, once its IID has a clean source */
};

static LONG object_count;

static inline struct compositor *impl_from_ICompositor(ICompositor *i)
{ return CONTAINING_RECORD(i, struct compositor, ICompositor_iface); }
static inline struct compositor *comp_from_identity(IInspectable *i)
{ return CONTAINING_RECORD(i, struct compositor, IInspectable_iface); }
static inline struct compositor *comp_from_interop(ICompositorInterop *i)
{ return CONTAINING_RECORD(i, struct compositor, ICompositorInterop_iface); }
static inline struct compositor *comp_from_desktop(ICompositorDesktopInterop *i)
{ return CONTAINING_RECORD(i, struct compositor, ICompositorDesktopInterop_iface); }
static inline struct compositor *comp_from_closable(IClosable *i)
{ return CONTAINING_RECORD(i, struct compositor, IClosable_iface); }
static inline struct compositor *comp_from_agile(IAgileObject *i)
{ return CONTAINING_RECORD(i, struct compositor, IAgileObject_iface); }
static inline struct controller *ctl_from_identity(IInspectable *i)
{ return CONTAINING_RECORD(i, struct controller, IInspectable_iface); }
static inline struct controller *ctl_from_closable(IClosable *i)
{ return CONTAINING_RECORD(i, struct controller, IClosable_iface); }
static inline struct controller *ctl_from_agile(IAgileObject *i)
{ return CONTAINING_RECORD(i, struct controller, IAgileObject_iface); }

/* ---- shared IInspectable helpers ---- */

static HRESULT make_iids(ULONG *count, IID **iids, const IID **list, ULONG n)
{
    IID *out;
    ULONG i;

    if (!count || !iids) return E_POINTER;
    if (!(out = CoTaskMemAlloc(n * sizeof(IID)))) return E_OUTOFMEMORY;
    for (i = 0; i < n; i++) out[i] = *list[i];
    *count = n;
    *iids = out;
    return S_OK;
}

static HRESULT class_name_out(const WCHAR *name, HSTRING *out)
{
    if (!out) return E_POINTER;
    return WindowsCreateString(name, wcslen(name), out);
}

/* ---- Compositor ---- */

static HRESULT STDMETHODCALLTYPE compositor_id_QueryInterface(IInspectable *iface, REFIID iid, void **out)
{
    struct compositor *This = comp_from_identity(iface);

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable))
        *out = &This->IInspectable_iface;
    else if (IsEqualGUID(iid, &IID___x_ABI_CWindows_CUI_CComposition_CICompositor))
        *out = &This->ICompositor_iface;
    else if (IsEqualGUID(iid, &IID___x_ABI_CWindows_CUI_CComposition_CICompositorInterop))
        *out = &This->ICompositorInterop_iface;
    else if (IsEqualGUID(iid, &IID_ICompositorDesktopInterop))
        *out = &This->ICompositorDesktopInterop_iface;
    else if (IsEqualGUID(iid, &IID___x_ABI_CWindows_CFoundation_CIClosable))
        *out = &This->IClosable_iface;
    else if (IsEqualGUID(iid, &IID_IAgileObject))
        *out = &This->IAgileObject_iface;
    else if (IsEqualGUID(iid, &IID_IMarshal) && This->marshal)
        return IUnknown_QueryInterface(This->marshal, iid, out);
    else
    {
        FIXME("Compositor: interface %s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
        return E_NOINTERFACE;
    }
    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}

static ULONG STDMETHODCALLTYPE compositor_id_AddRef(IInspectable *iface)
{
    return InterlockedIncrement(&comp_from_identity(iface)->ref);
}

static ULONG STDMETHODCALLTYPE compositor_id_Release(IInspectable *iface)
{
    struct compositor *This = comp_from_identity(iface);
    ULONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
    {
        if (This->marshal) IUnknown_Release(This->marshal);
        HeapFree(GetProcessHeap(), 0, This);
        InterlockedDecrement(&object_count);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE compositor_id_GetIids(IInspectable *iface, ULONG *count, IID **iids)
{
    const IID *list[] = { &IID___x_ABI_CWindows_CUI_CComposition_CICompositor,
                          &IID___x_ABI_CWindows_CUI_CComposition_CICompositorInterop,
                          &IID___x_ABI_CWindows_CFoundation_CIClosable };
    return make_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE compositor_id_GetRuntimeClassName(IInspectable *iface, HSTRING *name)
{
    return class_name_out(name_compositor, name);
}

static HRESULT STDMETHODCALLTYPE compositor_id_GetTrustLevel(IInspectable *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static const IInspectableVtbl compositor_id_vtbl =
{
    compositor_id_QueryInterface, compositor_id_AddRef, compositor_id_Release,
    compositor_id_GetIids, compositor_id_GetRuntimeClassName, compositor_id_GetTrustLevel
};

#define FWD_UNKNOWN(prefix, T, from, ident) \
static HRESULT STDMETHODCALLTYPE prefix##_QueryInterface(T *iface, REFIID iid, void **out) \
{ return IInspectable_QueryInterface(&from(iface)->ident, iid, out); } \
static ULONG STDMETHODCALLTYPE prefix##_AddRef(T *iface) \
{ return IInspectable_AddRef(&from(iface)->ident); } \
static ULONG STDMETHODCALLTYPE prefix##_Release(T *iface) \
{ return IInspectable_Release(&from(iface)->ident); } \
static HRESULT STDMETHODCALLTYPE prefix##_GetIids(T *iface, ULONG *count, IID **iids) \
{ return IInspectable_GetIids(&from(iface)->ident, count, iids); } \
static HRESULT STDMETHODCALLTYPE prefix##_GetRuntimeClassName(T *iface, HSTRING *name) \
{ return IInspectable_GetRuntimeClassName(&from(iface)->ident, name); } \
static HRESULT STDMETHODCALLTYPE prefix##_GetTrustLevel(T *iface, TrustLevel *level) \
{ return IInspectable_GetTrustLevel(&from(iface)->ident, level); }

static IUnknown *comp_identity(ICompositor *i)
{ return (IUnknown *)&impl_from_ICompositor(i)->IInspectable_iface; }
static IUnknown *interop_identity(ICompositorInterop *i)
{ return (IUnknown *)&comp_from_interop(i)->IInspectable_iface; }

FWD_UNKNOWN(compositor, ICompositor, impl_from_ICompositor, IInspectable_iface)

static const ICompositorVtbl compositor_vtbl =
{
    compositor_QueryInterface, compositor_AddRef, compositor_Release,
    compositor_GetIids, compositor_GetRuntimeClassName, compositor_GetTrustLevel,
    compositor_CreateColorKeyFrameAnimation,
    compositor_CreateColorBrush,
    compositor_CreateColorBrushWithColor,
    compositor_CreateContainerVisual,
    compositor_CreateCubicBezierEasingFunction,
    compositor_CreateEffectFactory,
    compositor_CreateEffectFactoryWithProperties,
    compositor_CreateExpressionAnimation,
    compositor_CreateExpressionAnimationWithExpression,
    compositor_CreateInsetClip,
    compositor_CreateInsetClipWithInsets,
    compositor_CreateLinearEasingFunction,
    compositor_CreatePropertySet,
    compositor_CreateQuaternionKeyFrameAnimation,
    compositor_CreateScalarKeyFrameAnimation,
    compositor_CreateScopedBatch,
    compositor_CreateSpriteVisual,
    compositor_CreateSurfaceBrush,
    compositor_CreateSurfaceBrushWithSurface,
    compositor_CreateTargetForCurrentView,
    compositor_CreateVector2KeyFrameAnimation,
    compositor_CreateVector3KeyFrameAnimation,
    compositor_CreateVector4KeyFrameAnimation,
    compositor_GetCommitBatch,
};

/* ICompositorInterop is a plain IUnknown interface */
static HRESULT STDMETHODCALLTYPE interop_u_QueryInterface(ICompositorInterop *iface, REFIID iid, void **out)
{ return IInspectable_QueryInterface(&comp_from_interop(iface)->IInspectable_iface, iid, out); }
static ULONG STDMETHODCALLTYPE interop_u_AddRef(ICompositorInterop *iface)
{ return IInspectable_AddRef(&comp_from_interop(iface)->IInspectable_iface); }
static ULONG STDMETHODCALLTYPE interop_u_Release(ICompositorInterop *iface)
{ return IInspectable_Release(&comp_from_interop(iface)->IInspectable_iface); }

static const ICompositorInteropVtbl interop_vtbl =
{
    interop_u_QueryInterface, interop_u_AddRef, interop_u_Release,
    interop_CreateCompositionSurfaceForHandle,
    interop_CreateCompositionSurfaceForSwapChain,
    interop_CreateGraphicsDevice,
};

/* ICompositorDesktopInterop is a plain IUnknown interface */
static HRESULT STDMETHODCALLTYPE desktop_QueryInterface(ICompositorDesktopInterop *iface, REFIID iid, void **out)
{ return IInspectable_QueryInterface(&comp_from_desktop(iface)->IInspectable_iface, iid, out); }
static ULONG STDMETHODCALLTYPE desktop_AddRef(ICompositorDesktopInterop *iface)
{ return IInspectable_AddRef(&comp_from_desktop(iface)->IInspectable_iface); }
static ULONG STDMETHODCALLTYPE desktop_Release(ICompositorDesktopInterop *iface)
{ return IInspectable_Release(&comp_from_desktop(iface)->IInspectable_iface); }

static HRESULT STDMETHODCALLTYPE desktop_CreateDesktopWindowTarget(ICompositorDesktopInterop *iface, HWND hwnd,
        BOOL topmost, IInspectable **result)
{
    struct compositor *This = comp_from_desktop(iface);

    TRACE("%p, hwnd %p, topmost %d, result %p\n", iface, hwnd, topmost, result);
    /* What Windows answers for a NULL, foreign, child or already targeted window is neither documented nor
     * measured yet (an oracle probe outside an interactive session cannot create a Compositor): verify on the
     * oracle in an interactive session before adding checks. */
    if (!result) return E_POINTER;
    *result = NULL;
    return comp_new_desktop_target((IUnknown *)&This->IInspectable_iface, hwnd, topmost, result);
}

static const ICompositorDesktopInteropVtbl desktop_vtbl =
{
    desktop_QueryInterface, desktop_AddRef, desktop_Release,
    desktop_CreateDesktopWindowTarget,
};

#define IFACE_CLOSABLE(prefix, T, from, ident, ctype) \
static HRESULT STDMETHODCALLTYPE prefix##_c_QueryInterface(IClosable *iface, REFIID iid, void **out) \
{ return IInspectable_QueryInterface(&from(iface)->ident, iid, out); } \
static ULONG STDMETHODCALLTYPE prefix##_c_AddRef(IClosable *iface) \
{ return IInspectable_AddRef(&from(iface)->ident); } \
static ULONG STDMETHODCALLTYPE prefix##_c_Release(IClosable *iface) \
{ return IInspectable_Release(&from(iface)->ident); } \
static HRESULT STDMETHODCALLTYPE prefix##_c_GetIids(IClosable *iface, ULONG *count, IID **iids) \
{ return IInspectable_GetIids(&from(iface)->ident, count, iids); } \
static HRESULT STDMETHODCALLTYPE prefix##_c_GetRuntimeClassName(IClosable *iface, HSTRING *name) \
{ return IInspectable_GetRuntimeClassName(&from(iface)->ident, name); } \
static HRESULT STDMETHODCALLTYPE prefix##_c_GetTrustLevel(IClosable *iface, TrustLevel *level) \
{ return IInspectable_GetTrustLevel(&from(iface)->ident, level); } \
static HRESULT STDMETHODCALLTYPE prefix##_c_Close(IClosable *iface) \
{ from(iface)->closed = TRUE; return S_OK; } \
static const IClosableVtbl prefix##_closable_vtbl = \
{ prefix##_c_QueryInterface, prefix##_c_AddRef, prefix##_c_Release, prefix##_c_GetIids, \
  prefix##_c_GetRuntimeClassName, prefix##_c_GetTrustLevel, prefix##_c_Close };

IFACE_CLOSABLE(compositor, struct compositor, comp_from_closable, IInspectable_iface, 0)
IFACE_CLOSABLE(controller, struct controller, ctl_from_closable, IInspectable_iface, 0)

#define IFACE_AGILE(prefix, from) \
static HRESULT STDMETHODCALLTYPE prefix##_a_QueryInterface(IAgileObject *iface, REFIID iid, void **out) \
{ return IInspectable_QueryInterface(&from(iface)->IInspectable_iface, iid, out); } \
static ULONG STDMETHODCALLTYPE prefix##_a_AddRef(IAgileObject *iface) \
{ return IInspectable_AddRef(&from(iface)->IInspectable_iface); } \
static ULONG STDMETHODCALLTYPE prefix##_a_Release(IAgileObject *iface) \
{ return IInspectable_Release(&from(iface)->IInspectable_iface); } \
static const IAgileObjectVtbl prefix##_agile_vtbl = \
{ prefix##_a_QueryInterface, prefix##_a_AddRef, prefix##_a_Release };

IFACE_AGILE(compositor, comp_from_agile)
IFACE_AGILE(controller, ctl_from_agile)

static HRESULT compositor_create(struct compositor **out)
{
    struct compositor *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));

    if (!This) return E_OUTOFMEMORY;
    This->IInspectable_iface.lpVtbl = &compositor_id_vtbl;
    This->ICompositor_iface.lpVtbl = &compositor_vtbl;
    This->ICompositorInterop_iface.lpVtbl = &interop_vtbl;
    This->ICompositorDesktopInterop_iface.lpVtbl = &desktop_vtbl;
    This->IClosable_iface.lpVtbl = &compositor_closable_vtbl;
    This->IAgileObject_iface.lpVtbl = &compositor_agile_vtbl;
    This->ref = 1;
    CoCreateFreeThreadedMarshaler((IUnknown *)&This->IInspectable_iface, &This->marshal);
    InterlockedIncrement(&object_count);
    *out = This;
    return S_OK;
}

/* ---- CompositorController ---- */

static HRESULT STDMETHODCALLTYPE controller_id_QueryInterface(IInspectable *iface, REFIID iid, void **out)
{
    struct controller *This = ctl_from_identity(iface);

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable))
        *out = &This->IInspectable_iface;
    else if (IsEqualGUID(iid, &IID___x_ABI_CWindows_CFoundation_CIClosable))
        *out = &This->IClosable_iface;
    else if (IsEqualGUID(iid, &IID_IAgileObject))
        *out = &This->IAgileObject_iface;
    else if (IsEqualGUID(iid, &IID_IMarshal) && This->marshal)
        return IUnknown_QueryInterface(This->marshal, iid, out);
    else
    {
        /* ICompositorController is the default interface; it has no clean IID source yet */
        FIXME("CompositorController: interface %s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
        return E_NOINTERFACE;
    }
    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}

static ULONG STDMETHODCALLTYPE controller_id_AddRef(IInspectable *iface)
{
    return InterlockedIncrement(&ctl_from_identity(iface)->ref);
}

static ULONG STDMETHODCALLTYPE controller_id_Release(IInspectable *iface)
{
    struct controller *This = ctl_from_identity(iface);
    ULONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
    {
        if (This->compositor) IInspectable_Release(&This->compositor->IInspectable_iface);
        if (This->marshal) IUnknown_Release(This->marshal);
        HeapFree(GetProcessHeap(), 0, This);
        InterlockedDecrement(&object_count);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE controller_id_GetIids(IInspectable *iface, ULONG *count, IID **iids)
{
    const IID *list[] = { &IID___x_ABI_CWindows_CFoundation_CIClosable };
    return make_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE controller_id_GetRuntimeClassName(IInspectable *iface, HSTRING *name)
{
    return class_name_out(name_controller, name);
}

static HRESULT STDMETHODCALLTYPE controller_id_GetTrustLevel(IInspectable *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static const IInspectableVtbl controller_id_vtbl =
{
    controller_id_QueryInterface, controller_id_AddRef, controller_id_Release,
    controller_id_GetIids, controller_id_GetRuntimeClassName, controller_id_GetTrustLevel
};

static HRESULT controller_create(IInspectable **out)
{
    struct controller *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));
    HRESULT hr;

    if (!This) return E_OUTOFMEMORY;
    This->IInspectable_iface.lpVtbl = &controller_id_vtbl;
    This->IClosable_iface.lpVtbl = &controller_closable_vtbl;
    This->IAgileObject_iface.lpVtbl = &controller_agile_vtbl;
    This->ref = 1;
    if (FAILED(hr = compositor_create(&This->compositor)))
    {
        HeapFree(GetProcessHeap(), 0, This);
        return hr;
    }
    CoCreateFreeThreadedMarshaler((IUnknown *)&This->IInspectable_iface, &This->marshal);
    InterlockedIncrement(&object_count);
    *out = &This->IInspectable_iface;
    return S_OK;
}

static HRESULT compositor_activate(IInspectable **out)
{
    struct compositor *c;
    HRESULT hr = compositor_create(&c);

    if (SUCCEEDED(hr)) *out = &c->IInspectable_iface;
    return hr;
}

/* ---- activation factories (one static object per class, free-threaded) ---- */

struct factory
{
    IActivationFactory IActivationFactory_iface;
    IAgileObject IAgileObject_iface;
    const WCHAR *name;
    HRESULT (*activate)(IInspectable **out);
};

static inline struct factory *factory_from_IActivationFactory(IActivationFactory *i)
{ return CONTAINING_RECORD(i, struct factory, IActivationFactory_iface); }
static inline struct factory *factory_from_agile(IAgileObject *i)
{ return CONTAINING_RECORD(i, struct factory, IAgileObject_iface); }

static HRESULT STDMETHODCALLTYPE factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    struct factory *This = factory_from_IActivationFactory(iface);

    if (!out) return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IActivationFactory))
        *out = &This->IActivationFactory_iface;
    else if (IsEqualGUID(iid, &IID_IAgileObject))
        *out = &This->IAgileObject_iface;
    else
    {
        FIXME("factory of %s: interface %s not implemented, returning E_NOINTERFACE.\n",
               debugstr_w(This->name), debugstr_guid(iid));
        *out = NULL;
        return E_NOINTERFACE;
    }
    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}

static ULONG STDMETHODCALLTYPE factory_AddRef(IActivationFactory *iface) { return 2; }
static ULONG STDMETHODCALLTYPE factory_Release(IActivationFactory *iface) { return 1; }

static HRESULT STDMETHODCALLTYPE factory_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    const IID *list[] = { &IID_IActivationFactory };
    return make_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *name)
{
    return class_name_out(factory_from_IActivationFactory(iface)->name, name);
}

static HRESULT STDMETHODCALLTYPE factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    struct factory *This = factory_from_IActivationFactory(iface);

    TRACE("%s\n", debugstr_w(This->name));
    if (!instance) return E_POINTER;
    *instance = NULL;
    return This->activate(instance);
}

static const IActivationFactoryVtbl factory_vtbl =
{
    factory_QueryInterface, factory_AddRef, factory_Release, factory_GetIids,
    factory_GetRuntimeClassName, factory_GetTrustLevel, factory_ActivateInstance
};

static HRESULT STDMETHODCALLTYPE factory_a_QueryInterface(IAgileObject *iface, REFIID iid, void **out)
{ return factory_QueryInterface(&factory_from_agile(iface)->IActivationFactory_iface, iid, out); }
static ULONG STDMETHODCALLTYPE factory_a_AddRef(IAgileObject *iface) { return 2; }
static ULONG STDMETHODCALLTYPE factory_a_Release(IAgileObject *iface) { return 1; }
static const IAgileObjectVtbl factory_agile_vtbl = { factory_a_QueryInterface, factory_a_AddRef, factory_a_Release };

static struct factory compositor_factory =
    { { &factory_vtbl }, { &factory_agile_vtbl }, name_compositor, compositor_activate };
static struct factory controller_factory =
    { { &factory_vtbl }, { &factory_agile_vtbl }, name_controller, controller_create };

HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **out)
{
    const WCHAR *name = WindowsGetStringRawBuffer(classid, NULL);

    TRACE("%s, %p\n", debugstr_w(name), out);

    if (!out) return E_POINTER;
    *out = NULL;
    if (name && !wcscmp(name, name_compositor))
        *out = &compositor_factory.IActivationFactory_iface;
    else if (name && !wcscmp(name, name_controller))
        *out = &controller_factory.IActivationFactory_iface;
    else
    {
        FIXME("class %s not implemented\n", debugstr_w(name));
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    return S_OK;
}
