/*
 * PROJECT:     ReactOS DirectComposition
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows.UI.Composition WinRT classes: activation, Compositor, CompositorController, VisualInteractionSource, ExpressionAnimation, InteractionTracker (stages 1-3)
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
 * caller asks for next.
 *
 * ICompositorController, ICompositorDesktopInterop (second method) and IDesktopWindowTarget take their IID, slot
 * order and signatures from microsoft/windows-rs (MIT OR Apache-2.0), commit
 * 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0 (details at each interface).
 * Windows.UI.Composition.Interactions.VisualInteractionSource (composition.c) is created through its statics here;
 * the interfaces come from the same repository (see comp_private.h for path and commit). Known gaps (no source for IID or vtable):
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
 * ICompositorDesktopInterop (windows.ui.composition.interop.h), a plain IUnknown interface, IID
 * 29E691FA-4567-4DCA-B319-D0F207EB6807. Two sources agree:
 *  - learn.microsoft.com, "Using the Visual layer with Windows Forms" (MicrosoftDocs/windows-dev-docs-pr,
 *    uwp/composition/using-the-visual-layer-with-windows-forms.md, page git_commit_id
 *    6b6b4abfd0405ca8dc14905fd4aa4ab21ca74fee): the IID and the first method
 *    CreateDesktopWindowTarget(HWND hwndTarget, BOOL isTopmost, IDesktopWindowTarget **result);
 *  - microsoft/windows-rs (MIT OR Apache-2.0), commit 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0,
 *    metadata/win32/windowsuicompositioninterop.rdl, interface ICompositorDesktopInterop: IUnknown: the same IID and
 *    exactly two methods in this order: CreateDesktopWindowTarget (slot 3), EnsureOnThread(DWORD threadId) (slot 4).
 * Windows documents nothing about EnsureOnThread: it logs a FIXME and returns E_NOTIMPL.
 * The result of CreateDesktopWindowTarget is a Windows.UI.Composition.Desktop.DesktopWindowTarget, returned as its
 * IDesktopWindowTarget (composition.c; that vtable is complete, it has IsTopmost only).
 * Both vtables here are complete per the metadata, so nothing is padded after them.
 */
typedef struct ICompositorDesktopInterop ICompositorDesktopInterop;
typedef struct ICompositorDesktopInteropVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICompositorDesktopInterop *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICompositorDesktopInterop *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICompositorDesktopInterop *This);
    HRESULT (STDMETHODCALLTYPE *CreateDesktopWindowTarget)(ICompositorDesktopInterop *This, HWND hwnd, BOOL topmost,
            WIDesktopWindowTarget **result);
    HRESULT (STDMETHODCALLTYPE *EnsureOnThread)(ICompositorDesktopInterop *This, DWORD thread_id);
} ICompositorDesktopInteropVtbl;
struct ICompositorDesktopInterop { const ICompositorDesktopInteropVtbl *lpVtbl; };

/*
 * ICompositorController (Windows.UI.Composition.Core), the default interface of CompositorController
 * (Activatable, agile, threading both; also IClosable). Source: microsoft/windows-rs (MIT OR Apache-2.0), commit
 * 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0, metadata/winrt/Windows.UI.Composition.Core.rdl, interface
 * ICompositorController, guid 2d75f35a-70a7-4395-ba2d-cef0b18399f9, members in order after IInspectable:
 *   get Compositor: Compositor              (slot 6)
 *   Commit()                                (slot 7)
 *   EnsurePreviousCommitCompletedAsync() -> IAsyncAction   (slot 8)
 *   event CommitNeeded: TypedEventHandler<CompositorController, Object>   (add slot 9, remove slot 10)
 * Only GUID, order and signatures were taken. The vtable is complete.
 * IAsyncAction / IAsyncInfo are the ones in sdk/include/psdk (Wine).
 */
typedef struct ICompositorController ICompositorController;
typedef struct ICommitNeededHandler ICommitNeededHandler;
typedef struct { INT64 value; } EventToken;     /* Windows.Foundation.EventRegistrationToken */
typedef struct WIAsyncAction WIAsyncAction;
typedef struct WIAsyncInfo WIAsyncInfo;

/* TypedEventHandler<CompositorController, Object>: a plain delegate, Invoke is slot 3 */
typedef struct ICommitNeededHandlerVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICommitNeededHandler *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICommitNeededHandler *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICommitNeededHandler *This);
    HRESULT (STDMETHODCALLTYPE *Invoke)(ICommitNeededHandler *This, ICompositorController *sender,
            IInspectable *args);
} ICommitNeededHandlerVtbl;
struct ICommitNeededHandler { const ICommitNeededHandlerVtbl *lpVtbl; };

typedef struct ICompositorControllerVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICompositorController *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICompositorController *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICompositorController *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(ICompositorController *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(ICompositorController *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(ICompositorController *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_Compositor)(ICompositorController *This, ICompositor **value);
    HRESULT (STDMETHODCALLTYPE *Commit)(ICompositorController *This);
    HRESULT (STDMETHODCALLTYPE *EnsurePreviousCommitCompletedAsync)(ICompositorController *This,
            WIAsyncAction **operation);
    HRESULT (STDMETHODCALLTYPE *add_CommitNeeded)(ICompositorController *This, ICommitNeededHandler *handler,
            EventToken *token);
    HRESULT (STDMETHODCALLTYPE *remove_CommitNeeded)(ICompositorController *This, EventToken token);
} ICompositorControllerVtbl;
struct ICompositorController { const ICompositorControllerVtbl *lpVtbl; };

/* Windows.Foundation.IAsyncAction (5a648006-...), AsyncActionCompletedHandler, IAsyncInfo (00000036-...) */
typedef struct IAsyncActionHandler IAsyncActionHandler;
typedef struct IAsyncActionHandlerVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IAsyncActionHandler *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IAsyncActionHandler *This);
    ULONG (STDMETHODCALLTYPE *Release)(IAsyncActionHandler *This);
    HRESULT (STDMETHODCALLTYPE *Invoke)(IAsyncActionHandler *This, WIAsyncAction *action, INT32 status);
} IAsyncActionHandlerVtbl;
struct IAsyncActionHandler { const IAsyncActionHandlerVtbl *lpVtbl; };

typedef struct WIAsyncActionVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIAsyncAction *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIAsyncAction *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIAsyncAction *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIAsyncAction *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIAsyncAction *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIAsyncAction *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *put_Completed)(WIAsyncAction *This, IAsyncActionHandler *handler);
    HRESULT (STDMETHODCALLTYPE *get_Completed)(WIAsyncAction *This, IAsyncActionHandler **handler);
    HRESULT (STDMETHODCALLTYPE *GetResults)(WIAsyncAction *This);
} WIAsyncActionVtbl;
struct WIAsyncAction { const WIAsyncActionVtbl *lpVtbl; };

typedef struct WIAsyncInfoVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIAsyncInfo *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIAsyncInfo *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIAsyncInfo *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIAsyncInfo *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIAsyncInfo *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIAsyncInfo *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_Id)(WIAsyncInfo *This, UINT32 *id);
    HRESULT (STDMETHODCALLTYPE *get_Status)(WIAsyncInfo *This, INT32 *status);
    HRESULT (STDMETHODCALLTYPE *get_ErrorCode)(WIAsyncInfo *This, HRESULT *code);
    HRESULT (STDMETHODCALLTYPE *Cancel)(WIAsyncInfo *This);
    HRESULT (STDMETHODCALLTYPE *Close)(WIAsyncInfo *This);
} WIAsyncInfoVtbl;
struct WIAsyncInfo { const WIAsyncInfoVtbl *lpVtbl; };

DEFINE_GUID(IID_ICompositorDesktopInterop, 0x29e691fa, 0x4567, 0x4dca, 0xb3, 0x19, 0xd0, 0xf2, 0x07, 0xeb, 0x68, 0x07);
/*
 * ICompositor2 (Windows.UI.Composition), guid 735081dc-5e24-45da-a38f-e32cc349a9a0. Source: microsoft/windows-rs
 * (MIT OR Apache-2.0), the published `windows` crate 0.62.2 (vcs commit 32c3144490c016fe496a0aed769bce60987a2e9d),
 * src/Windows/UI/Composition/mod.rs (ICompositor2_Vtbl). Members in slot order after IInspectable:
 * 6 CreateAmbientLight, 7 CreateAnimationGroup, 8 CreateBackdropBrush, 9 CreateDistantLight, 10 CreateDropShadow,
 * 11 CreateImplicitAnimationCollection, 12 CreateLayerVisual, 13 CreateMaskBrush, 14 CreateNineGridBrush,
 * 15 CreatePointLight, 16 CreateSpotLight, 17 CreateStepEasingFunction, 18 CreateStepEasingFunctionWithStepCount(int).
 * Every member creates a class this object model does not have: E_NOTIMPL with a FIXME naming the member.
 */
typedef struct ICompositor2 ICompositor2;
typedef struct ICompositor2Vtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICompositor2 *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICompositor2 *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICompositor2 *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(ICompositor2 *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(ICompositor2 *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(ICompositor2 *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *CreateAmbientLight)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateAnimationGroup)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateBackdropBrush)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateDistantLight)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateDropShadow)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateImplicitAnimationCollection)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateLayerVisual)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateMaskBrush)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateNineGridBrush)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreatePointLight)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateSpotLight)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateStepEasingFunction)(ICompositor2 *This, void **result);
    HRESULT (STDMETHODCALLTYPE *CreateStepEasingFunctionWithStepCount)(ICompositor2 *This, INT32 steps, void **result);
} ICompositor2Vtbl;
struct ICompositor2 { const ICompositor2Vtbl *lpVtbl; };
DEFINE_GUID(IID_ICompositor2, 0x735081dc, 0x5e24, 0x45da, 0xa3, 0x8f, 0xe3, 0x2c, 0xc3, 0x49, 0xa9, 0xa0);
DEFINE_GUID(IID_ICompositorController, 0x2d75f35a, 0x70a7, 0x4395, 0xba, 0x2d, 0xce, 0xf0, 0xb1, 0x83, 0x99, 0xf9);
DEFINE_GUID(IID_WIAsyncAction, 0x5a648006, 0x843a, 0x4da9, 0x86, 0x5b, 0x9d, 0x26, 0xe5, 0xdf, 0xad, 0x7b);
DEFINE_GUID(IID_WIAsyncInfo, 0x00000036, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);

#ifndef RO_E_CLOSED
#define RO_E_CLOSED ((HRESULT)0x80000013)
#endif

static const WCHAR name_compositor[] = L"Windows.UI.Composition.Compositor";
static const WCHAR name_controller[] = L"Windows.UI.Composition.Core.CompositorController";
static const WCHAR name_visrc[] = L"Windows.UI.Composition.Interactions.VisualInteractionSource";
static const WCHAR name_tracker[] = L"Windows.UI.Composition.Interactions.InteractionTracker";

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
    return comp_new_expression_animation(comp_identity(This), NULL, (WIExpressionAnimation **)result);
}

static HRESULT STDMETHODCALLTYPE compositor_CreateExpressionAnimationWithExpression(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, HSTRING expression, __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation **result)
{
    return comp_new_expression_animation(comp_identity(This), expression, (WIExpressionAnimation **)result);
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

/* documented: a new, empty CompositionPropertySet of this Compositor (the class of CompositionObject.Properties) */
static HRESULT STDMETHODCALLTYPE compositor_CreatePropertySet(__x_ABI_CWindows_CUI_CComposition_CICompositor *This, __x_ABI_CWindows_CUI_CComposition_CICompositionPropertySet **result)
{
    TRACE("%p, %p\n", This, result);
    return comp_new_object(comp_identity(This), K_PROPSET, &IID_ICompositionPropertySet, (void **)result);
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
    ICompositor2 ICompositor2_iface;
    ICompositorInterop ICompositorInterop_iface;
    ICompositorDesktopInterop ICompositorDesktopInterop_iface;
    IClosable IClosable_iface;
    IAgileObject IAgileObject_iface;
    IUnknown *marshal;                  /* free-threaded marshaler */
    LONG ref;
    BOOL closed;
    /* commits (under comp_lock): a Compositor without a controller commits by itself shortly after a change; one
     * made by a CompositorController raises CommitNeeded once and waits for ICompositorController::Commit */
    struct controller *controller;      /* weak: the controller that made this Compositor, cleared when it goes */
    BOOL work_queued;                   /* a commit_work item is queued */
    LONG work_items;                    /* commit_work items queued or running: they use the object without a
                                         * reference (a reference would show in the Compositor's count) */
    BOOL zombie;                        /* released while work_items != 0: the last item frees it */
    BOOL dirty;                         /* changed since the last commit */
    BOOL need_raised;                   /* CommitNeeded raised since the last commit */
    struct compositor *qnext;           /* the queue of the commit thread, under comp_lock */
    DWORD due;                          /* tick count at which the queued commit_work runs */
};

struct commit_handler
{
    ICommitNeededHandler *handler;      /* referenced */
    INT64 token;
};

struct controller
{
    IInspectable IInspectable_iface;
    ICompositorController ICompositorController_iface;
    IClosable IClosable_iface;
    IAgileObject IAgileObject_iface;
    IUnknown *marshal;
    LONG ref;
    BOOL closed;
    struct compositor *compositor;      /* ICompositorController::Compositor, referenced */
    struct commit_handler *handlers;    /* CommitNeeded, under comp_lock */
    int nhandlers, caphandlers;
    INT64 next_token;
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
static inline struct controller *ctl_from_ctl(ICompositorController *i)
{ return CONTAINING_RECORD(i, struct controller, ICompositorController_iface); }
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
    else if (IsEqualGUID(iid, &IID_ICompositor2))
        *out = &This->ICompositor2_iface;
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

static void compositor_free(struct compositor *This)
{
    if (This->marshal) IUnknown_Release(This->marshal);
    HeapFree(GetProcessHeap(), 0, This);
    InterlockedDecrement(&object_count);
}

static ULONG STDMETHODCALLTYPE compositor_id_Release(IInspectable *iface)
{
    struct compositor *This = comp_from_identity(iface);
    ULONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
    {
        BOOL later;

        comp_lock();
        later = This->work_items != 0;
        if (later) This->zombie = TRUE;
        comp_unlock();
        if (!later) compositor_free(This);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE compositor_id_GetIids(IInspectable *iface, ULONG *count, IID **iids)
{
    const IID *list[] = { &IID___x_ABI_CWindows_CUI_CComposition_CICompositor,
                          &IID_ICompositor2,
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

/* ICompositor2: see the comment at its definition; nothing here can be created yet */
static inline struct compositor *comp_from_comp2(ICompositor2 *i)
{ return CONTAINING_RECORD(i, struct compositor, ICompositor2_iface); }
FWD_UNKNOWN(compositor2, ICompositor2, comp_from_comp2, IInspectable_iface)

#define C2_STUB(N) \
static HRESULT STDMETHODCALLTYPE compositor2_##N(ICompositor2 *iface, void **result) \
{ FIXME("ICompositor2::" #N ": not implemented\n"); if (result) *result = NULL; return E_NOTIMPL; }
C2_STUB(CreateAmbientLight)
C2_STUB(CreateAnimationGroup)
C2_STUB(CreateBackdropBrush)
C2_STUB(CreateDistantLight)
C2_STUB(CreateDropShadow)
C2_STUB(CreateImplicitAnimationCollection)
C2_STUB(CreateLayerVisual)
C2_STUB(CreateMaskBrush)
static HRESULT STDMETHODCALLTYPE compositor2_CreateNineGridBrush(ICompositor2 *iface, void **result)
{
    TRACE("%p, %p\n", iface, result);
    return comp_new_object((IUnknown *)&comp_from_comp2(iface)->IInspectable_iface, K_NINEGRID, &IID_ICompositionNineGridBrush, result);
}
C2_STUB(CreatePointLight)
C2_STUB(CreateSpotLight)
C2_STUB(CreateStepEasingFunction)
static HRESULT STDMETHODCALLTYPE compositor2_CreateStepEasingFunctionWithStepCount(ICompositor2 *iface, INT32 steps,
        void **result)
{
    FIXME("ICompositor2::CreateStepEasingFunctionWithStepCount(%d): not implemented\n", steps);
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static const ICompositor2Vtbl compositor2_vtbl =
{
    compositor2_QueryInterface, compositor2_AddRef, compositor2_Release, compositor2_GetIids,
    compositor2_GetRuntimeClassName, compositor2_GetTrustLevel,
    compositor2_CreateAmbientLight, compositor2_CreateAnimationGroup, compositor2_CreateBackdropBrush,
    compositor2_CreateDistantLight, compositor2_CreateDropShadow, compositor2_CreateImplicitAnimationCollection,
    compositor2_CreateLayerVisual, compositor2_CreateMaskBrush, compositor2_CreateNineGridBrush,
    compositor2_CreatePointLight, compositor2_CreateSpotLight, compositor2_CreateStepEasingFunction,
    compositor2_CreateStepEasingFunctionWithStepCount,
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
        BOOL topmost, WIDesktopWindowTarget **result)
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

static HRESULT STDMETHODCALLTYPE desktop_EnsureOnThread(ICompositorDesktopInterop *iface, DWORD thread_id)
{
    FIXME("ICompositorDesktopInterop::EnsureOnThread(%lu): not implemented\n", thread_id);
    return E_NOTIMPL;
}

static const ICompositorDesktopInteropVtbl desktop_vtbl =
{
    desktop_QueryInterface, desktop_AddRef, desktop_Release,
    desktop_CreateDesktopWindowTarget,
    desktop_EnsureOnThread,
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

static void commit_thread_start(void);

static HRESULT compositor_create(struct compositor **out)
{
    struct compositor *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));

    if (!This) return E_OUTOFMEMORY;
    This->IInspectable_iface.lpVtbl = &compositor_id_vtbl;
    This->ICompositor_iface.lpVtbl = &compositor_vtbl;
    This->ICompositor2_iface.lpVtbl = &compositor2_vtbl;
    This->ICompositorInterop_iface.lpVtbl = &interop_vtbl;
    This->ICompositorDesktopInterop_iface.lpVtbl = &desktop_vtbl;
    This->IClosable_iface.lpVtbl = &compositor_closable_vtbl;
    This->IAgileObject_iface.lpVtbl = &compositor_agile_vtbl;
    This->ref = 1;
    CoCreateFreeThreadedMarshaler((IUnknown *)&This->IInspectable_iface, &This->marshal);
    InterlockedIncrement(&object_count);
    commit_thread_start();              /* the first change of an object should not pay for creating the thread */
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
    else if (IsEqualGUID(iid, &IID_ICompositorController))
        *out = &This->ICompositorController_iface;
    else if (IsEqualGUID(iid, &IID___x_ABI_CWindows_CFoundation_CIClosable))
        *out = &This->IClosable_iface;
    else if (IsEqualGUID(iid, &IID_IAgileObject))
        *out = &This->IAgileObject_iface;
    else if (IsEqualGUID(iid, &IID_IMarshal) && This->marshal)
        return IUnknown_QueryInterface(This->marshal, iid, out);
    else
    {
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
        int i;

        comp_lock();
        if (This->compositor && This->compositor->controller == This) This->compositor->controller = NULL;
        comp_unlock();
        for (i = 0; i < This->nhandlers; i++) This->handlers[i].handler->lpVtbl->Release(This->handlers[i].handler);
        HeapFree(GetProcessHeap(), 0, This->handlers);
        if (This->compositor) IInspectable_Release(&This->compositor->IInspectable_iface);
        if (This->marshal) IUnknown_Release(This->marshal);
        HeapFree(GetProcessHeap(), 0, This);
        InterlockedDecrement(&object_count);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE controller_id_GetIids(IInspectable *iface, ULONG *count, IID **iids)
{
    const IID *list[] = { &IID_ICompositorController, &IID___x_ABI_CWindows_CFoundation_CIClosable };
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

/* ---- ICompositorController ---- */

FWD_UNKNOWN(ctl, ICompositorController, ctl_from_ctl, IInspectable_iface)

/* The only asynchronous result of the controller: nothing is ever in flight (Commit has no deferred work yet), so
 * the IAsyncAction is complete from the start. Completed handlers run at once on the calling thread. */
struct done_action
{
    WIAsyncAction action;
    WIAsyncInfo info;
    IAgileObject agile;
    LONG ref;
    LONG handler_set;
    BOOL closed;
};

static inline struct done_action *da_from_action(WIAsyncAction *i)
{ return CONTAINING_RECORD(i, struct done_action, action); }
static inline struct done_action *da_from_info(WIAsyncInfo *i)
{ return CONTAINING_RECORD(i, struct done_action, info); }
static inline struct done_action *da_from_agile(IAgileObject *i)
{ return CONTAINING_RECORD(i, struct done_action, agile); }

static HRESULT STDMETHODCALLTYPE da_QueryInterface(WIAsyncAction *iface, REFIID iid, void **out)
{
    struct done_action *This = da_from_action(iface);

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) || IsEqualGUID(iid, &IID_WIAsyncAction))
        *out = &This->action;
    else if (IsEqualGUID(iid, &IID_WIAsyncInfo))
        *out = &This->info;
    else if (IsEqualGUID(iid, &IID_IAgileObject))
        *out = &This->agile;
    else
        return E_NOINTERFACE;
    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}

static ULONG STDMETHODCALLTYPE da_AddRef(WIAsyncAction *iface)
{ return InterlockedIncrement(&da_from_action(iface)->ref); }

static ULONG STDMETHODCALLTYPE da_Release(WIAsyncAction *iface)
{
    struct done_action *This = da_from_action(iface);
    ULONG ref = InterlockedDecrement(&This->ref);

    if (!ref) HeapFree(GetProcessHeap(), 0, This);
    return ref;
}

static HRESULT STDMETHODCALLTYPE da_GetIids(WIAsyncAction *iface, ULONG *count, IID **iids)
{
    const IID *list[] = { &IID_WIAsyncAction, &IID_WIAsyncInfo };
    return make_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE da_GetRuntimeClassName(WIAsyncAction *iface, HSTRING *name)
{ return class_name_out(L"Windows.Foundation.IAsyncAction", name); }

static HRESULT STDMETHODCALLTYPE da_GetTrustLevel(WIAsyncAction *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE da_put_Completed(WIAsyncAction *iface, IAsyncActionHandler *handler)
{
    struct done_action *This = da_from_action(iface);

    if (!handler) return E_INVALIDARG;
    if (This->closed) return E_ILLEGAL_METHOD_CALL;
    if (InterlockedCompareExchange(&This->handler_set, 1, 0)) return E_ILLEGAL_DELEGATE_ASSIGNMENT;
    handler->lpVtbl->Invoke(handler, iface, 1 /* Completed */);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE da_get_Completed(WIAsyncAction *iface, IAsyncActionHandler **handler)
{
    if (!handler) return E_POINTER;
    *handler = NULL;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE da_GetResults(WIAsyncAction *iface)
{ return da_from_action(iface)->closed ? E_ILLEGAL_METHOD_CALL : S_OK; }

static const WIAsyncActionVtbl da_vtbl =
{
    da_QueryInterface, da_AddRef, da_Release, da_GetIids, da_GetRuntimeClassName, da_GetTrustLevel,
    da_put_Completed, da_get_Completed, da_GetResults
};

static HRESULT STDMETHODCALLTYPE dai_QueryInterface(WIAsyncInfo *i, REFIID iid, void **out)
{ return da_QueryInterface(&da_from_info(i)->action, iid, out); }
static ULONG STDMETHODCALLTYPE dai_AddRef(WIAsyncInfo *i) { return da_AddRef(&da_from_info(i)->action); }
static ULONG STDMETHODCALLTYPE dai_Release(WIAsyncInfo *i) { return da_Release(&da_from_info(i)->action); }
static HRESULT STDMETHODCALLTYPE dai_GetIids(WIAsyncInfo *i, ULONG *c, IID **iids)
{ return da_GetIids(&da_from_info(i)->action, c, iids); }
static HRESULT STDMETHODCALLTYPE dai_GetRuntimeClassName(WIAsyncInfo *i, HSTRING *n)
{ return da_GetRuntimeClassName(&da_from_info(i)->action, n); }
static HRESULT STDMETHODCALLTYPE dai_GetTrustLevel(WIAsyncInfo *i, TrustLevel *l)
{ return da_GetTrustLevel(&da_from_info(i)->action, l); }

static HRESULT STDMETHODCALLTYPE dai_get_Id(WIAsyncInfo *i, UINT32 *id)
{
    if (!id) return E_POINTER;
    *id = 1;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dai_get_Status(WIAsyncInfo *i, INT32 *status)
{
    if (!status) return E_POINTER;
    if (da_from_info(i)->closed) return E_ILLEGAL_METHOD_CALL;
    *status = 1;                        /* Completed */
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dai_get_ErrorCode(WIAsyncInfo *i, HRESULT *code)
{
    if (!code) return E_POINTER;
    *code = S_OK;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dai_Cancel(WIAsyncInfo *i) { return S_OK; }   /* already complete */

static HRESULT STDMETHODCALLTYPE dai_Close(WIAsyncInfo *i)
{
    da_from_info(i)->closed = TRUE;
    return S_OK;
}

static const WIAsyncInfoVtbl dai_vtbl =
{
    dai_QueryInterface, dai_AddRef, dai_Release, dai_GetIids, dai_GetRuntimeClassName, dai_GetTrustLevel,
    dai_get_Id, dai_get_Status, dai_get_ErrorCode, dai_Cancel, dai_Close
};

static HRESULT STDMETHODCALLTYPE dag_QueryInterface(IAgileObject *i, REFIID iid, void **out)
{ return da_QueryInterface(&da_from_agile(i)->action, iid, out); }
static ULONG STDMETHODCALLTYPE dag_AddRef(IAgileObject *i) { return da_AddRef(&da_from_agile(i)->action); }
static ULONG STDMETHODCALLTYPE dag_Release(IAgileObject *i) { return da_Release(&da_from_agile(i)->action); }
static const IAgileObjectVtbl dag_vtbl = { dag_QueryInterface, dag_AddRef, dag_Release };

static HRESULT done_action_create(WIAsyncAction **out)
{
    struct done_action *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));

    if (!This) return E_OUTOFMEMORY;
    This->action.lpVtbl = &da_vtbl;
    This->info.lpVtbl = &dai_vtbl;
    This->agile.lpVtbl = &dag_vtbl;
    This->ref = 1;
    *out = &This->action;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ctl_get_Compositor(ICompositorController *iface, ICompositor **value)
{
    struct controller *This = ctl_from_ctl(iface);

    TRACE("%p, %p\n", iface, value);
    if (!value) return E_POINTER;
    *value = NULL;
    if (This->closed) return RO_E_CLOSED;   /* FIXME: verify on the oracle */
    *value = &This->compositor->ICompositor_iface;
    IInspectable_AddRef(&This->compositor->IInspectable_iface);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ctl_Commit(ICompositorController *iface)
{
    struct controller *This = ctl_from_ctl(iface);

    TRACE("%p\n", iface);
    if (This->closed) return RO_E_CLOSED;   /* FIXME: verify on the oracle */
    /* Documented: sends the batched changes of the Compositor to the renderer: every DesktopWindowTarget of the
     * Compositor gets the tree as it is now (present.c). */
    comp_lock();
    This->compositor->dirty = FALSE;
    This->compositor->need_raised = FALSE;
    comp_unlock();
    /* returns at once: the render thread draws the frames (present.c). A closed Compositor shows nothing new. */
    if (!This->compositor->closed) comp_commit_targets((IUnknown *)&This->compositor->IInspectable_iface);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ctl_EnsurePreviousCommitCompletedAsync(ICompositorController *iface,
        WIAsyncAction **operation)
{
    struct controller *This = ctl_from_ctl(iface);

    TRACE("%p, %p\n", iface, operation);
    if (!operation) return E_POINTER;
    *operation = NULL;
    if (This->closed) return RO_E_CLOSED;   /* FIXME: verify on the oracle */
    return done_action_create(operation);
}

static HRESULT STDMETHODCALLTYPE ctl_add_CommitNeeded(ICompositorController *iface, ICommitNeededHandler *handler,
        EventToken *token)
{
    struct controller *This = ctl_from_ctl(iface);
    struct commit_handler *grown;
    HRESULT hr = S_OK;

    TRACE("%p, %p, %p\n", iface, handler, token);
    if (!token) return E_POINTER;
    token->value = 0;
    if (!handler) return E_INVALIDARG;
    if (This->closed) return RO_E_CLOSED;   /* FIXME: verify on the oracle */
    handler->lpVtbl->AddRef(handler);
    comp_lock();
    if (This->nhandlers == This->caphandlers)
    {
        int cap = This->caphandlers ? This->caphandlers * 2 : 4;

        grown = This->handlers ? HeapReAlloc(GetProcessHeap(), 0, This->handlers, cap * sizeof(*grown))
                               : HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*grown));
        if (grown)
        {
            This->handlers = grown;
            This->caphandlers = cap;
        }
        else
            hr = E_OUTOFMEMORY;
    }
    if (hr == S_OK)
    {
        token->value = This->next_token++;
        This->handlers[This->nhandlers].handler = handler;
        This->handlers[This->nhandlers++].token = token->value;
    }
    comp_unlock();
    if (hr != S_OK) handler->lpVtbl->Release(handler);
    /* changes made before the handler came are announced to it too */
    else if (This->compositor->dirty) comp_compositor_changed((IUnknown *)&This->compositor->IInspectable_iface);
    return hr;
}

static HRESULT STDMETHODCALLTYPE ctl_remove_CommitNeeded(ICompositorController *iface, EventToken token)
{
    struct controller *This = ctl_from_ctl(iface);
    ICommitNeededHandler *gone = NULL;
    int i;

    TRACE("%p, %s\n", iface, wine_dbgstr_longlong(token.value));
    comp_lock();
    for (i = 0; i < This->nhandlers; i++)
        if (This->handlers[i].token == token.value)
        {
            gone = This->handlers[i].handler;
            memmove(&This->handlers[i], &This->handlers[i + 1], (This->nhandlers - i - 1) * sizeof(*This->handlers));
            This->nhandlers--;
            break;
        }
    comp_unlock();
    if (gone) gone->lpVtbl->Release(gone);
    return S_OK;                        /* an unknown token is not an error for a WinRT event */
}

static const ICompositorControllerVtbl controller_vtbl =
{
    ctl_QueryInterface, ctl_AddRef, ctl_Release, ctl_GetIids, ctl_GetRuntimeClassName, ctl_GetTrustLevel,
    ctl_get_Compositor,
    ctl_Commit,
    ctl_EnsurePreviousCommitCompletedAsync,
    ctl_add_CommitNeeded,
    ctl_remove_CommitNeeded,
};

static HRESULT controller_create(IInspectable **out)
{
    struct controller *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));
    HRESULT hr;

    if (!This) return E_OUTOFMEMORY;
    This->IInspectable_iface.lpVtbl = &controller_id_vtbl;
    This->ICompositorController_iface.lpVtbl = &controller_vtbl;
    This->IClosable_iface.lpVtbl = &controller_closable_vtbl;
    This->IAgileObject_iface.lpVtbl = &controller_agile_vtbl;
    This->ref = 1;
    This->next_token = 1;
    if (FAILED(hr = compositor_create(&This->compositor)))
    {
        HeapFree(GetProcessHeap(), 0, This);
        return hr;
    }
    This->compositor->controller = This;
    CoCreateFreeThreadedMarshaler((IUnknown *)&This->IInspectable_iface, &This->marshal);
    InterlockedIncrement(&object_count);
    *out = &This->IInspectable_iface;
    return S_OK;
}

/* ---- commits: CommitNeeded, automatic commit ----
 * Documented (learn.microsoft.com): a Compositor commits its changes by itself; one made by a CompositorController
 * leaves that to the app (ICompositorController::Commit) and raises CommitNeeded when it has changes to commit.
 * Here the work runs on a thread-pool thread, about one frame (16 ms) after the first change, so that a batch of
 * changes ends up in one commit. FIXME, verify on the oracle: the thread CommitNeeded is raised on (here a pool
 * thread), how often (here once until the next Commit), and its args object (here NULL). */

static BOOL controller_grab_locked(struct controller *c)
{
    LONG r;

    for (;;)
    {
        r = c->ref;
        if (r <= 0) return FALSE;
        if (InterlockedCompareExchange(&c->ref, r + 1, r) == r) return TRUE;
    }
}

/* The commit thread: one DLL-owned thread (started on demand, retires when idle) runs the queued Compositors in
 * order, each 16 ms after its first change. It runs the CommitNeeded handlers (app code), so it does no rendering. */
static struct compositor *cq_head, *cq_tail;    /* under comp_lock */

static void commit_work(struct compositor *c)
{
    struct controller *ctl;
    ICommitNeededHandler **list = NULL;
    int n = 0, k;
    BOOL commit = FALSE, free_now;

    comp_lock();
    c->work_queued = FALSE;
    if (c->zombie)
    {
        BOOL last = !--c->work_items;
        comp_unlock();
        if (last) compositor_free(c);
        return;
    }
    ctl = c->controller;
    if (ctl && !controller_grab_locked(ctl)) ctl = NULL;
    if (ctl)
    {
        if (!ctl->closed && c->dirty && !c->need_raised && ctl->nhandlers &&
            (list = HeapAlloc(GetProcessHeap(), 0, ctl->nhandlers * sizeof(*list))))
        {
            c->need_raised = TRUE;
            for (k = 0; k < ctl->nhandlers; k++)
            {
                list[n] = ctl->handlers[k].handler;
                list[n]->lpVtbl->AddRef(list[n]);
                n++;
            }
        }
    }
    else if (!c->controller && c->dirty && !c->closed)
    {
        c->dirty = FALSE;
        commit = TRUE;
    }
    comp_unlock();
    if (ctl)
    {
        for (k = 0; k < n; k++)
        {
            TRACE("CommitNeeded -> handler %p\n", list[k]);
            list[k]->lpVtbl->Invoke(list[k], &ctl->ICompositorController_iface, NULL);
            list[k]->lpVtbl->Release(list[k]);
        }
        HeapFree(GetProcessHeap(), 0, list);
        IInspectable_Release(&ctl->IInspectable_iface);
    }
    else if (commit)
        comp_commit_targets((IUnknown *)&c->IInspectable_iface);   /* identity only compared: the targets hold it */
    comp_lock();
    free_now = !--c->work_items && c->zombie;
    comp_unlock();
    if (free_now) compositor_free(c);
}

static DWORD WINAPI commit_main(void *arg);
static struct comp_worker commit_worker = { commit_main };

static void commit_thread_start(void)
{
    comp_worker_kick(&commit_worker);
}

static DWORD WINAPI commit_main(void *arg)
{
    for (;;)
    {
        struct compositor *c = NULL;
        LONG left = -1;

        comp_lock();
        if (cq_head)
        {
            left = (LONG)(cq_head->due - GetTickCount());
            if (left <= 0)
            {
                c = cq_head;
                cq_head = c->qnext;
                if (!cq_head) cq_tail = NULL;
                c->qnext = NULL;
            }
        }
        comp_unlock();
        if (c) { commit_work(c); continue; }
        if (left > 0) comp_worker_sleep(&commit_worker, left, FALSE);
        else comp_worker_sleep(&commit_worker, 3000, !object_count);   /* parked while a Compositor exists */
    }
    return 0;
}

void comp_compositor_changed(IUnknown *identity)
{
    struct compositor *c = comp_from_identity((IInspectable *)identity);
    BOOL queue;

    comp_lock();
    c->dirty = TRUE;
    queue = !c->work_queued && !c->need_raised;
    if (queue)
    {
        c->work_queued = TRUE; c->work_items++;
        c->due = GetTickCount() + 16;
        c->qnext = NULL;
        if (cq_tail) cq_tail->qnext = c; else cq_head = c;
        cq_tail = c;
    }
    comp_unlock();
    if (!queue) return;
    if (!comp_worker_kick(&commit_worker))
    {
        struct compositor **p;

        WARN("no commit thread\n");
        comp_lock();
        for (p = &cq_head; *p; p = &(*p)->qnext)
            if (*p == c)
            {
                *p = c->qnext;
                if (cq_tail == c) { cq_tail = NULL; for (p = &cq_head; *p; p = &(*p)->qnext) cq_tail = *p; }
                break;
            }
        c->work_queued = FALSE; c->work_items--;
        comp_unlock();
    }
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


/* ---- VisualInteractionSource statics ----
 * The class has no default constructor (it is composable with the statics Create and CreateFromIVisualElement,
 * microsoft/windows-rs metadata/winrt/Windows.UI.Composition.Interactions.rdl at commit
 * 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0), so ActivateInstance is not supported. The factory object also answers
 * IActivationFactory so that a generic activation path can obtain it; FIXME verify on the oracle which of the
 * factory interfaces Windows exposes. */

typedef struct WIVisualInteractionSourceStatics WIVisualInteractionSourceStatics;
typedef struct WIVisualInteractionSourceStaticsVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIVisualInteractionSourceStatics *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIVisualInteractionSourceStatics *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIVisualInteractionSourceStatics *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIVisualInteractionSourceStatics *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIVisualInteractionSourceStatics *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIVisualInteractionSourceStatics *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *Create)(WIVisualInteractionSourceStatics *This, WIVisual *source,
            WIVisualInteractionSource **result);
} WIVisualInteractionSourceStaticsVtbl;
struct WIVisualInteractionSourceStatics { const WIVisualInteractionSourceStaticsVtbl *lpVtbl; };

typedef struct WIVisualInteractionSourceStatics2 WIVisualInteractionSourceStatics2;
typedef struct WIVisualInteractionSourceStatics2Vtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIVisualInteractionSourceStatics2 *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIVisualInteractionSourceStatics2 *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIVisualInteractionSourceStatics2 *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIVisualInteractionSourceStatics2 *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIVisualInteractionSourceStatics2 *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIVisualInteractionSourceStatics2 *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *CreateFromIVisualElement)(WIVisualInteractionSourceStatics2 *This, void *element,
            WIVisualInteractionSource **result);
} WIVisualInteractionSourceStatics2Vtbl;
struct WIVisualInteractionSourceStatics2 { const WIVisualInteractionSourceStatics2Vtbl *lpVtbl; };

/* IVisualInteractionSourceObjectFactory has no members: a bare IInspectable */
typedef struct VSObjectFactory { const IInspectableVtbl *lpVtbl; } VSObjectFactory;

struct vsfactory
{
    IActivationFactory IActivationFactory_iface;
    WIVisualInteractionSourceStatics statics;
    WIVisualInteractionSourceStatics2 statics2;
    VSObjectFactory objfactory;
    IAgileObject agile;
};
static struct vsfactory vsfactory;

#define VSF_OF(i, f) CONTAINING_RECORD(i, struct vsfactory, f)

static HRESULT STDMETHODCALLTYPE vsf_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    struct vsfactory *This = VSF_OF(iface, IActivationFactory_iface);

    if (!out) return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IActivationFactory))
        *out = &This->IActivationFactory_iface;
    else if (IsEqualGUID(iid, &IID_IVisualInteractionSourceStatics))
        *out = &This->statics;
    else if (IsEqualGUID(iid, &IID_IVisualInteractionSourceStatics2))
        *out = &This->statics2;
    else if (IsEqualGUID(iid, &IID_IVisualInteractionSourceObjectFactory))
        *out = &This->objfactory;
    else if (IsEqualGUID(iid, &IID_IAgileObject))
        *out = &This->agile;
    else
    {
        FIXME("factory of %s: interface %s not implemented, returning E_NOINTERFACE.\n",
              debugstr_w(name_visrc), debugstr_guid(iid));
        *out = NULL;
        return E_NOINTERFACE;
    }
    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}
static ULONG STDMETHODCALLTYPE vsf_AddRef(IActivationFactory *iface) { return 2; }
static ULONG STDMETHODCALLTYPE vsf_Release(IActivationFactory *iface) { return 1; }

static HRESULT STDMETHODCALLTYPE vsf_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    const IID *list[] = { &IID_IVisualInteractionSourceStatics, &IID_IVisualInteractionSourceStatics2,
                          &IID_IVisualInteractionSourceObjectFactory };
    return make_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE vsf_GetRuntimeClassName(IActivationFactory *iface, HSTRING *name)
{
    return class_name_out(name_visrc, name);
}

static HRESULT STDMETHODCALLTYPE vsf_GetTrustLevel(IActivationFactory *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE vsf_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    /* no default constructor: FIXME verify the error on the oracle */
    FIXME("VisualInteractionSource has no default constructor\n");
    if (instance) *instance = NULL;
    return E_NOTIMPL;
}

static const IActivationFactoryVtbl vsf_vtbl =
{
    vsf_QueryInterface, vsf_AddRef, vsf_Release, vsf_GetIids, vsf_GetRuntimeClassName, vsf_GetTrustLevel,
    vsf_ActivateInstance
};

#define VSF_FWD(prefix, T, field) \
static HRESULT STDMETHODCALLTYPE prefix##_QueryInterface(T *iface, REFIID iid, void **out) \
{ return vsf_QueryInterface(&VSF_OF(iface, field)->IActivationFactory_iface, iid, out); } \
static ULONG STDMETHODCALLTYPE prefix##_AddRef(T *iface) { return 2; } \
static ULONG STDMETHODCALLTYPE prefix##_Release(T *iface) { return 1; } \
static HRESULT STDMETHODCALLTYPE prefix##_GetIids(T *iface, ULONG *count, IID **iids) \
{ return vsf_GetIids(&VSF_OF(iface, field)->IActivationFactory_iface, count, iids); } \
static HRESULT STDMETHODCALLTYPE prefix##_GetRuntimeClassName(T *iface, HSTRING *name) \
{ return class_name_out(name_visrc, name); } \
static HRESULT STDMETHODCALLTYPE prefix##_GetTrustLevel(T *iface, TrustLevel *level) \
{ return vsf_GetTrustLevel(&VSF_OF(iface, field)->IActivationFactory_iface, level); }

VSF_FWD(vss, WIVisualInteractionSourceStatics, statics)
VSF_FWD(vs2s, WIVisualInteractionSourceStatics2, statics2)

static HRESULT STDMETHODCALLTYPE vss_Create(WIVisualInteractionSourceStatics *iface, WIVisual *source,
        WIVisualInteractionSource **result)
{
    TRACE("%p, %p, %p\n", iface, source, result);
    return comp_new_visual_interaction_source(source, result);
}

static HRESULT STDMETHODCALLTYPE vs2s_CreateFromIVisualElement(WIVisualInteractionSourceStatics2 *iface,
        void *element, WIVisualInteractionSource **result)
{
    FIXME("VisualInteractionSource::CreateFromIVisualElement(%p): not implemented\n", element);
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static const WIVisualInteractionSourceStaticsVtbl vss_vtbl =
{
    vss_QueryInterface, vss_AddRef, vss_Release, vss_GetIids, vss_GetRuntimeClassName, vss_GetTrustLevel, vss_Create
};
static const WIVisualInteractionSourceStatics2Vtbl vs2s_vtbl =
{
    vs2s_QueryInterface, vs2s_AddRef, vs2s_Release, vs2s_GetIids, vs2s_GetRuntimeClassName, vs2s_GetTrustLevel,
    vs2s_CreateFromIVisualElement
};

/* the empty object factory interface and the agile marker forward to the factory */
static HRESULT STDMETHODCALLTYPE vsof_QueryInterface(IInspectable *iface, REFIID iid, void **out)
{ return vsf_QueryInterface(&vsfactory.IActivationFactory_iface, iid, out); }
static ULONG STDMETHODCALLTYPE vsof_AddRef(IInspectable *iface) { return 2; }
static ULONG STDMETHODCALLTYPE vsof_Release(IInspectable *iface) { return 1; }
static HRESULT STDMETHODCALLTYPE vsof_GetIids(IInspectable *iface, ULONG *count, IID **iids)
{ return vsf_GetIids(&vsfactory.IActivationFactory_iface, count, iids); }
static HRESULT STDMETHODCALLTYPE vsof_GetRuntimeClassName(IInspectable *iface, HSTRING *name)
{ return class_name_out(name_visrc, name); }
static HRESULT STDMETHODCALLTYPE vsof_GetTrustLevel(IInspectable *iface, TrustLevel *level)
{ return vsf_GetTrustLevel(&vsfactory.IActivationFactory_iface, level); }
static const IInspectableVtbl vsof_vtbl =
    { vsof_QueryInterface, vsof_AddRef, vsof_Release, vsof_GetIids, vsof_GetRuntimeClassName, vsof_GetTrustLevel };

static HRESULT STDMETHODCALLTYPE vsa_QueryInterface(IAgileObject *iface, REFIID iid, void **out)
{ return vsf_QueryInterface(&vsfactory.IActivationFactory_iface, iid, out); }
static ULONG STDMETHODCALLTYPE vsa_AddRef(IAgileObject *iface) { return 2; }
static ULONG STDMETHODCALLTYPE vsa_Release(IAgileObject *iface) { return 1; }
static const IAgileObjectVtbl vsa_vtbl = { vsa_QueryInterface, vsa_AddRef, vsa_Release };

static struct vsfactory vsfactory =
    { { &vsf_vtbl }, { &vss_vtbl }, { &vs2s_vtbl }, { &vsof_vtbl }, { &vsa_vtbl } };


/* ---- InteractionTracker statics ----
 * IInteractionTrackerStatics (Create, CreateWithOwner) and the IActivationFactory view of the same factory. The class
 * has no default constructor (no Activatable attribute in the windows-rs metadata), so ActivateInstance is E_NOTIMPL
 * (VERIFY ON ORACLE). IInteractionTrackerStatics2 (SetBindingMode/GetBindingMode) is not implemented: QueryInterface
 * for it logs a FIXME. */
struct trkfactory
{
    IActivationFactory IActivationFactory_iface;
    WIInteractionTrackerStatics statics;
    IAgileObject agile;
};
static struct trkfactory trkfactory;
#define TKF_OF(i, f) CONTAINING_RECORD(i, struct trkfactory, f)

static HRESULT STDMETHODCALLTYPE tkf_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    struct trkfactory *This = TKF_OF(iface, IActivationFactory_iface);

    if (!out) return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IActivationFactory))
        *out = &This->IActivationFactory_iface;
    else if (IsEqualGUID(iid, &IID_IInteractionTrackerStatics))
        *out = &This->statics;
    else if (IsEqualGUID(iid, &IID_IAgileObject))
        *out = &This->agile;
    else
    {
        FIXME("factory of %s: interface %s not implemented, returning E_NOINTERFACE.\n",
              debugstr_w(name_tracker), debugstr_guid(iid));
        *out = NULL;
        return E_NOINTERFACE;
    }
    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}
static ULONG STDMETHODCALLTYPE tkf_AddRef(IActivationFactory *iface) { return 2; }
static ULONG STDMETHODCALLTYPE tkf_Release(IActivationFactory *iface) { return 1; }
static HRESULT STDMETHODCALLTYPE tkf_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    const IID *list[] = { &IID_IInteractionTrackerStatics };
    return make_iids(count, iids, list, ARRAY_SIZE(list));
}
static HRESULT STDMETHODCALLTYPE tkf_GetRuntimeClassName(IActivationFactory *iface, HSTRING *name)
{ return class_name_out(name_tracker, name); }
static HRESULT STDMETHODCALLTYPE tkf_GetTrustLevel(IActivationFactory *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE tkf_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    FIXME("InteractionTracker has no default constructor\n");
    if (instance) *instance = NULL;
    return E_NOTIMPL;
}
static const IActivationFactoryVtbl tkf_vtbl =
{
    tkf_QueryInterface, tkf_AddRef, tkf_Release, tkf_GetIids, tkf_GetRuntimeClassName, tkf_GetTrustLevel,
    tkf_ActivateInstance
};

static HRESULT STDMETHODCALLTYPE tks_QueryInterface(WIInteractionTrackerStatics *iface, REFIID iid, void **out)
{ return tkf_QueryInterface(&TKF_OF(iface, statics)->IActivationFactory_iface, iid, out); }
static ULONG STDMETHODCALLTYPE tks_AddRef(WIInteractionTrackerStatics *iface) { return 2; }
static ULONG STDMETHODCALLTYPE tks_Release(WIInteractionTrackerStatics *iface) { return 1; }
static HRESULT STDMETHODCALLTYPE tks_GetIids(WIInteractionTrackerStatics *iface, ULONG *count, IID **iids)
{ return tkf_GetIids(&TKF_OF(iface, statics)->IActivationFactory_iface, count, iids); }
static HRESULT STDMETHODCALLTYPE tks_GetRuntimeClassName(WIInteractionTrackerStatics *iface, HSTRING *name)
{ return class_name_out(name_tracker, name); }
static HRESULT STDMETHODCALLTYPE tks_GetTrustLevel(WIInteractionTrackerStatics *iface, TrustLevel *level)
{ return tkf_GetTrustLevel(&TKF_OF(iface, statics)->IActivationFactory_iface, level); }
static HRESULT STDMETHODCALLTYPE tks_Create(WIInteractionTrackerStatics *iface, WICompositor *compositor,
        WIInteractionTracker **result)
{
    TRACE("%p, %p, %p\n", iface, compositor, result);
    return comp_new_interaction_tracker(compositor, NULL, result);
}
static HRESULT STDMETHODCALLTYPE tks_CreateWithOwner(WIInteractionTrackerStatics *iface, WICompositor *compositor,
        void *owner, WIInteractionTracker **result)
{
    TRACE("%p, %p, %p, %p\n", iface, compositor, owner, result);
    return comp_new_interaction_tracker(compositor, owner, result);
}
static const WIInteractionTrackerStaticsVtbl tks_vtbl =
{
    tks_QueryInterface, tks_AddRef, tks_Release, tks_GetIids, tks_GetRuntimeClassName, tks_GetTrustLevel,
    tks_Create, tks_CreateWithOwner
};

static HRESULT STDMETHODCALLTYPE tka_QueryInterface(IAgileObject *iface, REFIID iid, void **out)
{ return tkf_QueryInterface(&trkfactory.IActivationFactory_iface, iid, out); }
static ULONG STDMETHODCALLTYPE tka_AddRef(IAgileObject *iface) { return 2; }
static ULONG STDMETHODCALLTYPE tka_Release(IAgileObject *iface) { return 1; }
static const IAgileObjectVtbl tka_vtbl = { tka_QueryInterface, tka_AddRef, tka_Release };

static struct trkfactory trkfactory = { { &tkf_vtbl }, { &tks_vtbl }, { &tka_vtbl } };

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
    else if (name && !wcscmp(name, name_visrc))
        *out = &vsfactory.IActivationFactory_iface;
    else if (name && !wcscmp(name, name_tracker))
        *out = &trkfactory.IActivationFactory_iface;
    else
    {
        FIXME("class %s not implemented\n", debugstr_w(name));
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    return S_OK;
}
