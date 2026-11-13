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
WIFACE(ICompositionAnimation)
WIFACE(ICompositionAnimationBase)
WIFACE(IExpressionAnimation)
WIFACE(ICompositionPropertySet)

typedef __x_ABI_CWindows_CFoundation_CIClosable WIClosable;
typedef __x_ABI_CWindows_CFoundation_CIClosableVtbl WIClosableVtbl;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CVector2 Vec2;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CVector3 Vec3;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CQuaternion Quat;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CMatrix4x4 Mat4;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CMatrix3x2 Mat3x2;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CVector4 Vec4;

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

/*
 * Windows.UI.Composition.IVisual2 (second interface of Visual). Source: microsoft/windows-rs (MIT OR Apache-2.0), the
 * published `windows` crate 0.62.2 (vcs commit 32c3144490c016fe496a0aed769bce60987a2e9d), src/Windows/UI/Composition/mod.rs
 * (IVisual2_Vtbl), and metadata/winrt/Windows.UI.Composition.rdl at commit 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0:
 * guid 3052b611-56c3-4c3e-8bf3-f6e1ad473f06, slots after IInspectable: 6/7 get/put ParentForTransform (Visual),
 * 8/9 get/put RelativeOffsetAdjustment (Vector3), 10/11 get/put RelativeSizeAdjustment (Vector2). Facts only.
 */
typedef struct WIVisual2 WIVisual2;
typedef struct WIVisual2Vtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIVisual2 *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIVisual2 *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIVisual2 *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIVisual2 *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIVisual2 *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIVisual2 *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_ParentForTransform)(WIVisual2 *This, WIVisual **value);
    HRESULT (STDMETHODCALLTYPE *put_ParentForTransform)(WIVisual2 *This, WIVisual *value);
    HRESULT (STDMETHODCALLTYPE *get_RelativeOffsetAdjustment)(WIVisual2 *This, Vec3 *value);
    HRESULT (STDMETHODCALLTYPE *put_RelativeOffsetAdjustment)(WIVisual2 *This, Vec3 value);
    HRESULT (STDMETHODCALLTYPE *get_RelativeSizeAdjustment)(WIVisual2 *This, Vec2 *value);
    HRESULT (STDMETHODCALLTYPE *put_RelativeSizeAdjustment)(WIVisual2 *This, Vec2 value);
} WIVisual2Vtbl;
struct WIVisual2 { const WIVisual2Vtbl *lpVtbl; };
DEFINE_GUID(IID_IVisual2, 0x3052b611, 0x56c3, 0x4c3e, 0x8b, 0xf3, 0xf6, 0xe1, 0xad, 0x47, 0x3f, 0x06);

/*
 * Windows.UI.Composition.ICompositionSurfaceBrush3. Source: microsoft/windows-rs (MIT OR Apache-2.0), the published
 * `windows` crate 0.62.2 (vcs commit 32c3144490c016fe496a0aed769bce60987a2e9d), src/Windows/UI/Composition/mod.rs
 * (ICompositionSurfaceBrush3_Vtbl): guid 550bb289-1fe0-42e5-8195-1eefa87ff08e, slots after IInspectable:
 * 6/7 get/put SnapToPixels (bool). Facts only.
 */
typedef struct WICompositionSurfaceBrush3 WICompositionSurfaceBrush3;
typedef struct WICompositionSurfaceBrush3Vtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WICompositionSurfaceBrush3 *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WICompositionSurfaceBrush3 *This);
    ULONG (STDMETHODCALLTYPE *Release)(WICompositionSurfaceBrush3 *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WICompositionSurfaceBrush3 *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WICompositionSurfaceBrush3 *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WICompositionSurfaceBrush3 *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_SnapToPixels)(WICompositionSurfaceBrush3 *This, BOOLEAN *value);
    HRESULT (STDMETHODCALLTYPE *put_SnapToPixels)(WICompositionSurfaceBrush3 *This, BOOLEAN value);
} WICompositionSurfaceBrush3Vtbl;
struct WICompositionSurfaceBrush3 { const WICompositionSurfaceBrush3Vtbl *lpVtbl; };
DEFINE_GUID(IID_ICompositionSurfaceBrush3, 0x550bb289, 0x1fe0, 0x42e5, 0x81, 0x95, 0x1e, 0xef, 0xa8, 0x7f, 0xf0, 0x8e);

/*
 * Windows.UI.Composition.ICompositionNineGridBrush. Source: microsoft/windows-rs (MIT OR Apache-2.0), the published
 * `windows` crate 0.62.2 (vcs commit 32c3144490c016fe496a0aed769bce60987a2e9d), src/Windows/UI/Composition/mod.rs
 * (ICompositionNineGridBrush_Vtbl, and the wrappers for the the SetInsets and SetInsetScales argument order): guid
 * f25154e4-bc8c-4be7-b80f-8685b83c0186, slots after IInspectable (get/put pairs unless noted):
 * 6/7 BottomInset, 8/9 BottomInsetScale, 10/11 IsCenterHollow, 12/13 LeftInset, 14/15 LeftInsetScale,
 * 16/17 RightInset, 18/19 RightInsetScale, 20/21 Source (ICompositionBrush), 22/23 TopInset, 24/25 TopInsetScale,
 * 26 SetInsets(inset), 27 SetInsetsWithValues(left, top, right, bottom), 28 SetInsetScales(scale),
 * 29 SetInsetScalesWithValues(left, top, right, bottom). Facts only.
 */
typedef struct WICompositionNineGridBrush WICompositionNineGridBrush;
typedef struct WICompositionNineGridBrushVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WICompositionNineGridBrush *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WICompositionNineGridBrush *This);
    ULONG (STDMETHODCALLTYPE *Release)(WICompositionNineGridBrush *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WICompositionNineGridBrush *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WICompositionNineGridBrush *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WICompositionNineGridBrush *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_BottomInset)(WICompositionNineGridBrush *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *put_BottomInset)(WICompositionNineGridBrush *This, FLOAT value);
    HRESULT (STDMETHODCALLTYPE *get_BottomInsetScale)(WICompositionNineGridBrush *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *put_BottomInsetScale)(WICompositionNineGridBrush *This, FLOAT value);
    HRESULT (STDMETHODCALLTYPE *get_IsCenterHollow)(WICompositionNineGridBrush *This, BOOLEAN *value);
    HRESULT (STDMETHODCALLTYPE *put_IsCenterHollow)(WICompositionNineGridBrush *This, BOOLEAN value);
    HRESULT (STDMETHODCALLTYPE *get_LeftInset)(WICompositionNineGridBrush *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *put_LeftInset)(WICompositionNineGridBrush *This, FLOAT value);
    HRESULT (STDMETHODCALLTYPE *get_LeftInsetScale)(WICompositionNineGridBrush *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *put_LeftInsetScale)(WICompositionNineGridBrush *This, FLOAT value);
    HRESULT (STDMETHODCALLTYPE *get_RightInset)(WICompositionNineGridBrush *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *put_RightInset)(WICompositionNineGridBrush *This, FLOAT value);
    HRESULT (STDMETHODCALLTYPE *get_RightInsetScale)(WICompositionNineGridBrush *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *put_RightInsetScale)(WICompositionNineGridBrush *This, FLOAT value);
    HRESULT (STDMETHODCALLTYPE *get_Source)(WICompositionNineGridBrush *This, WICompositionBrush **value);
    HRESULT (STDMETHODCALLTYPE *put_Source)(WICompositionNineGridBrush *This, WICompositionBrush *value);
    HRESULT (STDMETHODCALLTYPE *get_TopInset)(WICompositionNineGridBrush *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *put_TopInset)(WICompositionNineGridBrush *This, FLOAT value);
    HRESULT (STDMETHODCALLTYPE *get_TopInsetScale)(WICompositionNineGridBrush *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *put_TopInsetScale)(WICompositionNineGridBrush *This, FLOAT value);
    HRESULT (STDMETHODCALLTYPE *SetInsets)(WICompositionNineGridBrush *This, FLOAT inset);
    HRESULT (STDMETHODCALLTYPE *SetInsetsWithValues)(WICompositionNineGridBrush *This, FLOAT left, FLOAT top, FLOAT right, FLOAT bottom);
    HRESULT (STDMETHODCALLTYPE *SetInsetScales)(WICompositionNineGridBrush *This, FLOAT scale);
    HRESULT (STDMETHODCALLTYPE *SetInsetScalesWithValues)(WICompositionNineGridBrush *This, FLOAT left, FLOAT top, FLOAT right, FLOAT bottom);
} WICompositionNineGridBrushVtbl;
struct WICompositionNineGridBrush { const WICompositionNineGridBrushVtbl *lpVtbl; };
DEFINE_GUID(IID_ICompositionNineGridBrush, 0xf25154e4, 0xbc8c, 0x4be7, 0xb8, 0x0f, 0x86, 0x85, 0xb8, 0x3c, 0x01, 0x86);

/*
 * ExpressionAnimation, CompositionAnimation, CompositionPropertySet and the Interactions.InteractionTracker family.
 * Source: microsoft/windows-rs (MIT OR Apache-2.0), the published `windows` crate 0.62.2 (vcs commit
 * 32c3144490c016fe496a0aed769bce60987a2e9d), src/Windows/UI/Composition/mod.rs and
 * src/Windows/UI/Composition/Interactions/mod.rs (the *_Vtbl structs give the slot order; define_interface! the
 * guids), cross-checked with metadata/winrt/Windows.UI.Composition{,.Interactions}.rdl at commit
 * 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0. Only GUIDs, slot order and signatures were taken, no code. Slots count from
 * 6 (after IInspectable):
 *   ICompositionAnimation 464c4c2c-1caa-4061-9b40-e13fde1503ca: 6 ClearAllParameters, 7 ClearParameter, 8 SetColorParameter,
 *     9 SetMatrix3x2Parameter, 10 SetMatrix4x4Parameter, 11 SetQuaternionParameter, 12 SetReferenceParameter,
 *     13 SetScalarParameter, 14 SetVector2Parameter, 15 SetVector3Parameter, 16 SetVector4Parameter
 *   ICompositionAnimation2 369b603e-a80f-4948-93e3-ed23fb38c6cb: 6 SetBooleanParameter, 7/8 get/put Target (string)
 *   ICompositionAnimationBase 1c2c2999-e818-48d3-a6dd-d78c82f8ace9: no members
 *   IExpressionAnimation 6acc5431-7d3d-4bf3-abb6-f44bdc4888c1: 6/7 get/put Expression (string)
 *   ICompositionPropertySet c9d6d202-5f67-4453-9117-9eadd430d3c2: 6..13 InsertColor, Matrix3x2, Matrix4x4, Quaternion,
 *     Scalar, Vector2, Vector3, Vector4; 14..21 TryGet of the same eight, each (name, out value) -> CompositionGetValueStatus
 *     (Succeeded 0, TypeMismatch 1, NotFound 2)
 *   ICompositionInteractionSourceCollection 1b468e4b-a5bf-47d8-a547-3894155a158c: 6 get Count (int32), 7 Add, 8 Remove,
 *     9 RemoveAll (ICompositionInteractionSource)
 *   IInteractionTracker 2a8e8cb1-1000-4416-8363-cc27fb877308: 6 get InteractionSources, 7 get IsPositionRoundingSuggested,
 *     8/9 MaxPosition, 10/11 MaxScale, 12/13 MinPosition, 14/15 MinScale, 16 get NaturalRestingPosition, 17 get
 *     NaturalRestingScale, 18 get Owner, 19 get Position, 20/21 PositionInertiaDecayRate (IReference<Vector3>), 22 get
 *     PositionVelocityInPixelsPerSecond, 23 get Scale, 24/25 ScaleInertiaDecayRate (IReference<float>), 26 get
 *     ScaleVelocityInPercentPerSecond, 27 AdjustPositionXIfGreaterThanThreshold, 28 ..YIf.., 29 ConfigurePositionXInertiaModifiers,
 *     30 ..Y.., 31 ConfigureScaleInertiaModifiers, 32 TryUpdatePosition, 33 TryUpdatePositionBy, 34 TryUpdatePositionWithAnimation,
 *     35 TryUpdatePositionWithAdditionalVelocity, 36 TryUpdateScale, 37 TryUpdateScaleWithAnimation, 38 TryUpdateScaleWithAdditionalVelocity
 *   IInteractionTrackerStatics bba5d7b7-6590-4498-8d6c-eb62b514c92a: 6 Create(Compositor), 7 CreateWithOwner(Compositor, Owner)
 * Defaults from learn.microsoft.com (MicrosoftDocs/winrt-api commit 4c1e9164521785f82dc63ab57a5ee4644f9d1888,
 * windows.ui.composition.interactions/interactiontracker*.md): Position 0, Scale 1, MinScale and MaxScale 1.
 */
typedef struct WICompositionAnimation2 WICompositionAnimation2;
typedef struct WICompositionAnimation2Vtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WICompositionAnimation2 *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WICompositionAnimation2 *This);
    ULONG (STDMETHODCALLTYPE *Release)(WICompositionAnimation2 *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WICompositionAnimation2 *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WICompositionAnimation2 *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WICompositionAnimation2 *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *SetBooleanParameter)(WICompositionAnimation2 *This, HSTRING key, BOOLEAN value);
    HRESULT (STDMETHODCALLTYPE *get_Target)(WICompositionAnimation2 *This, HSTRING *value);
    HRESULT (STDMETHODCALLTYPE *put_Target)(WICompositionAnimation2 *This, HSTRING value);
} WICompositionAnimation2Vtbl;
struct WICompositionAnimation2 { const WICompositionAnimation2Vtbl *lpVtbl; };

typedef struct WICompositionInteractionSourceCollection WICompositionInteractionSourceCollection;
typedef struct WICompositionInteractionSourceCollectionVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WICompositionInteractionSourceCollection *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WICompositionInteractionSourceCollection *This);
    ULONG (STDMETHODCALLTYPE *Release)(WICompositionInteractionSourceCollection *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WICompositionInteractionSourceCollection *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WICompositionInteractionSourceCollection *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WICompositionInteractionSourceCollection *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_Count)(WICompositionInteractionSourceCollection *This, INT32 *value);
    HRESULT (STDMETHODCALLTYPE *Add)(WICompositionInteractionSourceCollection *This, WICompositionInteractionSource *value);
    HRESULT (STDMETHODCALLTYPE *Remove)(WICompositionInteractionSourceCollection *This, WICompositionInteractionSource *value);
    HRESULT (STDMETHODCALLTYPE *RemoveAll)(WICompositionInteractionSourceCollection *This);
} WICompositionInteractionSourceCollectionVtbl;
struct WICompositionInteractionSourceCollection { const WICompositionInteractionSourceCollectionVtbl *lpVtbl; };

typedef struct WIInteractionTracker WIInteractionTracker;
typedef struct WIInteractionTrackerVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIInteractionTracker *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIInteractionTracker *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIInteractionTracker *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIInteractionTracker *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIInteractionTracker *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIInteractionTracker *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *get_InteractionSources)(WIInteractionTracker *This, WICompositionInteractionSourceCollection **value);
    HRESULT (STDMETHODCALLTYPE *get_IsPositionRoundingSuggested)(WIInteractionTracker *This, BOOLEAN *value);
    HRESULT (STDMETHODCALLTYPE *get_MaxPosition)(WIInteractionTracker *This, Vec3 *value);
    HRESULT (STDMETHODCALLTYPE *put_MaxPosition)(WIInteractionTracker *This, Vec3 value);
    HRESULT (STDMETHODCALLTYPE *get_MaxScale)(WIInteractionTracker *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *put_MaxScale)(WIInteractionTracker *This, FLOAT value);
    HRESULT (STDMETHODCALLTYPE *get_MinPosition)(WIInteractionTracker *This, Vec3 *value);
    HRESULT (STDMETHODCALLTYPE *put_MinPosition)(WIInteractionTracker *This, Vec3 value);
    HRESULT (STDMETHODCALLTYPE *get_MinScale)(WIInteractionTracker *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *put_MinScale)(WIInteractionTracker *This, FLOAT value);
    HRESULT (STDMETHODCALLTYPE *get_NaturalRestingPosition)(WIInteractionTracker *This, Vec3 *value);
    HRESULT (STDMETHODCALLTYPE *get_NaturalRestingScale)(WIInteractionTracker *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *get_Owner)(WIInteractionTracker *This, void **value);
    HRESULT (STDMETHODCALLTYPE *get_Position)(WIInteractionTracker *This, Vec3 *value);
    HRESULT (STDMETHODCALLTYPE *get_PositionInertiaDecayRate)(WIInteractionTracker *This, void **value);
    HRESULT (STDMETHODCALLTYPE *put_PositionInertiaDecayRate)(WIInteractionTracker *This, void *value);
    HRESULT (STDMETHODCALLTYPE *get_PositionVelocityInPixelsPerSecond)(WIInteractionTracker *This, Vec3 *value);
    HRESULT (STDMETHODCALLTYPE *get_Scale)(WIInteractionTracker *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *get_ScaleInertiaDecayRate)(WIInteractionTracker *This, void **value);
    HRESULT (STDMETHODCALLTYPE *put_ScaleInertiaDecayRate)(WIInteractionTracker *This, void *value);
    HRESULT (STDMETHODCALLTYPE *get_ScaleVelocityInPercentPerSecond)(WIInteractionTracker *This, FLOAT *value);
    HRESULT (STDMETHODCALLTYPE *AdjustPositionXIfGreaterThanThreshold)(WIInteractionTracker *This, FLOAT adjustment, FLOAT threshold);
    HRESULT (STDMETHODCALLTYPE *AdjustPositionYIfGreaterThanThreshold)(WIInteractionTracker *This, FLOAT adjustment, FLOAT threshold);
    HRESULT (STDMETHODCALLTYPE *ConfigurePositionXInertiaModifiers)(WIInteractionTracker *This, void *modifiers);
    HRESULT (STDMETHODCALLTYPE *ConfigurePositionYInertiaModifiers)(WIInteractionTracker *This, void *modifiers);
    HRESULT (STDMETHODCALLTYPE *ConfigureScaleInertiaModifiers)(WIInteractionTracker *This, void *modifiers);
    HRESULT (STDMETHODCALLTYPE *TryUpdatePosition)(WIInteractionTracker *This, Vec3 value, INT32 *result);
    HRESULT (STDMETHODCALLTYPE *TryUpdatePositionBy)(WIInteractionTracker *This, Vec3 amount, INT32 *result);
    HRESULT (STDMETHODCALLTYPE *TryUpdatePositionWithAnimation)(WIInteractionTracker *This, WICompositionAnimation *animation, INT32 *result);
    HRESULT (STDMETHODCALLTYPE *TryUpdatePositionWithAdditionalVelocity)(WIInteractionTracker *This, Vec3 velocity, INT32 *result);
    HRESULT (STDMETHODCALLTYPE *TryUpdateScale)(WIInteractionTracker *This, FLOAT value, Vec3 center, INT32 *result);
    HRESULT (STDMETHODCALLTYPE *TryUpdateScaleWithAnimation)(WIInteractionTracker *This, WICompositionAnimation *animation, Vec3 center, INT32 *result);
    HRESULT (STDMETHODCALLTYPE *TryUpdateScaleWithAdditionalVelocity)(WIInteractionTracker *This, FLOAT velocity, Vec3 center, INT32 *result);
} WIInteractionTrackerVtbl;
struct WIInteractionTracker { const WIInteractionTrackerVtbl *lpVtbl; };

typedef struct WIInteractionTrackerStatics WIInteractionTrackerStatics;
typedef struct WIInteractionTrackerStaticsVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(WIInteractionTrackerStatics *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(WIInteractionTrackerStatics *This);
    ULONG (STDMETHODCALLTYPE *Release)(WIInteractionTrackerStatics *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(WIInteractionTrackerStatics *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(WIInteractionTrackerStatics *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(WIInteractionTrackerStatics *This, TrustLevel *level);
    HRESULT (STDMETHODCALLTYPE *Create)(WIInteractionTrackerStatics *This, WICompositor *compositor, WIInteractionTracker **result);
    HRESULT (STDMETHODCALLTYPE *CreateWithOwner)(WIInteractionTrackerStatics *This, WICompositor *compositor, void *owner,
            WIInteractionTracker **result);
} WIInteractionTrackerStaticsVtbl;
struct WIInteractionTrackerStatics { const WIInteractionTrackerStaticsVtbl *lpVtbl; };

DEFINE_GUID(IID_ICompositionAnimation, 0x464c4c2c, 0x1caa, 0x4061, 0x9b, 0x40, 0xe1, 0x3f, 0xde, 0x15, 0x03, 0xca);
DEFINE_GUID(IID_ICompositionAnimation2, 0x369b603e, 0xa80f, 0x4948, 0x93, 0xe3, 0xed, 0x23, 0xfb, 0x38, 0xc6, 0xcb);
DEFINE_GUID(IID_ICompositionAnimationBase, 0x1c2c2999, 0xe818, 0x48d3, 0xa6, 0xdd, 0xd7, 0x8c, 0x82, 0xf8, 0xac, 0xe9);
DEFINE_GUID(IID_IExpressionAnimation, 0x6acc5431, 0x7d3d, 0x4bf3, 0xab, 0xb6, 0xf4, 0x4b, 0xdc, 0x48, 0x88, 0xc1);
DEFINE_GUID(IID_ICompositionPropertySet, 0xc9d6d202, 0x5f67, 0x4453, 0x91, 0x17, 0x9e, 0xad, 0xd4, 0x30, 0xd3, 0xc2);
DEFINE_GUID(IID_ICompositionInteractionSourceCollection, 0x1b468e4b, 0xa5bf, 0x47d8, 0xa5, 0x47, 0x38, 0x94, 0x15, 0x5a, 0x15, 0x8c);
DEFINE_GUID(IID_IInteractionTracker, 0x2a8e8cb1, 0x1000, 0x4416, 0x83, 0x63, 0xcc, 0x27, 0xfb, 0x87, 0x73, 0x08);
DEFINE_GUID(IID_IInteractionTrackerStatics, 0xbba5d7b7, 0x6590, 0x4498, 0x8d, 0x6c, 0xeb, 0x62, 0xb5, 0x14, 0xc9, 0x2a);

/* a stored parameter of a CompositionAnimation, or an entry of a CompositionPropertySet */
enum ptype { PT_COLOR = 1, PT_M32, PT_M44, PT_QUAT, PT_REF, PT_SCALAR, PT_V2, PT_V3, PT_V4, PT_BOOL };
struct cparam
{
    WCHAR *name;
    enum ptype type;
    union
    {
        __x_ABI_CWindows_CUI_CColor c;
        Mat3x2 m32;
        Mat4 m44;
        Quat q;
        float f;
        Vec2 v2;
        Vec3 v3;
        Vec4 v4;
        BOOLEAN b;
    } v;
    IUnknown *ref;                  /* PT_REF: referenced */
};

/* CompositionObject.StartAnimation bookkeeping: the animation started on a property name */
struct canim_start
{
    WCHAR *name;
    IUnknown *anim;                 /* referenced */
};

enum cobj_kind
{
    K_CONTAINER, K_SPRITE, K_VCOLL, K_COLORBRUSH, K_SURFBRUSH, K_INSETCLIP, K_GDEVICE, K_DSURFACE, K_TARGET, K_VISRC, K_NINEGRID, K_EXPRANIM, K_PROPSET, K_TRACKER, K_ISRCCOLL
};
#define KM(k) (1u << (k))
#define KM_VISUAL (KM(K_CONTAINER) | KM(K_SPRITE))
#define KM_BRUSH  (KM(K_COLORBRUSH) | KM(K_SURFBRUSH) | KM(K_NINEGRID))
#define KM_ALL    0xffffffffu

struct cobj
{
    IInspectable identity;
    WICompositionObject objbase;
    WIVisual visual;
    WIVisual2 visual2;
    WIContainerVisual container;
    WISpriteVisual sprite;
    WIVisualCollection vcoll;
    WICompositionBrush brush;
    WICompositionColorBrush colorbrush;
    WICompositionSurfaceBrush surfbrush;
    WICompositionSurfaceBrush3 surfbrush3;
    WICompositionNineGridBrush ninegrid;
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
    WICompositionAnimation anim;
    WICompositionAnimation2 anim2;
    WICompositionAnimationBase animbase;
    WIExpressionAnimation expr;
    WICompositionPropertySet propset;
    WIInteractionTracker tracker;
    WICompositionInteractionSourceCollection srccoll;
    WICompositionInteractionSource intsrc;
    INitroDrawingSurfaceInterop dsinterop;
    ICompGraphicsDeviceInterop gdinterop;
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
    struct cobj *xparent;           /* IVisual2.ParentForTransform, referenced (not used for rendering yet) */
    Vec3 reloffset;                 /* IVisual2.RelativeOffsetAdjustment (X and Y applied, times the parent's size) */
    Vec2 relsize;                   /* IVisual2.RelativeSizeAdjustment (applied, times the parent's size) */

    /* VisualCollection */
    struct cobj *owner;             /* weak, cleared when the owner is destroyed */

    /* color brush */
    __x_ABI_CWindows_CUI_CColor color;

    /* surface brush */
    int bitmap_interp, stretch;
    float halign, valign;
    IUnknown *bsurface;             /* the ICompositionSurface identity, referenced */
    BOOLEAN snap;                   /* ICompositionSurfaceBrush3.SnapToPixels (stored, not applied yet) */

    /* nine-grid brush: Source is kept in sbrush (referenced); nothing paints it yet (no brush renderer) */
    float ng_inset[4], ng_scale[4]; /* left, top, right, bottom */
    BOOLEAN ng_hollow;

    /* inset clip */
    float inset_l, inset_t, inset_r, inset_b;

    /* graphics device and drawing surface (compgfx.c) */
    IUnknown *d3d;                  /* ID3D11Device */
    IUnknown *d2d;                  /* ID2D1Device */
    IUnknown *rdev;                 /* graphics device: the rendering device as the app gave it, referenced */
    LONG gen;                       /* graphics device: bumped by SetRenderingDevice; surface: gen of its texture */
    struct cobj *gfxdev;            /* drawing surface: its device, referenced */
    IUnknown *tex;                  /* ID3D11Texture2D */
    UINT width, height;
    int pixfmt, alphamode;
    IUnknown *dc;                   /* ID2D1DeviceContext between BeginDraw and EndDraw */
    IUnknown *dcbitmap;             /* ID2D1Bitmap1 */
    BOOL drawing, suspended;

    /* DesktopWindowTarget (present.c) */
    HWND hwnd;                      /* the window it was created for; the tree is drawn into it on commit */
    BOOL topmost;                   /* IDesktopWindowTarget.IsTopmost */
    struct cobj *root;              /* CompositionTarget.Root, referenced */
    struct cobj *tnext;             /* list of attached targets, under comp_lock */
    BOOL attached;                  /* in that list */
    BYTE *frame;                    /* last rendered frame, premultiplied BGRA, fw x fh, under comp_lock */
    UINT fw, fh;
    BOOL frame_used;                /* the frame has a pixel that is not transparent */
    BOOL post_pending;              /* the blend after a WM_PAINT is queued */
    DWORD hook_tid;                 /* the window's thread carries our message hooks (window of this process) */

    /* VisualInteractionSource (nothing is routed to it yet: no input redirection, no InteractionTracker) */
    struct cobj *isource;           /* VisualInteractionSource.Source, referenced */
    BOOLEAN rails_x, rails_y;
    INT32 redirect_mode;
    INT32 chain_px, chain_py, chain_s;
    INT32 mode_px, mode_py, mode_s;

    /* every CompositionObject: Properties (created on first use, referenced) and the started animations */
    struct cobj *props;
    struct canim_start *started;
    int nstarted, capstarted;

    /* CompositionAnimation / ExpressionAnimation (and the entries of a CompositionPropertySet) */
    struct cparam *params;
    int nparams, capparams;
    HSTRING expression;             /* ExpressionAnimation.Expression, NULL = empty */
    HSTRING anim_target;            /* CompositionAnimation.Target, NULL = empty */

    /* InteractionTracker (stored state only: no input handling, no inertia, no animation) */
    struct cobj *srcs;              /* InteractionSources, referenced */
    IUnknown *towner;               /* IInteractionTrackerOwner, referenced, may be NULL */
    Vec3 tmin, tmax, tpos;
    float tscale, tminscale, tmaxscale;
    IUnknown *pdecay, *sdecay;      /* IReference<Vector3> / IReference<float>, referenced, may be NULL */

    /* CompositionInteractionSourceCollection */
    IUnknown **sources;             /* identities, referenced */
    int nsources, capsources;
};

void comp_lock(void);
void comp_unlock(void);
/* comp_unlock after changing o: the Compositor of o has something to commit */
void comp_unlock_changed(struct cobj *o);
/* caller holds comp_lock: render the tree under root into a cleared w x h premultiplied BGRA bitmap */
void comp_render_locked(struct cobj *root, UINT w, UINT h, BYTE *bgra, UINT stride);
struct cobj *comp_alloc_obj(enum cobj_kind kind, IUnknown *compositor);
extern LONG comp_object_count;

/* compgfx.c */
HRESULT gfx_device_init(struct cobj *dev, IUnknown *device);
void gfx_device_free(struct cobj *dev);
HRESULT gfx_surface_create(struct cobj *dev, Vec2 size, int format, int alpha, struct cobj **out);
void gfx_surface_free(struct cobj *s);
HRESULT gfx_surface_snapshot(struct cobj *s, BYTE **pixels, UINT *w, UINT *h);
EXTERN_C const INitroDrawingSurfaceInteropVtbl nitro_dsinterop_vtbl;
EXTERN_C const ICompGraphicsDeviceInteropVtbl gfx_device_interop_vtbl;

/* present.c */
void present_attach(struct cobj *target);
void present_detach(struct cobj *target);
void comp_commit_targets(IUnknown *compositor);

/* winrt.c: the Compositor (identity) has changes to commit; schedules CommitNeeded or the automatic commit */
void comp_compositor_changed(IUnknown *compositor);

/* winrt.c <-> composition.c */
HRESULT comp_new_object(IUnknown *compositor, enum cobj_kind kind, REFIID want, void **out);
HRESULT comp_new_graphics_device(IUnknown *compositor, IUnknown *device, WICompositionGraphicsDevice **out);
struct cobj *cobj_from_iface(void *iface, size_t offset);
HRESULT comp_surface_brush_set_surface(struct cobj *brush, WICompositionSurface *surface);
HRESULT comp_create(IUnknown *compositor, enum cobj_kind kind, struct cobj **out);
/* *out: the IDesktopWindowTarget interface of the new object (one reference) */
HRESULT comp_new_desktop_target(IUnknown *compositor, HWND hwnd, BOOL topmost, WIDesktopWindowTarget **out);
/* *out: the IInteractionTracker interface of the new object (one reference); compositor is the ICompositor, owner an IInteractionTrackerOwner or NULL */
HRESULT comp_new_interaction_tracker(WICompositor *compositor, void *owner, WIInteractionTracker **out);
/* *out: the IExpressionAnimation interface of the new object (one reference); expression may be NULL */
HRESULT comp_new_expression_animation(IUnknown *compositor, HSTRING expression, WIExpressionAnimation **out);
/* *out: the IVisualInteractionSource interface of the new object (one reference); source is a visual of this object model */
HRESULT comp_new_visual_interaction_source(WIVisual *source, WIVisualInteractionSource **out);
