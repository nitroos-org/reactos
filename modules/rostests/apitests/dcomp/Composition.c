/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the Windows.UI.Composition object model, drawing surfaces and the CPU test renderer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Stage 2: ContainerVisual, SpriteVisual, VisualCollection, CompositionColorBrush, CompositionSurfaceBrush,
 * InsetClip behave as documented. ICompositorDesktopInterop::CreateDesktopWindowTarget and CompositionTarget.Root.
 * Stage 3: CompositionGraphicsDevice from a D3D11 device, CompositionDrawingSurface
 * drawn through D2D, Resize/Scroll. The pixel tests render the tree with the Nitro-private INitroCompositionTest
 * hook into a bitmap and compare pixels. The parts that use Nitro-private interfaces are skipped where the
 * interface is absent (Windows).
 */

#include <apitest.h>
#include <math.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
#define COBJMACROS
#include <objbase.h>
#include <d3d11.h>
#include <dxgi.h>
#include <initguid.h>
#include <d2d1_1.h>
#include <inspectable.h>
#include <winstring.h>
#include <windows.foundation.h>
#include <windows.ui.composition.h>
#include <windows.ui.composition.interop.h>
#include "../../../../dll/win32/dcomp/dcomp_nitro.h"

#define WUC(n) __x_ABI_CWindows_CUI_CComposition_C##n
#define WIFACE(n) typedef WUC(n) W##n;
WIFACE(ICompositor) WIFACE(ICompositorInterop) WIFACE(IVisual) WIFACE(IContainerVisual) WIFACE(ISpriteVisual)
WIFACE(IVisualCollection) WIFACE(ICompositionBrush) WIFACE(ICompositionColorBrush) WIFACE(ICompositionSurfaceBrush)
WIFACE(ICompositionClip) WIFACE(IInsetClip) WIFACE(ICompositionGraphicsDevice) WIFACE(ICompositionSurface)
WIFACE(ICompositionDrawingSurface) WIFACE(ICompositionObject) WIFACE(ICompositionTarget)
typedef __x_ABI_CWindows_CUI_CColor Color;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CVector2 Vec2;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CVector3 Vec3;

#define IID_Visual IID___x_ABI_CWindows_CUI_CComposition_CIVisual
#define IID_Container IID___x_ABI_CWindows_CUI_CComposition_CIContainerVisual
#define IID_Sprite IID___x_ABI_CWindows_CUI_CComposition_CISpriteVisual
#define IID_Compositor IID___x_ABI_CWindows_CUI_CComposition_CICompositor
#define IID_Interop IID___x_ABI_CWindows_CUI_CComposition_CICompositorInterop
#define IID_CompObject IID___x_ABI_CWindows_CUI_CComposition_CICompositionObject
#define IID_Brush IID___x_ABI_CWindows_CUI_CComposition_CICompositionBrush
#define IID_ColorBrush IID___x_ABI_CWindows_CUI_CComposition_CICompositionColorBrush
#define IID_SurfBrush IID___x_ABI_CWindows_CUI_CComposition_CICompositionSurfaceBrush
#define IID_Surface IID___x_ABI_CWindows_CUI_CComposition_CICompositionSurface
#define IID_Clip IID___x_ABI_CWindows_CUI_CComposition_CICompositionClip
#define IID_Target IID___x_ABI_CWindows_CUI_CComposition_CICompositionTarget

/*
 * ICompositorDesktopInterop, IDesktopWindowTarget, IDesktopWindowTargetInterop, ICompositorController: IIDs, slot
 * order and signatures from microsoft/windows-rs (MIT OR Apache-2.0), commit 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0:
 * metadata/win32/windowsuicompositioninterop.rdl (ICompositorDesktopInterop: CreateDesktopWindowTarget, EnsureOnThread;
 * IDesktopWindowTargetInterop: get_Hwnd), metadata/winrt/Windows.UI.Composition.Desktop.rdl (IDesktopWindowTarget:
 * get IsTopmost), metadata/winrt/Windows.UI.Composition.Core.rdl (ICompositorController: get Compositor, Commit,
 * EnsurePreviousCommitCompletedAsync, event CommitNeeded). The ICompositorDesktopInterop IID and its first method
 * are also on learn.microsoft.com ("Using the Visual layer with Windows Forms"). IAsyncAction/IAsyncInfo: Wine.
 */
typedef struct IDesktopTarget IDesktopTarget;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDesktopTarget *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDesktopTarget *This);
    ULONG (STDMETHODCALLTYPE *Release)(IDesktopTarget *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IDesktopTarget *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IDesktopTarget *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IDesktopTarget *This, int *level);
    HRESULT (STDMETHODCALLTYPE *get_IsTopmost)(IDesktopTarget *This, BOOLEAN *value);
} IDesktopTargetVtbl;
struct IDesktopTarget { const IDesktopTargetVtbl *lpVtbl; };
static const GUID IID_DesktopTarget = {0x6329d6ca, 0x3366, 0x490e, {0x9d, 0xb3, 0x25, 0x31, 0x29, 0x29, 0xac, 0x51}};

typedef struct IDesktopTargetInterop IDesktopTargetInterop;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDesktopTargetInterop *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDesktopTargetInterop *This);
    ULONG (STDMETHODCALLTYPE *Release)(IDesktopTargetInterop *This);
    HRESULT (STDMETHODCALLTYPE *get_Hwnd)(IDesktopTargetInterop *This, HWND *value);
} IDesktopTargetInteropVtbl;
struct IDesktopTargetInterop { const IDesktopTargetInteropVtbl *lpVtbl; };
static const GUID IID_DesktopTargetInterop = {0x35dbf59e, 0xe3f9, 0x45b0, {0x81, 0xe7, 0xfe, 0x75, 0xf4, 0x14, 0x5d, 0xc9}};

typedef struct IDesktopInterop IDesktopInterop;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDesktopInterop *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDesktopInterop *This);
    ULONG (STDMETHODCALLTYPE *Release)(IDesktopInterop *This);
    HRESULT (STDMETHODCALLTYPE *CreateDesktopWindowTarget)(IDesktopInterop *This, HWND hwnd, BOOL topmost,
            IDesktopTarget **result);
    HRESULT (STDMETHODCALLTYPE *EnsureOnThread)(IDesktopInterop *This, DWORD thread_id);
} IDesktopInteropVtbl;
struct IDesktopInterop { const IDesktopInteropVtbl *lpVtbl; };
static const GUID IID_DesktopInterop = {0x29e691fa, 0x4567, 0x4dca, {0xb3, 0x19, 0xd0, 0xf2, 0x07, 0xeb, 0x68, 0x07}};

typedef struct ICtlHandler ICtlHandler;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICtlHandler *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICtlHandler *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICtlHandler *This);
    HRESULT (STDMETHODCALLTYPE *Invoke)(ICtlHandler *This, void *sender, IInspectable *args);
} ICtlHandlerVtbl;
struct ICtlHandler { const ICtlHandlerVtbl *lpVtbl; };

typedef struct ICtlAction ICtlAction;
typedef struct ICtlActionHandler ICtlActionHandler;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICtlActionHandler *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICtlActionHandler *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICtlActionHandler *This);
    HRESULT (STDMETHODCALLTYPE *Invoke)(ICtlActionHandler *This, ICtlAction *action, int status);
} ICtlActionHandlerVtbl;
struct ICtlActionHandler { const ICtlActionHandlerVtbl *lpVtbl; };
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICtlAction *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICtlAction *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICtlAction *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(ICtlAction *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(ICtlAction *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(ICtlAction *This, int *level);
    HRESULT (STDMETHODCALLTYPE *put_Completed)(ICtlAction *This, ICtlActionHandler *handler);
    HRESULT (STDMETHODCALLTYPE *get_Completed)(ICtlAction *This, ICtlActionHandler **handler);
    HRESULT (STDMETHODCALLTYPE *GetResults)(ICtlAction *This);
} ICtlActionVtbl;
struct ICtlAction { const ICtlActionVtbl *lpVtbl; };
static const GUID IID_CtlAction = {0x5a648006, 0x843a, 0x4da9, {0x86, 0x5b, 0x9d, 0x26, 0xe5, 0xdf, 0xad, 0x7b}};

typedef struct ICtlInfo ICtlInfo;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICtlInfo *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICtlInfo *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICtlInfo *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(ICtlInfo *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(ICtlInfo *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(ICtlInfo *This, int *level);
    HRESULT (STDMETHODCALLTYPE *get_Id)(ICtlInfo *This, UINT32 *id);
    HRESULT (STDMETHODCALLTYPE *get_Status)(ICtlInfo *This, int *status);
    HRESULT (STDMETHODCALLTYPE *get_ErrorCode)(ICtlInfo *This, HRESULT *code);
    HRESULT (STDMETHODCALLTYPE *Cancel)(ICtlInfo *This);
    HRESULT (STDMETHODCALLTYPE *Close)(ICtlInfo *This);
} ICtlInfoVtbl;
struct ICtlInfo { const ICtlInfoVtbl *lpVtbl; };
static const GUID IID_CtlInfo = {0x00000036, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

typedef struct ICtl ICtl;
typedef struct { INT64 value; } CtlToken;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICtl *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICtl *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICtl *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(ICtl *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(ICtl *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(ICtl *This, int *level);
    HRESULT (STDMETHODCALLTYPE *get_Compositor)(ICtl *This, WICompositor **value);
    HRESULT (STDMETHODCALLTYPE *Commit)(ICtl *This);
    HRESULT (STDMETHODCALLTYPE *EnsurePreviousCommitCompletedAsync)(ICtl *This, ICtlAction **operation);
    HRESULT (STDMETHODCALLTYPE *add_CommitNeeded)(ICtl *This, ICtlHandler *handler, CtlToken *token);
    HRESULT (STDMETHODCALLTYPE *remove_CommitNeeded)(ICtl *This, CtlToken token);
} ICtlVtbl;
struct ICtl { const ICtlVtbl *lpVtbl; };
static const GUID IID_Ctl = {0x2d75f35a, 0x70a7, 0x4395, {0xba, 0x2d, 0xce, 0xf0, 0xb1, 0x83, 0x99, 0xf9}};

#define QI(p, iid, out) (p)->lpVtbl->QueryInterface(p, iid, (void **)(out))
#define REL(p) (p)->lpVtbl->Release(p)

typedef HRESULT (WINAPI *PRO_ACTIVATE)(HSTRING, IInspectable **);
typedef HRESULT (WINAPI *PWCS)(LPCWSTR, UINT32, HSTRING *);
typedef HRESULT (WINAPI *PWDS)(HSTRING);

static WICompositor *Comp;
static const UINT W = 64, H = 64;

static Color C(BYTE a, BYTE r, BYTE g, BYTE b) { Color c; c.A = a; c.R = r; c.G = g; c.B = b; return c; }

/* ---- helpers ---- */

static WISpriteVisual *NewSprite(float x, float y, float w, float h, Color color, WIVisual **visual)
{
    WISpriteVisual *s = NULL;
    WICompositionColorBrush *cb = NULL;
    WICompositionBrush *b = NULL;
    Vec3 off;
    Vec2 size;
    HRESULT hr;

    hr = Comp->lpVtbl->CreateSpriteVisual(Comp, &s);
    ok(hr == S_OK, "CreateSpriteVisual %#lx\n", hr);
    if (!s) return NULL;
    hr = QI(s, &IID_Visual, (void **)visual);
    ok(hr == S_OK, "QI IVisual %#lx\n", hr);
    off.X = x; off.Y = y; off.Z = 0; size.X = w; size.Y = h;
    (*visual)->lpVtbl->put_Offset(*visual, off);
    (*visual)->lpVtbl->put_Size(*visual, size);
    hr = Comp->lpVtbl->CreateColorBrushWithColor(Comp, color, &cb);
    ok(hr == S_OK, "CreateColorBrushWithColor %#lx\n", hr);
    if (cb)
    {
        hr = QI(cb, &IID_Brush, (void **)&b);
        ok(hr == S_OK, "QI IBrush %#lx\n", hr);
        hr = s->lpVtbl->put_Brush(s, b);
        ok(hr == S_OK, "put_Brush %#lx\n", hr);
        REL(b);
        REL(cb);
    }
    return s;
}

static WIVisualCollection *Children(WIVisual *v)
{
    WIContainerVisual *c = NULL;
    WIVisualCollection *col = NULL;
    HRESULT hr = QI(v, &IID_Container, (void **)&c);

    ok(hr == S_OK, "QI IContainerVisual %#lx\n", hr);
    if (!c) return NULL;
    hr = c->lpVtbl->get_Children(c, &col);
    ok(hr == S_OK && col, "get_Children %#lx\n", hr);
    REL(c);
    return col;
}

static WIVisual *NewContainer(float x, float y, float w, float h)
{
    WIContainerVisual *c = NULL;
    WIVisual *v = NULL;
    Vec3 off;
    Vec2 size;
    HRESULT hr = Comp->lpVtbl->CreateContainerVisual(Comp, &c);

    ok(hr == S_OK, "CreateContainerVisual %#lx\n", hr);
    if (!c) return NULL;
    QI(c, &IID_Visual, (void **)&v);
    REL(c);
    off.X = x; off.Y = y; off.Z = 0; size.X = w; size.Y = h;
    v->lpVtbl->put_Offset(v, off);
    v->lpVtbl->put_Size(v, size);
    return v;
}

static BOOL Render(WIVisual *root, BYTE *px)
{
    INitroCompositionTest *t = NULL;
    HRESULT hr = QI(root, &IID_INitroCompositionTest, (void **)&t);

    if (hr != S_OK) return FALSE;
    hr = t->lpVtbl->RenderToBitmap(t, W, H, px, W * 4);
    ok(hr == S_OK, "RenderToBitmap %#lx\n", hr);
    t->lpVtbl->Release(t);
    return TRUE;
}

static const BYTE *P(const BYTE *px, int x, int y) { return px + ((size_t)y * W + x) * 4; }

static void CheckPx(const BYTE *px, int x, int y, int a, int r, int g, int b, int tol, const char *what)
{
    const BYTE *p = P(px, x, y);

    ok(abs(p[3] - a) <= tol && abs(p[2] - r) <= tol && abs(p[1] - g) <= tol && abs(p[0] - b) <= tol,
       "%s: (%d,%d) is a%u r%u g%u b%u, expected a%d r%d g%d b%d\n", what, x, y, p[3], p[2], p[1], p[0], a, r, g, b);
}

/* ---- stage 2 ---- */

static void TestModel(void)
{
    WIVisual *v = NULL, *v2 = NULL, *parent = NULL;
    WISpriteVisual *s;
    WIContainerVisual *cp = NULL;
    WIVisualCollection *col, *col2;
    WICompositionObject *obj = NULL;
    WICompositor *c2 = NULL;
    Vec3 vec3 = {0};
    Vec2 vec2 = {0};
    FLOAT f = 0;
    boolean b = 0;
    INT32 count = -1;
    Color color;
    HRESULT hr;
    WICompositionColorBrush *cb = NULL;

    s = NewSprite(3, 4, 10, 20, C(255, 1, 2, 3), &v);
    if (!s) return;
    hr = v->lpVtbl->get_Offset(v, &vec3);
    ok(hr == S_OK && vec3.X == 3 && vec3.Y == 4 && vec3.Z == 0, "offset %g %g %g\n", vec3.X, vec3.Y, vec3.Z);
    hr = v->lpVtbl->get_Size(v, &vec2);
    ok(hr == S_OK && vec2.X == 10 && vec2.Y == 20, "size %g %g\n", vec2.X, vec2.Y);

    /* documented defaults */
    v->lpVtbl->get_Opacity(v, &f);
    ok(f == 1.0f, "opacity %g\n", f);
    v->lpVtbl->get_IsVisible(v, &b);
    ok(b, "IsVisible %d\n", b);
    v->lpVtbl->get_Scale(v, &vec3);
    ok(vec3.X == 1 && vec3.Y == 1 && vec3.Z == 1, "scale %g %g %g\n", vec3.X, vec3.Y, vec3.Z);
    v->lpVtbl->get_AnchorPoint(v, &vec2);
    ok(vec2.X == 0 && vec2.Y == 0, "anchor %g %g\n", vec2.X, vec2.Y);
    v->lpVtbl->get_RotationAngle(v, &f);
    ok(f == 0, "rotation %g\n", f);

    /* round trips; degrees and radians are one property */
    hr = v->lpVtbl->put_Opacity(v, 0.25f);
    ok(hr == S_OK, "put_Opacity %#lx\n", hr);
    v->lpVtbl->get_Opacity(v, &f);
    ok(f == 0.25f, "opacity %g\n", f);
    v->lpVtbl->put_RotationAngleInDegrees(v, 90.0f);
    v->lpVtbl->get_RotationAngle(v, &f);
    ok(fabsf(f - 1.5707964f) < 1e-5f, "rotation radians %g\n", f);
    v->lpVtbl->put_RotationAngle(v, 3.14159265f);
    v->lpVtbl->get_RotationAngleInDegrees(v, &f);
    ok(fabsf(f - 180.0f) < 1e-3f, "rotation degrees %g\n", f);
    v->lpVtbl->put_IsVisible(v, FALSE);
    v->lpVtbl->get_IsVisible(v, &b);
    ok(!b, "IsVisible %d\n", b);

    /* identity: every interface of one object gives the same IUnknown; CompositionObject.Compositor */
    hr = QI(v, &IID_CompObject, (void **)&obj);
    ok(hr == S_OK, "QI ICompositionObject %#lx\n", hr);
    if (obj)
    {
        hr = obj->lpVtbl->get_Compositor(obj, &c2);
        ok(hr == S_OK && c2, "get_Compositor %#lx\n", hr);
        if (c2)
        {
            IUnknown *u1 = NULL, *u2 = NULL;
            QI(c2, &IID_IUnknown, (void **)&u1);
            QI(Comp, &IID_IUnknown, (void **)&u2);
            ok(u1 == u2, "Compositor identity %p vs %p\n", u1, u2);
            REL(u1); REL(u2);
            REL(c2);
        }
        REL(obj);
    }

    /* the brush of a sprite */
    {
        WICompositionBrush *br = NULL;
        hr = s->lpVtbl->get_Brush(s, &br);
        ok(hr == S_OK && br, "get_Brush %#lx\n", hr);
        if (br)
        {
            hr = QI(br, &IID_ColorBrush, (void **)&cb);
            ok(hr == S_OK, "QI colour brush %#lx\n", hr);
            if (cb)
            {
                hr = cb->lpVtbl->get_Color(cb, &color);
                ok(hr == S_OK && color.A == 255 && color.R == 1 && color.G == 2 && color.B == 3, "colour %u %u %u %u\n", color.A, color.R, color.G, color.B);
                cb->lpVtbl->put_Color(cb, C(9, 8, 7, 6));
                cb->lpVtbl->get_Color(cb, &color);
                ok(color.A == 9 && color.R == 8 && color.G == 7 && color.B == 6, "colour %u %u %u %u\n", color.A, color.R, color.G, color.B);
                REL(cb);
            }
            REL(br);
        }
    }
    {
        WICompositionBrush *none = (WICompositionBrush *)0x1234;
        hr = s->lpVtbl->put_Brush(s, NULL);
        ok(hr == S_OK, "put_Brush(NULL) %#lx\n", hr);
        hr = s->lpVtbl->get_Brush(s, &none);
        ok(hr == S_OK && !none, "get_Brush after reset: %#lx %p\n", hr, none);
    }

    /* the tree */
    {
        WIVisual *root = NewContainer(0, 0, 100, 100), *a = NULL, *bb = NULL, *cc = NULL;
        WISpriteVisual *sa = NewSprite(0, 0, 1, 1, C(255, 0, 0, 0), &a);
        WISpriteVisual *sb = NewSprite(0, 0, 1, 1, C(255, 0, 0, 0), &bb);
        WISpriteVisual *sc = NewSprite(0, 0, 1, 1, C(255, 0, 0, 0), &cc);

        col = Children(root);
        hr = col->lpVtbl->get_Count(col, &count);
        ok(hr == S_OK && count == 0, "empty count %d\n", count);
        col2 = Children(root);
        ok(col == col2, "Children returned two objects\n");
        REL(col2);

        hr = col->lpVtbl->InsertAtTop(col, a);
        ok(hr == S_OK, "InsertAtTop %#lx\n", hr);
        hr = col->lpVtbl->InsertAtTop(col, bb);
        ok(hr == S_OK, "InsertAtTop %#lx\n", hr);
        hr = col->lpVtbl->InsertAtBottom(col, cc);
        ok(hr == S_OK, "InsertAtBottom %#lx\n", hr);
        col->lpVtbl->get_Count(col, &count);
        ok(count == 3, "count %d\n", count);
        /* order bottom to top: c a b */
        {
            INitroCompositionTest *t = NULL;
            char buf[2048];
            if (SUCCEEDED(QI(root, &IID_INitroCompositionTest, (void **)&t)))
            {
                t->lpVtbl->DumpTree(t, buf, sizeof(buf));
                ok(strstr(buf, "ContainerVisual") && strstr(buf, "SpriteVisual"), "dump:\n%s\n", buf);
                t->lpVtbl->Release(t);
            }
        }

        hr = a->lpVtbl->get_Parent(a, &cp);
        ok(hr == S_OK && cp, "get_Parent %#lx\n", hr);
        if (cp)
        {
            WIVisual *pv = NULL;
            QI(cp, &IID_Visual, (void **)&pv);
            ok(pv == root, "parent %p vs %p\n", pv, root);
            REL(pv);
            REL(cp);
        }

        /* inserting a member again moves it; inserting into a descendant of itself fails */
        hr = col->lpVtbl->InsertAtBottom(col, bb);
        ok(hr == S_OK, "move %#lx\n", hr);
        col->lpVtbl->get_Count(col, &count);
        ok(count == 3, "count after move %d\n", count);
        hr = col->lpVtbl->InsertAtTop(col, NULL);
        ok(hr == E_INVALIDARG, "InsertAtTop(NULL) %#lx\n", hr);
        hr = col->lpVtbl->InsertAbove(col, bb, bb);
        ok(hr == E_INVALIDARG, "InsertAbove(self) %#lx\n", hr);
        {
            WIVisualCollection *acol = Children(a);
            hr = acol->lpVtbl->InsertAtTop(acol, root);
            ok(hr == E_INVALIDARG, "cycle %#lx\n", hr);
            hr = acol->lpVtbl->InsertAtTop(acol, a);
            ok(hr == E_INVALIDARG, "self %#lx\n", hr);
            REL(acol);
        }

        hr = col->lpVtbl->Remove(col, a);
        ok(hr == S_OK, "Remove %#lx\n", hr);
        col->lpVtbl->get_Count(col, &count);
        ok(count == 2, "count after remove %d\n", count);
        parent = (WIVisual *)0x1234;
        {
            WIContainerVisual *pp = (WIContainerVisual *)0x1234;
            hr = a->lpVtbl->get_Parent(a, &pp);
            ok(hr == S_OK && !pp, "parent after remove %#lx %p\n", hr, pp);
        }
        hr = col->lpVtbl->RemoveAll(col);
        ok(hr == S_OK, "RemoveAll %#lx\n", hr);
        col->lpVtbl->get_Count(col, &count);
        ok(count == 0, "count after RemoveAll %d\n", count);

        /* a child outlives its parent when the app holds it */
        hr = col->lpVtbl->InsertAtTop(col, cc);
        ok(hr == S_OK, "InsertAtTop %#lx\n", hr);
        REL(col);
        REL(root);
        {
            WIContainerVisual *pp = (WIContainerVisual *)0x1234;
            hr = cc->lpVtbl->get_Parent(cc, &pp);
            ok(hr == S_OK && !pp, "parent after the parent died: %#lx %p\n", hr, pp);
        }
        REL(a); REL(bb); REL(cc);
        REL(sa); REL(sb); REL(sc);
    }
    (void)v2; (void)parent; (void)col2;
    REL(v);
    REL(s);
}

static void TestInsetClipObject(void)
{
    WIInsetClip *ic = NULL, *ic2 = NULL;
    WICompositionClip *clip = NULL;
    FLOAT f;
    HRESULT hr = Comp->lpVtbl->CreateInsetClip(Comp, &ic);

    ok(hr == S_OK && ic, "CreateInsetClip %#lx\n", hr);
    if (!ic) return;
    ic->lpVtbl->get_LeftInset(ic, &f);
    ok(f == 0, "left %g\n", f);
    hr = Comp->lpVtbl->CreateInsetClipWithInsets(Comp, 1, 2, 3, 4, &ic2);
    ok(hr == S_OK && ic2, "CreateInsetClipWithInsets %#lx\n", hr);
    if (ic2)
    {
        ic2->lpVtbl->get_LeftInset(ic2, &f); ok(f == 1, "left %g\n", f);
        ic2->lpVtbl->get_TopInset(ic2, &f); ok(f == 2, "top %g\n", f);
        ic2->lpVtbl->get_RightInset(ic2, &f); ok(f == 3, "right %g\n", f);
        ic2->lpVtbl->get_BottomInset(ic2, &f); ok(f == 4, "bottom %g\n", f);
        hr = QI(ic2, &IID_Clip, (void **)&clip);
        ok(hr == S_OK, "QI clip %#lx\n", hr);
        if (clip) REL(clip);
        REL(ic2);
    }
    REL(ic);
}

/* ---- pixel tests, colour brushes only ---- */

static void TestPixels(void)
{
    BYTE *px = HeapAlloc(GetProcessHeap(), 0, W * H * 4);
    WIVisual *root = NewContainer(0, 0, W, H), *a = NULL, *b = NULL, *c = NULL;
    WISpriteVisual *sa, *sb, *sc;
    WIVisualCollection *col = Children(root);
    HRESULT hr;
    Vec3 v3;
    Vec2 v2;

    sa = NewSprite(8, 8, 24, 24, C(255, 255, 0, 0), &a);
    sb = NewSprite(20, 20, 24, 24, C(255, 0, 255, 0), &b);
    col->lpVtbl->InsertAtTop(col, a);
    col->lpVtbl->InsertAtTop(col, b);
    if (!Render(root, px))
    {
        skip("INitroCompositionTest is not available\n");
        goto out;
    }
    CheckPx(px, 2, 2, 0, 0, 0, 0, 0, "outside");
    CheckPx(px, 8, 8, 255, 255, 0, 0, 0, "first pixel of red");
    CheckPx(px, 7, 8, 0, 0, 0, 0, 0, "left of red");
    CheckPx(px, 31, 19, 255, 255, 0, 0, 0, "last pixel of red");
    CheckPx(px, 32, 19, 0, 0, 0, 0, 0, "right of red");
    CheckPx(px, 25, 25, 255, 0, 255, 0, 0, "green over red");
    CheckPx(px, 43, 43, 255, 0, 255, 0, 0, "last pixel of green");
    CheckPx(px, 44, 44, 0, 0, 0, 0, 0, "after green");

    /* z order: red moved above green */
    hr = col->lpVtbl->InsertAbove(col, a, b);
    ok(hr == S_OK, "InsertAbove %#lx\n", hr);
    Render(root, px);
    CheckPx(px, 25, 25, 255, 255, 0, 0, 0, "red over green after InsertAbove");
    hr = col->lpVtbl->InsertBelow(col, a, b);
    ok(hr == S_OK, "InsertBelow %#lx\n", hr);
    Render(root, px);
    CheckPx(px, 25, 25, 255, 0, 255, 0, 0, "green over red after InsertBelow");

    /* invisible and opacity */
    {
        WICompositionColorBrush *cbr = NULL;
        b->lpVtbl->put_IsVisible(b, FALSE);
        Render(root, px);
        CheckPx(px, 25, 25, 255, 255, 0, 0, 0, "hidden green");
        b->lpVtbl->put_IsVisible(b, TRUE);
        b->lpVtbl->put_Opacity(b, 0.5f);
        Render(root, px);
        /* source over: 0.5 green on opaque red */
        CheckPx(px, 25, 25, 255, 127, 128, 0, 2, "half transparent green over red");
        CheckPx(px, 40, 40, 128, 0, 128, 0, 2, "half transparent green over nothing");
        b->lpVtbl->put_Opacity(b, 1.0f);
        (void)cbr;
    }

    /* parent opacity multiplies, parent offset moves */
    col->lpVtbl->RemoveAll(col);
    {
        WIVisual *grp = NewContainer(10, 10, 40, 40), *d = NULL;
        WISpriteVisual *sd = NewSprite(5, 5, 10, 10, C(255, 0, 0, 255), &d);
        WIVisualCollection *gcol = Children(grp);
        gcol->lpVtbl->InsertAtTop(gcol, d);
        col->lpVtbl->InsertAtTop(col, grp);
        Render(root, px);
        CheckPx(px, 14, 14, 0, 0, 0, 0, 0, "before nested offset");
        CheckPx(px, 15, 15, 255, 0, 0, 255, 0, "nested offset start");
        CheckPx(px, 24, 24, 255, 0, 0, 255, 0, "nested offset end");
        CheckPx(px, 25, 25, 0, 0, 0, 0, 0, "after nested offset");
        grp->lpVtbl->put_Opacity(grp, 0.5f);
        Render(root, px);
        CheckPx(px, 20, 20, 128, 0, 0, 128, 2, "group opacity");
        grp->lpVtbl->put_Opacity(grp, 1.0f);

        /* scale about the origin */
        v3.X = 2; v3.Y = 2; v3.Z = 1;
        d->lpVtbl->put_Scale(d, v3);
        Render(root, px);
        CheckPx(px, 15, 15, 255, 0, 0, 255, 0, "scaled start");
        CheckPx(px, 34, 34, 255, 0, 0, 255, 0, "scaled end");
        CheckPx(px, 35, 35, 0, 0, 0, 0, 0, "after scaled");
        v3.X = v3.Y = v3.Z = 1;
        d->lpVtbl->put_Scale(d, v3);

        /* anchor point: the middle of the visual sits at the offset */
        v2.X = 0.5f; v2.Y = 0.5f;
        d->lpVtbl->put_AnchorPoint(d, v2);
        Render(root, px);
        CheckPx(px, 9, 9, 0, 0, 0, 0, 0, "anchor: before start");
        CheckPx(px, 10, 10, 255, 0, 0, 255, 0, "anchor start");
        CheckPx(px, 19, 19, 255, 0, 0, 255, 0, "anchor end");
        CheckPx(px, 20, 20, 0, 0, 0, 0, 0, "anchor after");
        v2.X = v2.Y = 0;
        d->lpVtbl->put_AnchorPoint(d, v2);

        /* rotation of 90 degrees about the centre of a 20x10 visual at (20,20) in the root */
        col->lpVtbl->RemoveAll(col);
        REL(gcol);
        REL(grp);
        REL(d);
        REL(sd);
    }
    {
        WIVisual *r = NULL;
        WISpriteVisual *sr = NewSprite(20, 20, 20, 10, C(255, 200, 100, 50), &r);
        v3.X = 10; v3.Y = 5; v3.Z = 0;
        r->lpVtbl->put_CenterPoint(r, v3);
        r->lpVtbl->put_RotationAngleInDegrees(r, 90.0f);
        col->lpVtbl->InsertAtTop(col, r);
        Render(root, px);
        /* the rectangle becomes 10 wide, 20 tall around (30, 25) */
        CheckPx(px, 30, 16, 255, 200, 100, 50, 0, "rotated inside top");
        CheckPx(px, 30, 34, 255, 200, 100, 50, 0, "rotated inside bottom");
        CheckPx(px, 22, 25, 0, 0, 0, 0, 0, "rotated: old left end");
        CheckPx(px, 38, 25, 0, 0, 0, 0, 0, "rotated: old right end");
        col->lpVtbl->RemoveAll(col);

        /* inset clip */
        {
            WIInsetClip *ic = NULL;
            WICompositionClip *clip = NULL;
            v3.X = v3.Y = v3.Z = 0;
            r->lpVtbl->put_CenterPoint(r, v3);
            r->lpVtbl->put_RotationAngle(r, 0);
            v2.X = 20; v2.Y = 20;
            r->lpVtbl->put_Size(r, v2);
            Comp->lpVtbl->CreateInsetClipWithInsets(Comp, 5, 6, 7, 8, &ic);
            QI(ic, &IID_Clip, (void **)&clip);
            hr = r->lpVtbl->put_Clip(r, clip);
            ok(hr == S_OK, "put_Clip %#lx\n", hr);
            col->lpVtbl->InsertAtTop(col, r);
            Render(root, px);
            CheckPx(px, 24, 25, 0, 0, 0, 0, 0, "clip: left of clip");
            CheckPx(px, 25, 25, 0, 0, 0, 0, 0, "clip: top of clip");
            CheckPx(px, 25, 26, 255, 200, 100, 50, 0, "clip: first pixel");
            CheckPx(px, 32, 31, 255, 200, 100, 50, 0, "clip: last pixel");
            CheckPx(px, 33, 31, 0, 0, 0, 0, 0, "clip: right");
            CheckPx(px, 32, 32, 0, 0, 0, 0, 0, "clip: below");
            REL(clip);
            REL(ic);
        }
        REL(r);
        REL(sr);
    }
    (void)c; (void)sc;
out:
    REL(col);
    REL(root);
    REL(a); REL(b);
    REL(sa); REL(sb);
    HeapFree(GetProcessHeap(), 0, px);
}

/* ---- stage 3: graphics device and drawing surfaces ---- */

static ID3D11Device *MakeDevice(void)
{
    ID3D11Device *dev = NULL;
    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                                   D3D11_SDK_VERSION, &dev, &fl, NULL);

    if (FAILED(hr))
        hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_WARP, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                               D3D11_SDK_VERSION, &dev, &fl, NULL);
    if (FAILED(hr)) trace("no D3D11 device: %#lx\n", hr);
    return dev;
}


/* Direct2D needs a render target the renderer may lack (softpipe on the i386 images): then the drawing tests cannot run */
static BOOL D2DUsable(ID3D11Device *d3d)
{
    typedef HRESULT (WINAPI *PFN_CREATE)(IDXGIDevice *, const D2D1_CREATION_PROPERTIES *, ID2D1Device **);
    HMODULE mod = LoadLibraryW(L"d2d1.dll");
    PFN_CREATE create = mod ? (PFN_CREATE)GetProcAddress(mod, "D2D1CreateDevice") : NULL;
    IDXGIDevice *dxgi = NULL;
    ID2D1Device *dev = NULL;
    ID2D1DeviceContext *ctx = NULL;
    BOOL ok_ = FALSE;

    if (create && SUCCEEDED(ID3D11Device_QueryInterface(d3d, &IID_IDXGIDevice, (void **)&dxgi)) &&
        SUCCEEDED(create(dxgi, NULL, &dev)) &&
        SUCCEEDED(ID2D1Device_CreateDeviceContext(dev, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &ctx)))
        ok_ = TRUE;
    if (ctx) ID2D1DeviceContext_Release(ctx);
    if (dev) ID2D1Device_Release(dev);
    if (dxgi) IDXGIDevice_Release(dxgi);
    return ok_;
}

static void FillRc(ID2D1DeviceContext *dc, float l, float t, float r, float b, float R, float G, float B)
{
    ID2D1SolidColorBrush *brush = NULL;
    D2D1_COLOR_F col;
    D2D1_RECT_F rc;

    col.r = R; col.g = G; col.b = B; col.a = 1.0f;
    rc.left = l; rc.top = t; rc.right = r; rc.bottom = b;
    if (SUCCEEDED(ID2D1DeviceContext_CreateSolidColorBrush(dc, &col, NULL, &brush)))
    {
        ID2D1DeviceContext_FillRectangle(dc, &rc, (ID2D1Brush *)brush);
        REL(brush);
    }
}

static void TestSurfaces(void)
{
    ID3D11Device *d3d = MakeDevice();
    WICompositorInterop *interop = NULL;
    WICompositionGraphicsDevice *gdev = NULL;
    WICompositionDrawingSurface *ds = NULL;
    INitroDrawingSurfaceInterop *dsi = NULL;
    ID2D1DeviceContext *dc = NULL;
    IDXGISurface *dxgi = NULL;
    __x_ABI_CWindows_CFoundation_CSize size;
    __x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat fmt;
    __x_ABI_CWindows_CGraphics_CDirectX_CDirectXAlphaMode am;
    D2D1_COLOR_F clear;
    POINT off;
    RECT rc;
    HRESULT hr;

    if (!d3d) { skip("no D3D11 device\n"); return; }
    hr = QI(Comp, &IID_Interop, (void **)&interop);
    ok(hr == S_OK, "QI ICompositorInterop %#lx\n", hr);
    if (!interop) goto out;

    hr = interop->lpVtbl->CreateGraphicsDevice(interop, NULL, &gdev);
    ok(hr == E_INVALIDARG || hr == E_POINTER, "CreateGraphicsDevice(NULL) %#lx\n", hr);
    hr = interop->lpVtbl->CreateGraphicsDevice(interop, (IUnknown *)d3d, &gdev);
    ok(hr == S_OK && gdev, "CreateGraphicsDevice %#lx\n", hr);
    if (!gdev) goto out;

    size.Width = 64; size.Height = 32;
    hr = gdev->lpVtbl->CreateDrawingSurface(gdev, size, DirectXPixelFormat_B8G8R8A8UIntNormalized,
                                            DirectXAlphaMode_Premultiplied, &ds);
    ok(hr == S_OK && ds, "CreateDrawingSurface %#lx\n", hr);
    if (!ds) goto out;
    ds->lpVtbl->get_Size(ds, &size);
    ok(size.Width == 64 && size.Height == 32, "size %g x %g\n", size.Width, size.Height);
    ds->lpVtbl->get_PixelFormat(ds, &fmt);
    ok((int)fmt == 87, "format %d\n", fmt);
    ds->lpVtbl->get_AlphaMode(ds, &am);
    ok((int)am == 1, "alpha %d\n", am);
    {
        WICompositionDrawingSurface *bad = (WICompositionDrawingSurface *)0x1234;
        size.Width = 0; size.Height = 10;
        hr = gdev->lpVtbl->CreateDrawingSurface(gdev, size, (int)87, (int)1, &bad);
        ok(hr == E_INVALIDARG && !bad, "empty surface %#lx %p\n", hr, bad);
    }

    hr = QI(ds, &IID_INitroDrawingSurfaceInterop, (void **)&dsi);
    if (hr != S_OK)
    {
        skip("no drawing surface interop interface\n");
        goto out;
    }

    /* errors */
    hr = dsi->lpVtbl->EndDraw(dsi);
    ok(hr == E_FAIL, "EndDraw without BeginDraw %#lx\n", hr);
    rc.left = 0; rc.top = 0; rc.right = 100; rc.bottom = 10;
    hr = dsi->lpVtbl->BeginDraw(dsi, &rc, &IID_ID2D1DeviceContext, (void **)&dc, &off);
    ok(hr == E_INVALIDARG, "BeginDraw outside %#lx\n", hr);
    hr = dsi->lpVtbl->BeginDraw(dsi, NULL, &IID_ID2D1DeviceContext, NULL, &off);
    ok(hr == E_POINTER, "BeginDraw(NULL out) %#lx\n", hr);

    if (!D2DUsable(d3d))
    {
        skip("Direct2D device contexts are not available on this renderer\n");
        goto out;
    }

    /* draw the whole surface: blue, with a green 16x16 square at (8,8) */
    off.x = off.y = 77;
    hr = dsi->lpVtbl->BeginDraw(dsi, NULL, &IID_ID2D1DeviceContext, (void **)&dc, &off);
    ok(hr == S_OK && dc, "BeginDraw %#lx\n", hr);
    ok(off.x == 0 && off.y == 0, "offset %ld %ld\n", off.x, off.y);
    if (!dc) goto out;
    {
        void *again = NULL;
        hr = dsi->lpVtbl->BeginDraw(dsi, NULL, &IID_ID2D1DeviceContext, &again, &off);
        ok(hr == E_FAIL, "second BeginDraw %#lx\n", hr);
    }
    clear.r = 0; clear.g = 0; clear.b = 1; clear.a = 1;
    ID2D1DeviceContext_Clear(dc, &clear);
    FillRc(dc, 8, 8, 24, 24, 0, 1, 0);
    hr = dsi->lpVtbl->EndDraw(dsi);
    ok(hr == S_OK, "EndDraw %#lx\n", hr);
    REL(dc);

    /* partial update asks for the offset, and the clip keeps the rest */
    rc.left = 40; rc.top = 4; rc.right = 56; rc.bottom = 20;
    dc = NULL;
    hr = dsi->lpVtbl->BeginDraw(dsi, &rc, &IID_ID2D1DeviceContext, (void **)&dc, &off);
    ok(hr == S_OK && dc, "partial BeginDraw %#lx\n", hr);
    ok(off.x == 40 && off.y == 4, "partial offset %ld %ld\n", off.x, off.y);
    if (dc)
    {
        clear.r = 1; clear.g = 0; clear.b = 0;
        ID2D1DeviceContext_Clear(dc, &clear);      /* Clear honours the clip: only the update rect turns red */
        hr = dsi->lpVtbl->EndDraw(dsi);
        ok(hr == S_OK, "EndDraw %#lx\n", hr);
        REL(dc);
    }

    /* the texture itself on request */
    hr = dsi->lpVtbl->BeginDraw(dsi, NULL, &IID_IDXGISurface, (void **)&dxgi, &off);
    ok(hr == S_OK && dxgi, "BeginDraw(IDXGISurface) %#lx\n", hr);
    if (dxgi) REL(dxgi);
    hr = dsi->lpVtbl->EndDraw(dsi);
    ok(hr == S_OK, "EndDraw %#lx\n", hr);

    /* show it: surface brush, Fill, nearest */
    {
        BYTE *px = HeapAlloc(GetProcessHeap(), 0, W * H * 4);
        WIVisual *root = NewContainer(0, 0, W, H), *v = NULL;
        WISpriteVisual *sp = NULL;
        WIVisualCollection *col = Children(root);
        WICompositionSurfaceBrush *sb = NULL;
        WICompositionBrush *br = NULL;
        WICompositionSurface *surf = NULL;
        Vec3 v3 = {0};
        Vec2 v2;
        INitroCompositionTest *t = NULL;

        hr = Comp->lpVtbl->CreateSpriteVisual(Comp, &sp);
        QI(sp, &IID_Visual, (void **)&v);
        v3.X = 0; v3.Y = 0;
        v->lpVtbl->put_Offset(v, v3);
        v2.X = 64; v2.Y = 32;
        v->lpVtbl->put_Size(v, v2);
        hr = QI(ds, &IID_Surface, (void **)&surf);
        ok(hr == S_OK, "QI ICompositionSurface %#lx\n", hr);
        hr = Comp->lpVtbl->CreateSurfaceBrushWithSurface(Comp, surf, &sb);
        ok(hr == S_OK && sb, "CreateSurfaceBrushWithSurface %#lx\n", hr);
        {
            WICompositionSurface *back = NULL;
            sb->lpVtbl->get_Surface(sb, &back);
            ok(back != NULL, "get_Surface returned NULL\n");
            if (back) REL(back);
        }
        sb->lpVtbl->put_Stretch(sb, CompositionStretch_Fill);
        sb->lpVtbl->put_BitmapInterpolationMode(sb, CompositionBitmapInterpolationMode_NearestNeighbor);
        QI(sb, &IID_Brush, (void **)&br);
        sp->lpVtbl->put_Brush(sp, br);
        col->lpVtbl->InsertAtTop(col, v);
        if (SUCCEEDED(QI(root, &IID_INitroCompositionTest, (void **)&t)))
        {
            t->lpVtbl->RenderToBitmap(t, W, H, px, W * 4);
            t->lpVtbl->Release(t);
            CheckPx(px, 2, 2, 255, 0, 0, 255, 2, "surface: blue");
            CheckPx(px, 10, 10, 255, 0, 255, 0, 2, "surface: green square");
            CheckPx(px, 23, 23, 255, 0, 255, 0, 2, "surface: green square end");
            CheckPx(px, 24, 24, 255, 0, 0, 255, 2, "surface: after green square");
            CheckPx(px, 48, 10, 255, 255, 0, 0, 2, "surface: partial update red");
            CheckPx(px, 39, 10, 255, 0, 0, 255, 2, "surface: left of partial update");
            CheckPx(px, 56, 10, 255, 0, 0, 255, 2, "surface: right of partial update");
            CheckPx(px, 48, 20, 255, 0, 0, 255, 2, "surface: below partial update");
            CheckPx(px, 10, 40, 0, 0, 0, 0, 0, "below the sprite");
        }

        /* Scroll the whole surface by (8,4): the green square moves */
        hr = dsi->lpVtbl->Scroll(dsi, NULL, NULL, 8, 4);
        ok(hr == S_OK, "Scroll %#lx\n", hr);
        if (SUCCEEDED(QI(root, &IID_INitroCompositionTest, (void **)&t)))
        {
            t->lpVtbl->RenderToBitmap(t, W, H, px, W * 4);
            t->lpVtbl->Release(t);
            CheckPx(px, 16, 12, 255, 0, 255, 0, 2, "scrolled: green square start");
            CheckPx(px, 31, 27, 255, 0, 255, 0, 2, "scrolled: green square end");
            CheckPx(px, 12, 10, 255, 0, 0, 255, 2, "scrolled: old green start is now blue");
        }

        /* Resize keeps the overlap */
        {
            SIZE sz;
            sz.cx = 128; sz.cy = 64;
            hr = dsi->lpVtbl->Resize(dsi, sz);
            ok(hr == S_OK, "Resize %#lx\n", hr);
            ds->lpVtbl->get_Size(ds, &size);
            ok(size.Width == 128 && size.Height == 64, "size after resize %g x %g\n", size.Width, size.Height);
            v2.X = 128; v2.Y = 64;
            sz.cx = 0; sz.cy = 5;
            hr = dsi->lpVtbl->Resize(dsi, sz);
            ok(hr == E_INVALIDARG, "Resize(0) %#lx\n", hr);
        }

        REL(br);
        REL(sb);
        REL(surf);
        col->lpVtbl->RemoveAll(col);
        REL(col);
        REL(v);
        REL(sp);
        REL(root);
        HeapFree(GetProcessHeap(), 0, px);
    }

out:
    if (dsi) dsi->lpVtbl->Release(dsi);
    if (ds) REL(ds);
    if (gdev) REL(gdev);
    if (interop) REL(interop);
    REL(d3d);
}

/* stretch and alignment of a 2x2 surface on an 8x8 sprite */
/*
 * A rendering device that is only an ID2D1Device (what Office hands to CreateGraphicsDevice). Documented: the
 * graphics device is made from a Direct2D device and its surfaces are drawn with it. The D3D device under the
 * D2D device must be the one the surface texture lives on.
 */
static void TestSurfacesD2DDevice(void)
{
    typedef HRESULT (WINAPI *PFN_CREATE)(IDXGIDevice *, const D2D1_CREATION_PROPERTIES *, ID2D1Device **);
    ID3D11Device *d3d = MakeDevice();
    HMODULE mod = LoadLibraryW(L"d2d1.dll");
    PFN_CREATE create = mod ? (PFN_CREATE)GetProcAddress(mod, "D2D1CreateDevice") : NULL;
    WICompositorInterop *interop = NULL;
    WICompositionGraphicsDevice *gdev = NULL, *bad = NULL;
    WICompositionDrawingSurface *ds = NULL;
    INitroDrawingSurfaceInterop *dsi = NULL;
    IDXGIDevice *dxgi = NULL;
    ID2D1Device *d2d = NULL;
    ID2D1DeviceContext *dc = NULL;
    ID3D11Texture2D *tex = NULL;
    ID3D11Device *texdev = NULL;
    IUnknown *notdev = NULL;
    __x_ABI_CWindows_CFoundation_CSize size;
    D2D1_COLOR_F clear;
    POINT off;
    HRESULT hr;

    if (!d3d || !create) { skip("no D3D11 device or d2d1\n"); goto out; }
    if (FAILED(ID3D11Device_QueryInterface(d3d, &IID_IDXGIDevice, (void **)&dxgi)) || FAILED(create(dxgi, NULL, &d2d)) || !d2d)
    {
        skip("no ID2D1Device\n");
        goto out;
    }
    hr = QI(Comp, &IID_Interop, (void **)&interop);
    ok(hr == S_OK, "QI ICompositorInterop %#lx\n", hr);
    if (!interop) goto out;

    /* anything that is not a device stays E_INVALIDARG */
    hr = CreateDXGIFactory(&IID_IUnknown, (void **)&notdev);
    if (SUCCEEDED(hr))
    {
        hr = interop->lpVtbl->CreateGraphicsDevice(interop, notdev, &bad);
        ok(hr == E_INVALIDARG && !bad, "CreateGraphicsDevice(not a device) %#lx %p\n", hr, bad);
    }

    hr = interop->lpVtbl->CreateGraphicsDevice(interop, (IUnknown *)d2d, &gdev);
    ok(hr == S_OK && gdev, "CreateGraphicsDevice(ID2D1Device) %#lx\n", hr);
    if (!gdev) goto out;

    size.Width = 64; size.Height = 32;
    hr = gdev->lpVtbl->CreateDrawingSurface(gdev, size, DirectXPixelFormat_B8G8R8A8UIntNormalized,
                                            DirectXAlphaMode_Premultiplied, &ds);
    ok(hr == S_OK && ds, "CreateDrawingSurface %#lx\n", hr);
    if (!ds) goto out;
    /* the real ICompositionDrawingSurfaceInterop (same layout as the Nitro one) */
    hr = QI(ds, &IID_ICompositionDrawingSurfaceInterop, (void **)&dsi);
    ok(hr == S_OK && dsi, "QI ICompositionDrawingSurfaceInterop %#lx\n", hr);
    if (hr != S_OK) goto out;

    /* the texture is on the D3D device of the D2D device */
    hr = dsi->lpVtbl->BeginDraw(dsi, NULL, &IID_ID3D11Texture2D, (void **)&tex, &off);
    ok(hr == S_OK && tex, "BeginDraw(ID3D11Texture2D) %#lx\n", hr);
    if (tex)
    {
        ID3D11Texture2D_GetDevice(tex, &texdev);
        ok(texdev == d3d, "texture device %p, expected %p\n", texdev, d3d);
        if (texdev) ID3D11Device_Release(texdev);
        ID3D11Texture2D_Release(tex);
        hr = dsi->lpVtbl->EndDraw(dsi);
        ok(hr == S_OK, "EndDraw %#lx\n", hr);
    }

    if (!D2DUsable(d3d)) { skip("Direct2D device contexts are not available on this renderer\n"); goto out; }

    hr = dsi->lpVtbl->BeginDraw(dsi, NULL, &IID_ID2D1DeviceContext, (void **)&dc, &off);
    ok(hr == S_OK && dc, "BeginDraw(ID2D1DeviceContext) %#lx\n", hr);
    if (dc)
    {
        ID2D1Device *dcdev = NULL;

        ID2D1DeviceContext_GetDevice(dc, &dcdev);
        ok(dcdev == d2d, "context device %p, expected the app's %p\n", dcdev, d2d);
        if (dcdev) ID2D1Device_Release(dcdev);
        clear.r = 0; clear.g = 0; clear.b = 1; clear.a = 1;
        ID2D1DeviceContext_Clear(dc, &clear);
        hr = dsi->lpVtbl->EndDraw(dsi);
        ok(hr == S_OK, "EndDraw %#lx\n", hr);
        REL(dc);

        /* read the pixel back: opaque blue, BGRA */
        {
            D3D11_TEXTURE2D_DESC desc;
            D3D11_MAPPED_SUBRESOURCE map;
            ID3D11Texture2D *stage = NULL, *t2 = NULL;
            ID3D11DeviceContext *ctx = NULL;

            if (SUCCEEDED(dsi->lpVtbl->BeginDraw(dsi, NULL, &IID_ID3D11Texture2D, (void **)&t2, &off)) && t2)
            {
                ID3D11Texture2D_GetDesc(t2, &desc);
                desc.Usage = D3D11_USAGE_STAGING; desc.BindFlags = 0; desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ; desc.MiscFlags = 0;
                ID3D11Device_GetImmediateContext(d3d, &ctx);
                if (SUCCEEDED(ID3D11Device_CreateTexture2D(d3d, &desc, NULL, &stage)))
                {
                    ID3D11DeviceContext_CopyResource(ctx, (ID3D11Resource *)stage, (ID3D11Resource *)t2);
                    if (SUCCEEDED(ID3D11DeviceContext_Map(ctx, (ID3D11Resource *)stage, 0, D3D11_MAP_READ, 0, &map)))
                    {
                        const BYTE *px = (const BYTE *)map.pData + 5 * map.RowPitch + 5 * 4;
                        ok(px[0] == 255 && px[1] == 0 && px[2] == 0 && px[3] == 255, "pixel %u %u %u %u\n", px[0], px[1], px[2], px[3]);
                        ID3D11DeviceContext_Unmap(ctx, (ID3D11Resource *)stage, 0);
                    }
                    ID3D11Texture2D_Release(stage);
                }
                ID3D11DeviceContext_Release(ctx);
                ID3D11Texture2D_Release(t2);
                dsi->lpVtbl->EndDraw(dsi);
            }
        }
    }

out:
    if (dsi) REL(dsi);
    if (ds) REL(ds);
    if (gdev) REL(gdev);
    if (notdev) IUnknown_Release(notdev);
    if (interop) REL(interop);
    if (d2d) ID2D1Device_Release(d2d);
    if (dxgi) IDXGIDevice_Release(dxgi);
    if (d3d) ID3D11Device_Release(d3d);
}

static void TestStretch(void)
{
    ID3D11Device *d3d = MakeDevice();
    WICompositorInterop *interop = NULL;
    WICompositionGraphicsDevice *gdev = NULL;
    WICompositionDrawingSurface *ds = NULL;
    INitroDrawingSurfaceInterop *dsi = NULL;
    ID2D1DeviceContext *dc = NULL;
    __x_ABI_CWindows_CFoundation_CSize size;
    POINT off;
    HRESULT hr;

    if (!d3d) return;
    if (!D2DUsable(d3d)) { REL(d3d); return; }
    QI(Comp, &IID_Interop, (void **)&interop);
    if (!interop) goto out;
    interop->lpVtbl->CreateGraphicsDevice(interop, (IUnknown *)d3d, &gdev);
    if (!gdev) goto out;
    size.Width = 2; size.Height = 2;
    gdev->lpVtbl->CreateDrawingSurface(gdev, size, (int)87, (int)1, &ds);
    if (!ds || FAILED(QI(ds, &IID_INitroDrawingSurfaceInterop, (void **)&dsi))) goto out;
    hr = dsi->lpVtbl->BeginDraw(dsi, NULL, &IID_ID2D1DeviceContext, (void **)&dc, &off);
    ok(hr == S_OK && dc, "BeginDraw %#lx\n", hr);
    if (!dc) goto out;
    FillRc(dc, 0, 0, 1, 1, 1, 0, 0);       /* top left red */
    FillRc(dc, 1, 0, 2, 1, 0, 1, 0);       /* top right green */
    FillRc(dc, 0, 1, 1, 2, 0, 0, 1);       /* bottom left blue */
    FillRc(dc, 1, 1, 2, 2, 1, 1, 1);       /* bottom right white */
    hr = dsi->lpVtbl->EndDraw(dsi);
    ok(hr == S_OK, "EndDraw %#lx\n", hr);
    REL(dc);
    {
        BYTE *px = HeapAlloc(GetProcessHeap(), 0, W * H * 4);
        WIVisual *root = NewContainer(0, 0, W, H), *v = NULL;
        WISpriteVisual *sp = NULL;
        WIVisualCollection *col = Children(root);
        WICompositionSurfaceBrush *sb = NULL;
        WICompositionBrush *br = NULL;
        WICompositionSurface *surf = NULL;
        Vec3 v3 = {0};
        Vec2 v2;

        Comp->lpVtbl->CreateSpriteVisual(Comp, &sp);
        QI(sp, &IID_Visual, (void **)&v);
        v2.X = 8; v2.Y = 8;
        v->lpVtbl->put_Size(v, v2);
        v3.X = 4; v3.Y = 4;
        v->lpVtbl->put_Offset(v, v3);
        QI(ds, &IID_Surface, (void **)&surf);
        Comp->lpVtbl->CreateSurfaceBrush(Comp, &sb);
        sb->lpVtbl->put_Surface(sb, surf);
        sb->lpVtbl->put_BitmapInterpolationMode(sb, CompositionBitmapInterpolationMode_NearestNeighbor);
        QI(sb, &IID_Brush, (void **)&br);
        sp->lpVtbl->put_Brush(sp, br);
        col->lpVtbl->InsertAtTop(col, v);

        sb->lpVtbl->put_Stretch(sb, CompositionStretch_Fill);
        if (Render(root, px))
        {
            CheckPx(px, 5, 5, 255, 255, 0, 0, 1, "fill: top left");
            CheckPx(px, 10, 5, 255, 0, 255, 0, 1, "fill: top right");
            CheckPx(px, 5, 10, 255, 0, 0, 255, 1, "fill: bottom left");
            CheckPx(px, 10, 10, 255, 255, 255, 255, 1, "fill: bottom right");
            CheckPx(px, 3, 3, 0, 0, 0, 0, 0, "fill: outside");
        }
        /* None: native size (2x2) in the middle (ratios 0.5 default): pixels (7,7)..(8,8) */
        sb->lpVtbl->put_Stretch(sb, CompositionStretch_None);
        if (Render(root, px))
        {
            CheckPx(px, 7, 7, 255, 255, 0, 0, 1, "none: top left");
            CheckPx(px, 8, 7, 255, 0, 255, 0, 1, "none: top right");
            CheckPx(px, 7, 8, 255, 0, 0, 255, 1, "none: bottom left");
            CheckPx(px, 8, 8, 255, 255, 255, 255, 1, "none: bottom right");
            CheckPx(px, 6, 7, 0, 0, 0, 0, 0, "none: left of image");
            CheckPx(px, 5, 5, 0, 0, 0, 0, 0, "none: corner is empty");
        }
        /* alignment ratios 0,0: image in the top left corner of the sprite */
        sb->lpVtbl->put_HorizontalAlignmentRatio(sb, 0.0f);
        sb->lpVtbl->put_VerticalAlignmentRatio(sb, 0.0f);
        if (Render(root, px))
        {
            CheckPx(px, 4, 4, 255, 255, 0, 0, 1, "none/0,0: top left");
            CheckPx(px, 5, 5, 255, 255, 255, 255, 1, "none/0,0: bottom right");
            CheckPx(px, 6, 6, 0, 0, 0, 0, 0, "none/0,0: past the image");
        }
        {
            FLOAT r = -1;
            sb->lpVtbl->put_HorizontalAlignmentRatio(sb, 7.0f);
            sb->lpVtbl->get_HorizontalAlignmentRatio(sb, &r);
            ok(r == 1.0f, "alignment ratio is clamped to 1: %g\n", r);
        }
        /* Uniform on a square surface in a 8x4 sprite: 4x4 centred */
        v2.X = 8; v2.Y = 4;
        v->lpVtbl->put_Size(v, v2);
        sb->lpVtbl->put_HorizontalAlignmentRatio(sb, 0.5f);
        sb->lpVtbl->put_VerticalAlignmentRatio(sb, 0.5f);
        sb->lpVtbl->put_Stretch(sb, CompositionStretch_Uniform);
        if (Render(root, px))
        {
            CheckPx(px, 4 + 2, 4, 255, 255, 0, 0, 1, "uniform: image starts at 2");
            CheckPx(px, 4 + 1, 4, 0, 0, 0, 0, 0, "uniform: left margin");
            CheckPx(px, 4 + 6, 4, 0, 0, 0, 0, 0, "uniform: right margin");
        }
        sb->lpVtbl->put_Stretch(sb, CompositionStretch_UniformToFill);
        if (Render(root, px))
        {
            CheckPx(px, 4, 4, 255, 255, 0, 0, 1, "uniformtofill: top left");
            CheckPx(px, 11, 4, 255, 0, 255, 0, 1, "uniformtofill: top right");
        }
        REL(br);
        REL(sb);
        REL(surf);
        col->lpVtbl->RemoveAll(col);
        REL(col);
        REL(v);
        REL(sp);
        REL(root);
        HeapFree(GetProcessHeap(), 0, px);
    }
out:
    if (dsi) dsi->lpVtbl->Release(dsi);
    if (ds) REL(ds);
    if (gdev) REL(gdev);
    if (interop) REL(interop);
    REL(d3d);
}

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS *ep)
{
    HMODULE mod = NULL;
    char name[MAX_PATH] = "?";
    ULONG_PTR addr = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;

    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)addr, &mod);
    if (mod) GetModuleFileNameA(mod, name, sizeof(name));
    printf("CRASH code %#lx at %p (%s + %#lx), info %p %p\n", ep->ExceptionRecord->ExceptionCode, (void *)addr, name,
           mod ? (ULONG)(addr - (ULONG_PTR)mod) : 0, (void *)ep->ExceptionRecord->ExceptionInformation[0],
           (void *)ep->ExceptionRecord->ExceptionInformation[1]);
    fflush(stdout);
    return EXCEPTION_EXECUTE_HANDLER;
}

static ULONG RefOf(IUnknown *u)
{
    u->lpVtbl->AddRef(u);
    return u->lpVtbl->Release(u);
}

#define IID_Closable IID___x_ABI_CWindows_CFoundation_CIClosable
static const GUID IID_AgileObj = {0x94ea2b94, 0xe9cc, 0x49e0, {0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90}};
static const GUID IID_Unknown1 = {0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34}};

static BOOL HasIid(const IID *iids, ULONG count, const GUID *want)
{
    ULONG i;

    for (i = 0; i < count; i++) if (IsEqualGUID(&iids[i], want)) return TRUE;
    return FALSE;
}

static void TestDesktopTarget(void)
{
    IDesktopInterop *di = NULL;
    IDesktopTarget *t = NULL, *t2 = NULL;
    IDesktopTargetInterop *ti = NULL;
    WICompositionTarget *ct = NULL;
    WICompositionObject *obj = NULL;
    __x_ABI_CWindows_CFoundation_CIClosable *clo = NULL;
    WICompositor *c2 = NULL;
    WIVisual *v, *got;
    IUnknown *u1 = NULL, *u2 = NULL;
    HSTRING cls = NULL;
    HMODULE combase = GetModuleHandleW(L"combase.dll");
    LPCWSTR (WINAPI *pRaw)(HSTRING, UINT32 *) = combase ? (void *)GetProcAddress(combase, "WindowsGetStringRawBuffer") : NULL;
    HRESULT (WINAPI *pDel)(HSTRING) = combase ? (void *)GetProcAddress(combase, "WindowsDeleteString") : NULL;
    ULONG comp_ref, vis_ref, count;
    IID *iids;
    BOOLEAN topmost;
    HWND hwnd, got_hwnd;
    HRESULT hr;

    hr = QI(Comp, &IID_DesktopInterop, (void **)&di);
    ok(hr == S_OK && di, "QI ICompositorDesktopInterop %#lx\n", hr);
    if (!di) return;
    QI(di, &IID_IUnknown, (void **)&u1);
    QI(Comp, &IID_IUnknown, (void **)&u2);
    ok(u1 == u2, "identity %p vs %p\n", u1, u2);
    REL(u1); REL(u2);

    hwnd = CreateWindowExW(0, L"STATIC", L"dcomp target", WS_OVERLAPPEDWINDOW, 0, 0, 200, 150, NULL, NULL, NULL, NULL);
    ok(hwnd != NULL, "CreateWindowExW failed %lu\n", GetLastError());
    if (!hwnd) { REL(di); return; }
    comp_ref = RefOf((IUnknown *)Comp);

    hr = di->lpVtbl->CreateDesktopWindowTarget(di, hwnd, TRUE, NULL);
    ok(hr == E_POINTER, "CreateDesktopWindowTarget(NULL) %#lx\n", hr);
    hr = di->lpVtbl->CreateDesktopWindowTarget(di, hwnd, TRUE, &t);
    ok(hr == S_OK && t, "CreateDesktopWindowTarget %#lx %p\n", hr, t);
    if (!t) goto out;

    /* the result is the IDesktopWindowTarget itself, not only an IInspectable: its own method is callable directly */
    topmost = FALSE;
    hr = t->lpVtbl->get_IsTopmost(t, &topmost);
    ok(hr == S_OK && topmost, "get_IsTopmost %#lx %u\n", hr, topmost);
    hr = t->lpVtbl->get_IsTopmost(t, NULL);
    ok(hr == E_POINTER, "get_IsTopmost(NULL) %#lx\n", hr);

    hr = t->lpVtbl->GetRuntimeClassName(t, &cls);
    ok(hr == S_OK, "GetRuntimeClassName %#lx\n", hr);
    if (hr == S_OK && pRaw && pDel)
    {
        ok(!lstrcmpW(pRaw(cls, NULL), L"Windows.UI.Composition.Desktop.DesktopWindowTarget"), "class %ls\n",
           pRaw(cls, NULL));
        pDel(cls);
    }

    iids = NULL; count = 0;
    hr = t->lpVtbl->GetIids(t, &count, &iids);
    ok(hr == S_OK && iids, "GetIids %#lx\n", hr);
    if (iids)
    {
        ok(HasIid(iids, count, &IID_DesktopTarget), "GetIids lacks IDesktopWindowTarget\n");
        ok(HasIid(iids, count, &IID_Target), "GetIids lacks ICompositionTarget\n");
        ok(HasIid(iids, count, &IID_Closable), "GetIids lacks IClosable\n");
        CoTaskMemFree(iids);
    }

    u1 = (IUnknown *)0x1234;
    hr = QI(t, &IID_Unknown1, (void **)&u1);
    ok(hr == E_NOINTERFACE && u1 == NULL, "QI(unknown IID) %#lx %p\n", hr, u1);

    hr = QI(t, &IID_DesktopTargetInterop, (void **)&ti);
    ok(hr == S_OK && ti, "QI IDesktopWindowTargetInterop %#lx\n", hr);
    if (ti)
    {
        got_hwnd = NULL;
        hr = ti->lpVtbl->get_Hwnd(ti, &got_hwnd);
        ok(hr == S_OK && got_hwnd == hwnd, "get_Hwnd %#lx %p, expected %p\n", hr, got_hwnd, hwnd);
        hr = ti->lpVtbl->get_Hwnd(ti, NULL);
        ok(hr == E_POINTER, "get_Hwnd(NULL) %#lx\n", hr);
        QI(ti, &IID_IUnknown, (void **)&u1);
        QI(t, &IID_IUnknown, (void **)&u2);
        ok(u1 == u2, "interop identity %p vs %p\n", u1, u2);
        REL(u1); REL(u2);
        REL(ti);
    }

    hr = QI(t, &IID_Target, (void **)&ct);
    ok(hr == S_OK && ct, "QI ICompositionTarget %#lx\n", hr);
    hr = QI(t, &IID_CompObject, (void **)&obj);
    ok(hr == S_OK && obj, "QI ICompositionObject %#lx\n", hr);
    if (obj)
    {
        hr = obj->lpVtbl->get_Compositor(obj, &c2);
        ok(hr == S_OK && c2, "get_Compositor %#lx\n", hr);
        if (c2)
        {
            QI(c2, &IID_IUnknown, (void **)&u1);
            QI(Comp, &IID_IUnknown, (void **)&u2);
            ok(u1 == u2, "target's Compositor %p vs %p\n", u1, u2);
            REL(u1); REL(u2); REL(c2);
        }
        REL(obj);
    }
    if (ct)
    {
        got = (WIVisual *)0xdead;
        hr = ct->lpVtbl->get_Root(ct, &got);
        ok(hr == S_OK && got == NULL, "initial Root %#lx %p\n", hr, got);
        v = NewContainer(0, 0, 100, 100);
        if (v)
        {
            vis_ref = RefOf((IUnknown *)v);
            hr = ct->lpVtbl->put_Root(ct, v);
            ok(hr == S_OK, "put_Root %#lx\n", hr);
            got = NULL;
            hr = ct->lpVtbl->get_Root(ct, &got);
            ok(hr == S_OK && got, "get_Root %#lx %p\n", hr, got);
            if (got)
            {
                QI(got, &IID_IUnknown, (void **)&u1);
                QI(v, &IID_IUnknown, (void **)&u2);
                ok(u1 == u2, "Root %p is not the visual %p\n", u1, u2);
                REL(u1); REL(u2); REL(got);
            }
            /* a second target on the same window is not checked: its result is not documented */
            hr = ct->lpVtbl->put_Root(ct, NULL);
            ok(hr == S_OK, "put_Root(NULL) %#lx\n", hr);
            hr = ct->lpVtbl->get_Root(ct, &got);
            ok(hr == S_OK && got == NULL, "Root after NULL %#lx %p\n", hr, got);
            ok(RefOf((IUnknown *)v) == vis_ref, "visual refs %lu, were %lu\n", RefOf((IUnknown *)v), vis_ref);
            /* a target that holds a Root, even a Closed one, frees it with its last reference */
            hr = ct->lpVtbl->put_Root(ct, v);
            ok(hr == S_OK, "put_Root %#lx\n", hr);
            ok(RefOf((IUnknown *)v) == vis_ref + 1, "visual refs %lu while the target holds it, were %lu\n",
               RefOf((IUnknown *)v), vis_ref);
            hr = QI(t, &IID_Closable, (void **)&clo);
            ok(hr == S_OK && clo, "QI IClosable %#lx\n", hr);
            if (clo)
            {
                hr = clo->lpVtbl->Close(clo);
                ok(hr == S_OK, "Close %#lx\n", hr);
                hr = clo->lpVtbl->Close(clo);
                ok(hr == S_OK, "second Close %#lx\n", hr);
                REL(clo);
            }
            REL(ct);
            ct = NULL;
            REL(t);
            t = NULL;
            ok(RefOf((IUnknown *)v) == vis_ref, "visual refs %lu after the target is freed, were %lu\n",
               RefOf((IUnknown *)v), vis_ref);
            REL(v);
        }
        if (ct) REL(ct);
    }
    if (t) REL(t);
    ok(RefOf((IUnknown *)Comp) == comp_ref, "Compositor refs %lu after the target, were %lu\n",
       RefOf((IUnknown *)Comp), comp_ref);

    /* topmost FALSE works as well */
    hr = di->lpVtbl->CreateDesktopWindowTarget(di, hwnd, FALSE, &t2);
    ok(hr == S_OK && t2, "CreateDesktopWindowTarget(topmost FALSE) %#lx %p\n", hr, t2);
    if (t2)
    {
        topmost = TRUE;
        hr = t2->lpVtbl->get_IsTopmost(t2, &topmost);
        ok(hr == S_OK && !topmost, "get_IsTopmost(FALSE) %#lx %u\n", hr, topmost);
        REL(t2);
    }

    /* the second method; Windows documents nothing about it */
    hr = di->lpVtbl->EnsureOnThread(di, GetCurrentThreadId());
    ok(hr == S_OK || hr == E_NOTIMPL, "EnsureOnThread %#lx\n", hr);
out:
    DestroyWindow(hwnd);
    REL(di);
}

typedef struct
{
    ICtlHandler iface;
    LONG ref;
    LONG invoked;
} TestHandler;

static HRESULT STDMETHODCALLTYPE th_QI(ICtlHandler *i, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IUnknown)) { *out = i; i->lpVtbl->AddRef(i); return S_OK; }
    *out = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE th_AddRef(ICtlHandler *i) { return InterlockedIncrement(&((TestHandler *)i)->ref); }
static ULONG STDMETHODCALLTYPE th_Release(ICtlHandler *i) { return InterlockedDecrement(&((TestHandler *)i)->ref); }
static HRESULT STDMETHODCALLTYPE th_Invoke(ICtlHandler *i, void *s, IInspectable *a)
{ InterlockedIncrement(&((TestHandler *)i)->invoked); return S_OK; }
static const ICtlHandlerVtbl th_vtbl = { th_QI, th_AddRef, th_Release, th_Invoke };

typedef struct
{
    ICtlActionHandler iface;
    LONG invoked;
    int status;
    ICtlAction *action;
} TestActionHandler;

static HRESULT STDMETHODCALLTYPE ah_QI(ICtlActionHandler *i, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IUnknown)) { *out = i; return S_OK; }
    *out = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE ah_AddRef(ICtlActionHandler *i) { return 2; }
static ULONG STDMETHODCALLTYPE ah_Release(ICtlActionHandler *i) { return 1; }
static HRESULT STDMETHODCALLTYPE ah_Invoke(ICtlActionHandler *i, ICtlAction *a, int status)
{
    TestActionHandler *h = (TestActionHandler *)i;

    h->invoked++; h->status = status; h->action = a;
    return S_OK;
}
static const ICtlActionHandlerVtbl ah_vtbl = { ah_QI, ah_AddRef, ah_Release, ah_Invoke };

static void TestController(PRO_ACTIVATE pRoActivateInstance, PWCS pWindowsCreateString, PWDS pWindowsDeleteString)
{
    const WCHAR name[] = L"Windows.UI.Composition.Core.CompositorController";
    IInspectable *obj = NULL;
    ICtl *ctl = NULL;
    WICompositor *c1 = NULL, *c2 = NULL;
    WIContainerVisual *cv = NULL;
    ICtlAction *act = NULL;
    ICtlInfo *info = NULL;
    __x_ABI_CWindows_CFoundation_CIClosable *clo = NULL;
    IUnknown *u1 = NULL, *u2 = NULL, *agile = NULL;
    TestHandler h1 = { { &th_vtbl }, 1, 0 }, h2 = { { &th_vtbl }, 1, 0 };
    TestActionHandler ah = { { &ah_vtbl }, 0, -1, NULL };
    CtlToken tok1, tok2, bogus = { 0x7fffffff };
    HSTRING cls = NULL;
    IID *iids = NULL;
    ULONG count = 0, comp_ref;
    UINT32 id;
    int status;
    HRESULT hr, ehr;
    HMODULE combase = GetModuleHandleW(L"combase.dll");
    LPCWSTR (WINAPI *pRaw)(HSTRING, UINT32 *) = combase ? (void *)GetProcAddress(combase, "WindowsGetStringRawBuffer") : NULL;

    hr = pWindowsCreateString(name, lstrlenW(name), &cls);
    ok(hr == S_OK, "WindowsCreateString %#lx\n", hr);
    hr = pRoActivateInstance(cls, &obj);
    pWindowsDeleteString(cls);
    ok(hr == S_OK && obj, "activate CompositorController %#lx %p\n", hr, obj);
    if (!obj) return;

    hr = QI(obj, &IID_Ctl, (void **)&ctl);
    ok(hr == S_OK && ctl, "QI ICompositorController %#lx\n", hr);
    if (!ctl) { REL(obj); return; }
    QI(obj, &IID_IUnknown, (void **)&u1);
    QI(ctl, &IID_IUnknown, (void **)&u2);
    ok(u1 == u2, "controller identity %p vs %p\n", u1, u2);
    REL(u1); REL(u2);

    hr = ctl->lpVtbl->GetIids(ctl, &count, &iids);
    ok(hr == S_OK && iids, "GetIids %#lx\n", hr);
    if (iids)
    {
        ok(HasIid(iids, count, &IID_Ctl), "GetIids lacks ICompositorController\n");
        ok(HasIid(iids, count, &IID_Closable), "GetIids lacks IClosable\n");
        CoTaskMemFree(iids);
    }
    hr = ctl->lpVtbl->GetRuntimeClassName(ctl, &cls);
    ok(hr == S_OK, "GetRuntimeClassName %#lx\n", hr);
    if (hr == S_OK && pRaw)
    {
        ok(!lstrcmpW(pRaw(cls, NULL), name), "class %ls\n", pRaw(cls, NULL));
        pWindowsDeleteString(cls);
    }
    hr = QI(ctl, &IID_AgileObj, (void **)&agile);
    ok(hr == S_OK && agile, "QI IAgileObject %#lx\n", hr);
    if (agile) REL(agile);
    u1 = (IUnknown *)0x1234;
    hr = QI(ctl, &IID_Unknown1, (void **)&u1);
    ok(hr == E_NOINTERFACE && u1 == NULL, "QI(unknown IID) %#lx %p\n", hr, u1);

    /* Compositor */
    hr = ctl->lpVtbl->get_Compositor(ctl, NULL);
    ok(hr == E_POINTER, "get_Compositor(NULL) %#lx\n", hr);
    hr = ctl->lpVtbl->get_Compositor(ctl, &c1);
    ok(hr == S_OK && c1, "get_Compositor %#lx %p\n", hr, c1);
    hr = ctl->lpVtbl->get_Compositor(ctl, &c2);
    ok(hr == S_OK && c2, "get_Compositor again %#lx %p\n", hr, c2);
    if (c1 && c2)
    {
        QI(c1, &IID_IUnknown, (void **)&u1);
        QI(c2, &IID_IUnknown, (void **)&u2);
        ok(u1 == u2, "the controller's Compositor changed: %p vs %p\n", u1, u2);
        REL(u1); REL(u2);
        hr = c1->lpVtbl->CreateContainerVisual(c1, &cv);
        ok(hr == S_OK && cv, "CreateContainerVisual on the controller's Compositor %#lx\n", hr);
        if (cv) REL(cv);
    }
    if (c2) REL(c2);

    /* Commit and EnsurePreviousCommitCompletedAsync */
    hr = ctl->lpVtbl->Commit(ctl);
    ok(hr == S_OK, "Commit %#lx\n", hr);
    hr = ctl->lpVtbl->EnsurePreviousCommitCompletedAsync(ctl, NULL);
    ok(hr == E_POINTER, "EnsurePreviousCommitCompletedAsync(NULL) %#lx\n", hr);
    hr = ctl->lpVtbl->EnsurePreviousCommitCompletedAsync(ctl, &act);
    ok(hr == S_OK && act, "EnsurePreviousCommitCompletedAsync %#lx %p\n", hr, act);
    if (act)
    {
        hr = QI(act, &IID_CtlInfo, (void **)&info);
        ok(hr == S_OK && info, "QI IAsyncInfo %#lx\n", hr);
        if (info)
        {
            status = -1;
            hr = info->lpVtbl->get_Status(info, &status);
            ok(hr == S_OK && status == 1, "AsyncStatus %#lx %d, expected Completed\n", hr, status);
            id = 0xdead;
            hr = info->lpVtbl->get_Id(info, &id);
            ok(hr == S_OK, "get_Id %#lx\n", hr);
            ehr = E_FAIL;
            hr = info->lpVtbl->get_ErrorCode(info, &ehr);
            ok(hr == S_OK && ehr == S_OK, "get_ErrorCode %#lx %#lx\n", hr, ehr);
            REL(info);
        }
        hr = act->lpVtbl->GetResults(act);
        ok(hr == S_OK, "GetResults %#lx\n", hr);
        hr = act->lpVtbl->put_Completed(act, &ah.iface);
        ok(hr == S_OK, "put_Completed %#lx\n", hr);
        ok(ah.invoked == 1 && ah.status == 1 && ah.action == act, "completed handler: %ld calls, status %d\n",
           ah.invoked, ah.status);
        hr = act->lpVtbl->put_Completed(act, &ah.iface);
        ok(hr == E_ILLEGAL_DELEGATE_ASSIGNMENT, "second put_Completed %#lx\n", hr);
        REL(act);
    }

    /* CommitNeeded */
    tok1.value = tok2.value = 0;
    hr = ctl->lpVtbl->add_CommitNeeded(ctl, NULL, &tok1);
    ok(hr == E_INVALIDARG, "add_CommitNeeded(NULL handler) %#lx\n", hr);
    hr = ctl->lpVtbl->add_CommitNeeded(ctl, &h1.iface, &tok1);
    ok(hr == S_OK && tok1.value != 0, "add_CommitNeeded %#lx token %I64d\n", hr, tok1.value);
    hr = ctl->lpVtbl->add_CommitNeeded(ctl, &h2.iface, &tok2);
    ok(hr == S_OK && tok2.value != 0 && tok2.value != tok1.value, "second add_CommitNeeded %#lx tokens %I64d %I64d\n", hr,
       tok1.value, tok2.value);
    ok(h1.ref == 2 && h2.ref == 2, "handler refs %ld %ld after add\n", h1.ref, h2.ref);
    hr = ctl->lpVtbl->remove_CommitNeeded(ctl, tok1);
    ok(hr == S_OK, "remove_CommitNeeded %#lx\n", hr);
    ok(h1.ref == 1 && h2.ref == 2, "handler refs %ld %ld after remove\n", h1.ref, h2.ref);
    hr = ctl->lpVtbl->remove_CommitNeeded(ctl, tok1);
    ok(hr == S_OK, "remove_CommitNeeded twice %#lx\n", hr);
    hr = ctl->lpVtbl->remove_CommitNeeded(ctl, bogus);
    ok(hr == S_OK, "remove_CommitNeeded(unknown token) %#lx\n", hr);
    ok(h1.ref == 1 && h2.ref == 2, "handler refs %ld %ld after the bogus removals\n", h1.ref, h2.ref);

    /* Close, then freeing: the Compositor the controller held and the handlers still registered go away */
    comp_ref = 0;
    hr = ctl->lpVtbl->get_Compositor(ctl, &c2);
    if (hr == S_OK && c2)
    {
        comp_ref = RefOf((IUnknown *)c2);
        ok(comp_ref == 3, "Compositor refs %lu while the controller lives\n", comp_ref);
    }
    hr = QI(ctl, &IID_Closable, (void **)&clo);
    ok(hr == S_OK && clo, "QI IClosable %#lx\n", hr);
    if (clo)
    {
        hr = clo->lpVtbl->Close(clo);
        ok(hr == S_OK, "Close %#lx\n", hr);
        hr = clo->lpVtbl->Close(clo);
        ok(hr == S_OK, "second Close %#lx\n", hr);
        REL(clo);
    }
    REL(ctl);
    REL(obj);
    ok(h2.ref == 1, "handler ref %ld after the controller is freed, expected 1\n", h2.ref);
    if (c2)
    {
        ok(RefOf((IUnknown *)c2) == comp_ref - 1, "Compositor refs %lu after the controller is freed, were %lu\n",
           RefOf((IUnknown *)c2), comp_ref);
        REL(c2);
    }
    if (c1) REL(c1);
}


/*
 * Windows.UI.Composition.Interactions.VisualInteractionSource: IIDs, slot order and signatures from microsoft/windows-rs
 * (MIT OR Apache-2.0), the published `windows` crate 0.62.2 (vcs commit 32c3144490c016fe496a0aed769bce60987a2e9d,
 * path crates/libs/windows/src/Windows/UI/Composition/Interactions/mod.rs; the rdl at
 * metadata/winrt/Windows.UI.Composition.Interactions.rdl, commit 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0).
 * Documented behaviour only (learn.microsoft.com): Create(Visual) is static, Source returns the visual, rails are
 * on by default, DeltaPosition defaults to 0, Scale to 1.
 */
typedef struct IVis IVis;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IVis *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IVis *This);
    ULONG (STDMETHODCALLTYPE *Release)(IVis *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IVis *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IVis *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IVis *This, int *level);
    HRESULT (STDMETHODCALLTYPE *get_RailsX)(IVis *This, BOOLEAN *v);
    HRESULT (STDMETHODCALLTYPE *put_RailsX)(IVis *This, BOOLEAN v);
    HRESULT (STDMETHODCALLTYPE *get_RailsY)(IVis *This, BOOLEAN *v);
    HRESULT (STDMETHODCALLTYPE *put_RailsY)(IVis *This, BOOLEAN v);
    HRESULT (STDMETHODCALLTYPE *get_Redirect)(IVis *This, INT32 *v);
    HRESULT (STDMETHODCALLTYPE *put_Redirect)(IVis *This, INT32 v);
    HRESULT (STDMETHODCALLTYPE *get_PXChain)(IVis *This, INT32 *v);
    HRESULT (STDMETHODCALLTYPE *put_PXChain)(IVis *This, INT32 v);
    HRESULT (STDMETHODCALLTYPE *get_PXMode)(IVis *This, INT32 *v);
    HRESULT (STDMETHODCALLTYPE *put_PXMode)(IVis *This, INT32 v);
    HRESULT (STDMETHODCALLTYPE *get_PYChain)(IVis *This, INT32 *v);
    HRESULT (STDMETHODCALLTYPE *put_PYChain)(IVis *This, INT32 v);
    HRESULT (STDMETHODCALLTYPE *get_PYMode)(IVis *This, INT32 *v);
    HRESULT (STDMETHODCALLTYPE *put_PYMode)(IVis *This, INT32 v);
    HRESULT (STDMETHODCALLTYPE *get_SChain)(IVis *This, INT32 *v);
    HRESULT (STDMETHODCALLTYPE *put_SChain)(IVis *This, INT32 v);
    HRESULT (STDMETHODCALLTYPE *get_SMode)(IVis *This, INT32 *v);
    HRESULT (STDMETHODCALLTYPE *put_SMode)(IVis *This, INT32 v);
    HRESULT (STDMETHODCALLTYPE *get_Source)(IVis *This, WIVisual **v);
    HRESULT (STDMETHODCALLTYPE *TryRedirect)(IVis *This, void *pp);
} IVisVtbl;
struct IVis { const IVisVtbl *lpVtbl; };

typedef struct IVis2 IVis2;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IVis2 *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IVis2 *This);
    ULONG (STDMETHODCALLTYPE *Release)(IVis2 *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IVis2 *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IVis2 *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IVis2 *This, int *level);
    HRESULT (STDMETHODCALLTYPE *get_DeltaPosition)(IVis2 *This, float *xyz);
    HRESULT (STDMETHODCALLTYPE *get_DeltaScale)(IVis2 *This, float *v);
    HRESULT (STDMETHODCALLTYPE *get_Position)(IVis2 *This, float *xyz);
    HRESULT (STDMETHODCALLTYPE *get_PositionVelocity)(IVis2 *This, float *xyz);
    HRESULT (STDMETHODCALLTYPE *get_Scale)(IVis2 *This, float *v);
    HRESULT (STDMETHODCALLTYPE *get_ScaleVelocity)(IVis2 *This, float *v);
} IVis2Vtbl;
struct IVis2 { const IVis2Vtbl *lpVtbl; };

typedef struct IVisStatics IVisStatics;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IVisStatics *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IVisStatics *This);
    ULONG (STDMETHODCALLTYPE *Release)(IVisStatics *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IVisStatics *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IVisStatics *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IVisStatics *This, int *level);
    HRESULT (STDMETHODCALLTYPE *Create)(IVisStatics *This, WIVisual *source, IVis **result);
} IVisStaticsVtbl;
struct IVisStatics { const IVisStaticsVtbl *lpVtbl; };

static const GUID IID_IVis = {0xca0e8a86, 0xd8d6, 0x4111, {0xb0, 0x88, 0x70, 0x34, 0x7b, 0x2b, 0xd0, 0xed}};
static const GUID IID_IVis2 = {0xaa914893, 0xa73c, 0x414d, {0x80, 0xd0, 0x24, 0x9b, 0xad, 0x2f, 0xbd, 0x93}};
static const GUID IID_IVis3 = {0xd941ef2a, 0x0d5c, 0x4057, {0x92, 0xd7, 0xc9, 0x71, 0x15, 0x33, 0x20, 0x4f}};
static const GUID IID_IVisStatics = {0x369965e1, 0x8645, 0x4f75, {0xba, 0x00, 0x64, 0x79, 0xcd, 0x10, 0xc8, 0xe6}};
static const GUID IID_ICompInteractionSource = {0x043b2431, 0x06e3, 0x495a, {0xba, 0x54, 0x40, 0x9f, 0x00, 0x17, 0xfa, 0xc0}};

/*
 * Windows.UI.Composition.IVisual2: IID, slot order and signatures from microsoft/windows-rs (MIT OR Apache-2.0), the
 * published `windows` crate 0.62.2 (vcs commit 32c3144490c016fe496a0aed769bce60987a2e9d, src/Windows/UI/Composition/mod.rs
 * IVisual2_Vtbl; metadata/winrt/Windows.UI.Composition.rdl at commit 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0):
 * 6/7 ParentForTransform, 8/9 RelativeOffsetAdjustment (Vector3), 10/11 RelativeSizeAdjustment (Vector2).
 */
typedef struct { float x, y, z; } V3T;
typedef struct { float x, y; } V2T;
typedef struct IVisual2T IVisual2T;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IVisual2T *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IVisual2T *This);
    ULONG (STDMETHODCALLTYPE *Release)(IVisual2T *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IVisual2T *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IVisual2T *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IVisual2T *This, int *level);
    HRESULT (STDMETHODCALLTYPE *get_ParentForTransform)(IVisual2T *This, WIVisual **v);
    HRESULT (STDMETHODCALLTYPE *put_ParentForTransform)(IVisual2T *This, WIVisual *v);
    HRESULT (STDMETHODCALLTYPE *get_RelOffset)(IVisual2T *This, float *xyz);
    HRESULT (STDMETHODCALLTYPE *put_RelOffset)(IVisual2T *This, V3T v);
    HRESULT (STDMETHODCALLTYPE *get_RelSize)(IVisual2T *This, float *xy);
    HRESULT (STDMETHODCALLTYPE *put_RelSize)(IVisual2T *This, V2T v);
} IVisual2TVtbl;
struct IVisual2T { const IVisual2TVtbl *lpVtbl; };
static const GUID IID_IVisual2T = {0x3052b611, 0x56c3, 0x4c3e, {0x8b, 0xf3, 0xf6, 0xe1, 0xad, 0x47, 0x3f, 0x06}};

static void TestVisual2(void)
{
    WIContainerVisual *cv = NULL, *other = NULL;
    WISpriteVisual *sp = NULL;
    WIVisual *v = NULL, *ov = NULL, *got = NULL;
    IVisual2T *v2 = NULL, *s2 = NULL;
    IUnknown *u1 = NULL, *u2 = NULL;
    ULONG oref;
    float f[3];
    V3T o3 = { 0.5f, 0.25f, 2.0f };
    V2T o2 = { 1.0f, 0.5f };
    HRESULT hr;

    hr = Comp->lpVtbl->CreateContainerVisual(Comp, &cv);
    ok(hr == S_OK && cv, "CreateContainerVisual %#lx\n", hr);
    hr = Comp->lpVtbl->CreateContainerVisual(Comp, &other);
    ok(hr == S_OK && other, "CreateContainerVisual %#lx\n", hr);
    hr = Comp->lpVtbl->CreateSpriteVisual(Comp, &sp);
    ok(hr == S_OK && sp, "CreateSpriteVisual %#lx\n", hr);
    if (!cv || !other || !sp) goto out;
    QI(cv, &IID___x_ABI_CWindows_CUI_CComposition_CIVisual, (void **)&v);
    QI(other, &IID___x_ABI_CWindows_CUI_CComposition_CIVisual, (void **)&ov);
    hr = QI(cv, &IID_IVisual2T, (void **)&v2);
    ok(hr == S_OK && v2, "QI IVisual2 on ContainerVisual %#lx\n", hr);
    hr = QI(sp, &IID_IVisual2T, (void **)&s2);
    ok(hr == S_OK && s2, "QI IVisual2 on SpriteVisual %#lx\n", hr);
    if (!v2) goto out;
    QI(v2, &IID_IUnknown, (void **)&u1);
    QI(cv, &IID_IUnknown, (void **)&u2);
    ok(u1 == u2, "IVisual2 identity %p vs %p\n", u1, u2);
    REL(u1); REL(u2);

    got = (WIVisual *)0x1234;
    hr = v2->lpVtbl->get_ParentForTransform(v2, &got);
    ok(hr == S_OK && got == NULL, "ParentForTransform default %#lx %p\n", hr, got);
    hr = v2->lpVtbl->get_ParentForTransform(v2, NULL);
    ok(hr == E_POINTER, "get_ParentForTransform(NULL) %#lx\n", hr);
    f[0] = f[1] = f[2] = 9.0f;
    hr = v2->lpVtbl->get_RelOffset(v2, f);
    ok(hr == S_OK && f[0] == 0.0f && f[1] == 0.0f && f[2] == 0.0f, "RelativeOffsetAdjustment default %#lx %g %g %g\n", hr, f[0], f[1], f[2]);
    f[0] = f[1] = 9.0f;
    hr = v2->lpVtbl->get_RelSize(v2, f);
    ok(hr == S_OK && f[0] == 0.0f && f[1] == 0.0f, "RelativeSizeAdjustment default %#lx %g %g\n", hr, f[0], f[1]);

    hr = v2->lpVtbl->put_RelOffset(v2, o3);
    ok(hr == S_OK, "put_RelativeOffsetAdjustment %#lx\n", hr);
    f[0] = f[1] = f[2] = 0.0f;
    hr = v2->lpVtbl->get_RelOffset(v2, f);
    ok(hr == S_OK && f[0] == 0.5f && f[1] == 0.25f && f[2] == 2.0f, "RelativeOffsetAdjustment %#lx %g %g %g\n", hr, f[0], f[1], f[2]);
    hr = v2->lpVtbl->put_RelSize(v2, o2);
    ok(hr == S_OK, "put_RelativeSizeAdjustment %#lx\n", hr);
    f[0] = f[1] = 0.0f;
    hr = v2->lpVtbl->get_RelSize(v2, f);
    ok(hr == S_OK && f[0] == 1.0f && f[1] == 0.5f, "RelativeSizeAdjustment %#lx %g %g\n", hr, f[0], f[1]);

    /* ParentForTransform keeps a reference to the other visual until it is replaced or the visual is freed */
    oref = RefOf((IUnknown *)ov);
    hr = v2->lpVtbl->put_ParentForTransform(v2, ov);
    ok(hr == S_OK, "put_ParentForTransform %#lx\n", hr);
    ok(RefOf((IUnknown *)ov) == oref + 1, "other visual refs %lu, were %lu\n", RefOf((IUnknown *)ov), oref);
    hr = v2->lpVtbl->get_ParentForTransform(v2, &got);
    ok(hr == S_OK && got, "get_ParentForTransform %#lx %p\n", hr, got);
    if (got)
    {
        QI(got, &IID_IUnknown, (void **)&u1);
        QI(ov, &IID_IUnknown, (void **)&u2);
        ok(u1 == u2, "ParentForTransform is not the visual: %p vs %p\n", u1, u2);
        REL(u1); REL(u2);
        REL(got);
    }
    hr = v2->lpVtbl->put_ParentForTransform(v2, NULL);
    ok(hr == S_OK, "put_ParentForTransform(NULL) %#lx\n", hr);
    ok(RefOf((IUnknown *)ov) == oref, "other visual refs %lu after NULL, were %lu\n", RefOf((IUnknown *)ov), oref);
    hr = v2->lpVtbl->put_ParentForTransform(v2, ov);
    ok(hr == S_OK, "put_ParentForTransform again %#lx\n", hr);
    REL(v2);
    v2 = NULL;
    REL(cv);
    cv = NULL;
    REL(v);
    v = NULL;
    ok(RefOf((IUnknown *)ov) == oref, "other visual refs %lu after the visual is freed, were %lu\n", RefOf((IUnknown *)ov), oref);
out:
    if (s2) REL(s2);
    if (v2) REL(v2);
    if (v) REL(v);
    if (ov) REL(ov);
    if (cv) REL(cv);
    if (other) REL(other);
    if (sp) REL(sp);
}

/*
 * ICompositor2 (guid 735081dc-5e24-45da-a38f-e32cc349a9a0, slots 6.. CreateAmbientLight, CreateAnimationGroup,
 * CreateBackdropBrush, CreateDistantLight, CreateDropShadow, CreateImplicitAnimationCollection, CreateLayerVisual, ...)
 * and ICompositionSurfaceBrush3 (guid 550bb289-1fe0-42e5-8195-1eefa87ff08e, 6/7 get/put SnapToPixels): microsoft/windows-rs
 * (MIT OR Apache-2.0), the published `windows` crate 0.62.2 (vcs commit 32c3144490c016fe496a0aed769bce60987a2e9d,
 * src/Windows/UI/Composition/mod.rs). The members of ICompositor2 create classes that are not available yet: S_OK
 * (Windows) or E_NOTIMPL (here) is accepted.
 */
typedef struct ICompositor2T ICompositor2T;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICompositor2T *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICompositor2T *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICompositor2T *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(ICompositor2T *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(ICompositor2T *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(ICompositor2T *This, int *level);
    HRESULT (STDMETHODCALLTYPE *CreateAmbientLight)(ICompositor2T *This, IUnknown **result);
    HRESULT (STDMETHODCALLTYPE *CreateAnimationGroup)(ICompositor2T *This, IUnknown **result);
    HRESULT (STDMETHODCALLTYPE *CreateBackdropBrush)(ICompositor2T *This, IUnknown **result);
    HRESULT (STDMETHODCALLTYPE *CreateDistantLight)(ICompositor2T *This, IUnknown **result);
    HRESULT (STDMETHODCALLTYPE *CreateDropShadow)(ICompositor2T *This, IUnknown **result);
    HRESULT (STDMETHODCALLTYPE *CreateImplicitAnimationCollection)(ICompositor2T *This, IUnknown **result);
    HRESULT (STDMETHODCALLTYPE *CreateLayerVisual)(ICompositor2T *This, IUnknown **result);
    HRESULT (STDMETHODCALLTYPE *CreateMaskBrush)(ICompositor2T *This, IUnknown **result);
    HRESULT (STDMETHODCALLTYPE *CreateNineGridBrush)(ICompositor2T *This, IUnknown **result);
} ICompositor2TVtbl;
struct ICompositor2T { const ICompositor2TVtbl *lpVtbl; };
static const GUID IID_ICompositor2T = {0x735081dc, 0x5e24, 0x45da, {0xa3, 0x8f, 0xe3, 0x2c, 0xc3, 0x49, 0xa9, 0xa0}};

typedef struct ISurfBrush3T ISurfBrush3T;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ISurfBrush3T *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ISurfBrush3T *This);
    ULONG (STDMETHODCALLTYPE *Release)(ISurfBrush3T *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(ISurfBrush3T *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(ISurfBrush3T *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(ISurfBrush3T *This, int *level);
    HRESULT (STDMETHODCALLTYPE *get_SnapToPixels)(ISurfBrush3T *This, BOOLEAN *v);
    HRESULT (STDMETHODCALLTYPE *put_SnapToPixels)(ISurfBrush3T *This, BOOLEAN v);
} ISurfBrush3TVtbl;
struct ISurfBrush3T { const ISurfBrush3TVtbl *lpVtbl; };
static const GUID IID_ISurfBrush3T = {0x550bb289, 0x1fe0, 0x42e5, {0x81, 0x95, 0x1e, 0xef, 0xa8, 0x7f, 0xf0, 0x8e}};

static void TestCompositor2AndBrush3(void)
{
    ICompositor2T *c2 = NULL;
    ISurfBrush3T *b3 = NULL;
    WICompositionSurfaceBrush *brush = NULL;
    IUnknown *u1 = NULL, *u2 = NULL, *made;
    IID *iids = NULL;
    ULONG count = 0;
    BOOLEAN b;
    HRESULT hr;

    hr = QI(Comp, &IID_ICompositor2T, (void **)&c2);
    ok(hr == S_OK && c2, "QI ICompositor2 %#lx\n", hr);
    if (c2)
    {
        QI(c2, &IID_IUnknown, (void **)&u1);
        QI(Comp, &IID_IUnknown, (void **)&u2);
        ok(u1 == u2, "ICompositor2 identity %p vs %p\n", u1, u2);
        REL(u1); REL(u2);
        hr = c2->lpVtbl->GetIids(c2, &count, &iids);
        ok(hr == S_OK && iids, "GetIids %#lx\n", hr);
        if (iids)
        {
            ok(HasIid(iids, count, &IID_ICompositor2T), "GetIids lacks ICompositor2\n");
            CoTaskMemFree(iids);
        }
        made = (IUnknown *)0x1234;
        hr = c2->lpVtbl->CreateLayerVisual(c2, &made);
        ok(hr == S_OK || hr == E_NOTIMPL, "CreateLayerVisual %#lx\n", hr);
        if (hr == S_OK && made) REL(made);
        else ok(made == NULL, "CreateLayerVisual failed but returned %p\n", made);
        made = (IUnknown *)0x1234;
        hr = c2->lpVtbl->CreateBackdropBrush(c2, &made);
        ok(hr == S_OK || hr == E_NOTIMPL, "CreateBackdropBrush %#lx\n", hr);
        if (hr == S_OK && made) REL(made);
        else ok(made == NULL, "CreateBackdropBrush failed but returned %p\n", made);
        REL(c2);
    }

    hr = Comp->lpVtbl->CreateSurfaceBrush(Comp, &brush);
    ok(hr == S_OK && brush, "CreateSurfaceBrush %#lx\n", hr);
    if (!brush) return;
    hr = QI(brush, &IID_ISurfBrush3T, (void **)&b3);
    ok(hr == S_OK && b3, "QI ICompositionSurfaceBrush3 %#lx\n", hr);
    if (b3)
    {
        QI(b3, &IID_IUnknown, (void **)&u1);
        QI(brush, &IID_IUnknown, (void **)&u2);
        ok(u1 == u2, "ICompositionSurfaceBrush3 identity %p vs %p\n", u1, u2);
        REL(u1); REL(u2);
        hr = b3->lpVtbl->get_SnapToPixels(b3, NULL);
        ok(hr == E_POINTER, "get_SnapToPixels(NULL) %#lx\n", hr);
        hr = b3->lpVtbl->put_SnapToPixels(b3, TRUE);
        ok(hr == S_OK, "put_SnapToPixels %#lx\n", hr);
        b = FALSE;
        hr = b3->lpVtbl->get_SnapToPixels(b3, &b);
        ok(hr == S_OK && b, "SnapToPixels after put(TRUE) %#lx %u\n", hr, b);
        hr = b3->lpVtbl->put_SnapToPixels(b3, FALSE);
        ok(hr == S_OK, "put_SnapToPixels(FALSE) %#lx\n", hr);
        b = TRUE;
        hr = b3->lpVtbl->get_SnapToPixels(b3, &b);
        ok(hr == S_OK && !b, "SnapToPixels after put(FALSE) %#lx %u\n", hr, b);
        REL(b3);
    }
    REL(brush);
}

/*
 * ICompositionNineGridBrush (guid f25154e4-bc8c-4be7-b80f-8685b83c0186; slots after IInspectable: 6/7 BottomInset,
 * 8/9 BottomInsetScale, 10/11 IsCenterHollow, 12/13 LeftInset, 14/15 LeftInsetScale, 16/17 RightInset,
 * 18/19 RightInsetScale, 20/21 Source, 22/23 TopInset, 24/25 TopInsetScale, 26 SetInsets, 27 SetInsetsWithValues
 * (left, top, right, bottom), 28 SetInsetScales, 29 SetInsetScalesWithValues): microsoft/windows-rs (MIT OR
 * Apache-2.0), the published `windows` crate 0.62.2 (vcs commit 32c3144490c016fe496a0aed769bce60987a2e9d,
 * src/Windows/UI/Composition/mod.rs). Defaults from learn.microsoft.com (windows.ui.composition.compositionninegridbrush
 * members): insets 0, inset scales 1.
 */
typedef struct INineGridT INineGridT;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(INineGridT *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(INineGridT *This);
    ULONG (STDMETHODCALLTYPE *Release)(INineGridT *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(INineGridT *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(INineGridT *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(INineGridT *This, int *level);
    HRESULT (STDMETHODCALLTYPE *get_BottomInset)(INineGridT *This, float *v);
    HRESULT (STDMETHODCALLTYPE *put_BottomInset)(INineGridT *This, float v);
    HRESULT (STDMETHODCALLTYPE *get_BottomInsetScale)(INineGridT *This, float *v);
    HRESULT (STDMETHODCALLTYPE *put_BottomInsetScale)(INineGridT *This, float v);
    HRESULT (STDMETHODCALLTYPE *get_IsCenterHollow)(INineGridT *This, BOOLEAN *v);
    HRESULT (STDMETHODCALLTYPE *put_IsCenterHollow)(INineGridT *This, BOOLEAN v);
    HRESULT (STDMETHODCALLTYPE *get_LeftInset)(INineGridT *This, float *v);
    HRESULT (STDMETHODCALLTYPE *put_LeftInset)(INineGridT *This, float v);
    HRESULT (STDMETHODCALLTYPE *get_LeftInsetScale)(INineGridT *This, float *v);
    HRESULT (STDMETHODCALLTYPE *put_LeftInsetScale)(INineGridT *This, float v);
    HRESULT (STDMETHODCALLTYPE *get_RightInset)(INineGridT *This, float *v);
    HRESULT (STDMETHODCALLTYPE *put_RightInset)(INineGridT *This, float v);
    HRESULT (STDMETHODCALLTYPE *get_RightInsetScale)(INineGridT *This, float *v);
    HRESULT (STDMETHODCALLTYPE *put_RightInsetScale)(INineGridT *This, float v);
    HRESULT (STDMETHODCALLTYPE *get_Source)(INineGridT *This, WICompositionBrush **v);
    HRESULT (STDMETHODCALLTYPE *put_Source)(INineGridT *This, WICompositionBrush *v);
    HRESULT (STDMETHODCALLTYPE *get_TopInset)(INineGridT *This, float *v);
    HRESULT (STDMETHODCALLTYPE *put_TopInset)(INineGridT *This, float v);
    HRESULT (STDMETHODCALLTYPE *get_TopInsetScale)(INineGridT *This, float *v);
    HRESULT (STDMETHODCALLTYPE *put_TopInsetScale)(INineGridT *This, float v);
    HRESULT (STDMETHODCALLTYPE *SetInsets)(INineGridT *This, float inset);
    HRESULT (STDMETHODCALLTYPE *SetInsetsWithValues)(INineGridT *This, float l, float t, float r, float b);
    HRESULT (STDMETHODCALLTYPE *SetInsetScales)(INineGridT *This, float scale);
    HRESULT (STDMETHODCALLTYPE *SetInsetScalesWithValues)(INineGridT *This, float l, float t, float r, float b);
} INineGridTVtbl;
struct INineGridT { const INineGridTVtbl *lpVtbl; };
static const GUID IID_INineGridT = {0xf25154e4, 0xbc8c, 0x4be7, {0xb8, 0x0f, 0x86, 0x85, 0xb8, 0x3c, 0x01, 0x86}};

static void Inset4(INineGridT *g, const char *what, float l, float t, float r, float b, BOOL scale)
{
    float v[4] = {-1, -1, -1, -1};
    HRESULT hr[4];

    if (scale)
    {
        hr[0] = g->lpVtbl->get_LeftInsetScale(g, &v[0]); hr[1] = g->lpVtbl->get_TopInsetScale(g, &v[1]);
        hr[2] = g->lpVtbl->get_RightInsetScale(g, &v[2]); hr[3] = g->lpVtbl->get_BottomInsetScale(g, &v[3]);
    }
    else
    {
        hr[0] = g->lpVtbl->get_LeftInset(g, &v[0]); hr[1] = g->lpVtbl->get_TopInset(g, &v[1]);
        hr[2] = g->lpVtbl->get_RightInset(g, &v[2]); hr[3] = g->lpVtbl->get_BottomInset(g, &v[3]);
    }
    ok(hr[0] == S_OK && hr[1] == S_OK && hr[2] == S_OK && hr[3] == S_OK, "%s getters %#lx %#lx %#lx %#lx\n",
       what, hr[0], hr[1], hr[2], hr[3]);
    ok(v[0] == l && v[1] == t && v[2] == r && v[3] == b, "%s l,t,r,b = %g,%g,%g,%g, expected %g,%g,%g,%g\n",
       what, v[0], v[1], v[2], v[3], l, t, r, b);
}

static void TestNineGridBrush(void)
{
    ICompositor2T *c2 = NULL;
    INineGridT *g = NULL;
    IUnknown *made = (IUnknown *)0x1234, *u1 = NULL, *u2 = NULL;
    WICompositionBrush *base = NULL, *got = NULL, *other = NULL;
    WICompositionColorBrush *cb = NULL, *cb2 = NULL;
    WISpriteVisual *sp = NULL;
    IID *iids = NULL;
    ULONG count = 0, oref;
    BOOLEAN hollow;
    float f;
    HRESULT hr;

    hr = QI(Comp, &IID_ICompositor2T, (void **)&c2);
    ok(hr == S_OK && c2, "QI ICompositor2 %#lx\n", hr);
    if (!c2) return;
    hr = c2->lpVtbl->CreateNineGridBrush(c2, NULL);
    ok(hr == E_POINTER, "CreateNineGridBrush(NULL) %#lx\n", hr);
    hr = c2->lpVtbl->CreateNineGridBrush(c2, &made);
    ok(hr == S_OK && made, "CreateNineGridBrush %#lx %p\n", hr, made);
    REL(c2);
    if (hr != S_OK || !made) return;
    hr = QI(made, &IID_INineGridT, (void **)&g);
    ok(hr == S_OK && g, "QI ICompositionNineGridBrush %#lx\n", hr);
    hr = QI(made, &IID_Brush, (void **)&base);
    ok(hr == S_OK && base, "QI ICompositionBrush %#lx\n", hr);
    if (!g || !base) goto out;

    QI(g, &IID_IUnknown, (void **)&u1);
    QI(base, &IID_IUnknown, (void **)&u2);
    ok(u1 == u2, "identity %p vs %p\n", u1, u2);
    REL(u1); REL(u2);
    hr = g->lpVtbl->GetIids(g, &count, &iids);
    ok(hr == S_OK && iids, "GetIids %#lx\n", hr);
    if (iids)
    {
        ok(HasIid(iids, count, &IID_INineGridT), "GetIids lacks ICompositionNineGridBrush\n");
        ok(HasIid(iids, count, &IID_Brush), "GetIids lacks ICompositionBrush\n");
        CoTaskMemFree(iids);
    }

    /* documented defaults: insets 0, inset scales 1, no Source */
    Inset4(g, "default insets", 0, 0, 0, 0, FALSE);
    Inset4(g, "default scales", 1, 1, 1, 1, TRUE);
    hr = g->lpVtbl->get_Source(g, &got);
    ok(hr == S_OK && !got, "default Source %#lx %p\n", hr, got);
    hr = g->lpVtbl->get_LeftInset(g, NULL);
    ok(hr == E_POINTER, "get_LeftInset(NULL) %#lx\n", hr);
    hr = g->lpVtbl->get_IsCenterHollow(g, NULL);
    ok(hr == E_POINTER, "get_IsCenterHollow(NULL) %#lx\n", hr);
    hr = g->lpVtbl->get_Source(g, NULL);
    ok(hr == E_POINTER, "get_Source(NULL) %#lx\n", hr);

    /* each pair stores its own value */
    ok(g->lpVtbl->put_LeftInset(g, 1.5f) == S_OK, "put_LeftInset\n");
    ok(g->lpVtbl->put_TopInset(g, 2.5f) == S_OK, "put_TopInset\n");
    ok(g->lpVtbl->put_RightInset(g, 3.5f) == S_OK, "put_RightInset\n");
    ok(g->lpVtbl->put_BottomInset(g, 4.5f) == S_OK, "put_BottomInset\n");
    Inset4(g, "put insets", 1.5f, 2.5f, 3.5f, 4.5f, FALSE);
    Inset4(g, "scales untouched by insets", 1, 1, 1, 1, TRUE);
    ok(g->lpVtbl->put_LeftInsetScale(g, 2) == S_OK, "put_LeftInsetScale\n");
    ok(g->lpVtbl->put_TopInsetScale(g, 3) == S_OK, "put_TopInsetScale\n");
    ok(g->lpVtbl->put_RightInsetScale(g, 4) == S_OK, "put_RightInsetScale\n");
    ok(g->lpVtbl->put_BottomInsetScale(g, 5) == S_OK, "put_BottomInsetScale\n");
    Inset4(g, "put scales", 2, 3, 4, 5, TRUE);
    Inset4(g, "insets untouched by scales", 1.5f, 2.5f, 3.5f, 4.5f, FALSE);

    /* the setters: one value for all four, or left, top, right, bottom */
    ok(g->lpVtbl->SetInsets(g, 7) == S_OK, "SetInsets\n");
    Inset4(g, "SetInsets(7)", 7, 7, 7, 7, FALSE);
    ok(g->lpVtbl->SetInsetsWithValues(g, 1, 2, 3, 4) == S_OK, "SetInsetsWithValues\n");
    Inset4(g, "SetInsetsWithValues(1,2,3,4)", 1, 2, 3, 4, FALSE);
    ok(g->lpVtbl->SetInsetScales(g, 0.5f) == S_OK, "SetInsetScales\n");
    Inset4(g, "SetInsetScales(0.5)", 0.5f, 0.5f, 0.5f, 0.5f, TRUE);
    ok(g->lpVtbl->SetInsetScalesWithValues(g, 5, 6, 7, 8) == S_OK, "SetInsetScalesWithValues\n");
    Inset4(g, "SetInsetScalesWithValues(5,6,7,8)", 5, 6, 7, 8, TRUE);
    Inset4(g, "insets untouched by SetInsetScales*", 1, 2, 3, 4, FALSE);
    f = -1;
    g->lpVtbl->get_BottomInset(g, &f);
    ok(f == 4, "BottomInset %g\n", f);

    /* IsCenterHollow: FIXME the default is undocumented, only the round trip is checked */
    ok(g->lpVtbl->put_IsCenterHollow(g, TRUE) == S_OK, "put_IsCenterHollow(TRUE)\n");
    hollow = FALSE;
    hr = g->lpVtbl->get_IsCenterHollow(g, &hollow);
    ok(hr == S_OK && hollow, "IsCenterHollow after TRUE %#lx %u\n", hr, hollow);
    ok(g->lpVtbl->put_IsCenterHollow(g, FALSE) == S_OK, "put_IsCenterHollow(FALSE)\n");
    hollow = TRUE;
    hr = g->lpVtbl->get_IsCenterHollow(g, &hollow);
    ok(hr == S_OK && !hollow, "IsCenterHollow after FALSE %#lx %u\n", hr, hollow);

    /* Source: a color brush, kept with a reference, replaced, cleared */
    hr = Comp->lpVtbl->CreateColorBrush(Comp, &cb);
    ok(hr == S_OK && cb, "CreateColorBrush %#lx\n", hr);
    hr = Comp->lpVtbl->CreateColorBrush(Comp, &cb2);
    ok(hr == S_OK && cb2, "CreateColorBrush 2 %#lx\n", hr);
    if (!cb || !cb2) goto out;
    QI(cb, &IID_Brush, (void **)&other);
    oref = RefOf((IUnknown *)cb);
    hr = g->lpVtbl->put_Source(g, other);
    ok(hr == S_OK, "put_Source %#lx\n", hr);
    ok(RefOf((IUnknown *)cb) == oref + 1, "put_Source did not take one reference: %lu, was %lu\n", RefOf((IUnknown *)cb), oref);
    hr = g->lpVtbl->get_Source(g, &got);
    ok(hr == S_OK && got, "get_Source %#lx\n", hr);
    if (got)
    {
        QI(got, &IID_IUnknown, (void **)&u1);
        QI(cb, &IID_IUnknown, (void **)&u2);
        ok(u1 == u2, "Source is not the brush that was set: %p vs %p\n", u1, u2);
        REL(u1); REL(u2);
        REL(got);
    }
    hr = g->lpVtbl->put_Source(g, NULL);
    ok(hr == S_OK, "put_Source(NULL) %#lx\n", hr);
    got = (WICompositionBrush *)0x1234;
    hr = g->lpVtbl->get_Source(g, &got);
    ok(hr == S_OK && !got, "Source after NULL %#lx %p\n", hr, got);
    hr = g->lpVtbl->put_Source(g, other);
    ok(hr == S_OK, "put_Source again %#lx\n", hr);
    REL(other); other = NULL;
    REL(cb);
    cb = NULL;                          /* the nine-grid brush now holds the last reference of the color brush */
    hr = g->lpVtbl->get_Source(g, &got);
    ok(hr == S_OK && got, "Source kept alive by the brush %#lx %p\n", hr, got);
    if (got) REL(got);
    hr = g->lpVtbl->put_Source(g, (WICompositionBrush *)base);
    ok(hr == E_INVALIDARG, "a brush as its own Source %#lx\n", hr);
    got = (WICompositionBrush *)0x1234;
    hr = g->lpVtbl->get_Source(g, &got);
    ok(hr == S_OK && got && got != (WICompositionBrush *)0x1234, "Source after the rejected put %#lx %p\n", hr, got);
    if (got && got != (WICompositionBrush *)0x1234) REL(got);

    /* a SpriteVisual accepts it as its Brush (nothing is painted yet) */
    hr = Comp->lpVtbl->CreateSpriteVisual(Comp, &sp);
    ok(hr == S_OK && sp, "CreateSpriteVisual %#lx\n", hr);
    if (sp)
    {
        hr = sp->lpVtbl->put_Brush(sp, base);
        ok(hr == S_OK, "SpriteVisual.put_Brush(nine-grid) %#lx\n", hr);
        got = NULL;
        hr = sp->lpVtbl->get_Brush(sp, &got);
        ok(hr == S_OK && got, "SpriteVisual.get_Brush %#lx\n", hr);
        if (got)
        {
            QI(got, &IID_INineGridT, (void **)&other);
            ok(other != NULL, "the Brush of the sprite is not the nine-grid brush\n");
            if (other) REL(other);
            other = NULL;
            REL(got);
        }
        REL(sp);
    }
out:
    if (cb2) REL(cb2);
    if (cb) REL(cb);
    if (other) REL(other);
    if (g) REL(g);
    if (base) REL(base);
    REL(made);
}

static void TestVisualInteractionSource(PRO_ACTIVATE pRoActivateInstance, PWCS pWindowsCreateString, PWDS pWindowsDeleteString)
{
    const WCHAR name[] = L"Windows.UI.Composition.Interactions.VisualInteractionSource";
    HMODULE combase = GetModuleHandleW(L"combase.dll");
    HRESULT (WINAPI *pGetFactory)(HSTRING, REFIID, void **) = combase ? (void *)GetProcAddress(combase, "RoGetActivationFactory") : NULL;
    LPCWSTR (WINAPI *pRaw)(HSTRING, UINT32 *) = combase ? (void *)GetProcAddress(combase, "WindowsGetStringRawBuffer") : NULL;
    HSTRING cls = NULL, fcls = NULL;
    IVisStatics *st = NULL;
    IVis *src = NULL, *src2 = NULL;
    IVis2 *s2 = NULL;
    IUnknown *u1 = NULL, *u2 = NULL, *x = NULL;
    WIContainerVisual *cv = NULL;
    WIVisual *vis = NULL, *got = NULL;
    IID *iids = NULL;
    ULONG count = 0, vref;
    BOOLEAN b;
    INT32 m;
    float f[3];
    HRESULT hr;

    if (!pGetFactory) { skip("no RoGetActivationFactory\n"); return; }
    hr = pWindowsCreateString(name, lstrlenW(name), &fcls);
    ok(hr == S_OK, "WindowsCreateString %#lx\n", hr);
    hr = pGetFactory(fcls, &IID_IVisStatics, (void **)&st);
    if (hr != S_OK)
    {
        skip("VisualInteractionSource is not registered: %#lx\n", hr);
        pWindowsDeleteString(fcls);
        return;
    }
    ok(st != NULL, "no statics\n");

    hr = Comp->lpVtbl->CreateContainerVisual(Comp, &cv);
    ok(hr == S_OK && cv, "CreateContainerVisual %#lx\n", hr);
    if (!cv) goto out;
    QI(cv, &IID___x_ABI_CWindows_CUI_CComposition_CIVisual, (void **)&vis);
    vref = RefOf((IUnknown *)vis);

    hr = st->lpVtbl->Create(st, vis, NULL);
    ok(hr == E_POINTER, "Create(NULL result) %#lx\n", hr);
    src = (IVis *)0x1234;
    hr = st->lpVtbl->Create(st, NULL, &src);
    ok(FAILED(hr) && src == NULL, "Create(NULL visual) %#lx %p\n", hr, src);
    hr = st->lpVtbl->Create(st, vis, &src);
    ok(hr == S_OK && src, "Create %#lx %p\n", hr, src);
    if (!src) goto out;
    ok(RefOf((IUnknown *)vis) == vref + 1, "the source holds the visual: refs %lu, were %lu\n", RefOf((IUnknown *)vis), vref);

    /* identity, class name, IIDs, other interfaces */
    QI(src, &IID_IUnknown, (void **)&u1);
    hr = QI(src, &IID_IVis2, (void **)&s2);
    ok(hr == S_OK && s2, "QI IVisualInteractionSource2 %#lx\n", hr);
    QI(s2, &IID_IUnknown, (void **)&u2);
    ok(u1 == u2, "identity %p vs %p\n", u1, u2);
    REL(u1); REL(u2);
    hr = QI(src, &IID_IVis3, (void **)&x);
    ok(hr == S_OK && x, "QI IVisualInteractionSource3 %#lx\n", hr);
    if (x) REL(x);
    x = NULL;
    hr = QI(src, &IID_ICompInteractionSource, (void **)&x);
    ok(hr == S_OK && x, "QI ICompositionInteractionSource %#lx\n", hr);
    if (x) REL(x);
    x = NULL;
    hr = QI(src, &IID___x_ABI_CWindows_CUI_CComposition_CICompositionObject, (void **)&x);
    ok(hr == S_OK && x, "QI ICompositionObject %#lx\n", hr);
    if (x) REL(x);
    x = NULL;
    hr = QI(src, &IID_Closable, (void **)&x);
    ok(hr == S_OK && x, "QI IClosable %#lx\n", hr);
    if (x) { hr = ((__x_ABI_CWindows_CFoundation_CIClosable *)x)->lpVtbl->Close((__x_ABI_CWindows_CFoundation_CIClosable *)x); ok(hr == S_OK, "Close %#lx\n", hr); REL(x); }
    x = (IUnknown *)0x1234;
    hr = QI(src, &IID_Unknown1, (void **)&x);
    ok(hr == E_NOINTERFACE && x == NULL, "QI(unknown IID) %#lx %p\n", hr, x);
    hr = src->lpVtbl->GetIids(src, &count, &iids);
    ok(hr == S_OK && iids, "GetIids %#lx\n", hr);
    if (iids)
    {
        ok(HasIid(iids, count, &IID_IVis), "GetIids lacks IVisualInteractionSource\n");
        ok(HasIid(iids, count, &IID_IVis2), "GetIids lacks IVisualInteractionSource2\n");
        ok(HasIid(iids, count, &IID_ICompInteractionSource), "GetIids lacks ICompositionInteractionSource\n");
        CoTaskMemFree(iids);
    }
    hr = src->lpVtbl->GetRuntimeClassName(src, &cls);
    ok(hr == S_OK, "GetRuntimeClassName %#lx\n", hr);
    if (hr == S_OK && pRaw)
    {
        ok(!lstrcmpW(pRaw(cls, NULL), name), "class %ls\n", pRaw(cls, NULL));
        pWindowsDeleteString(cls);
    }

    /* Source */
    hr = src->lpVtbl->get_Source(src, NULL);
    ok(hr == E_POINTER, "get_Source(NULL) %#lx\n", hr);
    hr = src->lpVtbl->get_Source(src, &got);
    ok(hr == S_OK && got, "get_Source %#lx %p\n", hr, got);
    if (got)
    {
        QI(got, &IID_IUnknown, (void **)&u1);
        QI(vis, &IID_IUnknown, (void **)&u2);
        ok(u1 == u2, "Source is not the visual: %p vs %p\n", u1, u2);
        REL(u1); REL(u2);
        REL(got);
    }

    /* defaults and round trips (the rails default is documented: on) */
    b = FALSE;
    hr = src->lpVtbl->get_RailsX(src, &b);
    ok(hr == S_OK && b, "IsPositionXRailsEnabled default %#lx %u\n", hr, b);
    b = FALSE;
    hr = src->lpVtbl->get_RailsY(src, &b);
    ok(hr == S_OK && b, "IsPositionYRailsEnabled default %#lx %u\n", hr, b);
    hr = src->lpVtbl->put_RailsX(src, FALSE);
    ok(hr == S_OK, "put_RailsX %#lx\n", hr);
    b = TRUE;
    hr = src->lpVtbl->get_RailsX(src, &b);
    ok(hr == S_OK && !b, "RailsX after put %#lx %u\n", hr, b);
    hr = src->lpVtbl->get_RailsX(src, NULL);
    ok(hr == E_POINTER, "get_RailsX(NULL) %#lx\n", hr);
#define ROUNDTRIP(N, V) \
    hr = src->lpVtbl->put_##N(src, V); ok(hr == S_OK, "put_" #N " %#lx\n", hr); \
    m = -1; hr = src->lpVtbl->get_##N(src, &m); ok(hr == S_OK && m == V, "get_" #N " %#lx %d, expected " #V "\n", hr, m);
    ROUNDTRIP(Redirect, 3)          /* CapableTouchpadAndPointerWheel */
    ROUNDTRIP(PXChain, 1)           /* Always */
    ROUNDTRIP(PXMode, 1)            /* EnabledWithInertia */
    ROUNDTRIP(PYChain, 2)           /* Never */
    ROUNDTRIP(PYMode, 2)            /* EnabledWithoutInertia */
    ROUNDTRIP(SChain, 2)
    ROUNDTRIP(SMode, 1)
#undef ROUNDTRIP

    /* values that are only read through expressions: documented defaults (0 and, for Scale, 1) */
    if (s2)
    {
        f[0] = f[1] = f[2] = 9.0f;
        hr = s2->lpVtbl->get_DeltaPosition(s2, f);
        ok(hr == S_OK && f[0] == 0.0f && f[1] == 0.0f && f[2] == 0.0f, "DeltaPosition %#lx %g %g %g\n", hr, f[0], f[1], f[2]);
        f[0] = 9.0f;
        hr = s2->lpVtbl->get_Scale(s2, f);
        ok(hr == S_OK && f[0] == 1.0f, "Scale %#lx %g\n", hr, f[0]);
        hr = s2->lpVtbl->get_Scale(s2, NULL);
        ok(hr == E_POINTER, "get_Scale(NULL) %#lx\n", hr);
    }

    /* a second source on the same visual is independent; the visual is freed with the last of them */
    hr = st->lpVtbl->Create(st, vis, &src2);
    ok(hr == S_OK && src2 && src2 != src, "second Create %#lx %p\n", hr, src2);
    if (src2)
    {
        b = FALSE;
        hr = src2->lpVtbl->get_RailsX(src2, &b);
        ok(hr == S_OK && b, "second source RailsX %#lx %u (independent of the first)\n", hr, b);
        REL(src2);
    }

    REL(src);
    src = NULL;
    if (s2) { REL(s2); s2 = NULL; }
    ok(RefOf((IUnknown *)vis) == vref, "visual refs %lu after the sources are freed, were %lu\n", RefOf((IUnknown *)vis), vref);
out:
    if (s2) REL(s2);
    if (vis) REL(vis);
    if (cv) REL(cv);
    st->lpVtbl->Release(st);
    pWindowsDeleteString(fcls);
}

/*
 * ExpressionAnimation, CompositionAnimation, CompositionPropertySet and Interactions.InteractionTracker: IIDs, slot
 * order and signatures from microsoft/windows-rs (MIT OR Apache-2.0), the published `windows` crate 0.62.2 (vcs commit
 * 32c3144490c016fe496a0aed769bce60987a2e9d, crates/libs/windows/src/Windows/UI/Composition/mod.rs and
 * .../Interactions/mod.rs, the *_Vtbl structs), cross-checked with the rdl files of commit
 * 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0. The defaults are from learn.microsoft.com (MicrosoftDocs/winrt-api commit
 * 4c1e9164521785f82dc63ab57a5ee4644f9d1888, interactiontracker*.md): Position 0, Scale 1, MinScale/MaxScale 1.
 * What the docs do not say (errors for empty keys, NULL arguments, defaults of the bounds and decay rates, duplicates)
 * is checked only against what this implementation chose: those expectations are marked "unmeasured" and are
 * VERIFY ON ORACLE; the tests that are tagged with it must not be taken as Windows behaviour.
 */
typedef __x_ABI_CWindows_CFoundation_CNumerics_CVector4 Vec4;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CMatrix3x2 Mat3x2;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CMatrix4x4 Mat4;
typedef __x_ABI_CWindows_CFoundation_CNumerics_CQuaternion Quat;

#define INSP6(T) \
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(T *This, REFIID iid, void **out); \
    ULONG (STDMETHODCALLTYPE *AddRef)(T *This); \
    ULONG (STDMETHODCALLTYPE *Release)(T *This); \
    HRESULT (STDMETHODCALLTYPE *GetIids)(T *This, ULONG *count, IID **iids); \
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(T *This, HSTRING *name); \
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(T *This, int *level);

typedef struct IAnim IAnim;
typedef struct { INSP6(IAnim)
    HRESULT (STDMETHODCALLTYPE *ClearAllParameters)(IAnim *This);
    HRESULT (STDMETHODCALLTYPE *ClearParameter)(IAnim *This, HSTRING key);
    HRESULT (STDMETHODCALLTYPE *SetColorParameter)(IAnim *This, HSTRING key, Color value);
    HRESULT (STDMETHODCALLTYPE *SetMatrix3x2Parameter)(IAnim *This, HSTRING key, Mat3x2 value);
    HRESULT (STDMETHODCALLTYPE *SetMatrix4x4Parameter)(IAnim *This, HSTRING key, Mat4 value);
    HRESULT (STDMETHODCALLTYPE *SetQuaternionParameter)(IAnim *This, HSTRING key, Quat value);
    HRESULT (STDMETHODCALLTYPE *SetReferenceParameter)(IAnim *This, HSTRING key, IUnknown *obj);
    HRESULT (STDMETHODCALLTYPE *SetScalarParameter)(IAnim *This, HSTRING key, float value);
    HRESULT (STDMETHODCALLTYPE *SetVector2Parameter)(IAnim *This, HSTRING key, Vec2 value);
    HRESULT (STDMETHODCALLTYPE *SetVector3Parameter)(IAnim *This, HSTRING key, Vec3 value);
    HRESULT (STDMETHODCALLTYPE *SetVector4Parameter)(IAnim *This, HSTRING key, Vec4 value);
} IAnimVtbl;
struct IAnim { const IAnimVtbl *lpVtbl; };

typedef struct IAnim2 IAnim2;
typedef struct { INSP6(IAnim2)
    HRESULT (STDMETHODCALLTYPE *SetBooleanParameter)(IAnim2 *This, HSTRING key, BOOLEAN value);
    HRESULT (STDMETHODCALLTYPE *get_Target)(IAnim2 *This, HSTRING *value);
    HRESULT (STDMETHODCALLTYPE *put_Target)(IAnim2 *This, HSTRING value);
} IAnim2Vtbl;
struct IAnim2 { const IAnim2Vtbl *lpVtbl; };

typedef struct IExprAnim IExprAnim;
typedef struct { INSP6(IExprAnim)
    HRESULT (STDMETHODCALLTYPE *get_Expression)(IExprAnim *This, HSTRING *value);
    HRESULT (STDMETHODCALLTYPE *put_Expression)(IExprAnim *This, HSTRING value);
} IExprAnimVtbl;
struct IExprAnim { const IExprAnimVtbl *lpVtbl; };

typedef struct ICompObj ICompObj;
typedef struct { INSP6(ICompObj)
    HRESULT (STDMETHODCALLTYPE *get_Compositor)(ICompObj *This, WICompositor **value);
    HRESULT (STDMETHODCALLTYPE *get_Dispatcher)(ICompObj *This, void **value);
    HRESULT (STDMETHODCALLTYPE *get_Properties)(ICompObj *This, IUnknown **value);
    HRESULT (STDMETHODCALLTYPE *StartAnimation)(ICompObj *This, HSTRING name, IUnknown *animation);
    HRESULT (STDMETHODCALLTYPE *StopAnimation)(ICompObj *This, HSTRING name);
} ICompObjVtbl;
struct ICompObj { const ICompObjVtbl *lpVtbl; };

typedef struct IPropSet IPropSet;
typedef struct { INSP6(IPropSet)
    HRESULT (STDMETHODCALLTYPE *InsertColor)(IPropSet *This, HSTRING n, Color v);
    HRESULT (STDMETHODCALLTYPE *InsertMatrix3x2)(IPropSet *This, HSTRING n, Mat3x2 v);
    HRESULT (STDMETHODCALLTYPE *InsertMatrix4x4)(IPropSet *This, HSTRING n, Mat4 v);
    HRESULT (STDMETHODCALLTYPE *InsertQuaternion)(IPropSet *This, HSTRING n, Quat v);
    HRESULT (STDMETHODCALLTYPE *InsertScalar)(IPropSet *This, HSTRING n, float v);
    HRESULT (STDMETHODCALLTYPE *InsertVector2)(IPropSet *This, HSTRING n, Vec2 v);
    HRESULT (STDMETHODCALLTYPE *InsertVector3)(IPropSet *This, HSTRING n, Vec3 v);
    HRESULT (STDMETHODCALLTYPE *InsertVector4)(IPropSet *This, HSTRING n, Vec4 v);
    HRESULT (STDMETHODCALLTYPE *TryGetColor)(IPropSet *This, HSTRING n, Color *v, int *st);
    HRESULT (STDMETHODCALLTYPE *TryGetMatrix3x2)(IPropSet *This, HSTRING n, Mat3x2 *v, int *st);
    HRESULT (STDMETHODCALLTYPE *TryGetMatrix4x4)(IPropSet *This, HSTRING n, Mat4 *v, int *st);
    HRESULT (STDMETHODCALLTYPE *TryGetQuaternion)(IPropSet *This, HSTRING n, Quat *v, int *st);
    HRESULT (STDMETHODCALLTYPE *TryGetScalar)(IPropSet *This, HSTRING n, float *v, int *st);
    HRESULT (STDMETHODCALLTYPE *TryGetVector2)(IPropSet *This, HSTRING n, Vec2 *v, int *st);
    HRESULT (STDMETHODCALLTYPE *TryGetVector3)(IPropSet *This, HSTRING n, Vec3 *v, int *st);
    HRESULT (STDMETHODCALLTYPE *TryGetVector4)(IPropSet *This, HSTRING n, Vec4 *v, int *st);
} IPropSetVtbl;
struct IPropSet { const IPropSetVtbl *lpVtbl; };

typedef struct ITracker ITracker;
typedef struct ISrcColl ISrcColl;
typedef struct { INSP6(ISrcColl)
    HRESULT (STDMETHODCALLTYPE *get_Count)(ISrcColl *This, INT32 *v);
    HRESULT (STDMETHODCALLTYPE *Add)(ISrcColl *This, IUnknown *v);
    HRESULT (STDMETHODCALLTYPE *Remove)(ISrcColl *This, IUnknown *v);
    HRESULT (STDMETHODCALLTYPE *RemoveAll)(ISrcColl *This);
} ISrcCollVtbl;
struct ISrcColl { const ISrcCollVtbl *lpVtbl; };
typedef struct { INSP6(ITracker)
    HRESULT (STDMETHODCALLTYPE *get_InteractionSources)(ITracker *This, ISrcColl **v);
    HRESULT (STDMETHODCALLTYPE *get_IsPositionRoundingSuggested)(ITracker *This, BOOLEAN *v);
    HRESULT (STDMETHODCALLTYPE *get_MaxPosition)(ITracker *This, Vec3 *v);
    HRESULT (STDMETHODCALLTYPE *put_MaxPosition)(ITracker *This, Vec3 v);
    HRESULT (STDMETHODCALLTYPE *get_MaxScale)(ITracker *This, float *v);
    HRESULT (STDMETHODCALLTYPE *put_MaxScale)(ITracker *This, float v);
    HRESULT (STDMETHODCALLTYPE *get_MinPosition)(ITracker *This, Vec3 *v);
    HRESULT (STDMETHODCALLTYPE *put_MinPosition)(ITracker *This, Vec3 v);
    HRESULT (STDMETHODCALLTYPE *get_MinScale)(ITracker *This, float *v);
    HRESULT (STDMETHODCALLTYPE *put_MinScale)(ITracker *This, float v);
    HRESULT (STDMETHODCALLTYPE *get_NaturalRestingPosition)(ITracker *This, Vec3 *v);
    HRESULT (STDMETHODCALLTYPE *get_NaturalRestingScale)(ITracker *This, float *v);
    HRESULT (STDMETHODCALLTYPE *get_Owner)(ITracker *This, IUnknown **v);
    HRESULT (STDMETHODCALLTYPE *get_Position)(ITracker *This, Vec3 *v);
    HRESULT (STDMETHODCALLTYPE *get_PositionInertiaDecayRate)(ITracker *This, IUnknown **v);
    HRESULT (STDMETHODCALLTYPE *put_PositionInertiaDecayRate)(ITracker *This, IUnknown *v);
    HRESULT (STDMETHODCALLTYPE *get_PositionVelocityInPixelsPerSecond)(ITracker *This, Vec3 *v);
    HRESULT (STDMETHODCALLTYPE *get_Scale)(ITracker *This, float *v);
    HRESULT (STDMETHODCALLTYPE *get_ScaleInertiaDecayRate)(ITracker *This, IUnknown **v);
    HRESULT (STDMETHODCALLTYPE *put_ScaleInertiaDecayRate)(ITracker *This, IUnknown *v);
    HRESULT (STDMETHODCALLTYPE *get_ScaleVelocityInPercentPerSecond)(ITracker *This, float *v);
    void *rest[12];     /* Adjust*, Configure*, TryUpdate*: not exercised */
} ITrackerVtbl;
struct ITracker { const ITrackerVtbl *lpVtbl; };

typedef struct ITrackerStatics ITrackerStatics;
typedef struct { INSP6(ITrackerStatics)
    HRESULT (STDMETHODCALLTYPE *Create)(ITrackerStatics *This, WICompositor *c, ITracker **r);
    HRESULT (STDMETHODCALLTYPE *CreateWithOwner)(ITrackerStatics *This, WICompositor *c, IUnknown *owner, ITracker **r);
} ITrackerStaticsVtbl;
struct ITrackerStatics { const ITrackerStaticsVtbl *lpVtbl; };

static const GUID IID_IAnim = {0x464c4c2c, 0x1caa, 0x4061, {0x9b, 0x40, 0xe1, 0x3f, 0xde, 0x15, 0x03, 0xca}};
static const GUID IID_IAnim2 = {0x369b603e, 0xa80f, 0x4948, {0x93, 0xe3, 0xed, 0x23, 0xfb, 0x38, 0xc6, 0xcb}};
static const GUID IID_IAnimBase = {0x1c2c2999, 0xe818, 0x48d3, {0xa6, 0xdd, 0xd7, 0x8c, 0x82, 0xf8, 0xac, 0xe9}};
static const GUID IID_IExprAnim = {0x6acc5431, 0x7d3d, 0x4bf3, {0xab, 0xb6, 0xf4, 0x4b, 0xdc, 0x48, 0x88, 0xc1}};
static const GUID IID_IPropSet = {0xc9d6d202, 0x5f67, 0x4453, {0x91, 0x17, 0x9e, 0xad, 0xd4, 0x30, 0xd3, 0xc2}};
static const GUID IID_ISrcColl = {0x1b468e4b, 0xa5bf, 0x47d8, {0xa5, 0x47, 0x38, 0x94, 0x15, 0x5a, 0x15, 0x8c}};
static const GUID IID_ITracker = {0x2a8e8cb1, 0x1000, 0x4416, {0x83, 0x63, 0xcc, 0x27, 0xfb, 0x87, 0x73, 0x08}};
static const GUID IID_ITrackerStatics = {0xbba5d7b7, 0x6590, 0x4498, {0x8d, 0x6c, 0xeb, 0x62, 0xb5, 0x14, 0xc9, 0x2a}};
static const GUID IID_ICompObjW = {0xbcb4ad45, 0x7609, 0x4550, {0x93, 0x4f, 0x16, 0x00, 0x2a, 0x68, 0xfd, 0xed}};

/* a stand-in object (an IInteractionTrackerOwner or an IReference) that counts its references */
typedef struct { IUnknown iface; LONG ref; } Counted;
static HRESULT WINAPI Counted_QI(IUnknown *i, REFIID iid, void **o)
{
    if (IsEqualGUID(iid, &IID_IUnknown)) { *o = i; i->lpVtbl->AddRef(i); return S_OK; }
    *o = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI Counted_AddRef(IUnknown *i) { return InterlockedIncrement(&((Counted *)i)->ref); }
static ULONG WINAPI Counted_Release(IUnknown *i) { return InterlockedDecrement(&((Counted *)i)->ref); }
static IUnknownVtbl counted_vtbl = { Counted_QI, Counted_AddRef, Counted_Release };

static HSTRING HS(const WCHAR *s)
{
    HSTRING h = NULL;
    HRESULT hr = WindowsCreateString(s, lstrlenW(s), &h);
    ok(hr == S_OK, "WindowsCreateString %#lx\n", hr);
    return h;
}

static BOOL HSEq(HSTRING h, const WCHAR *s)
{
    UINT32 len = 0;
    const WCHAR *b = WindowsGetStringRawBuffer(h, &len);
    if (!b) len = 0;
    return len == (UINT32)lstrlenW(s) && !wcsncmp(b ? b : L"", s, len);
}

static BOOL SameObject(IUnknown *a, IUnknown *b)
{
    IUnknown *ua = NULL, *ub = NULL;
    BOOL same;
    QI(a, &IID_IUnknown, &ua);
    QI(b, &IID_IUnknown, &ub);
    same = ua == ub;
    if (ua) REL(ua);
    if (ub) REL(ub);
    return same;
}

static void TestExpressionAnimation(void)
{
    const WCHAR expr[] = L"this.Target.Offset + Vector3(1, 2, 3)";
    WIContainerVisual *cv = NULL;
    IExprAnim *ea = NULL, *ea2 = NULL, *none = (IExprAnim *)0x1234;
    IAnim *an = NULL;
    IAnim2 *an2 = NULL;
    ICompObj *co = NULL, *vco = NULL;
    IPropSet *ps = NULL, *ps2 = NULL;
    IUnknown *x = NULL, *u1 = NULL, *u2 = NULL, *props = NULL;
    WICompositor *c = NULL;
    HSTRING h, k, v = NULL;
    IID *iids = NULL;
    ULONG count = 0, r0, r1;
    HRESULT hr;
    int st;
    float fv;
    Vec3 v3;
    Color col;
    Counted refobj = { { &counted_vtbl }, 1 };

    /* creation */
    hr = Comp->lpVtbl->CreateExpressionAnimation(Comp, NULL);
    ok(hr == E_POINTER, "CreateExpressionAnimation(NULL) %#lx\n", hr);
    hr = Comp->lpVtbl->CreateExpressionAnimation(Comp, (__x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation **)&ea);
    ok(hr == S_OK && ea, "CreateExpressionAnimation %#lx %p\n", hr, ea);
    h = HS(expr);
    hr = Comp->lpVtbl->CreateExpressionAnimationWithExpression(Comp, h, NULL);
    ok(hr == E_POINTER, "CreateExpressionAnimationWithExpression(NULL result) %#lx\n", hr);
    hr = Comp->lpVtbl->CreateExpressionAnimationWithExpression(Comp, h, (__x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation **)&ea2);
    ok(hr == S_OK && ea2, "CreateExpressionAnimationWithExpression %#lx %p\n", hr, ea2);
    WindowsDeleteString(h);
    if (!ea || !ea2) { skip("no ExpressionAnimation\n"); goto out; }
    ok(ea != ea2, "the same object twice\n");

    /* Expression: empty by default, round trip */
    hr = ea->lpVtbl->get_Expression(ea, &v);
    ok(hr == S_OK && HSEq(v, L""), "default Expression %#lx\n", hr);
    WindowsDeleteString(v); v = NULL;
    hr = ea->lpVtbl->get_Expression(ea, NULL);
    ok(hr == E_POINTER, "get_Expression(NULL) %#lx\n", hr);
    hr = ea2->lpVtbl->get_Expression(ea2, &v);
    ok(hr == S_OK && HSEq(v, expr), "Expression of the created animation %#lx\n", hr);
    WindowsDeleteString(v); v = NULL;
    h = HS(L"x + 1");
    hr = ea->lpVtbl->put_Expression(ea, h);
    ok(hr == S_OK, "put_Expression %#lx\n", hr);
    WindowsDeleteString(h);
    hr = ea->lpVtbl->get_Expression(ea, &v);
    ok(hr == S_OK && HSEq(v, L"x + 1"), "Expression after put %#lx\n", hr);
    WindowsDeleteString(v); v = NULL;

    /* identity, interfaces, class name */
    hr = QI(ea, &IID_IAnim, &an);
    ok(hr == S_OK && an, "QI ICompositionAnimation %#lx\n", hr);
    hr = QI(ea, &IID_IAnim2, &an2);
    ok(hr == S_OK && an2, "QI ICompositionAnimation2 %#lx\n", hr);
    hr = QI(ea, &IID_ICompObjW, &co);
    ok(hr == S_OK && co, "QI ICompositionObject %#lx\n", hr);
    hr = QI(ea, &IID_IAnimBase, &x);
    ok(hr == S_OK && x, "QI ICompositionAnimationBase %#lx\n", hr);
    if (x) REL(x);
    x = NULL;
    hr = QI(ea, &IID_Closable, &x);
    ok(hr == S_OK && x, "QI IClosable %#lx\n", hr);
    if (x) REL(x);
    x = NULL;
    hr = QI(ea, &IID_IAgileObject, &x);
    ok(hr == S_OK && x, "QI IAgileObject %#lx\n", hr);
    if (x) REL(x);
    x = (IUnknown *)0x1234;
    hr = QI(ea, &IID_Unknown1, &x);
    ok(hr == E_NOINTERFACE && !x, "QI(unknown IID) %#lx %p\n", hr, x);
    ok(SameObject((IUnknown *)ea, (IUnknown *)an) && SameObject((IUnknown *)ea, (IUnknown *)an2) &&
       SameObject((IUnknown *)ea, (IUnknown *)co), "the interfaces are not one object\n");
    hr = ea->lpVtbl->GetIids(ea, &count, &iids);
    ok(hr == S_OK && iids, "GetIids %#lx\n", hr);
    if (iids)
    {
        ok(HasIid(iids, count, &IID_IExprAnim), "GetIids lacks IExpressionAnimation\n");
        ok(HasIid(iids, count, &IID_IAnim), "GetIids lacks ICompositionAnimation\n");
        CoTaskMemFree(iids);
    }
    hr = ea->lpVtbl->GetRuntimeClassName(ea, &v);
    ok(hr == S_OK && HSEq(v, L"Windows.UI.Composition.ExpressionAnimation"), "class name %#lx\n", hr);
    WindowsDeleteString(v); v = NULL;
    if (!an || !an2 || !co) goto out;

    /* CompositionObject.Compositor is the creating compositor */
    hr = co->lpVtbl->get_Compositor(co, &c);
    ok(hr == S_OK && c && SameObject((IUnknown *)c, (IUnknown *)Comp), "Compositor %#lx %p\n", hr, c);
    if (c) REL(c);

    /* Target: empty by default, round trip */
    hr = an2->lpVtbl->get_Target(an2, &v);
    ok(hr == S_OK && HSEq(v, L""), "default Target %#lx\n", hr);
    WindowsDeleteString(v); v = NULL;
    h = HS(L"Offset");
    hr = an2->lpVtbl->put_Target(an2, h);
    ok(hr == S_OK, "put_Target %#lx\n", hr);
    WindowsDeleteString(h);
    hr = an2->lpVtbl->get_Target(an2, &v);
    ok(hr == S_OK && HSEq(v, L"Offset"), "Target after put %#lx\n", hr);
    WindowsDeleteString(v); v = NULL;

    /* parameters: every Set*Parameter stores; a reference parameter holds its object until it is replaced, cleared or
     * the animation is freed (the only observable part of the stored values) */
    k = HS(L"tracker");
    r0 = refobj.ref;
    hr = an->lpVtbl->SetReferenceParameter(an, k, &refobj.iface);
    ok(hr == S_OK, "SetReferenceParameter %#lx\n", hr);
    ok(refobj.ref == r0 + 1, "reference parameter holds the object: %ld, was %lu\n", refobj.ref, r0);
    hr = an->lpVtbl->SetReferenceParameter(an, k, &refobj.iface);
    ok(hr == S_OK && refobj.ref == r0 + 1, "same key again: %#lx refs %ld\n", hr, refobj.ref);
    hr = an->lpVtbl->SetScalarParameter(an, k, 2.5f);
    ok(hr == S_OK, "SetScalarParameter over a reference %#lx\n", hr);
    ok(refobj.ref == r0, "replacing the reference releases it: %ld, was %lu\n", refobj.ref, r0);
    hr = an->lpVtbl->SetReferenceParameter(an, k, &refobj.iface);
    ok(hr == S_OK && refobj.ref == r0 + 1, "reference again %#lx %ld\n", hr, refobj.ref);
    hr = an->lpVtbl->ClearParameter(an, k);
    ok(hr == S_OK && refobj.ref == r0, "ClearParameter %#lx refs %ld, was %lu\n", hr, refobj.ref, r0);
    hr = an->lpVtbl->ClearParameter(an, k);
    ok(hr == S_OK, "ClearParameter of a missing key (unmeasured) %#lx\n", hr);
    hr = an->lpVtbl->SetReferenceParameter(an, k, NULL);
    ok(hr == E_INVALIDARG, "SetReferenceParameter(NULL) (unmeasured) %#lx\n", hr);
    WindowsDeleteString(k);
    {
        Mat3x2 m32 = {1, 2, 3, 4, 5, 6};
        Mat4 m44 = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 7, 8, 9, 1};
        Quat q = {0, 0, 0, 1};
        Vec2 v2 = {1, 2};
        Vec4 v4 = {1, 2, 3, 4};
        Color cc = {1, 2, 3, 4};

        k = HS(L"a");
        ok(an->lpVtbl->SetColorParameter(an, k, cc) == S_OK, "SetColorParameter\n");
        ok(an->lpVtbl->SetMatrix3x2Parameter(an, k, m32) == S_OK, "SetMatrix3x2Parameter\n");
        ok(an->lpVtbl->SetMatrix4x4Parameter(an, k, m44) == S_OK, "SetMatrix4x4Parameter\n");
        ok(an->lpVtbl->SetQuaternionParameter(an, k, q) == S_OK, "SetQuaternionParameter\n");
        ok(an->lpVtbl->SetScalarParameter(an, k, 1.0f) == S_OK, "SetScalarParameter\n");
        ok(an->lpVtbl->SetVector2Parameter(an, k, v2) == S_OK, "SetVector2Parameter\n");
        v3.X = 1; v3.Y = 2; v3.Z = 3;
        ok(an->lpVtbl->SetVector3Parameter(an, k, v3) == S_OK, "SetVector3Parameter\n");
        ok(an->lpVtbl->SetVector4Parameter(an, k, v4) == S_OK, "SetVector4Parameter\n");
        ok(an2->lpVtbl->SetBooleanParameter(an2, k, TRUE) == S_OK, "SetBooleanParameter\n");
        WindowsDeleteString(k);
        k = HS(L"");
        ok(an->lpVtbl->SetScalarParameter(an, k, 1.0f) == E_INVALIDARG, "SetScalarParameter(empty key) (unmeasured)\n");
        WindowsDeleteString(k);
    }
    k = HS(L"o");
    r0 = refobj.ref;
    an->lpVtbl->SetReferenceParameter(an, k, &refobj.iface);
    ok(refobj.ref == r0 + 1, "reference held\n");
    hr = an->lpVtbl->ClearAllParameters(an);
    ok(hr == S_OK && refobj.ref == r0, "ClearAllParameters %#lx refs %ld, was %lu\n", hr, refobj.ref, r0);
    an->lpVtbl->SetReferenceParameter(an, k, &refobj.iface);
    WindowsDeleteString(k);

    /* StartAnimation / StopAnimation bookkeeping on a visual: the animation is held while it is started */
    hr = Comp->lpVtbl->CreateContainerVisual(Comp, &cv);
    ok(hr == S_OK && cv, "CreateContainerVisual %#lx\n", hr);
    if (!cv) goto out;
    hr = QI(cv, &IID_ICompObjW, &vco);
    ok(hr == S_OK && vco, "QI visual ICompositionObject %#lx\n", hr);
    if (!vco) goto out;
    r0 = RefOf((IUnknown *)ea);
    h = HS(L"Offset");
    hr = vco->lpVtbl->StartAnimation(vco, h, (IUnknown *)an);
    ok(hr == S_OK, "StartAnimation %#lx\n", hr);
    r1 = RefOf((IUnknown *)ea);
    ok(r1 == r0 + 1, "the started animation is held: %lu, was %lu\n", r1, r0);
    hr = vco->lpVtbl->StartAnimation(vco, h, (IUnknown *)an);
    ok(hr == S_OK && RefOf((IUnknown *)ea) == r1, "StartAnimation again on the same name %#lx %lu\n", hr, RefOf((IUnknown *)ea));
    hr = vco->lpVtbl->StartAnimation(vco, h, NULL);
    ok(hr == E_INVALIDARG, "StartAnimation(NULL) (unmeasured) %#lx\n", hr);
    hr = vco->lpVtbl->StopAnimation(vco, h);
    ok(hr == S_OK && RefOf((IUnknown *)ea) == r0, "StopAnimation %#lx %lu, was %lu\n", hr, RefOf((IUnknown *)ea), r0);
    hr = vco->lpVtbl->StopAnimation(vco, h);
    ok(hr == S_OK, "StopAnimation of a name that is not started (unmeasured) %#lx\n", hr);
    hr = vco->lpVtbl->StartAnimation(vco, h, (IUnknown *)an);
    ok(hr == S_OK && RefOf((IUnknown *)ea) == r0 + 1, "StartAnimation before the target is freed %#lx\n", hr);
    WindowsDeleteString(h);
    REL(vco); vco = NULL;
    REL(cv); cv = NULL;
    ok(RefOf((IUnknown *)ea) == r0, "freeing the target releases its animations: %lu, was %lu\n", RefOf((IUnknown *)ea), r0);

    /* CompositionObject.Properties: one CompositionPropertySet per object, values stored */
    hr = Comp->lpVtbl->CreateContainerVisual(Comp, &cv);
    QI(cv, &IID_ICompObjW, &vco);
    hr = vco->lpVtbl->get_Properties(vco, NULL);
    ok(hr == E_POINTER, "get_Properties(NULL) %#lx\n", hr);
    hr = vco->lpVtbl->get_Properties(vco, &props);
    ok(hr == S_OK && props, "get_Properties %#lx %p\n", hr, props);
    if (props)
    {
        hr = QI(props, &IID_IPropSet, &ps);
        ok(hr == S_OK && ps, "QI ICompositionPropertySet %#lx\n", hr);
        hr = vco->lpVtbl->get_Properties(vco, &u1);
        ok(hr == S_OK && u1 && SameObject(props, u1), "second get_Properties is another object\n");
        if (u1) REL(u1);
        hr = props->lpVtbl->QueryInterface(props, &IID_IUnknown, (void **)&u2);
        if (u2) REL(u2);
    }
    if (ps)
    {
        k = HS(L"Speed");
        st = 99; fv = 0;
        hr = ps->lpVtbl->TryGetScalar(ps, k, &fv, &st);
        ok(hr == S_OK && st == 2, "TryGetScalar of a missing name: %#lx status %d (NotFound is 2)\n", hr, st);
        hr = ps->lpVtbl->InsertScalar(ps, k, 4.25f);
        ok(hr == S_OK, "InsertScalar %#lx\n", hr);
        st = 99; fv = 0;
        hr = ps->lpVtbl->TryGetScalar(ps, k, &fv, &st);
        ok(hr == S_OK && st == 0 && fv == 4.25f, "TryGetScalar %#lx status %d value %g\n", hr, st, fv);
        v3.X = v3.Y = v3.Z = 7;
        st = 99;
        hr = ps->lpVtbl->TryGetVector3(ps, k, &v3, &st);
        ok(hr == S_OK && st == 1 && v3.X == 7 && v3.Y == 7, "TryGetVector3 on a scalar: %#lx status %d (TypeMismatch is 1) %g\n", hr, st, v3.X);
        hr = ps->lpVtbl->InsertScalar(ps, k, 5.0f);
        st = 99; fv = 0;
        ps->lpVtbl->TryGetScalar(ps, k, &fv, &st);
        ok(st == 0 && fv == 5.0f, "Insert over an existing name: status %d value %g\n", st, fv);
        v3.X = 1; v3.Y = 2; v3.Z = 3;
        WindowsDeleteString(k);
        k = HS(L"Pos");
        ps->lpVtbl->InsertVector3(ps, k, v3);
        v3.X = v3.Y = v3.Z = 0; st = 99;
        hr = ps->lpVtbl->TryGetVector3(ps, k, &v3, &st);
        ok(hr == S_OK && st == 0 && v3.X == 1 && v3.Y == 2 && v3.Z == 3, "TryGetVector3 %#lx %d %g %g %g\n", hr, st, v3.X, v3.Y, v3.Z);
        col.A = 1; col.R = 2; col.G = 3; col.B = 4;
        ps->lpVtbl->InsertColor(ps, k, col);
        col.A = col.R = col.G = col.B = 0; st = 99;
        hr = ps->lpVtbl->TryGetColor(ps, k, &col, &st);
        ok(hr == S_OK && st == 0 && col.A == 1 && col.R == 2 && col.G == 3 && col.B == 4, "TryGetColor %#lx %d\n", hr, st);
        hr = ps->lpVtbl->TryGetColor(ps, k, NULL, &st);
        ok(hr == E_POINTER, "TryGetColor(NULL) %#lx\n", hr);
        WindowsDeleteString(k);
        /* the property set is a CompositionObject too */
        hr = QI(ps, &IID_ICompObjW, &x);
        ok(hr == S_OK && x, "QI property set ICompositionObject %#lx\n", hr);
        if (x) { REL(x); x = NULL; }
        REL(ps); ps = NULL;
    }
    if (props) REL(props);
    (void)ps2; (void)none;
    REL(vco); vco = NULL;
    REL(cv); cv = NULL;

out:
    if (co) REL(co);
    if (an2) REL(an2);
    if (an) REL(an);
    if (ea2) REL(ea2);
    if (ea) REL(ea);
    ok(refobj.ref == 1, "the stand-in object is still referenced: %ld\n", refobj.ref);
}

static void TestInteractionTracker(PRO_ACTIVATE pRoActivateInstance, PWCS pWindowsCreateString, PWDS pWindowsDeleteString)
{
    const WCHAR name[] = L"Windows.UI.Composition.Interactions.InteractionTracker";
    const WCHAR visname[] = L"Windows.UI.Composition.Interactions.VisualInteractionSource";
    HMODULE combase = GetModuleHandleW(L"combase.dll");
    HRESULT (WINAPI *pGetFactory)(HSTRING, REFIID, void **) = combase ? (void *)GetProcAddress(combase, "RoGetActivationFactory") : NULL;
    HSTRING fcls = NULL, vcls = NULL, v = NULL;
    ITrackerStatics *st = NULL;
    IVisStatics *vst = NULL;
    ITracker *t = NULL, *t2 = NULL, *t3 = NULL;
    ISrcColl *sc = NULL, *sc2 = NULL;
    IVis *src = NULL, *src2 = NULL;
    WIContainerVisual *cv = NULL;
    WIVisual *vis = NULL;
    IUnknown *x = NULL, *u = NULL, *obj = NULL;
    ICompObj *co = NULL;
    IInspectable *insp = NULL;
    IID *iids = NULL;
    ULONG count = 0, r0;
    INT32 n;
    BOOLEAN b;
    Vec3 p;
    float f;
    HRESULT hr;
    Counted owner = { { &counted_vtbl }, 1 }, decay = { { &counted_vtbl }, 1 };

    if (!pGetFactory) { skip("no RoGetActivationFactory\n"); return; }
    hr = pWindowsCreateString(name, lstrlenW(name), &fcls);
    ok(hr == S_OK, "WindowsCreateString %#lx\n", hr);
    hr = pGetFactory(fcls, &IID_ITrackerStatics, (void **)&st);
    if (hr == REGDB_E_CLASSNOTREG)
    {
        skip("InteractionTracker is not registered: %#lx\n", hr);
        pWindowsDeleteString(fcls);
        return;
    }
    ok(hr == S_OK, "RoGetActivationFactory(InteractionTracker) %#lx\n", hr);
    if (hr != S_OK)
    {
        pWindowsDeleteString(fcls);
        return;
    }
    ok(st != NULL, "no statics\n");

    /* no default constructor */
    hr = pRoActivateInstance(fcls, &insp);
    ok(FAILED(hr) && !insp, "RoActivateInstance of a class without a default constructor: %#lx %p\n", hr, insp);
    if (insp) REL(insp);

    /* statics */
    hr = st->lpVtbl->Create(st, (WICompositor *)Comp, NULL);
    ok(hr == E_POINTER, "Create(NULL result) %#lx\n", hr);
    t = (ITracker *)0x1234;
    hr = st->lpVtbl->Create(st, NULL, &t);
    ok(FAILED(hr) && !t, "Create(NULL compositor) (unmeasured) %#lx %p\n", hr, t);
    hr = st->lpVtbl->Create(st, (WICompositor *)Comp, &t);
    ok(hr == S_OK && t, "Create %#lx %p\n", hr, t);
    hr = st->lpVtbl->CreateWithOwner(st, (WICompositor *)Comp, &owner.iface, &t2);
    ok(hr == S_OK && t2 && t2 != t, "CreateWithOwner %#lx %p\n", hr, t2);
    ok(owner.ref == 2, "the tracker holds its owner: %ld\n", owner.ref);
    if (!t || !t2) goto out;

    /* identity, interfaces, class name */
    hr = QI(t, &IID_ICompObjW, &co);
    ok(hr == S_OK && co, "QI ICompositionObject %#lx\n", hr);
    ok(co && SameObject((IUnknown *)t, (IUnknown *)co), "the interfaces are not one object\n");
    if (co)
    {
        WICompositor *c = NULL;
        hr = co->lpVtbl->get_Compositor(co, &c);
        ok(hr == S_OK && c && SameObject((IUnknown *)c, (IUnknown *)Comp), "Compositor %#lx %p\n", hr, c);
        if (c) REL(c);
        REL(co);
    }
    hr = QI(t, &IID_Closable, &x);
    ok(hr == S_OK && x, "QI IClosable %#lx\n", hr);
    if (x) { REL(x); x = NULL; }
    hr = QI(t, &IID_IAgileObject, &x);
    ok(hr == S_OK && x, "QI IAgileObject %#lx\n", hr);
    if (x) { REL(x); x = NULL; }
    x = (IUnknown *)0x1234;
    hr = QI(t, &IID_Unknown1, &x);
    ok(hr == E_NOINTERFACE && !x, "QI(unknown IID) %#lx %p\n", hr, x);
    hr = t->lpVtbl->GetIids(t, &count, &iids);
    ok(hr == S_OK && iids, "GetIids %#lx\n", hr);
    if (iids)
    {
        ok(HasIid(iids, count, &IID_ITracker), "GetIids lacks IInteractionTracker\n");
        CoTaskMemFree(iids);
    }
    hr = t->lpVtbl->GetRuntimeClassName(t, &v);
    ok(hr == S_OK && HSEq(v, name), "class name %#lx\n", hr);
    pWindowsDeleteString(v);

    /* Owner */
    hr = t->lpVtbl->get_Owner(t, NULL);
    ok(hr == E_POINTER, "get_Owner(NULL) %#lx\n", hr);
    x = (IUnknown *)0x1234;
    hr = t->lpVtbl->get_Owner(t, &x);
    ok(hr == S_OK && !x, "Owner of a tracker without one (unmeasured): %#lx %p\n", hr, x);
    hr = t2->lpVtbl->get_Owner(t2, &x);
    ok(hr == S_OK && x == &owner.iface, "Owner %#lx %p, expected %p\n", hr, x, &owner.iface);
    ok(owner.ref == 3, "get_Owner adds a reference: %ld\n", owner.ref);
    if (x) REL(x);

    /* documented defaults: Position 0, Scale 1, MinScale and MaxScale 1 */
    p.X = p.Y = p.Z = 9;
    hr = t->lpVtbl->get_Position(t, &p);
    ok(hr == S_OK && p.X == 0 && p.Y == 0 && p.Z == 0, "Position %#lx %g %g %g\n", hr, p.X, p.Y, p.Z);
    f = 9;
    hr = t->lpVtbl->get_Scale(t, &f);
    ok(hr == S_OK && f == 1.0f, "Scale %#lx %g\n", hr, f);
    f = 9;
    hr = t->lpVtbl->get_MinScale(t, &f);
    ok(hr == S_OK && f == 1.0f, "MinScale %#lx %g\n", hr, f);
    f = 9;
    hr = t->lpVtbl->get_MaxScale(t, &f);
    ok(hr == S_OK && f == 1.0f, "MaxScale %#lx %g\n", hr, f);
    p.X = p.Y = p.Z = 9;
    hr = t->lpVtbl->get_MinPosition(t, &p);
    ok(hr == S_OK && p.X == 0 && p.Y == 0 && p.Z == 0, "MinPosition default (unmeasured) %#lx %g %g %g\n", hr, p.X, p.Y, p.Z);
    p.X = p.Y = p.Z = 9;
    hr = t->lpVtbl->get_MaxPosition(t, &p);
    ok(hr == S_OK && p.X == 0 && p.Y == 0 && p.Z == 0, "MaxPosition default (unmeasured) %#lx %g %g %g\n", hr, p.X, p.Y, p.Z);
    b = TRUE;
    hr = t->lpVtbl->get_IsPositionRoundingSuggested(t, &b);
    ok(hr == S_OK && !b, "IsPositionRoundingSuggested %#lx %u\n", hr, b);
    p.X = p.Y = p.Z = 9;
    hr = t->lpVtbl->get_PositionVelocityInPixelsPerSecond(t, &p);
    ok(hr == S_OK && p.X == 0 && p.Y == 0 && p.Z == 0, "PositionVelocityInPixelsPerSecond %#lx\n", hr);
    f = 9;
    hr = t->lpVtbl->get_ScaleVelocityInPercentPerSecond(t, &f);
    ok(hr == S_OK && f == 0.0f, "ScaleVelocityInPercentPerSecond %#lx %g\n", hr, f);
    hr = t->lpVtbl->get_Position(t, NULL);
    ok(hr == E_POINTER, "get_Position(NULL) %#lx\n", hr);
    hr = t->lpVtbl->get_MaxScale(t, NULL);
    ok(hr == E_POINTER, "get_MaxScale(NULL) %#lx\n", hr);

    /* bounds: stored as given, per tracker */
    p.X = 100; p.Y = 2000; p.Z = 0;
    hr = t->lpVtbl->put_MaxPosition(t, p);
    ok(hr == S_OK, "put_MaxPosition %#lx\n", hr);
    p.X = -5; p.Y = -6; p.Z = -7;
    hr = t->lpVtbl->put_MinPosition(t, p);
    ok(hr == S_OK, "put_MinPosition %#lx\n", hr);
    hr = t->lpVtbl->put_MaxScale(t, 4.0f);
    ok(hr == S_OK, "put_MaxScale %#lx\n", hr);
    hr = t->lpVtbl->put_MinScale(t, 0.25f);
    ok(hr == S_OK, "put_MinScale %#lx\n", hr);
    hr = t->lpVtbl->get_MaxPosition(t, &p);
    ok(hr == S_OK && p.X == 100 && p.Y == 2000 && p.Z == 0, "MaxPosition %#lx %g %g %g\n", hr, p.X, p.Y, p.Z);
    hr = t->lpVtbl->get_MinPosition(t, &p);
    ok(hr == S_OK && p.X == -5 && p.Y == -6 && p.Z == -7, "MinPosition %#lx %g %g %g\n", hr, p.X, p.Y, p.Z);
    hr = t->lpVtbl->get_MaxScale(t, &f);
    ok(hr == S_OK && f == 4.0f, "MaxScale %#lx %g\n", hr, f);
    hr = t->lpVtbl->get_MinScale(t, &f);
    ok(hr == S_OK && f == 0.25f, "MinScale %#lx %g\n", hr, f);
    hr = t2->lpVtbl->get_MaxScale(t2, &f);
    ok(hr == S_OK && f == 1.0f, "another tracker's MaxScale %#lx %g\n", hr, f);
    hr = t->lpVtbl->get_Position(t, &p);
    ok(hr == S_OK && p.X == 0 && p.Y == 0 && p.Z == 0, "Position is not moved by the bounds (unmeasured) %#lx %g %g %g\n", hr, p.X, p.Y, p.Z);

    /* inertia decay rates (IReference): stored and returned, NULL by default (unmeasured) */
    x = (IUnknown *)0x1234;
    hr = t->lpVtbl->get_PositionInertiaDecayRate(t, &x);
    ok(hr == S_OK && !x, "PositionInertiaDecayRate default (unmeasured) %#lx %p\n", hr, x);
    hr = t->lpVtbl->put_PositionInertiaDecayRate(t, &decay.iface);
    ok(hr == S_OK && decay.ref == 2, "put_PositionInertiaDecayRate %#lx refs %ld\n", hr, decay.ref);
    hr = t->lpVtbl->get_PositionInertiaDecayRate(t, &x);
    ok(hr == S_OK && x == &decay.iface && decay.ref == 3, "get_PositionInertiaDecayRate %#lx %p refs %ld\n", hr, x, decay.ref);
    if (x) REL(x);
    hr = t->lpVtbl->put_ScaleInertiaDecayRate(t, &decay.iface);
    ok(hr == S_OK && decay.ref == 3, "put_ScaleInertiaDecayRate %#lx refs %ld\n", hr, decay.ref);
    hr = t->lpVtbl->put_PositionInertiaDecayRate(t, NULL);
    ok(hr == S_OK && decay.ref == 2, "put_PositionInertiaDecayRate(NULL) releases %#lx refs %ld\n", hr, decay.ref);
    hr = t->lpVtbl->get_ScaleInertiaDecayRate(t, &x);
    ok(hr == S_OK && x == &decay.iface, "get_ScaleInertiaDecayRate %#lx %p\n", hr, x);
    if (x) REL(x);

    /* InteractionSources: the collection of the tracker, with the VisualInteractionSource of this dll */
    hr = t->lpVtbl->get_InteractionSources(t, NULL);
    ok(hr == E_POINTER, "get_InteractionSources(NULL) %#lx\n", hr);
    hr = t->lpVtbl->get_InteractionSources(t, &sc);
    ok(hr == S_OK && sc, "get_InteractionSources %#lx %p\n", hr, sc);
    hr = t->lpVtbl->get_InteractionSources(t, &sc2);
    ok(hr == S_OK && sc2 && SameObject((IUnknown *)sc, (IUnknown *)sc2), "the collection is not stable\n");
    if (sc2) REL(sc2);
    hr = t2->lpVtbl->get_InteractionSources(t2, &sc2);
    ok(hr == S_OK && sc2 && !SameObject((IUnknown *)sc, (IUnknown *)sc2), "two trackers share a collection\n");
    if (sc2) { REL(sc2); sc2 = NULL; }
    if (!sc) goto out;
    hr = QI(sc, &IID_ISrcColl, &x);
    ok(hr == S_OK && x, "QI ICompositionInteractionSourceCollection %#lx\n", hr);
    if (x) { REL(x); x = NULL; }
    hr = sc->lpVtbl->GetRuntimeClassName(sc, &v);
    ok(hr == S_OK && HSEq(v, L"Windows.UI.Composition.Interactions.CompositionInteractionSourceCollection"), "collection class name %#lx\n", hr);
    pWindowsDeleteString(v);
    n = 99;
    hr = sc->lpVtbl->get_Count(sc, &n);
    ok(hr == S_OK && n == 0, "Count of a new collection %#lx %d\n", hr, n);
    hr = sc->lpVtbl->get_Count(sc, NULL);
    ok(hr == E_POINTER, "get_Count(NULL) %#lx\n", hr);

    hr = pWindowsCreateString(visname, lstrlenW(visname), &vcls);
    hr = pGetFactory(vcls, &IID_IVisStatics, (void **)&vst);
    pWindowsDeleteString(vcls);
    ok(hr == S_OK && vst, "VisualInteractionSource statics %#lx\n", hr);
    hr = Comp->lpVtbl->CreateContainerVisual(Comp, &cv);
    ok(hr == S_OK && cv, "CreateContainerVisual %#lx\n", hr);
    if (!vst || !cv) goto out;
    QI(cv, &IID___x_ABI_CWindows_CUI_CComposition_CIVisual, &vis);
    hr = vst->lpVtbl->Create(vst, vis, &src);
    ok(hr == S_OK && src, "VisualInteractionSource Create %#lx\n", hr);
    hr = vst->lpVtbl->Create(vst, vis, &src2);
    ok(hr == S_OK && src2, "second VisualInteractionSource %#lx\n", hr);
    if (!src || !src2) goto out;
    hr = QI(src, &IID_ICompInteractionSource, &obj);
    ok(hr == S_OK && obj, "QI ICompositionInteractionSource %#lx\n", hr);
    if (!obj) goto out;
    r0 = RefOf((IUnknown *)src);
    hr = sc->lpVtbl->Add(sc, obj);
    ok(hr == S_OK, "Add %#lx\n", hr);
    ok(RefOf((IUnknown *)src) == r0 + 1, "the collection holds the source: %lu, was %lu\n", RefOf((IUnknown *)src), r0);
    sc->lpVtbl->get_Count(sc, &n);
    ok(n == 1, "Count after Add %d\n", n);
    hr = sc->lpVtbl->Add(sc, obj);
    sc->lpVtbl->get_Count(sc, &n);
    ok(hr == S_OK && n == 1 && RefOf((IUnknown *)src) == r0 + 1, "Add of a member again (unmeasured) %#lx count %d refs %lu\n", hr, n, RefOf((IUnknown *)src));
    hr = sc->lpVtbl->Add(sc, NULL);
    ok(FAILED(hr), "Add(NULL) (unmeasured) %#lx\n", hr);
    hr = QI(src2, &IID_ICompInteractionSource, &u);
    hr = sc->lpVtbl->Add(sc, u);
    sc->lpVtbl->get_Count(sc, &n);
    ok(hr == S_OK && n == 2, "Add second source %#lx count %d\n", hr, n);
    hr = sc->lpVtbl->Remove(sc, obj);
    sc->lpVtbl->get_Count(sc, &n);
    ok(hr == S_OK && n == 1 && RefOf((IUnknown *)src) == r0, "Remove %#lx count %d refs %lu\n", hr, n, RefOf((IUnknown *)src));
    hr = sc->lpVtbl->Remove(sc, obj);
    sc->lpVtbl->get_Count(sc, &n);
    ok(hr == S_OK && n == 1, "Remove of a non-member (unmeasured) %#lx count %d\n", hr, n);
    hr = sc->lpVtbl->RemoveAll(sc);
    sc->lpVtbl->get_Count(sc, &n);
    ok(hr == S_OK && n == 0, "RemoveAll %#lx count %d\n", hr, n);
    sc->lpVtbl->Add(sc, obj);
    sc->lpVtbl->Add(sc, u);
    /* the sources are released when the tracker (and with it the collection) is freed */
    r0 = RefOf((IUnknown *)src);
    REL(sc); sc = NULL;
    ok(RefOf((IUnknown *)src) == r0, "a collection reference held by the test only: %lu, was %lu\n", RefOf((IUnknown *)src), r0);
    REL(t); t = NULL;
    ok(RefOf((IUnknown *)src) == r0 - 1, "freeing the tracker releases its sources: %lu, was %lu\n", RefOf((IUnknown *)src), r0);

    /* Properties of a tracker */
    {
        ICompObj *tco = NULL;
        IUnknown *props = NULL;
        hr = QI(t2, &IID_ICompObjW, &tco);
        if (tco)
        {
            hr = tco->lpVtbl->get_Properties(tco, &props);
            ok(hr == S_OK && props, "tracker Properties %#lx\n", hr);
            if (props) REL(props);
            REL(tco);
        }
    }
    (void)t3;

out:
    if (u) REL(u);
    if (obj) REL(obj);
    if (src2) REL(src2);
    if (src) REL(src);
    if (vis) REL(vis);
    if (cv) REL(cv);
    if (vst) vst->lpVtbl->Release(vst);
    if (sc) REL(sc);
    if (t2) REL(t2);
    if (t) REL(t);
    ok(owner.ref == 1, "the owner is released with its tracker: %ld\n", owner.ref);
    ok(decay.ref == 1, "the decay rate is released with its tracker: %ld\n", decay.ref);
    st->lpVtbl->Release(st);
    pWindowsDeleteString(fcls);
}

START_TEST(Composition)
{
    SetUnhandledExceptionFilter(CrashFilter);
    HMODULE combase = LoadLibraryW(L"combase.dll");
    PRO_ACTIVATE pRoActivateInstance;
    PWCS pWindowsCreateString;
    PWDS pWindowsDeleteString;
    HSTRING cls = NULL;
    IInspectable *obj = NULL;
    HRESULT hr;
    const WCHAR name[] = L"Windows.UI.Composition.Compositor";

    if (!combase) { skip("no combase\n"); return; }
    pRoActivateInstance = (PRO_ACTIVATE)GetProcAddress(combase, "RoActivateInstance");
    pWindowsCreateString = (PWCS)GetProcAddress(combase, "WindowsCreateString");
    pWindowsDeleteString = (PWDS)GetProcAddress(combase, "WindowsDeleteString");
    if (!pRoActivateInstance || !pWindowsCreateString || !pWindowsDeleteString) { skip("no WinRT activation\n"); return; }

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    hr = pWindowsCreateString(name, lstrlenW(name), &cls);
    ok(hr == S_OK, "WindowsCreateString %#lx\n", hr);
    hr = pRoActivateInstance(cls, &obj);
    pWindowsDeleteString(cls);
    if (hr != S_OK)
    {
        skip("Windows.UI.Composition.Compositor does not activate: %#lx\n", hr);
        CoUninitialize();
        return;
    }
    hr = QI(obj, &IID_Compositor, (void **)&Comp);
    ok(hr == S_OK, "QI ICompositor %#lx\n", hr);
    REL(obj);
    if (Comp)
    {
        TestModel();
        TestInsetClipObject();
        TestPixels();
        TestSurfaces();
        TestSurfacesD2DDevice();
        TestStretch();
        TestDesktopTarget();
        TestVisual2();
        TestCompositor2AndBrush3();
        TestNineGridBrush();
        TestVisualInteractionSource(pRoActivateInstance, pWindowsCreateString, pWindowsDeleteString);
        TestExpressionAnimation();
        TestInteractionTracker(pRoActivateInstance, pWindowsCreateString, pWindowsDeleteString);
        REL(Comp);
    }
    TestController(pRoActivateInstance, pWindowsCreateString, pWindowsDeleteString);
    CoUninitialize();
}
