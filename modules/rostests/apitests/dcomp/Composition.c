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

/* ICompositorDesktopInterop: IID and first method from the C# declaration on learn.microsoft.com ("Using the Visual
 * layer with Windows Forms"); only that method is declared there, so only it is used */
typedef struct IDesktopInterop IDesktopInterop;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDesktopInterop *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDesktopInterop *This);
    ULONG (STDMETHODCALLTYPE *Release)(IDesktopInterop *This);
    HRESULT (STDMETHODCALLTYPE *CreateDesktopWindowTarget)(IDesktopInterop *This, HWND hwnd, BOOL topmost,
            IInspectable **result);
} IDesktopInteropVtbl;
struct IDesktopInterop { const IDesktopInteropVtbl *lpVtbl; };
static const GUID IID_DesktopInterop = {0x29e691fa, 0x4567, 0x4dca, {0xb3, 0x19, 0xd0, 0xf2, 0x07, 0xeb, 0x68, 0x07}};

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

static void TestDesktopTarget(void)
{
    IDesktopInterop *di = NULL;
    IInspectable *t = NULL, *t2 = NULL;
    WICompositionTarget *ct = NULL;
    WICompositionObject *obj = NULL;
    WICompositor *c2 = NULL;
    WIVisual *v, *got;
    IUnknown *u1 = NULL, *u2 = NULL;
    HSTRING cls = NULL;
    HMODULE combase = GetModuleHandleW(L"combase.dll");
    LPCWSTR (WINAPI *pRaw)(HSTRING, UINT32 *) = combase ? (void *)GetProcAddress(combase, "WindowsGetStringRawBuffer") : NULL;
    HRESULT (WINAPI *pDel)(HSTRING) = combase ? (void *)GetProcAddress(combase, "WindowsDeleteString") : NULL;
    ULONG comp_ref, vis_ref;
    HWND hwnd;
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

    hr = di->lpVtbl->CreateDesktopWindowTarget(di, hwnd, TRUE, &t);
    ok(hr == S_OK && t, "CreateDesktopWindowTarget %#lx %p\n", hr, t);
    if (!t) goto out;
    hr = t->lpVtbl->GetRuntimeClassName(t, &cls);
    ok(hr == S_OK, "GetRuntimeClassName %#lx\n", hr);
    if (hr == S_OK && pRaw && pDel)
    {
        ok(!lstrcmpW(pRaw(cls, NULL), L"Windows.UI.Composition.Desktop.DesktopWindowTarget"), "class %ls\n",
           pRaw(cls, NULL));
        pDel(cls);
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
            /* the target keeps its root alive; releasing the target drops it */
            ct->lpVtbl->put_Root(ct, v);
            REL(v);
        }
        REL(ct);
    }
    REL(t);
    ok(RefOf((IUnknown *)Comp) == comp_ref, "Compositor refs %lu after the target, were %lu\n",
       RefOf((IUnknown *)Comp), comp_ref);

    /* topmost FALSE works as well */
    hr = di->lpVtbl->CreateDesktopWindowTarget(di, hwnd, FALSE, &t2);
    ok(hr == S_OK && t2, "CreateDesktopWindowTarget(topmost FALSE) %#lx %p\n", hr, t2);
    if (t2) REL(t2);
out:
    DestroyWindow(hwnd);
    REL(di);
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
        TestStretch();
        TestDesktopTarget();
        REL(Comp);
    }
    CoUninitialize();
}
