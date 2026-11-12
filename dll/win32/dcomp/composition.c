/*
 * PROJECT:     ReactOS DirectComposition
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows.UI.Composition object model (stage 2): visual tree, brushes, clip, CPU test renderer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Objects are kept in memory only; nothing is presented (stage 4 needs the win32k window surfaces). One struct
 * cobj serves every class: a table maps interface IIDs to the embedded interface slots a class implements.
 * All objects are agile and share one global lock (the scene graph is small and every call is short).
 *
 * What is NOT implemented, and logged with FIXME where it is reachable:
 *   CompositionObject.Properties/StartAnimation/StopAnimation (needs animations and property sets),
 *   Dispatcher (returns NULL), VisualCollection IIterable<Visual> (First), the interfaces above contract 2.0
 *   (IVisual2.., ICompositionSurfaceBrush2.. for brush transforms), 3D transforms (only the 2D part of
 *   Scale/RotationAngle/TransformMatrix is used by the test renderer), CompositeMode other than SourceOver,
 *   BorderMode, BackfaceVisibility (stored only).
 * Unverified defaults and orderings (docs do not state them; verify on the oracle before relying on them):
 *   CompositionSurfaceBrush.Stretch default (UniformToFill used), bitmap interpolation default (Linear),
 *   transform order (centre scale/rotate, anchor, TransformMatrix, offset), InsertAbove/Below with a NULL
 *   sibling (top / bottom), Remove of a non-member (S_OK), inserting a visual that has another parent (moves it).
 */

#include <stdarg.h>
#include <stdio.h>
#include <math.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "objbase.h"
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

#ifndef RO_E_CLOSED
#define RO_E_CLOSED ((HRESULT)0x80000013)
#endif

LONG comp_object_count;
static CRITICAL_SECTION comp_cs;
static CRITICAL_SECTION_DEBUG comp_cs_debug =
{
    0, 0, &comp_cs, { &comp_cs_debug.ProcessLocksList, &comp_cs_debug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": comp_cs") }
};
static CRITICAL_SECTION comp_cs = { &comp_cs_debug, -1, 0, 0, 0, 0 };
void comp_lock(void) { EnterCriticalSection(&comp_cs); }
void comp_unlock(void) { LeaveCriticalSection(&comp_cs); }

#define OBJ_OF(i, field) CONTAINING_RECORD(i, struct cobj, field)

/* ---- identity and interface table ---- */

struct iface_entry
{
    const IID *iid;
    size_t offset;
    unsigned kinds;
    BOOL listed;                        /* reported by GetIids */
};

#define IE(name, field, kinds, listed) { &IID___x_ABI_CWindows_CUI_CComposition_C##name, offsetof(struct cobj, field), kinds, listed }
static const struct iface_entry iface_table[] =
{
    IE(ICompositionObject, objbase, KM_ALL, TRUE),
    IE(IVisual, visual, KM_VISUAL, TRUE),
    IE(IContainerVisual, container, KM_VISUAL, TRUE),
    IE(ISpriteVisual, sprite, KM(K_SPRITE), TRUE),
    IE(IVisualCollection, vcoll, KM(K_VCOLL), TRUE),
    IE(ICompositionBrush, brush, KM_BRUSH, TRUE),
    IE(ICompositionColorBrush, colorbrush, KM(K_COLORBRUSH), TRUE),
    IE(ICompositionSurfaceBrush, surfbrush, KM(K_SURFBRUSH), TRUE),
    IE(ICompositionClip, clip, KM(K_INSETCLIP), TRUE),
    IE(IInsetClip, inset, KM(K_INSETCLIP), TRUE),
    IE(ICompositionGraphicsDevice, gdev, KM(K_GDEVICE), TRUE),
    IE(ICompositionSurface, surface, KM(K_DSURFACE), TRUE),
    IE(ICompositionDrawingSurface, dsurf, KM(K_DSURFACE), TRUE),
    IE(ICompositionTarget, target, KM(K_TARGET), TRUE),
    { &IID___x_ABI_CWindows_CFoundation_CIClosable, offsetof(struct cobj, closable), KM_ALL, TRUE },
    { &IID_IAgileObject, offsetof(struct cobj, agile), KM_ALL, FALSE },
    { &IID_INitroDrawingSurfaceInterop, offsetof(struct cobj, dsinterop), KM(K_DSURFACE), FALSE },
    { &IID_INitroCompositionTest, offsetof(struct cobj, test), KM_VISUAL, FALSE },
};

static const WCHAR *const kind_names[] =
{
    L"Windows.UI.Composition.ContainerVisual", L"Windows.UI.Composition.SpriteVisual",
    L"Windows.UI.Composition.VisualCollection", L"Windows.UI.Composition.CompositionColorBrush",
    L"Windows.UI.Composition.CompositionSurfaceBrush", L"Windows.UI.Composition.InsetClip",
    L"Windows.UI.Composition.CompositionGraphicsDevice", L"Windows.UI.Composition.CompositionDrawingSurface",
    L"Windows.UI.Composition.Desktop.DesktopWindowTarget",
};

static void cobj_destroy(struct cobj *o);

static HRESULT STDMETHODCALLTYPE id_QueryInterface(IInspectable *iface, REFIID iid, void **out)
{
    struct cobj *o = OBJ_OF(iface, identity);
    size_t i;

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable))
        *out = &o->identity;
    else if (IsEqualGUID(iid, &IID_IMarshal) && o->marshal)
        return IUnknown_QueryInterface(o->marshal, iid, out);
    else
    {
        for (i = 0; i < ARRAY_SIZE(iface_table); i++)
            if ((iface_table[i].kinds & KM(o->kind)) && IsEqualGUID(iface_table[i].iid, iid))
            {
                *out = (char *)o + iface_table[i].offset;
                break;
            }
        if (!*out)
        {
            FIXME("%s: interface %s not implemented, returning E_NOINTERFACE.\n",
                  debugstr_w(kind_names[o->kind]), debugstr_guid(iid));
            return E_NOINTERFACE;
        }
    }
    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}

static ULONG STDMETHODCALLTYPE id_AddRef(IInspectable *iface)
{
    return InterlockedIncrement(&OBJ_OF(iface, identity)->ref);
}

static ULONG STDMETHODCALLTYPE id_Release(IInspectable *iface)
{
    struct cobj *o = OBJ_OF(iface, identity);
    ULONG ref = InterlockedDecrement(&o->ref);

    if (!ref) cobj_destroy(o);
    return ref;
}

static HRESULT STDMETHODCALLTYPE id_GetIids(IInspectable *iface, ULONG *count, IID **iids)
{
    struct cobj *o = OBJ_OF(iface, identity);
    ULONG n = 0;
    size_t i;
    IID *out;

    if (!count || !iids) return E_POINTER;
    for (i = 0; i < ARRAY_SIZE(iface_table); i++)
        if (iface_table[i].listed && (iface_table[i].kinds & KM(o->kind))) n++;
    if (!(out = CoTaskMemAlloc(n * sizeof(IID)))) return E_OUTOFMEMORY;
    n = 0;
    for (i = 0; i < ARRAY_SIZE(iface_table); i++)
        if (iface_table[i].listed && (iface_table[i].kinds & KM(o->kind))) out[n++] = *iface_table[i].iid;
    *count = n;
    *iids = out;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE id_GetRuntimeClassName(IInspectable *iface, HSTRING *name)
{
    const WCHAR *s = kind_names[OBJ_OF(iface, identity)->kind];

    if (!name) return E_POINTER;
    return WindowsCreateString(s, wcslen(s), name);
}

static HRESULT STDMETHODCALLTYPE id_GetTrustLevel(IInspectable *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static const IInspectableVtbl id_vtbl =
{
    id_QueryInterface, id_AddRef, id_Release, id_GetIids, id_GetRuntimeClassName, id_GetTrustLevel
};

/* IUnknown part of every slot forwards to the identity */
#define UNK_FWD(pfx, T, field) \
static HRESULT STDMETHODCALLTYPE pfx##_QueryInterface(T *i, REFIID iid, void **o) \
{ return id_QueryInterface(&OBJ_OF(i, field)->identity, iid, o); } \
static ULONG STDMETHODCALLTYPE pfx##_AddRef(T *i) { return id_AddRef(&OBJ_OF(i, field)->identity); } \
static ULONG STDMETHODCALLTYPE pfx##_Release(T *i) { return id_Release(&OBJ_OF(i, field)->identity); }
#define INSP_FWD(pfx, T, field) UNK_FWD(pfx, T, field) \
static HRESULT STDMETHODCALLTYPE pfx##_GetIids(T *i, ULONG *c, IID **iids) \
{ return id_GetIids(&OBJ_OF(i, field)->identity, c, iids); } \
static HRESULT STDMETHODCALLTYPE pfx##_GetRuntimeClassName(T *i, HSTRING *n) \
{ return id_GetRuntimeClassName(&OBJ_OF(i, field)->identity, n); } \
static HRESULT STDMETHODCALLTYPE pfx##_GetTrustLevel(T *i, TrustLevel *l) \
{ return id_GetTrustLevel(&OBJ_OF(i, field)->identity, l); }
#define INSP_HEAD(pfx) pfx##_QueryInterface, pfx##_AddRef, pfx##_Release, pfx##_GetIids, \
    pfx##_GetRuntimeClassName, pfx##_GetTrustLevel

INSP_FWD(objb, WICompositionObject, objbase)
INSP_FWD(vis, WIVisual, visual)
INSP_FWD(cont, WIContainerVisual, container)
INSP_FWD(spr, WISpriteVisual, sprite)
INSP_FWD(vcol, WIVisualCollection, vcoll)
INSP_FWD(brs, WICompositionBrush, brush)
INSP_FWD(cbr, WICompositionColorBrush, colorbrush)
INSP_FWD(sbr, WICompositionSurfaceBrush, surfbrush)
INSP_FWD(clp, WICompositionClip, clip)
INSP_FWD(ins, WIInsetClip, inset)
INSP_FWD(gdv, WICompositionGraphicsDevice, gdev)
INSP_FWD(srf, WICompositionSurface, surface)
INSP_FWD(dsf, WICompositionDrawingSurface, dsurf)
INSP_FWD(tgt, WICompositionTarget, target)
INSP_FWD(clo, WIClosable, closable)
UNK_FWD(agl, IAgileObject, agile)
UNK_FWD(tst, INitroCompositionTest, test)

static const WICompositionBrushVtbl brush_vtbl = { INSP_HEAD(brs) };
static const WICompositionClipVtbl clip_vtbl = { INSP_HEAD(clp) };
static const WICompositionSurfaceVtbl surface_vtbl = { INSP_HEAD(srf) };

struct cobj *cobj_from_iface(void *iface, size_t offset)
{
    return (struct cobj *)((char *)iface - offset);
}

/* an interface pointer is ours when its vtable is one of ours */
#define IS_OURS(p, vt) ((p) && *(const void *const *)(p) == (const void *)&(vt))

/* ---- lifetime ---- */

struct cobj *comp_alloc_obj(enum cobj_kind kind, IUnknown *compositor)
{
    struct cobj *o = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*o));

    if (!o) return NULL;
    o->kind = kind;
    o->ref = 1;
    o->identity.lpVtbl = &id_vtbl;
    o->objbase.lpVtbl = NULL;           /* filled in by comp_new_object */
    o->compositor = compositor;
    if (compositor) IUnknown_AddRef(compositor);
    o->anchor.X = o->anchor.Y = 0;
    o->scale.X = o->scale.Y = o->scale.Z = 1.0f;
    o->axis.Z = 1.0f;
    o->orientation.W = 1.0f;
    o->opacity = 1.0f;
    o->xform.M11 = o->xform.M22 = o->xform.M33 = o->xform.M44 = 1.0f;
    o->visible = TRUE;
    o->composite = 1;                   /* SourceOver is documented as the effective mode of Inherit at the root */
    o->stretch = CompositionStretch_UniformToFill;
    o->bitmap_interp = 1;
    o->halign = o->valign = 0.5f;
    o->color.A = 0xff;
    CoCreateFreeThreadedMarshaler((IUnknown *)&o->identity, &o->marshal);
    InterlockedIncrement(&comp_object_count);
    return o;
}

static void release_cobj(struct cobj *o)
{
    if (o) id_Release(&o->identity);
}

static void cobj_destroy(struct cobj *o)
{
    struct cobj **kids;
    struct cobj *vclip, *sbrush, *collection, *gfxdev, *root;
    IUnknown *bsurface;
    int i, n;

    /* a destroyed object has ref 0, keep it from being re-entered while its children are released */
    comp_lock();
    kids = o->kids; n = o->nkids;
    o->kids = NULL; o->nkids = o->capkids = 0;
    for (i = 0; i < n; i++) kids[i]->parent = NULL;
    if (o->collection) o->collection->owner = NULL;
    collection = o->collection; o->collection = NULL;
    vclip = o->vclip; o->vclip = NULL;
    sbrush = o->sbrush; o->sbrush = NULL;
    root = o->root; o->root = NULL;
    bsurface = o->bsurface; o->bsurface = NULL;
    gfxdev = o->gfxdev;
    comp_unlock();

    for (i = 0; i < n; i++) release_cobj(kids[i]);
    HeapFree(GetProcessHeap(), 0, kids);
    release_cobj(collection);
    release_cobj(vclip);
    release_cobj(sbrush);
    release_cobj(root);
    if (bsurface) IUnknown_Release(bsurface);

    if (o->kind == K_GDEVICE) gfx_device_free(o);
    if (o->kind == K_DSURFACE) { gfx_surface_free(o); o->gfxdev = NULL; release_cobj(gfxdev); }
    if (o->marshal) IUnknown_Release(o->marshal);
    if (o->compositor) IUnknown_Release(o->compositor);
    HeapFree(GetProcessHeap(), 0, o);
    InterlockedDecrement(&comp_object_count);
}

/* ---- IClosable / ICompositionObject ---- */

static HRESULT STDMETHODCALLTYPE clo_Close(WIClosable *i)
{
    struct cobj *o = OBJ_OF(i, closable);

    if (o->kind == K_GDEVICE || o->kind == K_DSURFACE)
    {
        if (o->kind == K_GDEVICE) gfx_device_free(o);
        else gfx_surface_free(o);
    }
    o->closed = TRUE;
    return S_OK;
}
static const WIClosableVtbl closable_vtbl = { INSP_HEAD(clo), clo_Close };

static const IAgileObjectVtbl agile_vtbl = { agl_QueryInterface, agl_AddRef, agl_Release };

static HRESULT STDMETHODCALLTYPE objb_get_Compositor(WICompositionObject *i, WICompositor **value)
{
    struct cobj *o = OBJ_OF(i, objbase);

    if (!value) return E_POINTER;
    *value = NULL;
    if (!o->compositor) return E_NOINTERFACE;
    return IUnknown_QueryInterface(o->compositor, &IID___x_ABI_CWindows_CUI_CComposition_CICompositor, (void **)value);
}

static HRESULT STDMETHODCALLTYPE objb_get_Dispatcher(WICompositionObject *i, __x_ABI_CWindows_CUI_CCore_CICoreDispatcher **value)
{
    FIXME("ICompositionObject::Dispatcher: returning NULL\n");
    if (!value) return E_POINTER;
    *value = NULL;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE objb_get_Properties(WICompositionObject *i, WUC(ICompositionPropertySet) **value)
{
    FIXME("ICompositionObject::Properties: not implemented\n");
    if (value) *value = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE objb_StartAnimation(WICompositionObject *i, HSTRING name, WUC(ICompositionAnimation) *animation)
{
    FIXME("ICompositionObject::StartAnimation: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE objb_StopAnimation(WICompositionObject *i, HSTRING name)
{
    FIXME("ICompositionObject::StopAnimation: not implemented\n");
    return E_NOTIMPL;
}

static const WICompositionObjectVtbl objbase_vtbl =
{
    INSP_HEAD(objb), objb_get_Compositor, objb_get_Dispatcher, objb_get_Properties, objb_StartAnimation, objb_StopAnimation
};

/* ---- IVisual ---- */

#define VIS(i) OBJ_OF(i, visual)
#define VGETPUT(N, T, F) \
static HRESULT STDMETHODCALLTYPE vis_get_##N(WIVisual *i, T *v) \
{ struct cobj *o = VIS(i); if (!v) return E_POINTER; comp_lock(); *v = (T)o->F; comp_unlock(); return S_OK; } \
static HRESULT STDMETHODCALLTYPE vis_put_##N(WIVisual *i, T v) \
{ struct cobj *o = VIS(i); comp_lock(); o->F = v; comp_unlock(); return S_OK; }

VGETPUT(AnchorPoint, Vec2, anchor)
VGETPUT(BackfaceVisibility, WUC(CompositionBackfaceVisibility), backface)
VGETPUT(BorderMode, WUC(CompositionBorderMode), border)
VGETPUT(CenterPoint, Vec3, center)
VGETPUT(CompositeMode, WUC(CompositionCompositeMode), composite)
VGETPUT(IsVisible, boolean, visible)
VGETPUT(Offset, Vec3, offset)
VGETPUT(Opacity, FLOAT, opacity)
VGETPUT(Orientation, Quat, orientation)
VGETPUT(RotationAngle, FLOAT, rotation)
VGETPUT(RotationAxis, Vec3, axis)
VGETPUT(Scale, Vec3, scale)
VGETPUT(Size, Vec2, size)
VGETPUT(TransformMatrix, Mat4, xform)

static HRESULT STDMETHODCALLTYPE vis_get_RotationAngleInDegrees(WIVisual *i, FLOAT *v)
{
    struct cobj *o = VIS(i);
    if (!v) return E_POINTER;
    comp_lock(); *v = o->rotation * (180.0f / 3.14159265358979f); comp_unlock();
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE vis_put_RotationAngleInDegrees(WIVisual *i, FLOAT v)
{
    struct cobj *o = VIS(i);
    comp_lock(); o->rotation = v * (3.14159265358979f / 180.0f); comp_unlock();
    return S_OK;
}

static struct cobj *clip_from(WICompositionClip *p)
{
    return IS_OURS(p, clip_vtbl) ? OBJ_OF(p, clip) : NULL;
}

static HRESULT STDMETHODCALLTYPE vis_get_Clip(WIVisual *i, WICompositionClip **v)
{
    struct cobj *o = VIS(i);

    if (!v) return E_POINTER;
    comp_lock();
    *v = o->vclip ? &o->vclip->clip : NULL;
    if (o->vclip) id_AddRef(&o->vclip->identity);
    comp_unlock();
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE vis_put_Clip(WIVisual *i, WICompositionClip *v)
{
    struct cobj *o = VIS(i), *old, *c = NULL;

    if (v && !(c = clip_from(v)))
    {
        FIXME("Visual.Clip: foreign or unsupported clip %p\n", v);
        return E_INVALIDARG;
    }
    if (c) id_AddRef(&c->identity);
    comp_lock(); old = o->vclip; o->vclip = c; comp_unlock();
    release_cobj(old);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE vis_get_Parent(WIVisual *i, WIContainerVisual **v)
{
    struct cobj *o = VIS(i);

    if (!v) return E_POINTER;
    comp_lock();
    *v = o->parent ? &o->parent->container : NULL;
    if (o->parent) id_AddRef(&o->parent->identity);
    comp_unlock();
    return S_OK;
}

static const WIVisualVtbl visual_vtbl =
{
    INSP_HEAD(vis),
    vis_get_AnchorPoint, vis_put_AnchorPoint,
    vis_get_BackfaceVisibility, vis_put_BackfaceVisibility,
    vis_get_BorderMode, vis_put_BorderMode,
    vis_get_CenterPoint, vis_put_CenterPoint,
    vis_get_Clip, vis_put_Clip,
    vis_get_CompositeMode, vis_put_CompositeMode,
    vis_get_IsVisible, vis_put_IsVisible,
    vis_get_Offset, vis_put_Offset,
    vis_get_Opacity, vis_put_Opacity,
    vis_get_Orientation, vis_put_Orientation,
    vis_get_Parent,
    vis_get_RotationAngle, vis_put_RotationAngle,
    vis_get_RotationAngleInDegrees, vis_put_RotationAngleInDegrees,
    vis_get_RotationAxis, vis_put_RotationAxis,
    vis_get_Scale, vis_put_Scale,
    vis_get_Size, vis_put_Size,
    vis_get_TransformMatrix, vis_put_TransformMatrix,
};

/* ---- ContainerVisual / VisualCollection ---- */

static HRESULT STDMETHODCALLTYPE cont_get_Children(WIContainerVisual *i, WIVisualCollection **v)
{
    struct cobj *o = OBJ_OF(i, container), *c;

    if (!v) return E_POINTER;
    *v = NULL;
    comp_lock();
    if (!o->collection)
    {
        comp_unlock();
        if (FAILED(comp_create(o->compositor, K_VCOLL, &c))) return E_OUTOFMEMORY;
        comp_lock();
        if (!o->collection) { o->collection = c; c->owner = o; c = NULL; }
        comp_unlock();
        release_cobj(c);                /* lost the race */
        comp_lock();
    }
    id_AddRef(&o->collection->identity);
    *v = &o->collection->vcoll;
    comp_unlock();
    return S_OK;
}

static const WIContainerVisualVtbl container_vtbl = { INSP_HEAD(cont), cont_get_Children };

#define COLL(i) OBJ_OF(i, vcoll)

static struct cobj *visual_from(WIVisual *p)
{
    return IS_OURS(p, visual_vtbl) ? VIS(p) : NULL;
}

static int kid_index(struct cobj *owner, struct cobj *child)
{
    int k;
    for (k = 0; k < owner->nkids; k++) if (owner->kids[k] == child) return k;
    return -1;
}

static void unlink_kid(struct cobj *owner, struct cobj *child)
{
    int k = kid_index(owner, child);

    if (k < 0) return;
    memmove(&owner->kids[k], &owner->kids[k + 1], (owner->nkids - k - 1) * sizeof(*owner->kids));
    owner->nkids--;
    child->parent = NULL;
}

enum { INS_TOP, INS_BOTTOM, INS_ABOVE, INS_BELOW };

static HRESULT collection_insert(struct cobj *c, WIVisual *childp, WIVisual *sibp, int mode)
{
    struct cobj *child = visual_from(childp), *sib = NULL, *owner, *a, **grown;
    BOOL addref = FALSE;
    int pos;

    if (!child) return E_INVALIDARG;
    if (sibp && !(sib = visual_from(sibp))) return E_INVALIDARG;

    comp_lock();
    if (!(owner = c->owner)) { comp_unlock(); return RO_E_CLOSED; }
    if (mode == INS_ABOVE && !sib) mode = INS_TOP;
    if (mode == INS_BELOW && !sib) mode = INS_BOTTOM;
    if (sib && (sib == child || sib->parent != owner)) { comp_unlock(); return E_INVALIDARG; }
    for (a = owner; a; a = a->parent)
        if (a == child) { comp_unlock(); return E_INVALIDARG; }

    if (child->parent) unlink_kid(child->parent, child);      /* the old parent's reference moves to the new one */
    else addref = TRUE;
    if (owner->nkids == owner->capkids)
    {
        int cap = owner->capkids ? owner->capkids * 2 : 4;
        if (owner->kids) grown = HeapReAlloc(GetProcessHeap(), 0, owner->kids, cap * sizeof(*grown));
        else grown = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*grown));
        if (!grown)
        {
            /* the child is unlinked: give its reference back */
            comp_unlock();
            if (!addref) release_cobj(child);
            return E_OUTOFMEMORY;
        }
        owner->kids = grown; owner->capkids = cap;
    }
    switch (mode)
    {
    case INS_BOTTOM: pos = 0; break;
    case INS_ABOVE: pos = kid_index(owner, sib) + 1; break;
    case INS_BELOW: pos = kid_index(owner, sib); break;
    default: pos = owner->nkids; break;
    }
    memmove(&owner->kids[pos + 1], &owner->kids[pos], (owner->nkids - pos) * sizeof(*owner->kids));
    owner->kids[pos] = child;
    owner->nkids++;
    child->parent = owner;
    if (addref) id_AddRef(&child->identity);
    comp_unlock();
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE vcol_get_Count(WIVisualCollection *i, INT32 *v)
{
    struct cobj *c = COLL(i);

    if (!v) return E_POINTER;
    comp_lock(); *v = c->owner ? c->owner->nkids : 0; comp_unlock();
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE vcol_InsertAbove(WIVisualCollection *i, WIVisual *child, WIVisual *sib)
{ return collection_insert(COLL(i), child, sib, INS_ABOVE); }
static HRESULT STDMETHODCALLTYPE vcol_InsertAtBottom(WIVisualCollection *i, WIVisual *child)
{ return collection_insert(COLL(i), child, NULL, INS_BOTTOM); }
static HRESULT STDMETHODCALLTYPE vcol_InsertAtTop(WIVisualCollection *i, WIVisual *child)
{ return collection_insert(COLL(i), child, NULL, INS_TOP); }
static HRESULT STDMETHODCALLTYPE vcol_InsertBelow(WIVisualCollection *i, WIVisual *child, WIVisual *sib)
{ return collection_insert(COLL(i), child, sib, INS_BELOW); }

static HRESULT STDMETHODCALLTYPE vcol_Remove(WIVisualCollection *i, WIVisual *childp)
{
    struct cobj *c = COLL(i), *child = visual_from(childp), *owner;
    BOOL removed = FALSE;

    if (!child) return E_INVALIDARG;
    comp_lock();
    if (!(owner = c->owner)) { comp_unlock(); return RO_E_CLOSED; }
    if (child->parent == owner) { unlink_kid(owner, child); removed = TRUE; }
    comp_unlock();
    if (removed) release_cobj(child);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE vcol_RemoveAll(WIVisualCollection *i)
{
    struct cobj *c = COLL(i), *owner, **kids;
    int k, n;

    comp_lock();
    if (!(owner = c->owner)) { comp_unlock(); return RO_E_CLOSED; }
    kids = owner->kids; n = owner->nkids;
    owner->kids = NULL; owner->nkids = owner->capkids = 0;
    for (k = 0; k < n; k++) kids[k]->parent = NULL;
    comp_unlock();
    for (k = 0; k < n; k++) release_cobj(kids[k]);
    HeapFree(GetProcessHeap(), 0, kids);
    return S_OK;
}

static const WIVisualCollectionVtbl vcoll_vtbl =
{
    INSP_HEAD(vcol), vcol_get_Count, vcol_InsertAbove, vcol_InsertAtBottom, vcol_InsertAtTop, vcol_InsertBelow,
    vcol_Remove, vcol_RemoveAll
};

/* ---- SpriteVisual and brushes ---- */

static struct cobj *brush_from(WICompositionBrush *p)
{
    return IS_OURS(p, brush_vtbl) ? OBJ_OF(p, brush) : NULL;
}

static HRESULT STDMETHODCALLTYPE spr_get_Brush(WISpriteVisual *i, WICompositionBrush **v)
{
    struct cobj *o = OBJ_OF(i, sprite);

    if (!v) return E_POINTER;
    comp_lock();
    *v = o->sbrush ? &o->sbrush->brush : NULL;
    if (o->sbrush) id_AddRef(&o->sbrush->identity);
    comp_unlock();
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE spr_put_Brush(WISpriteVisual *i, WICompositionBrush *v)
{
    struct cobj *o = OBJ_OF(i, sprite), *b = NULL, *old;

    if (v && !(b = brush_from(v)))
    {
        FIXME("SpriteVisual.Brush: foreign or unsupported brush %p\n", v);
        return E_INVALIDARG;
    }
    if (b) id_AddRef(&b->identity);
    comp_lock(); old = o->sbrush; o->sbrush = b; comp_unlock();
    release_cobj(old);
    return S_OK;
}
static const WISpriteVisualVtbl sprite_vtbl = { INSP_HEAD(spr), spr_get_Brush, spr_put_Brush };

static HRESULT STDMETHODCALLTYPE cbr_get_Color(WICompositionColorBrush *i, __x_ABI_CWindows_CUI_CColor *v)
{
    struct cobj *o = OBJ_OF(i, colorbrush);
    if (!v) return E_POINTER;
    comp_lock(); *v = o->color; comp_unlock();
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE cbr_put_Color(WICompositionColorBrush *i, __x_ABI_CWindows_CUI_CColor v)
{
    struct cobj *o = OBJ_OF(i, colorbrush);
    comp_lock(); o->color = v; comp_unlock();
    return S_OK;
}
static const WICompositionColorBrushVtbl colorbrush_vtbl = { INSP_HEAD(cbr), cbr_get_Color, cbr_put_Color };

#define SB(i) OBJ_OF(i, surfbrush)
#define SBGETPUT(N, T, F) \
static HRESULT STDMETHODCALLTYPE sbr_get_##N(WICompositionSurfaceBrush *i, T *v) \
{ struct cobj *o = SB(i); if (!v) return E_POINTER; comp_lock(); *v = (T)o->F; comp_unlock(); return S_OK; } \
static HRESULT STDMETHODCALLTYPE sbr_put_##N(WICompositionSurfaceBrush *i, T v) \
{ struct cobj *o = SB(i); comp_lock(); o->F = v; comp_unlock(); return S_OK; }

SBGETPUT(BitmapInterpolationMode, WUC(CompositionBitmapInterpolationMode), bitmap_interp)
SBGETPUT(Stretch, WUC(CompositionStretch), stretch)

static HRESULT STDMETHODCALLTYPE sbr_get_HorizontalAlignmentRatio(WICompositionSurfaceBrush *i, FLOAT *v)
{
    struct cobj *o = SB(i);
    if (!v) return E_POINTER;
    comp_lock(); *v = o->halign; comp_unlock();
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE sbr_put_HorizontalAlignmentRatio(WICompositionSurfaceBrush *i, FLOAT v)
{
    struct cobj *o = SB(i);
    comp_lock(); o->halign = v < 0 ? 0 : v > 1 ? 1 : v; comp_unlock();      /* documented: clamped to 0..1 */
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE sbr_get_VerticalAlignmentRatio(WICompositionSurfaceBrush *i, FLOAT *v)
{
    struct cobj *o = SB(i);
    if (!v) return E_POINTER;
    comp_lock(); *v = o->valign; comp_unlock();
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE sbr_put_VerticalAlignmentRatio(WICompositionSurfaceBrush *i, FLOAT v)
{
    struct cobj *o = SB(i);
    comp_lock(); o->valign = v < 0 ? 0 : v > 1 ? 1 : v; comp_unlock();
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sbr_get_Surface(WICompositionSurfaceBrush *i, WICompositionSurface **v)
{
    struct cobj *o = SB(i);
    if (!v) return E_POINTER;
    *v = NULL;
    comp_lock();
    if (o->bsurface) IUnknown_QueryInterface(o->bsurface, &IID___x_ABI_CWindows_CUI_CComposition_CICompositionSurface, (void **)v);
    comp_unlock();
    return S_OK;
}

HRESULT comp_surface_brush_set_surface(struct cobj *brush, WICompositionSurface *surface)
{
    IUnknown *id = NULL, *old;

    if (surface)
    {
        /* only our own drawing surfaces can be painted; remember the identity */
        if (!IS_OURS(surface, surface_vtbl))
        {
            FIXME("SurfaceBrush.Surface: foreign ICompositionSurface %p is not supported\n", surface);
            return E_INVALIDARG;
        }
        id = (IUnknown *)&OBJ_OF(surface, surface)->identity;
        IUnknown_AddRef(id);
    }
    comp_lock(); old = brush->bsurface; brush->bsurface = id; comp_unlock();
    if (old) IUnknown_Release(old);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sbr_put_Surface(WICompositionSurfaceBrush *i, WICompositionSurface *v)
{
    return comp_surface_brush_set_surface(SB(i), v);
}

static const WICompositionSurfaceBrushVtbl surfbrush_vtbl =
{
    INSP_HEAD(sbr),
    sbr_get_BitmapInterpolationMode, sbr_put_BitmapInterpolationMode,
    sbr_get_HorizontalAlignmentRatio, sbr_put_HorizontalAlignmentRatio,
    sbr_get_Stretch, sbr_put_Stretch,
    sbr_get_Surface, sbr_put_Surface,
    sbr_get_VerticalAlignmentRatio, sbr_put_VerticalAlignmentRatio,
};

#define INSETGETPUT(N, F) \
static HRESULT STDMETHODCALLTYPE ins_get_##N(WIInsetClip *i, FLOAT *v) \
{ struct cobj *o = OBJ_OF(i, inset); if (!v) return E_POINTER; comp_lock(); *v = o->F; comp_unlock(); return S_OK; } \
static HRESULT STDMETHODCALLTYPE ins_put_##N(WIInsetClip *i, FLOAT v) \
{ struct cobj *o = OBJ_OF(i, inset); comp_lock(); o->F = v; comp_unlock(); return S_OK; }
INSETGETPUT(BottomInset, inset_b)
INSETGETPUT(LeftInset, inset_l)
INSETGETPUT(RightInset, inset_r)
INSETGETPUT(TopInset, inset_t)
static const WIInsetClipVtbl inset_vtbl =
{
    INSP_HEAD(ins), ins_get_BottomInset, ins_put_BottomInset, ins_get_LeftInset, ins_put_LeftInset,
    ins_get_RightInset, ins_put_RightInset, ins_get_TopInset, ins_put_TopInset
};

/* ---- graphics device and surface slots (methods in compgfx.c) ---- */

static HRESULT STDMETHODCALLTYPE gdv_CreateDrawingSurface(WICompositionGraphicsDevice *i, __x_ABI_CWindows_CFoundation_CSize pixels,
        __x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat format,
        __x_ABI_CWindows_CGraphics_CDirectX_CDirectXAlphaMode mode, WICompositionDrawingSurface **result)
{
    struct cobj *dev = OBJ_OF(i, gdev), *s;
    Vec2 sz;
    HRESULT hr;

    if (!result) return E_POINTER;
    *result = NULL;
    sz.X = pixels.Width; sz.Y = pixels.Height;
    if (FAILED(hr = gfx_surface_create(dev, sz, (int)format, (int)mode, &s))) return hr;
    *result = &s->dsurf;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE gdv_add_RenderingDeviceReplaced(WICompositionGraphicsDevice *i,
        __FITypedEventHandler_2_Windows__CUI__CComposition__CCompositionGraphicsDevice_Windows__CUI__CComposition__CRenderingDeviceReplacedEventArgs *handler,
        EventRegistrationToken *token)
{
    /* the device is never lost here (WARP / the app's device): accept the handler, never raise it */
    FIXME("CompositionGraphicsDevice.RenderingDeviceReplaced: handler accepted, never raised\n");
    if (token) token->value = 1;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE gdv_remove_RenderingDeviceReplaced(WICompositionGraphicsDevice *i, EventRegistrationToken token)
{
    return S_OK;
}

static const WICompositionGraphicsDeviceVtbl gdev_vtbl =
{
    INSP_HEAD(gdv), gdv_CreateDrawingSurface, gdv_add_RenderingDeviceReplaced, gdv_remove_RenderingDeviceReplaced
};

#define DS(i) OBJ_OF(i, dsurf)
static HRESULT STDMETHODCALLTYPE dsf_get_AlphaMode(WICompositionDrawingSurface *i, __x_ABI_CWindows_CGraphics_CDirectX_CDirectXAlphaMode *v)
{
    if (!v) return E_POINTER;
    *v = (__x_ABI_CWindows_CGraphics_CDirectX_CDirectXAlphaMode)DS(i)->alphamode;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE dsf_get_PixelFormat(WICompositionDrawingSurface *i, __x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat *v)
{
    if (!v) return E_POINTER;
    *v = (__x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat)DS(i)->pixfmt;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE dsf_get_Size(WICompositionDrawingSurface *i, __x_ABI_CWindows_CFoundation_CSize *v)
{
    struct cobj *o = DS(i);
    if (!v) return E_POINTER;
    comp_lock(); v->Width = (float)o->width; v->Height = (float)o->height; comp_unlock();
    return S_OK;
}
static const WICompositionDrawingSurfaceVtbl dsurf_vtbl =
{
    INSP_HEAD(dsf), dsf_get_AlphaMode, dsf_get_PixelFormat, dsf_get_Size
};

/* ---- CPU renderer and dump (test hook INitroCompositionTest) ---- */

struct m2 { float a, b, c, d, e, f; };      /* x' = a x + c y + e, y' = b x + d y + f */

static struct m2 m2_ident(void) { struct m2 m = { 1, 0, 0, 1, 0, 0 }; return m; }

/* apply A first, then B */
static struct m2 m2_then(struct m2 A, struct m2 B)
{
    struct m2 r;
    r.a = B.a * A.a + B.c * A.b;
    r.b = B.b * A.a + B.d * A.b;
    r.c = B.a * A.c + B.c * A.d;
    r.d = B.b * A.c + B.d * A.d;
    r.e = B.a * A.e + B.c * A.f + B.e;
    r.f = B.b * A.e + B.d * A.f + B.f;
    return r;
}

static BOOL m2_invert(struct m2 m, struct m2 *inv)
{
    float det = m.a * m.d - m.b * m.c;

    if (fabsf(det) < 1e-9f) return FALSE;
    inv->a = m.d / det;  inv->b = -m.b / det;
    inv->c = -m.c / det; inv->d = m.a / det;
    inv->e = -(inv->a * m.e + inv->c * m.f);
    inv->f = -(inv->b * m.e + inv->d * m.f);
    return TRUE;
}

static void m2_apply(struct m2 m, float x, float y, float *ox, float *oy)
{
    *ox = m.a * x + m.c * y + m.e;
    *oy = m.b * x + m.d * y + m.f;
}

static struct m2 m2_about(struct m2 lin, float cx, float cy)       /* linear part lin about (cx, cy) */
{
    lin.e = cx - (lin.a * cx + lin.c * cy);
    lin.f = cy - (lin.b * cx + lin.d * cy);
    return lin;
}

/* local space of a visual -> its parent's space (2D part only; order: centre scale/rotate, anchor, matrix, offset) */
static struct m2 visual_local(const struct cobj *v)
{
    struct m2 m = m2_ident(), t = m2_ident(), s;
    float ang = v->rotation;

    s.a = v->scale.X; s.b = 0; s.c = 0; s.d = v->scale.Y; s.e = s.f = 0;
    m = m2_about(s, v->center.X, v->center.Y);
    if (v->orientation.X == 0 && v->orientation.Y == 0 && (v->orientation.Z != 0))
        ang += 2.0f * atan2f(v->orientation.Z, v->orientation.W);
    else if (v->orientation.X != 0 || v->orientation.Y != 0)
        FIXME("3D orientation ignored by the test renderer\n");
    if (ang != 0)
    {
        struct m2 r = { cosf(ang), sinf(ang), -sinf(ang), cosf(ang), 0, 0 };
        if (v->axis.X != 0 || v->axis.Y != 0) FIXME("rotation axis other than Z ignored by the test renderer\n");
        m = m2_then(m, m2_about(r, v->center.X, v->center.Y));
    }
    t.e = -v->anchor.X * v->size.X; t.f = -v->anchor.Y * v->size.Y;
    m = m2_then(m, t);
    if (v->xform.M11 != 1 || v->xform.M12 != 0 || v->xform.M21 != 0 || v->xform.M22 != 1 ||
        v->xform.M41 != 0 || v->xform.M42 != 0)
    {
        struct m2 x = { v->xform.M11, v->xform.M12, v->xform.M21, v->xform.M22, v->xform.M41, v->xform.M42 };
        m = m2_then(m, x);
    }
    t = m2_ident(); t.e = v->offset.X; t.f = v->offset.Y;
    return m2_then(m, t);
}

#define MAX_CLIPS 16
struct clip_rec { struct m2 inv; float l, t, r, b; };

struct rctx
{
    BYTE *bgra; UINT width, height, stride;
    struct clip_rec clips[MAX_CLIPS];
    int nclips;
};

struct sample_src { BYTE *px; UINT w, h; float ox, oy, sx, sy; BOOL linear; };

static void fetch(const struct sample_src *s, int x, int y, float out[4])
{
    const BYTE *p;

    if (x < 0) x = 0; else if (x >= (int)s->w) x = s->w - 1;
    if (y < 0) y = 0; else if (y >= (int)s->h) y = s->h - 1;
    p = s->px + ((size_t)y * s->w + x) * 4;
    out[0] = p[0]; out[1] = p[1]; out[2] = p[2]; out[3] = p[3];
}

/* premultiplied BGRA of the brush at local point (lx, ly) of a w x h visual; FALSE = no paint */
static BOOL sample_brush(struct cobj *br, const struct sample_src *s, float lx, float ly, float out[4])
{
    if (br->kind == K_COLORBRUSH)
    {
        float a = br->color.A;
        out[0] = br->color.B * a / 255.0f; out[1] = br->color.G * a / 255.0f;
        out[2] = br->color.R * a / 255.0f; out[3] = a;
        return TRUE;
    }
    if (!s || !s->px) return FALSE;
    {
        float u = (lx - s->ox) / s->sx, v = (ly - s->oy) / s->sy;      /* in surface pixels */
        float c00[4], c10[4], c01[4], c11[4];
        int x0, y0, k;
        float fx, fy;

        if (u < 0 || v < 0 || u >= s->w || v >= s->h) return FALSE;
        if (!s->linear)
        {
            fetch(s, (int)u, (int)v, out);
            return TRUE;
        }
        u -= 0.5f; v -= 0.5f;
        x0 = (int)floorf(u); y0 = (int)floorf(v);
        fx = u - x0; fy = v - y0;
        fetch(s, x0, y0, c00); fetch(s, x0 + 1, y0, c10); fetch(s, x0, y0 + 1, c01); fetch(s, x0 + 1, y0 + 1, c11);
        for (k = 0; k < 4; k++)
            out[k] = (c00[k] * (1 - fx) + c10[k] * fx) * (1 - fy) + (c01[k] * (1 - fx) + c11[k] * fx) * fy;
        return TRUE;
    }
}

static void render_visual(struct cobj *v, struct m2 parentm, float parent_opacity, struct rctx *ctx)
{
    struct m2 m, inv;
    float opacity;
    int saved = ctx->nclips, k;

    if (!v->visible) return;
    opacity = v->opacity < 0 ? 0 : v->opacity > 1 ? 1 : v->opacity;
    opacity *= parent_opacity;
    m = m2_then(visual_local(v), parentm);

    if (v->vclip && v->vclip->kind == K_INSETCLIP && ctx->nclips < MAX_CLIPS && m2_invert(m, &inv))
    {
        struct clip_rec *c = &ctx->clips[ctx->nclips++];
        c->inv = inv;
        c->l = v->vclip->inset_l; c->t = v->vclip->inset_t;
        c->r = v->size.X - v->vclip->inset_r; c->b = v->size.Y - v->vclip->inset_b;
    }

    if (v->kind == K_SPRITE && v->sbrush && v->size.X > 0 && v->size.Y > 0 && opacity > 0 && m2_invert(m, &inv))
    {
        struct sample_src src = { 0 };
        struct cobj *br = v->sbrush;
        BYTE *snap = NULL;
        float xs[4], ys[4], minx, maxx, miny, maxy;
        int x0, x1, y0, y1, px, py;
        BOOL ok = TRUE;

        if (br->kind == K_SURFBRUSH)
        {
            struct cobj *surf = br->bsurface ? CONTAINING_RECORD(br->bsurface, struct cobj, identity) : NULL;
            ok = FALSE;
            if (surf)
            {
                if (SUCCEEDED(gfx_surface_snapshot(surf, &snap, &src.w, &src.h)) && src.w && src.h)
                {
                    float sx = 1, sy = 1, W = v->size.X, H = v->size.Y;
                    switch (br->stretch)
                    {
                    case CompositionStretch_Fill: sx = W / src.w; sy = H / src.h; break;
                    case CompositionStretch_Uniform: sx = sy = fminf(W / src.w, H / src.h); break;
                    case CompositionStretch_UniformToFill: sx = sy = fmaxf(W / src.w, H / src.h); break;
                    default: break;
                    }
                    src.px = snap; src.sx = sx; src.sy = sy;
                    src.ox = (W - src.w * sx) * br->halign;
                    src.oy = (H - src.h * sy) * br->valign;
                    src.linear = br->bitmap_interp != CompositionBitmapInterpolationMode_NearestNeighbor;
                    ok = TRUE;
                }
            }
        }
        if (ok)
        {
            m2_apply(m, 0, 0, &xs[0], &ys[0]);
            m2_apply(m, v->size.X, 0, &xs[1], &ys[1]);
            m2_apply(m, 0, v->size.Y, &xs[2], &ys[2]);
            m2_apply(m, v->size.X, v->size.Y, &xs[3], &ys[3]);
            minx = maxx = xs[0]; miny = maxy = ys[0];
            for (k = 1; k < 4; k++)
            {
                minx = fminf(minx, xs[k]); maxx = fmaxf(maxx, xs[k]);
                miny = fminf(miny, ys[k]); maxy = fmaxf(maxy, ys[k]);
            }
            x0 = (int)floorf(minx); x1 = (int)ceilf(maxx); y0 = (int)floorf(miny); y1 = (int)ceilf(maxy);
            if (x0 < 0) x0 = 0;
            if (y0 < 0) y0 = 0;
            if (x1 > (int)ctx->width) x1 = ctx->width;
            if (y1 > (int)ctx->height) y1 = ctx->height;
            for (py = y0; py < y1; py++)
                for (px = x0; px < x1; px++)
                {
                    float lx, ly, c[4], inva;
                    BYTE *d = ctx->bgra + (size_t)py * ctx->stride + (size_t)px * 4;
                    BOOL inside = TRUE;

                    m2_apply(inv, px + 0.5f, py + 0.5f, &lx, &ly);
                    if (lx < 0 || ly < 0 || lx >= v->size.X || ly >= v->size.Y) continue;
                    for (k = 0; k < ctx->nclips && inside; k++)
                    {
                        float cx, cy;
                        /* clip rectangles live in their visual's space: map the pixel through its inverse */
                        m2_apply(ctx->clips[k].inv, px + 0.5f, py + 0.5f, &cx, &cy);
                        inside = cx >= ctx->clips[k].l && cx < ctx->clips[k].r && cy >= ctx->clips[k].t && cy < ctx->clips[k].b;
                    }
                    if (!inside) continue;
                    if (!sample_brush(br, &src, lx, ly, c)) continue;
                    for (k = 0; k < 4; k++) c[k] *= opacity;
                    inva = 1.0f - c[3] / 255.0f;
                    for (k = 0; k < 4; k++)
                    {
                        float r = c[k] + d[k] * inva + 0.5f;
                        d[k] = r > 255 ? 255 : (BYTE)r;
                    }
                }
        }
        HeapFree(GetProcessHeap(), 0, snap);
    }

    for (k = 0; k < v->nkids; k++) render_visual(v->kids[k], m, opacity, ctx);
    ctx->nclips = saved;
}

static HRESULT STDMETHODCALLTYPE tst_RenderToBitmap(INitroCompositionTest *i, UINT width, UINT height, void *bgra, UINT stride)
{
    struct cobj *o = OBJ_OF(i, test);
    struct rctx *ctx;
    UINT y;

    if (!bgra || !width || !height || stride < width * 4) return E_INVALIDARG;
    if (!(ctx = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ctx)))) return E_OUTOFMEMORY;
    ctx->bgra = bgra; ctx->width = width; ctx->height = height; ctx->stride = stride;
    for (y = 0; y < height; y++) memset(ctx->bgra + (size_t)y * stride, 0, width * 4);
    comp_lock();
    render_visual(o, m2_ident(), 1.0f, ctx);
    comp_unlock();
    HeapFree(GetProcessHeap(), 0, ctx);
    return S_OK;
}

struct dump { char *buf; UINT size, len; };

static void dump_printf(struct dump *d, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (d->len + 1 >= d->size) return;
    va_start(ap, fmt);
    n = vsnprintf(d->buf + d->len, d->size - d->len, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    d->len += (UINT)n < d->size - d->len ? (UINT)n : d->size - d->len - 1;
}

static void dump_visual(struct dump *d, struct cobj *v, int depth)
{
    int k;

    dump_printf(d, "%*s%s offset=(%g,%g,%g) size=(%g,%g) opacity=%g%s", depth * 2, "",
                v->kind == K_SPRITE ? "SpriteVisual" : "ContainerVisual", v->offset.X, v->offset.Y, v->offset.Z,
                v->size.X, v->size.Y, v->opacity, v->visible ? "" : " hidden");
    if (v->vclip) dump_printf(d, " clip=inset(%g,%g,%g,%g)", v->vclip->inset_l, v->vclip->inset_t, v->vclip->inset_r, v->vclip->inset_b);
    if (v->sbrush)
    {
        if (v->sbrush->kind == K_COLORBRUSH)
            dump_printf(d, " brush=color(a%u,r%u,g%u,b%u)", v->sbrush->color.A, v->sbrush->color.R, v->sbrush->color.G, v->sbrush->color.B);
        else
            dump_printf(d, " brush=surface(%s stretch=%d)", v->sbrush->bsurface ? "set" : "none", v->sbrush->stretch);
    }
    dump_printf(d, "\n");
    for (k = 0; k < v->nkids; k++) dump_visual(d, v->kids[k], depth + 1);
}

static HRESULT STDMETHODCALLTYPE tst_DumpTree(INitroCompositionTest *i, char *buffer, UINT size)
{
    struct cobj *o = OBJ_OF(i, test);
    struct dump d;

    if (!buffer || !size) return E_INVALIDARG;
    d.buf = buffer; d.size = size; d.len = 0; buffer[0] = 0;
    comp_lock();
    dump_visual(&d, o, 0);
    comp_unlock();
    TRACE("scene graph:\n%s", debugstr_a(buffer));
    return S_OK;
}

static const INitroCompositionTestVtbl nitro_test_vtbl_impl =
{
    tst_QueryInterface, tst_AddRef, tst_Release, tst_RenderToBitmap, tst_DumpTree
};

/* ---- creation ---- */

/* ---- DesktopWindowTarget: CompositionTarget.Root (documented); created by ICompositorDesktopInterop ---- */

#define TGT(i) OBJ_OF(i, target)

static HRESULT STDMETHODCALLTYPE tgt_get_Root(WICompositionTarget *i, WIVisual **v)
{
    struct cobj *o = TGT(i);

    if (!v) return E_POINTER;
    comp_lock();
    *v = o->root ? &o->root->visual : NULL;
    if (o->root) id_AddRef(&o->root->identity);
    comp_unlock();
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE tgt_put_Root(WICompositionTarget *i, WIVisual *v)
{
    struct cobj *o = TGT(i), *old, *r = NULL;

    if (v && !(r = visual_from(v)))
    {
        FIXME("CompositionTarget.Root: foreign visual %p\n", v);
        return E_INVALIDARG;
    }
    if (r) id_AddRef(&r->identity);
    comp_lock(); old = o->root; o->root = r; comp_unlock();
    release_cobj(old);
    return S_OK;
}

static const WICompositionTargetVtbl target_vtbl = { INSP_HEAD(tgt), tgt_get_Root, tgt_put_Root };

HRESULT comp_new_desktop_target(IUnknown *compositor, HWND hwnd, BOOL topmost, IInspectable **out)
{
    struct cobj *o;
    HRESULT hr;

    if (FAILED(hr = comp_create(compositor, K_TARGET, &o))) return hr;
    o->hwnd = hwnd;
    o->topmost = topmost;
    FIXME("DesktopWindowTarget for window %p: the visual tree is not presented yet (no window surfaces)\n", hwnd);
    *out = &o->identity;
    return S_OK;
}

HRESULT comp_create(IUnknown *compositor, enum cobj_kind kind, struct cobj **out)
{
    struct cobj *o = comp_alloc_obj(kind, compositor);

    if (!o) return E_OUTOFMEMORY;
    o->objbase.lpVtbl = &objbase_vtbl;
    o->visual.lpVtbl = &visual_vtbl;
    o->container.lpVtbl = &container_vtbl;
    o->sprite.lpVtbl = &sprite_vtbl;
    o->vcoll.lpVtbl = &vcoll_vtbl;
    o->brush.lpVtbl = &brush_vtbl;
    o->colorbrush.lpVtbl = &colorbrush_vtbl;
    o->surfbrush.lpVtbl = &surfbrush_vtbl;
    o->clip.lpVtbl = &clip_vtbl;
    o->inset.lpVtbl = &inset_vtbl;
    o->gdev.lpVtbl = &gdev_vtbl;
    o->surface.lpVtbl = &surface_vtbl;
    o->dsurf.lpVtbl = &dsurf_vtbl;
    o->target.lpVtbl = &target_vtbl;
    o->dsinterop.lpVtbl = &nitro_dsinterop_vtbl;
    o->test.lpVtbl = &nitro_test_vtbl_impl;
    o->closable.lpVtbl = &closable_vtbl;
    o->agile.lpVtbl = &agile_vtbl;
    *out = o;
    return S_OK;
}

HRESULT comp_new_object(IUnknown *compositor, enum cobj_kind kind, REFIID want, void **out)
{
    struct cobj *o;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;
    if (FAILED(hr = comp_create(compositor, kind, &o))) return hr;
    hr = id_QueryInterface(&o->identity, want, out);
    id_Release(&o->identity);
    return hr;
}

HRESULT comp_new_graphics_device(IUnknown *compositor, IUnknown *device, WICompositionGraphicsDevice **out)
{
    struct cobj *o;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;
    if (FAILED(hr = comp_create(compositor, K_GDEVICE, &o))) return hr;
    if (SUCCEEDED(hr = gfx_device_init(o, device))) *out = &o->gdev, id_AddRef(&o->identity);
    id_Release(&o->identity);
    return hr;
}
