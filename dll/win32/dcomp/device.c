/*
 * Copyright 2020 Nikolay Sivov for CodeWeavers
 * Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#include <stdarg.h>
#include <stdlib.h>
#include <math.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "objidl.h"
#include "dxgi1_6.h"
#include "initguid.h"
/* types of the wined3d methods of the header, not used here */
struct wined3d_resource;
struct wined3d_texture;
#include "wine/winedxgi.h"
#include "dcomp_private.h"
#include "wine/debug.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

/* DirectComposition, the part of it a software renderer needs to show a swap chain in a window:
 * DCompositionCreateDevice gives an IDCompositionDevice whose targets (one per window) hold a tree of visuals
 * with offsets and content. On Commit, every composition swap chain (IDXGIFactory2::CreateSwapChainForComposition)
 * that is the content of a visual of a target is told its window and position; its presents then copy into that
 * window. Surfaces, transforms, clips, effects and animations are not implemented (E_NOTIMPL), and neither are
 * the devices of DCompositionCreateDevice2 and 3. Without a desktop compositor, content is drawn into the window
 * itself: it is not kept when the window is painted over until the next present. */

static CRITICAL_SECTION dcomp_cs;
static CRITICAL_SECTION_DEBUG dcomp_cs_debug =
{
    0, 0, &dcomp_cs,
    { &dcomp_cs_debug.ProcessLocksList, &dcomp_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": dcomp_cs") }
};
static CRITICAL_SECTION dcomp_cs = { &dcomp_cs_debug, -1, 0, 0, 0, 0 };

/* every live target of the process, to refuse a second one on the same window and layer */
static struct list dcomp_targets = LIST_INIT(dcomp_targets);

struct dcomp_target;

struct dcomp_binding
{
    IWineDXGICompositionSwapChain *swapchain;
    struct dcomp_target *target;
    HWND window;
    POINT offset;
};

struct dcomp_device
{
    IDCompositionDevice IDCompositionDevice_iface;
    LONG refcount;
    IUnknown *rendering_device;
    struct dcomp_binding *bound;
    SIZE_T bound_count;
};

struct dcomp_visual
{
    IDCompositionVisual IDCompositionVisual_iface;
    LONG refcount;
    struct dcomp_device *device;
    struct dcomp_visual *parent;
    BOOL is_root;
    float offset_x, offset_y;
    IUnknown *content;
    struct dcomp_visual **children;
    SIZE_T child_count, child_size;
};

struct dcomp_target
{
    IDCompositionTarget IDCompositionTarget_iface;
    LONG refcount;
    struct list entry;
    struct dcomp_device *device;
    HWND window;
    BOOL topmost;
    struct dcomp_visual *root;
};

static const IDCompositionVisualVtbl dcomp_visual_vtbl;

static inline struct dcomp_device *impl_from_IDCompositionDevice(IDCompositionDevice *iface)
{
    return CONTAINING_RECORD(iface, struct dcomp_device, IDCompositionDevice_iface);
}

static inline struct dcomp_target *impl_from_IDCompositionTarget(IDCompositionTarget *iface)
{
    return CONTAINING_RECORD(iface, struct dcomp_target, IDCompositionTarget_iface);
}

static inline struct dcomp_visual *impl_from_IDCompositionVisual(IDCompositionVisual *iface)
{
    return CONTAINING_RECORD(iface, struct dcomp_visual, IDCompositionVisual_iface);
}

/* a visual of this module and of this device, or NULL */
static struct dcomp_visual *unsafe_visual(IDCompositionVisual *iface, struct dcomp_device *device)
{
    struct dcomp_visual *visual;

    if (!iface || iface->lpVtbl != &dcomp_visual_vtbl)
        return NULL;
    visual = impl_from_IDCompositionVisual(iface);
    return visual->device == device ? visual : NULL;
}

/* -------------------------------------------------------------------------------------------------- visual */

static HRESULT STDMETHODCALLTYPE dcomp_visual_QueryInterface(IDCompositionVisual *iface, REFIID iid, void **out)
{
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (!out)
        return E_POINTER;

    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IDCompositionVisual))
    {
        IDCompositionVisual_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE dcomp_visual_AddRef(IDCompositionVisual *iface)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);
    ULONG refcount = InterlockedIncrement(&visual->refcount);

    TRACE("%p increasing refcount to %lu.\n", iface, refcount);
    return refcount;
}

static void dcomp_visual_remove_children(struct dcomp_visual *visual)
{
    SIZE_T i;

    for (i = 0; i < visual->child_count; ++i)
    {
        visual->children[i]->parent = NULL;
        IDCompositionVisual_Release(&visual->children[i]->IDCompositionVisual_iface);
    }
    visual->child_count = 0;
}

static ULONG STDMETHODCALLTYPE dcomp_visual_Release(IDCompositionVisual *iface)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);
    ULONG refcount = InterlockedDecrement(&visual->refcount);

    TRACE("%p decreasing refcount to %lu.\n", iface, refcount);

    if (!refcount)
    {
        EnterCriticalSection(&dcomp_cs);
        dcomp_visual_remove_children(visual);
        LeaveCriticalSection(&dcomp_cs);
        free(visual->children);
        if (visual->content)
            IUnknown_Release(visual->content);
        IDCompositionDevice_Release(&visual->device->IDCompositionDevice_iface);
        free(visual);
    }
    return refcount;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetOffsetXAnimation(IDCompositionVisual *iface, IUnknown *animation)
{
    FIXME("iface %p, animation %p stub!\n", iface, animation);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetOffsetX(IDCompositionVisual *iface, float offset)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);

    TRACE("iface %p, offset %.8e.\n", iface, offset);

    if (!isfinite(offset))
        return E_INVALIDARG;
    EnterCriticalSection(&dcomp_cs);
    visual->offset_x = offset;
    LeaveCriticalSection(&dcomp_cs);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetOffsetYAnimation(IDCompositionVisual *iface, IUnknown *animation)
{
    FIXME("iface %p, animation %p stub!\n", iface, animation);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetOffsetY(IDCompositionVisual *iface, float offset)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);

    TRACE("iface %p, offset %.8e.\n", iface, offset);

    if (!isfinite(offset))
        return E_INVALIDARG;
    EnterCriticalSection(&dcomp_cs);
    visual->offset_y = offset;
    LeaveCriticalSection(&dcomp_cs);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetTransformObject(IDCompositionVisual *iface, IUnknown *transform)
{
    TRACE("iface %p, transform %p.\n", iface, transform);

    if (!transform)
        return S_OK;
    FIXME("Transforms are not implemented.\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetTransform(IDCompositionVisual *iface, const void *matrix)
{
    FIXME("iface %p, matrix %p stub!\n", iface, matrix);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetTransformParent(IDCompositionVisual *iface, IDCompositionVisual *parent)
{
    /* only transforms are taken from the transform parent, and there are none */
    TRACE("iface %p, parent %p.\n", iface, parent);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetEffect(IDCompositionVisual *iface, IUnknown *effect)
{
    TRACE("iface %p, effect %p.\n", iface, effect);

    if (!effect)
        return S_OK;
    FIXME("Effects are not implemented.\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetBitmapInterpolationMode(IDCompositionVisual *iface, int mode)
{
    /* content is shown at its size, nothing is interpolated */
    TRACE("iface %p, mode %d.\n", iface, mode);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetBorderMode(IDCompositionVisual *iface, int mode)
{
    TRACE("iface %p, mode %d.\n", iface, mode);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetClipObject(IDCompositionVisual *iface, IUnknown *clip)
{
    TRACE("iface %p, clip %p.\n", iface, clip);

    if (!clip)
        return S_OK;
    FIXME("Clips are not implemented.\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetClip(IDCompositionVisual *iface, const void *rect)
{
    FIXME("iface %p, rect %p stub!\n", iface, rect);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetContent(IDCompositionVisual *iface, IUnknown *content)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);
    IUnknown *old;

    TRACE("iface %p, content %p.\n", iface, content);

    if (content)
        IUnknown_AddRef(content);
    EnterCriticalSection(&dcomp_cs);
    old = visual->content;
    visual->content = content;
    LeaveCriticalSection(&dcomp_cs);
    if (old)
        IUnknown_Release(old);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_AddVisual(IDCompositionVisual *iface, IDCompositionVisual *child_iface,
        BOOL insert_above, IDCompositionVisual *reference_iface)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);
    struct dcomp_visual *child, *reference = NULL, *p;
    SIZE_T i, pos;
    HRESULT hr = E_INVALIDARG;

    TRACE("iface %p, visual %p, insert_above %d, reference %p.\n", iface, child_iface, insert_above, reference_iface);

    EnterCriticalSection(&dcomp_cs);
    if (!(child = unsafe_visual(child_iface, visual->device)) || child->parent || child->is_root)
        goto done;
    for (p = visual; p; p = p->parent)
        if (p == child)
            goto done;
    if (reference_iface && (!(reference = unsafe_visual(reference_iface, visual->device)) || reference->parent != visual))
        goto done;

    /* children are kept bottom to top: with no reference, above puts the visual on top of all */
    if (reference)
    {
        for (i = 0; i < visual->child_count && visual->children[i] != reference; ++i);
        pos = insert_above ? i + 1 : i;
    }
    else
    {
        pos = insert_above ? visual->child_count : 0;
    }

    if (visual->child_count == visual->child_size)
    {
        SIZE_T size = max(4, visual->child_size * 2);
        struct dcomp_visual **children = realloc(visual->children, size * sizeof(*children));

        if (!children)
        {
            hr = E_OUTOFMEMORY;
            goto done;
        }
        visual->children = children;
        visual->child_size = size;
    }
    memmove(&visual->children[pos + 1], &visual->children[pos], (visual->child_count - pos) * sizeof(*visual->children));
    visual->children[pos] = child;
    ++visual->child_count;
    child->parent = visual;
    IDCompositionVisual_AddRef(child_iface);
    hr = S_OK;

done:
    LeaveCriticalSection(&dcomp_cs);
    return hr;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_RemoveVisual(IDCompositionVisual *iface, IDCompositionVisual *child_iface)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);
    struct dcomp_visual *child;
    SIZE_T i;

    TRACE("iface %p, visual %p.\n", iface, child_iface);

    EnterCriticalSection(&dcomp_cs);
    if (!(child = unsafe_visual(child_iface, visual->device)) || child->parent != visual)
    {
        LeaveCriticalSection(&dcomp_cs);
        return E_INVALIDARG;
    }
    for (i = 0; i < visual->child_count && visual->children[i] != child; ++i);
    memmove(&visual->children[i], &visual->children[i + 1], (visual->child_count - i - 1) * sizeof(*visual->children));
    --visual->child_count;
    child->parent = NULL;
    LeaveCriticalSection(&dcomp_cs);

    IDCompositionVisual_Release(child_iface);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_RemoveAllVisuals(IDCompositionVisual *iface)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);

    TRACE("iface %p.\n", iface);

    EnterCriticalSection(&dcomp_cs);
    dcomp_visual_remove_children(visual);
    LeaveCriticalSection(&dcomp_cs);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetCompositeMode(IDCompositionVisual *iface, int mode)
{
    TRACE("iface %p, mode %d.\n", iface, mode);
    return S_OK;
}

static const IDCompositionVisualVtbl dcomp_visual_vtbl =
{
    dcomp_visual_QueryInterface,
    dcomp_visual_AddRef,
    dcomp_visual_Release,
    dcomp_visual_SetOffsetXAnimation,
    dcomp_visual_SetOffsetX,
    dcomp_visual_SetOffsetYAnimation,
    dcomp_visual_SetOffsetY,
    dcomp_visual_SetTransformObject,
    dcomp_visual_SetTransform,
    dcomp_visual_SetTransformParent,
    dcomp_visual_SetEffect,
    dcomp_visual_SetBitmapInterpolationMode,
    dcomp_visual_SetBorderMode,
    dcomp_visual_SetClipObject,
    dcomp_visual_SetClip,
    dcomp_visual_SetContent,
    dcomp_visual_AddVisual,
    dcomp_visual_RemoveVisual,
    dcomp_visual_RemoveAllVisuals,
    dcomp_visual_SetCompositeMode,
};

/* -------------------------------------------------------------------------------------------------- target */

static HRESULT STDMETHODCALLTYPE dcomp_target_QueryInterface(IDCompositionTarget *iface, REFIID iid, void **out)
{
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (!out)
        return E_POINTER;

    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IDCompositionTarget))
    {
        IDCompositionTarget_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

/* A released target no longer shows its tree, as on Windows: the swap chains committed through it stop
 * painting into its window. The caller holds dcomp_cs. */
static void dcomp_device_unbind_target(struct dcomp_device *device, struct dcomp_target *target)
{
    SIZE_T i, kept = 0;

    for (i = 0; i < device->bound_count; ++i)
    {
        struct dcomp_binding *binding = &device->bound[i];

        if (binding->target == target)
        {
            IWineDXGICompositionSwapChain_set_composition_target(binding->swapchain, NULL, NULL);
            IWineDXGICompositionSwapChain_Release(binding->swapchain);
        }
        else
        {
            device->bound[kept++] = *binding;
        }
    }
    device->bound_count = kept;
}

static ULONG STDMETHODCALLTYPE dcomp_target_AddRef(IDCompositionTarget *iface)
{
    struct dcomp_target *target = impl_from_IDCompositionTarget(iface);
    ULONG refcount = InterlockedIncrement(&target->refcount);

    TRACE("%p increasing refcount to %lu.\n", iface, refcount);
    return refcount;
}

static ULONG STDMETHODCALLTYPE dcomp_target_Release(IDCompositionTarget *iface)
{
    struct dcomp_target *target = impl_from_IDCompositionTarget(iface);
    ULONG refcount = InterlockedDecrement(&target->refcount);
    struct dcomp_visual *root;

    TRACE("%p decreasing refcount to %lu.\n", iface, refcount);

    if (!refcount)
    {
        EnterCriticalSection(&dcomp_cs);
        list_remove(&target->entry);
        dcomp_device_unbind_target(target->device, target);
        if ((root = target->root))
            root->is_root = FALSE;
        LeaveCriticalSection(&dcomp_cs);
        if (root)
            IDCompositionVisual_Release(&root->IDCompositionVisual_iface);
        IDCompositionDevice_Release(&target->device->IDCompositionDevice_iface);
        free(target);
    }
    return refcount;
}

static HRESULT STDMETHODCALLTYPE dcomp_target_SetRoot(IDCompositionTarget *iface, IDCompositionVisual *visual_iface)
{
    struct dcomp_target *target = impl_from_IDCompositionTarget(iface);
    struct dcomp_visual *visual = NULL, *old;

    TRACE("iface %p, visual %p.\n", iface, visual_iface);

    EnterCriticalSection(&dcomp_cs);
    if (visual_iface && (!(visual = unsafe_visual(visual_iface, target->device))
            || visual->parent || (visual->is_root && visual != target->root)))
    {
        LeaveCriticalSection(&dcomp_cs);
        return E_INVALIDARG;
    }
    old = target->root;
    if (old == visual)
    {
        LeaveCriticalSection(&dcomp_cs);
        return S_OK;
    }
    if (old)
        old->is_root = FALSE;
    if (visual)
    {
        visual->is_root = TRUE;
        IDCompositionVisual_AddRef(visual_iface);
    }
    target->root = visual;
    LeaveCriticalSection(&dcomp_cs);

    if (old)
        IDCompositionVisual_Release(&old->IDCompositionVisual_iface);
    return S_OK;
}

static const IDCompositionTargetVtbl dcomp_target_vtbl =
{
    dcomp_target_QueryInterface,
    dcomp_target_AddRef,
    dcomp_target_Release,
    dcomp_target_SetRoot,
};

/* -------------------------------------------------------------------------------------------------- device */

static HRESULT STDMETHODCALLTYPE dcomp_device_QueryInterface(IDCompositionDevice *iface, REFIID iid, void **out)
{
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (!out)
        return E_POINTER;

    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IDCompositionDevice))
    {
        IDCompositionDevice_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE dcomp_device_AddRef(IDCompositionDevice *iface)
{
    struct dcomp_device *device = impl_from_IDCompositionDevice(iface);
    ULONG refcount = InterlockedIncrement(&device->refcount);

    TRACE("%p increasing refcount to %lu.\n", iface, refcount);
    return refcount;
}

static void dcomp_device_unbind(struct dcomp_binding *bound, SIZE_T count)
{
    SIZE_T i;

    for (i = 0; i < count; ++i)
    {
        IWineDXGICompositionSwapChain_set_composition_target(bound[i].swapchain, NULL, NULL);
        IWineDXGICompositionSwapChain_Release(bound[i].swapchain);
    }
    free(bound);
}

static ULONG STDMETHODCALLTYPE dcomp_device_Release(IDCompositionDevice *iface)
{
    struct dcomp_device *device = impl_from_IDCompositionDevice(iface);
    ULONG refcount = InterlockedDecrement(&device->refcount);

    TRACE("%p decreasing refcount to %lu.\n", iface, refcount);

    if (!refcount)
    {
        dcomp_device_unbind(device->bound, device->bound_count);
        if (device->rendering_device)
            IUnknown_Release(device->rendering_device);
        free(device);
    }
    return refcount;
}

struct dcomp_bindings
{
    struct dcomp_binding *items;
    SIZE_T count, size;
    HRESULT hr;
};

/* offsets are sums of finite floats: keep them where a conversion to LONG is defined */
static LONG dcomp_round_offset(float v)
{
    if (!(v > -1.0e9f))
        return -1000000000;
    if (v > 1.0e9f)
        return 1000000000;
    return (LONG)floorf(v + 0.5f);
}

static void dcomp_collect(struct dcomp_bindings *b, struct dcomp_visual *visual, struct dcomp_target *target,
        float x, float y)
{
    IWineDXGICompositionSwapChain *swapchain;
    SIZE_T i;

    x += visual->offset_x;
    y += visual->offset_y;
    if (visual->content && SUCCEEDED(IUnknown_QueryInterface(visual->content,
            &IID_IWineDXGICompositionSwapChain, (void **)&swapchain)))
    {
        if (b->count == b->size)
        {
            SIZE_T size = max(4, b->size * 2);
            struct dcomp_binding *items = realloc(b->items, size * sizeof(*items));

            if (!items)
            {
                IWineDXGICompositionSwapChain_Release(swapchain);
                b->hr = E_OUTOFMEMORY;
                return;
            }
            b->items = items;
            b->size = size;
        }
        b->items[b->count].swapchain = swapchain;
        b->items[b->count].target = target;
        b->items[b->count].window = target->window;
        b->items[b->count].offset.x = dcomp_round_offset(x);
        b->items[b->count].offset.y = dcomp_round_offset(y);
        ++b->count;
    }
    else if (visual->content)
    {
        FIXME("Content %p of visual %p is not a composition swap chain.\n", visual->content, visual);
    }

    for (i = 0; i < visual->child_count; ++i)
        dcomp_collect(b, visual->children[i], target, x, y);
}

static HRESULT STDMETHODCALLTYPE dcomp_device_Commit(IDCompositionDevice *iface)
{
    struct dcomp_device *device = impl_from_IDCompositionDevice(iface);
    struct dcomp_bindings b = {NULL, 0, 0, S_OK};
    struct dcomp_binding *old;
    struct dcomp_target *target;
    SIZE_T old_count, i, j;

    TRACE("iface %p.\n", iface);

    EnterCriticalSection(&dcomp_cs);
    LIST_FOR_EACH_ENTRY(target, &dcomp_targets, struct dcomp_target, entry)
    {
        if (target->device == device && target->root)
            dcomp_collect(&b, target->root, target, 0.0f, 0.0f);
    }
    if (FAILED(b.hr))
    {
        LeaveCriticalSection(&dcomp_cs);
        dcomp_device_unbind(b.items, b.count);
        return b.hr;
    }

    old = device->bound;
    old_count = device->bound_count;
    device->bound = b.items;
    device->bound_count = b.count;

    /* swap chains no longer in a committed tree leave their window, the others take their place */
    for (i = 0; i < old_count; ++i)
    {
        for (j = 0; j < b.count && b.items[j].swapchain != old[i].swapchain; ++j);
        if (j == b.count)
            IWineDXGICompositionSwapChain_set_composition_target(old[i].swapchain, NULL, NULL);
        IWineDXGICompositionSwapChain_Release(old[i].swapchain);
    }
    free(old);
    for (i = 0; i < b.count; ++i)
        IWineDXGICompositionSwapChain_set_composition_target(b.items[i].swapchain, b.items[i].window, &b.items[i].offset);
    LeaveCriticalSection(&dcomp_cs);

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_WaitForCommitCompletion(IDCompositionDevice *iface)
{
    /* a commit is complete when Commit returns */
    TRACE("iface %p.\n", iface);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_GetFrameStatistics(IDCompositionDevice *iface,
        DCOMPOSITION_FRAME_STATISTICS *stats)
{
    LARGE_INTEGER now, frequency;

    TRACE("iface %p, stats %p.\n", iface, stats);

    if (!stats)
        return E_INVALIDARG;

    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&frequency);
    stats->lastFrameTime = now;
    stats->currentCompositionRate.Numerator = 60;
    stats->currentCompositionRate.Denominator = 1;
    stats->currentTime = now;
    stats->timeFrequency = frequency;
    stats->nextEstimatedFrameTime.QuadPart = now.QuadPart + frequency.QuadPart / 60;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateTargetForHwnd(IDCompositionDevice *iface, HWND window,
        BOOL topmost, IDCompositionTarget **out)
{
    struct dcomp_device *device = impl_from_IDCompositionDevice(iface);
    struct dcomp_target *target, *other;

    TRACE("iface %p, window %p, topmost %d, out %p.\n", iface, window, topmost, out);

    if (!out)
        return E_INVALIDARG;
    *out = NULL;
    if (!IsWindow(window))
        return E_INVALIDARG;

    if (!(target = calloc(1, sizeof(*target))))
        return E_OUTOFMEMORY;
    target->IDCompositionTarget_iface.lpVtbl = &dcomp_target_vtbl;
    target->refcount = 1;
    target->window = window;
    target->topmost = !!topmost;
    target->device = device;

    EnterCriticalSection(&dcomp_cs);
    LIST_FOR_EACH_ENTRY(other, &dcomp_targets, struct dcomp_target, entry)
    {
        if (other->window == window && other->topmost == target->topmost)
        {
            LeaveCriticalSection(&dcomp_cs);
            free(target);
            return DCOMPOSITION_ERROR_WINDOW_ALREADY_COMPOSED;
        }
    }
    IDCompositionDevice_AddRef(&device->IDCompositionDevice_iface);
    list_add_tail(&dcomp_targets, &target->entry);
    LeaveCriticalSection(&dcomp_cs);

    *out = &target->IDCompositionTarget_iface;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateVisual(IDCompositionDevice *iface, IDCompositionVisual **out)
{
    struct dcomp_device *device = impl_from_IDCompositionDevice(iface);
    struct dcomp_visual *visual;

    TRACE("iface %p, out %p.\n", iface, out);

    if (!out)
        return E_INVALIDARG;
    if (!(visual = calloc(1, sizeof(*visual))))
    {
        *out = NULL;
        return E_OUTOFMEMORY;
    }
    visual->IDCompositionVisual_iface.lpVtbl = &dcomp_visual_vtbl;
    visual->refcount = 1;
    visual->device = device;
    IDCompositionDevice_AddRef(&device->IDCompositionDevice_iface);
    *out = &visual->IDCompositionVisual_iface;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateSurface(IDCompositionDevice *iface, UINT width, UINT height,
        DXGI_FORMAT format, DXGI_ALPHA_MODE alpha_mode, IUnknown **surface)
{
    FIXME("iface %p, width %u, height %u, format %#x, alpha_mode %#x, surface %p stub!\n",
            iface, width, height, format, alpha_mode, surface);
    if (surface)
        *surface = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateVirtualSurface(IDCompositionDevice *iface, UINT width, UINT height,
        DXGI_FORMAT format, DXGI_ALPHA_MODE alpha_mode, IUnknown **surface)
{
    FIXME("iface %p, width %u, height %u, format %#x, alpha_mode %#x, surface %p stub!\n",
            iface, width, height, format, alpha_mode, surface);
    if (surface)
        *surface = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateSurfaceFromHandle(IDCompositionDevice *iface, HANDLE handle,
        IUnknown **surface)
{
    FIXME("iface %p, handle %p, surface %p stub!\n", iface, handle, surface);
    if (surface)
        *surface = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateSurfaceFromHwnd(IDCompositionDevice *iface, HWND window,
        IUnknown **surface)
{
    FIXME("iface %p, window %p, surface %p stub!\n", iface, window, surface);
    if (surface)
        *surface = NULL;
    return E_NOTIMPL;
}

#define DCOMP_CREATE_STUB(name) \
static HRESULT STDMETHODCALLTYPE dcomp_device_##name(IDCompositionDevice *iface, IUnknown **object) \
{ \
    FIXME("iface %p, object %p stub!\n", iface, object); \
    if (object) \
        *object = NULL; \
    return E_NOTIMPL; \
}

DCOMP_CREATE_STUB(CreateTranslateTransform)
DCOMP_CREATE_STUB(CreateScaleTransform)
DCOMP_CREATE_STUB(CreateRotateTransform)
DCOMP_CREATE_STUB(CreateSkewTransform)
DCOMP_CREATE_STUB(CreateMatrixTransform)
DCOMP_CREATE_STUB(CreateTranslateTransform3D)
DCOMP_CREATE_STUB(CreateScaleTransform3D)
DCOMP_CREATE_STUB(CreateRotateTransform3D)
DCOMP_CREATE_STUB(CreateMatrixTransform3D)
DCOMP_CREATE_STUB(CreateEffectGroup)
DCOMP_CREATE_STUB(CreateRectangleClip)
DCOMP_CREATE_STUB(CreateAnimation)

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateTransformGroup(IDCompositionDevice *iface, IUnknown **transforms,
        UINT count, IUnknown **group)
{
    FIXME("iface %p, transforms %p, count %u, group %p stub!\n", iface, transforms, count, group);
    if (group)
        *group = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateTransform3DGroup(IDCompositionDevice *iface, IUnknown **transforms,
        UINT count, IUnknown **group)
{
    FIXME("iface %p, transforms %p, count %u, group %p stub!\n", iface, transforms, count, group);
    if (group)
        *group = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CheckDeviceState(IDCompositionDevice *iface, BOOL *valid)
{
    TRACE("iface %p, valid %p.\n", iface, valid);

    if (!valid)
        return E_INVALIDARG;
    *valid = TRUE;
    return S_OK;
}

static const IDCompositionDeviceVtbl dcomp_device_vtbl =
{
    dcomp_device_QueryInterface,
    dcomp_device_AddRef,
    dcomp_device_Release,
    dcomp_device_Commit,
    dcomp_device_WaitForCommitCompletion,
    dcomp_device_GetFrameStatistics,
    dcomp_device_CreateTargetForHwnd,
    dcomp_device_CreateVisual,
    dcomp_device_CreateSurface,
    dcomp_device_CreateVirtualSurface,
    dcomp_device_CreateSurfaceFromHandle,
    dcomp_device_CreateSurfaceFromHwnd,
    dcomp_device_CreateTranslateTransform,
    dcomp_device_CreateScaleTransform,
    dcomp_device_CreateRotateTransform,
    dcomp_device_CreateSkewTransform,
    dcomp_device_CreateMatrixTransform,
    dcomp_device_CreateTransformGroup,
    dcomp_device_CreateTranslateTransform3D,
    dcomp_device_CreateScaleTransform3D,
    dcomp_device_CreateRotateTransform3D,
    dcomp_device_CreateMatrixTransform3D,
    dcomp_device_CreateTransform3DGroup,
    dcomp_device_CreateEffectGroup,
    dcomp_device_CreateRectangleClip,
    dcomp_device_CreateAnimation,
    dcomp_device_CheckDeviceState,
};

HRESULT WINAPI DCompositionCreateDevice(IDXGIDevice *dxgi_device, REFIID iid, void **out)
{
    struct dcomp_device *device;
    HRESULT hr;

    TRACE("%p, %s, %p.\n", dxgi_device, debugstr_guid(iid), out);

    if (!out)
        return E_INVALIDARG;
    *out = NULL;

    if (!(device = calloc(1, sizeof(*device))))
        return E_OUTOFMEMORY;
    device->IDCompositionDevice_iface.lpVtbl = &dcomp_device_vtbl;
    device->refcount = 1;
    if ((device->rendering_device = (IUnknown *)dxgi_device))
        IUnknown_AddRef(device->rendering_device);

    hr = IDCompositionDevice_QueryInterface(&device->IDCompositionDevice_iface, iid, out);
    IDCompositionDevice_Release(&device->IDCompositionDevice_iface);
    return hr;
}

HRESULT WINAPI DCompositionCreateDevice2(IUnknown *rendering_device, REFIID iid, void **device)
{
    FIXME("%p, %s, %p.\n", rendering_device, debugstr_guid(iid), device);

    return E_NOTIMPL;
}

HRESULT WINAPI DCompositionCreateDevice3(IUnknown *rendering_device, REFIID iid, void **device)
{
    FIXME("%p, %s, %p.\n", rendering_device, debugstr_guid(iid), device);

    return E_NOTIMPL;
}

HRESULT WINAPI DCompositionCreateSurfaceHandle(DWORD access, SECURITY_ATTRIBUTES *attributes, HANDLE *handle)
{
    FIXME("%#lx, %p, %p.\n", access, attributes, handle);

    return E_NOTIMPL;
}

HRESULT WINAPI DCompositionAttachMouseDragToHwnd(void *visual, HWND hwnd, BOOL enable)
{
    FIXME("%p, %p, %d.\n", visual, hwnd, enable);

    return E_NOTIMPL;
}

HRESULT WINAPI DCompositionAttachMouseWheelToHwnd(void *visual, HWND hwnd, BOOL enable)
{
    FIXME("%p, %p, %d.\n", visual, hwnd, enable);

    return E_NOTIMPL;
}

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **obj)
{
    FIXME("%s, %s, %p.\n", debugstr_guid(clsid), debugstr_guid(iid), obj);

    *obj = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllGetActivationFactory(void *classid, void **factory)
{
    FIXME("%p, %p.\n", classid, factory);

    *factory = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DwmEnableMMCSS(BOOL enable)
{
    FIXME("%d.\n", enable);

    return E_NOTIMPL;
}

HRESULT WINAPI DwmFlush(void)
{
    FIXME("\n");

    return E_NOTIMPL;
}

HRESULT WINAPI DwmpEnableDDASupport(void)
{
    FIXME("\n");

    return E_NOTIMPL;
}
