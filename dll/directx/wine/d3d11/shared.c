/*
 * D3D11 shared resources: legacy shared handles (D3D11_RESOURCE_MISC_SHARED and
 * D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX), NT handles (D3D11_RESOURCE_MISC_SHARED_NTHANDLE,
 * IDXGIResource1::CreateSharedHandle, ID3D11Device1::OpenSharedResource1 / OpenSharedResourceByName)
 * and IDXGIKeyedMutex, for textures of the software (wined3d) stack.
 *
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
 *
 * Design (written from learn.microsoft.com and from the behaviour measured on Windows 10 22H2):
 *
 * The pixels of a wined3d texture live in the process that created it, so a shared texture is
 * backed by a section object (a pagefile-backed file mapping) that every process maps. The
 * section holds a small header (the description, a content generation counter, the keyed-mutex
 * state) and a tightly packed copy of every subresource. Each process keeps an ordinary wined3d
 * texture and exchanges contents with the section:
 *
 *  - push: read the texture back through a staging texture and store changed rows in the section;
 *  - pull: when the section's generation differs from the last one seen, UpdateSubresource() the
 *    section data into the texture.
 *
 * Keyed mutex: AcquireSync waits for the mutex to be free with the requested key, takes it, then
 * pulls; ReleaseSync pushes, stores the new key and frees the mutex. Waiting polls the section
 * state, so that no second kernel object has to travel with the handle. A holder that exited
 * without releasing is reported to the next waiter as WAIT_ABANDONED.
 *
 * Without a keyed mutex there is no explicit hand-over: a texture that was bound as a render target
 * (or written by a copy, an update or a clear) is pushed on ID3D11DeviceContext::Flush, and every
 * shared texture is checked for a newer generation on Flush, when it is bound as a shader resource
 * and when it is the source of a copy.
 *
 * Legacy handles are 32-bit tokens (0x40000000 | n): the section is a named object
 * "Local\NitroD3D11Shared.<token>" and OpenSharedResource looks it up by that name. NT handles are
 * handles to the (unnamed, or when asked for, named) section itself. Windows' NT handle is an
 * object of a graphics-specific type; ours is a section, so the handle also maps as a file mapping.
 *
 * Not synchronised: multisampled textures, depth/stencil and planar formats (the handle and the
 * mutex work, contents are not exchanged), staging textures.
 */

#include "d3d11_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(d3d11);

#define SHARED_MAGIC    0x4853334eu /* "N3SH" */
#define SHARED_VERSION  1
#define SHARED_HDR_SIZE 4096

struct shared_header
{
    DWORD magic;
    DWORD version;
    DWORD total_size;
    DWORD sync_enabled;

    DWORD width, height, mip_levels, array_size;
    DWORD format, bind_flags, misc_flags, sample_count;

    volatile LONG gen;      /* content generation; odd while a push is in progress */
    volatile LONG lock;     /* protects key, held and holder */
    volatile LONG held;
    DWORD holder_pid;
    DWORD holder_obj;       /* low bits of the keyed-mutex object address */
    LONG64 holder_ctime;
    LONG64 key;
};

struct d3d_shared
{
    struct list entry;
    struct d3d_texture2d *texture;
    struct d3d_device *device;

    struct shared_header local_hdr;  /* state until a section exists (NT handle textures) */
    struct shared_header *hdr;
    BYTE *view;
    HANDLE section;

    DWORD token;            /* legacy handle, 0 if none */
    BOOL nt, keyed, listed, sync;
    LONG last_gen;
    BOOL rt_bound, dirty, busy;

    UINT sub_count;
    UINT64 *sub_offset;     /* offsets from the start of the view */
    UINT *sub_row_bytes, *sub_rows;
    SIZE_T data_size;

    ID3D11Texture2D *staging;
    IDXGIKeyedMutex IDXGIKeyedMutex_iface;
};

static inline struct d3d_shared *impl_from_IDXGIKeyedMutex(IDXGIKeyedMutex *iface)
{
    return CONTAINING_RECORD(iface, struct d3d_shared, IDXGIKeyedMutex_iface);
}

static LONG shared_token_counter;

/* ---------------------------------------------------------------------- layout */

/* bytes per element and block edge for the formats whose contents can be exchanged */
static BOOL shared_format_info(DXGI_FORMAT format, UINT *bytes, UINT *block)
{
    *block = 1;
    if ((format >= 1 && format <= 4) || (format >= 5 && format <= 8 && 0)) { *bytes = 16; return TRUE; }
    if (format >= 9 && format <= 18) { *bytes = 8; return TRUE; }
    if (format >= 23 && format <= 43 && format != 19 && format != 20 && format != 21 && format != 22) { *bytes = 4; return TRUE; }
    if (format >= 48 && format <= 58) { *bytes = 2; return TRUE; }
    if (format >= 60 && format <= 65) { *bytes = 1; return TRUE; }
    if (format == 67) { *bytes = 4; return TRUE; }
    if ((format >= 70 && format <= 72) || (format >= 79 && format <= 81)) { *bytes = 8; *block = 4; return TRUE; }
    if ((format >= 73 && format <= 78) || (format >= 82 && format <= 84)) { *bytes = 16; *block = 4; return TRUE; }
    if (format == 85 || format == 86 || format == 115) { *bytes = 2; return TRUE; }
    if (format >= 87 && format <= 93) { *bytes = 4; return TRUE; }
    if (format >= 94 && format <= 99) { *bytes = 16; *block = 4; return TRUE; }
    return FALSE;
}

/* 24/32-bit packed depth formats are not byte-addressable through UpdateSubresource */
static BOOL shared_can_sync(const D3D11_TEXTURE2D_DESC *desc)
{
    UINT bytes, block;

    if (desc->SampleDesc.Count > 1 || desc->Usage == D3D11_USAGE_STAGING)
        return FALSE;
    if (desc->BindFlags & D3D11_BIND_DEPTH_STENCIL)
        return FALSE;
    return shared_format_info(desc->Format, &bytes, &block);
}

/* the description of an opened resource comes from a section another process wrote: untrusted */
static BOOL shared_desc_sane(const D3D11_TEXTURE2D_DESC *desc)
{
    UINT max_mips = 1, dim;

    if (!desc->Width || desc->Width > 16384 || !desc->Height || desc->Height > 16384)
        return FALSE;
    if (!desc->ArraySize || desc->ArraySize > 2048 || !desc->MipLevels || desc->MipLevels > 15)
        return FALSE;
    if (!desc->SampleDesc.Count || desc->SampleDesc.Count > 32 || desc->Format > 200)
        return FALSE;
    for (dim = max(desc->Width, desc->Height); dim > 1; dim >>= 1)
        ++max_mips;
    return desc->MipLevels <= max_mips;
}

/* bytes of packed subresource data, computed in 64 bits; 0 when nothing is exchanged */
static UINT64 shared_data_bytes(const D3D11_TEXTURE2D_DESC *desc)
{
    UINT bytes, block, mip, w, h;
    UINT64 total = 0;

    if (!shared_can_sync(desc))
        return 0;
    shared_format_info(desc->Format, &bytes, &block);
    for (mip = 0; mip < desc->MipLevels; ++mip)
    {
        w = max(1u, desc->Width >> mip);
        h = max(1u, desc->Height >> mip);
        total += (UINT64)((w + block - 1) / block) * bytes * ((h + block - 1) / block);
    }
    return total * desc->ArraySize;
}

/* section layout of a description must fit a DWORD size and, when opening, the mapped region */
static BOOL shared_layout_fits(const D3D11_TEXTURE2D_DESC *desc, UINT64 region)
{
    UINT64 total;

    if (!shared_desc_sane(desc))
        return FALSE;
    total = SHARED_HDR_SIZE + shared_data_bytes(desc);
    if (total > 0xffffffffull)
        return FALSE;
    return !region || total <= region;
}

static BOOL shared_compute_layout(struct d3d_shared *shared, const D3D11_TEXTURE2D_DESC *desc)
{
    UINT bytes, block, mip, arr, w, h, i = 0;
    UINT64 off = SHARED_HDR_SIZE;

    shared->sub_count = 0;
    shared->data_size = 0;
    if (!shared_can_sync(desc))
        return TRUE;
    shared_format_info(desc->Format, &bytes, &block);
    shared->sub_count = desc->MipLevels * desc->ArraySize;
    if (!(shared->sub_offset = calloc(shared->sub_count, sizeof(*shared->sub_offset)))
            || !(shared->sub_row_bytes = calloc(shared->sub_count, sizeof(*shared->sub_row_bytes)))
            || !(shared->sub_rows = calloc(shared->sub_count, sizeof(*shared->sub_rows))))
        return FALSE;
    for (arr = 0; arr < desc->ArraySize; ++arr)
    {
        for (mip = 0; mip < desc->MipLevels; ++mip, ++i)
        {
            w = max(1u, desc->Width >> mip);
            h = max(1u, desc->Height >> mip);
            shared->sub_row_bytes[i] = ((w + block - 1) / block) * bytes;
            shared->sub_rows[i] = (h + block - 1) / block;
            shared->sub_offset[i] = off;
            off += (UINT64)shared->sub_row_bytes[i] * shared->sub_rows[i];
        }
    }
    shared->data_size = off - SHARED_HDR_SIZE;
    return TRUE;
}

static void shared_fill_header(struct d3d_shared *shared, struct shared_header *hdr, const D3D11_TEXTURE2D_DESC *desc)
{
    hdr->magic = SHARED_MAGIC;
    hdr->version = SHARED_VERSION;
    hdr->total_size = SHARED_HDR_SIZE + (DWORD)shared->data_size;
    hdr->sync_enabled = shared->sub_count != 0;
    hdr->width = desc->Width;
    hdr->height = desc->Height;
    hdr->mip_levels = desc->MipLevels;
    hdr->array_size = desc->ArraySize;
    hdr->format = desc->Format;
    hdr->bind_flags = desc->BindFlags;
    hdr->misc_flags = desc->MiscFlags;
    hdr->sample_count = desc->SampleDesc.Count;
}

/* ---------------------------------------------------------------------- section */

static void shared_unmap(struct d3d_shared *shared)
{
    if (shared->view)
        UnmapViewOfFile(shared->view);
    if (shared->section)
        CloseHandle(shared->section);
    shared->view = NULL;
    shared->section = NULL;
    shared->hdr = &shared->local_hdr;
}

static BOOL shared_get_ctime(DWORD pid, LONG64 *ctime)
{
    FILETIME c, e, k, u;
    HANDLE h;
    BOOL ret;

    if (pid == GetCurrentProcessId())
        h = GetCurrentProcess();
    else if (!(h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid)))
        return FALSE;
    ret = GetProcessTimes(h, &c, &e, &k, &u);
    if (h != GetCurrentProcess())
        CloseHandle(h);
    if (ret)
        *ctime = ((LONG64)c.dwHighDateTime << 32) | c.dwLowDateTime;
    return ret;
}

static void shared_state_lock(struct shared_header *hdr)
{
    unsigned int spins = 0;

    while (InterlockedCompareExchange(&hdr->lock, 1, 0))
    {
        if (++spins > 64)
            Sleep(0);
    }
}

static void shared_state_unlock(struct shared_header *hdr)
{
    InterlockedExchange(&hdr->lock, 0);
}

/* ---------------------------------------------------------------------- content exchange */

static HRESULT shared_ensure_staging(struct d3d_shared *shared)
{
    D3D11_TEXTURE2D_DESC desc = shared->texture->desc;

    if (shared->staging)
        return S_OK;
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.MiscFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    return ID3D11Device2_CreateTexture2D(shared->texture->device, &desc, NULL, &shared->staging);
}

static ID3D11DeviceContext1 *shared_context(struct d3d_shared *shared)
{
    return &shared->device->immediate_context.ID3D11DeviceContext1_iface;
}

/* store the texture contents in the section; only rows that changed are written */
static void shared_push(struct d3d_shared *shared)
{
    struct shared_header *hdr = shared->hdr;
    ID3D11DeviceContext1 *context = shared_context(shared);
    BOOL started = FALSE;
    UINT i, r;

    if (!shared->view || !shared->sub_count || shared->texture->desc.Usage == D3D11_USAGE_STAGING)
        return;
    if (FAILED(shared_ensure_staging(shared)))
    {
        WARN("Cannot create the staging texture.\n");
        return;
    }
    shared->busy = TRUE;

    ID3D11DeviceContext1_CopyResource(context, (ID3D11Resource *)shared->staging,
            (ID3D11Resource *)&shared->texture->ID3D11Texture2D_iface);

    for (i = 0; i < shared->sub_count; ++i)
    {
        D3D11_MAPPED_SUBRESOURCE map;
        BYTE *dst = shared->view + shared->sub_offset[i];
        const BYTE *src;

        if (FAILED(ID3D11DeviceContext1_Map(context, (ID3D11Resource *)shared->staging, i, D3D11_MAP_READ, 0, &map)))
        {
            WARN("Cannot map the staging texture, subresource %u.\n", i);
            continue;
        }
        src = map.pData;
        for (r = 0; r < shared->sub_rows[i]; ++r)
        {
            if (memcmp(dst, src, shared->sub_row_bytes[i]))
            {
                if (!started)
                {
                    InterlockedIncrement(&hdr->gen); /* odd: push in progress */
                    started = TRUE;
                }
                memcpy(dst, src, shared->sub_row_bytes[i]);
            }
            dst += shared->sub_row_bytes[i];
            src += map.RowPitch;
        }
        ID3D11DeviceContext1_Unmap(context, (ID3D11Resource *)shared->staging, i);
    }

    if (started)
        InterlockedIncrement(&hdr->gen);
    shared->last_gen = hdr->gen;
    shared->dirty = FALSE;
    shared->busy = FALSE;
}

/* load newer section contents into the texture; returns TRUE if the texture was updated */
static BOOL shared_pull(struct d3d_shared *shared)
{
    struct shared_header *hdr = shared->hdr;
    ID3D11DeviceContext1 *context = shared_context(shared);
    LONG g1, g2;
    UINT i;

    if (!shared->view || !shared->sub_count)
        return FALSE;
    g1 = hdr->gen;
    if ((g1 & 1) || g1 == shared->last_gen)
        return FALSE;

    shared->busy = TRUE;
    for (i = 0; i < shared->sub_count; ++i)
        ID3D11DeviceContext1_UpdateSubresource(context, (ID3D11Resource *)&shared->texture->ID3D11Texture2D_iface, i,
                NULL, shared->view + shared->sub_offset[i], shared->sub_row_bytes[i],
                shared->sub_row_bytes[i] * shared->sub_rows[i]);

    shared->busy = FALSE;
    shared->dirty = FALSE;
    g2 = hdr->gen;
    if (g1 != g2)
        return FALSE; /* a writer was active meanwhile: try again at the next sync point */
    shared->last_gen = g1;
    return TRUE;
}

/* ---------------------------------------------------------------------- keyed mutex */

static HRESULT STDMETHODCALLTYPE shared_mutex_QueryInterface(IDXGIKeyedMutex *iface, REFIID iid, void **out)
{
    struct d3d_shared *shared = impl_from_IDXGIKeyedMutex(iface);

    return ID3D11Texture2D_QueryInterface(&shared->texture->ID3D11Texture2D_iface, iid, out);
}

static ULONG STDMETHODCALLTYPE shared_mutex_AddRef(IDXGIKeyedMutex *iface)
{
    struct d3d_shared *shared = impl_from_IDXGIKeyedMutex(iface);

    return ID3D11Texture2D_AddRef(&shared->texture->ID3D11Texture2D_iface);
}

static ULONG STDMETHODCALLTYPE shared_mutex_Release(IDXGIKeyedMutex *iface)
{
    struct d3d_shared *shared = impl_from_IDXGIKeyedMutex(iface);

    return ID3D11Texture2D_Release(&shared->texture->ID3D11Texture2D_iface);
}

static HRESULT STDMETHODCALLTYPE shared_mutex_SetPrivateData(IDXGIKeyedMutex *iface, REFGUID guid, UINT size,
        const void *data)
{
    struct d3d_shared *shared = impl_from_IDXGIKeyedMutex(iface);

    return ID3D11Texture2D_SetPrivateData(&shared->texture->ID3D11Texture2D_iface, guid, size, data);
}

static HRESULT STDMETHODCALLTYPE shared_mutex_SetPrivateDataInterface(IDXGIKeyedMutex *iface, REFGUID guid,
        const IUnknown *object)
{
    struct d3d_shared *shared = impl_from_IDXGIKeyedMutex(iface);

    return ID3D11Texture2D_SetPrivateDataInterface(&shared->texture->ID3D11Texture2D_iface, guid, object);
}

static HRESULT STDMETHODCALLTYPE shared_mutex_GetPrivateData(IDXGIKeyedMutex *iface, REFGUID guid, UINT *size,
        void *data)
{
    struct d3d_shared *shared = impl_from_IDXGIKeyedMutex(iface);

    return ID3D11Texture2D_GetPrivateData(&shared->texture->ID3D11Texture2D_iface, guid, size, data);
}

static HRESULT STDMETHODCALLTYPE shared_mutex_GetParent(IDXGIKeyedMutex *iface, REFIID iid, void **parent)
{
    struct d3d_shared *shared = impl_from_IDXGIKeyedMutex(iface);
    IDXGIResource *resource;
    HRESULT hr;

    if (FAILED(hr = IUnknown_QueryInterface(shared->texture->dxgi_resource, &IID_IDXGIResource, (void **)&resource)))
        return hr;
    hr = IDXGIResource_GetParent(resource, iid, parent);
    IDXGIResource_Release(resource);
    return hr;
}

static HRESULT STDMETHODCALLTYPE shared_mutex_GetDevice(IDXGIKeyedMutex *iface, REFIID iid, void **device)
{
    struct d3d_shared *shared = impl_from_IDXGIKeyedMutex(iface);
    IDXGIResource *resource;
    HRESULT hr;

    if (FAILED(hr = IUnknown_QueryInterface(shared->texture->dxgi_resource, &IID_IDXGIResource, (void **)&resource)))
        return hr;
    hr = IDXGIResource_GetDevice(resource, iid, device);
    IDXGIResource_Release(resource);
    return hr;
}

static BOOL shared_holder_is_dead(DWORD pid, LONG64 ctime)
{
    LONG64 now;
    HANDLE h;
    BOOL dead;

    if (!(h = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, pid)))
        return GetLastError() == ERROR_INVALID_PARAMETER; /* no such process; access denied means alive */
    dead = WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
    CloseHandle(h);
    if (!dead && ctime && shared_get_ctime(pid, &now) && now != ctime)
        dead = TRUE; /* the id was reused */
    return dead;
}

static HRESULT STDMETHODCALLTYPE shared_mutex_AcquireSync(IDXGIKeyedMutex *iface, UINT64 key, DWORD timeout)
{
    struct d3d_shared *shared = impl_from_IDXGIKeyedMutex(iface);
    struct shared_header *hdr = shared->hdr;
    DWORD pid = GetCurrentProcessId(), obj = (DWORD)(ULONG_PTR)shared, start = GetTickCount(), spins = 0;
    LONG64 ctime = 0;
    HRESULT hr;

    TRACE("iface %p, key %s, timeout %lu.\n", iface, wine_dbgstr_longlong(key), timeout);

    shared_get_ctime(pid, &ctime);
    for (;;)
    {
        DWORD hpid = 0;
        LONG64 hctime = 0;
        BOOL cand = FALSE;

        hdr = shared->hdr;
        shared_state_lock(hdr);
        if (!hdr->held && (UINT64)hdr->key == key)
        {
            hdr->held = 1;
            hdr->holder_pid = pid;
            hdr->holder_obj = obj;
            hdr->holder_ctime = ctime;
            shared_state_unlock(hdr);
            hr = S_OK;
            break;
        }
        if (hdr->held && hdr->holder_pid != pid)
        {
            cand = TRUE;
            hpid = hdr->holder_pid;
            hctime = hdr->holder_ctime;
        }
        shared_state_unlock(hdr);

        if (cand && shared_holder_is_dead(hpid, hctime))
        {
            shared_state_lock(hdr);
            if (hdr->held && hdr->holder_pid == hpid && hdr->holder_ctime == hctime)
            {
                hdr->holder_pid = pid;
                hdr->holder_obj = obj;
                hdr->holder_ctime = ctime;
                shared_state_unlock(hdr);
                WARN("Keyed mutex abandoned by process %lu.\n", hpid);
                hr = (HRESULT)WAIT_ABANDONED;
                break;
            }
            shared_state_unlock(hdr);
            continue;
        }

        if (!timeout || (timeout != INFINITE && GetTickCount() - start >= timeout))
            return (HRESULT)WAIT_TIMEOUT;
        if (++spins < 16)
            Sleep(0);
        else
            Sleep(1);
    }

    shared_pull(shared);
    return hr;
}

static HRESULT STDMETHODCALLTYPE shared_mutex_ReleaseSync(IDXGIKeyedMutex *iface, UINT64 key)
{
    struct d3d_shared *shared = impl_from_IDXGIKeyedMutex(iface);
    struct shared_header *hdr = shared->hdr;
    DWORD pid = GetCurrentProcessId(), obj = (DWORD)(ULONG_PTR)shared;
    BOOL mine;

    TRACE("iface %p, key %s.\n", iface, wine_dbgstr_longlong(key));

    shared_state_lock(hdr);
    mine = hdr->held && hdr->holder_pid == pid && hdr->holder_obj == obj;
    shared_state_unlock(hdr);
    if (!mine)
        return E_FAIL;

    /* a depth/stencil, multisampled or staging texture has nothing to exchange; render targets and UAVs
     * may have been written by commands we did not see */
    if (shared->dirty || (shared->texture->desc.BindFlags & (D3D11_BIND_RENDER_TARGET | D3D11_BIND_UNORDERED_ACCESS)))
        shared_push(shared);

    shared_state_lock(hdr);
    hdr->key = (LONG64)key;
    hdr->held = 0;
    hdr->holder_pid = 0;
    hdr->holder_obj = 0;
    hdr->holder_ctime = 0;
    shared_state_unlock(hdr);
    return S_OK;
}

static const struct IDXGIKeyedMutexVtbl shared_mutex_vtbl =
{
    shared_mutex_QueryInterface,
    shared_mutex_AddRef,
    shared_mutex_Release,
    shared_mutex_SetPrivateData,
    shared_mutex_SetPrivateDataInterface,
    shared_mutex_GetPrivateData,
    shared_mutex_GetParent,
    shared_mutex_GetDevice,
    shared_mutex_AcquireSync,
    shared_mutex_ReleaseSync,
};

/* ---------------------------------------------------------------------- IDXGIResource1 */

static inline struct d3d_texture2d *impl_from_IDXGIResource1(IDXGIResource1 *iface)
{
    return CONTAINING_RECORD(iface, struct d3d_texture2d, IDXGIResource1_iface);
}

static IDXGIResource *inner_resource(struct d3d_texture2d *texture)
{
    IDXGIResource *resource = NULL;

    IUnknown_QueryInterface(texture->dxgi_resource, &IID_IDXGIResource, (void **)&resource);
    return resource;
}

static HRESULT STDMETHODCALLTYPE dxgi_res1_QueryInterface(IDXGIResource1 *iface, REFIID iid, void **out)
{
    return ID3D11Texture2D_QueryInterface(&impl_from_IDXGIResource1(iface)->ID3D11Texture2D_iface, iid, out);
}

static ULONG STDMETHODCALLTYPE dxgi_res1_AddRef(IDXGIResource1 *iface)
{
    return ID3D11Texture2D_AddRef(&impl_from_IDXGIResource1(iface)->ID3D11Texture2D_iface);
}

static ULONG STDMETHODCALLTYPE dxgi_res1_Release(IDXGIResource1 *iface)
{
    return ID3D11Texture2D_Release(&impl_from_IDXGIResource1(iface)->ID3D11Texture2D_iface);
}

#define FORWARD_RES(call) \
    IDXGIResource *r = inner_resource(impl_from_IDXGIResource1(iface)); \
    HRESULT hr; \
    if (!r) return E_NOINTERFACE; \
    hr = call; \
    IDXGIResource_Release(r); \
    return hr;

static HRESULT STDMETHODCALLTYPE dxgi_res1_SetPrivateData(IDXGIResource1 *iface, REFGUID guid, UINT size, const void *data)
{
    FORWARD_RES(IDXGIResource_SetPrivateData(r, guid, size, data))
}

static HRESULT STDMETHODCALLTYPE dxgi_res1_SetPrivateDataInterface(IDXGIResource1 *iface, REFGUID guid, const IUnknown *obj)
{
    FORWARD_RES(IDXGIResource_SetPrivateDataInterface(r, guid, obj))
}

static HRESULT STDMETHODCALLTYPE dxgi_res1_GetPrivateData(IDXGIResource1 *iface, REFGUID guid, UINT *size, void *data)
{
    FORWARD_RES(IDXGIResource_GetPrivateData(r, guid, size, data))
}

static HRESULT STDMETHODCALLTYPE dxgi_res1_GetParent(IDXGIResource1 *iface, REFIID iid, void **parent)
{
    FORWARD_RES(IDXGIResource_GetParent(r, iid, parent))
}

static HRESULT STDMETHODCALLTYPE dxgi_res1_GetDevice(IDXGIResource1 *iface, REFIID iid, void **device)
{
    FORWARD_RES(IDXGIResource_GetDevice(r, iid, device))
}

static HRESULT STDMETHODCALLTYPE dxgi_res1_GetSharedHandle(IDXGIResource1 *iface, HANDLE *handle)
{
    struct d3d_texture2d *texture = impl_from_IDXGIResource1(iface);
    struct d3d_shared *shared = texture->shared;

    TRACE("iface %p, handle %p.\n", iface, handle);

    if (!handle)
        return E_INVALIDARG;
    if (!shared)
    {
        *handle = NULL; /* not a shared resource: success, no handle */
        return S_OK;
    }
    if (!shared->token)
        return E_INVALIDARG; /* NT handle resources have no legacy handle */
    *handle = (HANDLE)(ULONG_PTR)shared->token;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dxgi_res1_GetUsage(IDXGIResource1 *iface, DXGI_USAGE *usage)
{
    FORWARD_RES(IDXGIResource_GetUsage(r, usage))
}

static HRESULT STDMETHODCALLTYPE dxgi_res1_SetEvictionPriority(IDXGIResource1 *iface, UINT priority)
{
    FORWARD_RES(IDXGIResource_SetEvictionPriority(r, priority))
}

static HRESULT STDMETHODCALLTYPE dxgi_res1_GetEvictionPriority(IDXGIResource1 *iface, UINT *priority)
{
    FORWARD_RES(IDXGIResource_GetEvictionPriority(r, priority))
}

static HRESULT STDMETHODCALLTYPE dxgi_res1_CreateSubresourceSurface(IDXGIResource1 *iface, UINT index,
        IDXGISurface2 **surface)
{
    FIXME("iface %p, index %u, surface %p stub!\n", iface, index, surface);

    return E_NOTIMPL;
}

static HRESULT shared_create_section(struct d3d_shared *shared, SECURITY_ATTRIBUTES *sa, const WCHAR *name,
        BOOL publish);

static HRESULT STDMETHODCALLTYPE dxgi_res1_CreateSharedHandle(IDXGIResource1 *iface, const SECURITY_ATTRIBUTES *attributes,
        DWORD access, const WCHAR *name, HANDLE *handle)
{
    struct d3d_texture2d *texture = impl_from_IDXGIResource1(iface);
    struct d3d_shared *shared = texture->shared;
    HRESULT hr;

    TRACE("iface %p, attributes %p, access %#lx, name %s, handle %p.\n", iface, attributes, access,
            debugstr_w(name), handle);

    if (!handle)
        return E_INVALIDARG;
    *handle = NULL;
    if (!shared || !shared->nt)
        return E_INVALIDARG; /* only SHARED_NTHANDLE resources */

    if (!shared->section)
    {
        /* the section is created now so that the first request can name it */
        if (FAILED(hr = shared_create_section(shared, (SECURITY_ATTRIBUTES *)attributes, name, TRUE)))
            return hr;
    }
    else if (name)
    {
        FIXME("A name for a resource that already has a section is not supported.\n");
        return DXGI_ERROR_NAME_ALREADY_EXISTS;
    }

    if (!DuplicateHandle(GetCurrentProcess(), shared->section, GetCurrentProcess(), handle, 0,
            attributes && attributes->bInheritHandle, DUPLICATE_SAME_ACCESS))
    {
        *handle = NULL;
        return HRESULT_FROM_WIN32(GetLastError());
    }
    return S_OK;
}

static const struct IDXGIResource1Vtbl dxgi_resource1_vtbl =
{
    dxgi_res1_QueryInterface,
    dxgi_res1_AddRef,
    dxgi_res1_Release,
    dxgi_res1_SetPrivateData,
    dxgi_res1_SetPrivateDataInterface,
    dxgi_res1_GetPrivateData,
    dxgi_res1_GetParent,
    dxgi_res1_GetDevice,
    dxgi_res1_GetSharedHandle,
    dxgi_res1_GetUsage,
    dxgi_res1_SetEvictionPriority,
    dxgi_res1_GetEvictionPriority,
    dxgi_res1_CreateSubresourceSurface,
    dxgi_res1_CreateSharedHandle,
};

void d3d_texture2d_init_dxgi_resource1(struct d3d_texture2d *texture)
{
    texture->IDXGIResource1_iface.lpVtbl = &dxgi_resource1_vtbl;
}

/* called by d3d11_texture2d_QueryInterface; TRUE when the interface was handled */
BOOL d3d_texture2d_shared_query_interface(struct d3d_texture2d *texture, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IDXGIResource) || IsEqualGUID(iid, &IID_IDXGIResource1))
    {
        *out = &texture->IDXGIResource1_iface;
        ID3D11Texture2D_AddRef(&texture->ID3D11Texture2D_iface);
        return TRUE;
    }
    if (IsEqualGUID(iid, &IID_IDXGIKeyedMutex) && texture->shared && texture->shared->keyed)
    {
        *out = &texture->shared->IDXGIKeyedMutex_iface;
        ID3D11Texture2D_AddRef(&texture->ID3D11Texture2D_iface);
        return TRUE;
    }
    return FALSE;
}

/* ---------------------------------------------------------------------- creation */

static void shared_adopt_header(struct d3d_shared *shared, struct shared_header *hdr, BYTE *view)
{
    shared->view = view;
    shared->hdr = hdr;
}

static HRESULT shared_create_section(struct d3d_shared *shared, SECURITY_ATTRIBUTES *sa, const WCHAR *name,
        BOOL publish)
{
    WCHAR token_name[64];
    struct shared_header *hdr;
    DWORD total = SHARED_HDR_SIZE + (DWORD)shared->data_size, i;
    HANDLE section = NULL;
    BYTE *view;

    if (shared->token)
    {
        for (i = 0; i < 64; ++i)
        {
            SetLastError(0);
            swprintf(token_name, ARRAY_SIZE(token_name), L"Local\\NitroD3D11Shared.%08lX", (unsigned long)shared->token);
            section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, total, token_name);
            if (section && GetLastError() != ERROR_ALREADY_EXISTS)
                break;
            if (section)
                CloseHandle(section);
            section = NULL;
            shared->token = 0x40000002 + 0x40 * ((InterlockedIncrement(&shared_token_counter) + GetCurrentProcessId() * 0x400) & 0xffffff);
        }
        if (!section)
            return E_OUTOFMEMORY;
    }
    else
    {
        SetLastError(0);
        section = CreateFileMappingW(INVALID_HANDLE_VALUE, sa, PAGE_READWRITE, 0, total, name);
        if (section && name && GetLastError() == ERROR_ALREADY_EXISTS)
        {
            CloseHandle(section);
            return DXGI_ERROR_NAME_ALREADY_EXISTS;
        }
        if (!section)
            return E_OUTOFMEMORY;
    }

    if (!(view = MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, 0)))
    {
        CloseHandle(section);
        return E_OUTOFMEMORY;
    }
    hdr = (struct shared_header *)view;
    if (shared->hdr == &shared->local_hdr)
    {
        /* migrate the keyed-mutex state of the local header, then publish the contents */
        *hdr = shared->local_hdr;
        hdr->lock = 0;
        hdr->gen = 0;
    }
    shared->section = section;
    shared_adopt_header(shared, hdr, view);
    shared->last_gen = 0;
    if (publish && shared->sub_count)
        shared_push(shared);
    return S_OK;
}

struct d3d_shared_open
{
    HANDLE section;     /* owned by the callee on success */
    BYTE *view;
    struct shared_header *hdr;
    SIZE_T view_size;
    DWORD token;        /* the legacy handle it was opened with */
};

static BOOL shared_validate_view(BYTE *view, SIZE_T *size)
{
    MEMORY_BASIC_INFORMATION info;
    struct shared_header *hdr = (struct shared_header *)view;

    if (!VirtualQuery(view, &info, sizeof(info)) || info.RegionSize < SHARED_HDR_SIZE)
        return FALSE;
    if (hdr->magic != SHARED_MAGIC || hdr->version != SHARED_VERSION || hdr->total_size < SHARED_HDR_SIZE
            || info.RegionSize < hdr->total_size)
        return FALSE;
    *size = info.RegionSize;
    return TRUE;
}

/* attach shared state to a texture being created; open is NULL for a new resource */
HRESULT d3d_texture2d_shared_attach(struct d3d_device *device, struct d3d_texture2d *texture,
        struct d3d_shared_open *open)
{
    UINT misc = texture->desc.MiscFlags;
    struct d3d_shared *shared;

    if (!(misc & (D3D11_RESOURCE_MISC_SHARED | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX | D3D11_RESOURCE_MISC_SHARED_NTHANDLE)))
        return S_OK;

    if (!(shared = calloc(1, sizeof(*shared))))
        return E_OUTOFMEMORY;
    shared->texture = texture;
    shared->device = device;
    shared->nt = !!(misc & D3D11_RESOURCE_MISC_SHARED_NTHANDLE);
    shared->keyed = !!(misc & D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX);
    shared->IDXGIKeyedMutex_iface.lpVtbl = &shared_mutex_vtbl;
    shared->hdr = &shared->local_hdr;
    texture->shared = shared;

    if (!shared_layout_fits(&texture->desc, open ? open->view_size : 0)
            || (open && (open->hdr->total_size < SHARED_HDR_SIZE + shared_data_bytes(&texture->desc)
            || open->hdr->total_size > open->view_size)))
    {
        free(shared);
        texture->shared = NULL;
        return E_INVALIDARG;
    }
    if (!shared_compute_layout(shared, &texture->desc))
    {
        free(shared->sub_offset); free(shared->sub_row_bytes); free(shared->sub_rows);
        free(shared);
        texture->shared = NULL;
        return E_OUTOFMEMORY;
    }
    shared_fill_header(shared, &shared->local_hdr, &texture->desc);

    if (open)
    {
        shared->section = open->section;
        shared->view = open->view;
        shared->hdr = open->hdr;
        shared->token = open->token;
        shared->last_gen = 0;
    }
    else
    {
        if (!shared->nt)
        {
            HRESULT hr;

            shared->token = 0x40000002 + 0x40 * ((InterlockedIncrement(&shared_token_counter) + GetCurrentProcessId() * 0x400) & 0xffffff);
            if (FAILED(hr = shared_create_section(shared, NULL, NULL, FALSE)))
            {
                free(shared->sub_offset); free(shared->sub_row_bytes); free(shared->sub_rows);
                free(shared);
                texture->shared = NULL;
                return hr;
            }
        }
    }

    EnterCriticalSection(&device->shared_cs);
    list_add_tail(&device->shared_list, &shared->entry);
    shared->listed = TRUE;
    LeaveCriticalSection(&device->shared_cs);
    return S_OK;
}

/* initial contents of a new shared resource */
void d3d_texture2d_shared_created(struct d3d_texture2d *texture, BOOL has_initial_data)
{
    if (texture->shared && has_initial_data && texture->shared->view)
        shared_push(texture->shared);
}

/* last reference to the texture is gone; the device is still alive */
void d3d_texture2d_shared_destroy(struct d3d_texture2d *texture)
{
    struct d3d_shared *shared = texture->shared;

    if (!shared)
        return;
    texture->shared = NULL;

    EnterCriticalSection(&shared->device->shared_cs);
    if (shared->listed)
        list_remove(&shared->entry);
    shared->listed = FALSE;
    LeaveCriticalSection(&shared->device->shared_cs);

    if (shared->staging)
        ID3D11Texture2D_Release(shared->staging);
    /* a keyed mutex still held by this texture must not leave the others waiting forever */
    if (shared->view && shared->keyed)
    {
        struct shared_header *hdr = shared->hdr;

        shared_state_lock(hdr);
        if (hdr->held && hdr->holder_pid == GetCurrentProcessId() && hdr->holder_obj == (DWORD)(ULONG_PTR)shared)
        {
            hdr->held = 0;
            hdr->holder_pid = 0;
            hdr->holder_obj = 0;
        }
        shared_state_unlock(hdr);
    }
    shared_unmap(shared);
    free(shared->sub_offset);
    free(shared->sub_row_bytes);
    free(shared->sub_rows);
    free(shared);
}

void d3d_device_shared_init(struct d3d_device *device)
{
    list_init(&device->shared_list);
    InitializeCriticalSection(&device->shared_cs);
}

void d3d_device_shared_cleanup(struct d3d_device *device)
{
    DeleteCriticalSection(&device->shared_cs);
}

/* ---------------------------------------------------------------------- context hooks */

static struct d3d_texture2d *texture_from_resource(ID3D11Resource *resource)
{
    D3D11_RESOURCE_DIMENSION dim;

    if (!resource)
        return NULL;
    ID3D11Resource_GetType(resource, &dim);
    if (dim != D3D11_RESOURCE_DIMENSION_TEXTURE2D)
        return NULL;
    return unsafe_impl_from_ID3D11Texture2D((ID3D11Texture2D *)resource);
}

/* before a shared texture is read by the GPU (shader resource, copy source): bring in newer contents */
void d3d_shared_resource_read(ID3D11Resource *resource)
{
    struct d3d_texture2d *texture = texture_from_resource(resource);

    if (texture && texture->shared && !texture->shared->keyed && !texture->shared->busy)
        shared_pull(texture->shared);
}

/* a shared texture is written (copy destination, update, clear, render target bind) */
void d3d_shared_resource_written(ID3D11Resource *resource, BOOL bound_as_target)
{
    struct d3d_texture2d *texture = texture_from_resource(resource);

    if (!texture || !texture->shared || texture->shared->busy)
        return;
    texture->shared->dirty = TRUE;
    if (bound_as_target)
        texture->shared->rt_bound = TRUE;
}

void d3d_shared_view_resource_read(ID3D11ShaderResourceView *view)
{
    ID3D11Resource *resource = NULL;

    if (!view)
        return;
    ID3D11ShaderResourceView_GetResource(view, &resource);
    if (resource)
    {
        d3d_shared_resource_read(resource);
        ID3D11Resource_Release(resource);
    }
}

void d3d_shared_view_resource_written(ID3D11RenderTargetView *view, BOOL bound_as_target)
{
    ID3D11Resource *resource = NULL;

    if (!view)
        return;
    ID3D11RenderTargetView_GetResource(view, &resource);
    if (resource)
    {
        d3d_shared_resource_written(resource, bound_as_target);
        ID3D11Resource_Release(resource);
    }
}

/* ID3D11DeviceContext::Flush on the immediate context */
void d3d_device_shared_flush(struct d3d_device *device)
{
    struct d3d_shared *shared;
    BOOL activity;

    if (list_empty(&device->shared_list))
        return;
    activity = device->shared_activity;
    device->shared_activity = FALSE;
    EnterCriticalSection(&device->shared_cs);
    LIST_FOR_EACH_ENTRY(shared, &device->shared_list, struct d3d_shared, entry)
    {
        if (shared->keyed || !shared->view)
            continue;
        if (shared_pull(shared))
            continue;
        if (shared->dirty || (shared->rt_bound && activity))
            shared_push(shared);
    }
    LeaveCriticalSection(&device->shared_cs);
}

/* ---------------------------------------------------------------------- opening */

static HRESULT shared_open_view(HANDLE section, struct d3d_shared_open *open)
{
    BYTE *view;

    if (!(view = MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, 0)))
        return E_INVALIDARG;
    if (!shared_validate_view(view, &open->view_size))
    {
        UnmapViewOfFile(view);
        return E_INVALIDARG;
    }
    open->section = section;
    open->view = view;
    open->hdr = (struct shared_header *)view;
    return S_OK;
}

HRESULT d3d_device_open_shared(struct d3d_device *device, HANDLE handle, const WCHAR *name, int mode,
        REFIID iid, void **out)
{
    struct d3d_shared_open open = {0};
    D3D11_TEXTURE2D_DESC desc = {0};
    struct d3d_texture2d *texture;
    HANDLE section = NULL, dup = NULL;
    struct shared_header *hdr;
    HRESULT hr;

    if (!out)
        return E_INVALIDARG;
    *out = NULL;

    switch (mode)
    {
        case D3D_OPEN_LEGACY:
        {
            WCHAR token_name[64];

            if (!handle)
                return E_INVALIDARG;
            swprintf(token_name, ARRAY_SIZE(token_name), L"Local\\NitroD3D11Shared.%08lX", (unsigned long)(ULONG_PTR)handle);
            if (!(section = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, token_name)))
                return E_INVALIDARG;
            dup = section;
            open.token = (DWORD)(ULONG_PTR)handle;
            break;
        }
        case D3D_OPEN_NT:
            if (!handle || handle == INVALID_HANDLE_VALUE)
                return E_INVALIDARG;
            if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
                return E_INVALIDARG;
            break;
        case D3D_OPEN_NAME:
            if (!name || !(dup = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name)))
                return E_INVALIDARG;
            break;
        default:
            return E_INVALIDARG;
    }

    if (FAILED(hr = shared_open_view(dup, &open)))
    {
        CloseHandle(dup);
        return hr;
    }
    hdr = open.hdr;

    /* a legacy handle only opens legacy resources and the other way round is what Windows enforces */
    if (mode == D3D_OPEN_LEGACY && (hdr->misc_flags & D3D11_RESOURCE_MISC_SHARED_NTHANDLE))
    {
        UnmapViewOfFile(open.view);
        CloseHandle(dup);
        return E_INVALIDARG;
    }
    if (mode != D3D_OPEN_LEGACY && !(hdr->misc_flags & D3D11_RESOURCE_MISC_SHARED_NTHANDLE))
    {
        UnmapViewOfFile(open.view);
        CloseHandle(dup);
        return E_INVALIDARG;
    }

    desc.Width = hdr->width;
    desc.Height = hdr->height;
    desc.MipLevels = hdr->mip_levels;
    desc.ArraySize = hdr->array_size;
    desc.Format = hdr->format;
    desc.SampleDesc.Count = hdr->sample_count;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = hdr->bind_flags;
    desc.MiscFlags = hdr->misc_flags;

    /* the header is another process's data: check it before anything is allocated from it */
    if (!(desc.MiscFlags & (D3D11_RESOURCE_MISC_SHARED | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX))
            || !shared_layout_fits(&desc, open.view_size)
            || hdr->total_size < SHARED_HDR_SIZE + shared_data_bytes(&desc) || hdr->total_size > open.view_size)
    {
        UnmapViewOfFile(open.view);
        CloseHandle(dup);
        return E_INVALIDARG;
    }

    if (FAILED(hr = d3d_texture2d_create_shared_open(device, &desc, &open, &texture)))
    {
        UnmapViewOfFile(open.view);
        CloseHandle(dup);
        return hr;
    }

    /* the texture owns the section now; it holds whatever the creator had pushed */
    if (texture->shared)
    {
        texture->shared->last_gen = 0;
        shared_pull(texture->shared);
    }
    hr = ID3D11Texture2D_QueryInterface(&texture->ID3D11Texture2D_iface, iid, out);
    ID3D11Texture2D_Release(&texture->ID3D11Texture2D_iface);
    return hr;
}
