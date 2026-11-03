/*
 * A stub manager is an object that controls interface stubs. It is
 * identified by an OID (object identifier) and acts as the network
 * identity of the object. There can be many stub managers in a
 * process or apartment.
 *
 * Copyright 2002 Marcus Meissner
 * Copyright 2004 Mike Hearn for CodeWeavers
 * Copyright 2004 Robert Shearman (for CodeWeavers)
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

#define COBJMACROS

#include <assert.h>
#include <stdarg.h>
#include <limits.h>

#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "objbase.h"
#include "rpc.h"

#include "wine/debug.h"
#include "wine/exception.h"

#include "initguid.h"
#include "dcom.h"
#include "combase_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(ole);

/* generates an ipid in the following format (similar to native version):
 * Data1 = apartment-local ipid counter
 * Data2 = apartment creator thread ID, or 0 for an MTA.
 * Data3 = process ID
 * Data4 = random value
 */
static inline HRESULT generate_ipid(struct stub_manager *m, IPID *ipid)
{
    HRESULT hr;
    hr = UuidCreate(ipid);
    if (FAILED(hr))
    {
        ERR("couldn't create IPID for stub manager %p\n", m);
        UuidCreateNil(ipid);
        return hr;
    }

    ipid->Data1 = InterlockedIncrement(&m->apt->ipidc);
    ipid->Data2 = !m->apt->multi_threaded ? (USHORT)m->apt->tid : 0;
    ipid->Data3 = (USHORT)GetCurrentProcessId();
    return S_OK;
}

/* registers a new interface stub COM object with the stub manager and returns registration record */
struct ifstub * stub_manager_new_ifstub(struct stub_manager *m, IRpcStubBuffer *sb, REFIID iid, DWORD dest_context,
    void *dest_context_data, MSHLFLAGS flags)
{
    struct ifstub *stub;
    HRESULT hr;

    TRACE("oid=%s, stubbuffer=%p, iid=%s, dest_context=%lx\n", wine_dbgstr_longlong(m->oid), sb,
          debugstr_guid(iid), dest_context);

    stub = calloc(1, sizeof(struct ifstub));
    if (!stub) return NULL;

    hr = IUnknown_QueryInterface(m->object, iid, (void **)&stub->iface);
    if (hr != S_OK)
    {
        free(stub);
        return NULL;
    }

    hr = rpc_create_serverchannel(dest_context, dest_context_data, &stub->chan);
    if (hr != S_OK)
    {
        IUnknown_Release(stub->iface);
        free(stub);
        return NULL;
    }

    stub->stubbuffer = sb;
    if (sb) IRpcStubBuffer_AddRef(sb);

    stub->flags = flags;
    stub->iid = *iid;

    /* FIXME: find a cleaner way of identifying that we are creating an ifstub
     * for the remunknown interface */
    if (flags & MSHLFLAGSP_REMUNKNOWN)
        stub->ipid = m->oxid_info.ipidRemUnknown;
    else
        generate_ipid(m, &stub->ipid);

    EnterCriticalSection(&m->lock);
    list_add_head(&m->ifstubs, &stub->entry);
    /* every normal marshal is counted so we don't allow more than we should */
    if (flags & MSHLFLAGS_NORMAL) m->norm_refs++;
    LeaveCriticalSection(&m->lock);

    TRACE("ifstub %p created with ipid %s\n", stub, debugstr_guid(&stub->ipid));

    return stub;
}

static void stub_manager_delete_ifstub(struct stub_manager *m, struct ifstub *ifstub)
{
    TRACE("m=%p, m->oid=%s, ipid=%s\n", m, wine_dbgstr_longlong(m->oid), debugstr_guid(&ifstub->ipid));

    list_remove(&ifstub->entry);

    /* Do not wait for the calls that are running on the interface: the thread that destroys the
     * stub manager can be the one that dispatches the last of them (the last reference of the
     * manager is released when that call returns), and it would wait for itself while it holds
     * the interface registration lock, which blocks every marshal in the process. A running call
     * holds a reference of the stub manager, so none runs on a stub that is being deleted, and
     * the RPC runtime frees the interface after the last call completed. */
    if (!m->disconnected)
        rpc_unregister_interface(&ifstub->iid, FALSE);

    if (ifstub->stubbuffer) IRpcStubBuffer_Release(ifstub->stubbuffer);
    IUnknown_Release(ifstub->iface);
    IRpcChannelBuffer_Release(ifstub->chan);

    free(ifstub);
}

static struct ifstub *stub_manager_ipid_to_ifstub(struct stub_manager *m, const IPID *ipid)
{
    struct ifstub *result = NULL, *ifstub;

    EnterCriticalSection(&m->lock);
    LIST_FOR_EACH_ENTRY(ifstub, &m->ifstubs, struct ifstub, entry)
    {
        if (IsEqualGUID(ipid, &ifstub->ipid))
        {
            result = ifstub;
            break;
        }
    }
    LeaveCriticalSection(&m->lock);

    return result;
}

struct ifstub * stub_manager_find_ifstub(struct stub_manager *m, REFIID iid, MSHLFLAGS flags)
{
    struct ifstub  *result = NULL;
    struct ifstub  *ifstub;

    EnterCriticalSection(&m->lock);
    LIST_FOR_EACH_ENTRY( ifstub, &m->ifstubs, struct ifstub, entry )
    {
        if (IsEqualIID(iid, &ifstub->iid) && (ifstub->flags == flags))
        {
            result = ifstub;
            break;
        }
    }
    LeaveCriticalSection(&m->lock);

    return result;
}

/* creates a new stub manager and adds it into the apartment. caller must
 * release stub manager when it is no longer required. the apartment and
 * external refs together take one implicit ref */
static struct stub_manager *new_stub_manager(struct apartment *apt, IUnknown *object)
{
    struct stub_manager *sm;
    HRESULT hres;

    assert(apt);

    sm = calloc(1, sizeof(struct stub_manager));
    if (!sm) return NULL;

    list_init(&sm->ifstubs);

    InitializeCriticalSectionEx(&sm->lock, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
    sm->lock.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": stub_manager");

    IUnknown_AddRef(object);
    sm->object = object;
    sm->apt    = apt;

    /* start off with 2 references because the stub is in the apartment
     * and the caller will also hold a reference */
    sm->refs   = 2;
    sm->weakrefs = 0;

    sm->oxid_info.dwPid = GetCurrentProcessId();
    sm->oxid_info.dwTid = GetCurrentThreadId();
    /*
     * FIXME: this is a hack for marshalling IRemUnknown. In real
     * DCOM, the IPID of the IRemUnknown interface is generated like
     * any other and passed to the OXID resolver which then returns it
     * when queried. We don't have an OXID resolver yet so instead we
     * use a magic IPID reserved for IRemUnknown.
     */
    sm->oxid_info.ipidRemUnknown.Data1 = 0xffffffff;
    sm->oxid_info.ipidRemUnknown.Data2 = 0xffff;
    sm->oxid_info.ipidRemUnknown.Data3 = 0xffff;
    assert(sizeof(sm->oxid_info.ipidRemUnknown.Data4) == sizeof(apt->oxid));
    memcpy(sm->oxid_info.ipidRemUnknown.Data4, &apt->oxid, sizeof(OXID));
    sm->oxid_info.dwAuthnHint = RPC_C_AUTHN_LEVEL_NONE;
    sm->oxid_info.psa = NULL /* FIXME */;

    /* Yes, that's right, this starts at zero. that's zero EXTERNAL
     * refs, i.e., nobody has unmarshalled anything yet. We can't have
     * negative refs because the stub manager cannot be explicitly
     * killed, it has to die by somebody unmarshalling then releasing
     * the marshalled ifptr.
     */
    sm->extrefs = 0;
    sm->counted_refs = 0;
    sm->disconnected = FALSE;

    hres = IUnknown_QueryInterface(object, &IID_IExternalConnection, (void**)&sm->extern_conn);
    if(FAILED(hres))
        sm->extern_conn = NULL;

    EnterCriticalSection(&apt->cs);
    sm->oid = apt->oidc++;
    list_add_head(&apt->stubmgrs, &sm->entry);
    LeaveCriticalSection(&apt->cs);

    TRACE("Created new stub manager (oid=%s) at %p for object with IUnknown %p\n", wine_dbgstr_longlong(sm->oid), sm, object);
    
    return sm;
}

static void stub_manager_uncount_refs(struct stub_manager *m);

void stub_manager_disconnect(struct stub_manager *m)
{
    struct ifstub *ifstub;

    EnterCriticalSection(&m->lock);
    if (!m->disconnected)
    {
        LIST_FOR_EACH_ENTRY(ifstub, &m->ifstubs, struct ifstub, entry)
            rpc_unregister_interface(&ifstub->iid, FALSE);

        m->disconnected = TRUE;
    }
    LeaveCriticalSection(&m->lock);

    stub_manager_uncount_refs(m);
}

/* caller must remove stub manager from apartment prior to calling this function */
static void stub_manager_delete(struct stub_manager *m)
{
    struct list *cursor;

    TRACE("destroying %p (oid=%s)\n", m, wine_dbgstr_longlong(m->oid));

    stub_manager_uncount_refs(m);

    /* release every ifstub */
    while ((cursor = list_head(&m->ifstubs)))
    {
        struct ifstub *ifstub = LIST_ENTRY(cursor, struct ifstub, entry);
        stub_manager_delete_ifstub(m, ifstub);
    }

    if(m->extern_conn)
        IExternalConnection_Release(m->extern_conn);

    CoTaskMemFree(m->oxid_info.psa);

    /* Some broken apps crash in object destructors. We have a test showing
     * that on winxp+ those crashes are caught and ignored. */
    __TRY
    {
        IUnknown_Release(m->object);
    }
    __EXCEPT_PAGE_FAULT
    {
        ERR("Got page fault when releasing stub!\n");
    }
    __ENDTRY

    m->lock.DebugInfo->Spare[0] = 0;
    DeleteCriticalSection(&m->lock);

    free(m);
}

/* increments the internal refcount */
static ULONG stub_manager_int_addref(struct stub_manager *m)
{
    ULONG refs;

    EnterCriticalSection(&m->apt->cs);
    refs = ++m->refs;
    LeaveCriticalSection(&m->apt->cs);

    TRACE("before %ld\n", refs - 1);

    return refs;
}

/* decrements the internal refcount */
ULONG stub_manager_int_release(struct stub_manager *m)
{
    ULONG refs;
    struct apartment *apt = m->apt;

    EnterCriticalSection(&apt->cs);
    refs = --m->refs;

    TRACE("after %ld\n", refs);

    /* remove from apartment so no other thread can access it... */
    if (!refs)
        list_remove(&m->entry);

    LeaveCriticalSection(&apt->cs);

    /* ... so now we can delete it without being inside the apartment critsec */
    if (!refs)
        stub_manager_delete(m);

    return refs;
}

/* gets the stub manager associated with an object - caller must have
 * a reference to the apartment while a reference to the stub manager is held.
 * it must also call release on the stub manager when it is no longer needed */
struct stub_manager * get_stub_manager_from_object(struct apartment *apt, IUnknown *obj, BOOL alloc)
{
    struct stub_manager *result = NULL, *m;
    IUnknown *object;
    HRESULT hres;

    hres = IUnknown_QueryInterface(obj, &IID_IUnknown, (void**)&object);
    if (FAILED(hres))
    {
        ERR("QueryInterface(IID_IUnknown failed): %#lx\n", hres);
        return NULL;
    }

    EnterCriticalSection(&apt->cs);
    LIST_FOR_EACH_ENTRY(m, &apt->stubmgrs, struct stub_manager, entry)
    {
        if (m->object == object)
        {
            result = m;
            stub_manager_int_addref(result);
            break;
        }
    }
    LeaveCriticalSection(&apt->cs);

    if (result)
    {
        TRACE("found %p for object %p\n", result, object);
    }
    else if (alloc)
    {
        TRACE("not found, creating new stub manager...\n");
        result = new_stub_manager(apt, object);
    }
    else
    {
        TRACE("not found for object %p\n", object);
    }

    IUnknown_Release(object);
    return result;    
}

/* gets the stub manager associated with an object id - caller must have
 * a reference to the apartment while a reference to the stub manager is held.
 * it must also call release on the stub manager when it is no longer needed */
struct stub_manager * get_stub_manager(struct apartment *apt, OID oid)
{
    struct stub_manager *result = NULL, *m;

    EnterCriticalSection(&apt->cs);
    LIST_FOR_EACH_ENTRY(m, &apt->stubmgrs, struct stub_manager, entry)
    {
        if (m->oid == oid)
        {
            result = m;
            stub_manager_int_addref(result);
            break;
        }
    }
    LeaveCriticalSection(&apt->cs);

    if (result)
        TRACE("found %p for oid %s\n", result, wine_dbgstr_longlong(oid));
    else
        TRACE("not found for oid %s\n", wine_dbgstr_longlong(oid));

    return result;
}

/* External references held by clients on objects of this process, table-strong
 * references excluded. When a surrogate is registered and the count drops back
 * to zero, the last client is gone and the surrogate is asked to exit. */
static LONG surrogate_extrefs;
static ISurrogate *process_surrogate;
static CRITICAL_SECTION surrogate_cs = { NULL, -1, 0, 0, 0, 0 };

void stub_manager_set_surrogate(ISurrogate *surrogate)
{
    ISurrogate *old;

    if (surrogate) ISurrogate_AddRef(surrogate);
    EnterCriticalSection(&surrogate_cs);
    old = process_surrogate;
    process_surrogate = surrogate;
    LeaveCriticalSection(&surrogate_cs);
    if (old) ISurrogate_Release(old);
}

/* Each stub manager tracks how many of its external references are counted in
 * surrogate_extrefs (m->counted_refs), so that what it drops without a client
 * releasing it (disconnect, destruction) is taken back exactly, and so that
 * releases never take back more than was counted. */
static void surrogate_extrefs_changed(LONG delta)
{
    ISurrogate *surrogate = NULL;

    if (InterlockedExchangeAdd(&surrogate_extrefs, delta) + delta != 0 || delta > 0)
        return;

    EnterCriticalSection(&surrogate_cs);
    if ((surrogate = process_surrogate)) ISurrogate_AddRef(surrogate);
    LeaveCriticalSection(&surrogate_cs);
    if (!surrogate) return;

    TRACE("last external reference gone, freeing surrogate %p\n", surrogate);
    ISurrogate_FreeSurrogate(surrogate);
    ISurrogate_Release(surrogate);
}

/* the clients of a disconnected or destroyed stub are gone: stop counting their references */
static void stub_manager_uncount_refs(struct stub_manager *m)
{
    ULONG counted;

    EnterCriticalSection(&m->lock);
    counted = m->counted_refs;
    m->counted_refs = 0;
    LeaveCriticalSection(&m->lock);

    if (counted)
        surrogate_extrefs_changed(-(LONG)counted);
}

static ULONG ext_addref(struct stub_manager *m, ULONG refs, BOOL tableweak, BOOL table)
{
    BOOL first_extern_ref;
    ULONG rc;

    EnterCriticalSection(&m->lock);

    first_extern_ref = refs && !m->extrefs;

    /* make sure we don't overflow extrefs */
    refs = min(refs, (ULONG_MAX-1 - m->extrefs));
    rc = (m->extrefs += refs);
    if (!table)
        m->counted_refs += refs;

    if (tableweak)
        rc += ++m->weakrefs;

    LeaveCriticalSection(&m->lock);

    if (!table && refs)
        InterlockedExchangeAdd(&surrogate_extrefs, refs);

    TRACE("added %lu refs to %p (oid %s), rc is now %lu\n", refs, m, wine_dbgstr_longlong(m->oid), rc);

    /*
     * NOTE: According to tests, creating a stub causes two AddConnection calls followed by
     * one ReleaseConnection call (with fLastReleaseCloses=FALSE).
     */
    if(first_extern_ref && m->extern_conn)
        IExternalConnection_AddConnection(m->extern_conn, EXTCONN_STRONG, 0);

    return rc;
}

/* add some external references (ie from a client that unmarshaled an ifptr) */
ULONG stub_manager_ext_addref(struct stub_manager *m, ULONG refs, BOOL tableweak)
{
    return ext_addref(m, refs, tableweak, FALSE);
}

/* references of the process itself (the table-strong marshal of a class registration,
 * the apartment's IRemUnknown), which are not a client's */
ULONG stub_manager_ext_addref_internal(struct stub_manager *m, ULONG refs)
{
    return ext_addref(m, refs, FALSE, TRUE);
}

static ULONG ext_release(struct stub_manager *m, ULONG refs, BOOL tableweak, BOOL last_unlock_releases, BOOL table)
{
    BOOL last_extern_ref;
    ULONG rc, counted = 0;

    EnterCriticalSection(&m->lock);

    /* make sure we don't underflow extrefs */
    refs = min(refs, m->extrefs);
    rc = (m->extrefs -= refs);

    if (tableweak)
        --m->weakrefs;
    if (!last_unlock_releases)
        rc += m->weakrefs;

    last_extern_ref = refs && !m->extrefs;

    if (!table)
    {
        counted = min(refs, m->counted_refs);
        m->counted_refs -= counted;
    }

    LeaveCriticalSection(&m->lock);

    if (counted)
        surrogate_extrefs_changed(-(LONG)counted);

    TRACE("removed %lu refs from %p (oid %s), rc is now %lu\n", refs, m, wine_dbgstr_longlong(m->oid), rc);

    if (last_extern_ref && m->extern_conn)
        IExternalConnection_ReleaseConnection(m->extern_conn, EXTCONN_STRONG, 0, last_unlock_releases);

    if (rc == 0)
        if (!(m->extern_conn && last_unlock_releases && m->weakrefs))
            stub_manager_int_release(m);

    return rc;
}

/* remove some external references */
ULONG stub_manager_ext_release(struct stub_manager *m, ULONG refs, BOOL tableweak, BOOL last_unlock_releases)
{
    return ext_release(m, refs, tableweak, last_unlock_releases, FALSE);
}

/* remove references of the process itself (see stub_manager_ext_addref_internal) */
ULONG stub_manager_ext_release_internal(struct stub_manager *m, ULONG refs, BOOL last_unlock_releases)
{
    return ext_release(m, refs, FALSE, last_unlock_releases, TRUE);
}

/* gets the stub manager associated with an ipid - caller must have
 * a reference to the apartment while a reference to the stub manager is held.
 * it must also call release on the stub manager when it is no longer needed */
static struct stub_manager *get_stub_manager_from_ipid(struct apartment *apt, const IPID *ipid, struct ifstub **ifstub)
{
    struct stub_manager *result = NULL, *m;

    EnterCriticalSection(&apt->cs);
    LIST_FOR_EACH_ENTRY(m, &apt->stubmgrs, struct stub_manager, entry)
    {
        if ((*ifstub = stub_manager_ipid_to_ifstub(m, ipid)))
        {
            result = m;
            stub_manager_int_addref(result);
            break;
        }
    }
    LeaveCriticalSection(&apt->cs);

    if (result)
        TRACE("found %p for ipid %s\n", result, debugstr_guid(ipid));
    else
        ERR("not found for ipid %s\n", debugstr_guid(ipid));

    return result;
}

static HRESULT ipid_to_ifstub(const IPID *ipid, struct apartment **stub_apt,
                              struct stub_manager **stubmgr_ret, struct ifstub **ifstub)
{
    /* FIXME: hack for IRemUnknown */
    if (ipid->Data2 == 0xffff)
        *stub_apt = apartment_findfromoxid(*(const OXID *)ipid->Data4);
    else if (!ipid->Data2 && (ipid->Data3 == (USHORT)GetCurrentProcessId()))
        *stub_apt = apartment_get_mta();
    else
        *stub_apt = apartment_findfromtid(ipid->Data2);
    if (!*stub_apt)
    {
        TRACE("Couldn't find apartment corresponding to TID 0x%04x, PID 0x%04x\n", ipid->Data2, ipid->Data3);
        return RPC_E_INVALID_OBJECT;
    }
    *stubmgr_ret = get_stub_manager_from_ipid(*stub_apt, ipid, ifstub);
    if (!*stubmgr_ret)
    {
        apartment_release(*stub_apt);
        *stub_apt = NULL;
        return RPC_E_INVALID_OBJECT;
    }
    return S_OK;
}

static HRESULT ipid_to_stub_manager(const IPID *ipid, struct apartment **stub_apt, struct stub_manager **stub)
{
    struct ifstub *ifstub;
    return ipid_to_ifstub(ipid, stub_apt, stub, &ifstub);
}

/* gets the apartment, stub and channel of an object. the caller must
 * release the references to all objects (except iface) if the function
 * returned success, otherwise no references are returned. */
HRESULT ipid_get_dispatch_params(const IPID *ipid, struct apartment **stub_apt,
        struct stub_manager **manager, IRpcStubBuffer **stub, IRpcChannelBuffer **chan,
        IID *iid, IUnknown **iface)
{
    struct stub_manager *stubmgr;
    struct ifstub *ifstub;
    struct apartment *apt;
    HRESULT hr;

    hr = ipid_to_ifstub(ipid, &apt, &stubmgr, &ifstub);
    if (hr != S_OK) return RPC_E_DISCONNECTED;

    *stub = ifstub->stubbuffer;
    IRpcStubBuffer_AddRef(*stub);
    *chan = ifstub->chan;
    IRpcChannelBuffer_AddRef(*chan);
    *stub_apt = apt;
    *iid = ifstub->iid;
    *iface = ifstub->iface;

    if (manager)
        *manager = stubmgr;
    else
        stub_manager_int_release(stubmgr);
    return S_OK;
}

HRESULT ipid_get_dest_context(const IPID *ipid, MSHCTX *dest_context, void **dest_context_data)
{
    struct stub_manager *stubmgr;
    struct ifstub *ifstub;
    struct apartment *apt;
    void *data;
    HRESULT hr;
    DWORD ctx;

    hr = ipid_to_ifstub(ipid, &apt, &stubmgr, &ifstub);
    if (hr != S_OK) return RPC_E_DISCONNECTED;

    hr = IRpcChannelBuffer_GetDestCtx(ifstub->chan, &ctx, &data);
    if (SUCCEEDED(hr))
    {
        *dest_context = ctx;
        *dest_context_data = data;
    }

    stub_manager_int_release(stubmgr);
    apartment_release(apt);

    return hr;
}

/* returns TRUE if it is possible to unmarshal, FALSE otherwise. */
BOOL stub_manager_notify_unmarshal(struct stub_manager *m, const IPID *ipid)
{
    BOOL ret = TRUE;
    struct ifstub *ifstub;

    if (!(ifstub = stub_manager_ipid_to_ifstub(m, ipid)))
    {
        ERR("attempted unmarshal of unknown IPID %s\n", debugstr_guid(ipid));
        return FALSE;
    }

    EnterCriticalSection(&m->lock);

    /* track normal marshals so we can enforce rules whilst in-process */
    if (ifstub->flags & MSHLFLAGS_NORMAL)
    {
        if (m->norm_refs)
            m->norm_refs--;
        else
        {
            ERR("attempted invalid normal unmarshal, norm_refs is zero\n");
            ret = FALSE;
        }
    }

    LeaveCriticalSection(&m->lock);

    return ret;
}

/* handles refcounting for CoReleaseMarshalData */
void stub_manager_release_marshal_data(struct stub_manager *m, ULONG refs, const IPID *ipid, BOOL tableweak)
{
    struct ifstub *ifstub;

    if (!(ifstub = stub_manager_ipid_to_ifstub(m, ipid)))
        return;

    if (ifstub->flags & MSHLFLAGS_TABLEWEAK)
        refs = 0;
    else if (ifstub->flags & MSHLFLAGS_TABLESTRONG)
        refs = 1;

    ext_release(m, refs, tableweak, !tableweak, !!(ifstub->flags & MSHLFLAGS_TABLESTRONG));
}

/* is an ifstub table marshaled? */
BOOL stub_manager_is_table_marshaled(struct stub_manager *m, const IPID *ipid)
{
    struct ifstub *ifstub = stub_manager_ipid_to_ifstub(m, ipid);
 
    assert(ifstub);

    return ifstub->flags & (MSHLFLAGS_TABLESTRONG | MSHLFLAGS_TABLEWEAK);
}

/*****************************************************************************
 *
 * IRemUnknown implementation
 *
 *
 * Note: this object is not related to the lifetime of a stub_manager, but it
 * interacts with stub managers.
 */

typedef struct rem_unknown
{
    IRemUnknown IRemUnknown_iface;
    LONG refs;
} RemUnknown;

static const IRemUnknownVtbl RemUnknown_Vtbl;

static inline RemUnknown *impl_from_IRemUnknown(IRemUnknown *iface)
{
    return CONTAINING_RECORD(iface, RemUnknown, IRemUnknown_iface);
}

/* construct an IRemUnknown object with one outstanding reference */
static HRESULT RemUnknown_Construct(IRemUnknown **ppRemUnknown)
{
    RemUnknown *object = malloc(sizeof(*object));

    if (!object)
        return E_OUTOFMEMORY;

    object->IRemUnknown_iface.lpVtbl = &RemUnknown_Vtbl;
    object->refs = 1;

    *ppRemUnknown = &object->IRemUnknown_iface;
    return S_OK;
}

static HRESULT WINAPI RemUnknown_QueryInterface(IRemUnknown *iface, REFIID riid, void **ppv)
{
    TRACE("%p, %s, %p\n", iface, debugstr_guid(riid), ppv);

    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IRemUnknown))
    {
        *ppv = iface;
        IRemUnknown_AddRef(iface);
        return S_OK;
    }

    if (!IsEqualIID(riid, &IID_IExternalConnection))
        FIXME("No interface for iid %s\n", debugstr_guid(riid));

    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI RemUnknown_AddRef(IRemUnknown *iface)
{
    ULONG refs;
    RemUnknown *remunk = impl_from_IRemUnknown(iface);

    refs = InterlockedIncrement(&remunk->refs);

    TRACE("%p before: %ld\n", iface, refs-1);
    return refs;
}

static ULONG WINAPI RemUnknown_Release(IRemUnknown *iface)
{
    ULONG refs;
    RemUnknown *remunk = impl_from_IRemUnknown(iface);

    refs = InterlockedDecrement(&remunk->refs);
    if (!refs)
        free(remunk);

    TRACE("%p after: %ld\n", iface, refs);
    return refs;
}

static HRESULT WINAPI RemUnknown_RemQueryInterface(IRemUnknown *iface,
    REFIPID ripid, ULONG cRefs, USHORT cIids, IID *iids /* [size_is(cIids)] */,
    REMQIRESULT **ppQIResults /* [size_is(,cIids)] */)
{
    HRESULT hr;
    USHORT i;
    USHORT successful_qis = 0;
    struct apartment *apt;
    struct stub_manager *stubmgr;
    struct ifstub *ifstub;
    DWORD dest_context;
    void *dest_context_data;

    TRACE("%p, %s, %ld, %d, %p, %p.\n", iface, debugstr_guid(ripid), cRefs, cIids, iids, ppQIResults);

    hr = ipid_to_ifstub(ripid, &apt, &stubmgr, &ifstub);
    if (hr != S_OK) return hr;

    IRpcChannelBuffer_GetDestCtx(ifstub->chan, &dest_context, &dest_context_data);

    *ppQIResults = CoTaskMemAlloc(sizeof(REMQIRESULT) * cIids);

    for (i = 0; i < cIids; i++)
    {
        HRESULT hrobj = marshal_object(apt, &(*ppQIResults)[i].std, &iids[i],
                                       stubmgr->object, dest_context, dest_context_data, MSHLFLAGS_NORMAL);
        if (hrobj == S_OK)
            successful_qis++;
        (*ppQIResults)[i].hResult = hrobj;
    }

    stub_manager_int_release(stubmgr);
    apartment_release(apt);

    if (successful_qis == cIids)
        return S_OK; /* we got all requested interfaces */
    else if (successful_qis == 0)
        return E_NOINTERFACE; /* we didn't get any interfaces */
    else
        return S_FALSE; /* we got some interfaces */
}

static HRESULT WINAPI RemUnknown_RemAddRef(IRemUnknown *iface,
    USHORT cInterfaceRefs,
    REMINTERFACEREF* InterfaceRefs /* [size_is(cInterfaceRefs)] */,
    HRESULT *pResults /* [size_is(cInterfaceRefs)] */)
{
    HRESULT hr = S_OK;
    USHORT i;

    TRACE("%p, %d, %p, %p\n", iface, cInterfaceRefs, InterfaceRefs, pResults);

    for (i = 0; i < cInterfaceRefs; i++)
    {
        struct apartment *apt;
        struct stub_manager *stubmgr;

        pResults[i] = ipid_to_stub_manager(&InterfaceRefs[i].ipid, &apt, &stubmgr);
        if (pResults[i] != S_OK)
        {
            hr = S_FALSE;
            continue;
        }

        stub_manager_ext_addref(stubmgr, InterfaceRefs[i].cPublicRefs, FALSE);
        if (InterfaceRefs[i].cPrivateRefs)
            FIXME("Adding %ld refs securely not implemented\n", InterfaceRefs[i].cPrivateRefs);

        stub_manager_int_release(stubmgr);
        apartment_release(apt);
    }

    return hr;
}

static HRESULT WINAPI RemUnknown_RemRelease(IRemUnknown *iface,
    USHORT cInterfaceRefs,
    REMINTERFACEREF* InterfaceRefs /* [size_is(cInterfaceRefs)] */)
{
    HRESULT hr = S_OK;
    USHORT i;

    TRACE("%p, %d, %p\n", iface, cInterfaceRefs, InterfaceRefs);

    for (i = 0; i < cInterfaceRefs; i++)
    {
        struct apartment *apt;
        struct stub_manager *stubmgr;

        hr = ipid_to_stub_manager(&InterfaceRefs[i].ipid, &apt, &stubmgr);
        if (hr != S_OK)
        {
            hr = E_INVALIDARG;
            /* FIXME: we should undo any changes already made in this function */
            break;
        }

        stub_manager_ext_release(stubmgr, InterfaceRefs[i].cPublicRefs, FALSE, TRUE);
        if (InterfaceRefs[i].cPrivateRefs)
            FIXME("Releasing %ld refs securely not implemented\n", InterfaceRefs[i].cPrivateRefs);

        stub_manager_int_release(stubmgr);
        apartment_release(apt);
    }

    return hr;
}

static const IRemUnknownVtbl RemUnknown_Vtbl =
{
    RemUnknown_QueryInterface,
    RemUnknown_AddRef,
    RemUnknown_Release,
    RemUnknown_RemQueryInterface,
    RemUnknown_RemAddRef,
    RemUnknown_RemRelease
};

/* starts the IRemUnknown listener for the current apartment */
HRESULT start_apartment_remote_unknown(struct apartment *apt)
{
    IRemUnknown *pRemUnknown;
    HRESULT hr = S_OK;

    EnterCriticalSection(&apt->cs);
    if (!apt->remunk_exported)
    {
        /* create the IRemUnknown object */
        hr = RemUnknown_Construct(&pRemUnknown);
        if (hr == S_OK)
        {
            STDOBJREF stdobjref; /* dummy - not used */
            /* register it with the stub manager */
            hr = marshal_object(apt, &stdobjref, &IID_IRemUnknown, (IUnknown *)pRemUnknown,
                    MSHCTX_DIFFERENTMACHINE, NULL, MSHLFLAGS_NORMAL|MSHLFLAGSP_REMUNKNOWN);
            /* release our reference to the object as the stub manager will manage the life cycle for us */
            IRemUnknown_Release(pRemUnknown);
            if (hr == S_OK)
                apt->remunk_exported = TRUE;
        }
    }
    LeaveCriticalSection(&apt->cs);
    return hr;
}
