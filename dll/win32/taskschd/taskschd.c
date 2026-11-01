/*
 * Task Scheduler
 *
 * Copyright 2013 Dmitry Timoshkov
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

#define COBJMACROS

#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "rpcproxy.h"
#include "taskschd.h"
#include "taskschd_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(taskschd);

static const IID * const typeinfo_iids[] =
{
    &IID_IRepetitionPattern,
    &IID_IDailyTrigger,
    &IID_IWeeklyTrigger,
    &IID_IMonthlyTrigger,
    &IID_IMonthlyDOWTrigger,
    &IID_IIdleTrigger,
    &IID_IEventTrigger,
    &IID_ISessionStateChangeTrigger,
    &IID_IRegistrationTrigger,
    &IID_ILogonTrigger,
    &IID_IBootTrigger,
    &IID_ITimeTrigger,
    &IID_ITriggerCollection,
    &IID_IRegistrationInfo,
    &IID_IIdleSettings,
    &IID_ITaskSettings,
    &IID_IPrincipal,
    &IID_IExecAction,
    &IID_IActionCollection,
    &IID_ITaskDefinition,
    &IID_ITaskService,
    &IID_IRegisteredTask,
    &IID_IRunningTaskCollection,
    &IID_IRegisteredTaskCollection,
    &IID_ITaskFolder,
    &IID_ITaskFolderCollection,
};

/* IDispatch support shared by all taskschd objects: every object is a dual
 * interface described by the taskschd type library, so the IDispatch methods
 * simply forward to the cached ITypeInfo of the interface. */

static ITypeLib *typelib;
static ITypeInfo *typeinfos[ARRAY_SIZE(typeinfo_iids)];

static HRESULT load_typelib(void)
{
    WCHAR path[MAX_PATH];
    HMODULE module;
    ITypeLib *lib;
    HRESULT hr;

    if (typelib) return S_OK;

    hr = LoadRegTypeLib(&LIBID_TaskScheduler, 1, 0, LOCALE_NEUTRAL, &lib);
    if (FAILED(hr))
    {
        /* not registered (yet): use the type library resource of this module */
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCWSTR)load_typelib, &module) ||
            !GetModuleFileNameW(module, path, ARRAY_SIZE(path)))
            return hr;
        hr = LoadTypeLib(path, &lib);
    }
    if (FAILED(hr))
    {
        ERR("Failed to load typelib, hr %#lx\n", hr);
        return hr;
    }

    if (InterlockedCompareExchangePointer((void **)&typelib, lib, NULL))
        ITypeLib_Release(lib);
    return S_OK;
}

static HRESULT get_typeinfo(REFIID iid, ITypeInfo **ret)
{
    ITypeInfo *ti;
    UINT i;
    HRESULT hr;

    for (i = 0; i < ARRAY_SIZE(typeinfo_iids); i++)
        if (IsEqualIID(iid, typeinfo_iids[i])) break;
    if (i == ARRAY_SIZE(typeinfo_iids)) return E_NOINTERFACE;

    if (!typeinfos[i])
    {
        hr = load_typelib();
        if (FAILED(hr)) return hr;

        hr = ITypeLib_GetTypeInfoOfGuid(typelib, iid, &ti);
        if (FAILED(hr))
        {
            ERR("Failed to get typeinfo for %s, hr %#lx\n", debugstr_guid(iid), hr);
            return hr;
        }
        if (InterlockedCompareExchangePointer((void **)&typeinfos[i], ti, NULL))
            ITypeInfo_Release(ti);
    }

    *ret = typeinfos[i];
    ITypeInfo_AddRef(*ret);
    return S_OK;
}

HRESULT taskschd_GetTypeInfoCount(UINT *count)
{
    TRACE("%p\n", count);
    if (!count) return E_POINTER;
    *count = 1;
    return S_OK;
}

HRESULT taskschd_GetTypeInfo(REFIID iid, UINT index, LCID lcid, ITypeInfo **info)
{
    TRACE("%s,%u,%#lx,%p\n", debugstr_guid(iid), index, lcid, info);
    if (!info) return E_POINTER;
    *info = NULL;
    if (index != 0) return DISP_E_BADINDEX;
    return get_typeinfo(iid, info);
}

HRESULT taskschd_GetIDsOfNames(REFIID iid, REFIID riid, LPOLESTR *names, UINT count, LCID lcid, DISPID *dispid)
{
    ITypeInfo *ti;
    HRESULT hr;

    TRACE("%s,%s,%p,%u,%#lx,%p\n", debugstr_guid(iid), debugstr_guid(riid), names, count, lcid, dispid);

    if (!IsEqualGUID(riid, &GUID_NULL)) return DISP_E_UNKNOWNINTERFACE;
    hr = get_typeinfo(iid, &ti);
    if (FAILED(hr)) return hr;
    hr = DispGetIDsOfNames(ti, names, count, dispid);
    ITypeInfo_Release(ti);
    return hr;
}

HRESULT taskschd_Invoke(REFIID iid, void *obj, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                        DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    ITypeInfo *ti;
    HRESULT hr;

    TRACE("%s,%p,%ld,%s,%#lx,%#x,%p,%p,%p,%p\n", debugstr_guid(iid), obj, dispid, debugstr_guid(riid),
          lcid, flags, params, result, excepinfo, argerr);

    if (!IsEqualGUID(riid, &GUID_NULL)) return DISP_E_UNKNOWNINTERFACE;
    hr = get_typeinfo(iid, &ti);
    if (FAILED(hr)) return hr;
    hr = ITypeInfo_Invoke(ti, obj, dispid, flags, params, result, excepinfo, argerr);
    ITypeInfo_Release(ti);
    return hr;
}

/* A snapshot IEnumVARIANT over a list of objects, used by the collections for
 * the _NewEnum property (For Each in VBScript, foreach in PowerShell). */
typedef struct
{
    IEnumVARIANT IEnumVARIANT_iface;
    LONG ref;
    ULONG pos, count;
    IDispatch **items;
} SnapshotEnum;

static inline SnapshotEnum *impl_from_snapshot(IEnumVARIANT *iface)
{
    return CONTAINING_RECORD(iface, SnapshotEnum, IEnumVARIANT_iface);
}

static HRESULT WINAPI snapenum_QueryInterface(IEnumVARIANT *iface, REFIID riid, void **obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    if (IsEqualGUID(riid, &IID_IEnumVARIANT) || IsEqualGUID(riid, &IID_IUnknown))
    {
        IEnumVARIANT_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI snapenum_AddRef(IEnumVARIANT *iface)
{
    return InterlockedIncrement(&impl_from_snapshot(iface)->ref);
}

static ULONG WINAPI snapenum_Release(IEnumVARIANT *iface)
{
    SnapshotEnum *This = impl_from_snapshot(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
    {
        ULONG i;

        for (i = 0; i < This->count; i++)
            IDispatch_Release(This->items[i]);
        free(This->items);
        free(This);
    }
    return ref;
}

static HRESULT WINAPI snapenum_Next(IEnumVARIANT *iface, ULONG celt, VARIANT *var, ULONG *fetched)
{
    SnapshotEnum *This = impl_from_snapshot(iface);
    ULONG i;

    if (!var && celt) return E_POINTER;

    for (i = 0; i < celt && This->pos < This->count; i++)
    {
        V_VT(&var[i]) = VT_DISPATCH;
        V_DISPATCH(&var[i]) = This->items[This->pos++];
        IDispatch_AddRef(V_DISPATCH(&var[i]));
    }
    if (fetched) *fetched = i;
    return i == celt ? S_OK : S_FALSE;
}

static HRESULT WINAPI snapenum_Skip(IEnumVARIANT *iface, ULONG celt)
{
    SnapshotEnum *This = impl_from_snapshot(iface);

    if (celt > This->count - This->pos)
    {
        This->pos = This->count;
        return S_FALSE;
    }
    This->pos += celt;
    return S_OK;
}

static HRESULT WINAPI snapenum_Reset(IEnumVARIANT *iface)
{
    impl_from_snapshot(iface)->pos = 0;
    return S_OK;
}

static HRESULT taskschd_create_enum_ref(IDispatch **items, ULONG count, BOOL addref, IUnknown **obj);

static HRESULT WINAPI snapenum_Clone(IEnumVARIANT *iface, IEnumVARIANT **penum)
{
    SnapshotEnum *This = impl_from_snapshot(iface);
    IDispatch **items;
    HRESULT hr;

    if (!penum) return E_POINTER;

    items = calloc(This->count ? This->count : 1, sizeof(*items));
    if (!items) return E_OUTOFMEMORY;
    memcpy(items, This->items, This->count * sizeof(*items));

    hr = taskschd_create_enum_ref(items, This->count, TRUE, (IUnknown **)penum);
    if (SUCCEEDED(hr))
        impl_from_snapshot(*penum)->pos = This->pos;
    return hr;
}

static const IEnumVARIANTVtbl snapenum_vtbl =
{
    snapenum_QueryInterface,
    snapenum_AddRef,
    snapenum_Release,
    snapenum_Next,
    snapenum_Skip,
    snapenum_Reset,
    snapenum_Clone
};

static HRESULT taskschd_create_enum_ref(IDispatch **items, ULONG count, BOOL addref, IUnknown **obj)
{
    SnapshotEnum *This;
    ULONG i;

    This = calloc(1, sizeof(*This));
    if (!This)
    {
        if (!addref)
        {
            for (i = 0; i < count; i++) IDispatch_Release(items[i]);
            free(items);
        }
        else
            free(items);
        return E_OUTOFMEMORY;
    }

    This->IEnumVARIANT_iface.lpVtbl = &snapenum_vtbl;
    This->ref = 1;
    This->items = items;
    This->count = count;
    if (addref)
        for (i = 0; i < count; i++) IDispatch_AddRef(items[i]);
    *obj = (IUnknown *)&This->IEnumVARIANT_iface;
    return S_OK;
}

/* items is a malloc'ed array of count referenced objects, the enumerator takes it over */
HRESULT taskschd_create_enum(IDispatch **items, ULONG count, IUnknown **obj)
{
    return taskschd_create_enum_ref(items, count, FALSE, obj);
}

typedef struct
{
    IClassFactory IClassFactory_iface;
    HRESULT (*constructor)(void **);
} TaskScheduler_factory;

static inline TaskScheduler_factory *impl_from_IClassFactory(IClassFactory *iface)
{
    return CONTAINING_RECORD(iface, TaskScheduler_factory, IClassFactory_iface);
}

static HRESULT WINAPI factory_QueryInterface(IClassFactory *iface, REFIID riid, LPVOID *obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", iface, debugstr_guid(riid), obj);

    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IClassFactory))
    {
        IClassFactory_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    *obj = NULL;
    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    return E_NOINTERFACE;
}

static ULONG WINAPI factory_AddRef(IClassFactory *iface)
{
    return 2;
}

static ULONG WINAPI factory_Release(IClassFactory *iface)
{
    return 1;
}

static HRESULT WINAPI factory_CreateInstance(IClassFactory *iface, IUnknown *outer, REFIID riid, void **obj)
{
    TaskScheduler_factory *factory = impl_from_IClassFactory(iface);
    IUnknown *unknown;
    HRESULT hr;

    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", outer, debugstr_guid(riid), obj);

    *obj = NULL;
    if (outer) return CLASS_E_NOAGGREGATION;

    hr = factory->constructor((void **)&unknown);
    if (hr != S_OK) return hr;

    hr = IUnknown_QueryInterface(unknown, riid, obj);
    IUnknown_Release(unknown);

    return hr;
}

static HRESULT WINAPI factory_LockServer(IClassFactory *iface, BOOL lock)
{
    FIXME("%p,%d: stub\n", iface, lock);
    return S_OK;
}

static const struct IClassFactoryVtbl factory_vtbl =
{
    factory_QueryInterface,
    factory_AddRef,
    factory_Release,
    factory_CreateInstance,
    factory_LockServer
};

static TaskScheduler_factory TaskScheduler_cf = { { &factory_vtbl }, TaskService_create };

/***********************************************************************
 *      DllGetClassObject
 */
HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *obj)
{
    IClassFactory *factory = NULL;

    if (!rclsid || !riid || !obj) return E_INVALIDARG;

    TRACE("%s,%s,%p\n", debugstr_guid(rclsid), debugstr_guid(riid), obj);

    *obj = NULL;

    if (IsEqualGUID(rclsid, &CLSID_TaskScheduler))
    {
        factory = &TaskScheduler_cf.IClassFactory_iface;
    }

    if (factory) return IClassFactory_QueryInterface(factory, riid, obj);

    FIXME("class %s/%s is not implemented\n", debugstr_guid(rclsid), debugstr_guid(riid));
    return CLASS_E_CLASSNOTAVAILABLE;
}
