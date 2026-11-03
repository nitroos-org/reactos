/*
 * PROJECT:     ReactOS AppXDeploymentClient
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The Windows.Management.Deployment.PackageManager WinRT class, for a system without packages
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The Office Deployment Tool (setup.exe of Microsoft 365 Apps) activates PackageManager and calls
 * FindPackages(name, publisher) to look for a Store copy of Office before it installs. Without the
 * class the C++/WinRT activation throws and setup ends with 0xC0000409 before it writes a log.
 *
 * No packages are installed on this system, so every query returns what Windows 10 returns for a
 * package that is not installed (measured on Windows 10 22H2): an empty collection, or S_OK and a
 * NULL package for a full-name lookup. Deployment operations are not implemented.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "objbase.h"
#include "initguid.h"
#include "inspectable.h"
#include "activation.h"
#include "winstring.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(appx);

static const WCHAR class_name[] = L"Windows.Management.Deployment.PackageManager";
/* What Windows answers for the collection that a FindPackages* call returns */
static const WCHAR packages_class_name[] = L"Windows.Foundation.Collections.IVector`1<Windows.ApplicationModel.Package>";
static const WCHAR users_class_name[] = L"Windows.Foundation.Collections.IVector`1<Windows.Management.Deployment.PackageUserInformation>";

DEFINE_GUID(IID_IPackageManager, 0x9a7d4b65, 0x5e8f, 0x4fc7, 0xa2, 0xe5, 0x7f, 0x69, 0x25, 0xcb, 0x8b, 0x53);
DEFINE_GUID(IID_IPackageManager2, 0xf7aad08d, 0x0840, 0x46f2, 0xb5, 0xd8, 0xca, 0xd4, 0x76, 0x93, 0xa0, 0x95);
DEFINE_GUID(IID_IAsyncInfo_, 0x00000036, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);
DEFINE_GUID(IID_IPackageManager3, 0xdaad9948, 0x36f1, 0x41a7, 0x91, 0x88, 0xbc, 0x26, 0x3e, 0x0d, 0xcb, 0x72);
DEFINE_GUID(IID_IPackageManager4, 0x3c719963, 0xbab6, 0x46bf, 0x8f, 0xf7, 0xda, 0x47, 0x19, 0x23, 0x0a, 0xe6);
DEFINE_GUID(IID_IPackageManager5, 0x711f3117, 0x1afd, 0x4313, 0x97, 0x8c, 0x9b, 0xb6, 0xe1, 0xb8, 0x64, 0xa7);
DEFINE_GUID(IID_IPackageManager6, 0x0847e909, 0x53cd, 0x4e4f, 0x83, 0x2e, 0x57, 0xd1, 0x80, 0xf6, 0xe4, 0x47);
DEFINE_GUID(IID_IPackageManager7, 0xf28654f4, 0x2ba7, 0x4b80, 0x88, 0xd6, 0xbe, 0x15, 0xf9, 0xa2, 0x3f, 0xba);
DEFINE_GUID(IID_IPackageManager8, 0xb8575330, 0x1298, 0x4ee2, 0x80, 0xee, 0x7f, 0x65, 0x9c, 0x5d, 0x27, 0x82);
DEFINE_GUID(IID_IPackageManager9, 0x1aa79035, 0xcc71, 0x4b2e, 0x80, 0xa6, 0xc7, 0x04, 0x1d, 0x85, 0x79, 0xa7);
/* Parameterized interface IIDs (the WinRT pinterface hash of the instantiation) */
DEFINE_GUID(IID_IIterable_Package, 0x69ad6aa7, 0x0c49, 0x5f27, 0xa5, 0xeb, 0xef, 0x4d, 0x59, 0x46, 0x7b, 0x6d);
DEFINE_GUID(IID_IIterator_Package, 0x0217f069, 0x025c, 0x5ee6, 0xa8, 0x7f, 0xe7, 0x82, 0xe3, 0xb6, 0x23, 0xae);
DEFINE_GUID(IID_IIterable_PackageUserInformation, 0x341348b9, 0x52c8, 0x5b57, 0x9e, 0x91, 0xf1, 0x9f, 0x2a, 0x05, 0xb1, 0x88);
DEFINE_GUID(IID_IIterator_PackageUserInformation, 0x75660566, 0xae43, 0x5858, 0xad, 0xa6, 0xd5, 0x7d, 0xda, 0xe9, 0x02, 0x77);

/* Every object here is an IInspectable with a different tail of methods; one header serves them all */
typedef struct object object;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(object *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(object *This);
    ULONG (STDMETHODCALLTYPE *Release)(object *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(object *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(object *This, HSTRING *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(object *This, TrustLevel *level);
} object_vtbl;

struct object
{
    const object_vtbl *vtbl;
};

/* ---- empty collections: IIterable<T> and its IIterator<T> ---- */

typedef struct
{
    object iface;
    LONG ref;
    const GUID *iid;           /* IIterable<T> or IIterator<T> */
    const WCHAR *name;
    BOOL users;                /* T is PackageUserInformation, else Package */
} collection;

static HRESULT collection_create(BOOL users, BOOL iterator, void **out);

static collection *impl_from_object(object *iface)
{
    return CONTAINING_RECORD(iface, collection, iface);
}

static HRESULT STDMETHODCALLTYPE collection_QueryInterface(object *iface, REFIID iid, void **out)
{
    collection *This = impl_from_object(iface);

    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, This->iid))
    {
        *out = iface;
        InterlockedIncrement(&This->ref);
        return S_OK;
    }
    TRACE("%s not supported\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE collection_AddRef(object *iface)
{
    return InterlockedIncrement(&impl_from_object(iface)->ref);
}

static ULONG STDMETHODCALLTYPE collection_Release(object *iface)
{
    collection *This = impl_from_object(iface);
    ULONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
        HeapFree(GetProcessHeap(), 0, This);
    return ref;
}

static HRESULT STDMETHODCALLTYPE collection_GetIids(object *iface, ULONG *count, IID **iids)
{
    IID *list;

    if (!count || !iids)
        return E_POINTER;
    list = CoTaskMemAlloc(sizeof(IID));
    if (!list)
        return E_OUTOFMEMORY;
    list[0] = *impl_from_object(iface)->iid;
    *count = 1;
    *iids = list;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE collection_GetRuntimeClassName(object *iface, HSTRING *name)
{
    const WCHAR *str = impl_from_object(iface)->name;

    if (!name)
        return E_POINTER;
    return WindowsCreateString(str, lstrlenW(str), name);
}

static HRESULT STDMETHODCALLTYPE collection_GetTrustLevel(object *iface, TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

/* IIterable<T>::First */
static HRESULT STDMETHODCALLTYPE iterable_First(object *iface, void **iterator)
{
    if (!iterator)
        return E_POINTER;
    return collection_create(impl_from_object(iface)->users, TRUE, iterator);
}

/* IIterator<T>: an iterator of an empty collection is past its end from the start */
static HRESULT STDMETHODCALLTYPE iterator_get_Current(object *iface, void **current)
{
    if (!current)
        return E_POINTER;
    *current = NULL;
    return E_BOUNDS;
}

static HRESULT STDMETHODCALLTYPE iterator_get_HasCurrent(object *iface, BOOLEAN *has)
{
    if (!has)
        return E_POINTER;
    *has = FALSE;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE iterator_MoveNext(object *iface, BOOLEAN *has)
{
    if (!has)
        return E_POINTER;
    *has = FALSE;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE iterator_GetMany(object *iface, UINT32 capacity, void **items, UINT32 *count)
{
    if (!count)
        return E_POINTER;
    *count = 0;
    return S_OK;
}

static const struct
{
    object_vtbl base;
    void *methods[1];
} iterable_vtbl =
{
    {
        collection_QueryInterface,
        collection_AddRef,
        collection_Release,
        collection_GetIids,
        collection_GetRuntimeClassName,
        collection_GetTrustLevel,
    },
    { (void *)iterable_First },
};

static const struct
{
    object_vtbl base;
    void *methods[4];
} iterator_vtbl =
{
    {
        collection_QueryInterface,
        collection_AddRef,
        collection_Release,
        collection_GetIids,
        collection_GetRuntimeClassName,
        collection_GetTrustLevel,
    },
    { (void *)iterator_get_Current, (void *)iterator_get_HasCurrent, (void *)iterator_MoveNext, (void *)iterator_GetMany },
};

static HRESULT collection_create(BOOL users, BOOL iterator, void **out)
{
    collection *This = HeapAlloc(GetProcessHeap(), 0, sizeof(*This));

    *out = NULL;
    if (!This)
        return E_OUTOFMEMORY;
    This->iface.vtbl = iterator ? &iterator_vtbl.base : &iterable_vtbl.base;
    This->ref = 1;
    This->users = users;
    if (users)
        This->iid = iterator ? &IID_IIterator_PackageUserInformation : &IID_IIterable_PackageUserInformation;
    else
        This->iid = iterator ? &IID_IIterator_Package : &IID_IIterable_Package;
    This->name = users ? users_class_name : packages_class_name;
    *out = &This->iface;
    return S_OK;
}

/* ---- PackageManager: IPackageManager and IPackageManager2 ---- */

typedef struct
{
    object iface[7];          /* IPackageManager3 .. IPackageManager9 */
} extra_interfaces;

typedef struct
{
    object IPackageManager_iface;
    object IPackageManager2_iface;
    extra_interfaces extra;
    LONG ref;
} package_manager;

static package_manager *manager_from_pm(object *iface)
{
    return CONTAINING_RECORD(iface, package_manager, IPackageManager_iface);
}

static package_manager *manager_from_pm2(object *iface)
{
    return CONTAINING_RECORD(iface, package_manager, IPackageManager2_iface);
}

static HRESULT manager_query_interface(package_manager *This, REFIID iid, void **out)
{
    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IPackageManager))
        *out = &This->IPackageManager_iface;
    else if (IsEqualGUID(iid, &IID_IPackageManager2))
        *out = &This->IPackageManager2_iface;
    else if (IsEqualGUID(iid, &IID_IPackageManager3))
        *out = &This->extra.iface[0];
    else if (IsEqualGUID(iid, &IID_IPackageManager4))
        *out = &This->extra.iface[1];
    else if (IsEqualGUID(iid, &IID_IPackageManager5))
        *out = &This->extra.iface[2];
    else if (IsEqualGUID(iid, &IID_IPackageManager6))
        *out = &This->extra.iface[3];
    else if (IsEqualGUID(iid, &IID_IPackageManager7))
        *out = &This->extra.iface[4];
    else if (IsEqualGUID(iid, &IID_IPackageManager8))
        *out = &This->extra.iface[5];
    else if (IsEqualGUID(iid, &IID_IPackageManager9))
        *out = &This->extra.iface[6];
    else
    {
        FIXME("%s not implemented\n", debugstr_guid(iid));
        *out = NULL;
        return E_NOINTERFACE;
    }
    InterlockedIncrement(&This->ref);
    return S_OK;
}

static ULONG manager_release(package_manager *This)
{
    ULONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
        HeapFree(GetProcessHeap(), 0, This);
    return ref;
}

static HRESULT manager_get_iids(ULONG *count, IID **iids)
{
    IID *list;

    if (!count || !iids)
        return E_POINTER;
    list = CoTaskMemAlloc(9 * sizeof(IID));
    if (!list)
        return E_OUTOFMEMORY;
    list[0] = IID_IPackageManager;
    list[1] = IID_IPackageManager2;
    list[2] = IID_IPackageManager3;
    list[3] = IID_IPackageManager4;
    list[4] = IID_IPackageManager5;
    list[5] = IID_IPackageManager6;
    list[6] = IID_IPackageManager7;
    list[7] = IID_IPackageManager8;
    list[8] = IID_IPackageManager9;
    *count = 9;
    *iids = list;
    return S_OK;
}

static HRESULT manager_get_class_name(HSTRING *name)
{
    if (!name)
        return E_POINTER;
    return WindowsCreateString(class_name, ARRAYSIZE(class_name) - 1, name);
}

/* Windows reports PartialTrust for this class */
static HRESULT manager_get_trust_level(TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = PartialTrust;
    return S_OK;
}

static BOOL is_empty(HSTRING str)
{
    return WindowsGetStringLen(str) == 0;
}

/* The answer for any package query: nothing is installed */
static HRESULT no_packages(void **packages)
{
    if (!packages)
        return E_POINTER;
    return collection_create(FALSE, FALSE, packages);
}

static HRESULT no_package(void **package)
{
    if (!package)
        return E_POINTER;
    *package = NULL;
    return S_OK;
}

static HRESULT not_implemented(const char *method, void **operation)
{
    FIXME("%s: deployment is not implemented\n", method);
    if (operation)
        *operation = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm_QueryInterface(object *iface, REFIID iid, void **out)
{
    return manager_query_interface(manager_from_pm(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE pm_AddRef(object *iface)
{
    return InterlockedIncrement(&manager_from_pm(iface)->ref);
}

static ULONG STDMETHODCALLTYPE pm_Release(object *iface)
{
    return manager_release(manager_from_pm(iface));
}

static HRESULT STDMETHODCALLTYPE pm_GetIids(object *iface, ULONG *count, IID **iids)
{
    return manager_get_iids(count, iids);
}

static HRESULT STDMETHODCALLTYPE pm_GetRuntimeClassName(object *iface, HSTRING *name)
{
    return manager_get_class_name(name);
}

static HRESULT STDMETHODCALLTYPE pm_GetTrustLevel(object *iface, TrustLevel *level)
{
    return manager_get_trust_level(level);
}

static HRESULT STDMETHODCALLTYPE pm_AddPackageAsync(object *iface, void *uri, void *dependencies, UINT32 options, void **operation)
{
    return not_implemented("AddPackageAsync", operation);
}

static HRESULT STDMETHODCALLTYPE pm_UpdatePackageAsync(object *iface, void *uri, void *dependencies, UINT32 options, void **operation)
{
    return not_implemented("UpdatePackageAsync", operation);
}

static HRESULT STDMETHODCALLTYPE pm_RemovePackageAsync(object *iface, HSTRING name, void **operation)
{
    return not_implemented("RemovePackageAsync", operation);
}

static HRESULT STDMETHODCALLTYPE pm_StagePackageAsync(object *iface, void *uri, void *dependencies, void **operation)
{
    return not_implemented("StagePackageAsync", operation);
}

static HRESULT STDMETHODCALLTYPE pm_RegisterPackageAsync(object *iface, void *uri, void *dependencies, UINT32 options, void **operation)
{
    return not_implemented("RegisterPackageAsync", operation);
}

static HRESULT STDMETHODCALLTYPE pm_FindPackages(object *iface, void **packages)
{
    TRACE("(%p)\n", packages);
    return no_packages(packages);
}

/* An empty security identifier means the current user */
static HRESULT STDMETHODCALLTYPE pm_FindPackagesByUserSecurityId(object *iface, HSTRING sid, void **packages)
{
    TRACE("(%s, %p)\n", debugstr_hstring(sid), packages);
    return no_packages(packages);
}

static HRESULT STDMETHODCALLTYPE pm_FindPackagesByNamePublisher(object *iface, HSTRING name, HSTRING publisher, void **packages)
{
    TRACE("(%s, %s, %p)\n", debugstr_hstring(name), debugstr_hstring(publisher), packages);
    if (!packages)
        return E_POINTER;
    if (is_empty(name) || is_empty(publisher))
        return E_INVALIDARG;
    return no_packages(packages);
}

static HRESULT STDMETHODCALLTYPE pm_FindPackagesByUserSecurityIdNamePublisher(object *iface, HSTRING sid, HSTRING name, HSTRING publisher, void **packages)
{
    TRACE("(%s, %s, %s, %p)\n", debugstr_hstring(sid), debugstr_hstring(name), debugstr_hstring(publisher), packages);
    if (!packages)
        return E_POINTER;
    if (is_empty(name) || is_empty(publisher))
        return E_INVALIDARG;
    return no_packages(packages);
}

static HRESULT STDMETHODCALLTYPE pm_FindUsers(object *iface, HSTRING name, void **users)
{
    TRACE("(%s, %p)\n", debugstr_hstring(name), users);
    if (!users)
        return E_POINTER;
    if (is_empty(name))
        return E_INVALIDARG;
    return collection_create(TRUE, FALSE, users);
}

static HRESULT STDMETHODCALLTYPE pm_SetPackageState(object *iface, HSTRING name, UINT32 state)
{
    return not_implemented("SetPackageState", NULL);
}

static HRESULT STDMETHODCALLTYPE pm_FindPackageByPackageFullName(object *iface, HSTRING name, void **package)
{
    TRACE("(%s, %p)\n", debugstr_hstring(name), package);
    if (!package)
        return E_POINTER;
    if (is_empty(name))
        return E_INVALIDARG;
    return no_package(package);
}

static HRESULT STDMETHODCALLTYPE pm_CleanupPackageForUserAsync(object *iface, HSTRING name, HSTRING sid, void **operation)
{
    return not_implemented("CleanupPackageForUserAsync", operation);
}

static HRESULT STDMETHODCALLTYPE pm_FindPackagesByPackageFamilyName(object *iface, HSTRING family, void **packages)
{
    TRACE("(%s, %p)\n", debugstr_hstring(family), packages);
    if (!packages)
        return E_POINTER;
    if (is_empty(family))
        return E_INVALIDARG;
    return no_packages(packages);
}

static HRESULT STDMETHODCALLTYPE pm_FindPackagesByUserSecurityIdPackageFamilyName(object *iface, HSTRING sid, HSTRING family, void **packages)
{
    TRACE("(%s, %s, %p)\n", debugstr_hstring(sid), debugstr_hstring(family), packages);
    if (!packages)
        return E_POINTER;
    if (is_empty(family))
        return E_INVALIDARG;
    return no_packages(packages);
}

static HRESULT STDMETHODCALLTYPE pm_FindPackageByUserSecurityIdPackageFullName(object *iface, HSTRING sid, HSTRING name, void **package)
{
    TRACE("(%s, %s, %p)\n", debugstr_hstring(sid), debugstr_hstring(name), package);
    if (!package)
        return E_POINTER;
    if (is_empty(name))
        return E_INVALIDARG;
    return no_package(package);
}

static const struct
{
    object_vtbl base;
    void *methods[16];
} pm_vtbl =
{
    {
        pm_QueryInterface,
        pm_AddRef,
        pm_Release,
        pm_GetIids,
        pm_GetRuntimeClassName,
        pm_GetTrustLevel,
    },
    {
        (void *)pm_AddPackageAsync,
        (void *)pm_UpdatePackageAsync,
        (void *)pm_RemovePackageAsync,
        (void *)pm_StagePackageAsync,
        (void *)pm_RegisterPackageAsync,
        (void *)pm_FindPackages,
        (void *)pm_FindPackagesByUserSecurityId,
        (void *)pm_FindPackagesByNamePublisher,
        (void *)pm_FindPackagesByUserSecurityIdNamePublisher,
        (void *)pm_FindUsers,
        (void *)pm_SetPackageState,
        (void *)pm_FindPackageByPackageFullName,
        (void *)pm_CleanupPackageForUserAsync,
        (void *)pm_FindPackagesByPackageFamilyName,
        (void *)pm_FindPackagesByUserSecurityIdPackageFamilyName,
        (void *)pm_FindPackageByUserSecurityIdPackageFullName,
    },
};

/* IPackageManager2 */
static HRESULT STDMETHODCALLTYPE pm2_QueryInterface(object *iface, REFIID iid, void **out)
{
    return manager_query_interface(manager_from_pm2(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE pm2_AddRef(object *iface)
{
    return InterlockedIncrement(&manager_from_pm2(iface)->ref);
}

static ULONG STDMETHODCALLTYPE pm2_Release(object *iface)
{
    return manager_release(manager_from_pm2(iface));
}

static HRESULT STDMETHODCALLTYPE pm2_GetIids(object *iface, ULONG *count, IID **iids)
{
    return manager_get_iids(count, iids);
}

static HRESULT STDMETHODCALLTYPE pm2_GetRuntimeClassName(object *iface, HSTRING *name)
{
    return manager_get_class_name(name);
}

static HRESULT STDMETHODCALLTYPE pm2_GetTrustLevel(object *iface, TrustLevel *level)
{
    return manager_get_trust_level(level);
}

static HRESULT STDMETHODCALLTYPE pm2_RemovePackageWithOptionsAsync(object *iface, HSTRING name, UINT32 options, void **operation)
{
    return not_implemented("RemovePackageWithOptionsAsync", operation);
}

static HRESULT STDMETHODCALLTYPE pm2_StagePackageWithOptionsAsync(object *iface, void *uri, void *dependencies, UINT32 options, void **operation)
{
    return not_implemented("StagePackageWithOptionsAsync", operation);
}

static HRESULT STDMETHODCALLTYPE pm2_RegisterPackageByFullNameAsync(object *iface, HSTRING name, void *dependencies, UINT32 options, void **operation)
{
    return not_implemented("RegisterPackageByFullNameAsync", operation);
}

static HRESULT STDMETHODCALLTYPE pm2_FindPackagesWithPackageTypes(object *iface, UINT32 types, void **packages)
{
    TRACE("(%#x, %p)\n", types, packages);
    return no_packages(packages);
}

static HRESULT STDMETHODCALLTYPE pm2_FindPackagesByUserSecurityIdWithPackageTypes(object *iface, HSTRING sid, UINT32 types, void **packages)
{
    TRACE("(%s, %#x, %p)\n", debugstr_hstring(sid), types, packages);
    return no_packages(packages);
}

static HRESULT STDMETHODCALLTYPE pm2_FindPackagesByNamePublisherWithPackageTypes(object *iface, HSTRING name, HSTRING publisher, UINT32 types, void **packages)
{
    return pm_FindPackagesByNamePublisher(iface, name, publisher, packages);
}

static HRESULT STDMETHODCALLTYPE pm2_FindPackagesByUserSecurityIdNamePublisherWithPackageTypes(object *iface, HSTRING sid, HSTRING name, HSTRING publisher, UINT32 types, void **packages)
{
    return pm_FindPackagesByUserSecurityIdNamePublisher(iface, sid, name, publisher, packages);
}

static HRESULT STDMETHODCALLTYPE pm2_FindPackagesByPackageFamilyNameWithPackageTypes(object *iface, HSTRING family, UINT32 types, void **packages)
{
    return pm_FindPackagesByPackageFamilyName(iface, family, packages);
}

static HRESULT STDMETHODCALLTYPE pm2_FindPackagesByUserSecurityIdPackageFamilyNameWithPackageTypes(object *iface, HSTRING sid, HSTRING family, UINT32 types, void **packages)
{
    return pm_FindPackagesByUserSecurityIdPackageFamilyName(iface, sid, family, packages);
}

static HRESULT STDMETHODCALLTYPE pm2_StageUserDataAsync(object *iface, HSTRING name, void **operation)
{
    return not_implemented("StageUserDataAsync", operation);
}

static const struct
{
    object_vtbl base;
    void *methods[10];
} pm2_vtbl =
{
    {
        pm2_QueryInterface,
        pm2_AddRef,
        pm2_Release,
        pm2_GetIids,
        pm2_GetRuntimeClassName,
        pm2_GetTrustLevel,
    },
    {
        (void *)pm2_RemovePackageWithOptionsAsync,
        (void *)pm2_StagePackageWithOptionsAsync,
        (void *)pm2_RegisterPackageByFullNameAsync,
        (void *)pm2_FindPackagesWithPackageTypes,
        (void *)pm2_FindPackagesByUserSecurityIdWithPackageTypes,
        (void *)pm2_FindPackagesByNamePublisherWithPackageTypes,
        (void *)pm2_FindPackagesByUserSecurityIdNamePublisherWithPackageTypes,
        (void *)pm2_FindPackagesByPackageFamilyNameWithPackageTypes,
        (void *)pm2_FindPackagesByUserSecurityIdPackageFamilyNameWithPackageTypes,
        (void *)pm2_StageUserDataAsync,
    },
};


/* ---- IPackageManager3 .. IPackageManager9: the interfaces of Windows 10 22H2 (vtables and argument counts
 * from Windows.Management.winmd of that system). Queries are not answered with data, deployment is not
 * implemented. The Click-To-Run service queries these interfaces without checking the result, so a missing
 * interface is a NULL call. ---- */


/* ---- an asynchronous operation that has completed with an error: IAsyncOperationWithProgress<DeploymentResult,
 * DeploymentProgress> and IAsyncInfo. Its Completed handler is called when it is set, as for any completed
 * operation. ---- */

#define ASYNC_STATUS_ERROR 3
/* ERROR_INSTALL_PACKAGE_NOT_FOUND */
// TODO(oracle): exact HRESULT for an unknown family (not measured on Windows)
#define DEPLOY_ERROR_UNKNOWN_PACKAGE HRESULT_FROM_WIN32(15601)

typedef struct
{
    const void *const *vtbl;
} handler_object;

typedef HRESULT (STDMETHODCALLTYPE *handler_invoke)(handler_object *This, object *operation, int status);

typedef struct
{
    object operation_iface;   /* IAsyncOperationWithProgress<...> */
    object info_iface;        /* IAsyncInfo */
    LONG ref;
    handler_object *completed;
} async_operation;

static async_operation *async_from_op(object *iface)
{
    return CONTAINING_RECORD(iface, async_operation, operation_iface);
}

static async_operation *async_from_info(object *iface)
{
    return CONTAINING_RECORD(iface, async_operation, info_iface);
}

static HRESULT async_query_interface(async_operation *This, REFIID iid, void **out)
{
    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) || IsEqualGUID(iid, &IID_IAgileObject))
        *out = &This->operation_iface;
    else if (IsEqualGUID(iid, &IID_IAsyncInfo_))
        *out = &This->info_iface;
    else
    {
        *out = NULL;
        return E_NOINTERFACE;
    }
    InterlockedIncrement(&This->ref);
    return S_OK;
}

static ULONG async_release(async_operation *This)
{
    ULONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
    {
        if (This->completed)
            ((ULONG (STDMETHODCALLTYPE *)(handler_object *))This->completed->vtbl[2])(This->completed);
        HeapFree(GetProcessHeap(), 0, This);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE aop_QueryInterface(object *iface, REFIID iid, void **out)
{
    return async_query_interface(async_from_op(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE aop_AddRef(object *iface)
{
    return InterlockedIncrement(&async_from_op(iface)->ref);
}

static ULONG STDMETHODCALLTYPE aop_Release(object *iface)
{
    return async_release(async_from_op(iface));
}

static HRESULT STDMETHODCALLTYPE async_GetIids(object *iface, ULONG *count, IID **iids)
{
    IID *list;

    if (!count || !iids)
        return E_POINTER;
    list = CoTaskMemAlloc(sizeof(IID));
    if (!list)
        return E_OUTOFMEMORY;
    list[0] = IID_IAsyncInfo_;
    *count = 1;
    *iids = list;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE async_GetRuntimeClassName(object *iface, HSTRING *name)
{
    static const WCHAR str[] = L"Windows.Foundation.IAsyncOperationWithProgress`2<Windows.Management.Deployment.DeploymentResult,Windows.Management.Deployment.DeploymentProgress>";

    if (!name)
        return E_POINTER;
    return WindowsCreateString(str, ARRAYSIZE(str) - 1, name);
}

static HRESULT STDMETHODCALLTYPE async_GetTrustLevel(object *iface, TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE aop_put_Progress(object *iface, void *handler)
{
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE aop_get_Progress(object *iface, void **handler)
{
    if (!handler)
        return E_POINTER;
    *handler = NULL;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE aop_put_Completed(object *iface, handler_object *handler)
{
    async_operation *This = async_from_op(iface);

    if (This->completed)
        return ((HRESULT)0x80000018L);
    if (!handler)
        return S_OK;
    ((ULONG (STDMETHODCALLTYPE *)(handler_object *))handler->vtbl[1])(handler);
    This->completed = handler;
    ((handler_invoke)handler->vtbl[3])(handler, iface, ASYNC_STATUS_ERROR);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE aop_get_Completed(object *iface, handler_object **handler)
{
    async_operation *This = async_from_op(iface);

    if (!handler)
        return E_POINTER;
    *handler = This->completed;
    if (*handler)
        ((ULONG (STDMETHODCALLTYPE *)(handler_object *))(*handler)->vtbl[1])(*handler);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE aop_GetResults(object *iface, void **result)
{
    if (!result)
        return E_POINTER;
    *result = NULL;
    return DEPLOY_ERROR_UNKNOWN_PACKAGE;
}

static HRESULT STDMETHODCALLTYPE ainfo_QueryInterface(object *iface, REFIID iid, void **out)
{
    return async_query_interface(async_from_info(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE ainfo_AddRef(object *iface)
{
    return InterlockedIncrement(&async_from_info(iface)->ref);
}

static ULONG STDMETHODCALLTYPE ainfo_Release(object *iface)
{
    return async_release(async_from_info(iface));
}

static HRESULT STDMETHODCALLTYPE ainfo_get_Id(object *iface, UINT32 *id)
{
    if (!id)
        return E_POINTER;
    *id = 1;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ainfo_get_Status(object *iface, int *status)
{
    if (!status)
        return E_POINTER;
    *status = ASYNC_STATUS_ERROR;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ainfo_get_ErrorCode(object *iface, HRESULT *code)
{
    if (!code)
        return E_POINTER;
    *code = DEPLOY_ERROR_UNKNOWN_PACKAGE;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ainfo_Cancel(object *iface)
{
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ainfo_Close(object *iface)
{
    return S_OK;
}

static const struct
{
    object_vtbl base;
    void *methods[5];
} aop_vtbl =
{
    { aop_QueryInterface, aop_AddRef, aop_Release, async_GetIids, async_GetRuntimeClassName, async_GetTrustLevel },
    { (void *)aop_put_Progress, (void *)aop_get_Progress, (void *)aop_put_Completed, (void *)aop_get_Completed, (void *)aop_GetResults },
};

static const struct
{
    object_vtbl base;
    void *methods[5];
} ainfo_vtbl =
{
    { ainfo_QueryInterface, ainfo_AddRef, ainfo_Release, async_GetIids, async_GetRuntimeClassName, async_GetTrustLevel },
    { (void *)ainfo_get_Id, (void *)ainfo_get_Status, (void *)ainfo_get_ErrorCode, (void *)ainfo_Cancel, (void *)ainfo_Close },
};

/* The answer of a deployment operation: the call succeeds, the operation has completed with an error */
static HRESULT failed_operation(const char *method, void **operation)
{
    async_operation *This;

    FIXME("%s: deployment is not implemented\n", method);
    if (!operation)
        return E_POINTER;
    *operation = NULL;
    This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));
    if (!This)
        return E_OUTOFMEMORY;
    This->operation_iface.vtbl = &aop_vtbl.base;
    This->info_iface.vtbl = &ainfo_vtbl.base;
    This->ref = 1;
    *operation = &This->operation_iface;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE pm3_AddPackageVolumeAsync(object *iface, void *a1, void *a2)
{
    FIXME("AddPackageVolumeAsync: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm3_AddPackageAsync(object *iface, void *a1, void *a2, void *a3, void *a4, void *a5)
{
    return failed_operation("AddPackageAsync", (void **)a5);
}

static HRESULT STDMETHODCALLTYPE pm3_ClearPackageStatus(object *iface, void *a1, void *a2)
{
    FIXME("ClearPackageStatus: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm3_RegisterPackageAsync(object *iface, void *a1, void *a2, void *a3, void *a4, void *a5)
{
    return failed_operation("RegisterPackageAsync", (void **)a5);
}

static HRESULT STDMETHODCALLTYPE pm3_FindPackageVolume(object *iface, void *a1, void *a2)
{
    FIXME("FindPackageVolume: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm3_FindPackageVolumes(object *iface, void *a1)
{
    FIXME("FindPackageVolumes: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm3_GetDefaultPackageVolume(object *iface, void *a1)
{
    FIXME("GetDefaultPackageVolume: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm3_MovePackageToVolumeAsync(object *iface, void *a1, void *a2, void *a3, void *a4)
{
    return failed_operation("MovePackageToVolumeAsync", (void **)a4);
}

static HRESULT STDMETHODCALLTYPE pm3_RemovePackageVolumeAsync(object *iface, void *a1, void *a2)
{
    return failed_operation("RemovePackageVolumeAsync", (void **)a2);
}

static HRESULT STDMETHODCALLTYPE pm3_SetDefaultPackageVolume(object *iface, void *a1)
{
    FIXME("SetDefaultPackageVolume: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm3_SetPackageStatus(object *iface, void *a1, void *a2)
{
    FIXME("SetPackageStatus: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm3_SetPackageVolumeOfflineAsync(object *iface, void *a1, void *a2)
{
    return failed_operation("SetPackageVolumeOfflineAsync", (void **)a2);
}

static HRESULT STDMETHODCALLTYPE pm3_SetPackageVolumeOnlineAsync(object *iface, void *a1, void *a2)
{
    return failed_operation("SetPackageVolumeOnlineAsync", (void **)a2);
}

static HRESULT STDMETHODCALLTYPE pm3_StagePackageAsync(object *iface, void *a1, void *a2, void *a3, void *a4, void *a5)
{
    return failed_operation("StagePackageAsync", (void **)a5);
}

static HRESULT STDMETHODCALLTYPE pm3_StageUserDataAsync(object *iface, void *a1, void *a2, void *a3)
{
    return failed_operation("StageUserDataAsync", (void **)a3);
}

static HRESULT STDMETHODCALLTYPE pm4_GetPackageVolumesAsync(object *iface, void *a1)
{
    FIXME("GetPackageVolumesAsync: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm5_AddPackageAsync(object *iface, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    return failed_operation("AddPackageAsync", (void **)a7);
}

static HRESULT STDMETHODCALLTYPE pm5_StagePackageAsync(object *iface, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    return failed_operation("StagePackageAsync", (void **)a7);
}

static HRESULT STDMETHODCALLTYPE pm5_RegisterPackageByFamilyNameAsync(object *iface, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6)
{
    return failed_operation("RegisterPackageByFamilyNameAsync", (void **)a6);
}

static HRESULT STDMETHODCALLTYPE pm5_get_DebugSettings(object *iface, void *a1)
{
    FIXME("get_DebugSettings: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm6_ProvisionPackageForAllUsersAsync(object *iface, void *a1, void *a2)
{
    return failed_operation("ProvisionPackageForAllUsersAsync", (void **)a2);
}

static HRESULT STDMETHODCALLTYPE pm6_AddPackageByAppInstallerFileAsync(object *iface, void *a1, void *a2, void *a3, void *a4)
{
    return failed_operation("AddPackageByAppInstallerFileAsync", (void **)a4);
}

static HRESULT STDMETHODCALLTYPE pm6_RequestAddPackageByAppInstallerFileAsync(object *iface, void *a1, void *a2, void *a3, void *a4)
{
    return failed_operation("RequestAddPackageByAppInstallerFileAsync", (void **)a4);
}

static HRESULT STDMETHODCALLTYPE pm6_AddPackageAsync(object *iface, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8)
{
    return failed_operation("AddPackageAsync", (void **)a8);
}

static HRESULT STDMETHODCALLTYPE pm6_StagePackageAsync(object *iface, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8)
{
    return failed_operation("StagePackageAsync", (void **)a8);
}

static HRESULT STDMETHODCALLTYPE pm6_RequestAddPackageAsync(object *iface, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    return failed_operation("RequestAddPackageAsync", (void **)a7);
}

static HRESULT STDMETHODCALLTYPE pm7_RequestAddPackageAsync(object *iface, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8)
{
    return failed_operation("RequestAddPackageAsync", (void **)a8);
}

static HRESULT STDMETHODCALLTYPE pm8_DeprovisionPackageForAllUsersAsync(object *iface, void *a1, void *a2)
{
    return failed_operation("DeprovisionPackageForAllUsersAsync", (void **)a2);
}

static HRESULT STDMETHODCALLTYPE pm9_FindProvisionedPackages(object *iface, void *a1)
{
    FIXME("FindProvisionedPackages: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm9_AddPackageByUriAsync(object *iface, void *a1, void *a2, void *a3)
{
    return failed_operation("AddPackageByUriAsync", (void **)a3);
}

static HRESULT STDMETHODCALLTYPE pm9_StagePackageByUriAsync(object *iface, void *a1, void *a2, void *a3)
{
    return failed_operation("StagePackageByUriAsync", (void **)a3);
}

static HRESULT STDMETHODCALLTYPE pm9_RegisterPackageByUriAsync(object *iface, void *a1, void *a2, void *a3)
{
    return failed_operation("RegisterPackageByUriAsync", (void **)a3);
}

static HRESULT STDMETHODCALLTYPE pm9_RegisterPackagesByFullNameAsync(object *iface, void *a1, void *a2, void *a3)
{
    return failed_operation("RegisterPackagesByFullNameAsync", (void **)a3);
}

static HRESULT STDMETHODCALLTYPE pm9_SetPackageStubPreference(object *iface, void *a1, void *a2)
{
    FIXME("SetPackageStubPreference: not implemented\n");
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE pm9_GetPackageStubPreference(object *iface, void *a1, void *a2)
{
    FIXME("GetPackageStubPreference: not implemented\n");
    return E_NOTIMPL;
}

static package_manager *manager_from_pm3(object *iface)
{
    return CONTAINING_RECORD(iface, package_manager, extra.iface[0]);
}

static HRESULT STDMETHODCALLTYPE pm3_QueryInterface(object *iface, REFIID iid, void **out)
{
    return manager_query_interface(manager_from_pm3(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE pm3_AddRef(object *iface)
{
    return InterlockedIncrement(&manager_from_pm3(iface)->ref);
}

static ULONG STDMETHODCALLTYPE pm3_Release(object *iface)
{
    return manager_release(manager_from_pm3(iface));
}

static HRESULT STDMETHODCALLTYPE pm3_GetIids(object *iface, ULONG *count, IID **iids)
{
    return manager_get_iids(count, iids);
}

static HRESULT STDMETHODCALLTYPE pm3_GetRuntimeClassName(object *iface, HSTRING *name)
{
    return manager_get_class_name(name);
}

static HRESULT STDMETHODCALLTYPE pm3_GetTrustLevel(object *iface, TrustLevel *level)
{
    return manager_get_trust_level(level);
}

static const struct
{
    object_vtbl base;
    void *methods[15];
} pm3_vtbl =
{
    { pm3_QueryInterface, pm3_AddRef, pm3_Release, pm3_GetIids, pm3_GetRuntimeClassName, pm3_GetTrustLevel },
    {
        (void *)pm3_AddPackageVolumeAsync,
        (void *)pm3_AddPackageAsync,
        (void *)pm3_ClearPackageStatus,
        (void *)pm3_RegisterPackageAsync,
        (void *)pm3_FindPackageVolume,
        (void *)pm3_FindPackageVolumes,
        (void *)pm3_GetDefaultPackageVolume,
        (void *)pm3_MovePackageToVolumeAsync,
        (void *)pm3_RemovePackageVolumeAsync,
        (void *)pm3_SetDefaultPackageVolume,
        (void *)pm3_SetPackageStatus,
        (void *)pm3_SetPackageVolumeOfflineAsync,
        (void *)pm3_SetPackageVolumeOnlineAsync,
        (void *)pm3_StagePackageAsync,
        (void *)pm3_StageUserDataAsync,
    },
};

static package_manager *manager_from_pm4(object *iface)
{
    return CONTAINING_RECORD(iface, package_manager, extra.iface[1]);
}

static HRESULT STDMETHODCALLTYPE pm4_QueryInterface(object *iface, REFIID iid, void **out)
{
    return manager_query_interface(manager_from_pm4(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE pm4_AddRef(object *iface)
{
    return InterlockedIncrement(&manager_from_pm4(iface)->ref);
}

static ULONG STDMETHODCALLTYPE pm4_Release(object *iface)
{
    return manager_release(manager_from_pm4(iface));
}

static HRESULT STDMETHODCALLTYPE pm4_GetIids(object *iface, ULONG *count, IID **iids)
{
    return manager_get_iids(count, iids);
}

static HRESULT STDMETHODCALLTYPE pm4_GetRuntimeClassName(object *iface, HSTRING *name)
{
    return manager_get_class_name(name);
}

static HRESULT STDMETHODCALLTYPE pm4_GetTrustLevel(object *iface, TrustLevel *level)
{
    return manager_get_trust_level(level);
}

static const struct
{
    object_vtbl base;
    void *methods[1];
} pm4_vtbl =
{
    { pm4_QueryInterface, pm4_AddRef, pm4_Release, pm4_GetIids, pm4_GetRuntimeClassName, pm4_GetTrustLevel },
    {
        (void *)pm4_GetPackageVolumesAsync,
    },
};

static package_manager *manager_from_pm5(object *iface)
{
    return CONTAINING_RECORD(iface, package_manager, extra.iface[2]);
}

static HRESULT STDMETHODCALLTYPE pm5_QueryInterface(object *iface, REFIID iid, void **out)
{
    return manager_query_interface(manager_from_pm5(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE pm5_AddRef(object *iface)
{
    return InterlockedIncrement(&manager_from_pm5(iface)->ref);
}

static ULONG STDMETHODCALLTYPE pm5_Release(object *iface)
{
    return manager_release(manager_from_pm5(iface));
}

static HRESULT STDMETHODCALLTYPE pm5_GetIids(object *iface, ULONG *count, IID **iids)
{
    return manager_get_iids(count, iids);
}

static HRESULT STDMETHODCALLTYPE pm5_GetRuntimeClassName(object *iface, HSTRING *name)
{
    return manager_get_class_name(name);
}

static HRESULT STDMETHODCALLTYPE pm5_GetTrustLevel(object *iface, TrustLevel *level)
{
    return manager_get_trust_level(level);
}

static const struct
{
    object_vtbl base;
    void *methods[4];
} pm5_vtbl =
{
    { pm5_QueryInterface, pm5_AddRef, pm5_Release, pm5_GetIids, pm5_GetRuntimeClassName, pm5_GetTrustLevel },
    {
        (void *)pm5_AddPackageAsync,
        (void *)pm5_StagePackageAsync,
        (void *)pm5_RegisterPackageByFamilyNameAsync,
        (void *)pm5_get_DebugSettings,
    },
};

static package_manager *manager_from_pm6(object *iface)
{
    return CONTAINING_RECORD(iface, package_manager, extra.iface[3]);
}

static HRESULT STDMETHODCALLTYPE pm6_QueryInterface(object *iface, REFIID iid, void **out)
{
    return manager_query_interface(manager_from_pm6(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE pm6_AddRef(object *iface)
{
    return InterlockedIncrement(&manager_from_pm6(iface)->ref);
}

static ULONG STDMETHODCALLTYPE pm6_Release(object *iface)
{
    return manager_release(manager_from_pm6(iface));
}

static HRESULT STDMETHODCALLTYPE pm6_GetIids(object *iface, ULONG *count, IID **iids)
{
    return manager_get_iids(count, iids);
}

static HRESULT STDMETHODCALLTYPE pm6_GetRuntimeClassName(object *iface, HSTRING *name)
{
    return manager_get_class_name(name);
}

static HRESULT STDMETHODCALLTYPE pm6_GetTrustLevel(object *iface, TrustLevel *level)
{
    return manager_get_trust_level(level);
}

static const struct
{
    object_vtbl base;
    void *methods[6];
} pm6_vtbl =
{
    { pm6_QueryInterface, pm6_AddRef, pm6_Release, pm6_GetIids, pm6_GetRuntimeClassName, pm6_GetTrustLevel },
    {
        (void *)pm6_ProvisionPackageForAllUsersAsync,
        (void *)pm6_AddPackageByAppInstallerFileAsync,
        (void *)pm6_RequestAddPackageByAppInstallerFileAsync,
        (void *)pm6_AddPackageAsync,
        (void *)pm6_StagePackageAsync,
        (void *)pm6_RequestAddPackageAsync,
    },
};

static package_manager *manager_from_pm7(object *iface)
{
    return CONTAINING_RECORD(iface, package_manager, extra.iface[4]);
}

static HRESULT STDMETHODCALLTYPE pm7_QueryInterface(object *iface, REFIID iid, void **out)
{
    return manager_query_interface(manager_from_pm7(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE pm7_AddRef(object *iface)
{
    return InterlockedIncrement(&manager_from_pm7(iface)->ref);
}

static ULONG STDMETHODCALLTYPE pm7_Release(object *iface)
{
    return manager_release(manager_from_pm7(iface));
}

static HRESULT STDMETHODCALLTYPE pm7_GetIids(object *iface, ULONG *count, IID **iids)
{
    return manager_get_iids(count, iids);
}

static HRESULT STDMETHODCALLTYPE pm7_GetRuntimeClassName(object *iface, HSTRING *name)
{
    return manager_get_class_name(name);
}

static HRESULT STDMETHODCALLTYPE pm7_GetTrustLevel(object *iface, TrustLevel *level)
{
    return manager_get_trust_level(level);
}

static const struct
{
    object_vtbl base;
    void *methods[1];
} pm7_vtbl =
{
    { pm7_QueryInterface, pm7_AddRef, pm7_Release, pm7_GetIids, pm7_GetRuntimeClassName, pm7_GetTrustLevel },
    {
        (void *)pm7_RequestAddPackageAsync,
    },
};

static package_manager *manager_from_pm8(object *iface)
{
    return CONTAINING_RECORD(iface, package_manager, extra.iface[5]);
}

static HRESULT STDMETHODCALLTYPE pm8_QueryInterface(object *iface, REFIID iid, void **out)
{
    return manager_query_interface(manager_from_pm8(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE pm8_AddRef(object *iface)
{
    return InterlockedIncrement(&manager_from_pm8(iface)->ref);
}

static ULONG STDMETHODCALLTYPE pm8_Release(object *iface)
{
    return manager_release(manager_from_pm8(iface));
}

static HRESULT STDMETHODCALLTYPE pm8_GetIids(object *iface, ULONG *count, IID **iids)
{
    return manager_get_iids(count, iids);
}

static HRESULT STDMETHODCALLTYPE pm8_GetRuntimeClassName(object *iface, HSTRING *name)
{
    return manager_get_class_name(name);
}

static HRESULT STDMETHODCALLTYPE pm8_GetTrustLevel(object *iface, TrustLevel *level)
{
    return manager_get_trust_level(level);
}

static const struct
{
    object_vtbl base;
    void *methods[1];
} pm8_vtbl =
{
    { pm8_QueryInterface, pm8_AddRef, pm8_Release, pm8_GetIids, pm8_GetRuntimeClassName, pm8_GetTrustLevel },
    {
        (void *)pm8_DeprovisionPackageForAllUsersAsync,
    },
};

static package_manager *manager_from_pm9(object *iface)
{
    return CONTAINING_RECORD(iface, package_manager, extra.iface[6]);
}

static HRESULT STDMETHODCALLTYPE pm9_QueryInterface(object *iface, REFIID iid, void **out)
{
    return manager_query_interface(manager_from_pm9(iface), iid, out);
}

static ULONG STDMETHODCALLTYPE pm9_AddRef(object *iface)
{
    return InterlockedIncrement(&manager_from_pm9(iface)->ref);
}

static ULONG STDMETHODCALLTYPE pm9_Release(object *iface)
{
    return manager_release(manager_from_pm9(iface));
}

static HRESULT STDMETHODCALLTYPE pm9_GetIids(object *iface, ULONG *count, IID **iids)
{
    return manager_get_iids(count, iids);
}

static HRESULT STDMETHODCALLTYPE pm9_GetRuntimeClassName(object *iface, HSTRING *name)
{
    return manager_get_class_name(name);
}

static HRESULT STDMETHODCALLTYPE pm9_GetTrustLevel(object *iface, TrustLevel *level)
{
    return manager_get_trust_level(level);
}

static const struct
{
    object_vtbl base;
    void *methods[7];
} pm9_vtbl =
{
    { pm9_QueryInterface, pm9_AddRef, pm9_Release, pm9_GetIids, pm9_GetRuntimeClassName, pm9_GetTrustLevel },
    {
        (void *)pm9_FindProvisionedPackages,
        (void *)pm9_AddPackageByUriAsync,
        (void *)pm9_StagePackageByUriAsync,
        (void *)pm9_RegisterPackageByUriAsync,
        (void *)pm9_RegisterPackagesByFullNameAsync,
        (void *)pm9_SetPackageStubPreference,
        (void *)pm9_GetPackageStubPreference,
    },
};


/* ---- the activation factory: static, lives as long as the DLL ---- */

static struct
{
    IActivationFactory IActivationFactory_iface;
    LONG ref;
} factory;

static HRESULT STDMETHODCALLTYPE factory_QueryInterface(IActivationFactory *This, REFIID iid, void **out)
{
    if (!out)
        return E_POINTER;
    /* Windows' factory of this class is not agile */
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IActivationFactory))
    {
        *out = This;
        InterlockedIncrement(&factory.ref);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE factory_AddRef(IActivationFactory *This)
{
    return InterlockedIncrement(&factory.ref);
}

static ULONG STDMETHODCALLTYPE factory_Release(IActivationFactory *This)
{
    return InterlockedDecrement(&factory.ref);
}

static HRESULT STDMETHODCALLTYPE factory_GetIids(IActivationFactory *This, ULONG *count, IID **iids)
{
    IID *list;

    if (!count || !iids)
        return E_POINTER;
    list = CoTaskMemAlloc(sizeof(IID));
    if (!list)
        return E_OUTOFMEMORY;
    list[0] = IID_IActivationFactory;
    *count = 1;
    *iids = list;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE factory_GetRuntimeClassName(IActivationFactory *This, HSTRING *name)
{
    return manager_get_class_name(name);
}

static HRESULT STDMETHODCALLTYPE factory_GetTrustLevel(IActivationFactory *This, TrustLevel *level)
{
    return manager_get_trust_level(level);
}

static HRESULT STDMETHODCALLTYPE factory_ActivateInstance(IActivationFactory *This, IInspectable **instance)
{
    package_manager *manager;

    TRACE("(%p)\n", instance);
    if (!instance)
        return E_POINTER;
    *instance = NULL;
    manager = HeapAlloc(GetProcessHeap(), 0, sizeof(*manager));
    if (!manager)
        return E_OUTOFMEMORY;
    manager->IPackageManager_iface.vtbl = &pm_vtbl.base;
    manager->IPackageManager2_iface.vtbl = &pm2_vtbl.base;
    manager->extra.iface[0].vtbl = &pm3_vtbl.base;
    manager->extra.iface[1].vtbl = &pm4_vtbl.base;
    manager->extra.iface[2].vtbl = &pm5_vtbl.base;
    manager->extra.iface[3].vtbl = &pm6_vtbl.base;
    manager->extra.iface[4].vtbl = &pm7_vtbl.base;
    manager->extra.iface[5].vtbl = &pm8_vtbl.base;
    manager->extra.iface[6].vtbl = &pm9_vtbl.base;
    manager->ref = 1;
    *instance = (IInspectable *)&manager->IPackageManager_iface;
    return S_OK;
}

static const IActivationFactoryVtbl factory_vtbl =
{
    factory_QueryInterface,
    factory_AddRef,
    factory_Release,
    factory_GetIids,
    factory_GetRuntimeClassName,
    factory_GetTrustLevel,
    factory_ActivateInstance,
};

HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **out)
{
    LPCWSTR name = WindowsGetStringRawBuffer(classid, NULL);

    TRACE("(%s, %p)\n", debugstr_hstring(classid), out);

    if (!out)
        return E_POINTER;
    *out = NULL;

    if (!name || _wcsicmp(name, class_name) != 0)
        return CLASS_E_CLASSNOTAVAILABLE;

    *out = &factory.IActivationFactory_iface;
    InterlockedIncrement(&factory.ref);
    return S_OK;
}

/* The factory is static and may be in use by anyone holding a reference: stay loaded */
HRESULT WINAPI DllCanUnloadNow(void)
{
    return S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(instance);
            factory.IActivationFactory_iface.lpVtbl = (IActivationFactoryVtbl *)&factory_vtbl;
            factory.ref = 1;
            break;
    }
    return TRUE;
}
