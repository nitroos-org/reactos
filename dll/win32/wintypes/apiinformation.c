/*
 * PROJECT:     ReactOS Windows Runtime type support (wintypes.dll)
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows.Foundation.Metadata.ApiInformation: the statics that tell an application which
 *              Windows Runtime types, members and API contracts this system has
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Interface id and member order of IApiInformationStatics: microsoft/windows-rs (MIT),
 * crates/libs/windows/src/Windows/Foundation/Metadata/mod.rs (IApiInformationStatics_Vtbl).
 * The meaning of each member: the public documentation (learn.microsoft.com,
 * Windows.Foundation.Metadata.ApiInformation).
 *
 * What the answers mean. An application asks ApiInformation before it uses a type, so a TRUE for
 * something this system does not have makes the application take a path that fails later. Every
 * answer therefore comes from what NitroOS provides, never from what Windows has:
 *  - API contracts: the contract table of RoIsApiContractPresent (main.c), the same answer.
 *  - IsTypePresent: TRUE for a runtime class that is registered (a key below
 *    HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId, in the registry view of the
 *    calling process) whose DLL exists, and for the few non-activatable types of the table below
 *    that this DLL implements. FALSE for everything else, also for types that Windows has.
 *  - Member checks (method, event, property, enum value): TRUE only for the members of the
 *    types of the table below. NitroOS ships no WinMetadata files from which other members could be
 *    resolved, so every other member is FALSE; that errs on the side of the application using a
 *    fallback.
 *
 * Behaviour measured on Windows 10 22H2 (read-only probe, x64): type and member names are compared
 * case-sensitively; an empty or NULL name is E_INVALIDARG; IsTypePresent of a name whose namespace
 * Windows cannot resolve ("System.String", "Nonexistent.Type.Name", or a name in lower case) is
 * 0x80073D54 with FALSE, a name in a known namespace that is no type ("Windows", "Windows.Foundation",
 * a trailing space) is S_OK with FALSE; a NULL result pointer faults (we fail with E_POINTER); the
 * factory is IActivationFactory + IApiInformationStatics (GetIids lists both, IActivationFactory
 * first), GetRuntimeClassName of the factory fails with E_ILLEGAL_METHOD_CALL, ActivateInstance is
 * E_NOTIMPL. Not measured (the probe ended before it): event/property/enum checks, the contract
 * members, and any member check of an unknown type; those are marked "verify on oracle" below.
 */

#define COBJMACROS
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winreg.h"
#include "objbase.h"
#include "inspectable.h"
#include "activation.h"
#include "winstring.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wintypes);

static const GUID IID_AI_IUnknown = { 0x00000000, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_AI_IInspectable = { 0xaf86e2e0, 0xb12d, 0x4c6a, { 0x9c, 0x5a, 0xd7, 0xaa, 0x65, 0x10, 0x1e, 0x90 } };
static const GUID IID_AI_IActivationFactory = { 0x00000035, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_AI_IAgileObject = { 0x94ea2b94, 0xe9cc, 0x49e0, { 0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90 } };
static const GUID IID_AI_IApiInformationStatics = { 0x997439fe, 0xf681, 0x4a11, { 0xb4, 0x16, 0xc1, 0x3a, 0x47, 0xe8, 0xba, 0x36 } };

HRESULT WINAPI RoIsApiContractPresent(const WCHAR *name, UINT16 major, UINT16 minor, BOOL *present);

/* What IsTypePresent returns on Windows 10 for a name in a namespace it cannot resolve (measured) */
#define E_API_NAMESPACE_UNKNOWN ((HRESULT)0x80073D54)
#ifndef E_ILLEGAL_METHOD_CALL
#define E_ILLEGAL_METHOD_CALL ((HRESULT)0x8000000E)
#endif

/* Types this DLL implements that are not activatable classes (the classes are found in the registry) */
static const WCHAR *const plain_types[] =
{
    L"Windows.Foundation.IPropertyValue",
    L"Windows.Foundation.IPropertyValueStatics",
    L"Windows.Foundation.PropertyType",
    L"Windows.Foundation.Metadata.IApiInformationStatics",
};

/* The members of the types of this DLL: type, member name, kind and number of input parameters */
enum member_kind { MEMBER_METHOD, MEMBER_ENUM_VALUE, MEMBER_EVENT, MEMBER_PROPERTY };

static const struct
{
    const WCHAR *type;
    const WCHAR *name;
    enum member_kind kind;
    UINT32 arity;
} members[] =
{
    { L"Windows.Foundation.Metadata.ApiInformation", L"IsTypePresent", MEMBER_METHOD, 1 },
    { L"Windows.Foundation.Metadata.ApiInformation", L"IsMethodPresent", MEMBER_METHOD, 2 },
    { L"Windows.Foundation.Metadata.ApiInformation", L"IsMethodPresent", MEMBER_METHOD, 3 },
    { L"Windows.Foundation.Metadata.ApiInformation", L"IsEventPresent", MEMBER_METHOD, 2 },
    { L"Windows.Foundation.Metadata.ApiInformation", L"IsPropertyPresent", MEMBER_METHOD, 2 },
    { L"Windows.Foundation.Metadata.ApiInformation", L"IsReadOnlyPropertyPresent", MEMBER_METHOD, 2 },
    { L"Windows.Foundation.Metadata.ApiInformation", L"IsWriteablePropertyPresent", MEMBER_METHOD, 2 },
    { L"Windows.Foundation.Metadata.ApiInformation", L"IsEnumNamedValuePresent", MEMBER_METHOD, 2 },
    { L"Windows.Foundation.Metadata.ApiInformation", L"IsApiContractPresent", MEMBER_METHOD, 2 },
    { L"Windows.Foundation.Metadata.ApiInformation", L"IsApiContractPresent", MEMBER_METHOD, 3 },
    { L"Windows.Foundation.PropertyType", L"Empty", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"UInt8", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Int16", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"UInt16", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Int32", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"UInt32", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Int64", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"UInt64", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Single", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Double", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Char16", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Boolean", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"String", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Inspectable", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"DateTime", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"TimeSpan", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Guid", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Point", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Size", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Rect", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"OtherType", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"UInt8Array", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Int16Array", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"UInt16Array", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Int32Array", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"UInt32Array", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Int64Array", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"UInt64Array", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"SingleArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"DoubleArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"Char16Array", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"BooleanArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"StringArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"InspectableArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"DateTimeArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"TimeSpanArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"GuidArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"PointArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"SizeArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"RectArray", MEMBER_ENUM_VALUE, 0 },
    { L"Windows.Foundation.PropertyType", L"OtherTypeArray", MEMBER_ENUM_VALUE, 0 },
};

/* A name argument: the characters, or NULL for a NULL or empty string, or a string with an embedded NULL */
static const WCHAR *get_name(HSTRING str, UINT32 *len)
{
    BOOL has_null;

    *len = 0;
    if (WindowsIsStringEmpty(str))
        return NULL;
    if (FAILED(WindowsStringHasEmbeddedNull(str, &has_null)) || has_null)
        return NULL;
    return WindowsGetStringRawBuffer(str, len);
}

/* Names are compared case-sensitively (measured) */
static BOOL name_equals(const WCHAR *name, UINT32 len, const WCHAR *known)
{
    return wcslen(known) == len && !wcsncmp(name, known, len);
}

/* A registered activatable class whose DLL is there. The key names are searched by enumeration: the registry
 * compares names without case, the name of a type is case-sensitive. */
static BOOL class_is_registered(const WCHAR *name, UINT32 len)
{
    static const WCHAR base[] = L"SOFTWARE\\Microsoft\\WindowsRuntime\\ActivatableClassId";
    WCHAR sub[257], dll[MAX_PATH], expanded[MAX_PATH];
    DWORD type, size, sub_len, attrs, i;
    HKEY classes, key;
    BOOL found = FALSE;

    if (len >= ARRAYSIZE(sub))
        return FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base, 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &classes))
        return FALSE;
    for (i = 0; ; i++)
    {
        sub_len = ARRAYSIZE(sub);
        if (RegEnumKeyExW(classes, i, sub, &sub_len, NULL, NULL, NULL, NULL))
            break;
        if (sub_len != len || wcsncmp(sub, name, len))
            continue;
        if (RegOpenKeyExW(classes, sub, 0, KEY_QUERY_VALUE, &key))
            break;
        size = sizeof(dll) - sizeof(WCHAR);
        if (!RegQueryValueExW(key, L"DllPath", NULL, &type, (BYTE *)dll, &size) &&
            (type == REG_SZ || type == REG_EXPAND_SZ))
        {
            dll[size / sizeof(WCHAR)] = 0;
            if (type == REG_EXPAND_SZ)
            {
                /* The return value is the size needed: 0 is a failure and a larger one means that expanded
                 * was not filled in. Either way the class is not registered, the buffer is not used. */
                DWORD expanded_len = ExpandEnvironmentStringsW(dll, expanded, ARRAYSIZE(expanded));

                if (!expanded_len || expanded_len > ARRAYSIZE(expanded) || !expanded[0])
                {
                    RegCloseKey(key);
                    break;
                }
                wcscpy(dll, expanded);
            }
            attrs = GetFileAttributesW(dll);
            found = attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
        }
        RegCloseKey(key);
        break;
    }
    RegCloseKey(classes);
    return found;
}

static BOOL is_type_present(const WCHAR *name, UINT32 len)
{
    UINT32 i;

    for (i = 0; i < ARRAYSIZE(plain_types); i++)
        if (name_equals(name, len, plain_types[i]))
            return TRUE;
    return class_is_registered(name, len);
}

static BOOL is_member_present(const WCHAR *type, UINT32 type_len, const WCHAR *name, UINT32 name_len,
                              enum member_kind kind, BOOL check_arity, UINT32 arity)
{
    UINT32 i;

    for (i = 0; i < ARRAYSIZE(members); i++)
    {
        if (members[i].kind != kind || !name_equals(type, type_len, members[i].type) ||
            !name_equals(name, name_len, members[i].name))
            continue;
        if (!check_arity || members[i].arity == arity)
            return TRUE;
    }
    return FALSE;
}

/* ---- IApiInformationStatics ---- */

#define AI_CHECK_RESULT(r) do { if (!(r)) return E_POINTER; *(r) = FALSE; } while (0)

static HRESULT WINAPI ai_IsTypePresent(void *iface, HSTRING type, BOOLEAN *present)
{
    const WCHAR *name;
    UINT32 len;

    TRACE("(%p, %s, %p)\n", iface, debugstr_hstring(type), present);
    AI_CHECK_RESULT(present);
    if (!(name = get_name(type, &len)))
        return E_INVALIDARG;
    /* Windows resolves the namespace of the name first and fails for one it does not know (measured). We have no
     * list of its namespaces: names of the Windows namespace ("Windows.") are answered, anything else fails the
     * same way. */
    if (len > 8 && !wcsncmp(name, L"Windows.", 8))
    {
        *present = is_type_present(name, len);
        return S_OK;
    }
    if (len == 7 && !wcsncmp(name, L"Windows", 7))
        return S_OK;
    return E_API_NAMESPACE_UNKNOWN;
}

static HRESULT member_check(HSTRING type, HSTRING member, enum member_kind kind, BOOL check_arity, UINT32 arity,
                            BOOLEAN *present)
{
    const WCHAR *type_name, *member_name;
    UINT32 type_len, member_len;

    AI_CHECK_RESULT(present);
    if (!(type_name = get_name(type, &type_len)) || !(member_name = get_name(member, &member_len)))
        return E_INVALIDARG;
    *present = is_member_present(type_name, type_len, member_name, member_len, kind, check_arity, arity);
    return S_OK;
}

static HRESULT WINAPI ai_IsMethodPresent(void *iface, HSTRING type, HSTRING method, BOOLEAN *present)
{
    TRACE("(%p, %s, %s, %p)\n", iface, debugstr_hstring(type), debugstr_hstring(method), present);
    return member_check(type, method, MEMBER_METHOD, FALSE, 0, present);
}

static HRESULT WINAPI ai_IsMethodPresentWithArity(void *iface, HSTRING type, HSTRING method, UINT32 arity,
                                                  BOOLEAN *present)
{
    TRACE("(%p, %s, %s, %lu, %p)\n", iface, debugstr_hstring(type), debugstr_hstring(method), arity, present);
    return member_check(type, method, MEMBER_METHOD, TRUE, arity, present);
}

/* No type of this DLL has events or properties: nothing is in the table for them. Not measured on Windows (the
 * probe ended before): the result for a type that has no such member and the arguments of these members. */
static HRESULT WINAPI ai_IsEventPresent(void *iface, HSTRING type, HSTRING event, BOOLEAN *present)
{
    TRACE("(%p, %s, %s, %p)\n", iface, debugstr_hstring(type), debugstr_hstring(event), present);
    return member_check(type, event, MEMBER_EVENT, FALSE, 0, present);
}

static HRESULT WINAPI ai_IsPropertyPresent(void *iface, HSTRING type, HSTRING property, BOOLEAN *present)
{
    TRACE("(%p, %s, %s, %p)\n", iface, debugstr_hstring(type), debugstr_hstring(property), present);
    return member_check(type, property, MEMBER_PROPERTY, FALSE, 0, present);
}

static HRESULT WINAPI ai_IsReadOnlyPropertyPresent(void *iface, HSTRING type, HSTRING property, BOOLEAN *present)
{
    TRACE("(%p, %s, %s, %p)\n", iface, debugstr_hstring(type), debugstr_hstring(property), present);
    return member_check(type, property, MEMBER_PROPERTY, FALSE, 0, present);
}

static HRESULT WINAPI ai_IsWriteablePropertyPresent(void *iface, HSTRING type, HSTRING property, BOOLEAN *present)
{
    TRACE("(%p, %s, %s, %p)\n", iface, debugstr_hstring(type), debugstr_hstring(property), present);
    return member_check(type, property, MEMBER_PROPERTY, FALSE, 0, present);
}

static HRESULT WINAPI ai_IsEnumNamedValuePresent(void *iface, HSTRING type, HSTRING value, BOOLEAN *present)
{
    TRACE("(%p, %s, %s, %p)\n", iface, debugstr_hstring(type), debugstr_hstring(value), present);
    return member_check(type, value, MEMBER_ENUM_VALUE, FALSE, 0, present);
}

static HRESULT contract_check(HSTRING contract, UINT16 major, UINT16 minor, BOOLEAN *present)
{
    const WCHAR *name;
    UINT32 len;
    BOOL result = FALSE;
    HRESULT hr;

    AI_CHECK_RESULT(present);
    /* Not measured on Windows for this interface: the case of the name and an unknown contract (the answers are
     * those of RoIsApiContractPresent, measured for that function): verify on oracle */
    if (!(name = get_name(contract, &len)))
        return E_INVALIDARG;
    /* the string is NUL terminated (HSTRINGs are) and has no embedded NUL, see get_name */
    hr = RoIsApiContractPresent(name, major, minor, &result);
    if (SUCCEEDED(hr))
        *present = result;
    return hr;
}

static HRESULT WINAPI ai_IsApiContractPresentByMajor(void *iface, HSTRING contract, UINT16 major, BOOLEAN *present)
{
    TRACE("(%p, %s, %u, %p)\n", iface, debugstr_hstring(contract), major, present);
    return contract_check(contract, major, 0, present);
}

static HRESULT WINAPI ai_IsApiContractPresentByMajorAndMinor(void *iface, HSTRING contract, UINT16 major,
                                                             UINT16 minor, BOOLEAN *present)
{
    TRACE("(%p, %s, %u, %u, %p)\n", iface, debugstr_hstring(contract), major, minor, present);
    return contract_check(contract, major, minor, present);
}

/* ---- the activation factory: IActivationFactory and IApiInformationStatics on one object ---- */

struct ai_factory
{
    const void *lpVtbl;             /* IApiInformationStatics */
    const void *afVtbl;             /* IActivationFactory */
};

static struct ai_factory factory;

static HRESULT WINAPI fac_QueryInterface(void *iface, REFIID iid, void **out)
{
    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_AI_IUnknown) || IsEqualGUID(iid, &IID_AI_IInspectable) ||
        IsEqualGUID(iid, &IID_AI_IAgileObject) || IsEqualGUID(iid, &IID_AI_IActivationFactory))
        *out = &factory.afVtbl;
    else if (IsEqualGUID(iid, &IID_AI_IApiInformationStatics))
        *out = &factory.lpVtbl;
    else
    {
        *out = NULL;
        return E_NOINTERFACE;
    }
    return S_OK;
}

static ULONG WINAPI fac_AddRef(void *iface) { return 2; }
static ULONG WINAPI fac_Release(void *iface) { return 1; }

static HRESULT WINAPI fac_GetIids(void *iface, ULONG *count, IID **iids)
{
    IID *p;

    if (!count || !iids)
        return E_POINTER;
    if (!(p = CoTaskMemAlloc(2 * sizeof(IID))))
        return E_OUTOFMEMORY;
    p[0] = IID_AI_IActivationFactory;
    p[1] = IID_AI_IApiInformationStatics;
    *count = 2;
    *iids = p;
    return S_OK;
}

/* Measured: the factory of a static class has no runtime class name */
static HRESULT WINAPI fac_GetRuntimeClassName(void *iface, HSTRING *name)
{
    if (!name)
        return E_POINTER;
    *name = NULL;
    return E_ILLEGAL_METHOD_CALL;
}

static HRESULT WINAPI fac_GetTrustLevel(void *iface, int *level)
{
    if (!level)
        return E_POINTER;
    *level = 0; /* BaseTrust */
    return S_OK;
}

/* A static class has no instances */
static HRESULT WINAPI fac_ActivateInstance(void *iface, IInspectable **instance)
{
    if (instance)
        *instance = NULL;
    return E_NOTIMPL;
}

static const struct
{
    HRESULT (WINAPI *QueryInterface)(void *, REFIID, void **);
    ULONG (WINAPI *AddRef)(void *);
    ULONG (WINAPI *Release)(void *);
    HRESULT (WINAPI *GetIids)(void *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(void *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(void *, int *);
    HRESULT (WINAPI *IsTypePresent)(void *, HSTRING, BOOLEAN *);
    HRESULT (WINAPI *IsMethodPresent)(void *, HSTRING, HSTRING, BOOLEAN *);
    HRESULT (WINAPI *IsMethodPresentWithArity)(void *, HSTRING, HSTRING, UINT32, BOOLEAN *);
    HRESULT (WINAPI *IsEventPresent)(void *, HSTRING, HSTRING, BOOLEAN *);
    HRESULT (WINAPI *IsPropertyPresent)(void *, HSTRING, HSTRING, BOOLEAN *);
    HRESULT (WINAPI *IsReadOnlyPropertyPresent)(void *, HSTRING, HSTRING, BOOLEAN *);
    HRESULT (WINAPI *IsWriteablePropertyPresent)(void *, HSTRING, HSTRING, BOOLEAN *);
    HRESULT (WINAPI *IsEnumNamedValuePresent)(void *, HSTRING, HSTRING, BOOLEAN *);
    HRESULT (WINAPI *IsApiContractPresentByMajor)(void *, HSTRING, UINT16, BOOLEAN *);
    HRESULT (WINAPI *IsApiContractPresentByMajorAndMinor)(void *, HSTRING, UINT16, UINT16, BOOLEAN *);
} statics_vtbl =
{
    fac_QueryInterface, fac_AddRef, fac_Release, fac_GetIids, fac_GetRuntimeClassName, fac_GetTrustLevel,
    ai_IsTypePresent, ai_IsMethodPresent, ai_IsMethodPresentWithArity, ai_IsEventPresent, ai_IsPropertyPresent,
    ai_IsReadOnlyPropertyPresent, ai_IsWriteablePropertyPresent, ai_IsEnumNamedValuePresent,
    ai_IsApiContractPresentByMajor, ai_IsApiContractPresentByMajorAndMinor,
};

static const struct
{
    HRESULT (WINAPI *QueryInterface)(void *, REFIID, void **);
    ULONG (WINAPI *AddRef)(void *);
    ULONG (WINAPI *Release)(void *);
    HRESULT (WINAPI *GetIids)(void *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(void *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(void *, int *);
    HRESULT (WINAPI *ActivateInstance)(void *, IInspectable **);
} af_vtbl =
{
    fac_QueryInterface, fac_AddRef, fac_Release, fac_GetIids, fac_GetRuntimeClassName, fac_GetTrustLevel,
    fac_ActivateInstance,
};

static struct ai_factory factory = { &statics_vtbl, &af_vtbl };

/* The activation factory of Windows.Foundation.Metadata.ApiInformation */
HRESULT ai_get_activation_factory(HSTRING classid, IActivationFactory **out)
{
    if (!out)
        return E_POINTER;
    if (!classid)
    {
        *out = NULL;
        return E_INVALIDARG;
    }
    if (_wcsicmp(WindowsGetStringRawBuffer(classid, NULL), L"Windows.Foundation.Metadata.ApiInformation"))
        return CLASS_E_CLASSNOTAVAILABLE;
    *out = (IActivationFactory *)&factory.afVtbl;
    return S_OK;
}
