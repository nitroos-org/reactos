/*
 * Copyright 2014 Martin Storsjo
 * Copyright 2016 Michael Müller
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
#include <stdio.h>
#include <stdlib.h>

#include "objbase.h"
#include "initguid.h"
#include "roapi.h"
#include "roparameterizediid.h"
#include "roerrorapi.h"
#include "winstring.h"

#include "combase_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(combase);

struct activatable_class_data
{
    ULONG size;
    DWORD unk;
    DWORD module_len;
    DWORD module_offset;
    DWORD threading_model;
};

static HRESULT get_library_for_classid(const WCHAR *classid, WCHAR **out)
{
    ACTCTX_SECTION_KEYED_DATA data;
    HKEY hkey_root, hkey_class;
    DWORD type, size;
    HRESULT hr;
    WCHAR *buf = NULL;

    *out = NULL;

    /* search activation context first */
    data.cbSize = sizeof(data);
    if (FindActCtxSectionStringW(FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX, NULL,
            ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES, classid, &data))
    {
        struct activatable_class_data *activatable_class = (struct activatable_class_data *)data.lpData;
        void *ptr = (BYTE *)data.lpSectionBase + activatable_class->module_offset;
        *out = wcsdup(ptr);
        return S_OK;
    }

    /* load class registry key */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\WindowsRuntime\\ActivatableClassId",
                      0, KEY_READ, &hkey_root))
        return REGDB_E_READREGDB;
    if (RegOpenKeyExW(hkey_root, classid, 0, KEY_READ, &hkey_class))
    {
        WARN("Class %s not found in registry\n", debugstr_w(classid));
        RegCloseKey(hkey_root);
        return REGDB_E_CLASSNOTREG;
    }
    RegCloseKey(hkey_root);

    /* load (and expand) DllPath registry value */
    if (RegQueryValueExW(hkey_class, L"DllPath", NULL, &type, NULL, &size))
    {
        hr = REGDB_E_READREGDB;
        goto done;
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ)
    {
        hr = REGDB_E_READREGDB;
        goto done;
    }
    if (!(buf = malloc(size)))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if (RegQueryValueExW(hkey_class, L"DllPath", NULL, NULL, (BYTE *)buf, &size))
    {
        hr = REGDB_E_READREGDB;
        goto done;
    }
    if (type == REG_EXPAND_SZ)
    {
        WCHAR *expanded;
        DWORD len = ExpandEnvironmentStringsW(buf, NULL, 0);
        if (!(expanded = malloc(len * sizeof(WCHAR))))
        {
            hr = E_OUTOFMEMORY;
            goto done;
        }
        ExpandEnvironmentStringsW(buf, expanded, len);
        free(buf);
        buf = expanded;
    }

    *out = buf;
    return S_OK;

done:
    free(buf);
    RegCloseKey(hkey_class);
    return hr;
}


/***********************************************************************
 *      RoInitialize (combase.@)
 */
HRESULT WINAPI RoInitialize(RO_INIT_TYPE type)
{
    switch (type) {
    case RO_INIT_SINGLETHREADED:
        return CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    default:
        FIXME("type %d\n", type);
    case RO_INIT_MULTITHREADED:
        return CoInitializeEx(NULL, COINIT_MULTITHREADED);
    }
}

/***********************************************************************
 *      RoUninitialize (combase.@)
 */
void WINAPI RoUninitialize(void)
{
    CoUninitialize();
}

/***********************************************************************
 *      RoGetActivationFactory (combase.@)
 */
HRESULT WINAPI DECLSPEC_HOTPATCH RoGetActivationFactory(HSTRING classid, REFIID iid, void **class_factory)
{
    PFNGETACTIVATIONFACTORY pDllGetActivationFactory;
    IActivationFactory *factory;
    WCHAR *library;
    HMODULE module;
    HRESULT hr;

    FIXME("(%s, %s, %p): semi-stub\n", debugstr_hstring(classid), debugstr_guid(iid), class_factory);

    if (!iid || !class_factory)
        return E_INVALIDARG;

    if (FAILED(hr = ensure_mta()))
        return hr;

    hr = get_library_for_classid(WindowsGetStringRawBuffer(classid, NULL), &library);
    if (FAILED(hr))
    {
        ERR("Failed to find library for %s\n", debugstr_hstring(classid));
        return hr;
    }

    if (!(module = LoadLibraryW(library)))
    {
        ERR("Failed to load module %s\n", debugstr_w(library));
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }

    if (!(pDllGetActivationFactory = (void *)GetProcAddress(module, "DllGetActivationFactory")))
    {
        ERR("Module %s does not implement DllGetActivationFactory\n", debugstr_w(library));
        hr = E_FAIL;
        goto done;
    }

    TRACE("Found library %s for class %s\n", debugstr_w(library), debugstr_hstring(classid));

    hr = pDllGetActivationFactory(classid, &factory);
    if (SUCCEEDED(hr))
    {
        hr = IActivationFactory_QueryInterface(factory, iid, class_factory);
        if (SUCCEEDED(hr))
        {
            TRACE("Created interface %p\n", *class_factory);
            module = NULL;
        }
        IActivationFactory_Release(factory);
    }

done:
    free(library);
    if (module) FreeLibrary(module);
    return hr;
}

/***********************************************************************
 *      RoGetParameterizedTypeInstanceIID (combase.@)
 *
 * The IID of an instance of a parameterized interface or delegate (IIterable<Package>): the
 * name-based (version 5) UUID of its type signature, "pinterface({faa585ea-...};rc(...;{...}))",
 * in the Windows Runtime namespace 11f47ad5-7b73-42c0-abae-878b1e16adee. The caller's locator
 * tells what each named type is. The .NET Framework calls this for every generic Windows Runtime
 * interface it uses (a foreach over IIterable<T>).
 */
#ifdef __REACTOS__
typedef struct
{
    ULONG Unknown[6];
    ULONG State[5];
    ULONG Count[2];
    UCHAR Buffer[64];
} ROAPI_SHA_CTX;

VOID WINAPI A_SHAInit(ROAPI_SHA_CTX *ctx);
VOID WINAPI A_SHAUpdate(ROAPI_SHA_CTX *ctx, const unsigned char *buffer, UINT size);
VOID WINAPI A_SHAFinal(ROAPI_SHA_CTX *ctx, PULONG result);

struct param_iid_extra
{
    char *signature;
};

struct signature_builder
{
    IRoSimpleMetaDataBuilder IRoSimpleMetaDataBuilder_iface;
    const IRoMetaDataLocator *locator;
    char *buffer;
    size_t length;
    size_t allocated;
    UINT32 arg_count;       /* type arguments that the parameterized type just located takes */
    BOOL located;
    UINT depth;
    HRESULT hr;
};

static HRESULT append(struct signature_builder *b, const char *str)
{
    size_t len = strlen(str);

    if (b->length + len + 1 > b->allocated)
    {
        size_t allocated = max(b->allocated * 2, b->length + len + 64);
        char *buffer = realloc(b->buffer, allocated);

        if (!buffer) return E_OUTOFMEMORY;
        b->buffer = buffer;
        b->allocated = allocated;
    }
    memcpy(b->buffer + b->length, str, len + 1);
    b->length += len;
    return S_OK;
}

static HRESULT append_name(struct signature_builder *b, const WCHAR *name)
{
    char *str;
    int len;
    HRESULT hr;

    if (!name) return E_INVALIDARG;
    len = WideCharToMultiByte(CP_UTF8, 0, name, -1, NULL, 0, NULL, NULL);
    if (!len || !(str = malloc(len))) return E_OUTOFMEMORY;
    WideCharToMultiByte(CP_UTF8, 0, name, -1, str, len, NULL, NULL);
    hr = append(b, str);
    free(str);
    return hr;
}

static HRESULT append_guid(struct signature_builder *b, const GUID *guid)
{
    char str[40];

    sprintf(str, "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", (unsigned long)guid->Data1, guid->Data2,
            guid->Data3, guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3], guid->Data4[4],
            guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    return append(b, str);
}

static const struct
{
    const WCHAR *name;
    const char *signature;
}
basic_types[] =
{
    { L"UInt8", "u1" }, { L"Int8", "i1" }, { L"Int16", "i2" }, { L"UInt16", "u2" }, { L"Int32", "i4" },
    { L"UInt32", "u4" }, { L"Int64", "i8" }, { L"UInt64", "u8" }, { L"Single", "f4" }, { L"Double", "f8" },
    { L"Boolean", "b1" }, { L"Char16", "c2" }, { L"String", "string" }, { L"Guid", "g16" },
    { L"Object", "cinterface(IInspectable)" },
};

static HRESULT append_type(struct signature_builder *b, UINT32 count, const WCHAR **names, UINT32 *pos);

static HRESULT append_args(struct signature_builder *b, UINT32 count, const WCHAR **names, UINT32 *pos, UINT32 args)
{
    HRESULT hr = S_OK;

    while (args-- && SUCCEEDED(hr))
    {
        if (FAILED(hr = append(b, ";"))) break;
        hr = append_type(b, count, names, pos);
    }
    if (SUCCEEDED(hr)) hr = append(b, ")");
    return hr;
}

/* one type from names[*pos]: a parameterized one takes the types after it as its arguments */
static HRESULT append_type(struct signature_builder *b, UINT32 count, const WCHAR **names, UINT32 *pos)
{
    const WCHAR *name;
    UINT32 i, args;
    HRESULT hr;

    if (*pos >= count) return E_INVALIDARG;
    name = names[(*pos)++];
    if (!name || !*name) return E_INVALIDARG;
    for (i = 0; i < ARRAY_SIZE(basic_types); i++)
        if (!wcscmp(name, basic_types[i].name)) return append(b, basic_types[i].signature);

    if (++b->depth > 64) return E_INVALIDARG;
    b->located = FALSE;
    b->arg_count = 0;
    b->hr = S_OK;
    hr = IRoMetaDataLocator_Locate((IRoMetaDataLocator *)b->locator, name, &b->IRoSimpleMetaDataBuilder_iface);
    if (SUCCEEDED(hr)) hr = b->hr;
    if (SUCCEEDED(hr) && !b->located)
    {
        WARN("locator gave nothing for %s\n", debugstr_w(name));
        hr = E_UNEXPECTED;
    }
    args = b->arg_count;
    /* a parameterized interface or delegate wrote "pinterface({piid}": its arguments follow */
    if (SUCCEEDED(hr) && args) hr = append_args(b, count, names, pos, args);
    b->depth--;
    return hr;
}

static inline struct signature_builder *impl_from_IRoSimpleMetaDataBuilder(IRoSimpleMetaDataBuilder *iface)
{
    return CONTAINING_RECORD(iface, struct signature_builder, IRoSimpleMetaDataBuilder_iface);
}

/* the builder is called once per Locate: a second call is a locator error */
static BOOL begin_set(struct signature_builder *b)
{
    if (b->located)
    {
        b->hr = E_UNEXPECTED;
        return FALSE;
    }
    b->located = TRUE;
    return TRUE;
}

static HRESULT set_result(struct signature_builder *b, HRESULT hr)
{
    if (FAILED(hr)) b->hr = hr;
    return hr;
}

static HRESULT STDMETHODCALLTYPE builder_SetWinRtInterface(IRoSimpleMetaDataBuilder *iface, GUID iid)
{
    struct signature_builder *b = impl_from_IRoSimpleMetaDataBuilder(iface);

    if (!begin_set(b)) return E_UNEXPECTED;
    return set_result(b, append_guid(b, &iid));
}

static HRESULT STDMETHODCALLTYPE builder_SetDelegate(IRoSimpleMetaDataBuilder *iface, GUID iid)
{
    struct signature_builder *b = impl_from_IRoSimpleMetaDataBuilder(iface);
    HRESULT hr;

    if (!begin_set(b)) return E_UNEXPECTED;
    if (SUCCEEDED(hr = append(b, "delegate(")) && SUCCEEDED(hr = append_guid(b, &iid))) hr = append(b, ")");
    return set_result(b, hr);
}

/* "rc(name;{iid})" or "ig(name;{iid})" */
static HRESULT set_simple_default(IRoSimpleMetaDataBuilder *iface, const char *kind, const WCHAR *name,
                                  const GUID *iid)
{
    struct signature_builder *b = impl_from_IRoSimpleMetaDataBuilder(iface);
    HRESULT hr;

    if (!begin_set(b)) return E_UNEXPECTED;
    if (!iid) return set_result(b, E_INVALIDARG);
    if (SUCCEEDED(hr = append(b, kind)) && SUCCEEDED(hr = append_name(b, name)) && SUCCEEDED(hr = append(b, ";")) &&
        SUCCEEDED(hr = append_guid(b, iid)))
        hr = append(b, ")");
    return set_result(b, hr);
}

/* "rc(name;pinterface(...))" or "ig(name;pinterface(...))": the default interface is parameterized */
static HRESULT set_parameterized_default(IRoSimpleMetaDataBuilder *iface, const char *kind, const WCHAR *name,
                                         UINT32 count, const WCHAR **names)
{
    struct signature_builder *b = impl_from_IRoSimpleMetaDataBuilder(iface);
    UINT32 pos = 0;
    HRESULT hr;

    if (!begin_set(b)) return E_UNEXPECTED;
    if (!count || !names) return set_result(b, E_INVALIDARG);
    if (SUCCEEDED(hr = append(b, kind)) && SUCCEEDED(hr = append_name(b, name)) && SUCCEEDED(hr = append(b, ";")))
    {
        hr = append_type(b, count, names, &pos);
        b->located = TRUE;
        b->arg_count = 0;
        if (SUCCEEDED(hr) && pos != count) hr = E_INVALIDARG;
        if (SUCCEEDED(hr)) hr = append(b, ")");
    }
    return set_result(b, hr);
}

static HRESULT STDMETHODCALLTYPE builder_SetInterfaceGroupSimpleDefault(IRoSimpleMetaDataBuilder *iface,
        const WCHAR *name, const WCHAR *default_name, const GUID *default_iid)
{
    return set_simple_default(iface, "ig(", name, default_iid);
}

static HRESULT STDMETHODCALLTYPE builder_SetInterfaceGroupParameterizedDefault(IRoSimpleMetaDataBuilder *iface,
        const WCHAR *name, UINT32 count, const WCHAR **names)
{
    return set_parameterized_default(iface, "ig(", name, count, names);
}

static HRESULT STDMETHODCALLTYPE builder_SetRuntimeClassSimpleDefault(IRoSimpleMetaDataBuilder *iface,
        const WCHAR *name, const WCHAR *default_name, const GUID *default_iid)
{
    return set_simple_default(iface, "rc(", name, default_iid);
}

static HRESULT STDMETHODCALLTYPE builder_SetRuntimeClassParameterizedDefault(IRoSimpleMetaDataBuilder *iface,
        const WCHAR *name, UINT32 count, const WCHAR **names)
{
    return set_parameterized_default(iface, "rc(", name, count, names);
}

static HRESULT STDMETHODCALLTYPE builder_SetStruct(IRoSimpleMetaDataBuilder *iface, const WCHAR *name,
        UINT32 field_count, const WCHAR **field_names)
{
    struct signature_builder *b = impl_from_IRoSimpleMetaDataBuilder(iface);
    UINT32 i, pos;
    HRESULT hr;

    if (!begin_set(b)) return E_UNEXPECTED;
    if (field_count && !field_names) return set_result(b, E_INVALIDARG);
    if (FAILED(hr = append(b, "struct(")) || FAILED(hr = append_name(b, name))) return set_result(b, hr);
    for (i = 0; i < field_count && SUCCEEDED(hr); i++)
    {
        if (FAILED(hr = append(b, ";"))) break;
        pos = 0;
        hr = append_type(b, 1, &field_names[i], &pos);
        b->located = TRUE;
        b->arg_count = 0;
    }
    if (SUCCEEDED(hr)) hr = append(b, ")");
    return set_result(b, hr);
}

static HRESULT STDMETHODCALLTYPE builder_SetEnum(IRoSimpleMetaDataBuilder *iface, const WCHAR *name,
        const WCHAR *base_type)
{
    struct signature_builder *b = impl_from_IRoSimpleMetaDataBuilder(iface);
    HRESULT hr;

    if (!begin_set(b)) return E_UNEXPECTED;
    if (SUCCEEDED(hr = append(b, "enum(")) && SUCCEEDED(hr = append_name(b, name)))
        hr = append(b, base_type && !wcscmp(base_type, L"UInt32") ? ";u4)" : ";i4)");
    return set_result(b, hr);
}

/* "pinterface({piid}" for both: append_type writes the arguments and the ")" */
static HRESULT set_parameterized(IRoSimpleMetaDataBuilder *iface, const GUID *piid, UINT32 arg_count)
{
    struct signature_builder *b = impl_from_IRoSimpleMetaDataBuilder(iface);
    HRESULT hr;

    if (!begin_set(b)) return E_UNEXPECTED;
    if (!arg_count) return set_result(b, E_INVALIDARG);
    if (SUCCEEDED(hr = append(b, "pinterface(")) && SUCCEEDED(hr = append_guid(b, piid)))
        b->arg_count = arg_count;
    return set_result(b, hr);
}

static HRESULT STDMETHODCALLTYPE builder_SetParameterizedInterface(IRoSimpleMetaDataBuilder *iface, GUID piid,
        UINT32 arg_count)
{
    return set_parameterized(iface, &piid, arg_count);
}

static HRESULT STDMETHODCALLTYPE builder_SetParameterizedDelegate(IRoSimpleMetaDataBuilder *iface, GUID piid,
        UINT32 arg_count)
{
    return set_parameterized(iface, &piid, arg_count);
}

static const IRoSimpleMetaDataBuilderVtbl signature_builder_vtbl =
{
    builder_SetWinRtInterface,
    builder_SetDelegate,
    builder_SetInterfaceGroupSimpleDefault,
    builder_SetInterfaceGroupParameterizedDefault,
    builder_SetRuntimeClassSimpleDefault,
    builder_SetRuntimeClassParameterizedDefault,
    builder_SetStruct,
    builder_SetEnum,
    builder_SetParameterizedInterface,
    builder_SetParameterizedDelegate,
};

HRESULT WINAPI RoGetParameterizedTypeInstanceIID(UINT32 name_element_count, const WCHAR **name_elements,
                                                 const IRoMetaDataLocator *meta_data_locator, GUID *iid,
                                                 ROPARAMIIDHANDLE *hiid)
{
    static const BYTE winrt_namespace[16] =
        { 0x11, 0xf4, 0x7a, 0xd5, 0x7b, 0x73, 0x42, 0xc0, 0xab, 0xae, 0x87, 0x8b, 0x1e, 0x16, 0xad, 0xee };
    struct signature_builder b = { { &signature_builder_vtbl } };
    struct param_iid_extra *extra;
    ROAPI_SHA_CTX sha;
    ULONG digest[5];
    BYTE *hash = (BYTE *)digest;
    UINT32 pos = 0;
    HRESULT hr;

    TRACE("%u %p %p %p %p\n", name_element_count, name_elements, meta_data_locator, iid, hiid);

    if (hiid) *hiid = NULL;
    if (!iid) return E_INVALIDARG;
    memset(iid, 0, sizeof(*iid));
    if (!name_element_count || !name_elements || !meta_data_locator) return E_INVALIDARG;

    b.locator = meta_data_locator;
    hr = append_type(&b, name_element_count, name_elements, &pos);
    /* the first element has to be the parameterized type itself, and every element is used */
    if (SUCCEEDED(hr) && (pos != name_element_count || strncmp(b.buffer, "pinterface(", 11))) hr = E_INVALIDARG;
    if (FAILED(hr))
    {
        free(b.buffer);
        return hr;
    }
    TRACE("signature %s\n", debugstr_a(b.buffer));

    A_SHAInit(&sha);
    A_SHAUpdate(&sha, winrt_namespace, sizeof(winrt_namespace));
    A_SHAUpdate(&sha, (const unsigned char *)b.buffer, (UINT)b.length);
    A_SHAFinal(&sha, digest);

    iid->Data1 = (ULONG)hash[0] << 24 | (ULONG)hash[1] << 16 | (ULONG)hash[2] << 8 | hash[3];
    iid->Data2 = (USHORT)(hash[4] << 8 | hash[5]);
    iid->Data3 = (USHORT)(((hash[6] & 0x0f) | 0x50) << 8 | hash[7]);
    iid->Data4[0] = (hash[8] & 0x3f) | 0x80;
    memcpy(iid->Data4 + 1, hash + 9, 7);

    if (hiid && (extra = malloc(sizeof(*extra))))
    {
        extra->signature = b.buffer;
        *hiid = extra;
        return S_OK;
    }
    free(b.buffer);
    return S_OK;
}

/***********************************************************************
 *      RoFreeParameterizedTypeExtra (combase.@)
 */
void WINAPI RoFreeParameterizedTypeExtra(ROPARAMIIDHANDLE handle)
{
    struct param_iid_extra *extra = handle;

    TRACE("%p\n", handle);
    if (!extra || extra == INVALID_HANDLE_VALUE) return;
    free(extra->signature);
    free(extra);
}

/***********************************************************************
 *      RoParameterizedTypeExtraGetTypeSignature (combase.@)
 */
const char * WINAPI RoParameterizedTypeExtraGetTypeSignature(ROPARAMIIDHANDLE handle)
{
    struct param_iid_extra *extra = handle;

    TRACE("%p\n", handle);
    if (!extra || extra == INVALID_HANDLE_VALUE) return NULL;
    return extra->signature;
}
#else
HRESULT WINAPI RoGetParameterizedTypeInstanceIID(UINT32 name_element_count, const WCHAR **name_elements,
                                                 const IRoMetaDataLocator *meta_data_locator, GUID *iid,
                                                 ROPARAMIIDHANDLE *hiid)
{
    FIXME("stub: %d %p %p %p %p\n", name_element_count, name_elements, meta_data_locator, iid, hiid);
    if (iid) *iid = GUID_NULL;
    if (hiid) *hiid = INVALID_HANDLE_VALUE;
    return E_NOTIMPL;
}
#endif

/***********************************************************************
 *      RoActivateInstance (combase.@)
 */
HRESULT WINAPI RoActivateInstance(HSTRING classid, IInspectable **instance)
{
    IActivationFactory *factory;
    HRESULT hr;

    FIXME("(%p, %p): semi-stub\n", classid, instance);

    hr = RoGetActivationFactory(classid, &IID_IActivationFactory, (void **)&factory);
    if (SUCCEEDED(hr))
    {
        hr = IActivationFactory_ActivateInstance(factory, instance);
        IActivationFactory_Release(factory);
    }

    return hr;
}

struct agile_reference
{
    IAgileReference IAgileReference_iface;
    enum AgileReferenceOptions option;
    IStream *marshal_stream;
    CRITICAL_SECTION cs;
    IUnknown *obj;
    LONG ref;
};

static HRESULT marshal_object_in_agile_reference(struct agile_reference *ref, REFIID riid, IUnknown *obj)
{
    HRESULT hr;

    hr = CreateStreamOnHGlobal(0, TRUE, &ref->marshal_stream);
    if (FAILED(hr))
        return hr;

    hr = CoMarshalInterface(ref->marshal_stream, riid, obj, MSHCTX_INPROC, NULL, MSHLFLAGS_TABLESTRONG);
    if (FAILED(hr))
    {
        IStream_Release(ref->marshal_stream);
        ref->marshal_stream = NULL;
    }
    return hr;
}

static inline struct agile_reference *impl_from_IAgileReference(IAgileReference *iface)
{
    return CONTAINING_RECORD(iface, struct agile_reference, IAgileReference_iface);
}

static HRESULT WINAPI agile_ref_QueryInterface(IAgileReference *iface, REFIID riid, void **obj)
{
    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(riid), obj);

    if (!riid || !obj) return E_INVALIDARG;

    if (IsEqualGUID(riid, &IID_IUnknown)
        || IsEqualGUID(riid, &IID_IAgileObject)
        || IsEqualGUID(riid, &IID_IAgileReference))
    {
        IUnknown_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    *obj = NULL;
    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    return E_NOINTERFACE;
}

static ULONG WINAPI agile_ref_AddRef(IAgileReference *iface)
{
    struct agile_reference *impl = impl_from_IAgileReference(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI agile_ref_Release(IAgileReference *iface)
{
    struct agile_reference *impl = impl_from_IAgileReference(iface);
    LONG ref = InterlockedDecrement(&impl->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);

        if (impl->obj)
            IUnknown_Release(impl->obj);

        if (impl->marshal_stream)
        {
            LARGE_INTEGER zero = {0};

            IStream_Seek(impl->marshal_stream, zero, STREAM_SEEK_SET, NULL);
            CoReleaseMarshalData(impl->marshal_stream);
            IStream_Release(impl->marshal_stream);
        }
        DeleteCriticalSection(&impl->cs);
        free(impl);
    }

    return ref;
}

static HRESULT WINAPI agile_ref_Resolve(IAgileReference *iface, REFIID riid, void **obj)
{
    struct agile_reference *impl = impl_from_IAgileReference(iface);
    LARGE_INTEGER zero = {0};
    HRESULT hr;

    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(riid), obj);

    EnterCriticalSection(&impl->cs);
    if (impl->option == AGILEREFERENCE_DELAYEDMARSHAL && impl->marshal_stream == NULL)
    {
        if (FAILED(hr = marshal_object_in_agile_reference(impl, riid, impl->obj)))
        {
            LeaveCriticalSection(&impl->cs);
            return hr;
        }

        IUnknown_Release(impl->obj);
        impl->obj = NULL;
    }

    if (SUCCEEDED(hr = IStream_Seek(impl->marshal_stream, zero, STREAM_SEEK_SET, NULL)))
        hr = CoUnmarshalInterface(impl->marshal_stream, riid, obj);

    LeaveCriticalSection(&impl->cs);
    return hr;
}

static const IAgileReferenceVtbl agile_ref_vtbl =
{
    agile_ref_QueryInterface,
    agile_ref_AddRef,
    agile_ref_Release,
    agile_ref_Resolve,
};

/***********************************************************************
 *      RoGetAgileReference (combase.@)
 */
HRESULT WINAPI RoGetAgileReference(enum AgileReferenceOptions option, REFIID riid, IUnknown *obj,
                                   IAgileReference **agile_reference)
{
    struct agile_reference *impl;
    IUnknown *unknown;
    HRESULT hr;

    TRACE("(%d, %s, %p, %p).\n", option, debugstr_guid(riid), obj, agile_reference);

    if (option != AGILEREFERENCE_DEFAULT && option != AGILEREFERENCE_DELAYEDMARSHAL)
        return E_INVALIDARG;

    if (!InternalIsProcessInitialized())
    {
        ERR("Apartment not initialized\n");
        return CO_E_NOTINITIALIZED;
    }

    hr = IUnknown_QueryInterface(obj, riid, (void **)&unknown);
    if (FAILED(hr))
        return E_NOINTERFACE;
    IUnknown_Release(unknown);

    hr = IUnknown_QueryInterface(obj, &IID_INoMarshal, (void **)&unknown);
    if (SUCCEEDED(hr))
    {
        IUnknown_Release(unknown);
        return CO_E_NOT_SUPPORTED;
    }

    impl = calloc(1, sizeof(*impl));
    if (!impl)
        return E_OUTOFMEMORY;

    impl->IAgileReference_iface.lpVtbl = &agile_ref_vtbl;
    impl->option = option;
    impl->ref = 1;

    if (option == AGILEREFERENCE_DEFAULT)
    {
        if (FAILED(hr = marshal_object_in_agile_reference(impl, riid, obj)))
        {
            free(impl);
            return hr;
        }
    }
    else if (option == AGILEREFERENCE_DELAYEDMARSHAL)
    {
        impl->obj = obj;
        IUnknown_AddRef(impl->obj);
    }

    InitializeCriticalSection(&impl->cs);

    *agile_reference = &impl->IAgileReference_iface;
    return S_OK;
}

/***********************************************************************
 *      RoGetApartmentIdentifier (combase.@)
 */
HRESULT WINAPI RoGetApartmentIdentifier(UINT64 *identifier)
{
    FIXME("(%p): stub\n", identifier);

    if (!identifier)
        return E_INVALIDARG;

#ifdef __REACTOS__
    /* There is no apartment identifier to give: do not hand out the same made-up one for every apartment */
    return E_NOTIMPL;
#else
    *identifier = 0xdeadbeef;
    return S_OK;
#endif
}

/***********************************************************************
 *      RoRegisterForApartmentShutdown (combase.@)
 */
HRESULT WINAPI RoRegisterForApartmentShutdown(IApartmentShutdown *callback,
        UINT64 *identifier, APARTMENT_SHUTDOWN_REGISTRATION_COOKIE *cookie)
{
    HRESULT hr;

    FIXME("(%p, %p, %p): stub\n", callback, identifier, cookie);

#ifdef __REACTOS__
    /* The callback is never called on apartment shutdown: do not pretend it was registered */
    (void)hr;
    return E_NOTIMPL;
#else
    hr = RoGetApartmentIdentifier(identifier);
    if (FAILED(hr))
        return hr;

    if (cookie)
        *cookie = (void *)0xcafecafe;
    return S_OK;
#endif
}

/***********************************************************************
 *      RoGetServerActivatableClasses (combase.@)
 */
HRESULT WINAPI RoGetServerActivatableClasses(HSTRING name, HSTRING **classes, DWORD *count)
{
    FIXME("(%p, %p, %p): stub\n", name, classes, count);

#ifdef __REACTOS__
    /* No enumeration: give back empty outputs and say so */
    if (classes)
        *classes = NULL;
    if (count)
        *count = 0;
    return E_NOTIMPL;
#else
    if (count)
        *count = 0;
    return S_OK;
#endif
}

/***********************************************************************
 *      RoRegisterActivationFactories (combase.@)
 */
HRESULT WINAPI RoRegisterActivationFactories(HSTRING *classes, PFNGETACTIVATIONFACTORY *callbacks,
                                             UINT32 count, RO_REGISTRATION_COOKIE *cookie)
{
    FIXME("(%p, %p, %d, %p): stub\n", classes, callbacks, count, cookie);

#ifdef __REACTOS__
    /* Nothing would find the factories: do not pretend they were registered */
    return E_NOTIMPL;
#else
    return S_OK;
#endif
}

#if DLL_EXPORT_VERSION >= 0x601
VOID WINAPI RaiseFailFastException(PEXCEPTION_RECORD record, PCONTEXT context, DWORD flags);
#endif

/***********************************************************************
 *      RoRevokeActivationFactories (combase.@)
 *
 * Nothing to take back: RoRegisterActivationFactories fails and gives out no cookie. A cookie that is not one
 * of a registration is ignored (Windows does not check it either).
 */
void WINAPI RoRevokeActivationFactories(RO_REGISTRATION_COOKIE cookie)
{
    FIXME("(%p): stub\n", cookie);
}

/***********************************************************************
 *      RoFailFastWithErrorContext (combase.@)
 *
 * Ends the process like RaiseFailFastException does (STATUS_FAIL_FAST_EXCEPTION, no handler runs and no
 * exit code of its own); Windows first reports the error and its context to the error reporting.
 */
void WINAPI RoFailFastWithErrorContext(HRESULT hr)
{
    FIXME("(%#lx): the error context is not reported\n", hr);
#if DLL_EXPORT_VERSION >= 0x601
    RaiseFailFastException(NULL, NULL, 0);
#else
    RaiseException(0xC0000602 /* STATUS_FAIL_FAST_EXCEPTION */, EXCEPTION_NONCONTINUABLE, 0, NULL);
#endif
}

/***********************************************************************
 *      GetRestrictedErrorInfo (combase.@)
 */
HRESULT WINAPI GetRestrictedErrorInfo(IRestrictedErrorInfo **info)
{
    FIXME( "(%p)\n", info );
    return E_NOTIMPL;
}

/***********************************************************************
 *      SetRestrictedErrorInfo (combase.@)
 */
HRESULT WINAPI SetRestrictedErrorInfo(IRestrictedErrorInfo *info)
{
    FIXME( "(%p)\n", info );
    return E_NOTIMPL;
}

/***********************************************************************
 *      RoOriginateLanguageException (combase.@)
 */
BOOL WINAPI RoOriginateLanguageException(HRESULT error, HSTRING message, IUnknown *language_exception)
{
    FIXME("%#lx, %s, %p: stub\n", error, debugstr_hstring(message), language_exception);
    return FALSE;
}

/***********************************************************************
 *      RoOriginateError (combase.@)
 */
BOOL WINAPI RoOriginateError(HRESULT error, HSTRING message)
{
    FIXME("%#lx, %s: stub\n", error, debugstr_hstring(message));
    return FALSE;
}

/***********************************************************************
 *      RoOriginateErrorW (combase.@)
 */
BOOL WINAPI RoOriginateErrorW(HRESULT error, UINT max_len, const WCHAR *message)
{
    FIXME("%#lx, %u, %p: stub\n", error, max_len, message);
    return FALSE;
}

/***********************************************************************
 *      RoSetErrorReportingFlags (combase.@)
 */
HRESULT WINAPI RoSetErrorReportingFlags(UINT32 flags)
{
    FIXME("(%08x): stub\n", flags);
#ifdef __REACTOS__
    /* The flags would not be honoured */
    return E_NOTIMPL;
#else
    return S_OK;
#endif
}

/***********************************************************************
 *      CleanupTlsOleState (combase.@)
 */
void WINAPI CleanupTlsOleState(void *unknown)
{
    FIXME("(%p): stub\n", unknown);
}

/***********************************************************************
 *      DllGetActivationFactory (combase.@)
 */
HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **factory)
{
    FIXME("(%s, %p): stub\n", debugstr_hstring(classid), factory);

    return REGDB_E_CLASSNOTREG;
}
