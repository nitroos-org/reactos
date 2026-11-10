/*
 * PROJECT:     ReactOS Windows Runtime type support (wintypes.dll)
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows.Foundation.PropertyValue: the boxed-value factory (IPropertyValueStatics) and the
 *              objects it creates (IPropertyValue plus IReference<T> / IReferenceArray<T>)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Interface ids and member order: the public Windows Runtime documentation (learn.microsoft.com,
 * Windows.Foundation.IPropertyValue, IPropertyValueStatics, IReference<T>, IReferenceArray<T>) and the
 * IDL of Wine/mingw-w64 (windows.foundation.idl). The ids of the IReference<T> / IReferenceArray<T>
 * instances are the documented name-based (version 5) ids of the parameterized interfaces.
 * Behaviour (class names, which conversions succeed, error codes) was measured on Windows 10 22H2.
 */

#define COBJMACROS
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <wchar.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "objbase.h"
#include "inspectable.h"
#include "activation.h"
#include "winstring.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wintypes);

/* Windows.Foundation.PropertyType */
enum
{
    PT_EMPTY = 0, PT_UINT8, PT_INT16, PT_UINT16, PT_INT32, PT_UINT32, PT_INT64, PT_UINT64, PT_SINGLE, PT_DOUBLE,
    PT_CHAR16, PT_BOOLEAN, PT_STRING, PT_INSPECTABLE, PT_DATETIME, PT_TIMESPAN, PT_GUID, PT_POINT, PT_SIZE, PT_RECT,
    PT_OTHER, PT_ARRAY = 1024
};

typedef struct { float X, Y; } PV_POINT;
typedef struct { float Width, Height; } PV_SIZE;
typedef struct { float X, Y, Width, Height; } PV_RECT;
typedef struct { INT64 UniversalTime; } PV_DATETIME;
typedef struct { INT64 Duration; } PV_TIMESPAN;

#define E_PV_TYPEMISMATCH ((HRESULT)0x80028CA0)
#define E_PV_OVERFLOW     ((HRESULT)0x8002000A) /* DISP_E_OVERFLOW */

static const GUID IID_PV_IUnknown = { 0x00000000, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_PV_IInspectable = { 0xaf86e2e0, 0xb12d, 0x4c6a, { 0x9c, 0x5a, 0xd7, 0xaa, 0x65, 0x10, 0x1e, 0x90 } };
static const GUID IID_PV_IActivationFactory = { 0x00000035, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID IID_PV_IPropertyValue = { 0x4bd682dd, 0x7554, 0x40e9, { 0x9a, 0x9b, 0x82, 0x65, 0x4e, 0xde, 0x7e, 0x62 } };
static const GUID IID_PV_IPropertyValueStatics = { 0x629bdbc8, 0xd932, 0x4ff4, { 0x96, 0xb9, 0x8d, 0x96, 0xc5, 0xc1, 0xe8, 0x58 } };
static const GUID IID_PV_IAgileObject = { 0x94ea2b94, 0xe9cc, 0x49e0, { 0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90 } };

/* Per type: element size, the type name used in the runtime class name, and the ids of IReference<T> and IReferenceArray<T> */
struct type_info
{
    const WCHAR *name;
    UINT32 size;
    GUID ref;
    GUID refarray;
};

#define TI(n, sz, a,b,c, d0,d1,d2,d3,d4,d5,d6,d7, A,B,C, D0,D1,D2,D3,D4,D5,D6,D7) \
    { n, sz, { 0x##a, 0x##b, 0x##c, { 0x##d0, 0x##d1, 0x##d2, 0x##d3, 0x##d4, 0x##d5, 0x##d6, 0x##d7 } }, \
             { 0x##A, 0x##B, 0x##C, { 0x##D0, 0x##D1, 0x##D2, 0x##D3, 0x##D4, 0x##D5, 0x##D6, 0x##D7 } } }

/* indexed by PropertyType 1..19 (index 0 unused) */
static const struct type_info type_infos[20] =
{
    { 0 },
    TI(L"UInt8",   1, e5198cc8,2873,55f5, b0,a1,84,ff,9e,4a,ad,62,  2af22683,3734,56d0, a6,0e,68,8c,c8,5d,16,19),
    TI(L"Int16",   2, 6ec9e41b,6709,5647, 99,18,a1,27,01,10,fc,4e,  912f8fd7,adc0,5d60, a8,96,7e,d7,60,89,cc,5b),
    TI(L"UInt16",  2, 5ab7d2c3,6b62,5e71, a4,b6,2d,49,c4,f2,38,fd,  6624a2dd,83f7,519c, 9d,55,bb,1f,65,60,45,6b),
    TI(L"Int32",   4, 548cefbd,bc8a,5fa0, 8d,f2,95,74,40,fc,8b,f4,  a6d080a5,b087,5bc2, 9a,9f,5c,d6,87,b4,d1,f7),
    TI(L"UInt32",  4, 513ef3af,e784,5325, a9,1e,97,c2,b8,11,1c,f3,  97374b68,eb87,56cc, b1,8e,27,ef,0f,9c,fd,0c),
    TI(L"Int64",   8, 4dda9e24,e69f,5c6a, a0,a6,93,42,73,65,af,2a,  6e333271,2e2a,5955, 87,90,83,6c,76,ee,53,b6),
    TI(L"UInt64",  8, 6755e376,53bb,568b, a1,1d,17,23,98,68,30,9e,  38b60434,d67c,523e, 9d,0e,24,d6,43,41,10,73),
    TI(L"Single",  4, 719cc2ba,3e76,5def, 9f,1a,38,d8,5a,14,5e,a8,  6ab1ea83,cb41,5f99, 92,cc,23,bd,43,36,a1,fb),
    TI(L"Double",  8, 2f2d6c29,5473,5f3e, 92,e7,96,57,2b,b9,90,e2,  d301f253,e0a3,5d2b, 9a,41,a4,d6,2b,ec,46,23),
    TI(L"Char16",  2, fb393ef3,bbac,5bd5, 91,44,84,f2,35,76,f4,15,  a4095aab,eb7d,5782, 8f,ad,16,09,de,a2,49,ad),
    TI(L"Boolean", 1, 3c00fd60,2950,5939, a2,1a,2d,12,c5,a0,1b,8a,  e8e72666,48cc,593f, ba,85,26,63,49,69,56,e3),
    TI(L"String",  sizeof(void *), fd416dfb,2a07,52eb, aa,e3,df,ce,14,11,6c,05,  0385688e,e3c7,5c5e, a3,89,55,24,ed,e3,49,f1),
    TI(L"Inspectable", sizeof(void *), 06dccc90,a058,5c88, 87,b7,6f,33,60,a2,fc,16,  9cd7a84f,0c80,59c5, b4,4e,97,78,41,bb,43,d9),
    TI(L"Windows.Foundation.DateTime", 8, 5541d8a7,497c,5aa4, 86,fc,77,13,ad,bf,2a,2c,  1b8e9594,588e,5a07, 9e,65,07,31,a4,c9,a2,db),
    TI(L"Windows.Foundation.TimeSpan", 8, 604d0c4c,91de,5c2a, 93,5f,36,2f,13,ea,f8,00,  ad73197d,2cfa,57a6, 89,93,9f,ac,40,fe,b7,91),
    TI(L"Guid",   16, 7d50f649,632c,51f9, 84,9a,ee,49,42,89,33,ea,  eecf9838,c1c2,5b4a, 97,6f,ce,c2,61,d1,55,ae),
    TI(L"Windows.Foundation.Point",   8, 84f14c22,a00a,5272, 8d,3d,82,11,2e,66,df,00,  39313214,5c7d,599d, ae,5a,17,d9,d6,49,22,58),
    TI(L"Windows.Foundation.Size",    8, 61723086,8e53,5276, 9f,36,2a,4b,b9,3e,2b,75,  3b40e9d4,e0c3,56f6, b8,8b,e5,05,eb,73,75,7b),
    TI(L"Windows.Foundation.Rect",   16, 80423f11,054f,5eac, af,d3,63,b6,ce,15,e7,7b,  8a444256,d661,5e9a, a7,2b,d8,f1,d7,96,2d,0c),
};

struct property_value;

struct pv_ref
{
    const void *lpVtbl;
    struct property_value *owner;
};

struct property_value
{
    const void *lpVtbl;             /* IPropertyValue */
    struct pv_ref ref;              /* IReference<T> or IReferenceArray<T> (not used for the empty value) */
    LONG refcount;
    int type;                       /* PropertyType, without PT_ARRAY */
    BOOL is_array;
    UINT32 count;                   /* elements, arrays only */
    union
    {
        UINT8 u8; INT16 i16; UINT16 u16; INT32 i32; UINT32 u32; INT64 i64; UINT64 u64; float f32; double f64;
        WCHAR c16; BOOLEAN b; HSTRING str; IInspectable *insp; GUID guid; PV_DATETIME dt; PV_TIMESPAN ts;
        PV_POINT pt; PV_SIZE sz; PV_RECT rc;
        void *arr;
    } v;
};

static inline struct property_value *impl_from_pv(void *iface) { return (struct property_value *)iface; }
static inline struct property_value *impl_from_ref(void *iface) { return ((struct pv_ref *)iface)->owner; }

static HRESULT pv_query(struct property_value *pv, REFIID iid, void **out)
{
    *out = NULL;
    /* one identity for IUnknown, IInspectable and the value interface */
    if (IsEqualGUID(iid, &IID_PV_IUnknown) || IsEqualGUID(iid, &IID_PV_IInspectable)
        || IsEqualGUID(iid, &IID_PV_IPropertyValue) || IsEqualGUID(iid, &IID_PV_IAgileObject))
        *out = pv;
    else if (pv->type != PT_EMPTY && IsEqualGUID(iid, pv->is_array ? &type_infos[pv->type].refarray : &type_infos[pv->type].ref))
        *out = &pv->ref;
    else
        return E_NOINTERFACE;
    InterlockedIncrement(&pv->refcount);
    return S_OK;
}

static ULONG pv_release_obj(struct property_value *pv)
{
    ULONG ref = InterlockedDecrement(&pv->refcount);
    UINT32 i;

    if (ref) return ref;
    if (pv->is_array)
    {
        if (pv->type == PT_STRING)
            for (i = 0; i < pv->count; i++) WindowsDeleteString(((HSTRING *)pv->v.arr)[i]);
        else if (pv->type == PT_INSPECTABLE)
            for (i = 0; i < pv->count; i++)
                if (((IInspectable **)pv->v.arr)[i]) IInspectable_Release(((IInspectable **)pv->v.arr)[i]);
        free(pv->v.arr);
    }
    else if (pv->type == PT_STRING) WindowsDeleteString(pv->v.str);
    else if (pv->type == PT_INSPECTABLE && pv->v.insp) IInspectable_Release(pv->v.insp);
    free(pv);
    return 0;
}

static HRESULT pv_get_iids(struct property_value *pv, ULONG *count, IID **iids)
{
    IID *p;
    ULONG n = pv->type == PT_EMPTY ? 1 : 2;

    if (!count || !iids) return E_POINTER;
    if (!(p = CoTaskMemAlloc(n * sizeof(IID)))) return E_OUTOFMEMORY;
    p[0] = IID_PV_IPropertyValue;
    if (n > 1) p[1] = pv->is_array ? type_infos[pv->type].refarray : type_infos[pv->type].ref;
    *count = n;
    *iids = p;
    return S_OK;
}

static HRESULT pv_get_class_name(struct property_value *pv, HSTRING *name)
{
    WCHAR buf[96];

    if (!name) return E_POINTER;
    if (pv->type == PT_EMPTY) return WindowsCreateString(L"Windows.Foundation.IPropertyValue", 33, name);
    wcscpy(buf, L"Windows.Foundation.");
    wcscat(buf, pv->is_array ? L"IReferenceArray" : L"IReference");
    wcscat(buf, L"`1<");
    wcscat(buf, type_infos[pv->type].name);
    wcscat(buf, L">");
    return WindowsCreateString(buf, wcslen(buf), name);
}

static HRESULT pv_get_trust(int *level)
{
    if (!level) return E_POINTER;
    *level = 0; /* BaseTrust */
    return S_OK;
}

/* ---- IPropertyValue ---- */

static HRESULT WINAPI pvi_QueryInterface(void *iface, REFIID iid, void **out)
{
    return pv_query(impl_from_pv(iface), iid, out);
}
static ULONG WINAPI pvi_AddRef(void *iface) { return InterlockedIncrement(&impl_from_pv(iface)->refcount); }
static ULONG WINAPI pvi_Release(void *iface) { return pv_release_obj(impl_from_pv(iface)); }
static HRESULT WINAPI pvi_GetIids(void *iface, ULONG *c, IID **i) { return pv_get_iids(impl_from_pv(iface), c, i); }
static HRESULT WINAPI pvi_GetRuntimeClassName(void *iface, HSTRING *n) { return pv_get_class_name(impl_from_pv(iface), n); }
static HRESULT WINAPI pvi_GetTrustLevel(void *iface, int *l) { return pv_get_trust(l); }

static HRESULT WINAPI pvi_get_Type(void *iface, int *value)
{
    struct property_value *pv = impl_from_pv(iface);

    if (!value) return E_POINTER;
    *value = pv->type | (pv->is_array ? PT_ARRAY : 0);
    return S_OK;
}

static HRESULT WINAPI pvi_get_IsNumericScalar(void *iface, BOOLEAN *value)
{
    if (!value) return E_POINTER;
    /* Windows 10 22H2 answers FALSE for every value (measured for all scalar types and arrays) */
    *value = FALSE;
    return S_OK;
}

/*
 * Number conversions. Measured on Windows: a numeric value converts to another numeric type when the
 * conversion is exact (the converted value converts back to the original); anything else is
 * DISP_E_OVERFLOW (0x8002000A). So Int32 -1 reads as Int16, Int32 and Int64 but not as UInt8/UInt16/
 * UInt32/UInt64, Double 3.7 only as Double, Double -2.5 as Single and Double, and a floating point
 * value only reads as an integer when it is integral and in range. Non-numeric types (and arrays read as
 * scalars) are TYPE_E_TYPEMISMATCH.
 */
struct num
{
    int kind;      /* 0 signed (i), 1 unsigned above INT64_MAX (u), 2 floating point (d) */
    INT64 i;
    UINT64 u;
    double d;
};

static BOOL is_numeric_type(int type) { return type >= PT_UINT8 && type <= PT_DOUBLE; }

static void read_num(int type, const void *p, struct num *n)
{
    memset(n, 0, sizeof(*n));
    switch (type)
    {
    case PT_UINT8: n->i = *(const UINT8 *)p; break;
    case PT_INT16: n->i = *(const INT16 *)p; break;
    case PT_UINT16: n->i = *(const UINT16 *)p; break;
    case PT_INT32: n->i = *(const INT32 *)p; break;
    case PT_UINT32: n->i = *(const UINT32 *)p; break;
    case PT_INT64: n->i = *(const INT64 *)p; break;
    case PT_UINT64:
        n->u = *(const UINT64 *)p;
        if (n->u > (UINT64)INT64_MAX) n->kind = 1; else n->i = (INT64)n->u;
        break;
    case PT_SINGLE: n->kind = 2; n->d = *(const float *)p; break;
    case PT_DOUBLE: n->kind = 2; n->d = *(const double *)p; break;
    }
}

/* Converts to a numeric type and stores it at dst (as large as the type) */
static HRESULT store_num(int type, const struct num *n, void *dst)
{
    INT64 min = 0;
    UINT64 max = 0;
    INT64 iv = 0;
    UINT64 uv = 0;

    switch (type)
    {
    case PT_UINT8: max = 0xff; break;
    case PT_INT16: min = -32768; max = 32767; break;
    case PT_UINT16: max = 0xffff; break;
    case PT_INT32: min = INT32_MIN; max = INT32_MAX; break;
    case PT_UINT32: max = 0xffffffffu; break;
    case PT_INT64: min = INT64_MIN; max = INT64_MAX; break;
    case PT_UINT64: max = UINT64_MAX; break;
    case PT_SINGLE:
    {
        float f;
        if (n->kind == 2) { f = (float)n->d; if (!(n->d == n->d) || fabs(n->d) > 3.4028234663852886e38 || (double)f != n->d) return E_PV_OVERFLOW; }
        else if (n->kind == 1) { f = (float)n->u; if (f >= 18446744073709551616.0f || (UINT64)f != n->u) return E_PV_OVERFLOW; }
        else { f = (float)n->i; if (f >= 9223372036854775808.0f || f < -9223372036854775808.0f || (INT64)f != n->i) return E_PV_OVERFLOW; }
        *(float *)dst = f;
        return S_OK;
    }
    case PT_DOUBLE:
    {
        double d;
        if (n->kind == 2) d = n->d;
        else if (n->kind == 1) { d = (double)n->u; if (d >= 18446744073709551616.0 || (UINT64)d != n->u) return E_PV_OVERFLOW; }
        else { d = (double)n->i; if (d >= 9223372036854775808.0 || d < -9223372036854775808.0 || (INT64)d != n->i) return E_PV_OVERFLOW; }
        *(double *)dst = d;
        return S_OK;
    }
    default: return E_PV_TYPEMISMATCH;
    }

    if (n->kind == 2)
    {
        double d = n->d;
        if (!(d == d) || d != floor(d)) return E_PV_OVERFLOW;
        if (d < 0)
        {
            if (min == 0 || d < (double)min) return E_PV_OVERFLOW;
            iv = (INT64)d;
        }
        else
        {
            if (d >= 18446744073709551616.0) return E_PV_OVERFLOW;
            uv = (UINT64)d;
            if (uv > max) return E_PV_OVERFLOW;
        }
    }
    else if (n->kind == 1)
    {
        if (n->u > max) return E_PV_OVERFLOW;
        uv = n->u;
    }
    else if (n->i < 0)
    {
        if (n->i < min) return E_PV_OVERFLOW;
        iv = n->i;
    }
    else
    {
        if ((UINT64)n->i > max) return E_PV_OVERFLOW;
        uv = (UINT64)n->i;
    }
    /* iv holds a negative value, otherwise uv the non-negative one */
    switch (type)
    {
    case PT_UINT8: *(UINT8 *)dst = (UINT8)uv; break;
    case PT_INT16: *(INT16 *)dst = (INT16)(iv < 0 ? iv : (INT64)uv); break;
    case PT_UINT16: *(UINT16 *)dst = (UINT16)uv; break;
    case PT_INT32: *(INT32 *)dst = (INT32)(iv < 0 ? iv : (INT64)uv); break;
    case PT_UINT32: *(UINT32 *)dst = (UINT32)uv; break;
    case PT_INT64: *(INT64 *)dst = iv < 0 ? iv : (INT64)uv; break;
    case PT_UINT64: *(UINT64 *)dst = uv; break;
    }
    return S_OK;
}

static HRESULT get_scalar_number(void *iface, int type, void *value)
{
    struct property_value *pv = impl_from_pv(iface);
    struct num n;

    if (!value) return E_POINTER;
    if (pv->is_array || !is_numeric_type(pv->type)) return E_PV_TYPEMISMATCH;
    read_num(pv->type, &pv->v, &n);
    return store_num(type, &n, value);
}

#define GET_NUM(name, ctype, tp) \
static HRESULT WINAPI pvi_Get##name(void *iface, ctype *value) { return get_scalar_number(iface, tp, value); }

GET_NUM(UInt8, UINT8, PT_UINT8)
GET_NUM(Int16, INT16, PT_INT16)
GET_NUM(UInt16, UINT16, PT_UINT16)
GET_NUM(Int32, INT32, PT_INT32)
GET_NUM(UInt32, UINT32, PT_UINT32)
GET_NUM(Int64, INT64, PT_INT64)
GET_NUM(UInt64, UINT64, PT_UINT64)
GET_NUM(Single, float, PT_SINGLE)
GET_NUM(Double, double, PT_DOUBLE)

static HRESULT WINAPI pvi_GetChar16(void *iface, WCHAR *value)
{
    struct property_value *pv = impl_from_pv(iface);

    if (!value) return E_POINTER;
    if (pv->is_array || pv->type != PT_CHAR16) return E_PV_TYPEMISMATCH;
    *value = pv->v.c16;
    return S_OK;
}

static HRESULT WINAPI pvi_GetBoolean(void *iface, BOOLEAN *value)
{
    struct property_value *pv = impl_from_pv(iface);

    if (!value) return E_POINTER;
    if (pv->is_array || pv->type != PT_BOOLEAN) return E_PV_TYPEMISMATCH;
    *value = pv->v.b;
    return S_OK;
}

static HRESULT WINAPI pvi_GetString(void *iface, HSTRING *value)
{
    struct property_value *pv = impl_from_pv(iface);

    if (!value) return E_POINTER;
    if (!pv->is_array && pv->type == PT_GUID)
    {
        /* measured: a Guid reads as its text, lower case digits without braces */
        WCHAR buf[40];
        const GUID *g = &pv->v.guid;
        static const WCHAR hex[] = L"0123456789abcdef";
        unsigned i, n = 0;

        for (i = 0; i < 16; i++)
        {
            BYTE b = i < 4 ? (BYTE)(g->Data1 >> (24 - 8 * i)) : i < 6 ? (BYTE)(g->Data2 >> (8 - 8 * (i - 4))) :
                     i < 8 ? (BYTE)(g->Data3 >> (8 - 8 * (i - 6))) : g->Data4[i - 8];
            if (i == 4 || i == 6 || i == 8 || i == 10) buf[n++] = L'-';
            buf[n++] = hex[b >> 4];
            buf[n++] = hex[b & 15];
        }
        return WindowsCreateString(buf, n, value);
    }
    if (pv->is_array || pv->type != PT_STRING) return E_PV_TYPEMISMATCH;
    return WindowsDuplicateString(pv->v.str, value);
}

#define GET_STRUCT(name, ctype, tp, field) \
static HRESULT WINAPI pvi_Get##name(void *iface, ctype *value) \
{ \
    struct property_value *pv = impl_from_pv(iface); \
    if (!value) return E_POINTER; \
    if (pv->is_array || pv->type != tp) return E_PV_TYPEMISMATCH; \
    *value = pv->v.field; \
    return S_OK; \
}

GET_STRUCT(Guid, GUID, PT_GUID, guid)
GET_STRUCT(DateTime, PV_DATETIME, PT_DATETIME, dt)
GET_STRUCT(TimeSpan, PV_TIMESPAN, PT_TIMESPAN, ts)
GET_STRUCT(Point, PV_POINT, PT_POINT, pt)
GET_STRUCT(Size, PV_SIZE, PT_SIZE, sz)
GET_STRUCT(Rect, PV_RECT, PT_RECT, rc)

/* Copies out the elements of an array of the given type (deep for strings and objects) with CoTaskMemAlloc */
static HRESULT copy_array_out(const struct property_value *pv, int type, UINT32 *size, void **out)
{
    UINT32 i, bytes;
    void *p = NULL;

    if (!size || !out) return E_POINTER;
    *size = 0;
    *out = NULL;
    if (!pv->is_array) return E_PV_TYPEMISMATCH;
    if (is_numeric_type(type) && is_numeric_type(pv->type) && pv->type != type)
    {
        /* element-wise exact conversion between the numeric array types (as for scalars) */
        UINT32 src_size = type_infos[pv->type].size;

        bytes = pv->count * type_infos[type].size;
        if (bytes && !(p = CoTaskMemAlloc(bytes))) return E_OUTOFMEMORY;
        for (i = 0; i < pv->count; i++)
        {
            struct num n;
            HRESULT hr;

            read_num(pv->type, (BYTE *)pv->v.arr + i * src_size, &n);
            if (FAILED(hr = store_num(type, &n, (BYTE *)p + i * type_infos[type].size)))
            {
                CoTaskMemFree(p);
                return hr;
            }
        }
        *size = pv->count;
        *out = p;
        return S_OK;
    }
    if (pv->type != type) return E_PV_TYPEMISMATCH;
    bytes = pv->count * type_infos[type].size;
    if (bytes && !(p = CoTaskMemAlloc(bytes))) return E_OUTOFMEMORY;
    if (type == PT_STRING)
    {
        memset(p, 0, bytes);
        for (i = 0; i < pv->count; i++)
        {
            HRESULT hr = WindowsDuplicateString(((HSTRING *)pv->v.arr)[i], &((HSTRING *)p)[i]);
            if (FAILED(hr))
            {
                while (i--) WindowsDeleteString(((HSTRING *)p)[i]);
                CoTaskMemFree(p);
                return hr;
            }
        }
    }
    else if (type == PT_INSPECTABLE)
    {
        for (i = 0; i < pv->count; i++)
        {
            IInspectable *o = ((IInspectable **)pv->v.arr)[i];
            ((IInspectable **)p)[i] = o;
            if (o) IInspectable_AddRef(o);
        }
    }
    else if (bytes)
        memcpy(p, pv->v.arr, bytes);
    *size = pv->count;
    *out = p;
    return S_OK;
}

#define GET_ARRAY(name, tp, ctype) \
static HRESULT WINAPI pvi_Get##name##Array(void *iface, UINT32 *size, ctype **value) \
{ \
    return copy_array_out(impl_from_pv(iface), tp, size, (void **)value); \
}

GET_ARRAY(UInt8, PT_UINT8, UINT8)
GET_ARRAY(Int16, PT_INT16, INT16)
GET_ARRAY(UInt16, PT_UINT16, UINT16)
GET_ARRAY(Int32, PT_INT32, INT32)
GET_ARRAY(UInt32, PT_UINT32, UINT32)
GET_ARRAY(Int64, PT_INT64, INT64)
GET_ARRAY(UInt64, PT_UINT64, UINT64)
GET_ARRAY(Single, PT_SINGLE, float)
GET_ARRAY(Double, PT_DOUBLE, double)
GET_ARRAY(Char16, PT_CHAR16, WCHAR)
GET_ARRAY(Boolean, PT_BOOLEAN, BOOLEAN)
GET_ARRAY(String, PT_STRING, HSTRING)
GET_ARRAY(Inspectable, PT_INSPECTABLE, IInspectable *)
GET_ARRAY(Guid, PT_GUID, GUID)
GET_ARRAY(DateTime, PT_DATETIME, PV_DATETIME)
GET_ARRAY(TimeSpan, PT_TIMESPAN, PV_TIMESPAN)
GET_ARRAY(Point, PT_POINT, PV_POINT)
GET_ARRAY(Size, PT_SIZE, PV_SIZE)
GET_ARRAY(Rect, PT_RECT, PV_RECT)

static const struct
{
    HRESULT (WINAPI *QueryInterface)(void *, REFIID, void **);
    ULONG (WINAPI *AddRef)(void *);
    ULONG (WINAPI *Release)(void *);
    HRESULT (WINAPI *GetIids)(void *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(void *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(void *, int *);
    HRESULT (WINAPI *get_Type)(void *, int *);
    HRESULT (WINAPI *get_IsNumericScalar)(void *, BOOLEAN *);
    HRESULT (WINAPI *GetUInt8)(void *, UINT8 *);
    HRESULT (WINAPI *GetInt16)(void *, INT16 *);
    HRESULT (WINAPI *GetUInt16)(void *, UINT16 *);
    HRESULT (WINAPI *GetInt32)(void *, INT32 *);
    HRESULT (WINAPI *GetUInt32)(void *, UINT32 *);
    HRESULT (WINAPI *GetInt64)(void *, INT64 *);
    HRESULT (WINAPI *GetUInt64)(void *, UINT64 *);
    HRESULT (WINAPI *GetSingle)(void *, float *);
    HRESULT (WINAPI *GetDouble)(void *, double *);
    HRESULT (WINAPI *GetChar16)(void *, WCHAR *);
    HRESULT (WINAPI *GetBoolean)(void *, BOOLEAN *);
    HRESULT (WINAPI *GetString)(void *, HSTRING *);
    HRESULT (WINAPI *GetGuid)(void *, GUID *);
    HRESULT (WINAPI *GetDateTime)(void *, PV_DATETIME *);
    HRESULT (WINAPI *GetTimeSpan)(void *, PV_TIMESPAN *);
    HRESULT (WINAPI *GetPoint)(void *, PV_POINT *);
    HRESULT (WINAPI *GetSize)(void *, PV_SIZE *);
    HRESULT (WINAPI *GetRect)(void *, PV_RECT *);
    HRESULT (WINAPI *GetUInt8Array)(void *, UINT32 *, UINT8 **);
    HRESULT (WINAPI *GetInt16Array)(void *, UINT32 *, INT16 **);
    HRESULT (WINAPI *GetUInt16Array)(void *, UINT32 *, UINT16 **);
    HRESULT (WINAPI *GetInt32Array)(void *, UINT32 *, INT32 **);
    HRESULT (WINAPI *GetUInt32Array)(void *, UINT32 *, UINT32 **);
    HRESULT (WINAPI *GetInt64Array)(void *, UINT32 *, INT64 **);
    HRESULT (WINAPI *GetUInt64Array)(void *, UINT32 *, UINT64 **);
    HRESULT (WINAPI *GetSingleArray)(void *, UINT32 *, float **);
    HRESULT (WINAPI *GetDoubleArray)(void *, UINT32 *, double **);
    HRESULT (WINAPI *GetChar16Array)(void *, UINT32 *, WCHAR **);
    HRESULT (WINAPI *GetBooleanArray)(void *, UINT32 *, BOOLEAN **);
    HRESULT (WINAPI *GetStringArray)(void *, UINT32 *, HSTRING **);
    HRESULT (WINAPI *GetInspectableArray)(void *, UINT32 *, IInspectable ***);
    HRESULT (WINAPI *GetGuidArray)(void *, UINT32 *, GUID **);
    HRESULT (WINAPI *GetDateTimeArray)(void *, UINT32 *, PV_DATETIME **);
    HRESULT (WINAPI *GetTimeSpanArray)(void *, UINT32 *, PV_TIMESPAN **);
    HRESULT (WINAPI *GetPointArray)(void *, UINT32 *, PV_POINT **);
    HRESULT (WINAPI *GetSizeArray)(void *, UINT32 *, PV_SIZE **);
    HRESULT (WINAPI *GetRectArray)(void *, UINT32 *, PV_RECT **);
} pv_vtbl =
{
    pvi_QueryInterface, pvi_AddRef, pvi_Release, pvi_GetIids, pvi_GetRuntimeClassName, pvi_GetTrustLevel,
    pvi_get_Type, pvi_get_IsNumericScalar,
    pvi_GetUInt8, pvi_GetInt16, pvi_GetUInt16, pvi_GetInt32, pvi_GetUInt32, pvi_GetInt64, pvi_GetUInt64,
    pvi_GetSingle, pvi_GetDouble, pvi_GetChar16, pvi_GetBoolean, pvi_GetString, pvi_GetGuid, pvi_GetDateTime,
    pvi_GetTimeSpan, pvi_GetPoint, pvi_GetSize, pvi_GetRect,
    pvi_GetUInt8Array, pvi_GetInt16Array, pvi_GetUInt16Array, pvi_GetInt32Array, pvi_GetUInt32Array,
    pvi_GetInt64Array, pvi_GetUInt64Array, pvi_GetSingleArray, pvi_GetDoubleArray, pvi_GetChar16Array,
    pvi_GetBooleanArray, pvi_GetStringArray, pvi_GetInspectableArray, pvi_GetGuidArray, pvi_GetDateTimeArray,
    pvi_GetTimeSpanArray, pvi_GetPointArray, pvi_GetSizeArray, pvi_GetRectArray,
};

/* ---- IReference<T> / IReferenceArray<T> ---- */

static HRESULT WINAPI ref_QueryInterface(void *iface, REFIID iid, void **out)
{
    return pv_query(impl_from_ref(iface), iid, out);
}
static ULONG WINAPI ref_AddRef(void *iface) { return InterlockedIncrement(&impl_from_ref(iface)->refcount); }
static ULONG WINAPI ref_Release(void *iface) { return pv_release_obj(impl_from_ref(iface)); }
static HRESULT WINAPI ref_GetIids(void *iface, ULONG *c, IID **i) { return pv_get_iids(impl_from_ref(iface), c, i); }
static HRESULT WINAPI ref_GetRuntimeClassName(void *iface, HSTRING *n) { return pv_get_class_name(impl_from_ref(iface), n); }
static HRESULT WINAPI ref_GetTrustLevel(void *iface, int *l) { return pv_get_trust(l); }

static HRESULT WINAPI ref_get_Value(void *iface, void *value)
{
    struct property_value *pv = impl_from_ref(iface);

    if (!value) return E_POINTER;
    switch (pv->type)
    {
    case PT_STRING: return WindowsDuplicateString(pv->v.str, value);
    case PT_INSPECTABLE:
        *(IInspectable **)value = pv->v.insp;
        if (pv->v.insp) IInspectable_AddRef(pv->v.insp);
        return S_OK;
    default:
        memcpy(value, &pv->v, type_infos[pv->type].size);
        return S_OK;
    }
}

static HRESULT WINAPI refarray_get_Value(void *iface, UINT32 *size, void **value)
{
    struct property_value *pv = impl_from_ref(iface);

    return copy_array_out(pv, pv->type, size, value);
}

static const struct
{
    HRESULT (WINAPI *QueryInterface)(void *, REFIID, void **);
    ULONG (WINAPI *AddRef)(void *);
    ULONG (WINAPI *Release)(void *);
    HRESULT (WINAPI *GetIids)(void *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(void *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(void *, int *);
    HRESULT (WINAPI *get_Value)(void *, void *);
} ref_vtbl = { ref_QueryInterface, ref_AddRef, ref_Release, ref_GetIids, ref_GetRuntimeClassName, ref_GetTrustLevel, ref_get_Value };

static const struct
{
    HRESULT (WINAPI *QueryInterface)(void *, REFIID, void **);
    ULONG (WINAPI *AddRef)(void *);
    ULONG (WINAPI *Release)(void *);
    HRESULT (WINAPI *GetIids)(void *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(void *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(void *, int *);
    HRESULT (WINAPI *get_Value)(void *, UINT32 *, void **);
} refarray_vtbl = { ref_QueryInterface, ref_AddRef, ref_Release, ref_GetIids, ref_GetRuntimeClassName, ref_GetTrustLevel, refarray_get_Value };

/* ---- construction ---- */

static HRESULT create_value(int type, const void *data, IInspectable **out)
{
    struct property_value *pv;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!(pv = calloc(1, sizeof(*pv)))) return E_OUTOFMEMORY;
    pv->lpVtbl = &pv_vtbl;
    pv->ref.lpVtbl = &ref_vtbl;
    pv->ref.owner = pv;
    pv->refcount = 1;
    pv->type = type;
    if (type == PT_STRING)
    {
        HRESULT hr = WindowsDuplicateString(*(HSTRING *)data, &pv->v.str);
        if (FAILED(hr)) { free(pv); return hr; }
    }
    else if (type == PT_INSPECTABLE)
    {
        pv->v.insp = *(IInspectable **)data;
        if (pv->v.insp) IInspectable_AddRef(pv->v.insp);
    }
    else if (type != PT_EMPTY)
        memcpy(&pv->v, data, type_infos[type].size);
    *out = (IInspectable *)pv;
    return S_OK;
}

static HRESULT create_array(int type, UINT32 count, const void *data, IInspectable **out)
{
    struct property_value *pv;
    UINT32 i, bytes;

    if (!out) return E_POINTER;
    *out = NULL;
    if (count && !data) return E_POINTER;
    if (count > UINT32_MAX / type_infos[type].size) return E_OUTOFMEMORY;
    if (!(pv = calloc(1, sizeof(*pv)))) return E_OUTOFMEMORY;
    bytes = count * type_infos[type].size;
    if (bytes && !(pv->v.arr = calloc(1, bytes))) { free(pv); return E_OUTOFMEMORY; }
    pv->lpVtbl = &pv_vtbl;
    pv->ref.lpVtbl = &refarray_vtbl;
    pv->ref.owner = pv;
    pv->refcount = 1;
    pv->type = type;
    pv->is_array = TRUE;
    pv->count = count;
    if (type == PT_STRING)
    {
        for (i = 0; i < count; i++)
        {
            HRESULT hr = WindowsDuplicateString(((HSTRING *)data)[i], &((HSTRING *)pv->v.arr)[i]);
            if (FAILED(hr)) { pv->count = i; pv_release_obj(pv); return hr; }
        }
    }
    else if (type == PT_INSPECTABLE)
    {
        for (i = 0; i < count; i++)
        {
            IInspectable *o = ((IInspectable **)data)[i];
            ((IInspectable **)pv->v.arr)[i] = o;
            if (o) IInspectable_AddRef(o);
        }
    }
    else if (bytes)
        memcpy(pv->v.arr, data, bytes);
    *out = (IInspectable *)pv;
    return S_OK;
}

/* ---- IPropertyValueStatics, IActivationFactory ---- */

struct pv_factory
{
    const void *lpVtbl;             /* IPropertyValueStatics */
    const void *afVtbl;             /* IActivationFactory */
};

static struct pv_factory factory;

static HRESULT WINAPI fac_QueryInterface(void *iface, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_PV_IUnknown) || IsEqualGUID(iid, &IID_PV_IInspectable) || IsEqualGUID(iid, &IID_PV_IAgileObject)
        || IsEqualGUID(iid, &IID_PV_IActivationFactory))
        *out = &factory.afVtbl;
    else if (IsEqualGUID(iid, &IID_PV_IPropertyValueStatics))
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

    if (!count || !iids) return E_POINTER;
    if (!(p = CoTaskMemAlloc(sizeof(IID)))) return E_OUTOFMEMORY;
    p[0] = IID_PV_IPropertyValueStatics;
    *count = 1;
    *iids = p;
    return S_OK;
}
static HRESULT WINAPI fac_GetRuntimeClassName(void *iface, HSTRING *name)
{
    if (!name) return E_POINTER;
    return WindowsCreateString(L"Windows.Foundation.PropertyValue", 32, name);
}
static HRESULT WINAPI fac_GetTrustLevel(void *iface, int *level) { return pv_get_trust(level); }
static HRESULT WINAPI fac_ActivateInstance(void *iface, IInspectable **instance)
{
    if (instance) *instance = NULL;
    return E_NOTIMPL;
}

/* Measured: the empty value is a NULL object */
static HRESULT WINAPI st_CreateEmpty(void *iface, IInspectable **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    return S_OK;
}

/* Measured: the object itself (no wrapper), E_INVALIDARG for NULL */
static HRESULT WINAPI st_CreateInspectable(void *iface, IInspectable *value, IInspectable **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!value) return E_INVALIDARG;
    IInspectable_AddRef(value);
    *out = value;
    return S_OK;
}

#define CREATE(name, ctype, tp) \
static HRESULT WINAPI st_Create##name(void *iface, ctype value, IInspectable **out) \
{ \
    return create_value(tp, &value, out); \
}

CREATE(UInt8, UINT8, PT_UINT8)
CREATE(Int16, INT16, PT_INT16)
CREATE(UInt16, UINT16, PT_UINT16)
CREATE(Int32, INT32, PT_INT32)
CREATE(UInt32, UINT32, PT_UINT32)
CREATE(Int64, INT64, PT_INT64)
CREATE(UInt64, UINT64, PT_UINT64)
CREATE(Single, float, PT_SINGLE)
CREATE(Double, double, PT_DOUBLE)
CREATE(Char16, WCHAR, PT_CHAR16)
CREATE(Boolean, BOOLEAN, PT_BOOLEAN)
CREATE(String, HSTRING, PT_STRING)
CREATE(Guid, GUID, PT_GUID)
CREATE(DateTime, PV_DATETIME, PT_DATETIME)
CREATE(TimeSpan, PV_TIMESPAN, PT_TIMESPAN)
CREATE(Point, PV_POINT, PT_POINT)
CREATE(Size, PV_SIZE, PT_SIZE)
CREATE(Rect, PV_RECT, PT_RECT)

#define CREATE_ARRAY(name, ctype, tp) \
static HRESULT WINAPI st_Create##name##Array(void *iface, UINT32 size, ctype *value, IInspectable **out) \
{ \
    return create_array(tp, size, value, out); \
}

CREATE_ARRAY(UInt8, UINT8, PT_UINT8)
CREATE_ARRAY(Int16, INT16, PT_INT16)
CREATE_ARRAY(UInt16, UINT16, PT_UINT16)
CREATE_ARRAY(Int32, INT32, PT_INT32)
CREATE_ARRAY(UInt32, UINT32, PT_UINT32)
CREATE_ARRAY(Int64, INT64, PT_INT64)
CREATE_ARRAY(UInt64, UINT64, PT_UINT64)
CREATE_ARRAY(Single, float, PT_SINGLE)
CREATE_ARRAY(Double, double, PT_DOUBLE)
CREATE_ARRAY(Char16, WCHAR, PT_CHAR16)
CREATE_ARRAY(Boolean, BOOLEAN, PT_BOOLEAN)
CREATE_ARRAY(String, HSTRING, PT_STRING)
CREATE_ARRAY(Inspectable, IInspectable *, PT_INSPECTABLE)
CREATE_ARRAY(Guid, GUID, PT_GUID)
CREATE_ARRAY(DateTime, PV_DATETIME, PT_DATETIME)
CREATE_ARRAY(TimeSpan, PV_TIMESPAN, PT_TIMESPAN)
CREATE_ARRAY(Point, PV_POINT, PT_POINT)
CREATE_ARRAY(Size, PV_SIZE, PT_SIZE)
CREATE_ARRAY(Rect, PV_RECT, PT_RECT)

static const struct
{
    HRESULT (WINAPI *QueryInterface)(void *, REFIID, void **);
    ULONG (WINAPI *AddRef)(void *);
    ULONG (WINAPI *Release)(void *);
    HRESULT (WINAPI *GetIids)(void *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(void *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(void *, int *);
    HRESULT (WINAPI *CreateEmpty)(void *, IInspectable **);
    HRESULT (WINAPI *CreateUInt8)(void *, UINT8, IInspectable **);
    HRESULT (WINAPI *CreateInt16)(void *, INT16, IInspectable **);
    HRESULT (WINAPI *CreateUInt16)(void *, UINT16, IInspectable **);
    HRESULT (WINAPI *CreateInt32)(void *, INT32, IInspectable **);
    HRESULT (WINAPI *CreateUInt32)(void *, UINT32, IInspectable **);
    HRESULT (WINAPI *CreateInt64)(void *, INT64, IInspectable **);
    HRESULT (WINAPI *CreateUInt64)(void *, UINT64, IInspectable **);
    HRESULT (WINAPI *CreateSingle)(void *, float, IInspectable **);
    HRESULT (WINAPI *CreateDouble)(void *, double, IInspectable **);
    HRESULT (WINAPI *CreateChar16)(void *, WCHAR, IInspectable **);
    HRESULT (WINAPI *CreateBoolean)(void *, BOOLEAN, IInspectable **);
    HRESULT (WINAPI *CreateString)(void *, HSTRING, IInspectable **);
    HRESULT (WINAPI *CreateInspectable)(void *, IInspectable *, IInspectable **);
    HRESULT (WINAPI *CreateGuid)(void *, GUID, IInspectable **);
    HRESULT (WINAPI *CreateDateTime)(void *, PV_DATETIME, IInspectable **);
    HRESULT (WINAPI *CreateTimeSpan)(void *, PV_TIMESPAN, IInspectable **);
    HRESULT (WINAPI *CreatePoint)(void *, PV_POINT, IInspectable **);
    HRESULT (WINAPI *CreateSize)(void *, PV_SIZE, IInspectable **);
    HRESULT (WINAPI *CreateRect)(void *, PV_RECT, IInspectable **);
    HRESULT (WINAPI *CreateUInt8Array)(void *, UINT32, UINT8 *, IInspectable **);
    HRESULT (WINAPI *CreateInt16Array)(void *, UINT32, INT16 *, IInspectable **);
    HRESULT (WINAPI *CreateUInt16Array)(void *, UINT32, UINT16 *, IInspectable **);
    HRESULT (WINAPI *CreateInt32Array)(void *, UINT32, INT32 *, IInspectable **);
    HRESULT (WINAPI *CreateUInt32Array)(void *, UINT32, UINT32 *, IInspectable **);
    HRESULT (WINAPI *CreateInt64Array)(void *, UINT32, INT64 *, IInspectable **);
    HRESULT (WINAPI *CreateUInt64Array)(void *, UINT32, UINT64 *, IInspectable **);
    HRESULT (WINAPI *CreateSingleArray)(void *, UINT32, float *, IInspectable **);
    HRESULT (WINAPI *CreateDoubleArray)(void *, UINT32, double *, IInspectable **);
    HRESULT (WINAPI *CreateChar16Array)(void *, UINT32, WCHAR *, IInspectable **);
    HRESULT (WINAPI *CreateBooleanArray)(void *, UINT32, BOOLEAN *, IInspectable **);
    HRESULT (WINAPI *CreateStringArray)(void *, UINT32, HSTRING *, IInspectable **);
    HRESULT (WINAPI *CreateInspectableArray)(void *, UINT32, IInspectable **, IInspectable **);
    HRESULT (WINAPI *CreateGuidArray)(void *, UINT32, GUID *, IInspectable **);
    HRESULT (WINAPI *CreateDateTimeArray)(void *, UINT32, PV_DATETIME *, IInspectable **);
    HRESULT (WINAPI *CreateTimeSpanArray)(void *, UINT32, PV_TIMESPAN *, IInspectable **);
    HRESULT (WINAPI *CreatePointArray)(void *, UINT32, PV_POINT *, IInspectable **);
    HRESULT (WINAPI *CreateSizeArray)(void *, UINT32, PV_SIZE *, IInspectable **);
    HRESULT (WINAPI *CreateRectArray)(void *, UINT32, PV_RECT *, IInspectable **);
} statics_vtbl =
{
    fac_QueryInterface, fac_AddRef, fac_Release, fac_GetIids, fac_GetRuntimeClassName, fac_GetTrustLevel,
    st_CreateEmpty, st_CreateUInt8, st_CreateInt16, st_CreateUInt16, st_CreateInt32, st_CreateUInt32, st_CreateInt64,
    st_CreateUInt64, st_CreateSingle, st_CreateDouble, st_CreateChar16, st_CreateBoolean, st_CreateString,
    st_CreateInspectable, st_CreateGuid, st_CreateDateTime, st_CreateTimeSpan, st_CreatePoint, st_CreateSize, st_CreateRect,
    st_CreateUInt8Array, st_CreateInt16Array, st_CreateUInt16Array, st_CreateInt32Array, st_CreateUInt32Array,
    st_CreateInt64Array, st_CreateUInt64Array, st_CreateSingleArray, st_CreateDoubleArray, st_CreateChar16Array,
    st_CreateBooleanArray, st_CreateStringArray, st_CreateInspectableArray, st_CreateGuidArray, st_CreateDateTimeArray,
    st_CreateTimeSpanArray, st_CreatePointArray, st_CreateSizeArray, st_CreateRectArray,
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
} af_vtbl = { fac_QueryInterface, fac_AddRef, fac_Release, fac_GetIids, fac_GetRuntimeClassName, fac_GetTrustLevel,
              fac_ActivateInstance };

static struct pv_factory factory = { &statics_vtbl, &af_vtbl };

/* The activation factory of Windows.Foundation.PropertyValue */
HRESULT pv_get_activation_factory(HSTRING classid, IActivationFactory **out)
{
    if (!out) return E_POINTER;
    if (!classid) { *out = NULL; return E_INVALIDARG; }
    if (_wcsicmp(WindowsGetStringRawBuffer(classid, NULL), L"Windows.Foundation.PropertyValue"))
        return CLASS_E_CLASSNOTAVAILABLE;
    *out = (IActivationFactory *)&factory.afVtbl;
    return S_OK;
}
