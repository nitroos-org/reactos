/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The legacy (Windows XP/Vista) firewall automation objects on top of the rule store:
 *              INetFwMgr, INetFwProfile, INetFwAuthorizedApplications / INetFwAuthorizedApplication,
 *              INetFwOpenPorts / INetFwOpenPort and INetFwServices / INetFwService.
 *
 * Old installers add an authorized application or open a port through these interfaces. Each entry becomes
 * one inbound Allow rule in the same store INetFwPolicy2 and netsh use (FirewallPolicy\FirewallRules), so
 * the rule is enforced by the kernel filter and visible to "netsh advfirewall firewall show rule". An entry
 * created here carries the private token Legacy=App or Legacy=Port: the collections list and remove only
 * those rules, never the rules of INetFwPolicy2 or netsh.
 *
 * The legacy profile types map to the store's profile bits: DOMAIN = Domain, STANDARD = Private + Public.
 *
 * Not verified on a Windows reference machine (only the interface contracts are from the documentation):
 * the error codes of Add of an entry that exists (here: the entry is replaced, S_OK) and of Remove of an entry
 * that does not exist (here: S_OK). Item of a missing entry returns HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND).
 */

#include <stdarg.h>
#include <stdio.h>

#define COBJMACROS

#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "ole2.h"
#include "netfw.h"
#include "winnetwk.h"

#include "wine/debug.h"
#include "hnetcfg_private.h"
#include <fwstore.h>

WINE_DEFAULT_DEBUG_CHANNEL(hnetcfg);

#define LG_TOKEN  L"Legacy"
#define LG_APP    L"App"
#define LG_PORT   L"Port"
#define LG_IPVER  L"LegacyIpV"

static HRESULT hr_win32(DWORD e) { return e ? HRESULT_FROM_WIN32(e) : S_OK; }

/* ------------------------------------------------------------------ profile mapping */

NET_FW_PROFILE_TYPE legacy_current_type(void)
{
    return FwCurrentProfiles() == FWP_DOMAIN ? NET_FW_PROFILE_DOMAIN : NET_FW_PROFILE_STANDARD;
}

LONG legacy_profile_bits(NET_FW_PROFILE_TYPE type)
{
    if (type == NET_FW_PROFILE_CURRENT) type = legacy_current_type();
    return type == NET_FW_PROFILE_DOMAIN ? FWP_DOMAIN : (FWP_PRIVATE | FWP_PUBLIC);
}

/* the single store profile that stands for the settings of a legacy profile */
static ULONG primary_bit(LONG bits)
{
    ULONG cur;
    if (bits == FWP_DOMAIN) return FWP_DOMAIN;
    cur = FwCurrentProfiles();
    return cur == FWP_PUBLIC ? FWP_PUBLIC : FWP_PRIVATE;
}

/* ------------------------------------------------------------------ IDispatch boilerplate */

#define DISPATCH_IMPL(prefix, Iface, tid) \
static HRESULT WINAPI prefix##_GetTypeInfoCount(Iface *iface, UINT *pctinfo) \
{ if (!pctinfo) return E_POINTER; *pctinfo = 1; return S_OK; } \
static HRESULT WINAPI prefix##_GetTypeInfo(Iface *iface, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) \
{ if (!ppTInfo) return E_POINTER; if (iTInfo) { *ppTInfo = NULL; return DISP_E_BADINDEX; } return get_typeinfo(tid, ppTInfo); } \
static HRESULT WINAPI prefix##_GetIDsOfNames(Iface *iface, REFIID riid, LPOLESTR *rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) \
{ ITypeInfo *ti; HRESULT hr = get_typeinfo(tid, &ti); \
  if (SUCCEEDED(hr)) { hr = ITypeInfo_GetIDsOfNames(ti, rgszNames, cNames, rgDispId); ITypeInfo_Release(ti); } return hr; } \
static HRESULT WINAPI prefix##_Invoke(Iface *iface, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, \
        DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) \
{ ITypeInfo *ti; HRESULT hr = get_typeinfo(tid, &ti); \
  if (SUCCEEDED(hr)) { hr = ITypeInfo_Invoke(ti, iface, dispIdMember, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr); \
                       ITypeInfo_Release(ti); } return hr; }

static HRESULT get_bstr(const WCHAR *v, BSTR *out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!v) return S_OK;
    *out = SysAllocString(v);
    return *out ? S_OK : E_OUTOFMEMORY;
}

/* ------------------------------------------------------------------ enumerator over a list of dispatch objects */

typedef struct legacy_enum
{
    IEnumVARIANT IEnumVARIANT_iface;
    LONG refs;
    IDispatch **items;
    ULONG count, pos;
} legacy_enum;

static inline legacy_enum *impl_from_IEnumVARIANT(IEnumVARIANT *iface)
{
    return CONTAINING_RECORD(iface, legacy_enum, IEnumVARIANT_iface);
}

static HRESULT WINAPI legacy_enum_QueryInterface(IEnumVARIANT *iface, REFIID riid, void **obj)
{
    if (!obj) return E_POINTER;
    if (IsEqualGUID(riid, &IID_IEnumVARIANT) || IsEqualGUID(riid, &IID_IUnknown))
    {
        *obj = iface;
        IEnumVARIANT_AddRef(iface);
        return S_OK;
    }
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI legacy_enum_AddRef(IEnumVARIANT *iface)
{
    return InterlockedIncrement(&impl_from_IEnumVARIANT(iface)->refs);
}

static ULONG WINAPI legacy_enum_Release(IEnumVARIANT *iface)
{
    legacy_enum *This = impl_from_IEnumVARIANT(iface);
    LONG refs = InterlockedDecrement(&This->refs);
    if (!refs)
    {
        ULONG i;
        for (i = 0; i < This->count; i++) IDispatch_Release(This->items[i]);
        free(This->items);
        free(This);
    }
    return refs;
}

static HRESULT WINAPI legacy_enum_Next(IEnumVARIANT *iface, ULONG celt, VARIANT *rgVar, ULONG *fetched)
{
    legacy_enum *This = impl_from_IEnumVARIANT(iface);
    ULONG n = 0;

    if (!rgVar) return E_POINTER;
    while (n < celt && This->pos < This->count)
    {
        VariantInit(&rgVar[n]);
        V_VT(&rgVar[n]) = VT_DISPATCH;
        V_DISPATCH(&rgVar[n]) = This->items[This->pos++];
        IDispatch_AddRef(V_DISPATCH(&rgVar[n]));
        n++;
    }
    if (fetched) *fetched = n;
    return n == celt ? S_OK : S_FALSE;
}

static HRESULT WINAPI legacy_enum_Skip(IEnumVARIANT *iface, ULONG celt)
{
    legacy_enum *This = impl_from_IEnumVARIANT(iface);
    if (celt > This->count - This->pos) { This->pos = This->count; return S_FALSE; }
    This->pos += celt;
    return S_OK;
}

static HRESULT WINAPI legacy_enum_Reset(IEnumVARIANT *iface)
{
    impl_from_IEnumVARIANT(iface)->pos = 0;
    return S_OK;
}

static HRESULT legacy_enum_create(IDispatch **items, ULONG count, IUnknown **out);

static HRESULT WINAPI legacy_enum_Clone(IEnumVARIANT *iface, IEnumVARIANT **out)
{
    legacy_enum *This = impl_from_IEnumVARIANT(iface);
    IDispatch **copy;
    IUnknown *unk;
    ULONG i;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;
    copy = calloc(This->count ? This->count : 1, sizeof(*copy));
    if (!copy) return E_OUTOFMEMORY;
    for (i = 0; i < This->count; i++) { copy[i] = This->items[i]; IDispatch_AddRef(copy[i]); }
    hr = legacy_enum_create(copy, This->count, &unk);
    if (FAILED(hr)) return hr;
    impl_from_IEnumVARIANT((IEnumVARIANT *)unk)->pos = This->pos;
    *out = (IEnumVARIANT *)unk;
    return S_OK;
}

static const IEnumVARIANTVtbl legacy_enum_vtbl =
{
    legacy_enum_QueryInterface, legacy_enum_AddRef, legacy_enum_Release,
    legacy_enum_Next, legacy_enum_Skip, legacy_enum_Reset, legacy_enum_Clone
};

/* takes over the array and the references in it (also on failure) */
static HRESULT legacy_enum_create(IDispatch **items, ULONG count, IUnknown **out)
{
    legacy_enum *e = calloc(1, sizeof(*e));
    if (!e)
    {
        ULONG i;
        for (i = 0; i < count; i++) IDispatch_Release(items[i]);
        free(items);
        return E_OUTOFMEMORY;
    }
    e->IEnumVARIANT_iface.lpVtbl = &legacy_enum_vtbl;
    e->refs = 1;
    e->items = items;
    e->count = count;
    *out = (IUnknown *)&e->IEnumVARIANT_iface;
    return S_OK;
}

/* ------------------------------------------------------------------ scope helpers shared by the entries */

static NET_FW_SCOPE rule_scope(const FW_RULE *r)
{
    if (!r->RAddr || !*r->RAddr || !wcscmp(r->RAddr, L"*")) return NET_FW_SCOPE_ALL;
    if (!_wcsicmp(r->RAddr, L"LocalSubnet")) return NET_FW_SCOPE_LOCAL_SUBNET;
    return NET_FW_SCOPE_CUSTOM;
}

static HRESULT rule_put_scope(FW_RULE *r, NET_FW_SCOPE scope)
{
    switch (scope)
    {
    case NET_FW_SCOPE_ALL: return FwRuleSetStr(&r->RAddr, NULL) ? S_OK : E_OUTOFMEMORY;
    case NET_FW_SCOPE_LOCAL_SUBNET: return FwRuleSetStr(&r->RAddr, L"LocalSubnet") ? S_OK : E_OUTOFMEMORY;
    case NET_FW_SCOPE_CUSTOM: return S_OK;   /* the addresses come with RemoteAddresses */
    default: return E_INVALIDARG;
    }
}

static HRESULT rule_get_raddr(const FW_RULE *r, BSTR *out)
{
    if (!out) return E_POINTER;
    return get_bstr(rule_scope(r) == NET_FW_SCOPE_ALL ? L"*" : r->RAddr, out);
}

static HRESULT rule_put_raddr(FW_RULE *r, BSTR v)
{
    if (!v) return E_INVALIDARG;
    if (*v && wcscmp(v, L"*"))
    {
        if (wcschr(v, L'|') || FwCheckAddrs(v)) return E_INVALIDARG;
        return FwRuleSetStr(&r->RAddr, v) ? S_OK : E_OUTOFMEMORY;
    }
    return FwRuleSetStr(&r->RAddr, NULL) ? S_OK : E_OUTOFMEMORY;
}

static NET_FW_IP_VERSION rule_ipver(const FW_RULE *r)
{
    PCWSTR v = FwrGet(&r->Raw, LG_IPVER, 0);
    int n = v ? _wtoi(v) : NET_FW_IP_VERSION_ANY;
    return (n >= 0 && n < NET_FW_IP_VERSION_MAX) ? n : NET_FW_IP_VERSION_ANY;
}

static HRESULT rule_put_ipver(FW_RULE *r, NET_FW_IP_VERSION ver)
{
    WCHAR num[8];
    if (ver < 0 || ver >= NET_FW_IP_VERSION_MAX) return E_INVALIDARG;
    _swprintf(num, L"%d", (int)ver);
    return FwrSet(&r->Raw, LG_IPVER, num) ? S_OK : E_OUTOFMEMORY;
}

static BOOL is_entry(const FW_RULE *r, PCWSTR kind, LONG profiles)
{
    PCWSTR v = FwrGet(&r->Raw, LG_TOKEN, 0);
    return v && !wcscmp(v, kind) && r->Profiles == profiles;
}

/* ------------------------------------------------------------------ INetFwAuthorizedApplication */

typedef struct fw_app
{
    INetFwAuthorizedApplication INetFwAuthorizedApplication_iface;
    LONG refs;
    FW_RULE r;
    BOOL stored;    /* bound to a rule in the store: property writes are committed at once */
} fw_app;

static const struct INetFwAuthorizedApplicationVtbl fw_app_vtbl;

static inline fw_app *impl_from_INetFwAuthorizedApplication(INetFwAuthorizedApplication *iface)
{
    return CONTAINING_RECORD(iface, fw_app, INetFwAuthorizedApplication_iface);
}

static HRESULT app_commit(fw_app *This)
{
    if (!This->stored) return S_OK;
    return hr_win32(FwStoreUpdate(&This->r));
}

static ULONG WINAPI fw_app_AddRef(INetFwAuthorizedApplication *iface)
{
    return InterlockedIncrement(&impl_from_INetFwAuthorizedApplication(iface)->refs);
}

static ULONG WINAPI fw_app_Release(INetFwAuthorizedApplication *iface)
{
    fw_app *This = impl_from_INetFwAuthorizedApplication(iface);
    LONG refs = InterlockedDecrement(&This->refs);
    if (!refs)
    {
        TRACE("destroying %p\n", This);
        FwRuleFree(&This->r);
        free(This);
    }
    return refs;
}

static HRESULT WINAPI fw_app_QueryInterface(INetFwAuthorizedApplication *iface, REFIID riid, void **ppvObject)
{
    TRACE("%p %s %p\n", iface, debugstr_guid(riid), ppvObject);
    if (!ppvObject) return E_POINTER;
    if (IsEqualGUID(riid, &IID_INetFwAuthorizedApplication) || IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IUnknown))
        *ppvObject = iface;
    else
    {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }
    INetFwAuthorizedApplication_AddRef(iface);
    return S_OK;
}

DISPATCH_IMPL(fw_app, INetFwAuthorizedApplication, INetFwAuthorizedApplication_tid)

static HRESULT WINAPI fw_app_get_Name(INetFwAuthorizedApplication *iface, BSTR *name)
{
    return get_bstr(impl_from_INetFwAuthorizedApplication(iface)->r.Name, name);
}

static HRESULT set_name(FW_RULE *r, BSTR name)
{
    if (!name || !*name || wcschr(name, L'|')) return E_INVALIDARG;
    return FwRuleSetStr(&r->Name, name) ? S_OK : E_OUTOFMEMORY;
}

static HRESULT WINAPI fw_app_put_Name(INetFwAuthorizedApplication *iface, BSTR name)
{
    fw_app *This = impl_from_INetFwAuthorizedApplication(iface);
    HRESULT hr = set_name(&This->r, name);
    return SUCCEEDED(hr) ? app_commit(This) : hr;
}

static HRESULT WINAPI fw_app_get_ProcessImageFileName(INetFwAuthorizedApplication *iface, BSTR *imageFileName)
{
    return get_bstr(impl_from_INetFwAuthorizedApplication(iface)->r.App, imageFileName);
}

/* the path as the collection stores it: the UNC name of a mapped drive, else the full long path */
static HRESULT normalize_image(const WCHAR *image, WCHAR **out)
{
    DWORD sz = 0, res, longsz;
    WCHAR *path, *new_path;

    *out = NULL;
    if (!image || !image[0]) return E_INVALIDARG;

    res = WNetGetUniversalNameW(image, UNIVERSAL_NAME_INFO_LEVEL, NULL, &sz);
    if (res == WN_MORE_DATA)
    {
        BYTE *buf = malloc(sz);
        if (!buf) return E_OUTOFMEMORY;
        res = WNetGetUniversalNameW(image, UNIVERSAL_NAME_INFO_LEVEL, buf, &sz);
        if (res == NO_ERROR)
        {
            const WCHAR *unc = ((UNIVERSAL_NAME_INFOW *)buf)->lpUniversalName;
            *out = _wcsdup(unc);
            free(buf);
            return *out ? S_OK : E_OUTOFMEMORY;
        }
        free(buf);
        return HRESULT_FROM_WIN32(res);
    }

    sz = GetFullPathNameW(image, 0, NULL, NULL);
    if (!sz) return HRESULT_FROM_WIN32(GetLastError());
    if (!(path = malloc(++sz * sizeof(WCHAR)))) return E_OUTOFMEMORY;
    GetFullPathNameW(image, sz, path, NULL);

    longsz = GetLongPathNameW(path, path, sz);
    if (longsz > sz)
    {
        if (!(new_path = realloc(path, longsz * sizeof(WCHAR)))) { free(path); return E_OUTOFMEMORY; }
        path = new_path;
        GetLongPathNameW(path, path, longsz);
    }
    *out = path;
    return S_OK;
}

static HRESULT WINAPI fw_app_put_ProcessImageFileName(INetFwAuthorizedApplication *iface, BSTR image)
{
    fw_app *This = impl_from_INetFwAuthorizedApplication(iface);
    WCHAR *path;
    HRESULT hr;

    TRACE("%p, %s\n", This, debugstr_w(image));

    hr = normalize_image(image, &path);
    if (FAILED(hr)) return hr;
    if (wcschr(path, L'|')) { free(path); return E_INVALIDARG; }
    hr = FwRuleSetStr(&This->r.App, path) ? S_OK : E_OUTOFMEMORY;
    free(path);
    return SUCCEEDED(hr) ? app_commit(This) : hr;
}

static HRESULT WINAPI fw_app_get_IpVersion(INetFwAuthorizedApplication *iface, NET_FW_IP_VERSION *ipVersion)
{
    if (!ipVersion) return E_POINTER;
    *ipVersion = rule_ipver(&impl_from_INetFwAuthorizedApplication(iface)->r);
    return S_OK;
}

static HRESULT WINAPI fw_app_put_IpVersion(INetFwAuthorizedApplication *iface, NET_FW_IP_VERSION ipVersion)
{
    fw_app *This = impl_from_INetFwAuthorizedApplication(iface);
    HRESULT hr = rule_put_ipver(&This->r, ipVersion);
    return SUCCEEDED(hr) ? app_commit(This) : hr;
}

static HRESULT WINAPI fw_app_get_Scope(INetFwAuthorizedApplication *iface, NET_FW_SCOPE *scope)
{
    if (!scope) return E_POINTER;
    *scope = rule_scope(&impl_from_INetFwAuthorizedApplication(iface)->r);
    return S_OK;
}

static HRESULT WINAPI fw_app_put_Scope(INetFwAuthorizedApplication *iface, NET_FW_SCOPE scope)
{
    fw_app *This = impl_from_INetFwAuthorizedApplication(iface);
    HRESULT hr = rule_put_scope(&This->r, scope);
    return SUCCEEDED(hr) ? app_commit(This) : hr;
}

static HRESULT WINAPI fw_app_get_RemoteAddresses(INetFwAuthorizedApplication *iface, BSTR *remoteAddrs)
{
    return rule_get_raddr(&impl_from_INetFwAuthorizedApplication(iface)->r, remoteAddrs);
}

static HRESULT WINAPI fw_app_put_RemoteAddresses(INetFwAuthorizedApplication *iface, BSTR remoteAddrs)
{
    fw_app *This = impl_from_INetFwAuthorizedApplication(iface);
    HRESULT hr = rule_put_raddr(&This->r, remoteAddrs);
    return SUCCEEDED(hr) ? app_commit(This) : hr;
}

static HRESULT WINAPI fw_app_get_Enabled(INetFwAuthorizedApplication *iface, VARIANT_BOOL *enabled)
{
    if (!enabled) return E_POINTER;
    *enabled = impl_from_INetFwAuthorizedApplication(iface)->r.Enabled ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI fw_app_put_Enabled(INetFwAuthorizedApplication *iface, VARIANT_BOOL enabled)
{
    fw_app *This = impl_from_INetFwAuthorizedApplication(iface);
    This->r.Enabled = enabled != VARIANT_FALSE;
    return app_commit(This);
}

static const struct INetFwAuthorizedApplicationVtbl fw_app_vtbl =
{
    fw_app_QueryInterface, fw_app_AddRef, fw_app_Release,
    fw_app_GetTypeInfoCount, fw_app_GetTypeInfo, fw_app_GetIDsOfNames, fw_app_Invoke,
    fw_app_get_Name, fw_app_put_Name,
    fw_app_get_ProcessImageFileName, fw_app_put_ProcessImageFileName,
    fw_app_get_IpVersion, fw_app_put_IpVersion,
    fw_app_get_Scope, fw_app_put_Scope,
    fw_app_get_RemoteAddresses, fw_app_put_RemoteAddresses,
    fw_app_get_Enabled, fw_app_put_Enabled
};

HRESULT NetFwAuthorizedApplication_create(IUnknown *pUnkOuter, LPVOID *ppObj)
{
    fw_app *fa;

    TRACE("(%p,%p)\n", pUnkOuter, ppObj);

    fa = calloc(1, sizeof(*fa));
    if (!fa) return E_OUTOFMEMORY;
    fa->INetFwAuthorizedApplication_iface.lpVtbl = &fw_app_vtbl;
    fa->refs = 1;
    FwRuleInit(&fa->r);
    fa->r.Enabled = TRUE;
    *ppObj = &fa->INetFwAuthorizedApplication_iface;
    return S_OK;
}

static HRESULT app_from_store(const FW_RULE *src, INetFwAuthorizedApplication **out)
{
    INetFwAuthorizedApplication *iface;
    fw_app *impl;
    HRESULT hr = NetFwAuthorizedApplication_create(NULL, (void **)&iface);
    if (FAILED(hr)) return hr;
    impl = impl_from_INetFwAuthorizedApplication(iface);
    FwRuleFree(&impl->r);
    FwRuleInit(&impl->r);
    if (!FwRuleCopy(&impl->r, src)) { INetFwAuthorizedApplication_Release(iface); return E_OUTOFMEMORY; }
    impl->stored = TRUE;
    *out = iface;
    return S_OK;
}

/* ------------------------------------------------------------------ INetFwAuthorizedApplications */

typedef struct fw_apps
{
    INetFwAuthorizedApplications INetFwAuthorizedApplications_iface;
    LONG refs;
    LONG profiles;
} fw_apps;

static inline fw_apps *impl_from_INetFwAuthorizedApplications(INetFwAuthorizedApplications *iface)
{
    return CONTAINING_RECORD(iface, fw_apps, INetFwAuthorizedApplications_iface);
}

static ULONG WINAPI fw_apps_AddRef(INetFwAuthorizedApplications *iface)
{
    return InterlockedIncrement(&impl_from_INetFwAuthorizedApplications(iface)->refs);
}

static ULONG WINAPI fw_apps_Release(INetFwAuthorizedApplications *iface)
{
    fw_apps *This = impl_from_INetFwAuthorizedApplications(iface);
    LONG refs = InterlockedDecrement(&This->refs);
    if (!refs) free(This);
    return refs;
}

static HRESULT WINAPI fw_apps_QueryInterface(INetFwAuthorizedApplications *iface, REFIID riid, void **ppvObject)
{
    TRACE("%p %s %p\n", iface, debugstr_guid(riid), ppvObject);
    if (!ppvObject) return E_POINTER;
    if (IsEqualGUID(riid, &IID_INetFwAuthorizedApplications) || IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IUnknown))
        *ppvObject = iface;
    else
    {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }
    INetFwAuthorizedApplications_AddRef(iface);
    return S_OK;
}

DISPATCH_IMPL(fw_apps, INetFwAuthorizedApplications, INetFwAuthorizedApplications_tid)

static HRESULT WINAPI fw_apps_get_Count(INetFwAuthorizedApplications *iface, LONG *count)
{
    fw_apps *This = impl_from_INetFwAuthorizedApplications(iface);
    FW_RULESET rs;
    ULONG i;
    DWORD err;

    if (!count) return E_POINTER;
    *count = 0;
    err = FwStoreLoad(&rs);
    if (err) return hr_win32(err);
    for (i = 0; i < rs.N; i++)
        if (is_entry(&rs.R[i], LG_APP, This->profiles)) (*count)++;
    FwRuleSetFree(&rs);
    return S_OK;
}

static HRESULT WINAPI fw_apps_Add(INetFwAuthorizedApplications *iface, INetFwAuthorizedApplication *app)
{
    fw_apps *This = impl_from_INetFwAuthorizedApplications(iface);
    fw_app *impl;
    FW_RULE copy;
    FW_RULESET rs;
    ULONG i;
    DWORD err;
    HRESULT hr = S_OK;

    if (!app) return E_POINTER;
    if (app->lpVtbl != &fw_app_vtbl) return E_INVALIDARG;
    impl = impl_from_INetFwAuthorizedApplication(app);
    if (!impl->r.App || !*impl->r.App) return E_INVALIDARG;

    FwRuleInit(&copy);
    if (!FwRuleCopy(&copy, &impl->r)) { FwRuleFree(&copy); return E_OUTOFMEMORY; }
    if (!copy.Name || !*copy.Name) FwRuleSetStr(&copy.Name, copy.App);
    FwRuleSetStr(&copy.Id, NULL);
    copy.Action = 1;
    copy.Dir = 1;
    copy.Profiles = This->profiles;
    if (!FwrSet(&copy.Raw, LG_TOKEN, LG_APP)) hr = E_OUTOFMEMORY;

    /* an entry for the same program replaces the old one */
    if (SUCCEEDED(hr))
    {
        err = FwStoreLoad(&rs);
        if (err) hr = hr_win32(err);
        else
        {
            for (i = 0; i < rs.N; i++)
                if (is_entry(&rs.R[i], LG_APP, This->profiles) && rs.R[i].App && !_wcsicmp(rs.R[i].App, copy.App))
                {
                    if (!FwRuleSetStr(&copy.Id, rs.R[i].Id)) hr = E_OUTOFMEMORY;
                    break;
                }
            FwRuleSetFree(&rs);
        }
    }
    if (SUCCEEDED(hr))
        hr = hr_win32(copy.Id ? FwStoreUpdate(&copy) : FwStoreAdd(&copy));
    FwRuleFree(&copy);
    return hr;
}

static HRESULT WINAPI fw_apps_Remove(INetFwAuthorizedApplications *iface, BSTR imageFileName)
{
    fw_apps *This = impl_from_INetFwAuthorizedApplications(iface);
    FW_RULESET rs;
    WCHAR *path = NULL;
    ULONG i;
    DWORD err;
    HRESULT hr;

    if (!imageFileName || !*imageFileName) return E_INVALIDARG;
    hr = normalize_image(imageFileName, &path);
    if (FAILED(hr)) path = NULL;    /* compare the name as given */
    err = FwStoreLoad(&rs);
    if (err) { free(path); return hr_win32(err); }
    for (i = 0; i < rs.N && !err; i++)
    {
        const FW_RULE *r = &rs.R[i];
        if (is_entry(r, LG_APP, This->profiles) && r->App &&
            (!_wcsicmp(r->App, imageFileName) || (path && !_wcsicmp(r->App, path))))
            err = FwStoreDelete(r->Id);
    }
    FwRuleSetFree(&rs);
    free(path);
    return hr_win32(err);
}

static HRESULT WINAPI fw_apps_Item(INetFwAuthorizedApplications *iface, BSTR imageFileName, INetFwAuthorizedApplication **app)
{
    fw_apps *This = impl_from_INetFwAuthorizedApplications(iface);
    FW_RULESET rs;
    WCHAR *path = NULL;
    ULONG i;
    DWORD err;
    HRESULT hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    if (!app) return E_POINTER;
    *app = NULL;
    if (!imageFileName || !*imageFileName) return E_INVALIDARG;
    if (FAILED(normalize_image(imageFileName, &path))) path = NULL;
    err = FwStoreLoad(&rs);
    if (err) { free(path); return hr_win32(err); }
    for (i = 0; i < rs.N; i++)
    {
        const FW_RULE *r = &rs.R[i];
        if (is_entry(r, LG_APP, This->profiles) && r->App &&
            (!_wcsicmp(r->App, imageFileName) || (path && !_wcsicmp(r->App, path))))
        {
            hr = app_from_store(r, app);
            break;
        }
    }
    FwRuleSetFree(&rs);
    free(path);
    return hr;
}

static HRESULT WINAPI fw_apps_get__NewEnum(INetFwAuthorizedApplications *iface, IUnknown **newEnum)
{
    fw_apps *This = impl_from_INetFwAuthorizedApplications(iface);
    FW_RULESET rs;
    IDispatch **items;
    ULONG i, n = 0;
    DWORD err;

    if (!newEnum) return E_POINTER;
    *newEnum = NULL;
    err = FwStoreLoad(&rs);
    if (err) return hr_win32(err);
    items = calloc(rs.N ? rs.N : 1, sizeof(*items));
    if (!items) { FwRuleSetFree(&rs); return E_OUTOFMEMORY; }
    for (i = 0; i < rs.N; i++)
    {
        INetFwAuthorizedApplication *app;
        if (is_entry(&rs.R[i], LG_APP, This->profiles) && SUCCEEDED(app_from_store(&rs.R[i], &app)))
            items[n++] = (IDispatch *)app;
    }
    FwRuleSetFree(&rs);
    return legacy_enum_create(items, n, newEnum);
}

static const struct INetFwAuthorizedApplicationsVtbl fw_apps_vtbl =
{
    fw_apps_QueryInterface, fw_apps_AddRef, fw_apps_Release,
    fw_apps_GetTypeInfoCount, fw_apps_GetTypeInfo, fw_apps_GetIDsOfNames, fw_apps_Invoke,
    fw_apps_get_Count, fw_apps_Add, fw_apps_Remove, fw_apps_Item, fw_apps_get__NewEnum
};

HRESULT NetFwAuthorizedApplications_create_profile(LONG profiles, void **ppObj)
{
    fw_apps *fa = calloc(1, sizeof(*fa));
    if (!fa) return E_OUTOFMEMORY;
    fa->INetFwAuthorizedApplications_iface.lpVtbl = &fw_apps_vtbl;
    fa->refs = 1;
    fa->profiles = profiles;
    *ppObj = &fa->INetFwAuthorizedApplications_iface;
    return S_OK;
}

/* ------------------------------------------------------------------ INetFwOpenPort */

typedef struct fw_port
{
    INetFwOpenPort INetFwOpenPort_iface;
    LONG refs;
    FW_RULE r;
    BOOL stored;
} fw_port;

static const struct INetFwOpenPortVtbl fw_port_vtbl;

static inline fw_port *impl_from_INetFwOpenPort(INetFwOpenPort *iface)
{
    return CONTAINING_RECORD(iface, fw_port, INetFwOpenPort_iface);
}

static HRESULT port_commit(fw_port *This)
{
    if (!This->stored) return S_OK;
    return hr_win32(FwStoreUpdate(&This->r));
}

static LONG port_number(const FW_RULE *r)
{
    return r->LPorts ? _wtol(r->LPorts) : 0;
}

static ULONG WINAPI fw_port_AddRef(INetFwOpenPort *iface)
{
    return InterlockedIncrement(&impl_from_INetFwOpenPort(iface)->refs);
}

static ULONG WINAPI fw_port_Release(INetFwOpenPort *iface)
{
    fw_port *This = impl_from_INetFwOpenPort(iface);
    LONG refs = InterlockedDecrement(&This->refs);
    if (!refs)
    {
        TRACE("destroying %p\n", This);
        FwRuleFree(&This->r);
        free(This);
    }
    return refs;
}

static HRESULT WINAPI fw_port_QueryInterface(INetFwOpenPort *iface, REFIID riid, void **ppvObject)
{
    TRACE("%p %s %p\n", iface, debugstr_guid(riid), ppvObject);
    if (!ppvObject) return E_POINTER;
    if (IsEqualGUID(riid, &IID_INetFwOpenPort) || IsEqualGUID(riid, &IID_IDispatch) || IsEqualGUID(riid, &IID_IUnknown))
        *ppvObject = iface;
    else
    {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }
    INetFwOpenPort_AddRef(iface);
    return S_OK;
}

DISPATCH_IMPL(fw_port, INetFwOpenPort, INetFwOpenPort_tid)

static HRESULT WINAPI fw_port_get_Name(INetFwOpenPort *iface, BSTR *name)
{
    return get_bstr(impl_from_INetFwOpenPort(iface)->r.Name, name);
}

static HRESULT WINAPI fw_port_put_Name(INetFwOpenPort *iface, BSTR name)
{
    fw_port *This = impl_from_INetFwOpenPort(iface);
    HRESULT hr = set_name(&This->r, name);
    return SUCCEEDED(hr) ? port_commit(This) : hr;
}

static HRESULT WINAPI fw_port_get_IpVersion(INetFwOpenPort *iface, NET_FW_IP_VERSION *ipVersion)
{
    if (!ipVersion) return E_POINTER;
    *ipVersion = rule_ipver(&impl_from_INetFwOpenPort(iface)->r);
    return S_OK;
}

static HRESULT WINAPI fw_port_put_IpVersion(INetFwOpenPort *iface, NET_FW_IP_VERSION ipVersion)
{
    fw_port *This = impl_from_INetFwOpenPort(iface);
    HRESULT hr = rule_put_ipver(&This->r, ipVersion);
    return SUCCEEDED(hr) ? port_commit(This) : hr;
}

static HRESULT WINAPI fw_port_get_Protocol(INetFwOpenPort *iface, NET_FW_IP_PROTOCOL *ipProtocol)
{
    if (!ipProtocol) return E_POINTER;
    *ipProtocol = impl_from_INetFwOpenPort(iface)->r.Protocol;
    return S_OK;
}

static HRESULT WINAPI fw_port_put_Protocol(INetFwOpenPort *iface, NET_FW_IP_PROTOCOL ipProtocol)
{
    fw_port *This = impl_from_INetFwOpenPort(iface);

    TRACE("%p %u\n", This, ipProtocol);
    if (ipProtocol != NET_FW_IP_PROTOCOL_TCP && ipProtocol != NET_FW_IP_PROTOCOL_UDP) return E_INVALIDARG;
    This->r.Protocol = ipProtocol;
    return port_commit(This);
}

static HRESULT WINAPI fw_port_get_Port(INetFwOpenPort *iface, LONG *portNumber)
{
    if (!portNumber) return E_POINTER;
    *portNumber = port_number(&impl_from_INetFwOpenPort(iface)->r);
    return S_OK;
}

static HRESULT WINAPI fw_port_put_Port(INetFwOpenPort *iface, LONG portNumber)
{
    fw_port *This = impl_from_INetFwOpenPort(iface);
    WCHAR num[16];

    TRACE("%p %ld\n", This, portNumber);
    if (portNumber < 1 || portNumber > 65535) return E_INVALIDARG;
    _swprintf(num, L"%ld", portNumber);
    if (!FwRuleSetStr(&This->r.LPorts, num)) return E_OUTOFMEMORY;
    return port_commit(This);
}

static HRESULT WINAPI fw_port_get_Scope(INetFwOpenPort *iface, NET_FW_SCOPE *scope)
{
    if (!scope) return E_POINTER;
    *scope = rule_scope(&impl_from_INetFwOpenPort(iface)->r);
    return S_OK;
}

static HRESULT WINAPI fw_port_put_Scope(INetFwOpenPort *iface, NET_FW_SCOPE scope)
{
    fw_port *This = impl_from_INetFwOpenPort(iface);
    HRESULT hr = rule_put_scope(&This->r, scope);
    return SUCCEEDED(hr) ? port_commit(This) : hr;
}

static HRESULT WINAPI fw_port_get_RemoteAddresses(INetFwOpenPort *iface, BSTR *remoteAddrs)
{
    return rule_get_raddr(&impl_from_INetFwOpenPort(iface)->r, remoteAddrs);
}

static HRESULT WINAPI fw_port_put_RemoteAddresses(INetFwOpenPort *iface, BSTR remoteAddrs)
{
    fw_port *This = impl_from_INetFwOpenPort(iface);
    HRESULT hr = rule_put_raddr(&This->r, remoteAddrs);
    return SUCCEEDED(hr) ? port_commit(This) : hr;
}

static HRESULT WINAPI fw_port_get_Enabled(INetFwOpenPort *iface, VARIANT_BOOL *enabled)
{
    if (!enabled) return E_POINTER;
    *enabled = impl_from_INetFwOpenPort(iface)->r.Enabled ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI fw_port_put_Enabled(INetFwOpenPort *iface, VARIANT_BOOL enabled)
{
    fw_port *This = impl_from_INetFwOpenPort(iface);
    This->r.Enabled = enabled != VARIANT_FALSE;
    return port_commit(This);
}

static HRESULT WINAPI fw_port_get_BuiltIn(INetFwOpenPort *iface, VARIANT_BOOL *builtIn)
{
    if (!builtIn) return E_POINTER;
    *builtIn = VARIANT_FALSE;   /* every entry here was added through the API */
    return S_OK;
}

static const struct INetFwOpenPortVtbl fw_port_vtbl =
{
    fw_port_QueryInterface, fw_port_AddRef, fw_port_Release,
    fw_port_GetTypeInfoCount, fw_port_GetTypeInfo, fw_port_GetIDsOfNames, fw_port_Invoke,
    fw_port_get_Name, fw_port_put_Name,
    fw_port_get_IpVersion, fw_port_put_IpVersion,
    fw_port_get_Protocol, fw_port_put_Protocol,
    fw_port_get_Port, fw_port_put_Port,
    fw_port_get_Scope, fw_port_put_Scope,
    fw_port_get_RemoteAddresses, fw_port_put_RemoteAddresses,
    fw_port_get_Enabled, fw_port_put_Enabled,
    fw_port_get_BuiltIn
};

HRESULT NetFwOpenPort_create(IUnknown *pUnkOuter, LPVOID *ppObj)
{
    fw_port *fp;

    TRACE("(%p,%p)\n", pUnkOuter, ppObj);

    fp = calloc(1, sizeof(*fp));
    if (!fp) return E_OUTOFMEMORY;
    fp->INetFwOpenPort_iface.lpVtbl = &fw_port_vtbl;
    fp->refs = 1;
    FwRuleInit(&fp->r);
    fp->r.Enabled = TRUE;
    fp->r.Protocol = NET_FW_IP_PROTOCOL_TCP;
    *ppObj = &fp->INetFwOpenPort_iface;
    return S_OK;
}

static HRESULT port_from_store(const FW_RULE *src, INetFwOpenPort **out)
{
    INetFwOpenPort *iface;
    fw_port *impl;
    HRESULT hr = NetFwOpenPort_create(NULL, (void **)&iface);
    if (FAILED(hr)) return hr;
    impl = impl_from_INetFwOpenPort(iface);
    FwRuleFree(&impl->r);
    FwRuleInit(&impl->r);
    if (!FwRuleCopy(&impl->r, src)) { INetFwOpenPort_Release(iface); return E_OUTOFMEMORY; }
    impl->stored = TRUE;
    *out = iface;
    return S_OK;
}

/* ------------------------------------------------------------------ INetFwOpenPorts */

typedef struct fw_ports
{
    INetFwOpenPorts INetFwOpenPorts_iface;
    LONG refs;
    LONG profiles;
    BOOL readonly;  /* the list of a service: always empty here, Add and Remove are refused */
} fw_ports;

static inline fw_ports *impl_from_INetFwOpenPorts(INetFwOpenPorts *iface)
{
    return CONTAINING_RECORD(iface, fw_ports, INetFwOpenPorts_iface);
}

static BOOL port_matches(const FW_RULE *r, LONG profiles, LONG port, LONG proto)
{
    return is_entry(r, LG_PORT, profiles) && r->Protocol == proto && port_number(r) == port;
}

static BOOL valid_proto(NET_FW_IP_PROTOCOL p) { return p == NET_FW_IP_PROTOCOL_TCP || p == NET_FW_IP_PROTOCOL_UDP; }

static ULONG WINAPI fw_ports_AddRef(INetFwOpenPorts *iface)
{
    return InterlockedIncrement(&impl_from_INetFwOpenPorts(iface)->refs);
}

static ULONG WINAPI fw_ports_Release(INetFwOpenPorts *iface)
{
    fw_ports *This = impl_from_INetFwOpenPorts(iface);
    LONG refs = InterlockedDecrement(&This->refs);
    if (!refs) free(This);
    return refs;
}

static HRESULT WINAPI fw_ports_QueryInterface(INetFwOpenPorts *iface, REFIID riid, void **ppvObject)
{
    TRACE("%p %s %p\n", iface, debugstr_guid(riid), ppvObject);
    if (!ppvObject) return E_POINTER;
    if (IsEqualGUID(riid, &IID_INetFwOpenPorts) || IsEqualGUID(riid, &IID_IDispatch) || IsEqualGUID(riid, &IID_IUnknown))
        *ppvObject = iface;
    else
    {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }
    INetFwOpenPorts_AddRef(iface);
    return S_OK;
}

DISPATCH_IMPL(fw_ports, INetFwOpenPorts, INetFwOpenPorts_tid)

static HRESULT WINAPI fw_ports_get_Count(INetFwOpenPorts *iface, LONG *count)
{
    fw_ports *This = impl_from_INetFwOpenPorts(iface);
    FW_RULESET rs;
    ULONG i;
    DWORD err;

    if (!count) return E_POINTER;
    *count = 0;
    if (This->readonly) return S_OK;
    err = FwStoreLoad(&rs);
    if (err) return hr_win32(err);
    for (i = 0; i < rs.N; i++)
        if (is_entry(&rs.R[i], LG_PORT, This->profiles)) (*count)++;
    FwRuleSetFree(&rs);
    return S_OK;
}

static HRESULT WINAPI fw_ports_Add(INetFwOpenPorts *iface, INetFwOpenPort *port)
{
    fw_ports *This = impl_from_INetFwOpenPorts(iface);
    fw_port *impl;
    FW_RULE copy;
    FW_RULESET rs;
    ULONG i;
    DWORD err;
    HRESULT hr = S_OK;

    if (!port) return E_POINTER;
    if (This->readonly) return E_ACCESSDENIED;
    if (port->lpVtbl != &fw_port_vtbl) return E_INVALIDARG;
    impl = impl_from_INetFwOpenPort(port);
    if (!port_number(&impl->r) || !valid_proto(impl->r.Protocol)) return E_INVALIDARG;

    FwRuleInit(&copy);
    if (!FwRuleCopy(&copy, &impl->r)) { FwRuleFree(&copy); return E_OUTOFMEMORY; }
    if (!copy.Name || !*copy.Name)
    {
        WCHAR def[32];
        _swprintf(def, L"%ld/%s", port_number(&copy), copy.Protocol == NET_FW_IP_PROTOCOL_TCP ? L"TCP" : L"UDP");
        FwRuleSetStr(&copy.Name, def);
    }
    FwRuleSetStr(&copy.Id, NULL);
    copy.Action = 1;
    copy.Dir = 1;
    copy.Profiles = This->profiles;
    if (!FwrSet(&copy.Raw, LG_TOKEN, LG_PORT)) hr = E_OUTOFMEMORY;

    if (SUCCEEDED(hr))
    {
        err = FwStoreLoad(&rs);
        if (err) hr = hr_win32(err);
        else
        {
            for (i = 0; i < rs.N; i++)
                if (port_matches(&rs.R[i], This->profiles, port_number(&copy), copy.Protocol))
                {
                    if (!FwRuleSetStr(&copy.Id, rs.R[i].Id)) hr = E_OUTOFMEMORY;
                    break;
                }
            FwRuleSetFree(&rs);
        }
    }
    if (SUCCEEDED(hr))
        hr = hr_win32(copy.Id ? FwStoreUpdate(&copy) : FwStoreAdd(&copy));
    FwRuleFree(&copy);
    return hr;
}

static HRESULT WINAPI fw_ports_Remove(INetFwOpenPorts *iface, LONG portNumber, NET_FW_IP_PROTOCOL ipProtocol)
{
    fw_ports *This = impl_from_INetFwOpenPorts(iface);
    FW_RULESET rs;
    ULONG i;
    DWORD err;

    if (This->readonly) return E_ACCESSDENIED;
    if (portNumber < 1 || portNumber > 65535 || !valid_proto(ipProtocol)) return E_INVALIDARG;
    err = FwStoreLoad(&rs);
    if (err) return hr_win32(err);
    for (i = 0; i < rs.N && !err; i++)
        if (port_matches(&rs.R[i], This->profiles, portNumber, ipProtocol)) err = FwStoreDelete(rs.R[i].Id);
    FwRuleSetFree(&rs);
    return hr_win32(err);
}

static HRESULT WINAPI fw_ports_Item(INetFwOpenPorts *iface, LONG portNumber, NET_FW_IP_PROTOCOL ipProtocol, INetFwOpenPort **openPort)
{
    fw_ports *This = impl_from_INetFwOpenPorts(iface);
    FW_RULESET rs;
    ULONG i;
    DWORD err;
    HRESULT hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    if (!openPort) return E_POINTER;
    *openPort = NULL;
    if (portNumber < 1 || portNumber > 65535 || !valid_proto(ipProtocol)) return E_INVALIDARG;
    if (This->readonly) return hr;
    err = FwStoreLoad(&rs);
    if (err) return hr_win32(err);
    for (i = 0; i < rs.N; i++)
        if (port_matches(&rs.R[i], This->profiles, portNumber, ipProtocol))
        {
            hr = port_from_store(&rs.R[i], openPort);
            break;
        }
    FwRuleSetFree(&rs);
    return hr;
}

static HRESULT WINAPI fw_ports_get__NewEnum(INetFwOpenPorts *iface, IUnknown **newEnum)
{
    fw_ports *This = impl_from_INetFwOpenPorts(iface);
    FW_RULESET rs;
    IDispatch **items;
    ULONG i, n = 0;
    DWORD err;

    if (!newEnum) return E_POINTER;
    *newEnum = NULL;
    err = This->readonly ? 0 : FwStoreLoad(&rs);
    if (err) return hr_win32(err);
    if (This->readonly) { rs.R = NULL; rs.N = 0; }
    items = calloc(rs.N ? rs.N : 1, sizeof(*items));
    if (!items) { if (!This->readonly) FwRuleSetFree(&rs); return E_OUTOFMEMORY; }
    for (i = 0; i < rs.N; i++)
    {
        INetFwOpenPort *port;
        if (is_entry(&rs.R[i], LG_PORT, This->profiles) && SUCCEEDED(port_from_store(&rs.R[i], &port)))
            items[n++] = (IDispatch *)port;
    }
    if (!This->readonly) FwRuleSetFree(&rs);
    return legacy_enum_create(items, n, newEnum);
}

static const struct INetFwOpenPortsVtbl fw_ports_vtbl =
{
    fw_ports_QueryInterface, fw_ports_AddRef, fw_ports_Release,
    fw_ports_GetTypeInfoCount, fw_ports_GetTypeInfo, fw_ports_GetIDsOfNames, fw_ports_Invoke,
    fw_ports_get_Count, fw_ports_Add, fw_ports_Remove, fw_ports_Item, fw_ports_get__NewEnum
};

static HRESULT ports_create(LONG profiles, BOOL readonly, void **ppObj)
{
    fw_ports *fp = calloc(1, sizeof(*fp));
    if (!fp) return E_OUTOFMEMORY;
    fp->INetFwOpenPorts_iface.lpVtbl = &fw_ports_vtbl;
    fp->refs = 1;
    fp->profiles = profiles;
    fp->readonly = readonly;
    *ppObj = &fp->INetFwOpenPorts_iface;
    return S_OK;
}

HRESULT NetFwOpenPorts_create_profile(LONG profiles, void **ppObj)
{
    return ports_create(profiles, FALSE, ppObj);
}

/* ------------------------------------------------------------------ INetFwService / INetFwServices
 * The three well-known services are the rule groups of the same name; enabling a service enables the
 * rules of the group that apply to the profile. */

static const struct { PCWSTR Name; PCWSTR Group; } g_Services[] =
{
    { L"File and Printer Sharing", L"File and Printer Sharing" },   /* NET_FW_SERVICE_FILE_AND_PRINT */
    { L"UPnP Framework",           L"UPnP Framework" },             /* NET_FW_SERVICE_UPNP */
    { L"Remote Desktop",           L"Remote Desktop" },             /* NET_FW_SERVICE_REMOTE_DESKTOP */
};

typedef struct fw_service
{
    INetFwService INetFwService_iface;
    LONG refs;
    NET_FW_SERVICE_TYPE type;
    LONG profiles;
} fw_service;

static inline fw_service *impl_from_INetFwService(INetFwService *iface)
{
    return CONTAINING_RECORD(iface, fw_service, INetFwService_iface);
}

static BOOL service_rule(const fw_service *This, const FW_RULE *r)
{
    return r->Group && !_wcsicmp(r->Group, g_Services[This->type].Group) &&
           (r->Profiles == FWP_ANY_COM || (r->Profiles & This->profiles));
}

static ULONG WINAPI fw_service_AddRef(INetFwService *iface)
{
    return InterlockedIncrement(&impl_from_INetFwService(iface)->refs);
}

static ULONG WINAPI fw_service_Release(INetFwService *iface)
{
    fw_service *This = impl_from_INetFwService(iface);
    LONG refs = InterlockedDecrement(&This->refs);
    if (!refs) free(This);
    return refs;
}

static HRESULT WINAPI fw_service_QueryInterface(INetFwService *iface, REFIID riid, void **ppvObject)
{
    TRACE("%p %s %p\n", iface, debugstr_guid(riid), ppvObject);
    if (!ppvObject) return E_POINTER;
    if (IsEqualGUID(riid, &IID_INetFwService) || IsEqualGUID(riid, &IID_IDispatch) || IsEqualGUID(riid, &IID_IUnknown))
        *ppvObject = iface;
    else
    {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }
    INetFwService_AddRef(iface);
    return S_OK;
}

DISPATCH_IMPL(fw_service, INetFwService, INetFwService_tid)

static HRESULT WINAPI fw_service_get_Name(INetFwService *iface, BSTR *name)
{
    return get_bstr(g_Services[impl_from_INetFwService(iface)->type].Name, name);
}

static HRESULT WINAPI fw_service_get_Type(INetFwService *iface, NET_FW_SERVICE_TYPE *type)
{
    if (!type) return E_POINTER;
    *type = impl_from_INetFwService(iface)->type;
    return S_OK;
}

static HRESULT WINAPI fw_service_get_Customized(INetFwService *iface, VARIANT_BOOL *customized)
{
    if (!customized) return E_POINTER;
    *customized = VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI fw_service_get_IpVersion(INetFwService *iface, NET_FW_IP_VERSION *ipVersion)
{
    if (!ipVersion) return E_POINTER;
    *ipVersion = NET_FW_IP_VERSION_ANY;     /* the rules of a group are not split by IP version here */
    return S_OK;
}

static HRESULT WINAPI fw_service_put_IpVersion(INetFwService *iface, NET_FW_IP_VERSION ipVersion)
{
    if (ipVersion < 0 || ipVersion >= NET_FW_IP_VERSION_MAX) return E_INVALIDARG;
    return ipVersion == NET_FW_IP_VERSION_ANY ? S_OK : E_NOTIMPL;
}

/* Scope and RemoteAddresses of a service are those of the enabled rules of its group */
static HRESULT service_remote(fw_service *This, BOOL set, PCWSTR value, NET_FW_SCOPE *scope)
{
    FW_RULESET rs;
    ULONG i;
    BOOL any = FALSE, subnet = TRUE, all = TRUE;
    DWORD err = FwStoreLoad(&rs);

    if (err) return hr_win32(err);
    for (i = 0; i < rs.N && !err; i++)
    {
        FW_RULE *r = &rs.R[i];
        if (!service_rule(This, r)) continue;
        if (set)
        {
            if (!FwRuleSetStr(&r->RAddr, value)) { err = ERROR_OUTOFMEMORY; break; }
            err = FwStoreUpdate(r);
        }
        else if (r->Enabled)
        {
            NET_FW_SCOPE s = rule_scope(r);
            any = TRUE;
            if (s != NET_FW_SCOPE_ALL) all = FALSE;
            if (s != NET_FW_SCOPE_LOCAL_SUBNET) subnet = FALSE;
        }
    }
    FwRuleSetFree(&rs);
    if (!set) *scope = !any || all ? NET_FW_SCOPE_ALL : (subnet ? NET_FW_SCOPE_LOCAL_SUBNET : NET_FW_SCOPE_CUSTOM);
    return hr_win32(err);
}

static HRESULT WINAPI fw_service_get_Scope(INetFwService *iface, NET_FW_SCOPE *scope)
{
    if (!scope) return E_POINTER;
    return service_remote(impl_from_INetFwService(iface), FALSE, NULL, scope);
}

static HRESULT WINAPI fw_service_put_Scope(INetFwService *iface, NET_FW_SCOPE scope)
{
    fw_service *This = impl_from_INetFwService(iface);
    switch (scope)
    {
    case NET_FW_SCOPE_ALL: return service_remote(This, TRUE, NULL, NULL);
    case NET_FW_SCOPE_LOCAL_SUBNET: return service_remote(This, TRUE, L"LocalSubnet", NULL);
    case NET_FW_SCOPE_CUSTOM: return S_OK;
    default: return E_INVALIDARG;
    }
}

static HRESULT WINAPI fw_service_get_RemoteAddresses(INetFwService *iface, BSTR *remoteAddrs)
{
    fw_service *This = impl_from_INetFwService(iface);
    FW_RULESET rs;
    ULONG i;
    PCWSTR found = L"*";
    HRESULT hr = E_OUTOFMEMORY;
    DWORD err;

    if (!remoteAddrs) return E_POINTER;
    err = FwStoreLoad(&rs);
    if (err) return hr_win32(err);
    for (i = 0; i < rs.N; i++)
        if (service_rule(This, &rs.R[i]) && rs.R[i].Enabled && rule_scope(&rs.R[i]) != NET_FW_SCOPE_ALL)
        {
            found = rs.R[i].RAddr;
            break;
        }
    *remoteAddrs = SysAllocString(found);
    if (*remoteAddrs) hr = S_OK;
    FwRuleSetFree(&rs);
    return hr;
}

static HRESULT WINAPI fw_service_put_RemoteAddresses(INetFwService *iface, BSTR remoteAddrs)
{
    if (!remoteAddrs) return E_INVALIDARG;
    if (*remoteAddrs && wcscmp(remoteAddrs, L"*") && (wcschr(remoteAddrs, L'|') || FwCheckAddrs(remoteAddrs)))
        return E_INVALIDARG;
    return service_remote(impl_from_INetFwService(iface), TRUE,
                          (*remoteAddrs && wcscmp(remoteAddrs, L"*")) ? remoteAddrs : NULL, NULL);
}

static HRESULT WINAPI fw_service_get_Enabled(INetFwService *iface, VARIANT_BOOL *enabled)
{
    fw_service *This = impl_from_INetFwService(iface);
    FW_RULESET rs;
    ULONG i;
    BOOL any = FALSE, all = TRUE;
    DWORD err;

    if (!enabled) return E_POINTER;
    err = FwStoreLoad(&rs);
    if (err) return hr_win32(err);
    for (i = 0; i < rs.N; i++)
        if (service_rule(This, &rs.R[i])) { any = TRUE; if (!rs.R[i].Enabled) all = FALSE; }
    FwRuleSetFree(&rs);
    *enabled = (any && all) ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI fw_service_put_Enabled(INetFwService *iface, VARIANT_BOOL enabled)
{
    fw_service *This = impl_from_INetFwService(iface);
    FW_RULESET rs;
    ULONG i;
    BOOL any = FALSE;
    DWORD err;

    err = FwStoreLoad(&rs);
    if (err) return hr_win32(err);
    for (i = 0; i < rs.N && !err; i++)
        if (service_rule(This, &rs.R[i]))
        {
            any = TRUE;
            rs.R[i].Enabled = enabled != VARIANT_FALSE;
            err = FwStoreUpdate(&rs.R[i]);
        }
    FwRuleSetFree(&rs);
    if (!err && !any) err = ERROR_NOT_FOUND;    /* this system has no rules for the service */
    return hr_win32(err);
}

static HRESULT WINAPI fw_service_get_GloballyOpenPorts(INetFwService *iface, INetFwOpenPorts **openPorts)
{
    if (!openPorts) return E_POINTER;
    return ports_create(impl_from_INetFwService(iface)->profiles, TRUE, (void **)openPorts);
}

static const struct INetFwServiceVtbl fw_service_vtbl =
{
    fw_service_QueryInterface, fw_service_AddRef, fw_service_Release,
    fw_service_GetTypeInfoCount, fw_service_GetTypeInfo, fw_service_GetIDsOfNames, fw_service_Invoke,
    fw_service_get_Name, fw_service_get_Type, fw_service_get_Customized,
    fw_service_get_IpVersion, fw_service_put_IpVersion,
    fw_service_get_Scope, fw_service_put_Scope,
    fw_service_get_RemoteAddresses, fw_service_put_RemoteAddresses,
    fw_service_get_Enabled, fw_service_put_Enabled,
    fw_service_get_GloballyOpenPorts
};

static HRESULT service_create(NET_FW_SERVICE_TYPE type, LONG profiles, INetFwService **out)
{
    fw_service *fs = calloc(1, sizeof(*fs));
    if (!fs) return E_OUTOFMEMORY;
    fs->INetFwService_iface.lpVtbl = &fw_service_vtbl;
    fs->refs = 1;
    fs->type = type;
    fs->profiles = profiles;
    *out = &fs->INetFwService_iface;
    return S_OK;
}

typedef struct fw_services
{
    INetFwServices INetFwServices_iface;
    LONG refs;
    LONG profiles;
} fw_services;

static inline fw_services *impl_from_INetFwServices(INetFwServices *iface)
{
    return CONTAINING_RECORD(iface, fw_services, INetFwServices_iface);
}

static ULONG WINAPI fw_services_AddRef(INetFwServices *iface)
{
    return InterlockedIncrement(&impl_from_INetFwServices(iface)->refs);
}

static ULONG WINAPI fw_services_Release(INetFwServices *iface)
{
    fw_services *This = impl_from_INetFwServices(iface);
    LONG refs = InterlockedDecrement(&This->refs);
    if (!refs) free(This);
    return refs;
}

static HRESULT WINAPI fw_services_QueryInterface(INetFwServices *iface, REFIID riid, void **ppvObject)
{
    TRACE("%p %s %p\n", iface, debugstr_guid(riid), ppvObject);
    if (!ppvObject) return E_POINTER;
    if (IsEqualGUID(riid, &IID_INetFwServices) || IsEqualGUID(riid, &IID_IDispatch) || IsEqualGUID(riid, &IID_IUnknown))
        *ppvObject = iface;
    else
    {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }
    INetFwServices_AddRef(iface);
    return S_OK;
}

DISPATCH_IMPL(fw_services, INetFwServices, INetFwServices_tid)

static HRESULT WINAPI fw_services_get_Count(INetFwServices *iface, LONG *count)
{
    if (!count) return E_POINTER;
    *count = ARRAY_SIZE(g_Services);
    return S_OK;
}

static HRESULT WINAPI fw_services_Item(INetFwServices *iface, NET_FW_SERVICE_TYPE svcType, INetFwService **service)
{
    if (!service) return E_POINTER;
    *service = NULL;
    if (svcType < 0 || svcType >= (NET_FW_SERVICE_TYPE)ARRAY_SIZE(g_Services)) return E_INVALIDARG;
    return service_create(svcType, impl_from_INetFwServices(iface)->profiles, service);
}

static HRESULT WINAPI fw_services_get__NewEnum(INetFwServices *iface, IUnknown **newEnum)
{
    fw_services *This = impl_from_INetFwServices(iface);
    IDispatch **items;
    ULONG i, n = 0;

    if (!newEnum) return E_POINTER;
    *newEnum = NULL;
    items = calloc(ARRAY_SIZE(g_Services), sizeof(*items));
    if (!items) return E_OUTOFMEMORY;
    for (i = 0; i < ARRAY_SIZE(g_Services); i++)
    {
        INetFwService *svc;
        if (SUCCEEDED(service_create(i, This->profiles, &svc))) items[n++] = (IDispatch *)svc;
    }
    return legacy_enum_create(items, n, newEnum);
}

static const struct INetFwServicesVtbl fw_services_vtbl =
{
    fw_services_QueryInterface, fw_services_AddRef, fw_services_Release,
    fw_services_GetTypeInfoCount, fw_services_GetTypeInfo, fw_services_GetIDsOfNames, fw_services_Invoke,
    fw_services_get_Count, fw_services_Item, fw_services_get__NewEnum
};

HRESULT NetFwServices_create_profile(LONG profiles, void **ppObj)
{
    fw_services *fs = calloc(1, sizeof(*fs));
    if (!fs) return E_OUTOFMEMORY;
    fs->INetFwServices_iface.lpVtbl = &fw_services_vtbl;
    fs->refs = 1;
    fs->profiles = profiles;
    *ppObj = &fs->INetFwServices_iface;
    return S_OK;
}

/* ------------------------------------------------------------------ INetFwProfile */

typedef struct fw_profile
{
    INetFwProfile INetFwProfile_iface;
    LONG refs;
    NET_FW_PROFILE_TYPE type;   /* NET_FW_PROFILE_DOMAIN or NET_FW_PROFILE_STANDARD */
} fw_profile;

static inline fw_profile *impl_from_INetFwProfile(INetFwProfile *iface)
{
    return CONTAINING_RECORD(iface, fw_profile, INetFwProfile_iface);
}

static ULONG WINAPI fw_profile_AddRef(INetFwProfile *iface)
{
    return InterlockedIncrement(&impl_from_INetFwProfile(iface)->refs);
}

static ULONG WINAPI fw_profile_Release(INetFwProfile *iface)
{
    fw_profile *This = impl_from_INetFwProfile(iface);
    LONG refs = InterlockedDecrement(&This->refs);
    if (!refs) free(This);
    return refs;
}

static HRESULT WINAPI fw_profile_QueryInterface(INetFwProfile *iface, REFIID riid, void **ppvObject)
{
    TRACE("%p %s %p\n", iface, debugstr_guid(riid), ppvObject);
    if (!ppvObject) return E_POINTER;
    if (IsEqualGUID(riid, &IID_INetFwProfile) || IsEqualGUID(riid, &IID_IDispatch) || IsEqualGUID(riid, &IID_IUnknown))
        *ppvObject = iface;
    else
    {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }
    INetFwProfile_AddRef(iface);
    return S_OK;
}

DISPATCH_IMPL(fw_profile, INetFwProfile, INetFwProfile_tid)

static HRESULT WINAPI fw_profile_get_Type(INetFwProfile *iface, NET_FW_PROFILE_TYPE *type)
{
    if (!type) return E_POINTER;
    *type = impl_from_INetFwProfile(iface)->type;
    return S_OK;
}

enum { PF_ENABLE, PF_NOEXC, PF_NONOTIFY, PF_NOUNICAST };

static HRESULT profile_get(INetFwProfile *iface, int which, VARIANT_BOOL *out)
{
    fw_profile *This = impl_from_INetFwProfile(iface);
    FW_PROFILE p;
    DWORD err, v = 0;

    if (!out) return E_POINTER;
    err = FwProfileLoad(primary_bit(legacy_profile_bits(This->type)), &p);
    if (err) return hr_win32(err);
    switch (which)
    {
    case PF_ENABLE: v = p.Enable; break;
    case PF_NOEXC: v = p.DoNotAllowExceptions; break;
    case PF_NONOTIFY: v = p.DisableNotifications; break;
    case PF_NOUNICAST: v = p.DisableUnicastResponses; break;
    }
    *out = v ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT profile_put(INetFwProfile *iface, int which, VARIANT_BOOL value)
{
    static const PCWSTR names[] = { L"EnableFirewall", L"DoNotAllowExceptions", L"DisableNotifications",
                                    L"DisableUnicastResponsesToMulticastBroadcast" };
    fw_profile *This = impl_from_INetFwProfile(iface);
    LONG bits = legacy_profile_bits(This->type);
    ULONG b;
    DWORD err = 0;

    for (b = 1; b <= 4 && !err; b <<= 1)
        if (bits & b) err = FwProfileSetDword(b, names[which], value != VARIANT_FALSE, FALSE);
    return hr_win32(err);
}

static HRESULT WINAPI fw_profile_get_FirewallEnabled(INetFwProfile *iface, VARIANT_BOOL *enabled)
{ return profile_get(iface, PF_ENABLE, enabled); }
static HRESULT WINAPI fw_profile_put_FirewallEnabled(INetFwProfile *iface, VARIANT_BOOL enabled)
{ return profile_put(iface, PF_ENABLE, enabled); }
static HRESULT WINAPI fw_profile_get_ExceptionsNotAllowed(INetFwProfile *iface, VARIANT_BOOL *notAllowed)
{ return profile_get(iface, PF_NOEXC, notAllowed); }
static HRESULT WINAPI fw_profile_put_ExceptionsNotAllowed(INetFwProfile *iface, VARIANT_BOOL notAllowed)
{ return profile_put(iface, PF_NOEXC, notAllowed); }
static HRESULT WINAPI fw_profile_get_NotificationsDisabled(INetFwProfile *iface, VARIANT_BOOL *disabled)
{ return profile_get(iface, PF_NONOTIFY, disabled); }
static HRESULT WINAPI fw_profile_put_NotificationsDisabled(INetFwProfile *iface, VARIANT_BOOL disabled)
{ return profile_put(iface, PF_NONOTIFY, disabled); }
static HRESULT WINAPI fw_profile_get_UnicastResponsesToMulticastBroadcastDisabled(INetFwProfile *iface, VARIANT_BOOL *disabled)
{ return profile_get(iface, PF_NOUNICAST, disabled); }
static HRESULT WINAPI fw_profile_put_UnicastResponsesToMulticastBroadcastDisabled(INetFwProfile *iface, VARIANT_BOOL disabled)
{ return profile_put(iface, PF_NOUNICAST, disabled); }

static HRESULT WINAPI fw_profile_get_RemoteAdminSettings(INetFwProfile *iface, INetFwRemoteAdminSettings **remoteAdminSettings)
{
    FIXME("%p, %p\n", iface, remoteAdminSettings);
    return E_NOTIMPL;
}

static HRESULT WINAPI fw_profile_get_IcmpSettings(INetFwProfile *iface, INetFwIcmpSettings **icmpSettings)
{
    FIXME("%p, %p\n", iface, icmpSettings);
    return E_NOTIMPL;
}

static HRESULT WINAPI fw_profile_get_GloballyOpenPorts(INetFwProfile *iface, INetFwOpenPorts **openPorts)
{
    if (!openPorts) return E_POINTER;
    return NetFwOpenPorts_create_profile(legacy_profile_bits(impl_from_INetFwProfile(iface)->type), (void **)openPorts);
}

static HRESULT WINAPI fw_profile_get_Services(INetFwProfile *iface, INetFwServices **services)
{
    if (!services) return E_POINTER;
    return NetFwServices_create_profile(legacy_profile_bits(impl_from_INetFwProfile(iface)->type), (void **)services);
}

static HRESULT WINAPI fw_profile_get_AuthorizedApplications(INetFwProfile *iface, INetFwAuthorizedApplications **apps)
{
    if (!apps) return E_POINTER;
    return NetFwAuthorizedApplications_create_profile(legacy_profile_bits(impl_from_INetFwProfile(iface)->type), (void **)apps);
}

static const struct INetFwProfileVtbl fw_profile_vtbl =
{
    fw_profile_QueryInterface, fw_profile_AddRef, fw_profile_Release,
    fw_profile_GetTypeInfoCount, fw_profile_GetTypeInfo, fw_profile_GetIDsOfNames, fw_profile_Invoke,
    fw_profile_get_Type,
    fw_profile_get_FirewallEnabled, fw_profile_put_FirewallEnabled,
    fw_profile_get_ExceptionsNotAllowed, fw_profile_put_ExceptionsNotAllowed,
    fw_profile_get_NotificationsDisabled, fw_profile_put_NotificationsDisabled,
    fw_profile_get_UnicastResponsesToMulticastBroadcastDisabled,
    fw_profile_put_UnicastResponsesToMulticastBroadcastDisabled,
    fw_profile_get_RemoteAdminSettings, fw_profile_get_IcmpSettings,
    fw_profile_get_GloballyOpenPorts, fw_profile_get_Services, fw_profile_get_AuthorizedApplications
};

/* type: NET_FW_PROFILE_DOMAIN, NET_FW_PROFILE_STANDARD or NET_FW_PROFILE_CURRENT */
HRESULT NetFwProfile_create_type(NET_FW_PROFILE_TYPE type, void **ppObj)
{
    fw_profile *fp;

    if (type == NET_FW_PROFILE_CURRENT) type = legacy_current_type();
    if (type != NET_FW_PROFILE_DOMAIN && type != NET_FW_PROFILE_STANDARD) return E_INVALIDARG;
    fp = calloc(1, sizeof(*fp));
    if (!fp) return E_OUTOFMEMORY;
    fp->INetFwProfile_iface.lpVtbl = &fw_profile_vtbl;
    fp->refs = 1;
    fp->type = type;
    *ppObj = &fp->INetFwProfile_iface;
    return S_OK;
}

HRESULT NetFwProfile_create(IUnknown *pUnkOuter, LPVOID *ppObj)
{
    TRACE("(%p,%p)\n", pUnkOuter, ppObj);
    return NetFwProfile_create_type(NET_FW_PROFILE_CURRENT, ppObj);
}

/* ------------------------------------------------------------------ INetFwMgr */

typedef struct fw_manager
{
    INetFwMgr INetFwMgr_iface;
    LONG refs;
} fw_manager;

static inline fw_manager *impl_from_INetFwMgr(INetFwMgr *iface)
{
    return CONTAINING_RECORD(iface, fw_manager, INetFwMgr_iface);
}

static ULONG WINAPI fw_manager_AddRef(INetFwMgr *iface)
{
    return InterlockedIncrement(&impl_from_INetFwMgr(iface)->refs);
}

static ULONG WINAPI fw_manager_Release(INetFwMgr *iface)
{
    fw_manager *This = impl_from_INetFwMgr(iface);
    LONG refs = InterlockedDecrement(&This->refs);
    if (!refs) free(This);
    return refs;
}

static HRESULT WINAPI fw_manager_QueryInterface(INetFwMgr *iface, REFIID riid, void **ppvObject)
{
    TRACE("%p %s %p\n", iface, debugstr_guid(riid), ppvObject);
    if (!ppvObject) return E_POINTER;
    if (IsEqualGUID(riid, &IID_INetFwMgr) || IsEqualGUID(riid, &IID_IDispatch) || IsEqualGUID(riid, &IID_IUnknown))
        *ppvObject = iface;
    else
    {
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }
    INetFwMgr_AddRef(iface);
    return S_OK;
}

DISPATCH_IMPL(fw_manager, INetFwMgr, INetFwMgr_tid)

static HRESULT WINAPI fw_manager_get_LocalPolicy(INetFwMgr *iface, INetFwPolicy **localPolicy)
{
    TRACE("%p, %p\n", iface, localPolicy);
    if (!localPolicy) return E_POINTER;
    return NetFwPolicy_create(NULL, (void **)localPolicy);
}

static HRESULT WINAPI fw_manager_get_CurrentProfileType(INetFwMgr *iface, NET_FW_PROFILE_TYPE *profileType)
{
    if (!profileType) return E_POINTER;
    *profileType = legacy_current_type();
    return S_OK;
}

static HRESULT WINAPI fw_manager_RestoreDefaults(INetFwMgr *iface)
{
    return hr_win32(FwResetAll());
}

static HRESULT WINAPI fw_manager_IsPortAllowed(INetFwMgr *iface, BSTR imageFileName, NET_FW_IP_VERSION ipVersion,
        LONG portNumber, BSTR localAddress, NET_FW_IP_PROTOCOL ipProtocol, VARIANT *allowed, VARIANT *restricted)
{
    FIXME("%p, %s, %u, %ld, %s, %u, %p, %p\n", iface, debugstr_w(imageFileName), ipVersion, portNumber,
          debugstr_w(localAddress), ipProtocol, allowed, restricted);
    return E_NOTIMPL;
}

static HRESULT WINAPI fw_manager_IsIcmpTypeAllowed(INetFwMgr *iface, NET_FW_IP_VERSION ipVersion, BSTR localAddress,
        BYTE type, VARIANT *allowed, VARIANT *restricted)
{
    FIXME("%p, %u, %s, %u, %p, %p\n", iface, ipVersion, debugstr_w(localAddress), type, allowed, restricted);
    return E_NOTIMPL;
}

static const struct INetFwMgrVtbl fw_manager_vtbl =
{
    fw_manager_QueryInterface, fw_manager_AddRef, fw_manager_Release,
    fw_manager_GetTypeInfoCount, fw_manager_GetTypeInfo, fw_manager_GetIDsOfNames, fw_manager_Invoke,
    fw_manager_get_LocalPolicy, fw_manager_get_CurrentProfileType, fw_manager_RestoreDefaults,
    fw_manager_IsPortAllowed, fw_manager_IsIcmpTypeAllowed
};

HRESULT NetFwMgr_create(IUnknown *pUnkOuter, LPVOID *ppObj)
{
    fw_manager *fm;

    TRACE("(%p,%p)\n", pUnkOuter, ppObj);

    fm = calloc(1, sizeof(*fm));
    if (!fm) return E_OUTOFMEMORY;
    fm->INetFwMgr_iface.lpVtbl = &fw_manager_vtbl;
    fm->refs = 1;
    *ppObj = &fm->INetFwMgr_iface;
    return S_OK;
}
