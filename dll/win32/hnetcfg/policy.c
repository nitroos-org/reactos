/*
 * Copyright 2009 Hans Leidekker for CodeWeavers
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
#include <stdio.h>

#define COBJMACROS

#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "ole2.h"
#include "netfw.h"

#include "wine/debug.h"
#include "hnetcfg_private.h"
#include <fwstore.h>

WINE_DEFAULT_DEBUG_CHANNEL(hnetcfg);

typedef struct fw_policy
{
    INetFwPolicy INetFwPolicy_iface;
    LONG refs;
} fw_policy;

static inline fw_policy *impl_from_INetFwPolicy( INetFwPolicy *iface )
{
    return CONTAINING_RECORD(iface, fw_policy, INetFwPolicy_iface);
}

typedef struct fw_policy2
{
    INetFwPolicy2 INetFwPolicy2_iface;
    INetFwRules   *fw_policy2_rules;
    LONG refs;
} fw_policy2;

static inline fw_policy2 *impl_from_INetFwPolicy2( INetFwPolicy2 *iface )
{
    return CONTAINING_RECORD(iface, fw_policy2, INetFwPolicy2_iface);
}

typedef struct fw_rule
{
    INetFwRule INetFwRule_iface;
    LONG refs;
    FW_RULE r;
    BOOL stored;    /* read from / bound to the registry store: property writes are committed at once */
} fw_rule;

static HRESULT hr_win32(DWORD e) { return e ? HRESULT_FROM_WIN32(e) : S_OK; }

static HRESULT rule_commit(fw_rule *This)
{
    if (!This->stored) return S_OK;
    return hr_win32(FwStoreUpdate(&This->r));
}

static HRESULT get_str(const WCHAR *v, BSTR *out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!v) return S_OK;
    *out = SysAllocString(v);
    return *out ? S_OK : E_OUTOFMEMORY;
}

static HRESULT put_str(fw_rule *This, WCHAR **field, BSTR v)
{
    if (!FwRuleSetStr(field, v)) return E_OUTOFMEMORY;
    return rule_commit(This);
}

static HRESULT put_ports(fw_rule *This, WCHAR **field, BSTR v)
{
    if (v && *v && FwCheckPorts(v)) return E_INVALIDARG;
    if (v && !wcscmp(v, L"*")) v = NULL;
    return put_str(This, field, v);
}

static HRESULT put_addrs(fw_rule *This, WCHAR **field, BSTR v)
{
    if (v && *v && FwCheckAddrs(v)) return E_INVALIDARG;
    if (v && !wcscmp(v, L"*")) v = NULL;
    return put_str(This, field, v);
}

static inline fw_rule *impl_from_INetFwRule( INetFwRule *iface )
{
    return CONTAINING_RECORD(iface, fw_rule, INetFwRule_iface);
}

static HRESULT WINAPI netfw_rule_QueryInterface(
    INetFwRule *iface,
    REFIID riid,
    void **object)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    TRACE("%p %s %p\n", This, debugstr_guid( riid ), object );

    if ( IsEqualGUID( riid, &IID_INetFwRule ) ||
         IsEqualGUID( riid, &IID_IDispatch ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *object = iface;
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    INetFwRule_AddRef( iface );
    return S_OK;
}

static ULONG WINAPI netfw_rule_AddRef(
    INetFwRule *iface )
{
    fw_rule *This = impl_from_INetFwRule( iface );
    return InterlockedIncrement( &This->refs );
}

static ULONG WINAPI netfw_rule_Release(
    INetFwRule *iface )
{
    fw_rule *This = impl_from_INetFwRule( iface );
    LONG refs = InterlockedDecrement( &This->refs );
    if (!refs)
    {
        TRACE("destroying %p\n", This);
        FwRuleFree( &This->r );
        free( This );
    }
    return refs;
}

static HRESULT WINAPI netfw_rule_GetTypeInfoCount(
    INetFwRule *iface,
    UINT *pctinfo )
{
    fw_rule *This = impl_from_INetFwRule( iface );

    TRACE("%p %p\n", This, pctinfo);
    *pctinfo = 1;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_GetTypeInfo(
    INetFwRule *iface,
    UINT iTInfo,
    LCID lcid,
    ITypeInfo **ppTInfo)
{
    fw_rule *This = impl_from_INetFwRule( iface );

    TRACE("%p %u %lu %p\n", This, iTInfo, lcid, ppTInfo);
    return get_typeinfo( INetFwRule_tid, ppTInfo );
}

static HRESULT WINAPI netfw_rule_GetIDsOfNames(
    INetFwRule *iface,
    REFIID riid,
    LPOLESTR *rgszNames,
    UINT cNames,
    LCID lcid,
    DISPID *rgDispId)
{
    fw_rule *This = impl_from_INetFwRule( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %s %p %u %lu %p\n", This, debugstr_guid(riid), rgszNames, cNames, lcid, rgDispId);

    hr = get_typeinfo( INetFwRule_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_GetIDsOfNames( typeinfo, rgszNames, cNames, rgDispId );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI netfw_rule_Invoke(
    INetFwRule *iface,
    DISPID dispIdMember,
    REFIID riid,
    LCID lcid,
    WORD wFlags,
    DISPPARAMS *pDispParams,
    VARIANT *pVarResult,
    EXCEPINFO *pExcepInfo,
    UINT *puArgErr)
{
    fw_rule *This = impl_from_INetFwRule( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %ld %s %ld %d %p %p %p %p\n", This, dispIdMember, debugstr_guid(riid),
          lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);

    hr = get_typeinfo( INetFwRule_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_Invoke( typeinfo, &This->INetFwRule_iface, dispIdMember,
                               wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI netfw_rule_get_Name(
    INetFwRule *iface,
    BSTR *name)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.Name, name);
}

static HRESULT WINAPI netfw_rule_put_Name(
    INetFwRule *iface,
    BSTR name)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return put_str(This, &This->r.Name, name);
}

static HRESULT WINAPI netfw_rule_get_Description(
    INetFwRule *iface,
    BSTR *desc)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.Desc, desc);
}

static HRESULT WINAPI netfw_rule_put_Description(
    INetFwRule *iface,
    BSTR desc)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return put_str(This, &This->r.Desc, desc);
}

static HRESULT WINAPI netfw_rule_get_ApplicationName(
    INetFwRule *iface,
    BSTR *app)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.App, app);
}

static HRESULT WINAPI netfw_rule_put_ApplicationName(
    INetFwRule *iface,
    BSTR app)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return put_str(This, &This->r.App, app);
}

static HRESULT WINAPI netfw_rule_get_ServiceName(
    INetFwRule *iface,
    BSTR *service)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.Svc, service);
}

static HRESULT WINAPI netfw_rule_put_ServiceName(
    INetFwRule *iface,
    BSTR service)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return put_str(This, &This->r.Svc, service);
}

static HRESULT WINAPI netfw_rule_get_Protocol(
    INetFwRule *iface,
    LONG *protocol)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (!protocol) return E_POINTER;
    *protocol = This->r.Protocol;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Protocol(
    INetFwRule *iface,
    LONG protocol)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (protocol < 0 || protocol > 256) return E_INVALIDARG;
    This->r.Protocol = protocol;
    return rule_commit(This);
}

static HRESULT WINAPI netfw_rule_get_LocalPorts(
    INetFwRule *iface,
    BSTR *ports)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.LPorts ? This->r.LPorts : (This->stored ? L"*" : NULL), ports);
}

static HRESULT WINAPI netfw_rule_put_LocalPorts(
    INetFwRule *iface,
    BSTR ports)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return put_ports(This, &This->r.LPorts, ports);
}

static HRESULT WINAPI netfw_rule_get_RemotePorts(
    INetFwRule *iface,
    BSTR *ports)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.RPorts ? This->r.RPorts : (This->stored ? L"*" : NULL), ports);
}

static HRESULT WINAPI netfw_rule_put_RemotePorts(
    INetFwRule *iface,
    BSTR ports)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return put_ports(This, &This->r.RPorts, ports);
}

static HRESULT WINAPI netfw_rule_get_LocalAddresses(
    INetFwRule *iface,
    BSTR *addresses)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.LAddr ? This->r.LAddr : L"*", addresses);
}

static HRESULT WINAPI netfw_rule_put_LocalAddresses(
    INetFwRule *iface,
    BSTR addresses)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return put_addrs(This, &This->r.LAddr, addresses);
}

static HRESULT WINAPI netfw_rule_get_RemoteAddresses(
    INetFwRule *iface,
    BSTR *addresses)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.RAddr ? This->r.RAddr : L"*", addresses);
}

static HRESULT WINAPI netfw_rule_put_RemoteAddresses(
    INetFwRule *iface,
    BSTR addresses)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return put_addrs(This, &This->r.RAddr, addresses);
}

static HRESULT WINAPI netfw_rule_get_IcmpTypesAndCodes(
    INetFwRule *iface,
    BSTR *codes)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.Icmp, codes);
}

static HRESULT WINAPI netfw_rule_put_IcmpTypesAndCodes(
    INetFwRule *iface,
    BSTR codes)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return put_str(This, &This->r.Icmp, codes);
}

static HRESULT WINAPI netfw_rule_get_Direction(
    INetFwRule *iface,
    NET_FW_RULE_DIRECTION *dir)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (!dir) return E_POINTER;
    *dir = This->r.Dir;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Direction(
    INetFwRule *iface,
    NET_FW_RULE_DIRECTION dir)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (dir != NET_FW_RULE_DIR_IN && dir != NET_FW_RULE_DIR_OUT) return E_INVALIDARG;
    This->r.Dir = dir;
    return rule_commit(This);
}

static HRESULT WINAPI netfw_rule_get_Interfaces(
    INetFwRule *iface,
    VARIANT *interfaces)
{
if (!interfaces) return E_POINTER;
    VariantInit(interfaces);
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Interfaces(
    INetFwRule *iface,
    VARIANT interfaces)
{
return S_OK;
}

static HRESULT WINAPI netfw_rule_get_InterfaceTypes(
    INetFwRule *iface,
    BSTR *types)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.IfTypes ? This->r.IfTypes : L"All", types);
}

static HRESULT WINAPI netfw_rule_put_InterfaceTypes(
    INetFwRule *iface,
    BSTR types)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (types && *types && _wcsicmp(types, L"All"))
    {
        WCHAR *copy = _wcsdup(types), *tok;
        BOOL ok = TRUE;
        if (!copy) return E_OUTOFMEMORY;
        for (tok = wcstok(copy, L","); tok; tok = wcstok(NULL, L","))
            if (_wcsicmp(tok, L"Lan") && _wcsicmp(tok, L"Wireless") && _wcsicmp(tok, L"RemoteAccess")) ok = FALSE;
        free(copy);
        if (!ok) return E_INVALIDARG;
    }
    return put_str(This, &This->r.IfTypes, types);
}

static HRESULT WINAPI netfw_rule_get_Enabled(
    INetFwRule *iface,
    VARIANT_BOOL *enabled)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (!enabled) return E_POINTER;
    *enabled = This->r.Enabled ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Enabled(
    INetFwRule *iface,
    VARIANT_BOOL enabled)
{
fw_rule *This = impl_from_INetFwRule( iface );
    This->r.Enabled = enabled != VARIANT_FALSE;
    return rule_commit(This);
}

static HRESULT WINAPI netfw_rule_get_Grouping(
    INetFwRule *iface,
    BSTR *grouping)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return get_str(This->r.Group, grouping);
}

static HRESULT WINAPI netfw_rule_put_Grouping(
    INetFwRule *iface,
    BSTR grouping)
{
fw_rule *This = impl_from_INetFwRule( iface );
    return put_str(This, &This->r.Group, grouping);
}

static HRESULT WINAPI netfw_rule_get_Profiles(
    INetFwRule *iface,
    LONG *profiles)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (!profiles) return E_POINTER;
    *profiles = This->r.Profiles;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Profiles(
    INetFwRule *iface,
    LONG profiles)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (profiles != FWP_ANY_COM && (profiles & ~FWP_ALL)) return E_INVALIDARG;
    This->r.Profiles = profiles;
    return rule_commit(This);
}

static HRESULT WINAPI netfw_rule_get_EdgeTraversal(
    INetFwRule *iface,
    VARIANT_BOOL *enabled)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (!enabled) return E_POINTER;
    *enabled = This->r.Edge ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_EdgeTraversal(
    INetFwRule *iface,
    VARIANT_BOOL enabled)
{
fw_rule *This = impl_from_INetFwRule( iface );
    This->r.Edge = enabled != VARIANT_FALSE;
    return rule_commit(This);
}

static HRESULT WINAPI netfw_rule_get_Action(
    INetFwRule *iface,
    NET_FW_ACTION *action)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (!action) return E_POINTER;
    *action = This->r.Action;
    return S_OK;
}

static HRESULT WINAPI netfw_rule_put_Action(
    INetFwRule *iface,
    NET_FW_ACTION action)
{
fw_rule *This = impl_from_INetFwRule( iface );
    if (action != NET_FW_ACTION_BLOCK && action != NET_FW_ACTION_ALLOW) return E_INVALIDARG;
    This->r.Action = action;
    return rule_commit(This);
}

static const struct INetFwRuleVtbl fw_rule_vtbl =
{
    netfw_rule_QueryInterface,
    netfw_rule_AddRef,
    netfw_rule_Release,
    netfw_rule_GetTypeInfoCount,
    netfw_rule_GetTypeInfo,
    netfw_rule_GetIDsOfNames,
    netfw_rule_Invoke,
    netfw_rule_get_Name,
    netfw_rule_put_Name,
    netfw_rule_get_Description,
    netfw_rule_put_Description,
    netfw_rule_get_ApplicationName,
    netfw_rule_put_ApplicationName,
    netfw_rule_get_ServiceName,
    netfw_rule_put_ServiceName,
    netfw_rule_get_Protocol,
    netfw_rule_put_Protocol,
    netfw_rule_get_LocalPorts,
    netfw_rule_put_LocalPorts,
    netfw_rule_get_RemotePorts,
    netfw_rule_put_RemotePorts,
    netfw_rule_get_LocalAddresses,
    netfw_rule_put_LocalAddresses,
    netfw_rule_get_RemoteAddresses,
    netfw_rule_put_RemoteAddresses,
    netfw_rule_get_IcmpTypesAndCodes,
    netfw_rule_put_IcmpTypesAndCodes,
    netfw_rule_get_Direction,
    netfw_rule_put_Direction,
    netfw_rule_get_Interfaces,
    netfw_rule_put_Interfaces,
    netfw_rule_get_InterfaceTypes,
    netfw_rule_put_InterfaceTypes,
    netfw_rule_get_Enabled,
    netfw_rule_put_Enabled,
    netfw_rule_get_Grouping,
    netfw_rule_put_Grouping,
    netfw_rule_get_Profiles,
    netfw_rule_put_Profiles,
    netfw_rule_get_EdgeTraversal,
    netfw_rule_put_EdgeTraversal,
    netfw_rule_get_Action,
    netfw_rule_put_Action,
};

HRESULT NetFwRule_create( IUnknown *outer, void **obj )
{
    fw_rule *rule;

    TRACE("(%p)\n", obj);

    rule = calloc( 1, sizeof(*rule) );
    if (!rule) return E_OUTOFMEMORY;

    rule->INetFwRule_iface.lpVtbl = &fw_rule_vtbl;
    rule->refs = 1;
    FwRuleInit( &rule->r );

    *obj = &rule->INetFwRule_iface;

    TRACE("returning iface %p\n", *obj);
    return S_OK;
}

typedef struct fw_rules
{
    INetFwRules INetFwRules_iface;
    LONG refs;
} fw_rules;

static inline fw_rules *impl_from_INetFwRules( INetFwRules *iface )
{
    return CONTAINING_RECORD(iface, fw_rules, INetFwRules_iface);
}

static HRESULT WINAPI netfw_rules_QueryInterface(
    INetFwRules *iface,
    REFIID riid,
    void **object)
{
    fw_rules *This = impl_from_INetFwRules( iface );

    TRACE("%p %s %p\n", This, debugstr_guid( riid ), object );

    if ( IsEqualGUID( riid, &IID_INetFwRules ) ||
         IsEqualGUID( riid, &IID_IDispatch ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *object = iface;
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    INetFwRules_AddRef( iface );
    return S_OK;
}

static ULONG WINAPI netfw_rules_AddRef(
    INetFwRules *iface )
{
    fw_rules *This = impl_from_INetFwRules( iface );
    return InterlockedIncrement( &This->refs );
}

static ULONG WINAPI netfw_rules_Release(
    INetFwRules *iface )
{
    fw_rules *This = impl_from_INetFwRules( iface );
    LONG refs = InterlockedDecrement( &This->refs );
    if (!refs)
    {
        TRACE("destroying %p\n", This);
        free( This );
    }
    return refs;
}

static HRESULT WINAPI netfw_rules_GetTypeInfoCount(
    INetFwRules *iface,
    UINT *pctinfo )
{
    fw_rules *This = impl_from_INetFwRules( iface );

    TRACE("%p %p\n", This, pctinfo);
    *pctinfo = 1;
    return S_OK;
}

static HRESULT WINAPI netfw_rules_GetTypeInfo(
    INetFwRules *iface,
    UINT iTInfo,
    LCID lcid,
    ITypeInfo **ppTInfo)
{
    fw_rules *This = impl_from_INetFwRules( iface );

    TRACE("%p %u %lu %p\n", This, iTInfo, lcid, ppTInfo);
    return get_typeinfo( INetFwRules_tid, ppTInfo );
}

static HRESULT WINAPI netfw_rules_GetIDsOfNames(
    INetFwRules *iface,
    REFIID riid,
    LPOLESTR *rgszNames,
    UINT cNames,
    LCID lcid,
    DISPID *rgDispId)
{
    fw_rules *This = impl_from_INetFwRules( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %s %p %u %lu %p\n", This, debugstr_guid(riid), rgszNames, cNames, lcid, rgDispId);

    hr = get_typeinfo( INetFwRules_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_GetIDsOfNames( typeinfo, rgszNames, cNames, rgDispId );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI netfw_rules_Invoke(
    INetFwRules *iface,
    DISPID dispIdMember,
    REFIID riid,
    LCID lcid,
    WORD wFlags,
    DISPPARAMS *pDispParams,
    VARIANT *pVarResult,
    EXCEPINFO *pExcepInfo,
    UINT *puArgErr)
{
    fw_rules *This = impl_from_INetFwRules( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %ld %s %ld %d %p %p %p %p\n", This, dispIdMember, debugstr_guid(riid),
          lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);

    hr = get_typeinfo( INetFwRules_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_Invoke( typeinfo, &This->INetFwRules_iface, dispIdMember,
                               wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT rule_from_store(const FW_RULE *src, INetFwRule **out)
{
    INetFwRule *iface;
    fw_rule *impl;
    HRESULT hr = NetFwRule_create( NULL, (void **)&iface );
    if (FAILED(hr)) return hr;
    impl = CONTAINING_RECORD(iface, fw_rule, INetFwRule_iface);
    FwRuleFree( &impl->r );
    if (!FwRuleCopy( &impl->r, src )) { INetFwRule_Release( iface ); return E_OUTOFMEMORY; }
    impl->stored = TRUE;
    *out = iface;
    return S_OK;
}

typedef struct rules_enum
{
    IEnumVARIANT IEnumVARIANT_iface;
    LONG refs;
    INetFwRule **items;
    ULONG count, pos;
} rules_enum;

static inline rules_enum *impl_from_IEnumVARIANT(IEnumVARIANT *iface) { return CONTAINING_RECORD(iface, rules_enum, IEnumVARIANT_iface); }

static HRESULT WINAPI rules_enum_QueryInterface(IEnumVARIANT *iface, REFIID riid, void **obj)
{
    if (IsEqualGUID(riid, &IID_IEnumVARIANT) || IsEqualGUID(riid, &IID_IUnknown)) { *obj = iface; IEnumVARIANT_AddRef(iface); return S_OK; }
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI rules_enum_AddRef(IEnumVARIANT *iface) { return InterlockedIncrement(&impl_from_IEnumVARIANT(iface)->refs); }

static ULONG WINAPI rules_enum_Release(IEnumVARIANT *iface)
{
    rules_enum *This = impl_from_IEnumVARIANT(iface);
    LONG refs = InterlockedDecrement(&This->refs);
    if (!refs)
    {
        ULONG i;
        for (i = 0; i < This->count; i++) INetFwRule_Release(This->items[i]);
        free(This->items);
        free(This);
    }
    return refs;
}

static HRESULT WINAPI rules_enum_Next(IEnumVARIANT *iface, ULONG celt, VARIANT *rgVar, ULONG *fetched)
{
    rules_enum *This = impl_from_IEnumVARIANT(iface);
    ULONG n = 0;
    while (n < celt && This->pos < This->count)
    {
        VariantInit(&rgVar[n]);
        V_VT(&rgVar[n]) = VT_DISPATCH;
        INetFwRule_QueryInterface(This->items[This->pos], &IID_IDispatch, (void **)&V_DISPATCH(&rgVar[n]));
        This->pos++; n++;
    }
    if (fetched) *fetched = n;
    return n == celt ? S_OK : S_FALSE;
}

static HRESULT WINAPI rules_enum_Skip(IEnumVARIANT *iface, ULONG celt)
{
    rules_enum *This = impl_from_IEnumVARIANT(iface);
    This->pos += celt;
    if (This->pos > This->count) { This->pos = This->count; return S_FALSE; }
    return S_OK;
}

static HRESULT WINAPI rules_enum_Reset(IEnumVARIANT *iface) { impl_from_IEnumVARIANT(iface)->pos = 0; return S_OK; }

static HRESULT WINAPI rules_enum_Clone(IEnumVARIANT *iface, IEnumVARIANT **out) { *out = NULL; return E_NOTIMPL; }

static const IEnumVARIANTVtbl rules_enum_vtbl =
{
    rules_enum_QueryInterface, rules_enum_AddRef, rules_enum_Release,
    rules_enum_Next, rules_enum_Skip, rules_enum_Reset, rules_enum_Clone
};

static HRESULT validate_rule(const FW_RULE *r)
{
    if (!r->Name || !*r->Name || wcschr(r->Name, L'|') || !_wcsicmp(r->Name, L"all")) return E_INVALIDARG;
    if (((r->LPorts && *r->LPorts) || (r->RPorts && *r->RPorts)) && r->Protocol != 6 && r->Protocol != 17) return E_INVALIDARG;
    if (r->Icmp && *r->Icmp && r->Protocol != 1 && r->Protocol != 58) return E_INVALIDARG;
    if (r->Edge && r->Dir != 1) return E_INVALIDARG;
    if (r->Desc && wcschr(r->Desc, L'|')) return E_INVALIDARG;
    if (r->App && wcschr(r->App, L'|')) return E_INVALIDARG;
    return S_OK;
}

static HRESULT WINAPI netfw_rules_get_Count(
    INetFwRules *iface,
    LONG *count)
{
    FW_RULESET rs;
    DWORD err;
    if (!count) return E_POINTER;
    *count = 0;
    err = FwStoreLoad( &rs );
    if (err) return hr_win32( err );
    *count = rs.N;
    FwRuleSetFree( &rs );
    return S_OK;
}

static HRESULT WINAPI netfw_rules_Add(
    INetFwRules *iface,
    INetFwRule *rule)
{
    fw_rule *impl;
    FW_RULE copy;
    HRESULT hr;
    DWORD err;

    if (!rule) return E_POINTER;
    if (rule->lpVtbl != &fw_rule_vtbl) return E_INVALIDARG;
    impl = CONTAINING_RECORD(rule, fw_rule, INetFwRule_iface);
    hr = validate_rule( &impl->r );
    if (FAILED(hr)) return hr;
    FwRuleInit( &copy );
    if (!FwRuleCopy( &copy, &impl->r )) { FwRuleFree( &copy ); return E_OUTOFMEMORY; }
    FwRuleSetStr( &copy.Id, NULL );
    err = FwStoreAdd( &copy );
    FwRuleFree( &copy );
    return hr_win32( err );
}

static HRESULT WINAPI netfw_rules_Remove(
    INetFwRules *iface,
    BSTR name)
{
    FW_RULESET rs;
    ULONG i;
    DWORD err;
    if (!name) return E_POINTER;
    err = FwStoreLoad( &rs );
    if (err) return hr_win32( err );
    for (i = 0; i < rs.N; i++)
        if (rs.R[i].Name && !_wcsicmp( rs.R[i].Name, name ))
        {
            err = FwStoreDelete( rs.R[i].Id );
            if (err) break;
        }
    FwRuleSetFree( &rs );
    return hr_win32( err );
}

static HRESULT WINAPI netfw_rules_Item(
    INetFwRules *iface,
    BSTR name,
    INetFwRule **rule)
{
    FW_RULESET rs;
    ULONG i;
    HRESULT hr = HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND );
    DWORD err;
    if (!rule) return E_POINTER;
    *rule = NULL;
    if (!name) return E_POINTER;
    err = FwStoreLoad( &rs );
    if (err) return hr_win32( err );
    for (i = 0; i < rs.N; i++)
        if (rs.R[i].Name && !_wcsicmp( rs.R[i].Name, name ))
        {
            hr = rule_from_store( &rs.R[i], rule );
            break;
        }
    FwRuleSetFree( &rs );
    return hr;
}

static HRESULT WINAPI netfw_rules_get__NewEnum(
    INetFwRules *iface,
    IUnknown **newEnum)
{
    FW_RULESET rs;
    rules_enum *e;
    ULONG i;
    DWORD err;

    if (!newEnum) return E_POINTER;
    *newEnum = NULL;
    err = FwStoreLoad( &rs );
    if (err) return hr_win32( err );
    e = calloc( 1, sizeof(*e) );
    if (e) e->items = calloc( rs.N ? rs.N : 1, sizeof(*e->items) );
    if (!e || !e->items) { free( e ); FwRuleSetFree( &rs ); return E_OUTOFMEMORY; }
    e->IEnumVARIANT_iface.lpVtbl = &rules_enum_vtbl;
    e->refs = 1;
    for (i = 0; i < rs.N; i++)
        if (SUCCEEDED( rule_from_store( &rs.R[i], &e->items[e->count] ) )) e->count++;
    FwRuleSetFree( &rs );
    *newEnum = (IUnknown *)&e->IEnumVARIANT_iface;
    return S_OK;
}

static const struct INetFwRulesVtbl fw_rules_vtbl =
{
    netfw_rules_QueryInterface,
    netfw_rules_AddRef,
    netfw_rules_Release,
    netfw_rules_GetTypeInfoCount,
    netfw_rules_GetTypeInfo,
    netfw_rules_GetIDsOfNames,
    netfw_rules_Invoke,
    netfw_rules_get_Count,
    netfw_rules_Add,
    netfw_rules_Remove,
    netfw_rules_Item,
    netfw_rules_get__NewEnum
};

static HRESULT create_INetFwRules(INetFwRules **object)
{
    fw_rules *rules;

    TRACE("(%p)\n", object);

    rules = malloc( sizeof(*rules) );
    if (!rules) return E_OUTOFMEMORY;

    rules->INetFwRules_iface.lpVtbl = &fw_rules_vtbl;
    rules->refs = 1;

    *object = &rules->INetFwRules_iface;

    TRACE("returning iface %p\n", *object);
    return S_OK;
}

static ULONG WINAPI fw_policy_AddRef(
    INetFwPolicy *iface )
{
    fw_policy *fw_policy = impl_from_INetFwPolicy( iface );
    return InterlockedIncrement( &fw_policy->refs );
}

static ULONG WINAPI fw_policy_Release(
    INetFwPolicy *iface )
{
    fw_policy *fw_policy = impl_from_INetFwPolicy( iface );
    LONG refs = InterlockedDecrement( &fw_policy->refs );
    if (!refs)
    {
        TRACE("destroying %p\n", fw_policy);
        free( fw_policy );
    }
    return refs;
}

static HRESULT WINAPI fw_policy_QueryInterface(
    INetFwPolicy *iface,
    REFIID riid,
    void **ppvObject )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );

    TRACE("%p %s %p\n", This, debugstr_guid( riid ), ppvObject );

    if ( IsEqualGUID( riid, &IID_INetFwPolicy ) ||
         IsEqualGUID( riid, &IID_IDispatch ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *ppvObject = iface;
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    INetFwPolicy_AddRef( iface );
    return S_OK;
}

static HRESULT WINAPI fw_policy_GetTypeInfoCount(
    INetFwPolicy *iface,
    UINT *pctinfo )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );

    TRACE("%p %p\n", This, pctinfo);
    *pctinfo = 1;
    return S_OK;
}

static HRESULT WINAPI fw_policy_GetTypeInfo(
    INetFwPolicy *iface,
    UINT iTInfo,
    LCID lcid,
    ITypeInfo **ppTInfo )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );

    TRACE("%p %u %lu %p\n", This, iTInfo, lcid, ppTInfo);
    return get_typeinfo( INetFwPolicy_tid, ppTInfo );
}

static HRESULT WINAPI fw_policy_GetIDsOfNames(
    INetFwPolicy *iface,
    REFIID riid,
    LPOLESTR *rgszNames,
    UINT cNames,
    LCID lcid,
    DISPID *rgDispId )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %s %p %u %lu %p\n", This, debugstr_guid(riid), rgszNames, cNames, lcid, rgDispId);

    hr = get_typeinfo( INetFwPolicy_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_GetIDsOfNames( typeinfo, rgszNames, cNames, rgDispId );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI fw_policy_Invoke(
    INetFwPolicy *iface,
    DISPID dispIdMember,
    REFIID riid,
    LCID lcid,
    WORD wFlags,
    DISPPARAMS *pDispParams,
    VARIANT *pVarResult,
    EXCEPINFO *pExcepInfo,
    UINT *puArgErr )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %ld %s %ld %d %p %p %p %p\n", This, dispIdMember, debugstr_guid(riid),
          lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);

    hr = get_typeinfo( INetFwPolicy_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_Invoke( typeinfo, &This->INetFwPolicy_iface, dispIdMember,
                               wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI fw_policy_get_CurrentProfile(
    INetFwPolicy *iface,
    INetFwProfile **profile )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );

    TRACE("%p, %p\n", This, profile);
    return NetFwProfile_create( NULL, (void **)profile );
}

static HRESULT WINAPI fw_policy_GetProfileByType(
    INetFwPolicy *iface,
    NET_FW_PROFILE_TYPE profileType,
    INetFwProfile **profile )
{
    fw_policy *This = impl_from_INetFwPolicy( iface );

    FIXME("%p, %u, %p\n", This, profileType, profile);
    return E_NOTIMPL;
}

static const struct INetFwPolicyVtbl fw_policy_vtbl =
{
    fw_policy_QueryInterface,
    fw_policy_AddRef,
    fw_policy_Release,
    fw_policy_GetTypeInfoCount,
    fw_policy_GetTypeInfo,
    fw_policy_GetIDsOfNames,
    fw_policy_Invoke,
    fw_policy_get_CurrentProfile,
    fw_policy_GetProfileByType
};

HRESULT NetFwPolicy_create( IUnknown *pUnkOuter, LPVOID *ppObj )
{
    fw_policy *fp;

    TRACE("(%p,%p)\n", pUnkOuter, ppObj);

    fp = malloc( sizeof(*fp) );
    if (!fp) return E_OUTOFMEMORY;

    fp->INetFwPolicy_iface.lpVtbl = &fw_policy_vtbl;
    fp->refs = 1;

    *ppObj = &fp->INetFwPolicy_iface;

    TRACE("returning iface %p\n", *ppObj);
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_QueryInterface(INetFwPolicy2 *iface, REFIID riid, void **out)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    TRACE("%p %s %p\n", This, debugstr_guid( riid ), out );

    if ( IsEqualGUID( riid, &IID_INetFwPolicy2 ) ||
         IsEqualGUID( riid, &IID_IDispatch ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *out = iface;
    }
    else if( IsEqualGUID( riid, &IID_INetFwRules ) )
    {
        TRACE("INetFwRules not supported\n");
        return E_NOINTERFACE;
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    INetFwPolicy2_AddRef( iface );
    return S_OK;
}

static ULONG WINAPI fwpolicy2_AddRef(INetFwPolicy2 *iface)
{
    fw_policy2 *fw_policy = impl_from_INetFwPolicy2( iface );
    return InterlockedIncrement( &fw_policy->refs );
}

static ULONG WINAPI fwpolicy2_Release(INetFwPolicy2 *iface)
{
    fw_policy2 *fw_policy = impl_from_INetFwPolicy2( iface );
    LONG refs = InterlockedDecrement( &fw_policy->refs );
    if (!refs)
    {
        INetFwRules_Release(fw_policy->fw_policy2_rules);
        TRACE("destroying %p\n", fw_policy);
        free( fw_policy );
    }
    return refs;
}

static HRESULT WINAPI fwpolicy2_GetTypeInfoCount(INetFwPolicy2 *iface, UINT *pctinfo)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    TRACE("%p %p\n", This, pctinfo);
    *pctinfo = 1;
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_GetTypeInfo(INetFwPolicy2 *iface, UINT iTInfo, LCID lcid, ITypeInfo **info)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    TRACE("%p %u %lu %p\n", This, iTInfo, lcid, info);
    return get_typeinfo( INetFwPolicy2_tid, info );
}

static HRESULT WINAPI fwpolicy2_GetIDsOfNames(INetFwPolicy2 *iface, REFIID riid, LPOLESTR *rgszNames,
                        UINT cNames, LCID lcid, DISPID *rgDispId)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %s %p %u %lu %p\n", This, debugstr_guid(riid), rgszNames, cNames, lcid, rgDispId);

    hr = get_typeinfo( INetFwPolicy2_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_GetIDsOfNames( typeinfo, rgszNames, cNames, rgDispId );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI fwpolicy2_Invoke(INetFwPolicy2 *iface, DISPID dispIdMember, REFIID riid, LCID lcid,
                WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );
    ITypeInfo *typeinfo;
    HRESULT hr;

    TRACE("%p %ld %s %ld %d %p %p %p %p\n", This, dispIdMember, debugstr_guid(riid),
          lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);

    hr = get_typeinfo( INetFwPolicy2_tid, &typeinfo );
    if (SUCCEEDED(hr))
    {
        hr = ITypeInfo_Invoke( typeinfo, &This->INetFwPolicy2_iface, dispIdMember,
                               wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr );
        ITypeInfo_Release( typeinfo );
    }
    return hr;
}

static HRESULT WINAPI fwpolicy2_get_CurrentProfileTypes(INetFwPolicy2 *iface, LONG *profile)
{
if (!profile) return E_POINTER;
    *profile = FwCurrentProfiles();
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_get_FirewallEnabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL *enabled)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    if (!enabled) return E_POINTER;
    { FW_PROFILE p; FwProfileLoad( profileType, &p ); *enabled = (p.Enable) ? VARIANT_TRUE : VARIANT_FALSE; }
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_put_FirewallEnabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL enabled)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    return hr_win32( FwProfileSetDword( profileType, L"EnableFirewall", enabled != VARIANT_FALSE, FALSE ) );
}

static HRESULT WINAPI fwpolicy2_get_ExcludedInterfaces(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT *interfaces)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %d %p\n", This, profileType, interfaces);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_put_ExcludedInterfaces(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT interfaces)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );
    FIXME("%p %d\n", This, profileType);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_BlockAllInboundTraffic(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL *block)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    if (!block) return E_POINTER;
    { FW_PROFILE p; FwProfileLoad( profileType, &p ); *block = (p.DoNotAllowExceptions) ? VARIANT_TRUE : VARIANT_FALSE; }
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_put_BlockAllInboundTraffic(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL block)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    return hr_win32( FwProfileSetDword( profileType, L"DoNotAllowExceptions", block != VARIANT_FALSE, FALSE ) );
}

static HRESULT WINAPI fwpolicy2_get_NotificationsDisabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL *disabled)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    if (!disabled) return E_POINTER;
    { FW_PROFILE p; FwProfileLoad( profileType, &p ); *disabled = (p.DisableNotifications) ? VARIANT_TRUE : VARIANT_FALSE; }
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_put_NotificationsDisabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL disabled)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    return hr_win32( FwProfileSetDword( profileType, L"DisableNotifications", disabled != VARIANT_FALSE, FALSE ) );
}

static HRESULT WINAPI fwpolicy2_get_UnicastResponsesToMulticastBroadcastDisabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL *disabled)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    if (!disabled) return E_POINTER;
    { FW_PROFILE p; FwProfileLoad( profileType, &p ); *disabled = (p.DisableUnicastResponses) ? VARIANT_TRUE : VARIANT_FALSE; }
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_put_UnicastResponsesToMulticastBroadcastDisabled(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, VARIANT_BOOL disabled)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    return hr_win32( FwProfileSetDword( profileType, L"DisableUnicastResponsesToMulticastBroadcast", disabled != VARIANT_FALSE, FALSE ) );
}

static HRESULT WINAPI fwpolicy2_get_Rules(INetFwPolicy2 *iface, INetFwRules **rules)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    TRACE("%p %p\n", This, rules);

    if(!rules)
        return E_POINTER;

    *rules = This->fw_policy2_rules;
    INetFwRules_AddRef(This->fw_policy2_rules);

    return S_OK;
}

static HRESULT WINAPI fwpolicy2_get_ServiceRestriction(INetFwPolicy2 *iface, INetFwServiceRestriction **ServiceRestriction)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %p\n", This, ServiceRestriction);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_EnableRuleGroup(INetFwPolicy2 *iface, LONG bitmask, BSTR group, VARIANT_BOOL enable)
{
FW_RULESET rs; ULONG i; DWORD err = 0; BOOL any = FALSE, all = TRUE;
    if (!group) return E_POINTER;
    err = FwStoreLoad( &rs );
    if (err) return hr_win32( err );
    for (i = 0; i < rs.N; i++)
    {
        FW_RULE *r = &rs.R[i];
        if (!r->Group || _wcsicmp( r->Group, group )) continue;
        if (!(r->Profiles & bitmask) && r->Profiles != FWP_ANY_COM) continue;
        any = TRUE;
        { r->Enabled = enable != VARIANT_FALSE; err = FwStoreUpdate( r ); if (err) break; }
    }
    FwRuleSetFree( &rs );
    return hr_win32( err );
}

static HRESULT WINAPI fwpolicy2_IsRuleGroupEnabled(INetFwPolicy2 *iface, LONG bitmask, BSTR group, VARIANT_BOOL *enabled)
{
FW_RULESET rs; ULONG i; DWORD err = 0; BOOL any = FALSE, all = TRUE;
    if (!group) return E_POINTER;
    err = FwStoreLoad( &rs );
    if (err) return hr_win32( err );
    for (i = 0; i < rs.N; i++)
    {
        FW_RULE *r = &rs.R[i];
        if (!r->Group || _wcsicmp( r->Group, group )) continue;
        if (!(r->Profiles & bitmask) && r->Profiles != FWP_ANY_COM) continue;
        any = TRUE;
        { if (!r->Enabled) all = FALSE; }
    }
    FwRuleSetFree( &rs );
    if (!enabled) return E_POINTER;
    *enabled = (any && all) ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_RestoreLocalFirewallDefaults(INetFwPolicy2 *iface)
{
return hr_win32( FwResetAll() );
}

static HRESULT WINAPI fwpolicy2_get_DefaultInboundAction(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, NET_FW_ACTION *action)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    if (!action) return E_POINTER;
    { FW_PROFILE p; FwProfileLoad( profileType, &p ); *action = p.DefaultInbound ? NET_FW_ACTION_BLOCK : NET_FW_ACTION_ALLOW; }
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_put_DefaultInboundAction(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, NET_FW_ACTION action)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    if (action != NET_FW_ACTION_BLOCK && action != NET_FW_ACTION_ALLOW) return E_INVALIDARG;
    return hr_win32( FwProfileSetDword( profileType, L"DefaultInboundAction", action == NET_FW_ACTION_BLOCK, FALSE ) );
}

static HRESULT WINAPI fwpolicy2_get_DefaultOutboundAction(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, NET_FW_ACTION *action)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    if (!action) return E_POINTER;
    { FW_PROFILE p; FwProfileLoad( profileType, &p ); *action = p.DefaultOutbound ? NET_FW_ACTION_BLOCK : NET_FW_ACTION_ALLOW; }
    return S_OK;
}

static HRESULT WINAPI fwpolicy2_put_DefaultOutboundAction(INetFwPolicy2 *iface, NET_FW_PROFILE_TYPE2 profileType, NET_FW_ACTION action)
{
if (profileType != NET_FW_PROFILE2_DOMAIN && profileType != NET_FW_PROFILE2_PRIVATE && profileType != NET_FW_PROFILE2_PUBLIC) return E_INVALIDARG;
    if (action != NET_FW_ACTION_BLOCK && action != NET_FW_ACTION_ALLOW) return E_INVALIDARG;
    return hr_win32( FwProfileSetDword( profileType, L"DefaultOutboundAction", action == NET_FW_ACTION_BLOCK, FALSE ) );
}

static HRESULT WINAPI fwpolicy2_get_IsRuleGroupCurrentlyEnabled(INetFwPolicy2 *iface, BSTR group, VARIANT_BOOL *enabled)
{
    fw_policy2 *This = impl_from_INetFwPolicy2( iface );

    FIXME("%p %s %p\n", This, debugstr_w(group), enabled);
    return E_NOTIMPL;
}

static HRESULT WINAPI fwpolicy2_get_LocalPolicyModifyState(INetFwPolicy2 *iface, NET_FW_MODIFY_STATE *modifyState)
{
if (!modifyState) return E_POINTER;
    *modifyState = NET_FW_MODIFY_STATE_OK;
    return S_OK;
}

static const struct INetFwPolicy2Vtbl fw_policy2_vtbl =
{
    fwpolicy2_QueryInterface,
    fwpolicy2_AddRef,
    fwpolicy2_Release,
    fwpolicy2_GetTypeInfoCount,
    fwpolicy2_GetTypeInfo,
    fwpolicy2_GetIDsOfNames,
    fwpolicy2_Invoke,
    fwpolicy2_get_CurrentProfileTypes,
    fwpolicy2_get_FirewallEnabled,
    fwpolicy2_put_FirewallEnabled,
    fwpolicy2_get_ExcludedInterfaces,
    fwpolicy2_put_ExcludedInterfaces,
    fwpolicy2_get_BlockAllInboundTraffic,
    fwpolicy2_put_BlockAllInboundTraffic,
    fwpolicy2_get_NotificationsDisabled,
    fwpolicy2_put_NotificationsDisabled,
    fwpolicy2_get_UnicastResponsesToMulticastBroadcastDisabled,
    fwpolicy2_put_UnicastResponsesToMulticastBroadcastDisabled,
    fwpolicy2_get_Rules,
    fwpolicy2_get_ServiceRestriction,
    fwpolicy2_EnableRuleGroup,
    fwpolicy2_IsRuleGroupEnabled,
    fwpolicy2_RestoreLocalFirewallDefaults,
    fwpolicy2_get_DefaultInboundAction,
    fwpolicy2_put_DefaultInboundAction,
    fwpolicy2_get_DefaultOutboundAction,
    fwpolicy2_put_DefaultOutboundAction,
    fwpolicy2_get_IsRuleGroupCurrentlyEnabled,
    fwpolicy2_get_LocalPolicyModifyState
};

HRESULT NetFwPolicy2_create( IUnknown *outer, void **obj )
{
    fw_policy2 *fp;

    TRACE("(%p,%p)\n", outer, obj);

    fp = malloc( sizeof(*fp) );
    if (!fp) return E_OUTOFMEMORY;

    fp->INetFwPolicy2_iface.lpVtbl = &fw_policy2_vtbl;
    fp->refs = 1;

    *obj = &fp->INetFwPolicy2_iface;

    if (FAILED(create_INetFwRules(&fp->fw_policy2_rules)))
    {
        free( fp );
        return E_OUTOFMEMORY;
    }

    TRACE("returning iface %p\n", *obj);
    return S_OK;
}
