/*
 * Copyright 2012 Hans Leidekker for CodeWeavers
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

#include <stdarg.h>
#ifdef __REACTOS__
#include <wchar.h>
#endif

#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "wbemcli.h"

#include "wine/debug.h"
#include "wbemprox_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(wbemprox);

struct client_security
{
    IClientSecurity IClientSecurity_iface;
};

static inline struct client_security *impl_from_IClientSecurity( IClientSecurity *iface )
{
    return CONTAINING_RECORD( iface, struct client_security, IClientSecurity_iface );
}

static HRESULT WINAPI client_security_QueryInterface(
    IClientSecurity *iface,
    REFIID riid,
    void **ppvObject )
{
    struct client_security *cs = impl_from_IClientSecurity( iface );

    TRACE("%p %s %p\n", cs, debugstr_guid( riid ), ppvObject );

    if ( IsEqualGUID( riid, &IID_IClientSecurity ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *ppvObject = cs;
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    IClientSecurity_AddRef( iface );
    return S_OK;
}

static ULONG WINAPI client_security_AddRef(
    IClientSecurity *iface )
{
    FIXME("%p\n", iface);
    return 2;
}

static ULONG WINAPI client_security_Release(
    IClientSecurity *iface )
{
    FIXME("%p\n", iface);
    return 1;
}

static HRESULT WINAPI client_security_QueryBlanket(
    IClientSecurity *iface,
    IUnknown *pProxy,
    DWORD *pAuthnSvc,
    DWORD *pAuthzSvc,
    OLECHAR **pServerPrincName,
    DWORD *pAuthnLevel,
    DWORD *pImpLevel,
    void **pAuthInfo,
    DWORD *pCapabilities )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI client_security_SetBlanket(
    IClientSecurity *iface,
    IUnknown *pProxy,
    DWORD AuthnSvc,
    DWORD AuthzSvc,
    OLECHAR *pServerPrincName,
    DWORD AuthnLevel,
    DWORD ImpLevel,
    void *pAuthInfo,
    DWORD Capabilities )
{
    static const OLECHAR defaultW[] =
        {'<','C','O','L','E','_','D','E','F','A','U','L','T','_','P','R','I','N','C','I','P','A','L','>',0};
    const OLECHAR *princname = (pServerPrincName == COLE_DEFAULT_PRINCIPAL) ? defaultW : pServerPrincName;

    FIXME("%p, %p, %u, %u, %s, %u, %u, %p, 0x%08x\n", iface, pProxy, AuthnSvc, AuthzSvc,
          debugstr_w(princname), AuthnLevel, ImpLevel, pAuthInfo, Capabilities);
    return WBEM_NO_ERROR;
}

static HRESULT WINAPI client_security_CopyProxy(
    IClientSecurity *iface,
    IUnknown *pProxy,
    IUnknown **ppCopy )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static const IClientSecurityVtbl client_security_vtbl =
{
    client_security_QueryInterface,
    client_security_AddRef,
    client_security_Release,
    client_security_QueryBlanket,
    client_security_SetBlanket,
    client_security_CopyProxy
};

IClientSecurity client_security = { &client_security_vtbl };

struct async_header
{
    IWbemObjectSink *sink;
    void (*proc)( struct async_header * );
    HANDLE cancel;
    HANDLE wait;
};

struct async_query
{
    struct async_header hdr;
    WCHAR *str;
#ifdef __REACTOS__
    enum wbm_namespace ns;
#endif
};

static void free_async( struct async_header *async )
{
    if (async->sink) IWbemObjectSink_Release( async->sink );
    CloseHandle( async->cancel );
    CloseHandle( async->wait );
    heap_free( async );
}

static BOOL init_async( struct async_header *async, IWbemObjectSink *sink,
                        void (*proc)(struct async_header *) )
{
    if (!(async->wait = CreateEventW( NULL, FALSE, FALSE, NULL ))) return FALSE;
    if (!(async->cancel = CreateEventW( NULL, FALSE, FALSE, NULL )))
    {
        CloseHandle( async->wait );
        return FALSE;
    }
    async->proc = proc;
    async->sink = sink;
    IWbemObjectSink_AddRef( sink );
    return TRUE;
}

static DWORD CALLBACK async_proc( LPVOID param )
{
    struct async_header *async = param;
    HANDLE wait = async->wait;

    async->proc( async );

    WaitForSingleObject( async->cancel, INFINITE );
    SetEvent( wait );
    return ERROR_SUCCESS;
}

static HRESULT queue_async( struct async_header *async )
{
    if (QueueUserWorkItem( async_proc, async, WT_EXECUTELONGFUNCTION )) return S_OK;
    return HRESULT_FROM_WIN32( GetLastError() );
}

struct wbem_services
{
    IWbemServices IWbemServices_iface;
    LONG refs;
    CRITICAL_SECTION cs;
    WCHAR *namespace;
    struct async_header *async;
#ifdef __REACTOS__
    enum wbm_namespace ns;
#endif
};

static inline struct wbem_services *impl_from_IWbemServices( IWbemServices *iface )
{
    return CONTAINING_RECORD( iface, struct wbem_services, IWbemServices_iface );
}

static ULONG WINAPI wbem_services_AddRef(
    IWbemServices *iface )
{
    struct wbem_services *ws = impl_from_IWbemServices( iface );
    return InterlockedIncrement( &ws->refs );
}

static ULONG WINAPI wbem_services_Release(
    IWbemServices *iface )
{
    struct wbem_services *ws = impl_from_IWbemServices( iface );
    LONG refs = InterlockedDecrement( &ws->refs );
    if (!refs)
    {
        TRACE("destroying %p\n", ws);

        EnterCriticalSection( &ws->cs );
        if (ws->async) SetEvent( ws->async->cancel );
        LeaveCriticalSection( &ws->cs );
        if (ws->async)
        {
            WaitForSingleObject( ws->async->wait, INFINITE );
            free_async( ws->async );
        }
        ws->cs.DebugInfo->Spare[0] = 0;
        DeleteCriticalSection( &ws->cs );
        heap_free( ws->namespace );
        heap_free( ws );
    }
    return refs;
}

static HRESULT WINAPI wbem_services_QueryInterface(
    IWbemServices *iface,
    REFIID riid,
    void **ppvObject )
{
    struct wbem_services *ws = impl_from_IWbemServices( iface );

    TRACE("%p %s %p\n", ws, debugstr_guid( riid ), ppvObject );

    if ( IsEqualGUID( riid, &IID_IWbemServices ) ||
         IsEqualGUID( riid, &IID_IUnknown ) )
    {
        *ppvObject = ws;
    }
    else if ( IsEqualGUID( riid, &IID_IClientSecurity ) )
    {
        *ppvObject = &client_security;
        return S_OK;
    }
    else
    {
        FIXME("interface %s not implemented\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    IWbemServices_AddRef( iface );
    return S_OK;
}

static HRESULT WINAPI wbem_services_OpenNamespace(
    IWbemServices *iface,
    const BSTR strNamespace,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemServices **ppWorkingNamespace,
    IWbemCallResult **ppResult )
{
    static const WCHAR cimv2W[] = {'c','i','m','v','2',0};
    static const WCHAR defaultW[] = {'d','e','f','a','u','l','t',0};
    struct wbem_services *ws = impl_from_IWbemServices( iface );

    TRACE("%p, %s, 0x%08x, %p, %p, %p\n", iface, debugstr_w(strNamespace), lFlags,
          pCtx, ppWorkingNamespace, ppResult);

#ifdef __REACTOS__
    {
        /* a child of this namespace: <this namespace>\<strNamespace> */
        enum wbm_namespace ns;
        const WCHAR *base = get_namespace_path( ws->ns ) + 4; /* skip "ROOT" */
        WCHAR *path;
        HRESULT hr;
        UINT len;

        (void)cimv2W; (void)defaultW;
        if (!strNamespace || !strNamespace[0] || !ppWorkingNamespace) return WBEM_E_INVALID_PARAMETER;
        if (*base == '\\') base++;
        len = lstrlenW( base ) + lstrlenW( strNamespace ) + 2;
        if (!(path = heap_alloc( len * sizeof(WCHAR) ))) return E_OUTOFMEMORY;
        swprintf( path, L"%s%s%s", base, base[0] ? L"\\" : L"", strNamespace );
        if (!parse_namespace( path, &ns )) hr = WBEM_E_INVALID_NAMESPACE;
        else hr = WbemServices_create( path, (void **)ppWorkingNamespace );
        heap_free( path );
        return hr;
    }
#else
    if ((wcsicmp( strNamespace, cimv2W ) && wcsicmp( strNamespace, defaultW )) || ws->namespace)
        return WBEM_E_INVALID_NAMESPACE;

    return WbemServices_create( cimv2W, (void **)ppWorkingNamespace );
#endif
}

static HRESULT WINAPI wbem_services_CancelAsyncCall(
    IWbemServices *iface,
    IWbemObjectSink *pSink )
{
    struct wbem_services *services = impl_from_IWbemServices( iface );
    struct async_header *async;

    TRACE("%p, %p\n", iface, pSink);

    if (!pSink) return WBEM_E_INVALID_PARAMETER;

    EnterCriticalSection( &services->cs );

    if (!(async = services->async))
    {
        LeaveCriticalSection( &services->cs );
        return WBEM_E_INVALID_PARAMETER;
    }
    services->async = NULL;
    SetEvent( async->cancel );

    LeaveCriticalSection( &services->cs );

    WaitForSingleObject( async->wait, INFINITE );
    free_async( async );
    return S_OK;
}

static HRESULT WINAPI wbem_services_QueryObjectSink(
    IWbemServices *iface,
    LONG lFlags,
    IWbemObjectSink **ppResponseHandler )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

HRESULT parse_path( const WCHAR *str, struct path **ret )
{
    struct path *path;
    const WCHAR *p = str, *q;
    UINT len;

    if (!(path = heap_alloc_zero( sizeof(*path) ))) return E_OUTOFMEMORY;

    if (*p == '\\')
    {
        static const WCHAR cimv2W[] = {'R','O','O','T','\\','C','I','M','V','2',0};
        WCHAR server[MAX_COMPUTERNAME_LENGTH+1];
        DWORD server_len = ARRAY_SIZE(server);

        p++;
        if (*p != '\\')
        {
            heap_free( path );
            return WBEM_E_INVALID_OBJECT_PATH;
        }
        p++;

        q = p;
        while (*p && *p != '\\') p++;
        if (!*p)
        {
            heap_free( path );
            return WBEM_E_INVALID_OBJECT_PATH;
        }

        len = p - q;
        if (!GetComputerNameW( server, &server_len ) || server_len != len || _wcsnicmp( q, server, server_len ))
        {
            heap_free( path );
            return WBEM_E_NOT_SUPPORTED;
        }

        q = ++p;
        while (*p && *p != ':') p++;
        if (!*p)
        {
            heap_free( path );
            return WBEM_E_INVALID_OBJECT_PATH;
        }

        len = p - q;
        if (len != ARRAY_SIZE(cimv2W) - 1 || _wcsnicmp( q, cimv2W, ARRAY_SIZE(cimv2W) - 1 ))
        {
            heap_free( path );
            return WBEM_E_INVALID_NAMESPACE;
        }
        p++;
    }

    q = p;
#ifdef __REACTOS__
    while (*p && *p != '.' && !(p[0] == '=' && p[1] == '@' && !p[2])) p++;
    if (p[0] == '=') path->singleton = TRUE;
#else
    while (*p && *p != '.') p++;
#endif

    len = p - q;
    if (!(path->class = heap_alloc( (len + 1) * sizeof(WCHAR) )))
    {
        heap_free( path );
        return E_OUTOFMEMORY;
    }
    memcpy( path->class, q, len * sizeof(WCHAR) );
    path->class[len] = 0;
    path->class_len = len;

    if (p[0] == '.' && p[1])
    {
        q = ++p;
        while (*q) q++;

        len = q - p;
        if (!(path->filter = heap_alloc( (len + 1) * sizeof(WCHAR) )))
        {
            heap_free( path->class );
            heap_free( path );
            return E_OUTOFMEMORY;
        }
        memcpy( path->filter, p, len * sizeof(WCHAR) );
        path->filter[len] = 0;
        path->filter_len = len;
    }
    *ret = path;
    return S_OK;
}

void free_path( struct path *path )
{
    if (!path) return;
    heap_free( path->class );
    heap_free( path->filter );
    heap_free( path );
}

WCHAR *query_from_path( const struct path *path )
{
    static const WCHAR selectW[] =
        {'S','E','L','E','C','T',' ','*',' ','F','R','O','M',' ','%','s',' ',
         'W','H','E','R','E',' ','%','s',0};
    static const WCHAR select_allW[] =
        {'S','E','L','E','C','T',' ','*',' ','F','R','O','M',' ',0};
    WCHAR *query;
    UINT len;

    if (path->filter)
    {
        len = path->class_len + path->filter_len + ARRAY_SIZE(selectW);
        if (!(query = heap_alloc( len * sizeof(WCHAR) ))) return NULL;
        swprintf( query, selectW, path->class, path->filter );
    }
    else
    {
        len = path->class_len + ARRAY_SIZE(select_allW);
        if (!(query = heap_alloc( len * sizeof(WCHAR) ))) return NULL;
        lstrcpyW( query, select_allW );
        lstrcatW( query, path->class );
    }
    return query;
}

#ifdef __REACTOS__
static HRESULT create_instance_enum_ns( enum wbm_namespace ns, const struct path *path, IEnumWbemClassObject **iter )
{
    WCHAR *query;
    HRESULT hr;

    if (!(query = query_from_path( path ))) return E_OUTOFMEMORY;
    hr = exec_query_ns( ns, query, iter );
    heap_free( query );
    return hr;
}
#define create_instance_enum( path, iter ) create_instance_enum_ns( WBEMPROX_NAMESPACE_CIMV2, path, iter )
#else
static HRESULT create_instance_enum( const struct path *path, IEnumWbemClassObject **iter )
{
    WCHAR *query;
    HRESULT hr;

    if (!(query = query_from_path( path ))) return E_OUTOFMEMORY;
    hr = exec_query( query, iter );
    heap_free( query );
    return hr;
}
#endif

#ifdef __REACTOS__
HRESULT get_object( const WCHAR *object_path, IWbemClassObject **obj )
{
    return get_object_ns( WBEMPROX_NAMESPACE_CIMV2, object_path, obj );
}

HRESULT get_object_ns( enum wbm_namespace ns, const WCHAR *object_path, IWbemClassObject **obj )
#else
HRESULT get_object( const WCHAR *object_path, IWbemClassObject **obj )
#endif
{
    IEnumWbemClassObject *iter;
    struct path *path;
    HRESULT hr;

    hr = parse_path( object_path, &path );
    if (hr != S_OK) return hr;

#ifdef __REACTOS__
    if (!path->filter && !path->singleton)
    {
        /* a class definition: never run a provider for it, nor for its subclasses (static data and
         * signature tables, which have no subclasses, keep their row of defaults) */
        struct table *table = grab_table( path->class );
        BOOL dynamic = table && (table->fill || is_namespace_table( table ) || !table->num_rows);

        if (!table)
        {
            free_path( path );
            return WBEM_E_NOT_FOUND;
        }
        /* keep our reference until the view holds its own: a transient table (method signatures) is
         * destroyed when its last reference goes */
        if (dynamic) hr = create_class_view_object( ns, path->class, obj );
        else hr = create_instance_enum_ns( ns, path, &iter );
        release_table( table );
        if (dynamic || hr != S_OK)
        {
            free_path( path );
            return hr;
        }
    }
    else hr = create_instance_enum_ns( ns, path, &iter );
#else
    hr = create_instance_enum( path, &iter );
#endif
    if (hr != S_OK)
    {
        free_path( path );
        return hr;
    }
#ifdef __REACTOS__
    {
        IWbemClassObject *first = NULL;
        ULONG count = 0;

        /* WMI: an unknown class is WBEM_E_NOT_FOUND, and so is a key path that matches no instance */
        hr = IEnumWbemClassObject_Next( iter, WBEM_INFINITE, 1, &first, &count );
        if (first) IWbemClassObject_Release( first );
        if (hr == WBEM_E_INVALID_CLASS || (hr == WBEM_S_FALSE && (path->filter || path->singleton)))
        {
            IEnumWbemClassObject_Release( iter );
            free_path( path );
            return WBEM_E_NOT_FOUND;
        }
    }
    /* an instance found through a base class belongs to its own (sub)class */
    {
        const WCHAR *name = get_enum_class_name( iter, 0 );
        hr = create_class_object( name ? name : path->class, iter, 0, NULL, obj );
    }
#else
    hr = create_class_object( path->class, iter, 0, NULL, obj );
#endif
    IEnumWbemClassObject_Release( iter );
    free_path( path );
    return hr;
}

static HRESULT WINAPI wbem_services_GetObject(
    IWbemServices *iface,
    const BSTR strObjectPath,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemClassObject **ppObject,
    IWbemCallResult **ppCallResult )
{
    TRACE("%p, %s, 0x%08x, %p, %p, %p\n", iface, debugstr_w(strObjectPath), lFlags,
          pCtx, ppObject, ppCallResult);

    if (lFlags) FIXME("unsupported flags 0x%08x\n", lFlags);

    if (!strObjectPath || !strObjectPath[0])
        return create_class_object( NULL, NULL, 0, NULL, ppObject );

#ifdef __REACTOS__
    return get_object_ns( impl_from_IWbemServices( iface )->ns, strObjectPath, ppObject );
#else
    return get_object( strObjectPath, ppObject );
#endif
}

static HRESULT WINAPI wbem_services_GetObjectAsync(
    IWbemServices *iface,
    const BSTR strObjectPath,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_PutClass(
    IWbemServices *iface,
    IWbemClassObject *pObject,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemCallResult **ppCallResult )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_PutClassAsync(
    IWbemServices *iface,
    IWbemClassObject *pObject,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_DeleteClass(
    IWbemServices *iface,
    const BSTR strClass,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemCallResult **ppCallResult )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_DeleteClassAsync(
    IWbemServices *iface,
    const BSTR strClass,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_CreateClassEnum(
    IWbemServices *iface,
    const BSTR strSuperclass,
    LONG lFlags,
    IWbemContext *pCtx,
    IEnumWbemClassObject **ppEnum )
{
#ifdef __REACTOS__
    TRACE("%p, %s, 0x%08x, %p, %p\n", iface, debugstr_w(strSuperclass), lFlags, pCtx, ppEnum);
    if (!ppEnum) return WBEM_E_INVALID_PARAMETER;
    return create_class_enum( impl_from_IWbemServices( iface )->ns, strSuperclass, lFlags, ppEnum );
#else
    FIXME("\n");
    return WBEM_E_FAILED;
#endif
}

static HRESULT WINAPI wbem_services_CreateClassEnumAsync(
    IWbemServices *iface,
    const BSTR strSuperclass,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_PutInstance(
    IWbemServices *iface,
    IWbemClassObject *pInst,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemCallResult **ppCallResult )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_PutInstanceAsync(
    IWbemServices *iface,
    IWbemClassObject *pInst,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_DeleteInstance(
    IWbemServices *iface,
    const BSTR strObjectPath,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemCallResult **ppCallResult )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_DeleteInstanceAsync(
    IWbemServices *iface,
    const BSTR strObjectPath,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_CreateInstanceEnum(
    IWbemServices *iface,
    const BSTR strClass,
    LONG lFlags,
    IWbemContext *pCtx,
    IEnumWbemClassObject **ppEnum )
{
    struct path *path;
    HRESULT hr;

    TRACE("%p, %s, 0%08x, %p, %p\n", iface, debugstr_w(strClass), lFlags, pCtx, ppEnum);

    if (lFlags) FIXME("unsupported flags 0x%08x\n", lFlags);

    hr = parse_path( strClass, &path );
    if (hr != S_OK) return hr;

#ifdef __REACTOS__
    hr = create_instance_enum_ns( impl_from_IWbemServices( iface )->ns, path, ppEnum );
#else
    hr = create_instance_enum( path, ppEnum );
#endif
    free_path( path );
    return hr;
}

static HRESULT WINAPI wbem_services_CreateInstanceEnumAsync(
    IWbemServices *iface,
    const BSTR strFilter,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_ExecQuery(
    IWbemServices *iface,
    const BSTR strQueryLanguage,
    const BSTR strQuery,
    LONG lFlags,
    IWbemContext *pCtx,
    IEnumWbemClassObject **ppEnum )
{
    static const WCHAR wqlW[] = {'W','Q','L',0};

    TRACE("%p, %s, %s, 0x%08x, %p, %p\n", iface, debugstr_w(strQueryLanguage),
          debugstr_w(strQuery), lFlags, pCtx, ppEnum);

    if (!strQueryLanguage || !strQuery || !strQuery[0]) return WBEM_E_INVALID_PARAMETER;
    if (wcsicmp( strQueryLanguage, wqlW )) return WBEM_E_INVALID_QUERY_TYPE;
#ifdef __REACTOS__
    return exec_query_flags( impl_from_IWbemServices( iface )->ns, strQuery, lFlags, ppEnum );
#else
    return exec_query( strQuery, ppEnum );
#endif
}

static void async_exec_query( struct async_header *hdr )
{
    struct async_query *query = (struct async_query *)hdr;
    IEnumWbemClassObject *result;
    IWbemClassObject *obj;
    ULONG count;
    HRESULT hr;

#ifdef __REACTOS__
    hr = exec_query_ns( query->ns, query->str, &result );
#else
    hr = exec_query( query->str, &result );
#endif
    if (hr == S_OK)
    {
        for (;;)
        {
            IEnumWbemClassObject_Next( result, WBEM_INFINITE, 1, &obj, &count );
            if (!count) break;
            IWbemObjectSink_Indicate( query->hdr.sink, 1, &obj );
            IWbemClassObject_Release( obj );
        }
        IEnumWbemClassObject_Release( result );
    }
    IWbemObjectSink_SetStatus( query->hdr.sink, WBEM_STATUS_COMPLETE, hr, NULL, NULL );
    heap_free( query->str );
}

static HRESULT WINAPI wbem_services_ExecQueryAsync(
    IWbemServices *iface,
    const BSTR strQueryLanguage,
    const BSTR strQuery,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler )
{
    struct wbem_services *services = impl_from_IWbemServices( iface );
    IWbemObjectSink *sink;
    HRESULT hr = E_OUTOFMEMORY;
    struct async_header *async;
    struct async_query *query;

    TRACE("%p, %s, %s, 0x%08x, %p, %p\n", iface, debugstr_w(strQueryLanguage), debugstr_w(strQuery),
          lFlags, pCtx, pResponseHandler);

    if (!pResponseHandler) return WBEM_E_INVALID_PARAMETER;

    hr = IWbemObjectSink_QueryInterface( pResponseHandler, &IID_IWbemObjectSink, (void **)&sink );
    if (FAILED(hr)) return hr;

    EnterCriticalSection( &services->cs );

    if (services->async)
    {
        FIXME("handle more than one pending async\n");
        hr = WBEM_E_FAILED;
        goto done;
    }
    if (!(query = heap_alloc_zero( sizeof(*query) ))) goto done;
    async = (struct async_header *)query;

    if (!(init_async( async, sink, async_exec_query )))
    {
        free_async( async );
        goto done;
    }
    if (!(query->str = heap_strdupW( strQuery )))
    {
        free_async( async );
        goto done;
    }
#ifdef __REACTOS__
    query->ns = services->ns;
#endif
    hr = queue_async( async );
    if (hr == S_OK) services->async = async;
    else
    {
        heap_free( query->str );
        free_async( async );
    }

done:
    LeaveCriticalSection( &services->cs );
    IWbemObjectSink_Release( sink );
    return hr;
}

static HRESULT WINAPI wbem_services_ExecNotificationQuery(
    IWbemServices *iface,
    const BSTR strQueryLanguage,
    const BSTR strQuery,
    LONG lFlags,
    IWbemContext *pCtx,
    IEnumWbemClassObject **ppEnum )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static HRESULT WINAPI wbem_services_ExecNotificationQueryAsync(
    IWbemServices *iface,
    const BSTR strQueryLanguage,
    const BSTR strQuery,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler )
{
    struct wbem_services *services = impl_from_IWbemServices( iface );
    IWbemObjectSink *sink;
    HRESULT hr = E_OUTOFMEMORY;
    struct async_header *async;
    struct async_query *query;

    TRACE("%p, %s, %s, 0x%08x, %p, %p\n", iface, debugstr_w(strQueryLanguage), debugstr_w(strQuery),
          lFlags, pCtx, pResponseHandler);

    if (!pResponseHandler) return WBEM_E_INVALID_PARAMETER;

    hr = IWbemObjectSink_QueryInterface( pResponseHandler, &IID_IWbemObjectSink, (void **)&sink );
    if (FAILED(hr)) return hr;

    EnterCriticalSection( &services->cs );

    if (services->async)
    {
        FIXME("handle more than one pending async\n");
        hr = WBEM_E_FAILED;
        goto done;
    }
    if (!(query = heap_alloc_zero( sizeof(*query) ))) goto done;
    async = (struct async_header *)query;

    if (!(init_async( async, sink, async_exec_query )))
    {
        free_async( async );
        goto done;
    }
    if (!(query->str = heap_strdupW( strQuery )))
    {
        free_async( async );
        goto done;
    }
#ifdef __REACTOS__
    query->ns = services->ns;
#endif
    hr = queue_async( async );
    if (hr == S_OK) services->async = async;
    else
    {
        heap_free( query->str );
        free_async( async );
    }

done:
    LeaveCriticalSection( &services->cs );
    IWbemObjectSink_Release( sink );
    return hr;
}

static HRESULT WINAPI wbem_services_ExecMethod(
    IWbemServices *iface,
    const BSTR strObjectPath,
    const BSTR strMethodName,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemClassObject *pInParams,
    IWbemClassObject **ppOutParams,
    IWbemCallResult **ppCallResult )
{
    IEnumWbemClassObject *result = NULL;
    IWbemClassObject *obj = NULL;
    struct query *query = NULL;
    struct path *path;
    WCHAR *str = NULL;
    class_method *func;
    struct table *table;
    UINT column;
    HRESULT hr;

    TRACE("%p, %s, %s, %08x, %p, %p, %p, %p\n", iface, debugstr_w(strObjectPath),
          debugstr_w(strMethodName), lFlags, pCtx, pInParams, ppOutParams, ppCallResult);

    if (lFlags) FIXME("flags %08x not supported\n", lFlags);

    if ((hr = parse_path( strObjectPath, &path )) != S_OK) return hr;
#ifdef __REACTOS__
    {
        /* the class must be visible in this namespace and have the method; a method that acts on an
         * instance needs an instance path: the class alone never means "the first instance" */
        struct wbem_services *services = impl_from_IWbemServices( iface );

        hr = S_OK;
        if (!(table = grab_table( path->class )) || !is_table_visible( table->name, services->ns ))
        {
            if (table) release_table( table );
            hr = WBEM_E_NOT_FOUND; /* what Windows returns for a class path the namespace does not have */
            goto done;
        }
        /* the method is a column of the table: its function sits in a row, which a provider fills only
         * when the query runs */
        if (!strMethodName || get_column_index( table, strMethodName, &column ) != S_OK || !is_method( table, column ))
            hr = WBEM_E_INVALID_METHOD;
        if (hr == S_OK && !path->filter && !is_class_method( table->name, strMethodName ))
            hr = WBEM_E_INVALID_METHOD_PARAMETERS;
        release_table( table );
        if (hr != S_OK) goto done;
    }
#endif
    if (!(str = query_from_path( path )))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if (!(query = create_query()))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    hr = parse_query( str, &query->view, &query->mem );
    if (hr != S_OK) goto done;

    hr = execute_view( query->view );
    if (hr != S_OK) goto done;

#ifdef __REACTOS__
    /* an instance path names one instance */
    if (path->filter && query->view->result_count != 1)
    {
        hr = query->view->result_count ? WBEM_E_INVALID_OBJECT_PATH : WBEM_E_NOT_FOUND;
        goto done;
    }
#endif

    hr = EnumWbemClassObject_create( query, (void **)&result );
    if (hr != S_OK) goto done;

    table = get_view_table( query->view, 0 );
    hr = create_class_object( table->name, result, 0, NULL, &obj );
    if (hr != S_OK) goto done;

#ifdef __REACTOS__
    lock_tables();
#endif
    hr = get_method( table, strMethodName, &func );
#ifdef __REACTOS__
    unlock_tables();
#endif
    if (hr != S_OK) goto done;

    hr = func( obj, pInParams, ppOutParams );

done:
    if (result) IEnumWbemClassObject_Release( result );
    if (obj) IWbemClassObject_Release( obj );
    free_query( query );
    free_path( path );
    heap_free( str );
    return hr;
}

static HRESULT WINAPI wbem_services_ExecMethodAsync(
    IWbemServices *iface,
    const BSTR strObjectPath,
    const BSTR strMethodName,
    LONG lFlags,
    IWbemContext *pCtx,
    IWbemClassObject *pInParams,
    IWbemObjectSink *pResponseHandler )
{
    FIXME("\n");
    return WBEM_E_FAILED;
}

static const IWbemServicesVtbl wbem_services_vtbl =
{
    wbem_services_QueryInterface,
    wbem_services_AddRef,
    wbem_services_Release,
    wbem_services_OpenNamespace,
    wbem_services_CancelAsyncCall,
    wbem_services_QueryObjectSink,
    wbem_services_GetObject,
    wbem_services_GetObjectAsync,
    wbem_services_PutClass,
    wbem_services_PutClassAsync,
    wbem_services_DeleteClass,
    wbem_services_DeleteClassAsync,
    wbem_services_CreateClassEnum,
    wbem_services_CreateClassEnumAsync,
    wbem_services_PutInstance,
    wbem_services_PutInstanceAsync,
    wbem_services_DeleteInstance,
    wbem_services_DeleteInstanceAsync,
    wbem_services_CreateInstanceEnum,
    wbem_services_CreateInstanceEnumAsync,
    wbem_services_ExecQuery,
    wbem_services_ExecQueryAsync,
    wbem_services_ExecNotificationQuery,
    wbem_services_ExecNotificationQueryAsync,
    wbem_services_ExecMethod,
    wbem_services_ExecMethodAsync
};

HRESULT WbemServices_create( const WCHAR *namespace, LPVOID *ppObj )
{
    struct wbem_services *ws;

    TRACE("(%p)\n", ppObj);

    ws = heap_alloc( sizeof(*ws) );
    if (!ws) return E_OUTOFMEMORY;

    ws->IWbemServices_iface.lpVtbl = &wbem_services_vtbl;
    ws->refs      = 1;
    ws->namespace = heap_strdupW( namespace );
    ws->async     = NULL;
#ifdef __REACTOS__
    if (!parse_namespace( namespace, &ws->ns ))
    {
        heap_free( ws->namespace );
        heap_free( ws );
        return WBEM_E_INVALID_NAMESPACE;
    }
#endif
    InitializeCriticalSection( &ws->cs );
    ws->cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": wbemprox_services.cs");

    *ppObj = &ws->IWbemServices_iface;

    TRACE("returning iface %p\n", *ppObj);
    return S_OK;
}
