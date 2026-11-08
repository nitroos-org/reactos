/* WinRT Windows.Security.Authentication.Onlineid Implementation
 *
 * Copyright (C) 2024 Mohamad Al-Jaf
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

#include "private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(onlineid);

/* The interfaces used here are all public: IOnlineIdSystemTicketResult and IAsyncInfo come from the IDL files, the IIDs of
 * IAsyncOperation<OnlineIdSystemTicketResult*> and of its completed handler are the parameterized-interface IIDs that widl
 * computes from the public signatures (the WinRT pinterface algorithm: a version-5 UUID, SHA-1 over the pinterface
 * namespace GUID and the signature string). */

/* ---- OnlineIdSystemTicketResult ---- */

struct ticket_result
{
    IOnlineIdSystemTicketResult IOnlineIdSystemTicketResult_iface;
    LONG ref;
    OnlineIdSystemTicketStatus status;
    HRESULT extended_error;
};

static inline struct ticket_result *impl_from_IOnlineIdSystemTicketResult( IOnlineIdSystemTicketResult *iface )
{
    return CONTAINING_RECORD( iface, struct ticket_result, IOnlineIdSystemTicketResult_iface );
}

static HRESULT WINAPI result_QueryInterface( IOnlineIdSystemTicketResult *iface, REFIID iid, void **out )
{
    struct ticket_result *impl = impl_from_IOnlineIdSystemTicketResult( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown ) ||
        IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) ||
        IsEqualGUID( iid, &IID_IOnlineIdSystemTicketResult ))
    {
        *out = &impl->IOnlineIdSystemTicketResult_iface;
        IInspectable_AddRef( (IInspectable *)*out );
        return S_OK;
    }

    FIXME( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid( iid ) );
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI result_AddRef( IOnlineIdSystemTicketResult *iface )
{
    struct ticket_result *impl = impl_from_IOnlineIdSystemTicketResult( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p increasing refcount to %lu.\n", iface, ref );
    return ref;
}

static ULONG WINAPI result_Release( IOnlineIdSystemTicketResult *iface )
{
    struct ticket_result *impl = impl_from_IOnlineIdSystemTicketResult( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );

    TRACE( "iface %p decreasing refcount to %lu.\n", iface, ref );

    if (!ref) free( impl );
    return ref;
}

static HRESULT WINAPI result_GetIids( IOnlineIdSystemTicketResult *iface, ULONG *iid_count, IID **iids )
{
    FIXME( "iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids );
    return E_NOTIMPL;
}

static HRESULT WINAPI result_GetRuntimeClassName( IOnlineIdSystemTicketResult *iface, HSTRING *class_name )
{
    static const WCHAR name[] = L"Windows.Security.Authentication.OnlineId.OnlineIdSystemTicketResult";

    TRACE( "iface %p, class_name %p.\n", iface, class_name );
    if (!class_name) return E_POINTER;
    return WindowsCreateString( name, ARRAY_SIZE(name) - 1, class_name );
}

static HRESULT WINAPI result_GetTrustLevel( IOnlineIdSystemTicketResult *iface, TrustLevel *trust_level )
{
    TRACE( "iface %p, trust_level %p.\n", iface, trust_level );
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI result_get_Identity( IOnlineIdSystemTicketResult *iface, IOnlineIdSystemIdentity **value )
{
    TRACE( "iface %p, value %p.\n", iface, value );

    if (!value) return E_POINTER;
    /* the only identity this system can have is an online one, and there is none */
    *value = NULL;
    return S_OK;
}

static HRESULT WINAPI result_get_Status( IOnlineIdSystemTicketResult *iface, OnlineIdSystemTicketStatus *value )
{
    struct ticket_result *impl = impl_from_IOnlineIdSystemTicketResult( iface );

    TRACE( "iface %p, value %p.\n", iface, value );

    if (!value) return E_POINTER;
    *value = impl->status;
    return S_OK;
}

static HRESULT WINAPI result_get_ExtendedError( IOnlineIdSystemTicketResult *iface, HRESULT *value )
{
    struct ticket_result *impl = impl_from_IOnlineIdSystemTicketResult( iface );

    TRACE( "iface %p, value %p.\n", iface, value );

    if (!value) return E_POINTER;
    *value = impl->extended_error;
    return S_OK;
}

static IOnlineIdSystemTicketResultVtbl result_vtbl =
{
    result_QueryInterface,
    result_AddRef,
    result_Release,
    /* IInspectable methods */
    result_GetIids,
    result_GetRuntimeClassName,
    result_GetTrustLevel,
    /* IOnlineIdSystemTicketResult methods */
    result_get_Identity,
    result_get_Status,
    result_get_ExtendedError,
};

/* ---- IAsyncOperation<OnlineIdSystemTicketResult*>, completed when it is handed out ---- */

struct ticket_async
{
    IAsyncOperation_OnlineIdSystemTicketResult IAsyncOperation_OnlineIdSystemTicketResult_iface;
    IAsyncInfo IAsyncInfo_iface;
    LONG ref;
    CRITICAL_SECTION cs;
    IAsyncOperationCompletedHandler_OnlineIdSystemTicketResult *handler;
    IOnlineIdSystemTicketResult *result;
    BOOL closed;
};

static inline struct ticket_async *impl_from_IAsyncOperation( IAsyncOperation_OnlineIdSystemTicketResult *iface )
{
    return CONTAINING_RECORD( iface, struct ticket_async, IAsyncOperation_OnlineIdSystemTicketResult_iface );
}

static inline struct ticket_async *impl_from_IAsyncInfo( IAsyncInfo *iface )
{
    return CONTAINING_RECORD( iface, struct ticket_async, IAsyncInfo_iface );
}

static HRESULT async_query_interface( struct ticket_async *impl, REFIID iid, void **out )
{
    TRACE( "impl %p, iid %s, out %p.\n", impl, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown ) ||
        IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) ||
        IsEqualGUID( iid, &IID_IAsyncOperation_OnlineIdSystemTicketResult ))
        *out = &impl->IAsyncOperation_OnlineIdSystemTicketResult_iface;
    else if (IsEqualGUID( iid, &IID_IAsyncInfo ))
        *out = &impl->IAsyncInfo_iface;
    else
    {
        FIXME( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid( iid ) );
        *out = NULL;
        return E_NOINTERFACE;
    }

    IInspectable_AddRef( (IInspectable *)*out );
    return S_OK;
}

static ULONG async_add_ref( struct ticket_async *impl )
{
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "impl %p increasing refcount to %lu.\n", impl, ref );
    return ref;
}

static ULONG async_release( struct ticket_async *impl )
{
    ULONG ref = InterlockedDecrement( &impl->ref );

    TRACE( "impl %p decreasing refcount to %lu.\n", impl, ref );

    if (!ref)
    {
        if (impl->handler) IAsyncOperationCompletedHandler_OnlineIdSystemTicketResult_Release( impl->handler );
        if (impl->result) IOnlineIdSystemTicketResult_Release( impl->result );
        impl->cs.DebugInfo->Spare[0] = 0;
        DeleteCriticalSection( &impl->cs );
        free( impl );
    }
    return ref;
}

static HRESULT async_get_iids( ULONG *iid_count, IID **iids )
{
    IID *list;

    if (!iid_count || !iids) return E_POINTER;
    if (!(list = CoTaskMemAlloc( sizeof(*list) ))) return E_OUTOFMEMORY;
    *list = IID_IAsyncInfo;
    *iid_count = 1;
    *iids = list;
    return S_OK;
}

static HRESULT async_class_name( HSTRING *class_name )
{
    static const WCHAR name[] = L"Windows.Foundation.IAsyncOperation`1<Windows.Security.Authentication.OnlineId.OnlineIdSystemTicketResult>";

    if (!class_name) return E_POINTER;
    return WindowsCreateString( name, ARRAY_SIZE(name) - 1, class_name );
}

/* IAsyncOperation<OnlineIdSystemTicketResult*> */

static HRESULT WINAPI op_QueryInterface( IAsyncOperation_OnlineIdSystemTicketResult *iface, REFIID iid, void **out )
{
    return async_query_interface( impl_from_IAsyncOperation( iface ), iid, out );
}

static ULONG WINAPI op_AddRef( IAsyncOperation_OnlineIdSystemTicketResult *iface )
{
    return async_add_ref( impl_from_IAsyncOperation( iface ) );
}

static ULONG WINAPI op_Release( IAsyncOperation_OnlineIdSystemTicketResult *iface )
{
    return async_release( impl_from_IAsyncOperation( iface ) );
}

static HRESULT WINAPI op_GetIids( IAsyncOperation_OnlineIdSystemTicketResult *iface, ULONG *iid_count, IID **iids )
{
    TRACE( "iface %p, iid_count %p, iids %p.\n", iface, iid_count, iids );
    return async_get_iids( iid_count, iids );
}

static HRESULT WINAPI op_GetRuntimeClassName( IAsyncOperation_OnlineIdSystemTicketResult *iface, HSTRING *class_name )
{
    TRACE( "iface %p, class_name %p.\n", iface, class_name );
    return async_class_name( class_name );
}

static HRESULT WINAPI op_GetTrustLevel( IAsyncOperation_OnlineIdSystemTicketResult *iface, TrustLevel *trust_level )
{
    TRACE( "iface %p, trust_level %p.\n", iface, trust_level );
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI op_put_Completed( IAsyncOperation_OnlineIdSystemTicketResult *iface,
                                        IAsyncOperationCompletedHandler_OnlineIdSystemTicketResult *handler )
{
    struct ticket_async *impl = impl_from_IAsyncOperation( iface );

    TRACE( "iface %p, handler %p.\n", iface, handler );

    EnterCriticalSection( &impl->cs );
    if (impl->closed)
    {
        LeaveCriticalSection( &impl->cs );
        return E_ILLEGAL_METHOD_CALL;
    }
    if (impl->handler)
    {
        LeaveCriticalSection( &impl->cs );
        return E_ILLEGAL_DELEGATE_ASSIGNMENT;
    }
    if (handler)
    {
        IAsyncOperationCompletedHandler_OnlineIdSystemTicketResult_AddRef( handler );
        impl->handler = handler;
    }
    LeaveCriticalSection( &impl->cs );

    /* the operation has completed already: the handler runs now */
    if (handler) IAsyncOperationCompletedHandler_OnlineIdSystemTicketResult_Invoke( handler, iface, Completed );
    return S_OK;
}

static HRESULT WINAPI op_get_Completed( IAsyncOperation_OnlineIdSystemTicketResult *iface,
                                        IAsyncOperationCompletedHandler_OnlineIdSystemTicketResult **handler )
{
    struct ticket_async *impl = impl_from_IAsyncOperation( iface );

    TRACE( "iface %p, handler %p.\n", iface, handler );

    if (!handler) return E_POINTER;
    EnterCriticalSection( &impl->cs );
    if (impl->closed)
    {
        LeaveCriticalSection( &impl->cs );
        *handler = NULL;
        return E_ILLEGAL_METHOD_CALL;
    }
    if ((*handler = impl->handler)) IAsyncOperationCompletedHandler_OnlineIdSystemTicketResult_AddRef( *handler );
    LeaveCriticalSection( &impl->cs );
    return S_OK;
}

static HRESULT WINAPI op_GetResults( IAsyncOperation_OnlineIdSystemTicketResult *iface, IOnlineIdSystemTicketResult **results )
{
    struct ticket_async *impl = impl_from_IAsyncOperation( iface );

    TRACE( "iface %p, results %p.\n", iface, results );

    if (!results) return E_POINTER;
    EnterCriticalSection( &impl->cs );
    if (impl->closed)
    {
        LeaveCriticalSection( &impl->cs );
        *results = NULL;
        return E_ILLEGAL_METHOD_CALL;
    }
    *results = impl->result;
    IOnlineIdSystemTicketResult_AddRef( *results );
    LeaveCriticalSection( &impl->cs );
    return S_OK;
}

static IAsyncOperation_OnlineIdSystemTicketResultVtbl op_vtbl =
{
    op_QueryInterface,
    op_AddRef,
    op_Release,
    /* IInspectable methods */
    op_GetIids,
    op_GetRuntimeClassName,
    op_GetTrustLevel,
    /* IAsyncOperation<OnlineIdSystemTicketResult*> methods */
    op_put_Completed,
    op_get_Completed,
    op_GetResults,
};

/* IAsyncInfo */

static HRESULT WINAPI info_QueryInterface( IAsyncInfo *iface, REFIID iid, void **out )
{
    return async_query_interface( impl_from_IAsyncInfo( iface ), iid, out );
}

static ULONG WINAPI info_AddRef( IAsyncInfo *iface )
{
    return async_add_ref( impl_from_IAsyncInfo( iface ) );
}

static ULONG WINAPI info_Release( IAsyncInfo *iface )
{
    return async_release( impl_from_IAsyncInfo( iface ) );
}

static HRESULT WINAPI info_GetIids( IAsyncInfo *iface, ULONG *iid_count, IID **iids )
{
    TRACE( "iface %p, iid_count %p, iids %p.\n", iface, iid_count, iids );
    return async_get_iids( iid_count, iids );
}

static HRESULT WINAPI info_GetRuntimeClassName( IAsyncInfo *iface, HSTRING *class_name )
{
    TRACE( "iface %p, class_name %p.\n", iface, class_name );
    return async_class_name( class_name );
}

static HRESULT WINAPI info_GetTrustLevel( IAsyncInfo *iface, TrustLevel *trust_level )
{
    TRACE( "iface %p, trust_level %p.\n", iface, trust_level );
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI info_get_Id( IAsyncInfo *iface, UINT32 *id )
{
    struct ticket_async *impl = impl_from_IAsyncInfo( iface );

    TRACE( "iface %p, id %p.\n", iface, id );

    if (!id) return E_POINTER;
    if (impl->closed) { *id = 0; return E_ILLEGAL_METHOD_CALL; }
    *id = 1;
    return S_OK;
}

static HRESULT WINAPI info_get_Status( IAsyncInfo *iface, AsyncStatus *status )
{
    struct ticket_async *impl = impl_from_IAsyncInfo( iface );

    TRACE( "iface %p, status %p.\n", iface, status );

    if (!status) return E_POINTER;
    if (impl->closed) { *status = (AsyncStatus)4; return S_OK; }
    *status = Completed;
    return S_OK;
}

static HRESULT WINAPI info_get_ErrorCode( IAsyncInfo *iface, HRESULT *error_code )
{
    struct ticket_async *impl = impl_from_IAsyncInfo( iface );

    TRACE( "iface %p, error_code %p.\n", iface, error_code );

    if (!error_code) return E_POINTER;
    *error_code = impl->closed ? E_ILLEGAL_METHOD_CALL : S_OK;
    return S_OK;
}

static HRESULT WINAPI info_Cancel( IAsyncInfo *iface )
{
    TRACE( "iface %p.\n", iface );
    /* completed operations cannot be canceled */
    return S_OK;
}

static HRESULT WINAPI info_Close( IAsyncInfo *iface )
{
    struct ticket_async *impl = impl_from_IAsyncInfo( iface );

    TRACE( "iface %p.\n", iface );

    EnterCriticalSection( &impl->cs );
    impl->closed = TRUE;
    LeaveCriticalSection( &impl->cs );
    return S_OK;
}

static IAsyncInfoVtbl info_vtbl =
{
    info_QueryInterface,
    info_AddRef,
    info_Release,
    /* IInspectable methods */
    info_GetIids,
    info_GetRuntimeClassName,
    info_GetTrustLevel,
    /* IAsyncInfo methods */
    info_get_Id,
    info_get_Status,
    info_get_ErrorCode,
    info_Cancel,
    info_Close,
};

/* An operation that has completed with a ticket result of the given status. */
HRESULT create_ticket_async( OnlineIdSystemTicketStatus status, HRESULT extended_error,
                             IAsyncOperation_OnlineIdSystemTicketResult **operation )
{
    struct ticket_result *result;
    struct ticket_async *impl;

    if (!(result = calloc( 1, sizeof(*result) ))) return E_OUTOFMEMORY;
    result->IOnlineIdSystemTicketResult_iface.lpVtbl = &result_vtbl;
    result->ref = 1;
    result->status = status;
    result->extended_error = extended_error;

    if (!(impl = calloc( 1, sizeof(*impl) )))
    {
        free( result );
        return E_OUTOFMEMORY;
    }
    impl->IAsyncOperation_OnlineIdSystemTicketResult_iface.lpVtbl = &op_vtbl;
    impl->IAsyncInfo_iface.lpVtbl = &info_vtbl;
    impl->ref = 1;
    impl->result = &result->IOnlineIdSystemTicketResult_iface;
    InitializeCriticalSectionEx( &impl->cs, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO );
    impl->cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": ticket_async.cs");

    *operation = &impl->IAsyncOperation_OnlineIdSystemTicketResult_iface;
    return S_OK;
}
