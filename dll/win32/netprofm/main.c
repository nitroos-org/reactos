/*
 * PROJECT:     ReactOS Network List Manager
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The COM class NetworkListManager (INetworkListManager) of Windows Vista and later
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Qt 5.15 (Qt5Network.dll) creates a NetworkListManager when a QNetworkAccessManager starts a request and
 * calls GetNetworkConnections on it. With the class not registered CoCreateInstance fails with
 * REGDB_E_CLASSNOTREG, Qt keeps a null interface pointer and calls through it: the thread that opens the
 * connection of the Slovak eID client dies with an access violation after the TCP connection is up, and its
 * update check and the download of the Disig Web Signer never finish.
 *
 * The manager reports the network of the first IPv4 adapter that has an address: one network and one
 * connection, with Internet connectivity when the adapter has a default gateway and local network
 * connectivity otherwise. Without such an adapter it reports none and DISCONNECTED. The connectivity
 * events are accepted and never raised, names and categories cannot be changed, and the automation
 * (IDispatch) side has no type information.
 */

#include <stdarg.h>

#define COBJMACROS

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <objbase.h>
#include <ocidl.h>
#include <oleauto.h>
#include <initguid.h>
#include <netlistmgr.h>
#include <iphlpapi.h>
#include <wine/debug.h>

#ifndef CONNECT_E_NOCONNECTION
#define CONNECT_E_NOCONNECTION    ((HRESULT)0x80040200L)
#define CONNECT_E_ADVISELIMIT     ((HRESULT)0x80040201L)
#define CONNECT_E_CANNOTCONNECT   ((HRESULT)0x80040202L)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

WINE_DEFAULT_DEBUG_CHANNEL(netprofm);

static LONG g_objects;

/* ---------------------------------------------------------------------------------------------------- */
/* The network of this machine */

typedef struct
{
    GUID adapter;
    GUID connection;
    GUID network;
    NLM_CONNECTIVITY connectivity;
    FILETIME created;
} NET_STATE;

/* a.b.c.d to the address in network byte order, 0 for anything else */
static ULONG ParseIPv4(const char *Text)
{
    ULONG Value = 0;
    int Part, Digits, i;

    for (i = 0; i < 4; i++)
    {
        Part = 0;
        Digits = 0;
        while (*Text >= '0' && *Text <= '9')
        {
            Part = Part * 10 + (*Text++ - '0');
            if (++Digits > 3 || Part > 255)
                return 0;
        }
        if (!Digits || (i < 3 && *Text++ != '.'))
            return 0;
        Value |= (ULONG)Part << (8 * i);
    }
    return *Text ? 0 : Value;
}

static BOOL GetNetState(NET_STATE *State)
{
    IP_ADAPTER_INFO *Info, *Adapter;
    ULONG Size = 0;
    BOOL Found = FALSE;

    ZeroMemory(State, sizeof(*State));
    if (GetAdaptersInfo(NULL, &Size) != ERROR_BUFFER_OVERFLOW)
        return FALSE;
    Info = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Info)
        return FALSE;
    if (GetAdaptersInfo(Info, &Size) == ERROR_SUCCESS)
    {
        for (Adapter = Info; Adapter && !Found; Adapter = Adapter->Next)
        {
            ULONG Address = ParseIPv4(Adapter->IpAddressList.IpAddress.String);
            ULONG Gateway = ParseIPv4(Adapter->GatewayList.IpAddress.String);
            WCHAR Name[64];

            /* No address yet, or one of the automatic private range: no connectivity */
            if (!Address || Address == 0xFFFFFFFF || (Address & 0xFFFF) == 0xFEA9)
                continue;

            MultiByteToWideChar(CP_ACP, 0, Adapter->AdapterName, -1, Name, ARRAY_SIZE(Name));
            if (FAILED(CLSIDFromString(Name, &State->adapter)))
                ZeroMemory(&State->adapter, sizeof(State->adapter));

            State->connection = State->adapter;
            State->connection.Data1 ^= 0x1;
            State->network = State->adapter;
            State->network.Data1 ^= 0x2;
            State->connectivity = (Gateway && Gateway != 0xFFFFFFFF) ? NLM_CONNECTIVITY_IPV4_INTERNET
                                                                       : NLM_CONNECTIVITY_IPV4_LOCALNETWORK;
            GetSystemTimeAsFileTime(&State->created);
            Found = TRUE;
        }
    }
    HeapFree(GetProcessHeap(), 0, Info);
    return Found;
}

static VARIANT_BOOL IsInternet(NLM_CONNECTIVITY Connectivity)
{
    return (Connectivity & (NLM_CONNECTIVITY_IPV4_INTERNET | NLM_CONNECTIVITY_IPV6_INTERNET)) ? VARIANT_TRUE : VARIANT_FALSE;
}

/* ---------------------------------------------------------------------------------------------------- */
/* IDispatch without type information, shared by all the interfaces */

#define DISPATCH_STUBS(Prefix, Type) \
static HRESULT STDMETHODCALLTYPE Prefix##_GetTypeInfoCount(Type *This, UINT *pctinfo) \
{ \
    if (!pctinfo) return E_POINTER; \
    *pctinfo = 0; \
    return S_OK; \
} \
static HRESULT STDMETHODCALLTYPE Prefix##_GetTypeInfo(Type *This, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) \
{ \
    if (ppTInfo) *ppTInfo = NULL; \
    return E_NOTIMPL; \
} \
static HRESULT STDMETHODCALLTYPE Prefix##_GetIDsOfNames(Type *This, REFIID riid, LPOLESTR *rgszNames, UINT cNames, \
                                                        LCID lcid, DISPID *rgDispId) \
{ \
    return E_NOTIMPL; \
} \
static HRESULT STDMETHODCALLTYPE Prefix##_Invoke(Type *This, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, \
                                                 DISPPARAMS *pDispParams, VARIANT *pVarResult, EXCEPINFO *pExcepInfo, \
                                                 UINT *puArgErr) \
{ \
    return E_NOTIMPL; \
}

static HRESULT NewNetwork(const NET_STATE *State, INetwork **Out);
static HRESULT NewConnection(const NET_STATE *State, INetworkConnection **Out);
static HRESULT NewEnumNetworks(const NET_STATE *State, ULONG Count, IEnumNetworks **Out);
static HRESULT NewEnumConnections(const NET_STATE *State, ULONG Count, IEnumNetworkConnections **Out);

/* ---------------------------------------------------------------------------------------------------- */
/* INetworkConnection */

typedef struct
{
    INetworkConnection iface;
    LONG ref;
    NET_STATE state;
} CONNECTION;

static CONNECTION *Connection_from(INetworkConnection *iface) { return CONTAINING_RECORD(iface, CONNECTION, iface); }

static HRESULT STDMETHODCALLTYPE Connection_QueryInterface(INetworkConnection *iface, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IDispatch) || IsEqualIID(riid, &IID_INetworkConnection))
    {
        *out = iface;
        INetworkConnection_AddRef(iface);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Connection_AddRef(INetworkConnection *iface)
{
    return InterlockedIncrement(&Connection_from(iface)->ref);
}

static ULONG STDMETHODCALLTYPE Connection_Release(INetworkConnection *iface)
{
    CONNECTION *This = Connection_from(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
    {
        HeapFree(GetProcessHeap(), 0, This);
        InterlockedDecrement(&g_objects);
    }
    return ref;
}

DISPATCH_STUBS(Connection, INetworkConnection)

static HRESULT STDMETHODCALLTYPE Connection_GetNetwork(INetworkConnection *iface, INetwork **out)
{
    if (!out) return E_POINTER;
    return NewNetwork(&Connection_from(iface)->state, out);
}

static HRESULT STDMETHODCALLTYPE Connection_get_IsConnectedToInternet(INetworkConnection *iface, VARIANT_BOOL *out)
{
    if (!out) return E_POINTER;
    *out = IsInternet(Connection_from(iface)->state.connectivity);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Connection_get_IsConnected(INetworkConnection *iface, VARIANT_BOOL *out)
{
    if (!out) return E_POINTER;
    *out = Connection_from(iface)->state.connectivity ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Connection_GetConnectivity(INetworkConnection *iface, NLM_CONNECTIVITY *out)
{
    if (!out) return E_POINTER;
    *out = Connection_from(iface)->state.connectivity;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Connection_GetConnectionId(INetworkConnection *iface, GUID *out)
{
    if (!out) return E_POINTER;
    *out = Connection_from(iface)->state.connection;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Connection_GetAdapterId(INetworkConnection *iface, GUID *out)
{
    if (!out) return E_POINTER;
    *out = Connection_from(iface)->state.adapter;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Connection_GetDomainType(INetworkConnection *iface, NLM_DOMAIN_TYPE *out)
{
    if (!out) return E_POINTER;
    *out = NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK;
    return S_OK;
}

static INetworkConnectionVtbl ConnectionVtbl =
{
    Connection_QueryInterface, Connection_AddRef, Connection_Release,
    Connection_GetTypeInfoCount, Connection_GetTypeInfo, Connection_GetIDsOfNames, Connection_Invoke,
    Connection_GetNetwork, Connection_get_IsConnectedToInternet, Connection_get_IsConnected,
    Connection_GetConnectivity, Connection_GetConnectionId, Connection_GetAdapterId, Connection_GetDomainType
};

static HRESULT NewConnection(const NET_STATE *State, INetworkConnection **Out)
{
    CONNECTION *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));

    if (!This) return E_OUTOFMEMORY;
    This->iface.lpVtbl = &ConnectionVtbl;
    This->ref = 1;
    This->state = *State;
    InterlockedIncrement(&g_objects);
    *Out = &This->iface;
    return S_OK;
}

/* ---------------------------------------------------------------------------------------------------- */
/* INetwork */

typedef struct
{
    INetwork iface;
    LONG ref;
    NET_STATE state;
} NETWORK;

static NETWORK *Network_from(INetwork *iface) { return CONTAINING_RECORD(iface, NETWORK, iface); }

static HRESULT STDMETHODCALLTYPE Network_QueryInterface(INetwork *iface, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IDispatch) || IsEqualIID(riid, &IID_INetwork))
    {
        *out = iface;
        INetwork_AddRef(iface);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Network_AddRef(INetwork *iface)
{
    return InterlockedIncrement(&Network_from(iface)->ref);
}

static ULONG STDMETHODCALLTYPE Network_Release(INetwork *iface)
{
    NETWORK *This = Network_from(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
    {
        HeapFree(GetProcessHeap(), 0, This);
        InterlockedDecrement(&g_objects);
    }
    return ref;
}

DISPATCH_STUBS(Network, INetwork)

static HRESULT STDMETHODCALLTYPE Network_GetName(INetwork *iface, BSTR *out)
{
    if (!out) return E_POINTER;
    *out = SysAllocString(L"Network");
    return *out ? S_OK : E_OUTOFMEMORY;
}

static HRESULT STDMETHODCALLTYPE Network_SetName(INetwork *iface, BSTR name)
{
    return E_ACCESSDENIED;
}

static HRESULT STDMETHODCALLTYPE Network_GetDescription(INetwork *iface, BSTR *out)
{
    if (!out) return E_POINTER;
    *out = SysAllocString(L"Network");
    return *out ? S_OK : E_OUTOFMEMORY;
}

static HRESULT STDMETHODCALLTYPE Network_SetDescription(INetwork *iface, BSTR description)
{
    return E_ACCESSDENIED;
}

static HRESULT STDMETHODCALLTYPE Network_GetNetworkId(INetwork *iface, GUID *out)
{
    if (!out) return E_POINTER;
    *out = Network_from(iface)->state.network;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Network_GetDomainType(INetwork *iface, NLM_DOMAIN_TYPE *out)
{
    if (!out) return E_POINTER;
    *out = NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Network_GetNetworkConnections(INetwork *iface, IEnumNetworkConnections **out)
{
    if (!out) return E_POINTER;
    return NewEnumConnections(&Network_from(iface)->state, 1, out);
}

static HRESULT STDMETHODCALLTYPE Network_GetTimeCreatedAndConnected(INetwork *iface, DWORD *createdLow, DWORD *createdHigh,
                                                                    DWORD *connectedLow, DWORD *connectedHigh)
{
    const FILETIME *Time = &Network_from(iface)->state.created;

    if (!createdLow || !createdHigh || !connectedLow || !connectedHigh) return E_POINTER;
    *createdLow = *connectedLow = Time->dwLowDateTime;
    *createdHigh = *connectedHigh = Time->dwHighDateTime;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Network_get_IsConnectedToInternet(INetwork *iface, VARIANT_BOOL *out)
{
    if (!out) return E_POINTER;
    *out = IsInternet(Network_from(iface)->state.connectivity);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Network_get_IsConnected(INetwork *iface, VARIANT_BOOL *out)
{
    if (!out) return E_POINTER;
    *out = Network_from(iface)->state.connectivity ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Network_GetConnectivity(INetwork *iface, NLM_CONNECTIVITY *out)
{
    if (!out) return E_POINTER;
    *out = Network_from(iface)->state.connectivity;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Network_GetCategory(INetwork *iface, NLM_NETWORK_CATEGORY *out)
{
    if (!out) return E_POINTER;
    *out = NLM_NETWORK_CATEGORY_PUBLIC;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Network_SetCategory(INetwork *iface, NLM_NETWORK_CATEGORY category)
{
    return E_ACCESSDENIED;
}

static INetworkVtbl NetworkVtbl =
{
    Network_QueryInterface, Network_AddRef, Network_Release,
    Network_GetTypeInfoCount, Network_GetTypeInfo, Network_GetIDsOfNames, Network_Invoke,
    Network_GetName, Network_SetName, Network_GetDescription, Network_SetDescription, Network_GetNetworkId,
    Network_GetDomainType, Network_GetNetworkConnections, Network_GetTimeCreatedAndConnected,
    Network_get_IsConnectedToInternet, Network_get_IsConnected, Network_GetConnectivity,
    Network_GetCategory, Network_SetCategory
};

static HRESULT NewNetwork(const NET_STATE *State, INetwork **Out)
{
    NETWORK *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));

    if (!This) return E_OUTOFMEMORY;
    This->iface.lpVtbl = &NetworkVtbl;
    This->ref = 1;
    This->state = *State;
    InterlockedIncrement(&g_objects);
    *Out = &This->iface;
    return S_OK;
}

/* ---------------------------------------------------------------------------------------------------- */
/* IEnumNetworks and IEnumNetworkConnections: zero or one element */

typedef struct
{
    IEnumNetworks iface;
    LONG ref;
    NET_STATE state;
    ULONG count, pos;
} ENUM_NETWORKS;

static ENUM_NETWORKS *EnumNetworks_from(IEnumNetworks *iface) { return CONTAINING_RECORD(iface, ENUM_NETWORKS, iface); }

static HRESULT STDMETHODCALLTYPE EnumNetworks_QueryInterface(IEnumNetworks *iface, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IDispatch) || IsEqualIID(riid, &IID_IEnumNetworks))
    {
        *out = iface;
        IEnumNetworks_AddRef(iface);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE EnumNetworks_AddRef(IEnumNetworks *iface)
{
    return InterlockedIncrement(&EnumNetworks_from(iface)->ref);
}

static ULONG STDMETHODCALLTYPE EnumNetworks_Release(IEnumNetworks *iface)
{
    ENUM_NETWORKS *This = EnumNetworks_from(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
    {
        HeapFree(GetProcessHeap(), 0, This);
        InterlockedDecrement(&g_objects);
    }
    return ref;
}

DISPATCH_STUBS(EnumNetworks, IEnumNetworks)

static HRESULT STDMETHODCALLTYPE EnumNetworks_get__NewEnum(IEnumNetworks *iface, IEnumVARIANT **out)
{
    if (out) *out = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE EnumNetworks_Next(IEnumNetworks *iface, ULONG celt, INetwork **items, ULONG *fetched)
{
    ENUM_NETWORKS *This = EnumNetworks_from(iface);
    ULONG Done = 0;
    HRESULT hr = S_OK;

    if (!items || (!fetched && celt != 1)) return E_POINTER;
    while (Done < celt && This->pos < This->count)
    {
        hr = NewNetwork(&This->state, &items[Done]);
        if (FAILED(hr))
            break;
        Done++;
        This->pos++;
    }
    if (fetched) *fetched = Done;
    return FAILED(hr) ? hr : (Done == celt ? S_OK : S_FALSE);
}

static HRESULT STDMETHODCALLTYPE EnumNetworks_Skip(IEnumNetworks *iface, ULONG celt)
{
    ENUM_NETWORKS *This = EnumNetworks_from(iface);

    if (celt > This->count - This->pos)
    {
        This->pos = This->count;
        return S_FALSE;
    }
    This->pos += celt;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE EnumNetworks_Reset(IEnumNetworks *iface)
{
    EnumNetworks_from(iface)->pos = 0;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE EnumNetworks_Clone(IEnumNetworks *iface, IEnumNetworks **out)
{
    ENUM_NETWORKS *This = EnumNetworks_from(iface);
    HRESULT hr;

    if (!out) return E_POINTER;
    hr = NewEnumNetworks(&This->state, This->count, out);
    if (SUCCEEDED(hr))
        EnumNetworks_from(*out)->pos = This->pos;
    return hr;
}

static IEnumNetworksVtbl EnumNetworksVtbl =
{
    EnumNetworks_QueryInterface, EnumNetworks_AddRef, EnumNetworks_Release,
    EnumNetworks_GetTypeInfoCount, EnumNetworks_GetTypeInfo, EnumNetworks_GetIDsOfNames, EnumNetworks_Invoke,
    EnumNetworks_get__NewEnum, EnumNetworks_Next, EnumNetworks_Skip, EnumNetworks_Reset, EnumNetworks_Clone
};

static HRESULT NewEnumNetworks(const NET_STATE *State, ULONG Count, IEnumNetworks **Out)
{
    ENUM_NETWORKS *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));

    if (!This) return E_OUTOFMEMORY;
    This->iface.lpVtbl = &EnumNetworksVtbl;
    This->ref = 1;
    This->state = *State;
    This->count = Count;
    InterlockedIncrement(&g_objects);
    *Out = &This->iface;
    return S_OK;
}

typedef struct
{
    IEnumNetworkConnections iface;
    LONG ref;
    NET_STATE state;
    ULONG count, pos;
} ENUM_CONNECTIONS;

static ENUM_CONNECTIONS *EnumConnections_from(IEnumNetworkConnections *iface)
{
    return CONTAINING_RECORD(iface, ENUM_CONNECTIONS, iface);
}

static HRESULT STDMETHODCALLTYPE EnumConnections_QueryInterface(IEnumNetworkConnections *iface, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IDispatch) || IsEqualIID(riid, &IID_IEnumNetworkConnections))
    {
        *out = iface;
        IEnumNetworkConnections_AddRef(iface);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE EnumConnections_AddRef(IEnumNetworkConnections *iface)
{
    return InterlockedIncrement(&EnumConnections_from(iface)->ref);
}

static ULONG STDMETHODCALLTYPE EnumConnections_Release(IEnumNetworkConnections *iface)
{
    ENUM_CONNECTIONS *This = EnumConnections_from(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
    {
        HeapFree(GetProcessHeap(), 0, This);
        InterlockedDecrement(&g_objects);
    }
    return ref;
}

DISPATCH_STUBS(EnumConnections, IEnumNetworkConnections)

static HRESULT STDMETHODCALLTYPE EnumConnections_get__NewEnum(IEnumNetworkConnections *iface, IEnumVARIANT **out)
{
    if (out) *out = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE EnumConnections_Next(IEnumNetworkConnections *iface, ULONG celt, INetworkConnection **items,
                                                      ULONG *fetched)
{
    ENUM_CONNECTIONS *This = EnumConnections_from(iface);
    ULONG Done = 0;
    HRESULT hr = S_OK;

    if (!items || (!fetched && celt != 1)) return E_POINTER;
    while (Done < celt && This->pos < This->count)
    {
        hr = NewConnection(&This->state, &items[Done]);
        if (FAILED(hr))
            break;
        Done++;
        This->pos++;
    }
    if (fetched) *fetched = Done;
    return FAILED(hr) ? hr : (Done == celt ? S_OK : S_FALSE);
}

static HRESULT STDMETHODCALLTYPE EnumConnections_Skip(IEnumNetworkConnections *iface, ULONG celt)
{
    ENUM_CONNECTIONS *This = EnumConnections_from(iface);

    if (celt > This->count - This->pos)
    {
        This->pos = This->count;
        return S_FALSE;
    }
    This->pos += celt;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE EnumConnections_Reset(IEnumNetworkConnections *iface)
{
    EnumConnections_from(iface)->pos = 0;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE EnumConnections_Clone(IEnumNetworkConnections *iface, IEnumNetworkConnections **out)
{
    ENUM_CONNECTIONS *This = EnumConnections_from(iface);
    HRESULT hr;

    if (!out) return E_POINTER;
    hr = NewEnumConnections(&This->state, This->count, out);
    if (SUCCEEDED(hr))
        EnumConnections_from(*out)->pos = This->pos;
    return hr;
}

static IEnumNetworkConnectionsVtbl EnumConnectionsVtbl =
{
    EnumConnections_QueryInterface, EnumConnections_AddRef, EnumConnections_Release,
    EnumConnections_GetTypeInfoCount, EnumConnections_GetTypeInfo, EnumConnections_GetIDsOfNames, EnumConnections_Invoke,
    EnumConnections_get__NewEnum, EnumConnections_Next, EnumConnections_Skip, EnumConnections_Reset, EnumConnections_Clone
};

static HRESULT NewEnumConnections(const NET_STATE *State, ULONG Count, IEnumNetworkConnections **Out)
{
    ENUM_CONNECTIONS *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));

    if (!This) return E_OUTOFMEMORY;
    This->iface.lpVtbl = &EnumConnectionsVtbl;
    This->ref = 1;
    This->state = *State;
    This->count = Count;
    InterlockedIncrement(&g_objects);
    *Out = &This->iface;
    return S_OK;
}

/* ---------------------------------------------------------------------------------------------------- */
/* INetworkListManager and its connection points */

typedef struct NLM NLM;

typedef struct
{
    IConnectionPoint iface;
    NLM *manager;
    const IID *iid;
    IUnknown *sink;
    DWORD cookie;
} CONNECTION_POINT;

struct NLM
{
    INetworkListManager iface;
    IConnectionPointContainer container;
    LONG ref;
    CONNECTION_POINT points[3];
};

static NLM *Nlm_from(INetworkListManager *iface) { return CONTAINING_RECORD(iface, NLM, iface); }
static NLM *Nlm_from_container(IConnectionPointContainer *iface) { return CONTAINING_RECORD(iface, NLM, container); }
static CONNECTION_POINT *Point_from(IConnectionPoint *iface) { return CONTAINING_RECORD(iface, CONNECTION_POINT, iface); }

static HRESULT STDMETHODCALLTYPE Nlm_QueryInterface(INetworkListManager *iface, REFIID riid, void **out)
{
    NLM *This = Nlm_from(iface);

    if (!out) return E_POINTER;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IDispatch) || IsEqualIID(riid, &IID_INetworkListManager))
        *out = &This->iface;
    else if (IsEqualIID(riid, &IID_IConnectionPointContainer))
        *out = &This->container;
    else
    {
        *out = NULL;
        return E_NOINTERFACE;
    }
    INetworkListManager_AddRef(&This->iface);
    return S_OK;
}

static ULONG STDMETHODCALLTYPE Nlm_AddRef(INetworkListManager *iface)
{
    return InterlockedIncrement(&Nlm_from(iface)->ref);
}

static ULONG STDMETHODCALLTYPE Nlm_Release(INetworkListManager *iface)
{
    NLM *This = Nlm_from(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    if (!ref)
    {
        ULONG i;

        for (i = 0; i < ARRAY_SIZE(This->points); i++)
            if (This->points[i].sink)
                IUnknown_Release(This->points[i].sink);
        HeapFree(GetProcessHeap(), 0, This);
        InterlockedDecrement(&g_objects);
    }
    return ref;
}

DISPATCH_STUBS(Nlm, INetworkListManager)

static HRESULT STDMETHODCALLTYPE Nlm_GetNetworks(INetworkListManager *iface, NLM_ENUM_NETWORK flags, IEnumNetworks **out)
{
    NET_STATE State;
    BOOL Have;

    if (!out) return E_POINTER;
    *out = NULL;
    Have = GetNetState(&State);
    return NewEnumNetworks(&State, (Have && (flags & NLM_ENUM_NETWORK_CONNECTED)) ? 1 : 0, out);
}

static HRESULT STDMETHODCALLTYPE Nlm_GetNetwork(INetworkListManager *iface, GUID id, INetwork **out)
{
    NET_STATE State;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!GetNetState(&State) || !IsEqualGUID(&State.network, &id))
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    return NewNetwork(&State, out);
}

static HRESULT STDMETHODCALLTYPE Nlm_GetNetworkConnections(INetworkListManager *iface, IEnumNetworkConnections **out)
{
    NET_STATE State;
    BOOL Have;

    if (!out) return E_POINTER;
    *out = NULL;
    Have = GetNetState(&State);
    return NewEnumConnections(&State, Have ? 1 : 0, out);
}

static HRESULT STDMETHODCALLTYPE Nlm_GetNetworkConnection(INetworkListManager *iface, GUID id, INetworkConnection **out)
{
    NET_STATE State;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!GetNetState(&State) || !IsEqualGUID(&State.connection, &id))
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    return NewConnection(&State, out);
}

static HRESULT STDMETHODCALLTYPE Nlm_IsConnectedToInternet(INetworkListManager *iface, VARIANT_BOOL *out)
{
    NET_STATE State;

    if (!out) return E_POINTER;
    *out = GetNetState(&State) ? IsInternet(State.connectivity) : VARIANT_FALSE;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Nlm_IsConnected(INetworkListManager *iface, VARIANT_BOOL *out)
{
    NET_STATE State;

    if (!out) return E_POINTER;
    *out = GetNetState(&State) ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Nlm_GetConnectivity(INetworkListManager *iface, NLM_CONNECTIVITY *out)
{
    NET_STATE State;

    if (!out) return E_POINTER;
    *out = GetNetState(&State) ? State.connectivity : NLM_CONNECTIVITY_DISCONNECTED;
    return S_OK;
}

static INetworkListManagerVtbl NlmVtbl =
{
    Nlm_QueryInterface, Nlm_AddRef, Nlm_Release,
    Nlm_GetTypeInfoCount, Nlm_GetTypeInfo, Nlm_GetIDsOfNames, Nlm_Invoke,
    Nlm_GetNetworks, Nlm_GetNetwork, Nlm_GetNetworkConnections, Nlm_GetNetworkConnection,
    Nlm_IsConnectedToInternet, Nlm_IsConnected, Nlm_GetConnectivity
};

/* IConnectionPoint: one sink per point, never called */

static HRESULT STDMETHODCALLTYPE Point_QueryInterface(IConnectionPoint *iface, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IConnectionPoint))
    {
        *out = iface;
        IConnectionPoint_AddRef(iface);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Point_AddRef(IConnectionPoint *iface)
{
    return INetworkListManager_AddRef(&Point_from(iface)->manager->iface);
}

static ULONG STDMETHODCALLTYPE Point_Release(IConnectionPoint *iface)
{
    return INetworkListManager_Release(&Point_from(iface)->manager->iface);
}

static HRESULT STDMETHODCALLTYPE Point_GetConnectionInterface(IConnectionPoint *iface, IID *out)
{
    if (!out) return E_POINTER;
    *out = *Point_from(iface)->iid;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Point_GetConnectionPointContainer(IConnectionPoint *iface, IConnectionPointContainer **out)
{
    if (!out) return E_POINTER;
    *out = &Point_from(iface)->manager->container;
    IConnectionPointContainer_AddRef(*out);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Point_Advise(IConnectionPoint *iface, IUnknown *sink, DWORD *cookie)
{
    CONNECTION_POINT *This = Point_from(iface);
    IUnknown *Typed;
    HRESULT hr;

    if (!sink || !cookie) return E_POINTER;
    if (This->sink) return CONNECT_E_ADVISELIMIT;
    hr = IUnknown_QueryInterface(sink, This->iid, (void **)&Typed);
    if (FAILED(hr)) return CONNECT_E_CANNOTCONNECT;
    This->sink = Typed;
    This->cookie++;
    *cookie = This->cookie;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Point_Unadvise(IConnectionPoint *iface, DWORD cookie)
{
    CONNECTION_POINT *This = Point_from(iface);

    if (!This->sink || cookie != This->cookie) return CONNECT_E_NOCONNECTION;
    IUnknown_Release(This->sink);
    This->sink = NULL;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Point_EnumConnections(IConnectionPoint *iface, IEnumConnections **out)
{
    if (out) *out = NULL;
    return E_NOTIMPL;
}

static IConnectionPointVtbl PointVtbl =
{
    Point_QueryInterface, Point_AddRef, Point_Release, Point_GetConnectionInterface, Point_GetConnectionPointContainer,
    Point_Advise, Point_Unadvise, Point_EnumConnections
};

static HRESULT STDMETHODCALLTYPE Container_QueryInterface(IConnectionPointContainer *iface, REFIID riid, void **out)
{
    return Nlm_QueryInterface(&Nlm_from_container(iface)->iface, riid, out);
}

static ULONG STDMETHODCALLTYPE Container_AddRef(IConnectionPointContainer *iface)
{
    return Nlm_AddRef(&Nlm_from_container(iface)->iface);
}

static ULONG STDMETHODCALLTYPE Container_Release(IConnectionPointContainer *iface)
{
    return Nlm_Release(&Nlm_from_container(iface)->iface);
}

static HRESULT STDMETHODCALLTYPE Container_EnumConnectionPoints(IConnectionPointContainer *iface, IEnumConnectionPoints **out)
{
    if (out) *out = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE Container_FindConnectionPoint(IConnectionPointContainer *iface, REFIID riid,
                                                               IConnectionPoint **out)
{
    NLM *This = Nlm_from_container(iface);
    ULONG i;

    if (!out) return E_POINTER;
    for (i = 0; i < ARRAY_SIZE(This->points); i++)
    {
        if (IsEqualIID(riid, This->points[i].iid))
        {
            *out = &This->points[i].iface;
            IConnectionPoint_AddRef(*out);
            return S_OK;
        }
    }
    *out = NULL;
    return CONNECT_E_NOCONNECTION;
}

static IConnectionPointContainerVtbl ContainerVtbl =
{
    Container_QueryInterface, Container_AddRef, Container_Release,
    Container_EnumConnectionPoints, Container_FindConnectionPoint
};

static HRESULT NewManager(REFIID riid, void **out)
{
    NLM *This = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*This));
    HRESULT hr;
    ULONG i;
    static const IID *Points[3] = { &IID_INetworkListManagerEvents, &IID_INetworkConnectionEvents, &IID_INetworkEvents };

    if (!This) return E_OUTOFMEMORY;
    This->iface.lpVtbl = &NlmVtbl;
    This->container.lpVtbl = &ContainerVtbl;
    This->ref = 1;
    for (i = 0; i < ARRAY_SIZE(This->points); i++)
    {
        This->points[i].iface.lpVtbl = &PointVtbl;
        This->points[i].manager = This;
        This->points[i].iid = Points[i];
    }
    InterlockedIncrement(&g_objects);
    hr = INetworkListManager_QueryInterface(&This->iface, riid, out);
    INetworkListManager_Release(&This->iface);
    return hr;
}

/* ---------------------------------------------------------------------------------------------------- */
/* The class factory and the DLL entry points */

static HRESULT STDMETHODCALLTYPE Factory_QueryInterface(IClassFactory *iface, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IClassFactory))
    {
        *out = iface;
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Factory_AddRef(IClassFactory *iface) { return 2; }
static ULONG STDMETHODCALLTYPE Factory_Release(IClassFactory *iface) { return 1; }

static HRESULT STDMETHODCALLTYPE Factory_CreateInstance(IClassFactory *iface, IUnknown *outer, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (outer) return CLASS_E_NOAGGREGATION;
    return NewManager(riid, out);
}

static HRESULT STDMETHODCALLTYPE Factory_LockServer(IClassFactory *iface, BOOL lock)
{
    return S_OK;
}

static IClassFactoryVtbl FactoryVtbl =
{
    Factory_QueryInterface, Factory_AddRef, Factory_Release, Factory_CreateInstance, Factory_LockServer
};

static IClassFactory g_factory = { &FactoryVtbl };

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualCLSID(clsid, &CLSID_NetworkListManager))
        return CLASS_E_CLASSNOTAVAILABLE;
    return IClassFactory_QueryInterface(&g_factory, riid, out);
}

HRESULT WINAPI DllCanUnloadNow(void)
{
    return g_objects ? S_FALSE : S_OK;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(instance);
    return TRUE;
}
