/*
 * PROJECT:         ReactOS API Tests
 * LICENSE:         LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:         Tests for the Network List Manager COM class (netprofm.dll)
 * COPYRIGHT:       Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Qt 5.15 creates a NetworkListManager when a request starts and calls GetNetworkConnections on it. With
 * the class missing the interface pointer stays null and the calling thread dies.
 */

#include "com_apitest.h"
#include <oleauto.h>
#include <netlistmgr.h>

#ifndef CONNECT_E_NOCONNECTION
#define CONNECT_E_NOCONNECTION    ((HRESULT)0x80040200L)
#define CONNECT_E_ADVISELIMIT     ((HRESULT)0x80040201L)
#define CONNECT_E_CANNOTCONNECT   ((HRESULT)0x80040202L)
#endif

typedef struct { INetworkListManagerEvents iface; LONG ref; } SINK;

static HRESULT STDMETHODCALLTYPE Sink_QueryInterface(INetworkListManagerEvents *iface, REFIID riid, void **out)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_INetworkListManagerEvents))
    {
        *out = iface;
        INetworkListManagerEvents_AddRef(iface);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Sink_AddRef(INetworkListManagerEvents *iface)
{
    return InterlockedIncrement(&CONTAINING_RECORD(iface, SINK, iface)->ref);
}

static ULONG STDMETHODCALLTYPE Sink_Release(INetworkListManagerEvents *iface)
{
    return InterlockedDecrement(&CONTAINING_RECORD(iface, SINK, iface)->ref);
}

static HRESULT STDMETHODCALLTYPE Sink_ConnectivityChanged(INetworkListManagerEvents *iface, NLM_CONNECTIVITY connectivity)
{
    return S_OK;
}

static INetworkListManagerEventsVtbl SinkVtbl =
{
    Sink_QueryInterface, Sink_AddRef, Sink_Release, Sink_ConnectivityChanged
};

START_TEST(netprofm)
{
    INetworkListManager *Manager = NULL, *Again = NULL;
    IUnknown *Unknown = NULL, *Unknown2 = NULL, *Outer = NULL;
    IDispatch *Dispatch = NULL;
    IConnectionPointContainer *Container = NULL;
    IConnectionPoint *Point = NULL;
    IEnumNetworkConnections *Connections = NULL;
    IEnumNetworks *Networks = NULL;
    INetworkConnection *Connection = NULL, *Same = NULL;
    INetwork *Network = NULL, *Net2 = NULL;
    NLM_CONNECTIVITY Connectivity, Other;
    VARIANT_BOOL Connected, Internet;
    GUID ConnectionId, NetworkId, Zero = {0};
    SINK Sink = { { &SinkVtbl }, 1 };
    ULONG Fetched;
    DWORD Cookie = 0, Cookie2 = 0;
    BSTR Name;
    HRESULT hr;
    BOOL HaveNetwork;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(SUCCEEDED(hr), "CoInitializeEx returned 0x%08lx\n", hr);

    hr = CoCreateInstance(&CLSID_NetworkListManager, NULL, CLSCTX_INPROC_SERVER, &IID_INetworkListManager,
                          (void **)&Manager);
    ok(hr == S_OK, "CoCreateInstance(NetworkListManager) returned 0x%08lx\n", hr);
    if (!Manager)
    {
        skip("no Network List Manager\n");
        goto Done;
    }

    /* No aggregation */
    hr = CoCreateInstance(&CLSID_NetworkListManager, (IUnknown *)Manager, CLSCTX_INPROC_SERVER, &IID_IUnknown,
                          (void **)&Outer);
    ok(hr == CLASS_E_NOAGGREGATION, "aggregated CoCreateInstance returned 0x%08lx\n", hr);
    if (Outer)
        IUnknown_Release(Outer);

    /* Interfaces, and one identity for IUnknown */
    hr = INetworkListManager_QueryInterface(Manager, &IID_IDispatch, (void **)&Dispatch);
    ok(hr == S_OK, "IDispatch: 0x%08lx\n", hr);
    if (Dispatch)
        IDispatch_Release(Dispatch);
    hr = INetworkListManager_QueryInterface(Manager, &IID_IConnectionPointContainer, (void **)&Container);
    ok(hr == S_OK, "IConnectionPointContainer: 0x%08lx\n", hr);
    hr = INetworkListManager_QueryInterface(Manager, &IID_IUnknown, (void **)&Unknown);
    ok(hr == S_OK, "IUnknown: 0x%08lx\n", hr);
    if (Container)
    {
        hr = IConnectionPointContainer_QueryInterface(Container, &IID_IUnknown, (void **)&Unknown2);
        ok(hr == S_OK && Unknown2 == Unknown, "IUnknown identity: 0x%08lx %p %p\n", hr, Unknown2, Unknown);
        if (Unknown2)
            IUnknown_Release(Unknown2);
        hr = IConnectionPointContainer_QueryInterface(Container, &IID_INetworkListManager, (void **)&Again);
        ok(hr == S_OK && Again == Manager, "INetworkListManager from the container: 0x%08lx\n", hr);
        if (Again)
            INetworkListManager_Release(Again);
    }
    if (Unknown)
        IUnknown_Release(Unknown);
    hr = INetworkListManager_QueryInterface(Manager, &IID_IEnumNetworks, (void **)&Unknown);
    ok(hr == E_NOINTERFACE && !Unknown, "IEnumNetworks: 0x%08lx\n", hr);

    /* The state: connectivity, IsConnected and IsConnectedToInternet agree */
    Connectivity = 0xdeadbeef;
    hr = INetworkListManager_GetConnectivity(Manager, &Connectivity);
    ok(hr == S_OK && Connectivity != 0xdeadbeef, "GetConnectivity: 0x%08lx %lx\n", hr, (ULONG)Connectivity);
    Connected = 0x1234;
    hr = INetworkListManager_IsConnected(Manager, &Connected);
    ok(hr == S_OK, "IsConnected: 0x%08lx\n", hr);
    ok((Connected == VARIANT_TRUE) == (Connectivity != NLM_CONNECTIVITY_DISCONNECTED), "IsConnected %d, connectivity %lx\n",
       Connected, (ULONG)Connectivity);
    Internet = 0x1234;
    hr = INetworkListManager_IsConnectedToInternet(Manager, &Internet);
    ok(hr == S_OK, "IsConnectedToInternet: 0x%08lx\n", hr);
    ok((Internet == VARIANT_TRUE) == !!(Connectivity & (NLM_CONNECTIVITY_IPV4_INTERNET | NLM_CONNECTIVITY_IPV6_INTERNET)),
       "IsConnectedToInternet %d, connectivity %lx\n", Internet, (ULONG)Connectivity);
    HaveNetwork = Connectivity != NLM_CONNECTIVITY_DISCONNECTED;

    /* The enumerators: one connection and one network when connected, none otherwise */
    hr = INetworkListManager_GetNetworkConnections(Manager, &Connections);
    ok(hr == S_OK && Connections, "GetNetworkConnections: 0x%08lx\n", hr);
    if (Connections)
    {
        Fetched = 0xdeadbeef;
        hr = IEnumNetworkConnections_Next(Connections, 1, &Connection, &Fetched);
        ok(hr == (HaveNetwork ? S_OK : S_FALSE), "Next: 0x%08lx\n", hr);
        ok(Fetched == (HaveNetwork ? 1 : 0), "fetched %lu\n", Fetched);
        if (HaveNetwork && Connection)
        {
            Other = 0xdeadbeef;
            hr = INetworkConnection_GetConnectivity(Connection, &Other);
            ok(hr == S_OK && Other == Connectivity, "connection connectivity 0x%08lx %lx, manager %lx\n", hr, (ULONG)Other,
               (ULONG)Connectivity);
            hr = INetworkConnection_get_IsConnected(Connection, &Connected);
            ok(hr == S_OK && Connected == VARIANT_TRUE, "connection IsConnected 0x%08lx %d\n", hr, Connected);
            ZeroMemory(&ConnectionId, sizeof(ConnectionId));
            hr = INetworkConnection_GetConnectionId(Connection, &ConnectionId);
            ok(hr == S_OK, "GetConnectionId: 0x%08lx\n", hr);
            hr = INetworkListManager_GetNetworkConnection(Manager, ConnectionId, &Same);
            ok(hr == S_OK && Same, "GetNetworkConnection: 0x%08lx\n", hr);
            if (Same)
                INetworkConnection_Release(Same);
            hr = INetworkConnection_GetNetwork(Connection, &Network);
            ok(hr == S_OK && Network, "connection GetNetwork: 0x%08lx\n", hr);
            if (Network)
            {
                ZeroMemory(&NetworkId, sizeof(NetworkId));
                hr = INetwork_GetNetworkId(Network, &NetworkId);
                ok(hr == S_OK, "GetNetworkId: 0x%08lx\n", hr);
                hr = INetworkListManager_GetNetwork(Manager, NetworkId, &Net2);
                ok(hr == S_OK && Net2, "GetNetwork: 0x%08lx\n", hr);
                if (Net2)
                    INetwork_Release(Net2);
                Name = NULL;
                hr = INetwork_GetName(Network, &Name);
                ok(hr == S_OK && Name && Name[0], "GetName: 0x%08lx\n", hr);
                SysFreeString(Name);
                Other = 0xdeadbeef;
                hr = INetwork_GetConnectivity(Network, &Other);
                ok(hr == S_OK && Other == Connectivity, "network connectivity 0x%08lx %lx\n", hr, (ULONG)Other);
                INetwork_Release(Network);
            }
            INetworkConnection_Release(Connection);
        }
        /* The enumeration is over, Reset starts it again */
        hr = IEnumNetworkConnections_Next(Connections, 1, &Same, &Fetched);
        ok(hr == S_FALSE && Fetched == 0, "Next past the end: 0x%08lx %lu\n", hr, Fetched);
        ok(IEnumNetworkConnections_Reset(Connections) == S_OK, "Reset failed\n");
        IEnumNetworkConnections_Release(Connections);
    }
    hr = INetworkListManager_GetNetworks(Manager, NLM_ENUM_NETWORK_ALL, &Networks);
    ok(hr == S_OK && Networks, "GetNetworks: 0x%08lx\n", hr);
    if (Networks)
    {
        Fetched = 0xdeadbeef;
        hr = IEnumNetworks_Next(Networks, 1, &Network, &Fetched);
        ok(hr == (HaveNetwork ? S_OK : S_FALSE) && Fetched == (HaveNetwork ? 1 : 0), "networks Next: 0x%08lx %lu\n", hr, Fetched);
        if (Network)
            INetwork_Release(Network);
        IEnumNetworks_Release(Networks);
    }
    hr = INetworkListManager_GetNetwork(Manager, Zero, &Net2);
    ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && !Net2, "GetNetwork(unknown): 0x%08lx\n", hr);
    hr = INetworkListManager_GetNetworkConnection(Manager, Zero, &Same);
    ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && !Same, "GetNetworkConnection(unknown): 0x%08lx\n", hr);

    /* Events: one sink per connection point, never called */
    if (Container)
    {
        hr = IConnectionPointContainer_FindConnectionPoint(Container, &IID_INetworkListManagerEvents, &Point);
        ok(hr == S_OK && Point, "FindConnectionPoint: 0x%08lx\n", hr);
        if (Point)
        {
            IID Iid;

            hr = IConnectionPoint_GetConnectionInterface(Point, &Iid);
            ok(hr == S_OK && IsEqualIID(&Iid, &IID_INetworkListManagerEvents), "GetConnectionInterface: 0x%08lx\n", hr);
            hr = IConnectionPoint_Advise(Point, (IUnknown *)Manager, &Cookie);
            ok(hr == CONNECT_E_CANNOTCONNECT, "Advise with a sink of another type: 0x%08lx\n", hr);
            hr = IConnectionPoint_Advise(Point, (IUnknown *)&Sink.iface, &Cookie);
            ok(hr == S_OK && Cookie, "Advise: 0x%08lx %lu\n", hr, Cookie);
            hr = IConnectionPoint_Advise(Point, (IUnknown *)&Sink.iface, &Cookie2);
            ok(hr == CONNECT_E_ADVISELIMIT, "second Advise: 0x%08lx\n", hr);
            hr = IConnectionPoint_Unadvise(Point, Cookie + 1);
            ok(hr == CONNECT_E_NOCONNECTION, "Unadvise(bad cookie): 0x%08lx\n", hr);
            hr = IConnectionPoint_Unadvise(Point, Cookie);
            ok(hr == S_OK, "Unadvise: 0x%08lx\n", hr);
            ok(Sink.ref == 1, "the sink is still referenced: %ld\n", Sink.ref);
            IConnectionPoint_Release(Point);
        }
        hr = IConnectionPointContainer_FindConnectionPoint(Container, &IID_IUnknown, &Point);
        ok(hr == CONNECT_E_NOCONNECTION && !Point, "FindConnectionPoint(IUnknown): 0x%08lx\n", hr);
        IConnectionPointContainer_Release(Container);
    }

    INetworkListManager_Release(Manager);
Done:
    CoUninitialize();
}
