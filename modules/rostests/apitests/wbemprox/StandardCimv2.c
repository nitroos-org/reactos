/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The WMI namespace root\StandardCimv2: the network classes of the NetTCPIP provider
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values are the ones measured on Windows 10 22H2: property names and types, the
 * "++"-separated keys (shifted by 10 characters for the address, interface and route classes), the class
 * hierarchy, and the properties that are NULL in every instance.
 */

#include <apitest.h>

#define COBJMACROS
#include <initguid.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <wine/netioapi.h>
#include <wbemcli.h>

static IWbemServices *g_Cimv2;
static IWbemServices *g_Scv2;

static
IWbemServices *
Connect(IWbemLocator *Locator, const WCHAR *Namespace)
{
    IWbemServices *Services = NULL;
    BSTR Path = SysAllocString(Namespace);
    HRESULT hr = IWbemLocator_ConnectServer(Locator, Path, NULL, NULL, NULL, 0, NULL, NULL, &Services);

    SysFreeString(Path);
    ok(hr == S_OK, "ConnectServer(%ls) failed: 0x%08lx\n", Namespace, hr);
    return hr == S_OK ? Services : NULL;
}

static
HRESULT
RunQuery(IWbemServices *Services, const WCHAR *Query, IEnumWbemClassObject **Enum)
{
    BSTR Language = SysAllocString(L"WQL");
    BSTR Text = SysAllocString(Query);
    HRESULT hr = IWbemServices_ExecQuery(Services, Language, Text,
                                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, Enum);

    SysFreeString(Language);
    SysFreeString(Text);
    return hr;
}

static
IWbemClassObject *
NextObject(IEnumWbemClassObject *Enum)
{
    IWbemClassObject *Object = NULL;
    ULONG Count = 0;

    if (IEnumWbemClassObject_Next(Enum, 10000, 1, &Object, &Count) != S_OK || !Count)
        return NULL;
    return Object;
}

static
UINT
CountRows(IWbemServices *Services, const WCHAR *Query)
{
    IEnumWbemClassObject *Enum;
    IWbemClassObject *Object;
    UINT Count = 0;
    HRESULT hr = RunQuery(Services, Query, &Enum);

    ok(hr == S_OK, "%ls: ExecQuery failed: 0x%08lx\n", Query, hr);
    if (hr != S_OK)
        return 0;
    while ((Object = NextObject(Enum)))
    {
        Count++;
        IWbemClassObject_Release(Object);
    }
    IEnumWbemClassObject_Release(Enum);
    return Count;
}

/* The first object of a query, or NULL */
static
IWbemClassObject *
FirstObject(IWbemServices *Services, const WCHAR *Query)
{
    IEnumWbemClassObject *Enum;
    IWbemClassObject *Object;
    HRESULT hr = RunQuery(Services, Query, &Enum);

    ok(hr == S_OK, "%ls: ExecQuery failed: 0x%08lx\n", Query, hr);
    if (hr != S_OK)
        return NULL;
    Object = NextObject(Enum);
    IEnumWbemClassObject_Release(Enum);
    return Object;
}

static
BOOL
GetString(IWbemClassObject *Object, const WCHAR *Name, WCHAR *Buffer, SIZE_T Size)
{
    VARIANT Var;
    CIMTYPE Type;
    HRESULT hr;
    BOOL Ret = FALSE;

    Buffer[0] = UNICODE_NULL;
    VariantInit(&Var);
    hr = IWbemClassObject_Get(Object, Name, 0, &Var, &Type, NULL);
    ok(hr == S_OK, "Get(%ls) failed: 0x%08lx\n", Name, hr);
    if (hr == S_OK && V_VT(&Var) == VT_BSTR)
    {
        wcsncpy(Buffer, V_BSTR(&Var), Size - 1);
        Buffer[Size - 1] = UNICODE_NULL;
        Ret = TRUE;
    }
    VariantClear(&Var);
    return Ret;
}

/* A numeric property: its value and CIM type, FALSE when it is NULL */
static
BOOL
GetNumber(IWbemClassObject *Object, const WCHAR *Name, LONGLONG *Value, CIMTYPE *Type)
{
    VARIANT Var;
    CIMTYPE CimType = 0;
    HRESULT hr;
    BOOL Ret = FALSE;

    *Value = 0;
    VariantInit(&Var);
    hr = IWbemClassObject_Get(Object, Name, 0, &Var, &CimType, NULL);
    ok(hr == S_OK, "Get(%ls) failed: 0x%08lx\n", Name, hr);
    if (Type)
        *Type = CimType;
    if (hr == S_OK)
    {
        switch (V_VT(&Var))
        {
            case VT_I4:
                *Value = V_I4(&Var);
                if (CimType == CIM_UINT32)
                    *Value &= 0xffffffffLL;
                Ret = TRUE;
                break;
            case VT_UI4: *Value = V_UI4(&Var); Ret = TRUE; break;
            case VT_I2: *Value = V_I2(&Var); Ret = TRUE; break;
            case VT_UI2: *Value = V_UI2(&Var); Ret = TRUE; break;
            case VT_UI1: *Value = V_UI1(&Var); Ret = TRUE; break;
            case VT_I1: *Value = V_I1(&Var); Ret = TRUE; break;
            case VT_BOOL: *Value = V_BOOL(&Var) ? 1 : 0; Ret = TRUE; break;
            case VT_BSTR: *Value = _wtoi64(V_BSTR(&Var)); Ret = TRUE; break; /* 64-bit values */
            default: break;
        }
    }
    VariantClear(&Var);
    return Ret;
}

static
BOOL
IsNull(IWbemClassObject *Object, const WCHAR *Name)
{
    VARIANT Var;
    HRESULT hr;
    BOOL Ret;

    VariantInit(&Var);
    hr = IWbemClassObject_Get(Object, Name, 0, &Var, NULL, NULL);
    ok(hr == S_OK, "Get(%ls) failed: 0x%08lx\n", Name, hr);
    Ret = hr == S_OK && V_VT(&Var) == VT_NULL;
    VariantClear(&Var);
    return Ret;
}

/* undo the shift of 10 characters of the keys of MSFT_NetIPAddress, MSFT_NetIPInterface and MSFT_NetRoute */
static
void
DecodeKey(WCHAR *Text)
{
    for (; *Text; Text++)
        *Text -= 10;
}

/* The superclass chain of a class object, nearest first, joined with ">" */
static
void
GetChain(IWbemClassObject *Object, WCHAR *Chain, SIZE_T Size)
{
    VARIANT Var;
    HRESULT hr;
    LONG Lower, Upper, i;

    Chain[0] = UNICODE_NULL;
    VariantInit(&Var);
    hr = IWbemClassObject_Get(Object, L"__DERIVATION", 0, &Var, NULL, NULL);
    ok(hr == S_OK, "Get(__DERIVATION) failed: 0x%08lx\n", hr);
    if (hr == S_OK && V_VT(&Var) == (VT_BSTR | VT_ARRAY))
    {
        SafeArrayGetLBound(V_ARRAY(&Var), 1, &Lower);
        SafeArrayGetUBound(V_ARRAY(&Var), 1, &Upper);
        for (i = Lower; i <= Upper; i++)
        {
            BSTR Name = NULL;

            if (SafeArrayGetElement(V_ARRAY(&Var), &i, &Name) == S_OK && Name)
            {
                if (Chain[0])
                    wcsncat(Chain, L">", Size - wcslen(Chain) - 1);
                wcsncat(Chain, Name, Size - wcslen(Chain) - 1);
                SysFreeString(Name);
            }
        }
    }
    VariantClear(&Var);
}

static
void
TestNamespace(void)
{
    IEnumWbemClassObject *Enum;
    IWbemClassObject *Object;
    IWbemServices *Root, *Slash;
    IWbemLocator *Locator = NULL;
    WCHAR Name[64];
    BOOL Found = FALSE;
    HRESULT hr;
    UINT Count;

    CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void **)&Locator);
    ok(Locator != NULL, "no locator\n");
    if (!Locator)
        return;

    Root = Connect(Locator, L"ROOT");
    if (Root)
    {
        hr = RunQuery(Root, L"SELECT * FROM __NAMESPACE", &Enum);
        ok(hr == S_OK, "ExecQuery(__NAMESPACE) failed: 0x%08lx\n", hr);
        if (hr == S_OK)
        {
            while ((Object = NextObject(Enum)))
            {
                if (GetString(Object, L"Name", Name, ARRAY_SIZE(Name)) && !_wcsicmp(Name, L"StandardCimv2"))
                    Found = TRUE;
                IWbemClassObject_Release(Object);
            }
            IEnumWbemClassObject_Release(Enum);
        }
        ok(Found, "StandardCimv2 is not a child namespace of ROOT\n");
        IWbemServices_Release(Root);
    }

    /* a namespace accepts a forward slash and is not case sensitive */
    Slash = Connect(Locator, L"root/standardcimv2");
    if (Slash)
    {
        Count = CountRows(Slash, L"SELECT * FROM MSFT_NetIPAddress");
        ok(Count != 0, "no MSFT_NetIPAddress through root/standardcimv2\n");
        IWbemServices_Release(Slash);
    }

    g_Cimv2 = Connect(Locator, L"ROOT\\CIMV2");
    g_Scv2 = Connect(Locator, L"ROOT\\StandardCimv2");
    IWbemLocator_Release(Locator);
}

/* a class belongs to its namespace only */
static
void
TestVisibility(void)
{
    IEnumWbemClassObject *Enum;
    HRESULT hr;

    hr = RunQuery(g_Cimv2, L"SELECT * FROM MSFT_NetTCPConnection", &Enum);
    if (hr == S_OK)
    {
        /* the error of an unknown class comes with the first Next */
        IWbemClassObject *Object = NextObject(Enum);
        ok(Object == NULL, "MSFT_NetTCPConnection found in root\\cimv2\n");
        if (Object)
            IWbemClassObject_Release(Object);
        IEnumWbemClassObject_Release(Enum);
    }
    else
    {
        ok(hr == WBEM_E_INVALID_CLASS, "root\\cimv2: 0x%08lx\n", hr);
    }

    hr = RunQuery(g_Scv2, L"SELECT * FROM Win32_Process", &Enum);
    if (hr == S_OK)
    {
        IWbemClassObject *Object = NextObject(Enum);
        ok(Object == NULL, "Win32_Process found in root\\StandardCimv2\n");
        if (Object)
            IWbemClassObject_Release(Object);
        IEnumWbemClassObject_Release(Enum);
    }
    else
    {
        ok(hr == WBEM_E_INVALID_CLASS, "root\\StandardCimv2: 0x%08lx\n", hr);
    }
}

/* the classes of root\cimv2 keep their hierarchy: the class tables are shared with root\StandardCimv2 */
static
void
TestCimv2Unchanged(void)
{
    IWbemClassObject *Object;
    WCHAR Chain[256];

    Object = FirstObject(g_Cimv2, L"SELECT * FROM Win32_NetworkAdapter");
    if (Object)
    {
        GetChain(Object, Chain, ARRAY_SIZE(Chain));
        ok(!wcscmp(Chain, L"CIM_NetworkAdapter>CIM_LogicalDevice>CIM_LogicalElement>CIM_ManagedSystemElement"),
           "Win32_NetworkAdapter derivation %ls\n", Chain);
        IWbemClassObject_Release(Object);
    }
    Object = FirstObject(g_Cimv2, L"SELECT * FROM Win32_OperatingSystem");
    ok(Object != NULL, "no Win32_OperatingSystem\n");
    if (Object)
        IWbemClassObject_Release(Object);
}

static
void
TestHierarchy(void)
{
    static const struct
    {
        const WCHAR *Class;
        const WCHAR *Chain;
    }
    Classes[] =
    {
        { L"MSFT_NetTCPConnection",
          L"MSFT_NetTransportConnection>CIM_NetworkPipe>CIM_EnabledLogicalElement>CIM_LogicalElement>"
          L"CIM_ManagedSystemElement>CIM_ManagedElement" },
        { L"MSFT_NetUDPEndpoint",
          L"MSFT_NetTransportConnection>CIM_NetworkPipe>CIM_EnabledLogicalElement>CIM_LogicalElement>"
          L"CIM_ManagedSystemElement>CIM_ManagedElement" },
        { L"MSFT_NetIPAddress",
          L"CIM_IPProtocolEndpoint>CIM_ProtocolEndpoint>CIM_ServiceAccessPoint>CIM_EnabledLogicalElement>"
          L"CIM_LogicalElement>CIM_ManagedSystemElement>CIM_ManagedElement" },
        { L"MSFT_NetIPInterface",
          L"CIM_LANEndpoint>CIM_ProtocolEndpoint>CIM_ServiceAccessPoint>CIM_EnabledLogicalElement>"
          L"CIM_LogicalElement>CIM_ManagedSystemElement>CIM_ManagedElement" },
        { L"MSFT_NetRoute", L"CIM_NextHopRoute>CIM_ManagedElement" },
        { L"MSFT_NetAdapter",
          L"CIM_NetworkPort>CIM_LogicalPort>CIM_LogicalDevice>CIM_EnabledLogicalElement>CIM_LogicalElement>"
          L"CIM_ManagedSystemElement>CIM_ManagedElement" },
        { L"MSFT_DNSClientServerAddress",
          L"CIM_RemoteServiceAccessPoint>CIM_ServiceAccessPoint>CIM_EnabledLogicalElement>CIM_LogicalElement>"
          L"CIM_ManagedSystemElement>CIM_ManagedElement" },
    };
    UINT i;

    for (i = 0; i < ARRAY_SIZE(Classes); i++)
    {
        IWbemClassObject *Class = NULL;
        BSTR Name = SysAllocString(Classes[i].Class);
        HRESULT hr = IWbemServices_GetObject(g_Scv2, Name, 0, NULL, &Class, NULL);
        WCHAR Chain[512];

        SysFreeString(Name);
        ok(hr == S_OK, "GetObject(%ls) failed: 0x%08lx\n", Classes[i].Class, hr);
        if (hr != S_OK)
            continue;
        GetChain(Class, Chain, ARRAY_SIZE(Chain));
        ok(!wcscmp(Chain, Classes[i].Chain), "%ls derivation %ls\n", Classes[i].Class, Chain);
        IWbemClassObject_Release(Class);
    }
}

/* Properties Windows leaves NULL in every instance are part of the class, with a NULL value */
static
void
CheckCommonProperties(IWbemClassObject *Object, const WCHAR *Class)
{
    static const WCHAR *Nulls[] = { L"Caption", L"Description", L"OperationalStatus", L"HealthState", L"Status",
                                    L"StatusDescriptions", L"InstallDate" };
    LONGLONG Value;
    CIMTYPE Type;
    UINT i;

    for (i = 0; i < ARRAY_SIZE(Nulls); i++)
        ok(IsNull(Object, Nulls[i]), "%ls: %ls is not NULL\n", Class, Nulls[i]);
    ok(GetNumber(Object, L"EnabledDefault", &Value, &Type) && Value == 2 && Type == CIM_UINT16,
       "%ls: EnabledDefault %lld type %lu\n", Class, Value, Type);
    ok(GetNumber(Object, L"TransitioningToState", &Value, &Type) && Value == 12 && Type == CIM_UINT16,
       "%ls: TransitioningToState %lld type %lu\n", Class, Value, Type);
}

static
void
TestTcp(void)
{
    SOCKET Listener;
    struct sockaddr_in Address = { 0 };
    int Length = sizeof(Address);
    WCHAR Query[256], Text[128], Expect[128];
    IWbemClassObject *Object;
    LONGLONG Value;
    CIMTYPE Type;
    USHORT Port;
    UINT Count;

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Listener == INVALID_SOCKET)
    {
        skip("no socket\n");
        return;
    }
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Listener, (struct sockaddr *)&Address, sizeof(Address)) ||
        listen(Listener, 1) || getsockname(Listener, (struct sockaddr *)&Address, &Length))
    {
        skip("cannot listen: %d\n", WSAGetLastError());
        closesocket(Listener);
        return;
    }
    Port = ntohs(Address.sin_port);

    _snwprintf(Query, ARRAY_SIZE(Query), L"SELECT * FROM MSFT_NetTCPConnection WHERE LocalPort=%u AND State=2", Port);
    Count = CountRows(g_Scv2, Query);
    ok(Count == 1, "%ls: %u rows\n", Query, Count);
    Object = FirstObject(g_Scv2, Query);
    if (Object)
    {
        _snwprintf(Expect, ARRAY_SIZE(Expect), L"127.0.0.1++%u++0.0.0.0++0", Port);
        ok(GetString(Object, L"InstanceID", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, Expect), "InstanceID %ls\n", Text);
        ok(GetString(Object, L"LocalAddress", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, L"127.0.0.1"), "LocalAddress %ls\n", Text);
        ok(GetString(Object, L"RemoteAddress", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, L"0.0.0.0"), "RemoteAddress %ls\n", Text);
        ok(GetNumber(Object, L"LocalPort", &Value, &Type) && Value == Port && Type == CIM_UINT16,
           "LocalPort %lld type %lu\n", Value, Type);
        ok(GetNumber(Object, L"RemotePort", &Value, &Type) && Value == 0 && Type == CIM_UINT16,
           "RemotePort %lld type %lu\n", Value, Type);
        ok(GetNumber(Object, L"OwningProcess", &Value, &Type) && Value == (LONGLONG)GetCurrentProcessId() && Type == CIM_UINT32,
           "OwningProcess %lld type %lu\n", Value, Type);
        ok(GetNumber(Object, L"State", &Value, &Type) && Value == 2 && Type == CIM_UINT8,
           "State %lld type %lu\n", Value, Type);
        ok(GetNumber(Object, L"OffloadState", &Value, &Type) && Value == 0 && Type == CIM_UINT8,
           "OffloadState %lld type %lu\n", Value, Type);
        ok(GetNumber(Object, L"RequestedState", &Value, &Type) && Value == 5, "RequestedState %lld\n", Value);
        ok(GetNumber(Object, L"AppliedSetting", &Value, &Type) && Type == CIM_UINT8, "AppliedSetting type %lu\n", Type);
        CheckCommonProperties(Object, L"MSFT_NetTCPConnection");
        IWbemClassObject_Release(Object);
    }

    /* a condition that matches nothing */
    _snwprintf(Query, ARRAY_SIZE(Query), L"SELECT * FROM MSFT_NetTCPConnection WHERE LocalPort=%u AND State=5", Port);
    Count = CountRows(g_Scv2, Query);
    ok(Count == 0, "%ls: %u rows\n", Query, Count);
    closesocket(Listener);
}

static
void
TestUdp(void)
{
    SOCKET Socket;
    struct sockaddr_in Address = { 0 };
    int Length = sizeof(Address);
    WCHAR Query[256], Text[128], Expect[128];
    IWbemClassObject *Object;
    LONGLONG Value;
    CIMTYPE Type;
    USHORT Port;
    UINT Count;

    Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Socket == INVALID_SOCKET)
    {
        skip("no socket\n");
        return;
    }
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Socket, (struct sockaddr *)&Address, sizeof(Address)) ||
        getsockname(Socket, (struct sockaddr *)&Address, &Length))
    {
        skip("cannot bind: %d\n", WSAGetLastError());
        closesocket(Socket);
        return;
    }
    Port = ntohs(Address.sin_port);

    _snwprintf(Query, ARRAY_SIZE(Query), L"SELECT * FROM MSFT_NetUDPEndpoint WHERE LocalPort=%u", Port);
    Count = CountRows(g_Scv2, Query);
    ok(Count == 1, "%ls: %u rows\n", Query, Count);
    Object = FirstObject(g_Scv2, Query);
    if (Object)
    {
        _snwprintf(Expect, ARRAY_SIZE(Expect), L"127.0.0.1++%u", Port);
        ok(GetString(Object, L"InstanceID", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, Expect), "InstanceID %ls\n", Text);
        ok(GetString(Object, L"LocalAddress", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, L"127.0.0.1"), "LocalAddress %ls\n", Text);
        ok(GetNumber(Object, L"OwningProcess", &Value, &Type) && Value == (LONGLONG)GetCurrentProcessId() && Type == CIM_UINT32,
           "OwningProcess %lld type %lu\n", Value, Type);
        ok(GetNumber(Object, L"LocalPort", &Value, &Type) && Value == Port && Type == CIM_UINT16,
           "LocalPort %lld type %lu\n", Value, Type);
        CheckCommonProperties(Object, L"MSFT_NetUDPEndpoint");
        IWbemClassObject_Release(Object);
    }
    closesocket(Socket);
}

static
void
TestIPAddress(void)
{
    MIB_UNICASTIPADDRESS_TABLE *Table = NULL;
    IWbemClassObject *Object;
    WCHAR Text[128], Expect[128];
    LONGLONG Value;
    CIMTYPE Type;
    UINT i, Count;

    Count = CountRows(g_Scv2, L"SELECT * FROM MSFT_NetIPAddress");
    if (GetUnicastIpAddressTable(AF_UNSPEC, &Table) == NO_ERROR && Table)
    {
        ok(Count == Table->NumEntries, "%u rows for %lu unicast addresses\n", Count, Table->NumEntries);
        for (i = 0; i < Table->NumEntries; i++)
        {
            MIB_UNICASTIPADDRESS_ROW *Row = &Table->Table[i];

            if (Row->Address.si_family != AF_INET || Row->Address.Ipv4.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
                continue;
            Object = FirstObject(g_Scv2, L"SELECT * FROM MSFT_NetIPAddress WHERE IPAddress='127.0.0.1'");
            ok(Object != NULL, "no 127.0.0.1\n");
            if (!Object)
                break;
            ok(GetString(Object, L"Name", Text, ARRAY_SIZE(Text)), "no Name\n");
            DecodeKey(Text);
            _snwprintf(Expect, ARRAY_SIZE(Expect), L"127.0.0.1++%lu++1++1", Row->InterfaceIndex);
            ok(!wcscmp(Text, Expect), "Name %ls, expected %ls\n", Text, Expect);
            ok(GetString(Object, L"IPv4Address", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, L"127.0.0.1"), "IPv4Address %ls\n", Text);
            ok(IsNull(Object, L"IPv6Address"), "IPv6Address is not NULL\n");
            ok(GetNumber(Object, L"AddressFamily", &Value, &Type) && Value == 2 && Type == CIM_UINT16, "AddressFamily %lld type %lu\n", Value, Type);
            ok(GetNumber(Object, L"PrefixLength", &Value, &Type) && Value == Row->OnLinkPrefixLength && Type == CIM_UINT8,
               "PrefixLength %lld type %lu\n", Value, Type);
            ok(GetNumber(Object, L"InterfaceIndex", &Value, &Type) && Value == (LONGLONG)Row->InterfaceIndex && Type == CIM_UINT32,
               "InterfaceIndex %lld type %lu\n", Value, Type);
            ok(GetNumber(Object, L"AddressState", &Value, &Type) && Value == (LONGLONG)Row->DadState && Type == CIM_UINT16,
               "AddressState %lld type %lu\n", Value, Type);
            ok(GetNumber(Object, L"PrefixOrigin", &Value, &Type) && Value == (LONGLONG)Row->PrefixOrigin && Type == CIM_UINT16,
               "PrefixOrigin %lld type %lu\n", Value, Type);
            ok(GetNumber(Object, L"SuffixOrigin", &Value, &Type) && Value == (LONGLONG)Row->SuffixOrigin && Type == CIM_UINT16,
               "SuffixOrigin %lld type %lu\n", Value, Type);
            ok(GetNumber(Object, L"Type", &Value, &Type) && Value == 1 && Type == CIM_UINT8, "Type %lld type %lu\n", Value, Type);
            ok(GetNumber(Object, L"Store", &Value, &Type) && Value == 1 && Type == CIM_UINT8, "Store %lld type %lu\n", Value, Type);
            ok(GetNumber(Object, L"SkipAsSource", &Value, &Type) && Type == CIM_BOOLEAN, "SkipAsSource type %lu\n", Type);
            ok(GetNumber(Object, L"ProtocolIFType", &Value, &Type) && Value == 4096 && Type == CIM_UINT16, "ProtocolIFType %lld\n", Value);
            ok(GetString(Object, L"InterfaceAlias", Text, ARRAY_SIZE(Text)) && Text[0], "no InterfaceAlias\n");
            ok(GetString(Object, L"IPAddress", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, L"127.0.0.1"), "IPAddress %ls\n", Text);
            /* the loopback address never expires: TimeSpan.MaxValue */
            ok(GetString(Object, L"ValidLifetime", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, L"10675199024805.477580:000"),
               "ValidLifetime %ls\n", Text);
            ok(GetString(Object, L"CreationClassName", Text, ARRAY_SIZE(Text)) && !Text[0], "CreationClassName %ls\n", Text);
            CheckCommonProperties(Object, L"MSFT_NetIPAddress");
            IWbemClassObject_Release(Object);
            break;
        }
        FreeMibTable(Table);
    }
    ok(CountRows(g_Scv2, L"SELECT * FROM MSFT_NetIPAddress WHERE IPAddress='no such address'") == 0, "rows for a bad address\n");
}

static
void
TestIPInterface(void)
{
    MIB_IPINTERFACE_TABLE *Table = NULL;
    IWbemClassObject *Object;
    WCHAR Text[128], Expect[128], Query[256];
    LONGLONG Value;
    CIMTYPE Type;
    UINT Count;

    Count = CountRows(g_Scv2, L"SELECT * FROM MSFT_NetIPInterface");
    if (GetIpInterfaceTable(AF_INET, &Table) == NO_ERROR && Table && Table->NumEntries)
    {
        MIB_IPINTERFACE_ROW *Row = &Table->Table[0];

        ok(Count >= Table->NumEntries, "%u rows for %lu IPv4 interfaces\n", Count, Table->NumEntries);
        _snwprintf(Query, ARRAY_SIZE(Query), L"SELECT * FROM MSFT_NetIPInterface WHERE InterfaceIndex=%lu AND AddressFamily=2", Row->InterfaceIndex);
        Object = FirstObject(g_Scv2, Query);
        ok(Object != NULL, "%ls: no row\n", Query);
        if (Object)
        {
            ok(GetString(Object, L"Name", Text, ARRAY_SIZE(Text)), "no Name\n");
            DecodeKey(Text);
            _snwprintf(Expect, ARRAY_SIZE(Expect), L"%lu++2++1", Row->InterfaceIndex);
            ok(!wcscmp(Text, Expect), "Name %ls, expected %ls\n", Text, Expect);
            ok(GetNumber(Object, L"InterfaceMetric", &Value, &Type) && Value == (LONGLONG)Row->Metric && Type == CIM_UINT32,
               "InterfaceMetric %lld type %lu\n", Value, Type);
            ok(GetNumber(Object, L"NlMtu", &Value, &Type) && Value == (LONGLONG)Row->NlMtu && Type == CIM_UINT32,
               "NlMtu %lld type %lu\n", Value, Type);
            ok(GetNumber(Object, L"AddressFamily", &Value, &Type) && Value == 2 && Type == CIM_UINT16, "AddressFamily %lld\n", Value);
            ok(GetNumber(Object, L"Store", &Value, &Type) && Value == 1 && Type == CIM_UINT8, "Store %lld\n", Value);
            ok(GetNumber(Object, L"CompartmentId", &Value, &Type) && Value == 1 && Type == CIM_UINT32, "CompartmentId %lld\n", Value);
            ok(GetNumber(Object, L"LowestIfNetLuid", &Value, &Type) && Type == CIM_UINT64, "LowestIfNetLuid type %lu\n", Type);
            ok(GetNumber(Object, L"Forwarding", &Value, &Type) && Value == Row->ForwardingEnabled && Type == CIM_UINT8,
               "Forwarding %lld\n", Value);
            ok(GetString(Object, L"AdvertisedRouterLifetime", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, L"00000000003000.000000:000"),
               "AdvertisedRouterLifetime %ls\n", Text);
            ok(IsNull(Object, L"MACAddress"), "MACAddress is not NULL\n");
            CheckCommonProperties(Object, L"MSFT_NetIPInterface");
            IWbemClassObject_Release(Object);
        }
        FreeMibTable(Table);
    }
}

static
void
TestRoute(void)
{
    IEnumWbemClassObject *Enum;
    IWbemClassObject *Object;
    MIB_IPFORWARDTABLE *Forward = NULL;
    DWORD Size = 0;
    WCHAR Text[256], Prefix[256], Next[64];
    LONGLONG Value, Index;
    CIMTYPE Type;
    UINT Count = 0;
    HRESULT hr;

    hr = RunQuery(g_Scv2, L"SELECT * FROM MSFT_NetRoute", &Enum);
    ok(hr == S_OK, "ExecQuery(MSFT_NetRoute) failed: 0x%08lx\n", hr);
    if (hr != S_OK)
        return;
    while ((Object = NextObject(Enum)))
    {
        WCHAR Expect[300];

        Count++;
        ok(GetString(Object, L"DestinationPrefix", Prefix, ARRAY_SIZE(Prefix)) && wcschr(Prefix, L'/'),
           "DestinationPrefix %ls\n", Prefix);
        ok(GetString(Object, L"NextHop", Next, ARRAY_SIZE(Next)), "no NextHop\n");
        ok(GetNumber(Object, L"InterfaceIndex", &Index, &Type) && Type == CIM_UINT32, "InterfaceIndex type %lu\n", Type);
        ok(GetString(Object, L"InstanceID", Text, ARRAY_SIZE(Text)), "no InstanceID\n");
        DecodeKey(Text);
        _snwprintf(Expect, ARRAY_SIZE(Expect), L"%ls++%lld++%ls++1", Prefix, Index, Next);
        ok(!wcscmp(Text, Expect), "InstanceID %ls, expected %ls\n", Text, Expect);
        ok(GetNumber(Object, L"RouteMetric", &Value, &Type) && Type == CIM_UINT16 && Value <= 65535, "RouteMetric %lld type %lu\n", Value, Type);
        ok(GetNumber(Object, L"AddressFamily", &Value, &Type) && Value == 2 && Type == CIM_UINT16, "AddressFamily %lld\n", Value);
        ok(GetNumber(Object, L"Store", &Value, &Type) && Value == 1 && Type == CIM_UINT8, "Store %lld\n", Value);
        ok(GetNumber(Object, L"Protocol", &Value, &Type) && Type == CIM_UINT16, "Protocol type %lu\n", Type);
        ok(GetNumber(Object, L"InterfaceMetric", &Value, &Type) && Type == CIM_UINT32, "InterfaceMetric type %lu\n", Type);
        ok(IsNull(Object, L"Caption"), "Caption is not NULL\n");
        IWbemClassObject_Release(Object);
    }
    IEnumWbemClassObject_Release(Enum);

    if (GetIpForwardTable(NULL, &Size, FALSE) == ERROR_INSUFFICIENT_BUFFER && (Forward = malloc(Size)))
    {
        if (GetIpForwardTable(Forward, &Size, FALSE) == NO_ERROR)
            ok(Count == Forward->dwNumEntries, "%u routes for %lu forwarding entries\n", Count, Forward->dwNumEntries);
        free(Forward);
    }
}

static
void
TestAdapter(void)
{
    IEnumWbemClassObject *Enum;
    IWbemClassObject *Object;
    WCHAR Text[256], Guid[256], Machine[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD MachineLength = ARRAY_SIZE(Machine);
    LONGLONG Value;
    CIMTYPE Type;
    HRESULT hr;
    UINT Count = 0;

    GetComputerNameW(Machine, &MachineLength);
    hr = RunQuery(g_Scv2, L"SELECT * FROM MSFT_NetAdapter", &Enum);
    ok(hr == S_OK, "ExecQuery(MSFT_NetAdapter) failed: 0x%08lx\n", hr);
    if (hr != S_OK)
        return;
    while ((Object = NextObject(Enum)))
    {
        Count++;
        ok(GetString(Object, L"InstanceID", Guid, ARRAY_SIZE(Guid)) && Guid[0] == L'{', "InstanceID %ls\n", Guid);
        ok(GetString(Object, L"DeviceID", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, Guid), "DeviceID %ls\n", Text);
        ok(GetString(Object, L"InterfaceGuid", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, Guid), "InterfaceGuid %ls\n", Text);
        ok(GetString(Object, L"CreationClassName", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, L"MSFT_NetAdapter"), "CreationClassName %ls\n", Text);
        ok(GetString(Object, L"SystemCreationClassName", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, L"CIM_NetworkPort"),
           "SystemCreationClassName %ls\n", Text);
        ok(GetString(Object, L"SystemName", Text, ARRAY_SIZE(Text)) && !_wcsicmp(Text, Machine), "SystemName %ls\n", Text);
        ok(GetString(Object, L"Name", Text, ARRAY_SIZE(Text)) && Text[0], "no Name\n");
        ok(GetString(Object, L"InterfaceDescription", Text, ARRAY_SIZE(Text)) && Text[0], "no InterfaceDescription\n");
        ok(GetNumber(Object, L"InterfaceIndex", &Value, &Type) && Value > 0 && Type == CIM_UINT32, "InterfaceIndex %lld type %lu\n", Value, Type);
        ok(GetNumber(Object, L"Speed", &Value, &Type) && Type == CIM_UINT64, "Speed type %lu\n", Type);
        ok(GetNumber(Object, L"NetLuid", &Value, &Type) && Type == CIM_UINT64, "NetLuid type %lu\n", Type);
        ok(GetNumber(Object, L"MtuSize", &Value, &Type) && Value > 0 && Type == CIM_UINT32, "MtuSize %lld type %lu\n", Value, Type);
        ok(GetNumber(Object, L"InterfaceType", &Value, &Type) && Type == CIM_UINT32, "InterfaceType type %lu\n", Type);
        ok(GetNumber(Object, L"Hidden", &Value, &Type) && Type == CIM_BOOLEAN, "Hidden type %lu\n", Type);
        ok(GetNumber(Object, L"State", &Value, &Type) && Value == 2 && Type == CIM_UINT32, "State %lld type %lu\n", Value, Type);
        ok(GetNumber(Object, L"EnabledState", &Value, &Type) && Value == 5, "EnabledState %lld\n", Value);
        ok(GetNumber(Object, L"DriverMajorNdisVersion", &Value, &Type) && Type == CIM_UINT8, "DriverMajorNdisVersion type %lu\n", Type);
        ok(IsNull(Object, L"Availability"), "Availability is not NULL\n");
        CheckCommonProperties(Object, L"MSFT_NetAdapter");
        IWbemClassObject_Release(Object);
    }
    IEnumWbemClassObject_Release(Enum);
    trace("%u network adapters\n", Count);
}

static
void
TestDns(void)
{
    IEnumWbemClassObject *Enum;
    IWbemClassObject *Object;
    WCHAR Text[256], Expect[64];
    LONGLONG Index, Family, Value;
    CIMTYPE Type;
    HRESULT hr;
    UINT Count = 0;

    hr = RunQuery(g_Scv2, L"SELECT * FROM MSFT_DNSClientServerAddress", &Enum);
    ok(hr == S_OK, "ExecQuery(MSFT_DNSClientServerAddress) failed: 0x%08lx\n", hr);
    if (hr != S_OK)
        return;
    while ((Object = NextObject(Enum)))
    {
        VARIANT Var;

        Count++;
        ok(GetNumber(Object, L"InterfaceIndex", &Index, &Type) && Type == CIM_UINT32, "InterfaceIndex type %lu\n", Type);
        ok(GetNumber(Object, L"AddressFamily", &Family, &Type) && (Family == 2 || Family == 23) && Type == CIM_UINT16,
           "AddressFamily %lld\n", Family);
        _snwprintf(Expect, ARRAY_SIZE(Expect), L"%lld", Index);
        ok(GetString(Object, L"Name", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, Expect), "Name %ls\n", Text);
        _snwprintf(Expect, ARRAY_SIZE(Expect), L"%lld", Family);
        ok(GetString(Object, L"SystemName", Text, ARRAY_SIZE(Text)) && !wcscmp(Text, Expect), "SystemName %ls\n", Text);
        ok(GetString(Object, L"CreationClassName", Text, ARRAY_SIZE(Text)) && !Text[0], "CreationClassName %ls\n", Text);
        ok(GetString(Object, L"InterfaceAlias", Text, ARRAY_SIZE(Text)) && Text[0], "no InterfaceAlias\n");
        ok(GetNumber(Object, L"AccessContext", &Value, &Type) && Value == 0 && Type == CIM_UINT16, "AccessContext %lld\n", Value);
        VariantInit(&Var);
        hr = IWbemClassObject_Get(Object, L"ServerAddresses", 0, &Var, &Type, NULL);
        ok(hr == S_OK && V_VT(&Var) == (VT_BSTR | VT_ARRAY) && Type == (CIM_STRING | CIM_FLAG_ARRAY),
           "ServerAddresses 0x%08lx vt %u type %lu\n", hr, V_VT(&Var), Type);
        VariantClear(&Var);
        CheckCommonProperties(Object, L"MSFT_DNSClientServerAddress");
        IWbemClassObject_Release(Object);
    }
    IEnumWbemClassObject_Release(Enum);
    trace("%u DNS rows\n", Count);
}

/* Create and RequestStateChange are methods of MSFT_NetIPAddress; Create is static. Changing the network
 * configuration is not implemented. */
static
void
TestMethods(void)
{
    IWbemClassObject *Class = NULL;
    BSTR Name = SysAllocString(L"MSFT_NetIPAddress");
    BSTR Create = SysAllocString(L"Create");
    BSTR Path = SysAllocString(L"MSFT_NetIPAddress");
    BSTR Method = NULL;
    BOOL HasCreate = FALSE, HasRsc = FALSE;
    HRESULT hr;

    hr = IWbemServices_GetObject(g_Scv2, Name, 0, NULL, &Class, NULL);
    ok(hr == S_OK, "GetObject failed: 0x%08lx\n", hr);
    if (hr == S_OK)
    {
        hr = IWbemClassObject_BeginMethodEnumeration(Class, 0);
        ok(hr == S_OK, "BeginMethodEnumeration failed: 0x%08lx\n", hr);
        while (hr == S_OK)
        {
            IWbemClassObject *In = NULL, *Out = NULL;

            Method = NULL;
            hr = IWbemClassObject_NextMethod(Class, 0, &Method, &In, &Out);
            if (hr != S_OK)
                break;
            trace("method %ls\n", Method);
            if (!wcscmp(Method, L"Create")) HasCreate = TRUE;
            if (!wcscmp(Method, L"RequestStateChange")) HasRsc = TRUE;
            SysFreeString(Method);
            if (In) IWbemClassObject_Release(In);
            if (Out) IWbemClassObject_Release(Out);
        }
        trace("methods enumerated\n");
        ok(HasCreate, "no Create method\n");
        ok(HasRsc, "no RequestStateChange method\n");
        IWbemClassObject_EndMethodEnumeration(Class);
        IWbemClassObject_Release(Class);
    }
    trace("before ExecMethod\n");
    hr = IWbemServices_ExecMethod(g_Scv2, Path, Create, 0, NULL, NULL, NULL, NULL);
    trace("ExecMethod 0x%08lx\n", hr);
    ok(hr != S_OK, "Create succeeded without parameters\n");
    SysFreeString(Name);
    SysFreeString(Create);
    SysFreeString(Path);
}

START_TEST(StandardCimv2)
{
    WSADATA Data;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        skip("CoInitializeEx failed: 0x%08lx\n", hr);
        return;
    }
    WSAStartup(MAKEWORD(2, 2), &Data);

    TestNamespace();
    if (g_Cimv2 && g_Scv2)
    {
        TestVisibility();
        TestCimv2Unchanged();
        TestHierarchy();
        TestTcp();
        TestUdp();
        TestIPAddress();
        TestIPInterface();
        TestRoute();
        TestAdapter();
        TestDns();
        TestMethods();
    }
    if (g_Cimv2)
        IWbemServices_Release(g_Cimv2);
    if (g_Scv2)
        IWbemServices_Release(g_Scv2);
    WSACleanup();
    CoUninitialize();
}
