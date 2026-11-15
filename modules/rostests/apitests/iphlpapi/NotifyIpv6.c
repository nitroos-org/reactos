/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     NotifyIpInterfaceChange, NotifyUnicastIpAddressChange and NotifyRouteChange2 for AF_INET6 and AF_UNSPEC:
 *              the initial notification (one per address family: two for AF_UNSPEC where there is IPv6, as Windows 10 does,
 *              oracle probe), no call without a change, the registration of an address family sees the changes of that
 *              family only, and an AF_UNSPEC registration still sees the IPv4 changes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "Ipv6Common.h"

#define NOTIF_PARAMETER 0
#define NOTIF_ADD 1
#define NOTIF_DELETE 2
#define NOTIF_INITIAL 3

#define TEST_ADDRESS "192.0.2.78"
#define TEST_MASK "255.255.255.0"

typedef VOID (WINAPI *CHANGE_CALLBACK)(PVOID, PVOID, ULONG);
typedef DWORD (WINAPI *FN_Notify)(ADDRESS_FAMILY, CHANGE_CALLBACK, PVOID, BOOLEAN, HANDLE *);
typedef DWORD (WINAPI *FN_Cancel)(HANDLE);

/* the head of MIB_UNICASTIPADDRESS_ROW */
typedef struct
{
    SOCKADDR_INET Address;
    NET_LUID InterfaceLuid;
    ULONG InterfaceIndex;
} UNI_HEAD;

typedef struct
{
    LONG Calls, Initial, InitialWithRow, InitialOnCaller;
    LONG V4Adds, V4Deletes, V6Rows;
    DWORD RegisterThread;
    ULONG TestAddress;
    int Kind;
} STATE;

static FN_Notify pNotifyIpInterfaceChange, pNotifyUnicastIpAddressChange, pNotifyRouteChange2;
static FN_Cancel pCancelMibChangeNotify2;

static VOID WINAPI Callback(PVOID Context, PVOID Row, ULONG Type)
{
    STATE *State = Context;

    InterlockedIncrement(&State->Calls);
    if (Type == NOTIF_INITIAL)
    {
        InterlockedIncrement(&State->Initial);
        if (Row)
            InterlockedIncrement(&State->InitialWithRow);
        if (GetCurrentThreadId() == State->RegisterThread)
            InterlockedIncrement(&State->InitialOnCaller);
        return;
    }
    if (!Row || State->Kind != 1)
        return;
    if (((UNI_HEAD *)Row)->Address.si_family == AF_INET6)
        InterlockedIncrement(&State->V6Rows);
    else if (((UNI_HEAD *)Row)->Address.Ipv4.sin_addr.s_addr == State->TestAddress)
    {
        if (Type == NOTIF_ADD)
            InterlockedIncrement(&State->V4Adds);
        else if (Type == NOTIF_DELETE)
            InterlockedIncrement(&State->V4Deletes);
    }
}

static FN_Notify Function(int Kind)
{
    return Kind == 0 ? pNotifyIpInterfaceChange : Kind == 1 ? pNotifyUnicastIpAddressChange : pNotifyRouteChange2;
}

static const char *const Names[] = { "NotifyIpInterfaceChange", "NotifyUnicastIpAddressChange", "NotifyRouteChange2" };

static void TestInitial(int Kind, BOOL On)
{
    static const ADDRESS_FAMILY Families[] = { AF_INET6, AF_UNSPEC, AF_INET };
    ULONG f;

    for (f = 0; f < 3; f++)
    {
        STATE State;
        HANDLE Handle = NULL;
        DWORD Error;
        LONG Expected = (Families[f] == AF_UNSPEC && On) ? 2 : 1;

        memset(&State, 0, sizeof(State));
        State.Kind = Kind;
        State.RegisterThread = GetCurrentThreadId();
        Error = Function(Kind)(Families[f], Callback, &State, TRUE, &Handle);
        ok(Error == NO_ERROR, "%s(family %u): %lu\n", Names[Kind], Families[f], Error);
        if (Error != NO_ERROR)
            continue;
        ok(Handle != NULL, "%s(family %u): no handle\n", Names[Kind], Families[f]);
        ok(State.Initial == Expected, "%s(family %u): %ld initial notifications, expected %ld\n", Names[Kind], Families[f],
           State.Initial, Expected);
        ok(State.InitialWithRow == 0, "%s(family %u): an initial notification with a row\n", Names[Kind], Families[f]);
        ok(State.InitialOnCaller == State.Initial, "%s(family %u): the initial notification is not on the caller's thread\n",
           Names[Kind], Families[f]);
        Error = pCancelMibChangeNotify2(Handle);
        ok(Error == NO_ERROR, "%s(family %u): cancel %lu\n", Names[Kind], Families[f], Error);
        Error = pCancelMibChangeNotify2(Handle);
        ok(Error == ERROR_INVALID_HANDLE, "%s(family %u): second cancel %lu\n", Names[Kind], Families[f], Error);

        /* without the initial notification: no call */
        memset(&State, 0, sizeof(State));
        Handle = NULL;
        Error = Function(Kind)(Families[f], Callback, &State, FALSE, &Handle);
        ok(Error == NO_ERROR, "%s(family %u, no initial): %lu\n", Names[Kind], Families[f], Error);
        if (Error == NO_ERROR)
        {
            ok(State.Initial == 0, "%s(family %u): initial notification not asked for\n", Names[Kind], Families[f]);
            pCancelMibChangeNotify2(Handle);
        }
    }
}

static BOOL FindInterface(DWORD *Index)
{
    ULONG Size = 0;
    PIP_ADAPTER_INFO Adapters, A;
    BOOL Found = FALSE;

    GetAdaptersInfo(NULL, &Size);
    Adapters = HeapAlloc(GetProcessHeap(), 0, Size ? Size : 1);
    if (Adapters && GetAdaptersInfo(Adapters, &Size) == NO_ERROR)
    {
        for (A = Adapters; A && !Found; A = A->Next)
        {
            if (A->Type != MIB_IF_TYPE_LOOPBACK && strcmp(A->IpAddressList.IpAddress.String, "0.0.0.0"))
            {
                *Index = A->Index;
                Found = TRUE;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Adapters);
    return Found;
}

/* An IPv4 address is added and deleted: the registration of AF_UNSPEC sees both, the one of AF_INET6 sees nothing */
static void TestFamilies(void)
{
    STATE Unspec, V6, V4;
    HANDLE HUnspec = NULL, HV6 = NULL, HV4 = NULL;
    DWORD Index, Error, Tries;
    ULONG Context = 0, Instance = 0;

    if (!is_reactos())
    {
        skip("Changing an address of the computer is not tried on Windows\n");
        return;
    }
    if (!FindInterface(&Index))
    {
        skip("No adapter with an IPv4 address\n");
        return;
    }

    memset(&Unspec, 0, sizeof(Unspec));
    memset(&V6, 0, sizeof(V6));
    memset(&V4, 0, sizeof(V4));
    Unspec.Kind = V6.Kind = V4.Kind = 1;
    Unspec.TestAddress = V6.TestAddress = V4.TestAddress = inet_addr(TEST_ADDRESS);
    Error = pNotifyUnicastIpAddressChange(AF_UNSPEC, Callback, &Unspec, FALSE, &HUnspec);
    ok(Error == NO_ERROR, "AF_UNSPEC: %lu\n", Error);
    Error = pNotifyUnicastIpAddressChange(AF_INET6, Callback, &V6, FALSE, &HV6);
    ok(Error == NO_ERROR, "AF_INET6: %lu\n", Error);
    Error = pNotifyUnicastIpAddressChange(AF_INET, Callback, &V4, FALSE, &HV4);
    ok(Error == NO_ERROR, "AF_INET: %lu\n", Error);

    Error = AddIPAddress(inet_addr(TEST_ADDRESS), inet_addr(TEST_MASK), Index, &Context, &Instance);
    ok(Error == NO_ERROR, "AddIPAddress: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        for (Tries = 0; Tries < 100 && (Unspec.V4Adds == 0 || V4.V4Adds == 0); Tries++)
            Sleep(100);
        ok(Unspec.V4Adds == 1, "AF_UNSPEC: %ld additions of the test address\n", Unspec.V4Adds);
        ok(V4.V4Adds == 1, "AF_INET: %ld additions of the test address\n", V4.V4Adds);
        Sleep(300);
        ok(V6.Calls == 0, "AF_INET6: %ld calls for an IPv4 address\n", V6.Calls);

        DeleteIPAddress(Context);
        for (Tries = 0; Tries < 100 && (Unspec.V4Deletes == 0 || V4.V4Deletes == 0); Tries++)
            Sleep(100);
        ok(Unspec.V4Deletes == 1, "AF_UNSPEC: %ld deletions of the test address\n", Unspec.V4Deletes);
        ok(V4.V4Deletes == 1, "AF_INET: %ld deletions of the test address\n", V4.V4Deletes);
    }
    ok(V4.V6Rows == 0, "AF_INET: %ld IPv6 rows\n", V4.V6Rows);
    pCancelMibChangeNotify2(HUnspec);
    pCancelMibChangeNotify2(HV6);
    pCancelMibChangeNotify2(HV4);
    Sleep(500);
}

START_TEST(NotifyIpv6)
{
    WSADATA Wsa;
    HMODULE Module;
    int Kind;

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    Module = LoadLibraryW(L"iphlpapi.dll");
    pNotifyIpInterfaceChange = (FN_Notify)GetProcAddress(Module, "NotifyIpInterfaceChange");
    pNotifyUnicastIpAddressChange = (FN_Notify)GetProcAddress(Module, "NotifyUnicastIpAddressChange");
    pNotifyRouteChange2 = (FN_Notify)GetProcAddress(Module, "NotifyRouteChange2");
    pCancelMibChangeNotify2 = (FN_Cancel)GetProcAddress(Module, "CancelMibChangeNotify2");
    if (!pNotifyIpInterfaceChange || !pNotifyUnicastIpAddressChange || !pNotifyRouteChange2 || !pCancelMibChangeNotify2)
    {
        skip("The notification functions are not available\n");
        return;
    }

    for (Kind = 0; Kind < 3; Kind++)
        TestInitial(Kind, Ipv6SocketsWork());
    TestFamilies();
}
