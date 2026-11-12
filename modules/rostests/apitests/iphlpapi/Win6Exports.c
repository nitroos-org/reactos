/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     iphlpapi exports of Windows Vista and later that Oracle XE's orahasgen.dll imports:
 *              ConvertIpv4MaskToLength, GetTcpTable2, GetTcp6Table2 and the unicast address entry functions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Oracle XE's JNI library oranjni.dll (netca, loaded by the setup) imports these through orahasgen.dll, so none
 * of them resolving stops netca with "The specified procedure could not be found". The expected values here
 * come from the documentation of the functions and are not measured on Windows (the oracle probe of the lane
 * returned no output).
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <wine/netioapi.h>

static DWORD (WINAPI *pConvertIpv4MaskToLength)(ULONG Mask, PUINT8 MaskLength);
static DWORD (WINAPI *pConvertLengthToIpv4Mask)(ULONG MaskLength, PULONG Mask);
static DWORD (WINAPI *pGetTcpTable2)(PMIB_TCPTABLE2 Table, PULONG Size, BOOL Order);
static DWORD (WINAPI *pGetTcp6Table2)(PMIB_TCP6TABLE2 Table, PULONG Size, BOOL Order);
static VOID (WINAPI *pInitializeUnicastIpAddressEntry)(PMIB_UNICASTIPADDRESS_ROW Row);
static DWORD (WINAPI *pCreateUnicastIpAddressEntry)(const MIB_UNICASTIPADDRESS_ROW *Row);
static DWORD (WINAPI *pDeleteUnicastIpAddressEntry)(const MIB_UNICASTIPADDRESS_ROW *Row);

#define GET(name) ok((p##name = (void *)GetProcAddress(hIphlpapi, #name)) != NULL, "iphlpapi does not export " #name "\n")

static void TestMask(void)
{
    ULONG Mask, Length;
    UINT8 Out;
    DWORD Error;
    static const ULONG Bad[] = { 0xff00ff00, 0x00ff00ff, 0x01000000, 0x000000fd, 0x80000000 };

    for (Length = 0; Length <= 32; Length++)
    {
        Error = pConvertLengthToIpv4Mask(Length, &Mask);
        ok(Error == NO_ERROR, "pConvertLengthToIpv4Mask(%lu): %lu\n", Length, Error);
        Out = 0x77;
        Error = pConvertIpv4MaskToLength(Mask, &Out);
        ok(Error == NO_ERROR, "pConvertIpv4MaskToLength(%08lx): %lu\n", Mask, Error);
        ok(Out == Length, "mask %08lx gave length %u, expected %lu\n", Mask, Out, Length);
    }

    /* network byte order: 255.255.255.0 is 0x00ffffff in a little endian ULONG */
    Out = 0;
    Error = pConvertIpv4MaskToLength(inet_addr("255.255.255.0"), &Out);
    ok(Error == NO_ERROR && Out == 24, "255.255.255.0: %lu, %u\n", Error, Out);
    Error = pConvertIpv4MaskToLength(inet_addr("255.255.240.0"), &Out);
    ok(Error == NO_ERROR && Out == 20, "255.255.240.0: %lu, %u\n", Error, Out);

    /* a mask is a run of one bits followed by zero bits */
    for (Length = 0; Length < ARRAYSIZE(Bad); Length++)
    {
        Out = 0x77;
        Error = pConvertIpv4MaskToLength(Bad[Length], &Out);
        ok(Error == ERROR_INVALID_PARAMETER, "pConvertIpv4MaskToLength(%08lx): %lu\n", Bad[Length], Error);
    }
}

static void TestTcpTable2(void)
{
    WSADATA Data;
    SOCKET Listener;
    struct sockaddr_in Address;
    int Length = sizeof(Address);
    PMIB_TCPTABLE2 Table;
    ULONG Size = 0, Tries;
    DWORD Error = ERROR_INSUFFICIENT_BUFFER, i;
    BOOL Found = FALSE;

    if (WSAStartup(MAKEWORD(2, 2), &Data))
    {
        skip("WSAStartup failed\n");
        return;
    }
    Listener = socket(AF_INET, SOCK_STREAM, 0);
    memset(&Address, 0, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (Listener == INVALID_SOCKET || bind(Listener, (struct sockaddr *)&Address, sizeof(Address)) ||
        listen(Listener, 1) || getsockname(Listener, (struct sockaddr *)&Address, &Length))
    {
        skip("Could not create a listening socket\n");
        if (Listener != INVALID_SOCKET)
            closesocket(Listener);
        WSACleanup();
        return;
    }

    Error = pGetTcpTable2(NULL, &Size, FALSE);
    ok(Error == ERROR_INSUFFICIENT_BUFFER, "GetTcpTable2 size query: %lu\n", Error);
    ok(Size >= FIELD_OFFSET(MIB_TCPTABLE2, table), "size %lu\n", Size);
    ok(pGetTcpTable2(NULL, NULL, FALSE) == ERROR_INVALID_PARAMETER, "GetTcpTable2 without a size\n");

    Table = NULL;
    for (Tries = 0; Tries < 5 && Error == ERROR_INSUFFICIENT_BUFFER; Tries++)
    {
        free(Table);
        Table = malloc(Size);
        Error = pGetTcpTable2(Table, &Size, TRUE);
    }
    ok(Error == NO_ERROR, "GetTcpTable2: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        ok(Size == FIELD_OFFSET(MIB_TCPTABLE2, table) + Table->dwNumEntries * sizeof(MIB_TCPROW2),
           "size %lu for %lu rows\n", Size, Table->dwNumEntries);
        for (i = 0; i < Table->dwNumEntries; i++)
        {
            if (Table->table[i].dwLocalPort == (DWORD)Address.sin_port &&
                Table->table[i].dwState == MIB_TCP_STATE_LISTEN)
            {
                Found = TRUE;
                ok(Table->table[i].dwOwningPid == GetCurrentProcessId(), "owner %lu, expected %lu\n",
                   Table->table[i].dwOwningPid, GetCurrentProcessId());
                ok(Table->table[i].dwLocalAddr == Address.sin_addr.s_addr || Table->table[i].dwLocalAddr == 0,
                   "local address %08lx\n", Table->table[i].dwLocalAddr);
                ok(Table->table[i].dwOffloadState == 0, "offload state %d\n", Table->table[i].dwOffloadState);
            }
        }
        ok(Found, "The listener on port %u is not in the table of %lu rows\n", ntohs(Address.sin_port), Table->dwNumEntries);
    }
    free(Table);
    closesocket(Listener);
    WSACleanup();
}

static void TestTcp6Table2(void)
{
    MIB_TCP6TABLE2 Header;
    ULONG Size = 0;
    DWORD Error;
    PMIB_TCP6TABLE2 Table;

    Error = pGetTcp6Table2(NULL, &Size, FALSE);
    ok(Error == ERROR_INSUFFICIENT_BUFFER || Error == NO_ERROR, "GetTcp6Table2 size query: %lu\n", Error);
    ok(Size >= sizeof(DWORD), "size %lu\n", Size);
    ok(pGetTcp6Table2(NULL, NULL, FALSE) == ERROR_INVALID_PARAMETER, "GetTcp6Table2 without a size\n");

    Table = malloc(Size + 4096);
    Size += 4096;
    Error = pGetTcp6Table2(Table, &Size, FALSE);
    ok(Error == NO_ERROR, "GetTcp6Table2: %lu\n", Error);
    if (Error == NO_ERROR)
        ok(Size >= FIELD_OFFSET(MIB_TCP6TABLE2, table) + Table->dwNumEntries * sizeof(MIB_TCP6ROW2) ||
           Size == FIELD_OFFSET(MIB_TCP6TABLE2, table), "size %lu for %lu rows\n", Size, Table->dwNumEntries);
    free(Table);
    (void)Header;
}

static void TestUnicastEntries(void)
{
    MIB_UNICASTIPADDRESS_ROW Row;

    memset(&Row, 0xaa, sizeof(Row));
    pInitializeUnicastIpAddressEntry(&Row);
    ok(Row.ValidLifetime == 0xffffffff, "ValidLifetime %08lx\n", Row.ValidLifetime);
    ok(Row.PreferredLifetime == 0xffffffff, "PreferredLifetime %08lx\n", Row.PreferredLifetime);
    ok(Row.OnLinkPrefixLength == 255, "OnLinkPrefixLength %u\n", Row.OnLinkPrefixLength);
    ok(Row.Address.si_family == AF_UNSPEC, "family %u\n", Row.Address.si_family);
    ok(Row.InterfaceIndex == 0 && Row.InterfaceLuid.Value == 0, "interface %lu\n", Row.InterfaceIndex);

    /* nothing is created or deleted: no family, or an interface that does not exist */
    ok(pCreateUnicastIpAddressEntry(&Row) == ERROR_INVALID_PARAMETER, "Create without an address family\n");
    ok(pDeleteUnicastIpAddressEntry(&Row) == ERROR_INVALID_PARAMETER, "Delete without an address family\n");
    Row.Address.si_family = AF_INET;
    Row.Address.Ipv4.sin_addr.s_addr = inet_addr("192.0.2.77");
    Row.OnLinkPrefixLength = 24;
    Row.InterfaceIndex = 0x7ffffff0;
    ok(pCreateUnicastIpAddressEntry(&Row) != NO_ERROR, "Create on an interface that does not exist\n");
    ok(pDeleteUnicastIpAddressEntry(&Row) != NO_ERROR, "Delete on an interface that does not exist\n");
}

START_TEST(Win6Exports)
{
    HMODULE hIphlpapi = LoadLibraryA("iphlpapi.dll");

    GET(ConvertIpv4MaskToLength);
    GET(ConvertLengthToIpv4Mask);
    GET(GetTcpTable2);
    GET(GetTcp6Table2);
    GET(InitializeUnicastIpAddressEntry);
    GET(CreateUnicastIpAddressEntry);
    GET(DeleteUnicastIpAddressEntry);

    if (pConvertIpv4MaskToLength && pConvertLengthToIpv4Mask)
        TestMask();
    if (pGetTcpTable2)
        TestTcpTable2();
    if (pGetTcp6Table2)
        TestTcp6Table2();
    if (pInitializeUnicastIpAddressEntry && pCreateUnicastIpAddressEntry && pDeleteUnicastIpAddressEntry)
        TestUnicastEntries();
}
