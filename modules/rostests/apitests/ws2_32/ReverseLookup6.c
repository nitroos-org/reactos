/*
 * PROJECT:     ws2_32.dll API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Reverse lookups of IPv6 addresses (PTR records under ip6.arpa): getnameinfo, GetNameInfoW and
 *              gethostbyaddr with AF_INET6, against a name server that is part of the test (loopback, IPv4 and IPv6
 *              transport). The test points the name server list of an adapter at it (registry, restored at the end).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <winreg.h>
#include <iphlpapi.h>
#include <winnls.h>
#include <stdlib.h>

/* dnsapi: drops the resolver service's cache */
BOOL WINAPI DnsFlushResolverCache(VOID);

/*
 * The names are those of RFC 3849 documentation prefix 2001:db8::/32:
 *  2001:db8:5300::1   PTR host1.rl6.test.   (both transports)
 *  2001:db8:5300::2   no such name          (NXDOMAIN)
 *  2001:db8:5300::3   PTR host3.rl6.test.   (the IPv4 transport never answers: the IPv6 server is the one that does)
 *  ::ffff:192.0.2.55  PTR map4.rl6.test.    (in-addr.arpa: an IPv4-mapped address is an IPv4 address)
 */
static const UCHAR Addr1[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x53, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const UCHAR Addr2[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x53, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
static const UCHAR Addr3[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x53, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 };
static const UCHAR AddrMapped[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 55 };

static SOCKET Srv4 = INVALID_SOCKET, Srv6 = INVALID_SOCKET;
static volatile LONG Stop;
static volatile LONG Hits4, Hits6, HitsLast;

/* The query name as text (labels joined by dots, lower case) and the offset after the question; 0 on a bad packet */
static int ParseQuestion(const UCHAR *Pkt, int Len, char *Name, int NameSize, USHORT *Type)
{
    int Pos = 12, N = 0;

    if (Len < 17)
        return 0;
    for (;;)
    {
        int L;

        if (Pos >= Len)
            return 0;
        L = Pkt[Pos++];
        if (L == 0)
            break;
        if (L > 63 || Pos + L > Len || N + L + 2 > NameSize)
            return 0;
        if (N)
            Name[N++] = '.';
        while (L--)
        {
            UCHAR C = Pkt[Pos++];
            Name[N++] = (C >= 'A' && C <= 'Z') ? C + 32 : C;
        }
    }
    Name[N] = 0;
    if (Pos + 4 > Len)
        return 0;
    *Type = (Pkt[Pos] << 8) | Pkt[Pos + 1];
    return Pos + 4;
}

static void Ip6ReverseName(const UCHAR *Addr, char *Out)
{
    int i;

    for (i = 15; i >= 0; i--)
        Out += sprintf(Out, "%x.%x.", Addr[i] & 0xF, Addr[i] >> 4);
    strcpy(Out, "ip6.arpa");
}

static int AppendName(UCHAR *Out, const char *Name)
{
    int N = 0;

    while (*Name)
    {
        const char *Dot = strchr(Name, '.');
        int L = Dot ? (int)(Dot - Name) : (int)strlen(Name);

        Out[N++] = (UCHAR)L;
        memcpy(&Out[N], Name, L);
        N += L;
        Name += L + (Dot ? 1 : 0);
    }
    Out[N++] = 0;
    return N;
}

/* The answer for a query that came in on the IPv6 (V6) or the IPv4 socket; returns the packet size, 0: no answer */
static int Answer(const UCHAR *Pkt, int Len, BOOL V6, UCHAR *Out)
{
    char Name[300], Rev[100];
    USHORT Type;
    int QEnd, N;
    const char *Target = NULL;
    int Rcode = 3;

    QEnd = ParseQuestion(Pkt, Len, Name, sizeof(Name), &Type);
    if (!QEnd)
        return 0;

    if (V6)
        InterlockedIncrement(&Hits6);
    else
        InterlockedIncrement(&Hits4);
    InterlockedExchange(&HitsLast, V6 ? 6 : 4);

    if (Type == 12)
    {
        Ip6ReverseName(Addr1, Rev);
        if (!strcmp(Name, Rev))
        {
            Target = "host1.rl6.test";
            Rcode = 0;
        }
        Ip6ReverseName(Addr3, Rev);
        if (!strcmp(Name, Rev))
        {
            if (!V6)
                return 0;
            Target = "host3.rl6.test";
            Rcode = 0;
        }
        if (!strcmp(Name, "55.2.0.192.in-addr.arpa"))
        {
            Target = "map4.rl6.test";
            Rcode = 0;
        }
    }

    memcpy(Out, Pkt, QEnd);
    Out[2] = 0x81;
    Out[3] = 0x80 | Rcode;
    Out[4] = 0; Out[5] = 1;
    Out[6] = 0; Out[7] = Target ? 1 : 0;
    Out[8] = Out[9] = Out[10] = Out[11] = 0;
    N = QEnd;
    if (Target)
    {
        Out[N++] = 0xC0; Out[N++] = 0x0C;
        Out[N++] = 0; Out[N++] = 12;
        Out[N++] = 0; Out[N++] = 1;
        Out[N++] = 0; Out[N++] = 0; Out[N++] = 0; Out[N++] = 60;
        N += 2;
        Len = AppendName(&Out[N], Target);
        Out[N - 2] = 0;
        Out[N - 1] = (UCHAR)Len;
        N += Len;
    }
    return N;
}

static DWORD WINAPI ServerThread(PVOID Param)
{
    while (!Stop)
    {
        fd_set Fds;
        struct timeval Tv = { 0, 100000 };
        int Ready;
        SOCKET S[2] = { Srv4, Srv6 };
        int i;

        FD_ZERO(&Fds);
        for (i = 0; i < 2; i++)
        {
            if (S[i] != INVALID_SOCKET)
                FD_SET(S[i], &Fds);
        }
        Ready = select(0, &Fds, NULL, NULL, &Tv);
        if (Ready <= 0)
            continue;

        for (i = 0; i < 2; i++)
        {
            UCHAR In[512], Out[600];
            SOCKADDR_STORAGE From;
            int FromLen = sizeof(From), Got, N;

            if (S[i] == INVALID_SOCKET || !FD_ISSET(S[i], &Fds))
                continue;
            Got = recvfrom(S[i], (char *)In, sizeof(In), 0, (PSOCKADDR)&From, &FromLen);
            if (Got <= 0)
                continue;
            N = Answer(In, Got, i == 1, Out);
            if (N)
                sendto(S[i], (const char *)Out, N, 0, (PSOCKADDR)&From, FromLen);
        }
    }
    return 0;
}

static BOOL StartServer(HANDLE *Thread)
{
    SOCKADDR_IN A4;
    SOCKADDR_IN6 A6;
    DWORD V6Only = 1;

    Srv4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ZeroMemory(&A4, sizeof(A4));
    A4.sin_family = AF_INET;
    A4.sin_port = htons(53);
    A4.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
    if (Srv4 == INVALID_SOCKET || bind(Srv4, (PSOCKADDR)&A4, sizeof(A4)) != 0)
        return FALSE;

    Srv6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (Srv6 != INVALID_SOCKET)
    {
        setsockopt(Srv6, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&V6Only, sizeof(V6Only));
        ZeroMemory(&A6, sizeof(A6));
        A6.sin6_family = AF_INET6;
        A6.sin6_port = htons(53);
        A6.sin6_addr.u.Byte[15] = 1; /* ::1 */
        if (bind(Srv6, (PSOCKADDR)&A6, sizeof(A6)) != 0)
        {
            closesocket(Srv6);
            Srv6 = INVALID_SOCKET;
        }
    }

    *Thread = CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);
    return *Thread != NULL;
}

static void SetServers(HKEY Key4, HKEY Key6, const char *V4, const char *V6)
{
    if (V4)
        RegSetValueExA(Key4, "NameServer", 0, REG_SZ, (const BYTE *)V4, (DWORD)strlen(V4) + 1);
    else
        RegDeleteValueA(Key4, "NameServer");
    if (V6)
        RegSetValueExA(Key6, "NameServer", 0, REG_SZ, (const BYTE *)V6, (DWORD)strlen(V6) + 1);
    else
        RegDeleteValueA(Key6, "NameServer");
}

static void SetAddr(SOCKADDR_IN6 *Sin, const UCHAR *Addr, ULONG Scope)
{
    ZeroMemory(Sin, sizeof(*Sin));
    Sin->sin6_family = AF_INET6;
    Sin->sin6_port = htons(80);
    memcpy(&Sin->sin6_addr, Addr, 16);
    Sin->sin6_scope_id = Scope;
}

static void Reset(void)
{
    DnsFlushResolverCache();
    Hits4 = Hits6 = HitsLast = 0;
}

/* getnameinfo and GetNameInfoW of one address: the same result from both */
static void CheckNameInfo(const SOCKADDR_IN6 *Sin, int Flags, int ExpectedError, const char *Expected, const char *What)
{
    CHAR Host[NI_MAXHOST] = "";
    WCHAR HostW[NI_MAXHOST] = L"";
    WCHAR ExpectedW[NI_MAXHOST];
    int Error;

    Error = getnameinfo((PSOCKADDR)Sin, sizeof(*Sin), Host, sizeof(Host), NULL, 0, Flags);
    ok(Error == ExpectedError, "%s: getnameinfo(0x%x) returned %d, expected %d\n", What, Flags, Error, ExpectedError);
    if (Error == 0 && Expected)
        ok(!lstrcmpiA(Host, Expected), "%s: getnameinfo(0x%x) gave '%s', expected '%s'\n", What, Flags, Host, Expected);

    Error = GetNameInfoW((PSOCKADDR)Sin, sizeof(*Sin), HostW, RTL_NUMBER_OF(HostW), NULL, 0, Flags);
    ok(Error == ExpectedError, "%s: GetNameInfoW(0x%x) returned %d, expected %d\n", What, Flags, Error, ExpectedError);
    if (Error == 0 && Expected)
    {
        MultiByteToWideChar(CP_ACP, 0, Expected, -1, ExpectedW, RTL_NUMBER_OF(ExpectedW));
        ok(!lstrcmpiW(HostW, ExpectedW), "%s: GetNameInfoW(0x%x) gave '%ls', expected '%ls'\n", What, Flags, HostW, ExpectedW);
    }
}

static void test_ipv4_server(void)
{
    SOCKADDR_IN6 Sin;
    struct hostent *He;

    /* the IPv4 name server answers */
    Reset();
    SetAddr(&Sin, Addr1, 0);
    CheckNameInfo(&Sin, 0, 0, "host1.rl6.test", "IPv4 server, PTR");
    ok(Hits4 >= 1, "the IPv4 server saw no query (%ld)\n", Hits4);
    ok(Hits6 == 0, "the IPv6 server saw %ld queries\n", Hits6);

    /* the resolver service caches it; the other flags give the same name */
    CheckNameInfo(&Sin, NI_NAMEREQD, 0, "host1.rl6.test", "IPv4 server, PTR");
    CheckNameInfo(&Sin, NI_NOFQDN, 0, "host1", "IPv4 server, PTR");

    /* NI_NUMERICHOST: the address, no query */
    Reset();
    CheckNameInfo(&Sin, NI_NUMERICHOST, 0, "2001:db8:5300::1", "NI_NUMERICHOST");
    CheckNameInfo(&Sin, NI_NUMERICHOST | NI_NAMEREQD, 0, "2001:db8:5300::1", "NI_NUMERICHOST|NI_NAMEREQD");
    ok(Hits4 == 0 && Hits6 == 0, "NI_NUMERICHOST made %ld+%ld queries\n", Hits4, Hits6);

    /* no PTR record: the numeric address, or an error with NI_NAMEREQD */
    Reset();
    SetAddr(&Sin, Addr2, 0);
    CheckNameInfo(&Sin, 0, 0, "2001:db8:5300::2", "no PTR");
    CheckNameInfo(&Sin, NI_NAMEREQD, WSAHOST_NOT_FOUND, NULL, "no PTR");
    ok(Hits4 >= 1, "no query for an address without PTR (%ld)\n", Hits4);

    /* an IPv4-mapped address is named through in-addr.arpa */
    Reset();
    SetAddr(&Sin, AddrMapped, 0);
    CheckNameInfo(&Sin, 0, 0, "map4.rl6.test", "IPv4-mapped");

    /* gethostbyaddr */
    Reset();
    He = gethostbyaddr((const char *)Addr1, 16, AF_INET6);
    ok(He != NULL, "gethostbyaddr(AF_INET6) failed: %d\n", WSAGetLastError());
    if (He)
    {
        ok(He->h_name && !lstrcmpiA(He->h_name, "host1.rl6.test"), "gethostbyaddr named '%s'\n", He->h_name);
        ok(He->h_addrtype == AF_INET6, "h_addrtype %d\n", He->h_addrtype);
        ok(He->h_length == 16, "h_length %d\n", He->h_length);
        ok(He->h_addr_list && He->h_addr_list[0] && !memcmp(He->h_addr_list[0], Addr1, 16),
           "h_addr_list does not hold the address\n");
        ok(He->h_addr_list && !He->h_addr_list[1], "more than one address\n");
    }

    He = gethostbyaddr((const char *)Addr2, 16, AF_INET6);
    ok(He == NULL, "gethostbyaddr of an address without PTR returned a name\n");
    ok(WSAGetLastError() == WSANO_DATA || WSAGetLastError() == WSAHOST_NOT_FOUND, "error %d\n", WSAGetLastError());
}

static void test_ipv6_server(void)
{
    SOCKADDR_IN6 Sin;
    struct hostent *He;

    /* the IPv4 server does not answer for this name: the IPv6 one does */
    Reset();
    SetAddr(&Sin, Addr3, 0);
    CheckNameInfo(&Sin, NI_NAMEREQD, 0, "host3.rl6.test", "IPv6 server");
    ok(Hits6 >= 1, "the IPv6 server saw no query (%ld)\n", Hits6);

    Reset();
    He = gethostbyaddr((const char *)Addr3, 16, AF_INET6);
    ok(He != NULL && He->h_name && !lstrcmpiA(He->h_name, "host3.rl6.test"), "gethostbyaddr via the IPv6 server: %s (%d)\n",
       He ? He->h_name : "(null)", WSAGetLastError());
}

static void test_no_query(void)
{
    SOCKADDR_IN6 Sin;
    static const UCHAR LinkLocal[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const UCHAR Unspec[16] = { 0 };
    static const UCHAR Multicast[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    CHAR Host[NI_MAXHOST];
    int Error;

    /* link-local (with its scope), unspecified and multicast addresses are not looked up: the numeric form, or an
       error with NI_NAMEREQD (VERIFY ON ORACLE: the error code Windows gives) */
    Reset();
    SetAddr(&Sin, LinkLocal, 3);
    CheckNameInfo(&Sin, 0, 0, "fe80::1%3", "link-local with scope");
    CheckNameInfo(&Sin, NI_NAMEREQD, WSAHOST_NOT_FOUND, NULL, "link-local with scope");
    CheckNameInfo(&Sin, NI_NUMERICHOST, 0, "fe80::1%3", "link-local with scope");
    SetAddr(&Sin, LinkLocal, 0);
    CheckNameInfo(&Sin, 0, 0, "fe80::1", "link-local, no scope");
    SetAddr(&Sin, Unspec, 0);
    CheckNameInfo(&Sin, NI_NAMEREQD, WSAHOST_NOT_FOUND, NULL, "unspecified");
    SetAddr(&Sin, Multicast, 0);
    CheckNameInfo(&Sin, NI_NAMEREQD, WSAHOST_NOT_FOUND, NULL, "multicast");
    ok(Hits4 == 0 && Hits6 == 0, "no query was to be made: %ld+%ld\n", Hits4, Hits6);

    /* a buffer that is too small is an error, whatever the cache holds */
    SetAddr(&Sin, Addr1, 0);
    Error = getnameinfo((PSOCKADDR)&Sin, sizeof(Sin), Host, 5, NULL, 0, NI_NAMEREQD);
    ok(Error != 0, "getnameinfo into a 5 byte buffer succeeded: '%s'\n", Host);
}

START_TEST(ReverseLookup6)
{
    WSADATA WsaData;
    IP_ADAPTER_ADDRESSES *All = NULL, *A, *Use = NULL;
    ULONG Size = 0, Tries;
    DWORD Error = ERROR_BUFFER_OVERFLOW, Type, Len;
    HANDLE Thread = NULL;
    HKEY Key4, Key6;
    char Name4[512], Name6[512], Old4[512], Old6[512];
    BOOL Had4, Had6;

    Error = WSAStartup(MAKEWORD(2, 2), &WsaData);
    ok_dec(Error, 0);

    if (!is_reactos())
    {
        skip("the name servers are configured in ReactOS's registry values\n");
        return;
    }

    for (Tries = 0, Error = ERROR_BUFFER_OVERFLOW; Tries < 5 && Error == ERROR_BUFFER_OVERFLOW; Tries++)
    {
        free(All);
        All = Size ? malloc(Size) : NULL;
        Error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, All, &Size);
    }
    for (A = (Error == NO_ERROR) ? All : NULL; A; A = A->Next)
    {
        if (A->IfType != IF_TYPE_SOFTWARE_LOOPBACK && A->OperStatus == IfOperStatusUp &&
            (A->Flags & IP_ADAPTER_IPV6_ENABLED))
        {
            Use = A;
            break;
        }
    }
    if (!Use)
    {
        free(All);
        skip("No adapter with IPv6 is up\n");
        return;
    }

    if (!StartServer(&Thread))
    {
        free(All);
        skip("Cannot bind the test name server (127.0.0.1 port 53)\n");
        return;
    }

    snprintf(Name4, sizeof(Name4), "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s", Use->AdapterName);
    snprintf(Name6, sizeof(Name6), "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\%s", Use->AdapterName);
    Error = RegCreateKeyExA(HKEY_LOCAL_MACHINE, Name4, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &Key4, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyEx(%s): %lu\n", Name4, Error);
    if (Error != ERROR_SUCCESS)
        goto Done;
    Error = RegCreateKeyExA(HKEY_LOCAL_MACHINE, Name6, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &Key6, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyEx(%s): %lu\n", Name6, Error);
    if (Error != ERROR_SUCCESS)
    {
        RegCloseKey(Key4);
        goto Done;
    }
    Len = sizeof(Old4) - 1;
    Had4 = RegQueryValueExA(Key4, "NameServer", NULL, &Type, (LPBYTE)Old4, &Len) == ERROR_SUCCESS && Type == REG_SZ;
    if (Had4)
        Old4[Len] = 0;
    Len = sizeof(Old6) - 1;
    Had6 = RegQueryValueExA(Key6, "NameServer", NULL, &Type, (LPBYTE)Old6, &Len) == ERROR_SUCCESS && Type == REG_SZ;
    if (Had6)
        Old6[Len] = 0;

    /* the IPv4 server only, then the IPv4 server that stays silent for one name and the IPv6 one */
    SetServers(Key4, Key6, "127.0.0.1", NULL);
    test_ipv4_server();
    SetServers(Key4, Key6, "127.0.0.1", "::1");
    test_ipv6_server();
    test_no_query();

    /* restore */
    if (Had4)
        RegSetValueExA(Key4, "NameServer", 0, REG_SZ, (const BYTE *)Old4, (DWORD)strlen(Old4) + 1);
    else
        RegDeleteValueA(Key4, "NameServer");
    if (Had6)
        RegSetValueExA(Key6, "NameServer", 0, REG_SZ, (const BYTE *)Old6, (DWORD)strlen(Old6) + 1);
    else
        RegDeleteValueA(Key6, "NameServer");
    RegCloseKey(Key4);
    RegCloseKey(Key6);
    DnsFlushResolverCache();

Done:
    InterlockedExchange(&Stop, 1);
    WaitForSingleObject(Thread, 5000);
    CloseHandle(Thread);
    closesocket(Srv4);
    if (Srv6 != INVALID_SOCKET)
        closesocket(Srv6);
    free(All);
    WSACleanup();
}
