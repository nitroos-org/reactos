/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     getaddrinfo with and without IPv6 on the stack (Tcpip\Parameters\Ipv6Enable): the answers of a system
 *              without IPv6 while it is off, and the order, flags and error codes Windows 10 22H2 gives for the
 *              names that mean this machine, numeric IPv6 addresses and AI_ADDRCONFIG while it is on
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <winreg.h>
#include <winnls.h>
#include <iptypes.h>
#include <nldef.h>

#define MAX_EXPECTED 3

typedef struct
{
    int Family;
    int Flags;
    const char *Addr;           /* "::1" (the eight groups, e.g. "0:0:0:0:0:0:0:1") or "127.0.0.1" */
} EXPECTED;

typedef struct
{
    const char *Node;
    const char *Service;
    int UseHints;
    int Family;
    int Flags;
    int SockType;
    /* what a system without IPv6 answers: an error (non-zero Error), or the entries */
    int ErrorOff;
    EXPECTED Off[MAX_EXPECTED];
    /* with IPv6 on and a usable non-loopback IPv6 address */
    int ErrorOn;
    EXPECTED On[MAX_EXPECTED];
    /* with IPv6 on and no usable non-loopback IPv6 address (AI_ADDRCONFIG cases only; Family 0 end = same as On) */
    int HasNoV6Variant;
    int ErrorNoV6;
    EXPECTED NoV6[MAX_EXPECTED];
} CASE;

#define V4(a)       { AF_INET, 0, a }
#define V6(a)       { AF_INET6, 0, a }
#define NUM4(a)     { AF_INET, AI_NUMERICHOST, a }
#define NUM6(a)     { AF_INET6, AI_NUMERICHOST, a }
#define END         { 0, 0, NULL }

#define LOOP6       "0:0:0:0:0:0:0:1"
#define ANY6        "0:0:0:0:0:0:0:0"

static BOOL Ipv6On;
static BOOL HasUsableV6;    /* a non-loopback IPv6 address that is preferred or deprecated */

static const CASE Cases[] =
{
    /* localhost: IPv6 before IPv4 for both families, whatever the socket type and port */
    { "localhost", NULL, 0, 0, 0, 0,
      0, { V4("127.0.0.1"), END },
      0, { V6(LOOP6), V4("127.0.0.1") } },
    { "localhost", NULL, 1, AF_UNSPEC, 0, 0,
      0, { V4("127.0.0.1"), END },
      0, { V6(LOOP6), V4("127.0.0.1") } },
    { "localhost", "80", 1, AF_UNSPEC, 0, SOCK_STREAM,
      0, { V4("127.0.0.1"), END },
      0, { V6(LOOP6), V4("127.0.0.1") } },
    { "localhost", "80", 1, AF_UNSPEC, 0, 0,
      0, { V4("127.0.0.1"), END },
      0, { V6(LOOP6), V4("127.0.0.1") } },
    { "LOCALHOST", "80", 1, AF_UNSPEC, 0, SOCK_STREAM,
      0, { V4("127.0.0.1"), END },
      0, { V6(LOOP6), V4("127.0.0.1") } },
    { "localhost.", "80", 1, AF_UNSPEC, 0, SOCK_STREAM,
      WSAHOST_NOT_FOUND, { END },
      0, { V6(LOOP6), V4("127.0.0.1") } },
    { "localhost", "80", 1, AF_INET6, 0, SOCK_STREAM,
      0, { V6(LOOP6), END },
      0, { V6(LOOP6), END } },
    { "localhost", "80", 1, AF_INET, 0, SOCK_STREAM,
      0, { V4("127.0.0.1"), END },
      0, { V4("127.0.0.1"), END } },
    { "localhost", "80", 1, AF_UNSPEC, AI_NUMERICHOST, SOCK_STREAM,
      WSAHOST_NOT_FOUND, { END },
      WSAHOST_NOT_FOUND, { END } },
    { "localhost", "80", 1, AF_INET6, AI_NUMERICHOST, SOCK_STREAM,
      WSAEAFNOSUPPORT, { END },
      WSAHOST_NOT_FOUND, { END } },
    /* AI_ADDRCONFIG: IPv6 answers only while there is a non-loopback IPv6 address to use */
    { "localhost", "80", 1, AF_UNSPEC, AI_ADDRCONFIG, SOCK_STREAM,
      0, { V4("127.0.0.1"), END },
      0, { V6(LOOP6), V4("127.0.0.1") },
      1, 0, { V4("127.0.0.1"), END } },
    { "localhost", "80", 1, AF_INET6, AI_ADDRCONFIG, SOCK_STREAM,
      0, { V6(LOOP6), END },
      0, { V6(LOOP6), END },
      1, WSAHOST_NOT_FOUND, { END } },
    { "localhost", "80", 1, AF_INET, AI_ADDRCONFIG, SOCK_STREAM,
      0, { V4("127.0.0.1"), END },
      0, { V4("127.0.0.1"), END } },
    /* no node name: the wildcard for a server, the loopback address for a client */
    { NULL, "80", 1, AF_UNSPEC, AI_PASSIVE, SOCK_STREAM,
      0, { V4("0.0.0.0"), END },
      0, { V6(ANY6), V4("0.0.0.0") } },
    { NULL, "80", 1, AF_UNSPEC, 0, SOCK_STREAM,
      0, { V4("127.0.0.1"), END },
      0, { V6(LOOP6), V4("127.0.0.1") } },
    { NULL, "80", 0, 0, 0, 0,
      0, { V4("127.0.0.1"), END },
      0, { V6(LOOP6), V4("127.0.0.1") } },
    { NULL, "80", 1, AF_UNSPEC, AI_PASSIVE, SOCK_DGRAM,
      0, { V4("0.0.0.0"), END },
      0, { V6(ANY6), V4("0.0.0.0") } },
    { NULL, "80", 1, AF_UNSPEC, AI_PASSIVE, SOCK_RAW,
      0, { V4("0.0.0.0"), END },
      0, { V6(ANY6), V4("0.0.0.0") } },
    { NULL, "80", 1, AF_INET6, AI_PASSIVE, SOCK_STREAM,
      0, { V6(ANY6), END },
      0, { V6(ANY6), END } },
    { NULL, "80", 1, AF_INET6, 0, SOCK_STREAM,
      0, { V6(LOOP6), END },
      0, { V6(LOOP6), END } },
    { NULL, "80", 1, AF_INET, AI_PASSIVE, SOCK_STREAM,
      0, { V4("0.0.0.0"), END },
      0, { V4("0.0.0.0"), END } },
    { NULL, "80", 1, AF_INET, 0, SOCK_STREAM,
      0, { V4("127.0.0.1"), END },
      0, { V4("127.0.0.1"), END } },
    { NULL, "80", 1, AF_UNSPEC, AI_PASSIVE | AI_ADDRCONFIG, SOCK_STREAM,
      0, { V4("0.0.0.0"), END },
      0, { V6(ANY6), V4("0.0.0.0") },
      1, 0, { V4("0.0.0.0"), END } },
    { NULL, "80", 1, AF_UNSPEC, AI_ADDRCONFIG, SOCK_STREAM,
      0, { V4("127.0.0.1"), END },
      0, { V6(LOOP6), V4("127.0.0.1") },
      1, 0, { V4("127.0.0.1"), END } },
    { NULL, "80", 1, AF_INET6, AI_PASSIVE | AI_ADDRCONFIG, SOCK_STREAM,
      0, { V6(ANY6), END },
      0, { V6(ANY6), END },
      1, WSAHOST_NOT_FOUND, { END } },
    /* numeric addresses: not filtered, not resolved */
    { "::1", NULL, 1, AF_UNSPEC, 0, 0,
      0, { NUM6(LOOP6), END },
      0, { NUM6(LOOP6), END } },
    { "::1", "80", 1, AF_UNSPEC, AI_ADDRCONFIG, SOCK_STREAM,
      0, { NUM6(LOOP6), END },
      0, { NUM6(LOOP6), END } },
    { "::1", "80", 1, AF_INET, 0, SOCK_STREAM,
      WSAHOST_NOT_FOUND, { END },
      WSAHOST_NOT_FOUND, { END } },
    { "::ffff:1.2.3.4", "80", 1, AF_UNSPEC, 0, SOCK_STREAM,
      0, { NUM6("0:0:0:0:0:ffff:102:304"), END },
      0, { NUM6("0:0:0:0:0:ffff:102:304"), END } },
    { "[::1]", "80", 1, AF_INET6, 0, SOCK_STREAM,
      0, { NUM6(LOOP6), END },
      0, { NUM6(LOOP6), END } },
    { "2001:db8::1", "80", 1, AF_UNSPEC, AI_ADDRCONFIG, SOCK_STREAM,
      0, { NUM6("2001:db8:0:0:0:0:0:1"), END },
      0, { NUM6("2001:db8:0:0:0:0:0:1"), END } },
    { "127.0.0.1", "80", 1, AF_UNSPEC, AI_ADDRCONFIG, SOCK_STREAM,
      0, { NUM4("127.0.0.1"), END },
      0, { NUM4("127.0.0.1"), END } },
    { "1.2.3.4", "80", 1, AF_UNSPEC, 0, SOCK_STREAM,
      0, { NUM4("1.2.3.4"), END },
      0, { NUM4("1.2.3.4"), END } },
    /* the IPv6 family finds no IPv4 address; a system without IPv6 has no such family */
    { "1.2.3.4", "80", 1, AF_INET6, 0, SOCK_STREAM,
      WSAEAFNOSUPPORT, { END },
      WSAHOST_NOT_FOUND, { END } },
    { "1:2:3:4:5:6:7:8:9", "80", 1, AF_INET6, 0, SOCK_STREAM,
      WSAEAFNOSUPPORT, { END },
      WSAHOST_NOT_FOUND, { END } },
};

/* An address as the test spells it: IPv4 in dotted form, IPv6 as eight groups of hexadecimal digits */
static void FormatAddress(const ADDRINFOA *Info, char *Text, size_t Size)
{
    if (Info->ai_family == AF_INET && Info->ai_addr)
    {
        const UCHAR *p = (const UCHAR *)&((const SOCKADDR_IN *)Info->ai_addr)->sin_addr;

        _snprintf(Text, Size, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    }
    else if (Info->ai_family == AF_INET6 && Info->ai_addr)
    {
        const UCHAR *p = (const UCHAR *)&((const SOCKADDR_IN6 *)Info->ai_addr)->sin6_addr;

        _snprintf(Text, Size, "%x:%x:%x:%x:%x:%x:%x:%x", (p[0] << 8) | p[1], (p[2] << 8) | p[3], (p[4] << 8) | p[5],
                  (p[6] << 8) | p[7], (p[8] << 8) | p[9], (p[10] << 8) | p[11], (p[12] << 8) | p[13],
                  (p[14] << 8) | p[15]);
    }
    else
        _snprintf(Text, Size, "family %d", Info->ai_family);
    Text[Size - 1] = 0;
}

/* Whether an IPv6 address that can be used as a source (preferred, or deprecated) is on a non-loopback interface */
typedef ULONG (WINAPI *PGET_ADAPTERS_ADDRESSES)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);

static BOOL FindUsableV6(void)
{
    PGET_ADAPTERS_ADDRESSES pGetAdaptersAddresses;
    HMODULE hIphlpapi = LoadLibraryA("iphlpapi.dll");
    IP_ADAPTER_ADDRESSES *Buffer = NULL, *A;
    ULONG Size = 0, Try, Result = ERROR_BUFFER_OVERFLOW;
    BOOL Found = FALSE;

    pGetAdaptersAddresses = hIphlpapi ? (PGET_ADAPTERS_ADDRESSES)GetProcAddress(hIphlpapi, "GetAdaptersAddresses") : NULL;
    if (!pGetAdaptersAddresses)
        return FALSE;

    for (Try = 0; Try < 4 && Result == ERROR_BUFFER_OVERFLOW; Try++)
    {
        free(Buffer);
        Buffer = Size ? malloc(Size) : NULL;
        if (Size && !Buffer)
            return FALSE;
        Result = pGetAdaptersAddresses(AF_INET6, 0, NULL, Buffer, &Size);
    }
    for (A = Result == NO_ERROR ? Buffer : NULL; A; A = A->Next)
    {
        IP_ADAPTER_UNICAST_ADDRESS *U;

        if (A->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        for (U = A->FirstUnicastAddress; U; U = U->Next)
            if (U->Address.lpSockaddr && U->Address.lpSockaddr->sa_family == AF_INET6 &&
                (U->DadState == IpDadStatePreferred || U->DadState == IpDadStateDeprecated))
                Found = TRUE;
    }
    free(Buffer);
    return Found;
}

static BOOL ReadSwitch(void)
{
    HKEY Key;
    DWORD Value = 0, Size = sizeof(Value), Type = 0;
    BOOL On = FALSE;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", 0, KEY_READ, &Key) ==
        ERROR_SUCCESS)
    {
        if (RegQueryValueExA(Key, "Ipv6Enable", NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
            Type == REG_DWORD && Value != 0)
            On = TRUE;
        RegCloseKey(Key);
    }
    return On;
}

static void RunCase(int Index, const CASE *C, int Wide)
{
    ADDRINFOA Hints, *Result = NULL, *Info;
    ADDRINFOW HintsW, *ResultW = NULL;
    int Error, Count = 0, ExpectedError, n;
    const EXPECTED *Expected;
    char Text[96];

    if (!Ipv6On)
    {
        ExpectedError = C->ErrorOff;
        Expected = C->Off;
    }
    else if (C->HasNoV6Variant && !HasUsableV6)
    {
        ExpectedError = C->ErrorNoV6;
        Expected = C->NoV6;
    }
    else
    {
        ExpectedError = C->ErrorOn;
        Expected = C->On;
    }

    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_family = C->Family;
    Hints.ai_flags = C->Flags;
    Hints.ai_socktype = C->SockType;

    if (!Wide)
    {
        Error = getaddrinfo(C->Node, C->Service, C->UseHints ? &Hints : NULL, &Result);
    }
    else
    {
        WCHAR NodeW[64], ServiceW[16];
        ADDRINFOA *Convert;

        memset(&HintsW, 0, sizeof(HintsW));
        HintsW.ai_family = C->Family;
        HintsW.ai_flags = C->Flags;
        HintsW.ai_socktype = C->SockType;
        if (C->Node)
            MultiByteToWideChar(CP_ACP, 0, C->Node, -1, NodeW, 64);
        if (C->Service)
            MultiByteToWideChar(CP_ACP, 0, C->Service, -1, ServiceW, 16);
        Error = GetAddrInfoW(C->Node ? NodeW : NULL, C->Service ? ServiceW : NULL, C->UseHints ? &HintsW : NULL,
                             &ResultW);
        /* the same entries, read through the ANSI view: the layouts agree up to the canonical name */
        Convert = (ADDRINFOA *)ResultW;
        Result = Convert;
    }

    ok(Error == ExpectedError, "%d%s: '%s' family %d flags 0x%x type %d: error %d, expected %d\n", Index,
       Wide ? "W" : "", C->Node ? C->Node : "(null)", C->Family, C->Flags, C->SockType, Error, ExpectedError);

    if (Error == 0)
    {
        for (Info = Result; Info; Info = Info->ai_next)
        {
            Count++;
            n = Count - 1;
            if (n >= MAX_EXPECTED || !Expected[n].Addr)
                continue;

            FormatAddress(Info, Text, sizeof(Text));
            ok(Info->ai_family == Expected[n].Family, "%d%s entry %d: family %d, expected %d\n", Index, Wide ? "W" : "",
               n, Info->ai_family, Expected[n].Family);
            ok(!strcmp(Text, Expected[n].Addr), "%d%s entry %d: address %s, expected %s\n", Index, Wide ? "W" : "", n,
               Text, Expected[n].Addr);
            ok(Info->ai_flags == Expected[n].Flags, "%d%s entry %d: flags 0x%x, expected 0x%x\n", Index,
               Wide ? "W" : "", n, Info->ai_flags, Expected[n].Flags);
            ok(Info->ai_socktype == (C->UseHints ? C->SockType : 0), "%d%s entry %d: socket type %d\n", Index,
               Wide ? "W" : "", n, Info->ai_socktype);
            ok(Info->ai_protocol == 0, "%d%s entry %d: protocol %d\n", Index, Wide ? "W" : "", n, Info->ai_protocol);
            ok(Info->ai_addrlen == (size_t)(Info->ai_family == AF_INET6 ? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN)),
               "%d%s entry %d: address length %u\n", Index, Wide ? "W" : "", n, (unsigned)Info->ai_addrlen);
            if (C->Service && Info->ai_addr)
            {
                USHORT Port = Info->ai_family == AF_INET6 ? ((SOCKADDR_IN6 *)Info->ai_addr)->sin6_port
                                                          : ((SOCKADDR_IN *)Info->ai_addr)->sin_port;
                ok(ntohs(Port) == 80, "%d%s entry %d: port %u\n", Index, Wide ? "W" : "", n, ntohs(Port));
            }
            if (Info->ai_family == AF_INET6 && Info->ai_addr)
            {
                SOCKADDR_IN6 *S = (SOCKADDR_IN6 *)Info->ai_addr;

                ok(S->sin6_flowinfo == 0 && S->sin6_scope_id == 0, "%d%s entry %d: flow %lu scope %lu\n", Index,
                   Wide ? "W" : "", n, S->sin6_flowinfo, S->sin6_scope_id);
            }
        }
        {
            int Want = 0;

            while (Want < MAX_EXPECTED && Expected[Want].Addr)
                Want++;
            ok(Count == Want, "%d%s: '%s' family %d flags 0x%x type %d: %d entries, expected %d\n", Index,
               Wide ? "W" : "", C->Node ? C->Node : "(null)", C->Family, C->Flags, C->SockType, Count, Want);
        }
    }
    else
    {
        ok(Wide ? ResultW == NULL : Result == NULL, "%d%s: result %p after the error\n", Index, Wide ? "W" : "",
           Wide ? (void *)ResultW : (void *)Result);
    }

    if (Wide)
    {
        if (ResultW)
            FreeAddrInfoW(ResultW);
    }
    else if (Result)
        freeaddrinfo(Result);
}

static void TestCanonicalNames(void)
{
    ADDRINFOA Hints, *Info = NULL;
    char Host[256];
    int Error;

    if (!Ipv6On)
        return;

    if (gethostname(Host, sizeof(Host)) != 0)
        Host[0] = 0;

    /* "localhost": the name of this computer, on the first entry only */
    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_flags = AI_CANONNAME;
    Hints.ai_socktype = SOCK_STREAM;
    Error = getaddrinfo("localhost", "80", &Hints, &Info);
    ok(Error == 0 && Info, "getaddrinfo(localhost, AI_CANONNAME): %d\n", Error);
    if (Error == 0 && Info)
    {
        ok(Info->ai_canonname && !_stricmp(Info->ai_canonname, Host), "canonical name '%s', computer '%s'\n",
           Info->ai_canonname ? Info->ai_canonname : "(null)", Host);
        ok(Info->ai_next && Info->ai_next->ai_canonname == NULL, "the second entry has a canonical name\n");
        freeaddrinfo(Info);
    }

    /* a numeric address with a service: "[::1]:80" (Windows 10 measured) */
    Info = NULL;
    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_flags = AI_CANONNAME;
    Hints.ai_socktype = SOCK_STREAM;
    Error = getaddrinfo("::1", "80", &Hints, &Info);
    ok(Error == 0 && Info, "getaddrinfo(::1, AI_CANONNAME): %d\n", Error);
    if (Error == 0 && Info)
    {
        ok(Info->ai_canonname && !strcmp(Info->ai_canonname, "[::1]:80"), "canonical name '%s'\n",
           Info->ai_canonname ? Info->ai_canonname : "(null)");
        freeaddrinfo(Info);
    }
}

START_TEST(getaddrinfo6)
{
    WSADATA WsaData;
    unsigned i;
    int Error;

    Error = WSAStartup(MAKEWORD(2, 2), &WsaData);
    ok_dec(Error, 0);

    Ipv6On = ReadSwitch();
    if (Ipv6On)
    {
        /* DAD takes a moment: wait until the link-local address can be used */
        for (i = 0; i < 30 && !(HasUsableV6 = FindUsableV6()); i++)
            Sleep(500);
    }
    trace("Ipv6Enable is %s, usable non-loopback IPv6 address: %s\n", Ipv6On ? "on" : "off",
          HasUsableV6 ? "yes" : "no");

    for (i = 0; i < sizeof(Cases) / sizeof(Cases[0]); i++)
        RunCase((int)i, &Cases[i], 0);
    /* the wide function behind getaddrinfo, a few of them */
    for (i = 0; i < 12 && i < sizeof(Cases) / sizeof(Cases[0]); i++)
        RunCase((int)i, &Cases[i], 1);

    TestCanonicalNames();

    WSACleanup();
}
