/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPLv2+ - See COPYING in the top level directory
 * PURPOSE:         Test for getaddrinfo
 * PROGRAMMER:      Thomas Faber <thomas.faber@reactos.org>
 */

#include "ws2_32.h"

#define ok_addrinfo(ai, flags, family, socktype, protocol, addrlen) do  \
{                                                                       \
    ok_hex((ai)->ai_flags, flags);                                      \
    ok_dec((ai)->ai_family, family);                                    \
    ok_dec((ai)->ai_socktype, socktype);                                \
    ok_dec((ai)->ai_protocol, protocol);                                \
    ok_dec((int)(ai)->ai_addrlen, addrlen);                             \
} while (0)

#define ok_sockaddr_in(sockaddr, family, port, addr) do                 \
{                                                                       \
    int _i;                                                             \
    ok_dec(((SOCKADDR_IN *)(sockaddr))->sin_family, family);            \
    ok_dec(ntohs(((SOCKADDR_IN *)(sockaddr))->sin_port), port);         \
    ok_hex(((SOCKADDR_IN *)(sockaddr))->sin_addr.S_un.S_addr,           \
           inet_addr(addr));                                            \
    for (_i = 0; _i < 7; _i++)                                          \
        ok_dec(((SOCKADDR_IN *)(sockaddr))->sin_zero[_i], 0);           \
} while (0)

static CHAR LocalAddress[sizeof("255.255.255.255")];

static
VOID
TestNodeName(VOID)
{
    int Error;
    PADDRINFOA AddrInfo;
    ADDRINFOA Hints;
    struct
    {
        PCSTR NodeName;
        PCSTR ExpectedAddress;
        INT Flags;
    } Tests[] =
    {
        { "",                               LocalAddress },
        { " ",                              NULL },
        { "doesntexist.example.com",        NULL },
        { "localhost",                      "127.0.0.1" },
        { "localhost:80",                   NULL },
        { "7.8.9.10",                       "7.8.9.10",         AI_NUMERICHOST },
        { "0.0.0.0",                        "0.0.0.0",          AI_NUMERICHOST },
        { "255.255.255.255",                "255.255.255.255",  AI_NUMERICHOST },
        { "0.0.0.0 ",                       "0.0.0.0",    /* no AI_NUMERICHOST */ },
        { "0.0.0.0:80",                     NULL },
        { "0.0.0.0.0",                      NULL },
        { "1.1.1.256",                      NULL },
        { "1.2.3",                          NULL },
        { "1.2.3.0x4",                      "1.2.3.4",          AI_NUMERICHOST },
        { "1.2.3.010",                      "1.2.3.8",          AI_NUMERICHOST },
        /* let's just assume this one doesn't change any time soon ;) */
        { "google-public-dns-a.google.com", "8.8.8.8" },
    };
    const INT TestCount = sizeof(Tests) / sizeof(Tests[0]);
    INT i;

    /* make sure we don't get IPv6 responses */
    ZeroMemory(&Hints, sizeof(Hints));
    Hints.ai_family = AF_INET;

    trace("Nodes\n");
    for (i = 0; i < TestCount; i++)
    {
        trace("%d: '%s'\n", i, Tests[i].NodeName);
        StartSeh()
            AddrInfo = InvalidPointer;
            Error = getaddrinfo(Tests[i].NodeName, NULL, &Hints, &AddrInfo);
            if (Tests[i].ExpectedAddress)
            {
                ok_dec(Error, 0);
                ok_dec(WSAGetLastError(), 0);
                ok(AddrInfo != NULL && AddrInfo != InvalidPointer,
                   "AddrInfo = %p\n", AddrInfo);
            }
            else
            {
                ok_dec(Error, WSAHOST_NOT_FOUND);
                ok_dec(WSAGetLastError(), WSAHOST_NOT_FOUND);
                ok_ptr(AddrInfo, NULL);
            }
            if (!Error && AddrInfo && AddrInfo != InvalidPointer)
            {
                ok_addrinfo(AddrInfo, Tests[i].Flags, AF_INET,
                            0, 0, sizeof(SOCKADDR_IN));
                ok_ptr(AddrInfo->ai_canonname, NULL);
                ok_sockaddr_in(AddrInfo->ai_addr, AF_INET,
                               0, Tests[i].ExpectedAddress);
                ok_ptr(AddrInfo->ai_next, NULL);
                freeaddrinfo(AddrInfo);
            }
        EndSeh(STATUS_SUCCESS);
    }
}

static
VOID
TestServiceName(VOID)
{
    int Error;
    PADDRINFOA AddrInfo;
    ADDRINFOA Hints;
    struct
    {
        PCSTR ServiceName;
        INT ExpectedPort;
        INT SockType;
    } Tests[] =
    {
        { "", 0 },
        { "0", 0 },
        { "1", 1 },
        { "a", -1 },
        { "010", 10 },
        { "0x1a", -1 },
        { "http", 80, SOCK_STREAM },
        { "smtp", 25, SOCK_STREAM },
        { "mail", 25, SOCK_STREAM }, /* alias for smtp */
        { "router", 520, SOCK_DGRAM },
        { "domain", 53, 0 /* DNS supports both UDP and TCP */ },
        { ":0", -1 },
        { "123", 123 },
        { " 123", 123 },
        { "    123", 123 },
        { "32767", 32767 },
        { "32768", 32768 },
        { "65535", 65535 },
        { "65536", 0 },
        { "65537", 1 },
        { "65540", 4 },
        { "65536", 0 },
        { "4294967295", 65535 },
        { "4294967296", 65535 },
        { "9999999999", 65535 },
        { "999999999999999999999999999999999999", 65535 },
        { "+5", 5 },
        { "-1", 65535 },
        { "-4", 65532 },
        { "-65534", 2 },
        { "-65535", 1 },
        { "-65536", 0 },
        { "-65537", 65535 },
        { "28a", -1 },
        { "28 ", -1 },
        { "a28", -1 },
    };
    const INT TestCount = sizeof(Tests) / sizeof(Tests[0]);
    INT i;

    /* make sure we don't get IPv6 responses */
    ZeroMemory(&Hints, sizeof(Hints));
    Hints.ai_family = AF_INET;

    trace("Services\n");
    for (i = 0; i < TestCount; i++)
    {
        trace("%d: '%s'\n", i, Tests[i].ServiceName);
        StartSeh()
            AddrInfo = InvalidPointer;
            Error = getaddrinfo(NULL, Tests[i].ServiceName, &Hints, &AddrInfo);
            if (Tests[i].ExpectedPort != -1)
            {
                ok_dec(Error, 0);
                ok_dec(WSAGetLastError(), 0);
                ok(AddrInfo != NULL && AddrInfo != InvalidPointer,
                   "AddrInfo = %p\n", AddrInfo);
            }
            else
            {
                ok_dec(Error, WSATYPE_NOT_FOUND);
                ok_dec(WSAGetLastError(), WSATYPE_NOT_FOUND);
                ok_ptr(AddrInfo, NULL);
            }
            if (!Error && AddrInfo && AddrInfo != InvalidPointer)
            {
                ok_addrinfo(AddrInfo, 0, AF_INET,
                            Tests[i].SockType, 0, sizeof(SOCKADDR_IN));
                ok_ptr(AddrInfo->ai_canonname, NULL);
                ok_sockaddr_in(AddrInfo->ai_addr, AF_INET,
                               Tests[i].ExpectedPort, "127.0.0.1");
                ok_ptr(AddrInfo->ai_next, NULL);
                freeaddrinfo(AddrInfo);
            }
        EndSeh(STATUS_SUCCESS);
    }
}

static
VOID
TestIpv6Literal(VOID)
{
    static const IN6_ADDR Loopback = { { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };
    static const IN6_ADDR LinkLocal = { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };
    static const IN6_ADDR Global = { { { 0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11 } } };
    struct
    {
        PCSTR NodeName;
        INT Family;
        INT Flags;
        const IN6_ADDR *Address;    /* NULL: not found */
        ULONG ScopeId;
    } Tests[] =
    {
        /* An IPv6 address is returned whether or not the machine has IPv6: nothing is looked up */
        { "::1",                    AF_UNSPEC,  AI_NUMERICHOST, &Loopback },
        { "::1",                    AF_INET6,   AI_NUMERICHOST, &Loopback },
        { "::1",                    AF_UNSPEC,  0,              &Loopback },
        { "[::1]",                  AF_UNSPEC,  AI_NUMERICHOST, &Loopback },
        { "[::1]:80",               AF_UNSPEC,  AI_NUMERICHOST, &Loopback },
        { "2606:4700::1111",        AF_UNSPEC,  AI_NUMERICHOST, &Global },
        { "fe80::1",                AF_UNSPEC,  AI_NUMERICHOST, &LinkLocal },
        { "fe80::1%4",              AF_UNSPEC,  AI_NUMERICHOST, &LinkLocal, 4 },
        { "[fe80::1%4]",            AF_UNSPEC,  AI_NUMERICHOST, &LinkLocal, 4 },
        /* Only the IPv4 family was asked for */
        { "::1",                    AF_INET,    AI_NUMERICHOST, NULL },
        /* Not addresses */
        { "[::1",                   AF_UNSPEC,  AI_NUMERICHOST, NULL },
        { "::1]",                   AF_UNSPEC,  AI_NUMERICHOST, NULL },
        { "[::1]x",                 AF_UNSPEC,  AI_NUMERICHOST, NULL },
        { ":::1",                   AF_UNSPEC,  AI_NUMERICHOST, NULL },
        { "::g",                    AF_UNSPEC,  AI_NUMERICHOST, NULL },
        { "fe80::1%",               AF_UNSPEC,  AI_NUMERICHOST, NULL },
        { "1:2:3:4:5:6:7:8:9",      AF_UNSPEC,  AI_NUMERICHOST, NULL },
    };
    INT i;

    trace("IPv6 literals\n");
    for (i = 0; i < (INT)RTL_NUMBER_OF(Tests); i++)
    {
        ADDRINFOA Hints, *AddrInfo = InvalidPointer;
        INT Error;

        ZeroMemory(&Hints, sizeof(Hints));
        Hints.ai_family = Tests[i].Family;
        Hints.ai_flags = Tests[i].Flags;
        Hints.ai_socktype = SOCK_STREAM;
        Error = getaddrinfo(Tests[i].NodeName, "80", &Hints, &AddrInfo);
        if (Tests[i].Address)
        {
            ok(Error == 0, "%d: '%s' returned %d\n", i, Tests[i].NodeName, Error);
            ok(AddrInfo != NULL && AddrInfo != InvalidPointer, "%d: AddrInfo = %p\n", i, AddrInfo);
            if (!Error && AddrInfo && AddrInfo != InvalidPointer)
            {
                SOCKADDR_IN6 *Address = (SOCKADDR_IN6 *)AddrInfo->ai_addr;

                ok(AddrInfo->ai_family == AF_INET6, "%d: ai_family = %d\n", i, AddrInfo->ai_family);
                ok(AddrInfo->ai_socktype == SOCK_STREAM, "%d: ai_socktype = %d\n", i, AddrInfo->ai_socktype);
                ok((int)AddrInfo->ai_addrlen == sizeof(SOCKADDR_IN6), "%d: ai_addrlen = %d\n", i, (int)AddrInfo->ai_addrlen);
                ok(AddrInfo->ai_next == NULL, "%d: ai_next = %p\n", i, AddrInfo->ai_next);
                if (AddrInfo->ai_addr && (int)AddrInfo->ai_addrlen == sizeof(SOCKADDR_IN6))
                {
                    ok(Address->sin6_family == AF_INET6, "%d: sin6_family = %d\n", i, Address->sin6_family);
                    ok(ntohs(Address->sin6_port) == 80, "%d: sin6_port = %d\n", i, ntohs(Address->sin6_port));
                    ok(!memcmp(&Address->sin6_addr, Tests[i].Address, sizeof(IN6_ADDR)), "%d: wrong address\n", i);
                    ok(Address->sin6_scope_id == Tests[i].ScopeId, "%d: sin6_scope_id = %lu\n", i, Address->sin6_scope_id);
                    ok(Address->sin6_flowinfo == 0, "%d: sin6_flowinfo = %lu\n", i, Address->sin6_flowinfo);
                }
                freeaddrinfo(AddrInfo);
            }
        }
        else
        {
            ok(Error == WSAHOST_NOT_FOUND, "%d: '%s' returned %d\n", i, Tests[i].NodeName, Error);
            ok(AddrInfo == NULL, "%d: AddrInfo = %p\n", i, AddrInfo);
        }
    }

    /* The canonical name is the numeric form */
    {
        ADDRINFOA Hints, *AddrInfo = NULL;

        ZeroMemory(&Hints, sizeof(Hints));
        Hints.ai_flags = AI_NUMERICHOST | AI_CANONNAME;
        if (getaddrinfo("::1", NULL, &Hints, &AddrInfo) == 0 && AddrInfo)
        {
            ok(AddrInfo->ai_canonname != NULL, "ai_canonname is NULL\n");
            if (AddrInfo->ai_canonname)
                ok(!strcmp(AddrInfo->ai_canonname, "::1"), "ai_canonname = '%s'\n", AddrInfo->ai_canonname);
            freeaddrinfo(AddrInfo);
        }
        else
        {
            ok(0, "getaddrinfo(::1, AI_CANONNAME) failed\n");
        }
    }
}

START_TEST(getaddrinfo)
{
    WSADATA WsaData;
    int Error;
    PADDRINFOA AddrInfo;
    PADDRINFOW AddrInfoW;
    ADDRINFOA Hints;
    ADDRINFOW HintsW;
    CHAR LocalHostName[128];
    struct hostent *Hostent;

    /* not yet initialized */
    StartSeh()
        Error = getaddrinfo(NULL, NULL, NULL, NULL);
        ok_dec(Error, WSANOTINITIALISED);
    EndSeh(STATUS_SUCCESS);
    StartSeh()
        AddrInfo = InvalidPointer;
        Error = getaddrinfo(NULL, NULL, NULL, &AddrInfo);
        ok_dec(Error, WSANOTINITIALISED);
        ok_ptr(AddrInfo, InvalidPointer);
    EndSeh(STATUS_SUCCESS);

    Error = getaddrinfo("127.0.0.1", "80", NULL, &AddrInfo);
    ok_dec(Error, WSANOTINITIALISED);

    Error = GetAddrInfoW(L"127.0.0.1", L"80", NULL, &AddrInfoW);
    ok_dec(Error, WSANOTINITIALISED);

    Error = WSAStartup(MAKEWORD(2, 2), &WsaData);
    ok_dec(Error, 0);

    /* initialize LocalAddress for tests */
    Error = gethostname(LocalHostName, sizeof(LocalHostName));
    ok_dec(Error, 0);
    ok_dec(WSAGetLastError(), 0);
    trace("Local host name is '%s'\n", LocalHostName);
    Hostent = gethostbyname(LocalHostName);
    ok(Hostent != NULL, "gethostbyname failed with %d\n", WSAGetLastError());
    if (Hostent && Hostent->h_addr_list[0] && Hostent->h_length == sizeof(IN_ADDR))
    {
        IN_ADDR Address;
        memcpy(&Address, Hostent->h_addr_list[0], sizeof(Address));
        strcpy(LocalAddress, inet_ntoa(Address));
    }
    trace("Local address is '%s'\n", LocalAddress);
    ok(LocalAddress[0] != '\0',
       "Could not determine local address. Following test results may be wrong.\n");

    ZeroMemory(&Hints, sizeof(Hints));
    /* parameter tests for getaddrinfo */
    StartSeh() getaddrinfo(NULL, NULL, NULL, NULL); EndSeh(STATUS_ACCESS_VIOLATION);
    StartSeh() getaddrinfo("", "", &Hints, NULL);   EndSeh(STATUS_ACCESS_VIOLATION);
    StartSeh()
        AddrInfo = InvalidPointer;
        Error = getaddrinfo(NULL, NULL, NULL, &AddrInfo);
        ok_dec(Error, WSAHOST_NOT_FOUND);
        ok_dec(WSAGetLastError(), WSAHOST_NOT_FOUND);
        ok_ptr(AddrInfo, NULL);
    EndSeh(STATUS_SUCCESS);

    /* parameter tests for GetAddrInfoW */
    StartSeh() GetAddrInfoW(NULL, NULL, NULL, NULL);  EndSeh(STATUS_ACCESS_VIOLATION);
    StartSeh() GetAddrInfoW(L"", L"", &HintsW, NULL); EndSeh(STATUS_ACCESS_VIOLATION);
    StartSeh()
        AddrInfo = InvalidPointer;
        Error = GetAddrInfoW(NULL, NULL, NULL, &AddrInfoW);
        ok_dec(Error, WSAHOST_NOT_FOUND);
        ok_dec(WSAGetLastError(), WSAHOST_NOT_FOUND);
        ok_ptr(AddrInfo, InvalidPointer); /* differs from getaddrinfo */
    EndSeh(STATUS_SUCCESS);

    TestNodeName();
    TestServiceName();
    TestIpv6Literal();
    /* TODO: test passing both node name and service name */
    /* TODO: test hints */

    Error = WSACleanup();
    ok_dec(Error, 0);

    /* not initialized anymore */
    Error = getaddrinfo("127.0.0.1", "80", NULL, &AddrInfo);
    ok_dec(Error, WSANOTINITIALISED);

    Error = GetAddrInfoW(L"127.0.0.1", L"80", NULL, &AddrInfoW);
    ok_dec(Error, WSANOTINITIALISED);
}
