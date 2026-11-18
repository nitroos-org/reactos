/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     The options a socket from accept() or AcceptEx takes from its listener, and the SO_KEEPALIVE and SO_DONTROUTE answers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every expected value is what Windows Server 2022 (20348, x64 and x86) answered when this file was built with -DWINREF_PROBE and
 * run there (loopback only, nothing else touched):
 *  - accept() gives the new socket the listener's TCP_NODELAY, SO_KEEPALIVE, SO_DONTROUTE, SO_OOBINLINE, SO_LINGER, SO_RCVBUF,
 *    SO_SNDBUF, SO_REUSEADDR, SO_DEBUG, SO_RCVTIMEO and SO_SNDTIMEO, whether they were set before or after listen(), but not
 *    SO_EXCLUSIVEADDRUSE;
 *  - the socket AcceptEx fills shows TCP_NODELAY, SO_KEEPALIVE and SO_DONTROUTE of the listener as soon as the call is made, and
 *    the others only after SO_UPDATE_ACCEPT_CONTEXT;
 *  - SO_KEEPALIVE (stream sockets only, WSAENOPROTOOPT otherwise) and SO_DONTROUTE are one byte values: getsockopt answers one byte
 *    for any buffer of one byte or more and WSAEFAULT for an empty one, setsockopt reads the first byte and fails an empty buffer.
 */

#if defined(WINREF_PROBE)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <stdio.h>
#include <string.h>
static int g_Failures;
#define ok(cond, ...) do { if (!(cond)) { g_Failures++; printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); } } while (0)
#define START_TEST(x) void func_##x(void)
#else
#include "ws2_32.h"
#include <mswsock.h>
#endif

#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR))
#endif

typedef struct
{
    const char *Name;
    int Level, Option;
    BYTE Value[8];      /* what the listener sets */
    int Length;
    int Bytes;          /* the bytes getsockopt answers on Windows with a buffer of 8 */
    int InheritedByAcceptEx;   /* visible before SO_UPDATE_ACCEPT_CONTEXT */
} OPTION;

static const OPTION Options[] =
{
    { "TCP_NODELAY",  IPPROTO_TCP, TCP_NODELAY,   { 1, 0, 0, 0 },       4, 1, 1 },
    { "SO_KEEPALIVE", SOL_SOCKET,  SO_KEEPALIVE,  { 1, 0, 0, 0 },       4, 1, 1 },
    { "SO_DONTROUTE", SOL_SOCKET,  SO_DONTROUTE,  { 1, 0, 0, 0 },       4, 1, 1 },
    { "SO_OOBINLINE", SOL_SOCKET,  SO_OOBINLINE,  { 1, 0, 0, 0 },       4, 4, 0 },
    { "SO_LINGER",    SOL_SOCKET,  SO_LINGER,     { 1, 0, 7, 0 },       4, 4, 0 },
    { "SO_RCVBUF",    SOL_SOCKET,  SO_RCVBUF,     { 0x00, 0x30, 0, 0 }, 4, 4, 0 },
    { "SO_SNDBUF",    SOL_SOCKET,  SO_SNDBUF,     { 0x00, 0x28, 0, 0 }, 4, 4, 0 },
    { "SO_REUSEADDR", SOL_SOCKET,  SO_REUSEADDR,  { 1, 0, 0, 0 },       4, 4, 0 },
    { "SO_DEBUG",     SOL_SOCKET,  SO_DEBUG,      { 1, 0, 0, 0 },       4, 4, 0 },
    { "SO_RCVTIMEO",  SOL_SOCKET,  SO_RCVTIMEO,   { 0xd2, 0x04, 0, 0 }, 4, 4, 0 },
    { "SO_SNDTIMEO",  SOL_SOCKET,  SO_SNDTIMEO,   { 0xe1, 0x10, 0, 0 }, 4, 4, 0 },
};

static int Read(SOCKET s, const OPTION *o, BYTE *Out)
{
    int Len = 8, Result;

    memset(Out, 0, 8);
    Result = getsockopt(s, o->Level, o->Option, (char *)Out, &Len);
    if (Result) return -1;
    return Len;
}

static SOCKET MakeListener(const OPTION *o, BOOL SetBeforeListen, struct sockaddr_in *Addr)
{
    SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int Len = sizeof(*Addr), Result;

    ok(l != INVALID_SOCKET, "socket failed\n");
    if (SetBeforeListen)
    {
        Result = setsockopt(l, o->Level, o->Option, (char *)o->Value, o->Length);
        ok(Result == 0, "%s: setsockopt before listen: %d\n", o->Name, WSAGetLastError());
    }
    memset(Addr, 0, sizeof(*Addr));
    Addr->sin_family = AF_INET;
    Addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(l, (struct sockaddr *)Addr, sizeof(*Addr)) == 0, "bind failed\n");
    ok(getsockname(l, (struct sockaddr *)Addr, &Len) == 0, "getsockname failed\n");
    ok(listen(l, 4) == 0, "listen failed\n");
    if (!SetBeforeListen)
    {
        Result = setsockopt(l, o->Level, o->Option, (char *)o->Value, o->Length);
        ok(Result == 0, "%s: setsockopt after listen: %d\n", o->Name, WSAGetLastError());
    }
    return l;
}

static void CheckEqual(SOCKET s, const OPTION *o, const BYTE *Want, int WantLen, const char *What)
{
    BYTE Got[8];
    int Len = Read(s, o, Got);

    ok(Len == WantLen, "%s, %s: length %d, expected %d\n", o->Name, What, Len, WantLen);
    if (Len == WantLen && Len > 0)
        ok(!memcmp(Got, Want, Len), "%s, %s: %02x %02x %02x %02x, expected %02x %02x %02x %02x\n", o->Name, What,
           Got[0], Got[1], Got[2], Got[3], Want[0], Want[1], Want[2], Want[3]);
}

static void TestAccept(const OPTION *o, BOOL SetBeforeListen)
{
    struct sockaddr_in Addr;
    SOCKET l, c, a, Fresh;
    BYTE Fresh_[8], Want[8];
    int FreshLen;
    char What[40];

    Fresh = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    FreshLen = Read(Fresh, o, Fresh_);
    ok(FreshLen == o->Bytes, "%s: fresh socket length %d\n", o->Name, FreshLen);
    closesocket(Fresh);

    memset(Want, 0, sizeof(Want));
    memcpy(Want, o->Value, o->Bytes);
    if (o->Option == SO_LINGER) { Want[0] = 1; Want[1] = 0; Want[2] = 7; Want[3] = 0; }

    l = MakeListener(o, SetBeforeListen, &Addr);
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(connect(c, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "connect failed\n");
    a = accept(l, NULL, NULL);
    ok(a != INVALID_SOCKET, "accept failed\n");
    sprintf(What, "accept(), set %s listen", SetBeforeListen ? "before" : "after");
    CheckEqual(a, o, Want, o->Bytes, What);
    CheckEqual(c, o, Fresh_, FreshLen, "the connecting client");
    closesocket(a);
    closesocket(c);
    closesocket(l);
}

static void TestAcceptEx(const OPTION *o, LPFN_ACCEPTEX pAcceptEx)
{
    struct sockaddr_in Addr;
    SOCKET l, c, a, Fresh;
    BYTE FreshValue[8], Want[8], Buffer[2 * (sizeof(struct sockaddr_in) + 16)];
    int FreshLen, Result;
    DWORD Got = 0;
    OVERLAPPED Ov;

    Fresh = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    FreshLen = Read(Fresh, o, FreshValue);
    closesocket(Fresh);
    memset(Want, 0, sizeof(Want));
    memcpy(Want, o->Value, o->Bytes);
    if (o->Option == SO_LINGER) { Want[0] = 1; Want[1] = 0; Want[2] = 7; Want[3] = 0; }

    l = MakeListener(o, TRUE, &Addr);
    a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&Ov, 0, sizeof(Ov));
    Ov.hEvent = WSACreateEvent();
    Result = pAcceptEx(l, a, Buffer, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, &Got, &Ov);
    ok(Result || WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx: %d\n", WSAGetLastError());
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(connect(c, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "connect failed\n");
    ok(WaitForSingleObject(Ov.hEvent, 10000) == WAIT_OBJECT_0, "AcceptEx did not complete\n");

    if (o->InheritedByAcceptEx) CheckEqual(a, o, Want, o->Bytes, "AcceptEx, before the update");
    else CheckEqual(a, o, FreshValue, FreshLen, "AcceptEx, before the update");
    Result = setsockopt(a, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&l, sizeof(l));
    ok(Result == 0, "%s: SO_UPDATE_ACCEPT_CONTEXT: %d\n", o->Name, WSAGetLastError());
    CheckEqual(a, o, Want, o->Bytes, "AcceptEx, after the update");
    WSACloseEvent(Ov.hEvent);
    closesocket(c);
    closesocket(a);
    closesocket(l);
}

static void TestExclusive(void)
{
    struct sockaddr_in Addr;
    SOCKET l, c, a;
    int One = 1, Value = 5, Len = sizeof(Value);

    l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(setsockopt(l, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&One, sizeof(One)) == 0, "SO_EXCLUSIVEADDRUSE: %d\n", WSAGetLastError());
    memset(&Addr, 0, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(l, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "bind failed\n");
    Len = sizeof(Addr);
    getsockname(l, (struct sockaddr *)&Addr, &Len);
    ok(listen(l, 1) == 0, "listen failed\n");
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(connect(c, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "connect failed\n");
    a = accept(l, NULL, NULL);
    Len = sizeof(Value);
    ok(getsockopt(l, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&Value, &Len) == 0 && Value == 1, "listener SO_EXCLUSIVEADDRUSE %d\n", Value);
    Value = 5; Len = sizeof(Value);
    ok(getsockopt(a, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&Value, &Len) == 0 && Value == 0, "accepted SO_EXCLUSIVEADDRUSE %d (not inherited)\n", Value);
    closesocket(a);
    closesocket(c);
    closesocket(l);
}

static void TestOneByte(int Type, int Option, const char *Name)
{
    SOCKET s = socket(AF_INET, Type, 0), t;
    BYTE Out[8], In[4];
    int Len, Result, Lens[] = { 1, 2, 3, 4, 8 }, i;
    BOOL Exists = (Option == SO_DONTROUTE || Type == SOCK_STREAM);

    /* an empty buffer is WSAEFAULT whether the option exists or not */
    Len = 0;
    Result = getsockopt(s, SOL_SOCKET, Option, (char *)Out, &Len);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "%s type %d, get with no buffer: %d, error %d\n", Name, Type, Result, WSAGetLastError());

    for (i = 0; i < 5; i++)
    {
        memset(Out, 0xcc, sizeof(Out));
        Len = Lens[i];
        Result = getsockopt(s, SOL_SOCKET, Option, (char *)Out, &Len);
        if (Exists)
        {
            ok(Result == 0 && Len == 1 && Out[0] == 0 && Out[1] == 0xcc, "%s get(%d): %d len %d byte %02x %02x\n", Name, Lens[i], Result, Len, Out[0], Out[1]);
        }
        else
            ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAENOPROTOOPT, "%s on a datagram socket, get(%d): %d, error %d\n", Name, Lens[i], Result, WSAGetLastError());
    }

    memset(In, 0, sizeof(In));
    In[0] = 1;
    Result = setsockopt(s, SOL_SOCKET, Option, (char *)In, 4);
    if (!Exists)
    {
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAENOPROTOOPT, "%s on a datagram socket, set: %d, error %d\n", Name, Result, WSAGetLastError());
        closesocket(s);
        return;
    }
    ok(Result == 0, "%s set: %d\n", Name, WSAGetLastError());
    Len = 4;
    Result = getsockopt(s, SOL_SOCKET, Option, (char *)Out, &Len);
    ok(Result == 0 && Len == 1 && Out[0] == 1, "%s after set: %d len %d byte %02x\n", Name, Result, Len, Out[0]);

    /* only the first byte counts, an empty buffer fails */
    for (i = 0; i < 4; i++)
    {
        t = socket(AF_INET, Type, 0);
        memset(In, 0, sizeof(In));
        In[1] = 1;
        Result = setsockopt(t, SOL_SOCKET, Option, (char *)In, i < 2 ? 1 + i : 4);
        ok(Result == 0, "%s set {0,1}: %d\n", Name, WSAGetLastError());
        Len = 4;
        getsockopt(t, SOL_SOCKET, Option, (char *)Out, &Len);
        ok(Out[0] == 0, "%s set {0,1} reads back %02x\n", Name, Out[0]);
        closesocket(t);
    }
    Result = setsockopt(s, SOL_SOCKET, Option, (char *)In, 0);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "%s set with no buffer: %d, error %d\n", Name, Result, WSAGetLastError());
    closesocket(s);
}

START_TEST(sockinherit)
{
    WSADATA Data;
    SOCKET Probe;
    LPFN_ACCEPTEX pAcceptEx = NULL;
    GUID Guid = WSAID_ACCEPTEX;
    DWORD Bytes;
    ULONG i;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");

    Probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(WSAIoctl(Probe, SIO_GET_EXTENSION_FUNCTION_POINTER, &Guid, sizeof(Guid), &pAcceptEx, sizeof(pAcceptEx), &Bytes, NULL, NULL) == 0,
       "no AcceptEx\n");
    closesocket(Probe);

    for (i = 0; i < sizeof(Options) / sizeof(Options[0]); i++)
    {
        TestAccept(&Options[i], TRUE);
        TestAccept(&Options[i], FALSE);
        if (pAcceptEx) TestAcceptEx(&Options[i], pAcceptEx);
    }
    TestExclusive();
    TestOneByte(SOCK_STREAM, SO_KEEPALIVE, "SO_KEEPALIVE");
    TestOneByte(SOCK_STREAM, SO_DONTROUTE, "SO_DONTROUTE");
    TestOneByte(SOCK_DGRAM, SO_KEEPALIVE, "SO_KEEPALIVE");
    TestOneByte(SOCK_DGRAM, SO_DONTROUTE, "SO_DONTROUTE");

    WSACleanup();
}

#ifdef WINREF_PROBE
int main(void)
{
    func_sockinherit();
    printf("done, %d check failures\n", g_Failures);
    return 0;
}
#endif
