/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     SIO_ADDRESS_LIST_SORT (the destination ordering of RFC 6724 on a socket) and the order getaddrinfo
 *              gives for this machine: loopback destinations only, so the answer does not depend on the network
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

#ifndef SIO_ADDRESS_LIST_SORT
#define SIO_ADDRESS_LIST_SORT _WSAIORW(IOC_WS2, 25)
#endif

typedef struct
{
    ULONG Count;
    SOCKET_ADDRESS Address[8];
    UCHAR Data[8 * sizeof(SOCKADDR_IN6)];
    ULONG Used;
} LIST_BUILDER;

static void AddV4(LIST_BUILDER *B, UCHAR D)
{
    SOCKADDR_IN *Sa = (SOCKADDR_IN *)(B->Data + B->Used);

    memset(Sa, 0, sizeof(*Sa));
    Sa->sin_family = AF_INET;
    Sa->sin_addr.s_addr = htonl(0x7f000000 | D);
    B->Address[B->Count].iSockaddrLength = sizeof(*Sa);
    B->Address[B->Count].lpSockaddr = (LPSOCKADDR)Sa;
    B->Count++;
    B->Used += sizeof(*Sa);
}

static void AddLoopback6(LIST_BUILDER *B)
{
    SOCKADDR_IN6 *Sa = (SOCKADDR_IN6 *)(B->Data + B->Used);

    memset(Sa, 0, sizeof(*Sa));
    Sa->sin6_family = AF_INET6;
    Sa->sin6_addr.u.Byte[15] = 1;
    B->Address[B->Count].iSockaddrLength = sizeof(*Sa);
    B->Address[B->Count].lpSockaddr = (LPSOCKADDR)Sa;
    B->Count++;
    B->Used += sizeof(*Sa);
}

/* the layout the ioctl takes: the header, the SOCKET_ADDRESS array, then the addresses; pointers into the buffer */
static ULONG Serialize(const LIST_BUILDER *B, PVOID Buffer)
{
    SOCKET_ADDRESS_LIST *List = Buffer;
    PUCHAR Data = (PUCHAR)&List->Address[B->Count];
    ULONG i;

    List->iAddressCount = B->Count;
    for (i = 0; i < B->Count; i++)
    {
        memcpy(Data, B->Address[i].lpSockaddr, B->Address[i].iSockaddrLength);
        List->Address[i].lpSockaddr = (LPSOCKADDR)Data;
        List->Address[i].iSockaddrLength = B->Address[i].iSockaddrLength;
        Data += B->Address[i].iSockaddrLength;
    }
    return (ULONG)(Data - (PUCHAR)Buffer);
}

/* "4:2", "6", ...: family and last byte, for a short comparison */
static void Describe(const SOCKET_ADDRESS_LIST *List, char *Out, size_t Size)
{
    ULONG i;
    size_t Len = 0;

    Out[0] = 0;
    for (i = 0; i < (ULONG)List->iAddressCount && Len + 8 < Size; i++)
    {
        const SOCKADDR *Sa = List->Address[i].lpSockaddr;

        if (Sa->sa_family == AF_INET)
            Len += sprintf(Out + Len, "4:%u ", ((const SOCKADDR_IN *)Sa)->sin_addr.S_un.S_un_b.s_b4);
        else
            Len += sprintf(Out + Len, "6:%u ", ((const SOCKADDR_IN6 *)Sa)->sin6_addr.u.Byte[15]);
    }
}

static BOOL HaveIpv6(void)
{
    SOCKET S = socket(AF_INET6, SOCK_DGRAM, 0);

    if (S == INVALID_SOCKET)
        return FALSE;
    closesocket(S);
    return TRUE;
}

START_TEST(addrlistsort)
{
    WSADATA Data;
    SOCKET S;
    LIST_BUILDER B;
    UCHAR In[1024], Out[1024];
    DWORD Bytes, Needed;
    int Result, Error;
    ULONG Size, i;
    char Text[128];
    BOOL V6;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup\n");
    V6 = HaveIpv6();
    S = socket(AF_INET, SOCK_DGRAM, 0);
    ok(S != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());

    /* loopback destinations: ::1 (precedence 50) before 127.0.0.1 before 127.0.0.2 (not an address of the host);
       without IPv6 the ::1 cannot be reached and goes last */
    memset(&B, 0, sizeof(B));
    AddV4(&B, 2);
    AddV4(&B, 1);
    AddLoopback6(&B);
    Size = Serialize(&B, In);
    memset(Out, 0xcc, sizeof(Out));
    Bytes = 0;
    Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, Size, Out, sizeof(Out), &Bytes, NULL, NULL);
    Error = WSAGetLastError();
    ok(Result == 0, "SIO_ADDRESS_LIST_SORT failed, error %d\n", Error);
    ok(Bytes == Size, "returned %lu bytes, expected %lu\n", Bytes, Size);
    if (Result == 0)
    {
        SOCKET_ADDRESS_LIST *List = (SOCKET_ADDRESS_LIST *)Out;

        ok(List->iAddressCount == 3, "count %d\n", List->iAddressCount);
        Describe(List, Text, sizeof(Text));
        if (V6)
            ok(!strcmp(Text, "6:1 4:1 4:2 "), "order is %s\n", Text);
        else
            ok(!strcmp(Text, "4:1 4:2 6:1 "), "order without IPv6 is %s\n", Text);
        /* the answer points into its own buffer */
        for (i = 0; i < (ULONG)List->iAddressCount; i++)
            ok((PUCHAR)List->Address[i].lpSockaddr >= Out &&
               (PUCHAR)List->Address[i].lpSockaddr + List->Address[i].iSockaddrLength <= Out + Bytes,
               "address %lu is outside the output buffer\n", i);
    }

    /* the same list given the other way round: the same order for the reachable ones */
    memset(&B, 0, sizeof(B));
    AddLoopback6(&B);
    AddV4(&B, 1);
    AddV4(&B, 2);
    Size = Serialize(&B, In);
    Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, Size, Out, sizeof(Out), &Bytes, NULL, NULL);
    ok(Result == 0, "reversed: failed, error %d\n", WSAGetLastError());
    if (Result == 0)
    {
        Describe((SOCKET_ADDRESS_LIST *)Out, Text, sizeof(Text));
        ok(!strcmp(Text, V6 ? "6:1 4:1 4:2 " : "4:1 4:2 6:1 "), "reversed: order is %s\n", Text);
    }

    /* two addresses that rank the same stay in the order given */
    memset(&B, 0, sizeof(B));
    AddV4(&B, 3);
    AddV4(&B, 2);
    Size = Serialize(&B, In);
    Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, Size, Out, sizeof(Out), &Bytes, NULL, NULL);
    ok(Result == 0, "stable: failed, error %d\n", WSAGetLastError());
    if (Result == 0)
    {
        Describe((SOCKET_ADDRESS_LIST *)Out, Text, sizeof(Text));
        ok(!strcmp(Text, "4:3 4:2 "), "stable: order is %s\n", Text);
    }

    /* an output buffer that is too small: WSAEFAULT and the size that is needed */
    memset(&B, 0, sizeof(B));
    AddV4(&B, 2);
    AddV4(&B, 1);
    Size = Serialize(&B, In);
    Bytes = 0;
    Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, Size, Out, Size - 1, &Bytes, NULL, NULL);
    ok(Result == SOCKET_ERROR, "small buffer: result %d\n", Result);
    ok(WSAGetLastError() == WSAEFAULT, "small buffer: error %d\n", WSAGetLastError());
    ok(Bytes == Size, "small buffer: needed %lu, expected %lu\n", Bytes, Size);
    Needed = Bytes;
    Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, Size, Out, Needed, &Bytes, NULL, NULL);
    ok(Result == 0, "exact buffer: error %d\n", WSAGetLastError());

    /* input that is not a list inside the buffer */
    Bytes = 0;
    Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, 2, Out, sizeof(Out), &Bytes, NULL, NULL);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "short input: %d, error %d\n", Result, WSAGetLastError());
    {
        SOCKET_ADDRESS_LIST *List = (SOCKET_ADDRESS_LIST *)In;

        Serialize(&B, In);
        List->Address[0].lpSockaddr = (LPSOCKADDR)(Out + 4);    /* not in the input buffer */
        Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, Size, Out, sizeof(Out), &Bytes, NULL, NULL);
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "foreign pointer: %d, error %d\n", Result,
           WSAGetLastError());
        Serialize(&B, In);
        List->iAddressCount = 1000;
        Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, Size, Out, sizeof(Out), &Bytes, NULL, NULL);
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "huge count: %d, error %d\n", Result,
           WSAGetLastError());
    }

    /* malformed lists are rejected without touching the output: pointers past the end of the input, lengths that
       are negative, too short or longer than a SOCKADDR_STORAGE, a negative count, another family */
    {
        static const struct { const char *Name; int Kind; } Bad[] =
        {
            { "pointer just past the input", 0 }, { "pointer far past the input", 1 }, { "length -1", 2 },
            { "length 0x7fffffff", 3 }, { "length 129", 4 }, { "length 8", 5 }, { "count -1", 6 },
            { "count 0x80000000", 7 }, { "family AF_UNSPEC", 8 }, { "AF_INET6 entry of 16 bytes", 9 },
            { "count larger than the input", 10 },
        };
        SOCKET_ADDRESS_LIST *List = (SOCKET_ADDRESS_LIST *)In;

        memset(&B, 0, sizeof(B));
        AddV4(&B, 2);
        AddLoopback6(&B);
        for (i = 0; i < sizeof(Bad) / sizeof(Bad[0]); i++)
        {
            Size = Serialize(&B, In);
            switch (Bad[i].Kind)
            {
                case 0: List->Address[0].lpSockaddr = (LPSOCKADDR)(In + Size); break;
                case 1:
                    /* a well-formed address, but outside the input: only the bounds check can reject it */
                    memcpy(In + Size + 64, List->Address[1].lpSockaddr, sizeof(SOCKADDR_IN6));
                    List->Address[1].lpSockaddr = (LPSOCKADDR)(In + Size + 64);
                    break;
                case 2: List->Address[0].iSockaddrLength = -1; break;
                case 3: List->Address[1].iSockaddrLength = 0x7fffffff; break;
                case 4: List->Address[0].iSockaddrLength = 129; break;
                case 5: List->Address[0].iSockaddrLength = 8; break;
                case 6: List->iAddressCount = -1; break;
                case 7: List->iAddressCount = (INT)0x80000000; break;
                case 8: List->Address[0].lpSockaddr->sa_family = AF_UNSPEC; break;
                case 9: List->Address[1].iSockaddrLength = sizeof(SOCKADDR_IN); break;
                case 10: List->iAddressCount = 3; Size = FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address[2]); break;
            }
            memset(Out, 0xcc, sizeof(Out));
            Bytes = 0x5555;
            Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, Size, Out, sizeof(Out), &Bytes, NULL, NULL);
            Error = WSAGetLastError();
            ok(Result == SOCKET_ERROR && Error == WSAEINVAL, "%s: result %d error %d\n", Bad[i].Name, Result, Error);
            ok(Out[0] == 0xcc && Out[sizeof(Out) - 1] == 0xcc, "%s: the output buffer was written\n", Bad[i].Name);
        }
    }

    /* sorting in place (the output buffer is the input buffer), as the SDK's callers do */
    memset(&B, 0, sizeof(B));
    AddV4(&B, 2);
    AddV4(&B, 1);
    AddLoopback6(&B);
    Size = Serialize(&B, In);
    Bytes = 0;
    Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, Size, In, Size, &Bytes, NULL, NULL);
    ok(Result == 0, "in place: failed, error %d\n", WSAGetLastError());
    ok(Bytes == Size, "in place: returned %lu bytes, expected %lu\n", Bytes, Size);
    if (Result == 0)
    {
        SOCKET_ADDRESS_LIST *List = (SOCKET_ADDRESS_LIST *)In;

        ok(List->iAddressCount == 3, "in place: count %d\n", List->iAddressCount);
        Describe(List, Text, sizeof(Text));
        ok(!strcmp(Text, V6 ? "6:1 4:1 4:2 " : "4:1 4:2 6:1 "), "in place: order is %s\n", Text);
    }
    /* in place with the list given in sorted order already: nothing may be lost while it is rewritten */
    Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In, Size, In, Size, &Bytes, NULL, NULL);
    ok(Result == 0, "in place again: failed, error %d\n", WSAGetLastError());
    if (Result == 0)
    {
        Describe((SOCKET_ADDRESS_LIST *)In, Text, sizeof(Text));
        ok(!strcmp(Text, V6 ? "6:1 4:1 4:2 " : "4:1 4:2 6:1 "), "in place again: order is %s\n", Text);
    }
    /* the output overlapping the input at another offset */
    Size = Serialize(&B, In + 64);
    Result = WSAIoctl(S, SIO_ADDRESS_LIST_SORT, In + 64, Size, In, sizeof(In), &Bytes, NULL, NULL);
    ok(Result == 0, "overlapping: failed, error %d\n", WSAGetLastError());
    if (Result == 0)
    {
        Describe((SOCKET_ADDRESS_LIST *)In, Text, sizeof(Text));
        ok(!strcmp(Text, V6 ? "6:1 4:1 4:2 " : "4:1 4:2 6:1 "), "overlapping: order is %s\n", Text);
    }

    closesocket(S);

    /* getaddrinfo for this machine: ::1 first when there is IPv6 (the destination ordering must keep that) */
    {
        ADDRINFOA Hints, *Res = NULL, *R;

        memset(&Hints, 0, sizeof(Hints));
        Hints.ai_family = AF_UNSPEC;
        Hints.ai_socktype = SOCK_STREAM;
        Result = getaddrinfo("localhost", "80", &Hints, &Res);
        ok(Result == 0, "getaddrinfo(localhost) failed %d\n", Result);
        if (Result == 0)
        {
            ok(Res->ai_family == (V6 ? AF_INET6 : AF_INET), "localhost: first family %d\n", Res->ai_family);
            for (R = Res; R; R = R->ai_next)
                ok(R->ai_family == AF_INET || R->ai_family == AF_INET6, "family %d\n", R->ai_family);
            freeaddrinfo(Res);
        }
    }

    WSACleanup();
}
