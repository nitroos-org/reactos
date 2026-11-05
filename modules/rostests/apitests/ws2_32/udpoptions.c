/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     IP and UDP socket options of a datagram socket, and the WSASendMsg extension function
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results are those of Windows 10 22H2 (measured on the oracle VM): what was set is read back, an option
 * that was not set reads as its default, and WSASendMsg is handed out by SIO_GET_EXTENSION_FUNCTION_POINTER.
 * Rust's quinn-udp, which Firefox's HTTP/3 uses, sets these on every UDP socket and sends with WSASendMsg.
 */

#include "ws2_32.h"
#include <mswsock.h>

typedef INT (WINAPI *LPFN_WSASENDMSG)(SOCKET, LPWSAMSG, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

#define T_DONTFRAGMENT   14
#define T_PKTINFO        19
#define T_RECVTOS        40
#define T_ECN            50   /* IP_RECVECN and IP_ECN are the same option */
#define T_MTU_DISCOVER   71
#define T_UDP_SEND_MSG_SIZE 2
#define T_UDP_RECV_MAX_COALESCED_SIZE 3

static void CheckGet(SOCKET s, const char *What, int Level, int Name, int Expected)
{
    int Value = 0x55555555, Len = sizeof(Value), Result;

    Result = getsockopt(s, Level, Name, (char *)&Value, &Len);
    ok(Result == 0, "%s: getsockopt failed: %d\n", What, WSAGetLastError());
    if (Result == 0)
    {
        ok(Value == Expected, "%s: got %d (0x%x), expected %d\n", What, Value, Value, Expected);
        ok(Len == sizeof(Value), "%s: length %d\n", What, Len);
    }
}

static void CheckSet(SOCKET s, const char *What, int Level, int Name, int Value, int Len, int Error)
{
    int Result = setsockopt(s, Level, Name, (char *)&Value, Len);

    if (Error == 0)
        ok(Result == 0, "%s: setsockopt failed: %d\n", What, WSAGetLastError());
    else
    {
        ok(Result == SOCKET_ERROR, "%s: setsockopt succeeded, expected error %d\n", What, Error);
        if (Result == SOCKET_ERROR)
            ok(WSAGetLastError() == Error, "%s: error %d, expected %d\n", What, WSAGetLastError(), Error);
    }
}

static void TestDefaults(void)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int Value, Len, Result;

    ok(s != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (s == INVALID_SOCKET)
        return;

    CheckGet(s, "IP_TTL default", IPPROTO_IP, IP_TTL, 128);
    CheckGet(s, "IP_TOS default", IPPROTO_IP, IP_TOS, 0);
    CheckGet(s, "IP_DONTFRAGMENT default", IPPROTO_IP, T_DONTFRAGMENT, 0);
    CheckGet(s, "IP_PKTINFO default", IPPROTO_IP, T_PKTINFO, 0);
    CheckGet(s, "IP_RECVTOS default", IPPROTO_IP, T_RECVTOS, 0);
    CheckGet(s, "IP_RECVECN default", IPPROTO_IP, T_ECN, 0);
    CheckGet(s, "IP_MTU_DISCOVER default", IPPROTO_IP, T_MTU_DISCOVER, 0);
    CheckGet(s, "IP_MULTICAST_LOOP default", IPPROTO_IP, IP_MULTICAST_LOOP, 1);
    CheckGet(s, "IP_MULTICAST_TTL default", IPPROTO_IP, IP_MULTICAST_TTL, 1);
    CheckGet(s, "UDP_SEND_MSG_SIZE default", IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, 0);
    CheckGet(s, "UDP_RECV_MAX_COALESCED_SIZE default", IPPROTO_UDP, T_UDP_RECV_MAX_COALESCED_SIZE, 0);
    CheckGet(s, "SO_MAX_MSG_SIZE", SOL_SOCKET, SO_MAX_MSG_SIZE, 65507);

    /* An option that does not exist: IP says so, UDP calls the request invalid */
    Value = 0; Len = sizeof(Value);
    Result = getsockopt(s, IPPROTO_IP, 99, (char *)&Value, &Len);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAENOPROTOOPT, "IP option 99: %d, error %d\n", Result, WSAGetLastError());
    Len = sizeof(Value);
    Result = getsockopt(s, IPPROTO_UDP, 99, (char *)&Value, &Len);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "UDP option 99: %d, error %d\n", Result, WSAGetLastError());
    closesocket(s);
}

static void TestSetGet(void)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    BYTE Byte;
    int Len, Result, i;
    static const int Ttls[] = { 64, 0, 255 };

    ok(s != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (s == INVALID_SOCKET)
        return;

    /* IP_MTU_DISCOVER: 0 to 3; the last one set is read back */
    CheckSet(s, "MTU_DISCOVER 0", IPPROTO_IP, T_MTU_DISCOVER, 0, 4, 0);
    CheckSet(s, "MTU_DISCOVER 3", IPPROTO_IP, T_MTU_DISCOVER, 3, 4, 0);
    CheckSet(s, "MTU_DISCOVER 4", IPPROTO_IP, T_MTU_DISCOVER, 4, 4, WSAEINVAL);
    CheckSet(s, "MTU_DISCOVER -1", IPPROTO_IP, T_MTU_DISCOVER, -1, 4, WSAEINVAL);
    CheckGet(s, "MTU_DISCOVER read back", IPPROTO_IP, T_MTU_DISCOVER, 3);

    for (i = 0; i < 3; i++)
    {
        CheckSet(s, "IP_TTL", IPPROTO_IP, IP_TTL, Ttls[i], 4, 0);
        CheckGet(s, "IP_TTL read back", IPPROTO_IP, IP_TTL, Ttls[i]);
    }
    CheckSet(s, "IP_TTL 256", IPPROTO_IP, IP_TTL, 256, 4, WSAEINVAL);
    CheckGet(s, "IP_TTL after 256", IPPROTO_IP, IP_TTL, 255);

    /* A one byte value is accepted, and a buffer of fewer than 4 bytes gets one byte */
    CheckSet(s, "IP_TTL one byte", IPPROTO_IP, IP_TTL, 33, 1, 0);
    CheckGet(s, "IP_TTL after one byte", IPPROTO_IP, IP_TTL, 33);
    Byte = 0xcc; Len = sizeof(Byte);
    Result = getsockopt(s, IPPROTO_IP, IP_TTL, (char *)&Byte, &Len);
    ok(Result == 0 && Byte == 33 && Len == 1, "IP_TTL into one byte: %d, value %u, length %d\n", Result, Byte, Len);

    CheckSet(s, "IP_TOS", IPPROTO_IP, IP_TOS, 0x10, 4, 0);
    CheckGet(s, "IP_TOS read back", IPPROTO_IP, IP_TOS, 0x10);
    CheckSet(s, "IP_TOS 256", IPPROTO_IP, IP_TOS, 256, 4, WSAEINVAL);
    CheckGet(s, "IP_TOS after 256", IPPROTO_IP, IP_TOS, 0x10);

    /* The receive switches read back as 0 or 1; IP_RECVECN and IP_ECN are one option */
    CheckSet(s, "IP_RECVTOS", IPPROTO_IP, T_RECVTOS, 5, 4, 0);
    CheckGet(s, "IP_RECVTOS read back", IPPROTO_IP, T_RECVTOS, 1);
    CheckSet(s, "IP_RECVECN", IPPROTO_IP, T_ECN, 1, 4, 0);
    CheckGet(s, "IP_RECVECN read back", IPPROTO_IP, T_ECN, 1);
    CheckSet(s, "IP_ECN 0", IPPROTO_IP, T_ECN, 0, 4, 0);
    CheckGet(s, "IP_ECN 0 read back", IPPROTO_IP, T_ECN, 0);
    CheckSet(s, "IP_MULTICAST_LOOP 0", IPPROTO_IP, IP_MULTICAST_LOOP, 0, 4, 0);
    CheckGet(s, "IP_MULTICAST_LOOP read back", IPPROTO_IP, IP_MULTICAST_LOOP, 0);
    CheckSet(s, "IP_MULTICAST_TTL", IPPROTO_IP, IP_MULTICAST_TTL, 9, 4, 0);
    CheckGet(s, "IP_MULTICAST_TTL read back", IPPROTO_IP, IP_MULTICAST_TTL, 9);

    /* The UDP sizes are kept as they are, whatever the value, and need a full DWORD */
    CheckSet(s, "UDP_SEND_MSG_SIZE", IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, 1200, 4, 0);
    CheckGet(s, "UDP_SEND_MSG_SIZE read back", IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, 1200);
    CheckSet(s, "UDP_SEND_MSG_SIZE -1", IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, -1, 4, 0);
    CheckGet(s, "UDP_SEND_MSG_SIZE -1 read back", IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, -1);
    CheckSet(s, "UDP_SEND_MSG_SIZE one byte", IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, 5, 1, WSAEFAULT);
    CheckSet(s, "UDP_RECV_MAX_COALESCED_SIZE", IPPROTO_UDP, T_UDP_RECV_MAX_COALESCED_SIZE, 65535, 4, 0);
    CheckGet(s, "UDP_RECV_MAX_COALESCED_SIZE read back", IPPROTO_UDP, T_UDP_RECV_MAX_COALESCED_SIZE, 65535);
    CheckSet(s, "UDP_RECV_MAX_COALESCED_SIZE 100000", IPPROTO_UDP, T_UDP_RECV_MAX_COALESCED_SIZE, 100000, 4, 0);
    CheckGet(s, "UDP_RECV_MAX_COALESCED_SIZE 100000 read back", IPPROTO_UDP, T_UDP_RECV_MAX_COALESCED_SIZE, 100000);
    closesocket(s);

    /* IP_DONTFRAGMENT and IP_MTU_DISCOVER exclude each other: with one set the other is invalid */
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CheckSet(s, "IP_DONTFRAGMENT", IPPROTO_IP, T_DONTFRAGMENT, 1, 4, 0);
    CheckGet(s, "IP_DONTFRAGMENT read back", IPPROTO_IP, T_DONTFRAGMENT, 1);
    CheckSet(s, "MTU_DISCOVER after DF", IPPROTO_IP, T_MTU_DISCOVER, 2, 4, WSAEINVAL);
    CheckSet(s, "MTU_DISCOVER 3 after DF", IPPROTO_IP, T_MTU_DISCOVER, 3, 4, WSAEINVAL);
    CheckGet(s, "MTU_DISCOVER after DF", IPPROTO_IP, T_MTU_DISCOVER, 0);
    closesocket(s);
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CheckSet(s, "MTU_DISCOVER 3", IPPROTO_IP, T_MTU_DISCOVER, 3, 4, 0);
    CheckSet(s, "IP_DONTFRAGMENT after MTU_DISCOVER", IPPROTO_IP, T_DONTFRAGMENT, 1, 4, WSAEINVAL);
    closesocket(s);
}

static void TestStream(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int Value, Len, Result;

    ok(s != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (s == INVALID_SOCKET)
        return;

    CheckGet(s, "TCP IP_TTL default", IPPROTO_IP, IP_TTL, 128);
    CheckGet(s, "TCP IP_TOS default", IPPROTO_IP, IP_TOS, 0);
    CheckGet(s, "TCP SO_MAX_MSG_SIZE", SOL_SOCKET, SO_MAX_MSG_SIZE, -1);

    /* The datagram only options are invalid on a stream */
    CheckSet(s, "TCP UDP_SEND_MSG_SIZE", IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, 1200, 4, WSAEINVAL);
    CheckSet(s, "TCP IP_RECVTOS", IPPROTO_IP, T_RECVTOS, 1, 4, WSAEINVAL);
    Len = sizeof(Value);
    Result = getsockopt(s, IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, (char *)&Value, &Len);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "TCP get UDP_SEND_MSG_SIZE: %d, error %d\n", Result, WSAGetLastError());
    Len = sizeof(Value);
    Result = getsockopt(s, IPPROTO_IP, T_RECVTOS, (char *)&Value, &Len);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "TCP get IP_RECVTOS: %d, error %d\n", Result, WSAGetLastError());
    closesocket(s);
}

static LPFN_WSASENDMSG GetSendMsg(SOCKET s)
{
    GUID Guid = {0xa441e712,0x754f,0x43ca,{0x84,0xa7,0x0d,0xee,0x44,0xcf,0x60,0x6d}};
    LPFN_WSASENDMSG Fn = NULL;
    DWORD Bytes = 0;
    int Result = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &Guid, sizeof(Guid), &Fn, sizeof(Fn), &Bytes, NULL, NULL);

    ok(Result == 0, "WSAIoctl(WSAID_WSASENDMSG) failed: %d\n", WSAGetLastError());
    ok(Bytes == sizeof(Fn), "WSAID_WSASENDMSG returned %lu bytes\n", Bytes);
    ok(Fn != NULL, "WSAID_WSASENDMSG gave no function\n");

    /* A buffer that is too small */
    Bytes = 0;
    Result = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &Guid, sizeof(Guid), &Fn, 2, &Bytes, NULL, NULL);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "WSAID_WSASENDMSG into 2 bytes: %d, error %d\n", Result, WSAGetLastError());
    return Fn;
}

static LPFN_WSARECVMSG GetRecvMsg(SOCKET s)
{
    GUID Guid = WSAID_WSARECVMSG;
    LPFN_WSARECVMSG Fn = NULL;
    DWORD Bytes = 0;
    int Result = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &Guid, sizeof(Guid), &Fn, sizeof(Fn), &Bytes, NULL, NULL);

    ok(Result == 0 && Fn, "WSAIoctl(WSAID_WSARECVMSG) failed: %d\n", WSAGetLastError());
    return Fn;
}

static int Send(LPFN_WSASENDMSG SendMsg, SOCKET s, struct sockaddr_in *To, int Length, int Level, int Type, int Value, DWORD *Sent)
{
    static char Payload[2000];
    char Control[64];
    WSAMSG Msg;
    WSABUF Buffer;
    WSACMSGHDR *Header = (WSACMSGHDR *)Control;

    memset(Payload, 'q', sizeof(Payload));
    memset(&Msg, 0, sizeof(Msg));
    memset(Control, 0, sizeof(Control));
    Buffer.buf = Payload; Buffer.len = Length;
    Msg.name = (LPSOCKADDR)To; Msg.namelen = sizeof(*To);
    Msg.lpBuffers = &Buffer; Msg.dwBufferCount = 1;
    if (Level >= 0)
    {
        Header->cmsg_len = WSA_CMSG_LEN(sizeof(int));
        Header->cmsg_level = Level;
        Header->cmsg_type = Type;
        *(int *)WSA_CMSG_DATA(Header) = Value;
        Msg.Control.buf = Control;
        Msg.Control.len = WSA_CMSG_SPACE(sizeof(int));
    }
    *Sent = 0;
    return SendMsg(s, &Msg, 0, Sent, NULL, NULL);
}

static int Receive(SOCKET s, int *Length)
{
    char Buffer[2000];
    fd_set Set;
    struct timeval Timeout = { 2, 0 };

    FD_ZERO(&Set);
    FD_SET(s, &Set);
    if (select(0, &Set, NULL, NULL, &Timeout) != 1)
        return 0;
    *Length = recv(s, Buffer, sizeof(Buffer), 0);
    return *Length >= 0;
}

static void TestSendMsg(void)
{
    SOCKET Tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), Rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in Addr, To;
    int Len = sizeof(To), Result, Got;
    DWORD Sent;
    LPFN_WSASENDMSG SendMsg;
    LPFN_WSARECVMSG RecvMsg;
    SOCKET Other;

    ok(Tx != INVALID_SOCKET && Rx != INVALID_SOCKET, "socket failed\n");
    if (Tx == INVALID_SOCKET || Rx == INVALID_SOCKET)
        return;

    SendMsg = GetSendMsg(Tx);
    RecvMsg = GetRecvMsg(Rx);
    Other = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (SendMsg)
    {
        /* The function is the same for every socket */
        LPFN_WSASENDMSG Again = GetSendMsg(Other);
        ok(Again == SendMsg, "another socket got %p, not %p\n", Again, SendMsg);
    }
    closesocket(Other);
    if (!SendMsg || !RecvMsg)
        return;

    memset(&Addr, 0, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(Rx, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "bind failed\n");
    ok(bind(Tx, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "bind failed\n");
    getsockname(Rx, (struct sockaddr *)&To, &Len);

    /* A plain message */
    Result = Send(SendMsg, Tx, &To, 100, -1, 0, 0, &Sent);
    ok(Result == 0 && Sent == 100, "plain: %d, sent %lu, error %d\n", Result, Sent, WSAGetLastError());
    ok(Receive(Rx, &Got) && Got == 100, "plain: received %d\n", Got);

    /* The ECN codepoint: 0 to 3 are accepted, others are invalid */
    Result = Send(SendMsg, Tx, &To, 100, IPPROTO_IP, T_ECN, 2, &Sent);
    ok(Result == 0 && Sent == 100, "IP_ECN 2: %d, sent %lu, error %d\n", Result, Sent, WSAGetLastError());
    ok(Receive(Rx, &Got) && Got == 100, "IP_ECN 2: received %d\n", Got);
    Result = Send(SendMsg, Tx, &To, 100, IPPROTO_IP, T_ECN, 5, &Sent);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "IP_ECN 5: %d, error %d\n", Result, WSAGetLastError());

    /* A segment size splits the message into datagrams of that size, the last one smaller */
    Result = Send(SendMsg, Tx, &To, 1200, IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, 600, &Sent);
    ok(Result == 0 && Sent == 1200, "segments of 600: %d, sent %lu, error %d\n", Result, Sent, WSAGetLastError());
    ok(Receive(Rx, &Got) && Got == 600, "first segment: %d\n", Got);
    ok(Receive(Rx, &Got) && Got == 600, "second segment: %d\n", Got);
    Result = Send(SendMsg, Tx, &To, 1000, IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, 400, &Sent);
    ok(Result == 0 && Sent == 1000, "segments of 400: %d, sent %lu\n", Result, Sent);
    ok(Receive(Rx, &Got) && Got == 400, "400 segment 1: %d\n", Got);
    ok(Receive(Rx, &Got) && Got == 400, "400 segment 2: %d\n", Got);
    ok(Receive(Rx, &Got) && Got == 200, "400 last segment: %d\n", Got);
    Result = Send(SendMsg, Tx, &To, 100, IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, 600, &Sent);
    ok(Result == 0 && Sent == 100, "segment larger than the message: %d, sent %lu\n", Result, Sent);
    ok(Receive(Rx, &Got) && Got == 100, "unsplit: %d\n", Got);
    Result = Send(SendMsg, Tx, &To, 100, IPPROTO_UDP, T_UDP_SEND_MSG_SIZE, 0, &Sent);
    ok(Result == 0 && Sent == 100, "segment size 0: %d, sent %lu\n", Result, Sent);
    ok(Receive(Rx, &Got) && Got == 100, "segment size 0: received %d\n", Got);

    /* WSARecvMsg with IP_PKTINFO: the datagram's destination address and interface */
    {
        int On = 1;
        char Data[200], Control[128];
        WSAMSG Msg;
        WSABUF Buffer;
        DWORD Bytes = 0;
        WSACMSGHDR *Header;
        BOOL Found = FALSE;
        struct sockaddr_in From;

        ok(setsockopt(Rx, IPPROTO_IP, T_PKTINFO, (char *)&On, sizeof(On)) == 0, "IP_PKTINFO failed\n");
        Result = Send(SendMsg, Tx, &To, 50, -1, 0, 0, &Sent);
        ok(Result == 0 && Sent == 50, "pktinfo send: %d\n", Result);

        memset(&Msg, 0, sizeof(Msg));
        Buffer.buf = Data; Buffer.len = sizeof(Data);
        Msg.name = (LPSOCKADDR)&From; Msg.namelen = sizeof(From);
        Msg.lpBuffers = &Buffer; Msg.dwBufferCount = 1;
        Msg.Control.buf = Control; Msg.Control.len = sizeof(Control);
        Result = RecvMsg(Rx, &Msg, &Bytes, NULL, NULL);
        ok(Result == 0 && Bytes == 50, "WSARecvMsg: %d, %lu bytes, error %d\n", Result, Bytes, WSAGetLastError());
        for (Header = WSA_CMSG_FIRSTHDR(&Msg); Header; Header = WSA_CMSG_NXTHDR(&Msg, Header))
        {
            if (Header->cmsg_level == IPPROTO_IP && Header->cmsg_type == T_PKTINFO)
            {
                IN_PKTINFO *Info = (IN_PKTINFO *)WSA_CMSG_DATA(Header);

                Found = TRUE;
                ok(Info->ipi_addr.s_addr == htonl(INADDR_LOOPBACK), "pktinfo address %08lx\n", (unsigned long)Info->ipi_addr.s_addr);
                ok(Info->ipi_ifindex != 0, "pktinfo interface 0\n");
            }
        }
        ok(Found, "no IP_PKTINFO message received\n");
        ok(From.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "sender address %08lx\n", (unsigned long)From.sin_addr.s_addr);
    }
    closesocket(Tx);
    closesocket(Rx);
}

START_TEST(udpoptions)
{
    WSADATA wsaData;

    ok(WSAStartup(MAKEWORD(2, 2), &wsaData) == 0, "WSAStartup failed\n");
    TestDefaults();
    TestSetGet();
    TestStream();
    TestSendMsg();
    WSACleanup();
}
