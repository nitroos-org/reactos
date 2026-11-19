/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for WSAPoll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *              Ported from Wine's dlls/ws2_32/tests/sock.c (test_WSAPoll and its helpers),
 *              Copyright 2002 Martin Wilck, 2005 Chris Morgan, 2020 Zebediah Figura for CodeWeavers,
 *              and other Wine contributors
 */

#include "ws2_32.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef POLLRDNORM
#define POLLRDNORM  0x0100
#define POLLRDBAND  0x0200
#define POLLIN      (POLLRDNORM | POLLRDBAND)
#define POLLPRI     0x0400
#define POLLWRNORM  0x0010
#define POLLOUT     (POLLWRNORM)
#define POLLWRBAND  0x0020
#define POLLERR     0x0001
#define POLLHUP     0x0002
#define POLLNVAL    0x0004
typedef struct pollfd
{
    SOCKET fd;
    SHORT events;
    SHORT revents;
} WSAPOLLFD, *PWSAPOLLFD, *LPWSAPOLLFD;
#endif

static int (WINAPI *pWSAPoll)(WSAPOLLFD *, ULONG, INT);
static unsigned int apc_count;

static void tcp_socketpair_flags(SOCKET *src, SOCKET *dst, DWORD flags)
{
    SOCKET server = INVALID_SOCKET;
    struct sockaddr_in addr;
    int len, ret;

    *src = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags);
    ok(*src != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    server = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags);
    ok(server != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ret = bind(server, (struct sockaddr *)&addr, sizeof(addr));
    ok(!ret, "failed to bind socket, error %u\n", WSAGetLastError());

    len = sizeof(addr);
    ret = getsockname(server, (struct sockaddr *)&addr, &len);
    ok(!ret, "failed to get address, error %u\n", WSAGetLastError());

    ret = listen(server, 1);
    ok(!ret, "failed to listen, error %u\n", WSAGetLastError());

    ret = connect(*src, (struct sockaddr *)&addr, sizeof(addr));
    ok(!ret, "failed to connect, error %u\n", WSAGetLastError());

    len = sizeof(addr);
    *dst = accept(server, (struct sockaddr *)&addr, &len);
    ok(*dst != INVALID_SOCKET, "failed to accept socket, error %u\n", WSAGetLastError());

    closesocket(server);
}

static void tcp_socketpair(SOCKET *src, SOCKET *dst)
{
    tcp_socketpair_flags(src, dst, WSA_FLAG_OVERLAPPED);
}

static void WINAPI apc_func(ULONG_PTR param)
{
    ++*(unsigned int *)param;
}

#define check_poll(a, b) check_poll_(__LINE__, a, POLLRDNORM | POLLRDBAND | POLLWRNORM, b, FALSE)
#define check_poll_todo(a, b) check_poll_(__LINE__, a, POLLRDNORM | POLLRDBAND | POLLWRNORM, b, TRUE)
#define check_poll_mask(a, b, c) check_poll_(__LINE__, a, b, c, FALSE)
#define check_poll_mask_todo(a, b, c) check_poll_(__LINE__, a, b, c, TRUE)
static void check_poll_(int line, SOCKET s, short mask, short expect, BOOL todo)
{
    WSAPOLLFD pollfd;
    int ret, tries;

    /* Data and state changes of the peer arrive a little after the call that caused them */
    for (tries = 0; tries < 20; tries++)
    {
        pollfd.fd = s;
        pollfd.events = mask;
        pollfd.revents = 0xdead;
        ret = pWSAPoll(&pollfd, 1, 1000);
        if (pollfd.revents == expect)
            break;
        Sleep(25);
    }
    ok_(__FILE__, line)(ret == (pollfd.revents ? 1 : 0), "WSAPoll() returned %d\n", ret);
    todo_ros_if(todo) ok_(__FILE__, line)(pollfd.revents == expect, "got wrong events %#x\n", pollfd.revents);
}

static int set_blocking ( SOCKET s, BOOL blocking )
{
    u_long val = !blocking;
    return ioctlsocket ( s, FIONBIO, &val );
}

static DWORD WINAPI SelectCloseThread(void *param)
{
    SOCKET s = *(SOCKET*)param;
    Sleep(500);
    closesocket(s);
    return 0;
}

static SOCKET setup_server_socket(struct sockaddr_in *addr, int *len)
{
    int ret, val;
    SOCKET server_socket;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    ok(server_socket != INVALID_SOCKET, "failed to bind socket, error %u\n", WSAGetLastError());

    val = 1;
    ret = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&val, sizeof(val));
    ok(!ret, "failed to set SO_REUSEADDR, error %u\n", WSAGetLastError());

    ret = bind(server_socket, (struct sockaddr *)addr, *len);
    ok(!ret, "failed to bind socket, error %u\n", WSAGetLastError());

    ret = getsockname(server_socket, (struct sockaddr *)addr, len);
    ok(!ret, "failed to get address, error %u\n", WSAGetLastError());

    ret = listen(server_socket, 5);
    ok(!ret, "failed to listen, error %u\n", WSAGetLastError());

    return server_socket;
}

static SOCKET setup_connector_socket(const struct sockaddr_in *addr, int len, BOOL nonblock)
{
    int ret;
    SOCKET connector;

    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create connector socket %d\n", WSAGetLastError());

    if (nonblock)
        set_blocking(connector, !nonblock);

    ret = connect(connector, (const struct sockaddr *)addr, len);
    if (!nonblock)
        ok(!ret, "connecting to accepting socket failed %d\n", WSAGetLastError());
    else if (ret == SOCKET_ERROR)
        ok(WSAGetLastError() == WSAEWOULDBLOCK, "got error %u\n", WSAGetLastError());

    return connector;
}


static int sync_recv(SOCKET s, void *buffer, int len, DWORD flags)
{
    OVERLAPPED overlapped = {0};
    WSABUF wsabuf;
    DWORD ret_len;
    int ret;

    overlapped.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wsabuf.buf = buffer;
    wsabuf.len = len;
    ret = WSARecv(s, &wsabuf, 1, &ret_len, &flags, &overlapped, NULL);
    if (ret == -1 && WSAGetLastError() == ERROR_IO_PENDING)
    {
        ret = WaitForSingleObject(overlapped.hEvent, 1000);
        ok(!ret, "wait timed out\n");
        if (ret)
        {
            /* The request must not outlive its OVERLAPPED */
            CancelIo((HANDLE)s);
            GetOverlappedResult((HANDLE)s, &overlapped, &ret_len, TRUE);
        }
        ret = WSAGetOverlappedResult(s, &overlapped, &ret_len, FALSE, &flags);
        ret = (ret ? 0 : -1);
    }
    CloseHandle(overlapped.hEvent);
    if (!ret) return ret_len;
    return -1;
}

static void test_WSAPoll(void)
{
    const struct sockaddr_in bind_addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int ret, err, len;
    SOCKET listener, server, client;
    struct sockaddr_in address;
    WSAPOLLFD fds[16];
    HANDLE thread_handle;
    unsigned int i;
    char buffer[6];

    static const short invalid_flags[] =
            {POLLERR, POLLHUP, POLLNVAL, 0x8, POLLWRBAND, 0x40, 0x80, POLLPRI, 0x800, 0x1000, 0x2000, 0x4000, 0x8000};

    if (!pWSAPoll) /* >= Vista */
    {
        win_skip("WSAPoll is unsupported, some tests will be skipped.\n");
        return;
    }

    /* Invalid parameters test */
    SetLastError(0xdeadbeef);
    ret = pWSAPoll(NULL, 0, 0);
    err = GetLastError();
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(err == WSAEINVAL, "expected 10022, got %d\n", err);
    SetLastError(0xdeadbeef);
    ret = pWSAPoll(NULL, 1, 0);
    err = GetLastError();
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(err == WSAEFAULT, "expected 10014, got %d\n", err);
    SetLastError(0xdeadbeef);
    ret = pWSAPoll(NULL, 0, 1);
    err = GetLastError();
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(err == WSAEINVAL, "expected 10022, got %d\n", err);
    SetLastError(0xdeadbeef);
    ret = pWSAPoll(NULL, 1, 1);
    err = GetLastError();
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(err == WSAEFAULT, "expected 10014, got %d\n", err);

    memset(&address, 0, sizeof(address));
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_family = AF_INET;
    len = sizeof(address);
    listener = setup_server_socket(&address, &len);

    for (i = 0; i < ARRAY_SIZE(invalid_flags); ++i)
    {
        fds[0].fd = listener;
        fds[0].events = invalid_flags[i];
        fds[0].revents = 0xdead;
        WSASetLastError(0xdeadbeef);
        ret = pWSAPoll(fds, 1, 0);
        ok(ret == -1, "got %d\n", ret);
        ok(WSAGetLastError() == WSAEINVAL, "got error %u\n", WSAGetLastError());
    }

    /* When no events are pending poll returns 0 with no error */
    fds[0].fd = listener;
    fds[0].events = POLLRDNORM | POLLRDBAND | POLLWRNORM;
    fds[0].revents = 0xdead;
    ret = pWSAPoll(fds, 1, 0);
    ok(ret == 0, "got %d\n", ret);
    ok(!fds[0].revents, "got events %#x\n", fds[0].revents);

    fds[0].fd = -1;
    fds[0].events = POLLERR;
    fds[0].revents = 0xdead;
    fds[1].fd = listener;
    fds[1].events = POLLIN;
    fds[1].revents = 0xdead;
    WSASetLastError(0xdeadbeef);
    ret = pWSAPoll(fds, 2, 0);
    ok(!ret, "got %d\n", ret);
    ok(!WSAGetLastError(), "got error %u\n", WSAGetLastError());
    ok(fds[0].revents == POLLNVAL, "got events %#x\n", fds[0].revents);
    ok(!fds[1].revents, "got events %#x\n", fds[1].revents);

    fds[0].fd = listener;
    fds[0].events = POLLIN;
    fds[0].revents = 0xdead;
    fds[1].fd = 0xabacab;
    fds[1].events = POLLIN;
    fds[1].revents = 0xdead;
    WSASetLastError(0xdeadbeef);
    ret = pWSAPoll(fds, 2, 0);
    ok(!ret, "got %d\n", ret);
    ok(!WSAGetLastError(), "got error %u\n", WSAGetLastError());
    ok(!fds[0].revents, "got events %#x\n", fds[0].revents);
    ok(fds[1].revents == POLLNVAL, "got events %#x\n", fds[1].revents);

    fds[0].fd = listener;
    fds[0].events = POLLIN;
    fds[0].revents = 0xdead;
    fds[1].fd = 0xabacab;
    fds[1].events = POLLERR;
    fds[1].revents = 0xdead;
    WSASetLastError(0xdeadbeef);
    ret = pWSAPoll(fds, 2, 0);
    ok(ret == -1, "got %d\n", ret);
    ok(WSAGetLastError() == WSAEINVAL, "got error %u\n", WSAGetLastError());
    ok(!fds[0].revents, "got events %#x\n", fds[0].revents);
    ok(!fds[1].revents, "got events %#x\n", fds[1].revents);

    fds[0].fd = -1;
    fds[0].events = POLLERR;
    fds[0].revents = 0xdead;
    fds[1].fd = 0xabacab;
    fds[1].events = POLLERR;
    fds[1].revents = 0xdead;
    WSASetLastError(0xdeadbeef);
    ret = pWSAPoll(fds, 2, 0);
    ok(ret == -1, "got %d\n", ret);
    ok(WSAGetLastError() == WSAENOTSOCK, "got error %u\n", WSAGetLastError());
    ok(fds[0].revents == POLLNVAL, "got events %#x\n", fds[0].revents);
    ok(fds[1].revents == POLLNVAL, "got events %#x\n", fds[1].revents);

    /* Test listening socket connection attempt notifications */
    client = setup_connector_socket(&address, len, TRUE);

    fds[0].fd = listener;
    fds[0].events = POLLIN;
    fds[0].revents = 0xdead;
    ret = pWSAPoll(fds, 1, 100);
    ok(ret == 1, "got %d\n", ret);
    ok(fds[0].revents == POLLRDNORM, "got events %#x\n", fds[0].revents);

    fds[0].revents = 0xdead;
    ret = pWSAPoll(fds, 1, 0);
    ok(ret == 1, "got %d\n", ret);
    ok(fds[0].revents == POLLRDNORM, "got events %#x\n", fds[0].revents);

    fds[0].events = POLLRDBAND | POLLWRNORM;
    fds[0].revents = 0xdead;
    ret = pWSAPoll(fds, 1, 0);
    ok(ret == 0, "got %d\n", ret);
    ok(!fds[0].revents, "got events %#x\n", fds[0].revents);

    server = accept(listener, NULL, NULL);
    ok(server != INVALID_SOCKET, "failed to accept, error %u\n", WSAGetLastError());
    set_blocking(client, FALSE);
    set_blocking(server, FALSE);

    for (i = 0; i < ARRAY_SIZE(invalid_flags); ++i)
    {
        fds[0].fd = server;
        fds[0].events = invalid_flags[i];
        fds[0].revents = 0xdead;
        WSASetLastError(0xdeadbeef);
        ret = pWSAPoll(fds, 1, 0);
        ok(ret == -1, "got %d\n", ret);
        ok(WSAGetLastError() == WSAEINVAL, "got error %u\n", WSAGetLastError());
    }

    /* Test flags exposed by connected sockets. */

    fds[0].fd = listener;
    fds[0].events = POLLRDNORM | POLLRDBAND | POLLWRNORM;
    fds[0].revents = 0xdead;
    fds[1].fd = server;
    fds[1].events = POLLRDNORM | POLLRDBAND | POLLWRNORM;
    fds[1].revents = 0xdead;
    fds[2].fd = client;
    fds[2].events = POLLRDNORM | POLLRDBAND | POLLWRNORM;
    fds[2].revents = 0xdead;
    ret = pWSAPoll(fds, 3, 0);
    ok(ret == 2, "got %d\n", ret);
    ok(!fds[0].revents, "got events %#x\n", fds[0].revents);
    ok(fds[1].revents == POLLWRNORM, "got events %#x\n", fds[1].revents);
    ok(fds[2].revents == POLLWRNORM, "got events %#x\n", fds[2].revents);

    /* Test data receiving notifications */

    ret = send(server, "1234", 4, 0);
    ok(ret == 4, "got %d\n", ret);

    check_poll_mask(client, POLLRDNORM | POLLRDBAND, POLLRDNORM);
    check_poll(client, POLLRDNORM | POLLWRNORM);
    check_poll(server, POLLWRNORM);

    ret = sync_recv(client, buffer, sizeof(buffer), 0);
    ok(ret == 4, "got %d\n", ret);

    check_poll(client, POLLWRNORM);
    check_poll(server, POLLWRNORM);

    /* Because the kernel asynchronously buffers data, this test is not reliable. */

    if (0)
    {
        static const int large_buffer_size = 1024 * 1024;
        char *large_buffer = malloc(large_buffer_size);

        while (send(server, large_buffer, large_buffer_size, 0) == large_buffer_size);

        check_poll(client, POLLWRNORM | POLLRDNORM);
        check_poll(server, 0);

        while (recv(client, large_buffer, large_buffer_size, 0) > 0);

        check_poll(client, POLLWRNORM);
        check_poll(server, POLLWRNORM);

        free(large_buffer);
    }

    /* Test OOB data notifications */

    ret = send(client, "A", 1, MSG_OOB);
    ok(ret == 1, "got %d\n", ret);

    /* ReactOS AFD and tcpip: OOB data is reported as normal data, shutdown(SD_SEND) clears the write event of the sender and the FIN of data in the pipe is not reported as POLLHUP */
    check_poll(client, POLLWRNORM);
    check_poll_mask_todo(server, POLLRDNORM | POLLRDBAND, POLLRDBAND);
    check_poll_todo(server, POLLWRNORM | POLLRDBAND);

    buffer[0] = 0xcc;
    ret = recv(server, buffer, 1, MSG_OOB);
    ok(ret == 1, "got %d\n", ret);
    ok(buffer[0] == 'A', "got %#x\n", buffer[0]);

    check_poll(client, POLLWRNORM);
    check_poll(server, POLLWRNORM);

    /* If the socket is OOBINLINED the notification is like normal data */

    ret = 1;
    ret = setsockopt(server, SOL_SOCKET, SO_OOBINLINE, (char *)&ret, sizeof(ret));
    ok(!ret, "got error %u\n", WSAGetLastError());
    ret = send(client, "A", 1, MSG_OOB);
    ok(ret == 1, "got %d\n", ret);

    check_poll(client, POLLWRNORM);
    check_poll_mask(server, POLLRDNORM | POLLRDBAND, POLLRDNORM);
    check_poll(server, POLLWRNORM | POLLRDNORM);

    buffer[0] = 0xcc;
    ret = recv(server, buffer, 1, 0);
    ok(ret == 1, "got %d\n", ret);
    ok(buffer[0] == 'A', "got %#x\n", buffer[0]);

    check_poll(client, POLLWRNORM);
    check_poll(server, POLLWRNORM);

    /* Test shutdown. */

    ret = shutdown(client, SD_RECEIVE);
    ok(!ret, "got error %u\n", WSAGetLastError());

    check_poll(client, POLLWRNORM);
    check_poll(server, POLLWRNORM);

    ret = shutdown(client, SD_SEND);
    ok(!ret, "got error %u\n", WSAGetLastError());

    check_poll_todo(client, POLLWRNORM);
    check_poll_mask(server, 0, POLLHUP);
    check_poll(server, POLLWRNORM | POLLHUP);

    closesocket(client);
    closesocket(server);

    /* Test shutdown via closesocket(). */

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ret = connect(client, (struct sockaddr *)&address, sizeof(address));
    ok(!ret, "got error %u\n", WSAGetLastError());
    server = accept(listener, NULL, NULL);
    ok(server != -1, "got error %u\n", WSAGetLastError());

    closesocket(client);

    check_poll_mask(server, 0, POLLHUP);
    check_poll(server, POLLWRNORM | POLLHUP);

    closesocket(server);

    /* Test shutdown with data in the pipe. */

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ret = connect(client, (struct sockaddr *)&address, sizeof(address));
    ok(!ret, "got error %u\n", WSAGetLastError());
    server = accept(listener, NULL, NULL);
    ok(server != -1, "got error %u\n", WSAGetLastError());

    ret = send(client, "data", 5, 0);
    ok(ret == 5, "got %d\n", ret);

    check_poll(client, POLLWRNORM);
    check_poll_mask(server, POLLRDNORM | POLLRDBAND, POLLRDNORM);
    check_poll(server, POLLWRNORM | POLLRDNORM);

    ret = shutdown(client, SD_SEND);

    check_poll_todo(client, POLLWRNORM);
    /* the peer's end of the stream is POLLHUP, with the data not read yet as well (Windows Server 2022) */
    check_poll_mask(server, 0, POLLHUP);
    check_poll(server, POLLWRNORM | POLLRDNORM | POLLHUP);

    closesocket(client);
    closesocket(server);

    /* Test closing a socket while selecting on it. */

    tcp_socketpair(&client, &server);

    thread_handle = CreateThread(NULL, 0, SelectCloseThread, &client, 0, NULL);
    fds[0].fd = client;
    fds[0].events = POLLRDNORM | POLLRDBAND;
    fds[0].revents = 0xdead;
    apc_count = 0;
    ret = QueueUserAPC(apc_func, GetCurrentThread(), (ULONG_PTR)&apc_count);
    ok(ret, "QueueUserAPC returned %d\n", ret);
    ret = pWSAPoll(fds, 1, 2000);
    ok(apc_count == 1, "APC was called %u times\n", apc_count);
    ok(ret == 1, "got %d\n", ret);
    ok(fds[0].revents == POLLNVAL, "got events %#x\n", fds[0].revents);
    ret = WaitForSingleObject(thread_handle, 1000);
    ok(!ret, "wait failed\n");
    CloseHandle(thread_handle);

    closesocket(server);

    /* Test a failed connection.
     *
     * The following WSAPoll() call times out on versions older than w10pro64,
     * but even on w10pro64 it takes over 2 seconds for an error to be reported,
     * so make the test interactive-only. */
    if (winetest_interactive)
    {
        const struct sockaddr_in invalid_addr =
        {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
            .sin_port = 255,
        };
        SOCKET client;

        client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        set_blocking(client, FALSE);

        ret = connect(client, (const struct sockaddr *)&invalid_addr, sizeof(invalid_addr));
        ok(ret == -1, "got %d\n", ret);
        ok(WSAGetLastError() == WSAEWOULDBLOCK, "got error %u\n", WSAGetLastError());

        fds[0].fd = client;
        fds[0].events = POLLRDNORM | POLLRDBAND | POLLWRNORM;
        fds[0].revents = 0xdead;
        ret = pWSAPoll(fds, 1, 10000);
        ok(ret == 1, "got %d\n", ret);
        ok(fds[0].revents == (POLLWRNORM | POLLHUP | POLLERR), "got events %#x\n", fds[0].revents);

        len = sizeof(err);
        err = 0xdeadbeef;
        ret = getsockopt(client, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
        ok(!ret, "getsockopt failed with %d\n", WSAGetLastError());
        ok(err == WSAECONNREFUSED, "got error %u\n", err);

        len = sizeof(err);
        err = 0xdeadbeef;
        ret = getsockopt(client, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
        ok(!ret, "getsockopt failed with %d\n", WSAGetLastError());
        ok(err == WSAECONNREFUSED, "got error %u\n", err);

        check_poll(client, POLLWRNORM | POLLHUP | POLLERR);

        closesocket(client);

        /* test polling after a (synchronous) failure */

        client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        ret = connect(client, (const struct sockaddr *)&invalid_addr, sizeof(invalid_addr));
        ok(ret == -1, "got %d\n", ret);
        ok(WSAGetLastError() == WSAECONNREFUSED, "got error %u\n", WSAGetLastError());

        check_poll(client, POLLWRNORM | POLLHUP | POLLERR);

        len = sizeof(err);
        err = 0xdeadbeef;
        ret = getsockopt(client, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
        ok(!ret, "getsockopt failed with %d\n", WSAGetLastError());
        ok(!err, "got error %u\n", err);

        closesocket(client);
    }

    closesocket(listener);

    /* Test UDP sockets. */

    client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    check_poll(client, POLLWRNORM);
    check_poll(server, POLLWRNORM);

    ret = bind(client, (const struct sockaddr *)&bind_addr, sizeof(bind_addr));
    ok(!ret, "got error %u\n", WSAGetLastError());
    len = sizeof(address);
    ret = getsockname(client, (struct sockaddr *)&address, &len);
    ok(!ret, "got error %u\n", WSAGetLastError());

    check_poll(client, POLLWRNORM);
    check_poll(server, POLLWRNORM);

    ret = sendto(server, "data", 5, 0, (struct sockaddr *)&address, sizeof(address));
    ok(ret == 5, "got %d\n", ret);

    check_poll_mask(client, POLLRDNORM | POLLRDBAND, POLLRDNORM);
    check_poll(client, POLLWRNORM | POLLRDNORM);
    check_poll(server, POLLWRNORM);

    closesocket(client);
    closesocket(server);
}

typedef struct _CLOSE_REUSE
{
    SOCKET Socket;
    HANDLE Polling;
} CLOSE_REUSE;

/* Closes the socket while the poll is pending, then opens sockets at once so that the handle value may be reused */
static DWORD WINAPI CloseAndReuseThread(void *param)
{
    CLOSE_REUSE *Close = param;
    SOCKET Fresh[4];
    ULONG i;

    WaitForSingleObject(Close->Polling, 5000);
    Sleep(30);
    closesocket(Close->Socket);
    for (i = 0; i < ARRAY_SIZE(Fresh); i++)
        Fresh[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Sleep(200);
    for (i = 0; i < ARRAY_SIZE(Fresh); i++)
    {
        if (Fresh[i] != INVALID_SOCKET)
            closesocket(Fresh[i]);
    }
    return 0;
}

/* A socket that is closed while polled is POLLNVAL, also with other sockets in the set and when its handle
 * value is taken by a new socket at once */
static void test_WSAPoll_close_race(void)
{
    ULONG Round;

    for (Round = 0; Round < 20; Round++)
    {
        SOCKET Client, Server, OtherClient, OtherServer;
        CLOSE_REUSE Close;
        HANDLE Thread;
        WSAPOLLFD fds[2];
        int ret;

        tcp_socketpair(&Client, &Server);
        tcp_socketpair(&OtherClient, &OtherServer);

        Close.Socket = Client;
        Close.Polling = CreateEventA(NULL, FALSE, FALSE, NULL);
        Thread = CreateThread(NULL, 0, CloseAndReuseThread, &Close, 0, NULL);

        fds[0].fd = Client;
        fds[0].events = POLLRDNORM;
        fds[0].revents = 0xdead;
        fds[1].fd = OtherClient;
        fds[1].events = POLLRDNORM;
        fds[1].revents = 0xdead;
        SetEvent(Close.Polling);
        ret = pWSAPoll(fds, 2, 5000);
        ok(ret == 1, "round %lu: got %d, error %d\n", Round, ret, WSAGetLastError());
        ok(fds[0].revents == POLLNVAL, "round %lu: got events %#x\n", Round, fds[0].revents);
        ok(!fds[1].revents, "round %lu: got events %#x for the other socket\n", Round, fds[1].revents);

        WaitForSingleObject(Thread, 5000);
        CloseHandle(Thread);
        CloseHandle(Close.Polling);
        closesocket(Server);
        closesocket(OtherClient);
        closesocket(OtherServer);
    }
}

typedef struct _CLOSE_SPIN
{
    SOCKET Socket;
    volatile LONG Go;
    LONG Spin;
} CLOSE_SPIN;

static DWORD WINAPI CloseAfterSpinThread(void *param)
{
    CLOSE_SPIN *Close = param;
    volatile LONG Counter;
    LONG i;

    while (!Close->Go)
        ;
    for (i = 0, Counter = 0; i < Close->Spin; i++)
        Counter++;
    closesocket(Close->Socket);
    return 0;
}

/* The close lands at a varying point around the submission of the poll. Whatever the timing, the call must not fail
 * with an error, must report the closed socket as POLLNVAL, and must not wait for the timeout when it reports one:
 * the other socket is idle, so a retry that keeps the timeout shows as a call that runs to its end. The point of
 * the close cannot be forced from user mode, so this stresses the window and does not pin it. */
static void test_WSAPoll_close_submit(void)
{
    ULONG Round, Reported = 0;

    for (Round = 0; Round < 300; Round++)
    {
        SOCKET Client, Server, OtherClient, OtherServer;
        CLOSE_SPIN Close;
        HANDLE Thread;
        WSAPOLLFD fds[2];
        DWORD Start, Elapsed;
        int ret;

        tcp_socketpair(&Client, &Server);
        tcp_socketpair(&OtherClient, &OtherServer);

        Close.Socket = Client;
        Close.Go = 0;
        Close.Spin = (Round * 1237) % 200000;
        Thread = CreateThread(NULL, 0, CloseAfterSpinThread, &Close, 0, NULL);

        fds[0].fd = Client;
        fds[0].events = POLLRDNORM;
        fds[0].revents = 0xdead;
        fds[1].fd = OtherClient;
        fds[1].events = POLLRDNORM;
        fds[1].revents = 0xdead;
        Start = GetTickCount();
        InterlockedExchange(&Close.Go, 1);
        ret = pWSAPoll(fds, 2, 400);
        Elapsed = GetTickCount() - Start;

        ok(ret >= 0, "round %lu: got %d, error %d\n", Round, ret, WSAGetLastError());
        ok(fds[0].revents == POLLNVAL, "round %lu: got events %#x\n", Round, fds[0].revents);
        ok(!fds[1].revents, "round %lu: got events %#x for the other socket\n", Round, fds[1].revents);
        if (ret == 1)
        {
            Reported++;
            ok(Elapsed < 250, "round %lu: the closed socket was reported after %lu ms\n", Round, Elapsed);
        }

        WaitForSingleObject(Thread, 5000);
        CloseHandle(Thread);
        closesocket(Server);
        closesocket(OtherClient);
        closesocket(OtherServer);
    }
    trace("the closed socket was reported by %lu of 300 calls\n", Reported);
}

START_TEST(WSAPoll)
{
    WSADATA data;
    int ret;

    ret = WSAStartup(MAKEWORD(2, 2), &data);
    ok(!ret, "WSAStartup failed with %d\n", ret);
    if (ret)
        return;

    pWSAPoll = (void *)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "WSAPoll");
    if (pWSAPoll)
    {
        test_WSAPoll();
        test_WSAPoll_close_race();
        test_WSAPoll_close_submit();
    }
    else
        skip("WSAPoll is not available\n");

    WSACleanup();
}
