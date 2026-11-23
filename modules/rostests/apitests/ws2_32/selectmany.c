/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test select() with 65 to 1024 sockets in its sets
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * An application may define FD_SETSIZE larger than the 64 Winsock was built with and pass sets with
 * any number of sockets: select() takes the count the set carries (Windows Server 2022 selected 1000
 * and 1500 sockets per call). The sets here are laid out like such an application's: a count, then
 * the sockets, in memory of the test's own size.
 */

#include "ws2_32.h"

#define MAX_SOCKETS 1024

/* A set of any size: the same layout as fd_set, with room for Capacity sockets */
static fd_set *
AllocSet(unsigned Capacity)
{
    fd_set *Set = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                            FIELD_OFFSET(fd_set, fd_array) + (SIZE_T)Capacity * sizeof(SOCKET));

    return Set;
}

static BOOL
InSet(const fd_set *Set, SOCKET Socket)
{
    u_int i;

    for (i = 0; i < Set->fd_count; i++)
        if (Set->fd_array[i] == Socket)
            return TRUE;
    return FALSE;
}

/* A bound loopback UDP socket, and the address to send to it */
static SOCKET
OpenUdp(struct sockaddr_in *Addr)
{
    SOCKET Socket = socket(AF_INET, SOCK_DGRAM, 0);
    int Length = sizeof(*Addr);

    if (Socket == INVALID_SOCKET)
        return INVALID_SOCKET;
    ZeroMemory(Addr, sizeof(*Addr));
    Addr->sin_family = AF_INET;
    Addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Socket, (struct sockaddr *)Addr, sizeof(*Addr)) != 0 ||
        getsockname(Socket, (struct sockaddr *)Addr, &Length) != 0)
    {
        closesocket(Socket);
        return INVALID_SOCKET;
    }
    return Socket;
}

static void
TestCount(SOCKET *Sockets, struct sockaddr_in *Addrs, SOCKET Sender, int Count)
{
    fd_set *Read = AllocSet(Count), *Write = AllocSet(Count), *Except = AllocSet(Count);
    struct timeval Zero = { 0, 0 };
    struct timeval Short = { 0, 100000 };
    struct timeval Long = { 5, 0 };
    int i, Result, Error, Ready, Wrong;
    DWORD Start, Elapsed;
    char Byte = 'x';

    if (!Read || !Write || !Except)
    {
        skip("%d sockets: no memory\n", Count);
        goto Done;
    }

    /* Nothing is readable: the read set comes back empty, with timeout 0 and with a short timeout */
    for (i = 0; i < Count; i++)
        Read->fd_array[i] = Sockets[i];
    Read->fd_count = Count;
    Result = select(0, Read, NULL, NULL, &Zero);
    Error = Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    ok(Result == 0 && Read->fd_count == 0, "%d sockets, none readable, timeout 0: %d (error %d), %u left\n",
       Count, Result, Error, Read->fd_count);

    for (i = 0; i < Count; i++)
        Read->fd_array[i] = Sockets[i];
    Read->fd_count = Count;
    Start = GetTickCount();
    Result = select(0, Read, NULL, NULL, &Short);
    Error = Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    Elapsed = GetTickCount() - Start;
    ok(Result == 0 && Read->fd_count == 0, "%d sockets, none readable, short timeout: %d (error %d), %u left\n",
       Count, Result, Error, Read->fd_count);
    ok(Elapsed >= 50, "%d sockets, none readable: returned after %lu ms, the timeout is 100\n", Count, Elapsed);

    /* Every socket can be written */
    for (i = 0; i < Count; i++)
        Write->fd_array[i] = Sockets[i];
    Write->fd_count = Count;
    Result = select(0, NULL, Write, NULL, &Zero);
    Error = Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    ok(Result == Count && Write->fd_count == (u_int)Count, "%d sockets in the write set: %d (error %d), %u left\n",
       Count, Result, Error, Write->fd_count);
    for (Wrong = 0, i = 0; i < Count; i++)
        Wrong += !InSet(Write, Sockets[i]);
    ok(Wrong == 0, "%d sockets in the write set: %d missing from the result\n", Count, Wrong);

    /* The exception set of sockets that have no urgent data stays empty */
    for (i = 0; i < Count; i++)
        Except->fd_array[i] = Sockets[i];
    Except->fd_count = Count;
    Result = select(0, NULL, NULL, Except, &Zero);
    Error = Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    ok(Result == 0 && Except->fd_count == 0, "%d sockets in the except set: %d (error %d), %u left\n",
       Count, Result, Error, Except->fd_count);

    /* Every third socket gets a datagram: readable. The last socket is one of them */
    Ready = 0;
    for (i = 0; i < Count; i++)
    {
        if ((Count - 1 - i) % 3 == 0)
        {
            Result = sendto(Sender, &Byte, 1, 0, (struct sockaddr *)&Addrs[i], sizeof(Addrs[i]));
            if (Result != 1)
                trace("sendto %d failed: %d\n", i, WSAGetLastError());
            Ready++;
        }
    }

    for (i = 0; i < Count; i++)
        Read->fd_array[i] = Sockets[i];
    Read->fd_count = Count;
    Result = select(0, Read, NULL, NULL, &Long);
    Error = Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    /* Loopback delivery can be late: the ready ones may come in more than one call */
    ok(Result > 0 && Result <= Ready, "%d sockets, %d ready: select returned %d (error %d)\n",
       Count, Ready, Result, Error);

    /* After a pause all of them are there: the result holds those and only those, with timeout 0 */
    Sleep(500);
    for (i = 0; i < Count; i++)
        Read->fd_array[i] = Sockets[i];
    Read->fd_count = Count;
    Result = select(0, Read, NULL, NULL, &Zero);
    Error = Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    ok(Result == Ready && Read->fd_count == (u_int)Ready, "%d sockets, %d ready, timeout 0: select returned %d (error %d), %u in the set\n",
       Count, Ready, Result, Error, Read->fd_count);
    for (Wrong = 0, i = 0; i < Count; i++)
        Wrong += InSet(Read, Sockets[i]) != ((Count - 1 - i) % 3 == 0);
    ok(Wrong == 0, "%d sockets, %d ready: %d sockets in the wrong state in the result\n", Count, Ready, Wrong);

    /* All three sets at once, the same sockets in each: the readable ones are in the read set, all of them in the write set */
    for (i = 0; i < Count; i++)
        Read->fd_array[i] = Write->fd_array[i] = Except->fd_array[i] = Sockets[i];
    Read->fd_count = Write->fd_count = Except->fd_count = Count;
    Result = select(0, Read, Write, Except, &Zero);
    Error = Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    ok(Result == Ready + Count && Read->fd_count == (u_int)Ready && Write->fd_count == (u_int)Count &&
       Except->fd_count == 0,
       "%d sockets in all three sets: select returned %d (error %d), read %u write %u except %u, %d readable\n",
       Count, Result, Error, Read->fd_count, Write->fd_count, Except->fd_count, Ready);

    /* The sockets split over the three sets: the first third to read, the second to write, the third to except */
    Read->fd_count = Write->fd_count = Except->fd_count = 0;
    for (i = 0; i < Count; i++)
    {
        fd_set *Set = (i % 3 == 0) ? Read : (i % 3 == 1) ? Write : Except;

        Set->fd_array[Set->fd_count++] = Sockets[i];
    }
    Result = select(0, Read, Write, Except, &Zero);
    Error = Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    /* i % 3 == 0 sockets to read: ready when (Count - 1 - i) % 3 == 0, which is when (Count - 1) % 3 == 0 */
    {
        int ReadReady = ((Count - 1) % 3 == 0) ? (Count + 2) / 3 : 0;
        int WriteSockets = (Count + 1) / 3;

        ok(Result == ReadReady + WriteSockets && (int)Read->fd_count == ReadReady && (int)Write->fd_count == WriteSockets &&
           Except->fd_count == 0,
           "%d sockets split over three sets: select returned %d (error %d), read %u (%d) write %u (%d) except %u\n",
           Count, Result, Error, Read->fd_count, ReadReady, Write->fd_count, WriteSockets, Except->fd_count);
    }

    /* Drain, so the next count starts with nothing readable */
    for (i = 0; i < Count; i++)
    {
        char Buffer[4];

        if ((Count - 1 - i) % 3 == 0)
            recv(Sockets[i], Buffer, sizeof(Buffer), 0);
    }

Done:
    if (Read) HeapFree(GetProcessHeap(), 0, Read);
    if (Write) HeapFree(GetProcessHeap(), 0, Write);
    if (Except) HeapFree(GetProcessHeap(), 0, Except);
}

/* A set whose count is more than its memory holds, or more than a select() takes, fails cleanly */
static void
TestBogusCount(SOCKET Socket)
{
    static const u_int Counts[] = { 1000, 0x7FFFFFFF, 0xFFFFFFFF };
    struct timeval Zero = { 0, 0 };
    SYSTEM_INFO Info;
    PUCHAR Base;
    fd_set *Set;
    DWORD Old;
    int Result, Error, i;

    GetSystemInfo(&Info);
    Base = VirtualAlloc(NULL, 2 * Info.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Base || !VirtualProtect(Base + Info.dwPageSize, Info.dwPageSize, PAGE_NOACCESS, &Old))
    {
        skip("no guard page: %lu\n", GetLastError());
        return;
    }

    /* The set ends at the guard page: room for two sockets */
    Set = (fd_set *)(Base + Info.dwPageSize - (FIELD_OFFSET(fd_set, fd_array) + 2 * sizeof(SOCKET)));

    for (i = 0; i < (int)(sizeof(Counts) / sizeof(Counts[0])); i++)
    {
        Set->fd_array[0] = Set->fd_array[1] = Socket;
        Set->fd_count = Counts[i];
        SetLastError(0xdeadbeef);
        Result = select(0, Set, NULL, NULL, &Zero);
        Error = WSAGetLastError();
        ok(Result == SOCKET_ERROR && Error == WSAEFAULT, "read set with count %u and room for 2: select returned %d, error %d\n",
           Counts[i], Result, Error);

        Set->fd_array[0] = Set->fd_array[1] = Socket;
        Set->fd_count = Counts[i];
        Result = select(0, NULL, Set, NULL, &Zero);
        Error = WSAGetLastError();
        ok(Result == SOCKET_ERROR && Error == WSAEFAULT, "write set with count %u and room for 2: select returned %d, error %d\n",
           Counts[i], Result, Error);

        Set->fd_array[0] = Set->fd_array[1] = Socket;
        Set->fd_count = Counts[i];
        Result = select(0, NULL, NULL, Set, &Zero);
        Error = WSAGetLastError();
        ok(Result == SOCKET_ERROR && Error == WSAEFAULT, "except set with count %u and room for 2: select returned %d, error %d\n",
           Counts[i], Result, Error);
    }

    /* The socket still works after those */
    Set->fd_array[0] = Socket;
    Set->fd_count = 1;
    Result = select(0, NULL, Set, NULL, &Zero);
    ok(Result == 1, "write set with one socket after the bogus counts: %d, error %d\n", Result, WSAGetLastError());

    VirtualFree(Base, 0, MEM_RELEASE);
}

START_TEST(selectmany)
{
    static const int Counts[] = { 65, 256, 1000, 1024 };
    WSADATA WsaData;
    SOCKET *Sockets;
    struct sockaddr_in *Addrs, SenderAddr;
    SOCKET Sender;
    int i, Opened;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    Sockets = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_SOCKETS * sizeof(*Sockets));
    Addrs = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_SOCKETS * sizeof(*Addrs));
    Sender = OpenUdp(&SenderAddr);
    if (!Sockets || !Addrs || Sender == INVALID_SOCKET)
    {
        skip("setup failed: %d\n", WSAGetLastError());
        goto Cleanup;
    }

    for (Opened = 0; Opened < MAX_SOCKETS; Opened++)
    {
        Sockets[Opened] = OpenUdp(&Addrs[Opened]);
        if (Sockets[Opened] == INVALID_SOCKET)
            break;
    }
    ok(Opened == MAX_SOCKETS, "only %d sockets: %d\n", Opened, WSAGetLastError());

    if (Opened == MAX_SOCKETS)
    {
        for (i = 0; i < (int)(sizeof(Counts) / sizeof(Counts[0])); i++)
            TestCount(Sockets, Addrs, Sender, Counts[i]);

        TestBogusCount(Sockets[0]);
    }

    for (i = 0; i < Opened; i++)
        closesocket(Sockets[i]);

Cleanup:
    if (Sender != INVALID_SOCKET)
        closesocket(Sender);
    if (Sockets) HeapFree(GetProcessHeap(), 0, Sockets);
    if (Addrs) HeapFree(GetProcessHeap(), 0, Addrs);
    WSACleanup();
}
