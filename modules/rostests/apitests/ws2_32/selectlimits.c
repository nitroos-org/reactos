/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test the limits of select(): 65535 sockets in one set, counts and pointers that are not real
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Measured on Windows Server 2022 (sets of one socket repeated, the count the caller gives):
 * 65535 in a set works, 65536 or more in ANY set (also 0xFFFFFFFF, also three sets of 65536) is WSAENOBUFS
 * before the memory is read and leaves the sets as they were; a count below 65536 that reaches beyond the
 * readable memory of the set is WSAEFAULT, and so is a pointer to memory that cannot be read.
 */

#include "ws2_32.h"

typedef struct
{
    u_int fd_count;
    SOCKET fd_array[1];
} BIG_FD_SET;

static BIG_FD_SET *
NewSet(ULONG Capacity)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(u_int) + sizeof(SOCKET) + Capacity * sizeof(SOCKET));
}

static int
Select(BIG_FD_SET *Read, BIG_FD_SET *Write, BIG_FD_SET *Except, int *Error)
{
    struct timeval Timeout = { 0, 0 };
    int Result = select(0, (fd_set *)Read, (fd_set *)Write, (fd_set *)Except, &Timeout);

    *Error = Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    return Result;
}

START_TEST(selectlimits)
{
    WSADATA WsaData;
    SYSTEM_INFO Info;
    PUCHAR Base;
    BIG_FD_SET *Set, *Big, *Other1, *Other2;
    SOCKET Socket;
    int Result, Error;
    ULONG i;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }
    Socket = socket(AF_INET, SOCK_DGRAM, 0);
    GetSystemInfo(&Info);

    /* A set that ends at the end of its page: a count of 2 is fine, a count of 100 reaches beyond it */
    Base = VirtualAlloc(NULL, 2 * Info.dwPageSize, MEM_RESERVE, PAGE_NOACCESS);
    if (Base && VirtualAlloc(Base, Info.dwPageSize, MEM_COMMIT, PAGE_READWRITE))
    {
        Set = (BIG_FD_SET *)(Base + Info.dwPageSize - FIELD_OFFSET(BIG_FD_SET, fd_array[2]));
        Set->fd_array[0] = Socket;
        Set->fd_array[1] = Socket;
        Set->fd_count = 2;
        Result = Select(NULL, Set, NULL, &Error);
        ok(Result == 1, "count 2 at the end of a page: select returned %d (error %d)\n", Result, Error);

        Set->fd_array[0] = Socket;
        Set->fd_array[1] = Socket;
        Set->fd_count = 100;
        Result = Select(NULL, Set, NULL, &Error);
        ok(Result == SOCKET_ERROR && Error == WSAEFAULT,
           "count 100 beyond the page: select returned %d, error %d\n", Result, Error);

        /* More than 65535 is refused before the memory is looked at */
        Set->fd_array[0] = Socket;
        Set->fd_count = 0xFFFFFFFF;
        Result = Select(Set, NULL, NULL, &Error);
        ok(Result == SOCKET_ERROR && Error == WSAENOBUFS, "count 0xFFFFFFFF: select returned %d, error %d\n", Result, Error);
        Set->fd_count = 65536;
        Result = Select(NULL, NULL, Set, &Error);
        ok(Result == SOCKET_ERROR && Error == WSAENOBUFS, "count 65536 beyond the page: select returned %d, error %d\n", Result, Error);
        VirtualFree(Base, 0, MEM_RELEASE);
    }
    else
    {
        skip("no page\n");
    }

    /* A pointer to memory that cannot be read */
    Base = VirtualAlloc(NULL, Info.dwPageSize, MEM_RESERVE, PAGE_NOACCESS);
    if (Base)
    {
        Result = Select((BIG_FD_SET *)Base, NULL, NULL, &Error);
        ok(Result == SOCKET_ERROR && Error == WSAEFAULT, "bad pointer: select returned %d, error %d\n", Result, Error);
        VirtualFree(Base, 0, MEM_RELEASE);
    }

    /* 65535 sockets in a set are fine, 65536 are not: the set is left untouched */
    Big = NewSet(65536);
    if (Big)
    {
        for (i = 0; i < 65536; i++)
            Big->fd_array[i] = Socket;
        Big->fd_count = 65535;
        Result = Select(NULL, Big, NULL, &Error);
        ok(Result == 1 && Big->fd_count == 1, "65535 times one socket: select returned %d (error %d), %u left\n",
           Result, Error, Big->fd_count);
        for (i = 0; i < 65536; i++)
            Big->fd_array[i] = Socket;
        Big->fd_count = 65536;
        Result = Select(Big, NULL, NULL, &Error);
        ok(Result == SOCKET_ERROR && Error == WSAENOBUFS && Big->fd_count == 65536,
           "65536 in the read set: select returned %d (error %d), %u left\n", Result, Error, Big->fd_count);

        /* The limit is per set, and any set over it is refused */
        Other1 = NewSet(2);
        Other2 = NewSet(2);
        if (Other1 && Other2)
        {
            Other1->fd_array[0] = Other2->fd_array[0] = Socket;
            Other1->fd_count = Other2->fd_count = 1;
            Result = Select(Other1, Other2, Big, &Error);
            ok(Result == SOCKET_ERROR && Error == WSAENOBUFS, "65536 in the except set: select returned %d, error %d\n",
               Result, Error);
        }
        HeapFree(GetProcessHeap(), 0, Other1);
        HeapFree(GetProcessHeap(), 0, Other2);
        HeapFree(GetProcessHeap(), 0, Big);
    }

    closesocket(Socket);
    WSACleanup();
}
