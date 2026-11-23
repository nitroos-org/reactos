/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A local user sends one datagram to each of many distinct multicast groups; the neighbour
 *              table the system lists, its pool, and the sending itself are checked
 *
 *                mcspray v4|v6 GROUPS [WAIT_SECONDS]
 *
 *              Rows (stdout, one per line, "MCSPRAY" prefix):
 *                before / after-spray / after-wait: group entries the neighbour table lists
 *                  (GetIpNetTable: addresses 224.0.0.0/4; GetIpNetTable2: ff00::/8), the nonpaged pool tag
 *                  "NCE " (live allocations and bytes), the sum of every nonpaged tag's bytes
 *                send: datagrams that failed to send, of GROUPS
 *                work: after the spray a datagram to a group a second socket of the process has joined
 *                  arrives (checked with a receive timeout)
 *                tags: every pool tag whose live count changed by 50 or more between before and the end
 *                MCSPRAY-PASS when no send failed, the work row held, and the table listed at most LIMIT
 *                  group entries after the spray (LIMIT: 4096 unless -DLIMIT=... : the bound to check)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

/* MIB_IPNET_ROW2 and MIB_IPNET_TABLE2 of the Windows SDK under private names (the headers of this tree do not
   declare them for the version it is built for) */
typedef struct
{
    struct sockaddr_in6 Address6;   /* SOCKADDR_INET (28 bytes) */
    ULONG InterfaceIndex;
    ULONGLONG InterfaceLuid;
    UCHAR PhysicalAddress[32];
    ULONG PhysicalAddressLength;
    ULONG State;
    UCHAR Flags;
    ULONG ReachabilityTime;
} NEIGH_ROW6;

typedef struct
{
    ULONG NumEntries;
    NEIGH_ROW6 Table[1];
} NEIGH_TABLE6;

#ifndef LIMIT
#define LIMIT 4096
#endif

typedef struct { union { UCHAR Tag[4]; ULONG TagUlong; }; ULONG PagedAllocs, PagedFrees; SIZE_T PagedUsed;
                 ULONG NonPagedAllocs, NonPagedFrees; SIZE_T NonPagedUsed; } POOLTAG;
typedef struct { ULONG Count; POOLTAG TagInfo[1]; } POOLTAG_INFO;
typedef LONG (WINAPI *QSI)(ULONG, PVOID, ULONG, PULONG);

typedef struct { char Name[5]; long Live; unsigned long Bytes; } TAGROW;

static TAGROW *g_Before, *g_After;
static ULONG g_BeforeN, g_AfterN;

/* pool tags: every tag, nonpaged live allocations and bytes */
static ULONG
Tags(TAGROW **Rows, unsigned long *NpTotal, long *NceLive, unsigned long *NceBytes)
{
    QSI Query = (QSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    ULONG Size = 1 << 16, Need = 0, i;
    POOLTAG_INFO *Info = NULL;
    LONG Status;

    for (;;)
    {
        Info = realloc(Info, Size);
        Status = Query(22, Info, Size, &Need);
        if (Status != (LONG)0xC0000004 || Size > (64u << 20))
            break;
        Size = Need > Size ? Need + 4096 : Size * 2;
    }
    *NpTotal = 0; *NceLive = -1; *NceBytes = 0;
    if (Status < 0)
    {
        printf("MCSPRAY pool tag query failed 0x%08lx\n", (unsigned long)Status);
        free(Info);
        *Rows = NULL;
        return 0;
    }
    *Rows = calloc(Info->Count, sizeof(TAGROW));
    for (i = 0; i < Info->Count; i++)
    {
        POOLTAG *T = &Info->TagInfo[i];
        TAGROW *R = &(*Rows)[i];
        int k;

        for (k = 0; k < 4; k++)
            R->Name[k] = (T->Tag[k] >= 0x21 && T->Tag[k] < 0x7f) ? (char)T->Tag[k] : '_';
        R->Name[4] = 0;
        if (T->Tag[0] == 'N' && T->Tag[1] == 'C' && T->Tag[2] == 'E' && T->Tag[3] == ' ')
        {
            R->Name[3] = '_';
            *NceLive = (long)(T->NonPagedAllocs - T->NonPagedFrees);
            *NceBytes = (unsigned long)T->NonPagedUsed;
        }
        R->Live = (long)(T->NonPagedAllocs - T->NonPagedFrees);
        R->Bytes = (unsigned long)T->NonPagedUsed;
        *NpTotal += (unsigned long)T->NonPagedUsed;
    }
    i = Info->Count;
    free(Info);
    return i;
}

static int
ListGroups4(void)
{
    PMIB_IPNETTABLE Table = NULL;
    ULONG Size = 0, i, Count = 0;
    DWORD Err;

    for (;;)
    {
        Err = GetIpNetTable(Table, &Size, FALSE);
        if (Err != ERROR_INSUFFICIENT_BUFFER)
            break;
        free(Table);
        Table = malloc(Size);
    }
    if (Err != NO_ERROR)
    {
        free(Table);
        return -(int)Err;
    }
    for (i = 0; i < Table->dwNumEntries; i++)
    {
        UCHAR First = (UCHAR)(Table->table[i].dwAddr & 0xFF);

        if (First >= 224 && First <= 239)
            Count++;
    }
    free(Table);
    return (int)Count;
}

static int
ListGroups6(void)
{
    typedef DWORD (WINAPI *PGET)(USHORT, PVOID *);
    typedef VOID (WINAPI *PFREE)(PVOID);
    HMODULE Mod = LoadLibraryA("iphlpapi.dll");
    PGET Get = Mod ? (PGET)GetProcAddress(Mod, "GetIpNetTable2") : NULL;
    PFREE Free = Mod ? (PFREE)GetProcAddress(Mod, "FreeMibTable") : NULL;
    NEIGH_TABLE6 *Table = NULL;
    ULONG i, Count = 0;
    DWORD Err;

    if (!Get || !Free)
        return -1;
    Err = Get(AF_INET6, (PVOID *)&Table);
    if (Err != NO_ERROR)
        return -(int)Err;
    for (i = 0; i < Table->NumEntries; i++)
        if (Table->Table[i].Address6.sin6_addr.u.Byte[0] == 0xFF)
            Count++;
    Free(Table);
    return (int)Count;
}

static int g_V6;

static int
Listed(void)
{
    return g_V6 ? ListGroups6() : ListGroups4();
}

static void
Snapshot(const char *Label, int Which)
{
    unsigned long NpTotal, NceBytes;
    long NceLive;
    TAGROW *Rows;
    ULONG N = Tags(&Rows, &NpTotal, &NceLive, &NceBytes);

    printf("MCSPRAY %s: listed-group-entries=%d pool NCE-live=%ld NCE-bytes=%lu nonpaged-total=%lu\n",
           Label, Listed(), NceLive, NceBytes, NpTotal);
    if (Which == 1) { g_Before = Rows; g_BeforeN = N; }
    else if (Which == 2) { free(g_After); g_After = Rows; g_AfterN = N; }
    else free(Rows);
}

static void
GroupAddr(int Index, struct sockaddr_storage *Sa, int *Len)
{
    memset(Sa, 0, sizeof(*Sa));
    if (g_V6)
    {
        struct sockaddr_in6 *A = (struct sockaddr_in6 *)Sa;

        A->sin6_family = AF_INET6;
        A->sin6_port = htons(5599);
        /* ff15::/16 (site scope: no link-local scope id needed), 10 000 distinct low 32 bits */
        A->sin6_addr.u.Byte[0] = 0xFF; A->sin6_addr.u.Byte[1] = 0x15;
        A->sin6_addr.u.Byte[12] = (UCHAR)(Index >> 24); A->sin6_addr.u.Byte[13] = (UCHAR)(Index >> 16);
        A->sin6_addr.u.Byte[14] = (UCHAR)(Index >> 8);  A->sin6_addr.u.Byte[15] = (UCHAR)Index;
        A->sin6_addr.u.Byte[11] = 0x77;
        *Len = sizeof(*A);
    }
    else
    {
        struct sockaddr_in *A = (struct sockaddr_in *)Sa;

        A->sin_family = AF_INET;
        A->sin_port = htons(5599);
        /* 239.100.0.0 upwards */
        A->sin_addr.S_un.S_un_b.s_b1 = 239;
        A->sin_addr.S_un.S_un_b.s_b2 = (UCHAR)(100 + (Index >> 16));
        A->sin_addr.S_un.S_un_b.s_b3 = (UCHAR)(Index >> 8);
        A->sin_addr.S_un.S_un_b.s_b4 = (UCHAR)Index;
        *Len = sizeof(*A);
    }
}

/* a datagram to a group a second socket joined arrives */
static int
WorkCheck(void)
{
    SOCKET Rx, Tx;
    struct sockaddr_storage Sa;
    int Len, Ok = 0, Got;
    char Buf[16];
    DWORD Tmo = 2000;
    int One = 1;

    Rx = socket(g_V6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    Tx = socket(g_V6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Rx == INVALID_SOCKET || Tx == INVALID_SOCKET)
        return 0;
    setsockopt(Rx, SOL_SOCKET, SO_REUSEADDR, (char *)&One, sizeof(One));
    setsockopt(Rx, SOL_SOCKET, SO_RCVTIMEO, (char *)&Tmo, sizeof(Tmo));

    GroupAddr(0x7000, &Sa, &Len);
    if (g_V6)
    {
        struct sockaddr_in6 Any = {0};
        struct ipv6_mreq M;
        DWORD Index = 0;

        Any.sin6_family = AF_INET6; Any.sin6_port = htons(5599);
        if (bind(Rx, (struct sockaddr *)&Any, sizeof(Any)) != 0)
            return 0;
        M.ipv6mr_multiaddr = ((struct sockaddr_in6 *)&Sa)->sin6_addr;
        /* the first adapter that is up (ipv6mr_interface 0 lets the stack choose) */
        M.ipv6mr_interface = Index;
        if (setsockopt(Rx, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&M, sizeof(M)) != 0)
        {
            printf("MCSPRAY work: IPV6_ADD_MEMBERSHIP failed %d\n", WSAGetLastError());
            return 0;
        }
        setsockopt(Tx, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&One, sizeof(One));
    }
    else
    {
        struct sockaddr_in Any = {0};
        struct ip_mreq M;

        Any.sin_family = AF_INET; Any.sin_port = htons(5599);
        if (bind(Rx, (struct sockaddr *)&Any, sizeof(Any)) != 0)
            return 0;
        M.imr_multiaddr = ((struct sockaddr_in *)&Sa)->sin_addr;
        M.imr_interface.s_addr = 0;
        if (setsockopt(Rx, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&M, sizeof(M)) != 0)
        {
            printf("MCSPRAY work: IP_ADD_MEMBERSHIP failed %d\n", WSAGetLastError());
            return 0;
        }
    }
    /* a few tries: the first send to a group may be the one that makes its entry */
    {
        int Try;

        for (Try = 0; Try < 3 && !Ok; Try++)
        {
            sendto(Tx, "work", 4, 0, (struct sockaddr *)&Sa, Len);
            Got = recv(Rx, Buf, sizeof(Buf), 0);
            if (Got == 4 && !memcmp(Buf, "work", 4))
                Ok = 1;
        }
    }
    closesocket(Rx);
    closesocket(Tx);
    return Ok;
}

int
main(int argc, char **argv)
{
    WSADATA Wsa;
    SOCKET S;
    struct sockaddr_storage Sa;
    int Len, Groups, i, Failed = 0, Hops = 1, Listed0, ListedAfter, Work;
    ULONG Wait, t;
    unsigned long NpTotal, NceBytes;
    long NceLive;
    TAGROW *Rows;

    if (argc < 3 || (strcmp(argv[1], "v4") && strcmp(argv[1], "v6")))
    {
        printf("usage: mcspray v4|v6 GROUPS [WAIT_SECONDS]\n");
        return 2;
    }
    g_V6 = !strcmp(argv[1], "v6");
    Groups = atoi(argv[2]);
    Wait = argc > 3 ? (ULONG)atoi(argv[3]) : 0;
    WSAStartup(MAKEWORD(2, 2), &Wsa);

    Snapshot("before", 1);
    Listed0 = Listed();

    S = socket(g_V6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (S == INVALID_SOCKET)
    {
        printf("MCSPRAY socket failed %d\n", WSAGetLastError());
        return 2;
    }
    if (g_V6)
        setsockopt(S, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&Hops, sizeof(Hops));
    else
        setsockopt(S, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&Hops, sizeof(Hops));

    {
        DWORD t0 = GetTickCount();

        for (i = 0; i < Groups; i++)
        {
            GroupAddr(i, &Sa, &Len);
            if (sendto(S, "x", 1, 0, (struct sockaddr *)&Sa, Len) != 1)
                Failed++;
        }
        printf("MCSPRAY send: %d of %d datagrams failed, %lu ms\n", Failed, Groups, (unsigned long)(GetTickCount() - t0));
    }
    Snapshot("after-spray", 2);
    ListedAfter = Listed();

    Work = WorkCheck();
    printf("MCSPRAY work: datagram to a joined group after the spray %s\n", Work ? "arrived" : "DID NOT ARRIVE");

    for (t = 10; t <= Wait; t += 10)
    {
        char L[32];

        Sleep(10000);
        _snprintf(L, sizeof(L), "after-%lus", t);
        Snapshot(L, 0);
    }
    Snapshot("end", 2);

    /* tags with a changed live count */
    for (i = 0; (ULONG)i < g_BeforeN && g_Before; i++)
    {
        ULONG j;

        for (j = 0; j < g_AfterN && g_After; j++)
        {
            if (!strcmp(g_Before[i].Name, g_After[j].Name) && labs(g_After[j].Live - g_Before[i].Live) >= 50)
                printf("MCSPRAY tags: %s live %ld -> %ld, bytes %lu -> %lu\n", g_Before[i].Name, g_Before[i].Live,
                       g_After[j].Live, g_Before[i].Bytes, g_After[j].Bytes);
        }
    }
    (void)Rows; (void)NpTotal; (void)NceLive; (void)NceBytes;

    printf("MCSPRAY summary: listed before %d after-spray %d (bound %d)\n", Listed0, ListedAfter, LIMIT);
    printf("MCSPRAY-%s\n", (Failed == 0 && Work && ListedAfter <= LIMIT) ? "PASS" : "FAIL");
    return 0;
}
