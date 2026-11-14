/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     The nonpaged receive windows of stream sockets are bounded: by a global budget (the nonpaged
 *              pool they take stays under it however many sockets there are) and charged to the process that
 *              owns the socket (its nonpaged pool quota), and given back when the sockets close.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"
#include <ndk/psfuncs.h>

#define NPW_CONNECTIONS 5000
#define NPW_WINDOW      0x2000   /* the default receive window of a stream socket */

/* The nonpaged pool AFD holds under its data buffer tag ('AfdB'), -1 when the tag is not reported */
static
LONGLONG
NpwAfdNonPagedBytes(void)
{
    ULONG Size = 0x10000, Needed, i;
    PSYSTEM_POOLTAG_INFORMATION Info;
    NTSTATUS Status;
    LONGLONG Result = -1;

    for (;;)
    {
        Info = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Info)
            return -1;
        Status = NtQuerySystemInformation(SystemPoolTagInformation, Info, Size, &Needed);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;
        HeapFree(GetProcessHeap(), 0, Info);
        Size = Needed + 0x4000;
    }
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < Info->Count; i++)
        {
            if (memcmp(Info->TagInfo[i].Tag, "AfdB", 4) == 0)
            {
                Result = (LONGLONG)Info->TagInfo[i].NonPagedUsed;
                break;
            }
        }
        if (Result < 0)
            Result = 0;
    }
    HeapFree(GetProcessHeap(), 0, Info);
    return Result;
}

static
LONGLONG
NpwQuotaNonPaged(void)
{
    VM_COUNTERS Counters;
    NTSTATUS Status;

    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessVmCounters, &Counters, sizeof(Counters), NULL);
    ok(Status == STATUS_SUCCESS, "NtQueryInformationProcess failed with %lx\n", Status);
    return NT_SUCCESS(Status) ? (LONGLONG)Counters.QuotaNonPagedPoolUsage : -1;
}

/* The budget as AfdNonPagedWindowBudget is set at load: 1/128 of the RAM, 4 MB to 64 MB */
static
LONGLONG
NpwBudget(void)
{
    SYSTEM_BASIC_INFORMATION Basic;
    LONGLONG Budget;

    if (!NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &Basic, sizeof(Basic), NULL)))
        return 0x2000000;
    Budget = (LONGLONG)Basic.NumberOfPhysicalPages * Basic.PageSize / 128;
    if (Budget < 0x400000) Budget = 0x400000;
    if (Budget > 0x4000000) Budget = 0x4000000;
    return Budget;
}

START_TEST(nonpagedwindow)
{
    WSADATA wsa;
    SOCKET lst, *cli, *srv;
    struct sockaddr_in a;
    int len = sizeof(a), r, i, n = 0, bad = 0, tries, step, sampled = 0;
    char c, rc;
    LONGLONG Tag0, Tag1, Tag2, Quota0, Quota1, Quota2, Budget, Slack = 0x80000;

    ok(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "WSAStartup failed\n");

    cli = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NPW_CONNECTIONS * sizeof(SOCKET));
    srv = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NPW_CONNECTIONS * sizeof(SOCKET));
    ok(cli && srv, "no memory\n");
    if (!cli || !srv)
        return;

    lst = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(lst != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(lst, (struct sockaddr *)&a, sizeof(a)) == 0, "bind failed %d\n", WSAGetLastError());
    getsockname(lst, (struct sockaddr *)&a, &len);
    ok(listen(lst, SOMAXCONN) == 0, "listen failed %d\n", WSAGetLastError());

    Budget = NpwBudget();
    Tag0 = NpwAfdNonPagedBytes();
    Quota0 = NpwQuotaNonPaged();

    for (i = 0; i < NPW_CONNECTIONS; i++)
    {
        cli[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (cli[i] == INVALID_SOCKET)
            break;
        if (connect(cli[i], (struct sockaddr *)&a, sizeof(a)) != 0)
        {
            closesocket(cli[i]);
            cli[i] = INVALID_SOCKET;
            break;
        }
        srv[i] = accept(lst, NULL, NULL);
        if (srv[i] == INVALID_SOCKET)
            break;
        n++;
    }
    ok(n == NPW_CONNECTIONS, "only %d of %d connections (last error %d)\n", n, NPW_CONNECTIONS, WSAGetLastError());

    Tag1 = NpwAfdNonPagedBytes();
    Quota1 = NpwQuotaNonPaged();
    trace("budget %I64d, AFD nonpaged %I64d -> %I64d, process nonpaged quota %I64d -> %I64d with %d connections\n",
          Budget, Tag0, Tag1, Quota0, Quota1, n);

    if (Tag0 >= 0 && Tag1 >= 0)
    {
        LONGLONG Growth = Tag1 - Tag0;

        ok(Growth <= Budget + Slack, "nonpaged windows took %I64d bytes, budget %I64d\n", Growth, Budget);
        /* the first sockets still get their window in nonpaged pool */
        ok(Growth >= (LONGLONG)min(Budget, 2LL * n * NPW_WINDOW) / 2,
           "nonpaged windows took only %I64d bytes, budget %I64d\n", Growth, Budget);
        /* and the windows are charged to this process, which owns every one of the sockets */
        if (Quota0 >= 0 && Quota1 >= 0)
            ok(Quota1 - Quota0 + Slack >= Growth, "quota grew by %I64d, the windows took %I64d\n", Quota1 - Quota0, Growth);
    }

    /* The charge alone, for a process that cannot read the pool tags (a 32-bit one under WoW64) */
    if (Quota0 >= 0 && Quota1 >= 0)
    {
        ok(Quota1 - Quota0 <= Budget + Slack, "quota grew by %I64d, budget %I64d\n", Quota1 - Quota0, Budget);
        ok(Quota1 - Quota0 >= (LONGLONG)min(Budget, 2LL * n * NPW_WINDOW) / 2,
           "quota grew by only %I64d, budget %I64d\n", Quota1 - Quota0, Budget);
    }

    /* The connections work, whether their window is in nonpaged or paged pool: every 8th one, from the first
     * (nonpaged windows) to the last (paged windows), carries a byte each way. All of them is too many: the
     * first send of a socket takes a 64 KB send window in paged pool, which 2200 senders already exhaust
     * on a 32-bit system of 2 GB (WSAENOBUFS), with or without this change. */
    for (i = 0; i < n; i += 8)
    {
        sampled++;
        c = (char)('a' + i % 26);
        step = 1;
        r = send(cli[i], &c, 1, 0);
        if (r == 1)
        {
            step = 2;
            rc = 0;
            r = recv(srv[i], &rc, 1, 0);
            if (r == 1 && rc == c)
            {
                step = 3;
                r = send(srv[i], &c, 1, 0);
                if (r == 1)
                {
                    step = 4;
                    rc = 0;
                    r = recv(cli[i], &rc, 1, 0);
                    if (r == 1 && rc == c)
                        continue;
                }
            }
        }
        if (bad++ == 0)
            trace("connection %d failed at step %d: result %d, last error %d\n", i, step, r, WSAGetLastError());
    }
    ok(bad == 0, "%d of %d connections failed to carry a byte each way\n", bad, sampled);

    for (i = 0; i < n; i++)
    {
        closesocket(cli[i]);
        closesocket(srv[i]);
    }
    closesocket(lst);

    /* the windows are freed when AFD closes the endpoints, which can trail the last closesocket */
    for (tries = 0; tries < 100; tries++)
    {
        Tag2 = NpwAfdNonPagedBytes();
        if (Tag2 < 0 || Tag2 <= Tag0 + Slack)
            break;
        Sleep(100);
    }
    Quota2 = NpwQuotaNonPaged();
    trace("after close: AFD nonpaged %I64d, process nonpaged quota %I64d\n", Tag2, Quota2);
    if (Tag0 >= 0 && Tag2 >= 0)
        ok(Tag2 <= Tag0 + Slack, "AFD nonpaged pool did not come back: %I64d, started at %I64d\n", Tag2, Tag0);
    if (Quota0 >= 0 && Quota2 >= 0)
        ok(Quota2 <= Quota0 + 0x10000, "nonpaged quota did not come back: %I64d, started at %I64d\n", Quota2, Quota0);

    HeapFree(GetProcessHeap(), 0, cli);
    HeapFree(GetProcessHeap(), 0, srv);
    WSACleanup();
}
