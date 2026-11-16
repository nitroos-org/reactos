/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Destination address ordering (RFC 6724) with the Windows prefix policy table: the engine
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef ADDRSORT_H
#define ADDRSORT_H

#include <windef.h>
#include <winbase.h>
/* the policy table, scopes and source address selection, shared with the stack (sdk/lib/addrsel) */
#include <addrsel.h>

/*
 * All addresses are 16 bytes: IPv4 ones are IPv4-mapped (::ffff:a.b.c.d), as CreateSortedAddressPairs takes
 * them. The engine knows nothing about the stack: the addresses of the host and the route lookup are given in
 * the environment, so a test can sort a fixed list against a fixed host.
 */

/* A unicast address of this host that can be used as a source (tentative and duplicate ones are left out) */
typedef struct _ADDRSORT_LOCAL
{
    UCHAR Address[16];
    ULONG IfIndex;
    BOOLEAN Deprecated;
    BOOLEAN Temporary;
    BOOLEAN Loopback;           /* the address is on the loopback interface */
    BOOLEAN SkipAsSource;       /* configured skip-as-source: the source of a packet to itself only */
} ADDRSORT_LOCAL, *PADDRSORT_LOCAL;

/* The interface a packet to Dest (scope id Scope, 0 = none) leaves over. FALSE: no route, Dest cannot be reached */
typedef BOOL (*ADDRSORT_ROUTE_FN)(PVOID Context, const UCHAR *Dest, ULONG Scope, ULONG *IfIndex);

typedef struct _ADDRSORT_ENV
{
    const ADDRSORT_POLICY_TABLE *Policy;
    const ADDRSORT_LOCAL *Local;
    ULONG LocalCount;
    ADDRSORT_ROUTE_FN Route;
    PVOID Context;
} ADDRSORT_ENV, *PADDRSORT_ENV;

typedef struct _ADDRSORT_ENTRY
{
    /* in */
    UCHAR Address[16];
    ULONG Scope;                /* scope id of a link-local destination, else 0 */
    /* out */
    ULONG Original;             /* the position in the list that was given */
    BOOLEAN Reachable;          /* a route and a source address exist */
    UCHAR Source[16];
    ULONG SourceScope;          /* scope id of a link-local source */
    /* the engine's own */
    ULONG DestLevel, SrcLevel, DestLabel, SrcLabel, Precedence, Common;
    BOOLEAN Mapped, SrcDeprecated, Own, OwnOnLoopback;
} ADDRSORT_ENTRY, *PADDRSORT_ENTRY;

/* Orders Entries (Count of them, Original and the outputs are filled in): stable, RFC 6724 section 6 */
VOID AddrSortOrder(const ADDRSORT_ENV *Env, PADDRSORT_ENTRY Entries, ULONG Count);

/* sortpairs.c: the table in force now (Tcpip6\Parameters, see addrsel.h), as the stack has it */
VOID AddrSortLoadPolicy(PADDRSORT_POLICY_TABLE Table);

#endif
