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

/*
 * All addresses are 16 bytes: IPv4 ones are IPv4-mapped (::ffff:a.b.c.d), as CreateSortedAddressPairs takes
 * them. The engine knows nothing about the stack: the addresses of the host and the route lookup are given in
 * the environment, so a test can sort a fixed list against a fixed host.
 */

#define ADDRSORT_MAX_POLICY     64

/* RFC 6724 scopes (the multicast scope values; unicast: 2 link-local, 5 site-local, 14 global) */
#define ADDRSORT_SCOPE_LINK     2
#define ADDRSORT_SCOPE_SITE     5
#define ADDRSORT_SCOPE_GLOBAL   14

typedef struct _ADDRSORT_POLICY
{
    UCHAR Prefix[16];
    ULONG Length;               /* bits, 0..128 */
    ULONG Precedence;
    ULONG Label;
} ADDRSORT_POLICY, *PADDRSORT_POLICY;

typedef struct _ADDRSORT_POLICY_TABLE
{
    ULONG Count;
    ADDRSORT_POLICY Entry[ADDRSORT_MAX_POLICY];
} ADDRSORT_POLICY_TABLE, *PADDRSORT_POLICY_TABLE;

/* A unicast address of this host that can be used as a source (tentative and duplicate ones are left out) */
typedef struct _ADDRSORT_LOCAL
{
    UCHAR Address[16];
    ULONG IfIndex;
    BOOLEAN Deprecated;
    BOOLEAN Temporary;
    BOOLEAN Loopback;           /* the address is on the loopback interface */
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

/* The Windows default prefix policy table (precedence, label, prefix) */
VOID AddrSortDefaultPolicy(PADDRSORT_POLICY_TABLE Table);

/* Tcpip6\Parameters\DisabledComponents bit 0x20: IPv4 before IPv6 in the table in use (the IPv4-mapped prefix
   ::ffff:0:0/96 gets precedence 100, above ::1/128 and ::/0, the change Microsoft's documentation gives for "prefer IPv4") */
VOID AddrSortPreferIpv4(PADDRSORT_POLICY_TABLE Table);

/*
 * The table from the lines of a REG_MULTI_SZ value ("prefix/length precedence label", one per string; a line
 * that does not parse is skipped). Returns the number of entries read; Table is filled with them only when it
 * is more than 0, so a value without a valid line leaves Table (the defaults) alone.
 */
ULONG AddrSortParsePolicy(const WCHAR *MultiSz, ULONG Chars, PADDRSORT_POLICY_TABLE Table);

/* Precedence and label of an address: the longest matching prefix of the table (0 and 0 when none matches) */
VOID AddrSortLookupPolicy(const ADDRSORT_POLICY_TABLE *Table, const UCHAR *Address, PULONG Precedence, PULONG Label);

ULONG AddrSortScope(const UCHAR *Address);

/* Orders Entries (Count of them, Original and the outputs are filled in): stable, RFC 6724 section 6 */
VOID AddrSortOrder(const ADDRSORT_ENV *Env, PADDRSORT_ENTRY Entries, ULONG Count);

#endif
