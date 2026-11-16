/*
 * PROJECT:     ReactOS IPv6 address selection
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RFC 6724 pieces shared by the stack (tcpip.sys source address selection) and user mode
 *              (iphlpapi: GetBestRoute2, CreateSortedAddressPairs): the prefix policy table, scopes, the common
 *              prefix length and source address selection
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef ADDRSEL_H
#define ADDRSEL_H

/* The includer has the base types (windef.h in user mode, ntddk.h/ntdef.h in kernel mode) */

/*
 * The policy table lives in HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters, value PrefixPolicies
 * (REG_MULTI_SZ, one "prefix/length precedence label" per string, e.g. "fc00::/7 3 13"), and the volatile subkey
 * ActiveState with the same value, which wins while it exists; no value (or no valid line) = the Windows default
 * table below. Tcpip6\Parameters\DisabledComponents bit 0x20 (and Tcpip\Parameters\Ipv6Enable = 0, which stands for
 * DisabledComponents 0xFF) raises the precedence of ::ffff:0:0/96 in it.
 * User mode reads it on every use; the stack reads it at start and when IOCTL_IP6_POLICY_RELOAD asks for it
 * (iphlpapi's NitroSetPrefixPolicies does after every change), so both sort and choose with the same table.
 */
#define ADDRSEL_PARAMETERS_KEY      L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
#define ADDRSEL_POLICY_VALUE        L"PrefixPolicies"
#define ADDRSEL_ACTIVE_STATE_KEY    L"ActiveState"
/* one line is at most "<39 characters>/128 100000 100000" */
#define ADDRSEL_POLICY_LINE_CHARS   64

#define ADDRSORT_MAX_POLICY     64
#define ADDRSEL_POLICY_BUFFER_CHARS (ADDRSORT_MAX_POLICY * ADDRSEL_POLICY_LINE_CHARS + 2)

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

/* A candidate source address: an address of the outgoing interface in a usable state (preferred or deprecated;
   tentative and duplicate ones are not candidates) */
typedef struct _ADDRSEL_CANDIDATE
{
    UCHAR Address[16];
    BOOLEAN Deprecated;
    BOOLEAN Temporary;          /* RFC 8981 temporary address */
    BOOLEAN SkipAsSource;       /* never chosen, but for a destination that is the address itself (rule 1) */
} ADDRSEL_CANDIDATE, *PADDRSEL_CANDIDATE;

/* The Windows default prefix policy table (precedence, label, prefix) */
VOID AddrSortDefaultPolicy(PADDRSORT_POLICY_TABLE Table);

/* Tcpip6\Parameters\DisabledComponents bit 0x20 ("prefer IPv4 in the default prefix policy"): the IPv4-mapped prefix
   ::ffff:0:0/96 gets precedence 100. Microsoft's documentation only asks for it to rank above ::/0 (40); 100 also puts
   it above ::1/128 (50), and the value Windows uses is not documented */
VOID AddrSortPreferIpv4(PADDRSORT_POLICY_TABLE Table);

/*
 * The table from the lines of a REG_MULTI_SZ value ("prefix/length precedence label", one per string; a line
 * that does not parse is skipped). Returns the number of entries read; Table is filled with them only when it
 * is more than 0, so a value without a valid line leaves Table (the defaults) alone.
 */
ULONG AddrSortParsePolicy(const WCHAR *MultiSz, ULONG Chars, PADDRSORT_POLICY_TABLE Table);

/* An IPv6 address in text (hex groups and one "::"), up to Chars characters or the first one that is not part of
   it. Returns the number of characters used, 0 when it is not an address */
ULONG AddrSortParseAddress(const WCHAR *Text, ULONG Chars, UCHAR *Address);

/* Precedence and label of an address: the longest matching prefix of the table (0 and 0 when none matches) */
VOID AddrSortLookupPolicy(const ADDRSORT_POLICY_TABLE *Table, const UCHAR *Address, PULONG Precedence, PULONG Label);

/* RFC 6724 section 3.1 scope of an address (IPv4 ones in IPv4-mapped form). Unique local addresses are global */
ULONG AddrSortScope(const UCHAR *Address);

BOOLEAN AddrSortIsMapped(const UCHAR *Address);

/* CommonPrefixLen(S, D) of RFC 6724 section 2.2: the leading bits S and D share, at most the length of the prefix
   of S, which is 64 for every unicast IPv6 address the stack forms or is given on an Ethernet-like link (an IPv4
   source: the whole 128) */
ULONG AddrSortCommonPrefix(const UCHAR *Source, const UCHAR *Dest);

/*
 * RFC 6724 section 5: the best source for Dest among Candidates (the addresses of the interface the packet leaves
 * over, all of one family as Dest). Rules 1 (Dest itself), 2 (appropriate scope), 3 (avoid deprecated), 6 (matching
 * label, with Policy), 7 (temporary preferred, as Windows by default) and 8 (longest matching prefix); 4 and 5 have
 * nothing to choose between (no home addresses, one interface), 5.5 is not used. A link-local address that is the
 * only candidate is chosen for a destination of a larger scope too, as Windows does. Returns the index of the chosen
 * candidate, -1 when there is none.
 */
LONG AddrSortSelectSource(const ADDRSORT_POLICY_TABLE *Policy, const ADDRSEL_CANDIDATE *Candidates, ULONG Count,
                          const UCHAR *Dest);

#endif
