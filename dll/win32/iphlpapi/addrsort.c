/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Destination address ordering (RFC 6724) with the Windows prefix policy table: the engine
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "addrsort.h"

/*
 * RFC 6724 section 6, with what a Windows 10 oracle probe showed on top of it:
 *  - unreachable destinations (no route or no source address) are the last ones (rule 1; the oracle's
 *    CreateSortedAddressPairs leaves them out, the callers that want them put them back at the end);
 *  - rule 9 (longest matching prefix) is applied to IPv6 destinations only: IPv4 destinations keep their order
 *    (the oracle did not move 192.168.x or 172.16.x ahead of 10.x and 8.8.8.8 for a source of 172.30.0.2);
 *  - the oracle put the host's own address (172.30.0.2) before 127.0.0.1, and both before 8.8.8.8 and before 127.0.0.2
 *    (not an address of the host), in both input orders, which neither rule 8 (smaller scope: 127.x first) nor a
 *    stable order explains: taken as a rule of its own just before rule 8 (own address of a real interface,
 *    then own address of the loopback interface, then the rest);
 *  - rule 7 (native transport) and rule 4 (home address) have no data here and are skipped.
 * The sort is stable (rule 10 = keep the order given).
 * The policy table, the scopes, CommonPrefixLen and the source address selection are those of the stack
 * (sdk/lib/addrsel), so the source the order assumes is the one tcpip.sys sends from.
 */

/* ---- source address selection (RFC 6724 section 5, AddrSortSelectSource) ---- */

static
BOOLEAN
SelectSource(const ADDRSORT_ENV *Env, PADDRSORT_ENTRY Entry, ULONG IfIndex)
{
    const ADDRSORT_LOCAL *Chosen = NULL;
    ADDRSEL_CANDIDATE Candidates[64];
    const ADDRSORT_LOCAL *Of[64];
    ULONG i, Count = 0;
    LONG Best;

    /* rule 1: the destination is an address of this host (of any interface: such a packet stays in the host) */
    for (i = 0; i < Env->LocalCount; i++)
    {
        const ADDRSORT_LOCAL *L = &Env->Local[i];

        if (RtlCompareMemory(L->Address, Entry->Address, 16) != 16)
            continue;
        if (Entry->Scope && AddrSortScope(Entry->Address) == ADDRSORT_SCOPE_LINK && L->IfIndex != Entry->Scope &&
            !L->Loopback)
            continue;
        Chosen = L;
        break;
    }

    if (!Chosen)
    {
        /* the addresses of the outgoing interface (the environment has at most a few dozen; more are not
           candidates) */
        for (i = 0; i < Env->LocalCount && Count < RTL_NUMBER_OF(Candidates); i++)
        {
            const ADDRSORT_LOCAL *L = &Env->Local[i];

            if (L->IfIndex != IfIndex)
                continue;
            RtlCopyMemory(Candidates[Count].Address, L->Address, 16);
            Candidates[Count].Deprecated = L->Deprecated;
            Candidates[Count].Temporary = L->Temporary;
            Candidates[Count].SkipAsSource = L->SkipAsSource;
            Of[Count++] = L;
        }
        Best = AddrSortSelectSource(Env->Policy, Candidates, Count, Entry->Address);
        if (Best >= 0)
            Chosen = Of[Best];
    }

    if (!Chosen)
        return FALSE;
    RtlCopyMemory(Entry->Source, Chosen->Address, 16);
    Entry->SourceScope = (Chosen->Address[0] == 0xfe && (Chosen->Address[1] & 0xc0) == 0x80) ? Chosen->IfIndex : 0;
    Entry->SrcDeprecated = Chosen->Deprecated;
    Entry->OwnOnLoopback = Chosen->Loopback;
    return TRUE;
}

/* ---- destination ordering (RFC 6724 section 6) ---- */

static
ULONG
OwnRank(const ADDRSORT_ENTRY *E)
{
    if (!E->Own)
        return 2;
    return E->OwnOnLoopback ? 1 : 0;
}

/* < 0: A goes before B, > 0: B before A, 0: no rule decides */
static
int
CompareDestinations(const ADDRSORT_ENTRY *A, const ADDRSORT_ENTRY *B)
{
    BOOLEAN Ma, Mb;

    /* rule 1: avoid unusable destinations */
    if (A->Reachable != B->Reachable)
        return A->Reachable ? -1 : 1;
    if (!A->Reachable)
        return 0;

    /* rule 2: prefer matching scope */
    Ma = A->DestLevel == A->SrcLevel;
    Mb = B->DestLevel == B->SrcLevel;
    if (Ma != Mb)
        return Ma ? -1 : 1;

    /* rule 3: avoid deprecated addresses */
    if (A->SrcDeprecated != B->SrcDeprecated)
        return A->SrcDeprecated ? 1 : -1;

    /* rule 5: prefer matching label */
    Ma = A->DestLabel == A->SrcLabel;
    Mb = B->DestLabel == B->SrcLabel;
    if (Ma != Mb)
        return Ma ? -1 : 1;

    /* rule 6: prefer higher precedence */
    if (A->Precedence != B->Precedence)
        return A->Precedence > B->Precedence ? -1 : 1;

    /* the host's own addresses before the others, those of a real interface before those of the loopback one (oracle) */
    if (OwnRank(A) != OwnRank(B))
        return OwnRank(A) < OwnRank(B) ? -1 : 1;

    /* rule 8: prefer smaller scope */
    if (A->DestLevel != B->DestLevel)
        return A->DestLevel < B->DestLevel ? -1 : 1;

    /* rule 9: prefer the longest matching prefix, IPv6 destinations only (oracle) */
    if (!A->Mapped && !B->Mapped && A->Common != B->Common)
        return A->Common > B->Common ? -1 : 1;

    /* rule 10: leave the order unchanged */
    return 0;
}

VOID
AddrSortOrder(const ADDRSORT_ENV *Env, PADDRSORT_ENTRY Entries, ULONG Count)
{
    ULONG i, k, IfIndex;

    for (i = 0; i < Count; i++)
    {
        PADDRSORT_ENTRY E = &Entries[i];
        ULONG Dummy;

        E->Original = i;
        E->Mapped = AddrSortIsMapped(E->Address);
        E->DestLevel = AddrSortScope(E->Address);
        AddrSortLookupPolicy(Env->Policy, E->Address, &E->Precedence, &E->DestLabel);
        E->Reachable = FALSE;
        E->SrcLevel = E->SrcLabel = E->Common = 0;
        E->SrcDeprecated = E->Own = E->OwnOnLoopback = FALSE;
        RtlZeroMemory(E->Source, sizeof(E->Source));
        E->SourceScope = 0;

        IfIndex = 0;
        if (!Env->Route(Env->Context, E->Address, E->Scope, &IfIndex))
            continue;
        if (!SelectSource(Env, E, IfIndex))
            continue;

        E->Reachable = TRUE;
        E->SrcLevel = AddrSortScope(E->Source);
        AddrSortLookupPolicy(Env->Policy, E->Source, &Dummy, &E->SrcLabel);
        E->Common = AddrSortCommonPrefix(E->Source, E->Address);
        E->Own = RtlCompareMemory(E->Source, E->Address, 16) == 16;
    }

    /* stable insertion sort: the lists are short, and a comparison that is not a total order cannot hurt it */
    for (i = 1; i < Count; i++)
    {
        ADDRSORT_ENTRY Held = Entries[i];

        for (k = i; k > 0 && CompareDestinations(&Held, &Entries[k - 1]) < 0; k--)
            Entries[k] = Entries[k - 1];
        Entries[k] = Held;
    }
}
