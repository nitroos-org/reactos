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
 */

/* the Windows defaults: precedence, label, prefix (netsh interface ipv6 show prefixpolicies on the oracle) */
static const struct
{
    UCHAR Prefix[16];
    UCHAR Length;
    UCHAR Precedence;
    UCHAR Label;
} DefaultPolicy[] =
{
    { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }, 128, 50, 0 },                                 /* ::1/128 */
    { { 0 }, 0, 40, 1 },                                                                 /* ::/0 */
    { { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,0,0 }, 96, 35, 4 },                            /* ::ffff:0:0/96 */
    { { 0x20,0x02 }, 16, 30, 2 },                                                        /* 2002::/16 */
    { { 0x20,0x01 }, 32, 5, 5 },                                                         /* 2001::/32 */
    { { 0xfc }, 7, 3, 13 },                                                              /* fc00::/7 */
    { { 0xfe,0xc0 }, 10, 1, 11 },                                                        /* fec0::/10 */
    { { 0x3f,0xfe }, 16, 1, 12 },                                                        /* 3ffe::/16 */
    { { 0 }, 96, 1, 3 },                                                                 /* ::/96 */
};

VOID
AddrSortDefaultPolicy(PADDRSORT_POLICY_TABLE Table)
{
    ULONG i, k;

    RtlZeroMemory(Table, sizeof(*Table));
    for (i = 0; i < sizeof(DefaultPolicy) / sizeof(DefaultPolicy[0]); i++)
    {
        for (k = 0; k < 16; k++)
            Table->Entry[i].Prefix[k] = DefaultPolicy[i].Prefix[k];
        Table->Entry[i].Length = DefaultPolicy[i].Length;
        Table->Entry[i].Precedence = DefaultPolicy[i].Precedence;
        Table->Entry[i].Label = DefaultPolicy[i].Label;
    }
    Table->Count = i;
}

VOID
AddrSortPreferIpv4(PADDRSORT_POLICY_TABLE Table)
{
    static const UCHAR Mapped[16] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,0,0 };
    ULONG i;

    for (i = 0; i < Table->Count; i++)
    {
        if (Table->Entry[i].Length == 96 && !memcmp(Table->Entry[i].Prefix, Mapped, 16))
            Table->Entry[i].Precedence = 100;
    }
}

static
LONG
HexValue(WCHAR c)
{
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}

/* An IPv6 address in text (hex groups and one "::"), up to the end of the string or a character that is not
   part of it. Returns the number of characters used, 0 when it is not an address */
static
ULONG
ParseV6(const WCHAR *Text, ULONG Chars, UCHAR *Address)
{
    USHORT Groups[8];
    ULONG Used = 0, Count = 0, i, After;
    LONG Gap = -1, Digit;

    RtlZeroMemory(Groups, sizeof(Groups));
    if (Chars >= 2 && Text[0] == L':' && Text[1] == L':')
    {
        Gap = 0;
        Used = 2;
    }
    else if (Chars && Text[0] == L':')
        return 0;

    while (Used < Chars && HexValue(Text[Used]) >= 0)
    {
        ULONG Value = 0, Digits = 0;

        while (Used < Chars && (Digit = HexValue(Text[Used])) >= 0)
        {
            Value = Value * 16 + Digit;
            if (++Digits > 4)
                return 0;
            Used++;
        }
        if (Count >= 8)
            return 0;
        Groups[Count++] = (USHORT)Value;

        if (Used < Chars && Text[Used] == L':')
        {
            if (Used + 1 < Chars && Text[Used + 1] == L':')
            {
                if (Gap >= 0)
                    return 0;
                Gap = Count;
                Used += 2;
            }
            else
            {
                Used++;
                if (Used >= Chars || HexValue(Text[Used]) < 0)
                    return 0;
            }
        }
    }

    if (Used == 0)
        return 0;
    if (Gap < 0 ? Count != 8 : Count > 7)
        return 0;

    RtlZeroMemory(Address, 16);
    After = (Gap < 0) ? 0 : Count - Gap;
    for (i = 0; i < Count; i++)
    {
        ULONG Slot = (Gap < 0 || (LONG)i < Gap) ? i : 8 - After + (i - Gap);

        Address[Slot * 2] = (UCHAR)(Groups[i] >> 8);
        Address[Slot * 2 + 1] = (UCHAR)Groups[i];
    }
    return Used;
}

static
BOOLEAN
ParseNumber(const WCHAR *Text, ULONG Chars, ULONG *Used, ULONG *Value)
{
    ULONG i = 0, V = 0;

    while (i < Chars && Text[i] >= L'0' && Text[i] <= L'9')
    {
        V = V * 10 + (Text[i] - L'0');
        if (V > 100000)
            return FALSE;
        i++;
    }
    if (!i)
        return FALSE;
    *Used = i;
    *Value = V;
    return TRUE;
}

/* One line "prefix/length precedence label" */
static
BOOLEAN
ParseLine(const WCHAR *Line, ULONG Chars, PADDRSORT_POLICY Entry)
{
    ULONG Used, Value, Position;

    RtlZeroMemory(Entry, sizeof(*Entry));
    while (Chars && (*Line == L' ' || *Line == L'\t'))
    {
        Line++;
        Chars--;
    }
    Used = ParseV6(Line, Chars, Entry->Prefix);
    if (!Used || Used >= Chars || Line[Used] != L'/')
        return FALSE;
    Position = Used + 1;
    if (!ParseNumber(Line + Position, Chars - Position, &Used, &Value) || Value > 128)
        return FALSE;
    Entry->Length = Value;
    Position += Used;
    while (Position < Chars && (Line[Position] == L' ' || Line[Position] == L'\t'))
        Position++;
    if (!ParseNumber(Line + Position, Chars - Position, &Used, &Value))
        return FALSE;
    Entry->Precedence = Value;
    Position += Used;
    if (Position >= Chars || (Line[Position] != L' ' && Line[Position] != L'\t'))
        return FALSE;
    while (Position < Chars && (Line[Position] == L' ' || Line[Position] == L'\t'))
        Position++;
    if (!ParseNumber(Line + Position, Chars - Position, &Used, &Value))
        return FALSE;
    Entry->Label = Value;
    Position += Used;
    while (Position < Chars && (Line[Position] == L' ' || Line[Position] == L'\t'))
        Position++;
    return Position == Chars;
}

ULONG
AddrSortParsePolicy(const WCHAR *MultiSz, ULONG Chars, PADDRSORT_POLICY_TABLE Table)
{
    ADDRSORT_POLICY_TABLE Read;
    ULONG Position = 0, Start;

    RtlZeroMemory(&Read, sizeof(Read));
    while (Position < Chars && Read.Count < ADDRSORT_MAX_POLICY)
    {
        for (Start = Position; Position < Chars && MultiSz[Position]; Position++)
            ;
        if (Position == Start)
            break;      /* the empty string that ends the value */
        if (ParseLine(MultiSz + Start, Position - Start, &Read.Entry[Read.Count]))
            Read.Count++;
        Position++;
    }
    if (Read.Count)
        *Table = Read;
    return Read.Count;
}

static
ULONG
CommonPrefix(const UCHAR *A, const UCHAR *B)
{
    ULONG Bits = 0, i;

    for (i = 0; i < 16; i++)
    {
        UCHAR Diff = A[i] ^ B[i];

        if (!Diff)
        {
            Bits += 8;
            continue;
        }
        while (!(Diff & 0x80))
        {
            Bits++;
            Diff <<= 1;
        }
        break;
    }
    return Bits;
}

static
BOOLEAN
PrefixMatches(const UCHAR *Prefix, ULONG Length, const UCHAR *Address)
{
    ULONG Bytes = Length / 8, Bits = Length % 8, i;

    for (i = 0; i < Bytes; i++)
        if (Prefix[i] != Address[i])
            return FALSE;
    if (Bits && ((Prefix[Bytes] ^ Address[Bytes]) & (0xff << (8 - Bits)) & 0xff))
        return FALSE;
    return TRUE;
}

VOID
AddrSortLookupPolicy(const ADDRSORT_POLICY_TABLE *Table, const UCHAR *Address, PULONG Precedence, PULONG Label)
{
    ULONG i, Best = 0;
    BOOLEAN Found = FALSE;

    *Precedence = 0;
    *Label = 0;
    for (i = 0; i < Table->Count; i++)
    {
        if (!PrefixMatches(Table->Entry[i].Prefix, Table->Entry[i].Length, Address))
            continue;
        if (!Found || Table->Entry[i].Length > Table->Entry[Best].Length)
        {
            Found = TRUE;
            Best = i;
        }
    }
    if (Found)
    {
        *Precedence = Table->Entry[Best].Precedence;
        *Label = Table->Entry[Best].Label;
    }
}

static
BOOLEAN
IsMapped(const UCHAR *A)
{
    ULONG i;

    for (i = 0; i < 10; i++)
        if (A[i])
            return FALSE;
    return A[10] == 0xff && A[11] == 0xff;
}

static
BOOLEAN
IsLoopback(const UCHAR *A)
{
    ULONG i;

    for (i = 0; i < 15; i++)
        if (A[i])
            return FALSE;
    return A[15] == 1;
}

ULONG
AddrSortScope(const UCHAR *A)
{
    if (A[0] == 0xff)
        return A[1] & 0x0f;
    if (IsLoopback(A))
        return ADDRSORT_SCOPE_LINK;
    if (A[0] == 0xfe && (A[1] & 0xc0) == 0x80)
        return ADDRSORT_SCOPE_LINK;
    if (A[0] == 0xfe && (A[1] & 0xc0) == 0xc0)
        return ADDRSORT_SCOPE_SITE;
    if (IsMapped(A))
    {
        /* 127.0.0.0/8 and 169.254.0.0/16 */
        if (A[12] == 127 || (A[12] == 169 && A[13] == 254))
            return ADDRSORT_SCOPE_LINK;
    }
    return ADDRSORT_SCOPE_GLOBAL;
}

/* ---- source address selection (RFC 6724 section 5) ---- */

typedef struct _SOURCE_INFO
{
    const ADDRSORT_LOCAL *Local;
    ULONG Level, Label;
} SOURCE_INFO;

/* TRUE when candidate A is a better source than B for a destination of scope DestLevel and label DestLabel */
static
BOOLEAN
SourceBetter(const SOURCE_INFO *A, const SOURCE_INFO *B, const UCHAR *Dest, ULONG DestLevel, ULONG DestLabel)
{
    ULONG Ca, Cb;

    /* rule 2: appropriate scope */
    if (A->Level != B->Level)
    {
        if (A->Level < B->Level)
            return A->Level >= DestLevel;
        return B->Level < DestLevel;
    }
    /* rule 3: avoid deprecated addresses */
    if (A->Local->Deprecated != B->Local->Deprecated)
        return !A->Local->Deprecated;
    /* rule 5 (the outgoing interface) is the same for all: the candidates are the addresses of that interface */
    /* rule 6: matching label */
    if ((A->Label == DestLabel) != (B->Label == DestLabel))
        return A->Label == DestLabel;
    /* rule 7: temporary addresses (Windows prefers them by default) */
    if (A->Local->Temporary != B->Local->Temporary)
        return A->Local->Temporary;
    /* rule 8: longest matching prefix */
    Ca = CommonPrefix(A->Local->Address, Dest);
    Cb = CommonPrefix(B->Local->Address, Dest);
    return Ca > Cb;
}

static
BOOLEAN
SelectSource(const ADDRSORT_ENV *Env, PADDRSORT_ENTRY Entry, ULONG IfIndex)
{
    const ADDRSORT_LOCAL *Chosen = NULL;
    SOURCE_INFO Best, Cur;
    ULONG i, Unused;
    BOOLEAN Mapped = Entry->Mapped;

    /* rule 1: the destination is an address of this host */
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
        RtlZeroMemory(&Best, sizeof(Best));
        for (i = 0; i < Env->LocalCount; i++)
        {
            const ADDRSORT_LOCAL *L = &Env->Local[i];

            if (L->IfIndex != IfIndex || IsMapped(L->Address) != Mapped)
                continue;
            Cur.Local = L;
            Cur.Level = AddrSortScope(L->Address);
            AddrSortLookupPolicy(Env->Policy, L->Address, &Unused, &Cur.Label);
            if (!Best.Local || SourceBetter(&Cur, &Best, Entry->Address, Entry->DestLevel, Entry->DestLabel))
                Best = Cur;
        }
        Chosen = Best.Local;
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
        E->Mapped = IsMapped(E->Address);
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
        E->Common = CommonPrefix(E->Source, E->Address);
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
