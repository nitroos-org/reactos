/*
 * PROJECT:     ReactOS IPv6 address selection
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RFC 6724 pieces shared by the stack and user mode: the prefix policy table, scopes, the common
 *              prefix length and source address selection
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Linked into tcpip.sys and into user-mode modules: base types only, no Win32 or kernel calls (memcpy and memset,
   which both have; memcmp is not exported to drivers) */
#include <windef.h>
#include <string.h>
#include <addrsel.h>

static
BOOLEAN
SameAddress(const UCHAR *A, const UCHAR *B)
{
    ULONG i;

    for (i = 0; i < 16; i++)
        if (A[i] != B[i])
            return FALSE;
    return TRUE;
}

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
    ULONG i;

    memset(Table, 0, sizeof(*Table));
    for (i = 0; i < sizeof(DefaultPolicy) / sizeof(DefaultPolicy[0]); i++)
    {
        memcpy(Table->Entry[i].Prefix, DefaultPolicy[i].Prefix, 16);
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
        if (Table->Entry[i].Length == 96 && SameAddress(Table->Entry[i].Prefix, Mapped))
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

ULONG
AddrSortParseAddress(const WCHAR *Text, ULONG Chars, UCHAR *Address)
{
    USHORT Groups[8];
    ULONG Used = 0, Count = 0, i, After;
    LONG Gap = -1, Digit;

    memset(Groups, 0, sizeof(Groups));
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

    memset(Address, 0, 16);
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

    memset(Entry, 0, sizeof(*Entry));
    while (Chars && (*Line == L' ' || *Line == L'\t'))
    {
        Line++;
        Chars--;
    }
    Used = AddrSortParseAddress(Line, Chars, Entry->Prefix);
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
    /* Table stays as it is when no line parses, so the lines go to a copy first (about 1.8 KB of stack; the
       stack parses at PASSIVE_LEVEL, outside its locks) */
    ADDRSORT_POLICY_TABLE Read;
    ULONG Position = 0, Start;

    memset(&Read, 0, sizeof(Read));
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
FullCommonPrefix(const UCHAR *A, const UCHAR *B)
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

ULONG
AddrSortCommonPrefix(const UCHAR *Source, const UCHAR *Dest)
{
    ULONG Bits = FullCommonPrefix(Source, Dest);

    if (!AddrSortIsMapped(Source) && Bits > 64)
        Bits = 64;
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

BOOLEAN
AddrSortIsMapped(const UCHAR *A)
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

static
BOOLEAN
IsLinkLocalUnicast(const UCHAR *A)
{
    return A[0] == 0xfe && (A[1] & 0xc0) == 0x80;
}

ULONG
AddrSortScope(const UCHAR *A)
{
    if (A[0] == 0xff)
        return A[1] & 0x0f;
    if (IsLoopback(A))
        return ADDRSORT_SCOPE_LINK;
    if (IsLinkLocalUnicast(A))
        return ADDRSORT_SCOPE_LINK;
    if (A[0] == 0xfe && (A[1] & 0xc0) == 0xc0)
        return ADDRSORT_SCOPE_SITE;
    if (AddrSortIsMapped(A))
    {
        /* 127.0.0.0/8 and 169.254.0.0/16 */
        if (A[12] == 127 || (A[12] == 169 && A[13] == 254))
            return ADDRSORT_SCOPE_LINK;
    }
    return ADDRSORT_SCOPE_GLOBAL;
}

/* ---- source address selection (RFC 6724 section 5) ---- */

/* The stack runs this for every datagram it sends from an unbound socket: the label and the common prefix of a
   candidate are only looked up when the rules before them leave a tie */
typedef struct _SOURCE_INFO
{
    const ADDRSEL_CANDIDATE *Candidate;
    ULONG Level, Label, Common;
    BOOLEAN HaveLabel, HaveCommon;
} SOURCE_INFO;

typedef struct _SOURCE_DEST
{
    const ADDRSORT_POLICY_TABLE *Policy;
    const UCHAR *Address;
    ULONG Level, Label;
} SOURCE_DEST;

static
ULONG
SourceLabel(SOURCE_INFO *S, const SOURCE_DEST *D)
{
    ULONG Unused;

    if (!S->HaveLabel)
    {
        AddrSortLookupPolicy(D->Policy, S->Candidate->Address, &Unused, &S->Label);
        S->HaveLabel = TRUE;
    }
    return S->Label;
}

static
ULONG
SourceCommon(SOURCE_INFO *S, const SOURCE_DEST *D)
{
    if (!S->HaveCommon)
    {
        S->Common = AddrSortCommonPrefix(S->Candidate->Address, D->Address);
        S->HaveCommon = TRUE;
    }
    return S->Common;
}

/* TRUE when candidate A is a better source than B for the destination D */
static
BOOLEAN
SourceBetter(SOURCE_INFO *A, SOURCE_INFO *B, const SOURCE_DEST *D)
{
    BOOLEAN La, Lb;

    /* rule 2: appropriate scope */
    if (A->Level != B->Level)
    {
        if (A->Level < B->Level)
            return A->Level >= D->Level;
        return B->Level < D->Level;
    }
    /* rule 3: avoid deprecated addresses */
    if (A->Candidate->Deprecated != B->Candidate->Deprecated)
        return !A->Candidate->Deprecated;
    /* rule 5 (the outgoing interface) is the same for all: the candidates are the addresses of that interface */
    /* rule 6: matching label */
    La = SourceLabel(A, D) == D->Label;
    Lb = SourceLabel(B, D) == D->Label;
    if (La != Lb)
        return La;
    /* rule 7: temporary addresses (Windows prefers them by default) */
    if (A->Candidate->Temporary != B->Candidate->Temporary)
        return A->Candidate->Temporary;
    /* rule 8: longest matching prefix */
    return SourceCommon(A, D) > SourceCommon(B, D);
}

LONG
AddrSortSelectSource(const ADDRSORT_POLICY_TABLE *Policy, const ADDRSEL_CANDIDATE *Candidates, ULONG Count,
                     const UCHAR *Dest)
{
    SOURCE_INFO Best, Cur;
    SOURCE_DEST D;
    ULONG i, Unused;
    BOOLEAN Mapped = AddrSortIsMapped(Dest);
    LONG Chosen = -1;

    /* rule 1: the destination is an address of the interface */
    for (i = 0; i < Count; i++)
    {
        if (SameAddress(Candidates[i].Address, Dest))
            return (LONG)i;
    }

    D.Policy = Policy;
    D.Address = Dest;
    D.Level = AddrSortScope(Dest);
    AddrSortLookupPolicy(Policy, Dest, &Unused, &D.Label);
    memset(&Best, 0, sizeof(Best));
    for (i = 0; i < Count; i++)
    {
        const ADDRSEL_CANDIDATE *C = &Candidates[i];

        if (C->SkipAsSource || AddrSortIsMapped(C->Address) != Mapped)
            continue;
        memset(&Cur, 0, sizeof(Cur));
        Cur.Candidate = C;
        Cur.Level = AddrSortScope(C->Address);
        if (!Best.Candidate || SourceBetter(&Cur, &Best, &D))
        {
            Best = Cur;
            Chosen = (LONG)i;
        }
    }

    /* no link-local source for a unicast destination beyond the link (the loopback address stays a source: what
       the loopback interface sends never leaves the host) */
    if (Chosen >= 0 && Dest[0] != 0xff && D.Level > ADDRSORT_SCOPE_LINK &&
        IsLinkLocalUnicast(Best.Candidate->Address))
        return -1;
    return Chosen;
}
