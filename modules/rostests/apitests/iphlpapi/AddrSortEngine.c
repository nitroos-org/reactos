/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The destination ordering engine (RFC 6724 and the Windows prefix policy table) on fixed hosts and
 *              fixed address lists: no network, no stack
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <stdio.h>

/* the engine itself, compiled into the test */
#include "../../../../dll/win32/iphlpapi/addrsort.c"

#define LOOP_IF 1
#define ETH_IF  6

typedef struct
{
    ADDRSORT_LOCAL Local[8];
    ULONG LocalCount;
    BOOL V4Default;     /* any IPv4 address can be reached over ETH_IF */
    BOOL V6Default;     /* any global IPv6 address can be reached over ETH_IF (a default router) */
} HOST;

static void A6(const char *Text, UCHAR *Address)
{
    WCHAR Wide[64];
    ULONG i;

    for (i = 0; Text[i] && i < 63; i++)
        Wide[i] = Text[i];
    Wide[i] = 0;
    ok(AddrSortParseAddress(Wide, i, Address) == i, "bad test address %s\n", Text);
}

static void A4(const char *Text, UCHAR *Address)
{
    unsigned a, b, c, d;

    ok(sscanf(Text, "%u.%u.%u.%u", &a, &b, &c, &d) == 4, "bad test address %s\n", Text);
    memset(Address, 0, 16);
    Address[10] = Address[11] = 0xff;
    Address[12] = a; Address[13] = b; Address[14] = c; Address[15] = d;
}

/* "a.b.c.d" is IPv4 (mapped), anything else IPv6 */
static void Addr(const char *Text, UCHAR *Address)
{
    if (strchr(Text, ':'))
        A6(Text, Address);
    else
        A4(Text, Address);
}

static void AddLocal(HOST *H, const char *Text, ULONG If, BOOL Deprecated, BOOL Temporary)
{
    ADDRSORT_LOCAL *L = &H->Local[H->LocalCount++];

    memset(L, 0, sizeof(*L));
    Addr(Text, L->Address);
    L->IfIndex = If;
    L->Deprecated = Deprecated;
    L->Temporary = Temporary;
    L->Loopback = (If == LOOP_IF);
}

static BOOL Route(PVOID Context, const UCHAR *Dest, ULONG Scope, ULONG *IfIndex)
{
    HOST *H = Context;
    ULONG i;
    BOOL Mapped = !memcmp(Dest, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);

    /* an address of this host */
    for (i = 0; i < H->LocalCount; i++)
        if (!memcmp(H->Local[i].Address, Dest, 16))
        {
            *IfIndex = H->Local[i].IfIndex;
            return TRUE;
        }
    if (Mapped)
    {
        if (Dest[12] == 127)
        {
            *IfIndex = LOOP_IF;
            return TRUE;
        }
        *IfIndex = ETH_IF;
        return H->V4Default;
    }
    if (Dest[0] == 0xfe && (Dest[1] & 0xc0) == 0x80)
    {
        *IfIndex = Scope;
        return Scope == ETH_IF;
    }
    *IfIndex = ETH_IF;
    return H->V6Default;
}

static void Sort(HOST *H, const ADDRSORT_POLICY_TABLE *Policy, const char **Dest, ULONG Count, ADDRSORT_ENTRY *Out)
{
    ADDRSORT_ENV Env;
    ULONG i;

    Env.Policy = Policy;
    Env.Local = H->Local;
    Env.LocalCount = H->LocalCount;
    Env.Route = Route;
    Env.Context = H;
    memset(Out, 0, Count * sizeof(*Out));
    for (i = 0; i < Count; i++)
    {
        char Copy[64], *Pct;

        strcpy(Copy, Dest[i]);
        Pct = strchr(Copy, '%');
        if (Pct)
        {
            *Pct = 0;
            Out[i].Scope = atoi(Pct + 1);
        }
        Addr(Copy, Out[i].Address);
    }
    AddrSortOrder(&Env, Out, Count);
}

/* the sorted list must be Expect[0..N-1] (indexes into Dest); Reach = how many are reachable (the first ones) */
static void Check(const char *Label, HOST *H, const ADDRSORT_POLICY_TABLE *Policy, const char **Dest, ULONG Count,
                  const ULONG *Expect, ULONG Reach)
{
    ADDRSORT_ENTRY Out[32];
    ULONG i, Got = 0;

    Sort(H, Policy, Dest, Count, Out);
    for (i = 0; i < Count; i++)
    {
        if (Out[i].Reachable)
            Got++;
        ok(Out[i].Original == Expect[i], "%s: position %lu holds %s, expected %s\n", Label, i,
           Dest[Out[i].Original], Dest[Expect[i]]);
    }
    ok(Got == Reach, "%s: %lu reachable, expected %lu\n", Label, Got, Reach);
    for (i = 0; i < Count; i++)
        ok(Out[i].Reachable == (i < Reach), "%s: position %lu reachable = %d\n", Label, i, Out[i].Reachable);
}

static void CheckSource(const char *Label, HOST *H, const ADDRSORT_POLICY_TABLE *Policy, const char *Dest,
                        const char *Source)
{
    ADDRSORT_ENTRY Out[1];
    UCHAR Wanted[16];
    const char *List[1];

    List[0] = Dest;
    Sort(H, Policy, List, 1, Out);
    Addr(Source, Wanted);
    ok(Out[0].Reachable, "%s: %s is not reachable\n", Label, Dest);
    ok(!memcmp(Out[0].Source, Wanted, 16), "%s: source of %s is not %s\n", Label, Dest, Source);
}

static void TestPolicy(void)
{
    ADDRSORT_POLICY_TABLE Table, Parsed;
    ULONG P, L, N;
    static const struct { const char *Addr; ULONG Prec, Label; } Cases[] =
    {
        { "::1", 50, 0 }, { "2001:db8::1", 40, 1 }, { "2606:4700::1", 40, 1 }, { "1.2.3.4", 35, 4 },
        { "2002:808:808::1", 30, 2 }, { "2001::1", 5, 5 }, { "fd00::1", 3, 13 }, { "fc00::9", 3, 13 },
        { "fec0::1", 1, 11 }, { "3ffe::1", 1, 12 }, { "::1.2.3.4", 1, 3 }, { "fe80::1", 40, 1 }, { "ff02::1", 40, 1 },
    };
    /* "::1.2.3.4" is IPv4-compatible text: written as hex groups */
    ULONG i;
    static const WCHAR Lines[] = L"fc00::/7 3 13\0 2001:db8::/32  7 99 \0nonsense\0::/0 1 1\0fe80::/10 4\0::1/129 1 1\0\0";
    static const WCHAR Bad[] = L"nonsense\0::/0 x 1\0\0";

    AddrSortDefaultPolicy(&Table);
    ok(Table.Count == 9, "default table has %lu entries\n", Table.Count);
    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        UCHAR A[16];
        const char *Text = Cases[i].Addr;

        if (!strcmp(Text, "::1.2.3.4"))
            Text = "::102:304";
        Addr(Text, A);
        AddrSortLookupPolicy(&Table, A, &P, &L);
        ok(P == Cases[i].Prec && L == Cases[i].Label, "%s: precedence %lu label %lu, expected %lu %lu\n",
           Cases[i].Addr, P, L, Cases[i].Prec, Cases[i].Label);
    }

    Parsed = Table;
    N = AddrSortParsePolicy(Lines, RTL_NUMBER_OF(Lines), &Parsed);
    ok(N == 3, "parsed %lu lines, expected 3 (two lines do not parse)\n", N);
    ok(Parsed.Count == 3, "table has %lu entries\n", Parsed.Count);
    {
        UCHAR A[16];

        A6("2001:db8::5", A);
        AddrSortLookupPolicy(&Parsed, A, &P, &L);
        ok(P == 7 && L == 99, "parsed entry: %lu %lu\n", P, L);
        A6("fd00::1", A);
        AddrSortLookupPolicy(&Parsed, A, &P, &L);
        ok(P == 3 && L == 13, "parsed fc00::/7: %lu %lu\n", P, L);
        A6("2606::1", A);
        AddrSortLookupPolicy(&Parsed, A, &P, &L);
        ok(P == 1 && L == 1, "parsed ::/0: %lu %lu\n", P, L);
    }

    Parsed = Table;
    N = AddrSortParsePolicy(Bad, RTL_NUMBER_OF(Bad), &Parsed);
    ok(N == 0, "parsed %lu lines of an invalid value\n", N);
    ok(Parsed.Count == 9, "an invalid value changed the table (%lu entries)\n", Parsed.Count);
    N = AddrSortParsePolicy(L"\0", 1, &Parsed);
    ok(N == 0 && Parsed.Count == 9, "an empty value changed the table\n");
}

/* The lines Windows' netsh shows for the IPv4-mapped and IPv4-compatible prefixes have a dotted IPv4 tail */
static void TestPolicyDottedTail(void)
{
    static const WCHAR Dotted[] = L"::ffff:0.0.0.0/96 60 4\0::/96 2 3\0::ffff:1.2.3.4/128 9 8\0\0";
    static const struct { const WCHAR *Text; ULONG Used; UCHAR Tail[4]; UCHAR Head; } Addresses[] =
    {
        { L"::ffff:1.2.3.4", 14, { 1, 2, 3, 4 }, 0xff }, { L"::1.2.3.4", 9, { 1, 2, 3, 4 }, 0 },
        { L"0:0:0:0:0:ffff:255.255.255.255/96", 30, { 255, 255, 255, 255 }, 0xff },
    };
    static const WCHAR *Invalid[] =
    {
        L"::ffff:1.2.3", L"::ffff:1.2.3.4.5", L"::ffff:256.1.1.1", L"::ffff:1.2.3.", L"::ffff:1..3.4", L"1.2.3.4",
        L"1:2:3:4:5:6:7:1.2.3.4", L"::ffff:0001.2.3.4", L"::ffff:a.2.3.4", L"1::2::1.2.3.4",
    };
    ADDRSORT_POLICY_TABLE Table, Parsed;
    UCHAR A[16];
    ULONG i, N, P, L;

    for (i = 0; i < RTL_NUMBER_OF(Addresses); i++)
    {
        memset(A, 0x55, sizeof(A));
        N = AddrSortParseAddress(Addresses[i].Text, (ULONG)wcslen(Addresses[i].Text), A);
        ok(N == Addresses[i].Used, "dotted tail %lu: used %lu, expected %lu\n", i, N, Addresses[i].Used);
        ok(!memcmp(A + 12, Addresses[i].Tail, 4) && A[10] == Addresses[i].Head && A[11] == Addresses[i].Head,
           "dotted tail %lu: parsed wrong\n", i);
    }
    for (i = 0; i < RTL_NUMBER_OF(Invalid); i++)
    {
        N = AddrSortParseAddress(Invalid[i], (ULONG)wcslen(Invalid[i]), A);
        ok(N == 0, "invalid dotted tail %lu accepted (%lu characters)\n", i, N);
    }

    AddrSortDefaultPolicy(&Table);
    Parsed = Table;
    N = AddrSortParsePolicy(Dotted, RTL_NUMBER_OF(Dotted), &Parsed);
    ok(N == 3, "dotted policy lines: %lu parsed of 3\n", N);
    A6("::ffff:9.9.9.9", A);
    AddrSortLookupPolicy(&Parsed, A, &P, &L);
    ok(P == 60 && L == 4, "::ffff:0.0.0.0/96: %lu %lu\n", P, L);
    A6("::ffff:1.2.3.4", A);
    AddrSortLookupPolicy(&Parsed, A, &P, &L);
    ok(P == 9 && L == 8, "::ffff:1.2.3.4/128: %lu %lu\n", P, L);
    A6("::7", A);
    AddrSortLookupPolicy(&Parsed, A, &P, &L);
    ok(P == 2 && L == 3, "::/96: %lu %lu\n", P, L);
}

/* A value with more than 64 lines is not used as a whole (the callers log it); 64 are */
static void TestPolicyTooMany(void)
{
    static WCHAR Value[70 * 32 + 1];
    ADDRSORT_POLICY_TABLE Table, Parsed;
    ULONG Lines, N, Length;

    AddrSortDefaultPolicy(&Table);
    for (Lines = 64; Lines <= 65; Lines++)
    {
        ULONG i, Position = 0;

        for (i = 0; i < Lines; i++)
        {
            WCHAR Line[32];

            _snwprintf(Line, RTL_NUMBER_OF(Line), L"2001:db8:%lx::/48 %lu 7", i + 1, i + 1);
            Line[RTL_NUMBER_OF(Line) - 1] = 0;
            Length = (ULONG)wcslen(Line) + 1;
            memcpy(Value + Position, Line, Length * sizeof(WCHAR));
            Position += Length;
        }
        Value[Position++] = 0;
        Parsed = Table;
        N = AddrSortParsePolicy(Value, Position, &Parsed);
        if (Lines == 64)
            ok(N == 64 && Parsed.Count == 64, "64 lines: %lu parsed, %lu in the table\n", N, Parsed.Count);
        else
            ok(N == ADDRSORT_POLICY_TOO_MANY && Parsed.Count == Table.Count && !memcmp(&Parsed, &Table, sizeof(Table)),
               "65 lines: %lu parsed, table changed or not\n", N);
    }
    /* invalid lines do not count towards the limit */
    {
        ULONG Position = 0, i;

        for (i = 0; i < 100; i++)
        {
            memcpy(Value + Position, L"nonsense", 9 * sizeof(WCHAR));
            Position += 9;
            if (Position > RTL_NUMBER_OF(Value) - 40)
                break;
        }
        memcpy(Value + Position, L"fc00::/7 3 13\0", 15 * sizeof(WCHAR));
        Position += 15;
        Parsed = Table;
        N = AddrSortParsePolicy(Value, Position, &Parsed);
        ok(N == 1, "many invalid lines and one valid: %lu\n", N);
    }
}

static void TestScopes(void)
{
    static const struct { const char *Addr; ULONG Scope; } Cases[] =
    {
        { "::1", 2 }, { "127.0.0.1", 2 }, { "127.5.5.5", 2 }, { "169.254.1.1", 2 }, { "fe80::1", 2 },
        { "fec0::1", 5 }, { "fd00::1", 14 }, { "2001:db8::1", 14 }, { "10.1.2.3", 14 }, { "192.168.1.1", 14 },
        { "8.8.8.8", 14 }, { "ff02::1", 2 }, { "ff05::1", 5 }, { "ff0e::1", 14 }, { "ff01::1", 1 },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        UCHAR A[16];

        Addr(Cases[i].Addr, A);
        ok(AddrSortScope(A) == Cases[i].Scope, "scope of %s is %lu, expected %lu\n", Cases[i].Addr,
           AddrSortScope(A), Cases[i].Scope);
    }
}

/* The sorted list: the first Expect addresses (reachable, in this order), then the others unreachable */
static void CheckList(const char *Label, HOST *H, const ADDRSORT_POLICY_TABLE *Policy, const char **Dest, ULONG Count,
                      const char **Expect, ULONG Reach)
{
    ADDRSORT_ENTRY Out[32];
    ULONG i;

    Sort(H, Policy, Dest, Count, Out);
    for (i = 0; i < Count; i++)
    {
        if (i < Reach)
        {
            UCHAR Want[16];
            char Copy[64], *Pct;

            strcpy(Copy, Expect[i]);
            Pct = strchr(Copy, '%');
            if (Pct)
                *Pct = 0;
            Addr(Copy, Want);
            ok(Out[i].Reachable && !memcmp(Out[i].Address, Want, 16), "%s: position %lu is not %s (reachable %d)\n",
               Label, i, Expect[i], Out[i].Reachable);
        }
        else
            ok(!Out[i].Reachable, "%s: position %lu is reachable\n", Label, i);
    }
}

/* The host and the lists of the Windows 10 oracle probe (CreateSortedAddressPairs): the order it answered */
static void TestOracle(const ADDRSORT_POLICY_TABLE *Policy)
{
    HOST H;
    static const char *L1[] = { "8.8.8.8", "2001:db8::1", "::1", "127.0.0.1", "172.30.0.2", "fe80::1%1", "fc00::1",
                                "fec0::1", "2002:808:808::1", "3ffe::1", "2001::1", "::102:304", "169.254.1.1",
                                "10.1.2.3", "192.168.1.1" };
    static const char *O1[] = { "::1", "172.30.0.2", "127.0.0.1", "8.8.8.8", "10.1.2.3", "192.168.1.1", "169.254.1.1" };
    static const char *L1r[] = { "192.168.1.1", "10.1.2.3", "169.254.1.1", "::102:304", "2001::1", "3ffe::1",
                                 "2002:808:808::1", "fec0::1", "fc00::1", "fe80::1%1", "172.30.0.2", "127.0.0.1",
                                 "::1", "2001:db8::1", "8.8.8.8" };
    static const char *O1r[] = { "::1", "172.30.0.2", "127.0.0.1", "192.168.1.1", "10.1.2.3", "8.8.8.8", "169.254.1.1" };
    static const char *L2[] = { "10.1.1.1", "8.8.8.8", "192.168.55.5", "10.1.1.2", "172.16.5.5", "1.1.1.1" };
    static const char *L2r[] = { "1.1.1.1", "172.16.5.5", "10.1.1.2", "192.168.55.5", "8.8.8.8", "10.1.1.1" };
    static const char *L3[] = { "1.1.1.1", "2606:4700::1111", "2a00:1450::1", "9.9.9.9" };
    static const char *O3[] = { "1.1.1.1", "9.9.9.9" };
    static const char *L3r[] = { "9.9.9.9", "2a00:1450::1", "2606:4700::1111", "1.1.1.1" };
    static const char *O3r[] = { "9.9.9.9", "1.1.1.1" };
    static const char *L4[] = { "::1", "127.0.0.1", "::ffff:7f00:1", "127.0.0.2" };
    static const char *L5[] = { "fe80::7dde:44db:e91b:7b3e%6", "1.1.1.1" };
    static const char *L5r[] = { "1.1.1.1", "fe80::7dde:44db:e91b:7b3e%6" };

    memset(&H, 0, sizeof(H));
    AddLocal(&H, "::1", LOOP_IF, FALSE, FALSE);
    AddLocal(&H, "127.0.0.1", LOOP_IF, FALSE, FALSE);
    AddLocal(&H, "fe80::7dde:44db:e91b:7b3e", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "172.30.0.2", ETH_IF, FALSE, FALSE);
    H.V4Default = TRUE;
    H.V6Default = FALSE;

    /* 7 of the 15 can be reached; the oracle answered exactly these, in this order */
    CheckList("oracle mixed list", &H, Policy, L1, 15, O1, 7);
    CheckList("oracle mixed list, reversed input", &H, Policy, L1r, 15, O1r, 7);
    /* IPv4 destinations keep the order they were given (no longest-prefix rule for them) */
    CheckList("oracle IPv4 only", &H, Policy, L2, 6, L2, 6);
    CheckList("oracle IPv4 only, reversed input", &H, Policy, L2r, 6, L2r, 6);
    /* global IPv6 has no route there: left out; IPv4 keeps its order */
    CheckList("oracle global v6 + v4", &H, Policy, L3, 4, O3, 2);
    CheckList("oracle global v6 + v4, reversed input", &H, Policy, L3r, 4, O3r, 2);
    CheckList("oracle loopbacks", &H, Policy, L4, 4, L4, 4);
    CheckList("oracle link-local + v4", &H, Policy, L5, 2, L5, 2);
    CheckList("oracle link-local + v4, reversed input", &H, Policy, L5r, 2, L5, 2);

    CheckSource("oracle", &H, Policy, "8.8.8.8", "172.30.0.2");
    CheckSource("oracle", &H, Policy, "127.0.0.2", "127.0.0.1");
    CheckSource("oracle", &H, Policy, "::1", "::1");
    CheckSource("oracle", &H, Policy, "fe80::7dde:44db:e91b:7b3e%6", "fe80::7dde:44db:e91b:7b3e");
}

static void TestHosts(const ADDRSORT_POLICY_TABLE *Policy)
{
    HOST H;

    /* dual stack: GUA + ULA + link-local + IPv4 */
    memset(&H, 0, sizeof(H));
    AddLocal(&H, "::1", LOOP_IF, FALSE, FALSE);
    AddLocal(&H, "127.0.0.1", LOOP_IF, FALSE, FALSE);
    AddLocal(&H, "fe80::a", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "2001:db8:1::10", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "fd00:aa::10", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "192.0.2.10", ETH_IF, FALSE, FALSE);
    H.V4Default = H.V6Default = TRUE;
    {
        static const char *Mix[] = { "192.0.2.99", "2001:db8:2::1" };
        static const ULONG E[] = { 1, 0 };
        static const char *Mix2[] = { "2001:db8:2::1", "192.0.2.99" };
        static const ULONG E2[] = { 0, 1 };
        /* GUA before ULA (precedence 40 against 3); the ULA one has a ULA source (label 13 = 13) */
        static const char *Ula[] = { "fd00:bb::1", "2001:db8:3::1" };
        static const ULONG EU[] = { 1, 0 };
        /* rule 9: the destination that shares more bits with its source first, whatever the input order */
        static const char *Pre[] = { "2001:db8:77::1", "2001:db8:1::99" };
        static const ULONG EP[] = { 1, 0 };
        static const char *Pre2[] = { "2001:db8:1::99", "2001:db8:77::1" };
        static const ULONG EP2[] = { 0, 1 };
        /* the policy label decides before precedence: 6to4 (label 2) has a GUA source (label 1): after IPv4 (35)?
           no: rule 5 is matching label, so the 6to4 destination (mismatch) goes after IPv4 (match) */
        static const char *Sx[] = { "2002:c000:263::1", "192.0.2.99" };
        static const ULONG ES[] = { 1, 0 };

        Check("dual stack v6 before v4", &H, Policy, Mix, 2, E, 2);
        Check("dual stack v6 before v4, other input order", &H, Policy, Mix2, 2, E2, 2);
        Check("GUA before ULA", &H, Policy, Ula, 2, EU, 2);
        Check("rule 9 (given 2nd)", &H, Policy, Pre, 2, EP, 2);
        Check("rule 9 (given 1st)", &H, Policy, Pre2, 2, EP2, 2);
        Check("label mismatch after IPv4", &H, Policy, Sx, 2, ES, 2);
        CheckSource("dual stack", &H, Policy, "fd00:bb::1", "fd00:aa::10");
        CheckSource("dual stack", &H, Policy, "2001:db8:5::1", "2001:db8:1::10");
        CheckSource("dual stack", &H, Policy, "fe80::99%6", "fe80::a");
        CheckSource("dual stack", &H, Policy, "192.0.2.77", "192.0.2.10");
        CheckSource("dual stack own address", &H, Policy, "2001:db8:1::10", "2001:db8:1::10");
    }

    /* ULA only, with a default router: a GUA destination has a ULA source (label mismatch): after IPv4 */
    memset(&H, 0, sizeof(H));
    AddLocal(&H, "::1", LOOP_IF, FALSE, FALSE);
    AddLocal(&H, "fe80::b", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "fd00:aa::20", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "10.0.0.5", ETH_IF, FALSE, FALSE);
    H.V4Default = H.V6Default = TRUE;
    {
        static const char *L[] = { "2001:db8::1", "192.0.2.7" };
        static const ULONG E[] = { 1, 0 };
        static const char *U[] = { "fd00:bb::1", "192.0.2.7" };
        static const ULONG EU[] = { 1, 0 };

        Check("ULA-only host: GUA name after IPv4", &H, Policy, L, 2, E, 2);
        /* a ULA destination from a ULA source: IPv6 (precedence 3) is below IPv4 (35) */
        Check("ULA-only host: ULA destination", &H, Policy, U, 2, EU, 2);
        CheckSource("ULA-only host", &H, Policy, "2001:db8::1", "fd00:aa::20");
    }

    /* IPv4 only (the IPv6 address is link-local, no router): a global IPv6 destination cannot be reached */
    memset(&H, 0, sizeof(H));
    AddLocal(&H, "::1", LOOP_IF, FALSE, FALSE);
    AddLocal(&H, "fe80::c", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "10.0.0.6", ETH_IF, FALSE, FALSE);
    H.V4Default = TRUE;
    H.V6Default = FALSE;
    {
        static const char *L[] = { "2001:db8::1", "192.0.2.7" };
        static const ULONG E[] = { 1, 0 };

        Check("IPv4-only host", &H, Policy, L, 2, E, 1);
    }

    /* link-local IPv6 only, with a default router: the global destination is reachable from the link-local
       address (Windows sends from it); rule 2 puts the IPv4 destination, whose source has the same scope, first */
    H.V6Default = TRUE;
    {
        static const char *L[] = { "2001:db8::1", "192.0.2.7" };
        static const ULONG E[] = { 1, 0 };

        Check("link-local-only host", &H, Policy, L, 2, E, 2);
    }

    /* source selection: deprecated, temporary, longest prefix */
    memset(&H, 0, sizeof(H));
    AddLocal(&H, "fe80::d", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "2001:db8:2::10", ETH_IF, TRUE, FALSE);        /* deprecated, but the longest match */
    AddLocal(&H, "2001:db8:1::10", ETH_IF, FALSE, FALSE);
    H.V6Default = TRUE;
    CheckSource("deprecated source avoided", &H, Policy, "2001:db8:2::99", "2001:db8:1::10");

    memset(&H, 0, sizeof(H));
    AddLocal(&H, "fe80::d", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "2001:db8:1::10", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "2001:db8:1:0:aaaa::1", ETH_IF, FALSE, TRUE);  /* temporary */
    H.V6Default = TRUE;
    CheckSource("temporary source preferred", &H, Policy, "2001:db8:1::99", "2001:db8:1:0:aaaa::1");

    memset(&H, 0, sizeof(H));
    AddLocal(&H, "fe80::d", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "2001:db8:1::10", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "2001:db8:2::10", ETH_IF, FALSE, FALSE);
    H.V6Default = TRUE;
    CheckSource("longest prefix source", &H, Policy, "2001:db8:2::99", "2001:db8:2::10");
    CheckSource("longest prefix source (other)", &H, Policy, "2001:db8:1::99", "2001:db8:1::10");
    /* a link-local destination takes the link-local source, not a global one */
    CheckSource("link-local destination", &H, Policy, "fe80::77%6", "fe80::d");
}

/* the table is the thing that decides: another table, another order */
static void TestOtherPolicy(void)
{
    ADDRSORT_POLICY_TABLE Table;
    HOST H;
    static const char *L[] = { "192.0.2.99", "2001:db8:2::1" };
    static const ULONG E[] = { 0, 1 };
    static const WCHAR Prefer4[] = L"::ffff:0:0/96 100 4\0::/0 40 1\0\0";

    memset(&H, 0, sizeof(H));
    AddLocal(&H, "fe80::a", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "2001:db8:1::10", ETH_IF, FALSE, FALSE);
    AddLocal(&H, "192.0.2.10", ETH_IF, FALSE, FALSE);
    H.V4Default = H.V6Default = TRUE;

    AddrSortDefaultPolicy(&Table);
    ok(AddrSortParsePolicy(Prefer4, RTL_NUMBER_OF(Prefer4), &Table) == 2, "policy lines\n");
    Check("IPv4 preferred by the table", &H, &Table, L, 2, E, 2);

    /* DisabledComponents 0x20: the default table with the mapped prefix raised, the same order */
    AddrSortDefaultPolicy(&Table);
    AddrSortPreferIpv4(&Table);
    Check("IPv4 preferred by DisabledComponents", &H, &Table, L, 2, E, 2);
}

/*
 * The source address selection of the stack itself (AddrSortSelectSource, the function tcpip.sys calls for every
 * IPv6 packet it sends, and GetBestRoute2 for its source answer): the addresses of one interface, each "address"
 * or "address/flags" with d = deprecated, t = temporary, s = skip-as-source. Expect: the index of the source, -1
 * none. 3fff::/20 (RFC 9637) stands for a global prefix of label 1.
 */
static void CheckPick(const char *Label, const ADDRSORT_POLICY_TABLE *Policy, const char **Addrs, ULONG Count,
                      const char *Dest, LONG Expect)
{
    ADDRSEL_CANDIDATE C[16];
    UCHAR D[16];
    ULONG i;
    LONG Got;

    for (i = 0; i < Count; i++)
    {
        char Copy[64], *Flags;

        strcpy(Copy, Addrs[i]);
        memset(&C[i], 0, sizeof(C[i]));
        Flags = strchr(Copy, '/');
        if (Flags)
        {
            *Flags++ = 0;
            C[i].Deprecated = strchr(Flags, 'd') != NULL;
            C[i].Temporary = strchr(Flags, 't') != NULL;
            C[i].SkipAsSource = strchr(Flags, 's') != NULL;
        }
        Addr(Copy, C[i].Address);
    }
    Addr(Dest, D);
    Got = AddrSortSelectSource(Policy, C, Count, D);
    ok(Got == Expect, "%s: source for %s is %ld (%s), expected %ld (%s)\n", Label, Dest, Got,
       Got >= 0 ? Addrs[Got] : "none", Expect, Expect >= 0 ? Addrs[Expect] : "none");
}

static void TestSourceRules(const ADDRSORT_POLICY_TABLE *Policy)
{
    UCHAR A[16], B[16];

    /* a new on-link prefix: the source of a packet into it is its address, not the older prefix's */
    {
        static const char *L[] = { "fe80::10", "3fff:a1::10", "3fff:b1::10" };

        CheckPick("new prefix", Policy, L, 3, "3fff:b1::1", 2);
        CheckPick("old prefix", Policy, L, 3, "3fff:a1::1", 1);
    }
    /* rule 3 before rule 8: a deprecated address loses even with the longer match */
    {
        static const char *L[] = { "fe80::10", "3fff:a1::10/d", "3fff:b1::10" };
        static const char *P[] = { "fe80::10", "3fff:a1::10", "3fff:b1::10" };

        CheckPick("deprecated avoided", Policy, L, 3, "3fff:a1:ff::1", 2);
        CheckPick("deprecated avoided, on its own prefix", Policy, L, 3, "3fff:a1::1", 2);
        CheckPick("both preferred: longest match", Policy, P, 3, "3fff:a1:ff::1", 1);
        /* only deprecated ones: still a source */
        {
            static const char *O[] = { "fe80::10", "3fff:a1::10/d" };

            CheckPick("only a deprecated global", Policy, O, 2, "3fff:ff::1", 1);
        }
    }
    /* rule 6: the matching label wins over a longer match (2a00:: shares 4 bits with 2002::, 3 with 3fff::) */
    {
        static const char *L[] = { "fe80::10", "2002:c000:201::10", "3fff:a1::10" };

        CheckPick("label: global destination, global source", Policy, L, 3, "2a00:ff::1", 2);
        CheckPick("label: 6to4 destination, 6to4 source", Policy, L, 3, "2002:abcd::1", 1);
    }
    /* GUA and ULA on one interface: each destination takes the source of its kind */
    {
        static const char *L[] = { "fe80::10", "fd00:a1::10", "3fff:a1::10" };
        static const char *R[] = { "fe80::10", "3fff:a1::10", "fd00:a1::10" };
        static const char *Dep[] = { "fe80::10", "fd00:a1::10", "3fff:a1::10/d" };

        CheckPick("ULA destination", Policy, L, 3, "fd00:ff::1", 1);
        CheckPick("GUA destination", Policy, L, 3, "3fff:ff::1", 2);
        CheckPick("ULA destination, other order", Policy, R, 3, "fd00:ff::1", 2);
        CheckPick("GUA destination, other order", Policy, R, 3, "2a00::1", 1);
        /* a ULA is of global scope (RFC 6724 3.1): a preferred ULA before a deprecated GUA, rule 3 before rule 6 */
        CheckPick("deprecated GUA, preferred ULA", Policy, Dep, 3, "3fff:ff::1", 1);
    }
    /* rule 8: the longest matching prefix, not only "same /64 or not" */
    {
        static const char *L[] = { "fe80::10", "3fff:a1:0:1::10", "3fff:a1:0:2::10" };
        static const char *R[] = { "fe80::10", "3fff:a1:0:2::10", "3fff:a1:0:1::10" };

        CheckPick("longest prefix (63 bits against 62)", Policy, L, 3, "3fff:a1:0:3::1", 2);
        CheckPick("longest prefix, other order", Policy, R, 3, "3fff:a1:0:3::1", 1);
        /* 3fff:a1:0:0:ff::1 shares 63 bits with 3fff:a1:0:1::/64, 62 with 3fff:a1:0:2::/64 */
        CheckPick("longest prefix (more bits of the first)", Policy, L, 3, "3fff:a1:0:0:ff::1", 1);
        CheckPick("longest prefix (more bits of the first), other order", Policy, R, 3, "3fff:a1:0:0:ff::1", 2);
    }
    /* CommonPrefixLen stops at the /64 of the source: the interface identifier does not decide */
    {
        static const char *L[] = { "fe80::10", "3fff:a1:0:1:8000::1", "3fff:a1:0:1::10" };

        CheckPick("prefix length capped at 64", Policy, L, 3, "3fff:a1:0:1::11", 1);
        Addr("3fff:a1:0:1::10", A);
        Addr("3fff:a1:0:1::11", B);
        ok(AddrSortCommonPrefix(A, B) == 64, "CommonPrefixLen %lu\n", AddrSortCommonPrefix(A, B));
        Addr("3fff:a1:0:3::1", B);
        ok(AddrSortCommonPrefix(A, B) == 62, "CommonPrefixLen %lu\n", AddrSortCommonPrefix(A, B));
        Addr("10.1.2.3", A);
        Addr("10.1.2.4", B);
        ok(AddrSortCommonPrefix(A, B) == 125, "CommonPrefixLen (IPv4) %lu\n", AddrSortCommonPrefix(A, B));
    }
    /* rule 7: a temporary address before a public one of the same state; rule 3 still comes first */
    {
        static const char *L[] = { "fe80::10", "3fff:a1::10", "3fff:a1::9d3c:11ff:fe01:7/t" };
        static const char *D[] = { "fe80::10", "3fff:a1::10", "3fff:a1::9d3c:11ff:fe01:7/td" };

        CheckPick("temporary preferred", Policy, L, 3, "3fff:ff::1", 2);
        CheckPick("temporary preferred, on-link", Policy, L, 3, "3fff:a1::99", 2);
        CheckPick("deprecated temporary loses", Policy, D, 3, "3fff:ff::1", 1);
    }
    /* rule 2: scope */
    {
        static const char *L[] = { "3fff:a1::10", "fe80::10", "fec0::10" };

        CheckPick("link-local destination", Policy, L, 3, "fe80::99", 1);
        CheckPick("site-local destination", Policy, L, 3, "fec0::99", 2);
        CheckPick("global destination", Policy, L, 3, "3fff:ff::1", 0);
        CheckPick("link-scope multicast", Policy, L, 3, "ff02::1", 1);
        CheckPick("global multicast", Policy, L, 3, "ff0e::1", 0);
    }
    /* link-local only: the link-local address is the source for every destination (Windows sends from it) */
    {
        static const char *L[] = { "fe80::10" };
        static const char *Loop[] = { "::1" };

        CheckPick("link-local only, global destination", Policy, L, 1, "3fff:ff::1", 0);
        CheckPick("link-local only, ULA destination", Policy, L, 1, "fd00::1", 0);
        CheckPick("link-local only, site-local destination", Policy, L, 1, "fec0::1", 0);
        CheckPick("link-local only, link-local destination", Policy, L, 1, "fe80::1", 0);
        CheckPick("link-local only, global multicast", Policy, L, 1, "ff0e::1", 0);
        CheckPick("loopback interface, global destination", Policy, Loop, 1, "3fff:ff::1", 0);
        CheckPick("no address at all", Policy, L, 0, "3fff:ff::1", -1);
    }
    /* rule 1 and skip-as-source */
    {
        static const char *L[] = { "fe80::10", "3fff:a1::10/d", "3fff:a1::20/s", "3fff:a1::30" };
        static const char *S[] = { "fe80::10", "3fff:a1::20/s" };

        CheckPick("own deprecated address", Policy, L, 4, "3fff:a1::10", 1);
        CheckPick("own skip-as-source address", Policy, L, 4, "3fff:a1::20", 2);
        CheckPick("skip-as-source not chosen", Policy, L, 4, "3fff:a1::99", 3);
        CheckPick("skip-as-source and link-local only: the link-local one", Policy, S, 2, "3fff:ff::1", 0);
        CheckPick("skip-as-source only: none", Policy, S + 1, 1, "3fff:ff::1", -1);
    }
    /* IPv4: the IPv4 address, never an IPv6 one */
    {
        static const char *L[] = { "fe80::10", "3fff:a1::10", "192.0.2.10" };

        CheckPick("IPv4 destination", Policy, L, 3, "198.51.100.1", 2);
        CheckPick("IPv6 destination with IPv4 there", Policy, L, 3, "3fff:ff::1", 1);
    }
}

/* the label rule follows the table: a table that gives 3fff::/16 the 6to4 label turns the choice around */
static void TestSourcePolicy(void)
{
    ADDRSORT_POLICY_TABLE Table;
    static const WCHAR Lines[] = L"::/0 40 1\0" L"3fff::/16 30 2\0" L"2002::/16 30 7\0\0";
    static const char *L[] = { "fe80::10", "2002:c000:201::10", "3fff:a1::10" };

    AddrSortDefaultPolicy(&Table);
    ok(AddrSortParsePolicy(Lines, RTL_NUMBER_OF(Lines), &Table) == 3, "policy lines\n");
    /* 2a00::1 has label 1, neither source has it now: rule 8 decides (2002:: shares 4 bits) */
    CheckPick("other table: no label matches", &Table, L, 3, "2a00:ff::1", 1);
    /* a destination in 3fff::/16 (label 2) */
    CheckPick("other table: label 2 matches 3fff", &Table, L, 3, "3fff:ff::1", 2);
}

START_TEST(AddrSortEngine)
{
    ADDRSORT_POLICY_TABLE Policy;

    AddrSortDefaultPolicy(&Policy);
    TestPolicy();
    TestPolicyDottedTail();
    TestPolicyTooMany();
    TestScopes();
    TestOracle(&Policy);
    TestHosts(&Policy);
    TestOtherPolicy();
    TestSourceRules(&Policy);
    TestSourcePolicy();
}
