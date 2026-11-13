/*
 * PROJECT:     ReactOS cmlib regression tests
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     The 'sk' cell primitives of cmlib (cmse.c) and the 'sk' check of
 *              CmCheckRegistry (cmcheck.c): insert with dedup, the per-hive
 *              hash, the reference count, the ring, the cache built at load,
 *              the release of a key's reference, and what a corrupt 'sk' does
 *              to a load (the key loses its descriptor, the hive loads, nothing
 *              faults and nothing bugchecks).
 *
 *              Host test against the real cmlib sources. Built with
 *              -fsanitize=address a read outside a bin is a failure too.
 */

#include "CmHostGlue.h"

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

/* A valid self-relative SD (owner and group Administrators, DACL Everyone), 76 bytes. */
static const UCHAR g_Sd[] =
{
    1, 0, 0x04, 0x80, 0x30, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0x14, 0, 0, 0,
    2, 0, 0x1c, 0, 1, 0, 0, 0,
    0, 0, 0x14, 0, 0x3f, 0, 0x1f, 0,
    1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0,
    1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0,
};
#define SD_MASK_OFFSET 32

/* The N-th distinct valid SD (the ACE mask differs) */
static ULONG Sd(ULONG N, UCHAR *Out)
{
    memcpy(Out, g_Sd, sizeof(g_Sd));
    Out[SD_MASK_OFFSET] = (UCHAR)N;
    Out[SD_MASK_OFFSET + 1] = (UCHAR)(N >> 8);
    return sizeof(g_Sd);
}

static void InitCache(PCMHIVE Cm)
{
    ULONG i;

    /* what CmpInitSecurityCache of the kernel does */
    for (i = 0; i < CMP_SECURITY_HASH_LISTS; i++)
        InitializeListHead(&Cm->SecurityHash[i]);
    Cm->SecurityCount = 0;
#ifndef BASE_CMLIB
    Cm->SecurityRingAnchor[Stable] = HCELL_NIL;
    Cm->SecurityRingAnchor[Volatile] = HCELL_NIL;
#endif
}

static PCM_KEY_SECURITY Sk(PHHIVE Hive, HCELL_INDEX Cell)
{
    return CmpGetCheckedSecurityCell(Hive, Cell, NULL);
}

/* Walk the ring both ways from Start: the number of cells, or -1 if it is not a sound ring */
static LONG RingLength(PHHIVE Hive, HCELL_INDEX Start)
{
    HCELL_INDEX Cell = Start;
    PCM_KEY_SECURITY S, N;
    LONG Fwd = 0, Back = 0;

    do
    {
        S = Sk(Hive, Cell);
        N = S ? Sk(Hive, S->Flink) : NULL;
        if (!N || N->Blink != Cell || Fwd > 100000)
            return -1;
        Cell = S->Flink;
        Fwd++;
    } while (Cell != Start);
    do
    {
        S = Sk(Hive, Cell);
        N = S ? Sk(Hive, S->Blink) : NULL;
        if (!N || N->Flink != Cell || Back > 100000)
            return -1;
        Cell = S->Blink;
        Back++;
    } while (Cell != Start);
    return Fwd == Back ? Fwd : -1;
}

static ULONG CacheEntries(PCMHIVE Cm)
{
    ULONG i, n = 0;
    PLIST_ENTRY L;

    for (i = 0; i < CMP_SECURITY_HASH_LISTS; i++)
        for (L = Cm->SecurityHash[i].Flink; L != &Cm->SecurityHash[i]; L = L->Flink)
            n++;
    return n;
}

static HCELL_INDEX Insert(PCMHIVE Cm, ULONG N, HSTORAGE_TYPE Type)
{
    UCHAR Buf[sizeof(g_Sd)];
    ULONG Len = Sd(N, Buf);
    HCELL_INDEX Cell;
    NTSTATUS Status = CmpInsertSecurityDescriptor(Cm, Buf, Len, Type, &Cell);

    CHECK(NT_SUCCESS(Status), "insert %lu: 0x%lx", (unsigned long)N, (unsigned long)Status);
    return NT_SUCCESS(Status) ? Cell : HCELL_NIL;
}

static HCELL_INDEX Find_(PCMHIVE Cm, ULONG N, HSTORAGE_TYPE Type)
{
    UCHAR Buf[sizeof(g_Sd)];
    ULONG Len = Sd(N, Buf);
    HCELL_INDEX Cell;

    return CmpFindMatchingDescriptorCell(Cm, Buf, Len, Type, &Cell) ? Cell : HCELL_NIL;
}

static ULONG Refs(PHHIVE Hive, HCELL_INDEX Cell)
{
    PCM_KEY_SECURITY S = Sk(Hive, Cell);

    return S ? S->ReferenceCount : 0xFFFFFFFF;
}

/* A new hive with a root key; an empty cache */
static BOOLEAN NewHive(PCMHIVE Cm)
{
    PHHIVE Hive = &Cm->Hive;
    HCELL_INDEX Root;

    if (!NT_SUCCESS(OpenHive(Cm, HINIT_CREATE)))
        return FALSE;
    InitCache(Cm);
    Root = NewKey(Hive, L"ROOT", HCELL_NIL);
    ((PCM_KEY_NODE)HvGetCell(Hive, Root))->Flags |= KEY_HIVE_ENTRY | KEY_NO_DELETE;
    Hive->BaseBlock->RootCell = Root;
    return TRUE;
}

static HCELL_INDEX RootOf(PHHIVE Hive)
{
    return Hive->BaseBlock->RootCell;
}

/* A key under Parent that names Sec (the reference was taken by the caller) */
static HCELL_INDEX KeyWith(PHHIVE Hive, HCELL_INDEX Parent, PCWSTR Name, HCELL_INDEX Sec)
{
    HCELL_INDEX K = NewKey(Hive, Name, Parent);

    CHECK(K != HCELL_NIL && CmpAddSubKey(Hive, Parent, K), "add key");
    ((PCM_KEY_NODE)HvGetCell(Hive, K))->Security = Sec;
    return K;
}

static HCELL_INDEX SecOf(PHHIVE Hive, HCELL_INDEX Key)
{
    return ((PCM_KEY_NODE)HvGetCell(Hive, Key))->Security;
}

/* ---- insert, find, dedup, the hash ---- */

static void TestInsertDedup(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX A, A2, B, C, V, Cells[300];
    ULONG i;
    LONG Out;

    printf("-- insert / find / dedup\n");
    CHECK(NewHive(&Cm), "hive");
    Out = g_PoolOut;

    CHECK(Find_(&Cm, 1, Stable) == HCELL_NIL, "found in an empty cache");
    A = Insert(&Cm, 1, Stable);
    CHECK(Refs(Hive, A) == 1 && RingLength(Hive, A) == 1, "first cell: refs %lu ring %ld", (unsigned long)Refs(Hive, A), (long)RingLength(Hive, A));
    CHECK(Sk(Hive, A)->Flink == A && Sk(Hive, A)->Blink == A, "a lone cell points to itself");
    CHECK(Find_(&Cm, 1, Stable) == A, "find");

    A2 = Insert(&Cm, 1, Stable);
    CHECK(A2 == A && Refs(Hive, A) == 2, "same descriptor shares the cell: refs %lu", (unsigned long)Refs(Hive, A));
    CHECK(Cm.SecurityCount == 1 && CacheEntries(&Cm) == 1, "one entry");

    B = Insert(&Cm, 2, Stable);
    C = Insert(&Cm, 3, Stable);
    CHECK(B != A && C != A && B != C, "distinct descriptors, distinct cells");
    CHECK(RingLength(Hive, A) == 3 && RingLength(Hive, B) == 3 && RingLength(Hive, C) == 3, "ring of three");
    CHECK(Cm.SecurityCount == 3, "count %lu", (unsigned long)Cm.SecurityCount);

    /* the storage type is part of the identity, and a volatile cell is in a ring of its own */
    V = Insert(&Cm, 1, Volatile);
    CHECK(V != A && HvGetCellType(V) == Volatile, "a volatile key does not share a stable cell");
    CHECK(RingLength(Hive, V) == 1 && RingLength(Hive, A) == 3, "separate rings by storage type");
    CHECK(Find_(&Cm, 1, Stable) == A && Find_(&Cm, 1, Volatile) == V, "find by type");

    /* a longer descriptor and a shorter one with the same prefix are different */
    {
        UCHAR Buf[sizeof(g_Sd) + 8];
        HCELL_INDEX Long_;
        NTSTATUS St;

        Sd(1, Buf);
        memset(Buf + sizeof(g_Sd), 0, 8);
        St = CmpInsertSecurityDescriptor(&Cm, Buf, sizeof(g_Sd) + 8, Stable, &Long_);
        CHECK(NT_SUCCESS(St) && Long_ != A, "longer descriptor: a cell of its own");
    }

    /* many distinct descriptors: the 64 lists all have several */
    for (i = 0; i < 300; i++)
        Cells[i] = Insert(&Cm, 100 + i, Stable);
    for (i = 0; i < 300; i++)
        CHECK(Find_(&Cm, 100 + i, Stable) == Cells[i] && Insert(&Cm, 100 + i, Stable) == Cells[i] &&
              Refs(Hive, Cells[i]) == 2, "descriptor %lu", (unsigned long)i);
    /* stable cells: A, B, C, the long one, and the 300 */
    CHECK(RingLength(Hive, A) == 304, "ring of the stable cells: %ld", (long)RingLength(Hive, A));
    CHECK(CacheEntries(&Cm) == Cm.SecurityCount, "entries == count");

    /* input that is not a descriptor is refused, nothing allocated */
    {
        UCHAR Bad[sizeof(g_Sd)];
        HCELL_INDEX X;
        ULONG Len = Sd(1, Bad);

        CHECK(CmpInsertSecurityDescriptor(&Cm, Bad, 4, Stable, &X) == STATUS_INVALID_PARAMETER, "short");
        CHECK(CmpInsertSecurityDescriptor(&Cm, Bad, 0, Stable, &X) == STATUS_INVALID_PARAMETER, "empty");
        Bad[0] = 2;
        CHECK(CmpInsertSecurityDescriptor(&Cm, Bad, Len, Stable, &X) == STATUS_INVALID_PARAMETER, "revision");
        Sd(1, Bad);
        Bad[4] = 0xF0;  /* owner offset past the end */
        CHECK(CmpInsertSecurityDescriptor(&Cm, Bad, Len, Stable, &X) == STATUS_INVALID_PARAMETER, "owner offset");
        Sd(1, Bad);
        Bad[16] = 0x40; /* DACL at 0x40: the ACL header runs into the group SID, size field 0 */
        CHECK(CmpInsertSecurityDescriptor(&Cm, Bad, Len, Stable, &X) == STATUS_INVALID_PARAMETER, "dacl size");
    }

    CHECK(g_PoolOut - Out == (LONG)Cm.SecurityCount, "one pool block per entry");
    CmpFreeSecurityCache(&Cm);
    CHECK(Cm.SecurityCount == 0 && g_PoolOut == Out && CacheEntries(&Cm) == 0, "cache freed: pool %ld", (long)(g_PoolOut - Out));
}

/* ---- release, the reference count ---- */

static void TestRelease(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX A, B, C;

    printf("-- release / reference count\n");
    CHECK(NewHive(&Cm), "hive");
    A = Insert(&Cm, 1, Stable);
    Insert(&Cm, 1, Stable);
    Insert(&Cm, 1, Stable);
    B = Insert(&Cm, 2, Stable);
    C = Insert(&Cm, 3, Stable);
    CHECK(Refs(Hive, A) == 3, "refs %lu", (unsigned long)Refs(Hive, A));

    CHECK(CmpReleaseSecurityCell(Hive, A) && Refs(Hive, A) == 2, "release 1");
    CHECK(CmpReleaseSecurityCell(Hive, A) && Refs(Hive, A) == 1, "release 2");
    CHECK(Sk(Hive, A) != NULL && Find_(&Cm, 1, Stable) == A && RingLength(Hive, A) == 3, "still there with a reference");

    /* the last reference of a cell in the middle of the ring */
    CHECK(CmpReleaseSecurityCell(Hive, B), "release B");
    CHECK(Sk(Hive, B) == NULL, "B is freed");
    CHECK(Find_(&Cm, 2, Stable) == HCELL_NIL && Cm.SecurityCount == 2, "B left the cache");
    CHECK(RingLength(Hive, A) == 2 && RingLength(Hive, C) == 2, "ring closed over B: %ld", (long)RingLength(Hive, A));

    /* a released descriptor can be inserted again */
    B = Insert(&Cm, 2, Stable);
    CHECK(Refs(Hive, B) == 1 && RingLength(Hive, B) == 3, "B again");

    /* a cell that is not an 'sk' cell is refused and nothing changes */
    CHECK(!CmpReleaseSecurityCell(Hive, RootOf(Hive)), "a key node is not an sk cell");
    CHECK(!CmpReleaseSecurityCell(Hive, HCELL_NIL), "NIL");
    CHECK(!CmpReleaseSecurityCell(Hive, 0x7FFFF000), "out of range");
    CHECK(!CmpReleaseSecurityCell(Hive, A + 4), "unaligned");
    CHECK(!CmpReleaseSecurityCell(Hive, 0x80000000), "volatile index, empty volatile storage");

    /* down to one cell, then none */
    CmpReleaseSecurityCell(Hive, A);
    CmpReleaseSecurityCell(Hive, B);
    CHECK(RingLength(Hive, C) == 1, "last one alone");
    CHECK(CmpReleaseSecurityCell(Hive, C), "release C");
    CHECK(Cm.SecurityCount == 0 && CacheEntries(&Cm) == 0, "cache empty");
    CHECK(Sk(Hive, A) == NULL && Sk(Hive, C) == NULL, "all freed");
    CmpFreeSecurityCache(&Cm);
}

/* The keys: CmpFreeKeyByCell, CmpFreeKeyBody and the descriptor they share */
static void TestKeyDelete(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX S, S2, K1, K2, K3, Root, Extra;
    ULONG i;

    printf("-- key delete releases its reference\n");
    CHECK(NewHive(&Cm), "hive");
    Root = RootOf(Hive);
    S = Insert(&Cm, 1, Stable);
    Insert(&Cm, 1, Stable);
    Insert(&Cm, 1, Stable);                       /* 3 references: root, K1, K2 */
    ((PCM_KEY_NODE)HvGetCell(Hive, Root))->Security = S;
    K1 = KeyWith(Hive, Root, L"K1", S);
    K2 = KeyWith(Hive, Root, L"K2", S);
    S2 = Insert(&Cm, 2, Stable);
    K3 = KeyWith(Hive, Root, L"K3", S2);
    CHECK(Refs(Hive, S) == 3 && Refs(Hive, S2) == 1, "setup");

    /* K1 goes: the shared cell stays */
    CHECK(CmpFreeKeyByCell(Hive, K1, TRUE) == STATUS_SUCCESS, "delete K1");
    CHECK(Refs(Hive, S) == 2 && Sk(Hive, S) != NULL, "shared cell kept: refs %lu", (unsigned long)Refs(Hive, S));
    CHECK(RingLength(Hive, S) == 2, "ring intact");

    /* K3 is the only user of S2: it goes with the key */
    CHECK(CmpFreeKeyByCell(Hive, K3, TRUE) == STATUS_SUCCESS, "delete K3");
    CHECK(Sk(Hive, S2) == NULL, "the sole user's cell is freed");
    CHECK(RingLength(Hive, S) == 1 && Cm.SecurityCount == 1, "ring and cache");

    /* CmpFreeKeyBody called on its own with Security still set: a reference, not the cell */
    Extra = Insert(&Cm, 1, Stable);               /* S, refs 3 */
    CHECK(Extra == S && Refs(Hive, S) == 3, "extra reference");
    {
        HCELL_INDEX Loose = NewKey(Hive, L"Loose", Root);

        ((PCM_KEY_NODE)HvGetCell(Hive, Loose))->Security = S;
        CHECK(CmpFreeKeyBody(Hive, Loose), "body");
    }
    CHECK(Sk(Hive, S) != NULL && Refs(Hive, S) == 2, "the body freed a reference only: refs %lu", (unsigned long)Refs(Hive, S));

    /* a key with a bad Security is deleted without a fault, and nothing else changes */
    {
        HCELL_INDEX Bad = NewKey(Hive, L"Bad", Root);
        PCM_KEY_NODE N = (PCM_KEY_NODE)HvGetCell(Hive, Bad);

        CHECK(CmpAddSubKey(Hive, Root, Bad), "add Bad");
        N->Security = 0x7FFFF008;
        CHECK(CmpFreeKeyByCell(Hive, Bad, TRUE) == STATUS_SUCCESS, "delete a key with a bad Security");
        CHECK(Refs(Hive, S) == 2 && RingLength(Hive, S) == 1, "no side effect");
    }

    /* many keys sharing and leaving */
    {
        HCELL_INDEX Keys[200];
        WCHAR Name[16];

        for (i = 0; i < 200; i++)
        {
            HCELL_INDEX Sec = Insert(&Cm, 1, Stable);

            Name[0] = L'k'; Name[1] = L'0' + i / 100; Name[2] = L'0' + i / 10 % 10; Name[3] = L'0' + i % 10; Name[4] = 0;
            Keys[i] = KeyWith(Hive, Root, Name, Sec);
        }
        CHECK(Refs(Hive, S) == 202, "200 more: %lu", (unsigned long)Refs(Hive, S));
        for (i = 0; i < 200; i++)
            CHECK(CmpFreeKeyByCell(Hive, Keys[i], TRUE) == STATUS_SUCCESS, "delete %lu", (unsigned long)i);
        CHECK(Refs(Hive, S) == 2 && RingLength(Hive, S) == 1, "back to two: %lu", (unsigned long)Refs(Hive, S));
    }
    CmpFreeSecurityCache(&Cm);
}

/* ---- a random walk against a model; the ring, the counts and the pool stay sound ---- */

static void TestModel(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    enum { SDS = 24, STEPS = 6000 };
    struct { HCELL_INDEX Cell; ULONG Refs; } Model[SDS][2];
    ULONG Seed = 12345, Step, n, t, i;
    LONG Pool0;

    printf("-- random insert / release against a model\n");
    CHECK(NewHive(&Cm), "hive");
    Pool0 = g_PoolOut;
    memset(Model, 0, sizeof(Model));
    for (Step = 0; Step < STEPS && g_Errors == 0; Step++)
    {
        Seed = Seed * 1103515245 + 12345;
        n = (Seed >> 8) % SDS;
        t = (Seed >> 20) & 1;
        if (((Seed >> 4) & 3) < 2 || Model[n][t].Refs == 0)
        {
            HCELL_INDEX C = Insert(&Cm, n, t ? Volatile : Stable);

            if (Model[n][t].Refs)
                CHECK(C == Model[n][t].Cell, "dedup returned another cell");
            Model[n][t].Cell = C;
            Model[n][t].Refs++;
        }
        else
        {
            CHECK(CmpReleaseSecurityCell(Hive, Model[n][t].Cell), "release");
            Model[n][t].Refs--;
        }

        /* the invariants, after every step */
        {
            ULONG Live[2] = {0, 0}, Total = 0;
            HCELL_INDEX First[2] = {HCELL_NIL, HCELL_NIL};

            for (i = 0; i < SDS; i++)
                for (t = 0; t < 2; t++)
                    if (Model[i][t].Refs)
                    {
                        Live[t]++;
                        Total++;
                        First[t] = Model[i][t].Cell;
                        CHECK(Refs(Hive, Model[i][t].Cell) == Model[i][t].Refs, "step %lu: refs", (unsigned long)Step);
                    }
            for (t = 0; t < 2; t++)
                if (Live[t])
                    CHECK(RingLength(Hive, First[t]) == (LONG)Live[t], "step %lu: ring %ld of %lu", (unsigned long)Step,
                          (long)RingLength(Hive, First[t]), (unsigned long)Live[t]);
            CHECK(Cm.SecurityCount == Total && CacheEntries(&Cm) == Total, "step %lu: cache %lu of %lu",
                  (unsigned long)Step, (unsigned long)Cm.SecurityCount, (unsigned long)Total);
            CHECK(g_PoolOut - Pool0 == (LONG)Total, "step %lu: pool %ld for %lu cells", (unsigned long)Step,
                  (long)(g_PoolOut - Pool0), (unsigned long)Total);
        }
    }
    /* drain */
    for (i = 0; i < SDS; i++)
        for (t = 0; t < 2; t++)
            while (Model[i][t].Refs)
            {
                CHECK(CmpReleaseSecurityCell(Hive, Model[i][t].Cell), "drain");
                Model[i][t].Refs--;
            }
    CHECK(Cm.SecurityCount == 0 && g_PoolOut == Pool0, "drained: count %lu, pool %ld", (unsigned long)Cm.SecurityCount,
          (long)(g_PoolOut - Pool0));
    CmpFreeSecurityCache(&Cm);
}

/* ---- a saved hive: load, check, build the cache ---- */

#define K_SHARED 0
#define K_SOLE   1
#define K_NONE   2
static HCELL_INDEX g_Key[3];
static ULONG g_SavedSecurity[3];

/* ROOT (sd 1) with K0 (sd 1, shared), K1 (sd 2), K2 (no Security); written to g_File */
static BOOLEAN BuildFile(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Root, S1, S2;

    if (!NewHive(&Cm))
        return FALSE;
    Root = RootOf(Hive);
    S1 = Insert(&Cm, 1, Stable);
    Insert(&Cm, 1, Stable);
    Insert(&Cm, 1, Stable);
    S2 = Insert(&Cm, 2, Stable);
    ((PCM_KEY_NODE)HvGetCell(Hive, Root))->Security = S1;
    g_Key[K_SHARED] = KeyWith(Hive, Root, L"Shared", S1);
    g_Key[K_SOLE] = KeyWith(Hive, Root, L"Sole", S2);
    g_Key[K_NONE] = KeyWith(Hive, Root, L"None", HCELL_NIL);
    g_SavedSecurity[K_SHARED] = S1;
    g_SavedSecurity[K_SOLE] = S2;
    g_SavedSecurity[K_NONE] = HCELL_NIL;
    HvMarkCellDirty(Hive, Root, FALSE);
    CHECK(HvWriteHive(Hive), "write");
    CmpFreeSecurityCache(&Cm);
    return TRUE;
}

static ULONG g_Flags = CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES | CM_CHECK_REGISTRY_VALIDATE_HIVE;

static void TestLoadGood(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX S1, S2;
    LONG Pool0;
    UCHAR Buf[sizeof(g_Sd)];
    ULONG Len, i;

    printf("-- load a good hive: checked as it is, cache built, dedup against the loaded cells\n");
    CHECK(BuildFile(), "build");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    InitCache(&Cm);
    Pool0 = g_PoolOut;
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_Flags)), "check");
    CHECK(Hive->DirtyCount == 0, "a good hive was changed (dirty %lu)", (unsigned long)Hive->DirtyCount);
    for (i = 0; i < 3; i++)
        CHECK(SecOf(Hive, g_Key[i]) == g_SavedSecurity[i], "key %lu keeps its Security", (unsigned long)i);

    CHECK(CmpBuildSecurityCache(&Cm), "build cache");
    CHECK(Cm.SecurityCount == 2 && CacheEntries(&Cm) == 2 && g_PoolOut - Pool0 == 2, "two cells cached");
    S1 = g_SavedSecurity[K_SHARED];
    S2 = g_SavedSecurity[K_SOLE];
    CHECK(Find_(&Cm, 1, Stable) == S1 && Find_(&Cm, 2, Stable) == S2, "find in the loaded cells");
    CHECK(Insert(&Cm, 1, Stable) == S1 && Refs(Hive, S1) == 4, "dedup against a loaded cell");
    CHECK(Cm.SecurityCount == 2, "no new entry");
    CHECK(Insert(&Cm, 9, Stable) != HCELL_NIL && RingLength(Hive, S1) == 3, "a new cell joins the loaded ring");

    /* build again: the same cache, no leak */
    CHECK(CmpBuildSecurityCache(&Cm) && Cm.SecurityCount == 3 && g_PoolOut - Pool0 == 3, "rebuild");

    /* flush, reload, check: the new cell is a sound part of the ring */
    CHECK(HvSyncHive(Hive), "flush");
    CmpFreeSecurityCache(&Cm);
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "reload");
    InitCache(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_Flags)) && Cm.Hive.DirtyCount == 0, "second check clean");
    CHECK(SecOf(Hive, g_Key[K_SOLE]) == S2, "still there");
    CHECK(CmpBuildSecurityCache(&Cm) && Cm.SecurityCount == 3, "cache of the reloaded hive");
    Len = Sd(9, Buf);
    {
        HCELL_INDEX C9;
        CHECK(CmpFindMatchingDescriptorCell(&Cm, Buf, Len, Stable, &C9) && RingLength(&Cm.Hive, C9) == 3, "the new cell survived");
    }
    CmpFreeSecurityCache(&Cm);
}

/* ---- corrupt 'sk': every kind heals, none faults ---- */

typedef void (*TAMPER)(PHHIVE Hive);

static void T_ZeroLength(PHHIVE H)      { Sk(H, g_SavedSecurity[K_SOLE])->DescriptorLength = 0; }
static void T_BadSignature(PHHIVE H)    { Sk(H, g_SavedSecurity[K_SOLE])->Signature = 0x4242; }
static void T_ZeroRefs(PHHIVE H)        { Sk(H, g_SavedSecurity[K_SOLE])->ReferenceCount = 0; }
static void T_LengthPastCell(PHHIVE H)  { Sk(H, g_SavedSecurity[K_SOLE])->DescriptorLength = 0x10000; }
static void T_LengthHuge(PHHIVE H)      { Sk(H, g_SavedSecurity[K_SOLE])->DescriptorLength = 0xFFFFFFF0; }
static void T_OwnerPastEnd(PHHIVE H)    { ((PISECURITY_DESCRIPTOR_RELATIVE)&Sk(H, g_SavedSecurity[K_SOLE])->Descriptor)->Owner = 0x1000; }
static void T_OwnerHuge(PHHIVE H)       { ((PISECURITY_DESCRIPTOR_RELATIVE)&Sk(H, g_SavedSecurity[K_SOLE])->Descriptor)->Owner = 0xFFFFFFF8; }
static void T_DaclSizeBig(PHHIVE H)
{
    PUCHAR D = (PUCHAR)&Sk(H, g_SavedSecurity[K_SOLE])->Descriptor;

    D[((PISECURITY_DESCRIPTOR_RELATIVE)D)->Dacl + 2] = 0xFF;   /* AclSize 0x1ff > what is left */
    D[((PISECURITY_DESCRIPTOR_RELATIVE)D)->Dacl + 3] = 0x01;
}
static void T_Revision(PHHIVE H)        { ((PISECURITY_DESCRIPTOR_RELATIVE)&Sk(H, g_SavedSecurity[K_SOLE])->Descriptor)->Revision = 9; }
static void T_SidSubAuth(PHHIVE H)
{
    PUCHAR D = (PUCHAR)&Sk(H, g_SavedSecurity[K_SOLE])->Descriptor;

    D[((PISECURITY_DESCRIPTOR_RELATIVE)D)->Owner + 1] = 200;   /* SubAuthorityCount */
}
static void T_FlinkGarbage(PHHIVE H)    { Sk(H, g_SavedSecurity[K_SOLE])->Flink = 0x00ABC000; }
static void T_BlinkNotMutual(PHHIVE H)  { Sk(H, g_SavedSecurity[K_SOLE])->Blink = g_SavedSecurity[K_SOLE]; }
static void T_FlinkToKeyNode(PHHIVE H)  { Sk(H, g_SavedSecurity[K_SOLE])->Flink = g_Key[K_NONE]; }
static void T_NodePtrOutOfRange(PHHIVE H)  { ((PCM_KEY_NODE)HvGetCell(H, g_Key[K_SOLE]))->Security = 0x7FFFF000; }
static void T_NodePtrUnaligned(PHHIVE H)   { ((PCM_KEY_NODE)HvGetCell(H, g_Key[K_SOLE]))->Security = g_SavedSecurity[K_SOLE] + 4; }
static void T_NodePtrMiddle(PHHIVE H)      { ((PCM_KEY_NODE)HvGetCell(H, g_Key[K_SOLE]))->Security = g_SavedSecurity[K_SOLE] + 8; }
static void T_NodePtrKeyNode(PHHIVE H)     { ((PCM_KEY_NODE)HvGetCell(H, g_Key[K_SOLE]))->Security = g_Key[K_NONE]; }
static void T_NodePtrVolatile(PHHIVE H)    { ((PCM_KEY_NODE)HvGetCell(H, g_Key[K_SOLE]))->Security = 0x80000008; }
static void T_NodePtrBinEnd(PHHIVE H)      { ((PCM_KEY_NODE)HvGetCell(H, g_Key[K_SOLE]))->Security = 0x00000FF8; }
static void T_NodePtrPastHive(PHHIVE H)    { ((PCM_KEY_NODE)HvGetCell(H, g_Key[K_SOLE]))->Security = 0x00200000; }
static void T_NodePtrFree(PHHIVE H)
{
    /* the end of the first bin is a free cell */
    PHBIN Bin = (PHBIN)H->Storage[Stable].BlockList[0].BinAddress;
    PHCELL C = (PHCELL)((PUCHAR)Bin + sizeof(HBIN));

    while (C->Size < 0 && (PUCHAR)C < (PUCHAR)Bin + Bin->Size)
        C = (PHCELL)((PUCHAR)C + (0 - C->Size));
    ((PCM_KEY_NODE)HvGetCell(H, g_Key[K_SOLE]))->Security = (HCELL_INDEX)(Bin->FileOffset + ((PUCHAR)C - (PUCHAR)Bin));
}

static const struct
{
    const char *Name;
    TAMPER Tamper;
    /*
     * A cell is only usable if its ring neighbours are sound 'sk' cells that
     * point back at it. When the cell that is tampered with is the one that is
     * not sound (or its links are), the cell next to it (here: the one the root
     * and Shared name) is reset as well.
     */
    BOOLEAN SharedHeals;
} g_Tampers[] =
{
    { "zero length descriptor (mkhive SECURITY)", T_ZeroLength, FALSE },
    { "bad signature", T_BadSignature, TRUE },
    { "zero reference count", T_ZeroRefs, FALSE },
    { "length past the cell", T_LengthPastCell, TRUE },
    { "length 0xFFFFFFF0", T_LengthHuge, TRUE },
    { "owner offset past the end", T_OwnerPastEnd, FALSE },
    { "owner offset 0xFFFFFFF8", T_OwnerHuge, FALSE },
    { "ACL size past the end", T_DaclSizeBig, FALSE },
    { "descriptor revision", T_Revision, FALSE },
    { "SID subauthority count", T_SidSubAuth, FALSE },
    { "Flink garbage", T_FlinkGarbage, TRUE },
    { "Blink not mutual", T_BlinkNotMutual, TRUE },
    { "Flink to a key node", T_FlinkToKeyNode, TRUE },
    { "Security out of range", T_NodePtrOutOfRange, FALSE },
    { "Security unaligned", T_NodePtrUnaligned, FALSE },
    { "Security into the middle of a cell", T_NodePtrMiddle, FALSE },
    { "Security names a key node", T_NodePtrKeyNode, FALSE },
    { "Security volatile in a stable key", T_NodePtrVolatile, FALSE },
    { "Security at the end of the bin", T_NodePtrBinEnd, FALSE },
    { "Security past the hive", T_NodePtrPastHive, FALSE },
    { "Security names a free cell", T_NodePtrFree, FALSE },
};

static void TestCorrupt(ULONG Fix)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    ULONG t;

    printf("-- corrupt sk cells %s FixHive\n", Fix ? "with" : "without");
    CHECK(BuildFile(), "build");
    for (t = 0; t < COUNT_OF(g_Tampers); t++)
    {
        CM_CHECK_REGISTRY_STATUS Status;
        ULONG Dirty;
        HCELL_INDEX C;

        CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
        InitCache(&Cm);
        g_Tampers[t].Tamper(Hive);
        Dirty = Hive->DirtyCount;

        Status = CmCheckRegistry(&Cm, g_Flags | (Fix ? CM_CHECK_REGISTRY_FIX_HIVE : 0));
        CHECK(CM_CHECK_REGISTRY_SUCCESS(Status), "[%s] the hive must load: status %lu", g_Tampers[t].Name, (unsigned long)Status);

        /* the key that named the bad cell has no descriptor; the others keep theirs */
        CHECK(SecOf(Hive, g_Key[K_SOLE]) == HCELL_NIL, "[%s] Sole was not reset: 0x%x", g_Tampers[t].Name, SecOf(Hive, g_Key[K_SOLE]));
        /* ...unless the ring is what is broken: the neighbour that disagrees with it goes too */
        CHECK(SecOf(Hive, g_Key[K_SHARED]) == (g_Tampers[t].SharedHeals ? HCELL_NIL : g_SavedSecurity[K_SHARED]),
              "[%s] Shared: 0x%x", g_Tampers[t].Name, SecOf(Hive, g_Key[K_SHARED]));
        CHECK(SecOf(Hive, RootOf(Hive)) == (g_Tampers[t].SharedHeals ? HCELL_NIL : g_SavedSecurity[K_SHARED]),
              "[%s] the root: 0x%x", g_Tampers[t].Name, SecOf(Hive, RootOf(Hive)));
        CHECK(SecOf(Hive, g_Key[K_NONE]) == HCELL_NIL, "[%s] a key without one gained one", g_Tampers[t].Name);
        CHECK(Fix ? Hive->DirtyCount > Dirty : Hive->DirtyCount == Dirty, "[%s] dirty %lu -> %lu", g_Tampers[t].Name,
              (unsigned long)Dirty, (unsigned long)Hive->DirtyCount);

        /* and the rest of the work goes on: the cache, an insert, a delete, a second check */
        CmpBuildSecurityCache(&Cm);
        if (!g_Tampers[t].SharedHeals)
            CHECK(Find_(&Cm, 1, Stable) == g_SavedSecurity[K_SHARED], "[%s] the good cell is found", g_Tampers[t].Name);
        C = Insert(&Cm, 77, Stable);
        CHECK(C != HCELL_NIL && Sk(Hive, C) != NULL, "[%s] insert after the heal", g_Tampers[t].Name);
        CHECK(CmpFreeKeyByCell(Hive, g_Key[K_SOLE], TRUE) == STATUS_SUCCESS, "[%s] delete the healed key", g_Tampers[t].Name);
        CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_Flags)), "[%s] second check", g_Tampers[t].Name);
        CmpFreeSecurityCache(&Cm);
    }
}

/* the damaged shared cell: three keys lose it, the other is unaffected */
static void TestCorruptShared(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;

    printf("-- the shared cell is zero length: every key that names it is reset\n");
    CHECK(BuildFile(), "build");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    InitCache(&Cm);
    Sk(Hive, g_SavedSecurity[K_SHARED])->DescriptorLength = 0;
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_Flags)), "loads");
    CHECK(SecOf(Hive, RootOf(Hive)) == HCELL_NIL && SecOf(Hive, g_Key[K_SHARED]) == HCELL_NIL, "root and Shared reset");
    CHECK(SecOf(Hive, g_Key[K_SOLE]) == g_SavedSecurity[K_SOLE], "Sole untouched");
    /* the root is NIL: nothing to walk, an empty cache, and the hive works */
    CHECK(CmpBuildSecurityCache(&Cm) && Cm.SecurityCount == 0, "empty cache for a root without Security");
    CHECK(Insert(&Cm, 5, Stable) != HCELL_NIL, "insert");
    CmpFreeSecurityCache(&Cm);
}

/* ---- the recount of the references (CM_CHECK_REGISTRY_RECOUNT_SECURITY) ---- */

#define RC_FLAGS (CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES | CM_CHECK_REGISTRY_VALIDATE_HIVE | CM_CHECK_REGISTRY_RECOUNT_SECURITY)

static HCELL_INDEX g_RcRoot, g_RcShared, g_RcDeep, g_RcSole, g_RcNone, g_RcS1, g_RcS2;

/*
 * ROOT, Shared and Shared\Deep name S1 (3 keys); Sole names S2 (1 key); None has
 * no Security. The stored counts are set to Refs1 and Refs2 and the hive is
 * written to g_File.
 */
static BOOLEAN BuildCounted(ULONG Refs1, ULONG Refs2)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;

    if (!NewHive(&Cm))
        return FALSE;
    g_RcRoot = RootOf(Hive);
    g_RcS1 = Insert(&Cm, 1, Stable);
    g_RcS2 = Insert(&Cm, 2, Stable);
    ((PCM_KEY_NODE)HvGetCell(Hive, g_RcRoot))->Security = g_RcS1;
    g_RcShared = KeyWith(Hive, g_RcRoot, L"Shared", g_RcS1);
    g_RcDeep = KeyWith(Hive, g_RcShared, L"Deep", g_RcS1);
    g_RcSole = KeyWith(Hive, g_RcRoot, L"Sole", g_RcS2);
    g_RcNone = KeyWith(Hive, g_RcRoot, L"None", HCELL_NIL);
    Sk(Hive, g_RcS1)->ReferenceCount = Refs1;
    Sk(Hive, g_RcS2)->ReferenceCount = Refs2;
    HvMarkCellDirty(Hive, g_RcRoot, FALSE);
    CHECK(HvWriteHive(Hive), "write");
    CmpFreeSecurityCache(&Cm);
    return TRUE;
}

/* The stored counts of the two cells after the recount, in memory and in the file that a flush leaves */
static void RecountCase(const char *Name, ULONG Refs1, ULONG Refs2, ULONG Want1, ULONG Want2, BOOLEAN Fix)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    ULONG Dirty, Changed;

    CHECK(BuildCounted(Refs1, Refs2), "[%s] build", Name);
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "[%s] load", Name);
    InitCache(&Cm);
    Dirty = Hive->DirtyCount;
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS | (Fix ? CM_CHECK_REGISTRY_FIX_HIVE : 0))),
          "[%s] the hive must load", Name);
    CHECK(Refs(Hive, g_RcS1) == Want1 && Refs(Hive, g_RcS2) == Want2, "[%s] in memory: %lu and %lu, want %lu and %lu", Name,
          (unsigned long)Refs(Hive, g_RcS1), (unsigned long)Refs(Hive, g_RcS2), (unsigned long)Want1, (unsigned long)Want2);
    Changed = (Refs1 != Want1 || Refs2 != Want2);
    CHECK(Fix && Changed ? Hive->DirtyCount > Dirty : Hive->DirtyCount == Dirty, "[%s] dirty %lu -> %lu (fix %d, changed %lu)", Name,
          (unsigned long)Dirty, (unsigned long)Hive->DirtyCount, (int)Fix, (unsigned long)Changed);
    CHECK(SecOf(Hive, g_RcRoot) == g_RcS1 && SecOf(Hive, g_RcShared) == g_RcS1 && SecOf(Hive, g_RcDeep) == g_RcS1 &&
          SecOf(Hive, g_RcSole) == g_RcS2 && SecOf(Hive, g_RcNone) == HCELL_NIL, "[%s] a key lost or gained its Security", Name);
    CHECK(RingLength(Hive, g_RcS1) == 2, "[%s] ring", Name);

    CHECK(HvSyncHive(Hive), "[%s] flush", Name);

    /* what is on disk: the fix only with FixHive, otherwise the file is left as it was */
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "[%s] reload", Name);
    CHECK(Refs(Hive, g_RcS1) == (Fix ? Want1 : Refs1) && Refs(Hive, g_RcS2) == (Fix ? Want2 : Refs2),
          "[%s] on disk: %lu and %lu (fix %d)", Name, (unsigned long)Refs(Hive, g_RcS1), (unsigned long)Refs(Hive, g_RcS2), (int)Fix);
}

static void TestRecount(void)
{
    ULONG Fix;
    LONG Pool0 = g_PoolOut;

    printf("-- recount of the references\n");
    for (Fix = 0; Fix <= 1; Fix++)
    {
        printf("   %s FixHive\n", Fix ? "with" : "without");
        RecountCase("exact", 3, 1, 3, 1, Fix);
        RecountCase("under-count by 1", 2, 1, 3, 1, Fix);
        RecountCase("under-count, one reference for three keys", 1, 1, 3, 1, Fix);
        RecountCase("over-count by 1", 4, 1, 3, 1, Fix);
        RecountCase("over-count, huge", 0x7FFFFFF0, 9, 3, 1, Fix);
        RecountCase("saturated", MAXULONG, MAXULONG, 3, 1, Fix);
        RecountCase("S1 under, S2 over", 1, 5, 3, 1, Fix);
        RecountCase("S1 over, S2 exact", 40, 1, 3, 1, Fix);
    }
    CHECK(g_PoolOut == Pool0, "pool %ld", (long)(g_PoolOut - Pool0));
}

/* The reason for the under-count rule: without it a delete frees a cell that other keys use */
static void TestRecountDelete(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;

    printf("-- recount: a key delete after the load\n");
    CHECK(BuildCounted(1, 1), "build");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    InitCache(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS)), "check");
    CmpBuildSecurityCache(&Cm);
    CHECK(Refs(Hive, g_RcS1) == 3, "3 keys name S1");
    CHECK(CmpFreeKeyByCell(Hive, g_RcDeep, TRUE) == STATUS_SUCCESS, "delete Deep");
    CHECK(Sk(Hive, g_RcS1) != NULL && Refs(Hive, g_RcS1) == 2, "S1 still there for the others: refs %lu", (unsigned long)Refs(Hive, g_RcS1));
    CHECK(CmpFreeKeyByCell(Hive, g_RcShared, TRUE) == STATUS_SUCCESS, "delete Shared");
    CHECK(Sk(Hive, g_RcS1) != NULL && Refs(Hive, g_RcS1) == 1, "S1 held by the root: refs %lu", (unsigned long)Refs(Hive, g_RcS1));
    CHECK(SecOf(Hive, g_RcRoot) == g_RcS1 && RingLength(Hive, g_RcS1) == 2, "root and ring intact");
    CHECK(CmpFreeKeyByCell(Hive, g_RcSole, TRUE) == STATUS_SUCCESS && Sk(Hive, g_RcS2) == NULL, "S2 goes with its only key");
    CHECK(RingLength(Hive, g_RcS1) == 1 && Cm.SecurityCount == 1, "ring and cache");
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS)) && Refs(Hive, g_RcS1) == 1, "second check, nothing to recount");
    CmpFreeSecurityCache(&Cm);

    /* the same hive without the recount: the under-count is what frees the shared cell */
    CHECK(BuildCounted(1, 1), "build");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    InitCache(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_Flags)), "check without the recount");
    CmpBuildSecurityCache(&Cm);
    CHECK(CmpFreeKeyByCell(Hive, g_RcDeep, TRUE) == STATUS_SUCCESS, "delete Deep");
    CHECK(Sk(Hive, g_RcS1) == NULL, "(control) an under-count lets the delete free the cell that Shared and the root name");
    CmpFreeSecurityCache(&Cm);
}

/* A hive that has no 'sk' cell at all (every key NIL): untouched */
static void TestRecountNoCells(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Root;
    ULONG Fix, Dirty;

    printf("-- recount: a hive without sk cells\n");
    for (Fix = 0; Fix <= 1; Fix++)
    {
        LONG Pool0 = g_PoolOut;

        CHECK(NewHive(&Cm), "hive");
        Root = RootOf(Hive);
        KeyWith(Hive, Root, L"A", HCELL_NIL);
        KeyWith(Hive, KeyWith(Hive, Root, L"B", HCELL_NIL), L"C", HCELL_NIL);
        HvMarkCellDirty(Hive, Root, FALSE);
        CHECK(HvWriteHive(Hive), "write");
        CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
        InitCache(&Cm);
        Dirty = Hive->DirtyCount;
        CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS | (Fix ? CM_CHECK_REGISTRY_FIX_HIVE : 0))), "check");
        CHECK(Hive->DirtyCount == Dirty, "nothing was changed (dirty %lu -> %lu)", (unsigned long)Dirty, (unsigned long)Hive->DirtyCount);
        CHECK(SecOf(Hive, RootOf(Hive)) == HCELL_NIL && SecOf(Hive, Find(Hive, RootOf(Hive), L"A")) == HCELL_NIL, "still NIL");
        CHECK(g_PoolOut == Pool0, "no allocation left behind: %ld", (long)(g_PoolOut - Pool0));
    }
}

/* A cell in the ring that no key names is not counted and not touched */
static void TestRecountOrphan(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Orphan;

    printf("-- recount: a cell that no key names\n");
    CHECK(BuildCounted(3, 1), "build");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    InitCache(&Cm);
    CmpBuildSecurityCache(&Cm);
    Orphan = Insert(&Cm, 7, Stable);
    Sk(Hive, Orphan)->ReferenceCount = 5;
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS)), "check");
    CHECK(Refs(Hive, Orphan) == 5 && RingLength(Hive, Orphan) == 3, "the orphan is left as it is");
    CHECK(Refs(Hive, g_RcS1) == 3 && Refs(Hive, g_RcS2) == 1, "the others are right");
    CmpFreeSecurityCache(&Cm);
}

/* A reference count of 0 on a named cell is the existing heal (the keys lose the cell), not a recount */
static void TestRecountZero(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;

    printf("-- recount: a stored count of 0\n");
    CHECK(BuildCounted(0, 1), "build");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    InitCache(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS)), "loads");
    CHECK(SecOf(Hive, g_RcRoot) == HCELL_NIL && SecOf(Hive, g_RcShared) == HCELL_NIL && SecOf(Hive, g_RcDeep) == HCELL_NIL,
          "the three keys that named the zero cell lost it");
    CHECK(SecOf(Hive, g_RcSole) == g_RcS2 && Refs(Hive, g_RcS2) == 1, "Sole is right");
    CmpFreeSecurityCache(&Cm);
}

/* Many cells: the table grows (64 to 16384 slots); each cell is wrong in a different way */
#define MANY 3000
static void MakeName(WCHAR *W, ULONG i, ULONG u)
{
    ULONG n = 0, d;
    char Tmp[24];

    W[n++] = L'k';
    d = 0;
    do { Tmp[d++] = (char)('0' + i % 10); i /= 10; } while (i);
    while (d) W[n++] = (WCHAR)Tmp[--d];
    W[n++] = L'_';
    W[n++] = (WCHAR)('0' + u);
    W[n] = 0;
}

static ULONG ManyActual(ULONG i)
{
    return 1 + (i % 3) + (i == 0 ? 1 : 0);   /* the keys, and the root names cell 0 as well */
}

static void TestRecountMany(void)
{
    static CMHIVE Cm;
    static HCELL_INDEX Cell[MANY];
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Root;
    WCHAR Name[32];
    ULONG i, u, Actual, Bad = 0;
    LONG Pool0 = g_PoolOut;

    printf("-- recount: %d cells, the table grows\n", MANY);
    CHECK(NewHive(&Cm), "hive");
    Root = RootOf(Hive);
    for (i = 0; i < MANY; i++)
    {
        Cell[i] = Insert(&Cm, 1000 + i, Stable);
        if (i == 0)
            ((PCM_KEY_NODE)HvGetCell(Hive, Root))->Security = Cell[0];
        for (u = 0; u < 1 + (i % 3); u++)
        {
            MakeName(Name, i, u);
            KeyWith(Hive, Root, Name, Cell[i]);
        }
        /* stored: one too few (a 1 would be an under-count to 0, the other heal), exact, one too many, very wrong */
        Actual = ManyActual(i);
        switch (i % 4)
        {
            case 0: Sk(Hive, Cell[i])->ReferenceCount = Actual > 1 ? Actual - 1 : Actual + 1; break;
            case 1: Sk(Hive, Cell[i])->ReferenceCount = Actual; break;
            case 2: Sk(Hive, Cell[i])->ReferenceCount = Actual + 1; break;
            default: Sk(Hive, Cell[i])->ReferenceCount = 100000; break;
        }
    }
    HvMarkCellDirty(Hive, Root, FALSE);
    CHECK(HvWriteHive(Hive), "write");
    CmpFreeSecurityCache(&Cm);

    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    InitCache(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS)), "check");
    for (i = 0; i < MANY; i++)
    {
        if (Refs(Hive, Cell[i]) != ManyActual(i))
        {
            Bad++;
            CHECK(0, "cell %lu: %lu, want %lu", (unsigned long)i, (unsigned long)Refs(Hive, Cell[i]), (unsigned long)ManyActual(i));
        }
    }
    CHECK(Bad == 0, "%lu cells wrong", (unsigned long)Bad);
    CmpFreeSecurityCache(&Cm);
    CHECK(g_PoolOut == Pool0, "pool %ld", (long)(g_PoolOut - Pool0));
}

/* No memory for the table: the counts stay as they are, and the load succeeds */
static void TestRecountNoMemory(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    ULONG n;

    printf("-- recount: no memory for the table\n");
    for (n = 1; n <= 2; n++)
    {
        LONG Pool0 = g_PoolOut;

        CHECK(BuildCounted(1, 5), "build");
        CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
        InitCache(&Cm);
        g_FailAllocIn = n;      /* the work stack of the walk, then the table */
        CHECK(n == 1 ? !CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS)) : CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS)),
              "check with the allocation %lu failing", (unsigned long)n);
        g_FailAllocIn = 0;
        CHECK(Refs(Hive, g_RcS1) == 1 && Refs(Hive, g_RcS2) == 5, "[%lu] counts left as they were: %lu and %lu", (unsigned long)n,
              (unsigned long)Refs(Hive, g_RcS1), (unsigned long)Refs(Hive, g_RcS2));
        CHECK(g_PoolOut == Pool0, "[%lu] pool %ld", (unsigned long)n, (long)(g_PoolOut - Pool0));
    }
}

/* A repair that removes a key restarts the walk: the key was counted before it was removed, and must not stay counted */
static void TestRecountRestart(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Root, S1, A, B, C;
    PCM_KEY_NODE N;

    printf("-- recount: a repair restarts the walk\n");
    CHECK(NewHive(&Cm), "hive");
    Root = RootOf(Hive);
    S1 = Insert(&Cm, 1, Stable);
    ((PCM_KEY_NODE)HvGetCell(Hive, Root))->Security = S1;
    A = KeyWith(Hive, Root, L"A", S1);
    B = KeyWith(Hive, Root, L"B", S1);
    C = KeyWith(Hive, Root, L"C", S1);
    (void)A;
    Sk(Hive, S1)->ReferenceCount = 4;           /* the root and A, B and C */
    /* B is renamed in place to a name that sorts after C: the index is out of order at C */
    N = (PCM_KEY_NODE)HvGetCell(Hive, B);
    ((PUCHAR)N->Name)[0] = 'Z';
    HvMarkCellDirty(Hive, Root, FALSE);
    CHECK(HvWriteHive(Hive), "write");
    CmpFreeSecurityCache(&Cm);

    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    InitCache(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS | CM_CHECK_REGISTRY_FIX_HIVE)), "check");
    CHECK(Find(Hive, Root, L"C") == HCELL_NIL, "(setup) the key that is out of order was removed by the repair");
    CHECK(((PCM_KEY_NODE)HvGetCell(Hive, Root))->SubKeyCounts[Stable] == 2, "(setup) the other two are still there");
    CHECK(Refs(Hive, S1) == 3, "the removed key is not counted: refs %lu", (unsigned long)Refs(Hive, S1));
    (void)C;
    CmpFreeSecurityCache(&Cm);
}

/* A hive exit node names a cell and is not counted: raise, but never lower */
static void TestRecountExitNode(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Exit;

    printf("-- recount: a key that is not counted (hive exit node)\n");
    CHECK(BuildCounted(1, 4), "build");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    InitCache(&Cm);
    Exit = Find(Hive, g_RcRoot, L"None");
    ((PCM_KEY_NODE)HvGetCell(Hive, Exit))->Flags |= KEY_HIVE_EXIT;
    ((PCM_KEY_NODE)HvGetCell(Hive, Exit))->Security = g_RcS2;
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS)), "check");
    CHECK(Refs(Hive, g_RcS1) == 3, "S1 was under-counted: raised: %lu", (unsigned long)Refs(Hive, g_RcS1));
    CHECK(Refs(Hive, g_RcS2) == 4, "S2 is above what was counted, and the count is not complete: left: %lu", (unsigned long)Refs(Hive, g_RcS2));
    CmpFreeSecurityCache(&Cm);
}

/* a flat hive (the boot loader's): the same checks, on the image in place */
static void TestFlat(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX C;

    printf("-- flat hive (boot loader)\n");
    CHECK(BuildFile(), "build");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_FLAT)), "flat load");
    CHECK(Hive->Flat, "flat");
    C = g_SavedSecurity[K_SOLE];
    CHECK(Sk(Hive, C) != NULL && Refs(Hive, C) == 1, "a flat cell");
    CHECK(Sk(Hive, 0x80000008) == NULL && Sk(Hive, 0x7FFFFFF8) == NULL && Sk(Hive, 0xFFFFFFF8) == NULL &&
          Sk(Hive, HCELL_NIL) == NULL && Sk(Hive, C + 1) == NULL, "flat: bad indexes");
    CHECK(Sk(Hive, Hive->BaseBlock->Length) == NULL && Sk(Hive, Hive->BaseBlock->Length - 8) == NULL,
          "flat: the end of the data");
    Sk(Hive, C)->DescriptorLength = 0;
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, CM_CHECK_REGISTRY_BOOTLOADER_PURGE_VOLATILES)), "flat check heals");
    CHECK(SecOf(Hive, g_Key[K_SOLE]) == HCELL_NIL, "flat: reset");
}

/* ---- the ring cache of a load is linear, and every search is bounded (hostile hives) ---- */

#define CACHE_FLAGS (RC_FLAGS | CM_CHECK_REGISTRY_CACHE_SECURITY)
#define IDENT 40000
#define IDENT_SD 65000

static double NowMs(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

/*
 * IDENT keys under a root without Security, each naming its own 'sk' cell, all
 * cells in one ring and all with the same bytes (a hive check accepts that:
 * the cells are just not shared). The load used to cost IDENT^2 / 2 steps
 * (every cell's ring walk asked whether each cell was cached by scanning the
 * one hash list all of them are in).
 */
static void TestRingCacheIdentical(void)
{
    static CMHIVE Cm;
    static HCELL_INDEX Cell[IDENT], Key[IDENT];
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Root, C, Ext;
    UCHAR Buf[sizeof(g_Sd)];
    WCHAR Name[32];
    ULONG i, Len, Deleted = 0;
    double T0, T1;

    printf("-- ring cache: %d cells with the same descriptor, one key each\n", IDENT);
    CHECK(NewHive(&Cm), "hive");
    Root = RootOf(Hive);
    Len = Sd(IDENT_SD, Buf);
    for (i = 0; i < IDENT; i++)
    {
        Cell[i] = Insert(&Cm, i, Stable);
        MakeName(Name, i, 0);
        Key[i] = KeyWith(Hive, Root, Name, Cell[i]);
    }
    /* now make the bytes identical */
    for (i = 0; i < IDENT; i++)
        memcpy(&Sk(Hive, Cell[i])->Descriptor, Buf, Len);
    HvMarkCellDirty(Hive, Root, FALSE);
    CHECK(HvWriteHive(Hive), "write");
    CmpFreeSecurityCache(&Cm);

    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    InitCache(&Cm);
    T0 = NowMs();
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, CACHE_FLAGS)), "check");
    T1 = NowMs();
    printf("   check + recount + ring cache: %.1f ms\n", T1 - T0);
#ifndef BASE_CMLIB
    CHECK(CacheEntries(&Cm) == Cm.SecurityCount && Cm.SecurityCount <= 256, "the list is bounded: %lu entries",
          (unsigned long)Cm.SecurityCount);
#endif
    CHECK(RingLength(Hive, Cell[0]) == IDENT, "one ring of %d", IDENT);

    /* the cache still shares, a new descriptor joins the ring, deletes keep it sound */
    T0 = NowMs();
    C = Find_(&Cm, IDENT_SD, Stable);
    CHECK(C != HCELL_NIL, "an identical cell is found");
    CHECK(Insert(&Cm, IDENT_SD, Stable) == C && Refs(Hive, C) == 2, "shared");
    Ext = Insert(&Cm, IDENT + 7, Stable);
    CHECK(Ext != HCELL_NIL && RingLength(Hive, Ext) == IDENT + 1, "a new cell joins the ring");
    for (i = 0; i < IDENT; i += 4)
    {
        CHECK(CmpFreeKeyByCell(Hive, Key[i], TRUE) == STATUS_SUCCESS, "delete %lu", (unsigned long)i);
        Deleted++;
    }
    T1 = NowMs();
    printf("   find, insert and %lu deletes: %.1f ms\n", (unsigned long)Deleted, T1 - T0);
    /* the deleted keys' cells: those of the keys that were shared stay */
    CHECK(RingLength(Hive, Ext) == (LONG)(IDENT + 1 - Deleted + (Sk(Hive, C) && C == Cell[0] ? 1 : 0)) ||
          RingLength(Hive, Ext) == (LONG)(IDENT + 1 - Deleted), "ring after deletes: %ld", (long)RingLength(Hive, Ext));
    CHECK(CacheEntries(&Cm) == Cm.SecurityCount, "cache entries == count");
    CHECK(Insert(&Cm, IDENT + 8, Stable) != HCELL_NIL && RingLength(Hive, Ext) > 0, "insert after the deletes");
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, RC_FLAGS)), "second check");
    CmpFreeSecurityCache(&Cm);
}

/*
 * Rings that do not close, met by the root walk (CmpBuildSecurityCache) and by
 * the walks of the cells keys name: a rho (a Flink back into the middle) and a
 * self loop off the start. Each walk ends after a few times the ring's length.
 */
static void TestRingCacheShapes(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Root, S[6], R[6];
    WCHAR Name[32];
    ULONG i;

    printf("-- ring cache: a rho off the root, a self loop, cells named by keys\n");
    CHECK(NewHive(&Cm), "hive");
    Root = RootOf(Hive);
    for (i = 0; i < 6; i++)
    {
        S[i] = Insert(&Cm, 500 + i, Stable);
        MakeName(Name, i, 1);
        KeyWith(Hive, Root, Name, S[i]);
    }
    ((PCM_KEY_NODE)HvGetCell(Hive, Root))->Security = S[0];
    Sk(Hive, S[0])->ReferenceCount++;
    /* the cache sees the ring as it is in the file; the check (which would heal it) is not run here */
    CmpFreeSecurityCache(&Cm);
    /* the ring in its order from S0: R0 = S0, R1, .. R5 */
    R[0] = S[0];
    for (i = 1; i < 6; i++)
        R[i] = Sk(Hive, R[i - 1])->Flink;
    CHECK(Sk(Hive, R[5])->Flink == S[0], "a ring of six");
    Sk(Hive, R[5])->Flink = R[2];     /* R0 .. R5 -> R2: a rho that misses S0 */
    CHECK(!CmpBuildSecurityCache(&Cm), "the rho is reported");
    CHECK(Cm.SecurityCount == 6 && CacheEntries(&Cm) == 6, "each cell cached once: %lu", (unsigned long)Cm.SecurityCount);
    Sk(Hive, R[1])->Flink = R[1];     /* R0 -> R1 -> R1 */
    CHECK(!CmpBuildSecurityCache(&Cm), "the self loop is reported");
    CHECK(Cm.SecurityCount == 2, "S0 and S1 cached: %lu", (unsigned long)Cm.SecurityCount);
    CmpFreeSecurityCache(&Cm);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    TestInsertDedup();
    TestRelease();
    TestKeyDelete();
    TestModel();
    TestLoadGood();
    TestCorrupt(0);
    TestCorrupt(1);
    TestCorruptShared();
    TestFlat();
    TestRecount();
    TestRecountDelete();
    TestRecountNoCells();
    TestRecountOrphan();
    TestRecountZero();
    TestRecountMany();
    TestRecountNoMemory();
    TestRecountRestart();
    TestRecountExitNode();
    TestRingCacheShapes();
    TestRingCacheIdentical();
    printf(g_Errors ? "RESULT: FAIL (%lu)\n" : "RESULT: PASS\n", (unsigned long)g_Errors);
    return g_Errors != 0;
}
