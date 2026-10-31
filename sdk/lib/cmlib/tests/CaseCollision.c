/*
 * PROJECT:     ReactOS cmlib regression tests
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     Two sibling key names that were distinct under the old Unicode
 *              case table and are equal under the present one (U+0436 and
 *              U+0416 in the same position): what the load-time repair does
 *              with them, and how the lookup, the enumeration, a create and a
 *              delete treat the pair afterwards.
 *
 *              Host test against the real cmlib sources and the real
 *              media/nls/l_intl.nls.
 *
 *              Usage: CaseCollision l_intl.nls            (the test)
 *                     CaseCollision l_intl.nls --gen DIR  (write the hive files
 *                       the oracle probe loads; see the ticket)
 */

#include "CmHostGlue.h"
#include <l_intl_upcase.h>      /* the upcase table as C data (boot loader, mkhive) */

/* The names of the sibling sets; "same" = equal under the present table */
static const WCHAR *g_CyrPair[] = { L"A\x0436", L"A\x0416" };            /* zhe, ZHE */
static const WCHAR *g_AscPair[] = { L"abc", L"ABC" };
static const WCHAR *g_Mix[] =
{
    L"Alpha", L"A\x0436", L"A\x0416", L"Beta", L"\x0434\x0436", L"\x0414\x0416",
    L"gamma", L"GAMMA", L"Omega", L"\x03c3x", L"\x03a3x", L"Zeta", L"\x042f", L"\x044f"
};
static const WCHAR *g_Ctl[] = { L"Alpha", L"A\x0436", L"Beta", L"\x0434\x0436", L"Zeta" };

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

/* ---- a hive that Windows can load: a root with a security descriptor ---- */

/* self-relative SD: owner and group Administrators, DACL Everyone full access */
static const UCHAR g_Sd[] =
{
    1, 0, 0x04, 0x80,           /* Revision, Sbz1, Control = DACL present | self relative */
    0x30, 0, 0, 0,              /* Owner at 48 */
    0x40, 0, 0, 0,              /* Group at 64 */
    0, 0, 0, 0,                 /* no SACL */
    0x14, 0, 0, 0,              /* DACL at 20 */
    /* DACL: revision 2, 1 ACE, 28 bytes */
    2, 0, 0x1c, 0, 1, 0, 0, 0,
    0, 0, 0x14, 0, 0x3f, 0, 0x1f, 0, /* ACCESS_ALLOWED_ACE, size 20, mask KEY_ALL_ACCESS */
    1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, /* S-1-1-0 */
    /* Owner S-1-5-32-544 */
    1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0,
    /* Group S-1-5-32-544 */
    1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0,
};

static HCELL_INDEX g_Sk;

static HCELL_INDEX MakeSecurity(PHHIVE Hive)
{
    HCELL_INDEX Cell = HvAllocateCell(Hive, FIELD_OFFSET(CM_KEY_SECURITY, Descriptor) + sizeof(g_Sd),
                                      Stable, HCELL_NIL);
    PCM_KEY_SECURITY Sk;

    if (Cell == HCELL_NIL)
        return Cell;
    Sk = (PCM_KEY_SECURITY)HvGetCell(Hive, Cell);
    RtlZeroMemory(Sk, FIELD_OFFSET(CM_KEY_SECURITY, Descriptor));
    Sk->Signature = CM_KEY_SECURITY_SIGNATURE;
    Sk->Flink = Sk->Blink = Cell;
    Sk->ReferenceCount = 0;
    Sk->DescriptorLength = sizeof(g_Sd);
    memcpy(&Sk->Descriptor, g_Sd, sizeof(g_Sd));
    return Cell;
}

static void UseSecurity(PHHIVE Hive, HCELL_INDEX Key)
{
    PCM_KEY_NODE Node = (PCM_KEY_NODE)HvGetCell(Hive, Key);

    Node->Security = g_Sk;
    ((PCM_KEY_SECURITY)HvGetCell(Hive, g_Sk))->ReferenceCount++;
}

static HCELL_INDEX NewKeyS(PHHIVE Hive, PCWSTR Text, HCELL_INDEX Parent)
{
    HCELL_INDEX Cell = NewKey(Hive, Text, Parent);

    if (Cell != HCELL_NIL)
        UseSecurity(Hive, Cell);
    return Cell;
}

static BOOLEAN AddS(PHHIVE Hive, HCELL_INDEX Parent, PCWSTR Text, PHCELL_INDEX Out)
{
    HCELL_INDEX Child = NewKeyS(Hive, Text, Parent);

    if (Out)
        *Out = Child;
    return Child != HCELL_NIL && CmpAddSubKey(Hive, Parent, Child);
}

/* ---- order of the entries of a one-leaf index ---- */

static PCM_KEY_INDEX LeafOf(PHHIVE Hive, HCELL_INDEX Parent, PHCELL_INDEX Cell)
{
    PCM_KEY_NODE P = (PCM_KEY_NODE)HvGetCell(Hive, Parent);

    *Cell = P->SubKeyLists[Stable];
    return (PCM_KEY_INDEX)HvGetCell(Hive, *Cell);
}

static HCELL_INDEX EntryCell(PCM_KEY_INDEX Leaf, ULONG i)
{
    if (Leaf->Signature == CM_KEY_INDEX_LEAF)
        return Leaf->List[i];
    return ((PCM_KEY_FAST_INDEX)Leaf)->List[i].Cell;
}

/* Raw name, as a string of WCHARs */
static void RawName(PHHIVE Hive, HCELL_INDEX Cell, WCHAR *W, PUNICODE_STRING S)
{
    ExpandName((PCM_KEY_NODE)HvGetCell(Hive, Cell), W, S);
}

static LONG RawCompare(PCUNICODE_STRING A, PCUNICODE_STRING B)
{
    ULONG i, n = min(A->Length, B->Length) / sizeof(WCHAR);

    for (i = 0; i < n; i++)
        if (A->Buffer[i] != B->Buffer[i])
            return (LONG)A->Buffer[i] - (LONG)B->Buffer[i];
    return (LONG)A->Length - (LONG)B->Length;
}

/*
 * Put the entries in the order case-insensitive compare gives, with names that
 * are equal in the order of their raw characters: ascending (Descending is
 * FALSE) or descending. A stable insertion sort of one leaf.
 */
static void SortLeaf(PHHIVE Hive, HCELL_INDEX Parent, BOOLEAN Descending)
{
    HCELL_INDEX LeafCell;
    PCM_KEY_INDEX Leaf = LeafOf(Hive, Parent, &LeafCell);
    PCM_KEY_FAST_INDEX Fast = (PCM_KEY_FAST_INDEX)Leaf;
    ULONG i, j;

    HvMarkCellDirty(Hive, LeafCell, FALSE);
    for (i = 1; i < Leaf->Count; i++)
    {
        for (j = i; j > 0; j--)
        {
            WCHAR WA[300], WB[300];
            UNICODE_STRING A, B;
            LONG R;

            RawName(Hive, EntryCell(Leaf, j - 1), WA, &A);
            RawName(Hive, EntryCell(Leaf, j), WB, &B);
            R = RtlCompareUnicodeString(&A, &B, TRUE);
            if (R == 0)
                R = Descending ? RawCompare(&B, &A) : RawCompare(&A, &B);
            if (R <= 0)
                break;
            if (Leaf->Signature == CM_KEY_INDEX_LEAF)
            {
                HCELL_INDEX T = Leaf->List[j];
                Leaf->List[j] = Leaf->List[j - 1];
                Leaf->List[j - 1] = T;
            }
            else
            {
                CM_INDEX T = Fast->List[j];
                Fast->List[j] = Fast->List[j - 1];
                Fast->List[j - 1] = T;
            }
        }
    }
}

/* ---- the hive files ---- */

/*
 * A hive: ROOT\P with the given names, each with a subkey "idN" (N = number
 * in the list) so that a probe can tell which key a lookup returned.
 */
static int BuildHive(ULONG Version, const WCHAR **Names, ULONG NameCount, BOOLEAN Descending, BOOLEAN SortOneLeaf)
{
    CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Root, P, Child, Marker;
    ULONG i;
    WCHAR Id[8];

    g_Errors = 0;
    if (!NT_SUCCESS(OpenHive(&Cm, HINIT_CREATE)))
        return 2;
    Hive->Version = Version;
    Hive->BaseBlock->Minor = Version;

    g_Sk = MakeSecurity(Hive);
    Root = NewKey(Hive, L"ROOT", HCELL_NIL);
    ((PCM_KEY_NODE)HvGetCell(Hive, Root))->Flags |= KEY_HIVE_ENTRY | KEY_NO_DELETE;
    UseSecurity(Hive, Root);
    Hive->BaseBlock->RootCell = Root;
    P = NewKeyS(Hive, L"P", Root);
    CHECK(CmpAddSubKey(Hive, Root, P), "parent");
    for (i = 0; i < NameCount; i++)
    {
        CHECK(AddS(Hive, P, Names[i], &Child), "add %lu", (unsigned long)i);
        Id[0] = L'i'; Id[1] = L'd'; Id[2] = L'0' + (i / 10); Id[3] = L'0' + (i % 10); Id[4] = 0;
        CHECK(AddS(Hive, Child, Id, &Marker), "marker %lu", (unsigned long)i);
    }
    if (SortOneLeaf)
        SortLeaf(Hive, P, Descending);
    HvMarkCellDirty(Hive, Root, FALSE);
    CHECK(HvWriteHive(Hive), "write");
    return g_Errors ? 2 : 0;
}

static int WriteFile_(const char *Dir, const char *Name)
{
    char Path[512];
    FILE *f;

    snprintf(Path, sizeof(Path), "%s/%s", Dir, Name);
    f = fopen(Path, "wb");
    if (!f || fwrite(g_File, 1, g_FileSize, f) != g_FileSize)
    {
        printf("cannot write %s\n", Path);
        return 2;
    }
    fclose(f);
    printf("wrote %s (%lu bytes)\n", Path, (unsigned long)g_FileSize);
    return 0;
}

static int GenAll(const char *Dir)
{
    static const struct { const char *Kind; const WCHAR **Names; ULONG Count; } Sets[] =
    {
        { "cyr", g_CyrPair, COUNT_OF(g_CyrPair) },
        { "asc", g_AscPair, COUNT_OF(g_AscPair) },
        { "mix", g_Mix, COUNT_OF(g_Mix) },
        { "ctl", g_Ctl, COUNT_OF(g_Ctl) },
    };
    ULONG s, Ver, Order;
    char Name[64];
    int r = 0;

    for (s = 0; s < COUNT_OF(Sets); s++)
        for (Ver = 3; Ver <= 5; Ver += 2)
            for (Order = 0; Order < 2; Order++)
            {
                if (BuildHive(Ver, Sets[s].Names, Sets[s].Count, Order != 0, TRUE))
                    return 2;
                snprintf(Name, sizeof(Name), "%s-%s-v%lu.hiv", Sets[s].Kind, Order ? "desc" : "asc",
                         (unsigned long)Ver);
                r |= WriteFile_(Dir, Name);
            }
    return r;
}

/* ---- the test ---- */

typedef struct _SIBLING
{
    HCELL_INDEX Cell;
    WCHAR Id[8];                /* the name of the marker subkey */
    WCHAR Name[40];
} SIBLING;

/* The children of P in index order */
static ULONG ListSiblings(PHHIVE Hive, HCELL_INDEX P, SIBLING *Out, ULONG Max)
{
    PCM_KEY_NODE Node = (PCM_KEY_NODE)HvGetCell(Hive, P);
    ULONG i, n = Node->SubKeyCounts[Stable];

    if (n > Max)
        n = Max;
    for (i = 0; i < n; i++)
    {
        PCM_KEY_NODE C, M;
        HCELL_INDEX Cell = CmpFindSubKeyByNumber(Hive, Node, i), MCell;
        UNICODE_STRING S;

        Out[i].Cell = Cell;
        Out[i].Id[0] = 0;
        if (Cell == HCELL_NIL)
            return i;
        C = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
        ExpandName(C, Out[i].Name, &S);
        Out[i].Name[S.Length / sizeof(WCHAR)] = 0;
        MCell = (C->SubKeyCounts[Stable] != 0) ? CmpFindSubKeyByNumber(Hive, C, 0) : HCELL_NIL;
        if (MCell != HCELL_NIL)
        {
            M = (PCM_KEY_NODE)HvGetCell(Hive, MCell);
            ExpandName(M, Out[i].Id, &S);
            Out[i].Id[min(S.Length / sizeof(WCHAR), 7)] = 0;
        }
    }
    return n;
}

static int Wcmp(const WCHAR *a, const WCHAR *b)
{
    while (*a && *a == *b)
        a++, b++;
    return (int)*a - (int)*b;
}

static BOOLEAN SameName(PCWSTR A, PCWSTR B)
{
    UNICODE_STRING UA, UB;

    RtlInitUnicodeString(&UA, A);
    RtlInitUnicodeString(&UB, B);
    return RtlCompareUnicodeString(&UA, &UB, TRUE) == 0;
}

static PUCHAR g_Saved;
static ULONG g_SavedSize;

static void SaveImage(void)
{
    free(g_Saved);
    g_Saved = malloc(g_FileSize);
    memcpy(g_Saved, g_File, g_FileSize);
    g_SavedSize = g_FileSize;
}

static void RestoreImage(void)
{
    g_File = realloc(g_File, g_SavedSize);
    memcpy(g_File, g_Saved, g_SavedSize);
    g_FileSize = g_SavedSize;
}

static HCELL_INDEX RootP(PHHIVE Hive)
{
    UNICODE_STRING Name;
    PCM_KEY_NODE Root = (PCM_KEY_NODE)HvGetCell(Hive, Hive->BaseBlock->RootCell);

    RtlInitUnicodeString(&Name, L"P");
    return CmpFindSubKeyByName(Hive, Root, &Name);
}

#define MAX_SIB 4000

/*
 * One hive file: the pair (or pairs) of siblings equal under the present table
 * is repaired the way Windows does it (measured on the oracle: the first of
 * the equal siblings in index order stays, the others are removed from the
 * parent), every spelling finds the key that stayed, nothing else is lost, and
 * once flushed a second load finds nothing to repair.
 */
static int RunCollision(const char *Label, const WCHAR **Names, ULONG NameCount, ULONG Version,
                        BOOLEAN Descending, BOOLEAN SortOneLeaf)
{
    static SIBLING Before[MAX_SIB], After[MAX_SIB], Expect[MAX_SIB];
    CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX P;
    CM_CHECK_REGISTRY_STATUS Status;
    ULONG nBefore, nAfter, nExpect = 0, i, j, Pairs = 0;
    ULONG Flags = CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES | CM_CHECK_REGISTRY_VALIDATE_HIVE;

    g_Errors = 0;
    printf("== %s, hive version %lu, %s\n", Label, (unsigned long)Version, Descending ? "descending" : "ascending");
    if (BuildHive(Version, Names, NameCount, Descending, SortOneLeaf))
        return 2;
    SaveImage();

    /* what Windows keeps: the first of every run of equal names, in index order */
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    if (g_Errors)
        return 2;
    P = RootP(Hive);
    nBefore = ListSiblings(Hive, P, Before, MAX_SIB);
    CHECK(nBefore == NameCount, "stored %lu siblings", (unsigned long)nBefore);
    for (i = 0; i < nBefore; i++)
    {
        if (i > 0 && SameName(Before[i - 1].Name, Before[i].Name))
        {
            Pairs++;
            continue;
        }
        Expect[nExpect++] = Before[i];
    }

    /* without self heal (the host, the boot loader) a pair is refused */
    Status = CmCheckRegistry(&Cm, Flags);
    if (Pairs)
        CHECK(Status == CM_CHECK_REGISTRY_BAD_LEXICOGRAPHICAL_ORDER, "check without fix: status %lu",
              (unsigned long)Status);
    else
        CHECK(CM_CHECK_REGISTRY_SUCCESS(Status), "check without fix of a hive without pairs: %lu",
              (unsigned long)Status);

    /* with it (the kernel) */
    RestoreImage();
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "reload");
    if (g_Errors)
        return 2;
    Status = CmCheckRegistry(&Cm, Flags | CM_CHECK_REGISTRY_FIX_HIVE);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Status), "check with fix: status %lu", (unsigned long)Status);
    if (!CM_CHECK_REGISTRY_SUCCESS(Status))
    {
        printf("RESULT: FAIL (the hive does not load)\n");
        return 1;
    }
    P = RootP(Hive);
    nAfter = ListSiblings(Hive, P, After, MAX_SIB);
    printf("%lu siblings, %lu equal to a previous one; after the repair %lu (Windows keeps %lu), dirty %lu\n",
           (unsigned long)nBefore, (unsigned long)Pairs, (unsigned long)nAfter, (unsigned long)nExpect,
           (unsigned long)Hive->DirtyCount);
    CHECK(nAfter == nExpect, "%lu siblings left, expected %lu", (unsigned long)nAfter, (unsigned long)nExpect);
    for (i = 0; i < nAfter && i < nExpect; i++)
    {
        CHECK(After[i].Cell == Expect[i].Cell, "sibling %lu: the key that stayed is not the first of its run", (unsigned long)i);
        CHECK(!Wcmp(After[i].Id, Expect[i].Id), "sibling %lu: id differs", (unsigned long)i);
    }
    CHECK(Pairs == 0 || Hive->DirtyCount != 0, "the repair left nothing dirty");
    CHECK(Pairs != 0 || Hive->DirtyCount == 0, "a hive without pairs was changed (dirty %lu)", (unsigned long)Hive->DirtyCount);

    /* every spelling finds the key that stayed */
    for (i = 0; i < NameCount; i++)
    {
        HCELL_INDEX Found = Find(Hive, P, Names[i]);
        BOOLEAN Ok = FALSE;

        for (j = 0; j < nExpect; j++)
            if (SameName(Expect[j].Name, Names[i]))
                Ok = (Found == Expect[j].Cell);
        CHECK(Ok, "lookup of spelling %lu finds the wrong key or none", (unsigned long)i);
    }
    /* strictly increasing now */
    for (i = 1; i < nAfter; i++)
        CHECK(!SameName(After[i - 1].Name, After[i].Name), "equal siblings left at %lu", (unsigned long)i);

    /* flush, load again: nothing to repair, the same keys */
    CHECK(HvSyncHive(Hive), "flush");
    CHECK(Hive->DirtyCount == 0, "dirty after the flush: %lu", (unsigned long)Hive->DirtyCount);
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "second load");
    if (g_Errors)
        return 2;
    Status = CmCheckRegistry(&Cm, Flags);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Status), "second check (no fix): %lu", (unsigned long)Status);
    CHECK(Cm.Hive.DirtyCount == 0, "second check changed the hive (dirty %lu)", (unsigned long)Cm.Hive.DirtyCount);
    P = RootP(&Cm.Hive);
    nAfter = ListSiblings(&Cm.Hive, P, After, MAX_SIB);
    CHECK(nAfter == nExpect, "second load: %lu siblings, expected %lu", (unsigned long)nAfter, (unsigned long)nExpect);
    for (i = 0; i < nAfter && i < nExpect; i++)
        CHECK(!Wcmp(After[i].Id, Expect[i].Id), "second load: sibling %lu differs", (unsigned long)i);

    printf(g_Errors ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return g_Errors != 0;
}

/* 3000 siblings over several leaves, a pair of every 60th, from the Cyrillic and ASCII classes */
static int RunBig(ULONG Version)
{
    static WCHAR Store[MAX_SIB][12];
    static const WCHAR *Names[MAX_SIB];
    ULONG n = 0, i;

    for (i = 0; i < 2900; i++)
    {
        WCHAR *w = Store[n];
        ULONG k = (i * 7919) % 2900;

        w[0] = (k % 3 == 0) ? 0x0428 + k % 24 : L'K';
        w[1] = L'0' + k / 1000 % 10; w[2] = L'0' + k / 100 % 10; w[3] = L'0' + k / 10 % 10; w[4] = L'0' + k % 10;
        w[5] = 0;
        Names[n] = w;
        n++;
        if (i % 60 == 0)
        {
            /* the twin: same name, the case of the first character (and of the ASCII letter) changed */
            WCHAR *t = Store[n];
            { ULONG q; for (q = 0; q < 6; q++) t[q] = w[q]; }
            t[0] = (w[0] == L'K') ? L'k' : (WCHAR)(w[0] + 0x20);
            Names[n] = t;
            n++;
        }
    }
    return RunCollision("big, several leaves", Names, n, Version, FALSE, FALSE);
}

/* ---- the boot loader: its upcase with the table as C data, against ASCII only ---- */

static WCHAR LoaderUpcase(WCHAR Source)
{
    return NlsUpcaseTableChar(Source);
}

/* What boot/rtl/nlsboot.c did before: ASCII only */
static WCHAR LoaderUpcaseAsciiOnly(WCHAR Source)
{
    return (Source >= 'a' && Source <= 'z') ? (WCHAR)(Source - ('a' - 'A')) : Source;
}

static const WCHAR *g_Lookup[] =
{
    L"Alpha", L"beta", L"Zeta", L"K1",
    L"\x0436\x0443\x043a", L"\x042f\x0440\x043b\x044b\x043a", L"\x0410\x043f\x0435\x043b\x044c\x0441\x0438\x043d",
    L"\x0428\x0430\x043f\x043a\x0430", L"\x0434\x043e\x043c", L"\x0441\x0442\x043e\x043b",
    L"\x03a9mega", L"\x03b1\x03b2\x03b3", L"\x0180" L"bar", L"\x0201x", L"\x00c0ngstr", L"\x00e9t\x00e9",
};

/* Case flip of a name: lower <-> upper with the table, so a lookup has to match another spelling */
static void OtherCase(PCWSTR In, WCHAR *Out)
{
    ULONG i;

    for (i = 0; In[i]; i++)
    {
        WCHAR Up = NlsUpcaseTableChar(In[i]);
        Out[i] = (Up != In[i]) ? Up : In[i];
    }
    Out[i] = 0;
}

/*
 * A hive in the order of the kernel's table (what the kernel and mkhive write),
 * looked up with the upcase of the boot loader: with the table every name is
 * found, also under another spelling; with ASCII only (what the loader had)
 * names with a character the table changes are not.
 */
static int RunLoaderLookup(void)
{
    CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    ULONG Pass, i, Found, FoundOther;
    HCELL_INDEX P;
    WCHAR Other[40];
    ULONG Failures = 0;

    g_Errors = 0;
    printf("== the boot loader's lookup of non-ASCII names\n");
    if (BuildHive(5, g_Lookup, COUNT_OF(g_Lookup), FALSE, FALSE))
        return 2;
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    if (g_Errors)
        return 2;
    P = RootP(Hive);

    for (Pass = 0; Pass < 2; Pass++)
    {
        g_UpcaseHook = Pass ? LoaderUpcaseAsciiOnly : LoaderUpcase;
        Found = FoundOther = 0;
        for (i = 0; i < COUNT_OF(g_Lookup); i++)
        {
            if (Find(Hive, P, g_Lookup[i]) != HCELL_NIL)
                Found++;
            OtherCase(g_Lookup[i], Other);
            if (Find(Hive, P, Other) != HCELL_NIL)
                FoundOther++;
        }
        printf("%s: found %lu of %lu by name, %lu of %lu by the name upper cased\n",
               Pass ? "ASCII-only upcase (the loader before)" : "table as C data (the loader now)",
               (unsigned long)Found, (unsigned long)COUNT_OF(g_Lookup),
               (unsigned long)FoundOther, (unsigned long)COUNT_OF(g_Lookup));
        if (Pass == 0)
        {
            CHECK(Found == COUNT_OF(g_Lookup), "the loader's table misses names");
            CHECK(FoundOther == COUNT_OF(g_Lookup), "the loader's table misses upper cased names");
        }
        else
        {
            Failures = (ULONG)(2 * COUNT_OF(g_Lookup)) - Found - FoundOther;
            /* informational: shows what the ASCII-only upcase gets wrong */
            printf("  (%lu lookups fail with ASCII only)\n", (unsigned long)Failures);
        }
    }
    g_UpcaseHook = NULL;
    CHECK(Failures != 0, "the test would not tell the two upcases apart");

    printf(g_Errors ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return g_Errors != 0;
}

/* The C copy of the upcase table (boot loader, mkhive) gives what l_intl.nls gives, for every character */
static int RunUpcaseHeader(void)
{
    ULONG c, Bad = 0, Changed = 0;

    printf("== l_intl_upcase.h against l_intl.nls\n");
    for (c = 0; c < 65536; c++)
    {
        WCHAR Want = NewUpcase((WCHAR)c);

        if (Want != (WCHAR)c)
            Changed++;
        if (NlsUpcaseTableChar((unsigned short)c) != Want)
        {
            if (Bad++ < 10)
                printf("FAIL: U+%04lX: header U+%04X, file U+%04X\n", (unsigned long)c,
                       NlsUpcaseTableChar((unsigned short)c), Want);
        }
    }
    printf("%lu characters have an upper case, %lu differ\n", (unsigned long)Changed, (unsigned long)Bad);
    printf(Bad ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return Bad != 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *Label; const WCHAR **Names; ULONG Count; } Sets[] =
    {
        { "Cyrillic pair", g_CyrPair, COUNT_OF(g_CyrPair) },
        { "ASCII pair (compressed names)", g_AscPair, COUNT_OF(g_AscPair) },
        { "mixed pairs", g_Mix, COUNT_OF(g_Mix) },
        { "control, no pair", g_Ctl, COUNT_OF(g_Ctl) },
    };
    ULONG s, Ver, Order;
    int r = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2 || !LoadTables(argv[1]))
    {
        printf("usage: %s l_intl.nls [--gen DIR]\n", argv[0]);
        return 2;
    }
    if (argc >= 4 && !strcmp(argv[2], "--gen"))
        return GenAll(argv[3]);

    r |= RunUpcaseHeader();
    r |= RunLoaderLookup();
    for (s = 0; s < COUNT_OF(Sets); s++)
        for (Ver = 3; Ver <= 5; Ver += 2)
            for (Order = 0; Order < 2; Order++)
                r |= RunCollision(Sets[s].Label, Sets[s].Names, Sets[s].Count, Ver, Order != 0, TRUE);
    r |= RunBig(5);
    r |= RunBig(3);
    printf(r ? "ALL: FAIL\n" : "ALL: PASS\n");
    return r;
}
