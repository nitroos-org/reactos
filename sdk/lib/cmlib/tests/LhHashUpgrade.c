/*
 * PROJECT:     ReactOS cmlib regression tests
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     A hive written while the old Unicode case table (the l_intl.nls
 *              before 6f1f2dbb8bf) was in use, loaded with the present one:
 *              its lh hashes of names with characters whose uppercase changed
 *              no longer match, and its names are not in order any more.
 *              CmCheckRegistry must bring the subkey indexes up to date: every
 *              key is found, the repair is dirty so that a flush writes it, and
 *              a second load finds nothing to repair.
 *
 *              Host test against the real cmlib sources. The case table is the
 *              real media/nls/l_intl.nls; "old" is that table with the
 *              uppercase of 341 characters set back to what the old one gave
 *              (LhHashUpgradeOldCase.h).
 *
 *              Usage: LhHashUpgrade l_intl.nls
 *                     LhHashUpgrade l_intl.nls --check HIVEFILE
 *                       (time the check of a hive file, no test; reports the
 *                        hive left dirty by it, i.e. what a load would repair)
 *                     LhHashUpgrade l_intl.nls --gen HIVEFILE KEYS PERCENT OLD
 *                       (write a hive of KEYS keys under 200 parents, PERCENT
 *                        of them with a Cyrillic name, made with the old table
 *                        if OLD is 1; to time --check on a big hive)
 */

#include <cmlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "LhHashUpgradeOldCase.h"

/* ---- the case tables ---- */
static USHORT *g_NlsTable;                /* the upcase table of l_intl.nls */
static BOOLEAN g_UseOldTable;
static WCHAR g_OldUpcaseMap[65536];       /* 0 = same as the present table */

static WCHAR NewUpcase(WCHAR Source)
{
    USHORT Offset;

    if (Source < 'a')
        return Source;
    if (Source <= 'z')
        return Source - ('a' - 'A');

    Offset = (Source >> 8) & 0xFF;
    Offset = g_NlsTable[Offset];
    Offset += (Source >> 4) & 0xF;
    Offset = g_NlsTable[Offset];
    Offset += Source & 0xF;
    Offset = g_NlsTable[Offset];
    return Source + (SHORT)Offset;
}

static BOOLEAN LoadTables(const char *Path)
{
    FILE *f = fopen(Path, "rb");
    long Size;
    USHORT *Image;
    size_t i;

    if (!f)
        return FALSE;
    fseek(f, 0, SEEK_END);
    Size = ftell(f);
    fseek(f, 0, SEEK_SET);
    Image = malloc(Size);
    if (!Image || fread(Image, 1, Size, f) != (size_t)Size)
        return FALSE;
    fclose(f);
    g_NlsTable = Image + 2;       /* the upcase table follows the two header words */

    for (i = 0; i < sizeof(g_OldUpcase) / sizeof(g_OldUpcase[0]); i++)
        g_OldUpcaseMap[g_OldUpcase[i].Char] = g_OldUpcase[i].OldUpcase ? g_OldUpcase[i].OldUpcase : 0xFFFF;
    return TRUE;
}

WCHAR NTAPI RtlUpcaseUnicodeChar(WCHAR Source)
{
    if (g_UseOldTable && g_OldUpcaseMap[Source])
        return g_OldUpcaseMap[Source];
    return NewUpcase(Source);
}

/* ---- what cmlib wants from the kernel ---- */
VOID NTAPI RtlInitializeBitMap(PRTL_BITMAP Header, PULONG Buffer, ULONG SizeOfBitMap)
{
    Header->SizeOfBitMap = SizeOfBitMap;
    Header->Buffer = Buffer;
}
VOID NTAPI RtlClearAllBits(PRTL_BITMAP Header)
{
    if (Header->Buffer)
        memset(Header->Buffer, 0x00, ((Header->SizeOfBitMap + 31) / 32) * sizeof(ULONG));
}
VOID NTAPI RtlSetAllBits(PRTL_BITMAP Header)
{
    if (Header->Buffer)
        memset(Header->Buffer, 0xFF, ((Header->SizeOfBitMap + 31) / 32) * sizeof(ULONG));
}
VOID NTAPI RtlSetBits(PRTL_BITMAP Header, ULONG Start, ULONG Count)
{
    ULONG i;
    for (i = Start; i < Start + Count; i++)
        Header->Buffer[i / 32] |= 1u << (i % 32);
}
ULONG NTAPI RtlFindSetBits(PRTL_BITMAP Header, ULONG Count, ULONG Hint)
{
    ULONG Pass, i, Run, Start, End;

    /* a run of Count set bits at or after Hint, else (wrapping) from the start */
    for (Pass = 0; Pass < 2; Pass++)
    {
        Start = Pass ? 0 : Hint;
        End = Pass ? Header->SizeOfBitMap : Header->SizeOfBitMap;
        Run = 0;
        for (i = Start; i < End; i++)
        {
            if (Header->Buffer[i / 32] & (1u << (i % 32)))
            {
                if (++Run == Count)
                    return i + 1 - Count;
            }
            else
            {
                Run = 0;
            }
        }
    }
    return 0xFFFFFFFF;
}
VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING String, PCWSTR Source)
{
    size_t n = 0;
    while (Source && Source[n]) n++;
    String->Buffer = (PWSTR)Source;
    String->Length = (USHORT)(n * sizeof(WCHAR));
    String->MaximumLength = String->Length + sizeof(WCHAR);
}
LONG NTAPI RtlCompareUnicodeString(PCUNICODE_STRING s1, PCUNICODE_STRING s2, BOOLEAN CaseInSensitive)
{
    ULONG i, n = min(s1->Length, s2->Length) / sizeof(WCHAR);

    for (i = 0; i < n; i++)
    {
        WCHAR c1 = s1->Buffer[i], c2 = s2->Buffer[i];
        if (c1 != c2 && CaseInSensitive)
        {
            c1 = RtlUpcaseUnicodeChar(c1);
            c2 = RtlUpcaseUnicodeChar(c2);
        }
        if (c1 != c2)
            return (LONG)c1 - (LONG)c2;
    }
    return (LONG)s1->Length - (LONG)s2->Length;
}
VOID NTAPI KeQuerySystemTime(PLARGE_INTEGER CurrentTime)
{
    if (CurrentTime)
        CurrentTime->QuadPart = 0;
}
VOID NTAPI
KeBugCheckEx(ULONG Code, ULONG_PTR P1, ULONG_PTR P2, ULONG_PTR P3, ULONG_PTR P4)
{
    (void)P1; (void)P2; (void)P3; (void)P4;
    fprintf(stderr, "unexpected KeBugCheckEx 0x%lx\n", (unsigned long)Code);
    abort();
}
PVOID NTAPI CmpAllocate(SIZE_T Size, BOOLEAN Paged, ULONG Tag)
{
    (void)Paged; (void)Tag;
    return calloc(1, (size_t)Size);
}
VOID NTAPI CmpFree(PVOID Ptr, ULONG Quota)
{
    (void)Quota;
    free(Ptr);
}
VOID NTAPI CmpFreeSecurityDescriptor(PHHIVE Hive, HCELL_INDEX Cell)
{
    (void)Hive; (void)Cell;
}

/* ---- the "file" of a hive: a buffer ---- */
static PUCHAR g_File;
static ULONG g_FileSize;

static BOOLEAN CMAPI FileSetSize(PHHIVE Hive, ULONG Type, ULONG Size, ULONG OldSize)
{
    PUCHAR New;
    (void)Hive; (void)Type; (void)OldSize;
    New = realloc(g_File, Size ? Size : 1);
    if (!New)
        return FALSE;
    if (Size > g_FileSize)
        memset(New + g_FileSize, 0, Size - g_FileSize);
    g_File = New;
    g_FileSize = Size;
    return TRUE;
}
static BOOLEAN CMAPI FileWrite(PHHIVE Hive, ULONG Type, PULONG Offset, PVOID Buffer, SIZE_T Length)
{
    (void)Type;
    if (*Offset + Length > g_FileSize && !FileSetSize(Hive, Type, (ULONG)(*Offset + Length), g_FileSize))
        return FALSE;
    memcpy(g_File + *Offset, Buffer, Length);
    return TRUE;
}
static BOOLEAN CMAPI FileRead(PHHIVE Hive, ULONG Type, PULONG Offset, PVOID Buffer, SIZE_T Length)
{
    (void)Hive; (void)Type;
    if (*Offset + Length > g_FileSize)
        return FALSE;
    memcpy(Buffer, g_File + *Offset, Length);
    return TRUE;
}
static BOOLEAN CMAPI FileFlush(PHHIVE Hive, ULONG Type, PLARGE_INTEGER Offset, ULONG Length)
{
    (void)Hive; (void)Type; (void)Offset; (void)Length;
    return TRUE;
}

static PVOID CMAPI TestAllocate(SIZE_T Size, BOOLEAN Paged, ULONG Tag)
{
    (void)Paged; (void)Tag;
    return calloc(1, (size_t)Size);
}
static VOID CMAPI TestFree(PVOID Ptr, ULONG Quota)
{
    (void)Quota;
    free(Ptr);
}

/* ---- the fixture ---- */
static ULONG g_Errors;
#define CHECK(c, ...) \
    do { if (!(c)) { g_Errors++; if (g_Errors < 30) { printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

static NTSTATUS OpenHive(PCMHIVE CmHive, ULONG Operation)
{
    NTSTATUS Status;

    memset(CmHive, 0, sizeof(*CmHive));
    /* a loaded hive file is read into memory: HINIT_MEMORY on the file image, as a boot hive is */
    Status = HvInitialize(&CmHive->Hive, Operation, 0, HFILE_TYPE_PRIMARY, g_File,
                          TestAllocate, TestFree, FileSetSize, FileWrite, FileRead, FileFlush, 1, NULL);
    if (!NT_SUCCESS(Status))
        printf("HvInitialize(%lu) failed 0x%lx\n", (unsigned long)Operation, (unsigned long)Status);
    return Status;
}

static HCELL_INDEX NewKey(PHHIVE Hive, PCWSTR Text, HCELL_INDEX Parent)
{
    UNICODE_STRING Name;
    HCELL_INDEX Cell;
    PCM_KEY_NODE Node;

    RtlInitUnicodeString(&Name, Text);
    Cell = HvAllocateCell(Hive, FIELD_OFFSET(CM_KEY_NODE, Name) + CmpNameSize(Hive, &Name),
                          Stable, HCELL_NIL);
    if (Cell == HCELL_NIL)
        return Cell;
    Node = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
    RtlZeroMemory(Node, FIELD_OFFSET(CM_KEY_NODE, Name));
    Node->Signature = CM_KEY_NODE_SIGNATURE;
    Node->Parent = Parent;
    Node->SubKeyLists[Stable] = Node->SubKeyLists[Volatile] = HCELL_NIL;
    Node->ValueList.List = HCELL_NIL;
    Node->Security = Node->Class = HCELL_NIL;
    Node->NameLength = CmpCopyName(Hive, Node->Name, &Name);
    if (Node->NameLength < Name.Length)
        Node->Flags |= KEY_COMP_NAME;
    return Cell;
}

static BOOLEAN Add(PHHIVE Hive, HCELL_INDEX Parent, PCWSTR Text)
{
    HCELL_INDEX Child = NewKey(Hive, Text, Parent);

    return Child != HCELL_NIL && CmpAddSubKey(Hive, Parent, Child);
}

static HCELL_INDEX Find(PHHIVE Hive, HCELL_INDEX Parent, PCWSTR Text)
{
    UNICODE_STRING Name;

    RtlInitUnicodeString(&Name, Text);
    return CmpFindSubKeyByName(Hive, (PCM_KEY_NODE)HvGetCell(Hive, Parent), &Name);
}

/* Names that sort differently, and hash differently, under the old table */
static const WCHAR *g_Special[] =
{
    L"Alpha", L"beta", L"Zeta", L"Sb", L"Tc", L"K1",                   /* ASCII siblings */
    L"\x0436\x0443\x043a",                                              /* zhuk: U+0436 */
    L"\x042f\x0440\x043b\x044b\x043a",                                  /* Yarlyk: U+042F */
    L"\x0410\x043f\x0435\x043b\x044c\x0441\x0438\x043d",                /* Apelsin */
    L"\x0428\x0430\x043f\x043a\x0430",                                  /* Shapka: U+0428 */
    L"\x0434\x043e\x043c", L"\x0441\x0442\x043e\x043b",                 /* dom, stol: unchanged */
    L"\x03c2" L"abc", L"\x03a9mega", L"\x03b1\x03b2\x03b3",             /* Greek: final sigma */
    L"\x0180" L"bar", L"\x0201x", L"\x017f" L"a",                       /* Latin Extended-B, long s */
    L"\x00b5m", L"\x00c0" L"ngstr",                                     /* micro sign (compressed names) */
};
#define SPECIAL_COUNT (sizeof(g_Special) / sizeof(g_Special[0]))

#define BIG_COUNT 3000
static void BigName(ULONG n, WCHAR *Buffer)
{
    static const WCHAR Lead[] = { L'K', 0x042f, 0x0436, 0x0428, 0x0448, 0x03c2, 0x0180, L'M' };
    ULONG Kind = (n * 7) % 8, i;

    Buffer[0] = Lead[Kind];
    for (i = 5; i >= 1; i--) { Buffer[i] = L'0' + (n % 10); n /= 10; }
    Buffer[6] = 0;
}

static void ExpandName(PCM_KEY_NODE N, WCHAR *W, PUNICODE_STRING S)
{
    ULONG k, n = N->NameLength / ((N->Flags & KEY_COMP_NAME) ? 1 : 2);

    for (k = 0; k < n; k++)
        W[k] = (N->Flags & KEY_COMP_NAME) ? ((PUCHAR)N->Name)[k] : N->Name[k];
    S->Buffer = W;
    S->Length = (USHORT)(n * sizeof(WCHAR));
    S->MaximumLength = S->Length;
}

/* Independent check of one subkey index: in order, hashes as the present table has them */
static void VerifyIndex(PHHIVE Hive, HCELL_INDEX Parent, ULONG Count, const char *Where)
{
    PCM_KEY_NODE P = (PCM_KEY_NODE)HvGetCell(Hive, Parent);
    HCELL_INDEX PrevCell = HCELL_NIL, Cell;
    PCM_KEY_NODE Prev, Cur;
    ULONG i;
    PCM_KEY_INDEX Top = (PCM_KEY_INDEX)HvGetCell(Hive, P->SubKeyLists[Stable]);
    ULONG Leaves = (Top->Signature == CM_KEY_INDEX_ROOT) ? Top->Count : 1, l, j, Seen = 0;

    CHECK(P->SubKeyCounts[Stable] == Count, "%s: count %lu, expected %lu", Where,
          (unsigned long)P->SubKeyCounts[Stable], (unsigned long)Count);

    for (i = 0; i < Count; i++)
    {
        UNICODE_STRING A, B;
        WCHAR WA[300], WB[300];

        Cell = CmpFindSubKeyByNumber(Hive, P, i);
        CHECK(Cell != HCELL_NIL, "%s: no key at number %lu", Where, (unsigned long)i);
        if (Cell == HCELL_NIL)
            return;
        Cur = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
        if (PrevCell != HCELL_NIL)
        {
            Prev = (PCM_KEY_NODE)HvGetCell(Hive, PrevCell);
            ExpandName(Prev, WA, &A);
            ExpandName(Cur, WB, &B);
            CHECK(RtlCompareUnicodeString(&A, &B, TRUE) < 0, "%s: not in order at %lu", Where, (unsigned long)i);
        }
        PrevCell = Cell;
    }

    /* the hash of every entry of every lh leaf */
    for (l = 0; l < Leaves; l++)
    {
        PCM_KEY_FAST_INDEX Leaf = (PCM_KEY_FAST_INDEX)((Top->Signature == CM_KEY_INDEX_ROOT) ?
                                  (PVOID)HvGetCell(Hive, Top->List[l]) : (PVOID)Top);
        if (Leaf->Signature != CM_KEY_HASH_LEAF)
            continue;
        for (j = 0; j < Leaf->Count; j++, Seen++)
        {
            PCM_KEY_NODE N = (PCM_KEY_NODE)HvGetCell(Hive, Leaf->List[j].Cell);
            WCHAR W[300];
            UNICODE_STRING S;

            ExpandName(N, W, &S);
            CHECK(Leaf->List[j].HashKey == CmpComputeHashKey(0, &S, FALSE),
                  "%s: hash of entry %lu of leaf %lu", Where, (unsigned long)j, (unsigned long)l);
        }
    }
    CHECK(Seen == 0 || Seen == Count, "%s: %lu entries in lh leaves, %lu keys", Where,
          (unsigned long)Seen, (unsigned long)Count);
}

static void CountFound(PHHIVE Hive, HCELL_INDEX Parent, ULONG *SpecialFound, ULONG *BigFound,
                       HCELL_INDEX BigParent)
{
    ULONG i;
    WCHAR Name[8];

    *SpecialFound = *BigFound = 0;
    for (i = 0; i < SPECIAL_COUNT; i++)
        if (Find(Hive, Parent, g_Special[i]) != HCELL_NIL)
            (*SpecialFound)++;
    for (i = 0; i < BIG_COUNT; i++)
    {
        BigName(i, Name);
        if (Find(Hive, BigParent, Name) != HCELL_NIL)
            (*BigFound)++;
    }
}

static HCELL_INDEX g_Root, g_Special1, g_Big;

static int BuildOldHive(ULONG Version)
{
    CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    ULONG i, n;
    WCHAR Name[8];

    if (!NT_SUCCESS(OpenHive(&Cm, HINIT_CREATE)))
        return 2;
    Hive->Version = Version;
    Hive->BaseBlock->Minor = Version;

    g_UseOldTable = TRUE;
    g_Root = NewKey(Hive, L"ROOT", HCELL_NIL);
    Hive->BaseBlock->RootCell = g_Root;
    g_Special1 = NewKey(Hive, L"Special", g_Root);
    g_Big = NewKey(Hive, L"Big", g_Root);
    CHECK(CmpAddSubKey(Hive, g_Root, g_Special1) && CmpAddSubKey(Hive, g_Root, g_Big), "parents");
    for (i = 0; i < SPECIAL_COUNT; i++)
        CHECK(Add(Hive, g_Special1, g_Special[i]), "add special %lu", (unsigned long)i);
    for (n = 0; n < BIG_COUNT; n++)
    {
        BigName((n * 7919) % BIG_COUNT, Name);          /* a permutation */
        CHECK(Add(Hive, g_Big, Name), "add big %lu", (unsigned long)n);
    }
    VerifyIndex(Hive, g_Special1, SPECIAL_COUNT, "old table, special");
    VerifyIndex(Hive, g_Big, BIG_COUNT, "old table, big");
    g_UseOldTable = FALSE;      /* VerifyIndex above ran with the old table; the new one is next */

    HvMarkCellDirty(Hive, g_Root, FALSE);
    if (!HvWriteHive(Hive))
    {
        printf("HvWriteHive failed\n");
        return 2;
    }
    return 0;
}

static int Run(ULONG Version)
{
    CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    ULONG SpecialFound, BigFound, DirtyAfter;
    ULONG Flags = CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES | CM_CHECK_REGISTRY_VALIDATE_HIVE;
    CM_CHECK_REGISTRY_STATUS Status;
    int r;

    g_Errors = 0;
    printf("== hive version %lu\n", (unsigned long)Version);
    r = BuildOldHive(Version);
    if (r)
        return r;
    printf("old table: hive file of %lu bytes, %lu + %d keys\n", (unsigned long)g_FileSize,
           (unsigned long)SPECIAL_COUNT, BIG_COUNT);

    /* ---- the present table, first load ---- */
    if (!NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)))
    {
        printf("load failed\n");
        return 2;
    }
    CountFound(Hive, g_Special1, &SpecialFound, &BigFound, g_Big);
    printf("present table, before the check: found %lu of %lu special, %lu of %d big\n",
           (unsigned long)SpecialFound, (unsigned long)SPECIAL_COUNT, (unsigned long)BigFound, BIG_COUNT);
    printf("  (names that were affected are not found, or the index is out of order)\n");
    Status = CmCheckRegistry(&Cm, Flags);
    printf("CmCheckRegistry: status %lu (0 = good)\n", (unsigned long)Status);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Status), "the check failed with %lu", (unsigned long)Status);
    if (!CM_CHECK_REGISTRY_SUCCESS(Status))
    {
        printf("RESULT: FAIL (the hive does not load)\n");
        return 1;
    }

    CountFound(Hive, g_Special1, &SpecialFound, &BigFound, g_Big);
    printf("after the check: found %lu of %lu special, %lu of %d big, dirty count %lu\n",
           (unsigned long)SpecialFound, (unsigned long)SPECIAL_COUNT, (unsigned long)BigFound,
           BIG_COUNT, (unsigned long)Hive->DirtyCount);
    CHECK(SpecialFound == SPECIAL_COUNT, "special keys found: %lu", (unsigned long)SpecialFound);
    CHECK(BigFound == BIG_COUNT, "big keys found: %lu", (unsigned long)BigFound);
    CHECK(Hive->DirtyCount != 0, "the repair left nothing dirty");
    VerifyIndex(Hive, g_Special1, SPECIAL_COUNT, "after the check, special");
    VerifyIndex(Hive, g_Big, BIG_COUNT, "after the check, big");

    /* ---- flush, then load again: nothing to repair ---- */
    CHECK(HvSyncHive(Hive), "flush");
    DirtyAfter = Hive->DirtyCount;
    CHECK(DirtyAfter == 0, "dirty count after the flush %lu", (unsigned long)DirtyAfter);

    if (!NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)))
    {
        printf("second load failed\n");
        return 2;
    }
    CountFound(Hive, g_Special1, &SpecialFound, &BigFound, g_Big);
    printf("second load, before the check: found %lu special, %lu big\n",
           (unsigned long)SpecialFound, (unsigned long)BigFound);
    CHECK(SpecialFound == SPECIAL_COUNT && BigFound == BIG_COUNT, "the flush did not write the repair");
    VerifyIndex(Hive, g_Special1, SPECIAL_COUNT, "second load, special");
    VerifyIndex(Hive, g_Big, BIG_COUNT, "second load, big");
    Status = CmCheckRegistry(&Cm, Flags);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Status), "second check %lu", (unsigned long)Status);
    printf("second check: status %lu, dirty count %lu\n", (unsigned long)Status, (unsigned long)Hive->DirtyCount);
    CHECK(Hive->DirtyCount == 0, "the second check found something to repair (dirty %lu)",
          (unsigned long)Hive->DirtyCount);

    printf(g_Errors ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return g_Errors != 0;
}

/*
 * One key whose name has a character with another uppercase, in order against
 * its ASCII siblings: the old hive loads, but the lookup misses and a create
 * adds a second key of the same name.
 */
static int RunHashOnly(void)
{
    static const WCHAR *Names[] = { L"Alpha", L"\x0436uk", L"Zeta" };
    CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Root, P;
    CM_CHECK_REGISTRY_STATUS Status;
    ULONG i, Count;

    g_Errors = 0;
    printf("== one changed hash, order unchanged\n");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_CREATE)), "create");
    Hive->Version = 5;                  /* hash leaves */
    Hive->BaseBlock->Minor = 5;
    g_UseOldTable = TRUE;
    Root = NewKey(Hive, L"ROOT", HCELL_NIL);
    Hive->BaseBlock->RootCell = Root;
    P = NewKey(Hive, L"P", Root);
    CHECK(CmpAddSubKey(Hive, Root, P), "parent");
    for (i = 0; i < 3; i++)
        CHECK(Add(Hive, P, Names[i]), "add %lu", (unsigned long)i);
    g_UseOldTable = FALSE;
    HvMarkCellDirty(Hive, Root, FALSE);
    CHECK(HvWriteHive(Hive), "write");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    if (g_Errors)
        return 1;

    Status = CmCheckRegistry(&Cm, CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES);
    printf("CmCheckRegistry: status %lu, dirty count %lu\n", (unsigned long)Status,
           (unsigned long)Hive->DirtyCount);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Status), "check %lu", (unsigned long)Status);
    if (Find(Hive, P, Names[1]) == HCELL_NIL)
    {
        printf("lookup of the Cyrillic key MISSES; a create adds ");
        CHECK(Add(Hive, P, Names[1]), "create");
        Count = ((PCM_KEY_NODE)HvGetCell(Hive, P))->SubKeyCounts[Stable];
        printf("a duplicate: %lu subkeys instead of 3\n", (unsigned long)Count);
        g_Errors++;
    }
    else
    {
        printf("lookup of the Cyrillic key finds it\n");
    }
    printf(g_Errors ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return g_Errors != 0;
}

/* A hive made of ASCII names only is left alone by the check */
static int RunAscii(void)
{
    CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    WCHAR Name[8];
    ULONG i;
    HCELL_INDEX Root, P;
    CM_CHECK_REGISTRY_STATUS Status;

    g_Errors = 0;
    printf("== ASCII hive\n");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_CREATE)), "create");
    Root = NewKey(Hive, L"ROOT", HCELL_NIL);
    Hive->BaseBlock->RootCell = Root;
    P = NewKey(Hive, L"P", Root);
    CHECK(CmpAddSubKey(Hive, Root, P), "parent");
    for (i = 0; i < 2000; i++)
    {
        Name[0] = L'K';
        Name[1] = L'0' + (i * 7919 % 2000) / 1000 % 10;
        Name[2] = L'0' + (i * 7919 % 2000) / 100 % 10;
        Name[3] = L'0' + (i * 7919 % 2000) / 10 % 10;
        Name[4] = L'0' + (i * 7919 % 2000) % 10;
        Name[5] = 0;
        CHECK(Add(Hive, P, Name), "add %lu", (unsigned long)i);
    }
    HvMarkCellDirty(Hive, Root, FALSE);
    CHECK(HvWriteHive(Hive), "write");
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "load");
    if (g_Errors)
        return 1;
    Status = CmCheckRegistry(&Cm, CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Status), "check %lu", (unsigned long)Status);
    CHECK(Hive->DirtyCount == 0, "an ASCII hive was changed (dirty %lu)", (unsigned long)Hive->DirtyCount);
    printf(g_Errors ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return g_Errors != 0;
}

/* Time CmCheckRegistry on a hive file */
static int CheckFile(const char *Path)
{
    FILE *f = fopen(Path, "rb");
    CMHIVE Cm;
    struct timespec t0, t1;
    CM_CHECK_REGISTRY_STATUS Status;
    NTSTATUS St;
    double ms;
    ULONG Dirty0;

    if (!f)
    {
        printf("cannot open %s\n", Path);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    g_FileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    g_File = malloc(g_FileSize);
    if (!g_File || fread(g_File, 1, g_FileSize, f) != g_FileSize)
        return 2;
    fclose(f);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    St = OpenHive(&Cm, HINIT_MEMORY);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (!NT_SUCCESS(St))
    {
        printf("load failed 0x%lx\n", (unsigned long)St);
        return 2;
    }
    ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    printf("%s: %lu bytes, HvInitialize %.1f ms\n", Path, (unsigned long)g_FileSize, ms);
    Dirty0 = Cm.Hive.DirtyCount;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    Status = CmCheckRegistry(&Cm, CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    printf("CmCheckRegistry: status %lu, %.1f ms, dirty count %lu -> %lu\n", (unsigned long)Status, ms,
           (unsigned long)Dirty0, (unsigned long)Cm.Hive.DirtyCount);
    return !CM_CHECK_REGISTRY_SUCCESS(Status);
}

/* A big hive to time the check: KEYS keys in 200 parents, Percent of them with a Cyrillic name */
static int GenFile(const char *Path, ULONG Keys, ULONG Percent, BOOLEAN Old)
{
    CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Root, P[200];
    ULONG n, i;
    WCHAR Name[16];
    FILE *f;

    if (!NT_SUCCESS(OpenHive(&Cm, HINIT_CREATE)))
        return 2;
    Hive->Version = 5;
    Hive->BaseBlock->Minor = 5;
    g_UseOldTable = Old;
    Root = NewKey(Hive, L"ROOT", HCELL_NIL);
    Hive->BaseBlock->RootCell = Root;
    for (i = 0; i < 200; i++)
    {
        Name[0] = L'P'; Name[1] = L'0' + i / 100; Name[2] = L'0' + i / 10 % 10; Name[3] = L'0' + i % 10; Name[4] = 0;
        P[i] = NewKey(Hive, Name, Root);
        if (!CmpAddSubKey(Hive, Root, P[i]))
            return 2;
    }
    for (n = 0; n < Keys; n++)
    {
        ULONG m = (ULONG)(((unsigned long long)n * 2654435761u) % Keys);
        ULONG v = m, k;

        Name[0] = (m % 100 < Percent) ? (WCHAR)(0x0428 + m % 24) : L'K';
        for (k = 8; k >= 1; k--) { Name[k] = L'0' + v % 10; v /= 10; }
        Name[9] = L'a' + m % 26;
        Name[10] = 0;
        if (!Add(Hive, P[m % 200], Name))
        {
            printf("add %lu failed\n", (unsigned long)n);
            return 2;
        }
    }
    g_UseOldTable = FALSE;
    HvMarkCellDirty(Hive, Root, FALSE);
    if (!HvWriteHive(Hive))
        return 2;
    f = fopen(Path, "wb");
    if (!f || fwrite(g_File, 1, g_FileSize, f) != g_FileSize)
        return 2;
    fclose(f);
    printf("%s: %lu bytes, %lu keys, %lu%% Cyrillic, %s table\n", Path, (unsigned long)g_FileSize,
           (unsigned long)Keys, (unsigned long)Percent, Old ? "old" : "present");
    return 0;
}

int main(int argc, char **argv)
{
    int r = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2 || !LoadTables(argv[1]))
    {
        printf("usage: %s l_intl.nls [--check HIVEFILE]\n", argv[0]);
        return 2;
    }
    if (argc >= 4 && !strcmp(argv[2], "--check"))
        return CheckFile(argv[3]);
    if (argc >= 7 && !strcmp(argv[2], "--gen"))
        return GenFile(argv[3], atoi(argv[4]), atoi(argv[5]), atoi(argv[6]) != 0);

    /* version 3: fast leaves and index leaves; version 5: hash leaves */
    r |= Run(5);
    r |= Run(3);
    r |= RunHashOnly();
    r |= RunAscii();
    return r;
}
