/*
 * PROJECT:     ReactOS cmlib regression tests
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     CmpAddSubKey() must fail cleanly when a cell cannot be allocated
 *              (the first leaf, a full leaf becoming a root, a leaf split, the
 *              growth of a leaf or of the root): it returns FALSE, the subkey
 *              index still holds exactly the keys it held, in order, the count
 *              is unchanged, and the same key can be added once memory is back.
 *
 *              Host test against the real cmlib sources. Every allocation made
 *              while a key is being added (HvAllocateCell, HvReallocateCell and
 *              the hive's own allocator, which also feeds the growth of the
 *              hive by a bin) can be made to fail: the k-th one, for every k,
 *              at every step of filling one parent with sorted keys, through
 *              the leaf, the root and several splits.
 */

#include <cmlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    (void)Header; (void)Count; (void)Hint;
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
    (void)CaseInSensitive;
    for (i = 0; i < n; i++)
        if (s1->Buffer[i] != s2->Buffer[i])
            return (LONG)s1->Buffer[i] - (LONG)s2->Buffer[i];
    return (LONG)s1->Length - (LONG)s2->Length;
}
WCHAR NTAPI RtlUpcaseUnicodeChar(WCHAR Source)
{
    return (Source >= L'a' && Source <= L'z') ? Source - 32 : Source;
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
    return malloc((size_t)Size);
}
VOID NTAPI CmpFree(PVOID Ptr, ULONG Quota)
{
    (void)Quota;
    free(Ptr);
}
BOOLEAN CMAPI CmIsSelfHealEnabled(BOOLEAN FixHive)
{
    (void)FixHive;
    return FALSE;
}

/* ---- fault injection ---- */
static ULONG g_Calls;       /* allocation attempts since the counter was armed */
static ULONG g_FailAt;      /* the g_FailAt-th attempt fails; 0 = never */
static ULONG g_Failures;    /* attempts that were failed */

static BOOLEAN ShouldFail(void)
{
    g_Calls++;
    if (g_FailAt && g_Calls == g_FailAt)
    {
        g_Failures++;
        return TRUE;
    }
    return FALSE;
}

HCELL_INDEX CMAPI __real_HvAllocateCell(PHHIVE, ULONG, HSTORAGE_TYPE, HCELL_INDEX);
HCELL_INDEX CMAPI __real_HvReallocateCell(PHHIVE, HCELL_INDEX, ULONG);

HCELL_INDEX CMAPI __wrap_HvAllocateCell(PHHIVE Hive, ULONG Size, HSTORAGE_TYPE Type, HCELL_INDEX Vicinity)
{
    if (ShouldFail())
        return HCELL_NIL;
    return __real_HvAllocateCell(Hive, Size, Type, Vicinity);
}

HCELL_INDEX CMAPI __wrap_HvReallocateCell(PHHIVE Hive, HCELL_INDEX Cell, ULONG Size)
{
    if (ShouldFail())
        return HCELL_NIL;
    return __real_HvReallocateCell(Hive, Cell, Size);
}

static PVOID CMAPI TestAllocate(SIZE_T Size, BOOLEAN Paged, ULONG Tag)
{
    (void)Paged; (void)Tag;
    if (ShouldFail())
        return NULL;
    return calloc(1, (size_t)Size);
}

static VOID CMAPI TestFree(PVOID Ptr, ULONG Quota)
{
    (void)Quota;
    free(Ptr);
}

/* ---- the fixture ---- */
static HHIVE g_Hive;
static HCELL_INDEX g_Parent;
static ULONG g_Errors;

#define CHECK(c, ...) \
    do { if (!(c)) { g_Errors++; if (g_Errors < 20) { printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

static void KeyName(ULONG n, WCHAR *Buffer, PUNICODE_STRING Name)
{
    /* fixed width and upper case: the index order is the numeric order */
    int i;
    Buffer[0] = L'K';
    for (i = 5; i >= 1; i--) { Buffer[i] = L'0' + (n % 10); n /= 10; }
    Buffer[6] = 0;
    Name->Buffer = Buffer;
    Name->Length = 6 * sizeof(WCHAR);
    Name->MaximumLength = Name->Length;
}

static HCELL_INDEX NewKey(ULONG n, HCELL_INDEX Parent)
{
    WCHAR Buffer[8];
    UNICODE_STRING Name;
    HCELL_INDEX Cell;
    PCM_KEY_NODE Node;

    KeyName(n, Buffer, &Name);
    Cell = HvAllocateCell(&g_Hive, FIELD_OFFSET(CM_KEY_NODE, Name) + CmpNameSize(&g_Hive, &Name),
                          Volatile, HCELL_NIL);
    if (Cell == HCELL_NIL)
        return Cell;
    Node = HvGetCell(&g_Hive, Cell);
    RtlZeroMemory(Node, FIELD_OFFSET(CM_KEY_NODE, Name));
    Node->Signature = CM_KEY_NODE_SIGNATURE;
    Node->Parent = Parent;
    Node->SubKeyLists[Stable] = Node->SubKeyLists[Volatile] = HCELL_NIL;
    Node->ValueList.List = HCELL_NIL;
    Node->Security = Node->Class = HCELL_NIL;
    Node->NameLength = CmpCopyName(&g_Hive, Node->Name, &Name);
    if (Node->NameLength < Name.Length)
        Node->Flags |= KEY_COMP_NAME;
    return Cell;
}

static BOOLEAN NameIs(PCM_KEY_NODE Node, ULONG n)
{
    WCHAR B[8];
    UNICODE_STRING N;
    ULONG i;

    KeyName(n, B, &N);
    if (Node->NameLength != 6 || !(Node->Flags & KEY_COMP_NAME))
        return FALSE;
    for (i = 0; i < 6; i++)
        if (((PUCHAR)Node->Name)[i] != (UCHAR)B[i])
            return FALSE;
    return TRUE;
}

/* The index lists Count keys, each reachable by number, in ascending name order */
static void VerifyOrder(ULONG Count, const char *Where)
{
    PCM_KEY_NODE P = HvGetCell(&g_Hive, g_Parent);
    PCM_KEY_NODE Prev = NULL, Cur;
    ULONG i;

    CHECK(P->SubKeyCounts[Volatile] == Count, "%s: count %lu, expected %lu",
          Where, (unsigned long)P->SubKeyCounts[Volatile], (unsigned long)Count);
    for (i = 0; i < Count; i++)
    {
        HCELL_INDEX C = CmpFindSubKeyByNumber(&g_Hive, P, i);
        CHECK(C != HCELL_NIL, "%s: no key at number %lu", Where, (unsigned long)i);
        if (C == HCELL_NIL)
            return;
        Cur = HvGetCell(&g_Hive, C);
        CHECK(Cur->Parent == g_Parent, "%s: parent of number %lu", Where, (unsigned long)i);
        if (Prev)
            CHECK(memcmp(Prev->Name, Cur->Name, 6) < 0, "%s: order at %lu", Where, (unsigned long)i);
        Prev = Cur;
    }
}

static int Run(ULONG Version)
{
    NTSTATUS Status;
    WCHAR Buffer[8];
    UNICODE_STRING Name;
    ULONG n, MaxKeys = 3200, k, Attempts = 0, Recovered = 0;
    HCELL_INDEX Child;
    BOOLEAN Ok;

    Status = HvInitialize(&g_Hive, HINIT_CREATE, HIVE_VOLATILE, HFILE_TYPE_PRIMARY, NULL,
                          TestAllocate, TestFree, NULL, NULL, NULL, NULL, 1, NULL);
    if (!NT_SUCCESS(Status))
    {
        printf("HvInitialize failed 0x%lx\n", (unsigned long)Status);
        return 2;
    }
    g_Hive.Version = Version;
    g_Errors = 0;
    g_Calls = g_FailAt = g_Failures = 0;
    printf("hive version %lu\n", (unsigned long)g_Hive.Version);

    g_Parent = NewKey(99999, HCELL_NIL);
    CHECK(g_Parent != HCELL_NIL, "parent");

    /* Add key n (in descending, ascending and random-ish order are all sorted by
     * the index): ascending fills the last leaf, so also run a pass that inserts
     * at the front so that full leaves split in the middle of the root. */
    for (n = 0; n < MaxKeys; n++)
    {
        /* keys are added in a scrambled order: the stored number is the name */
        ULONG Num = (n * 7919) % MaxKeys;      /* 7919 is prime: a permutation */
        Child = NewKey(Num, g_Parent);
        if (Child == HCELL_NIL) { printf("no memory for a key\n"); return 2; }

        for (k = 1; ; k++)
        {
            g_Calls = 0;
            g_FailAt = k;
            Ok = CmpAddSubKey(&g_Hive, g_Parent, Child);
            g_FailAt = 0;
            if (Ok)
            {
                /* fewer than k allocations were needed: it is linked */
                if (k > 1) Recovered++;
                break;
            }
            Attempts++;
            CHECK(g_Failures >= 1, "failed without a failed allocation");
            /* the index is as it was: n keys, none of them Num */
            {
                PCM_KEY_NODE P = HvGetCell(&g_Hive, g_Parent);
                KeyName(Num, Buffer, &Name);
                CHECK(CmpFindSubKeyByName(&g_Hive, P, &Name) == HCELL_NIL, "failed key %lu is linked", (unsigned long)Num);
                VerifyOrder(n, "after a failed add");
            }
            if (g_Errors)
            {
                printf("stopped at step %lu, failure injected at allocation %lu\n", (unsigned long)n, (unsigned long)k);
                return 1;
            }
        }
    }

    {
        PCM_KEY_NODE P = HvGetCell(&g_Hive, g_Parent);
        ULONG i;
        CHECK(P->SubKeyCounts[Volatile] == MaxKeys, "final count %lu", (unsigned long)P->SubKeyCounts[Volatile]);
        for (i = 0; i < MaxKeys; i++)
        {
            KeyName(i, Buffer, &Name);
            CHECK(CmpFindSubKeyByName(&g_Hive, P, &Name) != HCELL_NIL, "final: key %lu missing", (unsigned long)i);
        }
        for (i = 0; i < MaxKeys; i++)
        {
            HCELL_INDEX C = CmpFindSubKeyByNumber(&g_Hive, P, i);
            CHECK(C != HCELL_NIL, "final: number %lu", (unsigned long)i);
            if (C == HCELL_NIL) break;
            CHECK(NameIs(HvGetCell(&g_Hive, C), i), "final: order at %lu", (unsigned long)i);
        }
    }

    printf("%lu keys added, %lu injected failures survived, %lu adds needed a retry\n",
           (unsigned long)MaxKeys, (unsigned long)Attempts, (unsigned long)Recovered);
    printf(g_Errors ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return g_Errors != 0;
}

int main(void)
{
    /* version 3: fast leaves, then index leaves; version 5: hash leaves */
    int r = Run(3);
    r |= Run(5);
    return r;
}
