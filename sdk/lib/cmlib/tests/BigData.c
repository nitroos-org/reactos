/*
 * PROJECT:     ReactOS cmlib regression tests
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     Big data values: in a hive of format 1.4 or later, data longer
 *              than 16344 bytes is a 'db' cell naming a list of segments
 *              (layout: the public "Windows registry file format
 *              specification" by Maxim Suhanov, github.com/msuhanov/regf,
 *              section "Big data"). The check must keep a sound chain and
 *              leave the file as it is, and drop a value whose chain is not
 *              sound (and nothing else); the readers put the segments
 *              together; the writers store such data as big data in a 1.4+
 *              hive and as one cell in an older one, and free every cell of a
 *              chain; a copy converts between the two. Every hive here is
 *              made by cmlib, written to a "file" and loaded from it as the
 *              kernel loads a hive file.
 *
 *              Usage: BigData NLS [--max]
 *              (--max adds the largest chain, 65535 segments: about 1 GB)
 *              Exit code 0 = PASS.
 */

#include "CmHostGlue.h"

#define SEG CM_KEY_VALUE_BIG    /* 16344 */

/* The kernel loads a hive file with self-healing on (CmpSelfHeal); here that is FIX_HIVE */
static const ULONG g_LoadFlags = CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES | CM_CHECK_REGISTRY_RECOUNT_SECURITY |
                                 CM_CHECK_REGISTRY_CACHE_SECURITY | CM_CHECK_REGISTRY_FIX_HIVE;
static const ULONG g_LiveFlags = CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES | CM_CHECK_REGISTRY_VALIDATE_HIVE |
                                 CM_CHECK_REGISTRY_LIVE_HIVE;

static void InitCache(PCMHIVE Cm)
{
    ULONG i;

    for (i = 0; i < CMP_SECURITY_HASH_LISTS; i++)
        InitializeListHead(&Cm->SecurityHash[i]);
    Cm->SecurityCount = 0;
    Cm->SecurityRingAnchor[Stable] = HCELL_NIL;
    Cm->SecurityRingAnchor[Volatile] = HCELL_NIL;
}

/* ---- data ---- */
static UCHAR Pat(ULONG i, ULONG Seed)
{
    return (UCHAR)(i * 31u + Seed + (i >> 9) * 7u);
}

static PUCHAR MakeData(ULONG Length, ULONG Seed)
{
    PUCHAR B = malloc(Length ? Length : 1);
    ULONG i;

    for (i = 0; i < Length; i++)
        B[i] = Pat(i, Seed);
    return B;
}

/* ---- hives ---- */
static HCELL_INDEX g_Root;

/* A new hive of format 1.Minor with a root key */
static BOOLEAN NewHive(PCMHIVE Cm, ULONG Minor)
{
    PHHIVE Hive = &Cm->Hive;

    if (!NT_SUCCESS(OpenHive(Cm, HINIT_CREATE)))
        return FALSE;
    InitCache(Cm);
    Hive->Version = Minor;
    Hive->BaseBlock->Minor = Minor;
    g_Root = NewKey(Hive, L"ROOT", HCELL_NIL);
    ((PCM_KEY_NODE)HvGetCell(Hive, g_Root))->Flags |= KEY_HIVE_ENTRY | KEY_NO_DELETE;
    Hive->BaseBlock->RootCell = g_Root;
    return TRUE;
}

static HCELL_INDEX SubKey(PHHIVE Hive, HCELL_INDEX Parent, PCWSTR Name)
{
    HCELL_INDEX K = NewKey(Hive, Name, Parent);

    CHECK(K != HCELL_NIL && CmpAddSubKey(Hive, Parent, K), "add key");
    return K;
}

#define REG_BINARY_ 3
#define COUNT_OF_LENGTHS (sizeof(g_Lengths) / sizeof(g_Lengths[0]))

/* "v<number>" */
static void ValueName(WCHAR *Out, ULONG Number)
{
    char Narrow[16];
    int i, n = snprintf(Narrow, sizeof(Narrow), "v%lu", (unsigned long)Number);

    for (i = 0; i <= n; i++)
        Out[i] = (WCHAR)Narrow[i];
}

/* What CmpSetValueKeyNew of the kernel does: a value cell, its data (CmpSetValueDataNew), the list */
static HCELL_INDEX AddValueCell(PHHIVE Hive, HCELL_INDEX Key, PCWSTR Text, ULONG Type, HCELL_INDEX DataCell,
                                ULONG DataLength, ULONG Small)
{
    UNICODE_STRING Name;
    HCELL_INDEX Cell;
    PCM_KEY_VALUE V;
    PCM_KEY_NODE N;

    RtlInitUnicodeString(&Name, Text);
    Cell = HvAllocateCell(Hive, FIELD_OFFSET(CM_KEY_VALUE, Name) + CmpNameSize(Hive, &Name), Stable, HCELL_NIL);
    if (Cell == HCELL_NIL)
        return Cell;
    V = (PCM_KEY_VALUE)HvGetCell(Hive, Cell);
    memset(V, 0, FIELD_OFFSET(CM_KEY_VALUE, Name));
    V->Signature = CM_KEY_VALUE_SIGNATURE;
    V->Type = Type;
    V->NameLength = CmpCopyName(Hive, V->Name, &Name);
    if (V->NameLength < Name.Length)
        V->Flags |= VALUE_COMP_NAME;
    V->DataLength = DataLength;
    V->Data = (DataLength & CM_KEY_VALUE_SPECIAL_SIZE) ? Small : DataCell;

    N = (PCM_KEY_NODE)HvGetCell(Hive, Key);
    HvMarkCellDirty(Hive, Key, FALSE);
    if (N->ValueList.List != HCELL_NIL)
        HvMarkCellDirty(Hive, N->ValueList.List, FALSE);
    CHECK(NT_SUCCESS(CmpAddValueToList(Hive, Cell, N->ValueList.Count, Stable, &N->ValueList)), "add to list");
    N = (PCM_KEY_NODE)HvGetCell(Hive, Key);
    if (N->MaxValueNameLen < Name.Length)
        N->MaxValueNameLen = Name.Length;
    if (N->MaxValueDataLen < (DataLength & ~CM_KEY_VALUE_SPECIAL_SIZE))
        N->MaxValueDataLen = DataLength & ~CM_KEY_VALUE_SPECIAL_SIZE;
    return Cell;
}

static HCELL_INDEX SetValue(PHHIVE Hive, HCELL_INDEX Key, PCWSTR Text, ULONG Length, ULONG Seed)
{
    PUCHAR Data = MakeData(Length, Seed);
    HCELL_INDEX DataCell = HCELL_NIL, Cell;
    ULONG Small = 0;
    NTSTATUS Status;

    if (Length <= CM_KEY_VALUE_SMALL)
    {
        memcpy(&Small, Data, Length);
        Cell = AddValueCell(Hive, Key, Text, REG_BINARY_, HCELL_NIL, Length | CM_KEY_VALUE_SPECIAL_SIZE, Small);
    }
    else
    {
        Status = CmpSetValueDataNew(Hive, Data, Length, Stable, HCELL_NIL, &DataCell);
        CHECK(NT_SUCCESS(Status), "store %lu bytes: 0x%lx", (unsigned long)Length, (unsigned long)Status);
        Cell = NT_SUCCESS(Status) ? AddValueCell(Hive, Key, Text, REG_BINARY_, DataCell, Length, 0) : HCELL_NIL;
    }
    free(Data);
    return Cell;
}

static HCELL_INDEX FindValue(PHHIVE Hive, HCELL_INDEX Key, PCWSTR Text)
{
    UNICODE_STRING Name;

    RtlInitUnicodeString(&Name, Text);
    return CmpFindValueByName(Hive, (PCM_KEY_NODE)HvGetCell(Hive, Key), &Name);
}

/* Every byte of the value as CmpGetValueData gives it; the buffer of big data is freed */
static BOOLEAN DataIs(PHHIVE Hive, HCELL_INDEX ValueCell, ULONG Length, ULONG Seed)
{
    PCM_KEY_VALUE V;
    PVOID Buffer;
    BOOLEAN Allocated, Same = TRUE;
    HCELL_INDEX Release;
    ULONG Got, i;

    if (ValueCell == HCELL_NIL)
        return FALSE;
    V = (PCM_KEY_VALUE)HvGetCell(Hive, ValueCell);
    if (!CmpGetValueData(Hive, V, &Got, &Buffer, &Allocated, &Release))
        return FALSE;
    if (Got != Length)
        Same = FALSE;
    for (i = 0; Same && i < Length; i++)
        if (((PUCHAR)Buffer)[i] != Pat(i, Seed))
            Same = FALSE;
    if (Allocated)
        Hive->Free(Buffer, 0);
    return Same;
}

/* The cells of a chain (the 'db' cell, the list, the segments) */
typedef struct { HCELL_INDEX Db, List; ULONG Count; HCELL_INDEX Seg[8]; } CHAIN;
static BOOLEAN Chain(PHHIVE Hive, HCELL_INDEX ValueCell, CHAIN *C)
{
    PCM_KEY_VALUE V = (PCM_KEY_VALUE)HvGetCell(Hive, ValueCell);
    PCM_BIG_DATA B;
    PHCELL_INDEX L;
    ULONG i;

    memset(C, 0xFF, sizeof(*C));
    C->Count = 0;
    if (V->DataLength & CM_KEY_VALUE_SPECIAL_SIZE || V->Data == HCELL_NIL)
        return FALSE;
    B = (PCM_BIG_DATA)HvGetCell(Hive, V->Data);
    if (HvGetCellSize(Hive, B) >= (LONG)V->DataLength || B->Signature != CM_BIG_DATA_SIGNATURE)
        return FALSE;
    C->Db = V->Data;
    C->List = B->List;
    C->Count = B->Count;
    L = (PHCELL_INDEX)HvGetCell(Hive, B->List);
    for (i = 0; i < B->Count && i < 8; i++)
        C->Seg[i] = L[i];
    return TRUE;
}

/*
 * The layout a Windows reader accepts (measured on a Windows Server 2022 peer): the list holds exactly the segments the
 * data needs, every segment cell, the last too, holds SEG bytes (not smaller), and what the data does not use is zero.
 */
static void CheckLayout(PHHIVE Hive, const CHAIN *C, ULONG Length)
{
    ULONG s, Used;
    PUCHAR P;

    CHECK(C->Count == CMP_BIG_DATA_SEGMENTS(Length), "length %lu: exactly the segments needed (%lu)",
          (unsigned long)Length, (unsigned long)C->Count);
    for (s = 0; s < C->Count && s < 8; s++)
    {
        P = (PUCHAR)HvGetCell(Hive, C->Seg[s]);
        Used = (s + 1 < C->Count) ? SEG : Length - s * SEG;
        CHECK(HvGetCellSize(Hive, P) >= (LONG)SEG, "length %lu: segment %lu holds at least %lu bytes",
              (unsigned long)Length, (unsigned long)s, (unsigned long)SEG);
        CHECK(HvGetCellSize(Hive, P) < (LONG)SEG + 16, "length %lu: segment %lu is not oversized",
              (unsigned long)Length, (unsigned long)s);
        for (; Used < SEG; Used++)
            if (P[Used] != 0)
                break;
        CHECK(Used == SEG, "length %lu: the tail of segment %lu is zero", (unsigned long)Length, (unsigned long)s);
    }
}

/* Allocated bytes of the stable storage (cells tile the bins) */
static ULONG AllocatedBytes(PHHIVE Hive)
{
    ULONG Block = 0, Off, Total = 0;

    while (Block < Hive->Storage[Stable].Length)
    {
        PHBIN Bin = (PHBIN)Hive->Storage[Stable].BlockList[Block].BinAddress;
        for (Off = sizeof(HBIN); Off < Bin->Size; )
        {
            LONG S = ((PHCELL)((PUCHAR)Bin + Off))->Size;
            if (S < 0)
            {
                Total += (ULONG)-S;
                Off += (ULONG)-S;
            }
            else
            {
                Off += (ULONG)S;
            }
        }
        Block += Bin->Size / HBLOCK_SIZE;
    }
    return Total;
}

/* Load g_File as the kernel loads a hive file; the check's status, and whether it changed anything */
static CM_CHECK_REGISTRY_STATUS Load(PCMHIVE Cm, BOOLEAN *Changed)
{
    CM_CHECK_REGISTRY_STATUS St;
    ULONG Before;

    if (!NT_SUCCESS(OpenHive(Cm, HINIT_MEMORY)))
        return CM_CHECK_REGISTRY_HIVE_CORRUPT_SIGNATURE;
    InitCache(Cm);
    Before = Cm->Hive.BaseBlock->BootType;
    St = CmCheckRegistry(Cm, g_LoadFlags);
    if (Changed)
        *Changed = Cm->Hive.DirtyCount != 0 || Cm->Hive.BaseBlock->BootType != Before;
    return St;
}

static void Unload(PCMHIVE Cm)
{
    CmpFreeSecurityCache(Cm);
    HvFree(&Cm->Hive);
}

static PUCHAR SaveFile(ULONG *Size)
{
    PUCHAR Copy = malloc(g_FileSize);

    memcpy(Copy, g_File, g_FileSize);
    *Size = g_FileSize;
    return Copy;
}

static void RestoreFile(PUCHAR Copy, ULONG Size)
{
    FileSetSize(NULL, 0, Size, g_FileSize);
    memcpy(g_File, Copy, Size);
}

/* ---- 1: the writers and the readers, boundary lengths, both formats ---- */
static const ULONG g_Lengths[] = { 0, 1, 4, 5, 100, 4096, SEG - 1, SEG, SEG + 1, 2 * SEG, 2 * SEG + 1,
                                   4 * SEG + 1, 5 * SEG, 40000, 100000 };

static void TestWriteRead(ULONG Minor)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX K, V[COUNT_OF_LENGTHS];
    WCHAR Name[32];
    ULONG i, Base, After;
    BOOLEAN Changed;
    PUCHAR Before;
    ULONG BeforeSize;
    CHAIN C;

    printf("-- format 1.%lu: values of every boundary length are stored, read back, written, loaded unchanged\n",
           (unsigned long)Minor);
    CHECK(NewHive(&Cm, Minor), "new hive");
    K = SubKey(Hive, g_Root, L"Values");
    Base = AllocatedBytes(Hive);
    for (i = 0; i < COUNT_OF_LENGTHS; i++)
    {
        ValueName(Name, g_Lengths[i]);
        V[i] = SetValue(Hive, K, Name, g_Lengths[i], i + Minor);
        CHECK(DataIs(Hive, V[i], g_Lengths[i], i + Minor), "length %lu reads back", (unsigned long)g_Lengths[i]);
        if (Minor >= 4 && g_Lengths[i] > SEG)
        {
            CHECK(Chain(Hive, V[i], &C), "length %lu is big data", (unsigned long)g_Lengths[i]);
            CHECK(C.Count == CMP_BIG_DATA_SEGMENTS(g_Lengths[i]), "length %lu: %lu segments",
                  (unsigned long)g_Lengths[i], (unsigned long)C.Count);
            CHECK(CmpValueToData(Hive, (PCM_KEY_VALUE)HvGetCell(Hive, V[i]), &After) == NULL,
                  "the boot-time reader refuses big data");

            CheckLayout(Hive, &C, g_Lengths[i]);
        }
        else if (g_Lengths[i] > SEG)
        {
            /* an older format: one cell, as before */
            PCM_KEY_VALUE Vk = (PCM_KEY_VALUE)HvGetCell(Hive, V[i]);
            CHECK(!Chain(Hive, V[i], &C) &&
                  HvGetCellSize(Hive, HvGetCell(Hive, Vk->Data)) >= (LONG)g_Lengths[i],
                  "1.%lu: length %lu in one cell", (unsigned long)Minor, (unsigned long)g_Lengths[i]);
            CHECK(CmpValueToData(Hive, Vk, &After) != NULL && After == g_Lengths[i], "the boot-time reader reads it");
        }
    }
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_LiveFlags)), "live check of what was written");
    CHECK(HvWriteHive(Hive), "write");
    Unload(&Cm);

    Before = SaveFile(&BeforeSize);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)), "load");
    CHECK(!Changed, "the check changed a valid hive");
    for (i = 0; i < COUNT_OF_LENGTHS; i++)
    {
        ValueName(Name, g_Lengths[i]);
        CHECK(DataIs(Hive, FindValue(Hive, Find(Hive, g_Root, L"Values"), Name), g_Lengths[i], i + Minor),
              "after the load, length %lu reads back", (unsigned long)g_Lengths[i]);
    }
    CHECK(HvSyncHive(Hive), "sync");
    CHECK(g_FileSize == BeforeSize && memcmp(g_File, Before, BeforeSize) == 0, "the file is unchanged after load + read + sync");

    /* delete every value: every cell goes back (free cells accounted) */
    K = Find(Hive, g_Root, L"Values");
    while (((PCM_KEY_NODE)HvGetCell(Hive, K))->ValueList.Count)
    {
        PCM_KEY_NODE N = (PCM_KEY_NODE)HvGetCell(Hive, K);
        PCELL_DATA L = (PCELL_DATA)HvGetCell(Hive, N->ValueList.List);
        HCELL_INDEX Vc = L->u.KeyList[0];

        HvMarkCellDirty(Hive, K, FALSE);
        HvMarkCellDirty(Hive, N->ValueList.List, FALSE);
        HvMarkCellDirty(Hive, Vc, FALSE);
        CHECK(CmpMarkValueDataDirty(Hive, (PCM_KEY_VALUE)HvGetCell(Hive, Vc)), "mark dirty");
        CHECK(NT_SUCCESS(CmpRemoveValueFromList(Hive, 0, &N->ValueList)), "remove");
        CHECK(CmpFreeValue(Hive, Vc), "free");
    }
    After = AllocatedBytes(Hive);
    CHECK(After == Base, "after the deletes %lu bytes allocated, before the values %lu", (unsigned long)After, (unsigned long)Base);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_LiveFlags)), "live check after the deletes");
    Unload(&Cm);
    free(Before);
}

/* ---- 2: a value changes: small -> big -> small -> one cell -> big -> other big ---- */
static void TestReplace(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    static const ULONG Steps[] = { 3, 40000, 2, 100, 16345, 16344, 32689, 32688, 70000, 0, 20000, 5, 100000, 1 };
    HCELL_INDEX K, V;
    ULONG i, Base;
    PUCHAR Data;
    ULONG Temp;
    CHAIN C;
    NTSTATUS Status;
    BOOLEAN Changed;

    printf("-- overwrite: small, big, small, one cell, big ... in a 1.5 hive; the old chain is freed every time\n");
    CHECK(NewHive(&Cm, 5), "new hive");
    K = SubKey(Hive, g_Root, L"K");
    Base = AllocatedBytes(Hive);
    V = SetValue(Hive, K, L"v", 1, 1);
    for (i = 0; i < sizeof(Steps) / sizeof(Steps[0]); i++)
    {
        Data = MakeData(Steps[i], 100 + i);
        Temp = 0;
        memcpy(&Temp, Data, min(Steps[i], sizeof(Temp)));
        HvMarkCellDirty(Hive, V, FALSE);
        Status = CmpReplaceValueData(Hive, (PCM_KEY_VALUE)HvGetCell(Hive, V), REG_BINARY_, Data, Steps[i], Stable, Temp);
        CHECK(NT_SUCCESS(Status), "replace with %lu bytes: 0x%lx", (unsigned long)Steps[i], (unsigned long)Status);
        CHECK(DataIs(Hive, V, Steps[i], 100 + i), "%lu bytes read back", (unsigned long)Steps[i]);
        CHECK(Chain(Hive, V, &C) == (Steps[i] > SEG), "%lu bytes: big data %s", (unsigned long)Steps[i],
              Steps[i] > SEG ? "expected" : "not expected");
        if (Steps[i] > SEG)
            CheckLayout(Hive, &C, Steps[i]);
        CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_LiveFlags)), "live check after %lu bytes",
              (unsigned long)Steps[i]);
        free(Data);
    }
    CHECK(HvWriteHive(Hive), "write");
    Unload(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && !Changed, "reload unchanged");
    V = FindValue(Hive, Find(Hive, g_Root, L"K"), L"v");
    CHECK(DataIs(Hive, V, 1, 100 + i - 1), "the last data after the reload");
    /* the last data is small: everything but the value cell is free again */
    HvMarkCellDirty(Hive, V, FALSE);
    {
        PCM_KEY_NODE N = (PCM_KEY_NODE)HvGetCell(Hive, Find(Hive, g_Root, L"K"));
        HvMarkCellDirty(Hive, Find(Hive, g_Root, L"K"), FALSE);
        HvMarkCellDirty(Hive, N->ValueList.List, FALSE);
        CHECK(NT_SUCCESS(CmpRemoveValueFromList(Hive, 0, &N->ValueList)) && CmpFreeValue(Hive, V), "delete");
    }
    CHECK(AllocatedBytes(Hive) == Base, "no cell left behind: %lu bytes allocated, %lu before",
          (unsigned long)AllocatedBytes(Hive), (unsigned long)Base);
    Unload(&Cm);
}

/* ---- 3: what a 1.3 hive gets: one cell, also for 20 KB and 2 MB (as before big data) ---- */
static void TestOldFormat(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX K, V1, V2;
    PCM_KEY_VALUE Vk;
    CHAIN C;
    BOOLEAN Changed;

    printf("-- format 1.3: 20 KB and 2 MB values are one cell each, never big data\n");
    CHECK(NewHive(&Cm, 3), "new hive");
    K = SubKey(Hive, g_Root, L"K");
    V1 = SetValue(Hive, K, L"20k", 20 * 1024, 7);
    V2 = SetValue(Hive, K, L"2m", 2 * 1024 * 1024, 8);
    CHECK(!Chain(Hive, V1, &C) && !Chain(Hive, V2, &C), "no chain in a 1.3 hive");
    Vk = (PCM_KEY_VALUE)HvGetCell(Hive, V2);
    CHECK(HvGetCellSize(Hive, HvGetCell(Hive, Vk->Data)) >= 2 * 1024 * 1024, "2 MB in one cell");
    CHECK(HvWriteHive(Hive), "write");
    Unload(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && !Changed, "loads unchanged");
    K = Find(Hive, g_Root, L"K");
    CHECK(DataIs(Hive, FindValue(Hive, K, L"20k"), 20 * 1024, 7) && DataIs(Hive, FindValue(Hive, K, L"2m"), 2 * 1024 * 1024, 8),
          "both read back");
    Unload(&Cm);
}

/* ---- 4: copies between the formats (save, restore, merge use CmpCopyValue) ---- */
static void TestCopy(void)
{
    static CMHIVE Src, Dst;
    HCELL_INDEX K, V, D, Kd;
    static const ULONG Minor[2] = { 3, 5 };
    ULONG s, d;
    CHAIN C;

    printf("-- copy of a value between hives of format 1.3 and 1.5, all four ways\n");
    for (s = 0; s < 2; s++)
        for (d = 0; d < 2; d++)
        {
            CHECK(NewHive(&Src, Minor[s]), "source");
            K = SubKey(&Src.Hive, g_Root, L"K");
            V = SetValue(&Src.Hive, K, L"v", 40000, 30 + s);
            {
                /* the destination is a second hive: its own "file" is not needed, it is not written */
                PUCHAR Keep; ULONG KeepSize;
                Keep = SaveFile(&KeepSize);
                CHECK(NewHive(&Dst, Minor[d]), "destination");
                Kd = SubKey(&Dst.Hive, g_Root, L"K");
                D = CmpCopyValue(&Src.Hive, V, &Dst.Hive, Stable);
                CHECK(D != HCELL_NIL, "copy 1.%lu -> 1.%lu", (unsigned long)Minor[s], (unsigned long)Minor[d]);
                if (D != HCELL_NIL)
                {
                    PCM_KEY_NODE N = (PCM_KEY_NODE)HvGetCell(&Dst.Hive, Kd);
                    CHECK(NT_SUCCESS(CmpAddValueToList(&Dst.Hive, D, 0, Stable, &N->ValueList)), "list");
                    ((PCM_KEY_NODE)HvGetCell(&Dst.Hive, Kd))->MaxValueDataLen = 40000;
                    ((PCM_KEY_NODE)HvGetCell(&Dst.Hive, Kd))->MaxValueNameLen = 2;
                    CHECK(DataIs(&Dst.Hive, D, 40000, 30 + s), "the copy reads back");
                    CHECK(Chain(&Dst.Hive, D, &C) == (Minor[d] >= 4), "the copy is %s",
                          Minor[d] >= 4 ? "big data" : "one cell");
                    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Dst, g_LiveFlags)), "live check of the copy");
                }
                Unload(&Dst);
                RestoreFile(Keep, KeepSize);
                free(Keep);
            }
            Unload(&Src);
        }
}

/* ---- 5: chains the writer does not make but a file may hold ---- */

/* A chain made by hand: Count segments of the given sizes for Length bytes of pattern Seed */
static HCELL_INDEX HandChain(PHHIVE Hive, ULONG Length, ULONG Seed, ULONG Count, const ULONG *Sizes)
{
    HCELL_INDEX Db, List, S;
    PCM_BIG_DATA B;
    ULONG i, Off = 0, n;

    Db = HvAllocateCell(Hive, sizeof(CM_BIG_DATA), Stable, HCELL_NIL);
    List = HvAllocateCell(Hive, Count * sizeof(HCELL_INDEX), Stable, HCELL_NIL);
    for (i = 0; i < Count; i++)
    {
        S = HvAllocateCell(Hive, Sizes[i], Stable, HCELL_NIL);
        for (n = 0; n < Sizes[i]; n++)
            ((PUCHAR)HvGetCell(Hive, S))[n] = (Off + n < Length && n < SEG) ? Pat(Off + n, Seed) : 0xEE;
        Off += SEG;
        ((PHCELL_INDEX)HvGetCell(Hive, List))[i] = S;
    }
    B = (PCM_BIG_DATA)HvGetCell(Hive, Db);
    B->Signature = CM_BIG_DATA_SIGNATURE;
    B->Count = (USHORT)Count;
    B->List = List;
    return Db;
}

static void TestHandMade(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX K, Db, Plain;
    static const ULONG Extra[4] = { SEG, SEG, SEG, 100 };   /* 40000 bytes need 3; a 4th listed */
    BOOLEAN Changed;
    ULONG Base;

    printf("-- a chain that lists more segments than needed, and a 1.5 value in one cell (written by an older ReactOS)\n");
    CHECK(NewHive(&Cm, 5), "new hive");
    K = SubKey(Hive, g_Root, L"K");
    Db = HandChain(Hive, 40000, 51, 4, Extra);
    AddValueCell(Hive, K, L"extra", REG_BINARY_, Db, 40000, 0);
    Plain = HvAllocateCell(Hive, 30000, Stable, HCELL_NIL);
    {
        ULONG n;
        for (n = 0; n < 30000; n++)
            ((PUCHAR)HvGetCell(Hive, Plain))[n] = Pat(n, 52);
    }
    AddValueCell(Hive, K, L"plain", REG_BINARY_, Plain, 30000, 0);
    CHECK(HvWriteHive(Hive), "write");
    Unload(&Cm);

    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && !Changed, "both kept, file unchanged");
    K = Find(Hive, g_Root, L"K");
    CHECK(DataIs(Hive, FindValue(Hive, K, L"extra"), 40000, 51), "the chain with an extra segment reads back");
    CHECK(DataIs(Hive, FindValue(Hive, K, L"plain"), 30000, 52), "the one-cell value reads back");
    CHECK(CmpValueToData(Hive, (PCM_KEY_VALUE)HvGetCell(Hive, FindValue(Hive, K, L"plain")), &Base) != NULL,
          "the boot-time reader reads one cell");
    Unload(&Cm);
}

/* ---- 5b: the layout of builds that sized the last segment cell to the rest (still read; rewritten in full size) ---- */
static void TestOldLayout(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    /* what the earlier writer made: every cell but the last SEG bytes, the last exactly the rest */
    static const ULONG A[3] = { SEG, SEG, 40000 - 2 * SEG };            /* 40000 */
    static const ULONG B[2] = { SEG, 8 };                                /* 16345 */
    static const ULONG C6[7] = { SEG, SEG, SEG, SEG, SEG, SEG, 100000 - 6 * SEG };
    static const ULONG Step[3] = { SEG, SEG, 40000 - 2 * SEG - 8 };     /* the last cell one allocation step short */
    HCELL_INDEX K, V;
    CHAIN Ch;
    PUCHAR Data;
    ULONG Temp;
    BOOLEAN Changed;
    NTSTATUS Status;

    printf("-- the old layout (last segment cell sized to the rest): loads unchanged, reads back, rewritten in full size; one step short is dropped\n");
    CHECK(NewHive(&Cm, 5), "new hive");
    K = SubKey(Hive, g_Root, L"K");
    AddValueCell(Hive, K, L"a", REG_BINARY_, HandChain(Hive, 40000, 81, 3, A), 40000, 0);
    AddValueCell(Hive, K, L"b", REG_BINARY_, HandChain(Hive, SEG + 1, 82, 2, B), SEG + 1, 0);
    AddValueCell(Hive, K, L"c", REG_BINARY_, HandChain(Hive, 100000, 83, 7, C6), 100000, 0);
    AddValueCell(Hive, K, L"short", REG_BINARY_, HandChain(Hive, 40000, 84, 3, Step), 40000, 0);
    CHECK(HvWriteHive(Hive), "write");
    Unload(&Cm);

    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && Changed, "loads; only the chain one step short is repaired");
    K = Find(Hive, g_Root, L"K");
    CHECK(DataIs(Hive, FindValue(Hive, K, L"a"), 40000, 81), "a (40000, old layout) reads back");
    CHECK(DataIs(Hive, FindValue(Hive, K, L"b"), SEG + 1, 82), "b (16345, old layout) reads back");
    CHECK(DataIs(Hive, FindValue(Hive, K, L"c"), 100000, 83), "c (100000, old layout) reads back");
    CHECK(FindValue(Hive, K, L"short") == HCELL_NIL, "a last cell one allocation step short of the data is dropped");
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_LiveFlags)), "live check");

    /* an untouched old chain stays as it is: its last cell is smaller than SEG */
    V = FindValue(Hive, K, L"a");
    CHECK(Chain(Hive, V, &Ch) && Ch.Count == 3 && HvGetCellSize(Hive, HvGetCell(Hive, Ch.Seg[2])) < (LONG)SEG,
          "an untouched old chain keeps its short last cell");

    /* written again (same size): full-size layout */
    Data = MakeData(40000, 91);
    Temp = 0;
    memcpy(&Temp, Data, sizeof(Temp));
    HvMarkCellDirty(Hive, V, FALSE);
    Status = CmpReplaceValueData(Hive, (PCM_KEY_VALUE)HvGetCell(Hive, V), REG_BINARY_, Data, 40000, Stable, Temp);
    CHECK(NT_SUCCESS(Status), "rewrite a at the same size");
    free(Data);
    CHECK(DataIs(Hive, V, 40000, 91), "a reads back after the rewrite");
    CHECK(Chain(Hive, V, &Ch), "a is still big data");
    CheckLayout(Hive, &Ch, 40000);

    /* grown across a boundary: full size */
    V = FindValue(Hive, K, L"b");
    Data = MakeData(2 * SEG + 5, 92);
    Temp = 0;
    memcpy(&Temp, Data, sizeof(Temp));
    HvMarkCellDirty(Hive, V, FALSE);
    Status = CmpReplaceValueData(Hive, (PCM_KEY_VALUE)HvGetCell(Hive, V), REG_BINARY_, Data, 2 * SEG + 5, Stable, Temp);
    CHECK(NT_SUCCESS(Status), "grow b");
    free(Data);
    CHECK(DataIs(Hive, V, 2 * SEG + 5, 92) && Chain(Hive, V, &Ch), "b reads back and is big data");
    CheckLayout(Hive, &Ch, 2 * SEG + 5);

    /* shrunk to one cell: a plain cell */
    V = FindValue(Hive, K, L"c");
    Data = MakeData(SEG, 93);
    Temp = 0;
    memcpy(&Temp, Data, sizeof(Temp));
    HvMarkCellDirty(Hive, V, FALSE);
    Status = CmpReplaceValueData(Hive, (PCM_KEY_VALUE)HvGetCell(Hive, V), REG_BINARY_, Data, SEG, Stable, Temp);
    CHECK(NT_SUCCESS(Status), "shrink c");
    free(Data);
    CHECK(DataIs(Hive, V, SEG, 93) && !Chain(Hive, V, &Ch), "c reads back as one cell");
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_LiveFlags)), "live check after the rewrites");
    CHECK(HvWriteHive(Hive), "write");
    Unload(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && !Changed, "the rewritten hive loads unchanged");
    K = Find(Hive, g_Root, L"K");
    CHECK(DataIs(Hive, FindValue(Hive, K, L"a"), 40000, 91) && DataIs(Hive, FindValue(Hive, K, L"b"), 2 * SEG + 5, 92) &&
          DataIs(Hive, FindValue(Hive, K, L"c"), SEG, 93), "all three read back after the reload");
    Unload(&Cm);
}

/* ---- 6: every kind of unsound chain: that value is dropped, nothing else ---- */
typedef struct
{
    HCELL_INDEX Key, Big, Other, Small, Big2, Key2, Sk, Free, RootClass;
    CHAIN BigC, OtherC;
    HCELL_INDEX SmallData;
    HCELL_INDEX Short;      /* an allocated cell of 64 bytes no value owns */
} GOOD;
static GOOD g_G;

/* K: "other" (20000, 2 segments), "small" (100, one cell), "big" (40000, 3 segments); K2: "big2" (16345) */
static PUCHAR BuildGood(ULONG *Size)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    UCHAR Sd[] = { 1, 0, 0x04, 0x80, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0 };   /* owner SYSTEM, no DACL */
    HCELL_INDEX A, B;

    CHECK(NewHive(&Cm, 5), "new hive");
    CHECK(NT_SUCCESS(CmpInsertSecurityDescriptor(&Cm, Sd, sizeof(Sd), Stable, &g_G.Sk)), "sk");
    ((PCM_KEY_NODE)HvGetCell(Hive, g_Root))->Security = g_G.Sk;
    /* the root's class: a cell of 20000 bytes, checked before any value */
    g_G.RootClass = HvAllocateCell(Hive, 20000, Stable, HCELL_NIL);
    memset(HvGetCell(Hive, g_G.RootClass), 'c', 20000);
    ((PCM_KEY_NODE)HvGetCell(Hive, g_Root))->Class = g_G.RootClass;
    ((PCM_KEY_NODE)HvGetCell(Hive, g_Root))->ClassLength = 20000;
    g_G.Key = SubKey(Hive, g_Root, L"K");
    g_G.Key2 = SubKey(Hive, g_Root, L"K2");
    g_G.Other = SetValue(Hive, g_G.Key, L"other", 20000, 61);
    g_G.Small = SetValue(Hive, g_G.Key, L"small", 100, 62);
    g_G.Big = SetValue(Hive, g_G.Key, L"big", 40000, 63);
    g_G.Big2 = SetValue(Hive, g_G.Key2, L"big2", SEG + 1, 64);
    g_G.SmallData = ((PCM_KEY_VALUE)HvGetCell(Hive, g_G.Small))->Data;
    CHECK(Chain(Hive, g_G.Big, &g_G.BigC) && g_G.BigC.Count == 3, "big: 3 segments");
    CHECK(Chain(Hive, g_G.Other, &g_G.OtherC) && g_G.OtherC.Count == 2, "other: 2 segments");
    /* a free cell between two allocated ones */
    A = HvAllocateCell(Hive, 20000, Stable, HCELL_NIL);
    B = HvAllocateCell(Hive, 64, Stable, HCELL_NIL);
    HvFreeCell(Hive, A);
    g_G.Free = A;
    g_G.Short = B;
    CHECK(HvWriteHive(Hive), "write");
    Unload(&Cm);
    return SaveFile(Size);
}

typedef void (*TAMPER)(PHHIVE Hive);
static PCM_BIG_DATA BigDb(PHHIVE H) { return (PCM_BIG_DATA)HvGetCell(H, g_G.BigC.Db); }
static PHCELL_INDEX BigList(PHHIVE H) { return (PHCELL_INDEX)HvGetCell(H, g_G.BigC.List); }
static PCM_KEY_VALUE BigV(PHHIVE H) { return (PCM_KEY_VALUE)HvGetCell(H, g_G.Big); }

static void T_Signature(PHHIVE H)       { BigDb(H)->Signature = 0x6264 ^ 0x0100; }
static void T_CountZero(PHHIVE H)       { BigDb(H)->Count = 0; }
static void T_CountOne(PHHIVE H)        { BigDb(H)->Count = 1; }
static void T_CountBelow(PHHIVE H)      { BigDb(H)->Count = 2; }
static void T_CountHuge(PHHIVE H)       { BigDb(H)->Count = 0xFFFF; }
static void T_ListNil(PHHIVE H)         { BigDb(H)->List = HCELL_NIL; }
static void T_ListMidCell(PHHIVE H)     { BigDb(H)->List = g_G.BigC.List + 8; }
static void T_ListPastEnd(PHHIVE H)     { BigDb(H)->List = H->Storage[Stable].Length * HBLOCK_SIZE + 0x20; }
static void T_ListVolatile(PHHIVE H)    { BigDb(H)->List = g_G.BigC.List | HCELL_TYPE_MASK; }
static void T_ListSmall(PHHIVE H)       { BigDb(H)->List = g_G.SmallData; }   /* large enough; "small" took it */
static void T_ListTooShort(PHHIVE H)    { BigDb(H)->Count = 4; }               /* the list cell holds 3 entries */
static void T_ListIsDb(PHHIVE H)        { BigDb(H)->List = g_G.BigC.Db; }
static void T_ListFree(PHHIVE H)        { BigDb(H)->List = g_G.Free; }
static void T_SegNil(PHHIVE H)          { BigList(H)[1] = HCELL_NIL; }
static void T_SegMidCell(PHHIVE H)      { BigList(H)[0] = g_G.BigC.Seg[0] + 16; }
static void T_SegPastEnd(PHHIVE H)      { BigList(H)[2] = H->Storage[Stable].Length * HBLOCK_SIZE; }
static void T_SegFree(PHHIVE H)         { BigList(H)[0] = g_G.Free; }
/* the writer makes every segment cell SEG bytes: a short segment is a cell of 64 bytes put into the list */
static void T_SegShortMiddle(PHHIVE H)  { BigList(H)[1] = g_G.Short; }
static void T_SegShortLast(PHHIVE H)    { BigList(H)[2] = g_G.Short; BigV(H)->DataLength = 2 * SEG + 8000; }
/* The last segment then needs 10 bytes only: any cell is large enough, only its use makes the chain unsound */
static void ShortLast(PHHIVE H)         { BigV(H)->DataLength = 2 * SEG + 10; }
static void T_SegTwice(PHHIVE H)        { BigList(H)[2] = BigList(H)[0]; }
static void T_SegIsDb(PHHIVE H)         { ShortLast(H); BigList(H)[2] = g_G.BigC.Db; }
static void T_SegIsList(PHHIVE H)       { ShortLast(H); BigList(H)[2] = g_G.BigC.List; }
static void T_SegIsOwnVk(PHHIVE H)      { ShortLast(H); BigList(H)[2] = g_G.Big; }
static void T_SegOfOther(PHHIVE H)      { BigList(H)[0] = g_G.OtherC.Seg[0]; }
static void T_SegIsKey(PHHIVE H)        { ShortLast(H); BigList(H)[2] = g_G.Key; }
static void T_SegIsSk(PHHIVE H)         { ShortLast(H); BigList(H)[2] = g_G.Sk; }
static void T_SegIsOtherData(PHHIVE H)  { ShortLast(H); BigList(H)[2] = g_G.SmallData; }
static void T_SegIsClass(PHHIVE H)      { BigList(H)[0] = g_G.RootClass; }
static void T_ShortLastSound(PHHIVE H)  { ShortLast(H); }   /* not a damage: see TestMalformed */
static void T_SegVolatile(PHHIVE H)     { BigList(H)[1] |= HCELL_TYPE_MASK; }
static void T_DbOfOther(PHHIVE H)       { BigV(H)->Data = g_G.OtherC.Db; BigV(H)->DataLength = 20000; }
static void T_DbIsKey(PHHIVE H)         { BigV(H)->Data = g_G.Key2; }
static void T_DbMidCell(PHHIVE H)       { BigV(H)->Data = g_G.BigC.Db + 8; }
static void T_LengthTooBig(PHHIVE H)    { BigV(H)->DataLength = 3 * SEG + 1; }
static void T_LengthUnreadable(PHHIVE H){ BigDb(H)->Count = 0xFFFF; BigV(H)->DataLength = 0x7FFFFFF0; }

typedef struct { const char *Name; TAMPER Do; } CASE;
static const CASE g_Cases[] =
{
    { "db signature",                          T_Signature },
    { "count 0",                               T_CountZero },
    { "count 1",                               T_CountOne },
    { "count below the segments needed",       T_CountBelow },
    { "count 65535, list too short for it",    T_CountHuge },
    { "list NIL",                              T_ListNil },
    { "list inside a cell",                    T_ListMidCell },
    { "list past the end of the hive",         T_ListPastEnd },
    { "list in the volatile storage",          T_ListVolatile },
    { "list is another value's data cell",     T_ListSmall },
    { "list cell too short for the count",     T_ListTooShort },
    { "list is the db cell (cycle)",           T_ListIsDb },
    { "list is a free cell",                   T_ListFree },
    { "segment NIL",                           T_SegNil },
    { "segment inside a cell",                 T_SegMidCell },
    { "segment past the end of the hive",      T_SegPastEnd },
    { "segment is a free cell",                T_SegFree },
    { "a short segment not last",              T_SegShortMiddle },
    { "last segment shorter than the rest",    T_SegShortLast },
    { "a segment listed twice",                T_SegTwice },
    { "segment is the db cell (cycle)",        T_SegIsDb },
    { "segment is the list cell (cycle)",      T_SegIsList },
    { "segment is the value cell itself",      T_SegIsOwnVk },
    { "segment of another value's chain",      T_SegOfOther },
    { "segment is a key node",                 T_SegIsKey },
    { "segment is an sk cell",                 T_SegIsSk },
    { "segment is another value's data cell",  T_SegIsOtherData },
    { "segment is the root key's class cell",  T_SegIsClass },
    { "segment in the volatile storage",       T_SegVolatile },
    { "db cell of another value",              T_DbOfOther },
    { "db cell is a key node",                 T_DbIsKey },
    { "db cell index inside a cell",           T_DbMidCell },
    { "length needs more segments than listed", T_LengthTooBig },
    { "length needs more than 65535 segments", T_LengthUnreadable },
};

static void TestMalformed(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    PUCHAR Good;
    ULONG GoodSize, i;
    BOOLEAN Changed;
    HCELL_INDEX K;

    printf("-- every kind of unsound chain: the value is dropped, the rest is intact, the repair is written and holds\n");
    Good = BuildGood(&GoodSize);

    /* the good hive itself: loads unchanged */
    RestoreFile(Good, GoodSize);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && !Changed, "the good hive loads unchanged");
    Unload(&Cm);

    for (i = 0; i < sizeof(g_Cases) / sizeof(g_Cases[0]); i++)
    {
        ULONG E0 = g_Errors;

        RestoreFile(Good, GoodSize);
        CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "open");
        InitCache(&Cm);
        g_Cases[i].Do(Hive);
        CHECK(HvWriteHive(Hive), "write the damaged hive");
        Unload(&Cm);

        CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)), "%s: loads", g_Cases[i].Name);
        CHECK(Changed, "%s: a repair was made", g_Cases[i].Name);
        K = Find(Hive, g_Root, L"K");
        CHECK(FindValue(Hive, K, L"big") == HCELL_NIL, "%s: the value is dropped", g_Cases[i].Name);
        CHECK(DataIs(Hive, FindValue(Hive, K, L"other"), 20000, 61), "%s: other kept", g_Cases[i].Name);
        CHECK(DataIs(Hive, FindValue(Hive, K, L"small"), 100, 62), "%s: small kept", g_Cases[i].Name);
        CHECK(DataIs(Hive, FindValue(Hive, Find(Hive, g_Root, L"K2"), L"big2"), SEG + 1, 64), "%s: big2 kept",
              g_Cases[i].Name);
        CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Cm, g_LiveFlags)), "%s: live check", g_Cases[i].Name);
        CHECK(HvSyncHive(Hive), "%s: sync", g_Cases[i].Name);
        Unload(&Cm);

        /* the repair was written: the next load changes nothing */
        CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && !Changed, "%s: the next load is clean", g_Cases[i].Name);
        Unload(&Cm);
        printf("   %-42s %s\n", g_Cases[i].Name, g_Errors == E0 ? "dropped, rest intact" : "FAILED");
    }

    /* the control of the cases with a 10-byte last segment: alone, that chain is sound and kept */
    RestoreFile(Good, GoodSize);
    CHECK(NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)), "open");
    InitCache(&Cm);
    T_ShortLastSound(Hive);
    CHECK(HvWriteHive(Hive), "write");
    Unload(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && !Changed, "control: a shorter length over the same chain is sound");
    CHECK(DataIs(Hive, FindValue(Hive, Find(Hive, g_Root, L"K"), L"big"), 2 * SEG + 10, 63), "control: reads back");
    Unload(&Cm);

    /* the same chains in a 1.3 hive are not big data: one cell too short, so every long value goes */
    RestoreFile(Good, GoodSize);
    ((PHBASE_BLOCK)g_File)->Minor = 3;
    ((PHBASE_BLOCK)g_File)->CheckSum = HvpHiveHeaderChecksum((PHBASE_BLOCK)g_File);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && Changed, "1.3 with chains: loads, repaired");
    K = Find(Hive, g_Root, L"K");
    CHECK(FindValue(Hive, K, L"big") == HCELL_NIL && FindValue(Hive, K, L"other") == HCELL_NIL &&
          FindValue(Hive, Find(Hive, g_Root, L"K2"), L"big2") == HCELL_NIL, "1.3: no chain is read");
    CHECK(DataIs(Hive, FindValue(Hive, K, L"small"), 100, 62), "1.3: small kept");
    Unload(&Cm);
    free(Good);
}

/* ---- 7: the boot loader's view (flat image, no repairs): a sound chain is accepted, the reader refuses it ---- */
static void TestFlat(void)
{
    static CMHIVE Flat;
    PUCHAR Good, Image;
    ULONG GoodSize, Length;
    HCELL_INDEX K;

    printf("-- the boot loader's check accepts a sound chain; its reader (CmpValueToData) refuses it cleanly\n");
    Good = BuildGood(&GoodSize);
    Image = malloc(GoodSize);
    memcpy(Image, Good, GoodSize);
    memset(&Flat, 0, sizeof(Flat));
    CHECK(NT_SUCCESS(HvInitialize(&Flat.Hive, HINIT_FLAT, 0, HFILE_TYPE_PRIMARY, Image,
                                  TestAllocate, TestFree, NULL, NULL, NULL, NULL, 1, NULL)), "flat init");
    CHECK(CM_CHECK_REGISTRY_SUCCESS(CmCheckRegistry(&Flat, CM_CHECK_REGISTRY_BOOTLOADER_PURGE_VOLATILES |
                                                           CM_CHECK_REGISTRY_VALIDATE_HIVE)), "flat check");
    CHECK(memcmp(Image, Good, GoodSize) == 0, "the loader changed nothing");
    K = Find(&Flat.Hive, Flat.Hive.BaseBlock->RootCell, L"K");
    CHECK(CmpValueToData(&Flat.Hive, (PCM_KEY_VALUE)HvGetCell(&Flat.Hive, FindValue(&Flat.Hive, K, L"big")), &Length) == NULL,
          "big data refused at boot");
    CHECK(CmpValueToData(&Flat.Hive, (PCM_KEY_VALUE)HvGetCell(&Flat.Hive, FindValue(&Flat.Hive, K, L"small")), &Length) != NULL &&
          Length == 100, "one cell read at boot");
    free(Image);
    free(Good);
}

/* ---- 8: a value without data and without a data cell (the kernel's copy writes those): kept, unchanged ---- */
static void TestNoData(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX K, V;
    BOOLEAN Changed;
    PUCHAR Before;
    ULONG Size, Length;
    PVOID Buffer;
    BOOLEAN Allocated;
    HCELL_INDEX Release;

    printf("-- DataLength 0, Data NIL: loads unchanged, reads as empty, boot reader too\n");
    CHECK(NewHive(&Cm, 3), "new hive");
    K = SubKey(Hive, g_Root, L"K");
    V = AddValueCell(Hive, K, L"empty", REG_BINARY_, HCELL_NIL, 0, 0);
    CHECK(HvWriteHive(Hive), "write");
    Unload(&Cm);
    Before = SaveFile(&Size);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && !Changed, "loads unchanged");
    V = FindValue(Hive, Find(Hive, g_Root, L"K"), L"empty");
    CHECK(V != HCELL_NIL && ((PCM_KEY_VALUE)HvGetCell(Hive, V))->Data == HCELL_NIL, "kept as it was");
    CHECK(CmpGetValueData(Hive, (PCM_KEY_VALUE)HvGetCell(Hive, V), &Length, &Buffer, &Allocated, &Release) &&
          Length == 0 && Buffer && !Allocated && Release == HCELL_NIL, "reads as empty without a cell");
    CHECK(CmpValueToData(Hive, (PCM_KEY_VALUE)HvGetCell(Hive, V), &Length) != NULL && Length == 0, "boot reader too");
    CHECK(HvSyncHive(Hive) && memcmp(g_File, Before, Size) == 0, "file unchanged");
    Unload(&Cm);
    free(Before);
}

/* ---- 9: the largest chain: 65535 segments (about 1 GB); one byte more cannot be stored ---- */
static void TestMax(void)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    const ULONG Max = 65535u * SEG;
    HCELL_INDEX K, V, Cell;
    PUCHAR Data;
    NTSTATUS Status;
    CHAIN C;
    BOOLEAN Changed;

    printf("-- the largest chain: 65535 segments, %lu bytes; %lu bytes are refused\n",
           (unsigned long)Max, (unsigned long)Max + 1);
    CHECK(NewHive(&Cm, 5), "new hive");
    K = SubKey(Hive, g_Root, L"K");
    Data = MakeData(Max + 1, 71);
    Status = CmpSetValueDataNew(Hive, Data, Max + 1, Stable, HCELL_NIL, &Cell);
    CHECK(Status == STATUS_INSUFFICIENT_RESOURCES && Cell == HCELL_NIL, "65536 segments refused: 0x%lx", (unsigned long)Status);
    free(Data);
    V = SetValue(Hive, K, L"max", Max, 72);
    CHECK(Chain(Hive, V, &C) && C.Count == 65535, "65535 segments");
    CHECK(DataIs(Hive, V, Max, 72), "reads back");
    CHECK(HvWriteHive(Hive), "write");
    Unload(&Cm);
    CHECK(CM_CHECK_REGISTRY_SUCCESS(Load(&Cm, &Changed)) && !Changed, "loads unchanged");
    CHECK(DataIs(Hive, FindValue(Hive, Find(Hive, g_Root, L"K"), L"max"), Max, 72), "reads back after the load");
    Unload(&Cm);
}

int main(int argc, char **argv)
{
    if (argc < 2 || !LoadTables(argv[1]))
    {
        printf("usage: BigData NLS [--max]\n");
        return 2;
    }
    TestWriteRead(3);
    TestWriteRead(5);
    TestReplace();
    TestOldFormat();
    TestCopy();
    TestHandMade();
    TestOldLayout();
    TestMalformed();
    TestFlat();
    TestNoData();
    if (argc > 2 && !strcmp(argv[2], "--max"))
        TestMax();
    if (g_PoolOut != 0)
        CHECK(FALSE, "cmlib pool balance %ld", (long)g_PoolOut);
    printf("%lu failures\nRESULT: %s\n", (unsigned long)g_Errors, g_Errors ? "FAIL" : "PASS");
    return g_Errors ? 1 : 0;
}
