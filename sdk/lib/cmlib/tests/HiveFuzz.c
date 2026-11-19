/*
 * PROJECT:     ReactOS cmlib regression tests
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     Structure-aware fuzz of the hive check: a hive file that loads
 *              must be one that no later cmlib path reads or writes outside a
 *              cell of. Each seed mutates a base hive (made here, or a hive
 *              file given on the command line), loads it as the kernel loads a
 *              hive file (HINIT_MEMORY + CmCheckRegistry with the kernel's load
 *              flags) and as the boot loader does (HINIT_FLAT + its flags),
 *              and, if it loads, uses it: every key, subkey lookup, value,
 *              class and descriptor is read; keys are deleted and created,
 *              values and descriptors added; the live check must then find
 *              the hive sound, and a written copy must load again.
 *
 *              Host test against the real cmlib sources; built with
 *              -fsanitize=address every bin is its own allocation, so a read
 *              or a write outside a bin is a failure. A seed that runs longer
 *              than 20 s is a hang. Deterministic: a seed gives the same file.
 *
 *              Usage: HiveFuzz NLS FIRST COUNT [BASEHIVE...]
 *                     HiveFuzz NLS --write SEED OUTFILE [BASEHIVE...]
 *              (the second form writes the mutated file of SEED)
 *              Exit 0: no crash, no hang, the invariants held and every key
 *              the enumeration gives was found by its name, for every seed.
 */

#include "CmHostGlue.h"
#include <signal.h>
#include <unistd.h>

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define HFZ_ASAN 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__)
#define HFZ_ASAN 1
#endif
#ifdef HFZ_ASAN
void __sanitizer_set_death_callback(void (*Callback)(void));
#endif

ULONG CMAPI HvpHiveHeaderChecksum(PHBASE_BLOCK BaseBlock);

#ifndef REG_SZ
#define REG_SZ 1
#define REG_BINARY 3
#define REG_DWORD 4
#define REG_LINK 6
#define REG_MULTI_SZ 7
#endif

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

/* ---- deterministic randomness ---- */
static ULONG g_Rng;
static ULONG Rnd(void)
{
    g_Rng ^= g_Rng << 13;
    g_Rng ^= g_Rng >> 17;
    g_Rng ^= g_Rng << 5;
    return g_Rng;
}
static ULONG RndN(ULONG n) { return n ? Rnd() % n : 0; }

static volatile unsigned g_CurSeed;
static volatile const char *g_CurStep = "start";

static void OnDeath(void)
{
    fprintf(stderr, "HFZ CRASH seed %u step %s\n", g_CurSeed, g_CurStep);
}
static void OnSignal(int Sig)
{
    char Buf[128];
    int n = snprintf(Buf, sizeof(Buf), "HFZ %s seed %u step %s\n",
                     Sig == SIGALRM ? "HANG" : "SIGNAL", g_CurSeed, (const char *)g_CurStep);
    if (write(2, Buf, n) < 0) {}
    _exit(Sig == SIGALRM ? 3 : 4);
}

/* ---- the base hive made here ---- */
static const UCHAR g_SdTemplate[] =
{
    1, 0, 0x04, 0x80, 0x30, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0x14, 0, 0, 0,
    2, 0, 0x1c, 0, 1, 0, 0, 0,
    0, 0, 0x14, 0, 0x3f, 0, 0x1f, 0,
    1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0,
    1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0,
};

/* swprintf does not work with the 2-byte WCHAR of -fshort-wchar */
static void WName(PWCHAR Out, const char *Format, unsigned A, unsigned B)
{
    char Narrow[64];
    int i, n = snprintf(Narrow, sizeof(Narrow), Format, A, B);

    for (i = 0; i <= n && i < 63; i++)
        Out[i] = (WCHAR)(UCHAR)Narrow[i];
    Out[63] = 0;
}

static void InitCache(PCMHIVE Cm)
{
    ULONG i;

    for (i = 0; i < CMP_SECURITY_HASH_LISTS; i++)
        InitializeListHead(&Cm->SecurityHash[i]);
    Cm->SecurityCount = 0;
    Cm->SecurityRingAnchor[Stable] = HCELL_NIL;
    Cm->SecurityRingAnchor[Volatile] = HCELL_NIL;
}

static HCELL_INDEX Sec(PCMHIVE Cm, ULONG N, HSTORAGE_TYPE Type)
{
    UCHAR Buf[sizeof(g_SdTemplate)];
    HCELL_INDEX Cell;

    memcpy(Buf, g_SdTemplate, sizeof(Buf));
    Buf[32] = (UCHAR)N;
    Buf[33] = (UCHAR)(N >> 8);
    if (!NT_SUCCESS(CmpInsertSecurityDescriptor(Cm, Buf, sizeof(Buf), Type, &Cell)))
        return HCELL_NIL;
    return Cell;
}

/* A key under Parent; Security N (0 = none); a class of ClassChars characters */
static HCELL_INDEX MkKey(PCMHIVE Cm, HCELL_INDEX Parent, PCWSTR Name, ULONG SdN, ULONG ClassChars)
{
    PHHIVE Hive = &Cm->Hive;
    HCELL_INDEX Cell = NewKey(Hive, Name, Parent), ClassCell;
    PCM_KEY_NODE Node;
    PWCHAR Class;
    ULONG i;

    if (Cell == HCELL_NIL)
        return Cell;
    if (SdN)
        ((PCM_KEY_NODE)HvGetCell(Hive, Cell))->Security = Sec(Cm, SdN, HvGetCellType(Cell));
    if (ClassChars)
    {
        ClassCell = HvAllocateCell(Hive, ClassChars * sizeof(WCHAR), HvGetCellType(Cell), HCELL_NIL);
        if (ClassCell != HCELL_NIL)
        {
            Class = (PWCHAR)HvGetCell(Hive, ClassCell);
            for (i = 0; i < ClassChars; i++)
                Class[i] = (WCHAR)('A' + i % 26);
            Node = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
            Node->Class = ClassCell;
            Node->ClassLength = (USHORT)(ClassChars * sizeof(WCHAR));
        }
    }
    if (Parent != HCELL_NIL && !CmpAddSubKey(Hive, Parent, Cell))
        return HCELL_NIL;
    return Cell;
}

static BOOLEAN MkValue(PHHIVE Hive, HCELL_INDEX Key, PCWSTR Text, ULONG Type, const void *Data, ULONG Length)
{
    UNICODE_STRING Name;
    HCELL_INDEX Cell, DataCell;
    PCM_KEY_VALUE Value;
    PCM_KEY_NODE Node;
    ULONG NameSize;

    RtlInitUnicodeString(&Name, Text);
    NameSize = CmpNameSize(Hive, &Name);
    Cell = HvAllocateCell(Hive, FIELD_OFFSET(CM_KEY_VALUE, Name) + NameSize, HvGetCellType(Key), HCELL_NIL);
    if (Cell == HCELL_NIL)
        return FALSE;
    Value = (PCM_KEY_VALUE)HvGetCell(Hive, Cell);
    RtlZeroMemory(Value, FIELD_OFFSET(CM_KEY_VALUE, Name));
    Value->Signature = CM_KEY_VALUE_SIGNATURE;
    Value->Type = Type;
    Value->NameLength = CmpCopyName(Hive, Value->Name, &Name);
    if (Value->NameLength < Name.Length)
        Value->Flags |= VALUE_COMP_NAME;
    if (Length <= CM_KEY_VALUE_SMALL)
    {
        Value->DataLength = Length + CM_KEY_VALUE_SPECIAL_SIZE;
        Value->Data = 0;
        memcpy(&Value->Data, Data, Length);
    }
    else
    {
        DataCell = HvAllocateCell(Hive, Length, HvGetCellType(Key), HCELL_NIL);
        if (DataCell == HCELL_NIL)
            return FALSE;
        Value = (PCM_KEY_VALUE)HvGetCell(Hive, Cell);
        memcpy(HvGetCell(Hive, DataCell), Data, Length);
        Value->Data = DataCell;
        Value->DataLength = Length;
    }
    Node = (PCM_KEY_NODE)HvGetCell(Hive, Key);
    HvMarkCellDirty(Hive, Key, FALSE);
    if (Node->ValueList.List != HCELL_NIL)
        HvMarkCellDirty(Hive, Node->ValueList.List, FALSE);
    return NT_SUCCESS(CmpAddValueToList(Hive, Cell, Node->ValueList.Count, HvGetCellType(Key), &Node->ValueList));
}

static void SomeValues(PHHIVE Hive, HCELL_INDEX Key, ULONG n)
{
    static UCHAR Big[0x5000];
    ULONG D = 0x12345678, i;
    static const WCHAR Sz[] = L"string value";
    static const WCHAR Multi[] = L"a\0bc\0";

    for (i = 0; i < sizeof(Big); i++)
        Big[i] = (UCHAR)i;
    MkValue(Hive, Key, L"d", REG_DWORD, &D, 4);
    MkValue(Hive, Key, L"s", REG_SZ, Sz, sizeof(Sz));
    MkValue(Hive, Key, L"b", REG_BINARY, Big, 40 + n);
    MkValue(Hive, Key, L"m", REG_MULTI_SZ, Multi, sizeof(Multi));
    MkValue(Hive, Key, L"", REG_SZ, Sz, 8);
    MkValue(Hive, Key, L"z", REG_BINARY, Big, 0);
    MkValue(Hive, Key, L"\x00e9t\x00e9", REG_DWORD, &D, 2);
    MkValue(Hive, Key, L"\x0436\x0416", REG_SZ, Sz, 6);
    if (n == 3)
        MkValue(Hive, Key, L"big", REG_BINARY, Big, sizeof(Big));
}

/* The base: a tree with every kind of cell the check knows */
static BOOLEAN BuildBase(PUCHAR *Out, ULONG *OutSize)
{
    static CMHIVE Cm;
    PHHIVE Hive = &Cm.Hive;
    HCELL_INDEX Root, K, Big, Deep, Lnk;
    WCHAR Name[64];
    ULONG i, j;

    free(g_File);
    g_File = NULL;
    g_FileSize = 0;
    if (!NT_SUCCESS(OpenHive(&Cm, HINIT_CREATE)))
        return FALSE;
    InitCache(&Cm);
    Root = NewKey(Hive, L"HiveFuzzBase", HCELL_NIL);
    ((PCM_KEY_NODE)HvGetCell(Hive, Root))->Flags |= KEY_HIVE_ENTRY | KEY_NO_DELETE;
    ((PCM_KEY_NODE)HvGetCell(Hive, Root))->Security = Sec(&Cm, 1, Stable);
    Hive->BaseBlock->RootCell = Root;
    SomeValues(Hive, Root, 0);

    for (i = 0; i < 6; i++)
    {
        WName(Name, "k%u", i, 0);
        K = MkKey(&Cm, Root, Name, i % 3 ? 1 + i % 3 : 0, i % 2 ? 0 : 3 + i);
        SomeValues(Hive, K, i);
        K = MkKey(&Cm, K, L"sub", 1, 0);
        K = MkKey(&Cm, K, L"deeper", 4, 0);
        SomeValues(Hive, K, 1);
    }

    /* non-ASCII and mixed case names, compressed and not */
    MkKey(&Cm, Root, L"\x0414\x0416", 5, 0);
    MkKey(&Cm, Root, L"\x00c9t\x00e9", 0, 0);
    MkKey(&Cm, Root, L"Zeta", 2, 0);

    /* enough subkeys for an index root with several leaves */
    Big = MkKey(&Cm, Root, L"many", 1, 0);
    for (i = 0; i < 1100; i++)
    {
        WName(Name, "n%04u", i, 0);
        K = MkKey(&Cm, Big, Name, i % 7 == 0 ? 6 + i % 5 : 0, i % 50 == 0 ? 2 : 0);
        if (i % 100 == 0)
            MkValue(Hive, K, L"v", REG_DWORD, &i, 4);
    }

    /* a chain of keys */
    Deep = MkKey(&Cm, Root, L"chain", 0, 0);
    for (j = 0; j < 40 && Deep != HCELL_NIL; j++)
    {
        WName(Name, "c%u", j, 0);
        Deep = MkKey(&Cm, Deep, Name, j % 4 == 0 ? 12 : 0, 0);
    }

    /* a link key */
    Lnk = MkKey(&Cm, Root, L"lnk", 0, 0);
    if (Lnk != HCELL_NIL)
    {
        static const WCHAR T[] = L"\\REGISTRY\\MACHINE\\SOFTWARE";
        ((PCM_KEY_NODE)HvGetCell(Hive, Lnk))->Flags |= KEY_SYM_LINK;
        MkValue(Hive, Lnk, L"SymbolicLinkValue", REG_LINK, T, sizeof(T) - sizeof(WCHAR));
    }

    if (!HvWriteHive(Hive))
        return FALSE;
    CmpFreeSecurityCache(&Cm);
    HvFree(Hive);
    *Out = g_File;
    *OutSize = g_FileSize;
    g_File = NULL;
    g_FileSize = 0;
    return TRUE;
}

static BOOLEAN ReadFileAll(const char *Path, PUCHAR *Out, ULONG *OutSize)
{
    FILE *f = fopen(Path, "rb");
    long n;

    if (!f)
        return FALSE;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    *Out = malloc(n ? n : 1);
    if (!*Out || fread(*Out, 1, n, f) != (size_t)n)
    {
        fclose(f);
        return FALSE;
    }
    fclose(f);
    *OutSize = (ULONG)n;
    return TRUE;
}

/* ---- the cells of a file image, for targeted mutations ---- */
typedef struct _FCELL { ULONG Off; ULONG Size; USHORT Sig; } FCELL;
static FCELL *g_Cells;
static ULONG g_CellCount, g_CellMax;

static void ScanCells(PUCHAR F, ULONG Size)
{
    ULONG Off = HBLOCK_SIZE, BinSize, c;
    LONG CSize;

    g_CellCount = 0;
    while (Off + sizeof(HBIN) <= Size)
    {
        PHBIN Bin = (PHBIN)(F + Off);
        BinSize = Bin->Size;
        if (Bin->Signature != HV_HBIN_SIGNATURE || BinSize < HBLOCK_SIZE || BinSize % HBLOCK_SIZE ||
            BinSize > Size - Off)
        {
            Off += HBLOCK_SIZE;
            continue;
        }
        c = sizeof(HBIN);
        while (c + 8 <= BinSize)
        {
            CSize = *(PLONG)(F + Off + c);
            ULONG Abs = CSize < 0 ? (ULONG)-CSize : (ULONG)CSize;
            if (Abs < 8 || Abs % 8 || Abs > BinSize - c)
                break;
            if (CSize < 0)
            {
                if (g_CellCount == g_CellMax)
                {
                    g_CellMax = g_CellMax ? g_CellMax * 2 : 1024;
                    g_Cells = realloc(g_Cells, g_CellMax * sizeof(FCELL));
                }
                g_Cells[g_CellCount].Off = Off + c;
                g_Cells[g_CellCount].Size = Abs;
                g_Cells[g_CellCount].Sig = Abs >= 6 ? *(PUSHORT)(F + Off + c + 4) : 0;
                g_CellCount++;
            }
            c += Abs;
        }
        Off += BinSize;
    }
}

static const ULONG g_Edge[] =
{
    0, 1, 2, 3, 4, 7, 8, 0x10, 0x20, 0x7F, 0x80, 0xFF, 0x100, 0xFFF, 0x1000, 0x3FD8, 0x3FD9, 0x7FFF, 0x8000,
    0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0x80000001, 0x80000004, 0x80000005, 0xBAADF00D, 0xFFFFFFF8,
    0xFFFFFFFE, 0xFFFFFFFF
};

static FCELL *PickCell(USHORT Sig)
{
    ULONG i, Start, n = 0;
    FCELL *Found = NULL;

    if (!g_CellCount)
        return NULL;
    Start = RndN(g_CellCount);
    for (i = 0; i < g_CellCount; i++)
    {
        FCELL *C = &g_Cells[(Start + i) % g_CellCount];
        if (!Sig || C->Sig == Sig)
        {
            Found = C;
            if (++n > RndN(4))
                break;
        }
    }
    return Found;
}

/* A cell index worth writing into a field: another cell, the middle of one, an edge */
static ULONG CrossRef(PUCHAR F, ULONG Size, ULONG Self)
{
    FCELL *C;
    static const USHORT Sigs[] = { 0, 'kn', 'kv', 'ks', 'il', 'fl', 'hl', 'ir' };

    switch (RndN(8))
    {
    case 0: return g_Edge[RndN(COUNT_OF(g_Edge))];
    case 1: return Self;
    case 2: return (RndN(Size) & ~7u) - HBLOCK_SIZE;
    case 3: C = PickCell(0); return C ? C->Off - HBLOCK_SIZE + 8 * (1 + RndN(3)) : 0;
    case 4: C = PickCell(0); return C ? (C->Off - HBLOCK_SIZE) | 0x80000000 : 0;
    case 5: return 0x20 + 8 * RndN(4);
    default:
        C = PickCell(Sigs[RndN(COUNT_OF(Sigs))]);
        return C ? C->Off - HBLOCK_SIZE : HCELL_NIL;
    }
    (void)F;
}

static void FixChecksum(PUCHAR F)
{
    ((PHBASE_BLOCK)F)->CheckSum = HvpHiveHeaderChecksum((PHBASE_BLOCK)F);
}

#define FIELD32(Base, Off) (*(PULONG)((Base) + (Off)))
#define FIELD16(Base, Off) (*(PUSHORT)((Base) + (Off)))

static void Mutate(PUCHAR F, ULONG Size)
{
    ULONG n = 1 + RndN(RndN(4) ? 3 : 8), i, Off, Field;
    FCELL *C, *D;
    PUCHAR P;

    ScanCells(F, Size);
    for (i = 0; i < n; i++)
    {
        switch (RndN(20))
        {
        case 0: /* a byte */
            F[HBLOCK_SIZE + RndN(Size - HBLOCK_SIZE)] = (UCHAR)Rnd();
            break;
        case 1: /* a bit */
            F[HBLOCK_SIZE + RndN(Size - HBLOCK_SIZE)] ^= (UCHAR)(1u << RndN(8));
            break;
        case 2: /* a dword := edge */
            Off = (HBLOCK_SIZE + RndN(Size - HBLOCK_SIZE - 4)) & ~3u;
            FIELD32(F, Off) = g_Edge[RndN(COUNT_OF(g_Edge))];
            break;
        case 3: case 4: case 5: /* key node fields */
            if (!(C = PickCell('kn')) || C->Size < 0x50)
                break;
            P = F + C->Off + 4;
            switch (RndN(14))
            {
            case 0: FIELD16(P, FIELD_OFFSET(CM_KEY_NODE, Flags)) ^= (USHORT)(1u << RndN(16)); break;
            case 1: FIELD32(P, FIELD_OFFSET(CM_KEY_NODE, Parent)) = CrossRef(F, Size, C->Off - HBLOCK_SIZE); break;
            case 2: FIELD32(P, FIELD_OFFSET(CM_KEY_NODE, SubKeyCounts[RndN(2)])) = g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 3: FIELD32(P, FIELD_OFFSET(CM_KEY_NODE, SubKeyLists[RndN(2)])) = CrossRef(F, Size, C->Off - HBLOCK_SIZE); break;
            case 4: FIELD32(P, FIELD_OFFSET(CM_KEY_NODE, ValueList.Count)) = g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 5: FIELD32(P, FIELD_OFFSET(CM_KEY_NODE, ValueList.List)) = CrossRef(F, Size, C->Off - HBLOCK_SIZE); break;
            case 6: FIELD32(P, FIELD_OFFSET(CM_KEY_NODE, Security)) = CrossRef(F, Size, C->Off - HBLOCK_SIZE); break;
            case 7: FIELD32(P, FIELD_OFFSET(CM_KEY_NODE, Class)) = CrossRef(F, Size, C->Off - HBLOCK_SIZE); break;
            case 8: FIELD16(P, FIELD_OFFSET(CM_KEY_NODE, ClassLength)) = (USHORT)g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 9: FIELD16(P, FIELD_OFFSET(CM_KEY_NODE, NameLength)) = (USHORT)g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 10: FIELD32(P, FIELD_OFFSET(CM_KEY_NODE, MaxNameLen) + 4 * RndN(4)) = g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 11: FIELD16(P, FIELD_OFFSET(CM_KEY_NODE, Flags)) |= (USHORT)(1u << RndN(8)); break;
            case 12: FIELD16(P, FIELD_OFFSET(CM_KEY_NODE, Signature)) = (USHORT)Rnd(); break;
            default: P[FIELD_OFFSET(CM_KEY_NODE, Name) + RndN(8)] = (UCHAR)Rnd(); break;
            }
            break;
        case 6: case 7: /* value fields */
            if (!(C = PickCell('kv')) || C->Size < 0x18)
                break;
            P = F + C->Off + 4;
            switch (RndN(7))
            {
            case 0: FIELD16(P, FIELD_OFFSET(CM_KEY_VALUE, NameLength)) = (USHORT)g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 1: FIELD32(P, FIELD_OFFSET(CM_KEY_VALUE, DataLength)) = g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 2: FIELD32(P, FIELD_OFFSET(CM_KEY_VALUE, DataLength)) ^= 0x80000000; break;
            case 3: FIELD32(P, FIELD_OFFSET(CM_KEY_VALUE, Data)) = CrossRef(F, Size, C->Off - HBLOCK_SIZE); break;
            case 4: FIELD32(P, FIELD_OFFSET(CM_KEY_VALUE, Type)) = g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 5: FIELD16(P, FIELD_OFFSET(CM_KEY_VALUE, Flags)) ^= (USHORT)(1u << RndN(16)); break;
            default: FIELD32(P, FIELD_OFFSET(CM_KEY_VALUE, DataLength)) += RndN(64); break;
            }
            break;
        case 8: case 9: /* security cell fields */
            if (!(C = PickCell('ks')) || C->Size < 0x18)
                break;
            P = F + C->Off + 4;
            switch (RndN(7))
            {
            case 0: FIELD32(P, FIELD_OFFSET(CM_KEY_SECURITY, Flink)) = CrossRef(F, Size, C->Off - HBLOCK_SIZE); break;
            case 1: FIELD32(P, FIELD_OFFSET(CM_KEY_SECURITY, Blink)) = CrossRef(F, Size, C->Off - HBLOCK_SIZE); break;
            case 2: FIELD32(P, FIELD_OFFSET(CM_KEY_SECURITY, ReferenceCount)) = g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 3: FIELD32(P, FIELD_OFFSET(CM_KEY_SECURITY, DescriptorLength)) = g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 4: Field = FIELD_OFFSET(CM_KEY_SECURITY, Descriptor) + RndN(40);
                    if (Field + 4 <= C->Size - 4) P[Field] = (UCHAR)Rnd();
                    break;
            case 5: Field = FIELD_OFFSET(CM_KEY_SECURITY, Descriptor) + 4 * (1 + RndN(4));
                    if (Field + 4 <= C->Size - 4) FIELD32(P, Field) = g_Edge[RndN(COUNT_OF(g_Edge))];
                    break;
            default: /* swap the two links */
                Field = FIELD32(P, FIELD_OFFSET(CM_KEY_SECURITY, Flink));
                FIELD32(P, FIELD_OFFSET(CM_KEY_SECURITY, Flink)) = FIELD32(P, FIELD_OFFSET(CM_KEY_SECURITY, Blink));
                FIELD32(P, FIELD_OFFSET(CM_KEY_SECURITY, Blink)) = Field;
                break;
            }
            break;
        case 10: case 11: case 12: /* index cells */
        {
            static const USHORT Idx[] = { 'il', 'fl', 'hl', 'ir' };
            ULONG Count, Entry;
            USHORT S;

            if (!(C = PickCell(Idx[RndN(4)])))
                break;
            P = F + C->Off + 4;
            S = FIELD16(P, 0);
            Count = FIELD16(P, 2);
            Entry = (S == 'fl' || S == 'hl') ? 8 : 4;
            switch (RndN(6))
            {
            case 0: FIELD16(P, 2) = (USHORT)g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 1: FIELD16(P, 2) = (USHORT)(Count + 1 + RndN(3)); break;
            case 2: FIELD16(P, 0) = Idx[RndN(4)]; break;
            case 3: case 4:
                if (Count && 4 + Entry * Count <= C->Size - 4)
                    FIELD32(P, 4 + Entry * RndN(Count)) = CrossRef(F, Size, C->Off - HBLOCK_SIZE);
                break;
            default: /* an entry equal to another one */
                if (Count > 1 && 4 + Entry * Count <= C->Size - 4)
                    FIELD32(P, 4 + Entry * RndN(Count)) = FIELD32(P, 4 + Entry * RndN(Count));
                break;
            }
            break;
        }
        case 13: /* value list or class: an entry crossed */
            if (!(C = PickCell(0)) || C->Size < 12)
                break;
            Off = C->Off + 4 + 4 * RndN((C->Size - 4) / 4);
            FIELD32(F, Off) = CrossRef(F, Size, C->Off - HBLOCK_SIZE);
            break;
        case 14: /* a cell size */
            if (!(C = PickCell(0)))
                break;
            switch (RndN(5))
            {
            case 0: FIELD32(F, C->Off) = -(LONG)FIELD32(F, C->Off); break;
            case 1: FIELD32(F, C->Off) = (ULONG)-8; break;
            case 2: FIELD32(F, C->Off) -= 8 * (1 + RndN(4)); break;
            case 3: FIELD32(F, C->Off) += 8 * (1 + RndN(4)); break;
            default: FIELD32(F, C->Off) = g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            }
            break;
        case 15: /* a bin header */
            Off = HBLOCK_SIZE * (1 + RndN((Size - HBLOCK_SIZE) / HBLOCK_SIZE));
            if (Off + sizeof(HBIN) > Size)
                break;
            switch (RndN(4))
            {
            case 0: ((PHBIN)(F + Off))->Size = g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            case 1: ((PHBIN)(F + Off))->Size += HBLOCK_SIZE * (RndN(3) - 1); break;
            case 2: ((PHBIN)(F + Off))->FileOffset = g_Edge[RndN(COUNT_OF(g_Edge))]; break;
            default: ((PHBIN)(F + Off))->Signature ^= 1u << RndN(32); break;
            }
            break;
        case 16: /* the base block */
        {
            PHBASE_BLOCK B = (PHBASE_BLOCK)F;
            switch (RndN(6))
            {
            case 0: B->RootCell = CrossRef(F, Size, B->RootCell); break;
            case 1: B->Length = RndN(2) ? g_Edge[RndN(COUNT_OF(g_Edge))] : B->Length + HBLOCK_SIZE * (RndN(5) - 2); break;
            case 2: B->Minor = 3 + RndN(4); break;
            case 3: B->Sequence2 = B->Sequence1 + 1; break;
            case 4: B->Major = RndN(3); break;
            default: B->Cluster = RndN(3); break;
            }
            if (RndN(8))
                FixChecksum(F);
            break;
        }
        case 17: /* one cell's bytes over another's */
            C = PickCell(0);
            D = PickCell(0);
            if (C && D && C != D)
                memcpy(F + D->Off + 4, F + C->Off + 4, (C->Size < D->Size ? C->Size : D->Size) - 4);
            break;
        case 18: /* a key's subkey list given to another key */
            C = PickCell('kn');
            D = PickCell('kn');
            if (C && D && C->Size >= 0x50 && D->Size >= 0x50)
            {
                Field = RndN(3) == 0 ? FIELD_OFFSET(CM_KEY_NODE, ValueList) : FIELD_OFFSET(CM_KEY_NODE, SubKeyCounts);
                memcpy(F + D->Off + 4 + Field, F + C->Off + 4 + Field, Field == FIELD_OFFSET(CM_KEY_NODE, ValueList) ? 8 : 16);
            }
            break;
        default: /* a key's security named by another key, or the root's */
            C = PickCell('kn');
            D = PickCell('kn');
            if (C && D && C->Size >= 0x50 && D->Size >= 0x50)
                FIELD32(F, D->Off + 4 + FIELD_OFFSET(CM_KEY_NODE, Security)) = FIELD32(F, C->Off + 4 + FIELD_OFFSET(CM_KEY_NODE, Security));
            break;
        }
    }
}

/* ---- using a hive that loaded ---- */
static ULONG g_Sink;
static ULONG g_Anomaly[8];
static const char *g_AnomalyName[8] = { "live-check-failed", "reload-failed", "lookup-missed", "load-ok", "load-refused",
                                         "flat-ok", "flat-refused", "write-failed" };
static ULONG g_Verbose, g_NoMutate;

static void Note(ULONG What, unsigned Seed, const char *Text)
{
    g_Anomaly[What]++;
    if (g_Verbose || (What <= 2 && g_Anomaly[What] <= 20))
        fprintf(stderr, "HFZ seed %u: %s %s\n", Seed, g_AnomalyName[What], Text ? Text : "");
}

static void Touch(const void *P, ULONG Length)
{
    const UCHAR *B = P;
    ULONG i;
    for (i = 0; i < Length; i++)
        g_Sink += B[i];
}

#define MAX_KEYS 200000
static HCELL_INDEX *g_Keys;
static ULONG g_KeyCount;

/* Read everything a key has, as the kernel's query and enumerate paths do */
static void UseKey(PHHIVE Hive, HCELL_INDEX Cell, PCM_KEY_NODE Node, BOOLEAN Flat, unsigned Seed)
{
    ULONG i, Length;
    PCELL_DATA List;
    PCM_KEY_VALUE Value;
    PVOID Data;
    BOOLEAN Allocated;
    HCELL_INDEX Release, Found;
    UNICODE_STRING Name;
    WCHAR Buf[300];

    Touch(Node->Name, Node->NameLength);

    /* The maxima a key reports are what programs size buffers by, and the kernel keeps some in 16 bits */
    if (Node->MaxNameLen > MAXUSHORT || Node->MaxClassLen > MAXUSHORT || Node->MaxValueNameLen > MAXUSHORT ||
        Node->MaxValueDataLen > Hive->Storage[Stable].Length * HBLOCK_SIZE + (Flat ? Hive->BaseBlock->Length : 0))
    {
        Note(0, Seed, "a key reports a longest name, class or data it cannot have");
    }
    if (Node->ClassLength && Node->Class != HCELL_NIL)
        Touch(HvGetCell(Hive, Node->Class), Node->ClassLength);
    if (Node->Security != HCELL_NIL)
    {
        PCM_KEY_SECURITY S = CmpGetCheckedSecurityCell(Hive, Node->Security, NULL);
        if (S)
            Touch(&S->Descriptor, S->DescriptorLength);
    }
    if (Node->ValueList.Count)
    {
        List = HvGetCell(Hive, Node->ValueList.List);
        for (i = 0; i < Node->ValueList.Count; i++)
        {
            Value = (PCM_KEY_VALUE)HvGetCell(Hive, List->u.KeyList[i]);
            Touch(Value->Name, Value->NameLength);
            if (CmpGetValueData(Hive, Value, &Length, &Data, &Allocated, &Release))
            {
                Touch(Data, Length);
                if (Allocated)
                    Hive->Free(Data, 0);
            }
            if (Value->NameLength < sizeof(Buf) / 2)
            {
                ULONG k, Chars = (Value->Flags & VALUE_COMP_NAME) ? Value->NameLength : Value->NameLength / 2;
                for (k = 0; k < Chars; k++)
                    Buf[k] = (Value->Flags & VALUE_COMP_NAME) ? ((PUCHAR)Value->Name)[k] : Value->Name[k];
                Name.Buffer = Buf;
                Name.Length = Name.MaximumLength = (USHORT)(Chars * 2);
                Found = CmpFindValueByName(Hive, Node, &Name);
                (void)Found;
            }
        }
    }
    (void)Cell;
    (void)Flat;
    (void)Seed;
}

/* Every key, its subkeys by number and by name */
static void Walk(PHHIVE Hive, BOOLEAN Flat, unsigned Seed)
{
    static struct { HCELL_INDEX Cell; ULONG Next; } Stack[600];
    LONG Depth = 0;
    PCM_KEY_NODE Node, ChildNode;
    HCELL_INDEX Child, ByName;
    ULONG Total;
    UNICODE_STRING Name;
    WCHAR Buf[300];

    g_KeyCount = 0;
    Stack[0].Cell = Hive->BaseBlock->RootCell;
    Stack[0].Next = 0;
    Node = (PCM_KEY_NODE)HvGetCell(Hive, Stack[0].Cell);
    UseKey(Hive, Stack[0].Cell, Node, Flat, Seed);
    while (Depth >= 0)
    {
        Node = (PCM_KEY_NODE)HvGetCell(Hive, Stack[Depth].Cell);
        Total = Node->SubKeyCounts[Stable] + (Flat ? 0 : Node->SubKeyCounts[Volatile]);
        if (Stack[Depth].Next >= Total || Depth >= 590)
        {
            if (g_KeyCount < MAX_KEYS)
                g_Keys[g_KeyCount++] = Stack[Depth].Cell;
            Depth--;
            continue;
        }
        Child = CmpFindSubKeyByNumber(Hive, Node, Stack[Depth].Next++);
        if (Child == HCELL_NIL)
        {
            Note(2, Seed, "by number");
            continue;
        }
        ChildNode = (PCM_KEY_NODE)HvGetCell(Hive, Child);
        if (ChildNode->NameLength / ((ChildNode->Flags & KEY_COMP_NAME) ? 1 : 2) < 300)
        {
            ExpandName(ChildNode, Buf, &Name);
            ByName = CmpFindSubKeyByName(Hive, Node, &Name);
            if (ByName != Child)
            {
                char T[200];
                ULONG k, n = 0;
                PCM_KEY_INDEX Top = (PCM_KEY_INDEX)HvGetCell(Hive, Node->SubKeyLists[Stable]);

                n += snprintf(T + n, sizeof(T) - n, "by name (index %.2s count %u, name", (char *)&Top->Signature, Top->Count);
                for (k = 0; k < Name.Length / 2 && n < sizeof(T) - 8; k++)
                    n += snprintf(T + n, sizeof(T) - n, " %x", Name.Buffer[k]);
                snprintf(T + n, sizeof(T) - n, ")");
                Note(2, Seed, T);
            }
        }
        UseKey(Hive, Child, ChildNode, Flat, Seed);
        Depth++;
        Stack[Depth].Cell = Child;
        Stack[Depth].Next = 0;
    }
}

/* Change the hive the way the registry API does */
static void Change(PCMHIVE Cm, unsigned Seed)
{
    PHHIVE Hive = &Cm->Hive;
    ULONG i, n, Deleted = 0;
    HCELL_INDEX Key, New;
    PCM_KEY_NODE Node;
    WCHAR Name[64];
    ULONG D = Seed;

    if (!g_KeyCount)
        return;
    /* delete some keys without subkeys (g_Keys is in post-order: children first) */
    n = 1 + RndN(8);
    for (i = 0; i < g_KeyCount && Deleted < n; i++)
    {
        Key = g_Keys[RndN(g_KeyCount)];
        if (Key == Hive->BaseBlock->RootCell || Key == HCELL_NIL)
            continue;
        Node = (PCM_KEY_NODE)HvGetCell(Hive, Key);
        if (Node->Signature != CM_KEY_NODE_SIGNATURE || Node->SubKeyCounts[Stable] || Node->SubKeyCounts[Volatile])
            continue;
        g_CurStep = "delete";
        if (NT_SUCCESS(CmpFreeKeyByCell(Hive, Key, TRUE)))
        {
            Deleted++;
            for (D = 0; D < g_KeyCount; D++)
                if (g_Keys[D] == Key)
                    g_Keys[D] = HCELL_NIL;
        }
    }
    /* create keys and values */
    n = 1 + RndN(6);
    for (i = 0; i < n; i++)
    {
        Key = g_Keys[RndN(g_KeyCount)];
        if (Key == HCELL_NIL)
            continue;
        WName(Name, "new%u_%u", Seed, i);
        g_CurStep = "create";
        HvMarkCellDirty(Hive, Key, FALSE);
        New = MkKey(Cm, Key, Name, 1 + RndN(20), RndN(3) ? 0 : 5);
        g_CurStep = "setvalue";
        if (New != HCELL_NIL)
            MkValue(Hive, New, L"v", REG_DWORD, &D, 4);
        MkValue(Hive, Key, Name, REG_SZ, Name, 10);
    }
}

/* The kernel loads with self-healing on (CmpSelfHeal); here that is FIX_HIVE */
static ULONG g_LoadFlags = CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES | CM_CHECK_REGISTRY_RECOUNT_SECURITY |
                           CM_CHECK_REGISTRY_CACHE_SECURITY | CM_CHECK_REGISTRY_FIX_HIVE;

static void RunOne(PUCHAR Base, ULONG BaseSize, unsigned Seed, PUCHAR Out)
{
    static CMHIVE Cm, Cm2;
    PHHIVE Hive = &Cm.Hive;
    PUCHAR F;
    ULONG Size = BaseSize;
    CM_CHECK_REGISTRY_STATUS St;
    PHBASE_BLOCK B;

    g_Rng = Seed * 2654435761u + 0x9E3779B9u;
    if (!g_Rng)
        g_Rng = 1;
    F = malloc(Size);
    memcpy(F, Base, Size);
    g_CurStep = "mutate";
    if (!g_NoMutate)
        Mutate(F, Size);
    if (Out)
    {
        memcpy(Out, F, Size);
        free(F);
        return;
    }
    B = (PHBASE_BLOCK)F;

    /* the kernel: HvLoadHive refuses a hive file shorter than its base block's length */
    g_CurStep = "load";
    if ((ULONGLONG)B->Length + HBLOCK_SIZE <= Size)
    {
        free(g_File);
        g_File = F;
        g_FileSize = Size;
        F = NULL;
        if (NT_SUCCESS(OpenHive(&Cm, HINIT_MEMORY)))
        {
            InitCache(&Cm);
            g_CurStep = "check";
            St = CmCheckRegistry(&Cm, g_LoadFlags);
            if (CM_CHECK_REGISTRY_SUCCESS(St))
            {
                Note(3, Seed, NULL);
                g_CurStep = "walk";
                Walk(Hive, FALSE, Seed);
                Change(&Cm, Seed);
                g_CurStep = "walk2";
                Walk(Hive, FALSE, Seed);
                g_CurStep = "livecheck";
                /* As the Debug kernel checks a hive in use after a flush (CmpCheckLiveHive) */
                St = CmCheckRegistry(&Cm, CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES | CM_CHECK_REGISTRY_VALIDATE_HIVE |
                                          CM_CHECK_REGISTRY_LIVE_HIVE);
                if (!CM_CHECK_REGISTRY_SUCCESS(St))
                {
                    char T[32];
                    sprintf(T, "status %lu", (unsigned long)St);
                    Note(0, Seed, T);
                }
                g_CurStep = "write";
                if (!HvWriteHive(Hive))
                    Note(7, Seed, NULL);
                CmpFreeSecurityCache(&Cm);
                HvFree(Hive);
                g_CurStep = "reload";
                if (NT_SUCCESS(OpenHive(&Cm2, HINIT_MEMORY)))
                {
                    InitCache(&Cm2);
                    St = CmCheckRegistry(&Cm2, g_LoadFlags);
                    if (!CM_CHECK_REGISTRY_SUCCESS(St))
                        Note(1, Seed, "check");
                    else
                        Walk(&Cm2.Hive, FALSE, Seed);
                    CmpFreeSecurityCache(&Cm2);
                    HvFree(&Cm2.Hive);
                }
                else
                {
                    Note(1, Seed, "init");
                }
            }
            else
            {
                Note(4, Seed, NULL);
                CmpFreeSecurityCache(&Cm);
                HvFree(Hive);
            }
        }
        else
        {
            Note(4, Seed, NULL);
        }
    }

    /* the boot loader: the file as one flat, read-only image */
    g_CurStep = "flat";
    {
        static CMHIVE Flat;
        PUCHAR Image = malloc(BaseSize);

        g_Rng = Seed * 2654435761u + 0x9E3779B9u;
        if (!g_Rng)
            g_Rng = 1;
        memcpy(Image, Base, BaseSize);
        if (!g_NoMutate)
            Mutate(Image, BaseSize);
        B = (PHBASE_BLOCK)Image;
        memset(&Flat, 0, sizeof(Flat));
        if ((ULONGLONG)B->Length + HBLOCK_SIZE <= BaseSize &&
            NT_SUCCESS(HvInitialize(&Flat.Hive, HINIT_FLAT, 0, HFILE_TYPE_PRIMARY, Image,
                                    TestAllocate, TestFree, NULL, NULL, NULL, NULL, 1, NULL)))
        {
            St = CmCheckRegistry(&Flat, CM_CHECK_REGISTRY_BOOTLOADER_PURGE_VOLATILES | CM_CHECK_REGISTRY_VALIDATE_HIVE);
            if (CM_CHECK_REGISTRY_SUCCESS(St))
            {
                Note(5, Seed, NULL);
                g_CurStep = "flatwalk";
                Walk(&Flat.Hive, TRUE, Seed);
            }
            else
            {
                Note(6, Seed, NULL);
            }
        }
        free(Image);
    }
    free(F);
}

int main(int argc, char **argv)
{
    PUCHAR Base[16];
    ULONG BaseSize[16], Bases = 0, i;
    unsigned First, Count, s;
    int a;
    const char *WritePath = NULL;
    unsigned WriteSeed = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 4 || !LoadTables(argv[1]))
    {
        fprintf(stderr, "usage: HiveFuzz NLS FIRST COUNT [BASEHIVE...] | NLS --write SEED OUT [BASEHIVE...]\n");
        return 2;
    }
    if (!strcmp(argv[2], "--write"))
    {
        WriteSeed = strtoul(argv[3], NULL, 0);
        WritePath = argv[4];
        a = 5;
        First = WriteSeed;
        Count = 1;
    }
    else
    {
        First = strtoul(argv[2], NULL, 0);
        Count = strtoul(argv[3], NULL, 0);
        a = 4;
    }
    g_Verbose = getenv("HFZ_VERBOSE") != NULL;
    g_NoMutate = getenv("HFZ_NOMUTATE") != NULL;
    /* the library's own messages (DPRINT1 is printf here) are not wanted */
    if (!getenv("HFZ_DPRINT") && !freopen("/dev/null", "w", stdout))
        return 7;
    g_Keys = malloc(MAX_KEYS * sizeof(HCELL_INDEX));
    for (; a < argc && Bases < 15; a++)
    {
        if (ReadFileAll(argv[a], &Base[Bases], &BaseSize[Bases]) && BaseSize[Bases] >= 2 * HBLOCK_SIZE)
            Bases++;
        else
            fprintf(stderr, "cannot use %s\n", argv[a]);
    }
    if (!Bases)
    {
        if (!BuildBase(&Base[0], &BaseSize[0]))
        {
            fprintf(stderr, "cannot build the base hive\n");
            return 5;
        }
        Bases = 1;
    }
    if (WritePath)
    {
        PUCHAR Out = malloc(BaseSize[WriteSeed % Bases]);
        FILE *f;
        RunOne(Base[WriteSeed % Bases], BaseSize[WriteSeed % Bases], WriteSeed, Out);
        f = fopen(WritePath, "wb");
        if (!f || fwrite(Out, 1, BaseSize[WriteSeed % Bases], f) != BaseSize[WriteSeed % Bases])
            return 6;
        fclose(f);
        return 0;
    }

#ifdef HFZ_ASAN
    __sanitizer_set_death_callback(OnDeath);
#endif
    signal(SIGALRM, OnSignal);
    signal(SIGSEGV, OnSignal);
    signal(SIGABRT, OnSignal);
    for (s = First; s < First + Count; s++)
    {
        g_CurSeed = s;
        alarm(20);
        RunOne(Base[s % Bases], BaseSize[s % Bases], s, NULL);

        /* So that a run that is stopped still says how far it got */
        if ((s - First + 1) % 1000 == 0)
        {
            fprintf(stderr, "HFZ progress %u..%u:", First, s);
            for (i = 0; i < 8; i++)
                fprintf(stderr, " %s=%lu", g_AnomalyName[i], (unsigned long)g_Anomaly[i]);
            fprintf(stderr, "\n");
        }
    }
    alarm(0);
    fprintf(stderr, "HFZ seeds %u..%u bases %lu:", First, First + Count - 1, (unsigned long)Bases);
    for (i = 0; i < 8; i++)
        fprintf(stderr, " %s=%lu", g_AnomalyName[i], (unsigned long)g_Anomaly[i]);
    fprintf(stderr, "\n");
    (void)OnDeath;
    return (g_Anomaly[0] || g_Anomaly[1] || g_Anomaly[2]) ? 1 : 0;
}
