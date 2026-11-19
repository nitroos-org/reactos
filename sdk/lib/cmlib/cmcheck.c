/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Configuration Manager Library - Registry Validation
 * COPYRIGHT:   Copyright 2022 George Bișoc <george.bisoc@reactos.org>
 */

#include "cmlib.h"
#define NDEBUG
#include <debug.h>

/*
 * A hive read from a file is untrusted input: a user can edit its own
 * profile hive while it is not loaded, an administrator loads any file. The
 * check below is the only code that reads a hive before it is known to be
 * sound; everything else (lookups, enumeration, value reads, deletes, the
 * security cache, saves) trusts every cell index, count and length it finds.
 * So when the check accepts a hive, these hold:
 *
 *  - The bins tile the storage: each bin is a whole number of blocks at the
 *    offset it names, and its cells tile the bin (sizes multiples of 8, at
 *    least 8, inside the bin). The free cells are what the free lists are
 *    made of (HvpCreateHiveFreeCellList).
 *  - Every cell index the tree holds is the start of an allocated cell of the
 *    stable storage (of the volatile one too in a live hive), as large as
 *    what is read from it. The check knows where cells start from a map of
 *    the bins made first (one bit per 8 bytes).
 *  - Every cell is used once: by one key (as its node, index, value list,
 *    value, data or class), or as an 'sk' cell of one sound ring. A second use
 *    of a cell (two keys sharing a list, a value cell that is also a key, an
 *    index that names itself, a cycle) is found in O(1) from a second map, so
 *    the tree has no cycle and its walk is linear in the size of the hive.
 *  - Key nodes: signature 'nk', a name inside the cell, the right parent, no
 *    flag a file key cannot have (hive exit, predefined handle, volatile), no
 *    volatile subkey in a file, a subkey index whose counts fit its cells and
 *    add up to the key's count, subkeys in the order lookups assume, a value
 *    list whose count fits its cell, a class inside its cell.
 *  - Values: signature 'vk', a name inside the cell, small data at most 4
 *    bytes, other data in one cell that holds all of it (ReactOS has no reader
 *    for big data chains: a value whose data is not one such cell is removed).
 *  - Security: a key's 'sk' cell is in a ring of sound 'sk' cells (each named
 *    by its neighbours, descriptor inside the cell) and holds a valid
 *    self-relative descriptor; reference counts are recounted.
 *
 * What does not hold is either repaired by a write inside a cell the check
 * has accepted (a count lowered, an entry removed from a list, a field
 * cleared), when self-healing is allowed, or the hive is refused. The boot
 * loader never repairs: it refuses. A live hive (CM_CHECK_REGISTRY_LIVE_HIVE)
 * is only checked.
 */

/* DEFINES  ******************************************************************/

#define GET_HHIVE(CmHive) (&((CmHive)->Hive))

#if !defined(CMLIB_HOST) && !defined(_BLDR_)
extern PCMHIVE CmiVolatileHive;
#endif

#define CMP_REGISTRY_MAX_LEVELS_TREE_DEPTH 512

#define CMP_KEY_SIZE_THRESHOLD 0x45C
#define CMP_MAX(a, b) ((a) > (b) ? (a) : (b))
#define CMP_VOLATILE_LIST_UNINTIALIZED 0xBAADF00D

/* PRIVATE FUNCTIONS **********************************************************/

/*
 * Recount of the references to the 'sk' cells.
 *
 * ReferenceCount of an 'sk' cell is the number of key nodes that name it. A
 * count that is too low is the dangerous one: the last key to go frees a cell
 * that other keys still use. A count that is too high only keeps a cell that is
 * no longer needed. At load the walk of the tree counts, per cell, the keys
 * that name it (a table keyed by the cell index), and when the walk is done the
 * stored counts are made equal to what was counted. The mkhive SYSTEM hive is
 * one too high; a hive that lost keys to a repair, or to a crash between the
 * write of a key and of its 'sk', could be either.
 *
 * Hive contents are not trusted: a cell is only counted after the check has
 * accepted it. Nothing here can fail the load: if the table cannot be built
 * the counts are left as they are.
 */
typedef struct _CMP_SK_TALLY_ENTRY
{
    HCELL_INDEX Cell;       /* HCELL_NIL: the slot is free */
    ULONG Count;
} CMP_SK_TALLY_ENTRY, *PCMP_SK_TALLY_ENTRY;

typedef struct _CMP_SK_TALLY
{
    PCMP_SK_TALLY_ENTRY Table;  /* open addressing, Capacity is a power of two */
    ULONG Capacity;
    ULONG Used;
    ULONG Multiplier;           /* odd, per table: the cell indexes are the hive's, the slots are not foreseeable */
    BOOLEAN Failed;             /* no memory, or more cells than a table may hold: no recount */
    BOOLEAN Partial;            /* a key that may name a cell was not counted: raise, never lower */
} CMP_SK_TALLY, *PCMP_SK_TALLY;

#define CMP_SK_TALLY_FIRST_CAPACITY 64
#define CMP_SK_TALLY_MAX_CAPACITY   (1UL << 22)

static
VOID
CmpSkTallyReset(
    _Inout_ PCMP_SK_TALLY Tally)
{
    if (Tally->Table)
        CmpFree(Tally->Table, Tally->Capacity * sizeof(CMP_SK_TALLY_ENTRY));
    RtlZeroMemory(Tally, sizeof(*Tally));
}

/*
 * The cell indexes come from the hive, so a crafted hive can choose them: in
 * the kernel the multiplier of the hash is drawn per table, so that the cells
 * of a hive cannot be picked to fall into one run of slots (which would make
 * every lookup walk the run). Elsewhere (boot loader, host tools) it is fixed.
 */
static
ULONG
CmpSkTallyNewMultiplier(VOID)
{
#if !defined(CMLIB_HOST) && !defined(_BLDR_)
    LARGE_INTEGER Counter = KeQueryPerformanceCounter(NULL);
    ULONG Seed = Counter.LowPart ^ (Counter.HighPart * 0x9E3779B9U) ^ (ULONG)(ULONG_PTR)&Counter;

    Seed ^= Seed >> 16;
    Seed *= 0x85EBCA6BU;
    Seed ^= Seed >> 13;
    return Seed | 1;
#else
    return 2654435761U;
#endif
}

static
ULONG
CmpSkTallySlot(
    _In_ HCELL_INDEX Cell,
    _In_ ULONG Capacity,
    _In_ ULONG Multiplier)
{
    ULONG Hash = (Cell >> 3) * Multiplier;

    Hash ^= Hash >> 15;
    return Hash & (Capacity - 1);
}

/* Find the entry of Cell, or the free slot where it goes */
static
PCMP_SK_TALLY_ENTRY
CmpSkTallyFind(
    _In_ PCMP_SK_TALLY_ENTRY Table,
    _In_ ULONG Capacity,
    _In_ ULONG Multiplier,
    _In_ HCELL_INDEX Cell)
{
    ULONG Slot = CmpSkTallySlot(Cell, Capacity, Multiplier);

    /* The table is at most half full: a free slot is always found */
    while (Table[Slot].Cell != HCELL_NIL && Table[Slot].Cell != Cell)
        Slot = (Slot + 1) & (Capacity - 1);
    return &Table[Slot];
}

static
BOOLEAN
CmpSkTallyGrow(
    _Inout_ PCMP_SK_TALLY Tally)
{
    PCMP_SK_TALLY_ENTRY NewTable, Entry;
    ULONG NewCapacity, i;

    NewCapacity = Tally->Capacity ? Tally->Capacity * 2 : CMP_SK_TALLY_FIRST_CAPACITY;
    if (NewCapacity > CMP_SK_TALLY_MAX_CAPACITY)
        return FALSE;
    if (!Tally->Multiplier)
        Tally->Multiplier = CmpSkTallyNewMultiplier();
    NewTable = CmpAllocate(NewCapacity * sizeof(CMP_SK_TALLY_ENTRY), TRUE, TAG_CM);
    if (!NewTable)
        return FALSE;
    for (i = 0; i < NewCapacity; i++)
    {
        NewTable[i].Cell = HCELL_NIL;
        NewTable[i].Count = 0;
    }
    for (i = 0; i < Tally->Capacity; i++)
    {
        if (Tally->Table[i].Cell == HCELL_NIL)
            continue;
        Entry = CmpSkTallyFind(NewTable, NewCapacity, Tally->Multiplier, Tally->Table[i].Cell);
        *Entry = Tally->Table[i];
    }
    if (Tally->Table)
        CmpFree(Tally->Table, Tally->Capacity * sizeof(CMP_SK_TALLY_ENTRY));
    Tally->Table = NewTable;
    Tally->Capacity = NewCapacity;
    return TRUE;
}

/* One more key names Cell (a cell the check accepted) */
static
VOID
CmpSkTallyAdd(
    _Inout_ PCMP_SK_TALLY Tally,
    _In_ HCELL_INDEX Cell)
{
    PCMP_SK_TALLY_ENTRY Entry;

    if (Tally->Failed)
        return;
    if (Tally->Table)
    {
        Entry = CmpSkTallyFind(Tally->Table, Tally->Capacity, Tally->Multiplier, Cell);
        if (Entry->Cell == Cell)
        {
            if (Entry->Count != MAXULONG)
                Entry->Count++;
            return;
        }
    }

    /* A new cell: keep the table at most half full */
    if ((Tally->Used + 1) * 2 > Tally->Capacity && !CmpSkTallyGrow(Tally))
    {
        DPRINT1("No room to recount the references of the security cells, left as they are\n");
        CmpSkTallyReset(Tally);
        Tally->Failed = TRUE;
        return;
    }
    Entry = CmpSkTallyFind(Tally->Table, Tally->Capacity, Tally->Multiplier, Cell);
    Entry->Cell = Cell;
    Entry->Count = 1;
    Tally->Used++;
}

/*
 * The walk is complete and found nothing wrong that stops the load: make the
 * stored counts equal to the counted ones. In memory this is always done; the
 * cell is marked dirty (so that the fix is written) only with FixHive.
 * An over-count is lowered only if every key was counted; raising is always
 * right, since what was counted is a lower bound of the keys that name the cell.
 */
static
VOID
CmpApplySecurityRecount(
    _In_ PHHIVE Hive,
    _In_ PCMP_SK_TALLY Tally,
    _In_ BOOLEAN FixHive)
{
    PCM_KEY_SECURITY Security;
    ULONG i, Raised = 0, Lowered = 0, Kept = 0;

    if (Tally->Failed || !Tally->Table)
        return;

    for (i = 0; i < Tally->Capacity; i++)
    {
        HCELL_INDEX Cell = Tally->Table[i].Cell;
        ULONG Actual = Tally->Table[i].Count;

        if (Cell == HCELL_NIL)
            continue;

        /* Accepted when the key was counted, but never trust the pointer twice */
        Security = CmpGetCheckedSecurityCell(Hive, Cell, NULL);
        if (!Security || Security->ReferenceCount == Actual)
            continue;

        if (Security->ReferenceCount > Actual && Tally->Partial)
        {
            Kept++;
            continue;
        }

        /* The first of each kind; the totals follow below */
        if (Security->ReferenceCount < Actual ? Raised == 0 : Lowered == 0)
        {
            DPRINT1("Security cell 0x%x: %lu keys name it, ReferenceCount %lu, %s\n",
                    Cell, (unsigned long)Actual, (unsigned long)Security->ReferenceCount,
                    Security->ReferenceCount < Actual ? "raised" : "lowered");
        }
        if (Security->ReferenceCount < Actual)
            Raised++;
        else
            Lowered++;

        /* Dirty first; if that cannot be done the memory still gets the safe value */
        if (FixHive)
            HvMarkCellDirty(Hive, Cell, FALSE);
        Security->ReferenceCount = Actual;
    }

    if (Raised || Lowered || Kept)
    {
        DPRINT1("Hive 0x%p: security cell reference counts: %lu raised, %lu lowered, %lu too high and left\n",
                Hive, (unsigned long)Raised, (unsigned long)Lowered, (unsigned long)Kept);
    }
}

/* The set of cells the ring walks of one load have visited (a tally whose counts are unused) */
static
BOOLEAN
NTAPI
CmpSkMarkSeen(
    _In_ PVOID Context,
    _In_ HCELL_INDEX Cell,
    _Out_ PBOOLEAN Seen)
{
    PCMP_SK_TALLY Visited = Context;
    PCMP_SK_TALLY_ENTRY Entry;

    *Seen = FALSE;
    if (Visited->Table)
    {
        Entry = CmpSkTallyFind(Visited->Table, Visited->Capacity, Visited->Multiplier, Cell);
        if (Entry->Cell == Cell)
        {
            *Seen = TRUE;
            return TRUE;
        }
    }
    CmpSkTallyAdd(Visited, Cell);
    return !Visited->Failed;
}

/*
 * The cache of a hive being loaded: the root's ring first, then the ring of
 * every cell a key names. Keys created since a hive got stored descriptors may
 * name cells of a ring the root is not in (the root has none on hives
 * installed before), and those cells must be found again to be shared. Runs
 * after the walk, which has reset every Security that is not a valid cell.
 * The walks share one set of visited cells, so that the work is linear in the
 * number of cells whatever the rings look like. Never fails the load.
 */
static
VOID
CmpCacheSecurityRings(
    _In_ PHHIVE Hive,
    _In_ PCMP_SK_TALLY Tally)
{
    CMP_SK_TALLY Visited;
    ULONG i;

    CmpBuildSecurityCache((PCMHIVE)Hive);
    if (Tally->Failed || !Tally->Table)
        return;
    RtlZeroMemory(&Visited, sizeof(Visited));
    for (i = 0; i < Tally->Capacity; i++)
    {
        if (Tally->Table[i].Cell != HCELL_NIL &&
            !CmpAddSecurityRingToCache((PCMHIVE)Hive, Tally->Table[i].Cell, CmpSkMarkSeen, &Visited))
        {
            DPRINT1("Hive 0x%p: no room to walk the security rings, the cache is short\n", Hive);
            break;
        }
    }
    CmpSkTallyReset(&Visited);
}

#if defined(_BLDR_)
/* A name with a character that the loader cannot upper case, see below */
static
BOOLEAN
CmpKeyNodeNameHasNonAscii(
    _In_ PCM_KEY_NODE Node)
{
    ULONG i;

    if (Node->Flags & KEY_COMP_NAME)
    {
        for (i = 0; i < Node->NameLength; i++)
        {
            if (((PUCHAR)Node->Name)[i] >= 0x80)
                return TRUE;
        }
    }
    else
    {
        for (i = 0; i < Node->NameLength / sizeof(WCHAR); i++)
        {
            if (Node->Name[i] >= 0x80)
                return TRUE;
        }
    }
    return FALSE;
}
#endif

/**
 * @brief
 * Validates the lexicographical order between a child
 * and prior sibling of the said child. Both are key
 * nodes the check has accepted.
 *
 * @return
 * Returns TRUE if the order is legal, FALSE otherwise.
 */
static
BOOLEAN
CmpValidateLexicalOrder(
    _In_ PCM_KEY_NODE ChildNode,
    _In_ PCM_KEY_NODE SiblingNode)
{
    LONG Result;
    UNICODE_STRING ChildString, SiblingString;

    PAGED_CODE();

#if defined(_BLDR_)
    /*
     * The boot loader looks names up with the case table of the kernel (it
     * has it as C data) but it cannot repair a hive. A name that is not plain
     * ASCII may stand in the order an older kernel, with another case table,
     * gave it, or be equal to its sibling under this table: refusing the hive
     * for that would leave the system unbootable, while the kernel repairs
     * it (CmpRepairSubKeyIndexCase, then the check below drops the second of
     * two siblings that are equal, as Windows does). So these are left to the
     * kernel, which checks every hive when it loads it.
     */
    if (CmpKeyNodeNameHasNonAscii(ChildNode) ||
        CmpKeyNodeNameHasNonAscii(SiblingNode))
    {
        return TRUE;
    }
#endif

    /* CASE 1: Two distinct non-compressed Unicode names */
    if ((ChildNode->Flags & KEY_COMP_NAME) == 0 &&
        (SiblingNode->Flags & KEY_COMP_NAME) == 0)
    {
        SiblingString.Buffer = &(SiblingNode->Name[0]);
        SiblingString.Length = SiblingNode->NameLength;
        SiblingString.MaximumLength = SiblingNode->NameLength;

        ChildString.Buffer = &(ChildNode->Name[0]);
        ChildString.Length = ChildNode->NameLength;
        ChildString.MaximumLength = ChildNode->NameLength;

        Result = RtlCompareUnicodeString(&SiblingString, &ChildString, TRUE);
        if (Result >= 0)
        {
            DPRINT1("The sibling node name is greater or equal to that of the child\n");
            return FALSE;
        }
    }

    /* CASE 2: Both compressed Unicode names */
    if ((ChildNode->Flags & KEY_COMP_NAME) &&
        (SiblingNode->Flags & KEY_COMP_NAME))
    {
        /*
         * The same rule as for the Unicode names: the sibling must be
         * lesser, names that are equal when upper cased are as much out
         * of order as names that are in the wrong order (Windows removes
         * the second of such siblings when it loads the hive).
         */
        PUCHAR SiblingName = (PUCHAR)SiblingNode->Name;
        PUCHAR ChildName = (PUCHAR)ChildNode->Name;
        ULONG Common = min(SiblingNode->NameLength, ChildNode->NameLength);
        ULONG i;

        Result = 0;
        for (i = 0; i < Common && Result == 0; i++)
        {
            if (SiblingName[i] != ChildName[i])
            {
                Result = (LONG)RtlUpcaseUnicodeChar(SiblingName[i]) -
                         (LONG)RtlUpcaseUnicodeChar(ChildName[i]);
            }
        }
        if (Result == 0)
            Result = (LONG)SiblingNode->NameLength - (LONG)ChildNode->NameLength;

        if (Result >= 0)
        {
            DPRINT1("The compressed sibling node name is greater or equal to that of the compressed child\n");
            return FALSE;
        }
    }

    /* CASE 3: The child name is compressed but the sibling is not */
    if ((ChildNode->Flags & KEY_COMP_NAME) &&
        (SiblingNode->Flags & KEY_COMP_NAME) == 0)
    {
        SiblingString.Buffer = &(SiblingNode->Name[0]);
        SiblingString.Length = SiblingNode->NameLength;
        SiblingString.MaximumLength = SiblingNode->NameLength;
        Result = CmpCompareCompressedName(&SiblingString,
                                          ChildNode->Name,
                                          ChildNode->NameLength);
        if (Result >= 0)
        {
            DPRINT1("The sibling node name is greater or equal to that of the compressed child\n");
            return FALSE;
        }
    }

    /* CASE 4: The sibling name is compressed but the child is not */
    if ((SiblingNode->Flags & KEY_COMP_NAME) &&
        (ChildNode->Flags & KEY_COMP_NAME) == 0)
    {
        ChildString.Buffer = &(ChildNode->Name[0]);
        ChildString.Length = ChildNode->NameLength;
        ChildString.MaximumLength = ChildNode->NameLength;
        Result = CmpCompareCompressedName(&ChildString,
                                          SiblingNode->Name,
                                          SiblingNode->NameLength);
        if (Result <= 0)
        {
            DPRINT1("The compressed sibling node name is lesser or equal to that of the child\n");
            return FALSE;
        }
    }

    return TRUE;
}

/* THE CELL MAP ***************************************************************/

/*
 * Per storage type, one bit per 8 bytes of the storage (cells are 8-byte
 * aligned and at least 8 bytes long):
 *
 *  Start  an allocated cell starts here (from the walk of the bins);
 *  Used   the tree uses this cell (with Sk: an 'sk' cell of a sound ring);
 *  Sk     an 'sk' cell (without Used: one that is not sound, or that a ring
 *         walk in progress has passed).
 */
typedef struct _CMP_CELL_MAP
{
    PULONG Start[HTYPE_COUNT];
    PULONG Used[HTYPE_COUNT];
    PULONG Sk[HTYPE_COUNT];
    ULONG Length[HTYPE_COUNT];      /* bytes of storage the map covers */
    ULONG Bytes[HTYPE_COUNT];       /* size of each of the three bitmaps */
} CMP_CELL_MAP, *PCMP_CELL_MAP;

/* Memory the check frees before it returns */
static
PVOID
CmpCheckAllocate(
    _In_ SIZE_T Size)
{
#if defined(_BLDR_)
    return CmpAllocateTemporary(Size);
#else
    return CmpAllocate(Size, TRUE, TAG_REGISTRY_STACK);
#endif
}

static
VOID
CmpCheckFree(
    _In_ PVOID Ptr,
    _In_ SIZE_T Size)
{
#if defined(_BLDR_)
    UNREFERENCED_PARAMETER(Size);
    CmpFreeTemporary(Ptr);
#else
    CmpFree(Ptr, (ULONG)Size);
#endif
}

#define CMP_BIT_TEST(Map, Bit)  (((Map)[(Bit) >> 5] >> ((Bit) & 31)) & 1)
#define CMP_BIT_SET(Map, Bit)   ((Map)[(Bit) >> 5] |= (1UL << ((Bit) & 31)))

/* The most a storage may hold: the offset of a cell index has 31 bits */
#define CMP_MAX_STORAGE_LENGTH  0x80000000UL

typedef struct _CMP_CHECK
{
    PHHIVE Hive;
    ULONG Flags;
    BOOLEAN Live;           /* a hive in use: check only, volatile keys too */
    BOOLEAN Heal;           /* repairs are allowed (self-healing, not live) */
    BOOLEAN FixHive;
    CMP_CELL_MAP Map;
    PCMP_SK_TALLY Tally;
    CMP_CASE_REPAIR_STATS Stats;
    ULONG KeysRemoved;
    ULONG ValuesRemoved;
    ULONG ListsPurged;
    ULONG FieldsReset;
} CMP_CHECK, *PCMP_CHECK;

static
VOID
CmpFreeCellMap(
    _Inout_ PCMP_CELL_MAP Map)
{
    ULONG Type;

    for (Type = 0; Type < HTYPE_COUNT; Type++)
    {
        if (Map->Start[Type])
            CmpCheckFree(Map->Start[Type], 3 * Map->Bytes[Type]);
        Map->Start[Type] = Map->Used[Type] = Map->Sk[Type] = NULL;
        Map->Length[Type] = Map->Bytes[Type] = 0;
    }
}

/*
 * The cells of one bin (at Offset in its storage, Length bytes of storage):
 * the header, then cells that tile it. Marks the allocated cells in Start if
 * given.
 */
static
CM_CHECK_REGISTRY_STATUS
CmpCheckBinCells(
    _In_ PHBIN Bin,
    _In_ ULONG Offset,
    _In_ ULONG Length,
    _Inout_ PULONG Start OPTIONAL)
{
    ULONG CellOffset, CellSize;
    LONG RawSize;

    if (Bin->Signature != HV_HBIN_SIGNATURE)
    {
        DPRINT1("Bin at 0x%x: bad signature\n", Offset);
        return CM_CHECK_REGISTRY_BIN_SIGNATURE_HEADER_CORRUPT;
    }

    /* A whole number of blocks, at least one, where the bin says it is, inside the storage */
    if (Bin->FileOffset != Offset ||
        Bin->Size < HBLOCK_SIZE ||
        (Bin->Size % HBLOCK_SIZE) != 0 ||
        Bin->Size > Length - Offset)
    {
        DPRINT1("Bin at 0x%x: bad size 0x%x or offset 0x%x\n", Offset, Bin->Size, Bin->FileOffset);
        return CM_CHECK_REGISTRY_BIN_SIZE_OR_OFFSET_CORRUPT;
    }

    for (CellOffset = sizeof(HBIN); CellOffset < Bin->Size; CellOffset += CellSize)
    {
        if (Bin->Size - CellOffset < sizeof(HCELL) + sizeof(HCELL_INDEX))
        {
            DPRINT1("Bin at 0x%x: a cell header at 0x%x runs past the bin\n", Offset, CellOffset);
            return CM_CHECK_REGISTRY_BAD_FREE_CELL;
        }
        RawSize = ((PHCELL)((PUCHAR)Bin + CellOffset))->Size;
        CellSize = RawSize < 0 ? 0 - (ULONG)RawSize : (ULONG)RawSize;
        if (CellSize < sizeof(HCELL) + sizeof(HCELL_INDEX) ||
            (CellSize & 7) != 0 ||
            CellSize > Bin->Size - CellOffset)
        {
            DPRINT1("Bin at 0x%x: cell at 0x%x has a bad size %d\n", Offset, CellOffset, RawSize);
            return RawSize < 0 ? CM_CHECK_REGISTRY_BAD_ALLOC_CELL : CM_CHECK_REGISTRY_BAD_FREE_CELL;
        }
        if (RawSize < 0 && Start)
            CMP_BIT_SET(Start, (Offset + CellOffset) >> 3);
    }
    return CM_CHECK_REGISTRY_GOOD;
}

/*
 * The map of the cells of every storage the check covers: the stable one (a
 * hive being loaded has nothing else), and the volatile one of a live hive.
 * Every bin and every cell is checked on the way.
 */
static
CM_CHECK_REGISTRY_STATUS
CmpBuildCellMap(
    _In_ PHHIVE Hive,
    _In_ BOOLEAN Live,
    _Out_ PCMP_CELL_MAP Map)
{
    CM_CHECK_REGISTRY_STATUS Status;
    ULONG Type, Types, Offset, Length, Block, i;
    PHMAP_ENTRY Entry;
    PHBIN Bin;
    PULONG Bits;

    RtlZeroMemory(Map, sizeof(*Map));
    Types = (Live && !Hive->Flat) ? HTYPE_COUNT : 1;
    for (Type = 0; Type < Types; Type++)
    {
        if (Hive->Flat)
        {
            Length = Hive->BaseBlock->Length;
            if ((Length % HBLOCK_SIZE) != 0)
                return CM_CHECK_REGISTRY_BIN_SIZE_OR_OFFSET_CORRUPT;
        }
        else
        {
            if (Hive->Storage[Type].Length > CMP_MAX_STORAGE_LENGTH / HBLOCK_SIZE)
                return CM_CHECK_REGISTRY_BIN_SIZE_OR_OFFSET_CORRUPT;
            Length = Hive->Storage[Type].Length * HBLOCK_SIZE;
        }
        if (Length > CMP_MAX_STORAGE_LENGTH)
            return CM_CHECK_REGISTRY_BIN_SIZE_OR_OFFSET_CORRUPT;
        if (Length == 0)
            continue;

        /* One bit per 8 bytes, three bitmaps in one allocation */
        Map->Length[Type] = Length;
        Map->Bytes[Type] = ((Length / 8 + 31) / 32) * sizeof(ULONG);
        Bits = CmpCheckAllocate(3 * Map->Bytes[Type]);
        if (!Bits)
        {
            DPRINT1("No memory for the cell map of the hive (%lu bytes)\n", (unsigned long)(3 * Map->Bytes[Type]));
            CmpFreeCellMap(Map);
            return CM_CHECK_REGISTRY_ALLOCATE_MEM_STACK_FAIL;
        }
        RtlZeroMemory(Bits, 3 * Map->Bytes[Type]);
        Map->Start[Type] = Bits;
        Map->Used[Type] = (PULONG)((PUCHAR)Bits + Map->Bytes[Type]);
        Map->Sk[Type] = (PULONG)((PUCHAR)Bits + 2 * Map->Bytes[Type]);

        for (Offset = 0; Offset < Length; Offset += Bin->Size)
        {
            if (Hive->Flat)
            {
                /* One run of bins right after the base block */
                Bin = (PHBIN)((PUCHAR)Hive->BaseBlock + HBLOCK_SIZE + Offset);
            }
            else
            {
                /* A bin's first block maps the bin, and so do all of its blocks */
                Block = Offset / HBLOCK_SIZE;
                Entry = &Hive->Storage[Type].BlockList[Block];
                Bin = (PHBIN)Entry->BinAddress;
                if (!Bin || Entry->BlockAddress != (ULONG_PTR)Bin)
                {
                    DPRINT1("Block %lu of storage %lu does not start a bin\n", (unsigned long)Block, (unsigned long)Type);
                    CmpFreeCellMap(Map);
                    return CM_CHECK_REGISTRY_BIN_SIZE_OR_OFFSET_CORRUPT;
                }
            }

            Status = CmpCheckBinCells(Bin, Offset, Length, Map->Start[Type]);
            if (!CM_CHECK_REGISTRY_SUCCESS(Status))
            {
                CmpFreeCellMap(Map);
                return Status;
            }

            if (!Hive->Flat)
            {
                for (i = 1; i < Bin->Size / HBLOCK_SIZE; i++)
                {
                    if (Entry[i].BinAddress != (ULONG_PTR)Bin ||
                        Entry[i].BlockAddress != (ULONG_PTR)Bin + i * HBLOCK_SIZE)
                    {
                        DPRINT1("Block %lu of storage %lu is not mapped to its bin\n",
                                (unsigned long)(Block + i), (unsigned long)Type);
                        CmpFreeCellMap(Map);
                        return CM_CHECK_REGISTRY_BIN_SIZE_OR_OFFSET_CORRUPT;
                    }
                }
            }
        }
    }
    return CM_CHECK_REGISTRY_GOOD;
}

/*
 * The data of Cell if it is the start of an allocated cell the map covers
 * and holds at least MinSize bytes, else NULL. Only cells of the stable
 * storage, unless the hive is live.
 */
static
PVOID
CmpMapCell(
    _In_ PCMP_CHECK Ctx,
    _In_ HCELL_INDEX Cell,
    _In_ ULONG MinSize,
    _Out_ PULONG Size OPTIONAL)
{
    ULONG Type, Offset;
    LONG CellSize;
    PVOID Data;

    if (Cell == HCELL_NIL)
        return NULL;
    Type = HvGetCellType(Cell);
    Offset = Cell & ~HCELL_TYPE_MASK;
    if ((Type != Stable && !Ctx->Live) ||
        (Offset & 7) != 0 ||
        Offset >= Ctx->Map.Length[Type] ||
        !CMP_BIT_TEST(Ctx->Map.Start[Type], Offset >> 3))
    {
        return NULL;
    }

    /* A cell start of the map: the header and the data lie inside one bin */
    Data = (PVOID)HvGetCell(Ctx->Hive, Cell);
    if (!Data)
        return NULL;
    CellSize = HvGetCellSize(Ctx->Hive, Data);
    if (CellSize < 0 || (ULONG)CellSize < MinSize)
        return NULL;
    if (Size)
        *Size = (ULONG)CellSize;
    return Data;
}

/* Give Cell its one use in the tree; FALSE if it has one already */
static
BOOLEAN
CmpClaimCell(
    _In_ PCMP_CHECK Ctx,
    _In_ HCELL_INDEX Cell)
{
    ULONG Type = HvGetCellType(Cell);
    ULONG Bit = (Cell & ~HCELL_TYPE_MASK) >> 3;

    if (CMP_BIT_TEST(Ctx->Map.Used[Type], Bit) || CMP_BIT_TEST(Ctx->Map.Sk[Type], Bit))
        return FALSE;
    CMP_BIT_SET(Ctx->Map.Used[Type], Bit);
    return TRUE;
}

/* A cell checked and given its use; NULL if it is not a cell, too small, or in use */
static
PVOID
CmpTakeCell(
    _In_ PCMP_CHECK Ctx,
    _In_ HCELL_INDEX Cell,
    _In_ ULONG MinSize,
    _Out_ PULONG Size OPTIONAL)
{
    PVOID Data = CmpMapCell(Ctx, Cell, MinSize, Size);

    if (!Data || !CmpClaimCell(Ctx, Cell))
        return NULL;
    return Data;
}

/* A cell the check changes: dirty, so that a repair is written, if the hive can be written */
static
VOID
CmpCheckDirty(
    _In_ PCMP_CHECK Ctx,
    _In_ HCELL_INDEX Cell)
{
    if (Ctx->Heal && !Ctx->Hive->ReadOnly && !Ctx->Hive->Flat)
        HvMarkCellDirty(Ctx->Hive, Cell, FALSE);
}

/* A repair was made: the hive is self-healed */
static
VOID
CmpCheckHealed(
    _In_ PCMP_CHECK Ctx)
{
    Ctx->Hive->BaseBlock->BootType |= HBOOT_TYPE_SELF_HEAL;
}

/* For CmpRepairSubKeyIndexCase: an index entry it may read as a key node */
static
BOOLEAN
CmpIsKeyCell(
    _In_ PVOID Context,
    _In_ HCELL_INDEX Cell)
{
    PCMP_CHECK Ctx = Context;
    PCM_KEY_NODE Node;
    ULONG Size;
    ULONG Type = HvGetCellType(Cell);

    Node = CmpMapCell(Ctx, Cell, FIELD_OFFSET(CM_KEY_NODE, Name), &Size);
    if (!Node ||
        CMP_BIT_TEST(Ctx->Map.Sk[Type], (Cell & ~HCELL_TYPE_MASK) >> 3) ||
        Node->Signature != CM_KEY_NODE_SIGNATURE ||
        Node->NameLength == 0 ||
        Node->NameLength > Size - FIELD_OFFSET(CM_KEY_NODE, Name) ||
        (!(Node->Flags & KEY_COMP_NAME) && (Node->NameLength % sizeof(WCHAR)) != 0))
    {
        return FALSE;
    }
    return TRUE;
}

/* SECURITY *******************************************************************/

/*
 * Is the ring Cell is in sound: every cell of it an 'sk' cell of the same
 * storage, its descriptor inside the cell, named by its neighbours both ways,
 * and the ring closes. Each cell is walked once per check: a sound ring is
 * marked Used+Sk, the cells of a walk that fails stay Sk only (not sound),
 * so a key naming any of them is answered at once.
 */
static
BOOLEAN
CmpCheckSecurityRing(
    _In_ PCMP_CHECK Ctx,
    _In_ HCELL_INDEX Cell)
{
    PCM_KEY_SECURITY Security, Next;
    HCELL_INDEX Current, Flink;
    ULONG Type = HvGetCellType(Cell), Bit, Size;

    Current = Cell;
    for (;;)
    {
        Security = CmpMapCell(Ctx, Current, FIELD_OFFSET(CM_KEY_SECURITY, Descriptor), &Size);
        if (!Security || HvGetCellType(Current) != Type)
            return FALSE;
        Bit = (Current & ~HCELL_TYPE_MASK) >> 3;

        /* In use as something else, not sound, or met before in this walk (a loop that misses Cell) */
        if (CMP_BIT_TEST(Ctx->Map.Used[Type], Bit) || CMP_BIT_TEST(Ctx->Map.Sk[Type], Bit))
            return FALSE;
        CMP_BIT_SET(Ctx->Map.Sk[Type], Bit);

        if (Security->Signature != CM_KEY_SECURITY_SIGNATURE ||
            Security->DescriptorLength > Size - FIELD_OFFSET(CM_KEY_SECURITY, Descriptor))
        {
            return FALSE;
        }

        /* The next cell must name this one back */
        Flink = Security->Flink;
        Next = CmpMapCell(Ctx, Flink, FIELD_OFFSET(CM_KEY_SECURITY, Descriptor), NULL);
        if (!Next || HvGetCellType(Flink) != Type || Next->Blink != Current)
            return FALSE;

        Current = Flink;
        if (Current == Cell)
            break;
    }

    /* Sound: every cell of the ring becomes an 'sk' cell in use */
    do
    {
        CMP_BIT_SET(Ctx->Map.Used[Type], (Current & ~HCELL_TYPE_MASK) >> 3);
        Current = ((PCM_KEY_SECURITY)HvGetCell(Ctx->Hive, Current))->Flink;
    } while (Current != Cell);
    return TRUE;
}

/* May a key name Cell as its security: a cell of a sound ring with a valid descriptor */
static
BOOLEAN
CmpCheckKeySecurity(
    _In_ PCMP_CHECK Ctx,
    _In_ HCELL_INDEX Cell)
{
    PCM_KEY_SECURITY Security;
    ULONG Type, Bit;

    if (!CmpMapCell(Ctx, Cell, FIELD_OFFSET(CM_KEY_SECURITY, Descriptor), NULL))
        return FALSE;
    Type = HvGetCellType(Cell);
    Bit = (Cell & ~HCELL_TYPE_MASK) >> 3;
    if (!CMP_BIT_TEST(Ctx->Map.Sk[Type], Bit))
    {
        if (CMP_BIT_TEST(Ctx->Map.Used[Type], Bit) || !CmpCheckSecurityRing(Ctx, Cell))
            return FALSE;
    }
    else if (!CMP_BIT_TEST(Ctx->Map.Used[Type], Bit))
    {
        /* Seen in a ring that is not sound */
        return FALSE;
    }

    /* A cell no key holds a reference to is not one a key may name (as before the recount) */
    Security = (PCM_KEY_SECURITY)HvGetCell(Ctx->Hive, Cell);
    if (Security->ReferenceCount == 0)
        return FALSE;
    if (!CmpIsSaneRelativeDescriptor(&Security->Descriptor, Security->DescriptorLength))
        return FALSE;
#if !defined(CMLIB_HOST) && !defined(_BLDR_)
    if (!RtlValidRelativeSecurityDescriptor(&Security->Descriptor, Security->DescriptorLength, 0))
        return FALSE;
#endif
    return TRUE;
}

/* VALUES *********************************************************************/

/* Is the value at Cell sound; its name length in bytes as a Unicode string, its data length */
static
BOOLEAN
CmpCheckValue(
    _In_ PCMP_CHECK Ctx,
    _In_ HCELL_INDEX Cell,
    _Out_ PULONG NameBytes,
    _Out_ PULONG DataBytes)
{
    PCM_KEY_VALUE Value;
    ULONG Size, Length;

    Value = CmpTakeCell(Ctx, Cell, FIELD_OFFSET(CM_KEY_VALUE, Name), &Size);
    if (!Value ||
        Value->Signature != CM_KEY_VALUE_SIGNATURE ||
        Value->NameLength > Size - FIELD_OFFSET(CM_KEY_VALUE, Name) ||
        (!(Value->Flags & VALUE_COMP_NAME) && (Value->NameLength % sizeof(WCHAR)) != 0))
    {
        return FALSE;
    }

    if (CmpIsKeyValueSmall(&Length, Value->DataLength))
    {
        /* The data is the Data field itself */
        if (Length > CM_KEY_VALUE_SMALL)
            return FALSE;
    }
    else if (Value->Data == HCELL_NIL)
    {
        if (Length != 0)
            return FALSE;

        /* No data and no cell: the readers would look the cell up (CmpGetValueData); make it empty small data */
        if (!Ctx->Live)
        {
            CmpCheckDirty(Ctx, Cell);
            Value->DataLength = CM_KEY_VALUE_SPECIAL_SIZE;
            Value->Data = 0;
        }
    }
    else
    {
        /* One cell holds all of the data (a big data chain does not, see above) */
        if (!CmpTakeCell(Ctx, Value->Data, Length, NULL))
            return FALSE;
    }

    *NameBytes = (Value->Flags & VALUE_COMP_NAME) ? Value->NameLength * sizeof(WCHAR) : Value->NameLength;
    *DataBytes = Length;
    return TRUE;
}

/*
 * The value list of a key: the list cell holds Count entries, every entry is
 * a sound value. A value that is not is removed from the list (the list is
 * compacted in place, in one pass); a list cell that is not sound is dropped.
 * Gives the longest name (bytes, as Unicode) and data of the values kept.
 */
static
BOOLEAN
CmpCheckValueList(
    _In_ PCMP_CHECK Ctx,
    _In_ HCELL_INDEX KeyCell,
    _Inout_ PCM_KEY_NODE Node,
    _Out_ PULONG MaxNameBytes,
    _Out_ PULONG MaxDataBytes)
{
    PHCELL_INDEX List;
    ULONG Size, Count, i, Kept, NameBytes, DataBytes, MaxName = 0, MaxData = 0;

    *MaxNameBytes = 0;
    *MaxDataBytes = 0;
    Count = Node->ValueList.Count;
    if (Count == 0)
    {
        /* A new value would take this as a list cell to grow */
        if (Node->ValueList.List != HCELL_NIL && !Ctx->Live)
        {
            Node->ValueList.List = HCELL_NIL;
            CmpCheckDirty(Ctx, KeyCell);
        }
        return TRUE;
    }

    List = CmpTakeCell(Ctx, Node->ValueList.List, 0, &Size);
    if (!List || Count > Size / sizeof(HCELL_INDEX))
    {
        DPRINT1("Key 0x%x: the value list (count %lu) is not sound\n", KeyCell, (unsigned long)Count);
        if (!Ctx->Heal)
            return FALSE;
        CmpCheckDirty(Ctx, KeyCell);
        Node->ValueList.List = HCELL_NIL;
        Node->ValueList.Count = 0;
        Ctx->ListsPurged++;
        CmpCheckHealed(Ctx);
        return TRUE;
    }

    for (i = 0, Kept = 0; i < Count; i++)
    {
        if (!CmpCheckValue(Ctx, List[i], &NameBytes, &DataBytes))
        {
            if (!Ctx->Heal)
            {
                DPRINT1("Key 0x%x: value %lu (cell 0x%x) is not sound\n", KeyCell, (unsigned long)i, List[i]);
                return FALSE;
            }
            Ctx->ValuesRemoved++;
            continue;
        }
        MaxName = CMP_MAX(MaxName, NameBytes);
        MaxData = CMP_MAX(MaxData, DataBytes);
        if (Kept != i)
            List[Kept] = List[i];
        Kept++;
    }

    if (Kept != Count)
    {
        CmpCheckDirty(Ctx, KeyCell);
        CmpCheckDirty(Ctx, Node->ValueList.List);
        Node->ValueList.Count = Kept;
        if (Kept == 0)
            Node->ValueList.List = HCELL_NIL;
        CmpCheckHealed(Ctx);
    }

    *MaxNameBytes = MaxName;
    *MaxDataBytes = MaxData;
    return TRUE;
}

/* KEYS ***********************************************************************/

/* The flags a key of a hive file may have */
#define CMP_FILE_KEY_FLAGS_DROPPED (KEY_HIVE_EXIT | KEY_PREDEF_HANDLE | KEY_IS_VOLATILE)

/*
 * Is the key at Cell sound by itself (its subkeys are checked by the walk):
 * a key node cell not in use, its name inside it, its security, class and
 * value list. Fields that are wrong but repairable are repaired; FALSE means
 * the key cannot be kept (the caller removes it from its parent, or refuses
 * the hive for the root).
 */
static
BOOLEAN
CmpCheckKey(
    _In_ PCMP_CHECK Ctx,
    _In_ HCELL_INDEX Cell,
    _In_ HCELL_INDEX Parent,
    _Out_ PCM_KEY_NODE *KeyNode)
{
    PCM_KEY_NODE Node;
    ULONG Size, MaxValueName, MaxValueData;

    *KeyNode = NULL;
    Node = CmpTakeCell(Ctx, Cell, FIELD_OFFSET(CM_KEY_NODE, Name), &Size);
    if (!Node)
    {
        DPRINT1("Key 0x%x is not a cell, or a cell in use\n", Cell);
        return FALSE;
    }
    /* A Unicode name is a whole number of characters: the lookups compare lengths in bytes */
    if (Node->Signature != CM_KEY_NODE_SIGNATURE ||
        Size > CMP_KEY_SIZE_THRESHOLD ||
        Node->NameLength == 0 ||
        Node->NameLength > Size - FIELD_OFFSET(CM_KEY_NODE, Name) ||
        (!(Node->Flags & KEY_COMP_NAME) && (Node->NameLength % sizeof(WCHAR)) != 0))
    {
        DPRINT1("Key 0x%x: bad signature, cell size %lu or name length %u\n",
                Cell, (unsigned long)Size, Node->NameLength);
        return FALSE;
    }

    /* The parent named by the key is the one it is found under */
    if (Parent != HCELL_NIL && Node->Parent != Parent)
    {
        if (!Ctx->Heal)
            return FALSE;
        CmpCheckDirty(Ctx, Cell);
        Node->Parent = Parent;
        Ctx->FieldsReset++;
        CmpCheckHealed(Ctx);
    }

    if (!Ctx->Live)
    {
        /*
         * A key of a hive file is never a hive exit (its subkey fields would
         * be taken for a pointer to another hive), a predefined handle (its
         * value count would be taken for a handle) or volatile, and only the
         * root is a hive entry. The flags come from the file: drop them.
         */
        if ((Node->Flags & CMP_FILE_KEY_FLAGS_DROPPED) ||
            (Parent != HCELL_NIL && (Node->Flags & KEY_HIVE_ENTRY)) ||
            (Parent == HCELL_NIL && (Node->Flags & KEY_SYM_LINK)))
        {
            DPRINT1("Key 0x%x: flags 0x%x a key of a hive file cannot have, dropped\n", Cell, Node->Flags);
            CmpCheckDirty(Ctx, Cell);
            Node->Flags &= ~CMP_FILE_KEY_FLAGS_DROPPED;
            if (Parent != HCELL_NIL)
                Node->Flags &= ~KEY_HIVE_ENTRY;
            else
                Node->Flags &= ~KEY_SYM_LINK;   /* the root is linked into the registry, never followed as a link */
            Ctx->FieldsReset++;
        }

        /* A file holds no volatile key: whatever the volatile list says is gone */
        if (Node->SubKeyCounts[Volatile] != 0)
        {
            CmpCheckDirty(Ctx, Cell);
            Node->SubKeyCounts[Volatile] = 0;
            Node->SubKeyLists[Volatile] = (Ctx->Flags & CM_CHECK_REGISTRY_BOOTLOADER_PURGE_VOLATILES) &&
                                          Ctx->Hive->Version >= HSYS_WHISTLER_BETA1 ?
                                          CMP_VOLATILE_LIST_UNINTIALIZED : HCELL_NIL;
        }
    }
    else if (Node->Flags & KEY_HIVE_EXIT)
    {
        return FALSE;
    }

    /*
     * Security. A bad 'sk' cell is not a reason to refuse the hive or to stop
     * the boot: the key loses its stored descriptor (Security is reset to
     * HCELL_NIL, the state of every key of a hive that has none) and inherits.
     * Whoever can write the file can as well write a valid descriptor that
     * grants anything, so refusing would protect nothing, and hives made by
     * older setups (a zero length descriptor in SECURITY) must still boot.
     * A live hive is only checked.
     */
    if (Node->Security != HCELL_NIL && !CmpCheckKeySecurity(Ctx, Node->Security))
    {
        if (Ctx->Live)
            return FALSE;
        if (Ctx->Stats.SecurityReset++ == 0)
        {
            DPRINT1("Key 0x%x: security cell 0x%x is not valid, reset to none "
                    "(the first of this hive; the count follows)\n", Cell, Node->Security);
        }
        CmpCheckDirty(Ctx, Cell);
        Node->Security = HCELL_NIL;
    }

    /* No class: no class cell either (CmpMarkKeyDirty dirties a Class that is not NIL) */
    if (Node->ClassLength == 0 && Node->Class != HCELL_NIL && !Ctx->Live)
    {
        CmpCheckDirty(Ctx, Cell);
        Node->Class = HCELL_NIL;
    }

    /* The class, all of it inside its cell */
    if (Node->ClassLength > 0 && !CmpTakeCell(Ctx, Node->Class, Node->ClassLength, NULL))
    {
        if (!Ctx->Heal)
            return FALSE;
        CmpCheckDirty(Ctx, Cell);
        Node->Class = HCELL_NIL;
        Node->ClassLength = 0;
        Ctx->FieldsReset++;
        CmpCheckHealed(Ctx);
    }

    if (!CmpCheckValueList(Ctx, Cell, Node, &MaxValueName, &MaxValueData))
        return FALSE;

    /*
     * The longest value name and data the key reports are hints, larger
     * than the real ones after deletes, but programs size buffers by them
     * (RegQueryInfoKey: advapi32's RegDeleteTreeW multiplies the name length
     * in 32 bits) and the kernel keeps the name length in 16 bits in the key
     * control block (and asserts that both agree). A name length that does not
     * fit 16 bits, or a data length larger than the hive, becomes the real one.
     */
    if (!Ctx->Live && Node->MaxValueNameLen > MAXUSHORT)
    {
        CmpCheckDirty(Ctx, Cell);
        Node->MaxValueNameLen = MaxValueName;
        Ctx->FieldsReset++;
    }
    if (!Ctx->Live && Node->MaxValueDataLen > Ctx->Map.Length[Stable])
    {
        CmpCheckDirty(Ctx, Cell);
        Node->MaxValueDataLen = MaxValueData;
        Ctx->FieldsReset++;
    }

    *KeyNode = Node;
    return TRUE;
}

/* SUBKEY INDEXES *************************************************************/

static
ULONG
CmpIndexEntrySize(
    _In_ USHORT Signature)
{
    return (Signature == CM_KEY_FAST_LEAF || Signature == CM_KEY_HASH_LEAF) ? sizeof(CM_INDEX) : sizeof(HCELL_INDEX);
}

/* A leaf of a subkey index: a leaf signature, at least one entry, all of them inside the cell */
static
PCM_KEY_INDEX
CmpTakeLeaf(
    _In_ PCMP_CHECK Ctx,
    _In_ HCELL_INDEX Cell)
{
    PCM_KEY_INDEX Leaf;
    ULONG Size;

    Leaf = CmpTakeCell(Ctx, Cell, FIELD_OFFSET(CM_KEY_INDEX, List), &Size);
    if (!Leaf ||
        (Leaf->Signature != CM_KEY_INDEX_LEAF &&
         Leaf->Signature != CM_KEY_FAST_LEAF &&
         Leaf->Signature != CM_KEY_HASH_LEAF) ||
        Leaf->Count == 0 ||
        Leaf->Count > (Size - FIELD_OFFSET(CM_KEY_INDEX, List)) / CmpIndexEntrySize(Leaf->Signature))
    {
        return NULL;
    }
    return Leaf;
}

/*
 * The subkey index of a key (one storage): a leaf, or a root of leaves; every
 * count fits its cell, no leaf is empty, the entries add up without overflow.
 * The entries themselves are checked by the walk, as it goes down to them.
 */
static
BOOLEAN
CmpCheckSubKeyIndex(
    _In_ PCMP_CHECK Ctx,
    _In_ PCM_KEY_NODE Node,
    _In_ ULONG Type)
{
    PCM_KEY_INDEX Index;
    ULONG Size, i;
    ULONGLONG Total = 0;

    Index = CmpMapCell(Ctx, Node->SubKeyLists[Type], FIELD_OFFSET(CM_KEY_INDEX, List), &Size);
    if (!Index || HvGetCellType(Node->SubKeyLists[Type]) != Type)
        return FALSE;
    if (Index->Signature != CM_KEY_INDEX_ROOT)
        return CmpTakeLeaf(Ctx, Node->SubKeyLists[Type]) != NULL;

    if (!CmpClaimCell(Ctx, Node->SubKeyLists[Type]) ||
        Index->Count == 0 ||
        Index->Count > (Size - FIELD_OFFSET(CM_KEY_INDEX, List)) / sizeof(HCELL_INDEX))
    {
        return FALSE;
    }
    for (i = 0; i < Index->Count; i++)
    {
        PCM_KEY_INDEX Leaf = CmpTakeLeaf(Ctx, Index->List[i]);

        if (!Leaf || HvGetCellType(Index->List[i]) != Type)
            return FALSE;
        Total += Leaf->Count;
    }
    return Total <= MAXULONG;
}

/* The hash and hint of a key node's name, as CmpAddToLeaf writes them */
static
ULONG
CmpKeyNameHash(
    _In_ PCM_KEY_NODE Node)
{
    ULONG i, Hash = 0;
    ULONG Chars = (Node->Flags & KEY_COMP_NAME) ? Node->NameLength : Node->NameLength / sizeof(WCHAR);

    for (i = 0; i < Chars; i++)
    {
        WCHAR Char = (Node->Flags & KEY_COMP_NAME) ? ((PUCHAR)Node->Name)[i] : Node->Name[i];
        Hash = Hash * 37 + RtlUpcaseUnicodeChar(Char);
    }
    return Hash;
}

static
ULONG
CmpKeyNameHint(
    _In_ PCM_KEY_NODE Node)
{
    UCHAR Hint[4] = { 0, 0, 0, 0 };
    ULONG Chars = (Node->Flags & KEY_COMP_NAME) ? Node->NameLength : Node->NameLength / sizeof(WCHAR);
    ULONG j = min(Chars, 4);
    WCHAR Char;

    /* The same loop as CmpAddToLeaf: backwards, stopping at a character above 0xFF */
    while (j > 0)
    {
        Char = (Node->Flags & KEY_COMP_NAME) ? ((PUCHAR)Node->Name)[j - 1] : Node->Name[j - 1];
        if (Char > 0xFF)
            break;
        Hint[j - 1] = (UCHAR)Char;
        j--;
    }
    return Hint[0] | (Hint[1] << 8) | (Hint[2] << 16) | ((ULONG)Hint[3] << 24);
}

/* THE WALK *******************************************************************/

/*
 * Where the walk is in the subkey index of one key. The entries of a leaf are
 * read at Entry and the ones kept written back at Kept (Kept <= Entry), and
 * the leaves of a root likewise, so removing any number of keys from an index
 * is one pass over it.
 */
typedef struct _CMP_WALK_LEVEL
{
    HCELL_INDEX Cell;           /* the key */
    PCM_KEY_NODE Node;
    ULONG Type;                 /* the storage whose index is walked */
    HCELL_INDEX IndexCell;      /* the root or the leaf of that index */
    PCM_KEY_INDEX Root;         /* NULL: the index is one leaf */
    ULONG LeafNumber, LeavesKept;
    HCELL_INDEX LeafCell;
    PCM_KEY_INDEX Leaf;
    ULONG Entry, Kept;
    ULONG Total;                /* keys kept in this storage */
    PCM_KEY_NODE Previous;      /* the last key kept, for the order */
    ULONG MaxName;              /* the longest subkey name (bytes, as Unicode) and class kept */
    ULONG MaxClass;
} CMP_WALK_LEVEL, *PCMP_WALK_LEVEL;

static
HCELL_INDEX
CmpLeafEntry(
    _In_ PCM_KEY_INDEX Leaf,
    _In_ ULONG i)
{
    return Leaf->Signature == CM_KEY_INDEX_LEAF ? Leaf->List[i] : ((PCM_KEY_FAST_INDEX)Leaf)->List[i].Cell;
}

/* Start the walk of the index of Level->Type; FALSE if the index is not sound */
static
BOOLEAN
CmpStartIndex(
    _In_ PCMP_CHECK Ctx,
    _Inout_ PCMP_WALK_LEVEL Level)
{
    PCM_KEY_NODE Node = Level->Node;
    PCM_KEY_INDEX Index;

    Level->Root = NULL;
    Level->Leaf = NULL;
    Level->LeafNumber = Level->LeavesKept = 0;
    Level->Entry = Level->Kept = 0;
    Level->Total = 0;
    Level->Previous = NULL;
    Level->IndexCell = Node->SubKeyLists[Level->Type];
    if (Node->SubKeyCounts[Level->Type] == 0)
        return TRUE;

    if (!CmpCheckSubKeyIndex(Ctx, Node, Level->Type))
    {
        DPRINT1("Key 0x%x: the subkey index (count %lu) is not sound\n",
                Level->Cell, (unsigned long)Node->SubKeyCounts[Level->Type]);
        if (!Ctx->Heal)
            return FALSE;
        CmpCheckDirty(Ctx, Level->Cell);
        Node->SubKeyLists[Level->Type] = HCELL_NIL;
        Node->SubKeyCounts[Level->Type] = 0;
        Ctx->ListsPurged++;
        CmpCheckHealed(Ctx);
        return TRUE;
    }

#if !defined(_BLDR_)
    /*
     * The hashes and the order of the subkey names depend on the Unicode case
     * table. If an older release wrote the hive with another table, bring the
     * index up to date before the names of the subkeys are checked against
     * each other. Its entries are read through the cell map.
     */
    if (!Ctx->Live && Level->Type == Stable)
        CmpRepairSubKeyIndexCase(Ctx->Hive, Node, &Ctx->Stats);
#endif

    Index = (PCM_KEY_INDEX)HvGetCell(Ctx->Hive, Level->IndexCell);
    if (Index->Signature == CM_KEY_INDEX_ROOT)
    {
        Level->Root = Index;
        Level->LeafCell = Index->List[0];
        Level->Leaf = (PCM_KEY_INDEX)HvGetCell(Ctx->Hive, Level->LeafCell);
    }
    else
    {
        Level->LeafCell = Level->IndexCell;
        Level->Leaf = Index;
    }
    return TRUE;
}

/* The walk is done with a leaf: its kept entries stay, an emptied leaf leaves the root */
static
VOID
CmpEndLeaf(
    _In_ PCMP_CHECK Ctx,
    _Inout_ PCMP_WALK_LEVEL Level)
{
    if (Level->Kept != Level->Leaf->Count)
    {
        CmpCheckDirty(Ctx, Level->LeafCell);
        Level->Leaf->Count = (USHORT)Level->Kept;
    }
    if (Level->Root)
    {
        if (Level->Kept != 0)
        {
            if (Level->LeavesKept != Level->LeafNumber)
            {
                CmpCheckDirty(Ctx, Level->IndexCell);
                Level->Root->List[Level->LeavesKept] = Level->LeafCell;
            }
            Level->LeavesKept++;
        }
        Level->LeafNumber++;
        Level->Entry = Level->Kept = 0;
        if (Level->LeafNumber < Level->Root->Count)
        {
            Level->LeafCell = Level->Root->List[Level->LeafNumber];
            Level->Leaf = (PCM_KEY_INDEX)HvGetCell(Ctx->Hive, Level->LeafCell);
            return;
        }
        if (Level->LeavesKept != Level->Root->Count)
        {
            CmpCheckDirty(Ctx, Level->IndexCell);
            Level->Root->Count = (USHORT)Level->LeavesKept;
        }
    }
    Level->Leaf = NULL;
}

/* The index of Level->Type is walked: the key's count is what was kept */
static
VOID
CmpEndIndex(
    _In_ PCMP_CHECK Ctx,
    _Inout_ PCMP_WALK_LEVEL Level)
{
    PCM_KEY_NODE Node = Level->Node;

    if (Node->SubKeyCounts[Level->Type] != Level->Total)
    {
        CmpCheckDirty(Ctx, Level->Cell);
        Node->SubKeyCounts[Level->Type] = Level->Total;
        if (Level->Total == 0)
            Node->SubKeyLists[Level->Type] = HCELL_NIL;
        CmpCheckHealed(Ctx);
    }
}

/*
 * The walk of the tree from the root, depth first, without recursion. Each
 * key is checked once, when the walk comes to it from its parent's index;
 * a key that is not sound, or out of order, is not kept in the index (or
 * the hive is refused if repairs are not allowed).
 */
static
CM_CHECK_REGISTRY_STATUS
CmpWalkTree(
    _In_ PCMP_CHECK Ctx)
{
    PCMP_WALK_LEVEL Levels, Level;
    PCM_KEY_NODE Node, Child;
    HCELL_INDEX RootCell, ChildCell;
    ULONG Size = CMP_REGISTRY_MAX_LEVELS_TREE_DEPTH * sizeof(CMP_WALK_LEVEL);
    ULONG Types = Ctx->Live ? HTYPE_COUNT : 1, NameBytes;
    LONG Depth;
    CM_CHECK_REGISTRY_STATUS Status = CM_CHECK_REGISTRY_GOOD;
    BOOLEAN Keep;

    RootCell = Ctx->Hive->BaseBlock->RootCell;
    if (!CmpCheckKey(Ctx, RootCell, HCELL_NIL, &Node))
    {
        DPRINT1("The root cell 0x%x is not a sound key\n", RootCell);
        return CM_CHECK_REGISTRY_ROOT_CELL_NOT_FOUND;
    }

    Levels = CmpCheckAllocate(Size);
    if (!Levels)
        return CM_CHECK_REGISTRY_ALLOCATE_MEM_STACK_FAIL;

    /* A key is counted as naming its 'sk' cell once it is kept */
    if (Ctx->Tally && Node->Security != HCELL_NIL)
        CmpSkTallyAdd(Ctx->Tally, Node->Security);

    Depth = 0;
    Level = &Levels[0];
    RtlZeroMemory(Level, sizeof(*Level));
    Level->Cell = RootCell;
    Level->Node = Node;
    Level->Type = Stable;
    if (!CmpStartIndex(Ctx, Level))
    {
        Status = CM_CHECK_REGISTRY_CORRUPT_SUBKEYS_INDEX;
        goto Quit;
    }

    while (Depth >= 0)
    {
        Level = &Levels[Depth];

        /* The next entry of the index of this key */
        if (Level->Leaf && Level->Entry >= Level->Leaf->Count)
        {
            CmpEndLeaf(Ctx, Level);
            continue;
        }
        if (!Level->Leaf)
        {
            CmpEndIndex(Ctx, Level);
            if (Level->Type + 1 < Types)
            {
                Level->Type++;
                if (!CmpStartIndex(Ctx, Level))
                {
                    Status = CM_CHECK_REGISTRY_CORRUPT_SUBKEYS_INDEX;
                    goto Quit;
                }
                continue;
            }

            /*
             * All subkeys done. The kernel keeps the longest subkey name in 16
             * bits in the key control block (and asserts that both agree): a
             * value that does not fit becomes the real one.
             */
            if (!Ctx->Live && Level->Node->MaxNameLen > MAXUSHORT)
            {
                CmpCheckDirty(Ctx, Level->Cell);
                Level->Node->MaxNameLen = Level->MaxName;
                Ctx->FieldsReset++;
            }
            /* A class is at most 64 KB (ClassLength): so is the longest one reported */
            if (!Ctx->Live && Level->Node->MaxClassLen > MAXUSHORT)
            {
                CmpCheckDirty(Ctx, Level->Cell);
                Level->Node->MaxClassLen = Level->MaxClass;
                Ctx->FieldsReset++;
            }
            Depth--;
            continue;
        }

        ChildCell = CmpLeafEntry(Level->Leaf, Level->Entry);
        Keep = CmpCheckKey(Ctx, ChildCell, Level->Cell, &Child);
        if (Keep && HvGetCellType(ChildCell) != Level->Type)
            Keep = FALSE;
        if (Keep && Level->Previous && !CmpValidateLexicalOrder(Child, Level->Previous))
            Keep = FALSE;

        if (!Keep)
        {
            if (!Ctx->Heal)
            {
                DPRINT1("Key 0x%x: subkey 0x%x is not sound or not in order\n", Level->Cell, ChildCell);
                Status = CM_CHECK_REGISTRY_BAD_LEXICOGRAPHICAL_ORDER;
                goto Quit;
            }
            Ctx->KeysRemoved++;
            Level->Entry++;
            CmpCheckHealed(Ctx);
            continue;
        }

        /* Kept: at its place in the leaf, with the hash or hint of its name (a live hive is only read) */
        if (!Ctx->Live && (Level->Kept != Level->Entry || Level->Leaf->Signature != CM_KEY_INDEX_LEAF))
        {
            PCM_KEY_FAST_INDEX Fast = (PCM_KEY_FAST_INDEX)Level->Leaf;

            if (Level->Leaf->Signature == CM_KEY_INDEX_LEAF)
            {
                CmpCheckDirty(Ctx, Level->LeafCell);
                Level->Leaf->List[Level->Kept] = ChildCell;
            }
            else
            {
                ULONG Hash = Level->Leaf->Signature == CM_KEY_HASH_LEAF ? CmpKeyNameHash(Child) : CmpKeyNameHint(Child);

                if (Level->Kept != Level->Entry || Fast->List[Level->Kept].HashKey != Hash)
                {
                    CmpCheckDirty(Ctx, Level->LeafCell);
                    if (Fast->List[Level->Kept].HashKey != Hash && Level->Kept == Level->Entry)
                        Ctx->Stats.Hashes++;
                    Fast->List[Level->Kept].Cell = ChildCell;
                    Fast->List[Level->Kept].HashKey = Hash;
                }
            }
        }
        if (Ctx->Tally && Child->Security != HCELL_NIL)
            CmpSkTallyAdd(Ctx->Tally, Child->Security);
        Level->Kept++;
        Level->Entry++;
        Level->Total++;
        Level->Previous = Child;
        NameBytes = (Child->Flags & KEY_COMP_NAME) ? Child->NameLength * sizeof(WCHAR) : Child->NameLength;
        Level->MaxName = CMP_MAX(Level->MaxName, NameBytes);
        Level->MaxClass = CMP_MAX(Level->MaxClass, Child->ClassLength);

        /* Down to the child */
        if (Depth + 1 >= CMP_REGISTRY_MAX_LEVELS_TREE_DEPTH - 1)
        {
            DPRINT1("The registry tree has too many levels\n");
            Status = CM_CHECK_REGISTRY_TREE_TOO_MANY_LEVELS;
            goto Quit;
        }
        Depth++;
        Level = &Levels[Depth];
        RtlZeroMemory(Level, sizeof(*Level));
        Level->Cell = ChildCell;
        Level->Node = Child;
        Level->Type = Stable;
        if (!CmpStartIndex(Ctx, Level))
        {
            Status = CM_CHECK_REGISTRY_CORRUPT_SUBKEYS_INDEX;
            goto Quit;
        }
    }

Quit:
    CmpCheckFree(Levels, Size);
    return Status;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/**
 * @brief
 * Validates a bin from a hive: its header, and cells that tile it (each at
 * least 8 bytes, a multiple of 8, inside the bin).
 *
 * @return
 * CM_CHECK_REGISTRY_GOOD if the bin is sound, a failure code otherwise.
 */
CM_CHECK_REGISTRY_STATUS
NTAPI
HvValidateBin(
    _In_ PHHIVE Hive,
    _In_ PHBIN Bin)
{
    PAGED_CODE();

    ASSERT(Bin);
    ASSERT(Hive);
    UNREFERENCED_PARAMETER(Hive);

    return CmpCheckBinCells(Bin, Bin->FileOffset, MAXULONG, NULL);
}

/**
 * @brief
 * Validates the storage of a hive: every bin and cell (see CmpBuildCellMap).
 *
 * @return
 * CM_CHECK_REGISTRY_GOOD if the hive storage is sound, a failure code otherwise.
 */
CM_CHECK_REGISTRY_STATUS
NTAPI
HvValidateHive(
    _In_ PHHIVE Hive)
{
    CM_CHECK_REGISTRY_STATUS Status;
    CMP_CELL_MAP Map;

    PAGED_CODE();

    ASSERT(Hive);

    if (Hive->Signature != HV_HHIVE_SIGNATURE)
    {
        DPRINT1("Hive's signature corrupted (signature %u)\n", Hive->Signature);
        return CM_CHECK_REGISTRY_HIVE_CORRUPT_SIGNATURE;
    }

    Status = CmpBuildCellMap(Hive, TRUE, &Map);
    CmpFreeCellMap(&Map);
    return Status;
}

/**
 * @brief
 * Checks that a registry hive is sound before anything else uses it, see the
 * rules at the top of this file. Repairs what can be repaired safely when
 * self-healing is allowed (or FIX_HIVE is given), refuses the hive otherwise.
 *
 * @param[in] RegistryHive
 * The hive.
 *
 * @param[in] Flags
 * CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES / PURGE_VOLATILES: a hive being
 * loaded holds no volatile key, whichever is given. BOOTLOADER_PURGE_VOLATILES:
 * the boot loader's image (the volatile lists are marked uninitialized).
 * VALIDATE_HIVE: kept for the callers, the bins are always checked. FIX_HIVE:
 * repair and make the repairs persistent. RECOUNT_SECURITY, CACHE_SECURITY:
 * see cmlib.h. LIVE_HIVE: a hive in use, only checked.
 *
 * @return
 * CM_CHECK_REGISTRY_GOOD (0) if the hive is sound (as it is, or repaired), a
 * failure code otherwise.
 */
CM_CHECK_REGISTRY_STATUS
NTAPI
CmCheckRegistry(
    _In_ PCMHIVE RegistryHive,
    _In_ ULONG Flags)
{
    CM_CHECK_REGISTRY_STATUS Status;
    CMP_SK_TALLY Tally;
    CMP_CHECK Ctx;
    PHHIVE Hive;

    PAGED_CODE();

    if (!RegistryHive)
    {
        DPRINT1("No registry hive given for check\n");
        return CM_CHECK_REGISTRY_INVALID_PARAMETER;
    }

#if !defined(CMLIB_HOST) && !defined(_BLDR_)
    /* The master hive holds the others together; it is made in memory */
    if (RegistryHive == CmiVolatileHive)
        return CM_CHECK_REGISTRY_GOOD;
#endif

    if (Flags & ~(CM_CHECK_REGISTRY_DONT_PURGE_VOLATILES       |
                  CM_CHECK_REGISTRY_PURGE_VOLATILES            |
                  CM_CHECK_REGISTRY_BOOTLOADER_PURGE_VOLATILES |
                  CM_CHECK_REGISTRY_VALIDATE_HIVE              |
                  CM_CHECK_REGISTRY_FIX_HIVE                   |
                  CM_CHECK_REGISTRY_RECOUNT_SECURITY           |
                  CM_CHECK_REGISTRY_CACHE_SECURITY             |
                  CM_CHECK_REGISTRY_LIVE_HIVE))
    {
        DPRINT1("Invalid flag for registry check given (flag %u)\n", Flags);
        return CM_CHECK_REGISTRY_INVALID_PARAMETER;
    }

    Hive = GET_HHIVE(RegistryHive);
    if (Hive->Signature != HV_HHIVE_SIGNATURE)
        return CM_CHECK_REGISTRY_HIVE_CORRUPT_SIGNATURE;

    RtlZeroMemory(&Ctx, sizeof(Ctx));
    RtlZeroMemory(&Tally, sizeof(Tally));
    Ctx.Hive = Hive;
    Ctx.Flags = Flags;
    Ctx.Live = (Flags & CM_CHECK_REGISTRY_LIVE_HIVE) != 0;
    Ctx.FixHive = (Flags & CM_CHECK_REGISTRY_FIX_HIVE) != 0;
    Ctx.Heal = !Ctx.Live && CmIsSelfHealEnabled(Ctx.FixHive);
    Ctx.Tally = (!Ctx.Live && (Flags & CM_CHECK_REGISTRY_RECOUNT_SECURITY)) ? &Tally : NULL;
    Ctx.Stats.SecurityTally = Ctx.Tally;
    Ctx.Stats.IsKeyCell = CmpIsKeyCell;
    Ctx.Stats.CheckContext = &Ctx;

    /* The bins and cells first: the map of where cells start */
    Status = CmpBuildCellMap(Hive, Ctx.Live, &Ctx.Map);
    if (!CM_CHECK_REGISTRY_SUCCESS(Status))
    {
        DPRINT1("The hive is not valid (hive 0x%p, check status code %u)\n", Hive, Status);
        return Status;
    }

    /* Then the tree */
    Status = CmpWalkTree(&Ctx);
    CmpFreeCellMap(&Ctx.Map);
    if (!CM_CHECK_REGISTRY_SUCCESS(Status))
    {
        DPRINT1("The hive is not valid (hive 0x%p, check status code %u)\n", Hive, Status);
        CmpSkTallyReset(&Tally);
        return Status;
    }

    if (Ctx.KeysRemoved || Ctx.ValuesRemoved || Ctx.ListsPurged || Ctx.FieldsReset || Ctx.Stats.SecurityReset)
    {
        DPRINT1("Hive 0x%p repaired: %lu keys and %lu values removed, %lu lists dropped, %lu fields reset, "
                "%lu keys lost a security cell that is not valid\n",
                Hive, (unsigned long)Ctx.KeysRemoved, (unsigned long)Ctx.ValuesRemoved,
                (unsigned long)Ctx.ListsPurged, (unsigned long)Ctx.FieldsReset,
                (unsigned long)Ctx.Stats.SecurityReset);
    }
    if (Ctx.Stats.Hashes || Ctx.Stats.Sorted || Ctx.Stats.Skipped)
    {
        DPRINT1("Subkey indexes brought up to date: %lu hashes, %lu indexes sorted, %lu not sorted\n",
                Ctx.Stats.Hashes, Ctx.Stats.Sorted, Ctx.Stats.Skipped);
    }

    /* The 'sk' references, then the security cache of a hive being loaded */
    if (Ctx.Tally)
    {
        CmpApplySecurityRecount(Hive, &Tally, Ctx.FixHive);
        if (Flags & CM_CHECK_REGISTRY_CACHE_SECURITY)
            CmpCacheSecurityRings(Hive, &Tally);
    }
    CmpSkTallyReset(&Tally);
    return CM_CHECK_REGISTRY_GOOD;
}

/* EOF */
