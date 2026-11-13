/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            lib/cmlib/cmse.c
 * PURPOSE:         Configuration Manager Library - Security Subsystem Interface
 * PROGRAMMERS:     Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

/* INCLUDES ******************************************************************/

#include "cmlib.h"
#define NDEBUG
#include <debug.h>

/*
 * Hive invariants for 'sk' (CM_KEY_SECURITY) cells, which everything here
 * relies on or restores:
 *
 *  - CM_KEY_NODE::Security is HCELL_NIL or the index of an allocated 'sk' cell
 *    of the same hive. A NIL key has no stored descriptor.
 *  - The 'sk' cells of a storage type (stable, volatile) of a hive form one
 *    ring, through Flink and Blink: Flink->Blink == this == Blink->Flink. A
 *    lone cell points to itself. A stable cell never links to a volatile one,
 *    which would not exist after a reboot.
 *  - ReferenceCount is the number of key nodes that name the cell. The cell is
 *    freed with the last reference, and not before.
 *  - 0 < DescriptorLength and the descriptor lies inside the cell.
 *  - A cell is in the hive's security cache (CMHIVE::SecurityHash) if it is in
 *    the ring and has a sane descriptor; the cache only decides whether a new
 *    descriptor can share a cell, so a missing entry costs space, never
 *    correctness.
 *
 * The work per operation is bounded whatever the hive holds (a crafted hive
 * can put any number of byte-identical descriptors, or descriptors with the
 * same hash, in one hash list): a list keeps at most
 * CMP_SECURITY_BUCKET_LIMIT entries (more cells are simply not offered for
 * sharing), a search compares the bytes of at most CMP_SECURITY_COMPARE_LIMIT
 * descriptors, the cell a new cell joins in the ring is kept in
 * CMHIVE::SecurityRingAnchor instead of being searched for, and an entry is
 * removed from the list of its descriptor's hash only. Filling the cache at
 * load visits every cell once (CmpAddSecurityRingToCache).
 *
 * Nothing below trusts a cell index, a size or a link read from the hive: the
 * hive file is untrusted input. CmpGetCheckedSecurityCell is the only place
 * that turns a cell index into a pointer to an 'sk' cell.
 */

/* DECLARATIONS **************************************************************/

/* Entries a hash list keeps, and descriptors a search compares byte by byte */
#define CMP_SECURITY_BUCKET_LIMIT   256
#define CMP_SECURITY_COMPARE_LIMIT  16

#if !defined(CMLIB_HOST) && !defined(_BLDR_)
BOOLEAN
NTAPI
CmpAcquireHiveSecurityLock(
    _In_ PHHIVE Hive);

VOID
NTAPI
CmpReleaseHiveSecurityLock(
    _In_ PHHIVE Hive,
    _In_ BOOLEAN Acquired);
#endif

/*
 * Keys of one hive are created and deleted under the shared registry lock, so
 * two of them that name the same 'sk' cell can run together: the reference
 * count, the ring and the cache need the hive's security lock (CMHIVE::
 * SecurityLock). Taken by the entry points that change or search them; the
 * library's other users (loader, mkhive, host tests) are single threaded.
 * Lock order: security lock, then the hive cell lock (HvMarkCellDirty,
 * HvAllocateCell and HvFreeCell take that one themselves).
 */
static __inline BOOLEAN
CmpLockSecurity(
    _In_ PHHIVE Hive)
{
#if !defined(CMLIB_HOST) && !defined(_BLDR_)
    return CmpAcquireHiveSecurityLock(Hive);
#else
    UNREFERENCED_PARAMETER(Hive);
    return FALSE;
#endif
}

static __inline VOID
CmpUnlockSecurity(
    _In_ PHHIVE Hive,
    _In_ BOOLEAN Acquired)
{
#if !defined(CMLIB_HOST) && !defined(_BLDR_)
    CmpReleaseHiveSecurityLock(Hive, Acquired);
#else
    UNREFERENCED_PARAMETER(Hive);
    UNREFERENCED_PARAMETER(Acquired);
#endif
}

/* PRIVATE FUNCTIONS *********************************************************/

/*
 * The cache lists of a hive are set up by the kernel (CmpInitSecurityCache),
 * not by the other users of this library (the boot loader, mkhive): there the
 * lists stay zeroed and the cache is simply not used.
 */
static
BOOLEAN
CmpSecurityCacheReady(
    IN PCMHIVE CmHive)
{
    return CmHive->SecurityHash[0].Flink != NULL;
}

static
ULONG
CmpHashDescriptor(
    IN PVOID Descriptor,
    IN ULONG Length)
{
    PUCHAR Bytes = Descriptor;
    ULONG i, Key = 0;

    for (i = 0; i < Length; i++)
        Key = Key * 37 + Bytes[i];
    return Key;
}

static
BOOLEAN
CmpSameBytes(
    IN PVOID A,
    IN PVOID B,
    IN ULONG Length)
{
    PUCHAR a = A, b = B;
    ULONG i;

    for (i = 0; i < Length; i++)
    {
        if (a[i] != b[i])
            return FALSE;
    }
    return TRUE;
}

/* A SID at Offset: the header and all its subauthorities lie inside Length */
static
BOOLEAN
CmpSidInBounds(
    IN PUCHAR Base,
    IN ULONG Length,
    IN ULONG Offset)
{
    if (Offset == 0)
        return TRUE;
    if (Offset > Length || Length - Offset < 8)
        return FALSE;
    /* SubAuthorityCount, at most 15 */
    if (Base[Offset + 1] > 15)
        return FALSE;
    return Length - Offset >= 8 + 4 * (ULONG)Base[Offset + 1];
}

/* An ACL at Offset: the header, and the size it claims, lie inside Length */
static
BOOLEAN
CmpAclInBounds(
    IN PUCHAR Base,
    IN ULONG Length,
    IN ULONG Offset)
{
    ULONG AclSize;

    if (Offset == 0)
        return TRUE;
    if (Offset > Length || Length - Offset < 8)
        return FALSE;
    AclSize = Base[Offset + 2] | (Base[Offset + 3] << 8);
    return AclSize >= 8 && Length - Offset >= AclSize;
}

/* Structure only (offsets inside the length); the ACEs are not interpreted */
static
BOOLEAN
CmpIsSaneRelativeDescriptor(
    IN PVOID Descriptor,
    IN ULONG Length)
{
    PISECURITY_DESCRIPTOR_RELATIVE Sd = Descriptor;

    if (Length < sizeof(SECURITY_DESCRIPTOR_RELATIVE))
        return FALSE;
    if (Sd->Revision != 1)
        return FALSE;
    return CmpSidInBounds(Descriptor, Length, Sd->Owner) &&
           CmpSidInBounds(Descriptor, Length, Sd->Group) &&
           CmpAclInBounds(Descriptor, Length, Sd->Sacl) &&
           CmpAclInBounds(Descriptor, Length, Sd->Dacl);
}

/* The most 'sk' cells the storage of the hive can hold (a cell is >= 16 bytes) */
static
ULONG
CmpSecurityCellLimit(
    IN PHHIVE Hive)
{
    ULONGLONG Bytes;

    if (Hive->Flat)
        Bytes = Hive->BaseBlock->Length;
    else
        Bytes = ((ULONGLONG)Hive->Storage[Stable].Length +
                 Hive->Storage[Volatile].Length) * HBLOCK_SIZE;
    Bytes /= 16;
    return Bytes > 0x7FFFFFFF ? 0x7FFFFFFF : (ULONG)Bytes;
}

/* PUBLIC FUNCTIONS **********************************************************/

PCM_KEY_SECURITY
NTAPI
CmpGetCheckedSecurityCell(IN PHHIVE Hive,
                          IN HCELL_INDEX Cell,
                          OUT PULONG CellSize OPTIONAL)
{
    PHCELL Header;
    ULONG_PTR Available;
    ULONG Size, DataSize;
    PCM_KEY_SECURITY Security;

    if (Cell == HCELL_NIL || (Cell & 7))
        return NULL;

    if (Hive->Flat)
    {
        /* One run of bins right after the base block, stable cells only */
        ULONG Length = Hive->BaseBlock->Length;

        if (HvGetCellType(Cell) != Stable || Cell > Length || Length - Cell < sizeof(HCELL))
            return NULL;
        Header = (PHCELL)((PUCHAR)Hive->BaseBlock + HBLOCK_SIZE + Cell);
        Available = Length - Cell;
    }
    else
    {
        ULONG Type = HvGetCellType(Cell), Block = HvGetCellBlock(Cell);
        PHMAP_ENTRY Entry;
        PHBIN Bin;
        ULONG_PTR BinEnd;

        if (Block >= Hive->Storage[Type].Length)
            return NULL;
        Entry = &Hive->Storage[Type].BlockList[Block];
        if (!Entry->BlockAddress || !Entry->BinAddress)
            return NULL;

        /* The cell must lie inside the bin of its block */
        Bin = (PHBIN)Entry->BinAddress;
        if (Bin->Signature != HV_HBIN_SIGNATURE || Bin->Size < sizeof(HBIN))
            return NULL;
        BinEnd = (ULONG_PTR)Bin + Bin->Size;
        Header = (PHCELL)(Entry->BlockAddress + (Cell & HCELL_OFFSET_MASK));
        if ((ULONG_PTR)Header < (ULONG_PTR)Bin + sizeof(HBIN) ||
            BinEnd < (ULONG_PTR)Bin ||
            BinEnd - (ULONG_PTR)Header < sizeof(HCELL))
        {
            return NULL;
        }
        Available = BinEnd - (ULONG_PTR)Header;
    }

    /* Allocated cells have a negative size; the size includes the header */
    if (Header->Size >= 0)
        return NULL;
    Size = 0 - (ULONG)Header->Size;
    if (Size > Available ||
        Size < sizeof(HCELL) + FIELD_OFFSET(CM_KEY_SECURITY, Descriptor))
    {
        return NULL;
    }

    Security = (PCM_KEY_SECURITY)(Header + 1);
    if (Security->Signature != CM_KEY_SECURITY_SIGNATURE)
        return NULL;

    /* The descriptor must lie inside the cell */
    DataSize = Size - sizeof(HCELL);
    if (Security->DescriptorLength > DataSize - FIELD_OFFSET(CM_KEY_SECURITY, Descriptor))
        return NULL;

    if (CellSize)
        *CellSize = DataSize;
    return Security;
}

/*
 * Is this cell fit to be named by a key: well formed, referenced, a sane
 * descriptor, and in the ring with neighbours that agree. A zero length
 * descriptor (what mkhive wrote for the SECURITY hive) is not sane.
 */
BOOLEAN
NTAPI
CmpValidateSecurityCell(IN PHHIVE Hive,
                        IN HCELL_INDEX Cell)
{
    PCM_KEY_SECURITY Security, Flink, Blink;

    Security = CmpGetCheckedSecurityCell(Hive, Cell, NULL);
    if (!Security || Security->ReferenceCount == 0)
        return FALSE;
    if (!CmpIsSaneRelativeDescriptor(&Security->Descriptor, Security->DescriptorLength))
        return FALSE;

    Flink = CmpGetCheckedSecurityCell(Hive, Security->Flink, NULL);
    Blink = CmpGetCheckedSecurityCell(Hive, Security->Blink, NULL);
    return Flink && Blink && Flink->Blink == Cell && Blink->Flink == Cell;
}

BOOLEAN
NTAPI
CmpAddSecurityCellToCache(IN PCMHIVE CmHive,
                          IN HCELL_INDEX SecurityCell)
{
    PCM_KEY_SECURITY Security;
    PCM_KEY_SECURITY_CACHE Entry;
    PLIST_ENTRY List, Head;
    ULONG ConvKey, Entries = 0;

    /* The caller holds the hive's security lock, or the hive is not live yet */
    if (!CmpSecurityCacheReady(CmHive))
        return FALSE;

    Security = CmpGetCheckedSecurityCell(&CmHive->Hive, SecurityCell, NULL);
    if (!Security ||
        !CmpIsSaneRelativeDescriptor(&Security->Descriptor, Security->DescriptorLength))
    {
        return FALSE;
    }

    /* A new cell joins the ring of its type after this one (see the insert) */
    if (CmHive->SecurityRingAnchor[HvGetCellType(SecurityCell)] == HCELL_NIL)
        CmHive->SecurityRingAnchor[HvGetCellType(SecurityCell)] = SecurityCell;

    /* Once per cell, and a bounded list: a cell not cached is only not shared */
    ConvKey = CmpHashDescriptor(&Security->Descriptor, Security->DescriptorLength);
    Head = &CmHive->SecurityHash[ConvKey % CMP_SECURITY_HASH_LISTS];
    for (List = Head->Flink; List != Head; List = List->Flink)
    {
        if (CONTAINING_RECORD(List, CM_KEY_SECURITY_CACHE, List)->Cell == SecurityCell)
            return TRUE;
        if (++Entries >= CMP_SECURITY_BUCKET_LIMIT)
            return TRUE;
    }

    Entry = CmpAllocate(sizeof(*Entry), TRUE, TAG_CMSD);
    if (!Entry)
        return FALSE;
    Entry->Cell = SecurityCell;
    Entry->DescriptorLength = Security->DescriptorLength;
    Entry->ConvKey = ConvKey;
    InsertTailList(Head, &Entry->List);
    CmHive->SecurityCount++;
    return TRUE;
}

VOID
NTAPI
CmpRemoveFromSecurityCache(IN PHHIVE Hive,
                           IN HCELL_INDEX SecurityCell)
{
    PCMHIVE CmHive = (PCMHIVE)Hive;
    PLIST_ENTRY List, Next, Head;
    PCM_KEY_SECURITY_CACHE Entry;
    PCM_KEY_SECURITY Security;
    ULONG i, First = 0, Last = CMP_SECURITY_HASH_LISTS;

    if (!CmpSecurityCacheReady(CmHive))
        return;

    /*
     * The entry is on the list of the descriptor's hash (the bytes of a cell
     * never change once it is written), at most CMP_SECURITY_BUCKET_LIMIT
     * entries long. Only a cell that is no longer a sound 'sk' cell, which no
     * caller hands in, makes this look at every list.
     */
    Security = CmpGetCheckedSecurityCell(Hive, SecurityCell, NULL);
    if (Security)
    {
        First = CmpHashDescriptor(&Security->Descriptor, Security->DescriptorLength) % CMP_SECURITY_HASH_LISTS;
        Last = First + 1;
    }
    for (i = First; i < Last; i++)
    {
        Head = &CmHive->SecurityHash[i];
        for (List = Head->Flink; List != Head; List = Next)
        {
            Next = List->Flink;
            Entry = CONTAINING_RECORD(List, CM_KEY_SECURITY_CACHE, List);
            if (Entry->Cell == SecurityCell)
            {
                RemoveEntryList(&Entry->List);
                CmHive->SecurityCount--;
                CmpFree(Entry, sizeof(*Entry));
                return;
            }
        }
    }
}

/* Entries of a cache, and the cache of a hive in one go */
VOID
NTAPI
CmpFreeSecurityCache(IN PCMHIVE CmHive)
{
    PLIST_ENTRY List;
    ULONG i;

    if (!CmpSecurityCacheReady(CmHive))
        return;

    for (i = 0; i < CMP_SECURITY_HASH_LISTS; i++)
    {
        while (!IsListEmpty(&CmHive->SecurityHash[i]))
        {
            List = RemoveHeadList(&CmHive->SecurityHash[i]);
            CmpFree(CONTAINING_RECORD(List, CM_KEY_SECURITY_CACHE, List), sizeof(CM_KEY_SECURITY_CACHE));
        }
    }
    CmHive->SecurityCount = 0;
    CmHive->SecurityRingAnchor[Stable] = HCELL_NIL;
    CmHive->SecurityRingAnchor[Volatile] = HCELL_NIL;
}

/*
 * Fill the cache of a freshly loaded hive from its ring of 'sk' cells, which
 * starts at the Security of the root key. A hive with a NIL root has no ring
 * to walk and gets an empty cache. Run after CmCheckRegistry, which has reset
 * any Security that is not valid, but it does not rely on it: every cell is
 * checked again and the walk stops at the first one that is not sound.
 * Never fails the load: a cache that is short only means less sharing.
 */
BOOLEAN
NTAPI
CmpBuildSecurityCache(IN PCMHIVE CmHive)
{
    PHHIVE Hive = &CmHive->Hive;
    PCM_KEY_NODE Root;
    PCM_KEY_SECURITY Security;
    HCELL_INDEX Start, Cell, Mark;
    ULONG Steps, Limit, Power;
    BOOLEAN Success = TRUE;

    if (!CmpSecurityCacheReady(CmHive) || !Hive->BaseBlock)
        return FALSE;

    CmpFreeSecurityCache(CmHive);

    if (Hive->BaseBlock->RootCell == HCELL_NIL || !HvIsCellAllocated(Hive, Hive->BaseBlock->RootCell))
        return FALSE;
    Root = (PCM_KEY_NODE)HvGetCell(Hive, Hive->BaseBlock->RootCell);
    if (!Root || Root->Signature != CM_KEY_NODE_SIGNATURE)
        return FALSE;
    Start = Root->Security;
    HvReleaseCell(Hive, Hive->BaseBlock->RootCell);
    if (Start == HCELL_NIL)
        return TRUE;

    /*
     * A ring that does not come back to Start (a crafted Flink into the
     * middle of it) is found with Brent's cycle detection: Mark is the cell
     * met at the last power of two steps, so a loop that misses Start is
     * seen within a few times its length, not after Limit steps.
     */
    Limit = CmpSecurityCellLimit(Hive);
    Cell = Start;
    Mark = Start;
    Power = 1;
    for (Steps = 0; Steps < Limit; Steps++)
    {
        Security = CmpGetCheckedSecurityCell(Hive, Cell, NULL);
        if (!Security)
        {
            DPRINT1("Hive 0x%p: broken security ring at cell 0x%x\n", Hive, Cell);
            return FALSE;
        }
        /* A cell that is not usable (zero length descriptor) is not cached; it
           stays in the ring, and is unlinked as usual when it is released */
        if (!CmpAddSecurityCellToCache(CmHive, Cell) &&
            CmpIsSaneRelativeDescriptor(&Security->Descriptor, Security->DescriptorLength))
        {
            Success = FALSE;
        }
        Cell = Security->Flink;
        if (Cell == Start)
            return Success;
        if (Cell == Mark)
            break;
        if (Steps + 1 == Power)
        {
            Mark = Cell;
            Power *= 2;
        }
    }

    /* The ring does not close */
    DPRINT1("Hive 0x%p: security ring does not close\n", Hive);
    return FALSE;
}

/*
 * Add to the cache every cell of the ring that SecurityCell is in. For a hive
 * being loaded, after CmpBuildSecurityCache: a hive whose root has no
 * descriptor (every hive installed before keys got one) still has rings, made
 * by the keys created since, and their cells must be found again to be shared
 * and to join new cells to.
 *
 * MarkSeen records every cell any walk of this load has visited (the caller's
 * set, cmcheck.c): a walk stops at a cell met before, by itself (a loop that
 * misses its start) or by an earlier walk (the rest of that ring was added
 * then), so a load visits each cell once however many keys name cells of one
 * ring and however the hive links them. The walk also stops at the first cell
 * that is not sound and after as many steps as the hive can hold cells.
 * Returns FALSE when MarkSeen could not record a cell (no memory): the caller
 * stops filling the cache. Never fails the load.
 */
BOOLEAN
NTAPI
CmpAddSecurityRingToCache(IN PCMHIVE CmHive,
                          IN HCELL_INDEX SecurityCell,
                          IN PCMP_SECURITY_CELL_SEEN MarkSeen,
                          IN PVOID Context)
{
    PHHIVE Hive = &CmHive->Hive;
    PCM_KEY_SECURITY Security;
    HCELL_INDEX Cell = SecurityCell;
    ULONG Steps, Limit;
    BOOLEAN Seen;

    if (!CmpSecurityCacheReady(CmHive))
        return TRUE;

    Limit = CmpSecurityCellLimit(Hive);
    for (Steps = 0; Steps < Limit; Steps++)
    {
        if (!MarkSeen(Context, Cell, &Seen))
            return FALSE;
        if (Seen)
            return TRUE;
        Security = CmpGetCheckedSecurityCell(Hive, Cell, NULL);
        if (!Security)
            return TRUE;
        if (CmpIsSaneRelativeDescriptor(&Security->Descriptor, Security->DescriptorLength))
            CmpAddSecurityCellToCache(CmHive, Cell);
        Cell = Security->Flink;
        if (Cell == SecurityCell)
            return TRUE;
    }
    return TRUE;
}

static
BOOLEAN
CmpFindMatchingDescriptorCellLocked(IN PCMHIVE CmHive,
                                    IN PVOID Descriptor,
                                    IN ULONG DescriptorLength,
                                    IN HSTORAGE_TYPE Type,
                                    OUT PHCELL_INDEX SecurityCell)
{
    PLIST_ENTRY List;
    PCM_KEY_SECURITY_CACHE Entry;
    PCM_KEY_SECURITY Security;
    ULONG ConvKey, Entries = 0, Compares = 0;

    *SecurityCell = HCELL_NIL;
    if (!CmpSecurityCacheReady(CmHive) || DescriptorLength == 0)
        return FALSE;

    /* Bounded: a list longer than the limit, or more candidates with the same
       hash and length than the compare limit, only means no sharing */
    ConvKey = CmpHashDescriptor(Descriptor, DescriptorLength);
    for (List = CmHive->SecurityHash[ConvKey % CMP_SECURITY_HASH_LISTS].Flink;
         List != &CmHive->SecurityHash[ConvKey % CMP_SECURITY_HASH_LISTS] &&
         Entries < CMP_SECURITY_BUCKET_LIMIT && Compares < CMP_SECURITY_COMPARE_LIMIT;
         List = List->Flink)
    {
        Entries++;
        Entry = CONTAINING_RECORD(List, CM_KEY_SECURITY_CACHE, List);
        if (Entry->ConvKey != ConvKey ||
            Entry->DescriptorLength != DescriptorLength ||
            HvGetCellType(Entry->Cell) != (ULONG)Type)
        {
            continue;
        }

        /* Compare in the cell. A shared cell that already has the most
           references a ULONG can count is not given out again */
        Compares++;
        Security = CmpGetCheckedSecurityCell(&CmHive->Hive, Entry->Cell, NULL);
        if (Security &&
            Security->DescriptorLength == DescriptorLength &&
            Security->ReferenceCount != 0 &&
            Security->ReferenceCount != MAXULONG &&
            CmpSameBytes(&Security->Descriptor, Descriptor, DescriptorLength))
        {
            *SecurityCell = Entry->Cell;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
NTAPI
CmpFindMatchingDescriptorCell(IN PCMHIVE CmHive,
                              IN PVOID Descriptor,
                              IN ULONG DescriptorLength,
                              IN HSTORAGE_TYPE Type,
                              OUT PHCELL_INDEX SecurityCell)
{
    BOOLEAN Acquired, Found;

    Acquired = CmpLockSecurity(&CmHive->Hive);
    Found = CmpFindMatchingDescriptorCellLocked(CmHive, Descriptor, DescriptorLength, Type, SecurityCell);
    CmpUnlockSecurity(&CmHive->Hive, Acquired);
    return Found;
}

/*
 * Give the caller a reference to an 'sk' cell holding this descriptor: an
 * existing cell with the same bytes (and storage type) if there is one, else
 * a new cell linked into the ring. The caller stores the cell in a key node
 * and owns one reference, which CmpReleaseSecurityCell gives back.
 */
static
NTSTATUS
CmpInsertSecurityDescriptorLocked(IN PCMHIVE CmHive,
                                  IN PVOID Descriptor,
                                  IN ULONG DescriptorLength,
                                  IN HSTORAGE_TYPE Type,
                                  OUT PHCELL_INDEX SecurityCell)
{
    PHHIVE Hive = &CmHive->Hive;
    PCM_KEY_SECURITY Security, Anchor, AnchorFlink;
    HCELL_INDEX Cell, AnchorCell = HCELL_NIL;
    PLIST_ENTRY List;
    ULONG i, Looked = 0;

    *SecurityCell = HCELL_NIL;

    /* The length also bounds the cell size computed below */
    if (!CmpIsSaneRelativeDescriptor(Descriptor, DescriptorLength) ||
        DescriptorLength > 0x7FFFFFFF - 64 ||
        (Type != Stable && Type != Volatile))
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Share a cell if one holds the same descriptor */
    if (CmpFindMatchingDescriptorCellLocked(CmHive, Descriptor, DescriptorLength, Type, &Cell))
    {
        Security = CmpGetCheckedSecurityCell(Hive, Cell, NULL);
        if (Security && HvMarkCellDirty(Hive, Cell, FALSE))
        {
            Security->ReferenceCount++;
            *SecurityCell = Cell;
            return STATUS_SUCCESS;
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /*
     * The cell joins the ring of its storage type after the hive's anchor cell
     * of that type: the first cell of the type cached, moved on to its Flink
     * when it is unlinked (CmpRemoveSecurityCellList). Should the anchor not
     * be a sound cell of the ring, any cached cell of the type is taken (a
     * bounded look), else the new cell starts a ring of its own.
     */
    if (CmpSecurityCacheReady(CmHive))
    {
        AnchorCell = CmHive->SecurityRingAnchor[Type];
        if (AnchorCell != HCELL_NIL &&
            (HvGetCellType(AnchorCell) != (ULONG)Type || !CmpValidateSecurityCell(Hive, AnchorCell)))
        {
            AnchorCell = HCELL_NIL;
        }
        for (i = 0; i < CMP_SECURITY_HASH_LISTS && AnchorCell == HCELL_NIL && Looked < CMP_SECURITY_BUCKET_LIMIT; i++)
        {
            for (List = CmHive->SecurityHash[i].Flink;
                 List != &CmHive->SecurityHash[i] && Looked < CMP_SECURITY_BUCKET_LIMIT;
                 List = List->Flink)
            {
                HCELL_INDEX Candidate = CONTAINING_RECORD(List, CM_KEY_SECURITY_CACHE, List)->Cell;

                Looked++;
                if (HvGetCellType(Candidate) == (ULONG)Type &&
                    CmpValidateSecurityCell(Hive, Candidate))
                {
                    AnchorCell = Candidate;
                    break;
                }
            }
        }
        CmHive->SecurityRingAnchor[Type] = AnchorCell;
    }
    Anchor = AnchorCell != HCELL_NIL ? CmpGetCheckedSecurityCell(Hive, AnchorCell, NULL) : NULL;
    AnchorFlink = Anchor ? CmpGetCheckedSecurityCell(Hive, Anchor->Flink, NULL) : NULL;
    if (!AnchorFlink)
        AnchorCell = HCELL_NIL;

    /* Dirty first: nothing is changed in the ring unless all of it can be written */
    Cell = HvAllocateCell(Hive, FIELD_OFFSET(CM_KEY_SECURITY, Descriptor) + DescriptorLength,
                          Type, HCELL_NIL);
    if (Cell == HCELL_NIL)
        return STATUS_INSUFFICIENT_RESOURCES;
    if (!HvMarkCellDirty(Hive, Cell, FALSE) ||
        (AnchorCell != HCELL_NIL &&
         (!HvMarkCellDirty(Hive, AnchorCell, FALSE) || !HvMarkCellDirty(Hive, Anchor->Flink, FALSE))))
    {
        HvFreeCell(Hive, Cell);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Security = (PCM_KEY_SECURITY)HvGetCell(Hive, Cell);
    RtlZeroMemory(Security, FIELD_OFFSET(CM_KEY_SECURITY, Descriptor));
    Security->Signature = CM_KEY_SECURITY_SIGNATURE;
    Security->ReferenceCount = 1;
    Security->DescriptorLength = DescriptorLength;
    RtlCopyMemory(&Security->Descriptor, Descriptor, DescriptorLength);
    if (AnchorCell == HCELL_NIL)
    {
        /* Alone in the ring */
        Security->Flink = Security->Blink = Cell;
    }
    else
    {
        Security->Flink = Anchor->Flink;
        Security->Blink = AnchorCell;
        AnchorFlink->Blink = Cell;
        Anchor->Flink = Cell;
    }

    /* Best effort: no entry only means this cell is not offered for sharing */
    CmpAddSecurityCellToCache(CmHive, Cell);
    *SecurityCell = Cell;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
CmpInsertSecurityDescriptor(IN PCMHIVE CmHive,
                            IN PVOID Descriptor,
                            IN ULONG DescriptorLength,
                            IN HSTORAGE_TYPE Type,
                            OUT PHCELL_INDEX SecurityCell)
{
    BOOLEAN Acquired;
    NTSTATUS Status;

    Acquired = CmpLockSecurity(&CmHive->Hive);
    Status = CmpInsertSecurityDescriptorLocked(CmHive, Descriptor, DescriptorLength, Type, SecurityCell);
    CmpUnlockSecurity(&CmHive->Hive, Acquired);
    return Status;
}

/* The cell and the two cells next to it in the ring (those that are sound) */
BOOLEAN
NTAPI
CmpMarkSecurityCellDirty(IN PHHIVE Hive,
                         IN HCELL_INDEX SecurityCell)
{
    PCM_KEY_SECURITY SecurityData;

    SecurityData = CmpGetCheckedSecurityCell(Hive, SecurityCell, NULL);
    if (!SecurityData) return FALSE;

    return HvMarkCellDirty(Hive, SecurityCell, FALSE) &&
           (!CmpGetCheckedSecurityCell(Hive, SecurityData->Flink, NULL) ||
            HvMarkCellDirty(Hive, SecurityData->Flink, FALSE)) &&
           (!CmpGetCheckedSecurityCell(Hive, SecurityData->Blink, NULL) ||
            HvMarkCellDirty(Hive, SecurityData->Blink, FALSE));
}

/* The caller holds the security lock (CmpReleaseSecurityCell does) */
VOID
NTAPI
CmpRemoveSecurityCellList(IN PHHIVE Hive,
                          IN HCELL_INDEX SecurityCell)
{
    PCM_KEY_SECURITY SecurityData, FlinkCell, BlinkCell;
    ULONG Type;

    PAGED_CODE();

    // ASSERT( (((PCMHIVE)Hive)->HiveSecurityLockOwner == KeGetCurrentThread()) || (CmpTestRegistryLockExclusive() == TRUE) );

    SecurityData = CmpGetCheckedSecurityCell(Hive, SecurityCell, NULL);
    if (!SecurityData) return;

    FlinkCell = CmpGetCheckedSecurityCell(Hive, SecurityData->Flink, NULL);
    BlinkCell = CmpGetCheckedSecurityCell(Hive, SecurityData->Blink, NULL);

    /* The cell a new one would join: its neighbour, or none if it was alone */
    Type = HvGetCellType(SecurityCell);
    if (CmpSecurityCacheReady((PCMHIVE)Hive) && ((PCMHIVE)Hive)->SecurityRingAnchor[Type] == SecurityCell)
    {
        ((PCMHIVE)Hive)->SecurityRingAnchor[Type] =
            (FlinkCell && SecurityData->Flink != SecurityCell && HvGetCellType(SecurityData->Flink) == Type) ?
            SecurityData->Flink : HCELL_NIL;
    }

    /* A ring that is not intact is left alone; never fail on a bad hive */
    if (FlinkCell && BlinkCell &&
        FlinkCell->Blink == SecurityCell &&
        BlinkCell->Flink == SecurityCell)
    {
        /* Unlink the security block. If it is alone, there is no one to tell. */
        if (SecurityData->Flink != SecurityCell)
        {
            FlinkCell->Blink = SecurityData->Blink;
            BlinkCell->Flink = SecurityData->Flink;
        }
    }
    else
    {
        DPRINT1("Security cell 0x%x: ring is not intact, not unlinked\n", SecurityCell);
    }

    CmpRemoveFromSecurityCache(Hive, SecurityCell);
}

/*
 * Give back one reference to an 'sk' cell; the last one unlinks and frees it.
 * Returns FALSE, and changes nothing, if the cell is not a sound 'sk' cell or
 * the cells that the change touches cannot be dirtied (the reference then
 * stays: a leaked count is safe, a freed shared cell is not).
 */
static
BOOLEAN
CmpReleaseSecurityCellLocked(IN PHHIVE Hive,
                             IN HCELL_INDEX SecurityCell)
{
    PCM_KEY_SECURITY SecurityData;

    SecurityData = CmpGetCheckedSecurityCell(Hive, SecurityCell, NULL);
    if (!SecurityData) return FALSE;

    if (SecurityData->ReferenceCount > 1)
    {
        if (!HvMarkCellDirty(Hive, SecurityCell, FALSE)) return FALSE;
        SecurityData->ReferenceCount--;
        return TRUE;
    }

    /* The last reference (a count of 0 is a hive that is wrong already) */
    if (!CmpMarkSecurityCellDirty(Hive, SecurityCell)) return FALSE;
    CmpRemoveSecurityCellList(Hive, SecurityCell);
    HvFreeCell(Hive, SecurityCell);
    return TRUE;
}

BOOLEAN
NTAPI
CmpReleaseSecurityCell(IN PHHIVE Hive,
                       IN HCELL_INDEX SecurityCell)
{
    BOOLEAN Acquired, Released;

    PAGED_CODE();

    Acquired = CmpLockSecurity(Hive);
    Released = CmpReleaseSecurityCellLocked(Hive, SecurityCell);
    CmpUnlockSecurity(Hive, Acquired);
    return Released;
}

VOID
NTAPI
CmpFreeSecurityDescriptor(IN PHHIVE Hive,
                          IN HCELL_INDEX Cell)
{
    PCM_KEY_NODE CellData;

    PAGED_CODE();

    // ASSERT( (((PCMHIVE)Hive)->HiveSecurityLockOwner == KeGetCurrentThread()) || (CmpTestRegistryLockExclusive() == TRUE) );

    CellData = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
    if (!CellData) return;

    ASSERT(CellData->Signature == CM_KEY_NODE_SIGNATURE);

    // FIXME: ReactOS-specific: check whether this key has a security block.
    // On Windows there is no such check, all keys seem to have a valid
    // security block.
    // If we remove this check on ReactOS (and continue running) then we get
    // a BSOD at the end...
    if (CellData->Security == HCELL_NIL)
    {
        DPRINT("Cell 0x%08x (data 0x%p) has no security block!\n", Cell, CellData);
        HvReleaseCell(Hive, Cell);
        return;
    }

    /* Drop the key's reference; the cell goes with the last one */
    if (!CmpReleaseSecurityCell(Hive, CellData->Security))
        DPRINT1("Key 0x%x: security cell 0x%x not released\n", Cell, CellData->Security);

    /* The key has no security either way (it is going away). The old code
       released HCELL_NIL here, after clearing the field. */
    CellData->Security = HCELL_NIL;
    HvReleaseCell(Hive, Cell);
}
