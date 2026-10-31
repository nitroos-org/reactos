/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Configuration Manager Library - Registry Self-Heal Routines
 * COPYRIGHT:   Copyright 2022 George Bișoc <george.bisoc@reactos.org>
 */

#include "cmlib.h"
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

#if !defined(CMLIB_HOST) && !defined(_BLDR_)
extern BOOLEAN CmpSelfHeal;
extern ULONG CmpBootType;
#endif

/* PRIVATE FUNCTIONS **********************************************************/

/**
 * @brief
 * Removes a cell from a fast key index.
 *
 * @param[in,out] FastIndex
 * The fast key index where a cell has to be removed.
 *
 * @param[in] Index
 * The index which points to the location of the
 * cell that is to be removed.
 *
 * @param[in] UpdateCount
 * If set to TRUE, the function will update the fast
 * index count accordingly by one value less. If set
 * to FALSE, the count won't be updated. See Remarks
 * for further information.
 *
 * @remarks
 * In case where the fast index count is not updated is
 * when the key index is not a root but a leaf. In such
 * scenario such leaf is the actual key index itself
 * so updating the fast index count is not necessary (aka
 * UpdateCount is set to FALSE).
 */
static
VOID
CmpRemoveFastIndexKeyCell(
    _Inout_ PCM_KEY_FAST_INDEX FastIndex,
    _In_ ULONG Index,
    _In_ BOOLEAN UpdateCount)
{
    ULONG MoveCount;
    ASSERT(Index < FastIndex->Count);

    /* Calculate the number of trailing cells */
    MoveCount = FastIndex->Count - Index - 1;
    if (MoveCount != 0)
    {
        /* Remove the cell now by moving one location ahead */
        RtlMoveMemory(&FastIndex->List[Index],
                      &FastIndex->List[Index + 1],
                      MoveCount * sizeof(CM_INDEX));
    }

    /* Update the fast index count if asked */
    if (UpdateCount)
        FastIndex->Count--;
}

/**
 * @brief
 * Removes a cell from a normal key index.
 *
 * @param[in,out] KeyIndex
 * The key index where a cell has to be removed.
 *
 * @param[in] Index
 * The index which points to the location of the
 * cell that is to be removed.
 */
static
VOID
CmpRemoveIndexKeyCell(
    _Inout_ PCM_KEY_INDEX KeyIndex,
    _In_ ULONG Index)
{
    ULONG MoveCount;
    ASSERT(Index < KeyIndex->Count);

    /* Calculate the number of trailing cells */
    MoveCount = KeyIndex->Count - Index - 1;
    if (MoveCount != 0)
    {
        /* Remove the cell now by moving one location ahead */
        RtlMoveMemory(&KeyIndex->List[Index],
                      &KeyIndex->List[Index + 1],
                      MoveCount * sizeof(HCELL_INDEX));
    }

    /* Update the key index count */
    KeyIndex->Count--;
}

/**
 * @brief
 * Removes a cell from a key value list node.
 *
 * @param[in,out] ValueListNode
 * The value list node which is used by the
 * function to update the value list count.
 *
 * @param[in,out] ValueListData
 * The value list data of which a cell has to be removed.
 *
 * @param[in] Index
 * The index which points to the location of the
 * cell that is to be removed.
 */
static
VOID
CmpRemoveValueFromValueList(
    _Inout_ PCM_KEY_NODE ValueListNode,
    _Inout_ PCELL_DATA ValueListData,
    _In_ ULONG Index)
{
    ULONG MoveCount;
    ASSERT(Index < ValueListNode->ValueList.Count);

    /* Calculate the number of trailing values */
    MoveCount = ValueListNode->ValueList.Count - Index - 1;
    if (MoveCount != 0)
    {
        /* Remove the value now by moving one location ahead */
        RtlMoveMemory(&ValueListData->u.KeyList[Index],
                      &ValueListData->u.KeyList[Index + 1],
                      MoveCount * sizeof(HCELL_INDEX));
    }

    /* Update the value list count */
    ValueListNode->ValueList.Count--;
}

/**
 * @brief
 * Removes the offending subkey from a root index.
 *
 * @param[in] Hive
 * A pointer to a hive descriptor containing faulty data.
 *
 * @param[in] RootIndex
 * The root index where a leaf is obtained from. Such
 * leaf is used to check deep down the leaf for the offending
 * subkey.
 *
 * @param[in] TargetKey
 * The offending target subkey to be removed.
 *
 * @return
 * Returns TRUE if the function successfully removed the target
 * key, FALSE otherwise.
 */
static
BOOLEAN
CmpRemoveSubkeyInRoot(
    _In_ PHHIVE Hive,
    _In_ PCM_KEY_INDEX RootIndex,
    _In_ HCELL_INDEX TargetKey)
{
    PCM_KEY_INDEX Leaf;
    PCM_KEY_FAST_INDEX FastIndex;
    HCELL_INDEX LeafCell;
    ULONG RootCountIndex;
    ULONG LeafCountIndex;

    PAGED_CODE();

    ASSERT(RootIndex);

    /* Loop the root index */
    for (RootCountIndex = 0; RootCountIndex < RootIndex->Count; RootCountIndex++)
    {
        /*
         * Release the leaf cell from previous iteration
         * of the loop. Make sure what we're releasing is
         * valid to begin with.
         */
        if (RootCountIndex)
        {
            ASSERT(Leaf);
            ASSERT(LeafCell == RootIndex->List[RootCountIndex - 1]);
            HvReleaseCell(Hive, LeafCell);
        }

        /* Get the leaf cell and the leaf for this index */
        LeafCell = RootIndex->List[RootCountIndex];
        Leaf = (PCM_KEY_INDEX)HvGetCell(Hive, LeafCell);
        if (!Leaf)
        {
            DPRINT1("Couldn't get the leaf from cell\n");
            return FALSE;
        }

        /* Start looping the leaf */
        for (LeafCountIndex = 0; LeafCountIndex < Leaf->Count; LeafCountIndex++)
        {
            /* Is the leaf a fast leaf or a hash one? */
            if ((Leaf->Signature == CM_KEY_FAST_LEAF) ||
                (Leaf->Signature == CM_KEY_HASH_LEAF))
            {
                /* It is one of the two, get the fast index */
                FastIndex = (PCM_KEY_FAST_INDEX)Leaf;

                /*
                 * Is the subkey cell from the fast
                 * index the one we one we're actually
                 * searching?
                 */
                if (FastIndex->List[LeafCountIndex].Cell == TargetKey)
                {
                    HvReleaseCell(Hive, LeafCell);
                    HvMarkCellDirty(Hive, LeafCell, FALSE);
                    CmpRemoveFastIndexKeyCell(FastIndex, LeafCountIndex, TRUE);
                    DPRINT1("The offending key cell has BEEN FOUND in fast index (fast index 0x%p, index %u)\n",
                            FastIndex, LeafCountIndex);
                    return TRUE;
                }
            }
            else
            {
                /*
                 * The leaf is neither of the two. Check if
                 * the target offending cell is inside the leaf
                 * itself.
                 */
                if (Leaf->List[LeafCountIndex] == TargetKey)
                {
                    HvReleaseCell(Hive, LeafCell);
                    HvMarkCellDirty(Hive, LeafCell, FALSE);
                    CmpRemoveIndexKeyCell(Leaf, LeafCountIndex);
                    DPRINT1("The offending key cell has BEEN FOUND in leaf (leaf 0x%p, index %u)\n",
                            Leaf, LeafCountIndex);
                    return TRUE;
                }
            }
        }
    }

    /*
     * We have searched everywhere but we couldn't
     * hunt the offending target key cell.
     */
    DPRINT1("No target key has been found to remove\n");
    return FALSE;
}

/**
 * @brief
 * Removes the offending subkey from a leaf index.
 *
 * @param[in] Hive
 * A pointer to a hive descriptor containing faulty data.
 *
 * @param[in] KeyNode
 * A pointer to a key node of the parent. This node is
 * used by the function to mark the whole subkeys list
 * of the parent dirty.
 *
 * @param[in] Leaf
 * A pointer to a leaf key index of which the offending
 * subkey is to be removed from.
 *
 * @param[in] TargetKey
 * The offending target subkey to remove.
 *
 * @return
 * Returns TRUE if the function successfully removed the target
 * key, FALSE otherwise.
 */
static
BOOLEAN
CmpRemoveSubKeyInLeaf(
    _In_ PHHIVE Hive,
    _In_ PCM_KEY_NODE KeyNode,
    _In_ PCM_KEY_INDEX Leaf,
    _In_ HCELL_INDEX TargetKey)
{
    PCM_KEY_FAST_INDEX FastIndex;
    ULONG LeafIndex;

    /* Loop the leaf index */
    for (LeafIndex = 0; LeafIndex < Leaf->Count; LeafIndex++)
    {
        /*
         * Check if the main leaf is a fast
         * leaf or a hash one.
         */
        if ((Leaf->Signature == CM_KEY_FAST_LEAF) ||
            (Leaf->Signature == CM_KEY_HASH_LEAF))
        {
            /* It is one of the two, get the fast index */
            FastIndex = (PCM_KEY_FAST_INDEX)Leaf;

            /*
             * Is the subkey cell from the fast
             * index the one we're actually
             * searching?
             */
            if (FastIndex->List[LeafIndex].Cell == TargetKey)
            {
                HvMarkCellDirty(Hive, KeyNode->SubKeyLists[Stable], FALSE);
                CmpRemoveFastIndexKeyCell(FastIndex, LeafIndex, FALSE);

                /*
                 * Since this fast index actually came from the
                 * actual leaf index itself, just update its count
                 * rather than that of the fast index.
                 */
                Leaf->Count--;
                DPRINT1("The offending key cell has BEEN FOUND in fast index (fast index 0x%p, leaf index %u)\n",
                        FastIndex, LeafIndex);
                return TRUE;
            }
        }
        else
        {
            /*
             * The leaf is neither of the two. The offending
             * cell must come directly from the normal leaf
             * at this point.
             */
            if (Leaf->List[LeafIndex] == TargetKey)
            {
                HvMarkCellDirty(Hive, KeyNode->SubKeyLists[Stable], FALSE);
                CmpRemoveIndexKeyCell(Leaf, LeafIndex);
                DPRINT1("The offending key cell has BEEN FOUND in leaf (leaf 0x%p, index %u)\n",
                        Leaf, LeafIndex);
                return TRUE;
            }
        }
    }

    /*
     * We have searched everywhere but we couldn't
     * hunt the offending target key cell.
     */
    DPRINT1("No target key has been found to remove\n");
    return FALSE;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/**
 * @brief
 * Checks if self healing is permitted by the kernel and/or
 * bootloader. Self healing is also triggered if such a
 * request was prompted by the user to fix a broken hive.
 * Such a request tipically comes from a registry repair
 * tool such as the ReactOS Check Registry Utility.
 *
 * @param[in] FixHive
 * If set to TRUE, self heal is triggered and the target
 * hive will be fixed. Otherwise the hive will not be fixed.
 *
 * @return
 * Returns TRUE if self healing is possible, FALSE otherwise.
 */
BOOLEAN
CMAPI
CmIsSelfHealEnabled(
    _In_ BOOLEAN FixHive)
{
    PAGED_CODE();

    if (FixHive)
        return TRUE;

#if !defined(CMLIB_HOST) && !defined(_BLDR_)
    if (CmpSelfHeal || (CmpBootType & HBOOT_TYPE_SELF_HEAL))
        return TRUE;
#endif

    return FALSE;
}

/**
 * @brief
 * Repairs the parent key from damage by removing the
 * offending subkey cell.
 *
 * @param[in,out] Hive
 * A pointer to a hive descriptor containing faulty data.
 *
 * @param[in] TargetKey
 * The offending target cell to remove from the parent.
 *
 * @param[in] ParentKey
 * The damaged parent key cell to heal.
 *
 * @param[in] FixHive
 * If set to TRUE, self heal is triggered and the target
 * hive will be fixed. Otherwise the hive will not be fixed.
 *
 * @return
 * Returns TRUE if the function successfully healed the parent
 * key, FALSE otherwise.
 */
BOOLEAN
CMAPI
CmpRepairParentKey(
    _Inout_ PHHIVE Hive,
    _In_ HCELL_INDEX TargetKey,
    _In_ HCELL_INDEX ParentKey,
    _In_ BOOLEAN FixHive)
{
    PCM_KEY_INDEX KeyIndex;
    PCM_KEY_NODE KeyNode;
    BOOLEAN ParentRepaired;

    PAGED_CODE();

    /* The target key must NEVER be NIL! */
    ASSERT(TargetKey != HCELL_NIL);

    /* Assume the parent hasn't been repaired yet */
    ParentRepaired = FALSE;

    /* Is self healing possible? */
    if (!CmIsSelfHealEnabled(FixHive))
    {
        DPRINT1("Self healing not possible\n");
        return ParentRepaired;
    }

    /* Obtain a node from the parent */
    KeyNode = (PCM_KEY_NODE)HvGetCell(Hive, ParentKey);
    if (!KeyNode)
    {
        DPRINT1("Couldn't get the parent key node\n");
        return ParentRepaired;
    }

    /* Obtain the index as well since we got the parent node */
    KeyIndex = (PCM_KEY_INDEX)HvGetCell(Hive, KeyNode->SubKeyLists[Stable]);
    if (!KeyIndex)
    {
        DPRINT1("Couldn't get the key index from parent node\n");
        HvReleaseCell(Hive, ParentKey);
        return ParentRepaired;
    }

    /* Check if this is a root */
    if (KeyIndex->Signature == CM_KEY_INDEX_ROOT)
    {
        /* It is, call the specific helper to discard the damaged key down the root */
        ParentRepaired = CmpRemoveSubkeyInRoot(Hive,
                                               KeyIndex,
                                               TargetKey);
    }
    else if ((KeyIndex->Signature == CM_KEY_INDEX_LEAF) ||
             (KeyIndex->Signature == CM_KEY_FAST_LEAF) ||
             (KeyIndex->Signature == CM_KEY_HASH_LEAF))
    {
        /* Otherwise call the leaf helper */
        ParentRepaired = CmpRemoveSubKeyInLeaf(Hive,
                                               KeyNode,
                                               KeyIndex,
                                               TargetKey);
    }
    else
    {
        /*
         * Generally CmCheckRegistry detects if a key index
         * in the subkeys list is totally broken (we understand
         * that if its signature is not root or leaf) and it will
         * purge the whole subkeys list in such cases. With that
         * being said, we should never reach this code path. But
         * if for whatever reason we reach here then something
         * is seriously wrong.
         */
        DPRINT1("The key index signature is invalid (KeyIndex->Signature == %u)",
                KeyIndex->Signature);
        ASSERT(FALSE);
    }

    /*
     * If we successfully removed the offending key
     * cell mark down the parent as dirty and punt down
     * the subkey count as well. Mark the hive as in
     * self heal mode as well.
     */
    if (ParentRepaired)
    {
        HvMarkCellDirty(Hive, ParentKey, FALSE);
        KeyNode->SubKeyCounts[Stable]--;
        Hive->BaseBlock->BootType |= HBOOT_TYPE_SELF_HEAL;
        DPRINT1("The subkey has been removed, the parent is now repaired\n");
    }

    HvReleaseCell(Hive, KeyNode->SubKeyLists[Stable]);
    HvReleaseCell(Hive, ParentKey);
    return ParentRepaired;
}

/**
 * @brief
 * Repairs the parent of the node from damage due
 * to parent cell and parent node incosistency.
 *
 * @param[in,out] Hive
 * A pointer to a hive descriptor containing faulty data.
 *
 * @param[in] CurrentCell
 * The current cell to be marked as dirty.
 *
 * @param[in] ParentCell
 * The sane parent cell which is used by the
 * function for new parent node assignment.
 *
 * @param[in,out] CellData
 * The cell data of the current cell of which
 * its parent node is to be repaired.
 *
 * @param[in] FixHive
 * If set to TRUE, self heal is triggered and the target
 * hive will be fixed. Otherwise the hive will not be fixed.
 *
 * @return
 * Returns TRUE if the function successfully healed the
 * parent node, FALSE otherwise.
 */
BOOLEAN
CMAPI
CmpRepairParentNode(
    _Inout_ PHHIVE Hive,
    _In_ HCELL_INDEX CurrentCell,
    _In_ HCELL_INDEX ParentCell,
    _Inout_ PCELL_DATA CellData,
    _In_ BOOLEAN FixHive)
{
    PAGED_CODE();

    /* Is self healing possible? */
    if (!CmIsSelfHealEnabled(FixHive))
    {
        DPRINT1("Self healing not possible\n");
        return FALSE;
    }

    /*
     * Mark the cell where we got the actual
     * cell data as dirty and fix the node.
     */
    HvMarkCellDirty(Hive, CurrentCell, FALSE);
    CellData->u.KeyNode.Parent = ParentCell;

    /* Mark the hive as in self healing mode since we repaired it */
    Hive->BaseBlock->BootType |= HBOOT_TYPE_SELF_HEAL;
    return TRUE;
}

/**
 * @brief
 * Repairs the key node signature from damage
 * due to signature corruption.
 *
 * @param[in,out] Hive
 * A pointer to a hive descriptor containing faulty data.
 *
 * @param[in] CurrentCell
 * The current cell to be marked as dirty.
 *
 * @param[in,out] CellData
 * The cell data of the current cell of which
 * its signature is to be repaired.
 *
 * @param[in] FixHive
 * If set to TRUE, self heal is triggered and the target
 * hive will be fixed. Otherwise the hive will not be fixed.
 *
 * @return
 * Returns TRUE if the function successfully healed the
 * key node signature, FALSE otherwise.
 */
BOOLEAN
CMAPI
CmpRepairKeyNodeSignature(
    _Inout_ PHHIVE Hive,
    _In_ HCELL_INDEX CurrentCell,
    _Inout_ PCELL_DATA CellData,
    _In_ BOOLEAN FixHive)
{
    PAGED_CODE();

    /* Is self healing possible? */
    if (!CmIsSelfHealEnabled(FixHive))
    {
        DPRINT1("Self healing not possible\n");
        return FALSE;
    }

    /*
     * Mark the cell where we got the actual
     * cell data as dirty and fix the key signature.
     */
    HvMarkCellDirty(Hive, CurrentCell, FALSE);
    CellData->u.KeyNode.Signature = CM_KEY_NODE_SIGNATURE;

    /* Mark the hive as in self healing mode since we repaired it */
    Hive->BaseBlock->BootType |= HBOOT_TYPE_SELF_HEAL;
    return TRUE;
}

/**
 * @brief
 * Repairs the class from damage due to class
 * corruption within the node key.
 *
 * @param[in,out] Hive
 * A pointer to a hive descriptor containing faulty data.
 *
 * @param[in] CurrentCell
 * The current cell to be marked as dirty.
 *
 * @param[in,out] CellData
 * The cell data of the current cell of which
 * its class is to be repaired.
 *
 * @param[in] FixHive
 * If set to TRUE, self heal is triggered and the target
 * hive will be fixed. Otherwise the hive will not be fixed.
 *
 * @return
 * Returns TRUE if the function successfully healed the
 * class of node key, FALSE otherwise.
 */
BOOLEAN
CMAPI
CmpRepairClassOfNodeKey(
    _Inout_ PHHIVE Hive,
    _In_ HCELL_INDEX CurrentCell,
    _Inout_ PCELL_DATA CellData,
    _In_ BOOLEAN FixHive)
{
    PAGED_CODE();

    /* Is self healing possible? */
    if (!CmIsSelfHealEnabled(FixHive))
    {
        DPRINT1("Self healing not possible\n");
        return FALSE;
    }

    /*
     * Mark the cell where we got the actual
     * cell data as dirty and fix the class field
     * of key node.
     */
    HvMarkCellDirty(Hive, CurrentCell, FALSE);
    CellData->u.KeyNode.Class = HCELL_NIL;
    CellData->u.KeyNode.ClassLength = 0;

    /* Mark the hive as in self healing mode since we repaired it */
    Hive->BaseBlock->BootType |= HBOOT_TYPE_SELF_HEAL;
    return TRUE;
}

/**
 * @brief
 * Repairs the value list count of key due to
 * corruption. The process involves by removing
 * one damaged value less from the list.
 *
 * @param[in,out] Hive
 * A pointer to a hive descriptor containing faulty data.
 *
 * @param[in] CurrentCell
 * The current cell to be marked as dirty.
 *
 * @param[in] ListCountIndex
 * The value count index which points to the actual
 * value in the list to be removed.
 *
 * @param[in,out] ValueListData
 * The value list cell data containing the actual list
 * of which the damaged is to be removed from.
 *
 * @param[in] FixHive
 * If set to TRUE, self heal is triggered and the target
 * hive will be fixed. Otherwise the hive will not be fixed.
 *
 * @return
 * Returns TRUE if the function successfully healed the
 * value list count, FALSE otherwise.
 */
BOOLEAN
CMAPI
CmpRepairValueListCount(
    _Inout_ PHHIVE Hive,
    _In_ HCELL_INDEX CurrentCell,
    _In_ ULONG ListCountIndex,
    _Inout_ PCELL_DATA ValueListData,
    _In_ BOOLEAN FixHive)
{
    PCM_KEY_NODE ValueListNode;

    PAGED_CODE();

    /* Is self healing possible? */
    if (!CmIsSelfHealEnabled(FixHive))
    {
        DPRINT1("Self healing not possible\n");
        return FALSE;
    }

    /*
     * Obtain a node from the cell that we mark it as dirty.
     * The node is that of the current cell of which its
     * value list is being validated.
     */
    ValueListNode = (PCM_KEY_NODE)HvGetCell(Hive, CurrentCell);
    if (!ValueListNode)
    {
        DPRINT1("Could not get a node from the current cell\n");
        return FALSE;
    }

    /*
     * Mark the current cell and value list as dirty
     * as we will be making changes onto them.
     */
    HvMarkCellDirty(Hive, CurrentCell, FALSE);
    HvMarkCellDirty(Hive, ValueListNode->ValueList.List, FALSE);

    /*
     * Now remove the value from the list and mark the
     * hive as in self healing mode.
     */
    CmpRemoveValueFromValueList(ValueListNode, ValueListData, ListCountIndex);
    Hive->BaseBlock->BootType |= HBOOT_TYPE_SELF_HEAL;
    HvReleaseCell(Hive, CurrentCell);
    return TRUE;
}

/**
 * @brief
 * Repairs the value list due to corruption. The
 * process involes by purging the whole damaged
 * list.
 *
 * @param[in,out] Hive
 * A pointer to a hive descriptor containing faulty data.
 *
 * @param[in] CurrentCell
 * The current cell to be marked as dirty.
 *
 * @param[in] FixHive
 * If set to TRUE, self heal is triggered and the target
 * hive will be fixed. Otherwise the hive will not be fixed.
 *
 * @return
 * Returns TRUE if the function successfully healed the
 * value list, FALSE otherwise.
 */
BOOLEAN
CMAPI
CmpRepairValueList(
    _Inout_ PHHIVE Hive,
    _In_ HCELL_INDEX CurrentCell,
    _In_ BOOLEAN FixHive)
{
    PCM_KEY_NODE ValueListNode;

    PAGED_CODE();

    /* Is self healing possible? */
    if (!CmIsSelfHealEnabled(FixHive))
    {
        DPRINT1("Self healing not possible\n");
        return FALSE;
    }

    /* Obtain a node */
    ValueListNode = (PCM_KEY_NODE)HvGetCell(Hive, CurrentCell);
    if (!ValueListNode)
    {
        DPRINT1("Could not get a node from the current cell\n");
        return FALSE;
    }

    /* Purge out the whole list */
    HvMarkCellDirty(Hive, CurrentCell, FALSE);
    ValueListNode->ValueList.List = HCELL_NIL;
    ValueListNode->ValueList.Count = 0;

    Hive->BaseBlock->BootType |= HBOOT_TYPE_SELF_HEAL;
    HvReleaseCell(Hive, CurrentCell);
    return TRUE;
}

/**
 * @brief
 * Repairs the subkey list count due to corruption.
 * The process involves by fixing the count itself
 * with a sane count.
 *
 * @param[in,out] Hive
 * A pointer to a hive descriptor containing faulty data.
 *
 * @param[in] CurrentCell
 * The current cell to be marked as dirty.
 *
 * @param[in] Count
 * The healthy count which is used by the function
 * to fix the subkeys list count.
 *
 * @param[in,out] CellData
 * The cell data of the current cell of which its
 * subkeys list is to be fixed.
 *
 * @param[in] FixHive
 * If set to TRUE, self heal is triggered and the target
 * hive will be fixed. Otherwise the hive will not be fixed.
 *
 * @return
 * Returns TRUE if the function successfully healed the
 * subkeys list count, FALSE otherwise.
 */
BOOLEAN
CMAPI
CmpRepairSubKeyCounts(
    _Inout_ PHHIVE Hive,
    _In_ HCELL_INDEX CurrentCell,
    _In_ ULONG Count,
    _Inout_ PCELL_DATA CellData,
    _In_ BOOLEAN FixHive)
{
    PAGED_CODE();

    /* Is self healing possible? */
    if (!CmIsSelfHealEnabled(FixHive))
    {
        DPRINT1("Self healing not possible\n");
        return FALSE;
    }

    /*
     * Mark the cell where we got the actual
     * cell data as dirty and fix the subkey
     * counts.
     */
    HvMarkCellDirty(Hive, CurrentCell, FALSE);
    CellData->u.KeyNode.SubKeyCounts[Stable] = Count;

    /* Mark the hive as in self healing mode since we repaired it */
    Hive->BaseBlock->BootType |= HBOOT_TYPE_SELF_HEAL;
    return TRUE;
}

/**
 * @brief
 * Repairs the subkey list due to corruption. The process
 * involves by purging the whole damaged subkeys list.
 *
 * @param[in,out] Hive
 * A pointer to a hive descriptor containing faulty data.
 *
 * @param[in] CurrentCell
 * The current cell to be marked as dirty.
 *
 * @param[in,out] CellData
 * The cell data of the current cell of which its
 * subkeys list is to be fixed.
 *
 * @param[in] FixHive
 * If set to TRUE, self heal is triggered and the target
 * hive will be fixed. Otherwise the hive will not be fixed.
 *
 * @return
 * Returns TRUE if the function successfully healed the
 * subkeys list, FALSE otherwise.
 */
BOOLEAN
CMAPI
CmpRepairSubKeyList(
    _Inout_ PHHIVE Hive,
    _In_ HCELL_INDEX CurrentCell,
    _Inout_ PCELL_DATA CellData,
    _In_ BOOLEAN FixHive)
{
    PAGED_CODE();

    /* Is self healing possible? */
    if (!CmIsSelfHealEnabled(FixHive))
    {
        DPRINT1("Self healing not possible\n");
        return FALSE;
    }

    /*
     * Mark the cell where we got the actual
     * cell data as dirty and fix the subkey
     * list.
     */
    HvMarkCellDirty(Hive, CurrentCell, FALSE);
    CellData->u.KeyNode.SubKeyLists[Stable] = HCELL_NIL;
    CellData->u.KeyNode.SubKeyCounts[Stable] = 0;

    /* Mark the hive as in self healing mode since we repaired it */
    Hive->BaseBlock->BootType |= HBOOT_TYPE_SELF_HEAL;
    return TRUE;
}

/* CASE TABLE REPAIR **********************************************************/

#if !defined(_BLDR_)

/*
 * The name of a key is looked up in the subkey index by comparing the names
 * upper cased, and a hash leaf (lh) holds a hash of the upper cased name. Both
 * depend on the Unicode case table. A hive written while a different table
 * was in use (a table that upper cased a character differently) has hashes
 * that are no longer found and, for the same reason, names that are no longer
 * in order. The functions below bring the index up to date: they recompute
 * the hash of every name that is not plain ASCII and, if the names are out of
 * order, sort the index again, in place, keeping the shape of the leaves.
 */

#define CMP_NAME_IS_COMPRESSED(Node)    (((Node)->Flags & KEY_COMP_NAME) != 0)

static
__inline
ULONG
CmpKeyNodeNameChars(
    _In_ PCM_KEY_NODE Node)
{
    return CMP_NAME_IS_COMPRESSED(Node) ? Node->NameLength :
                                          Node->NameLength / sizeof(WCHAR);
}

static
__inline
WCHAR
CmpKeyNodeNameChar(
    _In_ PCM_KEY_NODE Node,
    _In_ ULONG Index)
{
    return CMP_NAME_IS_COMPRESSED(Node) ? (WCHAR)((PUCHAR)Node->Name)[Index] :
                                          Node->Name[Index];
}

/* A name that is not plain ASCII is the only one the case table can change */
static
BOOLEAN
CmpKeyNodeNameIsNotAscii(
    _In_ PCM_KEY_NODE Node)
{
    ULONG i, Chars = CmpKeyNodeNameChars(Node);

    for (i = 0; i < Chars; i++)
    {
        if (CmpKeyNodeNameChar(Node, i) >= 0x80)
            return TRUE;
    }
    return FALSE;
}

/* Same value as CmpComputeHashKey gives for the name */
static
ULONG
CmpHashKeyNodeName(
    _In_ PCM_KEY_NODE Node)
{
    ULONG i, Chars = CmpKeyNodeNameChars(Node), Hash = 0;

    for (i = 0; i < Chars; i++)
    {
        Hash *= 37;
        Hash += RtlUpcaseUnicodeChar(CmpKeyNodeNameChar(Node, i));
    }
    return Hash;
}

/* The order the subkey index keeps: names compared upper cased */
static
LONG
CmpCompareKeyNodeNames(
    _In_ PCM_KEY_NODE Node1,
    _In_ PCM_KEY_NODE Node2)
{
    ULONG i, Chars1 = CmpKeyNodeNameChars(Node1), Chars2 = CmpKeyNodeNameChars(Node2);
    ULONG Common = min(Chars1, Chars2);
    WCHAR Char1, Char2;
    LONG Result;

    for (i = 0; i < Common; i++)
    {
        Char1 = CmpKeyNodeNameChar(Node1, i);
        Char2 = CmpKeyNodeNameChar(Node2, i);
        if (Char1 != Char2)
        {
            Result = (LONG)RtlUpcaseUnicodeChar(Char1) -
                     (LONG)RtlUpcaseUnicodeChar(Char2);
            if (Result)
                return Result;
        }
    }
    return (LONG)Chars1 - (LONG)Chars2;
}

/* The key node of a subkey, only if it can be trusted to be read */
static
PCM_KEY_NODE
CmpGetSubKeyNodeForCase(
    _In_ PHHIVE Hive,
    _In_ HCELL_INDEX Cell)
{
    PCM_KEY_NODE Node;
    LONG CellSize;

    if (Cell == HCELL_NIL || !HvIsCellAllocated(Hive, Cell))
        return NULL;

    Node = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
    if (!Node || Node->Signature != CM_KEY_NODE_SIGNATURE || Node->NameLength == 0)
        return NULL;

    CellSize = HvGetCellSize(Hive, Node);
    if (CellSize <= 0 ||
        (ULONG)CellSize < FIELD_OFFSET(CM_KEY_NODE, Name) + (ULONG)Node->NameLength)
    {
        return NULL;
    }
    return Node;
}

/* A leaf of the subkey index (the index itself, or a leaf of its root) */
static
PCM_KEY_INDEX
CmpGetSubKeyLeafForCase(
    _In_ PHHIVE Hive,
    _In_ PCM_KEY_INDEX Top,
    _In_ HCELL_INDEX TopCell,
    _In_ ULONG LeafNumber,
    _Out_ PHCELL_INDEX LeafCell)
{
    PCM_KEY_INDEX Leaf;
    ULONG EntrySize;
    LONG CellSize;

    if (Top->Signature == CM_KEY_INDEX_ROOT)
    {
        *LeafCell = Top->List[LeafNumber];
        if (*LeafCell == HCELL_NIL || !HvIsCellAllocated(Hive, *LeafCell))
            return NULL;
        Leaf = (PCM_KEY_INDEX)HvGetCell(Hive, *LeafCell);
    }
    else
    {
        *LeafCell = TopCell;
        Leaf = Top;
    }

    if (!Leaf ||
        (Leaf->Signature != CM_KEY_INDEX_LEAF &&
         Leaf->Signature != CM_KEY_FAST_LEAF &&
         Leaf->Signature != CM_KEY_HASH_LEAF))
    {
        return NULL;
    }

    /* The entries must lie within the cell */
    EntrySize = (Leaf->Signature == CM_KEY_INDEX_LEAF) ? sizeof(HCELL_INDEX) :
                                                         sizeof(CM_INDEX);
    CellSize = HvGetCellSize(Hive, Leaf);
    if (CellSize < (LONG)FIELD_OFFSET(CM_KEY_INDEX, List) ||
        ((ULONG)CellSize - FIELD_OFFSET(CM_KEY_INDEX, List)) / EntrySize < Leaf->Count)
    {
        return NULL;
    }
    return Leaf;
}

static
__inline
HCELL_INDEX
CmpGetLeafEntryCell(
    _In_ PCM_KEY_INDEX Leaf,
    _In_ ULONG Number)
{
    if (Leaf->Signature == CM_KEY_INDEX_LEAF)
        return Leaf->List[Number];
    return ((PCM_KEY_FAST_INDEX)Leaf)->List[Number].Cell;
}

static
LONG
CmpCompareIndexEntries(
    _In_ PHHIVE Hive,
    _In_ PCM_INDEX Entry1,
    _In_ PCM_INDEX Entry2)
{
    PCM_KEY_NODE Node1 = CmpGetSubKeyNodeForCase(Hive, Entry1->Cell);
    PCM_KEY_NODE Node2 = CmpGetSubKeyNodeForCase(Hive, Entry2->Cell);

    /* The nodes were all checked by the caller */
    if (!Node1 || !Node2)
        return 0;
    return CmpCompareKeyNodeNames(Node1, Node2);
}

/* Stable merge sort of the entries; Temp is as large as Entries */
static
VOID
CmpSortIndexEntries(
    _In_ PHHIVE Hive,
    _Inout_ PCM_INDEX Entries,
    _Inout_ PCM_INDEX Temp,
    _In_ ULONG Count)
{
    PCM_INDEX From = Entries, To = Temp, Swap;
    ULONG Width, Low, Mid, High, i, j, k;

    for (Width = 1; Width < Count; Width *= 2)
    {
        for (Low = 0; Low < Count; Low += 2 * Width)
        {
            Mid = min(Low + Width, Count);
            High = min(Low + 2 * Width, Count);
            i = Low;
            j = Mid;
            k = Low;

            /* Two runs that are already in order are just copied */
            if (Mid >= High || CmpCompareIndexEntries(Hive, &From[Mid - 1], &From[Mid]) <= 0)
            {
                RtlCopyMemory(&To[Low], &From[Low], (High - Low) * sizeof(CM_INDEX));
                continue;
            }

            while (i < Mid && j < High)
            {
                if (CmpCompareIndexEntries(Hive, &From[j], &From[i]) < 0)
                    To[k++] = From[j++];
                else
                    To[k++] = From[i++];
            }
            while (i < Mid)
                To[k++] = From[i++];
            while (j < High)
                To[k++] = From[j++];
        }

        Swap = From;
        From = To;
        To = Swap;
    }

    /* The sorted run is in From; make sure it is in Entries */
    if (From != Entries)
        RtlCopyMemory(Entries, From, Count * sizeof(CM_INDEX));
}

/**
 * @brief
 * Brings the subkey index of a key up to date with the Unicode case table
 * in use. A hash leaf entry of a name that is not plain ASCII gets the hash
 * of the name as the current table computes it, and if the names are not in
 * order any more (the table upper cases a character differently), the index
 * is sorted again. The leaves keep their number of entries, so the root, the
 * key and its subkey count are not touched. Every cell changed is marked as
 * dirty so that the flush of the hive writes the repair.
 *
 * @param[in,out] Hive
 * A pointer to the hive descriptor the key belongs to.
 *
 * @param[in] KeyNode
 * The key whose stable subkey index is brought up to date.
 *
 * @param[in,out] Stats
 * If given, counts what has been done.
 *
 * @remarks
 * Nothing is changed if the index cannot be read safely (it is the job of the
 * rest of the check to find that out). A list with names that are equal under
 * the current table (two names that differed under the old one) is sorted but
 * the pair stays, and is left to the lexicographical order check.
 */
VOID
CMAPI
CmpRepairSubKeyIndexCase(
    _Inout_ PHHIVE Hive,
    _In_ PCM_KEY_NODE KeyNode,
    _In_opt_ PCMP_CASE_REPAIR_STATS Stats)
{
    HCELL_INDEX TopCell, LeafCell;
    PCM_KEY_INDEX Top, Leaf;
    PCM_KEY_FAST_INDEX FastLeaf;
    PCM_KEY_NODE Node, PrevNode = NULL;
    PCM_INDEX Entries, Temp, Entry;
    ULONG LeafCount, LeafNumber, i, k, Hash, Total = 0, BufferSize;
    USHORT Type = 0;
    BOOLEAN NotAscii, PrevNotAscii = FALSE, Unsorted = FALSE, Mixed = FALSE, Dirty;

    PAGED_CODE();

    TopCell = KeyNode->SubKeyLists[Stable];
    if (KeyNode->SubKeyCounts[Stable] == 0 ||
        TopCell == HCELL_NIL ||
        !HvIsCellAllocated(Hive, TopCell))
    {
        return;
    }

    Top = (PCM_KEY_INDEX)HvGetCell(Hive, TopCell);
    if (!Top)
        return;

    if (Top->Signature == CM_KEY_INDEX_ROOT)
    {
        LONG CellSize = HvGetCellSize(Hive, Top);

        if (CellSize < (LONG)FIELD_OFFSET(CM_KEY_INDEX, List) ||
            ((ULONG)CellSize - FIELD_OFFSET(CM_KEY_INDEX, List)) / sizeof(HCELL_INDEX) < Top->Count)
        {
            return;
        }
        LeafCount = Top->Count;
    }
    else
    {
        LeafCount = 1;
    }

    /*
     * First pass: fix the hashes in place and find out if the names are in
     * order. The common case, a hive without a name that is not ASCII, only
     * reads the names.
     */
    for (LeafNumber = 0; LeafNumber < LeafCount; LeafNumber++)
    {
        Leaf = CmpGetSubKeyLeafForCase(Hive, Top, TopCell, LeafNumber, &LeafCell);
        if (!Leaf)
            return;

        if (Type == 0)
            Type = Leaf->Signature;
        else if (Type != Leaf->Signature)
            Mixed = TRUE;

        FastLeaf = (PCM_KEY_FAST_INDEX)Leaf;
        Dirty = FALSE;
        for (i = 0; i < Leaf->Count; i++)
        {
            Node = CmpGetSubKeyNodeForCase(Hive, CmpGetLeafEntryCell(Leaf, i));
            if (!Node)
                return;

            NotAscii = CmpKeyNodeNameIsNotAscii(Node);
            if (NotAscii && Leaf->Signature == CM_KEY_HASH_LEAF)
            {
                Hash = CmpHashKeyNodeName(Node);
                if (FastLeaf->List[i].HashKey != Hash)
                {
                    if (!Dirty)
                    {
                        if (!Hive->ReadOnly)
                            HvMarkCellDirty(Hive, LeafCell, FALSE);
                        Dirty = TRUE;
                    }
                    FastLeaf->List[i].HashKey = Hash;
                    if (Stats)
                        Stats->Hashes++;
                }
            }

            if (PrevNode && (PrevNotAscii || NotAscii) &&
                CmpCompareKeyNodeNames(PrevNode, Node) > 0)
            {
                Unsorted = TRUE;
            }
            PrevNode = Node;
            PrevNotAscii = NotAscii;
            Total++;
        }
    }

    if (!Unsorted)
        return;

    /* Entries of different kinds of leaves cannot be moved from one to another */
    if (Mixed)
    {
        DPRINT1("The subkey index has different kinds of leaves, can't sort it\n");
        if (Stats)
            Stats->Skipped++;
        return;
    }

    /* Second pass: take all the entries, sort them, put them back */
    BufferSize = Total * 2 * sizeof(CM_INDEX);
    Entries = (PCM_INDEX)Hive->Allocate(BufferSize, TRUE, TAG_CM);
    if (!Entries)
    {
        DPRINT1("No memory to sort the subkey index\n");
        if (Stats)
            Stats->Skipped++;
        return;
    }
    Temp = Entries + Total;

    k = 0;
    for (LeafNumber = 0; LeafNumber < LeafCount; LeafNumber++)
    {
        Leaf = CmpGetSubKeyLeafForCase(Hive, Top, TopCell, LeafNumber, &LeafCell);
        if (!Leaf)
        {
            /* It was fine a moment ago: leave the index as it is */
            Hive->Free(Entries, BufferSize);
            return;
        }
        FastLeaf = (PCM_KEY_FAST_INDEX)Leaf;
        for (i = 0; i < Leaf->Count; i++, k++)
        {
            if (Type == CM_KEY_INDEX_LEAF)
            {
                Entries[k].Cell = Leaf->List[i];
                Entries[k].HashKey = 0;
            }
            else
            {
                Entries[k] = FastLeaf->List[i];
            }
        }
    }
    if (k != Total)
    {
        Hive->Free(Entries, BufferSize);
        return;
    }

    CmpSortIndexEntries(Hive, Entries, Temp, Total);

    k = 0;
    for (LeafNumber = 0; LeafNumber < LeafCount; LeafNumber++)
    {
        Leaf = CmpGetSubKeyLeafForCase(Hive, Top, TopCell, LeafNumber, &LeafCell);
        if (!Leaf)
            break;
        FastLeaf = (PCM_KEY_FAST_INDEX)Leaf;
        Dirty = FALSE;
        for (i = 0; i < Leaf->Count; i++, k++)
        {
            Entry = &Entries[k];
            if (CmpGetLeafEntryCell(Leaf, i) == Entry->Cell)
                continue;

            if (!Dirty)
            {
                if (!Hive->ReadOnly)
                    HvMarkCellDirty(Hive, LeafCell, FALSE);
                Dirty = TRUE;
            }
            if (Type == CM_KEY_INDEX_LEAF)
                Leaf->List[i] = Entry->Cell;
            else
                FastLeaf->List[i] = *Entry;
        }
    }

    Hive->Free(Entries, BufferSize);
    if (Stats)
        Stats->Sorted++;
}

#else /* _BLDR_ */

VOID
CMAPI
CmpRepairSubKeyIndexCase(
    _Inout_ PHHIVE Hive,
    _In_ PCM_KEY_NODE KeyNode,
    _In_opt_ PCMP_CASE_REPAIR_STATS Stats)
{
    /* The loader only reads the hive */
    UNREFERENCED_PARAMETER(Hive);
    UNREFERENCED_PARAMETER(KeyNode);
    UNREFERENCED_PARAMETER(Stats);
}

#endif /* _BLDR_ */

/* EOF */
