/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            lib/cmlib/cmvalue.c
 * PURPOSE:         Configuration Manager Library - Cell Values
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include "cmlib.h"
#define NDEBUG
#include <debug.h>

/* BIG DATA ******************************************************************/

/*
 * Is the data of a value (not small, Length bytes, in DataCell) a big data
 * chain: a hive of format 1.4 or later, data longer than CM_KEY_VALUE_BIG,
 * and a data cell too small to hold it (see cmlib.h). The chain itself was
 * found sound by the check when the hive was loaded, and only the functions
 * below change it.
 */
BOOLEAN
NTAPI
CmpIsBigValueData(
    _In_ PHHIVE Hive,
    _In_ HCELL_INDEX DataCell,
    _In_ ULONG Length)
{
    PVOID Data;
    LONG Size;

    if (!CmpIsKeyValueBig(Hive, Length) || DataCell == HCELL_NIL)
        return FALSE;

    Data = HvGetCell(Hive, DataCell);
    if (!Data)
        return FALSE;
    Size = HvGetCellSize(Hive, Data);
    HvReleaseCell(Hive, DataCell);
    return (Size < 0) || ((ULONG)Size < Length);
}

/* The 'db' cell of a chain and its list of segments; NULL if they are not readable */
static
PHCELL_INDEX
CmpGetBigDataList(
    _In_ PHHIVE Hive,
    _In_ HCELL_INDEX DataCell,
    _Out_ PULONG Count,
    _Out_ PHCELL_INDEX ListCell)
{
    PCM_BIG_DATA BigData;
    PHCELL_INDEX List;

    *Count = 0;
    *ListCell = HCELL_NIL;
    BigData = (PCM_BIG_DATA)HvGetCell(Hive, DataCell);
    if (!BigData)
        return NULL;
    if (BigData->Signature != CM_BIG_DATA_SIGNATURE || BigData->List == HCELL_NIL)
    {
        HvReleaseCell(Hive, DataCell);
        return NULL;
    }
    *Count = BigData->Count;
    *ListCell = BigData->List;
    HvReleaseCell(Hive, DataCell);

    List = (PHCELL_INDEX)HvGetCell(Hive, *ListCell);
    if (!List)
        *ListCell = HCELL_NIL;
    return List;
}

/* Copy Length bytes of big data from the chain at DataCell into Buffer */
static
BOOLEAN
CmpReadBigData(
    _In_ PHHIVE Hive,
    _In_ HCELL_INDEX DataCell,
    _In_ ULONG Length,
    _Out_ PUCHAR Buffer)
{
    PHCELL_INDEX List;
    HCELL_INDEX ListCell;
    PVOID Segment;
    ULONG Count, Needed, i, Chunk;

    List = CmpGetBigDataList(Hive, DataCell, &Count, &ListCell);
    if (!List)
        return FALSE;

    /* Each segment holds CM_KEY_VALUE_BIG bytes, the last one the rest; a chain may list more */
    Needed = CMP_BIG_DATA_SEGMENTS(Length);
    for (i = 0; i < Needed && i < Count; i++)
    {
        Chunk = min(Length - i * CM_KEY_VALUE_BIG, CM_KEY_VALUE_BIG);
        Segment = HvGetCell(Hive, List[i]);
        if (!Segment)
            break;
        RtlCopyMemory(Buffer + i * CM_KEY_VALUE_BIG, Segment, Chunk);
        HvReleaseCell(Hive, List[i]);
    }
    HvReleaseCell(Hive, ListCell);
    return (i == Needed);
}

/* Mark every cell of a chain dirty: the 'db' cell, its list, every listed segment */
static
BOOLEAN
CmpMarkBigDataDirty(
    _In_ PHHIVE Hive,
    _In_ HCELL_INDEX DataCell)
{
    PHCELL_INDEX List;
    HCELL_INDEX ListCell;
    ULONG Count, i;
    BOOLEAN Result;

    if (!HvMarkCellDirty(Hive, DataCell, FALSE))
        return FALSE;
    List = CmpGetBigDataList(Hive, DataCell, &Count, &ListCell);
    if (!List)
        return FALSE;
    Result = HvMarkCellDirty(Hive, ListCell, FALSE);
    for (i = 0; Result && i < Count; i++)
        Result = HvMarkCellDirty(Hive, List[i], FALSE);
    HvReleaseCell(Hive, ListCell);
    return Result;
}

/* Free every cell of a chain: the listed segments, the list, the 'db' cell */
static
VOID
CmpFreeBigData(
    _In_ PHHIVE Hive,
    _In_ HCELL_INDEX DataCell)
{
    PHCELL_INDEX List;
    HCELL_INDEX ListCell;
    ULONG Count, i;

    List = CmpGetBigDataList(Hive, DataCell, &Count, &ListCell);
    if (List)
    {
        for (i = 0; i < Count; i++)
            HvFreeCell(Hive, List[i]);
        HvReleaseCell(Hive, ListCell);
        HvFreeCell(Hive, ListCell);
    }
    HvFreeCell(Hive, DataCell);
}

/*
 * Store DataSize bytes (more than CM_KEY_VALUE_BIG) as big data: the
 * segments, the list, the 'db' cell. On failure nothing is left allocated.
 */
static
NTSTATUS
CmpSetBigData(
    _In_ PHHIVE Hive,
    _In_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ HSTORAGE_TYPE StorageType,
    _Out_ PHCELL_INDEX DataCell)
{
    PCM_BIG_DATA BigData;
    PHCELL_INDEX List;
    HCELL_INDEX BigCell, ListCell, Segment;
    ULONG Count, i, Chunk;

    *DataCell = HCELL_NIL;
    Count = CMP_BIG_DATA_SEGMENTS(DataSize);

    /* The count of segments is 16 bits wide: about 1 GB at most */
    if (Count > MAXUSHORT)
        return STATUS_INSUFFICIENT_RESOURCES;

    BigCell = HvAllocateCell(Hive, sizeof(CM_BIG_DATA), StorageType, HCELL_NIL);
    if (BigCell == HCELL_NIL)
        return STATUS_INSUFFICIENT_RESOURCES;
    ListCell = HvAllocateCell(Hive, Count * sizeof(HCELL_INDEX), StorageType, BigCell);
    if (ListCell == HCELL_NIL)
    {
        HvFreeCell(Hive, BigCell);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (i = 0; i < Count; i++)
    {
        Chunk = min(DataSize - i * CM_KEY_VALUE_BIG, CM_KEY_VALUE_BIG);
        Segment = HvAllocateCell(Hive, Chunk, StorageType, ListCell);
        if (Segment == HCELL_NIL)
            break;
        RtlCopyMemory(HvGetCell(Hive, Segment), (PUCHAR)Data + i * CM_KEY_VALUE_BIG, Chunk);
        HvReleaseCell(Hive, Segment);

        /* Each get of a cell is paired with its release, none is held across an allocation */
        List = (PHCELL_INDEX)HvGetCell(Hive, ListCell);
        List[i] = Segment;
        HvReleaseCell(Hive, ListCell);
    }
    if (i < Count)
    {
        List = (PHCELL_INDEX)HvGetCell(Hive, ListCell);
        while (i-- > 0)
            HvFreeCell(Hive, List[i]);
        HvReleaseCell(Hive, ListCell);
        HvFreeCell(Hive, ListCell);
        HvFreeCell(Hive, BigCell);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    BigData = (PCM_BIG_DATA)HvGetCell(Hive, BigCell);
    BigData->Signature = CM_BIG_DATA_SIGNATURE;
    BigData->Count = (USHORT)Count;
    BigData->List = ListCell;
    HvReleaseCell(Hive, BigCell);

    *DataCell = BigCell;
    return STATUS_SUCCESS;
}

/* FUNCTIONS *****************************************************************/

BOOLEAN
NTAPI
CmpMarkValueDataDirty(IN PHHIVE Hive,
                      IN PCM_KEY_VALUE Value)
{
    ULONG KeySize;
    PAGED_CODE();

    /* Make sure there's actually any data */
    if (Value->Data != HCELL_NIL)
    {
        /* If this is a small key, there's no need to have it dirty */
        if (CmpIsKeyValueSmall(&KeySize, Value->DataLength)) return TRUE;

        /* Big data: every cell of the chain */
        if (CmpIsBigValueData(Hive, Value->Data, KeySize))
            return CmpMarkBigDataDirty(Hive, Value->Data);

        /* Normal value, just mark it dirty */
        HvMarkCellDirty(Hive, Value->Data, FALSE);
    }

    /* Operation complete */
    return TRUE;
}

BOOLEAN
NTAPI
CmpFreeValueData(IN PHHIVE Hive,
                 IN HCELL_INDEX DataCell,
                 IN ULONG DataLength)
{
    ULONG KeySize;
    PAGED_CODE();

    /* If this is a small key, the data is built-in */
    if (!CmpIsKeyValueSmall(&KeySize, DataLength))
    {
        /* If there's no data cell, there's nothing to do */
        if (DataCell == HCELL_NIL) return TRUE;

        /* Make sure the data cell is allocated */
        //ASSERT(HvIsCellAllocated(Hive, DataCell));

        /* Big data: the segments, the list and the 'db' cell */
        if (CmpIsBigValueData(Hive, DataCell, KeySize))
        {
            CmpFreeBigData(Hive, DataCell);
            return TRUE;
        }

        /* Normal value, just free the data cell */
        HvFreeCell(Hive, DataCell);
    }

    /* Operation complete */
    return TRUE;
}

BOOLEAN
NTAPI
CmpFreeValue(IN PHHIVE Hive,
             IN HCELL_INDEX Cell)
{
    PCM_KEY_VALUE Value;
    PAGED_CODE();

    /* Get the cell data */
    Value = (PCM_KEY_VALUE)HvGetCell(Hive, Cell);
    if (!Value) ASSERT(FALSE);

    /* Free it */
    if (!CmpFreeValueData(Hive, Value->Data, Value->DataLength))
    {
        /* We failed to free the data, return failure */
        HvReleaseCell(Hive, Cell);
        return FALSE;
    }

    /* Release the cell and free it */
    HvReleaseCell(Hive, Cell);
    HvFreeCell(Hive, Cell);
    return TRUE;
}

HCELL_INDEX
NTAPI
CmpFindValueByName(IN PHHIVE Hive,
                   IN PCM_KEY_NODE KeyNode,
                   IN PCUNICODE_STRING Name)
{
    HCELL_INDEX CellIndex;

    /* Call the main function */
    if (!CmpFindNameInList(Hive,
                           &KeyNode->ValueList,
                           Name,
                           NULL,
                           &CellIndex))
    {
        /* Sanity check */
        ASSERT(CellIndex == HCELL_NIL);
    }

    /* Return the index */
    return CellIndex;
}

/*
 * The data of a value. Big data is copied into a buffer from Hive->Allocate
 * (*BufferAllocated = TRUE: the caller frees it with Hive->Free or CmpFree);
 * other data is returned in place, in the value cell or in its data cell
 * (*CellToRelease, to be released by the caller). A value without data
 * (DataLength 0) gives a pointer to its Data field: no cell is read for it, a
 * hive may hold none (Data = HCELL_NIL).
 */
BOOLEAN
NTAPI
CmpGetValueData(IN PHHIVE Hive,
                IN PCM_KEY_VALUE Value,
                OUT PULONG Length,
                OUT PVOID *Buffer,
                OUT PBOOLEAN BufferAllocated,
                OUT PHCELL_INDEX CellToRelease)
{
    PVOID Data;

    PAGED_CODE();

    /* Sanity check */
    ASSERT(Value->Signature == CM_KEY_VALUE_SIGNATURE);

    /* Set failure defaults */
    *BufferAllocated = FALSE;
    *Buffer = NULL;
    *CellToRelease = HCELL_NIL;

    /* Check if this is a small key */
    if (CmpIsKeyValueSmall(Length, Value->DataLength))
    {
        /* Return the data immediately */
        *Buffer = &Value->Data;
        return TRUE;
    }

    /* No data: nothing to read (a hive may hold no data cell for it, Data = HCELL_NIL) */
    if (*Length == 0)
    {
        *Buffer = &Value->Data;
        return TRUE;
    }

    /* Big data: the segments are put together in a buffer */
    if (CmpIsBigValueData(Hive, Value->Data, *Length))
    {
        if (!Hive->Allocate)
            return FALSE;
        Data = Hive->Allocate(*Length, TRUE, TAG_CM);
        if (!Data)
            return FALSE;
        if (!CmpReadBigData(Hive, Value->Data, *Length, Data))
        {
            Hive->Free(Data, 0);
            return FALSE;
        }
        *Buffer = Data;
        *BufferAllocated = TRUE;
        return TRUE;
    }

    /* Get the data from the cell */
    *Buffer = HvGetCell(Hive, Value->Data);
    if (!(*Buffer)) return FALSE;

    /* Return success and the cell to be released */
    *CellToRelease = Value->Data;
    return TRUE;
}

/*
 * The data of a value in place, for the readers of flat hives at boot (the
 * boot loader, cmboot.c, cmcontrl.c), which need no big data: a value whose
 * data is big data gives NULL (as a value that cannot be read), without a
 * buffer being allocated.
 */
PCELL_DATA
NTAPI
CmpValueToData(IN PHHIVE Hive,
               IN PCM_KEY_VALUE Value,
               OUT PULONG Length)
{
    PCELL_DATA Buffer;
    BOOLEAN BufferAllocated;
    HCELL_INDEX CellToRelease;
    PAGED_CODE();

    /* Sanity check */
    ASSERT(Hive->ReleaseCellRoutine == NULL);

    /* Big data is not read here */
    if (!CmpIsKeyValueSmall(Length, Value->DataLength) &&
        CmpIsBigValueData(Hive, Value->Data, *Length))
    {
        DPRINT1("Value 0x%p: big data (%lu bytes) is not read at boot\n", Value, (unsigned long)*Length);
        return NULL;
    }

    /* Get the actual data */
    if (!CmpGetValueData(Hive,
                         Value,
                         Length,
                         (PVOID*)&Buffer,
                         &BufferAllocated,
                         &CellToRelease))
    {
        /* We failed */
        ASSERT(BufferAllocated == FALSE);
        ASSERT(Buffer == NULL);
        return NULL;
    }

    /* Not reached (big data was refused above); a buffer is not data in place */
    if (BufferAllocated)
    {
        Hive->Free(Buffer, 0);
        return NULL;
    }

    /* Otherwise, return the cell data */
    return Buffer;
}

NTSTATUS
NTAPI
CmpAddValueToList(IN PHHIVE Hive,
                  IN HCELL_INDEX ValueCell,
                  IN ULONG Index,
                  IN HSTORAGE_TYPE StorageType,
                  IN OUT PCHILD_LIST ChildList)
{
    HCELL_INDEX ListCell;
    ULONG ChildCount, Length, i;
    PCELL_DATA CellData;
    PAGED_CODE();

    /* Sanity check */
    ASSERT((((LONG)Index) >= 0) && (Index <= ChildList->Count));

    /* Get the number of entries in the child list */
    ChildCount = ChildList->Count;
    ChildCount++;
    if (ChildCount > 1)
    {
        ASSERT(ChildList->List != HCELL_NIL);

        /* The cell should be dirty at this point */
        ASSERT(HvIsCellDirty(Hive, ChildList->List));

        /* Check if we have less then 100 children */
        if (ChildCount < 100)
        {
            /* Allocate just enough as requested */
            Length = ChildCount * sizeof(HCELL_INDEX);
        }
        else
        {
            /* Otherwise, we have quite a few, so allocate a batch */
            Length = ROUND_UP(ChildCount, 100) * sizeof(HCELL_INDEX);
            if (Length > HBLOCK_SIZE)
            {
                /* But make sure we don't allocate beyond our block size */
                Length = ROUND_UP(Length, HBLOCK_SIZE);
            }
        }

        /* Perform the allocation */
        ListCell = HvReallocateCell(Hive, ChildList->List, Length);
    }
    else
    {
        /* This is our first child, so allocate a single cell */
        ASSERT(ChildList->List == HCELL_NIL);
        ListCell = HvAllocateCell(Hive, sizeof(HCELL_INDEX), StorageType, HCELL_NIL);
    }

    /* Fail if we couldn't get a cell */
    if (ListCell == HCELL_NIL) return STATUS_INSUFFICIENT_RESOURCES;

    /* Set this cell as the child list's list cell */
    ChildList->List = ListCell;

    /* Get the actual key list memory */
    CellData = HvGetCell(Hive, ListCell);
    ASSERT(CellData != NULL);

    /* Loop all the children */
    for (i = ChildCount - 1; i > Index; i--)
    {
        /* Move them all down */
        CellData->u.KeyList[i] = CellData->u.KeyList[i - 1];
    }

    /* Insert us on top now */
    CellData->u.KeyList[Index] = ValueCell;
    ChildList->Count = ChildCount;

    /* Release the list cell and make sure the value cell is dirty */
    HvReleaseCell(Hive, ListCell);
    ASSERT(HvIsCellDirty(Hive, ValueCell));

    /* We're done here */
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
CmpSetValueDataNew(IN PHHIVE Hive,
                   IN PVOID Data,
                   IN ULONG DataSize,
                   IN HSTORAGE_TYPE StorageType,
                   IN HCELL_INDEX ValueCell,
                   OUT PHCELL_INDEX DataCell)
{
    PCELL_DATA CellData;
    PAGED_CODE();
    ASSERT(DataSize > CM_KEY_VALUE_SMALL);
    UNREFERENCED_PARAMETER(ValueCell);

    /* What the hive's format holds as big data is stored so (a hive older than 1.4 never gets any) */
    if (CmpIsKeyValueBig(Hive, DataSize))
        return CmpSetBigData(Hive, Data, DataSize, StorageType, DataCell);

    /* Allocate a data cell */
    *DataCell = HvAllocateCell(Hive, DataSize, StorageType, HCELL_NIL);
    if (*DataCell == HCELL_NIL) return STATUS_INSUFFICIENT_RESOURCES;

    /* Get the actual data */
    CellData = HvGetCell(Hive, *DataCell);
    if (!CellData) ASSERT(FALSE);

    /* Copy our buffer into it */
    RtlCopyMemory(CellData, Data, DataSize);

    /* All done */
    return STATUS_SUCCESS;
}

/*
 * New data for a value that exists (NtSetValueKey on an existing name): the
 * value cell is dirty (the caller marked it). Data of up to 4 bytes goes into
 * the value cell; other data reuses the data cell when old and new data are
 * both one cell, else it is stored anew (as big data where the format wants
 * it) and the old data, a chain included, is freed only once the new data is
 * in place: on failure the value keeps its old data.
 */
NTSTATUS
NTAPI
CmpReplaceValueData(
    _In_ PHHIVE Hive,
    _Inout_ PCM_KEY_VALUE Value,
    _In_ ULONG Type,
    _In_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ HSTORAGE_TYPE StorageType,
    _In_ ULONG TempData)
{
    HCELL_INDEX DataCell, NewCell;
    PCELL_DATA CellData;
    ULONG Length;
    BOOLEAN WasSmall;
    NTSTATUS Status;

    PAGED_CODE();

    /* See if this is a small or normal key */
    WasSmall = CmpIsKeyValueSmall(&Length, Value->DataLength);

    /* Mark the old value dirty (every cell of a chain) */
    if (!CmpMarkValueDataDirty(Hive, Value)) return STATUS_NO_LOG_SPACE;

    /* Check if we have a small key */
    if (DataSize <= CM_KEY_VALUE_SMALL)
    {
        /* Free the previous data, if it was in cells */
        if (!WasSmall) CmpFreeValueData(Hive, Value->Data, Value->DataLength);

        /* Write our data directly */
        Value->DataLength = DataSize + CM_KEY_VALUE_SPECIAL_SIZE;
        Value->Data = TempData;
        Value->Type = Type;
        return STATUS_SUCCESS;
    }

    /* Old and new data in one cell each: the old cell is reused or grown */
    if (!WasSmall && (Length > 0) && (Value->Data != HCELL_NIL) &&
        !CmpIsBigValueData(Hive, Value->Data, Length) &&
        !CmpIsKeyValueBig(Hive, DataSize))
    {
        /* Get the current data cell and actual data inside it */
        DataCell = Value->Data;
        CellData = HvGetCell(Hive, DataCell);
        if (!CellData) return STATUS_INSUFFICIENT_RESOURCES;

        /* Immediately release the cell */
        HvReleaseCell(Hive, DataCell);

        /* Make sure that the data cell actually has a size */
        ASSERT(HvGetCellSize(Hive, CellData) > 0);

        /* Check if the previous data cell could fit our new data */
        if (DataSize <= (ULONG)(HvGetCellSize(Hive, CellData)))
        {
            /* Re-use it then */
            NewCell = DataCell;
        }
        else
        {
            /* Otherwise, re-allocate the current data cell */
            NewCell = HvReallocateCell(Hive, DataCell, DataSize);
            if (NewCell == HCELL_NIL) return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Now get the actual data for our data cell */
        CellData = HvGetCell(Hive, NewCell);
        ASSERT(CellData);

        /* Release it immediately */
        HvReleaseCell(Hive, NewCell);

        /* Copy our data into the data cell's buffer */
        RtlCopyMemory(CellData, Data, DataSize);
    }
    else
    {
        /* New cells (big data in a 1.4+ hive), then the old data goes */
        Status = CmpSetValueDataNew(Hive, Data, DataSize, StorageType, HCELL_NIL, &NewCell);
        if (!NT_SUCCESS(Status)) return Status;
        if (!WasSmall) CmpFreeValueData(Hive, Value->Data, Value->DataLength);
    }

    /* Set up the value */
    Value->Data = NewCell;
    Value->DataLength = DataSize;
    Value->Type = Type;

    /* Return success */
    ASSERT(HvIsCellDirty(Hive, NewCell));
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
CmpRemoveValueFromList(IN PHHIVE Hive,
                       IN ULONG Index,
                       IN OUT PCHILD_LIST ChildList)
{
    ULONG Count;
    PCELL_DATA CellData;
    HCELL_INDEX NewCell;
    PAGED_CODE();

    /* Sanity check */
    ASSERT((((LONG)Index) >= 0) && (Index <= ChildList->Count));

    /* Get the new count after removal */
    Count = ChildList->Count - 1;
    if (Count > 0)
    {
        /* Get the actual list array */
        CellData = HvGetCell(Hive, ChildList->List);
        if (!CellData) return STATUS_INSUFFICIENT_RESOURCES;

        /* Make sure cells data have been made dirty */
        ASSERT(HvIsCellDirty(Hive, ChildList->List));
        ASSERT(HvIsCellDirty(Hive, CellData->u.KeyList[Index]));

        /* Loop the list */
        while (Index < Count)
        {
            /* Move everything up */
            CellData->u.KeyList[Index] = CellData->u.KeyList[Index + 1];
            Index++;
        }

        /* Re-allocate the cell for the list by decreasing the count */
        NewCell = HvReallocateCell(Hive,
                                   ChildList->List,
                                   Count * sizeof(HCELL_INDEX));
        ASSERT(NewCell != HCELL_NIL);
        HvReleaseCell(Hive,ChildList->List);

        /* Update the list cell */
        ChildList->List = NewCell;
    }
    else
    {
        /* Otherwise, we were the last entry, so free the list entirely */
        HvFreeCell(Hive, ChildList->List);
        ChildList->List = HCELL_NIL;
    }

    /* Update the child list with the new count */
    ChildList->Count = Count;
    return STATUS_SUCCESS;
}

HCELL_INDEX
NTAPI
CmpCopyCell(IN PHHIVE SourceHive,
            IN HCELL_INDEX SourceCell,
            IN PHHIVE DestinationHive,
            IN HSTORAGE_TYPE StorageType)
{
    PCELL_DATA SourceData;
    PCELL_DATA DestinationData = NULL;
    HCELL_INDEX DestinationCell = HCELL_NIL;
    LONG DataSize;

    PAGED_CODE();

    /* Get the data and the size of the source cell */
    SourceData = HvGetCell(SourceHive, SourceCell);
    DataSize = HvGetCellSize(SourceHive, SourceData);

    /* Allocate a new cell in the destination hive */
    DestinationCell = HvAllocateCell(DestinationHive,
                                     DataSize,
                                     StorageType,
                                     HCELL_NIL);
    if (DestinationCell == HCELL_NIL) goto Cleanup;

    /* Get the data of the destination cell */
    DestinationData = HvGetCell(DestinationHive, DestinationCell);

    /* Copy the data from the source cell to the destination cell */
    RtlMoveMemory(DestinationData, SourceData, DataSize);

Cleanup:

    /* Release the cells */
    if (DestinationData) HvReleaseCell(DestinationHive, DestinationCell);
    if (SourceData) HvReleaseCell(SourceHive, SourceCell);

    /* Return the destination cell index */
    return DestinationCell;
}

HCELL_INDEX
NTAPI
CmpCopyValue(IN PHHIVE SourceHive,
             IN HCELL_INDEX SourceValueCell,
             IN PHHIVE DestinationHive,
             IN HSTORAGE_TYPE StorageType)
{
    PCM_KEY_VALUE Value, NewValue;
    HCELL_INDEX NewValueCell, NewDataCell, CellToRelease;
    PCELL_DATA CellData;
    PVOID Buffer;
    ULONG SmallData;
    ULONG DataSize;
    BOOLEAN IsSmall, BufferAllocated;

    PAGED_CODE();

    /* Get the actual source data */
    Value = (PCM_KEY_VALUE)HvGetCell(SourceHive, SourceValueCell);
    if (!Value) ASSERT(FALSE);

    /* Copy the value cell body */
    NewValueCell = CmpCopyCell(SourceHive,
                               SourceValueCell,
                               DestinationHive,
                               StorageType);
    if (NewValueCell == HCELL_NIL)
    {
        /* Not enough storage space */
        goto Quit;
    }

    /* Copy the value data */
    IsSmall = CmpIsKeyValueSmall(&DataSize, Value->DataLength);
    if (DataSize == 0)
    {
        /* Nothing to copy */

        NewValue = (PCM_KEY_VALUE)HvGetCell(DestinationHive, NewValueCell);
        ASSERT(NewValue);
        NewValue->DataLength = 0;
        NewValue->Data = HCELL_NIL;
        HvReleaseCell(DestinationHive, NewValueCell);

        goto Quit;
    }

    if (DataSize <= CM_KEY_VALUE_SMALL)
    {
        if (IsSmall)
        {
            /* Small value, copy directly */
            SmallData = Value->Data;
        }
        else
        {
            /* The value is small, but was stored in a regular cell. Get the data from it. */
            CellData = HvGetCell(SourceHive, Value->Data);
            ASSERT(CellData);
            SmallData = *(PULONG)CellData;
            HvReleaseCell(SourceHive, Value->Data);
        }

        /* This is a small key, set the data directly inside */
        NewValue = (PCM_KEY_VALUE)HvGetCell(DestinationHive, NewValueCell);
        ASSERT(NewValue);
        NewValue->DataLength = DataSize + CM_KEY_VALUE_SPECIAL_SIZE;
        NewValue->Data = SmallData;
        HvReleaseCell(DestinationHive, NewValueCell);
    }
    else
    {
        if (CmpIsBigValueData(SourceHive, Value->Data, DataSize) ||
            CmpIsKeyValueBig(DestinationHive, DataSize))
        {
            /*
             * Big data in the source, or data the destination's format holds
             * as big data: read it whole and store it as the destination's
             * format wants (one cell in a hive older than 1.4).
             */
            NewDataCell = HCELL_NIL;
            if (CmpGetValueData(SourceHive, Value, &DataSize, &Buffer, &BufferAllocated, &CellToRelease))
            {
                if (!NT_SUCCESS(CmpSetValueDataNew(DestinationHive,
                                                   Buffer,
                                                   DataSize,
                                                   StorageType,
                                                   NewValueCell,
                                                   &NewDataCell)))
                {
                    NewDataCell = HCELL_NIL;
                }
                if (BufferAllocated) SourceHive->Free(Buffer, 0);
                if (CellToRelease != HCELL_NIL) HvReleaseCell(SourceHive, CellToRelease);
            }
        }
        else
        {
            /* Regular value: copy the data cell */
            NewDataCell = CmpCopyCell(SourceHive,
                                      Value->Data,
                                      DestinationHive,
                                      StorageType);
        }
        if (NewDataCell == HCELL_NIL)
        {
            /* Not enough storage space */
            HvFreeCell(DestinationHive, NewValueCell);
            NewValueCell = HCELL_NIL;
            goto Quit;
        }

        NewValue = (PCM_KEY_VALUE)HvGetCell(DestinationHive, NewValueCell);
        ASSERT(NewValue);
        NewValue->DataLength = DataSize;
        NewValue->Data = NewDataCell;
        HvReleaseCell(DestinationHive, NewValueCell);
    }

Quit:
    HvReleaseCell(SourceHive, SourceValueCell);

    /* Return the copied value body cell index */
    return NewValueCell;
}

NTSTATUS
NTAPI
CmpCopyKeyValueList(IN PHHIVE SourceHive,
                    IN PCHILD_LIST SrcValueList,
                    IN PHHIVE DestinationHive,
                    IN OUT PCHILD_LIST DestValueList,
                    IN HSTORAGE_TYPE StorageType)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCELL_DATA SrcListData = NULL, DestListData = NULL;
    HCELL_INDEX NewValue;
    ULONG Index;

    PAGED_CODE();

    /* Reset the destination value list */
    DestValueList->Count = 0;
    DestValueList->List = HCELL_NIL;

    /* Check if the list is empty */
    if (!SrcValueList->Count)
        return STATUS_SUCCESS;

    /* Get the source value list */
    SrcListData = HvGetCell(SourceHive, SrcValueList->List);
    ASSERT(SrcListData);

    /* Copy the actual values */
    for (Index = 0; Index < SrcValueList->Count; Index++)
    {
        NewValue = CmpCopyValue(SourceHive,
                                SrcListData->u.KeyList[Index],
                                DestinationHive,
                                StorageType);
        if (NewValue == HCELL_NIL)
        {
            /* Not enough storage space, stop there and cleanup afterwards */
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /* Add this value cell to the child list */
        Status = CmpAddValueToList(DestinationHive,
                                   NewValue,
                                   Index,
                                   StorageType,
                                   DestValueList);
        if (!NT_SUCCESS(Status))
        {
            /* Not enough storage space, stop there */

            /* Cleanup the newly-created value here, the other ones will be cleaned up afterwards */
            if (!CmpFreeValue(DestinationHive, NewValue))
                HvFreeCell(DestinationHive, NewValue);
            break;
        }
    }

    /* Revert-cleanup if failure */
    if (!NT_SUCCESS(Status) && (DestValueList->List != HCELL_NIL))
    {
        /* Do not use CmpRemoveValueFromList but directly delete the data */

        /* Get the destination value list */
        DestListData = HvGetCell(DestinationHive, DestValueList->List);
        ASSERT(DestListData);

        /* Delete each copied value */
        while (Index--)
        {
            NewValue = DestListData->u.KeyList[Index];
            if (!CmpFreeValue(DestinationHive, NewValue))
                HvFreeCell(DestinationHive, NewValue);
        }

        /* Release and free the list */
        HvReleaseCell(DestinationHive, DestValueList->List);
        HvFreeCell(DestinationHive, DestValueList->List);

        DestValueList->Count = 0;
        DestValueList->List = HCELL_NIL;
    }

    /* Release the cells */
    HvReleaseCell(SourceHive, SrcValueList->List);

    return Status;
}
