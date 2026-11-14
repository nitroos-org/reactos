/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/config/cmkcbncb.c
 * PURPOSE:         Routines for handling KCBs, NCBs, as well as key hashes.
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

ULONG CmpHashTableSize = 2048;
PCM_KEY_HASH_TABLE_ENTRY CmpCacheTable;
PCM_NAME_HASH_TABLE_ENTRY CmpNameCacheTable;

/* FUNCTIONS *****************************************************************/

CODE_SEG("INIT")
VOID
NTAPI
CmpInitializeCache(VOID)
{
    ULONG Length, i;

    /* Calculate length for the table */
    Length = CmpHashTableSize * sizeof(CM_KEY_HASH_TABLE_ENTRY);

    /* Allocate it */
    CmpCacheTable = CmpAllocate(Length, TRUE, TAG_CM);
    if (!CmpCacheTable)
    {
        /* Take the system down */
        KeBugCheckEx(CONFIG_INITIALIZATION_FAILED, 3, 1, 0, 0);
    }

    /* Zero out the table */
    RtlZeroMemory(CmpCacheTable, Length);

    /* Initialize the locks */
    for (i = 0;i < CmpHashTableSize; i++)
    {
        /* Setup the pushlock */
        ExInitializePushLock(&CmpCacheTable[i].Lock);
    }

    /* Calculate length for the name cache */
    Length = CmpHashTableSize * sizeof(CM_NAME_HASH_TABLE_ENTRY);

    /* Now allocate the name cache table */
    CmpNameCacheTable = CmpAllocate(Length, TRUE, TAG_CM);
    if (!CmpNameCacheTable)
    {
        /* Take the system down */
        KeBugCheckEx(CONFIG_INITIALIZATION_FAILED, 3, 3, 0, 0);
    }

    /* Zero out the table */
    RtlZeroMemory(CmpNameCacheTable, Length);

    /* Initialize the locks */
    for (i = 0;i < CmpHashTableSize; i++)
    {
        /* Setup the pushlock */
        ExInitializePushLock(&CmpNameCacheTable[i].Lock);
    }

    /*
     * The delayed close size is registry-tunable but is stored in the
     * 12-bit KCB DelayedCloseIndex field: clamp it so it never truncates.
     */
    if (CmpDelayedCloseSize > CM_KCB_MAX_DELAYED_CLOSE_SIZE)
    {
        CmpDelayedCloseSize = CM_KCB_MAX_DELAYED_CLOSE_SIZE;
    }

    /* Setup the delayed close table */
    CmpInitializeDelayedCloseTable();
}

VOID
NTAPI
CmpRemoveKeyHash(IN PCM_KEY_HASH KeyHash)
{
    PCM_KEY_HASH *Prev;
    PCM_KEY_HASH Current;
    ASSERT_VALID_HASH(KeyHash);

    /* Lookup all the keys in this index entry */
    Prev = &GET_HASH_ENTRY(CmpCacheTable, KeyHash->ConvKey)->Entry;
    while (TRUE)
    {
        /* Save the current one and make sure it's valid */
        Current = *Prev;
        ASSERT(Current != NULL);
        ASSERT_VALID_HASH(Current);

        /* Check if it matches */
        if (Current == KeyHash)
        {
            /* Then write the previous one */
            *Prev = Current->NextHash;
            if (*Prev) ASSERT_VALID_HASH(*Prev);
            break;
        }

        /* Otherwise, keep going */
        Prev = &Current->NextHash;
    }
}

PCM_KEY_CONTROL_BLOCK
NTAPI
CmpInsertKeyHash(IN PCM_KEY_HASH KeyHash,
                 IN BOOLEAN IsFake)
{
    ULONG i;
    PCM_KEY_HASH Entry;
    ASSERT_VALID_HASH(KeyHash);

    /* Get the hash index */
    i = GET_HASH_INDEX(KeyHash->ConvKey);

    /* If this is a fake key, increase the key cell to use the parent data */
    if (IsFake) KeyHash->KeyCell++;

    /* Loop the hash table */
    Entry = CmpCacheTable[i].Entry;
    while (Entry)
    {
        /* Check if this matches */
        ASSERT_VALID_HASH(Entry);
        if ((KeyHash->ConvKey == Entry->ConvKey) &&
            (KeyHash->KeyCell == Entry->KeyCell) &&
            (KeyHash->KeyHive == Entry->KeyHive))
        {
            /* Return it */
            return CONTAINING_RECORD(Entry, CM_KEY_CONTROL_BLOCK, KeyHash);
        }

        /* Keep looping */
        Entry = Entry->NextHash;
    }

    /* No entry found, add this one and return NULL since none existed */
    KeyHash->NextHash = CmpCacheTable[i].Entry;
    CmpCacheTable[i].Entry = KeyHash;
    return NULL;
}

PCM_NAME_CONTROL_BLOCK
NTAPI
CmpGetNameControlBlock(IN PUNICODE_STRING NodeName)
{
    PCM_NAME_CONTROL_BLOCK Ncb = NULL;
    ULONG ConvKey = 0;
    PWCHAR p, pp;
    ULONG i;
    BOOLEAN IsCompressed = TRUE, Found = FALSE;
    PCM_NAME_HASH HashEntry;
    ULONG NcbSize;
    USHORT Length;

    /* Loop the name */
    p = NodeName->Buffer;
    for (i = 0; i < NodeName->Length; i += sizeof(WCHAR))
    {
        /* Make sure it's not a slash */
        if (*p != OBJ_NAME_PATH_SEPARATOR)
        {
            /* Add it to the hash */
            ConvKey = COMPUTE_HASH_CHAR(ConvKey, *p);
        }

        /* Next character */
        p++;
    }

    /* Set assumed lengh and loop to check */
    Length = NodeName->Length / sizeof(WCHAR);
    for (i = 0; i < (NodeName->Length / sizeof(WCHAR)); i++)
    {
        /* Check if this is a 16-bit character */
        if (NodeName->Buffer[i] > (UCHAR)-1)
        {
            /* This is the actual size, and we know we're not compressed */
            Length = NodeName->Length;
            IsCompressed = FALSE;
            break;
        }
    }

    /* Lock the NCB entry */
    CmpAcquireNcbLockExclusiveByKey(ConvKey);

    /* Get the hash entry */
    HashEntry = GET_HASH_ENTRY(CmpNameCacheTable, ConvKey)->Entry;
    while (HashEntry)
    {
        /* Get the current NCB */
        Ncb = CONTAINING_RECORD(HashEntry, CM_NAME_CONTROL_BLOCK, NameHash);

        /* Check if the hash matches */
        if ((ConvKey == HashEntry->ConvKey) && (Length == Ncb->NameLength))
        {
            /* Assume success */
            Found = TRUE;

            /* If the NCB is compressed, do a compressed name compare */
            if (Ncb->Compressed)
            {
                /* Compare names */
                if (CmpCompareCompressedName(NodeName, Ncb->Name, Length))
                {
                    /* We failed */
                    Found = FALSE;
                }
            }
            else
            {
                /* Do a manual compare */
                p = NodeName->Buffer;
                pp = Ncb->Name;
                for (i = 0; i < Ncb->NameLength; i += sizeof(WCHAR))
                {
                    /* Compare the character */
                    if (RtlUpcaseUnicodeChar(*p) != RtlUpcaseUnicodeChar(*pp))
                    {
                        /* Failed */
                        Found = FALSE;
                        break;
                    }

                    /* Next chars */
                    p++;
                    pp++;
                }
            }

            /* Check if we found a name */
            if (Found)
            {
                /*
                 * One NCB is shared by every KCB with this name, under any
                 * parent and in any hive, so its count is not bounded by
                 * the 16-bit KCB reference limit. Refuse rather than wrap:
                 * a wrapped count frees the NCB while KCBs still use it.
                 */
                if (Ncb->RefCount == MAXULONG)
                {
                    CmpReleaseNcbLockByKey(ConvKey);
                    return NULL;
                }

                /* Reference it */
                Ncb->RefCount++;
                break;
            }
        }

        /* Go to the next hash */
        HashEntry = HashEntry->NextHash;
    }

    /* Check if we didn't find it */
    if (!Found)
    {
        /* Allocate one */
        NcbSize = FIELD_OFFSET(CM_NAME_CONTROL_BLOCK, Name) + Length;
        Ncb = CmpAllocate(NcbSize, TRUE, TAG_CM);
        if (!Ncb)
        {
            /* Release the lock and fail */
            CmpReleaseNcbLockByKey(ConvKey);
            return NULL;
        }

        /* Clear it out */
        RtlZeroMemory(Ncb, NcbSize);

        /* Check if the name was compressed */
        if (IsCompressed)
        {
            /* Copy the compressed name */
            for (i = 0; i < NodeName->Length / sizeof(WCHAR); i++)
            {
                /* Copy Unicode to ANSI */
                ((PCHAR)Ncb->Name)[i] = (CHAR)RtlUpcaseUnicodeChar(NodeName->Buffer[i]);
            }
        }
        else
        {
            /* Copy the name directly */
            for (i = 0; i < NodeName->Length / sizeof(WCHAR); i++)
            {
                /* Copy each unicode character */
                Ncb->Name[i] = RtlUpcaseUnicodeChar(NodeName->Buffer[i]);
            }
        }

        /* Setup the rest of the NCB */
        Ncb->Compressed = IsCompressed;
        Ncb->ConvKey = ConvKey;
        Ncb->RefCount++;
        Ncb->NameLength = Length;

        /* Insert the name in the hash table */
        HashEntry = &Ncb->NameHash;
        HashEntry->NextHash = GET_HASH_ENTRY(CmpNameCacheTable, ConvKey)->Entry;
        GET_HASH_ENTRY(CmpNameCacheTable, ConvKey)->Entry = HashEntry;
    }

    /* Release NCB lock */
    CmpReleaseNcbLockByKey(ConvKey);

    /* Return the NCB found */
    return Ncb;
}

VOID
NTAPI
CmpRemoveKeyControlBlock(IN PCM_KEY_CONTROL_BLOCK Kcb)
{
    /* Make sure we have the exclusive lock */
    CMP_ASSERT_KCB_LOCK(Kcb);

    /* Remove the key hash */
    CmpRemoveKeyHash(&Kcb->KeyHash);
}

VOID
NTAPI
CmpDereferenceNameControlBlockWithLock(IN PCM_NAME_CONTROL_BLOCK Ncb)
{
    PCM_NAME_HASH Current, *Next;
    ULONG ConvKey = Ncb->ConvKey;

    /* Lock the NCB */
    CmpAcquireNcbLockExclusiveByKey(ConvKey);

    /* Decrease the reference count */
    ASSERT(Ncb->RefCount >= 1);
    if (!(--Ncb->RefCount))
    {
        /* Find the NCB in the table */
        Next = &GET_HASH_ENTRY(CmpNameCacheTable, Ncb->ConvKey)->Entry;
        while (TRUE)
        {
            /* Check the current entry */
            Current = *Next;
            ASSERT(Current != NULL);
            if (Current == &Ncb->NameHash)
            {
                /* Unlink it */
                *Next = Current->NextHash;
                break;
            }

            /* Get to the next one */
            Next = &Current->NextHash;
        }

        /* Found it, now free it */
        CmpFree(Ncb, 0);
    }

    /* Release the lock */
    CmpReleaseNcbLockByKey(ConvKey);
}

BOOLEAN
NTAPI
CmpReferenceKeyControlBlock(IN PCM_KEY_CONTROL_BLOCK Kcb)
{
    CMTRACE(CM_REFERENCE_DEBUG,
            "%s - Referencing KCB: %p\n", __FUNCTION__, Kcb);

    /* Check if this is the KCB's first reference */
    if (Kcb->RefCount == 0)
    {
        /* Check if the KCB is locked in shared mode */
        if (!CmpIsKcbLockedExclusive(Kcb))
        {
            /* Convert it to exclusive */
            if (!CmpTryToConvertKcbSharedToExclusive(Kcb))
            {
                /* Set the delayed close index so that we can be ignored */
                Kcb->DelayedCloseIndex = 1;

                /* Increase the reference count while we release the lock */
                InterlockedIncrement((PLONG)&Kcb->RefCount);

                /* Go from shared to exclusive */
                CmpConvertKcbSharedToExclusive(Kcb);

                /* Decrement the reference count; the lock is now held again */
                InterlockedDecrement((PLONG)&Kcb->RefCount);

                /* Check if we still control the index */
                if (Kcb->DelayedCloseIndex == 1)
                {
                    /* Reset it */
                    Kcb->DelayedCloseIndex = 0;
                }
                else
                {
                    /* Sanity check */
                    ASSERT((Kcb->DelayedCloseIndex == CmpDelayedCloseSize) ||
                           (Kcb->DelayedCloseIndex == 0));
                }
            }
        }
    }

    /* Increase the reference count */
    if ((InterlockedIncrement((PLONG)&Kcb->RefCount) & 0xFFFF) == 0)
    {
        /* We've overflown to 64K references, bail out */
        InterlockedDecrement((PLONG)&Kcb->RefCount);
        return FALSE;
    }

    /* Check if this was the last close index */
    if (!Kcb->DelayedCloseIndex)
    {
        /* Check if the KCB is locked in shared mode */
        if (!CmpIsKcbLockedExclusive(Kcb))
        {
            /* Convert it to exclusive */
            if (!CmpTryToConvertKcbSharedToExclusive(Kcb))
            {
                /* Go from shared to exclusive */
                CmpConvertKcbSharedToExclusive(Kcb);
            }
        }

        /* If we're still the last entry, remove us */
        if (!Kcb->DelayedCloseIndex) CmpRemoveFromDelayedClose(Kcb);
    }

    /* Return success */
    return TRUE;
}

VOID
NTAPI
CmpCleanUpKcbValueCache(IN PCM_KEY_CONTROL_BLOCK Kcb)
{
    PULONG_PTR CachedList;
    ULONG i;

    /* Make sure we have the exclusive lock */
    CMP_ASSERT_KCB_LOCK(Kcb);

    /* Check if the value list is cached */
    if (CMP_IS_CELL_CACHED(Kcb->ValueCache.ValueList))
    {
        /* Get the cache list */
        CachedList = (PULONG_PTR)CMP_GET_CACHED_DATA(Kcb->ValueCache.ValueList);
        for (i = 0; i < Kcb->ValueCache.Count; i++)
        {
            /* Check if this cell is cached */
            if (CMP_IS_CELL_CACHED(CachedList[i]))
            {
                /* Free it */
                CmpFree((PVOID)CMP_GET_CACHED_CELL(CachedList[i]), 0);
            }
        }

        /* Now free the list */
        CmpFree((PVOID)CMP_GET_CACHED_CELL(Kcb->ValueCache.ValueList), 0);
        Kcb->ValueCache.ValueList = HCELL_NIL;
    }
    else if (Kcb->ExtFlags & CM_KCB_SYM_LINK_FOUND)
    {
        /* This is a sym link, check if there's only one reference left */
        if ((Kcb->ValueCache.RealKcb->RefCount == 1) &&
            !(Kcb->ValueCache.RealKcb->Delete))
        {
            /* Disable delay close for the KCB */
            Kcb->ValueCache.RealKcb->ExtFlags |= CM_KCB_NO_DELAY_CLOSE;
        }

        /* Dereference the KCB */
        CmpDelayDerefKeyControlBlock(Kcb->ValueCache.RealKcb);
        Kcb->ExtFlags &= ~CM_KCB_SYM_LINK_FOUND;
    }
}

VOID
NTAPI
CmpCleanUpKcbCacheWithLock(IN PCM_KEY_CONTROL_BLOCK Kcb,
                           IN BOOLEAN LockHeldExclusively)
{
    PCM_KEY_CONTROL_BLOCK Parent;
    PAGED_CODE();

    /* Sanity checks */
    CMP_ASSERT_KCB_LOCK(Kcb);
    ASSERT(Kcb->RefCount == 0);

    /* Cleanup the value cache */
    CmpCleanUpKcbValueCache(Kcb);

    /* Dereference the NCB */
    CmpDereferenceNameControlBlockWithLock(Kcb->NameBlock);

    /* Check if we have an index hint block and free it */
    if (Kcb->ExtFlags & CM_KCB_SUBKEY_HINT) CmpFree(Kcb->IndexHint, 0);

    /* Check if we were already deleted */
    Parent = Kcb->ParentKcb;
    if (!Kcb->Delete) CmpRemoveKeyControlBlock(Kcb);

    /* Set invalid KCB signature */
    Kcb->Signature = CM_KCB_INVALID_SIGNATURE;

    /* Free the KCB as well */
    CmpFreeKeyControlBlock(Kcb);

    /* Check if we have a parent */
    if (Parent)
    {
        /* Dereference the parent */
        LockHeldExclusively ?
            CmpDereferenceKeyControlBlockWithLock(Parent,LockHeldExclusively) :
            CmpDelayDerefKeyControlBlock(Parent);
    }
}

VOID
NTAPI
CmpCleanUpSubKeyInfo(IN PCM_KEY_CONTROL_BLOCK Kcb)
{
    PCM_KEY_NODE KeyNode;

    /* Make sure we have the exclusive lock */
    CMP_ASSERT_KCB_LOCK(Kcb);

    /* Check if there's any cached subkey */
    if (Kcb->ExtFlags & (CM_KCB_NO_SUBKEY | CM_KCB_SUBKEY_ONE | CM_KCB_SUBKEY_HINT))
    {
        /* Check if there's a hint */
        if (Kcb->ExtFlags & (CM_KCB_SUBKEY_HINT))
        {
            /* Kill it */
            CmpFree(Kcb->IndexHint, 0);
        }

        /* Remove subkey flags */
        Kcb->ExtFlags &= ~(CM_KCB_NO_SUBKEY | CM_KCB_SUBKEY_ONE | CM_KCB_SUBKEY_HINT);
    }

    /* Check if there's no linked cell */
    if (Kcb->KeyCell == HCELL_NIL)
    {
        /* Make sure it's a delete */
        ASSERT(Kcb->Delete);
        KeyNode = NULL;
    }
    else
    {
        /* Get the key node */
        KeyNode = (PCM_KEY_NODE)HvGetCell(Kcb->KeyHive, Kcb->KeyCell);
    }

    /* Check if we got the node */
    if (!KeyNode)
    {
        /* We didn't, mark the cached data invalid */
        Kcb->ExtFlags |= CM_KCB_INVALID_CACHED_INFO;
    }
    else
    {
        /* We have a keynode, update subkey counts */
        Kcb->ExtFlags &= ~CM_KCB_INVALID_CACHED_INFO;
        Kcb->SubKeyCount = KeyNode->SubKeyCounts[Stable] +
                           KeyNode->SubKeyCounts[Volatile];

        /* Release the cell */
        HvReleaseCell(Kcb->KeyHive, Kcb->KeyCell);
    }
}

VOID
NTAPI
CmpDereferenceKeyControlBlock(IN PCM_KEY_CONTROL_BLOCK Kcb)
{
    LONG OldRefCount, NewRefCount;
    ULONG ConvKey;
    CMTRACE(CM_REFERENCE_DEBUG,
            "%s - Dereferencing KCB: %p\n", __FUNCTION__, Kcb);

    /* Get the ref count and update it */
    OldRefCount = *(PLONG)&Kcb->RefCount;
    NewRefCount = OldRefCount - 1;

    /* Check if we still have references */
    if ((NewRefCount & 0xFFFF) > 0)
    {
        /* Do the dereference */
        if (InterlockedCompareExchange((PLONG)&Kcb->RefCount,
                                       NewRefCount,
                                       OldRefCount) == OldRefCount)
        {
            /* We'de done */
            return;
        }
    }

    /* Save the key */
    ConvKey = Kcb->ConvKey;

    /* Do the dereference inside the lock */
    CmpAcquireKcbLockExclusive(Kcb);
    CmpDereferenceKeyControlBlockWithLock(Kcb, FALSE);
    CmpReleaseKcbLockByKey(ConvKey);
}

VOID
NTAPI
CmpDereferenceKeyControlBlockWithLock(IN PCM_KEY_CONTROL_BLOCK Kcb,
                                      IN BOOLEAN LockHeldExclusively)
{
    CMTRACE(CM_REFERENCE_DEBUG,
            "%s - Dereferencing KCB: %p\n", __FUNCTION__, Kcb);

    /* Sanity check */
    ASSERT_KCB_VALID(Kcb);

    /* Check if this is the last reference */
    if ((InterlockedDecrement((PLONG)&Kcb->RefCount) & 0xFFFF) == 0)
    {
        /* Make sure we have the exclusive lock */
        CMP_ASSERT_KCB_LOCK(Kcb);

        /* Check if we should do a direct delete */
        if ((CmpHoldLazyFlush &&
             !(Kcb->ExtFlags & CM_KCB_SYM_LINK_FOUND) &&
             !(Kcb->Flags & KEY_SYM_LINK)) ||
            (Kcb->ExtFlags & CM_KCB_NO_DELAY_CLOSE) ||
             Kcb->Delete)
        {
            /* Clean up the KCB*/
            CmpCleanUpKcbCacheWithLock(Kcb, LockHeldExclusively);
        }
        else
        {
            /* Otherwise, use delayed close */
            CmpAddToDelayedClose(Kcb, LockHeldExclusively);
        }
    }
}

VOID
NTAPI
InitializeKCBKeyBodyList(IN PCM_KEY_CONTROL_BLOCK Kcb)
{
    /* Initialize the list */
    InitializeListHead(&Kcb->KeyBodyListHead);

    /* Clear the bodies */
    Kcb->KeyBodyArray[0] =
    Kcb->KeyBodyArray[1] =
    Kcb->KeyBodyArray[2] =
    Kcb->KeyBodyArray[3] = NULL;
}

PCM_KEY_CONTROL_BLOCK
NTAPI
CmpCreateKeyControlBlock(IN PHHIVE Hive,
                         IN HCELL_INDEX Index,
                         IN PCM_KEY_NODE Node,
                         IN PCM_KEY_CONTROL_BLOCK Parent,
                         IN ULONG Flags,
                         IN PUNICODE_STRING KeyName)
{
    PCM_KEY_CONTROL_BLOCK Kcb, FoundKcb = NULL;
    UNICODE_STRING NodeName;
    ULONG ConvKey = 0, i;
    BOOLEAN IsFake, HashLock;
    PWCHAR p;

    /* Make sure we own this hive in case it's being unloaded */
    if ((Hive->HiveFlags & HIVE_IS_UNLOADING) &&
        (((PCMHIVE)Hive)->CreatorOwner != KeGetCurrentThread()))
    {
        /* Fail */
        return NULL;
    }

    /* Check if this is a fake KCB */
    IsFake = Flags & CMP_CREATE_FAKE_KCB ? TRUE : FALSE;

    /* If we have a parent, use its ConvKey */
    if (Parent) ConvKey = Parent->ConvKey;

    /* Make a copy of the name */
    NodeName = *KeyName;

    /* Remove leading slash */
    while (NodeName.Length && (*NodeName.Buffer == OBJ_NAME_PATH_SEPARATOR))
    {
        /* Move the buffer by one */
        NodeName.Buffer++;
        NodeName.Length -= sizeof(WCHAR);
    }

    /* Make sure we didn't get just a slash or something */
    ASSERT(NodeName.Length > 0);

    /* Now setup the hash */
    p = NodeName.Buffer;
    for (i = 0; i < NodeName.Length; i += sizeof(WCHAR))
    {
        /* Make sure it's a valid character */
        if (*p != OBJ_NAME_PATH_SEPARATOR)
        {
            /* Add this key to the hash */
            ConvKey = COMPUTE_HASH_CHAR(ConvKey, *p);
        }

        /* Move on */
        p++;
    }

    /* Allocate the KCB */
    Kcb = CmpAllocateKeyControlBlock();
    if (!Kcb) return NULL;

    /* Initialize the key list */
    InitializeKCBKeyBodyList(Kcb);

    /* Set it up */
    Kcb->Signature = CM_KCB_SIGNATURE;
    Kcb->Delete = FALSE;
    Kcb->RefCount = 1;
    Kcb->KeyHive = Hive;
    Kcb->KeyCell = Index;
    Kcb->ConvKey = ConvKey;
    Kcb->DelayedCloseIndex = CmpDelayedCloseSize;
    Kcb->InDelayClose = 0;
    ASSERT_KCB_VALID(Kcb);

    /* Check if we have two hash entires */
    HashLock = Flags & CMP_LOCK_HASHES_FOR_KCB ? TRUE : FALSE;
    if (!HashLock)
    {
        /* It's not locked, do we have a parent? */
        if (Parent)
        {
            /* Lock the parent KCB and ourselves */
            CmpAcquireTwoKcbLocksExclusiveByKey(ConvKey, Parent->ConvKey);
        }
        else
        {
            /* Lock only ourselves */
            CmpAcquireKcbLockExclusive(Kcb);
        }
    }

    /* Check if we already have a KCB */
    FoundKcb = CmpInsertKeyHash(&Kcb->KeyHash, IsFake);
    if (FoundKcb)
    {
        /* Sanity check */
        ASSERT(!FoundKcb->Delete);
        Kcb->Signature = CM_KCB_INVALID_SIGNATURE;

        /* Free the one we allocated and reference this one */
        CmpFreeKeyControlBlock(Kcb);
        ASSERT_KCB_VALID(FoundKcb);
        Kcb = FoundKcb;
        if (!CmpReferenceKeyControlBlock(Kcb))
        {
            /* We got too many handles */
            ASSERT(Kcb->RefCount + 1 != 0);
            Kcb = NULL;
        }
        else
        {
            /* Check if we're not creating a fake one, but it used to be fake */
            if ((Kcb->ExtFlags & CM_KCB_KEY_NON_EXIST) && !IsFake)
            {
                /* Set the hive and cell */
                Kcb->KeyHive = Hive;
                Kcb->KeyCell = Index;

                /* This means that our current information is invalid */
                Kcb->ExtFlags = CM_KCB_INVALID_CACHED_INFO;
            }

            /* Check if we didn't have any valid data */
            if (!(Kcb->ExtFlags & (CM_KCB_NO_SUBKEY |
                                   CM_KCB_SUBKEY_ONE |
                                   CM_KCB_SUBKEY_HINT)))
            {
                /* Calculate the index hint */
                Kcb->SubKeyCount = Node->SubKeyCounts[Stable] +
                                   Node->SubKeyCounts[Volatile];

                /* Cached information is now valid */
                Kcb->ExtFlags &= ~CM_KCB_INVALID_CACHED_INFO;
            }

            /* Setup the other data */
            Kcb->KcbLastWriteTime = Node->LastWriteTime;
            Kcb->KcbMaxNameLen = (USHORT)Node->MaxNameLen;
            Kcb->KcbMaxValueNameLen = (USHORT)Node->MaxValueNameLen;
            Kcb->KcbMaxValueDataLen = Node->MaxValueDataLen;
        }
    }
    else
    {
        /* No KCB, do we have a parent? */
        if (Parent)
        {
            /* Reference the parent */
            if (((Parent->TotalLevels + 1) < 512) &&
                CmpReferenceKeyControlBlock(Parent))
            {
                /* Link it */
                Kcb->ParentKcb = Parent;
                Kcb->TotalLevels = Parent->TotalLevels + 1;
            }
            else
            {
                /* Remove the KCB and free it */
                CmpRemoveKeyControlBlock(Kcb);
                Kcb->Signature = CM_KCB_INVALID_SIGNATURE;
                CmpFreeKeyControlBlock(Kcb);
                Kcb = NULL;
            }
        }
        else
        {
            /* No parent, this is the root node */
            Kcb->ParentKcb = NULL;
            Kcb->TotalLevels = 1;
        }

        /* Check if we have a KCB */
        if (Kcb)
        {
            /* Get the NCB */
            Kcb->NameBlock = CmpGetNameControlBlock(&NodeName);
            if (Kcb->NameBlock)
            {
                /* Fill it out */
                Kcb->ValueCache.Count = Node->ValueList.Count;
                Kcb->ValueCache.ValueList = Node->ValueList.List;
                Kcb->Flags = Node->Flags;
                Kcb->ExtFlags = 0;
                Kcb->DelayedCloseIndex = CmpDelayedCloseSize;

                /* Remember if this is a fake key */
                if (IsFake) Kcb->ExtFlags |= CM_KCB_KEY_NON_EXIST;

                /* Setup the other data */
                Kcb->SubKeyCount = Node->SubKeyCounts[Stable] +
                                   Node->SubKeyCounts[Volatile];
                Kcb->KcbLastWriteTime = Node->LastWriteTime;
                Kcb->KcbMaxNameLen = (USHORT)Node->MaxNameLen;
                Kcb->KcbMaxValueNameLen = (USHORT)Node->MaxValueNameLen;
                Kcb->KcbMaxValueDataLen = Node->MaxValueDataLen;
            }
            else
            {
                /* Dereference the parent (a root key has none) */
                if (Parent)
                {
                    CmpDereferenceKeyControlBlockWithLock(Parent, FALSE);
                }

                /* Remove the KCB and free it */
                CmpRemoveKeyControlBlock(Kcb);
                Kcb->Signature = CM_KCB_INVALID_SIGNATURE;
                CmpFreeKeyControlBlock(Kcb);
                Kcb = NULL;
            }
        }
    }

    /* Check if this is a KCB inside a frozen hive */
    if (Kcb && ((PCMHIVE)Hive)->Frozen && !(Kcb->Flags & KEY_SYM_LINK))
    {
        /* Don't add these to the delay close */
        Kcb->ExtFlags |= CM_KCB_NO_DELAY_CLOSE;
    }

    /* Sanity check */
    ASSERT(!Kcb || !Kcb->Delete);

    /* Check if we had locked the hashes */
    if (!HashLock)
    {
        /* We locked them manually, do we have a parent? */
        if (Parent)
        {
            /* Unlock the parent KCB and ourselves */
            CmpReleaseTwoKcbLockByKey(ConvKey, Parent->ConvKey);
        }
        else
        {
            /* Unlock only ourselves */
            CmpReleaseKcbLockByKey(ConvKey);
        }
    }

    /* Return the KCB */
    return Kcb;
}

/*
 * Copy the display name of one KCB component (ComponentLength bytes of
 * unicode) to Target. The name cache (NCB) holds the UPPERCASED name, so the
 * stored spelling is read from the key node, as Windows reports it, unless
 * UseKeyNode is FALSE (deleted key) or the KCB is a hive entry/exit, whose
 * node carries the hive's own root name rather than the mount name.
 * Returns FALSE when the key node cannot be mapped.
 */
BOOLEAN
NTAPI
CmpCopyKcbComponentName(IN PCM_KEY_CONTROL_BLOCK Kcb,
                        IN BOOLEAN UseKeyNode,
                        IN ULONG ComponentLength,
                        OUT PWCHAR Target)
{
    PCM_KEY_NODE KeyNode = NULL;
    PWSTR CurrentName;
    ULONG SourceLength;
    BOOLEAN Compressed;

    if (UseKeyNode)
    {
        KeyNode = (PCM_KEY_NODE)HvGetCell(Kcb->KeyHive, Kcb->KeyCell);
        if (!KeyNode) return FALSE;
    }

    /* The cached uppercase spelling may compress even when the live
     * spelling does not (for example U+0131 uppercases to ASCII I). Use
     * the compression flag belonging to the actual source buffer. */
    if ((Kcb->Flags & (KEY_HIVE_ENTRY | KEY_HIVE_EXIT)) || !KeyNode)
    {
        CurrentName = Kcb->NameBlock->Name;
        SourceLength = Kcb->NameBlock->NameLength;
        Compressed = Kcb->NameBlock->Compressed;
    }
    else
    {
        CurrentName = KeyNode->Name;
        SourceLength = KeyNode->NameLength;
        Compressed = (KeyNode->Flags & KEY_COMP_NAME) != 0;
    }

    if (Compressed)
    {
        CmpCopyCompressedName(Target, ComponentLength, CurrentName, SourceLength);
    }
    else
    {
        /* Never read past the source, whatever the cached length says */
        ULONG CopyLength = min(ComponentLength, SourceLength);

        RtlCopyMemory(Target, CurrentName, CopyLength);
        RtlZeroMemory((PUCHAR)Target + CopyLength, ComponentLength - CopyLength);
    }

    if (KeyNode) HvReleaseCell(Kcb->KeyHive, Kcb->KeyCell);
    return TRUE;
}

PUNICODE_STRING
NTAPI
CmpConstructName(IN PCM_KEY_CONTROL_BLOCK Kcb)
{
    PUNICODE_STRING KeyName;
    ULONG NameLength, ComponentLength;
    PCM_KEY_CONTROL_BLOCK MyKcb;
    BOOLEAN DeletedKey = FALSE;
    PWCHAR TargetBuffer;

    /* Calculate how much size our key name is going to occupy */
    NameLength = 0;
    MyKcb = Kcb;

    while (MyKcb)
    {
        /* Add length of the name */
        if (!MyKcb->NameBlock->Compressed)
        {
            NameLength += MyKcb->NameBlock->NameLength;
        }
        else
        {
            NameLength += CmpCompressedNameSize(MyKcb->NameBlock->Name,
                                                MyKcb->NameBlock->NameLength);
        }

        /* Sum up the separator too */
        NameLength += sizeof(WCHAR);

        /* UNICODE_STRING lengths are USHORT byte counts. Relative opens can
         * build an ancestry longer than any single supplied object name. */
        if (NameLength > MAXUSHORT) return NULL;

        /* Go to the parent KCB */
        MyKcb = MyKcb->ParentKcb;
    }

    /* Allocate the unicode string now */
    KeyName = CmpAllocate(NameLength + sizeof(UNICODE_STRING),
                          TRUE,
                          TAG_CM);

    if (!KeyName) return NULL;

    /* Set it up */
    KeyName->Buffer = (PWSTR)(KeyName + 1);
    KeyName->Length = NameLength;
    KeyName->MaximumLength = NameLength;

    /* Loop the keys again, now adding names */
    NameLength = 0;
    MyKcb = Kcb;

    while (MyKcb)
    {
        /* Sanity checks for deleted and fake keys */
        if ((!MyKcb->KeyCell && !MyKcb->Delete) ||
            !MyKcb->KeyHive ||
            (MyKcb->ExtFlags & CM_KCB_KEY_NON_EXIST))
        {
            /* Failure */
            CmpFree(KeyName, 0);
            return NULL;
        }

        /* Use the keynode name (the stored case) unless the key is deleted */
        if (DeletedKey || MyKcb->Delete)
            DeletedKey = TRUE;

        ComponentLength = MyKcb->NameBlock->Compressed ?
            CmpCompressedNameSize(MyKcb->NameBlock->Name, MyKcb->NameBlock->NameLength) :
            MyKcb->NameBlock->NameLength;
        NameLength += ComponentLength + sizeof(WCHAR);
        if (NameLength > KeyName->Length)
        {
            CmpFree(KeyName, 0);
            return NULL;
        }
        TargetBuffer = &KeyName->Buffer[(KeyName->Length - NameLength) / sizeof(WCHAR)];

        /* Add a separator */
        TargetBuffer[0] = OBJ_NAME_PATH_SEPARATOR;

        if (!CmpCopyKcbComponentName(MyKcb, !DeletedKey, ComponentLength, TargetBuffer + 1))
        {
            CmpFree(KeyName, 0);
            return NULL;
        }

        /* Go to the parent KCB */
        MyKcb = MyKcb->ParentKcb;
    }

    /* Return resulting buffer (both UNICODE_STRING and
       its buffer following it) */
    return KeyName;
}

VOID
NTAPI
EnlistKeyBodyWithKCB(IN PCM_KEY_BODY KeyBody,
                     IN ULONG Flags)
{
    ULONG i;

    /* Sanity check */
    ASSERT(KeyBody->KeyControlBlock != NULL);

    /* Initialize the list entry */
    InitializeListHead(&KeyBody->KeyBodyList);

    /* Check if we can use the parent KCB array */
    for (i = 0; i < 4; i++)
    {
        /* Add it into the list */
        if (!InterlockedCompareExchangePointer((PVOID*)&KeyBody->KeyControlBlock->
                                               KeyBodyArray[i],
                                               KeyBody,
                                               NULL))
        {
            /* Added */
            return;
        }
    }

    /* Array full, check if we need to unlock the KCB */
    if (Flags & CMP_ENLIST_KCB_LOCKED_SHARED)
    {
        /* It's shared, so release the KCB shared lock */
        CmpReleaseKcbLock(KeyBody->KeyControlBlock);
        ASSERT(!(Flags & CMP_ENLIST_KCB_LOCKED_EXCLUSIVE));
    }

    /* Check if we need to lock the KCB */
    if (!(Flags & CMP_ENLIST_KCB_LOCKED_EXCLUSIVE))
    {
        /* Acquire the lock */
        CmpAcquireKcbLockExclusive(KeyBody->KeyControlBlock);
    }

    /* Make sure we have the exclusive lock */
    CMP_ASSERT_KCB_LOCK(KeyBody->KeyControlBlock);

    /* Do the insert */
    InsertTailList(&KeyBody->KeyControlBlock->KeyBodyListHead,
                   &KeyBody->KeyBodyList);

    /* Check if we did a manual lock */
    if (!(Flags & (CMP_ENLIST_KCB_LOCKED_SHARED |
                   CMP_ENLIST_KCB_LOCKED_EXCLUSIVE)))
    {
        /* Release the lock */
        CmpReleaseKcbLock(KeyBody->KeyControlBlock);
    }
}

VOID
NTAPI
DelistKeyBodyFromKCB(IN PCM_KEY_BODY KeyBody,
                     IN BOOLEAN LockHeld)
{
    ULONG i;

    /* Sanity check */
    ASSERT(KeyBody->KeyControlBlock != NULL);

    /* Check if we can use the parent KCB array */
    for (i = 0; i < 4; i++)
    {
        /* Add it into the list */
        if (InterlockedCompareExchangePointer((PVOID*)&KeyBody->KeyControlBlock->
                                              KeyBodyArray[i],
                                              NULL,
                                              KeyBody) == KeyBody)
        {
            /* Removed */
            return;
        }
    }

    /* Sanity checks */
    ASSERT(IsListEmpty(&KeyBody->KeyControlBlock->KeyBodyListHead) == FALSE);
    ASSERT(IsListEmpty(&KeyBody->KeyBodyList) == FALSE);

    /* Lock the KCB */
    if (!LockHeld) CmpAcquireKcbLockExclusive(KeyBody->KeyControlBlock);
    CMP_ASSERT_KCB_LOCK(KeyBody->KeyControlBlock);

    /* Remove the entry */
    RemoveEntryList(&KeyBody->KeyBodyList);

    /* Unlock it it if we did a manual lock */
    if (!LockHeld) CmpReleaseKcbLock(KeyBody->KeyControlBlock);
}

/**
 * @brief
 * Unlocks a number of KCBs provided by a KCB array.
 *
 * @param[in] KcbArray
 * A pointer to an array of KCBs to be unlocked.
 */
VOID
CmpUnLockKcbArray(
    _In_ PULONG KcbArray)
{
    ULONG i;

    /* Release the locked KCBs in reverse order */
    for (i = KcbArray[0]; i > 0; i--)
    {
        CmpReleaseKcbLockByIndex(KcbArray[i]);
    }
}

/**
 * @brief
 * Locks a given number of KCBs.
 *
 * @param[in] KcbArray
 * A pointer to an array of KCBs to be locked.
 * The count of KCBs to be locked is defined by the
 * first element in the array.
 *
 * @param[in] KcbLockFlags
 * Define a lock flag to lock the KCBs.
 *
 * CMP_LOCK_KCB_ARRAY_EXCLUSIVE -- indicates the KCBs are locked
 * exclusively and owned by the calling thread.
 *
 * CMP_LOCK_KCB_ARRAY_SHARED --  indicates the KCBs are locked
 * in shared mode by the owning threads.
 */
static
VOID
CmpLockKcbArray(
    _In_ PULONG KcbArray,
    _In_ ULONG KcbLockFlags)
{
    ULONG i;

    /* Lock the KCBs */
    for (i = 1; i <= KcbArray[0]; i++)
    {
        if (KcbLockFlags & CMP_LOCK_KCB_ARRAY_EXCLUSIVE)
        {
            CmpAcquireKcbLockExclusiveByIndex(KcbArray[i]);
        }
        else // CMP_LOCK_KCB_ARRAY_SHARED
        {
            CmpAcquireKcbLockSharedByIndex(KcbArray[i]);
        }
    }
}

/**
 * @brief
 * Sorts an array of KCB hashes in ascending order
 * and removes any key indices that are duplicates.
 * The purpose of sorting the KCB elements is to
 * ensure consistent and proper locking order, so
 * that we can prevent a deadlock.
 *
 * @param[in,out] KcbArray
 * A pointer to an array of KCBs of which the key
 * indices are to be sorted.
 */
static
VOID
CmpSortKcbArray(
    _Inout_ PULONG KcbArray)
{
    ULONG i, j, k, KcbCount;

    /* Ensure we don't go above the limit of KCBs we can hold */
    KcbCount = KcbArray[0];
    ASSERT(KcbCount < CMP_KCBS_IN_ARRAY_LIMIT);

    /* Exchange-Sort the array in ascending order. Complexity: O[n^2] */
    for (i = 1; i <= KcbCount; i++)
    {
        for (j = i + 1; j <= KcbCount; j++)
        {
            if (KcbArray[i] > KcbArray[j])
            {
                ULONG Temp = KcbArray[i];
                KcbArray[i] = KcbArray[j];
                KcbArray[j] = Temp;
            }
        }
    }

    /* Now remove any duplicated indices on the sorted array if any */
    for (i = 1; i <= KcbCount; i++)
    {
        for (j = i + 1; j <= KcbCount; j++)
        {
            if (KcbArray[i] == KcbArray[j])
            {
                for (k = j; k <= KcbCount; k++)
                {
                    KcbArray[k - 1] = KcbArray[k];
                }

                j--;
                KcbCount--;
            }
        }
    }

    /* Update the KCB count */
    KcbArray[0] = KcbCount;
}

/**
 * @brief
 * Builds an array of KCBs and locks them. Whether these
 * KCBs are locked exclusively or in shared mode by the calling
 * thread, is specified by the KcbLockFlags parameter. The array
 * is sorted.
 *
 * @param[in] HashCacheStack
 * A pointer to a hash cache stack. This stack parameter
 * stores the convkey hashes of interested KCBs of a
 * key path name that need to be locked.
 *
 * @param[in] KcbLockFlags
 * Define a lock flag to lock the KCBs. Consult the
 * CmpLockKcbArray documentation for more information.
 *
 * @param[in] Kcb
 * A pointer to a key control block to be given. This
 * KCB is included in the array for locking, that is,
 * given by the CmpParseKey from the parser object.
 *
 * @param[in,out] OuterStackArray
 * A pointer to an array that lives on the caller's
 * stack. It acts like an auxiliary array used by
 * the function to store the KCB elements for locking.
 * The expected size of the array is up to 32 elements,
 * which is the imposed limit by CMP_HASH_STACK_LIMIT.
 * This limit also corresponds to the maximum depth of
 * subkey levels.
 *
 * @param[in] TotalRemainingSubkeys
 * The number of total remaining subkey levels.
 *
 * @param[in] MatchRemainSubkeyLevel
 * The number of remaining subkey levels that match.
 *
 * @return
 * Returns a pointer to an array of KCBs that have been
 * locked.
 *
 * @remarks
 * The caller HAS THE RESPONSIBILITY to unlock the KCBs
 * after the necessary operations are done!
 */
PULONG
NTAPI
CmpBuildAndLockKcbArray(
    _In_ PCM_HASH_CACHE_STACK HashCacheStack,
    _In_ ULONG KcbLockFlags,
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _Inout_ PULONG OuterStackArray,
    _In_ ULONG TotalRemainingSubkeys,
    _In_ ULONG MatchRemainSubkeyLevel)
{
    ULONG KcbIndex = 1, HashStackIndex, TotalRemaining;
    PULONG LockedKcbs = NULL;
    PCM_KEY_CONTROL_BLOCK ParentKcb = Kcb->ParentKcb;;

    /* These parameters are expected */
    ASSERT(HashCacheStack != NULL);
    ASSERT(Kcb != NULL);
    ASSERT(OuterStackArray != NULL);

    /*
     * Ensure when we build an array of KCBs to lock, that
     * we don't go beyond the boundary the limit allows us
     * to. 1 is the current KCB we would want to lock
     * alongside with the remaining key levels in the formula.
     */
    TotalRemaining = (1 + TotalRemainingSubkeys) - MatchRemainSubkeyLevel;
    ASSERT(TotalRemaining <= CMP_KCBS_IN_ARRAY_LIMIT);

    /* Count the parent if we have one */
    if (ParentKcb)
    {
        /* Ensure we are still below the limit and add the parent to KCBs to lock */
        if (TotalRemainingSubkeys == MatchRemainSubkeyLevel)
        {
            TotalRemaining++;
            ASSERT(TotalRemaining <= CMP_KCBS_IN_ARRAY_LIMIT);
            OuterStackArray[KcbIndex++] = GET_HASH_INDEX(ParentKcb->ConvKey);
        }
    }

    /* Add the current KCB */
    OuterStackArray[KcbIndex++] = GET_HASH_INDEX(Kcb->ConvKey);

    /* Loop over the hash stack and grab the hashes for locking (they will be converted to indices) */
    for (HashStackIndex = 0;
         HashStackIndex < TotalRemainingSubkeys;
         HashStackIndex++)
    {
        OuterStackArray[KcbIndex++] = GET_HASH_INDEX(HashCacheStack[HashStackIndex].ConvKey);
    }

    /*
     * Store how many KCBs we need to lock and sort the array.
     * Remove any duplicated indices from the array if any.
     */
    OuterStackArray[0] = KcbIndex - 1;
    CmpSortKcbArray(OuterStackArray);

    /* Lock them */
    CmpLockKcbArray(OuterStackArray, KcbLockFlags);

    /* Give the locked KCBs to caller now */
    LockedKcbs = OuterStackArray;
    return LockedKcbs;
}

VOID
NTAPI
CmpFlushNotifiesOnKeyBodyList(IN PCM_KEY_CONTROL_BLOCK Kcb,
                              IN BOOLEAN LockHeld)
{
    PLIST_ENTRY NextEntry, ListHead;
    PCM_KEY_BODY KeyBody;

    /* Sanity check */
    LockHeld ? CMP_ASSERT_EXCLUSIVE_REGISTRY_LOCK() : CmpIsKcbLockedExclusive(Kcb);
    while (TRUE)
    {
        /* Is the list empty? */
        ListHead = &Kcb->KeyBodyListHead;
        if (!IsListEmpty(ListHead))
        {
            /* Loop the list */
            NextEntry = ListHead->Flink;
            while (NextEntry != ListHead)
            {
                /* Get the key body */
                KeyBody = CONTAINING_RECORD(NextEntry, CM_KEY_BODY, KeyBodyList);
                ASSERT(KeyBody->Type == CM_KEY_BODY_TYPE);

                /* Check for notifications */
                if (KeyBody->NotifyBlock)
                {
                    /* Is the lock held? */
                    if (LockHeld)
                    {
                        /* Flush it */
                        CmpFlushNotify(KeyBody, LockHeld);
                        ASSERT(KeyBody->NotifyBlock == NULL);
                        continue;
                    }

                    /* Lock isn't held, so we need to take a reference */
                    if (ObReferenceObjectSafe(KeyBody))
                    {
                        /* Now we can flush */
                        CmpFlushNotify(KeyBody, LockHeld);
                        ASSERT(KeyBody->NotifyBlock == NULL);

                        /* Release the reference we took */
                        ObDereferenceObjectDeferDelete(KeyBody);
                        continue;
                    }
                }

                /* Try the next entry */
                NextEntry = NextEntry->Flink;
            }
        }

        /* List has been parsed, exit */
        break;
    }
}

/*
 * Renaming a KCB (CmRenameKey). A KCB's hash key is its parent's, carried on
 * over the characters of its own name (COMPUTE_HASH_CHAR, modulo 2^32), so a
 * new name changes the hash key of the KCB and of every cached KCB below it:
 * a descendant N name characters further down moves by 37^N times the KCB's
 * change. Prepare gets everything that can fail (the name block, the list of
 * descendants) before the hive is touched; commit moves the KCBs; abort
 * drops what prepare got. All under the exclusive registry lock.
 */
static
ULONG
CmpPowerOf37(
    _In_ ULONG Exponent)
{
    ULONG Result = 1, Base = 37;

    while (Exponent)
    {
        if (Exponent & 1) Result *= Base;
        Base *= Base;
        Exponent >>= 1;
    }
    return Result;
}

static
ULONG
CmpHashedNameChars(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb)
{
    PCM_NAME_CONTROL_BLOCK Ncb = Kcb->NameBlock;
    ULONG i, Count = 0;

    /* The characters COMPUTE_HASH_CHAR went over when the KCB was made */
    if (Ncb->Compressed)
    {
        for (i = 0; i < Ncb->NameLength; i++)
        {
            if (((PUCHAR)Ncb->Name)[i] != OBJ_NAME_PATH_SEPARATOR) Count++;
        }
    }
    else
    {
        for (i = 0; i < Ncb->NameLength / sizeof(WCHAR); i++)
        {
            if (Ncb->Name[i] != OBJ_NAME_PATH_SEPARATOR) Count++;
        }
    }
    return Count;
}

static
ULONG
CmpCollectKcbSubtree(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_ ULONG Delta,
    _Out_writes_opt_(MaxEntries) PCM_KCB_REHASH_ENTRY Entries,
    _In_ ULONG MaxEntries)
{
    ULONG i, Count = 0, Chars;
    PCM_KEY_HASH Entry;
    PCM_KEY_CONTROL_BLOCK Current, Walk;

    /* Every cached KCB below Kcb: open ones and those in delayed close */
    for (i = 0; i < CmpHashTableSize; i++)
    {
        for (Entry = CmpCacheTable[i].Entry; Entry; Entry = Entry->NextHash)
        {
            Current = CONTAINING_RECORD(Entry, CM_KEY_CONTROL_BLOCK, KeyHash);
            if (Current->TotalLevels <= Kcb->TotalLevels) continue;

            Chars = 0;
            for (Walk = Current;
                 Walk && (Walk->TotalLevels > Kcb->TotalLevels);
                 Walk = Walk->ParentKcb)
            {
                Chars += CmpHashedNameChars(Walk);
            }
            if (Walk != Kcb) continue;

            if (Entries && (Count < MaxEntries))
            {
                Entries[Count].Kcb = Current;
                Entries[Count].ConvKey = Current->ConvKey + CmpPowerOf37(Chars) * Delta;
            }
            Count++;
        }
    }
    return Count;
}

NTSTATUS
NTAPI
CmpPrepareKcbRename(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_ PCUNICODE_STRING NewName,
    _Out_ PCM_KCB_RENAME_CONTEXT Context)
{
    ULONG i, Delta;

    CMP_ASSERT_EXCLUSIVE_REGISTRY_LOCK();
    ASSERT(Kcb->ParentKcb);
    RtlZeroMemory(Context, sizeof(*Context));

    /* The hash key of the new path, as CmpCreateKeyControlBlock makes it */
    Context->ConvKey = Kcb->ParentKcb->ConvKey;
    for (i = 0; i < NewName->Length / sizeof(WCHAR); i++)
    {
        if (NewName->Buffer[i] != OBJ_NAME_PATH_SEPARATOR)
            Context->ConvKey = COMPUTE_HASH_CHAR(Context->ConvKey, NewName->Buffer[i]);
    }

    Context->NameBlock = CmpGetNameControlBlock((PUNICODE_STRING)NewName);
    if (!Context->NameBlock)
        return STATUS_INSUFFICIENT_RESOURCES;

    Delta = Context->ConvKey - Kcb->ConvKey;
    Context->Count = CmpCollectKcbSubtree(Kcb, Delta, NULL, 0);
    if (Context->Count)
    {
        Context->Entries = CmpAllocate(Context->Count * sizeof(CM_KCB_REHASH_ENTRY), TRUE, TAG_CM);
        if (!Context->Entries)
        {
            CmpDereferenceNameControlBlockWithLock(Context->NameBlock);
            Context->NameBlock = NULL;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        i = CmpCollectKcbSubtree(Kcb, Delta, Context->Entries, Context->Count);
        ASSERT(i == Context->Count);
    }
    return STATUS_SUCCESS;
}

static
VOID
CmpRehashKcb(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_ ULONG ConvKey,
    _In_ HCELL_INDEX Cell)
{
    PCM_KEY_CONTROL_BLOCK Existing;

    /* Hash key and cell are the hash entry: change them out of the table */
    CmpRemoveKeyHash(&Kcb->KeyHash);
    Kcb->ConvKey = ConvKey;
    Kcb->KeyCell = Cell;
    Existing = CmpInsertKeyHash(&Kcb->KeyHash, FALSE);
    ASSERT(Existing == NULL);
    UNREFERENCED_PARAMETER(Existing);
}

VOID
NTAPI
CmpCommitKcbRename(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_ HCELL_INDEX NewCell,
    _Inout_ PCM_KCB_RENAME_CONTEXT Context)
{
    PCM_NAME_CONTROL_BLOCK OldNameBlock;
    ULONG i;

    CMP_ASSERT_EXCLUSIVE_REGISTRY_LOCK();

    CmpRehashKcb(Kcb, Context->ConvKey, NewCell);

    OldNameBlock = Kcb->NameBlock;
    Kcb->NameBlock = Context->NameBlock;
    Context->NameBlock = OldNameBlock;

    for (i = 0; i < Context->Count; i++)
    {
        CmpRehashKcb(Context->Entries[i].Kcb,
                     Context->Entries[i].ConvKey,
                     Context->Entries[i].Kcb->KeyCell);
    }

    /* What is left is the old name block and the list */
    CmpAbortKcbRename(Context);
}

VOID
NTAPI
CmpAbortKcbRename(
    _Inout_ PCM_KCB_RENAME_CONTEXT Context)
{
    if (Context->NameBlock)
        CmpDereferenceNameControlBlockWithLock(Context->NameBlock);
    if (Context->Entries)
        CmpFree(Context->Entries, 0);
    RtlZeroMemory(Context, sizeof(*Context));
}
