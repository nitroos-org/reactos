/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/config/cmparse.c
 * PURPOSE:         Configuration Manager - Object Manager Parse Interface
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include "ntoskrnl.h"
#define NDEBUG
#include "debug.h"

/* GLOBALS *******************************************************************/

/* FUNCTIONS *****************************************************************/

BOOLEAN
NTAPI
CmpGetNextName(IN OUT PUNICODE_STRING RemainingName,
               OUT PUNICODE_STRING NextName,
               OUT PBOOLEAN LastName)
{
    BOOLEAN NameValid = TRUE;

    ASSERT(RemainingName->Length % sizeof(WCHAR) == 0);

    /* Check if there's nothing left in the name */
    if (!(RemainingName->Buffer) ||
        (!RemainingName->Length) ||
        !(*RemainingName->Buffer))
    {
        /* Clear the next name and set this as last */
        *LastName = TRUE;
        NextName->Buffer = NULL;
        NextName->Length = 0;
        return TRUE;
    }

    /* Check if we have a path separator */
    while (RemainingName->Length &&
           (*RemainingName->Buffer == OBJ_NAME_PATH_SEPARATOR))
    {
        /* Skip it */
        RemainingName->Buffer++;
        RemainingName->Length -= sizeof(WCHAR);
        RemainingName->MaximumLength -= sizeof(WCHAR);
    }

    /* Start loop at where the current buffer is */
    NextName->Buffer = RemainingName->Buffer;
    while (RemainingName->Length &&
           (*RemainingName->Buffer != OBJ_NAME_PATH_SEPARATOR))
    {
        /* Move to the next character */
        RemainingName->Buffer++;
        RemainingName->Length -= sizeof(WCHAR);
        RemainingName->MaximumLength -= sizeof(WCHAR);
    }

    /* See how many chars we parsed and validate the length */
    NextName->Length = (USHORT)((ULONG_PTR)RemainingName->Buffer -
                                (ULONG_PTR)NextName->Buffer);
    if (NextName->Length > 512) NameValid = FALSE;
    NextName->MaximumLength = NextName->Length;

    /* If there's nothing left, we're last */
    *LastName = !RemainingName->Length;
    return NameValid;
}

BOOLEAN
NTAPI
CmpGetSymbolicLink(IN PHHIVE Hive,
                   IN OUT PUNICODE_STRING ObjectName,
                   IN OUT PCM_KEY_CONTROL_BLOCK SymbolicKcb,
                   IN PUNICODE_STRING RemainingName OPTIONAL)
{
    HCELL_INDEX LinkCell = HCELL_NIL;
    PCM_KEY_VALUE LinkValue = NULL;
    PWSTR LinkName = NULL;
    BOOLEAN LinkNameAllocated = FALSE;
    PWSTR NewBuffer;
    ULONG Length = 0;
    ULONG ValueLength = 0;
    BOOLEAN Result = FALSE;
    HCELL_INDEX CellToRelease = HCELL_NIL;
    PCM_KEY_NODE Node;
    UNICODE_STRING NewObjectName;

    /* Make sure we're not being deleted */
    if (SymbolicKcb->Delete) return FALSE;

    /* Get the key node */
    Node = (PCM_KEY_NODE)HvGetCell(SymbolicKcb->KeyHive, SymbolicKcb->KeyCell);
    if (!Node) goto Exit;

    /* Find the symbolic link key */
    LinkCell = CmpFindValueByName(Hive, Node, &CmSymbolicLinkValueName);
    HvReleaseCell(SymbolicKcb->KeyHive, SymbolicKcb->KeyCell);
    if (LinkCell == HCELL_NIL) goto Exit;

    /* Get the value cell */
    LinkValue = (PCM_KEY_VALUE)HvGetCell(Hive, LinkCell);
    if (!LinkValue) goto Exit;

    /* Make sure it's a registry link */
    if (LinkValue->Type != REG_LINK) goto Exit;

    /* Now read the value data */
    if (!CmpGetValueData(Hive,
                         LinkValue,
                         &ValueLength,
                         (PVOID*)&LinkName,
                         &LinkNameAllocated,
                         &CellToRelease))
    {
        /* Fail */
        goto Exit;
    }

    /* Get the length */
    Length = ValueLength + sizeof(WCHAR);

    /* Make sure we start with a slash */
    if (*LinkName != OBJ_NAME_PATH_SEPARATOR) goto Exit;

    /* Add the remaining name if needed */
    if (RemainingName) Length += RemainingName->Length + sizeof(WCHAR);

    /* Check for overflow */
    if (Length > 0xFFFF) goto Exit;

    /* Check if we need a new buffer */
    if (Length > ObjectName->MaximumLength)
    {
        /* We do -- allocate one */
        NewBuffer = ExAllocatePoolWithTag(PagedPool, Length, TAG_CM);
        if (!NewBuffer) goto Exit;

        /* Setup the new string and copy the symbolic target */
        NewObjectName.Buffer = NewBuffer;
        NewObjectName.MaximumLength = (USHORT)Length;
        NewObjectName.Length = (USHORT)ValueLength;
        RtlCopyMemory(NewBuffer, LinkName, ValueLength);

        /* Check if we need to add anything else */
        if (RemainingName)
        {
            /* Add the remaining name */
            NewBuffer[ValueLength / sizeof(WCHAR)] = OBJ_NAME_PATH_SEPARATOR;
            NewObjectName.Length += sizeof(WCHAR);
            RtlAppendUnicodeStringToString(&NewObjectName, RemainingName);
        }

        /* Free the old buffer */
        ExFreePool(ObjectName->Buffer);
        *ObjectName = NewObjectName;
    }
    else
    {
        /* The old name is large enough -- update the length */
        ObjectName->Length = (USHORT)ValueLength;
        if (RemainingName)
        {
            /* Copy the remaining name inside */
            RtlMoveMemory(&ObjectName->Buffer[(ValueLength / sizeof(WCHAR)) + 1],
                          RemainingName->Buffer,
                          RemainingName->Length);

            /* Add the slash and update the length */
            ObjectName->Buffer[ValueLength / sizeof(WCHAR)] = OBJ_NAME_PATH_SEPARATOR;
            ObjectName->Length += RemainingName->Length + sizeof(WCHAR);
        }

        /* Copy the symbolic link target name */
        RtlCopyMemory(ObjectName->Buffer, LinkName, ValueLength);
    }

    /* Null-terminate the whole thing */
    ObjectName->Buffer[ObjectName->Length / sizeof(WCHAR)] = UNICODE_NULL;
    Result = TRUE;

Exit:
    /* Free the link name */
    if (LinkNameAllocated) ExFreePool(LinkName);

    /* Check if we had a value cell */
    if (LinkValue)
    {
        /* Release it */
        ASSERT(LinkCell != HCELL_NIL);
        HvReleaseCell(Hive, LinkCell);
    }

    /* Check if we had an active cell and release it, then return the result */
    if (CellToRelease != HCELL_NIL) HvReleaseCell(Hive, CellToRelease);
    return Result;
}

NTSTATUS
NTAPI
CmpDoCreateChild(IN PHHIVE Hive,
                 IN HCELL_INDEX ParentCell,
                 IN PSECURITY_DESCRIPTOR ParentDescriptor OPTIONAL,
                 IN PACCESS_STATE AccessState,
                 IN PUNICODE_STRING Name,
                 IN KPROCESSOR_MODE AccessMode,
                 IN PCM_PARSE_CONTEXT ParseContext,
                 IN PCM_KEY_CONTROL_BLOCK ParentKcb,
                 IN ULONG Flags,
                 OUT PHCELL_INDEX KeyCell,
                 OUT PVOID *Object)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCM_KEY_BODY KeyBody;
    HCELL_INDEX ClassCell = HCELL_NIL;
    PCM_KEY_NODE KeyNode;
    PCELL_DATA CellData;
    ULONG StorageType;
    PCM_KEY_CONTROL_BLOCK Kcb;
    PSECURITY_DESCRIPTOR NewDescriptor, ParentSd = NULL;
    HCELL_INDEX SecurityCell = HCELL_NIL;
    BOOLEAN StoreExplicit;

    *KeyCell = HCELL_NIL;

    /* Get the storage type */
    StorageType = Stable;
    if (ParseContext->CreateOptions & REG_OPTION_VOLATILE) StorageType = Volatile;

    /*
     * The new key's descriptor, before anything is allocated: inherited from
     * the parent's (its effective one when the parent has none stored, see
     * CmpCaptureParentSecurity) and the caller's explicit descriptor, as on
     * Windows: the DACL is not auto-inherited (inherited ACEs carry no
     * INHERITED_ACE), the SACL is (SE_SACL_AUTO_INHERITED is set, as in the
     * oracle's stored descriptors, control 0x8804). It is stored in an 'sk'
     * cell of the key's storage type, shared with the keys that have the same
     * one. Without a parent descriptor (legacy mode) nothing is stored and the
     * key has none, as before.
     */
    if (!ParentDescriptor)
        ParentDescriptor = ParentSd = CmpCaptureParentSecurity(ParentKcb);
    /*
     * Setup stores no inherited descriptors, but the one a user-mode creator names (setup
     * builds the hives this way). The kernel's own creates, which pass the hive default,
     * keep leaving the key without one.
     */
    StoreExplicit = !ParentDescriptor && AccessMode == UserMode &&
                    AccessState->SecurityDescriptor && CmpStoreExplicitKeySecurity();

    /*
     * An explicit descriptor that is stored must be one the caller may
     * assign, as on Windows: an owner of its own (or SeRestorePrivilege) and
     * a SACL only with SeSecurityPrivilege (SepCheckCreatorDescriptor). Where
     * nothing is stored (legacy mode) the descriptor is not used and not
     * checked, as before.
     */
    if ((ParentDescriptor || StoreExplicit) && AccessState->SecurityDescriptor)
    {
        Status = SepCheckCreatorDescriptor(AccessState->SecurityDescriptor,
                                           &AccessState->SubjectSecurityContext,
                                           AccessMode);
        if (!NT_SUCCESS(Status))
        {
            if (ParentSd)
                CmpFreeParentSecurity(ParentSd);
            return Status;
        }
    }
    Status = SeAssignSecurityEx(ParentDescriptor,
                                AccessState->SecurityDescriptor,
                                &NewDescriptor,
                                NULL,
                                TRUE,
                                (ParentDescriptor || StoreExplicit) ? SEF_SACL_AUTO_INHERIT : 0,
                                &AccessState->SubjectSecurityContext,
                                &CmpKeyObjectType->TypeInfo.GenericMapping,
                                CmpKeyObjectType->TypeInfo.PoolType);
    if (ParentSd)
        CmpFreeParentSecurity(ParentSd);
    if (!NT_SUCCESS(Status))
        return Status;
    if (ParentDescriptor || StoreExplicit)
    {
        Status = CmpInsertSecurityDescriptor((PCMHIVE)Hive,
                                             NewDescriptor,
                                             RtlLengthSecurityDescriptor(NewDescriptor),
                                             StorageType,
                                             &SecurityCell);
    }
    SeDeassignSecurity(&NewDescriptor);
    if (!NT_SUCCESS(Status))
        return Status;

    /* Allocate the child */
    *KeyCell = HvAllocateCell(Hive,
                              FIELD_OFFSET(CM_KEY_NODE, Name) +
                              CmpNameSize(Hive, Name),
                              StorageType,
                              HCELL_NIL);
    if (*KeyCell == HCELL_NIL)
    {
        /* Fail */
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Quickie;
    }

    /* Get the key node */
    KeyNode = (PCM_KEY_NODE)HvGetCell(Hive, *KeyCell);
    if (!KeyNode)
    {
        /* Fail, this should never happen */
        ASSERT(FALSE);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Quickie;
    }

    /* Release the cell */
    HvReleaseCell(Hive, *KeyCell);

    /* Check if we have a class name */
    if (ParseContext->Class.Length > 0)
    {
        /* Allocate a class cell */
        ClassCell = HvAllocateCell(Hive,
                                   ParseContext->Class.Length,
                                   StorageType,
                                   HCELL_NIL);
        if (ClassCell == HCELL_NIL)
        {
            /* Fail */
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Quickie;
        }
    }

    /* Allocate the Cm Object */
    Status = ObCreateObject(AccessMode,
                            CmpKeyObjectType,
                            NULL,
                            AccessMode,
                            NULL,
                            sizeof(CM_KEY_BODY),
                            0,
                            0,
                            Object);
    if (!NT_SUCCESS(Status)) goto Quickie;

    /* Setup the key body */
    KeyBody = (PCM_KEY_BODY)(*Object);
    KeyBody->Type = CM_KEY_BODY_TYPE;
    KeyBody->KeyControlBlock = NULL;
    KeyBody->KcbLocked = FALSE;

    /* Check if we had a class */
    if (ParseContext->Class.Length > 0)
    {
        /* Get the class cell */
        CellData = HvGetCell(Hive, ClassCell);
        if (!CellData)
        {
            /* Fail, this should never happen */
            ASSERT(FALSE);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ObDereferenceObject(*Object);
            goto Quickie;
        }

        /* Release the cell */
        HvReleaseCell(Hive, ClassCell);

        /* Copy the class data */
        RtlCopyMemory(&CellData->u.KeyString[0],
                      ParseContext->Class.Buffer,
                      ParseContext->Class.Length);
    }

    /* Fill out the key node */
    KeyNode->Signature = CM_KEY_NODE_SIGNATURE;
    KeyNode->Flags = Flags;
    KeQuerySystemTime(&KeyNode->LastWriteTime);
    KeyNode->Spare = 0;
    KeyNode->Parent = ParentCell;
    KeyNode->SubKeyCounts[Stable] = 0;
    KeyNode->SubKeyCounts[Volatile] = 0;
    KeyNode->SubKeyLists[Stable] = HCELL_NIL;
    KeyNode->SubKeyLists[Volatile] = HCELL_NIL;
    KeyNode->ValueList.Count = 0;
    KeyNode->ValueList.List = HCELL_NIL;
    KeyNode->Security = SecurityCell;
    KeyNode->Class = ClassCell;
    KeyNode->ClassLength = ParseContext->Class.Length;
    KeyNode->MaxValueDataLen = 0;
    KeyNode->MaxNameLen = 0;
    KeyNode->MaxValueNameLen = 0;
    KeyNode->MaxClassLen = 0;
    KeyNode->NameLength = CmpCopyName(Hive, KeyNode->Name, Name);
    if (KeyNode->NameLength < Name->Length) KeyNode->Flags |= KEY_COMP_NAME;

    /* Create the KCB */
    Kcb = CmpCreateKeyControlBlock(Hive,
                                   *KeyCell,
                                   KeyNode,
                                   ParentKcb,
                                   CMP_LOCK_HASHES_FOR_KCB,
                                   Name);
    if (!Kcb)
    {
        /* Fail */
        ObDereferenceObjectDeferDelete(*Object);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Quickie;
    }

    /* Sanity check */
    ASSERT(Kcb->RefCount == 1);

    /* Now fill out the Cm object */
    KeyBody->NotifyBlock = NULL;
    KeyBody->ProcessID = PsGetCurrentProcessId();
    KeyBody->KeyControlBlock = Kcb;

    /* Link it with the KCB */
    EnlistKeyBodyWithKCB(KeyBody, CMP_ENLIST_KCB_LOCKED_EXCLUSIVE);

    /* Send notification to registered callbacks */
    CmpReportNotify(Kcb, Hive, Kcb->KeyCell, REG_NOTIFY_CHANGE_NAME);

Quickie:
    /* Check if we got here because of failure */
    if (!NT_SUCCESS(Status))
    {
        /* Free any cells we might've allocated, and the key's reference to its 'sk' cell */
        if (ClassCell != HCELL_NIL) HvFreeCell(Hive, ClassCell);
        if (*KeyCell != HCELL_NIL)
        {
            HvFreeCell(Hive, *KeyCell);
            *KeyCell = HCELL_NIL;
        }
        if (SecurityCell != HCELL_NIL) CmpReleaseSecurityCell(Hive, SecurityCell);
    }

    /* Return status */
    return Status;
}

NTSTATUS
NTAPI
CmpDoCreate(IN PHHIVE Hive,
            IN HCELL_INDEX Cell,
            IN PACCESS_STATE AccessState,
            IN PUNICODE_STRING Name,
            IN KPROCESSOR_MODE AccessMode,
            IN PCM_PARSE_CONTEXT ParseContext,
            IN PCM_KEY_CONTROL_BLOCK ParentKcb,
            OUT PVOID *Object)
{
    NTSTATUS Status;
    PCELL_DATA CellData;
    HCELL_INDEX KeyCell;
    ULONG ParentType;
    PCM_KEY_BODY KeyBody;
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    LARGE_INTEGER TimeStamp;
    PCM_KEY_NODE KeyNode;

    /* Make sure the KCB is locked and lock the flusher */
    CMP_ASSERT_KCB_LOCK(ParentKcb);
    CmpLockHiveFlusherShared((PCMHIVE)Hive);

    /* Bail out on read-only KCBs */
    if (ParentKcb->ExtFlags & CM_KCB_READ_ONLY_KEY)
    {
        Status = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    /* Check if the parent is being deleted */
    if (ParentKcb->Delete)
    {
        /* It has, quit */
        ASSERT(FALSE);
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Exit;
    }

    /* Get the parent node */
    KeyNode = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
    if (!KeyNode)
    {
        /* Fail */
        ASSERT(FALSE);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    /* Make sure nobody added us yet */
    if (CmpFindSubKeyByName(Hive, KeyNode, Name) != HCELL_NIL)
    {
        /* Fail */
        ASSERT(FALSE);
        Status = STATUS_REPARSE;
        goto Exit;
    }

    /* Sanity check */
    ASSERT(Cell == ParentKcb->KeyCell);

    /* Get the parent type */
    ParentType = HvGetCellType(Cell);
    if ((ParentType == Volatile) &&
        !(ParseContext->CreateOptions & REG_OPTION_VOLATILE))
    {
        /* Children of volatile parents must also be volatile */
        //ASSERT(FALSE);
        Status = STATUS_CHILD_MUST_BE_VOLATILE;
        goto Exit;
    }

    /* Don't allow children under symlinks */
    if (ParentKcb->Flags & KEY_SYM_LINK)
    {
        /* Fail */
        ASSERT(FALSE);
        Status = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    /* Make the cell dirty for now */
    HvMarkCellDirty(Hive, Cell, FALSE);

    /* Do the actual create operation */
    Status = CmpDoCreateChild(Hive,
                              Cell,
                              SecurityDescriptor,
                              AccessState,
                              Name,
                              AccessMode,
                              ParseContext,
                              ParentKcb,
                              0,
                              &KeyCell,
                              Object);
    if (NT_SUCCESS(Status))
    {
        /* Get the key body */
        KeyBody = (PCM_KEY_BODY)(*Object);

        /* Now add the subkey */
        if (!CmpAddSubKey(Hive, Cell, KeyCell))
        {
            /* Free the created child */
            CmpFreeKeyByCell(Hive, KeyCell, FALSE);

            /* Purge out this KCB */
            KeyBody->KeyControlBlock->Delete = TRUE;
            CmpRemoveKeyControlBlock(KeyBody->KeyControlBlock);

            /* And cleanup the key body object */
            ObDereferenceObjectDeferDelete(*Object);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        /* Get the key node */
        KeyNode = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
        if (!KeyNode)
        {
            /* Fail, this shouldn't happen */
            CmpFreeKeyByCell(Hive, KeyCell, TRUE); // Subkey linked above

            /* Purge out this KCB */
            KeyBody->KeyControlBlock->Delete = TRUE;
            CmpRemoveKeyControlBlock(KeyBody->KeyControlBlock);

            /* And cleanup the key body object */
            ObDereferenceObjectDeferDelete(*Object);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        /* Clean up information on this subkey */
        CmpCleanUpSubKeyInfo(KeyBody->KeyControlBlock->ParentKcb);

        /* Sanity checks */
        ASSERT(KeyBody->KeyControlBlock->ParentKcb->KeyCell == Cell);
        ASSERT(KeyBody->KeyControlBlock->ParentKcb->KeyHive == Hive);
        ASSERT(KeyBody->KeyControlBlock->ParentKcb == ParentKcb);
        ASSERT(KeyBody->KeyControlBlock->ParentKcb->KcbMaxNameLen == KeyNode->MaxNameLen);

        /* Update the timestamp */
        KeQuerySystemTime(&TimeStamp);
        KeyNode->LastWriteTime = TimeStamp;
        KeyBody->KeyControlBlock->ParentKcb->KcbLastWriteTime = TimeStamp;

        /* Check if we need to update name maximum */
        if (KeyNode->MaxNameLen < Name->Length)
        {
            /* Do it */
            KeyNode->MaxNameLen = Name->Length;
            KeyBody->KeyControlBlock->ParentKcb->KcbMaxNameLen = Name->Length;
        }

        /* Check if we need to update class length maximum */
        if (KeyNode->MaxClassLen < ParseContext->Class.Length)
        {
            /* Update it */
            KeyNode->MaxClassLen = ParseContext->Class.Length;
        }

        /* Check if we're creating a symbolic link */
        if (ParseContext->CreateOptions & REG_OPTION_CREATE_LINK)
        {
            /* Get the cell data */
            CellData = HvGetCell(Hive, KeyCell);
            if (!CellData)
            {
                /* This shouldn't happen */
                CmpFreeKeyByCell(Hive, KeyCell, TRUE); // Subkey linked above

                /* Purge out this KCB */
                KeyBody->KeyControlBlock->Delete = TRUE;
                CmpRemoveKeyControlBlock(KeyBody->KeyControlBlock);

                /* And cleanup the key body object */
                ObDereferenceObjectDeferDelete(*Object);
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }

            /* Update the flags */
            CellData->u.KeyNode.Flags |= KEY_SYM_LINK;
            KeyBody->KeyControlBlock->Flags = CellData->u.KeyNode.Flags;
            HvReleaseCell(Hive, KeyCell);
        }

        /* Registry ACL audit: the right Windows checks on the parent (logged only, the create stands) */
        if (ParseContext->CreateOptions & REG_OPTION_CREATE_LINK)
        {
            CmpShadowAccessCheck(ParentKcb, Name, CM_REGACL_OP_CREATELINK, AccessState,
                                 KEY_CREATE_LINK, 0, 0, AccessMode, ParseContext->CreateOptions);
        }
        else
        {
            CmpShadowAccessCheck(ParentKcb, Name, CM_REGACL_OP_CREATE, AccessState,
                                 KEY_CREATE_SUB_KEY, 0, 0, AccessMode, ParseContext->CreateOptions);
        }
    }

Exit:
    /* Release the flusher lock and return status */
    CmpUnlockHiveFlusher((PCMHIVE)Hive);
    return Status;
}

NTSTATUS
NTAPI
CmpDoOpen(IN PHHIVE Hive,
          IN HCELL_INDEX Cell,
          IN PCM_KEY_NODE Node,
          IN PACCESS_STATE AccessState,
          IN KPROCESSOR_MODE AccessMode,
          IN ULONG Attributes,
          IN PCM_PARSE_CONTEXT Context OPTIONAL,
          IN ULONG ControlFlags,
          IN OUT PCM_KEY_CONTROL_BLOCK *CachedKcb,
          IN PULONG KcbsLocked,
          IN PUNICODE_STRING KeyName,
          IN ULONG AclOptions,
          OUT PVOID *Object)
{
    NTSTATUS Status;
    BOOLEAN LockKcb = FALSE;
    BOOLEAN IsLockShared = FALSE;
    PCM_KEY_BODY KeyBody = NULL;
    PCM_KEY_CONTROL_BLOCK Kcb = NULL;
    ACCESS_MASK AclDesired, AclPrevious;

    /* Make sure the hive isn't locked */
    if ((Hive->HiveFlags & HIVE_IS_UNLOADING) &&
        (((PCMHIVE)Hive)->CreatorOwner != KeGetCurrentThread()))
    {
        /* It is, don't touch it */
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    /* Check if we have a context */
    if (Context)
    {
        /* Check if this is a link create (which shouldn't be an open) */
        if (Context->CreateLink)
        {
            return STATUS_ACCESS_DENIED;
        }

        /* Check if this is symlink create attempt */
        if (Context->CreateOptions & REG_OPTION_CREATE_LINK)
        {
            /* Key already exists */
            return STATUS_OBJECT_NAME_COLLISION;
        }

        /* Set the disposition */
        Context->Disposition = REG_OPENED_EXISTING_KEY;
    }

    /* Lock the KCB on creation if asked */
    if (ControlFlags & CMP_CREATE_KCB_KCB_LOCKED)
    {
        LockKcb = TRUE;
    }

    /* Check if caller doesn't want to create a KCB */
    if (ControlFlags & CMP_OPEN_KCB_NO_CREATE)
    {
        /*
         * The caller doesn't want to create a KCB. This means the KCB
         * is already in cache and other threads may take use of it
         * so it has to be locked in share mode.
         */
        IsLockShared = TRUE;

        /* Check if this is a symlink */
        if (((*CachedKcb)->Flags & KEY_SYM_LINK) && !(Attributes & OBJ_OPENLINK))
        {
            /* Is this symlink found? */
            if ((*CachedKcb)->ExtFlags & CM_KCB_SYM_LINK_FOUND)
            {
                /* Get the real KCB */
                Kcb = (*CachedKcb)->ValueCache.RealKcb;

                /* Before we drop all locks, we need to reference the real KCB */
                if (!CmpReferenceKeyControlBlock(Kcb))
                {
                    DPRINT("Failed to reference the real KCB, attempt a reparse\n");
                    return STATUS_REPARSE;
                }

                /*
                 * Lock the real KCB of the symlink exclusively, we don't want anybody
                 * to mess it up.
                 */
                CmpUnLockKcbArray(KcbsLocked);
                KcbsLocked[0] = 1;
                KcbsLocked[1] = GET_HASH_INDEX(Kcb->ConvKey);
                CmpAcquireKcbLockExclusiveByIndex(KcbsLocked[1]);
                IsLockShared = FALSE;

                /* Was the real KCB deleted? */
                if (Kcb->Delete)
                {
                    /*
                     * The real KCB is gone, do a reparse. We used to lock the KCB in
                     * shared mode as others may have taken use of it but since we
                     * must do a reparse of the key the only thing that matter is us.
                     * Lock the KCB exclusively so nobody is going to mess with the KCB.
                     */
                    DPRINT1("The real KCB is deleted, attempt a reparse\n");
                    CmpUnLockKcbArray(KcbsLocked);
                    CmpDereferenceKeyControlBlock(Kcb);
                    CmpAcquireKcbLockExclusiveByIndex(GET_HASH_INDEX((*CachedKcb)->ConvKey));
                    CmpCleanUpKcbValueCache(*CachedKcb);
                    KcbsLocked[0] = 1;
                    KcbsLocked[1] = GET_HASH_INDEX((*CachedKcb)->ConvKey);
                    return STATUS_REPARSE;
                }
            }
            else
            {
                /* We must do a reparse */
                DPRINT("The symlink is not found, attempt a reparse\n");
                return STATUS_REPARSE;
            }
        }
        else
        {
            /* This is not a symlink, just give the cached KCB already */
            Kcb = *CachedKcb;

            /* The caller wants to open a cached KCB */
            if (!CmpReferenceKeyControlBlock(Kcb))
            {
                /* Return failure code */
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
    }
    else
    {
        /*
         * The caller wants to create a new KCB. Unlike the code path above, here
         * we must check if the lock is exclusively held because in the scenario
         * where the caller doesn't want to create a KCB is because it is already
         * in the cache and it must have a shared lock instead.
         */
        ASSERT(CmpIsKcbLockedExclusive(*CachedKcb));

        /* Check if this is a symlink */
        if ((Node->Flags & KEY_SYM_LINK) && !(Attributes & OBJ_OPENLINK))
        {
            /* Create the KCB for the symlink */
            Kcb = CmpCreateKeyControlBlock(Hive,
                                           Cell,
                                           Node,
                                           *CachedKcb,
                                           LockKcb ? CMP_LOCK_HASHES_FOR_KCB : 0,
                                           KeyName);
            if (!Kcb)
            {
                /* Return failure */
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            /* Make sure it's also locked, and set the pointer */
            ASSERT(CmpIsKcbLockedExclusive(Kcb));
            *CachedKcb = Kcb;

            /* Return reparse required */
            return STATUS_REPARSE;
        }

        /* Create the KCB */
        Kcb = CmpCreateKeyControlBlock(Hive,
                                       Cell,
                                       Node,
                                       *CachedKcb,
                                       LockKcb ? CMP_LOCK_HASHES_FOR_KCB : 0,
                                       KeyName);
        if (!Kcb)
        {
            /* Return failure */
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Make sure it's also locked, and set the pointer */
        ASSERT(CmpIsKcbLockedExclusive(Kcb));
        *CachedKcb = Kcb;
    }

    /* Allocate the key object */
    Status = ObCreateObject(AccessMode,
                            CmpKeyObjectType,
                            NULL,
                            AccessMode,
                            NULL,
                            sizeof(CM_KEY_BODY),
                            0,
                            0,
                            Object);
    if (NT_SUCCESS(Status))
    {
        /* Get the key body and fill it out */
        KeyBody = (PCM_KEY_BODY)(*Object);
        KeyBody->KeyControlBlock = Kcb;
        KeyBody->Type = CM_KEY_BODY_TYPE;
        KeyBody->ProcessID = PsGetCurrentProcessId();
        KeyBody->NotifyBlock = NULL;

        /* Link to the KCB */
        EnlistKeyBodyWithKCB(KeyBody, IsLockShared ? CMP_ENLIST_KCB_LOCKED_SHARED : CMP_ENLIST_KCB_LOCKED_EXCLUSIVE);

        /*
         * We are already holding a lock against the KCB that is assigned
         * to this key body. Should anything below call CmpSecurityMethod
         * for this body (a query), it must not take that lock again.
         */
        KeyBody->KcbLocked = TRUE;

        /* What the access check is asked for, before it updates the access state */
        AclDesired = AccessState->RemainingDesiredAccess;
        AclPrevious = AccessState->PreviouslyGrantedAccess;

        /*
         * The open decision is the configuration manager's, not a check of
         * the descriptor the key reports (that is the real one now): see
         * CmpCheckKeyOpenAccess. It grants what opens always got until key
         * access is enforced (registry ACL plan R8).
         */
        if (!CmpCheckKeyOpenAccess(*Object,
                                   AccessState,
                                   AccessMode,
                                   &Status))
        {
            /* Access check failed */
            ObDereferenceObject(*Object);
        }
        else
        {
            /* Registry ACL audit: what Windows would decide (logged only, the open stands) */
            CmpShadowAccessCheck(Kcb,
                                 NULL,
                                 CM_REGACL_OP_OPEN,
                                 AccessState,
                                 AclDesired,
                                 AclPrevious,
                                 AccessState->PreviouslyGrantedAccess,
                                 AccessMode,
                                 AclOptions);
        }

        /*
         * We are done, the lock we are holding will be released
         * once the registry parsing is done.
         */
        KeyBody->KcbLocked = FALSE;
    }
    else
    {
        /* Failed, dereference the KCB */
        CmpDereferenceKeyControlBlockWithLock(Kcb, FALSE);
    }

    /* Return status */
    return Status;
}

NTSTATUS
NTAPI
CmpCreateLinkNode(IN PHHIVE Hive,
                  IN HCELL_INDEX Cell,
                  IN PACCESS_STATE AccessState,
                  IN UNICODE_STRING Name,
                  IN KPROCESSOR_MODE AccessMode,
                  IN ULONG CreateOptions,
                  IN PCM_PARSE_CONTEXT Context,
                  IN PCM_KEY_CONTROL_BLOCK ParentKcb,
                  IN PULONG KcbsLocked,
                  OUT PVOID *Object)
{
    NTSTATUS Status;
    HCELL_INDEX KeyCell, LinkCell, ChildCell;
    PCM_KEY_BODY KeyBody;
    LARGE_INTEGER TimeStamp;
    PCM_KEY_NODE KeyNode;
    PCM_KEY_CONTROL_BLOCK Kcb = ParentKcb;

    /* Link nodes only allowed on the master */
    if (Hive != &CmiVolatileHive->Hive)
    {
        /* Fail */
        DPRINT1("Invalid link node attempt\n");
        return STATUS_ACCESS_DENIED;
    }

    /* Make sure the KCB is locked and lock the flusher */
    CMP_ASSERT_KCB_LOCK(ParentKcb);
    CmpLockHiveFlusherShared((PCMHIVE)Hive);
    CmpLockHiveFlusherShared((PCMHIVE)Context->ChildHive.KeyHive);

    /* Bail out on read-only KCBs */
    if (ParentKcb->ExtFlags & CM_KCB_READ_ONLY_KEY)
    {
        Status = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    /* Check if the parent is being deleted */
    if (ParentKcb->Delete)
    {
        /* It is, quit */
        ASSERT(FALSE);
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Exit;
    }

    /* Allocate a link node */
    LinkCell = HvAllocateCell(Hive,
                              FIELD_OFFSET(CM_KEY_NODE, Name) +
                              CmpNameSize(Hive, &Name),
                              Stable,
                              HCELL_NIL);
    if (LinkCell == HCELL_NIL)
    {
        /* Fail */
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    /* Get the key cell */
    KeyCell = Context->ChildHive.KeyCell;
    if (KeyCell != HCELL_NIL)
    {
        /* Hive exists! */
        ChildCell = KeyCell;

        /* Get the node data */
        KeyNode = (PCM_KEY_NODE)HvGetCell(Context->ChildHive.KeyHive, ChildCell);
        if (!KeyNode)
        {
            /* Fail */
            ASSERT(FALSE);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        /* Fill out the data */
        KeyNode->Parent = LinkCell;
        KeyNode->Flags |= KEY_HIVE_ENTRY | KEY_NO_DELETE;
        HvReleaseCell(Context->ChildHive.KeyHive, ChildCell);

        /* Now open the key cell */
        KeyNode = (PCM_KEY_NODE)HvGetCell(Context->ChildHive.KeyHive, KeyCell);
        if (!KeyNode)
        {
            /* Fail */
            ASSERT(FALSE);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        /* Open the parent */
        Status = CmpDoOpen(Context->ChildHive.KeyHive,
                           KeyCell,
                           KeyNode,
                           AccessState,
                           AccessMode,
                           CreateOptions,
                           NULL,
                           CMP_CREATE_KCB_KCB_LOCKED,
                           &Kcb,
                           KcbsLocked,
                           &Name,
                           Context->CreateOptions,
                           Object);
        HvReleaseCell(Context->ChildHive.KeyHive, KeyCell);
    }
    else
    {
        /* Do the actual create operation */
        Status = CmpDoCreateChild(Context->ChildHive.KeyHive,
                                  Cell,
                                  NULL,
                                  AccessState,
                                  &Name,
                                  AccessMode,
                                  Context,
                                  ParentKcb,
                                  KEY_HIVE_ENTRY | KEY_NO_DELETE,
                                  &ChildCell,
                                  Object);
        if (NT_SUCCESS(Status))
        {
            /* Setup root pointer */
            Context->ChildHive.KeyHive->BaseBlock->RootCell = ChildCell;

            /* Registry ACL audit (hive links are made from kernel mode, so normally not checked) */
            CmpShadowAccessCheck(ParentKcb, &Name, CM_REGACL_OP_LINKNODE, AccessState,
                                 KEY_CREATE_SUB_KEY, 0, 0, AccessMode, Context->CreateOptions);
        }
    }

    /* Check if open or create suceeded */
    if (NT_SUCCESS(Status))
    {
        /* Mark the cell dirty */
        HvMarkCellDirty(Context->ChildHive.KeyHive, ChildCell, FALSE);

        /* Get the key node */
        KeyNode = (PCM_KEY_NODE)HvGetCell(Context->ChildHive.KeyHive, ChildCell);
        if (!KeyNode)
        {
            /* Fail */
            ASSERT(FALSE);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        /* Release it */
        HvReleaseCell(Context->ChildHive.KeyHive, ChildCell);

        /* Set the parent and flags */
        KeyNode->Parent = LinkCell;
        KeyNode->Flags |= KEY_HIVE_ENTRY | KEY_NO_DELETE;

        /* Get the link node */
        KeyNode = (PCM_KEY_NODE)HvGetCell(Hive, LinkCell);
        if (!KeyNode)
        {
            /* Fail */
            ASSERT(FALSE);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        /* Set it up */
        KeyNode->Signature = CM_LINK_NODE_SIGNATURE;
        KeyNode->Flags = KEY_HIVE_EXIT | KEY_NO_DELETE;
        KeyNode->Parent = Cell;
        KeyNode->NameLength = CmpCopyName(Hive, KeyNode->Name, &Name);
        if (KeyNode->NameLength < Name.Length) KeyNode->Flags |= KEY_COMP_NAME;
        KeQuerySystemTime(&TimeStamp);
        KeyNode->LastWriteTime = TimeStamp;

        /* Clear out the rest */
        KeyNode->SubKeyCounts[Stable] = 0;
        KeyNode->SubKeyCounts[Volatile] = 0;
        KeyNode->SubKeyLists[Stable] = HCELL_NIL;
        KeyNode->SubKeyLists[Volatile] = HCELL_NIL;
        KeyNode->ValueList.Count = 0;
        KeyNode->ValueList.List = HCELL_NIL;
        KeyNode->ClassLength = 0;
        KeyNode->Class = HCELL_NIL;

        /* A link node (a hive exit) has no descriptor: the hive root it leads to has */
        KeyNode->Security = HCELL_NIL;

        /* Reference the root node */
        KeyNode->ChildHiveReference.KeyHive = Context->ChildHive.KeyHive;
        KeyNode->ChildHiveReference.KeyCell = ChildCell;
        HvReleaseCell(Hive, LinkCell);

        /* Get the parent node */
        KeyNode = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
        if (!KeyNode)
        {
            /* Fail */
            ASSERT(FALSE);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        /* Now add the subkey */
        if (!CmpAddSubKey(Hive, Cell, LinkCell))
        {
            /*
             * Not linked (no cell for the master hive's index): give the link
             * node back. The child hive's root was only pointed at it
             * (Parent), so the hive load fails as for any other error here;
             * the caller then drops the hive.
             */
            HvReleaseCell(Hive, Cell);
            HvFreeCell(Hive, LinkCell);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        /* Get the key body */
        KeyBody = (PCM_KEY_BODY)*Object;

        /* Clean up information on this subkey */
        CmpCleanUpSubKeyInfo(KeyBody->KeyControlBlock->ParentKcb);

        /* Sanity checks */
        ASSERT(KeyBody->KeyControlBlock->ParentKcb->KeyCell == Cell);
        ASSERT(KeyBody->KeyControlBlock->ParentKcb->KeyHive == Hive);
        ASSERT(KeyBody->KeyControlBlock->ParentKcb->KcbMaxNameLen == KeyNode->MaxNameLen);

        /* Update the timestamp */
        KeQuerySystemTime(&TimeStamp);
        KeyNode->LastWriteTime = TimeStamp;
        KeyBody->KeyControlBlock->ParentKcb->KcbLastWriteTime = TimeStamp;

        /* Check if we need to update name maximum */
        if (KeyNode->MaxNameLen < Name.Length)
        {
            /* Do it */
            KeyNode->MaxNameLen = Name.Length;
            KeyBody->KeyControlBlock->ParentKcb->KcbMaxNameLen = Name.Length;
        }

        /* Check if we need to update class length maximum */
        if (KeyNode->MaxClassLen < Context->Class.Length)
        {
            /* Update it */
            KeyNode->MaxClassLen = Context->Class.Length;
        }

        /* Release the cell */
        HvReleaseCell(Hive, Cell);
    }
    else
    {
        /* Release the link cell */
        HvReleaseCell(Hive, LinkCell);
    }

Exit:
    /* Release the flusher locks and return status */
    CmpUnlockHiveFlusher((PCMHIVE)Context->ChildHive.KeyHive);
    CmpUnlockHiveFlusher((PCMHIVE)Hive);
    return Status;
}

VOID
NTAPI
CmpHandleExitNode(IN OUT PHHIVE *Hive,
                  IN OUT HCELL_INDEX *Cell,
                  IN OUT PCM_KEY_NODE *KeyNode,
                  IN OUT PHHIVE *ReleaseHive,
                  IN OUT HCELL_INDEX *ReleaseCell)
{
    /* Check if we have anything to release */
    if (*ReleaseCell != HCELL_NIL)
    {
        /* Release it */
        ASSERT(*ReleaseHive != NULL);
        HvReleaseCell(*ReleaseHive, *ReleaseCell);
    }

    /* Get the link references */
    *Hive = (*KeyNode)->ChildHiveReference.KeyHive;
    *Cell = (*KeyNode)->ChildHiveReference.KeyCell;

    /* Get the new node */
    *KeyNode = (PCM_KEY_NODE)HvGetCell(*Hive, *Cell);
    if (*KeyNode)
    {
        /* Set the new release values */
        *ReleaseCell = *Cell;
        *ReleaseHive = *Hive;
    }
    else
    {
        /* Nothing to release */
        *ReleaseCell = HCELL_NIL;
        *ReleaseHive = NULL;
    }
}

/**
 * @brief
 * Computes the hashes of each subkey in key path name
 * and stores them in a hash stack for cache lookup.
 *
 * @param[in] RemainingName
 * A Unicode string structure consisting of the remaining
 * registry key path name.
 *
 * @param[in] ConvKey
 * The hash convkey of the current KCB to be supplied.
 *
 * @param[in,out] HashCacheStack
 * An array stack. This function uses this array to store
 * all the computed hashes of a key pathname.
 *
 * @param[out] TotalSubKeys
 * The number of total subkeys that have been found, returned
 * by this function to the caller. If no subkey levels are found
 * the function returns 0.
 *
 * @return
 * Returns the number of remaining subkey levels to caller.
 * If no subkey levels are found then this function returns 0.
 */
static
ULONG
CmpComputeHashValue(
    _In_ PUNICODE_STRING RemainingName,
    _In_ ULONG ConvKey,
    _Inout_ PCM_HASH_CACHE_STACK HashCacheStack,
    _Out_ PULONG TotalSubKeys)
{
    ULONG CopyConvKey;
    ULONG SubkeysInTotal;
    ULONG RemainingSubkeysInTotal;
    PWCHAR RemainingNameBuffer;
    USHORT RemainingNameLength;
    USHORT KeyNameLength;

    /* Don't compute the hashes on a NULL remaining name */
    RemainingNameBuffer = RemainingName->Buffer;
    RemainingNameLength = RemainingName->Length;
    if (RemainingNameLength == 0)
    {
        *TotalSubKeys = 0;
        return 0;
    }

    /* Skip any leading separator */
    while (RemainingNameLength >= sizeof(WCHAR) &&
           *RemainingNameBuffer == OBJ_NAME_PATH_SEPARATOR)
    {
        RemainingNameBuffer++;
        RemainingNameLength -= sizeof(WCHAR);
    }

    /* Now set up the hash stack entries and compute the hashes */
    SubkeysInTotal = 0;
    RemainingSubkeysInTotal = 0;
    KeyNameLength = 0;
    CopyConvKey = ConvKey;
    HashCacheStack[RemainingSubkeysInTotal].NameOfKey.Buffer = RemainingNameBuffer;
    while (RemainingNameLength > 0)
    {
        /* Is this character a separator? */
        if (*RemainingNameBuffer != OBJ_NAME_PATH_SEPARATOR)
        {
            /* It's not, add it to the hash */
            CopyConvKey = COMPUTE_HASH_CHAR(CopyConvKey, *RemainingNameBuffer);

            /* Go to the next character (add up the length of the character as well) */
            RemainingNameBuffer++;
            KeyNameLength += sizeof(WCHAR);
            RemainingNameLength -= sizeof(WCHAR);

            /*
             * We are at the end of the key name path. Take into account
             * the last character and if we still have space in the hash
             * stack, add it up in the remaining list.
             */
            if (RemainingNameLength == 0)
            {
                if (RemainingSubkeysInTotal < CMP_SUBKEY_LEVELS_DEPTH_LIMIT)
                {
                    HashCacheStack[RemainingSubkeysInTotal].NameOfKey.Length = KeyNameLength;
                    HashCacheStack[RemainingSubkeysInTotal].NameOfKey.MaximumLength = KeyNameLength;
                    HashCacheStack[RemainingSubkeysInTotal].ConvKey = CopyConvKey;
                    RemainingSubkeysInTotal++;
                }

                SubkeysInTotal++;
            }
        }
        else
        {
            /* Skip any leading separator */
            while (RemainingNameLength >= sizeof(WCHAR) &&
                   *RemainingNameBuffer == OBJ_NAME_PATH_SEPARATOR)
            {
                RemainingNameBuffer++;
                RemainingNameLength -= sizeof(WCHAR);
            }

            /*
             * It would be possible that a malformed key pathname may be passed
             * to the registry parser such as a path with only separators like
             * "\\\\" for example. This would trick the function into believing
             * the key path has subkeys albeit that is not the case.
             */
            ASSERT(RemainingNameLength != 0);

            /* Take into account this subkey */
            SubkeysInTotal++;

            /* And add it up to the hash stack */
            if (RemainingSubkeysInTotal < CMP_SUBKEY_LEVELS_DEPTH_LIMIT)
            {
                HashCacheStack[RemainingSubkeysInTotal].NameOfKey.Length = KeyNameLength;
                HashCacheStack[RemainingSubkeysInTotal].NameOfKey.MaximumLength = KeyNameLength;
                HashCacheStack[RemainingSubkeysInTotal].ConvKey = CopyConvKey;

                RemainingSubkeysInTotal++;
                KeyNameLength = 0;

                /*
                 * Precaution check -- we have added up a remaining
                 * subkey above but we must ensure we still have space
                 * to hold up the new subkey for which we will compute
                 * the hashes, so that we don't blow up the hash stack.
                 */
                if (RemainingSubkeysInTotal < CMP_SUBKEY_LEVELS_DEPTH_LIMIT)
                {
                    HashCacheStack[RemainingSubkeysInTotal].NameOfKey.Buffer = RemainingNameBuffer;
                }
            }
        }
    }

    *TotalSubKeys = SubkeysInTotal;
    return RemainingSubkeysInTotal;
}

/**
 * @brief
 * Compares each subkey's hash and name with those
 * captured in the hash cache stack.
 *
 * @param[in] HashCacheStack
 * A pointer to a hash cache stack array filled with
 * subkey hashes and names for comparison.
 *
 * @param[in] CurrentKcb
 * A pointer to the currently given KCB.
 *
 * @param[in] RemainingSubkeys
 * The remaining subkey levels to be supplied.
 *
 * @param[out] ParentKcb
 * A pointer to the parent KCB returned to the caller.
 * This parameter points to the parent of the current
 * KCB if all the subkeys match, otherwise it points
 * to the actual current KCB.
 *
 * @return
 * Returns TRUE if all the subkey levels match, otherwise
 * FALSE is returned.
 */
static
BOOLEAN
CmpCompareSubkeys(
    _In_ PCM_HASH_CACHE_STACK HashCacheStack,
    _In_ PCM_KEY_CONTROL_BLOCK CurrentKcb,
    _In_ ULONG RemainingSubkeys,
    _Out_ PCM_KEY_CONTROL_BLOCK *ParentKcb)
{
    LONG HashStackIndex;
    LONG Result;
    PCM_NAME_CONTROL_BLOCK NameBlock;
    UNICODE_STRING CurrentNameBlock;

    ASSERT(CurrentKcb != NULL);

    /* Loop each hash and check that they match */
    HashStackIndex = RemainingSubkeys;
    while (HashStackIndex >= 0)
    {
        /* Does the subkey hash match? */
        if (CurrentKcb->ConvKey != HashCacheStack[HashStackIndex].ConvKey)
        {
            *ParentKcb = CurrentKcb;
            return FALSE;
        }

        /* Compare the subkey string, is the name compressed? */
        NameBlock = CurrentKcb->NameBlock;
        if (NameBlock->Compressed)
        {
            Result = CmpCompareCompressedName(&HashCacheStack[HashStackIndex].NameOfKey,
                                              NameBlock->Name,
                                              NameBlock->NameLength);
        }
        else
        {
            CurrentNameBlock.Buffer = NameBlock->Name;
            CurrentNameBlock.Length = NameBlock->NameLength;
            CurrentNameBlock.MaximumLength = NameBlock->NameLength;

            Result = RtlCompareUnicodeString(&HashCacheStack[HashStackIndex].NameOfKey,
                                             &CurrentNameBlock,
                                             TRUE);
        }

        /* Do the subkey names match? */
        if (Result)
        {
            *ParentKcb = CurrentKcb;
            return FALSE;
        }

        /* Go to the next subkey hash */
        HashStackIndex--;
    }

    /* All the subkeys match */
    *ParentKcb = CurrentKcb->ParentKcb;
    return TRUE;
}

/**
 * @brief
 * Removes the subkeys on a remaining key pathname.
 *
 * @param[in] HashCacheStack
 * A pointer to a hash cache stack array filled with
 * subkey hashes and names.
 *
 * @param[in] RemainingSubkeys
 * The remaining subkey levels to be supplied.
 *
 * @param[in,out] RemainingName
 * A Unicode string structure consisting of the remaining
 * registry key path name, where the subkeys of such path
 * are to be removed.
 */
static
VOID
CmpRemoveSubkeysInRemainingName(
    _In_ PCM_HASH_CACHE_STACK HashCacheStack,
    _In_ ULONG RemainingSubkeys,
    _Inout_ PUNICODE_STRING RemainingName)
{
    ULONG HashStackIndex = 0;

    /* Skip any leading separator on matching name */
    while (RemainingName->Length >= sizeof(WCHAR) &&
           RemainingName->Buffer[0] == OBJ_NAME_PATH_SEPARATOR)
    {
        RemainingName->Buffer++;
        RemainingName->Length -= sizeof(WCHAR);
    }

    /* Skip the subkeys as well */
    while (HashStackIndex <= RemainingSubkeys)
    {
        RemainingName->Buffer += HashCacheStack[HashStackIndex].NameOfKey.Length / sizeof(WCHAR);
        RemainingName->Length -= HashCacheStack[HashStackIndex].NameOfKey.Length;

        /* Skip any leading separator */
        while (RemainingName->Length >= sizeof(WCHAR) &&
               RemainingName->Buffer[0] == OBJ_NAME_PATH_SEPARATOR)
        {
            RemainingName->Buffer++;
            RemainingName->Length -= sizeof(WCHAR);
        }

        /* Go to the next hash */
        HashStackIndex++;
    }
}

/**
 * @brief
 * Looks up in the pool cache for key pathname that matches
 * with one in the said cache and returns a KCB pointing
 * to that name. This function performs locking of KCBs
 * during cache lookup.
 *
 * @param[in] HashCacheStack
 * A pointer to a hash cache stack array filled with
 * subkey hashes and names.
 *
 * @param[in] LockKcbsExclusive
 * If set to TRUE, the KCBs are locked exclusively by the
 * calling thread, otherwise they are locked in shared mode.
 * See Remarks for further information.
 *
 * @param[in] TotalRemainingSubkeys
 * The total remaining subkey levels to be supplied.
 *
 * @param[in,out] RemainingName
 * A Unicode string structure consisting of the remaining
 * registry key path name. The remaining name is updated
 * by the function if a key pathname is found in cache.
 *
 * @param[in,out] OuterStackArray
 * A pointer to an array that lives on the caller's stack.
 * The expected size of the array is up to 32 elements,
 * which is the imposed limit by CMP_HASH_STACK_LIMIT.
 * This limit also corresponds to the maximum depth of
 * subkey levels.
 *
 * @param[in,out] Kcb
 * A pointer to a KCB, this KCB is changed if the key pathname
 * is found in cache.
 *
 * @param[out] Hive
 * A pointer to a hive, this hive is changed if the key pathname
 * is found in cache.
 *
 * @param[out] Cell
 * A pointer to a cell, this cell is changed if the key pathname
 * is found in cache.
 *
 * @param[out] MatchRemainSubkeyLevel
 * A pointer to match subkey levels returned by the function.
 * If no match levels are found, this is 0.
 *
 * @return
 * Returns STATUS_SUCCESS if cache lookup has completed successfully.
 * STATUS_OBJECT_NAME_NOT_FOUND is returned if the current KCB of
 * the key pathname has been deleted. STATUS_RETRY is returned if
 * at least the current KCB or its parent have been deleted, or if
 * the KCB found needs an exclusive lock to be referenced, and a
 * cache lookup must be retried again with exclusive lock.
 * STATUS_UNSUCCESSFUL is returned if a KCB is referenced too many
 * times.
 *
 * @remarks
 * The function attempts to do a cache lookup with a shared lock
 * on KCBs so that other threads can simultaneously get access
 * to these KCBs. When the captured KCB is being deleted on us
 * we have to retry a lookup with exclusive look so that no other
 * threads will mess with the KCBs and perform appropriate actions
 * if a KCB is deleted.
 */
static
NTSTATUS
CmpLookInCache(
    _In_ PCM_HASH_CACHE_STACK HashCacheStack,
    _In_ BOOLEAN LockKcbsExclusive,
    _In_ ULONG TotalRemainingSubkeys,
    _Inout_ PUNICODE_STRING RemainingName,
    _Inout_ PULONG OuterStackArray,
    _Inout_ PCM_KEY_CONTROL_BLOCK *Kcb,
    _Out_ PHHIVE *Hive,
    _Out_ PHCELL_INDEX Cell,
    _Out_ PULONG MatchRemainSubkeyLevel)
{
    LONG RemainingSubkeys;
    ULONG TotalLevels;
    BOOLEAN SubkeysMatch;
    PCM_KEY_CONTROL_BLOCK CurrentKcb, ParentKcb;
    PCM_KEY_HASH HashEntry = NULL;
    BOOLEAN KeyFoundInCache = FALSE;
    PULONG LockedKcbs = NULL;

    /* Reference the KCB */
    if (!CmpReferenceKeyControlBlock(*Kcb))
    {
        /* This key is opened too many times, bail out */
        DPRINT1("Could not reference the KCB, too many references (KCB 0x%p)\n", Kcb);
        return STATUS_UNSUCCESSFUL;
    }

    /* Prepare to lock the KCBs */
    LockedKcbs = CmpBuildAndLockKcbArray(HashCacheStack,
                                         LockKcbsExclusive ? CMP_LOCK_KCB_ARRAY_EXCLUSIVE : CMP_LOCK_KCB_ARRAY_SHARED,
                                         *Kcb,
                                         OuterStackArray,
                                         TotalRemainingSubkeys,
                                         0);
    NT_ASSERT(LockedKcbs);

    /* Lookup in the cache */
    RemainingSubkeys = TotalRemainingSubkeys - 1;
    TotalLevels = TotalRemainingSubkeys + (*Kcb)->TotalLevels + 1;
    while (RemainingSubkeys >= 0)
    {
        /* Get the hash entry from the cache */
        HashEntry = GET_HASH_ENTRY(CmpCacheTable, HashCacheStack[RemainingSubkeys].ConvKey)->Entry;

        /* Take one level down as we are processing this hash entry */
        TotalLevels--;

        while (HashEntry != NULL)
        {
            /* Validate this hash and obtain the current KCB */
            ASSERT_VALID_HASH(HashEntry);
            CurrentKcb = CONTAINING_RECORD(HashEntry, CM_KEY_CONTROL_BLOCK, KeyHash);

            /* Does this KCB have matching levels? */
            if (TotalLevels == CurrentKcb->TotalLevels)
            {
                /*
                 * We have matching subkey levels but don't directly assume we have
                 * a matching key path in cache. Start comparing each subkey.
                 */
                SubkeysMatch = CmpCompareSubkeys(HashCacheStack,
                                                 CurrentKcb,
                                                 RemainingSubkeys,
                                                 &ParentKcb);
                if (SubkeysMatch)
                {
                    /* All subkeys match, now check if the base KCB matches with parent */
                    if (*Kcb == ParentKcb)
                    {
                        /* Is the KCB marked as deleted? */
                        if (CurrentKcb->Delete ||
                            CurrentKcb->ParentKcb->Delete)
                        {
                            /*
                             * Either the current or its parent KCB is marked
                             * but we had a shared lock so probably a naughty
                             * thread was deleting it. Retry doing a cache
                             * lookup again with exclusive lock.
                             */
                            if (!LockKcbsExclusive)
                            {
                                CmpUnLockKcbArray(LockedKcbs);
                                CmpDereferenceKeyControlBlock(*Kcb);
                                DPRINT1("The current KCB or its parent is deleted, retrying looking in the cache\n");
                                return STATUS_RETRY;
                            }

                            /* We're under an exclusive lock, is the KCB deleted yet? */
                            if (CurrentKcb->Delete)
                            {
                                /* The KCB is gone, the key should no longer belong in the cache */
                                CmpRemoveKeyControlBlock(CurrentKcb);
                                CmpUnLockKcbArray(LockedKcbs);
                                CmpDereferenceKeyControlBlock(*Kcb);
                                DPRINT1("The current KCB is deleted (KCB 0x%p)\n", CurrentKcb);
                                return STATUS_OBJECT_NAME_NOT_FOUND;
                            }

                            /*
                             * The parent is deleted so it must be that somebody created
                             * a fake key. Assert ourselves that is the case.
                             */
                            ASSERT(CurrentKcb->ExtFlags & CM_KCB_KEY_NON_EXIST);

                            /* Remove this KCB out of cache if someone still uses it */
                            if (CurrentKcb->RefCount != 0)
                            {
                                CurrentKcb->Delete = TRUE;
                                CmpRemoveKeyControlBlock(CurrentKcb);
                            }
                            else
                            {
                                /* Otherwise expunge it */
                                CmpRemoveFromDelayedClose(CurrentKcb);
                                CmpCleanUpKcbCacheWithLock(CurrentKcb, FALSE);
                            }

                            /* Stop looking for next hashes as the KCB is kaput */
                            break;
                        }

                        /*
                         * Referencing a KCB that has no references or sits in
                         * the delayed close table needs its hash lock held
                         * exclusively. Do not let CmpReferenceKeyControlBlock
                         * convert it below: that releases and re-acquires one
                         * lock of the sorted array while the others stay held,
                         * out of order. With push locks preferring a queued
                         * exclusive waiter over new shared acquires, that
                         * deadlocks against a thread that locks an array
                         * exclusively in order. Retry the lookup with the whole
                         * array locked exclusively instead, before the remaining
                         * name is consumed.
                         */
                        if (!LockKcbsExclusive &&
                            CmpKcbReferenceNeedsExclusiveLock(CurrentKcb))
                        {
                            CmpUnLockKcbArray(LockedKcbs);
                            CmpDereferenceKeyControlBlock(*Kcb);
                            DPRINT("The found KCB needs an exclusive lock to be referenced, retrying looking in the cache\n");
                            return STATUS_RETRY;
                        }

                        /* We finally found the key in cache, acknowledge it */
                        KeyFoundInCache = TRUE;

                        /* Remove the subkeys in the remaining name and stop looking in the cache */
                        CmpRemoveSubkeysInRemainingName(HashCacheStack, RemainingSubkeys, RemainingName);
                        break;
                    }
                }
            }

            /* Go to the next hash */
            HashEntry = HashEntry->NextHash;
        }

        /* Stop looking in cache if we found the matching key */
        if (KeyFoundInCache)
        {
            DPRINT("Key found in cache, stop looking\n");
            break;
        }

        /* Keep looking in the cache until we run out of remaining subkeys */
        RemainingSubkeys--;
    }

    /* Return the matching subkey levels */
    *MatchRemainSubkeyLevel = RemainingSubkeys + 1;

    /* We have to update the KCB if the key was found in cache */
    if (KeyFoundInCache)
    {
        /*
         * Reference the new KCB before dropping the locks.
         */
        if (!CmpReferenceKeyControlBlock(CurrentKcb))
        {
            /* This key is opened too many times, bail out */
            DPRINT1("Could not reference the KCB, too many references (KCB 0x%p)\n", CurrentKcb);

            /*
             * Make sure to unlock the KCBs and release the KCB reference we took
             * at the start of the function, so that the caller sees a clean state.
             */
            CmpUnLockKcbArray(LockedKcbs);
            CmpDereferenceKeyControlBlock(*Kcb);
            return STATUS_UNSUCCESSFUL;
        }

        /*
         * Dereference the prior KCB that we no longer need
         * and switch to the newly referenced one.
         */
        CmpUnLockKcbArray(LockedKcbs);
        CmpDereferenceKeyControlBlock(*Kcb);
        *Kcb = CurrentKcb;

        /* Update hive and cell data from current KCB */
        *Hive = CurrentKcb->KeyHive;
        *Cell = CurrentKcb->KeyCell;
        return STATUS_SUCCESS;
    }

    /* Unlock the KCBs */
    CmpUnLockKcbArray(LockedKcbs);
    return STATUS_SUCCESS;
}

/**
 * @brief
 * Builds a hash stack cache and looks up in the
 * pool cache for a matching key pathname.
 *
 * @param[in] ParseObject
 * A pointer to a parse object, acting as a key
 * body. This parameter is unused.
 *
 * @param[in,out] Kcb
 * A pointer to a KCB. This KCB is used by the
 * registry parser after hash stack and cache
 * lookup are done. This KCB might change if the
 * key is found to be cached in the cache pool.
 *
 * @param[in] Current
 * The current remaining key pathname.
 *
 * @param[out] Hive
 * A pointer to a registry hive, returned by the caller.
 *
 * @param[out] Cell
 * A pointer to a hive cell, returned by the caller.
 *
 * @param[out] TotalRemainingSubkeys
 * A pointer to a number of total remaining subkey levels,
 * returned by the caller. This can be 0 if no subkey levels
 * have been found.
 *
 * @param[out] MatchRemainSubkeyLevel
 * A pointer to a number of remaining subkey levels that match,
 * returned by the caller. This can be 0 if no matching levels
 * are found.
 *
 * @param[out] TotalSubkeys
 * A pointer to a number of total subkeys. This can be 0 if no
 * subkey levels are found. By definition, both MatchRemainSubkeyLevel
 * and TotalRemainingSubkeys are 0 as well.
 *
 * @param[in,out] OuterStackArray
 * A pointer to an array that lives on the caller's stack.
 * The expected size of the array is up to 32 elements,
 * which is the imposed limit by CMP_HASH_STACK_LIMIT.
 * This limit also corresponds to the maximum depth of
 * subkey levels.
 *
 * @param[out] LockedKcbs
 * A pointer to an array of locked KCBs, returned by the caller.
 *
 * @return
 * Returns STATUS_SUCCESS if all the operations have succeeded without
 * problems. STATUS_NAME_TOO_LONG is returned if the key pathname has
 * too many subkey levels (more than 32 levels deep). A failure NTSTATUS
 * code is returned otherwise. Refer to CmpLookInCache documentation
 * for more information about other returned status codes.
 * STATUS_UNSUCCESSFUL is returned if a KCB is referenced too many times.
 */
NTSTATUS
NTAPI
CmpBuildHashStackAndLookupCache(
    _In_ PCM_KEY_BODY ParseObject,
    _Inout_ PCM_KEY_CONTROL_BLOCK *Kcb,
    _In_ PUNICODE_STRING Current,
    _Out_ PHHIVE *Hive,
    _Out_ PHCELL_INDEX Cell,
    _Out_ PULONG TotalRemainingSubkeys,
    _Out_ PULONG MatchRemainSubkeyLevel,
    _Out_ PULONG TotalSubkeys,
    _Inout_ PULONG OuterStackArray,
    _Out_ PULONG *LockedKcbs)
{
    NTSTATUS Status;
    ULONG ConvKey;
    ULONG SubkeysInTotal, RemainingSubkeysInTotal, MatchRemainingSubkeys;
    CM_HASH_CACHE_STACK HashCacheStack[CMP_SUBKEY_LEVELS_DEPTH_LIMIT];

    /* Make sure it's not a dead KCB */
    ASSERT((*Kcb)->RefCount > 0);

    /* Lock the registry */
    CmpLockRegistry();

    /* Calculate hash values for every subkey this key path has */
    ConvKey = (*Kcb)->ConvKey;
    RemainingSubkeysInTotal = CmpComputeHashValue(Current,
                                                  ConvKey,
                                                  HashCacheStack,
                                                  &SubkeysInTotal);

    /* This key path has too many subkeys */
    if (SubkeysInTotal > CMP_SUBKEY_LEVELS_DEPTH_LIMIT)
    {
        DPRINT1("The key path has too many subkeys - %lu\n", SubkeysInTotal);
        *LockedKcbs = NULL;
        return STATUS_NAME_TOO_LONG;
    }

    /* Return hive and cell data */
    *Hive = (*Kcb)->KeyHive;
    *Cell = (*Kcb)->KeyCell;

    /* Do we have any subkeys? */
    if (!RemainingSubkeysInTotal && !SubkeysInTotal)
    {
        /*
         * We don't have any subkeys nor remaining levels, the
         * KCB points to the actual key. Lock it.
         */
        if (!CmpReferenceKeyControlBlock(*Kcb))
        {
            /* This key is opened too many times, bail out */
            DPRINT1("Could not reference the KCB, too many references (KCB 0x%p)\n", Kcb);
            return STATUS_UNSUCCESSFUL;
        }

        CmpAcquireKcbLockSharedByIndex(GET_HASH_INDEX(ConvKey));

        /* Add this KCB in the array of locked KCBs */
        OuterStackArray[0] = 1;
        OuterStackArray[1] = GET_HASH_INDEX(ConvKey);
        *LockedKcbs = OuterStackArray;

        /* And return all the subkey level counters */
        *TotalRemainingSubkeys = RemainingSubkeysInTotal;
        *MatchRemainSubkeyLevel = 0;
        *TotalSubkeys = SubkeysInTotal;
        return STATUS_SUCCESS;
    }

    /* Lookup in the cache */
    Status = CmpLookInCache(HashCacheStack,
                            FALSE,
                            RemainingSubkeysInTotal,
                            Current,
                            OuterStackArray,
                            Kcb,
                            Hive,
                            Cell,
                            &MatchRemainingSubkeys);
    if (!NT_SUCCESS(Status))
    {
        /* Bail out if cache lookup failed for other reasons */
        if (Status != STATUS_RETRY)
        {
            DPRINT1("CmpLookInCache() failed (Status 0x%lx)\n", Status);
            *LockedKcbs = NULL;
            return Status;
        }

        /* Retry looking in the cache but with KCBs locked exclusively */
        Status = CmpLookInCache(HashCacheStack,
                                TRUE,
                                RemainingSubkeysInTotal,
                                Current,
                                OuterStackArray,
                                Kcb,
                                Hive,
                                Cell,
                                &MatchRemainingSubkeys);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("CmpLookInCache() failed after retry (Status 0x%lx)\n", Status);
            *LockedKcbs = NULL;
            return Status;
        }
    }

    /*
     * Check if we have a full match of remaining levels.
     *
     * FIXME: It is possible we can catch a fake key from the cache
     * when we did the lookup, in such case we should not do any
     * locking as such KCB does not point to any real information.
     * Currently ReactOS doesn't create fake KCBs so we are good
     * for now.
     */
    if (RemainingSubkeysInTotal == MatchRemainingSubkeys)
    {
        /*
         * Just simply lock this KCB as it points to the full
         * subkey levels in cache.
         */
        CmpAcquireKcbLockSharedByIndex(GET_HASH_INDEX((*Kcb)->ConvKey));
        OuterStackArray[0] = 1;
        OuterStackArray[1] = GET_HASH_INDEX((*Kcb)->ConvKey);
        *LockedKcbs = OuterStackArray;
    }
    else
    {
        /*
         * We only have a partial match so other subkey levels
         * have each KCB. Simply just lock them.
         */
        *LockedKcbs = CmpBuildAndLockKcbArray(HashCacheStack,
                                              CMP_LOCK_KCB_ARRAY_EXCLUSIVE,
                                              *Kcb,
                                              OuterStackArray,
                                              RemainingSubkeysInTotal,
                                              MatchRemainingSubkeys);
        NT_ASSERT(*LockedKcbs);
    }

    /* Return all the subkey level counters */
    *TotalRemainingSubkeys = RemainingSubkeysInTotal;
    *MatchRemainSubkeyLevel = MatchRemainingSubkeys;
    *TotalSubkeys = SubkeysInTotal;
    return Status;
}

#ifdef BUILD_WOW64_ENABLED
/* Reparse inside the configuration manager, after object-name capture. Both
 * native KEY_WOW64_32KEY callers and the user-mode WoW64 translator use this
 * path, with the original access state and security checks left in place. */
static BOOLEAN
CmpWow64Prefix(PCUNICODE_STRING Name, PCUNICODE_STRING Prefix)
{
    return RtlPrefixUnicodeString(Prefix, Name, TRUE) &&
           (Name->Length == Prefix->Length || Name->Buffer[Prefix->Length / sizeof(WCHAR)] == L'\\');
}

#include <wow64reg.h>

static const PCWSTR CmpWow64RedirectedClasses[] = {
    L"\\CLSID", L"\\DirectShow", L"\\Interface", L"\\Media Type", L"\\MediaFoundation"
};

static BOOLEAN
CmpWow64Path(PCUNICODE_STRING Name, PCWSTR Path)
{
    UNICODE_STRING Prefix;
    RtlInitUnicodeString(&Prefix, Path);
    return CmpWow64Prefix(Name, &Prefix);
}

/* Return the insertion point in bytes, or zero for a shared/physical path. */
static ULONG
CmpWow64KeyOffset(PCUNICODE_STRING Name, PULONG Cut)
{
    static const UNICODE_STRING Software = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE");
    static const UNICODE_STRING Users = RTL_CONSTANT_STRING(L"\\REGISTRY\\USER\\");
    UNICODE_STRING Tail, Component;
    ULONG Offset, i;
    BOOLEAN Machine = CmpWow64Prefix(Name, &Software);

    if (Machine)
    {
        Offset = Software.Length;
    }
    else if (RtlPrefixUnicodeString(&Users, Name, TRUE))
    {
        /* HKCU's Classes tree and a separately mounted <SID>_Classes hive
         * have the same subviews. Other per-user software remains shared. */
        Offset = Users.Length;
        while (Offset < Name->Length && Name->Buffer[Offset / sizeof(WCHAR)] != L'\\')
            Offset += sizeof(WCHAR);
        Component.Buffer = (PWSTR)((PUCHAR)Name->Buffer + Users.Length);
        Component.Length = Component.MaximumLength = Offset - Users.Length;
        if (Component.Length >= 8 * sizeof(WCHAR))
        {
            UNICODE_STRING Suffix = RTL_CONSTANT_STRING(L"_Classes");
            Component.Buffer += Component.Length / sizeof(WCHAR) - 8;
            Component.Length = Component.MaximumLength = 8 * sizeof(WCHAR);
            if (RtlEqualUnicodeString(&Component, &Suffix, TRUE)) goto Classes;
        }
        Tail.Buffer = (PWSTR)((PUCHAR)Name->Buffer + Offset);
        Tail.Length = Tail.MaximumLength = Name->Length - Offset;
        if (!CmpWow64Path(&Tail, L"\\Software\\Classes")) return 0;
        Offset += sizeof(L"\\Software\\Classes") - sizeof(WCHAR);
        goto Classes;
    }
    else return 0;

    Tail.Buffer = (PWSTR)((PUCHAR)Name->Buffer + Offset);
    Tail.Length = Tail.MaximumLength = Name->Length - Offset;
    /* A root handle already in the physical 32-bit tree stays there even
     * when the caller requests KEY_WOW64_64KEY. Never strip its node. */
    if (CmpWow64Path(&Tail, L"\\Wow6432Node")) return 0;
    if (CmpWow64Path(&Tail, L"\\Classes"))
    {
        Offset += sizeof(L"\\Classes") - sizeof(WCHAR);
        goto Classes;
    }
    for (i = 0; i < RTL_NUMBER_OF(Wow64SharedSoftware); ++i)
        if (CmpWow64Path(&Tail, Wow64SharedSoftware[i])) return 0;
    return Offset;

Classes:
    Tail.Buffer = (PWSTR)((PUCHAR)Name->Buffer + Offset);
    Tail.Length = Tail.MaximumLength = Name->Length - Offset;
    if (CmpWow64Path(&Tail, L"\\Wow6432Node"))
    {
        ULONG NodeLength = sizeof(L"\\Wow6432Node") - sizeof(WCHAR);
        Tail.Buffer += NodeLength / sizeof(WCHAR);
        Tail.Length = Tail.MaximumLength = Tail.Length - NodeLength;
        /* The container itself and redirected children stay physical. Only
         * shared children are aliases, and only in the 32-bit Classes view. */
        if (!Tail.Length || CmpWow64Path(&Tail, L"\\Wow6432Node")) return 0;
        for (i = 0; i < RTL_NUMBER_OF(CmpWow64RedirectedClasses); ++i)
            if (CmpWow64Path(&Tail, CmpWow64RedirectedClasses[i])) return 0;
        *Cut = NodeLength;
        return Offset;
    }
    for (i = 0; i < RTL_NUMBER_OF(CmpWow64RedirectedClasses); ++i)
        if (CmpWow64Path(&Tail, CmpWow64RedirectedClasses[i])) return Offset;
    return 0;
}

/* Compare only the policy prefix, without reconstructing the whole ancestry.
 * Native relative names outside these aliases have no counted absolute-name
 * limit, even if an ordinary application component is called Wow6432Node. */
static BOOLEAN
CmpWow64MatchComponents(PCM_KEY_CONTROL_BLOCK Kcb, ULONG Depth,
                       PCUNICODE_STRING Remaining, PULONG Index,
                       PULONG Position, PCWSTR Prefix)
{
    UNICODE_STRING Expected, Actual;
    PCM_KEY_CONTROL_BLOCK Ancestor;
    ULONG Start, Level;

    while (*Prefix)
    {
        while (*Prefix == L'\\') ++Prefix;
        if (!*Prefix) break;
        Expected.Buffer = (PWSTR)Prefix;
        while (*Prefix && *Prefix != L'\\') ++Prefix;
        Expected.Length = Expected.MaximumLength = (Prefix - Expected.Buffer) * sizeof(WCHAR);
        if (*Index < Depth)
        {
            Ancestor = Kcb;
            for (Level = Depth - *Index - 1; Level; --Level) Ancestor = Ancestor->ParentKcb;
            if (Ancestor->NameBlock->Compressed)
            {
                if (CmpCompareCompressedName(&Expected, Ancestor->NameBlock->Name,
                                             Ancestor->NameBlock->NameLength)) return FALSE;
            }
            else
            {
                Actual.Buffer = Ancestor->NameBlock->Name;
                Actual.Length = Actual.MaximumLength = Ancestor->NameBlock->NameLength;
                if (!RtlEqualUnicodeString(&Actual, &Expected, TRUE)) return FALSE;
            }
            ++*Index;
        }
        else
        {
            while (*Position < Remaining->Length / sizeof(WCHAR) && Remaining->Buffer[*Position] == L'\\')
                ++*Position;
            Start = *Position;
            while (*Position < Remaining->Length / sizeof(WCHAR) && Remaining->Buffer[*Position] != L'\\')
                ++*Position;
            Actual.Buffer = Remaining->Buffer + Start;
            Actual.Length = Actual.MaximumLength = (*Position - Start) * sizeof(WCHAR);
            if (!RtlEqualUnicodeString(&Actual, &Expected, TRUE)) return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
CmpWow64HasPhysicalAlias(PCM_KEY_CONTROL_BLOCK Kcb, PCUNICODE_STRING Remaining)
{
    PCM_KEY_CONTROL_BLOCK Ancestor;
    ULONG Depth = 0, Index = 0, Position = 0, i, NextIndex, NextPosition;
    for (Ancestor = Kcb; Ancestor; Ancestor = Ancestor->ParentKcb) ++Depth;
    if (!CmpWow64MatchComponents(Kcb, Depth, Remaining, &Index, &Position,
                                L"\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node")) return FALSE;
    NextIndex = Index;
    NextPosition = Position;
    if (CmpWow64MatchComponents(Kcb, Depth, Remaining, &NextIndex, &NextPosition, L"\\Classes")) return TRUE;
    for (i = 0; i < RTL_NUMBER_OF(Wow64SharedSoftware); ++i)
    {
        NextIndex = Index;
        NextPosition = Position;
        if (CmpWow64MatchComponents(Kcb, Depth, Remaining, &NextIndex, &NextPosition,
                                   Wow64SharedSoftware[i])) return TRUE;
    }
    return FALSE;
}

static NTSTATUS
CmpRedirectWow64Key(PCM_KEY_BODY Root, PUNICODE_STRING CompleteName,
                    PCUNICODE_STRING RemainingName, PCM_PARSE_CONTEXT Context)
{
    static const UNICODE_STRING Software = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE");
    static const WCHAR Node[] = L"\\Wow6432Node";
    PCM_KEY_CONTROL_BLOCK Kcb = Root->KeyControlBlock;
    PUNICODE_STRING RootName;
    UNICODE_STRING Full, Tail;
    PWSTR NewName;
    ULONG Length, Separator, Offset, Cut = 0, Insert = sizeof(Node) - sizeof(WCHAR), i;

    if (!Context || Context->Wow64Reparsed)
        return STATUS_SUCCESS;
    /* A relative open that names no view stays in the view the parent handle
     * was opened in, whatever kind of process asks. Names from the root have
     * no parent: their caller (the WoW64 thunk) chooses the default. */
    if (!Context->Wow64Flags) Context->Wow64Flags = Root->Wow64View;
    CmpLockRegistry();
    CmpAcquireKcbLockShared(Kcb);
    if (Kcb->Delete)
    {
        CmpReleaseKcbLock(Kcb);
        CmpUnlockRegistry();
        return STATUS_KEY_DELETED;
    }
    if (!Context->Wow64Flags && !CmpWow64HasPhysicalAlias(Kcb, RemainingName))
    {
        CmpReleaseKcbLock(Kcb);
        CmpUnlockRegistry();
        return STATUS_SUCCESS;
    }
    RootName = CmpConstructName(Kcb);
    CmpReleaseKcbLock(Kcb);
    CmpUnlockRegistry();
    if (!RootName) return STATUS_INSUFFICIENT_RESOURCES;
    Separator = RemainingName->Length && RemainingName->Buffer[0] != L'\\' ? sizeof(WCHAR) : 0;
    Length = RootName->Length + Separator + RemainingName->Length;
    if (Length > MAXUSHORT - sizeof(Node))
    {
        ExFreePoolWithTag(RootName, TAG_CM);
        return STATUS_NAME_TOO_LONG;
    }
    Full.Buffer = ExAllocatePoolWithTag(PagedPool, Length + sizeof(Node), TAG_CM);
    if (!Full.Buffer)
    {
        ExFreePoolWithTag(RootName, TAG_CM);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Full.Length = Length;
    Full.MaximumLength = Length + sizeof(Node);
    RtlCopyMemory(Full.Buffer, RootName->Buffer, RootName->Length);
    if (Separator) Full.Buffer[RootName->Length / sizeof(WCHAR)] = L'\\';
    RtlCopyMemory((PUCHAR)Full.Buffer + RootName->Length + Separator,
                  RemainingName->Buffer, RemainingName->Length);
    ExFreePoolWithTag(RootName, TAG_CM);
    /* The ordinary name parser accepts repeated separators. Classify the
     * same components so an alternate spelling cannot choose another view. */
    for (i = 0, Length = 0; i < Full.Length / sizeof(WCHAR); ++i)
    {
        if (Full.Buffer[i] == L'\\' && Length && Full.Buffer[Length - 1] == L'\\')
            continue;
        Full.Buffer[Length++] = Full.Buffer[i];
    }
    Full.Length = Length * sizeof(WCHAR);
    Offset = 0;
    if (CmpWow64Path(&Full, L"\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node"))
    {
        /* Windows exposes shared subtrees through the physical Software view
         * as well. Only those aliases leave a physical root; an ordinary
         * 32-bit application key remains anchored regardless of selector. */
        Tail.Buffer = (PWSTR)((PUCHAR)Full.Buffer + Software.Length + Insert);
        Tail.Length = Tail.MaximumLength = Full.Length - Software.Length - Insert;
        if (CmpWow64Path(&Tail, L"\\Classes"))
        {
            /* Software32\Classes aliases the Classes tree. A 32-bit view
             * applies the shared/redirected Classes matrix there; an explicit
             * native view exposes its physical 32-bit container. */
            RtlMoveMemory((PUCHAR)Full.Buffer + Software.Length,
                          Tail.Buffer, Tail.Length);
            Full.Length -= Insert;
            if (Context->Wow64Flags & KEY_WOW64_32KEY)
            {
                Offset = CmpWow64KeyOffset(&Full, &Cut);
                if (!Offset) { Offset = Software.Length; Insert = 0; }
            }
            else Offset = Software.Length + sizeof(L"\\Classes") - sizeof(WCHAR);
        }
        else for (i = 0; i < RTL_NUMBER_OF(Wow64SharedSoftware); ++i)
        {
            if (CmpWow64Path(&Tail, Wow64SharedSoftware[i]))
            {
                Offset = Software.Length;
                Cut = Insert;
                Insert = 0;
                break;
            }
        }
    }
    else if (Context->Wow64Flags & KEY_WOW64_32KEY)
        Offset = CmpWow64KeyOffset(&Full, &Cut);
    if (Cut) Insert = 0;
    if (!Offset)
    {
        ExFreePoolWithTag(Full.Buffer, TAG_CM);
        return STATUS_SUCCESS;
    }
    Length = Full.Length - Cut + Insert;
    NewName = ExAllocatePoolWithTag(PagedPool, Length + sizeof(WCHAR), TAG_CM);
    if (!NewName)
    {
        ExFreePoolWithTag(Full.Buffer, TAG_CM);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(NewName, Full.Buffer, Offset);
    RtlCopyMemory((PUCHAR)NewName + Offset, Node, Insert);
    RtlCopyMemory((PUCHAR)NewName + Offset + Insert, (PUCHAR)Full.Buffer + Offset + Cut, Full.Length - Offset - Cut);
    NewName[Length / sizeof(WCHAR)] = UNICODE_NULL;
    ExFreePoolWithTag(Full.Buffer, TAG_CM);

    /* New per-user Classes trees need their physical view container. Create
     * only that container, under the caller's token and ordinary ACL checks;
     * an open never creates registry objects. The requested key itself still
     * goes through the original access state on the reparse. */
    if (Context->CreateOperation && Insert)
    {
        UNICODE_STRING Container;
        OBJECT_ATTRIBUTES Attributes;
        HANDLE Handle;
        NTSTATUS Status;
        Container.Buffer = NewName;
        Container.Length = Container.MaximumLength = Offset + Insert;
        InitializeObjectAttributes(&Attributes, &Container,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK, NULL, NULL);
        Status = ZwOpenKey(&Handle, KEY_QUERY_VALUE, &Attributes);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            /* The container follows its parent, not the requested child's
             * lifetime. Let the normal create path check the actual parent,
             * including hive boundaries, before trying a volatile container. */
            Status = ZwCreateKey(&Handle, KEY_CREATE_SUB_KEY, &Attributes, 0, NULL,
                                 REG_OPTION_NON_VOLATILE, NULL);
            if (Status == STATUS_CHILD_MUST_BE_VOLATILE)
                Status = ZwCreateKey(&Handle, KEY_CREATE_SUB_KEY, &Attributes, 0, NULL,
                                     REG_OPTION_VOLATILE, NULL);
        }
        if (NT_SUCCESS(Status)) ZwClose(Handle);
        else if (Status != STATUS_ACCESS_DENIED)
        {
            ExFreePoolWithTag(NewName, TAG_CM);
            return Status;
        }
        /* An inaccessible existing container adds no rights requirement:
         * the reparse below still checks the requested object's access. */
    }
    ExFreePool(CompleteName->Buffer);
    CompleteName->Buffer = NewName;
    CompleteName->Length = Length;
    CompleteName->MaximumLength = Length + sizeof(WCHAR);
    Context->Wow64Reparsed = TRUE;
    return STATUS_REPARSE;
}
#endif

static NTSTATUS
NTAPI
CmpParseKeyWorker(IN PVOID ParseObject,
            IN PVOID ObjectType,
            IN OUT PACCESS_STATE AccessState,
            IN KPROCESSOR_MODE AccessMode,
            IN ULONG Attributes,
            IN OUT PUNICODE_STRING CompleteName,
            IN OUT PUNICODE_STRING RemainingName,
            IN OUT PVOID Context OPTIONAL,
            IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
            OUT PVOID *Object)
{
    NTSTATUS Status;
    PCM_KEY_CONTROL_BLOCK Kcb, ParentKcb;
    PHHIVE Hive = NULL;
    PCM_KEY_NODE Node = NULL;
    HCELL_INDEX Cell = HCELL_NIL, NextCell;
    PHHIVE HiveToRelease = NULL;
    HCELL_INDEX CellToRelease = HCELL_NIL;
    UNICODE_STRING Current, NextName;
    PCM_PARSE_CONTEXT ParseContext = Context;
    ULONG TotalRemainingSubkeys = 0, MatchRemainSubkeyLevel = 0, TotalSubkeys = 0;
    ULONG LockedKcbArray[CMP_KCBS_IN_ARRAY_LIMIT];
    PULONG LockedKcbs;
    BOOLEAN IsKeyCached = FALSE;
    BOOLEAN Result, Last;
    ULONG AclOptions;
    PAGED_CODE();

    /* Loop path separators at the end */
    while (RemainingName->Length &&
           (RemainingName->Buffer[(RemainingName->Length / sizeof(WCHAR)) - 1] ==
            OBJ_NAME_PATH_SEPARATOR))
    {
        /* Remove path separator */
        RemainingName->Length -= sizeof(WCHAR);
    }

    /* Fail if this isn't a key object */
    if (ObjectType != CmpKeyObjectType) return STATUS_OBJECT_TYPE_MISMATCH;

#ifdef BUILD_WOW64_ENABLED
    *Object = NULL;
    Status = CmpRedirectWow64Key(ParseObject, CompleteName, RemainingName, Context);
    if (Status != STATUS_SUCCESS) return Status;
#endif

    /* Copy the remaining name */
    Current = *RemainingName;

    /*
     * NtOpenKeyEx requests open-link semantics (don't traverse a symbolic
     * link key) by placing REG_OPTION_OPEN_LINK in the parse context. The
     * context is cleared for opens just below, so fold the request into
     * Attributes here: this is exactly equivalent to the caller having set
     * the OBJ_OPENLINK object attribute, and it rides the same code path.
     */
    if (ParseContext &&
        !ParseContext->CreateOperation &&
        (ParseContext->CreateOptions & REG_OPTION_OPEN_LINK))
    {
        Attributes |= OBJ_OPENLINK;
    }

    /* REG_OPTION_BACKUP_RESTORE of an open or create, for the registry ACL audit */
    AclOptions = ParseContext ? (ParseContext->CreateOptions & REG_OPTION_BACKUP_RESTORE) : 0;

    /* Check if this is a create */
    if (!ParseContext || !ParseContext->CreateOperation)
    {
        /* It isn't, so no context */
        ParseContext = NULL;
    }

    /* Grab the KCB */
    Kcb = ((PCM_KEY_BODY)ParseObject)->KeyControlBlock;

    /* Sanity check */
    ASSERT(Kcb != NULL);

    /* Fail if the key was marked as deleted */
    if (Kcb->Delete)
        return STATUS_KEY_DELETED;

    /* Lookup in the cache */
    Status = CmpBuildHashStackAndLookupCache(ParseObject,
                                             &Kcb,
                                             &Current,
                                             &Hive,
                                             &Cell,
                                             &TotalRemainingSubkeys,
                                             &MatchRemainSubkeyLevel,
                                             &TotalSubkeys,
                                             LockedKcbArray,
                                             &LockedKcbs);
    CMP_ASSERT_REGISTRY_LOCK();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to look in cache, stop parsing (Status 0x%lx)\n", Status);
        ParentKcb = NULL;
        goto Quickie;
    }

    /* This is now the parent */
    ParentKcb = Kcb;

    /* Sanity check */
    ASSERT(ParentKcb != NULL);

    /* Don't do anything if we're being deleted */
    if (Kcb->Delete)
    {
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Quickie;
    }

    /* Check if everything was found cached */
    if (!TotalRemainingSubkeys)
    {
        /*
         * We don't have any remaining subkey levels so we're good
         * that we have an already perfect candidate for a KCB, just
         * do the open directly.
         */
        DPRINT("No remaining subkeys, the KCB points to the actual key\n");
        IsKeyCached = TRUE;
        goto KeyCachedOpenNow;
    }

    /* Check if we have a matching level */
    if (MatchRemainSubkeyLevel)
    {
        /*
         * We have a matching level, check if that matches
         * with the total levels of subkeys. Do the open directly
         * if that is the case, because the whole subkeys levels
         * is cached.
         */
        if (MatchRemainSubkeyLevel == TotalSubkeys)
        {
            DPRINT("We have a full matching level, open the key now\n");
            IsKeyCached = TRUE;
            goto KeyCachedOpenNow;
        }

        /*
         * We only have a partial match, make sure we did not
         * get mismatched hive data.
         */
        ASSERT(Hive == Kcb->KeyHive);
        ASSERT(Cell == Kcb->KeyCell);
    }

    /*
     * FIXME: Currently the registry parser doesn't check for fake
     * KCBs. CmpCreateKeyControlBlock does have the necessary implementation
     * to create such fake keys but we don't create these fake keys anywhere.
     * When we will do, we must improve the registry parser routine to handle
     * fake keys a bit differently here.
     */

    /* Check if this is a symlink */
    if (Kcb->Flags & KEY_SYM_LINK)
    {
        /* Get the next name */
        Result = CmpGetNextName(&Current, &NextName, &Last);
        Current.Buffer = NextName.Buffer;

        /* Validate the current name string length */
        if (Current.Length + NextName.Length > MAXUSHORT)
        {
            /* too long */
            Status = STATUS_NAME_TOO_LONG;
            goto Quickie;
        }
        Current.Length += NextName.Length;

        /* Validate the current name string maximum length */
        if (Current.MaximumLength + NextName.MaximumLength > MAXUSHORT)
        {
            /* too long */
            Status = STATUS_NAME_TOO_LONG;
            goto Quickie;
        }
        Current.MaximumLength += NextName.MaximumLength;

        /* CmpGetSymbolicLink doesn't want a lock */
        CmpUnLockKcbArray(LockedKcbs);
        LockedKcbs = NULL;

        /* Parse the symlink */
        if (CmpGetSymbolicLink(Hive,
                               CompleteName,
                               Kcb,
                               &Current))
        {
            /* Symlink parse succeeded */
            Status = STATUS_REPARSE;
        }
        else
        {
            /* Couldn't find symlink */
            Status = STATUS_OBJECT_NAME_NOT_FOUND;
        }

        /* We're done */
        goto Quickie;
    }

    /* Get the key node */
    Node = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
    if (!Node)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Quickie;
    }

    /* Start parsing */
    Status = STATUS_NOT_IMPLEMENTED;
    while (TRUE)
    {
        /* Get the next component */
        Result = CmpGetNextName(&Current, &NextName, &Last);
        if (Result && NextName.Length)
        {
            /* See if this is a sym link */
            if (!(Kcb->Flags & KEY_SYM_LINK))
            {
                /* Find the subkey */
                NextCell = CmpFindSubKeyByName(Hive, Node, &NextName);
                if (NextCell != HCELL_NIL)
                {
                    /* Get the new node */
                    Cell = NextCell;
                    Node = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
                    ASSERT(Node);

                    /* Check if this was the last key */
                    if (Last)
                    {
                        /* Is this an exit node */
                        if (Node->Flags & KEY_HIVE_EXIT)
                        {
                            /* Handle it */
                            CmpHandleExitNode(&Hive,
                                              &Cell,
                                              &Node,
                                              &HiveToRelease,
                                              &CellToRelease);
                            if (!Node)
                            {
                                /* Fail */
                                Status = STATUS_INSUFFICIENT_RESOURCES;
                                break;
                            }
                        }

KeyCachedOpenNow:
                        /* Do the open */
                        Status = CmpDoOpen(Hive,
                                           Cell,
                                           Node,
                                           AccessState,
                                           AccessMode,
                                           Attributes,
                                           ParseContext,
                                           IsKeyCached ? CMP_OPEN_KCB_NO_CREATE : CMP_CREATE_KCB_KCB_LOCKED,
                                           &Kcb,
                                           LockedKcbs,
                                           &NextName,
                                           AclOptions,
                                           Object);
                        if (Status == STATUS_REPARSE)
                        {
                            /* CmpGetSymbolicLink doesn't want a lock */
                            CmpUnLockKcbArray(LockedKcbs);
                            LockedKcbs = NULL;

                            /* Parse the symlink */
                            if (!CmpGetSymbolicLink(Hive,
                                                    CompleteName,
                                                    Kcb,
                                                    NULL))
                            {
                                /* Symlink parse failed */
                                Status = STATUS_OBJECT_NAME_NOT_FOUND;
                            }
                        }

                        /* We are done */
                        break;
                    }

                    /* Is this an exit node */
                    if (Node->Flags & KEY_HIVE_EXIT)
                    {
                        /* Handle it */
                        CmpHandleExitNode(&Hive,
                                          &Cell,
                                          &Node,
                                          &HiveToRelease,
                                          &CellToRelease);
                        if (!Node)
                        {
                            /* Fail */
                            Status = STATUS_INSUFFICIENT_RESOURCES;
                            break;
                        }
                    }

                    /* Create a KCB for this key */
                    Kcb = CmpCreateKeyControlBlock(Hive,
                                                   Cell,
                                                   Node,
                                                   ParentKcb,
                                                   CMP_LOCK_HASHES_FOR_KCB,
                                                   &NextName);
                    if (!Kcb)
                    {
                        /* Fail */
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        break;
                    }

                    /* Dereference the parent and set the new one */
                    CmpDereferenceKeyControlBlockWithLock(ParentKcb, FALSE);
                    ParentKcb = Kcb;
                }
                else
                {
                    /* Check if this was the last key for a create */
                    if (Last && ParseContext)
                    {
                        /* Check if we're doing a link node */
                        if (ParseContext->CreateLink)
                        {
                            /* The only thing we should see */
                            Status = CmpCreateLinkNode(Hive,
                                                       Cell,
                                                       AccessState,
                                                       NextName,
                                                       AccessMode,
                                                       Attributes,
                                                       ParseContext,
                                                       ParentKcb,
                                                       LockedKcbs,
                                                       Object);
                        }
                        else if (Hive == &CmiVolatileHive->Hive && CmpNoVolatileCreates)
                        {
                            /* Creating keys in the master hive is not allowed */
                            Status = STATUS_INVALID_PARAMETER;
                        }
                        else
                        {
                            /* Do the create */
                            Status = CmpDoCreate(Hive,
                                                 Cell,
                                                 AccessState,
                                                 &NextName,
                                                 AccessMode,
                                                 ParseContext,
                                                 ParentKcb,
                                                 Object);
                        }

                        /* Check for reparse (in this case, someone beat us) */
                        if (Status == STATUS_REPARSE) break;

                        /* Update disposition */
                        ParseContext->Disposition = REG_CREATED_NEW_KEY;
                        break;
                    }
                    else
                    {
                        /* Key not found */
                        Status = STATUS_OBJECT_NAME_NOT_FOUND;
                        break;
                    }
                }
            }
            else
            {
                /* Save the next name */
                Current.Buffer = NextName.Buffer;

                /* Validate the current name string length */
                if (Current.Length + NextName.Length > MAXUSHORT)
                {
                    /* too long */
                    Status = STATUS_NAME_TOO_LONG;
                    break;
                }
                Current.Length += NextName.Length;

                /* Validate the current name string maximum length */
                if (Current.MaximumLength + NextName.MaximumLength > MAXUSHORT)
                {
                    /* too long */
                    Status = STATUS_NAME_TOO_LONG;
                    break;
                }
                Current.MaximumLength += NextName.MaximumLength;

                /* CmpGetSymbolicLink doesn't want a lock */
                CmpUnLockKcbArray(LockedKcbs);
                LockedKcbs = NULL;

                /* Parse the symlink */
                if (CmpGetSymbolicLink(Hive,
                                       CompleteName,
                                       Kcb,
                                       &Current))
                {
                    /* Symlink parse succeeded */
                    Status = STATUS_REPARSE;
                }
                else
                {
                    /* Couldn't find symlink */
                    Status = STATUS_OBJECT_NAME_NOT_FOUND;
                }

                /* We're done */
                break;
            }
        }
        else if (Result && Last)
        {
            /* Opening the root. Is this an exit node? */
            if (Node->Flags & KEY_HIVE_EXIT)
            {
                /* Handle it */
                CmpHandleExitNode(&Hive,
                                  &Cell,
                                  &Node,
                                  &HiveToRelease,
                                  &CellToRelease);
                if (!Node)
                {
                    /* Fail */
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
                }
            }

            /* Do the open */
            Status = CmpDoOpen(Hive,
                               Cell,
                               Node,
                               AccessState,
                               AccessMode,
                               Attributes,
                               ParseContext,
                               CMP_OPEN_KCB_NO_CREATE,
                               &Kcb,
                               LockedKcbs,
                               &NextName,
                               AclOptions,
                               Object);
            if (Status == STATUS_REPARSE)
            {
                /* Nothing to do */
            }

            /* We're done */
            break;
        }
        else
        {
            /* Bogus */
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

Quickie:
    /* Unlock all the KCBs */
    if (LockedKcbs != NULL)
    {
        CmpUnLockKcbArray(LockedKcbs);
    }

    /* Dereference the parent if it exists */
    if (ParentKcb)
        CmpDereferenceKeyControlBlock(ParentKcb);

    /* Unlock the registry */
    CmpUnlockRegistry();
    return Status;
}

NTSTATUS
NTAPI
CmpParseKey(IN PVOID ParseObject,
            IN PVOID ObjectType,
            IN OUT PACCESS_STATE AccessState,
            IN KPROCESSOR_MODE AccessMode,
            IN ULONG Attributes,
            IN OUT PUNICODE_STRING CompleteName,
            IN OUT PUNICODE_STRING RemainingName,
            IN OUT PVOID Context OPTIONAL,
            IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
            OUT PVOID *Object)
{
    NTSTATUS Status;

    Status = CmpParseKeyWorker(ParseObject, ObjectType, AccessState, AccessMode, Attributes,
                               CompleteName, RemainingName, Context, SecurityQos, Object);
#ifdef BUILD_WOW64_ENABLED
    /* Remember the view of every key that was opened or created, for the
     * relative opens that start from its handle. The view was settled
     * before the reparse; the context keeps it across the restart. */
    if (Status == STATUS_SUCCESS && *Object)
    {
        PCM_PARSE_CONTEXT ParseContext = Context;
        ((PCM_KEY_BODY)*Object)->Wow64View = ParseContext ? ParseContext->Wow64Flags : 0;
    }
#endif
    return Status;
}
