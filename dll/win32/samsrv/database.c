/*
 * PROJECT:     Local Security Authority Server DLL
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        dll/win32/samsrv/database.c
 * PURPOSE:     SAM object database
 * COPYRIGHT:   Copyright 2012 Eric Kohl
 */

#include "samsrv.h"

#include <pseh/pseh2.h>

/* GLOBALS *****************************************************************/

static HANDLE SamKeyHandle = NULL;


/* FUNCTIONS ***************************************************************/

/*
 * Descriptors that the earlier setup stored and that give more than the Windows ones do. They are replaced
 * by the current default, and only when the stored descriptor has the wrong entry, so that a descriptor
 * that an administrator has set is left alone:
 *  - the account domain let the Guests alias create users and aliases (Windows: Account Operators);
 *  - the Administrators and Backup Operators aliases let Account Operators change them.
 */
static
BOOLEAN
SampDaclAllowsSid(IN PSECURITY_DESCRIPTOR Sd,
                  IN ULONG SdLength,
                  IN ULONG Rid,
                  IN ACCESS_MASK AnyOfMask)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID BuiltinSid = NULL;
    PACL Dacl = NULL;
    BOOLEAN Present = FALSE, Defaulted = FALSE, Found = FALSE;
    ULONG i;

    if (!RtlValidRelativeSecurityDescriptor(Sd, SdLength, 0))
        return FALSE;

    if (!NT_SUCCESS(RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, Rid,
                                                0, 0, 0, 0, 0, 0, &BuiltinSid)))
        return FALSE;

    if (NT_SUCCESS(RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted)) && Present && Dacl != NULL)
    {
        for (i = 0; i < Dacl->AceCount; i++)
        {
            PACCESS_ALLOWED_ACE Ace;

            if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)))
                break;

            if (Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                (Ace->Mask & AnyOfMask) != 0 &&
                RtlEqualSid((PSID)&Ace->SidStart, BuiltinSid))
            {
                Found = TRUE;
                break;
            }
        }
    }

    RtlFreeSid(BuiltinSid);
    return Found;
}


static
VOID
SampRepairStoredSd(IN HANDLE ObjectKey,
                   IN ULONG BuiltinRid,
                   IN ACCESS_MASK AnyOfMask,
                   IN ULONG AliasRid,
                   IN BOOLEAN IsAccountDomain)
{
    PSECURITY_DESCRIPTOR Sd = NULL, NewSd = NULL;
    ULONG Length = 0, NewLength = 0;
    NTSTATUS Status;

    Status = SampRegQueryValue(ObjectKey, L"SecDesc", NULL, NULL, &Length);
    if ((Status != STATUS_BUFFER_OVERFLOW && !NT_SUCCESS(Status)) || Length == 0)
        return;

    Sd = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
    if (Sd == NULL)
        return;

    Status = SampRegQueryValue(ObjectKey, L"SecDesc", NULL, Sd, &Length);
    if (NT_SUCCESS(Status) && SampDaclAllowsSid(Sd, Length, BuiltinRid, AnyOfMask))
    {
        if (IsAccountDomain)
            Status = SampCreateAccountDomainSD(&NewSd, &NewLength);
        else
            Status = SampCreateAliasSD(AliasRid, &NewSd, &NewLength);

        if (NT_SUCCESS(Status))
        {
            Status = SampRegSetValue(ObjectKey, L"SecDesc", REG_BINARY, NewSd, NewLength);
            WARN("Replaced a security descriptor of the account database that gave too much access (Status 0x%08lx)\n", Status);
            RtlFreeHeap(RtlGetProcessHeap(), 0, NewSd);
        }
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, Sd);
}


static
VOID
SampRepairDefaultSDs(VOID)
{
    HANDLE DomainsKey = NULL, DomainKey = NULL, AliasesKey = NULL, AliasKey = NULL;
    static const struct { ULONG Rid; WCHAR Key[9]; } Aliases[] =
    {
        { DOMAIN_ALIAS_RID_ADMINS, L"00000220" },
        { DOMAIN_ALIAS_RID_BACKUP_OPS, L"00000227" },
    };
    ULONG i;

    if (!NT_SUCCESS(SampRegOpenKey(SamKeyHandle, L"SAM\\Domains", KEY_READ, &DomainsKey)))
        return;

    if (NT_SUCCESS(SampRegOpenKey(DomainsKey, L"Account", KEY_READ | KEY_SET_VALUE, &DomainKey)))
    {
        SampRepairStoredSd(DomainKey, DOMAIN_ALIAS_RID_GUESTS, DOMAIN_CREATE_USER | DOMAIN_CREATE_ALIAS, 0, TRUE);
        SampRegCloseKey(&DomainKey);
    }

    if (NT_SUCCESS(SampRegOpenKey(DomainsKey, L"Builtin", KEY_READ, &DomainKey)))
    {
        if (NT_SUCCESS(SampRegOpenKey(DomainKey, L"Aliases", KEY_READ, &AliasesKey)))
        {
            for (i = 0; i < ARRAYSIZE(Aliases); i++)
            {
                if (NT_SUCCESS(SampRegOpenKey(AliasesKey, Aliases[i].Key, KEY_READ | KEY_SET_VALUE, &AliasKey)))
                {
                    SampRepairStoredSd(AliasKey, DOMAIN_ALIAS_RID_ACCOUNT_OPS, ALIAS_ALL_ACCESS & ~STANDARD_RIGHTS_REQUIRED,
                                       Aliases[i].Rid, FALSE);
                    SampRegCloseKey(&AliasKey);
                }
            }
            SampRegCloseKey(&AliasesKey);
        }
        SampRegCloseKey(&DomainKey);
    }

    SampRegCloseKey(&DomainsKey);
}


NTSTATUS
SampInitDatabase(VOID)
{
    NTSTATUS Status;

    TRACE("SampInitDatabase()\n");

    Status = SampRegOpenKey(NULL,
                            L"\\Registry\\Machine\\SAM",
                            KEY_READ | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS,
                            &SamKeyHandle);
    if (!NT_SUCCESS(Status))
    {
        ERR("Failed to open the SAM key (Status: 0x%08lx)\n", Status);
        return Status;
    }

    SampRepairDefaultSDs();

    TRACE("SampInitDatabase() done\n");

    return STATUS_SUCCESS;
}


NTSTATUS
SampCreateDbObject(IN PSAM_DB_OBJECT ParentObject,
                   IN LPWSTR ContainerName,
                   IN LPWSTR ObjectName,
                   IN ULONG RelativeId,
                   IN SAM_DB_OBJECT_TYPE ObjectType,
                   IN ACCESS_MASK DesiredAccess,
                   OUT PSAM_DB_OBJECT *DbObject)
{
    PSAM_DB_OBJECT NewObject = NULL;
    HANDLE ParentKeyHandle;
    HANDLE ContainerKeyHandle = NULL;
    HANDLE ObjectKeyHandle = NULL;
    HANDLE MembersKeyHandle = NULL;
    NTSTATUS Status;

    if (DbObject == NULL)
        return STATUS_INVALID_PARAMETER;

    *DbObject = NULL;

    if (ParentObject == NULL)
        ParentKeyHandle = SamKeyHandle;
    else
        ParentKeyHandle = ParentObject->KeyHandle;

    if (ContainerName != NULL)
    {
        /* Open the container key */
        Status = SampRegOpenKey(ParentKeyHandle,
                                ContainerName,
                                KEY_ALL_ACCESS,
                                &ContainerKeyHandle);
        if (!NT_SUCCESS(Status))
        {
            goto done;
        }

        /* Create the object key */
        Status = SampRegCreateKey(ContainerKeyHandle,
                                  ObjectName,
                                  KEY_ALL_ACCESS,
                                  &ObjectKeyHandle);
        if (!NT_SUCCESS(Status))
        {
            goto done;
        }

        if (ObjectType == SamDbAliasObject)
        {
            /* Create the object key */
            Status = SampRegCreateKey(ContainerKeyHandle,
                                      L"Members",
                                      KEY_ALL_ACCESS,
                                      &MembersKeyHandle);
            if (!NT_SUCCESS(Status))
            {
                goto done;
            }
        }
    }
    else
    {
        /* Create the object key */
        Status = SampRegCreateKey(ParentKeyHandle,
                                  ObjectName,
                                  KEY_ALL_ACCESS,
                                  &ObjectKeyHandle);
        if (!NT_SUCCESS(Status))
        {
            goto done;
        }
    }

    NewObject = RtlAllocateHeap(RtlGetProcessHeap(),
                                HEAP_ZERO_MEMORY,
                                sizeof(SAM_DB_OBJECT));
    if (NewObject == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    NewObject->Name = RtlAllocateHeap(RtlGetProcessHeap(),
                                      0,
                                      (wcslen(ObjectName) + 1) * sizeof(WCHAR));
    if (NewObject->Name == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    wcscpy(NewObject->Name, ObjectName);

    NewObject->Signature = SAMP_DB_SIGNATURE;
    NewObject->RefCount = 1;
    NewObject->ObjectType = ObjectType;
    NewObject->Access = DesiredAccess;
    NewObject->KeyHandle = ObjectKeyHandle;
    NewObject->MembersKeyHandle = MembersKeyHandle;
    NewObject->RelativeId = RelativeId;
    NewObject->ParentObject = ParentObject;

    if (ParentObject != NULL)
        NewObject->Trusted = ParentObject->Trusted;

    *DbObject = NewObject;

done:
    if (!NT_SUCCESS(Status))
    {
        if (NewObject != NULL)
        {
            if (NewObject->Name != NULL)
                RtlFreeHeap(RtlGetProcessHeap(), 0, NewObject->Name);

            RtlFreeHeap(RtlGetProcessHeap(), 0, NewObject);
        }

        SampRegCloseKey(&MembersKeyHandle);
        SampRegCloseKey(&ObjectKeyHandle);
    }

    SampRegCloseKey(&ContainerKeyHandle);

    return Status;
}


NTSTATUS
SampOpenDbObject(IN PSAM_DB_OBJECT ParentObject,
                 IN LPWSTR ContainerName,
                 IN LPWSTR ObjectName,
                 IN ULONG RelativeId,
                 IN SAM_DB_OBJECT_TYPE ObjectType,
                 IN ACCESS_MASK DesiredAccess,
                 OUT PSAM_DB_OBJECT *DbObject)
{
    PSAM_DB_OBJECT NewObject = NULL;
    HANDLE ParentKeyHandle;
    HANDLE ContainerKeyHandle = NULL;
    HANDLE ObjectKeyHandle = NULL;
    HANDLE MembersKeyHandle = NULL;
    NTSTATUS Status;

    if (DbObject == NULL)
        return STATUS_INVALID_PARAMETER;

    *DbObject = NULL;

    if (ParentObject == NULL)
        ParentKeyHandle = SamKeyHandle;
    else
        ParentKeyHandle = ParentObject->KeyHandle;

    if (ContainerName != NULL)
    {
        /* Open the container key */
        Status = SampRegOpenKey(ParentKeyHandle,
                                ContainerName,
                                KEY_ALL_ACCESS,
                                &ContainerKeyHandle);
        if (!NT_SUCCESS(Status))
        {
            goto done;
        }

        /* Open the object key */
        Status = SampRegOpenKey(ContainerKeyHandle,
                                ObjectName,
                                KEY_ALL_ACCESS,
                                &ObjectKeyHandle);
        if (!NT_SUCCESS(Status))
        {
            goto done;
        }

        if (ObjectType == SamDbAliasObject)
        {
            /* Open the object key */
            Status = SampRegOpenKey(ContainerKeyHandle,
                                    L"Members",
                                    KEY_ALL_ACCESS,
                                    &MembersKeyHandle);
            if (!NT_SUCCESS(Status))
            {
                goto done;
            }
        }
    }
    else
    {
        /* Open the object key */
        Status = SampRegOpenKey(ParentKeyHandle,
                                ObjectName,
                                KEY_ALL_ACCESS,
                                &ObjectKeyHandle);
        if (!NT_SUCCESS(Status))
        {
            goto done;
        }
    }

    NewObject = RtlAllocateHeap(RtlGetProcessHeap(),
                                HEAP_ZERO_MEMORY,
                                sizeof(SAM_DB_OBJECT));
    if (NewObject == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    NewObject->Name = RtlAllocateHeap(RtlGetProcessHeap(),
                                      0,
                                      (wcslen(ObjectName) + 1) * sizeof(WCHAR));
    if (NewObject->Name == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    wcscpy(NewObject->Name, ObjectName);
    NewObject->Signature = SAMP_DB_SIGNATURE;
    NewObject->RefCount = 1;
    NewObject->ObjectType = ObjectType;
    NewObject->Access = DesiredAccess;
    NewObject->KeyHandle = ObjectKeyHandle;
    NewObject->MembersKeyHandle = MembersKeyHandle;
    NewObject->RelativeId = RelativeId;
    NewObject->ParentObject = ParentObject;

    if (ParentObject != NULL)
        NewObject->Trusted = ParentObject->Trusted;

    *DbObject = NewObject;

done:
    if (!NT_SUCCESS(Status))
    {
        if (NewObject != NULL)
        {
            if (NewObject->Name != NULL)
                RtlFreeHeap(RtlGetProcessHeap(), 0, NewObject->Name);

            RtlFreeHeap(RtlGetProcessHeap(), 0, NewObject);
        }

        SampRegCloseKey(&MembersKeyHandle);
        SampRegCloseKey(&ObjectKeyHandle);
    }

    SampRegCloseKey(&ContainerKeyHandle);

    return Status;
}


NTSTATUS
SampValidateDbObject(SAMPR_HANDLE Handle,
                     SAM_DB_OBJECT_TYPE ObjectType,
                     ACCESS_MASK DesiredAccess,
                     PSAM_DB_OBJECT *DbObject)
{
    PSAM_DB_OBJECT LocalObject = (PSAM_DB_OBJECT)Handle;
    BOOLEAN bValid = FALSE;

    _SEH2_TRY
    {
        if (LocalObject->Signature == SAMP_DB_SIGNATURE)
        {
            if ((ObjectType == SamDbIgnoreObject) ||
                (LocalObject->ObjectType == ObjectType))
                bValid = TRUE;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        bValid = FALSE;
    }
    _SEH2_END;

    if (bValid == FALSE)
        return STATUS_INVALID_HANDLE;

    if (DesiredAccess != 0)
    {
        /* Check for granted access rights */
        if ((LocalObject->Access & DesiredAccess) != DesiredAccess)
        {
            ERR("SampValidateDbObject access check failed %08lx  %08lx\n",
                LocalObject->Access, DesiredAccess);
            return STATUS_ACCESS_DENIED;
        }
    }

    if (DbObject != NULL)
        *DbObject = LocalObject;

    return STATUS_SUCCESS;
}


NTSTATUS
SampCloseDbObject(PSAM_DB_OBJECT DbObject)
{
    NTSTATUS Status = STATUS_SUCCESS;

    DbObject->RefCount--;

    if (DbObject->RefCount > 0)
        return STATUS_SUCCESS;

    SampRegCloseKey(&DbObject->KeyHandle);
    SampRegCloseKey(&DbObject->MembersKeyHandle);

    if (DbObject->Name != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, DbObject->Name);

    RtlFreeHeap(RtlGetProcessHeap(), 0, DbObject);

    return Status;
}


NTSTATUS
SampDeleteAccountDbObject(PSAM_DB_OBJECT DbObject)
{
    LPCWSTR ContainerName;
    LPWSTR AccountName = NULL;
    HANDLE ContainerKey = NULL;
    HANDLE NamesKey = NULL;
    ULONG Length = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    TRACE("(%p)\n", DbObject);

    /* Server and Domain objects cannot be deleted */
    switch (DbObject->ObjectType)
    {
        case SamDbAliasObject:
            ContainerName = L"Aliases";
            break;

        case SamDbGroupObject:
            ContainerName = L"Groups";
            break;

        case SamDbUserObject:
            ContainerName = L"Users";
            break;

        default:
           return STATUS_INVALID_PARAMETER;
    }

    /* Get the account name */
    Status = SampGetObjectAttribute(DbObject,
                                    L"Name",
                                    NULL,
                                    NULL,
                                    &Length);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
    {
        TRACE("SampGetObjectAttribute failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    AccountName = RtlAllocateHeap(RtlGetProcessHeap(),
                                  HEAP_ZERO_MEMORY,
                                  Length);
    if (AccountName == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    Status = SampGetObjectAttribute(DbObject,
                                    L"Name",
                                    NULL,
                                    (PVOID)AccountName,
                                    &Length);
    if (!NT_SUCCESS(Status))
    {
        TRACE("SampGetObjectAttribute failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    SampRegCloseKey(&DbObject->KeyHandle);

    if (DbObject->ObjectType == SamDbAliasObject)
    {
        SampRegCloseKey(&DbObject->MembersKeyHandle);

        SampRegDeleteKey(DbObject->KeyHandle,
                         L"Members");
    }

    /* Open the domain container key */
    Status = SampRegOpenKey(DbObject->ParentObject->KeyHandle,
                            ContainerName,
                            DELETE | KEY_SET_VALUE,
                            &ContainerKey);
    if (!NT_SUCCESS(Status))
    {
        TRACE("SampRegOpenKey failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    /* Open the Names key */
    Status = SampRegOpenKey(ContainerKey,
                            L"Names",
                            KEY_SET_VALUE,
                            &NamesKey);
    if (!NT_SUCCESS(Status))
    {
        TRACE("SampRegOpenKey failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    /* Remove the account from the Names key */
    Status = SampRegDeleteValue(NamesKey,
                                AccountName);
    if (!NT_SUCCESS(Status))
    {
        TRACE("SampRegDeleteValue failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    /* Remove the account key from the container */
    Status = SampRegDeleteKey(ContainerKey,
                              DbObject->Name);
    if (!NT_SUCCESS(Status))
    {
        TRACE("SampRegDeleteKey failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    /* Release the database object name */
    if (DbObject->Name != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, DbObject->Name);

    /* Release the database object */
    RtlFreeHeap(RtlGetProcessHeap(), 0, DbObject);

    Status = STATUS_SUCCESS;

done:
    SampRegCloseKey(&NamesKey);
    SampRegCloseKey(&ContainerKey);

    if (AccountName != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, AccountName);

    return Status;
}


NTSTATUS
SampSetObjectAttribute(PSAM_DB_OBJECT DbObject,
                       LPWSTR AttributeName,
                       ULONG AttributeType,
                       LPVOID AttributeData,
                       ULONG AttributeSize)
{
    return SampRegSetValue(DbObject->KeyHandle,
                           AttributeName,
                           AttributeType,
                           AttributeData,
                           AttributeSize);
}


NTSTATUS
SampGetObjectAttribute(PSAM_DB_OBJECT DbObject,
                       LPWSTR AttributeName,
                       PULONG AttributeType,
                       LPVOID AttributeData,
                       PULONG AttributeSize)
{
    return SampRegQueryValue(DbObject->KeyHandle,
                             AttributeName,
                             AttributeType,
                             AttributeData,
                             AttributeSize);
}


NTSTATUS
SampGetObjectAttributeString(PSAM_DB_OBJECT DbObject,
                             LPWSTR AttributeName,
                             PRPC_UNICODE_STRING String)
{
    ULONG Length = 0;
    NTSTATUS Status;

    Status = SampGetObjectAttribute(DbObject,
                                    AttributeName,
                                    NULL,
                                    NULL,
                                    &Length);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
    {
        TRACE("Status 0x%08lx\n", Status);
        goto done;
    }

    if (Length == 0)
    {
        String->Length = 0;
        String->MaximumLength = 0;
        String->Buffer = NULL;

        Status = STATUS_SUCCESS;
        goto done;
    }

    String->Length = (USHORT)(Length - sizeof(WCHAR));
    String->MaximumLength = (USHORT)Length;
    String->Buffer = midl_user_allocate(Length);
    if (String->Buffer == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    TRACE("Length: %lu\n", Length);
    Status = SampGetObjectAttribute(DbObject,
                                    AttributeName,
                                    NULL,
                                    (PVOID)String->Buffer,
                                    &Length);
    if (!NT_SUCCESS(Status))
    {
        TRACE("Status 0x%08lx\n", Status);
        goto done;
    }

done:
    if (!NT_SUCCESS(Status))
    {
        if (String->Buffer != NULL)
        {
            midl_user_free(String->Buffer);
            String->Buffer = NULL;
        }
    }

    return Status;
}


NTSTATUS
SampSetObjectAttributeString(PSAM_DB_OBJECT DbObject,
                             LPWSTR AttributeName,
                             PRPC_UNICODE_STRING String)
{
    PWCHAR Buffer = NULL;
    USHORT Length = 0;

    if ((String != NULL) && (String->Buffer != NULL))
    {
        Buffer = String->Buffer;
        Length = String->Length + sizeof(WCHAR);
    }

    return SampSetObjectAttribute(DbObject,
                                  AttributeName,
                                  REG_SZ,
                                  Buffer,
                                  Length);
}


/* EOF */

