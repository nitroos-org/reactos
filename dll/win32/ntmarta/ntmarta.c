/*
 * ReactOS MARTA provider
 * Copyright (C) 2005 - 2006 ReactOS Team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
/*
 * PROJECT:         ReactOS MARTA provider
 * FILE:            lib/ntmarta/ntmarta.c
 * PURPOSE:         ReactOS MARTA provider
 * PROGRAMMER:      Thomas Weidenmueller <w3seek@reactos.com>
 *
 * UPDATE HISTORY:
 *      07/26/2005  Created
 */

#include "ntmarta.h"

#define NDEBUG
#include <debug.h>

HINSTANCE hDllInstance;

/* FIXME: Vista+ API */
VOID
WINAPI
SetSecurityAccessMask(IN SECURITY_INFORMATION SecurityInformation,
                      OUT LPDWORD DesiredAccess)
{
    *DesiredAccess = 0;

    if (SecurityInformation & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                               LABEL_SECURITY_INFORMATION))
        *DesiredAccess |= WRITE_OWNER;

    if (SecurityInformation & DACL_SECURITY_INFORMATION)
        *DesiredAccess |= WRITE_DAC;

    if (SecurityInformation & SACL_SECURITY_INFORMATION)
        *DesiredAccess |= ACCESS_SYSTEM_SECURITY;
}

/* FIXME: Vista+ API */
VOID
WINAPI
QuerySecurityAccessMask(IN SECURITY_INFORMATION SecurityInformation,
                        OUT LPDWORD DesiredAccess)
{
    *DesiredAccess = 0;

    if (SecurityInformation & (OWNER_SECURITY_INFORMATION |
                               GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
                               LABEL_SECURITY_INFORMATION))
    {
        *DesiredAccess |= READ_CONTROL;
    }

    if (SecurityInformation & SACL_SECURITY_INFORMATION)
        *DesiredAccess |= ACCESS_SYSTEM_SECURITY;
}

static ACCESS_MODE
AccpGetAceAccessMode(IN PACE_HEADER AceHeader)
{
    ACCESS_MODE Mode = NOT_USED_ACCESS;

    switch (AceHeader->AceType)
    {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            Mode = GRANT_ACCESS;
            break;

        case ACCESS_DENIED_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
            Mode = DENY_ACCESS;
            break;

        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            if (AceHeader->AceFlags & FAILED_ACCESS_ACE_FLAG)
                Mode = SET_AUDIT_FAILURE;
            else if (AceHeader->AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG)
                Mode = SET_AUDIT_SUCCESS;
            break;
    }

    return Mode;
}

static UINT
AccpGetAceStructureSize(IN PACE_HEADER AceHeader)
{
    UINT Size = 0;

    switch (AceHeader->AceType)
    {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_DENIED_ACE_TYPE:
            Size = FIELD_OFFSET(ACCESS_ALLOWED_ACE,
                                SidStart);
            break;
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:
            Size = FIELD_OFFSET(ACCESS_ALLOWED_CALLBACK_ACE,
                                SidStart);
            break;
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
        {
            PACCESS_ALLOWED_CALLBACK_OBJECT_ACE Ace = (PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)AceHeader;
            Size = FIELD_OFFSET(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
                                ObjectType);
            if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                Size += sizeof(Ace->ObjectType);
            if (Ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
                Size += sizeof(Ace->InheritedObjectType);
            break;
        }
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        {
            PACCESS_ALLOWED_OBJECT_ACE Ace = (PACCESS_ALLOWED_OBJECT_ACE)AceHeader;
            Size = FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE,
                                ObjectType);
            if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                Size += sizeof(Ace->ObjectType);
            if (Ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
                Size += sizeof(Ace->InheritedObjectType);
            break;
        }

        case SYSTEM_AUDIT_ACE_TYPE:
            Size = FIELD_OFFSET(SYSTEM_AUDIT_ACE,
                                SidStart);
            break;
        case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
            Size = FIELD_OFFSET(SYSTEM_AUDIT_CALLBACK_ACE,
                                SidStart);
            break;
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
        {
            PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE Ace = (PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE)AceHeader;
            Size = FIELD_OFFSET(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
                                ObjectType);
            if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                Size += sizeof(Ace->ObjectType);
            if (Ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
                Size += sizeof(Ace->InheritedObjectType);
            break;
        }
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
        {
            PSYSTEM_AUDIT_OBJECT_ACE Ace = (PSYSTEM_AUDIT_OBJECT_ACE)AceHeader;
            Size = FIELD_OFFSET(SYSTEM_AUDIT_OBJECT_ACE,
                                ObjectType);
            if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                Size += sizeof(Ace->ObjectType);
            if (Ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
                Size += sizeof(Ace->InheritedObjectType);
            break;
        }

        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            Size = FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE,
                                SidStart);
            break;
    }

    return Size;
}

static PSID
AccpGetAceSid(IN PACE_HEADER AceHeader)
{
    return (PSID)((ULONG_PTR)AceHeader + AccpGetAceStructureSize(AceHeader));
}

static ACCESS_MASK
AccpGetAceAccessMask(IN PACE_HEADER AceHeader)
{
    return *((PACCESS_MASK)(AceHeader + 1));
}

static BOOL
AccpIsObjectAce(IN PACE_HEADER AceHeader)
{
    BOOL Ret;

    switch (AceHeader->AceType)
    {
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            Ret = TRUE;
            break;

        default:
            Ret = FALSE;
            break;
    }

    return Ret;
}

static DWORD
AccpGetTrusteeObjects(IN PTRUSTEE_W Trustee,
                      OUT GUID *pObjectTypeGuid  OPTIONAL,
                      OUT GUID *pInheritedObjectTypeGuid  OPTIONAL)
{
    DWORD Ret;

    switch (Trustee->TrusteeForm)
    {
        case TRUSTEE_IS_OBJECTS_AND_NAME:
        {
            POBJECTS_AND_NAME_W pOan = (POBJECTS_AND_NAME_W)Trustee->ptstrName;

            /* pOan->ObjectsPresent should always be 0 here because a previous
               call to AccpGetTrusteeSid should have rejected these trustees
               already. */
            ASSERT(pOan->ObjectsPresent == 0);

            Ret = pOan->ObjectsPresent;
            break;
        }

        case TRUSTEE_IS_OBJECTS_AND_SID:
        {
            POBJECTS_AND_SID pOas = (POBJECTS_AND_SID)Trustee->ptstrName;

            if (pObjectTypeGuid != NULL && pOas->ObjectsPresent & ACE_OBJECT_TYPE_PRESENT)
                *pObjectTypeGuid = pOas->ObjectTypeGuid;

            if (pInheritedObjectTypeGuid != NULL && pOas->ObjectsPresent & ACE_INHERITED_OBJECT_TYPE_PRESENT)
                *pInheritedObjectTypeGuid = pOas->InheritedObjectTypeGuid;

            Ret = pOas->ObjectsPresent;
            break;
        }

        default:
            /* Any other trustee forms have no objects attached... */
            Ret = 0;
            break;
    }

    return Ret;
}

static DWORD
AccpCalcNeededAceSize(IN PSID Sid,
                      IN DWORD ObjectsPresent)
{
    DWORD Ret;

    Ret = sizeof(ACE) + GetLengthSid(Sid);

    /* This routine calculates the generic size of the ACE needed.
       If no objects are present it is assumed that only a standard
       ACE is to be created. */

    if (ObjectsPresent & ACE_OBJECT_TYPE_PRESENT)
        Ret += sizeof(GUID);
    if (ObjectsPresent & ACE_INHERITED_OBJECT_TYPE_PRESENT)
        Ret += sizeof(GUID);

    if (ObjectsPresent != 0)
        Ret += sizeof(DWORD); /* Include the Flags member to make it an object ACE */

    return Ret;
}

static GUID*
AccpGetObjectAceObjectType(IN PACE_HEADER AceHeader)
{
    GUID *ObjectType = NULL;

    switch (AceHeader->AceType)
    {
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
        {
            PACCESS_ALLOWED_CALLBACK_OBJECT_ACE Ace = (PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)AceHeader;
            if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                ObjectType = &Ace->ObjectType;
            break;
        }
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        {
            PACCESS_ALLOWED_OBJECT_ACE Ace = (PACCESS_ALLOWED_OBJECT_ACE)AceHeader;
            if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                ObjectType = &Ace->ObjectType;
            break;
        }

        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
        {
            PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE Ace = (PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE)AceHeader;
            if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                ObjectType = &Ace->ObjectType;
            break;
        }
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
        {
            PSYSTEM_AUDIT_OBJECT_ACE Ace = (PSYSTEM_AUDIT_OBJECT_ACE)AceHeader;
            if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                ObjectType = &Ace->ObjectType;
            break;
        }
    }

    return ObjectType;
}

static GUID*
AccpGetObjectAceInheritedObjectType(IN PACE_HEADER AceHeader)
{
    GUID *ObjectType = NULL;

    switch (AceHeader->AceType)
    {
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
        {
            PACCESS_ALLOWED_CALLBACK_OBJECT_ACE Ace = (PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)AceHeader;
            if (Ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
            {
                if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                    ObjectType = &Ace->InheritedObjectType;
                else
                    ObjectType = &Ace->ObjectType;
            }
            break;
        }
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        {
            PACCESS_ALLOWED_OBJECT_ACE Ace = (PACCESS_ALLOWED_OBJECT_ACE)AceHeader;
            if (Ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
            {
                if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                    ObjectType = &Ace->InheritedObjectType;
                else
                    ObjectType = &Ace->ObjectType;
            }
            break;
        }

        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
        {
            PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE Ace = (PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE)AceHeader;
            if (Ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
            {
                if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                    ObjectType = &Ace->InheritedObjectType;
                else
                    ObjectType = &Ace->ObjectType;
            }
            break;
        }
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
        {
            PSYSTEM_AUDIT_OBJECT_ACE Ace = (PSYSTEM_AUDIT_OBJECT_ACE)AceHeader;
            if (Ace->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
            {
                if (Ace->Flags & ACE_OBJECT_TYPE_PRESENT)
                    ObjectType = &Ace->InheritedObjectType;
                else
                    ObjectType = &Ace->ObjectType;
            }
            break;
        }
    }

    return ObjectType;
}

static DWORD
AccpOpenLSAPolicyHandle(IN LPWSTR SystemName,
                        IN ACCESS_MASK DesiredAccess,
                        OUT PLSA_HANDLE pPolicyHandle)
{
    LSA_OBJECT_ATTRIBUTES LsaObjectAttributes = {0};
    LSA_UNICODE_STRING LsaSystemName, *psn;
    SIZE_T SystemNameLength;
    NTSTATUS Status;

    if (SystemName != NULL && SystemName[0] != L'\0')
    {
        SystemNameLength = wcslen(SystemName);
        if (SystemNameLength > UNICODE_STRING_MAX_CHARS)
        {
            return ERROR_INVALID_PARAMETER;
        }

        LsaSystemName.Buffer = SystemName;
        LsaSystemName.Length = (USHORT)SystemNameLength * sizeof(WCHAR);
        LsaSystemName.MaximumLength = LsaSystemName.Length + sizeof(WCHAR);
        psn = &LsaSystemName;
    }
    else
    {
        psn = NULL;
    }

    Status = LsaOpenPolicy(psn,
                           &LsaObjectAttributes,
                           DesiredAccess,
                           pPolicyHandle);
    if (!NT_SUCCESS(Status))
        return LsaNtStatusToWinError(Status);

    return ERROR_SUCCESS;
}

static LPWSTR
AccpGetTrusteeName(IN PTRUSTEE_W Trustee)
{
    switch (Trustee->TrusteeForm)
    {
        case TRUSTEE_IS_NAME:
            return Trustee->ptstrName;

        case TRUSTEE_IS_OBJECTS_AND_NAME:
            return ((POBJECTS_AND_NAME_W)Trustee->ptstrName)->ptstrName;

        default:
            return NULL;
    }
}

static DWORD
AccpLookupCurrentUser(OUT PSID *ppSid)
{
    DWORD Ret;
    CHAR Buffer[sizeof(TOKEN_USER) + sizeof(SID) + sizeof(DWORD)*SID_MAX_SUB_AUTHORITIES];
    DWORD Length;
    HANDLE Token;
    PSID pSid;

    *ppSid = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_READ, TRUE, &Token))
    {
        Ret = GetLastError();
        if (Ret != ERROR_NO_TOKEN)
        {
            return Ret;
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &Token))
        {
            return GetLastError();
        }
    }

    Length = sizeof(Buffer);
    if (!GetTokenInformation(Token, TokenUser, Buffer, Length, &Length))
    {
        Ret = GetLastError();
        CloseHandle(Token);
        return Ret;
    }
    CloseHandle(Token);

    pSid = ((PTOKEN_USER)Buffer)->User.Sid;
    Length = GetLengthSid(pSid);
    *ppSid = LocalAlloc(LMEM_FIXED, Length);
    if (!*ppSid)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    CopyMemory(*ppSid, pSid, Length);

    return ERROR_SUCCESS;
}

static DWORD
AccpLookupSidByName(IN LSA_HANDLE PolicyHandle,
                    IN LPWSTR Name,
                    OUT PSID *pSid)
{
    NTSTATUS Status;
    LSA_UNICODE_STRING LsaNames[1];
    PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = NULL;
    PLSA_TRANSLATED_SID2 TranslatedSid = NULL;
    DWORD SidLen;
    SIZE_T NameLength;
    DWORD Ret = ERROR_SUCCESS;

    NameLength = wcslen(Name);
    if (NameLength > UNICODE_STRING_MAX_CHARS)
    {
        return ERROR_INVALID_PARAMETER;
    }

    LsaNames[0].Buffer = Name;
    LsaNames[0].Length = (USHORT)NameLength * sizeof(WCHAR);
    LsaNames[0].MaximumLength = LsaNames[0].Length + sizeof(WCHAR);

    Status = LsaLookupNames2(PolicyHandle,
                             0,
                             sizeof(LsaNames) / sizeof(LsaNames[0]),
                             LsaNames,
                             &ReferencedDomains,
                             &TranslatedSid);

    if (!NT_SUCCESS(Status))
        return LsaNtStatusToWinError(Status);

    if (TranslatedSid->Use == SidTypeUnknown || TranslatedSid->Use == SidTypeInvalid)
    {
        Ret = LsaNtStatusToWinError(STATUS_NONE_MAPPED); /* FIXME- what error code? */
        goto Cleanup;
    }

    SidLen = GetLengthSid(TranslatedSid->Sid);
    ASSERT(SidLen != 0);

    *pSid = LocalAlloc(LMEM_FIXED, (SIZE_T)SidLen);
    if (*pSid != NULL)
    {
        if (!CopySid(SidLen,
                     *pSid,
                     TranslatedSid->Sid))
        {
            Ret = GetLastError();

            LocalFree((HLOCAL)*pSid);
            *pSid = NULL;
        }
    }
    else
        Ret = ERROR_NOT_ENOUGH_MEMORY;

Cleanup:
    LsaFreeMemory(ReferencedDomains);
    LsaFreeMemory(TranslatedSid);

    return Ret;
}


static DWORD
AccpGetTrusteeSid(IN PTRUSTEE_W Trustee,
                  IN OUT PLSA_HANDLE pPolicyHandle,
                  OUT PSID *ppSid,
                  OUT BOOL *Allocated)
{
    DWORD Ret = ERROR_SUCCESS;
    LPWSTR TrusteeName;

    *ppSid = NULL;
    *Allocated = FALSE;

    /* Windows ignores this */
#if 0
    if (Trustee->pMultipleTrustee || Trustee->MultipleTrusteeOperation != NO_MULTIPLE_TRUSTEE)
    {
        /* This is currently not supported */
        return ERROR_INVALID_PARAMETER;
    }
#endif

    switch (Trustee->TrusteeForm)
    {
        case TRUSTEE_IS_OBJECTS_AND_NAME:
            if (((POBJECTS_AND_NAME_W)Trustee->ptstrName)->ObjectsPresent != 0)
            {
                /* This is not supported as there is no way to interpret the
                   strings provided, and we need GUIDs for the ACEs... */
                Ret = ERROR_INVALID_PARAMETER;
                break;
            }
            /* fall through */

        case TRUSTEE_IS_NAME:
            TrusteeName = AccpGetTrusteeName(Trustee);
            if (!wcscmp(TrusteeName, L"CURRENT_USER"))
            {
                Ret = AccpLookupCurrentUser(ppSid);
                if (Ret == ERROR_SUCCESS)
                {
                    ASSERT(*ppSid != NULL);
                    *Allocated = TRUE;
                }
                break;
            }

            if (*pPolicyHandle == NULL)
            {
                Ret = AccpOpenLSAPolicyHandle(NULL, /* FIXME - always local? */
                                              POLICY_LOOKUP_NAMES,
                                              pPolicyHandle);
                if (Ret != ERROR_SUCCESS)
                    return Ret;

                ASSERT(*pPolicyHandle != NULL);
            }

            Ret = AccpLookupSidByName(*pPolicyHandle,
                                      TrusteeName,
                                      ppSid);
            if (Ret == ERROR_SUCCESS)
            {
                ASSERT(*ppSid != NULL);
                *Allocated = TRUE;
            }
            break;

        case TRUSTEE_IS_OBJECTS_AND_SID:
            *ppSid = ((POBJECTS_AND_SID)Trustee->ptstrName)->pSid;
            break;

        case TRUSTEE_IS_SID:
            *ppSid = (PSID)Trustee->ptstrName;
            break;

        default:
            Ret = ERROR_INVALID_PARAMETER;
            break;
    }

    return Ret;
}


/**********************************************************************
 * AccRewriteGetHandleRights				EXPORTED
 *
 * @unimplemented
 */
DWORD WINAPI
AccRewriteGetHandleRights(HANDLE handle,
                          SE_OBJECT_TYPE ObjectType,
                          SECURITY_INFORMATION SecurityInfo,
                          PSID* ppsidOwner,
                          PSID* ppsidGroup,
                          PACL* ppDacl,
                          PACL* ppSacl,
                          PSECURITY_DESCRIPTOR* ppSecurityDescriptor)
{
    PSECURITY_DESCRIPTOR pSD = NULL;
    ULONG SDSize = 0;
    NTSTATUS Status;
    DWORD LastErr;
    DWORD Ret;

    /* save the last error code */
    LastErr = GetLastError();

    do
    {
        Ret = ERROR_SUCCESS;

        /* allocate a buffer large enough to hold the
           security descriptor we need to return */
        SDSize += 0x100;
        if (pSD == NULL)
        {
            pSD = LocalAlloc(LMEM_FIXED,
                             (SIZE_T)SDSize);
        }
        else
        {
            PSECURITY_DESCRIPTOR newSD;

            newSD = LocalReAlloc((HLOCAL)pSD,
                                 (SIZE_T)SDSize,
                                 LMEM_MOVEABLE);
            if (newSD != NULL)
                pSD = newSD;
        }

        if (pSD == NULL)
        {
            Ret = GetLastError();
            break;
        }

        /* perform the actual query depending on the object type */
        switch (ObjectType)
        {
            case SE_REGISTRY_KEY:
            {
                Ret = (DWORD)RegGetKeySecurity((HKEY)handle,
                                               SecurityInfo,
                                               pSD,
                                               &SDSize);
                break;
            }

            case SE_FILE_OBJECT:
                /* FIXME - handle console handles? */
            case SE_KERNEL_OBJECT:
            {
                Status = NtQuerySecurityObject(handle,
                                               SecurityInfo,
                                               pSD,
                                               SDSize,
                                               &SDSize);
                if (!NT_SUCCESS(Status))
                {
                    Ret = RtlNtStatusToDosError(Status);
                }
                break;
            }

            case SE_SERVICE:
            {
                if (!QueryServiceObjectSecurity((SC_HANDLE)handle,
                                                SecurityInfo,
                                                pSD,
                                                SDSize,
                                                &SDSize))
                {
                    Ret = GetLastError();
                }
                break;
            }

            case SE_WINDOW_OBJECT:
            {
                if (!GetUserObjectSecurity(handle,
                                           &SecurityInfo,
                                           pSD,
                                           SDSize,
                                           &SDSize))
                {
                    Ret = GetLastError();
                }
                break;
            }

            default:
            {
                UNIMPLEMENTED;
                Ret = ERROR_CALL_NOT_IMPLEMENTED;
                break;
            }
        }

    } while (Ret == ERROR_INSUFFICIENT_BUFFER);

    if (Ret == ERROR_SUCCESS)
    {
        BOOL Present, Defaulted;

        if (SecurityInfo & OWNER_SECURITY_INFORMATION && ppsidOwner != NULL)
        {
            *ppsidOwner = NULL;
            if (!GetSecurityDescriptorOwner(pSD,
                                            ppsidOwner,
                                            &Defaulted))
            {
                Ret = GetLastError();
                goto Cleanup;
            }
        }

        if (SecurityInfo & GROUP_SECURITY_INFORMATION && ppsidGroup != NULL)
        {
            *ppsidGroup = NULL;
            if (!GetSecurityDescriptorGroup(pSD,
                                            ppsidGroup,
                                            &Defaulted))
            {
                Ret = GetLastError();
                goto Cleanup;
            }
        }

        if (SecurityInfo & DACL_SECURITY_INFORMATION && ppDacl != NULL)
        {
            *ppDacl = NULL;
            if (!GetSecurityDescriptorDacl(pSD,
                                           &Present,
                                           ppDacl,
                                           &Defaulted))
            {
                Ret = GetLastError();
                goto Cleanup;
            }
        }

        /* A label comes in the SACL */
        if ((SecurityInfo & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION)) && ppSacl != NULL)
        {
            *ppSacl = NULL;
            if (!GetSecurityDescriptorSacl(pSD,
                                           &Present,
                                           ppSacl,
                                           &Defaulted))
            {
                Ret = GetLastError();
                goto Cleanup;
            }
        }

        *ppSecurityDescriptor = pSD;
    }
    else
    {
Cleanup:
        if (pSD != NULL)
        {
            LocalFree((HLOCAL)pSD);
        }
    }

    /* restore the last error code */
    SetLastError(LastErr);

    return Ret;
}


/**********************************************************************
 * AccRewriteSetHandleRights				EXPORTED
 *
 * @unimplemented
 */
DWORD WINAPI
AccRewriteSetHandleRights(HANDLE handle,
                          SE_OBJECT_TYPE ObjectType,
                          SECURITY_INFORMATION SecurityInfo,
                          PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
    NTSTATUS Status;
    DWORD LastErr;
    DWORD Ret = ERROR_SUCCESS;

    /* save the last error code */
    LastErr = GetLastError();

    /* set the security according to the object type */
    switch (ObjectType)
    {
        case SE_REGISTRY_KEY:
        {
            Ret = (DWORD)RegSetKeySecurity((HKEY)handle,
                                           SecurityInfo,
                                           pSecurityDescriptor);
            if (Ret == ERROR_ACCESS_DENIED)
            {
                /* Like Windows, reopen the key with the rights the change needs
                 * instead of requiring them on the caller's handle: Google Updater
                 * sets the DACL through a KEY_WRITE handle (READ_CONTROL only).
                 * The reopen is access checked against the key's own security. */
                HKEY hReopened;
                REGSAM Access = 0;

                if (SecurityInfo & DACL_SECURITY_INFORMATION)
                    Access |= WRITE_DAC;
                if (SecurityInfo & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION))
                    Access |= WRITE_OWNER;
                if (SecurityInfo & SACL_SECURITY_INFORMATION)
                    Access |= ACCESS_SYSTEM_SECURITY;

                if (Access != 0 &&
                    RegOpenKeyExW((HKEY)handle, L"", 0, Access, &hReopened) == ERROR_SUCCESS)
                {
                    Ret = (DWORD)RegSetKeySecurity(hReopened,
                                                   SecurityInfo,
                                                   pSecurityDescriptor);
                    RegCloseKey(hReopened);
                }
            }
            break;
        }

        case SE_FILE_OBJECT:
            /* FIXME - handle console handles? */
        case SE_KERNEL_OBJECT:
        {
            Status = NtSetSecurityObject(handle,
                                         SecurityInfo,
                                         pSecurityDescriptor);
            if (!NT_SUCCESS(Status))
            {
                Ret = RtlNtStatusToDosError(Status);
            }
            break;
        }

        case SE_SERVICE:
        {
            if (!SetServiceObjectSecurity((SC_HANDLE)handle,
                                          SecurityInfo,
                                          pSecurityDescriptor))
            {
                Ret = GetLastError();
            }
            break;
        }

        case SE_WINDOW_OBJECT:
        {
            if (!SetUserObjectSecurity(handle,
                                       &SecurityInfo,
                                       pSecurityDescriptor))
            {
                Ret = GetLastError();
            }
            break;
        }

        default:
        {
            UNIMPLEMENTED;
            Ret = ERROR_CALL_NOT_IMPLEMENTED;
            break;
        }
    }


    /* restore the last error code */
    SetLastError(LastErr);

    return Ret;
}


static DWORD
AccpOpenNamedObject(LPWSTR pObjectName,
                    SE_OBJECT_TYPE ObjectType,
                    SECURITY_INFORMATION SecurityInfo,
                    PHANDLE Handle,
                    PHANDLE Handle2,
                    BOOL Write)
{
    LPWSTR lpPath;
    NTSTATUS Status;
    ACCESS_MASK DesiredAccess = (ACCESS_MASK)0;
    DWORD Ret = ERROR_SUCCESS;

    /* determine the required access rights */
    switch (ObjectType)
    {
        case SE_REGISTRY_KEY:
        case SE_FILE_OBJECT:
        case SE_KERNEL_OBJECT:
        case SE_SERVICE:
        case SE_WINDOW_OBJECT:
            if (Write)
            {
                SetSecurityAccessMask(SecurityInfo,
                                      (PDWORD)&DesiredAccess);
            }
            else
            {
                QuerySecurityAccessMask(SecurityInfo,
                                        (PDWORD)&DesiredAccess);
            }
            break;

        default:
            break;
    }

    /* make a copy of the path if we're modifying the string */
    switch (ObjectType)
    {
        case SE_REGISTRY_KEY:
        case SE_SERVICE:
            lpPath = (LPWSTR)LocalAlloc(LMEM_FIXED,
                                        (wcslen(pObjectName) + 1) * sizeof(WCHAR));
            if (lpPath == NULL)
            {
                Ret = GetLastError();
                goto Cleanup;
            }

            wcscpy(lpPath,
                   pObjectName);
            break;

        default:
            lpPath = pObjectName;
            break;
    }

    /* open a handle to the path depending on the object type */
    switch (ObjectType)
    {
        case SE_FILE_OBJECT:
        {
            IO_STATUS_BLOCK IoStatusBlock;
            OBJECT_ATTRIBUTES ObjectAttributes;
            UNICODE_STRING FileName;

            if (!RtlDosPathNameToNtPathName_U(pObjectName,
                                              &FileName,
                                              NULL,
                                              NULL))
            {
                Ret = ERROR_INVALID_NAME;
                goto Cleanup;
            }

            InitializeObjectAttributes(&ObjectAttributes,
                                       &FileName,
                                       OBJ_CASE_INSENSITIVE,
                                       NULL,
                                       NULL);

            /* Security queries and updates do no I/O on the handle and, as on Windows, apply to a junction or
               symbolic link itself. Asking for SYNCHRONIZE would make an
               explicit deny of SYNCHRONIZE (which icacls /deny W produces) lock the owner out of the DACL. */
            Status = NtOpenFile(Handle,
                                DesiredAccess,
                                &ObjectAttributes,
                                &IoStatusBlock,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_OPEN_REPARSE_POINT);

            RtlFreeHeap(RtlGetProcessHeap(),
                        0,
                        FileName.Buffer);

            if (!NT_SUCCESS(Status))
            {
                Ret = RtlNtStatusToDosError(Status);
            }
            break;
        }

        case SE_REGISTRY_KEY:
        {
            static const struct
            {
                HKEY hRootKey;
                LPCWSTR szRootKey;
            } AccRegRootKeys[] =
            {
                {HKEY_CLASSES_ROOT, L"CLASSES_ROOT"},
                {HKEY_CURRENT_USER, L"CURRENT_USER"},
                {HKEY_LOCAL_MACHINE, L"MACHINE"},
                {HKEY_USERS, L"USERS"},
                {HKEY_CURRENT_CONFIG, L"CONFIG"},
            };
            LPWSTR lpMachineName, lpRootKeyName, lpKeyName;
            HKEY hRootKey = NULL;
            UINT i;

            /* parse the registry path */
            if (lpPath[0] == L'\\' && lpPath[1] == L'\\')
            {
                lpMachineName = lpPath;

                lpRootKeyName = wcschr(lpPath + 2,
                                       L'\\');
                if (lpRootKeyName == NULL)
                    goto ParseRegErr;
                else
                    *(lpRootKeyName++) = L'\0';
            }
            else
            {
                lpMachineName = NULL;
                lpRootKeyName = lpPath;
            }

            lpKeyName = wcschr(lpRootKeyName,
                               L'\\');
            if (lpKeyName != NULL)
            {
                *(lpKeyName++) = L'\0';
            }

            for (i = 0;
                 i != sizeof(AccRegRootKeys) / sizeof(AccRegRootKeys[0]);
                 i++)
            {
                if (!_wcsicmp(lpRootKeyName,
                             AccRegRootKeys[i].szRootKey))
                {
                    hRootKey = AccRegRootKeys[i].hRootKey;
                    break;
                }
            }

            if (hRootKey == NULL)
            {
ParseRegErr:
                /* FIXME - right error code? */
                Ret = ERROR_INVALID_PARAMETER;
                goto Cleanup;
            }

            /* open the registry key */
            if (lpMachineName != NULL)
            {
                Ret = RegConnectRegistry(lpMachineName,
                                         hRootKey,
                                         (PHKEY)Handle2);

                if (Ret != ERROR_SUCCESS)
                    goto Cleanup;

                hRootKey = (HKEY)(*Handle2);
            }

            Ret = RegOpenKeyEx(hRootKey,
                               lpKeyName,
                               0,
                               (REGSAM)DesiredAccess,
                               (PHKEY)Handle);
            if (Ret != ERROR_SUCCESS)
            {
                if (*Handle2 != NULL)
                {
                    RegCloseKey((HKEY)(*Handle2));
                }

                goto Cleanup;
            }
            break;
        }

        case SE_SERVICE:
        {
            LPWSTR lpServiceName, lpMachineName;

            /* parse the service path */
            if (lpPath[0] == L'\\' && lpPath[1] == L'\\')
            {
                DesiredAccess |= SC_MANAGER_CONNECT;

                lpMachineName = lpPath;

                lpServiceName = wcschr(lpPath + 2,
                                       L'\\');
                if (lpServiceName == NULL)
                {
                    /* FIXME - right error code? */
                    Ret = ERROR_INVALID_PARAMETER;
                    goto Cleanup;
                }
                else
                    *(lpServiceName++) = L'\0';
            }
            else
            {
                lpMachineName = NULL;
                lpServiceName = lpPath;
            }

            /* open the service */
            *Handle2 = (HANDLE)OpenSCManager(lpMachineName,
                                             NULL,
                                             (DWORD)DesiredAccess);
            if (*Handle2 == NULL)
            {
                Ret = GetLastError();
                ASSERT(Ret != ERROR_SUCCESS);
                goto Cleanup;
            }

            DesiredAccess &= ~SC_MANAGER_CONNECT;
            *Handle = (HANDLE)OpenService((SC_HANDLE)(*Handle2),
                                          lpServiceName,
                                          (DWORD)DesiredAccess);
            if (*Handle == NULL)
            {
                Ret = GetLastError();
                ASSERT(Ret != ERROR_SUCCESS);
                ASSERT(*Handle2 != NULL);
                CloseServiceHandle((SC_HANDLE)(*Handle2));

                goto Cleanup;
            }
            break;
        }

        case SE_KERNEL_OBJECT:
        {
            /* A named kernel object, as the Create/Open functions take the name
               (e.g. "Global\\name"): the object type is not given, so try each
               type that has a name in turn. A name that exists with another type
               fails with ERROR_INVALID_HANDLE and the search goes on; a name that
               exists but is not readable ends it with ERROR_ACCESS_DENIED. */
            HANDLE WINAPI OpenJobObjectW(DWORD, BOOL, LPCWSTR);
            typedef HANDLE (WINAPI *PFN_OPENNAMED)(DWORD, BOOL, LPCWSTR);
            static const PFN_OPENNAMED OpenFns[] =
            {
                (PFN_OPENNAMED)OpenEventW,
                (PFN_OPENNAMED)OpenMutexW,
                (PFN_OPENNAMED)OpenSemaphoreW,
                (PFN_OPENNAMED)OpenWaitableTimerW,
                (PFN_OPENNAMED)OpenFileMappingW,
                (PFN_OPENNAMED)OpenJobObjectW,
            };
            DWORD Denied = ERROR_SUCCESS;
            UINT i;

            if (pObjectName[0] == L'\0')
            {
                /* Windows: GetNamedSecurityInfo(SE_KERNEL_OBJECT, L"") is ERROR_INVALID_HANDLE */
                Ret = ERROR_INVALID_HANDLE;
                goto Cleanup;
            }

            Ret = ERROR_FILE_NOT_FOUND;
            for (i = 0; i != sizeof(OpenFns) / sizeof(OpenFns[0]); i++)
            {
                HANDLE h = OpenFns[i]((DWORD)DesiredAccess, FALSE, pObjectName);
                if (h != NULL)
                {
                    *Handle = h;
                    Ret = ERROR_SUCCESS;
                    goto Cleanup;
                }
                if (GetLastError() == ERROR_ACCESS_DENIED)
                    Denied = ERROR_ACCESS_DENIED;
            }
            if (Denied != ERROR_SUCCESS)
                Ret = Denied;
            break;
        }

        default:
        {
            UNIMPLEMENTED;
            Ret = ERROR_CALL_NOT_IMPLEMENTED;
            break;
        }
    }

Cleanup:
    if (lpPath != NULL && lpPath != pObjectName)
    {
        LocalFree((HLOCAL)lpPath);
    }

    return Ret;
}


static VOID
AccpCloseObjectHandle(SE_OBJECT_TYPE ObjectType,
                      HANDLE Handle,
                      HANDLE Handle2)
{
    ASSERT(Handle != NULL);

    /* close allocated handles depending on the object type */
    switch (ObjectType)
    {
        case SE_REGISTRY_KEY:
            RegCloseKey((HKEY)Handle);
            if (Handle2 != NULL)
                RegCloseKey((HKEY)Handle2);
            break;

        case SE_FILE_OBJECT:
            NtClose(Handle);
            break;

        case SE_KERNEL_OBJECT:
        case SE_WINDOW_OBJECT:
            CloseHandle(Handle);
            break;

        case SE_SERVICE:
            CloseServiceHandle((SC_HANDLE)Handle);
            ASSERT(Handle2 != NULL);
            CloseServiceHandle((SC_HANDLE)Handle2);
            break;

        default:
            break;
    }
}


/**********************************************************************
 * AccRewriteGetNamedRights				EXPORTED
 *
 * @unimplemented
 */
DWORD WINAPI
AccRewriteGetNamedRights(LPWSTR pObjectName,
                         SE_OBJECT_TYPE ObjectType,
                         SECURITY_INFORMATION SecurityInfo,
                         PSID* ppsidOwner,
                         PSID* ppsidGroup,
                         PACL* ppDacl,
                         PACL* ppSacl,
                         PSECURITY_DESCRIPTOR* ppSecurityDescriptor)
{
    HANDLE Handle = NULL;
    HANDLE Handle2 = NULL;
    DWORD LastErr;
    DWORD Ret;

    /* save the last error code */
    LastErr = GetLastError();

    /* create the handle */
    Ret = AccpOpenNamedObject(pObjectName,
                              ObjectType,
                              SecurityInfo,
                              &Handle,
                              &Handle2,
                              FALSE);

    if (Ret == ERROR_SUCCESS)
    {
        ASSERT(Handle != NULL);

        /* perform the operation */
        Ret = AccRewriteGetHandleRights(Handle,
                                        ObjectType,
                                        SecurityInfo,
                                        ppsidOwner,
                                        ppsidGroup,
                                        ppDacl,
                                        ppSacl,
                                        ppSecurityDescriptor);

        /* close opened handles */
        AccpCloseObjectHandle(ObjectType,
                              Handle,
                              Handle2);
    }

    /* restore the last error code */
    SetLastError(LastErr);

    return Ret;
}



/*
 * Inheritance from the parent container for SetNamedSecurityInfo with
 * UNPROTECTED_DACL_SECURITY_INFORMATION: the new DACL holds the caller's explicit
 * ACEs followed by the parent's inheritable ACEs, marked INHERITED_ACE. The rules follow
 * the ones the kernel applies to a new object.
 */
static BOOLEAN
AccpShouldInheritAce(IN UCHAR AceFlags,
                     OUT PUCHAR NewAceFlags,
                     IN BOOLEAN IsDirectory)
{
    if (!IsDirectory)
    {
        if (!(AceFlags & OBJECT_INHERIT_ACE))
            return FALSE;

        *NewAceFlags = AceFlags & ~VALID_INHERIT_FLAGS;
        return TRUE;
    }

    if (AceFlags & NO_PROPAGATE_INHERIT_ACE)
    {
        if (!(AceFlags & CONTAINER_INHERIT_ACE))
            return FALSE;

        *NewAceFlags = AceFlags & ~VALID_INHERIT_FLAGS;
        return TRUE;
    }

    if (AceFlags & CONTAINER_INHERIT_ACE)
    {
        *NewAceFlags = CONTAINER_INHERIT_ACE | (AceFlags & OBJECT_INHERIT_ACE) | (AceFlags & ~VALID_INHERIT_FLAGS);
        return TRUE;
    }

    if (AceFlags & OBJECT_INHERIT_ACE)
    {
        *NewAceFlags = AceFlags | INHERIT_ONLY_ACE;
        return TRUE;
    }

    return FALSE;
}

static DWORD
AccpAddInheritedAce(IN OUT PACL Acl,
                    IN UCHAR AclRevision,
                    IN PACE_HEADER Ace,
                    IN BOOLEAN IsDirectory,
                    IN PSID Owner OPTIONAL,
                    IN PSID Group OPTIONAL)
{
    static GENERIC_MAPPING FileMapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
    static SID_IDENTIFIER_AUTHORITY CreatorAuthority = { SECURITY_CREATOR_SID_AUTHORITY };
    BYTE CreatorOwner[SECURITY_MAX_SID_SIZE], CreatorGroup[SECURITY_MAX_SID_SIZE];
    BYTE Buffer[FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + SECURITY_MAX_SID_SIZE];
    PACCESS_ALLOWED_ACE Out = (PACCESS_ALLOWED_ACE)Buffer;
    PACCESS_ALLOWED_ACE Source = (PACCESS_ALLOWED_ACE)Ace;
    UCHAR AceFlags;
    ACCESS_MASK Mask, SourceMask;
    PSID Sid, SourceSid;
    ULONG Size;
    BOOLEAN WriteTwo = FALSE;

    if (!AccpShouldInheritAce(Ace->AceFlags, &AceFlags, IsDirectory))
        return ERROR_SUCCESS;

    if (Ace->AceType > ACCESS_MAX_MS_V2_ACE_TYPE)
    {
        /* object and compound ACEs are copied with their flags changed only */
        PACE_HEADER Copy = (PACE_HEADER)LocalAlloc(LMEM_FIXED, Ace->AceSize);
        DWORD Ret = ERROR_SUCCESS;

        if (Copy == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;
        RtlCopyMemory(Copy, Ace, Ace->AceSize);
        Copy->AceFlags = AceFlags | INHERITED_ACE;
        if (!AddAce(Acl, AclRevision, MAXDWORD, Copy, Ace->AceSize))
            Ret = GetLastError();
        LocalFree(Copy);
        return Ret;
    }

    SourceMask = Source->Mask;
    SourceSid = (PSID)&Source->SidStart;
    if (Ace->AceSize < FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + sizeof(SID) - sizeof(DWORD) ||
        !RtlValidSid(SourceSid) ||
        FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(SourceSid) > Ace->AceSize)
    {
        return ERROR_INVALID_ACL;
    }

    Mask = SourceMask;
    Sid = SourceSid;

    if (!(AceFlags & INHERIT_ONLY_ACE))
    {
        RtlMapGenericMask(&Mask, &FileMapping);
        Mask &= FileMapping.GenericAll;

        RtlInitializeSid((PSID)CreatorOwner, &CreatorAuthority, 1);
        *RtlSubAuthoritySid((PSID)CreatorOwner, 0) = SECURITY_CREATOR_OWNER_RID;
        RtlInitializeSid((PSID)CreatorGroup, &CreatorAuthority, 1);
        *RtlSubAuthoritySid((PSID)CreatorGroup, 0) = SECURITY_CREATOR_GROUP_RID;

        if (RtlEqualSid(Sid, (PSID)CreatorOwner))
        {
            if (Owner == NULL)
                return ERROR_INVALID_OWNER;
            Sid = Owner;
        }
        else if (RtlEqualSid(Sid, (PSID)CreatorGroup))
        {
            if (Group == NULL)
                return ERROR_INVALID_PRIMARY_GROUP;
            Sid = Group;
        }

        /* an inheritable ACE with generic rights or a creator SID becomes an effective ACE and an inherit-only ACE */
        if (IsDirectory && (AceFlags & CONTAINER_INHERIT_ACE) &&
            (Mask != SourceMask || Sid != SourceSid))
        {
            WriteTwo = TRUE;
        }
    }

    for (;;)
    {
        if (!RtlValidSid(Sid))
            return ERROR_INVALID_SID;
        Size = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(Sid);

        Out->Header.AceType = Ace->AceType;
        Out->Header.AceFlags = (WriteTwo ? (AceFlags & ~VALID_INHERIT_FLAGS) : AceFlags) | INHERITED_ACE;
        Out->Header.AceSize = (USHORT)Size;
        Out->Mask = Mask;
        if (!NT_SUCCESS(RtlCopySid(Size - FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart), (PSID)&Out->SidStart, Sid)))
            return ERROR_INVALID_SID;
        if (!AddAce(Acl, AclRevision, MAXDWORD, Out, Size))
            return GetLastError();

        if (!WriteTwo)
            break;

        WriteTwo = FALSE;
        Mask = SourceMask;
        Sid = SourceSid;
        AceFlags |= INHERIT_ONLY_ACE;
    }

    return ERROR_SUCCESS;
}

/*
 * The length of the root part of a local or UNC path, including its trailing backslash when there is one:
 * "C:\", "\\server\share\", and the same behind "\\?\" (and "\\?\UNC\"). 0 for other paths.
 */
static SIZE_T
AccpGetPathRootLength(IN PCWSTR Path)
{
    PCWSTR p = Path, q;
    BOOLEAN Unc = FALSE;

    if (p[0] == L'\\' && p[1] == L'\\' && p[2] == L'?' && p[3] == L'\\')
    {
        p += 4;
        if (_wcsnicmp(p, L"UNC\\", 4) == 0)
        {
            p += 4;
            Unc = TRUE;
        }
    }
    else if (p[0] == L'\\' && p[1] == L'\\' && p[2] != L'.' && p[2] != L'?')
    {
        p += 2;
        Unc = TRUE;
    }

    if (!Unc)
    {
        if (((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) && p[1] == L':' && p[2] == L'\\')
            return (p + 3) - Path;
        return 0;
    }

    q = p;
    while (*q != UNICODE_NULL && *q != L'\\')
        q++;
    if (*q == UNICODE_NULL)
        return 0;
    q++;
    while (*q != UNICODE_NULL && *q != L'\\')
        q++;
    if (*q == L'\\')
        q++;
    return q - Path;
}

/*
 * Resolves a name to an absolute path once, so that every later query and the final open use the
 * same object even if the current directory changes. An extended path is used as it is:
 * GetFullPathNameW would normalise its components. The result is always an extended path.
 * It is freed with LocalFree.
 */
static DWORD
AccpResolvePath(IN PCWSTR Name,
                OUT PWSTR *Path)
{
    PWSTR Buffer;
    DWORD Length, Capacity = MAX_PATH;

    *Path = NULL;

    if (Name[0] == L'\\' && Name[1] == L'\\' && Name[2] == L'?' && Name[3] == L'\\')
    {
        Length = (DWORD)wcslen(Name);
        Buffer = (PWSTR)LocalAlloc(LMEM_FIXED, (Length + 1) * sizeof(WCHAR));
        if (Buffer == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;
        RtlCopyMemory(Buffer, Name, (Length + 1) * sizeof(WCHAR));
        *Path = Buffer;
        return ERROR_SUCCESS;
    }

    /* the current directory can change between the calls, so retry while the result does not fit */
    for (;;)
    {
        Buffer = (PWSTR)LocalAlloc(LMEM_FIXED, Capacity * sizeof(WCHAR));
        if (Buffer == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;
        Length = GetFullPathNameW(Name, Capacity, Buffer, NULL);
        if (Length == 0)
        {
            /* GetFullPathNameW can fail (an empty name) without setting an error */
            DWORD Ret = GetLastError();

            LocalFree(Buffer);
            return Ret != ERROR_SUCCESS ? Ret : ERROR_INVALID_NAME;
        }
        if (Length < Capacity)
            break;
        LocalFree(Buffer);
        Capacity = Length + 1;
    }

    /*
     * Write the result as an extended path, so that the later queries and the open take it as it is:
     * normalising a normalised path again can change it (trailing dots and spaces of components).
     */
    if (Buffer[0] == L'\\' && Buffer[1] == L'\\' && Buffer[2] != L'?' && Buffer[2] != L'.')
    {
        /* \\server\share\... becomes \\?\UNC\server\share\... */
        PWSTR Extended = (PWSTR)LocalAlloc(LMEM_FIXED, (Length + 8 + 1) * sizeof(WCHAR));

        if (Extended == NULL)
        {
            LocalFree(Buffer);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        RtlCopyMemory(Extended, L"\\\\?\\UNC\\", 8 * sizeof(WCHAR));
        RtlCopyMemory(Extended + 8, Buffer + 2, (Length - 2 + 1) * sizeof(WCHAR));
        LocalFree(Buffer);
        Buffer = Extended;
    }
    else if (((Buffer[0] >= L'A' && Buffer[0] <= L'Z') || (Buffer[0] >= L'a' && Buffer[0] <= L'z')) &&
             Buffer[1] == L':' && Buffer[2] == L'\\')
    {
        PWSTR Extended = (PWSTR)LocalAlloc(LMEM_FIXED, (Length + 4 + 1) * sizeof(WCHAR));

        if (Extended == NULL)
        {
            LocalFree(Buffer);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        RtlCopyMemory(Extended, L"\\\\?\\", 4 * sizeof(WCHAR));
        RtlCopyMemory(Extended + 4, Buffer, (Length + 1) * sizeof(WCHAR));
        LocalFree(Buffer);
        Buffer = Extended;
    }

    *Path = Buffer;
    return ERROR_SUCCESS;
}

/*
 * Path is an absolute path from AccpResolvePath.
 * Returns ERROR_SUCCESS with *NewDacl NULL if the object has no parent to inherit from
 * (a volume root, or a parent without DACL); any other failure is an error.
 */
static DWORD
AccpBuildInheritedDacl(IN PCWSTR Path,
                       IN PACL ExplicitDacl OPTIONAL,
                       IN PSID Owner OPTIONAL,
                       IN PSID Group OPTIONAL,
                       OUT PACL *NewDacl)
{
    PWSTR ParentPath = NULL;
    PWCHAR Last;
    DWORD Length, Attributes, Ret;
    SIZE_T RootLength;
    PACL ParentDacl = NULL, Acl = NULL;
    PSECURITY_DESCRIPTOR ParentSd = NULL;
    ACL_SIZE_INFORMATION ParentInfo, ExplicitInfo, NewInfo;
    BOOLEAN IsDirectory;
    ULONG i, AclSize;
    UCHAR Revision;
    PACE_HEADER Ace;

    *NewDacl = NULL;

    RootLength = AccpGetPathRootLength(Path);
    if (RootLength == 0)
        return ERROR_NOT_SUPPORTED;

    Length = (DWORD)wcslen(Path);
    ParentPath = (PWSTR)LocalAlloc(LMEM_FIXED, (Length + 1) * sizeof(WCHAR));
    if (ParentPath == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;
    RtlCopyMemory(ParentPath, Path, (Length + 1) * sizeof(WCHAR));

    while (Length > RootLength && ParentPath[Length - 1] == L'\\')
        ParentPath[--Length] = UNICODE_NULL;
    if (Length <= RootLength)
    {
        /* a volume root or a share has no parent: nothing to ask the file system about */
        Ret = ERROR_SUCCESS;
        goto Cleanup;
    }

    Attributes = GetFileAttributesW(ParentPath);
    if (Attributes == INVALID_FILE_ATTRIBUTES)
    {
        Ret = GetLastError();
        goto Cleanup;
    }
    IsDirectory = (Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

    Last = wcsrchr(ParentPath, L'\\');
    if ((SIZE_T)(Last - ParentPath) < RootLength)
        ParentPath[RootLength] = UNICODE_NULL;
    else
        *Last = UNICODE_NULL;

    Ret = AccRewriteGetNamedRights(ParentPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                   NULL, NULL, &ParentDacl, NULL, &ParentSd);
    if (Ret != ERROR_SUCCESS)
        goto Cleanup;
    if (ParentDacl == NULL)
    {
        /* a parent without DACL has nothing to inherit */
        Ret = ERROR_SUCCESS;
        goto Cleanup;
    }

    if (!GetAclInformation(ParentDacl, &ParentInfo, sizeof(ParentInfo), AclSizeInformation))
    {
        Ret = GetLastError();
        goto Cleanup;
    }

    ExplicitInfo.AceCount = 0;
    ExplicitInfo.AclBytesInUse = 0;
    Revision = ParentDacl->AclRevision;
    if (ExplicitDacl != NULL)
    {
        if (!GetAclInformation(ExplicitDacl, &ExplicitInfo, sizeof(ExplicitInfo), AclSizeInformation))
        {
            Ret = GetLastError();
            goto Cleanup;
        }
        if (ExplicitDacl->AclRevision > Revision)
            Revision = ExplicitDacl->AclRevision;
    }
    if (Revision < ACL_REVISION)
        Revision = ACL_REVISION;

    /* an inherited ACE can double (effective plus inherit-only) and a creator SID can be replaced by a longer one;
       the ACL is trimmed to the bytes in use afterwards, and AddAce fails if the result does not fit */
    AclSize = sizeof(ACL) + ExplicitInfo.AclBytesInUse + 2 * ParentInfo.AclBytesInUse +
              ParentInfo.AceCount * 2 * SECURITY_MAX_SID_SIZE;
    if (AclSize > 0xFFFC)
        AclSize = 0xFFFC;
    Acl = (PACL)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, AclSize);
    if (Acl == NULL)
    {
        Ret = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }
    if (!InitializeAcl(Acl, AclSize, Revision))
    {
        Ret = GetLastError();
        goto Cleanup;
    }

    /* the caller's ACEs that are marked inherited are replaced by the freshly computed ones */
    for (i = 0; i < ExplicitInfo.AceCount; i++)
    {
        if (!GetAce(ExplicitDacl, i, (PVOID *)&Ace))
        {
            Ret = GetLastError();
            goto Cleanup;
        }
        if (Ace->AceFlags & INHERITED_ACE)
            continue;
        if (!AddAce(Acl, Revision, MAXDWORD, Ace, Ace->AceSize))
        {
            Ret = GetLastError();
            goto Cleanup;
        }
    }

    for (i = 0; i < ParentInfo.AceCount; i++)
    {
        if (!GetAce(ParentDacl, i, (PVOID *)&Ace))
        {
            Ret = GetLastError();
            goto Cleanup;
        }
        Ret = AccpAddInheritedAce(Acl, Revision, Ace, IsDirectory, Owner, Group);
        if (Ret != ERROR_SUCCESS)
            goto Cleanup;
    }

    /* do not store the unused tail of the buffer in the descriptor */
    if (!GetAclInformation(Acl, &NewInfo, sizeof(NewInfo), AclSizeInformation))
    {
        Ret = GetLastError();
        goto Cleanup;
    }
    Acl->AclSize = (WORD)NewInfo.AclBytesInUse;

    *NewDacl = Acl;
    Acl = NULL;
    Ret = ERROR_SUCCESS;

Cleanup:
    if (Acl != NULL)
        LocalFree(Acl);
    if (ParentSd != NULL)
        LocalFree(ParentSd);
    if (ParentPath != NULL)
        LocalFree(ParentPath);
    return Ret;
}

/**********************************************************************
 * AccRewriteSetNamedRights				EXPORTED
 *
 * @unimplemented
 */
DWORD WINAPI
AccRewriteSetNamedRights(LPWSTR pObjectName,
                         SE_OBJECT_TYPE ObjectType,
                         SECURITY_INFORMATION SecurityInfo,
                         PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
    HANDLE Handle = NULL;
    HANDLE Handle2 = NULL;
    DWORD LastErr;
    DWORD Ret;

    /* save the last error code */
    LastErr = GetLastError();

    /* an unprotected DACL inherits the parent's inheritable ACEs */
    if (ObjectType == SE_FILE_OBJECT &&
        (SecurityInfo & DACL_SECURITY_INFORMATION) &&
        (SecurityInfo & UNPROTECTED_DACL_SECURITY_INFORMATION) &&
        !(SecurityInfo & PROTECTED_DACL_SECURITY_INFORMATION))
    {
        SECURITY_DESCRIPTOR InheritedSd;
        SECURITY_DESCRIPTOR_CONTROL Control;
        DWORD Revision;
        PWSTR pFullPath = NULL;
        PSECURITY_DESCRIPTOR pOwnSd = NULL;
        PACL pExplicit = NULL, pInherited = NULL;
        PSID pOwner = NULL, pGroup = NULL;
        BOOLEAN Present = FALSE, Defaulted;

        RtlGetDaclSecurityDescriptor(pSecurityDescriptor, &Present, &pExplicit, &Defaulted);

        /* a missing or NULL DACL is set as given */
        if (Present && pExplicit != NULL)
        {
            /* the name is resolved once: every query and the final open use this path */
            Ret = AccpResolvePath(pObjectName, &pFullPath);
            if (Ret != ERROR_SUCCESS)
            {
                SetLastError(LastErr);
                return Ret;
            }

            RtlGetOwnerSecurityDescriptor(pSecurityDescriptor, &pOwner, &Defaulted);
            RtlGetGroupSecurityDescriptor(pSecurityDescriptor, &pGroup, &Defaulted);

            if (pOwner == NULL || pGroup == NULL)
            {
                PSID pCurOwner = NULL, pCurGroup = NULL;

                /* the owner and group are only needed for CREATOR OWNER and CREATOR GROUP ACEs */
                if (AccRewriteGetNamedRights(pFullPath, ObjectType, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
                                             &pCurOwner, &pCurGroup, NULL, NULL, &pOwnSd) == ERROR_SUCCESS)
                {
                    if (pOwner == NULL)
                        pOwner = pCurOwner;
                    if (pGroup == NULL)
                        pGroup = pCurGroup;
                }
            }

            Ret = AccpBuildInheritedDacl(pFullPath, pExplicit, pOwner, pGroup, &pInherited);
            if (Ret != ERROR_SUCCESS)
            {
                if (pOwnSd != NULL)
                    LocalFree(pOwnSd);
                LocalFree(pFullPath);
                SetLastError(LastErr);
                return Ret;
            }

            if (pInherited != NULL)
            {
                PSID pSdOwner = NULL, pSdGroup = NULL;
                PACL pSdSacl = NULL;

                Ret = ERROR_SUCCESS;
                if (!InitializeSecurityDescriptor(&InheritedSd, SECURITY_DESCRIPTOR_REVISION) ||
                    !SetSecurityDescriptorDacl(&InheritedSd, TRUE, pInherited, FALSE))
                {
                    Ret = GetLastError();
                }

                if (Ret == ERROR_SUCCESS && (SecurityInfo & OWNER_SECURITY_INFORMATION))
                {
                    RtlGetOwnerSecurityDescriptor(pSecurityDescriptor, &pSdOwner, &Defaulted);
                    if (!SetSecurityDescriptorOwner(&InheritedSd, pSdOwner, FALSE))
                        Ret = GetLastError();
                }
                if (Ret == ERROR_SUCCESS && (SecurityInfo & GROUP_SECURITY_INFORMATION))
                {
                    RtlGetGroupSecurityDescriptor(pSecurityDescriptor, &pSdGroup, &Defaulted);
                    if (!SetSecurityDescriptorGroup(&InheritedSd, pSdGroup, FALSE))
                        Ret = GetLastError();
                }
                /* the mandatory label lives in the SACL; LABEL info must propagate it too, or the label is dropped */
                if (Ret == ERROR_SUCCESS && (SecurityInfo & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION)))
                {
                    RtlGetSaclSecurityDescriptor(pSecurityDescriptor, &Present, &pSdSacl, &Defaulted);
                    if (!SetSecurityDescriptorSacl(&InheritedSd, Present, pSdSacl, FALSE))
                        Ret = GetLastError();

                    /* the SACL keeps the control bits of the caller's descriptor */
                    if (Ret == ERROR_SUCCESS &&
                        GetSecurityDescriptorControl(pSecurityDescriptor, &Control, &Revision) &&
                        !SetSecurityDescriptorControl(&InheritedSd,
                                                      SE_SACL_PROTECTED | SE_SACL_AUTO_INHERIT_REQ | SE_SACL_AUTO_INHERITED,
                                                      Control & (SE_SACL_PROTECTED | SE_SACL_AUTO_INHERIT_REQ | SE_SACL_AUTO_INHERITED)))
                    {
                        Ret = GetLastError();
                    }
                }

                if (Ret == ERROR_SUCCESS)
                {
                    Ret = AccpOpenNamedObject(pFullPath, ObjectType, SecurityInfo, &Handle, &Handle2, TRUE);
                    if (Ret == ERROR_SUCCESS)
                    {
                        Ret = AccRewriteSetHandleRights(Handle, ObjectType, SecurityInfo, &InheritedSd);
                        AccpCloseObjectHandle(ObjectType, Handle, Handle2);
                    }
                }

                LocalFree(pInherited);
                if (pOwnSd != NULL)
                    LocalFree(pOwnSd);
                LocalFree(pFullPath);
                SetLastError(LastErr);
                return Ret;
            }

            /* nothing to inherit (a root or a parent without DACL): set as given, on the resolved path */
            if (pOwnSd != NULL)
                LocalFree(pOwnSd);
            Ret = AccpOpenNamedObject(pFullPath, ObjectType, SecurityInfo, &Handle, &Handle2, TRUE);
            if (Ret == ERROR_SUCCESS)
            {
                Ret = AccRewriteSetHandleRights(Handle, ObjectType, SecurityInfo, pSecurityDescriptor);
                AccpCloseObjectHandle(ObjectType, Handle, Handle2);
            }
            LocalFree(pFullPath);
            SetLastError(LastErr);
            return Ret;
        }
    }

    /* create the handle */
    Ret = AccpOpenNamedObject(pObjectName,
                              ObjectType,
                              SecurityInfo,
                              &Handle,
                              &Handle2,
                              TRUE);

    if (Ret == ERROR_SUCCESS)
    {
        ASSERT(Handle != NULL);

        /* perform the operation */
        Ret = AccRewriteSetHandleRights(Handle,
                                        ObjectType,
                                        SecurityInfo,
                                        pSecurityDescriptor);

        /* close opened handles */
        AccpCloseObjectHandle(ObjectType,
                              Handle,
                              Handle2);
    }

    /* restore the last error code */
    SetLastError(LastErr);

    return Ret;
}


/* the three groups of an ACL in canonical order: audit, denied and allowed (everything else) */
#define ACEGROUP_AUDIT   0
#define ACEGROUP_DENIED  1
#define ACEGROUP_ALLOWED 2

static DWORD
AccpGetAceGroup(IN PACE_HEADER AceHeader)
{
    switch (AceHeader->AceType)
    {
        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_ALARM_ACE_TYPE:
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
        case SYSTEM_ALARM_OBJECT_ACE_TYPE:
        case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
        case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
        case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
            return ACEGROUP_AUDIT;

        case ACCESS_DENIED_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
            return ACEGROUP_DENIED;

        default:
            return ACEGROUP_ALLOWED;
    }
}

/* appends the new denied (Deny) or allowed (otherwise) entries of the list to the new ACL */
static DWORD
AccpAddNewAces(IN OUT PACL pNew,
               IN ULONG cCountOfExplicitEntries,
               IN PEXPLICIT_ACCESS_W pListOfExplicitEntries,
               IN BOOL Deny,
               IN OUT LSA_HANDLE *pPolicyHandle)
{
    GUID ObjectTypeGuid, InheritedObjectTypeGuid;
    DWORD ObjectsPresent;
    BOOL needToClean, bRet;
    PSID pSid;
    ULONG i;
    DWORD Ret;

    for (i = 0; i < cCountOfExplicitEntries; i++)
    {
        if (Deny)
        {
            if (pListOfExplicitEntries[i].grfAccessMode != DENY_ACCESS)
                continue;
        }
        else if (pListOfExplicitEntries[i].grfAccessMode != SET_ACCESS &&
                 pListOfExplicitEntries[i].grfAccessMode != GRANT_ACCESS)
            continue;

        Ret = AccpGetTrusteeSid(&pListOfExplicitEntries[i].Trustee,
                                pPolicyHandle,
                                &pSid,
                                &needToClean);
        if (Ret != ERROR_SUCCESS)
            return Ret;

        ObjectsPresent = AccpGetTrusteeObjects(&pListOfExplicitEntries[i].Trustee,
                                               &ObjectTypeGuid,
                                               &InheritedObjectTypeGuid);

        if (ObjectsPresent == 0)
        {
            if (Deny)
                bRet = AddAccessDeniedAceEx(pNew,
                                            ACL_REVISION,
                                            pListOfExplicitEntries[i].grfInheritance & VALID_INHERIT_FLAGS,
                                            pListOfExplicitEntries[i].grfAccessPermissions,
                                            pSid);
            else
                bRet = AddAccessAllowedAceEx(pNew,
                                             ACL_REVISION,
                                             pListOfExplicitEntries[i].grfInheritance & VALID_INHERIT_FLAGS,
                                             pListOfExplicitEntries[i].grfAccessPermissions,
                                             pSid);
        }
        else
        {
            /* FIXME: Call AddAccessDeniedObjectAce / AddAccessAllowedObjectAce */
            DPRINT1("Object ACEs not yet supported!\n");
            SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
            bRet = FALSE;
        }

        if (needToClean) LocalFree((HLOCAL)pSid);
        if (!bRet)
            return GetLastError();
    }

    return ERROR_SUCCESS;
}

/**********************************************************************
 * AccRewriteSetEntriesInAcl				EXPORTED
 *
 * @implemented
 */
DWORD WINAPI
AccRewriteSetEntriesInAcl(ULONG cCountOfExplicitEntries,
                          PEXPLICIT_ACCESS_W pListOfExplicitEntries,
                          PACL OldAcl,
                          PACL* NewAcl)
{
    PACL pNew = NULL;
    ACL_SIZE_INFORMATION SizeInformation;
    PACE_HEADER pAce;
    UCHAR Revision;
    BOOLEAN KeepAceBuf[8];
    BOOLEAN *pKeepAce = NULL;
    DWORD ObjectsPresent;
    BOOL needToClean;
    PSID pSid1, pSid2;
    ULONG i, j;
    LSA_HANDLE PolicyHandle = NULL;
    DWORD LastErr;
    DWORD Ret = ERROR_SUCCESS;

    /* save the last error code */
    LastErr = GetLastError();

    *NewAcl = NULL;

    /* Get information about previous ACL */
    if (OldAcl)
    {
        if (!GetAclInformation(OldAcl, &SizeInformation, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
        {
            Ret = GetLastError();
            goto Cleanup;
        }

        if (SizeInformation.AceCount > sizeof(KeepAceBuf) / sizeof(KeepAceBuf[0]))
        {
            pKeepAce = (BOOLEAN *)LocalAlloc(LMEM_FIXED, SizeInformation.AceCount * sizeof(*pKeepAce));
            if (!pKeepAce)
            {
                Ret = ERROR_NOT_ENOUGH_MEMORY;
                goto Cleanup;
            }
        }
        else
            pKeepAce = KeepAceBuf;

        memset(pKeepAce, TRUE, SizeInformation.AceCount * sizeof(*pKeepAce));
    }
    else
    {
        ZeroMemory(&SizeInformation, sizeof(ACL_SIZE_INFORMATION));
        SizeInformation.AclBytesInUse = sizeof(ACL);
    }

    /* Get size required for new entries */
    for (i = 0; i < cCountOfExplicitEntries; i++)
    {
        Ret = AccpGetTrusteeSid(&pListOfExplicitEntries[i].Trustee,
                                &PolicyHandle,
                                &pSid1,
                                &needToClean);
        if (Ret != ERROR_SUCCESS)
            goto Cleanup;

        ObjectsPresent = AccpGetTrusteeObjects(&pListOfExplicitEntries[i].Trustee,
                                               NULL,
                                               NULL);

        switch (pListOfExplicitEntries[i].grfAccessMode)
        {
            case REVOKE_ACCESS:
            case SET_ACCESS:
                /* Discard all accesses for the trustee... */
                for (j = 0; j < SizeInformation.AceCount; j++)
                {
                    if (!pKeepAce[j])
                        continue;
                    if (!GetAce(OldAcl, j, (PVOID*)&pAce))
                    {
                        Ret = GetLastError();
                        goto Cleanup;
                    }

                    /* REVOKE_ACCESS removes the access-allowed and audit entries of the trustee: its deny
                       entries (and a mandatory label) stay. SET_ACCESS replaces everything. */
                    if (pListOfExplicitEntries[i].grfAccessMode == REVOKE_ACCESS &&
                        (AccpGetAceGroup(pAce) == ACEGROUP_DENIED ||
                         pAce->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE))
                        continue;

                    pSid2 = AccpGetAceSid(pAce);
                    if (RtlEqualSid(pSid1, pSid2))
                    {
                        pKeepAce[j] = FALSE;
                        SizeInformation.AclBytesInUse -= pAce->AceSize;
                    }
                }
                if (pListOfExplicitEntries[i].grfAccessMode == REVOKE_ACCESS)
                    break;
                /* ...and replace by the current access */
            case GRANT_ACCESS:
            case DENY_ACCESS:
                /* Add to ACL */
                SizeInformation.AclBytesInUse += AccpCalcNeededAceSize(pSid1, ObjectsPresent);
                break;
            case SET_AUDIT_SUCCESS:
            case SET_AUDIT_FAILURE:
                /* FIXME */
                DPRINT1("Case not implemented!\n");
                break;
            default:
                DPRINT1("Unknown access mode 0x%x. Ignoring it\n", pListOfExplicitEntries[i].grfAccessMode);
                break;
        }

        if (needToClean)
            LocalFree((HLOCAL)pSid1);
    }

    /* Succeed, if no ACL needs to be allocated */
    if (SizeInformation.AclBytesInUse == 0)
        goto Cleanup;

    /* OK, now create the new ACL */
    DPRINT("Allocating %u bytes for the new ACL\n", SizeInformation.AclBytesInUse);
    pNew = (PACL)LocalAlloc(LMEM_FIXED, SizeInformation.AclBytesInUse);
    if (!pNew)
    {
        Ret = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }
    Revision = (OldAcl != NULL && OldAcl->AclRevision > ACL_REVISION) ? OldAcl->AclRevision : ACL_REVISION;
    if (!InitializeAcl(pNew, SizeInformation.AclBytesInUse, Revision))
    {
        Ret = GetLastError();
        goto Cleanup;
    }

    /* Fill it */
    /* New audit entries (SET_AUDIT_SUCCESS, SET_AUDIT_FAILURE): FIXME */

    /* The kept entries of the old ACL stay in their order. The new denied entries come before the
       first old denied or allowed entry, the new allowed entries before the first old allowed entry
       (an old ACL in canonical order thus gets: audit, new denied, old denied, new allowed, old
       allowed) and both go to the end if there is no such entry. */
    {
        BOOL DeniedAdded = FALSE, AllowedAdded = FALSE;

        for (j = 0; OldAcl != NULL && j < SizeInformation.AceCount; j++)
        {
            DWORD Group;

            if (!pKeepAce[j])
                continue;
            if (!GetAce(OldAcl, j, (PVOID *)&pAce))
            {
                Ret = GetLastError();
                goto Cleanup;
            }
            Group = AccpGetAceGroup(pAce);

            if (!DeniedAdded && Group != ACEGROUP_AUDIT)
            {
                DeniedAdded = TRUE;
                Ret = AccpAddNewAces(pNew, cCountOfExplicitEntries, pListOfExplicitEntries, TRUE, &PolicyHandle);
                if (Ret != ERROR_SUCCESS)
                    goto Cleanup;
            }
            if (!AllowedAdded && Group == ACEGROUP_ALLOWED)
            {
                AllowedAdded = TRUE;
                Ret = AccpAddNewAces(pNew, cCountOfExplicitEntries, pListOfExplicitEntries, FALSE, &PolicyHandle);
                if (Ret != ERROR_SUCCESS)
                    goto Cleanup;
            }

            if (!AddAce(pNew, Revision, MAXDWORD, pAce, pAce->AceSize))
            {
                Ret = GetLastError();
                goto Cleanup;
            }
        }

        if (!DeniedAdded)
        {
            Ret = AccpAddNewAces(pNew, cCountOfExplicitEntries, pListOfExplicitEntries, TRUE, &PolicyHandle);
            if (Ret != ERROR_SUCCESS)
                goto Cleanup;
        }
        if (!AllowedAdded)
        {
            Ret = AccpAddNewAces(pNew, cCountOfExplicitEntries, pListOfExplicitEntries, FALSE, &PolicyHandle);
            if (Ret != ERROR_SUCCESS)
                goto Cleanup;
        }
    }

    *NewAcl = pNew;

Cleanup:
    if (pKeepAce && pKeepAce != KeepAceBuf)
        LocalFree((HLOCAL)pKeepAce);

    if (pNew && Ret != ERROR_SUCCESS)
        LocalFree((HLOCAL)pNew);

    if (PolicyHandle)
        LsaClose(PolicyHandle);

    /* restore the last error code */
    SetLastError(LastErr);

    return Ret;
}


/**********************************************************************
 * AccGetInheritanceSource				EXPORTED
 *
 * @unimplemented
 */
DWORD WINAPI
AccGetInheritanceSource(LPWSTR pObjectName,
                        SE_OBJECT_TYPE ObjectType,
                        SECURITY_INFORMATION SecurityInfo,
                        BOOL Container,
                        GUID** pObjectClassGuids,
                        DWORD GuidCount,
                        PACL pAcl,
                        PFN_OBJECT_MGR_FUNCTS pfnArray,
                        PGENERIC_MAPPING pGenericMapping,
                        PINHERITED_FROMW pInheritArray)
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/**********************************************************************
 * AccFreeIndexArray					EXPORTED
 *
 * @implemented
 */
DWORD WINAPI
AccFreeIndexArray(PINHERITED_FROMW pInheritArray,
                  USHORT AceCnt,
                  PFN_OBJECT_MGR_FUNCTS pfnArray  OPTIONAL)
{
    PINHERITED_FROMW pLast;

    UNREFERENCED_PARAMETER(pfnArray);

    pLast = pInheritArray + AceCnt;
    while (pInheritArray != pLast)
    {
        if (pInheritArray->AncestorName != NULL)
        {
            LocalFree((HLOCAL)pInheritArray->AncestorName);
            pInheritArray->AncestorName = NULL;
        }

        pInheritArray++;
    }

    return ERROR_SUCCESS;
}


/**********************************************************************
 * AccRewriteGetExplicitEntriesFromAcl			EXPORTED
 *
 * @implemented
 */
DWORD WINAPI
AccRewriteGetExplicitEntriesFromAcl(PACL pacl,
                                    PULONG pcCountOfExplicitEntries,
                                    PEXPLICIT_ACCESS_W* pListOfExplicitEntries)
{
    PACE_HEADER AceHeader;
    PSID Sid, SidTarget;
    ULONG ObjectAceCount = 0;
    POBJECTS_AND_SID ObjSid;
    SIZE_T Size;
    PEXPLICIT_ACCESS_W peaw;
    DWORD LastErr, SidLen;
    DWORD AceIndex = 0;
    DWORD ErrorCode = ERROR_SUCCESS;

    /* save the last error code */
    LastErr = GetLastError();

    if (pacl != NULL)
    {
        if (pacl->AceCount != 0)
        {
            Size = (SIZE_T)pacl->AceCount * sizeof(EXPLICIT_ACCESS_W);

            /* calculate the space needed */
            while (GetAce(pacl,
                          AceIndex,
                          (LPVOID*)&AceHeader))
            {
                Sid = AccpGetAceSid(AceHeader);
                Size += GetLengthSid(Sid);

                if (AccpIsObjectAce(AceHeader))
                    ObjectAceCount++;

                AceIndex++;
            }

            Size += ObjectAceCount * sizeof(OBJECTS_AND_SID);

            ASSERT(pacl->AceCount == AceIndex);

            /* allocate the array */
            peaw = (PEXPLICIT_ACCESS_W)LocalAlloc(LMEM_FIXED,
                                                  Size);
            if (peaw != NULL)
            {
                AceIndex = 0;
                ObjSid = (POBJECTS_AND_SID)(peaw + pacl->AceCount);
                SidTarget = (PSID)(ObjSid + ObjectAceCount);

                /* initialize the array */
                while (GetAce(pacl,
                              AceIndex,
                              (LPVOID*)&AceHeader))
                {
                    Sid = AccpGetAceSid(AceHeader);
                    SidLen = GetLengthSid(Sid);

                    peaw[AceIndex].grfAccessPermissions = AccpGetAceAccessMask(AceHeader);
                    peaw[AceIndex].grfAccessMode = AccpGetAceAccessMode(AceHeader);
                    peaw[AceIndex].grfInheritance = AceHeader->AceFlags & VALID_INHERIT_FLAGS;

                    if (CopySid(SidLen,
                                SidTarget,
                                Sid))
                    {
                        if (AccpIsObjectAce(AceHeader))
                        {
                            BuildTrusteeWithObjectsAndSid(&peaw[AceIndex].Trustee,
                                                          ObjSid++,
                                                          AccpGetObjectAceObjectType(AceHeader),
                                                          AccpGetObjectAceInheritedObjectType(AceHeader),
                                                          SidTarget);
                        }
                        else
                        {
                            BuildTrusteeWithSid(&peaw[AceIndex].Trustee,
                                                SidTarget);
                        }

                        SidTarget = (PSID)((ULONG_PTR)SidTarget + SidLen);
                    }
                    else
                    {
                        /* copying the SID failed, treat it as an fatal error... */
                        ErrorCode = GetLastError();

                        /* free allocated resources */
                        LocalFree(peaw);
                        peaw = NULL;
                        AceIndex = 0;
                        break;
                    }

                    AceIndex++;
                }

                *pcCountOfExplicitEntries = AceIndex;
                *pListOfExplicitEntries = peaw;
            }
            else
                ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        }
        else
        {
            goto EmptyACL;
        }
    }
    else
    {
EmptyACL:
        *pcCountOfExplicitEntries = 0;
        *pListOfExplicitEntries = NULL;
    }

    /* restore the last error code */
    SetLastError(LastErr);

    return ErrorCode;
}


/**********************************************************************
 * AccTreeResetNamedSecurityInfo			EXPORTED
 *
 * @unimplemented
 */
DWORD WINAPI
AccTreeResetNamedSecurityInfo(LPWSTR pObjectName,
                              SE_OBJECT_TYPE ObjectType,
                              SECURITY_INFORMATION SecurityInfo,
                              PSID pOwner,
                              PSID pGroup,
                              PACL pDacl,
                              PACL pSacl,
                              BOOL KeepExplicit,
                              FN_PROGRESSW fnProgress,
                              PROG_INVOKE_SETTING ProgressInvokeSetting,
                              PVOID Args)
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


BOOL WINAPI
DllMain(IN HINSTANCE hinstDLL,
        IN DWORD dwReason,
        IN LPVOID lpvReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            hDllInstance = hinstDLL;
            DisableThreadLibraryCalls(hinstDLL);
            break;

        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

