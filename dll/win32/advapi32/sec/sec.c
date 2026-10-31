/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/advapi32/sec/sec.c
 * PURPOSE:         Security descriptor functions
 * PROGRAMMER:      Ariadne ( ariadne@xs4all.nl)
 *                  Steven Edwards ( Steven_Ed4153@yahoo.com )
 *                  Andrew Greenwood ( silverblade_uk@hotmail.com )
 * UPDATE HISTORY:
 *                  Created 01/11/98
 */

#include <advapi32.h>
WINE_DEFAULT_DEBUG_CHANNEL(advapi);

/*
 * @implemented
 */
BOOL
WINAPI
GetSecurityDescriptorControl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                             PSECURITY_DESCRIPTOR_CONTROL pControl,
                             LPDWORD lpdwRevision)
{
    NTSTATUS Status;

    Status = RtlGetControlSecurityDescriptor(pSecurityDescriptor,
                                             pControl,
                                             (PULONG)lpdwRevision);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                          LPBOOL lpbDaclPresent,
                          PACL *pDacl,
                          LPBOOL lpbDaclDefaulted)
{
    BOOLEAN DaclPresent;
    BOOLEAN DaclDefaulted;
    NTSTATUS Status;

    Status = RtlGetDaclSecurityDescriptor(pSecurityDescriptor,
                                          &DaclPresent,
                                          pDacl,
                                          &DaclDefaulted);
    *lpbDaclPresent = (BOOL)DaclPresent;
    *lpbDaclDefaulted = (BOOL)DaclDefaulted;

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
GetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                           PSID *pGroup,
                           LPBOOL lpbGroupDefaulted)
{
    BOOLEAN GroupDefaulted;
    NTSTATUS Status;

    Status = RtlGetGroupSecurityDescriptor(pSecurityDescriptor,
                                           pGroup,
                                           &GroupDefaulted);
    *lpbGroupDefaulted = (BOOL)GroupDefaulted;

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                           PSID *pOwner,
                           LPBOOL lpbOwnerDefaulted)
{
    BOOLEAN OwnerDefaulted;
    NTSTATUS Status;

    Status = RtlGetOwnerSecurityDescriptor(pSecurityDescriptor,
                                           pOwner,
                                           &OwnerDefaulted);
    *lpbOwnerDefaulted = (BOOL)OwnerDefaulted;

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
DWORD
WINAPI
GetSecurityDescriptorRMControl(PSECURITY_DESCRIPTOR SecurityDescriptor,
                               PUCHAR RMControl)
{
    if (!RtlGetSecurityDescriptorRMControl(SecurityDescriptor,
                                           RMControl))
        return ERROR_INVALID_DATA;

    return ERROR_SUCCESS;
}


/*
 * @implemented
 */
BOOL
WINAPI
GetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                          LPBOOL lpbSaclPresent,
                          PACL *pSacl,
                          LPBOOL lpbSaclDefaulted)
{
    BOOLEAN SaclPresent;
    BOOLEAN SaclDefaulted;
    NTSTATUS Status;

    Status = RtlGetSaclSecurityDescriptor(pSecurityDescriptor,
                                          &SaclPresent,
                                          pSacl,
                                          &SaclDefaulted);
    *lpbSaclPresent = (BOOL)SaclPresent;
    *lpbSaclDefaulted = (BOOL)SaclDefaulted;

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
IsValidSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
    BOOLEAN Result;

    Result = RtlValidSecurityDescriptor (pSecurityDescriptor);
    if (Result == FALSE)
        SetLastError(RtlNtStatusToDosError(STATUS_INVALID_SECURITY_DESCR));

    return (BOOL)Result;
}

/*
 * @implemented
 */
BOOL
WINAPI
MakeAbsoluteSD2(IN OUT PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
                OUT LPDWORD lpdwBufferSize)
{
    NTSTATUS Status;

    Status = RtlSelfRelativeToAbsoluteSD2(pSelfRelativeSecurityDescriptor,
                                          lpdwBufferSize);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
MakeSelfRelativeSD(PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor,
                   PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
                   LPDWORD lpdwBufferLength)
{
    NTSTATUS Status;

    Status = RtlAbsoluteToSelfRelativeSD(pAbsoluteSecurityDescriptor,
                                         pSelfRelativeSecurityDescriptor,
                                         (PULONG)lpdwBufferLength);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
SetSecurityDescriptorControl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                             SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
                             SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet)
{
    NTSTATUS Status;

    Status = RtlSetControlSecurityDescriptor(pSecurityDescriptor,
                                             ControlBitsOfInterest,
                                             ControlBitsToSet);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                          BOOL bDaclPresent,
                          PACL pDacl,
                          BOOL bDaclDefaulted)
{
    NTSTATUS Status;

    Status = RtlSetDaclSecurityDescriptor(pSecurityDescriptor,
                                          bDaclPresent,
                                          pDacl,
                                          bDaclDefaulted);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
SetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                           PSID pGroup,
                           BOOL bGroupDefaulted)
{
    NTSTATUS Status;

    Status = RtlSetGroupSecurityDescriptor(pSecurityDescriptor,
                                           pGroup,
                                           bGroupDefaulted);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOL
WINAPI
SetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                           PSID pOwner,
                           BOOL bOwnerDefaulted)
{
    NTSTATUS Status;

    Status = RtlSetOwnerSecurityDescriptor(pSecurityDescriptor,
                                           pOwner,
                                           bOwnerDefaulted);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
DWORD
WINAPI
SetSecurityDescriptorRMControl(PSECURITY_DESCRIPTOR SecurityDescriptor,
                               PUCHAR RMControl)
{
    RtlSetSecurityDescriptorRMControl(SecurityDescriptor,
                                      RMControl);

    return ERROR_SUCCESS;
}


/*
 * @implemented
 */
BOOL
WINAPI
SetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                          BOOL bSaclPresent,
                          PACL pSacl,
                          BOOL bSaclDefaulted)
{
    NTSTATUS Status;

    Status = RtlSetSaclSecurityDescriptor(pSecurityDescriptor,
                                          bSaclPresent,
                                          pSacl,
                                          bSaclDefaulted);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}


#ifndef ATTRIBUTE_SECURITY_INFORMATION
#define ATTRIBUTE_SECURITY_INFORMATION          0x00000020
#endif
#ifndef SCOPE_SECURITY_INFORMATION
#define SCOPE_SECURITY_INFORMATION              0x00000040
#endif
#ifndef PROCESS_TRUST_LABEL_SECURITY_INFORMATION
#define PROCESS_TRUST_LABEL_SECURITY_INFORMATION 0x00000080
#endif
#ifndef ACCESS_FILTER_SECURITY_INFORMATION
#define ACCESS_FILTER_SECURITY_INFORMATION      0x00000100
#endif
#ifndef BACKUP_SECURITY_INFORMATION
#define BACKUP_SECURITY_INFORMATION             0x00010000
#endif

/*
 * @implemented
 *
 * The access to read the parts of a security descriptor; the table of Windows 10 22H2 (build 19045, measured for
 * every combination of the nine low bits and of the backup bit).
 */
VOID
WINAPI
QuerySecurityAccessMask(IN SECURITY_INFORMATION SecurityInformation,
                        OUT LPDWORD DesiredAccess)
{
    *DesiredAccess = 0;

    if (SecurityInformation & BACKUP_SECURITY_INFORMATION)
        *DesiredAccess = ACCESS_SYSTEM_SECURITY | READ_CONTROL;

    if (SecurityInformation & (OWNER_SECURITY_INFORMATION |
                               GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
                               LABEL_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION |
                               SCOPE_SECURITY_INFORMATION | PROCESS_TRUST_LABEL_SECURITY_INFORMATION |
                               ACCESS_FILTER_SECURITY_INFORMATION))
    {
        *DesiredAccess |= READ_CONTROL;
    }

    if (SecurityInformation & SACL_SECURITY_INFORMATION)
        *DesiredAccess |= ACCESS_SYSTEM_SECURITY;
}


/*
 * @implemented
 *
 * The access to change the parts of a security descriptor (the same measurement as for the query).
 */
VOID
WINAPI
SetSecurityAccessMask(IN SECURITY_INFORMATION SecurityInformation,
                      OUT LPDWORD DesiredAccess)
{
    *DesiredAccess = 0;

    if (SecurityInformation & BACKUP_SECURITY_INFORMATION)
        *DesiredAccess = ACCESS_SYSTEM_SECURITY | WRITE_DAC | WRITE_OWNER;

    if (SecurityInformation & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                               LABEL_SECURITY_INFORMATION))
        *DesiredAccess |= WRITE_OWNER;

    if (SecurityInformation & (DACL_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION |
                               PROCESS_TRUST_LABEL_SECURITY_INFORMATION | ACCESS_FILTER_SECURITY_INFORMATION))
        *DesiredAccess |= WRITE_DAC;

    if (SecurityInformation & (SACL_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION))
        *DesiredAccess |= ACCESS_SYSTEM_SECURITY;
}


/*
 * @unimplemented
 */
BOOL
WINAPI
ConvertToAutoInheritPrivateObjectSecurity(IN PSECURITY_DESCRIPTOR ParentDescriptor,
                                          IN PSECURITY_DESCRIPTOR CurrentSecurityDescriptor,
                                          OUT PSECURITY_DESCRIPTOR* NewSecurityDescriptor,
                                          IN GUID* ObjectType,
                                          IN BOOLEAN IsDirectoryObject,
                                          IN PGENERIC_MAPPING GenericMapping)
{
    UNIMPLEMENTED;
    return FALSE;
}


/*
 * Resolve a TRUSTEE_W to a newly LocalAlloc'd SID. The caller frees *ppSid
 * with LocalFree on success. Supports the SID and NAME trustee forms, which
 * is what BuildSecurityDescriptor's owner/group arguments use in practice.
 */
static DWORD
InternalSidFromTrusteeW(IN PTRUSTEE_W pTrustee,
                        OUT PSID *ppSid)
{
    TRUSTEE_FORM Form;
    PSID pSid;
    DWORD SidLen, DomLen, Err;
    SID_NAME_USE Use;
    LPWSTR Name, Dom;

    *ppSid = NULL;

    Form = GetTrusteeFormW(pTrustee);
    switch (Form)
    {
        case TRUSTEE_IS_SID:
            pSid = (PSID)GetTrusteeNameW(pTrustee);
            if (pSid == NULL || !IsValidSid(pSid))
                return ERROR_INVALID_PARAMETER;

            SidLen = GetLengthSid(pSid);
            *ppSid = (PSID)LocalAlloc(LMEM_FIXED, SidLen);
            if (*ppSid == NULL)
                return ERROR_NOT_ENOUGH_MEMORY;

            if (!CopySid(SidLen, *ppSid, pSid))
            {
                Err = GetLastError();
                LocalFree(*ppSid);
                *ppSid = NULL;
                return Err;
            }
            return ERROR_SUCCESS;

        case TRUSTEE_IS_NAME:
            Name = GetTrusteeNameW(pTrustee);
            if (Name == NULL)
                return ERROR_INVALID_PARAMETER;

            SidLen = 0;
            DomLen = 0;
            if (LookupAccountNameW(NULL, Name, NULL, &SidLen, NULL, &DomLen, &Use) ||
                GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                return GetLastError();
            }

            *ppSid = (PSID)LocalAlloc(LMEM_FIXED, SidLen);
            if (*ppSid == NULL)
                return ERROR_NOT_ENOUGH_MEMORY;

            Dom = (LPWSTR)LocalAlloc(LMEM_FIXED, DomLen * sizeof(WCHAR));
            if (Dom == NULL)
            {
                LocalFree(*ppSid);
                *ppSid = NULL;
                return ERROR_NOT_ENOUGH_MEMORY;
            }

            if (!LookupAccountNameW(NULL, Name, *ppSid, &SidLen, Dom, &DomLen, &Use))
            {
                Err = GetLastError();
                LocalFree(Dom);
                LocalFree(*ppSid);
                *ppSid = NULL;
                return Err;
            }

            LocalFree(Dom);
            return ERROR_SUCCESS;

        default:
            return ERROR_INVALID_PARAMETER;
    }
}


/*
 * @implemented
 */
DWORD
WINAPI
BuildSecurityDescriptorW(IN PTRUSTEE_W pOwner  OPTIONAL,
                         IN PTRUSTEE_W pGroup  OPTIONAL,
                         IN ULONG cCountOfAccessEntries,
                         IN PEXPLICIT_ACCESS_W pListOfAccessEntries  OPTIONAL,
                         IN ULONG cCountOfAuditEntries,
                         IN PEXPLICIT_ACCESS_W pListOfAuditEntries  OPTIONAL,
                         IN PSECURITY_DESCRIPTOR pOldSD  OPTIONAL,
                         OUT PULONG pSizeNewSD,
                         OUT PSECURITY_DESCRIPTOR* pNewSD)
{
    SECURITY_DESCRIPTOR AbsSD;
    PSID Owner = NULL, Group = NULL;
    PSID OwnerAlloc = NULL, GroupAlloc = NULL;
    PACL Dacl = NULL, Sacl = NULL;
    PACL NewDacl = NULL, NewSacl = NULL;
    BOOL DaclPresent = FALSE, SaclPresent = FALSE, Defaulted;
    DWORD Ret = ERROR_SUCCESS;
    ULONG Length;

    if (pNewSD == NULL || pSizeNewSD == NULL)
        return ERROR_INVALID_PARAMETER;

    *pNewSD = NULL;
    *pSizeNewSD = 0;

    /* Start from the old descriptor's owner, group, DACL and SACL if given */
    if (pOldSD != NULL)
    {
        if (!IsValidSecurityDescriptor(pOldSD))
            return ERROR_INVALID_SECURITY_DESCR;

        GetSecurityDescriptorOwner(pOldSD, &Owner, &Defaulted);
        GetSecurityDescriptorGroup(pOldSD, &Group, &Defaulted);
        GetSecurityDescriptorDacl(pOldSD, &DaclPresent, &Dacl, &Defaulted);
        GetSecurityDescriptorSacl(pOldSD, &SaclPresent, &Sacl, &Defaulted);
    }

    /* An explicit owner/group trustee replaces the inherited one */
    if (pOwner != NULL)
    {
        Ret = InternalSidFromTrusteeW(pOwner, &OwnerAlloc);
        if (Ret != ERROR_SUCCESS)
            goto Cleanup;
        Owner = OwnerAlloc;
    }

    if (pGroup != NULL)
    {
        Ret = InternalSidFromTrusteeW(pGroup, &GroupAlloc);
        if (Ret != ERROR_SUCCESS)
            goto Cleanup;
        Group = GroupAlloc;
    }

    /*
     * Merge the access entries into the DACL. A NULL list leaves the old DACL
     * unchanged; a non-NULL list (even with a count of 0) carries the old ACEs
     * over via SetEntriesInAclW.
     */
    if (pListOfAccessEntries != NULL)
    {
        Ret = SetEntriesInAclW(cCountOfAccessEntries,
                               pListOfAccessEntries,
                               Dacl,
                               &NewDacl);
        if (Ret != ERROR_SUCCESS)
            goto Cleanup;

        Dacl = NewDacl;
        DaclPresent = TRUE;
    }

    /* Likewise for the audit entries and the SACL */
    if (pListOfAuditEntries != NULL)
    {
        Ret = SetEntriesInAclW(cCountOfAuditEntries,
                               pListOfAuditEntries,
                               Sacl,
                               &NewSacl);
        if (Ret != ERROR_SUCCESS)
            goto Cleanup;

        Sacl = NewSacl;
        SaclPresent = TRUE;
    }

    /* Assemble an absolute descriptor from the collected parts */
    if (!InitializeSecurityDescriptor(&AbsSD, SECURITY_DESCRIPTOR_REVISION))
    {
        Ret = GetLastError();
        goto Cleanup;
    }

    if (Owner != NULL)
        SetSecurityDescriptorOwner(&AbsSD, Owner, FALSE);
    if (Group != NULL)
        SetSecurityDescriptorGroup(&AbsSD, Group, FALSE);
    if (DaclPresent)
        SetSecurityDescriptorDacl(&AbsSD, TRUE, Dacl, FALSE);
    if (SaclPresent)
        SetSecurityDescriptorSacl(&AbsSD, TRUE, Sacl, FALSE);

    /* Emit a self-relative descriptor the caller frees with LocalFree */
    Length = 0;
    if (MakeSelfRelativeSD(&AbsSD, NULL, &Length) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        Ret = GetLastError();
        goto Cleanup;
    }

    *pNewSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LMEM_FIXED, Length);
    if (*pNewSD == NULL)
    {
        Ret = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }

    if (!MakeSelfRelativeSD(&AbsSD, *pNewSD, &Length))
    {
        Ret = GetLastError();
        LocalFree(*pNewSD);
        *pNewSD = NULL;
        goto Cleanup;
    }

    *pSizeNewSD = Length;

Cleanup:
    if (NewDacl != NULL)
        LocalFree(NewDacl);
    if (NewSacl != NULL)
        LocalFree(NewSacl);
    if (OwnerAlloc != NULL)
        LocalFree(OwnerAlloc);
    if (GroupAlloc != NULL)
        LocalFree(GroupAlloc);

    return Ret;
}

/*
 * @unimplemented
 *
 * Win8+ API. ReactOS has no support for conditional ACEs (SDDL conditional
 * expressions / central access policies), so this is a safe stub: it fails
 * cleanly with ERROR_CALL_NOT_IMPLEMENTED rather than corrupting the ACL.
 * Exported so that modern apps (e.g. Chromium) which statically import it can
 * load; callers that actually use conditional ACEs will get a documented
 * failure. Implement for real if an app depends on the behaviour.
 */
BOOL
WINAPI
AddConditionalAce(
    _Inout_ PACL pAcl,
    _In_ DWORD dwAceRevision,
    _In_ DWORD AceFlags,
    _In_ UCHAR AceType,
    _In_ DWORD AccessMask,
    _In_ PSID pSid,
    _In_ PWCHAR ConditionStr,
    _Out_ DWORD *ReturnLength)
{
    UNREFERENCED_PARAMETER(pAcl);
    UNREFERENCED_PARAMETER(dwAceRevision);
    UNREFERENCED_PARAMETER(AceFlags);
    UNREFERENCED_PARAMETER(AceType);
    UNREFERENCED_PARAMETER(AccessMask);
    UNREFERENCED_PARAMETER(pSid);
    UNREFERENCED_PARAMETER(ConditionStr);

    if (ReturnLength)
        *ReturnLength = 0;

    FIXME("AddConditionalAce is UNIMPLEMENTED (conditional ACEs unsupported)\n");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/* EOF */
