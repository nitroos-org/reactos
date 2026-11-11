/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Client/Server Runtime SubSystem
 * FILE:            subsystems/win32/csrsrv/init.c
 * PURPOSE:         CSR Server DLL Initialization
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 *                  ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "srv.h"

#include <winreg.h>
#include <ndk/cmfuncs.h>

#define NDEBUG
#include <debug.h>

/* DATA ***********************************************************************/

// Debug Flag
ULONG CsrDebug = 0; // 0xFFFFFFFF;

HANDLE CsrHeap = NULL;
HANDLE CsrObjectDirectory = NULL;
UNICODE_STRING CsrDirectoryName;
UNICODE_STRING CsrSbApiPortName;
HANDLE CsrSbApiPort = NULL;
PCSR_THREAD CsrSbApiRequestThreadPtr;
HANDLE CsrSmApiPort = NULL;
HANDLE hSbApiPort = NULL;
HANDLE CsrApiPort = NULL;
#ifdef __REACTOS__
BOOLEAN CsrWindowsControl;
ULONG CsrSubSystemType; // Known as SessionFirstProcessImageType in Windows 7+
#endif
ULONG CsrMaxApiRequestThreads;
ULONG CsrTotalPerProcessDataLength;
ULONG SessionId;
/* The SMSS that started us: the only client of the Sb port */
HANDLE CsrSmssProcess = NULL;
HANDLE CsrSmssProcessId = NULL;
LARGE_INTEGER CsrSmssCreateTime;
/* Our session as the kernel reports it (sessions design 3.5: SbCreateRemoteProcess) */
ULONG CsrKernelSessionId = (ULONG)-1;
HANDLE BNOLinksDirectory;
HANDLE SessionObjectDirectory;
HANDLE DosDevicesDirectory;
SYSTEM_BASIC_INFORMATION CsrNtSysInfo;


/* PRIVATE FUNCTIONS **********************************************************/

/* === INIT ROUTINES === */

/*++
 * @name CsrSetProcessSecurity
 *
 * The CsrSetProcessSecurity routine protects access to the CSRSS process
 * from unauthorized tampering.
 *
 * @param None.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrSetProcessSecurity(VOID)
{
    NTSTATUS Status;
    HANDLE hToken, hProcess = NtCurrentProcess();
    ULONG Length;
    PTOKEN_USER TokenInfo = NULL;
    PSECURITY_DESCRIPTOR ProcSd = NULL;
    PACL Dacl;
    PSID UserSid;

    /* Open our token */
    Status = NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(Status)) goto Quickie;

    /* Get the Token User Length */
    Status = NtQueryInformationToken(hToken, TokenUser, NULL, 0, &Length);
    if (Status != STATUS_BUFFER_TOO_SMALL)
    {
        NtClose(hToken);
        goto Quickie;
    }

    /* Allocate space for it */
    TokenInfo = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY, Length);
    if (!TokenInfo)
    {
        NtClose(hToken);
        Status = STATUS_NO_MEMORY;
        goto Quickie;
    }

    /* Now query the data */
    Status = NtQueryInformationToken(hToken, TokenUser, TokenInfo, Length, &Length);
    NtClose(hToken);
    if (!NT_SUCCESS(Status)) goto Quickie;

    /* Now check the SID Length */
    UserSid = TokenInfo->User.Sid;
    Length = RtlLengthSid(UserSid) + sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE);

    /* Allocate a buffer for the Security Descriptor, with SID and DACL */
    ProcSd = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY, SECURITY_DESCRIPTOR_MIN_LENGTH + Length);
    if (!ProcSd)
    {
        Status = STATUS_NO_MEMORY;
        goto Quickie;
    }

    /* Set the pointer to the DACL */
    Dacl = (PACL)((ULONG_PTR)ProcSd + SECURITY_DESCRIPTOR_MIN_LENGTH);

    /* Now create the SD itself */
    Status = RtlCreateSecurityDescriptor(ProcSd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: SD creation failed - status = %lx\n", Status);
        goto Quickie;
    }

    /* Create the DACL for it*/
    Status = RtlCreateAcl(Dacl, Length, ACL_REVISION2);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: DACL creation failed - status = %lx\n", Status);
        goto Quickie;
    }

    /* Create the ACE */
    Status = RtlAddAccessAllowedAce(Dacl,
                                    ACL_REVISION,
                                    PROCESS_VM_READ | PROCESS_VM_WRITE |
                                    PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE |
                                    PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME |
                                    PROCESS_QUERY_INFORMATION | READ_CONTROL,
                                    UserSid);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: ACE creation failed - status = %lx\n", Status);
        goto Quickie;
    }

    /* Clear the DACL in the SD */
    Status = RtlSetDaclSecurityDescriptor(ProcSd, TRUE, Dacl, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: set DACL failed - status = %lx\n", Status);
        goto Quickie;
    }

    /* Write the SD into the Process */
    Status = NtSetSecurityObject(hProcess, DACL_SECURITY_INFORMATION, ProcSd);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: set process DACL failed - status = %lx\n", Status);
        goto Quickie;
    }

    /* Free the memory and return */
Quickie:
    if (ProcSd) RtlFreeHeap(CsrHeap, 0, ProcSd);
    if (TokenInfo) RtlFreeHeap(CsrHeap, 0, TokenInfo);
    return Status;
}

/* One ACE of a DACL made by CsrBuildDacl */
typedef struct _CSR_ACE_SPEC
{
    PSID Sid;
    ACCESS_MASK Mask;
    UCHAR Flags;
} CSR_ACE_SPEC;

/*++
 * @name CsrBuildDacl
 *
 * Builds a DACL of access-allowed ACEs in the CSR heap and puts it in a
 * security descriptor. The caller frees the DACL with CsrFreeDacl.
 *
 *--*/
static
NTSTATUS
CsrBuildDacl(IN const CSR_ACE_SPEC *Aces,
             IN ULONG Count,
             OUT PSECURITY_DESCRIPTOR Sd)
{
    PACL Dacl;
    ULONG AclLength = sizeof(ACL), i;
    NTSTATUS Status;

    for (i = 0; i < Count; i++)
        AclLength += sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(Aces[i].Sid);

    Dacl = RtlAllocateHeap(CsrHeap, 0, AclLength);
    if (!Dacl) return STATUS_NO_MEMORY;

    Status = RtlCreateAcl(Dacl, AclLength, ACL_REVISION2);
    for (i = 0; NT_SUCCESS(Status) && i < Count; i++)
    {
        Status = RtlAddAccessAllowedAceEx(Dacl, ACL_REVISION2, Aces[i].Flags, Aces[i].Mask, Aces[i].Sid);
    }
    if (NT_SUCCESS(Status))
        Status = RtlCreateSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlSetDaclSecurityDescriptor(Sd, TRUE, Dacl, FALSE);
    if (!NT_SUCCESS(Status))
        RtlFreeHeap(CsrHeap, 0, Dacl);
    return Status;
}

static
VOID
CsrFreeDacl(IN PSECURITY_DESCRIPTOR Sd)
{
    PACL Dacl;
    BOOLEAN Present, Default;

    if (NT_SUCCESS(RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Default)) && Present && Dacl)
        RtlFreeHeap(CsrHeap, 0, Dacl);
}

/*++
 * @name CsrBuildSessionProtection
 *
 * The DACLs of the csrss objects of a session other than 0, as measured on
 * Windows 10 22H2 (session 1, minus the entries made for the session's logon:
 * the user, the logon SID and the Desktop Window Manager group, which logon
 * adds, phase P3c/P4). Session 0's objects are left as they are.
 *
 * @param Kind
 *        CSR_PROTECT_SESSION_DIR: \Sessions\<id>: SYSTEM and Administrators
 *            have full access, the creator's children inherit full access,
 *            the restricted code can traverse;
 *        CSR_PROTECT_WINDOWS_DIR: \Sessions\<id>\Windows (csrss ports): the
 *            world can only read, query and traverse, SYSTEM has full access;
 *        CSR_PROTECT_BNOLINK: \Sessions\BNOLINKS\<id>: the world and the
 *            restricted code can read/query, Administrators have full access;
 *        CSR_PROTECT_WINDOWS_LINK: \Sessions\0\Windows: SYSTEM and
 *            Administrators only.
 *
 *--*/
#define CSR_PROTECT_SESSION_DIR     0
#define CSR_PROTECT_WINDOWS_DIR     1
#define CSR_PROTECT_BNOLINK         2
#define CSR_PROTECT_WINDOWS_LINK    3

static
NTSTATUS
CsrBuildSessionProtection(IN ULONG Kind,
                          OUT PSECURITY_DESCRIPTOR Sd)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY CreatorAuthority = {SECURITY_CREATOR_SID_AUTHORITY};
    PSID SystemSid = NULL, AdminSid = NULL, WorldSid = NULL, CreatorSid = NULL, RestrictedSid = NULL;
    const UCHAR Inherit = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE;
    NTSTATUS Status;

    Status = RtlAllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                                         0, 0, 0, 0, 0, 0, 0, &SystemSid);
    if (NT_SUCCESS(Status))
        Status = RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                             DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminSid);
    if (NT_SUCCESS(Status))
        Status = RtlAllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID,
                                             0, 0, 0, 0, 0, 0, 0, &WorldSid);
    if (NT_SUCCESS(Status))
        Status = RtlAllocateAndInitializeSid(&CreatorAuthority, 1, SECURITY_CREATOR_OWNER_RID,
                                             0, 0, 0, 0, 0, 0, 0, &CreatorSid);
    if (NT_SUCCESS(Status))
        Status = RtlAllocateAndInitializeSid(&NtAuthority, 1, SECURITY_RESTRICTED_CODE_RID,
                                             0, 0, 0, 0, 0, 0, 0, &RestrictedSid);
    if (NT_SUCCESS(Status))
    {
        const CSR_ACE_SPEC SessionDir[] =
        {
            { CreatorSid,    GENERIC_ALL,           Inherit },
            { AdminSid,      DIRECTORY_ALL_ACCESS,  0 },
            { SystemSid,     DIRECTORY_ALL_ACCESS,  0 },
            { RestrictedSid, DIRECTORY_TRAVERSE,    0 },
        };
        const CSR_ACE_SPEC WindowsDir[] =
        {
            { WorldSid,      READ_CONTROL | DIRECTORY_QUERY | DIRECTORY_TRAVERSE, 0 },
            { SystemSid,     DIRECTORY_ALL_ACCESS,  0 },
        };
        const CSR_ACE_SPEC BnoLink[] =
        {
            { WorldSid,      READ_CONTROL | SYMBOLIC_LINK_QUERY, 0 },
            { RestrictedSid, READ_CONTROL | SYMBOLIC_LINK_QUERY, 0 },
            { AdminSid,      SYMBOLIC_LINK_ALL_ACCESS, 0 },
            { AdminSid,      SYMBOLIC_LINK_ALL_ACCESS, 0 }, /* Windows lists it twice */
        };
        const CSR_ACE_SPEC WindowsLink[] =
        {
            { SystemSid,     SYMBOLIC_LINK_ALL_ACCESS, 0 },
            { AdminSid,      SYMBOLIC_LINK_ALL_ACCESS, 0 },
            { AdminSid,      SYMBOLIC_LINK_ALL_ACCESS, 0 }, /* Windows lists it twice */
        };

        switch (Kind)
        {
            case CSR_PROTECT_SESSION_DIR:
                Status = CsrBuildDacl(SessionDir, RTL_NUMBER_OF(SessionDir), Sd);
                break;
            case CSR_PROTECT_WINDOWS_DIR:
                Status = CsrBuildDacl(WindowsDir, RTL_NUMBER_OF(WindowsDir), Sd);
                break;
            case CSR_PROTECT_BNOLINK:
                Status = CsrBuildDacl(BnoLink, RTL_NUMBER_OF(BnoLink), Sd);
                break;
            default:
                Status = CsrBuildDacl(WindowsLink, RTL_NUMBER_OF(WindowsLink), Sd);
                break;
        }
    }

    /* The DACL holds copies of the SIDs */
    if (SystemSid) RtlFreeSid(SystemSid);
    if (AdminSid) RtlFreeSid(AdminSid);
    if (WorldSid) RtlFreeSid(WorldSid);
    if (CreatorSid) RtlFreeSid(CreatorSid);
    if (RestrictedSid) RtlFreeSid(RestrictedSid);
    return Status;
}

/*++
 * @name CsrSetDirectorySecurity
 *
 * The CsrSetDirectorySecurity routine sets the security descriptor for the
 * specified Object Directory.
 *
 * @param ObjectDirectory
 *        Handle fo the Object Directory to protect.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrSetDirectorySecurity(IN HANDLE ObjectDirectory)
{
    SECURITY_DESCRIPTOR Sd;
    NTSTATUS Status;

    /*
     * Session 0 keeps the directory as it is (FIXME). A session other than
     * 0 (NitroSessions) gets the DACL that Windows gives its \Sessions\<id>\Windows.
     */
    if (SessionId == 0) return STATUS_SUCCESS;

    Status = CsrBuildSessionProtection(CSR_PROTECT_WINDOWS_DIR, &Sd);
    if (!NT_SUCCESS(Status)) return Status;
    Status = NtSetSecurityObject(ObjectDirectory, DACL_SECURITY_INFORMATION, &Sd);
    CsrFreeDacl(&Sd);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: cannot protect the object directory of session %lu, Status=%lx\n",
                SessionId, Status);
    }
    return Status;
}

/*++
 * @name GetDosDevicesProtection
 *
 * The GetDosDevicesProtection creates a security descriptor for the DOS Devices
 * Object Directory.
 *
 * @param DosDevicesSd
 *        Pointer to the Security Descriptor to return.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks Depending on the DOS Devices Protection Mode (set in the registry),
 *          regular users may or may not have full access to the directory.
 *
 *--*/
NTSTATUS
NTAPI
GetDosDevicesProtection(OUT PSECURITY_DESCRIPTOR DosDevicesSd)
{
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY CreatorAuthority = {SECURITY_CREATOR_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY NtSidAuthority = {SECURITY_NT_AUTHORITY};
    PSID WorldSid, CreatorSid, AdminSid, SystemSid;
    UCHAR KeyValueBuffer[0x40];
    PKEY_VALUE_PARTIAL_INFORMATION KeyValuePartialInfo;
    UNICODE_STRING KeyName;
    ULONG ProtectionMode = 0;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PACL Dacl;
    PACCESS_ALLOWED_ACE Ace;
    HANDLE hKey;
    NTSTATUS Status;
    ULONG ResultLength, SidLength, AclLength;

    /* Create the SD */
    Status = RtlCreateSecurityDescriptor(DosDevicesSd, SECURITY_DESCRIPTOR_REVISION);
    ASSERT(NT_SUCCESS(Status));

    /* Initialize the System SID */
    Status = RtlAllocateAndInitializeSid(&NtSidAuthority, 1,
                                         SECURITY_LOCAL_SYSTEM_RID,
                                         0, 0, 0, 0, 0, 0, 0,
                                         &SystemSid);
    ASSERT(NT_SUCCESS(Status));

    /* Initialize the World SID */
    Status = RtlAllocateAndInitializeSid(&WorldAuthority, 1,
                                         SECURITY_WORLD_RID,
                                         0, 0, 0, 0, 0, 0, 0,
                                         &WorldSid);
    ASSERT(NT_SUCCESS(Status));

    /* Initialize the Admin SID */
    Status = RtlAllocateAndInitializeSid(&NtSidAuthority, 2,
                                         SECURITY_BUILTIN_DOMAIN_RID,
                                         DOMAIN_ALIAS_RID_ADMINS,
                                         0, 0, 0, 0, 0, 0,
                                         &AdminSid);
    ASSERT(NT_SUCCESS(Status));

    /* Initialize the Creator SID */
    Status = RtlAllocateAndInitializeSid(&CreatorAuthority, 1,
                                         SECURITY_CREATOR_OWNER_RID,
                                         0, 0, 0, 0, 0, 0, 0,
                                         &CreatorSid);
    ASSERT(NT_SUCCESS(Status));

    /* Open the Session Manager Key */
    RtlInitUnicodeString(&KeyName, SM_REG_KEY);
    InitializeObjectAttributes(&ObjectAttributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    Status = NtOpenKey(&hKey, KEY_READ, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        /* Read the key value */
        RtlInitUnicodeString(&KeyName, L"ProtectionMode");
        Status = NtQueryValueKey(hKey,
                                 &KeyName,
                                 KeyValuePartialInformation,
                                 KeyValueBuffer,
                                 sizeof(KeyValueBuffer),
                                 &ResultLength);

        /* Make sure it's what we expect it to be */
        KeyValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)KeyValueBuffer;
        if ((NT_SUCCESS(Status)) && (KeyValuePartialInfo->Type == REG_DWORD) &&
            (*(PULONG)KeyValuePartialInfo->Data))
        {
            /* Save the Protection Mode */
            ProtectionMode = *(PULONG)KeyValuePartialInfo->Data;
        }

        /* Close the handle */
        NtClose(hKey);
    }

    /* Check the Protection Mode */
    if (ProtectionMode & 3)
    {
        /* Calculate SID Lengths */
        SidLength = RtlLengthSid(CreatorSid) + RtlLengthSid(SystemSid) +
                    RtlLengthSid(AdminSid);
        AclLength = sizeof(ACL) + 3 * sizeof(ACCESS_ALLOWED_ACE) + SidLength;

        /* Allocate memory for the DACL */
        Dacl = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY, AclLength);
        ASSERT(Dacl != NULL);

        /* Build the ACL and add 3 ACEs */
        Status = RtlCreateAcl(Dacl, AclLength, ACL_REVISION2);
        ASSERT(NT_SUCCESS(Status));
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, SystemSid);
        ASSERT(NT_SUCCESS(Status));
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, AdminSid);
        ASSERT(NT_SUCCESS(Status));
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, CreatorSid);
        ASSERT(NT_SUCCESS(Status));

        /* Edit the ACEs to make them inheritable */
        Status = RtlGetAce(Dacl, 0, (PVOID*)&Ace);
        ASSERT(NT_SUCCESS(Status));
        Ace->Header.AceFlags |= OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        Status = RtlGetAce(Dacl, 1, (PVOID*)&Ace);
        ASSERT(NT_SUCCESS(Status));
        Ace->Header.AceFlags |= OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        Status = RtlGetAce(Dacl, 2, (PVOID*)&Ace);
        ASSERT(NT_SUCCESS(Status));
        Ace->Header.AceFlags |= OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE;

        /* Set this DACL with the SD */
        Status = RtlSetDaclSecurityDescriptor(DosDevicesSd, TRUE, Dacl, FALSE);
        ASSERT(NT_SUCCESS(Status));
        goto Quickie;
    }
    else
    {
        /* Calculate SID Lengths */
        SidLength = RtlLengthSid(WorldSid) + RtlLengthSid(SystemSid);
        AclLength = sizeof(ACL) + 3 * sizeof(ACCESS_ALLOWED_ACE) + SidLength;

        /* Allocate memory for the DACL */
        Dacl = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY, AclLength);
        ASSERT(Dacl != NULL);

        /* Build the ACL and add 3 ACEs */
        Status = RtlCreateAcl(Dacl, AclLength, ACL_REVISION2);
        ASSERT(NT_SUCCESS(Status));
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, WorldSid);
        ASSERT(NT_SUCCESS(Status));
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, SystemSid);
        ASSERT(NT_SUCCESS(Status));
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, WorldSid);
        ASSERT(NT_SUCCESS(Status));

        /* Edit the last ACE to make it inheritable */
        Status = RtlGetAce(Dacl, 2, (PVOID*)&Ace);
        ASSERT(NT_SUCCESS(Status));
        Ace->Header.AceFlags |= OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE;

        /* Set this DACL with the SD */
        Status = RtlSetDaclSecurityDescriptor(DosDevicesSd, TRUE, Dacl, FALSE);
        ASSERT(NT_SUCCESS(Status));
        goto Quickie;
    }

/* FIXME: failure cases! Fail: */
    /* Free the memory */
    RtlFreeHeap(CsrHeap, 0, Dacl);

/* FIXME: semi-failure cases! Quickie: */
Quickie:
    /* Free the SIDs */
    RtlFreeSid(CreatorSid);
    RtlFreeSid(AdminSid);
    RtlFreeSid(WorldSid);
    RtlFreeSid(SystemSid);

    /* Return */
    return Status;
}

/*++
 * @name FreeDosDevicesProtection
 *
 * The FreeDosDevicesProtection frees the security descriptor that was created
 * by GetDosDevicesProtection
 *
 * @param DosDevicesSd
 *        Pointer to the security descriptor to free.

 * @return None.
 *
 * @remarks None.
 *
 *--*/
VOID
NTAPI
FreeDosDevicesProtection(IN PSECURITY_DESCRIPTOR DosDevicesSd)
{
    PACL Dacl;
    BOOLEAN Present, Default;
    NTSTATUS Status;

    /* Get the DACL corresponding to this SD */
    Status = RtlGetDaclSecurityDescriptor(DosDevicesSd, &Present, &Dacl, &Default);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Present);
    ASSERT(Dacl != NULL);

    /* Free it */
    if ((NT_SUCCESS(Status)) && (Dacl)) RtlFreeHeap(CsrHeap, 0, Dacl);
}

/*++
 * @name CsrCreateSessionObjectDirectory
 *
 * The CsrCreateSessionObjectDirectory routine creates the BaseNamedObjects,
 * Session and Dos Devices directories for the specified session.
 *
 * @param Session
 *        Session ID for which to create the directories.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrCreateSessionObjectDirectory(IN ULONG Session)
{
    WCHAR SessionBuffer[512], BnoBuffer[512];
    UNICODE_STRING SessionString, BnoString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE BnoHandle;
    SECURITY_DESCRIPTOR DosDevicesSd, SessionSd, LinkSd;
    BOOLEAN HaveSessionSd = FALSE, HaveLinkSd = FALSE;
    NTSTATUS Status;

    /* Generate the session BNOLINKS directory name */
    _swprintf(SessionBuffer, L"%ws\\BNOLINKS", SESSION_ROOT);
    RtlInitUnicodeString(&SessionString, SessionBuffer);

    /* Create it */
    InitializeObjectAttributes(&ObjectAttributes,
                               &SessionString,
                               OBJ_OPENIF | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    Status = NtCreateDirectoryObject(&BNOLinksDirectory,
                                     DIRECTORY_ALL_ACCESS,
                                     &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: NtCreateDirectoryObject failed in "
                "CsrCreateSessionObjectDirectory - status = %lx\n", Status);
        return Status;
    }

    /* Now add the Session ID */
    _swprintf(SessionBuffer, L"%lu", Session);
    RtlInitUnicodeString(&SessionString, SessionBuffer);

    /* Create the per-session symlink to the BaseNamedObjects directory */
    if (Session)
    {
        /* Use the session path */
        _swprintf(BnoBuffer, L"%ws\\%lu\\BaseNamedObjects", SESSION_ROOT, Session);
        RtlInitUnicodeString(&BnoString, BnoBuffer);
    }
    else
    {
        /* Use the direct name */
        RtlInitUnicodeString(&BnoString, L"\\BaseNamedObjects");
    }
    /* A session other than 0 (NitroSessions): the link has Windows' DACL */
    if (Session != 0)
    {
        Status = CsrBuildSessionProtection(CSR_PROTECT_BNOLINK, &LinkSd);
        if (!NT_SUCCESS(Status)) return Status;
        HaveLinkSd = TRUE;
    }
    InitializeObjectAttributes(&ObjectAttributes,
                               &SessionString,
                               OBJ_OPENIF | OBJ_CASE_INSENSITIVE,
                               BNOLinksDirectory,
                               HaveLinkSd ? &LinkSd : NULL);
    Status = NtCreateSymbolicLinkObject(&BnoHandle,
                                        SYMBOLIC_LINK_ALL_ACCESS,
                                        &ObjectAttributes,
                                        &BnoString);
    if (HaveLinkSd) CsrFreeDacl(&LinkSd);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: NtCreateSymbolicLinkObject failed in "
                "CsrCreateSessionObjectDirectory - status = %lx\n", Status);
        return Status;
    }

    /* Create the \DosDevices security descriptor */
    Status = GetDosDevicesProtection(&DosDevicesSd);
    if (!NT_SUCCESS(Status)) return Status;

    /* A session other than 0: the session directory has Windows' DACL */
    if (Session != 0)
    {
        Status = CsrBuildSessionProtection(CSR_PROTECT_SESSION_DIR, &SessionSd);
        if (!NT_SUCCESS(Status))
        {
            FreeDosDevicesProtection(&DosDevicesSd);
            return Status;
        }
        HaveSessionSd = TRUE;
    }

    /* Now create a directory for this session */
    _swprintf(SessionBuffer, L"%ws\\%lu", SESSION_ROOT, Session);
    RtlInitUnicodeString(&SessionString, SessionBuffer);

    /* Create the directory */
    InitializeObjectAttributes(&ObjectAttributes,
                               &SessionString,
                               OBJ_OPENIF | OBJ_CASE_INSENSITIVE,
                               0,
                               HaveSessionSd ? &SessionSd : &DosDevicesSd);
    Status = NtCreateDirectoryObject(&SessionObjectDirectory,
                                     DIRECTORY_ALL_ACCESS,
                                     &ObjectAttributes);
    if (HaveSessionSd) CsrFreeDacl(&SessionSd);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: NtCreateDirectoryObject failed in "
                "CsrCreateSessionObjectDirectory - status = %lx\n", Status);
        FreeDosDevicesProtection(&DosDevicesSd);
        return Status;
    }

    /* Next, create a directory for this session's DOS Devices */
    RtlInitUnicodeString(&SessionString, L"DosDevices");
    InitializeObjectAttributes(&ObjectAttributes,
                               &SessionString,
                               OBJ_CASE_INSENSITIVE,
                               SessionObjectDirectory,
                               &DosDevicesSd);
    Status = NtCreateDirectoryObject(&DosDevicesDirectory,
                                     DIRECTORY_ALL_ACCESS,
                                     &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: NtCreateDirectoryObject failed in "
                "CsrCreateSessionObjectDirectory - status = %lx\n", Status);
    }

    /* Release the security descriptor */
    FreeDosDevicesProtection(&DosDevicesSd);

    /* Return */
    return Status;
}

/*++
 * @name CsrCreateSession0WindowsLink
 *
 * Windows has \Sessions\0\Windows, a symbolic link to \Windows, so that
 * the csrss directory of every session, including session 0, can be reached
 * as \Sessions\<id>\Windows. The fork's session 0 has \Windows only. The
 * link is created when the session feature flag (NitroSessions) is not 0;
 * without it, session 0 is as it always was.
 *
 * @param Target
 *        The csrss object directory of session 0 (\Windows).
 *
 * @return None. A failure is logged and is not fatal.
 *
 * @remarks None.
 *
 *--*/
VOID
NTAPI
CsrCreateSession0WindowsLink(IN PUNICODE_STRING Target)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(SM_REG_KEY);
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"NitroSessions");
    UNICODE_STRING LinkName = RTL_CONSTANT_STRING(L"\\Sessions\\0\\Windows");
    OBJECT_ATTRIBUTES ObjectAttributes;
    UCHAR KeyValueBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION KeyValuePartialInfo = (PVOID)KeyValueBuffer;
    ULONG ResultLength;
    SECURITY_DESCRIPTOR LinkSd;
    HANDLE hKey, LinkHandle;
    NTSTATUS Status;

    /* Only when the flag is set to a non-zero DWORD */
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&hKey, KEY_QUERY_VALUE, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) return;
    Status = NtQueryValueKey(hKey,
                             &ValueName,
                             KeyValuePartialInformation,
                             KeyValueBuffer,
                             sizeof(KeyValueBuffer),
                             &ResultLength);
    NtClose(hKey);
    if (!NT_SUCCESS(Status) ||
        (KeyValuePartialInfo->Type != REG_DWORD) ||
        (KeyValuePartialInfo->DataLength != sizeof(ULONG)) ||
        (*(PULONG)KeyValuePartialInfo->Data == 0))
    {
        return;
    }

    /* Windows: only SYSTEM and Administrators have access to the link */
    Status = CsrBuildSessionProtection(CSR_PROTECT_WINDOWS_LINK, &LinkSd);
    if (!NT_SUCCESS(Status)) return;
    InitializeObjectAttributes(&ObjectAttributes,
                               &LinkName,
                               OBJ_OPENIF | OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
                               NULL,
                               &LinkSd);
    Status = NtCreateSymbolicLinkObject(&LinkHandle,
                                        SYMBOLIC_LINK_ALL_ACCESS,
                                        &ObjectAttributes,
                                        Target);
    CsrFreeDacl(&LinkSd);
    if (NT_SUCCESS(Status))
        NtClose(LinkHandle);
    else
        DPRINT1("CSRSS: cannot create %wZ, Status=%lx\n", &LinkName, Status);
}

/*++
 * @name CsrParseServerCommandLine
 *
 * The CsrParseServerCommandLine routine parses the CSRSS command-line in the
 * registry and performs operations for each entry found.
 *
 * @param ArgumentCount
 *        Number of arguments on the command line.
 *
 * @param Arguments
 *        Array of arguments.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrParseServerCommandLine(IN ULONG ArgumentCount,
                          IN PCHAR Arguments[])
{
    NTSTATUS Status;
    PCHAR ParameterName = NULL, ParameterValue = NULL, EntryPoint, ServerString;
    ULONG i, DllIndex;
    ANSI_STRING AnsiString;
    OBJECT_ATTRIBUTES ObjectAttributes;

    /* Set the Defaults */
    CsrTotalPerProcessDataLength = 0;
    CsrObjectDirectory = NULL;
#ifdef __REACTOS__
    CsrWindowsControl = FALSE;
    CsrSubSystemType = IMAGE_SUBSYSTEM_UNKNOWN;
#endif
    CsrMaxApiRequestThreads = 16;

    /* Save our Session ID, and create a Directory for it */
    SessionId = NtCurrentPeb()->SessionId;
    Status = CsrCreateSessionObjectDirectory(SessionId);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: CsrCreateSessionObjectDirectory failed (%lx)\n",
                Status);

        /* It's not fatal if the session ID isn't zero */
        if (SessionId != 0) return Status;
        ASSERT(NT_SUCCESS(Status));
    }

    /* Loop through every argument */
    for (i = 1; i < ArgumentCount; i++)
    {
        /* Split Name and Value */
        ParameterName = Arguments[i];
        ParameterValue = NULL;
        ParameterValue = strchr(ParameterName, '=');
        if (ParameterValue) *ParameterValue++ = ANSI_NULL;
        DPRINT("Name=%s, Value=%s\n", ParameterName, ParameterValue);

        /* Check for Object Directory */
        if (_stricmp(ParameterName, "ObjectDirectory") == 0)
        {
            /* Initialize the directory name */
            RtlInitAnsiString(&AnsiString, ParameterValue);
            if (SessionId != 0)
            {
                /* The csrss of a session other than 0 (NitroSessions):
                   ObjectDirectory=\Windows means \Sessions\<id>\Windows */
                UNICODE_STRING SessionDirectory;
                WCHAR SessionPrefix[32];
                ULONG Size;

                _swprintf(SessionPrefix, L"%ws\\%lu", SESSION_ROOT, SessionId);
                Status = RtlAnsiStringToUnicodeString(&SessionDirectory,
                                                      &AnsiString,
                                                      TRUE);
                if (!NT_SUCCESS(Status)) return Status;

                /* ULONG: the sum of two USHORT lengths cannot wrap, it is
                   only too long for a UNICODE_STRING */
                Size = (ULONG)(wcslen(SessionPrefix) * sizeof(WCHAR)) +
                       SessionDirectory.Length + sizeof(UNICODE_NULL);
                if (Size > MAXUSHORT)
                {
                    RtlFreeUnicodeString(&SessionDirectory);
                    return STATUS_NAME_TOO_LONG;
                }
                CsrDirectoryName.Buffer = RtlAllocateHeap(CsrHeap, 0, Size);
                if (!CsrDirectoryName.Buffer)
                {
                    RtlFreeUnicodeString(&SessionDirectory);
                    return STATUS_NO_MEMORY;
                }
                CsrDirectoryName.Length = 0;
                CsrDirectoryName.MaximumLength = (USHORT)Size;
                RtlAppendUnicodeToString(&CsrDirectoryName, SessionPrefix);
                RtlAppendUnicodeStringToString(&CsrDirectoryName, &SessionDirectory);
                RtlFreeUnicodeString(&SessionDirectory);
                DPRINT1("CSRSS: session %lu object directory %wZ\n",
                        SessionId, &CsrDirectoryName);
            }
            else
            {
                Status = RtlAnsiStringToUnicodeString(&CsrDirectoryName,
                                                      &AnsiString,
                                                      TRUE);
                ASSERT(NT_SUCCESS(Status));
                if (!NT_SUCCESS(Status)) return Status;
            }

            /* Create it */
            InitializeObjectAttributes(&ObjectAttributes,
                                       &CsrDirectoryName,
                                       OBJ_OPENIF | OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
                                       NULL,
                                       NULL);
            Status = NtCreateDirectoryObject(&CsrObjectDirectory,
                                             DIRECTORY_ALL_ACCESS,
                                             &ObjectAttributes);
            if (!NT_SUCCESS(Status)) return Status;

            /* Secure it */
            Status = CsrSetDirectorySecurity(CsrObjectDirectory);
            if (!NT_SUCCESS(Status)) return Status;

            /* Session 0: \Sessions\0\Windows -> \Windows, with the session flag */
            if (SessionId == 0)
                CsrCreateSession0WindowsLink(&CsrDirectoryName);
        }
        else if (_stricmp(ParameterName, "SubSystemType") == 0)
        {
#ifdef __REACTOS__
            /* Well-known subsystems, specified by names */
            if (_stricmp(ParameterValue, "windows") == 0)
            {
                /* Behaviour compatible with Windows 7+ */
                if (CsrWindowsControl)
                    CsrSubSystemType = IMAGE_SUBSYSTEM_WINDOWS_GUI;
                else
                    CsrSubSystemType = IMAGE_SUBSYSTEM_WINDOWS_CUI;
            }
            else if (_stricmp(ParameterValue, "posix") == 0)
            {
                CsrSubSystemType = IMAGE_SUBSYSTEM_POSIX_CUI;
            }
            else if (_stricmp(ParameterValue, "os2") == 0)
            {
                CsrSubSystemType = IMAGE_SUBSYSTEM_OS2_CUI;
            }
            else if (_stricmp(ParameterValue, "native") == 0)
            {
                CsrSubSystemType = IMAGE_SUBSYSTEM_NATIVE;
            }
            else
            {
                /* Another subsystem type, specified by a numerical value */
                Status = RtlCharToInteger(ParameterValue, 0, &CsrSubSystemType);
            }
#else
            /* Ignored */
#endif
        }
        else if (_stricmp(ParameterName, "MaxRequestThreads") == 0)
        {
            Status = RtlCharToInteger(ParameterValue,
                                      0,
                                      &CsrMaxApiRequestThreads);
        }
        else if (_stricmp(ParameterName, "RequestThreads") == 0)
        {
            /* Ignored */
            Status = STATUS_SUCCESS;
        }
        else if (_stricmp(ParameterName, "ProfileControl") == 0)
        {
            /* Related functionality ignored since NT 3.5 */
        }
        else if (_stricmp(ParameterName, "SharedSection") == 0)
        {
            /* Create the Section */
            Status = CsrSrvCreateSharedSection(ParameterValue);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("CSRSS: *** Invalid syntax for %s=%s (Status == %X)\n",
                        ParameterName, ParameterValue, Status);
                return Status;
            }

            /* Load us */
            Status = CsrLoadServerDll("CSRSS" /* "CSRSRV" */, NULL, CSRSRV_SERVERDLL_INDEX);
        }
        else if (_stricmp(ParameterName, "ServerDll") == 0)
        {
            /* Loop the command line */
            EntryPoint = NULL;
            Status = STATUS_INVALID_PARAMETER;
            ServerString = ParameterValue;
            while (*ServerString)
            {
                /* Check for the Entry Point */
                if ((*ServerString == ':') && (!EntryPoint))
                {
                    /* Found it. NULL-terminate and save it. */
                    *ServerString++ = ANSI_NULL;
                    EntryPoint = ServerString;
                }

                /* Check for the Dll Index */
                if (*ServerString++ == ',') break;
            }

            /* Did we find something to load? */
            if (!*ServerString)
            {
                DPRINT1("CSRSS: *** Invalid syntax for ServerDll=%s (Status == %X)\n",
                        ParameterValue, Status);
                return Status;
            }

            /* Convert it to a ULONG */
            Status = RtlCharToInteger(ServerString, 10, &DllIndex);

            /* Add a null char if it was valid */
            if (NT_SUCCESS(Status)) ServerString[-1] = ANSI_NULL;

            /* Load it */
            if (CsrDebug & 1) DPRINT1("CSRSS: Loading ServerDll=%s:%s\n", ParameterValue, EntryPoint);
            Status = CsrLoadServerDll(ParameterValue, EntryPoint, DllIndex);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("CSRSS: *** Failed loading ServerDll=%s (Status == 0x%x)\n",
                        ParameterValue, Status);
                return Status;
            }
        }
        else if (_stricmp(ParameterName, "Windows") == 0)
        {
#ifdef __REACTOS__
            CsrWindowsControl = (_stricmp(ParameterValue, "On") == 0);
#else
            /* Ignored */
#endif
        }
        else
        {
            /* Invalid parameter on the command line */
            Status = STATUS_INVALID_PARAMETER;
        }
    }

    /* Return status */
    return Status;
}

/*++
 * @name CsrInitCsrRootProcess
 *
 * The CsrInitCsrRootProcess routine further initializes the CSR Root Process
 * created by CsrInitializeProcessStructure, by allocating and initializing
 * per-process data for each Server DLL.
 *
 * @param None.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrInitCsrRootProcess(VOID)
{
    PVOID ProcessData;
    PCSR_SERVER_DLL ServerDll;
    ULONG i = 0;

    /* All Server DLLs are now loaded, allocate a heap for the Root Process */
    ProcessData = RtlAllocateHeap(CsrHeap,
                                  HEAP_ZERO_MEMORY,
                                  CsrTotalPerProcessDataLength);
    if (!ProcessData)
    {
        DPRINT1("CSRSRV:%s: RtlAllocateHeap failed (Status=%08lx)\n",
                __FUNCTION__, STATUS_NO_MEMORY);
        return STATUS_NO_MEMORY;
    }

    /*
     * Our Root Process was never officially initialized,
     * so write the data for each Server DLL manually.
     */

    /* Loop every DLL */
    for (i = 0; i < CSR_SERVER_DLL_MAX; i++)
    {
        /* Get the current Server */
        ServerDll = CsrLoadedServerDll[i];

        /* Is it loaded, and does it have per process data? */
        if (ServerDll && ServerDll->SizeOfProcessData)
        {
            /* It does, give it part of our allocated heap */
            CsrRootProcess->ServerData[i] = ProcessData;

            /* Move to the next heap position */
            ProcessData = (PVOID)((ULONG_PTR)ProcessData +
                                  ServerDll->SizeOfProcessData);
        }
        else
        {
            /* Nothing for this Server DLL */
            CsrRootProcess->ServerData[i] = NULL;
        }
    }

    /* Now initialize the Root Process manually as well */
    for (i = 0; i < CSR_SERVER_DLL_MAX; i++)
    {
        /* Get the current Server */
        ServerDll = CsrLoadedServerDll[i];

        /* Is it loaded, and does it a callback for new processes? */
        if (ServerDll && ServerDll->NewProcessCallback)
        {
            /* Call the callback */
            ServerDll->NewProcessCallback(NULL, CsrRootProcess);
        }
    }

    return STATUS_SUCCESS;
}

/*++
 * @name CsrCreateLocalSystemSD
 *
 * The CsrCreateLocalSystemSD routine creates a Security Descriptor for
 * the local account with PORT_ALL_ACCESS.
 *
 * @param LocalSystemSd
 *        Pointer to a pointer to the security descriptor to create.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrCreateLocalSystemSD(OUT PSECURITY_DESCRIPTOR *LocalSystemSd)
{
    SID_IDENTIFIER_AUTHORITY NtSidAuthority = {SECURITY_NT_AUTHORITY};
    PSID SystemSid;
    ULONG Length;
    PSECURITY_DESCRIPTOR SystemSd;
    PACL Dacl;
    NTSTATUS Status;

    /* Initialize the System SID */
    RtlAllocateAndInitializeSid(&NtSidAuthority, 1,
                                SECURITY_LOCAL_SYSTEM_RID,
                                0, 0, 0, 0, 0, 0, 0,
                                &SystemSid);

    /* Get the length of the SID */
    Length = RtlLengthSid(SystemSid) + sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE);

    /* Allocate a buffer for the Security Descriptor, with SID and DACL */
    SystemSd = RtlAllocateHeap(CsrHeap, 0, SECURITY_DESCRIPTOR_MIN_LENGTH + Length);

    /* Set the pointer to the DACL */
    Dacl = (PACL)((ULONG_PTR)SystemSd + SECURITY_DESCRIPTOR_MIN_LENGTH);

    /* Now create the SD itself */
    Status = RtlCreateSecurityDescriptor(SystemSd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status)) goto Quit;

    /* Create the DACL for it */
    RtlCreateAcl(Dacl, Length, ACL_REVISION2);

    /* Create the ACE */
    Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, PORT_ALL_ACCESS, SystemSid);
    if (!NT_SUCCESS(Status)) goto Quit;

    /* Clear the DACL in the SD */
    Status = RtlSetDaclSecurityDescriptor(SystemSd, TRUE, Dacl, FALSE);
    if (!NT_SUCCESS(Status)) goto Quit;

Quit:
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(CsrHeap, 0, SystemSd);
        SystemSd = NULL;
    }

    /* Free the SID and return*/
    RtlFreeSid(SystemSid);
    *LocalSystemSd = SystemSd;
    return Status;
}

/*++
 * @name CsrRecordSessionManager
 *
 * The Sb port serves only the Session Manager. SMSS starts every csrss, so
 * it is our parent. Keep a handle to it, so that its pid cannot name another
 * process while we run, and its create time, which must not be later than
 * ours. On any failure nothing is recorded and every Sb client is refused.
 *
 *--*/
static
VOID
CsrRecordSessionManager(VOID)
{
    NTSTATUS Status;
    ULONG KernelSessionId;
    PROCESS_BASIC_INFORMATION BasicInfo;
    KERNEL_USER_TIMES OwnTimes, ParentTimes;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;
    HANDLE Parent;

    /* Our session, as the kernel reports it */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessSessionInformation,
                                       &KernelSessionId,
                                       sizeof(KernelSessionId),
                                       NULL);
    if (NT_SUCCESS(Status)) CsrKernelSessionId = KernelSessionId;

    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessBasicInformation,
                                       &BasicInfo,
                                       sizeof(BasicInfo),
                                       NULL);
    if (!NT_SUCCESS(Status)) return;
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessTimes,
                                       &OwnTimes,
                                       sizeof(OwnTimes),
                                       NULL);
    if (!NT_SUCCESS(Status)) return;

    ClientId.UniqueProcess = (HANDLE)BasicInfo.InheritedFromUniqueProcessId;
    ClientId.UniqueThread = NULL;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtOpenProcess(&Parent,
                           PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
                           &ObjectAttributes,
                           &ClientId);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV: cannot open the Session Manager (pid %p), Status=%lx\n",
                ClientId.UniqueProcess, Status);
        return;
    }
    Status = NtQueryInformationProcess(Parent,
                                       ProcessTimes,
                                       &ParentTimes,
                                       sizeof(ParentTimes),
                                       NULL);
    if (!NT_SUCCESS(Status) ||
        (ParentTimes.CreateTime.QuadPart > OwnTimes.CreateTime.QuadPart))
    {
        NtClose(Parent);
        return;
    }

    CsrSmssProcess = Parent;
    CsrSmssProcessId = ClientId.UniqueProcess;
    CsrSmssCreateTime = ParentTimes.CreateTime;
}

/*++
 * @name CsrSbApiPortInitialize
 *
 * The CsrSbApiPortInitialize routine initializes the LPC Port used for
 * communications with the Session Manager (SM) and initializes the static
 * thread that will handle connection requests and APIs.
 *
 * @param None
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrSbApiPortInitialize(VOID)
{
    ULONG Size;
    PSECURITY_DESCRIPTOR PortSd;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE hRequestThread;
    CLIENT_ID ClientId;

    /* Calculate how much space we'll need for the Port Name */
    Size = CsrDirectoryName.Length + sizeof(SB_PORT_NAME) + sizeof(WCHAR);

    /* Create the buffer for it */
    CsrSbApiPortName.Buffer = RtlAllocateHeap(CsrHeap, 0, Size);
    if (!CsrSbApiPortName.Buffer) return STATUS_NO_MEMORY;

    /* Setup the Port Name string */
    CsrSbApiPortName.Length = 0;
    CsrSbApiPortName.MaximumLength = (USHORT)Size;
    RtlAppendUnicodeStringToString(&CsrSbApiPortName, &CsrDirectoryName);
    RtlAppendUnicodeToString(&CsrSbApiPortName, L"\\");
    RtlAppendUnicodeToString(&CsrSbApiPortName, SB_PORT_NAME);
    if (CsrDebug & 2)
        DPRINT1("CSRSS: Creating %wZ port and associated thread\n", &CsrSbApiPortName);

    /* Create Security Descriptor for this Port */
    Status = CsrCreateLocalSystemSD(&PortSd);
    if (!NT_SUCCESS(Status)) return Status;

    /* Initialize the Attributes */
    InitializeObjectAttributes(&ObjectAttributes,
                               &CsrSbApiPortName,
                               0,
                               NULL,
                               PortSd);

    /* Create the Port Object */
    Status = NtCreatePort(&CsrSbApiPort,
                          &ObjectAttributes,
                          sizeof(SB_CONNECTION_INFO),
                          sizeof(SB_API_MSG),
                          32 * sizeof(SB_API_MSG));
    if (PortSd) RtlFreeHeap(CsrHeap, 0, PortSd);

    if (NT_SUCCESS(Status))
    {
        /* Create the Thread to handle the API Requests */
        Status = RtlCreateUserThread(NtCurrentProcess(),
                                     NULL,
                                     TRUE,
                                     0,
                                     0,
                                     0,
                                     CsrSbApiRequestThread,
                                     NULL,
                                     &hRequestThread,
                                     &ClientId);
        if (NT_SUCCESS(Status))
        {
            /* Add it as a Static Server Thread */
            CsrSbApiRequestThreadPtr = CsrAddStaticServerThread(hRequestThread,
                                                                &ClientId,
                                                                0);

            /* Activate it */
            Status = NtResumeThread(hRequestThread, NULL);
        }
    }

    return Status;
}


/* PUBLIC FUNCTIONS ***********************************************************/

/*++
 * @name CsrServerInitialization
 * @implemented NT4
 *
 * The CsrServerInitialization routine is the native (not Server) entrypoint
 * of this Server DLL. It serves as the entrypoint for CSRSS.
 *
 * @param ArgumentCount
 *        Number of arguments on the command line.
 *
 * @param Arguments
 *        Array of arguments from the command line.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrServerInitialization(IN ULONG ArgumentCount,
                        IN PCHAR Arguments[])
{
    NTSTATUS Status = STATUS_SUCCESS;

    /* Cache System Basic Information so we don't always request it */
    Status = NtQuerySystemInformation(SystemBasicInformation,
                                      &CsrNtSysInfo,
                                      sizeof(SYSTEM_BASIC_INFORMATION),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV:%s: NtQuerySystemInformation failed (Status=0x%08lx)\n",
                __FUNCTION__, Status);
        return Status;
    }

    /* Save our Heap */
    CsrHeap = RtlGetProcessHeap();

    /* Set our Security Descriptor to protect the process */
    Status = CsrSetProcessSecurity();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV:%s: CsrSetProcessSecurity failed (Status=0x%08lx)\n",
                __FUNCTION__, Status);
        return Status;
    }

    /* Set up Session Support */
    Status = CsrInitializeNtSessionList();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV:%s: CsrInitializeSessions failed (Status=0x%08lx)\n",
                __FUNCTION__, Status);
        return Status;
    }

    /* Set up Process Support and allocate the CSR Root Process */
    Status = CsrInitializeProcessStructure();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV:%s: CsrInitializeProcessStructure failed (Status=0x%08lx)\n",
                __FUNCTION__, Status);
        return Status;
    }

    /* Parse the command line */
    Status = CsrParseServerCommandLine(ArgumentCount, Arguments);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV:%s: CsrParseServerCommandLine failed (Status=0x%08lx)\n",
                __FUNCTION__, Status);
        return Status;
    }

    /* Finish to initialize the CSR Root Process */
    Status = CsrInitCsrRootProcess();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV:%s: CsrInitCsrRootProcess failed (Status=0x%08lx)\n",
                __FUNCTION__, Status);
        return Status;
    }

    /* Now initialize our API Port */
    Status = CsrApiPortInitialize();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV:%s: CsrApiPortInitialize failed (Status=0x%08lx)\n",
                __FUNCTION__, Status);
        return Status;
    }

#ifdef __REACTOS__
    if (CsrSubSystemType != IMAGE_SUBSYSTEM_UNKNOWN)
    {
#endif
    /* Who may use the Sb port */
    CsrRecordSessionManager();

    /* Initialize the API Port for SM communication */
    Status = CsrSbApiPortInitialize();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV:%s: CsrSbApiPortInitialize failed (Status=0x%08lx)\n",
                __FUNCTION__, Status);
        return Status;
    }

    /* We're all set! Connect to SM! */
    Status = SmConnectToSm(&CsrSbApiPortName,
                           CsrSbApiPort,
#ifdef __REACTOS__
                           CsrSubSystemType,
#else
                           IMAGE_SUBSYSTEM_WINDOWS_GUI,
#endif
                           &CsrSmApiPort);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV:%s: SmConnectToSm failed (Status=0x%08lx)\n",
                __FUNCTION__, Status);
        return Status;
    }
#ifdef __REACTOS__
    }
#endif

    /* Have us handle Hard Errors */
    Status = NtSetDefaultHardErrorPort(CsrApiPort);
    if (!NT_SUCCESS(Status) && (SessionId != 0))
    {
        /*
         * NitroSessions: the kernel has one default hard error port, which
         * session 0's csrss owns. Until it has one per session, the hard
         * errors of other sessions keep going there.
         */
        DPRINT1("CSRSS: session %lu keeps the hard error port of session 0 (Status=0x%08lx)\n",
                SessionId, Status);
        Status = STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSRV:%s: NtSetDefaultHardErrorPort failed (Status=0x%08lx)\n",
                __FUNCTION__, Status);
        return Status;
    }

    /* Return status */
    return Status;
}

/*++
 * @name CsrPopulateDosDevices
 * @unimplemented NT5.1
 *
 * The CsrPopulateDosDevices routine uses the DOS Device Map from the Kernel
 * to populate the Dos Devices Object Directory for the session.
 *
 * @param None.
 *
 * @return None.
 *
 * @remarks None.
 *
 *--*/
VOID
NTAPI
CsrPopulateDosDevices(VOID)
{
    DPRINT1("Deprecated API in r55585.\n");
    return;
}

BOOL
NTAPI
DllMain(IN HINSTANCE hInstanceDll,
        IN DWORD dwReason,
        IN LPVOID lpReserved)
{
    /* We don't do much */
    UNREFERENCED_PARAMETER(hInstanceDll);
    UNREFERENCED_PARAMETER(dwReason);
    UNREFERENCED_PARAMETER(lpReserved);

    return TRUE;
}

/* EOF */
