/*
 * PROJECT:     ReactOS Service Control Manager
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/system/services/security.c
 * PURPOSE:     Security functions
 * COPYRIGHT:   Eric Kohl
 */

/* INCLUDES *****************************************************************/

#include "services.h"

#include <sddl.h>
#include <strsafe.h>

#define NDEBUG
#include <debug.h>

static PSID pLocalSystemSid = NULL;
static PSID pWorldSid = NULL;

static PACL pPipeDacl = NULL;

/* Self-relative descriptors, process heap */
static PSECURITY_DESCRIPTOR pDefaultSD = NULL;
PSECURITY_DESCRIPTOR pScmManagerSD = NULL;
PSECURITY_DESCRIPTOR pPipeSD = NULL;

/*
 * The descriptors below are the ones Windows uses (Windows Server 2022 build 20348, read with
 * QueryServiceObjectSecurity / "sc sdshow"). "Service Security and Access Rights" (learn.microsoft.com)
 * describes the same grants: on the service control manager, local interactive and service logons get
 * connect, enumerate, query lock status and read control, every authenticated user (a network logon too)
 * connect only, LocalSystem also the boot configuration, administrators everything; on a service,
 * interactive and service logons get the query rights, interrogate and user-defined controls, LocalSystem
 * also start, stop and pause, administrators everything.
 */
static const WCHAR ScmManagerSddl[] =
    L"O:SYG:SY"
    L"D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)"
    L"(A;;CC;;;S-1-15-3-1024-528118966-3876874398-709513571-1907873084-3598227634-3698730060-278077788-3990600205)"
    L"S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)";

static const WCHAR ScmDefaultServiceSddl[] =
    L"O:SYG:SY"
    L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
    L"S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";

/*
 * Services of this tree whose Windows descriptor differs from the default one (same source). Used when the
 * service has no stored descriptor yet (first boot, or a service created by an INF): the stored one is
 * written from it. These are the grants applications rely on, e.g. an interactive user may start the
 * Windows Installer service and the DNS client, every authenticated user Windows Update.
 */
static const struct
{
    PCWSTR pszServiceName;
    PCWSTR pszSddl;
} ScmBuiltinServiceSddl[] =
{
    { L"AudioSrv",      L"O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLORC;;;AC)" },
    { L"BITS",          L"O:BAG:BAD:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)" },
    { L"CertPropSvc",   L"O:BAG:BAD:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)" },
    { L"DcomLaunch",    L"O:SYG:SYD:(A;;CCLCLORC;;;AU)(A;;CCDCLCSWRPWPDTLORCWDWO;;;SY)(A;;CCLCSWRPWPDTLORCWDWO;;;BA)(A;;CCLCLO;;;BU)" },
    { L"Dhcp",          L"O:SYG:SYD:(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;NO)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;S-1-2-1)(A;;CCLCSWRPWPDTLOCRRC;;;SY)" },
    { L"Dnscache",      L"O:SYG:SYD:(A;CI;CCLCSWRPLORC;;;BU)(A;CI;CCLCSWRPDTLORC;;;BA)(A;CI;CCLCSWRPDTLORC;;;SY)(A;;CCLCSWRPLORC;;;IU)(A;CI;CCLCSWRPLORC;;;NS)(A;CI;CCLCSWRPLORC;;;LS)(A;CI;CCLCSWRPDTLORC;;;NO)(A;CI;CCLCSWRPLORC;;;AC)" },
    { L"EventLog",      L"O:SYG:SYD:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;LCLO;;;AC)" },
    { L"MpsSvc",        L"O:SYG:SYD:(A;;CCLCLORC;;;AU)(A;;CCDCLCSWRPLORCWDWO;;;SY)(A;;CCLCSWRPLORCWDWO;;;BA)(A;;CCLCLO;;;BU)" },
    /* Windows gives administrators less here but still grants them OpenService(SERVICE_ALL_ACCESS) (measured):
       administrators keep every right, the grants to users are Windows' */
    { L"MSIServer",     L"O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;SU)" },
    { L"RpcSs",         L"O:SYG:SYD:(A;;CCLCLORC;;;AU)(A;;CCDCLCSWRPWPDTLORCWDWO;;;SY)(A;;CCLCSWRPWPDTLORCWDWO;;;BA)(A;;CCLCLO;;;BU)" },
    { L"SamSs",         L"O:SYG:SYD:(A;;CCLCSWLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLO;;;IU)(A;;CCLCSWLO;;;BU)" },
    { L"SCardSvr",      L"O:BAG:BAD:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)" },
    { L"ScDeviceEnum",  L"O:BAG:BAD:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)" },
    { L"Schedule",      L"O:SYG:SYD:(A;;CCLCSWLORC;;;AU)(A;;CCLCSWRPDTLOCRRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWLORC;;;BU)" },
    { L"seclogon",      L"O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPDTLOCRRC;;;IU)(A;;CCLCSWDTLOCRRC;;;SU)(A;;CCLCSWRPDTLOCRRC;;;AU)" },
    { L"Spooler",       L"O:SYG:SYD:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)" },
    { L"W32Time",       L"O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPLOCRRC;;;LS)(A;;CCSWWPLORC;;;LS)" },
    { L"wuauserv",      L"O:SYG:SYD:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)" },
};

static const WCHAR ScmServiceSaclSddl[] = L"S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";


/* FUNCTIONS ****************************************************************/

/* An SDDL string as a self-relative descriptor on the process heap */
static
DWORD
ScmSddlToSD(
    _In_ PCWSTR pszSddl,
    _Out_ PSECURITY_DESCRIPTOR *ppSD)
{
    PSECURITY_DESCRIPTOR pLocalSD = NULL;
    ULONG ulLength = 0;

    *ppSD = NULL;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(pszSddl,
                                                              SDDL_REVISION_1,
                                                              &pLocalSD,
                                                              &ulLength))
    {
        DWORD dwError = GetLastError();
        DPRINT1("Descriptor %S failed to convert (Error %lu)\n", pszSddl, dwError);
        return dwError;
    }

    *ppSD = RtlAllocateHeap(RtlGetProcessHeap(), 0, ulLength);
    if (*ppSD == NULL)
    {
        LocalFree(pLocalSD);
        return ERROR_OUTOFMEMORY;
    }

    RtlCopyMemory(*ppSD, pLocalSD, ulLength);
    LocalFree(pLocalSD);

    return ERROR_SUCCESS;
}


static
DWORD
ScmCreateSids(VOID)
{
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};

    pWorldSid = RtlAllocateHeap(RtlGetProcessHeap(), 0, RtlLengthRequiredSid(1));
    if (pWorldSid == NULL)
        return ERROR_OUTOFMEMORY;
    RtlInitializeSid(pWorldSid, &WorldAuthority, 1);
    *RtlSubAuthoritySid(pWorldSid, 0) = SECURITY_WORLD_RID;

    pLocalSystemSid = RtlAllocateHeap(RtlGetProcessHeap(), 0, RtlLengthRequiredSid(1));
    if (pLocalSystemSid == NULL)
        return ERROR_OUTOFMEMORY;
    RtlInitializeSid(pLocalSystemSid, &NtAuthority, 1);
    *RtlSubAuthoritySid(pLocalSystemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;

    return ERROR_SUCCESS;
}


static
VOID
ScmFreeSids(VOID)
{
    if (pWorldSid != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pWorldSid);

    if (pLocalSystemSid != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pLocalSystemSid);
}


static
DWORD
ScmCreatePipeSD(VOID)
{
    ULONG ulLength;
    NTSTATUS Status;

    /* The control pipes: everybody may connect */
    ulLength = sizeof(ACL) + (sizeof(ACE) + RtlLengthSid(pWorldSid));

    pPipeDacl = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, ulLength);
    if (pPipeDacl == NULL)
        return ERROR_OUTOFMEMORY;

    RtlCreateAcl(pPipeDacl, ulLength, ACL_REVISION);

    RtlAddAccessAllowedAce(pPipeDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           pWorldSid);

    /* Create the absolute security descriptor */
    pPipeSD = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECURITY_DESCRIPTOR));
    if (pPipeSD == NULL)
        return ERROR_OUTOFMEMORY;

    DPRINT("pPipeSD %p\n", pPipeSD);

    Status = RtlCreateSecurityDescriptor(pPipeSD,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
        return RtlNtStatusToDosError(Status);

    Status = RtlSetOwnerSecurityDescriptor(pPipeSD,
                                           pLocalSystemSid,
                                           FALSE);
    if (!NT_SUCCESS(Status))
        return RtlNtStatusToDosError(Status);

    Status = RtlSetGroupSecurityDescriptor(pPipeSD,
                                           pLocalSystemSid,
                                           FALSE);
    if (!NT_SUCCESS(Status))
        return RtlNtStatusToDosError(Status);

    Status = RtlSetDaclSecurityDescriptor(pPipeSD,
                                          TRUE,
                                          pPipeDacl,
                                          FALSE);
    if (!NT_SUCCESS(Status))
        return RtlNtStatusToDosError(Status);

    return ERROR_SUCCESS;
}


static
VOID
ScmFreePipeSD(VOID)
{
    if (pPipeSD != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pPipeSD);

    if (pPipeDacl != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pPipeDacl);
}


static
DWORD
ScmCopySD(
    _In_ PSECURITY_DESCRIPTOR pSource,
    _Out_ PSECURITY_DESCRIPTOR *ppSecurityDescriptor)
{
    ULONG ulLength = RtlLengthSecurityDescriptor(pSource);

    *ppSecurityDescriptor = RtlAllocateHeap(RtlGetProcessHeap(), 0, ulLength);
    if (*ppSecurityDescriptor == NULL)
        return ERROR_OUTOFMEMORY;

    RtlCopyMemory(*ppSecurityDescriptor, pSource, ulLength);
    return ERROR_SUCCESS;
}


/* The default descriptor of a new service (self-relative, process heap: the caller frees it) */
DWORD
ScmCreateDefaultServiceSD(
    PSECURITY_DESCRIPTOR *ppSecurityDescriptor)
{
    *ppSecurityDescriptor = NULL;

    if (pDefaultSD == NULL)
        return ERROR_INVALID_SECURITY_DESCR;

    return ScmCopySD(pDefaultSD, ppSecurityDescriptor);
}


/* The default descriptor itself, read-only */
PSECURITY_DESCRIPTOR
ScmGetDefaultServiceSD(VOID)
{
    return pDefaultSD;
}


/*
 * The descriptor a service gets when it has none stored: the Windows one for the services listed above,
 * else the default one.
 */
DWORD
ScmCreateServiceSDByName(
    _In_ PCWSTR pszServiceName,
    _Out_ PSECURITY_DESCRIPTOR *ppSecurityDescriptor)
{
    WCHAR szSddl[512];
    ULONG i;

    for (i = 0; i < ARRAYSIZE(ScmBuiltinServiceSddl); i++)
    {
        if (_wcsicmp(pszServiceName, ScmBuiltinServiceSddl[i].pszServiceName) != 0)
            continue;

        if (FAILED(StringCchCopyW(szSddl, ARRAYSIZE(szSddl), ScmBuiltinServiceSddl[i].pszSddl)) ||
            FAILED(StringCchCatW(szSddl, ARRAYSIZE(szSddl), ScmServiceSaclSddl)))
            break;

        if (ScmSddlToSD(szSddl, ppSecurityDescriptor) == ERROR_SUCCESS)
            return ERROR_SUCCESS;
        break;
    }

    return ScmCreateDefaultServiceSD(ppSecurityDescriptor);
}


/*
 * A descriptor read from the registry is used only when it is a complete, valid self-relative descriptor of
 * the given length with an owner and a group. A malformed one must not grant anything: the caller falls
 * back to the default descriptor.
 */
BOOL
ScmIsValidStoredSD(
    _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
    _In_ DWORD dwLength)
{
    PSID pOwner = NULL, pGroup = NULL;
    BOOLEAN bDefaulted;

    if (dwLength < sizeof(SECURITY_DESCRIPTOR_RELATIVE))
        return FALSE;

    if (!RtlValidRelativeSecurityDescriptor(pSecurityDescriptor,
                                            dwLength,
                                            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION))
        return FALSE;

    if (!(((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Control & SE_SELF_RELATIVE))
        return FALSE;

    if (RtlLengthSecurityDescriptor(pSecurityDescriptor) > dwLength)
        return FALSE;

    if (!NT_SUCCESS(RtlGetOwnerSecurityDescriptor(pSecurityDescriptor, &pOwner, &bDefaulted)) || pOwner == NULL)
        return FALSE;

    if (!NT_SUCCESS(RtlGetGroupSecurityDescriptor(pSecurityDescriptor, &pGroup, &bDefaulted)) || pGroup == NULL)
        return FALSE;

    return TRUE;
}


DWORD
ScmInitializeSecurity(VOID)
{
    DWORD dwError;

    dwError = ScmCreateSids();
    if (dwError != ERROR_SUCCESS)
        return dwError;

    dwError = ScmSddlToSD(ScmDefaultServiceSddl, &pDefaultSD);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    dwError = ScmSddlToSD(ScmManagerSddl, &pScmManagerSD);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    dwError = ScmCreatePipeSD();
    if (dwError != ERROR_SUCCESS)
        return dwError;

    return ERROR_SUCCESS;
}


VOID
ScmShutdownSecurity(VOID)
{
    ScmFreePipeSD();

    if (pScmManagerSD != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pScmManagerSD);

    if (pDefaultSD != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pDefaultSD);

    ScmFreeSids();
}

/* EOF */
