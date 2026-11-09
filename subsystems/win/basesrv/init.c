/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Base API Server DLL
 * FILE:            subsystems/win/basesrv/init.c
 * PURPOSE:         Initialization
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 *                  Pierre Schweitzer (pierre@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "basesrv.h"
#include "vdm.h"

#include <winreg.h>

#define NDEBUG
#include <debug.h>

#include "api.h"

/* GLOBALS ********************************************************************/

HANDLE BaseSrvDllInstance = NULL;
extern UNICODE_STRING BaseSrvKernel32DllPath;

/* Memory */
HANDLE BaseSrvHeap = NULL;          // Our own heap.
HANDLE BaseSrvSharedHeap = NULL;    // Shared heap with CSR. (CsrSrvSharedSectionHeap)
PBASE_STATIC_SERVER_DATA BaseStaticServerData = NULL;   // Data that we can share amongst processes. Initialized inside BaseSrvSharedHeap.

ULONG SessionId = 0;
ULONG ProtectionMode = 0;

PINIFILE_MAPPING BaseSrvIniFileMapping;

// Windows Server 2003 table from http://j00ru.vexillium.org/csrss_list/api_list.html#Windows_2k3
PCSR_API_ROUTINE BaseServerApiDispatchTable[BasepMaxApiNumber - BASESRV_FIRST_API_NUMBER] =
{
    BaseSrvCreateProcess,
    BaseSrvCreateThread,
    BaseSrvGetTempFile,
    BaseSrvExitProcess,
    BaseSrvDebugProcess,
    BaseSrvCheckVDM,
    BaseSrvUpdateVDMEntry,
    BaseSrvGetNextVDMCommand,
    BaseSrvExitVDM,
    BaseSrvIsFirstVDM,
    BaseSrvGetVDMExitCode,
    BaseSrvSetReenterCount,
    BaseSrvSetProcessShutdownParam,
    BaseSrvGetProcessShutdownParam,
    BaseSrvNlsSetUserInfo,
    BaseSrvNlsSetMultipleUserInfo,
    BaseSrvNlsCreateSection,
    BaseSrvSetVDMCurDirs,
    BaseSrvGetVDMCurDirs,
    BaseSrvBatNotification,
    BaseSrvRegisterWowExec,
    BaseSrvSoundSentryNotification,
    BaseSrvRefreshIniFileMapping,
    BaseSrvDefineDosDevice,
    BaseSrvSetTermsrvAppInstallMode,
    BaseSrvNlsUpdateCacheCount,
    BaseSrvSetTermsrvClientTimeZone,
    BaseSrvSxsCreateActivationContext,
    BaseSrvDebugProcess,
    BaseSrvRegisterThread,
    BaseSrvNlsGetUserInfo,
    BaseSrvUpdateAppcompatCache,
};

BOOLEAN BaseServerApiServerValidTable[BasepMaxApiNumber - BASESRV_FIRST_API_NUMBER] =
{
    TRUE,   // BaseSrvCreateProcess
    TRUE,   // BaseSrvCreateThread
    TRUE,   // BaseSrvGetTempFile
    FALSE,  // BaseSrvExitProcess
    FALSE,  // BaseSrvDebugProcess
    TRUE,   // BaseSrvCheckVDM
    TRUE,   // BaseSrvUpdateVDMEntry
    TRUE,   // BaseSrvGetNextVDMCommand
    TRUE,   // BaseSrvExitVDM
    TRUE,   // BaseSrvIsFirstVDM
    TRUE,   // BaseSrvGetVDMExitCode
    TRUE,   // BaseSrvSetReenterCount
    TRUE,   // BaseSrvSetProcessShutdownParam
    TRUE,   // BaseSrvGetProcessShutdownParam
    TRUE,   // BaseSrvNlsSetUserInfo
    TRUE,   // BaseSrvNlsSetMultipleUserInfo
    TRUE,   // BaseSrvNlsCreateSection
    TRUE,   // BaseSrvSetVDMCurDirs
    TRUE,   // BaseSrvGetVDMCurDirs
    TRUE,   // BaseSrvBatNotification
    TRUE,   // BaseSrvRegisterWowExec
    TRUE,   // BaseSrvSoundSentryNotification
    TRUE,   // BaseSrvRefreshIniFileMapping
    TRUE,   // BaseSrvDefineDosDevice
    TRUE,   // BaseSrvSetTermsrvAppInstallMode
    TRUE,   // BaseSrvNlsUpdateCacheCount
    TRUE,   // BaseSrvSetTermsrvClientTimeZone
    TRUE,   // BaseSrvSxsCreateActivationContext
    FALSE,  // BaseSrvDebugProcess
    TRUE,   // BaseSrvRegisterThread
    TRUE,   // BaseSrvNlsGetUserInfo
    TRUE,   // BaseSrvUpdateAppcompatCache
};

/*
 * On Windows Server 2003, CSR Servers contain
 * the API Names Table only in Debug Builds.
 */
#ifdef CSR_DBG
PCHAR BaseServerApiNameTable[BasepMaxApiNumber - BASESRV_FIRST_API_NUMBER] =
{
    "BaseCreateProcess",
    "BaseCreateThread",
    "BaseGetTempFile",
    "BaseExitProcess",
    "BaseDebugProcess",
    "BaseCheckVDM",
    "BaseUpdateVDMEntry",
    "BaseGetNextVDMCommand",
    "BaseExitVDM",
    "BaseIsFirstVDM",
    "BaseGetVDMExitCode",
    "BaseSetReenterCount",
    "BaseSetProcessShutdownParam",
    "BaseGetProcessShutdownParam",
    "BaseNlsSetUserInfo",
    "BaseNlsSetMultipleUserInfo",
    "BaseNlsCreateSection",
    "BaseSetVDMCurDirs",
    "BaseGetVDMCurDirs",
    "BaseBatNotification",
    "BaseRegisterWowExec",
    "BaseSoundSentryNotification",
    "BaseRefreshIniFileMapping",
    "BaseDefineDosDevice",
    "BaseSetTermsrvAppInstallMode",
    "BaseNlsUpdateCacheCount",
    "BaseSetTermsrvClientTimeZone",
    "BaseSxsCreateActivationContext",
    "BaseSrvDebugProcessStop",
    "BaseRegisterThread",
    "BaseNlsGetUserInfo",
    "BaseUpdateAppcompatCache",
};
#endif

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
BaseSrvInitializeIniFileMappings(IN PBASE_STATIC_SERVER_DATA StaticServerData)
{
    /* Allocate the mapping blob */
    BaseSrvIniFileMapping = RtlAllocateHeap(BaseSrvSharedHeap,
                                            HEAP_ZERO_MEMORY,
                                            sizeof(*BaseSrvIniFileMapping));
    if (BaseSrvIniFileMapping == NULL)
    {
        DPRINT1("BASESRV: Unable to allocate memory in shared heap for IniFileMapping\n");
        return STATUS_NO_MEMORY;
    }

    /* Set it*/
    StaticServerData->IniFileMapping = BaseSrvIniFileMapping;

    /* FIXME: Do the work to initialize the mappings */
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
CreateBaseAcls(OUT PACL* Dacl,
               OUT PACL* RestrictedDacl)
{
    PSID SystemSid, WorldSid, RestrictedSid;
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    NTSTATUS Status;
    UCHAR KeyValueBuffer[0x40];
    PKEY_VALUE_PARTIAL_INFORMATION KeyValuePartialInfo;
    UNICODE_STRING KeyName;
    ULONG AclLength;
    ULONG ResultLength;
    HANDLE hKey;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG ObjectSecurityMode;
    ACCESS_MASK WorldAccess, RestrictedAccess;

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

    /*
     * Get object security mode. Windows 10 builds the named object directory
     * of every session other than 0 in the restricted mode (measured: the
     * directory lets the world only query and traverse; the logged-on user is
     * granted access when the session is logged on), whatever the kernel's
     * default says: the fork's kernel default is 0. Session 0 stays open.
     */
    if (SessionId == 0)
    {
        ObjectSecurityMode = 0;
    }
    else if (!NT_SUCCESS(NtQuerySystemInformation(SystemObjectSecurityMode, &ObjectSecurityMode, sizeof(ULONG), NULL)) ||
             ObjectSecurityMode == 0)
    {
        ObjectSecurityMode = 1;
    }

    /* Allocate the System SID */
    Status = RtlAllocateAndInitializeSid(&NtAuthority,
                                         1, SECURITY_LOCAL_SYSTEM_RID,
                                         0, 0, 0, 0, 0, 0, 0,
                                         &SystemSid);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* Allocate the World SID */
    Status = RtlAllocateAndInitializeSid(&WorldAuthority,
                                         1, SECURITY_WORLD_RID,
                                         0, 0, 0, 0, 0, 0, 0,
                                         &WorldSid);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeSid(SystemSid);
        goto Return;
    }

    /* Allocate the restricted SID */
    Status = RtlAllocateAndInitializeSid(&NtAuthority,
                                         1, SECURITY_RESTRICTED_CODE_RID,
                                         0, 0, 0, 0, 0, 0, 0,
                                         &RestrictedSid);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeSid(WorldSid);
        RtlFreeSid(SystemSid);
        goto Return;
    }

    /* Allocate one ACL with 3 ACEs each for one SID */
    AclLength = sizeof(ACL) + 3 * sizeof(ACCESS_ALLOWED_ACE) +
                    RtlLengthSid(SystemSid) +
                    RtlLengthSid(WorldSid)  +
                    RtlLengthSid(RestrictedSid);
    *Dacl = RtlAllocateHeap(BaseSrvHeap, 0, AclLength);
    if (*Dacl == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto FreeAndReturn;
    }

    /* Set the correct header fields */
    Status = RtlCreateAcl(*Dacl, AclLength, ACL_REVISION2);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(BaseSrvHeap, 0, *Dacl);
        goto FreeAndReturn;
    }

    /* Setup access for anyone depending on object security mode */
    if (ObjectSecurityMode != 0)
    {
        /*
         * If we have restrictions on security mode, make it read only
         * it also means session ID is not 0
         */
        WorldAccess = DIRECTORY_QUERY | DIRECTORY_TRAVERSE;
    }
    else
    {
        /* Otherwise, open wide */
        WorldAccess = READ_CONTROL | DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY;
    }

    /* Give the appropriate rights to each SID */
    if (NT_SUCCESS(RtlAddAccessAllowedAce(*Dacl, ACL_REVISION2, WorldAccess, WorldSid)) &&
        NT_SUCCESS(RtlAddAccessAllowedAce(*Dacl, ACL_REVISION2, DIRECTORY_ALL_ACCESS, SystemSid)))
    {
        RtlAddAccessAllowedAce(*Dacl, ACL_REVISION2, DIRECTORY_TRAVERSE, RestrictedSid);
    }

    /* Now allocate the restricted DACL */
    *RestrictedDacl = RtlAllocateHeap(BaseSrvHeap, 0, AclLength);
    if (*RestrictedDacl == NULL)
    {
        Status = STATUS_NO_MEMORY;
        RtlFreeHeap(BaseSrvHeap, 0, *Dacl);
        goto FreeAndReturn;
    }

    /* Initialize it */
    Status = RtlCreateAcl(*RestrictedDacl, AclLength, ACL_REVISION2);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(BaseSrvHeap, 0, *RestrictedDacl);
        RtlFreeHeap(BaseSrvHeap, 0, *Dacl);
        goto FreeAndReturn;
    }

    /* Setup access for restricted sid depending on session id and protection mode */
    if (SessionId == 0 || (ProtectionMode & 3) == 0)
    {
        /* If we have no session ID or if protection mode is not set, then open wide */
        RestrictedAccess = READ_CONTROL | DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY;
    }
    else
    {
        /* Otherwise, make read only */
        RestrictedAccess = READ_CONTROL | DIRECTORY_QUERY | DIRECTORY_TRAVERSE;
    }

    /* And add the same ACEs as before */
    Status = RtlAddAccessAllowedAce(*RestrictedDacl, ACL_REVISION2, WorldAccess, WorldSid);
    if (NT_SUCCESS(Status))
    {
        Status = RtlAddAccessAllowedAce(*RestrictedDacl, ACL_REVISION2, DIRECTORY_ALL_ACCESS, SystemSid);
        if (NT_SUCCESS(Status))
        {
            Status = RtlAddAccessAllowedAce(*RestrictedDacl, ACL_REVISION2, RestrictedAccess, RestrictedSid);
        }
    }

    /* The SIDs are captured, can free them now */
FreeAndReturn:
    RtlFreeSid(RestrictedSid);
    RtlFreeSid(WorldSid);
    RtlFreeSid(SystemSid);

Return:
    return Status;
}

/* S-1-15-2-2, "all restricted application packages" (not in the headers) */
#ifndef SECURITY_BUILTIN_PACKAGE_ANY_RESTRICTED_PACKAGE
#define SECURITY_BUILTIN_PACKAGE_ANY_RESTRICTED_PACKAGE 2
#endif

/* One ACE of a DACL made by BaseBuildDacl */
typedef struct _BASE_ACE_SPEC
{
    PSID Sid;
    ACCESS_MASK Mask;
    UCHAR Flags;
} BASE_ACE_SPEC;

static
NTSTATUS
BaseBuildDacl(
    IN const BASE_ACE_SPEC *Aces,
    IN ULONG Count,
    OUT PACL *Dacl)
{
    ULONG AclLength = sizeof(ACL), i;
    NTSTATUS Status;

    for (i = 0; i < Count; i++)
        AclLength += sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(Aces[i].Sid);

    *Dacl = RtlAllocateHeap(BaseSrvHeap, 0, AclLength);
    if (*Dacl == NULL) return STATUS_NO_MEMORY;

    Status = RtlCreateAcl(*Dacl, AclLength, ACL_REVISION2);
    for (i = 0; NT_SUCCESS(Status) && i < Count; i++)
    {
        Status = RtlAddAccessAllowedAceEx(*Dacl, ACL_REVISION2, Aces[i].Flags, Aces[i].Mask, Aces[i].Sid);
    }
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(BaseSrvHeap, 0, *Dacl);
        *Dacl = NULL;
    }
    return Status;
}

/*
 * The DACLs of the namespace objects of a session other than 0, as measured
 * on Windows 10 22H2 (session 1, minus the entries that are made for the
 * session's logon: the user, the logon SID, the Desktop Window Manager group):
 *  - the BaseNamedObjects directory: the world and the restricted code may
 *    only query/traverse (world: container-inheritable), SYSTEM has full
 *    access and its and the creator's children inherit full access;
 *  - the symbolic links in it (Global, Local, Session, AppContainerNamedObjects):
 *    the world may only query, SYSTEM has full access;
 *  - the AppContainerNamedObjects directory: as BaseNamedObjects, and the
 *    AppContainer packages may query/traverse.
 * Sessions are added at logon by the logon code (phase P3c/P4).
 */
static
NTSTATUS
BaseBuildSessionNamespaceDacls(
    OUT PACL *DirectoryDacl,
    OUT PACL *LinkDacl,
    OUT PACL *AppContainerDacl)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY CreatorAuthority = {SECURITY_CREATOR_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY PackageAuthority = {SECURITY_APP_PACKAGE_AUTHORITY};
    PSID SystemSid = NULL, WorldSid = NULL, CreatorSid = NULL, RestrictedSid = NULL;
    PSID AnyPackageSid = NULL, AnyRestrictedPackageSid = NULL;
    const UCHAR Inherit = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE;
    NTSTATUS Status;

    *DirectoryDacl = *LinkDacl = *AppContainerDacl = NULL;

    Status = RtlAllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                                         0, 0, 0, 0, 0, 0, 0, &SystemSid);
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
        Status = RtlAllocateAndInitializeSid(&PackageAuthority, 2, SECURITY_APP_PACKAGE_BASE_RID,
                                             SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE,
                                             0, 0, 0, 0, 0, 0, &AnyPackageSid);
    if (NT_SUCCESS(Status))
        Status = RtlAllocateAndInitializeSid(&PackageAuthority, 2, SECURITY_APP_PACKAGE_BASE_RID,
                                             SECURITY_BUILTIN_PACKAGE_ANY_RESTRICTED_PACKAGE,
                                             0, 0, 0, 0, 0, 0, &AnyRestrictedPackageSid);
    if (NT_SUCCESS(Status))
    {
        const BASE_ACE_SPEC Directory[] =
        {
            { SystemSid,     DIRECTORY_ALL_ACCESS,                         0 },
            { SystemSid,     GENERIC_ALL,                                  Inherit },
            { CreatorSid,    GENERIC_ALL,                                  Inherit },
            { WorldSid,      DIRECTORY_QUERY | DIRECTORY_TRAVERSE,         CONTAINER_INHERIT_ACE },
            { RestrictedSid, DIRECTORY_TRAVERSE,                           0 },
        };
        const BASE_ACE_SPEC Link[] =
        {
            { WorldSid,      SYMBOLIC_LINK_QUERY,                          0 },
            { RestrictedSid, 0,                                            0 },
            { SystemSid,     SYMBOLIC_LINK_ALL_ACCESS,                     0 },
        };
        const BASE_ACE_SPEC AppContainer[] =
        {
            { SystemSid,     DIRECTORY_ALL_ACCESS,                         0 },
            { SystemSid,     GENERIC_ALL,                                  Inherit },
            { CreatorSid,    GENERIC_ALL,                                  Inherit },
            { WorldSid,      DIRECTORY_QUERY | DIRECTORY_TRAVERSE,         CONTAINER_INHERIT_ACE },
            { RestrictedSid, DIRECTORY_TRAVERSE,                           0 },
            { AnyPackageSid, DIRECTORY_QUERY | DIRECTORY_TRAVERSE,         0 },
            { AnyRestrictedPackageSid, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, 0 },
        };

        Status = BaseBuildDacl(Directory, RTL_NUMBER_OF(Directory), DirectoryDacl);
        if (NT_SUCCESS(Status))
            Status = BaseBuildDacl(Link, RTL_NUMBER_OF(Link), LinkDacl);
        if (NT_SUCCESS(Status))
            Status = BaseBuildDacl(AppContainer, RTL_NUMBER_OF(AppContainer), AppContainerDacl);
    }

    /* The ACLs hold copies of the SIDs */
    if (SystemSid) RtlFreeSid(SystemSid);
    if (WorldSid) RtlFreeSid(WorldSid);
    if (CreatorSid) RtlFreeSid(CreatorSid);
    if (RestrictedSid) RtlFreeSid(RestrictedSid);
    if (AnyPackageSid) RtlFreeSid(AnyPackageSid);
    if (AnyRestrictedPackageSid) RtlFreeSid(AnyRestrictedPackageSid);
    return Status;
}

VOID
NTAPI
BaseInitializeStaticServerData(IN PCSR_SERVER_DLL LoadedServerDll)
{
    NTSTATUS Status;
    BOOLEAN Success;
    WCHAR BnoBuffer[100];
    WCHAR Buffer[MAX_PATH];
    PWCHAR HeapBuffer;
    UNICODE_STRING SystemRootString;
    UNICODE_STRING UnexpandedSystemRootString = RTL_CONSTANT_STRING(L"%SystemRoot%");
    UNICODE_STRING BaseSrvCSDString;
    UNICODE_STRING BaseSrvWindowsDirectory;
    UNICODE_STRING BaseSrvWindowsSystemDirectory;
    UNICODE_STRING BnoString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE BaseSrvNamedObjectDirectory;
    HANDLE BaseSrvRestrictedObjectDirectory;
    PACL BnoDacl, BnoRestrictedDacl;
    PACL LinkDacl = NULL, AppContainerDacl = NULL;
    PSECURITY_DESCRIPTOR BnoSd, LinkSd = NULL, AppContainerSd = NULL;
    HANDLE SymHandle;
    UNICODE_STRING DirectoryName, SymlinkName;
    ULONG LuidEnabled;
    RTL_QUERY_REGISTRY_TABLE BaseServerRegistryConfigurationTable[2] =
    {
        {
            NULL,
            RTL_QUERY_REGISTRY_DIRECT,
            L"CSDVersion",
            &BaseSrvCSDString,
            REG_NONE, NULL, 0
        },

        {0}
    };

    /* Initialize the memory */
    BaseSrvHeap = RtlGetProcessHeap();                  // Initialize our own heap.
    BaseSrvSharedHeap = LoadedServerDll->SharedSection; // Get the CSR shared heap.

    /* Get the session ID */
    SessionId = NtCurrentPeb()->SessionId;

    /* Get the Windows directory */
    RtlInitEmptyUnicodeString(&SystemRootString, Buffer, sizeof(Buffer));
    Status = RtlExpandEnvironmentStrings_U(NULL,
                                           &UnexpandedSystemRootString,
                                           &SystemRootString,
                                           NULL);
    ASSERT(NT_SUCCESS(Status));

    /* Create the base directory */
    Buffer[SystemRootString.Length / sizeof(WCHAR)] = UNICODE_NULL;
    Success = RtlCreateUnicodeString(&BaseSrvWindowsDirectory,
                                     SystemRootString.Buffer);
    ASSERT(Success);

    /* Create the system directory */
    wcscat(SystemRootString.Buffer, L"\\System32");
    Success = RtlCreateUnicodeString(&BaseSrvWindowsSystemDirectory,
                                     SystemRootString.Buffer);
    ASSERT(Success);

    /* Create the kernel32 path */
    wcscat(SystemRootString.Buffer, L"\\kernel32.dll");
    Success = RtlCreateUnicodeString(&BaseSrvKernel32DllPath,
                                     SystemRootString.Buffer);
    ASSERT(Success);

    if (SessionId != 0)
    {
        _swprintf(BnoBuffer, L"\\Sessions\\%lu\\BaseNamedObjects", SessionId);
    }
    else
    {
        wcscpy(BnoBuffer, L"\\BaseNamedObjects");
    }
    RtlInitUnicodeString(&BnoString, BnoBuffer);

    /* Allocate the server data */
    BaseStaticServerData = RtlAllocateHeap(BaseSrvSharedHeap,
                                           HEAP_ZERO_MEMORY,
                                           sizeof(BASE_STATIC_SERVER_DATA));
    ASSERT(BaseStaticServerData != NULL);

    /* Process timezone information */
    BaseStaticServerData->TermsrvClientTimeZoneId = TIME_ZONE_ID_INVALID;
    BaseStaticServerData->TermsrvClientTimeZoneChangeNum = 0;
    Status = NtQuerySystemInformation(SystemTimeOfDayInformation,
                                      &BaseStaticServerData->TimeOfDay,
                                      sizeof(BaseStaticServerData->TimeOfDay),
                                      NULL);
    ASSERT(NT_SUCCESS(Status));

    /* Make a shared heap copy of the Windows directory */
    BaseStaticServerData->WindowsDirectory = BaseSrvWindowsDirectory;
    HeapBuffer = RtlAllocateHeap(BaseSrvSharedHeap,
                                 0,
                                 BaseSrvWindowsDirectory.MaximumLength);
    ASSERT(HeapBuffer);
    RtlCopyMemory(HeapBuffer,
                  BaseStaticServerData->WindowsDirectory.Buffer,
                  BaseSrvWindowsDirectory.MaximumLength);
    BaseStaticServerData->WindowsDirectory.Buffer = HeapBuffer;

    /* Make a shared heap copy of the System directory */
    BaseStaticServerData->WindowsSystemDirectory = BaseSrvWindowsSystemDirectory;
    HeapBuffer = RtlAllocateHeap(BaseSrvSharedHeap,
                                 0,
                                 BaseSrvWindowsSystemDirectory.MaximumLength);
    ASSERT(HeapBuffer);
    RtlCopyMemory(HeapBuffer,
                  BaseStaticServerData->WindowsSystemDirectory.Buffer,
                  BaseSrvWindowsSystemDirectory.MaximumLength);
    BaseStaticServerData->WindowsSystemDirectory.Buffer = HeapBuffer;

    /* This string is not used */
    RtlInitEmptyUnicodeString(&BaseStaticServerData->WindowsSys32x86Directory,
                              NULL,
                              0);

    /* Make a shared heap copy of the BNO directory */
    BaseStaticServerData->NamedObjectDirectory = BnoString;
    BaseStaticServerData->NamedObjectDirectory.MaximumLength = BnoString.Length +
                                                               sizeof(UNICODE_NULL);
    HeapBuffer = RtlAllocateHeap(BaseSrvSharedHeap,
                                 0,
                                 BaseStaticServerData->NamedObjectDirectory.MaximumLength);
    ASSERT(HeapBuffer);
    RtlCopyMemory(HeapBuffer,
                  BaseStaticServerData->NamedObjectDirectory.Buffer,
                  BaseStaticServerData->NamedObjectDirectory.MaximumLength);
    BaseStaticServerData->NamedObjectDirectory.Buffer = HeapBuffer;

    /*
     * Confirmed that in Windows, CSDNumber and RCNumber are actually Length
     * and MaximumLength of the CSD String, since the same UNICODE_STRING is
     * being queried twice, the first time as a ULONG!
     *
     * Somehow, in Windows this doesn't cause a buffer overflow, but it might
     * in ReactOS, so this code is disabled until someone figures out WTF.
     */
    BaseStaticServerData->CSDNumber = 0;
    BaseStaticServerData->RCNumber = 0;

    /* Initialize the CSD string and query its value from the registry */
    RtlInitEmptyUnicodeString(&BaseSrvCSDString, Buffer, sizeof(Buffer));
    Status = RtlQueryRegistryValues(RTL_REGISTRY_WINDOWS_NT,
                                    L"",
                                    BaseServerRegistryConfigurationTable,
                                    NULL,
                                    NULL);
    if (NT_SUCCESS(Status))
    {
        /* Copy into the shared buffer */
        wcsncpy(BaseStaticServerData->CSDVersion,
                BaseSrvCSDString.Buffer,
                BaseSrvCSDString.Length / sizeof(WCHAR));
    }
    else
    {
        /* Indicate nothing is there */
        BaseSrvCSDString.Length = 0;
    }
    /* NULL-terminate */
    BaseStaticServerData->CSDVersion[BaseSrvCSDString.Length / sizeof(WCHAR)] = UNICODE_NULL;

    /* Cache the system information */
    Status = NtQuerySystemInformation(SystemBasicInformation,
                                      &BaseStaticServerData->SysInfo,
                                      sizeof(BaseStaticServerData->SysInfo),
                                      NULL);
    ASSERT(NT_SUCCESS(Status));

    /* Setup the ini file mappings */
    Status = BaseSrvInitializeIniFileMappings(BaseStaticServerData);
    ASSERT(NT_SUCCESS(Status));

    /* FIXME: Should query the registry for these */
    BaseStaticServerData->DefaultSeparateVDM = FALSE;
    BaseStaticServerData->IsWowTaskReady = FALSE;

    /* Allocate a security descriptor and create it */
    BnoSd = RtlAllocateHeap(BaseSrvHeap, 0, 1024);
    ASSERT(BnoSd);
    Status = RtlCreateSecurityDescriptor(BnoSd, SECURITY_DESCRIPTOR_REVISION);
    ASSERT(NT_SUCCESS(Status));

    /* Create the BNO and \Restricted DACLs */
    Status = CreateBaseAcls(&BnoDacl, &BnoRestrictedDacl);
    ASSERT(NT_SUCCESS(Status));

    /*
     * Sessions other than 0: the DACLs measured on Windows (see
     * BaseBuildSessionNamespaceDacls) replace the generic BNO DACL, and the
     * links and the AppContainer directory get their own security descriptors.
     */
    if (SessionId != 0)
    {
        PACL DirectoryDacl;

        Status = BaseBuildSessionNamespaceDacls(&DirectoryDacl, &LinkDacl, &AppContainerDacl);
        ASSERT(NT_SUCCESS(Status));
        if (NT_SUCCESS(Status))
        {
            BnoDacl = DirectoryDacl;
            LinkSd = RtlAllocateHeap(BaseSrvHeap, 0, 2 * 1024);
            AppContainerSd = RtlAllocateHeap(BaseSrvHeap, 0, 2 * 1024);
            ASSERT(LinkSd && AppContainerSd);
            Status = RtlCreateSecurityDescriptor(LinkSd, SECURITY_DESCRIPTOR_REVISION);
            ASSERT(NT_SUCCESS(Status));
            Status = RtlSetDaclSecurityDescriptor(LinkSd, TRUE, LinkDacl, FALSE);
            ASSERT(NT_SUCCESS(Status));
            Status = RtlCreateSecurityDescriptor(AppContainerSd, SECURITY_DESCRIPTOR_REVISION);
            ASSERT(NT_SUCCESS(Status));
            Status = RtlSetDaclSecurityDescriptor(AppContainerSd, TRUE, AppContainerDacl, FALSE);
            ASSERT(NT_SUCCESS(Status));
        }
        else
        {
            DPRINT1("BASESRV: cannot build the namespace DACLs of session %lu, Status=%lx\n",
                    SessionId, Status);
        }
    }

    /* Set the BNO DACL as active for now */
    Status = RtlSetDaclSecurityDescriptor(BnoSd, TRUE, BnoDacl, FALSE);
    ASSERT(NT_SUCCESS(Status));

    /* Create the BNO directory */
    InitializeObjectAttributes(&ObjectAttributes,
                               &BnoString,
                               OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
                               NULL,
                               BnoSd);
    Status = NtCreateDirectoryObject(&BaseSrvNamedObjectDirectory,
                                     DIRECTORY_ALL_ACCESS,
                                     &ObjectAttributes);
    ASSERT(NT_SUCCESS(Status));

    /*
     * NT6+ code (and the object-manager conformance tests) address the
     * session-local namespace of any session, including session 0, as
     * \Sessions\<id>\BaseNamedObjects. ReactOS runs the interactive desktop
     * in session 0, whose default (unqualified) namespace stays \BaseNamedObjects,
     * so also provide the \Sessions\0\BaseNamedObjects directory itself.
     */
    if (SessionId == 0)
    {
        HANDLE Session0BnoDirectory;

        RtlInitUnicodeString(&DirectoryName, L"\\Sessions\\0\\BaseNamedObjects");
        InitializeObjectAttributes(&ObjectAttributes,
                                   &DirectoryName,
                                   OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
                                   NULL,
                                   BnoSd);
        Status = NtCreateDirectoryObject(&Session0BnoDirectory,
                                         DIRECTORY_ALL_ACCESS,
                                         &ObjectAttributes);
        if (NT_SUCCESS(Status)) NtClose(Session0BnoDirectory);
    }

    /*
     * Tag the directory with this process's session (the object manager keeps
     * the caller's session id in it): creating a section or a symbolic link in
     * a directory of another session then needs SeCreateGlobalPrivilege. Every
     * session's directory is tagged, so that a process of session 1 cannot
     * plant a section in session 0's \BaseNamedObjects, nor in another
     * session's directory, as on Windows.
     */
    Status = NtSetInformationObject(BaseSrvNamedObjectDirectory,
                                    ObjectSessionInformation,
                                    NULL,
                                    0);
    ASSERT(NT_SUCCESS(Status));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("BASESRV: cannot tag the named object directory of session %lu, Status=%lx\n",
                SessionId, Status);
    }

    /* Check if LUID device maps are enabled */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessLUIDDeviceMapsEnabled,
                                       &LuidEnabled,
                                       sizeof(LuidEnabled),
                                       NULL);
    ASSERT(NT_SUCCESS(Status));
    BaseStaticServerData->LUIDDeviceMapsEnabled = (BOOLEAN)LuidEnabled;

    /* Initialize Global */
    if (!BaseStaticServerData->LUIDDeviceMapsEnabled ||
        NT_SUCCESS(RtlInitializeCriticalSectionAndSpinCount(&BaseSrvDDDBSMCritSec, 0x80000000)))
    {
        /* Make Global point back to BNO */
        RtlInitUnicodeString(&DirectoryName, L"Global");
        RtlInitUnicodeString(&SymlinkName, L"\\BaseNamedObjects");
        InitializeObjectAttributes(&ObjectAttributes,
                                   &DirectoryName,
                                   OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
                                   BaseSrvNamedObjectDirectory,
                                   LinkSd ? LinkSd : BnoSd);
        Status = NtCreateSymbolicLinkObject(&SymHandle,
                                            SYMBOLIC_LINK_ALL_ACCESS,
                                            &ObjectAttributes,
                                            &SymlinkName);
        if ((NT_SUCCESS(Status)) && SessionId == 0) NtClose(SymHandle);

        /* Make local point back to \Sessions\x\BNO */
        RtlInitUnicodeString(&DirectoryName, L"Local");
        InitializeObjectAttributes(&ObjectAttributes,
                                   &DirectoryName,
                                   OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
                                   BaseSrvNamedObjectDirectory,
                                   LinkSd ? LinkSd : BnoSd);
        Status = NtCreateSymbolicLinkObject(&SymHandle,
                                            SYMBOLIC_LINK_ALL_ACCESS,
                                            &ObjectAttributes,
                                            &BnoString);
        if ((NT_SUCCESS(Status)) && SessionId == 0) NtClose(SymHandle);

        /* Make Session point back to BNOLINKS */
        RtlInitUnicodeString(&DirectoryName, L"Session");
        RtlInitUnicodeString(&SymlinkName, L"\\Sessions\\BNOLINKS");
        InitializeObjectAttributes(&ObjectAttributes,
                                   &DirectoryName,
                                   OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
                                   BaseSrvNamedObjectDirectory,
                                   LinkSd ? LinkSd : BnoSd);
        Status = NtCreateSymbolicLinkObject(&SymHandle,
                                            SYMBOLIC_LINK_ALL_ACCESS,
                                            &ObjectAttributes,
                                            &SymlinkName);
        if ((NT_SUCCESS(Status)) && SessionId == 0) NtClose(SymHandle);

        /*
         * Sessions other than 0 (NitroSessions): AppContainerNamedObjects
         * points to the session's directory for AppContainer packages,
         * \Sessions\<id>\AppContainerNamedObjects, which is created here.
         * Session 0 keeps its set of objects until the phase that makes it
         * a Windows-style session.
         */
        if (SessionId != 0)
        {
            WCHAR AcBuffer[100];
            UNICODE_STRING AcName;
            HANDLE AcDirectory;

            _swprintf(AcBuffer, L"\\Sessions\\%lu\\AppContainerNamedObjects", SessionId);
            RtlInitUnicodeString(&AcName, AcBuffer);
            InitializeObjectAttributes(&ObjectAttributes,
                                       &AcName,
                                       OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
                                       NULL,
                                       AppContainerSd);
            Status = NtCreateDirectoryObject(&AcDirectory,
                                             DIRECTORY_ALL_ACCESS,
                                             &ObjectAttributes);
            ASSERT(NT_SUCCESS(Status));
            if (NT_SUCCESS(Status))
            {
                NtClose(AcDirectory);

                RtlInitUnicodeString(&DirectoryName, L"AppContainerNamedObjects");
                InitializeObjectAttributes(&ObjectAttributes,
                                           &DirectoryName,
                                           OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
                                           BaseSrvNamedObjectDirectory,
                                           LinkSd);
                Status = NtCreateSymbolicLinkObject(&SymHandle,
                                                    SYMBOLIC_LINK_ALL_ACCESS,
                                                    &ObjectAttributes,
                                                    &AcName);
                ASSERT(NT_SUCCESS(Status));
                if (NT_SUCCESS(Status)) NtClose(SymHandle);
            }
            else
            {
                DPRINT1("BASESRV: cannot create %wZ, Status=%lx\n", &AcName, Status);
            }
        }

        /* Create the BNO\Restricted directory and set the restricted DACL */
        RtlInitUnicodeString(&DirectoryName, L"Restricted");
        Status = RtlSetDaclSecurityDescriptor(BnoSd, TRUE, BnoRestrictedDacl, FALSE);
        ASSERT(NT_SUCCESS(Status));
        InitializeObjectAttributes(&ObjectAttributes,
                                   &DirectoryName,
                                   OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
                                   BaseSrvNamedObjectDirectory,
                                   BnoSd);
        Status = NtCreateDirectoryObject(&BaseSrvRestrictedObjectDirectory,
                                         DIRECTORY_ALL_ACCESS,
                                         &ObjectAttributes);
        ASSERT(NT_SUCCESS(Status));
    }
    else
    {
        /* That should never happen */
        ASSERT(FALSE);
    }

    /* Initialize NLS */
    BaseSrvNLSInit(BaseStaticServerData);

    /* Finally, set the pointer */
    LoadedServerDll->SharedSection = BaseStaticServerData;
}

NTSTATUS
NTAPI
BaseClientConnectRoutine(IN PCSR_PROCESS CsrProcess,
                         IN OUT PVOID  ConnectionInfo,
                         IN OUT PULONG ConnectionInfoLength)
{
    PBASESRV_API_CONNECTINFO ConnectInfo = (PBASESRV_API_CONNECTINFO)ConnectionInfo;

    if ( ConnectionInfo       == NULL ||
         ConnectionInfoLength == NULL ||
        *ConnectionInfoLength != sizeof(*ConnectInfo) )
    {
        DPRINT1("BASESRV: Connection failed - ConnectionInfo = 0x%p ; ConnectionInfoLength = 0x%p (%lu), expected %lu\n",
                ConnectionInfo,
                ConnectionInfoLength,
                ConnectionInfoLength ? *ConnectionInfoLength : (ULONG)-1,
                sizeof(*ConnectInfo));

        return STATUS_INVALID_PARAMETER;
    }

    /* Do the NLS connection */
    return BaseSrvNlsConnect(CsrProcess, ConnectionInfo, ConnectionInfoLength);
}

VOID
NTAPI
BaseClientDisconnectRoutine(IN PCSR_PROCESS CsrProcess)
{
    /* Cleanup VDM resources */
    BaseSrvCleanupVDMResources(CsrProcess);
}

CSR_SERVER_DLL_INIT(ServerDllInitialization)
{
    /* Setup the DLL Object */
    LoadedServerDll->ApiBase = BASESRV_FIRST_API_NUMBER;
    LoadedServerDll->HighestApiSupported = BasepMaxApiNumber;
    LoadedServerDll->DispatchTable = BaseServerApiDispatchTable;
    LoadedServerDll->ValidTable = BaseServerApiServerValidTable;
#ifdef CSR_DBG
    LoadedServerDll->NameTable = BaseServerApiNameTable;
#endif
    LoadedServerDll->SizeOfProcessData = 0;
    LoadedServerDll->ConnectCallback = BaseClientConnectRoutine;
    LoadedServerDll->DisconnectCallback = BaseClientDisconnectRoutine;
    LoadedServerDll->ShutdownProcessCallback = NULL;

    BaseSrvDllInstance = LoadedServerDll->ServerHandle;

    BaseInitializeStaticServerData(LoadedServerDll);

    /* Initialize DOS devices management */
    BaseInitDefineDosDevice();

    /* Initialize VDM support */
    BaseInitializeVDM();

    /* The shim cache the kernel loaded is only good for the shim database it was built with */
    BaseSrvValidateAppcompatCache();

    /* All done */
    return STATUS_SUCCESS;
}

BOOL
NTAPI
DllMain(IN HINSTANCE hInstanceDll,
        IN DWORD dwReason,
        IN LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hInstanceDll);
    UNREFERENCED_PARAMETER(dwReason);
    UNREFERENCED_PARAMETER(lpReserved);

    if (DLL_PROCESS_DETACH == dwReason)
    {
        BaseCleanupDefineDosDevice();
    }

    return TRUE;
}

/* EOF */
