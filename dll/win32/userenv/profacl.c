/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Security descriptors of the profile directories
 *
 * The DACLs are those of Windows (taken from a read-only icacls of the profile directories
 * of a Windows 10 machine): the profiles directory and the Default profile grant read access
 * to everyone, a user profile grants SYSTEM, Administrators and its user and nobody else, and
 * Public lets the interactive, service and batch logons modify. All of them are protected,
 * so nothing is inherited from the root of the volume (Authenticated Users: Modify there).
 */

#include "precomp.h"

#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>
#include <winioctl.h>
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>

#define NDEBUG
#include <debug.h>

#ifndef SE_TAKE_OWNERSHIP_PRIVILEGE
#define SE_TAKE_OWNERSHIP_PRIVILEGE 9L
#endif

/*
 * The DACLs are built entry by entry, not from an SDDL string: the string parser of advapi32 mis-reads a SID
 * written as S-1-5-x in every entry but the last (it gets the sub-authorities of the text behind it).
 */
typedef struct _PROFILE_ACE
{
    WELL_KNOWN_SID_TYPE SidType;    /* WinNullSid: the SID of the user, or pszSid */
    DWORD Mask;
    BYTE Flags;
    PCWSTR pszSid;                  /* a SID with no well-known type of the SDK, in the S-1-... form */
} PROFILE_ACE;

#define OI_CI (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
#define OI_CI_IO (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE)
#define RX_ACCESS 0x001200a9            /* FILE_GENERIC_READ | FILE_GENERIC_EXECUTE */
#define MODIFY_DC 0x001301ff            /* Modify and delete child */
#define USERS_ADD 0x00000116            /* add file, add subdirectory, write EA, write attributes */
#define RX_WD_AD  0x001200af            /* Read and execute, add file, add subdirectory */

/* The profiles directory and the Default profile: SYSTEM and Administrators full, Users and Everyone read */
static const PROFILE_ACE UsersAces[] =
{
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinUsersSid, RX_ACCESS, 0},
    {WinBuiltinUsersSid, GENERIC_READ | GENERIC_EXECUTE, OI_CI_IO},
    {WinWorldSid, RX_ACCESS, 0},
    {WinWorldSid, GENERIC_READ | GENERIC_EXECUTE, OI_CI_IO},
};

/* Administrators, CREATOR OWNER, SYSTEM full; interactive, service and batch logons modify */
static const PROFILE_ACE PublicAces[] =
{
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinCreatorOwnerSid, FILE_ALL_ACCESS, OI_CI_IO},
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
    {WinInteractiveSid, MODIFY_DC, OI_CI_IO},
    {WinInteractiveSid, RX_WD_AD, 0},
    {WinServiceSid, MODIFY_DC, OI_CI_IO},
    {WinServiceSid, RX_WD_AD, 0},
    {WinBatchSid, MODIFY_DC, OI_CI_IO},
    {WinBatchSid, RX_WD_AD, 0},
};

/*
 * ProgramData: SYSTEM and Administrators full; CREATOR OWNER full on what a user creates; Users read, and
 * (for directories, not for the files in them) add files and subdirectories and write attributes
 */
static const PROFILE_ACE ProgramDataAces[] =
{
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinCreatorOwnerSid, FILE_ALL_ACCESS, OI_CI_IO},
    {WinBuiltinUsersSid, RX_ACCESS, OI_CI},
    {WinBuiltinUsersSid, USERS_ADD, CONTAINER_INHERIT_ACE},
};

/*
 * ProgramData\Microsoft (a Windows Server 2022 reference: SYSTEM and Administrators full control, Users and Everyone read
 * and execute, protected): what is below it (the all-users Start Menu with its Startup folder, Templates) inherits that and
 * is not writable by a standard user, while ProgramData's own entry (Users add files and folders) stays out.
 */
static const PROFILE_ACE ProgramDataMicrosoftAces[] =
{
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinUsersSid, RX_ACCESS, OI_CI},
    {WinWorldSid, RX_ACCESS, OI_CI},
};

/* Public\Desktop (the same reference): Administrators and SYSTEM full control, the interactive users read and execute, protected */
static const PROFILE_ACE PublicDesktopAces[] =
{
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinInteractiveSid, RX_ACCESS, OI_CI},
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
};

/*
 * The folder that holds the recycle bins of a volume ($Recycle.Bin on the Windows Server 2022 reference, RECYCLER here, the
 * name the shell uses): Administrators and SYSTEM full control, Users read and add folders (their own bin), not files and
 * not the removal of what others made; the label Low, inherit-only, for what is made in it (SecureRecycleBinRoot).
 */
#define USERS_ADD_FOLDER 0x001201ad     /* read, add subdirectory, write attributes */
static const PROFILE_ACE RecycleRootAces[] =
{
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, 0},
    {WinBuiltinAdministratorsSid, GENERIC_ALL, OI_CI_IO},
    {WinLocalSystemSid, FILE_ALL_ACCESS, 0},
    {WinLocalSystemSid, GENERIC_ALL, OI_CI_IO},
    {WinBuiltinUsersSid, USERS_ADD_FOLDER, 0},
};

#define SID_ALL_APP_PACKAGES            L"S-1-15-2-1"
#define SID_ALL_RESTRICTED_APP_PACKAGES L"S-1-15-2-2"
#define MODIFY_MASK 0x001301bf          /* Modify */
#define TEMP_USERS  0x00100026          /* synchronize, add file, add subdirectory, traverse */

/*
 * Windows, Program Files and Program Files (x86), after the icacls of a Windows 10 machine. Those folders are owned and
 * fully controlled by TrustedInstaller there, which does not exist here: SYSTEM and Administrators keep full control
 * (on the folder itself too, where Windows gives them Modify). Users and the application packages only read.
 */
static const PROFILE_ACE SystemAces[] =
{
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinUsersSid, RX_ACCESS, 0},
    {WinBuiltinUsersSid, GENERIC_READ | GENERIC_EXECUTE, OI_CI_IO},
    {WinCreatorOwnerSid, FILE_ALL_ACCESS, OI_CI_IO},
    {WinNullSid, RX_ACCESS, 0, SID_ALL_APP_PACKAGES},
    {WinNullSid, GENERIC_READ | GENERIC_EXECUTE, OI_CI_IO, SID_ALL_APP_PACKAGES},
    {WinNullSid, RX_ACCESS, 0, SID_ALL_RESTRICTED_APP_PACKAGES},
    {WinNullSid, GENERIC_READ | GENERIC_EXECUTE, OI_CI_IO, SID_ALL_RESTRICTED_APP_PACKAGES},
};

/* Windows\Temp: users add files and directories but neither list nor read what others put there */
static const PROFILE_ACE TempAces[] =
{
    {WinBuiltinUsersSid, TEMP_USERS, CONTAINER_INHERIT_ACE},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
    {WinCreatorOwnerSid, FILE_ALL_ACCESS, OI_CI_IO},
};

/* The root of the system volume: Authenticated Users create directories there, not files */
static const PROFILE_ACE RootAces[] =
{
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinUsersSid, RX_ACCESS, OI_CI},
    {WinAuthenticatedUserSid, MODIFY_MASK, OI_CI_IO},
    {WinAuthenticatedUserSid, FILE_ADD_SUBDIRECTORY, 0},
};

/*
 * Windows\System32\config (the registry hives): SYSTEM and Administrators only, no Users (a read-only icacls of a Windows
 * 10 machine). There the folder also has a TrustedInstaller entry, which cannot exist here.
 */
static const PROFILE_ACE ConfigAces[] =
{
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinCreatorOwnerSid, FILE_ALL_ACCESS, OI_CI_IO},
};

/*
 * The boot files in the root of the system partition (freeldr.sys, freeldr.ini, ...): SYSTEM and Administrators
 * full, Users read and execute, protected. They name the kernel, the HAL and the boot options; in the root they
 * inherit Authenticated Users: Modify (the root's entry for what is created in it), so any user could change them.
 */
static const PROFILE_ACE BootFileAces[] =
{
    {WinLocalSystemSid, FILE_ALL_ACCESS, 0},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, 0},
    {WinBuiltinUsersSid, RX_ACCESS, 0},
};

/* A user profile: SYSTEM, Administrators and the user, full and inherited by all */
static const PROFILE_ACE UserAces[] =
{
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinNullSid, FILE_ALL_ACCESS, OI_CI},
};

/* FUNCTIONS ***************************************************************/

/* The SID of an entry, copied to pBuffer (cbBuffer bytes); NULL (last error set) when it cannot be made */
static PSID
GetAceSid(
    _In_ const PROFILE_ACE *pAce,
    _In_opt_ PSID pUserSid,
    _Out_writes_bytes_(cbBuffer) PBYTE pBuffer,
    _In_ DWORD cbBuffer)
{
    DWORD cbSid = cbBuffer;
    PSID pSid;

    if (pAce->pszSid)
    {
        if (!ConvertStringSidToSidW(pAce->pszSid, &pSid))
            return NULL;
        if (GetLengthSid(pSid) > cbBuffer)
        {
            LocalFree(pSid);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return NULL;
        }
        CopySid(cbBuffer, pBuffer, pSid);
        LocalFree(pSid);
        return pBuffer;
    }

    if (pAce->SidType == WinNullSid)
    {
        if (GetLengthSid(pUserSid) > cbBuffer)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return NULL;
        }
        CopySid(cbBuffer, pBuffer, pUserSid);
        return pBuffer;
    }

    if (!CreateWellKnownSid(pAce->SidType, NULL, pBuffer, &cbSid))
        return NULL;
    return pBuffer;
}

/* The protected security descriptor (LocalFree) of a kind of profile directory, its DACL behind it */
static PSECURITY_DESCRIPTOR
BuildProfileDescriptor(
    _In_ PROFILE_DIR_KIND Kind,
    _In_opt_ PSID pUserSid)
{
    const PROFILE_ACE *pAces;
    UINT cAces, i;
    BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD cbSid, cbAcl = sizeof(ACL);
    PSECURITY_DESCRIPTOR pSd;
    PACL pAcl;
    PSID pSid;

    switch (Kind)
    {
        case ProfileDirUsers:
            pAces = UsersAces;
            cAces = ARRAYSIZE(UsersAces);
            break;

        case ProfileDirPublic:
            pAces = PublicAces;
            cAces = ARRAYSIZE(PublicAces);
            break;

        case ProfileDirProgramData:
            pAces = ProgramDataAces;
            cAces = ARRAYSIZE(ProgramDataAces);
            break;

        case ProfileDirProgramDataMicrosoft:
            pAces = ProgramDataMicrosoftAces;
            cAces = ARRAYSIZE(ProgramDataMicrosoftAces);
            break;

        case ProfileDirPublicDesktop:
            pAces = PublicDesktopAces;
            cAces = ARRAYSIZE(PublicDesktopAces);
            break;

        case ProfileDirSystem:
            pAces = SystemAces;
            cAces = ARRAYSIZE(SystemAces);
            break;

        case ProfileDirRecycleRoot:
            pAces = RecycleRootAces;
            cAces = ARRAYSIZE(RecycleRootAces);
            break;

        case ProfileDirTemp:
            pAces = TempAces;
            cAces = ARRAYSIZE(TempAces);
            break;

        case ProfileDirRoot:
            pAces = RootAces;
            cAces = ARRAYSIZE(RootAces);
            break;

        case ProfileDirConfig:
            pAces = ConfigAces;
            cAces = ARRAYSIZE(ConfigAces);
            break;

        case ProfileDirBootFile:
            pAces = BootFileAces;
            cAces = ARRAYSIZE(BootFileAces);
            break;

        case ProfileDirUser:
            if (!pUserSid || !IsValidSid(pUserSid))
            {
                SetLastError(ERROR_INVALID_SID);
                return NULL;
            }
            pAces = UserAces;
            cAces = ARRAYSIZE(UserAces);
            break;

        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            return NULL;
    }

    /* The size of the ACL */
    for (i = 0; i < cAces; i++)
    {
        pSid = GetAceSid(&pAces[i], pUserSid, SidBuffer, sizeof(SidBuffer));
        if (!pSid)
            return NULL;
        cbSid = GetLengthSid(pSid);
        cbAcl += sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + cbSid;
    }
    cbAcl = (cbAcl + 3) & ~3;

    pSd = LocalAlloc(LMEM_FIXED, sizeof(SECURITY_DESCRIPTOR) + cbAcl);
    if (!pSd)
        return NULL;
    pAcl = (PACL)((PBYTE)pSd + sizeof(SECURITY_DESCRIPTOR));

    if (!InitializeSecurityDescriptor(pSd, SECURITY_DESCRIPTOR_REVISION) ||
        !InitializeAcl(pAcl, cbAcl, ACL_REVISION))
        goto fail;

    for (i = 0; i < cAces; i++)
    {
        pSid = GetAceSid(&pAces[i], pUserSid, SidBuffer, sizeof(SidBuffer));
        if (!pSid)
            goto fail;

        if (!AddAccessAllowedAceEx(pAcl, ACL_REVISION, pAces[i].Flags, pAces[i].Mask, pSid))
            goto fail;
    }

    if (!SetSecurityDescriptorDacl(pSd, TRUE, pAcl, FALSE) ||
        !SetSecurityDescriptorControl(pSd,
                                      SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED,
                                      SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED))
        goto fail;

    return pSd;

fail:
    LocalFree(pSd);
    return NULL;
}

BOOL
CreateSecuredProfileDir(
    _In_ PCWSTR pszPath,
    _In_ PROFILE_DIR_KIND Kind,
    _In_opt_ PSID pUserSid)
{
    SECURITY_ATTRIBUTES Sa;
    PSECURITY_DESCRIPTOR pSd;
    DWORD dwError;
    BOOL bResult;

    pSd = BuildProfileDescriptor(Kind, pUserSid);
    if (pSd == NULL)
    {
        /* No directory is better than one open to everybody */
        DPRINT1("No security descriptor for %S (error %lu)\n", pszPath, GetLastError());
        if (GetLastError() == ERROR_SUCCESS)
            SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Sa.nLength = sizeof(Sa);
    Sa.lpSecurityDescriptor = pSd;
    Sa.bInheritHandle = FALSE;

    bResult = CreateDirectoryW(pszPath, &Sa);
    dwError = GetLastError();
    LocalFree(pSd);
    SetLastError(dwError);
    return bResult;
}

/* A DACL that is not protected is one of an older install: it inherits Authenticated Users: Modify from the volume */
static BOOL
HasUnprotectedDacl(
    _In_ PCWSTR pszPath)
{
    PSECURITY_DESCRIPTOR pSd;
    SECURITY_DESCRIPTOR_CONTROL Control;
    DWORD dwSize = 0, dwRevision;
    BOOL bResult = FALSE;

    GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize);
    if (dwSize == 0)
        return FALSE;

    pSd = LocalAlloc(LMEM_FIXED, dwSize);
    if (!pSd)
        return FALSE;

    if (GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, pSd, dwSize, &dwSize) &&
        GetSecurityDescriptorControl(pSd, &Control, &dwRevision))
    {
        bResult = (Control & SE_DACL_PRESENT) && !(Control & SE_DACL_PROTECTED);
    }

    LocalFree(pSd);
    return bResult;
}

/*
 * The root of the volume of an older install gives Authenticated Users Modify on the root itself, so any user can
 * put a file there (C:\\Program.exe, found first by an unquoted service path). Windows lets them add directories only.
 */
static BOOL
RootLetsUsersCreateFiles(
    _In_ PCWSTR pszPath)
{
    PSECURITY_DESCRIPTOR pSd;
    PACL pAcl = NULL;
    BOOL bPresent, bDefaulted, bResult = FALSE;
    DWORD dwSize = 0, i;
    BYTE Auth[SECURITY_MAX_SID_SIZE];
    DWORD cbAuth = sizeof(Auth);

    if (!CreateWellKnownSid(WinAuthenticatedUserSid, NULL, Auth, &cbAuth))
        return FALSE;

    GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize);
    if (dwSize == 0)
        return FALSE;
    pSd = LocalAlloc(LMEM_FIXED, dwSize);
    if (!pSd)
        return FALSE;

    if (GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, pSd, dwSize, &dwSize) &&
        GetSecurityDescriptorDacl(pSd, &bPresent, &pAcl, &bDefaulted) && bPresent && pAcl)
    {
        for (i = 0; i < pAcl->AceCount; i++)
        {
            PACCESS_ALLOWED_ACE pAce;

            if (GetAce(pAcl, i, (PVOID *)&pAce) &&
                pAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                !(pAce->Header.AceFlags & INHERIT_ONLY_ACE) &&
                (pAce->Mask & (FILE_ADD_FILE | GENERIC_WRITE | GENERIC_ALL)) &&
                EqualSid((PSID)&pAce->SidStart, Auth))
            {
                bResult = TRUE;
                break;
            }
        }
    }

    LocalFree(pSd);
    return bResult;
}

/*
 * The older installs have no entry that says "inherited": every object got copies of the ACEs of the volume root
 * (Authenticated Users: Modify among them) as if they had been put there on purpose. An ACE that equals one of the
 * root of that time (same type, SID, access and flags) is such a copy.
 */
static BOOL
IsLegacyAce(
    _In_ PACE_HEADER pAce,
    _In_ PACL pLegacyAcl)
{
    DWORD i;

    if (pAce->AceType != ACCESS_ALLOWED_ACE_TYPE)
        return FALSE;

    for (i = 0; i < pLegacyAcl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE pRoot;

        if (GetAce(pLegacyAcl, i, (PVOID *)&pRoot) &&
            pRoot->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            (pRoot->Header.AceFlags & ~INHERITED_ACE) == (pAce->AceFlags & ~INHERITED_ACE) &&
            pRoot->Mask == ((PACCESS_ALLOWED_ACE)pAce)->Mask &&
            EqualSid((PSID)&pRoot->SidStart, (PSID)&((PACCESS_ALLOWED_ACE)pAce)->SidStart))
            return TRUE;
    }
    return FALSE;
}

/*
 * The repairs below run as SYSTEM over trees that users of an older install can write to. They never name an object
 * below their top folder by path: a directory they have listed could be replaced by a junction before they reach
 * its entries, and a path through it would then name an object elsewhere. Every object is opened relative to the
 * handle of the directory it was listed in, without following a reparse point (FILE_OPEN_REPARSE_POINT), and what
 * the handle shows decides, not the listing: a reparse point is left alone (it is not changed and not walked), a
 * directory is walked through a handle opened relative to its own handle, and a file with more than one name is
 * left alone (its other names can lie outside the tree; the rule of the propagation in ntmarta). Its new DACL is
 * computed from its parent's descriptor read through the parent's handle, and set through its own handle. The top
 * folder itself is opened the same way (OpenWalkTop): a top folder that is a reparse point is not touched.
 */
static GENERIC_MAPPING WalkFileMapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };

#ifndef SEF_DACL_AUTO_INHERIT
#define SEF_DACL_AUTO_INHERIT 0x01
#endif

/* ntdll (not in the user-mode NDK headers; ntmarta declares it the same way) */
NTSYSAPI
NTSTATUS
NTAPI
RtlNewSecurityObjectEx(IN PSECURITY_DESCRIPTOR ParentDescriptor,
                       IN PSECURITY_DESCRIPTOR CreatorDescriptor,
                       OUT PSECURITY_DESCRIPTOR *NewDescriptor,
                       IN LPGUID ObjectType,
                       IN BOOLEAN IsDirectoryObject,
                       IN ULONG AutoInheritFlags,
                       IN HANDLE Token,
                       IN PGENERIC_MAPPING GenericMapping);

#define WALK_MAX_DEPTH 64
#define WALK_BUFFER 0x1000

/* Opens Name (cbName bytes; none: hDirectory itself again) relative to hDirectory, never following a reparse point */
static NTSTATUS
OpenRelative(
    _In_ HANDLE hDirectory,
    _In_opt_ PCWSTR pszName,
    _In_ ULONG cbName,
    _In_ ACCESS_MASK Access,
    _In_ ULONG Options,
    _Out_ PHANDLE phFile)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING Name;
    IO_STATUS_BLOCK Iosb;

    Name.Buffer = (PWSTR)pszName;
    Name.Length = Name.MaximumLength = (USHORT)cbName;
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, hDirectory, NULL);
    return NtOpenFile(phFile, Access | SYNCHRONIZE, &Attributes, &Iosb,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      Options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT);
}

/* The parts Info of the descriptor of a handle (LocalFree), or NULL */
static PSECURITY_DESCRIPTOR
QueryHandleSecurity(
    _In_ HANDLE hObject,
    _In_ SECURITY_INFORMATION Info)
{
    PSECURITY_DESCRIPTOR pSd;
    DWORD dwSize = 0x200, dwNeeded = 0;

    for (;;)
    {
        pSd = LocalAlloc(LMEM_FIXED, dwSize);
        if (!pSd)
            return NULL;
        if (GetKernelObjectSecurity(hObject, Info, pSd, dwSize, &dwNeeded))
            return pSd;
        LocalFree(pSd);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || dwNeeded <= dwSize)
            return NULL;
        dwSize = dwNeeded;
    }
}

/*
 * The top folder of a walk, opened by its path for listing (and for its DACL with bWriteDac): NULL if that is not a
 * directory or is a reparse point (a junction put in its place is not followed)
 */
static HANDLE
OpenWalkTop(
    _In_ PCWSTR pszPath,
    _In_ BOOL bWriteDac)
{
    BY_HANDLE_FILE_INFORMATION Info;
    HANDLE hTop;

    hTop = CreateFileW(pszPath,
                       READ_CONTROL | FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES |
                       (bWriteDac ? WRITE_DAC : 0),
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hTop == INVALID_HANDLE_VALUE)
        return NULL;
    if (!GetFileInformationByHandle(hTop, &Info) ||
        !(Info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (Info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        DPRINT1("%S is not a directory or is a reparse point: left alone\n", pszPath);
        CloseHandle(hTop);
        return NULL;
    }
    return hTop;
}

/*
 * Gives hObject (listed in hParent) the DACL pKept followed by what its parent passes on, as SetNamedSecurityInfo with
 * UNPROTECTED_DACL_SECURITY_INFORMATION computes it, but from the parent's handle (RtlNewSecurityObjectEx, the
 * parent's inheritable entries marked inherited after the kept ones). bAutoInherited: set it as the propagation of
 * ntmarta sets a child's DACL (auto-inherited, DACL_SECURITY_INFORMATION alone) instead
 */
static DWORD
SetInheritingDacl(
    _In_ HANDLE hParent,
    _In_ HANDLE hObject,
    _In_ BOOL bDirectory,
    _In_ PACL pKept,
    _In_ BOOL bAutoInherited)
{
    PSECURITY_DESCRIPTOR pParentSd, pOwnSd, pNewSd = NULL;
    SECURITY_DESCRIPTOR Creator, Set;
    PSID pOwner = NULL, pGroup = NULL;
    PACL pNewAcl = NULL;
    BOOL bDefaulted, bPresent = FALSE;
    NTSTATUS Status;
    DWORD dwError = ERROR_SUCCESS;

    pParentSd = QueryHandleSecurity(hParent, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                             DACL_SECURITY_INFORMATION);
    pOwnSd = QueryHandleSecurity(hObject, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION);
    if (!pParentSd || !pOwnSd)
    {
        dwError = GetLastError() ? GetLastError() : ERROR_ACCESS_DENIED;
        goto done;
    }

    /* Its own owner and group (for CREATOR OWNER and CREATOR GROUP entries), the kept entries as explicit ones */
    GetSecurityDescriptorOwner(pOwnSd, &pOwner, &bDefaulted);
    GetSecurityDescriptorGroup(pOwnSd, &pGroup, &bDefaulted);
    if (!InitializeSecurityDescriptor(&Creator, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorOwner(&Creator, pOwner, FALSE) ||
        !SetSecurityDescriptorGroup(&Creator, pGroup, FALSE) ||
        !SetSecurityDescriptorDacl(&Creator, TRUE, pKept, FALSE))
    {
        dwError = GetLastError();
        goto done;
    }
    Status = RtlNewSecurityObjectEx(pParentSd, &Creator, &pNewSd, NULL, (BOOLEAN)bDirectory, SEF_DACL_AUTO_INHERIT,
                                    NULL, &WalkFileMapping);
    if (!NT_SUCCESS(Status))
    {
        dwError = RtlNtStatusToDosError(Status);
        pNewSd = NULL;
        goto done;
    }
    if (!GetSecurityDescriptorDacl(pNewSd, &bPresent, &pNewAcl, &bDefaulted) || !bPresent || !pNewAcl)
    {
        dwError = ERROR_INVALID_ACL;
        goto done;
    }

    if (!InitializeSecurityDescriptor(&Set, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&Set, TRUE, pNewAcl, FALSE) ||
        (bAutoInherited &&
         !SetSecurityDescriptorControl(&Set, SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED,
                                       SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED)) ||
        !SetKernelObjectSecurity(hObject,
                                 DACL_SECURITY_INFORMATION |
                                 (bAutoInherited ? 0 : UNPROTECTED_DACL_SECURITY_INFORMATION),
                                 &Set))
    {
        dwError = GetLastError();
    }

done:
    if (pNewSd)
        RtlDeleteSecurityObject(&pNewSd);
    if (pOwnSd)
        LocalFree(pOwnSd);
    if (pParentSd)
        LocalFree(pParentSd);
    return dwError;
}

typedef enum _WALK_EVENT
{
    WalkObject,         /* hObject is open (READ_CONTROL, WRITE_DAC); return TRUE to walk a directory's entries */
    WalkNotOpened,      /* the entry could not be opened (dwError) */
    WalkSeveralNames,   /* a file with more than one name: left alone */
    WalkTooDeep,        /* a directory below the depth limit: not walked */
    WalkReparse,        /* a reparse point, hObject is the link itself (READ_CONTROL, WRITE_DAC); never walked */
} WALK_EVENT;

/*
 * pLevel: what the visitor returned for the directory being listed (*ppChildLevel of its own visit; for the top folder
 * the walk's caller passes it); a visitor may return a LocalAlloc'd *ppChildLevel for a directory it asks to be walked,
 * freed by the walk afterwards
 */
typedef BOOL (*PWALK_VISIT)(
    _In_ WALK_EVENT Event,
    _In_ HANDLE hParent,
    _In_opt_ HANDLE hObject,
    _In_ PCWSTR pszPath,        /* for the log only: never opened */
    _In_ BOOL bDirectory,
    _In_ DWORD dwError,
    _Inout_ PVOID pContext,
    _In_opt_ PVOID pLevel,
    _Out_ PVOID *ppChildLevel);

/* The entries of hDirectory (FILE_LIST_DIRECTORY), and below the directories the visitor asks for, top down */
static VOID
WalkByHandle(
    _In_ HANDLE hDirectory,
    _In_ PCWSTR pszDirectory,
    _In_ UINT uDepth,
    _In_ PWALK_VISIT Visit,
    _Inout_ PVOID pContext,
    _In_opt_ PVOID pLevel)
{
    PUCHAR Buffer;
    BOOLEAN bRestart = TRUE;
    SIZE_T cchDir = wcslen(pszDirectory);

    Buffer = LocalAlloc(LMEM_FIXED, WALK_BUFFER);
    if (!Buffer)
        return;

    for (;;)
    {
        PFILE_DIRECTORY_INFORMATION Entry;
        IO_STATUS_BLOCK Iosb;
        ULONG Offset = 0;
        NTSTATUS Status;

        Status = NtQueryDirectoryFile(hDirectory, NULL, NULL, NULL, &Iosb, Buffer, WALK_BUFFER,
                                      FileDirectoryInformation, FALSE, NULL, bRestart);
        bRestart = FALSE;
        if (!NT_SUCCESS(Status))
            break;

        for (;;)
        {
            FILE_BASIC_INFORMATION Basic;
            FILE_STANDARD_INFORMATION Standard;
            HANDLE hObject = NULL, hList = NULL;
            PVOID pChildLevel = NULL;
            PWSTR pszPath;
            SIZE_T cchPath;
            BOOL bWalk;

            Entry = (PFILE_DIRECTORY_INFORMATION)(Buffer + Offset);
            Offset = Entry->NextEntryOffset ? Offset + Entry->NextEntryOffset : 0;

            if (!((Entry->FileNameLength == sizeof(WCHAR) && Entry->FileName[0] == L'.') ||
                  (Entry->FileNameLength == 2 * sizeof(WCHAR) && Entry->FileName[0] == L'.' &&
                   Entry->FileName[1] == L'.')))
            {
                /* The path, for the log */
                cchPath = cchDir + 1 + Entry->FileNameLength / sizeof(WCHAR) + 1;
                pszPath = LocalAlloc(LMEM_FIXED, cchPath * sizeof(WCHAR));
                if (pszPath)
                {
                    StringCchPrintfW(pszPath, cchPath, L"%s\\%.*s", pszDirectory,
                                     (int)(Entry->FileNameLength / sizeof(WCHAR)), Entry->FileName);

                    Status = OpenRelative(hDirectory, Entry->FileName, Entry->FileNameLength,
                                          READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES, 0, &hObject);
                    if (!NT_SUCCESS(Status))
                    {
                        hObject = NULL;
                        Visit(WalkNotOpened, hDirectory, NULL, pszPath, FALSE, RtlNtStatusToDosError(Status), pContext,
                              pLevel, &pChildLevel);
                    }
                    else if (!NT_SUCCESS(NtQueryInformationFile(hObject, &Iosb, &Basic, sizeof(Basic),
                                                                FileBasicInformation)) ||
                             !NT_SUCCESS(NtQueryInformationFile(hObject, &Iosb, &Standard, sizeof(Standard),
                                                                FileStandardInformation)))
                    {
                        Visit(WalkNotOpened, hDirectory, NULL, pszPath, FALSE, ERROR_ACCESS_DENIED, pContext, pLevel,
                              &pChildLevel);
                    }
                    else if (Basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                    {
                        /* The link itself (opened with FILE_OPEN_REPARSE_POINT), never what it points to */
                        Visit(WalkReparse, hDirectory, hObject, pszPath, Standard.Directory, ERROR_SUCCESS, pContext,
                              pLevel, &pChildLevel);
                    }
                    else if (!Standard.Directory && Standard.NumberOfLinks > 1)
                    {
                        Visit(WalkSeveralNames, hDirectory, hObject, pszPath, FALSE, ERROR_SUCCESS, pContext, pLevel,
                              &pChildLevel);
                    }
                    else
                    {
                        bWalk = Visit(WalkObject, hDirectory, hObject, pszPath, Standard.Directory, ERROR_SUCCESS,
                                      pContext, pLevel, &pChildLevel);
                        if (bWalk && Standard.Directory)
                        {
                            if (uDepth + 1 > WALK_MAX_DEPTH)
                            {
                                Visit(WalkTooDeep, hDirectory, hObject, pszPath, TRUE, ERROR_SUCCESS, pContext, pLevel,
                                      &pChildLevel);
                            }
                            /* Listed through this handle and the parent of what is listed: READ_CONTROL for
                               SetInheritingDacl, which reads the parent's descriptor through it */
                            else if (NT_SUCCESS(OpenRelative(hObject, NULL, 0,
                                                             FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL,
                                                             FILE_DIRECTORY_FILE, &hList)))
                            {
                                WalkByHandle(hList, pszPath, uDepth + 1, Visit, pContext, pChildLevel);
                                NtClose(hList);
                            }
                        }
                    }
                    if (pChildLevel)
                        LocalFree(pChildLevel);
                    if (hObject)
                        NtClose(hObject);
                    LocalFree(pszPath);
                }
            }
            if (Offset == 0)
                break;
        }
    }

    LocalFree(Buffer);
}

/*
 * Marks in pDrop[] (one per ACE of pAcl) the ACEs a new object made in a directory whose descriptor was pOldParentSd
 * got from it, as our file systems store them at a create (the inheritable entries of the parent, without
 * INHERITED_ACE: RtlNewSecurityObjectEx without auto-inheritance), when the object still holds every one of them.
 * Returns TRUE when it holds them all (they are its inherited entries), FALSE otherwise (nothing marked). This is the
 * rule by which the propagation of ntmarta takes such entries for inherited ones.
 */
static BOOL
MarkOldInheritedAces(
    _In_opt_ PSECURITY_DESCRIPTOR pOldParentSd,
    _In_ PSECURITY_DESCRIPTOR pOwnSd,
    _In_ BOOL bDirectory,
    _In_ PACL pAcl,
    _Inout_ PBOOL pDrop)
{
    PSECURITY_DESCRIPTOR pNewSd = NULL;
    SECURITY_DESCRIPTOR Creator;
    PACL pParentAcl = NULL, pSet = NULL;
    PSID pOwner = NULL, pGroup = NULL;
    BOOL bPresent = FALSE, bDefaulted, bInheritable = FALSE, bAll = FALSE;
    PACE_HEADER pAce, pSetAce;
    DWORD i, j;

    if (!pOldParentSd ||
        !GetSecurityDescriptorDacl(pOldParentSd, &bPresent, &pParentAcl, &bDefaulted) || !bPresent || !pParentAcl)
    {
        return FALSE;
    }
    for (i = 0; i < pParentAcl->AceCount && !bInheritable; i++)
    {
        if (GetAce(pParentAcl, i, (PVOID *)&pAce) && (pAce->AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)))
            bInheritable = TRUE;
    }
    if (!bInheritable)
        return FALSE;

    GetSecurityDescriptorOwner(pOwnSd, &pOwner, &bDefaulted);
    GetSecurityDescriptorGroup(pOwnSd, &pGroup, &bDefaulted);
    if (!InitializeSecurityDescriptor(&Creator, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorOwner(&Creator, pOwner, FALSE) ||
        !SetSecurityDescriptorGroup(&Creator, pGroup, FALSE) ||
        !NT_SUCCESS(RtlNewSecurityObjectEx(pOldParentSd, &Creator, &pNewSd, NULL, (BOOLEAN)bDirectory, 0, NULL,
                                           &WalkFileMapping)))
    {
        return FALSE;
    }
    if (GetSecurityDescriptorDacl(pNewSd, &bPresent, &pSet, &bDefaulted) && bPresent && pSet && pSet->AceCount != 0)
    {
        /* Every ACE of the set, each matched by one ACE of the object's DACL that is equal to it, byte for byte */
        bAll = TRUE;
        for (i = 0; i < pSet->AceCount && bAll; i++)
        {
            bAll = FALSE;
            if (!GetAce(pSet, i, (PVOID *)&pSetAce))
                break;
            for (j = 0; j < pAcl->AceCount; j++)
            {
                if (!pDrop[j] && GetAce(pAcl, j, (PVOID *)&pAce) && pAce->AceSize == pSetAce->AceSize &&
                    RtlEqualMemory(pAce, pSetAce, pAce->AceSize))
                {
                    pDrop[j] = TRUE;
                    bAll = TRUE;
                    break;
                }
            }
        }
        if (!bAll)
            ZeroMemory(pDrop, pAcl->AceCount * sizeof(BOOL));
    }
    RtlDeleteSecurityObject(&pNewSd);
    return bAll;
}

/*
 * Reset the DACL of everything under a directory to what its parent inherits, top down, each object set once. With
 * pLegacyAcl (the root's DACL of an older install) an object keeps its explicit entries but not its inherited ones (those
 * marked inherited, or else the copies of what its parent's descriptor before the walk passed on, see
 * MarkOldInheritedAces) and not the copies of the root's entries, and one whose DACL is protected (or that has none, or
 * cannot be read) is left alone with what is below it. Without it every object gets nothing but what its parent passes
 * on. A reparse point (a junction into the same profile) is never followed; its own DACL is treated as the propagation
 * of ntmarta treats a link below a directory whose DACL changed. Each directory's descriptor before its set is the
 * level of its entries (*ppChildLevel).
 */
typedef struct _RESET_WALK
{
    PACL pLegacyAcl;
} RESET_WALK, *PRESET_WALK;

static BOOL
ResetVisit(
    _In_ WALK_EVENT Event,
    _In_ HANDLE hParent,
    _In_opt_ HANDLE hObject,
    _In_ PCWSTR pszPath,
    _In_ BOOL bDirectory,
    _In_ DWORD dwError,
    _Inout_ PVOID pContext,
    _In_opt_ PVOID pLevel,
    _Out_ PVOID *ppChildLevel)
{
    PRESET_WALK pWalk = pContext;
    PSECURITY_DESCRIPTOR pSd = NULL;
    SECURITY_DESCRIPTOR_CONTROL Control = 0;
    PACL pOldAcl = NULL, pNewAcl = NULL;
    BOOL bPresent = FALSE, bDefaulted, bWalk = FALSE, bInherited = FALSE;
    PBOOL pDrop = NULL;
    DWORD dwRevision, i;
    ACL EmptyAcl;

    *ppChildLevel = NULL;
    if (Event == WalkNotOpened)
    {
        DPRINT1("Failed to secure %S, error: %lu\n", pszPath, dwError);
        return FALSE;
    }
    if (Event != WalkObject && Event != WalkReparse)
    {
        DPRINT1("Not secured (several names, or too deep): %S\n", pszPath);
        return FALSE;
    }

    /* What it has now (before this set): read for the rules below, and the level of its own entries */
    pSd = QueryHandleSecurity(hObject, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION);
    if (pSd)
    {
        GetSecurityDescriptorControl(pSd, &Control, &dwRevision);
        GetSecurityDescriptorDacl(pSd, &bPresent, &pOldAcl, &bDefaulted);
    }

    if (Event == WalkObject && !pWalk->pLegacyAcl)
    {
        if (InitializeAcl(&EmptyAcl, sizeof(EmptyAcl), ACL_REVISION))
        {
            dwError = SetInheritingDacl(hParent, hObject, bDirectory, &EmptyAcl, FALSE);
            if (dwError != ERROR_SUCCESS)
                DPRINT1("Failed to secure %S, error: %lu\n", pszPath, dwError);
        }
        *ppChildLevel = pSd;
        return TRUE;
    }

    /* Entries put there on purpose stay, a protected DACL and what hangs below it is not ours */
    if (!pSd || (Control & SE_DACL_PROTECTED) || !bPresent || !pOldAcl)
    {
        /* No DACL grants everything to everybody: that is how it was meant */
        goto done;
    }

    pDrop = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (pOldAcl->AceCount + 1) * sizeof(BOOL));
    pNewAcl = LocalAlloc(LMEM_FIXED, pOldAcl->AclSize);
    if (!pDrop || !pNewAcl || !InitializeAcl(pNewAcl, pOldAcl->AclSize, ACL_REVISION))
        goto done;

    /* Its inherited entries: those marked so, or else the copies of what its parent passed on before */
    for (i = 0; i < pOldAcl->AceCount; i++)
    {
        PACE_HEADER pAce;

        if (GetAce(pOldAcl, i, (PVOID *)&pAce) && (pAce->AceFlags & INHERITED_ACE))
            bInherited = TRUE;
    }
    if (!(Control & SE_DACL_AUTO_INHERITED) && !bInherited &&
        !MarkOldInheritedAces(pLevel, pSd, bDirectory, pOldAcl, pDrop) && Event == WalkReparse)
    {
        /* A link with entries of its own only: left alone, as the propagation leaves it */
        goto done;
    }

    for (i = 0; i < pOldAcl->AceCount; i++)
    {
        PACE_HEADER pAce;

        if (!GetAce(pOldAcl, i, (PVOID *)&pAce))
            goto done;
        if (pDrop[i] || (pAce->AceFlags & INHERITED_ACE) ||
            (Event == WalkObject && IsLegacyAce(pAce, pWalk->pLegacyAcl)))
        {
            continue;
        }
        if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pAce, pAce->AceSize))
            goto done;
    }

    dwError = SetInheritingDacl(hParent, hObject, bDirectory, pNewAcl, Event == WalkReparse);
    if (dwError != ERROR_SUCCESS)
        DPRINT1("Failed to secure %S, error: %lu\n", pszPath, dwError);
    if (Event == WalkObject)
    {
        bWalk = TRUE;
        *ppChildLevel = pSd;
        pSd = NULL;
    }

done:
    if (pDrop)
        LocalFree(pDrop);
    if (pNewAcl)
        LocalFree(pNewAcl);
    if (pSd)
        LocalFree(pSd);
    return bWalk;
}

/* The security descriptor (LocalFree) of the volume root if it still is the one of the older installs; its DACL in *ppAcl */
static PSECURITY_DESCRIPTOR
GetLegacyRootDacl(
    _Out_ PACL *ppAcl)
{
    WCHAR szWindows[MAX_PATH], szRoot[4];
    PSECURITY_DESCRIPTOR pSd;
    BOOL bPresent, bDefaulted;
    DWORD dwSize = 0;

    *ppAcl = NULL;
    if (!GetWindowsDirectoryW(szWindows, ARRAYSIZE(szWindows)) || szWindows[1] != L':')
        return NULL;
    szRoot[0] = szWindows[0];
    szRoot[1] = L':';
    szRoot[2] = L'\\';
    szRoot[3] = UNICODE_NULL;

    if (!RootLetsUsersCreateFiles(szRoot))
        return NULL;

    GetFileSecurityW(szRoot, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize);
    if (dwSize == 0)
        return NULL;
    pSd = LocalAlloc(LMEM_FIXED, dwSize);
    if (!pSd)
        return NULL;
    if (!GetFileSecurityW(szRoot, DACL_SECURITY_INFORMATION, pSd, dwSize, &dwSize) ||
        !GetSecurityDescriptorDacl(pSd, &bPresent, ppAcl, &bDefaulted) || !bPresent || !*ppAcl)
    {
        *ppAcl = NULL;
        LocalFree(pSd);
        return NULL;
    }
    return pSd;
}

/*
 * Give an existing directory the DACL of Windows, if it still has the one of the installs that
 * were made before (not protected), and with bRecurse everything in it the DACL that follows from
 * that. Not for a directory whose registry hive is loaded, and no recursion over the profiles
 * directory, whose profiles have their own.
 */
VOID
SecureExistingProfileDirectory(
    _In_ PCWSTR pszPath,
    _In_ PROFILE_DIR_KIND Kind,
    _In_opt_ PSID pUserSid,
    _In_ BOOL bRecurse)
{
    PSECURITY_DESCRIPTOR pSd, pLegacySd = NULL;
    PACL pAcl = NULL, pLegacyAcl = NULL;
    BOOL bPresent, bDefaulted;
    DWORD dwError;
    HANDLE hTop;
    RESET_WALK Walk;
    PSECURITY_DESCRIPTOR pTopOldSd = NULL;
    BOOL bWalk;
    BOOL bShared = (Kind == ProfileDirProgramData || Kind == ProfileDirSystem || Kind == ProfileDirTemp);

    if (GetFileAttributesW(pszPath) == INVALID_FILE_ATTRIBUTES)
        return;

    if (Kind == ProfileDirRoot)
    {
        if (!RootLetsUsersCreateFiles(pszPath))
            return;
    }
    else if (bShared)
    {
        /*
         * As long as the root of the volume is the old one, the work is not done: a pass that was cut short by a
         * shutdown has left the folder protected and what is in it not. Without it, only the folder itself.
         */
        pLegacySd = GetLegacyRootDacl(&pLegacyAcl);
        if (!pLegacySd && !HasUnprotectedDacl(pszPath))
            return;
    }
    else if (!HasUnprotectedDacl(pszPath))
    {
        return;
    }

    pSd = BuildProfileDescriptor(Kind, pUserSid);
    if (!pSd)
    {
        if (pLegacySd)
            LocalFree(pLegacySd);
        return;
    }

    /* The folder itself through a handle that is not a link (OpenWalkTop), and what is below it through that handle */
    hTop = OpenWalkTop(pszPath, TRUE);
    if (hTop && GetSecurityDescriptorDacl(pSd, &bPresent, &pAcl, &bDefaulted) && bPresent && pAcl)
    {
        bWalk = bRecurse && Kind != ProfileDirRoot && (!bShared || pLegacyAcl);
        if (bWalk)
        {
            /*
             * The walk below gives every object its DACL, once: the folder's own set does not propagate (the
             * propagation of ntmarta would set the whole tree first, and the walk then every object again)
             */
            SECURITY_DESCRIPTOR Set;

            /* What the folder passed on before: the walk recognises its copies below it as inherited entries */
            pTopOldSd = QueryHandleSecurity(hTop, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                                  DACL_SECURITY_INFORMATION);
            dwError = ERROR_SUCCESS;
            if (!InitializeSecurityDescriptor(&Set, SECURITY_DESCRIPTOR_REVISION) ||
                !SetSecurityDescriptorDacl(&Set, TRUE, pAcl, FALSE) ||
                !SetKernelObjectSecurity(hTop, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &Set))
            {
                dwError = GetLastError();
            }
        }
        else
        {
            /* Nothing walks below it: the propagation gives what is below the folder its inheritance */
            dwError = SetSecurityInfo(hTop,
                                      SE_FILE_OBJECT,
                                      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                      NULL, NULL, pAcl, NULL);
        }
        if (dwError != ERROR_SUCCESS)
        {
            DPRINT1("Failed to secure %S, error: %lu\n", pszPath, dwError);
        }
        else if (bWalk)
        {
            Walk.pLegacyAcl = pLegacyAcl;
            WalkByHandle(hTop, pszPath, 0, ResetVisit, &Walk, pTopOldSd);
        }
    }
    if (pTopOldSd)
        LocalFree(pTopOldSd);
    if (hTop)
        CloseHandle(hTop);

    LocalFree(pSd);
    if (pLegacySd)
        LocalFree(pLegacySd);
}

/*
 * C:\Windows is a junction to the system directory when that is somewhere else (setup makes it). The junction object has a
 * DACL of its own, which an older install left at what the volume root gave it (Authenticated Users: Modify): any user could
 * delete it and put another directory in its place. It gets the DACL of the Windows directory. Only the object is opened, never
 * what it points to (FILE_FLAG_OPEN_REPARSE_POINT, and the security is set through that handle), and nothing happens for
 * a plain directory (another Windows on the volume) or for one that is protected already.
 */
static BOOL
ReadPathValue(
    _In_ PCWSTR pszKey,
    _In_ PCWSTR pszValue,
    _Out_writes_(cchPath) PWSTR pszPath,
    _In_ DWORD cchPath);

typedef enum _JUNCTION_RESULT
{
    JunctionNotThere,       /* no such object, or it cannot be opened */
    JunctionNotJunction,    /* a plain directory or file, or a reparse point of another kind or target: left alone */
    JunctionProtected,      /* its DACL is protected already: nothing to do */
    JunctionForeignOwner,   /* owned by neither SYSTEM nor Administrators (not what setup made): left alone */
    JunctionSecured,        /* it got the DACL */
    JunctionFailed          /* setting the DACL failed */
} JUNCTION_RESULT;

/* The DACL of a template, after a deny of FILE_LIST_DIRECTORY to Everyone when bDenyListing (a legacy junction) */
static PACL
BuildJunctionDacl(
    _In_ PROFILE_DIR_KIND Kind,
    _In_ BOOL bDenyListing)
{
    PSECURITY_DESCRIPTOR pSd;
    PACL pTemplate = NULL, pAcl = NULL;
    BYTE WorldSid[SECURITY_MAX_SID_SIZE];
    DWORD cbSid = sizeof(WorldSid), dwSize, i;
    BOOL bPresent, bDefaulted;
    PACE_HEADER pAce;

    pSd = BuildProfileDescriptor(Kind, NULL);
    if (!pSd)
        return NULL;
    if (!GetSecurityDescriptorDacl(pSd, &bPresent, &pTemplate, &bDefaulted) || !bPresent || !pTemplate ||
        !CreateWellKnownSid(WinWorldSid, NULL, WorldSid, &cbSid))
    {
        goto done;
    }

    dwSize = pTemplate->AclSize + sizeof(ACCESS_DENIED_ACE) - sizeof(DWORD) + GetLengthSid((PSID)WorldSid);
    pAcl = LocalAlloc(LMEM_FIXED, dwSize);
    if (!pAcl || !InitializeAcl(pAcl, dwSize, ACL_REVISION) ||
        (bDenyListing && !AddAccessDeniedAce(pAcl, ACL_REVISION, FILE_LIST_DIRECTORY, (PSID)WorldSid)))
    {
        goto fail;
    }
    for (i = 0; i < pTemplate->AceCount; i++)
    {
        if (!GetAce(pTemplate, i, (PVOID *)&pAce) || !AddAce(pAcl, ACL_REVISION, MAXDWORD, pAce, pAce->AceSize))
            goto fail;
    }
    goto done;

fail:
    if (pAcl)
        LocalFree(pAcl);
    pAcl = NULL;
done:
    LocalFree(pSd);
    return pAcl;
}

/* The substitute name of a mount point (a junction) is \??\pszTarget */
static BOOL
JunctionPointsTo(
    _In_ HANDLE hLink,
    _In_ PCWSTR pszTarget)
{
    struct
    {
        ULONG ReparseTag;
        USHORT ReparseDataLength;
        USHORT Reserved;
        USHORT SubstituteNameOffset;
        USHORT SubstituteNameLength;
        USHORT PrintNameOffset;
        USHORT PrintNameLength;
        WCHAR PathBuffer[MAX_PATH + 8 + MAX_PATH];
    } Data;
    WCHAR szName[MAX_PATH + 8];
    DWORD dwLength;
    USHORT cch;

    if (!DeviceIoControl(hLink, FSCTL_GET_REPARSE_POINT, NULL, 0, &Data, sizeof(Data), &dwLength, NULL) ||
        Data.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT ||
        (ULONG)Data.SubstituteNameOffset + Data.SubstituteNameLength > sizeof(Data.PathBuffer))
    {
        return FALSE;
    }
    cch = Data.SubstituteNameLength / sizeof(WCHAR);
    if (cch < 4 || cch >= ARRAYSIZE(szName))
        return FALSE;
    CopyMemory(szName, &Data.PathBuffer[Data.SubstituteNameOffset / sizeof(WCHAR)], cch * sizeof(WCHAR));
    szName[cch] = UNICODE_NULL;
    /* "C:\Users" and "C:\Users\" are the same directory */
    if (cch > 7 && szName[cch - 1] == L'\\')
        szName[cch - 1] = UNICODE_NULL;
    return !wcsncmp(szName, L"\\??\\", 4) && !_wcsicmp(szName + 4, pszTarget);
}

/*
 * A junction object gets the DACL of the directory it points to (the template of that directory), protected. Only the
 * object is opened, never what it points to (FILE_FLAG_OPEN_REPARSE_POINT, and the security is set through that
 * handle). Nothing happens for a plain directory, for a reparse point that is not a junction to pszTarget (when given),
 * for one whose DACL is protected already or for one that neither SYSTEM nor Administrators own (not setup's).
 */
static JUNCTION_RESULT
SecureJunctionObject(
    _In_ PCWSTR pszLink,
    _In_opt_ PCWSTR pszTarget,
    _In_ PROFILE_DIR_KIND Kind,
    _In_ BOOL bDenyListing,
    _Out_opt_ PDWORD pdwError)
{
    BY_HANDLE_FILE_INFORMATION Info;
    SECURITY_DESCRIPTOR_CONTROL Control;
    PSECURITY_DESCRIPTOR pSd = NULL;
    PACL pAcl = NULL;
    PSID pOwner = NULL;
    DWORD dwRevision, dwError = ERROR_SUCCESS;
    JUNCTION_RESULT Result = JunctionNotJunction;
    HANDLE hLink;

    hLink = CreateFileW(pszLink, READ_CONTROL | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hLink == INVALID_HANDLE_VALUE)
    {
        if (pdwError)
            *pdwError = GetLastError();
        return JunctionNotThere;
    }

    if (!GetFileInformationByHandle(hLink, &Info) || !(Info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        !(Info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (pszTarget && !JunctionPointsTo(hLink, pszTarget)))
    {
        goto done;
    }

    /* The DACL of the object itself: nothing to do when it is protected */
    Result = JunctionFailed;
    dwError = GetSecurityInfo(hLink, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                              &pOwner, NULL, &pAcl, NULL, &pSd);
    if (dwError != ERROR_SUCCESS)
        goto done;
    if (!GetSecurityDescriptorControl(pSd, &Control, &dwRevision))
    {
        dwError = GetLastError();
        goto done;
    }
    if (Control & SE_DACL_PROTECTED)
    {
        Result = JunctionProtected;
        goto done;
    }

    /*
     * Setup (SYSTEM) made the junction: its owner is SYSTEM or Administrators. One with another owner was put there
     * by someone else (a user who deleted the junction and made a link of their own, which may point anywhere when no
     * target is checked): giving it a protected DACL would make it look like the system's, and its owner could still
     * change it. It is left alone.
     */
    if (!pOwner || (!IsWellKnownSid(pOwner, WinLocalSystemSid) && !IsWellKnownSid(pOwner, WinBuiltinAdministratorsSid)))
    {
        DPRINT1("%S: not owned by SYSTEM or Administrators, left alone\n", pszLink);
        Result = JunctionForeignOwner;
        dwError = ERROR_SUCCESS;
        goto done;
    }

    pAcl = BuildJunctionDacl(Kind, bDenyListing);
    if (!pAcl)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    dwError = SetSecurityInfo(hLink, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                              NULL, NULL, pAcl, NULL);
    LocalFree(pAcl);
    if (dwError == ERROR_SUCCESS)
        Result = JunctionSecured;
    else
        DPRINT1("Failed to secure %S, error: %lu\n", pszLink, dwError);

done:
    if (pSd)
        LocalFree(pSd);
    CloseHandle(hLink);
    if (pdwError)
        *pdwError = dwError;
    return Result;
}

/*
 * C:\Windows is a junction to the system directory when that is somewhere else (setup makes it). The junction object has a
 * DACL of its own, which an older install left at what the volume root gave it (Authenticated Users: Modify): any user could
 * delete it and put another directory in its place. It gets the DACL of the Windows directory.
 */
static VOID
SecureWindowsJunction(
    _In_ PCWSTR pszSystemDirectory)
{
    WCHAR szLink[] = L"X:\\Windows";

    if (pszSystemDirectory[1] != L':' || pszSystemDirectory[2] != L'\\')
        return;
    szLink[0] = pszSystemDirectory[0];
    if (!_wcsicmp(pszSystemDirectory, szLink))
        return;

    SecureJunctionObject(szLink, NULL, ProfileDirSystem, FALSE, NULL);
}

/*
 * "Documents and Settings" in the root of the system volume is the junction of NT 5 programs to the profiles directory
 * (directory.c, CreateLegacyProgramDataJunctions). Made after the root got its DACL, the object inherited the root's
 * entries (Authenticated Users: Modify), so any user could delete the junction and put a directory of its own in its
 * place, where programs that use the NT 5 path then look for profiles. It gets the DACL of the profiles directory
 * (UsersAces: SYSTEM and Administrators full, Users and Everyone read), protected, after the deny of the listing to
 * Everyone that the legacy junctions carry. Only a junction that points to the profiles directory is changed.
 *
 * SecureLegacyUsersJunction: when setup makes the junction. RepairLegacyUsersJunction: an existing install (winlogon at
 * every start; once in effect, as a protected DACL is left alone): every change is a line in
 * System32\LogFiles\FolderAcl\legacy-junction-repair.txt.
 */
#define LJ_REPAIR_LOG L"%SystemRoot%\\System32\\LogFiles\\FolderAcl\\legacy-junction-repair.txt"

BOOL
SecureLegacyUsersJunction(
    _In_ PCWSTR pszLink,
    _In_ PCWSTR pszProfilesPath)
{
    JUNCTION_RESULT Result = SecureJunctionObject(pszLink, pszProfilesPath, ProfileDirUsers, TRUE, NULL);

    return Result == JunctionSecured || Result == JunctionProtected;
}

/* One line of the legacy junction repair log (System32\LogFiles\FolderAcl\legacy-junction-repair.txt) */
static VOID
LogJunctionRepair(
    _In_ PCWSTR pszLink,
    _In_ PCWSTR pszTarget,
    _In_ JUNCTION_RESULT Result,
    _In_ DWORD dwError)
{
    WCHAR szLog[MAX_PATH], szLine[3 * MAX_PATH], szDir[MAX_PATH];
    CHAR szUtf8[9 * MAX_PATH];
    SYSTEMTIME st;
    DWORD dwWritten;
    HANDLE hLog;
    PWCHAR p;
    int n;

    GetSystemTime(&st);
    if (FAILED(StringCchPrintfW(szLine, ARRAYSIZE(szLine),
                                L"%04u-%02u-%02uT%02u:%02u:%02uZ userenv: %s (junction%s%s): %s (error %lu)\r\n",
                                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, pszLink,
                                pszTarget ? L" to " : L"", pszTarget ? pszTarget : L"",
                                Result == JunctionSecured ? L"the entries it inherited replaced by the DACL of the "
                                L"profiles directory, protected" : L"not repaired", dwError)))
    {
        return;
    }
    DPRINT1("%S", szLine);
    if (!ExpandEnvironmentStringsW(LJ_REPAIR_LOG, szLog, ARRAYSIZE(szLog)))
        return;

    /* System32\LogFiles\FolderAcl (both inherit the DACL of the system folder) */
    StringCchCopyW(szDir, ARRAYSIZE(szDir), szLog);
    p = wcsrchr(szDir, L'\\');
    if (!p)
        return;
    *p = UNICODE_NULL;
    p = wcsrchr(szDir, L'\\');
    if (p)
    {
        *p = UNICODE_NULL;
        CreateDirectoryW(szDir, NULL);
        *p = L'\\';
    }
    CreateDirectoryW(szDir, NULL);

    hLog = CreateFileW(szLog, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hLog == INVALID_HANDLE_VALUE)
        return;
    n = WideCharToMultiByte(CP_UTF8, 0, szLine, -1, szUtf8, sizeof(szUtf8), NULL, NULL);
    if (n > 1)
        WriteFile(hLog, szUtf8, n - 1, &dwWritten, NULL);
    CloseHandle(hLog);
}

static VOID
RepairLegacyUsersJunction(VOID)
{
    WCHAR szLink[MAX_PATH], szProfiles[MAX_PATH];
    JUNCTION_RESULT Result;
    DWORD dwError = ERROR_SUCCESS;
    int n;

    if (!ReadPathValue(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", L"ProfilesDirectory",
                       szProfiles, ARRAYSIZE(szProfiles)) ||
        !ExpandEnvironmentStringsW(L"%SystemDrive%\\Documents and Settings", szLink, ARRAYSIZE(szLink)))
    {
        return;
    }
    n = (int)wcslen(szProfiles);
    if (n > 3 && szProfiles[n - 1] == L'\\')
        szProfiles[n - 1] = UNICODE_NULL;

    Result = SecureJunctionObject(szLink, szProfiles, ProfileDirUsers, TRUE, &dwError);
    if (Result == JunctionSecured || Result == JunctionFailed)
        LogJunctionRepair(szLink, szProfiles, Result, dwError);
}

/*
 * The other legacy junctions of NT 5 (ProgramData\Application Data, Desktop, Documents, Start Menu, Templates, and
 * Public\Documents\My Music, My Pictures, My Videos) are junction objects that setup made after the folder around them
 * got its DACL: they inherited ProgramData's entry that lets Users add files and folders, so a standard user could delete
 * a junction and put a directory of its own in its place (measured on a reference: the junctions are protected, Everyone
 * reads, SYSTEM and Administrators full control). Every junction directly in pszFolder that SYSTEM or the Administrators
 * own and that has no protected DACL yet gets the DACL of the profiles directory (the same as the Documents and Settings
 * junction); one a user made is left alone, as is anything that is not a junction. Only the object is opened.
 * Setup calls it after it made them, winlogon at every start for installs that made them before.
 */
VOID
SecureLegacyJunctionsInFolder(
    _In_ PCWSTR pszFolder)
{
    WCHAR szPattern[MAX_PATH], szLink[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    HANDLE hFind;
    JUNCTION_RESULT Result;
    DWORD dwError;

    if (FAILED(StringCchPrintfW(szPattern, ARRAYSIZE(szPattern), L"%s\\*", pszFolder)))
        return;
    hFind = FindFirstFileW(szPattern, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if ((FindData.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) !=
            (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) ||
            FAILED(StringCchPrintfW(szLink, ARRAYSIZE(szLink), L"%s\\%s", pszFolder, FindData.cFileName)))
        {
            continue;
        }
        dwError = ERROR_SUCCESS;
        Result = SecureJunctionObject(szLink, NULL, ProfileDirUsers, TRUE, &dwError);
        if (Result == JunctionSecured || Result == JunctionFailed)
            LogJunctionRepair(szLink, NULL, Result, dwError);
    } while (FindNextFileW(hFind, &FindData));
    FindClose(hFind);
}

/* The value of a registry string under HKLM, expanded; FALSE when it is not there */
static BOOL
ReadPathValue(
    _In_ PCWSTR pszKey,
    _In_ PCWSTR pszValue,
    _Out_writes_(cchPath) PWSTR pszPath,
    _In_ DWORD cchPath)
{
    WCHAR szRaw[MAX_PATH];
    DWORD dwLength = sizeof(szRaw), dwType;
    HKEY hKey;
    BOOL bResult = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, pszKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;

    if (RegQueryValueExW(hKey, pszValue, NULL, &dwType, (LPBYTE)szRaw, &dwLength) == ERROR_SUCCESS &&
        (dwType == REG_SZ || dwType == REG_EXPAND_SZ) &&
        dwLength >= sizeof(WCHAR))
    {
        szRaw[ARRAYSIZE(szRaw) - 1] = UNICODE_NULL;
        bResult = ExpandEnvironmentStringsW(szRaw, pszPath, cchPath) != 0;
    }
    RegCloseKey(hKey);
    return bResult;
}

/*
 * The files setup puts in the root of the system partition (base/setup/lib/bootsup.c): the loader, its
 * configuration (boot options, the kernel and HAL to load), the boot sector and MBR copies it chains to,
 * and the boot sector of another system it found there (a dual boot: freeldr.ini gets an entry that loads
 * and runs BOOTSECT.DOS, BOOTSECT.OS2 or BOOTSECT.OLD before any system starts).
 */
static const PCWSTR BootFiles[] =
{
    L"freeldr.sys", L"freeldr.ini", L"rosload.exe", L"bootsect.ros", L"mbr.old",
    L"bootsect.dos", L"bootsect.os2", L"bootsect.old"
};

static BOOL
IsSystemOrAdministrators(
    _In_ PSID pSid)
{
    return IsWellKnownSid(pSid, WinLocalSystemSid) || IsWellKnownSid(pSid, WinBuiltinAdministratorsSid);
}

/* What only SYSTEM and the Administrators may do to a boot file: change it, delete it, change its security */
#define BOOT_FILE_WRITE_ACCESS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | \
                                DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)

/*
 * A boot file is in order when SYSTEM or the Administrators own it (the owner may always change the DACL) and
 * no entry of its DACL lets anybody else write, delete or re-secure it. Such a file is left as it is: an
 * administrator may have added entries that only read. Whether the DACL is protected says nothing: a user who
 * could replace the file on an older install (Authenticated Users: Modify) owns the new one and may have given
 * it a protected DACL of its own.
 */
static BOOL
BootFileIsSecured(
    _In_ PCWSTR pszPath)
{
    PSECURITY_DESCRIPTOR pSd = NULL;
    PSID pOwner = NULL;
    PACL pDacl = NULL;
    PACE_HEADER pHeader;
    BOOL bResult = FALSE;
    DWORD i;

    if (GetNamedSecurityInfoW((PWSTR)pszPath, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                              &pOwner, NULL, &pDacl, NULL, &pSd) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    /* No DACL grants everything */
    if (pOwner && IsValidSid(pOwner) && IsSystemOrAdministrators(pOwner) && pDacl)
    {
        bResult = TRUE;
        for (i = 0; i < pDacl->AceCount; i++)
        {
            if (!GetAce(pDacl, i, (PVOID *)&pHeader))
            {
                bResult = FALSE;
                break;
            }
            if (pHeader->AceFlags & INHERIT_ONLY_ACE)
                continue;
            if (pHeader->AceType == ACCESS_DENIED_ACE_TYPE || pHeader->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
                pHeader->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE || pHeader->AceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE)
            {
                continue;
            }
            /* An allowing entry of another kind is not judged: secure the file */
            if (pHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
            {
                bResult = FALSE;
                break;
            }
            if ((((PACCESS_ALLOWED_ACE)pHeader)->Mask & BOOT_FILE_WRITE_ACCESS) &&
                !IsSystemOrAdministrators((PSID)&((PACCESS_ALLOWED_ACE)pHeader)->SidStart))
            {
                bResult = FALSE;
                break;
            }
        }
    }

    LocalFree(pSd);
    return bResult;
}

/*
 * The boot file pszPath gets the Administrators for its owner and the DACL of a boot file, unless it is in order
 * already. The owner goes first (with the take-ownership privilege, whatever the DACL a user left on the file
 * says): the owner may always change the DACL, so a user who stays the owner could open the file again.
 */
static VOID
SecureBootFile(
    _In_ PCWSTR pszPath)
{
    BYTE Administrators[SECURITY_MAX_SID_SIZE];
    DWORD cbAdministrators = sizeof(Administrators), dwError;
    PSECURITY_DESCRIPTOR pSd;
    PACL pAcl = NULL;
    BOOL bPresent, bDefaulted;
    BOOLEAN bWasEnabled;
    NTSTATUS Status;

    if (GetFileAttributesW(pszPath) == INVALID_FILE_ATTRIBUTES || BootFileIsSecured(pszPath))
        return;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Administrators, &cbAdministrators))
        return;

    Status = RtlAdjustPrivilege(SE_TAKE_OWNERSHIP_PRIVILEGE, TRUE, FALSE, &bWasEnabled);
    dwError = SetNamedSecurityInfoW((PWSTR)pszPath, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                    (PSID)Administrators, NULL, NULL, NULL);
    if (NT_SUCCESS(Status) && !bWasEnabled)
        RtlAdjustPrivilege(SE_TAKE_OWNERSHIP_PRIVILEGE, FALSE, FALSE, &bWasEnabled);
    if (dwError != ERROR_SUCCESS)
        DPRINT1("Failed to give %S to the Administrators, error: %lu\n", pszPath, dwError);

    pSd = BuildProfileDescriptor(ProfileDirBootFile, NULL);
    if (!pSd)
        return;
    if (GetSecurityDescriptorDacl(pSd, &bPresent, &pAcl, &bDefaulted) && bPresent && pAcl)
    {
        dwError = SetNamedSecurityInfoW((PWSTR)pszPath,
                                        SE_FILE_OBJECT,
                                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                        NULL, NULL, pAcl, NULL);
        if (dwError != ERROR_SUCCESS)
            DPRINT1("Failed to secure %S, error: %lu\n", pszPath, dwError);
    }
    LocalFree(pSd);
}

/* Each boot file in the root RootPath ("X:\") is secured (SecureBootFile) */
static VOID
SecureBootFiles(
    _In_ PCWSTR pszRoot)
{
    WCHAR szPath[MAX_PATH];
    UINT i;

    for (i = 0; i < ARRAYSIZE(BootFiles); i++)
    {
        if (SUCCEEDED(StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s%s", pszRoot, BootFiles[i])))
            SecureBootFile(szPath);
    }
}

/*
 * The drive letter of the system partition (setup records its device in HKLM\SYSTEM\Setup\SystemPartition), as
 * "X:\". FALSE if it has none (a partition without a letter is out of the users' reach through a path anyway).
 */
static BOOL
GetSystemPartitionRoot(
    _Out_writes_(cchRoot) PWSTR pszRoot,
    _In_ DWORD cchRoot)
{
    WCHAR szDevice[MAX_PATH], szTarget[MAX_PATH], szDrive[3] = L"A:";
    DWORD dwType, dwSize = sizeof(szDevice) - sizeof(WCHAR);
    HKEY hKey;
    LONG lError;

    lError = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Setup", 0, KEY_QUERY_VALUE, &hKey);
    if (lError != ERROR_SUCCESS)
        return FALSE;
    lError = RegQueryValueExW(hKey, L"SystemPartition", NULL, &dwType, (PBYTE)szDevice, &dwSize);
    RegCloseKey(hKey);
    if (lError != ERROR_SUCCESS || dwType != REG_SZ || cchRoot < 4)
        return FALSE;
    szDevice[dwSize / sizeof(WCHAR)] = UNICODE_NULL;

    for (szDrive[0] = L'A'; szDrive[0] <= L'Z'; szDrive[0]++)
    {
        if (QueryDosDeviceW(szDrive, szTarget, ARRAYSIZE(szTarget)) && !_wcsicmp(szTarget, szDevice))
        {
            pszRoot[0] = szDrive[0];
            pszRoot[1] = L':';
            pszRoot[2] = L'\\';
            pszRoot[3] = UNICODE_NULL;
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Program Files and Program Files (x86), for setup: created with the DACL of Windows (ProfileDirSystem), so that what
 * is installed in them while setup runs (PowerShell 7 on amd64, Common Files) inherits that DACL and not the one of
 * the volume root (Authenticated Users: Modify on what is created below the root). A directory that is there
 * already gets the DACL if it is not protected; then the function fails with ERROR_ALREADY_EXISTS, as
 * CreateDirectoryW.
 */
BOOL
WINAPI
CreateProgramFilesDirectory(
    _In_ PCWSTR pszPath)
{
    if (CreateSecuredProfileDir(pszPath, ProfileDirSystem, NULL))
        return TRUE;
    if (GetLastError() != ERROR_ALREADY_EXISTS)
        return FALSE;

    SecureExistingProfileDirectory(pszPath, ProfileDirSystem, NULL, FALSE);
    SetLastError(ERROR_ALREADY_EXISTS);
    return FALSE;
}

/*
 * The repair of the installs whose setup created Program Files without that DACL (2026.11-1, 2026.11-2 and main up to
 * this change): the folder got the DACL of Windows at the next start (SecureSystemDirectories), but what setup had
 * installed in it by then kept the entries of the volume root: Authenticated Users: Modify, on PowerShell 7 (in the
 * machine Path) and Common Files among them. Such an object has an unprotected DACL holding the copies of the root's
 * inheritable entries (as a directory gets them: the inheritance flags without inherit-only; as a file: no flags).
 * Exactly those objects lose the copies and inherit from their parent afresh (top down, so the parent is repaired
 * first); entries put there on purpose stay; protected DACLs and what is below them, and reparse points, are left.
 * Once, after setup: the log in System32\LogFiles\FolderAcl is the mark that it ran (SYSTEM or the Administrators
 * own it; a file in System32 nobody else can create).
 */
#define PF_REPAIR_LOG L"%SystemRoot%\\System32\\LogFiles\\FolderAcl\\program-files-repair.txt"

typedef struct _PF_REPAIR
{
    HANDLE hLog;
    PACL pRootAcl;                          /* the DACL whose inheritable entries the objects hold copies of */
    BYTE TriggerSid[SECURITY_MAX_SID_SIZE]; /* an object is repaired when it holds a copy of an entry for this SID ... */
    DWORD TriggerMask;                      /* ... with this access (0: any) */
    ULONG Checked, Repaired, Failed, Skipped;
} PF_REPAIR, *PPF_REPAIR;

static VOID
PfRepairLog(
    _In_ PPF_REPAIR pCtx,
    _In_ PCWSTR pszFormat,
    ...)
{
    WCHAR szLine[MAX_PATH + 200];
    CHAR szUtf8[3 * (MAX_PATH + 200)];
    va_list Args;
    DWORD dwWritten;
    int n;

    va_start(Args, pszFormat);
    StringCchVPrintfW(szLine, ARRAYSIZE(szLine) - 2, pszFormat, Args);
    va_end(Args);
    StringCchCatW(szLine, ARRAYSIZE(szLine), L"\r\n");
    DPRINT1("%S", szLine);

    n = WideCharToMultiByte(CP_UTF8, 0, szLine, -1, szUtf8, sizeof(szUtf8), NULL, NULL);
    if (pCtx->hLog != INVALID_HANDLE_VALUE && n > 1)
        WriteFile(pCtx->hLog, szUtf8, n - 1, &dwWritten, NULL);
}

/* An ACE that is a copy of an inheritable entry of the root's DACL, as a directory (or a file) below the root gets it */
static BOOL
IsRootCopyAce(
    _In_ PACE_HEADER pAce,
    _In_ PACL pRootAcl)
{
    BYTE Flags = pAce->AceFlags & ~INHERITED_ACE, Inherit;
    PACCESS_ALLOWED_ACE pRoot;
    DWORD i;

    if (pAce->AceType != ACCESS_ALLOWED_ACE_TYPE)
        return FALSE;

    for (i = 0; i < pRootAcl->AceCount; i++)
    {
        if (!GetAce(pRootAcl, i, (PVOID *)&pRoot) || pRoot->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;
        Inherit = pRoot->Header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
        if (!Inherit || pRoot->Mask != ((PACCESS_ALLOWED_ACE)pAce)->Mask ||
            !EqualSid((PSID)&pRoot->SidStart, (PSID)&((PACCESS_ALLOWED_ACE)pAce)->SidStart))
        {
            continue;
        }
        if (Flags == Inherit || Flags == 0)
            return TRUE;
    }
    return FALSE;
}

/*
 * Repair one object (see above), opened relative to its folder's handle (WalkByHandle). FALSE: its DACL is protected,
 * leave what is below it alone
 */
static BOOL
RepairProgramFilesVisit(
    _In_ WALK_EVENT Event,
    _In_ HANDLE hParent,
    _In_opt_ HANDLE hObject,
    _In_ PCWSTR pszPath,
    _In_ BOOL bDirectory,
    _In_ DWORD dwError,
    _Inout_ PVOID pContext,
    _In_opt_ PVOID pLevel,
    _Out_ PVOID *ppChildLevel)
{
    PPF_REPAIR pCtx = pContext;
    PSECURITY_DESCRIPTOR pSd;
    SECURITY_DESCRIPTOR_CONTROL Control;
    PACL pOldAcl = NULL, pNewAcl;
    PACE_HEADER pAce;
    PSID pOwner = NULL;
    BOOL bPresent, bDefaulted, bCopies = FALSE, bResult = TRUE;
    DWORD dwRevision, i, nRemoved = 0;

    UNREFERENCED_PARAMETER(pLevel);
    *ppChildLevel = NULL;

    switch (Event)
    {
        case WalkReparse:
            /* A link is not walked and not repaired (the listing's reparse points were skipped before too) */
            return FALSE;
        case WalkNotOpened:
            pCtx->Checked++;
            pCtx->Failed++;
            PfRepairLog(pCtx, L"not read (error %lu): %s", dwError, pszPath);
            return FALSE;
        case WalkSeveralNames:
            pCtx->Checked++;
            pCtx->Skipped++;
            PfRepairLog(pCtx, L"not checked (a file with more than one name): %s", pszPath);
            return FALSE;
        case WalkTooDeep:
            pCtx->Skipped++;
            PfRepairLog(pCtx, L"not checked (too deep): %s", pszPath);
            return FALSE;
        default:
            break;
    }

    pCtx->Checked++;
    pSd = QueryHandleSecurity(hObject, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION);
    if (!pSd)
    {
        pCtx->Failed++;
        PfRepairLog(pCtx, L"not read (error %lu): %s", GetLastError(), pszPath);
        return TRUE;
    }

    if (!GetSecurityDescriptorControl(pSd, &Control, &dwRevision) ||
        !GetSecurityDescriptorOwner(pSd, &pOwner, &bDefaulted) ||
        !GetSecurityDescriptorDacl(pSd, &bPresent, &pOldAcl, &bDefaulted))
    {
        pCtx->Failed++;
        PfRepairLog(pCtx, L"not read (error %lu): %s", GetLastError(), pszPath);
        goto done;
    }
    if (Control & SE_DACL_PROTECTED)
    {
        bResult = FALSE;
        goto done;
    }
    if (!bPresent || !pOldAcl)
        goto done;

    /* only what the system owns: an object a user made is theirs, and stays as it is (nothing is blessed) */
    if (!pOwner || !IsValidSid(pOwner) || !IsSystemOrAdministrators(pOwner))
    {
        pCtx->Skipped++;
        PfRepairLog(pCtx, L"left alone (not owned by SYSTEM or the Administrators): %s", pszPath);
        bResult = FALSE;
        goto done;
    }

    /* only the objects with a copy of the template's entry for the trigger SID are the ones setup left behind */
    for (i = 0; i < pOldAcl->AceCount; i++)
    {
        if (GetAce(pOldAcl, i, (PVOID *)&pAce) && IsRootCopyAce(pAce, pCtx->pRootAcl) &&
            EqualSid((PSID)&((PACCESS_ALLOWED_ACE)pAce)->SidStart, (PSID)pCtx->TriggerSid) &&
            (!pCtx->TriggerMask || ((PACCESS_ALLOWED_ACE)pAce)->Mask == pCtx->TriggerMask))
        {
            bCopies = TRUE;
            break;
        }
    }
    if (!bCopies)
        goto done;

    pNewAcl = LocalAlloc(LMEM_FIXED, pOldAcl->AclSize);
    if (!pNewAcl || !InitializeAcl(pNewAcl, pOldAcl->AclSize, ACL_REVISION))
    {
        pCtx->Failed++;
        if (pNewAcl)
            LocalFree(pNewAcl);
        goto done;
    }

    for (i = 0; i < pOldAcl->AceCount; i++)
    {
        if (!GetAce(pOldAcl, i, (PVOID *)&pAce))
            break;
        if ((pAce->AceFlags & INHERITED_ACE) || IsRootCopyAce(pAce, pCtx->pRootAcl))
        {
            nRemoved++;
            continue;
        }
        if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pAce, pAce->AceSize))
            break;
    }

    if (i < pOldAcl->AceCount)
    {
        pCtx->Failed++;
        PfRepairLog(pCtx, L"not repaired (its DACL could not be copied): %s", pszPath);
    }
    else
    {
        /* the kept entries, then what the parent passes on */
        dwError = SetInheritingDacl(hParent, hObject, bDirectory, pNewAcl, FALSE);
        if (dwError == ERROR_SUCCESS)
        {
            pCtx->Repaired++;
            PfRepairLog(pCtx, L"repaired: %s (%lu entries of the volume root removed, %lu kept, the rest inherited)",
                        pszPath, nRemoved, pNewAcl->AceCount);
        }
        else
        {
            pCtx->Failed++;
            PfRepairLog(pCtx, L"not repaired (error %lu): %s", dwError, pszPath);
        }
    }
    LocalFree(pNewAcl);

done:
    LocalFree(pSd);
    return bResult;
}

/* TRUE when setup is still running (the second stage): Program Files is not finished yet */
static BOOL
IsSetupInProgress(VOID)
{
    DWORD dwValue = 0, dwSize = sizeof(dwValue), dwType;
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Setup", 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, L"SystemSetupInProgress", NULL, &dwType, (PBYTE)&dwValue, &dwSize) != ERROR_SUCCESS ||
        dwType != REG_DWORD)
    {
        dwValue = 0;
    }
    RegCloseKey(hKey);
    return dwValue != 0;
}

/* The log file exists and SYSTEM or the Administrators own it */
static BOOL
RepairLogExists(
    _In_ PCWSTR pszLog)
{
    PSECURITY_DESCRIPTOR pSd = NULL;
    PSID pOwner = NULL;
    BOOL bResult;

    if (GetFileAttributesW(pszLog) == INVALID_FILE_ATTRIBUTES)
        return FALSE;
    if (GetNamedSecurityInfoW((PWSTR)pszLog, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwner, NULL, NULL, NULL,
                              &pSd) != ERROR_SUCCESS)
    {
        /* a volume without security: nothing to repair there */
        return TRUE;
    }
    bResult = pOwner && IsValidSid(pOwner) && IsSystemOrAdministrators(pOwner);
    LocalFree(pSd);
    return bResult;
}

/*
 * One pass over the folders of pszRoots (cRoots of them, empty ones skipped): the objects below each that hold a copy of an
 * inheritable entry of the template of TemplateKind for the trigger SID (with the trigger access, 0: any) inherit from their
 * folder afresh. Logged to pszLog, which is the mark that the pass ran (see above).
 */
static VOID
RunFolderRepair(
    _In_ PCWSTR pszLog,
    _In_ PCWSTR pszWhat,
    _In_ PROFILE_DIR_KIND TemplateKind,
    _In_ WELL_KNOWN_SID_TYPE TriggerSidType,
    _In_ DWORD dwTriggerMask,
    _In_reads_(cRoots) WCHAR (*pszRoots)[MAX_PATH],
    _In_ UINT cRoots)
{
    WCHAR szLog[MAX_PATH], szTemp[MAX_PATH], szDir[MAX_PATH];
    PSECURITY_DESCRIPTOR pRootSd;
    BOOL bPresent, bDefaulted;
    DWORD cbSid, dwSize;
    PF_REPAIR Ctx;
    SYSTEMTIME st;
    HANDLE hTop;
    PWCHAR p;
    UINT i;

    if (IsSetupInProgress())
        return;
    if (!ExpandEnvironmentStringsW(pszLog, szLog, ARRAYSIZE(szLog)) || RepairLogExists(szLog))
        return;

    ZeroMemory(&Ctx, sizeof(Ctx));
    Ctx.hLog = INVALID_HANDLE_VALUE;
    Ctx.TriggerMask = dwTriggerMask;
    cbSid = sizeof(Ctx.TriggerSid);
    if (!CreateWellKnownSid(TriggerSidType, NULL, Ctx.TriggerSid, &cbSid))
        return;
    pRootSd = BuildProfileDescriptor(TemplateKind, NULL);
    if (!pRootSd)
        return;
    if (!GetSecurityDescriptorDacl(pRootSd, &bPresent, &Ctx.pRootAcl, &bDefaulted) || !bPresent || !Ctx.pRootAcl)
        goto done;

    /* the log's folder below System32\LogFiles (both inherit the DACL of the system folder) */
    StringCchCopyW(szDir, ARRAYSIZE(szDir), szLog);
    p = wcsrchr(szDir, L'\\');
    if (!p)
        goto done;
    *p = UNICODE_NULL;
    p = wcsrchr(szDir, L'\\');
    if (p)
    {
        *p = UNICODE_NULL;
        CreateDirectoryW(szDir, NULL);
        *p = L'\\';
    }
    CreateDirectoryW(szDir, NULL);

    /* written under another name and renamed when the pass is complete: a pass cut short runs again */
    if (FAILED(StringCchPrintfW(szTemp, ARRAYSIZE(szTemp), L"%s.tmp", szLog)))
        goto done;
    Ctx.hLog = CreateFileW(szTemp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (Ctx.hLog == INVALID_HANDLE_VALUE)
    {
        DPRINT1("Cannot create %S (error %lu): %S not checked\n", szTemp, GetLastError(), pszWhat);
        goto done;
    }

    GetSystemTime(&st);
    PfRepairLog(&Ctx, L"%04u-%02u-%02uT%02u:%02u:%02uZ userenv: %s: objects owned by the system that still have the entries "
                L"of the folder they were made in inherit from their folder", st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, pszWhat);

    for (i = 0; i < cRoots; i++)
    {
        PCWSTR pszPath = pszRoots[i];

        if (!pszPath[0] || GetFileAttributesW(pszPath) == INVALID_FILE_ATTRIBUTES)
            continue;
        /* A volume without access control lists (FAT): nothing to repair there */
        dwSize = 0;
        GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize);
        if (dwSize == 0)
        {
            PfRepairLog(&Ctx, L"%s: no access control list to read (error %lu), nothing to repair", pszPath, GetLastError());
            continue;
        }
        hTop = OpenWalkTop(pszPath, FALSE);
        if (!hTop)
        {
            PfRepairLog(&Ctx, L"%s: not a directory, or a link: not checked", pszPath);
            continue;
        }
        PfRepairLog(&Ctx, L"checking %s", pszPath);
        WalkByHandle(hTop, pszPath, 0, RepairProgramFilesVisit, &Ctx, NULL);
        CloseHandle(hTop);
    }

    PfRepairLog(&Ctx, L"done: %lu objects checked, %lu repaired, %lu failed, %lu not checked",
                Ctx.Checked, Ctx.Repaired, Ctx.Failed, Ctx.Skipped);
    CloseHandle(Ctx.hLog);
    Ctx.hLog = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(szTemp, szLog, MOVEFILE_REPLACE_EXISTING))
        DPRINT1("Cannot rename %S (error %lu)\n", szTemp, GetLastError());

done:
    if (Ctx.hLog != INVALID_HANDLE_VALUE)
        CloseHandle(Ctx.hLog);
    LocalFree(pRootSd);
}

static VOID
RepairProgramFiles(VOID)
{
    WCHAR szRoots[2][MAX_PATH] = {{0}};

    if (!ReadPathValue(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesDir", szRoots[0], MAX_PATH))
        szRoots[0][0] = UNICODE_NULL;
    if (!ReadPathValue(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesDir (x86)", szRoots[1], MAX_PATH))
        szRoots[1][0] = UNICODE_NULL;
    RunFolderRepair(PF_REPAIR_LOG, L"Program Files", ProfileDirRoot, WinAuthenticatedUserSid, 0, szRoots, ARRAYSIZE(szRoots));
}

/*
 * The same for the folders of the all-users Start Menu and Templates (ProgramData\Microsoft) and the all-users Desktop, on
 * installs that made them before they had their own descriptors: an object there that holds ProgramData's entry for
 * Users (add files and folders), or Public's entries for the interactive users (modify), is one a standard user could
 * write into, and a program put into Startup runs for every user at logon.
 */
#define PD_REPAIR_LOG L"%SystemRoot%\\System32\\LogFiles\\FolderAcl\\programdata-repair.txt"
#define PD_DESKTOP_REPAIR_LOG L"%SystemRoot%\\System32\\LogFiles\\FolderAcl\\public-desktop-repair.txt"
#define PROFILELIST_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"

static VOID
RepairProgramData(VOID)
{
    WCHAR szRoots[1][MAX_PATH] = {{0}};

    if (ReadPathValue(PROFILELIST_KEY, L"ProgramData", szRoots[0], MAX_PATH) &&
        SUCCEEDED(StringCchCatW(szRoots[0], MAX_PATH, L"\\Microsoft")))
    {
        RunFolderRepair(PD_REPAIR_LOG, L"ProgramData\\Microsoft", ProfileDirProgramData, WinBuiltinUsersSid, USERS_ADD,
                        szRoots, ARRAYSIZE(szRoots));
    }

    szRoots[0][0] = UNICODE_NULL;
    if (ReadPathValue(PROFILELIST_KEY, L"Public", szRoots[0], MAX_PATH) &&
        SUCCEEDED(StringCchCatW(szRoots[0], MAX_PATH, L"\\Desktop")))
    {
        RunFolderRepair(PD_DESKTOP_REPAIR_LOG, L"Public\\Desktop", ProfileDirPublic, WinInteractiveSid, MODIFY_DC,
                        szRoots, ARRAYSIZE(szRoots));
    }
}

/* The label Low (NO_WRITE_UP, inherit-only: what is made in the folder inherits it) of the recycle bin folder, when it has none */
static VOID
LabelRecycleBinRoot(
    _In_ PCWSTR pszPath)
{
    PSECURITY_DESCRIPTOR pSd = NULL, pLabelSd = NULL;
    PACL pSacl = NULL;
    BOOL bPresent, bDefaulted, bHasLabel = FALSE;

    if (GetNamedSecurityInfoW((PWSTR)pszPath, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &pSacl, &pSd) ==
        ERROR_SUCCESS)
    {
        bHasLabel = (pSacl != NULL && pSacl->AceCount != 0);
        LocalFree(pSd);
    }
    if (bHasLabel ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;OICIIO;NW;;;LW)", SDDL_REVISION_1, &pLabelSd, NULL))
    {
        return;
    }
    pSacl = NULL;
    if (GetSecurityDescriptorSacl(pLabelSd, &bPresent, &pSacl, &bDefaulted) && pSacl &&
        SetNamedSecurityInfoW((PWSTR)pszPath, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pSacl) != ERROR_SUCCESS)
    {
        DPRINT1("Cannot label %S\n", pszPath);
    }
    LocalFree(pLabelSd);
}

/*
 * The folder of the recycle bins on the system volume gets the descriptor Windows has (see RecycleRootAces). Made here, by
 * the system, the shell would make it as the first user who deletes a file and that user would own it: a user who owns the
 * folder may give themselves the right to remove the bins of others. One that is there is given the descriptor only when
 * SYSTEM or the Administrators own it; one a user made is left alone (nothing is blessed). pszRoot is the root of the volume
 * with a closing backslash; a volume without access control lists (FAT) has none of this.
 */
VOID
SecureRecycleBinRoot(
    _In_ PCWSTR pszRoot)
{
    WCHAR szPath[MAX_PATH];
    PSECURITY_DESCRIPTOR pSd = NULL;
    PSID pOwner = NULL;
    DWORD dwSize = 0;

    GetFileSecurityW(pszRoot, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize);
    if (dwSize == 0 || FAILED(StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%sRECYCLER", pszRoot)))
        return;

    if (GetFileAttributesW(szPath) == INVALID_FILE_ATTRIBUTES)
    {
        if (CreateSecuredProfileDir(szPath, ProfileDirRecycleRoot, NULL))
        {
            SetFileAttributesW(szPath, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
            LabelRecycleBinRoot(szPath);
        }
        return;
    }

    if (GetNamedSecurityInfoW(szPath, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwner, NULL, NULL, NULL, &pSd) != ERROR_SUCCESS)
        return;
    if (pOwner && IsValidSid(pOwner) && IsSystemOrAdministrators(pOwner))
    {
        SecureExistingProfileDirectory(szPath, ProfileDirRecycleRoot, NULL, FALSE);
        LabelRecycleBinRoot(szPath);
    }
    else
    {
        DPRINT1("%S: not owned by SYSTEM or the Administrators, left alone\n", szPath);
    }
    LocalFree(pSd);
}

/* The all-users Start Menu and Templates folder (ProgramData\Microsoft) and the all-users Desktop get their descriptors */
static VOID
SecureAllUsersFolders(VOID)
{
    WCHAR szPath[MAX_PATH];

    if (ReadPathValue(PROFILELIST_KEY, L"ProgramData", szPath, ARRAYSIZE(szPath)))
    {
        SecureLegacyJunctionsInFolder(szPath);
        if (SUCCEEDED(StringCchCatW(szPath, ARRAYSIZE(szPath), L"\\Microsoft")))
            SecureExistingProfileDirectory(szPath, ProfileDirProgramDataMicrosoft, NULL, FALSE);
    }
    if (ReadPathValue(PROFILELIST_KEY, L"Public", szPath, ARRAYSIZE(szPath)))
    {
        WCHAR szDocuments[MAX_PATH];

        if (SUCCEEDED(StringCchPrintfW(szDocuments, ARRAYSIZE(szDocuments), L"%s\\Documents", szPath)))
            SecureLegacyJunctionsInFolder(szDocuments);
        if (SUCCEEDED(StringCchCatW(szPath, ARRAYSIZE(szPath), L"\\Desktop")))
            SecureExistingProfileDirectory(szPath, ProfileDirPublicDesktop, NULL, FALSE);
    }
}

/*
 * Called by winlogon at every start: an install from before the well-known folders had the DACLs of Windows has the
 * one of the volume root on them (Authenticated Users: Modify, for ProgramData, Program Files, Windows and the
 * root itself). Each of them gets the DACL of Windows and what is in it inherits it afresh, entries put there on purpose
 * stay. Does nothing for a folder whose DACL is already protected, so it costs one security query per folder.
 */
BOOL
WINAPI
SecureSystemDirectories(VOID)
{
    WCHAR szPath[MAX_PATH], szWindows[MAX_PATH];
    BOOL bResult = FALSE;

    /* ProgramData */
    if (ReadPathValue(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", L"ProgramData", szPath, ARRAYSIZE(szPath)))
    {
        SecureExistingProfileDirectory(szPath, ProfileDirProgramData, NULL, TRUE);
        bResult = TRUE;

        /* What setup (or an older one) made below ProgramData\Microsoft and Public\Desktop, once */
        SecureAllUsersFolders();
        RepairProgramData();
    }

    /* Windows, with its Temp first: that has a DACL of its own, which the pass over the rest then leaves alone */
    if (GetWindowsDirectoryW(szWindows, ARRAYSIZE(szWindows)) &&
        SUCCEEDED(StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\Temp", szWindows)))
    {
        SecureExistingProfileDirectory(szPath, ProfileDirTemp, NULL, TRUE);
        SecureExistingProfileDirectory(szWindows, ProfileDirSystem, NULL, TRUE);

        /* The registry hives are for SYSTEM and Administrators only; the pass above has left them what system32 gives */
        if (SUCCEEDED(StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\system32\\config", szWindows)))
            SecureExistingProfileDirectory(szPath, ProfileDirConfig, NULL, TRUE);

        /* The \Windows junction to it, itself */
        SecureWindowsJunction(szWindows);
    }

    /* The \Documents and Settings junction to the profiles directory, itself */
    RepairLegacyUsersJunction();

    /* Program Files, and the 32-bit one */
    if (ReadPathValue(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesDir", szPath, ARRAYSIZE(szPath)))
        SecureExistingProfileDirectory(szPath, ProfileDirSystem, NULL, TRUE);
    if (ReadPathValue(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesDir (x86)", szPath, ARRAYSIZE(szPath)))
        SecureExistingProfileDirectory(szPath, ProfileDirSystem, NULL, TRUE);

    /* What setup installed in them before it gave them their DACL (once) */
    RepairProgramFiles();

    /* The root of the system volume, itself only */
    if (GetWindowsDirectoryW(szWindows, ARRAYSIZE(szWindows)) && szWindows[1] == L':' && szWindows[2] == L'\\')
    {
        szPath[0] = szWindows[0];
        szPath[1] = L':';
        szPath[2] = L'\\';
        szPath[3] = UNICODE_NULL;
        SecureExistingProfileDirectory(szPath, ProfileDirRoot, NULL, FALSE);
        SecureRecycleBinRoot(szPath);

        /* The boot files, where setup puts them when the system partition is this volume */
        SecureBootFiles(szPath);
    }

    /* The boot files on the system partition, when it is another volume with a letter */
    if (GetSystemPartitionRoot(szPath, ARRAYSIZE(szPath)) &&
        !(GetWindowsDirectoryW(szWindows, ARRAYSIZE(szWindows)) && towupper(szWindows[0]) == towupper(szPath[0])))
    {
        SecureBootFiles(szPath);
    }

    return bResult;
}

/*
 * AppData\LocalLow of a profile: "Windows Integrity Mechanism Design" (Mandatory label inheritance):
 * "This folder is assigned a low mandatory label when the profile is initialized and intended as the
 * top-level folder that is writeable by default by low-integrity applications"; the label is inheritable
 * (OI)(CI) with NO_WRITE_UP, so what is created below it is Low too. Low and Untrusted processes cannot
 * write anywhere else in the profile. Creates the folder if it is missing and labels it if it has no label
 * of its own; a folder that carries a label already is left alone.
 */
BOOL
SetLowIntegrityProfileFolder(
    _In_ PCWSTR pszProfilePath)
{
    WCHAR szPath[MAX_PATH];
    PSECURITY_DESCRIPTOR pSd = NULL, pLabelSd = NULL;
    PACL pSacl = NULL;
    BOOL bPresent, bDefaulted;
    DWORD dwError;

    if (FAILED(StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\AppData\\LocalLow", pszProfilePath)))
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return FALSE;
    }

    if (!CreateDirectoryW(szPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        DPRINT1("Cannot create %S (error %lu)\n", szPath, GetLastError());
        return FALSE;
    }

    dwError = GetNamedSecurityInfoW(szPath, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                                    NULL, NULL, NULL, &pSacl, &pSd);
    if (dwError == ERROR_SUCCESS && pSacl != NULL && pSacl->AceCount != 0)
    {
        LocalFree(pSd);
        return TRUE;
    }
    if (pSd)
        LocalFree(pSd);

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;OICI;NW;;;LW)", SDDL_REVISION_1,
                                                              &pLabelSd, NULL))
    {
        return FALSE;
    }
    pSacl = NULL;
    if (!GetSecurityDescriptorSacl(pLabelSd, &bPresent, &pSacl, &bDefaulted) || !pSacl)
    {
        LocalFree(pLabelSd);
        SetLastError(ERROR_INVALID_SECURITY_DESCR);
        return FALSE;
    }

    dwError = SetNamedSecurityInfoW(szPath, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
                                    NULL, NULL, NULL, pSacl);
    LocalFree(pLabelSd);
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT1("Cannot label %S Low (error %lu)\n", szPath, dwError);
        SetLastError(dwError);
        return FALSE;
    }
    return TRUE;
}

/* EOF */
