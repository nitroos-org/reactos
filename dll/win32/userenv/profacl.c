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

#define NDEBUG
#include <debug.h>

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

        case ProfileDirSystem:
            pAces = SystemAces;
            cAces = ARRAYSIZE(SystemAces);
            break;

        case ProfileDirTemp:
            pAces = TempAces;
            cAces = ARRAYSIZE(TempAces);
            break;

        case ProfileDirRoot:
            pAces = RootAces;
            cAces = ARRAYSIZE(RootAces);
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
 * Keep the explicit entries of an object and let it inherit afresh from its parent: the entries
 * it got from the old parent go. Returns FALSE for an object whose DACL is protected (nothing is
 * changed, and what is below it inherits from it, not from us) or cannot be read.
 */
static BOOL
ResetInheritedEntries(
    _In_ PCWSTR pszPath,
    _In_ PACL pLegacyAcl)
{
    PSECURITY_DESCRIPTOR pSd = NULL;
    SECURITY_DESCRIPTOR_CONTROL Control;
    PACL pOldAcl = NULL, pNewAcl;
    BOOL bPresent, bDefaulted, bResult = FALSE;
    DWORD dwSize = 0, dwRevision, dwError, i;

    GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize);
    if (dwSize == 0)
        return FALSE;

    pSd = LocalAlloc(LMEM_FIXED, dwSize);
    if (!pSd)
        return FALSE;

    if (!GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, pSd, dwSize, &dwSize) ||
        !GetSecurityDescriptorControl(pSd, &Control, &dwRevision) ||
        (Control & SE_DACL_PROTECTED) ||
        !GetSecurityDescriptorDacl(pSd, &bPresent, &pOldAcl, &bDefaulted))
        goto done;

    /* No DACL grants everything to everybody: that is how it was meant */
    if (!bPresent || !pOldAcl)
        goto done;

    pNewAcl = LocalAlloc(LMEM_FIXED, pOldAcl->AclSize);
    if (!pNewAcl)
        goto done;

    if (InitializeAcl(pNewAcl, pOldAcl->AclSize, ACL_REVISION))
    {
        BOOL bOk = TRUE;

        for (i = 0; i < pOldAcl->AceCount; i++)
        {
            PACE_HEADER pAce;

            if (!GetAce(pOldAcl, i, (PVOID *)&pAce))
            {
                bOk = FALSE;
                break;
            }
            if ((pAce->AceFlags & INHERITED_ACE) || IsLegacyAce(pAce, pLegacyAcl))
                continue;
            if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pAce, pAce->AceSize))
            {
                bOk = FALSE;
                break;
            }
        }

        if (bOk)
        {
            dwError = SetNamedSecurityInfoW((PWSTR)pszPath,
                                            SE_FILE_OBJECT,
                                            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                            NULL, NULL, pNewAcl, NULL);
            if (dwError != ERROR_SUCCESS)
                DPRINT1("Failed to secure %S, error: %lu\n", pszPath, dwError);
            bResult = TRUE;
        }
    }

    LocalFree(pNewAcl);

done:
    LocalFree(pSd);
    return bResult;
}

/*
 * Reset the DACL of everything under a directory to what its parent inherits, top down: the
 * explicit entries of the older installs (Authenticated Users: Modify) go, and so do the copies
 * of them that the files and directories got from their parents. Junctions are left alone:
 * they are links into the same profile and are listed by nobody.
 */
static VOID
ResetInheritance(
    _In_ PCWSTR pszDirectory,
    _In_ PACL pEmptyAcl,
    _In_opt_ PACL pLegacyAcl,
    _In_ UINT uDepth)
{
    WCHAR szPath[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    HANDLE hFind;
    SIZE_T cchDir;
    DWORD dwError;

    cchDir = wcslen(pszDirectory);
    if (uDepth > 64 || cchDir + 3 > ARRAYSIZE(szPath))
        return;

    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\*", pszDirectory);
    hFind = FindFirstFileW(szPath, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (!wcscmp(FindData.cFileName, L".") || !wcscmp(FindData.cFileName, L".."))
            continue;

        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        if (FAILED(StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\%s", pszDirectory, FindData.cFileName)))
        {
            DPRINT1("Path too long, not secured: %S\\%S\n", pszDirectory, FindData.cFileName);
            continue;
        }

        if (pLegacyAcl)
        {
            /* Entries put there on purpose stay, a protected DACL and what hangs below it is not ours */
            if (!ResetInheritedEntries(szPath, pLegacyAcl))
                continue;
        }
        else
        {
            dwError = SetNamedSecurityInfoW(szPath,
                                            SE_FILE_OBJECT,
                                            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                            NULL, NULL, pEmptyAcl, NULL);
            if (dwError != ERROR_SUCCESS)
                DPRINT1("Failed to secure %S, error: %lu\n", szPath, dwError);
        }

        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            ResetInheritance(szPath, pEmptyAcl, pLegacyAcl, uDepth + 1);
    } while (FindNextFileW(hFind, &FindData));

    FindClose(hFind);
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
    ACL EmptyAcl;
    BOOL bPresent, bDefaulted;
    DWORD dwError;
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

    if (GetSecurityDescriptorDacl(pSd, &bPresent, &pAcl, &bDefaulted) && bPresent && pAcl)
    {
        dwError = SetNamedSecurityInfoW((PWSTR)pszPath,
                                        SE_FILE_OBJECT,
                                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                        NULL, NULL, pAcl, NULL);
        if (dwError != ERROR_SUCCESS)
        {
            DPRINT1("Failed to secure %S, error: %lu\n", pszPath, dwError);
        }
        else if (bRecurse && Kind != ProfileDirRoot && (!bShared || pLegacyAcl) && InitializeAcl(&EmptyAcl, sizeof(EmptyAcl), ACL_REVISION))
        {
            ResetInheritance(pszPath, &EmptyAcl, pLegacyAcl, 0);
        }
    }

    LocalFree(pSd);
    if (pLegacySd)
        LocalFree(pLegacySd);
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
    }

    /* Windows, with its Temp first: that has a DACL of its own, which the pass over the rest then leaves alone */
    if (GetWindowsDirectoryW(szWindows, ARRAYSIZE(szWindows)) &&
        SUCCEEDED(StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\Temp", szWindows)))
    {
        SecureExistingProfileDirectory(szPath, ProfileDirTemp, NULL, TRUE);
        SecureExistingProfileDirectory(szWindows, ProfileDirSystem, NULL, TRUE);
    }

    /* Program Files, and the 32-bit one */
    if (ReadPathValue(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesDir", szPath, ARRAYSIZE(szPath)))
        SecureExistingProfileDirectory(szPath, ProfileDirSystem, NULL, TRUE);
    if (ReadPathValue(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesDir (x86)", szPath, ARRAYSIZE(szPath)))
        SecureExistingProfileDirectory(szPath, ProfileDirSystem, NULL, TRUE);

    /* The root of the system volume, itself only */
    if (GetWindowsDirectoryW(szWindows, ARRAYSIZE(szWindows)) && szWindows[1] == L':' && szWindows[2] == L'\\')
    {
        szPath[0] = szWindows[0];
        szPath[1] = L':';
        szPath[2] = L'\\';
        szPath[3] = UNICODE_NULL;
        SecureExistingProfileDirectory(szPath, ProfileDirRoot, NULL, FALSE);
    }

    return bResult;
}

/* EOF */
