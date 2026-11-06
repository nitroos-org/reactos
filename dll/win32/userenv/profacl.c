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

#define NDEBUG
#include <debug.h>

/*
 * The DACLs are built entry by entry, not from an SDDL string: the string parser of advapi32 mis-reads a SID
 * written as S-1-5-x in every entry but the last (it gets the sub-authorities of the text behind it).
 */
typedef struct _PROFILE_ACE
{
    WELL_KNOWN_SID_TYPE SidType;    /* WinNullSid: the SID of the user */
    DWORD Mask;
    BYTE Flags;
} PROFILE_ACE;

#define OI_CI (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
#define OI_CI_IO (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE)
#define RX_ACCESS 0x001200a9            /* FILE_GENERIC_READ | FILE_GENERIC_EXECUTE */
#define MODIFY_DC 0x001301ff            /* Modify and delete child */
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

/* A user profile: SYSTEM, Administrators and the user, full and inherited by all */
static const PROFILE_ACE UserAces[] =
{
    {WinLocalSystemSid, FILE_ALL_ACCESS, OI_CI},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OI_CI},
    {WinNullSid, FILE_ALL_ACCESS, OI_CI},
};

/* FUNCTIONS ***************************************************************/

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
        if (pAces[i].SidType == WinNullSid)
        {
            cbSid = GetLengthSid(pUserSid);
        }
        else
        {
            cbSid = sizeof(SidBuffer);
            if (!CreateWellKnownSid(pAces[i].SidType, NULL, SidBuffer, &cbSid))
                return NULL;
        }
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
        if (pAces[i].SidType == WinNullSid)
        {
            pSid = pUserSid;
        }
        else
        {
            cbSid = sizeof(SidBuffer);
            if (!CreateWellKnownSid(pAces[i].SidType, NULL, SidBuffer, &cbSid))
                goto fail;
            pSid = SidBuffer;
        }

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
 * Reset the DACL of everything under a directory to what its parent inherits, top down: the
 * explicit entries of the older installs (Authenticated Users: Modify) go, and so do the copies
 * of them that the files and directories got from their parents. Junctions are left alone:
 * they are links into the same profile and are listed by nobody.
 */
static VOID
ResetInheritance(
    _In_ PCWSTR pszDirectory,
    _In_ PACL pEmptyAcl,
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

        dwError = SetNamedSecurityInfoW(szPath,
                                        SE_FILE_OBJECT,
                                        DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                        NULL, NULL, pEmptyAcl, NULL);
        if (dwError != ERROR_SUCCESS)
            DPRINT1("Failed to secure %S, error: %lu\n", szPath, dwError);

        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            ResetInheritance(szPath, pEmptyAcl, uDepth + 1);
    } while (FindNextFileW(hFind, &FindData));

    FindClose(hFind);
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
    PSECURITY_DESCRIPTOR pSd;
    PACL pAcl = NULL;
    ACL EmptyAcl;
    BOOL bPresent, bDefaulted;
    DWORD dwError;

    if (GetFileAttributesW(pszPath) == INVALID_FILE_ATTRIBUTES ||
        !HasUnprotectedDacl(pszPath))
        return;

    pSd = BuildProfileDescriptor(Kind, pUserSid);
    if (!pSd)
        return;

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
        else if (bRecurse && InitializeAcl(&EmptyAcl, sizeof(EmptyAcl), ACL_REVISION))
        {
            ResetInheritance(pszPath, &EmptyAcl, 0);
        }
    }

    LocalFree(pSd);
}

/* EOF */
