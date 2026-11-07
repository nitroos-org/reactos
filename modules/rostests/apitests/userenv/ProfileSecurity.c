/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the DACLs of the profile directories and for the profile of a new user
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windows.h>
#include <sddl.h>
#include <lm.h>
#include <userenv.h>
#include <strsafe.h>

#define TEST_PASSWORD L"Nt3st-Pass-9!"

/* The allowed access of a SID in the DACL of a path, summed over its ACEs; -1: the DACL could not be read */
typedef struct _DACLINFO
{
    BOOL Protected;
    int AceCount;
    int InheritedAces;
    DWORD AccessSystem, AccessAdmins, AccessUser, AccessUsers, AccessAuth, AccessEveryone, AccessOther;
} DACLINFO;

static BOOL
GetDaclInfo(PCWSTR pszPath, PSID pUserSid, DACLINFO *pInfo)
{
    SECURITY_DESCRIPTOR_CONTROL Control;
    PSECURITY_DESCRIPTOR pSd;
    PACL pAcl;
    BOOL bPresent, bDefaulted;
    DWORD dwSize = 0, dwRev, i;
    PSID pSystem = NULL, pAdmins = NULL, pUsers = NULL, pAuth = NULL, pWorld = NULL;
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY}, World = {SECURITY_WORLD_SID_AUTHORITY};
    BOOL bResult = FALSE;

    ZeroMemory(pInfo, sizeof(*pInfo));
    GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize);
    if (!dwSize)
        return FALSE;
    pSd = LocalAlloc(LMEM_FIXED, dwSize);
    if (!pSd || !GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, pSd, dwSize, &dwSize) ||
        !GetSecurityDescriptorDacl(pSd, &bPresent, &pAcl, &bDefaulted) ||
        !GetSecurityDescriptorControl(pSd, &Control, &dwRev) || !bPresent || !pAcl)
        goto done;

    AllocateAndInitializeSid(&Nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystem);
    AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdmins);
    AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &pUsers);
    AllocateAndInitializeSid(&Nt, 1, SECURITY_AUTHENTICATED_USER_RID, 0, 0, 0, 0, 0, 0, 0, &pAuth);
    AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pWorld);

    pInfo->Protected = !!(Control & SE_DACL_PROTECTED);
    pInfo->AceCount = pAcl->AceCount;
    for (i = 0; i < pAcl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE pAce;
        PSID pSid;
        DWORD *pAccess;

        if (!GetAce(pAcl, i, (PVOID *)&pAce) || pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;
        /* Inherit-only entries do not apply to the object itself */
        if (pAce->Header.AceFlags & INHERIT_ONLY_ACE)
            continue;
        if (pAce->Header.AceFlags & INHERITED_ACE)
            pInfo->InheritedAces++;
        pSid = (PSID)&pAce->SidStart;
        if (EqualSid(pSid, pSystem)) pAccess = &pInfo->AccessSystem;
        else if (EqualSid(pSid, pAdmins)) pAccess = &pInfo->AccessAdmins;
        else if (pUserSid && EqualSid(pSid, pUserSid)) pAccess = &pInfo->AccessUser;
        else if (EqualSid(pSid, pUsers)) pAccess = &pInfo->AccessUsers;
        else if (EqualSid(pSid, pAuth)) pAccess = &pInfo->AccessAuth;
        else if (EqualSid(pSid, pWorld)) pAccess = &pInfo->AccessEveryone;
        else pAccess = &pInfo->AccessOther;
        *pAccess |= pAce->Mask;
    }
    bResult = TRUE;

done:
    if (pSystem) FreeSid(pSystem);
    if (pAdmins) FreeSid(pAdmins);
    if (pUsers) FreeSid(pUsers);
    if (pAuth) FreeSid(pAuth);
    if (pWorld) FreeSid(pWorld);
    if (pSd) LocalFree(pSd);
    return bResult;
}

#define WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER)

static void
CheckSharedDirectory(PCWSTR pszName, PCWSTR pszPath, BOOL bPublic)
{
    DACLINFO Info;
    BOOL bRead = GetDaclInfo(pszPath, NULL, &Info);

    ok(bRead, "%ls: cannot read the DACL of %ls (error %lu)\n", pszName, pszPath, GetLastError());
    if (!bRead)
        return;

    ok(Info.Protected, "%ls: the DACL is not protected\n", pszName);
    ok((Info.AccessSystem & FILE_ALL_ACCESS) == FILE_ALL_ACCESS, "%ls: SYSTEM has 0x%08lx\n", pszName, Info.AccessSystem);
    ok((Info.AccessAdmins & FILE_ALL_ACCESS) == FILE_ALL_ACCESS, "%ls: Administrators have 0x%08lx\n", pszName, Info.AccessAdmins);
    ok(Info.AccessAuth == 0, "%ls: Authenticated Users have 0x%08lx\n", pszName, Info.AccessAuth);
    if (!bPublic)
    {
        ok((Info.AccessUsers & WRITE_RIGHTS) == 0 && (Info.AccessUsers & FILE_GENERIC_READ) == FILE_GENERIC_READ,
           "%ls: Users have 0x%08lx\n", pszName, Info.AccessUsers);
        ok((Info.AccessEveryone & WRITE_RIGHTS) == 0 && (Info.AccessEveryone & FILE_GENERIC_READ) == FILE_GENERIC_READ,
           "%ls: Everyone has 0x%08lx\n", pszName, Info.AccessEveryone);
    }
    else
    {
        ok(Info.AccessUsers == 0 && Info.AccessEveryone == 0,
           "%ls: Users 0x%08lx, Everyone 0x%08lx\n", pszName, Info.AccessUsers, Info.AccessEveryone);
    }
}

static BOOL
AddUser(PCWSTR pszUser)
{
    USER_INFO_1 Info;
    DWORD dwParm;

    ZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = (PWSTR)pszUser;
    Info.usri1_password = (PWSTR)TEST_PASSWORD;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    return NetUserAdd(NULL, 1, (PBYTE)&Info, &dwParm) == NERR_Success;
}

typedef struct _TESTUSER
{
    WCHAR szName[32];
    HANDLE hToken;
    PROFILEINFOW Profile;
    PSID pSid;
    PWSTR pszSid;
    WCHAR szPath[MAX_PATH];
    BOOL bAdded, bLoaded;
} TESTUSER;

static BOOL
SetupUser(TESTUSER *pUser, PCWSTR pszName)
{
    DWORD cb = 0;
    PTOKEN_USER pTu;

    ZeroMemory(pUser, sizeof(*pUser));
    StringCchCopyW(pUser->szName, ARRAYSIZE(pUser->szName), pszName);
    NetUserDel(NULL, pszName);
    pUser->bAdded = AddUser(pszName);
    if (!pUser->bAdded)
        return FALSE;
    if (!LogonUserW(pUser->szName, (PWSTR)L".", (PWSTR)TEST_PASSWORD, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &pUser->hToken))
        return FALSE;
    GetTokenInformation(pUser->hToken, TokenUser, NULL, 0, &cb);
    pTu = LocalAlloc(LMEM_FIXED, cb);
    if (!pTu || !GetTokenInformation(pUser->hToken, TokenUser, pTu, cb, &cb))
        return FALSE;
    cb = GetLengthSid(pTu->User.Sid);
    pUser->pSid = LocalAlloc(LMEM_FIXED, cb);
    CopySid(cb, pUser->pSid, pTu->User.Sid);
    LocalFree(pTu);
    ConvertSidToStringSidW(pUser->pSid, &pUser->pszSid);

    pUser->Profile.dwSize = sizeof(pUser->Profile);
    pUser->Profile.dwFlags = PI_NOUI;
    pUser->Profile.lpUserName = pUser->szName;
    pUser->bLoaded = LoadUserProfileW(pUser->hToken, &pUser->Profile);
    if (!pUser->bLoaded)
        return FALSE;
    cb = ARRAYSIZE(pUser->szPath);
    return GetUserProfileDirectoryW(pUser->hToken, pUser->szPath, &cb);
}

static void
CleanupUser(TESTUSER *pUser)
{
    if (pUser->bLoaded)
        UnloadUserProfile(pUser->hToken, pUser->Profile.hProfile);
    if (pUser->hToken)
        CloseHandle(pUser->hToken);
    if (pUser->pszSid)
    {
        DeleteProfileW(pUser->pszSid, NULL, NULL);
        LocalFree(pUser->pszSid);
    }
    if (pUser->pSid)
        LocalFree(pUser->pSid);
    if (pUser->bAdded)
        NetUserDel(NULL, pUser->szName);
}

/* The error of creating (and deleting) a file in a directory as the user of the token; 0 for success */
static DWORD
CreateFileAs(HANDLE hToken, PCWSTR pszDirectory)
{
    WCHAR szFile[MAX_PATH];
    HANDLE hFile;
    DWORD dwError;

    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%s\\profsec-test.txt", pszDirectory);
    if (!ImpersonateLoggedOnUser(hToken))
        return 0xdeadbeef;
    hFile = CreateFileW(szFile, GENERIC_WRITE | DELETE, 0, NULL, CREATE_NEW, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    dwError = (hFile == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    RevertToSelf();
    return dwError;
}

static void
CheckUserProfile(TESTUSER *pUser, TESTUSER *pOther)
{
    WCHAR szSub[MAX_PATH], szProfiles[MAX_PATH], szExpected[MAX_PATH];
    DWORD cch = ARRAYSIZE(szProfiles), dwError;
    DACLINFO Info;
    BOOL bRead;

    ok(GetProfilesDirectoryW(szProfiles, &cch), "GetProfilesDirectory failed %lu\n", GetLastError());
    StringCchPrintfW(szExpected, ARRAYSIZE(szExpected), L"%s\\%s", szProfiles, pUser->szName);
    ok(!_wcsicmp(pUser->szPath, szExpected), "profile of %ls is %ls, expected %ls\n", pUser->szName, pUser->szPath, szExpected);
    ok(GetFileAttributesW(pUser->szPath) != INVALID_FILE_ATTRIBUTES, "%ls does not exist\n", pUser->szPath);

    bRead = GetDaclInfo(pUser->szPath, pUser->pSid, &Info);
    ok(bRead, "cannot read the DACL of %ls (error %lu)\n", pUser->szPath, GetLastError());
    if (bRead)
    {
        ok(Info.Protected, "%ls: the DACL is not protected\n", pUser->szPath);
        ok(Info.AceCount == 3, "%ls: %d ACEs, expected 3\n", pUser->szPath, Info.AceCount);
        ok((Info.AccessSystem & FILE_ALL_ACCESS) == FILE_ALL_ACCESS, "SYSTEM has 0x%08lx\n", Info.AccessSystem);
        ok((Info.AccessAdmins & FILE_ALL_ACCESS) == FILE_ALL_ACCESS, "Administrators have 0x%08lx\n", Info.AccessAdmins);
        ok((Info.AccessUser & FILE_ALL_ACCESS) == FILE_ALL_ACCESS, "the user has 0x%08lx\n", Info.AccessUser);
        ok(Info.AccessUsers == 0 && Info.AccessAuth == 0 && Info.AccessEveryone == 0 && Info.AccessOther == 0,
           "others: Users 0x%08lx, Authenticated 0x%08lx, Everyone 0x%08lx, other 0x%08lx\n",
           Info.AccessUsers, Info.AccessAuth, Info.AccessEveryone, Info.AccessOther);
    }

    /* What the profile was copied from carries the DACL of the profile, not the one of Default */
    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\NTUSER.DAT", pUser->szPath);
    bRead = GetDaclInfo(szSub, pUser->pSid, &Info);
    ok(bRead, "cannot read the DACL of %ls (error %lu)\n", szSub, GetLastError());
    if (bRead)
        ok(Info.AccessUsers == 0 && Info.AccessAuth == 0 && Info.AccessEveryone == 0,
           "NTUSER.DAT: Users 0x%08lx, Authenticated 0x%08lx, Everyone 0x%08lx\n",
           Info.AccessUsers, Info.AccessAuth, Info.AccessEveryone);
    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\AppData", pUser->szPath);
    bRead = GetDaclInfo(szSub, pUser->pSid, &Info);
    ok(bRead, "cannot read the DACL of %ls (error %lu)\n", szSub, GetLastError());
    if (bRead)
        ok(Info.AccessUsers == 0 && Info.AccessAuth == 0 && Info.AccessEveryone == 0 && (Info.AccessUser & FILE_ALL_ACCESS) == FILE_ALL_ACCESS,
           "AppData: Users 0x%08lx, Authenticated 0x%08lx, Everyone 0x%08lx, user 0x%08lx\n",
           Info.AccessUsers, Info.AccessAuth, Info.AccessEveryone, Info.AccessUser);

    dwError = CreateFileAs(pUser->hToken, pUser->szPath);
    ok(dwError == 0, "the user cannot create a file in the own profile (error %lu)\n", dwError);
    dwError = CreateFileAs(pUser->hToken, szSub);
    ok(dwError == 0, "the user cannot create a file in the own AppData (error %lu)\n", dwError);

    if (pOther && pOther->szPath[0])
    {
        dwError = CreateFileAs(pUser->hToken, pOther->szPath);
        ok(dwError == ERROR_ACCESS_DENIED, "creating a file in the profile of %ls as %ls: error %lu, expected %u\n",
           pOther->szName, pUser->szName, dwError, ERROR_ACCESS_DENIED);
        StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\AppData", pOther->szPath);
        dwError = CreateFileAs(pUser->hToken, szSub);
        ok(dwError == ERROR_ACCESS_DENIED, "creating a file in %ls as %ls: error %lu, expected %u\n",
           szSub, pUser->szName, dwError, ERROR_ACCESS_DENIED);
    }
}

START_TEST(ProfileSecurity)
{
    WCHAR szPath[MAX_PATH], szRaw[MAX_PATH];
    TESTUSER User1, User2;
    DWORD cch, cb;
    HKEY hKey;

    cch = ARRAYSIZE(szPath);
    if (GetProfilesDirectoryW(szPath, &cch))
        CheckSharedDirectory(L"profiles directory", szPath, FALSE);
    cch = ARRAYSIZE(szPath);
    if (GetDefaultUserProfileDirectoryW(szPath, &cch))
        CheckSharedDirectory(L"Default", szPath, FALSE);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                      0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        cb = sizeof(szRaw);
        if (RegQueryValueExW(hKey, L"Public", NULL, NULL, (PBYTE)szRaw, &cb) == ERROR_SUCCESS &&
            ExpandEnvironmentStringsW(szRaw, szPath, ARRAYSIZE(szPath)))
            CheckSharedDirectory(L"Public", szPath, TRUE);
        RegCloseKey(hKey);
    }

    if (!SetupUser(&User1, L"pfsec1") || !SetupUser(&User2, L"pfsec2"))
    {
        skip("Cannot create and log on the test users (error %lu)\n", GetLastError());
    }
    else
    {
        CheckUserProfile(&User1, &User2);
        CheckUserProfile(&User2, &User1);
    }

    CleanupUser(&User2);
    CleanupUser(&User1);
}
