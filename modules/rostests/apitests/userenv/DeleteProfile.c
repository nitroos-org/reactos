/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for DeleteProfileW
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windows.h>
#include <sddl.h>
#include <lm.h>
#include <userenv.h>
#include <strsafe.h>
#include <winioctl.h>
#include <pseh/pseh2.h>

typedef BOOL (WINAPI *PCREATEUSERPROFILEW)(PSID, LPCWSTR);
typedef HRESULT (WINAPI *PCREATEPROFILE)(LPCWSTR, LPCWSTR, LPWSTR, DWORD);

static PCREATEUSERPROFILEW pCreateUserProfileW;
static PCREATEPROFILE pCreateProfile;

/* CreateProfile (Vista+) or the NT 5 CreateUserProfileW (ordinal 110) */
static BOOL
CreateTestProfile(PSID pSid, PCWSTR pszSid, PCWSTR pszUser)
{
    WCHAR szPath[MAX_PATH];

    if (pCreateProfile)
        return SUCCEEDED(pCreateProfile(pszSid, pszUser, szPath, ARRAYSIZE(szPath)));
    return pCreateUserProfileW(pSid, pszUser);
}

static const WCHAR ProfileListKey[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

static BOOL
ProfileKeyExists(PCWSTR pszSid)
{
    WCHAR szKey[MAX_PATH];
    HKEY hKey;

    StringCchPrintfW(szKey, ARRAYSIZE(szKey), L"%s\\%s", ProfileListKey, pszSid);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL
GetProfilePath(PCWSTR pszSid, PWSTR pszPath, DWORD cchPath)
{
    WCHAR szKey[MAX_PATH], szRaw[MAX_PATH];
    DWORD cbRaw = sizeof(szRaw) - sizeof(WCHAR), dwType, cchExpanded;
    LONG lError;
    HKEY hKey;

    StringCchPrintfW(szKey, ARRAYSIZE(szKey), L"%s\\%s", ProfileListKey, pszSid);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    ZeroMemory(szRaw, sizeof(szRaw));
    lError = RegQueryValueExW(hKey, L"ProfileImagePath", NULL, &dwType, (PBYTE)szRaw, &cbRaw);
    RegCloseKey(hKey);
    if (lError != ERROR_SUCCESS || (dwType != REG_SZ && dwType != REG_EXPAND_SZ))
        return FALSE;
    cchExpanded = ExpandEnvironmentStringsW(szRaw, pszPath, cchPath);
    return cchExpanded != 0 && cchExpanded <= cchPath;
}

static BOOL
Exists(PCWSTR pszPath)
{
    return GetFileAttributesW(pszPath) != INVALID_FILE_ATTRIBUTES;
}

typedef struct _MOUNT_POINT_DATA
{
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    WCHAR PathBuffer[2 * MAX_PATH + 8];
} MOUNT_POINT_DATA;

static BOOL
CreateJunction(PCWSTR pszLink, PCWSTR pszTarget)
{
    MOUNT_POINT_DATA Data;
    USHORT cbTarget = (USHORT)(wcslen(pszTarget) * sizeof(WCHAR));
    DWORD dwSize, dwReturned;
    HANDLE hLink;
    BOOL bResult;

    if (cbTarget > MAX_PATH * sizeof(WCHAR) || !CreateDirectoryW(pszLink, NULL))
        return FALSE;

    ZeroMemory(&Data, sizeof(Data));
    Data.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Data.SubstituteNameLength = cbTarget + 4 * sizeof(WCHAR);
    Data.PrintNameOffset = Data.SubstituteNameLength + sizeof(WCHAR);
    Data.PrintNameLength = cbTarget;
    StringCchCopyW(Data.PathBuffer, MAX_PATH + 4, L"\\??\\");
    StringCchCatW(Data.PathBuffer, MAX_PATH + 4, pszTarget);
    StringCchCopyW(&Data.PathBuffer[Data.PrintNameOffset / sizeof(WCHAR)], MAX_PATH + 1, pszTarget);
    dwSize = FIELD_OFFSET(MOUNT_POINT_DATA, PathBuffer) +
             Data.PrintNameOffset + cbTarget + sizeof(WCHAR);
    Data.ReparseDataLength = (USHORT)(dwSize - FIELD_OFFSET(MOUNT_POINT_DATA, SubstituteNameOffset));

    hLink = CreateFileW(pszLink, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hLink == INVALID_HANDLE_VALUE)
    {
        RemoveDirectoryW(pszLink);
        return FALSE;
    }
    bResult = DeviceIoControl(hLink, FSCTL_SET_REPARSE_POINT, &Data, dwSize,
                              NULL, 0, &dwReturned, NULL);
    CloseHandle(hLink);
    if (!bResult)
        RemoveDirectoryW(pszLink);
    return bResult;
}

static BOOL
CreateTestFile(PCWSTR pszPath)
{
    HANDLE hFile = CreateFileW(pszPath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dwWritten;

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    WriteFile(hFile, "test", 4, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL
CallDeleteProfile(PCWSTR pszSid, PCWSTR pszPath, PDWORD pdwError)
{
    BOOL bResult = FALSE;

    *pdwError = 0xdeadbeef;
    _SEH2_TRY
    {
        SetLastError(0xdeadbeef);
        bResult = DeleteProfileW(pszSid, pszPath, NULL);
        *pdwError = GetLastError();
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        ok(FALSE, "DeleteProfileW raised 0x%08lx\n", _SEH2_GetExceptionCode());
        bResult = FALSE;
    }
    _SEH2_END;
    return bResult;
}

/* A profile directory and ProfileList entry made by hand, no hive loaded */
static BOOL
CreateManualProfile(PCWSTR pszSid, PCWSTR pszPath)
{
    WCHAR szKey[MAX_PATH];
    HKEY hKey;
    LONG lError;

    if (!CreateDirectoryW(pszPath, NULL))
        return FALSE;
    StringCchPrintfW(szKey, ARRAYSIZE(szKey), L"%s\\%s", ProfileListKey, pszSid);
    lError = RegCreateKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (lError == ERROR_SUCCESS)
    {
        lError = RegSetValueExW(hKey, L"ProfileImagePath", 0, REG_EXPAND_SZ, (const BYTE *)pszPath,
                                (DWORD)(wcslen(pszPath) + 1) * sizeof(WCHAR));
        RegCloseKey(hKey);
    }
    if (lError != ERROR_SUCCESS)
    {
        RemoveDirectoryW(pszPath);
        SetLastError(lError);
        return FALSE;
    }
    return TRUE;
}

static BOOL
HiveLoaded(PCWSTR pszSid)
{
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_USERS, pszSid, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL
IsNtfs(PCWSTR pszPath)
{
    WCHAR szVolume[MAX_PATH], szFileSystem[MAX_PATH];

    return GetVolumePathNameW(pszPath, szVolume, ARRAYSIZE(szVolume)) &&
           GetVolumeInformationW(szVolume, NULL, 0, NULL, NULL, NULL,
                                 szFileSystem, ARRAYSIZE(szFileSystem)) &&
           !_wcsicmp(szFileSystem, L"NTFS");
}

static WCHAR szSentinel[MAX_PATH], szSentinelFile[MAX_PATH], szRoot[MAX_PATH], szProfiles[MAX_PATH];

static BOOL
EnablePrivilege(PCWSTR pszName, BOOL bEnable)
{
    TOKEN_PRIVILEGES Privileges;
    HANDLE hToken;
    BOOL bResult;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
    bResult = LookupPrivilegeValueW(NULL, pszName, &Privileges.Privileges[0].Luid) &&
              AdjustTokenPrivileges(hToken, FALSE, &Privileges, 0, NULL, NULL) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return bResult;
}

/* Like the legacy profile junctions: Everyone may not list it */
static BOOL
DenyListing(PCWSTR pszLink)
{
    PSECURITY_DESCRIPTOR pSd;
    HANDLE hLink;
    BOOL bResult;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(D;;0x1;;;WD)(A;;FA;;;WD)",
                                                              SDDL_REVISION_1, &pSd, NULL))
        return FALSE;
    hLink = CreateFileW(pszLink, WRITE_DAC | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    bResult = hLink != INVALID_HANDLE_VALUE &&
              SetKernelObjectSecurity(hLink, DACL_SECURITY_INFORMATION, pSd);
    if (hLink != INVALID_HANDLE_VALUE)
        CloseHandle(hLink);
    LocalFree(pSd);
    return bResult;
}

/* Make a profile either with the profile code or (bManual) by hand */
static BOOL
MakeProfile(PSID pSid, PCWSTR pszSid, PCWSTR pszUser, BOOL bManual, PWSTR pszProfile)
{
    if (bManual)
    {
        StringCchPrintfW(pszProfile, MAX_PATH, L"%s\\%s", szProfiles, pszUser);
        return CreateManualProfile(pszSid, pszProfile);
    }
    return CreateTestProfile(pSid, pszSid, pszUser) &&
           GetProfilePath(pszSid, pszProfile, MAX_PATH);
}

/* Files and directories with the attributes that make a plain delete fail or that a walker may skip */
static VOID
CreateAttributeEntries(PCWSTR pszProfile)
{
    static const struct
    {
        PCWSTR pszName;
        DWORD dwAttributes;
    } Files[] =
    {
        { L"readonly.txt", FILE_ATTRIBUTE_READONLY },
        { L"hidden.txt", FILE_ATTRIBUTE_HIDDEN },
        { L"system.txt", FILE_ATTRIBUTE_SYSTEM },
        { L"all.txt", FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM },
    };
    WCHAR szPath[MAX_PATH], szFile[MAX_PATH];
    ULONG i;

    for (i = 0; i < ARRAYSIZE(Files); i++)
    {
        StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\%s", pszProfile, Files[i].pszName);
        ok(CreateTestFile(szPath), "Cannot create %S: %lu\n", szPath, GetLastError());
        ok(SetFileAttributesW(szPath, Files[i].dwAttributes),
           "Cannot set the attributes of %S: %lu\n", szPath, GetLastError());
    }

    /* Directories with such attributes, some holding files with such attributes */
    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\RoDir", pszProfile);
    ok(CreateDirectoryW(szPath, NULL), "Cannot create %S: %lu\n", szPath, GetLastError());
    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%s\\inner.txt", szPath);
    ok(CreateTestFile(szFile), "Cannot create %S: %lu\n", szFile, GetLastError());
    ok(SetFileAttributesW(szFile, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM),
       "Cannot set the attributes of %S: %lu\n", szFile, GetLastError());
    ok(SetFileAttributesW(szPath, FILE_ATTRIBUTE_READONLY), "Cannot set the attributes of %S: %lu\n", szPath, GetLastError());

    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\HiddenDir", pszProfile);
    ok(CreateDirectoryW(szPath, NULL), "Cannot create %S: %lu\n", szPath, GetLastError());
    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%s\\inner.txt", szPath);
    ok(CreateTestFile(szFile), "Cannot create %S: %lu\n", szFile, GetLastError());
    ok(SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN), "Cannot set the attributes of %S: %lu\n", szPath, GetLastError());

    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\SysDir", pszProfile);
    ok(CreateDirectoryW(szPath, NULL), "Cannot create %S: %lu\n", szPath, GetLastError());
    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%s\\inner.txt", szPath);
    ok(CreateTestFile(szFile), "Cannot create %S: %lu\n", szFile, GetLastError());
    ok(SetFileAttributesW(szPath, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN),
       "Cannot set the attributes of %S: %lu\n", szPath, GetLastError());
}

static VOID
TestDeleteProfile(PSID pSid, PCWSTR pszSid, PCWSTR pszUser, BOOL bManual)
{
    WCHAR szProfile[MAX_PATH], szPath[MAX_PATH];
    HANDLE hLink;
    DWORD dwError;
    ULONG i;
    BOOL bResult, bJunction;

    /* Delete with the path from the registry; a junction inside points to the sentinel */
    if (!MakeProfile(pSid, pszSid, pszUser, bManual, szProfile))
    {
        ok(FALSE, "Cannot create the profile of %S: %lu\n", pszSid, GetLastError());
        return;
    }
    ok(Exists(szProfile), "Profile %S does not exist\n", szProfile);
    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\Sub", szProfile);
    ok(CreateDirectoryW(szPath, NULL), "Cannot create %S: %lu\n", szPath, GetLastError());
    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\Sub\\file.txt", szProfile);
    ok(CreateTestFile(szPath), "Cannot create %S: %lu\n", szPath, GetLastError());
    /* More entries than one directory query returns */
    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\Many", szProfile);
    ok(CreateDirectoryW(szPath, NULL), "Cannot create %S: %lu\n", szPath, GetLastError());
    for (i = 0; i < 400; i++)
    {
        StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\Many\\file-number-%04lu.txt", szProfile, i);
        if (!CreateTestFile(szPath))
            break;
    }
    ok(i == 400, "Cannot create %S: %lu\n", szPath, GetLastError());
    CreateAttributeEntries(szProfile);

    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\Link", szProfile);
    bJunction = CreateJunction(szPath, szSentinel);
    if (IsNtfs(szProfile))
        ok(bJunction, "Cannot create the junction %S: %lu\n", szPath, GetLastError());
    else if (!bJunction)
        skip("No junctions on this file system, no reparse point test\n");
    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\Legacy", szProfile);
    if (bJunction)
    {
        ok(CreateJunction(szPath, szSentinel), "Cannot create the junction %S: %lu\n", szPath, GetLastError());
        ok(DenyListing(szPath), "Cannot deny listing %S: %lu\n", szPath, GetLastError());
        hLink = CreateFileW(szPath, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        ok(hLink == INVALID_HANDLE_VALUE, "Listing %S is not denied\n", szPath);
        if (hLink != INVALID_HANDLE_VALUE)
            CloseHandle(hLink);
    }

    bResult = CallDeleteProfile(pszSid, NULL, &dwError);
    ok(bResult, "DeleteProfileW(%S, NULL) failed: %lu\n", pszSid, dwError);
    ok(!Exists(szProfile), "Profile %S still exists\n", szProfile);
    ok(!ProfileKeyExists(pszSid), "Profile list entry %S still exists\n", pszSid);
    ok(Exists(szSentinel), "Junction target %S was deleted\n", szSentinel);
    ok(Exists(szSentinelFile), "File %S behind the junction was deleted\n", szSentinelFile);

    /* Delete with an explicit path */
    if (!MakeProfile(pSid, pszSid, pszUser, bManual, szProfile))
    {
        ok(FALSE, "Cannot create the profile of %S: %lu\n", pszSid, GetLastError());
        return;
    }
    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\file.txt", szProfile);
    ok(CreateTestFile(szPath), "Cannot create %S: %lu\n", szPath, GetLastError());
    CreateAttributeEntries(szProfile);
    bResult = CallDeleteProfile(pszSid, szProfile, &dwError);
    ok(bResult, "DeleteProfileW(%S, %S) failed: %lu\n", pszSid, szProfile, dwError);
    ok(!Exists(szProfile), "Profile %S still exists\n", szProfile);
    ok(!ProfileKeyExists(pszSid), "Profile list entry %S still exists\n", pszSid);

    /* The profile is gone now */
    bResult = CallDeleteProfile(pszSid, NULL, &dwError);
    ok(!bResult, "DeleteProfileW of a deleted profile succeeded\n");
    ok(dwError == ERROR_FILE_NOT_FOUND, "Wrong error %lu\n", dwError);
}

/* A profile whose hive is loaded (its user is logged on) is not deleted, not even in part */
static VOID
TestProfileInUse(PCWSTR pszSid, PCWSTR pszProfile, BOOL bLoad)
{
    WCHAR szPath[MAX_PATH], szMarker[MAX_PATH];
    DWORD dwError;
    LONG lError;
    BOOL bResult;

    if (bLoad)
    {
        ok(EnablePrivilege(L"SeRestorePrivilege", TRUE) && EnablePrivilege(L"SeBackupPrivilege", TRUE),
           "Cannot enable the privileges to load a hive\n");
        StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\NTUSER.DAT", pszProfile);
        lError = RegLoadKeyW(HKEY_USERS, pszSid, szPath);
        ok(lError == ERROR_SUCCESS, "RegLoadKeyW(%S) failed: %ld\n", szPath, lError);
        if (lError != ERROR_SUCCESS)
        {
            EnablePrivilege(L"SeRestorePrivilege", FALSE);
            EnablePrivilege(L"SeBackupPrivilege", FALSE);
            return;
        }
    }

    /* Sorts before everything else in the profile */
    StringCchPrintfW(szMarker, ARRAYSIZE(szMarker), L"%s\\0marker.txt", pszProfile);
    ok(CreateTestFile(szMarker), "Cannot create %S: %lu\n", szMarker, GetLastError());

    bResult = CallDeleteProfile(pszSid, NULL, &dwError);
    ok(!bResult, "DeleteProfileW of a loaded profile succeeded\n");
    /* Windows Server 2008 R2 fails with ERROR_INVALID_PARAMETER, Windows 10 with ERROR_SHARING_VIOLATION */
    ok(dwError == ERROR_INVALID_PARAMETER || dwError == ERROR_SHARING_VIOLATION,
       "Wrong error %lu\n", dwError);
    ok(Exists(pszProfile), "Profile %S was deleted\n", pszProfile);
    ok(Exists(szMarker), "File %S of a loaded profile was deleted\n", szMarker);
    ok(ProfileKeyExists(pszSid), "Profile list entry %S was deleted\n", pszSid);
    DeleteFileW(szMarker);

    if (bLoad)
    {
        lError = RegUnLoadKeyW(HKEY_USERS, pszSid);
        ok(lError == ERROR_SUCCESS, "RegUnLoadKeyW(%S) failed: %ld\n", pszSid, lError);
        /* Without them the deletion must cope with the junction that denies listing */
        EnablePrivilege(L"SeRestorePrivilege", FALSE);
        EnablePrivilege(L"SeBackupPrivilege", FALSE);
    }
}

static VOID
CleanupProfile(PCWSTR pszSid)
{
    /* Best effort after a failure: do not leave our profile behind */
    if (HiveLoaded(pszSid))
        trace("The hive of %S is loaded, its profile is left behind\n", pszSid);
    else if (ProfileKeyExists(pszSid))
    {
        _SEH2_TRY
        {
            DeleteProfileW(pszSid, NULL, NULL);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
        }
        _SEH2_END;
    }
}

START_TEST(DeleteProfile)
{
    HMODULE hUserenv = GetModuleHandleW(L"userenv.dll");
    USER_INFO_1 UserInfo = {0};
    BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
    PSID pSid = (PSID)SidBuffer;
    WCHAR szUser[21], szManualUser[22], szPassword[32], szRealProfile[MAX_PATH], szDomain[MAX_PATH], szManualSid[MAX_PATH];
    DWORD cbSid = sizeof(SidBuffer), cchDomain = ARRAYSIZE(szDomain), cchProfiles;
    SID_NAME_USE Use;
    PWSTR pszSid = NULL;
    NET_API_STATUS Status;
    BOOL bHive, bSentinelFile = FALSE;

    /* Parameter check */
    SetLastError(0xdeadbeef);
    ok(!DeleteProfileW(NULL, NULL, NULL), "DeleteProfileW(NULL) succeeded\n");
    ok_err(ERROR_INVALID_PARAMETER);

    pCreateProfile = (PCREATEPROFILE)GetProcAddress(hUserenv, "CreateProfile");
    if (!pCreateProfile)
        pCreateUserProfileW = (PCREATEUSERPROFILEW)GetProcAddress(hUserenv, MAKEINTRESOURCEA(110));
    if (!pCreateProfile && !pCreateUserProfileW)
    {
        skip("No function to create a profile\n");
        return;
    }

    /* A new user of our own, never an existing one */
    StringCchPrintfW(szUser, ARRAYSIZE(szUser), L"DelProf%06lx",
                     (GetTickCount() ^ (GetCurrentProcessId() << 8)) & 0xffffff);
    /* Disabled, with a password of this run only: nobody can log on with it */
    StringCchPrintfW(szPassword, ARRAYSIZE(szPassword), L"Dp#%08lx%08lx",
                     GetTickCount(), GetCurrentThreadId() * 2654435761UL);
    UserInfo.usri1_name = szUser;
    UserInfo.usri1_password = szPassword;
    UserInfo.usri1_priv = USER_PRIV_USER;
    UserInfo.usri1_flags = UF_SCRIPT | UF_ACCOUNTDISABLE | UF_DONT_EXPIRE_PASSWD;
    Status = NetUserAdd(NULL, 1, (LPBYTE)&UserInfo, NULL);
    if (Status != NERR_Success)
    {
        skip("NetUserAdd(%S) failed: %lu (not an administrator?)\n", szUser, Status);
        return;
    }

    if (!LookupAccountNameW(NULL, szUser, pSid, &cbSid, szDomain, &cchDomain, &Use) ||
        !ConvertSidToStringSidW(pSid, &pszSid))
    {
        ok(FALSE, "Cannot get the SID of the test user: %lu\n", GetLastError());
        goto Cleanup;
    }

    /* Sentinel outside of the profile, reached by a junction inside of it */
    GetWindowsDirectoryW(szRoot, ARRAYSIZE(szRoot));
    szRoot[3] = UNICODE_NULL;
    StringCchPrintfW(szSentinel, ARRAYSIZE(szSentinel), L"%s%s-Sentinel", szRoot, szUser);
    StringCchPrintfW(szSentinelFile, ARRAYSIZE(szSentinelFile), L"%s\\keep.txt", szSentinel);
    if (!CreateDirectoryW(szSentinel, NULL))
    {
        ok(FALSE, "Cannot create %S: %lu\n", szSentinel, GetLastError());
        szSentinel[0] = UNICODE_NULL;
        goto Cleanup;
    }
    bSentinelFile = CreateTestFile(szSentinelFile);
    ok(bSentinelFile, "Cannot create %S: %lu\n", szSentinelFile, GetLastError());

    cchProfiles = ARRAYSIZE(szProfiles);
    ok(GetProfilesDirectoryW(szProfiles, &cchProfiles), "GetProfilesDirectoryW failed: %lu\n", GetLastError());

    /* A profile made by the profile code must leave its hive unloaded */
    ok(CreateTestProfile(pSid, pszSid, szUser), "Cannot create the profile: %lu\n", GetLastError());
    ok(ProfileKeyExists(pszSid), "No profile list entry for %S\n", pszSid);
    bHive = HiveLoaded(pszSid);
    /* RegUnLoadKeyW() used to fail with ERROR_ACCESS_DENIED here and the row was a todo; it unloads the new hive now */
    ok(!bHive, "The hive of %S is still loaded\n", pszSid);
    if (GetProfilePath(pszSid, szRealProfile, ARRAYSIZE(szRealProfile)))
        TestProfileInUse(pszSid, szRealProfile, !bHive);
    else
        ok(FALSE, "No profile path for %S\n", pszSid);
    bHive = HiveLoaded(pszSid);
    if (!bHive)
    {
        CleanupProfile(pszSid);
        TestDeleteProfile(pSid, pszSid, szUser, FALSE);
    }
    else
    {
        /* Test on profiles made by hand instead, for a SID that has none */
        skip("The hive of the new profile is loaded, using profiles made by hand\n");
        StringCchPrintfW(szManualSid, ARRAYSIZE(szManualSid), L"%s-4242", pszSid);
        StringCchPrintfW(szManualUser, ARRAYSIZE(szManualUser), L"%sM", szUser);
        TestDeleteProfile(NULL, szManualSid, szManualUser, TRUE);
        CleanupProfile(szManualSid);
    }

Cleanup:
    if (pszSid)
        CleanupProfile(pszSid);
    if (szSentinel[0])
    {
        if (bSentinelFile)
            DeleteFileW(szSentinelFile);
        RemoveDirectoryW(szSentinel);
    }
    if (pszSid)
        LocalFree(pszSid);
    NetUserDel(NULL, szUser);
}
