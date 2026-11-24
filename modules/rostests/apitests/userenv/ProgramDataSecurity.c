/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the DACL of C:\ProgramData and what a standard user can do in it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <lm.h>
#include <userenv.h>
#include <strsafe.h>

#define TEST_PASSWORD L"Nt3st-Pass-9!"

typedef struct _EXPECTED_ACE
{
    WELL_KNOWN_SID_TYPE Sid;
    BYTE Flags;
    DWORD Mask;
} EXPECTED_ACE;

/* icacls of ProgramData on Windows 10 22H2 (read-only probe): the ACEs, in this order */
static const EXPECTED_ACE s_Expected[] =
{
    { WinLocalSystemSid, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS },
    { WinBuiltinAdministratorsSid, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS },
    { WinCreatorOwnerSid, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE, FILE_ALL_ACCESS },
    { WinBuiltinUsersSid, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE },
    { WinBuiltinUsersSid, CONTAINER_INHERIT_ACE, FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES },
};

#define OI_CI (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
#define OI_CI_IO (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE)
#define RX_MASK (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)
#define AAP L"S-1-15-2-1"
#define ARAP L"S-1-15-2-2"

/* An expected entry: a well-known SID or, when pszSid is set, a SID in the S-1-... form */
typedef struct _EXPECTED_ACE_EX
{
    WELL_KNOWN_SID_TYPE Sid;
    PCWSTR pszSid;
    BYTE Flags;
    DWORD Mask;
} EXPECTED_ACE_EX;

/* icacls of C:\Windows on Windows 10 22H2 (read-only probe); SYSTEM and Administrators have full control on the folder
 * itself here, there Modify, and TrustedInstaller is not here */
static const EXPECTED_ACE_EX s_ExpectedWindows[] =
{
    { WinLocalSystemSid, NULL, OI_CI, FILE_ALL_ACCESS },
    { WinBuiltinAdministratorsSid, NULL, OI_CI, FILE_ALL_ACCESS },
    { WinBuiltinUsersSid, NULL, 0, RX_MASK },
    { WinBuiltinUsersSid, NULL, OI_CI_IO, GENERIC_READ | GENERIC_EXECUTE },
    { WinCreatorOwnerSid, NULL, OI_CI_IO, FILE_ALL_ACCESS },
    { WinNullSid, AAP, 0, RX_MASK },
    { WinNullSid, AAP, OI_CI_IO, GENERIC_READ | GENERIC_EXECUTE },
    { WinNullSid, ARAP, 0, RX_MASK },
    { WinNullSid, ARAP, OI_CI_IO, GENERIC_READ | GENERIC_EXECUTE },
};

/* icacls of C:\Windows\System32\config on Windows 10 22H2, without TrustedInstaller */
static const EXPECTED_ACE_EX s_ExpectedConfig[] =
{
    { WinLocalSystemSid, NULL, OI_CI, FILE_ALL_ACCESS },
    { WinBuiltinAdministratorsSid, NULL, OI_CI, FILE_ALL_ACCESS },
    { WinCreatorOwnerSid, NULL, OI_CI_IO, FILE_ALL_ACCESS },
};

/* The security descriptor (LocalFree) of the object itself: a junction is not followed */
static PSECURITY_DESCRIPTOR
GetObjectDacl(PCWSTR pszPath, PACL *ppAcl)
{
    PSECURITY_DESCRIPTOR pSd = NULL;
    HANDLE hFile;
    DWORD dwError;

    *ppAcl = NULL;
    hFile = CreateFileW(pszPath, READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "cannot open %ls (error %lu)\n", pszPath, GetLastError());
    if (hFile == INVALID_HANDLE_VALUE)
        return NULL;
    dwError = GetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, ppAcl, NULL, &pSd);
    ok(dwError == ERROR_SUCCESS, "no security for %ls (error %lu)\n", pszPath, dwError);
    CloseHandle(hFile);
    return dwError == ERROR_SUCCESS ? pSd : NULL;
}

static void
CheckDaclEx(PCWSTR pszPath, const EXPECTED_ACE_EX *pExpected, UINT cExpected)
{
    SECURITY_DESCRIPTOR_CONTROL Control;
    PSECURITY_DESCRIPTOR pSd;
    PACL pAcl = NULL;
    DWORD dwRev, i;

    pSd = GetObjectDacl(pszPath, &pAcl);
    if (!pSd)
        return;
    ok(GetSecurityDescriptorControl(pSd, &Control, &dwRev), "no control\n");
    ok(pAcl != NULL, "%ls: no DACL\n", pszPath);
    ok(!!(Control & SE_DACL_PROTECTED), "%ls: the DACL is not protected (0x%x)\n", pszPath, Control);

    if (pAcl)
    {
        ok(pAcl->AceCount == cExpected, "%ls: %u ACEs, expected %u\n", pszPath, pAcl->AceCount, cExpected);
        for (i = 0; i < pAcl->AceCount && i < cExpected; i++)
        {
            PACCESS_ALLOWED_ACE pAce = NULL;
            BYTE Buf[SECURITY_MAX_SID_SIZE];
            DWORD cb = sizeof(Buf);
            PSID pSid = NULL;

            ok(GetAce(pAcl, i, (PVOID *)&pAce) && pAce, "no ACE %lu\n", i);
            if (!pAce)
                continue;
            if (pExpected[i].pszSid)
                ok(ConvertStringSidToSidW(pExpected[i].pszSid, &pSid), "no SID for ACE %lu\n", i);
            else
                ok(CreateWellKnownSid(pExpected[i].Sid, NULL, Buf, &cb), "no SID for ACE %lu\n", i);
            ok(pAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "%ls ACE %lu: type %u\n", pszPath, i, pAce->Header.AceType);
            ok(pAce->Header.AceFlags == pExpected[i].Flags, "%ls ACE %lu: flags 0x%x, expected 0x%x\n", pszPath, i, pAce->Header.AceFlags, pExpected[i].Flags);
            ok(pAce->Mask == pExpected[i].Mask, "%ls ACE %lu: mask 0x%08lx, expected 0x%08lx\n", pszPath, i, pAce->Mask, pExpected[i].Mask);
            ok(EqualSid((PSID)&pAce->SidStart, pSid ? pSid : Buf), "%ls ACE %lu: wrong SID\n", pszPath, i);
            if (pSid)
                LocalFree(pSid);
        }
    }
    LocalFree(pSd);
}

static void
CheckDacl(PCWSTR pszPath)
{
    EXPECTED_ACE_EX Expected[ARRAYSIZE(s_Expected)];
    UINT i;

    for (i = 0; i < ARRAYSIZE(s_Expected); i++)
    {
        Expected[i].Sid = s_Expected[i].Sid;
        Expected[i].pszSid = NULL;
        Expected[i].Flags = s_Expected[i].Flags;
        Expected[i].Mask = s_Expected[i].Mask;
    }
    CheckDaclEx(pszPath, Expected, ARRAYSIZE(Expected));
}

typedef struct _TESTUSER
{
    WCHAR szName[32];
    HANDLE hToken;
    BOOL bAdded;
} TESTUSER;

static BOOL
SetupUser(TESTUSER *pUser, PCWSTR pszName)
{
    USER_INFO_1 Info;
    DWORD dwParm;

    ZeroMemory(pUser, sizeof(*pUser));
    StringCchCopyW(pUser->szName, ARRAYSIZE(pUser->szName), pszName);
    NetUserDel(NULL, pszName);
    ZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = (PWSTR)pszName;
    Info.usri1_password = (PWSTR)TEST_PASSWORD;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    pUser->bAdded = NetUserAdd(NULL, 1, (PBYTE)&Info, &dwParm) == NERR_Success;
    if (!pUser->bAdded)
        return FALSE;
    return LogonUserW(pUser->szName, (PWSTR)L".", (PWSTR)TEST_PASSWORD, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &pUser->hToken);
}

static void
CleanupUser(TESTUSER *pUser)
{
    if (pUser->hToken)
        CloseHandle(pUser->hToken);
    if (pUser->bAdded)
        NetUserDel(NULL, pUser->szName);
}

/* Create a file (bDirectory FALSE) or a directory as the user: the error, 0 for success. Files are deleted again. */
static DWORD
CreateAs(HANDLE hToken, PCWSTR pszDirectory, PCWSTR pszName, BOOL bDirectory)
{
    WCHAR szPath[MAX_PATH];
    HANDLE hFile;
    DWORD dwError;

    StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\%s", pszDirectory, pszName);
    if (!ImpersonateLoggedOnUser(hToken))
        return 0xdeadbeef;
    if (bDirectory)
    {
        dwError = CreateDirectoryW(szPath, NULL) ? 0 : GetLastError();
    }
    else
    {
        hFile = CreateFileW(szPath, GENERIC_WRITE | DELETE, 0, NULL, CREATE_NEW, FILE_FLAG_DELETE_ON_CLOSE, NULL);
        dwError = (hFile == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
    }
    RevertToSelf();
    return dwError;
}

static void
CheckUsers(PCWSTR pszRoot)
{
    TESTUSER User1, User2;
    WCHAR szDir[MAX_PATH];
    DWORD dwError;

    if (!SetupUser(&User1, L"pdsec1") || !SetupUser(&User2, L"pdsec2"))
    {
        skip("Cannot create and log on the test users (error %lu)\n", GetLastError());
        goto done;
    }

    /*
     * Like on Windows (the DACL above is the one measured there), a standard user may add files and directories to
     * ProgramData and what it adds is its own. What it cannot do is change what others put there: the Authenticated
     * Users: Modify of the volume root, inherited before, let it.
     */
    dwError = CreateAs(User1.hToken, pszRoot, L"pdsec-file1.txt", FALSE);
    ok(dwError == 0, "creating a file in ProgramData as a user: error %lu\n", dwError);
    dwError = CreateAs(User1.hToken, pszRoot, L"pdsec-dir1", TRUE);
    ok(dwError == 0, "creating a directory in ProgramData as a user: error %lu\n", dwError);
    StringCchPrintfW(szDir, ARRAYSIZE(szDir), L"%s\\pdsec-dir1", pszRoot);
    if (dwError == 0)
    {
        WCHAR szFile[MAX_PATH];
        HANDLE hFile;

        /* A file of the first user, kept open by nobody: the second user may read it but not write or delete it */
        StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%s\\own.txt", szDir);
        ok(ImpersonateLoggedOnUser(User1.hToken), "impersonation failed\n");
        hFile = CreateFileW(szFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        ok(hFile != INVALID_HANDLE_VALUE, "the user cannot create a file in the own directory: error %lu\n", GetLastError());
        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
        RevertToSelf();

        ok(ImpersonateLoggedOnUser(User2.hToken), "impersonation failed\n");
        hFile = CreateFileW(szFile, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        dwError = (hFile == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
        ok(dwError == ERROR_ACCESS_DENIED, "writing the file of another user: error %lu, expected %u\n", dwError, ERROR_ACCESS_DENIED);
        hFile = CreateFileW(szFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        dwError = (hFile == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
        ok(dwError == 0, "reading the file of another user: error %lu\n", dwError);
        ok(!DeleteFileW(szFile) && GetLastError() == ERROR_ACCESS_DENIED, "deleting the file of another user: error %lu\n", GetLastError());
        RevertToSelf();

        DeleteFileW(szFile);
    }
    /* Neither may it change a file that the administrator put in ProgramData */
    {
        WCHAR szFile[MAX_PATH];
        HANDLE hFile;

        StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%s\\pdsec-admin.txt", pszRoot);
        hFile = CreateFileW(szFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        ok(hFile != INVALID_HANDLE_VALUE, "the administrator cannot create a file: error %lu\n", GetLastError());
        if (hFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hFile);
            ok(ImpersonateLoggedOnUser(User1.hToken), "impersonation failed\n");
            hFile = CreateFileW(szFile, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            dwError = (hFile == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
            if (hFile != INVALID_HANDLE_VALUE)
                CloseHandle(hFile);
            RevertToSelf();
            ok(dwError == ERROR_ACCESS_DENIED, "writing a file of the administrator: error %lu, expected %u\n", dwError, ERROR_ACCESS_DENIED);
            DeleteFileW(szFile);
        }
    }
    StringCchPrintfW(szDir, ARRAYSIZE(szDir), L"%s\\pdsec-dir1", pszRoot);
    RemoveDirectoryW(szDir);
    StringCchPrintfW(szDir, ARRAYSIZE(szDir), L"%s\\pdsec-file1.txt", pszRoot);
    DeleteFileW(szDir);

done:
    CleanupUser(&User2);
    CleanupUser(&User1);
}

/* No entry of the DACL of the object lets Users, Authenticated Users, Everyone or the application packages in at all */
static void
CheckNoUserAccess(PCWSTR pszPath)
{
    static const WELL_KNOWN_SID_TYPE Types[] = { WinBuiltinUsersSid, WinAuthenticatedUserSid, WinWorldSid };
    PSECURITY_DESCRIPTOR pSd;
    PACL pAcl = NULL;
    DWORD i, j;

    pSd = GetObjectDacl(pszPath, &pAcl);
    if (!pSd || !pAcl)
    {
        LocalFree(pSd);
        return;
    }
    for (i = 0; i < pAcl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE pAce;
        BYTE Buf[SECURITY_MAX_SID_SIZE];
        PSID pAap;

        if (!GetAce(pAcl, i, (PVOID *)&pAce) || pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;
        for (j = 0; j < ARRAYSIZE(Types); j++)
        {
            DWORD cb = sizeof(Buf);
            if (CreateWellKnownSid(Types[j], NULL, Buf, &cb))
                ok(!EqualSid((PSID)&pAce->SidStart, Buf), "%ls: entry %lu grants 0x%08lx to a user group (type %u)\n", pszPath, i, pAce->Mask, Types[j]);
        }
        if (ConvertStringSidToSidW(AAP, &pAap))
        {
            ok(!EqualSid((PSID)&pAce->SidStart, pAap), "%ls: entry %lu grants 0x%08lx to the application packages\n", pszPath, i, pAce->Mask);
            LocalFree(pAap);
        }
    }
    LocalFree(pSd);
}

/* Open the object itself (not what a junction points to) with the access, as the user: the error, 0 for success */
static DWORD
OpenObjectAs(HANDLE hToken, PCWSTR pszPath, DWORD dwAccess, BOOL bLink)
{
    HANDLE hFile;
    DWORD dwError;

    if (!ImpersonateLoggedOnUser(hToken))
        return 0xdeadbeef;
    hFile = CreateFileW(pszPath, dwAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | (bLink ? FILE_FLAG_OPEN_REPARSE_POINT : 0), NULL);
    dwError = (hFile == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    RevertToSelf();
    return dwError;
}

/*
 * C:\Windows, when that is a junction to the system directory: the junction object has the DACL of the Windows directory (the
 * target was always given it, the junction kept the one it got from the volume root: any user could delete it and put another
 * directory in its place), and the target was not touched through it. The registry hives are for SYSTEM and Administrators.
 */
static void
CheckWindowsAndConfig(void)
{
    WCHAR szSystem[MAX_PATH], szLink[] = L"X:\\Windows", szConfig[MAX_PATH], szFile[MAX_PATH], szFind[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE hFind;
    TESTUSER User;
    DWORD dwAttr, dwError;
    BOOL bJunction;

    if (!GetWindowsDirectoryW(szSystem, ARRAYSIZE(szSystem)) || szSystem[1] != L':')
    {
        skip("No Windows directory\n");
        return;
    }
    szLink[0] = szSystem[0];
    dwAttr = GetFileAttributesW(szLink);
    bJunction = dwAttr != INVALID_FILE_ATTRIBUTES && (dwAttr & FILE_ATTRIBUTE_REPARSE_POINT) && _wcsicmp(szSystem, szLink);

    CheckDaclEx(szSystem, s_ExpectedWindows, ARRAYSIZE(s_ExpectedWindows));
    if (bJunction)
        CheckDaclEx(szLink, s_ExpectedWindows, ARRAYSIZE(s_ExpectedWindows));
    else
        skip("%ls is not a junction\n", szLink);

    StringCchPrintfW(szConfig, ARRAYSIZE(szConfig), L"%s\\system32\\config", szSystem);
    CheckDaclEx(szConfig, s_ExpectedConfig, ARRAYSIZE(s_ExpectedConfig));
    StringCchPrintfW(szFind, ARRAYSIZE(szFind), L"%s\\*", szConfig);
    hFind = FindFirstFileW(szFind, &Find);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (!wcscmp(Find.cFileName, L".") || !wcscmp(Find.cFileName, L".."))
                continue;
            StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%s\\%s", szConfig, Find.cFileName);
            if (!_wcsicmp(Find.cFileName, L"LsaKey") || !_wcsicmp(Find.cFileName, L"LsaKey.new"))
            {
                /* The key of the secret values has a descriptor that grants SYSTEM alone (b0c7635ff97, 72a78dcebc1):
                 * even an administrator cannot read it, so there is no DACL to look at: the open is refused */
                HANDLE hKeyFile = CreateFileW(szFile, READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                              NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                dwError = (hKeyFile == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
                if (hKeyFile != INVALID_HANDLE_VALUE)
                    CloseHandle(hKeyFile);
                ok(dwError == ERROR_ACCESS_DENIED, "%ls: opened by the administrator, error %lu\n", szFile, dwError);
                continue;
            }
            CheckNoUserAccess(szFile);
        } while (FindNextFileW(hFind, &Find));
        FindClose(hFind);
    }

    if (!SetupUser(&User, L"pdsec3"))
    {
        skip("Cannot create and log on the test user (error %lu)\n", GetLastError());
        CleanupUser(&User);
        return;
    }
    if (bJunction)
    {
        /* Nothing is changed by opening it: what is checked is that the access is refused */
        dwError = OpenObjectAs(User.hToken, szLink, DELETE, TRUE);
        ok(dwError == ERROR_ACCESS_DENIED, "opening the junction to delete it as a user: error %lu, expected %u\n", dwError, ERROR_ACCESS_DENIED);
        dwError = OpenObjectAs(User.hToken, szLink, WRITE_DAC, TRUE);
        ok(dwError == ERROR_ACCESS_DENIED, "opening the junction to change its DACL as a user: error %lu, expected %u\n", dwError, ERROR_ACCESS_DENIED);
        dwError = OpenObjectAs(User.hToken, szLink, FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA, TRUE);
        ok(dwError == ERROR_ACCESS_DENIED, "opening the junction for writing as a user: error %lu, expected %u\n", dwError, ERROR_ACCESS_DENIED);
        /* ...while a user can still go through it */
        dwError = OpenObjectAs(User.hToken, szLink, FILE_LIST_DIRECTORY | SYNCHRONIZE, FALSE);
        ok(dwError == 0, "opening C:\\Windows through the junction as a user: error %lu\n", dwError);
    }
    /* The hives: no read access for a user */
    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%s\\SYSTEM", szConfig);
    dwError = OpenObjectAs(User.hToken, szFile, FILE_READ_DATA, FALSE);
    ok(dwError == ERROR_ACCESS_DENIED, "reading the SYSTEM hive file as a user: error %lu, expected %u\n", dwError, ERROR_ACCESS_DENIED);
    dwError = OpenObjectAs(User.hToken, szConfig, FILE_LIST_DIRECTORY, FALSE);
    ok(dwError == ERROR_ACCESS_DENIED, "listing system32\\config as a user: error %lu, expected %u\n", dwError, ERROR_ACCESS_DENIED);
    CleanupUser(&User);
}

/*
 * ProgramData\Microsoft (the all-users Start Menu with its Startup folder, Templates) and Public\Desktop, measured on a
 * Windows Server 2022 reference (icacls and a standard user): protected, SYSTEM and Administrators full control, users read
 * only. ProgramData's own entry (Users add files and folders) is not inherited there: a program a standard user puts into
 * the all-users Startup folder would start at every user's logon.
 */
static const EXPECTED_ACE_EX s_ExpectedMicrosoft[] =
{
    { WinLocalSystemSid, NULL, OI_CI, FILE_ALL_ACCESS },
    { WinBuiltinAdministratorsSid, NULL, OI_CI, FILE_ALL_ACCESS },
    { WinBuiltinUsersSid, NULL, OI_CI, RX_MASK },
    { WinWorldSid, NULL, OI_CI, RX_MASK },
};

static const EXPECTED_ACE_EX s_ExpectedRecycleRoot[] =
{
    { WinBuiltinAdministratorsSid, NULL, 0, FILE_ALL_ACCESS },
    { WinBuiltinAdministratorsSid, NULL, OI_CI_IO, GENERIC_ALL },
    { WinLocalSystemSid, NULL, 0, FILE_ALL_ACCESS },
    { WinLocalSystemSid, NULL, OI_CI_IO, GENERIC_ALL },
    { WinBuiltinUsersSid, NULL, 0, 0x001201ad },
};

static const EXPECTED_ACE_EX s_ExpectedPublicDesktop[] =
{
    { WinBuiltinAdministratorsSid, NULL, OI_CI, FILE_ALL_ACCESS },
    { WinInteractiveSid, NULL, OI_CI, RX_MASK },
    { WinLocalSystemSid, NULL, OI_CI, FILE_ALL_ACCESS },
};

#define USER_WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | \
                           GENERIC_WRITE | GENERIC_ALL)
static ULONG s_WritableObjects, s_CheckedObjects;

/* No allow entry of the object lets a group of every user (Users, Authenticated Users, Everyone, INTERACTIVE) write, delete or re-secure it */
static void
CheckNoUserWrite(PCWSTR pszPath)
{
    static const WELL_KNOWN_SID_TYPE Types[] = { WinBuiltinUsersSid, WinAuthenticatedUserSid, WinWorldSid, WinInteractiveSid };
    PSECURITY_DESCRIPTOR pSd;
    PACL pAcl = NULL;
    DWORD i, j;

    s_CheckedObjects++;
    pSd = GetObjectDacl(pszPath, &pAcl);
    if (!pSd || !pAcl)
    {
        LocalFree(pSd);
        return;
    }
    for (i = 0; i < pAcl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE pAce;
        BYTE Buf[SECURITY_MAX_SID_SIZE];

        if (!GetAce(pAcl, i, (PVOID *)&pAce) || pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            (pAce->Header.AceFlags & INHERIT_ONLY_ACE) || !(pAce->Mask & USER_WRITE_RIGHTS))
            continue;
        for (j = 0; j < ARRAYSIZE(Types); j++)
        {
            DWORD cb = sizeof(Buf);
            if (CreateWellKnownSid(Types[j], NULL, Buf, &cb) && EqualSid((PSID)&pAce->SidStart, Buf))
            {
                if (s_WritableObjects++ < 10)
                    ok(0, "%ls: entry %lu grants 0x%08lx to a group of every user (type %u)\n", pszPath, i, pAce->Mask, Types[j]);
            }
        }
    }
    LocalFree(pSd);
}

static void
WalkNoUserWrite(PCWSTR pszDirectory, UINT uDepth)
{
    WCHAR szPattern[MAX_PATH], szPath[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE hFind;

    if (uDepth > 6 || FAILED(StringCchPrintfW(szPattern, ARRAYSIZE(szPattern), L"%s\\*", pszDirectory)))
        return;
    hFind = FindFirstFileW(szPattern, &Find);
    if (hFind == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if (!wcscmp(Find.cFileName, L".") || !wcscmp(Find.cFileName, L"..") || (Find.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            continue;
        if (FAILED(StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s\\%s", pszDirectory, Find.cFileName)))
            continue;
        CheckNoUserWrite(szPath);
        if (Find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            WalkNoUserWrite(szPath, uDepth + 1);
    } while (FindNextFileW(hFind, &Find));
    FindClose(hFind);
}

static void
CheckAllUsersFolders(PCWSTR pszProgramData)
{
    static const PCWSTR Below[] = { L"", L"\\Windows", L"\\Windows\\Start Menu", L"\\Windows\\Start Menu\\Programs",
                                    L"\\Windows\\Start Menu\\Programs\\Startup", L"\\Windows\\Templates" };
    WCHAR szMicrosoft[MAX_PATH], szPublic[MAX_PATH], szDesktop[MAX_PATH], szPath[MAX_PATH];
    TESTUSER User;
    UINT i;
    DWORD dwError;

    StringCchPrintfW(szMicrosoft, ARRAYSIZE(szMicrosoft), L"%s\\Microsoft", pszProgramData);
    if (GetFileAttributesW(szMicrosoft) == INVALID_FILE_ATTRIBUTES)
    {
        skip("No %ls\n", szMicrosoft);
        return;
    }
    CheckDaclEx(szMicrosoft, s_ExpectedMicrosoft, ARRAYSIZE(s_ExpectedMicrosoft));

    s_WritableObjects = s_CheckedObjects = 0;
    CheckNoUserWrite(szMicrosoft);
    WalkNoUserWrite(szMicrosoft, 0);
    ok(s_WritableObjects == 0, "%lu of %lu objects below %ls let a group of every user write, delete or re-secure them\n",
       s_WritableObjects, s_CheckedObjects, szMicrosoft);

    if (!GetEnvironmentVariableW(L"PUBLIC", szPublic, ARRAYSIZE(szPublic)))
        szPublic[0] = UNICODE_NULL;
    StringCchPrintfW(szDesktop, ARRAYSIZE(szDesktop), L"%s\\Desktop", szPublic);
    if (szPublic[0] && GetFileAttributesW(szDesktop) != INVALID_FILE_ATTRIBUTES)
    {
        CheckDaclEx(szDesktop, s_ExpectedPublicDesktop, ARRAYSIZE(s_ExpectedPublicDesktop));
        s_WritableObjects = s_CheckedObjects = 0;
        CheckNoUserWrite(szDesktop);
        WalkNoUserWrite(szDesktop, 0);
        ok(s_WritableObjects == 0, "%lu of %lu objects below %ls let a group of every user write, delete or re-secure them\n",
           s_WritableObjects, s_CheckedObjects, szDesktop);
    }
    else
        szDesktop[0] = UNICODE_NULL;

    if (!SetupUser(&User, L"pdsec4"))
    {
        skip("Cannot create and log on the test user (error %lu)\n", GetLastError());
        CleanupUser(&User);
        return;
    }
    for (i = 0; i < ARRAYSIZE(Below); i++)
    {
        StringCchPrintfW(szPath, ARRAYSIZE(szPath), L"%s%s", szMicrosoft, Below[i]);
        if (GetFileAttributesW(szPath) == INVALID_FILE_ATTRIBUTES)
            continue;
        dwError = CreateAs(User.hToken, szPath, L"pdsec-user.txt", FALSE);
        ok(dwError == ERROR_ACCESS_DENIED, "creating a file in %ls as a user: error %lu, expected %u\n", szPath, dwError, ERROR_ACCESS_DENIED);
        dwError = CreateAs(User.hToken, szPath, L"pdsec-user.dir", TRUE);
        ok(dwError == ERROR_ACCESS_DENIED, "creating a directory in %ls as a user: error %lu, expected %u\n", szPath, dwError, ERROR_ACCESS_DENIED);
    }
    if (szDesktop[0])
    {
        dwError = CreateAs(User.hToken, szDesktop, L"pdsec-user.txt", FALSE);
        ok(dwError == ERROR_ACCESS_DENIED, "creating a file in %ls as a user: error %lu, expected %u\n", szDesktop, dwError, ERROR_ACCESS_DENIED);
    }
    /* the legacy junctions of ProgramData (Application Data, Start Menu, ...): the object cannot be deleted or re-secured by a user */
    {
        WCHAR szFind[MAX_PATH], szLink[MAX_PATH];
        WIN32_FIND_DATAW Find;
        HANDLE hFind;

        StringCchPrintfW(szFind, ARRAYSIZE(szFind), L"%s\\*", pszProgramData);
        hFind = FindFirstFileW(szFind, &Find);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (!(Find.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !(Find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    continue;
                StringCchPrintfW(szLink, ARRAYSIZE(szLink), L"%s\\%s", pszProgramData, Find.cFileName);
                dwError = OpenObjectAs(User.hToken, szLink, DELETE, TRUE);
                ok(dwError == ERROR_ACCESS_DENIED, "opening the junction %ls to delete it as a user: error %lu, expected %u\n",
                   szLink, dwError, ERROR_ACCESS_DENIED);
                dwError = OpenObjectAs(User.hToken, szLink, WRITE_DAC, TRUE);
                ok(dwError == ERROR_ACCESS_DENIED, "opening the junction %ls to change its DACL as a user: error %lu, expected %u\n",
                   szLink, dwError, ERROR_ACCESS_DENIED);
            } while (FindNextFileW(hFind, &Find));
            FindClose(hFind);
        }
    }
    /* the folder of the recycle bins: users add folders (their own bin) and nothing else; measured as $Recycle.Bin */
    {
        WCHAR szRecycler[MAX_PATH];

        if (GetEnvironmentVariableW(L"SystemDrive", szRecycler, ARRAYSIZE(szRecycler)) &&
            SUCCEEDED(StringCchCatW(szRecycler, ARRAYSIZE(szRecycler), L"\\RECYCLER")) &&
            GetFileAttributesW(szRecycler) != INVALID_FILE_ATTRIBUTES)
        {
            CheckDaclEx(szRecycler, s_ExpectedRecycleRoot, ARRAYSIZE(s_ExpectedRecycleRoot));
            dwError = CreateAs(User.hToken, szRecycler, L"pdsec-user.txt", FALSE);
            ok(dwError == ERROR_ACCESS_DENIED, "creating a file in %ls as a user: error %lu, expected %u\n", szRecycler, dwError, ERROR_ACCESS_DENIED);
            dwError = CreateAs(User.hToken, szRecycler, L"pdsec-user.dir", TRUE);
            ok(dwError == 0, "creating a directory in %ls as a user: error %lu\n", szRecycler, dwError);
        }
        else
            skip("No recycle bin folder\n");
    }
    /* what a user still needs: ProgramData itself (as measured), the own profile is not here */
    dwError = CreateAs(User.hToken, (PWSTR)pszProgramData, L"pdsec-user.txt", FALSE);
    ok(dwError == 0, "creating a file in ProgramData as a user: error %lu\n", dwError);
    CleanupUser(&User);
}

START_TEST(ProgramDataSecurity)
{
    WCHAR szPath[MAX_PATH];
    DWORD cch = ARRAYSIZE(szPath);

    if (!GetAllUsersProfileDirectoryW(szPath, &cch))
    {
        skip("No ProgramData (error %lu)\n", GetLastError());
        return;
    }
    CheckDacl(szPath);
    CheckUsers(szPath);
    CheckWindowsAndConfig();
    CheckAllUsersFolders(szPath);
}
