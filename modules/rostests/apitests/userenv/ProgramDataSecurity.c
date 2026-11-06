/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the DACL of C:\ProgramData and what a standard user can do in it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windows.h>
#include <sddl.h>
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

static void
CheckDacl(PCWSTR pszPath)
{
    SECURITY_DESCRIPTOR_CONTROL Control;
    PSECURITY_DESCRIPTOR pSd;
    PACL pAcl = NULL;
    BOOL bPresent, bDefaulted;
    DWORD dwSize = 0, dwRev, i;

    GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize);
    ok(dwSize != 0, "no security for %ls (error %lu)\n", pszPath, GetLastError());
    if (!dwSize)
        return;
    pSd = LocalAlloc(LMEM_FIXED, dwSize);
    ok(GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, pSd, dwSize, &dwSize), "GetFileSecurity failed %lu\n", GetLastError());
    ok(GetSecurityDescriptorControl(pSd, &Control, &dwRev), "no control\n");
    ok(GetSecurityDescriptorDacl(pSd, &bPresent, &pAcl, &bDefaulted) && bPresent && pAcl, "no DACL\n");
    ok(!!(Control & SE_DACL_PROTECTED), "the DACL is not protected (0x%x)\n", Control);

    if (pAcl)
    {
        ok(pAcl->AceCount == ARRAYSIZE(s_Expected), "%u ACEs, expected %u\n", pAcl->AceCount, (UINT)ARRAYSIZE(s_Expected));
        for (i = 0; i < pAcl->AceCount && i < ARRAYSIZE(s_Expected); i++)
        {
            PACCESS_ALLOWED_ACE pAce = NULL;
            BYTE Buf[SECURITY_MAX_SID_SIZE];
            DWORD cb = sizeof(Buf);

            ok(GetAce(pAcl, i, (PVOID *)&pAce) && pAce, "no ACE %lu\n", i);
            if (!pAce)
                continue;
            ok(CreateWellKnownSid(s_Expected[i].Sid, NULL, Buf, &cb), "no SID for ACE %lu\n", i);
            ok(pAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "ACE %lu: type %u\n", i, pAce->Header.AceType);
            ok(pAce->Header.AceFlags == s_Expected[i].Flags, "ACE %lu: flags 0x%x, expected 0x%x\n", i, pAce->Header.AceFlags, s_Expected[i].Flags);
            ok(pAce->Mask == s_Expected[i].Mask, "ACE %lu: mask 0x%08lx, expected 0x%08lx\n", i, pAce->Mask, s_Expected[i].Mask);
            ok(EqualSid((PSID)&pAce->SidStart, Buf), "ACE %lu: wrong SID\n", i);
        }
    }
    LocalFree(pSd);
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
}
