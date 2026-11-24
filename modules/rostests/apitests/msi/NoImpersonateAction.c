/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test the identity of deferred custom actions: "no impersonation" ones run as LocalSystem
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Microsoft Learn (Custom Action Type Flag msidbCustomActionTypeNoImpersonate, 0x800; "Custom Action In-Script
 * Execution Options"): a deferred action is run with the privileges of the installing user, impersonated by the
 * Installer service, unless it has the "no impersonation" flag: then it runs in the system context (LocalSystem).
 * Microsoft Edge's enterprise installer has a deferred, no-impersonation EXE action (DoInstall, type 3074 =
 * 0xC02) that starts the updater next to the updater's own service (LocalSystem); an updater of another identity
 * cannot open the named mutex that the service's copy has created (its default descriptor names LocalSystem
 * and gives the Administrators group read and execute only) and the installation silently stops half way.
 *
 * The test installs a package with three deferred actions and reads what each one reports:
 *  - a DLL action with the flag (0xC01): its process token must be LocalSystem, S-1-5-18;
 *  - a DLL action without it (0x401): the installing administrator, not LocalSystem;
 *  - an EXE action with the flag (0xC02, the type of Edge's): cmd.exe /c whoami says "nt authority\system".
 * It needs an elevated administrator and the Installer service; not run on the Windows reference (it would
 * install a product there).
 */

#include <apitest.h>

#include <winnls.h>
#include <wtypes.h>
#include <msi.h>
#include <msidefs.h>
#include <msiquery.h>
#include <strsafe.h>

static BOOL RunQuery(MSIHANDLE hDatabase, LPCWSTR pszQuery, MSIHANDLE hRecord)
{
    MSIHANDLE hView;
    UINT r;

    r = MsiDatabaseOpenViewW(hDatabase, pszQuery, &hView);
    if (r == ERROR_SUCCESS)
    {
        r = MsiViewExecute(hView, hRecord);
        MsiCloseHandle(hView);
    }
    ok(r == ERROR_SUCCESS, "%S failed: %u\n", pszQuery, r);
    return r == ERROR_SUCCESS;
}

static BOOL AddStream(MSIHANDLE hDatabase, LPCWSTR pszName, LPCWSTR pszFile)
{
    WCHAR szQuery[160];
    MSIHANDLE hRecord = MsiCreateRecord(1);
    UINT r = MsiRecordSetStreamW(hRecord, 1, pszFile);
    BOOL bOk;

    ok(r == ERROR_SUCCESS, "MsiRecordSetStreamW(%S) failed: %u\n", pszFile, r);
    StringCchPrintfW(szQuery, ARRAYSIZE(szQuery), L"INSERT INTO `Binary` (`Name`, `Data`) VALUES ('%s', ?)", pszName);
    bOk = (r == ERROR_SUCCESS) && RunQuery(hDatabase, szQuery, hRecord);
    MsiCloseHandle(hRecord);
    return bOk;
}

static BOOL CreatePackage(LPCWSTR pszPath, LPCWSTR pszDll, LPCWSTR pszCmd)
{
    MSIHANDLE hDatabase, hSummary;
    UINT r;
    BOOL bOk;

    DeleteFileW(pszPath);
    r = MsiOpenDatabaseW(pszPath, (LPCWSTR)MSIDBOPEN_CREATE, &hDatabase);
    ok(r == ERROR_SUCCESS, "MsiOpenDatabaseW failed: %u\n", r);
    if (r != ERROR_SUCCESS)
        return FALSE;

    bOk = RunQuery(hDatabase, L"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL PRIMARY KEY `Property`)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{3D5A7E92-84B1-4C06-9F2E-61A0C7B8D435}')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'No impersonation action test')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '1.0.0')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductLanguage', '1033')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('Manufacturer', 'Test')", 0) &&
          RunQuery(hDatabase, L"CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)", 0) &&
          RunQuery(hDatabase, L"CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255), `ExtendedType` LONG PRIMARY KEY `Action`)", 0) &&
          /* the files the actions write, named by the properties that have the actions' names (their CustomActionData) */
          RunQuery(hDatabase, L"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('SetSysId', 51, 'SysId', '[TempFolder]gbboot_noimp_sys.txt')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('SetUserId', 51, 'UserId', '[TempFolder]gbboot_noimp_user.txt')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('SetExeId', 51, 'ExeId', '/c whoami > \"[TempFolder]gbboot_noimp_exe.txt\"')", 0) &&
          /* deferred (0x400) + no impersonation (0x800) + DLL in the Binary table (1) */
          RunQuery(hDatabase, L"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('SysId', 3073, 'cadir', 'ReportIdentity')", 0) &&
          /* deferred (0x400) + DLL (1) */
          RunQuery(hDatabase, L"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('UserId', 1025, 'cadir', 'ReportIdentity')", 0) &&
          /* deferred + no impersonation + EXE in the Binary table (2): the type of Edge's DoInstall */
          RunQuery(hDatabase, L"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('ExeId', 3074, 'cmdexe', '[CustomActionData]')", 0) &&
          RunQuery(hDatabase, L"CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('SetSysId', 100)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('SetUserId', 101)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('SetExeId', 102)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallInitialize', 1500)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('SysId', 1600)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('UserId', 1700)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('ExeId', 1800)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallFinalize', 6600)", 0) &&
          AddStream(hDatabase, L"cadir", pszDll) &&
          AddStream(hDatabase, L"cmdexe", pszCmd);
    if (!bOk)
    {
        MsiCloseHandle(hDatabase);
        return FALSE;
    }

    r = MsiGetSummaryInformationW(hDatabase, NULL, 5, &hSummary);
    ok(r == ERROR_SUCCESS, "MsiGetSummaryInformationW failed: %u\n", r);
    if (r == ERROR_SUCCESS)
    {
        MsiSummaryInfoSetPropertyW(hSummary, PID_TEMPLATE, VT_LPSTR, 0, NULL, L"Intel;1033");
        MsiSummaryInfoSetPropertyW(hSummary, PID_REVNUMBER, VT_LPSTR, 0, NULL, L"{7A1C5E30-2B94-4D8F-A063-5E9B1D7C4F82}");
        MsiSummaryInfoSetPropertyW(hSummary, PID_PAGECOUNT, VT_I4, 200, NULL, NULL);
        MsiSummaryInfoSetPropertyW(hSummary, PID_WORDCOUNT, VT_I4, 0, NULL, NULL);
        r = MsiSummaryInfoPersist(hSummary);
        ok(r == ERROR_SUCCESS, "MsiSummaryInfoPersist failed: %u\n", r);
        MsiCloseHandle(hSummary);
    }
    if (r == ERROR_SUCCESS)
    {
        r = MsiDatabaseCommit(hDatabase);
        ok(r == ERROR_SUCCESS, "MsiDatabaseCommit failed: %u\n", r);
    }
    MsiCloseHandle(hDatabase);
    return r == ERROR_SUCCESS;
}

static BOOL IsElevatedAdministrator(void)
{
    HANDLE hToken;
    TOKEN_ELEVATION Elevation;
    DWORD cb;
    BOOL bOk = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cb))
            bOk = Elevation.TokenIsElevated;
        CloseHandle(hToken);
    }
    return bOk;
}

/* The text of a file the actions wrote (ANSI or UTF-16: the DLL action writes UTF-16, cmd.exe ANSI) */
static BOOL ReadResult(LPCWSTR pszFile, WCHAR *pszText, DWORD cchText)
{
    char buf[512];
    DWORD cb = 0, i;
    HANDLE hFile = CreateFileW(pszFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    pszText[0] = UNICODE_NULL;
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!ReadFile(hFile, buf, sizeof(buf) - 2, &cb, NULL))
        cb = 0;
    CloseHandle(hFile);
    buf[cb] = buf[cb + 1] = 0;
    if (cb >= 2 && buf[1] == 0)
    {
        StringCchCopyW(pszText, cchText, (WCHAR *)buf);
    }
    else
    {
        for (i = 0; i < cb && i + 1 < cchText; i++)
            pszText[i] = (UCHAR)buf[i];
        pszText[i < cchText ? i : cchText - 1] = UNICODE_NULL;
    }
    return TRUE;
}

START_TEST(NoImpersonateAction)
{
    WCHAR szExe[MAX_PATH], szDll[MAX_PATH], szPkg[MAX_PATH], szTemp[MAX_PATH], szCmd[MAX_PATH], szFile[MAX_PATH];
    WCHAR szText[256];
    SC_HANDLE hScm, hService;
    PWSTR pSlash;
    UINT r;

    if (!IsElevatedAdministrator())
    {
        skip("not an elevated administrator\n");
        return;
    }
    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    hService = hScm ? OpenServiceW(hScm, L"MSIServer", SERVICE_QUERY_STATUS) : NULL;
    if (hService)
        CloseServiceHandle(hService);
    if (hScm)
        CloseServiceHandle(hScm);
    if (!hService)
    {
        skip("no Installer service\n");
        return;
    }

    GetModuleFileNameW(NULL, szExe, ARRAYSIZE(szExe));
    pSlash = wcsrchr(szExe, L'\\');
    if (pSlash)
        pSlash[1] = UNICODE_NULL;
    StringCchPrintfW(szDll, ARRAYSIZE(szDll), L"%smsi_cadir.dll", szExe);
    if (GetFileAttributesW(szDll) == INVALID_FILE_ATTRIBUTES)
    {
        skip("%S not found\n", szDll);
        return;
    }
    GetSystemDirectoryW(szCmd, ARRAYSIZE(szCmd));
    StringCchCatW(szCmd, ARRAYSIZE(szCmd), L"\\cmd.exe");

    GetTempPathW(ARRAYSIZE(szTemp), szTemp);
    StringCchPrintfW(szPkg, ARRAYSIZE(szPkg), L"%sgbboot_noimp.msi", szTemp);
    if (!CreatePackage(szPkg, szDll, szCmd))
    {
        skip("Could not create the package\n");
        return;
    }
    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%sgbboot_noimp_sys.txt", szTemp);
    DeleteFileW(szFile);
    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%sgbboot_noimp_user.txt", szTemp);
    DeleteFileW(szFile);
    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%sgbboot_noimp_exe.txt", szTemp);
    DeleteFileW(szFile);

    MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
    r = MsiInstallProductW(szPkg, L"");
    ok(r == ERROR_SUCCESS, "MsiInstallProductW failed: %u\n", r);

    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%sgbboot_noimp_sys.txt", szTemp);
    ok(ReadResult(szFile, szText, ARRAYSIZE(szText)), "the no-impersonation DLL action wrote nothing\n");
    ok(!wcscmp(szText, L"S-1-5-18"), "the no-impersonation DLL action ran as '%S', expected LocalSystem S-1-5-18\n", szText);
    DeleteFileW(szFile);

    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%sgbboot_noimp_user.txt", szTemp);
    ok(ReadResult(szFile, szText, ARRAYSIZE(szText)), "the impersonating DLL action wrote nothing\n");
    ok(!wcsncmp(szText, L"S-1-5-21-", 9), "the impersonating DLL action ran as '%S', expected the installing user S-1-5-21-...\n", szText);
    DeleteFileW(szFile);

    StringCchPrintfW(szFile, ARRAYSIZE(szFile), L"%sgbboot_noimp_exe.txt", szTemp);
    ok(ReadResult(szFile, szText, ARRAYSIZE(szText)), "the no-impersonation EXE action wrote nothing\n");
    CharLowerBuffW(szText, lstrlenW(szText));
    ok(wcsstr(szText, L"system") != NULL, "the no-impersonation EXE action ran as '%S', expected nt authority\\system\n", szText);
    DeleteFileW(szFile);

    DeleteFileW(szPkg);
}
