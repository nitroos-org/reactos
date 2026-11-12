/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test the current directory of a DLL custom action
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Oracle XE's installer checks its ports from a DLL custom action that starts the program "cmd.exe" by CreateProcess
 * with "cmd.exe" as the application name. That name is looked for in the current directory only. Windows 10 22H2
 * (measured, no installation): CreateProcessA("cmd.exe", "/c ...") fails with error 2 when the current directory is
 * a temp directory and works when it is the system directory. The installer works on Windows, so the process that
 * runs a DLL custom action has the system directory as its current directory there. That last step is an inference
 * and was not measured. The test starts a DLL custom action from a client whose own current directory is a temp
 * directory and checks both the directory the action sees and that it can start cmd.exe by that bare name.
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

static BOOL CreatePackage(LPCWSTR pszPath, LPCWSTR pszDll)
{
    MSIHANDLE hDatabase, hSummary, hRecord;
    UINT r;
    BOOL bOk;

    DeleteFileW(pszPath);
    r = MsiOpenDatabaseW(pszPath, (LPCWSTR)MSIDBOPEN_CREATE, &hDatabase);
    ok(r == ERROR_SUCCESS, "MsiOpenDatabaseW failed: %u\n", r);
    if (r != ERROR_SUCCESS)
        return FALSE;

    bOk = RunQuery(hDatabase, L"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL PRIMARY KEY `Property`)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{6C2D8E41-5A97-4B13-8E60-1D4F7A9B3C25}')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Custom action directory test')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '1.0.0')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductLanguage', '1033')", 0) &&
          RunQuery(hDatabase, L"CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)", 0) &&
          RunQuery(hDatabase, L"CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255), `ExtendedType` LONG PRIMARY KEY `Action`)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('CheckDir', 1, 'cadir', 'CheckDir')", 0);
    if (bOk)
    {
        hRecord = MsiCreateRecord(1);
        r = MsiRecordSetStreamW(hRecord, 1, pszDll);
        ok(r == ERROR_SUCCESS, "MsiRecordSetStreamW failed: %u\n", r);
        bOk = r == ERROR_SUCCESS &&
              RunQuery(hDatabase, L"INSERT INTO `Binary` (`Name`, `Data`) VALUES ('cadir', ?)", hRecord);
        MsiCloseHandle(hRecord);
    }
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
        MsiSummaryInfoSetPropertyW(hSummary, PID_REVNUMBER, VT_LPSTR, 0, NULL, L"{4E7B1A93-0C58-4D2F-A6E1-9B3D5C8F7024}");
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

static void GetPkgProp(MSIHANDLE hPackage, LPCWSTR pszName, PWSTR pszValue, DWORD cchValue)
{
    UINT r;

    pszValue[0] = UNICODE_NULL;
    r = MsiGetPropertyW(hPackage, pszName, pszValue, &cchValue);
    ok(r == ERROR_SUCCESS, "MsiGetPropertyW(%S) failed: %u\n", pszName, r);
}

START_TEST(CustomActionDir)
{
    WCHAR szExe[MAX_PATH], szDll[MAX_PATH], szPkg[MAX_PATH], szTemp[MAX_PATH], szValue[MAX_PATH];
    WCHAR szSystem[MAX_PATH], szWow[MAX_PATH];
    MSIHANDLE hPackage;
    PWSTR pSlash;
    UINT r;

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

    GetTempPathW(ARRAYSIZE(szTemp), szTemp);
    StringCchPrintfW(szPkg, ARRAYSIZE(szPkg), L"%scadir.msi", szTemp);
    if (!CreatePackage(szPkg, szDll))
    {
        skip("Could not create the package\n");
        return;
    }

    /* The client is not in the system directory */
    ok(SetCurrentDirectoryW(szTemp), "SetCurrentDirectoryW failed: %lu\n", GetLastError());

    r = MsiOpenPackageW(szPkg, &hPackage);
    ok(r == ERROR_SUCCESS, "MsiOpenPackageW failed: %u\n", r);
    if (r != ERROR_SUCCESS)
    {
        DeleteFileW(szPkg);
        return;
    }

    r = MsiDoActionW(hPackage, L"CheckDir");
    ok(r == ERROR_SUCCESS, "CheckDir failed: %u\n", r);

    GetSystemDirectoryW(szSystem, ARRAYSIZE(szSystem));
    GetSystemWow64DirectoryW(szWow, ARRAYSIZE(szWow));
    GetPkgProp(hPackage, L"CA_CWD", szValue, ARRAYSIZE(szValue));
    ok(!_wcsicmp(szValue, szSystem) || (szWow[0] && !_wcsicmp(szValue, szWow)),
       "The custom action ran in '%S', expected the system directory '%S'\n", szValue, szSystem);
    GetPkgProp(hPackage, L"CA_CMD", szValue, ARRAYSIZE(szValue));
    ok(!wcscmp(szValue, L"7"), "CreateProcess with the application name cmd.exe in the custom action gave '%S', expected exit code 7\n", szValue);

    MsiCloseHandle(hPackage);
    SetCurrentDirectoryW(szSystem);
    DeleteFileW(szPkg);
}
