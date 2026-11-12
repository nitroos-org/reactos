/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that an Edit control with the PasswordInput attribute masks its text
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Oracle XE's installer (InstallShield) asks for the database password in two Edit controls whose Control
 * table row has the PasswordInput attribute (0x200000). The Windows Installer shows such an Edit with
 * the ES_PASSWORD style; a plain Edit has none. The test shows a non-modal dialog with one of each and
 * reads the window style of the two controls.
 */

#include <apitest.h>

#include <winnls.h>
#include <wtypes.h>
#include <msi.h>
#include <msidefs.h>
#include <msiquery.h>
#include <strsafe.h>

static BOOL PwRunQuery(MSIHANDLE hDatabase, LPCWSTR pszQuery)
{
    MSIHANDLE hView;
    UINT r;

    r = MsiDatabaseOpenViewW(hDatabase, pszQuery, &hView);
    if (r == ERROR_SUCCESS)
    {
        r = MsiViewExecute(hView, 0);
        MsiCloseHandle(hView);
    }
    ok(r == ERROR_SUCCESS, "%S failed: %u\n", pszQuery, r);
    return r == ERROR_SUCCESS;
}

static BOOL PwCreatePackage(LPCWSTR pszPath)
{
    MSIHANDLE hDatabase, hSummary;
    UINT r;
    BOOL bOk;

    DeleteFileW(pszPath);
    r = MsiOpenDatabaseW(pszPath, (LPCWSTR)MSIDBOPEN_CREATE, &hDatabase);
    ok(r == ERROR_SUCCESS, "MsiOpenDatabaseW failed: %u\n", r);
    if (r != ERROR_SUCCESS)
        return FALSE;

    bOk = PwRunQuery(hDatabase, L"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL PRIMARY KEY `Property`)") &&
          PwRunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{3B8F5D12-7A46-4C90-9E15-A2D0C6B47E83}')") &&
          PwRunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Password edit test')") &&
          PwRunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '1.0.0')") &&
          PwRunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductLanguage', '1033')") &&
          PwRunQuery(hDatabase, L"CREATE TABLE `Dialog` (`Dialog` CHAR(72) NOT NULL, `HCentering` SHORT NOT NULL, `VCentering` SHORT NOT NULL, `Width` SHORT NOT NULL, `Height` SHORT NOT NULL, `Attributes` LONG, `Title` CHAR(128) LOCALIZABLE, `Control_First` CHAR(50) NOT NULL, `Control_Default` CHAR(50), `Control_Cancel` CHAR(50) PRIMARY KEY `Dialog`)") &&
          PwRunQuery(hDatabase, L"CREATE TABLE `Control` (`Dialog_` CHAR(72) NOT NULL, `Control` CHAR(50) NOT NULL, `Type` CHAR(20) NOT NULL, `X` SHORT NOT NULL, `Y` SHORT NOT NULL, `Width` SHORT NOT NULL, `Height` SHORT NOT NULL, `Attributes` LONG, `Property` CHAR(50), `Text` CHAR(0) LOCALIZABLE, `Control_Next` CHAR(50), `Help` CHAR(50) LOCALIZABLE PRIMARY KEY `Dialog_`, `Control`)") &&
          PwRunQuery(hDatabase, L"INSERT INTO `Dialog` (`Dialog`, `HCentering`, `VCentering`, `Width`, `Height`, `Attributes`, `Title`, `Control_First`) VALUES ('PwDlg', 50, 50, 300, 100, 1, 'Password', 'Clear')") &&
          PwRunQuery(hDatabase, L"INSERT INTO `Control` (`Dialog_`, `Control`, `Type`, `X`, `Y`, `Width`, `Height`, `Attributes`, `Property`, `Control_Next`) VALUES ('PwDlg', 'Clear', 'Edit', 10, 10, 200, 18, 3, 'CLEARVAL', 'Secret')") &&
          PwRunQuery(hDatabase, L"INSERT INTO `Control` (`Dialog_`, `Control`, `Type`, `X`, `Y`, `Width`, `Height`, `Attributes`, `Property`, `Control_Next`) VALUES ('PwDlg', 'Secret', 'Edit', 10, 40, 200, 18, 2097155, 'SECRETVAL', 'Clear')");
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
        MsiSummaryInfoSetPropertyW(hSummary, PID_REVNUMBER, VT_LPSTR, 0, NULL, L"{9D14C7A8-52E3-4B6F-8A07-3E1F6C2B5D90}");
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

START_TEST(MsiPasswordEdit)
{
    WCHAR szTemp[MAX_PATH], szPkg[MAX_PATH];
    MSIHANDLE hPackage;
    HWND hDlg, hClear, hSecret;
    INSTALLUILEVEL old;
    UINT r;
    int i;

    GetTempPathW(ARRAYSIZE(szTemp), szTemp);
    StringCchPrintfW(szPkg, ARRAYSIZE(szPkg), L"%spwedit.msi", szTemp);
    if (!PwCreatePackage(szPkg))
    {
        skip("Could not create the package\n");
        return;
    }

    old = MsiSetInternalUI(INSTALLUILEVEL_FULL, NULL);
    r = MsiOpenPackageW(szPkg, &hPackage);
    ok(r == ERROR_SUCCESS, "MsiOpenPackageW failed: %u\n", r);
    if (r != ERROR_SUCCESS)
    {
        MsiSetInternalUI(old, NULL);
        DeleteFileW(szPkg);
        return;
    }

    r = MsiDoActionW(hPackage, L"PwDlg");
    ok(r == ERROR_SUCCESS || r == ERROR_IO_PENDING || r == ERROR_INSTALL_USEREXIT,
       "Showing the dialog failed: %u\n", r);

    hDlg = NULL;
    for (i = 0; i < 50 && !hDlg; i++)
    {
        hDlg = FindWindowW(L"MsiDialogCloseClass", L"Password");
        if (!hDlg)
            Sleep(100);
    }
    ok(hDlg != NULL, "The dialog window was not created\n");
    if (hDlg)
    {
        hClear = FindWindowExW(hDlg, NULL, L"Edit", NULL);
        hSecret = hClear ? FindWindowExW(hDlg, hClear, L"Edit", NULL) : NULL;
        ok(hClear && hSecret, "Edit controls not found: %p %p\n", hClear, hSecret);
        if (hClear && hSecret)
        {
            LONG_PTR s1 = GetWindowLongPtrW(hClear, GWL_STYLE), s2 = GetWindowLongPtrW(hSecret, GWL_STYLE);
            ok((s1 & ES_PASSWORD) != (s2 & ES_PASSWORD),
               "Exactly one Edit must be a password edit, styles %#Ix and %#Ix\n", s1, s2);
            ok(((s1 | s2) & ES_PASSWORD) != 0,
               "The PasswordInput Edit has no ES_PASSWORD style, styles %#Ix and %#Ix\n", s1, s2);
        }
    }

    MsiCloseHandle(hPackage);
    MsiSetInternalUI(old, NULL);
    DeleteFileW(szPkg);
}
