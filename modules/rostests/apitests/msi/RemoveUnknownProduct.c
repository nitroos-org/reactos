/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Removing a product that is not installed fails with ERROR_UNKNOWN_PRODUCT and runs no action
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>

#include <winnls.h>
#include <wtypes.h>
#include <msi.h>
#include <msidefs.h>
#include <msiquery.h>
#include <strsafe.h>

#define PRODUCT_CODE L"{5B2E7C14-6D3A-4F8B-9A21-C07E4D1B8F36}"

static BOOL RunQuery(MSIHANDLE hDatabase, LPCWSTR pszQuery)
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

/* A package with no files whose sequence registers and publishes the product */
static BOOL CreatePackage(LPCWSTR pszPath)
{
    static const PCWSTR Queries[] =
    {
        L"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL PRIMARY KEY `Property`)",
        L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '" PRODUCT_CODE L"')",
        L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Remove unknown product test')",
        L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '1.0.0')",
        L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('Manufacturer', 'ReactOS')",
        L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductLanguage', '1033')",
        L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ALLUSERS', '1')",
        L"CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), "
            L"`DefaultDir` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Directory`)",
        L"INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('TARGETDIR', '', 'SourceDir')",
        /* A feature at the default level makes the install publish and register the product */
        L"CREATE TABLE `Feature` (`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), `Title` CHAR(64) LOCALIZABLE, "
            L"`Description` CHAR(255) LOCALIZABLE, `Display` INT, `Level` INT NOT NULL, `Directory_` CHAR(72), "
            L"`Attributes` INT NOT NULL PRIMARY KEY `Feature`)",
        L"INSERT INTO `Feature` (`Feature`, `Feature_Parent`, `Title`, `Description`, `Display`, `Level`, `Directory_`, "
            L"`Attributes`) VALUES ('Main', '', 'Main', '', 1, 1, 'TARGETDIR', 0)",
        L"CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), "
            L"`Sequence` INT PRIMARY KEY `Action`)",
        L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('CostInitialize', 800)",
        L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('CostFinalize', 1000)",
        L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallValidate', 1400)",
        L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallInitialize', 1500)",
        L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('RegisterProduct', 6100)",
        L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('PublishProduct', 6400)",
        L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallFinalize', 6600)",
    };
    MSIHANDLE hDatabase, hSummary;
    UINT r;
    ULONG i;

    DeleteFileW(pszPath);
    r = MsiOpenDatabaseW(pszPath, (LPCWSTR)MSIDBOPEN_CREATE, &hDatabase);
    ok(r == ERROR_SUCCESS, "MsiOpenDatabaseW failed: %u\n", r);
    if (r != ERROR_SUCCESS)
        return FALSE;

    for (i = 0; i < ARRAYSIZE(Queries); i++)
    {
        if (!RunQuery(hDatabase, Queries[i]))
        {
            MsiCloseHandle(hDatabase);
            return FALSE;
        }
    }

    r = MsiGetSummaryInformationW(hDatabase, NULL, 5, &hSummary);
    ok(r == ERROR_SUCCESS, "MsiGetSummaryInformationW failed: %u\n", r);
    if (r == ERROR_SUCCESS)
    {
        MsiSummaryInfoSetPropertyW(hSummary, PID_TEMPLATE, VT_LPSTR, 0, NULL, L"Intel;1033");
        MsiSummaryInfoSetPropertyW(hSummary, PID_REVNUMBER, VT_LPSTR, 0, NULL, L"{7A1D4E92-3B5C-4C60-8E17-F2D9A0B6C358}");
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

/* TRUE if the log (UTF-16 with a BOM, or ANSI) contains an "Action start" line: a sequence ran */
static BOOL LogHasActions(LPCWSTR pszLogPath)
{
    HANDLE hFile;
    DWORD dwSize, dwRead, i;
    PBYTE pData;
    BOOL bFound = FALSE, bWide;

    hFile = CreateFileW(pszLogPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    dwSize = GetFileSize(hFile, NULL);
    pData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize + sizeof(WCHAR));
    if (pData && ReadFile(hFile, pData, dwSize, &dwRead, NULL) && dwRead == dwSize)
    {
        bWide = (dwSize >= 2 && pData[0] == 0xFF && pData[1] == 0xFE);
        if (bWide)
            bFound = wcsstr((PCWSTR)(pData + 2), L"Action start") != NULL;
        else
        {
            for (i = 0; i + 12 <= dwSize; i++)
            {
                if (memcmp(pData + i, "Action start", 12) == 0)
                {
                    bFound = TRUE;
                    break;
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, pData);
    CloseHandle(hFile);
    return bFound;
}

START_TEST(RemoveUnknownProduct)
{
    WCHAR szDir[MAX_PATH], szPackage[MAX_PATH], szLog[MAX_PATH];
    INSTALLSTATE State;
    UINT r;

    MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);

    GetTempPathW(ARRAYSIZE(szDir), szDir);
    StringCchPrintfW(szPackage, ARRAYSIZE(szPackage), L"%sremove_unknown_product.msi", szDir);
    StringCchPrintfW(szLog, ARRAYSIZE(szLog), L"%sremove_unknown_product.log", szDir);

    if (!CreatePackage(szPackage))
        return;

    State = MsiQueryProductStateW(PRODUCT_CODE);
    if (State != INSTALLSTATE_UNKNOWN)
    {
        skip("the test product is installed already (state %d)\n", State);
        DeleteFileW(szPackage);
        return;
    }

    /* Not installed: 1605, and not one action of the sequence ran */
    DeleteFileW(szLog);
    r = MsiEnableLogW(INSTALLLOGMODE_VERBOSE | INSTALLLOGMODE_INFO | INSTALLLOGMODE_ACTIONSTART, szLog, 0);
    ok(r == ERROR_SUCCESS, "MsiEnableLogW failed: %u\n", r);
    r = MsiInstallProductW(szPackage, L"REMOVE=ALL");
    MsiEnableLogW(0, NULL, 0);
    ok(r == ERROR_UNKNOWN_PRODUCT, "removal of a product that is not installed returned %u\n", r);
    ok(!LogHasActions(szLog), "an action ran for the removal of a product that is not installed\n");
    State = MsiQueryProductStateW(PRODUCT_CODE);
    ok(State == INSTALLSTATE_UNKNOWN, "state %d after the refused removal\n", State);

    /* Install it, then remove it twice: the first works, the second finds nothing to remove */
    r = MsiInstallProductW(szPackage, L"");
    ok(r == ERROR_SUCCESS, "install returned %u\n", r);
    State = MsiQueryProductStateW(PRODUCT_CODE);
    ok(State == INSTALLSTATE_DEFAULT, "state %d after the install\n", State);
    if (r == ERROR_SUCCESS)
    {
        r = MsiInstallProductW(szPackage, L"REMOVE=ALL");
        ok(r == ERROR_SUCCESS, "removal of the installed product returned %u\n", r);
        State = MsiQueryProductStateW(PRODUCT_CODE);
        ok(State == INSTALLSTATE_UNKNOWN || State == INSTALLSTATE_ABSENT, "state %d after the removal\n", State);

        r = MsiInstallProductW(szPackage, L"REMOVE=ALL");
        ok(r == ERROR_UNKNOWN_PRODUCT, "second removal returned %u\n", r);
    }

    DeleteFileW(szLog);
    DeleteFileW(szPackage);
}
