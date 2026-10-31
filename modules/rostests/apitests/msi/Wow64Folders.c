/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test the folder properties and the file searches of 32-bit and 64-bit packages on a 64-bit system
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Windows 10 22H2 (64-bit), measured with MsiOpenPackage and the AppSearch action, no installation, from a 64-bit and
 * from a 32-bit client, for a package of the template Intel and of the template x64, with the same result:
 *
 *   SystemFolder    <windir>\SysWOW64\      System64Folder  <windir>\system32\     System16Folder  (not set)
 *   [SystemFolder]               finds a file of SysWOW64 only, not one of System32 only
 *   [System64Folder]             finds a file of System32 only, not one of SysWOW64 only
 *   [WindowsFolder]System32      finds a file of System32 only (no WoW64 redirection of the search), not SysWOW64 only
 *   [WindowsFolder]SysWOW64      finds a file of SysWOW64 only, not System32 only
 */

#include <apitest.h>

#include <winnls.h>
#include <wtypes.h>
#include <msi.h>
#include <msidefs.h>
#include <msiquery.h>
#include <strsafe.h>
#include <wctype.h>

typedef BOOL (WINAPI *FN_Wow64DisableWow64FsRedirection)(PVOID *);
typedef BOOL (WINAPI *FN_Wow64RevertWow64FsRedirection)(PVOID);
typedef BOOL (WINAPI *FN_IsWow64Process)(HANDLE, PBOOL);

static FN_Wow64DisableWow64FsRedirection pDisableRedirection;
static FN_Wow64RevertWow64FsRedirection pRevertRedirection;

static WCHAR g_WindowsDir[MAX_PATH];
static WCHAR g_System32[MAX_PATH];
static WCHAR g_SysWOW64[MAX_PATH];

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

/* A file name of a plain DLL in pszDir that is not in pszOther (both read without redirection) */
static BOOL FindOnlyIn(LPCWSTR pszDir, LPCWSTR pszOther, PWSTR pszName, SIZE_T cchName)
{
    WCHAR szPattern[MAX_PATH], szOtherPath[MAX_PATH];
    WIN32_FIND_DATAW Data;
    HANDLE hFind;
    PVOID pOld = NULL;
    BOOL bFound = FALSE, bRedirectionOff;

    bRedirectionOff = pDisableRedirection && pDisableRedirection(&pOld);

    StringCchPrintfW(szPattern, ARRAYSIZE(szPattern), L"%s\\*.dll", pszDir);
    hFind = FindFirstFileW(szPattern, &Data);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            PCWSTR p;

            /* Names that need no quoting in a Signature */
            for (p = Data.cFileName; *p && (iswalnum(*p) || *p == L'.' || *p == L'_'); p++)
                ;
            if (*p || wcslen(Data.cFileName) >= cchName)
                continue;

            StringCchPrintfW(szOtherPath, ARRAYSIZE(szOtherPath), L"%s\\%s", pszOther, Data.cFileName);
            if (GetFileAttributesW(szOtherPath) == INVALID_FILE_ATTRIBUTES)
            {
                StringCchCopyW(pszName, cchName, Data.cFileName);
                bFound = TRUE;
            }
        } while (!bFound && FindNextFileW(hFind, &Data));
        FindClose(hFind);
    }

    if (bRedirectionOff && pRevertRedirection)
        pRevertRedirection(pOld);
    return bFound;
}

static const struct
{
    PCWSTR Property;
    PCWSTR Directory;           /* the Path of the DrLocator */
    BOOL OnlyIn32;              /* searches the file that exists in SysWOW64 only, otherwise System32 only */
    PCWSTR Base;                /* the directory the file is expected in, or NULL: not found */
} Searches[] =
{
    { L"SF_ONLY32",  L"[SystemFolder]",            TRUE,  L"SysWOW64" },
    { L"SF_ONLY64",  L"[SystemFolder]",            FALSE, NULL },
    { L"S64_ONLY32", L"[System64Folder]",          TRUE,  NULL },
    { L"S64_ONLY64", L"[System64Folder]",          FALSE, L"System32" },
    { L"WF32_ONLY32", L"[WindowsFolder]System32",  TRUE,  NULL },
    { L"WF32_ONLY64", L"[WindowsFolder]System32",  FALSE, L"System32" },
    { L"WFW_ONLY32", L"[WindowsFolder]SysWOW64",   TRUE,  L"SysWOW64" },
    { L"WFW_ONLY64", L"[WindowsFolder]SysWOW64",   FALSE, NULL },
};

static BOOL CreatePackage(LPCWSTR pszPath, LPCWSTR pszTemplate, LPCWSTR pszOnly32, LPCWSTR pszOnly64)
{
    MSIHANDLE hDatabase, hSummary;
    WCHAR szQuery[512];
    UINT r;
    SIZE_T i;

    DeleteFileW(pszPath);
    r = MsiOpenDatabaseW(pszPath, (LPCWSTR)MSIDBOPEN_CREATE, &hDatabase);
    ok(r == ERROR_SUCCESS, "MsiOpenDatabaseW failed: %u\n", r);
    if (r != ERROR_SUCCESS)
        return FALSE;

    if (!RunQuery(hDatabase, L"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL PRIMARY KEY `Property`)") ||
        !RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{5B1A6F0C-3D84-4C6E-9B21-7E0D4A9C1F52}')") ||
        !RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'WoW64 folders test')") ||
        !RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '1.0.0')") ||
        !RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductLanguage', '1033')") ||
        !RunQuery(hDatabase, L"CREATE TABLE `Signature` (`Signature` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL, `MinVersion` CHAR(20), `MaxVersion` CHAR(20), `MinSize` LONG, `MaxSize` LONG, `MinDate` LONG, `MaxDate` LONG, `Languages` CHAR(255) PRIMARY KEY `Signature`)") ||
        !RunQuery(hDatabase, L"CREATE TABLE `DrLocator` (`Signature_` CHAR(72) NOT NULL, `Parent` CHAR(72), `Path` CHAR(255), `Depth` INT PRIMARY KEY `Signature_`, `Parent`, `Path`)") ||
        !RunQuery(hDatabase, L"CREATE TABLE `AppSearch` (`Property` CHAR(72) NOT NULL, `Signature_` CHAR(72) NOT NULL PRIMARY KEY `Property`, `Signature_`)"))
    {
        MsiCloseHandle(hDatabase);
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(Searches); i++)
    {
        StringCchPrintfW(szQuery, ARRAYSIZE(szQuery), L"INSERT INTO `Signature` (`Signature`, `FileName`) VALUES ('sig_%s', '%s')",
                         Searches[i].Property, Searches[i].OnlyIn32 ? pszOnly32 : pszOnly64);
        RunQuery(hDatabase, szQuery);
        StringCchPrintfW(szQuery, ARRAYSIZE(szQuery), L"INSERT INTO `DrLocator` (`Signature_`, `Path`, `Depth`) VALUES ('sig_%s', '%s', 0)",
                         Searches[i].Property, Searches[i].Directory);
        RunQuery(hDatabase, szQuery);
        StringCchPrintfW(szQuery, ARRAYSIZE(szQuery), L"INSERT INTO `AppSearch` (`Property`, `Signature_`) VALUES ('%s', 'sig_%s')",
                         Searches[i].Property, Searches[i].Property);
        RunQuery(hDatabase, szQuery);
    }

    r = MsiGetSummaryInformationW(hDatabase, NULL, 5, &hSummary);
    ok(r == ERROR_SUCCESS, "MsiGetSummaryInformationW failed: %u\n", r);
    if (r == ERROR_SUCCESS)
    {
        MsiSummaryInfoSetPropertyW(hSummary, PID_TEMPLATE, VT_LPSTR, 0, NULL, pszTemplate);
        MsiSummaryInfoSetPropertyW(hSummary, PID_REVNUMBER, VT_LPSTR, 0, NULL, L"{9A3E5C71-2B64-4D08-8F1A-6C0B7D2E4A93}");
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

static void CheckFolder(MSIHANDLE hPackage, LPCWSTR pszTemplate, LPCWSTR pszName, LPCWSTR pszDir)
{
    WCHAR szValue[MAX_PATH], szExpected[MAX_PATH];

    GetPkgProp(hPackage, pszName, szValue, ARRAYSIZE(szValue));
    StringCchPrintfW(szExpected, ARRAYSIZE(szExpected), L"%s\\", pszDir);
    ok(!_wcsicmp(szValue, szExpected), "%S: %S is '%S', expected '%S'\n", pszTemplate, pszName, szValue, szExpected);
}

static void TestTemplate(LPCWSTR pszTemplate, LPCWSTR pszOnly32, LPCWSTR pszOnly64)
{
    WCHAR szPath[MAX_PATH], szValue[MAX_PATH], szExpected[MAX_PATH];
    MSIHANDLE hPackage;
    UINT r;
    SIZE_T i;

    GetTempPathW(ARRAYSIZE(szPath), szPath);
    StringCchCatW(szPath, ARRAYSIZE(szPath), L"wow64folders.msi");

    if (!CreatePackage(szPath, pszTemplate, pszOnly32, pszOnly64))
    {
        skip("Could not create the package\n");
        return;
    }

    r = MsiOpenPackageW(szPath, &hPackage);
    ok(r == ERROR_SUCCESS, "%S: MsiOpenPackageW failed: %u\n", pszTemplate, r);
    if (r != ERROR_SUCCESS)
    {
        DeleteFileW(szPath);
        return;
    }

    /* A 32-bit package and a 64-bit package see the same folders in this session */
    CheckFolder(hPackage, pszTemplate, L"SystemFolder", g_SysWOW64);
    CheckFolder(hPackage, pszTemplate, L"System64Folder", g_System32);
    CheckFolder(hPackage, pszTemplate, L"WindowsFolder", g_WindowsDir);
    GetPkgProp(hPackage, L"System16Folder", szValue, ARRAYSIZE(szValue));
    ok(szValue[0] == UNICODE_NULL, "%S: System16Folder is '%S'\n", pszTemplate, szValue);

    r = MsiDoActionW(hPackage, L"AppSearch");
    ok(r == ERROR_SUCCESS, "%S: AppSearch failed: %u\n", pszTemplate, r);

    for (i = 0; i < ARRAYSIZE(Searches); i++)
    {
        GetPkgProp(hPackage, Searches[i].Property, szValue, ARRAYSIZE(szValue));
        if (Searches[i].Base)
        {
            StringCchPrintfW(szExpected, ARRAYSIZE(szExpected), L"%s\\%s\\%s", g_WindowsDir, Searches[i].Base,
                             Searches[i].OnlyIn32 ? pszOnly32 : pszOnly64);
            ok(!_wcsicmp(szValue, szExpected), "%S: %S%s%S is '%S', expected '%S'\n", pszTemplate, Searches[i].Directory,
               L" -> ", Searches[i].OnlyIn32 ? pszOnly32 : pszOnly64, szValue, szExpected);
        }
        else
        {
            ok(szValue[0] == UNICODE_NULL, "%S: %S -> %S is '%S', expected not found\n", pszTemplate, Searches[i].Directory,
               Searches[i].OnlyIn32 ? pszOnly32 : pszOnly64, szValue);
        }
    }

    MsiCloseHandle(hPackage);
    DeleteFileW(szPath);
}

/*
 * A 32-bit client that has switched the WoW64 file system redirection off, as installers do while they look at the
 * 64-bit side, can still open a package. Windows has apphelp.dll mapped in every process, ReactOS loads it on demand
 * and used to fail with the delay-load exception 0xC06D007E (module not found) in MsiOpenPackage here. Run this
 * before any other package is opened: apphelp.dll stays loaded afterwards.
 * Windows 10 22H2: MsiOpenPackage returns ERROR_SUCCESS with the redirection off, in 64-bit and in 32-bit clients.
 */
static void TestOpenWithoutRedirection(void)
{
    WCHAR szPath[MAX_PATH], szValue[MAX_PATH];
    MSIHANDLE hPackage;
    PVOID pOld = NULL;
    UINT r;

    GetTempPathW(ARRAYSIZE(szPath), szPath);
    StringCchCatW(szPath, ARRAYSIZE(szPath), L"wow64open.msi");
    if (!CreatePackage(szPath, L"Intel;1033", L"x", L"y"))
    {
        skip("Could not create the package\n");
        return;
    }

    if (!pDisableRedirection(&pOld))
    {
        skip("Could not disable the file system redirection\n");
        DeleteFileW(szPath);
        return;
    }
    r = MsiOpenPackageW(szPath, &hPackage);
    pRevertRedirection(pOld);
    ok(r == ERROR_SUCCESS, "MsiOpenPackageW without file system redirection failed: %u\n", r);
    if (r == ERROR_SUCCESS)
    {
        GetPkgProp(hPackage, L"ProductName", szValue, ARRAYSIZE(szValue));
        ok(!wcscmp(szValue, L"WoW64 folders test"), "ProductName is '%S'\n", szValue);
        MsiCloseHandle(hPackage);
    }
    DeleteFileW(szPath);
}

START_TEST(Wow64Folders)
{
    FN_IsWow64Process pIsWow64Process;
    SYSTEM_INFO SystemInfo;
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    WCHAR szOnly32[MAX_PATH], szOnly64[MAX_PATH];
    BOOL bWow64 = FALSE;

    pDisableRedirection = (FN_Wow64DisableWow64FsRedirection)GetProcAddress(hKernel32, "Wow64DisableWow64FsRedirection");
    pRevertRedirection = (FN_Wow64RevertWow64FsRedirection)GetProcAddress(hKernel32, "Wow64RevertWow64FsRedirection");
    pIsWow64Process = (FN_IsWow64Process)GetProcAddress(hKernel32, "IsWow64Process");
    if (pIsWow64Process)
        pIsWow64Process(GetCurrentProcess(), &bWow64);

    GetNativeSystemInfo(&SystemInfo);
    if (SystemInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 &&
        SystemInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_ARM64)
    {
        skip("Not a 64-bit system\n");
        return;
    }

    GetWindowsDirectoryW(g_WindowsDir, ARRAYSIZE(g_WindowsDir));
    StringCchPrintfW(g_System32, ARRAYSIZE(g_System32), L"%s\\System32", g_WindowsDir);
    StringCchPrintfW(g_SysWOW64, ARRAYSIZE(g_SysWOW64), L"%s\\SysWOW64", g_WindowsDir);
    if (GetFileAttributesW(g_SysWOW64) == INVALID_FILE_ATTRIBUTES)
    {
        skip("No SysWOW64 directory\n");
        return;
    }

    /* First: once any package was opened, apphelp.dll is loaded and no longer needs a search */
    if (bWow64 && pDisableRedirection && pRevertRedirection)
        TestOpenWithoutRedirection();

    if (!FindOnlyIn(g_System32, g_SysWOW64, szOnly64, ARRAYSIZE(szOnly64)) ||
        !FindOnlyIn(g_SysWOW64, g_System32, szOnly32, ARRAYSIZE(szOnly32)))
    {
        skip("No file that exists in one of System32 and SysWOW64 only\n");
        return;
    }

    TestTemplate(L"Intel;1033", szOnly32, szOnly64);
    TestTemplate(L"x64;1033", szOnly32, szOnly64);
}
