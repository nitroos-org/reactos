/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Tests for the Software Licensing client API of sppc.dll
 */

#include <apitest.h>

#include <windef.h>
#include <winbase.h>
#include <wchar.h>
#include <string.h>
#include <slpublic.h>

typedef HRESULT (WINAPI *PFN_OPEN)(HSLC *);
typedef HRESULT (WINAPI *PFN_CLOSE)(HSLC);
typedef HRESULT (WINAPI *PFN_INSTALL)(HSLC, UINT, const BYTE *, SLID *);
typedef HRESULT (WINAPI *PFN_UNINSTALL)(HSLC, const SLID *);
typedef HRESULT (WINAPI *PFN_LIST)(HSLC, SLIDTYPE, const SLID *, SLIDTYPE, UINT *, SLID **);
typedef HRESULT (WINAPI *PFN_GETLICENSE)(HSLC, const SLID *, UINT *, PBYTE *);
typedef HRESULT (WINAPI *PFN_GETINFO)(HSLC, const SLID *, PCWSTR, SLDATATYPE *, UINT *, PBYTE *);

/*
 * An Office-shaped license file: a license group of two licenses, each followed by its
 * otherInfo table. The licenses carry one more id than the file's name says nothing about.
 */
#define LIC_A "{11111111-2222-3333-4444-555555555555}"
#define LIC_B "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
#define SKU "{149DBCE7-A48E-44DB-8364-A53386CD4580}"
#define APP "{0ff1ce15-a989-479d-af46-f275c6370663}"
static const char g_License[] =
    "\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"utf-8\"?>"
    "<rg:licenseGroup xmlns:rg=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\">"
    "<r:license xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" licenseId=\"" LIC_A "\"><r:title>apitest A</r:title>"
    "<r:otherInfo><tm:infoTables xmlns:tm=\"urn:x\"><tm:infoList tag=\"#global\">"
    "<tm:infoStr name=\"licenseType\">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr>"
    "<tm:infoStr name=\"productSkuId\">" SKU "</tm:infoStr>"
    "<tm:infoStr name=\"applicationId\">" APP "</tm:infoStr>"
    "<tm:infoStr name=\"productName\">A &amp; B &lt;test&gt;</tm:infoStr>"
    "</tm:infoList></tm:infoTables></r:otherInfo></r:license>"
    "<r:license xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" licenseId=\"" LIC_B "\"><r:title>apitest B</r:title>"
    "<r:otherInfo><tm:infoTables xmlns:tm=\"urn:x\"><tm:infoList tag=\"#global\">"
    "<tm:infoStr name=\"licenseType\">msft:sl/PL/GENERIC/PRIVATE</tm:infoStr>"
    "</tm:infoList></tm:infoTables></r:otherInfo></r:license>"
    "</rg:licenseGroup>";
static const SLID g_IdA = { 0x11111111, 0x2222, 0x3333, { 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 } };
static const SLID g_IdB = { 0xAAAAAAAA, 0xBBBB, 0xCCCC, { 0xDD, 0xDD, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE } };
static const SLID g_Sku = { 0x149DBCE7, 0xA48E, 0x44DB, { 0x83, 0x64, 0xA5, 0x33, 0x86, 0xCD, 0x45, 0x80 } };
static const SLID g_App = { 0x0ff1ce15, 0xa989, 0x479d, { 0xaf, 0x46, 0xf2, 0x75, 0xc6, 0x37, 0x06, 0x63 } };

static BOOL Contains(const SLID *Ids, UINT Count, const SLID *Id)
{
    UINT i;

    for (i = 0; i < Count; i++)
        if (IsEqualGUID(&Ids[i], Id))
            return TRUE;
    return FALSE;
}

START_TEST(licenses)
{
    HMODULE Sppc = LoadLibraryW(L"sppc.dll");
    PFN_OPEN pOpen;
    PFN_CLOSE pClose;
    PFN_INSTALL pInstall, pGetFileId;
    PFN_UNINSTALL pUninstall;
    PFN_LIST pList;
    PFN_GETLICENSE pGetLicense;
    PFN_GETINFO pGetInfo;
    HSLC Slc = NULL;
    SLID File, File2, Zero = { 0 };
    SLID *Ids = NULL;
    SLDATATYPE Type;
    UINT n = 123, cb = 0;
    PBYTE Blob = NULL;
    HRESULT hr;
    static const char *Names[] =
    {
        "SLActivateProduct", "SLClose", "SLConsumeRight", "SLDepositMigrationBlob", "SLGetInstalledProductKeyIds",
        "SLGetLicense", "SLGetLicenseFileId", "SLGetLicenseInformation", "SLGetLicensingStatusInformation",
        "SLGetPKeyInformation", "SLGetPolicyInformationDWORD", "SLGetSLIDList", "SLGetWindowsInformationDWORD",
        "SLInstallLicense", "SLInstallProofOfPurchase", "SLOpen", "SLPersistApplicationPolicies",
        "SLPersistRTSPayloadOverride", "SLUninstallLicense", "SLUninstallProofOfPurchase"
    };
    UINT i;

    if (!Sppc)
    {
        skip("sppc.dll is not available\n");
        return;
    }
    /* The exports Integrator.exe resolves by name; SLDepositMigrationBlob also decides whether the OS client is used */
    for (i = 0; i < ARRAYSIZE(Names); i++)
        ok(GetProcAddress(Sppc, Names[i]) != NULL, "%s is not exported\n", Names[i]);

    pOpen = (PFN_OPEN)GetProcAddress(Sppc, "SLOpen");
    pClose = (PFN_CLOSE)GetProcAddress(Sppc, "SLClose");
    pInstall = (PFN_INSTALL)GetProcAddress(Sppc, "SLInstallLicense");
    pUninstall = (PFN_UNINSTALL)GetProcAddress(Sppc, "SLUninstallLicense");
    pList = (PFN_LIST)GetProcAddress(Sppc, "SLGetSLIDList");
    pGetLicense = (PFN_GETLICENSE)GetProcAddress(Sppc, "SLGetLicense");
    pGetFileId = (PFN_INSTALL)GetProcAddress(Sppc, "SLGetLicenseFileId");
    pGetInfo = (PFN_GETINFO)GetProcAddress(Sppc, "SLGetLicenseInformation");
    if (!pOpen || !pClose || !pInstall || !pUninstall || !pList || !pGetLicense || !pGetFileId || !pGetInfo)
        return;

    /* Handles */
    hr = pOpen(NULL);
    ok(hr == E_INVALIDARG, "SLOpen(NULL) returned 0x%lx\n", hr);
    hr = pClose(NULL);
    ok(hr == E_HANDLE, "SLClose(NULL) returned 0x%lx\n", hr);
    hr = pOpen(&Slc);
    ok(hr == S_OK, "SLOpen returned 0x%lx\n", hr);
    ok(Slc != NULL, "no handle\n");
    if (hr != S_OK)
        return;
    hr = pInstall(Slc, 0, (const BYTE *)g_License, &File);
    ok(hr == E_INVALIDARG, "empty blob returned 0x%lx\n", hr);
    hr = pInstall(Slc, 5, (const BYTE *)"junk!", &File);
    ok(hr == E_INVALIDARG, "blob without a license returned 0x%lx\n", hr);

    /* Install: a license file gets an id that depends on its contents only */
    File = Zero;
    hr = pInstall(Slc, sizeof(g_License) - 1, (const BYTE *)g_License, &File);
    ok(hr == S_OK, "SLInstallLicense returned 0x%lx\n", hr);
    ok(!IsEqualGUID(&File, &Zero), "no license file id\n");
    File2 = Zero;
    hr = pGetFileId(Slc, sizeof(g_License) - 1, (const BYTE *)g_License, &File2);
    ok(hr == S_OK, "SLGetLicenseFileId returned 0x%lx\n", hr);
    ok(IsEqualGUID(&File, &File2), "the id differs from the one SLInstallLicense gave\n");
    File2 = Zero;
    hr = pInstall(Slc, sizeof(g_License) - 1, (const BYTE *)g_License, &File2);
    ok(hr == S_OK, "second SLInstallLicense returned 0x%lx\n", hr);
    ok(IsEqualGUID(&File, &File2), "installing the same file twice gave a different id\n");

    /* The licenses of the file, in file order (what Integrator asks after every install) */
    hr = pList(Slc, SL_ID_LICENSE_FILE, &File, SL_ID_LICENSE, &n, &Ids);
    ok(hr == S_OK, "SLGetSLIDList(file->licenses) returned 0x%lx\n", hr);
    ok(n == 2, "got %u licenses\n", n);
    if (n == 2 && Ids)
    {
        ok(IsEqualGUID(&Ids[0], &g_IdA), "first license id is wrong\n");
        ok(IsEqualGUID(&Ids[1], &g_IdB), "second license id is wrong\n");
    }
    if (Ids)
        LocalFree(Ids);

    /* The other relations */
    Ids = NULL;
    hr = pList(Slc, SL_ID_ALL_LICENSE_FILES, NULL, SL_ID_LICENSE_FILE, &n, &Ids);
    ok(hr == S_OK, "all files returned 0x%lx\n", hr);
    ok(Ids && Contains(Ids, n, &File), "the installed file is not in the list of all files\n");
    if (Ids)
        LocalFree(Ids);
    Ids = NULL;
    hr = pList(Slc, SL_ID_ALL_LICENSES, NULL, SL_ID_LICENSE, &n, &Ids);
    ok(hr == S_OK, "all licenses returned 0x%lx\n", hr);
    ok(Ids && Contains(Ids, n, &g_IdA) && Contains(Ids, n, &g_IdB), "the installed licenses are not in the list of all licenses\n");
    if (Ids)
        LocalFree(Ids);
    Ids = NULL;
    hr = pList(Slc, SL_ID_LICENSE, &g_IdB, SL_ID_LICENSE_FILE, &n, &Ids);
    ok(hr == S_OK, "license->file returned 0x%lx\n", hr);
    ok(n == 1 && Ids && IsEqualGUID(&Ids[0], &File), "the license does not lead to its file\n");
    if (Ids)
        LocalFree(Ids);
    Ids = (SLID *)1;
    n = 55;
    hr = pList(Slc, SL_ID_PKEY, &g_IdA, SL_ID_LICENSE, &n, &Ids);
    ok(hr == S_OK && n == 0 && Ids == NULL, "unanswerable relation: 0x%lx n=%u ids=%p\n", hr, n, Ids);

    /* The SKU and application relations, from the otherInfo tables */
    Ids = NULL;
    hr = pList(Slc, SL_ID_PRODUCT_SKU, &g_Sku, SL_ID_LICENSE, &n, &Ids);
    ok(hr == S_OK, "sku->licenses returned 0x%lx\n", hr);
    ok(n >= 1 && Ids && Contains(Ids, n, &g_IdA), "the SKU does not lead to its license\n");
    if (Ids)
        LocalFree(Ids);
    Ids = NULL;
    hr = pList(Slc, SL_ID_LICENSE_FILE, &File, SL_ID_PRODUCT_SKU, &n, &Ids);
    ok(hr == S_OK && n == 1 && Ids && IsEqualGUID(&Ids[0], &g_Sku), "file->skus: 0x%lx n=%u\n", hr, n);
    if (Ids)
        LocalFree(Ids);
    Ids = NULL;
    hr = pList(Slc, SL_ID_LICENSE, &g_IdA, SL_ID_APPLICATION, &n, &Ids);
    ok(hr == S_OK && n == 1 && Ids && IsEqualGUID(&Ids[0], &g_App), "license->application: 0x%lx n=%u\n", hr, n);
    if (Ids)
        LocalFree(Ids);
    Ids = NULL;
    hr = pList(Slc, SL_ID_LICENSE, &g_IdB, SL_ID_PRODUCT_SKU, &n, &Ids);
    ok(hr == S_OK && n == 0 && Ids == NULL, "license without a SKU: 0x%lx n=%u ids=%p\n", hr, n, Ids);

    /* The license information: the otherInfo table, names not case sensitive, entities decoded */
    Blob = NULL;
    cb = 0;
    Type = (SLDATATYPE)99;
    hr = pGetInfo(Slc, &g_IdA, L"licenseType", &Type, &cb, &Blob);
    ok(hr == S_OK, "SLGetLicenseInformation(licenseType) returned 0x%lx\n", hr);
    ok(Type == SL_DATA_SZ, "type %d\n", Type);
    ok(Blob && !wcscmp((WCHAR *)Blob, L"msft:sl/PL/GENERIC/PUBLIC") &&
       cb == (wcslen(L"msft:sl/PL/GENERIC/PUBLIC") + 1) * sizeof(WCHAR),
       "licenseType is %ls (%u bytes)\n", Blob ? (WCHAR *)Blob : L"(null)", cb);
    if (Blob)
        LocalFree(Blob);
    Blob = NULL;
    hr = pGetInfo(Slc, &g_IdB, L"LICENSETYPE", NULL, &cb, &Blob);
    ok(hr == S_OK && Blob && !wcscmp((WCHAR *)Blob, L"msft:sl/PL/GENERIC/PRIVATE"), "second license type: 0x%lx\n", hr);
    if (Blob)
        LocalFree(Blob);
    Blob = NULL;
    hr = pGetInfo(Slc, &g_IdA, L"productSkuId", NULL, &cb, &Blob);
    ok(hr == S_OK && Blob && !_wcsicmp((WCHAR *)Blob, L"" SKU), "productSkuId: 0x%lx\n", hr);
    if (Blob)
        LocalFree(Blob);
    Blob = NULL;
    hr = pGetInfo(Slc, &g_IdA, L"productName", NULL, &cb, &Blob);
    ok(hr == S_OK && Blob && !wcscmp((WCHAR *)Blob, L"A & B <test>"), "productName: 0x%lx\n", hr);
    if (Blob)
        LocalFree(Blob);
    Blob = (PBYTE)1;
    hr = pGetInfo(Slc, &g_IdB, L"productSkuId", NULL, &cb, &Blob);
    ok(hr == SL_E_VALUE_NOT_FOUND && Blob == NULL && cb == 0, "value the license does not have: 0x%lx\n", hr);
    Blob = NULL;
    hr = pGetInfo(Slc, &g_Sku, L"licenseType", NULL, &cb, &Blob);
    ok(hr == SL_E_VALUE_NOT_FOUND, "unknown license: 0x%lx\n", hr);

    /* The file reads back byte for byte */
    Blob = NULL;
    hr = pGetLicense(Slc, &File, &cb, &Blob);
    ok(hr == S_OK, "SLGetLicense returned 0x%lx\n", hr);
    ok(cb == sizeof(g_License) - 1 && Blob && !memcmp(Blob, g_License, cb), "the license file read back differs\n");
    if (Blob)
        LocalFree(Blob);

    /* Uninstall: the file and its licenses are gone */
    hr = pUninstall(Slc, &File);
    ok(hr == S_OK, "SLUninstallLicense returned 0x%lx\n", hr);
    hr = pUninstall(Slc, &File);
    ok(hr == SL_E_LICENSE_FILE_NOT_INSTALLED, "second SLUninstallLicense returned 0x%lx\n", hr);
    Ids = NULL;
    hr = pList(Slc, SL_ID_LICENSE_FILE, &File, SL_ID_LICENSE, &n, &Ids);
    ok(hr == SL_E_LICENSE_FILE_NOT_INSTALLED, "licenses of an uninstalled file returned 0x%lx\n", hr);
    Ids = NULL;
    hr = pList(Slc, SL_ID_ALL_LICENSE_FILES, NULL, SL_ID_LICENSE_FILE, &n, &Ids);
    ok(hr == S_OK, "all files returned 0x%lx\n", hr);
    ok(!Ids || !Contains(Ids, n, &File), "the uninstalled file is still listed\n");
    if (Ids)
        LocalFree(Ids);
    Ids = NULL;
    hr = pList(Slc, SL_ID_LICENSE, &g_IdA, SL_ID_LICENSE_FILE, &n, &Ids);
    ok(hr == S_OK && n == 0 && Ids == NULL, "an uninstalled license still leads to a file: 0x%lx n=%u\n", hr, n);
    Blob = NULL;
    hr = pGetInfo(Slc, &g_IdA, L"licenseType", NULL, &cb, &Blob);
    ok(hr == SL_E_VALUE_NOT_FOUND, "information of an uninstalled license: 0x%lx\n", hr);

    /* Closed handle */
    hr = pClose(Slc);
    ok(hr == S_OK, "SLClose returned 0x%lx\n", hr);

    FreeLibrary(Sppc);
}
