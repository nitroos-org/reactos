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
/* A second SKU of the same application, with an end-user license (the one that names the SKU) and two more licenses,
 * listed here in descending id order: the SKU relation comes back in ascending order (measured on Windows 10) */
#define SKU2 "{0ABCDEF0-1111-2222-3333-444444444444}"
#define LIC_E1 "{FFFFFFFF-0000-0000-0000-000000000001}"
#define LIC_E2 "{00000001-0000-0000-0000-000000000002}"
#define LIC_E3 "{7AAAAAAA-0000-0000-0000-000000000003}"
#define SKU3 "{0ABCDEF0-1111-2222-3333-555555555555}"
#define LIC_E4 "{7BBBBBBB-0000-0000-0000-000000000004}"
static const char g_Eul[] =
    "\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"utf-8\"?>"
    "<rg:licenseGroup xmlns:rg=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\">"
    "<r:license xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" licenseId=\"" LIC_E1 "\"><r:title>apitest E1</r:title>"
    "<r:otherInfo><tm:infoTables xmlns:tm=\"urn:x\"><tm:infoList tag=\"#global\">"
    "<tm:infoStr name=\"licenseType\">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr>"
    "<tm:infoStr name=\"productSkuId\">" SKU2 "</tm:infoStr>"
    "<tm:infoStr name=\"applicationId\">" APP "</tm:infoStr>"
    "<tm:infoStr name=\"productDescription\">Office 16</tm:infoStr>"
    "</tm:infoList></tm:infoTables></r:otherInfo></r:license>"
    "<r:license xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" licenseId=\"" LIC_E2 "\"><r:title>apitest E2</r:title>"
    "<r:otherInfo><tm:infoTables xmlns:tm=\"urn:x\"><tm:infoList tag=\"#global\">"
    "<tm:infoStr name=\"licenseType\">msft:sl/EUL/GENERIC/PUBLIC</tm:infoStr>"
    "<tm:infoStr name=\"productSkuId\">" SKU2 "</tm:infoStr>"
    "<tm:infoStr name=\"applicationId\">" APP "</tm:infoStr>"
    "<tm:infoStr name=\"productName\">Apitest 1, Suite edition</tm:infoStr>"
    "<tm:infoStr name=\"productDescription\">Apitest 1, TIMEBASED channel</tm:infoStr>"
    "<tm:infoStr name=\"Family\">ApitestSuite</tm:infoStr>"
    "<tm:infoStr name=\"productAuthor\">Nobody</tm:infoStr>"
    "<tm:infoStr name=\"Channel\">not-a-sku-value</tm:infoStr>"
    "</tm:infoList></tm:infoTables></r:otherInfo></r:license>"
    "<r:license xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" licenseId=\"" LIC_E3 "\"><r:title>apitest E3</r:title>"
    "<r:otherInfo><tm:infoTables xmlns:tm=\"urn:x\"><tm:infoList tag=\"#global\">"
    "<tm:infoStr name=\"licenseType\">msft:sl/PL/GENERIC/PRIVATE</tm:infoStr>"
    "<tm:infoStr name=\"productSkuId\">" SKU2 "</tm:infoStr>"
    "<tm:infoStr name=\"applicationId\">" APP "</tm:infoStr>"
    "</tm:infoList></tm:infoTables></r:otherInfo></r:license>"
    /* a SKU without an end-user license */
    "<r:license xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" licenseId=\"" LIC_E4 "\"><r:title>apitest E4</r:title>"
    "<r:otherInfo><tm:infoTables xmlns:tm=\"urn:x\"><tm:infoList tag=\"#global\">"
    "<tm:infoStr name=\"licenseType\">msft:sl/PL/GENERIC/PUBLIC</tm:infoStr>"
    "<tm:infoStr name=\"productSkuId\">" SKU3 "</tm:infoStr>"
    "<tm:infoStr name=\"applicationId\">" APP "</tm:infoStr>"
    "<tm:infoStr name=\"productName\">no end-user license</tm:infoStr>"
    "</tm:infoList></tm:infoTables></r:otherInfo></r:license>"
    "</rg:licenseGroup>";
static const SLID g_Sku3 = { 0x0ABCDEF0, 0x1111, 0x2222, { 0x33, 0x33, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 } };
static const SLID g_Sku2 = { 0x0ABCDEF0, 0x1111, 0x2222, { 0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 } };
static const SLID g_IdE1 = { 0xFFFFFFFF, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
static const SLID g_IdE2 = { 0x00000001, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } };
static const SLID g_IdE3 = { 0x7AAAAAAA, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 } };
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
        "SLPersistRTSPayloadOverride", "SLUninstallLicense", "SLUninstallProofOfPurchase",
        "SLGetPolicyInformation", "SLGetServiceInformation", "SLGetProductSkuInformation",
        "SLGenerateOfflineInstallationId", "SLDepositOfflineConfirmationId", "SLGetApplicationInformation",
#ifdef _WIN64
        /* Office 64-bit resolves the whole table by name and does not run when one is missing */
        "SLGetPKeyId", "SLReArm", "SLRegisterPlugin", "SLSetAuthenticationData", "SLGetAuthenticationResult",
        "SLLoadApplicationPolicies", "SLUnloadApplicationPolicies", "SLGetApplicationPolicy",
#endif
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

    /* The status query (measured on Windows 10 22H2: no id, and an application without a license) */
    {
        typedef HRESULT (WINAPI *PFN_STATUS)(HSLC, const SLID *, const SLID *, PCWSTR, UINT *, SL_LICENSING_STATUS **);
        typedef HRESULT (WINAPI *PFN_INFO5)(HSLC, PCWSTR, SLDATATYPE *, UINT *, PBYTE *);
        typedef HRESULT (WINAPI *PFN_SKUINFO)(HSLC, const SLID *, PCWSTR, SLDATATYPE *, UINT *, PBYTE *);
        typedef HRESULT (WINAPI *PFN_GENID)(HSLC, const SLID *, PWSTR *);
        typedef HRESULT (WINAPI *PFN_DEPOSIT)(HSLC, const SLID *, PCWSTR, PCWSTR);
        PFN_STATUS pStatus = (PFN_STATUS)GetProcAddress(Sppc, "SLGetLicensingStatusInformation");
        PFN_INFO5 pPolicy = (PFN_INFO5)GetProcAddress(Sppc, "SLGetPolicyInformation");
        PFN_INFO5 pService = (PFN_INFO5)GetProcAddress(Sppc, "SLGetServiceInformation");
        PFN_SKUINFO pSkuInfo = (PFN_SKUINFO)GetProcAddress(Sppc, "SLGetProductSkuInformation");
        PFN_GENID pGenId = (PFN_GENID)GetProcAddress(Sppc, "SLGenerateOfflineInstallationId");
        PFN_DEPOSIT pDeposit = (PFN_DEPOSIT)GetProcAddress(Sppc, "SLDepositOfflineConfirmationId");
        SL_LICENSING_STATUS *Status = NULL;
        PWSTR Text = (PWSTR)1;
        UINT cnt = 77;

        hr = pStatus(Slc, NULL, NULL, NULL, &cnt, &Status);
        ok(hr == (HRESULT)0xC004F002L && cnt == 0 && Status == NULL, "status without ids: 0x%lx count %u\n", hr, cnt);
        hr = pStatus(Slc, &Zero, NULL, NULL, &cnt, &Status);
        ok(hr == SL_E_PRODUCT_SKU_NOT_INSTALLED && cnt == 0 && Status == NULL, "status of an application without license: 0x%lx count %u\n", hr, cnt);
        hr = pStatus(NULL, &g_App, NULL, NULL, &cnt, &Status);
        ok(hr == E_HANDLE, "status with no handle: 0x%lx\n", hr);
        hr = pStatus(Slc, &g_App, NULL, NULL, NULL, &Status);
        ok(hr == E_INVALIDARG, "status without a count: 0x%lx\n", hr);
        /* other licenses of the same application may be installed (Office): the SKU is one of the entries */
        hr = pStatus(Slc, &g_App, NULL, NULL, &cnt, &Status);
        ok(hr == S_OK && cnt >= 1 && Status != NULL, "status of the installed application: 0x%lx count %u\n", hr, cnt);
        if (hr == S_OK && Status)
        {
            UINT k;
            BOOL Found = FALSE;

            for (k = 0; k < cnt; k++)
            {
                ok(Status[k].eStatus == SL_LICENSING_STATUS_UNLICENSED, "status %d: no product key was ever installed\n", Status[k].eStatus);
                if (IsEqualGUID(&Status[k].SkuId, &g_Sku))
                    Found = TRUE;
            }
            ok(Found, "the installed SKU is not in the status list\n");
        }
        if (Status)
            LocalFree(Status);
        Status = NULL;
        hr = pStatus(Slc, NULL, &g_Sku, NULL, &cnt, &Status);
        ok(hr == S_OK && cnt == 1 && Status && IsEqualGUID(&Status[0].SkuId, &g_Sku), "status of the SKU: 0x%lx count %u\n", hr, cnt);
        if (Status)
            LocalFree(Status);

        /* The entry points of the service */
        Blob = (PBYTE)1; cb = 9;
        hr = pPolicy(Slc, L"Office-NoSuchPolicy", &Type, &cb, &Blob);
        ok(hr == SL_E_RIGHT_NOT_GRANTED && cb == 0 && Blob == NULL, "SLGetPolicyInformation: 0x%lx\n", hr);
        hr = pPolicy(NULL, L"x", &Type, &cb, &Blob);
        ok(hr == E_HANDLE, "SLGetPolicyInformation with no handle: 0x%lx\n", hr);
        hr = pPolicy(Slc, NULL, &Type, &cb, &Blob);
        ok(hr == E_INVALIDARG, "SLGetPolicyInformation without a name: 0x%lx\n", hr);
        Blob = (PBYTE)1; cb = 9;
        hr = pService(Slc, L"ActivePlugins", &Type, &cb, &Blob);
        ok(hr == SL_E_VALUE_NOT_FOUND && cb == 0 && Blob == NULL, "SLGetServiceInformation: 0x%lx\n", hr);
        hr = pService(Slc, L"ActivePlugins", &Type, NULL, &Blob);
        ok(hr == E_INVALIDARG, "SLGetServiceInformation without a size: 0x%lx\n", hr);
        /* an installed SKU without an end-user license has no name; g_Sku is the id of a real Office SKU, whose
         * end-user license a store with Office installed holds: only the first is checked here (g_Sku3 below) */
        hr = pSkuInfo(Slc, &g_Sku, L"Name", &Type, &cb, &Blob);
        ok(hr == SL_E_VALUE_NOT_FOUND || hr == S_OK, "SLGetProductSkuInformation of an installed SKU: 0x%lx\n", hr);
        if (hr == S_OK && Blob)
            LocalFree(Blob);
        hr = pSkuInfo(Slc, &Zero, L"Name", &Type, &cb, &Blob);
        ok(hr == SL_E_PRODUCT_SKU_NOT_INSTALLED, "SLGetProductSkuInformation of an unknown SKU: 0x%lx\n", hr);
        hr = pGenId(Slc, &g_Sku, &Text);
        ok(hr == SL_E_NOT_SUPPORTED && Text == NULL, "SLGenerateOfflineInstallationId: 0x%lx\n", hr);
        hr = pDeposit(Slc, &g_Sku, L"1", L"2");
        ok(hr == SL_E_NOT_SUPPORTED, "SLDepositOfflineConfirmationId: 0x%lx\n", hr);
    }

    /* Measured on Windows 10 22H2 with Office installed and never activated */
    {
        typedef HRESULT (WINAPI *PFN_STATUS)(HSLC, const SLID *, const SLID *, PCWSTR, UINT *, SL_LICENSING_STATUS **);
        typedef HRESULT (WINAPI *PFN_SKUINFO)(HSLC, const SLID *, PCWSTR, SLDATATYPE *, UINT *, PBYTE *);
        typedef HRESULT (WINAPI *PFN_KEYIDS)(HSLC, const SLID *, UINT *, SLID **);
        typedef HRESULT (WINAPI *PFN_POLDW)(HSLC, PCWSTR, DWORD *);
        typedef HRESULT (WINAPI *PFN_CONSUME)(HSLC, const SLID *, const SLID *, PCWSTR, PVOID);
        typedef HRESULT (WINAPI *PFN_APPINFO)(HSLC, const SLID *, PCWSTR, SLDATATYPE *, UINT *, PBYTE *);
        PFN_STATUS pStatus = (PFN_STATUS)GetProcAddress(Sppc, "SLGetLicensingStatusInformation");
        PFN_SKUINFO pSkuInfo = (PFN_SKUINFO)GetProcAddress(Sppc, "SLGetProductSkuInformation");
        PFN_KEYIDS pKeyIds = (PFN_KEYIDS)GetProcAddress(Sppc, "SLGetInstalledProductKeyIds");
        PFN_POLDW pPolDw = (PFN_POLDW)GetProcAddress(Sppc, "SLGetPolicyInformationDWORD");
        PFN_CONSUME pConsume = (PFN_CONSUME)GetProcAddress(Sppc, "SLConsumeRight");
        PFN_APPINFO pAppInfo = (PFN_APPINFO)GetProcAddress(Sppc, "SLGetApplicationInformation");
        SL_LICENSING_STATUS *Status = NULL;
        SLID Eul;
        WCHAR Want[40];
        DWORD dw = 0x1234;
        UINT cnt = 0;
        SLID *Keys = (SLID *)1;
        UINT k;

        ok(pAppInfo != NULL, "SLGetApplicationInformation is not exported\n");
        hr = pInstall(Slc, sizeof(g_Eul) - 1, (const BYTE *)g_Eul, &Eul);
        ok(hr == S_OK, "installing the second license file: 0x%lx\n", hr);
        Blob = (PBYTE)1; cb = 9;
        hr = pSkuInfo(Slc, &g_Sku3, L"Name", &Type, &cb, &Blob);
        ok(hr == SL_E_VALUE_NOT_FOUND && cb == 0 && Blob == NULL, "SLGetProductSkuInformation of an installed SKU without an end-user license: 0x%lx\n", hr);

        /* SKU and license ids come back in ascending order, whatever the file order */
        Ids = NULL;
        hr = pList(Slc, SL_ID_PRODUCT_SKU, &g_Sku2, SL_ID_LICENSE, &n, &Ids);
        ok(hr == S_OK && n == 3 && Ids, "sku2->licenses: 0x%lx n=%u\n", hr, n);
        if (hr == S_OK && n == 3 && Ids)
        {
            ok(IsEqualGUID(&Ids[0], &g_IdE2) && IsEqualGUID(&Ids[1], &g_IdE3) && IsEqualGUID(&Ids[2], &g_IdE1), "licenses of the SKU are not in ascending order\n");
        }
        if (Ids)
            LocalFree(Ids);
        Ids = NULL;
        hr = pList(Slc, SL_ID_APPLICATION, &g_App, SL_ID_PRODUCT_SKU, &n, &Ids);
        ok(hr == S_OK && n >= 2 && Ids, "app->skus: 0x%lx n=%u\n", hr, n);
        for (k = 1; hr == S_OK && Ids && k < n; k++)
            ok(Ids[k - 1].Data1 <= Ids[k].Data1, "SKUs of the application are not in ascending order at %u\n", k);
        if (Ids)
            LocalFree(Ids);

        /* an installed SKU holds no product key: no key id, and the key query says value not found */
        Ids = (SLID *)1;
        n = 9;
        hr = pList(Slc, SL_ID_PRODUCT_SKU, &g_Sku2, SL_ID_PKEY, &n, &Ids);
        ok(hr == SL_E_VALUE_NOT_FOUND && n == 0 && Ids == NULL, "sku->product keys: 0x%lx n=%u ids=%p\n", hr, n, Ids);
        hr = pKeyIds(Slc, &g_Sku2, &cnt, &Keys);
        ok(hr == SL_E_VALUE_NOT_FOUND && cnt == 0 && Keys == NULL, "SLGetInstalledProductKeyIds of an installed SKU: 0x%lx\n", hr);
        hr = pKeyIds(Slc, &Zero, &cnt, &Keys);
        ok(hr == S_OK && cnt == 0 && Keys == NULL, "SLGetInstalledProductKeyIds of an unknown SKU: 0x%lx\n", hr);

        /* the status of a SKU that is asked for by name: that SKU only, unlicensed, reason 0xC004F014, no grace */
        cnt = 77;
        hr = pStatus(Slc, &g_App, &g_Sku2, NULL, &cnt, &Status);
        ok(hr == S_OK && cnt == 1 && Status && IsEqualGUID(&Status[0].SkuId, &g_Sku2), "status of application and SKU: 0x%lx count %u\n", hr, cnt);
        if (hr == S_OK && Status)
        {
            ok(Status[0].eStatus == SL_LICENSING_STATUS_UNLICENSED, "status %d\n", Status[0].eStatus);
            ok(Status[0].hrReason == (HRESULT)0xC004F014L, "reason 0x%lx\n", Status[0].hrReason);
            ok(Status[0].dwGraceTime == 0 && Status[0].dwTotalGraceDays == 0 && Status[0].qwValidityExpiration == 0, "grace %lu/%lu validity %I64u\n",
               Status[0].dwGraceTime, Status[0].dwTotalGraceDays, Status[0].qwValidityExpiration);
        }
        if (Status)
            LocalFree(Status);
        Status = NULL;
        hr = pStatus(Slc, &g_App, &Zero, NULL, &cnt, &Status);
        ok(hr == SL_E_PRODUCT_SKU_NOT_INSTALLED && cnt == 0 && Status == NULL, "status of the application and a SKU it does not have: 0x%lx count %u\n", hr, cnt);

        /* SKU information: from the SKU's end-user license (the licenseType msft:sl/EUL/.../PUBLIC) */
        for (k = 0; k < 4; k++)
        {
            static const WCHAR *Names[4] = { L"Name", L"Description", L"Family", L"Author" };
            static const WCHAR *Values[4] = { L"Apitest 1, Suite edition", L"Apitest 1, TIMEBASED channel", L"ApitestSuite", L"Nobody" };

            Blob = NULL; cb = 0; Type = (SLDATATYPE)99;
            hr = pSkuInfo(Slc, &g_Sku2, Names[k], &Type, &cb, &Blob);
            ok(hr == S_OK && Type == SL_DATA_SZ && Blob && !wcscmp((WCHAR *)Blob, Values[k]), "SLGetProductSkuInformation(%ls): 0x%lx\n", Names[k], hr);
            if (Blob)
                LocalFree(Blob);
        }
        /* the id of the license of a licenseType, and the id of the file, as lower case text */
        Blob = NULL;
        hr = pSkuInfo(Slc, &g_Sku2, L"msft:sl/EUL/GENERIC/PUBLIC", &Type, &cb, &Blob);
        wcscpy(Want, L"00000001-0000-0000-0000-000000000002");
        ok(hr == S_OK && Blob && !wcscmp((WCHAR *)Blob, Want), "license of the EUL type: 0x%lx %ls\n", hr, Blob ? (WCHAR *)Blob : L"(null)");
        if (Blob)
            LocalFree(Blob);
        Blob = NULL;
        hr = pSkuInfo(Slc, &g_Sku2, L"fileId", &Type, &cb, &Blob);
        ok(hr == S_OK && Blob && cb == 37 * sizeof(WCHAR), "fileId: 0x%lx cb %u\n", hr, cb);
        if (hr == S_OK && Blob)
        {
            WCHAR *p;

            for (p = (WCHAR *)Blob; *p; p++)
                ok(!(*p >= L'A' && *p <= L'F'), "fileId is not lower case: %ls\n", (WCHAR *)Blob);
        }
        if (Blob)
            LocalFree(Blob);
        /* names Windows does not answer for a SKU, even when the license happens to have a field of that name */
        Blob = (PBYTE)1; cb = 9;
        hr = pSkuInfo(Slc, &g_Sku2, L"Channel", &Type, &cb, &Blob);
        ok(hr == SL_E_VALUE_NOT_FOUND && cb == 0 && Blob == NULL, "SLGetProductSkuInformation(Channel): 0x%lx\n", hr);
        hr = pSkuInfo(Slc, &g_Sku2, L"ProductKeyType", &Type, &cb, &Blob);
        ok(hr == SL_E_VALUE_NOT_FOUND, "SLGetProductSkuInformation(ProductKeyType): 0x%lx\n", hr);

        /* policies are never granted; the consume call needs an application; the application information is empty */
        hr = pPolDw(Slc, L"office-DC5CCACD-A7AC-4FD3-9F70-9454B5DE5161", &dw);
        ok(hr == SL_E_RIGHT_NOT_GRANTED, "SLGetPolicyInformationDWORD: 0x%lx\n", hr);
        hr = pConsume(Slc, NULL, NULL, NULL, NULL);
        ok(hr == E_INVALIDARG, "SLConsumeRight without an application: 0x%lx\n", hr);
        hr = pConsume(Slc, &g_App, NULL, NULL, NULL);
        ok(hr == SL_E_RIGHT_NOT_GRANTED, "SLConsumeRight of the application: 0x%lx\n", hr);
        if (pAppInfo)
        {
            Blob = (PBYTE)1; cb = 9;
            hr = pAppInfo(Slc, &g_App, L"Name", &Type, &cb, &Blob);
            ok(hr == SL_E_VALUE_NOT_FOUND && cb == 0 && Blob == NULL, "SLGetApplicationInformation: 0x%lx\n", hr);
            hr = pAppInfo(Slc, NULL, L"Name", &Type, &cb, &Blob);
            ok(hr == E_INVALIDARG, "SLGetApplicationInformation without an application: 0x%lx\n", hr);
        }

        hr = pUninstall(Slc, &Eul);
        ok(hr == S_OK, "uninstalling the second license file: 0x%lx\n", hr);
    }

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

    {
        typedef HRESULT (WINAPI *PFN_STATUS)(HSLC, const SLID *, const SLID *, PCWSTR, UINT *, SL_LICENSING_STATUS **);
        SL_LICENSING_STATUS *Status = NULL;
        UINT cnt = 5;

        hr = ((PFN_STATUS)GetProcAddress(Sppc, "SLGetLicensingStatusInformation"))(Slc, NULL, &g_Sku2, NULL, &cnt, &Status);
        ok(hr == SL_E_PRODUCT_SKU_NOT_INSTALLED && cnt == 0, "status of the SKU after the uninstall: 0x%lx count %u\n", hr, cnt);
    }

    /* Closed handle */
    hr = pClose(Slc);
    ok(hr == S_OK, "SLClose returned 0x%lx\n", hr);

    FreeLibrary(Sppc);
}
