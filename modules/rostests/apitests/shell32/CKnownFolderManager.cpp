/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for CLSID_KnownFolderManager (in-process class registered by shell32)
 */

#include "shelltest.h"

#if DLL_EXPORT_VERSION >= 0x600 /* uses NT6 exports */

static void test_Registration(void)
{
    WCHAR buf[64];
    DWORD cb = sizeof(buf);
    LSTATUS ret = RegGetValueW(HKEY_CLASSES_ROOT,
                               L"CLSID\\{4df0c730-df9d-4ae3-9153-aa6b82e9795a}\\InprocServer32",
                               L"ThreadingModel", RRF_RT_REG_SZ, NULL, buf, &cb);
    ok_long(ret, ERROR_SUCCESS);
    if (ret == ERROR_SUCCESS)
        ok(!lstrcmpiW(buf, L"Both"), "ThreadingModel is %S\n", buf);
}

/* The Windows SDK layout: the structure is naturally aligned. Including <shlobj.h> must not byte-pack it:
   Office AppV reads pszName at offset 8 of the structure shell32 fills in */
static void test_DefinitionLayout(void)
{
#ifdef _WIN64
    ok_int((int)FIELD_OFFSET(KNOWNFOLDER_DEFINITION, pszName), 8);
    ok_int((int)FIELD_OFFSET(KNOWNFOLDER_DEFINITION, fidParent), 24);
    ok_int((int)FIELD_OFFSET(KNOWNFOLDER_DEFINITION, pszRelativePath), 40);
    ok_int((int)FIELD_OFFSET(KNOWNFOLDER_DEFINITION, dwAttributes), 88);
    ok_int((int)sizeof(KNOWNFOLDER_DEFINITION), 112);
#else
    ok_int((int)FIELD_OFFSET(KNOWNFOLDER_DEFINITION, pszName), 4);
    ok_int((int)FIELD_OFFSET(KNOWNFOLDER_DEFINITION, fidParent), 12);
    ok_int((int)sizeof(KNOWNFOLDER_DEFINITION), 76);
#endif
}

static void test_Manager(void)
{
    IKnownFolderManager *mgr = NULL;
    IClassFactory *cf = NULL;
    IUnknown *unk = NULL;
    IShellItem *item = NULL;
    IKnownFolder *folder = NULL;
    KNOWNFOLDERID *ids = NULL;
    KNOWNFOLDER_DEFINITION def;
    WCHAR windir[MAX_PATH];
    LPWSTR path = NULL;
    UINT count = 0, i, good = 0;
    HRESULT hr;

    hr = CoGetClassObject(CLSID_KnownFolderManager, CLSCTX_INPROC_SERVER, NULL, IID_IClassFactory, (void **)&cf);
    ok_hex(hr, S_OK);
    if (cf)
        cf->Release();

    hr = CoCreateInstance(CLSID_KnownFolderManager, NULL, CLSCTX_INPROC_SERVER, IID_IKnownFolderManager, (void **)&mgr);
    ok_hex(hr, S_OK);
    if (!mgr)
    {
        skip("No KnownFolderManager\n");
        return;
    }

    hr = mgr->QueryInterface(IID_IUnknown, (void **)&unk);
    ok_hex(hr, S_OK);
    if (unk)
        unk->Release();

    /* the requested interface is honoured */
    hr = CoCreateInstance(CLSID_KnownFolderManager, NULL, CLSCTX_INPROC_SERVER, IID_IUnknown, (void **)&unk);
    ok_hex(hr, S_OK);
    if (unk)
        unk->Release();
    hr = CoCreateInstance(CLSID_KnownFolderManager, NULL, CLSCTX_INPROC_SERVER, IID_IShellItem, (void **)&item);
    ok_hex(hr, E_NOINTERFACE);
    ok(item == NULL, "item = %p\n", item);

    hr = mgr->GetFolderIds(&ids, &count);
    ok_hex(hr, S_OK);
    ok(count > 0, "count = %u\n", count);
    for (i = 0; hr == S_OK && i < count; i++)
    {
        folder = NULL;
        if (SUCCEEDED(mgr->GetFolder(ids[i], &folder)) && folder)
        {
            ZeroMemory(&def, sizeof(def));
            if (folder->GetFolderDefinition(&def) == S_OK)
            {
                good++;
                ok(def.pszName && def.pszName[0], "folder %u: no name\n", i);
                CoTaskMemFree(def.pszName);
                CoTaskMemFree(def.pszDescription);
                CoTaskMemFree(def.pszRelativePath);
                CoTaskMemFree(def.pszParsingName);
                CoTaskMemFree(def.pszTooltip);
                CoTaskMemFree(def.pszLocalizedName);
                CoTaskMemFree(def.pszIcon);
                CoTaskMemFree(def.pszSecurity);
            }
            folder->Release();
        }
    }
    trace("%u of %u known folders have a definition\n", good, count);
    ok(good > 0, "no known folder has a definition\n");
    CoTaskMemFree(ids);

    folder = NULL;
    hr = mgr->GetFolder(FOLDERID_Windows, &folder);
    ok_hex(hr, S_OK);
    if (folder)
    {
        hr = folder->GetPath(0, &path);
        ok_hex(hr, S_OK);
        GetWindowsDirectoryW(windir, _countof(windir));
        if (path)
        {
            ok(!lstrcmpiW(path, windir), "got %S, expected %S\n", path, windir);
            CoTaskMemFree(path);
        }
        ZeroMemory(&def, sizeof(def));
        hr = folder ? folder->GetFolderDefinition(&def) : E_FAIL;
        ok_hex(hr, S_OK);
        if (hr == S_OK)
        {
            ok_int(def.category, KF_CATEGORY_FIXED);
            ok(def.pszName && !lstrcmpiW(def.pszName, L"Windows"), "name is %S\n", def.pszName ? def.pszName : L"(null)");
            CoTaskMemFree(def.pszName);
            CoTaskMemFree(def.pszDescription);
            CoTaskMemFree(def.pszRelativePath);
            CoTaskMemFree(def.pszParsingName);
            CoTaskMemFree(def.pszTooltip);
            CoTaskMemFree(def.pszLocalizedName);
            CoTaskMemFree(def.pszIcon);
            CoTaskMemFree(def.pszSecurity);
        }
        folder->Release();
    }

    mgr->Release();
}


/* the 139 known folders of Windows 10 (definitions taken from the oracle) */
static const GUID kfDownloads = { 0x374DE290, 0x123F, 0x4565, { 0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B } };
static const GUID kfAppDataProgramData = { 0x559D40A3, 0xA036, 0x40FA, { 0xAF, 0x61, 0x84, 0xCB, 0x43, 0x0A, 0x4D, 0x34 } };
static const GUID kfLocalAppDataLow = { 0xA520A1A4, 0x1780, 0x4FF6, { 0xBD, 0x18, 0x16, 0x73, 0x43, 0xC5, 0xAF, 0x16 } };
static const GUID kfUserProgramFiles = { 0x5CD7AEE2, 0x2219, 0x4A67, { 0xB8, 0x5D, 0x6C, 0x9C, 0xE1, 0x56, 0x60, 0xCB } };
static const GUID kfLibraries = { 0x1B3EA5DC, 0xB587, 0x4786, { 0xB4, 0xEF, 0xBD, 0x1D, 0xC3, 0x32, 0xAE, 0xAE } };
static const GUID kfSavedGames = { 0x4C5C32FF, 0xBB9D, 0x43B0, { 0xB5, 0xB4, 0x2D, 0x72, 0xE5, 0x4E, 0xAA, 0xA4 } };
static const GUID kfLinks = { 0xBFB9D5E0, 0xC6A9, 0x404C, { 0xB2, 0xB2, 0xAE, 0x6D, 0xB6, 0xAF, 0x49, 0x68 } };
static const GUID kfCameraRoll = { 0xAB5FB87B, 0x7CE2, 0x4F83, { 0x91, 0x5D, 0x55, 0x08, 0x46, 0xC9, 0x53, 0x7B } };
static const GUID kfGames = { 0xCAC52C1A, 0xB53D, 0x4EDC, { 0x92, 0xD7, 0x6B, 0x2E, 0x8A, 0xC1, 0x94, 0x34 } };
static const GUID kfDownloadsType = { 0x885A186E, 0xA440, 0x4ADA, { 0x81, 0x2B, 0xDB, 0x87, 0x1B, 0x94, 0x22, 0x59 } };

static void FreeDef(KNOWNFOLDER_DEFINITION *def)
{
    CoTaskMemFree(def->pszName);
    CoTaskMemFree(def->pszDescription);
    CoTaskMemFree(def->pszRelativePath);
    CoTaskMemFree(def->pszParsingName);
    CoTaskMemFree(def->pszTooltip);
    CoTaskMemFree(def->pszLocalizedName);
    CoTaskMemFree(def->pszIcon);
    CoTaskMemFree(def->pszSecurity);
}

static void test_Windows10Folders(void)
{
    IKnownFolderManager *mgr = NULL;
    IKnownFolder *folder = NULL;
    KNOWNFOLDERID *ids = NULL;
    KNOWNFOLDER_DEFINITION def;
    KF_REDIRECTION_CAPABILITIES caps;
    FOLDERTYPEID ftid;
    WCHAR windir[MAX_PATH], expect[MAX_PATH];
    LPWSTR path = NULL, local = NULL;
    UINT count = 0;
    int csidl;
    HRESULT hr;

    hr = CoCreateInstance(CLSID_KnownFolderManager, NULL, CLSCTX_INPROC_SERVER, IID_IKnownFolderManager, (void **)&mgr);
    ok_hex(hr, S_OK);
    if (!mgr)
        return;
    GetWindowsDirectoryW(windir, _countof(windir));

    hr = mgr->GetFolderIds(&ids, &count);
    ok_hex(hr, S_OK);
    ok_int((int)count, 139);
    CoTaskMemFree(ids);

    /* Downloads: definition as on Windows 10 */
    folder = NULL;
    hr = mgr->GetFolder(kfDownloads, &folder);
    ok_hex(hr, S_OK);
    if (folder)
    {
        ZeroMemory(&def, sizeof(def));
        hr = folder->GetFolderDefinition(&def);
        ok_hex(hr, S_OK);
        if (hr == S_OK)
        {
            ok_int(def.category, KF_CATEGORY_PERUSER);
            ok(def.pszName && !lstrcmpW(def.pszName, L"Downloads"), "name is %S\n", def.pszName ? def.pszName : L"(null)");
            ok(def.pszRelativePath && !lstrcmpW(def.pszRelativePath, L"Downloads"), "path is %S\n", def.pszRelativePath ? def.pszRelativePath : L"(null)");
            ok(IsEqualGUID(def.fidParent, FOLDERID_Profile), "parent is not the profile\n");
            ok_hex(def.dwAttributes, FILE_ATTRIBUTE_READONLY);
            ok_hex((DWORD)def.kfdFlags, KFDF_ROAMABLE | KFDF_PRECREATE | KFDF_PUBLISHEXPANDEDPATH);
            ok(IsEqualGUID(def.ftidType, kfDownloadsType), "wrong folder type\n");
            FreeDef(&def);
        }
        hr = folder->GetFolderType(&ftid);
        ok_hex(hr, S_OK);
        ok(IsEqualGUID(ftid, kfDownloadsType), "wrong folder type\n");
        hr = folder->GetRedirectionCapabilities(&caps);
        ok_hex(hr, S_OK);
        ok_hex(caps, KF_REDIRECTION_CAPABILITIES_REDIRECTABLE);
        folder->Release();
    }

    /* the folders known by their definition only: the path is the parent and the relative path */
    hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY, NULL, &local);
    ok_hex(hr, S_OK);
    if (local)
    {
        path = NULL;
        hr = SHGetKnownFolderPath(kfAppDataProgramData, KF_FLAG_DONT_VERIFY, NULL, &path);
        ok_hex(hr, S_OK);
        wsprintfW(expect, L"%s\\ProgramData", local);
        ok(path && !lstrcmpiW(path, expect), "got %S, expected %S\n", path ? path : L"(null)", expect);
        CoTaskMemFree(path);

        path = NULL;
        hr = SHGetKnownFolderPath(kfLocalAppDataLow, KF_FLAG_DONT_VERIFY, NULL, &path);
        ok_hex(hr, S_OK);
        if (path)
        {
            /* the profile folder and AppData\LocalLow */
            ok(wcsstr(path, L"\\AppData\\LocalLow") != NULL, "got %S\n", path);
        }
        CoTaskMemFree(path);
        CoTaskMemFree(local);
    }

    path = NULL;
    hr = SHGetKnownFolderPath(kfSavedGames, KF_FLAG_DONT_VERIFY, NULL, &path);
    ok_hex(hr, S_OK);
    ok(path && wcsstr(path, L"Saved Games"), "got %S\n", path ? path : L"(null)");
    CoTaskMemFree(path);

    path = NULL;
    hr = SHGetKnownFolderPath(kfLinks, KF_FLAG_DONT_VERIFY, NULL, &path);
    ok_hex(hr, S_OK);
    ok(path && wcsstr(path, L"\\Links"), "got %S\n", path ? path : L"(null)");
    CoTaskMemFree(path);

    path = NULL;
    hr = SHGetKnownFolderPath(kfUserProgramFiles, KF_FLAG_DONT_VERIFY, NULL, &path);
    ok_hex(hr, S_OK);
    ok(path && wcsstr(path, L"Programs"), "got %S\n", path ? path : L"(null)");
    CoTaskMemFree(path);

    path = NULL;
    hr = SHGetKnownFolderPath(kfLibraries, KF_FLAG_DONT_VERIFY, NULL, &path);
    ok_hex(hr, S_OK);
    ok(path && wcsstr(path, L"Microsoft\\Windows\\Libraries"), "got %S\n", path ? path : L"(null)");
    CoTaskMemFree(path);

    path = NULL;
    hr = SHGetKnownFolderPath(kfCameraRoll, KF_FLAG_DONT_VERIFY, NULL, &path);
    ok_hex(hr, S_OK);
    ok(path && wcsstr(path, L"Pictures\\Camera Roll"), "got %S\n", path ? path : L"(null)");
    CoTaskMemFree(path);

    /* a virtual folder has no path */
    path = (LPWSTR)(ULONG_PTR)0xdeadbeef;
    hr = SHGetKnownFolderPath(FOLDERID_ComputerFolder, 0, NULL, &path);
    ok_hex(hr, E_FAIL);

    /* the Windows folder: not redirectable, no CSIDL after CSIDL_CDBURN_AREA */
    folder = NULL;
    hr = mgr->GetFolder(FOLDERID_Windows, &folder);
    ok_hex(hr, S_OK);
    if (folder)
    {
        caps = (KF_REDIRECTION_CAPABILITIES)0xdead;
        hr = folder->GetRedirectionCapabilities(&caps);
        ok_hex(hr, S_OK);
        ok_hex(caps, 0);
        hr = folder->SetPath(0, windir);
        ok_hex(hr, E_INVALIDARG);
        hr = folder->GetFolderType(&ftid);
        ok_hex(hr, E_FAIL);
        folder->Release();
    }
    csidl = 1234;
    hr = mgr->FolderIdToCsidl(kfDownloads, &csidl);
    ok_hex(hr, E_INVALIDARG);
    ok_int(csidl, -1);

    /* Windows 10 does not know the folders of Windows Vista and 7 that it dropped */
    folder = NULL;
    hr = mgr->GetFolder(kfGames, &folder);
    ok_hex(hr, E_INVALIDARG);
    if (folder)
        folder->Release();

    mgr->Release();
}

START_TEST(CKnownFolderManager)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok_hex(hr, S_OK);

    test_Registration();
    test_DefinitionLayout();
    test_Manager();
    test_Windows10Folders();

    CoUninitialize();
}

#else

START_TEST(CKnownFolderManager)
{
    skip("CKnownFolderManager needs the NT6 exports\n");
}

#endif
