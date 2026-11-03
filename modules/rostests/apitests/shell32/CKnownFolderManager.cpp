/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for CLSID_KnownFolderManager (in-process class registered by shell32)
 */

#include "shelltest.h"

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
        folder->Release();
    }

    mgr->Release();
}

START_TEST(CKnownFolderManager)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok_hex(hr, S_OK);

    test_Registration();
    test_Manager();

    CoUninitialize();
}
