/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for FolderItems::_NewEnum (the IEnumVARIANT for-each walks) and the
 *              parameter names of the Shell.Application typelib
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "shelltest.h"
#include <shldisp.h>
#include <strsafe.h>

static WCHAR g_Dir[MAX_PATH];

static void MakeFiles(void)
{
    WCHAR Path[MAX_PATH];
    int i;

    GetTempPathW(MAX_PATH, g_Dir);
    StringCchPrintfW(g_Dir + lstrlenW(g_Dir), MAX_PATH - lstrlenW(g_Dir), L"folderitems%lu", GetCurrentProcessId());
    CreateDirectoryW(g_Dir, NULL);
    for (i = 1; i <= 3; i++)
    {
        StringCchPrintfW(Path, MAX_PATH, L"%s\\file%d", g_Dir, i);
        HANDLE File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (File != INVALID_HANDLE_VALUE)
            CloseHandle(File);
    }
}

static void DeleteFiles(void)
{
    WCHAR Path[MAX_PATH];
    int i;

    for (i = 1; i <= 3; i++)
    {
        StringCchPrintfW(Path, MAX_PATH, L"%s\\file%d", g_Dir, i);
        DeleteFileW(Path);
    }
    RemoveDirectoryW(g_Dir);
}

/* Name of the FolderItem in a VT_DISPATCH variant, "" when it is none */
static void ItemName(const VARIANT *pVar, WCHAR *Name)
{
    FolderItem *pItem = NULL;
    BSTR bs = NULL;

    Name[0] = 0;
    if (V_VT(pVar) != VT_DISPATCH || !V_DISPATCH(pVar))
        return;
    if (SUCCEEDED(V_DISPATCH(pVar)->QueryInterface(IID_FolderItem, (void **)&pItem)))
    {
        if (SUCCEEDED(pItem->get_Name(&bs)) && bs)
            lstrcpynW(Name, bs, 32);
        SysFreeString(bs);
        pItem->Release();
    }
}

static void TestEnum(FolderItems *pItems)
{
    IUnknown *pUnk = NULL;
    IEnumVARIANT *pEnum = NULL, *pClone = NULL;
    VARIANT Var[4];
    WCHAR Name[32];
    ULONG Fetched;
    HRESULT hr;
    long Count = -1;
    int i;

    hr = pItems->get_Count(&Count);
    ok_long(hr, S_OK);
    ok_long(Count, 3);

    hr = pItems->_NewEnum(&pUnk);
    ok_long(hr, S_OK);
    if (!pUnk)
        return;
    hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void **)&pEnum);
    ok_long(hr, S_OK);
    pUnk->Release();
    if (!pEnum)
        return;

    /* one at a time, in the order of the folder */
    for (i = 1; i <= 3; i++)
    {
        WCHAR Expected[16];
        StringCchPrintfW(Expected, 16, L"file%d", i);
        VariantInit(&Var[0]);
        Fetched = 99;
        hr = pEnum->Next(1, Var, &Fetched);
        ok_long(hr, S_OK);
        ok_long(Fetched, 1);
        ok_int(V_VT(&Var[0]), VT_DISPATCH);
        ItemName(&Var[0], Name);
        ok(!lstrcmpiW(Name, Expected), "item %d is \"%ls\", expected \"%ls\"\n", i, Name, Expected);
        VariantClear(&Var[0]);
    }
    VariantInit(&Var[0]);
    Fetched = 99;
    hr = pEnum->Next(1, Var, &Fetched);
    ok_long(hr, S_FALSE);
    ok_long(Fetched, 0);

    /* Reset, then all of them in one call */
    hr = pEnum->Reset();
    ok_long(hr, S_OK);
    for (i = 0; i < 4; i++)
        VariantInit(&Var[i]);
    Fetched = 99;
    hr = pEnum->Next(3, Var, &Fetched);
    ok_long(hr, S_OK);
    ok_long(Fetched, 3);
    for (i = 0; i < 3; i++)
        VariantClear(&Var[i]);

    /* asking for more than there are is a S_FALSE (what comes with it is not specified: Windows
     * returns nothing at all, the documented contract is the three) */
    pEnum->Reset();
    for (i = 0; i < 4; i++)
        VariantInit(&Var[i]);
    Fetched = 99;
    hr = pEnum->Next(4, Var, &Fetched);
    ok_long(hr, S_FALSE);
    ok(Fetched <= 3, "fetched %lu\n", Fetched);
    for (i = 0; i < 4; i++)
        VariantClear(&Var[i]);

    /* Skip, and a clone (Windows restarts the clone, the contract says it continues: only that
     * it works and yields items is checked) */
    pEnum->Reset();
    hr = pEnum->Skip(1);
    ok_long(hr, S_OK);
    hr = pEnum->Clone(&pClone);
    ok_long(hr, S_OK);
    VariantInit(&Var[0]);
    hr = pEnum->Next(1, Var, &Fetched);
    ok_long(hr, S_OK);
    ItemName(&Var[0], Name);
    ok(!lstrcmpiW(Name, L"file2"), "after Skip: \"%ls\"\n", Name);
    VariantClear(&Var[0]);
    if (pClone)
    {
        VariantInit(&Var[0]);
        hr = pClone->Next(1, Var, &Fetched);
        ok_long(hr, S_OK);
        ItemName(&Var[0], Name);
        ok(!lstrcmpiW(Name, L"file1") || !lstrcmpiW(Name, L"file2"), "clone: \"%ls\"\n", Name);
        VariantClear(&Var[0]);
        pClone->Release();
    }

    /* a NULL fetched count is for one element only */
    pEnum->Reset();
    VariantInit(&Var[0]);
    hr = pEnum->Next(1, Var, NULL);
    ok_long(hr, S_OK);
    VariantClear(&Var[0]);
    pEnum->Release();
}

/* What for-each does: Invoke(DISPID_NEWENUM) on the collection */
static void TestNewEnumDispatch(FolderItems *pItems)
{
    IDispatch *pDisp = NULL;
    IUnknown *pUnk = NULL;
    IEnumVARIANT *pEnum = NULL;
    DISPPARAMS Params = { NULL, NULL, 0, 0 };
    VARIANT Result;
    HRESULT hr;

    hr = pItems->QueryInterface(IID_IDispatch, (void **)&pDisp);
    ok_long(hr, S_OK);
    if (!pDisp)
        return;
    VariantInit(&Result);
    hr = pDisp->Invoke(DISPID_NEWENUM, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD | DISPATCH_PROPERTYGET,
                       &Params, &Result, NULL, NULL);
    ok_long(hr, S_OK);
    if (SUCCEEDED(hr))
    {
        pUnk = V_VT(&Result) == VT_UNKNOWN ? V_UNKNOWN(&Result) : (V_VT(&Result) == VT_DISPATCH ? V_DISPATCH(&Result) : NULL);
        ok(pUnk != NULL, "DISPID_NEWENUM returned vt %d\n", V_VT(&Result));
        if (pUnk)
        {
            hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void **)&pEnum);
            ok_long(hr, S_OK);
            if (pEnum)
                pEnum->Release();
        }
    }
    VariantClear(&Result);
    pDisp->Release();
}

/* The names of the parameters come from the typelib, and scripts print them (PowerShell's ToString) */
static void TestParameterNames(IShellDispatch *pSD)
{
    static const struct
    {
        PCWSTR Method;
        PCWSTR Names[6];
    } Cases[] =
    {
        { L"AddToRecent", { L"AddToRecent", L"varFile", L"bstrCategory", NULL } },
        { L"ControlPanelItem", { L"ControlPanelItem", L"bstrDir", NULL } },
        { L"ShellExecute", { L"ShellExecute", L"File", L"vArgs", L"vDir", L"vOperation", L"vShow" } },
        { L"ExplorerPolicy", { L"ExplorerPolicy", L"bstrPolicyName", NULL } },
        { L"GetSetting", { L"GetSetting", L"lSetting", NULL } },
        { L"IsRestricted", { L"IsRestricted", L"Group", L"Restriction", NULL } },
        { L"ServiceStart", { L"ServiceStart", L"ServiceName", L"Persistent", NULL } },
        { L"ShowBrowserBar", { L"ShowBrowserBar", L"bstrClsid", L"bShow", NULL } },
    };
    IDispatch *pDisp = NULL;
    ITypeInfo *pTI = NULL;
    HRESULT hr;
    int i, n;

    hr = pSD->QueryInterface(IID_IDispatch, (void **)&pDisp);
    if (FAILED(hr))
        return;
    hr = pDisp->GetTypeInfo(0, LOCALE_USER_DEFAULT, &pTI);
    ok_long(hr, S_OK);
    if (pTI)
    {
        for (i = 0; i < (int)ARRAYSIZE(Cases); i++)
        {
            BSTR Names[6] = { 0 };
            UINT Got = 0;
            PWSTR Method = (PWSTR)Cases[i].Method;
            MEMBERID Id;

            hr = pTI->GetIDsOfNames(&Method, 1, &Id);
            ok(hr == S_OK, "%ls: GetIDsOfNames 0x%08lx\n", Cases[i].Method, hr);
            if (hr != S_OK)
                continue;
            hr = pTI->GetNames(Id, Names, 6, &Got);
            ok(hr == S_OK, "%ls: GetNames 0x%08lx\n", Cases[i].Method, hr);
            for (n = 0; hr == S_OK && n < (int)Got && Cases[i].Names[n]; n++)
                ok(!lstrcmpW(Names[n], Cases[i].Names[n]), "%ls: name %d is \"%ls\", expected \"%ls\"\n",
                   Cases[i].Method, n, Names[n], Cases[i].Names[n]);
            for (n = 0; n < (int)Got; n++)
                SysFreeString(Names[n]);
        }
        pTI->Release();
    }
    pDisp->Release();
}

/* FolderItemVerbs::_NewEnum: for-each over $item.Verbs(). Windows Server 2022: one element per menu item, Count of
 * them (12 for notepad.exe: the separators come as verbs with an empty name), FolderItemVerb objects; Item(Count) is
 * an empty verb and Item(Count + 1) is nothing, but neither is part of the enumeration. */
static void TestVerbsEnum(FolderItems *pItems)
{
    FolderItem *pItem = NULL;
    FolderItemVerbs *pVerbs = NULL;
    IUnknown *pUnk = NULL;
    IEnumVARIANT *pEnum = NULL, *pClone = NULL;
    VARIANT Var[2], Index;
    ULONG Fetched;
    HRESULT hr;
    long Count = -1;
    int Seen = 0;

    V_VT(&Index) = VT_I4;
    V_I4(&Index) = 0;
    hr = pItems->Item(Index, &pItem);
    ok_long(hr, S_OK);
    if (!pItem)
        return;
    hr = pItem->Verbs(&pVerbs);
    ok_long(hr, S_OK);
    pItem->Release();
    if (!pVerbs)
        return;
    hr = pVerbs->get_Count(&Count);
    ok_long(hr, S_OK);
    if (Count <= 0)
    {
        skip("the item has no verbs\n");
        pVerbs->Release();
        return;
    }

    hr = pVerbs->_NewEnum(&pUnk);
    ok_long(hr, S_OK);
    if (!pUnk)
    {
        pVerbs->Release();
        return;
    }
    hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void **)&pEnum);
    ok_long(hr, S_OK);
    pUnk->Release();
    if (pEnum)
    {
        for (;;)
        {
            VariantInit(&Var[0]);
            Fetched = 99;
            hr = pEnum->Next(1, Var, &Fetched);
            if (hr != S_OK)
            {
                ok_long(hr, S_FALSE);
                ok_long(Fetched, 0);
                break;
            }
            ok_long(Fetched, 1);
            ok_int(V_VT(&Var[0]), VT_DISPATCH);
            if (V_VT(&Var[0]) == VT_DISPATCH && V_DISPATCH(&Var[0]))
            {
                FolderItemVerb *pVerb = NULL;
                BSTR Name = NULL;

                hr = V_DISPATCH(&Var[0])->QueryInterface(IID_FolderItemVerb, (void **)&pVerb);
                ok_long(hr, S_OK);
                if (pVerb)
                {
                    hr = pVerb->get_Name(&Name);
                    ok_long(hr, S_OK);
                    ok(Name != NULL, "verb %d has no name string\n", Seen);
                    SysFreeString(Name);
                    pVerb->Release();
                }
            }
            VariantClear(&Var[0]);
            Seen++;
            if (Seen > Count + 2)
                break;
        }
        ok(Seen == Count, "the enumerator gave %d elements, Count is %ld\n", Seen, Count);

        /* Reset, then everything in one call; asking for more is S_FALSE */
        hr = pEnum->Reset();
        ok_long(hr, S_OK);
        Fetched = 99;
        VariantInit(&Var[0]);
        VariantInit(&Var[1]);
        hr = pEnum->Skip(Count);
        ok_long(hr, S_OK);
        hr = pEnum->Next(1, Var, &Fetched);
        ok_long(hr, S_FALSE);
        ok_long(Fetched, 0);
        hr = pEnum->Reset();
        hr = pEnum->Skip(1);
        ok_long(hr, S_OK);
        hr = pEnum->Clone(&pClone);
        ok_long(hr, S_OK);
        if (pClone)
        {
            Fetched = 99;
            hr = pClone->Next(1, Var, &Fetched);
            ok_long(hr, S_OK);
            ok_long(Fetched, 1);
            VariantClear(&Var[0]);
            pClone->Release();
        }
        pEnum->Release();
    }

    /* what for-each does: Invoke(DISPID_NEWENUM) */
    {
        IDispatch *pDisp = NULL;
        DISPPARAMS Params = { NULL, NULL, 0, 0 };
        VARIANT Result;

        if (SUCCEEDED(pVerbs->QueryInterface(IID_IDispatch, (void **)&pDisp)))
        {
            VariantInit(&Result);
            hr = pDisp->Invoke(DISPID_NEWENUM, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD | DISPATCH_PROPERTYGET,
                               &Params, &Result, NULL, NULL);
            ok_long(hr, S_OK);
            VariantClear(&Result);
            pDisp->Release();
        }
    }
    pVerbs->Release();
}

START_TEST(CFolderItems)
{
    IShellDispatch *pSD = NULL;
    Folder *pFolder = NULL;
    FolderItems *pItems = NULL;
    VARIANT vDir;
    HRESULT hr;

    CoInitialize(NULL);
    hr = CoCreateInstance(CLSID_Shell, NULL, CLSCTX_ALL, IID_IShellDispatch, (void **)&pSD);
    if (FAILED(hr))
    {
        skip("Shell.Application is not available: 0x%08lx\n", hr);
        CoUninitialize();
        return;
    }

    TestParameterNames(pSD);

    MakeFiles();
    V_VT(&vDir) = VT_BSTR;
    V_BSTR(&vDir) = SysAllocString(g_Dir);
    hr = pSD->NameSpace(vDir, &pFolder);
    ok_long(hr, S_OK);
    VariantClear(&vDir);
    if (pFolder)
    {
        hr = pFolder->Items(&pItems);
        ok_long(hr, S_OK);
        if (pItems)
        {
            TestEnum(pItems);
            TestNewEnumDispatch(pItems);
            TestVerbsEnum(pItems);
            pItems->Release();
        }
        pFolder->Release();
    }
    DeleteFiles();

    pSD->Release();
    CoUninitialize();
}
