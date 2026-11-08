/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     MSXML3 selectNodes: a prefixed function call (ms:string-compare from the MSXML
 *              extension namespace urn:schemas-microsoft-com:xslt) must parse and evaluate.
 *              Click-to-Run/App-V selects its opaque directories with it, and its failure made
 *              the App-V virtual process creation (and so every Office start) fail.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <ole2.h>
#include <oleauto.h>

#define DEFINE_CLSID(name, a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)     static const CLSID name = { a, b, c, { d0, d1, d2, d3, d4, d5, d6, d7 } }

DEFINE_CLSID(TEST_DOMDocument30, 0xF5078F32, 0xC551, 0x11D3, 0x89, 0xB9, 0x00, 0x00, 0xF8, 0x1F, 0xE2, 0x21);

static HRESULT Invoke(IDispatch *Disp, PCWSTR Name, WORD Flags, VARIANT *Args, UINT ArgCount, VARIANT *Result)
{
    DISPID Id;
    DISPPARAMS Params = { Args, NULL, ArgCount, 0 };
    HRESULT hr;
    PWSTR Names[1];

    Names[0] = (PWSTR)Name;
    hr = Disp->lpVtbl->GetIDsOfNames(Disp, &IID_NULL, Names, 1, LOCALE_USER_DEFAULT, &Id);
    if (FAILED(hr))
        return hr;
    return Disp->lpVtbl->Invoke(Disp, Id, &IID_NULL, LOCALE_USER_DEFAULT, Flags, &Params, Result, NULL, NULL);
}

static const WCHAR DocText[] =
    L"<r xmlns=\"urn:t\">"
    L"<e Long=\"root\\VFS\\Common AppData\"/>"
    L"<e Long=\"Root\\vfs\\common appdata\\sub\"/>"
    L"<e Long=\"other\"/>"
    L"</r>";

/* returns the node count, or -1 when selectNodes failed */
static LONG Select(IDispatch *Doc, PCWSTR Query)
{
    VARIANT Arg, Result;
    IDispatch *List;
    HRESULT hr;
    LONG Count = -1;

    VariantInit(&Arg);
    V_VT(&Arg) = VT_BSTR;
    V_BSTR(&Arg) = SysAllocString(Query);
    VariantInit(&Result);
    hr = Invoke(Doc, L"selectNodes", DISPATCH_METHOD, &Arg, 1, &Result);
    SysFreeString(V_BSTR(&Arg));
    if (hr != S_OK || V_VT(&Result) != VT_DISPATCH)
    {
        VariantClear(&Result);
        return -1;
    }
    List = V_DISPATCH(&Result);
    VariantInit(&Arg);
    if (Invoke(List, L"length", DISPATCH_PROPERTYGET, NULL, 0, &Arg) == S_OK)
        Count = V_I4(&Arg);
    List->lpVtbl->Release(List);
    return Count;
}

START_TEST(XPathFunc)
{
    IDispatch *Doc = NULL;
    VARIANT Args[2], Result;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(SUCCEEDED(hr), "CoInitializeEx returned 0x%lx\n", hr);

    hr = CoCreateInstance(&TEST_DOMDocument30, NULL, CLSCTX_INPROC_SERVER, &IID_IDispatch, (void **)&Doc);
    ok(hr == S_OK, "CoCreateInstance(DOMDocument30) returned 0x%lx\n", hr);
    if (!Doc)
    {
        CoUninitialize();
        return;
    }

    VariantInit(&Args[0]);
    V_VT(&Args[0]) = VT_BSTR;
    V_BSTR(&Args[0]) = SysAllocString(DocText);
    VariantInit(&Result);
    hr = Invoke(Doc, L"loadXML", DISPATCH_METHOD, Args, 1, &Result);
    ok(hr == S_OK && V_BOOL(&Result) == VARIANT_TRUE, "loadXML returned 0x%lx\n", hr);
    SysFreeString(V_BSTR(&Args[0]));

    /* setProperty("SelectionLanguage", "XPath") and the two namespaces; arguments are reversed */
    V_VT(&Args[1]) = VT_BSTR;
    V_BSTR(&Args[1]) = SysAllocString(L"SelectionLanguage");
    V_VT(&Args[0]) = VT_BSTR;
    V_BSTR(&Args[0]) = SysAllocString(L"XPath");
    hr = Invoke(Doc, L"setProperty", DISPATCH_METHOD, Args, 2, NULL);
    ok(hr == S_OK, "setProperty(SelectionLanguage) returned 0x%lx\n", hr);
    SysFreeString(V_BSTR(&Args[1]));
    SysFreeString(V_BSTR(&Args[0]));

    V_VT(&Args[1]) = VT_BSTR;
    V_BSTR(&Args[1]) = SysAllocString(L"SelectionNamespaces");
    V_VT(&Args[0]) = VT_BSTR;
    V_BSTR(&Args[0]) = SysAllocString(L"xmlns:t='urn:t' xmlns:ms='urn:schemas-microsoft-com:xslt'");
    hr = Invoke(Doc, L"setProperty", DISPATCH_METHOD, Args, 2, NULL);
    ok(hr == S_OK, "setProperty(SelectionNamespaces) returned 0x%lx\n", hr);
    SysFreeString(V_BSTR(&Args[1]));
    SysFreeString(V_BSTR(&Args[0]));

    ok(Select(Doc, L"/t:r/t:e[ms:string-compare(@Long, \"root\\VFS\\Common AppData\", \"\", \"i\") = 0]") == 1,
       "case-insensitive ms:string-compare, exact text\n");
    ok(Select(Doc, L"/t:r/t:e[ms:string-compare(@Long, \"ROOT\\vfs\\COMMON appdata\", \"\", \"i\") = 0]") == 1,
       "case-insensitive ms:string-compare, other case\n");
    ok(Select(Doc, L"/t:r/t:e[ms:string-compare(@Long, \"ROOT\\vfs\\COMMON appdata\") = 0]") == 0,
       "case-sensitive ms:string-compare, other case\n");
    ok(Select(Doc, L"/t:r/t:e[ms:string-compare(@Long, \"zzz\") < 0]") == 3,
       "ms:string-compare orders strings\n");
    ok(Select(Doc, L"/t:r/t:e[(ms:string-compare(@Long, \"root\\VFS\\Common AppData\", \"\", \"i\") = 0) or "
                    L"(ms:string-compare(\"root\\VFS\\Common AppData\\\", substring(@Long, 1, 24), \"\", \"i\") = 0)]") == 2,
       "App-V opaque directory query\n");

    Doc->lpVtbl->Release(Doc);
    CoUninitialize();
}
