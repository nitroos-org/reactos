/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     MSXML3 schema cache: adding a loaded schema document whose XML declaration names
 *              a different encoding than the in-memory text (Click-to-Run/App-V does this with an
 *              encoding="utf-16" schema resource) must succeed.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <ole2.h>
#include <oleauto.h>

#define DEFINE_CLSID(name, a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)     static const CLSID name = { a, b, c, { d0, d1, d2, d3, d4, d5, d6, d7 } }

DEFINE_CLSID(TEST_DOMDocument30, 0xF5078F32, 0xC551, 0x11D3, 0x89, 0xB9, 0x00, 0x00, 0xF8, 0x1F, 0xE2, 0x21);
DEFINE_CLSID(TEST_XMLSchemaCache30, 0xF5078F34, 0xC551, 0x11D3, 0x89, 0xB9, 0x00, 0x00, 0xF8, 0x1F, 0xE2, 0x21);

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

static const WCHAR SchemaBody[] =
    L"<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" targetNamespace=\"urn:offbis:test\" "
    L"xmlns:t=\"urn:offbis:test\" elementFormDefault=\"qualified\">"
    L"<xs:element name=\"root\" type=\"xs:string\"/></xs:schema>";

static void TestAdd(PCWSTR Name, PCWSTR Declaration)
{
    IDispatch *Doc = NULL, *Cache = NULL;
    VARIANT Args[2], Result;
    WCHAR Text[1024];
    HRESULT hr;

    lstrcpyW(Text, Declaration);
    lstrcatW(Text, SchemaBody);

    hr = CoCreateInstance(&TEST_DOMDocument30, NULL, CLSCTX_INPROC_SERVER, &IID_IDispatch, (void **)&Doc);
    ok(hr == S_OK, "%S: CoCreateInstance(DOMDocument30) returned 0x%lx\n", Name, hr);
    hr = CoCreateInstance(&TEST_XMLSchemaCache30, NULL, CLSCTX_INPROC_SERVER, &IID_IDispatch, (void **)&Cache);
    ok(hr == S_OK, "%S: CoCreateInstance(XMLSchemaCache30) returned 0x%lx\n", Name, hr);
    if (!Doc || !Cache)
        goto done;

    VariantInit(&Args[0]);
    VariantInit(&Result);
    V_VT(&Args[0]) = VT_BSTR;
    V_BSTR(&Args[0]) = SysAllocString(Text);
    hr = Invoke(Doc, L"loadXML", DISPATCH_METHOD, Args, 1, &Result);
    ok(hr == S_OK, "%S: loadXML returned 0x%lx\n", Name, hr);
    ok(V_VT(&Result) == VT_BOOL && V_BOOL(&Result) == VARIANT_TRUE, "%S: loadXML result vt=%u\n", Name, V_VT(&Result));
    SysFreeString(V_BSTR(&Args[0]));
    VariantClear(&Result);

    /* IXMLDOMSchemaCollection::add(uri, var): args are passed last to first */
    VariantInit(&Args[0]);
    VariantInit(&Args[1]);
    V_VT(&Args[0]) = VT_DISPATCH;
    V_DISPATCH(&Args[0]) = Doc;
    V_VT(&Args[1]) = VT_BSTR;
    V_BSTR(&Args[1]) = SysAllocString(L"urn:offbis:test");
    hr = Invoke(Cache, L"add", DISPATCH_METHOD, Args, 2, &Result);
    ok(hr == S_OK, "%S: schema cache add(document) returned 0x%lx\n", Name, hr);
    SysFreeString(V_BSTR(&Args[1]));
    VariantClear(&Result);

    hr = Invoke(Cache, L"length", DISPATCH_PROPERTYGET, NULL, 0, &Result);
    ok(hr == S_OK, "%S: length returned 0x%lx\n", Name, hr);
    ok(V_VT(&Result) == VT_I4 && V_I4(&Result) == 1, "%S: length vt=%u value=%ld\n", Name, V_VT(&Result), V_I4(&Result));
    VariantClear(&Result);

done:
    if (Doc)
        Doc->lpVtbl->Release(Doc);
    if (Cache)
        Cache->lpVtbl->Release(Cache);
}

START_TEST(SchemaCache)
{
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(SUCCEEDED(hr), "CoInitializeEx returned 0x%lx\n", hr);

    TestAdd(L"no declaration", L"");
    TestAdd(L"utf-8", L"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    TestAdd(L"utf-16", L"<?xml version=\"1.0\" encoding=\"utf-16\"?>\n");
    TestAdd(L"UTF-16 + comment", L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<!-- schema resource -->\n");

    CoUninitialize();
}
