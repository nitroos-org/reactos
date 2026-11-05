/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that the type library of hnetcfg.dll is registered and complete: LoadRegTypeLib,
 *              GetTypeInfoOfGuid, and IDispatch on the firewall objects (PowerShell/VBScript late binding)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <ole2.h>
#include <oleauto.h>

/* NetFwPublicTypeLib 1.0 and NATUPNPLib 1.0 */
static const GUID LibNetFw = {0xdb4f3345, 0x3ef8, 0x45ed, {0xb9, 0x76, 0x25, 0xa6, 0xd3, 0xb8, 0x1b, 0x71}};
static const GUID LibNat = {0x1c565858, 0xf302, 0x471e, {0xb4, 0x09, 0xf1, 0x80, 0xaa, 0x4a, 0xbe, 0xc6}};

static const struct
{
    const char *Name;
    GUID Iid;
} NetFwTypes[] =
{
    { "INetFwRule",                  {0xaf230d27, 0xbaba, 0x4e42, {0xac, 0xed, 0xf5, 0x24, 0xf2, 0x2c, 0xfc, 0xe2}} },
    { "INetFwRules",                 {0x9c4c6277, 0x5027, 0x441e, {0xaf, 0xae, 0xca, 0x1f, 0x54, 0x2d, 0xa0, 0x09}} },
    { "INetFwPolicy2",               {0x98325047, 0xc671, 0x4174, {0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86}} },
    { "INetFwMgr",                   {0xf7898af5, 0xcac4, 0x4632, {0xa2, 0xec, 0xda, 0x06, 0xe5, 0x11, 0x1a, 0xf2}} },
    { "INetFwPolicy",                {0xd46d2478, 0x9ac9, 0x4008, {0x9d, 0xc7, 0x55, 0x63, 0xce, 0x55, 0x36, 0xcc}} },
    { "INetFwProfile",               {0x174a0dda, 0xe9f9, 0x449d, {0x99, 0x3b, 0x21, 0xab, 0x66, 0x7c, 0xa4, 0x56}} },
    { "INetFwOpenPort",              {0xe0483ba0, 0x47ff, 0x4d9c, {0xa6, 0xd6, 0x77, 0x41, 0xd0, 0xb1, 0x95, 0xf7}} },
    { "INetFwAuthorizedApplication", {0xb5e64ffa, 0xc2c5, 0x444e, {0xa3, 0x01, 0xfb, 0x5e, 0x00, 0x01, 0x80, 0x50}} },
};

static HRESULT
GetDispProp(IDispatch *Object, PCWSTR Name, VARIANT *Result)
{
    DISPPARAMS Params = { NULL, NULL, 0, 0 };
    PWSTR NameCopy = (PWSTR)Name;
    DISPID Id;
    HRESULT hr;

    VariantInit(Result);
    hr = IDispatch_GetIDsOfNames(Object, &IID_NULL, &NameCopy, 1, LOCALE_USER_DEFAULT, &Id);
    if (FAILED(hr))
        return hr;
    return IDispatch_Invoke(Object, Id, &IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET, &Params, Result, NULL, NULL);
}

static void
TestTypeLibs(void)
{
    ITypeLib *Lib;
    ITypeInfo *Info;
    TLIBATTR *Attr;
    HRESULT hr;
    ULONG i;

    hr = LoadRegTypeLib(&LibNetFw, 1, 0, LOCALE_SYSTEM_DEFAULT, &Lib);
    ok(hr == S_OK, "LoadRegTypeLib(NetFwPublicTypeLib) returned %08lx\n", hr);
    if (hr == S_OK)
    {
        hr = ITypeLib_GetLibAttr(Lib, &Attr);
        ok(hr == S_OK, "GetLibAttr returned %08lx\n", hr);
        if (hr == S_OK)
        {
            ok(IsEqualGUID(&Attr->guid, &LibNetFw), "wrong LIBID\n");
            ok(Attr->wMajorVerNum == 1 && Attr->wMinorVerNum == 0, "version %u.%u\n", Attr->wMajorVerNum, Attr->wMinorVerNum);
            ITypeLib_ReleaseTLibAttr(Lib, Attr);
        }
        for (i = 0; i < ARRAYSIZE(NetFwTypes); ++i)
        {
            Info = NULL;
            hr = ITypeLib_GetTypeInfoOfGuid(Lib, &NetFwTypes[i].Iid, &Info);
            ok(hr == S_OK, "GetTypeInfoOfGuid(%s) returned %08lx\n", NetFwTypes[i].Name, hr);
            if (Info)
                ITypeInfo_Release(Info);
        }
        ITypeLib_Release(Lib);
    }

    hr = LoadRegTypeLib(&LibNat, 1, 0, LOCALE_SYSTEM_DEFAULT, &Lib);
    ok(hr == S_OK, "LoadRegTypeLib(NATUPNPLib) returned %08lx\n", hr);
    if (hr == S_OK)
        ITypeLib_Release(Lib);
}

static void
TestDispatch(PCWSTR ProgId, UINT ExpectedTypeInfo)
{
    IDispatch *Disp = NULL;
    ITypeInfo *Info = NULL;
    CLSID Clsid;
    UINT Count = 99;
    HRESULT hr;

    hr = CLSIDFromProgID(ProgId, &Clsid);
    ok(hr == S_OK, "%ls: CLSIDFromProgID returned %08lx\n", ProgId, hr);
    if (hr != S_OK)
        return;
    hr = CoCreateInstance(&Clsid, NULL, CLSCTX_INPROC_SERVER, &IID_IDispatch, (void **)&Disp);
    ok(hr == S_OK, "%ls: CoCreateInstance returned %08lx\n", ProgId, hr);
    if (hr != S_OK)
        return;

    hr = IDispatch_GetTypeInfoCount(Disp, &Count);
    ok(hr == S_OK && Count == ExpectedTypeInfo, "%ls: GetTypeInfoCount returned %08lx, %u\n", ProgId, hr, Count);
    hr = IDispatch_GetTypeInfo(Disp, 0, LOCALE_USER_DEFAULT, &Info);
    ok(hr == S_OK, "%ls: GetTypeInfo returned %08lx\n", ProgId, hr);
    if (Info)
        ITypeInfo_Release(Info);
    IDispatch_Release(Disp);
}

static void
TestLateBound(void)
{
    IDispatch *Policy = NULL, *Rules, *Mgr = NULL, *Local, *Profile;
    VARIANT Var;
    CLSID Clsid;
    HRESULT hr;

    hr = CLSIDFromProgID(L"HNetCfg.FwPolicy2", &Clsid);
    if (hr == S_OK)
        hr = CoCreateInstance(&Clsid, NULL, CLSCTX_INPROC_SERVER, &IID_IDispatch, (void **)&Policy);
    ok(hr == S_OK, "HNetCfg.FwPolicy2 returned %08lx\n", hr);
    if (Policy)
    {
        hr = GetDispProp(Policy, L"Rules", &Var);
        ok(hr == S_OK && V_VT(&Var) == VT_DISPATCH, "Rules returned %08lx, vt %u\n", hr, V_VT(&Var));
        if (hr == S_OK && V_VT(&Var) == VT_DISPATCH)
        {
            Rules = V_DISPATCH(&Var);
            hr = GetDispProp(Rules, L"Count", &Var);
            ok(hr == S_OK && V_VT(&Var) == VT_I4, "Rules.Count returned %08lx, vt %u\n", hr, V_VT(&Var));
            IDispatch_Release(Rules);
        }
        IDispatch_Release(Policy);
    }

    hr = CLSIDFromProgID(L"HNetCfg.FwMgr", &Clsid);
    if (hr == S_OK)
        hr = CoCreateInstance(&Clsid, NULL, CLSCTX_INPROC_SERVER, &IID_IDispatch, (void **)&Mgr);
    ok(hr == S_OK, "HNetCfg.FwMgr returned %08lx\n", hr);
    if (!Mgr)
        return;
    hr = GetDispProp(Mgr, L"LocalPolicy", &Var);
    ok(hr == S_OK && V_VT(&Var) == VT_DISPATCH, "LocalPolicy returned %08lx, vt %u\n", hr, V_VT(&Var));
    if (hr == S_OK && V_VT(&Var) == VT_DISPATCH)
    {
        Local = V_DISPATCH(&Var);
        hr = GetDispProp(Local, L"CurrentProfile", &Var);
        ok(hr == S_OK && V_VT(&Var) == VT_DISPATCH, "CurrentProfile returned %08lx, vt %u\n", hr, V_VT(&Var));
        if (hr == S_OK && V_VT(&Var) == VT_DISPATCH)
        {
            Profile = V_DISPATCH(&Var);
            hr = GetDispProp(Profile, L"FirewallEnabled", &Var);
            ok(hr == S_OK && V_VT(&Var) == VT_BOOL, "FirewallEnabled returned %08lx, vt %u\n", hr, V_VT(&Var));
            IDispatch_Release(Profile);
        }
        IDispatch_Release(Local);
    }
    IDispatch_Release(Mgr);
}

START_TEST(HnetcfgTypeLib)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    ok(SUCCEEDED(hr), "CoInitializeEx returned %08lx\n", hr);
    TestTypeLibs();
    TestDispatch(L"HNetCfg.FwPolicy2", 1);
    TestDispatch(L"HNetCfg.FwMgr", 1);
    TestDispatch(L"HNetCfg.FwRule", 1);
    TestLateBound();
    CoUninitialize();
}
