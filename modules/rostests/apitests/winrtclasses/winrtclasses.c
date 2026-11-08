/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the Windows Runtime classes Windows.Networking.Connectivity.NetworkInformation,
 *              Windows.Security.Authentication.OnlineId.OnlineIdSystemAuthenticator (and its ticket request) and
 *              Windows.Globalization.Language
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The interface IIDs and the member order are those of the public Windows Runtime IDL of Wine
 * (include/windows.networking.connectivity.idl, windows.security.authentication.onlineid.idl, windows.globalization.idl).
 * The registry values of each class (DllPath, ActivationType, Threading, TrustLevel) were measured on Windows 10 22H2.
 * Every test skips where the class is not registered, so the file also runs on systems without the class.
 */

#define COBJMACROS
#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <winreg.h>
#include <objbase.h>
#include <initguid.h>
#include <winstring.h>

typedef HRESULT (WINAPI *PFN_RO_INIT)(int);
typedef HRESULT (WINAPI *PFN_RO_GETAF)(HSTRING, REFIID, void **);
typedef HRESULT (WINAPI *PFN_WCS)(LPCWSTR, UINT32, HSTRING *);
typedef HRESULT (WINAPI *PFN_WDS)(HSTRING);
typedef LPCWSTR (WINAPI *PFN_WGSRB)(HSTRING, UINT32 *);

static PFN_RO_GETAF pRoGetActivationFactory;
static PFN_WCS pWindowsCreateString;
static PFN_WDS pWindowsDeleteString;
static PFN_WGSRB pWindowsGetStringRawBuffer;
static BOOL Inited;

DEFINE_GUID(IID_IAF, 0x00000035, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);
DEFINE_GUID(IID_IAgile, 0x94ea2b94, 0xe9cc, 0x49e0, 0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90);
DEFINE_GUID(IID_INetworkInformationStatics_, 0x5074f851, 0x950d, 0x4165, 0x9c, 0x15, 0x36, 0x56, 0x19, 0x48, 0x1e, 0xea);
DEFINE_GUID(IID_IOnlineIdSystemAuthenticatorStatics_, 0x85047792, 0xf634, 0x41e3, 0x96, 0xa4, 0x51, 0x64, 0xe9, 0x02, 0xc7, 0x40);
DEFINE_GUID(IID_ILanguageStatics_, 0xb23cd557, 0x0865, 0x46d4, 0x89, 0xb8, 0xd5, 0x9b, 0xe8, 0x99, 0x0f, 0x0d);
DEFINE_GUID(IID_ILanguageFactory_, 0x9b0252ac, 0x0c27, 0x44f8, 0xb7, 0x92, 0x97, 0x93, 0xfb, 0x66, 0xc6, 0x3e);
DEFINE_GUID(IID_ILanguage_, 0xea79a752, 0xf7c2, 0x4265, 0xb1, 0xbd, 0xc4, 0xde, 0xc4, 0xe4, 0xf0, 0x80);
DEFINE_GUID(IID_IOnlineIdServiceTicketRequestFactory_, 0xbebb0a08, 0x9e73, 0x4077, 0x96, 0x14, 0x08, 0x61, 0x4c, 0x0b, 0xc2, 0x45);
DEFINE_GUID(IID_Unlisted, 0x12345678, 0x9abc, 0xdef0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0);

/* Every Windows Runtime object is an IUnknown with IInspectable's three methods; raw slot calls need no headers */
#define VTBL(o) (*(void ***)(o))
typedef HRESULT (STDMETHODCALLTYPE *PFN_QI)(void *, REFIID, void **);
typedef ULONG (STDMETHODCALLTYPE *PFN_REF)(void *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_GETIIDS)(void *, ULONG *, IID **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_GETNAME)(void *, HSTRING *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_GETTRUST)(void *, int *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_OUT)(void *, void *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_HSTR_OUT)(void *, HSTRING, void *);

#define QI(o, iid, out) ((PFN_QI)VTBL(o)[0])(o, iid, out)
#define ADDREF(o) ((PFN_REF)VTBL(o)[1])(o)
#define RELEASE(o) ((PFN_REF)VTBL(o)[2])(o)
#define GETNAME(o, out) ((PFN_GETNAME)VTBL(o)[4])(o, out)
#define GETTRUST(o, out) ((PFN_GETTRUST)VTBL(o)[5])(o, out)

static BOOL Init(void)
{
    HMODULE combase;
    PFN_RO_INIT pRoInitialize;

    if (Inited)
        return pRoGetActivationFactory != NULL;
    Inited = TRUE;
    combase = LoadLibraryW(L"combase.dll");
    if (!combase)
        return FALSE;
    pRoInitialize = (PFN_RO_INIT)GetProcAddress(combase, "RoInitialize");
    pRoGetActivationFactory = (PFN_RO_GETAF)GetProcAddress(combase, "RoGetActivationFactory");
    pWindowsCreateString = (PFN_WCS)GetProcAddress(combase, "WindowsCreateString");
    pWindowsDeleteString = (PFN_WDS)GetProcAddress(combase, "WindowsDeleteString");
    pWindowsGetStringRawBuffer = (PFN_WGSRB)GetProcAddress(combase, "WindowsGetStringRawBuffer");
    if (!pRoInitialize || !pRoGetActivationFactory || !pWindowsCreateString || !pWindowsDeleteString || !pWindowsGetStringRawBuffer)
    {
        pRoGetActivationFactory = NULL;
        return FALSE;
    }
    pRoInitialize(1 /* RO_INIT_MULTITHREADED */);
    return TRUE;
}

static HSTRING Str(const WCHAR *s)
{
    HSTRING h = NULL;
    HRESULT hr = pWindowsCreateString(s, (UINT32)wcslen(s), &h);
    ok(hr == S_OK, "WindowsCreateString(%ls) returned 0x%08lx\n", s, hr);
    return h;
}

/* Returns the factory, or NULL after skipping the test when the class is not registered */
static void *GetFactory(const WCHAR *cls, REFIID iid, HRESULT *phr)
{
    HSTRING name;
    void *obj = NULL;
    HRESULT hr;

    if (!Init())
    {
        skip("combase.dll has no Windows Runtime activation\n");
        return NULL;
    }
    name = Str(cls);
    hr = pRoGetActivationFactory(name, iid, &obj);
    pWindowsDeleteString(name);
    if (phr)
        *phr = hr;
    if (hr == REGDB_E_CLASSNOTREG)
    {
        skip("%ls is not registered\n", cls);
        return NULL;
    }
    return SUCCEEDED(hr) ? obj : NULL;
}

static void CheckString(HSTRING h, const WCHAR *expect, const char *what)
{
    UINT32 len = 0;
    LPCWSTR raw = h ? pWindowsGetStringRawBuffer(h, &len) : NULL;

    ok(raw && wcscmp(raw, expect) == 0, "%s: got '%ls', expected '%ls'\n", what, raw ? raw : L"(null)", expect);
}

/* ---- NetworkInformation ---- */

START_TEST(NetworkInformation)
{
    static const WCHAR Cls[] = L"Windows.Networking.Connectivity.NetworkInformation";
    void *statics, *profile = NULL;
    HRESULT hr;
    int level = -1;
    HSTRING name = NULL;

    statics = GetFactory(Cls, &IID_INetworkInformationStatics_, &hr);
    if (!statics)
        return;
    ok(hr == S_OK, "RoGetActivationFactory returned 0x%08lx\n", hr);

    /* INetworkInformationStatics: GetConnectionProfiles (6), GetInternetConnectionProfile (7) */
    hr = ((PFN_OUT)VTBL(statics)[7])(statics, &profile);
    ok(hr == S_OK, "GetInternetConnectionProfile returned 0x%08lx\n", hr);
    if (profile)
    {
        /* IConnectionProfile: ProfileName (6), GetNetworkConnectivityLevel (7) */
        hr = ((PFN_OUT)VTBL(profile)[7])(profile, &level);
        ok(hr == S_OK && level >= 0 && level <= 3, "GetNetworkConnectivityLevel 0x%08lx, level %d\n", hr, level);
        ok(level != 0 /* None */, "a profile of the internet connection reports no connectivity\n");
        hr = ((PFN_OUT)VTBL(profile)[6])(profile, &name);
        ok(hr == S_OK && name && pWindowsGetStringRawBuffer(name, NULL)[0], "ProfileName returned 0x%08lx\n", hr);
        if (name)
            pWindowsDeleteString(name);
        RELEASE(profile);
    }
    else
        trace("no internet connection profile (hr 0x%08lx): the test machine has no route\n", hr);
    RELEASE(statics);
}

/* ---- OnlineIdSystemAuthenticator ---- */

START_TEST(OnlineIdSystemAuthenticator)
{
    static const WCHAR Cls[] = L"Windows.Security.Authentication.OnlineId.OnlineIdSystemAuthenticator";
    static const GUID Id = {0x11223344, 0x5566, 0x7788, {0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}};
    void *statics, *def = NULL, *user = (void *)1;
    HRESULT hr;
    GUID got;

    statics = GetFactory(Cls, &IID_IOnlineIdSystemAuthenticatorStatics_, &hr);
    if (!statics)
        return;
    ok(hr == S_OK, "RoGetActivationFactory returned 0x%08lx\n", hr);

    /* IOnlineIdSystemAuthenticatorStatics: Default (6) */
    hr = ((PFN_OUT)VTBL(statics)[6])(statics, &def);
    ok(hr == S_OK && def, "Default returned 0x%08lx, object %p\n", hr, def);
    if (def)
    {
        /* IOnlineIdSystemAuthenticatorForUser: GetTicketAsync (6), put ApplicationId (7), get ApplicationId (8), User (9) */
        memset(&got, 0xcc, sizeof(got));
        hr = ((PFN_OUT)VTBL(def)[8])(def, &got);
        ok(hr == S_OK, "get_ApplicationId returned 0x%08lx\n", hr);
        hr = ((HRESULT (STDMETHODCALLTYPE *)(void *, GUID))VTBL(def)[7])(def, Id);
        ok(hr == S_OK, "put_ApplicationId returned 0x%08lx\n", hr);
        memset(&got, 0xcc, sizeof(got));
        hr = ((PFN_OUT)VTBL(def)[8])(def, &got);
        ok(hr == S_OK && IsEqualGUID(&got, &Id), "get_ApplicationId returned 0x%08lx\n", hr);
        hr = ((PFN_OUT)VTBL(def)[9])(def, &user);
        ok(hr == S_OK, "get_User returned 0x%08lx\n", hr);
        ok(user == NULL, "no user is signed in, but get_User returned %p\n", user);
        RELEASE(def);
    }
    RELEASE(statics);
}

/* ---- Language ---- */

static BYTE IsWellFormed(void *statics, const WCHAR *tag, HRESULT *phr)
{
    HSTRING h = Str(tag);
    BYTE result = 0xcc;

    *phr = ((PFN_HSTR_OUT)VTBL(statics)[6])(statics, h, &result);
    pWindowsDeleteString(h);
    return result;
}

START_TEST(Language)
{
    static const WCHAR Cls[] = L"Windows.Globalization.Language";
    void *statics, *factory, *lang = NULL, *ilang = NULL;
    HRESULT hr;
    HSTRING tag = NULL, str = NULL;
    BYTE r;
    int i;

    statics = GetFactory(Cls, &IID_ILanguageStatics_, &hr);
    if (!statics)
        return;
    ok(hr == S_OK, "RoGetActivationFactory returned 0x%08lx\n", hr);

    /* ILanguageStatics: IsWellFormed (6), CurrentInputMethodLanguageTag (7) */
    r = IsWellFormed(statics, L"en-US", &hr);
    ok(hr == S_OK && r == TRUE, "IsWellFormed(en-US) 0x%08lx result %u\n", hr, r);
    r = IsWellFormed(statics, L"cs", &hr);
    ok(hr == S_OK && r == TRUE, "IsWellFormed(cs) 0x%08lx result %u\n", hr, r);
    r = IsWellFormed(statics, L"zh-Hans-CN", &hr);
    ok(hr == S_OK && r == TRUE, "IsWellFormed(zh-Hans-CN) 0x%08lx result %u\n", hr, r);
    r = IsWellFormed(statics, L"x", &hr);
    ok(hr == S_OK && r == FALSE, "IsWellFormed(x) 0x%08lx result %u\n", hr, r);
    r = IsWellFormed(statics, L"i-klingon", &hr);
    ok(hr == S_OK && r == TRUE, "IsWellFormed(i-klingon) 0x%08lx result %u\n", hr, r);
    r = IsWellFormed(statics, L"en-1", &hr);
    ok(hr == S_OK && r == FALSE, "IsWellFormed(en-1) 0x%08lx result %u\n", hr, r);
    r = IsWellFormed(statics, L"", &hr);
    ok(hr == S_OK && r == FALSE, "IsWellFormed('') 0x%08lx result %u\n", hr, r);
    r = IsWellFormed(statics, L"en-US-", &hr);
    ok(hr == S_OK && r == FALSE, "IsWellFormed(en-US-) 0x%08lx result %u\n", hr, r);

    hr = ((PFN_OUT)VTBL(statics)[7])(statics, &tag);
    ok(hr == S_OK && tag, "CurrentInputMethodLanguageTag returned 0x%08lx\n", hr);
    if (tag)
    {
        const WCHAR *raw = pWindowsGetStringRawBuffer(tag, NULL);
        trace("CurrentInputMethodLanguageTag = %ls\n", raw);
        r = IsWellFormed(statics, raw, &hr);
        ok(r == TRUE, "the current input method tag '%ls' is not well formed\n", raw);
        pWindowsDeleteString(tag);
    }
    RELEASE(statics);

    factory = GetFactory(Cls, &IID_ILanguageFactory_, &hr);
    if (!factory)
        return;
    {
        HSTRING bad = Str(L"");
        lang = (void *)1;
        hr = ((PFN_HSTR_OUT)VTBL(factory)[6])(factory, bad, &lang);
        ok(hr == E_INVALIDARG, "CreateLanguage('') returned 0x%08lx\n", hr);
        pWindowsDeleteString(bad);
    }
    {
        static const struct { const WCHAR *tag; const WCHAR *expect; const WCHAR *script; } Tags[] =
        {
            { L"en-US", L"en-US", L"Latn" }, { L"de-DE", L"de-DE", L"Latn" }, { L"zh-Hans-CN", L"zh-Hans-CN", L"Hans" },
        };
        for (i = 0; i < ARRAYSIZE(Tags); i++)
        {
            HSTRING in = Str(Tags[i].tag);
            lang = NULL;
            hr = ((PFN_HSTR_OUT)VTBL(factory)[6])(factory, in, &lang);
            pWindowsDeleteString(in);
            ok(hr == S_OK && lang, "CreateLanguage(%ls) returned 0x%08lx\n", Tags[i].tag, hr);
            if (!lang)
                continue;
            hr = QI(lang, &IID_ILanguage_, &ilang);
            ok(hr == S_OK && ilang, "ILanguage 0x%08lx\n", hr);
            if (ilang)
            {
                /* ILanguage: LanguageTag (6), DisplayName (7), NativeName (8), Script (9) */
                str = NULL;
                hr = ((PFN_OUT)VTBL(ilang)[6])(ilang, &str);
                ok(hr == S_OK, "LanguageTag 0x%08lx\n", hr);
                if (str) { CheckString(str, Tags[i].expect, "LanguageTag"); pWindowsDeleteString(str); }
                str = NULL;
                hr = ((PFN_OUT)VTBL(ilang)[7])(ilang, &str);
                ok(hr == S_OK && str && pWindowsGetStringRawBuffer(str, NULL)[0], "DisplayName 0x%08lx\n", hr);
                if (str) pWindowsDeleteString(str);
                str = NULL;
                hr = ((PFN_OUT)VTBL(ilang)[8])(ilang, &str);
                ok(hr == S_OK && str && pWindowsGetStringRawBuffer(str, NULL)[0], "NativeName 0x%08lx\n", hr);
                if (str) pWindowsDeleteString(str);
                str = NULL;
                hr = ((PFN_OUT)VTBL(ilang)[9])(ilang, &str);
                ok(hr == S_OK, "Script 0x%08lx\n", hr);
                if (str) { CheckString(str, Tags[i].script, "Script"); pWindowsDeleteString(str); }
                RELEASE(ilang);
                ilang = NULL;
            }
            RELEASE(lang);
        }
    }
    RELEASE(factory);
}

/* ---- OnlineIdServiceTicketRequest ---- */

START_TEST(OnlineIdServiceTicketRequest)
{
    static const WCHAR Cls[] = L"Windows.Security.Authentication.OnlineId.OnlineIdServiceTicketRequest";
    void *factory, *request = NULL;
    HRESULT hr;
    HSTRING service, policy, got = NULL;

    factory = GetFactory(Cls, &IID_IOnlineIdServiceTicketRequestFactory_, &hr);
    if (!factory)
        return;
    ok(hr == S_OK, "RoGetActivationFactory returned 0x%08lx\n", hr);

    /* IOnlineIdServiceTicketRequestFactory: CreateOnlineIdServiceTicketRequest (6), the service-only one (7);
     * IOnlineIdServiceTicketRequest: Service (6), Policy (7) */
    service = Str(L"http://example.com/service");
    policy = Str(L"MBI_SSL");
    hr = ((HRESULT (STDMETHODCALLTYPE *)(void *, HSTRING, HSTRING, void **))VTBL(factory)[6])(factory, service, policy, &request);
    ok(hr == S_OK && request, "CreateOnlineIdServiceTicketRequest returned 0x%08lx\n", hr);
    if (request)
    {
        hr = ((PFN_OUT)VTBL(request)[6])(request, &got);
        ok(hr == S_OK, "Service 0x%08lx\n", hr);
        if (got) { CheckString(got, L"http://example.com/service", "Service"); pWindowsDeleteString(got); got = NULL; }
        hr = ((PFN_OUT)VTBL(request)[7])(request, &got);
        ok(hr == S_OK, "Policy 0x%08lx\n", hr);
        if (got) { CheckString(got, L"MBI_SSL", "Policy"); pWindowsDeleteString(got); got = NULL; }
        RELEASE(request);
    }
    request = NULL;
    hr = ((PFN_HSTR_OUT)VTBL(factory)[7])(factory, service, &request);
    ok(hr == S_OK && request, "the service-only constructor returned 0x%08lx\n", hr);
    if (request)
    {
        hr = ((PFN_OUT)VTBL(request)[7])(request, &got);
        ok(hr == S_OK, "Policy 0x%08lx\n", hr);
        if (got) { CheckString(got, L"", "default Policy"); pWindowsDeleteString(got); }
        RELEASE(request);
    }
    pWindowsDeleteString(service);
    pWindowsDeleteString(policy);
    RELEASE(factory);
}
