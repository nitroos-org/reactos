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

/* ---- GetTicketAsync ---- */

DEFINE_GUID(IID_IOnlineIdSystemTicketResult_, 0xdb0a5ff8, 0xb098, 0x4acd, 0x9d, 0x13, 0x9e, 0x64, 0x06, 0x52, 0xb5, 0xb6);
/* IAsyncOperation<OnlineIdSystemTicketResult*> as the WinRT pinterface algorithm computes it from its public signature */
DEFINE_GUID(IID_IAsyncOperation_TicketResult_, 0x162f5870, 0x5a4a, 0x503c, 0x98, 0x7f, 0xa0, 0x5a, 0x13, 0x12, 0xd8, 0xe4);
DEFINE_GUID(IID_IAsyncInfo_, 0x00000036, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);

typedef struct
{
    void **vtbl;
    LONG ref;
    LONG called;
    int status;
    void *operation;
} COMPLETION_HANDLER;

static HRESULT STDMETHODCALLTYPE Handler_QI(void *This, REFIID riid, void **out)
{
    /* the IID of AsyncOperationCompletedHandler<OnlineIdSystemTicketResult*> is not needed: the handler answers
     * what the object asks (IUnknown, IAgileObject) and, as the test only passes it in, nothing else */
    if (IsEqualGUID(riid, &IID_IUnknown) || IsEqualGUID(riid, &IID_IAgile))
    {
        *out = This;
        InterlockedIncrement(&((COMPLETION_HANDLER *)This)->ref);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE Handler_AddRef(void *This) { return InterlockedIncrement(&((COMPLETION_HANDLER *)This)->ref); }
static ULONG STDMETHODCALLTYPE Handler_Release(void *This) { return InterlockedDecrement(&((COMPLETION_HANDLER *)This)->ref); }
static HRESULT STDMETHODCALLTYPE Handler_Invoke(void *This, void *operation, int status)
{
    COMPLETION_HANDLER *h = This;
    h->operation = operation;
    h->status = status;
    InterlockedIncrement(&h->called);
    return S_OK;
}
static void *HandlerVtbl[] = { Handler_QI, Handler_AddRef, Handler_Release, Handler_Invoke };

static void TestGetTicketAsync(void *statics)
{
    static const WCHAR FactoryCls[] = L"Windows.Security.Authentication.OnlineId.OnlineIdServiceTicketRequest";
    static const GUID Id = {0x11223344, 0x5566, 0x7788, {0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}};
    void *authenticator = NULL, *factory, *request = NULL, *operation = (void *)1, *info = NULL, *same = NULL, *result = NULL, *iresult = NULL;
    COMPLETION_HANDLER handler, handler2;
    HRESULT hr;
    HSTRING service, policy;
    int status;
    UINT32 id;
    void *identity = (void *)1;

    /* a fresh authenticator: its ApplicationId is still the default */
    hr = ((PFN_OUT)VTBL(statics)[6])(statics, &authenticator);
    ok(hr == S_OK && authenticator, "Default returned 0x%08lx\n", hr);
    if (!authenticator)
        return;
    factory = GetFactory(FactoryCls, &IID_IOnlineIdServiceTicketRequestFactory_, &hr);
    if (!factory)
    {
        RELEASE(authenticator);
        return;
    }
    service = Str(L"http://example.com/service");
    policy = Str(L"MBI_SSL");
    hr = ((HRESULT (STDMETHODCALLTYPE *)(void *, HSTRING, HSTRING, void **))VTBL(factory)[6])(factory, service, policy, &request);
    ok(hr == S_OK && request, "CreateOnlineIdServiceTicketRequest returned 0x%08lx\n", hr);
    pWindowsDeleteString(service);
    pWindowsDeleteString(policy);
    RELEASE(factory);
    if (!request)
    {
        RELEASE(authenticator);
        return;
    }

    /* IOnlineIdSystemAuthenticatorForUser::GetTicketAsync is slot 6. Measured on Windows 10 22H2 (local account): a
     * NULL request is E_POINTER and leaves the out pointer alone; a valid request with the ApplicationId still all
     * zeros is E_INVALIDARG with a NULL operation. */
    hr = ((PFN_HSTR_OUT)VTBL(authenticator)[6])(authenticator, NULL, &operation);
    ok(hr == E_POINTER, "GetTicketAsync(NULL) returned 0x%08lx\n", hr);
    ok(operation == (void *)1, "GetTicketAsync(NULL) wrote the operation %p\n", operation);
    operation = (void *)1;
    hr = ((PFN_HSTR_OUT)VTBL(authenticator)[6])(authenticator, request, &operation);
    ok(hr == E_INVALIDARG, "GetTicketAsync without an ApplicationId returned 0x%08lx\n", hr);
    ok(operation == NULL, "GetTicketAsync without an ApplicationId returned the operation %p\n", operation);

    /* With an ApplicationId set the behaviour on Windows was not measured; here the operation is completed at once
     * (no Microsoft account) with no identity and a status other than Success. */
    hr = ((HRESULT (STDMETHODCALLTYPE *)(void *, GUID))VTBL(authenticator)[7])(authenticator, Id);
    ok(hr == S_OK, "put_ApplicationId returned 0x%08lx\n", hr);
    operation = NULL;
    hr = ((PFN_HSTR_OUT)VTBL(authenticator)[6])(authenticator, request, &operation);
    ok(hr == S_OK && operation, "GetTicketAsync returned 0x%08lx, operation %p\n", hr, operation);
    if (hr == S_OK && operation)
    {
        hr = QI(operation, &IID_IAsyncOperation_TicketResult_, &same);
        ok(hr == S_OK && same == operation, "QI(IAsyncOperation) returned 0x%08lx\n", hr);
        if (same) RELEASE(same);
        hr = QI(operation, &IID_IAsyncInfo_, &info);
        ok(hr == S_OK && info, "QI(IAsyncInfo) returned 0x%08lx\n", hr);
        if (info)
        {
            /* IAsyncInfo: Id (6), Status (7), ErrorCode (8) */
            status = -1;
            hr = ((PFN_OUT)VTBL(info)[7])(info, &status);
            ok(hr == S_OK && status == 1, "IAsyncInfo.Status returned 0x%08lx, %d (Completed is 1)\n", hr, status);
            id = 0;
            hr = ((PFN_OUT)VTBL(info)[6])(info, &id);
            ok(hr == S_OK && id != 0, "IAsyncInfo.Id returned 0x%08lx, %lu\n", hr, (unsigned long)id);
            hr = ((PFN_OUT)VTBL(info)[8])(info, &status);
            ok(hr == S_OK && status == 0, "IAsyncInfo.ErrorCode returned 0x%08lx, 0x%08x\n", hr, status);
        }

        /* IAsyncOperation: put_Completed (6), get_Completed (7), GetResults (8). A completed operation runs the handler
         * when it is set; a second handler is E_ILLEGAL_DELEGATE_ASSIGNMENT */
        memset(&handler, 0, sizeof(handler));
        handler.vtbl = HandlerVtbl;
        handler.ref = 1;
        hr = ((PFN_OUT)VTBL(operation)[6])(operation, &handler);
        ok(hr == S_OK, "put_Completed returned 0x%08lx\n", hr);
        ok(handler.called == 1 && handler.status == 1 && handler.operation == operation,
           "handler: called %ld, status %d, operation %p\n", handler.called, handler.status, handler.operation);
        memset(&handler2, 0, sizeof(handler2));
        handler2.vtbl = HandlerVtbl;
        handler2.ref = 1;
        hr = ((PFN_OUT)VTBL(operation)[6])(operation, &handler2);
        ok(hr == (HRESULT)0x80000018, "second put_Completed returned 0x%08lx\n", hr);
        ok(handler2.called == 0, "the second handler was called\n");

        hr = ((PFN_OUT)VTBL(operation)[8])(operation, &result);
        ok(hr == S_OK && result, "GetResults returned 0x%08lx, %p\n", hr, result);
        if (result)
        {
            hr = QI(result, &IID_IOnlineIdSystemTicketResult_, &iresult);
            ok(hr == S_OK && iresult, "QI(IOnlineIdSystemTicketResult) returned 0x%08lx\n", hr);
            if (iresult)
            {
                /* IOnlineIdSystemTicketResult: Identity (6), Status (7), ExtendedError (8) */
                hr = ((PFN_OUT)VTBL(iresult)[6])(iresult, &identity);
                ok(hr == S_OK && identity == NULL, "Identity returned 0x%08lx, %p\n", hr, identity);
                status = -1;
                hr = ((PFN_OUT)VTBL(iresult)[7])(iresult, &status);
                ok(hr == S_OK && (status == 1 || status == 2), "Status returned 0x%08lx, %d\n", hr, status);
                hr = ((PFN_OUT)VTBL(iresult)[8])(iresult, &status);
                ok(hr == S_OK && status < 0, "ExtendedError returned 0x%08lx, 0x%08x\n", hr, status);
                RELEASE(iresult);
            }
            RELEASE(result);
        }
        if (info)
        {
            /* IAsyncInfo: Close (10); after it the operation is closed (status 4) and GetResults is E_ILLEGAL_METHOD_CALL */
            hr = ((HRESULT (STDMETHODCALLTYPE *)(void *))VTBL(info)[10])(info);
            ok(hr == S_OK, "IAsyncInfo.Close returned 0x%08lx\n", hr);
            status = -1;
            hr = ((PFN_OUT)VTBL(info)[7])(info, &status);
            ok(hr == S_OK && status == 4, "Status after Close returned 0x%08lx, %d\n", hr, status);
            result = (void *)1;
            hr = ((PFN_OUT)VTBL(operation)[8])(operation, &result);
            ok(hr == E_ILLEGAL_METHOD_CALL, "GetResults after Close returned 0x%08lx\n", hr);
            RELEASE(info);
        }
        RELEASE(operation);
    }
    RELEASE(request);
    RELEASE(authenticator);
}

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
        TestGetTicketAsync(statics);
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

/* ---- PropertyValue ----
 *
 * Windows.Foundation.PropertyValue (boxed values). Everything asserted here was measured on Windows 10 22H2
 * (19045): the conversions between numeric types are exact-or-DISP_E_OVERFLOW, other mismatches are
 * TYPE_E_TYPEMISMATCH, the empty value is a NULL object, CreateInspectable returns its argument.
 * Member order and ids: IPropertyValue / IPropertyValueStatics of the public Windows Runtime IDL.
 */

DEFINE_GUID(IID_IPropertyValueStatics_, 0x629bdbc8, 0xd932, 0x4ff4, 0x96, 0xb9, 0x8d, 0x96, 0xc5, 0xc1, 0xe8, 0x58);
DEFINE_GUID(IID_IPropertyValue_, 0x4bd682dd, 0x7554, 0x40e9, 0x9a, 0x9b, 0x82, 0x65, 0x4e, 0xde, 0x7e, 0x62);
DEFINE_GUID(IID_IReference_Int32_, 0x548cefbd, 0xbc8a, 0x5fa0, 0x8d, 0xf2, 0x95, 0x74, 0x40, 0xfc, 0x8b, 0xf4);
DEFINE_GUID(IID_IReference_UInt32_, 0x513ef3af, 0xe784, 0x5325, 0xa9, 0x1e, 0x97, 0xc2, 0xb8, 0x11, 0x1c, 0xf3);
DEFINE_GUID(IID_IReference_Int64_, 0x4dda9e24, 0xe69f, 0x5c6a, 0xa0, 0xa6, 0x93, 0x42, 0x73, 0x65, 0xaf, 0x2a);
DEFINE_GUID(IID_IReference_String_, 0xfd416dfb, 0x2a07, 0x52eb, 0xaa, 0xe3, 0xdf, 0xce, 0x14, 0x11, 0x6c, 0x05);
DEFINE_GUID(IID_IReferenceArray_Int32_, 0xa6d080a5, 0xb087, 0x5bc2, 0x9a, 0x9f, 0x5c, 0xd6, 0x87, 0xb4, 0xd1, 0xf7);
DEFINE_GUID(IID_IReferenceArray_String_, 0x0385688e, 0xe3c7, 0x5c5e, 0xa3, 0x89, 0x55, 0x24, 0xed, 0xe3, 0x49, 0xf1);

#define PV_E_MISMATCH ((HRESULT)0x80028CA0)
#define PV_E_OVERFLOW ((HRESULT)0x8002000A)

/* IPropertyValue slots */
#define PV_TYPE 6
#define PV_ISNUMERIC 7
#define PV_GETU8 8
#define PV_GETI16 9
#define PV_GETU16 10
#define PV_GETI32 11
#define PV_GETU32 12
#define PV_GETI64 13
#define PV_GETU64 14
#define PV_GETF32 15
#define PV_GETF64 16
#define PV_GETC16 17
#define PV_GETBOOL 18
#define PV_GETSTR 19
#define PV_GETGUID 20
#define PV_GETDT 21
#define PV_GETTS 22
#define PV_GETPT 23
#define PV_GETSZ 24
#define PV_GETRC 25
#define PV_GETU8A 26
#define PV_GETI16A 27
#define PV_GETI32A 29
#define PV_GETI64A 31
#define PV_GETF64A 34
#define PV_GETSTRA 37

/* IPropertyValueStatics slots */
#define ST_EMPTY 6
#define ST_U8 7
#define ST_I32 10
#define ST_U64 13
#define ST_F64 15
#define ST_BOOL 17
#define ST_STR 18
#define ST_INSP 19
#define ST_GUID 20
#define ST_DT 21
#define ST_PT 23
#define ST_RC 25
#define ST_I32A 29
#define ST_STRA 37

typedef struct { float a, b; } PVPT;
typedef struct { float a, b, c, d; } PVRC;
typedef HRESULT (STDMETHODCALLTYPE *PFN_ST_V)(void *, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_ST_I32)(void *, INT32, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_ST_I64)(void *, INT64, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_ST_F64)(void *, double, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_ST_PTR)(void *, void *, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_ST_GUID)(void *, GUID, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_ST_PT)(void *, PVPT, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_ST_RC)(void *, PVRC, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_ST_ARR)(void *, UINT32, void *, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_ARR)(void *, UINT32 *, void **);

#define PVGET(pv, slot, out) ((PFN_OUT)VTBL(pv)[slot])(pv, out)

/* The IPropertyValue of a created object (NULL when creation failed) */
static void *PvOf(void *obj, const char *what)
{
    void *pv = NULL;
    HRESULT hr;

    ok(obj != NULL, "%s: no object\n", what);
    if (!obj)
        return NULL;
    hr = QI(obj, &IID_IPropertyValue_, &pv);
    ok(hr == S_OK && pv == obj, "%s: QI(IPropertyValue) returned 0x%08lx, %p (object %p)\n", what, hr, pv, obj);
    if (pv)
        RELEASE(pv);
    return hr == S_OK ? obj : NULL;
}

static void CheckClassName(void *obj, const WCHAR *expect, const char *what)
{
    HSTRING name = NULL;
    HRESULT hr = GETNAME(obj, &name);

    ok(hr == S_OK, "%s: GetRuntimeClassName returned 0x%08lx\n", what, hr);
    if (hr == S_OK)
        CheckString(name, expect, what);
    if (name)
        pWindowsDeleteString(name);
}

/* Reads one scalar through IPropertyValue into 16 bytes of output and checks the result code */
static void CheckGet(void *pv, int slot, HRESULT expect, const void *expect_value, size_t size, const char *what)
{
    BYTE buf[16];
    HRESULT hr;

    memset(buf, 0xCC, sizeof(buf));
    hr = PVGET(pv, slot, buf);
    ok(hr == expect, "%s: returned 0x%08lx, expected 0x%08lx\n", what, hr, expect);
    if (hr == S_OK && expect == S_OK && expect_value)
        ok(memcmp(buf, expect_value, size) == 0, "%s: wrong value\n", what);
}

/* Reads an array: returns the element count (0 for a failure) after checking the result code */
static UINT32 CheckGetArray(void *pv, int slot, HRESULT expect, const void *expect_values, size_t size, const char *what)
{
    UINT32 n = 0xCCCCCCCC;
    void *arr = NULL;
    HRESULT hr = ((PFN_ARR)VTBL(pv)[slot])(pv, &n, &arr);

    ok(hr == expect, "%s: returned 0x%08lx, expected 0x%08lx\n", what, hr, expect);
    if (hr == S_OK)
    {
        if (expect_values && arr)
            ok(memcmp(arr, expect_values, size) == 0, "%s: wrong values\n", what);
        if (arr)
            CoTaskMemFree(arr);
        return n;
    }
    ok(n == 0, "%s: %u elements returned on failure\n", what, n);
    return 0;
}

static void TestPropertyValueRegistration(void)
{
    HKEY key;
    WCHAR path[MAX_PATH];
    DWORD type, size, value;
    LONG ret;

    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\WindowsRuntime\\ActivatableClassId\\Windows.Foundation.PropertyValue",
                        0, KEY_READ, &key);
    ok(ret == ERROR_SUCCESS, "the class key is not registered: %ld\n", ret);
    if (ret)
        return;
    size = sizeof(path);
    ret = RegQueryValueExW(key, L"DllPath", NULL, &type, (BYTE *)path, &size);
    ok(ret == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ), "DllPath: %ld, type %lu\n", ret, type);
    if (ret == ERROR_SUCCESS)
    {
        WCHAR *end = path + wcslen(path) - wcslen(L"wintypes.dll");
        ok(end >= path && _wcsicmp(end, L"wintypes.dll") == 0, "DllPath is '%ls', expected wintypes.dll\n", path);
    }
    size = sizeof(value);
    ret = RegQueryValueExW(key, L"ActivationType", NULL, &type, (BYTE *)&value, &size);
    ok(ret == ERROR_SUCCESS && type == REG_DWORD && value == 0, "ActivationType: %ld, type %lu, value %lu\n", ret, type, value);
    size = sizeof(value);
    ret = RegQueryValueExW(key, L"Threading", NULL, &type, (BYTE *)&value, &size);
    ok(ret == ERROR_SUCCESS && type == REG_DWORD && value == 0, "Threading: %ld, type %lu, value %lu\n", ret, type, value);
    size = sizeof(value);
    ret = RegQueryValueExW(key, L"TrustLevel", NULL, &type, (BYTE *)&value, &size);
    ok(ret == ERROR_SUCCESS && type == REG_DWORD && value == 0, "TrustLevel: %ld, type %lu, value %lu\n", ret, type, value);
    RegCloseKey(key);
}

START_TEST(PropertyValue)
{
    static const WCHAR Cls[] = L"Windows.Foundation.PropertyValue";
    static const GUID Id = {0x11223344, 0x5566, 0x7788, {0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}};
    static const INT32 arr3[3] = { 1, -2, 70000 };
    static const INT64 arr3_64[3] = { 1, -2, 70000 };
    static const double arr3_f64[3] = { 1.0, -2.0, 70000.0 };
    void **sv;
    void *statics, *obj, *pv, *ref;
    HRESULT hr;
    HSTRING hs;
    BYTE isnum;
    int type;
    ULONG count;
    IID *iids;

    TestPropertyValueRegistration();

    statics = GetFactory(Cls, &IID_IPropertyValueStatics_, &hr);
    if (!statics)
        return;
    ok(hr == S_OK, "RoGetActivationFactory returned 0x%08lx\n", hr);
    sv = VTBL(statics);
    CheckClassName(statics, Cls, "factory class name");
    obj = NULL;
    hr = QI(statics, &IID_IAF, &obj);
    ok(hr == S_OK && obj, "QI(IActivationFactory) returned 0x%08lx\n", hr);
    if (obj)
        RELEASE(obj);

    /* the empty value is a NULL object; CreateInspectable returns its argument, NULL is an invalid argument */
    obj = (void *)1;
    hr = ((PFN_ST_V)sv[ST_EMPTY])(statics, &obj);
    ok(hr == S_OK && obj == NULL, "CreateEmpty returned 0x%08lx, %p\n", hr, obj);
    obj = (void *)1;
    hr = ((PFN_ST_PTR)sv[ST_INSP])(statics, NULL, &obj);
    ok(hr == E_INVALIDARG && obj == NULL, "CreateInspectable(NULL) returned 0x%08lx, %p\n", hr, obj);
    obj = NULL;
    hr = ((PFN_ST_PTR)sv[ST_INSP])(statics, statics, &obj);
    ok(hr == S_OK && obj == statics, "CreateInspectable returned 0x%08lx, %p (argument %p)\n", hr, obj, statics);
    if (obj)
        RELEASE(obj);

    /* Int32 42 */
    obj = NULL;
    hr = ((PFN_ST_I32)sv[ST_I32])(statics, 42, &obj);
    ok(hr == S_OK, "CreateInt32 returned 0x%08lx\n", hr);
    pv = PvOf(obj, "Int32");
    if (pv)
    {
        INT32 i32 = 42; INT64 i64 = 42; UINT8 u8 = 42; UINT64 u64 = 42; float f = 42.0f; double d = 42.0;

        CheckClassName(pv, L"Windows.Foundation.IReference`1<Int32>", "Int32 class name");
        type = -1;
        hr = PVGET(pv, PV_TYPE, &type);
        ok(hr == S_OK && type == 4, "Type returned 0x%08lx, %d\n", hr, type);
        isnum = 9;
        hr = PVGET(pv, PV_ISNUMERIC, &isnum);
        ok(hr == S_OK && isnum == 0, "IsNumericScalar returned 0x%08lx, %u\n", hr, isnum);
        CheckGet(pv, PV_GETU8, S_OK, &u8, 1, "Int32(42).GetUInt8");
        CheckGet(pv, PV_GETI32, S_OK, &i32, 4, "Int32(42).GetInt32");
        CheckGet(pv, PV_GETI64, S_OK, &i64, 8, "Int32(42).GetInt64");
        CheckGet(pv, PV_GETU64, S_OK, &u64, 8, "Int32(42).GetUInt64");
        CheckGet(pv, PV_GETF32, S_OK, &f, 4, "Int32(42).GetSingle");
        CheckGet(pv, PV_GETF64, S_OK, &d, 8, "Int32(42).GetDouble");
        CheckGet(pv, PV_GETC16, PV_E_MISMATCH, NULL, 0, "Int32.GetChar16");
        CheckGet(pv, PV_GETBOOL, PV_E_MISMATCH, NULL, 0, "Int32.GetBoolean");
        CheckGet(pv, PV_GETSTR, PV_E_MISMATCH, NULL, 0, "Int32.GetString");
        CheckGet(pv, PV_GETGUID, PV_E_MISMATCH, NULL, 0, "Int32.GetGuid");
        CheckGet(pv, PV_GETRC, PV_E_MISMATCH, NULL, 0, "Int32.GetRect");
        CheckGetArray(pv, PV_GETI32A, PV_E_MISMATCH, NULL, 0, "Int32.GetInt32Array");

        ref = NULL;
        hr = QI(obj, &IID_IReference_Int32_, &ref);
        ok(hr == S_OK && ref, "QI(IReference<Int32>) returned 0x%08lx\n", hr);
        if (ref)
        {
            INT32 got = 0;
            hr = ((PFN_OUT)VTBL(ref)[6])(ref, &got);
            ok(hr == S_OK && got == 42, "IReference<Int32>::Value returned 0x%08lx, %d\n", hr, got);
            CheckClassName(ref, L"Windows.Foundation.IReference`1<Int32>", "IReference<Int32> class name");
            RELEASE(ref);
        }
        ref = NULL;
        hr = QI(obj, &IID_IReference_UInt32_, &ref);
        ok(hr == E_NOINTERFACE && !ref, "QI(IReference<UInt32>) returned 0x%08lx\n", hr);
        hr = QI(obj, &IID_IReference_Int64_, &ref);
        ok(hr == E_NOINTERFACE && !ref, "QI(IReference<Int64>) returned 0x%08lx\n", hr);
        hr = QI(obj, &IID_IReferenceArray_Int32_, &ref);
        ok(hr == E_NOINTERFACE && !ref, "QI(IReferenceArray<Int32>) returned 0x%08lx\n", hr);
        hr = QI(obj, &IID_IAgile, &ref);
        ok(hr == S_OK && ref, "QI(IAgileObject) returned 0x%08lx\n", hr);
        if (ref)
            RELEASE(ref);
        iids = NULL;
        count = 0;
        hr = ((PFN_GETIIDS)VTBL(obj)[3])(obj, &count, &iids);
        ok(hr == S_OK && count >= 2 && iids, "GetIids returned 0x%08lx, %lu\n", hr, count);
        if (hr == S_OK && count >= 2)
        {
            ULONG i;
            BOOL got_pv = FALSE, got_ref = FALSE;
            for (i = 0; i < count; i++)
            {
                got_pv |= IsEqualGUID(&iids[i], &IID_IPropertyValue_);
                got_ref |= IsEqualGUID(&iids[i], &IID_IReference_Int32_);
            }
            ok(got_pv && got_ref, "GetIids misses IPropertyValue (%d) or IReference<Int32> (%d)\n", got_pv, got_ref);
        }
        if (iids)
            CoTaskMemFree(iids);
        RELEASE(obj);
    }

    /* Int32 -1 and 70000: exact conversions only */
    obj = NULL;
    hr = ((PFN_ST_I32)sv[ST_I32])(statics, -1, &obj);
    pv = PvOf(obj, "Int32(-1)");
    if (pv)
    {
        INT16 i16 = -1; INT32 i32 = -1; INT64 i64 = -1; float f = -1.0f; double d = -1.0;

        CheckGet(pv, PV_GETU8, PV_E_OVERFLOW, NULL, 0, "Int32(-1).GetUInt8");
        CheckGet(pv, PV_GETI16, S_OK, &i16, 2, "Int32(-1).GetInt16");
        CheckGet(pv, PV_GETU16, PV_E_OVERFLOW, NULL, 0, "Int32(-1).GetUInt16");
        CheckGet(pv, PV_GETI32, S_OK, &i32, 4, "Int32(-1).GetInt32");
        CheckGet(pv, PV_GETU32, PV_E_OVERFLOW, NULL, 0, "Int32(-1).GetUInt32");
        CheckGet(pv, PV_GETI64, S_OK, &i64, 8, "Int32(-1).GetInt64");
        CheckGet(pv, PV_GETU64, PV_E_OVERFLOW, NULL, 0, "Int32(-1).GetUInt64");
        CheckGet(pv, PV_GETF32, S_OK, &f, 4, "Int32(-1).GetSingle");
        CheckGet(pv, PV_GETF64, S_OK, &d, 8, "Int32(-1).GetDouble");
        RELEASE(obj);
    }
    obj = NULL;
    hr = ((PFN_ST_I32)sv[ST_I32])(statics, 70000, &obj);
    pv = PvOf(obj, "Int32(70000)");
    if (pv)
    {
        UINT32 u32 = 70000;

        CheckGet(pv, PV_GETU8, PV_E_OVERFLOW, NULL, 0, "Int32(70000).GetUInt8");
        CheckGet(pv, PV_GETI16, PV_E_OVERFLOW, NULL, 0, "Int32(70000).GetInt16");
        CheckGet(pv, PV_GETU16, PV_E_OVERFLOW, NULL, 0, "Int32(70000).GetUInt16");
        CheckGet(pv, PV_GETU32, S_OK, &u32, 4, "Int32(70000).GetUInt32");
        RELEASE(obj);
    }

    /* UInt8 200 reads as every wider numeric type */
    obj = NULL;
    hr = ((PFN_ST_I32)sv[ST_U8])(statics, 200, &obj);
    pv = PvOf(obj, "UInt8");
    if (pv)
    {
        INT16 i16 = 200; double d = 200.0;

        CheckClassName(pv, L"Windows.Foundation.IReference`1<UInt8>", "UInt8 class name");
        CheckGet(pv, PV_GETI16, S_OK, &i16, 2, "UInt8(200).GetInt16");
        CheckGet(pv, PV_GETF64, S_OK, &d, 8, "UInt8(200).GetDouble");
        RELEASE(obj);
    }

    /* floating point reads as an integer never when fractional, and exactly as the other float type */
    obj = NULL;
    hr = ((PFN_ST_F64)sv[ST_F64])(statics, 3.7, &obj);
    pv = PvOf(obj, "Double(3.7)");
    if (pv)
    {
        double d = 3.7;

        CheckGet(pv, PV_GETI32, PV_E_OVERFLOW, NULL, 0, "Double(3.7).GetInt32");
        CheckGet(pv, PV_GETU8, PV_E_OVERFLOW, NULL, 0, "Double(3.7).GetUInt8");
        CheckGet(pv, PV_GETF32, PV_E_OVERFLOW, NULL, 0, "Double(3.7).GetSingle");
        CheckGet(pv, PV_GETF64, S_OK, &d, 8, "Double(3.7).GetDouble");
        RELEASE(obj);
    }
    obj = NULL;
    hr = ((PFN_ST_F64)sv[ST_F64])(statics, -2.5, &obj);
    pv = PvOf(obj, "Double(-2.5)");
    if (pv)
    {
        float f = -2.5f;

        CheckGet(pv, PV_GETI32, PV_E_OVERFLOW, NULL, 0, "Double(-2.5).GetInt32");
        CheckGet(pv, PV_GETF32, S_OK, &f, 4, "Double(-2.5).GetSingle");
        RELEASE(obj);
    }
    obj = NULL;
    hr = ((PFN_ST_F64)sv[ST_F64])(statics, 1e20, &obj);
    pv = PvOf(obj, "Double(1e20)");
    if (pv)
    {
        CheckGet(pv, PV_GETI64, PV_E_OVERFLOW, NULL, 0, "Double(1e20).GetInt64");
        CheckGet(pv, PV_GETF32, PV_E_OVERFLOW, NULL, 0, "Double(1e20).GetSingle");
        RELEASE(obj);
    }

    /* UInt64 above INT64_MAX does not convert to a signed or a floating point type */
    obj = NULL;
    hr = ((PFN_ST_I64)sv[ST_U64])(statics, (INT64)0x8000000000000001ULL, &obj);
    pv = PvOf(obj, "UInt64");
    if (pv)
    {
        UINT64 u64 = 0x8000000000000001ULL;

        CheckGet(pv, PV_GETI64, PV_E_OVERFLOW, NULL, 0, "UInt64(2^63+1).GetInt64");
        CheckGet(pv, PV_GETF64, PV_E_OVERFLOW, NULL, 0, "UInt64(2^63+1).GetDouble");
        CheckGet(pv, PV_GETU64, S_OK, &u64, 8, "UInt64(2^63+1).GetUInt64");
        RELEASE(obj);
    }

    /* Boolean, String (also NULL), Guid (reads as text too) */
    obj = NULL;
    hr = ((PFN_ST_I32)sv[ST_BOOL])(statics, 1, &obj);
    pv = PvOf(obj, "Boolean");
    if (pv)
    {
        BYTE b = 1;

        CheckClassName(pv, L"Windows.Foundation.IReference`1<Boolean>", "Boolean class name");
        CheckGet(pv, PV_GETBOOL, S_OK, &b, 1, "Boolean.GetBoolean");
        CheckGet(pv, PV_GETI32, PV_E_MISMATCH, NULL, 0, "Boolean.GetInt32");
        RELEASE(obj);
    }
    hs = Str(L"123");
    obj = NULL;
    hr = ((PFN_ST_PTR)sv[ST_STR])(statics, hs, &obj);
    pv = PvOf(obj, "String");
    if (pv)
    {
        HSTRING got = NULL;

        CheckClassName(pv, L"Windows.Foundation.IReference`1<String>", "String class name");
        hr = PVGET(pv, PV_GETSTR, &got);
        ok(hr == S_OK, "String.GetString returned 0x%08lx\n", hr);
        CheckString(got, L"123", "String.GetString");
        if (got)
            pWindowsDeleteString(got);
        CheckGet(pv, PV_GETI32, PV_E_MISMATCH, NULL, 0, "String.GetInt32");
        ref = NULL;
        hr = QI(obj, &IID_IReference_String_, &ref);
        ok(hr == S_OK && ref, "QI(IReference<String>) returned 0x%08lx\n", hr);
        if (ref)
        {
            got = NULL;
            hr = ((PFN_OUT)VTBL(ref)[6])(ref, &got);
            ok(hr == S_OK, "IReference<String>::Value returned 0x%08lx\n", hr);
            CheckString(got, L"123", "IReference<String>::Value");
            if (got)
                pWindowsDeleteString(got);
            RELEASE(ref);
        }
        RELEASE(obj);
    }
    pWindowsDeleteString(hs);
    obj = NULL;
    hr = ((PFN_ST_PTR)sv[ST_STR])(statics, NULL, &obj);
    pv = PvOf(obj, "String(NULL)");
    if (pv)
    {
        HSTRING got = (HSTRING)1;

        hr = PVGET(pv, PV_GETSTR, &got);
        ok(hr == S_OK, "String(NULL).GetString returned 0x%08lx\n", hr);
        /* the empty string: a NULL handle or a string of no characters */
        ok(got != (HSTRING)1 && (!got || !pWindowsGetStringRawBuffer(got, NULL)[0]), "String(NULL).GetString returned a non-empty string\n");
        if (got && got != (HSTRING)1)
            pWindowsDeleteString(got);
        RELEASE(obj);
    }
    obj = NULL;
    hr = ((PFN_ST_GUID)sv[ST_GUID])(statics, Id, &obj);
    pv = PvOf(obj, "Guid");
    if (pv)
    {
        HSTRING got = NULL;

        CheckGet(pv, PV_GETGUID, S_OK, &Id, sizeof(Id), "Guid.GetGuid");
        hr = PVGET(pv, PV_GETSTR, &got);
        ok(hr == S_OK, "Guid.GetString returned 0x%08lx\n", hr);
        CheckString(got, L"11223344-5566-7788-99aa-bbccddeeff00", "Guid.GetString");
        if (got)
            pWindowsDeleteString(got);
        RELEASE(obj);
    }

    /* DateTime, Point, Rect */
    obj = NULL;
    hr = ((PFN_ST_I64)sv[ST_DT])(statics, 123456789LL, &obj);
    pv = PvOf(obj, "DateTime");
    if (pv)
    {
        INT64 v = 123456789LL;

        CheckClassName(pv, L"Windows.Foundation.IReference`1<Windows.Foundation.DateTime>", "DateTime class name");
        CheckGet(pv, PV_GETDT, S_OK, &v, 8, "DateTime.GetDateTime");
        CheckGet(pv, PV_GETTS, PV_E_MISMATCH, NULL, 0, "DateTime.GetTimeSpan");
        RELEASE(obj);
    }
    {
        PVPT pt = { 1.5f, 2.5f };
        PVRC rc = { 1.0f, 2.0f, 3.0f, 4.0f };

        obj = NULL;
        hr = ((PFN_ST_PT)sv[ST_PT])(statics, pt, &obj);
        pv = PvOf(obj, "Point");
        if (pv)
        {
            CheckGet(pv, PV_GETPT, S_OK, &pt, sizeof(pt), "Point.GetPoint");
            CheckGet(pv, PV_GETSZ, PV_E_MISMATCH, NULL, 0, "Point.GetSize");
            RELEASE(obj);
        }
        obj = NULL;
        hr = ((PFN_ST_RC)sv[ST_RC])(statics, rc, &obj);
        pv = PvOf(obj, "Rect");
        if (pv)
        {
            CheckClassName(pv, L"Windows.Foundation.IReference`1<Windows.Foundation.Rect>", "Rect class name");
            CheckGet(pv, PV_GETRC, S_OK, &rc, sizeof(rc), "Rect.GetRect");
            RELEASE(obj);
        }
    }

    /* Int32 array: copies, element-wise exact conversions, IReferenceArray<Int32> */
    obj = NULL;
    hr = ((PFN_ST_ARR)sv[ST_I32A])(statics, 3, (void *)arr3, &obj);
    ok(hr == S_OK, "CreateInt32Array returned 0x%08lx\n", hr);
    pv = PvOf(obj, "Int32Array");
    if (pv)
    {
        UINT32 n;

        CheckClassName(pv, L"Windows.Foundation.IReferenceArray`1<Int32>", "Int32Array class name");
        type = -1;
        hr = PVGET(pv, PV_TYPE, &type);
        ok(hr == S_OK && type == 1028, "Int32Array Type returned 0x%08lx, %d\n", hr, type);
        n = CheckGetArray(pv, PV_GETI32A, S_OK, arr3, sizeof(arr3), "Int32Array.GetInt32Array");
        ok(n == 3, "Int32Array.GetInt32Array: %u elements\n", n);
        n = CheckGetArray(pv, PV_GETI64A, S_OK, arr3_64, sizeof(arr3_64), "Int32Array.GetInt64Array");
        ok(n == 3, "Int32Array.GetInt64Array: %u elements\n", n);
        n = CheckGetArray(pv, PV_GETF64A, S_OK, arr3_f64, sizeof(arr3_f64), "Int32Array.GetDoubleArray");
        ok(n == 3, "Int32Array.GetDoubleArray: %u elements\n", n);
        CheckGetArray(pv, PV_GETU8A, PV_E_OVERFLOW, NULL, 0, "Int32Array.GetUInt8Array");
        CheckGetArray(pv, PV_GETI16A, PV_E_OVERFLOW, NULL, 0, "Int32Array.GetInt16Array");
        CheckGetArray(pv, PV_GETSTRA, PV_E_MISMATCH, NULL, 0, "Int32Array.GetStringArray");
        CheckGet(pv, PV_GETI32, PV_E_MISMATCH, NULL, 0, "Int32Array.GetInt32");
        ref = NULL;
        hr = QI(obj, &IID_IReferenceArray_Int32_, &ref);
        ok(hr == S_OK && ref, "QI(IReferenceArray<Int32>) returned 0x%08lx\n", hr);
        if (ref)
        {
            INT32 *vals = NULL;

            n = 0;
            hr = ((PFN_ARR)VTBL(ref)[6])(ref, &n, (void **)&vals);
            ok(hr == S_OK && n == 3 && vals && memcmp(vals, arr3, sizeof(arr3)) == 0,
               "IReferenceArray<Int32>::Value returned 0x%08lx, %u elements\n", hr, n);
            if (vals)
                CoTaskMemFree(vals);
            RELEASE(ref);
        }
        ref = NULL;
        hr = QI(obj, &IID_IReference_Int32_, &ref);
        ok(hr == E_NOINTERFACE && !ref, "QI(IReference<Int32>) on an array returned 0x%08lx\n", hr);
        RELEASE(obj);
    }
    obj = NULL;
    hr = ((PFN_ST_ARR)sv[ST_I32A])(statics, 0, (void *)arr3, &obj);
    pv = PvOf(obj, "Int32Array(0)");
    if (pv)
    {
        CheckGetArray(pv, PV_GETI32A, S_OK, NULL, 0, "Int32Array(0).GetInt32Array");
        CheckGetArray(pv, PV_GETI64A, S_OK, NULL, 0, "Int32Array(0).GetInt64Array");
        RELEASE(obj);
    }

    /* String array: deep copy */
    {
        HSTRING strs[2], *got = NULL;
        UINT32 n = 0;

        strs[0] = Str(L"x");
        strs[1] = Str(L"yz");
        obj = NULL;
        hr = ((PFN_ST_ARR)sv[ST_STRA])(statics, 2, strs, &obj);
        ok(hr == S_OK, "CreateStringArray returned 0x%08lx\n", hr);
        pv = PvOf(obj, "StringArray");
        if (pv)
        {
            CheckClassName(pv, L"Windows.Foundation.IReferenceArray`1<String>", "StringArray class name");
            hr = ((PFN_ARR)VTBL(pv)[PV_GETSTRA])(pv, &n, (void **)&got);
            ok(hr == S_OK && n == 2 && got, "GetStringArray returned 0x%08lx, %u\n", hr, n);
            if (hr == S_OK && n == 2)
            {
                CheckString(got[0], L"x", "StringArray[0]");
                CheckString(got[1], L"yz", "StringArray[1]");
                pWindowsDeleteString(got[0]);
                pWindowsDeleteString(got[1]);
            }
            if (got)
                CoTaskMemFree(got);
            ref = NULL;
            hr = QI(obj, &IID_IReferenceArray_String_, &ref);
            ok(hr == S_OK && ref, "QI(IReferenceArray<String>) returned 0x%08lx\n", hr);
            if (ref)
                RELEASE(ref);
            RELEASE(obj);
        }
        pWindowsDeleteString(strs[0]);
        pWindowsDeleteString(strs[1]);
    }

    RELEASE(statics);
}

/* ---- ApiInformation ----
 * Windows.Foundation.Metadata.ApiInformation. IApiInformationStatics: member order and id from microsoft/windows-rs
 * (Windows/Foundation/Metadata/mod.rs). The answers are those of this system's own types and contracts (see
 * dll/win32/wintypes/apiinformation.c), so the test only asks for types it knows to be provided or to be absent. */

DEFINE_GUID(IID_IApiInformationStatics_, 0x997439fe, 0xf681, 0x4a11, 0xb4, 0x16, 0xc1, 0x3a, 0x47, 0xe8, 0xba, 0x36);

#define AI_ISTYPE 6
#define AI_ISMETHOD 7
#define AI_ISMETHODARITY 8
#define AI_ISEVENT 9
#define AI_ISPROPERTY 10
#define AI_ISREADONLYPROP 11
#define AI_ISWRITEABLEPROP 12
#define AI_ISENUMVALUE 13
#define AI_CONTRACT 14
#define AI_CONTRACTMINOR 15

static const WCHAR ApiInfoClass[] = L"Windows.Foundation.Metadata.ApiInformation";
static const WCHAR ClassKeyBase[] = L"SOFTWARE\\Microsoft\\WindowsRuntime\\ActivatableClassId\\";

static void TestApiInformationRegistration(void)
{
    HKEY key;
    WCHAR path[MAX_PATH], key_name[256];
    DWORD type, size, value;
    LONG ret;

    wcscpy(key_name, ClassKeyBase);
    wcscat(key_name, ApiInfoClass);
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_name, 0, KEY_READ, &key);
    ok(ret == ERROR_SUCCESS, "the class key is not registered: %ld\n", ret);
    if (ret)
        return;
    size = sizeof(path);
    ret = RegQueryValueExW(key, L"DllPath", NULL, &type, (BYTE *)path, &size);
    ok(ret == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ), "DllPath: %ld, type %lu\n", ret, type);
    if (ret == ERROR_SUCCESS)
    {
        WCHAR *end = path + wcslen(path) - wcslen(L"wintypes.dll");
        ok(end >= path && _wcsicmp(end, L"wintypes.dll") == 0, "DllPath is '%ls', expected wintypes.dll\n", path);
    }
    size = sizeof(value);
    ret = RegQueryValueExW(key, L"ActivationType", NULL, &type, (BYTE *)&value, &size);
    ok(ret == ERROR_SUCCESS && type == REG_DWORD && value == 0, "ActivationType: %ld, type %lu, value %lu\n", ret, type, value);
    RegCloseKey(key);
}

static BYTE AiType(void *statics, const WCHAR *name, HRESULT *phr)
{
    HSTRING h = name ? Str(name) : NULL;
    BYTE present = 0xEE;
    HRESULT hr = ((PFN_HSTR_OUT)VTBL(statics)[AI_ISTYPE])(statics, h, &present);

    if (phr)
        *phr = hr;
    if (h)
        pWindowsDeleteString(h);
    return present;
}

typedef HRESULT (STDMETHODCALLTYPE *PFN_2HSTR_OUT)(void *, HSTRING, HSTRING, void *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_2HSTR_U32_OUT)(void *, HSTRING, HSTRING, UINT32, void *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_HSTR_U16_OUT)(void *, HSTRING, UINT16, void *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_HSTR_U16_U16_OUT)(void *, HSTRING, UINT16, UINT16, void *);

static BYTE AiMember(void *statics, int slot, const WCHAR *type, const WCHAR *member, HRESULT *phr)
{
    HSTRING t = type ? Str(type) : NULL, m = member ? Str(member) : NULL;
    BYTE present = 0xEE;
    HRESULT hr = ((PFN_2HSTR_OUT)VTBL(statics)[slot])(statics, t, m, &present);

    if (phr)
        *phr = hr;
    if (t)
        pWindowsDeleteString(t);
    if (m)
        pWindowsDeleteString(m);
    return present;
}

static BYTE AiContract(void *statics, const WCHAR *name, UINT16 major, int with_minor, UINT16 minor, HRESULT *phr)
{
    HSTRING h = name ? Str(name) : NULL;
    BYTE present = 0xEE;
    HRESULT hr;

    if (with_minor)
        hr = ((PFN_HSTR_U16_U16_OUT)VTBL(statics)[AI_CONTRACTMINOR])(statics, h, major, minor, &present);
    else
        hr = ((PFN_HSTR_U16_OUT)VTBL(statics)[AI_CONTRACT])(statics, h, major, &present);
    if (phr)
        *phr = hr;
    if (h)
        pWindowsDeleteString(h);
    return present;
}

/* A class key that points at a DLL that is there or is not: IsTypePresent follows the registration */
static void TestApiInformationRegisteredClasses(void *statics)
{
    static const WCHAR Scratch[] = L"Windows.NitroApiTest.ScratchClass";
    WCHAR key_name[256], dll[MAX_PATH];
    HKEY key;
    HRESULT hr;
    BYTE present;
    LONG ret;

    wcscpy(key_name, ClassKeyBase);
    wcscat(key_name, Scratch);
    present = AiType(statics, Scratch, &hr);
    ok(hr == S_OK && present == 0, "unregistered scratch class: 0x%08lx, %u\n", hr, present);

    ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key_name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL);
    if (ret)
    {
        skip("cannot create a class key (%ld)\n", ret);
        return;
    }
    wcscpy(dll, L"%SystemRoot%\\system32\\nitro-no-such-file.dll");
    RegSetValueExW(key, L"DllPath", 0, REG_EXPAND_SZ, (BYTE *)dll, (wcslen(dll) + 1) * sizeof(WCHAR));
    present = AiType(statics, Scratch, &hr);
    ok(hr == S_OK && present == 0, "registered class with a missing DLL: 0x%08lx, %u\n", hr, present);

    wcscpy(dll, L"%SystemRoot%\\system32\\kernel32.dll");
    RegSetValueExW(key, L"DllPath", 0, REG_EXPAND_SZ, (BYTE *)dll, (wcslen(dll) + 1) * sizeof(WCHAR));
    present = AiType(statics, Scratch, &hr);
    ok(hr == S_OK && present == 1, "registered class with its DLL: 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"Windows.nitroapitest.scratchclass", &hr);
    ok(hr == S_OK && present == 0, "case of a registered class (names are case-sensitive): 0x%08lx, %u\n", hr, present);

    /* A DllPath that expands to more than MAX_PATH characters: not registered. The unexpanded text is the name
     * of a file that exists, so a fallback to it (or a use of the unfilled buffer) would find a DLL. */
    {
        static const WCHAR LongVar[] = L"NITRO_APITEST_LONG";
        WCHAR value[301], literal[MAX_PATH];
        HANDLE file;
        UINT i;

        for (i = 0; i < ARRAYSIZE(value) - 1; i++)
            value[i] = L'a';
        value[i] = 0;
        GetTempPathW(ARRAYSIZE(literal), literal);
        wcscpy(dll, literal);
        wcscat(dll, L"%NITRO_APITEST_LONG%");
        wcscat(literal, L"%NITRO_APITEST_LONG%");
        file = CreateFileW(literal, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
        if (file == INVALID_HANDLE_VALUE)
            skip("cannot create %ls (%lu)\n", literal, GetLastError());
        else
        {
            CloseHandle(file);
            SetEnvironmentVariableW(LongVar, value);
            ok(ExpandEnvironmentStringsW(dll, value, ARRAYSIZE(value)) > MAX_PATH, "the path does not expand beyond MAX_PATH\n");
            RegSetValueExW(key, L"DllPath", 0, REG_EXPAND_SZ, (BYTE *)dll, (wcslen(dll) + 1) * sizeof(WCHAR));
            present = AiType(statics, Scratch, &hr);
            ok(hr == S_OK && present == 0, "registered class with a DllPath that expands beyond MAX_PATH: 0x%08lx, %u\n", hr, present);

            /* the same text as a REG_SZ is a path as it is, and is found */
            RegSetValueExW(key, L"DllPath", 0, REG_SZ, (BYTE *)dll, (wcslen(dll) + 1) * sizeof(WCHAR));
            present = AiType(statics, Scratch, &hr);
            ok(hr == S_OK && present == 1, "registered class with a literal DllPath: 0x%08lx, %u\n", hr, present);

            SetEnvironmentVariableW(LongVar, NULL);
            DeleteFileW(literal);
        }
    }

    RegCloseKey(key);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, key_name);
    present = AiType(statics, Scratch, &hr);
    ok(hr == S_OK && present == 0, "deleted scratch class: 0x%08lx, %u\n", hr, present);
}

START_TEST(ApiInformation)
{
    void *statics = NULL, *af = NULL, *obj;
    HRESULT hr;
    BYTE present;
    HSTRING name;
    ULONG count;
    IID *iids;
    int level;

    TestApiInformationRegistration();

    if (!Init())
    {
        skip("combase.dll has no Windows Runtime activation\n");
        return;
    }
    name = Str(ApiInfoClass);
    hr = pRoGetActivationFactory(name, &IID_IApiInformationStatics_, &statics);
    pWindowsDeleteString(name);
    ok(hr == S_OK && statics, "RoGetActivationFactory(ApiInformation) returned 0x%08lx, %p\n", hr, statics);
    if (!statics)
        return;

    /* measured on Windows 10: the factory of a static class has no runtime class name */
    name = (HSTRING)1;
    hr = GETNAME(statics, &name);
    ok(hr == 0x8000000E /* E_ILLEGAL_METHOD_CALL */ && !name, "GetRuntimeClassName: 0x%08lx, %p\n", hr, name);
    level = -1;
    hr = GETTRUST(statics, &level);
    ok(hr == S_OK && level == 0, "GetTrustLevel: 0x%08lx, %d\n", hr, level);
    hr = QI(statics, &IID_IAF, &af);
    ok(hr == S_OK && af, "QI(IActivationFactory) returned 0x%08lx\n", hr);
    if (af)
    {
        obj = (void *)1;
        hr = ((PFN_OUT)VTBL(af)[6])(af, &obj);
        ok(FAILED(hr) && !obj, "ActivateInstance of a static class: 0x%08lx, %p\n", hr, obj);
        RELEASE(af);
    }
    iids = NULL;
    count = 0;
    hr = ((PFN_GETIIDS)VTBL(statics)[3])(statics, &count, &iids);
    ok(hr == S_OK && count == 2 && iids && IsEqualGUID(&iids[0], &IID_IAF) && IsEqualGUID(&iids[1], &IID_IApiInformationStatics_),
       "GetIids: 0x%08lx, %lu\n", hr, count);
    if (iids)
        CoTaskMemFree(iids);

    /* contracts: the table of RoIsApiContractPresent */
    present = AiContract(statics, L"Windows.Foundation.UniversalApiContract", 1, 0, 0, &hr);
    ok(hr == S_OK && present == 1, "UniversalApiContract 1: 0x%08lx, %u\n", hr, present);
    present = AiContract(statics, L"Windows.Foundation.UniversalApiContract", 10, 0, 0, &hr);
    ok(hr == S_OK && present == 1, "UniversalApiContract 10: 0x%08lx, %u\n", hr, present);
    present = AiContract(statics, L"Windows.Foundation.UniversalApiContract", 11, 0, 0, &hr);
    ok(hr == S_OK && present == 0, "UniversalApiContract 11: 0x%08lx, %u\n", hr, present);
    present = AiContract(statics, L"Windows.Foundation.UniversalApiContract", 10, 1, 0, &hr);
    ok(hr == S_OK && present == 1, "UniversalApiContract 10.0: 0x%08lx, %u\n", hr, present);
    present = AiContract(statics, L"Windows.Foundation.UniversalApiContract", 10, 1, 1, &hr);
    ok(hr == S_OK && present == 0, "UniversalApiContract 10.1: 0x%08lx, %u\n", hr, present);
    present = AiContract(statics, L"Windows.Foundation.UniversalApiContract", 9, 1, 5, &hr);
    ok(hr == S_OK && present == 1, "UniversalApiContract 9.5: 0x%08lx, %u\n", hr, present);
    present = AiContract(statics, L"Windows.Foundation.NoSuchContract", 1, 0, 0, &hr);
    ok(hr == S_OK && present == 0, "unknown contract: 0x%08lx, %u\n", hr, present);
    present = AiContract(statics, L"windows.foundation.universalapicontract", 1, 0, 0, &hr);
    ok(hr == S_OK && present == 1, "contract name in lower case: 0x%08lx, %u\n", hr, present);
    present = AiContract(statics, L"", 1, 0, 0, &hr);
    ok(hr == E_INVALIDARG && present == 0, "empty contract name: 0x%08lx, %u\n", hr, present);
    present = AiContract(statics, NULL, 1, 1, 0, &hr);
    ok(hr == E_INVALIDARG && present == 0, "NULL contract name: 0x%08lx, %u\n", hr, present);

    /* types: what this system provides */
    present = AiType(statics, ApiInfoClass, &hr);
    ok(hr == S_OK && present == 1, "IsTypePresent(ApiInformation): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"Windows.Foundation.PropertyValue", &hr);
    ok(hr == S_OK && present == 1, "IsTypePresent(PropertyValue): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"Windows.Foundation.IPropertyValue", &hr);
    ok(hr == S_OK && present == 1, "IsTypePresent(IPropertyValue): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"Windows.Foundation.PropertyType", &hr);
    ok(hr == S_OK && present == 1, "IsTypePresent(PropertyType): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"Windows.Nonexistent.NoSuchType", &hr);
    ok(hr == S_OK && present == 0, "IsTypePresent(unknown type): 0x%08lx, %u\n", hr, present);
    /* measured on Windows 10: a name in a namespace that is not known fails with 0x80073D54 (also a name in lower case) */
    present = AiType(statics, L"Nonexistent.Type.Name", &hr);
    ok(hr == 0x80073D54 && present == 0, "IsTypePresent(unknown namespace): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"System.String", &hr);
    ok(hr == 0x80073D54 && present == 0, "IsTypePresent(System.String): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"windows.foundation.metadata.apiinformation", &hr);
    ok(hr == 0x80073D54 && present == 0, "IsTypePresent(lower case): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"Windows.Foundation.Metadata.ApiInformation ", &hr);
    ok(hr == S_OK && present == 0, "IsTypePresent(name and a space): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"Windows.Foundation", &hr);
    ok(hr == S_OK && present == 0, "IsTypePresent(a namespace): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"Windows", &hr);
    ok(hr == S_OK && present == 0, "IsTypePresent(Windows): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, L"", &hr);
    ok(hr == E_INVALIDARG && present == 0, "IsTypePresent(empty): 0x%08lx, %u\n", hr, present);
    present = AiType(statics, NULL, &hr);
    ok(hr == E_INVALIDARG && present == 0, "IsTypePresent(NULL): 0x%08lx, %u\n", hr, present);
    TestApiInformationRegisteredClasses(statics);

    /* members */
    present = AiMember(statics, AI_ISMETHOD, ApiInfoClass, L"IsTypePresent", &hr);
    ok(hr == S_OK && present == 1, "IsMethodPresent(IsTypePresent): 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISMETHOD, ApiInfoClass, L"IsApiContractPresent", &hr);
    ok(hr == S_OK && present == 1, "IsMethodPresent(IsApiContractPresent): 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISMETHOD, ApiInfoClass, L"isTypePresent", &hr);
    ok(hr == S_OK && present == 0, "IsMethodPresent(isTypePresent, names are case-sensitive): 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISMETHOD, ApiInfoClass, L"NoSuchMethod", &hr);
    ok(hr == S_OK && present == 0, "IsMethodPresent(NoSuchMethod): 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISMETHOD, L"Windows.Nonexistent.NoSuchType", L"IsTypePresent", &hr);
    ok(hr == S_OK && present == 0, "IsMethodPresent(unknown type): 0x%08lx, %u\n", hr, present);
    {
        HSTRING t = Str(ApiInfoClass), m = Str(L"IsApiContractPresent");

        present = 0xEE;
        hr = ((PFN_2HSTR_U32_OUT)VTBL(statics)[AI_ISMETHODARITY])(statics, t, m, 3, &present);
        ok(hr == S_OK && present == 1, "IsMethodPresent(IsApiContractPresent, 3): 0x%08lx, %u\n", hr, present);
        present = 0xEE;
        hr = ((PFN_2HSTR_U32_OUT)VTBL(statics)[AI_ISMETHODARITY])(statics, t, m, 4, &present);
        ok(hr == S_OK && present == 0, "IsMethodPresent(IsApiContractPresent, 4): 0x%08lx, %u\n", hr, present);
        pWindowsDeleteString(t);
        pWindowsDeleteString(m);
    }
    present = AiMember(statics, AI_ISEVENT, ApiInfoClass, L"Changed", &hr);
    ok(hr == S_OK && present == 0, "IsEventPresent: 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISPROPERTY, ApiInfoClass, L"IsTypePresent", &hr);
    ok(hr == S_OK && present == 0, "IsPropertyPresent: 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISREADONLYPROP, ApiInfoClass, L"IsTypePresent", &hr);
    ok(hr == S_OK && present == 0, "IsReadOnlyPropertyPresent: 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISWRITEABLEPROP, ApiInfoClass, L"IsTypePresent", &hr);
    ok(hr == S_OK && present == 0, "IsWriteablePropertyPresent: 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISENUMVALUE, L"Windows.Foundation.PropertyType", L"UInt8", &hr);
    ok(hr == S_OK && present == 1, "IsEnumNamedValuePresent(UInt8): 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISENUMVALUE, L"Windows.Foundation.PropertyType", L"RectArray", &hr);
    ok(hr == S_OK && present == 1, "IsEnumNamedValuePresent(RectArray): 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISENUMVALUE, L"Windows.Foundation.PropertyType", L"NoSuchValue", &hr);
    ok(hr == S_OK && present == 0, "IsEnumNamedValuePresent(NoSuchValue): 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISENUMVALUE, ApiInfoClass, L"UInt8", &hr);
    ok(hr == S_OK && present == 0, "IsEnumNamedValuePresent(not an enum): 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISMETHOD, NULL, L"IsTypePresent", &hr);
    ok(hr == E_INVALIDARG && present == 0, "IsMethodPresent(NULL type): 0x%08lx, %u\n", hr, present);
    present = AiMember(statics, AI_ISMETHOD, ApiInfoClass, L"", &hr);
    ok(hr == E_INVALIDARG && present == 0, "IsMethodPresent(empty member): 0x%08lx, %u\n", hr, present);

    /* a NULL result pointer */
    name = Str(ApiInfoClass);
    hr = ((PFN_HSTR_OUT)VTBL(statics)[AI_ISTYPE])(statics, name, NULL);
    ok(hr == E_POINTER, "IsTypePresent(NULL result): 0x%08lx\n", hr);
    pWindowsDeleteString(name);

    RELEASE(statics);
}
