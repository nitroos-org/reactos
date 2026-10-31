/*
 * PROJECT:     ReactOS WMI .NET helper library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     wminet_utils.dll: the native helper System.Management loads from the
 *              .NET Framework directory (clean-room implementation)
 *
 * System.Management (the one PowerShell 7 ships, and the .NET Framework one) loads
 * "<InstallRoot>\v4.0.30319\wminet_utils.dll", resolves the exports below by name and
 * calls them through delegates. Windows ships the DLL with the .NET Framework 4.x,
 * which is not part of ReactOS, so without this file the type initializer of
 * System.Management.WmiNetUtilsHelper throws.
 *
 * The exports fall in three groups:
 *  - "vtable forwarders" (Get, Put, Clone, QualifierSet_Get, GetPropertyHandle ...).
 *    The first argument is the vtable slot of the IWbemClassObject, IWbemQualifierSet,
 *    IWbemObjectAccess or IComThreadingInfo method, the second is the interface
 *    pointer, the rest are the arguments of that method (see the delegate
 *    declarations in System.Management's WmiNetUtilsHelper). Each forwarder calls the
 *    slot; the managed side does the VARIANT and SAFEARRAY marshaling.
 *  - the IWbemServices / IEnumWbemClassObject helpers (ConnectServerWmi,
 *    ExecQueryWmi ...): perform the call and set the COM security blanket from the
 *    caller's impersonation and authentication level, user, password and authority.
 *  - small helpers: SetSecurity/ResetSecurity, GetErrorInfo, GetDemultiplexedStub,
 *    Initialize, VerifyClientKey.
 */

#define COBJMACROS
#include <stdarg.h>
#include <string.h>
#include <wchar.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
#include <ole2.h>
#include <oleauto.h>
#include <wbemcli.h>

#define MAX_VTABLE_SLOT 64

/* CLSID_WbemLocator, {4590f811-1d3a-11d0-891f-00aa004b2e24}; wbemcli.h only declares it with DEFINE_GUID. */
static const GUID clsid_wbem_locator =
    {0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};

static BOOL allow_imanagementobject_qi;

/* Calls slot "slot" of the COM object "obj". "slot" comes from the managed caller, so keep it
 * inside the range of interfaces System.Management uses and never call QI/AddRef/Release. */
#define VCALL_CHECK(obj, slot) \
    do { if (!(obj) || (slot) < 3 || (slot) >= MAX_VTABLE_SLOT) return E_INVALIDARG; } while (0)
#define VSLOT(obj, slot) ((*(void ***)(obj))[(slot)])

/* ------------------------------------------------------------------------- */
/* Security                                                                  */
/* ------------------------------------------------------------------------- */

/* Moves the thread out of an impersonation so that the WMI calls that follow run with the
 * process identity, and hands the thread token back through ResetSecurity. */
HRESULT WINAPI wmi_SetSecurity(BOOL *need_reset, HANDLE *token)
{
    HANDLE thread_token = NULL;

    if (!need_reset || !token)
        return E_INVALIDARG;

    *need_reset = FALSE;
    *token = NULL;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE | TOKEN_QUERY, TRUE, &thread_token))
    {
        DWORD err = GetLastError();
        /* No impersonation: nothing to undo. */
        if (err == ERROR_NO_TOKEN)
            return S_OK;
        return HRESULT_FROM_WIN32(err);
    }

    if (!SetThreadToken(NULL, NULL))
    {
        DWORD err = GetLastError();
        CloseHandle(thread_token);
        return HRESULT_FROM_WIN32(err);
    }

    *token = thread_token;
    *need_reset = TRUE;
    return S_OK;
}

HRESULT WINAPI wmi_ResetSecurity(HANDLE token)
{
    if (!token)
        return S_OK;

    if (!SetThreadToken(NULL, token))
    {
        DWORD err = GetLastError();
        CloseHandle(token);
        return HRESULT_FROM_WIN32(err);
    }

    CloseHandle(token);
    return S_OK;
}

/* Sets the proxy blanket for "unk" from the caller's connection options.
 * "authority" is "NTLMDOMAIN:<domain>" or "Kerberos:<principal>" (or empty). */
static HRESULT set_blanket(IUnknown *unk, const WCHAR *user, const WCHAR *password,
                           const WCHAR *authority, DWORD imp_level, DWORD authn_level)
{
    static const WCHAR ntlmdomainW[] = {'n','t','l','m','d','o','m','a','i','n',':',0};
    static const WCHAR kerberosW[] = {'k','e','r','b','e','r','o','s',':',0};
    DWORD authn_svc = RPC_C_AUTHN_DEFAULT, authz_svc = RPC_C_AUTHZ_DEFAULT, caps = EOAC_NONE;
    WCHAR *principal = COLE_DEFAULT_PRINCIPAL, *domain = NULL;
    COAUTHIDENTITY identity;
    COAUTHIDENTITY *pidentity = NULL;
    HRESULT hr;

    if (!unk)
        return E_INVALIDARG;

    if (authority && *authority)
    {
        if (!_wcsnicmp(authority, kerberosW, ARRAYSIZE(kerberosW) - 1))
        {
            authn_svc = RPC_C_AUTHN_GSS_KERBEROS;
            principal = (WCHAR *)authority + ARRAYSIZE(kerberosW) - 1;
        }
        else if (!_wcsnicmp(authority, ntlmdomainW, ARRAYSIZE(ntlmdomainW) - 1))
        {
            authn_svc = RPC_C_AUTHN_WINNT;
            domain = (WCHAR *)authority + ARRAYSIZE(ntlmdomainW) - 1;
        }
    }

    if (user && *user)
    {
        const WCHAR *slash;

        memset(&identity, 0, sizeof(identity));
        /* "domain\user" in the user name overrides an empty authority domain */
        if (!domain && (slash = wcschr(user, '\\')))
        {
            domain = (WCHAR *)user;
            identity.DomainLength = (ULONG)(slash - user);
            user = slash + 1;
        }
        else if (domain)
            identity.DomainLength = (ULONG)wcslen(domain);

        identity.Domain = (USHORT *)domain;
        identity.User = (USHORT *)user;
        identity.UserLength = (ULONG)wcslen(user);
        identity.Password = (USHORT *)password;
        identity.PasswordLength = password ? (ULONG)wcslen(password) : 0;
        identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
        pidentity = &identity;
        if (authn_svc == RPC_C_AUTHN_DEFAULT)
            authn_svc = RPC_C_AUTHN_WINNT;
    }

    hr = CoSetProxyBlanket(unk, authn_svc, authz_svc, principal, authn_level, imp_level,
                           pidentity, caps);
    /* Not a proxy: an in-process object (wbemprox) has no blanket to set. */
    if (hr == E_NOINTERFACE || hr == E_INVALIDARG || hr == RPC_E_WRONG_THREAD)
        hr = S_OK;
    return hr;
}

HRESULT WINAPI wmi_BlessIWbemServices(IUnknown *services, BSTR user, const WCHAR *password,
                                             BSTR authority, int imp_level, int authn_level)
{
    return set_blanket(services, user, password, authority, imp_level, authn_level);
}

/* The managed side passes an IUnknown here (SecurityHandler.SecureIUnknown). */
HRESULT WINAPI wmi_BlessIWbemServicesObject(IUnknown *unk, BSTR user, const WCHAR *password,
                                                   BSTR authority, int imp_level, int authn_level)
{
    return set_blanket(unk, user, password, authority, imp_level, authn_level);
}

/* ------------------------------------------------------------------------- */
/* IWbemClassObject / IWbemObjectAccess forwarders                           */
/* ------------------------------------------------------------------------- */

HRESULT WINAPI wmi_GetPropertyHandle(int slot, void *obj, const WCHAR *name, LONG *type, LONG *handle)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, LONG *, LONG *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name, type, handle);
}

/* IWbemObjectAccess::WritePropertyValue(handle, numBytes, data): "data" is the managed string
 * (LPWSTR) whose bytes are copied into the property. */
HRESULT WINAPI wmi_WritePropertyValue(int slot, void *obj, LONG handle, LONG num_bytes, const WCHAR *data)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG, LONG, const BYTE *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, handle, num_bytes, (const BYTE *)data);
}

HRESULT WINAPI wmi_Clone(int slot, void *obj, void **copy)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, void **);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, copy);
}

HRESULT WINAPI wmi_GetQualifierSet(int slot, void *obj, void **qualset)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, void **);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, qualset);
}

HRESULT WINAPI wmi_Get(int slot, void *obj, const WCHAR *name, LONG flags, VARIANT *val, LONG *type, LONG *flavor)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, LONG, VARIANT *, LONG *, LONG *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name, flags, val, type, flavor);
}

HRESULT WINAPI wmi_Put(int slot, void *obj, const WCHAR *name, LONG flags, VARIANT *val, LONG type)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, LONG, VARIANT *, LONG);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name, flags, val, type);
}

HRESULT WINAPI wmi_Delete(int slot, void *obj, const WCHAR *name)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name);
}

HRESULT WINAPI wmi_GetNames(int slot, void *obj, const WCHAR *qualifier, LONG flags, VARIANT *qualval, SAFEARRAY **names)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, LONG, VARIANT *, SAFEARRAY **);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, qualifier, flags, qualval, names);
}

HRESULT WINAPI wmi_BeginEnumeration(int slot, void *obj, LONG flags)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags);
}

HRESULT WINAPI wmi_Next(int slot, void *obj, LONG flags, BSTR *name, VARIANT *val, LONG *type, LONG *flavor)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG, BSTR *, VARIANT *, LONG *, LONG *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags, name, val, type, flavor);
}

HRESULT WINAPI wmi_EndEnumeration(int slot, void *obj)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj);
}

HRESULT WINAPI wmi_GetPropertyQualifierSet(int slot, void *obj, const WCHAR *prop, void **qualset)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, void **);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, prop, qualset);
}

HRESULT WINAPI wmi_GetObjectText(int slot, void *obj, LONG flags, BSTR *text)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG, BSTR *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags, text);
}

HRESULT WINAPI wmi_SpawnDerivedClass(int slot, void *obj, LONG flags, void **newclass)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG, void **);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags, newclass);
}

HRESULT WINAPI wmi_SpawnInstance(int slot, void *obj, LONG flags, void **newinst)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG, void **);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags, newinst);
}

HRESULT WINAPI wmi_CompareTo(int slot, void *obj, LONG flags, void *compare_to)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG, void *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags, compare_to);
}

HRESULT WINAPI wmi_GetPropertyOrigin(int slot, void *obj, const WCHAR *name, BSTR *classname)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, BSTR *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name, classname);
}

HRESULT WINAPI wmi_InheritsFrom(int slot, void *obj, const WCHAR *ancestor)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, ancestor);
}

HRESULT WINAPI wmi_GetMethod(int slot, void *obj, const WCHAR *name, LONG flags, void **in_sig, void **out_sig)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, LONG, void **, void **);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name, flags, in_sig, out_sig);
}

HRESULT WINAPI wmi_PutMethod(int slot, void *obj, const WCHAR *name, LONG flags, void *in_sig, void *out_sig)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, LONG, void *, void *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name, flags, in_sig, out_sig);
}

HRESULT WINAPI wmi_DeleteMethod(int slot, void *obj, const WCHAR *name)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name);
}

HRESULT WINAPI wmi_BeginMethodEnumeration(int slot, void *obj, LONG flags)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags);
}

HRESULT WINAPI wmi_NextMethod(int slot, void *obj, LONG flags, BSTR *name, void **in_sig, void **out_sig)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG, BSTR *, void **, void **);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags, name, in_sig, out_sig);
}

HRESULT WINAPI wmi_EndMethodEnumeration(int slot, void *obj)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj);
}

HRESULT WINAPI wmi_GetMethodQualifierSet(int slot, void *obj, const WCHAR *method, void **qualset)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, void **);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, method, qualset);
}

HRESULT WINAPI wmi_GetMethodOrigin(int slot, void *obj, const WCHAR *method, BSTR *classname)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, BSTR *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, method, classname);
}

/* ------------------------------------------------------------------------- */
/* IWbemQualifierSet forwarders                                              */
/* ------------------------------------------------------------------------- */

HRESULT WINAPI wmi_QualifierSet_Get(int slot, void *obj, const WCHAR *name, LONG flags, VARIANT *val, LONG *flavor)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, LONG, VARIANT *, LONG *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name, flags, val, flavor);
}

HRESULT WINAPI wmi_QualifierSet_Put(int slot, void *obj, const WCHAR *name, VARIANT *val, LONG flavor)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR, VARIANT *, LONG);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name, val, flavor);
}

HRESULT WINAPI wmi_QualifierSet_Delete(int slot, void *obj, const WCHAR *name)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LPCWSTR);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, name);
}

HRESULT WINAPI wmi_QualifierSet_GetNames(int slot, void *obj, LONG flags, SAFEARRAY **names)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG, SAFEARRAY **);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags, names);
}

HRESULT WINAPI wmi_QualifierSet_BeginEnumeration(int slot, void *obj, LONG flags)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags);
}

HRESULT WINAPI wmi_QualifierSet_Next(int slot, void *obj, LONG flags, BSTR *name, VARIANT *val, LONG *flavor)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, LONG, BSTR *, VARIANT *, LONG *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, flags, name, val, flavor);
}

HRESULT WINAPI wmi_QualifierSet_EndEnumeration(int slot, void *obj)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj);
}

/* ------------------------------------------------------------------------- */
/* Apartment, stubs, errors                                                  */
/* ------------------------------------------------------------------------- */

/* IComThreadingInfo::GetCurrentApartmentType (slot 3). */
HRESULT WINAPI wmi_GetCurrentApartmentType(int slot, void *obj, int *apttype)
{
    typedef HRESULT (STDMETHODCALLTYPE *fn)(void *, int *);
    VCALL_CHECK(obj, slot);
    return ((fn)VSLOT(obj, slot))(obj, apttype);
}

/* Returns the object the event sink machinery calls into. Everything WMI hands out in
 * this process is called directly, so the "stub" is the object itself. */
HRESULT WINAPI wmi_GetDemultiplexedStub(IUnknown *unk, BOOL is_local, IUnknown **stub)
{
    if (!stub)
        return E_INVALIDARG;
    *stub = NULL;
    if (!unk)
        return E_INVALIDARG;

    IUnknown_AddRef(unk);
    *stub = unk;
    return S_OK;
}

/* The IErrorInfo of the thread, for Marshal.ThrowExceptionForHR. The caller takes the reference. */
IErrorInfo * WINAPI wmi_GetErrorInfo(void)
{
    IErrorInfo *info = NULL;

    if (GetErrorInfo(0, &info) != S_OK)
        return NULL;
    return info;
}

HRESULT WINAPI wmi_Initialize(BOOL allow_imanagementobject_qi_)
{
    allow_imanagementobject_qi = allow_imanagementobject_qi_;
    return S_OK;
}

/* Windows checks that the caller is signed by Microsoft here; the managed library calls it
 * once and ignores the result, so there is nothing to verify. */
void WINAPI wmi_VerifyClientKey(void)
{
}

/* ------------------------------------------------------------------------- */
/* IWbemServices / IEnumWbemClassObject helpers                              */
/* ------------------------------------------------------------------------- */

static HRESULT bless_enum(HRESULT hr, IEnumWbemClassObject **enum_, const WCHAR *user,
                          const WCHAR *password, const WCHAR *authority, int imp, int authn)
{
    if (FAILED(hr))
        return hr;

    hr = set_blanket((IUnknown *)*enum_, user, password, authority, imp, authn);
    if (FAILED(hr))
    {
        IEnumWbemClassObject_Release(*enum_);
        *enum_ = NULL;
    }
    return hr;
}

HRESULT WINAPI wmi_CreateInstanceEnumWmi(BSTR filter, LONG flags, IWbemContext *ctx,
        IEnumWbemClassObject **enum_, int imp, int authn, IWbemServices *ns,
        BSTR user, const WCHAR *password, BSTR authority)
{
    HRESULT hr;

    if (!enum_ || !ns)
        return WBEM_E_INVALID_PARAMETER;
    *enum_ = NULL;
    hr = IWbemServices_CreateInstanceEnum(ns, filter, flags, ctx, enum_);
    return bless_enum(hr, enum_, user, password, authority, imp, authn);
}

HRESULT WINAPI wmi_CreateClassEnumWmi(BSTR superclass, LONG flags, IWbemContext *ctx,
        IEnumWbemClassObject **enum_, int imp, int authn, IWbemServices *ns,
        BSTR user, const WCHAR *password, BSTR authority)
{
    HRESULT hr;

    if (!enum_ || !ns)
        return WBEM_E_INVALID_PARAMETER;
    *enum_ = NULL;
    hr = IWbemServices_CreateClassEnum(ns, superclass, flags, ctx, enum_);
    return bless_enum(hr, enum_, user, password, authority, imp, authn);
}

HRESULT WINAPI wmi_ExecQueryWmi(BSTR language, BSTR query, LONG flags, IWbemContext *ctx,
        IEnumWbemClassObject **enum_, int imp, int authn, IWbemServices *ns,
        BSTR user, const WCHAR *password, BSTR authority)
{
    HRESULT hr;

    if (!enum_ || !ns)
        return WBEM_E_INVALID_PARAMETER;
    *enum_ = NULL;
    hr = IWbemServices_ExecQuery(ns, language, query, flags, ctx, enum_);
    return bless_enum(hr, enum_, user, password, authority, imp, authn);
}

HRESULT WINAPI wmi_ExecNotificationQueryWmi(BSTR language, BSTR query, LONG flags, IWbemContext *ctx,
        IEnumWbemClassObject **enum_, int imp, int authn, IWbemServices *ns,
        BSTR user, const WCHAR *password, BSTR authority)
{
    HRESULT hr;

    if (!enum_ || !ns)
        return WBEM_E_INVALID_PARAMETER;
    *enum_ = NULL;
    hr = IWbemServices_ExecNotificationQuery(ns, language, query, flags, ctx, enum_);
    return bless_enum(hr, enum_, user, password, authority, imp, authn);
}

/* "call_result" is the address of an IWbemCallResult * the managed side may pass, or NULL. */
HRESULT WINAPI wmi_PutInstanceWmi(IWbemClassObject *inst, LONG flags, IWbemContext *ctx,
        IWbemCallResult **call_result, int imp, int authn, IWbemServices *ns,
        BSTR user, const WCHAR *password, BSTR authority)
{
    if (!ns)
        return WBEM_E_INVALID_PARAMETER;
    return IWbemServices_PutInstance(ns, inst, flags, ctx, call_result);
}

HRESULT WINAPI wmi_PutClassWmi(IWbemClassObject *obj, LONG flags, IWbemContext *ctx,
        IWbemCallResult **call_result, int imp, int authn, IWbemServices *ns,
        BSTR user, const WCHAR *password, BSTR authority)
{
    if (!ns)
        return WBEM_E_INVALID_PARAMETER;
    return IWbemServices_PutClass(ns, obj, flags, ctx, call_result);
}

HRESULT WINAPI wmi_CloneEnumWbemClassObject(IEnumWbemClassObject **enum_, int imp, int authn,
        IEnumWbemClassObject *cur, BSTR user, const WCHAR *password, BSTR authority)
{
    HRESULT hr;

    if (!enum_ || !cur)
        return WBEM_E_INVALID_PARAMETER;
    *enum_ = NULL;
    hr = IEnumWbemClassObject_Clone(cur, enum_);
    return bless_enum(hr, enum_, user, password, authority, imp, authn);
}

HRESULT WINAPI wmi_ConnectServerWmi(BSTR resource, BSTR user, const WCHAR *password, BSTR locale,
        LONG security_flags, BSTR authority, IWbemContext *ctx, IWbemServices **ns, int imp, int authn)
{
    IWbemLocator *locator;
    HRESULT hr;

    if (!ns)
        return WBEM_E_INVALID_PARAMETER;
    *ns = NULL;

    hr = CoCreateInstance(&clsid_wbem_locator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void **)&locator);
    if (FAILED(hr))
        return hr;

    hr = IWbemLocator_ConnectServer(locator, resource, user, (BSTR)password, locale,
                                    security_flags, authority, ctx, ns);
    IWbemLocator_Release(locator);
    if (FAILED(hr))
        return hr;

    hr = set_blanket((IUnknown *)*ns, user, password, authority, imp, authn);
    if (FAILED(hr))
    {
        IWbemServices_Release(*ns);
        *ns = NULL;
    }
    return hr;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(instance);
    return TRUE;
}
