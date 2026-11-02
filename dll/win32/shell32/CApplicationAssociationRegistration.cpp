/*
 * PROJECT:     shell32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IApplicationAssociationRegistration implementation
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *              Copyright 2002 Jon Griffiths (Wine, dlls/shell32/assoc.c: interface layout,
 *              QueryCurrentDefault arguments, SHCreateAssociationRegistration)
 *
 * The registry semantics (user choices, per protocol, per extension, per MIME type and per
 * client type keys, the RegisteredApplications capabilities) were measured black box on
 * Windows 7, see modules/rostests/apitests/shell32/IApplicationAssociationRegistration.cpp.
 */

#include "precomp.h"

WINE_DEFAULT_DEBUG_CHANNEL(shell);

#define ASSOC_ERR_NO_ASSOCIATION    HRESULT_FROM_WIN32(ERROR_NO_ASSOCIATION)
#define ASSOC_ERR_NOT_REGISTERED    HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)

static const WCHAR s_szUserAssociations[] = L"Software\\Microsoft\\Windows\\Shell\\Associations";
static const WCHAR s_szFileExts[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts";
static const WCHAR s_szClients[] = L"Software\\Clients";
static const WCHAR s_szRegisteredApps[] = L"SOFTWARE\\RegisteredApplications";

namespace
{

// Reads a string value (a REG_EXPAND_SZ value comes back expanded); returns the registry error.
static LONG ReadStringEx(HKEY hRoot, LPCWSTR pszKey, LPCWSTR pszValue, CStringW &strOut)
{
    DWORD cb = 0;
    LONG lError = RegGetValueW(hRoot, pszKey, pszValue, RRF_RT_REG_SZ,
                               NULL, NULL, &cb);
    if (lError != ERROR_SUCCESS)
        return lError;

    PWSTR pszBuf = strOut.GetBuffer(cb / sizeof(WCHAR) + 1);
    lError = RegGetValueW(hRoot, pszKey, pszValue, RRF_RT_REG_SZ,
                          NULL, pszBuf, &cb);
    strOut.ReleaseBuffer(lError == ERROR_SUCCESS ? -1 : 0);
    return lError;
}

static BOOL ReadString(HKEY hRoot, LPCWSTR pszKey, LPCWSTR pszValue, CStringW &strOut)
{
    return ReadStringEx(hRoot, pszKey, pszValue, strOut) == ERROR_SUCCESS;
}

// A missing key or value is "no association"; any other error is passed on.
static HRESULT ErrorToHResult(LONG lError)
{
    if (lError == ERROR_SUCCESS)
        return S_OK;
    if (lError == ERROR_FILE_NOT_FOUND || lError == ERROR_PATH_NOT_FOUND)
        return ASSOC_ERR_NO_ASSOCIATION;
    return HRESULT_FROM_WIN32(lError);
}

static BOOL KeyExists(HKEY hRoot, LPCWSTR pszKey)
{
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, pszKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL ValueExists(HKEY hRoot, LPCWSTR pszKey, LPCWSTR pszValue)
{
    HKEY hKey;
    BOOL bResult;
    if (RegOpenKeyExW(hRoot, pszKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    bResult = RegQueryValueExW(hKey, pszValue, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return bResult;
}

static HRESULT WriteString(HKEY hRoot, LPCWSTR pszKey, LPCWSTR pszValue, LPCWSTR pszData)
{
    HKEY hKey;
    LONG lError = RegCreateKeyExW(hRoot, pszKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (lError != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(lError);

    lError = RegSetValueExW(hKey, pszValue, 0, REG_SZ, (const BYTE *)pszData,
                            (lstrlenW(pszData) + 1) * sizeof(WCHAR));
    RegCloseKey(hKey);
    return HRESULT_FROM_WIN32(lError);
}

static LPCWSTR CapabilityGroup(ASSOCIATIONTYPE type)
{
    switch (type)
    {
        case AT_FILEEXTENSION:   return L"FileAssociations";
        case AT_URLPROTOCOL:     return L"UrlAssociations";
        case AT_STARTMENUCLIENT: return L"Startmenu";
        case AT_MIMETYPE:        return L"MIMEAssociations";
    }
    return NULL;
}

static HRESULT ValidateQuery(LPCWSTR pszQuery, ASSOCIATIONTYPE type)
{
    if ((UINT)type > AT_MIMETYPE)
        return E_INVALIDARG;
    if ((type == AT_URLPROTOCOL || type == AT_FILEEXTENSION) && !*pszQuery)
        return E_INVALIDARG;
    if (type == AT_FILEEXTENSION && *pszQuery != L'.')
        return E_INVALIDARG;
    if (type == AT_URLPROTOCOL && wcschr(pszQuery, L'\\'))
        return E_INVALIDARG;
    return S_OK;
}

// The user's choice: the progid of a UserChoice key, or the default value of a client key.
static HRESULT ReadUserChoice(ASSOCIATIONTYPE type, LPCWSTR pszQuery, CStringW &strOut)
{
    CStringW strKey;
    LPCWSTR pszValue = L"Progid";

    switch (type)
    {
        case AT_URLPROTOCOL:
            strKey.Format(L"%s\\UrlAssociations\\%s\\UserChoice", s_szUserAssociations, pszQuery);
            break;
        case AT_MIMETYPE:
            strKey.Format(L"%s\\MIMEAssociations\\%s\\UserChoice", s_szUserAssociations, pszQuery);
            break;
        case AT_FILEEXTENSION:
            strKey.Format(L"%s\\%s\\UserChoice", s_szFileExts, pszQuery);
            break;
        case AT_STARTMENUCLIENT:
            strKey.Format(L"%s\\%s", s_szClients, pszQuery);
            pszValue = NULL;
            break;
        default:
            return ASSOC_ERR_NO_ASSOCIATION;
    }

    LONG lError = ReadStringEx(HKEY_CURRENT_USER, strKey, pszValue, strOut);
    if (lError == ERROR_UNSUPPORTED_TYPE)
        lError = ERROR_DATATYPE_MISMATCH;
    return ErrorToHResult(lError);
}

// Command of the open verb of a protocol class.
static HRESULT ReadProtocolCommand(HKEY hRoot, LPCWSTR pszClassesKey, LPCWSTR pszClass, CStringW &strOut)
{
    CStringW strKey;
    strKey.Format(L"%s\\%s", pszClassesKey, pszClass);
    if (!KeyExists(hRoot, strKey))
        return ASSOC_ERR_NO_ASSOCIATION;
    if (!ValueExists(hRoot, strKey, L"URL Protocol"))
        return E_INVALIDARG;

    strKey += L"\\shell\\open\\command";
    return ErrorToHResult(ReadStringEx(hRoot, strKey, NULL, strOut));
}

static HRESULT ReadMachineProtocolCommand(LPCWSTR pszClass, CStringW &strOut)
{
    return ReadProtocolCommand(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes", pszClass, strOut);
}

// The system-wide default; for an extension, the effective one comes from the merged class view.
static HRESULT ReadMachineDefault(ASSOCIATIONTYPE type, LPCWSTR pszQuery, BOOL bMerged, CStringW &strOut)
{
    CStringW strKey;

    switch (type)
    {
        case AT_URLPROTOCOL:
        {
            HRESULT hr = ReadMachineProtocolCommand(pszQuery, strOut);
            if (FAILED(hr) && bMerged)
            {
                // the effective view also looks at the classes of the user
                CStringW strUser;
                if (SUCCEEDED(ReadProtocolCommand(HKEY_CURRENT_USER, L"Software\\Classes", pszQuery, strUser)))
                {
                    strOut = strUser;
                    hr = S_OK;
                }
            }
            return hr;
        }
        case AT_FILEEXTENSION:
            if (bMerged)
                return ErrorToHResult(ReadStringEx(HKEY_CLASSES_ROOT, pszQuery, NULL, strOut));
            strKey.Format(L"SOFTWARE\\Classes\\%s", pszQuery);
            return ErrorToHResult(ReadStringEx(HKEY_LOCAL_MACHINE, strKey, NULL, strOut));
        case AT_MIMETYPE:
            strKey.Format(L"MIME\\Database\\Content Type\\%s", pszQuery);
            return ErrorToHResult(ReadStringEx(HKEY_CLASSES_ROOT, strKey, L"CLSID", strOut));
        case AT_STARTMENUCLIENT:
            strKey.Format(L"SOFTWARE\\Clients\\%s", pszQuery);
            return ErrorToHResult(ReadStringEx(HKEY_LOCAL_MACHINE, strKey, NULL, strOut));
    }
    return E_INVALIDARG;
}

static HRESULT ReadDefault(LPCWSTR pszQuery, ASSOCIATIONTYPE type, ASSOCIATIONLEVEL level,
                           CStringW &strOut, BOOL *pbFromUser = NULL)
{
    if (pbFromUser)
        *pbFromUser = FALSE;

    if (!*pszQuery)
        return ASSOC_ERR_NO_ASSOCIATION;

    if (level != AL_MACHINE)
    {
        HRESULT hr = ReadUserChoice(type, pszQuery, strOut);
        if (hr != ASSOC_ERR_NO_ASSOCIATION)
        {
            if (pbFromUser && SUCCEEDED(hr))
                *pbFromUser = TRUE;
            return hr;
        }
    }
    if (level == AL_USER)
        return ASSOC_ERR_NO_ASSOCIATION;

    return ReadMachineDefault(type, pszQuery, level == AL_EFFECTIVE, strOut);
}

// The capabilities key of a registered application: RegisteredApplications of the user (a per-user
// install such as Chrome's, or Firefox's own) first, then the ones of the machine.
static HRESULT OpenCapabilities(LPCWSTR pszApp, HKEY *phKey)
{
    static const HKEY s_Roots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    CStringW strPath;
    *phKey = NULL;
    if (!*pszApp)
        return ASSOC_ERR_NOT_REGISTERED;

    for (UINT i = 0; i < _countof(s_Roots); ++i)
    {
        if (!ReadString(s_Roots[i], s_szRegisteredApps, pszApp, strPath))
            continue;
        LONG lError = RegOpenKeyExW(s_Roots[i], strPath, 0, KEY_READ, phKey);
        if (lError == ERROR_SUCCESS)
            return S_OK;
        if (s_Roots[i] == HKEY_LOCAL_MACHINE)
            return HRESULT_FROM_WIN32(lError);
    }
    return ASSOC_ERR_NOT_REGISTERED;
}

// The progid (or client name) an application declares for a protocol, extension, MIME type or client type.
static BOOL ReadCapability(HKEY hCaps, ASSOCIATIONTYPE type, LPCWSTR pszQuery, CStringW &strOut)
{
    HKEY hGroup;
    BOOL bFound = FALSE;

    if (RegOpenKeyExW(hCaps, CapabilityGroup(type), 0, KEY_QUERY_VALUE, &hGroup) != ERROR_SUCCESS)
        return FALSE;
    bFound = ReadString(hGroup, NULL, pszQuery, strOut);
    RegCloseKey(hGroup);
    return bFound;
}

// Open command of a progid, from the merged class view.
static BOOL ReadClassCommand(LPCWSTR pszProgId, CStringW &strOut)
{
    CStringW strKey;
    strKey.Format(L"%s\\shell\\open\\command", pszProgId);
    return ReadString(HKEY_CLASSES_ROOT, strKey, NULL, strOut);
}

// Two progids are the same association when their names are or, outside of the user level, their open commands are.
static BOOL ProgIdsMatch(LPCWSTR pszFirst, LPCWSTR pszSecond, BOOL bAllowCommand)
{
    if (!lstrcmpiW(pszFirst, pszSecond))
        return TRUE;
    if (!bAllowCommand)
        return FALSE;

    CStringW strFirst, strSecond;
    return ReadClassCommand(pszFirst, strFirst) && ReadClassCommand(pszSecond, strSecond) &&
           !strFirst.CompareNoCase(strSecond);
}

static HRESULT IsAppDefault(HKEY hCaps, LPCWSTR pszQuery, ASSOCIATIONTYPE type,
                            ASSOCIATIONLEVEL level, BOOL *pfDefault)
{
    CStringW strProgId, strCurrent;
    BOOL bFromUser;

    *pfDefault = FALSE;
    if (!*pszQuery || !ReadCapability(hCaps, type, pszQuery, strProgId))
        return E_INVALIDARG;

    HRESULT hr = ReadDefault(pszQuery, type, level, strCurrent, &bFromUser);
    if (FAILED(hr))
        return hr;

    if (!bFromUser && type == AT_URLPROTOCOL)
    {
        // The machine default is a command line: the application owns it when its handler has the same one.
        CStringW strHandlerCommand;
        if (SUCCEEDED(ReadMachineProtocolCommand(strProgId, strHandlerCommand)))
            *pfDefault = !strHandlerCommand.CompareNoCase(strCurrent);
    }
    else if (!bFromUser && type == AT_MIMETYPE)
    {
        // The machine default is the CLSID of the content type database: the progid has to carry the same one.
        CStringW strKey, strClsid;
        strKey.Format(L"%s\\CLSID", (LPCWSTR)strProgId);
        *pfDefault = ReadString(HKEY_CLASSES_ROOT, strKey, NULL, strClsid) && !strClsid.CompareNoCase(strCurrent);
    }
    else if (type == AT_STARTMENUCLIENT)
    {
        *pfDefault = !strProgId.CompareNoCase(strCurrent);
    }
    else
    {
        *pfDefault = ProgIdsMatch(strProgId, strCurrent, level != AL_USER);
    }
    return S_OK;
}

static HRESULT SetUserChoice(ASSOCIATIONTYPE type, LPCWSTR pszQuery, LPCWSTR pszProgId)
{
    CStringW strKey;

    switch (type)
    {
        case AT_URLPROTOCOL:
            strKey.Format(L"%s\\UrlAssociations\\%s\\UserChoice", s_szUserAssociations, pszQuery);
            return WriteString(HKEY_CURRENT_USER, strKey, L"Progid", pszProgId);
        case AT_MIMETYPE:
            strKey.Format(L"%s\\MIMEAssociations\\%s\\UserChoice", s_szUserAssociations, pszQuery);
            return WriteString(HKEY_CURRENT_USER, strKey, L"Progid", pszProgId);
        case AT_FILEEXTENSION:
            strKey.Format(L"%s\\%s\\UserChoice", s_szFileExts, pszQuery);
            return WriteString(HKEY_CURRENT_USER, strKey, L"Progid", pszProgId);
        case AT_STARTMENUCLIENT:
            strKey.Format(L"%s\\%s", s_szClients, pszQuery);
            return WriteString(HKEY_CURRENT_USER, strKey, NULL, pszProgId);
        default:
            return E_INVALIDARG;
    }
}

// Walks the capability groups in the order Windows 7 uses; a visitor other than S_OK ends the walk.
template<typename T>
static HRESULT ForEachCapability(HKEY hCaps, T &visitor)
{
    static const ASSOCIATIONTYPE s_Order[] = { AT_FILEEXTENSION, AT_URLPROTOCOL, AT_STARTMENUCLIENT, AT_MIMETYPE };

    for (UINT i = 0; i < _countof(s_Order); ++i)
    {
        HKEY hGroup;
        if (RegOpenKeyExW(hCaps, CapabilityGroup(s_Order[i]), 0, KEY_QUERY_VALUE, &hGroup) != ERROR_SUCCESS)
            continue;

        DWORD cchMax = 0;
        LONG lError = RegQueryInfoKeyW(hGroup, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &cchMax, NULL, NULL, NULL);
        CStringW strName;
        PWSTR pszName = lError == ERROR_SUCCESS ? strName.GetBuffer(cchMax + 1) : NULL;
        HRESULT hr = pszName ? S_OK : HRESULT_FROM_WIN32(lError);

        for (DWORD iValue = 0; pszName; ++iValue)
        {
            DWORD cchName = cchMax + 1;
            lError = RegEnumValueW(hGroup, iValue, pszName, &cchName, NULL, NULL, NULL, NULL);
            if (lError == ERROR_NO_MORE_ITEMS)
                break;
            if (lError != ERROR_SUCCESS)
            {
                hr = HRESULT_FROM_WIN32(lError);
                break;
            }

            CStringW strProgId;
            if (!ReadString(hGroup, NULL, pszName, strProgId))
                continue;

            hr = visitor.Visit(s_Order[i], pszName, strProgId);
            if (hr != S_OK)
                break;
        }
        if (pszName)
            strName.ReleaseBuffer(0);
        RegCloseKey(hGroup);
        if (hr != S_OK)
            return hr;
    }
    return S_OK;
}

struct IsDefaultAllVisitor
{
    HKEY hCaps;
    ASSOCIATIONLEVEL level;
    BOOL bDefault;

    // S_FALSE: an association the application does not own
    HRESULT Visit(ASSOCIATIONTYPE type, LPCWSTR pszName, LPCWSTR pszProgId)
    {
        BOOL bThis;
        HRESULT hr = IsAppDefault(hCaps, pszName, type, level, &bThis);
        if (FAILED(hr))
            return hr;
        bDefault = bThis;
        return bThis ? S_OK : S_FALSE;
    }
};

struct SetAllVisitor
{
    HRESULT Visit(ASSOCIATIONTYPE type, LPCWSTR pszName, LPCWSTR pszProgId)
    {
        return SetUserChoice(type, pszName, pszProgId);
    }
};

static void DeleteSubkeys(HKEY hRoot, LPCWSTR pszKey)
{
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, pszKey, 0, KEY_ENUMERATE_SUB_KEYS | DELETE, &hKey) != ERROR_SUCCESS)
        return;

    WCHAR szName[MAX_PATH];
    while (RegEnumKeyW(hKey, 0, szName, _countof(szName)) == ERROR_SUCCESS)
    {
        if (SHDeleteKeyW(hKey, szName) != ERROR_SUCCESS)
            break;
    }
    RegCloseKey(hKey);
}

} // namespace

CApplicationAssociationRegistration::CApplicationAssociationRegistration()
{
}

CApplicationAssociationRegistration::~CApplicationAssociationRegistration()
{
}

STDMETHODIMP
CApplicationAssociationRegistration::QueryCurrentDefault(LPCWSTR pszQuery, ASSOCIATIONTYPE atQueryType,
                                                         ASSOCIATIONLEVEL alQueryLevel,
                                                         LPWSTR *ppszAssociation)
{
    TRACE("(%p)->(%s, %d, %d, %p)\n", this, debugstr_w(pszQuery), atQueryType, alQueryLevel, ppszAssociation);

    if (!ppszAssociation || !pszQuery)
        return E_INVALIDARG;
    *ppszAssociation = NULL;

    if ((UINT)alQueryLevel > AL_USER)
        return E_INVALIDARG;
    HRESULT hr = ValidateQuery(pszQuery, atQueryType);
    if (FAILED(hr))
        return hr;

    CStringW strResult;
    hr = ReadDefault(pszQuery, atQueryType, alQueryLevel, strResult);
    if (FAILED(hr))
        return hr;

    SIZE_T cb = (strResult.GetLength() + 1) * sizeof(WCHAR);
    PWSTR pszCopy = (PWSTR)CoTaskMemAlloc(cb);
    if (!pszCopy)
        return E_OUTOFMEMORY;
    memcpy(pszCopy, (LPCWSTR)strResult, cb);
    *ppszAssociation = pszCopy;
    return S_OK;
}

STDMETHODIMP
CApplicationAssociationRegistration::QueryAppIsDefault(LPCWSTR pszQuery, ASSOCIATIONTYPE atQueryType,
                                                       ASSOCIATIONLEVEL alQueryLevel,
                                                       LPCWSTR pszAppRegistryName, BOOL *pfDefault)
{
    TRACE("(%p)->(%s, %d, %d, %s, %p)\n", this, debugstr_w(pszQuery), atQueryType, alQueryLevel,
          debugstr_w(pszAppRegistryName), pfDefault);

    if (!pfDefault || !pszQuery || !pszAppRegistryName)
        return E_INVALIDARG;
    *pfDefault = FALSE;

    if ((UINT)alQueryLevel > AL_USER)
        return E_INVALIDARG;
    HRESULT hr = ValidateQuery(pszQuery, atQueryType);
    if (FAILED(hr))
        return hr;

    HKEY hCaps;
    hr = OpenCapabilities(pszAppRegistryName, &hCaps);
    if (FAILED(hr))
        return hr;

    hr = IsAppDefault(hCaps, pszQuery, atQueryType, alQueryLevel, pfDefault);
    RegCloseKey(hCaps);
    return hr;
}

STDMETHODIMP
CApplicationAssociationRegistration::QueryAppIsDefaultAll(ASSOCIATIONLEVEL alQueryLevel,
                                                          LPCWSTR pszAppRegistryName, BOOL *pfDefault)
{
    TRACE("(%p)->(%d, %s, %p)\n", this, alQueryLevel, debugstr_w(pszAppRegistryName), pfDefault);

    if (!pfDefault || !pszAppRegistryName)
        return E_INVALIDARG;
    *pfDefault = FALSE;

    HKEY hCaps;
    HRESULT hr = OpenCapabilities(pszAppRegistryName, &hCaps);
    if (FAILED(hr))
        return hr;
    if ((UINT)alQueryLevel > AL_USER)
    {
        RegCloseKey(hCaps);
        return E_INVALIDARG;
    }

    IsDefaultAllVisitor visitor = { hCaps, alQueryLevel, TRUE };
    hr = ForEachCapability(hCaps, visitor);
    RegCloseKey(hCaps);
    if (FAILED(hr))
        return hr;

    *pfDefault = visitor.bDefault;
    return S_OK;
}

STDMETHODIMP
CApplicationAssociationRegistration::SetAppAsDefault(LPCWSTR pszAppRegistryName, LPCWSTR pszSet,
                                                     ASSOCIATIONTYPE atSetType)
{
    TRACE("(%p)->(%s, %s, %d)\n", this, debugstr_w(pszAppRegistryName), debugstr_w(pszSet), atSetType);

    if (!pszAppRegistryName || !pszSet)
        return E_INVALIDARG;
    HRESULT hr = ValidateQuery(pszSet, atSetType);
    if (FAILED(hr))
        return hr;

    HKEY hCaps;
    hr = OpenCapabilities(pszAppRegistryName, &hCaps);
    if (FAILED(hr))
        return hr;

    CStringW strProgId;
    if (!*pszSet || !ReadCapability(hCaps, atSetType, pszSet, strProgId))
        hr = E_INVALIDARG;
    else
        hr = SetUserChoice(atSetType, pszSet, strProgId);

    RegCloseKey(hCaps);
    return hr;
}

STDMETHODIMP
CApplicationAssociationRegistration::SetAppAsDefaultAll(LPCWSTR pszAppRegistryName)
{
    TRACE("(%p)->(%s)\n", this, debugstr_w(pszAppRegistryName));

    if (!pszAppRegistryName)
        return E_INVALIDARG;

    HKEY hCaps;
    HRESULT hr = OpenCapabilities(pszAppRegistryName, &hCaps);
    if (FAILED(hr))
        return hr;

    SetAllVisitor visitor;
    hr = ForEachCapability(hCaps, visitor);
    RegCloseKey(hCaps);
    return hr;
}

STDMETHODIMP
CApplicationAssociationRegistration::ClearUserAssociations()
{
    TRACE("(%p)\n", this);

    CStringW strKey;
    strKey.Format(L"%s\\UrlAssociations", s_szUserAssociations);
    DeleteSubkeys(HKEY_CURRENT_USER, strKey);
    strKey.Format(L"%s\\MIMEAssociations", s_szUserAssociations);
    DeleteSubkeys(HKEY_CURRENT_USER, strKey);

    DeleteSubkeys(HKEY_CURRENT_USER, s_szFileExts);

    HKEY hClients;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, s_szClients, 0, KEY_ENUMERATE_SUB_KEYS, &hClients) == ERROR_SUCCESS)
    {
        WCHAR szName[MAX_PATH];
        for (DWORD i = 0; RegEnumKeyW(hClients, i, szName, _countof(szName)) == ERROR_SUCCESS; ++i)
        {
            HKEY hClient;
            if (RegOpenKeyExW(hClients, szName, 0, KEY_SET_VALUE, &hClient) == ERROR_SUCCESS)
            {
                RegDeleteValueW(hClient, NULL);
                RegCloseKey(hClient);
            }
        }
        RegCloseKey(hClients);
    }

    return S_OK;
}

EXTERN_C HRESULT WINAPI
SHCreateAssociationRegistration(REFIID riid, void **ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = NULL;
    return ShellObjectCreator<CApplicationAssociationRegistration>(riid, ppv);
}
