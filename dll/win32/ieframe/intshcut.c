/*
 * Copyright 2008 Damjan Jovanovic
 *
 * ShellLink's barely documented cousin that handles URLs.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * TODO:
 * Implement the IShellLinkA/W interfaces
 * Handle the SetURL flags
 * Implement any other interfaces? Does any software actually use them?
 *
 * The installer for the Zuma Deluxe Popcap game is good for testing.
 */

#include <stdio.h>

#include "ieframe.h"

#include "shlobj.h"
#include "shobjidl.h"
#include "intshcut.h"
#include "shellapi.h"
#include "winreg.h"
#include "shlwapi.h"
#include "shlguid.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ieframe);

typedef struct
{
    IUniformResourceLocatorA IUniformResourceLocatorA_iface;
    IUniformResourceLocatorW IUniformResourceLocatorW_iface;
    IPersistFile IPersistFile_iface;
    IPropertySetStorage IPropertySetStorage_iface;

    LONG refCount;

    IPropertySetStorage *property_set_storage;
    WCHAR *url;
    BOOLEAN isDirty;
    LPOLESTR currentFile;
#ifdef __REACTOS__
    /* The icon values that were written through a storage a caller may still hold open: ole32 refuses a second
       exclusive open of the stream, so IPersistFile::Save could not read them back. */
    WCHAR *icon_file;
    INT icon_index;
    BOOLEAN has_icon_index;
#endif
} InternetShortcut;

/* utility functions */

static inline InternetShortcut* impl_from_IUniformResourceLocatorA(IUniformResourceLocatorA *iface)
{
    return CONTAINING_RECORD(iface, InternetShortcut, IUniformResourceLocatorA_iface);
}

static inline InternetShortcut* impl_from_IUniformResourceLocatorW(IUniformResourceLocatorW *iface)
{
    return CONTAINING_RECORD(iface, InternetShortcut, IUniformResourceLocatorW_iface);
}

static inline InternetShortcut* impl_from_IPersistFile(IPersistFile *iface)
{
    return CONTAINING_RECORD(iface, InternetShortcut, IPersistFile_iface);
}

static inline InternetShortcut* impl_from_IPropertySetStorage(IPropertySetStorage *iface)
{
    return CONTAINING_RECORD(iface, InternetShortcut, IPropertySetStorage_iface);
}

static BOOL run_winemenubuilder( const WCHAR *args )
{
    static const WCHAR menubuilder[] = L"\\winemenubuilder.exe";
    LONG len;
    LPWSTR buffer;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    BOOL ret;
    WCHAR app[MAX_PATH];
    void *redir;

    GetSystemDirectoryW( app, MAX_PATH - ARRAY_SIZE( menubuilder ));
    lstrcatW( app, menubuilder );

    len = (lstrlenW( app ) + lstrlenW( args ) + 1) * sizeof(WCHAR);
    buffer = malloc( len );
    if( !buffer )
        return FALSE;

    lstrcpyW( buffer, app );
    lstrcatW( buffer, args );

    TRACE("starting %s\n",debugstr_w(buffer));

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    Wow64DisableWow64FsRedirection( &redir );
    ret = CreateProcessW( app, buffer, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi );
    Wow64RevertWow64FsRedirection( redir );

    free( buffer );

    if (ret)
    {
        CloseHandle( pi.hProcess );
        CloseHandle( pi.hThread );
    }

    return ret;
}

static BOOL StartLinkProcessor( LPCOLESTR szLink )
{
    static const WCHAR szFormat[] = L" -w -u \"%s\"";
    LONG len;
    LPWSTR buffer;
    BOOL ret;

    len = sizeof(szFormat) + lstrlenW( szLink ) * sizeof(WCHAR);
    buffer = malloc( len );
    if( !buffer )
        return FALSE;

    swprintf( buffer, len / sizeof(WCHAR), szFormat, szLink );
    ret = run_winemenubuilder( buffer );
    free( buffer );
    return ret;
}

/* interface functions */

static HRESULT Unknown_QueryInterface(InternetShortcut *This, REFIID riid, PVOID *ppvObject)
{
    TRACE("(%p, %s, %p)\n", This, debugstr_guid(riid), ppvObject);
    *ppvObject = NULL;
    if (IsEqualGUID(&IID_IUnknown, riid))
        *ppvObject = &This->IUniformResourceLocatorA_iface;
    else if (IsEqualGUID(&IID_IUniformResourceLocatorA, riid))
        *ppvObject = &This->IUniformResourceLocatorA_iface;
    else if (IsEqualGUID(&IID_IUniformResourceLocatorW, riid))
        *ppvObject = &This->IUniformResourceLocatorW_iface;
    else if (IsEqualGUID(&IID_IPersistFile, riid))
        *ppvObject = &This->IPersistFile_iface;
    else if (IsEqualGUID(&IID_IPropertySetStorage, riid))
        *ppvObject = &This->IPropertySetStorage_iface;
    else if (IsEqualGUID(&IID_IShellLinkA, riid))
    {
        FIXME("The IShellLinkA interface is not yet supported by InternetShortcut\n");
        return E_NOINTERFACE;
    }
    else if (IsEqualGUID(&IID_IShellLinkW, riid))
    {
        FIXME("The IShellLinkW interface is not yet supported by InternetShortcut\n");
        return E_NOINTERFACE;
    }
    else
    {
        FIXME("Interface with GUID %s not yet implemented by InternetShortcut\n", debugstr_guid(riid));
        return E_NOINTERFACE;
    }
    IUnknown_AddRef((IUnknown*)*ppvObject);
    return S_OK;
}

static ULONG Unknown_AddRef(InternetShortcut *This)
{
    TRACE("(%p)\n", This);
    return InterlockedIncrement(&This->refCount);
}

static ULONG Unknown_Release(InternetShortcut *This)
{
    ULONG count;
    TRACE("(%p)\n", This);
    count = InterlockedDecrement(&This->refCount);
    if (count == 0)
    {
        CoTaskMemFree(This->url);
        CoTaskMemFree(This->currentFile);
#ifdef __REACTOS__
        free(This->icon_file);
#endif
        IPropertySetStorage_Release(This->property_set_storage);
        free(This);
        unlock_module();
    }
    return count;
}

static HRESULT WINAPI UniformResourceLocatorW_QueryInterface(IUniformResourceLocatorW *url, REFIID riid, PVOID *ppvObject)
{
    InternetShortcut *This = impl_from_IUniformResourceLocatorW(url);
    TRACE("(%p, %s, %p)\n", url, debugstr_guid(riid), ppvObject);
    return Unknown_QueryInterface(This, riid, ppvObject);
}

static ULONG WINAPI UniformResourceLocatorW_AddRef(IUniformResourceLocatorW *url)
{
    InternetShortcut *This = impl_from_IUniformResourceLocatorW(url);
    TRACE("(%p)\n", url);
    return Unknown_AddRef(This);
}

static ULONG WINAPI UniformResourceLocatorW_Release(IUniformResourceLocatorW *url)
{
    InternetShortcut *This = impl_from_IUniformResourceLocatorW(url);
    TRACE("(%p)\n", url);
    return Unknown_Release(This);
}

static HRESULT WINAPI UniformResourceLocatorW_SetUrl(IUniformResourceLocatorW *url, LPCWSTR pcszURL, DWORD dwInFlags)
{
    WCHAR *newURL = NULL;
    InternetShortcut *This = impl_from_IUniformResourceLocatorW(url);
    TRACE("(%p, %s, 0x%lx)\n", url, debugstr_w(pcszURL), dwInFlags);
    if (dwInFlags != 0)
        FIXME("ignoring unsupported flags 0x%lx\n", dwInFlags);
    if (pcszURL != NULL)
    {
        newURL = co_strdupW(pcszURL);
        if (newURL == NULL)
            return E_OUTOFMEMORY;
    }
    CoTaskMemFree(This->url);
    This->url = newURL;
    This->isDirty = TRUE;
    return S_OK;
}

static HRESULT WINAPI UniformResourceLocatorW_GetUrl(IUniformResourceLocatorW *url, LPWSTR *ppszURL)
{
    InternetShortcut *This = impl_from_IUniformResourceLocatorW(url);

    TRACE("(%p, %p)\n", url, ppszURL);

    if (!This->url) {
        *ppszURL = NULL;
        return S_FALSE;
    }

    *ppszURL = co_strdupW(This->url);
    if (!*ppszURL)
        return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI UniformResourceLocatorW_InvokeCommand(IUniformResourceLocatorW *url, PURLINVOKECOMMANDINFOW pCommandInfo)
{
    InternetShortcut *This = impl_from_IUniformResourceLocatorW(url);
    WCHAR app[64];
    HKEY hkey;
    SHELLEXECUTEINFOW sei;
    DWORD res, type;
    HRESULT hres;

    TRACE("%p %p\n", This, pCommandInfo );

    if (pCommandInfo->dwcbSize < sizeof (URLINVOKECOMMANDINFOW))
        return E_INVALIDARG;

    if (pCommandInfo->dwFlags != IURL_INVOKECOMMAND_FL_USE_DEFAULT_VERB)
    {
        FIXME("(%p, %p): non-default verbs not implemented\n", url, pCommandInfo);
        return E_NOTIMPL;
    }

    hres = CoInternetParseUrl(This->url, PARSE_SCHEMA, 0, app, ARRAY_SIZE(app), NULL, 0);
    if(FAILED(hres))
        return E_FAIL;

    res = RegOpenKeyW(HKEY_CLASSES_ROOT, app, &hkey);
    if(res != ERROR_SUCCESS)
        return E_FAIL;

    res = RegQueryValueExW(hkey, L"URL Protocol", NULL, &type, NULL, NULL);
    RegCloseKey(hkey);
    if(res != ERROR_SUCCESS || type != REG_SZ)
        return E_FAIL;

    memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.lpFile = This->url;
    sei.nShow = SW_SHOW;

    if( ShellExecuteExW(&sei) )
        return S_OK;
    else
        return E_FAIL;
}

static HRESULT WINAPI UniformResourceLocatorA_QueryInterface(IUniformResourceLocatorA *url, REFIID riid, PVOID *ppvObject)
{
    InternetShortcut *This = impl_from_IUniformResourceLocatorA(url);
    TRACE("(%p, %s, %p)\n", url, debugstr_guid(riid), ppvObject);
    return Unknown_QueryInterface(This, riid, ppvObject);
}

static ULONG WINAPI UniformResourceLocatorA_AddRef(IUniformResourceLocatorA *url)
{
    InternetShortcut *This = impl_from_IUniformResourceLocatorA(url);
    TRACE("(%p)\n", url);
    return Unknown_AddRef(This);
}

static ULONG WINAPI UniformResourceLocatorA_Release(IUniformResourceLocatorA *url)
{
    InternetShortcut *This = impl_from_IUniformResourceLocatorA(url);
    TRACE("(%p)\n", url);
    return Unknown_Release(This);
}

static HRESULT WINAPI UniformResourceLocatorA_SetUrl(IUniformResourceLocatorA *url, LPCSTR pcszURL, DWORD dwInFlags)
{
    WCHAR *newURL = NULL;
    InternetShortcut *This = impl_from_IUniformResourceLocatorA(url);
    TRACE("(%p, %s, 0x%lx)\n", url, debugstr_a(pcszURL), dwInFlags);
    if (dwInFlags != 0)
        FIXME("ignoring unsupported flags 0x%lx\n", dwInFlags);
    if (pcszURL != NULL)
    {
        newURL = co_strdupAtoW(pcszURL);
        if (newURL == NULL)
            return E_OUTOFMEMORY;
    }
    CoTaskMemFree(This->url);
    This->url = newURL;
    This->isDirty = TRUE;
    return S_OK;
}

static HRESULT WINAPI UniformResourceLocatorA_GetUrl(IUniformResourceLocatorA *url, LPSTR *ppszURL)
{
    InternetShortcut *This = impl_from_IUniformResourceLocatorA(url);

    TRACE("(%p, %p)\n", url, ppszURL);

    if (!This->url) {
        *ppszURL = NULL;
        return S_FALSE;

    }

    *ppszURL = co_strdupWtoA(This->url);
    if (!*ppszURL)
        return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI UniformResourceLocatorA_InvokeCommand(IUniformResourceLocatorA *url, PURLINVOKECOMMANDINFOA pCommandInfo)
{
    URLINVOKECOMMANDINFOW wideCommandInfo;
    int len;
    WCHAR *wideVerb;
    HRESULT res;
    InternetShortcut *This = impl_from_IUniformResourceLocatorA(url);

    wideCommandInfo.dwcbSize = sizeof wideCommandInfo;
    wideCommandInfo.dwFlags = pCommandInfo->dwFlags;
    wideCommandInfo.hwndParent = pCommandInfo->hwndParent;

    len = MultiByteToWideChar(CP_ACP, 0, pCommandInfo->pcszVerb, -1, NULL, 0);
    wideVerb = malloc(len * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, pCommandInfo->pcszVerb, -1, wideVerb, len);

    wideCommandInfo.pcszVerb = wideVerb;

    res = UniformResourceLocatorW_InvokeCommand(&This->IUniformResourceLocatorW_iface, &wideCommandInfo);
    free(wideVerb);

    return res;
}

static HRESULT WINAPI PersistFile_QueryInterface(IPersistFile *pFile, REFIID riid, PVOID *ppvObject)
{
    InternetShortcut *This = impl_from_IPersistFile(pFile);
    TRACE("(%p, %s, %p)\n", pFile, debugstr_guid(riid), ppvObject);
    return Unknown_QueryInterface(This, riid, ppvObject);
}

static ULONG WINAPI PersistFile_AddRef(IPersistFile *pFile)
{
    InternetShortcut *This = impl_from_IPersistFile(pFile);
    TRACE("(%p)\n", pFile);
    return Unknown_AddRef(This);
}

static ULONG WINAPI PersistFile_Release(IPersistFile *pFile)
{
    InternetShortcut *This = impl_from_IPersistFile(pFile);
    TRACE("(%p)\n", pFile);
    return Unknown_Release(This);
}

static HRESULT WINAPI PersistFile_GetClassID(IPersistFile *pFile, CLSID *pClassID)
{
    TRACE("(%p, %p)\n", pFile, pClassID);
    *pClassID = CLSID_InternetShortcut;
    return S_OK;
}

static HRESULT WINAPI PersistFile_IsDirty(IPersistFile *pFile)
{
    InternetShortcut *This = impl_from_IPersistFile(pFile);
    TRACE("(%p)\n", pFile);
    return This->isDirty ? S_OK : S_FALSE;
}

/* Returns allocated profile string and a standard return code. */
static HRESULT get_profile_string(LPCWSTR lpAppName, LPCWSTR lpKeyName,
                                LPCWSTR lpFileName, WCHAR **rString )
{
    DWORD r = 0;
    DWORD len = 128;
    WCHAR *buffer;

    *rString = NULL;
    buffer = CoTaskMemAlloc(len * sizeof(*buffer));
    if (!buffer)
        return E_OUTOFMEMORY;

    r = GetPrivateProfileStringW(lpAppName, lpKeyName, NULL, buffer, len, lpFileName);
    while (r == len-1)
    {
        WCHAR *realloc_buf;

        len *= 2;
        realloc_buf = CoTaskMemRealloc(buffer, len * sizeof(*buffer));
        if (realloc_buf == NULL)
        {
            CoTaskMemFree(buffer);
            return E_OUTOFMEMORY;
        }
        buffer = realloc_buf;

        r = GetPrivateProfileStringW(lpAppName, lpKeyName, NULL, buffer, len, lpFileName);
    }

    *rString = buffer;
    return r ? S_OK : E_FAIL;
}

static HRESULT WINAPI PersistFile_Load(IPersistFile *pFile, LPCOLESTR pszFileName, DWORD dwMode)
{
    InternetShortcut *This = impl_from_IPersistFile(pFile);
    WCHAR *filename = NULL;
    WCHAR *url;
    HRESULT hr;
    IPropertyStorage *pPropStg;
    WCHAR *iconfile;
    WCHAR *iconindexstring;

    TRACE("(%p, %s, 0x%lx)\n", pFile, debugstr_w(pszFileName), dwMode);

    if (dwMode != 0)
        FIXME("ignoring unimplemented mode 0x%lx\n", dwMode);

    filename = co_strdupW(pszFileName);
    if (!filename)
        return E_OUTOFMEMORY;

    if (FAILED(hr = get_profile_string(L"InternetShortcut", L"URL", pszFileName, &url)))
    {
        CoTaskMemFree(filename);
        return hr;
    }

    hr = IPropertySetStorage_Open(This->property_set_storage, &FMTID_Intshcut,
                STGM_READWRITE | STGM_SHARE_EXCLUSIVE, &pPropStg);
    if (FAILED(hr))
    {
        CoTaskMemFree(filename);
        CoTaskMemFree(url);
        return hr;
    }

    CoTaskMemFree(This->currentFile);
    This->currentFile = filename;
    CoTaskMemFree(This->url);
    This->url = url;
    This->isDirty = FALSE;

    /* Now we're going to read in the iconfile and iconindex.
       If we don't find them, that's not a failure case -- it's possible
       that they just aren't in there. */

    if (get_profile_string(L"InternetShortcut", L"iconfile", pszFileName, &iconfile) == S_OK)
    {
        PROPSPEC ps;
        PROPVARIANT pv;
        ps.ulKind = PRSPEC_PROPID;
        ps.propid = PID_IS_ICONFILE;
        pv.vt = VT_LPWSTR;
        pv.pwszVal = iconfile;
        hr = IPropertyStorage_WriteMultiple(pPropStg, 1, &ps, &pv, 0);
        if (FAILED(hr))
            TRACE("Failed to store the iconfile to our property storage.  hr = 0x%lx\n", hr);
#ifdef __REACTOS__
        if (SUCCEEDED(hr))
        {
            WCHAR *copy = wcsdup(iconfile);
            if (copy)
            {
                free(This->icon_file);
                This->icon_file = copy;
            }
        }
#endif
    }
    CoTaskMemFree(iconfile);

    if (get_profile_string(L"InternetShortcut", L"iconindex", pszFileName, &iconindexstring) == S_OK)
    {
        int iconindex;
        PROPSPEC ps;
        PROPVARIANT pv;
        iconindex = wcstol(iconindexstring, NULL, 10);
        ps.ulKind = PRSPEC_PROPID;
        ps.propid = PID_IS_ICONINDEX;
        pv.vt = VT_I4;
        pv.iVal = iconindex;
        hr = IPropertyStorage_WriteMultiple(pPropStg, 1, &ps, &pv, 0);
        if (FAILED(hr))
           TRACE("Failed to store the iconindex to our property storage.  hr = 0x%lx\n", hr);
#ifdef __REACTOS__
        if (SUCCEEDED(hr))
        {
            This->icon_index = iconindex;
            This->has_icon_index = TRUE;
        }
#endif
    }
    CoTaskMemFree(iconindexstring);

    IPropertyStorage_Release(pPropStg);
    return hr;
}

#ifdef __REACTOS__
static HRESULT WINAPI PersistFile_Save(IPersistFile *pFile, LPCOLESTR pszFileName, BOOL fRemember)
{
    static const char str_header[] = "[InternetShortcut]\r\nURL=";
    static const char str_ICONFILE[] = "ICONFILE=";
    static const char str_ICONINDEX[] = "ICONINDEX=";
    static const char str_eol[] = "\r\n";
    InternetShortcut *This = impl_from_IPersistFile(pFile);
    IPropertyStorage *pPropStgRead;
    PROPSPEC ps[2];
    PROPVARIANT pvread[2];
    WCHAR *icon_file = NULL;
    INT icon_index = 0;
    BOOL has_icon = FALSE;
    char *url = NULL, *icon = NULL, *data = NULL;
    DWORD size, written;
    HANDLE file;
    HRESULT hr;
    INT len;

    TRACE("(%p, %s, %d)\n", pFile, debugstr_w(pszFileName), fRemember);

    if (This->url == NULL)
        return E_FAIL;

    /* Everything the file will contain is collected before the destination is touched. Windows seems to always write:
     *   ASCII "[InternetShortcut]" headers
     *   ASCII names in "name=value" pairs
     *   An ASCII (probably UTF8?) value in "URL=..."
     */
    len = WideCharToMultiByte(CP_UTF8, 0, This->url, -1, NULL, 0, 0, 0);
    url = malloc(len);
    if (!url)
        return E_OUTOFMEMORY;
    WideCharToMultiByte(CP_UTF8, 0, This->url, -1, url, len, 0, 0);

    ps[0].ulKind = PRSPEC_PROPID;
    ps[0].propid = PID_IS_ICONFILE;
    ps[1].ulKind = PRSPEC_PROPID;
    ps[1].propid = PID_IS_ICONINDEX;
    memset(pvread, 0, sizeof(pvread));
    hr = IPropertySetStorage_Open(This->property_set_storage, &FMTID_Intshcut, STGM_READ|STGM_SHARE_EXCLUSIVE, &pPropStgRead);
    if (SUCCEEDED(hr))
    {
        hr = IPropertyStorage_ReadMultiple(pPropStgRead, 2, ps, pvread);
        IPropertyStorage_Release(pPropStgRead);
        if (hr == S_OK && pvread[0].vt == VT_LPWSTR && pvread[0].pwszVal && (pvread[1].vt == VT_I4 || pvread[1].vt == VT_I2))
        {
            icon_file = pvread[0].pwszVal;
            icon_index = pvread[1].vt == VT_I4 ? pvread[1].lVal : pvread[1].iVal;
            has_icon = TRUE;
        }
    }
    else if (This->icon_file && This->has_icon_index)
    {
        /* the storage is still open in a caller: use what was written through it */
        icon_file = This->icon_file;
        icon_index = This->icon_index;
        has_icon = TRUE;
    }

    size = ARRAY_SIZE(str_header) - 1 + strlen(url) + ARRAY_SIZE(str_eol) - 1;
    if (has_icon)
    {
        len = WideCharToMultiByte(CP_UTF8, 0, icon_file, -1, NULL, 0, 0, 0);
        icon = malloc(len);
        if (!icon)
        {
            hr = E_OUTOFMEMORY;
            goto done;
        }
        WideCharToMultiByte(CP_UTF8, 0, icon_file, -1, icon, len, 0, 0);
        size += ARRAY_SIZE(str_ICONFILE) - 1 + strlen(icon) + ARRAY_SIZE(str_eol) - 1
              + ARRAY_SIZE(str_ICONINDEX) - 1 + 12 + ARRAY_SIZE(str_eol) - 1;
    }
    data = malloc(size + 1);
    if (!data)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    size = sprintf(data, "%s%s%s", str_header, url, str_eol);
    if (has_icon)
        size += sprintf(data + size, "%s%s%s%s%d%s", str_ICONFILE, icon, str_eol, str_ICONINDEX, icon_index, str_eol);

    /* The content goes to a file next to the destination first and replaces the destination only when it is
       complete, so a failed save leaves the old file as it was. */
    if (!pszFileName)
    {
        hr = E_FAIL;
        goto done;
    }
    {
        WCHAR dir[MAX_PATH], temp[MAX_PATH];
        const WCHAR *slash = wcsrchr(pszFileName, '\\'), *slash2 = wcsrchr(pszFileName, '/');

        if (slash2 > slash) slash = slash2;
        if (slash && (SIZE_T)(slash - pszFileName) >= ARRAY_SIZE(dir))
        {
            hr = E_FAIL;
            goto done;
        }
        if (slash)
        {
            memcpy(dir, pszFileName, (slash - pszFileName) * sizeof(WCHAR));
            dir[slash - pszFileName] = 0;
            if (slash == pszFileName || (slash == pszFileName + 2 && dir[1] == ':')) lstrcpyW(dir + (slash - pszFileName), L"\\");
        }
        else
            lstrcpyW(dir, L".");

        if (!GetTempFileNameW(dir, L"url", 0, temp))
        {
            hr = E_FAIL;
            goto done;
        }
        file = CreateFileW(temp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE)
        {
            DeleteFileW(temp);
            hr = E_FAIL;
            goto done;
        }
        if (!WriteFile(file, data, size, &written, NULL) || written != size)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            if (SUCCEEDED(hr)) hr = E_FAIL;
            CloseHandle(file);
            DeleteFileW(temp);
            goto done;
        }
        CloseHandle(file);
        if (!MoveFileExW(temp, pszFileName, MOVEFILE_REPLACE_EXISTING))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            if (SUCCEEDED(hr)) hr = E_FAIL;
            DeleteFileW(temp);
            goto done;
        }
    }
    hr = S_OK;

    if (pszFileName != NULL && fRemember)
    {
        LPOLESTR oldFile = This->currentFile;
        This->currentFile = co_strdupW(pszFileName);
        if (This->currentFile == NULL)
            This->currentFile = oldFile;
        else
            CoTaskMemFree(oldFile);
    }
    if (pszFileName == NULL || fRemember)
        This->isDirty = FALSE;
    StartLinkProcessor(pszFileName);

done:
    PropVariantClear(&pvread[0]);
    PropVariantClear(&pvread[1]);
    free(url);
    free(icon);
    free(data);
    return hr;
}
#else
static HRESULT WINAPI PersistFile_Save(IPersistFile *pFile, LPCOLESTR pszFileName, BOOL fRemember)
{
    HRESULT hr = S_OK;
    INT len;
    CHAR *url;
    InternetShortcut *This = impl_from_IPersistFile(pFile);

    TRACE("(%p, %s, %d)\n", pFile, debugstr_w(pszFileName), fRemember);

    if (pszFileName != NULL && fRemember)
    {
        LPOLESTR oldFile = This->currentFile;
        This->currentFile = co_strdupW(pszFileName);
        if (This->currentFile == NULL)
        {
            This->currentFile = oldFile;
            return E_OUTOFMEMORY;
        }
        CoTaskMemFree(oldFile);
    }
    if (This->url == NULL)
        return E_FAIL;

    /* Windows seems to always write:
     *   ASCII "[InternetShortcut]" headers
     *   ASCII names in "name=value" pairs
     *   An ASCII (probably UTF8?) value in "URL=..."
     */
    len = WideCharToMultiByte(CP_UTF8, 0, This->url, -1, NULL, 0, 0, 0);
    url = malloc(len);
    if (url != NULL)
    {
        HANDLE file;
        WideCharToMultiByte(CP_UTF8, 0, This->url, -1, url, len, 0, 0);
        file = CreateFileW(pszFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE)
        {
            static const char str_header[] = "[InternetShortcut]";
            static const char str_URL[] = "URL=";
            static const char str_ICONFILE[] = "ICONFILE=";
            static const char str_eol[] = "\r\n";
            DWORD bytesWritten;
            char *iconfile;
            IPropertyStorage *pPropStgRead;
            PROPSPEC ps[2];
            PROPVARIANT pvread[2];
            ps[0].ulKind = PRSPEC_PROPID;
            ps[0].propid = PID_IS_ICONFILE;
            ps[1].ulKind = PRSPEC_PROPID;
            ps[1].propid = PID_IS_ICONINDEX;

            WriteFile(file, str_header, ARRAY_SIZE(str_header) - 1, &bytesWritten, NULL);
            WriteFile(file, str_eol, ARRAY_SIZE(str_eol) - 1, &bytesWritten, NULL);
            WriteFile(file, str_URL, ARRAY_SIZE(str_URL) - 1, &bytesWritten, NULL);
            WriteFile(file, url, lstrlenA(url), &bytesWritten, NULL);
            WriteFile(file, str_eol, ARRAY_SIZE(str_eol) - 1, &bytesWritten, NULL);

            hr = IPropertySetStorage_Open(This->property_set_storage, &FMTID_Intshcut, STGM_READ|STGM_SHARE_EXCLUSIVE, &pPropStgRead);
            if (SUCCEEDED(hr))
            {
                hr = IPropertyStorage_ReadMultiple(pPropStgRead, 2, ps, pvread);
                if (hr == S_FALSE)
                {
                    /* None of the properties are present, that's ok */
                    hr = S_OK;
                    IPropertyStorage_Release(pPropStgRead);
                }
                else if (SUCCEEDED(hr))
                {
                    char indexString[50];
                    len = WideCharToMultiByte(CP_UTF8, 0, pvread[0].pwszVal, -1, NULL, 0, 0, 0);
                    iconfile = malloc(len);
                    if (iconfile != NULL)
                    {
                        WideCharToMultiByte(CP_UTF8, 0, pvread[0].pwszVal, -1, iconfile, len, 0, 0);
                        WriteFile(file, str_ICONFILE, lstrlenA(str_ICONFILE), &bytesWritten, NULL);
                        WriteFile(file, iconfile, lstrlenA(iconfile), &bytesWritten, NULL);
                        WriteFile(file, str_eol, lstrlenA(str_eol), &bytesWritten, NULL);
                        free(iconfile);
                    }

                    sprintf(indexString, "ICONINDEX=%d", pvread[1].iVal);
                    WriteFile(file, indexString, lstrlenA(indexString), &bytesWritten, NULL);
                    WriteFile(file, str_eol, lstrlenA(str_eol), &bytesWritten, NULL);

                    IPropertyStorage_Release(pPropStgRead);
                    PropVariantClear(&pvread[0]);
                    PropVariantClear(&pvread[1]);
                }
                else
                {
                    TRACE("Unable to read properties.\n");
                    IPropertyStorage_Release(pPropStgRead);
                    hr = S_OK;
                }
            }
            else
            {
               /* A caller may still hold the property storage open; the URL is saved without the icon */
               TRACE("Unable to get the IPropertyStorage.\n");
               hr = S_OK;
            }

            CloseHandle(file);
            if (pszFileName == NULL || fRemember)
                This->isDirty = FALSE;
            StartLinkProcessor(pszFileName);
        }
        else
            hr = E_FAIL;
        free(url);
    }
    else
        hr = E_OUTOFMEMORY;

    return hr;
}

#endif /* __REACTOS__ */

static HRESULT WINAPI PersistFile_SaveCompleted(IPersistFile *pFile, LPCOLESTR pszFileName)
{
    FIXME("(%p, %p): stub\n", pFile, pszFileName);
    return E_NOTIMPL;
}

static HRESULT WINAPI PersistFile_GetCurFile(IPersistFile *pFile, LPOLESTR *ppszFileName)
{
    HRESULT hr = S_OK;
    InternetShortcut *This = impl_from_IPersistFile(pFile);
    TRACE("(%p, %p)\n", pFile, ppszFileName);
    if (This->currentFile == NULL)
        *ppszFileName = NULL;
    else
    {
        *ppszFileName = co_strdupW(This->currentFile);
        if (*ppszFileName == NULL)
            hr = E_OUTOFMEMORY;
    }
    return hr;
}

static HRESULT WINAPI PropertySetStorage_QueryInterface(IPropertySetStorage *iface, REFIID riid, PVOID *ppvObject)
{
    InternetShortcut *This = impl_from_IPropertySetStorage(iface);
    TRACE("(%p)\n", iface);
    return Unknown_QueryInterface(This, riid, ppvObject);
}

static ULONG WINAPI PropertySetStorage_AddRef(IPropertySetStorage *iface)
{
    InternetShortcut *This = impl_from_IPropertySetStorage(iface);
    TRACE("(%p)\n", iface);
    return Unknown_AddRef(This);
}

static ULONG WINAPI PropertySetStorage_Release(IPropertySetStorage *iface)
{
    InternetShortcut *This = impl_from_IPropertySetStorage(iface);
    TRACE("(%p)\n", iface);
    return Unknown_Release(This);
}

#ifdef __REACTOS__
static void forget_icon(InternetShortcut *This)
{
    free(This->icon_file);
    This->icon_file = NULL;
    This->has_icon_index = FALSE;
}

/* A property storage that notes the icon values written through it, see InternetShortcut.icon_file */
typedef struct
{
    IPropertyStorage IPropertyStorage_iface;
    LONG refCount;
    IPropertyStorage *real;
    InternetShortcut *owner;
} ShortcutPropertyStorage;

static inline ShortcutPropertyStorage *impl_from_IPropertyStorage(IPropertyStorage *iface)
{
    return CONTAINING_RECORD(iface, ShortcutPropertyStorage, IPropertyStorage_iface);
}

static HRESULT WINAPI ShortcutPropertyStorage_QueryInterface(IPropertyStorage *iface, REFIID riid, void **ppv)
{
    if (IsEqualGUID(riid, &IID_IUnknown) || IsEqualGUID(riid, &IID_IPropertyStorage))
    {
        *ppv = iface;
        IPropertyStorage_AddRef(iface);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI ShortcutPropertyStorage_AddRef(IPropertyStorage *iface)
{
    return InterlockedIncrement(&impl_from_IPropertyStorage(iface)->refCount);
}

static ULONG WINAPI ShortcutPropertyStorage_Release(IPropertyStorage *iface)
{
    ShortcutPropertyStorage *This = impl_from_IPropertyStorage(iface);
    ULONG count = InterlockedDecrement(&This->refCount);

    if (!count)
    {
        IPropertyStorage_Release(This->real);
        Unknown_Release(This->owner);
        free(This);
    }
    return count;
}

static HRESULT WINAPI ShortcutPropertyStorage_ReadMultiple(IPropertyStorage *iface, ULONG cpspec,
        const PROPSPEC rgpspec[], PROPVARIANT rgpropvar[])
{
    return IPropertyStorage_ReadMultiple(impl_from_IPropertyStorage(iface)->real, cpspec, rgpspec, rgpropvar);
}

static HRESULT WINAPI ShortcutPropertyStorage_WriteMultiple(IPropertyStorage *iface, ULONG cpspec,
        const PROPSPEC rgpspec[], const PROPVARIANT rgpropvar[], PROPID propidNameFirst)
{
    ShortcutPropertyStorage *This = impl_from_IPropertyStorage(iface);
    HRESULT hr = IPropertyStorage_WriteMultiple(This->real, cpspec, rgpspec, rgpropvar, propidNameFirst);
    ULONG i;

    if (FAILED(hr) || !rgpspec || !rgpropvar) return hr;

    for (i = 0; i < cpspec; i++)
    {
        if (rgpspec[i].ulKind != PRSPEC_PROPID) continue;
        if (rgpspec[i].propid == PID_IS_ICONFILE && rgpropvar[i].vt == VT_LPWSTR && rgpropvar[i].pwszVal)
        {
            WCHAR *copy = wcsdup(rgpropvar[i].pwszVal);
            if (copy)
            {
                free(This->owner->icon_file);
                This->owner->icon_file = copy;
            }
        }
        else if (rgpspec[i].propid == PID_IS_ICONINDEX && (rgpropvar[i].vt == VT_I4 || rgpropvar[i].vt == VT_I2))
        {
            This->owner->icon_index = rgpropvar[i].vt == VT_I4 ? rgpropvar[i].lVal : rgpropvar[i].iVal;
            This->owner->has_icon_index = TRUE;
        }
    }
    return hr;
}

static HRESULT WINAPI ShortcutPropertyStorage_DeleteMultiple(IPropertyStorage *iface, ULONG cpspec,
        const PROPSPEC rgpspec[])
{
    ShortcutPropertyStorage *This = impl_from_IPropertyStorage(iface);
    HRESULT hr = IPropertyStorage_DeleteMultiple(This->real, cpspec, rgpspec);
    ULONG i;

    if (FAILED(hr) || !rgpspec) return hr;

    for (i = 0; i < cpspec; i++)
    {
        if (rgpspec[i].ulKind != PRSPEC_PROPID) continue;
        if (rgpspec[i].propid == PID_IS_ICONFILE)
        {
            free(This->owner->icon_file);
            This->owner->icon_file = NULL;
        }
        else if (rgpspec[i].propid == PID_IS_ICONINDEX)
            This->owner->has_icon_index = FALSE;
    }
    return hr;
}

static HRESULT WINAPI ShortcutPropertyStorage_ReadPropertyNames(IPropertyStorage *iface, ULONG cpropid,
        const PROPID rgpropid[], LPOLESTR rglpwstrName[])
{
    return IPropertyStorage_ReadPropertyNames(impl_from_IPropertyStorage(iface)->real, cpropid, rgpropid, rglpwstrName);
}

static HRESULT WINAPI ShortcutPropertyStorage_WritePropertyNames(IPropertyStorage *iface, ULONG cpropid,
        const PROPID rgpropid[], const LPOLESTR rglpwstrName[])
{
    return IPropertyStorage_WritePropertyNames(impl_from_IPropertyStorage(iface)->real, cpropid, rgpropid, rglpwstrName);
}

static HRESULT WINAPI ShortcutPropertyStorage_DeletePropertyNames(IPropertyStorage *iface, ULONG cpropid,
        const PROPID rgpropid[])
{
    return IPropertyStorage_DeletePropertyNames(impl_from_IPropertyStorage(iface)->real, cpropid, rgpropid);
}

static HRESULT WINAPI ShortcutPropertyStorage_Commit(IPropertyStorage *iface, DWORD grfCommitFlags)
{
    return IPropertyStorage_Commit(impl_from_IPropertyStorage(iface)->real, grfCommitFlags);
}

static HRESULT WINAPI ShortcutPropertyStorage_Revert(IPropertyStorage *iface)
{
    return IPropertyStorage_Revert(impl_from_IPropertyStorage(iface)->real);
}

static HRESULT WINAPI ShortcutPropertyStorage_Enum(IPropertyStorage *iface, IEnumSTATPROPSTG **ppenum)
{
    return IPropertyStorage_Enum(impl_from_IPropertyStorage(iface)->real, ppenum);
}

static HRESULT WINAPI ShortcutPropertyStorage_SetTimes(IPropertyStorage *iface, const FILETIME *pctime,
        const FILETIME *patime, const FILETIME *pmtime)
{
    return IPropertyStorage_SetTimes(impl_from_IPropertyStorage(iface)->real, pctime, patime, pmtime);
}

static HRESULT WINAPI ShortcutPropertyStorage_SetClass(IPropertyStorage *iface, REFCLSID clsid)
{
    return IPropertyStorage_SetClass(impl_from_IPropertyStorage(iface)->real, clsid);
}

static HRESULT WINAPI ShortcutPropertyStorage_Stat(IPropertyStorage *iface, STATPROPSETSTG *pstatpsstg)
{
    return IPropertyStorage_Stat(impl_from_IPropertyStorage(iface)->real, pstatpsstg);
}

static const IPropertyStorageVtbl shortcutPropertyStorageVtbl =
{
    ShortcutPropertyStorage_QueryInterface,
    ShortcutPropertyStorage_AddRef,
    ShortcutPropertyStorage_Release,
    ShortcutPropertyStorage_ReadMultiple,
    ShortcutPropertyStorage_WriteMultiple,
    ShortcutPropertyStorage_DeleteMultiple,
    ShortcutPropertyStorage_ReadPropertyNames,
    ShortcutPropertyStorage_WritePropertyNames,
    ShortcutPropertyStorage_DeletePropertyNames,
    ShortcutPropertyStorage_Commit,
    ShortcutPropertyStorage_Revert,
    ShortcutPropertyStorage_Enum,
    ShortcutPropertyStorage_SetTimes,
    ShortcutPropertyStorage_SetClass,
    ShortcutPropertyStorage_Stat
};

/* Takes over the reference to *storage */
static void wrap_property_storage(InternetShortcut *This, IPropertyStorage **storage)
{
    ShortcutPropertyStorage *wrapper = calloc(1, sizeof(*wrapper));

    if (!wrapper) return;    /* the caller keeps the plain storage */
    wrapper->IPropertyStorage_iface.lpVtbl = &shortcutPropertyStorageVtbl;
    wrapper->refCount = 1;
    wrapper->real = *storage;
    wrapper->owner = This;
    Unknown_AddRef(This);
    *storage = &wrapper->IPropertyStorage_iface;
}
#endif /* __REACTOS__ */

static HRESULT WINAPI PropertySetStorage_Create(
        IPropertySetStorage* iface,
        REFFMTID rfmtid,
        const CLSID *pclsid,
        DWORD grfFlags,
        DWORD grfMode,
        IPropertyStorage **ppprstg)
{
    InternetShortcut *This = impl_from_IPropertySetStorage(iface);
    TRACE("(%s, %p, 0x%lx, 0x%lx, %p)\n", debugstr_guid(rfmtid), pclsid, grfFlags, grfMode, ppprstg);

#ifdef __REACTOS__
    HRESULT hr = IPropertySetStorage_Create(This->property_set_storage, rfmtid, pclsid, grfFlags, grfMode, ppprstg);
    if (SUCCEEDED(hr) && IsEqualGUID(rfmtid, &FMTID_Intshcut))
    {
        /* creating over an existing set replaces it, with no icon */
        if (grfMode & STGM_CREATE) forget_icon(This);
        wrap_property_storage(This, ppprstg);
    }
    return hr;
#else
    return IPropertySetStorage_Create(This->property_set_storage,
                                      rfmtid,
                                      pclsid,
                                      grfFlags,
                                      grfMode,
                                      ppprstg);
#endif
}

static HRESULT WINAPI PropertySetStorage_Open(
        IPropertySetStorage* iface,
        REFFMTID rfmtid,
        DWORD grfMode,
        IPropertyStorage **ppprstg)
{
    const DWORD STGM_ACCESS_MASK = 0x0000000f;
    InternetShortcut *This = impl_from_IPropertySetStorage(iface);
    TRACE("(%s, 0x%lx, %p)\n", debugstr_guid(rfmtid), grfMode, ppprstg);

    /* ole32 doesn't like STGM_WRITE */
    if ((grfMode & STGM_ACCESS_MASK) == STGM_WRITE)
        grfMode = (grfMode & ~STGM_ACCESS_MASK) | STGM_READWRITE;

    /* Note:  The |STGM_SHARE_EXCLUSIVE is to cope with a bug in the implementation.  Should be fixed in ole32. */
#ifdef __REACTOS__
    {
        HRESULT hr = IPropertySetStorage_Open(This->property_set_storage, rfmtid, grfMode|STGM_SHARE_EXCLUSIVE, ppprstg);
        if (SUCCEEDED(hr) && IsEqualGUID(rfmtid, &FMTID_Intshcut))
            wrap_property_storage(This, ppprstg);
        return hr;
    }
#else
    return IPropertySetStorage_Open(This->property_set_storage,
                                    rfmtid,
                                    grfMode|STGM_SHARE_EXCLUSIVE,
                                    ppprstg);
#endif
}

static HRESULT WINAPI PropertySetStorage_Delete(IPropertySetStorage *iface, REFFMTID rfmtid)
{
    InternetShortcut *This = impl_from_IPropertySetStorage(iface);
    TRACE("(%s)\n", debugstr_guid(rfmtid));


#ifdef __REACTOS__
    {
        HRESULT hr = IPropertySetStorage_Delete(This->property_set_storage, rfmtid);
        if (SUCCEEDED(hr) && IsEqualGUID(rfmtid, &FMTID_Intshcut)) forget_icon(This);
        return hr;
    }
#else
    return IPropertySetStorage_Delete(This->property_set_storage,
                                      rfmtid);
#endif
}

static HRESULT WINAPI PropertySetStorage_Enum(IPropertySetStorage *iface, IEnumSTATPROPSETSTG **ppenum)
{
    FIXME("(%p): stub\n", ppenum);
    return E_NOTIMPL;
}

static const IUniformResourceLocatorWVtbl uniformResourceLocatorWVtbl = {
    UniformResourceLocatorW_QueryInterface,
    UniformResourceLocatorW_AddRef,
    UniformResourceLocatorW_Release,
    UniformResourceLocatorW_SetUrl,
    UniformResourceLocatorW_GetUrl,
    UniformResourceLocatorW_InvokeCommand
};

static const IUniformResourceLocatorAVtbl uniformResourceLocatorAVtbl = {
    UniformResourceLocatorA_QueryInterface,
    UniformResourceLocatorA_AddRef,
    UniformResourceLocatorA_Release,
    UniformResourceLocatorA_SetUrl,
    UniformResourceLocatorA_GetUrl,
    UniformResourceLocatorA_InvokeCommand
};

static const IPersistFileVtbl persistFileVtbl = {
    PersistFile_QueryInterface,
    PersistFile_AddRef,
    PersistFile_Release,
    PersistFile_GetClassID,
    PersistFile_IsDirty,
    PersistFile_Load,
    PersistFile_Save,
    PersistFile_SaveCompleted,
    PersistFile_GetCurFile
};

static const IPropertySetStorageVtbl propertySetStorageVtbl = {
    PropertySetStorage_QueryInterface,
    PropertySetStorage_AddRef,
    PropertySetStorage_Release,
    PropertySetStorage_Create,
    PropertySetStorage_Open,
    PropertySetStorage_Delete,
    PropertySetStorage_Enum
};

static InternetShortcut *create_shortcut(void)
{
    InternetShortcut *newshortcut;

    newshortcut = calloc(1, sizeof(InternetShortcut));
    if (newshortcut)
    {
        HRESULT hr;
        IPropertyStorage *dummy;

        newshortcut->IUniformResourceLocatorA_iface.lpVtbl = &uniformResourceLocatorAVtbl;
        newshortcut->IUniformResourceLocatorW_iface.lpVtbl = &uniformResourceLocatorWVtbl;
        newshortcut->IPersistFile_iface.lpVtbl = &persistFileVtbl;
        newshortcut->IPropertySetStorage_iface.lpVtbl = &propertySetStorageVtbl;
        newshortcut->refCount = 1;
        hr = StgCreateStorageEx(NULL, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE | STGM_DELETEONRELEASE,
                                STGFMT_STORAGE, 0, NULL, NULL, &IID_IPropertySetStorage, (void **) &newshortcut->property_set_storage);
        if (FAILED(hr))
        {
            TRACE("Failed to create the storage object needed for the shortcut.\n");
            free(newshortcut);
            return NULL;
        }

        hr = IPropertySetStorage_Create(newshortcut->property_set_storage, &FMTID_Intshcut, NULL, PROPSETFLAG_DEFAULT, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, &dummy);
        if (FAILED(hr))
        {
            TRACE("Failed to create the property object needed for the shortcut.\n");
            IPropertySetStorage_Release(newshortcut->property_set_storage);
            free(newshortcut);
            return NULL;
        }
        IPropertyStorage_Release(dummy);
    }

    return newshortcut;
}

HRESULT WINAPI InternetShortcut_Create(IClassFactory *iface, IUnknown *outer, REFIID riid, void **ppv)
{
    InternetShortcut *This;
    HRESULT hres;

    TRACE("(%p, %s, %p)\n", outer, debugstr_guid(riid), ppv);

    *ppv = NULL;

    if(outer)
        return CLASS_E_NOAGGREGATION;

    This = create_shortcut();
    if(!This)
        return E_OUTOFMEMORY;

    hres = Unknown_QueryInterface(This, riid, ppv);
    Unknown_Release(This);
    return hres;
}


/**********************************************************************
 * OpenURL  (ieframe.@)
 */
void WINAPI OpenURL(HWND hWnd, HINSTANCE hInst, LPCSTR lpcstrUrl, int nShowCmd)
{
    InternetShortcut *shortcut;
    WCHAR* urlfilepath = NULL;
    int len;

    shortcut = create_shortcut();

    if(!shortcut)
        return;

    len = MultiByteToWideChar(CP_ACP, 0, lpcstrUrl, -1, NULL, 0);
    urlfilepath = malloc(len * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, lpcstrUrl, -1, urlfilepath, len);

    if(SUCCEEDED(IPersistFile_Load(&shortcut->IPersistFile_iface, urlfilepath, 0))) {
        URLINVOKECOMMANDINFOW ici;

        memset( &ici, 0, sizeof ici );
        ici.dwcbSize = sizeof ici;
        ici.dwFlags = IURL_INVOKECOMMAND_FL_USE_DEFAULT_VERB;
        ici.hwndParent = hWnd;

        if(FAILED(UniformResourceLocatorW_InvokeCommand(&shortcut->IUniformResourceLocatorW_iface, (PURLINVOKECOMMANDINFOW) &ici)))
            TRACE("failed to open URL: %s\n", debugstr_a(lpcstrUrl));
    }

    free(urlfilepath);
    Unknown_Release(shortcut);
}
