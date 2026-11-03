/*
 * PROJECT:     ReactOS Windows Runtime type resolution (wintypes.dll)
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RoResolveNamespace: the Windows Runtime metadata file of a namespace
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The .NET Framework binds a Windows Runtime type (an assembly reference with
 * ContentType=WindowsRuntime) by asking RoResolveNamespace for the metadata files of the
 * type's namespace, then reads the type from them. Without this DLL the runtime fails with
 * FileNotFoundException for 'Windows, ContentType=WindowsRuntime'.
 *
 * Behaviour measured on Windows 10 22H2 (x64 and x86, read-only probe): the answer depends
 * on the file names in %SystemRoot%\System32\WinMetadata only, compared case-sensitively.
 * A file belongs to a namespace when its name is the namespace or a namespace above it
 * ("Windows.Foundation.Nothing" gives Windows.Foundation.winmd); the subnamespaces come from
 * the names of the files below it ("Windows" gives no file and 18 subnamespaces). Nothing
 * found is RO_E_METADATA_NAME_NOT_FOUND, also when only files were asked for and only
 * subnamespaces exist. A 32-bit process on a 64-bit system gets paths through
 * %SystemRoot%\SysNative. Not measured: the order of several files for one namespace (we
 * give the most specific first) and the package graph directories (searched like the
 * Windows directory).
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "objbase.h"
#include "activation.h"
#include "winstring.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wintypes);

#ifndef RO_E_METADATA_NAME_NOT_FOUND
#define RO_E_METADATA_NAME_NOT_FOUND ((HRESULT)0x8000000F)
#endif

typedef struct
{
    HSTRING *items;
    DWORD count;
    DWORD allocated;
} string_list;

static HRESULT list_add(string_list *list, const WCHAR *str, UINT32 len)
{
    HRESULT hr;

    if (list->count == list->allocated)
    {
        DWORD allocated = list->allocated ? list->allocated * 2 : 8;
        HSTRING *items = CoTaskMemRealloc(list->items, allocated * sizeof(*items));

        if (!items)
            return E_OUTOFMEMORY;
        list->items = items;
        list->allocated = allocated;
    }
    hr = WindowsCreateString(str, len, &list->items[list->count]);
    if (SUCCEEDED(hr))
        list->count++;
    return hr;
}

static BOOL list_contains(const string_list *list, const WCHAR *str, UINT32 len)
{
    DWORD i;

    for (i = 0; i < list->count; i++)
    {
        UINT32 have_len;
        const WCHAR *have = WindowsGetStringRawBuffer(list->items[i], &have_len);

        if (have_len == len && !memcmp(have, str, len * sizeof(WCHAR)))
            return TRUE;
    }
    return FALSE;
}

static void list_free(string_list *list)
{
    DWORD i;

    for (i = 0; i < list->count; i++)
        WindowsDeleteString(list->items[i]);
    CoTaskMemFree(list->items);
    list->items = NULL;
    list->count = list->allocated = 0;
}

typedef struct
{
    WCHAR path[MAX_PATH];
    UINT32 ns_len;             /* length of the file's namespace: more is more specific */
} found_file;

/* Looks at the .winmd files of one directory */
static HRESULT search_directory(const WCHAR *dir, const WCHAR *name, UINT32 name_len,
                                found_file **files, DWORD *file_count, string_list *subs)
{
    WCHAR pattern[MAX_PATH];
    WIN32_FIND_DATAW data;
    HANDLE find;
    HRESULT hr = S_OK;
    size_t dir_len = wcslen(dir);

    if (dir_len + 9 >= ARRAYSIZE(pattern))
        return S_OK;
    wcscpy(pattern, dir);
    if (dir_len && dir[dir_len - 1] != L'\\')
        pattern[dir_len++] = L'\\';
    wcscpy(pattern + dir_len, L"*.winmd");

    find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE)
        return S_OK;
    do
    {
        size_t len = wcslen(data.cFileName);
        UINT32 ns_len;

        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || len <= 6 ||
            _wcsicmp(data.cFileName + len - 6, L".winmd"))
            continue;
        ns_len = (UINT32)(len - 6);

        /* the file's namespace is the name or above it */
        if (ns_len <= name_len && !wcsncmp(data.cFileName, name, ns_len) &&
            (ns_len == name_len || name[ns_len] == L'.'))
        {
            found_file *grown;

            if (dir_len + len >= MAX_PATH)
                continue;
            grown = CoTaskMemRealloc(*files, (*file_count + 1) * sizeof(**files));
            if (!grown)
            {
                hr = E_OUTOFMEMORY;
                break;
            }
            *files = grown;
            wcscpy(grown[*file_count].path, pattern);
            wcscpy(grown[*file_count].path + dir_len, data.cFileName);
            grown[*file_count].ns_len = ns_len;
            (*file_count)++;
        }
        /* a file below the name gives the next part of its namespace */
        else if (subs && ns_len > name_len + 1 && !wcsncmp(data.cFileName, name, name_len) &&
                 data.cFileName[name_len] == L'.')
        {
            const WCHAR *sub = data.cFileName + name_len + 1;
            UINT32 sub_len = 0;

            while (sub + sub_len < data.cFileName + ns_len && sub[sub_len] != L'.')
                sub_len++;
            if (sub_len && !list_contains(subs, sub, sub_len))
            {
                hr = list_add(subs, sub, sub_len);
                if (FAILED(hr))
                    break;
            }
        }
    } while (FindNextFileW(find, &data));
    FindClose(find);
    return hr;
}

static void get_metadata_directory(WCHAR *dir, UINT size)
{
    BOOL wow64 = FALSE;
    UINT len;

    if (IsWow64Process(GetCurrentProcess(), &wow64) && wow64)
    {
        len = GetWindowsDirectoryW(dir, size);
        if (len && len + 24 < size)
            wcscpy(dir + len, L"\\SysNative\\WinMetadata");
        else
            dir[0] = 0;
        return;
    }
    len = GetSystemDirectoryW(dir, size);
    if (len && len + 13 < size)
        wcscpy(dir + len, L"\\WinMetadata");
    else
        dir[0] = 0;
}

HRESULT WINAPI RoResolveNamespace(HSTRING name, HSTRING windowsMetaDataDir,
                                  DWORD packageGraphDirsCount, const HSTRING *packageGraphDirs,
                                  DWORD *metaDataFilePathsCount, HSTRING **metaDataFilePaths,
                                  DWORD *subNamespacesCount, HSTRING **subNamespaces)
{
    WCHAR dir[MAX_PATH];
    const WCHAR *name_str;
    UINT32 name_len;
    BOOL has_null;
    found_file *files = NULL;
    DWORD file_count = 0, i;
    string_list paths = { 0 }, subs = { 0 };
    HRESULT hr;

    TRACE("(%s, %s, %lu, %p, %p, %p, %p, %p)\n", debugstr_hstring(name), debugstr_hstring(windowsMetaDataDir),
          packageGraphDirsCount, packageGraphDirs, metaDataFilePathsCount, metaDataFilePaths,
          subNamespacesCount, subNamespaces);

    if (metaDataFilePathsCount)
        *metaDataFilePathsCount = 0;
    if (metaDataFilePaths)
        *metaDataFilePaths = NULL;
    if (subNamespacesCount)
        *subNamespacesCount = 0;
    if (subNamespaces)
        *subNamespaces = NULL;

    if (WindowsIsStringEmpty(name))
        return E_INVALIDARG;
    if (FAILED(WindowsStringHasEmbeddedNull(name, &has_null)) || has_null)
        return E_INVALIDARG;
    if (!metaDataFilePaths && !subNamespaces)
        return E_INVALIDARG;
    if (!metaDataFilePathsCount != !metaDataFilePaths || !subNamespacesCount != !subNamespaces)
        return E_INVALIDARG;
    if (packageGraphDirsCount && !packageGraphDirs)
        return E_INVALIDARG;

    name_str = WindowsGetStringRawBuffer(name, &name_len);

    if (!WindowsIsStringEmpty(windowsMetaDataDir))
        lstrcpynW(dir, WindowsGetStringRawBuffer(windowsMetaDataDir, NULL), ARRAYSIZE(dir));
    else
        get_metadata_directory(dir, ARRAYSIZE(dir));

    hr = search_directory(dir, name_str, name_len, &files, &file_count, subNamespaces ? &subs : NULL);
    for (i = 0; SUCCEEDED(hr) && i < packageGraphDirsCount; i++)
    {
        if (WindowsIsStringEmpty(packageGraphDirs[i]))
            continue;
        lstrcpynW(dir, WindowsGetStringRawBuffer(packageGraphDirs[i], NULL), ARRAYSIZE(dir));
        hr = search_directory(dir, name_str, name_len, &files, &file_count, subNamespaces ? &subs : NULL);
    }

    /* the most specific file first */
    for (i = 1; i < file_count; i++)
    {
        found_file file = files[i];
        DWORD j = i;

        for (; j && files[j - 1].ns_len < file.ns_len; j--)
            files[j] = files[j - 1];
        files[j] = file;
    }
    for (i = 0; SUCCEEDED(hr) && i < file_count; i++)
        hr = list_add(&paths, files[i].path, (UINT32)wcslen(files[i].path));
    CoTaskMemFree(files);

    if (SUCCEEDED(hr) && !paths.count && !(subNamespaces && subs.count))
        hr = RO_E_METADATA_NAME_NOT_FOUND;

    if (FAILED(hr))
    {
        list_free(&paths);
        list_free(&subs);
        return hr;
    }

    if (metaDataFilePaths && paths.count)
    {
        *metaDataFilePathsCount = paths.count;
        *metaDataFilePaths = paths.items;
    }
    else
        list_free(&paths);

    if (subNamespaces && subs.count)
    {
        *subNamespacesCount = subs.count;
        *subNamespaces = subs.items;
    }
    else
        list_free(&subs);

    return S_OK;
}

HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **factory)
{
    FIXME("(%s, %p): no activatable classes\n", debugstr_hstring(classid), factory);

    if (!factory)
        return E_POINTER;
    *factory = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllCanUnloadNow(void)
{
    return S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(instance);
    return TRUE;
}
