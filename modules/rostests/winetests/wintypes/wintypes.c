/*
 * Unit test suite for RoResolveNamespace (wintypes.dll)
 *
 * Copyright 2026 the reactos-nitro authors
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
 * The default-directory cases were measured on Windows 10 22H2 x64 and x86 (read-only probe,
 * 2026-11-03): Windows.Foundation(.Collections, .Nothing) -> Windows.Foundation.winmd;
 * "windows.foundation", "Nitro.Nothing", "Windows.Nothing" -> RO_E_METADATA_NAME_NOT_FOUND;
 * "Windows" -> no file and subnamespaces, or RO_E_METADATA_NAME_NOT_FOUND when only the files are
 * asked for; a WoW64 process gets %SystemRoot%\SysNative paths. The cases with our own directory
 * (empty files, nested names) follow the same rules but were not run on Windows.
 */

#include <stdarg.h>
#include <stdio.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "objbase.h"
#include "winstring.h"

#include "wine/test.h"

#ifndef RO_E_METADATA_NAME_NOT_FOUND
#define RO_E_METADATA_NAME_NOT_FOUND ((HRESULT)0x8000000F)
#endif

static HRESULT (WINAPI *pRoResolveNamespace)(HSTRING, HSTRING, DWORD, const HSTRING *, DWORD *, HSTRING **, DWORD *, HSTRING **);

static HSTRING str(const WCHAR *s)
{
    HSTRING h = NULL;
    WindowsCreateString(s, lstrlenW(s), &h);
    return h;
}

static void free_list(HSTRING *list, DWORD count)
{
    DWORD i;
    for (i = 0; i < count; i++) WindowsDeleteString(list[i]);
    CoTaskMemFree(list);
}

static BOOL ends_with(HSTRING h, const WCHAR *tail)
{
    UINT32 len, tail_len = lstrlenW(tail);
    const WCHAR *s = WindowsGetStringRawBuffer(h, &len);
    return len >= tail_len && !lstrcmpW(s + len - tail_len, tail);
}

static void test_default_directory(void)
{
    static const WCHAR *found[] = { L"Windows.Foundation", L"Windows.Foundation.Collections", L"Windows.Foundation.Nothing" };
    static const WCHAR *missing[] = { L"windows.foundation", L"Nitro.Nothing", L"Windows.Nothing" };
    WCHAR expect[MAX_PATH];
    HSTRING name, *files, *subs;
    DWORD nfiles, nsubs, i;
    BOOL wow64 = FALSE;
    HRESULT hr;

    IsWow64Process(GetCurrentProcess(), &wow64);
    if (wow64)
    {
        GetWindowsDirectoryW(expect, MAX_PATH);
        lstrcatW(expect, L"\\SysNative\\WinMetadata\\Windows.Foundation.winmd");
    }
    else
    {
        GetSystemDirectoryW(expect, MAX_PATH);
        lstrcatW(expect, L"\\WinMetadata\\Windows.Foundation.winmd");
    }

    for (i = 0; i < ARRAY_SIZE(found); i++)
    {
        name = str(found[i]);
        hr = pRoResolveNamespace(name, NULL, 0, NULL, &nfiles, &files, NULL, NULL);
        ok(hr == S_OK, "%s: got %#lx\n", wine_dbgstr_w(found[i]), hr);
        ok(nfiles >= 1, "%s: got %lu files\n", wine_dbgstr_w(found[i]), nfiles);
        if (hr == S_OK && nfiles)
        {
            ok(!lstrcmpiW(WindowsGetStringRawBuffer(files[0], NULL), expect), "%s: got %s, expected %s\n",
               wine_dbgstr_w(found[i]), wine_dbgstr_w(WindowsGetStringRawBuffer(files[0], NULL)), wine_dbgstr_w(expect));
            free_list(files, nfiles);
        }
        WindowsDeleteString(name);
    }

    for (i = 0; i < ARRAY_SIZE(missing); i++)
    {
        files = (HSTRING *)0xdeadbeef;
        nfiles = 0xdeadbeef;
        name = str(missing[i]);
        hr = pRoResolveNamespace(name, NULL, 0, NULL, &nfiles, &files, &nsubs, &subs);
        ok(hr == RO_E_METADATA_NAME_NOT_FOUND, "%s: got %#lx\n", wine_dbgstr_w(missing[i]), hr);
        ok(!nfiles && !files, "%s: got %lu %p\n", wine_dbgstr_w(missing[i]), nfiles, files);
        WindowsDeleteString(name);
    }

    name = str(L"Windows");
    hr = pRoResolveNamespace(name, NULL, 0, NULL, &nfiles, &files, &nsubs, &subs);
    ok(hr == S_OK, "Windows: got %#lx\n", hr);
    ok(!nfiles, "Windows: got %lu files\n", nfiles);
    ok(nsubs >= 1, "Windows: got %lu subnamespaces\n", nsubs);
    if (hr == S_OK)
    {
        BOOL foundation = FALSE;
        for (i = 0; i < nsubs; i++)
            if (!lstrcmpW(WindowsGetStringRawBuffer(subs[i], NULL), L"Foundation")) foundation = TRUE;
        ok(foundation, "Windows: no Foundation subnamespace\n");
        free_list(subs, nsubs);
    }
    hr = pRoResolveNamespace(name, NULL, 0, NULL, &nfiles, &files, NULL, NULL);
    ok(hr == RO_E_METADATA_NAME_NOT_FOUND, "Windows, files only: got %#lx\n", hr);
    WindowsDeleteString(name);
}

static void test_arguments(void)
{
    HSTRING name = str(L"Windows.Foundation"), empty = NULL, *files;
    DWORD nfiles;
    HRESULT hr;

    hr = pRoResolveNamespace(NULL, NULL, 0, NULL, &nfiles, NULL, NULL, NULL);
    ok(hr == E_INVALIDARG, "got %#lx\n", hr);
    hr = pRoResolveNamespace(empty, NULL, 0, NULL, &nfiles, &files, NULL, NULL);
    ok(hr == E_INVALIDARG, "empty name: got %#lx\n", hr);
    hr = pRoResolveNamespace(name, NULL, 0, NULL, NULL, NULL, NULL, NULL);
    ok(hr == E_INVALIDARG, "no output: got %#lx\n", hr);
    hr = pRoResolveNamespace(name, NULL, 0, NULL, NULL, &files, NULL, NULL);
    ok(hr == E_INVALIDARG, "no count: got %#lx\n", hr);
    WindowsDeleteString(name);
}

static void create_file(const WCHAR *dir, const WCHAR *name)
{
    WCHAR path[MAX_PATH];
    HANDLE file;

    lstrcpyW(path, dir);
    lstrcatW(path, L"\\");
    lstrcatW(path, name);
    file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "create %s: %lu\n", wine_dbgstr_w(path), GetLastError());
    CloseHandle(file);
}

static void delete_file(const WCHAR *dir, const WCHAR *name)
{
    WCHAR path[MAX_PATH];
    lstrcpyW(path, dir);
    lstrcatW(path, L"\\");
    lstrcatW(path, name);
    DeleteFileW(path);
}

static void test_own_directory(void)
{
    static const WCHAR *names[] = { L"Nitro.Test.winmd", L"Nitro.Test.Inner.winmd", L"Nitro.Test.Other.Deep.winmd", L"Nitro.Testing.winmd" };
    WCHAR dir[MAX_PATH];
    HSTRING hdir, name, *files, *subs;
    DWORD nfiles, nsubs, i;
    HRESULT hr;

    GetTempPathW(MAX_PATH, dir);
    lstrcatW(dir, L"wintypes_test");
    CreateDirectoryW(dir, NULL);
    for (i = 0; i < ARRAY_SIZE(names); i++) create_file(dir, names[i]);
    hdir = str(dir);

    /* the most specific file first, then the files above it; Nitro.Testing is not above Nitro.Test */
    name = str(L"Nitro.Test.Inner.Type");
    hr = pRoResolveNamespace(name, hdir, 0, NULL, &nfiles, &files, NULL, NULL);
    ok(hr == S_OK, "got %#lx\n", hr);
    ok(nfiles == 2, "got %lu files\n", nfiles);
    if (hr == S_OK && nfiles == 2)
    {
        ok(ends_with(files[0], L"\\Nitro.Test.Inner.winmd"), "got %s\n", wine_dbgstr_w(WindowsGetStringRawBuffer(files[0], NULL)));
        ok(ends_with(files[1], L"\\Nitro.Test.winmd"), "got %s\n", wine_dbgstr_w(WindowsGetStringRawBuffer(files[1], NULL)));
    }
    if (hr == S_OK) free_list(files, nfiles);
    WindowsDeleteString(name);

    /* subnamespaces: the next part of each name below, once */
    name = str(L"Nitro.Test");
    hr = pRoResolveNamespace(name, hdir, 0, NULL, &nfiles, &files, &nsubs, &subs);
    ok(hr == S_OK, "got %#lx\n", hr);
    ok(nfiles == 1, "got %lu files\n", nfiles);
    ok(nsubs == 2, "got %lu subnamespaces\n", nsubs);
    if (hr == S_OK)
    {
        if (nsubs == 2)
        {
            ok(!lstrcmpW(WindowsGetStringRawBuffer(subs[0], NULL), L"Inner"), "got %s\n", wine_dbgstr_w(WindowsGetStringRawBuffer(subs[0], NULL)));
            ok(!lstrcmpW(WindowsGetStringRawBuffer(subs[1], NULL), L"Other"), "got %s\n", wine_dbgstr_w(WindowsGetStringRawBuffer(subs[1], NULL)));
        }
        free_list(files, nfiles);
        free_list(subs, nsubs);
    }
    WindowsDeleteString(name);

    /* case matters */
    name = str(L"nitro.test");
    hr = pRoResolveNamespace(name, hdir, 0, NULL, &nfiles, &files, NULL, NULL);
    ok(hr == RO_E_METADATA_NAME_NOT_FOUND, "got %#lx\n", hr);
    WindowsDeleteString(name);

    for (i = 0; i < ARRAY_SIZE(names); i++) delete_file(dir, names[i]);
    RemoveDirectoryW(dir);
    WindowsDeleteString(hdir);
}

/* The metadata directory with "\." appended until the name has the wanted length (an odd length) */
static void long_directory(WCHAR *dir, UINT len)
{
    UINT n;

    n = GetWindowsDirectoryW(dir, MAX_PATH);
    lstrcpyW(dir + n, L"\\System32\\WinMetadata");
    for (n = lstrlenW(dir); n + 2 <= len; n += 2)
    {
        dir[n] = L'\\';
        dir[n + 1] = L'.';
    }
    dir[n] = 0;
}

/* Measured on Windows 10 22H2 (x64 and x86): a windowsMetaDataDir of up to 233 characters is
 * searched and found, up to 246 searched without a result (the file name does not fit MAX_PATH),
 * from 247 on E_INVALIDARG; a package graph directory that long is ignored. */
static void test_long_directory(void)
{
    static const UINT lengths[] = { 99, 233, 245, 247, 259, 1001 };
    WCHAR dir[1100];
    HSTRING name = str(L"Windows.Foundation"), hdir, *files;
    DWORD nfiles;
    HRESULT hr;
    UINT i;

    for (i = 0; i < ARRAYSIZE(lengths); i++)
    {
        HRESULT expect = lengths[i] <= 233 ? S_OK : lengths[i] <= 246 ? RO_E_METADATA_NAME_NOT_FOUND : E_INVALIDARG;

        long_directory(dir, lengths[i]);
        if (lstrlenW(dir) != lengths[i])
        {
            skip("cannot make a directory name of %u characters from %s\n", lengths[i], wine_dbgstr_w(dir));
            continue;
        }
        hdir = str(dir);
        files = NULL;
        nfiles = 0xdeadbeef;
        hr = pRoResolveNamespace(name, hdir, 0, NULL, &nfiles, &files, NULL, NULL);
        ok(hr == expect, "dir length %u: got %#lx, expected %#lx\n", lengths[i], hr, expect);
        if (hr == S_OK)
        {
            ok(nfiles == 1, "dir length %u: got %lu files\n", lengths[i], nfiles);
            if (nfiles == 1)
            {
                UINT32 len;
                const WCHAR *path = WindowsGetStringRawBuffer(files[0], &len);
                ok(len == lengths[i] + 25, "dir length %u: path %s\n", lengths[i], wine_dbgstr_w(path));
            }
            free_list(files, nfiles);
        }
        else
        {
            ok(!nfiles && !files, "dir length %u: %lu files, %p\n", lengths[i], nfiles, files);
        }
        WindowsDeleteString(hdir);

        /* as a package graph directory it is searched, or ignored when too long: never cut off */
        hdir = str(dir);
        files = NULL;
        nfiles = 0xdeadbeef;
        hr = pRoResolveNamespace(name, NULL, 1, &hdir, &nfiles, &files, NULL, NULL);
        ok(hr == S_OK, "graph length %u: got %#lx\n", lengths[i], hr);
        if (hr == S_OK)
        {
            DWORD j;

            for (j = 0; j < nfiles; j++)
            {
                UINT32 len;
                const WCHAR *path = WindowsGetStringRawBuffer(files[j], &len);
                ok(len < MAX_PATH, "graph length %u: path %s\n", lengths[i], wine_dbgstr_w(path));
            }
            free_list(files, nfiles);
        }
        WindowsDeleteString(hdir);
    }
    WindowsDeleteString(name);
}

START_TEST(wintypes)
{
    HMODULE module = LoadLibraryW(L"wintypes.dll");

    pRoResolveNamespace = (void *)GetProcAddress(module, "RoResolveNamespace");
    if (!pRoResolveNamespace)
    {
        win_skip("RoResolveNamespace is not available\n");
        return;
    }
    test_arguments();
    test_default_directory();
    test_own_directory();
    test_long_directory();
}
