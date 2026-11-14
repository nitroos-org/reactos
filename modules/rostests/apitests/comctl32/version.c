/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for the version that the v5 and the v6 comctl32 report
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "wine/test.h"

#include <windows.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <wchar.h>

#define MANIFEST_HEAD \
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n" \
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n" \
    "<dependency><dependentAssembly>\r\n" \
    "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\""
#define MANIFEST_TAIL \
    "\" publicKeyToken=\"6595b64144ccf1df\" processorArchitecture=\"*\" language=\"*\"/>\r\n" \
    "</dependentAssembly></dependency>\r\n" \
    "</assembly>\r\n"

/* Loads comctl32.dll while the activation context of the manifest with the given version is active */
static HMODULE load_comctl32(const char *version, HANDLE *ctx_out, ULONG_PTR *cookie_out, WCHAR *manifest_path)
{
    char manifest[512];
    WCHAR dir[MAX_PATH];
    ACTCTXW act = { sizeof(act) };
    HANDLE file, ctx;
    DWORD written;
    ULONG_PTR cookie;
    HMODULE module;

    *ctx_out = INVALID_HANDLE_VALUE;
    *cookie_out = 0;
    manifest_path[0] = 0;

    lstrcpyA(manifest, MANIFEST_HEAD);
    lstrcatA(manifest, version);
    lstrcatA(manifest, MANIFEST_TAIL);

    GetTempPathW(ARRAY_SIZE(dir), dir);
    GetTempFileNameW(dir, L"cv", 0, manifest_path);
    file = CreateFileW(manifest_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(file != INVALID_HANDLE_VALUE, "CreateFile failed, error %lu\n", GetLastError());
    if (file == INVALID_HANDLE_VALUE)
        return NULL;
    WriteFile(file, manifest, lstrlenA(manifest), &written, NULL);
    CloseHandle(file);

    act.lpSource = manifest_path;
    ctx = CreateActCtxW(&act);
    ok(ctx != INVALID_HANDLE_VALUE, "CreateActCtx(%s) failed, error %lu\n", version, GetLastError());
    if (ctx == INVALID_HANDLE_VALUE)
    {
        DeleteFileW(manifest_path);
        return NULL;
    }

    ok(ActivateActCtx(ctx, &cookie), "ActivateActCtx failed, error %lu\n", GetLastError());
    module = LoadLibraryW(L"comctl32.dll");
    ok(module != NULL, "LoadLibrary(comctl32.dll) with the %s manifest failed, error %lu\n",
       version, GetLastError());
    DeactivateActCtx(0, cookie);

    *ctx_out = ctx;
    *cookie_out = cookie;
    return module;
}

static void check_image(HMODULE module, BOOL v6)
{
    WCHAR path[MAX_PATH];
    HRESULT (WINAPI *pDllGetVersion)(DLLVERSIONINFO *);
    DLLVERSIONINFO dvi;
    VS_FIXEDFILEINFO *fixed;
    DWORD handle, size;
    UINT len;
    void *data;
    HRESULT hr;
    const char *name = v6 ? "v6" : "v5";

    pDllGetVersion = (void *)GetProcAddress(module, "DllGetVersion");
    ok(pDllGetVersion != NULL, "%s: DllGetVersion is not exported\n", name);
    if (pDllGetVersion)
    {
        memset(&dvi, 0, sizeof(dvi));
        dvi.cbSize = sizeof(dvi);
        hr = pDllGetVersion(&dvi);
        ok(hr == S_OK, "%s: DllGetVersion returned %#lx\n", name, hr);
        if (v6)
        {
            ok(dvi.dwMajorVersion == 6, "%s: major version is %lu\n", name, dvi.dwMajorVersion);
            ok(dvi.dwMinorVersion == 16, "%s: minor version is %lu\n", name, dvi.dwMinorVersion);
            ok(dvi.dwBuildNumber == 10586, "%s: build number is %lu\n", name, dvi.dwBuildNumber);
            ok(dvi.dwPlatformID == DLLVER_PLATFORM_NT, "%s: platform is %lu\n", name, dvi.dwPlatformID);
        }
        else
        {
            ok(dvi.dwMajorVersion == 5, "%s: major version is %lu\n", name, dvi.dwMajorVersion);
            ok(dvi.dwMinorVersion == 82, "%s: minor version is %lu\n", name, dvi.dwMinorVersion);
        }

        dvi.cbSize = sizeof(dvi) + 1;
        hr = pDllGetVersion(&dvi);
        ok(hr == E_INVALIDARG, "%s: DllGetVersion with a wrong size returned %#lx\n", name, hr);
    }

    ok(GetModuleFileNameW(module, path, ARRAY_SIZE(path)) != 0, "GetModuleFileName failed\n");
    trace("%s image: %ls\n", name, path);
    if (v6)
        ok(wcsstr(path, L"_6.0.") != NULL, "the v6 image is loaded from %ls\n", path);
    else
        ok(wcsstr(path, L"_6.0.") == NULL, "the v5 image is loaded from %ls\n", path);

    size = GetFileVersionInfoSizeW(path, &handle);
    ok(size != 0, "%s: GetFileVersionInfoSize(%ls) failed, error %lu\n", name, path, GetLastError());
    if (!size)
        return;
    data = HeapAlloc(GetProcessHeap(), 0, size);
    ok(GetFileVersionInfoW(path, 0, size, data), "%s: GetFileVersionInfo failed, error %lu\n",
       name, GetLastError());
    fixed = NULL;
    len = 0;
    if (VerQueryValueW(data, L"\\", (void **)&fixed, &len) && fixed)
    {
        if (v6)
        {
            ok(fixed->dwFileVersionMS == MAKELONG(16, 6), "%s: file version %lu.%lu\n", name,
               fixed->dwFileVersionMS >> 16, fixed->dwFileVersionMS & 0xffff);
            ok(HIWORD(fixed->dwFileVersionLS) == 10586, "%s: file build %lu\n", name,
               fixed->dwFileVersionLS >> 16);
            ok(fixed->dwProductVersionMS == MAKELONG(16, 6), "%s: product version %lu.%lu\n", name,
               fixed->dwProductVersionMS >> 16, fixed->dwProductVersionMS & 0xffff);
        }
        else
        {
            ok(fixed->dwFileVersionMS == MAKELONG(82, 5), "%s: file version %lu.%lu\n", name,
               fixed->dwFileVersionMS >> 16, fixed->dwFileVersionMS & 0xffff);
        }
    }
    else
    {
        ok(0, "%s: VerQueryValue failed, error %lu\n", name, GetLastError());
    }
    HeapFree(GetProcessHeap(), 0, data);
}

START_TEST(version)
{
    WCHAR path5[MAX_PATH], path6[MAX_PATH];
    HANDLE ctx5, ctx6;
    ULONG_PTR cookie5, cookie6;
    HMODULE v5, v6;
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES };

    v5 = load_comctl32("5.82.0.0", &ctx5, &cookie5, path5);
    v6 = load_comctl32("6.0.0.0", &ctx6, &cookie6, path6);

    ok(v5 != NULL && v6 != NULL, "comctl32 did not load (%p, %p)\n", v5, v6);
    if (v5 && v6)
    {
        ok(v5 != v6, "both manifests give the same comctl32 module %p\n", v5);
        check_image(v5, FALSE);
        check_image(v6, TRUE);

        /* InitCommonControlsEx works in both images */
        {
            BOOL (WINAPI *pInit5)(const INITCOMMONCONTROLSEX *) = (void *)GetProcAddress(v5, "InitCommonControlsEx");
            BOOL (WINAPI *pInit6)(const INITCOMMONCONTROLSEX *) = (void *)GetProcAddress(v6, "InitCommonControlsEx");

            ok(pInit5 && pInit5(&icc), "v5 InitCommonControlsEx failed\n");
            ok(pInit6 && pInit6(&icc), "v6 InitCommonControlsEx failed\n");
        }
    }

    if (v6) FreeLibrary(v6);
    if (v5) FreeLibrary(v5);
    if (ctx6 != INVALID_HANDLE_VALUE) ReleaseActCtx(ctx6);
    if (ctx5 != INVALID_HANDLE_VALUE) ReleaseActCtx(ctx5);
    if (path6[0]) DeleteFileW(path6);
    if (path5[0]) DeleteFileW(path5);
}
