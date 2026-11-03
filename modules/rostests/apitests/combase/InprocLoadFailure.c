/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test the result of CoCreateInstance when the in-process server of a class cannot be loaded
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The Click-To-Run service asks for the InfoPath MIME filter, whose server it cannot load, and takes the
 * failure as "not available" only for the loader's error. COM returns the Win32 error of the failed load as an
 * HRESULT (ERROR_MOD_NOT_FOUND for a missing file, ERROR_BAD_EXE_FORMAT for a file that is no image), not
 * E_ACCESSDENIED. The expected values follow the loader's documented errors and the broken() cases of the
 * ole32 compobj test (HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND) for a class whose server is gone).
 */

#define COBJMACROS
#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <objbase.h>

static const GUID CLSID_LoadFailure =
    {0x5d63ee0e, 0x7a5c, 0x4b2f, {0x9a, 0x16, 0x0f, 0x2c, 0x1c, 0x3a, 0x8e, 0x11}};
#define CLSID_KEY L"CLSID\\{5D63EE0E-7A5C-4B2F-9A16-0F2C1C3A8E11}"

static BOOL register_server(const WCHAR *path)
{
    HKEY key;
    LONG ret = RegCreateKeyExW(HKEY_CLASSES_ROOT, CLSID_KEY L"\\InprocServer32", 0, NULL, 0,
                               KEY_WRITE, NULL, &key, NULL);
    ok(ret == ERROR_SUCCESS, "RegCreateKeyEx failed: %ld\n", ret);
    if (ret != ERROR_SUCCESS)
        return FALSE;
    ret = RegSetValueExW(key, NULL, 0, REG_SZ, (const BYTE *)path, (lstrlenW(path) + 1) * sizeof(WCHAR));
    ok(ret == ERROR_SUCCESS, "RegSetValueEx failed: %ld\n", ret);
    RegSetValueExW(key, L"ThreadingModel", 0, REG_SZ, (const BYTE *)L"Apartment", 20);
    RegCloseKey(key);
    return TRUE;
}

static void check(const char *what, HRESULT expected)
{
    IUnknown *unk = (IUnknown *)(ULONG_PTR)1;
    HRESULT hr = CoCreateInstance(&CLSID_LoadFailure, NULL, CLSCTX_INPROC_SERVER, &IID_IUnknown, (void **)&unk);

    ok(hr == expected, "%s: CoCreateInstance returned %08lx, expected %08lx\n", what, hr, expected);
    ok(unk == NULL, "%s: got the interface %p\n", what, unk);
}

START_TEST(InprocLoadFailure)
{
    WCHAR dir[MAX_PATH], missing[MAX_PATH], garbage[MAX_PATH];
    HANDLE file;
    DWORD written;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %08lx\n", hr);

    GetTempPathW(MAX_PATH, dir);
    lstrcpyW(missing, dir);
    lstrcatW(missing, L"InprocLoadFailure-missing.dll");
    lstrcpyW(garbage, dir);
    lstrcatW(garbage, L"InprocLoadFailure-garbage.dll");
    DeleteFileW(missing);

    if (register_server(missing))
        check("missing file", HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND));

    file = CreateFileW(garbage, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(file != INVALID_HANDLE_VALUE, "CreateFile failed: %lu\n", GetLastError());
    if (file != INVALID_HANDLE_VALUE)
    {
        static const char text[] = "This is not a PE image, only text.\r\n";
        WriteFile(file, text, sizeof(text), &written, NULL);
        CloseHandle(file);
        if (register_server(garbage))
            check("file that is no image", HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT));
        DeleteFileW(garbage);
    }

    RegDeleteKeyW(HKEY_CLASSES_ROOT, CLSID_KEY L"\\InprocServer32");
    RegDeleteKeyW(HKEY_CLASSES_ROOT, CLSID_KEY);
    CoUninitialize();
}
