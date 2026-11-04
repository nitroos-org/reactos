/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Registration callbacks for cross-bitness regsvr32 tests
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Registration callbacks for cross-bitness regsvr32 tests. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>

static HRESULT Record(DWORD Operation)
{
    HANDLE File;
    DWORD Bytes, Value = Operation + sizeof(void *);
    WCHAR Fail[2];
    File = CreateFileW(L"C:\\harness\\reg-result.txt", GENERIC_WRITE, FILE_SHARE_READ,
                       NULL, CREATE_ALWAYS, 0, NULL);
    if (File == INVALID_HANDLE_VALUE) return E_FAIL;
    if (!WriteFile(File, &Value, sizeof(Value), &Bytes, NULL) || Bytes != sizeof(Value))
    {
        CloseHandle(File);
        return E_FAIL;
    }
    CloseHandle(File);
    return GetEnvironmentVariableW(L"W643C_REG_FAIL", Fail, 2) ? E_FAIL : S_OK;
}

HRESULT WINAPI DllRegisterServer(void) { return Record(0); }
HRESULT WINAPI DllUnregisterServer(void) { return Record(100); }
HRESULT WINAPI DllInstall(BOOL Install, PCWSTR Command)
{
    if (!Install || !Command || wcscmp(Command, L"argument with spaces")) return E_INVALIDARG;
    return Record(200);
}

BOOL WINAPI DllMain(HINSTANCE Instance, DWORD Reason, PVOID Reserved) { return TRUE; }
