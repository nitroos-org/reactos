/*
 * DISM API (dismapi.dll)
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
 * The part of the DISM API that the Microsoft 365 Apps Click-to-Run client needs:
 * InspectorOfficeGadget.exe ("deprovisionuninstall") initializes the API, opens
 * the online image, lists the provisioned AppX packages and removes the one
 * that matches. nitro has no servicing stack and no provisioned packages, so
 * the online image is an image with an empty provisioned package list.
 *
 * The return codes, the session numbers and the reference counting of
 * DismInitialize / DismShutdown / DismOpenSession / DismCloseSession follow
 * measurements on Windows 10 22H2 (DismApi.dll 6.2.19041.844, x64 and x86
 * agree). Everything else in the export table is a stub.
 */

#include <stdarg.h>
#include <stdio.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winerror.h>

#define DISMAPI_E_DISMAPI_NOT_INITIALIZED   ((HRESULT)0xC0040001)
#define DISMAPI_E_INVALID_DISM_SESSION      ((HRESULT)0xC0040004)

#define ONLINE_IMAGE L"DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}"
#define ONLINE_SESSION 2

typedef struct { PCWSTR Value; } DismString;

static CRITICAL_SECTION g_cs;

static LONG g_init;         /* DismInitialize calls not yet matched by DismShutdown */
static LONG g_online;       /* open references of the online session */
static DismString *g_lasterr;

/* the last error message is kept until the next failing call (Windows: per DismGetLastErrorMessage call) */
static HRESULT set_error(HRESULT hr)
{
    WCHAR *text = NULL;
    DismString *old, *str;
    DWORD len;
    HRESULT win;

    if (hr >= 0) return hr;

    win = hr;
    if (HRESULT_FACILITY(hr) == FACILITY_WIN32) win = HRESULT_CODE(hr);
    len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                         NULL, win, 0, (WCHAR *)&text, 0, NULL);
    if (!len)
    {
        static const WCHAR fmt[] = L"Error 0x%08x\r\n";
        text = LocalAlloc(LMEM_FIXED, 64 * sizeof(WCHAR));
        if (!text) return hr;
        _snwprintf(text, 64, fmt, (unsigned int)hr);
    }
    str = HeapAlloc(GetProcessHeap(), 0, sizeof(*str) + (lstrlenW(text) + 1) * sizeof(WCHAR));
    if (str)
    {
        str->Value = (WCHAR *)(str + 1);
        lstrcpyW((WCHAR *)str->Value, text);
    }
    LocalFree(text);

    EnterCriticalSection(&g_cs);
    old = g_lasterr;
    g_lasterr = str;
    LeaveCriticalSection(&g_cs);
    if (old) HeapFree(GetProcessHeap(), 0, old);
    return hr;
}

HRESULT WINAPI DismInitialize(INT log_level, PCWSTR log_path, PCWSTR scratch_dir)
{
    HRESULT hr;

    EnterCriticalSection(&g_cs);
    hr = g_init++ ? S_FALSE : S_OK;
    LeaveCriticalSection(&g_cs);
    return hr;
}

HRESULT WINAPI DismShutdown(void)
{
    HRESULT hr;

    EnterCriticalSection(&g_cs);
    if (!g_init) hr = DISMAPI_E_DISMAPI_NOT_INITIALIZED;
    else if (--g_init) hr = S_FALSE;
    else
    {
        g_online = 0;
        hr = S_OK;
    }
    LeaveCriticalSection(&g_cs);
    return hr == S_FALSE ? S_FALSE : set_error(hr);
}

HRESULT WINAPI DismOpenSession(PCWSTR image, PCWSTR windir, PCWSTR sysdrive, UINT *session)
{
    HRESULT hr;

    if (!image || !session) return set_error(E_INVALIDARG);

    EnterCriticalSection(&g_cs);
    if (!g_init) hr = DISMAPI_E_DISMAPI_NOT_INITIALIZED;
    else if (!lstrcmpiW(image, ONLINE_IMAGE))
    {
        g_online++;
        *session = ONLINE_SESSION;
        hr = S_OK;
    }
    else
    {
        /* no offline servicing: a path that does not exist fails like on Windows */
        DWORD attr = GetFileAttributesW(image);
        hr = (attr == INVALID_FILE_ATTRIBUTES) ? HRESULT_FROM_WIN32(GetLastError()) : HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }
    LeaveCriticalSection(&g_cs);
    return set_error(hr);
}

HRESULT WINAPI DismCloseSession(UINT session)
{
    HRESULT hr;

    EnterCriticalSection(&g_cs);
    if (!g_init) hr = DISMAPI_E_DISMAPI_NOT_INITIALIZED;
    else if (session == ONLINE_SESSION && g_online)
    {
        g_online--;
        hr = S_OK;
    }
    else hr = DISMAPI_E_INVALID_DISM_SESSION;
    LeaveCriticalSection(&g_cs);
    return set_error(hr);
}

static HRESULT check_session(UINT session)
{
    HRESULT hr;

    EnterCriticalSection(&g_cs);
    if (!g_init) hr = DISMAPI_E_DISMAPI_NOT_INITIALIZED;
    else if (session == ONLINE_SESSION && g_online) hr = S_OK;
    else hr = DISMAPI_E_INVALID_DISM_SESSION;
    LeaveCriticalSection(&g_cs);
    return hr;
}

HRESULT WINAPI DismDelete(void *ptr)
{
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
    return S_OK;
}

HRESULT WINAPI DismGetLastErrorMessage(DismString **message)
{
    DismString *copy = NULL, *src;

    if (!message) return E_INVALIDARG;
    EnterCriticalSection(&g_cs);
    src = g_lasterr;
    if (src)
    {
        copy = HeapAlloc(GetProcessHeap(), 0, sizeof(*copy) + (lstrlenW(src->Value) + 1) * sizeof(WCHAR));
        if (copy)
        {
            copy->Value = (WCHAR *)(copy + 1);
            lstrcpyW((WCHAR *)copy->Value, src->Value);
        }
    }
    LeaveCriticalSection(&g_cs);
    *message = copy;
    return S_OK;
}

/* the list of provisioned packages of the online image: nitro has none */
HRESULT WINAPI _DismGetProvisionedAppxPackages(UINT session, void **packages, UINT *count)
{
    HRESULT hr = check_session(session);

    if (FAILED(hr)) return set_error(hr);
    if (!packages || !count) return set_error(E_INVALIDARG);
    *packages = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(void *));
    *count = 0;
    return S_OK;
}

HRESULT WINAPI _DismRemoveProvisionedAppxPackage(UINT session, PCWSTR package)
{
    HRESULT hr = check_session(session);

    if (FAILED(hr)) return set_error(hr);
    if (!package) return set_error(E_INVALIDARG);
    return set_error(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, void *reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(inst);
        InitializeCriticalSection(&g_cs);
        break;
    case DLL_PROCESS_DETACH:
        if (!reserved) DeleteCriticalSection(&g_cs);
        break;
    }
    return TRUE;
}
