/*
 * Unit test suite for the DISM API (dismapi.dll), the part used by the Click-to-Run client
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

#include <stdarg.h>
#include <stdio.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winnls.h"

#include "wine/test.h"

/* every expectation was measured on Windows 10 22H2 (DismApi.dll 6.2.19041.844, x64 and x86) */
#define NOT_INITIALIZED ((HRESULT)0xC0040001)
#define INVALID_SESSION ((HRESULT)0xC0040004)
#define ONLINE L"DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}"

typedef struct { const WCHAR *Value; } DismString;

static HMODULE dism;
static HRESULT (WINAPI *pDismInitialize)(INT, const WCHAR *, const WCHAR *);
static HRESULT (WINAPI *pDismShutdown)(void);
static HRESULT (WINAPI *pDismOpenSession)(const WCHAR *, const WCHAR *, const WCHAR *, UINT *);
static HRESULT (WINAPI *pDismCloseSession)(UINT);
static HRESULT (WINAPI *pDismDelete)(void *);
static HRESULT (WINAPI *pDismGetLastErrorMessage)(DismString **);
static HRESULT (WINAPI *pGetProvisioned)(UINT, void **, UINT *);
static HRESULT (WINAPI *pRemoveProvisioned)(UINT, const WCHAR *);

static void test_dism(void)
{
    DismString *msg;
    UINT s, s2, count;
    void *pkg;
    HRESULT hr;

    /* nothing works before DismInitialize */
    s = 0;
    hr = pDismOpenSession(ONLINE, NULL, NULL, &s);
    ok(hr == NOT_INITIALIZED, "OpenSession before Initialize: %#lx\n", hr);
    ok(!s, "session %u\n", s);
    pkg = (void *)1; count = 99;
    hr = pGetProvisioned(5, &pkg, &count);
    ok(hr == NOT_INITIALIZED, "GetProvisioned before Initialize: %#lx\n", hr);
    ok(pkg == (void *)1 && count == 99, "outputs changed: %p %u\n", pkg, count);
    hr = pDismCloseSession(5);
    ok(hr == NOT_INITIALIZED, "CloseSession before Initialize: %#lx\n", hr);
    hr = pDismShutdown();
    ok(hr == NOT_INITIALIZED, "Shutdown before Initialize: %#lx\n", hr);

    /* initialize is reference counted: S_OK, then S_FALSE; shutdown S_FALSE, then S_OK */
    hr = pDismInitialize(0, NULL, NULL);
    ok(hr == S_OK, "Initialize: %#lx\n", hr);
    hr = pDismInitialize(0, NULL, NULL);
    ok(hr == S_FALSE, "second Initialize: %#lx\n", hr);

    /* the online image: the same session number, one open reference per call */
    s = s2 = 0;
    hr = pDismOpenSession(ONLINE, NULL, NULL, &s);
    ok(hr == S_OK, "OpenSession online: %#lx\n", hr);
    ok(s == 2, "session %u\n", s);
    hr = pDismOpenSession(ONLINE, NULL, NULL, &s2);
    ok(hr == S_OK, "second OpenSession online: %#lx\n", hr);
    ok(s2 == s, "sessions %u %u\n", s, s2);

    /* the provisioned package list is a valid answer with a count; DismDelete frees it */
    pkg = (void *)1; count = 99;
    hr = pGetProvisioned(s, &pkg, &count);
    ok(hr == S_OK, "GetProvisioned: %#lx\n", hr);
    ok(count != 99, "count not set\n");
    if (hr == S_OK)
    {
        hr = pDismDelete(pkg);
        ok(hr == S_OK, "DismDelete: %#lx\n", hr);
    }

    pkg = (void *)1; count = 99;
    hr = pGetProvisioned(s + 1000, &pkg, &count);
    ok(hr == INVALID_SESSION, "GetProvisioned bad session: %#lx\n", hr);
    ok(pkg == (void *)1 && count == 99, "outputs changed: %p %u\n", pkg, count);
    hr = pGetProvisioned(0, &pkg, &count);
    ok(hr == INVALID_SESSION, "GetProvisioned session 0: %#lx\n", hr);

    /* removing a package that is not provisioned */
    hr = pRemoveProvisioned(s, L"Nonexistent.Pkg_1.0.0.0_neutral__8wekyb3d8bbwe");
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "RemoveProvisioned: %#lx\n", hr);
    msg = NULL;
    hr = pDismGetLastErrorMessage(&msg);
    ok(hr == S_OK, "GetLastErrorMessage: %#lx\n", hr);
    ok(msg && msg->Value && msg->Value[0], "no message\n");
    if (msg)
    {
        ok(wcsstr(msg->Value, L"cannot find the file") != NULL || GetUserDefaultUILanguage() != 0x409,
                           "message %s\n", wine_dbgstr_w(msg->Value));
        pDismDelete(msg);
    }

    /* a path that does not exist */
    s2 = 7;
    hr = pDismOpenSession(L"C:\\nonexistent_image_dir", NULL, NULL, &s2);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "OpenSession bad path: %#lx\n", hr);
    ok(s2 == 7, "session changed to %u\n", s2);

    /* two opens, two closes, the third fails */
    hr = pDismCloseSession(s);
    ok(hr == S_OK, "CloseSession: %#lx\n", hr);
    hr = pDismCloseSession(s);
    ok(hr == S_OK, "second CloseSession: %#lx\n", hr);
    hr = pGetProvisioned(s, &pkg, &count);
    ok(hr == INVALID_SESSION, "GetProvisioned after close: %#lx\n", hr);
    hr = pDismCloseSession(s);
    ok(hr == INVALID_SESSION, "third CloseSession: %#lx\n", hr);

    hr = pDismShutdown();
    ok(hr == S_FALSE, "Shutdown: %#lx\n", hr);
    hr = pDismShutdown();
    ok(hr == S_OK, "second Shutdown: %#lx\n", hr);
    hr = pDismOpenSession(ONLINE, NULL, NULL, &s);
    ok(hr == NOT_INITIALIZED, "OpenSession after Shutdown: %#lx\n", hr);
}

START_TEST(dismapi)
{
    dism = LoadLibraryW(L"dismapi.dll");
    if (!dism)
    {
        win_skip("dismapi.dll not available\n");
        return;
    }
#define X(n) p##n = (void *)GetProcAddress(dism, #n)
    X(DismInitialize); X(DismShutdown); X(DismOpenSession); X(DismCloseSession); X(DismDelete); X(DismGetLastErrorMessage);
    pGetProvisioned = (void *)GetProcAddress(dism, "_DismGetProvisionedAppxPackages");
    pRemoveProvisioned = (void *)GetProcAddress(dism, "_DismRemoveProvisionedAppxPackage");
#undef X
    ok(pDismInitialize && pDismShutdown && pDismOpenSession && pDismCloseSession && pDismDelete &&
       pDismGetLastErrorMessage && pGetProvisioned && pRemoveProvisioned, "missing exports\n");
    if (!pRemoveProvisioned) return;
    test_dism();
}
