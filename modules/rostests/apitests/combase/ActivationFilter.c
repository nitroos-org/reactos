/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for CoRegisterActivationFilter
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Microsoft Office registers an activation filter while it starts and is gone without the
 * function (the stub raised an exception). Only the registration is tested: the answer for a
 * second registration, for NULL and what the filter is asked were not measured on Windows.
 */

#define COBJMACROS
#include <apitest.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <objbase.h>

typedef HRESULT (WINAPI *CoRegisterActivationFilter_t)(IUnknown *);

typedef struct
{
    const IUnknownVtbl *lpVtbl;
    LONG ref;
} filter_t;

static HRESULT WINAPI filter_QueryInterface(IUnknown *iface, REFIID riid, void **obj)
{
    if (IsEqualGUID(riid, &IID_IUnknown))
    {
        *obj = iface;
        IUnknown_AddRef(iface);
        return S_OK;
    }
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI filter_AddRef(IUnknown *iface)
{
    return InterlockedIncrement(&((filter_t *)iface)->ref);
}

static ULONG WINAPI filter_Release(IUnknown *iface)
{
    return InterlockedDecrement(&((filter_t *)iface)->ref);
}

static const IUnknownVtbl filter_vtbl = { filter_QueryInterface, filter_AddRef, filter_Release };

START_TEST(ActivationFilter)
{
    HMODULE ole32 = LoadLibraryW(L"ole32.dll");
    CoRegisterActivationFilter_t pCoRegisterActivationFilter;
    filter_t filter = { &filter_vtbl, 1 };
    HRESULT hr;

    pCoRegisterActivationFilter = (void *)GetProcAddress(ole32, "CoRegisterActivationFilter");
    ok(pCoRegisterActivationFilter != NULL, "ole32 does not export CoRegisterActivationFilter\n");
    if (!pCoRegisterActivationFilter)
        return;

    /* the filter must not raise, is held by the process, and a COM thread is not needed */
    hr = pCoRegisterActivationFilter((IUnknown *)&filter);
    ok(hr == S_OK, "hr = %#lx\n", hr);
    ok(filter.ref >= 2, "ref = %ld\n", filter.ref);

    /* ole32 forwards to combase */
    {
        HMODULE combase = LoadLibraryW(L"combase.dll");

        ok(combase && GetProcAddress(combase, "CoRegisterActivationFilter") != NULL,
           "combase does not export CoRegisterActivationFilter\n");
    }
}
