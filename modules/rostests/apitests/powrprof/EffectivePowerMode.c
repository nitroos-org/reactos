/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for PowerRegisterForEffectivePowerModeNotifications and
 *              PowerUnregisterFromEffectivePowerModeNotifications (msedge.dll delay-loads them)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>

typedef VOID (CALLBACK *FN_Callback)(ULONG, VOID *);
typedef HRESULT (WINAPI *FN_Register)(ULONG, FN_Callback, VOID *, VOID **);
typedef HRESULT (WINAPI *FN_Unregister)(VOID *);

static VOID CALLBACK TestCallback(ULONG Mode, VOID *Context)
{
}

START_TEST(EffectivePowerMode)
{
    HMODULE hPowrprof = LoadLibraryW(L"powrprof.dll");
    FN_Register pRegister;
    FN_Unregister pUnregister;
    VOID *Handle;
    HRESULT hr;

    ok(hPowrprof != NULL, "no powrprof.dll\n");
    if (!hPowrprof)
        return;
    pRegister = (FN_Register)GetProcAddress(hPowrprof, "PowerRegisterForEffectivePowerModeNotifications");
    pUnregister = (FN_Unregister)GetProcAddress(hPowrprof, "PowerUnregisterFromEffectivePowerModeNotifications");
    ok(pRegister && pUnregister, "effective power mode functions not exported: %p %p\n", pRegister, pUnregister);
    if (!pRegister || !pUnregister)
        return;

    Handle = NULL;
    hr = pRegister(1, TestCallback, NULL, &Handle);
    ok(hr == S_OK, "register v1: 0x%08lx\n", hr);
    ok(Handle != NULL, "no registration handle\n");
    if (hr == S_OK && Handle)
    {
        hr = pUnregister(Handle);
        ok(hr == S_OK, "unregister: 0x%08lx\n", hr);
    }

    Handle = NULL;
    hr = pRegister(2, TestCallback, (VOID *)(ULONG_PTR)0x1234, &Handle);
    ok(hr == S_OK && Handle, "register v2: 0x%08lx, %p\n", hr, Handle);
    if (hr == S_OK && Handle)
        pUnregister(Handle);

    Handle = (VOID *)(ULONG_PTR)0x5678;
    hr = pRegister(0, TestCallback, NULL, &Handle);
    ok(hr == E_INVALIDARG, "register with a bad version: 0x%08lx\n", hr);
    hr = pRegister(1, NULL, NULL, &Handle);
    ok(hr == E_INVALIDARG, "register with a NULL callback: 0x%08lx\n", hr);
    hr = pRegister(1, TestCallback, NULL, NULL);
    ok(hr == E_INVALIDARG, "register with a NULL handle pointer: 0x%08lx\n", hr);
}
