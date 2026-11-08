/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for FlsGetValue2 (kernel32, forwarded by kernelbase) and for twinapi.appcore's
 *              RegisterAppStateChangeNotification / UnregisterAppStateChangeNotification
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * FlsGetValue2 is exported by Windows 11 and later (Windows 10 22H2, measured: neither kernel32 nor kernelbase has it),
 * so what is tested is what the function is for: the value of the fiber local storage slot, without touching the last
 * error on success (FlsGetValue clears it).
 * Measured on Windows 10 22H2 (19045), x64, in a desktop process without a package:
 * RegisterAppStateChangeNotification returns S_OK and a registration that is not NULL, also with a NULL routine;
 * UnregisterAppStateChangeNotification takes it back.
 */

#include "precomp.h"

typedef PVOID (WINAPI *PFN_FlsGetValue2)(DWORD);
typedef HRESULT (WINAPI *PFN_Register)(PVOID, PVOID, PVOID *);
typedef VOID (WINAPI *PFN_Unregister)(PVOID);

static void Test_FlsGetValue2(void)
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    PFN_FlsGetValue2 pFlsGetValue2 = (PFN_FlsGetValue2)GetProcAddress(hKernel32, "FlsGetValue2");
    PFN_FlsGetValue2 pBase;
    DWORD Index;
    PVOID Value;

    if (!pFlsGetValue2)
    {
        skip("FlsGetValue2 not available\n");
        return;
    }

    /* kernelbase has it too (here as a forwarder to kernel32); load it if nothing did */
    if (!hKernelBase)
        hKernelBase = LoadLibraryW(L"kernelbase.dll");
    if (hKernelBase)
    {
        pBase = (PFN_FlsGetValue2)GetProcAddress(hKernelBase, "FlsGetValue2");
        ok(pBase != NULL, "kernelbase does not export FlsGetValue2\n");
    }

    Index = FlsAlloc(NULL);
    ok(Index != FLS_OUT_OF_INDEXES, "FlsAlloc failed %lu\n", GetLastError());
    if (Index == FLS_OUT_OF_INDEXES)
        return;

    /* the slot starts as NULL; the last error stays */
    SetLastError(0x1234);
    Value = pFlsGetValue2(Index);
    ok(Value == NULL, "Value = %p\n", Value);
    ok(GetLastError() == 0x1234, "last error %lu\n", GetLastError());

    ok(FlsSetValue(Index, (PVOID)(ULONG_PTR)0x5678), "FlsSetValue failed %lu\n", GetLastError());
    SetLastError(0x1234);
    Value = pFlsGetValue2(Index);
    ok(Value == (PVOID)(ULONG_PTR)0x5678, "Value = %p\n", Value);
    ok(GetLastError() == 0x1234, "last error %lu\n", GetLastError());

    /* the same slot through FlsGetValue: same value, and it clears the last error */
    SetLastError(0x1234);
    Value = FlsGetValue(Index);
    ok(Value == (PVOID)(ULONG_PTR)0x5678, "Value = %p\n", Value);
    ok(GetLastError() == ERROR_SUCCESS, "last error %lu\n", GetLastError());

    /* an index that cannot exist */
    SetLastError(0x1234);
    Value = pFlsGetValue2(0);
    ok(Value == NULL, "Value = %p\n", Value);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "last error %lu\n", GetLastError());
    SetLastError(0x1234);
    Value = pFlsGetValue2(FLS_OUT_OF_INDEXES);
    ok(Value == NULL, "Value = %p\n", Value);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "last error %lu\n", GetLastError());

    ok(FlsFree(Index), "FlsFree failed %lu\n", GetLastError());
}

static void Test_AppState(void)
{
    HMODULE hAppCore = LoadLibraryW(L"twinapi.appcore.dll");
    PFN_Register pRegister;
    PFN_Unregister pUnregister;
    PVOID Registration;
    HRESULT hr;

    if (!hAppCore)
    {
        skip("twinapi.appcore.dll not available\n");
        return;
    }

    pRegister = (PFN_Register)GetProcAddress(hAppCore, "RegisterAppStateChangeNotification");
    pUnregister = (PFN_Unregister)GetProcAddress(hAppCore, "UnregisterAppStateChangeNotification");
    ok(pRegister != NULL, "RegisterAppStateChangeNotification missing\n");
    ok(pUnregister != NULL, "UnregisterAppStateChangeNotification missing\n");
    if (!pRegister || !pUnregister)
    {
        FreeLibrary(hAppCore);
        return;
    }

    Registration = (PVOID)(ULONG_PTR)0x77;
    hr = pRegister((PVOID)(ULONG_PTR)Test_AppState, NULL, &Registration);
    ok(hr == S_OK, "hr = %#lx\n", hr);
    ok(Registration != NULL && Registration != (PVOID)(ULONG_PTR)0x77, "Registration = %p\n", Registration);
    pUnregister(Registration);

    Registration = (PVOID)(ULONG_PTR)0x77;
    hr = pRegister(NULL, NULL, &Registration);
    ok(hr == S_OK, "hr = %#lx\n", hr);
    ok(Registration != NULL && Registration != (PVOID)(ULONG_PTR)0x77, "Registration = %p\n", Registration);
    pUnregister(Registration);

    FreeLibrary(hAppCore);
}

START_TEST(FlsGetValue2)
{
    Test_FlsGetValue2();
    Test_AppState();
}
