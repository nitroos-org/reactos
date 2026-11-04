/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for AppPolicyGet*, LoadPackagedLibrary, IsUserCetAvailableInEnvironment, IsEnclaveTypeSupported
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The C runtime reads the policies through GetProcAddress; a process that is not a package has the policies of a
 * classic desktop program.
 */

#include "precomp.h"

typedef LONG (WINAPI *PFN_Policy)(HANDLE, PULONG);

static const struct
{
    PCSTR Name;
    ULONG Expected;
} g_Policies[] =
{
    { "AppPolicyGetClrCompat",                      1 /* ClassicDesktop */ },
    { "AppPolicyGetCreateFileAccess",               0 /* Full */ },
    { "AppPolicyGetLifecycleManagement",            0 /* Unmanaged */ },
    { "AppPolicyGetMediaFoundationCodecLoading",    0 /* All */ },
    { "AppPolicyGetProcessTerminationMethod",       0 /* ExitProcess */ },
    { "AppPolicyGetShowDeveloperDiagnostic",        1 /* ShowUI */ },
    { "AppPolicyGetThreadInitializationType",       0 /* None */ },
    { "AppPolicyGetWindowingModel",                 2 /* ClassicDesktop */ },
};

START_TEST(AppPolicy)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE Kernelbase = LoadLibraryW(L"kernelbase.dll");
    HMODULE (WINAPI *pLoadPackagedLibrary)(LPCWSTR, DWORD);
    BOOL (WINAPI *pIsUserCet)(DWORD);
    BOOL (WINAPI *pIsEnclave)(DWORD);
    HANDLE Token = NULL;
    ULONG i, Policy;
    LONG Ret;
    HMODULE Module;
    BOOL Result;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token), "OpenProcessToken failed with %lu\n", GetLastError());

    for (i = 0; i < ARRAYSIZE(g_Policies); i++)
    {
        PFN_Policy pPolicy = (PFN_Policy)GetProcAddress(Kernel32, g_Policies[i].Name);
        PFN_Policy pPolicyBase = Kernelbase ? (PFN_Policy)GetProcAddress(Kernelbase, g_Policies[i].Name) : NULL;

        if (!pPolicy)
        {
            ok(!is_reactos(), "%s is not exported by kernel32\n", g_Policies[i].Name);
            skip("%s is not available\n", g_Policies[i].Name);
            continue;
        }

        ok(pPolicyBase != NULL, "%s is not exported by kernelbase\n", g_Policies[i].Name);

        Policy = 0xdeadbeef;
        Ret = pPolicy(Token, &Policy);
        ok(Ret == ERROR_SUCCESS, "%s: returned %ld\n", g_Policies[i].Name, Ret);
        ok(Policy == g_Policies[i].Expected, "%s: policy %lu, expected %lu\n", g_Policies[i].Name, Policy, g_Policies[i].Expected);

        /* the pseudo handle of the effective token of the thread, which the C runtime passes */
        Policy = 0xdeadbeef;
        Ret = pPolicy((HANDLE)(LONG_PTR)-6, &Policy);
        ok(Ret == ERROR_SUCCESS, "%s: pseudo token returned %ld\n", g_Policies[i].Name, Ret);
        ok(Policy == g_Policies[i].Expected, "%s: pseudo token policy %lu\n", g_Policies[i].Name, Policy);
    }

    pLoadPackagedLibrary = (void *)GetProcAddress(Kernel32, "LoadPackagedLibrary");
    if (pLoadPackagedLibrary)
    {
        SetLastError(0xdeadbeef);
        Module = pLoadPackagedLibrary(L"kernel32.dll", 1);
        ok(Module == NULL && GetLastError() == ERROR_INVALID_PARAMETER, "reserved != 0: %p, error %lu\n", Module, GetLastError());

        /* no package to load from */
        SetLastError(0xdeadbeef);
        Module = pLoadPackagedLibrary(L"kernel32.dll", 0);
        ok(Module == NULL, "LoadPackagedLibrary succeeded: %p\n", Module);
        ok(GetLastError() == 15700 /* APPMODEL_ERROR_NO_PACKAGE */, "error %lu\n", GetLastError());
        if (Module)
            FreeLibrary(Module);
    }
    else
    {
        ok(!is_reactos(), "LoadPackagedLibrary is not exported\n");
        skip("LoadPackagedLibrary is not available\n");
    }

    pIsUserCet = (void *)GetProcAddress(Kernel32, "IsUserCetAvailableInEnvironment");
    if (pIsUserCet)
    {
        /* USER_CET_ENVIRONMENT_WIN32_PROCESS is 0; the answer depends on the hardware on Windows */
        Result = pIsUserCet(0);
        if (is_reactos())
            ok(Result == FALSE, "CET is available\n");
    }
    else
    {
        ok(!is_reactos(), "IsUserCetAvailableInEnvironment is not exported\n");
        skip("IsUserCetAvailableInEnvironment is not available\n");
    }

    pIsEnclave = (void *)GetProcAddress(Kernel32, "IsEnclaveTypeSupported");
    if (pIsEnclave)
    {
        /* ENCLAVE_TYPE_SGX, SGX2, VBS and VBS_BASIC: not on this system; an unknown type is an invalid parameter */
        if (is_reactos())
        {
            ULONG Types[] = { 1, 2, 0x10, 0x11 };

            for (i = 0; i < ARRAYSIZE(Types); i++)
            {
                SetLastError(0xdeadbeef);
                Result = pIsEnclave(Types[i]);
                ok(!Result && GetLastError() == ERROR_NOT_SUPPORTED, "type %lx: %d, error %lu\n", Types[i], Result, GetLastError());
            }
        }

        SetLastError(0xdeadbeef);
        Result = pIsEnclave(0x12345678);
        ok(!Result && GetLastError() == ERROR_INVALID_PARAMETER, "unknown type: %d, error %lu\n", Result, GetLastError());
    }
    else
    {
        ok(!is_reactos(), "IsEnclaveTypeSupported is not exported\n");
        skip("IsEnclaveTypeSupported is not available\n");
    }

    if (Token)
        CloseHandle(Token);
}
