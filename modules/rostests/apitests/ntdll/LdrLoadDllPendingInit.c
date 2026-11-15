/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A module that is mapped but whose DllMain has not run yet, reached from an earlier DllMain
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * ntdll_loadinit_p imports ntdll_loadinit_a and then ntdll_loadinit_b, and B imports ntdll_loadinit_c, so loading P
 * maps all of them and runs the DllMains in the order A, C, B, P. A's DllMain reaches B while B and C are mapped
 * but not yet initialized (what Office's c2r64.dll does with rpcrt4 and the C runtime from its DllMain at process
 * start). The expected event orders are the ones Windows 10 22H2 (19045, x64) gives with the same DLL layout:
 * - LoadLibrary(B) runs C's and B's DllMains before it returns;
 * - GetProcAddress(B) does too;
 * - LoadLibrary(N), a new module that imports B, runs C's and B's DllMains before N's;
 * - B's DllMain failing there fails A's LoadLibrary(B) with ERROR_DLL_INIT_FAILED and then LoadLibrary(P) too,
 *   without P's DllMain, and nothing stays loaded.
 */

#include "precomp.h"

#define LOADINIT_LOG_VAR "NTDLL_LOADINIT_LOG"

static const WCHAR *Modules[] =
{
    L"ntdll_loadinit_a.dll", L"ntdll_loadinit_b.dll", L"ntdll_loadinit_c.dll", L"ntdll_loadinit_n.dll",
    L"ntdll_loadinit_p.dll"
};

static BOOL AnyLoaded(VOID)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Modules); i++)
    {
        if (GetModuleHandleW(Modules[i])) return TRUE;
    }
    return FALSE;
}

static void TestScenario(const char *Mode, BOOL BFail, BOOL ExpectLoad, const char *Expected)
{
    char Log[1024];
    HMODULE hP;
    DWORD Error;

    if (AnyLoaded())
    {
        skip("%s: a helper DLL is still loaded from an earlier scenario\n", Mode);
        return;
    }

    SetEnvironmentVariableA(LOADINIT_LOG_VAR, NULL);
    SetEnvironmentVariableA("NTDLL_LOADINIT_MODE", Mode);
    SetEnvironmentVariableA("NTDLL_LOADINIT_BFAIL", BFail ? "1" : "0");

    SetLastError(0xdeadbeef);
    hP = LoadLibraryW(L"ntdll_loadinit_p.dll");
    Error = GetLastError();

    Log[0] = 0;
    GetEnvironmentVariableA(LOADINIT_LOG_VAR, Log, sizeof(Log));

    if (ExpectLoad)
    {
        ok(hP != NULL, "%s: LoadLibrary(P) failed with %lu\n", Mode, Error);
    }
    else
    {
        ok(hP == NULL, "%s: LoadLibrary(P) succeeded\n", Mode);
        ok(Error == ERROR_DLL_INIT_FAILED, "%s: error %lu, expected ERROR_DLL_INIT_FAILED\n", Mode, Error);
    }
    ok(!strcmp(Log, Expected), "%s%s: events '%s', expected '%s'\n", Mode, BFail ? " (B fails)" : "", Log, Expected);

    if (hP) FreeLibrary(hP);
    ok(!AnyLoaded(), "%s: a helper DLL is still loaded\n", Mode);

    SetEnvironmentVariableA(LOADINIT_LOG_VAR, NULL);
    SetEnvironmentVariableA("NTDLL_LOADINIT_MODE", NULL);
    SetEnvironmentVariableA("NTDLL_LOADINIT_BFAIL", NULL);
}

START_TEST(LdrLoadDllPendingInit)
{
    HMODULE hP;

    /* The helper DLLs are there, and the layout gives the init order the test needs */
    SetEnvironmentVariableA(LOADINIT_LOG_VAR, NULL);
    hP = LoadLibraryW(L"ntdll_loadinit_p.dll");
    if (!hP)
    {
        skip("ntdll_loadinit_p.dll is missing or does not load (error %lu)\n", GetLastError());
        return;
    }
    FreeLibrary(hP);

    TestScenario("none", FALSE, TRUE, "A+ A:ret C+ B+(C=1) P+");
    TestScenario("ll", FALSE, TRUE, "A+ A:LL(B) C+ B+(C=1) A:LL(B)=ok A:ret P+");
    TestScenario("gpa", FALSE, TRUE, "A+ A:GPA(B) C+ B+(C=1) A:GPA(B)=ok A:ret P+");
    TestScenario("lln", FALSE, TRUE, "A+ A:LL(N) C+ B+(C=1) N+(B=1) A:LL(N)=ok A:ret P+");
    TestScenario("none", TRUE, FALSE, "A+ A:ret C+ B+(C=1) B:FALSE");
    TestScenario("ll", TRUE, FALSE, "A+ A:LL(B) C+ B+(C=1) B:FALSE A:LL(B)=NULL,1114 A:ret");
}
