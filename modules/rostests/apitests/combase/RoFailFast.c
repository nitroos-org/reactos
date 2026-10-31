/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for RoRevokeActivationFactories and RoFailFastWithErrorContext
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86): VS Code imports both from combase.dll.
 */

#include <apitest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windef.h>
#include <winbase.h>

#define STATUS_FAIL_FAST_EXCEPTION_CODE 0xC0000602

typedef void (WINAPI *RoRevokeActivationFactories_t)(void *);
typedef void (WINAPI *RoFailFastWithErrorContext_t)(HRESULT);

static void test_revoke(HMODULE module)
{
    RoRevokeActivationFactories_t pRoRevokeActivationFactories =
        (RoRevokeActivationFactories_t)GetProcAddress(module, "RoRevokeActivationFactories");

    ok(pRoRevokeActivationFactories != NULL, "RoRevokeActivationFactories is not exported\n");
    if (!pRoRevokeActivationFactories)
        return;

    /* it returns nothing and does not look at a cookie that is not one */
    pRoRevokeActivationFactories(NULL);
    pRoRevokeActivationFactories((void *)(ULONG_PTR)0x1234);
    pRoRevokeActivationFactories((void *)(ULONG_PTR)0x1234);
}

static void test_fail_fast(HMODULE module)
{
    RoFailFastWithErrorContext_t pRoFailFastWithErrorContext =
        (RoFailFastWithErrorContext_t)GetProcAddress(module, "RoFailFastWithErrorContext");
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char path[MAX_PATH], command[MAX_PATH + 32];
    DWORD code = 0;

    ok(pRoFailFastWithErrorContext != NULL, "RoFailFastWithErrorContext is not exported\n");
    if (!pRoFailFastWithErrorContext)
        return;

    /* the process ends with the code of a fail fast exception, no handler runs and nothing after the call */
    GetModuleFileNameA(NULL, path, sizeof(path));
    sprintf(command, "\"%s\" RoFailFast", path);
    SetEnvironmentVariableA("COMBASE_APITEST_FAILFAST_CHILD", "1");
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        skip("cannot start the child process: %lu\n", GetLastError());
        return;
    }
    ok(WaitForSingleObject(pi.hProcess, 60000) == WAIT_OBJECT_0, "the child did not end\n");
    GetExitCodeProcess(pi.hProcess, &code);
    ok(code == STATUS_FAIL_FAST_EXCEPTION_CODE, "exit code %lx\n", code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    SetEnvironmentVariableA("COMBASE_APITEST_FAILFAST_CHILD", NULL);
}

static LONG WINAPI unhandled_filter(EXCEPTION_POINTERS *info)
{
    /* a fail fast does not run the filter of the process */
    ExitProcess(0x77);
    return EXCEPTION_EXECUTE_HANDLER;
}

START_TEST(RoFailFast)
{
    HMODULE module = LoadLibraryA("combase.dll");
    if (!module)
    {
        skip("combase.dll is not available\n");
        return;
    }

    if (GetEnvironmentVariableA("COMBASE_APITEST_FAILFAST_CHILD", NULL, 0))
    {
        RoFailFastWithErrorContext_t pRoFailFastWithErrorContext =
            (RoFailFastWithErrorContext_t)GetProcAddress(module, "RoFailFastWithErrorContext");

        SetUnhandledExceptionFilter(unhandled_filter);
        pRoFailFastWithErrorContext(E_FAIL);
        ExitProcess(0x66);
    }

    test_revoke(module);
    test_fail_fast(module);
    FreeLibrary(module);
}
