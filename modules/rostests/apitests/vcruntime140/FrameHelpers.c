/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the helper exports of vcruntime140 that programs import: __FrameUnwindFilter,
 *              __C_specific_handler_noexcept, __vcrt_GetModuleFileNameW, __vcrt_GetModuleHandleW and
 *              __vcrt_LoadLibraryExW
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The values were measured on Windows 10 22H2 with the Visual C++ redistributable (x64 and x86). LibreOffice
 * imports __FrameUnwindFilter, the JDK the others.
 */

#include <apitest.h>
#include <stdio.h>
#include <string.h>
#include <windef.h>
#include <winbase.h>

#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x800
#endif

#define CLR_EXCEPTION_CODE      0xE0434352
#define CLR_EXCEPTION_CODE_V4   0xE0434F4D

typedef int (__cdecl *FrameUnwindFilter_t)(EXCEPTION_POINTERS *);
typedef int *(__cdecl *processing_throw_t)(void);
typedef DWORD (__cdecl *GetModuleFileNameW_t)(HMODULE, WCHAR *, DWORD);
typedef HMODULE (__cdecl *GetModuleHandleW_t)(const WCHAR *);
typedef HMODULE (__cdecl *LoadLibraryExW_t)(const WCHAR *, HANDLE, DWORD);

static void test_frame_unwind_filter(HMODULE module)
{
    FrameUnwindFilter_t filter = (void *)GetProcAddress(module, "__FrameUnwindFilter");
    processing_throw_t processing = (void *)GetProcAddress(module, "__processing_throw");
    static const struct { DWORD code; int decrements; } codes[] =
    {
        { 0xC0000005, 0 },
        { 0xC00000FD, 0 },
        { 0x80000003, 0 },
        { CLR_EXCEPTION_CODE, 1 },
        { CLR_EXCEPTION_CODE_V4, 1 },
    };
    EXCEPTION_RECORD record;
    EXCEPTION_POINTERS pointers;
    int *count, ret;
    size_t i;

    ok(filter != NULL, "__FrameUnwindFilter is not exported\n");
    ok(processing != NULL, "__processing_throw is not exported\n");
    if (!filter || !processing)
        return;

    count = processing();
    *count = 0;
    memset(&record, 0, sizeof(record));
    pointers.ExceptionRecord = &record;
    pointers.ContextRecord = NULL;

    for (i = 0; i < ARRAYSIZE(codes); i++)
    {
        /* nothing is handled by the filter: the search goes on; the managed exceptions end a throw */
        record.ExceptionCode = codes[i].code;
        *count = 3;
        ret = filter(&pointers);
        ok(ret == EXCEPTION_CONTINUE_SEARCH, "%lx: returned %d\n", codes[i].code, ret);
        ok(*count == 3 - codes[i].decrements, "%lx: the count of throws is %d\n", codes[i].code, *count);

        /* the count does not go below zero */
        *count = 0;
        filter(&pointers);
        ok(*count == 0, "%lx: the count of throws is %d\n", codes[i].code, *count);
    }
    *count = 0;
}

static void test_noexcept_handler(HMODULE module)
{
#ifdef _WIN64
    typedef EXCEPTION_DISPOSITION (__cdecl *handler_t)(EXCEPTION_RECORD *, ULONG64, CONTEXT *, DISPATCHER_CONTEXT *);
    handler_t handler = (void *)GetProcAddress(module, "__C_specific_handler_noexcept");
    EXCEPTION_RECORD record;
    DISPATCHER_CONTEXT dispatch;
    CONTEXT context;
    ULONG scope_table[1] = { 0 };   /* no scopes: the handler finds nothing */
    RUNTIME_FUNCTION function;
    EXCEPTION_DISPOSITION ret;

    ok(handler != NULL, "__C_specific_handler_noexcept is not exported\n");
    if (!handler)
        return;

    memset(&record, 0, sizeof(record));
    memset(&dispatch, 0, sizeof(dispatch));
    memset(&context, 0, sizeof(context));
    memset(&function, 0, sizeof(function));
    dispatch.ImageBase = (ULONG_PTR)module;
    dispatch.ControlPc = (ULONG_PTR)module + 0x1000;
    dispatch.FunctionEntry = &function;
    dispatch.HandlerData = scope_table;
    dispatch.ContextRecord = &context;

    /* an exception that is not a C++ one is the business of __C_specific_handler: it has no scope here */
    record.ExceptionCode = 0xC0000005;
    ret = handler(&record, 0, &context, &dispatch);
    ok(ret == ExceptionContinueSearch, "access violation: returned %d\n", ret);

    /* a C++ exception that is unwinding is left alone (the handler would end the process while it searches) */
    record.ExceptionCode = 0xE06D7363;
    record.ExceptionFlags = EXCEPTION_UNWINDING;
    ret = handler(&record, 0, &context, &dispatch);
    ok(ret == ExceptionContinueSearch, "C++ exception unwinding: returned %d\n", ret);
#else
    ok(GetProcAddress(module, "__C_specific_handler_noexcept") == NULL, "exported on i386\n");
#endif
}

static void test_wrappers(HMODULE module)
{
    GetModuleFileNameW_t get_file_name = (void *)GetProcAddress(module, "__vcrt_GetModuleFileNameW");
    GetModuleHandleW_t get_handle = (void *)GetProcAddress(module, "__vcrt_GetModuleHandleW");
    LoadLibraryExW_t load_library = (void *)GetProcAddress(module, "__vcrt_LoadLibraryExW");
    WCHAR name[MAX_PATH], expected[MAX_PATH];
    HMODULE ret;
    DWORD len, expected_len;

    ok(get_file_name != NULL, "__vcrt_GetModuleFileNameW is not exported\n");
    ok(get_handle != NULL, "__vcrt_GetModuleHandleW is not exported\n");
    ok(load_library != NULL, "__vcrt_LoadLibraryExW is not exported\n");
    if (!get_file_name || !get_handle || !load_library)
        return;

    expected_len = GetModuleFileNameW(NULL, expected, ARRAYSIZE(expected));
    len = get_file_name(NULL, name, ARRAYSIZE(name));
    ok(len == expected_len && !wcscmp(name, expected), "file name %lu %S, expected %lu %S\n", len, name, expected_len, expected);

    /* a buffer that is too small gets the truncated name (what GetModuleFileNameW does) */
    len = get_file_name(module, name, 8);
    ok(len == 8, "length %lu\n", len);

    ok(get_handle(L"kernel32.dll") == GetModuleHandleW(L"kernel32.dll"), "handle of kernel32 differs\n");
    ok(get_handle(L"nonexistent_vcrt_probe.dll") == NULL, "handle of an unloaded module\n");

    SetLastError(0xdeadbeef);
    ret = load_library(L"nonexistent_vcrt_probe.dll", NULL, 0);
    ok(ret == NULL, "loaded %p\n", ret);
    ok(GetLastError() == ERROR_MOD_NOT_FOUND, "error %lu\n", GetLastError());

    ret = load_library(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    ok(ret != NULL, "version.dll not loaded: %lu\n", GetLastError());
    if (ret)
        FreeLibrary(ret);
}

#ifndef PF_FASTFAIL_AVAILABLE
#define PF_FASTFAIL_AVAILABLE 23
#endif
#define EH_EXCEPTION_NUMBER     0xE06D7363
#ifndef STATUS_STACK_BUFFER_OVERRUN
#define STATUS_STACK_BUFFER_OVERRUN 0xC0000409
#endif

/* A C++ exception that reaches __FrameUnwindFilter, and abort(), end the process through terminate: the process
 * is gone at once with STATUS_STACK_BUFFER_OVERRUN (__fastfail), on x86 as on x64. The crash handler must not
 * be involved: an unattended machine used to hang in it on i386, where the fast fail was not available. */
static void child_run(const char *mode)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (!strcmp(mode, "abort"))
    {
        void (__cdecl *abort_fn)(void) = (void *)GetProcAddress(LoadLibraryA("ucrtbase.dll"), "abort");

        if (abort_fn)
            abort_fn();
    }
    else
    {
        HMODULE module = LoadLibraryA("vcruntime140.dll");
        FrameUnwindFilter_t filter = (void *)GetProcAddress(module, "__FrameUnwindFilter");
        processing_throw_t processing = (void *)GetProcAddress(module, "__processing_throw");
        EXCEPTION_RECORD record;
        EXCEPTION_POINTERS pointers;
        CONTEXT context;

        if (filter && processing)
        {
            *processing() = 3;
            memset(&record, 0, sizeof(record));
            memset(&context, 0, sizeof(context));
            record.ExceptionCode = EH_EXCEPTION_NUMBER;
            pointers.ExceptionRecord = &record;
            pointers.ContextRecord = &context;
            filter(&pointers);
        }
    }
    ExitProcess(0x7E57DEAD);   /* the process was not ended */
}

static void test_terminate_child(const char *exe, const char *mode)
{
    char command[MAX_PATH + 64];
    STARTUPINFOA startup;
    PROCESS_INFORMATION info;
    DWORD wait, code = 0;

    sprintf(command, "\"%s\" FrameHelpers %s", exe, mode);
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &info))
    {
        skip("CreateProcess failed: %lu\n", GetLastError());
        return;
    }
    wait = WaitForSingleObject(info.hProcess, 60000);
    ok(wait == WAIT_OBJECT_0, "%s: the child did not end (%lu)\n", mode, wait);
    if (wait != WAIT_OBJECT_0)
        TerminateProcess(info.hProcess, 0);
    else
    {
        GetExitCodeProcess(info.hProcess, &code);
        ok(code == STATUS_STACK_BUFFER_OVERRUN, "%s: exit code %08lx\n", mode, code);
    }
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
}

START_TEST(FrameHelpers)
{
    HMODULE module;
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        child_run(argv[3]);
        return;
    }

    ok(IsProcessorFeaturePresent(PF_FASTFAIL_AVAILABLE), "fast fail is not available\n");
    test_terminate_child(argv[0], "child filter");
    test_terminate_child(argv[0], "child abort");

    module = LoadLibraryA("vcruntime140.dll");

    if (!module)
    {
        skip("vcruntime140.dll is not available\n");
        return;
    }

    test_frame_unwind_filter(module);
    test_noexcept_handler(module);
    test_wrappers(module);
    FreeLibrary(module);
}
