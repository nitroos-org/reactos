/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for std::_Throw_Cpp_error of msvcp140
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 with the Visual C++ redistributable (x64 and x86): the thread and mutex classes
 * throw a std::system_error of the generic category for the codes 0 to 6. Firefox and LibreOffice import it.
 */

#include <apitest.h>
#include <string.h>
#include <windef.h>
#include <winbase.h>
#include <pseh/pseh2.h>

#define CXX_EXCEPTION 0xE06D7363

static EXCEPTION_RECORD g_record;
static char g_what[128];
static int g_value;

static int capture(EXCEPTION_POINTERS *info)
{
    const char **what;
    const char *object;

    g_record = *info->ExceptionRecord;
    g_what[0] = 0;
    g_value = -1;
    if (g_record.ExceptionCode == CXX_EXCEPTION && g_record.NumberParameters >= 3)
    {
        /* the object: the vtable, the what string and the flag of the exception, then the error code */
        object = (const char *)g_record.ExceptionInformation[1];
        what = (const char **)(object + sizeof(void *));
        if (*what)
            strncpy(g_what, *what, sizeof(g_what) - 1);
        g_value = *(const int *)(object + 3 * sizeof(void *));
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

START_TEST(Msvcp140ThrowCppError)
{
    static const struct { int value; const char *what; } codes[] =
    {
        { 16, "device or resource busy: device or resource busy" },
        { 22, "invalid argument: invalid argument" },
        { 3, "no such process: no such process" },
        { 12, "not enough memory: not enough memory" },
        { 1, "operation not permitted: operation not permitted" },
        { 36, "resource deadlock would occur: resource deadlock would occur" },
        { 11, "resource unavailable try again: resource unavailable try again" },
    };
    HMODULE module = LoadLibraryA("msvcp140.dll");
    void (__cdecl *throw_error)(int);
    int i;

    if (!module)
    {
        skip("msvcp140.dll is not available\n");
        return;
    }
    throw_error = (void *)GetProcAddress(module, "?_Throw_Cpp_error@std@@YAXH@Z");
    ok(throw_error != NULL, "_Throw_Cpp_error is not exported\n");
    if (!throw_error)
        return;

    for (i = 0; i < ARRAYSIZE(codes); i++)
    {
        memset(&g_record, 0, sizeof(g_record));
        _SEH2_TRY
        {
            throw_error(i);
            ok(0, "%d: returned\n", i);
        }
        _SEH2_EXCEPT(capture(_SEH2_GetExceptionInformation()))
        {
        }
        _SEH2_END;

        ok(g_record.ExceptionCode == CXX_EXCEPTION, "%d: exception %lx\n", i, g_record.ExceptionCode);
        ok(g_record.ExceptionInformation[0] == 0x19930520, "%d: magic %Ix\n", i, g_record.ExceptionInformation[0]);
        ok(!strcmp(g_what, codes[i].what), "%d: what() is '%s', expected '%s'\n", i, g_what, codes[i].what);
        ok(g_value == codes[i].value, "%d: error code %d, expected %d\n", i, g_value, codes[i].value);
    }
    FreeLibrary(module);
}
