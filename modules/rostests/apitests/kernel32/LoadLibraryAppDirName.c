/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A library named like a system library that is not a known DLL is taken from the application directory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 with two copies of a test library named dbghelp.dll (not a known DLL there) and
 * imagehlp.dll (a known DLL), in the directory of a 32-bit and of a 64-bit program: LoadLibrary by the bare name and
 * the import table of the program give the copy in the application directory for dbghelp.dll, and the system copy
 * for imagehlp.dll; the full path of the application directory copy loads that file as a module of its own. Only the
 * non-known name is tested here, with a copy of this test's own helper library.
 */

#include "precomp.h"

/* A known DLL (imagehlp.dll) is taken from the system directory of the program's bitness, also when a file of that
 * name is in the application directory: for a 32-bit program that is \KnownDlls32 (Windows Server 2022 has it, 43
 * sections; a 32-bit program with its own imagehlp.dll gets SysWOW64's, measured). */
static void TestKnownDllName(void)
{
    WCHAR AppDir[MAX_PATH], Source[MAX_PATH], Copy[MAX_PATH], Path[MAX_PATH], System[MAX_PATH];
    HMODULE Lib;
    PWCHAR Slash;

    if (GetModuleHandleW(L"imagehlp.dll"))
    {
        skip("imagehlp.dll is loaded in the test process already\n");
        return;
    }

    GetModuleFileNameW(NULL, AppDir, _countof(AppDir));
    Slash = wcsrchr(AppDir, L'\\');
    *Slash = 0;
    _snwprintf(Source, MAX_PATH, L"%ls\\ll_search_dep.dll", AppDir);
    _snwprintf(Copy, MAX_PATH, L"%ls\\imagehlp.dll", AppDir);
    if (!CopyFileW(Source, Copy, FALSE))
    {
        skip("cannot write %ls: %lu\n", Copy, GetLastError());
        return;
    }

    Lib = LoadLibraryW(L"imagehlp.dll");
    ok(Lib != NULL, "LoadLibrary(imagehlp.dll) failed: %lu\n", GetLastError());
    if (Lib)
    {
        /* the directory of the system files of this program's bitness: SysWOW64 for a 32-bit program on a 64-bit
         * system (GetSystemDirectory is not asked: it names System32 there on NitroOS, another difference) */
        {
            BOOL Wow64 = FALSE;

            IsWow64Process(GetCurrentProcess(), &Wow64);
            if (!Wow64 || !GetSystemWow64DirectoryW(System, _countof(System)))
                GetSystemDirectoryW(System, _countof(System));
        }
        wcscat(System, L"\\imagehlp.dll");
        ok(GetModuleFileNameW(Lib, Path, _countof(Path)) != 0, "GetModuleFileName failed\n");
        ok(!_wcsicmp(Path, System), "LoadLibrary(imagehlp.dll) loaded \"%ls\", expected \"%ls\"\n", Path, System);
        FreeLibrary(Lib);
    }
    DeleteFileW(Copy);
}

START_TEST(LoadLibraryAppDirName)
{
    WCHAR AppDir[MAX_PATH], Source[MAX_PATH], Copy[MAX_PATH], Path[MAX_PATH];
    HMODULE Lib;
    PWCHAR Slash;

    TestKnownDllName();

    if (GetModuleHandleW(L"dbghelp.dll"))
    {
        skip("dbghelp.dll is loaded in the test process already\n");
        return;
    }

    GetModuleFileNameW(NULL, AppDir, _countof(AppDir));
    Slash = wcsrchr(AppDir, L'\\');
    *Slash = 0;
    _snwprintf(Source, MAX_PATH, L"%ls\\ll_search_dep.dll", AppDir);
    _snwprintf(Copy, MAX_PATH, L"%ls\\dbghelp.dll", AppDir);
    if (!CopyFileW(Source, Copy, FALSE))
    {
        skip("cannot write %ls: %lu\n", Copy, GetLastError());
        return;
    }

    Lib = LoadLibraryW(L"dbghelp.dll");
    ok(Lib != NULL, "LoadLibrary(dbghelp.dll) failed: %lu\n", GetLastError());
    if (Lib)
    {
        ok(GetModuleFileNameW(Lib, Path, _countof(Path)) != 0, "GetModuleFileName failed\n");
        ok(!_wcsicmp(Path, Copy), "LoadLibrary(dbghelp.dll) loaded \"%ls\", expected \"%ls\"\n", Path, Copy);

        /* imagehlp.dll (a known DLL) keeps working beside it: its symbol functions are not the program's copy's */
        {
            typedef DWORD (WINAPI *FN_SymGetOptions)(void);
            WCHAR System[MAX_PATH];
            UINT OldMode = SetErrorMode(SEM_FAILCRITICALERRORS);
            HMODULE Imagehlp = LoadLibraryW(L"imagehlp.dll");
            FN_SymGetOptions pSymGetOptions;

            SetErrorMode(OldMode);
            ok(Imagehlp != NULL, "LoadLibrary(imagehlp.dll) failed: %lu\n", GetLastError());
            if (Imagehlp)
            {
                pSymGetOptions = (FN_SymGetOptions)GetProcAddress(Imagehlp, "SymGetOptions");
                ok(pSymGetOptions != NULL, "imagehlp has no SymGetOptions\n");
                if (pSymGetOptions)
                    pSymGetOptions();
                GetSystemDirectoryW(System, _countof(System));
                wcscat(System, L"\\dbghelp.dll");
                trace("system dbghelp.dll loaded: %d\n", GetModuleHandleW(System) != NULL);
                FreeLibrary(Imagehlp);
            }
        }
        FreeLibrary(Lib);
    }
    DeleteFileW(Copy);
}
