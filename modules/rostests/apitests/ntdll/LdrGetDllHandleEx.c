/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.0-or-later (https://spdx.org/licenses/LGPL-2.0-or-later)
 * PURPOSE:     GetModuleHandle / LdrGetDllHandleEx: a full path of a loaded module is answered from the loaded
 *              list, without file system access
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The no-I/O check renames the DLL file while it is mapped: the loader list still holds the old path, which no
 * longer exists on disk, so only a lookup that does not probe the file system can still find the module.
 */

#include "precomp.h"

#include <winuser.h>

#define EMPTY_DLL_ID 102

static BOOL ExtractDll(PCWSTR Path)
{
    HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(EMPTY_DLL_ID), (PCWSTR)RT_RCDATA);
    HGLOBAL hGlobal = hRsrc ? LoadResource(NULL, hRsrc) : NULL;
    PVOID Data = hGlobal ? LockResource(hGlobal) : NULL;
    DWORD Size = hRsrc ? SizeofResource(NULL, hRsrc) : 0, Written = 0;
    HANDLE hFile;
    BOOL Ret;

    if (!Data)
        return FALSE;
    hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    Ret = WriteFile(hFile, Data, Size, &Written, NULL) && Written == Size;
    CloseHandle(hFile);
    return Ret;
}

static NTSTATUS NtHandle(PCWSTR Name, PVOID *Handle)
{
    UNICODE_STRING Us;

    RtlInitUnicodeString(&Us, Name);
    *Handle = (PVOID)(ULONG_PTR)0xdeadbeef;
    return LdrGetDllHandleEx(LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT, NULL, NULL, &Us, Handle);
}

/* Both entry points must agree */
static void ExpectFound(const char *What, PCWSTR Name, HMODULE Expected, int Line)
{
    HMODULE Mod;
    PVOID Handle;
    NTSTATUS Status;

    SetLastError(0xdeadbeef);
    Mod = GetModuleHandleW(Name);
    ok_(__FILE__, Line)(Mod == Expected, "%s: GetModuleHandleW(%ls) = %p, expected %p (error %lu)\n",
                        What, Name, Mod, Expected, GetLastError());
    Status = NtHandle(Name, &Handle);
    ok_(__FILE__, Line)(Status == STATUS_SUCCESS && Handle == Expected,
                        "%s: LdrGetDllHandleEx(%ls) = 0x%lx, %p, expected %p\n", What, Name, Status, Handle, Expected);
}

static void ExpectNotFound(const char *What, PCWSTR Name, int Line)
{
    HMODULE Mod;
    PVOID Handle;
    NTSTATUS Status;

    SetLastError(0xdeadbeef);
    Mod = GetModuleHandleW(Name);
    ok_(__FILE__, Line)(Mod == NULL && GetLastError() == ERROR_MOD_NOT_FOUND,
                        "%s: GetModuleHandleW(%ls) = %p, error %lu\n", What, Name, Mod, GetLastError());
    Status = NtHandle(Name, &Handle);
    ok_(__FILE__, Line)(Status == STATUS_DLL_NOT_FOUND && Handle == NULL,
                        "%s: LdrGetDllHandleEx(%ls) = 0x%lx, %p\n", What, Name, Status, Handle);
}

#define EXPECT_FOUND(w, n, e)  ExpectFound(w, n, e, __LINE__)
#define EXPECT_NOTFOUND(w, n)  ExpectNotFound(w, n, __LINE__)

static void TestSystemModules(void)
{
    WCHAR Path[MAX_PATH], Upper[MAX_PATH];
    HMODULE Kernel32, Ntdll, KernelBase;
    FARPROC Fwd, Target;
    UINT Len;

    Kernel32 = GetModuleHandleW(L"kernel32.dll");
    Ntdll = GetModuleHandleW(L"ntdll.dll");
    ok(Kernel32 != NULL && Ntdll != NULL, "kernel32 %p ntdll %p\n", Kernel32, Ntdll);

    /* Base names */
    EXPECT_FOUND("base name", L"kernel32.dll", Kernel32);
    EXPECT_FOUND("base name, case", L"KeRnEl32.DlL", Kernel32);
    EXPECT_FOUND("no extension", L"kernel32", Kernel32);

    /* Full path of a system module */
    Len = GetSystemDirectoryW(Path, _countof(Path));
    ok(Len != 0 && Len < _countof(Path) - 16, "GetSystemDirectoryW = %u\n", Len);
    StringCchCatW(Path, _countof(Path), L"\\kernel32.dll");
    EXPECT_FOUND("full path", Path, Kernel32);

    StringCchCopyW(Upper, _countof(Upper), Path);
    _wcsupr(Upper);
    EXPECT_FOUND("full path, upper case", Upper, Kernel32);

    /* The forwarders of kernel32 resolve into ntdll through the same loaded list */
    Fwd = GetProcAddress(Kernel32, "HeapAlloc");
    Target = GetProcAddress(Ntdll, "RtlAllocateHeap");
    if (Fwd && Target)
        ok(Fwd == Target, "HeapAlloc %p does not forward to RtlAllocateHeap %p\n", Fwd, Target);

    /* API set name: answered with the host, which is loaded */
    KernelBase = GetModuleHandleW(L"kernelbase.dll");
    {
        HMODULE Api = GetModuleHandleW(L"api-ms-win-core-synch-l1-1-0.dll");
        ok(Api != NULL && (Api == Kernel32 || Api == KernelBase),
           "api-ms-win-core-synch-l1-1-0.dll = %p, kernel32 %p kernelbase %p\n", Api, Kernel32, KernelBase);
    }

    /* Not loaded */
    EXPECT_NOTFOUND("not loaded base name", L"ldrgh_no_such_module.dll");
    EXPECT_NOTFOUND("not loaded, no extension", L"ldrgh_no_such_module");
    EXPECT_NOTFOUND("missing full path", L"C:\\ldrgh_no_such_dir\\ldrgh_no_such_module.dll");
}

START_TEST(LdrGetDllHandleEx)
{
    WCHAR Dir[MAX_PATH], Path[MAX_PATH], Moved[MAX_PATH], Short[MAX_PATH], Upper[MAX_PATH];
    HMODULE hMod;
    DWORD ShortLen;
    BOOL Moved_;
    int i;

    TestSystemModules();

    if (!FindResourceW(NULL, MAKEINTRESOURCEW(EMPTY_DLL_ID), (PCWSTR)RT_RCDATA))
    {
        skip("empty_dll.dll is not embedded\n");
        return;
    }

    GetTempPathW(_countof(Dir), Dir);
    StringCchPrintfW(Path, _countof(Path), L"%sldrgh_long_module_name_%lu.dll", Dir, GetCurrentProcessId());
    StringCchPrintfW(Moved, _countof(Moved), L"%sldrgh_moved_%lu.dll", Dir, GetCurrentProcessId());
    DeleteFileW(Moved);
    if (!ExtractDll(Path))
    {
        skip("Could not write %ls\n", Path);
        return;
    }

    /* An existing file that is not loaded: not found, and the lookup must not load it */
    EXPECT_NOTFOUND("existing file, not loaded", Path);
    ok(GetModuleHandleW(Path) == NULL, "The lookup mapped the file\n");

    hMod = LoadLibraryW(Path);
    ok(hMod != NULL, "LoadLibrary(%ls) failed with %lu\n", Path, GetLastError());
    if (!hMod)
    {
        DeleteFileW(Path);
        return;
    }

    EXPECT_FOUND("loaded, full path", Path, hMod);

    StringCchCopyW(Upper, _countof(Upper), Path);
    _wcsupr(Upper);
    EXPECT_FOUND("loaded, full path upper case", Upper, hMod);

    /* The base name of a module loaded by path */
    EXPECT_FOUND("loaded, base name", wcsrchr(Path, L'\\') + 1, hMod);

    /* 8.3 name of the same file (the same string when the volume has none) */
    ShortLen = GetShortPathNameW(Path, Short, _countof(Short));
    if (ShortLen && ShortLen < _countof(Short))
        EXPECT_FOUND("loaded, short path", Short, hMod);
    else
        skip("No short path (%lu)\n", GetLastError());

    /* Repeated lookups must not take references: one FreeLibrary has to unload it */
    for (i = 0; i < 8; i++)
        ok(GetModuleHandleW(Path) == hMod, "Lookup %d failed\n", i);

    /* No file I/O: the path no longer exists on disk, the loaded list still has it */
    Moved_ = MoveFileW(Path, Moved);
    if (Moved_)
    {
        ok(GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES, "The old path still exists\n");
        EXPECT_FOUND("loaded, file renamed away", Path, hMod);
        EXPECT_FOUND("loaded, file renamed away, upper case", Upper, hMod);
        MoveFileW(Moved, Path);
    }
    else
    {
        skip("Cannot rename a mapped DLL (%lu)\n", GetLastError());
    }

    ok(FreeLibrary(hMod), "FreeLibrary failed with %lu\n", GetLastError());
    EXPECT_NOTFOUND("unloaded, full path", Path);
    DeleteFileW(Path);
    DeleteFileW(Moved);
}
