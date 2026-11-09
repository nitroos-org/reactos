/*
 * PROJECT:     apphelp_apitest
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     The kernel shim cache is filled by CreateProcess for programs the database has nothing for,
 *              and a program that has to be shimmed never gets a stale "no shim" answer from it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <shlwapi.h>
#include <strsafe.h>

#include "wine/test.h"

#define CHILD_LOADED_SHIM       37
#define CHILD_NO_SHIM           38
#define CHILD_LAYER             39
#define CHILD_TIMEOUT           30000

#define LAYERS_KEY L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"

typedef struct
{
    USHORT Length, MaximumLength;
    PWSTR Buffer;
} CACHE_STRING;

typedef struct
{
    CACHE_STRING ImageName;
    HANDLE ImageHandle;
} CACHE_LOOKUP;

static NTSTATUS (NTAPI *pNtApphelpCacheControl)(ULONG, PVOID);

/* 0 = Lookup: the kernel answers STATUS_SUCCESS when it knows the file in this state */
static NTSTATUS cache_lookup(PCWSTR Path)
{
    CACHE_LOOKUP Lookup;
    WCHAR NtPath[MAX_PATH + 8];
    NTSTATUS Status;

    /* the cache knows an image by the NT path CreateProcess uses */
    StringCchPrintfW(NtPath, _countof(NtPath), L"\\??\\%ls", Path);
    Lookup.ImageName.Buffer = NtPath;
    Lookup.ImageName.Length = (USHORT)(wcslen(NtPath) * sizeof(WCHAR));
    Lookup.ImageName.MaximumLength = Lookup.ImageName.Length + sizeof(WCHAR);
    Lookup.ImageHandle = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                     NULL, OPEN_EXISTING, 0, NULL);
    ok(Lookup.ImageHandle != INVALID_HANDLE_VALUE, "CreateFile %ls failed with %lu\n", Path, GetLastError());
    if (Lookup.ImageHandle == INVALID_HANDLE_VALUE)
        return STATUS_UNSUCCESSFUL;
    Status = pNtApphelpCacheControl(0, &Lookup);
    CloseHandle(Lookup.ImageHandle);
    return Status;
}

/* A name the length of which cannot be stored with its terminator, or is odd, is refused without being copied */
static void test_bad_names(void)
{
    static const USHORT Lengths[] = { 0xFFFF, 0xFFFE, 0x8001, 0x0001, 0x0003 };
    CACHE_LOOKUP Lookup;
    PVOID Buffer;
    NTSTATUS Status;
    ULONG i, Service;

    Buffer = VirtualAlloc(NULL, 0x20000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok(Buffer != NULL, "VirtualAlloc failed with %lu\n", GetLastError());
    if (!Buffer)
        return;
    memset(Buffer, 'a', 0x20000);
    for (i = 0; i < _countof(Lengths); i++)
    {
        /* Lookup and Remove */
        for (Service = 0; Service < 2; Service++)
        {
            Lookup.ImageName.Length = Lengths[i];
            Lookup.ImageName.MaximumLength = Lengths[i];
            Lookup.ImageName.Buffer = Buffer;
            Lookup.ImageHandle = INVALID_HANDLE_VALUE;
            Status = pNtApphelpCacheControl(Service, &Lookup);
            ok(Status == STATUS_INVALID_PARAMETER, "Service %lu, length 0x%x: got %08lx\n", Service, Lengths[i], Status);
        }
    }
    VirtualFree(Buffer, 0, MEM_RELEASE);
}

static DWORD run_child(PCWSTR Exe, PCWSTR Dir, PVOID Environment)
{
    WCHAR CmdLine[MAX_PATH + 32];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD Wait, ExitCode = ~0u;
    BOOL Ret;

    ok(SUCCEEDED(StringCchPrintfW(CmdLine, _countof(CmdLine), L"\"%ls\"", Exe)), "Path too long\n");
    Ret = CreateProcessW(Exe, CmdLine, NULL, NULL, FALSE, Environment ? CREATE_UNICODE_ENVIRONMENT : 0,
                         Environment, Dir, &si, &pi);
    ok(Ret, "CreateProcess failed with %lu\n", GetLastError());
    if (!Ret)
        return ExitCode;
    Wait = WaitForSingleObject(pi.hProcess, CHILD_TIMEOUT);
    ok(Wait == WAIT_OBJECT_0, "Wait returned %lu: the program did not exit in %u ms\n", Wait, CHILD_TIMEOUT);
    if (Wait == WAIT_OBJECT_0)
        GetExitCodeProcess(pi.hProcess, &ExitCode);
    else
        TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return ExitCode;
}

static void delete_file_retry(PCWSTR Path)
{
    DWORD Try;

    for (Try = 0; Try < 50; Try++)
    {
        if (DeleteFileW(Path) || GetLastError() == ERROR_FILE_NOT_FOUND)
            return;
        Sleep(100);
    }
    ok(0, "Could not delete %ls, error %lu\n", Path, GetLastError());
}

/* The environment of this process and __COMPAT_LAYER=WIN98 */
static WCHAR *make_layer_env(void)
{
    static const WCHAR Layer[] = L"__COMPAT_LAYER=WIN98";
    WCHAR *Block = GetEnvironmentStringsW(), *p, *Copy = NULL;
    SIZE_T Chars;

    if (!Block)
        return NULL;
    for (p = Block; *p; p += wcslen(p) + 1) ;
    Chars = p - Block;
    Copy = HeapAlloc(GetProcessHeap(), 0, (Chars + _countof(Layer) + 1) * sizeof(WCHAR));
    if (Copy)
    {
        memcpy(Copy, Block, Chars * sizeof(WCHAR));
        memcpy(Copy + Chars, Layer, sizeof(Layer));
        Copy[Chars + _countof(Layer)] = UNICODE_NULL;
    }
    FreeEnvironmentStringsW(Block);
    return Copy;
}

static void test_cache(void)
{
    WCHAR TempDir[MAX_PATH], Dir[MAX_PATH], Self[MAX_PATH], SystemDir[MAX_PATH];
    WCHAR Helper[MAX_PATH], Exe[MAX_PATH], LongExe[MAX_PATH], Decoy[MAX_PATH], Source[MAX_PATH];
    WCHAR *EnvPtr;
    PWSTR Name;
    HKEY Key;
    HANDLE File;
    DWORD Written, Code;
    NTSTATUS Status;
    LONG Error;
    BOOL Ret;

    GetTempPathW(_countof(TempDir), TempDir);
    ok(SUCCEEDED(StringCchPrintfW(Dir, _countof(Dir), L"%sappcache_%lx", TempDir, GetCurrentProcessId())), "Path too long\n");
    Ret = CreateDirectoryW(Dir, NULL);
    ok(Ret, "CreateDirectory %ls failed with %lu\n", Dir, GetLastError());
    if (!Ret)
        return;

    GetModuleFileNameW(NULL, Self, _countof(Self));
    Name = StrRChrW(Self, NULL, L'\\');
    *Name = UNICODE_NULL;
    GetSystemDirectoryW(SystemDir, _countof(SystemDir));
    StringCchPrintfW(Helper, _countof(Helper), L"%ls\\apphelp_shimload_child.exe", Self);
    StringCchPrintfW(Source, _countof(Source), L"%ls\\lz32.dll", SystemDir);
    StringCchPrintfW(Exe, _countof(Exe), L"%ls\\appcache_child.exe", Dir);
    StringCchPrintfW(Decoy, _countof(Decoy), L"%ls\\msys-2.0.dll", Dir);

    Ret = CopyFileW(Helper, Exe, FALSE);
    ok(Ret, "CopyFile %ls failed with %lu\n", Helper, GetLastError());
    if (!Ret)
        goto done;

    /* A program nobody has started is not in the cache */
    Status = cache_lookup(Exe);
    if (Status == STATUS_INVALID_PARAMETER)
    {
        skip("The shim cache is off\n");
        goto done;
    }
    ok(Status != STATUS_SUCCESS, "A new program is in the cache already: %08lx\n", Status);

    /* The first start checks the database and enters the program: the later ones skip the database */
    Code = run_child(Exe, Dir, NULL);
    ok(Code == CHILD_NO_SHIM, "Exit code is %lu, expected %u\n", Code, CHILD_NO_SHIM);
    Status = cache_lookup(Exe);
    ok(Status == STATUS_SUCCESS, "The program is not in the cache after it started: %08lx\n", Status);
    Code = run_child(Exe, Dir, NULL);
    ok(Code == CHILD_NO_SHIM, "Exit code is %lu, expected %u\n", Code, CHILD_NO_SHIM);
    Status = cache_lookup(Exe);
    ok(Status == STATUS_SUCCESS, "The program left the cache: %08lx\n", Status);

    /* The file information of a handle is for a caller that has the right to read it */
    {
        CACHE_LOOKUP Lookup;
        WCHAR NtPath[MAX_PATH + 8];
        HANDLE Full = CreateFileW(Exe, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        HANDLE Weak = INVALID_HANDLE_VALUE;

        ok(Full != INVALID_HANDLE_VALUE, "CreateFile %ls failed with %lu\n", Exe, GetLastError());
        /* the same file object, with the right to wait for it and nothing else */
        if (Full != INVALID_HANDLE_VALUE)
        {
            ok(DuplicateHandle(GetCurrentProcess(), Full, GetCurrentProcess(), &Weak, SYNCHRONIZE, FALSE, 0),
               "DuplicateHandle failed with %lu\n", GetLastError());
            CloseHandle(Full);
        }
        if (Weak != INVALID_HANDLE_VALUE)
        {
            StringCchPrintfW(NtPath, _countof(NtPath), L"\\??\\%ls", Exe);
            Lookup.ImageName.Buffer = NtPath;
            Lookup.ImageName.Length = (USHORT)(wcslen(NtPath) * sizeof(WCHAR));
            Lookup.ImageName.MaximumLength = Lookup.ImageName.Length + sizeof(WCHAR);
            Lookup.ImageHandle = Weak;
            Status = pNtApphelpCacheControl(0, &Lookup);
            ok(Status != STATUS_SUCCESS, "A handle without access to the attributes validated the entry\n");
            CloseHandle(Weak);
        }
        /* a refused validation drops the entry: the next start enters it again */
        Code = run_child(Exe, Dir, NULL);
        ok(Code == CHILD_NO_SHIM, "Exit code is %lu, expected %u\n", Code, CHILD_NO_SHIM);
        Status = cache_lookup(Exe);
        ok(Status == STATUS_SUCCESS, "The program is not entered again: %08lx\n", Status);
    }

    /* A layer from the environment is applied to a program the cache knows */
    EnvPtr = make_layer_env();
    ok(EnvPtr != NULL, "No environment\n");
    Code = run_child(Exe, Dir, EnvPtr);
    ok(Code == CHILD_LAYER, "With a layer in the environment, exit code is %lu, expected %u\n", Code, CHILD_LAYER);
    HeapFree(GetProcessHeap(), 0, EnvPtr);
    Code = run_child(Exe, Dir, NULL);
    ok(Code == CHILD_NO_SHIM, "Without it, exit code is %lu, expected %u\n", Code, CHILD_NO_SHIM);

    /* So is a layer the user set for the file in the registry, and only while it is set */
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, LAYERS_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyEx failed with %lu\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        /* the value is named by the long path of the file */
        ok(GetLongPathNameW(Exe, LongExe, _countof(LongExe)) != 0, "GetLongPathName failed with %lu\n", GetLastError());
        Error = RegSetValueExW(Key, LongExe, 0, REG_SZ, (const BYTE *)L"WIN98", sizeof(L"WIN98"));
        ok(Error == ERROR_SUCCESS, "RegSetValueEx failed with %lu\n", Error);
        Code = run_child(Exe, Dir, NULL);
        ok(Code == CHILD_LAYER, "With a layer in the registry, exit code is %lu, expected %u\n", Code, CHILD_LAYER);
        RegDeleteValueW(Key, LongExe);
        RegCloseKey(Key);
        Code = run_child(Exe, Dir, NULL);
        ok(Code == CHILD_NO_SHIM, "Without it, exit code is %lu, expected %u\n", Code, CHILD_NO_SHIM);
        Status = cache_lookup(Exe);
        ok(Status == STATUS_SUCCESS, "The program left the cache: %08lx\n", Status);
    }

    /* A replaced program is not the one the cache knows, and a program that needs a shim gets it */
    File = CreateFileW(Exe, FILE_APPEND_DATA, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFile %ls failed with %lu\n", Exe, GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        ok(WriteFile(File, "appcache", 8, &Written, NULL), "WriteFile failed with %lu\n", GetLastError());
        CloseHandle(File);
    }
    Status = cache_lookup(Exe);
    ok(Status != STATUS_SUCCESS, "The replaced program is still in the cache: %08lx\n", Status);

    Ret = CopyFileW(Source, Decoy, FALSE);
    ok(Ret, "CopyFile %ls failed with %lu\n", Source, GetLastError());
    if (Ret)
    {
#ifdef _M_AMD64
        Code = run_child(Exe, Dir, NULL);
        ok(Code == CHILD_LOADED_SHIM, "Replaced program: exit code is %lu, expected %u\n", Code, CHILD_LOADED_SHIM);
        /* the program that is shimmed is never entered, however often it starts */
        Code = run_child(Exe, Dir, NULL);
        ok(Code == CHILD_LOADED_SHIM, "Second start: exit code is %lu, expected %u\n", Code, CHILD_LOADED_SHIM);
        Status = cache_lookup(Exe);
        ok(Status != STATUS_SUCCESS, "A shimmed program is in the cache: %08lx\n", Status);
#else
        Code = run_child(Exe, Dir, NULL);
        ok(Code == CHILD_NO_SHIM, "Replaced program: exit code is %lu, expected %u\n", Code, CHILD_NO_SHIM);
        Status = cache_lookup(Exe);
        ok(Status == STATUS_SUCCESS, "The replaced program is not entered again: %08lx\n", Status);
#endif
        delete_file_retry(Decoy);
    }

done:
    delete_file_retry(Exe);
    ok(RemoveDirectoryW(Dir), "RemoveDirectory %ls failed with %lu\n", Dir, GetLastError());
}

START_TEST(appcache)
{
    if (!is_reactos())
    {
        skip("The cache is checked through the ReactOS interface and shims\n");
        return;
    }

    pNtApphelpCacheControl = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtApphelpCacheControl");
    if (!pNtApphelpCacheControl)
    {
        skip("NtApphelpCacheControl is not available\n");
        return;
    }
    test_bad_names();
    test_cache();
}
