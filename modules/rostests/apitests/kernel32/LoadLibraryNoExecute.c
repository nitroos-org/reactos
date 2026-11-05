/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     LoadLibraryExW with LOAD_LIBRARY_AS_IMAGE_RESOURCE and LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE never
 *              runs the file (no imports, no DllMain), tags the module handle like Windows, and gives the
 *              resource functions a handle they can use. Expected values were measured on Windows 10 22H2.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <stddef.h>
#include <string.h>
#include <pshpack1.h>
#include <poppack.h>
#include "NoExecutePe.h"

#ifndef LOAD_LIBRARY_AS_IMAGE_RESOURCE
#define LOAD_LIBRARY_AS_IMAGE_RESOURCE 0x20
#endif
#ifndef LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE
#define LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE 0x40
#endif

#define NXRES(i) ((LPCWSTR)(ULONG_PTR)(i))
typedef int (WINAPI *PFN_LoadStringW)(HINSTANCE, UINT, LPWSTR, int);

static WCHAR TempDir[MAX_PATH];
static PFN_LoadStringW pLoadStringW;

static
BOOL
WriteImage(PCWSTR Name, const NXPEOPT *Opt, ULONG_PTR Base, PWSTR Path)
{
    unsigned char *Image = HeapAlloc(GetProcessHeap(), 0, NXPE_IMAGE_SIZE);
    HANDLE File;
    DWORD Written = 0;
    int Size;
    BOOL Ret;

    StringCchCopyW(Path, MAX_PATH, TempDir);
    StringCchCatW(Path, MAX_PATH, Name);
    Size = NxBuildPe(Image, Opt, Base);
    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        HeapFree(GetProcessHeap(), 0, Image);
        return FALSE;
    }
    Ret = WriteFile(File, Image, Size, &Written, NULL) && Written == (DWORD)Size;
    CloseHandle(File);
    HeapFree(GetProcessHeap(), 0, Image);
    return Ret;
}

static
BOOL CALLBACK
CountNames(HMODULE Module, LPCWSTR Type, LPWSTR Name, LONG_PTR Param)
{
    (*(int *)Param)++;
    return TRUE;
}

/* The resource functions on a module handle of a no-execute load */
static
VOID
CheckResources(HMODULE Module, PCSTR Tag)
{
    HRSRC Resource;
    HGLOBAL Global;
    PVOID Data;
    WCHAR Text[16];
    int Length, Count = 0;

    Resource = FindResourceW(Module, NXRES(1), NXRES(10));
    ok(Resource != NULL, "%s: FindResource failed %lu\n", Tag, GetLastError());
    if (Resource)
    {
        ok(SizeofResource(Module, Resource) == 8, "%s: SizeofResource = %lu\n", Tag, SizeofResource(Module, Resource));
        Global = LoadResource(Module, Resource);
        Data = Global ? LockResource(Global) : NULL;
        ok(Data && !memcmp(Data, NXPE_RCDATA, 8), "%s: resource data is wrong\n", Tag);
    }

    if (pLoadStringW)
    {
        Text[0] = UNICODE_NULL;
        Length = pLoadStringW(Module, 0, Text, _countof(Text));
        ok(Length == 5 && !wcscmp(Text, L"G4STR"), "%s: LoadString = %d '%ls'\n", Tag, Length, Text);
    }

    ok(EnumResourceNamesW(Module, NXRES(6), CountNames, (LONG_PTR)&Count) && Count == 1,
       "%s: EnumResourceNames: %d names, error %lu\n", Tag, Count, GetLastError());
}

static
VOID
TestFlags(PCWSTR Path, PCSTR What)
{
    static const struct
    {
        DWORD Flags;
        ULONG_PTR Tag;      /* bit 0: data file, bit 1: image resource */
        DWORD Error;        /* 0 = the load works */
    } Cases[] =
    {
        { LOAD_LIBRARY_AS_DATAFILE,                                                      1, 0 },
        { LOAD_LIBRARY_AS_IMAGE_RESOURCE,                                                2, 0 },
        { LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE,                                            1, 0 },
        { LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,                     2, 0 },
        { LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,           2, 0 },
        /* the exclusive data file is a data file by itself: both flags together are refused */
        { LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE,                 0, ERROR_INVALID_PARAMETER },
        { LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE |
          LOAD_LIBRARY_AS_IMAGE_RESOURCE,                                                0, ERROR_INVALID_PARAMETER },
    };
    ULONG i;

    for (i = 0; i < _countof(Cases); i++)
    {
        HMODULE Module, Other;
        CHAR Tag[64];
        FARPROC Proc;
        BOOL Ret;
        HANDLE File;

        StringCchPrintfA(Tag, sizeof(Tag), "%s flags 0x%02lx", What, Cases[i].Flags);

        SetLastError(0xdeadbeef);
        Module = LoadLibraryExW(Path, NULL, Cases[i].Flags);
        if (Cases[i].Error)
        {
            ok(Module == NULL, "%s: loaded %p\n", Tag, Module);
            ok(GetLastError() == Cases[i].Error, "%s: error %lu, expected %lu\n", Tag, GetLastError(), Cases[i].Error);
            if (Module) FreeLibrary(Module);
            continue;
        }

        ok(Module != NULL, "%s: failed, error %lu\n", Tag, GetLastError());
        if (!Module)
            continue;

        ok(((ULONG_PTR)Module & 3) == Cases[i].Tag, "%s: handle %p, tag bits %lu, expected %lu\n",
           Tag, Module, (ULONG)((ULONG_PTR)Module & 3), (ULONG)Cases[i].Tag);
        CheckResources(Module, Tag);

        /* the file is not a loaded module */
        SetLastError(0xdeadbeef);
        Other = GetModuleHandleW(Path);
        ok(Other == NULL, "%s: GetModuleHandle returned %p\n", Tag, Other);
        ok(GetLastError() == ERROR_MOD_NOT_FOUND, "%s: GetModuleHandle error %lu\n", Tag, GetLastError());
        SetLastError(0xdeadbeef);
        Proc = GetProcAddress(Module, "Foo");
        ok(Proc == NULL, "%s: GetProcAddress returned %p\n", Tag, Proc);
        ok(GetLastError() == ERROR_MOD_NOT_FOUND, "%s: GetProcAddress error %lu\n", Tag, GetLastError());

        /* DATAFILE_EXCLUSIVE keeps writers out, and shares delete; a plain data file lets everyone in */
        if (Cases[i].Flags == LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE)
        {
            SetLastError(0xdeadbeef);
            File = CreateFileW(Path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, 0, NULL);
            ok(File == INVALID_HANDLE_VALUE, "%s: opened for write\n", Tag);
            ok(GetLastError() == ERROR_SHARING_VIOLATION, "%s: error %lu\n", Tag, GetLastError());
            if (File != INVALID_HANDLE_VALUE) CloseHandle(File);
            File = CreateFileW(Path, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, 0, NULL);
            ok(File != INVALID_HANDLE_VALUE, "%s: not opened for delete, error %lu\n", Tag, GetLastError());
            if (File != INVALID_HANDLE_VALUE) CloseHandle(File);
        }

        Ret = FreeLibrary(Module);
        ok(Ret, "%s: FreeLibrary failed %lu\n", Tag, GetLastError());

        /* nothing holds the file once the module is gone */
        File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        ok(File != INVALID_HANDLE_VALUE, "%s: file still locked after FreeLibrary, error %lu\n", Tag, GetLastError());
        if (File != INVALID_HANDLE_VALUE) CloseHandle(File);
    }
}

/* A real system DLL, copied so that it is not already loaded: the resources it carries */
static
VOID
TestRealDll(VOID)
{
    static const DWORD Flags[] =
    {
        LOAD_LIBRARY_AS_DATAFILE,
        LOAD_LIBRARY_AS_IMAGE_RESOURCE,
        LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE,
        LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,
    };
    WCHAR Source[MAX_PATH], Copy[MAX_PATH];
    ULONG i;

    GetSystemDirectoryW(Source, _countof(Source));
    StringCchCatW(Source, _countof(Source), L"\\version.dll");
    StringCchCopyW(Copy, _countof(Copy), TempDir);
    StringCchCatW(Copy, _countof(Copy), L"nxcopy_version.dll");
    if (!CopyFileW(Source, Copy, FALSE))
    {
        skip("Cannot copy version.dll: %lu\n", GetLastError());
        return;
    }

    for (i = 0; i < _countof(Flags); i++)
    {
        HMODULE Module = LoadLibraryExW(Copy, NULL, Flags[i]);

        ok(Module != NULL, "Copy of version.dll, flags 0x%02lx: failed %lu\n", Flags[i], GetLastError());
        if (Module)
        {
            HRSRC Resource = FindResourceW(Module, NXRES(1), NXRES(16));
            ok(Resource != NULL, "Copy of version.dll, flags 0x%02lx: no version resource, error %lu\n",
               Flags[i], GetLastError());
            if (Resource)
                ok(SizeofResource(Module, Resource) != 0, "Empty version resource\n");
            ok(FreeLibrary(Module), "FreeLibrary failed %lu\n", GetLastError());
        }
    }
    DeleteFileW(Copy);
}

/* A module that is already loaded is returned as it is, for all the no-execute flags */
static
VOID
TestAlreadyLoaded(VOID)
{
    static const DWORD Flags[] =
    {
        LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE
    };
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    ULONG i;

    for (i = 0; i < _countof(Flags); i++)
    {
        HMODULE Module = LoadLibraryExW(L"kernel32.dll", NULL, Flags[i]);
        ok(Module == Kernel32, "kernel32 with flags 0x%02lx: %p, expected %p\n", Flags[i], Module, Kernel32);
    }
}

START_TEST(LoadLibraryNoExecute)
{
    WCHAR PathA[MAX_PATH], PathB[MAX_PATH];
    NXPEOPT OptA = { 0, 0, NXPE_RELOC_NONE, 0, 0 };     /* DllMain returns FALSE, no import */
    NXPEOPT OptB = { 1, 1, NXPE_RELOC_NONE, 0, 0 };     /* an import that cannot be resolved */
    HMODULE Module;

    GetTempPathW(_countof(TempDir), TempDir);
    pLoadStringW = (PFN_LoadStringW)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadStringW");
    if (!pLoadStringW)
    {
        HMODULE User32 = LoadLibraryW(L"user32.dll");
        if (User32)
            pLoadStringW = (PFN_LoadStringW)GetProcAddress(User32, "LoadStringW");
    }

    if (!WriteImage(L"nx_a.dll", &OptA, 0, PathA) || !WriteImage(L"nx_b.dll", &OptB, 0, PathB))
    {
        skip("Cannot write the test images\n");
        return;
    }

    /* controls: a normal load runs DllMain and resolves the imports, so these fail */
    SetLastError(0xdeadbeef);
    Module = LoadLibraryExW(PathA, NULL, 0);
    ok(Module == NULL, "DllMain returning FALSE: loaded\n");
    ok(GetLastError() == ERROR_DLL_INIT_FAILED, "DllMain returning FALSE: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    Module = LoadLibraryExW(PathB, NULL, 0);
    ok(Module == NULL, "Missing import: loaded\n");
    ok(GetLastError() == ERROR_MOD_NOT_FOUND, "Missing import: error %lu\n", GetLastError());

    TestFlags(PathA, "DllMain FALSE");
    TestFlags(PathB, "missing import");
    TestRealDll();
    TestAlreadyLoaded();

    DeleteFileW(PathA);
    DeleteFileW(PathB);
}
