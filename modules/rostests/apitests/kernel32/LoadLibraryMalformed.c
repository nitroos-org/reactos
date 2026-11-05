/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Malformed PE files on no-execute loads and on relocating loads, and file names longer than the
 *              loader's name buffers, fail cleanly instead of reading or writing out of bounds.
 *              Expected values were measured on Windows 10 22H2.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <stddef.h>
#include <string.h>
#include "NoExecutePe.h"

#ifndef LOAD_LIBRARY_AS_IMAGE_RESOURCE
#define LOAD_LIBRARY_AS_IMAGE_RESOURCE 0x20
#endif
#ifndef LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE
#define LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE 0x40
#endif
#define NXRES(i) ((LPCWSTR)(ULONG_PTR)(i))

static WCHAR TempDir[MAX_PATH];

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

/*
 * Windows (measured): a NT header offset that points outside the view is refused (ERROR_BAD_EXE_FORMAT)
 * by every no-execute flag; a section table or optional header that runs out of the view is accepted
 * as a data file and refused as an image resource. Looking resources up in the accepted ones must not fault.
 */
static
VOID
TestMalformed(VOID)
{
    static const struct
    {
        int Corrupt;
        PCSTR Name;
        BOOL DataFileLoads;
    } Cases[] =
    {
        { NXPE_CORRUPT_LFANEW_FAR,  "e_lfanew far",   FALSE },
        { NXPE_CORRUPT_LFANEW_EDGE, "e_lfanew edge",  FALSE },
        { NXPE_CORRUPT_SECTIONS,    "65535 sections", TRUE },
        { NXPE_CORRUPT_OPTSIZE,     "optional header too large", TRUE },
    };
    static const DWORD Flags[] =
    {
        LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE
    };
    WCHAR Path[MAX_PATH];
    ULONG i, f;

    for (i = 0; i < _countof(Cases); i++)
    {
        NXPEOPT Opt = { 0, 0, NXPE_RELOC_NONE, 0, Cases[i].Corrupt };

        if (!WriteImage(L"nx_malformed.dll", &Opt, 0, Path))
        {
            skip("Cannot write the test image\n");
            return;
        }
        for (f = 0; f < _countof(Flags); f++)
        {
            BOOL Expected = Cases[i].DataFileLoads && Flags[f] != LOAD_LIBRARY_AS_IMAGE_RESOURCE;
            HMODULE Module;

            SetLastError(0xdeadbeef);
            Module = LoadLibraryExW(Path, NULL, Flags[f]);
            ok((Module != NULL) == Expected, "%s, flags 0x%02lx: module %p, expected %s\n",
               Cases[i].Name, Flags[f], Module, Expected ? "a load" : "a failure");
            if (!Module)
            {
                ok(GetLastError() == ERROR_BAD_EXE_FORMAT, "%s, flags 0x%02lx: error %lu\n",
                   Cases[i].Name, Flags[f], GetLastError());
                continue;
            }

            /* the lookups either find the data or fail, they do not fault */
            _SEH2_TRY
            {
                HRSRC Resource = FindResourceW(Module, NXRES(1), NXRES(10));
                if (Resource)
                {
                    HGLOBAL Global = LoadResource(Module, Resource);
                    if (Global) (void)LockResource(Global);
                }
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                ok(0, "%s, flags 0x%02lx: the resource lookup faulted\n", Cases[i].Name, Flags[f]);
            }
            _SEH2_END;
            FreeLibrary(Module);
        }
        DeleteFileW(Path);
    }
}

/*
 * Relocation blocks that are too small, run past the directory, or point outside the image: the load of an
 * image that has to be relocated (its base is that of this process) fails, it does not touch memory.
 */
static
VOID
TestBadRelocations(VOID)
{
    static const struct
    {
        int Reloc;
        PCSTR Name;
    } Cases[] =
    {
        { NXPE_RELOC_SMALLBLOCK, "block smaller than its header" },
        { NXPE_RELOC_LONGBLOCK,  "block longer than the directory" },
        { NXPE_RELOC_BADTARGET,  "fixup outside the image" },
    };
    WCHAR Path[MAX_PATH];
    ULONG i;

    for (i = 0; i < _countof(Cases); i++)
    {
        NXPEOPT Opt = { 0, 1, Cases[i].Reloc, 1, 0 };
        HMODULE Module;

        if (!WriteImage(L"nx_reloc.dll", &Opt, (ULONG_PTR)GetModuleHandleW(NULL), Path))
        {
            skip("Cannot write the test image\n");
            return;
        }
        Module = LoadLibraryExW(Path, NULL, DONT_RESOLVE_DLL_REFERENCES);
        ok(Module == NULL, "%s: the image loaded (%p)\n", Cases[i].Name, Module);
        if (Module) FreeLibrary(Module);
        DeleteFileW(Path);
    }
}

/* Names longer than the loader's name buffers */
static
VOID
TestLongNames(VOID)
{
    PWSTR Name = HeapAlloc(GetProcessHeap(), 0, 2000 * sizeof(WCHAR));
    static const struct
    {
        PCWSTR Prefix;
        ULONG Chars;
        PCWSTR Suffix;
    } Cases[] =
    {
        { L"C:\\", 300, L"\\x.dll" },
        { L"",     300, L"\\x.dll" },
        { L"",     270, L".dll" },
        { L"",     262, L"\\x.dll" },
    };
    ULONG i, j, Pos;

    for (i = 0; i < _countof(Cases); i++)
    {
        HMODULE Module;

        wcscpy(Name, Cases[i].Prefix);
        Pos = (ULONG)wcslen(Name);
        for (j = 0; j < Cases[i].Chars; j++) Name[Pos++] = L'a';
        wcscpy(Name + Pos, Cases[i].Suffix);

        SetLastError(0xdeadbeef);
        Module = LoadLibraryW(Name);
        ok(Module == NULL, "Long name %lu loaded\n", i);
        /* Windows reports ERROR_MOD_NOT_FOUND for all of them; the error is not checked here */
        if (Module) FreeLibrary(Module);
    }
    HeapFree(GetProcessHeap(), 0, Name);
}

START_TEST(LoadLibraryMalformed)
{
    GetTempPathW(_countof(TempDir), TempDir);
    TestMalformed();
    TestBadRelocations();
    TestLongNames();
}
