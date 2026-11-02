/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.0-or-later (https://spdx.org/licenses/LGPL-2.0-or-later)
 * PURPOSE:     A DLL with a read-only shared section must load at a base other than its preferred one
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Qt6Core.dll has such a section (.qtmimed). Its view is not copy-on-write, so the loader cannot make it
 * writable; relocating the image used to fail with STATUS_SECTION_PROTECTION because it tried.
 */

#include "precomp.h"

#include <winuser.h>

#define SHARED_RO_DLL_ID 107

static BOOL ExtractDll(PCWSTR Path)
{
    HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(SHARED_RO_DLL_ID), (PCWSTR)RT_RCDATA);
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

START_TEST(LdrSharedReadOnlySection)
{
    WCHAR Path[MAX_PATH];
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER Section;
    HRSRC hRsrc;
    PVOID Resource, Reserved, ImageBase;
    SIZE_T ImageSize;
    HMODULE hMod;
    const int * const *Pointer;
    BOOLEAN FoundShared = FALSE;
    ULONG i;

    hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(SHARED_RO_DLL_ID), (PCWSTR)RT_RCDATA);
    if (!hRsrc)
    {
        skip("shared_ro_dll.dll is not embedded\n");
        return;
    }
    Resource = LockResource(LoadResource(NULL, hRsrc));
    NtHeaders = RtlImageNtHeader(Resource);
    ok(NtHeaders != NULL, "No NT headers in the embedded DLL\n");
    if (!NtHeaders)
        return;
    ImageBase = (PVOID)(ULONG_PTR)NtHeaders->OptionalHeader.ImageBase;
    ImageSize = NtHeaders->OptionalHeader.SizeOfImage;

    /* The point of the test is a read-only section with IMAGE_SCN_MEM_SHARED */
    Section = IMAGE_FIRST_SECTION(NtHeaders);
    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++, Section++)
    {
        if ((Section->Characteristics & IMAGE_SCN_MEM_SHARED) &&
            !(Section->Characteristics & IMAGE_SCN_MEM_WRITE))
            FoundShared = TRUE;
    }
    if (!FoundShared)
    {
        skip("The compiler did not emit a read-only shared section\n");
        return;
    }

    GetTempPathW(_countof(Path), Path);
    wcscat(Path, L"shared_ro_dll.dll");
    if (!ExtractDll(Path))
    {
        skip("Could not write %ls\n", Path);
        return;
    }

    /* Take the preferred base, so that the loader has to relocate the image */
    Reserved = VirtualAlloc(ImageBase, ImageSize, MEM_RESERVE, PAGE_NOACCESS);
    if (!Reserved)
    {
        skip("Could not reserve the preferred base %p\n", ImageBase);
        DeleteFileW(Path);
        return;
    }

    SetLastError(0xdeadbeef);
    hMod = LoadLibraryW(Path);
    ok(hMod != NULL, "LoadLibrary failed with %lu\n", GetLastError());
    if (hMod)
    {
        ok(hMod != ImageBase, "Loaded at the reserved base %p\n", hMod);
        Pointer = (const int * const *)GetProcAddress(hMod, "SharedRoPointer");
        ok(Pointer != NULL, "SharedRoPointer not exported\n");
        if (Pointer)
        {
            ok((ULONG_PTR)*Pointer >= (ULONG_PTR)hMod && (ULONG_PTR)*Pointer < (ULONG_PTR)hMod + ImageSize,
               "Pointer %p was not relocated (module at %p)\n", *Pointer, hMod);
            ok(**Pointer == 0x1234, "Shared value is 0x%x\n", **Pointer);
        }
        FreeLibrary(hMod);
    }
    VirtualFree(Reserved, 0, MEM_RELEASE);
    DeleteFileW(Path);
}
