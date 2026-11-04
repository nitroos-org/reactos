/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Page protection of the sections of an image, mapped at its preferred base or relocated
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows gives a code section (execute+read) PAGE_EXECUTE_READ whether or not the image was relocated; the loader
 * raises the protection for the fix-ups and restores the section protection afterwards. Hooking libraries (the
 * Firefox mozglue hook of BaseThreadInitThunk) and JIT runtimes test for PAGE_EXECUTE_READ.
 */

#include "precomp.h"

#define PROT_MASK   (~(DWORD)(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE))

static const PCWSTR Candidates[] = { L"version.dll", L"winmm.dll", L"imagehlp.dll", L"msimg32.dll" };

/* The protection the section declares, for a section that is not writable (a writable one is copy-on-write) */
static DWORD ExpectedProtection(DWORD Characteristics)
{
    if (!(Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)))
    {
        if (Characteristics & IMAGE_SCN_CNT_CODE)
            Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        if (Characteristics & (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA))
            Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    }
    if (Characteristics & IMAGE_SCN_MEM_WRITE)
        return 0;
    if (Characteristics & IMAGE_SCN_MEM_EXECUTE)
        return (Characteristics & IMAGE_SCN_MEM_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    if (Characteristics & IMAGE_SCN_MEM_READ)
        return PAGE_READONLY;
    return 0;
}

static void CheckSections(HMODULE Module, PCSTR What)
{
    PIMAGE_NT_HEADERS Nt = RtlImageNtHeader(Module);
    PIMAGE_SECTION_HEADER Section;
    ULONG i, Checked = 0;

    ok(Nt != NULL, "%s: no NT headers\n", What);
    if (!Nt)
        return;
    Section = IMAGE_FIRST_SECTION(Nt);
    for (i = 0; i < Nt->FileHeader.NumberOfSections; i++, Section++)
    {
        DWORD Expected = ExpectedProtection(Section->Characteristics);
        ULONG Size = Section->Misc.VirtualSize ? Section->Misc.VirtualSize : Section->SizeOfRawData;
        ULONG_PTR Page = (ULONG_PTR)Module + Section->VirtualAddress;
        ULONG_PTR End = Page + Size;
        MEMORY_BASIC_INFORMATION Mbi;

        if (!Expected || !Section->SizeOfRawData)
            continue;
        for (; Page < End; Page += Mbi.RegionSize - (Page - (ULONG_PTR)Mbi.BaseAddress))
        {
            SIZE_T Ret = VirtualQuery((PVOID)Page, &Mbi, sizeof(Mbi));
            ok(Ret == sizeof(Mbi), "%s: VirtualQuery(%p) failed: %lu\n", What, (PVOID)Page, GetLastError());
            if (Ret != sizeof(Mbi))
                break;
            ok((Mbi.Protect & PROT_MASK) == Expected,
               "%s: section %.8s (characteristics 0x%08lx) at %p has protection 0x%lx, expected 0x%lx\n",
               What, (PCSTR)Section->Name, Section->Characteristics, (PVOID)Page, Mbi.Protect, Expected);
            ok(Mbi.Type == MEM_IMAGE, "%s: type 0x%lx\n", What, Mbi.Type);
            Checked++;
        }
    }
    ok(Checked != 0, "%s: no section checked\n", What);
}

START_TEST(RelocatedImageProtection)
{
    HMODULE Module, Relocated;
    PIMAGE_NT_HEADERS Nt;
    ULONG_PTR Preferred;
    ULONG SizeOfImage, i;
    PVOID Block;

    /* The test program itself */
    CheckSections(GetModuleHandleW(NULL), "exe");

    for (i = 0; i < _countof(Candidates); i++)
    {
        Module = LoadLibraryExW(Candidates[i], NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (Module)
            break;
    }
    if (!Module)
    {
        skip("No candidate DLL to load\n");
        return;
    }
    trace("Using %S\n", Candidates[i]);

    Nt = RtlImageNtHeader(Module);
    Preferred = (ULONG_PTR)Nt->OptionalHeader.ImageBase;
    SizeOfImage = Nt->OptionalHeader.SizeOfImage;
    trace("Loaded at %p, preferred base %p (%s)\n", Module, (PVOID)Preferred,
          (ULONG_PTR)Module == Preferred ? "not relocated" : "relocated");
    CheckSections(Module, "first load");
    FreeLibrary(Module);

    /* Occupy the preferred base: the next load is relocated */
    Block = VirtualAlloc((PVOID)Preferred, SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
    if (!Block)
    {
        skip("Cannot reserve the preferred base %p: %lu\n", (PVOID)Preferred, GetLastError());
        return;
    }
    Relocated = LoadLibraryExW(Candidates[i], NULL, DONT_RESOLVE_DLL_REFERENCES);
    ok(Relocated != NULL, "LoadLibraryExW failed: %lu\n", GetLastError());
    if (Relocated)
    {
        ok((ULONG_PTR)Relocated != Preferred, "Not relocated: %p\n", Relocated);
        CheckSections(Relocated, "relocated");
        FreeLibrary(Relocated);
    }
    VirtualFree(Block, 0, MEM_RELEASE);
}
