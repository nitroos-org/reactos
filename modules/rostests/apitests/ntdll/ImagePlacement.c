/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Where a relocated image goes: a 64-bit image that opts into address space layout randomization is
 *              placed high (Windows loads it below the system DLLs), a fixed-base image takes the lowest free gap
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#include <winuser.h>

#define EMPTY_DLL_ID        102
#define FOUR_GB             0x100000000ULL

static BOOL
WriteVariant(PCWSTR Path, USHORT DllCharacteristics)
{
    HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(EMPTY_DLL_ID), (PCWSTR)RT_RCDATA);
    HGLOBAL hGlobal = hRsrc ? LoadResource(NULL, hRsrc) : NULL;
    PVOID Data = hGlobal ? LockResource(hGlobal) : NULL;
    DWORD Size = hRsrc ? SizeofResource(NULL, hRsrc) : 0, Written = 0;
    PBYTE Copy;
    PIMAGE_NT_HEADERS NtHeaders;
    HANDLE hFile;
    BOOL Ret;

    if (!Data)
        return FALSE;
    Copy = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Copy)
        return FALSE;
    RtlCopyMemory(Copy, Data, Size);
    NtHeaders = RtlImageNtHeader(Copy);
    if (!NtHeaders)
    {
        HeapFree(GetProcessHeap(), 0, Copy);
        return FALSE;
    }
    if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        ((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.DllCharacteristics = DllCharacteristics;
    else
        ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.DllCharacteristics = DllCharacteristics;

    hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        HeapFree(GetProcessHeap(), 0, Copy);
        return FALSE;
    }
    Ret = WriteFile(hFile, Copy, Size, &Written, NULL) && Written == Size;
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, Copy);
    return Ret;
}

static NTSTATUS
MapImage(HANDLE Section, ULONG_PTR ZeroBits, PVOID *Base, PSIZE_T Size)
{
    LARGE_INTEGER Offset;

    *Base = NULL;
    *Size = 0;
    Offset.QuadPart = 0;
    return NtMapViewOfSection(Section, NtCurrentProcess(), Base, ZeroBits, 0, &Offset, Size,
                              ViewUnmap, 0, PAGE_READONLY);
}

typedef enum { ExpectHigh, ExpectLow, ExpectOther } PLACEMENT;

static void
TestVariant(PCWSTR Name, USHORT DllCharacteristics, PLACEMENT Expect)
{
    WCHAR Path[MAX_PATH];
    HANDLE File, Section;
    PVOID Base1, Base2, Base3;
    SIZE_T Size1, Size2, Size3;
    NTSTATUS Status, Status2;
    ULONG_PTR Preferred;
    PIMAGE_NT_HEADERS NtHeaders;

    GetTempPathW(_countof(Path), Path);
    wcscat(Path, Name);
    if (!WriteVariant(Path, DllCharacteristics))
    {
        skip("Cannot create %ls\n", Name);
        return;
    }
    File = CreateFileW(Path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "%ls: cannot open: %lu\n", Name, GetLastError());
    if (File == INVALID_HANDLE_VALUE)
    {
        DeleteFileW(Path);
        return;
    }
    Status = NtCreateSection(&Section, SECTION_MAP_READ | SECTION_MAP_EXECUTE, NULL, NULL,
                             PAGE_EXECUTE_READ, SEC_IMAGE, File);
    CloseHandle(File);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        DeleteFileW(Path);
        return;
    }

    Base1 = Base2 = Base3 = NULL;
    Size1 = Size2 = Size3 = 0;
    Status = MapImage(Section, 0, &Base1, &Size1);
    ok(NT_SUCCESS(Status), "%ls: first view: %08lx\n", Name, Status);
    if (!NT_SUCCESS(Status))
        goto Done;
    NtHeaders = RtlImageNtHeader(Base1);
    Preferred = NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ?
                (ULONG_PTR)((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.ImageBase :
                (ULONG_PTR)((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.ImageBase;
    (void)Preferred;

    /* The same image again: whatever the first view took, this one is relocated */
    Status2 = MapImage(Section, 0, &Base2, &Size2);
    ok(NT_SUCCESS(Status2), "%ls: second view: %08lx\n", Name, Status2);
    if (NT_SUCCESS(Status2))
    {
        trace("%ls: first %p, second %p\n", Name, Base1, Base2);
        ok(Base2 != Base1, "%ls: both views at %p\n", Name, Base1);
#ifdef _WIN64
        if (Expect == ExpectHigh)
            ok((ULONG_PTR)Base2 >= FOUR_GB, "%ls: second view %p is not above 4 GB\n", Name, Base2);
        else if (Expect == ExpectLow && (ULONG_PTR)Base1 == Preferred)
            ok((ULONG_PTR)Base2 < FOUR_GB, "%ls: second view %p is not below 4 GB\n", Name, Base2);
#endif
        if (Expect == ExpectLow && (ULONG_PTR)Base1 == Preferred)
            ok_ntstatus(Status2, STATUS_IMAGE_NOT_AT_BASE);
    }

    /* A low-address mask holds for every placement */
    Status = MapImage(Section, 0x7fffffff, &Base3, &Size3);
    if (NT_SUCCESS(Status))
    {
        ok((ULONG_PTR)Base3 <= 0x7fffffff && Size3 - 1 <= 0x7fffffff - (ULONG_PTR)Base3,
           "%ls: range %p + %Ix exceeds 2 GB\n", Name, Base3, Size3);
        NtUnmapViewOfSection(NtCurrentProcess(), Base3);
    }
    else
    {
        trace("%ls: masked mapping: %08lx\n", Name, Status);
    }

    if (NT_SUCCESS(Status2))
        NtUnmapViewOfSection(NtCurrentProcess(), Base2);
    NtUnmapViewOfSection(NtCurrentProcess(), Base1);
Done:
    NtClose(Section);
    DeleteFileW(Path);
}

START_TEST(ImagePlacement)
{
    if (!FindResourceW(NULL, MAKEINTRESOURCEW(EMPTY_DLL_ID), (PCWSTR)RT_RCDATA))
    {
        skip("empty_dll.dll is not embedded\n");
        return;
    }

    /* ASLR-capable, with and without the high-entropy flag: placed high on 64-bit */
    TestVariant(L"imgplace_dyn.dll", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, ExpectHigh);
    TestVariant(L"imgplace_heva.dll", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | 0x0020, ExpectHigh);
    /* No ASLR: the lowest free gap, as before */
    TestVariant(L"imgplace_fixed.dll", 0, ExpectLow);
}
