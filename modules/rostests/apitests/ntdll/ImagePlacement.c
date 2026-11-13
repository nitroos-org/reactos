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
#define NONLAA_EXE_ID       108
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

static BOOL
ExtractResource(PCWSTR Path, UINT Id)
{
    HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(Id), (PCWSTR)RT_RCDATA);
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

/* Rewrites the file characteristics of an executable: without IMAGE_FILE_LARGE_ADDRESS_AWARE */
static BOOL
ClearLargeAddressAware(PCWSTR Path)
{
    HANDLE hFile = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    IMAGE_DOS_HEADER Dos;
    DWORD Done, Offset;
    WORD Characteristics;
    BOOL Ret = FALSE;

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (ReadFile(hFile, &Dos, sizeof(Dos), &Done, NULL) && Done == sizeof(Dos) && Dos.e_magic == IMAGE_DOS_SIGNATURE)
    {
        Offset = Dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, FileHeader.Characteristics);
        if (SetFilePointer(hFile, Offset, NULL, FILE_BEGIN) == Offset &&
            ReadFile(hFile, &Characteristics, sizeof(Characteristics), &Done, NULL) && Done == sizeof(Characteristics))
        {
            Characteristics &= ~IMAGE_FILE_LARGE_ADDRESS_AWARE;
            Ret = SetFilePointer(hFile, Offset, NULL, FILE_BEGIN) == Offset &&
                  WriteFile(hFile, &Characteristics, sizeof(Characteristics), &Done, NULL) &&
                  Done == sizeof(Characteristics);
        }
    }
    CloseHandle(hFile);
    return Ret;
}

/* A 64-bit process without LARGEADDRESSAWARE: its relocated images and its allocations stay below 2 GB */
static void
TestNonLargeAddressAware(void)
{
    WCHAR Dir[MAX_PATH], ExePath[MAX_PATH], DllPath[MAX_PATH], Cmd[3 * MAX_PATH];
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    DWORD Code = 0xdeadbeef;

    GetTempPathW(_countof(Dir), Dir);
    wcscat(Dir, L"imgplace_nonlaa_dir");
    if (!CreateDirectoryW(Dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        skip("Cannot create %ls\n", Dir);
        return;
    }
    StringCchPrintfW(ExePath, _countof(ExePath), L"%ls\\imgplace_nonlaa.exe", Dir);
    StringCchPrintfW(DllPath, _countof(DllPath), L"%ls\\imgplace_nonlaa_dyn.dll", Dir);
    if (!ExtractResource(ExePath, NONLAA_EXE_ID))
    {
        skip("Cannot extract the helper to %ls: %lu\n", ExePath, GetLastError());
        goto Cleanup;
    }
    if (!ClearLargeAddressAware(ExePath))
    {
        skip("Cannot patch the helper: %lu\n", GetLastError());
        goto Cleanup;
    }
    if (!WriteVariant(DllPath, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
    {
        skip("Cannot create %ls: %lu\n", DllPath, GetLastError());
        goto Cleanup;
    }

    StringCchPrintfW(Cmd, _countof(Cmd), L"\"%ls\" \"%ls\"", ExePath, DllPath);
    if (!CreateProcessW(ExePath, Cmd, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
    {
        skip("Cannot start the helper: %lu\n", GetLastError());
        goto Cleanup;
    }
    WaitForSingleObject(Pi.hProcess, 60000);
    GetExitCodeProcess(Pi.hProcess, &Code);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    ok(Code == 0, "non-LAA helper: failed checks %lx\n", Code);

Cleanup:
    DeleteFileW(ExePath);
    DeleteFileW(DllPath);
    RemoveDirectoryW(Dir);
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

    TestNonLargeAddressAware();
}
