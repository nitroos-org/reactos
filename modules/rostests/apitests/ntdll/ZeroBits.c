/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     Address limits for allocation and section mapping
 */

#include "precomp.h"

/* From Windows 10 on, every invalid ZeroBits is the generic STATUS_INVALID_PARAMETER (x86 and x64
   oracle, NtMapViewOfSection data and image, and NtAllocateVirtualMemory); earlier versions report
   the numbered status of the argument. */
static NTSTATUS
ParamStatus(NTSTATUS Numbered)
{
    return GetNTVersion() >= _WIN32_WINNT_WIN10 ? STATUS_INVALID_PARAMETER : Numbered;
}

static VOID
CheckLimit(PVOID Base, SIZE_T Size, ULONG_PTR Limit)
{
    ok((ULONG_PTR)Base <= Limit && Size - 1 <= Limit - (ULONG_PTR)Base,
       "Range %p + %Ix exceeds %Ix\n", Base, Size, Limit);
}

static VOID
TestPlacement(HANDLE Section, BOOLEAN MasksSupported)
{
    static const struct
    {
        ULONG_PTR ZeroBits;
        ULONG_PTR Limit;
    } Cases[] =
    {
        {1, 0x7fffffff},
        {10, 0x3fffff},
        {0x1aaaaaaa, 0x1fffffff}, /* Internal zeroes are not placement restrictions. */
        {0x7fffffff, 0x7fffffff},
        {MAXULONG, MAXULONG},
#ifdef _WIN64
        {0x100000000ULL, 0x1ffffffffULL},
        {MAXULONG_PTR, MAXULONG_PTR},
#endif
    };
    ULONG i, TopDown;
    PVOID Base;
    SIZE_T Size, FreeSize;
    LARGE_INTEGER Offset;
    NTSTATUS Status;

    for (i = 0; i < RTL_NUMBER_OF(Cases); ++i)
    for (TopDown = 0; TopDown < 2; ++TopDown)
    {
        Base = NULL;
        Size = PAGE_SIZE;
        if (Section)
        {
            Offset.QuadPart = 0;
            Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base,
                                       Cases[i].ZeroBits, 0, &Offset, &Size,
                                       ViewUnmap, TopDown ? MEM_TOP_DOWN : 0, PAGE_READWRITE);
        }
        else
        {
            Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, Cases[i].ZeroBits,
                                             &Size, MEM_RESERVE | MEM_COMMIT |
                                             (TopDown ? MEM_TOP_DOWN : 0), PAGE_READWRITE);
        }
        trace("%s ZeroBits=%Ix topdown=%lu: %08lx at %p\n",
              Section ? "map" : "allocate", Cases[i].ZeroBits, TopDown, Status, Base);
        if (Cases[i].ZeroBits >= 32 && !MasksSupported)
        {
            ok_ntstatus(Status, ParamStatus(Section ? STATUS_INVALID_PARAMETER_4 : STATUS_INVALID_PARAMETER_3));
        }
        else
        {
            ok(Status == STATUS_SUCCESS || (i == 1 && Status == STATUS_NO_MEMORY),
               "ZeroBits %Ix: unexpected status %08lx\n", Cases[i].ZeroBits, Status);
        }
        if (NT_SUCCESS(Status))
        {
            CheckLimit(Base, Size, Cases[i].Limit);
            *(volatile ULONG *)Base = 0x12345678;
            if (Section)
                Status = NtUnmapViewOfSection(NtCurrentProcess(), Base);
            else
            {
                FreeSize = 0;
                Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &FreeSize, MEM_RELEASE);
            }
            ok_ntstatus(Status, STATUS_SUCCESS);
        }
    }
}

static VOID
TestInvalidAndTiny(HANDLE Section, BOOLEAN MasksSupported)
{
    static const ULONG_PTR Values[] = {21, 22, 31, 32, 63, 0xffff};
    PVOID Base;
    SIZE_T Size, FreeSize;
    LARGE_INTEGER Offset;
    NTSTATUS Status, Expected;
    BOOLEAN Rejected;
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Values); ++i)
    {
        Rejected = !(Values[i] == 21 || (MasksSupported && Values[i] >= 32));
        Expected = Rejected ? ParamStatus(STATUS_INVALID_PARAMETER_4) : STATUS_NO_MEMORY;
        Base = NULL;
        Size = PAGE_SIZE;
        Offset.QuadPart = 0;
        Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, Values[i],
                                   0, &Offset, &Size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
        ok_ntstatus(Status, Expected);
        if (NT_SUCCESS(Status)) NtUnmapViewOfSection(NtCurrentProcess(), Base);

        if (Rejected || Values[i] == 63)
            Expected = ParamStatus(STATUS_INVALID_PARAMETER_3);
        else if (Values[i] == 21 || Values[i] == 32)
        {
            /* The range ZeroBits 21 allows (2 KB), and the one of the mask 32 (0x20), are smaller than the page: an
               invalid parameter, not a failure to find room (Windows Server 2022, x86 and x64; a Windows 10 22H2
               oracle answered STATUS_NO_MEMORY) */
            Expected = STATUS_INVALID_PARAMETER;
        }
        Base = NULL;
        Size = PAGE_SIZE;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, Values[i], &Size,
                                         MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
        ok_ntstatus(Status, Expected);
        if (NT_SUCCESS(Status))
        {
            FreeSize = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &Base, &FreeSize, MEM_RELEASE);
        }
    }
}

static VOID
TestBasedSection(BOOLEAN MasksSupported)
{
    HANDLE Section;
    LARGE_INTEGER MaximumSize, Offset;
    PVOID Base;
    SIZE_T Size;
    NTSTATUS Status;
    ULONG i;
    ULONG_PTR Limits[] = {10, MAXULONG};

    MaximumSize.QuadPart = 0x20000;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize,
                             PAGE_READWRITE, SEC_COMMIT | SEC_BASED, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;

    for (i = 0; i < RTL_NUMBER_OF(Limits); ++i)
    {
        /* Include a nonzero offset in the selected based range. */
        Base = NULL;
        Size = PAGE_SIZE;
        Offset.QuadPart = i * 0x10000;
        Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, Limits[i],
                                   0, &Offset, &Size, ViewUnmap, 0, PAGE_READWRITE);
        if (i == 0 || MasksSupported)
            ok_ntstatus(Status, STATUS_NO_MEMORY);
        else
            ok_ntstatus(Status, ParamStatus(STATUS_INVALID_PARAMETER_4));
        if (NT_SUCCESS(Status)) NtUnmapViewOfSection(NtCurrentProcess(), Base);
    }

    /* A failed constrained map must leave the section usable without a limit. */
    Base = NULL;
    Size = PAGE_SIZE;
    Offset.QuadPart = 0;
    Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0,
                               0, &Offset, &Size, ViewUnmap, 0, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok((ULONG_PTR)Base > 0x3fffff, "Unexpected based address %p\n", Base);
#ifdef _WIN64
        ok((ULONG_PTR)Base > MAXULONG, "Expected a native based address: %p\n", Base);
#endif
        *(volatile ULONG *)Base = 0x12345678;
        Status = NtUnmapViewOfSection(NtCurrentProcess(), Base);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
    NtClose(Section);
}

START_TEST(ZeroBits)
{
    HANDLE Section, File;
    LARGE_INTEGER MaximumSize, Offset;
    PVOID Base;
    SIZE_T Size;
    NTSTATUS Status;
    BOOLEAN MasksSupported;
    BOOL Wow64 = FALSE;
    WCHAR Path[MAX_PATH], TempPath[MAX_PATH];

    IsWow64Process(GetCurrentProcess(), &Wow64);
    MasksSupported = sizeof(void *) == 8 || Wow64;
    TestPlacement(NULL, MasksSupported);
    TestBasedSection(MasksSupported);

    MaximumSize.QuadPart = 0x10000;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize,
                             PAGE_READWRITE, SEC_COMMIT, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        TestPlacement(Section, MasksSupported);
        TestInvalidAndTiny(Section, MasksSupported);

        /* A fixed address must obey the mask too, before any VAD is inserted. */
        Base = (PVOID)0x30000000;
        Size = PAGE_SIZE;
        Offset.QuadPart = 0;
        Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0x1fffffff,
                                   0, &Offset, &Size, ViewUnmap, 0, PAGE_READWRITE);
        /* Where masks are supported this is the explicit-base check; where they are not, the mask
           itself is rejected first. Both are STATUS_INVALID_PARAMETER_4 before Windows 10 and the
           generic STATUS_INVALID_PARAMETER from Windows 10 on. */
        ok_ntstatus(Status, ParamStatus(STATUS_INVALID_PARAMETER_4));
        if (NT_SUCCESS(Status)) NtUnmapViewOfSection(NtCurrentProcess(), Base);
        NtClose(Section);
    }

    /* File-backed sections use a different mapper from pagefile sections. */
    if (!GetTempPathW(RTL_NUMBER_OF(TempPath), TempPath) ||
        !GetTempFileNameW(TempPath, L"zbt", 0, Path))
    {
        skip("Cannot create temporary file\n");
        return;
    }
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (File != INVALID_HANDLE_VALUE)
    {
        Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize,
                                 PAGE_READWRITE, SEC_COMMIT, File);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            TestPlacement(Section, MasksSupported);
            NtClose(Section);
        }
        CloseHandle(File);
    }
    else
    {
        ok(0, "CreateFile failed: %lu\n", GetLastError());
        DeleteFileW(Path);
    }

    /* Image relocation must respect a low-address mask as well. */
    GetModuleFileNameW(NULL, Path, RTL_NUMBER_OF(Path));
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Cannot open image: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE) return;
    Status = NtCreateSection(&Section, SECTION_MAP_READ, NULL, NULL,
                             PAGE_READONLY, SEC_IMAGE, File);
    CloseHandle(File);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    Base = NULL;
    Size = 0;
    Offset.QuadPart = 0;
    Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0x7fffffff,
                               0, &Offset, &Size, ViewUnmap, 0, PAGE_READONLY);
    if (MasksSupported)
        ok(NT_SUCCESS(Status), "Image mapping failed: %08lx\n", Status);
    else
        ok_ntstatus(Status, ParamStatus(STATUS_INVALID_PARAMETER_4));
    if (NT_SUCCESS(Status))
    {
        CheckLimit(Base, Size, 0x7fffffff);
        NtUnmapViewOfSection(NtCurrentProcess(), Base);
    }
    NtClose(Section);
}
