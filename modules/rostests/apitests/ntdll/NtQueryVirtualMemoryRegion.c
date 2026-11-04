/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for NtQueryVirtualMemory(MemoryRegionInformation)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* MemoryRegionInformation (class 3). Expected values measured on Windows 10 22H2 (x64 and WoW64):
 * RegionType is MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE, or 0x08000000 for a paging-file view;
 * RegionSize and CommitSize describe the whole allocation whatever the address queried. */
#define REGION_TYPE_PAGEFILE 0x08000000
#define REGION_NODE_NONE 0xFFFFFFFF

static
VOID
CheckRegion(
    PCSTR What,
    PVOID Address,
    PVOID AllocationBase,
    ULONG AllocationProtect,
    ULONG RegionType,
    SIZE_T RegionSize,
    SIZE_T CommitSize)
{
    MEMORY_REGION_INFORMATION Info;
    SIZE_T ReturnLength = 0xdead;
    NTSTATUS Status;

    RtlFillMemory(&Info, sizeof(Info), 0x11);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Address, MemoryRegionInformation,
                                  &Info, sizeof(Info), &ReturnLength);
    ok(Status == STATUS_SUCCESS, "%s: status %lx\n", What, Status);
    if (!NT_SUCCESS(Status)) return;
    ok(ReturnLength == sizeof(Info), "%s: return length %Ix\n", What, ReturnLength);
    ok(Info.AllocationBase == AllocationBase, "%s: AllocationBase %p, expected %p\n", What, Info.AllocationBase, AllocationBase);
    ok(Info.AllocationProtect == AllocationProtect, "%s: AllocationProtect %lx, expected %lx\n", What, Info.AllocationProtect, AllocationProtect);
    ok(Info.RegionType == RegionType, "%s: RegionType %lx, expected %lx\n", What, Info.RegionType, RegionType);
    ok(Info.RegionSize == RegionSize, "%s: RegionSize %Ix, expected %Ix\n", What, Info.RegionSize, RegionSize);
    ok(Info.CommitSize == CommitSize, "%s: CommitSize %Ix, expected %Ix\n", What, Info.CommitSize, CommitSize);
    ok(Info.PartitionId == 0, "%s: PartitionId %Ix\n", What, Info.PartitionId);
    ok(Info.NodePreference == REGION_NODE_NONE, "%s: NodePreference %Ix\n", What, Info.NodePreference);
}

static
VOID
Test_RegionPrivate(VOID)
{
    PUCHAR Base = NULL;
    SIZE_T Size = 0x10000;
    ULONG Old;
    NTSTATUS Status;

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&Base, 0, &Size, MEM_RESERVE, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;

    /* Reserved only; any address of the allocation, even an unaligned one, describes all of it */
    CheckRegion("reserve base", Base, Base, PAGE_READWRITE, MEM_PRIVATE, 0x10000, 0);
    CheckRegion("reserve +0x3000", Base + 0x3000, Base, PAGE_READWRITE, MEM_PRIVATE, 0x10000, 0);
    CheckRegion("reserve +0x3123", Base + 0x3123, Base, PAGE_READWRITE, MEM_PRIVATE, 0x10000, 0);

    /* Commit some pages: only their size is counted, and the protection of the allocation stays */
    {
        PVOID Part = Base + 0x2000;
        SIZE_T PartSize = 0x2000;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Part, 0, &PartSize, MEM_COMMIT, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        Part = Base + 0x8000;
        PartSize = 0x1000;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Part, 0, &PartSize, MEM_COMMIT, PAGE_READONLY);
        ok_ntstatus(Status, STATUS_SUCCESS);
        Part = Base + 0x2000;
        PartSize = 0x1000;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Part, &PartSize, PAGE_NOACCESS, &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
    CheckRegion("partial base", Base, Base, PAGE_READWRITE, MEM_PRIVATE, 0x10000, 0x3000);
    CheckRegion("partial +0x2000", Base + 0x2000, Base, PAGE_READWRITE, MEM_PRIVATE, 0x10000, 0x3000);
    CheckRegion("partial +0x8000", Base + 0x8000, Base, PAGE_READWRITE, MEM_PRIVATE, 0x10000, 0x3000);

    /* Decommit part again */
    {
        PVOID Part = Base + 0x2000;
        SIZE_T PartSize = 0x1000;
        Status = NtFreeVirtualMemory(NtCurrentProcess(), &Part, &PartSize, MEM_DECOMMIT);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
    CheckRegion("after decommit", Base, Base, PAGE_READWRITE, MEM_PRIVATE, 0x10000, 0x2000);

    /* Another handle to the process: PROCESS_QUERY_LIMITED_INFORMATION is enough, PROCESS_VM_READ is not */
    {
        CLIENT_ID Cid = { (HANDLE)(ULONG_PTR)GetCurrentProcessId(), NULL };
        OBJECT_ATTRIBUTES Oa;
        HANDLE Process;
        MEMORY_REGION_INFORMATION Info;

        InitializeObjectAttributes(&Oa, NULL, 0, NULL, NULL);
        Status = NtOpenProcess(&Process, PROCESS_QUERY_LIMITED_INFORMATION, &Oa, &Cid);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            Status = NtQueryVirtualMemory(Process, Base, MemoryRegionInformation, &Info, sizeof(Info), NULL);
            ok_ntstatus(Status, STATUS_SUCCESS);
            ok_ptr(Info.AllocationBase, Base);
            ok_size_t(Info.CommitSize, 0x2000);
            NtClose(Process);
        }
        Status = NtOpenProcess(&Process, PROCESS_VM_READ, &Oa, &Cid);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            Status = NtQueryVirtualMemory(Process, Base, MemoryRegionInformation, &Info, sizeof(Info), NULL);
            ok_ntstatus(Status, STATUS_ACCESS_DENIED);
            NtClose(Process);
        }
    }

    /* Released: free memory */
    Size = 0;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&Base, &Size, MEM_RELEASE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    {
        MEMORY_REGION_INFORMATION Info;
        SIZE_T ReturnLength = 0xdead;
        RtlFillMemory(&Info, sizeof(Info), 0x11);
        Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryRegionInformation, &Info, sizeof(Info), &ReturnLength);
        ok_ntstatus(Status, STATUS_INVALID_ADDRESS);
        ok_size_t(ReturnLength, 0xdead);
        ok_hex(((PUCHAR)&Info)[0], 0x11);
    }
}

static
VOID
Test_RegionSections(VOID)
{
    HANDLE Section;
    LARGE_INTEGER MaxSize, Offset;
    PUCHAR View = NULL;
    SIZE_T ViewSize = 0;
    NTSTATUS Status;
    WCHAR Path[MAX_PATH];
    HANDLE File;

    /* Paging-file section */
    MaxSize.QuadPart = 0x8000;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Offset.QuadPart = 0;
        Status = NtMapViewOfSection(Section, NtCurrentProcess(), (PVOID*)&View, 0, 0, &Offset, &ViewSize,
                                    ViewShare, 0, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            CheckRegion("pagefile view", View, View, PAGE_READWRITE, REGION_TYPE_PAGEFILE, 0x8000, 0);
            CheckRegion("pagefile view +0x4000", View + 0x4000, View, PAGE_READWRITE, REGION_TYPE_PAGEFILE, 0x8000, 0);
            NtUnmapViewOfSection(NtCurrentProcess(), View);
        }
        NtClose(Section);
    }

    /* Data file: a view of this module's file, not as an image */
    GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path));
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFile failed %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        Status = NtCreateSection(&Section, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT, File);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            View = NULL;
            ViewSize = 0x4000;
            Offset.QuadPart = 0;
            Status = NtMapViewOfSection(Section, NtCurrentProcess(), (PVOID*)&View, 0, 0, &Offset, &ViewSize,
                                        ViewShare, 0, PAGE_READONLY);
            ok_ntstatus(Status, STATUS_SUCCESS);
            if (NT_SUCCESS(Status))
            {
                CheckRegion("datafile view", View, View, PAGE_READONLY, MEM_MAPPED, 0x4000, 0);
                CheckRegion("datafile view +0x2000", View + 0x2000, View, PAGE_READONLY, MEM_MAPPED, 0x4000, 0);
                NtUnmapViewOfSection(NtCurrentProcess(), View);
            }
            NtClose(Section);
        }
        CloseHandle(File);
    }

    /* Image: ntdll, from any address inside, is one allocation of SizeOfImage */
    {
        PUCHAR Ntdll = (PUCHAR)GetModuleHandleW(L"ntdll.dll");
        PIMAGE_NT_HEADERS Nt = RtlImageNtHeader(Ntdll);
        SIZE_T ImageSize = (((SIZE_T)Nt->OptionalHeader.SizeOfImage + PAGE_SIZE - 1) & ~(SIZE_T)(PAGE_SIZE - 1));
        MEMORY_REGION_INFORMATION Info;
        SIZE_T Length = 0;

        Status = NtQueryVirtualMemory(NtCurrentProcess(), Ntdll + 0x1000, MemoryRegionInformation, &Info, sizeof(Info), &Length);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_ptr(Info.AllocationBase, Ntdll);
        ok_hex(Info.RegionType, MEM_IMAGE);
        ok_size_t(Info.RegionSize, ImageSize);
        ok_hex(Info.AllocationProtect, PAGE_EXECUTE_WRITECOPY);
        ok_size_t(Info.CommitSize % PAGE_SIZE, 0);
        ok(Info.CommitSize < Info.RegionSize, "CommitSize %Ix\n", Info.CommitSize);
        ok_hex(Info.PartitionId, 0);
        ok_hex(Info.NodePreference, REGION_NODE_NONE);
        Status = NtQueryVirtualMemory(NtCurrentProcess(), Ntdll, MemoryRegionInformation, &Info, sizeof(Info), &Length);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_ptr(Info.AllocationBase, Ntdll);
        ok_size_t(Info.RegionSize, ImageSize);
    }

    /* A copy-on-write view of a data file is charged in full */
    {
        WCHAR Name[MAX_PATH];
        HANDLE Map;
        LARGE_INTEGER Size;

        GetTempPathW(ARRAYSIZE(Name), Name);
        StringCchCatW(Name, ARRAYSIZE(Name), L"mrinfo-apitest.tmp");
        File = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
        ok(File != INVALID_HANDLE_VALUE, "CreateFile failed %lu\n", GetLastError());
        if (File != INVALID_HANDLE_VALUE)
        {
            Size.QuadPart = 0x10000;
            Status = NtCreateSection(&Map, SECTION_ALL_ACCESS, NULL, &Size, PAGE_READWRITE, SEC_COMMIT, File);
            ok_ntstatus(Status, STATUS_SUCCESS);
            if (NT_SUCCESS(Status))
            {
                View = NULL;
                ViewSize = 0x8000;
                Offset.QuadPart = 0;
                Status = NtMapViewOfSection(Map, NtCurrentProcess(), (PVOID*)&View, 0, 0, &Offset, &ViewSize,
                                            ViewShare, 0, PAGE_READWRITE);
                ok_ntstatus(Status, STATUS_SUCCESS);
                if (NT_SUCCESS(Status))
                {
                    CheckRegion("rw view", View, View, PAGE_READWRITE, MEM_MAPPED, 0x8000, 0);
                    NtUnmapViewOfSection(NtCurrentProcess(), View);
                }
                View = NULL;
                ViewSize = 0x8000;
                Status = NtMapViewOfSection(Map, NtCurrentProcess(), (PVOID*)&View, 0, 0, &Offset, &ViewSize,
                                            ViewShare, 0, PAGE_WRITECOPY);
                ok_ntstatus(Status, STATUS_SUCCESS);
                if (NT_SUCCESS(Status))
                {
                    CheckRegion("copy view", View, View, PAGE_WRITECOPY, MEM_MAPPED, 0x8000, 0x8000);
                    NtUnmapViewOfSection(NtCurrentProcess(), View);
                }
                NtClose(Map);
            }
            CloseHandle(File);
        }
    }
}

static
VOID
Test_RegionParameters(VOID)
{
    PUCHAR Base = NULL;
    SIZE_T Size = 0x4000;
    UCHAR Buffer[0x80];
    SIZE_T ReturnLength;
    NTSTATUS Status;
    ULONG i;
    MEMORY_REGION_INFORMATION Info;
    const SIZE_T Min = FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize);
    SYSTEM_BASIC_INFORMATION Basic;
    PVOID HighestUser;
#ifdef _WIN64
    PVOID KernelAddress = (PVOID)0xFFFF800000000000ULL;
#else
    PVOID KernelAddress = (PVOID)0x80001000UL;
#endif

    Status = NtQuerySystemInformation(SystemBasicInformation, &Basic, sizeof(Basic), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    HighestUser = (PVOID)Basic.MaximumUserModeAddress;

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;

    /* Too short: nothing written, return length untouched */
    for (i = 0; i < Min; i += 4)
    {
        ReturnLength = 0xdead;
        RtlFillMemory(Buffer, sizeof(Buffer), 0x11);
        Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryRegionInformation, Buffer, i, &ReturnLength);
        ok(Status == STATUS_INFO_LENGTH_MISMATCH, "length %lx: status %lx\n", i, Status);
        ok_size_t(ReturnLength, 0xdead);
        ok_hex(Buffer[0], 0x11);
    }
    /* The length is checked before the address, even a kernel one */
    Status = NtQueryVirtualMemory(NtCurrentProcess(), KernelAddress, MemoryRegionInformation, Buffer, 0, NULL);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);

#ifdef _WIN64
    /* Fields that fit completely are written, 8 bytes at a time, from RegionSize on */
    for (i = 0x18; i <= sizeof(Buffer); i += 4)
    {
        SIZE_T Expected = min(i & ~7, sizeof(Info));
        ULONG j, Last = 0;

        ReturnLength = 0xdead;
        RtlFillMemory(Buffer, sizeof(Buffer), 0x11);
        Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryRegionInformation, Buffer, i, &ReturnLength);
        ok(Status == STATUS_SUCCESS, "length %lx: status %lx\n", i, Status);
        ok(ReturnLength == Expected, "length %lx: return length %Ix, expected %Ix\n", i, ReturnLength, Expected);
        for (j = 0; j < sizeof(Buffer); j++)
            if (Buffer[j] != 0x11) Last = j + 1;
        ok(Last <= Expected && Last >= Expected - 8, "length %lx: wrote up to %lx, expected %Ix\n", i, Last, Expected);
        ok(Buffer[Expected] == 0x11, "length %lx: wrote past the end\n", i);
    }
#else
    for (i = Min; i <= sizeof(Buffer); i += 4)
    {
        ReturnLength = 0xdead;
        Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryRegionInformation, Buffer, i, &ReturnLength);
        if (i >= sizeof(Info))
        {
            ok(Status == STATUS_SUCCESS, "length %lx: status %lx\n", i, Status);
            ok_size_t(ReturnLength, sizeof(Info));
        }
    }
#endif

    /* Return length is optional */
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryRegionInformation, &Info, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);

    /* Kernel addresses and the first address above the user range */
    ReturnLength = 0xdead;
    Status = NtQueryVirtualMemory(NtCurrentProcess(), KernelAddress, MemoryRegionInformation, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    ok_size_t(ReturnLength, 0xdead);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)(ULONG_PTR)-1, MemoryRegionInformation, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), (PUCHAR)HighestUser + 1, MemoryRegionInformation, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);

    /* Free memory: NULL and a low address */
    Status = NtQueryVirtualMemory(NtCurrentProcess(), NULL, MemoryRegionInformation, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_ADDRESS);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)0x1000, MemoryRegionInformation, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_ADDRESS);

    /* Handles */
    Status = NtQueryVirtualMemory((HANDLE)(ULONG_PTR)0x7777, Base, MemoryRegionInformation, &Info, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = NtQueryVirtualMemory(NULL, Base, MemoryRegionInformation, &Info, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);

#ifdef _WIN64
    /* A bad buffer or return length pointer fails (a 32-bit caller under WoW64 gets no error on Windows) */
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryRegionInformation, NULL, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryRegionInformation, (PVOID)(ULONG_PTR)0x10, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryRegionInformation, &Info, sizeof(Info), (PSIZE_T)(ULONG_PTR)0x10);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
#endif

    Size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&Base, &Size, MEM_RELEASE);
}

static
VOID
Test_RegionInformation(VOID)
{
    Test_RegionPrivate();
    Test_RegionSections();
    Test_RegionParameters();
}

START_TEST(NtQueryVirtualMemoryRegion)
{
    Test_RegionInformation();
}
