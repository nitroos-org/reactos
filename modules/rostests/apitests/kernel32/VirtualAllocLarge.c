/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for large MEM_RESERVE reservations and the 128 TiB user address range of 64-bit processes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * MariaDB's InnoDB reserves its whole potential buffer pool (8 TiB) with one VirtualAlloc(MEM_RESERVE)
 * and commits pieces of it. The expected results are those of Windows 10 22H2 (amd64): the user range
 * of a 64-bit process ends at 0x7FFFFFFEFFFF, reservations of 8 to 120 TiB succeed, sizes of 128 TiB
 * and more fail with ERROR_INVALID_PARAMETER, and a 32-bit (WoW64) process keeps its 2/4 GiB range.
 */

#include "precomp.h"

#ifdef _WIN64

#define TIB (1ULL << 40)

static void
TestReserveBothEnds(SIZE_T Size, int Rounds)
{
    MEMORY_BASIC_INFORMATION Info;
    volatile char *Low, *High;
    char *Base;
    DWORD Start;
    int i;

    for (i = 0; i < Rounds; i++)
    {
        Base = VirtualAlloc(NULL, Size, MEM_RESERVE, PAGE_NOACCESS);
        ok(Base != NULL, "Reserve of %Ix bytes (round %d) failed: %lu\n", Size, i, GetLastError());
        if (!Base)
            return;
        ok((ULONG_PTR)Base + Size - 1 <= 0x00007FFFFFFEFFFFULL, "Reservation %p + %Ix ends above the user range\n", Base, Size);

        /* Commit the first and the last page and use them */
        Low = VirtualAlloc(Base, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
        High = VirtualAlloc(Base + Size - PAGE_SIZE, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
        ok(Low == (volatile char *)Base, "Commit at the start returned %p, expected %p (%lu)\n", Low, Base, GetLastError());
        ok(High == (volatile char *)(Base + Size - PAGE_SIZE), "Commit at the end returned %p (%lu)\n", High, GetLastError());
        if (Low && High)
        {
            Low[0] = 1;
            High[PAGE_SIZE - 1] = 2;
            ok(Low[0] == 1 && High[PAGE_SIZE - 1] == 2, "Committed pages do not hold their values\n");
        }

        /* The middle is still reserved */
        ok(VirtualQuery(Base + Size / 2, &Info, sizeof(Info)) == sizeof(Info), "VirtualQuery failed: %lu\n", GetLastError());
        ok(Info.State == MEM_RESERVE, "Middle state %lx\n", Info.State);
        ok(Info.AllocationBase == Base, "Middle allocation base %p, expected %p\n", Info.AllocationBase, Base);
        ok(Info.RegionSize == Size / 2 - PAGE_SIZE, "Middle region size %Ix, expected %Ix\n", Info.RegionSize, Size / 2 - PAGE_SIZE);
        if (High)
        {
            ok(VirtualQuery((PVOID)High, &Info, sizeof(Info)) == sizeof(Info), "VirtualQuery failed: %lu\n", GetLastError());
            ok(Info.State == MEM_COMMIT && Info.Protect == PAGE_READWRITE, "Last page state %lx protect %lx\n", Info.State, Info.Protect);
        }

        /* Decommitting the whole range does not have to visit every page of it */
        Start = GetTickCount();
        ok(VirtualFree(Base, Size, MEM_DECOMMIT), "Decommit of the whole range failed: %lu\n", GetLastError());
        ok(GetTickCount() - Start < 30000, "Decommit of %Ix bytes took %lu ms\n", Size, GetTickCount() - Start);
        ok(VirtualQuery(Base, &Info, sizeof(Info)) == sizeof(Info), "VirtualQuery failed: %lu\n", GetLastError());
        ok(Info.State == MEM_RESERVE && Info.RegionSize == Size, "After decommit: state %lx size %Ix\n", Info.State, Info.RegionSize);
        ok(VirtualFree(Base, 0, MEM_RELEASE), "Release failed: %lu\n", GetLastError());
    }
}

static void
TestFailure(SIZE_T Size, DWORD AllocationType, DWORD ExpectedError)
{
    PVOID Base;

    SetLastError(0xdeadbeef);
    Base = VirtualAlloc(NULL, Size, AllocationType, PAGE_READWRITE);
    ok(Base == NULL, "Allocation of %Ix bytes (type %lx) succeeded at %p\n", Size, AllocationType, Base);
    ok(GetLastError() == ExpectedError, "Allocation of %Ix bytes (type %lx): error %lu, expected %lu\n",
       Size, AllocationType, GetLastError(), ExpectedError);
    if (Base)
        VirtualFree(Base, 0, MEM_RELEASE);
}

/* Commit and use a page at a fixed address high in the user range: every paging level of the
   mapping must be user-accessible there, not only below the old 8 TiB limit */
static void
TestHighAddress(ULONG_PTR Hint)
{
    volatile unsigned char *Page = NULL;
    ULONG_PTR Address;
    int i;

    for (i = 0, Address = Hint; i < 16 && !Page; i++, Address -= 0x100000000ULL)
        Page = VirtualAlloc((PVOID)Address, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Page != NULL, "No 64 KiB could be committed below %p: %lu\n", (PVOID)Hint, GetLastError());
    if (!Page)
        return;
    Page[0] = 0x5a;
    Page[0xFFFF] = 0xa5;
    ok(Page[0] == 0x5a && Page[0xFFFF] == 0xa5, "Page at %p does not hold its values\n", Page);
    ok(VirtualFree((PVOID)Page, 0, MEM_RELEASE), "Release at %p failed: %lu\n", Page, GetLastError());
}

static void
TestRange(void)
{
    MEMORYSTATUSEX Status;
    MEMORY_BASIC_INFORMATION Info;
    SYSTEM_INFO SystemInfo;
    ULONG_PTR Highest;

    GetSystemInfo(&SystemInfo);
    Highest = (ULONG_PTR)SystemInfo.lpMaximumApplicationAddress;
    ok(Highest == 0x00007FFFFFFEFFFFULL, "Highest user address %p\n", (PVOID)Highest);

    Status.dwLength = sizeof(Status);
    ok(GlobalMemoryStatusEx(&Status), "GlobalMemoryStatusEx failed: %lu\n", GetLastError());
    ok(Status.ullTotalVirtual == 0x00007FFFFFFE0000ULL, "Total virtual %I64x\n", Status.ullTotalVirtual);
    ok(Status.ullAvailVirtual > 64 * TIB, "Available virtual %I64x\n", Status.ullAvailVirtual);

    SetLastError(0xdeadbeef);
    ok(VirtualQuery((PVOID)(Highest + 1), &Info, sizeof(Info)) == 0, "VirtualQuery above the user range succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "VirtualQuery above the user range: error %lu\n", GetLastError());

    SetLastError(0xdeadbeef);
    ok(VirtualAlloc((PVOID)(Highest + 1), 0x10000, MEM_RESERVE, PAGE_NOACCESS) == NULL, "Reserve at the probe address succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "Reserve at the probe address: error %lu\n", GetLastError());
}

#endif /* _WIN64 */

START_TEST(VirtualAllocLarge)
{
#ifdef _WIN64
    TestRange();

    /* MariaDB's InnoDB buffer pool reservation, and more */
    TestReserveBothEnds(8 * TIB, 3);
    TestReserveBothEnds(64 * TIB, 2);

    TestHighAddress(0x0000100000000000ULL);     /* 16 TiB */
    TestHighAddress(0x00007FF000000000ULL);     /* the top PML4 entry of the user range */

    /* More than the user range */
    TestFailure(128 * TIB, MEM_RESERVE, ERROR_INVALID_PARAMETER);
    TestFailure(256 * TIB, MEM_RESERVE, ERROR_INVALID_PARAMETER);

    /* A committed reservation of 8 TiB is over the commit limit */
    TestFailure(8 * TIB, MEM_RESERVE | MEM_COMMIT, ERROR_COMMITMENT_LIMIT);
#else
    SYSTEM_INFO SystemInfo;
    PVOID Base;

    /* A 32-bit process keeps its range: 2 GiB, or 4 GiB under WoW64 for a large-address-aware image */
    GetSystemInfo(&SystemInfo);
    ok((ULONG_PTR)SystemInfo.lpMaximumApplicationAddress == 0x7FFEFFFF ||
       (ULONG_PTR)SystemInfo.lpMaximumApplicationAddress == 0xFFFEFFFF ||
       (ULONG_PTR)SystemInfo.lpMaximumApplicationAddress == 0xBFFEFFFF,
       "Highest user address %p\n", SystemInfo.lpMaximumApplicationAddress);
    Base = VirtualAlloc(NULL, 256 * 1024 * 1024, MEM_RESERVE, PAGE_NOACCESS);
    ok(Base != NULL, "Reserve of 256 MiB failed: %lu\n", GetLastError());
    if (Base)
        ok(VirtualFree(Base, 0, MEM_RELEASE), "Release failed: %lu\n", GetLastError());
#endif
}
