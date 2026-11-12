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

#include <ndk/psfuncs.h>
#include <ndk/exfuncs.h>

#ifdef _WIN64

#define TIB (1ULL << 40)
#define MIB (1ULL << 20)
#define CHILD_ENV L"VIRTUALALLOCLARGE_CHILD"
#define CHILD_EXIT_CODE 0x4a1b

/* The private commit charge of this process, in bytes (what PrivateUsage reports) */
static SIZE_T
PrivateUsage(void)
{
    VM_COUNTERS_EX Counters;
    NTSTATUS Status;

    RtlZeroMemory(&Counters, sizeof(Counters));
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessVmCounters, &Counters, sizeof(Counters), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    return Counters.PrivateUsage;
}

/* The system wide committed pages */
static ULONG_PTR
SystemCommittedPages(void)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;
    NTSTATUS Status;

    RtlZeroMemory(&Info, sizeof(Info));
    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    return Info.CommittedPages;
}

/* Reserve 8 TiB and commit pieces of it: at the start, in the middle of a page table, in
   a far page table, and at the very end. Returns the base. */
static char *
ReserveAndCommitPieces(SIZE_T Size, SIZE_T *Committed)
{
    char *Base = VirtualAlloc(NULL, Size, MEM_RESERVE, PAGE_NOACCESS);
    SIZE_T Total = 0;

    if (!Base)
        return NULL;
    if (VirtualAlloc(Base, 16 * MIB, MEM_COMMIT, PAGE_READWRITE))
        Total += 16 * MIB;
    if (VirtualAlloc(Base + Size / 2 + 0x1F3000, 7 * PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE))
        Total += 7 * PAGE_SIZE;
    if (VirtualAlloc(Base + Size - 4 * MIB, 4 * MIB, MEM_COMMIT, PAGE_READWRITE))
        Total += 4 * MIB;
    *Committed = Total;
    return Base;
}

static void
ChildProcessMain(void)
{
    SIZE_T Committed;

    /* Exit with the reservation and the commit alive: the address space teardown frees them */
    if (!ReserveAndCommitPieces(8 * TIB, &Committed))
        ExitProcess(1);
    ExitProcess(CHILD_EXIT_CODE);
}

/* The process exit has to give back the commit of a live 8 TiB reservation, and not hang or fail
   while it tears down page tables in the high PML4 entries */
static void
TestProcessExit(void)
{
    WCHAR Path[MAX_PATH + 32];
    WCHAR CmdLine[MAX_PATH + 64];
    STARTUPINFOW Startup;
    PROCESS_INFORMATION Pi;
    ULONG_PTR Before, After;
    DWORD Exit, Wait;
    int i;

    if (!GetModuleFileNameW(NULL, Path, MAX_PATH))
    {
        skip("GetModuleFileName failed: %lu\n", GetLastError());
        return;
    }
    StringCchPrintfW(CmdLine, _countof(CmdLine), L"\"%s\" VirtualAllocLarge", Path);
    SetEnvironmentVariableW(CHILD_ENV, L"1");

    for (i = 0; i < 3; i++)
    {
        ZeroMemory(&Startup, sizeof(Startup));
        Startup.cb = sizeof(Startup);
        Before = SystemCommittedPages();
        if (!CreateProcessW(Path, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Pi))
        {
            skip("CreateProcess failed: %lu\n", GetLastError());
            break;
        }
        Wait = WaitForSingleObject(Pi.hProcess, 120000);
        ok(Wait == WAIT_OBJECT_0, "Child (round %d) did not exit: %lu\n", i, Wait);
        Exit = 0;
        GetExitCodeProcess(Pi.hProcess, &Exit);
        ok(Exit == CHILD_EXIT_CODE, "Child (round %d) exit code %lx\n", i, Exit);
        if (Wait != WAIT_OBJECT_0)
            TerminateProcess(Pi.hProcess, 1);
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);

        /* The child committed 20 MiB + 28 KiB (5127 pages); a leaked charge adds up over the rounds */
        Sleep(200);
        After = SystemCommittedPages();
        ok(After < Before + 2048, "Committed pages grew from %Iu to %Iu over a child with a live reservation (round %d)\n",
           Before, After, i);
    }
    SetEnvironmentVariableW(CHILD_ENV, NULL);
}

/* Exact commit accounting around commit, decommit and release of pieces of a large reservation */
static void
TestAccounting(SIZE_T Size)
{
    MEMORY_BASIC_INFORMATION Info;
    SIZE_T Base0, Reserved, Committed, Charged, After, Mid;
    char *Base, *P;
    int i;

    Base0 = PrivateUsage();
    Base = VirtualAlloc(NULL, Size, MEM_RESERVE, PAGE_NOACCESS);
    ok(Base != NULL, "Reserve failed: %lu\n", GetLastError());
    if (!Base)
        return;
    Reserved = PrivateUsage();
    ok(Reserved == Base0, "A reservation charged %Iu bytes of commit\n", Reserved - Base0);

    /* Commit: the charge is exactly the committed pages, in far apart page tables */
    P = VirtualAlloc(Base, 3 * PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
    ok(P == Base, "Commit at the start failed: %lu\n", GetLastError());
    P = VirtualAlloc(Base + Size - 5 * PAGE_SIZE, 5 * PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
    ok(P == Base + Size - 5 * PAGE_SIZE, "Commit at the end failed: %lu\n", GetLastError());
    Charged = PrivateUsage();
    ok(Charged == Base0 + 8 * PAGE_SIZE, "Commit of 8 pages charged %Iu bytes\n", Charged - Base0);

    /* Committing pages that are committed already charges nothing */
    VirtualAlloc(Base, 3 * PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
    ok(PrivateUsage() == Charged, "Re-commit of committed pages changed the charge\n");

    /* A decommit from an unaligned start in the middle of an absent page table, to an unaligned end in
       another absent one, skips the absent tables and does not touch the committed pages at both ends */
    Mid = 6 * MIB + 0x5000;
    ok(VirtualFree(Base + Mid, Size - Mid - 2 * MIB - 0x3000, MEM_DECOMMIT), "Unaligned decommit failed: %lu\n", GetLastError());
    After = PrivateUsage();
    ok(After == Charged, "Decommit of never committed pages changed the charge by %Id bytes\n", (SSIZE_T)(After - Charged));
    ok(VirtualQuery(Base, &Info, sizeof(Info)) == sizeof(Info) && Info.State == MEM_COMMIT && Info.RegionSize == 3 * PAGE_SIZE,
       "Start pages: state %lx size %Ix\n", Info.State, Info.RegionSize);
    ok(VirtualQuery(Base + Size - 5 * PAGE_SIZE, &Info, sizeof(Info)) == sizeof(Info) && Info.State == MEM_COMMIT &&
       Info.RegionSize == 5 * PAGE_SIZE, "End pages: state %lx size %Ix\n", Info.State, Info.RegionSize);
    ok(VirtualQuery(Base + Mid, &Info, sizeof(Info)) == sizeof(Info) && Info.State == MEM_RESERVE,
       "Decommitted range: state %lx\n", Info.State);

    /* Commit into the range the decommit skipped, use it, decommit it again, and commit it once more:
       the charge follows exactly, the pages are zero each time */
    for (i = 0; i < 3; i++)
    {
        volatile char *Q;
        SIZE_T k;

        Q = VirtualAlloc(Base + Mid, 40 * PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
        ok(Q == Base + Mid, "Re-commit (round %d) failed: %lu\n", i, GetLastError());
        if (!Q)
            break;
        After = PrivateUsage();
        ok(After == Charged + 40 * PAGE_SIZE, "Re-commit of 40 pages (round %d) charged %Id bytes\n", i, (SSIZE_T)(After - Charged));
        for (k = 0; k < 40 * PAGE_SIZE; k += PAGE_SIZE)
        {
            ok(Q[k] == 0, "Page %Iu of the re-commit (round %d) is not zero\n", k / PAGE_SIZE, i);
            Q[k] = (char)(k / PAGE_SIZE + 1);
        }
        ok(VirtualFree(Base + Mid, Size - Mid - 2 * MIB - 0x3000, MEM_DECOMMIT), "Decommit (round %d) failed: %lu\n", i, GetLastError());
        After = PrivateUsage();
        ok(After == Charged, "Decommit of 40 committed pages (round %d) left a charge of %Id bytes\n", i, (SSIZE_T)(After - Charged));
    }

    /* A decommit of a range that is decommitted already is a no-op for the charge */
    ok(VirtualFree(Base + Mid, 0x100000, MEM_DECOMMIT), "Second decommit failed: %lu\n", GetLastError());
    ok(PrivateUsage() == Charged, "Second decommit changed the charge\n");

    /* A part of a reservation can not be released */
    SetLastError(0xdeadbeef);
    ok(!VirtualFree(Base, Size / 2, MEM_RELEASE), "Partial release succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "Partial release: error %lu\n", GetLastError());
    ok(PrivateUsage() == Charged, "A failed release changed the charge\n");

    /* Release of the partially committed reservation returns exactly what was charged */
    ok(VirtualFree(Base, 0, MEM_RELEASE), "Release failed: %lu\n", GetLastError());
    After = PrivateUsage();
    ok(After == Base0, "After the release the charge is %Id bytes off\n", (SSIZE_T)(After - Base0));
    ok(VirtualQuery(Base, &Info, sizeof(Info)) == sizeof(Info) && Info.State == MEM_FREE, "After the release: state %lx\n", Info.State);

    /* The same with the commit spread over a reservation that spans many PML4 entries, then a decommit of all of it */
    Base = ReserveAndCommitPieces(Size, &Committed);
    ok(Base != NULL, "Reserve failed: %lu\n", GetLastError());
    if (Base)
    {
        After = PrivateUsage();
        ok(After == Base0 + Committed, "Commit of %Iu bytes charged %Id\n", Committed, (SSIZE_T)(After - Base0));
        ok(VirtualFree(Base, Size, MEM_DECOMMIT), "Decommit of all failed: %lu\n", GetLastError());
        After = PrivateUsage();
        ok(After == Base0, "After the decommit of all the charge is %Id bytes off\n", (SSIZE_T)(After - Base0));
        ok(VirtualFree(Base, 0, MEM_RELEASE), "Release failed: %lu\n", GetLastError());
        ok(PrivateUsage() == Base0, "After the release the charge is off\n");
    }
}

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
    WCHAR Value[4];

    /* The process the exit test starts */
    if (GetEnvironmentVariableW(CHILD_ENV, Value, _countof(Value)))
        ChildProcessMain();

    TestRange();
    TestAccounting(8 * TIB);
    TestAccounting(64 * TIB);
    TestProcessExit();

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
