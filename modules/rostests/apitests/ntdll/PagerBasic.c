/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NitroPager P0: private pages paged out on request (EmptyWorkingSet,
 *              flush modified list, purge standby list) come back with their data,
 *              protection, commit charge and slot accounting intact
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* SystemMemoryListInformation set commands (values as in public headers) */
#define MemoryEmptyWorkingSets          2
#define MemoryFlushModifiedList         3
#define MemoryPurgeStandbyList          4
#define MemoryPurgeLowPriorityStandbyList 5

#define TEST_PAGES 256

static SIZE_T PageSize = 4096;

static
NTSTATUS
MemoryListCommand(
    _In_ ULONG Command)
{
    return NtSetSystemInformation(SystemMemoryListInformation, &Command, sizeof(Command));
}

static
NTSTATUS
EmptyOwnWorkingSet(VOID)
{
    QUOTA_LIMITS Limits;

    RtlZeroMemory(&Limits, sizeof(Limits));
    Limits.MinimumWorkingSetSize = (SIZE_T)-1;
    Limits.MaximumWorkingSetSize = (SIZE_T)-1;
    return NtSetInformationProcess(NtCurrentProcess(), ProcessQuotaLimits, &Limits, sizeof(Limits));
}

/* EmptyWorkingSet, flush the modified list, purge the standby list: everything private goes to the paging file */
static
VOID
PageOutEverything(
    _In_ BOOLEAN Flush)
{
    ok_ntstatus(EmptyOwnWorkingSet(), STATUS_SUCCESS);
    if (Flush)
        ok_ntstatus(MemoryListCommand(MemoryFlushModifiedList), STATUS_SUCCESS);
    ok_ntstatus(MemoryListCommand(MemoryPurgeStandbyList), STATUS_SUCCESS);
}

static
ULONG_PTR
PatternWord(
    _In_ PVOID Page,
    _In_ ULONG Index,
    _In_ ULONG Generation)
{
    ULONG_PTR x = (ULONG_PTR)Page ^ ((ULONG_PTR)Generation * 0x9E3779B1u) ^ ((ULONG_PTR)Index * 0x85EBCA77u);
    x ^= x >> 13;
    x *= 0xC2B2AE35u;
    x ^= x >> 16;
    return x;
}

static
VOID
FillPage(
    _In_ PVOID Page,
    _In_ ULONG Generation)
{
    PULONG_PTR Words = Page;
    ULONG i;

    for (i = 0; i < PageSize / sizeof(ULONG_PTR); i++)
        Words[i] = PatternWord(Page, i, Generation);
}

static
BOOLEAN
CheckPage(
    _In_ PVOID Page,
    _In_ ULONG Generation)
{
    PULONG_PTR Words = Page;
    ULONG i;

    for (i = 0; i < PageSize / sizeof(ULONG_PTR); i++)
    {
        if (Words[i] != PatternWord(Page, i, Generation))
            return FALSE;
    }
    return TRUE;
}

static
ULONG
CheckRange(
    _In_ PUCHAR Base,
    _In_ ULONG Pages,
    _In_ ULONG Generation)
{
    ULONG i, Bad = 0;

    for (i = 0; i < Pages; i++)
    {
        if (!CheckPage(Base + i * PageSize, Generation))
            Bad++;
    }
    return Bad;
}

/* Pages of the range the working set query reports resident */
static
ULONG
CountResident(
    _In_ PUCHAR Base,
    _In_ ULONG Pages)
{
    struct { PVOID VirtualAddress; ULONG_PTR VirtualAttributes; } Entries[TEST_PAGES];
    NTSTATUS Status;
    ULONG i, Count = 0;

    ok(Pages <= TEST_PAGES, "%lu pages\n", Pages);
    for (i = 0; i < Pages; i++)
        Entries[i].VirtualAddress = Base + i * PageSize;
    Status = NtQueryVirtualMemory(NtCurrentProcess(), NULL, 4 /* MemoryWorkingSetExList */,
                                  Entries, Pages * sizeof(Entries[0]), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    for (i = 0; i < Pages; i++)
    {
        if (Entries[i].VirtualAttributes & 1)
            Count++;
    }
    return Count;
}

/* Slots in use in every paging file; MAXULONG when there is no paging file */
static
ULONG
PagingFileInUse(VOID)
{
    UCHAR Buffer[4096];
    PSYSTEM_PAGEFILE_INFORMATION Info = (PVOID)Buffer;
    NTSTATUS Status;
    ULONG Total = 0, Length;

    Status = NtQuerySystemInformation(SystemPageFileInformation, Buffer, sizeof(Buffer), &Length);
    if (!NT_SUCCESS(Status) || (Length == 0))
        return MAXULONG;
    for (;;)
    {
        Total += Info->TotalInUse;
        if (Info->NextEntryOffset == 0)
            break;
        Info = (PVOID)((PUCHAR)Info + Info->NextEntryOffset);
    }
    return Total;
}

static
ULONG
DirtyPagesWritten(VOID)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;

    ok_ntstatus(NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL), STATUS_SUCCESS);
    return Info.DirtyPagesWriteCount;
}

static
SIZE_T
PrivateUsage(VOID)
{
    VM_COUNTERS Counters;
    NTSTATUS Status;

    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessVmCounters, &Counters, sizeof(Counters), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    return Counters.PagefileUsage;
}

/* Generation each test page holds */
static ULONG Gen[TEST_PAGES];

static
VOID
FillRange(
    _In_ PUCHAR Base,
    _In_ ULONG First,
    _In_ ULONG Count,
    _In_ ULONG Step,
    _In_ ULONG Generation)
{
    ULONG i;

    for (i = First; i < First + Count; i += Step)
    {
        FillPage(Base + i * PageSize, Generation);
        Gen[i] = Generation;
    }
}

static
ULONG
CheckGen(
    _In_ PUCHAR Base,
    _In_ ULONG First,
    _In_ ULONG Count)
{
    ULONG i, Bad = 0;

    for (i = First; i < First + Count; i++)
    {
        if (!CheckPage(Base + i * PageSize, Gen[i]))
        {
            if (Bad++ < 4)
                trace("page %lu does not hold generation %lu\n", i, Gen[i]);
        }
    }
    return Bad;
}

static
VOID
TouchRange(
    _In_ PUCHAR Base,
    _In_ ULONG First,
    _In_ ULONG Count)
{
    volatile ULONG_PTR Sum = 0;
    ULONG i;

    for (i = First; i < First + Count; i++)
        Sum += *(volatile ULONG_PTR *)(Base + i * PageSize);
}

static
PUCHAR
AllocatePages(
    _In_ ULONG Pages,
    _In_ ULONG Protect)
{
    PVOID Base = NULL;
    SIZE_T Size = Pages * PageSize;
    NTSTATUS Status;

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_COMMIT | MEM_RESERVE, Protect);
    ok_ntstatus(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? Base : NULL;
}

static
VOID
FreePages(
    _In_ PVOID Base)
{
    SIZE_T Size = 0;

    ok_ntstatus(NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE), STATUS_SUCCESS);
}

/* The child: write a pattern, page it out, exit with its slots in use */
static
VOID
ChildMain(VOID)
{
    BOOLEAN Old;
    PUCHAR Base;
    ULONG i;

    RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &Old);
    Base = AllocatePages(TEST_PAGES, PAGE_READWRITE);
    if (!Base)
        return;
    for (i = 0; i < TEST_PAGES; i++)
        FillPage(Base + i * PageSize, 7);
    PageOutEverything(TRUE);
    ok_int(CheckRange(Base, TEST_PAGES / 2, 7), 0);
    PageOutEverything(TRUE);
    /* Exit with paged-out pages, clean pages with a copy and resident pages */
}

static
VOID
TestCommandRules(VOID)
{
    BOOLEAN Old;
    NTSTATUS Status;
    ULONG Command = MemoryPurgeStandbyList;

    ULONG Commands[2] = { MemoryPurgeStandbyList, 0 };
    UCHAR Info[sizeof(SYSTEM_MEMORY_LIST_INFORMATION) * 2];
    ULONG Length;

    /* Rows measured on Windows 10 22H2 (harness evidence pagerp0-20261106/oracle) */

    /* Query: no privilege, the length is returned also on a mismatch */
    Length = 0xdead;
    Status = NtQuerySystemInformation(SystemMemoryListInformation, Info, 0, &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_size_t(Length, sizeof(SYSTEM_MEMORY_LIST_INFORMATION));
    Length = 0xdead;
    Status = NtQuerySystemInformation(SystemMemoryListInformation, Info, sizeof(Info), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_size_t(Length, sizeof(SYSTEM_MEMORY_LIST_INFORMATION));

    /* Set: less than a command is a length mismatch, more is accepted */
    Status = NtSetSystemInformation(SystemMemoryListInformation, NULL, 0);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    Status = NtSetSystemInformation(SystemMemoryListInformation, &Command, 2);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    Status = NtSetSystemInformation(SystemMemoryListInformation, Commands, sizeof(Commands));
    ok_ntstatus(Status, STATUS_SUCCESS);

    /* Unknown command */
    Status = MemoryListCommand(99);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);

    /* Without the privilege; an unknown command fails first */
    RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, FALSE, FALSE, &Old);
    Status = MemoryListCommand(MemoryPurgeStandbyList);
    ok_ntstatus(Status, STATUS_PRIVILEGE_NOT_HELD);
    Status = NtSetSystemInformation(SystemMemoryListInformation, Commands, sizeof(Commands));
    ok_ntstatus(Status, STATUS_PRIVILEGE_NOT_HELD);
    Status = MemoryListCommand(99);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = NtSetSystemInformation(SystemMemoryListInformation, NULL, 0);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &Old);
}

START_TEST(PagerBasic)
{
    SYSTEM_BASIC_INFORMATION BasicInfo;
    SYSTEM_MEMORY_LIST_INFORMATION ListInfo;
    MEMORY_BASIC_INFORMATION Mbi;
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    WCHAR CommandLine[MAX_PATH + 32];
    PUCHAR Base, Locked;
    ULONG i, SlotsBefore, SlotsAfter, Written, Written1, Written2, Old32, Resident;
    SIZE_T Private, Size;
    NTSTATUS Status;
    BOOLEAN Old;
    PVOID Address;
    char **Argv;
    int Argc;

    if (!is_reactos())
    {
        skip("NitroPager tests: ReactOS only\n");
        return;
    }

    Status = NtQuerySystemInformation(SystemBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    PageSize = BasicInfo.PageSize;

    Argc = winetest_get_mainargs(&Argv);
    if ((Argc >= 3) && !strcmp(Argv[2], "child"))
    {
        ChildMain();
        return;
    }

    RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &Old);

    /* NitroPager off: the class and EmptyWorkingSet answer as before */
    Status = MemoryListCommand(MemoryPurgeStandbyList);
    if (Status == STATUS_INVALID_INFO_CLASS)
    {
        ok_ntstatus(EmptyOwnWorkingSet(), STATUS_NOT_IMPLEMENTED);
        ok_ntstatus(NtQuerySystemInformation(SystemMemoryListInformation, &ListInfo, sizeof(ListInfo), NULL),
                    STATUS_NOT_IMPLEMENTED);
        skip("NitroPager is off\n");
        return;
    }
    ok_ntstatus(Status, STATUS_SUCCESS);

    SlotsBefore = PagingFileInUse();
    if (SlotsBefore == MAXULONG)
    {
        skip("no paging file\n");
        return;
    }

    TestCommandRules();

    Status = NtQuerySystemInformation(SystemMemoryListInformation, &ListInfo, sizeof(ListInfo), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);

    /* 1. Write, page out, read back */
    Base = AllocatePages(TEST_PAGES, PAGE_READWRITE);
    if (!Base)
        return;
    FillRange(Base, 0, TEST_PAGES, 1, 1);
    Private = PrivateUsage();

    Written = DirtyPagesWritten();
    PageOutEverything(TRUE);
    Written1 = DirtyPagesWritten() - Written;
    ok(Written1 >= TEST_PAGES, "%lu pages written for %u dirty pages\n", Written1, TEST_PAGES);
    Resident = CountResident(Base, TEST_PAGES);
    ok(Resident == 0, "%lu of %u pages still resident after the page-out\n", Resident, TEST_PAGES);

    /* The class 1 view of a paged-out page: committed, same protection; the charge does not change */
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_hex(Mbi.State, MEM_COMMIT);
    ok_hex(Mbi.Protect, PAGE_READWRITE);
    ok(Mbi.RegionSize == TEST_PAGES * PageSize, "RegionSize %Iu\n", Mbi.RegionSize);
    ok(PrivateUsage() == Private, "PrivateUsage %Iu, was %Iu\n", PrivateUsage(), Private);

    ok_int(CheckGen(Base, 0, TEST_PAGES), 0);
    ok(CountResident(Base, TEST_PAGES) == TEST_PAGES, "not all pages resident after reading them\n");

    /* 2. Clean pages keep their copy: out again with no second write */
    Written = DirtyPagesWritten();
    PageOutEverything(FALSE);
    Written2 = DirtyPagesWritten() - Written;
    ok(Written2 + TEST_PAGES / 2 <= Written1, "%lu pages written for clean pages (%lu for dirty ones)\n", Written2, Written1);
    Resident = CountResident(Base, TEST_PAGES);
    ok(Resident == 0, "%lu clean pages still resident\n", Resident);
    ok_int(CheckGen(Base, 0, TEST_PAGES), 0);

    /* 3. Dirtied after the page-in: every other page gets a new generation */
    FillRange(Base, 0, TEST_PAGES, 2, 2);
    PageOutEverything(TRUE);
    ok_int(CheckGen(Base, 0, TEST_PAGES), 0);

    /* 4. F1b: clean pages dirtied, then made PAGE_NOACCESS, keep the new data */
    PageOutEverything(FALSE);
    TouchRange(Base, 0, 8);
    FillRange(Base, 0, 8, 1, 3);
    Address = Base;
    Size = 8 * PageSize;
    Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_NOACCESS, &Old32);
    ok_ntstatus(Status, STATUS_SUCCESS);
    PageOutEverything(TRUE);
    Address = Base;
    Size = 8 * PageSize;
    Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_READWRITE, &Old32);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_hex(Old32, PAGE_NOACCESS);
    ok_int(CheckGen(Base, 0, 8), 0);

    /* 5. Read-only on dirty clean-copy pages, then out and back: the data stays (D8 in the protection change) */
    PageOutEverything(FALSE);
    TouchRange(Base, 8, 8);
    FillRange(Base, 8, 8, 1, 4);
    Address = Base + 8 * PageSize;
    Size = 8 * PageSize;
    ok_ntstatus(NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_READONLY, &Old32), STATUS_SUCCESS);
    PageOutEverything(TRUE);
    ok_int(CheckGen(Base, 8, 8), 0);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Base + 8 * PageSize, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_hex(Mbi.Protect, PAGE_READONLY);
    Address = Base + 8 * PageSize;
    Size = 8 * PageSize;
    ok_ntstatus(NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_READWRITE, &Old32), STATUS_SUCCESS);

    /* 6. Protection change on paged-out pages, then decommit and recommit paged-out pages */
    PageOutEverything(TRUE);
    Address = Base + 16 * PageSize;
    Size = 16 * PageSize;
    ok_ntstatus(NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_READONLY, &Old32), STATUS_SUCCESS);
    ok_hex(Old32, PAGE_READWRITE);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Base + 20 * PageSize, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_hex(Mbi.Protect, PAGE_READONLY);
    ok_int(CheckGen(Base, 16, 16), 0);
    Address = Base + 16 * PageSize;
    Size = 16 * PageSize;
    ok_ntstatus(NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_READWRITE, &Old32), STATUS_SUCCESS);

    PageOutEverything(TRUE);
    Address = Base + 32 * PageSize;
    Size = 32 * PageSize;
    ok_ntstatus(NtFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, MEM_DECOMMIT), STATUS_SUCCESS);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Base + 40 * PageSize, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_hex(Mbi.State, MEM_RESERVE);
    Address = Base + 32 * PageSize;
    Size = 32 * PageSize;
    ok_ntstatus(NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE), STATUS_SUCCESS);
    for (i = 32; i < 64; i++)
    {
        PULONG_PTR Words = (PULONG_PTR)(Base + i * PageSize);
        ok(Words[0] == 0 && Words[PageSize / sizeof(ULONG_PTR) - 1] == 0, "recommitted page %lu is not zero\n", i);
    }
    ok_int(CheckGen(Base, 64, TEST_PAGES - 64), 0);

    /* 7. VirtualLock pages stay resident */
    Locked = AllocatePages(4, PAGE_READWRITE);
    if (Locked)
    {
        for (i = 0; i < 4; i++)
            FillPage(Locked + i * PageSize, 5);
        Address = Locked;
        Size = 4 * PageSize;
        Status = NtLockVirtualMemory(NtCurrentProcess(), &Address, &Size, MAP_PROCESS);
        ok_ntstatus(Status, STATUS_SUCCESS);
        PageOutEverything(TRUE);
        if (NT_SUCCESS(Status))
            ok(CountResident(Locked, 4) == 4, "locked pages were paged out\n");
        ok_int(CheckRange(Locked, 4, 5), 0);
        Address = Locked;
        Size = 4 * PageSize;
        NtUnlockVirtualMemory(NtCurrentProcess(), &Address, &Size, MAP_PROCESS);
        FreePages(Locked);
    }

    /* 8. Release of paged-out pages gives their slots back */
    PageOutEverything(TRUE);
    FreePages(Base);
    SlotsAfter = PagingFileInUse();
    ok(SlotsAfter <= SlotsBefore + 16, "paging file in use %lu, was %lu\n", SlotsAfter, SlotsBefore);

    /* 9. Process exit with paged-out pages gives their slots back */
    SlotsBefore = PagingFileInUse();
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%S\" PagerBasic child", Argv[0]);
    if (CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        ok_int(WaitForSingleObject(ProcessInfo.hProcess, 120000), WAIT_OBJECT_0);
        CloseHandle(ProcessInfo.hThread);
        CloseHandle(ProcessInfo.hProcess);
        SlotsAfter = PagingFileInUse();
        ok(SlotsAfter <= SlotsBefore + 16, "paging file in use %lu after the child, was %lu\n", SlotsAfter, SlotsBefore);
    }
    else
    {
        ok(FALSE, "CreateProcess failed: %lu\n", GetLastError());
    }

    /* The lists answer */
    Status = NtQuerySystemInformation(SystemMemoryListInformation, &ListInfo, sizeof(ListInfo), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    trace("memory lists: zero %Iu free %Iu modified %Iu standby(2) %Iu standby(3) %Iu repurposed(2) %Iu\n",
          ListInfo.ZeroPageCount, ListInfo.FreePageCount, ListInfo.ModifiedPageCount,
          ListInfo.PageCountByPriority[2], ListInfo.PageCountByPriority[3], ListInfo.RepurposedPagesByPriority[2]);
}
