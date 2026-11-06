/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NitroPager P0: page list transitions, slot accounting, in-page
 *              error and resource paths (test commands), the owner tag check,
 *              and a race of protect/decommit/recommit/fault/process exit
 *              against EmptyWorkingSet, flush and purge
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>
#include <ndk/exfuncs.h>
#include <ndk/psfuncs.h>

#ifndef SE_PROF_SINGLE_PROCESS_PRIVILEGE
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13L
#endif

/* SystemMemoryListInformation set commands (values as in public headers) */
#define MemoryEmptyWorkingSets          2
#define MemoryFlushModifiedList         3
#define MemoryPurgeStandbyList          4

/* NitroPager test commands (NitroPagerDebug) */
#define PAGER_TEST_FAIL_NEXT_READ       0x4E500001
#define PAGER_TEST_FAIL_NEXT_WRITE      0x4E500002
#define PAGER_TEST_MISMATCH_NEXT_READ   0x4E500003
#define PAGER_TEST_STARVE_NEXT_READ     0x4E500004
#define PAGER_TEST_PING                 0x4E500005

#define PRIVATE_STANDBY_PRIORITY 2

#define REGION_PAGES 64
#define RACE_SECONDS 20

static SIZE_T PageSize = 4096;
static volatile LONG StopRace;
static volatile LONG RaceErrors;
static volatile LONG RaceCycles[5];

static
NTSTATUS
MemoryListCommand(
    _In_ ULONG Command)
{
    return NtSetSystemInformation(SystemMemoryListInformation, &Command, sizeof(Command));
}

/* A NitroPagerDebug test command for one page of this process */
static
NTSTATUS
ArmTest(
    _In_ ULONG Command,
    _In_opt_ PVOID Address)
{
    ULONG64 Request[2];

    Request[0] = Command;
    Request[1] = (ULONG_PTR)Address;
    return NtSetSystemInformation(SystemMemoryListInformation, Request, sizeof(Request));
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

static
BOOLEAN
PageOut(VOID)
{
    BOOLEAN Ok = TRUE;

    Ok &= (EmptyOwnWorkingSet() == STATUS_SUCCESS);
    Ok &= (MemoryListCommand(MemoryFlushModifiedList) == STATUS_SUCCESS);
    Ok &= (MemoryListCommand(MemoryPurgeStandbyList) == STATUS_SUCCESS);
    return Ok;
}

static
ULONG_PTR
Pattern(
    _In_ PVOID Page,
    _In_ ULONG Index,
    _In_ ULONG Generation)
{
    ULONG_PTR x = (ULONG_PTR)Page ^ ((ULONG_PTR)Generation * 0x9E3779B1u) ^ ((ULONG_PTR)Index * 0x85EBCA77u);
    x ^= x >> 15;
    x *= 0x2C1B3C6Du;
    x ^= x >> 12;
    return x;
}

static
VOID
Fill(
    _In_ PUCHAR Page,
    _In_ ULONG Generation)
{
    PULONG_PTR Words = (PULONG_PTR)Page;
    ULONG i;

    for (i = 0; i < PageSize / sizeof(ULONG_PTR); i++)
        Words[i] = Pattern(Page, i, Generation);
}

static
BOOLEAN
Check(
    _In_ PUCHAR Page,
    _In_ ULONG Generation)
{
    PULONG_PTR Words = (PULONG_PTR)Page;
    ULONG i;

    for (i = 0; i < PageSize / sizeof(ULONG_PTR); i++)
    {
        if (Words[i] != Pattern(Page, i, Generation))
            return FALSE;
    }
    return TRUE;
}

static
ULONG
SlotsInUse(VOID)
{
    UCHAR Buffer[4096];
    PSYSTEM_PAGEFILE_INFORMATION Info = (PVOID)Buffer;
    ULONG Total = 0, Length = 0;

    if (!NT_SUCCESS(NtQuerySystemInformation(SystemPageFileInformation, Buffer, sizeof(Buffer), &Length)) || !Length)
        return MAXULONG;
    for (;;)
    {
        Total += Info->TotalInUse;
        if (!Info->NextEntryOffset)
            break;
        Info = (PVOID)((PUCHAR)Info + Info->NextEntryOffset);
    }
    return Total;
}

static
BOOLEAN
QueryLists(
    _Out_ PSYSTEM_MEMORY_LIST_INFORMATION Info)
{
    return NT_SUCCESS(NtQuerySystemInformation(SystemMemoryListInformation, Info, sizeof(*Info), NULL));
}

static
PUCHAR
Allocate(
    _In_ ULONG Pages)
{
    PVOID Base = NULL;
    SIZE_T Size = Pages * PageSize;

    if (!NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
        return NULL;
    return Base;
}

static
VOID
Release(
    _In_ PVOID Base)
{
    SIZE_T Size = 0;

    NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
}

static
ULONG
ResidentPages(
    _In_ PUCHAR Base,
    _In_ ULONG Pages)
{
    struct { PVOID VirtualAddress; ULONG_PTR VirtualAttributes; } Entries[REGION_PAGES];
    ULONG i, Count = 0;

    for (i = 0; i < Pages && i < REGION_PAGES; i++)
        Entries[i].VirtualAddress = Base + i * PageSize;
    if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), NULL, 4, Entries, i * sizeof(Entries[0]), NULL)))
        return MAXULONG;
    while (i--)
    {
        if (Entries[i].VirtualAttributes & 1)
            Count++;
    }
    return Count;
}

/* A read of the page under SEH: the exception code and its third parameter (the I/O status) */
static
NTSTATUS
ReadUnderSeh(
    _In_ PUCHAR Page,
    _In_ ULONG Generation,
    _Out_ PNTSTATUS IoStatus,
    _Out_ PBOOLEAN Correct)
{
    NTSTATUS Code = STATUS_SUCCESS;
    EXCEPTION_RECORD Record;

    *IoStatus = STATUS_SUCCESS;
    *Correct = FALSE;
    RtlZeroMemory(&Record, sizeof(Record));
    _SEH2_TRY
    {
        *Correct = Check(Page, Generation);
    }
    _SEH2_EXCEPT((Record = *(_SEH2_GetExceptionInformation())->ExceptionRecord, EXCEPTION_EXECUTE_HANDLER))
    {
        Code = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    if ((Code == STATUS_IN_PAGE_ERROR) && (Record.NumberParameters >= 3))
        *IoStatus = (NTSTATUS)Record.ExceptionInformation[2];
    return Code;
}

/*
 * A child process that exits with pages in every state: ntdll_apitest's
 * PagerBasic child mode (kmtest.exe cannot run twice, its device is exclusive)
 */
static
BOOLEAN
RunChild(
    _In_ ULONG TimeoutMs)
{
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    SECURITY_ATTRIBUTES Inherit = { sizeof(Inherit), NULL, TRUE };
    WCHAR Path[MAX_PATH], CommandLine[MAX_PATH + 32];
    PWCHAR Slash;
    HANDLE Null;
    DWORD ExitCode = 1;
    BOOL Created;

    GetModuleFileNameW(NULL, Path, RTL_NUMBER_OF(Path));
    Slash = wcsrchr(Path, L'\\');
    if (Slash)
        *Slash = UNICODE_NULL;
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%s\\ntdll_apitest.exe\" PagerBasic child", Path);

    Null = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &Inherit, OPEN_EXISTING, 0, NULL);
    StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    StartupInfo.hStdInput = Null;
    StartupInfo.hStdOutput = Null;
    StartupInfo.hStdError = Null;
    Created = CreateProcessW(NULL, CommandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &StartupInfo, &ProcessInfo);
    if (Null != INVALID_HANDLE_VALUE)
        CloseHandle(Null);
    if (!Created)
        return FALSE;
    if (WaitForSingleObject(ProcessInfo.hProcess, TimeoutMs) == WAIT_OBJECT_0)
        GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    else
        TerminateProcess(ProcessInfo.hProcess, 4);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    if (ExitCode != 0)
        trace("child exit code 0x%lx\n", ExitCode);
    return (ExitCode == 0);
}

/* Race thread 0: faults (read and write) on its own region */
static
DWORD
WINAPI
FaultThread(
    _In_ LPVOID Parameter)
{
    PUCHAR Base = Parameter;
    ULONG Generation = 100, i;

    for (i = 0; i < REGION_PAGES; i++)
        Fill(Base + i * PageSize, Generation + (i & 1));
    while (!StopRace)
    {
        for (i = 0; i < REGION_PAGES; i++)
        {
            if (!Check(Base + i * PageSize, Generation + (i & 1)))
            {
                InterlockedIncrement(&RaceErrors);
                trace("fault thread: page %lu, generation %lu\n", i, Generation + (i & 1));
            }
        }
        Generation += 2;
        for (i = 0; i < REGION_PAGES; i++)
            Fill(Base + i * PageSize, Generation + (i & 1));
        InterlockedIncrement(&RaceCycles[0]);
    }
    return 0;
}

/* Race thread 1: protection changes (NOACCESS and back, read-only and back) on a written region */
static
DWORD
WINAPI
ProtectThread(
    _In_ LPVOID Parameter)
{
    PUCHAR Base = Parameter;
    PVOID Address;
    SIZE_T Size;
    ULONG Old, i, Round = 0;

    for (i = 0; i < REGION_PAGES; i++)
        Fill(Base + i * PageSize, 200);
    while (!StopRace)
    {
        ULONG First = (Round * 7) % (REGION_PAGES - 8);

        Address = Base + First * PageSize;
        Size = 8 * PageSize;
        NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, (Round & 1) ? PAGE_NOACCESS : PAGE_READONLY, &Old);
        Address = Base + First * PageSize;
        Size = 8 * PageSize;
        NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_READWRITE, &Old);
        for (i = First; i < First + 8; i++)
        {
            if (!Check(Base + i * PageSize, 200))
            {
                InterlockedIncrement(&RaceErrors);
                trace("protect thread: page %lu\n", i);
            }
        }
        Round++;
        InterlockedIncrement(&RaceCycles[1]);
    }
    return 0;
}

/* Race thread 2: decommit and recommit pages of a written region */
static
DWORD
WINAPI
DecommitThread(
    _In_ LPVOID Parameter)
{
    PUCHAR Base = Parameter;
    PVOID Address;
    SIZE_T Size;
    ULONG i, Round = 0;
    ULONG Gen[REGION_PAGES];

    for (i = 0; i < REGION_PAGES; i++)
    {
        Fill(Base + i * PageSize, 300);
        Gen[i] = 300;
    }
    while (!StopRace)
    {
        ULONG First = (Round * 5) % (REGION_PAGES - 4);

        Address = Base + First * PageSize;
        Size = 4 * PageSize;
        if (NT_SUCCESS(NtFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, MEM_DECOMMIT)))
        {
            Address = Base + First * PageSize;
            Size = 4 * PageSize;
            if (NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE)))
            {
                for (i = First; i < First + 4; i++)
                {
                    if (*(PULONG_PTR)(Base + i * PageSize) != 0)
                    {
                        InterlockedIncrement(&RaceErrors);
                        trace("decommit thread: recommitted page %lu is not zero\n", i);
                    }
                    Fill(Base + i * PageSize, 301 + Round);
                    Gen[i] = 301 + Round;
                }
            }
        }
        for (i = 0; i < REGION_PAGES; i++)
        {
            if (!Check(Base + i * PageSize, Gen[i]))
            {
                InterlockedIncrement(&RaceErrors);
                trace("decommit thread: page %lu, generation %lu\n", i, Gen[i]);
            }
        }
        Round++;
        InterlockedIncrement(&RaceCycles[2]);
    }
    return 0;
}

/* Race thread 3: the pager, as fast as it goes */
static
DWORD
WINAPI
PagerThread(
    _In_ LPVOID Parameter)
{
    ULONG Round = 0;

    UNREFERENCED_PARAMETER(Parameter);
    while (!StopRace)
    {
        EmptyOwnWorkingSet();
        MemoryListCommand(MemoryFlushModifiedList);
        MemoryListCommand(MemoryPurgeStandbyList);
        Round++;
        InterlockedIncrement(&RaceCycles[3]);
    }
    return 0;
}

/* Race thread 4: processes that exit with paged-out pages */
static
DWORD
WINAPI
ChildThread(
    _In_ LPVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    while (!StopRace)
    {
        if (!RunChild(60000))
        {
            InterlockedIncrement(&RaceErrors);
            trace("child failed\n");
        }
        InterlockedIncrement(&RaceCycles[4]);
    }
    return 0;
}

static
VOID
TestTransitions(VOID)
{
    SYSTEM_MEMORY_LIST_INFORMATION Before, After;
    PUCHAR Base;
    ULONG i, Bad = 0;

    Base = Allocate(REGION_PAGES);
    ok(Base != NULL, "allocation failed\n");
    if (!Base)
        return;
    for (i = 0; i < REGION_PAGES; i++)
        Fill(Base + i * PageSize, 1);

    /* EmptyWorkingSet: trimmed, written (P0 writes at once), on the private standby list */
    ok(QueryLists(&Before), "lists\n");
    ok_eq_hex(EmptyOwnWorkingSet(), STATUS_SUCCESS);
    ok(QueryLists(&After), "lists\n");
    ok(ResidentPages(Base, REGION_PAGES) == 0, "%lu pages resident after EmptyWorkingSet\n", ResidentPages(Base, REGION_PAGES));
    ok(After.PageCountByPriority[PRIVATE_STANDBY_PRIORITY] >= Before.PageCountByPriority[PRIVATE_STANDBY_PRIORITY] + REGION_PAGES,
       "private standby %Iu -> %Iu\n", Before.PageCountByPriority[PRIVATE_STANDBY_PRIORITY], After.PageCountByPriority[PRIVATE_STANDBY_PRIORITY]);

    /* A soft fault takes a page back from standby, its copy stays */
    ok(Check(Base, 1), "soft fault data\n");

    /* Purge: repurposed, counted */
    Before = After;
    ok_eq_hex(MemoryListCommand(MemoryPurgeStandbyList), STATUS_SUCCESS);
    ok(QueryLists(&After), "lists\n");
    ok(After.RepurposedPagesByPriority[PRIVATE_STANDBY_PRIORITY] >= Before.RepurposedPagesByPriority[PRIVATE_STANDBY_PRIORITY] + REGION_PAGES - 1,
       "repurposed %Iu -> %Iu\n", Before.RepurposedPagesByPriority[PRIVATE_STANDBY_PRIORITY], After.RepurposedPagesByPriority[PRIVATE_STANDBY_PRIORITY]);
    ok(After.PageCountByPriority[PRIVATE_STANDBY_PRIORITY] < Before.PageCountByPriority[PRIVATE_STANDBY_PRIORITY],
       "private standby %Iu -> %Iu\n", Before.PageCountByPriority[PRIVATE_STANDBY_PRIORITY], After.PageCountByPriority[PRIVATE_STANDBY_PRIORITY]);

    /* Hard faults bring it all back */
    for (i = 0; i < REGION_PAGES; i++)
        Bad += !Check(Base + i * PageSize, 1);
    ok_eq_ulong(Bad, 0UL);
    Release(Base);
}

static
VOID
TestSlotAccounting(VOID)
{
    ULONG Before, After, i;

    /* Every process's private pages out once (the system-wide command), then ours */
    ok_eq_hex(MemoryListCommand(MemoryEmptyWorkingSets), STATUS_SUCCESS);
    ok_eq_hex(MemoryListCommand(MemoryFlushModifiedList), STATUS_SUCCESS);
    ok_eq_hex(MemoryListCommand(MemoryPurgeStandbyList), STATUS_SUCCESS);

    /* A child that exits with pages paged out, clean with a copy, and resident */
    PageOut();
    Before = SlotsInUse();
    for (i = 0; i < 4; i++)
        ok(RunChild(60000), "child %lu failed\n", i);
    After = SlotsInUse();
    ok(After <= Before + 8, "slots in use %lu after 4 children, %lu before\n", After, Before);
}

static
VOID
TestInjection(VOID)
{
    PUCHAR Base;
    NTSTATUS Code, IoStatus, Status;
    BOOLEAN Correct;
    UCHAR Buffer[64];
    SIZE_T Done;
    ULONG i;

    if (ArmTest(PAGER_TEST_PING, NULL) != STATUS_SUCCESS)
    {
        skip(FALSE, "NitroPager test commands are off\n");
        return;
    }

    Base = Allocate(8);
    ok(Base != NULL, "allocation failed\n");
    if (!Base)
        return;
    for (i = 0; i < 8; i++)
        Fill(Base + i * PageSize, 21);

    /* Injected device error on the read: in-page error with that status, the next access works */
    PageOut();
    ok_eq_hex(ArmTest(PAGER_TEST_FAIL_NEXT_READ, Base), STATUS_SUCCESS);
    Code = ReadUnderSeh(Base, 21, &IoStatus, &Correct);
    ok_eq_hex(Code, STATUS_IN_PAGE_ERROR);
    ok_eq_hex(IoStatus, STATUS_DEVICE_DATA_ERROR);
    Code = ReadUnderSeh(Base, 21, &IoStatus, &Correct);
    ok_eq_hex(Code, STATUS_SUCCESS);
    ok(Correct, "data after the failed read\n");

    /* The kernel consumer: NtReadVirtualMemory of a page whose read fails returns an error */
    PageOut();
    ok_eq_hex(ArmTest(PAGER_TEST_FAIL_NEXT_READ, Base + PageSize), STATUS_SUCCESS);
    Done = 0;
    Status = NtReadVirtualMemory(NtCurrentProcess(), Base + PageSize, Buffer, sizeof(Buffer), &Done);
    ok(!NT_SUCCESS(Status), "NtReadVirtualMemory: 0x%lx\n", Status);
    trace("NtReadVirtualMemory over a failing in-page read: 0x%lx, %Iu bytes\n", Status, Done);
    Status = NtReadVirtualMemory(NtCurrentProcess(), Base + PageSize, Buffer, sizeof(Buffer), &Done);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(!memcmp(Buffer, Base + PageSize, sizeof(Buffer)), "data\n");

    /* A shortage on the read is waited for and retried: no exception */
    PageOut();
    ok_eq_hex(ArmTest(PAGER_TEST_STARVE_NEXT_READ, Base + 2 * PageSize), STATUS_SUCCESS);
    Code = ReadUnderSeh(Base + 2 * PageSize, 21, &IoStatus, &Correct);
    ok_eq_hex(Code, STATUS_SUCCESS);
    ok(Correct, "data after the starved read\n");

    /* Owner tag mismatch: the read is refused, nothing is returned; the real owner then reads fine */
    PageOut();
    ok_eq_hex(ArmTest(PAGER_TEST_MISMATCH_NEXT_READ, Base + 3 * PageSize), STATUS_SUCCESS);
    Code = ReadUnderSeh(Base + 3 * PageSize, 21, &IoStatus, &Correct);
    ok_eq_hex(Code, STATUS_IN_PAGE_ERROR);
    Code = ReadUnderSeh(Base + 3 * PageSize, 21, &IoStatus, &Correct);
    ok_eq_hex(Code, STATUS_SUCCESS);
    ok(Correct, "data after the refused read\n");

    /* A failed write leaves the page modified and resident; the next flush writes it */
    for (i = 0; i < 8; i++)
        Fill(Base + i * PageSize, 22);
    ok_eq_hex(ArmTest(PAGER_TEST_FAIL_NEXT_WRITE, Base + 4 * PageSize), STATUS_SUCCESS);
    PageOut();
    PageOut();
    for (i = 0; i < 8; i++)
        ok(Check(Base + i * PageSize, 22), "page %lu after a failed write\n", i);

    Release(Base);
}

static
VOID
TestRace(VOID)
{
    HANDLE Threads[5];
    PUCHAR Regions[3];
    ULONG i, SlotsBefore, SlotsAfter;

    for (i = 0; i < 3; i++)
    {
        Regions[i] = Allocate(REGION_PAGES);
        ok(Regions[i] != NULL, "allocation failed\n");
        if (!Regions[i])
            return;
    }
    /* Every process out once now: their slots are in the baseline, and only go down from here */
    MemoryListCommand(MemoryEmptyWorkingSets);
    MemoryListCommand(MemoryFlushModifiedList);
    PageOut();
    SlotsBefore = SlotsInUse();

    StopRace = 0;
    RaceErrors = 0;
    Threads[0] = CreateThread(NULL, 0, FaultThread, Regions[0], 0, NULL);
    Threads[1] = CreateThread(NULL, 0, ProtectThread, Regions[1], 0, NULL);
    Threads[2] = CreateThread(NULL, 0, DecommitThread, Regions[2], 0, NULL);
    Threads[3] = CreateThread(NULL, 0, PagerThread, NULL, 0, NULL);
    Threads[4] = CreateThread(NULL, 0, ChildThread, NULL, 0, NULL);
    for (i = 0; i < 5; i++)
        ok(Threads[i] != NULL, "thread %lu\n", i);

    Sleep(RACE_SECONDS * 1000);
    InterlockedExchange(&StopRace, 1);
    for (i = 0; i < 5; i++)
    {
        if (Threads[i])
        {
            ok_eq_ulong(WaitForSingleObject(Threads[i], 180000), WAIT_OBJECT_0);
            CloseHandle(Threads[i]);
        }
    }

    ok_eq_long(RaceErrors, 0L);
    trace("race: %ld fault, %ld protect, %ld decommit, %ld pager, %ld child cycles\n",
          RaceCycles[0], RaceCycles[1], RaceCycles[2], RaceCycles[3], RaceCycles[4]);
    ok(RaceCycles[3] > 2, "pager cycles %ld\n", RaceCycles[3]);

    for (i = 0; i < 3; i++)
        Release(Regions[i]);
    PageOut();
    SlotsAfter = SlotsInUse();
    ok(SlotsAfter <= SlotsBefore + 64, "slots in use %lu after the race, %lu before\n", SlotsAfter, SlotsBefore);
}

START_TEST(MmPager)
{
    SYSTEM_BASIC_INFORMATION BasicInfo;
    BOOLEAN Old;
    NTSTATUS Status;

    if (NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL)))
        PageSize = BasicInfo.PageSize;

    RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &Old);
    Status = MemoryListCommand(MemoryPurgeStandbyList);
    if (Status == STATUS_INVALID_INFO_CLASS)
    {
        skip(FALSE, "NitroPager is off\n");
        return;
    }
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (SlotsInUse() == MAXULONG)
    {
        skip(FALSE, "no paging file\n");
        return;
    }

    TestTransitions();
    TestSlotAccounting();
    TestInjection();
    TestRace();
}
