/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test the system and process commit charge
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * The system charge is shared with every other process, so system checks
 * accept other activity: [expected - 1 MB, expected + max(1 MB, |expected| / 8)],
 * measured up to three times. They are strict only on ReactOS, where the
 * test system is quiet; on Windows a miss is printed. Process checks allow
 * for page tables and process overhead, expected +- (|expected| / 512 + 8
 * pages), and are strict everywhere.
 */

static SIZE_T PageSize = 4096;
static ULONG PhysicalPages;
/* System-wide checks assert only after the warm-up round, on ReactOS */
static BOOLEAN StrictSystemChecks;

#define MB_PAGES(x) ((LONG_PTR)(((x) * 1024 * 1024) / PageSize))

static
ULONG_PTR
QuerySystemCommit(
    _Out_opt_ PULONG_PTR CommitLimit)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (CommitLimit)
        *CommitLimit = Info.CommitLimit;
    return Info.CommittedPages;
}

static
LONG_PTR
QueryProcessCommit(
    _In_ HANDLE ProcessHandle)
{
    VM_COUNTERS_EX Counters;
    NTSTATUS Status;

    RtlZeroMemory(&Counters, sizeof(Counters));
    Status = NtQueryInformationProcess(ProcessHandle, ProcessVmCounters, &Counters, sizeof(Counters), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    return (LONG_PTR)(Counters.PrivateUsage / PageSize);
}

static
ULONG_PTR
QueryPagingFilePages(VOID)
{
    static UCHAR Buffer[16384];
    PSYSTEM_PAGEFILE_INFORMATION Info = (PSYSTEM_PAGEFILE_INFORMATION)Buffer;
    ULONG_PTR Total = 0;
    ULONG ReturnLength = 0, Offset = 0;
    NTSTATUS Status;

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQuerySystemInformation(SystemPageFileInformation, Buffer, sizeof(Buffer), &ReturnLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status) || (ReturnLength < sizeof(*Info)))
        return 0;

    for (;;)
    {
        Total += Info->TotalSize;
        if ((Info->NextEntryOffset == 0) ||
            (Offset + Info->NextEntryOffset + sizeof(*Info) > min(ReturnLength, sizeof(Buffer))))
        {
            break;
        }
        Offset += Info->NextEntryOffset;
        Info = (PSYSTEM_PAGEFILE_INFORMATION)(Buffer + Offset);
    }
    return Total;
}

static
BOOLEAN
SystemDeltaFits(
    _In_ LONG_PTR Delta,
    _In_ LONG_PTR Expected)
{
    LONG_PTR Magnitude = (Expected < 0) ? -Expected : Expected;
    LONG_PTR Slack = max(MB_PAGES(1), Magnitude / 8);

    return (Delta >= Expected - MB_PAGES(1)) && (Delta <= Expected + Slack);
}

#define CheckSystemDelta(Before, Expected, Text) CheckSystemDelta_(__LINE__, Before, Expected, Text)
static
VOID
CheckSystemDelta_(
    _In_ ULONG Line,
    _In_ ULONG_PTR Before,
    _In_ LONG_PTR Expected,
    _In_ PCSTR Text)
{
    LONG_PTR Delta = 0;
    ULONG Try;

    for (Try = 0; Try < 3; Try++)
    {
        Delta = (LONG_PTR)(QuerySystemCommit(NULL) - Before);
        if (SystemDeltaFits(Delta, Expected))
            break;
        Sleep(200);
    }
    if (is_reactos() && StrictSystemChecks)
        ok_(__FILE__, Line)(SystemDeltaFits(Delta, Expected),
                            "%s: system commit moved by %Id pages, expected %Id\n", Text, Delta, Expected);
    else if (!SystemDeltaFits(Delta, Expected))
        trace_(__FILE__, Line)("%s: system commit moved by %Id pages, expected %Id\n", Text, Delta, Expected);
}

#define CheckProcessDelta(Process, Before, Expected, Text) CheckProcessDelta_(__LINE__, Process, Before, Expected, Text)
static
VOID
CheckProcessDelta_(
    _In_ ULONG Line,
    _In_ HANDLE ProcessHandle,
    _In_ LONG_PTR Before,
    _In_ LONG_PTR Expected,
    _In_ PCSTR Text)
{
    LONG_PTR Delta = QueryProcessCommit(ProcessHandle) - Before;
    LONG_PTR Magnitude = (Expected < 0) ? -Expected : Expected;
    LONG_PTR Slack = Magnitude / 512 + 8;

    ok_(__FILE__, Line)((Delta >= Expected - Slack) && (Delta <= Expected + Slack),
                        "%s: process commit moved by %Id pages, expected %Id\n", Text, Delta, Expected);
}

static
VOID
TestPrivateBalance(VOID)
{
    PVOID Base = NULL, Address;
    SIZE_T Size = 64 * 1024 * 1024, RegionSize;
    ULONG_PTR System;
    LONG_PTR Process;
    NTSTATUS Status;

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* Let the page tables exist before measuring */
    RegionSize = Size;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    RegionSize = Size;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_DECOMMIT);
    ok_ntstatus(Status, STATUS_SUCCESS);

    System = QuerySystemCommit(NULL);
    Process = QueryProcessCommit(NtCurrentProcess());
    RegionSize = Size;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    CheckSystemDelta(System, MB_PAGES(64), "commit 64 MB");
    CheckProcessDelta(NtCurrentProcess(), Process, MB_PAGES(64), "commit 64 MB");

    System = QuerySystemCommit(NULL);
    Process = QueryProcessCommit(NtCurrentProcess());
    Address = (PUCHAR)Base + Size / 2;
    RegionSize = Size / 2;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Address, &RegionSize, MEM_DECOMMIT);
    ok_ntstatus(Status, STATUS_SUCCESS);
    CheckSystemDelta(System, -MB_PAGES(32), "decommit 32 MB");
    CheckProcessDelta(NtCurrentProcess(), Process, -MB_PAGES(32), "decommit 32 MB");

    /* Only the decommitted half is charged again */
    System = QuerySystemCommit(NULL);
    Process = QueryProcessCommit(NtCurrentProcess());
    RegionSize = Size;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    CheckSystemDelta(System, MB_PAGES(32), "recommit 64 MB, 32 MB committed");
    CheckProcessDelta(NtCurrentProcess(), Process, MB_PAGES(32), "recommit 64 MB, 32 MB committed");

    /* A committed page that is touched costs nothing more */
    if (NT_SUCCESS(Status))
    {
        System = QuerySystemCommit(NULL);
        for (Address = Base; Address < (PVOID)((PUCHAR)Base + Size); Address = (PUCHAR)Address + PageSize)
            *(volatile UCHAR *)Address = 1;
        CheckSystemDelta(System, 0, "touch 64 MB");
    }

    System = QuerySystemCommit(NULL);
    Process = QueryProcessCommit(NtCurrentProcess());
    RegionSize = 0;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    CheckSystemDelta(System, -MB_PAGES(64), "release 64 MB");
    CheckProcessDelta(NtCurrentProcess(), Process, -MB_PAGES(64), "release 64 MB");

    /* A committed reservation is charged in full and given back in full */
    System = QuerySystemCommit(NULL);
    Base = NULL;
    RegionSize = Size;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    CheckSystemDelta(System, MB_PAGES(64), "reserve and commit 64 MB");
    RegionSize = 0;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    CheckSystemDelta(System, 0, "release the committed reservation");
}

static
VOID
TestProcessExit(VOID)
{
    WCHAR CommandLine[MAX_PATH + 32];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    PVOID Base = NULL;
    SIZE_T Size = 64 * 1024 * 1024;
    ULONG_PTR System, AfterCreate;
    LONG_PTR ChildBefore;
    NTSTATUS Status;
    UINT Length;

    Length = GetSystemDirectoryW(CommandLine, MAX_PATH);
    ok(Length != 0 && Length < MAX_PATH, "GetSystemDirectoryW returned %u\n", Length);
    StringCchCatW(CommandLine, _countof(CommandLine), L"\\cmd.exe /c exit");

    System = QuerySystemCommit(NULL);
    if (!CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        skip("CreateProcessW failed with %lu\n", GetLastError());
        return;
    }

    AfterCreate = QuerySystemCommit(NULL);
    ChildBefore = QueryProcessCommit(ProcessInfo.hProcess);
    Status = NtAllocateVirtualMemory(ProcessInfo.hProcess, &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    CheckSystemDelta(AfterCreate, MB_PAGES(64), "commit 64 MB in a child");
    CheckProcessDelta(ProcessInfo.hProcess, ChildBefore, MB_PAGES(64), "commit 64 MB in a child");

    Status = NtTerminateProcess(ProcessInfo.hProcess, 0x2A);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_long(WaitForSingleObject(ProcessInfo.hProcess, 30000), WAIT_OBJECT_0);

    /* The handles are still open: the address space is gone, and so is its charge */
    CheckSystemDelta(System, 0, "child terminated, handle open");

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
}

static
HANDLE
CreateTestFile(
    _In_ SIZE_T Size)
{
    WCHAR TempPath[MAX_PATH], FileName[MAX_PATH];
    LARGE_INTEGER Distance;
    HANDLE File;

    if (!GetTempPathW(_countof(TempPath), TempPath) ||
        !GetTempFileNameW(TempPath, L"cmc", 0, FileName))
    {
        return INVALID_HANDLE_VALUE;
    }

    File = CreateFileW(FileName, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return File;

    Distance.QuadPart = Size;
    if (!SetFilePointerEx(File, Distance, NULL, FILE_BEGIN) || !SetEndOfFile(File))
    {
        CloseHandle(File);
        return INVALID_HANDLE_VALUE;
    }
    return File;
}

static
VOID
TestCopyOnWriteViews(VOID)
{
    LARGE_INTEGER MaximumSize;
    HANDLE File, Section;
    PVOID Base, Address;
    SIZE_T ViewSize, Size = 16 * 1024 * 1024;
    ULONG_PTR System, AfterMap;
    NTSTATUS Status;

    /* A data file mapped copy-on-write is charged in full when it is mapped */
    File = CreateTestFile(Size);
    ok(File != INVALID_HANDLE_VALUE, "CreateTestFile failed with %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        MaximumSize.QuadPart = Size;
        Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_WRITECOPY, SEC_COMMIT, File);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            System = QuerySystemCommit(NULL);
            Base = NULL;
            ViewSize = 0;
            Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_WRITECOPY);
            ok_ntstatus(Status, STATUS_SUCCESS);
            CheckSystemDelta(System, MB_PAGES(16), "map a 16 MB file copy-on-write");

            AfterMap = QuerySystemCommit(NULL);
            if (NT_SUCCESS(Status))
            {
                for (Address = Base; Address < (PVOID)((PUCHAR)Base + Size); Address = (PUCHAR)Address + PageSize)
                    *(volatile UCHAR *)Address = 1;
            }
            CheckSystemDelta(AfterMap, 0, "write every page of the copy-on-write view");

            Status = NtUnmapViewOfSection(NtCurrentProcess(), Base);
            ok_ntstatus(Status, STATUS_SUCCESS);
            CheckSystemDelta(System, 0, "unmap the copy-on-write file view");
            NtClose(Section);
        }
        CloseHandle(File);
    }

    /* The same for a pagefile-backed section, which is charged once more for the view */
    System = QuerySystemCommit(NULL);
    MaximumSize.QuadPart = Size;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    CheckSystemDelta(System, MB_PAGES(16), "create a 16 MB pagefile-backed section");

    Base = NULL;
    ViewSize = 0;
    Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_WRITECOPY);
    ok_ntstatus(Status, STATUS_SUCCESS);
    CheckSystemDelta(System, MB_PAGES(32), "map it copy-on-write");

    Status = NtUnmapViewOfSection(NtCurrentProcess(), Base);
    ok_ntstatus(Status, STATUS_SUCCESS);
    CheckSystemDelta(System, MB_PAGES(16), "unmap the copy-on-write view");

    NtClose(Section);
    CheckSystemDelta(System, 0, "close the section");
}

static
VOID
TestSections(VOID)
{
    LARGE_INTEGER MaximumSize;
    HANDLE Section;
    PVOID Base, Address;
    SIZE_T ViewSize, RegionSize, Size = 64 * 1024 * 1024;
    ULONG_PTR System;
    NTSTATUS Status;

    /* SEC_COMMIT: charged at creation, kept by a view after the handle is closed */
    System = QuerySystemCommit(NULL);
    MaximumSize.QuadPart = Size;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        CheckSystemDelta(System, MB_PAGES(64), "create a 64 MB SEC_COMMIT section");

        Base = NULL;
        ViewSize = 0;
        Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        CheckSystemDelta(System, MB_PAGES(64), "map it read-write");

        NtClose(Section);
        CheckSystemDelta(System, MB_PAGES(64), "close the handle, the view stays");

        Status = NtUnmapViewOfSection(NtCurrentProcess(), Base);
        ok_ntstatus(Status, STATUS_SUCCESS);
        CheckSystemDelta(System, 0, "unmap the last view");
    }

    /* SEC_RESERVE: charged only for what is committed through a view */
    System = QuerySystemCommit(NULL);
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    CheckSystemDelta(System, 0, "create a 64 MB SEC_RESERVE section");

    Base = NULL;
    ViewSize = 0;
    Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Address = Base;
        RegionSize = 16 * 1024 * 1024;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        CheckSystemDelta(System, MB_PAGES(16), "commit 16 MB through the view");

        /* Committing them again costs nothing */
        Address = Base;
        RegionSize = 16 * 1024 * 1024;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        CheckSystemDelta(System, MB_PAGES(16), "commit the same 16 MB again");

        Status = NtUnmapViewOfSection(NtCurrentProcess(), Base);
        ok_ntstatus(Status, STATUS_SUCCESS);
        CheckSystemDelta(System, MB_PAGES(16), "unmap, the section keeps its pages");
    }
    NtClose(Section);
    CheckSystemDelta(System, 0, "close the SEC_RESERVE section");
}

static
VOID
TestHugeCommit(VOID)
{
#ifdef _WIN64
    PVOID Base = NULL;
    SIZE_T Size = (SIZE_T)1 << 40;
    ULONG_PTR CommitLimit;
    NTSTATUS Status;

    QuerySystemCommit(&CommitLimit);
    if ((Size / PageSize) < CommitLimit + 16 * (ULONG_PTR)PhysicalPages)
    {
        skip("1 TB is within reach of this system's commit limit\n");
        return;
    }

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_COMMITMENT_LIMIT);
    if (NT_SUCCESS(Status))
    {
        Size = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
    }
#endif
}

static
VOID
TestReporting(VOID)
{
    MEMORYSTATUSEX MemoryStatus = { sizeof(MemoryStatus) };
    ULONG_PTR CommitLimit, LimitAfter, Before, After, PagingFile, PagingAfter;
    ULONGLONG AvailLow, AvailHigh;
    QUOTA_LIMITS QuotaLimits;
    BOOL InJob = FALSE;
    NTSTATUS Status;

    Before = QuerySystemCommit(&CommitLimit);
    PagingFile = QueryPagingFilePages();
    trace("commit %Iu pages of %Iu, paging files %Iu pages, physical %lu pages\n",
          Before, CommitLimit, PagingFile, PhysicalPages);

    ok(Before <= CommitLimit, "committed %Iu above the limit %Iu\n", Before, CommitLimit);

    /*
     * As on Windows (measured on Windows 10: 2423623 = 2095943 pages of RAM + one 327680 page paging file) the
     * limit is physical memory plus the size of every paging file. Applications derive the paging file size
     * from it: GlobalMemoryStatusEx ullTotalPageFile - ullTotalPhys. No paging file: the limit is RAM.
     */
    QuerySystemCommit(&LimitAfter);
    PagingAfter = QueryPagingFilePages();
    if ((LimitAfter != CommitLimit) || (PagingAfter != PagingFile))
        skip("a paging file grew or shrank in between\n");
    else
        ok(CommitLimit == PhysicalPages + PagingFile, "limit %Iu, physical memory %lu plus paging files %Iu pages\n",
           CommitLimit, PhysicalPages, PagingFile);

    Before = QuerySystemCommit(NULL);
    ok(GlobalMemoryStatusEx(&MemoryStatus), "GlobalMemoryStatusEx failed with %lu\n", GetLastError());
    After = QuerySystemCommit(&LimitAfter);
    PagingAfter = QueryPagingFilePages();
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessQuotaLimits, &QuotaLimits, sizeof(QuotaLimits), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!IsProcessInJob(GetCurrentProcess(), NULL, &InJob))
        InJob = TRUE;
    if (!NT_SUCCESS(Status) || (QuotaLimits.PagefileLimit != (SIZE_T)-1) || InJob ||
        (LimitAfter != CommitLimit) || (PagingAfter != PagingFile))
    {
        skip("process commit quota, a job, or a paging file growth in between\n");
    }
    else
    {
        ok(MemoryStatus.ullTotalPageFile == (ULONGLONG)CommitLimit * PageSize,
           "ullTotalPageFile %I64u, commit limit %Iu pages\n", MemoryStatus.ullTotalPageFile, CommitLimit);
        ok(MemoryStatus.ullTotalPageFile - MemoryStatus.ullTotalPhys == (ULONGLONG)PagingFile * PageSize,
           "ullTotalPageFile %I64u minus ullTotalPhys %I64u, paging files %Iu pages\n",
           MemoryStatus.ullTotalPageFile, MemoryStatus.ullTotalPhys, PagingFile);

        /* Available is limit less charge: the charge moved by at most the other activity in between */
        AvailLow = (ULONGLONG)(CommitLimit - max(Before, After)) * PageSize;
        AvailHigh = (ULONGLONG)(CommitLimit - min(Before, After)) * PageSize;
        AvailLow = (AvailLow > MB_PAGES(2) * PageSize) ? AvailLow - MB_PAGES(2) * PageSize : 0;
        AvailHigh += MB_PAGES(2) * PageSize;
        ok((MemoryStatus.ullAvailPageFile >= AvailLow) && (MemoryStatus.ullAvailPageFile <= AvailHigh),
           "ullAvailPageFile %I64u, limit less charge is %I64u to %I64u\n",
           MemoryStatus.ullAvailPageFile, AvailLow, AvailHigh);
    }
    ok(MemoryStatus.ullAvailPageFile <= MemoryStatus.ullTotalPageFile,
       "ullAvailPageFile %I64u above ullTotalPageFile %I64u\n", MemoryStatus.ullAvailPageFile, MemoryStatus.ullTotalPageFile);
}

/* ReactOS only from here: these depend on the paging file policy of the test system */

/*
 * Commitment is limited by the reported commit limit, RAM plus the paging files: a request that does not fit
 * fails at the allocation with STATUS_COMMITMENT_LIMIT, a request within it succeeds, also when it is more
 * than RAM. The ranges are never touched, so the test uses no memory.
 *
 * Known gap: ARM3 private memory and paging file backed sections cannot be paged out on ReactOS (no working
 * set trimming, no modified page writer for them), so RAM less a resident headroom is all that backs them.
 * ReactOS commits less than it reports, and fails requests that Windows accepts (a request beyond what RAM
 * holds is todo). Committing more would move the failure from the allocation to a page fault, which cannot
 * fail (bugcheck 0x7A for a page table page when the pages run out).
 */
static
VOID
CommitRange(
    _In_ SIZE_T Pages,
    _In_ BOOLEAN Expected,
    _In_ BOOLEAN Todo)
{
    LARGE_INTEGER MaximumSize;
    PVOID Base = NULL;
    HANDLE Section;
    SIZE_T Size = Pages * PageSize;
    NTSTATUS Status;

#ifndef _WIN64
    if (Size >= 1536 * 1024 * 1024)
    {
        skip("%Iu MB do not fit in the user address space\n", Size / (1024 * 1024));
    }
    else
#endif
    {
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        todo_if((Todo) && is_reactos())
            ok_ntstatus(Status, Expected ? STATUS_SUCCESS : STATUS_COMMITMENT_LIMIT);
        if (NT_SUCCESS(Status))
        {
            Size = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
        }
    }

    /* The same for a paging file backed section */
    MaximumSize.QuadPart = (LONGLONG)Pages * PageSize;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    todo_if((Todo) && is_reactos())
        ok_ntstatus(Status, Expected ? STATUS_SUCCESS : STATUS_COMMITMENT_LIMIT);
    if (NT_SUCCESS(Status))
        NtClose(Section);
}

static
VOID
TestCommitBeyondRam(VOID)
{
    ULONG_PTR CommitLimit, Committed;

    Committed = QuerySystemCommit(&CommitLimit);
    trace("commit %Iu of %Iu pages, physical %lu pages, paging files %Iu pages\n",
          Committed, CommitLimit, PhysicalPages, QueryPagingFilePages());

    /* More than is left below the limit fails */
    CommitRange(CommitLimit - Committed + MB_PAGES(64), FALSE, FALSE);

    /* Inside the limit, with a little to spare: Windows commits it, also when it is more than RAM */
    if (PhysicalPages < MB_PAGES(1024))
        skip("%lu pages of RAM: the gap between the limit and what ReactOS backs is small\n", PhysicalPages);
    else
        CommitRange(CommitLimit - Committed - MB_PAGES(64), TRUE, TRUE);
}

static
VOID
TestOverCommitFails(VOID)
{
    LARGE_INTEGER MaximumSize;
    ULONG_PTR CommitLimit, LimitAfter, PagingFile;
    HANDLE Section;
    NTSTATUS Status;

    QuerySystemCommit(&CommitLimit);
    PagingFile = QueryPagingFilePages();

    /* Beyond RAM plus every paging file at its maximum (3x RAM) */
    MaximumSize.QuadPart = ((LONGLONG)CommitLimit + 4LL * PhysicalPages + MB_PAGES(1024)) * PageSize;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    ok_ntstatus(Status, STATUS_COMMITMENT_LIMIT);
    if (NT_SUCCESS(Status))
        NtClose(Section);

    QuerySystemCommit(&LimitAfter);
    ok(LimitAfter == CommitLimit, "commit limit moved from %Iu to %Iu\n", CommitLimit, LimitAfter);
    ok(QueryPagingFilePages() == PagingFile, "paging files changed from %Iu pages\n", PagingFile);

    SetLastError(0xdeadbeef);
    Section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT,
                                 (DWORD)(MaximumSize.QuadPart >> 32), (DWORD)MaximumSize.QuadPart, NULL);
    ok(Section == NULL, "CreateFileMappingW succeeded\n");
    ok_err(ERROR_COMMITMENT_LIMIT);
    if (Section)
        CloseHandle(Section);
}

static
VOID
TestGrowthAndExhaustion(VOID)
{
    static HANDLE Sections[4096];
    LARGE_INTEGER MaximumSize;
    ULONG_PTR CommitLimit, Committed, LimitStart, System, PagingStart, PagingNow;
    PVOID Base = NULL;
    SIZE_T RegionSize, Chunk;
    ULONG Count = 0, i;
    NTSTATUS Status = STATUS_SUCCESS;

    /* A committed private range to recommit at the limit */
    RegionSize = 16 * 1024 * 1024;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    System = QuerySystemCommit(&LimitStart);
    PagingStart = QueryPagingFilePages();

    /*
     * More than is left below the limit. On Windows a system managed paging file grows to make room, so the
     * section succeeds and the limit and the paging file grow by what it needed. On ReactOS RAM binds, not
     * the paging files (see above): growing them cannot make room for memory that cannot be paged out, so
     * the section fails and nothing grows.
     */
    Committed = QuerySystemCommit(&CommitLimit);
    MaximumSize.QuadPart = (LONGLONG)(CommitLimit - Committed + MB_PAGES(64)) * PageSize;
    Status = NtCreateSection(&Sections[Count], SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    QuerySystemCommit(&CommitLimit);
    PagingNow = QueryPagingFilePages();
    todo_if(is_reactos())
    {
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(CommitLimit >= LimitStart + MB_PAGES(64), "commit limit grew from %Iu to %Iu pages\n", LimitStart, CommitLimit);
        ok(PagingNow >= PagingStart + MB_PAGES(64), "paging files grew from %Iu to %Iu pages\n", PagingStart, PagingNow);
    }
    if (NT_SUCCESS(Status))
        Count++;

    /* Fill everything, in 64 MB, then 1 MB pieces */
    for (Chunk = 64; Chunk >= 1; Chunk /= 64)
    {
        while (Count < _countof(Sections))
        {
            MaximumSize.QuadPart = (LONGLONG)Chunk * 1024 * 1024;
            Status = NtCreateSection(&Sections[Count], SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL);
            if (!NT_SUCCESS(Status))
                break;
            Count++;
        }
        ok_ntstatus(Status, STATUS_COMMITMENT_LIMIT);
    }

    Committed = QuerySystemCommit(&CommitLimit);
    trace("filled: %lu sections, commit %Iu of %Iu pages, paging files %Iu pages (from %Iu)\n",
          Count, Committed, CommitLimit, QueryPagingFilePages(), PagingStart);
    /* Windows fills the limit; ReactOS stops at what RAM can back, below the reported limit (known gap) */
    todo_if(is_reactos())
        ok(CommitLimit - Committed < MB_PAGES(64), "%Iu pages left below the limit\n", CommitLimit - Committed);

    /* Committing what is committed needs nothing, even now */
    RegionSize = 16 * 1024 * 1024;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(QuerySystemCommit(NULL) <= Committed + MB_PAGES(1), "recommit at the limit charged again\n");

    for (i = 0; i < Count; i++)
        NtClose(Sections[i]);
    RegionSize = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
    CheckSystemDelta(System, -MB_PAGES(16), "everything released");
}

/* The test system's paging file: system managed ("C:\pagefile.sys 0 0" or no sizes) on a named drive */
static
BOOLEAN
IsSystemManagedPagingFile(
    _Out_ PWCHAR Drive)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management");
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"PagingFiles");
    OBJECT_ATTRIBUTES ObjectAttributes;
    static UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 1024];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    PWSTR Value, Space;
    HANDLE Key;
    ULONG Length;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&Key, KEY_QUERY_VALUE, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return FALSE;

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer) - 2 * sizeof(WCHAR), &Length);
    NtClose(Key);
    if (!NT_SUCCESS(Status) || (Info->Type != 7 /* REG_MULTI_SZ */))
        return FALSE;

    /* Exactly one entry */
    Value = (PWSTR)Info->Data;
    if ((Value[0] == UNICODE_NULL) || (Value[wcslen(Value) + 1] != UNICODE_NULL))
        return FALSE;

    /* "?:" lets smss pick any volume: the drive to check is unknown */
    if (Value[0] == L'?')
        return FALSE;
    *Drive = Value[0];
    Space = wcschr(Value, L' ');
    return (Space == NULL) || (wcscmp(Space, L" 0 0") == 0);
}

START_TEST(CommitCharge)
{
    SYSTEM_BASIC_INFORMATION BasicInfo;
    ULONG_PTR Baseline, Committed, PagingFile;
    ULARGE_INTEGER FreeBytes, TotalBytes;
    ULONG_PTR InitialPages;
    WCHAR Drive[] = L"C:\\";
    NTSTATUS Status;
    ULONG Round;

    Status = NtQuerySystemInformation(SystemBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        PageSize = BasicInfo.PageSize;
        PhysicalPages = BasicInfo.NumberOfPhysicalPages;
    }

    TestReporting();

    /* One round to warm the caches, then three measured ones; a leak shows as a trend */
    TestPrivateBalance();
    TestSections();
    TestCopyOnWriteViews();
    TestProcessExit();
    /*
     * Shortly after boot the system charge can still drop by several MB at
     * once (boot-time memory freed when the idle-priority zero page thread
     * discards INIT code): the warm-up round only prints system deltas.
     */
    StrictSystemChecks = TRUE;
    Baseline = QuerySystemCommit(NULL);
    for (Round = 0; Round < 3; Round++)
    {
        TestPrivateBalance();
        TestSections();
        TestCopyOnWriteViews();
        TestProcessExit();
        trace("after round %lu: system commit %+Id pages\n", Round + 1, (LONG_PTR)(QuerySystemCommit(NULL) - Baseline));
    }

    /* On the quiet test system a leak shows here; elsewhere other processes move the total too */
    Committed = QuerySystemCommit(NULL);
    if (is_reactos())
        ok((LONG_PTR)(Committed - Baseline) < MB_PAGES(2), "system commit grew by %Id pages over three rounds\n",
           (LONG_PTR)(Committed - Baseline));

    if (is_reactos())
    {
        TestHugeCommit();
        TestCommitBeyondRam();

        /*
         * Over-commit and growth need the test system's fixture: one
         * system-managed paging file (registry) that sits at its initial
         * size (RAM / 8, at least 512 MB; see smss) and has room to grow:
         * its maximum is 3x RAM or 4 GB, whichever is larger, limited to
         * 1/8 of the volume and to the file plus the free space smss found
         * at boot minus 256 MB. The growth test needs 64 MB plus the
         * kernel reserve (at most 32 MB). Anything else skips.
         */
        PagingFile = QueryPagingFilePages();
        InitialPages = PhysicalPages / 8;
        if (InitialPages < MB_PAGES(512))
            InitialPages = MB_PAGES(512);
        if (!IsSystemManagedPagingFile(&Drive[0]) ||
            (PagingFile > InitialPages + MB_PAGES(16)) ||
            (PhysicalPages < MB_PAGES(1024)) ||
            !GetDiskFreeSpaceExW(Drive, &FreeBytes, &TotalBytes, NULL) ||
            (FreeBytes.QuadPart < 512LL * 1024 * 1024) ||
            (TotalBytes.QuadPart / 8 < (LONGLONG)(PagingFile + MB_PAGES(128)) * PageSize))
            skip("not the growth fixture: paging files %Iu pages, physical %lu pages, drive %lc\n",
                 PagingFile, PhysicalPages, Drive[0]);
        else
        {
            TestOverCommitFails();
            TestGrowthAndExhaustion();
        }
    }
}
