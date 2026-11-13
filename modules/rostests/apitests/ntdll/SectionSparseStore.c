/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Sparse Prototype PTE store of very large reserved sections: per-process and system-wide
 *              shares of its address range, failed populates, a leaked chunk
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The limits asserted here belong to this implementation (the range of the store is 1 TB, a process may hold a
 * quarter of it, sixteen 8 TB sections); Windows' own limits were not measured, so this test is for ReactOS and
 * skips where 8 TB reserved sections cannot be created. The fault-injection tests need a Debug kernel: its
 * knobs are one-shot registry values that the kernel resets when it takes them, which is also how a test sees
 * that the kernel has them (a Release kernel leaves the value, and the test skips).
 */

#include "precomp.h"
#include <pseh/pseh2.h>

#ifndef REG_DWORD
#define REG_DWORD 4
#endif

#define SECTION_8TB         0x80000000000LL
#define SHARE_SECTIONS      16      /* sections of 8 TB one process may hold */
#define SYSTEM_SECTIONS     64      /* sections of 8 TB the whole range holds */

#define KNOB_KEY    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"
#define KNOB_FAIL   L"SparseInjectPopulateFailAt"
#define KNOB_BUSY   L"SparseInjectBusyChunk"

static LONG_PTR QueryCommit(void)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    return (LONG_PTR)Info.CommittedPages;
}

static NTSTATUS CreateHuge(PHANDLE Section, ULONG Flags)
{
    LARGE_INTEGER MaximumSize;

    MaximumSize.QuadPart = SECTION_8TB;
    return NtCreateSection(Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE | Flags, NULL);
}

static void SetKnob(PCWSTR Name, ULONG Value)
{
    NTSTATUS Status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, KNOB_KEY, Name, REG_DWORD, &Value, sizeof(Value));
    ok_ntstatus(Status, STATUS_SUCCESS);
}

static ULONG GetKnob(PCWSTR Name)
{
    ULONG Value = 0;
    RTL_QUERY_REGISTRY_TABLE Table[2] = {{ 0 }};

    Table[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    Table[0].Name = (PWSTR)Name;
    Table[0].EntryContext = &Value;
    if (!NT_SUCCESS(RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, KNOB_KEY, Table, NULL, NULL))) return 0;
    return Value;
}

static BOOLEAN WaitKnobTaken(PCWSTR Name, ULONG Milliseconds)
{
    ULONG i;

    for (i = 0; i <= Milliseconds / 50; i++)
    {
        if (GetKnob(Name) == 0) return TRUE;
        Sleep(50);
    }
    return FALSE;
}

/* Map Size bytes of the section at Offset; CommitSize is the commit made by the map itself */
static NTSTATUS MapAt(HANDLE Section, LONGLONG Offset, SIZE_T Size, SIZE_T CommitSize, PVOID *Base)
{
    LARGE_INTEGER SectionOffset;
    SIZE_T ViewSize = Size;

    *Base = NULL;
    SectionOffset.QuadPart = Offset;
    return NtMapViewOfSection(Section, NtCurrentProcess(), Base, 0, CommitSize, &SectionOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
}

static NTSTATUS Commit(PVOID Base, SIZE_T Size)
{
    PVOID Address = Base;

    return NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
}

static NTSTATUS Touch(PVOID Address, UCHAR Value)
{
    NTSTATUS Status = STATUS_SUCCESS;

    _SEH2_TRY
    {
        *(volatile UCHAR *)Address = Value;
        if (*(volatile UCHAR *)Address != Value) Status = STATUS_DATA_ERROR;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    return Status;
}

/* Create 8 TB sections until one fails or Max are made; the handles go to Handles */
static ULONG CreateMany(HANDLE *Handles, ULONG Max, NTSTATUS *LastStatus)
{
    ULONG Count = 0;

    *LastStatus = STATUS_SUCCESS;
    while (Count < Max)
    {
        *LastStatus = CreateHuge(&Handles[Count], 0);
        if (!NT_SUCCESS(*LastStatus)) break;
        Count++;
    }
    return Count;
}

static void CloseMany(HANDLE *Handles, ULONG Count)
{
    while (Count--) NtClose(Handles[Count]);
}

/* A section creation that waits a moment for a closed section to be gone (deletion can run on a worker) */
static NTSTATUS CreateHugeRetry(PHANDLE Section)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;

    for (i = 0; i < 100; i++)
    {
        Status = CreateHuge(Section, 0);
        if (NT_SUCCESS(Status)) break;
        Sleep(50);
    }
    return Status;
}

static BOOLEAN HugeSectionsAvailable(void)
{
    HANDLE Section;
    NTSTATUS Status;

    if (GetNTVersion() < _WIN32_WINNT_WIN10) return FALSE;
    Status = CreateHuge(&Section, 0);
    if (!NT_SUCCESS(Status)) return FALSE;
    NtClose(Section);
    return TRUE;
}

/* A process holds a quarter of the range, then is refused; closing one gives its share back */
static void Test_ProcessShare(void)
{
    HANDLE Handles[SHARE_SECTIONS + 4], Extra;
    NTSTATUS Status;
    ULONG Count;

    Count = CreateMany(Handles, _countof(Handles), &Status);
    trace("%lu sections of 8 TB, then 0x%lx\n", Count, Status);
    ok(Count == SHARE_SECTIONS, "%lu sections of 8 TB created\n", Count);
    ok_ntstatus(Status, STATUS_INSUFFICIENT_RESOURCES);

    /* Refused for a smaller reserve as well: the share counts chunks, not sections */
    {
        LARGE_INTEGER MaximumSize;

        MaximumSize.QuadPart = SECTION_8TB / 2;
        Status = NtCreateSection(&Extra, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
        ok_ntstatus(Status, STATUS_INSUFFICIENT_RESOURCES);
        if (NT_SUCCESS(Status)) NtClose(Extra);
    }

    /* A section that is not sparse is not counted */
    {
        LARGE_INTEGER MaximumSize;

        MaximumSize.QuadPart = 0x10000;
        Status = NtCreateSection(&Extra, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status)) NtClose(Extra);
    }

    if (Count)
    {
        NtClose(Handles[--Count]);
        Status = CreateHugeRetry(&Extra);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status)) NtClose(Extra);
    }
    CloseMany(Handles, Count);

    /* All gone: the process can hold its share again */
    Count = CreateMany(Handles, _countof(Handles), &Status);
    ok(Count == SHARE_SECTIONS, "%lu sections of 8 TB created after closing all\n", Count);
    CloseMany(Handles, Count);
}

/* Child processes: this executable, run with the test name SectionSparseChild and the mode in the environment */
static HANDLE StartChild(PCWSTR Mode, PCWSTR Id, HANDLE *Ready, HANDLE *Go)
{
    WCHAR Path[MAX_PATH], Command[MAX_PATH + 64], Name[64];
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Info;
    BOOL Started;

    StringCchPrintfW(Name, _countof(Name), L"SparseStoreReady%s", Id);
    *Ready = CreateEventW(NULL, TRUE, FALSE, Name);
    StringCchPrintfW(Name, _countof(Name), L"SparseStoreGo%s", Id);
    *Go = CreateEventW(NULL, TRUE, FALSE, Name);
    SetEnvironmentVariableW(L"SPARSESTORE_MODE", Mode);
    SetEnvironmentVariableW(L"SPARSESTORE_ID", Id);
    GetModuleFileNameW(NULL, Path, _countof(Path));
    StringCchPrintfW(Command, _countof(Command), L"\"%s\" SectionSparseChild", Path);
    Started = CreateProcessW(NULL, Command, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Info);
    /* Only the child may see them: this process runs the helper test too when all tests are run */
    SetEnvironmentVariableW(L"SPARSESTORE_MODE", NULL);
    SetEnvironmentVariableW(L"SPARSESTORE_ID", NULL);
    if (!Started)
    {
        ok(0, "CreateProcess failed: %lu\n", GetLastError());
        return NULL;
    }
    CloseHandle(Info.hThread);
    return Info.hProcess;
}

/* The ready event, or the process ending first (its exit code is the count it made) */
static BOOLEAN WaitChildReady(HANDLE Process, HANDLE Ready, PULONG ExitCode)
{
    HANDLE Handles[2] = { Ready, Process };
    DWORD Wait = WaitForMultipleObjects(2, Handles, FALSE, 300000);

    if (Wait == WAIT_OBJECT_0) return TRUE;
    *ExitCode = 0xDEAD;
    if (Wait == WAIT_OBJECT_0 + 1) GetExitCodeProcess(Process, (PDWORD)ExitCode);
    return FALSE;
}

/* Four processes hold their share each, the range is full for the fifth; one leaves and it is free again */
static void Test_SystemShare(void)
{
    HANDLE Process[SYSTEM_SECTIONS / SHARE_SECTIONS] = { NULL }, Ready[_countof(Process)] = { NULL }, Go[_countof(Process)] = { NULL };
    HANDLE Section, Small;
    LARGE_INTEGER MaximumSize;
    NTSTATUS Status;
    ULONG i, Code, Started = 0;
    WCHAR Id[32];
    BOOLEAN AllReady = TRUE;

    for (i = 0; i < _countof(Process); i++)
    {
        StringCchPrintfW(Id, _countof(Id), L"S%lu_%lu", GetCurrentProcessId(), i);
        Process[i] = StartChild(L"hold", Id, &Ready[i], &Go[i]);
        if (!Process[i]) { AllReady = FALSE; break; }
        Started++;
        if (!WaitChildReady(Process[i], Ready[i], &Code))
        {
            ok(0, "child %lu made %lu sections of 8 TB\n", i, Code);
            AllReady = FALSE;
        }
    }

    if (AllReady)
    {
        /* Nothing of this process: the range itself is full (also for a 4 GB reserve) */
        Status = CreateHuge(&Section, 0);
        ok_ntstatus(Status, STATUS_INSUFFICIENT_RESOURCES);
        if (NT_SUCCESS(Status)) NtClose(Section);
        MaximumSize.QuadPart = 0x100000000LL;
        Status = NtCreateSection(&Small, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
        ok_ntstatus(Status, STATUS_INSUFFICIENT_RESOURCES);
        if (NT_SUCCESS(Status)) NtClose(Small);

        /* One process leaves: its share is free for this one */
        SetEvent(Go[0]);
        WaitForSingleObject(Process[0], 60000);
        Status = CreateHugeRetry(&Section);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status)) NtClose(Section);
    }

    for (i = 0; i < Started; i++)
    {
        SetEvent(Go[i]);
        WaitForSingleObject(Process[i], 60000);
        Code = 0xDEAD;
        GetExitCodeProcess(Process[i], (PDWORD)&Code);
        ok(Code == SHARE_SECTIONS, "child %lu exit code %lu\n", i, Code);
        CloseHandle(Process[i]);
        CloseHandle(Ready[i]);
        CloseHandle(Go[i]);
    }
}

/* Debug kernel: the Nth store page of a populate cannot be had; what was made stays, nothing else is lost */
static void Test_PopulateFailure(void)
{
    HANDLE Section;
    PVOID View;
    NTSTATUS Status;
    LONG_PTR Before, After;
    ULONG Fail;
    /* 4 MB at the start of a fresh 1 GB: a page table and two pages of Prototype PTEs */
    const SIZE_T Size = 0x400000;

    Status = CreateHuge(&Section, 0);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;

    /* Is the knob taken at all? */
    Status = MapAt(Section, 0x40000000LL, Size, 0, &View);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        NtClose(Section);
        return;
    }
    SetKnob(KNOB_FAIL, 1);
    Status = Commit(View, Size);
    if (GetKnob(KNOB_FAIL) != 0)
    {
        SetKnob(KNOB_FAIL, 0);
        skip("this kernel has no fault injection (Release build)\n");
        NtUnmapViewOfSection(NtCurrentProcess(), View);
        NtClose(Section);
        return;
    }
    NtUnmapViewOfSection(NtCurrentProcess(), View);

    /* Fail the 1st, 2nd and 3rd page of the populate (the table, then the pages): the commit fails, whatever was
     * made is charged and kept, the rest of the charge is returned; the same commit works afterwards */
    for (Fail = 1; Fail <= 3; Fail++)
    {
        LONGLONG Offset = 0x40000000LL * (Fail + 1);
        LONG_PTR Kept = (LONG_PTR)(Fail - 1);

        Status = MapAt(Section, Offset, Size, 0, &View);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status)) continue;

        Before = QueryCommit();
        SetKnob(KNOB_FAIL, Fail);
        Status = Commit(View, Size);
        After = QueryCommit();
        ok_ntstatus(Status, STATUS_NO_MEMORY);
        ok(GetKnob(KNOB_FAIL) == 0, "knob %lu not taken\n", Fail);
        ok((After - Before) >= Kept && (After - Before) <= Kept + 16, "fail at %lu: commit moved by %Id pages, %Id kept\n", Fail, After - Before, Kept);
        ok(Touch(View, 1) == STATUS_ACCESS_VIOLATION, "fail at %lu: the page was not committed\n", Fail);

        Before = QueryCommit();
        Status = Commit(View, Size);
        After = QueryCommit();
        ok_ntstatus(Status, STATUS_SUCCESS);
        /* 1024 section pages, and the store pages and table that the failed commit did not make */
        ok((After - Before) >= 1024 && (After - Before) <= 1024 + 3 - Kept + 16, "fail at %lu: retry charged %Id pages\n", Fail, After - Before);
        ok(Touch(View, 0x51) == STATUS_SUCCESS, "fail at %lu: first page after the retry\n", Fail);
        ok(Touch((PUCHAR)View + Size - PAGE_SIZE, 0x52) == STATUS_SUCCESS, "fail at %lu: last page after the retry\n", Fail);
        NtUnmapViewOfSection(NtCurrentProcess(), View);
    }

    /* The same through a map with a commit size: the view is not made, nothing but what was kept stays charged */
    Before = QueryCommit();
    SetKnob(KNOB_FAIL, 2);
    Status = MapAt(Section, 0x40000000LL * 8, Size, Size, &View);
    After = QueryCommit();
    ok_ntstatus(Status, STATUS_NO_MEMORY);
    ok(GetKnob(KNOB_FAIL) == 0, "map: knob not taken\n");
    ok((After - Before) >= 1 && (After - Before) <= 1 + 16, "map: commit moved by %Id pages\n", After - Before);
    if (NT_SUCCESS(Status)) NtUnmapViewOfSection(NtCurrentProcess(), View);
    Status = MapAt(Section, 0x40000000LL * 8, Size, Size, &View);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(Touch(View, 0x61) == STATUS_SUCCESS, "map retry: first page\n");
        NtUnmapViewOfSection(NtCurrentProcess(), View);
    }

    /* Closing returns all of it, the pages that were kept included: 4 x 1024 section pages, 4 tables, 8 store pages */
    Before = QueryCommit();
    NtClose(Section);
    After = QueryCommit();
    ok((Before - After) >= 4 * 1024, "close returned %Id pages\n", Before - After);
}

/* Child: "hold" keeps its share of sections until told, "leak" leaks one chunk and counts what is left of its share */
static ULONG ChildHold(PCWSTR Id)
{
    HANDLE Handles[SHARE_SECTIONS + 4], Ready, Go;
    WCHAR Name[64];
    NTSTATUS Status;
    ULONG Count;

    StringCchPrintfW(Name, _countof(Name), L"SparseStoreReady%s", Id);
    Ready = OpenEventW(EVENT_ALL_ACCESS, FALSE, Name);
    StringCchPrintfW(Name, _countof(Name), L"SparseStoreGo%s", Id);
    Go = OpenEventW(EVENT_ALL_ACCESS, FALSE, Name);
    if (!Ready || !Go) return 0xBAD;

    Count = CreateMany(Handles, _countof(Handles), &Status);
    if (Count == SHARE_SECTIONS)
    {
        SetEvent(Ready);
        WaitForSingleObject(Go, 300000);
    }
    CloseMany(Handles, Count);
    return Count;
}

static ULONG ChildLeak(void)
{
    HANDLE Section, Handles[SHARE_SECTIONS + 4];
    LARGE_INTEGER MaximumSize;
    PVOID View;
    NTSTATUS Status;
    ULONG Count;

    /* 4 GB: sparse, four chunks; one committed page populates the first chunk's table */
    MaximumSize.QuadPart = 0x100000000LL;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
    if (!NT_SUCCESS(Status)) return 0xBAD;
    Status = MapAt(Section, 0, 0x10000, 0, &View);
    if (!NT_SUCCESS(Status)) return 0xBAD;
    Status = Commit(View, PAGE_SIZE);
    NtUnmapViewOfSection(NtCurrentProcess(), View);
    if (!NT_SUCCESS(Status)) return 0xBAD;

    /* The first table freed is reported as still referenced */
    SetKnob(KNOB_BUSY, 1);
    NtClose(Section);
    if (!WaitKnobTaken(KNOB_BUSY, 10000))
    {
        SetKnob(KNOB_BUSY, 0);
        return 0x5C1;   /* no fault injection */
    }
    Sleep(500);

    Count = CreateMany(Handles, _countof(Handles), &Status);
    CloseMany(Handles, Count);
    return Count;
}

static void Test_LeakedChunk(void)
{
    HANDLE Process, Ready, Go;
    DWORD Code = 0xDEAD;

    Process = StartChild(L"leak", L"L", &Ready, &Go);
    if (!Process) return;
    WaitForSingleObject(Process, 300000);
    GetExitCodeProcess(Process, &Code);
    CloseHandle(Process);
    CloseHandle(Ready);
    CloseHandle(Go);
    if (Code == 0x5C1)
    {
        skip("this kernel has no fault injection (Release build)\n");
        return;
    }
    /* The leaked chunk is still the owner's: one 8 TB section fewer fits in its share */
    ok(Code == SHARE_SECTIONS - 1, "a process with a leaked chunk holds %lu sections of 8 TB, expected %d\n", Code, SHARE_SECTIONS - 1);
}

START_TEST(SectionSparseStore)
{
    if (!HugeSectionsAvailable())
    {
        skip("8 TB reserved sections are not available\n");
        return;
    }
    Test_ProcessShare();
    Test_SystemShare();
    Test_PopulateFailure();
    Test_LeakedChunk();
}

START_TEST(SectionSparseChild)
{
    WCHAR Mode[16] = L"", Id[32] = L"";
    ULONG Code = 0xBAD;

    if (!GetEnvironmentVariableW(L"SPARSESTORE_MODE", Mode, _countof(Mode)) ||
        !GetEnvironmentVariableW(L"SPARSESTORE_ID", Id, _countof(Id)))
    {
        skip("helper of SectionSparseStore\n");
        return;
    }
    if (!wcscmp(Mode, L"hold")) Code = ChildHold(Id);
    else if (!wcscmp(Mode, L"leak")) Code = ChildLeak();
    ExitProcess(Code);
}
