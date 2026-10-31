/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Pages of a pagefile-backed section go back to the system with the section
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Each cycle creates a section backed by the pagefile, maps a view, writes one page, unmaps the view
   and closes the section. Once both are gone the memory manager owes the system every page the cycle
   used. ReactOS lost one page per cycle: the page that held the section's prototype PTEs stayed in
   use after the segment was freed, because the data page never dropped the share count it held on
   it. Thousands of cycles move the available page count by thousands of pages; system activity
   moves it by far less. */

#define CYCLES      5000
#define WARMUP      200
#define TOLERANCE   512

typedef enum _VARIANT
{
    CommitUnmapClose,
    ReserveCommitUnmapClose,
    CommitCloseUnmap,
    CommitOtherProcess,
} VARIANT;

static const char *VariantName[] =
{
    "SEC_COMMIT, unmap then close",
    "SEC_RESERVE + commit, unmap then close",
    "SEC_COMMIT, close then unmap",
    "SEC_COMMIT, view in a second process",
};

static LONG_PTR AvailablePages(VOID)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? (LONG_PTR)Info.AvailablePages : 0;
}

static BOOLEAN Cycle(VARIANT Variant, HANDLE Process)
{
    HANDLE Section;
    LARGE_INTEGER Size;
    PVOID Base = NULL;
    SIZE_T ViewSize = 0, CommitSize = PAGE_SIZE, Written;
    UCHAR Byte = 0x5A;
    NTSTATUS Status;

    /* The prototype PTEs of a section this size fill pages of their own, on every architecture */
    Size.QuadPart = 16 << 20;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &Size, PAGE_READWRITE,
                             (Variant == ReserveCommitUnmapClose) ? SEC_RESERVE : SEC_COMMIT, NULL);
    if (!NT_SUCCESS(Status))
    {
        ok(0, "NtCreateSection failed: 0x%lx\n", Status);
        return FALSE;
    }

    Status = NtMapViewOfSection(Section, Process, &Base, 0, 0, NULL, &ViewSize,
                                ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
    {
        ok(0, "NtMapViewOfSection failed: 0x%lx\n", Status);
        NtClose(Section);
        return FALSE;
    }

    if (Variant == ReserveCommitUnmapClose)
    {
        PVOID CommitBase = Base;

        Status = NtAllocateVirtualMemory(Process, &CommitBase, 0, &CommitSize,
                                         MEM_COMMIT, PAGE_READWRITE);
        if (!NT_SUCCESS(Status))
        {
            ok(0, "NtAllocateVirtualMemory failed: 0x%lx\n", Status);
            NtUnmapViewOfSection(Process, Base);
            NtClose(Section);
            return FALSE;
        }
    }

    /* The write faults the page in, in whichever process maps the view */
    if (Process == NtCurrentProcess())
    {
        *(volatile UCHAR *)Base = Byte;
        Status = STATUS_SUCCESS;
    }
    else
    {
        Status = NtWriteVirtualMemory(Process, Base, &Byte, sizeof(Byte), &Written);
        if (!NT_SUCCESS(Status))
            ok(0, "NtWriteVirtualMemory failed: 0x%lx\n", Status);
    }

    if (Variant == CommitCloseUnmap)
    {
        NtClose(Section);
        NtUnmapViewOfSection(Process, Base);
    }
    else
    {
        NtUnmapViewOfSection(Process, Base);
        NtClose(Section);
    }

    return NT_SUCCESS(Status);
}

static VOID TestVariant(VARIANT Variant, HANDLE Process)
{
    LONG_PTR Before, After;
    ULONG i;

    for (i = 0; i < WARMUP; i++)
    {
        if (!Cycle(Variant, Process))
            return;
    }

    Sleep(100);
    Before = AvailablePages();
    for (i = 0; i < CYCLES; i++)
    {
        if (!Cycle(Variant, Process))
            return;
    }
    Sleep(100);
    After = AvailablePages();

    trace("%s: available pages %ld -> %ld over %u cycles\n", VariantName[Variant], (long)Before, (long)After, CYCLES);
    ok(Before - After < TOLERANCE, "%s: %ld pages lost over %u cycles\n",
       VariantName[Variant], (long)(Before - After), CYCLES);
}

START_TEST(SectionPageLeak)
{
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    WCHAR Path[MAX_PATH];

    TestVariant(CommitUnmapClose, NtCurrentProcess());
    TestVariant(ReserveCommitUnmapClose, NtCurrentProcess());
    TestVariant(CommitCloseUnmap, NtCurrentProcess());

    /* A suspended copy of this program holds the views of the last variant */
    GetModuleFileNameW(NULL, Path, _countof(Path));
    if (!CreateProcessW(Path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL,
                        &StartupInfo, &ProcessInfo))
    {
        skip("CreateProcessW failed: %lu\n", GetLastError());
        return;
    }
    TestVariant(CommitOtherProcess, ProcessInfo.hProcess);
    TerminateProcess(ProcessInfo.hProcess, 0);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
}
