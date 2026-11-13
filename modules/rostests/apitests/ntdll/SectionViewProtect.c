/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Protection changes and commits in views of page-file sections; very large reserved sections
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <pseh/pseh2.h>

static const ULONG Protections[] =
{
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
};

/* Read 1, write 2, execute 4; copy-on-write counts as read */
static ULONG AccessOf(ULONG Protect)
{
    switch (Protect)
    {
        case PAGE_READONLY: case PAGE_WRITECOPY: return 1;
        case PAGE_READWRITE: return 3;
        case PAGE_EXECUTE: case PAGE_EXECUTE_READ: case PAGE_EXECUTE_WRITECOPY: return 5;
        case PAGE_EXECUTE_READWRITE: return 7;
        default: return 0;
    }
}

/*
 * VirtualProtect: "For mapped views, this value must be compatible with the access protection specified when
 * the view was mapped". Windows 10 x64 fails both NtProtectVirtualMemory and NtAllocateVirtualMemory(MEM_COMMIT)
 * with STATUS_SECTION_PROTECTION for a PAGE_NOACCESS view (oracle); the full table follows the rule Wine's
 * kernel32 tests check on Windows (requested access a subset of the view's).
 */
static void Test_ViewProtect(ULONG SectionFlags)
{
    LARGE_INTEGER MaximumSize, Offset;
    HANDLE Section;
    NTSTATUS Status, Expected;
    PVOID Base, Address;
    SIZE_T ViewSize, Size;
    ULONG v, p, OldProtect;

    MaximumSize.QuadPart = 0x10000;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SectionFlags, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;

    for (v = 0; v < _countof(Protections); v++)
    {
        Base = NULL;
        Offset.QuadPart = 0;
        ViewSize = 0x10000;
        Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0, 0, &Offset, &ViewSize, ViewShare, 0, Protections[v]);
        ok(Status == STATUS_SUCCESS, "view 0x%lx: map 0x%lx\n", Protections[v], Status);
        if (!NT_SUCCESS(Status)) continue;

        /* The protection-change leg needs a committed page also in a reserved section: PAGE_NOACCESS fits every view */
        Address = (PUCHAR)Base + PAGE_SIZE;
        Size = PAGE_SIZE;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, PAGE_NOACCESS);
        ok(Status == STATUS_SUCCESS, "view 0x%lx (0x%lx): commit PAGE_NOACCESS: 0x%lx\n", Protections[v], SectionFlags, Status);

        for (p = 0; p < _countof(Protections); p++)
        {
            Expected = ((AccessOf(Protections[p]) & ~AccessOf(Protections[v])) == 0) ? STATUS_SUCCESS : STATUS_SECTION_PROTECTION;

            /* Commit first: a protection change needs committed pages */
            Address = Base;
            Size = PAGE_SIZE;
            Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, Protections[p]);
            ok(Status == Expected, "view 0x%lx (0x%lx): commit 0x%lx: 0x%lx, expected 0x%lx\n",
               Protections[v], SectionFlags, Protections[p], Status, Expected);

            Address = (PUCHAR)Base + PAGE_SIZE;
            Size = PAGE_SIZE;
            OldProtect = 0xdeadbeef;
            Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, Protections[p], &OldProtect);
            ok(Status == Expected, "view 0x%lx (0x%lx): protect 0x%lx: 0x%lx, expected 0x%lx\n",
               Protections[v], SectionFlags, Protections[p], Status, Expected);
        }

        /* Whatever was refused, a view without write access still cannot be written (a copy-on-write view can) */
        if (!(AccessOf(Protections[v]) & 2) &&
            (Protections[v] != PAGE_WRITECOPY) && (Protections[v] != PAGE_EXECUTE_WRITECOPY))
        {
            Status = STATUS_SUCCESS;
            _SEH2_TRY
            {
                *(volatile UCHAR *)Base = 1;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            ok(Status == STATUS_ACCESS_VIOLATION, "view 0x%lx (0x%lx): write 0x%lx\n", Protections[v], SectionFlags, Status);
        }

        Status = NtUnmapViewOfSection(NtCurrentProcess(), Base);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
    NtClose(Section);
}

#ifdef _WIN64
static LONG_PTR QueryCommit(void)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    return Info.CommittedPages;
}

static void QueryMemory(LONG_PTR *Committed, LONG_PTR *Limit, LONG_PTR *Available)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    *Committed = Info.CommittedPages;
    *Limit = Info.CommitLimit;
    *Available = Info.AvailablePages;
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

/* Map 64 KB at Offset, commit one page there, write and read it back */
static PVOID MapAndTouch(HANDLE Section, LONGLONG SectionOffset, UCHAR Value)
{
    LARGE_INTEGER Offset;
    NTSTATUS Status;
    PVOID Base = NULL, Address;
    SIZE_T ViewSize = 0x10000, Size = PAGE_SIZE;

    Offset.QuadPart = SectionOffset;
    Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0, 0, &Offset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    ok(Status == STATUS_SUCCESS, "map at 0x%I64x: 0x%lx\n", SectionOffset, Status);
    if (!NT_SUCCESS(Status)) return NULL;

    Address = Base;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
    ok(Status == STATUS_SUCCESS, "commit at 0x%I64x: 0x%lx\n", SectionOffset, Status);
    if (NT_SUCCESS(Status))
    {
        Status = STATUS_SUCCESS;
        _SEH2_TRY
        {
            ((volatile UCHAR *)Base)[0x123] = Value;
            ok(((volatile UCHAR *)Base)[0x123] == Value, "at 0x%I64x: read back\n", SectionOffset);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
        ok(Status == STATUS_SUCCESS, "at 0x%I64x: access 0x%lx\n", SectionOffset, Status);
    }

    /* The next page of the view is only reserved */
    Status = STATUS_SUCCESS;
    _SEH2_TRY
    {
        (void)((volatile UCHAR *)Base)[PAGE_SIZE];
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    ok(Status == STATUS_ACCESS_VIOLATION, "at 0x%I64x + page: 0x%lx\n", SectionOffset, Status);
    return Base;
}

static void Test_HugeReserve(void)
{
    static const LONGLONG Offsets[] = { 0, 0x40010000LL, 0x40000000000LL, 0x80000000000LL - 0x10000 };
    LARGE_INTEGER MaximumSize, Offset;
    HANDLE Section, Section2;
    NTSTATUS Status;
    PVOID Views[_countof(Offsets)], Base;
    SIZE_T ViewSize;
    LONG_PTR Before, After;
    ULONG i;

    if (GetNTVersion() < _WIN32_WINNT_WIN10)
    {
        skip("8 TB sections need Windows 10\n");
        return;
    }

    /* 8 TB and 128 TB (oracle, Windows 10 x64) */
    Before = QueryCommit();
    MaximumSize.QuadPart = 0x80000000000LL;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    After = QueryCommit();
    ok((After - Before) < 64, "8 TB reserve charged %Id pages\n", After - Before);

    MaximumSize.QuadPart = 0x800000000000LL;
    Status = NtCreateSection(&Section2, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
    ok_ntstatus(Status, STATUS_SECTION_TOO_BIG);
    if (NT_SUCCESS(Status)) NtClose(Section2);

    /* Between them Windows was not measured: record what this system does */
    MaximumSize.QuadPart = 0x80000000000LL + PAGE_SIZE;
    Status = NtCreateSection(&Section2, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
    trace("8 TB + 4 KB SEC_RESERVE: 0x%lx\n", Status);
    if (NT_SUCCESS(Status)) NtClose(Section2);

    /* Pages far apart, each committed on its own: one page of commit each */
    Before = QueryCommit();
    for (i = 0; i < _countof(Offsets); i++)
        Views[i] = MapAndTouch(Section, Offsets[i], (UCHAR)(0x40 + i));
    After = QueryCommit();
    ok((After - Before) >= (LONG_PTR)_countof(Offsets) && (After - Before) < 64 + (LONG_PTR)_countof(Offsets),
       "4 committed pages charged %Id pages\n", After - Before);

    /* A second view of the last offset sees the same page */
    Base = NULL;
    Offset.QuadPart = Offsets[_countof(Offsets) - 1];
    ViewSize = 0x10000;
    Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0, 0, &Offset, &ViewSize, ViewShare, 0, PAGE_READONLY);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(((volatile UCHAR *)Base)[0x123] == 0x40 + _countof(Offsets) - 1, "second view: 0x%x\n", ((volatile UCHAR *)Base)[0x123]);
        NtUnmapViewOfSection(NtCurrentProcess(), Base);
    }

    for (i = 0; i < _countof(Offsets); i++)
        if (Views[i]) NtUnmapViewOfSection(NtCurrentProcess(), Views[i]);

    /* The section still holds its committed pages: map again, the data is there */
    Base = MapAndTouch(Section, Offsets[2], 0x55);
    if (Base) NtUnmapViewOfSection(NtCurrentProcess(), Base);

    /*
     * A commit range across a store page (2 MB of section) and a store table (1 GB) boundary: 32 pages from
     * 1 GB - 64 KB; then the same range again (all committed: no charge); a view mapped with a commit size
     */
    {
        PUCHAR View = NULL;
        PVOID Address;
        SIZE_T Size = 0x20000;

        Offset.QuadPart = 0x40000000LL - 0x10000;
        ViewSize = 0x20000;
        Status = NtMapViewOfSection(Section, NtCurrentProcess(), (PVOID *)&View, 0, 0, &Offset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            Before = QueryCommit();
            Address = View;
            Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
            ok_ntstatus(Status, STATUS_SUCCESS);
            After = QueryCommit();
            /* 32 pages, and at most a few store pages and tables */
            ok((After - Before) >= 32 && (After - Before) <= 32 + 4 + 16, "32 pages across 1 GB charged %Id pages\n", After - Before);
            ok(Touch(View, 0x11) == STATUS_SUCCESS, "first page\n");
            ok(Touch(View + 0x10000, 0x12) == STATUS_SUCCESS, "page at 1 GB\n");
            ok(Touch(View + 0x1F000, 0x13) == STATUS_SUCCESS, "last page\n");

            Before = QueryCommit();
            Address = View;
            Size = 0x20000;
            Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, PAGE_READONLY);
            ok_ntstatus(Status, STATUS_SUCCESS);
            After = QueryCommit();
            ok((After - Before) < 16, "re-commit charged %Id pages\n", After - Before);
            ok(View[0] == 0x11 && View[0x10000] == 0x12, "data after re-commit\n");
            NtUnmapViewOfSection(NtCurrentProcess(), View);
        }

        View = NULL;
        Offset.QuadPart = 0x20000000000LL;
        ViewSize = 0x10000;
        Before = QueryCommit();
        Status = NtMapViewOfSection(Section, NtCurrentProcess(), (PVOID *)&View, 0, 0x10000, &Offset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            After = QueryCommit();
            ok((After - Before) >= 16 && (After - Before) <= 16 + 2 + 16, "map with commit size charged %Id pages\n", After - Before);
            ok(Touch(View, 0x21) == STATUS_SUCCESS, "first page of a view mapped with a commit size\n");
            ok(Touch(View + 0xF000, 0x22) == STATUS_SUCCESS, "last page of a view mapped with a commit size\n");
            NtUnmapViewOfSection(NtCurrentProcess(), View);
        }
    }

    /* Closing gives the commit back, also what the store pages were charged */
    Before = QueryCommit();
    NtClose(Section);
    After = QueryCommit();
    ok((Before - After) >= (LONG_PTR)_countof(Offsets) + 48, "close returned %Id pages\n", Before - After);

    /* Many in turn: the address range for the Prototype PTEs is reused, the store pages and their charge go back */
    Before = QueryCommit();
    for (i = 0; i < 200; i++)
    {
        MaximumSize.QuadPart = 0x80000000000LL;
        Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
        ok(Status == STATUS_SUCCESS, "round %lu: 0x%lx\n", i, Status);
        if (!NT_SUCCESS(Status)) break;
        Base = MapAndTouch(Section, 0x7000000000LL + (LONGLONG)(i % 64) * 0x40000000LL, (UCHAR)i);
        if (Base) NtUnmapViewOfSection(NtCurrentProcess(), Base);
        NtClose(Section);
    }
    After = QueryCommit();
    ok((After - Before) < 64, "200 sections with a committed page each: commit moved by %Id pages\n", After - Before);

    /* A few at once */
    {
        HANDLE Sections[16];
        ULONG Count = 0;

        for (i = 0; i < _countof(Sections); i++)
        {
            MaximumSize.QuadPart = 0x80000000000LL;
            Status = NtCreateSection(&Sections[i], SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
            ok(Status == STATUS_SUCCESS, "section %lu: 0x%lx\n", i, Status);
            if (!NT_SUCCESS(Status)) break;
            Count++;
        }
        for (i = 0; i < Count; i++)
        {
            Base = MapAndTouch(Sections[i], 0x10000000000LL * (i % 8), (UCHAR)(0x80 + i));
            if (Base) NtUnmapViewOfSection(NtCurrentProcess(), Base);
        }
        for (i = 0; i < Count; i++) NtClose(Sections[i]);
    }
}

/*
 * One page committed per 2 MB of an 8 TB reserved section: every commit also makes a page of Prototype PTEs
 * resident. The store pages are charged like the section pages, so this ends with STATUS_COMMITMENT_LIMIT
 * while physical memory is still available, and all of it comes back when the section is closed.
 */
static void Test_CommitToLimit(void)
{
    LARGE_INTEGER MaximumSize, Offset;
    LONG_PTR Committed0, Limit0, Available0, Committed, Limit, Available, Committed2, Limit2, Available2, Cap;
    HANDLE Section;
    NTSTATUS Status = STATUS_SUCCESS;
    PUCHAR View = NULL;
    PVOID Address, Private;
    SIZE_T ViewSize, Size, i, Count = 0;
    SYSTEM_BASIC_INFORMATION Basic;

    if (GetNTVersion() < _WIN32_WINNT_WIN10)
    {
        skip("8 TB sections need Windows 10\n");
        return;
    }
    Status = NtQuerySystemInformation(SystemBasicInformation, &Basic, sizeof(Basic), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);

    QueryMemory(&Committed0, &Limit0, &Available0);
    MaximumSize.QuadPart = 0x80000000000LL;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;

    /* 4 TB view: 2 M strides of 2 MB, far more than any commit limit allows */
    Offset.QuadPart = 0;
    ViewSize = 0x40000000000LL;
    Status = NtMapViewOfSection(Section, NtCurrentProcess(), (PVOID *)&View, 0, 0, &Offset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < ViewSize / 0x200000; i++)
        {
            Address = View + i * 0x200000;
            Size = PAGE_SIZE;
            Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
            if (!NT_SUCCESS(Status)) break;
            Count++;
        }
        QueryMemory(&Committed, &Limit, &Available);
        trace("%Iu strides committed, then 0x%lx; commit %Id of %Id pages, available %Id of %lu physical pages (before: commit %Id, available %Id)\n",
              Count, Status, Committed, Limit, Available, Basic.NumberOfPhysicalPages, Committed0, Available0);
        ok_ntstatus(Status, STATUS_COMMITMENT_LIMIT);
        ok(Count > 1000, "only %Iu strides\n", Count);
        /*
         * The failure comes from the cap on resident store pages, 1/32 of physical memory (tables on top, one
         * per 512 strides; a few pages of slack for other consumers), long before the commit limit: the
         * system-wide pin is bounded by the cap, not by half the commit ceiling (about 40 % of RAM).
         */
        Cap = (LONG_PTR)(Basic.NumberOfPhysicalPages / 32);
        ok(Count <= (SIZE_T)(Cap + Cap / 512 + 64), "%Iu strides, the cap is %Id store pages\n", Count, Cap);
        ok(Count >= (SIZE_T)(Cap / 2), "only %Iu strides, the cap is %Id store pages\n", Count, Cap);
        ok((Available0 - Available) <= (Cap + Cap / 8 + 2048), "%Id pages taken, the cap is %Id store pages\n", Available0 - Available, Cap);
        ok(Available >= Available0 - Available0 / 4, "available %Id pages at the commit failure, %Id before\n", Available, Available0);
        /* Each stride charged its section page and its store page */
        ok((Committed - Committed0) >= (LONG_PTR)(2 * Count), "commit grew by %Id pages for %Iu strides\n", Committed - Committed0, Count);

        /* The process can still work: the committed pages are there */
        ok(Touch(View, 0x31) == STATUS_SUCCESS, "first stride\n");
        if (Count) ok(Touch(View + (Count - 1) * 0x200000, 0x32) == STATUS_SUCCESS, "last stride\n");
        NtUnmapViewOfSection(NtCurrentProcess(), View);
    }
    NtClose(Section);

    /* Everything came back: commit and physical memory, and the system can allocate again */
    QueryMemory(&Committed2, &Limit2, &Available2);
    trace("after close: commit %Id, available %Id\n", Committed2, Available2);
    ok((Committed2 - Committed0) < 256, "commit after close %Id, before %Id\n", Committed2, Committed0);
    ok((Available0 - Available2) < 8192, "available after close %Id, before %Id\n", Available2, Available0);

    /* A normal pattern is not hurt by the cap: 512 MB contiguous in a fresh 8 TB section, and the cap is free again */
    MaximumSize.QuadPart = 0x80000000000LL;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        View = NULL;
        Offset.QuadPart = 0x10000000000LL;
        ViewSize = 0x20000000;
        Status = NtMapViewOfSection(Section, NtCurrentProcess(), (PVOID *)&View, 0, 0, &Offset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            Address = View;
            Size = ViewSize;
            Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
            ok_ntstatus(Status, STATUS_SUCCESS);
            if (NT_SUCCESS(Status))
            {
                ok(Touch(View, 0x41) == STATUS_SUCCESS, "first page of the contiguous commit\n");
                ok(Touch(View + ViewSize - PAGE_SIZE, 0x42) == STATUS_SUCCESS, "last page of the contiguous commit\n");
                ok(Touch(View + ViewSize / 2, 0x43) == STATUS_SUCCESS, "middle of the contiguous commit\n");
            }
            NtUnmapViewOfSection(NtCurrentProcess(), View);
        }
        NtClose(Section);
    }

    Private = NULL;
    Size = 64 * 1024 * 1024;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Private, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < Size; i += PAGE_SIZE) ((volatile UCHAR *)Private)[i] = 1;
        Size = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &Private, &Size, MEM_RELEASE);
    }
}
#endif

START_TEST(SectionSparseCommitLimit)
{
#ifdef _WIN64
    Test_CommitToLimit();
#else
    skip("64-bit only\n");
#endif
}

START_TEST(SectionViewProtect)
{
    if (GetNTVersion() < _WIN32_WINNT_WIN10)
    {
        skip("The Windows 10 view protection rules are not checked on this version\n");
    }
    else
    {
        Test_ViewProtect(SEC_COMMIT);
        Test_ViewProtect(SEC_RESERVE);
    }
#ifdef _WIN64
    Test_HugeReserve();
#endif
}
