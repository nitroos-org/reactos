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
            if (SectionFlags & SEC_COMMIT)
            {
                ok(Status == Expected, "view 0x%lx (0x%lx): protect 0x%lx: 0x%lx, expected 0x%lx\n",
                   Protections[v], SectionFlags, Protections[p], Status, Expected);
            }
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

    /* Closing gives the commit back */
    Before = QueryCommit();
    NtClose(Section);
    After = QueryCommit();
    ok((Before - After) >= (LONG_PTR)_countof(Offsets), "close returned %Id pages\n", Before - After);

    /* Many in turn: the address range for the Prototype PTEs is reused */
    for (i = 0; i < 200; i++)
    {
        MaximumSize.QuadPart = 0x80000000000LL;
        Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL);
        ok(Status == STATUS_SUCCESS, "round %lu: 0x%lx\n", i, Status);
        if (!NT_SUCCESS(Status)) break;
        if ((i % 50) == 0)
        {
            Base = MapAndTouch(Section, 0x7000000000LL + (LONGLONG)i * 0x10000, (UCHAR)i);
            if (Base) NtUnmapViewOfSection(NtCurrentProcess(), Base);
        }
        NtClose(Section);
    }

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
#endif

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
