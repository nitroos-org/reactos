/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     A page locked with VirtualLock in a view of a pagefile-backed section is released with the view
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Each cycle creates a section backed by the pagefile, maps a view, touches a page, locks it with
   VirtualLock and unmaps the view and closes the section without calling VirtualUnlock. Windows
   drops the lock when the page leaves the process; the available page count must come back. */

#define CYCLES      2000
#define WARMUP      100
#define TOLERANCE   256

typedef enum _VARIANT
{
    PrivateLockedFree,
    LockedUnmapClose,
    LockedCloseUnmap,
    LockedUnlockUnmapClose,
} VARIANT;

static const char *VariantName[] =
{
    "private memory, locked, freed without VirtualUnlock (control)",
    "section view, locked, unmap then close",
    "section view, locked, close then unmap",
    "section view, locked, VirtualUnlock then unmap then close (control)",
};

static LONG_PTR AvailablePages(VOID)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? (LONG_PTR)Info.AvailablePages : 0;
}

static BOOLEAN Cycle(VARIANT Variant)
{
    HANDLE Section;
    LARGE_INTEGER Size;
    PVOID Base = NULL;
    SIZE_T ViewSize = 0;
    NTSTATUS Status;

    if (Variant == PrivateLockedFree)
    {
        SIZE_T RegionSize = 16 << 20;

        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!NT_SUCCESS(Status))
        {
            ok(0, "NtAllocateVirtualMemory failed: 0x%lx\n", Status);
            return FALSE;
        }
        *(volatile UCHAR *)Base = 0x5A;
        if (!VirtualLock(Base, PAGE_SIZE))
        {
            ok(0, "VirtualLock failed: %lu\n", GetLastError());
            RegionSize = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
            return FALSE;
        }
        RegionSize = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
        return TRUE;
    }

    /* The prototype PTEs of a section this size fill pages of their own, on every architecture */
    Size.QuadPart = 16 << 20;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &Size, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    if (!NT_SUCCESS(Status))
    {
        ok(0, "NtCreateSection failed: 0x%lx\n", Status);
        return FALSE;
    }

    Status = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0, 0, NULL, &ViewSize,
                                ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
    {
        ok(0, "NtMapViewOfSection failed: 0x%lx\n", Status);
        NtClose(Section);
        return FALSE;
    }

    *(volatile UCHAR *)Base = 0x5A;
    if (!VirtualLock(Base, PAGE_SIZE))
    {
        ok(0, "VirtualLock failed: %lu\n", GetLastError());
        NtUnmapViewOfSection(NtCurrentProcess(), Base);
        NtClose(Section);
        return FALSE;
    }

    if (Variant == LockedUnlockUnmapClose)
        VirtualUnlock(Base, PAGE_SIZE);

    if (Variant == LockedCloseUnmap)
    {
        NtClose(Section);
        NtUnmapViewOfSection(NtCurrentProcess(), Base);
    }
    else
    {
        NtUnmapViewOfSection(NtCurrentProcess(), Base);
        NtClose(Section);
    }

    return TRUE;
}

static VOID TestVariant(VARIANT Variant)
{
    LONG_PTR Before, After;
    ULONG i;

    for (i = 0; i < WARMUP; i++)
    {
        if (!Cycle(Variant))
            return;
    }

    Sleep(100);
    Before = AvailablePages();
    for (i = 0; i < CYCLES; i++)
    {
        if (!Cycle(Variant))
            return;
    }
    Sleep(100);
    After = AvailablePages();

    trace("%s: available pages %ld -> %ld over %u cycles\n", VariantName[Variant], (long)Before, (long)After, CYCLES);
    ok(Before - After < TOLERANCE, "%s: %ld pages lost over %u cycles\n",
       VariantName[Variant], (long)(Before - After), CYCLES);
}

START_TEST(SectionVirtualLockLeak)
{
    TestVariant(PrivateLockedFree);
    TestVariant(LockedUnlockUnmapClose);
    TestVariant(LockedUnmapClose);
    TestVariant(LockedCloseUnmap);
}
