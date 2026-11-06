/*
 * PROJECT:         ReactOS API Tests
 * LICENSE:         GPLv2+ - See COPYING in the top level directory
 * PURPOSE:         Test for the NtProtectVirtualMemory API
 * PROGRAMMERS:     Jérôme Gardou <jerome.gardou@reactos.org>
 *                  Thomas Faber <thomas.faber@reactos.org>
 */

#include "precomp.h"

static
void
TestReadWrite(void)
{
    ULONG* allocationStart = NULL;
    NTSTATUS status;
    SIZE_T allocationSize;
    ULONG oldProtection;

    /* Reserve a page */
    allocationSize = PAGE_SIZE;
    status = NtAllocateVirtualMemory(NtCurrentProcess(),
        (void**)&allocationStart,
        0,
        &allocationSize,
        MEM_RESERVE,
        PAGE_NOACCESS);
    ok(NT_SUCCESS(status), "Reserving memory failed\n");

    /* Commit the page (RW) */
    status = NtAllocateVirtualMemory(NtCurrentProcess(),
        (void**)&allocationStart,
        0,
        &allocationSize,
        MEM_COMMIT,
        PAGE_READWRITE);
    ok(NT_SUCCESS(status), "Commiting memory failed\n");

    /* Try writing it */
    StartSeh()
    {
        *allocationStart = 0xFF;
    } EndSeh(STATUS_SUCCESS);

    /* Try reading it */
    StartSeh()
    {
        ok(*allocationStart == 0xFF, "Memory was not written\n");
    } EndSeh(STATUS_SUCCESS);

    /* Set it as read only */
    status = NtProtectVirtualMemory(NtCurrentProcess(),
        (void**)&allocationStart,
        &allocationSize,
        PAGE_READONLY,
        &oldProtection);
    ok(NT_SUCCESS(status), "NtProtectVirtualMemory failed.\n");
    ok(oldProtection == PAGE_READWRITE, "Expected PAGE_READWRITE, got %08lx.\n", oldProtection);

    /* Try writing it */
    StartSeh()
    {
        *allocationStart = 0xAA;
    } EndSeh(STATUS_ACCESS_VIOLATION);

    /* Try reading it */
    StartSeh()
    {
        ok(*allocationStart == 0xFF, "read-only memory were changed.\n");
    } EndSeh(STATUS_SUCCESS);

    /* Set it as no access */
    status = NtProtectVirtualMemory(NtCurrentProcess(),
        (void**)&allocationStart,
        &allocationSize,
        PAGE_NOACCESS,
        &oldProtection);
    ok(NT_SUCCESS(status), "NtProtectVirtualMemory failed.\n");
    ok(oldProtection == PAGE_READONLY, "Expected PAGE_READONLY, got %08lx.\n", oldProtection);

    /* Try writing it */
    StartSeh()
    {
        *allocationStart = 0xAA;
    } EndSeh(STATUS_ACCESS_VIOLATION);

    /* Try reading it */
    StartSeh()
    {
        ok(*allocationStart == 0, "Test should not go as far as this.\n");
    } EndSeh(STATUS_ACCESS_VIOLATION);

    /* Set it as readable again */
    status = NtProtectVirtualMemory(NtCurrentProcess(),
        (void**)&allocationStart,
        &allocationSize,
        PAGE_READONLY,
        &oldProtection);
    ok(NT_SUCCESS(status), "NtProtectVirtualMemory failed.\n");
    ok(oldProtection == PAGE_NOACCESS, "Expected PAGE_READONLY, got %08lx.\n", oldProtection);

    /* Try writing it */
    StartSeh()
    {
        *allocationStart = 0xAA;
    } EndSeh(STATUS_ACCESS_VIOLATION);

    /* Try reading it */
    StartSeh()
    {
        ok(*allocationStart == 0xFF, "Memory content was not preserved.\n");
    } EndSeh(STATUS_SUCCESS);

    /* Free memory */
    status = NtFreeVirtualMemory(NtCurrentProcess(),
        (void**)&allocationStart,
        &allocationSize,
        MEM_RELEASE);
    ok(NT_SUCCESS(status), "Failed freeing memory.\n");
}

/* Regression test for CORE-13311 */
static
void
TestFreeNoAccess(void)
{
    PVOID Mem;
    SIZE_T Size;
    NTSTATUS Status;
    ULONG Iteration, PageNumber;
    PUCHAR Page;
    ULONG OldProtection;

    for (Iteration = 0; Iteration < 50000; Iteration++)
    {
        Mem = NULL;
        Size = 16 * PAGE_SIZE;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                         &Mem,
                                         0,
                                         &Size,
                                         MEM_COMMIT,
                                         PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
        {
            break;
        }

        for (PageNumber = 0; PageNumber < 16; PageNumber++)
        {
            Page = Mem;
            Page += PageNumber * PAGE_SIZE;
            ok(*Page == 0,
               "[%lu, %lu] Got non-zero memory. %x at %p\n",
               Iteration, PageNumber, *Page, Page);
            *Page = 123;
        }

        Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                        &Mem,
                                        &Size,
                                        PAGE_NOACCESS,
                                        &OldProtection);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_hex(OldProtection, PAGE_READWRITE);

        Size = 0;
        Status = NtFreeVirtualMemory(NtCurrentProcess(),
                                     &Mem,
                                     &Size,
                                     MEM_RELEASE);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
}

#ifdef _WIN64
#define TOP_LEVEL_REGION_SIZE 0x8000000000ULL

/*
 * Commit 16 pages in a 512 GB region that this process never used, so that
 * it has no page map level 4 entry. Returns NULL if no such region is free.
 */
static
PVOID
AllocateInUntouchedTopLevelRegion(ULONG_PTR *Next)
{
    static const ULONG_PTR Candidates[] = { 0x50000000000ULL, 0x58000000000ULL, 0x60000000000ULL,
                                            0x68000000000ULL, 0x70000000000ULL, 0x78000000000ULL };
    MEMORY_BASIC_INFORMATION Mbi;
    PVOID Base;
    SIZE_T Size;
    NTSTATUS Status;

    for (; *Next < _countof(Candidates); (*Next)++)
    {
        Status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)Candidates[*Next],
                                      MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
        if (!NT_SUCCESS(Status) || Mbi.State != MEM_FREE ||
            (ULONG_PTR)Mbi.BaseAddress + Mbi.RegionSize < Candidates[*Next] + TOP_LEVEL_REGION_SIZE)
            continue;
        Base = (PVOID)Candidates[*Next];
        Size = 16 * PAGE_SIZE;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (NT_SUCCESS(Status))
        {
            (*Next)++;
            return Base;
        }
    }
    return NULL;
}

/*
 * Committed memory that was never touched has no page tables. Releasing part
 * of it counts its committed pages, and protecting it checks that the whole
 * range is committed: both walks skip the absent top-level entry, which used
 * to make them continue from a PTE address computed from the wrong pointer.
 */
static
void
TestUntouchedTopLevelRegion(void)
{
    MEMORY_BASIC_INFORMATION Mbi;
    ULONG_PTR Next = 0;
    PVOID Base, Address;
    SIZE_T Size;
    ULONG OldProtect;
    NTSTATUS Status;

    /* Release the middle of an untouched allocation */
    Base = AllocateInUntouchedTopLevelRegion(&Next);
    if (!Base)
    {
        skip("No untouched 512 GB region is free\n");
        return;
    }
    Address = (PUCHAR)Base + 4 * PAGE_SIZE;
    Size = 4 * PAGE_SIZE;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, MEM_RELEASE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), (PUCHAR)Base + 4 * PAGE_SIZE,
                                  MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_hex(Mbi.State, MEM_FREE);
    Address = Base;
    Size = 0;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, MEM_RELEASE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Address = (PUCHAR)Base + 8 * PAGE_SIZE;
    Size = 0;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, MEM_RELEASE);
    ok_ntstatus(Status, STATUS_SUCCESS);

    /* Protect an untouched allocation in another region */
    Base = AllocateInUntouchedTopLevelRegion(&Next);
    if (!Base)
    {
        skip("No second untouched 512 GB region is free\n");
        return;
    }
    Address = Base;
    Size = 16 * PAGE_SIZE;
    Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_READONLY, &OldProtect);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_hex(OldProtect, PAGE_READWRITE);
    Address = Base;
    Size = 0;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, MEM_RELEASE);
    ok_ntstatus(Status, STATUS_SUCCESS);
}
#endif

/*
 * A touched page made inaccessible and then accessible again is brought back
 * from the page lists by the next access; it must keep its protection
 */
static
void
TestProtectionAfterInaccessible(void)
{
    static const ULONG Inaccessible[] = { PAGE_NOACCESS, PAGE_READWRITE | PAGE_GUARD };
    static const ULONG Final[] = { PAGE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READWRITE };
    MEMORY_BASIC_INFORMATION Mbi;
    volatile UCHAR *Page;
    PVOID Base, Address;
    SIZE_T Size;
    ULONG i, j, Old, Locked;
    BOOLEAN StillLocked;
    UCHAR Value = 0;
    NTSTATUS Status;

    for (Locked = 0; Locked < 2; Locked++)
    for (i = 0; i < _countof(Inaccessible); i++)
    for (j = 0; j < _countof(Final); j++)
    {
        Base = NULL;
        Size = PAGE_SIZE;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
            continue;
        Page = Base;
        Page[0] = 0x5A;
        Value = 0;
        /* A locked page is kept off the page lists while it is inaccessible */
        if (Locked)
            ok(VirtualLock(Base, PAGE_SIZE), "VirtualLock failed with %lu\n", GetLastError());

        Address = Base;
        Size = PAGE_SIZE;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, Inaccessible[i], &Old);
        /* Windows unlocks the page here */
        ok(Status == STATUS_SUCCESS || (Locked && Status == STATUS_WAS_UNLOCKED),
           "%lx: NtProtectVirtualMemory returned 0x%08lx\n", Inaccessible[i], Status);
        StillLocked = (Locked && Status == STATUS_SUCCESS);
        Address = Base;
        Size = PAGE_SIZE;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, Final[j], &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(Old == Inaccessible[i], "%lx -> %lx: old protection %lx\n", Inaccessible[i], Final[j], Old);

        /* The access brings the page back */
        StartSeh()
        {
            Value = Page[0];
        } EndSeh(STATUS_SUCCESS);
        ok(Value == 0x5A, "%lx -> %lx: page holds %x\n", Inaccessible[i], Final[j], Value);

        Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(Mbi.Protect == Final[j], "%lx -> %lx: query reports %lx after the access\n", Inaccessible[i], Final[j], Mbi.Protect);
        Address = Base;
        Size = PAGE_SIZE;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_READONLY, &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(Old == Final[j], "%lx -> %lx: old protection %lx after the access\n", Inaccessible[i], Final[j], Old);
        if (StillLocked)
            ok(VirtualUnlock(Base, PAGE_SIZE), "VirtualUnlock failed with %lu\n", GetLastError());

        Address = Base;
        Size = 0;
        Status = NtFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, MEM_RELEASE);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
}

/*
 * A touched guard page goes into transition; the first access consumes the
 * guard and the next one brings the page back: it must have the protection
 * without the guard
 */
static
void
TestProtectionAfterGuard(void)
{
    static const ULONG First[] = { PAGE_READWRITE, PAGE_NOACCESS };
    static const ULONG Guard[] = { PAGE_READWRITE | PAGE_GUARD, PAGE_READONLY | PAGE_GUARD, PAGE_EXECUTE_READ | PAGE_GUARD };
    MEMORY_BASIC_INFORMATION Mbi;
    volatile UCHAR *Page;
    PVOID Base, Address;
    SIZE_T Size;
    ULONG i, j, Old;
    UCHAR Value = 0;
    NTSTATUS Status;

    for (i = 0; i < _countof(First); i++)
    for (j = 0; j < _countof(Guard); j++)
    {
        Base = NULL;
        Size = PAGE_SIZE;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
            continue;
        Page = Base;
        Page[0] = 0x5A;
        Value = 0;

        /* Optionally inaccessible first, then a guard page */
        Address = Base;
        Size = PAGE_SIZE;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, First[i], &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);
        Address = Base;
        Size = PAGE_SIZE;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, Guard[j], &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);

        StartSeh()
        {
            Value = Page[0];
        } EndSeh(STATUS_GUARD_PAGE_VIOLATION);
        StartSeh()
        {
            Value = Page[0];
        } EndSeh(STATUS_SUCCESS);
        ok(Value == 0x5A, "%lx -> %lx: page holds %x\n", First[i], Guard[j], Value);

        Status = NtQueryVirtualMemory(NtCurrentProcess(), Base, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(Mbi.Protect == (Guard[j] & ~PAGE_GUARD), "%lx -> %lx: query reports %lx after the guard\n", First[i], Guard[j], Mbi.Protect);
        Address = Base;
        Size = PAGE_SIZE;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_READWRITE, &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(Old == (Guard[j] & ~PAGE_GUARD), "%lx -> %lx: old protection %lx after the guard\n", First[i], Guard[j], Old);

        Address = Base;
        Size = 0;
        Status = NtFreeVirtualMemory(NtCurrentProcess(), &Address, &Size, MEM_RELEASE);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
}

#define CACHE_REGION_PAGES  16
#define CACHE_READ_PASSES   2000
#define CACHE_LOOP_COUNT    1000000UL

/* mov ecx, imm32; xor eax, eax; L: add eax, 3; dec ecx; jnz L; ret (same bytes in 32 and 64 bit mode) */
static const UCHAR LoopCode[] = { 0xB9, 0, 0, 0, 0, 0x31, 0xC0, 0x83, 0xC0, 0x03, 0xFF, 0xC9, 0x75, 0xF9, 0xC3 };

static
ULONGLONG
Ticks(void)
{
    LARGE_INTEGER Counter;

    NtQueryPerformanceCounter(&Counter, NULL);
    return Counter.QuadPart;
}

/* Best of three runs, so a preemption in one run does not decide the verdict */
static
ULONGLONG
TimeReads(
    _In_ volatile UCHAR *Base)
{
    ULONGLONG Best = (ULONGLONG)-1, Start, Elapsed;
    ULONG Run, Pass;
    SIZE_T Offset;
    static volatile ULONG Sink;
    ULONG Sum = 0;

    for (Run = 0; Run < 3; Run++)
    {
        Start = Ticks();
        for (Pass = 0; Pass < CACHE_READ_PASSES; Pass++)
            for (Offset = 0; Offset < CACHE_REGION_PAGES * PAGE_SIZE; Offset += 64)
                Sum += Base[Offset];
        Elapsed = Ticks() - Start;
        if (Elapsed < Best)
            Best = Elapsed;
    }
    Sink += Sum;
    return Best;
}

static
ULONGLONG
TimeCode(
    _In_ PVOID Code)
{
    ULONGLONG Best = (ULONGLONG)-1, Start, Elapsed;
    ULONG Run;

    for (Run = 0; Run < 3; Run++)
    {
        Start = Ticks();
        ((int (*)(void))Code)();
        Elapsed = Ticks() - Start;
        if (Elapsed < Best)
            Best = Elapsed;
    }
    return Best;
}

static
PVOID
AllocateCodeRegion(
    _In_ ULONG Protection)
{
    PVOID Base = NULL;
    SIZE_T Size = CACHE_REGION_PAGES * PAGE_SIZE;
    ULONG Count = CACHE_LOOP_COUNT, Page;
    NTSTATUS Status;

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, Protection);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return NULL;
    RtlCopyMemory(Base, LoopCode, sizeof(LoopCode));
    RtlCopyMemory((PUCHAR)Base + 1, &Count, sizeof(Count));
    for (Page = 0; Page < CACHE_REGION_PAGES; Page++)
        ((volatile UCHAR *)Base)[Page * PAGE_SIZE + 100] = 0;
    return Base;
}

static
void
FreeRegion(
    _In_ PVOID Base)
{
    SIZE_T Size = 0;
    NTSTATUS Status;

    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
    ok_ntstatus(Status, STATUS_SUCCESS);
}

/* Pages that were present when their protection changed must stay cached */
static
void
TestCachingAfterProtect(void)
{
    static const struct
    {
        ULONG First;
        ULONG Second;
        ULONG Third;
        PCSTR Name;
    } Cases[] =
    {
        { PAGE_READWRITE, PAGE_READONLY, 0, "RW to RO" },
        { PAGE_READWRITE, PAGE_EXECUTE_READ, 0, "RW to RX" },
        { PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_READWRITE, "RW to RX to RW" },
        { PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, 0, "RWX to RX" },
    };
    PVOID Control, Base;
    SIZE_T Size;
    ULONG Old;
    ULONGLONG ControlReads, ControlCode, Reads, Code;
    NTSTATUS Status;
    ULONG i;
    BOOLEAN Executable;

    Control = AllocateCodeRegion(PAGE_EXECUTE_READWRITE);
    if (!Control)
        return;
    ControlReads = TimeReads(Control);
    ControlCode = TimeCode(Control);

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        Base = AllocateCodeRegion(Cases[i].First);
        if (!Base)
            continue;
        Size = CACHE_REGION_PAGES * PAGE_SIZE;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, Cases[i].Second, &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (Cases[i].Third)
        {
            Size = CACHE_REGION_PAGES * PAGE_SIZE;
            Status = NtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, Cases[i].Third, &Old);
            ok_ntstatus(Status, STATUS_SUCCESS);
        }
        Executable = Cases[i].Third == 0 && Cases[i].Second == PAGE_EXECUTE_READ;

        Reads = TimeReads(Base);
        /* An uncached page takes about a hundred times longer, a cached one the same */
        ok(Reads < ControlReads * 10 + 1000, "%s: reading takes %I64u ticks, an untouched region takes %I64u\n",
           Cases[i].Name, Reads, ControlReads);
        if (Executable)
        {
            Code = TimeCode(Base);
            ok(Code < ControlCode * 10 + 1000, "%s: running code takes %I64u ticks, an untouched region takes %I64u\n",
               Cases[i].Name, Code, ControlCode);
        }
        FreeRegion(Base);
    }
    FreeRegion(Control);
}

/* A page that is present when its protection changes keeps the caching type it was made present with */
static
void
TestCachingTypeKept(void)
{
    static const struct
    {
        ULONG Allocation;
        ULONG Second;
        ULONG Third;
        PCSTR Name;
    } Cases[] =
    {
        { PAGE_READWRITE, PAGE_READWRITE | PAGE_NOCACHE, 0, "RW to RW|NOCACHE" },
        { PAGE_READWRITE, PAGE_READWRITE | PAGE_NOCACHE, PAGE_READWRITE, "RW to RW|NOCACHE to RW" },
        { PAGE_READWRITE | PAGE_NOCACHE, PAGE_READWRITE, 0, "RW|NOCACHE to RW" },
        { PAGE_READWRITE | PAGE_NOCACHE, PAGE_READONLY, 0, "RW|NOCACHE to RO" },
    };
    PVOID Control, Uncached, Base;
    SIZE_T Size;
    ULONG Old, i, Page;
    ULONGLONG ControlReads, UncachedReads, Reads;
    BOOLEAN HonoursNoCache, Cached;
    NTSTATUS Status;

    Control = AllocateCodeRegion(PAGE_READWRITE);
    Uncached = AllocateCodeRegion(PAGE_READWRITE | PAGE_NOCACHE);
    if (!Control || !Uncached)
        return;
    ControlReads = TimeReads(Control);
    UncachedReads = TimeReads(Uncached);
    /* Some virtual machines map guest RAM cached whatever the guest asks for */
    HonoursNoCache = UncachedReads > ControlReads * 10 + 1000;
    trace("cached region %I64u ticks, PAGE_NOCACHE region %I64u ticks\n", ControlReads, UncachedReads);

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        Base = NULL;
        Size = CACHE_REGION_PAGES * PAGE_SIZE;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, Cases[i].Allocation);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
            continue;
        for (Page = 0; Page < CACHE_REGION_PAGES; Page++)
            ((volatile UCHAR *)Base)[Page * PAGE_SIZE] = 1;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, Cases[i].Second, &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (Cases[i].Third)
        {
            Size = CACHE_REGION_PAGES * PAGE_SIZE;
            Status = NtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, Cases[i].Third, &Old);
            ok_ntstatus(Status, STATUS_SUCCESS);
        }

        Reads = TimeReads(Base);
        Cached = !(Cases[i].Allocation & PAGE_NOCACHE);
        if (Cached)
            ok(Reads < ControlReads * 10 + 1000, "%s: reading takes %I64u ticks, a cached region takes %I64u\n",
               Cases[i].Name, Reads, ControlReads);
        else if (HonoursNoCache)
            ok(Reads > ControlReads * 10 + 1000, "%s: reading takes %I64u ticks, a cached region takes %I64u, a PAGE_NOCACHE one %I64u\n",
               Cases[i].Name, Reads, ControlReads, UncachedReads);
        FreeRegion(Base);
    }
    if (!HonoursNoCache)
        skip("PAGE_NOCACHE memory reads as fast as cached memory here, uncached cases not checked\n");
    FreeRegion(Uncached);
    FreeRegion(Control);
}

/* A page made inaccessible and accessible again keeps one caching type until it is freed */
static
void
TestCachingAfterNoAccess(void)
{
    static const struct
    {
        ULONG Allocation;
        ULONG Back;
        PCSTR Name;
    } Cases[] =
    {
        { PAGE_READWRITE, PAGE_READWRITE | PAGE_NOCACHE, "RW, NOACCESS, RW|NOCACHE" },
        { PAGE_READWRITE | PAGE_NOCACHE, PAGE_READWRITE, "RW|NOCACHE, NOACCESS, RW" },
    };
    PVOID Control, Uncached, Base;
    SIZE_T Size;
    ULONG Old, i, Page;
    ULONGLONG ControlReads, UncachedReads, Before, After;
    NTSTATUS Status;

    Control = AllocateCodeRegion(PAGE_READWRITE);
    Uncached = AllocateCodeRegion(PAGE_READWRITE | PAGE_NOCACHE);
    if (!Control || !Uncached)
        return;
    ControlReads = TimeReads(Control);
    UncachedReads = TimeReads(Uncached);
    if (UncachedReads <= ControlReads * 10 + 1000)
    {
        skip("PAGE_NOCACHE memory reads as fast as cached memory here\n");
        goto Cleanup;
    }

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        Base = NULL;
        Size = CACHE_REGION_PAGES * PAGE_SIZE;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, Cases[i].Allocation);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
            continue;
        for (Page = 0; Page < CACHE_REGION_PAGES; Page++)
            ((volatile UCHAR *)Base)[Page * PAGE_SIZE] = 1;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, PAGE_NOACCESS, &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, Cases[i].Back, &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);
        for (Page = 0; Page < CACHE_REGION_PAGES; Page++)
            ((volatile UCHAR *)Base)[Page * PAGE_SIZE] = 2;
        Before = TimeReads(Base);
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, PAGE_READONLY, &Old);
        ok_ntstatus(Status, STATUS_SUCCESS);
        After = TimeReads(Base);

        /* Server 2008 R2 and Windows 10 pick different types here, but neither changes it at RO */
        ok((Before > ControlReads * 10 + 1000) == (After > ControlReads * 10 + 1000),
           "%s: reads take %I64u ticks, %I64u after RO (cached %I64u, PAGE_NOCACHE %I64u)\n",
           Cases[i].Name, Before, After, ControlReads, UncachedReads);
        FreeRegion(Base);
    }

Cleanup:
    FreeRegion(Uncached);
    FreeRegion(Control);
}

/* Up to 3 GB, so a large machine does not commit all its memory */
#define DRAIN_CHUNK (64 * 1024 * 1024)
#define DRAIN_CHUNKS 48

static volatile LONG BusyStop;

static
DWORD
WINAPI
BusyThread(
    _In_ LPVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    while (!BusyStop)
        YieldProcessor();
    return 0;
}

/* PAGE_NOCACHE pages made present when no zeroed page is left read as zero and stay uncached */
static
void
TestNoCacheFreshPages(void)
{
    MEMORYSTATUSEX Memory;
    SYSTEM_INFO System;
    HANDLE Threads[16];
    ULONG ThreadCount = 0, i, NonZero = 0;
    PVOID Control, Uncached, Drain[DRAIN_CHUNKS] = { NULL }, Base = NULL, Release;
    SIZE_T DrainSize, Size, Offset;
    ULONGLONG ControlReads, UncachedReads, Reads;
    NTSTATUS Status;

    Control = AllocateCodeRegion(PAGE_READWRITE);
    Uncached = AllocateCodeRegion(PAGE_READWRITE | PAGE_NOCACHE);
    if (!Control || !Uncached)
        return;
    ControlReads = TimeReads(Control);
    UncachedReads = TimeReads(Uncached);

    GetSystemInfo(&System);

    /* Keep the other processors busy, so the zero page thread cannot refill the zeroed list meanwhile */
    BusyStop = 0;
    for (i = 1; i < System.dwNumberOfProcessors && ThreadCount < RTL_NUMBER_OF(Threads); i++)
    {
        Threads[ThreadCount] = CreateThread(NULL, 0, BusyThread, NULL, 0, NULL);
        if (Threads[ThreadCount])
            ThreadCount++;
    }

    /* Use up the zeroed pages, then return a few pages to the free list without zeroing them */
    DrainSize = 0;
    for (i = 0; i < RTL_NUMBER_OF(Drain); i++)
    {
        Memory.dwLength = sizeof(Memory);
        GlobalMemoryStatusEx(&Memory);
        if (Memory.ullAvailPhys < 32 * 1024 * 1024)
            break;
        Size = (SIZE_T)min(Memory.ullAvailPhys - 24 * 1024 * 1024, DRAIN_CHUNK) & ~(SIZE_T)0xFFFF;
        Drain[i] = NULL;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Drain[i], 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!NT_SUCCESS(Status))
        {
            Drain[i] = NULL;
            break;
        }
        for (Offset = 0; Offset < Size; Offset += PAGE_SIZE)
            ((volatile UCHAR *)Drain[i])[Offset] = 1;
        DrainSize += Size;
    }
    if (i > 0)
    {
        Release = Drain[0];
        Size = 1024 * 1024;
        Status = NtFreeVirtualMemory(NtCurrentProcess(), &Release, &Size, MEM_DECOMMIT);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }

    Size = CACHE_REGION_PAGES * PAGE_SIZE;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_NOCACHE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        for (Offset = 0; Offset < Size; Offset += sizeof(ULONG))
            if (((volatile ULONG *)Base)[Offset / sizeof(ULONG)] != 0)
                NonZero++;
    }

    BusyStop = 1;
    for (i = 0; i < ThreadCount; i++)
    {
        WaitForSingleObject(Threads[i], INFINITE);
        CloseHandle(Threads[i]);
    }
    for (i = 0; i < RTL_NUMBER_OF(Drain); i++)
        if (Drain[i])
            FreeRegion(Drain[i]);
    trace("drained %Iu MB with %lu busy threads\n", DrainSize / (1024 * 1024), ThreadCount);

    if (Base)
    {
        ok(NonZero == 0, "%lu words of fresh PAGE_NOCACHE pages are not zero\n", NonZero);
        Reads = TimeReads(Base);
        if (UncachedReads > ControlReads * 10 + 1000)
            ok(Reads > ControlReads * 10 + 1000, "fresh PAGE_NOCACHE pages read in %I64u ticks, cached %I64u, PAGE_NOCACHE %I64u\n",
               Reads, ControlReads, UncachedReads);
        else
            skip("PAGE_NOCACHE memory reads as fast as cached memory here\n");
        FreeRegion(Base);
    }
    FreeRegion(Uncached);
    FreeRegion(Control);
}

/*
 * A view of a section must not be reprotectable beyond the section's maximum
 * protection. Reprotecting a read-only data mapping to writable or executable
 * is a W^X / privilege-escalation hole: MmProtectSectionView must reject it
 * with STATUS_SECTION_PROTECTION, exactly as NtMapViewOfSection rejects an
 * over-broad protection at map time.
 */
static
void
TestSectionMaxProtection(void)
{
    WCHAR ModulePath[MAX_PATH];
    UNICODE_STRING NtPath;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;
    HANDLE FileHandle, SectionHandle;
    PVOID BaseAddress;
    SIZE_T ViewSize;
    ULONG OldProtect;

    /* Use our own module file as the backing store for a read-only data section */
    if (GetModuleFileNameW(NULL, ModulePath, RTL_NUMBER_OF(ModulePath)) == 0)
    {
        ok(0, "GetModuleFileNameW failed: %lu\n", GetLastError());
        return;
    }

    if (!RtlDosPathNameToNtPathName_U(ModulePath, &NtPath, NULL, NULL))
    {
        ok(0, "RtlDosPathNameToNtPathName_U failed\n");
        return;
    }

    InitializeObjectAttributes(&ObjectAttributes, &NtPath, 0, NULL, NULL);
    Status = NtOpenFile(&FileHandle,
                        GENERIC_READ | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    RtlFreeHeap(RtlGetProcessHeap(), 0, NtPath.Buffer);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to open backing file\n");
        return;
    }

    /* Create a read-only *data* section (not SEC_IMAGE) over the file */
    Status = NtCreateSection(&SectionHandle,
                             SECTION_MAP_READ,
                             NULL,
                             NULL,
                             PAGE_READONLY,
                             SEC_COMMIT,
                             FileHandle);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to create read-only data section\n");
        NtClose(FileHandle);
        return;
    }

    /* Map a read-only view - this is within the section's maximum protection */
    BaseAddress = NULL;
    ViewSize = PAGE_SIZE;
    Status = NtMapViewOfSection(SectionHandle,
                                NtCurrentProcess(),
                                &BaseAddress,
                                0,
                                0,
                                NULL,
                                &ViewSize,
                                ViewShare,
                                0,
                                PAGE_READONLY);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to map read-only view\n");
        NtClose(SectionHandle);
        NtClose(FileHandle);
        return;
    }

    /* Positive control: re-stating PAGE_READONLY stays within the maximum */
    OldProtect = 0;
    Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                    &BaseAddress,
                                    &ViewSize,
                                    PAGE_READONLY,
                                    &OldProtect);
    ok_ntstatus(Status, STATUS_SUCCESS);

    /* Escalation to writable must be rejected (section is read-only) */
    BaseAddress = (PVOID)PAGE_ROUND_DOWN(BaseAddress);
    ViewSize = PAGE_SIZE;
    Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                    &BaseAddress,
                                    &ViewSize,
                                    PAGE_READWRITE,
                                    &OldProtect);
    ok_ntstatus(Status, STATUS_SECTION_PROTECTION);

    /* Escalation to executable must be rejected (section is read-only) */
    BaseAddress = (PVOID)PAGE_ROUND_DOWN(BaseAddress);
    ViewSize = PAGE_SIZE;
    Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                    &BaseAddress,
                                    &ViewSize,
                                    PAGE_EXECUTE_READ,
                                    &OldProtect);
    ok_ntstatus(Status, STATUS_SECTION_PROTECTION);

    /* Escalation to RWX must be rejected (section is read-only) */
    BaseAddress = (PVOID)PAGE_ROUND_DOWN(BaseAddress);
    ViewSize = PAGE_SIZE;
    Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                    &BaseAddress,
                                    &ViewSize,
                                    PAGE_EXECUTE_READWRITE,
                                    &OldProtect);
    ok_ntstatus(Status, STATUS_SECTION_PROTECTION);

    NtUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
    NtClose(SectionHandle);
    NtClose(FileHandle);
}

/*
 * The image-section counterpart of the check above. An image is mapped as one
 * segment per PE section, each carrying the protection derived from its section
 * header. The loader legitimately reprotects read-only / executable image pages
 * to PAGE_READWRITE (copy-on-write) to snap the IAT and apply relocations, and
 * programs such as the Inno Setup loader reprotect their whole image to
 * PAGE_EXECUTE_READWRITE: all of it is copy-on-write and must stay allowed.
 */
static
void
TestImageSectionMaxProtection(void)
{
    WCHAR ModulePath[MAX_PATH];
    UNICODE_STRING NtPath;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;
    HANDLE FileHandle, SectionHandle;
    PVOID BaseAddress = NULL;
    SIZE_T ViewSize;
    ULONG OldProtect;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER SectionHeader;
    ULONG i;
    PVOID CodePage = NULL;  /* an executable subsection (e.g. .text) */
    PVOID RoDataPage = NULL; /* a read-only, non-exec, non-write subsection (e.g. .rdata) */
    PVOID Target;

    if (GetModuleFileNameW(NULL, ModulePath, RTL_NUMBER_OF(ModulePath)) == 0)
    {
        ok(0, "GetModuleFileNameW failed: %lu\n", GetLastError());
        return;
    }

    if (!RtlDosPathNameToNtPathName_U(ModulePath, &NtPath, NULL, NULL))
    {
        ok(0, "RtlDosPathNameToNtPathName_U failed\n");
        return;
    }

    InitializeObjectAttributes(&ObjectAttributes, &NtPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&FileHandle,
                        GENERIC_READ | GENERIC_EXECUTE | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    RtlFreeHeap(RtlGetProcessHeap(), 0, NtPath.Buffer);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to open backing file\n");
        return;
    }

    /* Create an image (SEC_IMAGE) section over our own module */
    Status = NtCreateSection(&SectionHandle,
                             SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                             NULL,
                             NULL,
                             PAGE_EXECUTE_READ,
                             SEC_IMAGE,
                             FileHandle);
    NtClose(FileHandle);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to create image section\n");
        return;
    }

    ViewSize = 0;
    Status = NtMapViewOfSection(SectionHandle,
                                NtCurrentProcess(),
                                &BaseAddress,
                                0,
                                0,
                                NULL,
                                &ViewSize,
                                ViewShare,
                                0,
                                PAGE_EXECUTE_READ);
    ok(NT_SUCCESS(Status), "NtMapViewOfSection failed with 0x%08lx\n", Status);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to map image view\n");
        NtClose(SectionHandle);
        return;
    }

    /* Locate an executable and a read-only non-executable subsection in the view */
    DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ok(0, "Mapped image has no DOS signature\n");
        goto Cleanup;
    }
    NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)BaseAddress + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        ok(0, "Mapped image has no NT signature\n");
        goto Cleanup;
    }

    SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        PVOID SecBase = (PUCHAR)BaseAddress + SectionHeader[i].VirtualAddress;
        ULONG Chars = SectionHeader[i].Characteristics;

        if ((Chars & IMAGE_SCN_MEM_EXECUTE) && (CodePage == NULL))
            CodePage = SecBase;

        if ((Chars & IMAGE_SCN_MEM_READ) &&
            !(Chars & IMAGE_SCN_MEM_EXECUTE) &&
            !(Chars & IMAGE_SCN_MEM_WRITE) &&
            (RoDataPage == NULL))
        {
            RoDataPage = SecBase;
        }
    }

    /*
     * Executable subsection: a loader-style copy-on-write RW fixup (IAT snap /
     * relocation) must be permitted, and restoring it must succeed too.
     */
    if (CodePage != NULL)
    {
        Target = CodePage;
        ViewSize = PAGE_SIZE;
        OldProtect = 0;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Target, &ViewSize, PAGE_READWRITE, &OldProtect);
        ok_ntstatus(Status, STATUS_SUCCESS);

        Target = CodePage;
        ViewSize = PAGE_SIZE;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Target, &ViewSize, PAGE_EXECUTE_READ, &OldProtect);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
    else
    {
        skip("No executable subsection found in image\n");
    }

    /*
     * Read-only, non-executable subsection (where the IAT typically lives):
     * every reprotection is copy-on-write (it can only ever create a private
     * page), so the loader-style RW fixup and, as on Windows, execute and
     * write+execute (Inno Setup's loader VirtualProtect()s its whole image to
     * PAGE_EXECUTE_READWRITE before touching it) must all be permitted.
     */
    if (RoDataPage != NULL)
    {
        static const ULONG Requests[] =
            { PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY };
        ULONG k;

        for (k = 0; k < RTL_NUMBER_OF(Requests); k++)
        {
            Target = RoDataPage;
            ViewSize = PAGE_SIZE;
            OldProtect = 0;
            Status = NtProtectVirtualMemory(NtCurrentProcess(), &Target, &ViewSize, Requests[k], &OldProtect);
            ok_ntstatus(Status, STATUS_SUCCESS);
            if (k == 0)
                ok_hex(OldProtect, PAGE_READONLY);

            /* Restore to read-only - allowed */
            Target = RoDataPage;
            ViewSize = PAGE_SIZE;
            Status = NtProtectVirtualMemory(NtCurrentProcess(), &Target, &ViewSize, PAGE_READONLY, &OldProtect);
            ok_ntstatus(Status, STATUS_SUCCESS);
            ok(OldProtect == Requests[k], "request 0x%lx: old protection 0x%lx\n", Requests[k], OldProtect);
        }
    }
    else
    {
        skip("No read-only non-executable subsection found in image\n");
    }

Cleanup:
    NtUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
    NtClose(SectionHandle);
}

static
void
TestNoChangeVads(void)
{
    NTSTATUS Status;
    HANDLE SectionHandle;
    LARGE_INTEGER MaximumSize;
    PVOID BaseAddress;
    SIZE_T ViewSize, RegionSize;
    ULONG OldProtect;

    /* A SEC_NO_CHANGE section view must keep refusing protection changes */
    MaximumSize.QuadPart = PAGE_SIZE;
    Status = NtCreateSection(&SectionHandle,
                             SECTION_ALL_ACCESS,
                             NULL,
                             &MaximumSize,
                             PAGE_READWRITE,
                             SEC_COMMIT | SEC_NO_CHANGE,
                             NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        BaseAddress = NULL;
        ViewSize = 0;
        Status = NtMapViewOfSection(SectionHandle,
                                    NtCurrentProcess(),
                                    &BaseAddress,
                                    0,
                                    0,
                                    NULL,
                                    &ViewSize,
                                    ViewUnmap,
                                    0,
                                    PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            RegionSize = PAGE_SIZE;
            OldProtect = 0;
            Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                            &BaseAddress,
                                            &RegionSize,
                                            PAGE_READONLY,
                                            &OldProtect);
            ok_ntstatus(Status, STATUS_INVALID_PAGE_PROTECTION);
            NtUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
        }
        NtClose(SectionHandle);
    }

    /* The PEB and TEB are kernel-secured private VADs, but their process may reprotect them
     * (the Chromium renderer sandbox does) */
    BaseAddress = NtCurrentTeb();
    RegionSize = PAGE_SIZE;
    OldProtect = 0;
    Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                    &BaseAddress,
                                    &RegionSize,
                                    PAGE_READWRITE,
                                    &OldProtect);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(OldProtect == PAGE_READWRITE, "TEB: old protection 0x%lx\n", OldProtect);

    BaseAddress = NtCurrentPeb();
    RegionSize = PAGE_SIZE;
    OldProtect = 0;
    Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                    &BaseAddress,
                                    &RegionSize,
                                    PAGE_READWRITE,
                                    &OldProtect);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(OldProtect == PAGE_READWRITE, "PEB: old protection 0x%lx\n", OldProtect);

    /* The TEB stays usable */
    StartSeh()
    {
        ok(NtCurrentTeb()->ProcessEnvironmentBlock == NtCurrentPeb(), "TEB damaged\n");
    } EndSeh(STATUS_SUCCESS);

    /* The shared user data page stays immutable */
    BaseAddress = (PVOID)MM_SHARED_USER_DATA_VA;
    RegionSize = PAGE_SIZE;
    Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                    &BaseAddress,
                                    &RegionSize,
                                    PAGE_READWRITE,
                                    &OldProtect);
    ok_ntstatus(Status, STATUS_INVALID_PAGE_PROTECTION);
}

/* The old protection of a view of a pagefile-backed section is the protection of the view, not 0
 * (Windows 10 22H2: 0x40 for a view mapped PAGE_EXECUTE_READWRITE, harness evidence nodev8-20261106) */
static
void
TestPagefileViewOldProtection(void)
{
    NTSTATUS Status;
    HANDLE SectionHandle;
    LARGE_INTEGER MaximumSize;
    PVOID BaseAddress, Address;
    SIZE_T ViewSize, Size;
    ULONG OldProtect;
    static const ULONG NewProtect[] = { PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READWRITE };
    ULONG i;

    MaximumSize.QuadPart = 0x10000;
    Status = NtCreateSection(&SectionHandle,
                             SECTION_ALL_ACCESS,
                             NULL,
                             &MaximumSize,
                             PAGE_EXECUTE_READWRITE,
                             SEC_COMMIT,
                             NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to create a pagefile-backed section\n");
        return;
    }

    BaseAddress = NULL;
    ViewSize = 0;
    Status = NtMapViewOfSection(SectionHandle,
                                NtCurrentProcess(),
                                &BaseAddress,
                                0,
                                0,
                                NULL,
                                &ViewSize,
                                ViewShare,
                                0,
                                PAGE_EXECUTE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to map a view\n");
        NtClose(SectionHandle);
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(NewProtect); i++)
    {
        /* Fresh for every protection: the first page of a view that was not changed */
        Address = BaseAddress;
        Size = PAGE_SIZE;
        OldProtect = 0xDEAD;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, NewProtect[i], &OldProtect);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_hex(OldProtect, PAGE_EXECUTE_READWRITE);

        /* Put it back, so that the next one starts from the same view whatever the kernel keeps */
        Address = BaseAddress;
        Size = PAGE_SIZE;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, PAGE_EXECUTE_READWRITE, &OldProtect);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }

    NtUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
    NtClose(SectionHandle);
}

START_TEST(NtProtectVirtualMemory)
{
    TestReadWrite();
    TestFreeNoAccess();
#ifdef _WIN64
    TestUntouchedTopLevelRegion();
#endif
    TestProtectionAfterInaccessible();
    TestProtectionAfterGuard();
    TestCachingAfterProtect();
    TestCachingTypeKept();
    TestCachingAfterNoAccess();
    TestNoCacheFreshPages();
    TestSectionMaxProtection();
    TestImageSectionMaxProtection();
    TestNoChangeVads();
    TestPagefileViewOldProtection();
}
