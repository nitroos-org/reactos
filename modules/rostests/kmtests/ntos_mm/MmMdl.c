/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Kernel-Mode Test Suite MDL test
 * COPYRIGHT:   Copyright 2015,2023 Thomas Faber (thomas.faber@reactos.org)
 * COPYRIGHT:   Copyright 2017 Pierre Schweitzer (pierre@reactos.org)
 */

#include <kmt_test.h>

static
VOID
TestMmAllocatePagesForMdl(VOID)
{
    PMDL Mdl;
    PHYSICAL_ADDRESS LowAddress;
    PHYSICAL_ADDRESS HighAddress;
    PHYSICAL_ADDRESS SkipBytes;
    PVOID SystemVa;
    PMDL Mdls[32];
    PVOID SystemVas[32];
    ULONG i;
    PPFN_NUMBER MdlPages;
    ULONG MdlPageCount;

    LowAddress.QuadPart = 0;
    HighAddress.QuadPart = -1;
    SkipBytes.QuadPart = 0;
    /* simple allocate/free */
    Mdl = MmAllocatePagesForMdl(LowAddress,
                                HighAddress,
                                SkipBytes,
                                2 * 1024 * 1024);
    ok(Mdl != NULL, "MmAllocatePagesForMdl failed\n");
    if (skip(Mdl != NULL, "No Mdl\n"))
        return;
    ok(MmGetMdlByteCount(Mdl) == 2 * 1024 * 1024, "Byte count: %lu\n", MmGetMdlByteCount(Mdl));
    ok(MmGetMdlVirtualAddress(Mdl) == NULL, "Virtual address: %p\n", MmGetMdlVirtualAddress(Mdl));
    ok(!(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdl->MdlFlags);
    MdlPages = MmGetMdlPfnArray(Mdl);
    MdlPageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(Mdl), MmGetMdlByteCount(Mdl));
    ok(MdlPageCount == 2 * 1024 * 1024 / PAGE_SIZE, "MdlPageCount = %lu\n", MdlPageCount);
    for (i = 0; i < MdlPageCount; i++)
    {
        ok(MdlPages[i] != 0 && MdlPages[i] != (PFN_NUMBER)-1,
           "MdlPages[%lu] = 0x%I64x\n", i, (ULONGLONG)MdlPages[i]);
    }
    MmFreePagesFromMdl(Mdl);
    ExFreePoolWithTag(Mdl, 0);

    /* Now map/unmap it */
    Mdl = MmAllocatePagesForMdl(LowAddress,
                                HighAddress,
                                SkipBytes,
                                2 * 1024 * 1024);
    ok(Mdl != NULL, "MmAllocatePagesForMdl failed\n");
    if (skip(Mdl != NULL, "No Mdl\n"))
        return;
    ok(MmGetMdlByteCount(Mdl) == 2 * 1024 * 1024, "Byte count: %lu\n", MmGetMdlByteCount(Mdl));
    ok(MmGetMdlVirtualAddress(Mdl) == NULL, "Virtual address: %p\n", MmGetMdlVirtualAddress(Mdl));
    ok(!(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdl->MdlFlags);
    SystemVa = MmMapLockedPagesSpecifyCache(Mdl,
                                            KernelMode,
                                            MmCached,
                                            NULL,
                                            FALSE,
                                            NormalPagePriority);
    ok(SystemVa != NULL, "MmMapLockedPagesSpecifyCache failed\n");
    if (!skip(SystemVa != NULL, "No system VA\n"))
    {
        ok(MmGetMdlByteCount(Mdl) == 2 * 1024 * 1024, "Byte count: %lu\n", MmGetMdlByteCount(Mdl));
        ok(MmGetMdlVirtualAddress(Mdl) == NULL, "Virtual address: %p, System VA: %p\n", MmGetMdlVirtualAddress(Mdl), SystemVa);
        ok(Mdl->MappedSystemVa == SystemVa, "MappedSystemVa: %p, System VA: %p\n", Mdl->MappedSystemVa, SystemVa);
        ok((Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdl->MdlFlags);
        MmUnmapLockedPages(SystemVa, Mdl);
    }
    ok(MmGetMdlByteCount(Mdl) == 2 * 1024 * 1024, "Byte count: %lu\n", MmGetMdlByteCount(Mdl));
    ok(MmGetMdlVirtualAddress(Mdl) == NULL, "Virtual address: %p\n", MmGetMdlVirtualAddress(Mdl));
    ok(!(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdl->MdlFlags);
    MmFreePagesFromMdl(Mdl);
    ExFreePoolWithTag(Mdl, 0);

    /* Now map it, and free without unmapping */
    Mdl = MmAllocatePagesForMdl(LowAddress,
                                HighAddress,
                                SkipBytes,
                                2 * 1024 * 1024);
    ok(Mdl != NULL, "MmAllocatePagesForMdl failed\n");
    if (skip(Mdl != NULL, "No Mdl\n"))
        return;
    ok(MmGetMdlByteCount(Mdl) == 2 * 1024 * 1024, "Byte count: %lu\n", MmGetMdlByteCount(Mdl));
    ok(MmGetMdlVirtualAddress(Mdl) == NULL, "Virtual address: %p\n", MmGetMdlVirtualAddress(Mdl));
    ok(!(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdl->MdlFlags);
    SystemVa = MmMapLockedPagesSpecifyCache(Mdl,
                                            KernelMode,
                                            MmCached,
                                            NULL,
                                            FALSE,
                                            NormalPagePriority);
    ok(SystemVa != NULL, "MmMapLockedPagesSpecifyCache failed\n");
    ok(MmGetMdlByteCount(Mdl) == 2 * 1024 * 1024, "Byte count: %lu\n", MmGetMdlByteCount(Mdl));
    ok(MmGetMdlVirtualAddress(Mdl) == NULL, "Virtual address: %p, System VA: %p\n", MmGetMdlVirtualAddress(Mdl), SystemVa);
    ok(Mdl->MappedSystemVa == SystemVa, "MappedSystemVa: %p, System VA: %p\n", Mdl->MappedSystemVa, SystemVa);
    ok((Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdl->MdlFlags);
    MmFreePagesFromMdl(Mdl);
    ExFreePoolWithTag(Mdl, 0);

    /* try to allocate 2 GB -- should succeed (possibly with fewer pages) but not map */
    Mdl = MmAllocatePagesForMdl(LowAddress,
                                HighAddress,
                                SkipBytes,
                                2UL * 1024 * 1024 * 1024);
    ok(Mdl != NULL, "MmAllocatePagesForMdl failed for 2 GB\n");
    if (Mdl != NULL)
    {
        ok(MmGetMdlByteCount(Mdl) <= 2UL * 1024 * 1024 * 1024, "Byte count: %lu\n", MmGetMdlByteCount(Mdl));
        ok(MmGetMdlVirtualAddress(Mdl) == NULL, "Virtual address: %p\n", MmGetMdlVirtualAddress(Mdl));
        ok(!(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdl->MdlFlags);
        MdlPages = MmGetMdlPfnArray(Mdl);
        MdlPageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(Mdl), MmGetMdlByteCount(Mdl));
        ok(MdlPageCount <= 2UL * 1024 * 1024 * 1024 / PAGE_SIZE, "MdlPageCount = %lu\n", MdlPageCount);
        for (i = 0; i < MdlPageCount; i++)
        {
            if (MdlPages[i] == 0 ||
                MdlPages[i] == (PFN_NUMBER)-1)
            {
                ok(0, "MdlPages[%lu] = 0x%I64x\n", i, (ULONGLONG)MdlPages[i]);
            }
        }
        SystemVa = MmMapLockedPagesSpecifyCache(Mdl,
                                                KernelMode,
                                                MmCached,
                                                NULL,
                                                FALSE,
                                                NormalPagePriority);
#ifdef _M_IX86
        /*
         * MmAllocatePagesForMdl is allowed to return fewer pages than requested.
         * Only enforce the x86 mapping expectation if we actually got ~2GB.
         */
        if (MmGetMdlByteCount(Mdl) >= (1UL << 31))
            ok(SystemVa == NULL, "MmMapLockedPagesSpecifyCache succeeded for 2 GB\n");
        else
            trace("Skipping 2GB mapping expectation (allocated %lu bytes)\n",
                  MmGetMdlByteCount(Mdl));
#endif
        if (SystemVa != NULL)
            MmUnmapLockedPages(SystemVa, Mdl);
        ok(MmGetMdlByteCount(Mdl) <= 2UL * 1024 * 1024 * 1024, "Byte count: %lu\n", MmGetMdlByteCount(Mdl));
        ok(MmGetMdlVirtualAddress(Mdl) == NULL, "Virtual address: %p\n", MmGetMdlVirtualAddress(Mdl));
        ok(!(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdl->MdlFlags);
        MmFreePagesFromMdl(Mdl);
        ExFreePoolWithTag(Mdl, 0);
    }

    /* now allocate and map 32 MB Mdls until we fail */
    for (i = 0; i < sizeof(Mdls) / sizeof(Mdls[0]); i++)
    {
        Mdls[i] = MmAllocatePagesForMdl(LowAddress,
                                        HighAddress,
                                        SkipBytes,
                                        32 * 1024 * 1024);
        if (Mdls[i] == NULL)
        {
            trace("MmAllocatePagesForMdl failed with i = %lu\n", i);
            break;
        }
        ok(MmGetMdlVirtualAddress(Mdls[i]) == NULL, "Virtual address: %p\n", MmGetMdlVirtualAddress(Mdls[i]));
        ok(!(Mdls[i]->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdls[i]->MdlFlags);
        SystemVas[i] = MmMapLockedPagesSpecifyCache(Mdls[i],
                                                    KernelMode,
                                                    MmCached,
                                                    NULL,
                                                    FALSE,
                                                    NormalPagePriority);
        if (SystemVas[i] == NULL)
        {
            ok(MmGetMdlByteCount(Mdls[i]) <= 32 * 1024 * 1024, "Byte count: %lu\n", MmGetMdlByteCount(Mdls[i]));
            ok(MmGetMdlVirtualAddress(Mdls[i]) == NULL, "Virtual address: %p\n", MmGetMdlVirtualAddress(Mdls[i]));
            ok(!(Mdls[i]->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdls[i]->MdlFlags);
            trace("MmMapLockedPagesSpecifyCache failed with i = %lu\n", i);
            break;
        }
        ok(MmGetMdlByteCount(Mdls[i]) <= 32 * 1024 * 1024, "Byte count: %lu\n", MmGetMdlByteCount(Mdls[i]));
        ok(MmGetMdlVirtualAddress(Mdls[i]) == NULL, "Virtual address: %p, System VA: %p\n", MmGetMdlVirtualAddress(Mdls[i]), SystemVas[i]);
        ok(Mdls[i]->MappedSystemVa == SystemVas[i], "MappedSystemVa: %p\n", Mdls[i]->MappedSystemVa, SystemVas[i]);
        ok((Mdls[i]->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA), "MdlFlags: %lx\n", Mdls[i]->MdlFlags);
    }
    for (i = 0; i < sizeof(Mdls) / sizeof(Mdls[0]); i++)
    {
        if (Mdls[i] == NULL)
            break;
        if (SystemVas[i] != NULL)
            MmUnmapLockedPages(SystemVas[i], Mdls[i]);
        MmFreePagesFromMdl(Mdls[i]);
        ExFreePoolWithTag(Mdls[i], 0);
        if (SystemVas[i] == NULL)
            break;
    }
}

static
VOID
TestMmBuildMdlForNonPagedPool(VOID)
{
    PVOID Page;
    PMDL Mdl;

    Page = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, 'Test');
    ok(Page != NULL, "ExAllocatePoolWithTag failed\n");
    if (skip(Page != NULL, "No buffer\n"))
        return;

    Mdl = IoAllocateMdl(Page, PAGE_SIZE, FALSE, FALSE, NULL);
    ok(Mdl != NULL, "IoAllocateMdl failed\n");
    if (skip(Mdl != NULL, "No MDL\n"))
        return;

    ok((Mdl->MdlFlags & MDL_PAGES_LOCKED) == 0, "MDL locked\n");
    ok((Mdl->MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL) == 0, "MDL from non paged\n");

    // This fails an assertion on Windows 8+ checked and can bugcheck Windows 10+ free.
    if (GetNTVersion() < _WIN32_WINNT_WIN8)
    {
        MmBuildMdlForNonPagedPool(Mdl);
        ok((Mdl->MdlFlags & MDL_PAGES_LOCKED) == 0, "MDL locked\n");
        ok((Mdl->MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL) != 0, "MDL from paged\n");
    }

    IoFreeMdl(Mdl);
    ExFreePoolWithTag(Page, 'Test');

    Page = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'Test');
    ok(Page != NULL, "ExAllocatePoolWithTag failed\n");
    if (skip(Page != NULL, "No buffer\n"))
        return;

    Mdl = IoAllocateMdl(Page, PAGE_SIZE, FALSE, FALSE, NULL);
    ok(Mdl != NULL, "IoAllocateMdl failed\n");
    if (skip(Mdl != NULL, "No MDL\n"))
        return;

    ok((Mdl->MdlFlags & MDL_PAGES_LOCKED) == 0, "MDL locked\n");
    ok((Mdl->MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL) == 0, "MDL from non paged\n");

    MmBuildMdlForNonPagedPool(Mdl);
    ok((Mdl->MdlFlags & MDL_PAGES_LOCKED) == 0, "MDL locked\n");
    ok((Mdl->MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL) != 0, "MDL from paged\n");

    IoFreeMdl(Mdl);
    ExFreePoolWithTag(Page, 'Test');
}

/*
 * Locking the pages of a user buffer is charged against the resident available pages and given back by
 * MmUnlockPages: a lock and unlock of 2 MB, 4096 times, locks 16 GB in all and needs every page returned.
 * A request for all the physical memory is refused with STATUS_INSUFFICIENT_RESOURCES before any page is
 * touched, so its buffer is only reserved (a probe of reserved memory would be an access violation).
 */
static
NTSTATUS
LockUserMdl(
    _In_ PMDL Mdl)
{
    NTSTATUS Status = STATUS_SUCCESS;

    _SEH2_TRY
    {
        MmProbeAndLockPages(Mdl, UserMode, IoWriteAccess);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    return Status;
}

static
VOID
TestMmProbeAndLockPagesCharge(VOID)
{
    SYSTEM_BASIC_INFORMATION BasicInfo;
    NTSTATUS Status, LockStatus = STATUS_SUCCESS;
    PVOID Base = NULL;
    SIZE_T Size = 2 * 1024 * 1024;
    ULONGLONG Total;
    PMDL Mdl;
    ULONG i;

    Status = ZwQuerySystemInformation(SystemBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "No system information\n"))
        return;
    Total = (ULONGLONG)BasicInfo.NumberOfPhysicalPages * BasicInfo.PageSize;

    /* lock and unlock again and again */
    Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &Base, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!skip(NT_SUCCESS(Status), "No buffer\n"))
    {
        Mdl = IoAllocateMdl(Base, (ULONG)Size, FALSE, FALSE, NULL);
        ok(Mdl != NULL, "IoAllocateMdl failed\n");
        if (!skip(Mdl != NULL, "No MDL\n"))
        {
            for (i = 0; i < 4096; i++)
            {
                LockStatus = LockUserMdl(Mdl);
                if (!NT_SUCCESS(LockStatus))
                    break;
                MmUnlockPages(Mdl);
            }
            ok_eq_hex(LockStatus, STATUS_SUCCESS);
            ok_eq_ulong(i, 4096UL);
            IoFreeMdl(Mdl);
        }
        Size = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &Base, &Size, MEM_RELEASE);
    }

    /* all the physical memory cannot be locked */
    if (Total > 0x7FFFF000)
    {
        skip(FALSE, "More physical memory than an MDL describes\n");
        return;
    }
    Base = NULL;
    Size = (SIZE_T)Total;
    Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &Base, 0, &Size, MEM_RESERVE, PAGE_READWRITE);
    if (skip(NT_SUCCESS(Status), "No room to reserve all the physical memory (0x%lx)\n", Status))
        return;
    Mdl = IoAllocateMdl(Base, (ULONG)Size, FALSE, FALSE, NULL);
    if (!skip(Mdl != NULL, "No MDL for all the physical memory\n"))
    {
        LockStatus = LockUserMdl(Mdl);
        ok_eq_hex(LockStatus, STATUS_INSUFFICIENT_RESOURCES);
        if (NT_SUCCESS(LockStatus))
            MmUnlockPages(Mdl);
        ok((Mdl->MdlFlags & MDL_PAGES_LOCKED) == 0, "MDL locked after the refusal\n");
        IoFreeMdl(Mdl);
    }
    Size = 0;
    ZwFreeVirtualMemory(ZwCurrentProcess(), &Base, &Size, MEM_RELEASE);

    /* the refusal took nothing: locking works as before */
    Base = NULL;
    Size = 2 * 1024 * 1024;
    Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &Base, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NT_SUCCESS(Status))
    {
        Mdl = IoAllocateMdl(Base, (ULONG)Size, FALSE, FALSE, NULL);
        if (Mdl)
        {
            LockStatus = LockUserMdl(Mdl);
            ok_eq_hex(LockStatus, STATUS_SUCCESS);
            if (NT_SUCCESS(LockStatus))
                MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
        }
        Size = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &Base, &Size, MEM_RELEASE);
    }
}

START_TEST(MmMdl)
{
    TestMmProbeAndLockPagesCharge();
    TestMmAllocatePagesForMdl();
    TestMmBuildMdlForNonPagedPool();
}
