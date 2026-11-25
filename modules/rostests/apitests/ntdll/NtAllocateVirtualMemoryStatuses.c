/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NtAllocateVirtualMemory(MEM_RESERVE): the statuses for ZeroBits and for requests that cannot fit
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The values are those of Windows Server 2022 (64-bit process): a region larger than the range ZeroBits allows
 * is STATUS_INVALID_PARAMETER, a region that fills that range up to the lowest user address finds no address
 * range (STATUS_CONFLICTING_ADDRESSES), a limit below the lowest user address leaves no memory
 * (STATUS_NO_MEMORY), and a size beyond the user address space with no base address is
 * STATUS_INVALID_PARAMETER. The rows do not depend on what else the process has mapped.
 */

#include "precomp.h"

#ifdef _WIN64

static void
CheckAlloc(const char *What, ULONG_PTR ZeroBits, SIZE_T Size, ULONG Type, NTSTATUS Expected)
{
    PVOID Base = NULL;
    SIZE_T RegionSize = Size;
    NTSTATUS Status;

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, ZeroBits, &RegionSize, Type, PAGE_READWRITE);
    ok(Status == Expected, "%s (ZeroBits 0x%Ix, size 0x%Ix): got 0x%lx, expected 0x%lx\n",
       What, ZeroBits, Size, Status, Expected);
    if (NT_SUCCESS(Status))
    {
        RegionSize = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
    }
}

START_TEST(NtAllocateVirtualMemoryStatuses)
{
    ULONG_PTR ZeroBits;

    /* more than the range of 2^(32 - ZeroBits) bytes holds */
    for (ZeroBits = 13; ZeroBits <= 21; ZeroBits++)
        CheckAlloc("reserve 1 MB", ZeroBits, 0x100000, MEM_RESERVE, STATUS_INVALID_PARAMETER);
    CheckAlloc("reserve 8 KB", 0x14, 0x2000, MEM_RESERVE | MEM_COMMIT, STATUS_INVALID_PARAMETER);
    CheckAlloc("reserve 1 MB", 0x20, 0x100000, MEM_RESERVE, STATUS_INVALID_PARAMETER);
    CheckAlloc("reserve 1 MB", 0x21, 0x100000, MEM_RESERVE, STATUS_INVALID_PARAMETER);

    /* the range is exactly the size, but starts at the lowest user address */
    CheckAlloc("reserve 1 MB", 12, 0x100000, MEM_RESERVE, STATUS_CONFLICTING_ADDRESSES);

    /* a limit below the lowest user address */
    CheckAlloc("reserve 8 KB", 16, 0x2000, MEM_RESERVE | MEM_COMMIT, STATUS_NO_MEMORY);
    CheckAlloc("reserve 8 KB", 17, 0x2000, MEM_RESERVE | MEM_COMMIT, STATUS_NO_MEMORY);

    /* a size the user address space cannot hold, without an address */
    CheckAlloc("reserve", 0, 0x800000000000ULL, MEM_RESERVE, STATUS_INVALID_PARAMETER);
    CheckAlloc("reserve", 0, 0x4000000000000000ULL, MEM_RESERVE, STATUS_INVALID_PARAMETER);
    CheckAlloc("reserve", 0, 0x7fffffffffffffffULL, MEM_RESERVE, STATUS_INVALID_PARAMETER);
    CheckAlloc("reserve", 0, 0x8000000000000000ULL, MEM_RESERVE, STATUS_INVALID_PARAMETER);
    CheckAlloc("reserve", 0, 0xffffffffffffffffULL, MEM_RESERVE, STATUS_INVALID_PARAMETER);
    CheckAlloc("reserve and commit", 0, 0x800000000000ULL, MEM_RESERVE | MEM_COMMIT, STATUS_INVALID_PARAMETER);
    CheckAlloc("commit", 0, 0xffffffffffffffffULL, MEM_COMMIT, STATUS_INVALID_PARAMETER);
}

#else

START_TEST(NtAllocateVirtualMemoryStatuses)
{
    skip("The rows are those of a 64-bit process\n");
}

#endif
