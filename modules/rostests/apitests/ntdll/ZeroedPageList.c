/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The zero page thread keeps a bounded number of zeroed pages ready: it does not
 *              write every free page of the system once after boot
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* The thread keeps a thirtieth of the memory ready, from 32 MB to 256 MB; the test allows an eighth */
#define MAX_READY_FRACTION  8
#define SETTLE_POLLS        120
#define POLL_MS             250

static
BOOLEAN
QueryLists(
    _Out_ PSYSTEM_MEMORY_LIST_INFORMATION Lists)
{
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemMemoryListInformation, Lists, sizeof(*Lists), NULL);
    if (Status == STATUS_NOT_IMPLEMENTED)
        return FALSE;
    ok_ntstatus(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status);
}

/* Allocate, write to and release Megabytes of memory: they come back as free pages */
static
VOID
UseAndFree(
    _In_ ULONG Megabytes)
{
    SIZE_T Size = (SIZE_T)Megabytes << 20;
    PUCHAR Base;
    SIZE_T Offset;

    Base = VirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Base != NULL, "VirtualAlloc of %lu MB failed: %lu\n", Megabytes, GetLastError());
    if (!Base)
        return;

    for (Offset = 0; Offset < Size; Offset += 4096)
        Base[Offset] = 1;

    ok(VirtualFree(Base, 0, MEM_RELEASE), "VirtualFree failed: %lu\n", GetLastError());
}

START_TEST(ZeroedPageList)
{
    SYSTEM_BASIC_INFORMATION Basic;
    SYSTEM_MEMORY_LIST_INFORMATION Lists;
    NTSTATUS Status;
    SIZE_T Previous, Zeroed;
    ULONG Poll, Megabytes;
    PUCHAR Base;
    SIZE_T Offset, Size;
    BOOLEAN AllZero;

    if (!QueryLists(&Lists))
    {
        skip("The memory lists are not available\n");
        return;
    }

    Status = NtQuerySystemInformation(SystemBasicInformation, &Basic, sizeof(Basic), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    if (Basic.NumberOfPhysicalPages < 128 * 1024)
    {
        skip("Less than 512 MB of memory\n");
        return;
    }

    /* Pages freed by this process go to the free list and wake the thread up */
    Megabytes = 64;
    UseAndFree(Megabytes);
    UseAndFree(Megabytes);

    /* Wait until the number of zeroed pages stops changing */
    Zeroed = Lists.ZeroPageCount;
    for (Poll = 0; Poll < SETTLE_POLLS; Poll++)
    {
        Previous = Zeroed;
        Sleep(POLL_MS);
        if (!QueryLists(&Lists))
            return;
        Zeroed = Lists.ZeroPageCount;
        if (Zeroed == Previous && Poll >= 8)
            break;
    }

    trace("zeroed pages %Iu of %lu physical, free %Iu\n", Zeroed, (ULONG)Basic.NumberOfPhysicalPages, Lists.FreePageCount);
    ok(Zeroed <= Basic.NumberOfPhysicalPages / MAX_READY_FRACTION,
       "%Iu zeroed pages of %lu physical pages: the thread zeroes all the free memory\n",
       Zeroed, (ULONG)Basic.NumberOfPhysicalPages);

    /* Memory that was freed comes back zeroed, whichever list it was on */
    Size = (SIZE_T)Megabytes << 20;
    AllZero = TRUE;
    Base = VirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Base != NULL, "VirtualAlloc failed: %lu\n", GetLastError());
    if (Base)
    {
        for (Offset = 0; Offset < Size; Offset += 4096)
        {
            if (Base[Offset] != 0 || Base[Offset + 4095] != 0)
                AllZero = FALSE;
        }
        ok(AllZero, "a new allocation holds data\n");
        VirtualFree(Base, 0, MEM_RELEASE);
    }
}
