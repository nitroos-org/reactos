/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Kernel-Mode Test Suite: contiguous allocations while private pages wait on standby (user part)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>
#include <ndk/exfuncs.h>
#include <ndk/psfuncs.h>

#ifndef SE_PROF_SINGLE_PROCESS_PRIVILEGE
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13L
#endif

/*
 * With NitroPager, written private pages wait on the standby list, their PTEs in transition. A contiguous
 * allocation must never take one of them (it would become a driver's buffer while this process can still
 * fault it back). This part puts a third of the physical memory of its own on standby, the kernel part
 * allocates and writes contiguous memory until none is left, then every page here must still hold its data.
 */
#define MemoryEmptyWorkingSets      2
#define MemoryFlushModifiedList     3

static
NTSTATUS
MemoryListCommand(
    _In_ ULONG Command)
{
    return NtSetSystemInformation(SystemMemoryListInformation, &Command, sizeof(Command));
}

static
ULONG_PTR
Pattern(
    _In_ PUCHAR Page,
    _In_ SIZE_T Word)
{
    ULONG_PTR x = (ULONG_PTR)Page ^ ((ULONG_PTR)Word * 0x9E3779B1u);
    x ^= x >> 15;
    x *= 0x85EBCA77u;
    return x;
}

START_TEST(MmContiguousStandby)
{
    SYSTEM_BASIC_INFORMATION Info;
    QUOTA_LIMITS Limits;
    BOOLEAN Old;
    PUCHAR Base;
    SIZE_T Size, Pages, i, w, Bad = 0;
    DWORD Error;
    NTSTATUS Status;

    RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &Old);
    Status = MemoryListCommand(MemoryFlushModifiedList);
    if (Status == STATUS_INVALID_INFO_CLASS)
    {
        skip(FALSE, "NitroPager is off\n");
        return;
    }
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_hex(NtQuerySystemInformation(SystemBasicInformation, &Info, sizeof(Info), NULL), STATUS_SUCCESS);

    Size = (SIZE_T)Info.NumberOfPhysicalPages * Info.PageSize / 3;
    Pages = Size / Info.PageSize;
    Base = VirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Base != NULL, "VirtualAlloc of %Iu bytes failed\n", Size);
    if (!Base)
        return;
    for (i = 0; i < Pages; i++)
    {
        PULONG_PTR Words = (PULONG_PTR)(Base + i * Info.PageSize);
        for (w = 0; w < Info.PageSize / sizeof(ULONG_PTR); w += 64)
            Words[w] = Pattern(Base + i * Info.PageSize, w);
    }

    /* Out of the working set and written: the pages wait on standby, their PTEs in transition */
    RtlZeroMemory(&Limits, sizeof(Limits));
    Limits.MinimumWorkingSetSize = (SIZE_T)-1;
    Limits.MaximumWorkingSetSize = (SIZE_T)-1;
    ok_eq_hex(NtSetInformationProcess(NtCurrentProcess(), ProcessQuotaLimits, &Limits, sizeof(Limits)), STATUS_SUCCESS);
    ok_eq_hex(MemoryListCommand(MemoryFlushModifiedList), STATUS_SUCCESS);

    Error = KmtRunKernelTest("MmContiguousStandby");
    ok_eq_int(Error, ERROR_SUCCESS);

    for (i = 0; i < Pages; i++)
    {
        PULONG_PTR Words = (PULONG_PTR)(Base + i * Info.PageSize);
        for (w = 0; w < Info.PageSize / sizeof(ULONG_PTR); w += 64)
        {
            if (Words[w] != Pattern(Base + i * Info.PageSize, w))
            {
                Bad++;
                break;
            }
        }
    }
    ok(Bad == 0, "%Iu of %Iu pages lost their data\n", Bad, Pages);
    VirtualFree(Base, 0, MEM_RELEASE);
}
