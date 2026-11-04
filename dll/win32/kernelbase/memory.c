/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     VirtualAlloc2, VirtualAlloc2FromApp, MapViewOfFile3, MapViewOfFileNuma2 and UnmapViewOfFile2
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Cygwin (sshfs-win, git for Windows' ssh, MSYS2) reserves its thread stacks with VirtualAlloc2 and an address
 * requirement and aborts at start when KernelBase.dll does not export it. V8 (Chrome, Electron) reserves its
 * address space as a placeholder (MEM_RESERVE_PLACEHOLDER), splits it with VirtualFree, and maps views and
 * private memory into the pieces with MapViewOfFile3 and VirtualAlloc2 (MEM_REPLACE_PLACEHOLDER), when the
 * three functions are exported. The work is NtAllocateVirtualMemoryEx's and NtMapViewOfSectionEx's; the checks
 * of the arguments made here first, with their error codes, are those measured on Windows 10.
 */

#include <stdarg.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winternl.h>

#define BASEP_GRANULARITY   0x10000
#define BASEP_PAGE_SIZE     0x1000

#define BASEP_ROUND_UP(x, a)    (((x) + (a) - 1) & ~((ULONG_PTR)(a) - 1))

static
BOOL
BasepSetNtStatus(NTSTATUS Status)
{
    if ((LONG)Status >= 0) return TRUE;
    SetLastError(RtlNtStatusToDosError(Status));
    return FALSE;
}

static
PVOID
BasepVirtualAlloc2(
    _In_opt_ HANDLE Process,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _In_reads_opt_(ParameterCount) MEM_EXTENDED_PARAMETER *ExtendedParameters,
    _In_ ULONG ParameterCount)
{
    MEM_ADDRESS_REQUIREMENTS *Requirements = NULL;
    BOOL SeenNumaNode = FALSE;
    SYSTEM_INFO SystemInfo;
    ULONG_PTR Low, High;
    SIZE_T Align, Needed;
    ULONG i;
    PVOID Base;

    if (!Process)
        Process = GetCurrentProcess();

    if (ParameterCount != 0 && ExtendedParameters == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    for (i = 0; i < ParameterCount; i++)
    {
        switch (ExtendedParameters[i].Type)
        {
            case MemExtendedParameterAddressRequirements:
                if (Requirements)
                {
                    SetLastError(ERROR_INVALID_PARAMETER);
                    return NULL;
                }
                if (!ExtendedParameters[i].Pointer)
                {
                    SetLastError(ERROR_NOACCESS);
                    return NULL;
                }
                Requirements = ExtendedParameters[i].Pointer;
                break;

            case MemExtendedParameterNumaNode:
                /* the single node of this system */
                if (SeenNumaNode || ExtendedParameters[i].ULong != 0)
                {
                    SetLastError(ERROR_INVALID_PARAMETER);
                    return NULL;
                }
                SeenNumaNode = TRUE;
                break;

            default:
                /* partitions, physical pages, attribute flags and the image machine: Windows takes them for
                   placeholders and special memory only; invalid types are rejected the same way */
                SetLastError(ERROR_INVALID_PARAMETER);
                return NULL;
        }
    }

    /* No requirement, or one that does not ask for anything: the system places it */
    if (!Requirements ||
        (!Requirements->LowestStartingAddress && !Requirements->HighestEndingAddress && !Requirements->Alignment))
    {
        Base = BaseAddress;
        if (!BasepSetNtStatus(NtAllocateVirtualMemoryEx(Process, &Base, &Size, AllocationType, PageProtection,
                                                        ExtendedParameters, ParameterCount)))
        {
            return NULL;
        }
        return Base;
    }

    if (BaseAddress || Size == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    GetSystemInfo(&SystemInfo);
    Low = (ULONG_PTR)Requirements->LowestStartingAddress;
    High = (ULONG_PTR)Requirements->HighestEndingAddress;
    Align = Requirements->Alignment;

    if ((Low & (BASEP_GRANULARITY - 1)) ||
        (High && ((High & (BASEP_PAGE_SIZE - 1)) != (BASEP_PAGE_SIZE - 1) ||
                  High > (ULONG_PTR)SystemInfo.lpMaximumApplicationAddress)) ||
        (High && Low > High) ||
        (Align && ((Align & (Align - 1)) || Align < BASEP_GRANULARITY || (Low & (Align - 1)))))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    if (Size > (SIZE_T)SystemInfo.lpMaximumApplicationAddress)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    Needed = BASEP_ROUND_UP(Size, BASEP_PAGE_SIZE);
    if (High && Needed - 1 > High - Low)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* A reserve is meant even when the caller only commits */
    if (!(AllocationType & MEM_RESERVE))
        AllocationType |= MEM_RESERVE;

    if (High && (High < BASEP_GRANULARITY || High - max(Low, BASEP_GRANULARITY) + 1 < Needed))
    {
        /* nothing can be allocated below the first allocation granule */
        SetLastError(ERROR_INVALID_ADDRESS);
        return NULL;
    }

    Base = NULL;
    if (!BasepSetNtStatus(NtAllocateVirtualMemoryEx(Process, &Base, &Size, AllocationType, PageProtection,
                                                    ExtendedParameters, ParameterCount)))
    {
        return NULL;
    }
    return Base;
}

PVOID
WINAPI
VirtualAlloc2(
    _In_opt_ HANDLE Process,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ParameterCount) MEM_EXTENDED_PARAMETER *ExtendedParameters,
    _In_ ULONG ParameterCount)
{
    return BasepVirtualAlloc2(Process,
                              BaseAddress,
                              Size,
                              AllocationType,
                              PageProtection,
                              ExtendedParameters,
                              ParameterCount);
}

PVOID
WINAPI
MapViewOfFile3(
    _In_ HANDLE FileMapping,
    _In_opt_ HANDLE Process,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG64 Offset,
    _In_ SIZE_T ViewSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ParameterCount) MEM_EXTENDED_PARAMETER *ExtendedParameters,
    _In_ ULONG ParameterCount)
{
    LARGE_INTEGER SectionOffset;
    PVOID Base = BaseAddress;

    if (!Process)
        Process = GetCurrentProcess();

    SectionOffset.QuadPart = Offset;
    if (!BasepSetNtStatus(NtMapViewOfSectionEx(FileMapping, Process, &Base, &SectionOffset, &ViewSize,
                                               AllocationType, PageProtection, ExtendedParameters, ParameterCount)))
    {
        return NULL;
    }
    return Base;
}

PVOID
WINAPI
MapViewOfFileNuma2(
    _In_ HANDLE FileMapping,
    _In_ HANDLE Process,
    _In_ ULONG64 Offset,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T ViewSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _In_ ULONG PreferredNode)
{
    MEM_EXTENDED_PARAMETER Parameter;

    /* NUMA_NO_PREFERRED_NODE: no parameter at all */
    if (PreferredNode == 0xFFFFFFFF)
    {
        return MapViewOfFile3(FileMapping, Process, BaseAddress, Offset, ViewSize, AllocationType, PageProtection,
                              NULL, 0);
    }

    RtlZeroMemory(&Parameter, sizeof(Parameter));
    Parameter.Type = MemExtendedParameterNumaNode;
    Parameter.ULong = PreferredNode;
    return MapViewOfFile3(FileMapping, Process, BaseAddress, Offset, ViewSize, AllocationType, PageProtection,
                          &Parameter, 1);
}

BOOL
WINAPI
UnmapViewOfFile2(
    _In_ HANDLE Process,
    _In_ PVOID BaseAddress,
    _In_ ULONG UnmapFlags)
{
    return BasepSetNtStatus(NtUnmapViewOfSectionEx(Process, BaseAddress, UnmapFlags));
}

PVOID
WINAPI
VirtualAlloc2FromApp(
    _In_opt_ HANDLE Process,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ParameterCount) MEM_EXTENDED_PARAMETER *ExtendedParameters,
    _In_ ULONG ParameterCount)
{
    /* a Store app may not get memory that can run code */
    if (PageProtection == PAGE_EXECUTE || PageProtection == PAGE_EXECUTE_READ ||
        PageProtection == PAGE_EXECUTE_READWRITE || PageProtection == PAGE_EXECUTE_WRITECOPY)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    return BasepVirtualAlloc2(Process,
                              BaseAddress,
                              Size,
                              AllocationType,
                              PageProtection,
                              ExtendedParameters,
                              ParameterCount);
}
