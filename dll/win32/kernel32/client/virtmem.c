/*
 * PROJECT:         ReactOS Win32 Base API
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            dll/win32/kernel32/client/virtmem.c
 * PURPOSE:         Handles virtual memory APIs
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include <k32.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

/*
 * @implemented
 */
LPVOID
NTAPI
VirtualAllocEx(IN HANDLE hProcess,
               IN LPVOID lpAddress,
               IN SIZE_T dwSize,
               IN DWORD flAllocationType,
               IN DWORD flProtect)
{
    NTSTATUS Status;

    /* Make sure the address is within the granularity of the system (64K) */
    if ((lpAddress != NULL) &&
        (lpAddress < UlongToPtr(BaseStaticServerData->SysInfo.AllocationGranularity)))
    {
        /* Fail the call */
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* Allocate the memory */
    Status = NtAllocateVirtualMemory(hProcess,
                                     &lpAddress,
                                     0,
                                     &dwSize,
                                     flAllocationType,
                                     flProtect);

    /* Check for status */
    if (!NT_SUCCESS(Status))
    {
        /* We failed */
        BaseSetLastNTError(Status);
        return NULL;
    }

    /* Return the allocated address */
    return lpAddress;
}

BOOL WINAPI GetNumaHighestNodeNumber(OUT PULONG HighestNodeNumber);

/*
 * @implemented
 *
 * The preferred NUMA node must exist (or be NUMA_NO_PREFERRED_NODE), else this is an invalid parameter as on
 * Windows; the memory is then allocated as VirtualAllocEx does, without a preference.
 */
LPVOID
NTAPI
VirtualAllocExNuma(IN HANDLE hProcess,
                   IN LPVOID lpAddress,
                   IN SIZE_T dwSize,
                   IN DWORD flAllocationType,
                   IN DWORD flProtect,
                   IN DWORD nndPreferred)
{
    ULONG HighestNode;

    if (nndPreferred != 0xFFFFFFFF)
    {
        if (!GetNumaHighestNodeNumber(&HighestNode))
            return NULL;

        if (nndPreferred > HighestNode)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return NULL;
        }
    }

    return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

/*
 * @implemented
 */
LPVOID
NTAPI
VirtualAlloc(IN LPVOID lpAddress,
             IN SIZE_T dwSize,
             IN DWORD flAllocationType,
             IN DWORD flProtect)
{
    /* Call the extended API */
    return VirtualAllocEx(GetCurrentProcess(),
                          lpAddress,
                          dwSize,
                          flAllocationType,
                          flProtect);
}

/*
 * @implemented
 */
BOOL
NTAPI
VirtualFreeEx(IN HANDLE hProcess,
              IN LPVOID lpAddress,
              IN SIZE_T dwSize,
              IN DWORD dwFreeType)
{
    NTSTATUS Status;

    /* Validate size and flags: a size goes with a release only to split or join placeholders */
    if (!(dwSize) || !(dwFreeType & MEM_RELEASE) ||
        (dwFreeType & (MEM_PRESERVE_PLACEHOLDER | MEM_COALESCE_PLACEHOLDERS)))
    {
        /* Free the memory */
        Status = NtFreeVirtualMemory(hProcess,
                                     &lpAddress,
                                     &dwSize,
                                     dwFreeType);
        if (!NT_SUCCESS(Status))
        {
            /* We failed */
            BaseSetLastNTError(Status);
            return FALSE;
        }

        /* Return success */
        return TRUE;
    }

    /* Invalid combo */
    BaseSetLastNTError(STATUS_INVALID_PARAMETER);
    return FALSE;
}

/*
 * @implemented
 */
BOOL
NTAPI
VirtualFree(IN LPVOID lpAddress,
            IN SIZE_T dwSize,
            IN DWORD dwFreeType)
{
    /* Call the extended API */
    return VirtualFreeEx(GetCurrentProcess(),
                         lpAddress,
                         dwSize,
                         dwFreeType);
}

/*
 * @implemented
 */
BOOL
NTAPI
VirtualProtect(IN LPVOID lpAddress,
               IN SIZE_T dwSize,
               IN DWORD flNewProtect,
               OUT PDWORD lpflOldProtect)
{
    /* Call the extended API */
    return VirtualProtectEx(GetCurrentProcess(),
                            lpAddress,
                            dwSize,
                            flNewProtect,
                            lpflOldProtect);
}

/*
 * @implemented
 */
BOOL
NTAPI
VirtualProtectEx(IN HANDLE hProcess,
                 IN LPVOID lpAddress,
                 IN SIZE_T dwSize,
                 IN DWORD flNewProtect,
                 OUT PDWORD lpflOldProtect)
{
    NTSTATUS Status;

    /* Change the protection */
    Status = NtProtectVirtualMemory(hProcess,
                                    &lpAddress,
                                    &dwSize,
                                    flNewProtect,
                                    (PULONG)lpflOldProtect);
    if (!NT_SUCCESS(Status))
    {
        /* We failed */
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Return success */
    return TRUE;
}

/*
 * @implemented
 */
BOOL
NTAPI
VirtualLock(IN LPVOID lpAddress,
            IN SIZE_T dwSize)
{
    NTSTATUS Status;
    SIZE_T RegionSize = dwSize;
    PVOID BaseAddress = lpAddress;

    /* Lock the memory */
    Status = NtLockVirtualMemory(NtCurrentProcess(),
                                 &BaseAddress,
                                 &RegionSize,
                                 MAP_PROCESS);
    if (!NT_SUCCESS(Status))
    {
        /* We failed */
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Return success */
    return TRUE;
}

/*
 * @implemented
 */
SIZE_T
NTAPI
VirtualQuery(IN LPCVOID lpAddress,
             OUT PMEMORY_BASIC_INFORMATION lpBuffer,
             IN SIZE_T dwLength)
{
    /* Call the extended API */
    return VirtualQueryEx(NtCurrentProcess(),
                          lpAddress,
                          lpBuffer,
                          dwLength);
}

/*
 * @implemented
 */
SIZE_T
NTAPI
VirtualQueryEx(IN HANDLE hProcess,
               IN LPCVOID lpAddress,
               OUT PMEMORY_BASIC_INFORMATION lpBuffer,
               IN SIZE_T dwLength)
{
    NTSTATUS Status;
    SIZE_T ResultLength;

    /* Query basic information */
    Status = NtQueryVirtualMemory(hProcess,
                                  (LPVOID)lpAddress,
                                  MemoryBasicInformation,
                                  lpBuffer,
                                  dwLength,
                                  &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        /* We failed */
        BaseSetLastNTError(Status);
        return 0;
    }

    /* Return the length returned */
    return ResultLength;
}

/*
 * @implemented
 */
BOOL
NTAPI
VirtualUnlock(IN LPVOID lpAddress,
              IN SIZE_T dwSize)
{
    NTSTATUS Status;
    SIZE_T RegionSize = dwSize;
    PVOID BaseAddress = lpAddress;

    /* Lock the memory */
    Status = NtUnlockVirtualMemory(NtCurrentProcess(),
                                   &BaseAddress,
                                   &RegionSize,
                                   MAP_PROCESS);
    if (!NT_SUCCESS(Status))
    {
        /* We failed */
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Return success */
    return TRUE;
}

/*
 * @implemented
 */
UINT
WINAPI
GetWriteWatch(IN DWORD dwFlags,
              IN PVOID lpBaseAddress,
              IN SIZE_T dwRegionSize,
              IN PVOID *lpAddresses,
              OUT PULONG_PTR lpdwCount,
              OUT PULONG lpdwGranularity)
{
    NTSTATUS Status;

    Status = NtGetWriteWatch(GetCurrentProcess(),
                             dwFlags,
                             lpBaseAddress,
                             dwRegionSize,
                             lpAddresses,
                             lpdwCount,
                             lpdwGranularity);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return -1;
    }

    return 0;
}

/*
 * @implemented
 */
UINT
WINAPI
ResetWriteWatch(IN LPVOID lpBaseAddress,
                IN SIZE_T dwRegionSize)
{
    NTSTATUS Status;

    Status = NtResetWriteWatch(NtCurrentProcess(),
                               lpBaseAddress,
                               dwRegionSize);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return -1;
    }

    return 0;
}

/*
 * @implemented
 */
BOOL
WINAPI
AllocateUserPhysicalPages(IN HANDLE hProcess,
                          IN PULONG_PTR NumberOfPages,
                          OUT PULONG_PTR UserPfnArray)
{
    NTSTATUS Status;

    Status = NtAllocateUserPhysicalPages(hProcess, NumberOfPages, UserPfnArray);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
FreeUserPhysicalPages(IN HANDLE hProcess,
                      IN PULONG_PTR NumberOfPages,
                      IN PULONG_PTR PageArray)
{
    NTSTATUS Status;

    Status = NtFreeUserPhysicalPages(hProcess, NumberOfPages, PageArray);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
MapUserPhysicalPages(IN PVOID VirtualAddress,
                     IN ULONG_PTR NumberOfPages,
                     OUT PULONG_PTR PageArray OPTIONAL)
{
    NTSTATUS Status;

    Status = NtMapUserPhysicalPages(VirtualAddress, NumberOfPages, PageArray);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
MapUserPhysicalPagesScatter(IN PVOID *VirtualAddresses,
                            IN ULONG_PTR NumberOfPages,
                            OUT PULONG_PTR PageArray OPTIONAL)
{
    NTSTATUS Status;

    Status = NtMapUserPhysicalPagesScatter(VirtualAddresses,
                                           NumberOfPages,
                                           PageArray);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 *
 * Windows brings the pages of the ranges into memory ahead of use, and does nothing else: the call checks its
 * parameters and has no result besides that. The kernel here has no call for it, so the parameters are checked
 * the way Windows 10 checks them and the pages are left to the memory manager.
 */
BOOL
WINAPI
PrefetchVirtualMemory(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR NumberOfEntries,
    _In_reads_(NumberOfEntries) PWIN32_MEMORY_RANGE_ENTRY VirtualAddresses,
    _In_ ULONG Flags)
{
    ULONG_PTR HighestAddress = (ULONG_PTR)BaseStaticServerData->SysInfo.MaximumUserModeAddress;
    ULONG_PTR Index, Start, End;
    SIZE_T Size;
    BOOLEAN Invalid = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;

    /* The order of the checks is the one of Windows 10: the number of entries, the handle, the array, the flags, the ranges */
    if (NumberOfEntries == 0)
    {
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    Status = BasepCheckHandleType(hProcess, L"Process", PROCESS_VM_OPERATION);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    if (VirtualAddresses == NULL)
    {
        BaseSetLastNTError(STATUS_ACCESS_VIOLATION);
        return FALSE;
    }

    _SEH2_TRY
    {
        /* The whole array is read, an unreadable entry beyond a bad one still is an access violation */
        for (Index = 0; Index < NumberOfEntries; Index++)
        {
            Start = (ULONG_PTR)VirtualAddresses[Index].VirtualAddress;
            Size = VirtualAddresses[Index].NumberOfBytes;
            End = Start + Size;

            /* No empty range, no range that wraps around or ends above the memory that a process can use */
            if (Size == 0 || End < Start || End - 1 > HighestAddress)
                Invalid = TRUE;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_ACCESS_VIOLATION;
    }
    _SEH2_END;

    if (NT_SUCCESS(Status) && (Flags != 0 || Invalid))
        Status = STATUS_INVALID_PARAMETER;

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/* EOF */
