/*
 * PROJECT:         ReactOS Win32 Base API
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         System Information Functions
 * COPYRIGHT:       Emanuele Aliberti
 *                  Christoph von Wittich
 *                  Thomas Weidenmueller
 *                  Gunnar Andre Dalsnes
 *                  Stanislav Motylkov (x86corez@gmail.com)
 *                  Mark Jansen (mark.jansen@reactos.org)
 *                  Copyright 2023 Ratin Gao <ratin@knsoft.org>
 */

/* INCLUDES *******************************************************************/

#include <k32.h>

#define NDEBUG
#include <debug.h>

#define PV_NT351 0x00030033

/* PRIVATE FUNCTIONS **********************************************************/

VOID
WINAPI
GetSystemInfoInternal(IN PSYSTEM_BASIC_INFORMATION BasicInfo,
                      IN PSYSTEM_PROCESSOR_INFORMATION ProcInfo,
                      OUT LPSYSTEM_INFO SystemInfo)
{
    RtlZeroMemory(SystemInfo, sizeof (SYSTEM_INFO));
    SystemInfo->wProcessorArchitecture = ProcInfo->ProcessorArchitecture;
    SystemInfo->wReserved = 0;
    SystemInfo->dwPageSize = BasicInfo->PageSize;
    SystemInfo->lpMinimumApplicationAddress = (PVOID)BasicInfo->MinimumUserModeAddress;
    SystemInfo->lpMaximumApplicationAddress = (PVOID)BasicInfo->MaximumUserModeAddress;
    SystemInfo->dwActiveProcessorMask = BasicInfo->ActiveProcessorsAffinityMask;
    SystemInfo->dwNumberOfProcessors = BasicInfo->NumberOfProcessors;
    SystemInfo->wProcessorLevel = ProcInfo->ProcessorLevel;
    SystemInfo->wProcessorRevision = ProcInfo->ProcessorRevision;
    SystemInfo->dwAllocationGranularity = BasicInfo->AllocationGranularity;

    switch (ProcInfo->ProcessorArchitecture)
    {
        case PROCESSOR_ARCHITECTURE_INTEL:
            switch (ProcInfo->ProcessorLevel)
            {
                case 3:
                    SystemInfo->dwProcessorType = PROCESSOR_INTEL_386;
                    break;
                case 4:
                    SystemInfo->dwProcessorType = PROCESSOR_INTEL_486;
                    break;
                default:
                    SystemInfo->dwProcessorType = PROCESSOR_INTEL_PENTIUM;
            }
            break;

        case PROCESSOR_ARCHITECTURE_AMD64:
            SystemInfo->dwProcessorType = PROCESSOR_AMD_X8664;
            break;

        case PROCESSOR_ARCHITECTURE_IA64:
            SystemInfo->dwProcessorType = PROCESSOR_INTEL_IA64;
            break;

        default:
            SystemInfo->dwProcessorType = 0;
            break;
    }

    if (PV_NT351 > GetProcessVersion(0))
    {
        SystemInfo->wProcessorLevel = 0;
        SystemInfo->wProcessorRevision = 0;
    }
}

static
UINT
BaseQuerySystemFirmware(
    _In_ DWORD FirmwareTableProviderSignature,
    _In_ DWORD FirmwareTableID,
    _Out_writes_bytes_to_opt_(BufferSize, return) PVOID pFirmwareTableBuffer,
    _In_ DWORD BufferSize,
    _In_ SYSTEM_FIRMWARE_TABLE_ACTION Action)
{
    SYSTEM_FIRMWARE_TABLE_INFORMATION* SysFirmwareInfo;
    ULONG Result = 0, ReturnedSize;
    ULONG TotalSize = BufferSize + sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION);
    NTSTATUS Status;

    SysFirmwareInfo = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, TotalSize);
    if (!SysFirmwareInfo)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    _SEH2_TRY
    {
        SysFirmwareInfo->ProviderSignature = FirmwareTableProviderSignature;
        SysFirmwareInfo->TableID = FirmwareTableID;
        SysFirmwareInfo->Action = Action;
        SysFirmwareInfo->TableBufferLength = BufferSize;

        Status = NtQuerySystemInformation(SystemFirmwareTableInformation, SysFirmwareInfo, TotalSize, &ReturnedSize);

        if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_TOO_SMALL)
            Result = SysFirmwareInfo->TableBufferLength;

        if (NT_SUCCESS(Status) && pFirmwareTableBuffer)
        {
            RtlCopyMemory(pFirmwareTableBuffer, SysFirmwareInfo->TableBuffer, SysFirmwareInfo->TableBufferLength);
        }
    }
    _SEH2_FINALLY
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, SysFirmwareInfo);
    }
    _SEH2_END;

    BaseSetLastNTError(Status);
    return Result;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
SIZE_T
WINAPI
GetLargePageMinimum(VOID)
{
    return SharedUserData->LargePageMinimum;
}

/*
 * @implemented
 */
VOID
WINAPI
GetSystemInfo(IN LPSYSTEM_INFO lpSystemInfo)
{
    SYSTEM_BASIC_INFORMATION BasicInfo;
    SYSTEM_PROCESSOR_INFORMATION ProcInfo;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemBasicInformation,
                                      &BasicInfo,
                                      sizeof(BasicInfo),
                                      0);
    if (!NT_SUCCESS(Status)) return;

    Status = NtQuerySystemInformation(SystemProcessorInformation,
                                      &ProcInfo,
                                      sizeof(ProcInfo),
                                      0);
    if (!NT_SUCCESS(Status)) return;

    GetSystemInfoInternal(&BasicInfo, &ProcInfo, lpSystemInfo);
}

/*
 * @implemented
 */
BOOL
WINAPI
IsProcessorFeaturePresent(IN DWORD ProcessorFeature)
{
    if (ProcessorFeature >= PROCESSOR_FEATURE_MAX) return FALSE;
    return ((BOOL)SharedUserData->ProcessorFeatures[ProcessorFeature]);
}

/*
 * @implemented
 */
BOOL
WINAPI
GetSystemRegistryQuota(OUT PDWORD pdwQuotaAllowed,
                       OUT PDWORD pdwQuotaUsed)
{
    SYSTEM_REGISTRY_QUOTA_INFORMATION QuotaInfo;
    ULONG BytesWritten;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemRegistryQuotaInformation,
                                      &QuotaInfo,
                                      sizeof(QuotaInfo),
                                      &BytesWritten);
    if (NT_SUCCESS(Status))
    {
      if (pdwQuotaAllowed) *pdwQuotaAllowed = QuotaInfo.RegistryQuotaAllowed;
      if (pdwQuotaUsed) *pdwQuotaUsed = QuotaInfo.RegistryQuotaUsed;
      return TRUE;
    }

    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
VOID
WINAPI
GetNativeSystemInfo(IN LPSYSTEM_INFO lpSystemInfo)
{
    SYSTEM_BASIC_INFORMATION BasicInfo;
    SYSTEM_PROCESSOR_INFORMATION ProcInfo;
    NTSTATUS Status;

    Status = RtlGetNativeSystemInformation(SystemBasicInformation,
                                           &BasicInfo,
                                           sizeof(BasicInfo),
                                           0);
    if (!NT_SUCCESS(Status)) return;

    Status = RtlGetNativeSystemInformation(SystemProcessorInformation,
                                           &ProcInfo,
                                           sizeof(ProcInfo),
                                           0);
    if (!NT_SUCCESS(Status)) return;

    GetSystemInfoInternal(&BasicInfo, &ProcInfo, lpSystemInfo);
}

/*
 * @implemented
 */
BOOL
WINAPI
GetLogicalProcessorInformation(OUT PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer,
                               IN OUT PDWORD ReturnLength)
{
    NTSTATUS Status;

    if (!ReturnLength)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Status = NtQuerySystemInformation(SystemLogicalProcessorInformation,
                                      Buffer,
                                      *ReturnLength,
                                      ReturnLength);

    /* Normalize the error to what Win32 expects */
    if (Status == STATUS_INFO_LENGTH_MISMATCH) Status = STATUS_BUFFER_TOO_SMALL;
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
QueryIdleProcessorCycleTime(
    _Inout_ PULONG BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) PULONG64 ProcessorIdleCycleTime)
{
    NTSTATUS Status;

    /* Without a buffer, return the size it needs */
    if (!ProcessorIdleCycleTime)
    {
        Status = NtQuerySystemInformation(SystemProcessorIdleCycleTimeInformation,
                                          NULL,
                                          0,
                                          BufferLength);
        if (Status == STATUS_BUFFER_TOO_SMALL)
            Status = STATUS_SUCCESS;
    }
    else
    {
        Status = NtQuerySystemInformation(SystemProcessorIdleCycleTimeInformation,
                                          ProcessorIdleCycleTime,
                                          *BufferLength,
                                          BufferLength);
    }
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
GetNumaHighestNodeNumber(OUT PULONG HighestNodeNumber)
{
    NTSTATUS Status;
    ULONG Length;
    ULONG PartialInfo[2]; // First two members of SYSTEM_NUMA_INFORMATION

    /* Query partial NUMA info */
    Status = NtQuerySystemInformation(SystemNumaProcessorMap,
                                      PartialInfo,
                                      sizeof(PartialInfo),
                                      &Length);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    if (Length < sizeof(ULONG))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* First member of the struct is the highest node number */
    *HighestNodeNumber = PartialInfo[0];
    return TRUE;
}

static
ULONG
BasepLogicalProcessorInformationExSize(
    _In_ LOGICAL_PROCESSOR_RELATIONSHIP Relationship)
{
    switch (Relationship)
    {
        case RelationProcessorCore:
        case RelationProcessorPackage:
            return FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor.GroupMask[1]);

        case RelationNumaNode:
            return FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, NumaNode) +
                   sizeof(NUMA_NODE_RELATIONSHIP);

        case RelationCache:
            return FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Cache) +
                   sizeof(CACHE_RELATIONSHIP);

        case RelationGroup:
            return FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Group.GroupInfo[1]);

        default:
            return 0;
    }
}

/*
 * @implemented
 *
 * Built from the information of GetLogicalProcessorInformation, in its
 * order, with all processors in group 0, followed by the group entry.
 */
BOOL
WINAPI
GetLogicalProcessorInformationEx(
    _In_ LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType,
    _Out_writes_bytes_to_opt_(*ReturnedLength, *ReturnedLength) PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Buffer,
    _Inout_ PDWORD ReturnedLength)
{
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Info = NULL;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Entry;
    SYSTEM_BASIC_INFORMATION BasicInfo;
    ULONG InfoLength, Count, Index, Required, Size;
    NTSTATUS Status;
    PUCHAR Output;
    BOOL Result = FALSE;

    if (!ReturnedLength)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Relationships this version does not know have no entries */
    if ((RelationshipType > RelationGroup) && (RelationshipType != RelationAll))
    {
        *ReturnedLength = 0;
        return TRUE;
    }

    Status = NtQuerySystemInformation(SystemBasicInformation,
                                      &BasicInfo,
                                      sizeof(BasicInfo),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Get the information without group details */
    InfoLength = 0;
    Status = NtQuerySystemInformation(SystemLogicalProcessorInformation,
                                      NULL,
                                      0,
                                      &InfoLength);
    while ((Status == STATUS_INFO_LENGTH_MISMATCH) || (Status == STATUS_BUFFER_TOO_SMALL))
    {
        if (Info)
            RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
        Info = RtlAllocateHeap(RtlGetProcessHeap(), 0, InfoLength);
        if (!Info)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        Status = NtQuerySystemInformation(SystemLogicalProcessorInformation,
                                          Info,
                                          InfoLength,
                                          &InfoLength);
    }
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        goto Cleanup;
    }
    Count = InfoLength / sizeof(*Info);

    /* Compute the size of the result */
    Required = 0;
    for (Index = 0; Index < Count; Index++)
    {
        if ((RelationshipType == RelationAll) || (Info[Index].Relationship == RelationshipType))
            Required += BasepLogicalProcessorInformationExSize(Info[Index].Relationship);
    }
    if ((RelationshipType == RelationAll) || (RelationshipType == RelationGroup))
        Required += BasepLogicalProcessorInformationExSize(RelationGroup);

    if ((*ReturnedLength < Required) || (!Buffer && Required))
    {
        *ReturnedLength = Required;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        goto Cleanup;
    }

    /* Fill it */
    Output = (PUCHAR)Buffer;
    for (Index = 0; Index < Count; Index++)
    {
        if ((RelationshipType != RelationAll) && (Info[Index].Relationship != RelationshipType))
            continue;

        Size = BasepLogicalProcessorInformationExSize(Info[Index].Relationship);
        if (!Size)
            continue;

        Entry = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Output;
        RtlZeroMemory(Entry, Size);
        Entry->Relationship = Info[Index].Relationship;
        Entry->Size = Size;
        switch (Info[Index].Relationship)
        {
            case RelationProcessorCore:
            case RelationProcessorPackage:
                if (Info[Index].Relationship == RelationProcessorCore)
                    Entry->Processor.Flags = Info[Index].ProcessorCore.Flags;
                Entry->Processor.GroupCount = 1;
                Entry->Processor.GroupMask[0].Mask = Info[Index].ProcessorMask;
                break;

            case RelationNumaNode:
                Entry->NumaNode.NodeNumber = Info[Index].NumaNode.NodeNumber;
                Entry->NumaNode.GroupMask.Mask = Info[Index].ProcessorMask;
                break;

            case RelationCache:
                Entry->Cache.Level = Info[Index].Cache.Level;
                Entry->Cache.Associativity = Info[Index].Cache.Associativity;
                Entry->Cache.LineSize = Info[Index].Cache.LineSize;
                Entry->Cache.CacheSize = Info[Index].Cache.Size;
                Entry->Cache.Type = Info[Index].Cache.Type;
                Entry->Cache.GroupMask.Mask = Info[Index].ProcessorMask;
                break;

            default:
                break;
        }
        Output += Size;
    }

    if ((RelationshipType == RelationAll) || (RelationshipType == RelationGroup))
    {
        Size = BasepLogicalProcessorInformationExSize(RelationGroup);
        Entry = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Output;
        RtlZeroMemory(Entry, Size);
        Entry->Relationship = RelationGroup;
        Entry->Size = Size;
        Entry->Group.MaximumGroupCount = 1;
        Entry->Group.ActiveGroupCount = 1;
        Entry->Group.GroupInfo[0].MaximumProcessorCount = BasicInfo.NumberOfProcessors;
        Entry->Group.GroupInfo[0].ActiveProcessorCount = BasicInfo.NumberOfProcessors;
        Entry->Group.GroupInfo[0].ActiveProcessorMask = BasicInfo.ActiveProcessorsAffinityMask;
        Output += Size;
    }

    *ReturnedLength = Required;
    Result = TRUE;

Cleanup:
    if (Info)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
    return Result;
}

/*
 * @implemented
 *
 * Built from the information of GetLogicalProcessorInformation, with all processors in group 0. The kernel does not
 * report caches, so a processor has last level cache index 0 unless the information holds caches. The processor
 * ids follow Windows: 0x100 plus the number of the processor in its group. There is no allocation of CPU sets, so
 * no entry is parked, allocated or real time, and the efficiency class is 0.
 */
BOOL
WINAPI
GetSystemCpuSetInformation(
    _Out_writes_bytes_to_opt_(BufferLength, *ReturnedLength) PSYSTEM_CPU_SET_INFORMATION Information,
    _In_ ULONG BufferLength,
    _Out_ PULONG ReturnedLength,
    _In_opt_ HANDLE Process,
    _Reserved_ ULONG Flags)
{
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Info = NULL;
    SYSTEM_BASIC_INFORMATION BasicInfo;
    PSYSTEM_CPU_SET_INFORMATION Entry;
    ULONG InfoLength, Count, Index, Bit, Required, Core, Numa, Cache, MaxLevel;
    KAFFINITY Mask;
    NTSTATUS Status;
    BOOL Result = FALSE;

    if (!ReturnedLength)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Windows clears the length before it looks at anything else */
    *ReturnedLength = 0;

    if (Flags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /*
     * The process that the allocation is looked up for: a handle of a process that may be queried (limited
     * information is enough), else ERROR_INVALID_HANDLE for any other object and ERROR_ACCESS_DENIED for a
     * process handle without the right
     */
    if (Process && (Process != NtCurrentProcess()))
    {
        union
        {
            OBJECT_TYPE_INFORMATION Type;
            UCHAR Buffer[sizeof(OBJECT_TYPE_INFORMATION) + 64 * sizeof(WCHAR)];
        } TypeInfo;
        OBJECT_BASIC_INFORMATION BasicObjectInfo;

        Status = NtQueryObject(Process, ObjectTypeInformation, &TypeInfo, sizeof(TypeInfo), NULL);
        if (!NT_SUCCESS(Status))
        {
            BaseSetLastNTError(Status);
            return FALSE;
        }
        if ((TypeInfo.Type.TypeName.Length != 7 * sizeof(WCHAR)) ||
            _wcsnicmp(TypeInfo.Type.TypeName.Buffer, L"Process", 7))
        {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }

        Status = NtQueryObject(Process, ObjectBasicInformation, &BasicObjectInfo, sizeof(BasicObjectInfo), NULL);
        if (!NT_SUCCESS(Status))
        {
            BaseSetLastNTError(Status);
            return FALSE;
        }
        if (!(BasicObjectInfo.GrantedAccess & (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION)))
        {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }

    Status = NtQuerySystemInformation(SystemBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    InfoLength = 0;
    Status = NtQuerySystemInformation(SystemLogicalProcessorInformation, NULL, 0, &InfoLength);
    while ((Status == STATUS_INFO_LENGTH_MISMATCH) || (Status == STATUS_BUFFER_TOO_SMALL))
    {
        if (Info)
            RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
        Info = RtlAllocateHeap(RtlGetProcessHeap(), 0, InfoLength);
        if (!Info)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        Status = NtQuerySystemInformation(SystemLogicalProcessorInformation, Info, InfoLength, &InfoLength);
    }
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        goto Cleanup;
    }
    Count = InfoLength / sizeof(*Info);

    Mask = BasicInfo.ActiveProcessorsAffinityMask;
    Required = 0;
    for (Bit = 0; Bit < RTL_BITS_OF(Mask); Bit++)
    {
        if (Mask & ((KAFFINITY)1 << Bit))
            Required += sizeof(SYSTEM_CPU_SET_INFORMATION);
    }

    if (BufferLength < Required)
    {
        *ReturnedLength = Required;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        goto Cleanup;
    }

    /* A length that fits and no buffer */
    if (!Information && Required)
    {
        SetLastError(ERROR_NOACCESS);
        goto Cleanup;
    }

    /* The last level of cache that the information holds, if any */
    MaxLevel = 0;
    for (Index = 0; Index < Count; Index++)
    {
        if ((Info[Index].Relationship == RelationCache) && (Info[Index].Cache.Level > MaxLevel))
            MaxLevel = Info[Index].Cache.Level;
    }

    Entry = Information;
    for (Bit = 0; Bit < RTL_BITS_OF(Mask); Bit++)
    {
        KAFFINITY Member = (KAFFINITY)1 << Bit;
        ULONG CoreIndex = 0, NumaIndex = 0, CacheIndex = 0, Found = 0;

        if (!(Mask & Member))
            continue;

        /* The indexes count the entries of a relationship in the order of the information */
        Core = Numa = Cache = 0;
        for (Index = 0; Index < Count; Index++)
        {
            switch (Info[Index].Relationship)
            {
                case RelationProcessorCore:
                    if (Info[Index].ProcessorMask & Member)
                        CoreIndex = Core;
                    Core++;
                    break;

                case RelationNumaNode:
                    if (Info[Index].ProcessorMask & Member)
                        NumaIndex = Numa;
                    Numa++;
                    break;

                case RelationCache:
                    if (Info[Index].Cache.Level == MaxLevel)
                    {
                        if ((Info[Index].ProcessorMask & Member) && !Found)
                        {
                            CacheIndex = Cache;
                            Found = 1;
                        }
                        Cache++;
                    }
                    break;

                default:
                    break;
            }
        }

        RtlZeroMemory(Entry, sizeof(*Entry));
        Entry->Size = sizeof(*Entry);
        Entry->Type = CpuSetInformation;
        Entry->CpuSet.Id = 0x100 + Bit;
        Entry->CpuSet.Group = 0;
        Entry->CpuSet.LogicalProcessorIndex = (UCHAR)Bit;
        Entry->CpuSet.CoreIndex = (UCHAR)CoreIndex;
        Entry->CpuSet.LastLevelCacheIndex = (UCHAR)CacheIndex;
        Entry->CpuSet.NumaNodeIndex = (UCHAR)NumaIndex;
        Entry++;
    }

    *ReturnedLength = Required;
    Result = TRUE;

Cleanup:
    if (Info)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
    return Result;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetNumaNodeProcessorMask(IN UCHAR Node,
                         OUT PULONGLONG ProcessorMask)
{
    NTSTATUS Status;
    SYSTEM_NUMA_INFORMATION NumaInformation;
    ULONG Length;

    /* Query NUMA information */
    Status = NtQuerySystemInformation(SystemNumaProcessorMap,
                                      &NumaInformation,
                                      sizeof(NumaInformation),
                                      &Length);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Validate input node number */
    if (Node > NumaInformation.HighestNodeNumber)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Return mask for that node */
    *ProcessorMask = NumaInformation.ActiveProcessorsAffinityMask[Node];
    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetNumaProcessorNode(IN UCHAR Processor,
                     OUT PUCHAR NodeNumber)
{
    NTSTATUS Status;
    SYSTEM_NUMA_INFORMATION NumaInformation;
    ULONG Length;
    ULONG Node;
    ULONGLONG Proc;

    /* Can't handle processor number >= 32 */
    if (Processor >= MAXIMUM_PROCESSORS)
    {
        *NodeNumber = -1;
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Query NUMA information */
    Status = NtQuerySystemInformation(SystemNumaProcessorMap,
                                      &NumaInformation,
                                      sizeof(NumaInformation),
                                      &Length);
    if (!NT_SUCCESS(Status))
    {
        *NodeNumber = -1;
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Find ourselves */
    Node = 0;
    Proc = 1ULL << Processor;
    while ((Proc & NumaInformation.ActiveProcessorsAffinityMask[Node]) == 0ULL)
    {
        ++Node;
        /* Out of options */
        if (Node > NumaInformation.HighestNodeNumber)
        {
            *NodeNumber = -1;
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }

    /* Return found node */
    *NodeNumber = Node;
    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetNumaAvailableMemoryNode(IN UCHAR Node,
                           OUT PULONGLONG AvailableBytes)
{
    NTSTATUS Status;
    SYSTEM_NUMA_INFORMATION NumaInformation;
    ULONG Length;

    /* Query NUMA information */
    Status = NtQuerySystemInformation(SystemNumaAvailableMemory,
                                      &NumaInformation,
                                      sizeof(NumaInformation),
                                      &Length);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Validate input node number */
    if (Node > NumaInformation.HighestNodeNumber)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Return available memory for that node */
    *AvailableBytes = NumaInformation.AvailableMemory[Node];
    return TRUE;
}

_Success_(return > 0)
DWORD
WINAPI
GetFirmwareEnvironmentVariableExW(
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpGuid,
    _Out_writes_bytes_to_opt_(nSize, return) PVOID pBuffer,
    _In_ DWORD nSize,
    _Out_opt_ PDWORD pdwAttribubutes);

_Success_(return > 0)
DWORD
WINAPI
GetFirmwareEnvironmentVariableExA(
    _In_ LPCSTR lpName,
    _In_ LPCSTR lpGuid,
    _Out_writes_bytes_to_opt_(nSize, return) PVOID pBuffer,
    _In_ DWORD nSize,
    _Out_opt_ PDWORD pdwAttribubutes);

BOOL
WINAPI
SetFirmwareEnvironmentVariableExW(
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpGuid,
    _In_reads_bytes_opt_(nSize) PVOID pValue,
    _In_ DWORD nSize,
    _In_ DWORD dwAttributes);

BOOL
WINAPI
SetFirmwareEnvironmentVariableExA(
    _In_ LPCSTR lpName,
    _In_ LPCSTR lpGuid,
    _In_reads_bytes_opt_(nSize) PVOID pValue,
    _In_ DWORD nSize,
    _In_ DWORD dwAttributes);

_Success_(return > 0)
DWORD
WINAPI
GetFirmwareEnvironmentVariableW(
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpGuid,
    _Out_writes_bytes_to_opt_(nSize, return) PVOID pBuffer,
    _In_ DWORD nSize)
{
    return GetFirmwareEnvironmentVariableExW(lpName, lpGuid, pBuffer, nSize, NULL);
}

BOOL
WINAPI
SetFirmwareEnvironmentVariableW(
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpGuid,
    _In_reads_bytes_opt_(nSize) PVOID pValue,
    _In_ DWORD nSize)
{
    return SetFirmwareEnvironmentVariableExW(lpName,
                                             lpGuid,
                                             pValue,
                                             nSize,
                                             VARIABLE_ATTRIBUTE_NON_VOLATILE);
}

/**
 * @name EnumSystemFirmwareTables
 * @implemented
 *
 * Obtains firmware table identifiers.
 * https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-enumsystemfirmwaretables
 *
 * @param FirmwareTableProviderSignature
 * Can be either ACPI, FIRM, or RSMB.
 *
 * @param pFirmwareTableBuffer
 * Pointer to the output buffer, can be NULL.
 *
 * @param BufferSize
 * Size of the output buffer.
 *
 * @return
 * Actual size of the data in case of success, 0 otherwise.
 *
 * @remarks
 * Data would be written to buffer only if the specified size is
 * larger or equal to the actual size, in the other case Last Error
 * value would be set to ERROR_INSUFFICIENT_BUFFER.
 * In case of incorrect provider signature, Last Error value would be
 * set to ERROR_INVALID_FUNCTION.
 *
 */
UINT
WINAPI
EnumSystemFirmwareTables(
    _In_ DWORD FirmwareTableProviderSignature,
    _Out_writes_bytes_to_opt_(BufferSize, return) PVOID pFirmwareTableEnumBuffer,
    _In_ DWORD BufferSize)
{
    return BaseQuerySystemFirmware(FirmwareTableProviderSignature,
                                   0,
                                   pFirmwareTableEnumBuffer,
                                   BufferSize,
                                   SystemFirmwareTable_Enumerate);
}

/**
 * @name GetSystemFirmwareTable
 * @implemented
 *
 * Obtains the firmware table data.
 * https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
 *
 * @param FirmwareTableProviderSignature
 * Can be either ACPI, FIRM, or RSMB.
 *
 * @param FirmwareTableID
 * Correct table identifier.
 *
 * @param pFirmwareTableBuffer
 * Pointer to the output buffer, can be NULL.
 *
 * @param BufferSize
 * Size of the output buffer.
 *
 * @return
 * Actual size of the data in case of success, 0 otherwise.
 *
 * @remarks
 * Data would be written to buffer only if the specified size is
 * larger or equal to the actual size, in the other case Last Error
 * value would be set to ERROR_INSUFFICIENT_BUFFER.
 * In case of incorrect provider signature, Last Error value would be
 * set to ERROR_INVALID_FUNCTION.
 * Also Last Error value becomes ERROR_NOT_FOUND if incorrect
 * table identifier was specified along with ACPI provider, and
 * ERROR_INVALID_PARAMETER along with FIRM provider. The RSMB provider
 * accepts any table identifier.
 *
 */
UINT
WINAPI
GetSystemFirmwareTable(
    _In_ DWORD FirmwareTableProviderSignature,
    _In_ DWORD FirmwareTableID,
    _Out_writes_bytes_to_opt_(BufferSize, return) PVOID pFirmwareTableBuffer,
    _In_ DWORD BufferSize)
{
    return BaseQuerySystemFirmware(FirmwareTableProviderSignature,
                                   FirmwareTableID,
                                   pFirmwareTableBuffer,
                                   BufferSize,
                                   SystemFirmwareTable_Get);
}

#define SMBIOS_PROVIDER_RSMB            0x52534D42  /* 'RSMB' */

/* SMBIOS structure types and Memory Device (type 17) fields, DMTF DSP0134 */
#define SMBIOS_TYPE_MEMORY_DEVICE       17
#define SMBIOS_TYPE_END_OF_TABLE        127
#define SMBIOS_MEMDEV_MIN_LENGTH        0x15    /* formatted area of a Memory Device since SMBIOS 2.1 */
#define SMBIOS_MEMDEV_SIZE              0x0C    /* WORD, SMBIOS 2.1+ */
#define SMBIOS_MEMDEV_EXTENDED_SIZE     0x1C    /* DWORD, SMBIOS 2.7+ */
#define SMBIOS_MEMDEV_SIZE_UNKNOWN      0xFFFF
#define SMBIOS_MEMDEV_SIZE_USE_EXTENDED 0x7FFF
#define SMBIOS_MEMDEV_SIZE_IN_KB        0x8000

/*
 * Adds up the sizes of the Memory Device structures of a raw SMBIOS table,
 * in kilobytes. Returns FALSE when a structure runs past the end of the table
 * or a Memory Device is one that Windows refuses (see below).
 */
static
BOOL
BaseSumSmbiosMemoryDevices(
    _In_reads_bytes_(Length) const UCHAR *Table,
    _In_ ULONG Length,
    _Out_ PULONGLONG TotalKb)
{
    ULONG Offset = 0, Next;
    ULONGLONG Total = 0;
    UCHAR Type, HeaderLength;
    USHORT Size;

    while (Offset + 4 <= Length)
    {
        Type = Table[Offset];
        HeaderLength = Table[Offset + 1];
        if (HeaderLength < 4 || HeaderLength > Length - Offset)
            return FALSE;

        if (Type == SMBIOS_TYPE_MEMORY_DEVICE)
        {
            ULONGLONG Kb;

            /* What Windows Server 2022 rejects as invalid data (each measured with one 4096 MB device
             * and one more device that differs only in the field named): a formatted area shorter
             * than 0x15 bytes (0x14 fails, 0x15 and 0x1B pass), and a Size of 0xFFFF (unknown, also
             * with a 0x15 byte area). A Size of 0 (no device in the socket) is skipped. */
            if (HeaderLength < SMBIOS_MEMDEV_MIN_LENGTH)
                return FALSE;

            Size = *(const USHORT UNALIGNED *)&Table[Offset + SMBIOS_MEMDEV_SIZE];
            if (Size == SMBIOS_MEMDEV_SIZE_UNKNOWN)
                return FALSE;

            Kb = 0;
            if (Size == SMBIOS_MEMDEV_SIZE_USE_EXTENDED &&
                HeaderLength >= SMBIOS_MEMDEV_EXTENDED_SIZE + sizeof(ULONG))
            {
                ULONG Extended = *(const ULONG UNALIGNED *)&Table[Offset + SMBIOS_MEMDEV_EXTENDED_SIZE];

                /* Extended Size: bits 30:0 in megabytes. Windows takes 0x7FFF MB (the Size field's own
                 * value) when the DWORD is 0, and 0 when only bit 31 is set (measured). */
                if (Extended == 0)
                    Kb = (ULONGLONG)SMBIOS_MEMDEV_SIZE_USE_EXTENDED * 1024;
                else
                    Kb = (ULONGLONG)(Extended & 0x7FFFFFFF) * 1024;
            }
            else if (Size & SMBIOS_MEMDEV_SIZE_IN_KB)
            {
                /* bit 15 selects KB over MB */
                Kb = Size & ~SMBIOS_MEMDEV_SIZE_IN_KB;
            }
            else
            {
                Kb = (ULONGLONG)Size * 1024;
            }

            /* A sum that does not fit is not a memory size */
            if (Kb > ~(ULONGLONG)0 - Total)
                return FALSE;
            Total += Kb;
        }

        if (Type == SMBIOS_TYPE_END_OF_TABLE)
            break;

        /* The formatted area is followed by a string set that ends with two NUL bytes */
        Next = Offset + HeaderLength;
        while (Next + 1 < Length && (Table[Next] != 0 || Table[Next + 1] != 0))
            Next++;
        if (Next + 1 >= Length)
            return FALSE;
        Offset = Next + 2;
    }

    *TotalKb = Total;
    return TRUE;
}

/*
 * @implemented
 *
 * Returns the physically installed RAM in kilobytes, taken from the SMBIOS
 * Memory Device structures, as documented:
 * https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getphysicallyinstalledsystemmemory
 * A NULL pointer fails with ERROR_INVALID_PARAMETER. SMBIOS data that does not
 * parse, or whose total is less than the memory the system reports in
 * GlobalMemoryStatusEx, fails with ERROR_INVALID_DATA. On failure the output
 * is not written. Measured on Windows Server 2022: the result is the sum of the
 * type 17 sizes (4096 MB in one device: 4194304; 16 GB + 4 GB in two: 20971520).
 */
BOOL
WINAPI
GetPhysicallyInstalledSystemMemory(
    _Out_ PULONGLONG TotalMemoryInKilobytes)
{
    /* RawSMBIOSData as returned for the 'RSMB' provider */
    struct
    {
        UCHAR Used20CallingMethod;
        UCHAR SMBIOSMajorVersion;
        UCHAR SMBIOSMinorVersion;
        UCHAR DmiRevision;
        ULONG Length;
    } *Raw;
    MEMORYSTATUSEX MemStatus;
    ULONGLONG TotalKb = 0;
    UINT Size;
    BOOL Ok = FALSE;

    if (!TotalMemoryInKilobytes)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* No SMBIOS table at all: fail with the error of the table query
     * (measured on Windows Server 2022 without SMBIOS: ERROR_INVALID_FUNCTION for both) */
    Size = GetSystemFirmwareTable(SMBIOS_PROVIDER_RSMB, 0, NULL, 0);
    if (Size == 0)
        return FALSE;
    if (Size > sizeof(*Raw))
    {
        Raw = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
        if (!Raw)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        if (GetSystemFirmwareTable(SMBIOS_PROVIDER_RSMB, 0, Raw, Size) == Size &&
            Raw->Length <= Size - sizeof(*Raw))
        {
            Ok = BaseSumSmbiosMemoryDevices((const UCHAR *)(Raw + 1), Raw->Length, &TotalKb);
        }
        RtlFreeHeap(RtlGetProcessHeap(), 0, Raw);
    }

    MemStatus.dwLength = sizeof(MemStatus);
    if (Ok && TotalKb != 0 && GlobalMemoryStatusEx(&MemStatus) &&
        TotalKb >= MemStatus.ullTotalPhys / 1024)
    {
        *TotalMemoryInKilobytes = TotalKb;
        return TRUE;
    }

    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetSystemFileCacheSize(OUT PSIZE_T lpMinimumFileCacheSize,
                       OUT PSIZE_T lpMaximumFileCacheSize,
                       OUT PDWORD lpFlags)
{
    SYSTEM_FILECACHE_INFORMATION Info;
    NTSTATUS Status;

    /* The kernel reports the limits in pages. As on Windows, a limit that does not
     * fit in a SIZE_T in bytes fails with ERROR_ARITHMETIC_OVERFLOW. */
    Status = NtQuerySystemInformation(SystemFileCacheInformationEx,
                                      &Info,
                                      sizeof(Info),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    if ((Info.MinimumWorkingSet > (MAXULONG_PTR >> PAGE_SHIFT)) ||
        (Info.MaximumWorkingSet > (MAXULONG_PTR >> PAGE_SHIFT)))
    {
        SetLastError(ERROR_ARITHMETIC_OVERFLOW);
        return FALSE;
    }

    _SEH2_TRY
    {
        *lpMinimumFileCacheSize = Info.MinimumWorkingSet << PAGE_SHIFT;
        *lpMaximumFileCacheSize = Info.MaximumWorkingSet << PAGE_SHIFT;
        *lpFlags = Info.Flags;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastError(ERROR_NOACCESS);
        _SEH2_YIELD(return FALSE);
    }
    _SEH2_END;

    return TRUE;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
SetSystemFileCacheSize(IN SIZE_T MinimumFileCacheSize,
                       IN SIZE_T MaximumFileCacheSize,
                       IN DWORD Flags)
{
    STUB;
    return FALSE;
}

