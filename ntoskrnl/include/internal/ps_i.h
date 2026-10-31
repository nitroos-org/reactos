#if defined(_M_AMD64) && defined(BUILD_WOW64_ENABLED)
#include <reactos/wow64.h>
#endif

/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Info Classes for the Process Manager
 * COPYRIGHT:   Copyright Alex Ionescu <alex.ionescu@reactos.org>
 *              Copyright Thomas Weidenmueller <w3seek@reactos.org>
 *              Copyright 2020-2021 George Bișoc <george.bisoc@reactos.org>
 */

#include "icif.h"

//
// Process Information Classes
//
static const INFORMATION_CLASS_INFO PsProcessInfoClass[] =
{
    /* ProcessBasicInformation */
    IQS_SAME
    (
        PROCESS_BASIC_INFORMATION,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessQuotaLimits */
    IQS_SAME
    (
        QUOTA_LIMITS,
        ULONG,

        /* NOTE: ICIF_SIZE_VARIABLE is for QUOTA_LIMITS_EX support */
        ICIF_QUERY | ICIF_SET | ICIF_SIZE_VARIABLE
    ),

    /* ProcessIoCounters */
    IQS_SAME
    (
        IO_COUNTERS,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessVmCounters */
    IQS_SAME
    (
        VM_COUNTERS,
        ULONG,
        ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE
    ),

    /* ProcessTimes */
    IQS_SAME
    (
        KERNEL_USER_TIMES,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessBasePriority */
    IQS_SAME
    (
        KPRIORITY,
        ULONG,
        ICIF_SET
    ),

    /* ProcessRaisePriority */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_SET
    ),

    /* ProcessDebugPort */
    IQS_SAME
    (
        HANDLE,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessExceptionPort */
    IQS_SAME
    (
        HANDLE,
        HANDLE,
        ICIF_SET
    ),

    /* ProcessAccessToken */
    IQS_SAME
    (
        PROCESS_ACCESS_TOKEN,
        ULONG,
        ICIF_SET
    ),

    /* ProcessLdtInformation */
    IQS_SAME
    (
        PROCESS_LDT_INFORMATION,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessLdtSize */
    IQS_SAME
    (
        PROCESS_LDT_SIZE,
        ULONG,
        ICIF_SET
    ),

    /* ProcessDefaultHardErrorMode */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessIoPortHandlers */
    IQS_SAME
    (
        UCHAR,
        ULONG,
        ICIF_SET
    ),

    /* ProcessPooledUsageAndLimits */
    IQS_SAME
    (
        POOLED_USAGE_AND_LIMITS,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessWorkingSetWatch */
    IQS_SAME
    (
        PROCESS_WS_WATCH_INFORMATION,
        ULONG,
        ICIF_QUERY | ICIF_SET | ICIF_SET_SIZE_VARIABLE
    ),

    /* ProcessUserModeIOPL is only implemented in x86 */
#if defined (_X86_)
    IQS_NO_TYPE_LENGTH
    (
        ULONG,
        ICIF_SET
    ),
#else
    IQS_NONE,
#endif

    /* ProcessEnableAlignmentFaultFixup */
    IQS
    (
        BOOLEAN,
        ULONG,
        BOOLEAN,
        CHAR,
        ICIF_SET
    ),

    /* ProcessPriorityClass */
    IQS
    (
        PROCESS_PRIORITY_CLASS,
        ULONG,
        PROCESS_PRIORITY_CLASS,
        CHAR,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessWx86Information */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessHandleCount */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessAffinityMask */
    IQS_SAME
    (
        KAFFINITY,
        KAFFINITY,
        ICIF_SET
    ),

    /* ProcessPriorityBoost */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessDeviceMap */
    IQS
    (
        RTL_FIELD_TYPE(PROCESS_DEVICEMAP_INFORMATION, Query),
        ULONG,
        RTL_FIELD_TYPE(PROCESS_DEVICEMAP_INFORMATION, Set),
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessSessionInformation */
    IQS_SAME
    (
        PROCESS_SESSION_INFORMATION,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessForegroundInformation */
    IQS
    (
        CHAR,
        ULONG,
        BOOLEAN,
        CHAR,
        ICIF_SET
    ),

    /* ProcessWow64Information */
    IQS_SAME
    (
        ULONG_PTR,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessImageFileName */
    IQS_SAME
    (
        UNICODE_STRING,
        ULONG,
        ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE
    ),

    /* ProcessLUIDDeviceMapsEnabled */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessBreakOnTermination */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessDebugObjectHandle */
    IQS_SAME
    (
        HANDLE,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessDebugFlags */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessHandleTracing */
    IQS
    (
        PROCESS_HANDLE_TRACING_QUERY,
        ULONG,
        ULONG,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessIoPriority */
    IQS_NONE,

    /* ProcessExecuteFlags */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ProcessTlsInformation
     * Query is known to the table from Vista on so that buffer probing
     * behaves as on NT6+; NtQueryInformationProcess rejects it with
     * STATUS_INVALID_INFO_CLASS below that (runtime NT version gate) and has
     * no data to return for it (VERBUMP). */
    IQS_SAME
    (
        PROCESS_TLS_INFORMATION,
        ULONG,
        ICIF_QUERY | ICIF_SET | ICIF_SET_SIZE_VARIABLE
    ),

    /* ProcessCookie */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessImageInformation */
    IQS_SAME
    (
        SECTION_IMAGE_INFORMATION,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessCycleTime */
    IQS_SAME
    (
        PROCESS_CYCLE_TIME_INFORMATION,
        ULONG,
        ICIF_QUERY
    ),

    /* ProcessPagePriority */
    IQS_NONE,

    /* ProcessInstrumentationCallback */
    IQS_NONE,

    /* ProcessThreadStackAllocation */
    IQS_NONE,

    /* ProcessWorkingSetWatchEx */
    IQS_NONE,

    /* ProcessImageFileNameWin32 */
    IQS_SAME
    (
        UNICODE_STRING,
        ULONG_PTR,
        ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE
    ),

    /* ProcessImageFileMapping */
    IQS_NONE,

    /* ProcessAffinityUpdateMode */
    IQS_NONE,

    /* ProcessMemoryAllocationMode */
    IQS_NONE,

    /* 47..57: defined on NT6+ Windows but not implemented here; present only so
     * the info-class table spans the range up to ProcessHandleTable (58). */
    IQS_NONE, /* ProcessGroupInformation (47) */
    IQS_NONE, /* ProcessTokenVirtualizationEnabled (48) */
    IQS_NONE, /* ProcessConsoleHostProcess (49) */
    IQS_NONE, /* ProcessWindowInformation (50) */
    IQS_NONE, /* ProcessHandleInformation (51) */
    IQS_NONE, /* ProcessMitigationPolicy (52) */
    IQS_NONE, /* ProcessDynamicFunctionTableInformation (53) */
    IQS_NONE, /* ProcessHandleCheckingMode (54) */
    IQS_NONE, /* ProcessKeepAliveCount (55) */
    IQS_NONE, /* ProcessRevokeFileHandles (56) */
    IQS_NONE, /* ProcessWorkingSetControl (57) */

    /* ProcessHandleTable (58): queried as a ULONG[] of open handle values (Win8.1+) */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),

    /* ProcessCheckStackExtentsMode (59): not implemented */
    IQS_NONE,

    /* ProcessCommandLineInformation (60, Win8.1+): a UNICODE_STRING followed by
     * the target's PEB command line; the length is variable and the alignment
     * that of a ULONG, as measured on Windows 10 x64 */
    IQS_SAME
    (
        UNICODE_STRING,
        ULONG,
        ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE
    ),
};

//
// Thread Information Classes
//
static const INFORMATION_CLASS_INFO PsThreadInfoClass[] =
{
    /* ThreadBasicInformation */
    IQS_SAME
    (
        THREAD_BASIC_INFORMATION,
        ULONG,
        ICIF_QUERY
    ),

    /* ThreadTimes */
    IQS_SAME
    (
        KERNEL_USER_TIMES,
        ULONG,
        ICIF_QUERY
    ),

    /* ThreadPriority */
    IQS_SAME
    (
        KPRIORITY,
        ULONG,
        ICIF_SET
    ),

    /* ThreadBasePriority */
    IQS_SAME
    (
        LONG,
        ULONG,
        ICIF_SET
    ),

    /* ThreadAffinityMask */
    IQS_SAME
    (
        KAFFINITY,
        ULONG,
        ICIF_SET
    ),

    /* ThreadImpersonationToken */
    IQS_SAME
    (
        HANDLE,
        ULONG,
        ICIF_SET
    ),

    /* ThreadDescriptorTableEntry is only implemented in x86 as well as the descriptor entry */
#if defined(_X86_)
    IQS_SAME
    (
        DESCRIPTOR_TABLE_ENTRY,
        ULONG,
        ICIF_QUERY
    ),
#else
    IQS_NONE,
#endif

    /* ThreadEnableAlignmentFaultFixup */
    IQS
    (
        CHAR,
        CHAR,
        BOOLEAN,
        UCHAR,
        ICIF_SET
    ),

    /* ThreadEventPair_Reusable */
    IQS_NONE,

    /* ThreadQuerySetWin32StartAddress */
    IQS
    (
        PVOID,
        ULONG,
        ULONG_PTR,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ThreadZeroTlsCell */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_SET
    ),

    /* ThreadPerformanceCount */
    IQS_SAME
    (
        LARGE_INTEGER,
        ULONG,
        ICIF_QUERY
    ),

    /* ThreadAmILastThread */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY
    ),

    /* ThreadIdealProcessor */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_SET
    ),

    /* ThreadPriorityBoost */
    IQS
    (
        ULONG,
        ULONG,
        ULONG_PTR,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ThreadSetTlsArrayAddress */
    IQS_SAME
    (
        PVOID,
        ULONG,
        ICIF_SET | ICIF_SIZE_VARIABLE
    ),

    /* ThreadIsIoPending */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY
    ),

    /* ThreadHideFromDebugger
     * Query support exists on Vista and above only: NtQueryInformationThread
     * returns STATUS_INVALID_INFO_CLASS below that (runtime NT version gate,
     * see PspIsThreadInfoClassAvailable()). */
    {
        sizeof(BOOLEAN),
        sizeof(UCHAR),
        0, /* No size for Set */
        sizeof(ULONG),
        ICIF_QUERY | ICIF_SET
    },

    /* ThreadBreakOnTermination */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ThreadSwitchLegacyState */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_SET
    ),

    /* ThreadIsTerminated */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY
    ),

    /* ThreadLastSystemCall */
    IQS_NONE,

    /* ThreadIoPriority (Vista+) */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ThreadCycleTime */
    IQS_SAME
    (
        THREAD_CYCLE_TIME_INFORMATION,
        ULONG,
        ICIF_QUERY
    ),

    /* ThreadPagePriority (Vista+) */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY | ICIF_SET
    ),

    /* ThreadActualBasePriority (Win7+) */
    IQS_SAME
    (
        ULONG,
        ULONG,
        ICIF_QUERY
    ),

    /* ThreadTebInformation */
    IQS_NONE,

    /* ThreadCSwitchMon */
    IQS_NONE,

// TODO: Specify the probing info when implementing these classes (see commit 60aad33ed0 PR #8487)
// and adjust rostests/apitests/ntdll/probelib.c!QuerySetThreadValidator() as necessary.
#if 1
    // Windows 7
    /* ThreadCSwitchPmu: set-probe only, no query (class is Win7-only) */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
    /* ThreadWow64Context */
#if defined(_M_AMD64) && defined(BUILD_WOW64_ENABLED)
    IQS_SAME(WOW64_CONTEXT, ULONG, ICIF_QUERY | ICIF_SET),
#else
    /* Not implemented here; known to the table so that Set probing works */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
#endif
    /* ThreadGroupInformation */
    IQS_SAME(GROUP_AFFINITY, ULONG_PTR, ICIF_QUERY | ICIF_SET),
    /* ThreadUmsInformation */
    IQS_SAME(ULONG_PTR, ULONG_PTR, ICIF_SET),
    /* ThreadCounterProfiling */
    IQS_SAME(ULONG_PTR, ULONG_PTR, ICIF_SET),
    /* ThreadIdealProcessorEx */
    IQS_SAME(PROCESSOR_NUMBER, USHORT, ICIF_QUERY | ICIF_SET),

    // Windows 8
    /* ThreadCpuAccountingInformation */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_SET),

    // Windows 8.1
    /* ThreadSuspendCount */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_SET),

    // Windows 10
    /* ThreadHeterogeneousCpuPolicy */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_SET),
    /* ThreadContainerId */
    IQS_SAME(GUID, ULONG, ICIF_QUERY | ICIF_SET),

    /* ThreadNameInformation */
    IQS_SAME
    (
        UNICODE_STRING,
        ULONG_PTR,
        ICIF_QUERY | ICIF_SET | ICIF_SIZE_VARIABLE
    ),

    /* ThreadSelectedCpuSets */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_SET | ICIF_QUERY_SIZE_VARIABLE | ICIF_SET_SIZE_VARIABLE),
    /* ThreadSystemThreadInformation */
    IQS_SAME(SYSTEM_THREAD_INFORMATION, ULONG_PTR, ICIF_QUERY | ICIF_SET),
    /* ThreadActualGroupAffinity */
    IQS_SAME(GROUP_AFFINITY, ULONG_PTR, ICIF_QUERY | ICIF_SET),

    /* ThreadDynamicCodePolicyInfo */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_SET),
    /* ThreadExplicitCaseSensitivity */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_SET),
    /* ThreadWorkOnBehalfTicket */
    IQS_SAME(GUID, ULONG_PTR, ICIF_SET),
    /* ThreadSubsystemInformation */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_SET),
    /* ThreadDbgkWerReportActive */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
    /* ThreadAttachContainer */
    IQS_SAME(HANDLE, ULONG_PTR, ICIF_SET),
    /* ThreadManageWritesToExecutableMemory */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
    /* ThreadPowerThrottlingState */
    IQS_SAME(ULONG[3], ULONG, ICIF_SET),
    /* ThreadWorkloadClass */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
    /* ThreadCreateStateChange */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
    /* ThreadApplyStateChange */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
    /* ThreadStrongerBadHandleChecks */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
    /* ThreadEffectiveIoPriority */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
    /* ThreadEffectivePagePriority */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
#endif
};
