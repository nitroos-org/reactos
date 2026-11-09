/*
 * PROJECT:         ReactOS API tests
 * LICENSE:         LGPLv2.1+ - See COPYING.LIB in the top level directory
 * PURPOSE:         Tests for the NtQueryInformationProcess API
 * PROGRAMMER:      Thomas Faber <thomas.faber@reactos.org>
 *                  George Bișoc <george.bisoc@reactos.org>
 */

#include "precomp.h"
#include <internal/ps_i.h>
#include <tlhelp32.h>

static LARGE_INTEGER TestStartTime;

static
void
Test_ProcessTimes(void)
{
#define SPIN_TIME 1000000
    NTSTATUS Status;
    KERNEL_USER_TIMES Times1;
    KERNEL_USER_TIMES Times2;
    ULONG Length;
    LARGE_INTEGER Time1, Time2, Counter;

    /* Everything is NULL */
    Status = NtQueryInformationProcess(NULL,
                                       ProcessTimes,
                                       NULL,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Right size, invalid process */
    Status = NtQueryInformationProcess(NULL,
                                       ProcessTimes,
                                       NULL,
                                       sizeof(KERNEL_USER_TIMES),
                                       NULL);
    ok_hex(Status, STATUS_INVALID_HANDLE);

    /* Valid process, no buffer */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessTimes,
                                       NULL,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Unaligned buffer, wrong size */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessTimes,
                                       (PVOID)2,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Unaligned buffer, correct size */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessTimes,
                                       (PVOID)2,
                                       sizeof(KERNEL_USER_TIMES),
                                       NULL);
    ok_hex(Status, STATUS_DATATYPE_MISALIGNMENT);

    /* Buffer too small */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessTimes,
                                       NULL,
                                       sizeof(KERNEL_USER_TIMES) - 1,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Right buffer size but NULL pointer */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessTimes,
                                       NULL,
                                       sizeof(KERNEL_USER_TIMES),
                                       NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    /* Buffer too large */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessTimes,
                                       NULL,
                                       sizeof(KERNEL_USER_TIMES) + 1,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Buffer too small, ask for length */
    Length = 0x55555555;
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessTimes,
                                       NULL,
                                       sizeof(KERNEL_USER_TIMES) - 1,
                                       &Length);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_dec(Length, 0x55555555);

    Status = NtQuerySystemTime(&Time1);
    ok_hex(Status, STATUS_SUCCESS);

    /* Do some busy waiting to increase UserTime */
    do
    {
        /* A system call per round: reading the system time does not enter the kernel (the time is in the
           shared user data), and the kernel time that the checks below expect is charged at clock ticks
           that find the thread in the kernel */
        NtQueryPerformanceCounter(&Counter, NULL);
        Status = NtQuerySystemTime(&Time2);
        if (!NT_SUCCESS(Status))
        {
            ok(0, "NtQuerySystemTime failed with %lx\n", Status);
            break;
        }
    } while (Time2.QuadPart - Time1.QuadPart < SPIN_TIME);

    /* Valid parameters, no return length */
    Status = NtQuerySystemTime(&Time1);
    ok_hex(Status, STATUS_SUCCESS);

    RtlFillMemory(&Times1, sizeof(Times1), 0x55);
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessTimes,
                                       &Times1,
                                       sizeof(KERNEL_USER_TIMES),
                                       NULL);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Times1.CreateTime.QuadPart < TestStartTime.QuadPart,
       "CreateTime is %I64u, expected < %I64u\n", Times1.CreateTime.QuadPart, TestStartTime.QuadPart);
    ok(Times1.CreateTime.QuadPart > TestStartTime.QuadPart - 100000000LL,
       "CreateTime is %I64u, expected > %I64u\n", Times1.CreateTime.QuadPart, TestStartTime.QuadPart - 100000000LL);
    ok(Times1.ExitTime.QuadPart == 0,
       "ExitTime is %I64u, expected 0\n", Times1.ExitTime.QuadPart);
    ok(Times1.KernelTime.QuadPart != 0, "KernelTime is 0\n");
    ros_skip_flaky
    ok(Times1.UserTime.QuadPart != 0, "UserTime is 0\n");

    /* Do some busy waiting to increase UserTime */
    do
    {
        /* A system call per round: reading the system time does not enter the kernel (the time is in the
           shared user data), and the kernel time that the checks below expect is charged at clock ticks
           that find the thread in the kernel */
        NtQueryPerformanceCounter(&Counter, NULL);
        Status = NtQuerySystemTime(&Time2);
        if (!NT_SUCCESS(Status))
        {
            ok(0, "NtQuerySystemTime failed with %lx\n", Status);
            break;
        }
    } while (Time2.QuadPart - Time1.QuadPart < SPIN_TIME);

    /* Again, this time with a return length */
    Length = 0x55555555;
    RtlFillMemory(&Times2, sizeof(Times2), 0x55);
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessTimes,
                                       &Times2,
                                       sizeof(KERNEL_USER_TIMES),
                                       &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Length, sizeof(KERNEL_USER_TIMES));
    ok(Times1.CreateTime.QuadPart == Times2.CreateTime.QuadPart,
       "CreateTimes not equal: %I64u != %I64u\n", Times1.CreateTime.QuadPart, Times2.CreateTime.QuadPart);
    ok(Times2.ExitTime.QuadPart == 0,
       "ExitTime is %I64u, expected 0\n", Times2.ExitTime.QuadPart);
    ok(Times2.KernelTime.QuadPart != 0, "KernelTime is 0\n");
    ok(Times2.UserTime.QuadPart != 0, "UserTime is 0\n");

    /* Compare the two sets of KernelTime/UserTime values */
    Status = NtQuerySystemTime(&Time2);
    ok_hex(Status, STATUS_SUCCESS);
    /* Time values must have increased */
    ok(Times2.KernelTime.QuadPart > Times1.KernelTime.QuadPart,
       "KernelTime values inconsistent. Expected %I64u > %I64u\n", Times2.KernelTime.QuadPart, Times1.KernelTime.QuadPart);
    ros_skip_flaky
    ok(Times2.UserTime.QuadPart > Times1.UserTime.QuadPart,
       "UserTime values inconsistent. Expected %I64u > %I64u\n", Times2.UserTime.QuadPart, Times1.UserTime.QuadPart);
    /* They can't have increased by more than wall clock time difference (we only have one thread) */
    ros_skip_flaky
    ok(Times2.KernelTime.QuadPart - Times1.KernelTime.QuadPart < Time2.QuadPart - Time1.QuadPart,
       "KernelTime values inconsistent. Expected %I64u - %I64u < %I64u\n",
       Times2.KernelTime.QuadPart, Times1.KernelTime.QuadPart, Time2.QuadPart - Time1.QuadPart);
    ok(Times2.UserTime.QuadPart - Times1.UserTime.QuadPart < Time2.QuadPart - Time1.QuadPart,
       "UserTime values inconsistent. Expected %I64u - %I64u < %I64u\n",
       Times2.UserTime.QuadPart, Times1.UserTime.QuadPart, Time2.QuadPart - Time1.QuadPart);

    trace("KernelTime1 = %I64u\n", Times1.KernelTime.QuadPart);
    trace("KernelTime2 = %I64u\n", Times2.KernelTime.QuadPart);
    trace("UserTime1 = %I64u\n", Times1.UserTime.QuadPart);
    trace("UserTime2 = %I64u\n", Times2.UserTime.QuadPart);

    /* TODO: Test ExitTime on a terminated process */
#undef SPIN_TIME
}

static
void
Test_ProcessBasicInformation(void)
{
    NTSTATUS Status;
    ULONG Length;
    PROCESS_BASIC_INFORMATION BasicInfo;

    /* Everything is NULL */
    Status = NtQueryInformationProcess(NULL,
                                       ProcessBasicInformation,
                                       NULL,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Right size, invalid process handle */
    Status = NtQueryInformationProcess(NULL,
                                       ProcessBasicInformation,
                                       NULL,
                                       sizeof(BasicInfo),
                                       NULL);
    ok_hex(Status, STATUS_INVALID_HANDLE);

    /* Valid process handle, no buffer */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessBasicInformation,
                                       NULL,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Unaligned buffer, wrong size */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessBasicInformation,
                                       (PVOID)2,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Unaligned buffer, correct size */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessBasicInformation,
                                       (PVOID)2,
                                       sizeof(BasicInfo),
                                       NULL);
    ok_hex(Status, STATUS_DATATYPE_MISALIGNMENT);

    /* Buffer too small */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessBasicInformation,
                                       NULL,
                                       sizeof(BasicInfo) - 1,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Right buffer size but NULL pointer */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessBasicInformation,
                                       NULL,
                                       sizeof(BasicInfo),
                                       NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    /* Buffer too large */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessBasicInformation,
                                       NULL,
                                       sizeof(BasicInfo) + 1,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Buffer too small, ask for length */
    Length = 0x55555555;
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessBasicInformation,
                                       NULL,
                                       sizeof(BasicInfo) - 1,
                                       &Length);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_dec(Length, 0x55555555);

    /* Valid parameters, no return length */
    RtlFillMemory(&BasicInfo, sizeof(BasicInfo), 0x55);
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessBasicInformation,
                                       &BasicInfo,
                                       sizeof(BasicInfo),
                                       NULL);
    ok_hex(Status, STATUS_SUCCESS);

    /* Trace the returned data (1) */
    trace("[1] BasicInfo.ExitStatus = %lx\n", BasicInfo.ExitStatus);
    trace("[1] BasicInfo.PebBaseAddress = %p\n", BasicInfo.PebBaseAddress);
    trace("[1] BasicInfo.AffinityMask = %Ix\n", BasicInfo.AffinityMask);
    trace("[1] BasicInfo.BasePriority = %ld\n", BasicInfo.BasePriority);
    trace("[1] BasicInfo.UniqueProcessId = %Iu\n", BasicInfo.UniqueProcessId);
    trace("[1] BasicInfo.InheritedFromUniqueProcessId = %Iu\n", BasicInfo.InheritedFromUniqueProcessId);

    /* Again, this time with a return length */
    Length = 0x55555555;
    RtlFillMemory(&BasicInfo, sizeof(BasicInfo), 0x55);
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessBasicInformation,
                                       &BasicInfo,
                                       sizeof(BasicInfo),
                                       &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Length, sizeof(BasicInfo));

    /* Trace the returned data (2) */
    trace("[2] BasicInfo.ExitStatus = %lx\n", BasicInfo.ExitStatus);
    trace("[2] BasicInfo.PebBaseAddress = %p\n", BasicInfo.PebBaseAddress);
    trace("[2] BasicInfo.AffinityMask = %Ix\n", BasicInfo.AffinityMask);
    trace("[2] BasicInfo.BasePriority = %ld\n", BasicInfo.BasePriority);
    trace("[2] BasicInfo.UniqueProcessId = %Iu\n", BasicInfo.UniqueProcessId);
    trace("[2] BasicInfo.InheritedFromUniqueProcessId = %Iu\n", BasicInfo.InheritedFromUniqueProcessId);
}

static
void
Test_ProcessQuotaLimits(void)
{
    NTSTATUS Status;
    ULONG Length;
    QUOTA_LIMITS QuotaLimits;

    /* Everything is NULL */
    Status = NtQueryInformationProcess(NULL,
                                       ProcessQuotaLimits,
                                       NULL,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Right size, invalid process handle */
    Status = NtQueryInformationProcess(NULL,
                                       ProcessQuotaLimits,
                                       NULL,
                                       sizeof(QuotaLimits),
                                       NULL);
    ok_hex(Status, STATUS_INVALID_HANDLE);

    /* Valid process handle, no buffer */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       NULL,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Unaligned buffer, wrong size */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       (PVOID)2,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Unaligned buffer, correct size */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       (PVOID)2,
                                       sizeof(QuotaLimits),
                                       NULL);
    ok_hex(Status, STATUS_DATATYPE_MISALIGNMENT);

    /* Buffer too small */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       NULL,
                                       sizeof(QuotaLimits) - 1,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Right buffer size but NULL pointer */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       NULL,
                                       sizeof(QuotaLimits),
                                       NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    /* Buffer too large */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       NULL,
                                       sizeof(QuotaLimits) + 1,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Buffer too small, ask for length */
    Length = 0x55555555;
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       NULL,
                                       sizeof(QuotaLimits) - 1,
                                       &Length);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_dec(Length, 0x55555555);

    /* Valid parameters, no return length */
    RtlFillMemory(&QuotaLimits, sizeof(QuotaLimits), 0x55);
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       &QuotaLimits,
                                       sizeof(QuotaLimits),
                                       NULL);
    ok_hex(Status, STATUS_SUCCESS);

    /* Trace the returned data (1) */
    trace("[1] QuotaLimits.PagedPoolLimit = %Iu\n", QuotaLimits.PagedPoolLimit);
    trace("[1] QuotaLimits.NonPagedPoolLimit = %Iu\n", QuotaLimits.NonPagedPoolLimit);
    trace("[1] QuotaLimits.MinimumWorkingSetSize = %Iu\n", QuotaLimits.MinimumWorkingSetSize);
    trace("[1] QuotaLimits.MaximumWorkingSetSize = %Iu\n", QuotaLimits.MaximumWorkingSetSize);
    trace("[1] QuotaLimits.PagefileLimit = %Iu\n", QuotaLimits.PagefileLimit);
    trace("[1] QuotaLimits.TimeLimit = %I64d\n", QuotaLimits.TimeLimit.QuadPart);

    /* Again, this time with a return length */
    Length = 0x55555555;
    RtlFillMemory(&QuotaLimits, sizeof(QuotaLimits), 0x55);
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       &QuotaLimits,
                                       sizeof(QuotaLimits),
                                       &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Length, sizeof(QuotaLimits));

    /* Trace the returned data (2) */
    trace("[2] QuotaLimits.PagedPoolLimit = %Iu\n", QuotaLimits.PagedPoolLimit);
    trace("[2] QuotaLimits.NonPagedPoolLimit = %Iu\n", QuotaLimits.NonPagedPoolLimit);
    trace("[2] QuotaLimits.MinimumWorkingSetSize = %Iu\n", QuotaLimits.MinimumWorkingSetSize);
    trace("[2] QuotaLimits.MaximumWorkingSetSize = %Iu\n", QuotaLimits.MaximumWorkingSetSize);
    trace("[2] QuotaLimits.PagefileLimit = %Iu\n", QuotaLimits.PagefileLimit);
    trace("[2] QuotaLimits.TimeLimit = %I64d\n", QuotaLimits.TimeLimit.QuadPart);
}

static
void
Test_ProcessQuotaLimitsEx(void)
{
    NTSTATUS Status;
    ULONG Length;
    QUOTA_LIMITS_EX QuotaLimitsEx;

    /* Right size, invalid process handle */
    Status = NtQueryInformationProcess(NULL,
                                       ProcessQuotaLimits,
                                       NULL,
                                       sizeof(QuotaLimitsEx),
                                       NULL);
    ok_hex(Status, STATUS_INVALID_HANDLE);

    /* Unaligned buffer, correct size */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       (PVOID)2,
                                       sizeof(QuotaLimitsEx),
                                       NULL);
    ok_hex(Status, STATUS_DATATYPE_MISALIGNMENT);

    /* Buffer too small */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       NULL,
                                       sizeof(QuotaLimitsEx) - 1,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Right buffer size but NULL pointer */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       NULL,
                                       sizeof(QuotaLimitsEx),
                                       NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    /* Buffer too large */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       NULL,
                                       sizeof(QuotaLimitsEx) + 1,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Buffer too small, ask for length */
    Length = 0x55555555;
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       NULL,
                                       sizeof(QuotaLimitsEx) - 1,
                                       &Length);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_dec(Length, 0x55555555);

    /* Valid parameters, no return length */
    RtlFillMemory(&QuotaLimitsEx, sizeof(QuotaLimitsEx), 0x55);
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       &QuotaLimitsEx,
                                       sizeof(QuotaLimitsEx),
                                       NULL);
    ok_hex(Status, STATUS_SUCCESS);

    /* Trace the returned data (1) */
    trace("[1] QuotaLimitsEx.PagedPoolLimit = %Iu\n", QuotaLimitsEx.PagedPoolLimit);
    trace("[1] QuotaLimitsEx.NonPagedPoolLimit = %Iu\n", QuotaLimitsEx.NonPagedPoolLimit);
    trace("[1] QuotaLimitsEx.MinimumWorkingSetSize = %Iu\n", QuotaLimitsEx.MinimumWorkingSetSize);
    trace("[1] QuotaLimitsEx.MaximumWorkingSetSize = %Iu\n", QuotaLimitsEx.MaximumWorkingSetSize);
    trace("[1] QuotaLimitsEx.PagefileLimit = %Iu\n", QuotaLimitsEx.PagefileLimit);
    trace("[1] QuotaLimitsEx.TimeLimit = %I64d\n", QuotaLimitsEx.TimeLimit.QuadPart);
    //trace("[1] QuotaLimitsEx.WorkingSetLimit = %Iu\n", QuotaLimitsEx.WorkingSetLimit); // Not used on Win2k3
    trace("[1] QuotaLimitsEx.Flags = %lx\n", QuotaLimitsEx.Flags);
    trace("[1] QuotaLimitsEx.CpuRateLimit.RateData = %lx\n", QuotaLimitsEx.CpuRateLimit.RateData);

    /* Again, this time with a return length */
    Length = 0x55555555;
    RtlFillMemory(&QuotaLimitsEx, sizeof(QuotaLimitsEx), 0x55);
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessQuotaLimits,
                                       &QuotaLimitsEx,
                                       sizeof(QuotaLimitsEx),
                                       &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Length, sizeof(QuotaLimitsEx));

    /* Trace the returned data (2) */
    trace("[2] QuotaLimitsEx.PagedPoolLimit = %Iu\n", QuotaLimitsEx.PagedPoolLimit);
    trace("[2] QuotaLimitsEx.NonPagedPoolLimit = %Iu\n", QuotaLimitsEx.NonPagedPoolLimit);
    trace("[2] QuotaLimitsEx.MinimumWorkingSetSize = %Iu\n", QuotaLimitsEx.MinimumWorkingSetSize);
    trace("[2] QuotaLimitsEx.MaximumWorkingSetSize = %Iu\n", QuotaLimitsEx.MaximumWorkingSetSize);
    trace("[2] QuotaLimitsEx.PagefileLimit = %Iu\n", QuotaLimitsEx.PagefileLimit);
    trace("[2] QuotaLimitsEx.TimeLimit = %I64d\n", QuotaLimitsEx.TimeLimit.QuadPart);
    //trace("[2] QuotaLimitsEx.WorkingSetLimit = %Iu\n", QuotaLimitsEx.WorkingSetLimit); // Not used on Win2k3
    trace("[2] QuotaLimitsEx.Flags = %lx\n", QuotaLimitsEx.Flags);
    trace("[2] QuotaLimitsEx.CpuRateLimit.RateData = %lx\n", QuotaLimitsEx.CpuRateLimit.RateData);
}

static
void
Test_ProcessPriorityClassAlignment(void)
{
    NTSTATUS Status;
    PPROCESS_PRIORITY_CLASS ProcPriority;

    /* Allocate some memory for the priority class structure */
    ProcPriority = malloc(sizeof(PROCESS_PRIORITY_CLASS));
    if (ProcPriority == NULL)
    {
        skip("Failed to allocate memory for PROCESS_PRIORITY_CLASS!\n");
        return;
    }

    /*
     * Initialize the PriorityClass member to ensure the test won't randomly succeed (if such data is uninitialized).
     * Filling 85 to the data member makes sure that if the test fails continously then NtQueryInformationProcess()
     * didn't initialize the structure with data.
     */
    RtlFillMemory(&ProcPriority->PriorityClass, sizeof(ProcPriority->PriorityClass), 0x55);

    /* Unaligned buffer -- wrong size */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessPriorityClass,
                                       (PVOID)1,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Unaligned buffer -- correct size */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessPriorityClass,
                                       (PVOID)1,
                                       sizeof(PROCESS_PRIORITY_CLASS),
                                       NULL);
    ok_hex(Status, STATUS_DATATYPE_MISALIGNMENT);

    /* Unaligned buffer -- wrong size (but this time do with an alignment of 2) */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessPriorityClass,
                                       (PVOID)2,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Unaligned buffer -- correct size (but this time do with an alignment of 2) */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessPriorityClass,
                                       (PVOID)2,
                                       sizeof(PROCESS_PRIORITY_CLASS),
                                       NULL);
    ok_hex(Status, STATUS_DATATYPE_MISALIGNMENT);

    /* Do not care for the length but expect to return the priority class */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessPriorityClass,
                                       ProcPriority,
                                       sizeof(PROCESS_PRIORITY_CLASS),
                                       NULL);
    ok_hex(Status, STATUS_SUCCESS);

    /* Make sure the returned priority class is a valid number (non negative) but also it should be within the PROCESS_PRIORITY_CLASS range */
    ok(ProcPriority->PriorityClass > PROCESS_PRIORITY_CLASS_INVALID && ProcPriority->PriorityClass <= PROCESS_PRIORITY_CLASS_ABOVE_NORMAL,
       "Expected a valid number from priority class range but got %d\n", ProcPriority->PriorityClass);
    free(ProcPriority);
}

static
void
Test_ProcessWx86Information(void)
{
    NTSTATUS Status;
    ULONG VdmPower = 1, ReturnLength;

    /* Everything is NULL */
    Status = NtQueryInformationProcess(NULL,
                                       ProcessWx86Information,
                                       NULL,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* Given an invalid process handle */
    Status = NtQueryInformationProcess(NULL,
                                       ProcessWx86Information,
                                       &VdmPower,
                                       sizeof(VdmPower),
                                       NULL);
    ok_hex(Status, STATUS_INVALID_HANDLE);

    /* Don't query anything */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessWx86Information,
                                       NULL,
                                       sizeof(VdmPower),
                                       NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    /* The buffer is misaligned and information length is wrong */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessWx86Information,
                                       (PVOID)1,
                                       0,
                                       NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* The buffer is misaligned */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessWx86Information,
                                       (PVOID)1,
                                       sizeof(VdmPower),
                                       NULL);
    ok_hex(Status, STATUS_DATATYPE_MISALIGNMENT);

    /* The buffer is misaligned -- try with an alignment size of 2 */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessWx86Information,
                                       (PVOID)2,
                                       sizeof(VdmPower),
                                       NULL);
    ok_hex(Status, STATUS_DATATYPE_MISALIGNMENT);

    /* Query the VDM power */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessWx86Information,
                                       &VdmPower,
                                       sizeof(VdmPower),
                                       NULL);
    ok_hex(Status, STATUS_SUCCESS);
    ok(VdmPower == 0 || VdmPower == 1, "The VDM power value must be within the boundary between 0 and 1, not anything else! Got %lu\n", VdmPower);

    /* Same but with ReturnLength */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessWx86Information,
                                       &VdmPower,
                                       sizeof(VdmPower),
                                       &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    ok(ReturnLength != 0, "ReturnLength shouldn't be 0!\n");
    ok(VdmPower == 0 || VdmPower == 1, "The VDM power value must be within the boundary between 0 and 1, not anything else! Got %lu\n", VdmPower);

    /* Trace the VDM power value and returned length */
    trace("ReturnLength = %lu\n", ReturnLength);
    trace("VdmPower = %lu\n", VdmPower);
}

static
void
Test_ProcQueryAlignmentProbe(void)
{
    ULONG InfoClass;

    /* Iterate over the process info classes and begin the tests */
    for (InfoClass = 0; InfoClass < _countof(PsProcessInfoClass); InfoClass++)
    {
        /* The buffer is misaligned */
        QuerySetProcessValidator(QUERY,
                                 InfoClass,
                                 (PVOID)(ULONG_PTR)1,
                                 PsProcessInfoClass[InfoClass].RequiredSizeQUERY,
                                 STATUS_DATATYPE_MISALIGNMENT);

        /* We query an invalid buffer address */
        QuerySetProcessValidator(QUERY,
                                 InfoClass,
                                 (PVOID)(ULONG_PTR)PsProcessInfoClass[InfoClass].AlignmentQUERY,
                                 PsProcessInfoClass[InfoClass].RequiredSizeQUERY,
                                 STATUS_ACCESS_VIOLATION);

        /* The information length is wrong */
        QuerySetProcessValidator(QUERY,
                                 InfoClass,
                                 (PVOID)(ULONG_PTR)PsProcessInfoClass[InfoClass].AlignmentQUERY,
                                 PsProcessInfoClass[InfoClass].RequiredSizeQUERY - 1,
                                 STATUS_INFO_LENGTH_MISMATCH);
    }
}

/* The process list, in a heap buffer that grows as needed */
static
PSYSTEM_PROCESS_INFORMATION
QueryProcessList(VOID)
{
    PVOID Buffer;
    ULONG Size = 0x40000, Length, Try;
    NTSTATUS Status;

    for (Try = 0; Try < 8; Try++)
    {
        Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Buffer)
            break;
        Length = 0;
        Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Size, &Length);
        if (NT_SUCCESS(Status))
            return Buffer;
        HeapFree(GetProcessHeap(), 0, Buffer);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
        {
            ok_hex(Status, STATUS_SUCCESS);
            return NULL;
        }
        Size = max(Size * 2, Length + 0x10000);
    }
    ok(FALSE, "Cannot query the process list\n");
    return NULL;
}

typedef struct _PRIVATE_COMMIT
{
    /* ProcessVmCounters with a VM_COUNTERS_EX */
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivateUsage;
    /* The entry of the current process in SystemProcessInformation */
    SIZE_T SpiPagefileUsage;
    SIZE_T SpiPeakPagefileUsage;
    SIZE_T SpiPrivatePageCount;
} PRIVATE_COMMIT, *PPRIVATE_COMMIT;

static BOOL IsWow64;

/* Read the private commit charge of the current process through both queries */
static
BOOLEAN
QueryPrivateCommit(
    _Out_ PPRIVATE_COMMIT Commit,
    _In_ PCSTR What)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    VM_COUNTERS_EX Counters, ShortCounters;
    PSYSTEM_PROCESS_INFORMATION List, ProcessInfo;
    ULONG Length, Try;

    for (Try = 0; Try < 8; Try++)
    {
        /* Allocated before the counters are read, so that the buffer is in both */
        List = QueryProcessList();
        if (!List)
            return FALSE;

        RtlFillMemory(&Counters, sizeof(Counters), 0x55);
        Length = 0x55555555;
        Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessVmCounters, &Counters, sizeof(Counters), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        ok_dec(Length, sizeof(Counters));

        /* VM_COUNTERS has no PrivateUsage, and nothing is written after it */
        RtlFillMemory(&ShortCounters, sizeof(ShortCounters), 0x55);
        Length = 0x55555555;
        Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessVmCounters, &ShortCounters, sizeof(VM_COUNTERS), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        ok_dec(Length, sizeof(VM_COUNTERS));
        ok(ShortCounters.PrivateUsage == (SIZE_T)0x5555555555555555ULL, "%s: PrivateUsage written: %Iu\n",
           What, ShortCounters.PrivateUsage);
        ok(ShortCounters.PagefileUsage + 1024 * 1024 > Counters.PagefileUsage &&
           ShortCounters.PagefileUsage < Counters.PagefileUsage + 1024 * 1024,
           "%s: VM_COUNTERS PagefileUsage %Iu, VM_COUNTERS_EX %Iu\n", What, ShortCounters.PagefileUsage, Counters.PagefileUsage);

        /* A new process or thread may have grown the list meanwhile; then sample again */
        Status = NtQuerySystemInformation(SystemProcessInformation, List, (ULONG)HeapSize(GetProcessHeap(), 0, List), &Length);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;
        HeapFree(GetProcessHeap(), 0, List);
    }
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            HeapFree(GetProcessHeap(), 0, List);
        return FALSE;
    }

    for (ProcessInfo = List; ; )
    {
        if (ProcessInfo->UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess)
            break;
        if (ProcessInfo->NextEntryOffset == 0)
        {
            ok(FALSE, "%s: the current process is not in the process list\n", What);
            HeapFree(GetProcessHeap(), 0, List);
            return FALSE;
        }
        ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)ProcessInfo + ProcessInfo->NextEntryOffset);
    }
    Commit->PagefileUsage = Counters.PagefileUsage;
    Commit->PeakPagefileUsage = Counters.PeakPagefileUsage;
    Commit->PrivateUsage = Counters.PrivateUsage;
    Commit->SpiPagefileUsage = ProcessInfo->PagefileUsage;
    Commit->SpiPeakPagefileUsage = ProcessInfo->PeakPagefileUsage;
    Commit->SpiPrivatePageCount = ProcessInfo->PrivatePageCount;
    HeapFree(GetProcessHeap(), 0, List);

    /* The fields of one query are one value */
    ok(Commit->PrivateUsage == Commit->PagefileUsage, "%s: PrivateUsage %Iu, PagefileUsage %Iu\n",
       What, Commit->PrivateUsage, Commit->PagefileUsage);
    ok(Commit->PeakPagefileUsage >= Commit->PagefileUsage, "%s: PeakPagefileUsage %Iu, PagefileUsage %Iu\n",
       What, Commit->PeakPagefileUsage, Commit->PagefileUsage);
    ok(Commit->SpiPrivatePageCount == Commit->SpiPagefileUsage, "%s: SystemProcessInformation PrivatePageCount %Iu, PagefileUsage %Iu\n",
       What, Commit->SpiPrivatePageCount, Commit->SpiPagefileUsage);
    ok(Commit->SpiPeakPagefileUsage >= Commit->SpiPagefileUsage, "%s: SystemProcessInformation PeakPagefileUsage %Iu, PagefileUsage %Iu\n",
       What, Commit->SpiPeakPagefileUsage, Commit->SpiPagefileUsage);

    /* Both queries report the same charge, give or take what another thread commits meanwhile.
       Under WOW64 they differ by a constant amount. */
    if (!IsWow64)
    {
        ok(Commit->SpiPagefileUsage + 1024 * 1024 > Commit->PagefileUsage &&
           Commit->SpiPagefileUsage < Commit->PagefileUsage + 1024 * 1024,
           "%s: SystemProcessInformation PagefileUsage %Iu, ProcessVmCounters %Iu\n",
           What, Commit->SpiPagefileUsage, Commit->PagefileUsage);
    }
    return TRUE;
}

/* The charge must have changed by Size, give or take 1 MB (Windows also charges page tables,
   and other threads of the process may commit or free memory meanwhile) */
#define ok_delta(Before, After, Size, What) \
    ok((SSIZE_T)((After) - (Before)) > (SSIZE_T)(Size) - 1024 * 1024 && \
       (SSIZE_T)((After) - (Before)) < (SSIZE_T)(Size) + 1024 * 1024, \
       "%s: the charge changed by %Id bytes, expected %Id\n", What, (SSIZE_T)((After) - (Before)), (SSIZE_T)(Size))

/* Both queries must have changed by Size */
#define ok_commit_delta(Before, After, Size, What) \
    do { \
        ok_delta((Before).PrivateUsage, (After).PrivateUsage, Size, What); \
        ok_delta((Before).SpiPagefileUsage, (After).SpiPagefileUsage, Size, What " (SystemProcessInformation)"); \
    } while (0)

static
void
Test_ProcessVmCounters(void)
{
    NTSTATUS Status;
    PVOID Committed = NULL, Reserved = NULL;
    SIZE_T Size;
    PRIVATE_COMMIT Start, Previous, Commit;
    const SIZE_T Mb = 1024 * 1024;

    if (!IsWow64Process(GetCurrentProcess(), &IsWow64))
        IsWow64 = FALSE;

    /* The charge is in bytes */
    if (!QueryPrivateCommit(&Start, "start"))
        return;
    ok(Start.PrivateUsage >= 64 * 1024, "PrivateUsage %Iu is less than 64 KB\n", Start.PrivateUsage);
    ok((Start.PrivateUsage % PAGE_SIZE) == 0, "PrivateUsage %Iu is not a multiple of the page size\n", Start.PrivateUsage);
    ok((Start.SpiPagefileUsage % PAGE_SIZE) == 0, "SystemProcessInformation PagefileUsage %Iu is not a multiple of the page size\n",
       Start.SpiPagefileUsage);

    /* A committed reservation is charged in full, before it is touched */
    Size = 16 * Mb;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Committed, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status) || !QueryPrivateCommit(&Commit, "16 MB reserved and committed"))
        goto Cleanup;
    ok_commit_delta(Start, Commit, 16 * Mb, "16 MB reserved and committed");
    Previous = Commit;

    /* A reservation alone is not charged (page tables aside) */
    Size = 16 * Mb;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Reserved, 0, &Size, MEM_RESERVE, PAGE_READWRITE);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status) || !QueryPrivateCommit(&Commit, "16 MB reserved"))
        goto Cleanup;
    ok_commit_delta(Previous, Commit, 0, "16 MB reserved");
    Previous = Commit;

    /* Committing part of it charges that part */
    Size = 8 * Mb;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Reserved, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status) || !QueryPrivateCommit(&Commit, "8 MB committed"))
        goto Cleanup;
    ok_commit_delta(Previous, Commit, 8 * Mb, "8 MB committed");
    Previous = Commit;

    /* Decommitting returns the charge */
    Size = 4 * Mb;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Reserved, &Size, MEM_DECOMMIT);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status) || !QueryPrivateCommit(&Commit, "4 MB decommitted"))
        goto Cleanup;
    ok_commit_delta(Previous, Commit, -(SSIZE_T)(4 * Mb), "4 MB decommitted");

    /* Releasing both returns to the start; the peak stays */
    Size = 0;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Reserved, &Size, MEM_RELEASE);
    ok_hex(Status, STATUS_SUCCESS);
    Reserved = NULL;
    Size = 0;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Committed, &Size, MEM_RELEASE);
    ok_hex(Status, STATUS_SUCCESS);
    Committed = NULL;
    if (QueryPrivateCommit(&Commit, "both released"))
    {
        ok_commit_delta(Start, Commit, 0, "both released");
        ok(Commit.PeakPagefileUsage >= Start.PagefileUsage + 23 * Mb, "PeakPagefileUsage %Iu, expected at least %Iu\n",
           Commit.PeakPagefileUsage, Start.PagefileUsage + 23 * Mb);
        ok(Commit.SpiPeakPagefileUsage >= Start.SpiPagefileUsage + 23 * Mb,
           "SystemProcessInformation PeakPagefileUsage %Iu, expected at least %Iu\n",
           Commit.SpiPeakPagefileUsage, Start.SpiPagefileUsage + 23 * Mb);
    }

Cleanup:
    Size = 0;
    if (Reserved)
        NtFreeVirtualMemory(NtCurrentProcess(), &Reserved, &Size, MEM_RELEASE);
    Size = 0;
    if (Committed)
        NtFreeVirtualMemory(NtCurrentProcess(), &Committed, &Size, MEM_RELEASE);
}

/* BEGIN ProcessCommandLineInformation test (extracted verbatim for the Windows oracle build) */
#define PROCESS_COMMAND_LINE_CLASS  60
/* A failed query leaves the return length alone; the Windows WoW64 thunk of a 32-bit caller
 * adjusts it by the header difference whatever happens, so only native callers are held to it */
#ifdef _WIN64
#define CMDLINE_UNTOUCHED(Length)   ((Length) == 0x55555555)
#else
#define CMDLINE_UNTOUCHED(Length)   (TRUE)
#endif
#define CMDLINE_MARKER              L"marker \"quoted arg\" \x00e9 tail"

/* The size of the answer for a command line of Length bytes */
#define CMDLINE_NEEDED(Length)  (sizeof(UNICODE_STRING) + (Length) + sizeof(WCHAR))

static
void
CmdLineCheckString(
    _In_ const char *Test,
    _In_ PVOID Buffer,
    _In_ ULONG Needed,
    _In_opt_ PCWSTR Expected)
{
    PUNICODE_STRING String = Buffer;

    ok(String->Buffer == (PWSTR)(String + 1),
       "%s: Buffer is %p, expected %p\n", Test, String->Buffer, (PWSTR)(String + 1));
    ok(String->MaximumLength == String->Length + sizeof(WCHAR),
       "%s: Length %u, MaximumLength %u\n", Test, String->Length, String->MaximumLength);
    ok(Needed == CMDLINE_NEEDED(String->Length),
       "%s: needed %lu for a string of %u bytes\n", Test, Needed, String->Length);
    if (String->Buffer == (PWSTR)(String + 1) && String->MaximumLength == String->Length + sizeof(WCHAR))
    {
        ok(String->Buffer[String->Length / sizeof(WCHAR)] == UNICODE_NULL,
           "%s: the string is not terminated\n", Test);
        ok(String->Length != 0, "%s: empty command line\n", Test);
        if (Expected)
        {
            ok(String->Length == wcslen(Expected) * sizeof(WCHAR) &&
               !memcmp(String->Buffer, Expected, String->Length),
               "%s: got '%.*ls', expected '%ls'\n", Test, String->Length / (int)sizeof(WCHAR), String->Buffer, Expected);
        }
    }
}

/* Full query, then the size semantics of a short buffer, on one handle */
static
void
CmdLineQueryAll(
    _In_ const char *Test,
    _In_ HANDLE Process,
    _In_opt_ PCWSTR Expected)
{
    NTSTATUS Status;
    ULONG Length, Needed, Try;
    PVOID Buffer;
    PUCHAR Bytes;

    /* The size probe: no buffer room at all */
    Length = 0x55555555;
    Status = NtQueryInformationProcess(Process, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS, NULL, 0, &Length);
    ok(Status == STATUS_INFO_LENGTH_MISMATCH, "%s: size probe returned 0x%lx\n", Test, Status);
    if (Status != STATUS_INFO_LENGTH_MISMATCH)
        return;
    Needed = Length;
    ok(Needed > sizeof(UNICODE_STRING) + sizeof(WCHAR), "%s: needed only %lu\n", Test, Needed);
    if (Needed <= sizeof(UNICODE_STRING) + sizeof(WCHAR) || Needed > 0x20000)
        return;

    Buffer = HeapAlloc(GetProcessHeap(), 0, Needed + 16);
    if (!Buffer)
    {
        skip("%s: out of memory\n", Test);
        return;
    }
    Bytes = Buffer;

    /* Every length below the need fails, writes nothing and reports the need */
    for (Try = 0; Try < Needed; Try += (Try < sizeof(UNICODE_STRING) + 2 || Try + 8 > Needed) ? 1 : 7)
    {
        ULONG Offset;
        BOOLEAN Wrote = FALSE;

        memset(Buffer, 0xCC, Needed + 16);
        Length = 0x55555555;
        Status = NtQueryInformationProcess(Process, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS, Buffer, Try, &Length);
        ok(Status == STATUS_INFO_LENGTH_MISMATCH, "%s: length %lu returned 0x%lx\n", Test, Try, Status);
        ok(Length == Needed, "%s: length %lu reported %lu, expected %lu\n", Test, Try, Length, Needed);
        for (Offset = 0; Offset < Needed + 16; Offset++)
            Wrote |= (Bytes[Offset] != 0xCC);
        ok(!Wrote, "%s: length %lu wrote to the buffer\n", Test, Try);
    }

    /* Exactly enough, and more than enough; nothing is written past the length */
    for (Try = Needed; Try <= Needed + 6; Try += 6)
    {
        memset(Buffer, 0xCC, Needed + 16);
        Length = 0x55555555;
        Status = NtQueryInformationProcess(Process, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS, Buffer, Try, &Length);
        ok(Status == STATUS_SUCCESS, "%s: length %lu returned 0x%lx\n", Test, Try, Status);
        ok(Length == Needed, "%s: length %lu reported %lu, expected %lu\n", Test, Try, Length, Needed);
        if (Status == STATUS_SUCCESS)
        {
            CmdLineCheckString(Test, Buffer, Length, Expected);
            ok(Bytes[Needed] == 0xCC && Bytes[Needed + 15] == 0xCC, "%s: wrote past the size\n", Test);
        }
    }

    /* The return length is optional */
    memset(Buffer, 0xCC, Needed + 16);
    Status = NtQueryInformationProcess(Process, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS, Buffer, Needed, NULL);
    ok(Status == STATUS_SUCCESS, "%s: without return length returned 0x%lx\n", Test, Status);

    HeapFree(GetProcessHeap(), 0, Buffer);
}

#ifndef _WIN64 /* only the 32-bit build asks whether it runs under WoW64 */
static
BOOL
CmdLineIsWow64(
    _In_ HANDLE Process)
{
    typedef BOOL (WINAPI *PFN_ISWOW64)(HANDLE, PBOOL);
    PFN_ISWOW64 pIsWow64Process;
    BOOL Wow64 = FALSE;

    pIsWow64Process = (PFN_ISWOW64)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
    if (pIsWow64Process)
        pIsWow64Process(Process, &Wow64);
    return Wow64;
}
#endif

/* A suspended child of the given image: its PEB and parameters exist, it never runs */
static
BOOL
CmdLineCreateChild(
    _In_ PCWSTR ImageName,
    _In_ PCWSTR Args,
    _Out_ PROCESS_INFORMATION *ProcessInfo,
    _Out_writes_(MAX_PATH + 64) PWSTR CommandLine)
{
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    WCHAR Path[MAX_PATH];

    if (!GetEnvironmentVariableW(L"SystemRoot", Path, RTL_NUMBER_OF(Path)))
        return FALSE;
    StringCchCatW(Path, RTL_NUMBER_OF(Path), L"\\");
    StringCchCatW(Path, RTL_NUMBER_OF(Path), ImageName);
    if (GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES)
        return FALSE;
    StringCchPrintfW(CommandLine, MAX_PATH + 64, L"\"%ls\" %ls", Path, Args);
    return CreateProcessW(Path, CommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED,
                          NULL, NULL, &StartupInfo, ProcessInfo);
}

static
void
CmdLineTestChild(
    _In_ const char *Test,
    _In_ PCWSTR ImageName)
{
    PROCESS_INFORMATION ProcessInfo;
    WCHAR CommandLine[MAX_PATH + 64];
    HANDLE Handle;
    NTSTATUS Status;
    ULONG Length = 0x55555555;
    ULONGLONG Storage[128];
    PUCHAR Buffer = (PUCHAR)Storage;

    if (!CmdLineCreateChild(ImageName, L"/c " CMDLINE_MARKER, &ProcessInfo, CommandLine))
    {
        skip("%s: cannot start %ls\n", Test, ImageName);
        return;
    }

    CmdLineQueryAll(Test, ProcessInfo.hProcess, CommandLine);

    /* Query-limited is all it takes; reading memory alone is not enough */
    if (DuplicateHandle(GetCurrentProcess(), ProcessInfo.hProcess, GetCurrentProcess(), &Handle,
                        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
    {
        Status = NtQueryInformationProcess(Handle, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                           Buffer, sizeof(Storage), &Length);
        ok(Status == STATUS_SUCCESS, "%s: limited handle returned 0x%lx\n", Test, Status);
        CloseHandle(Handle);
    }
    Length = 0x55555555;
    if (DuplicateHandle(GetCurrentProcess(), ProcessInfo.hProcess, GetCurrentProcess(), &Handle,
                        PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, 0))
    {
        Status = NtQueryInformationProcess(Handle, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                           Buffer, sizeof(Storage), &Length);
        ok(Status == STATUS_ACCESS_DENIED, "%s: VM_READ handle returned 0x%lx\n", Test, Status);
        ok(CMDLINE_UNTOUCHED(Length), "%s: access denied changed the return length to %lu\n", Test, Length);
        CloseHandle(Handle);
    }

    /* Once it has exited, there is no process to read */
    TerminateProcess(ProcessInfo.hProcess, 0);
    WaitForSingleObject(ProcessInfo.hProcess, 10000);
    Length = 0x55555555;
    Status = NtQueryInformationProcess(ProcessInfo.hProcess, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                       Buffer, sizeof(Storage), &Length);
    ok(Status == STATUS_PROCESS_IS_TERMINATING, "%s: terminated child returned 0x%lx\n", Test, Status);
    ok(CMDLINE_UNTOUCHED(Length), "%s: terminated child changed the return length to %lu\n", Test, Length);

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
}

static
DWORD
CmdLineFindProcess(
    _In_ PCWSTR Name)
{
    PROCESSENTRY32W Entry = { sizeof(Entry) };
    HANDLE Snapshot;
    DWORD Pid = 0;

    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
        return 0;
    if (Process32FirstW(Snapshot, &Entry))
    {
        do
        {
            if (!_wcsicmp(Entry.szExeFile, Name))
            {
                Pid = Entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(Snapshot, &Entry));
    }
    CloseHandle(Snapshot);
    return Pid;
}

static
void
Test_ProcessCommandLineInformation(void)
{
    NTSTATUS Status;
    ULONG Length;
    HANDLE Handle, Self;
    PVOID Page;
    PCWSTR Own = GetCommandLineW();
    DWORD Pid;
    ULONGLONG Storage[128];
    PUCHAR Buffer = (PUCHAR)Storage;
    struct { PCSTR Name; DWORD Access; NTSTATUS Expected; } Rights[] =
    {
        { "QUERY_LIMITED_INFORMATION", PROCESS_QUERY_LIMITED_INFORMATION, STATUS_SUCCESS },
        { "QUERY_INFORMATION", PROCESS_QUERY_INFORMATION, STATUS_SUCCESS },
        { "QUERY_INFORMATION|VM_READ", PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, STATUS_SUCCESS },
        { "VM_READ", PROCESS_VM_READ, STATUS_ACCESS_DENIED },
        { "SYNCHRONIZE", SYNCHRONIZE, STATUS_ACCESS_DENIED },
        { "SET_INFORMATION", PROCESS_SET_INFORMATION, STATUS_ACCESS_DENIED },
        { "SET_LIMITED_INFORMATION", PROCESS_SET_LIMITED_INFORMATION, STATUS_ACCESS_DENIED },
        { "TERMINATE", PROCESS_TERMINATE, STATUS_ACCESS_DENIED },
    };
    ULONG i;

    /* The calling process, through the pseudo handle and through a real one */
    CmdLineQueryAll("self", NtCurrentProcess(), Own);
    Self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    ok(Self != NULL, "OpenProcess failed with %lu\n", GetLastError());
    if (Self)
        CmdLineQueryAll("self handle", Self, Own);

    /* The rights the query needs */
    for (i = 0; Self && i < RTL_NUMBER_OF(Rights); i++)
    {
        if (!DuplicateHandle(GetCurrentProcess(), Self, GetCurrentProcess(), &Handle, Rights[i].Access, FALSE, 0))
        {
            skip("cannot duplicate with %s\n", Rights[i].Name);
            continue;
        }
        Length = 0x55555555;
        memset(Buffer, 0xCC, sizeof(Storage));
        Status = NtQueryInformationProcess(Handle, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                           Buffer, sizeof(Storage), &Length);
        ok(Status == Rights[i].Expected, "%s: returned 0x%lx, expected 0x%lx\n",
           Rights[i].Name, Status, Rights[i].Expected);
        if (Status == STATUS_ACCESS_DENIED)
        {
            ok(CMDLINE_UNTOUCHED(Length), "%s: return length %lu\n", Rights[i].Name, Length);
            ok(Buffer[0] == 0xCC, "%s: wrote to the buffer\n", Rights[i].Name);
        }
        CloseHandle(Handle);
    }

    /* Bad handles and bad pointers */
    Length = 0x55555555;
    Status = NtQueryInformationProcess((HANDLE)(ULONG_PTR)0x12345670, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                       Buffer, sizeof(Storage), &Length);
    ok(Status == STATUS_INVALID_HANDLE, "bad handle returned 0x%lx\n", Status);
    ok(CMDLINE_UNTOUCHED(Length), "bad handle changed the return length to %lu\n", Length);
    Status = NtQueryInformationProcess(NULL, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                       Buffer, sizeof(Storage), &Length);
    ok(Status == STATUS_INVALID_HANDLE, "NULL handle returned 0x%lx\n", Status);

    Status = NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                       NULL, 0, NULL);
    ok(Status == STATUS_INFO_LENGTH_MISMATCH, "no buffer and no return length returned 0x%lx\n", Status);

    Status = NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                       Buffer, sizeof(Storage), (PULONG)(ULONG_PTR)0x10);
    ok(Status == STATUS_ACCESS_VIOLATION, "bad return length pointer returned 0x%lx\n", Status);

    Status = NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                       (PVOID)(ULONG_PTR)0x10, sizeof(Storage), &Length);
    ok(Status == STATUS_ACCESS_VIOLATION, "bad buffer pointer returned 0x%lx\n", Status);

    /* A read-only page cannot take the answer, and what is behind it is not touched */
    Page = VirtualAlloc(NULL, 2 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok(Page != NULL, "VirtualAlloc failed\n");
    if (Page)
    {
        DWORD OldProtect;

        memset(Page, 0xCC, 2 * 4096);
        VirtualProtect(Page, 4096, PAGE_READONLY, &OldProtect);
        Status = NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                           Page, 4096, &Length);
        ok(Status == STATUS_ACCESS_VIOLATION, "read-only buffer returned 0x%lx\n", Status);
        VirtualFree(Page, 0, MEM_RELEASE);
    }

#ifdef _WIN64
    /* Alignment is that of a ULONG, and the length is checked first */
    {
        PUCHAR Aligned = (PUCHAR)(((ULONG_PTR)Buffer + 7) & ~(ULONG_PTR)7);

        Status = NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                           Aligned + 1, 512, &Length);
        ok(Status == STATUS_DATATYPE_MISALIGNMENT, "misaligned buffer returned 0x%lx\n", Status);
        Status = NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                           Aligned + 4, 512, &Length);
        ok(Status == STATUS_SUCCESS, "4-byte aligned buffer returned 0x%lx\n", Status);
        Status = NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                           Aligned + 1, 0, &Length);
        ok(Status == STATUS_INFO_LENGTH_MISMATCH, "misaligned empty buffer returned 0x%lx\n", Status);
    }
#endif

    /* A native child, a WoW64 child of a 64-bit caller and the reverse */
    CmdLineTestChild("child", L"system32\\cmd.exe");
#ifdef _WIN64
    CmdLineTestChild("32-bit child", L"SysWOW64\\cmd.exe");
#else
    if (CmdLineIsWow64(GetCurrentProcess()))
        CmdLineTestChild("64-bit child", L"Sysnative\\cmd.exe");
#endif

    /* System has no PEB and so no command line; the query still needs a valid handle */
    Handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);
    if (Handle)
    {
        Length = 0x55555555;
        memset(Buffer, 0xCC, sizeof(Storage));
        Status = NtQueryInformationProcess(Handle, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                           Buffer, sizeof(Storage), &Length);
        ok(Status == STATUS_NOT_FOUND, "System returned 0x%lx\n", Status);
        ok(CMDLINE_UNTOUCHED(Length) && Buffer[0] == 0xCC, "System: return length %lu\n", Length);
        Status = NtQueryInformationProcess(Handle, (PROCESSINFOCLASS)PROCESS_COMMAND_LINE_CLASS,
                                           NULL, 0, &Length);
        ok(Status == STATUS_NOT_FOUND, "System with no buffer returned 0x%lx\n", Status);
        CloseHandle(Handle);
    }
    else
    {
        skip("cannot open System: %lu\n", GetLastError());
    }

    /* A system process that user mode cannot open for more than query-limited */
    Pid = CmdLineFindProcess(L"smss.exe");
    Handle = Pid ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid) : NULL;
    if (Handle)
    {
        CmdLineQueryAll("smss", Handle, NULL);
        CloseHandle(Handle);
    }
    else
    {
        skip("cannot open smss: %lu\n", GetLastError());
    }

    if (Self)
        CloseHandle(Self);
}
/* END ProcessCommandLineInformation test */

static
DWORD
WINAPI
HandleTableChurnThread(
    _In_ PVOID Context)
{
    volatile LONG *Stop = Context;
    HANDLE Handles[24] = { NULL };
    ULONG i = 0, k = 0;

    while (!*Stop)
    {
        i = (i + 7) % RTL_NUMBER_OF(Handles);
        if (Handles[i])
        {
            CloseHandle(Handles[i]);
            Handles[i] = NULL;
        }
        else if ((k++ & 1) == 0)
        {
            Handles[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        }
        else
        {
            Handles[i] = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
        }
    }
    for (i = 0; i < RTL_NUMBER_OF(Handles); i++)
    {
        if (Handles[i])
            CloseHandle(Handles[i]);
    }
    return 0;
}

/*
 * The Chromium sandbox calls this on itself, sized as GetProcessHandleCount() + 1000 handles, and
 * terminates the process (exit 0x1b62) when it fails. The snapshot must not fail
 * while other threads create and close handles.
 */
static
void
Test_ProcessHandleTableRace(void)
{
    volatile LONG Stop = 0;
    HANDLE Threads[3];
    ULONG Queries = 0, Failed = 0, i, Start;
    NTSTATUS Status, FirstBad = STATUS_SUCCESS;
    PULONG Buffer;
    DWORD Count;

    Status = NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)58, NULL, 0, NULL);
    if (Status == STATUS_INVALID_INFO_CLASS || Status == STATUS_NOT_IMPLEMENTED)
    {
        skip("ProcessHandleTable is not supported\n");
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(Threads); i++)
        Threads[i] = CreateThread(NULL, 0, HandleTableChurnThread, (PVOID)&Stop, 0, NULL);

    Start = GetTickCount();
    while (GetTickCount() - Start < 3000)
    {
        ULONG Length = 0;

        if (!GetProcessHandleCount(GetCurrentProcess(), &Count))
            break;
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, (Count + 1000) * sizeof(ULONG));
        if (!Buffer)
            break;
        Status = NtQueryInformationProcess(NtCurrentProcess(),
                                           (PROCESSINFOCLASS)58,
                                           Buffer,
                                           (Count + 1000) * sizeof(ULONG),
                                           &Length);
        Queries++;
        if (!NT_SUCCESS(Status))
        {
            if (Failed++ == 0)
                FirstBad = Status;
        }
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    }

    Stop = 1;
    for (i = 0; i < RTL_NUMBER_OF(Threads); i++)
    {
        if (Threads[i])
        {
            WaitForSingleObject(Threads[i], INFINITE);
            CloseHandle(Threads[i]);
        }
    }
    ok(Queries > 0, "no query ran\n");
    ok(Failed == 0, "%lu of %lu ProcessHandleTable queries failed, first status 0x%08lx\n", Failed, Queries, FirstBad);
}

START_TEST(NtQueryInformationProcess)
{
    NTSTATUS Status;

    /* Make sure that some time has passed since process creation, even if the resolution of our NtQuerySystemTime is low. */
    Sleep(1);

    Status = NtQuerySystemTime(&TestStartTime);
    ok_hex(Status, STATUS_SUCCESS);

    Test_ProcessTimes();
    Test_ProcessBasicInformation();
    Test_ProcessQuotaLimits();
    Test_ProcessQuotaLimitsEx();
    Test_ProcessPriorityClassAlignment();
    Test_ProcessWx86Information();
    Test_ProcQueryAlignmentProbe();
    Test_ProcessVmCounters();
    Test_ProcessCommandLineInformation();
    Test_ProcessHandleTableRace();
}
