/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Kernel
 * FILE:            ntoskrnl/ex/time.c
 * PURPOSE:         Time and Timezone Management
 * PROGRAMMERS:     Eric Kohl
 *                  Thomas Weidenmueller
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define TICKSPERMINUTE  600000000

/* GLOBALS ******************************************************************/

/* Note: Bias[minutes] = UTC - local time */
RTL_TIME_ZONE_INFORMATION ExpTimeZoneInfo;
ULONG ExpLastTimeZoneBias = -1;
LARGE_INTEGER ExpTimeZoneBias;
ULONG ExpAltTimeZoneBias;
ULONG ExpTimeZoneId;
ULONG ExpTickCountMultiplier;
ERESOURCE ExpTimeRefreshLock;
ULONG ExpKernelResolutionCount = 0;
ULONG ExpTimerResolutionCount = 0;

/* Fires at the next daylight saving transition */
static KTIMER ExpTimeZoneTimer;
static KDPC ExpTimeZoneDpc;
static WORK_QUEUE_ITEM ExpTimeZoneWorkItem;
static LONG ExpTimeZoneWorkQueued;
static BOOLEAN ExpTimeZoneTimerReady;

/* FUNCTIONS ****************************************************************/

/*++
 * If successful, this function sets the following global variable:
 * ExpTimeZoneInfo
 *--*/
static
BOOLEAN
ExpGetTimeZoneId(
    _In_ PLARGE_INTEGER TimeNow,
    _Out_ PULONG TimeZoneId,
    _Out_ PLARGE_INTEGER NewTimeZoneBias)
{
    LARGE_INTEGER StandardTime;
    LARGE_INTEGER DaylightTime;
    LARGE_INTEGER LocalTimeNow = *TimeNow;
    NTSTATUS Status;

    DPRINT("ExpGetTimeZoneId\n");

    /* Read time zone information from the registry */
    Status = RtlQueryTimeZoneInformation(&ExpTimeZoneInfo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlQueryTimeZoneInformation failed (Status 0x%08lx)\n", Status);
        return FALSE;
    }

    /* Get the default bias */
    NewTimeZoneBias->QuadPart = (LONGLONG)ExpTimeZoneInfo.Bias * TICKSPERMINUTE;

    if (ExpTimeZoneInfo.StandardDate.Month != 0 &&
        ExpTimeZoneInfo.DaylightDate.Month != 0)
    {
        /* Get this year's standard start time */
        if (!RtlCutoverTimeToSystemTime(&ExpTimeZoneInfo.StandardDate,
                                        &StandardTime,
                                        &LocalTimeNow,
                                        TRUE))
        {
            DPRINT1("RtlCutoverTimeToSystemTime for StandardDate failed\n");
            return FALSE;
        }

        /* Get this year's daylight start time */
        if (!RtlCutoverTimeToSystemTime(&ExpTimeZoneInfo.DaylightDate,
                                        &DaylightTime,
                                        &LocalTimeNow,
                                        TRUE))
        {
            DPRINT1("RtlCutoverTimeToSystemTime for DaylightDate failed\n");
            return FALSE;
        }

        /* Determine the time zone id and update the time zone bias */
        if (DaylightTime.QuadPart < StandardTime.QuadPart)
        {
            if ((LocalTimeNow.QuadPart >= DaylightTime.QuadPart) &&
                (LocalTimeNow.QuadPart < StandardTime.QuadPart))
            {
                DPRINT("Daylight time\n");
                *TimeZoneId = TIME_ZONE_ID_DAYLIGHT;
                NewTimeZoneBias->QuadPart += (LONGLONG)ExpTimeZoneInfo.DaylightBias * TICKSPERMINUTE;
            }
            else
            {
                DPRINT("Standard time\n");
                *TimeZoneId = TIME_ZONE_ID_STANDARD;
                NewTimeZoneBias->QuadPart += (LONGLONG)ExpTimeZoneInfo.StandardBias * TICKSPERMINUTE;
            }
        }
        else
        {
            if ((LocalTimeNow.QuadPart >= StandardTime.QuadPart) &&
                (LocalTimeNow.QuadPart < DaylightTime.QuadPart))
            {
                DPRINT("Standard time\n");
                *TimeZoneId = TIME_ZONE_ID_STANDARD;
                NewTimeZoneBias->QuadPart += (LONGLONG)ExpTimeZoneInfo.StandardBias * TICKSPERMINUTE;
            }
            else
            {
                DPRINT("Daylight time\n");
                *TimeZoneId = TIME_ZONE_ID_DAYLIGHT;
                NewTimeZoneBias->QuadPart += (LONGLONG)ExpTimeZoneInfo.DaylightBias * TICKSPERMINUTE;
            }
        }
    }
    else
    {
        *TimeZoneId = TIME_ZONE_ID_UNKNOWN;
    }

    return TRUE;
}

/*++
 * Checks that a transition date is either a fixed date or a valid
 * "day of week in month" rule.
 *--*/
static
BOOLEAN
ExpIsValidCutover(
    _In_ PTIME_FIELDS Cutover)
{
    TIME_FIELDS Fields;
    LARGE_INTEGER Time;

    /* Far enough from the end of the time range for any bias */
    if (Cutover->Year != 0)
        return Cutover->Year <= 30000 && RtlTimeFieldsToTime(Cutover, &Time);

    if (Cutover->Day < 1 || Cutover->Day > 5 ||
        Cutover->Weekday < 0 || Cutover->Weekday > 6)
    {
        return FALSE;
    }

    /* Check the month and the time of day */
    Fields = *Cutover;
    Fields.Year = 2001;
    Fields.Day = 1;
    return RtlTimeFieldsToTime(&Fields, &Time);
}

/*++
 * A zone without daylight saving time has no transition dates; otherwise
 * both dates must be valid.
 *--*/
static
BOOLEAN
ExpIsValidTimeZone(
    _In_ PRTL_TIME_ZONE_INFORMATION TimeZoneInfo)
{
    if (TimeZoneInfo->StandardDate.Month == 0 ||
        TimeZoneInfo->DaylightDate.Month == 0)
    {
        return TRUE;
    }

    return ExpIsValidCutover(&TimeZoneInfo->StandardDate) &&
           ExpIsValidCutover(&TimeZoneInfo->DaylightDate);
}

/*++
 * Computes the UTC instant of a transition in the given year. The
 * transition is given in local time, Bias minutes behind UTC.
 *--*/
static
BOOLEAN
ExpGetCutoverTime(
    _In_ PTIME_FIELDS Cutover,
    _In_ LONG Year,
    _In_ LONG Bias,
    _Out_ PLARGE_INTEGER UtcTime)
{
    TIME_FIELDS YearStartFields;
    LARGE_INTEGER YearStart, LocalTime;

    if (Cutover->Year != 0)
    {
        if (!RtlTimeFieldsToTime(Cutover, &LocalTime))
            return FALSE;
    }
    else
    {
        RtlZeroMemory(&YearStartFields, sizeof(YearStartFields));
        YearStartFields.Year = (CSHORT)Year;
        YearStartFields.Month = 1;
        YearStartFields.Day = 1;
        if (!RtlTimeFieldsToTime(&YearStartFields, &YearStart))
            return FALSE;

        if (!RtlCutoverTimeToSystemTime(Cutover, &LocalTime, &YearStart, TRUE))
            return FALSE;
    }

    UtcTime->QuadPart = LocalTime.QuadPart + (LONGLONG)Bias * TICKSPERMINUTE;
    return TRUE;
}

/*++
 * Computes the time zone id and the bias in effect at a UTC instant, and
 * the UTC instant of the next transition (zero if there is none).
 *--*/
static
VOID
ExpComputeTimeZoneState(
    _In_ PRTL_TIME_ZONE_INFORMATION TimeZoneInfo,
    _In_ PLARGE_INTEGER UtcTime,
    _Out_ PULONG TimeZoneId,
    _Out_ PLARGE_INTEGER TimeZoneBias,
    _Out_ PLARGE_INTEGER NextCutover)
{
    LONG StandardBias = TimeZoneInfo->Bias + TimeZoneInfo->StandardBias;
    LONG DaylightBias = TimeZoneInfo->Bias + TimeZoneInfo->DaylightBias;
    LARGE_INTEGER LocalTime, Cutover, Last, Next;
    ULONG LastId = TIME_ZONE_ID_UNKNOWN, NextId = TIME_ZONE_ID_UNKNOWN;
    ULONG Id, Rule;
    PTIME_FIELDS Date;
    TIME_FIELDS Fields;
    LONG Year, FirstYear, LastYear;
    LONG DateBias;

    *TimeZoneId = TIME_ZONE_ID_UNKNOWN;
    TimeZoneBias->QuadPart = (LONGLONG)TimeZoneInfo->Bias * TICKSPERMINUTE;
    NextCutover->QuadPart = 0;

    if (TimeZoneInfo->StandardDate.Month == 0 ||
        TimeZoneInfo->DaylightDate.Month == 0 ||
        !ExpIsValidTimeZone(TimeZoneInfo))
    {
        return;
    }

    LocalTime.QuadPart = UtcTime->QuadPart - (LONGLONG)StandardBias * TICKSPERMINUTE;
    RtlTimeToTimeFields(&LocalTime, &Fields);

    /* Find the last transition up to now and the first one after it */
    Last.QuadPart = 0;
    Next.QuadPart = 0;
    for (Rule = 0; Rule < 2; Rule++)
    {
        /* The daylight date is in standard time, the standard date in daylight time */
        if (Rule == 0)
        {
            Id = TIME_ZONE_ID_DAYLIGHT;
            Date = &TimeZoneInfo->DaylightDate;
            DateBias = StandardBias;
        }
        else
        {
            Id = TIME_ZONE_ID_STANDARD;
            Date = &TimeZoneInfo->StandardDate;
            DateBias = DaylightBias;
        }

        /* A fixed date occurs once; a recurring one around the current year */
        if (Date->Year != 0)
        {
            FirstYear = LastYear = Date->Year;
        }
        else
        {
            FirstYear = Fields.Year - 1;
            LastYear = Fields.Year + 1;
        }

        for (Year = FirstYear; Year <= LastYear; Year++)
        {
            if (!ExpGetCutoverTime(Date, Year, DateBias, &Cutover))
                continue;

            if (Cutover.QuadPart <= UtcTime->QuadPart)
            {
                if (LastId == TIME_ZONE_ID_UNKNOWN || Cutover.QuadPart >= Last.QuadPart)
                {
                    Last = Cutover;
                    LastId = Id;
                }
            }
            else if (NextId == TIME_ZONE_ID_UNKNOWN || Cutover.QuadPart < Next.QuadPart)
            {
                Next = Cutover;
                NextId = Id;
            }
        }
    }

    /* Before the first transition the opposite state applies */
    if (LastId != TIME_ZONE_ID_UNKNOWN)
        *TimeZoneId = LastId;
    else if (NextId == TIME_ZONE_ID_DAYLIGHT)
        *TimeZoneId = TIME_ZONE_ID_STANDARD;
    else if (NextId == TIME_ZONE_ID_STANDARD)
        *TimeZoneId = TIME_ZONE_ID_DAYLIGHT;
    else
        return;

    if (*TimeZoneId == TIME_ZONE_ID_DAYLIGHT)
        TimeZoneBias->QuadPart = (LONGLONG)DaylightBias * TICKSPERMINUTE;
    else
        TimeZoneBias->QuadPart = (LONGLONG)StandardBias * TICKSPERMINUTE;

    if (NextId != TIME_ZONE_ID_UNKNOWN)
        *NextCutover = Next;
}

/* Reads the current bias in one access, so that it cannot tear */
static
LONGLONG
ExpReadTimeZoneBias(VOID)
{
    return InterlockedCompareExchange64(&ExpTimeZoneBias.QuadPart, 0, 0);
}

static
VOID
ExpArmTimeZoneTimer(
    _In_ PLARGE_INTEGER NextCutover)
{
    if (!ExpTimeZoneTimerReady)
        return;

    /* A positive due time is an absolute system time */
    if (NextCutover->QuadPart > 0)
        KeSetTimer(&ExpTimeZoneTimer, *NextCutover, &ExpTimeZoneDpc);
    else
        KeCancelTimer(&ExpTimeZoneTimer);
}

/*++
 * Brings the bias and the time zone id in line with the current UTC and
 * keeps the real-time clock on local time. UTC itself does not change.
 * The caller holds the time refresh lock. Returns TRUE if the bias changed.
 *--*/
static
BOOLEAN
ExpUpdateTimeZoneBias(VOID)
{
    LARGE_INTEGER CurrentTime, LocalTime, NewTimeZoneBias, NextCutover;
    TIME_FIELDS TimeFields;
    BOOLEAN Changed;
    ULONG NewTimeZoneId;
    KIRQL OldIrql;

    KeQuerySystemTime(&CurrentTime);
    ExpComputeTimeZoneState(&ExpTimeZoneInfo,
                            &CurrentTime,
                            &NewTimeZoneId,
                            &NewTimeZoneBias,
                            &NextCutover);

    Changed = (NewTimeZoneBias.QuadPart != ExpTimeZoneBias.QuadPart);

    InterlockedExchange64(&ExpTimeZoneBias.QuadPart, NewTimeZoneBias.QuadPart);
    ExpTimeZoneId = NewTimeZoneId;

    /* Not preemptible, so that user-mode readers never wait on a half-written bias */
    KeRaiseIrql(HIGH_LEVEL, &OldIrql);
    KiWriteSystemTime(&SharedUserData->TimeZoneBias, NewTimeZoneBias);
    SharedUserData->TimeZoneId = NewTimeZoneId;
    KeLowerIrql(OldIrql);

    DPRINT("Time zone id %lu, bias %I64d minutes\n",
           ExpTimeZoneId, ExpTimeZoneBias.QuadPart / TICKSPERMINUTE);

    /* The real-time clock keeps local time */
    ExSystemTimeToLocalTime(&CurrentTime, &LocalTime);
    RtlTimeToTimeFields(&LocalTime, &TimeFields);
    HalSetRealTimeClock(&TimeFields);

    ExpArmTimeZoneTimer(&NextCutover);
    return Changed;
}

static
VOID
NTAPI
ExpTimeZoneWorker(
    _In_ PVOID Context)
{
    BOOLEAN Changed;

    UNREFERENCED_PARAMETER(Context);

    InterlockedExchange(&ExpTimeZoneWorkQueued, 0);

    ExAcquireTimeRefreshLock(TRUE);
    Changed = ExpUpdateTimeZoneBias();
    ExReleaseTimeRefreshLock();

    /* Local time has moved */
    if (Changed)
        PoNotifySystemTimeSet();
}

static
VOID
NTAPI
ExpTimeZoneDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    /* The time refresh lock needs passive level */
    if (InterlockedExchange(&ExpTimeZoneWorkQueued, 1) == 0)
        ExQueueWorkItem(&ExpTimeZoneWorkItem, DelayedWorkQueue);
}

/*++
 * @name ExAcquireTimeRefreshLock
 *
 *     The ExReleaseTimeRefreshLock routine acquires the system-wide lock used
 *     to synchronize clock interrupt frequency changes.
 *
 * @param Wait
 *        If TRUE, the system will block the caller thread waiting for the lock
 *        to become available. If FALSE, the routine will fail if the lock has
 *        already been acquired.
 *
 * @return Boolean value indicating success or failure of the lock acquisition.
 *
 * @remarks None.
 *
 *--*/
BOOLEAN
NTAPI
ExAcquireTimeRefreshLock(IN BOOLEAN Wait)
{
    /* Block APCs */
    KeEnterCriticalRegion();

    /* Attempt lock acquisition */
    if (!(ExAcquireResourceExclusiveLite(&ExpTimeRefreshLock, Wait)))
    {
        /* Lock was not acquired, enable APCs and fail */
        KeLeaveCriticalRegion();
        return FALSE;
    }

    /* Lock has been acquired */
    return TRUE;
}

/*++
 * @name ExReleaseTimeRefreshLock
 *
 *     The ExReleaseTimeRefreshLock routine releases the system-wide lock used
 *     to synchronize clock interrupt frequency changes.
 *
 * @param None.
 *
 * @return None.
 *
 * @remarks None.
 *
 *--*/
VOID
NTAPI
ExReleaseTimeRefreshLock(VOID)
{
    /* Release the lock and re-enable APCs */
    ExReleaseResourceLite(&ExpTimeRefreshLock);
    KeLeaveCriticalRegion();
}

/*++
 * @name ExSetTimerResolution
 * @exported
 *
 *     The KiInsertQueueApc routine modifies the frequency at which the system
 *     clock interrupts.
 *
 * @param DesiredTime
 *        Specifies the amount of time that should elapse between each timer
 *        interrupt, in 100-nanosecond units.
 *
 *        This parameter is ignored if SetResolution is FALSE.
 *
 * @param SetResolution
 *        If TRUE, the call is a request to set the clock interrupt frequency to
 *        the value specified by DesiredTime. If FALSE, the call is a request to
 *        restore the clock interrupt frequency to the system's default value.
 *
 * @return New timer resolution, in 100-nanosecond ticks.
 *
 * @remarks (1) The clock frequency is changed only if the DesiredTime value is
 *              less than the current setting.
 *
 *          (2) The routine just returns the current setting if the DesiredTime
 *              value is greater than what is currently set.
 *
 *          (3) If the DesiredTime value is less than the system clock can
 *              support, the routine uses the smallest resolution the system can
 *              support, and returns that value.
 *
 *          (4) If multiple drivers have attempted to change the clock interrupt
 *              frequency, the system will only restore the default frequency
 *              once ALL drivers have called the routine with SetResolution set
 *              to FALSE.
 *
 *          NB. This routine synchronizes with IRP_MJ_POWER requests through the
 *              TimeRefreshLock.
 *
 *--*/
ULONG
NTAPI
ExSetTimerResolution(IN ULONG DesiredTime,
                     IN BOOLEAN SetResolution)
{
    ULONG CurrentIncrement;

    /* Wait for clock interrupt frequency and power requests to synchronize */
    ExAcquireTimeRefreshLock(TRUE);

    /* Obey remark 2*/
    CurrentIncrement = KeTimeIncrement;

    /* Check the type of operation this is */
    if (SetResolution)
    {
        /*
         * If this is the first kernel change, bump the timer resolution change
         * count, then bump the kernel change count as well.
         *
         * These two variables are tracked differently since user-mode processes
         * can also change the timer resolution through the NtSetTimerResolution
         * system call. A per-process flag in the EPROCESS then stores the per-
         * process change state.
         *
         */
        if (!ExpKernelResolutionCount++) ExpTimerResolutionCount++;

        /* Obey remark 3 */
        if (DesiredTime < KeMinimumIncrement) DesiredTime = KeMinimumIncrement;

        /* Obey remark 1 */
        if (DesiredTime < KeTimeIncrement)
        {
            /* Force this thread on CPU zero, since we don't want it to drift */
            KeSetSystemAffinityThread(1);

            /* Now call the platform driver (HAL) to make the change */
            CurrentIncrement = HalSetTimeIncrement(DesiredTime);

            /* Put the thread back to its original affinity */
            KeRevertToUserAffinityThread();

            /* Finally, keep track of the new value in the kernel */
            KeTimeIncrement = CurrentIncrement;
        }
    }
    else
    {
        /* First, make sure that a driver has actually changed the resolution */
        if (ExpKernelResolutionCount)
        {
            /* Obey remark 4 */
            if (!--ExpKernelResolutionCount)
            {
                /*
                 * All kernel drivers have requested the original frequency to
                 * be restored, but there might still be user processes with an
                 * ongoing clock interrupt frequency change, so make sure that
                 * this isn't the case.
                 */
                if (!--ExpTimerResolutionCount)
                {
                    /* Force this thread on one CPU so that it doesn't drift */
                    KeSetSystemAffinityThread(1);

                    /* Call the HAL to restore the frequency to its default */
                    CurrentIncrement = HalSetTimeIncrement(KeMaximumIncrement);

                    /* Put the thread back to its original affinity */
                    KeRevertToUserAffinityThread();

                    /* Finally, keep track of the new value in the kernel */
                    KeTimeIncrement = CurrentIncrement;
                }
            }
        }
    }

    /* Release the clock interrupt frequency lock since changes are done */
    ExReleaseTimeRefreshLock();

    /* And return the current value -- which could reflect the new frequency */
    return CurrentIncrement;
}

VOID
NTAPI
ExUpdateSystemTimeFromCmos(IN BOOLEAN UpdateInterruptTime,
                           IN ULONG MaxSepInSeconds)
{
    /* FIXME: TODO */
    return;
}

BOOLEAN
NTAPI
ExRefreshTimeZoneInformation(IN PLARGE_INTEGER CurrentBootTime)
{
    LARGE_INTEGER CurrentTime, NewTimeZoneBias, BootTime, NextCutover;
    BOOLEAN Success;
    ULONG TimeZoneId;

    DPRINT("ExRefreshTimeZoneInformation\n");

    if (!ExpTimeZoneTimerReady)
    {
        KeInitializeTimer(&ExpTimeZoneTimer);
        KeInitializeDpc(&ExpTimeZoneDpc, ExpTimeZoneDpcRoutine, NULL);
        ExInitializeWorkItem(&ExpTimeZoneWorkItem, ExpTimeZoneWorker, NULL);
        ExpTimeZoneTimerReady = TRUE;
    }

    /* Set the global data for ExpTimeZoneBias and the Time Zone ID */
    Success = ExpGetTimeZoneId(CurrentBootTime, &ExpTimeZoneId, &NewTimeZoneBias);
    if (!Success)
    {
        DPRINT1("ExpGetTimeZoneId failed\n");
        return FALSE;
    }
    DPRINT("ExpTimeZoneId is %lu\n", ExpTimeZoneId);

    ExpTimeZoneBias = NewTimeZoneBias;

    /* Change SharedUserData->TimeZoneBias for user-mode applications */
    KiWriteSystemTime(&SharedUserData->TimeZoneBias, ExpTimeZoneBias);
    SharedUserData->TimeZoneId = ExpTimeZoneId;

    /* Convert boot time from local time to UTC */
    KeBootTime.QuadPart += ExpTimeZoneBias.QuadPart;

    /* Convert system time from local time to UTC */
    KeQuerySystemTime(&CurrentTime);;

    /* Change it for user-mode applications */
    CurrentTime.QuadPart += ExpTimeZoneBias.QuadPart;
    KiWriteSystemTime(&SharedUserData->SystemTime, CurrentTime);

    /* Arm the timer for the next transition after the boot time in UTC */
    BootTime.QuadPart = CurrentBootTime->QuadPart + ExpTimeZoneBias.QuadPart;
    ExpComputeTimeZoneState(&ExpTimeZoneInfo, &BootTime, &TimeZoneId, &NewTimeZoneBias, &NextCutover);
    ExpArmTimeZoneTimer(&NextCutover);

    /* Return success */
    return TRUE;
}

/*
 * The registry values of the zone, as they stood before a change, so that a
 * change that fails half way can put them back.
 */
typedef struct _EXP_TIME_ZONE_SNAPSHOT
{
    RTL_TIME_ZONE_INFORMATION Zone;
    WCHAR KeyName[RTL_NUMBER_OF(((PRTL_DYNAMIC_TIME_ZONE_INFORMATION)0)->TimeZoneKeyName)];
    ULONG Disabled;
    ULONG LegacyDisabled;
    BOOLEAN HaveZone;
    BOOLEAN HaveKeyName;
    BOOLEAN HaveDisabled;
    BOOLEAN HaveLegacyDisabled;
} EXP_TIME_ZONE_SNAPSHOT, *PEXP_TIME_ZONE_SNAPSHOT;

static
NTSTATUS
ExpOpenTimeZoneKey(
    _Out_ PHANDLE Key)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\TimeZoneInformation");
    OBJECT_ATTRIBUTES ObjectAttributes;

    /* A kernel handle, and a kernel-mode request: the caller's rights on the key do not matter */
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    return ZwCreateKey(Key,
                       KEY_QUERY_VALUE | KEY_SET_VALUE,
                       &ObjectAttributes,
                       0,
                       NULL,
                       REG_OPTION_NON_VOLATILE,
                       NULL);
}

static
NTSTATUS
ExpSetTimeZoneValue(
    _In_ HANDLE Key,
    _In_ PCWSTR Name,
    _In_ ULONG Type,
    _In_ PVOID Data,
    _In_ ULONG Size)
{
    UNICODE_STRING ValueName;

    RtlInitUnicodeString(&ValueName, Name);
    return ZwSetValueKey(Key, &ValueName, 0, Type, Data, Size);
}

/* TRUE if the value exists with the type; at most DataSize bytes are copied */
static
BOOLEAN
ExpQueryTimeZoneValue(
    _In_ HANDLE Key,
    _In_ PCWSTR Name,
    _In_ ULONG Type,
    _Out_writes_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PULONG ResultLength)
{
    UNICODE_STRING ValueName;
    union
    {
        KEY_VALUE_PARTIAL_INFORMATION Info;
        UCHAR Buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + 256 + sizeof(WCHAR)];
    } Value;
    ULONG Length;

    *ResultLength = 0;
    RtlInitUnicodeString(&ValueName, Name);
    if (!NT_SUCCESS(ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, &Value, sizeof(Value), &Length)) ||
        Value.Info.Type != Type ||
        Value.Info.DataLength > DataSize)
    {
        return FALSE;
    }

    RtlCopyMemory(Data, Value.Info.Data, Value.Info.DataLength);
    *ResultLength = Value.Info.DataLength;
    return TRUE;
}

static
VOID
ExpSnapshotTimeZone(
    _Out_ PEXP_TIME_ZONE_SNAPSHOT Snapshot,
    _In_ HANDLE Key)
{
    ULONG Length;

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    Snapshot->HaveZone = NT_SUCCESS(RtlQueryTimeZoneInformation(&Snapshot->Zone));

    /* The key name must end inside the buffer to be taken back */
    Snapshot->HaveKeyName = ExpQueryTimeZoneValue(Key,
                                                  L"TimeZoneKeyName",
                                                  REG_SZ,
                                                  Snapshot->KeyName,
                                                  sizeof(Snapshot->KeyName) - sizeof(WCHAR),
                                                  &Length);
    Snapshot->HaveDisabled = ExpQueryTimeZoneValue(Key,
                                                   L"DynamicDaylightTimeDisabled",
                                                   REG_DWORD,
                                                   &Snapshot->Disabled,
                                                   sizeof(Snapshot->Disabled),
                                                   &Length);
    Snapshot->HaveLegacyDisabled = ExpQueryTimeZoneValue(Key,
                                                         L"DisableAutoDaylightTimeSet",
                                                         REG_DWORD,
                                                         &Snapshot->LegacyDisabled,
                                                         sizeof(Snapshot->LegacyDisabled),
                                                         &Length);
}

static
VOID
ExpRestoreTimeZone(
    _In_ PEXP_TIME_ZONE_SNAPSHOT Snapshot,
    _In_ HANDLE Key)
{
    UNICODE_STRING ValueName;

    /* Best effort; the status of the change itself is what the caller learns */
    if (Snapshot->HaveZone)
        RtlSetTimeZoneInformation(&Snapshot->Zone);

    if (Snapshot->HaveKeyName)
    {
        ExpSetTimeZoneValue(Key,
                            L"TimeZoneKeyName",
                            REG_SZ,
                            Snapshot->KeyName,
                            (ULONG)(wcslen(Snapshot->KeyName) + 1) * sizeof(WCHAR));
    }
    if (Snapshot->HaveDisabled)
    {
        ExpSetTimeZoneValue(Key,
                            L"DynamicDaylightTimeDisabled",
                            REG_DWORD,
                            &Snapshot->Disabled,
                            sizeof(Snapshot->Disabled));
    }
    else
    {
        RtlInitUnicodeString(&ValueName, L"DynamicDaylightTimeDisabled");
        ZwDeleteValueKey(Key, &ValueName);
    }
    if (Snapshot->HaveLegacyDisabled)
    {
        ExpSetTimeZoneValue(Key,
                            L"DisableAutoDaylightTimeSet",
                            REG_DWORD,
                            &Snapshot->LegacyDisabled,
                            sizeof(Snapshot->LegacyDisabled));
    }
}

/*++
 * Writes the zone to the registry. This is the one writer of
 * HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation for a change
 * of the zone: the key belongs to SYSTEM and a standard user may only read it,
 * so the caller (after the privilege check) never writes it itself.
 *
 * The values are those of RtlSetTimeZoneInformation, which empties the key
 * name. With Dynamic, the key name and DynamicDaylightTimeDisabled follow, as
 * SystemDynamicTimeZoneInformation does on Windows. The older
 * DisableAutoDaylightTimeSet is dropped then: the caller has said what it
 * means by the flag. A failure puts back the values that were there.
 *
 * Called with the time refresh lock held.
 *--*/
static
NTSTATUS
ExpPersistTimeZone(
    _In_ PRTL_TIME_ZONE_INFORMATION Zone,
    _In_opt_ PRTL_DYNAMIC_TIME_ZONE_INFORMATION Dynamic)
{
    EXP_TIME_ZONE_SNAPSHOT Snapshot;
    UNICODE_STRING ValueName;
    ULONG Disabled;
    HANDLE Key;
    NTSTATUS Status;

    Status = ExpOpenTimeZoneKey(&Key);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Cannot open the TimeZoneInformation key (Status 0x%08lx)\n", Status);
        return Status;
    }

    ExpSnapshotTimeZone(&Snapshot, Key);

    Status = RtlSetTimeZoneInformation(Zone);
    if (NT_SUCCESS(Status) && Dynamic)
    {
        Status = ExpSetTimeZoneValue(Key,
                                     L"TimeZoneKeyName",
                                     REG_SZ,
                                     Dynamic->TimeZoneKeyName,
                                     (ULONG)(wcslen(Dynamic->TimeZoneKeyName) + 1) * sizeof(WCHAR));
        if (NT_SUCCESS(Status))
        {
            Disabled = Dynamic->DynamicDaylightTimeDisabled ? 1 : 0;
            Status = ExpSetTimeZoneValue(Key,
                                         L"DynamicDaylightTimeDisabled",
                                         REG_DWORD,
                                         &Disabled,
                                         sizeof(Disabled));
        }
        if (NT_SUCCESS(Status))
        {
            RtlInitUnicodeString(&ValueName, L"DisableAutoDaylightTimeSet");
            ZwDeleteValueKey(Key, &ValueName);
        }
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Saving the time zone failed (Status 0x%08lx)\n", Status);
        ExpRestoreTimeZone(&Snapshot, Key);
    }

    ZwClose(Key);
    return Status;
}

/*
 * Makes a zone current and keeps it across a restart. Zone is a kernel copy
 * whose names end inside their arrays; so does the key name of Dynamic. UTC
 * stays as it is; local time follows the new zone. Nothing changes in memory
 * if the registry cannot be written.
 */
static
NTSTATUS
ExpApplyTimeZoneInformation(
    _In_ PRTL_TIME_ZONE_INFORMATION Zone,
    _In_opt_ PRTL_DYNAMIC_TIME_ZONE_INFORMATION Dynamic)
{
    NTSTATUS Status;

    if (!ExpIsValidTimeZone(Zone))
    {
        DPRINT1("Invalid time zone transition dates\n");
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireTimeRefreshLock(TRUE);
    Status = ExpPersistTimeZone(Zone, Dynamic);
    if (NT_SUCCESS(Status))
    {
        RtlCopyMemory(&ExpTimeZoneInfo, Zone, sizeof(RTL_TIME_ZONE_INFORMATION));
        ExpUpdateTimeZoneBias();
    }
    ExReleaseTimeRefreshLock();

    if (NT_SUCCESS(Status))
        PoNotifySystemTimeSet();

    return Status;
}

NTSTATUS
ExpSetTimeZoneInformation(PRTL_TIME_ZONE_INFORMATION TimeZoneInformation)
{
    RTL_TIME_ZONE_INFORMATION NewTimeZoneInfo;

    DPRINT("ExpSetTimeZoneInformation called\n");

    /* Capture the caller's buffer before taking the lock; the names end in their arrays */
    RtlCopyMemory(&NewTimeZoneInfo,
                  TimeZoneInformation,
                  sizeof(RTL_TIME_ZONE_INFORMATION));
    NewTimeZoneInfo.StandardName[RTL_NUMBER_OF(NewTimeZoneInfo.StandardName) - 1] = UNICODE_NULL;
    NewTimeZoneInfo.DaylightName[RTL_NUMBER_OF(NewTimeZoneInfo.DaylightName) - 1] = UNICODE_NULL;

    return ExpApplyTimeZoneInformation(&NewTimeZoneInfo, NULL);
}

NTSTATUS
ExpSetDynamicTimeZoneInformation(PRTL_DYNAMIC_TIME_ZONE_INFORMATION DynamicTimeZoneInformation)
{
    RTL_DYNAMIC_TIME_ZONE_INFORMATION NewInfo;

    DPRINT("ExpSetDynamicTimeZoneInformation called\n");

    /* One copy of the caller's buffer, which is all that is looked at after this */
    RtlCopyMemory(&NewInfo,
                  DynamicTimeZoneInformation,
                  sizeof(RTL_DYNAMIC_TIME_ZONE_INFORMATION));
    NewInfo.TimeZoneInformation.StandardName[RTL_NUMBER_OF(NewInfo.TimeZoneInformation.StandardName) - 1] = UNICODE_NULL;
    NewInfo.TimeZoneInformation.DaylightName[RTL_NUMBER_OF(NewInfo.TimeZoneInformation.DaylightName) - 1] = UNICODE_NULL;
    NewInfo.TimeZoneKeyName[RTL_NUMBER_OF(NewInfo.TimeZoneKeyName) - 1] = UNICODE_NULL;

    return ExpApplyTimeZoneInformation(&NewInfo.TimeZoneInformation, &NewInfo);
}

VOID
ExpQueryTimeZoneInformation(PRTL_TIME_ZONE_INFORMATION TimeZoneInformation)
{
    /* A consistent copy; the caller copies it on to its buffer */
    ExAcquireTimeRefreshLock(TRUE);
    RtlCopyMemory(TimeZoneInformation,
                  &ExpTimeZoneInfo,
                  sizeof(RTL_TIME_ZONE_INFORMATION));
    ExReleaseTimeRefreshLock();
}

/*
 * FUNCTION: Sets the system time.
 * PARAMETERS:
 *        NewTime - Points to a variable that specified the new time
 *        of day in the standard time format.
 *        OldTime - Optionally points to a variable that receives the
 *        old time of day in the standard time format.
 * RETURNS: Status
 */
NTSTATUS
NTAPI
NtSetSystemTime(IN PLARGE_INTEGER SystemTime,
                OUT PLARGE_INTEGER PreviousTime OPTIONAL)
{
    LARGE_INTEGER OldSystemTime;
    LARGE_INTEGER NewSystemTime;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS ZoneStatus;
    RTL_TIME_ZONE_INFORMATION TimeZoneInformation = { 0 };

    PAGED_CODE();

    // TODO: Handle the case when SystemTime == NULL, which means:
    // "update system time using the current time-zone information".
    if (!SystemTime)
    {
        UNIMPLEMENTED;
        return STATUS_NOT_IMPLEMENTED;
    }

    /* Check if we were called from user-mode */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            /* Verify the time pointers */
            NewSystemTime = ProbeForReadLargeInteger(SystemTime);
            if (PreviousTime) ProbeForWriteLargeInteger(PreviousTime);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        /* Reuse the pointer */
        NewSystemTime = *SystemTime;
    }

    /* Make sure we have permission to change the time */
    if (!SeSinglePrivilegeCheck(SeSystemtimePrivilege, PreviousMode))
    {
        DPRINT1("NtSetSystemTime: Caller requires the "
                "SeSystemtimePrivilege privilege!\n");
        return STATUS_PRIVILEGE_NOT_HELD;
    }

    ExAcquireTimeRefreshLock(TRUE);

    /* Pick up a time zone that was changed in the registry only */
    ZoneStatus = RtlQueryTimeZoneInformation(&TimeZoneInformation);
    if (!NT_SUCCESS(ZoneStatus))
    {
        DPRINT1("RtlQueryTimeZoneInformation failed (Status 0x%08lx)\n", ZoneStatus);
    }
    else if (ExpIsValidTimeZone(&TimeZoneInformation))
    {
        RtlCopyMemory(&ExpTimeZoneInfo,
                      &TimeZoneInformation,
                      sizeof(RTL_TIME_ZONE_INFORMATION));
    }

    /* Set the system time, then the bias of the new time and the real-time clock */
    KeSetSystemTime(&NewSystemTime, &OldSystemTime, FALSE, NULL);
    ExpUpdateTimeZoneBias();

    ExReleaseTimeRefreshLock();

    PoNotifySystemTimeSet();

    /* Check if caller wanted previous time */
    if (PreviousTime)
    {
        /* Enter SEH Block for return */
        _SEH2_TRY
        {
            /* Return the previous time */
            *PreviousTime = OldSystemTime;
        }
        _SEH2_EXCEPT(ExSystemExceptionFilter())
        {
            /* Get the exception code */
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }

    /* Return status */
    return Status;
}

/*
 * FUNCTION: Retrieves the system time.
 * PARAMETERS:
 *          CurrentTime - Points to a variable that receives the current
 *          time of day in the standard time format.
 */
NTSTATUS
NTAPI
NtQuerySystemTime(OUT PLARGE_INTEGER SystemTime)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PAGED_CODE();

    /* Check if we were called from user-mode */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            /* Verify the time pointer */
            ProbeForWriteLargeInteger(SystemTime);

            /*
             * It's safe to pass the pointer directly to KeQuerySystemTime
             * as it's just a basic copy to this pointer. If it raises an
             * exception nothing dangerous can happen!
             */
            KeQuerySystemTime(SystemTime);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        /* Query the time directly */
        KeQuerySystemTime(SystemTime);
    }

    /* Return success */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
VOID
NTAPI
ExLocalTimeToSystemTime(PLARGE_INTEGER LocalTime,
                        PLARGE_INTEGER SystemTime)
{
    SystemTime->QuadPart = LocalTime->QuadPart + ExpReadTimeZoneBias();
}

/*
 * @implemented
 */
VOID
NTAPI
ExSystemTimeToLocalTime(PLARGE_INTEGER SystemTime,
                        PLARGE_INTEGER LocalTime)
{
    LocalTime->QuadPart = SystemTime->QuadPart - ExpReadTimeZoneBias();
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtQueryTimerResolution(OUT PULONG MinimumResolution,
                       OUT PULONG MaximumResolution,
                       OUT PULONG ActualResolution)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();

    /* Check if the call came from user-mode */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            /* Probe the parameters */
            ProbeForWriteUlong(MinimumResolution);
            ProbeForWriteUlong(MaximumResolution);
            ProbeForWriteUlong(ActualResolution);

            /*
             * Set the parameters to the actual values.
             *
             * NOTE:
             * MinimumResolution corresponds to the biggest time increment and
             * MaximumResolution corresponds to the smallest time increment.
             */
            *MinimumResolution = KeMaximumIncrement;
            *MaximumResolution = KeMinimumIncrement;
            *ActualResolution  = KeTimeIncrement;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        /* Set the parameters to the actual values */
        *MinimumResolution = KeMaximumIncrement;
        *MaximumResolution = KeMinimumIncrement;
        *ActualResolution  = KeTimeIncrement;
    }

    /* Return success */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtSetTimerResolution(IN ULONG DesiredResolution,
                     IN BOOLEAN SetResolution,
                     OUT PULONG CurrentResolution)
{
    NTSTATUS Status;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PEPROCESS Process = PsGetCurrentProcess();
    ULONG NewResolution;
    BOOLEAN HadResolution;

    /* Check if the call came from user-mode */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            /* Probe the parameter */
            ProbeForWriteUlong(CurrentResolution);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Keep the per-process state in step with the counts (the lock nests) */
    ExAcquireTimeRefreshLock(TRUE);
    HadResolution = Process->SetTimerResolution;

    if (SetResolution)
    {
        /* A process holds one request; a later one only applies the new rate */
        NewResolution = ExSetTimerResolution(DesiredResolution, TRUE);
        if (HadResolution) ExSetTimerResolution(0, FALSE);
        PspSetProcessFlag(Process, PSF_SET_TIMER_RESOLUTION_BIT);
    }
    else if (HadResolution)
    {
        /* Rescind the request of this process */
        NewResolution = ExSetTimerResolution(0, FALSE);
        PspClearProcessFlag(Process, PSF_SET_TIMER_RESOLUTION_BIT);
    }
    else
    {
        /* There is no request to rescind, so only return the current value */
        NewResolution = KeTimeIncrement;
    }

    ExReleaseTimeRefreshLock();

    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            *CurrentResolution = NewResolution;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        *CurrentResolution = NewResolution;
    }

    if (SetResolution || HadResolution)
    {
        /* The resolution has been changed now or in an earlier call */
        Status = STATUS_SUCCESS;
    }
    else
    {
        /* The resolution hasn't been changed */
        Status = STATUS_TIMER_RESOLUTION_NOT_SET;
    }

    return Status;
}

/* EOF */
