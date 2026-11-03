/*
 * PROJECT:     ReactOS Storport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Request timeouts and reset escalation
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Every request handed to the miniport counts down its Srb->TimeOutValue, in
 * seconds, on a one second adapter timer. When one runs out, the bus is reset
 * through HwResetBus: the miniport is expected to complete what it holds with
 * SRB_STATUS_BUS_RESET, and the class driver retries. The timed out request
 * gets its timeout once more. If it runs out again the miniport has lost it:
 * the adapter is stopped and restarted through HwAdapterControl (when the
 * miniport supports ScsiStopAdapter and ScsiRestartAdapter), after which no
 * request issued before the restart is owned by the hardware, and storport
 * completes those that are still outstanding itself (the timed out ones with
 * SRB_STATUS_TIMEOUT, the others with SRB_STATUS_BUS_RESET). A miniport
 * without HwAdapterControl only gets further bus resets: storport never
 * completes a request the hardware may still transfer into.
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"

#define NDEBUG
#include <debug.h>


/* A request that names no timeout */
#define STORP_DEFAULT_TIMEOUT_SECONDS   10

/* FUNCTIONS ******************************************************************/

VOID
PortTimeoutArmRequest(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PQUEUED_REQUEST_REFERENCE RequestReference)
{
    KIRQL OldIrql;
    ULONG Timeout = RequestReference->Srb->TimeOutValue;

    if (Timeout == 0)
        Timeout = STORP_DEFAULT_TIMEOUT_SECONDS;

    KeAcquireSpinLock(&FdoExtension->TimeoutLock, &OldIrql);
    RequestReference->TimeoutCounter = Timeout;
    RequestReference->ResetSent = FALSE;
    RequestReference->Generation = FdoExtension->ResetGeneration;
    InsertTailList(&FdoExtension->IssuedRequestsListHead, &RequestReference->TimeoutEntry);
    RequestReference->OnTimeoutList = TRUE;
    KeReleaseSpinLock(&FdoExtension->TimeoutLock, OldIrql);
}


VOID
PortTimeoutDisarmRequest(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PQUEUED_REQUEST_REFERENCE RequestReference)
{
    KIRQL OldIrql;

    if (!RequestReference->OnTimeoutList)
        return;

    KeAcquireSpinLock(&FdoExtension->TimeoutLock, &OldIrql);
    RemoveEntryList(&RequestReference->TimeoutEntry);
    RequestReference->OnTimeoutList = FALSE;
    KeReleaseSpinLock(&FdoExtension->TimeoutLock, OldIrql);
}


/**
 * @brief The first of the miniport's completion and storport's own wins. May run at DIRQL.
 */
BOOLEAN
PortClaimRequestCompletion(
    _In_ PQUEUED_REQUEST_REFERENCE RequestReference)
{
    return InterlockedExchange(&RequestReference->Completed, 1) == 0;
}


static
SCSI_ADAPTER_CONTROL_STATUS
PortCallAdapterControl(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ SCSI_ADAPTER_CONTROL_TYPE ControlType)
{
    SCSI_ADAPTER_CONTROL_STATUS Status;
    KIRQL OldIrql;

    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    Status = FdoExtension->Miniport.InitData->HwAdapterControl(
                 &FdoExtension->Miniport.MiniportExtension->HwDeviceExtension,
                 ControlType,
                 NULL);
    KeLowerIrql(OldIrql);

    return Status;
}


/**
 * @brief Asks the miniport which HwAdapterControl operations it supports. Called once it is up.
 */
VOID
PortQueryAdapterControlTypes(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    /* SCSI_SUPPORTED_CONTROL_TYPE_LIST (srb.h; storport.h has no definition) with its room */
    struct
    {
        ULONG MaxControlType;
        BOOLEAN SupportedTypeList[ScsiAdapterControlMax];
    } Query;
    PHW_INITIALIZATION_DATA HwInitData = FdoExtension->Miniport.InitData;
    ULONG i;

    RtlZeroMemory(FdoExtension->AdapterControlSupported, sizeof(FdoExtension->AdapterControlSupported));
    if (HwInitData == NULL || HwInitData->HwAdapterControl == NULL)
        return;

    RtlZeroMemory(&Query, sizeof(Query));
    Query.MaxControlType = ScsiAdapterControlMax;
    if (HwInitData->HwAdapterControl(&FdoExtension->Miniport.MiniportExtension->HwDeviceExtension,
                                     ScsiQuerySupportedControlTypes,
                                     &Query) != ScsiAdapterControlSuccess)
    {
        return;
    }

    for (i = 0; i < ScsiAdapterControlMax; i++)
        FdoExtension->AdapterControlSupported[i] = Query.SupportedTypeList[i];

    DPRINT1("Miniport adapter control: stop %u restart %u\n",
            FdoExtension->AdapterControlSupported[ScsiStopAdapter],
            FdoExtension->AdapterControlSupported[ScsiRestartAdapter]);
}


/**
 * @brief Stops and restarts the adapter, then completes every request issued before that
 * the miniport did not complete. Passive level.
 */
static
VOID
PortRestartAdapter(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PHW_INITIALIZATION_DATA HwInitData = FdoExtension->Miniport.InitData;
    PQUEUED_REQUEST_REFERENCE RequestReference;
    SCSI_ADAPTER_CONTROL_STATUS Status;
    PLIST_ENTRY Entry;
    ULONG Generation, Swept = 0;
    KIRQL OldIrql;

    FdoExtension->AdapterRestarts++;

    if (HwInitData->HwAdapterControl == NULL ||
        !FdoExtension->AdapterControlSupported[ScsiStopAdapter] ||
        !FdoExtension->AdapterControlSupported[ScsiRestartAdapter])
    {
        /* The miniport may still own the requests: reset again and wait */
        DPRINT1("storport: request still outstanding after a bus reset, the miniport cannot be restarted; resetting again\n");
        if (HwInitData->HwResetBus)
        {
            KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
            HwInitData->HwResetBus(&FdoExtension->Miniport.MiniportExtension->HwDeviceExtension, 0);
            KeLowerIrql(OldIrql);
        }

        KeAcquireSpinLock(&FdoExtension->TimeoutLock, &OldIrql);
        for (Entry = FdoExtension->IssuedRequestsListHead.Flink;
             Entry != &FdoExtension->IssuedRequestsListHead;
             Entry = Entry->Flink)
        {
            RequestReference = CONTAINING_RECORD(Entry, QUEUED_REQUEST_REFERENCE, TimeoutEntry);
            if (!RequestReference->Completed && RequestReference->TimeoutCounter == 0)
                RequestReference->TimeoutCounter = max(RequestReference->Srb->TimeOutValue, STORP_DEFAULT_TIMEOUT_SECONDS);
        }
        KeReleaseSpinLock(&FdoExtension->TimeoutLock, OldIrql);
        return;
    }

    /* Requests issued from here on belong to the restarted adapter */
    KeAcquireSpinLock(&FdoExtension->TimeoutLock, &OldIrql);
    Generation = ++FdoExtension->ResetGeneration;
    KeReleaseSpinLock(&FdoExtension->TimeoutLock, OldIrql);

    DPRINT1("storport: request still outstanding after a bus reset, restarting the adapter (restart %lu)\n",
            FdoExtension->AdapterRestarts);

    Status = PortCallAdapterControl(FdoExtension, ScsiStopAdapter);
    if (Status != ScsiAdapterControlSuccess)
        DPRINT1("storport: ScsiStopAdapter failed (%d)\n", Status);

    Status = PortCallAdapterControl(FdoExtension, ScsiRestartAdapter);
    if (Status != ScsiAdapterControlSuccess)
        DPRINT1("storport: ScsiRestartAdapter failed (%d)\n", Status);

    /* The hardware has let go of everything issued before the restart */
    KeAcquireSpinLock(&FdoExtension->TimeoutLock, &OldIrql);
    for (Entry = FdoExtension->IssuedRequestsListHead.Flink;
         Entry != &FdoExtension->IssuedRequestsListHead;
         Entry = Entry->Flink)
    {
        RequestReference = CONTAINING_RECORD(Entry, QUEUED_REQUEST_REFERENCE, TimeoutEntry);

        if ((LONG)(RequestReference->Generation - Generation) >= 0)
            continue;

        if (!PortClaimRequestCompletion(RequestReference))
            continue;

        RequestReference->Srb->SrbStatus = (RequestReference->TimeoutCounter == 0) ?
                                           SRB_STATUS_TIMEOUT : SRB_STATUS_BUS_RESET;
        InterlockedPushEntrySList(&FdoExtension->CompletionList, &RequestReference->CompletionEntry);
        Swept++;
    }
    KeReleaseSpinLock(&FdoExtension->TimeoutLock, OldIrql);

    DPRINT1("storport: adapter restarted, %lu outstanding request(s) completed by storport\n", Swept);

    if (Swept)
        KeInsertQueueDpc(&FdoExtension->Device->Dpc, NULL, NULL);
}


static
VOID
NTAPI
PortTimeoutWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context)
{
    PFDO_DEVICE_EXTENSION FdoExtension = (PFDO_DEVICE_EXTENSION)Context;
    PHW_INITIALIZATION_DATA HwInitData = FdoExtension->Miniport.InitData;
    PQUEUED_REQUEST_REFERENCE RequestReference;
    BOOLEAN Reset = FALSE, Escalate = FALSE, Result;
    ULONG PathId = 0;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(DeviceObject);

    KeAcquireSpinLock(&FdoExtension->TimeoutLock, &OldIrql);
    for (Entry = FdoExtension->IssuedRequestsListHead.Flink;
         Entry != &FdoExtension->IssuedRequestsListHead;
         Entry = Entry->Flink)
    {
        RequestReference = CONTAINING_RECORD(Entry, QUEUED_REQUEST_REFERENCE, TimeoutEntry);
        if (RequestReference->Completed || RequestReference->TimeoutCounter != 0)
            continue;

        if (RequestReference->ResetSent)
        {
            Escalate = TRUE;
            continue;
        }

        DPRINT1("storport: request timed out: (%u:%u:%u) Srb %p function %02x cdb %02x timeout %lu s\n",
                RequestReference->Srb->PathId, RequestReference->Srb->TargetId, RequestReference->Srb->Lun,
                RequestReference->Srb, RequestReference->Srb->Function, RequestReference->Srb->Cdb[0],
                RequestReference->Srb->TimeOutValue);

        /* It gets one more period to come back from the reset */
        Reset = TRUE;
        PathId = RequestReference->Srb->PathId;
        RequestReference->ResetSent = TRUE;
        RequestReference->TimeoutCounter = max(RequestReference->Srb->TimeOutValue, STORP_DEFAULT_TIMEOUT_SECONDS);
    }
    KeReleaseSpinLock(&FdoExtension->TimeoutLock, OldIrql);

    if (Escalate)
    {
        PortRestartAdapter(FdoExtension);
    }
    else if (Reset)
    {
        FdoExtension->BusResets++;
        DPRINT1("storport: resetting bus %lu (reset %lu)\n", PathId, FdoExtension->BusResets);

        if (HwInitData->HwResetBus)
        {
            KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
            Result = HwInitData->HwResetBus(&FdoExtension->Miniport.MiniportExtension->HwDeviceExtension,
                                            PathId);
            KeLowerIrql(OldIrql);

            if (!Result)
                DPRINT1("storport: HwResetBus failed\n");
        }
    }

    InterlockedExchange(&FdoExtension->TimeoutWorkQueued, 0);
}


static
VOID
NTAPI
PortTimeoutDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    PFDO_DEVICE_EXTENSION FdoExtension = (PFDO_DEVICE_EXTENSION)DeferredContext;
    PQUEUED_REQUEST_REFERENCE RequestReference;
    BOOLEAN Expired = FALSE;
    PLIST_ENTRY Entry;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    KeAcquireSpinLockAtDpcLevel(&FdoExtension->TimeoutLock);
    for (Entry = FdoExtension->IssuedRequestsListHead.Flink;
         Entry != &FdoExtension->IssuedRequestsListHead;
         Entry = Entry->Flink)
    {
        RequestReference = CONTAINING_RECORD(Entry, QUEUED_REQUEST_REFERENCE, TimeoutEntry);
        if (RequestReference->Completed)
            continue;

        if (RequestReference->TimeoutCounter > 1)
        {
            RequestReference->TimeoutCounter--;
            continue;
        }

        RequestReference->TimeoutCounter = 0;
        Expired = TRUE;
    }
    KeReleaseSpinLockFromDpcLevel(&FdoExtension->TimeoutLock);

    /* Resets call the miniport for a long time: not from the timer */
    if (Expired &&
        FdoExtension->TimeoutWorkItem != NULL &&
        InterlockedCompareExchange(&FdoExtension->TimeoutWorkQueued, 1, 0) == 0)
    {
        IoQueueWorkItem(FdoExtension->TimeoutWorkItem, PortTimeoutWorker, DelayedWorkQueue, FdoExtension);
    }
}


VOID
PortInitializeTimeouts(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    KeInitializeSpinLock(&FdoExtension->TimeoutLock);
    InitializeListHead(&FdoExtension->IssuedRequestsListHead);
    KeInitializeTimer(&FdoExtension->TimeoutTimer);
    KeInitializeDpc(&FdoExtension->TimeoutDpc, PortTimeoutDpc, FdoExtension);
}


VOID
PortStartTimeouts(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    LARGE_INTEGER DueTime;

    if (FdoExtension->TimeoutWorkItem == NULL)
        FdoExtension->TimeoutWorkItem = IoAllocateWorkItem(FdoExtension->Device);

    DueTime.QuadPart = -10000000LL;
    KeSetTimerEx(&FdoExtension->TimeoutTimer, DueTime, 1000, &FdoExtension->TimeoutDpc);
}


VOID
PortStopTimeouts(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PLIST_ENTRY Entry;
    KIRQL OldIrql;

    KeCancelTimer(&FdoExtension->TimeoutTimer);

    /* The miniport's timers (RequestTimerCall, StorPortRequestTimer) must not fire into an
       adapter that is going away either */
    KeCancelTimer(&FdoExtension->Timer);
    KeAcquireSpinLock(&FdoExtension->TimerListLock, &OldIrql);
    for (Entry = FdoExtension->TimerListHead.Flink;
         Entry != &FdoExtension->TimerListHead;
         Entry = Entry->Flink)
    {
        PTIMER_ENTRY TimerEntry = CONTAINING_RECORD(Entry, TIMER_ENTRY, ListEntry);
        if (KeCancelTimer(&TimerEntry->Timer))
            InterlockedExchange(&TimerEntry->TimerAlreadySet, 0);
    }
    KeReleaseSpinLock(&FdoExtension->TimerListLock, OldIrql);

    KeFlushQueuedDpcs();

    /* A miniport timer routine that was running may have set its timer again */
    KeCancelTimer(&FdoExtension->Timer);
    KeFlushQueuedDpcs();

    /* A queued worker holds the device object, and frees nothing */
    while (InterlockedCompareExchange(&FdoExtension->TimeoutWorkQueued, 0, 0) != 0)
    {
        LARGE_INTEGER Delay;
        Delay.QuadPart = -100000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    if (FdoExtension->TimeoutWorkItem != NULL)
    {
        IoFreeWorkItem(FdoExtension->TimeoutWorkItem);
        FdoExtension->TimeoutWorkItem = NULL;
    }
}

/* EOF */
