/*
 * PROJECT:     ReactOS Storport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Storport SRB I/O code
 * COPYRIGHT:   Copyright 2017 Eric Kohl (eric.kohl@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"
#include "inline.h"

#define NDEBUG
#include <debug/driverdbg.h>
#include <debug.h>


/* FUNCTIONS ******************************************************************/

/**
 * @brief Initializes a request reference and sets the SRB => ReqRef link.
 */
static
VOID
StorpSrbInitRequestReference(
    _In_ PQUEUED_REQUEST_REFERENCE RequestReference,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PIRP Irp,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    /* Both the lookaside entries and the reserve are recycled, so they need zeroing */
    RtlZeroMemory(RequestReference, sizeof(*RequestReference));

    Srb->OriginalRequest = (PVOID)RequestReference;
    RequestReference->Irp = Irp;
    RequestReference->Srb = Srb;
    RequestReference->TimeoutCounter = Srb->TimeOutValue;

    RequestReference->PdoExtension = PdoExtension;
}

/**
 * @brief Allocates QUEUED_REQUEST_REFERENCE for an SRB that is going to be processed.
 *
 * @param Srb
 * @param Irp
 * @return PQUEUED_REQUEST_REFERENCE RequestReference structure allocated, or NULL on failure.
 */
static
PQUEUED_REQUEST_REFERENCE
StorpSrbAllocateRequestReference(
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PIRP Irp,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    PQUEUED_REQUEST_REFERENCE RequestReference;

    RequestReference =
        ExAllocateFromNPagedLookasideList(&PdoExtension->FdoExtension->RequestReferenceLookaside);
    if (RequestReference == NULL)
    {
        return NULL;
    }

    StorpSrbInitRequestReference(RequestReference, Srb, Irp, PdoExtension);

    return RequestReference;
}

/**
 * @brief Takes the adapter reserve, if it is there and nobody else holds it.
 *
 * @return PQUEUED_REQUEST_REFERENCE The reserved reference, or NULL if unavailable.
 */
static
PQUEUED_REQUEST_REFERENCE
StorpSrbAcquireReservedRequestReference(
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PIRP Irp,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    PFDO_DEVICE_EXTENSION FdoExtension = PdoExtension->FdoExtension;
    PQUEUED_REQUEST_REFERENCE RequestReference;

    if (FdoExtension->ReservedRequestReference == NULL ||
        InterlockedCompareExchange(&FdoExtension->ReserveInUse, 1, 0) != 0)
    {
        return NULL;
    }

    RequestReference = FdoExtension->ReservedRequestReference;
    StorpSrbInitRequestReference(RequestReference, Srb, Irp, PdoExtension);
    RequestReference->FromReserve = TRUE;

    return RequestReference;
}

/**
 * @brief Frees an SRB's Request Reference and restore Srb->OriginalRequest field to IRP.
 * This function does not check if Srb->OriginalRequest is actually an request reference, and you
 * must determine it by other means.
 *
 * @param Srb
 */
VOID
StorpSrbFreeRequestReference(
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PQUEUED_REQUEST_REFERENCE RequestReference;
    PFDO_DEVICE_EXTENSION FdoExtension;

    RequestReference = (PQUEUED_REQUEST_REFERENCE)Srb->OriginalRequest;
    Srb->OriginalRequest = RequestReference->Irp;
    FdoExtension = RequestReference->PdoExtension->FdoExtension;

    if (RequestReference->FromReserve)
    {
        InterlockedExchange(&FdoExtension->ReserveInUse, 0);
    }
    else
    {
        ExFreeToNPagedLookasideList(&FdoExtension->RequestReferenceLookaside, RequestReference);
    }
}


/**
 * @brief Assigns a queue tag to a request if it stated it supports one.
 *
 * @param PdoExtension PDO Device extension
 * @param Srb SRB that represents this request
 * @return BOOLEAN Whether the request was assigned a tag at last.
 */
FORCEINLINE
BOOLEAN
StorpAssignTagToSrb(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb
)
{
    ULONG NewTag;

    /* Bail out if the request is untagged */
    if (!TEST_FLAG(Srb->SrbFlags, SRB_FLAGS_QUEUE_ACTION_ENABLE))
    {
        return FALSE;
    }

    /* FIXME: What if the counter overflows? */
    NewTag = InterlockedIncrement(&PdoExtension->TagCounter);

    /*
     * We use ULONG for tag counter, and here seems to do a stupid truncation by casting to UCHAR;
     * But since Storport has a default maximum 254 requests/LUN limitation, this is actually OK for
     * our use case. If a miniport needs to support more than 254 tags it must use
     * STORAGE_REQUEST_BLOCK which we don't support yet :D
     */
    Srb->QueueTag = (UCHAR)(NewTag % PdoExtension->OutstandingRequestMax);

    DPRINT("StorpAssignTagToSrb: Assigned Tag %x, TagCounter was %x\n", Srb->QueueTag, NewTag);

    return TRUE;
}


/**
 * @brief Arms the request's timeout and hands it to the miniport. DISPATCH_LEVEL.
 * The request is not touched after HwStartIo: the miniport may have completed it.
 */
static
VOID
PortHandRequestToMiniport(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PQUEUED_REQUEST_REFERENCE RequestReference)
{
    PVOID MiniportExtension = &FdoExtension->Miniport.MiniportExtension->HwDeviceExtension;
    PHW_INITIALIZATION_DATA HwInitData = FdoExtension->HwInitData;
    PSCSI_REQUEST_BLOCK Srb = RequestReference->Srb;
    ULONG Generation;

    /*
     * An SRB storport completed after a restart is in use again. Not before this point: until
     * now the packet may sit on the flow-control waiting lists, and a late completion of the
     * old command must still be recognised (and ignored) rather than claim the new packet.
     * From here on the packet is scheduled and counted, and HwBuildIo may complete it.
     */
    PortForgetSweptSrb(FdoExtension, Srb);

    /* BuildIo may complete the request itself, and then says so */
    if (HwInitData->HwBuildIo && !HwInitData->HwBuildIo(MiniportExtension, Srb))
        return;

    /*
     * From here on the request is the miniport's, and its timeout runs. A restart waits for
     * this HwStartIo to return before it stops the adapter (PortTimeoutStartIoReturned), so
     * a request it later completes itself was really handed over before the stop.
     */
    Generation = PortTimeoutArmRequest(FdoExtension, RequestReference);

#if DBG
    /* Fault knob for the timeout path (off unless the miniport's Parameters\DebugDropRequestEvery is set) */
    if (FdoExtension->DebugDropRequestEvery != 0 &&
        Srb->Function == SRB_FUNCTION_EXECUTE_SCSI &&
        StorpIsReadWriteCdb(Srb->Cdb[0]) &&
        ((ULONG)InterlockedIncrement(&FdoExtension->DebugDropCounter) % FdoExtension->DebugDropRequestEvery) == 0)
    {
        DPRINT1("storport: fault knob: Srb %p (cdb %02x) not handed to the miniport\n", Srb, Srb->Cdb[0]);
        PortTimeoutStartIoReturned(FdoExtension, Generation);
        return;
    }
#endif

    HwInitData->HwStartIo(MiniportExtension, Srb);

    PortTimeoutStartIoReturned(FdoExtension, Generation);
}


#if DBG
static
VOID
NTAPI
PortDebugDeferredStartDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    PQUEUED_REQUEST_REFERENCE RequestReference = (PQUEUED_REQUEST_REFERENCE)DeferredContext;
    PFDO_DEVICE_EXTENSION FdoExtension = RequestReference->PdoExtension->FdoExtension;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (FdoExtension->DebugDeferStopping)
    {
        /* The adapter is going away (PortStopTimeouts waits for us): never reached the
           miniport, so storport completes it */
        DPRINT1("storport: fault knob: held back Srb %p aborted, the adapter stops\n", RequestReference->Srb);
        if (PortClaimRequestCompletion(RequestReference))
        {
            RequestReference->Srb->SrbStatus = SRB_STATUS_ABORTED;
            InterlockedPushEntrySList(&FdoExtension->CompletionList, &RequestReference->CompletionEntry);
            KeInsertQueueDpc(&FdoExtension->Device->Dpc, NULL, NULL);
        }
    }
    else
    {
        DPRINT1("storport: fault knob: held back Srb %p goes to the miniport now (restarts %lu)\n",
                RequestReference->Srb, FdoExtension->AdapterRestarts);
        PortHandRequestToMiniport(FdoExtension, RequestReference);
    }

    /* Last: PortStopTimeouts may free the adapter once this drops to zero */
    InterlockedDecrement(&FdoExtension->DebugDeferredPending);
}
#endif


VOID
NTAPI
PortPdoAfterBuildingScatterGatherList(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PSCATTER_GATHER_LIST ScatterGatherList,
    _In_ PVOID Context)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PQUEUED_REQUEST_REFERENCE RequestReference;
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(Irp);

    RequestReference = (PQUEUED_REQUEST_REFERENCE)Context;
    FdoExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    /* BuildIo and StartIo are called on DISPATCH_LEVEL */
    OldIrql = KfRaiseIrql(DISPATCH_LEVEL);

    /*
     * Only an armed request (PortHandRequestToMiniport) can be completed by storport, and the
     * miniport has not seen this one, so nothing claims it while the HAL builds its list.
     * Should that ever change, the claimer completes the request: give the list back rather
     * than start I/O on it.
     */
    if (RequestReference->Completed)
    {
        DPRINT1("storport: Srb %p was completed while its scatter/gather list was built\n",
                RequestReference->Srb);
        if (ScatterGatherList)
        {
            FdoExtension->DmaAdapter->DmaOperations->
                PutScatterGatherList(FdoExtension->DmaAdapter, ScatterGatherList,
                                     RequestReference->WriteToDevice);
        }
        KeLowerIrql(OldIrql);
        return;
    }

    /* Save our SG List */
    RequestReference->ScatterGatherList = (PSTOR_SCATTER_GATHER_LIST)ScatterGatherList;

#if DBG
    /* Fault knob: hold the start back, as a HAL waiting for map registers would */
    if (FdoExtension->DebugDeferStartEvery != 0 &&
        RequestReference->Srb->Function == SRB_FUNCTION_EXECUTE_SCSI &&
        StorpIsReadWriteCdb(RequestReference->Srb->Cdb[0]) &&
        ((ULONG)InterlockedIncrement(&FdoExtension->DebugDeferCounter) % FdoExtension->DebugDeferStartEvery) == 0)
    {
        LARGE_INTEGER DueTime;

        DPRINT1("storport: fault knob: Srb %p (cdb %02x) held back for %lu s\n",
                RequestReference->Srb, RequestReference->Srb->Cdb[0], FdoExtension->DebugDeferStartSeconds);
        InterlockedIncrement(&FdoExtension->DebugDeferredPending);
        KeInitializeTimer(&RequestReference->DebugDeferTimer);
        KeInitializeDpc(&RequestReference->DebugDeferDpc, PortDebugDeferredStartDpc, RequestReference);
        DueTime.QuadPart = -10000000LL * FdoExtension->DebugDeferStartSeconds;
        KeSetTimer(&RequestReference->DebugDeferTimer, DueTime, &RequestReference->DebugDeferDpc);
        KeLowerIrql(OldIrql);
        return;
    }
#endif

    PortHandRequestToMiniport(FdoExtension, RequestReference);

    /* Restore IRQL */
    KeLowerIrql(OldIrql);
}


/**
 * @brief Parks a request that is out of memory, or fails it if there is no reserve to wait for.
 * Either way the IRP is no longer ours, hence STATUS_PENDING.
 */
static
NTSTATUS
PortPdoStarveRequest(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PIRP Irp)
{
    /* Without a reserve nothing guarantees a completion that would retry the request */
    if (FdoExtension->ReservedRequestReference == NULL)
    {
        Srb->InternalStatus = STATUS_INSUFFICIENT_RESOURCES;
        StorpCompleteRequest(Irp, SRB_STATUS_INTERNAL_ERROR, STATUS_INSUFFICIENT_RESOURCES);
    }
    else
    {
        PortQueueStarvedRequest(FdoExtension, Irp);
    }

    return STATUS_PENDING;
}

NTSTATUS
PortPdoSrbAllocatePrivateContexts(
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PQUEUED_REQUEST_REFERENCE RequestReference;
    ULONG SrbExtensionSize = FdoExtension->HwInitData->SrbExtensionSize;
    PIRP Irp;

    Irp = (PIRP)Srb->OriginalRequest;

    /* Allocate our private data area, falling back on the reserve when pool is exhausted */
    RequestReference = StorpSrbAllocateRequestReference(Srb, Irp, PdoExtension);
    if (RequestReference == NULL)
    {
        RequestReference = StorpSrbAcquireReservedRequestReference(Srb, Irp, PdoExtension);
        if (RequestReference == NULL)
        {
            return PortPdoStarveRequest(FdoExtension, Srb, Irp);
        }
    }

    /* Allocate SRB extension */
    if (SrbExtensionSize == 0)
    {
        Srb->SrbExtension = NULL;
        return STATUS_SUCCESS;
    }

    if (RequestReference->FromReserve)
    {
        Srb->SrbExtension = FdoExtension->ReservedSrbExtension;
        RtlZeroMemory(Srb->SrbExtension, SrbExtensionSize);
        return STATUS_SUCCESS;
    }

    Srb->SrbExtension = ExAllocatePoolWithTag(NonPagedPool,
                                              SrbExtensionSize,
                                              TAG_SRB_EXTENSION);
    if (Srb->SrbExtension == NULL)
    {
        StorpSrbFreeRequestReference(Srb);
        return PortPdoStarveRequest(FdoExtension, Srb, Irp);
    }

    return STATUS_SUCCESS;
}


/**
 * @brief TRUE for the SCSI read and write commands (data moved by DMA, never touched by a
 * miniport through Srb->DataBuffer).
 */
BOOLEAN
StorpIsReadWriteCdb(
    _In_ UCHAR OperationCode)
{
    switch (OperationCode)
    {
        case SCSIOP_READ6:
        case SCSIOP_WRITE6:
        case SCSIOP_READ:
        case SCSIOP_WRITE:
        case SCSIOP_READ12:
        case SCSIOP_WRITE12:
        case SCSIOP_READ16:
        case SCSIOP_WRITE16:
        case SCSIOP_WRITE_VERIFY:
        case SCSIOP_WRITE_VERIFY12:
        case SCSIOP_WRITE_VERIFY16:
            return TRUE;
        default:
            return FALSE;
    }
}


/**
 * @brief Whether the miniport's MapBuffers asks for a system address in Srb->DataBuffer:
 * STOR_MAP_ALL_BUFFERS and STOR_MAP_NON_READ_WRITE_BUFFERS (Windows treats the first as the
 * second) map every buffer except those of reads and writes.
 */
static
BOOLEAN
StorpNeedsSystemBuffer(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    switch (FdoExtension->Miniport.PortConfig.MapBuffers)
    {
        case STOR_MAP_ALL_BUFFERS:
        case STOR_MAP_NON_READ_WRITE_BUFFERS:
            return (Srb->Function != SRB_FUNCTION_EXECUTE_SCSI) ||
                   !StorpIsReadWriteCdb(Srb->Cdb[0]);
        default:
            return FALSE;
    }
}


/**
 * @brief Returns where in the MDL the SRB transfer starts: its data buffer when that lies
 * inside the MDL (a split request), else the start of the MDL.
 */
static
PVOID
StorpGetTransferVa(
    _In_ PMDL Mdl,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    ULONG_PTR Start = (ULONG_PTR)MmGetMdlVirtualAddress(Mdl);
    ULONG_PTR Buffer = (ULONG_PTR)Srb->DataBuffer;

    if (Buffer >= Start &&
        Buffer - Start <= MmGetMdlByteCount(Mdl) &&
        Srb->DataTransferLength <= MmGetMdlByteCount(Mdl) - (Buffer - Start))
    {
        return Srb->DataBuffer;
    }

    return (PVOID)Start;
}


NTSTATUS
PortPdoIssueRequest(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PQUEUED_REQUEST_REFERENCE RequestReference)
{
    PIRP Irp;
    NTSTATUS Status;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PHW_INITIALIZATION_DATA HwInitData;
    KIRQL OldIrql;

    Irp = RequestReference->Irp;
    FdoExtension = PdoExtension->FdoExtension;
    HwInitData = FdoExtension->Miniport.InitData;

    NT_ASSERT(HwInitData);

    /* Fill in SCSI address data */
    /* FIXME: Not sure if this is the best place for it. */
    RequestReference->Srb->PathId = PdoExtension->Bus;
    RequestReference->Srb->TargetId = PdoExtension->Target;
    RequestReference->Srb->Lun = PdoExtension->Lun;

    /* FIXME: Delete after debug */
    // PSCSI_REQUEST_BLOCK Srb = RequestReference->Srb;
    // if (Srb->Function == SRB_FUNCTION_EXECUTE_SCSI &&
    //     (Srb->Cdb[0] == SCSIOP_GET_EVENT_STATUS || Srb->Cdb[0] == SCSIOP_TEST_UNIT_READY))
    // {
    //     RequestReference->DumpSpecialRequest = TRUE;
    //     StorpDumpRequest(RequestReference);
    // }

    /* Its timeout is armed when it reaches the miniport (PortHandRequestToMiniport), not
       here: until then neither the miniport nor a restart can lose it */

    /* Start an DMA if IO subsystem allocated an MDL for us */
    /* FIXME: Does this strategy work? */
    if (RequestReference->Irp->MdlAddress)
    {
        PVOID TransferVa;
        PVOID SystemVa;

        /*
         * Lock the buffer so that it stays in physical memory.
         * In the two cases avoided here the memory has already been locked
         */
        if (!TEST_FLAG(Irp->MdlAddress->MdlFlags, MDL_SOURCE_IS_NONPAGED_POOL) &&
            !TEST_FLAG(Irp->MdlAddress->MdlFlags, MDL_MAPPED_TO_SYSTEM_VA) &&
            !TEST_FLAG(Irp->MdlAddress->MdlFlags, MDL_PAGES_LOCKED) &&
            !TEST_FLAG(Irp->MdlAddress->MdlFlags, MDL_PARTIAL))
        {
            RequestReference->MappedSystemVa = (PVOID)1; /* FIXME: CHANGE ITS NAME */
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoModifyAccess);
        }

        TransferVa = StorpGetTransferVa(RequestReference->Irp->MdlAddress, RequestReference->Srb);

        /* MapBuffers: the miniport reads this buffer through Srb->DataBuffer, which may be a
           user address of another process: give it the system address of the same bytes.
           A user address (a direct pass-through) is never handed to a miniport, except for a
           read or a write, whose data only moves by DMA through the scatter/gather list */
        if ((StorpNeedsSystemBuffer(FdoExtension, RequestReference->Srb) ||
             ((ULONG_PTR)RequestReference->Srb->DataBuffer <= (ULONG_PTR)MM_HIGHEST_USER_ADDRESS &&
              !(RequestReference->Srb->Function == SRB_FUNCTION_EXECUTE_SCSI &&
                StorpIsReadWriteCdb(RequestReference->Srb->Cdb[0])))) &&
            RequestReference->Srb->DataTransferLength != 0)
        {
            SystemVa = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
            if (SystemVa == NULL)
            {
                RequestReference->Srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
                RequestReference->Srb->InternalStatus = STATUS_INSUFFICIENT_RESOURCES;
                if (PortClaimRequestCompletion(RequestReference))
                {
                    InterlockedPushEntrySList(&FdoExtension->CompletionList, &RequestReference->CompletionEntry);
                    KeInsertQueueDpc(&FdoExtension->Device->Dpc, NULL, NULL);
                }
                return STATUS_PENDING;
            }

            RequestReference->OriginalDataBuffer = RequestReference->Srb->DataBuffer;
            RequestReference->DataBufferMapped = TRUE;
            RequestReference->Srb->DataBuffer =
                (PUCHAR)SystemVa + ((PUCHAR)TransferVa - (PUCHAR)MmGetMdlVirtualAddress(Irp->MdlAddress));
        }

        /* Following call requires DISPATCH_LEVEL. */
        OldIrql = KfRaiseIrql(DISPATCH_LEVEL);

        /* Make up the scatter gather list */
        /* FIXME: I don't know if we actually hit it */
        NT_ASSERT((RequestReference->Srb->SrbFlags & SRB_FLAGS_UNSPECIFIED_DIRECTION) !=
                  SRB_FLAGS_UNSPECIFIED_DIRECTION);
        RequestReference->WriteToDevice =
            TEST_FLAG(RequestReference->Srb->SrbFlags, SRB_FLAGS_DATA_OUT);

        Status = FdoExtension->DmaAdapter->DmaOperations->
            GetScatterGatherList(FdoExtension->DmaAdapter,
                                 FdoExtension->Device,
                                 RequestReference->Irp->MdlAddress,
                                 TransferVa,
                                 RequestReference->Srb->DataTransferLength,
                                 PortPdoAfterBuildingScatterGatherList,
                                 (PVOID)RequestReference,
                                 RequestReference->WriteToDevice);

        /* Restore IRQL */
        KeLowerIrql(OldIrql);

        /* No list, so the miniport never sees the request: fail it rather than let it hang */
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("GetScatterGatherList(0x%lx bytes) failed, Status 0x%08lx\n",
                    RequestReference->Srb->DataTransferLength, Status);
            RequestReference->Srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
            RequestReference->Srb->InternalStatus = Status;
            if (PortClaimRequestCompletion(RequestReference))
            {
                InterlockedPushEntrySList(&FdoExtension->CompletionList, &RequestReference->CompletionEntry);
                KeInsertQueueDpc(&FdoExtension->Device->Dpc, NULL, NULL);
            }
        }
    } else {
        /* Otherwise just start the IO with a NULL scatter gather list */
        PortPdoAfterBuildingScatterGatherList(FdoExtension->Device,
                                              RequestReference->Irp,
                                              NULL,
                                              RequestReference);
    }

    /* FIXME: Is this correct? */
    Status = STATUS_PENDING;

    return Status;
}


VOID
PortPdoScheduleRequestNoFlowControl(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PQUEUED_REQUEST_REFERENCE RequestReference)
{
    /* Ensure outstanding flag is unset */
    RequestReference->IsOutstanding = FALSE;
}


/**
 * @brief Schedules an outstanding request and return a boolean value to indicate if the request can
 * be immediately issued.
 *
 * @param PdoExtension PDO device extension.
 * @param FdoExtension FDO device extension.
 * @param RequestReference RequestReference must be allocated beforehand.
 * @return BOOLEAN When TRUE, you can call PortPdoIssueRequest to issue request right away;
 *                 When FALSE, the request is already queued in flow control structures and you can
 *                   safely go on without further processing, it will be issued upon completions.
 */
BOOLEAN
PortPdoScheduleRequestFlowControlled(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PQUEUED_REQUEST_REFERENCE RequestReference)
{
    PPDO_IO_FLOW_CONTROL FlowControl = &PdoExtension->FlowControl;
    KLOCK_QUEUE_HANDLE LockHandle;
    PSCSI_REQUEST_BLOCK Srb = RequestReference->Srb;
    BOOLEAN StrongOrderedRequest = FALSE;
    BOOLEAN IssueRequest = TRUE;

    /* Set outstanding flag */
    RequestReference->IsOutstanding = TRUE;

    /* Check if we can issue this request. */
    /* Acquire the HBA global flow control lock first */
    KeAcquireInStackQueuedSpinLock(&FdoExtension->FlowControl.Lock, &LockHandle);
    StorpCheckFlowControl(FdoExtension);

    do
    {
        /* Check PDO flow control conditions */

        /* Sanity check */
        NT_ASSERT(FlowControl->OutstandingRequestCount <= PdoExtension->OutstandingRequestMax);

        /* If PDO is not suitable to receive a request, make it wait */
        if (FlowControl->IsBusy || FlowControl->IsPaused ||
            (FlowControl->IsFrozen && !TEST_FLAG(Srb->SrbFlags, SRB_FLAGS_BYPASS_FROZEN_QUEUE)) ||
            (FlowControl->IsLocked && !TEST_FLAG(Srb->SrbFlags, SRB_FLAGS_BYPASS_LOCKED_QUEUE)) ||
            FlowControl->StrongOrderedCount ||
            FlowControl->OutstandingRequestCount == PdoExtension->OutstandingRequestMax ||
            (!IsListEmpty(&FlowControl->AwaitingRequestsListHead)))
        {
            InsertHeadList(&FlowControl->AwaitingRequestsListHead,
                           &RequestReference->PdoEntry);
            IssueRequest = FALSE;
            break;
        }

        /* Check if this request is strong-ordered */
        if (!TEST_FLAG(Srb->SrbFlags, SRB_FLAGS_QUEUE_ACTION_ENABLE) ||
            (Srb->QueueAction == SRB_ORDERED_QUEUE_TAG_REQUEST))
        {
            RequestReference->StrongOrdered = TRUE;
            StrongOrderedRequest = TRUE;
            ++FlowControl->StrongOrderedCount;
        }

        /*
        * If this request is strong ordered and the LUN's active/approved list is not
        * drained, the request must wait.
        */
        if (StrongOrderedRequest && !IsListEmpty(&FlowControl->ActiveRequestsListHead))
        {
            InsertHeadList(&FlowControl->AwaitingRequestsListHead,
                           &RequestReference->PdoEntry);
            IssueRequest = FALSE;
            break;
        }

        /*
        * If any break's triggered before this point, the request is in PDO waiting queue.
        * Going past this point meant PDO approves this request. Put it into active list.
        */
        if (Srb->QueueAction == SRB_HEAD_OF_QUEUE_TAG_REQUEST)
        {
            InsertTailList(&FlowControl->ActiveRequestsListHead,
                           &RequestReference->PdoEntry);
        } else {
            InsertHeadList(&FlowControl->ActiveRequestsListHead,
                           &RequestReference->PdoEntry);
        }

        /* A new outstanding request is added to this LUN */
        ++FlowControl->OutstandingRequestCount;

        /* Check FDO flow control status. */

        /* If the FDO can't handle more requests, then the request should be queued. */
        if (FlowControl->IsBusy || FlowControl->IsPaused ||
            FlowControl->OutstandingRequestCount == FdoExtension->OutstandingRequestMax)
        {
            /* Put into FDO queue */
            InsertHeadList(&FdoExtension->FlowControl.FdoBlockedRequestsListHead,
                           &RequestReference->FdoEntry);

            /*
            * Now the request is in PDO active list, in FDO awaiting queue, not issued.
            * Let it wait until another completion event schedules it.
            */
            break;
        }

        /* Seems good, increment FDO request count */
        ++FdoExtension->FlowControl.OutstandingRequestCount;

        /*
        * Now the request is counted in FDO & PDO, and is put into PDO active list,
        * next step we're going to issue it.
        */
    } while (0);

    // FIXME: The port driver indicates that an LU-specific queue has been frozen by
    // returning a request with SRB_STATUS_QUEUE_FROZEN in the SrbStatus member. New
    // requests from the class driver can be inserted into the queue, but only autosense
    // requests are sent to the logical unit as long as its queue is frozen.
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/storage-class-driver-s-releasequeue-routine

    /* We've determined where the request goes. Release the flow control lock */
    StorpCheckFlowControl(FdoExtension);
    KeReleaseInStackQueuedSpinLock(&LockHandle);

    return IssueRequest;
}


NTSTATUS
NTAPI
PortPdoScsi(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    NTSTATUS Status;
    PIO_STACK_LOCATION Stack;
    PSCSI_REQUEST_BLOCK Srb;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PMINIPORT Miniport;
    PHW_INITIALIZATION_DATA HwInitData;

    DPRINT("PortPdoScsi(%p %p)\n", DeviceObject, Irp);

    Stack = IoGetCurrentIrpStackLocation(Irp);
    Srb = Stack->Parameters.Scsi.Srb;

    if (Srb == NULL) {
        DPRINT1("Srb is NULL!");
        DbgBreakPoint();
        Status = STATUS_UNSUCCESSFUL;

        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = Status;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Status;
    }

    PdoExtension = (PPDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    NT_ASSERT(PdoExtension);
    FdoExtension = PdoExtension->FdoExtension;
    NT_ASSERT(FdoExtension);
    Miniport = &FdoExtension->Miniport;
    HwInitData = Miniport->InitData;

    switch (Srb->Function) {
        /* Both of these should be sent to device and let themselves process this */
        case SRB_FUNCTION_IO_CONTROL:
        case SRB_FUNCTION_EXECUTE_SCSI:
        {
            PQUEUED_REQUEST_REFERENCE RequestReference;
            BOOLEAN IssueRequest;

            /* Mark IRP as pending */
            IoMarkIrpPending(Irp);

            /* Allocate private contexts */
            Status = PortPdoSrbAllocatePrivateContexts(Srb, PdoExtension, FdoExtension);
            if (Status != STATUS_SUCCESS)
            {
                break;
            }
            RequestReference = (PQUEUED_REQUEST_REFERENCE)Srb->OriginalRequest;

            /* Assign a tag to the SRB if it supports tagging */
            StorpAssignTagToSrb(PdoExtension, Srb);

            DPRINT("New request (%d:%d:%d) ReqRef %p Srb %p Irp %p Tag %x SrbExt %p(%d)\n",
                    Srb->PathId, Srb->TargetId, Srb->Lun,
                    RequestReference, Srb, Irp, Srb->QueueTag,
                    Srb->SrbExtension, HwInitData->SrbExtensionSize);

            /*
             * Do the scheduling. If returns TRUE, we should issue this request to the hardware.
             * Otherwise it will keep waiting until next completion schedules it, or be cancelled on
             * an error, etc.
             */
            IssueRequest = PortPdoScheduleRequestFlowControlled(PdoExtension,
                                                                FdoExtension,
                                                                RequestReference);

            /* This request is viable to be issued. */
            if (IssueRequest)
            {
                Status = PortPdoIssueRequest(PdoExtension, RequestReference);
            } else {
                Status = STATUS_PENDING;
            }

            break;
        }

        /*
         * These requests are actually sent to adapters and are not outstanding requests for devices
         * so we simply pass them down to miniport
         */
        case SRB_FUNCTION_FLUSH:
        case SRB_FUNCTION_SHUTDOWN:
        {
            PQUEUED_REQUEST_REFERENCE RequestReference;

            /* Mark IRP as pending */
            IoMarkIrpPending(Irp);

            /* Allocate private contexts */
            Status = PortPdoSrbAllocatePrivateContexts(Srb, PdoExtension, FdoExtension);
            if (Status != STATUS_SUCCESS)
            {
                break;
            }
            RequestReference = (PQUEUED_REQUEST_REFERENCE)Srb->OriginalRequest;

            /*
             * Call the non-flow-controlled scheduling function (it does nothing but the model is
             * preserved for consistency)
             */
            PortPdoScheduleRequestNoFlowControl(FdoExtension, RequestReference);

            /* Fire up the request immediately */
            PortPdoIssueRequest(PdoExtension, RequestReference);

            break;
        }

        case SRB_FUNCTION_CLAIM_DEVICE:
        {
            if (InterlockedCompareExchange(&PdoExtension->IsClaimed, 1, 0))
            {
                Status = STATUS_DEVICE_BUSY;
                StorpCompleteRequest(Irp, SRB_STATUS_BUSY, Status);
                break;
            }

            /* The claimed device object is handed back to the class driver here */
            Srb->DataBuffer = PdoExtension->Device;
            Status = STATUS_SUCCESS;
            StorpCompleteRequest(Irp, SRB_STATUS_SUCCESS, Status);
            break;
        }

        case SRB_FUNCTION_RELEASE_DEVICE:
        {
            InterlockedExchange(&PdoExtension->IsClaimed, 0);

            Status = STATUS_SUCCESS;
            StorpCompleteRequest(Irp, SRB_STATUS_SUCCESS, Status);
            break;
        }

        default:
            DPRINT1("Unsupported Srb Function %02X!", Srb->Function);
            // DbgBreakPoint();
            Status = STATUS_NOT_IMPLEMENTED;
            StorpCompleteRequest(Irp, SRB_STATUS_INVALID_REQUEST, Status);
            break;
    }

    return Status;
}


static
VOID
PortScheduleComingRequestsOnCompletion(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PLIST_ENTRY Entry;
    PQUEUED_REQUEST_REFERENCE RequestReference;

    /* Sanity check again whether FDO has resource to handle the request */
    NT_ASSERT(FdoExtension->FlowControl.OutstandingRequestCount <
              FdoExtension->OutstandingRequestMax);

    /* If FDO has waiting requests, issue one. */
    if (!IsListEmpty(&FdoExtension->FlowControl.FdoBlockedRequestsListHead))
    {
        /* Sanity check */
        NT_ASSERT(FdoExtension->FlowControl.OutstandingRequestCount <
                  FdoExtension->OutstandingRequestMax);

        /* Take it out of FDO list */
        Entry = RemoveTailList(&FdoExtension->FlowControl.FdoBlockedRequestsListHead);
        RequestReference = CONTAINING_RECORD(Entry, QUEUED_REQUEST_REFERENCE, FdoEntry);

        /* Increment FDO request counter */
        ++FdoExtension->FlowControl.OutstandingRequestCount;
        NT_ASSERT(FdoExtension->FlowControl.OutstandingRequestCount <=
                  FdoExtension->OutstandingRequestMax);

        /* Call the start routine */
        PortPdoIssueRequest(PdoExtension, RequestReference);

        /* Our task is done */
        return;
    }

    /* FDO's got no request, check the PDO of the just-finished request for awaiting requests */
    if (!IsListEmpty(&PdoExtension->FlowControl.AwaitingRequestsListHead))
    {
        /* Sanity check */
        NT_ASSERT(PdoExtension->FlowControl.OutstandingRequestCount <
                  PdoExtension->OutstandingRequestMax);

        /* Take one request */
        Entry = RemoveTailList(&PdoExtension->FlowControl.AwaitingRequestsListHead);
        RequestReference = CONTAINING_RECORD(Entry, QUEUED_REQUEST_REFERENCE, PdoEntry);

        /* This one goes to active list */
        InsertHeadList(&PdoExtension->FlowControl.ActiveRequestsListHead, Entry);

        /* Increment PDO request counter */
        ++PdoExtension->FlowControl.OutstandingRequestCount;
        NT_ASSERT(PdoExtension->FlowControl.OutstandingRequestCount <=
                  PdoExtension->OutstandingRequestMax);

        /* FIXME: should be false. Allocate resource if it is determined required */
        if (RequestReference->Srb->SrbExtension == NULL)
        {
            __debugbreak();
        }

        /* Call the start routine */
        PortPdoIssueRequest(PdoExtension, RequestReference);

        /* Our task is done */
        return;
    }
}


static
VOID
PortCompleteRequest(
    _In_ PQUEUED_REQUEST_REFERENCE RequestReference)
{
    PSCSI_REQUEST_BLOCK Srb;
    PIRP Irp;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    KLOCK_QUEUE_HANDLE LockHandle;
    NTSTATUS IoStatus;
    BOOLEAN FromReserve;
#if DBG
    BOOLEAN Swept = RequestReference->Swept;
#endif

    /* Take out our information */
    Srb = RequestReference->Srb;
    Irp = RequestReference->Irp;
    PdoExtension = RequestReference->PdoExtension;
    FdoExtension = PdoExtension->FdoExtension;

    /* The reference is released further down, so remember this while it is still valid */
    FromReserve = RequestReference->FromReserve;

    /* FIXME: DELETE AFTER DEBUG */
    // if (RequestReference->DumpSpecialRequest)
    // {
    //     StorpDumpRequestResponse(RequestReference);
    // }

    DPRINT("Completing request: (%d:%d:%d) ReqRef %p Srb %p Irp %p Tag %x\n",
            Srb->PathId, Srb->TargetId, Srb->Lun, RequestReference, Srb, RequestReference->Irp, Srb->QueueTag);

    /* Its timeout no longer runs */
    PortTimeoutDisarmRequest(FdoExtension, RequestReference);

    /* The class driver gets its own buffer address back */
    if (RequestReference->DataBufferMapped)
    {
        Srb->DataBuffer = RequestReference->OriginalDataBuffer;
        RequestReference->DataBufferMapped = FALSE;
    }

    /* Return SG list resources back to system */
    if (RequestReference->ScatterGatherList)
    {
        FdoExtension->DmaAdapter->DmaOperations->
            PutScatterGatherList(FdoExtension->DmaAdapter,
                                 (PSCATTER_GATHER_LIST)RequestReference->ScatterGatherList,
                                 RequestReference->WriteToDevice);
        RequestReference->ScatterGatherList = NULL;

    }

    /* Unlock the pages locked for DMA, also when no list could be built for them */
    if (RequestReference->MappedSystemVa)
    {
        MmUnlockPages(RequestReference->Irp->MdlAddress);
        RequestReference->MappedSystemVa = NULL;
    }

    /* Check if we need to interact with flow control. */
    if (RequestReference->IsOutstanding)
    {
        /* Take the request out of FDO and PDO structures, and update flow control data */
        KeAcquireInStackQueuedSpinLock(&FdoExtension->FlowControl.Lock, &LockHandle);
        StorpCheckFlowControl(FdoExtension);

        FdoExtension->FlowControl.OutstandingRequestCount--;
        if (FdoExtension->FlowControl.RemainingBusyRequests)
        {
            --FdoExtension->FlowControl.RemainingBusyRequests;

            /* Clear busy state as needed */
            if (FdoExtension->FlowControl.OutstandingRequestCount == 0 ||
                FdoExtension->FlowControl.RemainingBusyRequests == 0)
            {
                FdoExtension->FlowControl.IsBusy = FALSE;
            }
        }

        RemoveEntryList(&RequestReference->PdoEntry);
        --PdoExtension->FlowControl.OutstandingRequestCount;
        if (PdoExtension->FlowControl.RemainingBusyRequests)
        {
            --PdoExtension->FlowControl.RemainingBusyRequests;

            /* Clear busy state as needed */
            if (PdoExtension->FlowControl.OutstandingRequestCount == 0 ||
                PdoExtension->FlowControl.RemainingBusyRequests == 0)
            {
                PdoExtension->FlowControl.IsBusy = FALSE;
            }
        }

        /* Decrement strong ordered request count if needed */
        if (RequestReference->StrongOrdered)
        {
            --PdoExtension->FlowControl.StrongOrderedCount;
        }

        /* Free the private data structure. No one should use it anymore */
        StorpSrbFreeRequestReference(Srb);
        RequestReference = NULL;

        /* Schedule next IO before we release flow control lock */
        PortScheduleComingRequestsOnCompletion(PdoExtension, FdoExtension);

        /* We're done, release flow control lock */
        StorpCheckFlowControl(FdoExtension);
        KeReleaseInStackQueuedSpinLock(&LockHandle);

    }
    else
    {
        /* Adapter requests (flush, shutdown): no flow control, but the packet goes back and
           the class driver gets its IRP in Srb->OriginalRequest all the same */
        StorpSrbFreeRequestReference(Srb);
        RequestReference = NULL;
    }

    /*
     * Free SRB extension as this request will never go back to miniport again. Must free it before
     * IoCompleteRequest because class driver's completion routine may issue another request. If we
     * free it after IoCompleteRequest we may zero out the newly-issued SRB's extension, since one
     * single SRB can be reused between requests, and the SRB issued in completion routine could be
     * the same one we operating here.
     */
    if (Srb->SrbExtension)
    {
        /* The reserved one is handed back along with its packet, not freed */
        if (!FromReserve)
        {
            ExFreePoolWithTag(Srb->SrbExtension, TAG_SRB_EXTENSION);
        }
        Srb->SrbExtension = NULL;
    }

    /*
     * After done with internal accountings, we can finally complete this IO.
     *
     * We must not complete the IO before scheduling next IO, because at that point the flow control
     * lock is still held, and class driver's completion routine may issue another request. This
     * will cause a recursive lock acquisition in PDO SCSI handler and lead to bugcheck.
     */
    switch (SRB_STATUS(Srb->SrbStatus))
    {
        case SRB_STATUS_SUCCESS:
            IoStatus = STATUS_SUCCESS;
            break;

        case SRB_STATUS_BUSY:
            IoStatus = STATUS_DEVICE_BUSY;
            break;

        case SRB_STATUS_TIMEOUT:
        case SRB_STATUS_COMMAND_TIMEOUT:
            IoStatus = STATUS_IO_TIMEOUT;
            break;

        default:
            IoStatus = STATUS_UNSUCCESSFUL; // FIXME:
            break;
    }
    Irp->IoStatus.Status = IoStatus;
    Irp->IoStatus.Information = Srb->DataTransferLength; /* FIXME: hopefully this is correct */

#if DBG
    /* Fault knob: the packet is gone and Srb->OriginalRequest is the IRP again; the class
       driver has not seen the SRB back, so it is not issued again yet */
    if (Swept && FdoExtension->DebugLateCompletion != 0)
    {
        DPRINT1("storport: fault knob: late miniport completion of swept Srb %p (OriginalRequest %p is the IRP)\n",
                Srb, Srb->OriginalRequest);
        StorPortNotification(RequestComplete,
                             &FdoExtension->Miniport.MiniportExtension->HwDeviceExtension,
                             Srb);
    }
#endif

    /* We just gave memory back, so let one request that ran out of it through */
    PortRetryStarvedRequest(FdoExtension);

    DPRINT("Calling IoCompleteRequest\n");
    IoCompleteRequest(Irp, IO_DISK_INCREMENT);
}


VOID
NTAPI
PortCompletionDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID Context,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    PQUEUED_REQUEST_REFERENCE RequestReference;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PSLIST_ENTRY Entry;
    PSLIST_ENTRY Next;
    ULONG Count = 0;

    DPRINT("PortCompletionDpc(%p %p %p %p)\n", Dpc, Context, SystemArgument1, SystemArgument2);

    /* Take context pointer as FDO extension */
    FdoExtension = (PFDO_DEVICE_EXTENSION)Context;

    /* Flush all entries in the list and complete all requests */
    Entry = InterlockedFlushSList(&FdoExtension->CompletionList);
    while (Entry)
    {
        /* Prepare Next pointer first (Completion routine will free the memory that contains it) */
        Next = Entry->Next;

        /* Get original request */
        RequestReference = CONTAINING_RECORD(Entry, QUEUED_REQUEST_REFERENCE, CompletionEntry);

        /* Call real completion routine */
        PortCompleteRequest(RequestReference);

        /* Move on to next one */
        Entry = Next;
        ++Count;
    }

    DPRINT("Completed %d requests\n", Count);
}


/* EOF */
