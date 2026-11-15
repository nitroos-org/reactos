/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS NDIS library
 * FILE:        ndis/protocol.c
 * PURPOSE:     Routines used by NDIS protocol drivers
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 *              Vizzini (vizzini@plasmic.com)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 *   09-13-2003 Vizzini Updates for SendPackets support
 */

#include "ndissys.h"

#define SERVICES_KEY L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
#define LINKAGE_KEY  L"\\Linkage"
#define PARAMETERS_KEY L"\\Parameters\\"

LIST_ENTRY ProtocolListHead;
KSPIN_LOCK ProtocolListLock;

#define WORKER_TEST 0

typedef struct _DMA_CONTEXT {
    PLOGICAL_ADAPTER Adapter;
    PNDIS_PACKET Packet;
} DMA_CONTEXT, *PDMA_CONTEXT;

PNET_PNP_EVENT
ProSetupPnPEvent(
    NET_PNP_EVENT_CODE EventCode,
    PVOID              EventBuffer,
    ULONG              EventBufferLength)
{
    PNET_PNP_EVENT PnPEvent;

    PnPEvent = ExAllocatePool(PagedPool, sizeof(NET_PNP_EVENT));
    if (!PnPEvent) {
        NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources\n"));
        return NULL;
    }

    RtlZeroMemory(PnPEvent, sizeof(NET_PNP_EVENT));

    PnPEvent->NetEvent = EventCode;

    if (EventBuffer != NULL)
    {
        PnPEvent->Buffer = ExAllocatePool(PagedPool, EventBufferLength);
        if (!PnPEvent->Buffer)
        {
            NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources\n"));
            ExFreePool(PnPEvent);
            return NULL;
        }

        PnPEvent->BufferLength = EventBufferLength;

        RtlCopyMemory(PnPEvent->Buffer, EventBuffer, PnPEvent->BufferLength);
    }

    return PnPEvent;
}

NDIS_STATUS
ProSendAndFreePnPEvent(
   PLOGICAL_ADAPTER Adapter,
   PNET_PNP_EVENT   PnPEvent,
   PIRP             Irp)
{
  PLIST_ENTRY CurrentEntry;
  NDIS_STATUS Status;
  PADAPTER_BINDING AdapterBinding;

  CurrentEntry = Adapter->ProtocolListHead.Flink;

  while (CurrentEntry != &Adapter->ProtocolListHead)
  {
     AdapterBinding = CONTAINING_RECORD(CurrentEntry, ADAPTER_BINDING, AdapterListEntry);

     Status = (*AdapterBinding->ProtocolBinding->Chars.PnPEventHandler)(
      AdapterBinding->NdisOpenBlock.ProtocolBindingContext,
      PnPEvent);

     if (Status == NDIS_STATUS_PENDING)
     {
         IoMarkIrpPending(Irp);
         /* Yes, I know this is stupid */
         PnPEvent->NdisReserved[0] = (ULONG_PTR)Irp;
         PnPEvent->NdisReserved[1] = (ULONG_PTR)CurrentEntry->Flink;
         return NDIS_STATUS_PENDING;
     }
     else if (Status != NDIS_STATUS_SUCCESS)
     {
         if (PnPEvent->Buffer) ExFreePool(PnPEvent->Buffer);
         ExFreePool(PnPEvent);
         return Status;
     }

     CurrentEntry = CurrentEntry->Flink;
  }

  if (PnPEvent->Buffer) ExFreePool(PnPEvent->Buffer);
  ExFreePool(PnPEvent);

  return NDIS_STATUS_SUCCESS;
}

NTSTATUS
NTAPI
NdisIPwrSetPower(
    IN PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
  PLOGICAL_ADAPTER Adapter = (PLOGICAL_ADAPTER)DeviceObject->DeviceExtension;
  PNET_PNP_EVENT PnPEvent;
  PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

  ASSERT(Stack->Parameters.Power.Type == DevicePowerState);

  PnPEvent = ProSetupPnPEvent(NetEventSetPower, &Stack->Parameters.Power.State, sizeof(NDIS_DEVICE_POWER_STATE));
  if (!PnPEvent) {
      NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources\n"));
      return NDIS_STATUS_RESOURCES;
  }

  return ProSendAndFreePnPEvent(Adapter, PnPEvent, Irp);
}

NTSTATUS
NTAPI
NdisIPwrQueryPower(
    IN PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
  PLOGICAL_ADAPTER Adapter = (PLOGICAL_ADAPTER)DeviceObject->DeviceExtension;
  PNET_PNP_EVENT PnPEvent;
  PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

  ASSERT(Stack->Parameters.Power.Type == DevicePowerState);

  PnPEvent = ProSetupPnPEvent(NetEventQueryPower, &Stack->Parameters.Power.State, sizeof(NDIS_DEVICE_POWER_STATE));
  if (!PnPEvent) {
      NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources\n"));
      return NDIS_STATUS_RESOURCES;
  }

  return ProSendAndFreePnPEvent(Adapter, PnPEvent, Irp);
}


NTSTATUS
NTAPI
NdisIPnPQueryStopDevice(
    IN PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
  PLOGICAL_ADAPTER Adapter = (PLOGICAL_ADAPTER)DeviceObject->DeviceExtension;
  PNET_PNP_EVENT PnPEvent;

  PnPEvent = ProSetupPnPEvent(NetEventQueryRemoveDevice, NULL, 0);
  if (!PnPEvent) {
      NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources\n"));
      return NDIS_STATUS_RESOURCES;
  }

  return ProSendAndFreePnPEvent(Adapter, PnPEvent, Irp);
}

NTSTATUS
NTAPI
NdisIPnPCancelStopDevice(
    IN PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
  PLOGICAL_ADAPTER Adapter = (PLOGICAL_ADAPTER)DeviceObject->DeviceExtension;
  PNET_PNP_EVENT PnPEvent;

  PnPEvent = ProSetupPnPEvent(NetEventCancelRemoveDevice, NULL, 0);
  if (!PnPEvent) {
      NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources\n"));
      return NDIS_STATUS_RESOURCES;
  }

  return ProSendAndFreePnPEvent(Adapter, PnPEvent, Irp);
}

/*
 * @implemented
 */
VOID
EXPORT
NdisCompleteBindAdapter(
    IN  NDIS_HANDLE BindAdapterContext,
    IN  NDIS_STATUS Status,
    IN  NDIS_STATUS OpenStatus)
/*
 * FUNCTION: Indicates a packet to bound protocols
 * ARGUMENTS:
 *     Adapter = Pointer to logical adapter
 *     Packet  = Pointer to packet to indicate
 * RETURNS:
 *     Status of operation
 * NOTES:
 *     - FIXME: partially-implemented
 */
{
  PROTOCOL_BINDING *Protocol = (PROTOCOL_BINDING *)BindAdapterContext;

  if (!NT_SUCCESS(Status)) {
      NDIS_DbgPrint(MIN_TRACE, ("Binding failed (%x)\n", Status));
      return;
  }

  /* Put protocol binding struct on global list */
  ExInterlockedInsertTailList(&ProtocolListHead, &Protocol->ListEntry, &ProtocolListLock);
}

/*
 * @implemented
 */
VOID
EXPORT
NdisCompleteUnbindAdapter(
    IN  NDIS_HANDLE UnbindAdapterContext,
    IN  NDIS_STATUS Status)
/*
 * FUNCTION: Completes an unbind that the protocol's UnbindAdapterHandler pended
 * ARGUMENTS:
 *     UnbindAdapterContext = The UnbindContext NDIS gave the handler (see ProUnbindAdapter)
 *     Status               = Status of the unbind
 */
{
  PNDIS_UNBIND_CONTEXT Context = (PNDIS_UNBIND_CONTEXT)UnbindAdapterContext;

  if (!NT_SUCCESS(Status))
      NDIS_DbgPrint(MIN_TRACE, ("Unbinding failed (%x)\n", Status));

  /* ProUnbindAdapter waits for this */
  Context->Status = Status;
  KeSetEvent(&Context->Event, IO_NO_INCREMENT, FALSE);
}

/*
 * Drops a reference on the binding. The binding is open with one reference (held until
 * NdisCloseAdapter) and takes one more per send or request in flight; the last reference
 * dropped frees it, whether that is NdisCloseAdapter or a completion that came in after it.
 */
VOID
ProLeaveBinding(
    PADAPTER_BINDING AdapterBinding)
{
    if (InterlockedDecrement(&AdapterBinding->Outstanding) == 0)
    {
        /* NdisCloseAdapter has unlinked it from both lists by now */
        ExFreePool(AdapterBinding);
    }
}

/*
 * A send, request, data transfer or reset of the binding starts: it takes a reference until it is done (ProLeaveBinding),
 * so that the binding is not freed under it. FALSE when it must fail at once (NdisCloseAdapter runs,
 * or the adapter is going away); the reference is taken then too, and its caller drops it as usual.
 */
static
BOOLEAN
ProEnterBinding(
    PADAPTER_BINDING AdapterBinding)
{
    /* Counted before the checks: NdisCloseAdapter sets Closing before it drops the open reference */
    InterlockedIncrement(&AdapterBinding->Outstanding);
    return !AdapterBinding->Closing && !AdapterBinding->Adapter->Removing;
}

static
NDIS_STATUS
ProBindingStatus(
    PADAPTER_BINDING AdapterBinding)
{
    return AdapterBinding->Closing ? NDIS_STATUS_CLOSING : NDIS_STATUS_ADAPTER_REMOVED;
}

NDIS_STATUS
ProIndicatePacket(
    PLOGICAL_ADAPTER Adapter,
    PNDIS_PACKET Packet)
/*
 * FUNCTION: Indicates a packet to bound protocols
 * ARGUMENTS:
 *     Adapter = Pointer to logical adapter
 *     Packet  = Pointer to packet to indicate
 * RETURNS:
 *     STATUS_SUCCESS in all cases
 * NOTES:
 *     - XXX ATM, this only handles loopback packets - is that its designed function?
 */
{
  UINT BufferedLength;
  UINT PacketLength;
  KIRQL OldIrql;
  PUCHAR LookaheadBuffer;

  NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

#if DBG
  MiniDisplayPacket(Packet, "INDICATE");
#endif

  NdisQueryPacket(Packet, NULL, NULL, NULL, &PacketLength);

  LookaheadBuffer = ExAllocatePool(NonPagedPool, PacketLength);
  if (!LookaheadBuffer) {
      NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources\n"));
      return NDIS_STATUS_RESOURCES;
  }

  NDIS_DbgPrint(MAX_TRACE, ("acquiring miniport block lock\n"));
  KeAcquireSpinLock(&Adapter->NdisMiniportBlock.Lock, &OldIrql);
    {
      BufferedLength = CopyPacketToBuffer(LookaheadBuffer, Packet, 0, PacketLength);
      Adapter->NdisMiniportBlock.IndicatedPacket[KeGetCurrentProcessorNumber()] = Packet;
    }
  KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);

  if (BufferedLength > Adapter->MediumHeaderSize)
    {
      /* XXX Change this to call SendPackets so we don't have to duplicate this wacky logic */
      MiniIndicateData(Adapter, NULL, LookaheadBuffer, Adapter->MediumHeaderSize,
          &LookaheadBuffer[Adapter->MediumHeaderSize], BufferedLength - Adapter->MediumHeaderSize,
          PacketLength - Adapter->MediumHeaderSize);
    }
  else
    {
      MiniIndicateData(Adapter, NULL, LookaheadBuffer, Adapter->MediumHeaderSize, NULL, 0, 0);
    }

  ExFreePool(LookaheadBuffer);

  KeAcquireSpinLock(&Adapter->NdisMiniportBlock.Lock, &OldIrql);
    {
      Adapter->NdisMiniportBlock.IndicatedPacket[KeGetCurrentProcessorNumber()] = NULL;
    }
  KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);

  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS NTAPI
ProRequest(
    IN  NDIS_HANDLE     MacBindingHandle,
    IN  PNDIS_REQUEST   NdisRequest)
/*
 * FUNCTION: Forwards a request to an NDIS miniport
 * ARGUMENTS:
 *     MacBindingHandle = Adapter binding handle
 *     NdisRequest      = Pointer to request to perform
 * RETURNS:
 *     Status of operation
 */
{
  PADAPTER_BINDING AdapterBinding;
  PLOGICAL_ADAPTER Adapter;
  PNDIS_REQUEST_MAC_BLOCK MacBlock = (PNDIS_REQUEST_MAC_BLOCK)NdisRequest->MacReserved;
  NDIS_STATUS Status;

  NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

  ASSERT(MacBindingHandle);
  AdapterBinding = GET_ADAPTER_BINDING(MacBindingHandle);

  ASSERT(AdapterBinding->Adapter);
  Adapter = AdapterBinding->Adapter;

  MacBlock->Binding = &AdapterBinding->NdisOpenBlock;

  /* Done when it is completed to the protocol (MiniCompleteRequest), or returned here */
  if (!ProEnterBinding(AdapterBinding))
  {
      ProLeaveBinding(AdapterBinding);
      return ProBindingStatus(AdapterBinding);
  }

  /* A serialized miniport that is being halted takes no request, see MiniStopSends */
  if (!(Adapter->NdisMiniportBlock.Flags & NDIS_ATTRIBUTE_DESERIALIZE) && Adapter->Stopping)
  {
      ProLeaveBinding(AdapterBinding);
      return NDIS_STATUS_FAILURE;
  }

#if WORKER_TEST
  MiniQueueWorkItem(Adapter, NdisWorkItemRequest, NdisRequest, FALSE);
  return NDIS_STATUS_PENDING;
#else
  Status = MiniStartRequest(Adapter, NdisRequest);
  if (Status != NDIS_STATUS_PENDING)
      ProLeaveBinding(AdapterBinding);
  return Status;
#endif
}


NDIS_STATUS NTAPI
ProReset(
    IN  NDIS_HANDLE MacBindingHandle)
/*
 * FUNCTION: Resets the adapter for a protocol
 * RETURNS:
 *     The status of a reset done at once, or NDIS_STATUS_PENDING: the protocol's ResetCompleteHandler
 *     is called when a reset of the adapter ends (MiniResetComplete, MiniFailReset), and the binding
 *     holds a reference until then (MiniEndResetWaits), so that NdisCloseAdapter does not free it under
 *     that completion
 */
{
    PADAPTER_BINDING AdapterBinding = GET_ADAPTER_BINDING(MacBindingHandle);
    PLOGICAL_ADAPTER Adapter = AdapterBinding->Adapter;
    NDIS_STATUS Status;
    KIRQL OldIrql;
    BOOLEAN KeepReference = FALSE, DropResetReference = FALSE;

    /* FIXME: Wait for all packets to be sent */

    if (!ProEnterBinding(AdapterBinding))
    {
        ProLeaveBinding(AdapterBinding);
        return ProBindingStatus(AdapterBinding);
    }

    /* One reset of a binding at a time: the one that pends holds the reference */
    KeAcquireSpinLock(&Adapter->NdisMiniportBlock.Lock, &OldIrql);
    if (AdapterBinding->ResetPending)
    {
        KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);
        ProLeaveBinding(AdapterBinding);
        return NDIS_STATUS_RESET_IN_PROGRESS;
    }
    AdapterBinding->ResetPending = TRUE;
    InsertTailList(&Adapter->ResetWaiters, &AdapterBinding->ResetEntry);
    KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);

    /* This call's own reference: the end of another reset (MiniEndResetWaits) may drain the entry above and
       drop the reset's reference while MiniReset runs, and an NdisCloseAdapter of the binding then frees it */
    InterlockedIncrement(&AdapterBinding->Outstanding);

    Status = MiniReset(Adapter);

    KeAcquireSpinLock(&Adapter->NdisMiniportBlock.Lock, &OldIrql);
    if (Status == NDIS_STATUS_PENDING)
    {
        /* The entry was drained before the miniport took this reset (the end of an earlier one), and this one
           is still going: put the binding back on the list, with this call's reference as the reset's */
        if (!AdapterBinding->ResetPending && !AdapterBinding->Closing &&
            Adapter->NdisMiniportBlock.ResetStatus == NDIS_STATUS_PENDING)
        {
            AdapterBinding->ResetPending = TRUE;
            InsertTailList(&Adapter->ResetWaiters, &AdapterBinding->ResetEntry);
            KeepReference = TRUE;
        }
    }
    else if (AdapterBinding->ResetPending)
    {
        /* Done at once. The end of another reset may have dropped the reset's reference already */
        AdapterBinding->ResetPending = FALSE;
        RemoveEntryList(&AdapterBinding->ResetEntry);
        DropResetReference = TRUE;
    }
    KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);

    if (DropResetReference)
        ProLeaveBinding(AdapterBinding);
    if (!KeepReference)
        ProLeaveBinding(AdapterBinding);

    return Status;
}

VOID NTAPI
ScatterGatherSendPacket(
   IN PDEVICE_OBJECT DeviceObject,
   IN PIRP Irp,
   IN PSCATTER_GATHER_LIST ScatterGather,
   IN PVOID Context)
{
   PDMA_CONTEXT DmaContext = Context;
   PLOGICAL_ADAPTER Adapter = DmaContext->Adapter;
   PNDIS_PACKET Packet = DmaContext->Packet;
   NDIS_STATUS Status;

   NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

   NDIS_PER_PACKET_INFO_FROM_PACKET(Packet,
                                    ScatterGatherListPacketInfo) = ScatterGather;

   Status = proSendPacketToMiniport(Adapter, Packet);

   if (Status != NDIS_STATUS_PENDING) {
       NDIS_DbgPrint(MAX_TRACE, ("Completing packet.\n"));
       MiniSendComplete(Adapter,
                        Packet,
                        Status);
   }

   ExFreePool(DmaContext);
}

NDIS_STATUS
proSendPacketToMiniport(PLOGICAL_ADAPTER Adapter, PNDIS_PACKET Packet)
{
#if WORKER_TEST
   MiniQueueWorkItem(Adapter, NdisWorkItemSend, Packet, FALSE);
   return NDIS_STATUS_PENDING;
#else
   KIRQL RaiseOldIrql, SerialOldIrql;
   NDIS_STATUS NdisStatus;
   BOOLEAN Serialized = !(Adapter->NdisMiniportBlock.Flags & NDIS_ATTRIBUTE_DESERIALIZE);

   NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

   if (Serialized)
   {
      /* Queued behind the call that runs the miniport, see MiniEnterSerialized.
         The one that runs it must not be preempted, the interrupt DPC waits for it */
      KeRaiseIrql(DISPATCH_LEVEL, &SerialOldIrql);
      NdisStatus = MiniEnterSerialized(Adapter, Packet);
      if (NdisStatus != NDIS_STATUS_SUCCESS)
      {
         KeLowerIrql(SerialOldIrql);
         return NdisStatus;
      }
   }
   else if(MiniIsBusy(Adapter, NdisWorkItemSend)) {
      NDIS_DbgPrint(MID_TRACE, ("Busy: NdisWorkItemSend.\n"));

      MiniQueueWorkItem(Adapter, NdisWorkItemSend, Packet, FALSE);
      return NDIS_STATUS_PENDING;
   }

#if DBG
   MiniDisplayPacket(Packet, "SEND");
#endif

   if(Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.SendPacketsHandler)
   {
        if(Adapter->NdisMiniportBlock.Flags & NDIS_ATTRIBUTE_DESERIALIZE)
        {
            NDIS_DbgPrint(MAX_TRACE, ("Calling miniport's SendPackets handler\n"));
            (*Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.SendPacketsHandler)(
             Adapter->NdisMiniportBlock.MiniportAdapterContext, &Packet, 1);
             NdisStatus = NDIS_STATUS_PENDING;
        } else {
            /* SendPackets is called at DISPATCH_LEVEL for all serialized miniports */
            KeRaiseIrql(DISPATCH_LEVEL, &RaiseOldIrql);
            {
               NDIS_DbgPrint(MAX_TRACE, ("Calling miniport's SendPackets handler\n"));
               (*Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.SendPacketsHandler)(
                Adapter->NdisMiniportBlock.MiniportAdapterContext, &Packet, 1);
            }
            KeLowerIrql(RaiseOldIrql);

            NdisStatus = NDIS_GET_PACKET_STATUS(Packet);
            if (NdisStatus == NDIS_STATUS_RESOURCES) {
                MiniQueueWorkItem(Adapter, NdisWorkItemSend, Packet, TRUE);
                NdisStatus = NDIS_STATUS_PENDING;
            }
            MiniLeaveSerialized(Adapter, MiniLeaveSender);
            KeLowerIrql(SerialOldIrql);
        }

        if (NdisStatus != NDIS_STATUS_PENDING) {
            MiniWorkItemComplete(Adapter, NdisWorkItemSend);
        }

        return NdisStatus;
   } else {
        if(Adapter->NdisMiniportBlock.Flags & NDIS_ATTRIBUTE_DESERIALIZE)
        {
            NDIS_DbgPrint(MAX_TRACE, ("Calling miniport's Send handler\n"));
            NdisStatus = (*Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.SendHandler)(
                          Adapter->NdisMiniportBlock.MiniportAdapterContext, Packet, Packet->Private.Flags);
            NDIS_DbgPrint(MAX_TRACE, ("back from miniport's send handler\n"));
        } else {
            /* Send is called at DISPATCH_LEVEL for all serialized miniports */
            KeRaiseIrql(DISPATCH_LEVEL, &RaiseOldIrql);
            NDIS_DbgPrint(MAX_TRACE, ("Calling miniport's Send handler\n"));
            NdisStatus = (*Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.SendHandler)(
                          Adapter->NdisMiniportBlock.MiniportAdapterContext, Packet, Packet->Private.Flags);
            NDIS_DbgPrint(MAX_TRACE, ("back from miniport's send handler\n"));
            KeLowerIrql(RaiseOldIrql);

            if (NdisStatus == NDIS_STATUS_RESOURCES) {
                MiniQueueWorkItem(Adapter, NdisWorkItemSend, Packet, TRUE);
                NdisStatus = NDIS_STATUS_PENDING;
            }
            MiniLeaveSerialized(Adapter, MiniLeaveSender);
            KeLowerIrql(SerialOldIrql);
        }

        if (NdisStatus != NDIS_STATUS_PENDING) {
            MiniWorkItemComplete(Adapter, NdisWorkItemSend);
        }

        return NdisStatus;
   }
#endif
}

static
NDIS_STATUS
ProSendToAdapter(
    IN  NDIS_HANDLE     MacBindingHandle,
    IN  PNDIS_PACKET    Packet)
/*
 * FUNCTION: Forwards a request to send a packet to an NDIS miniport
 * ARGUMENTS:
 *     MacBindingHandle = Adapter binding handle
 *     Packet           = Pointer to NDIS packet descriptor
 * RETURNS:
 *     NDIS_STATUS_SUCCESS if the packet was successfully sent
 *     NDIS_STATUS_PENDING if the miniport was busy or a serialized miniport returned NDIS_STATUS_RESOURCES
 */
{
  PADAPTER_BINDING AdapterBinding;
  PLOGICAL_ADAPTER Adapter;
  PNDIS_BUFFER NdisBuffer;
  PDMA_CONTEXT Context;
  NDIS_STATUS NdisStatus;
  UINT PacketLength;
  KIRQL OldIrql;

  NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

  ASSERT(MacBindingHandle);
  AdapterBinding = GET_ADAPTER_BINDING(MacBindingHandle);

  ASSERT(AdapterBinding);
  Adapter = AdapterBinding->Adapter;

  ASSERT(Adapter);

  /* if the following is not true, KeRaiseIrql() below will break */
  ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

  /* XXX what is this crazy black magic? */
  Packet->Reserved[1] = (ULONG_PTR)MacBindingHandle;

  /*
   * Test the packet to see if it is a MAC loopback.
   *
   * We may have to loop this packet if miniport cannot.
   * If dest MAC address of packet == MAC address of adapter,
   * this is a loopback frame.
   */

  if ((Adapter->NdisMiniportBlock.MacOptions & NDIS_MAC_OPTION_NO_LOOPBACK) &&
      MiniAdapterHasAddress(Adapter, Packet))
    {
#if WORKER_TEST
        MiniQueueWorkItem(Adapter, NdisWorkItemSendLoopback, Packet, FALSE);
        return NDIS_STATUS_PENDING;
#else
        return ProIndicatePacket(Adapter, Packet);
#endif
    } else {
        if (Adapter->NdisMiniportBlock.ScatterGatherListSize != 0)
        {
            NDIS_DbgPrint(MID_TRACE, ("Using Scatter/Gather DMA\n"));

            NdisQueryPacket(Packet,
                            NULL,
                            NULL,
                            &NdisBuffer,
                            &PacketLength);

            Context = ExAllocatePool(NonPagedPool, sizeof(DMA_CONTEXT));
            if (!Context) {
                NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources\n"));
                return NDIS_STATUS_RESOURCES;
            }

            Context->Adapter = Adapter;
            Context->Packet = Packet;

            KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

            KeFlushIoBuffers(NdisBuffer, FALSE, TRUE);

            NdisStatus = Adapter->NdisMiniportBlock.SystemAdapterObject->DmaOperations->GetScatterGatherList(
                          Adapter->NdisMiniportBlock.SystemAdapterObject,
                          Adapter->NdisMiniportBlock.PhysicalDeviceObject,
                          NdisBuffer,
                          MmGetMdlVirtualAddress(NdisBuffer),
                          PacketLength,
                          ScatterGatherSendPacket,
                          Context,
                          TRUE);

            KeLowerIrql(OldIrql);

            if (!NT_SUCCESS(NdisStatus)) {
                NDIS_DbgPrint(MIN_TRACE, ("GetScatterGatherList failed! (%x)\n", NdisStatus));
                return NdisStatus;
            }

            return NDIS_STATUS_PENDING;
        }


        return proSendPacketToMiniport(Adapter, Packet);
    }
}

NDIS_STATUS NTAPI
ProSend(
    IN  NDIS_HANDLE     MacBindingHandle,
    IN  PNDIS_PACKET    Packet)
/*
 * FUNCTION: Forwards a request to send a packet to an NDIS miniport
 * RETURNS:
 *     The status of a send done at once, or NDIS_STATUS_PENDING: MiniSendComplete completes it
 */
{
    PADAPTER_BINDING AdapterBinding = GET_ADAPTER_BINDING(MacBindingHandle);
    NDIS_STATUS NdisStatus;

    /* Done when it is completed to the protocol (MiniSendComplete), or returned here */
    if (!ProEnterBinding(AdapterBinding))
    {
        ProLeaveBinding(AdapterBinding);
        return ProBindingStatus(AdapterBinding);
    }

    NdisStatus = ProSendToAdapter(MacBindingHandle, Packet);
    if (NdisStatus != NDIS_STATUS_PENDING)
        ProLeaveBinding(AdapterBinding);
    return NdisStatus;
}

VOID NTAPI
ProSendPackets(
    IN  NDIS_HANDLE     NdisBindingHandle,
    IN  PPNDIS_PACKET   PacketArray,
    IN  UINT            NumberOfPackets)
{
    PADAPTER_BINDING AdapterBinding = NdisBindingHandle;
    PLOGICAL_ADAPTER Adapter = AdapterBinding->Adapter;
    KIRQL RaiseOldIrql;
    NDIS_STATUS NdisStatus;
    UINT i;
    BOOLEAN Fail = FALSE;

    /* Each packet is done when MiniSendComplete completes it to the protocol, which finds the
       binding in the packet as for ProSend */
    for (i = 0; i < NumberOfPackets; i++)
    {
        PacketArray[i]->Reserved[1] = (ULONG_PTR)AdapterBinding;
        if (!ProEnterBinding(AdapterBinding))
            Fail = TRUE;
    }
    if (Fail)
    {
        for (i = 0; i < NumberOfPackets; i++)
            MiniSendComplete(Adapter, PacketArray[i], ProBindingStatus(AdapterBinding));
        return;
    }

    /* A serialized miniport takes one send at a time, see MiniEnterSerialized */
    if (!(Adapter->NdisMiniportBlock.Flags & NDIS_ATTRIBUTE_DESERIALIZE))
    {
        for (i = 0; i < NumberOfPackets; i++)
        {
            NdisStatus = proSendPacketToMiniport(Adapter, PacketArray[i]);
            if (NdisStatus != NDIS_STATUS_PENDING)
                MiniSendComplete(Adapter, PacketArray[i], NdisStatus);
        }
        return;
    }

    if(Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.SendPacketsHandler)
    {
       if(Adapter->NdisMiniportBlock.Flags & NDIS_ATTRIBUTE_DESERIALIZE)
       {
          (*Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.SendPacketsHandler)(
           Adapter->NdisMiniportBlock.MiniportAdapterContext, PacketArray, NumberOfPackets);
       }
       else
       {
          /* SendPackets is called at DISPATCH_LEVEL for all serialized miniports */
          KeRaiseIrql(DISPATCH_LEVEL, &RaiseOldIrql);
          (*Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.SendPacketsHandler)(
           Adapter->NdisMiniportBlock.MiniportAdapterContext, PacketArray, NumberOfPackets);
          KeLowerIrql(RaiseOldIrql);
          for (i = 0; i < NumberOfPackets; i++)
          {
             NdisStatus = NDIS_GET_PACKET_STATUS(PacketArray[i]);
             if (NdisStatus != NDIS_STATUS_PENDING)
                 MiniSendComplete(Adapter, PacketArray[i], NdisStatus);
          }
       }
     }
     else
     {
       if(Adapter->NdisMiniportBlock.Flags & NDIS_ATTRIBUTE_DESERIALIZE)
       {
          for (i = 0; i < NumberOfPackets; i++)
          {
             NdisStatus = (*Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.SendHandler)(
                           Adapter->NdisMiniportBlock.MiniportAdapterContext, PacketArray[i], PacketArray[i]->Private.Flags);
             if (NdisStatus != NDIS_STATUS_PENDING)
                 MiniSendComplete(Adapter, PacketArray[i], NdisStatus);
          }
       }
       else
       {
         /* Send is called at DISPATCH_LEVEL for all serialized miniports */
         KeRaiseIrql(DISPATCH_LEVEL, &RaiseOldIrql);
         for (i = 0; i < NumberOfPackets; i++)
         {
            NdisStatus = (*Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.SendHandler)(
                           Adapter->NdisMiniportBlock.MiniportAdapterContext, PacketArray[i], PacketArray[i]->Private.Flags);
            if (NdisStatus != NDIS_STATUS_PENDING)
                MiniSendComplete(Adapter, PacketArray[i], NdisStatus);
         }
         KeLowerIrql(RaiseOldIrql);
       }
     }
}

NDIS_STATUS NTAPI
ProTransferData(
    IN  NDIS_HANDLE         MacBindingHandle,
    IN  NDIS_HANDLE         MacReceiveContext,
    IN  UINT                ByteOffset,
    IN  UINT                BytesToTransfer,
    IN  OUT PNDIS_PACKET    Packet,
    OUT PUINT               BytesTransferred)
/*
 * FUNCTION: Forwards a request to copy received data into a protocol-supplied packet
 * ARGUMENTS:
 *     MacBindingHandle  = Adapter binding handle
 *     MacReceiveContext = MAC receive context
 *     ByteOffset        = Offset in packet to place data
 *     BytesToTransfer   = Number of bytes to copy into packet
 *     Packet            = Pointer to NDIS packet descriptor
 *     BytesTransferred  = Address of buffer to place number of bytes copied
 */
{
    PADAPTER_BINDING AdapterBinding = GET_ADAPTER_BINDING(MacBindingHandle);
    PLOGICAL_ADAPTER Adapter        = AdapterBinding->Adapter;
    PPENDING_TRANSFER Transfer;
    NDIS_STATUS Status;
    KIRQL OldIrql;

    NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

    /* FIXME: Interrupts must be disabled for adapter */
    /* XXX sd - why is that true? */

    if (Adapter->NdisMiniportBlock.IndicatedPacket[KeGetCurrentProcessorNumber()]) {
	NDIS_DbgPrint(MAX_TRACE, ("LoopPacket\n"));
        /* NDIS is responsible for looping this packet */
        NdisCopyFromPacketToPacket(Packet,
                                   ByteOffset + Adapter->MediumHeaderSize,
                                   BytesToTransfer + Adapter->MediumHeaderSize,
                                   Adapter->NdisMiniportBlock.IndicatedPacket[KeGetCurrentProcessorNumber()],
                                   0,
                                   BytesTransferred);
        return NDIS_STATUS_SUCCESS;
    }

    ASSERT(Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.TransferDataHandler);

    /* Done when it is completed to the protocol (MiniTransferDataComplete or the halt, which find it on the
       adapter's list), or returned here */
    if (!ProEnterBinding(AdapterBinding))
    {
        ProLeaveBinding(AdapterBinding);
        return ProBindingStatus(AdapterBinding);
    }

    Transfer = ExAllocatePool(NonPagedPool, sizeof(*Transfer));
    if (!Transfer)
    {
        ProLeaveBinding(AdapterBinding);
        return NDIS_STATUS_RESOURCES;
    }
    Transfer->Packet = Packet;
    Transfer->AdapterBinding = AdapterBinding;
    Transfer->InHandler = TRUE;
    Transfer->FailAtReturn = FALSE;
    Transfer->Completed = FALSE;

    /* A miniport that is halted completes nothing: the transfer would wait for good (the halt fails the pending ones once) */
    KeAcquireSpinLock(&Adapter->TransferLock, &OldIrql);
    if (Adapter->TransfersClosed)
    {
        KeReleaseSpinLock(&Adapter->TransferLock, OldIrql);
        ExFreePool(Transfer);
        ProLeaveBinding(AdapterBinding);
        return NDIS_STATUS_ADAPTER_REMOVED;
    }
    InsertTailList(&Adapter->TransferList, &Transfer->ListEntry);
    KeReleaseSpinLock(&Adapter->TransferLock, OldIrql);

    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

    Status = (*Adapter->NdisMiniportBlock.DriverHandle->MiniportCharacteristics.TransferDataHandler)(
        Packet,
        BytesTransferred,
        Adapter->NdisMiniportBlock.MiniportAdapterContext,
        MacReceiveContext,
        ByteOffset,
        BytesToTransfer);

    KeLowerIrql(OldIrql);

    KeAcquireSpinLock(&Adapter->TransferLock, &OldIrql);
    if (Transfer->Completed)
    {
        /* The miniport completed it from inside the handler: that dropped the reference, and told the protocol */
        KeReleaseSpinLock(&Adapter->TransferLock, OldIrql);
        ExFreePool(Transfer);
        return Status;
    }
    if (Status == NDIS_STATUS_PENDING && !Transfer->FailAtReturn)
    {
        /* From here the miniport or the halt completes it */
        Transfer->InHandler = FALSE;
        KeReleaseSpinLock(&Adapter->TransferLock, OldIrql);
        return Status;
    }
    RemoveEntryList(&Transfer->ListEntry);
    KeReleaseSpinLock(&Adapter->TransferLock, OldIrql);
    ExFreePool(Transfer);
    ProLeaveBinding(AdapterBinding);

    /* Done at once, or pended and then failed by the halt before the handler returned */
    return (Status == NDIS_STATUS_PENDING) ? NDIS_STATUS_ADAPTER_REMOVED : Status;
}



/*
 * @implemented
 */
VOID
EXPORT
NdisCloseAdapter(
    OUT PNDIS_STATUS    Status,
    IN  NDIS_HANDLE     NdisBindingHandle)
/*
 * FUNCTION: Closes an adapter opened with NdisOpenAdapter
 * ARGUMENTS:
 *     Status            = Address of buffer for status information
 *     NdisBindingHandle = Handle returned by NdisOpenAdapter
 */
{
    PADAPTER_BINDING AdapterBinding = GET_ADAPTER_BINDING(NdisBindingHandle);
    PLOGICAL_ADAPTER Adapter = AdapterBinding->Adapter;
    LARGE_INTEGER Delay;
    ULONG Waited;
    KIRQL OldIrql;

    NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

    /* Called at PASSIVE_LEVEL, by the protocol's UnbindAdapterHandler too (ProUnbindAdapter holds no lock then) */
    PAGED_CODE();

    /* The binding takes no new send or request; the ones queued for the miniport fail now */
    InterlockedExchange(&AdapterBinding->Closing, TRUE);
    MiniFailBindingWork(Adapter, AdapterBinding);

    /* Wait, but not forever, for the sends, requests, transfers and resets in the miniport to complete, so that the
       protocol can free the context they complete to once this returns. The adapter is halted before
       this runs on a remove or stop, so the miniport has completed them (its halt does); the wait is
       the margin for one still on another processor. A miniport that never completes a send (surprise
       removal of hardware that only completes on halt) must not hang the PnP thread: after the wait the
       binding is unlinked and its open reference dropped, and the late completion frees it (ProLeaveBinding)
       instead of this. */
    Delay.QuadPart = -10000; /* 1 ms */
    for (Waited = 0; AdapterBinding->Outstanding != 1 && Waited < 2000; Waited++)
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);

    if (AdapterBinding->Outstanding != 1)
        NDIS_DbgPrint(MIN_TRACE, ("%wZ: %ld sends/requests/transfers/resets of the binding to %wZ did not complete; freeing the binding when they do\n",
                                  &AdapterBinding->ProtocolBinding->Chars.Name, AdapterBinding->Outstanding - 1,
                                  &Adapter->NdisMiniportBlock.MiniportName));

    /* Remove from protocol's bound adapters list */
    ExInterlockedRemoveEntryList(&AdapterBinding->ProtocolListEntry, &AdapterBinding->ProtocolBinding->Lock);

    /* Remove protocol from adapter's bound protocols list. The receive and status indications walk
       it under the miniport lock: none is in the protocol for this binding afterwards */
    KeAcquireSpinLock(&Adapter->NdisMiniportBlock.Lock, &OldIrql);
    RemoveEntryList(&AdapterBinding->AdapterListEntry);
    KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);

    /* Drop the open reference; if nothing is still in flight this frees the binding now, otherwise the
       last completion frees it (it is off both lists already) */
    ProLeaveBinding(AdapterBinding);

    *Status = NDIS_STATUS_SUCCESS;
}

/* The binding is still on the adapter's list (the pointer is only compared) */
static
BOOLEAN
ProAdapterHasBinding(
    PLOGICAL_ADAPTER Adapter,
    PADAPTER_BINDING AdapterBinding)
{
    PLIST_ENTRY CurrentEntry;
    BOOLEAN Found = FALSE;
    KIRQL OldIrql;

    KeAcquireSpinLock(&Adapter->NdisMiniportBlock.Lock, &OldIrql);
    for (CurrentEntry = Adapter->ProtocolListHead.Flink;
         CurrentEntry != &Adapter->ProtocolListHead;
         CurrentEntry = CurrentEntry->Flink)
    {
        if (CurrentEntry == &AdapterBinding->AdapterListEntry)
        {
            Found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);

    return Found;
}

/*
 * FUNCTION: Unbinds every protocol from an adapter that is stopped or removed, as Windows does:
 *           each protocol's UnbindAdapterHandler closes its binding (NdisCloseAdapter), and may
 *           pend and finish with NdisCompleteUnbindAdapter
 * NOTES:
 *     - Called at PASSIVE_LEVEL, before the miniport is halted, after MiniStartRemoving: the
 *       adapter is off the adapter list, so nothing binds to it again, and its sends and
 *       requests fail, so no protocol waits for the miniport here
 *     - A binding the protocol did not close is closed here: the adapter goes away regardless
 */
VOID
ProUnbindAdapter(
    PLOGICAL_ADAPTER Adapter)
{
    PADAPTER_BINDING AdapterBinding;
    PPROTOCOL_BINDING Protocol;
    NDIS_UNBIND_CONTEXT UnbindContext;
    NDIS_STATUS Status;
    KIRQL OldIrql;

    PAGED_CODE();

    for (;;)
    {
        KeAcquireSpinLock(&Adapter->NdisMiniportBlock.Lock, &OldIrql);
        if (IsListEmpty(&Adapter->ProtocolListHead))
        {
            KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);
            break;
        }
        AdapterBinding = CONTAINING_RECORD(Adapter->ProtocolListHead.Flink, ADAPTER_BINDING, AdapterListEntry);
        KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);

        Protocol = AdapterBinding->ProtocolBinding;
        NDIS_DbgPrint(MID_TRACE, ("Unbinding %wZ from %wZ\n", &Protocol->Chars.Name, &Adapter->NdisMiniportBlock.MiniportName));

        Status = NDIS_STATUS_NOT_SUPPORTED;
        if (Protocol->Chars.UnbindAdapterHandler)
        {
            KeInitializeEvent(&UnbindContext.Event, NotificationEvent, FALSE);
            UnbindContext.Status = NDIS_STATUS_SUCCESS;
            Status = NDIS_STATUS_SUCCESS;

            (*Protocol->Chars.UnbindAdapterHandler)(&Status,
                                                    AdapterBinding->NdisOpenBlock.ProtocolBindingContext,
                                                    &UnbindContext);
            if (Status == NDIS_STATUS_PENDING)
            {
                KeWaitForSingleObject(&UnbindContext.Event, Executive, KernelMode, FALSE, NULL);
                Status = UnbindContext.Status;
            }
        }

        if (ProAdapterHasBinding(Adapter, AdapterBinding))
        {
            NDIS_DbgPrint(MIN_TRACE, ("%wZ did not close its binding to %wZ (0x%x), closing it\n",
                                      &Protocol->Chars.Name, &Adapter->NdisMiniportBlock.MiniportName, Status));
            NdisCloseAdapter(&Status, AdapterBinding);
        }
    }
}


/*
 * @implemented
 */
VOID
EXPORT
NdisDeregisterProtocol(
    OUT PNDIS_STATUS    Status,
    IN NDIS_HANDLE      NdisProtocolHandle)
/*
 * FUNCTION: Releases the resources allocated by NdisRegisterProtocol
 * ARGUMENTS:
 *     Status             = Address of buffer for status information
 *     NdisProtocolHandle = Handle returned by NdisRegisterProtocol
 */
{
    PPROTOCOL_BINDING Protocol = GET_PROTOCOL_BINDING(NdisProtocolHandle);

    NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

    /* FIXME: Make sure no adapter bindings exist */

    /* Remove protocol from global list */
    ExInterlockedRemoveEntryList(&Protocol->ListEntry, &ProtocolListLock);

    ExFreePool(Protocol);

    *Status = NDIS_STATUS_SUCCESS;
}


/*
 * @implemented
 */
VOID
EXPORT
NdisOpenAdapter(
    OUT PNDIS_STATUS    Status,
    OUT PNDIS_STATUS    OpenErrorStatus,
    OUT PNDIS_HANDLE    NdisBindingHandle,
    OUT PUINT           SelectedMediumIndex,
    IN  PNDIS_MEDIUM    MediumArray,
    IN  UINT            MediumArraySize,
    IN  NDIS_HANDLE     NdisProtocolHandle,
    IN  NDIS_HANDLE     ProtocolBindingContext,
    IN  PNDIS_STRING    AdapterName,
    IN  UINT            OpenOptions,
    IN  PSTRING         AddressingInformation   OPTIONAL)
/*
 * FUNCTION: Opens an adapter for communication
 * ARGUMENTS:
 *     Status                 = Address of buffer for status information
 *     OpenErrorStatus        = Address of buffer for secondary error code
 *     NdisBindingHandle      = Address of buffer for adapter binding handle
 *     SelectedMediumIndex    = Address of buffer for selected medium
 *     MediumArray            = Pointer to an array of NDIS_MEDIUMs called can support
 *     MediumArraySize        = Number of elements in MediumArray
 *     NdisProtocolHandle     = Handle returned by NdisRegisterProtocol
 *     ProtocolBindingContext = Pointer to caller supplied context area
 *     AdapterName            = Pointer to buffer with name of adapter
 *     OpenOptions            = Bitmask with flags passed to next-lower driver
 *     AddressingInformation  = Optional pointer to buffer with NIC specific information
 */
{
  UINT i;
  BOOLEAN Found;
  PLOGICAL_ADAPTER Adapter;
  PADAPTER_BINDING AdapterBinding;
  PPROTOCOL_BINDING Protocol = GET_PROTOCOL_BINDING(NdisProtocolHandle);
  KIRQL OldIrql;

  NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

  if(!NdisProtocolHandle)
    {
      NDIS_DbgPrint(MIN_TRACE, ("NdisProtocolHandle is NULL\n"));
      *OpenErrorStatus = *Status = NDIS_STATUS_FAILURE;
      return;
    }

  Adapter = MiniLocateDevice(AdapterName);
  if (!Adapter)
    {
      NDIS_DbgPrint(MIN_TRACE, ("Adapter not found.\n"));
      *Status = NDIS_STATUS_ADAPTER_NOT_FOUND;
      return;
    }

  /* Find the media type in the list provided by the protocol driver */
  Found = FALSE;
  for (i = 0; i < MediumArraySize; i++)
    {
      if (Adapter->NdisMiniportBlock.MediaType == MediumArray[i])
        {
          *SelectedMediumIndex = i;
          Found = TRUE;
          break;
        }
    }

  if (!Found)
    {
      NDIS_DbgPrint(MIN_TRACE, ("Medium is not supported.\n"));
      *Status = NDIS_STATUS_UNSUPPORTED_MEDIA;
      return;
    }

  /* Now that we have confirmed that the adapter can be opened, create a binding */

  AdapterBinding = ExAllocatePool(NonPagedPool, sizeof(ADAPTER_BINDING));
  if (!AdapterBinding)
    {
      NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
      *Status = NDIS_STATUS_RESOURCES;
      return;
    }

  RtlZeroMemory(AdapterBinding, sizeof(ADAPTER_BINDING));

  /* The open holds one reference, dropped by NdisCloseAdapter (see ProLeaveBinding) */
  AdapterBinding->Outstanding            = 1;
  AdapterBinding->ProtocolBinding        = Protocol;
  AdapterBinding->Adapter                = Adapter;
  AdapterBinding->NdisOpenBlock.ProtocolBindingContext = ProtocolBindingContext;

  /* Set fields required by some NDIS macros */
  AdapterBinding->NdisOpenBlock.BindingHandle = (NDIS_HANDLE)AdapterBinding;

  /* Set handlers (some NDIS macros require these) */

  AdapterBinding->NdisOpenBlock.RequestHandler      = ProRequest;
  AdapterBinding->NdisOpenBlock.ResetHandler        = ProReset;
  AdapterBinding->NdisOpenBlock.SendHandler         = ProSend;
  AdapterBinding->NdisOpenBlock.SendPacketsHandler  = ProSendPackets;
  AdapterBinding->NdisOpenBlock.TransferDataHandler = ProTransferData;

  AdapterBinding->NdisOpenBlock.RequestCompleteHandler =
    Protocol->Chars.RequestCompleteHandler;

  /* On the protocol's bound-adapters list first, so that once the binding is on the adapter's list
     below (where ProUnbindAdapter and NdisCloseAdapter find it) its ProtocolListEntry is already valid */
  ExInterlockedInsertTailList(&Protocol->AdapterListHead, &AdapterBinding->ProtocolListEntry, &Protocol->Lock);

  /* Put protocol on adapter's bound protocols list, unless the adapter is being removed: the check and
     the insertion are one critical section, so a bind cannot race a remove and leave a binding on an
     adapter that ProUnbindAdapter has already walked (the original use-after-free) */
  NDIS_DbgPrint(MAX_TRACE, ("acquiring miniport block lock\n"));
  KeAcquireSpinLock(&Adapter->NdisMiniportBlock.Lock, &OldIrql);
  if (Adapter->Removing)
  {
      KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);
      NDIS_DbgPrint(MIN_TRACE, ("Adapter %wZ is being removed\n", &Adapter->NdisMiniportBlock.MiniportName));
      ExInterlockedRemoveEntryList(&AdapterBinding->ProtocolListEntry, &Protocol->Lock);
      ExFreePool(AdapterBinding);
      *Status = NDIS_STATUS_ADAPTER_REMOVED;
      return;
  }
  InsertTailList(&Adapter->ProtocolListHead, &AdapterBinding->AdapterListEntry);
  KeReleaseSpinLock(&Adapter->NdisMiniportBlock.Lock, OldIrql);

  *NdisBindingHandle = (NDIS_HANDLE)AdapterBinding;

  *Status = NDIS_STATUS_SUCCESS;
}

PADAPTER_BINDING
NTAPI
LocateAdapterBindingByName(IN PPROTOCOL_BINDING ProtocolBinding, IN PNDIS_STRING AdapterName)
{
    PLIST_ENTRY CurrentEntry;
    PADAPTER_BINDING AdapterBinding;
    KIRQL OldIrql;

    KeAcquireSpinLock(&ProtocolBinding->Lock, &OldIrql);

    CurrentEntry = ProtocolBinding->AdapterListHead.Flink;

    while (CurrentEntry != &ProtocolBinding->AdapterListHead)
    {
         AdapterBinding = CONTAINING_RECORD(CurrentEntry, ADAPTER_BINDING, ProtocolListEntry);

         if (RtlCompareUnicodeString(AdapterName, &AdapterBinding->Adapter->NdisMiniportBlock.MiniportName, TRUE) == 0)
         {
             KeReleaseSpinLock(&ProtocolBinding->Lock, OldIrql);
             return AdapterBinding;
         }

         CurrentEntry = CurrentEntry->Flink;
    }

    KeReleaseSpinLock(&ProtocolBinding->Lock, OldIrql);

    return NULL;
}

VOID
NTAPI
ndisBindMiniportsToProtocol(OUT PNDIS_STATUS Status, IN PPROTOCOL_BINDING Protocol)
{
  /*
   * bind the protocol to all of its miniports
   *
   * open registry path
   * get list of devices from Bind key
   * call BindAdapterHandler for each
   */
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING RegistryPath;
    WCHAR *RegistryPathStr, *DataPtr = NULL;
    NTSTATUS NtStatus;
    HANDLE DriverKeyHandle = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION KeyInformation = NULL;
    PNDIS_PROTOCOL_CHARACTERISTICS ProtocolCharacteristics = &Protocol->Chars;
    UNICODE_STRING ValueName;
    ULONG ResultLength;
    PLIST_ENTRY CurrentEntry = NULL;

    RegistryPathStr = ExAllocatePoolWithTag(PagedPool, sizeof(SERVICES_KEY) + ProtocolCharacteristics->Name.Length + sizeof(LINKAGE_KEY), NDIS_TAG);
    if(!RegistryPathStr)
    {
        NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
        *Status = NDIS_STATUS_RESOURCES;
        return;
    }

    wcscpy(RegistryPathStr, SERVICES_KEY);
    wcsncat(RegistryPathStr, ((WCHAR *)ProtocolCharacteristics->Name.Buffer), ProtocolCharacteristics->Name.Length / sizeof(WCHAR));
    RegistryPathStr[wcslen(SERVICES_KEY)+ProtocolCharacteristics->Name.Length/sizeof(WCHAR)] = 0;
    wcscat(RegistryPathStr, LINKAGE_KEY);

    RtlInitUnicodeString(&RegistryPath, RegistryPathStr);
    NDIS_DbgPrint(MAX_TRACE, ("Opening configuration key: %wZ\n", &RegistryPath));

    InitializeObjectAttributes(&ObjectAttributes, &RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    NtStatus = ZwOpenKey(&DriverKeyHandle, KEY_READ, &ObjectAttributes);

    ExFreePoolWithTag(RegistryPathStr, NDIS_TAG);

    if(NT_SUCCESS(NtStatus))
    {
        NDIS_DbgPrint(MAX_TRACE, ("Successfully opened the registry configuration\n"));

        RtlInitUnicodeString(&ValueName, L"Bind");

        NtStatus = ZwQueryValueKey(DriverKeyHandle, &ValueName, KeyValuePartialInformation, NULL, 0, &ResultLength);
        if(NtStatus != STATUS_BUFFER_OVERFLOW && NtStatus != STATUS_BUFFER_TOO_SMALL && NtStatus != STATUS_SUCCESS)
        {
            NDIS_DbgPrint(MIN_TRACE, ("Unable to query the Bind value for size\n"));
            ZwClose(DriverKeyHandle);
        }
        else
        {
            KeyInformation = ExAllocatePoolWithTag(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + ResultLength, NDIS_TAG);
            if(!KeyInformation)
            {
                NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
                ZwClose(DriverKeyHandle);
                NtStatus = STATUS_NO_MEMORY;
            }
            else
            {
                NtStatus = ZwQueryValueKey(DriverKeyHandle, &ValueName, KeyValuePartialInformation, KeyInformation,
                                           sizeof(KEY_VALUE_PARTIAL_INFORMATION) + ResultLength, &ResultLength);

                ZwClose(DriverKeyHandle);

                if(!NT_SUCCESS(NtStatus))
                {
                    NDIS_DbgPrint(MIN_TRACE, ("Unable to query the Bind value\n"));
                    ExFreePoolWithTag(KeyInformation, NDIS_TAG);
                    KeyInformation = NULL;
                }
            }
        }
    }

    if (!NT_SUCCESS(NtStatus))
    {
        NDIS_DbgPrint(MID_TRACE, ("Performing global bind for protocol '%wZ'\n", &ProtocolCharacteristics->Name));

        CurrentEntry = AdapterListHead.Flink;
    }
    else
    {
        NDIS_DbgPrint(MID_TRACE, ("Performing standard bind for protocol '%wZ'\n", &ProtocolCharacteristics->Name));

        DataPtr = (WCHAR*)KeyInformation->Data;
    }

    /* Assume success for now */
    *Status = NDIS_STATUS_SUCCESS;

    while (TRUE)
    {
        /* BindContext is for tracking pending binding operations */
        VOID *BindContext = 0;
        NDIS_STRING DeviceName;
        NDIS_STRING RegistryPath;
        WCHAR *RegistryPathStr = NULL;
        ULONG PathLength = 0;
        PLOGICAL_ADAPTER Adapter;

        if (KeyInformation)
        {
            /* Parse the REG_MULTI_SZ entry for device names */
            if (!(*DataPtr))
                break;

            RtlInitUnicodeString(&DeviceName, DataPtr);
        }
        else
        {
            /* Use the device name from the global adapter list */
            if (CurrentEntry == &AdapterListHead)
                break;

            Adapter = CONTAINING_RECORD(CurrentEntry, LOGICAL_ADAPTER, ListEntry);

            DeviceName = Adapter->NdisMiniportBlock.MiniportName;
        }

        /* Make sure the adapter has started */
        if (!MiniLocateDevice(&DeviceName))
        {
            /* It wasn't in the global miniport list, so skip the bind entry */
            goto next;
        }

        /* Make sure this device isn't already bound to this protocol */
        if (LocateAdapterBindingByName(Protocol, &DeviceName))
        {
            /* It was already in this protocol's bound adapter list, so skip the bind entry */
            goto next;
        }

        /*
         * RegistryPath should be:
         *     \Registry\Machine\System\CurrentControlSet\Services\Nic1\Parameters\Tcpip
         *
         *  This is constructed as follows:
         *      SERVICES_KEY + extracted device name + Protocol name from characteristics
         */

        PathLength = sizeof(SERVICES_KEY) +                               /* \Registry\Machine\System\CurrentControlSet\Services\ */
        wcslen( DeviceName.Buffer + 8 ) * sizeof(WCHAR) + /* Adapter1  (extracted from \Device\Adapter1)          */
        sizeof(PARAMETERS_KEY) +                                      /* \Parameters\                                         */
        ProtocolCharacteristics->Name.Length + sizeof(WCHAR);                         /* Tcpip                                                */

        RegistryPathStr = ExAllocatePool(PagedPool, PathLength);
        if(!RegistryPathStr)
        {
            NDIS_DbgPrint(MIN_TRACE, ("insufficient resources.\n"));
            *Status = NDIS_STATUS_RESOURCES;
            break;
        }

        wcscpy(RegistryPathStr, SERVICES_KEY);
        wcscat(RegistryPathStr, DeviceName.Buffer + 8 );
        wcscat(RegistryPathStr, PARAMETERS_KEY);
        wcsncat(RegistryPathStr, ProtocolCharacteristics->Name.Buffer, ProtocolCharacteristics->Name.Length / sizeof(WCHAR) );

        RegistryPathStr[PathLength/sizeof(WCHAR) - 1] = 0;

        RtlInitUnicodeString(&RegistryPath, RegistryPathStr);

        NDIS_DbgPrint(MAX_TRACE, ("Calling protocol's BindAdapter handler with DeviceName %wZ and RegistryPath %wZ\n",
                                  &DeviceName, &RegistryPath));

        {
            BIND_HANDLER BindHandler = ProtocolCharacteristics->BindAdapterHandler;
            if(BindHandler)
            {
                BindHandler(Status, BindContext, &DeviceName, &RegistryPath, 0);
                NDIS_DbgPrint(MID_TRACE, ("%wZ's BindAdapter handler returned 0x%x for %wZ\n", &ProtocolCharacteristics->Name, *Status, &DeviceName));
            }
            else
                NDIS_DbgPrint(MID_TRACE, ("No protocol bind handler specified\n"));
        }

        /* The handler has returned: nothing keeps the registry path */
        ExFreePool(RegistryPathStr);

    next:
        if (KeyInformation)
        {
            /* Advance to the next adapter in the REG_MULTI_SZ */
            DataPtr += (DeviceName.Length / sizeof(WCHAR)) + 1;
        }
        else
        {
            /* Advance to the next adapter in the global list */
            CurrentEntry = CurrentEntry->Flink;
        }
    }

    if (KeyInformation)
    {
        ExFreePoolWithTag(KeyInformation, NDIS_TAG);
    }
}

/*
 * @implemented
 */
VOID
EXPORT
NdisRegisterProtocol(
    OUT PNDIS_STATUS                    Status,
    OUT PNDIS_HANDLE                    NdisProtocolHandle,
    IN  PNDIS_PROTOCOL_CHARACTERISTICS  ProtocolCharacteristics,
    IN  UINT                            CharacteristicsLength)
/*
 * FUNCTION: Registers an NDIS driver's ProtocolXxx entry points
 * ARGUMENTS:
 *     Status                  = Address of buffer for status information
 *     NdisProtocolHandle      = Address of buffer for handle used to identify the driver
 *     ProtocolCharacteristics = Pointer to NDIS_PROTOCOL_CHARACTERISTICS structure
 *     CharacteristicsLength   = Size of structure which ProtocolCharacteristics targets
 * NOTES:
 *     - you *must* set NdisProtocolHandle before doing anything that could wind up
 *       getting BindAdapterHandler, as it will probably call OpenAdapter with this handle
 *     - the above implies that the initialization of the protocol block must be complete
 *       by then
 * TODO:
 *     - break this function up - probably do a 'ndisRefreshProtocolBindings' function
 *     - make this thing able to handle >1 protocol
 */
{
  PPROTOCOL_BINDING Protocol;
  NTSTATUS NtStatus;
  UINT MinSize;
  PNET_PNP_EVENT PnPEvent;

  NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

  *NdisProtocolHandle = NULL;

  /* first validate the PROTOCOL_CHARACTERISTICS */
  switch (ProtocolCharacteristics->MajorNdisVersion)
    {
    case 0x03:
      /* we don't really want to support ndis3 drivers - so we complain for now */
      NDIS_DbgPrint(MID_TRACE, ("NDIS 3 protocol attempting to register\n"));
      MinSize = sizeof(NDIS30_PROTOCOL_CHARACTERISTICS);
      break;

    case 0x04:
      MinSize = sizeof(NDIS40_PROTOCOL_CHARACTERISTICS);
      break;

    case 0x05:
      /* Identical for both NDIS50 and NDIS51 */
      MinSize = sizeof(NDIS50_PROTOCOL_CHARACTERISTICS);
      break;

    default:
      *Status = NDIS_STATUS_BAD_VERSION;
      NDIS_DbgPrint(MIN_TRACE, ("Incorrect characteristics size\n"));
      return;
    }

  if (CharacteristicsLength < MinSize)
    {
      NDIS_DbgPrint(MIN_TRACE, ("Bad protocol characteristics.\n"));
      *Status = NDIS_STATUS_BAD_CHARACTERISTICS;
      return;
    }

  /* set up the protocol block */
  Protocol = ExAllocatePool(NonPagedPool, sizeof(PROTOCOL_BINDING));
  if (!Protocol)
    {
      NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
      *Status = NDIS_STATUS_RESOURCES;
      return;
    }

  RtlZeroMemory(Protocol, sizeof(PROTOCOL_BINDING));
  RtlCopyMemory(&Protocol->Chars, ProtocolCharacteristics, MinSize);

  NtStatus = RtlUpcaseUnicodeString(&Protocol->Chars.Name, &ProtocolCharacteristics->Name, TRUE);
  if (!NT_SUCCESS(NtStatus))
    {
      NDIS_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
      ExFreePool(Protocol);
      *Status = NDIS_STATUS_RESOURCES;
      return;
    }

  KeInitializeSpinLock(&Protocol->Lock);

  InitializeListHead(&Protocol->AdapterListHead);

  /* We must set this before the call to ndisBindMiniportsToProtocol because the protocol's
   * BindAdapter handler might need it */

  *NdisProtocolHandle = Protocol;

  ndisBindMiniportsToProtocol(Status, Protocol);

  /* Should we only send this if ndisBindMiniportsToProtocol succeeds? */
  PnPEvent = ProSetupPnPEvent(NetEventBindsComplete, NULL, 0);
  if (PnPEvent)
  {
      if (Protocol->Chars.PnPEventHandler)
      {
          /* We call this with a NULL binding context because it affects all bindings */
          NtStatus = (*Protocol->Chars.PnPEventHandler)(NULL,
                                                        PnPEvent);

          /* FIXME: We don't support this yet */
          ASSERT(NtStatus != NDIS_STATUS_PENDING);
      }

      ExFreePool(PnPEvent);
  }

  if (*Status == NDIS_STATUS_SUCCESS) {
      ExInterlockedInsertTailList(&ProtocolListHead, &Protocol->ListEntry, &ProtocolListLock);
  } else {
      NDIS_DbgPrint(MIN_TRACE, ("Binding failed (%x)\n", *Status));
      ExFreePool(Protocol);
      *NdisProtocolHandle = NULL;
  }
}

/*
 * @implemented
 */
VOID
EXPORT
NdisRequest(
    OUT PNDIS_STATUS    Status,
    IN  NDIS_HANDLE     NdisBindingHandle,
    IN  PNDIS_REQUEST   NdisRequest)
/*
 * FUNCTION: Forwards a request to an NDIS driver
 * ARGUMENTS:
 *     Status            = Address of buffer for status information
 *     NdisBindingHandle = Adapter binding handle
 *     NdisRequest       = Pointer to request to perform
 */
{
    *Status = ProRequest(NdisBindingHandle, NdisRequest);
}

/*
 * @implemented
 */
VOID
EXPORT
NdisReset(
    OUT PNDIS_STATUS    Status,
    IN  NDIS_HANDLE     NdisBindingHandle)
{
    *Status = ProReset(NdisBindingHandle);
}

/*
 * @implemented
 */
#undef NdisSend
VOID
EXPORT
NdisSend(
    OUT PNDIS_STATUS    Status,
    IN  NDIS_HANDLE     NdisBindingHandle,
    IN  PNDIS_PACKET    Packet)
/*
 * FUNCTION: Forwards a request to send a packet
 * ARGUMENTS:
 *     Status             = Address of buffer for status information
 *     NdisBindingHandle  = Adapter binding handle
 *     Packet             = Pointer to NDIS packet descriptor
 */
{
    *Status = ProSend(NdisBindingHandle, Packet);
}

/*
 * @implemented
 */
#undef NdisSendPackets
VOID
EXPORT
NdisSendPackets(
    IN  NDIS_HANDLE     NdisBindingHandle,
    IN  PPNDIS_PACKET   PacketArray,
    IN  UINT            NumberOfPackets)
{
    ProSendPackets(NdisBindingHandle, PacketArray, NumberOfPackets);
}

/*
 * @implemented
 */
#undef NdisTransferData
VOID
EXPORT
NdisTransferData(
    OUT     PNDIS_STATUS    Status,
    IN      NDIS_HANDLE     NdisBindingHandle,
    IN      NDIS_HANDLE     MacReceiveContext,
    IN      UINT            ByteOffset,
    IN      UINT            BytesToTransfer,
    IN OUT	PNDIS_PACKET    Packet,
    OUT     PUINT           BytesTransferred)
/*
 * FUNCTION: Forwards a request to copy received data into a protocol-supplied packet
 * ARGUMENTS:
 *     Status            = Address of buffer for status information
 *     NdisBindingHandle = Adapter binding handle
 *     MacReceiveContext = MAC receive context
 *     ByteOffset        = Offset in packet to place data
 *     BytesToTransfer   = Number of bytes to copy into packet
 *     Packet            = Pointer to NDIS packet descriptor
 *     BytesTransferred  = Address of buffer to place number of bytes copied
 */
{
    *Status = ProTransferData(NdisBindingHandle,
                              MacReceiveContext,
                              ByteOffset,
                              BytesToTransfer,
                              Packet,
                              BytesTransferred);
}

/*
 * @implemented
 */
VOID
NTAPI
NdisReEnumerateProtocolBindings(IN NDIS_HANDLE NdisProtocolHandle)
{
    NDIS_STATUS NdisStatus;

    ndisBindMiniportsToProtocol(&NdisStatus, NdisProtocolHandle);
}


/*
 * @implemented
 */
VOID
EXPORT
NdisGetDriverHandle(
    IN  PNDIS_HANDLE    NdisBindingHandle,
    OUT PNDIS_HANDLE    NdisDriverHandle)
/*
 * FUNCTION:
 * ARGUMENTS:
 * NOTES:
 *    NDIS 5.0
 */
{
    PADAPTER_BINDING Binding = (PADAPTER_BINDING)NdisBindingHandle;

    if (!Binding)
    {
        NDIS_DbgPrint(MIN_TRACE, ("Bad binding handle\n"));
        *NdisDriverHandle = NULL;
        return;
    }

    *NdisDriverHandle = Binding->Adapter->NdisMiniportBlock.DriverHandle;
}

/* EOF */
