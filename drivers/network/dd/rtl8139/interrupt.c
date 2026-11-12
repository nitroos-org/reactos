/*
 * ReactOS Realtek 8139 Driver
 *
 * Copyright (C) 2013 Cameron Gutman
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "nic.h"

#define NDEBUG
#include <debug.h>

VOID
NTAPI
MiniportISR (
    OUT PBOOLEAN InterruptRecognized,
    OUT PBOOLEAN QueueMiniportHandleInterrupt,
    IN NDIS_HANDLE MiniportAdapterContext
    )
{
    PRTL_ADAPTER adapter = (PRTL_ADAPTER)MiniportAdapterContext;
    ULONG csConfig;

    //
    // FIXME: We need to synchronize with this ISR for changes to InterruptPending,
    // LinkChange, MediaState, and LinkSpeedMbps. We can get away with IRQL
    // synchronization on non-SMP machines because we run a DIRQL here.
    //

    adapter->InterruptPending |= NICInterruptRecognized(adapter, InterruptRecognized);
    if (!(*InterruptRecognized))
    {
        //
        // This is not ours.
        //
        *QueueMiniportHandleInterrupt = FALSE;
        return;
    }

    //
    // We have to check for a special link change interrupt before acknowledging
    //
    if (adapter->InterruptPending & R_I_RXUNDRUN)
    {
        NdisRawReadPortUlong(adapter->IoBase + R_CSCFG, &csConfig);
        if (csConfig & R_CSCR_LINKCHNG)
        {
            adapter->LinkChange = TRUE;
            NICUpdateLinkStatus(adapter);
        }
    }

    //
    // Acknowledge the interrupt and mark the events pending service
    //
    NICAcknowledgeInterrupts(adapter);
    *QueueMiniportHandleInterrupt = TRUE;
}

//
// A frame length the chip can never have stored: the receive ring is out of step with us.
//
static
BOOLEAN
RxPacketLengthIsSane (
    IN USHORT Length
    )
{
    return Length >= sizeof(ETH_HEADER) + RECV_CRC_LENGTH &&
           Length <= MAXIMUM_FRAME_SIZE + RECV_CRC_LENGTH + 4; // + VLAN tag
}

//
// Restarts the receiver at the beginning of the ring. Called with the adapter lock held.
//
static
VOID
RxResetReceiver (
    IN PRTL_ADAPTER Adapter
    )
{
    NdisRawWritePortUchar(Adapter->IoBase + R_CMD, B_CMD_TXE);
    NdisRawWritePortUlong(Adapter->IoBase + R_RXSA, Adapter->ReceiveBufferPa.LowPart);
    NdisRawWritePortUchar(Adapter->IoBase + R_CMD, B_CMD_TXE | B_CMD_RXE);
    NdisRawWritePortUlong(Adapter->IoBase + R_RC, RC_VAL);
    NICApplyPacketFilter(Adapter);
    RtlZeroMemory(Adapter->ReceiveBuffer, RECEIVE_BUFFER_SIZE);
    Adapter->ReceiveOffset = 0;
    NdisRawWritePortUshort(Adapter->IoBase + R_CAPR, (USHORT)(0 - 0x10));
}

VOID
NTAPI
MiniportHandleInterrupt (
    IN NDIS_HANDLE MiniportAdapterContext
    )
{
    PRTL_ADAPTER adapter = (PRTL_ADAPTER)MiniportAdapterContext;
    NIC_EVENTS events;
    ULONG txStatus;
    UCHAR command;
    PPACKET_HEADER nicHeader;
    PETH_HEADER ethHeader;
    BOOLEAN resume;
    BOOLEAN rxIndicated = FALSE;
    PNDIS_PACKET doneList[TX_DESC_COUNT];
    NDIS_STATUS doneStatus[TX_DESC_COUNT];
    UINT doneCount = 0, i;

    //
    // Take the events the ISR collected. The ISR sets bits from another processor or
    // preempts us, so the read and the clear have to be one step at DIRQL.
    //
    events.Adapter = adapter;
    NdisMSynchronizeWithInterrupt(&adapter->Interrupt, NICFetchEvents, &events);

    NdisDprAcquireSpinLock(&adapter->Lock);

    NDIS_DbgPrint(MAX_TRACE, ("Interrupts pending: 0x%x\n", events.Pending));

    //
    // Handle a link change
    //
    if (events.LinkChange)
    {
        NdisDprReleaseSpinLock(&adapter->Lock);
        NdisMIndicateStatus(adapter->MiniportAdapterHandle,
                            events.MediaState == NdisMediaStateConnected ?
                                NDIS_STATUS_MEDIA_CONNECT : NDIS_STATUS_MEDIA_DISCONNECT,
                            NULL,
                            0);
        NdisMIndicateStatusComplete(adapter->MiniportAdapterHandle);
        NdisDprAcquireSpinLock(&adapter->Lock);
    }

    //
    // Reclaim every finished TX descriptor. This does not depend on the TX interrupt
    // bits: a descriptor is finished when the chip says so, and a DPC that was queued
    // for any reason is as good a time as any to notice.
    //
    while (adapter->TxFull || adapter->DirtyTxDesc != adapter->CurrentTxDesc)
    {
        NdisRawReadPortUlong(adapter->IoBase + R_TXSTS0 +
                             (adapter->DirtyTxDesc * sizeof(ULONG)), &txStatus);

        if (!(txStatus & (R_TXS_STATOK | R_TXS_UNDERRUN | R_TXS_ABORTED)))
        {
            //
            // Not sent yet
            //
            break;
        }

        NDIS_DbgPrint(MAX_TRACE, ("Transmission for desc %d complete: 0x%x\n",
                                  adapter->DirtyTxDesc, txStatus));

        if (txStatus & R_TXS_STATOK)
        {
            adapter->TransmitOk++;
        }
        else
        {
            adapter->TransmitError++;
        }

        if (adapter->TxPackets[adapter->DirtyTxDesc] != NULL)
        {
            doneList[doneCount] = adapter->TxPackets[adapter->DirtyTxDesc];
            doneStatus[doneCount] = (txStatus & R_TXS_STATOK) ? NDIS_STATUS_SUCCESS :
                                                                 NDIS_STATUS_FAILURE;
            doneCount++;
            adapter->TxPackets[adapter->DirtyTxDesc] = NULL;
        }

        adapter->DirtyTxDesc++;
        adapter->DirtyTxDesc %= TX_DESC_COUNT;
        adapter->TxFull = FALSE;
    }

    resume = adapter->TxStarved && !adapter->TxFull;
    if (resume)
    {
        adapter->TxStarved = FALSE;
    }

    //
    // Drain the receive ring. Like the TX side this does not trust the RX interrupt bits
    // to still be set: the chip tells us whether the ring is empty.
    //
    for (;;)
    {
        NdisRawReadPortUchar(adapter->IoBase + R_CMD, &command);
        if (command & R_CMD_RXEMPTY)
        {
            //
            // The buffer is empty
            //
            break;
        }

        adapter->ReceiveOffset %= RECEIVE_BUFFER_SIZE;

        NDIS_DbgPrint(MAX_TRACE, ("Looking for a packet at offset 0x%x\n",
                        adapter->ReceiveOffset));
        nicHeader = (PPACKET_HEADER)(adapter->ReceiveBuffer + adapter->ReceiveOffset);

        if (nicHeader->Status == 0)
        {
            //
            // The chip has not finished this frame yet; the next interrupt brings us back.
            //
            break;
        }

        if (!RxPacketLengthIsSane(nicHeader->PacketLength))
        {
            //
            // We lost track of the frame boundaries. Nothing after this point can be
            // trusted, so restart the receiver.
            //
            NDIS_DbgPrint(MIN_TRACE, ("Bad receive header 0x%x/0x%x, resetting RX\n",
                                      nicHeader->Status, nicHeader->PacketLength));
            adapter->ReceiveError++;
            RxResetReceiver(adapter);
            break;
        }

        if (!(nicHeader->Status & RSR_ROK))
        {
            //
            // Receive failed
            //
            NDIS_DbgPrint(MIN_TRACE, ("Receive failed: 0x%x\n", nicHeader->Status));

            if (nicHeader->Status & RSR_FAE)
            {
                adapter->ReceiveAlignmentError++;
            }
            else if (nicHeader->Status & RSR_CRC)
            {
                adapter->ReceiveCrcError++;
            }
            adapter->ReceiveError++;

            goto NextPacket;
        }

        NDIS_DbgPrint(MAX_TRACE, ("Indicating %d byte packet to NDIS\n",
                       nicHeader->PacketLength - RECV_CRC_LENGTH));

        ethHeader = (PETH_HEADER)(nicHeader + 1);
        NdisMEthIndicateReceive(adapter->MiniportAdapterHandle,
                                NULL,
                                (PVOID)(ethHeader),
                                sizeof(ETH_HEADER),
                                (PVOID)(ethHeader + 1),
                                nicHeader->PacketLength - sizeof(ETH_HEADER) - RECV_CRC_LENGTH,
                                nicHeader->PacketLength - sizeof(ETH_HEADER) - RECV_CRC_LENGTH);
        rxIndicated = TRUE;
        adapter->ReceiveOk++;

    NextPacket:
        //
        // Hand the slot back. The header is cleared so that a stale status is never
        // mistaken for a finished frame when the ring wraps around to here again.
        //
        adapter->ReceiveOffset += nicHeader->PacketLength + sizeof(PACKET_HEADER);
        adapter->ReceiveOffset = (adapter->ReceiveOffset + 3) & ~3;
        nicHeader->Status = 0;
        NdisRawWritePortUshort(adapter->IoBase + R_CAPR, adapter->ReceiveOffset - 0x10);
    }

    if (rxIndicated)
    {
        NdisMEthIndicateReceiveComplete(adapter->MiniportAdapterHandle);
    }

    NdisDprReleaseSpinLock(&adapter->Lock);

    //
    // Completions go out with no lock held; the protocol may send from its handler.
    //
    for (i = 0; i < doneCount; i++)
    {
        NdisMSendComplete(adapter->MiniportAdapterHandle, doneList[i], doneStatus[i]);
    }

    if (resume)
    {
        NdisMSendResourcesAvailable(adapter->MiniportAdapterHandle);
    }
}
