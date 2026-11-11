/*
 * PROJECT:     ReactOS Intel PRO/1000 Driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Sending packets
 * COPYRIGHT:   Copyright 2018 Mark Jansen <mark.jansen@reactos.org>
 *              Copyright 2019 Victor Perevertkin <victor.perevertkin@reactos.org>
 */

#include "nic.h"

#include <debug.h>

/* Puts one packet on the transmit ring. The adapter does not see it until the tail register
   is written (NICTransmitKick); every write of it is a VM exit, so a batch of packets
   shares one. The caller has checked that TxFull is not set. */
static
VOID
NICTransmitPacket(
    _In_ PE1000_ADAPTER Adapter,
    _In_ PNDIS_PACKET Packet)
{
    volatile PE1000_TRANSMIT_DESCRIPTOR TransmitDescriptor;
    PSCATTER_GATHER_LIST sgList;

    NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

    sgList = NDIS_PER_PACKET_INFO_FROM_PACKET(Packet, ScatterGatherListPacketInfo);

    ASSERT(sgList != NULL);
    ASSERT(sgList->NumberOfElements == 1);
    ASSERT((sgList->Elements[0].Address.LowPart & 3) == 0);
    ASSERT(sgList->Elements[0].Length <= MAXIMUM_FRAME_SIZE);

    Adapter->TransmitPackets[Adapter->CurrentTxDesc] = Packet;

    TransmitDescriptor = Adapter->TransmitDescriptors + Adapter->CurrentTxDesc;
    TransmitDescriptor->Address = sgList->Elements[0].Address.QuadPart;
    TransmitDescriptor->Length = sgList->Elements[0].Length;
    TransmitDescriptor->ChecksumOffset = 0;
    TransmitDescriptor->Command = E1000_TDESC_CMD_RS | E1000_TDESC_CMD_IFCS |
                                  E1000_TDESC_CMD_EOP | E1000_TDESC_CMD_IDE;
    TransmitDescriptor->Status = 0;
    TransmitDescriptor->ChecksumStartField = 0;
    TransmitDescriptor->Special = 0;

    Adapter->CurrentTxDesc = (Adapter->CurrentTxDesc + 1) % NUM_TRANSMIT_DESCRIPTORS;

    if (Adapter->CurrentTxDesc == Adapter->LastTxDesc)
    {
        NDIS_DbgPrint(MID_TRACE, ("All TX descriptors are full now\n"));
        Adapter->TxFull = TRUE;
    }
}

/* Hands the queued descriptors to the adapter */
static
VOID
NICTransmitKick(
    _In_ PE1000_ADAPTER Adapter)
{
    E1000WriteUlong(Adapter, E1000_REG_TDT, Adapter->CurrentTxDesc);
}

NDIS_STATUS
NTAPI
MiniportSend(
    _In_ NDIS_HANDLE MiniportAdapterContext,
    _In_ PNDIS_PACKET Packet,
    _In_ UINT Flags)
{
    PE1000_ADAPTER Adapter = (PE1000_ADAPTER)MiniportAdapterContext;

    if (Adapter->TxFull)
    {
        NDIS_DbgPrint(MIN_TRACE, ("All TX descriptors are full\n"));
        return NDIS_STATUS_RESOURCES;
    }

    NICTransmitPacket(Adapter, Packet);
    NICTransmitKick(Adapter);

    return NDIS_STATUS_PENDING;
}

/* NDIS hands the packets that queued up behind the running send or interrupt DPC in one call: the
   adapter is told for every TX_KICK_BATCH of them and at the end, not for each. More than two
   at a time slows an HTTP download down on QEMU user networking (measured, lane netl5): the
   adapter does the work of the packets it is told of inside the register write, and the
   acknowledgements at the front of a large batch wait for the ones behind them.
   The status of each packet is PENDING (NdisMSendComplete follows) or, once the ring is full,
   RESOURCES for it and every packet after it: NDIS sends those again later. */
VOID
NTAPI
MiniportSendPackets(
    _In_ NDIS_HANDLE MiniportAdapterContext,
    _In_ PPNDIS_PACKET PacketArray,
    _In_ UINT NumberOfPackets)
{
    PE1000_ADAPTER Adapter = (PE1000_ADAPTER)MiniportAdapterContext;
    UINT i;
    UINT Unkicked = 0;

    for (i = 0; i < NumberOfPackets; i++)
    {
        if (Adapter->TxFull)
        {
            NDIS_DbgPrint(MIN_TRACE, ("All TX descriptors are full\n"));
            NDIS_SET_PACKET_STATUS(PacketArray[i], NDIS_STATUS_RESOURCES);
            continue;
        }

        NICTransmitPacket(Adapter, PacketArray[i]);
        NDIS_SET_PACKET_STATUS(PacketArray[i], NDIS_STATUS_PENDING);

        if (++Unkicked == TX_KICK_BATCH)
        {
            NICTransmitKick(Adapter);
            Unkicked = 0;
        }
    }

    if (Unkicked)
        NICTransmitKick(Adapter);
}
