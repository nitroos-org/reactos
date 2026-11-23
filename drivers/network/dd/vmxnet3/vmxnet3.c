/*
 * PROJECT:     ReactOS VMware vmxnet3 NDIS miniport driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Driver entry, initialisation, interrupts, transmit and receive
 * COPYRIGHT:   Copyright 2026 ReactOS Project contributors
 *
 * One transmit queue and one receive queue (two receive rings: head and body), INTx, no offloads,
 * no RSS. Frames are copied to and from buffers that the driver owns: the transmit path copies the
 * packet into a transmit buffer (one descriptor per packet), the receive path indicates the frame
 * from its buffer and gives the buffer back at once. Everything that the device writes (completion
 * indices, lengths, the MAC address, the link speed) is validated before it is used; the driver
 * waits for nothing on the device (commands are answered by the register they are written to).
 */

#include "vmxnet3.h"

#define GENBIT(Gen, Shift)          ((ULONG)(Gen) << (Shift))
#define BARCOUNT                    6

static
VOID
VmxFreeResources(
    _In_ PVMX_ADAPTER Adapter)
{
    if (Adapter->RxBuffers != NULL)
    {
        NdisMFreeSharedMemory(Adapter->AdapterHandle, (VMX_NRXDESC0 + VMX_NRXDESC1) * VMX_BUFFER_SIZE, TRUE,
                              Adapter->RxBuffers, Adapter->RxBuffersPa);
        Adapter->RxBuffers = NULL;
    }
    if (Adapter->TxBuffers != NULL)
    {
        NdisMFreeSharedMemory(Adapter->AdapterHandle, VMX_NTXDESC * VMX_BUFFER_SIZE, TRUE,
                              Adapter->TxBuffers, Adapter->TxBuffersPa);
        Adapter->TxBuffers = NULL;
    }
    if (Adapter->Ctl != NULL)
    {
        NdisMFreeSharedMemory(Adapter->AdapterHandle, VMX_CTL_SIZE, TRUE, Adapter->Ctl, Adapter->CtlPa);
        Adapter->Ctl = NULL;
    }
    if (Adapter->Bar0 != NULL)
    {
        NdisMUnmapIoSpace(Adapter->AdapterHandle, Adapter->Bar0, Adapter->Bar0Length);
        Adapter->Bar0 = NULL;
    }
    if (Adapter->Bar1 != NULL)
    {
        NdisMUnmapIoSpace(Adapter->AdapterHandle, Adapter->Bar1, Adapter->Bar1Length);
        Adapter->Bar1 = NULL;
    }
}

/* Find the two memory ranges of BAR0 and BAR1, and the interrupt, in the resource list */
static
NDIS_STATUS
VmxParseResources(
    _In_ PVMX_ADAPTER Adapter,
    _In_ PNDIS_RESOURCE_LIST ResourceList,
    _In_ PPCI_COMMON_CONFIG PciConfig)
{
    ULONGLONG BarAddress[BARCOUNT];
    UINT n, i;
    ULONG Found = 0;
    NDIS_PHYSICAL_ADDRESS Memory[BARCOUNT];
    ULONG MemoryLength[BARCOUNT];
    UINT MemoryCount = 0;

    RtlZeroMemory(BarAddress, sizeof(BarAddress));
    for (i = 0; i < BARCOUNT; i++)
    {
        ULONG Bar = PciConfig->u.type0.BaseAddresses[i];

        if (Bar & 1)
            continue;                                   /* I/O space */
        BarAddress[i] = Bar & ~0xFUL;
        if (((Bar >> 1) & 3) == 2 && i + 1 < BARCOUNT)  /* 64-bit memory BAR: the next dword is the high half */
        {
            BarAddress[i] |= (ULONGLONG)PciConfig->u.type0.BaseAddresses[i + 1] << 32;
            i++;
        }
    }

    for (n = 0; n < ResourceList->Count; n++)
    {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR Res = ResourceList->PartialDescriptors + n;

        switch (Res->Type)
        {
            case CmResourceTypeInterrupt:
                Adapter->InterruptVector = Res->u.Interrupt.Vector;
                Adapter->InterruptLevel = Res->u.Interrupt.Level;
                Adapter->InterruptShared = (Res->ShareDisposition == CmResourceShareShared);
                Adapter->InterruptFlags = Res->Flags;
                break;

            case CmResourceTypeMemory:
                if (MemoryCount < BARCOUNT)
                {
                    Memory[MemoryCount] = Res->u.Memory.Start;
                    MemoryLength[MemoryCount] = Res->u.Memory.Length;
                    MemoryCount++;
                }
                break;

            default:
                break;
        }
    }

    /* the ranges that start where BAR0 and BAR1 point; the first two memory ranges when the addresses were translated */
    for (n = 0; n < MemoryCount; n++)
    {
        if (BarAddress[0] != 0 && Memory[n].QuadPart == (LONGLONG)BarAddress[0] && !(Found & 1))
        {
            Adapter->Bar0Pa = Memory[n];
            Adapter->Bar0Length = MemoryLength[n];
            Found |= 1;
        }
        else if (BarAddress[1] != 0 && Memory[n].QuadPart == (LONGLONG)BarAddress[1] && !(Found & 2))
        {
            Adapter->Bar1Pa = Memory[n];
            Adapter->Bar1Length = MemoryLength[n];
            Found |= 2;
        }
    }
    if (Found != 3 && MemoryCount >= 2)
    {
        Adapter->Bar0Pa = Memory[0];
        Adapter->Bar0Length = MemoryLength[0];
        Adapter->Bar1Pa = Memory[1];
        Adapter->Bar1Length = MemoryLength[1];
        Found = 3;
    }

    if (Found != 3 || Adapter->InterruptVector == 0 ||
        Adapter->Bar0Length < VMX_BAR0_MIN_LENGTH || Adapter->Bar1Length < VMX_BAR1_MIN_LENGTH)
    {
        DbgPrint("vmxnet3: the adapter did not get the memory ranges and the interrupt it needs\n");
        return NDIS_STATUS_RESOURCES;
    }
    return NDIS_STATUS_SUCCESS;
}

static
NDIS_STATUS
VmxAllocateResources(
    _In_ PVMX_ADAPTER Adapter)
{
    NDIS_STATUS Status;

    Status = NdisMMapIoSpace((PVOID*)&Adapter->Bar0, Adapter->AdapterHandle, Adapter->Bar0Pa, Adapter->Bar0Length);
    if (Status != NDIS_STATUS_SUCCESS)
        return NDIS_STATUS_RESOURCES;
    Status = NdisMMapIoSpace((PVOID*)&Adapter->Bar1, Adapter->AdapterHandle, Adapter->Bar1Pa, Adapter->Bar1Length);
    if (Status != NDIS_STATUS_SUCCESS)
        return NDIS_STATUS_RESOURCES;

    NdisMAllocateSharedMemory(Adapter->AdapterHandle, VMX_CTL_SIZE, TRUE, (PVOID*)&Adapter->Ctl, &Adapter->CtlPa);
    if (Adapter->Ctl == NULL)
        return NDIS_STATUS_RESOURCES;
    NdisMAllocateSharedMemory(Adapter->AdapterHandle, VMX_NTXDESC * VMX_BUFFER_SIZE, TRUE,
                              (PVOID*)&Adapter->TxBuffers, &Adapter->TxBuffersPa);
    if (Adapter->TxBuffers == NULL)
        return NDIS_STATUS_RESOURCES;
    NdisMAllocateSharedMemory(Adapter->AdapterHandle, (VMX_NRXDESC0 + VMX_NRXDESC1) * VMX_BUFFER_SIZE, TRUE,
                              (PVOID*)&Adapter->RxBuffers, &Adapter->RxBuffersPa);
    if (Adapter->RxBuffers == NULL)
        return NDIS_STATUS_RESOURCES;

    RtlZeroMemory(Adapter->Ctl, VMX_CTL_SIZE);

    Adapter->Ds = (PVMX_DRIVER_SHARED)(Adapter->Ctl + VMX_OFF_DS);
    Adapter->Ts = (PVMX_TXQ_SHARED)(Adapter->Ctl + VMX_OFF_QS);
    Adapter->Rs = (PVMX_RXQ_SHARED)(Adapter->Ctl + VMX_OFF_QS + sizeof(VMX_TXQ_SHARED));
    Adapter->McastTable = Adapter->Ctl + VMX_OFF_MCAST;
    Adapter->TxDesc = (PVMX_TXDESC)(Adapter->Ctl + VMX_OFF_TXD);
    Adapter->TxComp = (PVMX_TXCOMPDESC)(Adapter->Ctl + VMX_OFF_TXC);
    Adapter->RxComp = (PVMX_RXCOMPDESC)(Adapter->Ctl + VMX_OFF_RXC);

    Adapter->Rx[0].Desc = (PVMX_RXDESC)(Adapter->Ctl + VMX_OFF_RXD0);
    Adapter->Rx[0].Buffers = Adapter->RxBuffers;
    Adapter->Rx[0].BuffersPa = Adapter->RxBuffersPa.QuadPart;
    Adapter->Rx[0].Size = VMX_NRXDESC0;
    Adapter->Rx[0].Btype = VMX_BTYPE_HEAD;
    Adapter->Rx[0].HeadReg = VMX_BAR0_RXH1(0);
    Adapter->Rx[1].Desc = (PVMX_RXDESC)(Adapter->Ctl + VMX_OFF_RXD1);
    Adapter->Rx[1].Buffers = Adapter->RxBuffers + VMX_NRXDESC0 * VMX_BUFFER_SIZE;
    Adapter->Rx[1].BuffersPa = Adapter->RxBuffersPa.QuadPart + VMX_NRXDESC0 * VMX_BUFFER_SIZE;
    Adapter->Rx[1].Size = VMX_NRXDESC1;
    Adapter->Rx[1].Btype = VMX_BTYPE_BODY;
    Adapter->Rx[1].HeadReg = VMX_BAR0_RXH2(0);
    return NDIS_STATUS_SUCCESS;
}

/* Give Count more buffers of a receive ring to the device */
static
VOID
VmxRxPost(
    _In_ PVMX_ADAPTER Adapter,
    _In_ UINT Ring,
    _In_ ULONG Count)
{
    VMX_RXRING *R = &Adapter->Rx[Ring];

    while (Count-- != 0 && R->Posted < R->Size - 1)
    {
        volatile VMX_RXDESC *D = &R->Desc[R->Fill];

        D->Addr = R->BuffersPa + (ULONGLONG)R->Fill * VMX_BUFFER_SIZE;
        D->Word3 = 0;
        KeMemoryBarrier();
        D->Word2 = VMX_BUFFER_SIZE | (R->Btype << VMX_RX_BTYPE_SHIFT) | GENBIT(R->Gen, VMX_RX_GEN_SHIFT);
        R->Posted++;
        if (++R->Fill == R->Size)
        {
            R->Fill = 0;
            R->Gen ^= 1;
        }
    }
    KeMemoryBarrier();
    VmxWrite0(Adapter, R->HeadReg, R->Fill);
}

/* Fill in the structures that the device is told about (driver shared, queue shared) and reset the ring state */
static
VOID
VmxSetupQueues(
    _In_ PVMX_ADAPTER Adapter)
{
    PVMX_DRIVER_SHARED Ds = Adapter->Ds;
    PVMX_TXQ_SHARED Ts = Adapter->Ts;
    PVMX_RXQ_SHARED Rs = Adapter->Rs;
    ULONGLONG Ctl = Adapter->CtlPa.QuadPart;
    UINT i;

    RtlZeroMemory(Adapter->Ctl, VMX_OFF_MCAST);
    RtlZeroMemory(Adapter->Ctl + VMX_OFF_TXD, VMX_CTL_SIZE - VMX_OFF_TXD);

    Ds->Magic = VMX_REV1_MAGIC;
    Ds->Version = 0x00010000;
#ifdef _WIN64
    Ds->Guest = VMX_GOS_WINDOWS | VMX_GOS_64BIT;
#else
    Ds->Guest = VMX_GOS_WINDOWS | VMX_GOS_32BIT;
#endif
    Ds->Vmxnet3Revision = 1;
    Ds->UptVersion = 1;
    Ds->UptFeatures = 0;
    Ds->DriverData = ~0ULL;
    Ds->DriverDataLen = 0;
    Ds->QueueShared = Ctl + VMX_OFF_QS;
    Ds->QueueSharedLen = sizeof(VMX_TXQ_SHARED) + sizeof(VMX_RXQ_SHARED);
    Ds->Mtu = VMX_MTU;
    Ds->NTxQueue = 1;
    Ds->NRxQueue = 1;
    Ds->McastTable = Ctl + VMX_OFF_MCAST;
    Ds->Automask = 1;
    Ds->NIntr = 1;
    Ds->EvIntr = 0;
    Ds->Ictrl = VMX_ICTRL_DISABLE_ALL;
    for (i = 0; i < Ds->NIntr; i++)
        Ds->ModLevel[i] = VMX_IMOD_ADAPTIVE;

    Ts->IntrThreshold = 1;
    Ts->CmdRing = Ctl + VMX_OFF_TXD;
    Ts->CmdRingLen = VMX_NTXDESC;
    Ts->CompRing = Ctl + VMX_OFF_TXC;
    Ts->CompRingLen = VMX_NTXDESC;
    Ts->DriverData = ~0ULL;
    Ts->IntrIdx = 0;
    Ts->Stopped = 1;

    Rs->CmdRing[0] = Ctl + VMX_OFF_RXD0;
    Rs->CmdRing[1] = Ctl + VMX_OFF_RXD1;
    Rs->CmdRingLen[0] = VMX_NRXDESC0;
    Rs->CmdRingLen[1] = VMX_NRXDESC1;
    Rs->CompRing = Ctl + VMX_OFF_RXC;
    Rs->CompRingLen = VMX_NRXCOMPDESC;
    Rs->DriverData = ~0ULL;
    Rs->IntrIdx = 0;
    Rs->Stopped = 1;

    Adapter->TxProd = 0;
    Adapter->TxCons = 0;
    Adapter->TxGen = 1;
    Adapter->TxCompNext = 0;
    Adapter->TxCompGen = 1;
    RtlZeroMemory(Adapter->TxPackets, sizeof(Adapter->TxPackets));

    Adapter->RxCompNext = 0;
    Adapter->RxCompGen = 1;
    Adapter->RxDropping = FALSE;
    for (i = 0; i < 2; i++)
    {
        Adapter->Rx[i].Fill = 0;
        Adapter->Rx[i].Gen = 1;
        Adapter->Rx[i].Posted = 0;
    }
}

VOID
VmxUpdateLink(
    _In_ PVMX_ADAPTER Adapter)
{
    ULONG Link = VmxCommand(Adapter, VMX_CMD_GET_LINK);
    ULONG Speed = Link >> 16;

    /* the speed is written by the device: a value that is not usable is taken as 1 Gbit/s */
    if (Speed == 0 || Speed > 100000)
        Speed = 1000;
    Adapter->LinkSpeedMbps = Speed;
    Adapter->MediaState = (Link & 1) ? NdisMediaStateConnected : NdisMediaStateDisconnected;
}

static
VOID
VmxEnableInterrupts(
    _In_ PVMX_ADAPTER Adapter)
{
    Adapter->Ds->Ictrl &= ~VMX_ICTRL_DISABLE_ALL;
    VmxWrite0(Adapter, VMX_BAR0_IMASK(0), 0);
}

static
VOID
VmxDisableInterrupts(
    _In_ PVMX_ADAPTER Adapter)
{
    Adapter->Ds->Ictrl |= VMX_ICTRL_DISABLE_ALL;
    VmxWrite0(Adapter, VMX_BAR0_IMASK(0), 1);
}

/* Tell the device about the queues, give it the receive buffers and enable it */
static
NDIS_STATUS
VmxActivate(
    _In_ PVMX_ADAPTER Adapter)
{
    VmxSetupQueues(Adapter);

    VmxWrite1(Adapter, VMX_BAR1_DSL, (ULONG)Adapter->CtlPa.QuadPart + VMX_OFF_DS);
    VmxWrite1(Adapter, VMX_BAR1_DSH, (ULONG)(Adapter->CtlPa.QuadPart >> 32));

    /* the descriptors, then the registers that tell the device where its heads are */
    VmxWrite0(Adapter, VMX_BAR0_RXH1(0), 0);
    VmxWrite0(Adapter, VMX_BAR0_RXH2(0), 0);
    VmxRxPost(Adapter, 0, VMX_NRXDESC0);
    VmxRxPost(Adapter, 1, VMX_NRXDESC1);
    VmxWrite0(Adapter, VMX_BAR0_RXH1(0), 0);
    VmxWrite0(Adapter, VMX_BAR0_RXH2(0), 0);

    if (VmxCommand(Adapter, VMX_CMD_ENABLE) != 0)
    {
        DbgPrint("vmxnet3: the device does not enable\n");
        return NDIS_STATUS_FAILURE;
    }

    VmxWrite0(Adapter, VMX_BAR0_RXH1(0), Adapter->Rx[0].Fill);
    VmxWrite0(Adapter, VMX_BAR0_RXH2(0), Adapter->Rx[1].Fill);

    Adapter->Active = TRUE;
    VmxApplyPacketFilter(Adapter);
    VmxEnableInterrupts(Adapter);
    VmxUpdateLink(Adapter);
    return NDIS_STATUS_SUCCESS;
}

/* Stop the device; the packets that were on the transmit ring are returned to NDIS with a failure */
static
VOID
VmxQuiesce(
    _In_ PVMX_ADAPTER Adapter,
    _In_ BOOLEAN CompleteSends)
{
    UINT i;

    Adapter->Active = FALSE;
    if (Adapter->Ds != NULL)
        VmxDisableInterrupts(Adapter);
    VmxCommand(Adapter, VMX_CMD_DISABLE);
    VmxCommand(Adapter, VMX_CMD_RESET);

    for (i = 0; i < VMX_NTXDESC; i++)
    {
        PNDIS_PACKET Packet = Adapter->TxPackets[i];

        Adapter->TxPackets[i] = NULL;
        if (Packet != NULL && CompleteSends)
            NdisMSendComplete(Adapter->AdapterHandle, Packet, NDIS_STATUS_REQUEST_ABORTED);
    }
}

/* The station address, from the device */
static
NDIS_STATUS
VmxReadMac(
    _In_ PVMX_ADAPTER Adapter)
{
    ULONG Low = VmxCommand(Adapter, VMX_CMD_GET_MACL);
    ULONG High = VmxCommand(Adapter, VMX_CMD_GET_MACH);
    PUCHAR Mac = Adapter->PermanentMacAddress;
    UINT i;
    BOOLEAN Zero = TRUE;

    Mac[0] = (UCHAR)Low;
    Mac[1] = (UCHAR)(Low >> 8);
    Mac[2] = (UCHAR)(Low >> 16);
    Mac[3] = (UCHAR)(Low >> 24);
    Mac[4] = (UCHAR)High;
    Mac[5] = (UCHAR)(High >> 8);

    for (i = 0; i < ETH_LENGTH_OF_ADDRESS; i++)
        Zero &= (Mac[i] == 0);
    if (Zero || (Mac[0] & 1))           /* no address, or a group address: the device does not tell a station address */
    {
        DbgPrint("vmxnet3: the device reports an unusable MAC address\n");
        return NDIS_STATUS_FAILURE;
    }

    VmxWrite1(Adapter, VMX_BAR1_MACL, Low);
    VmxWrite1(Adapter, VMX_BAR1_MACH, High);
    return NDIS_STATUS_SUCCESS;
}

/* The multicast list and the receive mode, from the NDIS packet filter */
NDIS_STATUS
VmxApplyPacketFilter(
    _In_ PVMX_ADAPTER Adapter)
{
    ULONG Mode = 0;
    ULONG Filter = Adapter->PacketFilter;

    if (!Adapter->Active)
        return NDIS_STATUS_SUCCESS;

    if (Filter & (NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_PROMISCUOUS))
        Mode |= VMX_RXMODE_UCAST;
    if (Filter & (NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_PROMISCUOUS))
        Mode |= VMX_RXMODE_BCAST;
    if (Filter & NDIS_PACKET_TYPE_PROMISCUOUS)
        Mode |= VMX_RXMODE_PROMISC;

    Adapter->Ds->McastTableLen = 0;
    if (Filter & (NDIS_PACKET_TYPE_ALL_MULTICAST | NDIS_PACKET_TYPE_PROMISCUOUS))
    {
        Mode |= VMX_RXMODE_MCAST | VMX_RXMODE_ALLMULTI;
    }
    else if ((Filter & NDIS_PACKET_TYPE_MULTICAST) && Adapter->MulticastListSize != 0)
    {
        ULONG Bytes = Adapter->MulticastListSize * ETH_LENGTH_OF_ADDRESS;

        ASSERT(Bytes <= VMX_MCAST_TABLE_BYTES);
        RtlCopyMemory(Adapter->McastTable, Adapter->MulticastList, Bytes);
        Adapter->Ds->McastTableLen = (USHORT)Bytes;
        Mode |= VMX_RXMODE_MCAST;
    }

    VmxCommand(Adapter, VMX_CMD_SET_FILTER);
    Adapter->Ds->RxMode = Mode;
    VmxCommand(Adapter, VMX_CMD_SET_RXMODE);
    return NDIS_STATUS_SUCCESS;
}

/* Statistics of the device (the counters of the queue structures, refreshed by GET_STATS) */
ULONG64
VmxQueryStatistic(
    _In_ PVMX_ADAPTER Adapter,
    _In_ NDIS_OID Oid)
{
    if (!Adapter->Active)
        return 0;

    VmxCommand(Adapter, VMX_CMD_GET_STATS);
    switch (Oid)
    {
        case OID_GEN_XMIT_OK:
            return Adapter->Ts->Stats[VMX_TXSTAT_UCAST_PACKETS] + Adapter->Ts->Stats[VMX_TXSTAT_MCAST_PACKETS] +
                   Adapter->Ts->Stats[VMX_TXSTAT_BCAST_PACKETS];
        case OID_GEN_RCV_OK:
            return Adapter->Rs->Stats[VMX_RXSTAT_UCAST_PACKETS] + Adapter->Rs->Stats[VMX_RXSTAT_MCAST_PACKETS] +
                   Adapter->Rs->Stats[VMX_RXSTAT_BCAST_PACKETS];
        case OID_GEN_XMIT_ERROR:
            return Adapter->Ts->Stats[VMX_TXSTAT_ERROR] + Adapter->Ts->Stats[VMX_TXSTAT_DISCARD] + Adapter->TxDropsDriver;
        case OID_GEN_RCV_ERROR:
            return Adapter->Rs->Stats[VMX_RXSTAT_ERROR] + Adapter->RxDropsDriver;
        case OID_GEN_RCV_NO_BUFFER:
            return Adapter->Rs->Stats[VMX_RXSTAT_NOBUFFER];
        default:
            return 0;
    }
}

/* One line with the counters of the device and of the driver, to the debug output (link changes and halt) */
static
VOID
VmxPrintStatistics(
    _In_ PVMX_ADAPTER Adapter,
    _In_ PCSTR Reason)
{
    DbgPrint("vmxnet3: %s: received %I64u, no buffer %I64u, errors %I64u, dropped by the driver %I64u; sent %I64u, errors %I64u\n",
             Reason,
             VmxQueryStatistic(Adapter, OID_GEN_RCV_OK),
             VmxQueryStatistic(Adapter, OID_GEN_RCV_NO_BUFFER),
             VmxQueryStatistic(Adapter, OID_GEN_RCV_ERROR) - Adapter->RxDropsDriver,
             Adapter->RxDropsDriver,
             VmxQueryStatistic(Adapter, OID_GEN_XMIT_OK),
             VmxQueryStatistic(Adapter, OID_GEN_XMIT_ERROR) - Adapter->TxDropsDriver);
}

/* Receive: take the completed descriptors, indicate the frames, give the buffers back */
static
VOID
VmxReceive(
    _In_ PVMX_ADAPTER Adapter)
{
    ULONG Consumed[2] = { 0, 0 };
    BOOLEAN GotAny = FALSE;
    UINT Budget;

    for (Budget = 0; Budget < VMX_NRXCOMPDESC; Budget++)
    {
        volatile VMX_RXCOMPDESC *C = &Adapter->RxComp[Adapter->RxCompNext];
        ULONG Word0, Word2, Idx, Qid, Len, Ring;

        if (((C->Word3 >> VMX_RXC_GEN_SHIFT) & 1) != Adapter->RxCompGen)
            break;
        KeMemoryBarrier();
        Word0 = C->Word0;
        Word2 = C->Word2;
        if (++Adapter->RxCompNext == VMX_NRXCOMPDESC)
        {
            Adapter->RxCompNext = 0;
            Adapter->RxCompGen ^= 1;
        }

        Idx = Word0 & VMX_RXC_IDX_MASK;
        Qid = (Word0 >> VMX_RXC_QID_SHIFT) & VMX_RXC_QID_MASK;
        Ring = (Qid == 0) ? 0 : 1;      /* one queue: its head ring has queue id 0, its body ring queue id 1 */
        Len = Word2 & VMX_RXC_LEN_MASK;

        if (Idx >= Adapter->Rx[Ring].Size || Adapter->Rx[Ring].Posted == 0)
        {
            DbgPrint("vmxnet3: receive completion %lu of ring %lu is not valid, ignored\n", Idx, Ring);
            Adapter->RxDropsDriver++;
            continue;
        }
        Adapter->Rx[Ring].Posted--;
        Consumed[Ring]++;

        /* only frames that came in one head buffer are indicated; the others (no offload is enabled, so none are expected)
           are dropped with all their descriptors */
        if (Adapter->RxDropping)
        {
            if (Word0 & VMX_RXC_EOP)
            {
                Adapter->RxDropping = FALSE;
                Adapter->RxDropsDriver++;
            }
            continue;
        }
        if (!((Word0 & VMX_RXC_SOP) && (Word0 & VMX_RXC_EOP) && Ring == 0))
        {
            if (Word0 & VMX_RXC_EOP)
                Adapter->RxDropsDriver++;
            else
                Adapter->RxDropping = TRUE;
            continue;
        }

        if ((Word2 & VMX_RXC_ERROR) || Len < VMX_ETH_HEADER || Len > VMX_BUFFER_SIZE)
        {
            Adapter->RxDropsDriver++;
            continue;
        }

        if (Adapter->PacketFilter != 0)
        {
            PUCHAR Frame = Adapter->Rx[0].Buffers + Idx * VMX_BUFFER_SIZE;

            NdisMEthIndicateReceive(Adapter->AdapterHandle,
                                    NULL,
                                    (PCHAR)Frame,
                                    VMX_ETH_HEADER,
                                    (PCHAR)(Frame + VMX_ETH_HEADER),
                                    Len - VMX_ETH_HEADER,
                                    Len - VMX_ETH_HEADER);
            GotAny = TRUE;
        }
    }

    if (Consumed[0] != 0)
        VmxRxPost(Adapter, 0, Consumed[0]);
    if (Consumed[1] != 0)
        VmxRxPost(Adapter, 1, Consumed[1]);

    if (GotAny)
        NdisMEthIndicateReceiveComplete(Adapter->AdapterHandle);
}

/* Transmit completions: every descriptor up to the end-of-packet index of a completion is done */
static
VOID
VmxTransmitComplete(
    _In_ PVMX_ADAPTER Adapter)
{
    PNDIS_PACKET Done[32];
    UINT NumDone = 0, i, Budget;

    for (Budget = 0; Budget < VMX_NTXDESC; Budget++)
    {
        volatile VMX_TXCOMPDESC *C = &Adapter->TxComp[Adapter->TxCompNext];
        ULONG Eop, InFlight, Distance, End;

        if (((C->Word3 >> VMX_TXC_GEN_SHIFT) & 1) != Adapter->TxCompGen)
            break;
        KeMemoryBarrier();
        Eop = C->Word0 & VMX_TXC_EOPIDX_MASK;
        if (++Adapter->TxCompNext == VMX_NTXDESC)
        {
            Adapter->TxCompNext = 0;
            Adapter->TxCompGen ^= 1;
        }

        /* the index is written by the device: it must name a descriptor that is in flight */
        InFlight = (Adapter->TxProd + VMX_NTXDESC - Adapter->TxCons) % VMX_NTXDESC;
        Distance = (Eop + VMX_NTXDESC - Adapter->TxCons) % VMX_NTXDESC;
        if (Eop >= VMX_NTXDESC || Distance >= InFlight)
        {
            DbgPrint("vmxnet3: transmit completion %lu is not in flight, ignored\n", Eop);
            continue;
        }

        End = (Eop + 1) % VMX_NTXDESC;
        while (Adapter->TxCons != End)
        {
            PNDIS_PACKET Packet = Adapter->TxPackets[Adapter->TxCons];

            Adapter->TxPackets[Adapter->TxCons] = NULL;
            Adapter->TxCons = (Adapter->TxCons + 1) % VMX_NTXDESC;
            if (Packet != NULL)
            {
                Done[NumDone++] = Packet;
                if (NumDone == ARRAYSIZE(Done))
                {
                    for (i = 0; i < NumDone; i++)
                        NdisMSendComplete(Adapter->AdapterHandle, Done[i], NDIS_STATUS_SUCCESS);
                    NumDone = 0;
                }
            }
        }
    }

    for (i = 0; i < NumDone; i++)
        NdisMSendComplete(Adapter->AdapterHandle, Done[i], NDIS_STATUS_SUCCESS);
}

VOID
NTAPI
MiniportISR(
    OUT PBOOLEAN InterruptRecognized,
    OUT PBOOLEAN QueueMiniportHandleInterrupt,
    IN NDIS_HANDLE MiniportAdapterContext)
{
    PVMX_ADAPTER Adapter = (PVMX_ADAPTER)MiniportAdapterContext;
    ULONG Status = VmxRead1(Adapter, VMX_BAR1_INTR);

    /* Reading the status of the interrupt acknowledges it. All ones: the device is not there. */
    if (Status == 0 || Status == 0xFFFFFFFF)
    {
        *InterruptRecognized = FALSE;
        *QueueMiniportHandleInterrupt = FALSE;
        return;
    }

    _InterlockedOr(&Adapter->InterruptPending, 1);
    *InterruptRecognized = TRUE;
    *QueueMiniportHandleInterrupt = TRUE;
}

VOID
NTAPI
MiniportHandleInterrupt(
    IN NDIS_HANDLE MiniportAdapterContext)
{
    PVMX_ADAPTER Adapter = (PVMX_ADAPTER)MiniportAdapterContext;
    LONG Pending = _InterlockedExchange(&Adapter->InterruptPending, 0);

    if (!Adapter->Active)
        return;

    /* The device masks the interrupt when it raises it (automask): it is enabled again at the end, also when a
       DPC found nothing left to do because an earlier one took the work */
    if (Pending != 0 && Adapter->Ds->Event != 0)
    {
        ULONG Event = Adapter->Ds->Event;

        VmxWrite1(Adapter, VMX_BAR1_EVENT, Event);

        if (Event & VMX_EVENT_LINK)
        {
            VmxUpdateLink(Adapter);
            VmxPrintStatistics(Adapter, Adapter->MediaState == NdisMediaStateConnected ? "link up" : "link down");
            NdisMIndicateStatus(Adapter->AdapterHandle,
                                Adapter->MediaState == NdisMediaStateConnected ? NDIS_STATUS_MEDIA_CONNECT : NDIS_STATUS_MEDIA_DISCONNECT,
                                NULL, 0);
            NdisMIndicateStatusComplete(Adapter->AdapterHandle);
        }
        if (Event & (VMX_EVENT_TQERROR | VMX_EVENT_RQERROR))
        {
            DbgPrint("vmxnet3: queue error (event %lx): a reset is requested\n", Event);
            Adapter->NeedReset = TRUE;
        }
    }

    VmxReceive(Adapter);
    VmxTransmitComplete(Adapter);
    VmxEnableInterrupts(Adapter);
}

/* Copies the packet into the transmit buffer of the next descriptor and hands the descriptor to the device */
static
NDIS_STATUS
VmxTransmitPacket(
    _In_ PVMX_ADAPTER Adapter,
    _In_ PNDIS_PACKET Packet)
{
    PNDIS_BUFFER Buffer;
    UINT Total, Copied = 0;
    PUCHAR Dest;
    volatile VMX_TXDESC *D;
    ULONG Slot = Adapter->TxProd;

    NdisQueryPacket(Packet, NULL, NULL, &Buffer, &Total);
    if (Total > VMX_MAX_FRAME + 4 || Total < VMX_ETH_HEADER)
    {
        Adapter->TxDropsDriver++;
        return NDIS_STATUS_INVALID_LENGTH;
    }

    Dest = Adapter->TxBuffers + Slot * VMX_BUFFER_SIZE;
    while (Buffer != NULL)
    {
        PVOID Va;
        UINT Length;

        NdisQueryBuffer(Buffer, &Va, &Length);
        if (Length > Total - Copied)
            Length = Total - Copied;
        NdisMoveMemory(Dest + Copied, Va, Length);
        Copied += Length;
        NdisGetNextBuffer(Buffer, &Buffer);
    }

    Adapter->TxPackets[Slot] = Packet;

    /* The descriptor is written with the generation that the device does not take yet, then flipped: the device never sees a half written one */
    D = &Adapter->TxDesc[Slot];
    D->Addr = Adapter->TxBuffersPa.QuadPart + (ULONGLONG)Slot * VMX_BUFFER_SIZE;
    D->Word3 = VMX_TX_EOP | VMX_TX_COMPREQ;
    D->Word2 = (Copied & VMX_TX_LEN_MASK) | GENBIT(Adapter->TxGen ^ 1, VMX_TX_GEN_SHIFT);
    KeMemoryBarrier();
    D->Word2 ^= GENBIT(1, VMX_TX_GEN_SHIFT);

    if (++Adapter->TxProd == VMX_NTXDESC)
    {
        Adapter->TxProd = 0;
        Adapter->TxGen ^= 1;
    }
    return NDIS_STATUS_PENDING;
}

static
BOOLEAN
VmxTxFull(
    _In_ PVMX_ADAPTER Adapter)
{
    return ((Adapter->TxProd + 1) % VMX_NTXDESC) == Adapter->TxCons;
}

static
VOID
VmxTransmitKick(
    _In_ PVMX_ADAPTER Adapter)
{
    KeMemoryBarrier();
    VmxWrite0(Adapter, VMX_BAR0_TXH(0), Adapter->TxProd);
}

NDIS_STATUS
NTAPI
MiniportSend(
    _In_ NDIS_HANDLE MiniportAdapterContext,
    _In_ PNDIS_PACKET Packet,
    _In_ UINT Flags)
{
    PVMX_ADAPTER Adapter = (PVMX_ADAPTER)MiniportAdapterContext;
    NDIS_STATUS Status;

    if (!Adapter->Active)
        return NDIS_STATUS_FAILURE;
    if (VmxTxFull(Adapter))
        return NDIS_STATUS_RESOURCES;

    Status = VmxTransmitPacket(Adapter, Packet);
    if (Status == NDIS_STATUS_PENDING)
        VmxTransmitKick(Adapter);
    return Status;
}

VOID
NTAPI
MiniportSendPackets(
    _In_ NDIS_HANDLE MiniportAdapterContext,
    _In_ PPNDIS_PACKET PacketArray,
    _In_ UINT NumberOfPackets)
{
    PVMX_ADAPTER Adapter = (PVMX_ADAPTER)MiniportAdapterContext;
    UINT i;
    BOOLEAN Queued = FALSE;

    for (i = 0; i < NumberOfPackets; i++)
    {
        NDIS_STATUS Status;

        if (!Adapter->Active)
            Status = NDIS_STATUS_FAILURE;
        else if (VmxTxFull(Adapter))
            Status = NDIS_STATUS_RESOURCES;
        else
        {
            Status = VmxTransmitPacket(Adapter, PacketArray[i]);
            Queued |= (Status == NDIS_STATUS_PENDING);
        }
        NDIS_SET_PACKET_STATUS(PacketArray[i], Status);
    }

    if (Queued)
        VmxTransmitKick(Adapter);
}

static
VOID
NTAPI
MiniportHalt(
    IN NDIS_HANDLE MiniportAdapterContext)
{
    PVMX_ADAPTER Adapter = (PVMX_ADAPTER)MiniportAdapterContext;

    if (Adapter->Bar1 != NULL && Adapter->Ctl != NULL)
    {
        if (Adapter->Active)
            VmxPrintStatistics(Adapter, "halt");
        VmxQuiesce(Adapter, FALSE);
    }

    if (Adapter->InterruptRegistered)
    {
        NdisMDeregisterInterrupt(&Adapter->Interrupt);
        Adapter->InterruptRegistered = FALSE;
    }

    VmxFreeResources(Adapter);
    NdisFreeMemory(Adapter, sizeof(*Adapter), 0);
}

static
BOOLEAN
NTAPI
MiniportCheckForHang(
    IN NDIS_HANDLE MiniportAdapterContext)
{
    return ((PVMX_ADAPTER)MiniportAdapterContext)->NeedReset;
}

static
NDIS_STATUS
NTAPI
MiniportReset(
    OUT PBOOLEAN AddressingReset,
    IN NDIS_HANDLE MiniportAdapterContext)
{
    PVMX_ADAPTER Adapter = (PVMX_ADAPTER)MiniportAdapterContext;
    NDIS_STATUS Status;

    *AddressingReset = FALSE;

    VmxQuiesce(Adapter, TRUE);
    Adapter->NeedReset = FALSE;
    Status = VmxActivate(Adapter);
    if (Status != NDIS_STATUS_SUCCESS)
        DbgPrint("vmxnet3: the reset did not bring the device back\n");
    return Status;
}

static
NDIS_STATUS
NTAPI
MiniportInitialize(
    OUT PNDIS_STATUS OpenErrorStatus,
    OUT PUINT SelectedMediumIndex,
    IN PNDIS_MEDIUM MediumArray,
    IN UINT MediumArraySize,
    IN NDIS_HANDLE MiniportAdapterHandle,
    IN NDIS_HANDLE WrapperConfigurationContext)
{
    PVMX_ADAPTER Adapter;
    NDIS_STATUS Status;
    UINT i;
    PNDIS_RESOURCE_LIST ResourceList = NULL;
    UINT ResourceListSize = 0;
    PCI_COMMON_CONFIG PciConfig;
    ULONG Version;

    UNREFERENCED_PARAMETER(OpenErrorStatus);

    for (i = 0; i < MediumArraySize; i++)
    {
        if (MediumArray[i] == NdisMedium802_3)
        {
            *SelectedMediumIndex = i;
            break;
        }
    }
    if (i == MediumArraySize)
        return NDIS_STATUS_UNSUPPORTED_MEDIA;

    Status = NdisAllocateMemoryWithTag((PVOID*)&Adapter, sizeof(*Adapter), VMX_TAG);
    if (Status != NDIS_STATUS_SUCCESS)
        return NDIS_STATUS_RESOURCES;

    RtlZeroMemory(Adapter, sizeof(*Adapter));
    Adapter->AdapterHandle = MiniportAdapterHandle;

    NdisMSetAttributesEx(MiniportAdapterHandle, Adapter, 0, NDIS_ATTRIBUTE_BUS_MASTER, NdisInterfacePci);

    NdisReadPciSlotInformation(MiniportAdapterHandle, 0, FIELD_OFFSET(PCI_COMMON_CONFIG, VendorID), &PciConfig, sizeof(PciConfig));
    if (PciConfig.VendorID != VMX_PCI_VENDOR_VMWARE || PciConfig.DeviceID != VMX_PCI_DEVICE_VMXNET3)
    {
        Status = NDIS_STATUS_UNSUPPORTED_MEDIA;
        goto Cleanup;
    }

    NdisMQueryAdapterResources(&Status, WrapperConfigurationContext, ResourceList, &ResourceListSize);
    if (Status != NDIS_STATUS_RESOURCES)
    {
        Status = NDIS_STATUS_FAILURE;
        goto Cleanup;
    }
    Status = NdisAllocateMemoryWithTag((PVOID*)&ResourceList, ResourceListSize, VMX_TAG);
    if (Status != NDIS_STATUS_SUCCESS)
        goto Cleanup;
    NdisMQueryAdapterResources(&Status, WrapperConfigurationContext, ResourceList, &ResourceListSize);
    if (Status != NDIS_STATUS_SUCCESS)
        goto Cleanup;

    Status = VmxParseResources(Adapter, ResourceList, &PciConfig);
    NdisFreeMemory(ResourceList, ResourceListSize, 0);
    ResourceList = NULL;
    if (Status != NDIS_STATUS_SUCCESS)
        goto Cleanup;

    Status = NdisMInitializeScatterGatherDma(MiniportAdapterHandle, FALSE, VMX_BUFFER_SIZE);
    if (Status != NDIS_STATUS_SUCCESS)
    {
        Status = NDIS_STATUS_RESOURCES;
        goto Cleanup;
    }

    Status = VmxAllocateResources(Adapter);
    if (Status != NDIS_STATUS_SUCCESS)
        goto Cleanup;

    /* the revision of the device interface and of the passthrough interface: version 1 of both is what the driver speaks */
    Version = VmxRead1(Adapter, VMX_BAR1_VRRS);
    if (Version == 0xFFFFFFFF || !(Version & 1))
    {
        DbgPrint("vmxnet3: unsupported device revision %lx\n", Version);
        Status = NDIS_STATUS_FAILURE;
        goto Cleanup;
    }
    VmxWrite1(Adapter, VMX_BAR1_VRRS, 1);
    Version = VmxRead1(Adapter, VMX_BAR1_UVRS);
    if (!(Version & 1))
    {
        DbgPrint("vmxnet3: unsupported passthrough version %lx\n", Version);
        Status = NDIS_STATUS_FAILURE;
        goto Cleanup;
    }
    VmxWrite1(Adapter, VMX_BAR1_UVRS, 1);

    VmxCommand(Adapter, VMX_CMD_RESET);

    Status = VmxReadMac(Adapter);
    if (Status != NDIS_STATUS_SUCCESS)
        goto Cleanup;

    Status = NdisMRegisterInterrupt(&Adapter->Interrupt,
                                    Adapter->AdapterHandle,
                                    Adapter->InterruptVector,
                                    Adapter->InterruptLevel,
                                    TRUE,
                                    Adapter->InterruptShared,
                                    (Adapter->InterruptFlags & CM_RESOURCE_INTERRUPT_LATCHED) ?
                                    NdisInterruptLatched : NdisInterruptLevelSensitive);
    if (Status != NDIS_STATUS_SUCCESS)
        goto Cleanup;
    Adapter->InterruptRegistered = TRUE;

    Status = VmxActivate(Adapter);
    if (Status != NDIS_STATUS_SUCCESS)
        goto Cleanup;

    return NDIS_STATUS_SUCCESS;

Cleanup:
    if (ResourceList != NULL)
        NdisFreeMemory(ResourceList, ResourceListSize, 0);
    MiniportHalt(Adapter);
    return Status;
}

NTSTATUS
NTAPI
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath)
{
    NDIS_HANDLE WrapperHandle;
    NDIS_MINIPORT_CHARACTERISTICS Characteristics = { 0 };
    NDIS_STATUS Status;

    Characteristics.MajorNdisVersion = NDIS_MINIPORT_MAJOR_VERSION;
    Characteristics.MinorNdisVersion = NDIS_MINIPORT_MINOR_VERSION;
    Characteristics.CheckForHangHandler = MiniportCheckForHang;
    Characteristics.HaltHandler = MiniportHalt;
    Characteristics.HandleInterruptHandler = MiniportHandleInterrupt;
    Characteristics.InitializeHandler = MiniportInitialize;
    Characteristics.ISRHandler = MiniportISR;
    Characteristics.QueryInformationHandler = MiniportQueryInformation;
    Characteristics.ResetHandler = MiniportReset;
    Characteristics.SendHandler = MiniportSend;
    Characteristics.SetInformationHandler = MiniportSetInformation;
    Characteristics.SendPacketsHandler = MiniportSendPackets;

    NdisMInitializeWrapper(&WrapperHandle, DriverObject, RegistryPath, NULL);
    if (WrapperHandle == NULL)
        return NDIS_STATUS_FAILURE;

    Status = NdisMRegisterMiniport(WrapperHandle, &Characteristics, sizeof(Characteristics));
    if (Status != NDIS_STATUS_SUCCESS)
    {
        NdisTerminateWrapper(WrapperHandle, 0);
        return NDIS_STATUS_FAILURE;
    }
    return NDIS_STATUS_SUCCESS;
}
