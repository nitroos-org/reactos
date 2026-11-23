/*
 * PROJECT:     ReactOS VMware vmxnet3 NDIS miniport driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Device interface, adapter structure and prototypes
 * COPYRIGHT:   Copyright 2026 ReactOS Project contributors
 *
 * The register offsets, the commands and the layouts of the descriptors and of the shared
 * structures in the first part of this file describe the vmxnet3 device interface. They were
 * taken from the OpenBSD driver vmx(4), sys/dev/pci/if_vmxreg.h revision 1.10 and the start-up
 * order of sys/dev/pci/if_vmx.c revision 1.96, which carry this notice:
 *
 *   Copyright (c) 2013 Tsubai Masanari
 *
 *   Permission to use, copy, modify, and distribute this software for any
 *   purpose with or without fee is hereby granted, provided that the above
 *   copyright notice and this permission notice appear in all copies.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * The driver code itself is new (an NDIS 5.1 miniport with one transmit and one receive queue,
 * INTx interrupts and no offloads).
 */

#pragma once

#include <ndis.h>

#define VMX_TAG                     'xmVX'

/* PCI */
#define VMX_PCI_VENDOR_VMWARE       0x15AD
#define VMX_PCI_DEVICE_VMXNET3      0x07B0

/* BAR0: queue registers, BAR1: configuration registers */
#define VMX_BAR0_IMASK(irq)         (0x000 + (irq) * 8)
#define VMX_BAR0_TXH(q)             (0x600 + (q) * 8)
#define VMX_BAR0_RXH1(q)            (0x800 + (q) * 8)
#define VMX_BAR0_RXH2(q)            (0xA00 + (q) * 8)
#define VMX_BAR0_MIN_LENGTH         0xA08

#define VMX_BAR1_VRRS               0x000
#define VMX_BAR1_UVRS               0x008
#define VMX_BAR1_DSL                0x010
#define VMX_BAR1_DSH                0x018
#define VMX_BAR1_CMD                0x020
#define VMX_BAR1_MACL               0x028
#define VMX_BAR1_MACH               0x030
#define VMX_BAR1_INTR               0x038
#define VMX_BAR1_EVENT              0x040
#define VMX_BAR1_MIN_LENGTH         0x048

#define VMX_CMD_ENABLE              0xCAFE0000
#define VMX_CMD_DISABLE             0xCAFE0001
#define VMX_CMD_RESET               0xCAFE0002
#define VMX_CMD_SET_RXMODE          0xCAFE0003
#define VMX_CMD_SET_FILTER          0xCAFE0004
#define VMX_CMD_GET_STATUS          0xF00D0000
#define VMX_CMD_GET_STATS           0xF00D0001
#define VMX_CMD_GET_LINK            0xF00D0002
#define VMX_CMD_GET_MACL            0xF00D0003
#define VMX_CMD_GET_MACH            0xF00D0004

#define VMX_REV1_MAGIC              0xBABEFEE1
#define VMX_GOS_WINDOWS             0x08
#define VMX_GOS_32BIT               0x01
#define VMX_GOS_64BIT               0x02
#define VMX_ICTRL_DISABLE_ALL       0x01
#define VMX_IMOD_ADAPTIVE           8
#define VMX_MAX_INTRS               25      /* 8 transmit + 16 receive queues + 1 */

#define VMX_RXMODE_UCAST            0x01
#define VMX_RXMODE_MCAST            0x02
#define VMX_RXMODE_BCAST            0x04
#define VMX_RXMODE_ALLMULTI         0x08
#define VMX_RXMODE_PROMISC          0x10

#define VMX_EVENT_RQERROR           0x01
#define VMX_EVENT_TQERROR           0x02
#define VMX_EVENT_LINK              0x04
#define VMX_EVENT_DIC               0x08
#define VMX_EVENT_DEBUG             0x10

/* Descriptors (little endian) */
#define VMX_TX_LEN_MASK             0x00003FFF
#define VMX_TX_GEN_SHIFT            14
#define VMX_TX_EOP                  0x00001000      /* in word3 */
#define VMX_TX_COMPREQ              0x00002000      /* in word3 */

#define VMX_TXC_EOPIDX_MASK         0x00000FFF
#define VMX_TXC_GEN_SHIFT           31

#define VMX_RX_LEN_MASK             0x00003FFF
#define VMX_RX_BTYPE_SHIFT          14
#define VMX_RX_GEN_SHIFT            31
#define VMX_BTYPE_HEAD              0
#define VMX_BTYPE_BODY              1

#define VMX_RXC_IDX_MASK            0x00000FFF
#define VMX_RXC_EOP                 0x00004000      /* in word0 */
#define VMX_RXC_SOP                 0x00008000      /* in word0 */
#define VMX_RXC_QID_SHIFT           16
#define VMX_RXC_QID_MASK            0x000003FF
#define VMX_RXC_LEN_MASK            0x00003FFF      /* in word2 */
#define VMX_RXC_ERROR               0x00004000      /* in word2 */
#define VMX_RXC_GEN_SHIFT           31              /* in word3 */

#include <pshpack1.h>

typedef struct _VMX_TXDESC
{
    ULONGLONG Addr;
    ULONG Word2;
    ULONG Word3;
} VMX_TXDESC, *PVMX_TXDESC;

typedef struct _VMX_TXCOMPDESC
{
    ULONG Word0;
    ULONG Word1;
    ULONG Word2;
    ULONG Word3;
} VMX_TXCOMPDESC, *PVMX_TXCOMPDESC;

typedef struct _VMX_RXDESC
{
    ULONGLONG Addr;
    ULONG Word2;
    ULONG Word3;
} VMX_RXDESC, *PVMX_RXDESC;

typedef struct _VMX_RXCOMPDESC
{
    ULONG Word0;
    ULONG Word1;
    ULONG Word2;
    ULONG Word3;
} VMX_RXCOMPDESC, *PVMX_RXCOMPDESC;

typedef struct _VMX_DRIVER_SHARED
{
    ULONG Magic;
    ULONG Pad1;
    ULONG Version;
    ULONG Guest;
    ULONG Vmxnet3Revision;
    ULONG UptVersion;
    ULONGLONG UptFeatures;
    ULONGLONG DriverData;
    ULONGLONG QueueShared;
    ULONG DriverDataLen;
    ULONG QueueSharedLen;
    ULONG Mtu;
    USHORT NrxsgMax;
    UCHAR NTxQueue;
    UCHAR NRxQueue;
    ULONG Reserved1[4];
    UCHAR Automask;
    UCHAR NIntr;
    UCHAR EvIntr;
    UCHAR ModLevel[VMX_MAX_INTRS];
    ULONG Ictrl;
    ULONG Reserved2[2];
    ULONG RxMode;
    USHORT McastTableLen;
    USHORT Pad2;
    ULONGLONG McastTable;
    ULONG VlanFilter[4096 / 32];
    struct
    {
        ULONG Version;
        ULONG Len;
        ULONGLONG PAddr;
    } Rss, Pm, Plugin;
    ULONG Event;
    ULONG Reserved3[5];
} VMX_DRIVER_SHARED, *PVMX_DRIVER_SHARED;

#define VMX_TXSTATS_COUNT           10
#define VMX_RXSTATS_COUNT           10
/* indices of the statistics arrays */
#define VMX_TXSTAT_UCAST_PACKETS    2
#define VMX_TXSTAT_MCAST_PACKETS    4
#define VMX_TXSTAT_BCAST_PACKETS    6
#define VMX_TXSTAT_ERROR            8
#define VMX_TXSTAT_DISCARD          9
#define VMX_RXSTAT_UCAST_PACKETS    2
#define VMX_RXSTAT_MCAST_PACKETS    4
#define VMX_RXSTAT_BCAST_PACKETS    6
#define VMX_RXSTAT_NOBUFFER         8
#define VMX_RXSTAT_ERROR            9

typedef struct _VMX_TXQ_SHARED
{
    ULONG NPending;
    ULONG IntrThreshold;
    ULONGLONG Reserved1;
    ULONGLONG CmdRing;
    ULONGLONG DataRing;
    ULONGLONG CompRing;
    ULONGLONG DriverData;
    ULONGLONG Reserved2;
    ULONG CmdRingLen;
    ULONG DataRingLen;
    ULONG CompRingLen;
    ULONG DriverDataLen;
    UCHAR IntrIdx;
    UCHAR Pad1[7];
    UCHAR Stopped;
    UCHAR Pad2[3];
    ULONG Error;
    ULONGLONG Stats[VMX_TXSTATS_COUNT];
    UCHAR Pad3[88];
} VMX_TXQ_SHARED, *PVMX_TXQ_SHARED;

typedef struct _VMX_RXQ_SHARED
{
    UCHAR UpdateRxHead;
    UCHAR Pad1[7];
    ULONGLONG Reserved1;
    ULONGLONG CmdRing[2];
    ULONGLONG CompRing;
    ULONGLONG DriverData;
    ULONGLONG Reserved2;
    ULONG CmdRingLen[2];
    ULONG CompRingLen;
    ULONG DriverDataLen;
    UCHAR IntrIdx;
    UCHAR Pad2[7];
    UCHAR Stopped;
    UCHAR Pad3[3];
    ULONG Error;
    ULONGLONG Stats[VMX_RXSTATS_COUNT];
    UCHAR Pad4[88];
} VMX_RXQ_SHARED, *PVMX_RXQ_SHARED;

#include <poppack.h>

C_ASSERT(sizeof(VMX_TXDESC) == 16);
C_ASSERT(sizeof(VMX_TXCOMPDESC) == 16);
C_ASSERT(sizeof(VMX_RXDESC) == 16);
C_ASSERT(sizeof(VMX_RXCOMPDESC) == 16);
C_ASSERT(sizeof(VMX_DRIVER_SHARED) == 720);
C_ASSERT(sizeof(VMX_TXQ_SHARED) == 256);
C_ASSERT(sizeof(VMX_RXQ_SHARED) == 256);

/* Driver layout */
#define VMX_NTXDESC                 256
#define VMX_NRXDESC0                256         /* head ring */
#define VMX_NRXDESC1                64          /* body ring: only used for frames that do not fit a head buffer */
#define VMX_NRXCOMPDESC             (VMX_NRXDESC0 + VMX_NRXDESC1)
#define VMX_BUFFER_SIZE             2048        /* transmit and receive buffers */
#define VMX_ETH_HEADER              14
#define VMX_MAX_FRAME               1514        /* Ethernet header and 1500 bytes */
#define VMX_MTU                     1500
#define VMX_MAX_MULTICAST           64
#define VMX_MCAST_TABLE_BYTES       (682 * 6)   /* what the shared page can describe */

C_ASSERT((VMX_NTXDESC % 32) == 0 && (VMX_NRXDESC0 % 32) == 0 && (VMX_NRXDESC1 % 32) == 0);
C_ASSERT(VMX_NRXCOMPDESC <= 0x1000 && VMX_NTXDESC <= 0x1000);

/* The control block: shared structures, tables, rings (page aligned pieces) */
#define VMX_OFF_DS                  0
#define VMX_OFF_QS                  1024
#define VMX_OFF_MCAST               4096
#define VMX_OFF_TXD                 8192
#define VMX_OFF_TXC                 (VMX_OFF_TXD + 4096)
#define VMX_OFF_RXD0                (VMX_OFF_TXC + 4096)
#define VMX_OFF_RXD1                (VMX_OFF_RXD0 + 4096)
#define VMX_OFF_RXC                 (VMX_OFF_RXD1 + 4096)
#define VMX_CTL_SIZE                (VMX_OFF_RXC + 8192)

C_ASSERT(VMX_NTXDESC * sizeof(VMX_TXDESC) <= 4096);
C_ASSERT(VMX_NTXDESC * sizeof(VMX_TXCOMPDESC) <= 4096);
C_ASSERT(VMX_NRXDESC0 * sizeof(VMX_RXDESC) <= 4096);
C_ASSERT(VMX_NRXDESC1 * sizeof(VMX_RXDESC) <= 4096);
C_ASSERT(VMX_NRXCOMPDESC * sizeof(VMX_RXCOMPDESC) <= 8192);
C_ASSERT(VMX_OFF_QS + 2 * 256 <= VMX_OFF_MCAST);
C_ASSERT(VMX_MCAST_TABLE_BYTES <= VMX_OFF_TXD - VMX_OFF_MCAST);

typedef struct _VMX_RXRING
{
    PVMX_RXDESC Desc;
    PUCHAR Buffers;                 /* one buffer per descriptor */
    ULONGLONG BuffersPa;
    ULONG Size;
    ULONG Fill;                     /* the next descriptor to give to the device */
    ULONG Gen;                      /* its generation bit (0 or 1) */
    ULONG Posted;                   /* descriptors the device owns */
    ULONG Btype;
    ULONG HeadReg;
} VMX_RXRING;

typedef struct _VMX_ADAPTER
{
    NDIS_HANDLE AdapterHandle;

    /* BAR0 and BAR1 */
    volatile PUCHAR Bar0;
    volatile PUCHAR Bar1;
    NDIS_PHYSICAL_ADDRESS Bar0Pa;
    NDIS_PHYSICAL_ADDRESS Bar1Pa;
    ULONG Bar0Length;
    ULONG Bar1Length;

    /* Interrupt */
    ULONG InterruptVector;
    ULONG InterruptLevel;
    BOOLEAN InterruptShared;
    ULONG InterruptFlags;
    NDIS_MINIPORT_INTERRUPT Interrupt;
    BOOLEAN InterruptRegistered;
    _Interlocked_ volatile LONG InterruptPending;

    UCHAR PermanentMacAddress[ETH_LENGTH_OF_ADDRESS];
    UCHAR MulticastList[VMX_MAX_MULTICAST][ETH_LENGTH_OF_ADDRESS];
    ULONG MulticastListSize;
    ULONG PacketFilter;
    ULONG MediaState;
    ULONG LinkSpeedMbps;
    BOOLEAN NeedReset;
    BOOLEAN Active;

    /* Shared memory */
    PUCHAR Ctl;
    NDIS_PHYSICAL_ADDRESS CtlPa;
    PUCHAR TxBuffers;
    NDIS_PHYSICAL_ADDRESS TxBuffersPa;
    PUCHAR RxBuffers;
    NDIS_PHYSICAL_ADDRESS RxBuffersPa;

    PVMX_DRIVER_SHARED Ds;
    PVMX_TXQ_SHARED Ts;
    PVMX_RXQ_SHARED Rs;
    PUCHAR McastTable;

    /* Transmit */
    PVMX_TXDESC TxDesc;
    PVMX_TXCOMPDESC TxComp;
    PNDIS_PACKET TxPackets[VMX_NTXDESC];
    ULONG TxProd;
    ULONG TxCons;
    ULONG TxGen;
    ULONG TxCompNext;
    ULONG TxCompGen;

    /* Receive */
    VMX_RXRING Rx[2];
    PVMX_RXCOMPDESC RxComp;
    ULONG RxCompNext;
    ULONG RxCompGen;
    BOOLEAN RxDropping;

    /* Statistics of the driver (the device keeps its own, read with GET_STATS) */
    ULONG64 RxDropsDriver;
    ULONG64 TxDropsDriver;
} VMX_ADAPTER, *PVMX_ADAPTER;

FORCEINLINE ULONG
VmxRead0(PVMX_ADAPTER A, ULONG Reg)
{
    ULONG V;
    NdisReadRegisterUlong((PULONG)(A->Bar0 + Reg), &V);
    return V;
}

FORCEINLINE VOID
VmxWrite0(PVMX_ADAPTER A, ULONG Reg, ULONG V)
{
    NdisWriteRegisterUlong((PULONG)(A->Bar0 + Reg), V);
}

FORCEINLINE ULONG
VmxRead1(PVMX_ADAPTER A, ULONG Reg)
{
    ULONG V;
    NdisReadRegisterUlong((PULONG)(A->Bar1 + Reg), &V);
    return V;
}

FORCEINLINE VOID
VmxWrite1(PVMX_ADAPTER A, ULONG Reg, ULONG V)
{
    NdisWriteRegisterUlong((PULONG)(A->Bar1 + Reg), V);
}

/* A command: write it, then read the answer from the same register */
FORCEINLINE ULONG
VmxCommand(PVMX_ADAPTER A, ULONG Cmd)
{
    VmxWrite1(A, VMX_BAR1_CMD, Cmd);
    return VmxRead1(A, VMX_BAR1_CMD);
}

NDIS_STATUS NTAPI MiniportQueryInformation(NDIS_HANDLE, NDIS_OID, PVOID, ULONG, PULONG, PULONG);
NDIS_STATUS NTAPI MiniportSetInformation(NDIS_HANDLE, NDIS_OID, PVOID, ULONG, PULONG, PULONG);
VOID NTAPI MiniportISR(PBOOLEAN, PBOOLEAN, NDIS_HANDLE);
VOID NTAPI MiniportHandleInterrupt(NDIS_HANDLE);
NDIS_STATUS NTAPI MiniportSend(NDIS_HANDLE, PNDIS_PACKET, UINT);
VOID NTAPI MiniportSendPackets(NDIS_HANDLE, PPNDIS_PACKET, UINT);

NDIS_STATUS VmxApplyPacketFilter(PVMX_ADAPTER Adapter);
VOID VmxUpdateLink(PVMX_ADAPTER Adapter);
ULONG64 VmxQueryStatistic(PVMX_ADAPTER Adapter, NDIS_OID Oid);
