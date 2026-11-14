/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     User mode stand-in for the tcpip precomp.h, for network/receive.c
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

#include <apitest.h>

#define WIN32_NO_STATUS
#include <ndk/rtlfuncs.h>

typedef UCHAR KIRQL, *PKIRQL;
typedef ULONG_PTR KSPIN_LOCK, *PKSPIN_LOCK;

#include <ip.h>

/* The lookaside lists hand out blocks of the size the test sets */
typedef struct _NPAGED_LOOKASIDE_LIST {
    SIZE_T Size;
} NPAGED_LOOKASIDE_LIST, *PNPAGED_LOOKASIDE_LIST;

#include "../../../../drivers/network/tcpip/include/receive.h"

/* KERNEL AND TCPIP DEFINITIONS (MOCK) ****************************************/

#ifndef ASSERT
#define ASSERT(x) ok((x), "ASSERT(%s)\n", #x)
#endif
#define PAGED_CODE()
#define TI_DbgPrint(Level, Args)
#define DISPLAY_IP_PACKET(Packet)
#define NonPagedPool 0
#define PACKET_BUFFER_TAG 'pbPI'
#define WN2H(w) ((USHORT)((((w) & 0xFF) << 8) | (((w) >> 8) & 0xFF)))
#define WH2N(w) WN2H(w)

#define TcpipInitializeSpinLock(Lock)
#define TcpipAcquireSpinLock(Lock, Irql) (*(Irql) = 0)
#define TcpipReleaseSpinLock(Lock, Irql)
#define TcpipAcquireSpinLockAtDpcLevel(Lock)
#define TcpipReleaseSpinLockFromDpcLevel(Lock)
#define KeTryToAcquireSpinLockAtDpcLevel(Lock) TRUE
#define TcpipInterlockedInsertTailList(Head, Entry, Lock) InsertTailList((Head), (Entry))

/* Allocation accounting, so a test can tell that nothing leaked */
extern LONG TestPoolBlocks;
extern LONG TestNdisPackets;

PVOID ExAllocatePoolWithTag(ULONG PoolType, SIZE_T NumberOfBytes, ULONG Tag);
VOID ExFreePoolWithTag(PVOID P, ULONG Tag);
PVOID ExAllocateFromNPagedLookasideList(PNPAGED_LOOKASIDE_LIST List);
VOID ExFreeToNPagedLookasideList(PNPAGED_LOOKASIDE_LIST List, PVOID Entry);
UINT CopyPacketToBuffer(PCHAR DstData, PNDIS_PACKET SrcPacket, UINT SrcOffset, UINT Length);
VOID FreeNdisPacket(PNDIS_PACKET Packet);
VOID NdisReturnPackets(PNDIS_PACKET *Packets, UINT Count);
PIP_PACKET IPInitializePacket(PIP_PACKET IPPacket, ULONG Type);
VOID IPDispatchProtocol(PIP_INTERFACE Interface, PIP_PACKET IPPacket);
BOOLEAN IPv4CorrectChecksum(PVOID Data, UINT Count);
USHORT IPv4Checksum(PVOID Data, UINT Count, ULONG Seed);
VOID AddrInitIPv4(PIP_ADDRESS IPAddress, IPv4_RAW_ADDRESS RawAddress);
BOOLEAN AddrIsEqual(PIP_ADDRESS Address1, PIP_ADDRESS Address2);

/* IPv6 (ip/transport/tcp/if6.c) */
extern BOOLEAN TCPIpv6Enabled;
VOID TCPReceive6(PIP_INTERFACE IF, PIP_PACKET IPPacket);
