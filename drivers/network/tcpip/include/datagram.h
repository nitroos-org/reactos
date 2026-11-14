/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        include/datagram.h
 * PURPOSE:     Datagram types and constants
 */

#pragma once

#include <titypes.h>

NTSTATUS DGReceiveDatagram(
    PADDRESS_FILE AddrFile,
    PTDI_CONNECTION_INFORMATION ConnInfo,
    PCHAR Buffer,
    ULONG ReceiveLength,
    ULONG ReceiveFlags,
    PTDI_CONNECTION_INFORMATION ReturnInfo,
    PULONG BytesReceived,
    PDATAGRAM_COMPLETION_ROUTINE Complete,
    PVOID Context,
    PIRP Irp);

BOOLEAN DGRemoveIRP(
    PADDRESS_FILE AddrFile,
    PIRP Irp);

/* What an IPv6 datagram's receive reports besides its addresses (ip/transport/udp/udp6.c): the scope id of a
   link-local source (the interface index), the interface it arrived on and its hop limit */
typedef struct _DG_RX_INFO6 {
    ULONG SrcScopeId;
    ULONG IfIndex;
    ULONG HopLimit;
} DG_RX_INFO6, *PDG_RX_INFO6;

VOID DGDeliverDataEx(
  PIP_INTERFACE Interface,
  PADDRESS_FILE AddrFile,
  PIP_ADDRESS SrcAddress,
  PIP_ADDRESS DstAddress,
  USHORT SrcPort,
  USHORT DstPort,
  PIP_PACKET IPPacket,
  UINT DataSize,
  PDG_RX_INFO6 Info6);

VOID DGDeliverData(
  PIP_INTERFACE Interface,
  PADDRESS_FILE AddrFile,
  PIP_ADDRESS SrcAddress,
  PIP_ADDRESS DstAddress,
  USHORT SrcPort,
  USHORT DstPort,
  PIP_PACKET IPPacket,
  UINT DataSize);

/* EOF */
