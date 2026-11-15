/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        include/arp.h
 * PURPOSE:     Address Resolution Protocol definitions
 */

#pragma once

typedef struct ARP_HEADER {
    USHORT HWType;       /* Hardware Type */
    USHORT ProtoType;    /* Protocol Type */
    UCHAR  HWAddrLen;    /* Hardware Address Length */
    UCHAR  ProtoAddrLen; /* Protocol Address Length */
    USHORT Opcode;       /* Opcode */
    /* Sender's Hardware Address */
    /* Sender's Protocol Address */
    /* Target's Hardware Address */
    /* Target's Protocol Address */
} ARP_HEADER, *PARP_HEADER;

/* We swap constants so we can compare values at runtime without swapping them */
#define ARP_OPCODE_REQUEST WH2N(0x0001) /* ARP request */
#define ARP_OPCODE_REPLY   WH2N(0x0002) /* ARP reply */


/* Largest link-layer address an ARP table entry (IPARP_ENTRY.PhysAddr) holds */
#define ARP_MAX_LINK_ADDRESS_LENGTH 8

/* Wire-field contract for an incoming ARP packet: the hardware address length
   must be exactly the receiving interface's link address length (and fit a
   neighbor table entry), and the protocol address length must be that of IPv4.
   Anything else is rejected before any variable-length field is used. */
static __inline BOOLEAN ARPValidateAddressLengths(
    UINT HWAddrLen,
    UINT ProtoAddrLen,
    UINT InterfaceAddressLength)
{
    if (HWAddrLen == 0 || HWAddrLen > ARP_MAX_LINK_ADDRESS_LENGTH)
        return FALSE;
    if (HWAddrLen != InterfaceAddressLength)
        return FALSE;
    return ProtoAddrLen == 4;
}

BOOLEAN ARPTransmit(PIP_ADDRESS Address, PVOID LinkAddress, PIP_INTERFACE Interface);
BOOLEAN ARPTransmitGratuitous(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Address);

VOID ARPReceive(
    PVOID Context,
    PIP_PACKET Packet);

/* EOF */
