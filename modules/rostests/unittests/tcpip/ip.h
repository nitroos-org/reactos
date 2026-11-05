/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     User mode stand-in for the tcpip ip.h, for network/receive.c
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

/* The definitions receive.c and receive.h use, as in drivers/network/tcpip/include/ip.h */

typedef ULONG IPv4_RAW_ADDRESS;
typedef USHORT IPv6_RAW_ADDRESS[8];

typedef struct IP_ADDRESS {
    UCHAR Type;
    union {
        IPv4_RAW_ADDRESS IPv4Address;
        IPv6_RAW_ADDRESS IPv6Address;
    } Address;
} IP_ADDRESS, *PIP_ADDRESS;

#define IP_ADDRESS_V4   0x04
#define IP_ADDRESS_V6   0x06

typedef struct IPv4_HEADER {
    UCHAR VerIHL;
    UCHAR Tos;
    USHORT TotalLength;
    USHORT Id;
    USHORT FlagsFragOfs;
    UCHAR Ttl;
    UCHAR Protocol;
    USHORT Checksum;
    IPv4_RAW_ADDRESS SrcAddr;
    IPv4_RAW_ADDRESS DstAddr;
} IPv4_HEADER, *PIPv4_HEADER;

typedef union _IP_HEADER {
    IPv4_HEADER v4;
} IP_HEADER, *PIP_HEADER;

#define IPv4_FRAGOFS_MASK       0x1FFF
#define IPv4_MF_MASK            0x2000
#define IPv4_MAX_HEADER_SIZE    60

/* The test's NDIS packet: one flat buffer */
typedef struct _NDIS_PACKET {
    PUCHAR Data;
    UINT Length;
} NDIS_PACKET, *PNDIS_PACKET;

typedef VOID (*OBJECT_FREE_ROUTINE)(PVOID Object);

typedef struct _IP_PACKET {
    OBJECT_FREE_ROUTINE Free;
    UCHAR Type;
    UCHAR Flags;
    BOOLEAN MappedHeader;
    BOOLEAN ReturnPacket;
    PVOID Header;
    UINT HeaderSize;
    PVOID Data;
    UINT TotalSize;
    UINT Position;
    PNDIS_PACKET NdisPacket;
    IP_ADDRESS SrcAddr;
    IP_ADDRESS DstAddr;
    BOOLEAN FromOwnLink;
} IP_PACKET, *PIP_PACKET;

typedef struct _IP_INTERFACE {
    ULONG Unused;
} IP_INTERFACE, *PIP_INTERFACE;
