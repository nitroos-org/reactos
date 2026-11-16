/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        include/rawip.h
 * PURPOSE:     Raw IP types and constants
 */

#pragma once

NTSTATUS RawIPSendDatagram(
    PADDRESS_FILE AddrFile,
    PTDI_CONNECTION_INFORMATION ConnInfo,
    PCHAR Buffer,
    ULONG DataSize,
    PULONG DataUsed);

VOID RawIpReceive(
    PIP_INTERFACE Interface,
    PIP_PACKET IPPacket);

/* Raw IPv6 sockets (ip/transport/rawip/rawip6.c) */
NTSTATUS RawIPSendDatagram6(
    PADDRESS_FILE AddrFile,
    PTDI_CONNECTION_INFORMATION ConnInfo,
    PCHAR Buffer,
    ULONG DataSize,
    PULONG DataUsed);
BOOLEAN RawIp6IsRawFile(PADDRESS_FILE AddrFile);
VOID RawIp6Startup(VOID);
extern volatile LONG RawIp6Sockets;

/* An unprivileged raw IPv4 socket (an ICMP one of a standard user) sends echo requests only (rawip.c) */
BOOLEAN RawIpUnprivilegedMaySend(PADDRESS_FILE AddrFile, PCHAR Data, ULONG Size);

NTSTATUS RawIPStartup(
    VOID);

NTSTATUS RawIPShutdown(
    VOID);

NTSTATUS AddGenericHeaderIPv4(
    PADDRESS_FILE AddrFile,
    PIP_ADDRESS RemoteAddress,
    USHORT RemotePort,
    PIP_ADDRESS LocalAddress,
    USHORT LocalPort,
    PIP_PACKET IPPacket,
    UINT DataLength,
    UINT Protocol,
    UINT ExtraLength,
    PVOID *NextHeader );

NTSTATUS BuildRawIpPacket(
    PADDRESS_FILE AddrFile,
    PIP_PACKET Packet,
    PIP_ADDRESS RemoteAddress,
    USHORT RemotePort,
    PIP_ADDRESS LocalAddress,
    USHORT LocalPort,
    PCHAR DataBuffer,
    UINT DataLen);

/* EOF */
