/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IGMP host side: membership reports for the IPv4 groups sockets joined (igmp.c)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

/* The most sources of a group's filter IGMP reports; a larger INCLUDE set is reported as EXCLUDE with none (all
   sources: more traffic, never less) */
#define IGMP_MAX_SOURCES        64

#define IGMP_MODE_INCLUDE       0
#define IGMP_MODE_EXCLUDE       1

NTSTATUS IGMPStartup(VOID);
VOID IGMPShutdown(VOID);

/* The merged filter of a group on an interface changed (udp.c, core lock held): Mode and the sorted Sources (at most
   IGMP_MAX_SOURCES); INCLUDE with none leaves the group. Callable at IRQL <= DISPATCH_LEVEL */
VOID IGMPSetGroupState(ULONG IfIndex, ULONG Group, UCHAR Mode, const ULONG *Sources, ULONG NumSources);

/* The interface got an IPv4 address or came up: its groups are reported again (state change reports) */
VOID IGMPInterfaceRefresh(ULONG IfIndex);

/* The interface is gone: everything kept for it is dropped, nothing is sent */
VOID IGMPInterfaceGone(ULONG IfIndex);

/* A received IGMP message (IPRegisterProtocol) */
VOID IGMPReceive(PIP_INTERFACE Interface, PIP_PACKET IPPacket);
