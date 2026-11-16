/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Private TDI extensions between AFD and tcpip.sys
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

/*
 * A TDI_RECEIVE_DATAGRAM with this flag in its receive flags (a bit no documented TDI_RECEIVE_* flag uses; it fits
 * the USHORT the TDI helpers take) asks the transport to complete it with STATUS_PORT_UNREACHABLE, no data, when an
 * ICMP or ICMPv6 port unreachable comes back for a datagram the address object sent. AFD posts its datagram
 * receives with it while the socket reports port unreachable (SIO_UDP_CONNRESET on, the default), and the next
 * recv/recvfrom then fails with WSAECONNRESET, as on Windows. A client that does not set it never sees such a
 * completion.
 */
#define TDI_RECEIVE_NITRO_PORT_UNREACHABLE  0x00008000

/*
 * The source filter of one multicast group of a datagram socket (RFC 3678 semantics), set as a whole: the Winsock
 * helper (wshtcpip) keeps the socket API's rules (MCAST_*, IP_*_SOURCE*, IP/IPV6_ADD_MEMBERSHIP,
 * SIO_SET_MULTICAST_FILTER, SIOCSMSFILTER) and hands the stack the group's filter after every change, through
 * IOCTL_TCP_SET_INFORMATION_EX with this option id (INFO_TYPE_ADDRESS_OBJECT). INCLUDE with no source leaves the
 * group. InterfaceIndex 0 is the stack's choice (the socket's existing join of the group, else the default
 * multicast interface). Answers: STATUS_INVALID_PARAMETER (malformed; with NITRO_MCAST_FILTER_NEW, the socket has
 * the group already), STATUS_INVALID_ADDRESS (no such interface or group; not a member when leaving),
 * STATUS_INSUFFICIENT_RESOURCES (no room).
 */
#define NITRO_AO_OPTION_MCAST_FILTER    0x4E540001

#define NITRO_MCAST_INCLUDE             0
#define NITRO_MCAST_EXCLUDE             1

#define NITRO_MCAST_FAMILY_IP           4
#define NITRO_MCAST_FAMILY_IP6          6

#define NITRO_MCAST_FILTER_NEW          0x01

/* Sources one socket may list for one group (Windows takes at least 1100: release notes) */
#define NITRO_MCAST_MAX_SOURCES         1024

/* Groups one socket may join, per family (Windows takes at least 300: release notes) */
#define NITRO_MCAST_MAX_GROUPS          20

typedef struct _NITRO_MCAST_FILTER {
    unsigned long InterfaceIndex;
    unsigned char Family;           /* NITRO_MCAST_FAMILY_IP / _IP6 */
    unsigned char Mode;             /* NITRO_MCAST_INCLUDE / _EXCLUDE */
    unsigned char Flags;            /* NITRO_MCAST_FILTER_* */
    unsigned char Reserved;
    unsigned char Group[16];        /* an IPv4 group in the first 4 bytes (network order) */
    unsigned long NumSources;
    unsigned char Sources[1][16];   /* NumSources of them, IPv4 ones in the first 4 bytes */
} NITRO_MCAST_FILTER, *PNITRO_MCAST_FILTER;

#define NITRO_MCAST_FILTER_SIZE(n)  (FIELD_OFFSET(NITRO_MCAST_FILTER, Sources) + (n) * 16)
