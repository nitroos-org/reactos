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
