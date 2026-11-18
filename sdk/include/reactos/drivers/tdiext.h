/*
 * PROJECT:     ReactOS TDI extensions
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Private TDI queries between afd.sys and tcpip.sys
 */

#ifndef _REACTOS_TDIEXT_H
#define _REACTOS_TDIEXT_H

/* TDI_QUERY_INFORMATION type: the buffer holds a TA_IP_ADDRESS, in the destination,
 * out the address of the interface a datagram sent to it leaves from. */
#define TDI_QUERY_ROS_SOURCE_ADDRESS 0x00008001

/* TDI_QUERY_INFORMATION type on a connection object: completes with STATUS_CONNECTION_RESET when the peer
 * reset the connection (the request carries no data; the buffer is not used, a ULONG is passed for the MDL),
 * else STATUS_SUCCESS. AFD asks it of a socket whose receive request ended with the peer's FIN: no request
 * is outstanding then, so nothing else tells AFD that a later reset arrived. */
#define TDI_QUERY_ROS_CONNECTION_STATUS 0x00008002

#endif /* _REACTOS_TDIEXT_H */
