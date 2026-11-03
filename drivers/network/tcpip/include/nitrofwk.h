/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Inbound packet filter inside tcpip.sys: the hooks the rest of the driver calls.
 *              Contract with user mode: sdk/include/reactos/nitrofw.h. Implementation: tcpip/nitrofw.c
 */

#pragma once

/* Non-zero only while an installed policy is actually enforced (filter not killed, NitroFwEnforce
   opt-in set, policy ENFORCE flag set, an active profile enabled). Read without a lock on the fast path. */
extern volatile LONG NitroFwEnforcing;

NTSTATUS NitroFwInitialize(PDRIVER_OBJECT DriverObject);
VOID NitroFwUnload(VOID);

/* Receive path, once per complete (reassembled) datagram, before the transport sees it */
BOOLEAN NitroFwInboundAllowed(PIP_INTERFACE Interface, PIP_PACKET IPPacket, UINT Protocol);
#define NITROFW_INBOUND_OK(IF, Packet, Protocol) \
    (!NitroFwEnforcing || NitroFwInboundAllowed((IF), (Packet), (Protocol)))

/* UDP send path: remember the exchange so the peer's replies pass (ports in network order) */
VOID NitroFwNoteUdpSend(USHORT LocalPort, PIP_ADDRESS Remote, USHORT RemotePort, BOOLEAN NonUnicast);
#define NITROFW_NOTE_UDP_SEND(LocalPort, Remote, RemotePort, NonUnicast) \
    do { if (NitroFwEnforcing) NitroFwNoteUdpSend((LocalPort), (Remote), (RemotePort), (NonUnicast)); } while (0)

/* Address files: image path of the creating process, captured at creation (program rules) */
PVOID NitroFwCaptureImage(VOID);
VOID NitroFwReleaseImage(PVOID Image);
