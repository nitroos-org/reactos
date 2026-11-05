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

/* Non-zero while the filter is loaded (not killed): UDP sends feed the flow table even when nothing is
   enforced yet, so an exchange that is in flight when enforcement starts is not cut off. */
extern volatile LONG NitroFwTracking;

/* UDP send path: remember the exchange so the peer's replies pass (ports in network order) */
VOID NitroFwNoteUdpSend(USHORT LocalPort, PIP_ADDRESS Remote, USHORT RemotePort, BOOLEAN NonUnicast);
#define NITROFW_NOTE_UDP_SEND(LocalPort, Remote, RemotePort, NonUnicast) \
    do { if (NitroFwTracking) NitroFwNoteUdpSend((LocalPort), (Remote), (RemotePort), (NonUnicast)); } while (0)

/* Raw ICMP send path: remember an outstanding request (echo, timestamp, information, address mask) so its
   reply passes; a reply with no such request is unsolicited. Remote in network order. */
VOID NitroFwNoteIcmpSend(PIP_ADDRESS Remote, PUCHAR Icmp, ULONG Length);
#define NITROFW_NOTE_ICMP_SEND(Remote, Icmp, Length) \
    do { if (NitroFwTracking) NitroFwNoteIcmpSend((Remote), (Icmp), (Length)); } while (0)

/* Address files: the image path of the creating process is only needed when a program rule is
   evaluated. It is resolved lazily, and only while an enforced policy has program rules
   (NitroFwWantImages): for a socket opened in that state right after it is listed, for sockets that
   already exist when such a policy is installed from the creator's process id. With enforcement off
   there is no per-socket work at all. */
extern volatile LONG NitroFwWantImages;
VOID NitroFwAddressFileCreated(PADDRESS_FILE AddrFile);
#define NITROFW_ADDRFILE_CREATED(AddrFile) \
    do { if (NitroFwWantImages) NitroFwAddressFileCreated(AddrFile); } while (0)
VOID NitroFwReleaseImage(PVOID Image);
