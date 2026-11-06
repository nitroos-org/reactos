/*
 * PROJECT:     NitroOS tcpip
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Interface type (LAN / wireless / remote access) of an adapter, for the inbound filter
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Needs ntddndis.h (NDIS_MEDIUM, NDIS_PHYSICAL_MEDIUM) and reactos/nitrofw.h (NITROFW_IFTYPE_*) first.
 * Kept in a header of its own so that the user-mode unit test compiles the same rule.
 */

#pragma once

/* NdisMediumNative802_11 (an NDIS 6 value the DDK headers of this tree hide behind the Vista version) */
#define FW_NDIS_MEDIUM_NATIVE_802_11 16

/* Rule InterfaceTypes of the adapter an inbound packet came in on (a NITROFW_IFTYPE_* bit):
 *   wireless      802.11 adapters: physical medium WirelessLan or Native802_11, or medium Native802_11
 *   remote access WAN adapters (dial-up, VPN virtual adapters): medium Wan or CoWan, or physical medium
 *                 WiredWAN or WiredCoWan. This stack only binds 802.3 adapters (LANInit), so today no
 *                 adapter of this kind exists and the bit is never produced.
 *   LAN           everything else, including an adapter that cannot say (the query fails, Unspecified).
 * Physical medium is OID_GEN_PHYSICAL_MEDIUM (0 when the miniport does not answer).
 * Checked against the Windows 10 oracle only for the LAN case (an Ethernet adapter reports InterfaceType 6,
 * MediaType 802.3, PhysicalMediaType Unspecified; none of its 468 firewall rules restricts the type). */
static __inline ULONG
FwIfTypeFromMedium(ULONG Medium, ULONG PhysicalMedium)
{
    if (PhysicalMedium == NdisPhysicalMediumWirelessLan || PhysicalMedium == NdisPhysicalMediumNative802_11 ||
        Medium == FW_NDIS_MEDIUM_NATIVE_802_11)
        return NITROFW_IFTYPE_WIRELESS;
    if (Medium == NdisMediumWan || Medium == NdisMediumCoWan ||
        PhysicalMedium == NdisPhysicalMediumWiredWAN || PhysicalMedium == NdisPhysicalMediumWiredCoWan)
        return NITROFW_IFTYPE_REMOTEACCESS;
    return NITROFW_IFTYPE_LAN;
}
