/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Interface type of an adapter for the inbound filter (tcpip include/fwiftype.h)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winioctl.h>
#include <ntddndis.h>
#include <reactos/nitrofw.h>
#include "../../../../drivers/network/tcpip/include/fwiftype.h"

START_TEST(IfType)
{
    ULONG Phys;

    /* Ethernet, whatever the miniport says about the physical medium or whether it answers (0) */
    ok_hex(FwIfTypeFromMedium(NdisMedium802_3, 0), NITROFW_IFTYPE_LAN);
    ok_hex(FwIfTypeFromMedium(NdisMedium802_3, NdisPhysicalMediumUnspecified), NITROFW_IFTYPE_LAN);
    ok_hex(FwIfTypeFromMedium(NdisMedium802_3, NdisPhysicalMedium802_3), NITROFW_IFTYPE_LAN);
    ok_hex(FwIfTypeFromMedium(NdisMedium802_3, NdisPhysicalMediumBluetooth), NITROFW_IFTYPE_LAN);
    ok_hex(FwIfTypeFromMedium(NdisMedium802_3, NdisPhysicalMediumOther), NITROFW_IFTYPE_LAN);

    /* 802.11 adapters */
    ok_hex(FwIfTypeFromMedium(NdisMedium802_3, NdisPhysicalMediumWirelessLan), NITROFW_IFTYPE_WIRELESS);
    ok_hex(FwIfTypeFromMedium(NdisMedium802_3, NdisPhysicalMediumNative802_11), NITROFW_IFTYPE_WIRELESS);
    ok_hex(FwIfTypeFromMedium(FW_NDIS_MEDIUM_NATIVE_802_11, 0), NITROFW_IFTYPE_WIRELESS);

    /* WAN adapters */
    ok_hex(FwIfTypeFromMedium(NdisMediumWan, 0), NITROFW_IFTYPE_REMOTEACCESS);
    ok_hex(FwIfTypeFromMedium(NdisMediumCoWan, 0), NITROFW_IFTYPE_REMOTEACCESS);
    ok_hex(FwIfTypeFromMedium(NdisMedium802_3, NdisPhysicalMediumWiredWAN), NITROFW_IFTYPE_REMOTEACCESS);
    ok_hex(FwIfTypeFromMedium(NdisMedium802_3, NdisPhysicalMediumWiredCoWan), NITROFW_IFTYPE_REMOTEACCESS);

    /* the result is always exactly one known bit */
    for (Phys = 0; Phys < 40; Phys++)
    {
        ULONG Medium;
        for (Medium = 0; Medium < 20; Medium++)
        {
            ULONG T = FwIfTypeFromMedium(Medium, Phys);
            ok((T & NITROFW_IFTYPE_ALL) == T && T && !(T & (T - 1)), "medium %lu physical %lu -> %lx\n", Medium, Phys, T);
        }
    }

    /* the value the header assumes for the NDIS 6 medium */
    ok_int(FW_NDIS_MEDIUM_NATIVE_802_11, 16);
    ok_int(NdisMediumCoWan, 12);
    ok_int(NdisMediumWan, 3);
}
