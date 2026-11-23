/*
 * PROJECT:     ReactOS VMware vmxnet3 NDIS miniport driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Query and set information (OIDs)
 * COPYRIGHT:   Copyright 2026 ReactOS Project contributors
 */

#include "vmxnet3.h"

static const NDIS_OID SupportedOidList[] =
{
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_MAXIMUM_LOOKAHEAD,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_LINK_SPEED,
    OID_GEN_TRANSMIT_BUFFER_SPACE,
    OID_GEN_RECEIVE_BUFFER_SPACE,
    OID_GEN_TRANSMIT_BLOCK_SIZE,
    OID_GEN_RECEIVE_BLOCK_SIZE,
    OID_GEN_VENDOR_ID,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_DRIVER_VERSION,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_MAC_OPTIONS,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_MAXIMUM_SEND_PACKETS,
    OID_GEN_PHYSICAL_MEDIUM,
    OID_GEN_XMIT_OK,
    OID_GEN_RCV_OK,
    OID_GEN_XMIT_ERROR,
    OID_GEN_RCV_ERROR,
    OID_GEN_RCV_NO_BUFFER,
    OID_802_3_PERMANENT_ADDRESS,
    OID_802_3_CURRENT_ADDRESS,
    OID_802_3_MULTICAST_LIST,
    OID_802_3_MAXIMUM_LIST_SIZE,
    OID_PNP_CAPABILITIES,
};

NDIS_STATUS
NTAPI
MiniportQueryInformation(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesWritten,
    OUT PULONG BytesNeeded)
{
    PVMX_ADAPTER Adapter = (PVMX_ADAPTER)MiniportAdapterContext;
    ULONG CopyLength = sizeof(ULONG);
    const VOID *CopySource;
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    union
    {
        USHORT Ushort;
        ULONG Ulong;
        ULONG64 Ulong64;
        NDIS_MEDIUM Medium;
        NDIS_PNP_CAPABILITIES PmCapabilities;
    } Info;

    CopySource = &Info;

    switch (Oid)
    {
        case OID_GEN_SUPPORTED_LIST:
            CopySource = SupportedOidList;
            CopyLength = sizeof(SupportedOidList);
            break;

        case OID_GEN_CURRENT_PACKET_FILTER:
            Info.Ulong = Adapter->PacketFilter;
            break;

        case OID_GEN_HARDWARE_STATUS:
            Info.Ulong = (ULONG)NdisHardwareStatusReady;
            break;

        case OID_GEN_MEDIA_SUPPORTED:
        case OID_GEN_MEDIA_IN_USE:
            Info.Medium = NdisMedium802_3;
            CopyLength = sizeof(NDIS_MEDIUM);
            break;

        case OID_GEN_RECEIVE_BLOCK_SIZE:
        case OID_GEN_TRANSMIT_BLOCK_SIZE:
        case OID_GEN_CURRENT_LOOKAHEAD:
        case OID_GEN_MAXIMUM_LOOKAHEAD:
            Info.Ulong = VMX_MAX_FRAME - VMX_ETH_HEADER;
            break;

        case OID_GEN_MAXIMUM_FRAME_SIZE:
            Info.Ulong = VMX_MTU;
            break;

        case OID_GEN_MAXIMUM_TOTAL_SIZE:
        case OID_GEN_TRANSMIT_BUFFER_SPACE:
            Info.Ulong = VMX_MAX_FRAME;
            break;

        case OID_GEN_RECEIVE_BUFFER_SPACE:
            Info.Ulong = VMX_NRXDESC0 * VMX_BUFFER_SIZE;
            break;

        case OID_802_3_MULTICAST_LIST:
            CopySource = Adapter->MulticastList;
            CopyLength = Adapter->MulticastListSize * ETH_LENGTH_OF_ADDRESS;
            break;

        case OID_802_3_MAXIMUM_LIST_SIZE:
            Info.Ulong = VMX_MAX_MULTICAST;
            break;

        case OID_GEN_LINK_SPEED:
            Info.Ulong = Adapter->LinkSpeedMbps * 10000;
            break;

        case OID_GEN_VENDOR_ID:
            /* the first three bytes of the MAC address are the vendor id */
            Info.Ulong = (Adapter->PermanentMacAddress[0] << 16) | (Adapter->PermanentMacAddress[1] << 8) |
                         Adapter->PermanentMacAddress[2];
            break;

        case OID_GEN_VENDOR_DESCRIPTION:
        {
            static const CHAR VendorDesc[] = "VMware vmxnet3 Ethernet Adapter";

            CopySource = VendorDesc;
            CopyLength = sizeof(VendorDesc);
            break;
        }

        case OID_GEN_VENDOR_DRIVER_VERSION:
            Info.Ulong = 1;
            break;

        case OID_GEN_DRIVER_VERSION:
            CopyLength = sizeof(USHORT);
            Info.Ushort = (NDIS_MINIPORT_MAJOR_VERSION << 8) + NDIS_MINIPORT_MINOR_VERSION;
            break;

        case OID_GEN_MAXIMUM_SEND_PACKETS:
            Info.Ulong = 16;
            break;

        case OID_GEN_MAC_OPTIONS:
            Info.Ulong = NDIS_MAC_OPTION_RECEIVE_SERIALIZED | NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |
                         NDIS_MAC_OPTION_TRANSFERS_NOT_PEND | NDIS_MAC_OPTION_NO_LOOPBACK;
            break;

        case OID_GEN_MEDIA_CONNECT_STATUS:
            Info.Ulong = Adapter->MediaState;
            break;

        case OID_802_3_CURRENT_ADDRESS:
        case OID_802_3_PERMANENT_ADDRESS:
            CopySource = Adapter->PermanentMacAddress;
            CopyLength = ETH_LENGTH_OF_ADDRESS;
            break;

        case OID_GEN_XMIT_OK:
        case OID_GEN_RCV_OK:
        case OID_GEN_XMIT_ERROR:
        case OID_GEN_RCV_ERROR:
        case OID_GEN_RCV_NO_BUFFER:
            Info.Ulong64 = VmxQueryStatistic(Adapter, Oid);
            *BytesNeeded = sizeof(ULONG64);
            if (InformationBufferLength >= sizeof(ULONG64))
            {
                *BytesWritten = sizeof(ULONG64);
                NdisMoveMemory(InformationBuffer, &Info, sizeof(ULONG64));
            }
            else if (InformationBufferLength >= sizeof(ULONG))
            {
                *BytesWritten = sizeof(ULONG);
                NdisMoveMemory(InformationBuffer, &Info, sizeof(ULONG));
            }
            else
            {
                *BytesWritten = 0;
                return NDIS_STATUS_BUFFER_TOO_SHORT;
            }
            return NDIS_STATUS_SUCCESS;

        case OID_GEN_PHYSICAL_MEDIUM:
            Info.Ulong = NdisPhysicalMedium802_3;
            break;

        case OID_PNP_CAPABILITIES:
            /* no wake up: the adapter reports nothing */
            Status = NDIS_STATUS_NOT_SUPPORTED;
            break;

        default:
            Status = NDIS_STATUS_NOT_SUPPORTED;
            break;
    }

    if (Status == NDIS_STATUS_SUCCESS)
    {
        if (CopyLength > InformationBufferLength)
        {
            *BytesNeeded = CopyLength;
            *BytesWritten = 0;
            return NDIS_STATUS_BUFFER_TOO_SHORT;
        }
        NdisMoveMemory(InformationBuffer, CopySource, CopyLength);
        *BytesWritten = CopyLength;
        *BytesNeeded = CopyLength;
    }
    else
    {
        *BytesWritten = 0;
        *BytesNeeded = 0;
    }
    return Status;
}

NDIS_STATUS
NTAPI
MiniportSetInformation(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesRead,
    OUT PULONG BytesNeeded)
{
    PVMX_ADAPTER Adapter = (PVMX_ADAPTER)MiniportAdapterContext;
    ULONG Value;
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;

    *BytesRead = 0;
    *BytesNeeded = 0;

    switch (Oid)
    {
        case OID_GEN_CURRENT_PACKET_FILTER:
            if (InformationBufferLength < sizeof(ULONG))
            {
                *BytesNeeded = sizeof(ULONG);
                return NDIS_STATUS_INVALID_LENGTH;
            }
            NdisMoveMemory(&Value, InformationBuffer, sizeof(ULONG));
            if (Value & ~(NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_MULTICAST | NDIS_PACKET_TYPE_ALL_MULTICAST |
                          NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_PROMISCUOUS | NDIS_PACKET_TYPE_MAC_FRAME))
            {
                *BytesRead = sizeof(ULONG);
                *BytesNeeded = sizeof(ULONG);
                return NDIS_STATUS_NOT_SUPPORTED;
            }
            Adapter->PacketFilter = Value;
            Status = VmxApplyPacketFilter(Adapter);
            break;

        case OID_GEN_CURRENT_LOOKAHEAD:
            if (InformationBufferLength < sizeof(ULONG))
            {
                *BytesNeeded = sizeof(ULONG);
                return NDIS_STATUS_INVALID_LENGTH;
            }
            NdisMoveMemory(&Value, InformationBuffer, sizeof(ULONG));
            if (Value > VMX_MAX_FRAME - VMX_ETH_HEADER)
                Status = NDIS_STATUS_INVALID_DATA;
            break;

        case OID_802_3_MULTICAST_LIST:
            if ((InformationBufferLength % ETH_LENGTH_OF_ADDRESS) != 0)
            {
                *BytesNeeded = InformationBufferLength + (ETH_LENGTH_OF_ADDRESS - InformationBufferLength % ETH_LENGTH_OF_ADDRESS);
                return NDIS_STATUS_INVALID_LENGTH;
            }
            if (InformationBufferLength > sizeof(Adapter->MulticastList))
            {
                *BytesNeeded = sizeof(Adapter->MulticastList);
                return NDIS_STATUS_MULTICAST_FULL;
            }
            NdisMoveMemory(Adapter->MulticastList, InformationBuffer, InformationBufferLength);
            Adapter->MulticastListSize = InformationBufferLength / ETH_LENGTH_OF_ADDRESS;
            Status = VmxApplyPacketFilter(Adapter);
            break;

        default:
            return NDIS_STATUS_NOT_SUPPORTED;
    }

    if (Status == NDIS_STATUS_SUCCESS)
        *BytesRead = InformationBufferLength;
    return Status;
}
