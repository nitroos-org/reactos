/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/ainfo.c
 * PURPOSE:     Per-socket information.
 * PROGRAMMER:  Cameron Gutman
 */

#include "precomp.h"

#include <nitrotdi.h>

TDI_STATUS SetAddressFileInfo(TDIObjectID *ID,
                              PADDRESS_FILE AddrFile,
                              PVOID Buffer,
                              UINT BufferSize)
{
    switch (ID->toi_id)
    {
      case AO_OPTION_TTL:
         if (BufferSize < sizeof(UINT))
             return TDI_INVALID_PARAMETER;

         LockObject(AddrFile);
         /* IPV6_UNICAST_HOPS -1: the default hop limit (128, as the TTL; VERIFY ON ORACLE) */
         if (AddrFile->Family == TDI_ADDRESS_TYPE_IP6 && *(PLONG)Buffer == -1)
             AddrFile->TTL = 128;
         else
             AddrFile->TTL = *((PUCHAR)Buffer);
         UnlockObject(AddrFile);

         return TDI_SUCCESS;

      case AO_OPTION_IP_DONTFRAGMENT:
         if (BufferSize < sizeof(UINT))
             return TDI_INVALID_PARAMETER;

         LockObject(AddrFile);
         AddrFile->DF = *((PUINT)Buffer);
         UnlockObject(AddrFile);

         return TDI_SUCCESS;

      case AO_OPTION_BROADCAST:
         if (BufferSize < sizeof(UINT))
             return TDI_INVALID_PARAMETER;

         LockObject(AddrFile);
         AddrFile->BCast = *((PUINT)Buffer);
         UnlockObject(AddrFile);

         return TDI_SUCCESS;

      case AO_OPTION_IP_HDRINCL:
         if (BufferSize < sizeof(UINT))
             return TDI_INVALID_PARAMETER;

         /* A raw socket's option (WSAEINVAL on a TCP or UDP one); only a privileged opener may set it, either way
            (WSAEACCES for a standard user's ICMP socket, as on Windows) */
         if (AddrFile->Protocol == IPPROTO_TCP || AddrFile->Protocol == IPPROTO_UDP)
             return TDI_INVALID_PARAMETER;
         if (!AddrFile->RawPrivileged)
             return STATUS_ACCESS_DENIED;

         LockObject(AddrFile);
         /* IPV6_HDRINCL of an IPv6 socket is about what it sends only (rawip6.c) */
         if (AddrFile->Family == TDI_ADDRESS_TYPE_IP6)
             AddrFile->HeaderIncl6 = (*((PUINT)Buffer) != 0);
         else
             AddrFile->HeaderIncl = *((PUINT)Buffer);
         UnlockObject(AddrFile);

         return TDI_SUCCESS;

      /* The IPv6 options of a UDP socket (IPV6_MULTICAST_HOPS, _LOOP, _IF, IPV6_ADD_MEMBERSHIP, _DROP_): a LONG
         from the Winsock helper, -1 for the default hop limit; the groups as struct ipv6_mreq */
      /* The IPv4 ones of a UDP or raw IPv4 socket (IP_MULTICAST_TTL, _LOOP: a LONG from the Winsock helper;
         IP_MULTICAST_IF: AO_OPTION_MCASTIF, an address of the interface, or its index as 0.0.0.x, network order;
         0.0.0.0 for the default), kept in the same fields (udp.c, rawip.c) */
      case AO_OPTION_MCASTIF:
      {
         ULONG Interface, IfIndex = 0;

         if (AddrFile->Family != TDI_ADDRESS_TYPE_IP || AddrFile->Protocol == IPPROTO_TCP)
             return TDI_INVALID_REQUEST;
         if (BufferSize < sizeof(ULONG))
             return TDI_INVALID_PARAMETER;
         Interface = *(PULONG)Buffer;

         if (Interface && (Interface & 0xFF))
         {
             IP_ADDRESS Address;
             PIP_INTERFACE IF;

             AddrInitIPv4(&Address, Interface);
             IF = AddrLocateInterface(&Address);
             if (!IF)
                 return STATUS_INVALID_ADDRESS;
             IfIndex = IF->Index;
             IPDereferenceInterface(IF);
         }
         else if (Interface)
         {
             IfIndex = RtlUlongByteSwap(Interface);
         }

         LockObject(AddrFile);
         AddrFile->McastIf = IfIndex;
         UnlockObject(AddrFile);
         return TDI_SUCCESS;
      }

      case AO_OPTION_MCASTTTL:
      case AO_OPTION_MCASTLOOP:
      case AO_OPTION_INDEX_MCASTIF:
      {
         LONG Value;

         if (AddrFile->Family == TDI_ADDRESS_TYPE_IP6 ? AddrFile->Protocol != IPPROTO_UDP :
             (AddrFile->Protocol == IPPROTO_TCP || ID->toi_id == AO_OPTION_INDEX_MCASTIF))
             return TDI_INVALID_REQUEST;
         if (BufferSize < sizeof(LONG))
             return TDI_INVALID_PARAMETER;
         Value = *(PLONG)Buffer;

         LockObject(AddrFile);
         if (ID->toi_id == AO_OPTION_MCASTTTL)
             AddrFile->McastHops = (Value < 0 || Value > 255) ? 1 : (UCHAR)Value;
         else if (ID->toi_id == AO_OPTION_MCASTLOOP)
             AddrFile->McastLoop = (Value != 0);
         else
             AddrFile->McastIf = (ULONG)Value;
         UnlockObject(AddrFile);

         return TDI_SUCCESS;
      }

      case AO_OPTION_INDEX_ADD_MCAST:
      case AO_OPTION_INDEX_DEL_MCAST:
         if (AddrFile->Family != TDI_ADDRESS_TYPE_IP6 || AddrFile->Protocol != IPPROTO_UDP)
             return TDI_INVALID_REQUEST;

         return UDP6SetMembership(AddrFile, ID->toi_id == AO_OPTION_INDEX_ADD_MCAST, Buffer, BufferSize);

      /* IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP (struct ip_mreq) of a datagram or raw socket; an IPv6 socket takes an
         IPv4 group only when it is dual stack (WSAEINVAL otherwise, as Windows answers an IPv6-only one) */
      case AO_OPTION_ADD_MCAST:
      case AO_OPTION_DEL_MCAST:
         if (AddrFile->Protocol == IPPROTO_TCP)
             return TDI_INVALID_REQUEST;
         if (AddrFile->Family == TDI_ADDRESS_TYPE_IP6 && !AddrFile->DualStack)
             return TDI_INVALID_PARAMETER;

         return UDP4SetMembership(AddrFile, ID->toi_id == AO_OPTION_ADD_MCAST, Buffer, BufferSize);

      /* A group's whole source filter from the Winsock helper (nitrotdi.h): an IPv6 group for an IPv6 UDP socket, an
         IPv4 one for an IPv4 UDP or raw socket or a dual stack IPv6 one (raw sockets join IPv4 groups as before) */
      case NITRO_AO_OPTION_MCAST_FILTER:
      {
         const NITRO_MCAST_FILTER *F = Buffer;

         if (AddrFile->Protocol == IPPROTO_TCP)
             return TDI_INVALID_REQUEST;
         if (BufferSize < NITRO_MCAST_FILTER_SIZE(0) || F->NumSources > NITRO_MCAST_MAX_SOURCES ||
             BufferSize < NITRO_MCAST_FILTER_SIZE(F->NumSources) || F->Mode > NITRO_MCAST_EXCLUDE)
             return TDI_INVALID_PARAMETER;

         if (F->Family == NITRO_MCAST_FAMILY_IP6 && AddrFile->Family == TDI_ADDRESS_TYPE_IP6 &&
             AddrFile->Protocol == IPPROTO_UDP)
             return UDP6SetFilter(AddrFile, F->InterfaceIndex, F->Group, F->Mode, F->NumSources,
                                  (const UCHAR (*)[16])F->Sources, (F->Flags & NITRO_MCAST_FILTER_NEW) != 0);
         if (F->Family == NITRO_MCAST_FAMILY_IP &&
             (AddrFile->Family != TDI_ADDRESS_TYPE_IP6 || AddrFile->DualStack))
         {
             ULONG Group;

             RtlCopyMemory(&Group, F->Group, sizeof(Group));
             return UDP4SetFilter(AddrFile, F->InterfaceIndex, Group, F->Mode, F->NumSources,
                                  (const UCHAR (*)[16])F->Sources, (F->Flags & NITRO_MCAST_FILTER_NEW) != 0);
         }
         return TDI_INVALID_PARAMETER;
      }

      default:
         DbgPrint("Unimplemented option %x\n", ID->toi_id);

         return TDI_INVALID_REQUEST;
    }
}

TDI_STATUS GetAddressFileInfo(TDIObjectID *ID,
                              PADDRESS_FILE AddrFile,
                              PVOID Buffer,
                              PUINT BufferSize)
{
    UNIMPLEMENTED;

    return TDI_INVALID_REQUEST;
}
