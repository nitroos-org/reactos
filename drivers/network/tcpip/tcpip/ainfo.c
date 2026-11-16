/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/ainfo.c
 * PURPOSE:     Per-socket information.
 * PROGRAMMER:  Cameron Gutman
 */

#include "precomp.h"

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
      case AO_OPTION_MCASTTTL:
      case AO_OPTION_MCASTLOOP:
      case AO_OPTION_INDEX_MCASTIF:
      {
         LONG Value;

         if (AddrFile->Family != TDI_ADDRESS_TYPE_IP6 || AddrFile->Protocol != IPPROTO_UDP)
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
