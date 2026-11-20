/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        network/neighbor.c
 * PURPOSE:     Neighbor address cache
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"

NEIGHBOR_CACHE_TABLE NeighborCache[NB_HASHMASK + 1];

/* Group entries in the cache (GroupEntry), at most NB_MAX_GROUP_ENTRIES (Windows: 256 neighbour entries per
   interface, netsh interface ipv4 show global) */
static volatile LONG NBGroupEntries;

VOID NBCompleteSend( PVOID Context,
		     PNDIS_PACKET NdisPacket,
		     NDIS_STATUS Status ) {
    PNEIGHBOR_PACKET Packet = (PNEIGHBOR_PACKET)Context;
    TI_DbgPrint(MID_TRACE, ("Called\n"));
    ASSERT_KM_POINTER(Packet);
    ASSERT_KM_POINTER(Packet->Complete);
    Packet->Complete( Packet->Context, Packet->Packet, Status );
    TI_DbgPrint(MID_TRACE, ("Completed\n"));
    ExFreePoolWithTag( Packet, NEIGHBOR_PACKET_TAG );
    TI_DbgPrint(MID_TRACE, ("Freed\n"));
}

VOID NBSendPackets( PNEIGHBOR_CACHE_ENTRY NCE ) {
    PLIST_ENTRY PacketEntry;
    PNEIGHBOR_PACKET Packet;
    UINT HashValue;
    KIRQL OldIrql;

    ASSERT(!(NCE->State & NUD_INCOMPLETE));

    HashValue  = *(PULONG)(&NCE->Address.Address);
    HashValue ^= HashValue >> 16;
    HashValue ^= HashValue >> 8;
    HashValue ^= HashValue >> 4;
    HashValue &= NB_HASHMASK;

    /* Send any waiting packets. The bucket lock is taken as a spin lock, not through
       ExInterlockedRemoveHeadList: that one spins with interrupts disabled, and the holder of
       the lock may wait for an IPI (a TLB flush when it frees pool, such as an NCE with its
       last reference): the spinning processor would never take it, a deadlock */
    for (;;)
    {
        TcpipAcquireSpinLock(&NeighborCache[HashValue].Lock, &OldIrql);
        PacketEntry = IsListEmpty(&NCE->PacketQueue) ? NULL : RemoveHeadList(&NCE->PacketQueue);
        TcpipReleaseSpinLock(&NeighborCache[HashValue].Lock, OldIrql);

        if (!PacketEntry)
            break;

	Packet = CONTAINING_RECORD( PacketEntry, NEIGHBOR_PACKET, Next );

	TI_DbgPrint
	    (MID_TRACE,
	     ("PacketEntry: %x, NdisPacket %x\n",
	      PacketEntry, Packet->Packet));

	PC(Packet->Packet)->DLComplete = NBCompleteSend;
	PC(Packet->Packet)->Context  = Packet;

	NCE->Interface->Transmit
	    ( NCE->Interface->Context,
	      Packet->Packet,
	      0,
	      NCE->LinkAddress,
	      LAN_PROTO_IPv4 );
    }
}

/* Must be called with table lock acquired */
VOID NBFlushPacketQueue( PNEIGHBOR_CACHE_ENTRY NCE,
			 NTSTATUS ErrorCode ) {
    PLIST_ENTRY PacketEntry;
    PNEIGHBOR_PACKET Packet;

    while( !IsListEmpty(&NCE->PacketQueue) ) {
        PacketEntry = RemoveHeadList(&NCE->PacketQueue);
	Packet = CONTAINING_RECORD
	    ( PacketEntry, NEIGHBOR_PACKET, Next );

        ASSERT_KM_POINTER(Packet);

	TI_DbgPrint
	    (MID_TRACE,
	     ("PacketEntry: %x, NdisPacket %x\n",
	      PacketEntry, Packet->Packet));

        ASSERT_KM_POINTER(Packet->Complete);
	Packet->Complete( Packet->Context,
                          Packet->Packet,
                          ErrorCode );

	ExFreePoolWithTag( Packet, NEIGHBOR_PACKET_TAG );
    }
}

VOID NBReferenceNeighbor(
    PNEIGHBOR_CACHE_ENTRY NCE)
{
    LONG RefCount = InterlockedIncrement(&NCE->RefCount);

    ASSERT(RefCount > 1);
    UNREFERENCED_PARAMETER(RefCount);
}

VOID NBDereferenceNeighbor(
    PNEIGHBOR_CACHE_ENTRY NCE)
/*
 * FUNCTION: Drops a reference to an NCE, and frees it with the last one
 * NOTES:
 *     At <= DISPATCH_LEVEL, also under the NCE's bucket lock (the cache's reference
 *     goes there): nothing else can reach an NCE without references, so the packets
 *     queued on it since it left the cache are completed without the lock
 */
{
    LONG RefCount = InterlockedDecrement(&NCE->RefCount);

    ASSERT(RefCount >= 0);
    if (RefCount != 0)
        return;

    ASSERT(NCE->Unlinked);

    NBFlushPacketQueue(NCE, NDIS_STATUS_REQUEST_ABORTED);

    if (NCE->GroupEntry)
        InterlockedDecrement(&NBGroupEntries);

    IPDereferenceInterface(NCE->Interface);

    ExFreePoolWithTag(NCE, NCE_TAG);
}

/* Takes an NCE out of the cache: the caller holds its bucket lock and has unlinked it. Drops the
   cache's reference, which may be the last one */
static VOID NBUnlinkedNeighbor(
    PNEIGHBOR_CACHE_ENTRY NCE,
    NDIS_STATUS Status)
{
    NCE->Unlinked = TRUE;
    NBFlushPacketQueue(NCE, Status);
    NBDereferenceNeighbor(NCE);
}

VOID NBTimeout(VOID)
/*
 * FUNCTION: Neighbor address cache timeout handler
 * NOTES:
 *     This routine is called by IPTimeout to remove outdated cache
 *     entries.
 */
{
    UINT i;
    PNEIGHBOR_CACHE_ENTRY *PrevNCE;
    PNEIGHBOR_CACHE_ENTRY NCE;
    NDIS_STATUS Status;

    for (i = 0; i <= NB_HASHMASK; i++) {
        TcpipAcquireSpinLockAtDpcLevel(&NeighborCache[i].Lock);

        for (PrevNCE = &NeighborCache[i].Cache;
             (NCE = *PrevNCE) != NULL;) {
            if (NCE->State & NUD_INCOMPLETE)
            {
                /* Solicit for an address */
                NBSendSolicit(NCE);
                if (NCE->EventTimer == 0)
                {
                    NCE->EventCount++;
                    if (NCE->EventCount == ARP_INCOMPLETE_TIMEOUT)
                    {
                        NBFlushPacketQueue(NCE, NDIS_STATUS_NETWORK_UNREACHABLE);
                        NCE->EventCount = 0;
                    }
                }
            }

            /* Check if event timer is running */
            if (NCE->EventTimer > 0)  {
                ASSERT(!(NCE->State & NUD_PERMANENT));
                NCE->EventCount++;

                if ((NCE->EventCount > ARP_RATE &&
                     NCE->EventCount % ARP_TIMEOUT_RETRANSMISSION == 0) ||
                    (NCE->EventCount == ARP_RATE))
                {
                    /* We haven't gotten a packet from them in
                     * EventCount seconds so we mark them as stale
                     * and solicit now */
                    NCE->State |= NUD_STALE;
                    NBSendSolicit(NCE);
                }
                if (NCE->EventTimer - NCE->EventCount == 0) {
                    /* Unlink and destroy the NCE */
                    *PrevNCE = NCE->Next;

                    /* Choose the proper failure status */
                    if (NCE->State & NUD_INCOMPLETE)
                    {
                        /* We couldn't get an address to this IP at all */
                        Status = NDIS_STATUS_HOST_UNREACHABLE;
                    }
                    else
                    {
                        /* This guy was stale for way too long */
                        Status = NDIS_STATUS_REQUEST_ABORTED;
                    }

                    NBUnlinkedNeighbor(NCE, Status);

                    continue;
                }
            }
            PrevNCE = &NCE->Next;
        }

        TcpipReleaseSpinLockFromDpcLevel(&NeighborCache[i].Lock);
    }
}

VOID NBStartup(VOID)
/*
 * FUNCTION: Starts the neighbor cache
 */
{
    UINT i;

    TI_DbgPrint(DEBUG_NCACHE, ("Called.\n"));

    for (i = 0; i <= NB_HASHMASK; i++) {
	NeighborCache[i].Cache = NULL;
	TcpipInitializeSpinLock(&NeighborCache[i].Lock);
    }
}

VOID NBShutdown(VOID)
/*
 * FUNCTION: Shuts down the neighbor cache
 */
{
  PNEIGHBOR_CACHE_ENTRY NextNCE;
  PNEIGHBOR_CACHE_ENTRY CurNCE;
  KIRQL OldIrql;
  UINT i;

  TI_DbgPrint(DEBUG_NCACHE, ("Called.\n"));

  /* Remove possible entries from the cache */
  for (i = 0; i <= NB_HASHMASK; i++)
    {
      TcpipAcquireSpinLock(&NeighborCache[i].Lock, &OldIrql);

      CurNCE = NeighborCache[i].Cache;
      while (CurNCE) {
          NextNCE = CurNCE->Next;

          /* Flush wait queue; whoever still uses it frees it */
          NBUnlinkedNeighbor(CurNCE, NDIS_STATUS_NOT_ACCEPTED);

	  CurNCE = NextNCE;
      }

    NeighborCache[i].Cache = NULL;

    TcpipReleaseSpinLock(&NeighborCache[i].Lock, OldIrql);
  }

  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));
}

VOID NBSendSolicit(PNEIGHBOR_CACHE_ENTRY NCE)
/*
 * FUNCTION: Sends a neighbor solicitation message
 * ARGUMENTS:
 *   NCE = Pointer to NCE of neighbor to solicit
 * NOTES:
 *   May be called with lock held on NCE's table
 */
{
    TI_DbgPrint(DEBUG_NCACHE, ("Called. NCE (0x%X).\n", NCE));

    ARPTransmit(&NCE->Address,
                (NCE->State & NUD_INCOMPLETE) ? NULL : NCE->LinkAddress,
                NCE->Interface);
}

VOID NBDestroyNeighborsForInterface(PIP_INTERFACE Interface)
{
    KIRQL OldIrql;
    PNEIGHBOR_CACHE_ENTRY *PrevNCE;
    PNEIGHBOR_CACHE_ENTRY NCE;
    ULONG i;

    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    for (i = 0; i <= NB_HASHMASK; i++)
    {
        TcpipAcquireSpinLockAtDpcLevel(&NeighborCache[i].Lock);

        for (PrevNCE = &NeighborCache[i].Cache;
             (NCE = *PrevNCE) != NULL;)
        {
            if (NCE->Interface == Interface)
            {
                /* Unlink the NCE: it goes when its last user lets go */
                *PrevNCE = NCE->Next;

                NBUnlinkedNeighbor(NCE, NDIS_STATUS_REQUEST_ABORTED);

                continue;
            }
            else
            {
                PrevNCE = &NCE->Next;
            }
        }

        TcpipReleaseSpinLockFromDpcLevel(&NeighborCache[i].Lock);
    }
    KeLowerIrql(OldIrql);
}

PNEIGHBOR_CACHE_ENTRY NBAddNeighbor(
  PIP_INTERFACE Interface,
  PIP_ADDRESS Address,
  PVOID LinkAddress,
  UINT LinkAddressLength,
  UCHAR State,
  UINT EventTimer)
/*
 * FUNCTION: Adds a neighbor to the neighbor cache
 * ARGUMENTS:
 *   Interface         = Pointer to interface
 *   Address           = Pointer to IP address
 *   LinkAddress       = Pointer to link address (may be NULL)
 *   LinkAddressLength = Length of link address
 *   State             = State of NCE
 * RETURNS:
 *   Pointer to NCE, NULL there is not enough free resources
 * NOTES:
 *   The NCE is referenced for the caller (NBDereferenceNeighbor), and
 *   references the interface. No NCE is added to an unregistered
 *   interface (NULL is returned)
 */
{
  PNEIGHBOR_CACHE_ENTRY NCE;
  ULONG HashValue;
  KIRQL OldIrql;
  IP_ADDRESS InternalAddress;

  TI_DbgPrint
      (DEBUG_NCACHE,
       ("Called. Interface (0x%X)  Address (0x%X)  "
	"LinkAddress (0x%X)  LinkAddressLength (%d)  State (0x%X)\n",
	Interface, Address, LinkAddress, LinkAddressLength, State));

  NCE = ExAllocatePoolWithTag
      (NonPagedPool, sizeof(NEIGHBOR_CACHE_ENTRY) + LinkAddressLength,
       NCE_TAG);
  if (NCE == NULL)
    {
      TI_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
      return NULL;
    }

  RtlCopyMemory(&InternalAddress, Address, sizeof(*Address));

  /* Map 127.x.x.x adresses to the loopback address (127.0.0.1) */
  if ((InternalAddress.Address.IPv4Address & LOOPBACK_ADDRMASK_IPv4) == (LOOPBACK_ADDRESS_IPv4 & LOOPBACK_ADDRMASK_IPv4))
    InternalAddress.Address.IPv4Address = LOOPBACK_ADDRESS_IPv4;

  NCE->RefCount = 2; /* The cache's and the caller's */
  NCE->Unlinked = FALSE;
  NCE->GroupEntry = FALSE;
  NCE->Interface = Interface;
  NCE->Address = InternalAddress;
  NCE->LinkAddressLength = LinkAddressLength;
  NCE->LinkAddress = (PVOID)&NCE[1];
  if( LinkAddress )
      RtlCopyMemory(NCE->LinkAddress, LinkAddress, LinkAddressLength);
  else
      memset(NCE->LinkAddress, 0xff, LinkAddressLength);
  NCE->State = State;
  NCE->EventTimer = EventTimer;
  NCE->EventCount = 0;
  InitializeListHead( &NCE->PacketQueue );

  TI_DbgPrint(MID_TRACE,("NCE: %x\n", NCE));

  HashValue = *(PULONG)&InternalAddress.Address;
  HashValue ^= HashValue >> 16;
  HashValue ^= HashValue >> 8;
  HashValue ^= HashValue >> 4;
  HashValue &= NB_HASHMASK;

  TcpipAcquireSpinLock(&NeighborCache[HashValue].Lock, &OldIrql);

  /* NBDestroyNeighborsForInterface takes this lock after the interface was unregistered:
     it finds the NCE if the flag was clear here */
  if (Interface->Unbound)
  {
      TcpipReleaseSpinLock(&NeighborCache[HashValue].Lock, OldIrql);
      ExFreePoolWithTag(NCE, NCE_TAG);
      return NULL;
  }

  IPReferenceInterface(Interface);
  NCE->Next = NeighborCache[HashValue].Cache;
  NeighborCache[HashValue].Cache = NCE;

  TcpipReleaseSpinLock(&NeighborCache[HashValue].Lock, OldIrql);

  return NCE;
}

VOID NBUpdateNeighbor(
  PNEIGHBOR_CACHE_ENTRY NCE,
  PVOID LinkAddress,
  UCHAR State)
/*
 * FUNCTION: Update link address information in NCE
 * ARGUMENTS:
 *   NCE         = Pointer to NCE to update
 *   LinkAddress = Pointer to link address
 *   State       = State of NCE
 * NOTES:
 *   The link address and state is updated. Any waiting packets are sent
 */
{
    KIRQL OldIrql;
    UINT HashValue;

    TI_DbgPrint(DEBUG_NCACHE, ("Called. NCE (0x%X)  LinkAddress (0x%X)  State (0x%X).\n", NCE, LinkAddress, State));

    HashValue  = *(PULONG)(&NCE->Address.Address);
    HashValue ^= HashValue >> 16;
    HashValue ^= HashValue >> 8;
    HashValue ^= HashValue >> 4;
    HashValue &= NB_HASHMASK;

    TcpipAcquireSpinLock(&NeighborCache[HashValue].Lock, &OldIrql);

    RtlCopyMemory(NCE->LinkAddress, LinkAddress, NCE->LinkAddressLength);
    NCE->State = State;
    NCE->EventCount = 0;

    TcpipReleaseSpinLock(&NeighborCache[HashValue].Lock, OldIrql);

    if( !(NCE->State & NUD_INCOMPLETE) )
    {
        if (NCE->EventTimer) NCE->EventTimer = ARP_COMPLETE_TIMEOUT;
        NBSendPackets( NCE );
    }
}

VOID
NBResetNeighborTimeout(PIP_ADDRESS Address)
{
    KIRQL OldIrql;
    UINT HashValue;
    PNEIGHBOR_CACHE_ENTRY NCE;

    TI_DbgPrint(DEBUG_NCACHE, ("Resetting NCE timout for 0x%s\n", A2S(Address)));

    HashValue  = *(PULONG)(&Address->Address);
    HashValue ^= HashValue >> 16;
    HashValue ^= HashValue >> 8;
    HashValue ^= HashValue >> 4;
    HashValue &= NB_HASHMASK;

    TcpipAcquireSpinLock(&NeighborCache[HashValue].Lock, &OldIrql);

    for (NCE = NeighborCache[HashValue].Cache;
         NCE != NULL;
         NCE = NCE->Next)
    {
         if (AddrIsEqual(Address, &NCE->Address))
         {
             NCE->EventCount = 0;
             break;
         }
    }

    TcpipReleaseSpinLock(&NeighborCache[HashValue].Lock, OldIrql);
}

PNEIGHBOR_CACHE_ENTRY NBLocateNeighbor(
  PIP_ADDRESS Address,
  PIP_INTERFACE Interface)
/*
 * FUNCTION: Locates a neighbor in the neighbor cache
 * ARGUMENTS:
 *   Address = Pointer to IP address
 *   Interface = Pointer to IP interface
 * RETURNS:
 *   Pointer to NCE, NULL if not found
 * NOTES:
 *   If the NCE is found, it is referenced. The caller is
 *   responsible for dereferencing it again after use
 */
{
  PNEIGHBOR_CACHE_ENTRY NCE;
  UINT HashValue;
  KIRQL OldIrql;
  PIP_INTERFACE FirstInterface;
  IP_ADDRESS InternalAddress;

  TI_DbgPrint(DEBUG_NCACHE, ("Called. Address (0x%X).\n", Address));

  RtlCopyMemory(&InternalAddress, Address, sizeof(*Address));

  /* Map 127.x.x.x adresses to the loopback address (127.0.0.1) */
  if ((InternalAddress.Address.IPv4Address & LOOPBACK_ADDRMASK_IPv4) == (LOOPBACK_ADDRESS_IPv4 & LOOPBACK_ADDRMASK_IPv4))
    InternalAddress.Address.IPv4Address = LOOPBACK_ADDRESS_IPv4;

  HashValue = *(PULONG)&InternalAddress.Address;;
  HashValue ^= HashValue >> 16;
  HashValue ^= HashValue >> 8;
  HashValue ^= HashValue >> 4;
  HashValue &= NB_HASHMASK;

  TcpipAcquireSpinLock(&NeighborCache[HashValue].Lock, &OldIrql);

  /* If there's no adapter specified, we'll look for a match on
   * each one. */
  if (Interface == NULL)
  {
      FirstInterface = GetDefaultInterface();
      Interface = FirstInterface;
  }
  else
  {
      FirstInterface = NULL;
  }

  do
  {
      NCE = NeighborCache[HashValue].Cache;
      while (NCE != NULL)
      {
         if (NCE->Interface == Interface &&
             AddrIsEqual(&InternalAddress, &NCE->Address))
         {
             break;
         }

         NCE = NCE->Next;
      }

      if (NCE != NULL)
          break;
  }
  while ((FirstInterface != NULL) &&
         ((Interface = GetDefaultInterface()) != FirstInterface));

  if ((NCE == NULL) && (FirstInterface != NULL))
  {
      /* This time we'll even match loopback NCEs */
      NCE = NeighborCache[HashValue].Cache;
      while (NCE != NULL)
      {
         if (AddrIsEqual(&InternalAddress, &NCE->Address))
         {
             break;
         }

         NCE = NCE->Next;
      }
  }

  if (NCE != NULL)
      NBReferenceNeighbor(NCE);

  TcpipReleaseSpinLock(&NeighborCache[HashValue].Lock, OldIrql);

  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));

  return NCE;
}

/*
 * An entry of a neighbour whose link address is known without asking (a group), not put in the cache: referenced
 * once for the caller and freed with that reference (NBDereferenceNeighbor). It holds a reference to its interface.
 * The send paths use it within the caller's reference (LANTransmit copies the link address; fragments are sent
 * synchronously), and nothing can find it, so no lock is needed.
 */
static
PNEIGHBOR_CACHE_ENTRY
NBCreateUncachedNeighbor(
  PIP_INTERFACE Interface,
  PIP_ADDRESS Address,
  PVOID LinkAddress,
  UINT LinkAddressLength,
  UCHAR State)
{
  PNEIGHBOR_CACHE_ENTRY NCE;

  if (Interface->Unbound)
      return NULL;
  NCE = ExAllocatePoolWithTag(NonPagedPool, sizeof(NEIGHBOR_CACHE_ENTRY) + LinkAddressLength, NCE_TAG);
  if (NCE == NULL)
      return NULL;
  RtlZeroMemory(NCE, sizeof(NEIGHBOR_CACHE_ENTRY));
  NCE->RefCount = 1;
  NCE->Unlinked = TRUE;
  NCE->Interface = Interface;
  NCE->Address = *Address;
  NCE->LinkAddressLength = LinkAddressLength;
  NCE->LinkAddress = (PVOID)&NCE[1];
  if (LinkAddress)
      RtlCopyMemory(NCE->LinkAddress, LinkAddress, LinkAddressLength);
  else
      memset(NCE->LinkAddress, 0xff, LinkAddressLength);
  NCE->State = State;
  InitializeListHead(&NCE->PacketQueue);
  IPReferenceInterface(Interface);
  return NCE;
}

PNEIGHBOR_CACHE_ENTRY NBFindOrCreateNeighbor(
  PIP_INTERFACE Interface,
  PIP_ADDRESS Address,
  BOOLEAN NoTimeout)
/*
 * FUNCTION: Tries to find a neighbor and if unsuccesful, creates a new NCE
 * ARGUMENTS:
 *   Interface = Pointer to interface to use (in case NCE is not found)
 *   Address   = Pointer to IP address
 * RETURNS:
 *   Pointer to NCE, NULL if there is not enough free resources
 * NOTES:
 *   The NCE is referenced if found or created. The caller is
 *   responsible for dereferencing it again after use
 */
{
  PNEIGHBOR_CACHE_ENTRY NCE;

  TI_DbgPrint(DEBUG_NCACHE, ("Called. Interface (0x%X)  Address (0x%X).\n", Interface, Address));

  NCE = NBLocateNeighbor(Address, Interface);
  if (NCE == NULL)
    {
        TI_DbgPrint(MID_TRACE,("BCAST: %s\n", A2S(&Interface->Broadcast)));
        if (Address->Type == IP_ADDRESS_V4 && IPV4_IS_MULTICAST(Address->Address.IPv4Address)) {
            /* An IPv4 group: its Ethernet address (RFC 1112 6.4: 01:00:5e and the low 23 bits of the group), a
               permanent entry, as Windows lists one ("static") for each group it sent to; no ARP. Permanent entries
               never time out and any user can send to 2^28 groups: past NB_MAX_GROUP_ENTRIES cached ones, a group
               gets an entry of its own that is not in the cache and goes with its last reference */
            const UCHAR *Group = (const UCHAR *)&Address->Address.IPv4Address;
            UCHAR Mac[6];

            Mac[0] = 0x01; Mac[1] = 0x00; Mac[2] = 0x5E;
            Mac[3] = Group[1] & 0x7F; Mac[4] = Group[2]; Mac[5] = Group[3];
            if (InterlockedIncrement(&NBGroupEntries) <= NB_MAX_GROUP_ENTRIES) {
                NCE = NBAddNeighbor(Interface, Address, (Interface->AddressLength == sizeof(Mac)) ? Mac : NULL,
                                    Interface->AddressLength, NUD_PERMANENT, 0);
                if (NCE)
                    NCE->GroupEntry = TRUE;
                else
                    InterlockedDecrement(&NBGroupEntries);
            } else {
                InterlockedDecrement(&NBGroupEntries);
                NCE = NBCreateUncachedNeighbor(Interface, Address,
                                               (Interface->AddressLength == sizeof(Mac)) ? Mac : NULL,
                                               Interface->AddressLength, NUD_PERMANENT);
            }
        } else if( AddrIsEqual(Address, &Interface->Broadcast) ||
            AddrIsUnspecified(Address) ) {
            TI_DbgPrint(MID_TRACE,("Packet targeted at broadcast addr\n"));
            NCE = NBAddNeighbor(Interface, Address, NULL,
                                Interface->AddressLength, NUD_PERMANENT, 0);
        } else {
            NCE = NBAddNeighbor(Interface, Address, NULL,
                                Interface->AddressLength, NUD_INCOMPLETE, NoTimeout ? 0 : ARP_INCOMPLETE_TIMEOUT);
            if (!NCE) return NULL;
            NBSendSolicit(NCE);
        }
    }

  return NCE;
}

BOOLEAN NBQueuePacketLimited(
  PNEIGHBOR_CACHE_ENTRY NCE,
  PNDIS_PACKET NdisPacket,
  PNEIGHBOR_PACKET_COMPLETE PacketComplete,
  PVOID PacketContext,
  UINT UnresolvedLimit)
/*
 * FUNCTION: Queues a packet on an NCE for later transmission
 * ARGUMENTS:
 *   NCE        = Pointer to NCE to queue packet on
 *   NdisPacket = Pointer to NDIS packet to queue
 *   UnresolvedLimit = If not 0, the packet is refused when the NCE is
 *                     unresolved and that many packets already wait on it
 * RETURNS:
 *   TRUE if the packet was successfully queued, FALSE if not
 */
{
  KIRQL OldIrql;
  PNEIGHBOR_PACKET Packet;
  PLIST_ENTRY Entry;
  UINT HashValue, Waiting;

  TI_DbgPrint
      (DEBUG_NCACHE,
       ("Called. NCE (0x%X)  NdisPacket (0x%X).\n", NCE, NdisPacket));

  Packet = ExAllocatePoolWithTag( NonPagedPool, sizeof(NEIGHBOR_PACKET),
                                  NEIGHBOR_PACKET_TAG );
  if( !Packet ) return FALSE;

  HashValue  = *(PULONG)(&NCE->Address.Address);
  HashValue ^= HashValue >> 16;
  HashValue ^= HashValue >> 8;
  HashValue ^= HashValue >> 4;
  HashValue &= NB_HASHMASK;

  TcpipAcquireSpinLock(&NeighborCache[HashValue].Lock, &OldIrql);

  /* Out of the cache, no reply resolves it any more and no timeout flushes it: the packet
     would wait until the NCE goes, and its sender may hold the NCE until the packet is done */
  if (NCE->Unlinked && (NCE->State & NUD_INCOMPLETE))
  {
      TcpipReleaseSpinLock(&NeighborCache[HashValue].Lock, OldIrql);
      ExFreePoolWithTag( Packet, NEIGHBOR_PACKET_TAG );
      return FALSE;
  }

  if (UnresolvedLimit && (NCE->State & NUD_INCOMPLETE))
  {
      Waiting = 0;
      for (Entry = NCE->PacketQueue.Flink;
           Entry != &NCE->PacketQueue && Waiting < UnresolvedLimit;
           Entry = Entry->Flink)
          Waiting++;

      if (Waiting >= UnresolvedLimit)
      {
          TcpipReleaseSpinLock(&NeighborCache[HashValue].Lock, OldIrql);
          ExFreePoolWithTag( Packet, NEIGHBOR_PACKET_TAG );
          return FALSE;
      }
  }

  Packet->Complete = PacketComplete;
  Packet->Context = PacketContext;
  Packet->Packet = NdisPacket;
  InsertTailList( &NCE->PacketQueue, &Packet->Next );

  TcpipReleaseSpinLock(&NeighborCache[HashValue].Lock, OldIrql);

  if( !(NCE->State & NUD_INCOMPLETE) )
      NBSendPackets( NCE );

  return TRUE;
}

BOOLEAN NBQueuePacket(
  PNEIGHBOR_CACHE_ENTRY NCE,
  PNDIS_PACKET NdisPacket,
  PNEIGHBOR_PACKET_COMPLETE PacketComplete,
  PVOID PacketContext)
{
  /* FIXME: Should we limit the number of queued packets? */
  return NBQueuePacketLimited(NCE, NdisPacket, PacketComplete, PacketContext, 0);
}

VOID NBRemoveNeighbor(
  PNEIGHBOR_CACHE_ENTRY NCE)
/*
 * FUNCTION: Removes a neighbor from the neighbor cache
 * ARGUMENTS:
 *   NCE = Pointer to NCE to remove from cache
 * NOTES:
 *   The caller holds a reference to the NCE, which it still has to drop
 */
{
  PNEIGHBOR_CACHE_ENTRY *PrevNCE;
  PNEIGHBOR_CACHE_ENTRY CurNCE;
  ULONG HashValue;
  KIRQL OldIrql;
  BOOLEAN Found = FALSE;

  TI_DbgPrint(DEBUG_NCACHE, ("Called. NCE (0x%X).\n", NCE));

  HashValue  = *(PULONG)(&NCE->Address.Address);
  HashValue ^= HashValue >> 16;
  HashValue ^= HashValue >> 8;
  HashValue ^= HashValue >> 4;
  HashValue &= NB_HASHMASK;

  TcpipAcquireSpinLock(&NeighborCache[HashValue].Lock, &OldIrql);

  /* Search the list and remove the NCE from the list if found */
  for (PrevNCE = &NeighborCache[HashValue].Cache;
    (CurNCE = *PrevNCE) != NULL;
    PrevNCE = &CurNCE->Next)
    {
      if (CurNCE == NCE)
        {
          /* Found it, now unlink it from the list */
          *PrevNCE = CurNCE->Next;

          CurNCE->Unlinked = TRUE;
	  NBFlushPacketQueue( CurNCE, NDIS_STATUS_REQUEST_ABORTED );
          Found = TRUE;

	  break;
        }
    }

  TcpipReleaseSpinLock(&NeighborCache[HashValue].Lock, OldIrql);

  /* The cache's reference (not the last one: the caller has one) */
  if (Found)
      NBDereferenceNeighbor(NCE);
}

ULONG NBCopyNeighbors
(PIP_INTERFACE Interface,
 PIPARP_ENTRY ArpTable,
 ULONG Capacity)
/*
 * Counts the neighbors of Interface; when ArpTable is given, copies at most
 * Capacity entries into it. The return value is the number of neighbors seen
 * (it can exceed Capacity if the cache grew), never the number copied.
 */
{
  PNEIGHBOR_CACHE_ENTRY CurNCE;
  KIRQL OldIrql;
  UINT Size = 0, i;

  for (i = 0; i <= NB_HASHMASK; i++) {
      TcpipAcquireSpinLock(&NeighborCache[i].Lock, &OldIrql);
      for( CurNCE = NeighborCache[i].Cache;
	   CurNCE;
	   CurNCE = CurNCE->Next ) {
	  if( CurNCE->Interface == Interface &&
              !AddrIsEqual( &CurNCE->Address, &CurNCE->Interface->Unicast ) ) {
	      if( ArpTable && Size < Capacity ) {
		  UINT CopyLen = min(CurNCE->LinkAddressLength,
				     sizeof(ArpTable[Size].PhysAddr));
		  RtlZeroMemory(&ArpTable[Size], sizeof(ArpTable[Size]));
		  ArpTable[Size].Index = Interface->Index;
		  ArpTable[Size].AddrSize = CopyLen;
		  RtlCopyMemory
		      (ArpTable[Size].PhysAddr,
		       CurNCE->LinkAddress,
		       CopyLen);
		  ArpTable[Size].LogAddr = CurNCE->Address.Address.IPv4Address;
		  if( CurNCE->State & NUD_PERMANENT )
		      ArpTable[Size].Type = ARP_ENTRY_STATIC;
		  else if( CurNCE->State & NUD_INCOMPLETE )
		      ArpTable[Size].Type = ARP_ENTRY_INVALID;
		  else
		      ArpTable[Size].Type = ARP_ENTRY_DYNAMIC;
	      }
	      Size++;
	  }
      }
      TcpipReleaseSpinLock(&NeighborCache[i].Lock, OldIrql);
  }

  return Size;
}
