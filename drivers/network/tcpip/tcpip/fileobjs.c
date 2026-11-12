/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/fileobjs.c
 * PURPOSE:     Routines for handling file objects
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"

/* FIXME: including pstypes.h without ntifs fails */
#include <ntifs.h>
#include <ndk/pstypes.h>
#include <nitrofwk.h>

/* Uncomment for logging of connections and address files every 10 seconds */
//#define LOG_OBJECTS

/* List of all address file objects managed by this driver */
LIST_ENTRY AddressFileListHead;
KSPIN_LOCK AddressFileListLock;
LIST_ENTRY AddressFilePortHash[ADDRESS_FILE_PORT_BUCKETS];

/* List of all connection endpoint file objects managed by this driver */
LIST_ENTRY ConnectionEndpointListHead;
KSPIN_LOCK ConnectionEndpointListLock;

/* Reference an address file found through the global list unless its last
 * reference has already gone, which means AddrFileFree is about to unlink and
 * free it. Returns whether the reference was taken. The caller holds
 * AddressFileListLock, which keeps the entry in memory until it is unlinked. */
static BOOLEAN ReferenceAddressFileIfLive(
    PADDRESS_FILE AddrFile)
{
    LONG OldRefCount;

    do
    {
        OldRefCount = *((volatile LONG *)&AddrFile->RefCount);
        if (OldRefCount == 0)
            return FALSE;
    } while (InterlockedCompareExchange(&AddrFile->RefCount,
                                        OldRefCount + 1,
                                        OldRefCount) != OldRefCount);

    return TRUE;
}

/*
 * FUNCTION: Searches through address file entries to find the first match
 * ARGUMENTS:
 *     Address       = IP address
 *     Port          = Port number
 *     Protocol      = Protocol number
 *     SearchContext = Pointer to search context
 * RETURNS:
 *     Pointer to address file, NULL if none was found
 */
PADDRESS_FILE AddrSearchFirst(
    PIP_ADDRESS Address,
    USHORT Port,
    USHORT Protocol,
    PAF_SEARCH SearchContext)
{
    KIRQL OldIrql;
    PLIST_ENTRY Entry;

    SearchContext->Address  = Address;
    SearchContext->Port     = Port;
    SearchContext->Protocol = Protocol;

    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);

    /* Hold a reference on the first entry that is still alive, so the walk in
     * AddrSearchNext has a stable starting point */
    for (Entry = AddressFileListHead.Flink;
         Entry != &AddressFileListHead;
         Entry = Entry->Flink)
    {
        if (ReferenceAddressFileIfLive(CONTAINING_RECORD(Entry, ADDRESS_FILE, ListEntry)))
            break;
    }

    SearchContext->Next = Entry;

    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);

    return AddrSearchNext(SearchContext);
}

BOOLEAN AddrIsBroadcastMatch(
    PIP_ADDRESS UnicastAddress,
    PIP_ADDRESS BroadcastAddress ) {
    BOOLEAN Match = FALSE;
    KIRQL OldIrql;
    IF_LIST_ITER(IF);

    /* The list changes when an adapter is unbound */
    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);

    ForEachInterface(IF) {
        if ((AddrIsUnspecified(UnicastAddress) ||
             AddrIsEqual(&IF->Unicast, UnicastAddress)) &&
            (AddrIsEqual(&IF->Broadcast, BroadcastAddress))) {
            Match = TRUE;
            break;
        }
    } EndFor(IF);

    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

    return Match;
}

BOOLEAN AddrReceiveMatch(
   PIP_ADDRESS LocalAddress,
   PIP_ADDRESS RemoteAddress)
{
   if (AddrIsEqual(LocalAddress, RemoteAddress))
   {
       /* Unicast address match */
       return TRUE;
   }

   if (AddrIsBroadcastMatch(LocalAddress, RemoteAddress))
   {
       /* Broadcast address match */
       return TRUE;
   }

   if (AddrIsUnspecified(LocalAddress))
   {
       /* Local address unspecified */
       return TRUE;
   }

   if (AddrIsUnspecified(RemoteAddress))
   {
       /* Remote address unspecified */
       return TRUE;
   }

   return FALSE;
}

VOID
LogActiveObjects(VOID)
{
#ifdef LOG_OBJECTS
    PLIST_ENTRY CurrentEntry;
    KIRQL OldIrql;
    PADDRESS_FILE AddrFile;
    PCONNECTION_ENDPOINT Conn;

    DbgPrint("----------- TCP/IP Active Object Dump -------------\n");

    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);

    CurrentEntry = AddressFileListHead.Flink;
    while (CurrentEntry != &AddressFileListHead)
    {
        AddrFile = CONTAINING_RECORD(CurrentEntry, ADDRESS_FILE, ListEntry);

        DbgPrint("Address File (%s, %d, %d) @ 0x%p | Ref count: %d | Sharers: %d\n",
                 A2S(&AddrFile->Address), WN2H(AddrFile->Port), AddrFile->Protocol,
                 AddrFile, AddrFile->RefCount, AddrFile->Sharers);
        DbgPrint("\tListener: ");
        if (AddrFile->Listener == NULL)
            DbgPrint("<None>\n");
        else
            DbgPrint("0x%p\n", AddrFile->Listener);
        DbgPrint("\tAssociated endpoints: ");
        if (AddrFile->Connection == NULL)
            DbgPrint("<None>\n");
        else
        {
            Conn = AddrFile->Connection;
            while (Conn)
            {
                DbgPrint("0x%p ", Conn);
                Conn = Conn->Next;
            }
            DbgPrint("\n");
        }

        CurrentEntry = CurrentEntry->Flink;
    }

    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);

    TcpipAcquireSpinLock(&ConnectionEndpointListLock, &OldIrql);

    CurrentEntry = ConnectionEndpointListHead.Flink;
    while (CurrentEntry != &ConnectionEndpointListHead)
    {
        Conn = CONTAINING_RECORD(CurrentEntry, CONNECTION_ENDPOINT, ListEntry);

        DbgPrint("Connection @ 0x%p | Ref count: %d\n", Conn, Conn->RefCount);
        DbgPrint("\tPCB: ");
        if (Conn->SocketContext == NULL)
            DbgPrint("<None>\n");
        else
        {
            DbgPrint("0x%p\n", Conn->SocketContext);
            LibTCPDumpPcb(Conn->SocketContext);
        }
        DbgPrint("\tPacket queue status: %s\n", IsListEmpty(&Conn->PacketQueue) ? "Empty" : "Not Empty");
        DbgPrint("\tRequest lists: Connect: %s | Recv: %s | Send: %s | Shutdown: %s | Listen: %s\n",
                 IsListEmpty(&Conn->ConnectRequest) ? "Empty" : "Not Empty",
                 IsListEmpty(&Conn->ReceiveRequest) ? "Empty" : "Not Empty",
                 IsListEmpty(&Conn->SendRequest) ? "Empty" : "Not Empty",
                 IsListEmpty(&Conn->ShutdownRequest) ? "Empty" : "Not Empty",
                 IsListEmpty(&Conn->ListenRequest) ? "Empty" : "Not Empty");
        DbgPrint("\tSend shutdown: %s\n", Conn->SendShutdown ? "Yes" : "No");
        DbgPrint("\tReceive shutdown: %s\n", Conn->ReceiveShutdown ? "Yes" : "No");
        if (Conn->ReceiveShutdown) DbgPrint("\tReceive shutdown status: 0x%x\n", Conn->ReceiveShutdownStatus);
        DbgPrint("\tClosing: %s\n", Conn->Closing ? "Yes" : "No");

        CurrentEntry = CurrentEntry->Flink;
    }

    TcpipReleaseSpinLock(&ConnectionEndpointListLock, OldIrql);

    DbgPrint("---------------------------------------------------\n");
#endif
}

/*
 * FUNCTION: Searches through address file entries to find next match
 * ARGUMENTS:
 *     SearchContext = Pointer to search context
 * RETURNS:
 *     Pointer to referenced address file, NULL if none was found
 */
PADDRESS_FILE AddrSearchNext(
    PAF_SEARCH SearchContext)
{
    PLIST_ENTRY CurrentEntry;
    PIP_ADDRESS IPAddress;
    KIRQL OldIrql;
    PADDRESS_FILE Current = NULL;
    BOOLEAN Found = FALSE;
    PADDRESS_FILE StartingAddrFile;

    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);

    if (SearchContext->Next == &AddressFileListHead)
    {
        TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);
        return NULL;
    }

    /* Save this pointer so we can dereference it later */
    StartingAddrFile = CONTAINING_RECORD(SearchContext->Next, ADDRESS_FILE, ListEntry);

    CurrentEntry = SearchContext->Next;

    while (CurrentEntry != &AddressFileListHead) {
        Current = CONTAINING_RECORD(CurrentEntry, ADDRESS_FILE, ListEntry);

        IPAddress = &Current->Address;

        TI_DbgPrint(DEBUG_ADDRFILE, ("Comparing: ((%d, %d, %s), (%d, %d, %s)).\n",
            WN2H(Current->Port),
            Current->Protocol,
            A2S(IPAddress),
            WN2H(SearchContext->Port),
            SearchContext->Protocol,
            A2S(SearchContext->Address)));

        /* See if this address matches the search criteria */
        if ((Current->Port    == SearchContext->Port) &&
            (Current->Protocol == SearchContext->Protocol) &&
            (AddrReceiveMatch(IPAddress, SearchContext->Address)) &&
            /* Skip an address file that is already being freed; referenced before
             * StartingAddrFile is dereferenced, because it may be the same one */
            ReferenceAddressFileIfLive(Current)) {
            /* We've found a match */
            Found = TRUE;
            break;
        }
        CurrentEntry = CurrentEntry->Flink;
    }

    if (Found)
    {
        /* Hold a reference on the next live entry to prevent the link from
         * disappearing behind our back */
        for (SearchContext->Next = CurrentEntry->Flink;
             SearchContext->Next != &AddressFileListHead;
             SearchContext->Next = SearchContext->Next->Flink)
        {
            if (ReferenceAddressFileIfLive(CONTAINING_RECORD(SearchContext->Next, ADDRESS_FILE, ListEntry)))
                break;
        }
    }
    else
        Current = NULL;

    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);

    DereferenceObject(StartingAddrFile);

    return Current;
}

/*
 * Windows decides whether a second socket may bind a port that others hold from the two
 * sockets alone, the same for TCP and UDP. Only bound endpoints count: a listener that has
 * been closed frees the port even while connections it accepted live on, and a connection
 * in TIME-WAIT holds nothing. With Old already bound and New binding:
 *   same address:  an exclusive socket on either side refuses (access denied when New asks
 *                  to reuse an address that Old holds exclusively, in use otherwise); both
 *                  reusing is allowed; reuse requested by New alone is access denied, and
 *                  by Old alone is in use
 *   Old wildcard, New specific: allowed, unless Old is exclusive (access denied)
 *   Old specific, New wildcard: allowed, unless New is exclusive (in use)
 *   two different specific addresses: never conflict
 * (all observed on Windows 10 22H2, probe in releases/2026.11/evidence/wsquirks-20261104).
 * Called with AddressFileListLock held. */
static NTSTATUS AddrBindConflictLocked(
    PADDRESS_FILE New)
{
    PLIST_ENTRY Entry;

    for (Entry = AddressFileListHead.Flink; Entry != &AddressFileListHead; Entry = Entry->Flink)
    {
        PADDRESS_FILE Old = CONTAINING_RECORD(Entry, ADDRESS_FILE, ListEntry);
        BOOLEAN OldWild, NewWild;

        if (Old == New || Old->Port != New->Port || Old->Protocol != New->Protocol ||
            Old->PortReleased || Old->Sharers == 0)
            continue;

        OldWild = AddrIsUnspecified(&Old->Address);
        NewWild = AddrIsUnspecified(&New->Address);

        if (OldWild == NewWild)
        {
            if (!OldWild && !AddrIsEqual(&Old->Address, &New->Address))
                continue;

            if (Old->ShareMode == ADDR_SHARE_EXCLUSIVE || New->ShareMode == ADDR_SHARE_EXCLUSIVE)
            {
                if (Old->ShareMode == ADDR_SHARE_EXCLUSIVE && New->ShareMode == ADDR_SHARE_REUSE)
                    return STATUS_ACCESS_DENIED;
                return STATUS_ADDRESS_ALREADY_EXISTS;
            }
            if (Old->ShareMode == ADDR_SHARE_REUSE && New->ShareMode == ADDR_SHARE_REUSE)
                continue;
            return (New->ShareMode == ADDR_SHARE_REUSE) ? STATUS_ACCESS_DENIED :
                                                          STATUS_ADDRESS_ALREADY_EXISTS;
        }
        else if (OldWild)
        {
            if (Old->ShareMode == ADDR_SHARE_EXCLUSIVE)
                return STATUS_ACCESS_DENIED;
        }
        else if (New->ShareMode == ADDR_SHARE_EXCLUSIVE)
        {
            return STATUS_ADDRESS_ALREADY_EXISTS;
        }
    }

    return STATUS_SUCCESS;
}

/* Gives up the port of an address file that has left (or never entered) the global list: the
 * port bit goes only when no other address file shares the port. */
static VOID AddrReleasePort(
    PADDRESS_FILE AddrFile)
{
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    BOOLEAN Shared = FALSE;

    if (!AddrFile->Port || (AddrFile->Protocol != IPPROTO_TCP && AddrFile->Protocol != IPPROTO_UDP))
        return;

    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
    for (Entry = AddressFileListHead.Flink; Entry != &AddressFileListHead; Entry = Entry->Flink)
    {
        PADDRESS_FILE Other = CONTAINING_RECORD(Entry, ADDRESS_FILE, ListEntry);

        if (Other != AddrFile && Other->Port == AddrFile->Port && Other->Protocol == AddrFile->Protocol)
        {
            Shared = TRUE;
            break;
        }
    }
    if (!Shared)
    {
        if (AddrFile->Protocol == IPPROTO_TCP)
            TCPFreePort(AddrFile->Port);
        else
            UDPFreePort(AddrFile->Port);
    }
    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);
}

VOID AddrFileFree(
    PVOID Object)
/*
 * FUNCTION: Frees an address file object
 * ARGUMENTS:
 *     Object = Pointer to address file object to free
 */
{
  PADDRESS_FILE AddrFile = Object;
  KIRQL OldIrql;
  PDATAGRAM_RECEIVE_REQUEST ReceiveRequest;
  // PDATAGRAM_SEND_REQUEST SendRequest; See WTF below
  PLIST_ENTRY CurrentEntry;

  TI_DbgPrint(MID_TRACE, ("Called.\n"));

  /* We should not be associated with a connection here */
  ASSERT(!AddrFile->Connection);

  /* Remove address file from the global list */
  TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
  RemoveEntryList(&AddrFile->ListEntry);
  RemoveEntryList(&AddrFile->FwPortEntry);
  TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);

  /* The creator process was referenced when the address file was listed */
  if (AddrFile->FwCreator)
      ObDereferenceObject(AddrFile->FwCreator);

  /* Give up the port unless another address file shares it */
  AddrReleasePort(AddrFile);

  /* Off the list: the inbound filter can no longer find (and reference) the image */
  NitroFwReleaseImage(AddrFile->FwImage);

  /* FIXME: Kill TCP connections on this address file object */

  /* Return pending requests with error */

  TI_DbgPrint(DEBUG_ADDRFILE, ("Aborting receive requests on AddrFile at (0x%X).\n", AddrFile));

  /* Go through pending receive request list and cancel them all */
  while (!IsListEmpty(&AddrFile->ReceiveQueue))
  {
    CurrentEntry = RemoveHeadList(&AddrFile->ReceiveQueue);
    ReceiveRequest = CONTAINING_RECORD(CurrentEntry, DATAGRAM_RECEIVE_REQUEST, ListEntry);
    (*ReceiveRequest->Complete)(ReceiveRequest->Context, STATUS_CANCELLED, 0);
    ExFreePoolWithTag(ReceiveRequest, DATAGRAM_RECV_TAG);
  }

  TI_DbgPrint(DEBUG_ADDRFILE, ("Aborting send requests on address file at (0x%X).\n", AddrFile));

#if 0 /* Biggest WTF. All of this was taken care of above as DATAGRAM_RECEIVE_REQUEST. */
  /* Go through pending send request list and cancel them all */
  while (!IsListEmpty(&AddrFile->ReceiveQueue))
  {
    CurrentEntry = RemoveHeadList(&AddrFile->ReceiveQueue);
    SendRequest = CONTAINING_RECORD(CurrentEntry, DATAGRAM_SEND_REQUEST, ListEntry);
    (*SendRequest->Complete)(SendRequest->Context, STATUS_CANCELLED, 0);
    ExFreePoolWithTag(SendRequest, DATAGRAM_SEND_TAG);
  }
#endif

  RemoveEntityByContext(AddrFile);

  ExDeleteResourceLite(&AddrFile->Resource);

  ExFreePoolWithTag(Object, ADDR_FILE_TAG);
}


VOID ControlChannelFree(
    PVOID Object)
/*
 * FUNCTION: Frees an address file object
 * ARGUMENTS:
 *     Object = Pointer to address file object to free
 */
{
    ExFreePoolWithTag(Object, CONTROL_CHANNEL_TAG);
}


/*
 * FUNCTION: Open an address file object
 * ARGUMENTS:
 *     Request  = Pointer to TDI request structure for this request
 *     Address  = Pointer to address to be opened
 *     Protocol = Protocol on which to open the address
 *     ShareAccess = Share access of the open: 0 unique, FILE_SHARE_READ/WRITE reuse
 *                   (SO_REUSEADDR), FILE_SHARE_DELETE alone exclusive (SO_EXCLUSIVEADDRUSE)
 *     Options  = Pointer to option buffer
 * RETURNS:
 *     Status of operation
 */
NTSTATUS FileOpenAddress(
  PTDI_REQUEST Request,
  PTA_IP_ADDRESS Address,
  USHORT Protocol,
  ULONG ShareAccess,
  PVOID Options)
{
  PADDRESS_FILE AddrFile;
  UINT AllocatedPort;
  BOOLEAN ExplicitPort = FALSE;
  KIRQL OldIrql;
  ULONG EntityType, EntityFlags;
  NTSTATUS Status;

  TI_DbgPrint(MID_TRACE, ("Called (Proto %d).\n", Protocol));

  AddrFile = ExAllocatePoolWithTag(NonPagedPool, sizeof(ADDRESS_FILE),
                                   ADDR_FILE_TAG);
  if (!AddrFile) {
    TI_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  RtlZeroMemory(AddrFile, sizeof(ADDRESS_FILE));

  AddrFile->RefCount = 1;
  AddrFile->Free = AddrFileFree;
  AddrFile->Sharers = 1;
  if (ShareAccess & (FILE_SHARE_READ | FILE_SHARE_WRITE))
      AddrFile->ShareMode = ADDR_SHARE_REUSE;
  else if (ShareAccess & FILE_SHARE_DELETE)
      AddrFile->ShareMode = ADDR_SHARE_EXCLUSIVE;
  else
      AddrFile->ShareMode = ADDR_SHARE_UNIQUE;

  /* Set our default options */
  AddrFile->TTL = 128;
  AddrFile->DF = 0;
  AddrFile->BCast = 1;
  AddrFile->HeaderIncl = 1;
  AddrFile->ProcessId = PsGetCurrentProcessId();

  _SEH2_TRY {
      PTEB Teb;

      Teb = PsGetCurrentThreadTeb();
      if (Teb != NULL)
         AddrFile->SubProcessTag = Teb->SubProcessTag;
  } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
      AddrFile->SubProcessTag = 0;
  } _SEH2_END;

  KeQuerySystemTime(&AddrFile->CreationTime);

  /* Make sure address is a local unicast address or 0 */
  /* FIXME: IPv4 only */
  AddrFile->Family = Address->Address[0].AddressType;
  AddrFile->Address.Address.IPv4Address = Address->Address[0].Address[0].in_addr;
  AddrFile->Address.Type = IP_ADDRESS_V4;

  if (!AddrIsUnspecified(&AddrFile->Address)) {
      PIP_INTERFACE LocalIF = AddrLocateInterface(&AddrFile->Address);

      if (!LocalIF) {
	  TI_DbgPrint(MIN_TRACE, ("Non-local address given (0x%X).\n", A2S(&AddrFile->Address)));
	  ExFreePoolWithTag(AddrFile, ADDR_FILE_TAG);
	  return STATUS_INVALID_ADDRESS;
      }
      IPDereferenceInterface(LocalIF);
  }

  TI_DbgPrint(MID_TRACE, ("Opening address %s for communication (P=%d U=%d).\n",
    A2S(&AddrFile->Address), Protocol, IPPROTO_UDP));

  /* Protocol specific handling */
  switch (Protocol) {
  case IPPROTO_TCP:
      if (Address->Address[0].Address[0].sin_port)
      {
          /* The client specified an explicit port: whether it may have it is decided
             against the other bound endpoints when the file is listed (below) */
          ExplicitPort = TRUE;
          AddrFile->Port = Address->Address[0].Address[0].sin_port;
      }
      else
      {
          /* No port given: reserve an ephemeral one now, so that getsockname
             after bind reports it for a wildcard address as well */
          PTCP_CONNECT_HINT Hint = (PTCP_CONNECT_HINT)Address->Address[0].Address[0].sin_zero;

          if (Hint->Magic == TCP_CONNECT_HINT_MAGIC)
              AllocatedPort = TCPAllocatePortForRemote(Hint->RemoteAddress, Hint->RemotePort);
          else
              AllocatedPort = TCPAllocatePort(0);

          /* Every ephemeral port is taken: WSAENOBUFS, as on Windows. The free ones all hold a TIME-WAIT of the
             remote endpoint the connect is for: WSAEADDRINUSE, as on Windows */
          if (AllocatedPort == (UINT)-1 || AllocatedPort == TCP_PORT_TIME_WAIT)
          {
              ExFreePoolWithTag(AddrFile, ADDR_FILE_TAG);
              return AllocatedPort == TCP_PORT_TIME_WAIT ? STATUS_ADDRESS_ALREADY_EXISTS : STATUS_INSUFFICIENT_RESOURCES;
          }
          AddrFile->Port = AllocatedPort;
      }

      EntityType = CO_TL_ENTITY;
      EntityFlags = CO_TL_TCP;

      AddrFile->Send = NULL; /* TCPSendData */
      break;

  case IPPROTO_UDP:
      TI_DbgPrint(MID_TRACE,("Allocating udp port\n"));
      if (Address->Address[0].Address[0].sin_port)
      {
          /* Decided against the other bound endpoints when the file is listed (below) */
          ExplicitPort = TRUE;
          AddrFile->Port = Address->Address[0].Address[0].sin_port;
      }
      else
      {
          AllocatedPort = UDPAllocatePort(0);
          if (AllocatedPort == (UINT)-1)
          {
              ExFreePoolWithTag(AddrFile, ADDR_FILE_TAG);
              return STATUS_ADDRESS_ALREADY_EXISTS;
          }
          AddrFile->Port = AllocatedPort;
      }

      TI_DbgPrint(MID_TRACE,("Setting port %d (wanted %d)\n",
                             AddrFile->Port,
                             Address->Address[0].Address[0].sin_port));

      EntityType = CL_TL_ENTITY;
      EntityFlags = CL_TL_UDP;

      AddrFile->Send = UDPSendDatagram;
      break;

  case IPPROTO_ICMP:
    AddrFile->Port = 0;
    AddrFile->Send = ICMPSendDatagram;

    /* FIXME: Verify this */
    EntityType = ER_ENTITY;
    EntityFlags = ER_ICMP;
    break;

  default:
    /* Use raw IP for all other protocols */
    AddrFile->Port = 0;
    AddrFile->Send = RawIPSendDatagram;

    /* FIXME: Verify this */
    EntityType = CL_TL_ENTITY;
    EntityFlags = 0;
    break;
  }

  TI_DbgPrint(MID_TRACE, ("IP protocol number for address file object is %d.\n",
    Protocol));

  TI_DbgPrint(MID_TRACE, ("Port number for address file object is %d.\n",
    WN2H(AddrFile->Port)));

  /* Set protocol */
  AddrFile->Protocol = Protocol;

  /* Initialize receive and transmit queues */
  InitializeListHead(&AddrFile->ReceiveQueue);
  InitializeListHead(&AddrFile->TransmitQueue);

  /* Initialize spin lock that protects the address file object */
  ExInitializeResourceLite(&AddrFile->Resource);

  /* Running out of memory here fails the open cleanly (WSAENOBUFS) */
  Status = AddEntity(EntityType, AddrFile, EntityFlags);
  if (!NT_SUCCESS(Status))
  {
      if (!ExplicitPort)
          AddrReleasePort(AddrFile);
      ExDeleteResourceLite(&AddrFile->Resource);
      ExFreePoolWithTag(AddrFile, ADDR_FILE_TAG);
      return Status;
  }

  /* Return address file object */
  Request->Handle.AddressHandle = AddrFile;

  AddrFile->ExplicitPort = ExplicitPort;

  /* Add address file to global list, if the bind rules let it have its port */
  TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
  Status = STATUS_SUCCESS;
  if (Protocol == IPPROTO_TCP || Protocol == IPPROTO_UDP)
  {
      Status = AddrBindConflictLocked(AddrFile);
      if (NT_SUCCESS(Status) && ExplicitPort)
      {
          BOOLEAN Reserved = (Protocol == IPPROTO_TCP) ? TCPReservePort(AddrFile->Port) :
                                                         UDPReservePort(AddrFile->Port);
          if (!Reserved)
              Status = STATUS_ADDRESS_ALREADY_EXISTS;
      }
  }
  if (NT_SUCCESS(Status))
  {
      /* The creator stays referenced for the life of the address file: its process id cannot be handed to a new
         process meanwhile, so the id on the address file always names the creator (the inbound filter resolves a
         program rule image from it for sockets that exist before the rule does) */
      AddrFile->FwCreator = PsGetCurrentProcess();
      ObReferenceObject(AddrFile->FwCreator);
      InsertTailList(&AddressFileListHead, &AddrFile->ListEntry);
      InsertTailList(&AddressFilePortHash[ADDRESS_FILE_PORT_BUCKET(AddrFile->Port)], &AddrFile->FwPortEntry);
  }
  TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);

  if (!NT_SUCCESS(Status))
  {
      RemoveEntityByContext(AddrFile);
      if (!ExplicitPort)
          AddrReleasePort(AddrFile);
      ExDeleteResourceLite(&AddrFile->Resource);
      ExFreePoolWithTag(AddrFile, ADDR_FILE_TAG);
      return Status;
  }

  /* Creator image for program rules of the inbound filter: resolved only while an enforced policy has
     program rules (no work otherwise). Done once the file is listed, so a policy installed
     concurrently finds it in its backfill pass. */
  NITROFW_ADDRFILE_CREATED(AddrFile);

  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));

  return STATUS_SUCCESS;
}


/*
 * FUNCTION: Closes an address file object
 * ARGUMENTS:
 *     Request = Pointer to TDI request structure for this request
 * RETURNS:
 *     Status of operation
 */
NTSTATUS FileCloseAddress(
  PTDI_REQUEST Request)
{
  PADDRESS_FILE AddrFile = Request->Handle.AddressHandle;
  PCONNECTION_ENDPOINT Listener;
  KIRQL OldIrql;
  BOOLEAN LastSharer;

  if (!Request->Handle.AddressHandle) return STATUS_INVALID_PARAMETER;

  LockObject(AddrFile);

  /* Decrement the sharer count under AddressFileListLock, so that the bind rules
   * (AddrBindConflictLocked) see the file as released or not, never in between. */
  TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
  LastSharer = (InterlockedDecrement(&AddrFile->Sharers) == 0);
  /* No longer a bound endpoint, though connections it accepted may hold the object for a while */
  if (LastSharer)
      AddrFile->PortReleased = TRUE;
  TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);

  if (!LastSharer)
  {
      /* Still other guys have open handles to this, so keep it around */
      UnlockObject(AddrFile);
      return STATUS_SUCCESS;
  }

  /* We have to close this listener because we started it */
  Listener = AddrFile->Listener;
  UnlockObject(AddrFile);
  if( Listener )
  {
      TCPClose( Listener );
  }

  DereferenceObject(AddrFile);

  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));

  return STATUS_SUCCESS;
}


/*
 * FUNCTION: Opens a connection file object
 * ARGUMENTS:
 *     Request       = Pointer to TDI request structure for this request
 *     ClientContext = Pointer to client context information
 * RETURNS:
 *     Status of operation
 */
NTSTATUS FileOpenConnection(
  PTDI_REQUEST Request,
  PVOID ClientContext)
{
  NTSTATUS Status;
  PCONNECTION_ENDPOINT Connection;

  TI_DbgPrint(MID_TRACE, ("Called.\n"));

  Connection = TCPAllocateConnectionEndpoint( ClientContext );

  if( !Connection ) return STATUS_NO_MEMORY;

  Status = TCPSocket( Connection, AF_INET, SOCK_STREAM, IPPROTO_TCP );

  if( !NT_SUCCESS(Status) ) {
      DereferenceObject( Connection );
      return Status;
  }

  /* Return connection endpoint file object */
  Request->Handle.ConnectionContext = Connection;

  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));

  return STATUS_SUCCESS;
}

/*
 * FUNCTION: Closes an connection file object
 * ARGUMENTS:
 *     Request = Pointer to TDI request structure for this request
 * RETURNS:
 *     Status of operation
 */
NTSTATUS FileCloseConnection(
  PTDI_REQUEST Request)
{
  PCONNECTION_ENDPOINT Connection;

  TI_DbgPrint(MID_TRACE, ("Called.\n"));

  Connection = Request->Handle.ConnectionContext;

  if (!Connection) return STATUS_INVALID_PARAMETER;

  TCPClose( Connection );

  Request->Handle.ConnectionContext = NULL;

  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));

  return STATUS_SUCCESS;
}

/*
 * FUNCTION: Opens a control channel file object
 * ARGUMENTS:
 *     Request = Pointer to TDI request structure for this request
 * RETURNS:
 *     Status of operation
 */
NTSTATUS FileOpenControlChannel(
    PTDI_REQUEST Request)
{
  PCONTROL_CHANNEL ControlChannel;
  TI_DbgPrint(MID_TRACE, ("Called.\n"));

  ControlChannel = ExAllocatePoolWithTag(NonPagedPool, sizeof(*ControlChannel),
                                         CONTROL_CHANNEL_TAG);

  if (!ControlChannel) {
    TI_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  RtlZeroMemory(ControlChannel, sizeof(CONTROL_CHANNEL));

  /* Make sure address is a local unicast address or 0 */

  /* Locate address entry. If specified address is 0, a random address is chosen */

  /* Initialize receive and transmit queues */
  InitializeListHead(&ControlChannel->ListEntry);

  /* Initialize spin lock that protects the address file object */
  KeInitializeSpinLock(&ControlChannel->Lock);

  ControlChannel->RefCount = 1;
  ControlChannel->Free = ControlChannelFree;

  /* Return address file object */
  Request->Handle.ControlChannel = ControlChannel;

  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));

  return STATUS_SUCCESS;
}

/*
 * FUNCTION: Closes a control channel file object
 * ARGUMENTS:
 *     Request = Pointer to TDI request structure for this request
 * RETURNS:
 *     Status of operation
 */
NTSTATUS FileCloseControlChannel(
  PTDI_REQUEST Request)
{
  if (!Request->Handle.ControlChannel) return STATUS_INVALID_PARAMETER;

  DereferenceObject((PCONTROL_CHANNEL)Request->Handle.ControlChannel);

  Request->Handle.ControlChannel = NULL;

  return STATUS_SUCCESS;
}

/* EOF */
