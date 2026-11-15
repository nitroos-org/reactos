/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/interface.c
 * PURPOSE:     Convenient abstraction for getting and setting information
 *              in IP_INTERFACE.
 * PROGRAMMERS: Art Yerkes
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"

#include <ntifs.h>
#include <ipifcons.h>

ULONG NextDefaultAdapter = 0;

NTSTATUS GetInterfaceIPv4Address( PIP_INTERFACE Interface,
				  ULONG TargetType,
				  PULONG Address ) {
    switch( TargetType ) {
    case ADE_UNICAST:
	*Address = Interface->Unicast.Address.IPv4Address;
	break;

    case ADE_ADDRMASK:
	*Address = Interface->Netmask.Address.IPv4Address;
	break;

    case ADE_BROADCAST:
	*Address = Interface->Broadcast.Address.IPv4Address;
	break;

    case ADE_POINTOPOINT:
	*Address = Interface->PointToPoint.Address.IPv4Address;
	break;

    default:
	return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

UINT CountInterfaces() {
    ULONG Count = 0;
    KIRQL OldIrql;
    IF_LIST_ITER(CurrentIF);

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);

    ForEachInterface(CurrentIF) {
	Count++;
    } EndFor(CurrentIF);

    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

    return Count;
}

NTSTATUS GetInterfaceSpeed( PIP_INTERFACE Interface, PUINT Speed ) {
    PLAN_ADAPTER IF = (PLAN_ADAPTER)Interface->Context;

    *Speed = IF->Speed;

    return STATUS_SUCCESS;
}

NTSTATUS GetInterfaceName( PIP_INTERFACE Interface,
			   PCHAR NameBuffer,
			   UINT Len ) {
    ULONG ResultSize = 0;
    NTSTATUS Status =
	RtlUnicodeToMultiByteN( NameBuffer,
				Len,
				&ResultSize,
				Interface->Name.Buffer,
				Interface->Name.Length );

    if( NT_SUCCESS(Status) )
	NameBuffer[ResultSize] = 0;
    else
	NameBuffer[0] = 0;

    return Status;
}

BOOLEAN HasLoopbackPrefix(PIP_ADDRESS Address, PIP_ADDRESS Prefix);

/* Additional addresses of an interface (IP_NTE, ip.h). NteLock is a leaf lock; the interface list lock, when it is
 * needed too, is taken first */

/* Is Address one of the additional addresses of the interface? */
BOOLEAN IFIsNteIPv4Address(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Address)
{
    KIRQL OldIrql;
    BOOLEAN Found = FALSE;
    UINT i;

    if (Address == 0)
        return FALSE;

    TcpipAcquireSpinLock(&Interface->NteLock, &OldIrql);
    for (i = 0; i < Interface->NteCount; i++)
    {
        if (Interface->Nte[i].Address == Address)
        {
            Found = TRUE;
            break;
        }
    }
    TcpipReleaseSpinLock(&Interface->NteLock, OldIrql);

    return Found;
}

/* Is Address the primary or an additional address of the interface? */
BOOLEAN IFIsOwnIPv4Address(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Address)
{
    if (Address == 0)
        return FALSE;
    if (Interface->Unicast.Type == IP_ADDRESS_V4 && Interface->Unicast.Address.IPv4Address == Address)
        return TRUE;
    return IFIsNteIPv4Address(Interface, Address);
}

/* Is Address in the subnet of one of the additional addresses of the interface? */
BOOLEAN IFIsNteSubnet(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Address)
{
    KIRQL OldIrql;
    BOOLEAN Found = FALSE;
    UINT i;

    TcpipAcquireSpinLock(&Interface->NteLock, &OldIrql);
    for (i = 0; i < Interface->NteCount; i++)
    {
        if (Interface->Nte[i].Netmask != 0 &&
            (Address & Interface->Nte[i].Netmask) == (Interface->Nte[i].Address & Interface->Nte[i].Netmask))
        {
            Found = TRUE;
            break;
        }
    }
    TcpipReleaseSpinLock(&Interface->NteLock, OldIrql);

    return Found;
}

/* The local address to send to Destination from over the interface: the primary address, unless Destination is in the
 * subnet of an additional address and not in that of the primary one (then the address of that subnet), and the
 * first additional address when the interface has no primary one */
IPv4_RAW_ADDRESS IFSelectSourceAddress(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Destination)
{
    KIRQL OldIrql;
    IPv4_RAW_ADDRESS Primary = Interface->Unicast.Address.IPv4Address;
    IPv4_RAW_ADDRESS Mask = Interface->Netmask.Address.IPv4Address;
    IPv4_RAW_ADDRESS Selected = Primary;
    UINT i;

    if (Interface->Unicast.Type != IP_ADDRESS_V4)
        return Primary;
    if (Primary != 0 && Mask != 0 && (Destination & Mask) == (Primary & Mask))
        return Primary;

    TcpipAcquireSpinLock(&Interface->NteLock, &OldIrql);
    if (Primary == 0 && Interface->NteCount != 0)
        Selected = Interface->Nte[0].Address;
    for (i = 0; i < Interface->NteCount; i++)
    {
        if (Interface->Nte[i].Netmask != 0 &&
            (Destination & Interface->Nte[i].Netmask) == (Interface->Nte[i].Address & Interface->Nte[i].Netmask))
        {
            Selected = Interface->Nte[i].Address;
            break;
        }
    }
    TcpipReleaseSpinLock(&Interface->NteLock, OldIrql);

    return Selected;
}

UINT IFCountNtes(PIP_INTERFACE Interface)
{
    KIRQL OldIrql;
    UINT Count;

    TcpipAcquireSpinLock(&Interface->NteLock, &OldIrql);
    Count = Interface->NteCount;
    TcpipReleaseSpinLock(&Interface->NteLock, OldIrql);

    return Count;
}

/* Copies at most Capacity additional addresses; returns how many */
UINT IFCopyNtes(PIP_INTERFACE Interface, PIP_NTE Entries, UINT Capacity)
{
    KIRQL OldIrql;
    UINT Count;

    TcpipAcquireSpinLock(&Interface->NteLock, &OldIrql);
    Count = min(Interface->NteCount, Capacity);
    RtlCopyMemory(Entries, Interface->Nte, Count * sizeof(IP_NTE));
    TcpipReleaseSpinLock(&Interface->NteLock, OldIrql);

    return Count;
}

static BOOLEAN IFNteContextInUse(USHORT Context)
{
    PIP_INTERFACE CurrentIF;
    PLIST_ENTRY CurrentEntry;
    BOOLEAN InUse = FALSE;
    KIRQL OldIrql;
    UINT i;

    /* The caller holds the interface list lock */
    for (CurrentEntry = InterfaceListHead.Flink; CurrentEntry != &InterfaceListHead && !InUse; CurrentEntry = CurrentEntry->Flink)
    {
        CurrentIF = CONTAINING_RECORD(CurrentEntry, IP_INTERFACE, ListEntry);
        TcpipAcquireSpinLock(&CurrentIF->NteLock, &OldIrql);
        for (i = 0; i < CurrentIF->NteCount; i++)
        {
            if (CurrentIF->Nte[i].Context == Context)
            {
                InUse = TRUE;
                break;
            }
        }
        TcpipReleaseSpinLock(&CurrentIF->NteLock, OldIrql);
    }

    return InUse;
}

/* Adds an additional address; the context that DeleteIPAddress takes for it comes back in *Context. The interface is
 * one the caller holds a reference to */
NTSTATUS IFAddNte(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Address, IPv4_RAW_ADDRESS Netmask, PUSHORT Context)
{
    static volatile LONG NextContext = 0;
    KIRQL OldIrql, OldIrql2;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
    USHORT Candidate = 0;
    UINT Tries;
    PLIST_ENTRY CurrentEntry;

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);

    /* The caller checked for a duplicate without the lock; two adds of one address at the same time must not both
     * get in */
    for (CurrentEntry = InterfaceListHead.Flink; CurrentEntry != &InterfaceListHead; CurrentEntry = CurrentEntry->Flink)
    {
        if (IFIsOwnIPv4Address(CONTAINING_RECORD(CurrentEntry, IP_INTERFACE, ListEntry), Address))
        {
            TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);
            return STATUS_DUPLICATE_OBJECTID;
        }
    }

    /* The contexts are 15 bits, all of the system's additional addresses are far fewer */
    for (Tries = 0; Tries < 0x8000; Tries++)
    {
        Candidate = (USHORT)(IP_NTE_CONTEXT_BASE | (InterlockedIncrement(&NextContext) & (IP_NTE_CONTEXT_BASE - 1)));
        if (!IFNteContextInUse(Candidate))
            break;
    }

    if (Tries < 0x8000)
    {
        TcpipAcquireSpinLock(&Interface->NteLock, &OldIrql2);
        if (Interface->NteCount < IP_MAX_NTE)
        {
            Interface->Nte[Interface->NteCount].Address = Address;
            Interface->Nte[Interface->NteCount].Netmask = Netmask;
            Interface->Nte[Interface->NteCount].Context = Candidate;
            Interface->NteCount++;
            *Context = Candidate;
            Status = STATUS_SUCCESS;
        }
        TcpipReleaseSpinLock(&Interface->NteLock, OldIrql2);
    }

    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

    return Status;
}

/* Removes the additional address with that context from whichever interface has it; the interface comes back
 * referenced in *Owner (IPDereferenceInterface) */
BOOLEAN IFRemoveNteByContext(USHORT Context, PIP_NTE Removed, PIP_INTERFACE *Owner)
{
    PIP_INTERFACE CurrentIF;
    PLIST_ENTRY CurrentEntry;
    BOOLEAN Found = FALSE;
    KIRQL OldIrql, OldIrql2;
    UINT i;

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);

    for (CurrentEntry = InterfaceListHead.Flink; CurrentEntry != &InterfaceListHead && !Found; CurrentEntry = CurrentEntry->Flink)
    {
        CurrentIF = CONTAINING_RECORD(CurrentEntry, IP_INTERFACE, ListEntry);
        TcpipAcquireSpinLock(&CurrentIF->NteLock, &OldIrql2);
        for (i = 0; i < CurrentIF->NteCount; i++)
        {
            if (CurrentIF->Nte[i].Context == Context)
            {
                *Removed = CurrentIF->Nte[i];
                CurrentIF->NteCount--;
                for (; i < CurrentIF->NteCount; i++)
                    CurrentIF->Nte[i] = CurrentIF->Nte[i + 1];
                Found = TRUE;
                break;
            }
        }
        TcpipReleaseSpinLock(&CurrentIF->NteLock, OldIrql2);
        if (Found)
        {
            IPReferenceInterface(CurrentIF);
            *Owner = CurrentIF;
        }
    }

    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

    return Found;
}

/* Forgets all additional addresses (the adapter went down; its neighbors and routes are destroyed with it) */
VOID IFClearNtes(PIP_INTERFACE Interface)
{
    KIRQL OldIrql;

    TcpipAcquireSpinLock(&Interface->NteLock, &OldIrql);
    Interface->NteCount = 0;
    TcpipReleaseSpinLock(&Interface->NteLock, OldIrql);
}


/* The interface with that unicast or broadcast address, referenced for the caller (IPDereferenceInterface) */
PIP_INTERFACE AddrLocateInterface(
    PIP_ADDRESS MatchAddress)
{
    KIRQL OldIrql;
    PIP_INTERFACE RetIF = NULL;
    IF_LIST_ITER(CurrentIF);

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);

    ForEachInterface(CurrentIF) {
	/* The loopback interface owns the whole 127.0.0.0/8, as on Windows */
	if( AddrIsEqual( &CurrentIF->Unicast, MatchAddress ) ||
            AddrIsEqual( &CurrentIF->Broadcast, MatchAddress ) ||
            (MatchAddress->Type == IP_ADDRESS_V4 &&
             IFIsNteIPv4Address( CurrentIF, MatchAddress->Address.IPv4Address )) ||
            HasLoopbackPrefix( MatchAddress, &CurrentIF->Unicast ) ) {
            RetIF = CurrentIF;
            IPReferenceInterface(RetIF);
            break;
	}
    } EndFor(CurrentIF);

    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

    return RetIF;
}

BOOLEAN HasPrefix(
    PIP_ADDRESS Address,
    PIP_ADDRESS Prefix,
    UINT Length)
/*
 * FUNCTION: Determines wether an address has an given prefix
 * ARGUMENTS:
 *     Address = Pointer to address to use
 *     Prefix  = Pointer to prefix to check for
 *     Length  = Length of prefix
 * RETURNS:
 *     TRUE if the address has the prefix, FALSE if not
 * NOTES:
 *     The two addresses must be of the same type
 */
{
    PUCHAR pAddress = (PUCHAR)&Address->Address;
    PUCHAR pPrefix  = (PUCHAR)&Prefix->Address;

    TI_DbgPrint(DEBUG_ROUTER, ("Called. Address (0x%X)  Prefix (0x%X)  Length (%d).\n", Address, Prefix, Length));

#if 0
    TI_DbgPrint(DEBUG_ROUTER, ("Address (%s)  Prefix (%s).\n",
        A2S(Address), A2S(Prefix)));
#endif

    /* Don't report matches for empty prefixes */
    if (Length == 0) {
        return FALSE;
    }

    /* Check that initial integral bytes match */
    while (Length > 8) {
        if (*pAddress++ != *pPrefix++)
            return FALSE;
        Length -= 8;
    }

    /* Check any remaining bits */
    if ((Length > 0) && ((*pAddress >> (8 - Length)) != (*pPrefix >> (8 - Length))))
        return FALSE;

    return TRUE;
}

/* Called with InterfaceListLock held, which keeps the interfaces on the list alive */
static
PIP_INTERFACE GetDefaultInterfaceLocked(VOID)
{
   ULONG Index = 0;
   ULONG IfStatus;

   IF_LIST_ITER(CurrentIF);

   /* DHCP hack: Always return the adapter without an IP address */
   ForEachInterface(CurrentIF) {
      if (CurrentIF->Context && AddrIsUnspecified(&CurrentIF->Unicast)) {
          GetInterfaceConnectionStatus(CurrentIF, &IfStatus);
          if (IfStatus == MIB_IF_OPER_STATUS_OPERATIONAL) {
              return CurrentIF;
          }
      }
   } EndFor(CurrentIF);

   /* Try to continue from the next adapter */
   ForEachInterface(CurrentIF) {
      if (CurrentIF->Context && (Index++ == NextDefaultAdapter)) {
          GetInterfaceConnectionStatus(CurrentIF, &IfStatus);
          if (IfStatus == MIB_IF_OPER_STATUS_OPERATIONAL) {
              NextDefaultAdapter++;
              return CurrentIF;
          }
      }
   } EndFor(CurrentIF);

   /* No luck, so we'll choose the first adapter this time */
   Index = 0;
   ForEachInterface(CurrentIF) {
      if (CurrentIF->Context) {
          Index++;
          GetInterfaceConnectionStatus(CurrentIF, &IfStatus);
          if (IfStatus == MIB_IF_OPER_STATUS_OPERATIONAL) {
              NextDefaultAdapter = Index;
              return CurrentIF;
          }
      }
   } EndFor(CurrentIF);

   /* Even that didn't work, so we'll just go with loopback */
   NextDefaultAdapter = 0;

   /* There are no physical interfaces on the system
    * so we must pick the loopback interface */

   return Loopback;
}

/* Not referenced: only to compare with (NBLocateNeighbor, under a neighbor cache lock) */
PIP_INTERFACE GetDefaultInterface(VOID)
{
   KIRQL OldIrql;
   PIP_INTERFACE IF;

   TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);
   IF = GetDefaultInterfaceLocked();
   TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

   return IF;
}

/* The default interface, referenced for the caller (IPDereferenceInterface) */
PIP_INTERFACE IPReferenceDefaultInterface(VOID)
{
   KIRQL OldIrql;
   PIP_INTERFACE IF;

   TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);
   IF = GetDefaultInterfaceLocked();
   if (IF)
       IPReferenceInterface(IF);
   TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

   return IF;
}

BOOLEAN
HasLoopbackPrefix(
    PIP_ADDRESS Address,
    PIP_ADDRESS Prefix)
{
    if (Address->Type == IP_ADDRESS_V4 && Prefix->Type == IP_ADDRESS_V4 &&
        ((Address->Address.IPv4Address & LOOPBACK_ADDRMASK_IPv4) == (LOOPBACK_ADDRESS_IPv4 & LOOPBACK_ADDRMASK_IPv4)) && 
        (Prefix->Address.IPv4Address == LOOPBACK_ADDRESS_IPv4))
        return TRUE;

    return FALSE;
}

PIP_INTERFACE FindOnLinkInterface(PIP_ADDRESS Address)
/*
 * FUNCTION: Checks all on-link prefixes to find out if an address is on-link
 * ARGUMENTS:
 *     Address = Pointer to address to check
 * RETURNS:
 *     Pointer to interface if address is on-link, NULL if not; the
 *     interface is referenced for the caller (IPDereferenceInterface)
 */
{
    KIRQL OldIrql;
    IF_LIST_ITER(CurrentIF);

    TI_DbgPrint(DEBUG_ROUTER, ("Called. Address (0x%X)\n", Address));
    TI_DbgPrint(DEBUG_ROUTER, ("Address (%s)\n", A2S(Address)));

    if (AddrIsUnspecified(Address))
        return IPReferenceDefaultInterface();

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);

    ForEachInterface(CurrentIF) {
        if (HasLoopbackPrefix(Address, &CurrentIF->Unicast) ||
            HasPrefix(Address, &CurrentIF->Unicast, AddrCountPrefixBits(&CurrentIF->Netmask)) ||
            (Address->Type == IP_ADDRESS_V4 && IFIsNteSubnet(CurrentIF, Address->Address.IPv4Address)))
        {
            IPReferenceInterface(CurrentIF);
            TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);
            return CurrentIF;
        }
    } EndFor(CurrentIF);

    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

    return NULL;
}

VOID GetInterfaceConnectionStatus(PIP_INTERFACE Interface, PULONG Result)
{
    PLAN_ADAPTER Adapter = Interface->Context;

    /* Loopback has no adapter context */
    if (Adapter == NULL || Adapter->State == LAN_STATE_STARTED) {
        *Result = MIB_IF_OPER_STATUS_OPERATIONAL;
    }
    else {
        *Result = MIB_IF_OPER_STATUS_DISCONNECTED;
    }
}
