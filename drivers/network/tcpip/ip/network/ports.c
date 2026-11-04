/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/ports.c
 * PURPOSE:     Port allocation
 * PROGRAMMERS: arty (ayerkes@speakeasy.net)
 * REVISIONS:
 *   arty 20041114 Created
 */

#include "precomp.h"

NTSTATUS PortsStartup( PPORT_SET PortSet,
		   UINT StartingPort,
		   UINT PortsToManage ) {
    PortSet->StartingPort = StartingPort;
    PortSet->PortsToOversee = PortsToManage;
    PortSet->NextPort = 0;

    PortSet->ProtoBitBuffer =
	ExAllocatePoolWithTag( NonPagedPool, (PortSet->PortsToOversee + 7) / 8,
                               PORT_SET_TAG );
    if(!PortSet->ProtoBitBuffer) return STATUS_INSUFFICIENT_RESOURCES;
    RtlInitializeBitMap( &PortSet->ProtoBitmap,
			 PortSet->ProtoBitBuffer,
			 PortSet->PortsToOversee );
    RtlClearAllBits( &PortSet->ProtoBitmap );
    KeInitializeSpinLock( &PortSet->Lock );
    return STATUS_SUCCESS;
}

VOID PortsShutdown( PPORT_SET PortSet ) {
    ExFreePoolWithTag( PortSet->ProtoBitBuffer, PORT_SET_TAG );
}

VOID DeallocatePort( PPORT_SET PortSet, ULONG Port ) {
    KIRQL OldIrql;

    Port = htons(Port);
    ASSERT(Port >= PortSet->StartingPort);
    ASSERT(Port < PortSet->StartingPort + PortSet->PortsToOversee);

    KeAcquireSpinLock( &PortSet->Lock, &OldIrql );
    RtlClearBits( &PortSet->ProtoBitmap, Port - PortSet->StartingPort, 1 );
    KeReleaseSpinLock( &PortSet->Lock, OldIrql );
}

BOOLEAN AllocatePort( PPORT_SET PortSet, ULONG Port ) {
    BOOLEAN Clear;
    KIRQL OldIrql;

    Port = htons(Port);

    if ((Port < PortSet->StartingPort) ||
        (Port >= PortSet->StartingPort + PortSet->PortsToOversee))
    {
       return FALSE;
    }

    Port -= PortSet->StartingPort;

    KeAcquireSpinLock( &PortSet->Lock, &OldIrql );
    Clear = RtlAreBitsClear( &PortSet->ProtoBitmap, Port, 1 );
    if( Clear ) RtlSetBits( &PortSet->ProtoBitmap, Port, 1 );
    KeReleaseSpinLock( &PortSet->Lock, OldIrql );

    return Clear;
}

/* Marks a port as taken whether or not it already was: several address files may share
 * a port when the bind rules allow it (see AddrBindConflict). FALSE if outside the set. */
BOOLEAN ReservePort( PPORT_SET PortSet, ULONG Port ) {
    KIRQL OldIrql;

    Port = htons(Port);

    if ((Port < PortSet->StartingPort) ||
        (Port >= PortSet->StartingPort + PortSet->PortsToOversee))
    {
       return FALSE;
    }

    Port -= PortSet->StartingPort;

    KeAcquireSpinLock( &PortSet->Lock, &OldIrql );
    RtlSetBits( &PortSet->ProtoBitmap, Port, 1 );
    KeReleaseSpinLock( &PortSet->Lock, OldIrql );

    return TRUE;
}

ULONG AllocateAnyPort( PPORT_SET PortSet ) {
    ULONG AllocatedPort;
    KIRQL OldIrql;

    KeAcquireSpinLock( &PortSet->Lock, &OldIrql );
    AllocatedPort = RtlFindClearBits( &PortSet->ProtoBitmap, 1, 0 );
    if( AllocatedPort != (ULONG)-1 ) {
	RtlSetBit( &PortSet->ProtoBitmap, AllocatedPort );
	AllocatedPort += PortSet->StartingPort;
	KeReleaseSpinLock( &PortSet->Lock, OldIrql );
	return htons(AllocatedPort);
    }
    KeReleaseSpinLock( &PortSet->Lock, OldIrql );

    return -1;
}

/* Next fit: a port is handed out again only after the rest of the range, so a
   new socket does not take the port a closed one used a moment ago (a connect
   to that closed port would connect the socket to itself) */
ULONG AllocatePortFromRange( PPORT_SET PortSet, ULONG Lowest, ULONG Highest ) {
    return AllocatePortFromRangeUnless( PortSet, Lowest, Highest, NULL );
}

/* As AllocatePortFromRange, but also skip the ports InUse (called with the
   port lock held, port in host order) reports as taken */
ULONG AllocatePortFromRangeUnless( PPORT_SET PortSet, ULONG Lowest, ULONG Highest,
                                   PPORT_IN_USE_ROUTINE InUse ) {
    ULONG Port, Start, Count, i;
    KIRQL OldIrql;

    /* The range is inclusive, and a port must fit in 16 bits */
    if ((Lowest < PortSet->StartingPort) ||
        (Highest >= PortSet->StartingPort + PortSet->PortsToOversee) ||
        (Highest > 0xFFFF) ||
        (Lowest > Highest))
    {
        return -1;
    }

    Count = Highest - Lowest + 1;

    KeAcquireSpinLock( &PortSet->Lock, &OldIrql );
    Start = PortSet->NextPort;
    if (Start < Lowest || Start > Highest)
        Start = Lowest;
    for (i = 0; i < Count; i++) {
        Port = Lowest + (Start - Lowest + i) % Count;
        if (RtlAreBitsClear( &PortSet->ProtoBitmap, Port - PortSet->StartingPort, 1 ) &&
            (!InUse || !InUse( Port ))) {
            RtlSetBits( &PortSet->ProtoBitmap, Port - PortSet->StartingPort, 1 );
            PortSet->NextPort = Port + 1;
            KeReleaseSpinLock( &PortSet->Lock, OldIrql );
            return htons(Port);
        }
    }
    KeReleaseSpinLock( &PortSet->Lock, OldIrql );

    return -1;
}
