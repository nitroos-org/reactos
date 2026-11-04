/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        include/ports.h
 * PURPOSE:     Port allocation
 * PROGRAMMERS: arty (ayerkes@speakeasy.net)
 * REVISIONS:
 *   arty 20041114 Created
 */

#pragma once

typedef struct _PORT_SET {
    RTL_BITMAP ProtoBitmap;
    PVOID ProtoBitBuffer;
    UINT StartingPort;
    UINT PortsToOversee;
    UINT NextPort;
    KSPIN_LOCK Lock;
} PORT_SET, *PPORT_SET;

NTSTATUS PortsStartup( PPORT_SET PortSet,
		       UINT StartingPort,
		       UINT PortsToManage );
VOID PortsShutdown( PPORT_SET PortSet );
VOID DeallocatePort( PPORT_SET PortSet, ULONG Port );
BOOLEAN AllocatePort( PPORT_SET PortSet, ULONG Port );
BOOLEAN ReservePort( PPORT_SET PortSet, ULONG Port );
ULONG AllocateAnyPort( PPORT_SET PortSet );
ULONG AllocatePortFromRange( PPORT_SET PortSet, ULONG Lowest, ULONG Highest );
typedef BOOLEAN (*PPORT_IN_USE_ROUTINE)( ULONG Port );
ULONG AllocatePortFromRangeUnless( PPORT_SET PortSet, ULONG Lowest, ULONG Highest,
                                   PPORT_IN_USE_ROUTINE InUse );
