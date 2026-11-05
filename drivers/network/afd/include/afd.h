/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/include/afd.h
 * PURPOSE:          Ancillary functions driver -- constants and structures
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040630 Created
 */

#ifndef _AFD_H
#define _AFD_H

#include <ntifs.h>
#include <ndk/obtypes.h>
#include <tdi.h>
#include <tcpioctl.h>
#define _WINBASE_
#define _WINDOWS_H
#define _INC_WINDOWS
#include <windef.h>
#include <winsock2.h>
#include <afd/shared.h>
#include <pseh/pseh2.h>

#include "tdi_proto.h"
#include "tdiconn.h"
#include "debug.h"

#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif

#define TL_INSTANCE 0
#define	IP_MIB_STATS_ID 1
#define	IP_MIB_ADDRTABLE_ENTRY_ID 0x102

#define TAG_AFD_DATA_BUFFER                'BdfA'
#define TAG_AFD_SEND_GHOST                 'GdfA'
#define TAG_AFD_TRANSPORT_ADDRESS          'tdfA'
#define TAG_AFD_SOCKET_CONTEXT             'XdfA'
#define TAG_AFD_CONNECT_DATA               'cdfA'
#define TAG_AFD_DISCONNECT_DATA            'ddfA'

#define TAG_AFD_CONNECT_OPTIONS            'ocfA'
#define TAG_AFD_DISCONNECT_OPTIONS         'odfA'
#define TAG_AFD_SUPER_CONNECT_BUFFER       'sdfA'
#define TAG_AFD_ACCEPT_QUEUE               'qafA'
#define TAG_AFD_POLL_HANDLE                'hpfA'
#define TAG_AFD_FCB                        'cffA'
#define TAG_AFD_ACTIVE_POLL                'pafA'
#define TAG_AFD_EA_INFO                    'aefA'
#define TAG_AFD_STORED_DATAGRAM            'gsfA'
#define TAG_AFD_DGRAM_SEND                 'sdfA'
#define TAG_AFD_SNMP_ADDRESS_INFO          'asfA'
#define TAG_AFD_TDI_CONNECTION_INFORMATION 'cTfA'
#define TAG_AFD_WSA_BUFFER                 'bWfA'

typedef struct IPADDR_ENTRY {
	ULONG  Addr;
	ULONG  Index;
	ULONG  Mask;
	ULONG  BcastAddr;
	ULONG  ReasmSize;
	USHORT Context;
	USHORT Pad;
} IPADDR_ENTRY, *PIPADDR_ENTRY;

#define DN2H(dw) \
    ((((dw) & 0xFF000000L) >> 24) | \
	 (((dw) & 0x00FF0000L) >> 8) | \
	 (((dw) & 0x0000FF00L) << 8) | \
	 (((dw) & 0x000000FFL) << 24))

#define SOCKET_STATE_INVALID_TRANSITION ((DWORD)-1)
#define SOCKET_STATE_CREATED            0
#define SOCKET_STATE_BOUND              1
#define SOCKET_STATE_CONNECTING         2
#define SOCKET_STATE_CONNECTED          3
#define SOCKET_STATE_LISTENING          4
#define SOCKET_STATE_MASK               0x0000ffff
#define SOCKET_STATE_EOF_READ           0x20000000
#define SOCKET_STATE_LOCKED             0x40000000
#define SOCKET_STATE_NEW                0x80000000
#define SOCKET_STATE_CLOSED             0x00000100

#define FUNCTION_CONNECT                0
#define FUNCTION_RECV                   1
#define FUNCTION_SEND                   2
#define FUNCTION_PREACCEPT              3
#define FUNCTION_ACCEPT                 4
#define FUNCTION_DISCONNECT             5
#define FUNCTION_CLOSE                  6
#define FUNCTION_CONNECTEX              7
#define MAX_FUNCTIONS                   8

#define IN_FLIGHT_REQUESTS              5

#define EXTRA_LOCK_BUFFERS              5 /* Number of extra buffers needed
					   * for ancillary data on packet
					   * requests: the address and its
					   * length, then (WSARecvMsg only)
					   * the control buffer, its length
					   * and the message flags. */
#define EXTRA_LOCK_ADDRESS              0 /* offsets of those buffers after */
#define EXTRA_LOCK_ADDRESS_LENGTH       1 /* the data buffers */
#define EXTRA_LOCK_CONTROL              2
#define EXTRA_LOCK_CONTROL_LENGTH       3
#define EXTRA_LOCK_MSG_FLAGS            4
/* The most control data AFD writes: one IP_PKTINFO message (16 byte header + in_pktinfo) */
#define AFD_MAX_CONTROL_LOCK            24

/* The referenced handle table of a select request; the caller's buffer is copied back to it */
#define AFD_HANDLES(Irp) ((PAFD_HANDLE)(Irp)->Tail.Overlay.DriverContext[2])
#define SET_AFD_HANDLES(Irp,y) ((Irp)->Tail.Overlay.DriverContext[2] = (y))

typedef struct _AFD_MAPBUF {
    PVOID BufferAddress;
    PMDL  Mdl;
} AFD_MAPBUF, *PAFD_MAPBUF;

typedef struct _AFD_DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    LIST_ENTRY Polls;
    KSPIN_LOCK Lock;
} AFD_DEVICE_EXTENSION, *PAFD_DEVICE_EXTENSION;

typedef struct _AFD_ACTIVE_POLL {
    LIST_ENTRY ListEntry;
    PIRP Irp;
    PAFD_DEVICE_EXTENSION DeviceExt;
    KDPC TimeoutDpc;
    KTIMER Timer;
    PKEVENT EventObject;
    BOOLEAN Exclusive;
} AFD_ACTIVE_POLL, *PAFD_ACTIVE_POLL; /* Irp is NULL once completed while its timeout DPC runs */

typedef struct _IRP_LIST {
    LIST_ENTRY ListEntry;
    PIRP Irp;
} IRP_LIST, *PIRP_LIST;

typedef struct _AFD_TDI_OBJECT {
    PFILE_OBJECT Object;
    HANDLE Handle;
} AFD_TDI_OBJECT, *PAFD_TDI_OBJECT;

typedef struct _AFD_TDI_OBJECT_QELT {
    LIST_ENTRY ListEntry;
    UINT Seq;
    PTDI_CONNECTION_INFORMATION ConnInfo;
    AFD_TDI_OBJECT Object;
} AFD_TDI_OBJECT_QELT, *PAFD_TDI_OBJECT_QELT;

typedef struct _AFD_IN_FLIGHT_REQUEST {
    PIRP InFlightRequest;
    PTDI_CONNECTION_INFORMATION ConnectionCallInfo;
    PTDI_CONNECTION_INFORMATION ConnectionReturnInfo;
} AFD_IN_FLIGHT_REQUEST, *PAFD_IN_FLIGHT_REQUEST;

/* One datagram handed to the transport, and the user send request it completes.
 * The transport may complete datagrams in any order and a user request may be
 * cancelled while its datagram is in flight, so the request is recorded here
 * rather than inferred from its position in the pending list. UserIrp is
 * cleared when that request goes away before the datagram completes. */
typedef struct _AFD_DGRAM_SEND_CONTEXT {
    LIST_ENTRY ListEntry;
    struct _AFD_FCB *FCB;
    PIRP UserIrp;
    PIRP TransportIrp;      /* the IRP in the transport; valid while the entry is listed */
    BOOLEAN CancelRequested;
} AFD_DGRAM_SEND_CONTEXT, *PAFD_DGRAM_SEND_CONTEXT;

/* Bytes of a cancelled stream send that are still in the send window. Ahead is the number of window bytes in front of them */
typedef struct _AFD_SEND_GHOST {
    LIST_ENTRY ListEntry;
    UINT Ahead, Bytes;
} AFD_SEND_GHOST, *PAFD_SEND_GHOST;

typedef struct _AFD_DATA_WINDOW {
    PCHAR Window;
    UINT BytesUsed, Size, Content;
} AFD_DATA_WINDOW, *PAFD_DATA_WINDOW;

/*
 * What the transport tells AFD about a received datagram besides its source, through the Options
 * of the connection information of the receive (tcpip: DGDeliverData). Valid is 0 until the
 * transport fills the structure in. DstAddress is the datagram's destination, as in the IP
 * header (network order); IfIndex is the index of the interface that owns it, or that the
 * datagram arrived on (the index tcpip reports for the interface).
 */
typedef struct _AFD_RECV_PKTINFO {
    ULONG Valid;
    ULONG DstAddress;
    ULONG IfIndex;
} AFD_RECV_PKTINFO, *PAFD_RECV_PKTINFO;

typedef struct _AFD_STORED_DATAGRAM {
    LIST_ENTRY ListEntry;
    UINT Len;
    PTRANSPORT_ADDRESS Address;
    AFD_RECV_PKTINFO PktInfo;
    CHAR Buffer[1];
} AFD_STORED_DATAGRAM, *PAFD_STORED_DATAGRAM;

/* Largest listen backlog, also used for SOMAXCONN, as on Windows */
#define AFD_MAX_BACKLOG 200

typedef struct _AFD_FCB {
    SOCK_SHARED_INFO SharedData;
    BOOLEAN Locked, Critical, NonBlocking, OobInline, TdiReceiveClosed, SendClosed;
    UINT Flags, GroupID, GroupType;
    KIRQL OldIrql;
    PVOID CurrentThread;
    PFILE_OBJECT FileObject;
    PAFD_DEVICE_EXTENSION DeviceExt;
    BOOLEAN DelayedAccept;
    BOOLEAN AbortingReceives; /* the cleanup of a stream socket is cancelling its receives */
    BOOLEAN ReceiveShutdown; /* shutdown(SD_RECEIVE) left receives pending: they wait for data, the end or a reset */
    BOOLEAN ShutdownBoth; /* ... and it shut the send direction down too (SD_BOTH) */
    BOOLEAN LocalReceiveShutdown; /* TdiReceiveClosed comes from shutdown(SD_RECEIVE), not from the peer */
    BOOLEAN ConnectionAborted; /* shutdown(SD_RECEIVE) with unread or arriving data reset the connection, as on Windows */
    ULONG Backlog;
    UINT ConnSeq;
    USHORT DisconnectFlags;
    BOOLEAN DisconnectPending;
    LARGE_INTEGER DisconnectTimeout;
    PTRANSPORT_ADDRESS LocalAddress, RemoteAddress;
    PTDI_CONNECTION_INFORMATION AddressFrom, ConnectCallInfo, ConnectReturnInfo;
    AFD_RECV_PKTINFO RecvPktInfo; /* AddressFrom->Options: filled in by the transport per datagram */
    AFD_TDI_OBJECT AddressFile, Connection;
    AFD_IN_FLIGHT_REQUEST ConnectIrp, ListenIrp, ReceiveIrp, SendIrp, DisconnectIrp;
    /* SendComplete runs in a loop: a send the transport finishes inside the call that starts it is handed on */
    BOOLEAN SendCompleteActive, SendDeferred;
    NTSTATUS SendDeferredStatus;
    ULONG_PTR SendDeferredBytes;
    /* ReceiveComplete runs in a loop: a receive the transport finishes inside the call that starts it
     * (data was queued already) is handed on, so the stack does not grow with the data queued */
    BOOLEAN RecvCompleteActive, RecvDeferred;
    NTSTATUS RecvDeferredStatus;
    ULONG_PTR RecvDeferredBytes;
    PIRP AcceptIrp;
    AFD_DATA_WINDOW Send, Recv;
    /* SO_RCVBUF, the largest receive window the transport may offer (0: the transport default) */
    ULONG RecvHint;
    LIST_ENTRY SendGhosts;      /* AFD_SEND_GHOST in window order */
    KMUTEX Mutex;
    KEVENT InFlightIdle;
    PKEVENT EventSelect;
    DWORD EventSelectTriggers;
    DWORD EventSelectDisabled;
    UNICODE_STRING TdiDeviceName;
    PVOID Context;
    DWORD PollState;
    NTSTATUS PollStatus[FD_MAX_EVENTS];
    NTSTATUS AsyncConnectStatus; /* failure of the last non-blocking connect, reported by SO_ERROR */
    NTSTATUS LastReceiveStatus;
    UINT ContextSize;
    PVOID ConnectData;
    UINT FilledConnectData;
    UINT ConnectDataSize;
    PVOID DisconnectData;
    UINT FilledDisconnectData;
    UINT DisconnectDataSize;
    PVOID ConnectOptions;
    UINT FilledConnectOptions;
    UINT ConnectOptionsSize;
    PVOID DisconnectOptions;
    UINT FilledDisconnectOptions;
    UINT DisconnectOptionsSize;
    PVOID OnConnectSendBuffer;
    UINT OnConnectSendBufferSize;
    LIST_ENTRY PendingIrpList[MAX_FUNCTIONS];
    LIST_ENTRY DatagramList;
    LIST_ENTRY DatagramSendList; /* AFD_DGRAM_SEND_CONTEXT of datagrams in the transport */
    LIST_ENTRY PendingConnections;
    PIO_WORKITEM RelistenWorkItem;
    KEVENT RelistenIdle;
    BOOLEAN Relistening;
    BOOLEAN ListenConnectionReady;
    NTSTATUS ListenStatus;
    PIO_WORKITEM AcceptWorkItem;
    KEVENT AcceptWorkIdle;
    BOOLEAN AcceptWorkQueued;
    PIO_WORKITEM RecvRelaunchWorkItem;
    BOOLEAN RecvRelaunchQueued;
} AFD_FCB, *PAFD_FCB;

/* bind.c */

NTSTATUS WarmSocketForBind( PAFD_FCB FCB, ULONG ShareType );
NTSTATUS NTAPI
AfdBindSocket(PDEVICE_OBJECT DeviceObject, PIRP Irp,
	      PIO_STACK_LOCATION IrpSp);

/* connect.c */

NTSTATUS MakeSocketIntoConnection(PAFD_FCB FCB, BOOL Receive);
NTSTATUS WarmSocketForConnection( PAFD_FCB FCB );
VOID AfdCloseConnectionEndpoint( PAFD_FCB FCB );
NTSTATUS NTAPI
AfdStreamSocketConnect(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                       PIO_STACK_LOCATION IrpSp);
NTSTATUS NTAPI
AfdStreamSocketSuperConnect(PDEVICE_OBJECT DeviceObject, PIRP Irp,
		                    PIO_STACK_LOCATION IrpSp);
NTSTATUS NTAPI
AfdGetConnectData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
	          PIO_STACK_LOCATION IrpSp);
NTSTATUS NTAPI
AfdSetConnectData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                  PIO_STACK_LOCATION IrpSp);
NTSTATUS NTAPI
AfdSetConnectDataSize(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                      PIO_STACK_LOCATION IrpSp);
NTSTATUS NTAPI
AfdGetConnectOptions(PDEVICE_OBJECT DeviceObject, PIRP Irp,
	             PIO_STACK_LOCATION IrpSp);
NTSTATUS NTAPI
AfdSetConnectOptions(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                     PIO_STACK_LOCATION IrpSp);
NTSTATUS NTAPI
AfdSetConnectOptionsSize(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                         PIO_STACK_LOCATION IrpSp);

/* context.c */

NTSTATUS NTAPI
AfdGetContext( PDEVICE_OBJECT DeviceObject, PIRP Irp,
	       PIO_STACK_LOCATION IrpSp );
NTSTATUS NTAPI
AfdGetContextSize( PDEVICE_OBJECT DeviceObject, PIRP Irp,
	           PIO_STACK_LOCATION IrpSp );
NTSTATUS NTAPI
AfdSetContext( PDEVICE_OBJECT DeviceObject, PIRP Irp,
	       PIO_STACK_LOCATION IrpSp );

/* info.c */

NTSTATUS NTAPI
AfdGetInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp,
	    PIO_STACK_LOCATION IrpSp );

NTSTATUS NTAPI
AfdSetInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp,
	    PIO_STACK_LOCATION IrpSp );

NTSTATUS AfdQueryRouteSource(PAFD_FCB FCB, ULONG Destination, PULONG Source);
NTSTATUS AfdQueryRouteSourceOn(PFILE_OBJECT Object, ULONG Destination, PULONG Source);

NTSTATUS NTAPI
AfdGetSockName( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                PIO_STACK_LOCATION IrpSp );

NTSTATUS NTAPI
AfdGetPeerName( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                PIO_STACK_LOCATION IrpSp );

/* listen.c */
NTSTATUS AfdWaitForListen( PDEVICE_OBJECT DeviceObject, PIRP Irp,
			   PIO_STACK_LOCATION IrpSp );

VOID FreeListenConnectionInfo(PAFD_FCB FCB);
NTSTATUS AfdListenSocket(PDEVICE_OBJECT DeviceObject, PIRP Irp,
			 PIO_STACK_LOCATION IrpSp);

NTSTATUS AfdAccept( PDEVICE_OBJECT DeviceObject, PIRP Irp,
		    PIO_STACK_LOCATION IrpSp );

NTSTATUS AfdSuperAccept( PDEVICE_OBJECT DeviceObject, PIRP Irp,
		    PIO_STACK_LOCATION IrpSp );

VOID FreeQueuedConnection(PAFD_TDI_OBJECT_QELT Qelt);

#if (NTDDI_VERSION < NTDDI_VISTA)
NTKERNELAPI
VOID
NTAPI
ObDereferenceObjectDeferDelete(
    _In_ PVOID Object);
#endif

/* lock.c */

PAFD_WSABUF LockBuffers( PAFD_WSABUF Buf, UINT Count,
			 PVOID AddressBuf, PINT AddressLen,
			 BOOLEAN Write, BOOLEAN LockAddress,
             KPROCESSOR_MODE LockMode,
             PAFD_RECV_INFO_MSG Msg );
VOID UnlockBuffers( PAFD_WSABUF Buf, UINT Count, BOOL Address );
BOOLEAN SocketAcquireStateLock( PAFD_FCB FCB );
NTSTATUS NTAPI UnlockAndMaybeComplete
( PAFD_FCB FCB, NTSTATUS Status, PIRP Irp,
  UINT Information );
VOID SocketStateUnlock( PAFD_FCB FCB );
BOOLEAN AfdHasInFlightRequest( PAFD_FCB FCB );
VOID AfdOrphanDatagramSend( PAFD_FCB FCB, PIRP Irp );
VOID AfdCancelDatagramSends( PAFD_FCB FCB );
VOID AfdOrphanStreamSend( PAFD_FCB FCB, PIRP Irp );
VOID AfdFreeSendGhosts( PAFD_FCB FCB );
VOID AfdClearCancelRoutine( PIRP Irp );
NTSTATUS LostSocket( PIRP Irp );
NTSTATUS LockHandles( PAFD_HANDLE HandleArray, UINT HandleCount,
                      PDEVICE_OBJECT DeviceObject, KPROCESSOR_MODE AccessMode,
                      PAFD_HANDLE *LockedHandles );
VOID UnlockHandles( PAFD_HANDLE HandleArray, UINT HandleCount );
PVOID LockRequest( PIRP Irp, PIO_STACK_LOCATION IrpSp, BOOLEAN Output, KPROCESSOR_MODE *LockMode );
VOID UnlockRequest( PIRP Irp, PIO_STACK_LOCATION IrpSp );
VOID AfdAbortPendingReceives( PAFD_FCB FCB );
VOID AfdCompleteReceiveShutdown( PAFD_FCB FCB );
VOID AfdAbortConnection( PAFD_FCB FCB );
PVOID GetLockedData( PIRP Irp, PIO_STACK_LOCATION IrpSp );
BOOLEAN AfdRequestLengthValid( PIRP Irp, PIO_STACK_LOCATION IrpSp, ULONG MinLength );
NTSTATUS LeaveIrpUntilLater( PAFD_FCB FCB, PIRP Irp, UINT Function );
NTSTATUS QueueUserModeIrp(PAFD_FCB FCB, PIRP Irp, UINT Function);
NTSTATUS AfdCopyToUserOutput(PIRP Irp, PIO_STACK_LOCATION IrpSp,
                             const VOID *Data, ULONG Length);

/* main.c */

VOID OskitDumpBuffer( PCHAR Buffer, UINT Len );
VOID DestroySocket( PAFD_FCB FCB );
DRIVER_CANCEL AfdCancelHandler;
VOID RetryDisconnectCompletion(PAFD_FCB FCB);
BOOLEAN CheckUnlockExtraBuffers(PAFD_FCB FCB, PIO_STACK_LOCATION IrpSp);

/* read.c */

IO_COMPLETION_ROUTINE AcceptExReceiveComplete;

IO_COMPLETION_ROUTINE ReceiveComplete;

IO_COMPLETION_ROUTINE PacketSocketRecvComplete;

NTSTATUS AfdApplyReceiveHint(PAFD_FCB FCB);

NTSTATUS NTAPI
AfdConnectedSocketReadData(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, BOOLEAN Short);
NTSTATUS NTAPI
AfdPacketSocketReadData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
			PIO_STACK_LOCATION IrpSp );

/* select.c */

NTSTATUS NTAPI
AfdSelect( PDEVICE_OBJECT DeviceObject, PIRP Irp,
	   PIO_STACK_LOCATION IrpSp );
NTSTATUS NTAPI
AfdEventSelect( PDEVICE_OBJECT DeviceObject, PIRP Irp,
		PIO_STACK_LOCATION IrpSp );
NTSTATUS NTAPI
AfdEnumEvents( PDEVICE_OBJECT DeviceObject, PIRP Irp,
	       PIO_STACK_LOCATION IrpSp );
VOID PollReeval( PAFD_DEVICE_EXTENSION DeviceObject, PFILE_OBJECT FileObject );
VOID KillSelectsForFCB( PAFD_DEVICE_EXTENSION DeviceExt,
                        PFILE_OBJECT FileObject, BOOLEAN ExclusiveOnly );
VOID ZeroEvents( PAFD_HANDLE HandleArray,
		 UINT HandleCount );
VOID SignalSocket(
   PAFD_ACTIVE_POLL Poll OPTIONAL, PIRP _Irp OPTIONAL,
   PAFD_POLL_INFO PollReq, NTSTATUS Status);

/* write.c */

NTSTATUS NTAPI
AfdConnectedSocketWriteData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
			    PIO_STACK_LOCATION IrpSp, BOOLEAN Short);
NTSTATUS NTAPI
AfdPacketSocketWriteData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
			 PIO_STACK_LOCATION IrpSp);

#endif /* _AFD_H */
