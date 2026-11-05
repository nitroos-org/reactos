/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        include/fileobjs.h
 * PURPOSE:     File object routine prototypes
 */

#pragma once

extern LIST_ENTRY AddressFileListHead;
extern KSPIN_LOCK AddressFileListLock;

/* The same address files, indexed by Port (network byte order; every protocol in one bucket), under
   AddressFileListLock. Within a bucket the order is the creation order, as on AddressFileListHead. */
#define ADDRESS_FILE_PORT_BUCKETS 256
#define ADDRESS_FILE_PORT_BUCKET(PortN) (((PortN) ^ ((PortN) >> 8)) & (ADDRESS_FILE_PORT_BUCKETS - 1))
extern LIST_ENTRY AddressFilePortHash[ADDRESS_FILE_PORT_BUCKETS];
extern LIST_ENTRY ConnectionEndpointListHead;
extern KSPIN_LOCK ConnectionEndpointListLock;

NTSTATUS FileOpenAddress(
  PTDI_REQUEST Request,
  PTA_IP_ADDRESS AddrList,
  USHORT Protocol,
  ULONG ShareAccess,
  PVOID Options);

NTSTATUS FileCloseAddress(
  PTDI_REQUEST Request);

NTSTATUS FileOpenConnection(
  PTDI_REQUEST Request,
  PVOID ClientContext);

NTSTATUS FileCloseConnection(
  PTDI_REQUEST Request);

NTSTATUS FileOpenControlChannel(
  PTDI_REQUEST Request);

NTSTATUS FileCloseControlChannel(
  PTDI_REQUEST Request);

VOID LogActiveObjects(VOID);

/* EOF */
