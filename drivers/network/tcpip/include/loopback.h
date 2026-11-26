/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        include/loopback.h
 * PURPOSE:     Loopback adapter definitions
 */

#pragma once

#include <lan.h>

extern PIP_INTERFACE Loopback;

/* TCP datagrams from lwIP to the loopback netif skip the NDIS packets and the IP layer (loopback.c) */
struct pbuf;
extern BOOLEAN LoopFastPath;
BOOLEAN LoopTransmitPbuf(struct pbuf *p);

/* A TCP send that asks for it (TCP_SEND_DELIVERED) and whose segments went to a peer on this machine completes when
 * the loopback worker has handed them to the peer's connection (on Windows the data is readable by the peer when the
 * send completes). Under the core lock:
 * LoopCoreSeq counts the datagrams LoopTransmitPbuf has queued and LoopCoreTicket is the ticket of the last one, so a
 * sender that read the count before its output and finds it changed after has a ticket to wait for */
extern ULONG LoopCoreSeq;
extern ULONG LoopCoreTicket;

/* Takes over the completion of Bucket (its status, byte count and AssociatedEndpoint set, a reference on the endpoint
 * held for the completion as CompleteBucket does) until the worker has done Ticket, then completes it. FALSE if the
 * worker has done so already: nothing is taken over then. No lock held; callable at any IRQL up to DISPATCH_LEVEL */
struct _TDI_BUCKET;
BOOLEAN LoopDeferCompletion(struct _TDI_BUCKET *Bucket, ULONG Ticket);

/* Whether the next segment waiting in the loopback queue is data of the connection of this lwIP PCB (a segment
 * that came from the PCB's peer): a segment that is followed at once by another need not be acknowledged by
 * itself */
struct tcp_pcb;
BOOLEAN LoopDataFollows(const struct tcp_pcb *pcb);

NDIS_STATUS LoopRegisterAdapter(
    PNDIS_STRING AdapterName,
    PLAN_ADAPTER *Adapter);

NDIS_STATUS LoopUnregisterAdapter(
    PLAN_ADAPTER Adapter);

/* EOF */
