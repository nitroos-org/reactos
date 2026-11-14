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
