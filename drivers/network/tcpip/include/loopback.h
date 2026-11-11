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

NDIS_STATUS LoopRegisterAdapter(
    PNDIS_STRING AdapterName,
    PLAN_ADAPTER *Adapter);

NDIS_STATUS LoopUnregisterAdapter(
    PLAN_ADAPTER Adapter);

/* EOF */
