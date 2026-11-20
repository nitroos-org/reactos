/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        include/neighbor.h
 * PURPOSE:     Neighbor definitions
 */

#pragma once

#define NB_HASHMASK 0xF /* Hash mask for neighbor cache */

typedef VOID (*PNEIGHBOR_PACKET_COMPLETE)
    ( PVOID Context, PNDIS_PACKET Packet, NDIS_STATUS Status );

typedef struct _NEIGHBOR_PACKET {
    LIST_ENTRY Next;
    PNDIS_PACKET Packet;
    PNEIGHBOR_PACKET_COMPLETE Complete;
    PVOID Context;
} NEIGHBOR_PACKET, *PNEIGHBOR_PACKET;

typedef struct NEIGHBOR_CACHE_TABLE {
    struct NEIGHBOR_CACHE_ENTRY *Cache; /* Pointer to cache */
    KSPIN_LOCK Lock;                    /* Protecting lock */
} NEIGHBOR_CACHE_TABLE, *PNEIGHBOR_CACHE_TABLE;

/*
 * Information about a neighbor
 *
 * Lifetime: RefCount counts the cache (while the NCE is linked in its hash bucket), each FIB
 * entry routing through it, and each caller that got it from NBAddNeighbor, NBLocateNeighbor,
 * NBFindOrCreateNeighbor, RouterGetRoute or RouteGetRouteToDestination (NBDereferenceNeighbor
 * when done). The NCE holds a reference to its interface. Unlinked is set, under the bucket
 * lock, when the NCE leaves the cache; an unresolved one takes no packets then (nothing would
 * resolve it), and the last reference completes whatever is still queued.
 */
typedef struct NEIGHBOR_CACHE_ENTRY {
    struct NEIGHBOR_CACHE_ENTRY *Next;  /* Pointer to next entry */
    volatile LONG RefCount;             /* See above */
    BOOLEAN Unlinked;                   /* Out of the cache (bucket lock) */
    BOOLEAN GroupEntry;                 /* A cached IPv4 group entry, counted (NBFindOrCreateNeighbor) */
    UCHAR State;                        /* State of NCE */
    UINT EventTimer;                    /* Ticks since last event */
    UINT EventCount;                    /* Number of events */
    PIP_INTERFACE Interface;            /* Pointer to interface */
    UINT LinkAddressLength;             /* Length of link address */
    PVOID LinkAddress;                  /* Pointer to link address */
    IP_ADDRESS Address;                 /* IP address of neighbor */
    LIST_ENTRY PacketQueue;             /* Packet queue */
} NEIGHBOR_CACHE_ENTRY, *PNEIGHBOR_CACHE_ENTRY;

/* NCE states */
#define NUD_INCOMPLETE 0x01
#define NUD_PERMANENT  0x02
#define NUD_STALE      0x04

/* The most IPv4 group entries kept in the cache (NBFindOrCreateNeighbor) */
#define NB_MAX_GROUP_ENTRIES 256

/* Timeout for incomplete NCE ARP requests */
#define ARP_INCOMPLETE_TIMEOUT 3

/* Number of seconds between ARP transmissions */
#define ARP_RATE 900

/* Number of seconds before the NCE times out */
#define ARP_COMPLETE_TIMEOUT (ARP_RATE + 9)

/* Number of seconds before retransmission */
#define ARP_TIMEOUT_RETRANSMISSION 3

extern NEIGHBOR_CACHE_TABLE NeighborCache[NB_HASHMASK + 1];


VOID NBTimeout(
    VOID);

VOID NBStartup(
    VOID);

VOID NBShutdown(
    VOID);

VOID NBSendSolicit(
    PNEIGHBOR_CACHE_ENTRY NCE);

PNEIGHBOR_CACHE_ENTRY NBAddNeighbor(
    PIP_INTERFACE Interface,
    PIP_ADDRESS Address,
    PVOID LinkAddress,
    UINT LinkAddressLength,
    UCHAR Type,
    UINT EventTimer);

VOID NBUpdateNeighbor(
    PNEIGHBOR_CACHE_ENTRY NCE,
    PVOID LinkAddress,
    UCHAR State);

PNEIGHBOR_CACHE_ENTRY NBLocateNeighbor(
    PIP_ADDRESS Address,
    PIP_INTERFACE Interface);

PNEIGHBOR_CACHE_ENTRY NBFindOrCreateNeighbor(
    PIP_INTERFACE Interface,
    PIP_ADDRESS Address,
    BOOLEAN NoTimeout);

BOOLEAN NBQueuePacket(
    PNEIGHBOR_CACHE_ENTRY NCE,
    PNDIS_PACKET NdisPacket,
    PNEIGHBOR_PACKET_COMPLETE PacketComplete,
    PVOID PacketContext);

BOOLEAN NBQueuePacketLimited(
    PNEIGHBOR_CACHE_ENTRY NCE,
    PNDIS_PACKET NdisPacket,
    PNEIGHBOR_PACKET_COMPLETE PacketComplete,
    PVOID PacketContext,
    UINT UnresolvedLimit);

VOID NBRemoveNeighbor(
    PNEIGHBOR_CACHE_ENTRY NCE);

VOID NBReferenceNeighbor(
    PNEIGHBOR_CACHE_ENTRY NCE);

VOID NBDereferenceNeighbor(
    PNEIGHBOR_CACHE_ENTRY NCE);

ULONG NBCopyNeighbors(
    PIP_INTERFACE Interface,
    PIPARP_ENTRY ArpTable,
    ULONG Capacity);

VOID NBResetNeighborTimeout(
    PIP_ADDRESS Address);

VOID NBDestroyNeighborsForInterface(PIP_INTERFACE Interface);

/* EOF */
