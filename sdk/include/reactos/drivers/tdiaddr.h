/*
 * PROJECT:     ReactOS TDI helpers
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Address conversions between Winsock socket addresses and TDI transport addresses (IPv4 and
 *              IPv6), without any dependency on the pool or the heap: usable from AFD, from Winsock providers
 *              and from tests. Needs <tdi.h> (TA_IP6_ADDRESS, TDI_ADDRESS_IP6) to be included first.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every length that comes in is treated as attacker controlled: nothing is read or written beyond the
 * lengths the caller states, and a result is only produced for a complete address.
 */

#ifndef _TDIADDR_H
#define _TDIADDR_H

#define TDIADDR_AF_INET                 2
#define TDIADDR_AF_INET6                23

/* The sizes of SOCKADDR_IN and SOCKADDR_IN6 (the latter with the scope id: SOCKADDR_IN6_LH) */
#define TDIADDR_SOCKADDR_IN_LENGTH      16
#define TDIADDR_SOCKADDR_IN6_LENGTH     28

/* TAAddressCount, AddressLength and AddressType: what is in front of the body of a TRANSPORT_ADDRESS */
#define TDIADDR_TA_HEADER_LENGTH        (sizeof(LONG) + 2 * sizeof(USHORT))

/* The body of an IPv4 / IPv6 TDI address: all of sockaddr but the family */
#define TDIADDR_BODY_LENGTH_IP          14
#define TDIADDR_BODY_LENGTH_IP6         26

/* The whole TA_IP6_ADDRESS */
#define TDIADDR_TA_LENGTH_IP6           (TDIADDR_TA_HEADER_LENGTH + TDIADDR_BODY_LENGTH_IP6)

#include <pshpack1.h>
/* SOCKADDR_IN6 without any dependency on the Winsock headers */
typedef struct _TDIADDR_SOCKADDR6
{
    USHORT Family;
    USHORT Port;
    ULONG FlowInfo;
    UCHAR Address[16];
    ULONG ScopeId;
} TDIADDR_SOCKADDR6, *PTDIADDR_SOCKADDR6;
#include <poppack.h>

C_ASSERT(sizeof(TDIADDR_SOCKADDR6) == TDIADDR_SOCKADDR_IN6_LENGTH);
C_ASSERT(sizeof(TA_IP6_ADDRESS) == TDIADDR_TA_LENGTH_IP6);
C_ASSERT(sizeof(TDI_ADDRESS_IP6) == TDIADDR_BODY_LENGTH_IP6);
C_ASSERT(sizeof(TDI_ADDRESS_IP) == TDIADDR_BODY_LENGTH_IP);

/* Stores without assuming the buffer is aligned */
static __inline
VOID
TdiAddrPut16(
    _Out_writes_bytes_(sizeof(USHORT)) PUCHAR Target,
    _In_ USHORT Value)
{
    RtlCopyMemory(Target, &Value, sizeof(Value));
}

static __inline
VOID
TdiAddrPut32(
    _Out_writes_bytes_(sizeof(LONG)) PUCHAR Target,
    _In_ LONG Value)
{
    RtlCopyMemory(Target, &Value, sizeof(Value));
}

/* ::ffff:a.b.c.d */
static __inline
BOOLEAN
TdiAddrIsV4Mapped(
    _In_reads_bytes_(16) const UCHAR *Address)
{
    ULONG i;

    for (i = 0; i < 10; i++)
    {
        if (Address[i] != 0)
            return FALSE;
    }
    return Address[10] == 0xff && Address[11] == 0xff;
}

/*
 * The transport address of a SOCKADDR_IN6 in Sockaddr, SockaddrLength bytes long. Needs a SOCKADDR_IN6 of the
 * family AF_INET6 (the scope id is part of it) and TaAvailable bytes of room for the TA_IP6_ADDRESS.
 * Returns the length of the transport address, or 0 when the socket address is not a complete IPv6 one or the
 * room is too small.
 */
static __inline
ULONG
TdiAddrSockaddr6ToTa(
    _In_reads_bytes_(SockaddrLength) const VOID *Sockaddr,
    _In_ ULONG SockaddrLength,
    _Out_writes_bytes_to_(TaAvailable, return) PVOID Ta,
    _In_ ULONG TaAvailable)
{
    const UCHAR *Source = Sockaddr;
    PUCHAR Target = Ta;
    USHORT Family;

    if (SockaddrLength < TDIADDR_SOCKADDR_IN6_LENGTH || TaAvailable < TDIADDR_TA_LENGTH_IP6)
        return 0;

    RtlCopyMemory(&Family, Source, sizeof(Family));
    if (Family != TDIADDR_AF_INET6)
        return 0;

    RtlZeroMemory(Target, TDIADDR_TA_LENGTH_IP6);
    TdiAddrPut32(Target, 1);
    TdiAddrPut16(Target + sizeof(LONG), TDIADDR_BODY_LENGTH_IP6);
    TdiAddrPut16(Target + sizeof(LONG) + sizeof(USHORT), TDIADDR_AF_INET6);
    RtlCopyMemory(Target + TDIADDR_TA_HEADER_LENGTH, Source + sizeof(USHORT), TDIADDR_BODY_LENGTH_IP6);
    return TDIADDR_TA_LENGTH_IP6;
}

/*
 * The inverse for a whole TRANSPORT_ADDRESS of TaLength valid bytes: the SOCKADDR_IN6 (Port, Flow, Address,
 * ScopeId as the stack holds them) of a TA_IP6_ADDRESS. Returns FALSE unless the buffer holds exactly one
 * complete IPv6 address.
 */
static __inline
BOOLEAN
TdiAddrTaToSockaddr6(
    _In_reads_bytes_(TaLength) const VOID *Ta,
    _In_ ULONG TaLength,
    _Out_ PTDIADDR_SOCKADDR6 Sockaddr)
{
    const UCHAR *Source = Ta;
    LONG Count;
    USHORT BodyLength, Type;

    if (TaLength < TDIADDR_TA_LENGTH_IP6)
        return FALSE;

    RtlCopyMemory(&Count, Source, sizeof(Count));
    RtlCopyMemory(&BodyLength, Source + sizeof(LONG), sizeof(BodyLength));
    RtlCopyMemory(&Type, Source + sizeof(LONG) + sizeof(USHORT), sizeof(Type));
    if (Count != 1 || Type != TDIADDR_AF_INET6 || BodyLength < TDIADDR_BODY_LENGTH_IP6 ||
        BodyLength > TaLength - TDIADDR_TA_HEADER_LENGTH)
        return FALSE;

    Sockaddr->Family = TDIADDR_AF_INET6;
    RtlCopyMemory(&Sockaddr->Port, Source + TDIADDR_TA_HEADER_LENGTH, TDIADDR_BODY_LENGTH_IP6);
    return TRUE;
}

/*
 * A socket address of the family Family (AF_INET or AF_INET6) from the address a transport reported: AddressType
 * and the body of BodyLength bytes (AddressLength). Same family: the body, short bodies refused; an IPv4 address
 * on an IPv6 socket (a dual stack socket) becomes ::ffff:a.b.c.d with the port. OutLength is the room in Out.
 * Returns the length of the socket address written (16 or 28), or 0 when there is no such conversion or the
 * address is incomplete or the room is too small. Nothing is written in the 0 case.
 */
static __inline
ULONG
TdiAddrToSockaddr(
    _In_ USHORT Family,
    _In_ USHORT Type,
    _In_ ULONG BodyLength,
    _In_reads_bytes_(BodyLength) const UCHAR *Body,
    _Out_writes_bytes_to_(OutLength, return) PVOID Out,
    _In_ ULONG OutLength)
{
    PUCHAR Target = Out;

    if (Family == TDIADDR_AF_INET && Type == TDIADDR_AF_INET)
    {
        if (BodyLength < TDIADDR_BODY_LENGTH_IP || OutLength < TDIADDR_SOCKADDR_IN_LENGTH)
            return 0;
        TdiAddrPut16(Target, TDIADDR_AF_INET);
        RtlCopyMemory(Target + sizeof(USHORT), Body, TDIADDR_BODY_LENGTH_IP);
        return TDIADDR_SOCKADDR_IN_LENGTH;
    }

    if (Family == TDIADDR_AF_INET6 && Type == TDIADDR_AF_INET6)
    {
        if (BodyLength < TDIADDR_BODY_LENGTH_IP6 || OutLength < TDIADDR_SOCKADDR_IN6_LENGTH)
            return 0;
        TdiAddrPut16(Target, TDIADDR_AF_INET6);
        RtlCopyMemory(Target + sizeof(USHORT), Body, TDIADDR_BODY_LENGTH_IP6);
        return TDIADDR_SOCKADDR_IN6_LENGTH;
    }

    if (Family == TDIADDR_AF_INET6 && Type == TDIADDR_AF_INET)
    {
        /* The body of an IPv4 address: port (2), address (4), padding */
        if (BodyLength < sizeof(USHORT) + sizeof(ULONG) || OutLength < TDIADDR_SOCKADDR_IN6_LENGTH)
            return 0;
        RtlZeroMemory(Target, TDIADDR_SOCKADDR_IN6_LENGTH);
        TdiAddrPut16(Target, TDIADDR_AF_INET6);
        RtlCopyMemory(Target + sizeof(USHORT), Body, sizeof(USHORT));
        Target[8 + 10] = 0xff;
        Target[8 + 11] = 0xff;
        RtlCopyMemory(Target + 8 + 12, Body + sizeof(USHORT), sizeof(ULONG));
        return TDIADDR_SOCKADDR_IN6_LENGTH;
    }

    return 0;
}

#endif /* _TDIADDR_H */
