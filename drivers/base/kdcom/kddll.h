/*
 * COPYRIGHT:       GPL, see COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            drivers/base/kddll/kddll.h
 * PURPOSE:         Base definitions for the kernel debugger.
 * PROGRAMMER:      Timo Kreuzer (timo.kreuzer@reactos.org)
 */

#ifndef _KDDLL_H_
#define _KDDLL_H_

#define NOEXTAPI
#include <ntifs.h>
#include <windbgkd.h>

// #define KDDEBUG /* uncomment to enable debugging this dll */

#ifndef KDDEBUG
#define KDDBGPRINT(...)
#else
extern ULONG KdpDbgPrint(const char* Format, ...);
#define KDDBGPRINT KdpDbgPrint
#endif

typedef enum
{
    KDP_PACKET_RECEIVED = 0,
    KDP_PACKET_TIMEOUT  = 1,
    KDP_PACKET_RESEND   = 2
} KDP_STATUS;

VOID
NTAPI
KdpSendBuffer(
    IN PVOID Buffer,
    IN ULONG Size);

KDP_STATUS
NTAPI
KdpReceiveBuffer(
    OUT PVOID Buffer,
    IN  ULONG Size);

KDP_STATUS
NTAPI
KdpReceivePacketLeader(
    OUT PULONG PacketLeader);

VOID
NTAPI
KdpSendByte(IN UCHAR Byte);

KDP_STATUS
NTAPI
KdpPollByte(OUT PUCHAR OutByte);

KDP_STATUS
NTAPI
KdpReceiveByte(OUT PUCHAR OutByte);

KDP_STATUS
NTAPI
KdpPollBreakIn(VOID);

/*
 * State of the link, see kdcom.c: how long the wait for an acknowledge may
 * last, whether a host was ever heard, and a break-in byte that was seen
 * while a packet was being exchanged.
 */
extern ULONG64 KdpByteWait;
extern BOOLEAN KdpHostSeen;
extern BOOLEAN KdpPatient;
extern BOOLEAN KdpBreakInSeen;
extern BOOLEAN KdpRememberBreakIn;

VOID
NTAPI
KdpHostIsPresent(VOID);

ULONG64
NTAPI
KdpAckWait(VOID);

#endif /* _KDDLL_H_ */
