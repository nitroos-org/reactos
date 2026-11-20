/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IGMP host side (RFC 3376 IGMPv3, with RFC 2236 IGMPv2 and RFC 1112 IGMPv1 compatibility): membership
 *              reports for the IPv4 groups the sockets of this computer joined
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * What a multicast-snooping switch or a multicast router learns from: a group the sockets joined on an interface is
 * announced there, and announced again when a querier asks. Shape as Windows Server 2022 sends it (peer captures):
 *
 * - IGMPv3 reports to 224.0.0.22, IP TTL 1, TOS 0, no DF, Router Alert option (RFC 2113), from the interface's address
 *   (0.0.0.0 without one, RFC 3376 4.2.13).
 * - A change of a group's filter (join, leave, a source filter) is a state change report sent at once and once more
 *   within a second (robustness 2; Windows: 0.1 to 0.5 s later): TO_EX{} or TO_IN{S}; the groups that change together
 *   share a report. (Windows sends ALLOW/BLOCK records for a source change inside INCLUDE mode; this sends TO_IN with
 *   the new set, which routers handle as the same change.)
 * - A general query is answered per group, each after its own random delay within the query's maximum response time,
 *   one group record per report (Windows does so; RFC 3376 allows a single report); a group-specific query by that
 *   group's record; a group-and-source-specific query by IS_IN with the asked sources the group takes.
 * - After an IGMPv1 or IGMPv2 query the interface answers in that version (v1/v2 reports to the group address, an
 *   IGMPv2 leave to 224.0.0.2) for the Older Version Querier Present Timeout, 260 s with the default timers
 *   (RFC 3376 8.12); Windows still answered a v3 query with v1 reports 37 s after the last v1 query.
 * - Never reported: 224.0.0.1 (all systems). 224.0.0.x groups other than that are (Windows reports 224.0.0.251/252).
 *
 * A group's filter is the merge of the sockets' filters for the interface (udp.c): any socket in EXCLUDE mode makes it
 * EXCLUDE with no source (exclusions are not reported: more traffic, never less), else INCLUDE with the union of the
 * sources, at most IGMP_MAX_SOURCES (more: EXCLUDE with none).
 *
 * Every received query is hostile input: the message length decides the version (8 octets: v1/v2, 12 or more: v3,
 * anything else is ignored, RFC 3376 7.1), the checksum must hold, the number of sources must fit in the message,
 * the IP TTL must be 1, a general query must be sent to 224.0.0.1 and a group query to its group (Windows ignored the
 * others). The work a query causes is bounded: one timer per group, at most IGMP_MAX_SOURCES remembered sources.
 *
 * Locking: IgmpLock (a spin lock) protects all state; nothing is sent and no other lock is taken while it is held,
 * except InterfaceListLock inside it to look an interface up. Reports are built under it and sent after it is released.
 * The timer runs only while something is due.
 */

#include "precomp.h"
#include <igmp.h>

#define IGMP_TAG                'pmgI'

#define IGMP_TYPE_QUERY         0x11
#define IGMP_TYPE_V1_REPORT     0x12
#define IGMP_TYPE_V2_REPORT     0x16
#define IGMP_TYPE_V2_LEAVE      0x17
#define IGMP_TYPE_V3_REPORT     0x22

#define IGMP_REC_IS_IN          1
#define IGMP_REC_IS_EX          2
#define IGMP_REC_TO_IN          3
#define IGMP_REC_TO_EX          4

#define IGMP_ALL_SYSTEMS        DH2N(0xE0000001)    /* 224.0.0.1 */
#define IGMP_ALL_ROUTERS        DH2N(0xE0000002)    /* 224.0.0.2 */
#define IGMP_V3_ROUTERS         DH2N(0xE0000016)    /* 224.0.0.22 */

#define IGMP_ROBUSTNESS         2                   /* reports per state change (RFC 3376 8.1) */
#define IGMP_OLDER_QUERIER_MS   260000              /* 2 x 125 s + 10 s (RFC 3376 8.12) */
#define IGMP_UNSOLICITED_MS     1000                /* Unsolicited Report Interval (RFC 3376 8.11) */
#define IGMP_MAX_GROUPS         1024                /* per interface */
#define IGMP_MAX_INTERFACES     64
#define IGMP_REPORT_MAX         1400                /* bytes of IGMP in one report */
#define IGMP_SENDS_PER_RUN      64

#define MS(x)                   ((ULONGLONG)(x) * 10000)

typedef struct _IGMP_GROUP
{
    LIST_ENTRY Entry;
    ULONG Group;                    /* network order */
    BOOLEAN Member;                 /* FALSE: left; kept until its leave reports are out */
    UCHAR Mode;                     /* IGMP_MODE_* of the merged filter */
    UCHAR ChangeLeft;               /* state change reports still to send */
    BOOLEAN AnswerSources;          /* the pending answer is to a group-and-source query (Query) */
    ULONGLONG ChangeDue;            /* interrupt time of the next state change report, 0: none */
    ULONGLONG AnswerDue;            /* interrupt time of the pending answer to a query, 0: none */
    USHORT NumSources;
    USHORT NumQuery;
    ULONG Sources[IGMP_MAX_SOURCES];    /* sorted, network order */
    ULONG Query[IGMP_MAX_SOURCES];      /* the sources asked about */
} IGMP_GROUP, *PIGMP_GROUP;

typedef struct _IGMP_INTERFACE
{
    LIST_ENTRY Entry;
    ULONG IfIndex;
    ULONG Count;
    ULONGLONG V1Until;              /* an IGMPv1 querier was heard: answer in v1 until then */
    ULONGLONG V2Until;
    LIST_ENTRY Groups;
} IGMP_INTERFACE, *PIGMP_INTERFACE;

/* One message to send, built under the lock */
typedef struct _IGMP_SEND
{
    ULONG IfIndex;
    ULONG Destination;
    ULONG Length;
    UCHAR Data[IGMP_REPORT_MAX];
} IGMP_SEND, *PIGMP_SEND;

static KSPIN_LOCK IgmpLock;
static LIST_ENTRY IgmpInterfaces;
static ULONG IgmpInterfaceCount;
static KTIMER IgmpTimer;
static KDPC IgmpDpc;
static ULONGLONG IgmpTimerDue;      /* interrupt time the timer is set for, 0: not set (IgmpArm, IgmpDpcRoutine) */
static BOOLEAN IgmpStarted;

static ULONGLONG
IgmpNow(VOID)
{
    return KeQueryInterruptTime();
}

/* A random delay in [0, Max] milliseconds */
static ULONGLONG
IgmpDelay(ULONG MaxMs)
{
    return MaxMs ? MS(Random() % (MaxMs + 1)) : 0;
}

static PIGMP_INTERFACE
IgmpFindInterface(ULONG IfIndex, BOOLEAN Create)
{
    PLIST_ENTRY Entry;
    PIGMP_INTERFACE IF;

    for (Entry = IgmpInterfaces.Flink; Entry != &IgmpInterfaces; Entry = Entry->Flink)
    {
        IF = CONTAINING_RECORD(Entry, IGMP_INTERFACE, Entry);
        if (IF->IfIndex == IfIndex)
            return IF;
    }
    if (!Create || IgmpInterfaceCount >= IGMP_MAX_INTERFACES)
        return NULL;
    IF = ExAllocatePoolWithTag(NonPagedPool, sizeof(*IF), IGMP_TAG);
    if (!IF)
        return NULL;
    RtlZeroMemory(IF, sizeof(*IF));
    IF->IfIndex = IfIndex;
    InitializeListHead(&IF->Groups);
    InsertTailList(&IgmpInterfaces, &IF->Entry);
    IgmpInterfaceCount++;
    return IF;
}

static PIGMP_GROUP
IgmpFindGroup(PIGMP_INTERFACE IF, ULONG Group)
{
    PLIST_ENTRY Entry;

    for (Entry = IF->Groups.Flink; Entry != &IF->Groups; Entry = Entry->Flink)
    {
        PIGMP_GROUP G = CONTAINING_RECORD(Entry, IGMP_GROUP, Entry);

        if (G->Group == Group)
            return G;
    }
    return NULL;
}

static VOID
IgmpFreeGroup(PIGMP_INTERFACE IF, PIGMP_GROUP G)
{
    RemoveEntryList(&G->Entry);
    IF->Count--;
    ExFreePoolWithTag(G, IGMP_TAG);
}

/* The version the interface answers with now */
static UCHAR
IgmpVersion(PIGMP_INTERFACE IF, ULONGLONG Now)
{
    if (IF->V1Until > Now)
        return 1;
    if (IF->V2Until > Now)
        return 2;
    return 3;
}

/* The timer for the earliest thing due (lock held) */
static VOID
IgmpArm(VOID)
{
    PLIST_ENTRY E1, E2;
    ULONGLONG Next = 0, Now = IgmpNow();
    LARGE_INTEGER Due;

    for (E1 = IgmpInterfaces.Flink; E1 != &IgmpInterfaces; E1 = E1->Flink)
    {
        PIGMP_INTERFACE IF = CONTAINING_RECORD(E1, IGMP_INTERFACE, Entry);

        for (E2 = IF->Groups.Flink; E2 != &IF->Groups; E2 = E2->Flink)
        {
            PIGMP_GROUP G = CONTAINING_RECORD(E2, IGMP_GROUP, Entry);

            if (G->ChangeDue && (!Next || G->ChangeDue < Next))
                Next = G->ChangeDue;
            if (G->AnswerDue && (!Next || G->AnswerDue < Next))
                Next = G->AnswerDue;
        }
    }
    if (!Next || !IgmpStarted)
        return;
    /* at least 1 ms from now; a deadline already armed is never moved later: setting the timer again for every query
       would push something due now out by 1 ms each time, and queries 1 ms apart would hold every report back */
    if (Next < Now + MS(1))
        Next = Now + MS(1);
    if (IgmpTimerDue && IgmpTimerDue <= Next)
        return;
    IgmpTimerDue = Next;
    Due.QuadPart = -(LONGLONG)(Next - Now);
    KeSetTimer(&IgmpTimer, Due, &IgmpDpc);
}

static VOID
IgmpPut16(PUCHAR P, USHORT V)
{
    P[0] = (UCHAR)(V >> 8);
    P[1] = (UCHAR)V;
}

static VOID
IgmpFinish(PIGMP_SEND S)
{
    USHORT Sum;

    S->Data[2] = S->Data[3] = 0;
    Sum = (USHORT)IPv4Checksum(S->Data, S->Length, 0);
    RtlCopyMemory(&S->Data[2], &Sum, sizeof(Sum));
}

/* A v1/v2 message of one group */
static VOID
IgmpBuildOld(PIGMP_SEND S, ULONG IfIndex, UCHAR Type, ULONG Group, ULONG Destination)
{
    S->IfIndex = IfIndex;
    S->Destination = Destination;
    S->Length = 8;
    S->Data[0] = Type;
    S->Data[1] = 0;
    RtlCopyMemory(&S->Data[4], &Group, sizeof(Group));
    IgmpFinish(S);
}

/* Appends one group record (IGMPv3 report); FALSE when it does not fit */
static BOOLEAN
IgmpAddRecord(PIGMP_SEND S, UCHAR Type, ULONG Group, const ULONG *Sources, ULONG NumSources)
{
    ULONG Needed = 8 + NumSources * sizeof(ULONG);
    USHORT Records;

    if (S->Length + Needed > IGMP_REPORT_MAX)
        return FALSE;
    S->Data[S->Length] = Type;
    S->Data[S->Length + 1] = 0;
    IgmpPut16(&S->Data[S->Length + 2], (USHORT)NumSources);
    RtlCopyMemory(&S->Data[S->Length + 4], &Group, sizeof(Group));
    if (NumSources)
        RtlCopyMemory(&S->Data[S->Length + 8], Sources, NumSources * sizeof(ULONG));
    S->Length += Needed;
    Records = (USHORT)((S->Data[6] << 8) | S->Data[7]);
    IgmpPut16(&S->Data[6], (USHORT)(Records + 1));
    return TRUE;
}

static VOID
IgmpStartV3(PIGMP_SEND S, ULONG IfIndex)
{
    S->IfIndex = IfIndex;
    S->Destination = IGMP_V3_ROUTERS;
    S->Length = 8;
    RtlZeroMemory(S->Data, 8);
    S->Data[0] = IGMP_TYPE_V3_REPORT;
}

/* One state change report of G went out (or, for a v1 leave, would have): the next one, or the end; a group that
   was left is freed after its last one. A v2 leave is sent once (RFC 2236 3) */
static VOID
IgmpChangeSent(PIGMP_INTERFACE IF, PIGMP_GROUP G, UCHAR Version, ULONGLONG Now)
{
    if (G->ChangeLeft)
        G->ChangeLeft--;
    if (Version != 3 && !G->Member)
        G->ChangeLeft = 0;
    G->ChangeDue = G->ChangeLeft ? Now + MS(1) + IgmpDelay(IGMP_UNSOLICITED_MS) : 0;
    if (!G->Member && !G->ChangeLeft)
        IgmpFreeGroup(IF, G);
}

/*
 * Builds the next message that is due (lock held): TRUE with S filled, FALSE when nothing is due. A v3 state change
 * report takes every group of the interface whose change is due (as many as fit); everything else is one group.
 */
static BOOLEAN
IgmpNextDue(PIGMP_SEND S, ULONGLONG Now)
{
    PLIST_ENTRY E1, E2, Next;

    for (E1 = IgmpInterfaces.Flink; E1 != &IgmpInterfaces; E1 = E1->Flink)
    {
        PIGMP_INTERFACE IF = CONTAINING_RECORD(E1, IGMP_INTERFACE, Entry);
        UCHAR Version = IgmpVersion(IF, Now);
        BOOLEAN Started = FALSE;

        for (E2 = IF->Groups.Flink; E2 != &IF->Groups; E2 = Next)
        {
            PIGMP_GROUP G = CONTAINING_RECORD(E2, IGMP_GROUP, Entry);

            Next = E2->Flink;

            /* a state change */
            if (G->ChangeDue && G->ChangeDue <= Now)
            {
                if (Version == 3)
                {
                    UCHAR Type = (G->Mode == IGMP_MODE_EXCLUDE) ? IGMP_REC_TO_EX : IGMP_REC_TO_IN;

                    if (!Started)
                    {
                        IgmpStartV3(S, IF->IfIndex);
                        Started = TRUE;
                    }
                    if (!IgmpAddRecord(S, Type, G->Group, G->Sources,
                                       (G->Mode == IGMP_MODE_INCLUDE) ? G->NumSources : 0))
                        break;      /* the report is full: the rest goes in the next one */
                    IgmpChangeSent(IF, G, Version, Now);
                    continue;
                }

                /* v1/v2: one message per group; v1 has no leave, a v2 leave goes to all routers */
                if (G->Member)
                {
                    IgmpBuildOld(S, IF->IfIndex, (Version == 1) ? IGMP_TYPE_V1_REPORT : IGMP_TYPE_V2_REPORT,
                                 G->Group, G->Group);
                    IgmpChangeSent(IF, G, Version, Now);
                    return TRUE;
                }
                if (Version == 2)
                {
                    IgmpBuildOld(S, IF->IfIndex, IGMP_TYPE_V2_LEAVE, G->Group, IGMP_ALL_ROUTERS);
                    IgmpChangeSent(IF, G, Version, Now);
                    return TRUE;
                }
                IgmpChangeSent(IF, G, Version, Now);
                continue;
            }

            /* an answer to a query (a v3 state change report being built goes out first) */
            if (!Started && G->AnswerDue && G->AnswerDue <= Now)
            {
                G->AnswerDue = 0;
                if (!G->Member)
                    continue;
                if (Version != 3)
                {
                    IgmpBuildOld(S, IF->IfIndex, (Version == 1) ? IGMP_TYPE_V1_REPORT : IGMP_TYPE_V2_REPORT,
                                 G->Group, G->Group);
                    return TRUE;
                }
                IgmpStartV3(S, IF->IfIndex);
                if (G->AnswerSources)
                {
                    /* IS_IN with the asked sources the group takes (RFC 3376 5.2); none: no report */
                    ULONG Taken[IGMP_MAX_SOURCES], n = 0, i, j;

                    for (i = 0; i < G->NumQuery; i++)
                    {
                        BOOLEAN Listed = FALSE;

                        for (j = 0; j < G->NumSources && !Listed; j++)
                            Listed = (G->Sources[j] == G->Query[i]);
                        if (G->Mode == IGMP_MODE_EXCLUDE ? !Listed : Listed)
                            Taken[n++] = G->Query[i];
                    }
                    G->AnswerSources = FALSE;
                    G->NumQuery = 0;
                    if (!n)
                        continue;
                    IgmpAddRecord(S, IGMP_REC_IS_IN, G->Group, Taken, n);
                }
                else if (G->Mode == IGMP_MODE_EXCLUDE)
                {
                    IgmpAddRecord(S, IGMP_REC_IS_EX, G->Group, NULL, 0);
                }
                else
                {
                    IgmpAddRecord(S, IGMP_REC_IS_IN, G->Group, G->Sources, G->NumSources);
                }
                IgmpFinish(S);
                return TRUE;
            }
        }
        if (Started)
        {
            IgmpFinish(S);
            return TRUE;
        }
    }
    return FALSE;
}

/* The interface with this index (referenced) */
static PIP_INTERFACE
IgmpReferenceInterface(ULONG IfIndex)
{
    PIP_INTERFACE Found = NULL;
    KIRQL OldIrql;
    IF_LIST_ITER(CurrentIF);

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);
    ForEachInterface(CurrentIF) {
        if (CurrentIF->Index == IfIndex)
        {
            if (CurrentIF != Loopback && !CurrentIF->Unbound && CurrentIF->AddressLength == 6)
            {
                IPReferenceInterface(CurrentIF);
                Found = CurrentIF;
            }
            break;
        }
    } EndFor(CurrentIF);
    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);
    return Found;
}

static VOID
IgmpTransmitComplete(PVOID Context, PNDIS_PACKET NdisPacket, NDIS_STATUS NdisStatus)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(NdisStatus);
    FreeNdisPacket(NdisPacket);
}

/* Sends one message: IPv4 header with the Router Alert option, TTL 1, to the destination's Ethernet address */
static VOID
IgmpTransmit(PIGMP_SEND S)
{
    PIP_INTERFACE IF = IgmpReferenceInterface(S->IfIndex);
    PNDIS_PACKET NdisPacket;
    PUCHAR Data;
    UINT Size, Contig;
    PIPv4_HEADER H;
    const UCHAR *D = (const UCHAR *)&S->Destination;
    UCHAR Mac[6];
    ULONG Total = sizeof(IPv4_HEADER) + 4 + S->Length;

    if (!IF)
        return;
    Size = Total;
    if (IF->MinFrameSize > IF->HeaderSize && Size < IF->MinFrameSize - IF->HeaderSize)
        Size = IF->MinFrameSize - IF->HeaderSize;
    if (!NT_SUCCESS(AllocatePacketWithBuffer(&NdisPacket, NULL, Size)))
    {
        IPDereferenceInterface(IF);
        return;
    }
    GetDataPtr(NdisPacket, 0, (PCHAR *)&Data, &Contig);
    RtlZeroMemory(Data, Size);

    H = (PIPv4_HEADER)Data;
    H->VerIHL = 0x46;                       /* 24-byte header: the Router Alert option */
    H->Tos = 0;
    H->TotalLength = WH2N((USHORT)Total);
    H->Id = (USHORT)Random();
    H->FlagsFragOfs = 0;
    H->Ttl = 1;
    H->Protocol = IPPROTO_IGMP;
    H->SrcAddr = (IF->Unicast.Type == IP_ADDRESS_V4) ? IF->Unicast.Address.IPv4Address : 0;
    H->DstAddr = S->Destination;
    Data[20] = 0x94;                        /* Router Alert (RFC 2113): type, length 4, value 0 */
    Data[21] = 0x04;
    H->Checksum = 0;
    H->Checksum = (USHORT)IPv4Checksum(H, 24, 0);
    RtlCopyMemory(Data + 24, S->Data, S->Length);

    Mac[0] = 0x01; Mac[1] = 0x00; Mac[2] = 0x5E;
    Mac[3] = D[1] & 0x7F; Mac[4] = D[2]; Mac[5] = D[3];

    PC(NdisPacket)->DLComplete = IgmpTransmitComplete;
    (*IF->Transmit)(IF->Context, NdisPacket, 0, Mac, LAN_PROTO_IPv4);
    IPDereferenceInterface(IF);
}

static VOID
NTAPI
IgmpDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    PIGMP_SEND S;
    KIRQL OldIrql;
    ULONG n;
    BOOLEAN More = FALSE;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    S = ExAllocatePoolWithTag(NonPagedPool, sizeof(*S), IGMP_TAG);

    for (n = 0; n < IGMP_SENDS_PER_RUN; n++)
    {
        KeAcquireSpinLock(&IgmpLock, &OldIrql);
        /* the timer fired: whatever comes due from now on sets it again (IgmpArm) */
        if (n == 0)
            IgmpTimerDue = 0;
        if (!S)
        {
            /* no memory for a message now: try again later */
            More = TRUE;
        }
        else
        {
            More = IgmpNextDue(S, IgmpNow());
        }
        if (!More || !S)
        {
            IgmpArm();
            KeReleaseSpinLock(&IgmpLock, OldIrql);
            break;
        }
        KeReleaseSpinLock(&IgmpLock, OldIrql);
        IgmpTransmit(S);
    }
    if (n == IGMP_SENDS_PER_RUN)
    {
        KeAcquireSpinLock(&IgmpLock, &OldIrql);
        IgmpArm();
        KeReleaseSpinLock(&IgmpLock, OldIrql);
    }
    if (S)
        ExFreePoolWithTag(S, IGMP_TAG);
}

VOID
IGMPSetGroupState(ULONG IfIndex, ULONG Group, UCHAR Mode, const ULONG *Sources, ULONG NumSources)
{
    PIGMP_INTERFACE IF;
    PIGMP_GROUP G;
    KIRQL OldIrql;
    BOOLEAN Member;

    if (!IgmpStarted || Group == IGMP_ALL_SYSTEMS || !IPV4_IS_MULTICAST(Group))
        return;
    if (NumSources > IGMP_MAX_SOURCES)
    {
        /* more sources than a record keeps: all of them (more traffic, never less) */
        Mode = IGMP_MODE_EXCLUDE;
        NumSources = 0;
    }
    if (Mode == IGMP_MODE_EXCLUDE)
        NumSources = 0;
    Member = !(Mode == IGMP_MODE_INCLUDE && NumSources == 0);

    KeAcquireSpinLock(&IgmpLock, &OldIrql);
    IF = IgmpFindInterface(IfIndex, Member);
    G = IF ? IgmpFindGroup(IF, Group) : NULL;
    if (!G)
    {
        if (!Member || !IF || IF->Count >= IGMP_MAX_GROUPS)
            goto Done;
        G = ExAllocatePoolWithTag(NonPagedPool, sizeof(*G), IGMP_TAG);
        if (!G)
            goto Done;
        RtlZeroMemory(G, sizeof(*G));
        G->Group = Group;
        G->Mode = IGMP_MODE_INCLUDE;
        InsertTailList(&IF->Groups, &G->Entry);
        IF->Count++;
    }
    else if (G->Member == Member && G->Mode == Mode && G->NumSources == NumSources &&
             (!NumSources ||
              RtlCompareMemory(G->Sources, Sources, NumSources * sizeof(ULONG)) == NumSources * sizeof(ULONG)))
    {
        goto Done;      /* nothing changed */
    }

    G->Member = Member;
    G->Mode = Mode;
    G->NumSources = (USHORT)NumSources;
    if (NumSources)
        RtlCopyMemory(G->Sources, Sources, NumSources * sizeof(ULONG));
    if (!Member)
    {
        G->AnswerDue = 0;
        G->AnswerSources = FALSE;
        G->NumQuery = 0;
    }
    G->ChangeLeft = IGMP_ROBUSTNESS;
    G->ChangeDue = IgmpNow();
    IgmpArm();
Done:
    KeReleaseSpinLock(&IgmpLock, OldIrql);
}

VOID
IGMPInterfaceRefresh(ULONG IfIndex)
{
    PIGMP_INTERFACE IF;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    ULONGLONG Now = IgmpNow();

    if (!IgmpStarted)
        return;
    KeAcquireSpinLock(&IgmpLock, &OldIrql);
    IF = IgmpFindInterface(IfIndex, FALSE);
    for (Entry = IF ? IF->Groups.Flink : NULL; IF && Entry != &IF->Groups; Entry = Entry->Flink)
    {
        PIGMP_GROUP G = CONTAINING_RECORD(Entry, IGMP_GROUP, Entry);

        if (!G->Member)
            continue;
        G->ChangeLeft = IGMP_ROBUSTNESS;
        G->ChangeDue = Now;
    }
    if (IF)
        IgmpArm();
    KeReleaseSpinLock(&IgmpLock, OldIrql);
}

VOID
IGMPInterfaceGone(ULONG IfIndex)
{
    PIGMP_INTERFACE IF;
    KIRQL OldIrql;

    if (!IgmpStarted)
        return;
    KeAcquireSpinLock(&IgmpLock, &OldIrql);
    IF = IgmpFindInterface(IfIndex, FALSE);
    if (IF)
    {
        while (!IsListEmpty(&IF->Groups))
            IgmpFreeGroup(IF, CONTAINING_RECORD(IF->Groups.Flink, IGMP_GROUP, Entry));
        RemoveEntryList(&IF->Entry);
        IgmpInterfaceCount--;
        ExFreePoolWithTag(IF, IGMP_TAG);
    }
    KeReleaseSpinLock(&IgmpLock, OldIrql);
}

/* A query's Max Resp Code in tenths of a second (RFC 3376 4.1.1: 128 and up is a floating point value) */
static ULONG
IgmpMaxResponse(UCHAR Code)
{
    if (Code < 128)
        return Code;
    return (ULONG)((Code & 0x0F) | 0x10) << (((Code >> 4) & 0x07) + 3);
}

/* Schedules the answer of one group to a query: the earlier of a pending answer and a new random one */
static VOID
IgmpScheduleAnswer(PIGMP_GROUP G, ULONGLONG Now, ULONG MaxMs, BOOLEAN WithSources)
{
    ULONGLONG Due = Now + IgmpDelay(MaxMs);

    if (!WithSources)
    {
        /* a group answer covers any source question that was pending */
        G->AnswerSources = FALSE;
        G->NumQuery = 0;
    }
    else
    {
        G->AnswerSources = TRUE;
    }
    if (!G->AnswerDue || Due < G->AnswerDue)
        G->AnswerDue = Due;
}

/* Whether the IPv4 header carries the Router Alert option (RFC 2113: type 148, length 4); a malformed option list ends
   the walk */
static BOOLEAN
IgmpHasRouterAlert(PIP_PACKET IPPacket)
{
    const UCHAR *O = (const UCHAR *)IPPacket->Header;
    ULONG i = sizeof(IPv4_HEADER), End = IPPacket->HeaderSize;

    while (i < End)
    {
        if (O[i] == 0)              /* end of the list */
            break;
        if (O[i] == 1)              /* no operation */
        {
            i++;
            continue;
        }
        if (i + 1 >= End || O[i + 1] < 2 || O[i + 1] > End - i)
            break;
        if (O[i] == 0x94 && O[i + 1] == 4)
            return TRUE;
        i += O[i + 1];
    }
    return FALSE;
}

VOID
IGMPReceive(PIP_INTERFACE Interface, PIP_PACKET IPPacket)
{
    PIPv4_HEADER H = (PIPv4_HEADER)IPPacket->Header;
    PUCHAR M = (PUCHAR)IPPacket->Data;
    ULONG Length, Group, MaxMs, NumSources = 0, i;
    UCHAR Version;
    PIGMP_INTERFACE IF;
    PIGMP_GROUP G;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    ULONGLONG Now;

    if (IPPacket->TotalSize < IPPacket->HeaderSize)
        return;
    Length = IPPacket->TotalSize - IPPacket->HeaderSize;

    /* The shortest IGMP message is 8 octets; the checksum covers the whole message (RFC 3376 4.1.2) */
    if (Length < 8 || !IPv4CorrectChecksum(M, Length))
        return;

    /* administrators' raw IGMP sockets see every well-formed message, as on Windows */
    RawIpReceive(Interface, IPPacket);

    if (!IgmpStarted || Interface == Loopback || M[0] != IGMP_TYPE_QUERY)
        return;     /* the reports of others change nothing for an IGMPv3 host */

    /* Version by length (RFC 3376 7.1): 8 octets v1 (Max Resp 0) or v2, 12 or more v3, anything else is ignored */
    if (Length == 8)
        Version = M[1] ? 2 : 1;
    else if (Length >= 12)
        Version = 3;
    else
        return;

    /* Which queries are taken, as Windows Server 2022 takes them (peer rows): an IGMPv3 query only with the Router Alert
       option (RFC 3376 9.1: hosts SHOULD ignore queries without it), whatever its TTL; an IGMPv2 or IGMPv1 one with the
       option or with TTL 1 (Windows answered a v2 query without it at TTL 1, not at TTL 64) */
    if (!IgmpHasRouterAlert(IPPacket) && (Version == 3 || H->Ttl != 1))
        return;

    RtlCopyMemory(&Group, &M[4], sizeof(Group));
    if (Group == 0)
    {
        if (H->DstAddr != IGMP_ALL_SYSTEMS)
            return;
    }
    else if (!IPV4_IS_MULTICAST(Group) || H->DstAddr != Group)
    {
        return;
    }

    if (Version == 3)
    {
        NumSources = ((ULONG)M[10] << 8) | M[11];
        if (NumSources > (Length - 12) / sizeof(ULONG))
            return;     /* more sources claimed than the message holds */
        if (Group == 0 && NumSources)
            return;     /* a general query names no source */
    }

    /* tenths of a second; v1 has none: 10 s (RFC 2236 4); a v2 query's is linear over its whole range, the floating
       point form is IGMPv3's only (RFC 3376 4.1.1, 7.2.1) */
    MaxMs = (Version == 1) ? 10000 : ((Version == 2) ? M[1] : IgmpMaxResponse(M[1])) * 100;

    Now = IgmpNow();
    KeAcquireSpinLock(&IgmpLock, &OldIrql);
    IF = IgmpFindInterface(Interface->Index, TRUE);
    if (!IF)
        goto Done;
    if (Version == 1)
        IF->V1Until = Now + MS(IGMP_OLDER_QUERIER_MS);
    else if (Version == 2 && Group == 0)
        IF->V2Until = Now + MS(IGMP_OLDER_QUERIER_MS);  /* a v2 General Query only (RFC 3376 7.2.1; Windows answered
                                                           a v3 query in v3 right after a v2 group query) */

    if (Group == 0)
    {
        /* each group after its own random delay */
        for (Entry = IF->Groups.Flink; Entry != &IF->Groups; Entry = Entry->Flink)
        {
            G = CONTAINING_RECORD(Entry, IGMP_GROUP, Entry);
            if (G->Member)
                IgmpScheduleAnswer(G, Now, MaxMs, FALSE);
        }
    }
    else if ((G = IgmpFindGroup(IF, Group)) != NULL && G->Member)
    {
        if (!NumSources || IgmpVersion(IF, Now) != 3 || (G->AnswerDue && !G->AnswerSources))
        {
            /* a group-specific query, an old version, or a group answer already pending */
            IgmpScheduleAnswer(G, Now, MaxMs, FALSE);
        }
        else
        {
            /* the asked sources are added to those pending (each once); too many: the group's whole record */
            BOOLEAN Overflow = FALSE;

            if (!G->AnswerDue)
                G->NumQuery = 0;
            for (i = 0; i < NumSources && !Overflow; i++)
            {
                ULONG Source, j;

                RtlCopyMemory(&Source, &M[12 + i * sizeof(ULONG)], sizeof(Source));
                for (j = 0; j < G->NumQuery && G->Query[j] != Source; j++)
                    ;
                if (j < G->NumQuery)
                    continue;
                if (G->NumQuery == IGMP_MAX_SOURCES)
                    Overflow = TRUE;
                else
                    G->Query[G->NumQuery++] = Source;
            }
            IgmpScheduleAnswer(G, Now, MaxMs, !Overflow);
        }
    }
    IgmpArm();
Done:
    KeReleaseSpinLock(&IgmpLock, OldIrql);
}

NTSTATUS
IGMPStartup(VOID)
{
    KeInitializeSpinLock(&IgmpLock);
    InitializeListHead(&IgmpInterfaces);
    KeInitializeTimer(&IgmpTimer);
    KeInitializeDpc(&IgmpDpc, IgmpDpcRoutine, NULL);
    IgmpStarted = TRUE;
    IPRegisterProtocol(IPPROTO_IGMP, IGMPReceive);
    return STATUS_SUCCESS;
}

VOID
IGMPShutdown(VOID)
{
    KIRQL OldIrql;

    if (!IgmpStarted)
        return;
    IPRegisterProtocol(IPPROTO_IGMP, NULL);
    KeAcquireSpinLock(&IgmpLock, &OldIrql);
    IgmpStarted = FALSE;
    KeReleaseSpinLock(&IgmpLock, OldIrql);
    KeCancelTimer(&IgmpTimer);
    KeFlushQueuedDpcs();
    while (!IsListEmpty(&IgmpInterfaces))
    {
        PIGMP_INTERFACE IF = CONTAINING_RECORD(IgmpInterfaces.Flink, IGMP_INTERFACE, Entry);

        while (!IsListEmpty(&IF->Groups))
            IgmpFreeGroup(IF, CONTAINING_RECORD(IF->Groups.Flink, IGMP_GROUP, Entry));
        RemoveEntryList(&IF->Entry);
        ExFreePoolWithTag(IF, IGMP_TAG);
    }
    IgmpInterfaceCount = 0;
}
