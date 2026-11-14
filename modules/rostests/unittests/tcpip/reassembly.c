/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IPv4 fragment reassembly of the tcpip driver (network/receive.c)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

LONG TestPoolBlocks;
LONG TestNdisPackets;

static ULONG DispatchCount;
static UINT DispatchTotalSize;
static UINT DispatchHeaderSize;
static BOOLEAN DispatchDataOk;
static UCHAR FragmentProtocol = 17;

BOOLEAN TCPIpv6Enabled;
static ULONG Receive6Count;

/* MOCKS **********************************************************************/

PVOID
ExAllocatePoolWithTag(ULONG PoolType, SIZE_T NumberOfBytes, ULONG Tag)
{
    PVOID P = HeapAlloc(GetProcessHeap(), 0, NumberOfBytes ? NumberOfBytes : 1);
    if (P)
        InterlockedIncrement(&TestPoolBlocks);
    return P;
}

VOID
ExFreePoolWithTag(PVOID P, ULONG Tag)
{
    InterlockedDecrement(&TestPoolBlocks);
    HeapFree(GetProcessHeap(), 0, P);
}

PVOID
ExAllocateFromNPagedLookasideList(PNPAGED_LOOKASIDE_LIST List)
{
    return ExAllocatePoolWithTag(NonPagedPool, List->Size, 0);
}

VOID
ExFreeToNPagedLookasideList(PNPAGED_LOOKASIDE_LIST List, PVOID Entry)
{
    ExFreePoolWithTag(Entry, 0);
}

UINT
CopyPacketToBuffer(PCHAR DstData, PNDIS_PACKET SrcPacket, UINT SrcOffset, UINT Length)
{
    if (SrcOffset >= SrcPacket->Length)
        return 0;
    if (Length > SrcPacket->Length - SrcOffset)
        Length = SrcPacket->Length - SrcOffset;
    RtlCopyMemory(DstData, SrcPacket->Data + SrcOffset, Length);
    return Length;
}

VOID
FreeNdisPacket(PNDIS_PACKET Packet)
{
    InterlockedDecrement(&TestNdisPackets);
    HeapFree(GetProcessHeap(), 0, Packet->Data);
    HeapFree(GetProcessHeap(), 0, Packet);
}

VOID
NdisReturnPackets(PNDIS_PACKET *Packets, UINT Count)
{
    UINT i;
    for (i = 0; i < Count; i++)
        FreeNdisPacket(Packets[i]);
}

static VOID
TestDeinitializePacket(PVOID Object)
{
    PIP_PACKET IPPacket = Object;

    if (IPPacket->NdisPacket)
        FreeNdisPacket(IPPacket->NdisPacket);
    if (!IPPacket->MappedHeader && IPPacket->Header)
        ExFreePoolWithTag(IPPacket->Header, PACKET_BUFFER_TAG);
}

PIP_PACKET
IPInitializePacket(PIP_PACKET IPPacket, ULONG Type)
{
    RtlZeroMemory(IPPacket, sizeof(IP_PACKET));
    IPPacket->Free = TestDeinitializePacket;
    IPPacket->Type = Type;
    return IPPacket;
}

static UCHAR
PatternByte(UINT Offset)
{
    return (UCHAR)(Offset * 7 + 3);
}

/* The upper layers take 16-bit lengths: lwIP's pbuf_alloc() (via LibIPInsertPacket)
   truncates TotalSize to u16_t, UDP and ICMP keep 16-bit length fields */
VOID
IPDispatchProtocol(PIP_INTERFACE Interface, PIP_PACKET IPPacket)
{
    PUCHAR Data = (PUCHAR)IPPacket->Header + IPPacket->HeaderSize;
    UINT i;

    DispatchCount++;
    DispatchTotalSize = IPPacket->TotalSize;
    DispatchHeaderSize = IPPacket->HeaderSize;
    DispatchDataOk = (IPPacket->Data == Data);
    for (i = 0; DispatchDataOk && i < IPPacket->TotalSize - IPPacket->HeaderSize; i++)
    {
        if (Data[i] != PatternByte(i))
            DispatchDataOk = FALSE;
    }
}

VOID
TCPReceive6(PIP_INTERFACE IF, PIP_PACKET IPPacket)
{
    Receive6Count++;
}

BOOLEAN
IPv4CorrectChecksum(PVOID Data, UINT Count)
{
    return TRUE;
}

VOID
AddrInitIPv4(PIP_ADDRESS IPAddress, IPv4_RAW_ADDRESS RawAddress)
{
    IPAddress->Type = IP_ADDRESS_V4;
    IPAddress->Address.IPv4Address = RawAddress;
}

BOOLEAN
AddrIsEqual(PIP_ADDRESS Address1, PIP_ADDRESS Address2)
{
    return Address1->Type == Address2->Type &&
           Address1->Address.IPv4Address == Address2->Address.IPv4Address;
}

/* HELPERS ********************************************************************/

#define H2WN(w) WN2H(w)

/* Deliver one IPv4 fragment through IPReceive(), as the LAN layer does */
static VOID
SendFragment(USHORT Id, UINT HeaderSize, UINT Offset, UINT PayloadSize, BOOLEAN MoreFragments)
{
    IP_INTERFACE If = { 0 };
    IP_PACKET Packet;
    PNDIS_PACKET Ndis;
    PIPv4_HEADER Header;
    UINT Length = HeaderSize + PayloadSize;
    UINT i;

    ok(Length <= 0xFFFF && (Offset & 7) == 0 && HeaderSize >= 20 && HeaderSize <= 60 && !(HeaderSize & 3),
       "bad test fragment %u/%u/%u\n", HeaderSize, Offset, PayloadSize);

    Ndis = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Ndis));
    Ndis->Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
    Ndis->Length = Length;
    InterlockedIncrement(&TestNdisPackets);

    Header = (PIPv4_HEADER)Ndis->Data;
    Header->VerIHL = 0x40 | (UCHAR)(HeaderSize / 4);
    Header->TotalLength = H2WN((USHORT)Length);
    Header->Id = Id;
    Header->FlagsFragOfs = H2WN((USHORT)((Offset >> 3) | (MoreFragments ? IPv4_MF_MASK : 0)));
    Header->Ttl = 64;
    Header->Protocol = FragmentProtocol;
    Header->SrcAddr = 0x0100000A;
    Header->DstAddr = 0x0200000A;
    for (i = 0; i < PayloadSize; i++)
        Ndis->Data[HeaderSize + i] = PatternByte(Offset + i);

    IPInitializePacket(&Packet, IP_ADDRESS_V4);
    Packet.NdisPacket = Ndis;
    Packet.TotalSize = Length;
    Packet.Position = 0;

    IPReceive(&If, &Packet);
}

static VOID
ResetDispatch(VOID)
{
    DispatchCount = 0;
    DispatchTotalSize = 0;
    DispatchHeaderSize = 0;
    DispatchDataOk = FALSE;
}

static VOID
ExpectNothingLeft(PCSTR Name)
{
    ok(IsListEmpty(&ReassemblyListHead), "%s: reassembly still pending\n", Name);
    IPFreeReassemblyList();
    ok(TestPoolBlocks == 0, "%s: %ld pool blocks leaked\n", Name, TestPoolBlocks);
    ok(TestNdisPackets == 0, "%s: %ld NDIS packets leaked\n", Name, TestNdisPackets);
}

/* TESTS **********************************************************************/

static VOID
TestLegitimate(VOID)
{
    /* Two fragments, the last one first */
    ResetDispatch();
    SendFragment(1, 20, 1480, 520, FALSE);
    ok(DispatchCount == 0, "completed early\n");
    SendFragment(1, 20, 0, 1480, TRUE);
    ok(DispatchCount == 1, "DispatchCount = %lu\n", DispatchCount);
    ok(DispatchTotalSize == 2020, "TotalSize = %u\n", DispatchTotalSize);
    ok(DispatchHeaderSize == 20, "HeaderSize = %u\n", DispatchHeaderSize);
    ok(DispatchDataOk, "reassembled data differs\n");
    ExpectNothingLeft("2 fragments");

    /* A first fragment with options: the datagram takes its header */
    ResetDispatch();
    SendFragment(2, 60, 0, 1440, TRUE);
    SendFragment(2, 20, 1440, 100, FALSE);
    ok(DispatchCount == 1, "DispatchCount = %lu\n", DispatchCount);
    ok(DispatchTotalSize == 1600, "TotalSize = %u\n", DispatchTotalSize);
    ok(DispatchHeaderSize == 60, "HeaderSize = %u\n", DispatchHeaderSize);
    ok(DispatchDataOk, "reassembled data differs\n");
    ExpectNothingLeft("options");
}

static VOID
TestMaximumSize(VOID)
{
    /* 65515 payload octets + a 20-octet header = 65535, the largest IP datagram */
    ResetDispatch();
    SendFragment(3, 20, 0, 65480, TRUE);
    SendFragment(3, 20, 65480, 35, FALSE);
    ok(DispatchCount == 1, "DispatchCount = %lu\n", DispatchCount);
    ok(DispatchTotalSize == 65535, "TotalSize = %u\n", DispatchTotalSize);
    ok(DispatchDataOk, "reassembled data differs\n");
    ExpectNothingLeft("65535");
}

static VOID
TestOversize(VOID)
{
    /* 65516 payload octets pass the per-fragment bound, but with the 20-octet header
       the datagram is 65536 octets: a 16-bit length makes it 0. It must be dropped. */
    ResetDispatch();
    SendFragment(4, 20, 0, 65480, TRUE);
    SendFragment(4, 20, 65480, 36, FALSE);
    ok(DispatchCount == 0, "65536-octet datagram delivered, TotalSize %u (0x%x as 16 bits)\n",
       DispatchTotalSize, DispatchTotalSize & 0xFFFF);
    ExpectNothingLeft("65536");

    /* The same with the last fragment first */
    ResetDispatch();
    SendFragment(5, 20, 65480, 55, FALSE);
    SendFragment(5, 20, 0, 65480, TRUE);
    ok(DispatchCount == 0, "65555-octet datagram delivered, TotalSize %u\n", DispatchTotalSize);
    ExpectNothingLeft("65555");

    /* A 60-octet first header: 65496 payload octets make 65556 */
    ResetDispatch();
    SendFragment(6, 60, 0, 65440, TRUE);
    SendFragment(6, 20, 65440, 56, FALSE);
    ok(DispatchCount == 0, "65556-octet datagram delivered, TotalSize %u\n", DispatchTotalSize);
    ExpectNothingLeft("65556");

    /* A datagram that fits still reassembles after the drops */
    ResetDispatch();
    SendFragment(7, 20, 0, 8, TRUE);
    SendFragment(7, 20, 8, 8, FALSE);
    ok(DispatchCount == 1, "DispatchCount = %lu\n", DispatchCount);
    ok(DispatchTotalSize == 36, "TotalSize = %u\n", DispatchTotalSize);
    ok(DispatchDataOk, "reassembled data differs\n");
    ExpectNothingLeft("after drops");
}

/* A TCP segment whose header is cut by a fragment boundary (a fragment needs only a multiple of 8 octets)
   reaches TCP as one contiguous datagram: the IPv4 path reassembles into a single buffer */
static VOID
TestTcpHeaderSplit(VOID)
{
    static const UINT Cuts[] = { 8, 16, 24 };
    UINT i;

    FragmentProtocol = 6;
    for (i = 0; i < sizeof(Cuts) / sizeof(Cuts[0]); i++)
    {
        ResetDispatch();
        SendFragment(8 + (USHORT)i, 20, 0, Cuts[i], TRUE);
        ok(DispatchCount == 0, "cut %u: completed early\n", Cuts[i]);
        SendFragment(8 + (USHORT)i, 20, Cuts[i], 40 - Cuts[i], FALSE);
        ok(DispatchCount == 1, "cut %u: DispatchCount = %lu\n", Cuts[i], DispatchCount);
        ok(DispatchTotalSize == 60, "cut %u: TotalSize = %u\n", Cuts[i], DispatchTotalSize);
        ok(DispatchHeaderSize == 20, "cut %u: HeaderSize = %u\n", Cuts[i], DispatchHeaderSize);
        ok(DispatchDataOk, "cut %u: reassembled data differs\n", Cuts[i]);
        ExpectNothingLeft("TCP header split");
    }
    FragmentProtocol = 17;
}

/* An IPv6 frame goes to lwIP (TCPReceive6) only with IPv6 on, and IPReceive frees it either way */
static VOID
TestIPv6Switch(VOID)
{
    IP_INTERFACE If = { 0 };
    IP_PACKET Packet;
    PNDIS_PACKET Ndis;
    BOOLEAN On;

    for (On = FALSE; On <= TRUE; On++)
    {
        TCPIpv6Enabled = On;
        Receive6Count = 0;
        ResetDispatch();

        Ndis = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Ndis));
        Ndis->Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 40);
        Ndis->Length = 40;
        Ndis->Data[0] = 0x60;
        Ndis->Data[6] = 59;
        InterlockedIncrement(&TestNdisPackets);

        IPInitializePacket(&Packet, IP_ADDRESS_V4);
        Packet.NdisPacket = Ndis;
        Packet.TotalSize = 40;
        Packet.Position = 0;
        IPReceive(&If, &Packet);

        ok(Receive6Count == (On ? 1 : 0), "switch %d: TCPReceive6 called %lu times\n", On, Receive6Count);
        ok(DispatchCount == 0, "switch %d: an IPv6 frame reached the IPv4 dispatch\n", On);
        ExpectNothingLeft(On ? "IPv6 on" : "IPv6 off");
    }
    TCPIpv6Enabled = FALSE;
}

/* A frame's ethertype decides: an IPv6 header in an IPv4 frame never reaches lwIP, an IPv4 header in an
   IPv6 frame never reaches the IPv4 dispatch; both are freed */
static VOID
TestEtherTypeVersion(VOID)
{
    IP_INTERFACE If = { 0 };
    IP_PACKET Packet;
    PNDIS_PACKET Ndis;
    UINT Case;

    TCPIpv6Enabled = TRUE;
    for (Case = 0; Case < 4; Case++)
    {
        /* 0: v6 header, v4 frame; 1: v4 header, v6 frame; 2: v6 in v6 (control); 3: v4 in v4 (control) */
        BOOLEAN V6Header = (Case == 0 || Case == 2);
        UINT FrameVersion = (Case == 0 || Case == 3) ? 4 : 6;

        Receive6Count = 0;
        ResetDispatch();

        Ndis = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Ndis));
        Ndis->Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 40);
        Ndis->Length = 40;
        if (V6Header)
        {
            Ndis->Data[0] = 0x60;
            Ndis->Data[6] = 59;
        }
        else
        {
            /* An unfragmented UDP datagram of 20 bytes of data, as SendFragment builds them: dispatched */
            PIPv4_HEADER Header = (PIPv4_HEADER)Ndis->Data;
            UINT i;

            Header->VerIHL = 0x45;
            Header->TotalLength = H2WN(40);
            Header->Id = 77;
            Header->Ttl = 64;
            Header->Protocol = 17;
            Header->SrcAddr = 0x0100000A;
            Header->DstAddr = 0x0200000A;
            for (i = 0; i < 20; i++)
                Ndis->Data[20 + i] = PatternByte(i);
        }
        InterlockedIncrement(&TestNdisPackets);

        IPInitializePacket(&Packet, IP_ADDRESS_V4);
        Packet.NdisPacket = Ndis;
        Packet.TotalSize = 40;
        Packet.Position = 0;
        IPReceiveVersion(&If, &Packet, FrameVersion);

        ok(Receive6Count == (Case == 2 ? 1 : 0), "case %u: TCPReceive6 called %lu times\n", Case, Receive6Count);
        ok(DispatchCount == (Case == 3 ? 1 : 0), "case %u: IPv4 dispatch %lu times\n", Case, DispatchCount);
        ExpectNothingLeft("ethertype/version");
    }
    TCPIpv6Enabled = FALSE;
}

START_TEST(Reassembly)
{
    IPDRList.Size = sizeof(IPDATAGRAM_REASSEMBLY);
    IPFragmentList.Size = sizeof(IP_FRAGMENT);
    IPHoleList.Size = sizeof(IPDATAGRAM_HOLE);
    InitializeListHead(&ReassemblyListHead);

    TestLegitimate();
    TestMaximumSize();
    TestOversize();
    TestTcpHeaderSplit();
    TestIPv6Switch();
    TestEtherTypeVersion();
}
