/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     In-driver self-test of IPv6 (if6.c), for test runs only
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Built into debug builds, and into a release build configured with -DTCPIP_IPV6_SELFTEST=ON. It runs only
 * with IPv6 on (Ipv6Enable) and Tcpip\Parameters\Ipv6SelfTest (REG_DWORD) non-zero, once, from a system
 * thread started at TCPStartup. There is no IPv6 socket yet, so it uses lwIP's raw API under the core lock.
 * Every result is a line "IPV6TEST: <name>: PASS|FAIL ..." on the debug port and in
 * %SystemRoot%\Temp\ipv6selftest.txt (a release build has no debug output), the last one
 * "IPV6TEST: DONE pass=<n> fail=<m>".
 *
 * Optional: Ipv6SelfTestPeer (REG_SZ, an IPv6 address on the first Ethernet link) and Ipv6SelfTestPeerPort
 * (REG_DWORD) name a TCP echo server to reach through neighbour discovery.
 *
 * Multicast reception (the adapter's multicast list, datalink/lan.c) is checked on every run. Optional, for
 * a test host that takes part:
 * - Ipv6SelfTestInboundWait (REG_DWORD, seconds): wait that long, at most, for a neighbour solicitation to our
 *   solicited-node group and an echo request (the host pings our link-local address with its neighbour cache
 *   flushed), and say whether they came;
 * - Ipv6SelfTestSlaacWait (REG_DWORD, seconds): wait that long, at most, for an address that stateless
 *   autoconfiguration (RFC 4862) forms from a multicast router advertisement;
 *   Ipv6SelfTestSlaacPeer (REG_SZ) and Ipv6SelfTestSlaacPeerPort (REG_DWORD): a TCP echo server to reach from it.
 */

#include "precomp.h"

#if DBG || defined(TCPIP_IPV6_SELFTEST)

#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/inet_chksum.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcp_priv.h"
#include <reactos/nitrofw.h>
#include <nitrofwk.h>
#include <stdio.h>
#include <stdarg.h>

extern volatile LONG TCP6ReceiveDropped;
extern volatile LONG TCP6ListenerRefused;
extern volatile LONG TCP6FilterDropped;
extern volatile LONG TCP6IcmpErrorsLimited;
extern volatile LONG TCP6IcmpErrorsSent;
VOID TCPInput6(PIP_INTERFACE IF, struct pbuf *p, BOOLEAN FromOwnLink);

#define ST_TAG 'T6pI'
#define ST_LOG_SIZE 65536

static BOOLEAN StReadValue(PCWSTR Name, ULONG Type, PVOID Data, ULONG Size);

static PCHAR StLog;
static ULONG StLogLength;
static ULONG StPass, StFail;
static UCHAR StPattern[4096];

static VOID
StFlush(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\SystemRoot\\Temp\\ipv6selftest.txt");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE File;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwCreateFile(&File, GENERIC_WRITE | SYNCHRONIZE, &Attributes, &Iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                                FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0)))
    {
        ZwWriteFile(File, NULL, NULL, NULL, &Iosb, StLog, StLogLength, NULL, NULL);
        ZwClose(File);
    }
}

static VOID
StPrint(const char *Format, ...)
{
    CHAR Line[256];
    va_list Args;
    int n;

    va_start(Args, Format);
    n = _vsnprintf(Line, sizeof(Line) - 1, Format, Args);
    va_end(Args);
    if (n < 0 || n > (int)sizeof(Line) - 2)
        n = sizeof(Line) - 2;
    Line[n++] = '\n';
    Line[n] = 0;

    DbgPrint("IPV6TEST: %s", Line);
    if (StLog && StLogLength + 10 + n < ST_LOG_SIZE)
    {
        RtlCopyMemory(StLog + StLogLength, "IPV6TEST: ", 10);
        RtlCopyMemory(StLog + StLogLength + 10, Line, n);
        StLogLength += 10 + n;
    }
}

static VOID
StResult(BOOLEAN Ok, const char *Name, const char *Detail)
{
    if (Ok)
        StPass++;
    else
        StFail++;
    StPrint("%s: %s %s", Name, Ok ? "PASS" : "FAIL", Detail ? Detail : "");
    StFlush();
}

static VOID
StSleep(ULONG Ms)
{
    LARGE_INTEGER Delay;

    Delay.QuadPart = -(LONGLONG)Ms * 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

static ULONG
StMicroseconds(LARGE_INTEGER Start)
{
    LARGE_INTEGER Now, Frequency;

    Now = KeQueryPerformanceCounter(&Frequency);
    return (ULONG)((Now.QuadPart - Start.QuadPart) * 1000000 / Frequency.QuadPart);
}

/* ---- TCP over the raw API (every lwIP call under the core lock; the callbacks run with it held) ---- */

typedef struct _ST_CONN
{
    KEVENT Done;
    struct tcp_pcb *Pcb;
    ULONG Want;         /* bytes to send */
    ULONG Sent;
    ULONG Got;          /* bytes received back (echo) or by the server (stream) */
    ULONG Sum;          /* sum of the received bytes */
    BOOLEAN Echo;       /* the server sends everything back */
    BOOLEAN Connected;
    BOOLEAN Failed;
    err_t Error;
    ULONG Accepted;
} ST_CONN, *PST_CONN;

static ST_CONN StServer;

static err_t
StServerRecv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    struct pbuf *q;
    u16_t i;

    if (!p)
    {
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_close(pcb);
        return ERR_OK;
    }
    for (q = p; q; q = q->next)
    {
        for (i = 0; i < q->len; i++)
            StServer.Sum += ((PUCHAR)q->payload)[i];
        if (StServer.Echo)
            tcp_write(pcb, q->payload, q->len, TCP_WRITE_FLAG_COPY);
    }
    StServer.Got += p->tot_len;
    if (StServer.Echo)
        tcp_output(pcb);
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void
StServerError(void *arg, err_t err)
{
}

static err_t
StServerAccept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    if (!newpcb || err != ERR_OK)
        return ERR_VAL;
    StServer.Accepted++;
    tcp_recv(newpcb, StServerRecv);
    tcp_err(newpcb, StServerError);
    return ERR_OK;
}

/* Sends what fits of the rest of the data (core lock held) */
static VOID
StPump(PST_CONN T, struct tcp_pcb *pcb)
{
    while (T->Sent < T->Want)
    {
        /* The byte at stream offset n is StPattern[n % sizeof(StPattern)] (StExpectedSum) */
        ULONG Offset = T->Sent % sizeof(StPattern);
        ULONG Piece = min(T->Want - T->Sent, sizeof(StPattern) - Offset);
        Piece = min(Piece, tcp_sndbuf(pcb));
        if (Piece == 0 || tcp_write(pcb, StPattern + Offset, (u16_t)Piece, TCP_WRITE_FLAG_COPY) != ERR_OK)
            break;
        T->Sent += Piece;
    }
    tcp_output(pcb);
}

static err_t
StClientSent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    PST_CONN T = arg;

    StPump(T, pcb);
    /* A stream is done once the server has everything (StWait looks at StServer.Got) */
    return ERR_OK;
}

static err_t
StClientConnected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    PST_CONN T = arg;

    T->Connected = TRUE;
    StPump(T, pcb);
    return ERR_OK;
}

static err_t
StClientRecv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    PST_CONN T = arg;
    struct pbuf *q;
    u16_t i;

    if (!p)
    {
        T->Failed = T->Got < T->Want;
        KeSetEvent(&T->Done, IO_NO_INCREMENT, FALSE);
        return ERR_OK;
    }
    for (q = p; q; q = q->next)
        for (i = 0; i < q->len; i++)
            T->Sum += ((PUCHAR)q->payload)[i];
    T->Got += p->tot_len;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    if (T->Got >= T->Want)
        KeSetEvent(&T->Done, IO_NO_INCREMENT, FALSE);
    return ERR_OK;
}

static void
StClientError(void *arg, err_t err)
{
    PST_CONN T = arg;

    T->Pcb = NULL; /* lwIP freed it */
    T->Failed = TRUE;
    T->Error = err;
    KeSetEvent(&T->Done, IO_NO_INCREMENT, FALSE);
}

static ULONG
StExpectedSum(ULONG Bytes)
{
    ULONG Sum = 0, i;

    for (i = 0; i < Bytes; i++)
        Sum += StPattern[i % sizeof(StPattern)];
    return Sum;
}

/* A connection from a new PCB to Dest:Port; with Listen, a server on ListenAddr:Port first. Echo: the
 * server sends back what it gets and the client waits for all of it; else the client streams Bytes and waits
 * until the server has them */
static BOOLEAN
StTransferEx(const char *Name, const ip_addr_t *ListenAddr, const ip_addr_t *Dest, u16_t Port, BOOLEAN Echo,
             ULONG Bytes, ULONG TimeoutMs, BOOLEAN ExpectRefused)
{
    ST_CONN T;
    struct tcp_pcb *Listener = NULL, *Client, *Pcb;
    LARGE_INTEGER Start, Timeout;
    ULONG Waited, Us;
    err_t Result;
    BOOLEAN Ok;
    CHAR Detail[160];

    RtlZeroMemory(&T, sizeof(T));
    KeInitializeEvent(&T.Done, NotificationEvent, FALSE);
    T.Want = Bytes;
    T.Echo = Echo;

    LOCK_TCPIP_CORE();
    RtlZeroMemory(&StServer, sizeof(StServer));
    StServer.Echo = Echo;
    if (ListenAddr)
    {
        Pcb = tcp_new_ip_type(IP_GET_TYPE(ListenAddr));
        if (!Pcb || tcp_bind(Pcb, ListenAddr, Port) != ERR_OK || !(Listener = tcp_listen(Pcb)))
        {
            if (Pcb && !Listener)
                tcp_close(Pcb);
            UNLOCK_TCPIP_CORE();
            StResult(FALSE, Name, "listener setup failed");
            return FALSE;
        }
        tcp_accept(Listener, StServerAccept);
    }
    Client = tcp_new_ip_type(IP_GET_TYPE(Dest));
    if (!Client)
    {
        if (Listener)
            tcp_close(Listener);
        UNLOCK_TCPIP_CORE();
        StResult(FALSE, Name, "no PCB");
        return FALSE;
    }
    T.Pcb = Client;
    tcp_arg(Client, &T);
    tcp_recv(Client, StClientRecv);
    tcp_sent(Client, StClientSent);
    tcp_err(Client, StClientError);
    Start = KeQueryPerformanceCounter(NULL);
    Result = tcp_connect(Client, Dest, Port, StClientConnected);
    UNLOCK_TCPIP_CORE();

    if (Result != ERR_OK)
    {
        T.Failed = TRUE;
        T.Error = Result;
    }
    else if (Echo)
    {
        Timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000;
        if (KeWaitForSingleObject(&T.Done, Executive, KernelMode, FALSE, &Timeout) == STATUS_TIMEOUT)
            T.Failed = TRUE;
    }
    else
    {
        for (Waited = 0; Waited < TimeoutMs && !T.Failed && StServer.Got < Bytes; Waited += 10)
            StSleep(10);
        if (StServer.Got < Bytes)
            T.Failed = TRUE;
    }
    Us = StMicroseconds(Start);

    LOCK_TCPIP_CORE();
    if (T.Pcb)
    {
        tcp_arg(T.Pcb, NULL);
        tcp_recv(T.Pcb, NULL);
        tcp_sent(T.Pcb, NULL);
        tcp_err(T.Pcb, NULL);
        if (tcp_close(T.Pcb) != ERR_OK)
            tcp_abort(T.Pcb);
    }
    if (Listener)
        tcp_close(Listener);
    UNLOCK_TCPIP_CORE();

    if (Echo)
        Ok = !T.Failed && T.Got == Bytes && T.Sum == StExpectedSum(Bytes);
    else
        Ok = !T.Failed && StServer.Got == Bytes && StServer.Sum == StExpectedSum(Bytes);
    /* A connection to a closed port fails at once with a reset (ERR_RST), not by its timeout */
    if (ExpectRefused)
        Ok = T.Failed && !T.Connected && T.Error == ERR_RST && Us < 1000000;
    _snprintf(Detail, sizeof(Detail), "connected=%d sent=%lu got=%lu accepted=%lu in %lu us (err %d)",
              (int)T.Connected, T.Sent, Echo ? T.Got : StServer.Got, StServer.Accepted, Us, (int)T.Error);
    StResult(Ok, Name, Detail);
    return Ok;
}

static BOOLEAN
StTransfer(const char *Name, const ip_addr_t *ListenAddr, const ip_addr_t *Dest, u16_t Port, BOOLEAN Echo,
           ULONG Bytes, ULONG TimeoutMs)
{
    return StTransferEx(Name, ListenAddr, Dest, Port, Echo, Bytes, TimeoutMs, FALSE);
}

/* ---- interfaces ---- */

static PIP_INTERFACE
StFindEthernet(VOID)
{
    PIP_INTERFACE Found = NULL;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);
    for (Entry = InterfaceListHead.Flink; Entry != &InterfaceListHead; Entry = Entry->Flink)
    {
        PIP_INTERFACE IF = CONTAINING_RECORD(Entry, IP_INTERFACE, ListEntry);

        if (IF != Loopback && IF->TCPContext && IF->AddressLength == 6 &&
            netif_is_link_up((struct netif *)IF->TCPContext))
        {
            IPReferenceInterface(IF);
            Found = IF;
            break;
        }
    }
    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);
    return Found;
}

static VOID
StDescribeAddresses(struct netif *netif, const char *Name)
{
    CHAR Text[IP6ADDR_STRLEN_MAX];
    s8_t i;

    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        if (netif_ip6_addr_state(netif, i) != IP6_ADDR_INVALID)
        {
            ip6addr_ntoa_r(netif_ip6_addr(netif, i), Text, sizeof(Text));
            StPrint("%s address %d %s state 0x%x", Name, (int)i, Text, (UINT)netif_ip6_addr_state(netif, i));
        }
    }
}

/* ---- multicast reception ---- */

static BOOLEAN
StListHas(const UCHAR *List, UINT Count, const UCHAR *Address)
{
    UINT i;

    for (i = 0; i < Count; i++)
    {
        if (RtlCompareMemory(List + i * 6, Address, 6) == 6)
            return TRUE;
    }
    return FALSE;
}

/* The adapter's multicast list (what lan.c asked for, what the miniport says it has) and packet filter: the
 * all-nodes group and the solicited-node group of the link-local address, or all multicast as the fallback;
 * never promiscuous */
static VOID
StTestMulticastList(PIP_INTERFACE Eth, const ip_addr_t *LinkLocal)
{
    PLAN_ADAPTER Adapter = Eth->Context;
    UCHAR AllNodes[6] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 };
    UCHAR Solicited[6] = { 0x33, 0x33, 0xff, 0, 0, 0 };
    UCHAR List[LL_MULTICAST_MAX * 6], Miniport[32 * 6];
    const u8_t *Ll = (const u8_t *)ip_2_ip6(LinkLocal)->addr;
    BOOLEAN Applied = FALSE, Ok;
    UINT Count = 0, Asked = 0, Filter = 0, i;
    NDIS_STATUS Status;
    ULONG Length = 0;
    KIRQL OldIrql;
    CHAR Detail[200];

    if (!Eth->SetMulticast || !Adapter)
    {
        StResult(FALSE, "adapter multicast list", "not a LAN adapter");
        return;
    }

    Solicited[3] = Ll[13];
    Solicited[4] = Ll[14];
    Solicited[5] = Ll[15];

    /* The list goes to the adapter on a work item */
    for (i = 0; i < 50 && !Applied; i++)
    {
        TcpipAcquireSpinLock(&Adapter->ReconfigureLock, &OldIrql);
        Applied = Adapter->McastWanted && !Adapter->McastChanged && !Adapter->McastQueued;
        Asked = Adapter->McastCount;
        Count = min(Asked, LL_MULTICAST_MAX);
        RtlCopyMemory(List, Adapter->McastList, Count * 6);
        TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);
        if (!Applied)
            StSleep(100);
    }

    for (i = 0; i < Count; i++)
        StPrint("multicast list asked [%u] %02x-%02x-%02x-%02x-%02x-%02x", i, List[i * 6], List[i * 6 + 1],
                List[i * 6 + 2], List[i * 6 + 3], List[i * 6 + 4], List[i * 6 + 5]);

    Status = NDISCall(Adapter, NdisRequestQueryInformation, OID_GEN_CURRENT_PACKET_FILTER, &Filter, sizeof(Filter));
    if (Status != NDIS_STATUS_SUCCESS)
        Filter = Adapter->McastFilter ? Adapter->McastFilter : Adapter->PacketFilter;

    RtlZeroMemory(Miniport, sizeof(Miniport));
    if (NDISCall(Adapter, NdisRequestQueryInformation, OID_802_3_MULTICAST_LIST, Miniport, sizeof(Miniport)) ==
        NDIS_STATUS_SUCCESS)
    {
        for (i = 0; i < sizeof(Miniport) / 6 && (Miniport[i * 6] | Miniport[i * 6 + 1]); i++)
            Length++;
        StPrint("miniport says its multicast list has %lu: all-nodes %d, solicited-node %d", Length,
                (int)StListHas(Miniport, Length, AllNodes), (int)StListHas(Miniport, Length, Solicited));
    }
    else
    {
        StPrint("miniport does not answer OID_802_3_MULTICAST_LIST queries");
    }

    Ok = Applied && !(Filter & NDIS_PACKET_TYPE_PROMISCUOUS) &&
         ((Filter & NDIS_PACKET_TYPE_ALL_MULTICAST) ||
          ((Filter & NDIS_PACKET_TYPE_MULTICAST) && StListHas(List, Count, AllNodes) && StListHas(List, Count, Solicited)));
    _snprintf(Detail, sizeof(Detail), "applied=%d entries=%u%s filter 0x%x (filter query 0x%lx, max list %lu)%s",
              (int)Applied, Count, Asked > LL_MULTICAST_MAX ? " (more asked for)" : "", Filter, Status, Adapter->McastMaxList,
              (Filter & NDIS_PACKET_TYPE_ALL_MULTICAST) ? " FALLBACK all multicast" : " list");
    StResult(Ok, "adapter multicast list: all-nodes + solicited-node, not promiscuous", Detail);
}

static VOID
StPrintReceived(const char *When)
{
    StPrint("%s: received NS to multicast %ld, NS unicast %ld, RA to multicast %ld, RA unicast %ld, echo requests %ld",
            When, TCP6ReceivedIcmp[TCP6_RX_NS_MULTICAST], TCP6ReceivedIcmp[TCP6_RX_NS_UNICAST],
            TCP6ReceivedIcmp[TCP6_RX_RA_MULTICAST], TCP6ReceivedIcmp[TCP6_RX_RA_UNICAST],
            TCP6ReceivedIcmp[TCP6_RX_ECHO_REQUEST]);
}

/* The test host pings our link-local address with its neighbour cache flushed: its solicitation goes to our
 * solicited-node group, and only multicast reception lets it in */
static VOID
StTestInbound(ULONG Seconds)
{
    LONG Ns0 = TCP6ReceivedIcmp[TCP6_RX_NS_MULTICAST], Echo0 = TCP6ReceivedIcmp[TCP6_RX_ECHO_REQUEST];
    LONG Ns = 0, Echo = 0;
    ULONG i;
    CHAR Detail[96];

    StPrint("waiting up to %lu s for the host's solicitation and echo requests", Seconds);
    for (i = 0; i < Seconds * 10; i++)
    {
        Ns = TCP6ReceivedIcmp[TCP6_RX_NS_MULTICAST] - Ns0;
        Echo = TCP6ReceivedIcmp[TCP6_RX_ECHO_REQUEST] - Echo0;
        if (Ns >= 3 && Echo >= 3)
            break;
        StSleep(100);
    }
    StPrintReceived("after the inbound wait");
    _snprintf(Detail, sizeof(Detail), "%ld multicast solicitations, %ld echo requests in %lu ms", Ns, Echo, i * 100);
    /* The host sends its echo request only after our answer to its multicast solicitation */
    StResult(Ns >= 1 && Echo >= 1, "inbound: the host's multicast solicitation (cold cache) arrived and its ping was answered", Detail);
}

/* A router advertisement to all-nodes (multicast) gives a prefix: lwIP forms an address from it */
static BOOLEAN
StTestSlaac(struct netif *En, ULONG Seconds, ip_addr_t *Slaac)
{
    BOOLEAN Found = FALSE;
    CHAR Text[IP6ADDR_STRLEN_MAX], Detail[160];
    ULONG i;
    s8_t j;

    for (i = 0; i < Seconds * 10 && !Found; i++)
    {
        LOCK_TCPIP_CORE();
        for (j = 1; j < LWIP_IPV6_NUM_ADDRESSES && !Found; j++)
        {
            if (ip6_addr_ispreferred(netif_ip6_addr_state(En, j)) && !ip6_addr_islinklocal(netif_ip6_addr(En, j)))
            {
                ip_addr_copy_from_ip6(*Slaac, *netif_ip6_addr(En, j));
                Found = TRUE;
            }
        }
        UNLOCK_TCPIP_CORE();
        if (!Found)
            StSleep(100);
    }

    LOCK_TCPIP_CORE();
    StDescribeAddresses(En, "ethernet after the router advertisement wait");
    UNLOCK_TCPIP_CORE();
    StPrintReceived("after the router advertisement wait");
    if (Found)
        ip6addr_ntoa_r(ip_2_ip6(Slaac), Text, sizeof(Text));
    else
        RtlCopyMemory(Text, "none", sizeof("none"));
    _snprintf(Detail, sizeof(Detail), "%s after about %lu ms; router advertisements to multicast %ld, unicast %ld",
              Text, i * 100, TCP6ReceivedIcmp[TCP6_RX_RA_MULTICAST], TCP6ReceivedIcmp[TCP6_RX_RA_UNICAST]);
    StResult(Found && TCP6ReceivedIcmp[TCP6_RX_RA_MULTICAST] > 0,
             "SLAAC: a multicast router advertisement arrived and an address was formed and passed DAD", Detail);
    return Found;
}

static BOOLEAN
StReadAddress(PCWSTR Name, struct netif *En, ip_addr_t *Address, CHAR *Text, ULONG TextSize)
{
    WCHAR W[64];
    ULONG i;

    RtlZeroMemory(W, sizeof(W));
    if (!StReadValue(Name, REG_SZ, W, sizeof(W) - sizeof(WCHAR)))
        return FALSE;
    for (i = 0; i + 1 < TextSize && W[i]; i++)
        Text[i] = (CHAR)W[i];
    Text[i] = 0;
    if (!ip6addr_aton(Text, ip_2_ip6(Address)))
        return FALSE;
    IP_SET_TYPE_VAL(*Address, IPADDR_TYPE_V6);
    ip6_addr_assign_zone(ip_2_ip6(Address), IP6_UNICAST, En);
    return TRUE;
}

/* ---- connection requests from the wire: crafted datagrams into the receive path, through the firewall ---- */

static struct tcp_pcb *
StFindSynReceived(u16_t Port)
{
    struct tcp_pcb *pcb;

    for (pcb = tcp_active_pcbs; pcb; pcb = pcb->next)
    {
        if (pcb->local_port == Port && pcb->state == SYN_RCVD && IP_IS_V6_VAL(pcb->remote_ip))
            return pcb;
    }
    return NULL;
}

/* A SYN from Src (an address on the link) to Dest:Port, as a datagram fresh from the adapter */
static struct pbuf *
StMakeSyn(const ip6_addr_t *Src, const ip6_addr_t *Dest, u16_t Port)
{
    struct pbuf *p;
    PUCHAR Ip, Tcp;
    u16_t Sum;

    p = pbuf_alloc(PBUF_RAW, 60, PBUF_RAM);
    if (!p)
        return NULL;
    Ip = p->payload;
    RtlZeroMemory(Ip, 60);
    Ip[0] = 0x60;
    Ip[5] = 20;     /* payload length */
    Ip[6] = 6;      /* TCP */
    Ip[7] = 64;
    RtlCopyMemory(Ip + 8, Src->addr, 16);
    RtlCopyMemory(Ip + 24, Dest->addr, 16);
    Tcp = Ip + 40;
    Tcp[0] = 0xC3; Tcp[1] = 0x51;               /* source port 50001 */
    Tcp[2] = (UCHAR)(Port >> 8); Tcp[3] = (UCHAR)Port;
    Tcp[4] = 0x12; Tcp[5] = 0x34; Tcp[6] = 0x56; Tcp[7] = 0x78;
    Tcp[12] = 5 << 4;
    Tcp[13] = 0x02;                             /* SYN */
    Tcp[14] = 0xFF; Tcp[15] = 0xFF;

    pbuf_remove_header(p, 40);
    Sum = ip6_chksum_pseudo(p, IP6_NEXTH_TCP, 20, Src, Dest);
    pbuf_add_header(p, 40);
    RtlCopyMemory(Tcp + 16, &Sum, 2);
    return p;
}

/* ---- the firewall (NitroFwInboundAllowed6) and the ICMPv6 error rate limit: crafted datagrams into the
   receive path (TCPInput6), under a policy of the test's own (NitroFwTestSetPolicy) ---- */

#define ST_PORT_ALLOWED_TCP  40640
#define ST_PORT_BLOCKED_TCP  40641
#define ST_PORT_ALLOWED_UDP  40650
#define ST_PORT_BLOCKED_UDP  40649
#define ST_ICMP_BURST        10
#define ST_ICMP_RATE         10

/* A datagram of Nh with Payload (Len bytes) from Src to Dest, hop limit Hop, as it arrives from the adapter */
static struct pbuf *
StPacket(const ip6_addr_t *Src, const ip6_addr_t *Dest, UCHAR Nh, UCHAR Hop, const UCHAR *Payload, UINT Len)
{
    struct pbuf *p;
    PUCHAR Ip;

    p = pbuf_alloc(PBUF_RAW, (u16_t)(40 + Len), PBUF_RAM);
    if (!p)
        return NULL;
    Ip = p->payload;
    RtlZeroMemory(Ip, 40);
    Ip[0] = 0x60;
    Ip[4] = (UCHAR)(Len >> 8);
    Ip[5] = (UCHAR)Len;
    Ip[6] = Nh;
    Ip[7] = Hop;
    RtlCopyMemory(Ip + 8, Src->addr, 16);
    RtlCopyMemory(Ip + 24, Dest->addr, 16);
    if (Len)
        RtlCopyMemory(Ip + 40, Payload, Len);
    return p;
}

/* An ICMPv6 message of Type, Code and a zero body, Length bytes in all (the checksum is not set: what is
   passed to lwIP is dropped there, which is all these tests need) */
static struct pbuf *
StIcmp(const ip6_addr_t *Src, const ip6_addr_t *Dest, UCHAR Type, UCHAR Code, UCHAR Hop, UINT Length)
{
    UCHAR Body[96];

    RtlZeroMemory(Body, sizeof(Body));
    Body[0] = Type;
    Body[1] = Code;
    return StPacket(Src, Dest, 58, Hop, Body, Length);
}

static VOID
StTcpHeader(PUCHAR Tcp, u16_t SrcPort, u16_t DstPort, UCHAR Flags)
{
    RtlZeroMemory(Tcp, 20);
    Tcp[0] = (UCHAR)(SrcPort >> 8); Tcp[1] = (UCHAR)SrcPort;
    Tcp[2] = (UCHAR)(DstPort >> 8); Tcp[3] = (UCHAR)DstPort;
    Tcp[4] = 0x12; Tcp[5] = 0x34; Tcp[6] = 0x56; Tcp[7] = 0x78;
    Tcp[12] = 5 << 4;
    Tcp[13] = Flags;
    Tcp[14] = 0xFF; Tcp[15] = 0xFF;
}

/* A UDP datagram header (8 bytes, no payload, checksum not set) */
static struct pbuf *
StUdp(const ip6_addr_t *Src, const ip6_addr_t *Dest, u16_t DstPort)
{
    UCHAR Udp[8];

    RtlZeroMemory(Udp, sizeof(Udp));
    Udp[0] = 0xC3; Udp[1] = 0x52;
    Udp[2] = (UCHAR)(DstPort >> 8); Udp[3] = (UCHAR)DstPort;
    Udp[5] = 8;
    return StPacket(Src, Dest, 17, 64, Udp, sizeof(Udp));
}

/* Hands p to the receive path as from the adapter; TRUE when the firewall dropped it */
static BOOLEAN
StInject(PIP_INTERFACE IF, struct pbuf *p, BOOLEAN FromOwnLink)
{
    LONG Before = TCP6FilterDropped;

    if (!p)
        return FALSE;
    TCPInput6(IF, p, FromOwnLink);
    return TCP6FilterDropped == Before + 1;
}

static VOID
StRule(PUCHAR Rule, UCHAR Protocol, u16_t Port)
{
    PNITROFW_RULE R = (PNITROFW_RULE)Rule;
    PNITROFW_PORT_RANGE Range = (PNITROFW_PORT_RANGE)(Rule + sizeof(NITROFW_RULE));

    RtlZeroMemory(Rule, sizeof(NITROFW_RULE) + 8);
    R->Size = sizeof(NITROFW_RULE) + 8;
    R->Action = NITROFW_ACTION_ALLOW;
    R->Direction = NITROFW_DIR_IN;
    R->Protocol = Protocol;
    R->ProfileMask = NITROFW_PROFILE_ALL;
    R->IfTypes = NITROFW_IFTYPE_ALL;
    R->LocalPortCount = 1;
    R->LocalPortOffset = sizeof(NITROFW_RULE);
    Range->Low = Range->High = Port;
}

/* All profiles on, default inbound Block, drops logged; Allow TCP to ST_PORT_ALLOWED_TCP and UDP to
   ST_PORT_ALLOWED_UDP */
static BOOLEAN
StInstallPolicy(VOID)
{
    UCHAR Blob[sizeof(NITROFW_POLICY) + 2 * (sizeof(NITROFW_RULE) + 8)];
    PNITROFW_POLICY Policy = (PNITROFW_POLICY)Blob;
    ULONG i;

    RtlZeroMemory(Blob, sizeof(Blob));
    Policy->Magic = NITROFW_POLICY_MAGIC;
    Policy->AbiVersion = NITROFW_ABI_VERSION;
    Policy->TotalSize = sizeof(Blob);
    Policy->Flags = NITROFW_POLICY_ENFORCE;
    Policy->Generation = 1;
    Policy->ActiveProfiles = NITROFW_PROFILE_ALL;
    Policy->RuleCount = 2;
    Policy->RulesOffset = sizeof(NITROFW_POLICY);
    for (i = 0; i < NITROFW_PROFILE_COUNT; i++)
    {
        Policy->Profile[i].Flags = NITROFW_PROFILE_ENABLED | NITROFW_PROFILE_LOG_DROPPED;
        Policy->Profile[i].DefaultInbound = NITROFW_ACTION_BLOCK;
        Policy->Profile[i].DefaultOutbound = NITROFW_ACTION_ALLOW;
    }
    StRule(Blob + sizeof(NITROFW_POLICY), IPPROTO_TCP, ST_PORT_ALLOWED_TCP);
    StRule(Blob + sizeof(NITROFW_POLICY) + sizeof(NITROFW_RULE) + 8, IPPROTO_UDP, ST_PORT_ALLOWED_UDP);
    return NT_SUCCESS(NitroFwTestSetPolicy(Blob, sizeof(Blob)));
}

static UCHAR StDropLogBuffer[sizeof(NITROFW_DROPLOG) + 32 * sizeof(NITROFW_DROP_RECORD)];

/* The newest drop log record, or NULL */
static PNITROFW_DROP_RECORD
StLastDrop(VOID)
{
    PNITROFW_DROPLOG Log = (PNITROFW_DROPLOG)StDropLogBuffer;
    PNITROFW_DROP_RECORD Records = (PNITROFW_DROP_RECORD)(Log + 1);

    if (!NT_SUCCESS(NitroFwTestGetDropLog(0, StDropLogBuffer, sizeof(StDropLogBuffer))) || !Log->Count)
        return NULL;
    /* the first 32 of the ring from the oldest: ask again from the newest sequence */
    if (!NT_SUCCESS(NitroFwTestGetDropLog(Log->NextSequence - 1, StDropLogBuffer, sizeof(StDropLogBuffer))) ||
        !Log->Count)
        return NULL;
    return &Records[Log->Count - 1];
}

static err_t
StNopConnected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    return ERR_OK;
}

static BOOLEAN
StDropped(PIP_INTERFACE IF, struct pbuf *p, BOOLEAN FromOwnLink, const char *Name, BOOLEAN WantDropped)
{
    BOOLEAN Dropped = StInject(IF, p, FromOwnLink);

    StResult(p && Dropped == WantDropped, Name, WantDropped ? "(dropped)" : "(passed)");
    return Dropped;
}

static VOID
StTestFirewall6(PIP_INTERFACE IF, const ip_addr_t *Local, u16_t Port)
{
    struct tcp_pcb *Pcb, *ListenerBlocked = NULL, *ListenerAllowed = NULL, *Half;
    ip6_addr_t Peer, Global, Router;
    const ip6_addr_t *Dest = ip_2_ip6(Local);
    struct pbuf *p;
    PNITROFW_DROP_RECORD Last;
    LONG64 DropBefore, PassBefore, DropAfter, PassAfter;
    BOOLEAN Dropped, Taken;
    CHAR Detail[160];
    UCHAR Payload[64];
    LONG SentBefore, LimitedBefore, SentDelta, LimitedDelta;
    LARGE_INTEGER Start;
    ULONG Micro, i;

    ip6addr_aton("fe80::5eed:1", &Peer);
    ip6addr_aton("fe80::5eed:2", &Router);
    ip6addr_aton("2001:db8::5eed", &Global);

    if (!StInstallPolicy())
    {
        StResult(FALSE, "firewall test policy installed", NULL);
        return;
    }
    StResult(TRUE, "firewall test policy installed", "(default block, allow TCP 40640 and UDP 40650)");

    LOCK_TCPIP_CORE();
    Pcb = tcp_new_ip_type(IPADDR_TYPE_V6);
    if (Pcb && tcp_bind(Pcb, Local, ST_PORT_BLOCKED_TCP) == ERR_OK)
        ListenerBlocked = tcp_listen(Pcb);
    else if (Pcb)
        tcp_close(Pcb);
    if (ListenerBlocked)
        tcp_accept(ListenerBlocked, StServerAccept);
    Pcb = tcp_new_ip_type(IPADDR_TYPE_V6);
    if (Pcb && tcp_bind(Pcb, Local, ST_PORT_ALLOWED_TCP) == ERR_OK)
        ListenerAllowed = tcp_listen(Pcb);
    else if (Pcb)
        tcp_close(Pcb);
    if (ListenerAllowed)
        tcp_accept(ListenerAllowed, StServerAccept);
    UNLOCK_TCPIP_CORE();
    if (!ListenerBlocked || !ListenerAllowed)
    {
        StResult(FALSE, "firewall test listeners", "listener setup failed");
        goto cleanup;
    }

    /* an unsolicited connection request to a listener no rule admits: dropped before lwIP, no half-open
       connection, no answer, one drop log record with the IPv6 addresses */
    NitroFwTestCounters(&DropBefore, &PassBefore);
    p = StMakeSyn(&Peer, Dest, ST_PORT_BLOCKED_TCP);
    Dropped = StInject(IF, p, FALSE);
    LOCK_TCPIP_CORE();
    Taken = StFindSynReceived(ST_PORT_BLOCKED_TCP) != NULL;
    UNLOCK_TCPIP_CORE();
    Last = StLastDrop();
    _snprintf(Detail, sizeof(Detail), "dropped=%d half-open=%d log: %s proto %d dport %d reason %d", (int)Dropped, (int)Taken,
              Last && (Last->Flags & NITROFW_DROP_F_IPV6) ? "ipv6" : "?", Last ? Last->Protocol : -1,
              Last ? Last->DstPort : -1, Last ? Last->Reason : -1);
    StResult(p && Dropped && !Taken && Last && (Last->Flags & NITROFW_DROP_F_IPV6) && Last->Protocol == 6 &&
             Last->DstPort == ST_PORT_BLOCKED_TCP && Last->SrcPort == 50001 && Last->Reason == NITROFW_DROP_DEFAULT &&
             RtlCompareMemory(Last->SrcAddr6, Peer.addr, 16) == 16 && RtlCompareMemory(Last->DstAddr6, Dest->addr, 16) == 16 &&
             Last->SrcAddr == 0 && Last->DstAddr == 0,
             "unsolicited SYN to an IPv6 listener without a rule dropped and logged", Detail);

    /* a rule admits the port: the request reaches the listener */
    p = StMakeSyn(&Peer, Dest, ST_PORT_ALLOWED_TCP);
    Dropped = StInject(IF, p, FALSE);
    LOCK_TCPIP_CORE();
    Half = StFindSynReceived(ST_PORT_ALLOWED_TCP);
    Taken = Half != NULL;
    if (Half)
        tcp_abort(Half);
    UNLOCK_TCPIP_CORE();
    StResult(p && !Dropped && Taken, "SYN to a rule-allowed port passes to the listener", NULL);

    /* the control: the request our own send path looped back (source one of our addresses) is taken */
    p = StMakeSyn(Dest, Dest, ST_PORT_BLOCKED_TCP);
    Dropped = StInject(IF, p, TRUE);
    LOCK_TCPIP_CORE();
    Half = StFindSynReceived(ST_PORT_BLOCKED_TCP);
    Taken = Half != NULL;
    if (Half)
        tcp_abort(Half);
    UNLOCK_TCPIP_CORE();
    StResult(p && !Dropped && Taken, "own-link SYN to an IPv6 listener taken (control)", NULL);

    /* the same SYN with our address as source but not tagged as looped back: a spoof from the wire, dropped */
    p = StMakeSyn(Dest, Dest, ST_PORT_BLOCKED_TCP);
    Dropped = StInject(IF, p, FALSE);
    LOCK_TCPIP_CORE();
    Taken = StFindSynReceived(ST_PORT_BLOCKED_TCP) != NULL;
    UNLOCK_TCPIP_CORE();
    StResult(p && Dropped && !Taken, "SYN from the wire with our own source address dropped", NULL);

    /* ::1 never arrives on a link */
    {
        ip6_addr_t Loop;

        ip6_addr_set_loopback(&Loop);
        p = StMakeSyn(&Loop, Dest, ST_PORT_ALLOWED_TCP);
        StDropped(IF, p, FALSE, "SYN from ::1 on a link dropped, even to an allowed port", TRUE);
    }

    /* a segment of an established connection (no SYN) is not a request: it passes (the stack answers it) */
    StTcpHeader(Payload, 50001, ST_PORT_BLOCKED_TCP, 0x10);
    p = StPacket(&Peer, Dest, 6, 64, Payload, 20);
    StDropped(IF, p, FALSE, "TCP ACK segment passes (belongs to a connection or gets a reset)", FALSE);

    /* UDP: unsolicited dropped and logged, a rule-allowed port passes */
    p = StUdp(&Peer, Dest, ST_PORT_BLOCKED_UDP);
    Dropped = StInject(IF, p, FALSE);
    Last = StLastDrop();
    StResult(p && Dropped && Last && Last->Protocol == 17 && Last->DstPort == ST_PORT_BLOCKED_UDP &&
             Last->Reason == NITROFW_DROP_DEFAULT && (Last->Flags & NITROFW_DROP_F_IPV6),
             "unsolicited UDP over IPv6 dropped and logged", NULL);

    /* neighbour discovery with what RFC 4861 7.1 requires passes */
    StDropped(IF, StIcmp(&Peer, Dest, 135, 0, 255, 24), FALSE, "neighbour solicitation (hop limit 255) passes", FALSE);
    StDropped(IF, StIcmp(&Peer, Dest, 136, 0, 255, 24), FALSE, "neighbour advertisement (hop limit 255) passes", FALSE);
    StDropped(IF, StIcmp(&Peer, Dest, 133, 0, 255, 8), FALSE, "router solicitation (hop limit 255) passes", FALSE);
    StDropped(IF, StIcmp(&Router, Dest, 134, 0, 255, 16), FALSE, "router advertisement from a link-local source passes", FALSE);
    StDropped(IF, StIcmp(&Router, Dest, 137, 0, 255, 40), FALSE, "redirect from a link-local source passes", FALSE);
    {
        ip6_addr_t Unspec;

        ip6_addr_set_zero(&Unspec);
        StDropped(IF, StIcmp(&Unspec, Dest, 135, 0, 255, 24), FALSE, "neighbour solicitation from :: (DAD) passes", FALSE);
    }
    StDropped(IF, StIcmp(&Router, Dest, 130, 0, 1, 24), FALSE, "MLD query (hop limit 1, link-local source) passes", FALSE);

    /* and what it forbids does not */
    StDropped(IF, StIcmp(&Peer, Dest, 135, 0, 64, 24), FALSE, "neighbour solicitation with hop limit 64 dropped", TRUE);
    Last = StLastDrop();
    StResult(Last && Last->Protocol == 58 && Last->IcmpType == 135 && Last->Reason == NITROFW_DROP_V6_INVALID,
             "...and logged as invalid", NULL);
    StDropped(IF, StIcmp(&Global, Dest, 134, 0, 255, 16), FALSE, "router advertisement from a global source dropped", TRUE);
    StDropped(IF, StIcmp(&Router, Dest, 134, 0, 254, 16), FALSE, "router advertisement with hop limit 254 dropped", TRUE);
    StDropped(IF, StIcmp(&Global, Dest, 137, 0, 255, 40), FALSE, "redirect from a global source dropped", TRUE);
    StDropped(IF, StIcmp(&Global, Dest, 130, 0, 1, 24), FALSE, "MLD query from a global source dropped", TRUE);

    /* ICMPv6 echo: a request is unsolicited (default block), a reply passes */
    StDropped(IF, StIcmp(&Peer, Dest, 128, 0, 64, 8), FALSE, "ICMPv6 echo request dropped (default block)", TRUE);
    StDropped(IF, StIcmp(&Peer, Dest, 129, 0, 64, 8), FALSE, "ICMPv6 echo reply passes", FALSE);

    /* extension headers: the walk finds the transport header behind them; a first fragment is judged, later
       fragments pass, a first fragment too short to judge does not */
    {
        UCHAR Chain[8 + 20];

        RtlZeroMemory(Chain, sizeof(Chain));
        Chain[0] = 6;           /* hop-by-hop: next header TCP, length 8 bytes */
        Chain[2] = 1; Chain[3] = 4;     /* PadN of 4 */
        StTcpHeader(Chain + 8, 50001, ST_PORT_BLOCKED_TCP, 0x02);
        p = StPacket(&Peer, Dest, 0, 64, Chain, sizeof(Chain));
        StDropped(IF, p, FALSE, "SYN behind a hop-by-hop header dropped", TRUE);
    }
    {
        UCHAR Frag[8 + 20];

        RtlZeroMemory(Frag, sizeof(Frag));
        Frag[0] = 6;
        Frag[3] = 0x01;         /* offset 0, more fragments */
        Frag[7] = 1;
        StTcpHeader(Frag + 8, 50001, ST_PORT_BLOCKED_TCP, 0x02);
        p = StPacket(&Peer, Dest, 44, 64, Frag, sizeof(Frag));
        StDropped(IF, p, FALSE, "first fragment holding a SYN dropped", TRUE);

        Frag[2] = 0; Frag[3] = 0x09;    /* offset 8, more fragments */
        p = StPacket(&Peer, Dest, 44, 64, Frag, sizeof(Frag));
        StDropped(IF, p, FALSE, "later fragment passes (reassembly decides)", FALSE);

        Frag[2] = 0; Frag[3] = 0x01;
        p = StPacket(&Peer, Dest, 44, 64, Frag, 8 + 8);
        StDropped(IF, p, FALSE, "first fragment too short to judge dropped", TRUE);
        Last = StLastDrop();
        StResult(Last && Last->Reason == NITROFW_DROP_V6_INVALID, "...and logged as invalid", NULL);
    }
    {
        UCHAR Chain[8];

        RtlZeroMemory(Chain, sizeof(Chain));
        Chain[1] = 200;         /* a header longer than the datagram */
        p = StPacket(&Peer, Dest, 0, 64, Chain, sizeof(Chain));
        StDropped(IF, p, FALSE, "extension header longer than the datagram dropped", TRUE);
    }

    /* an ICMPv6 error that answers a TCP segment of ours passes, one that does not is judged by the rules */
    LOCK_TCPIP_CORE();
    Pcb = tcp_new_ip_type(IPADDR_TYPE_V6);
    Taken = FALSE;
    if (Pcb)
    {
        ip_addr_t Remote;

        ip_addr_copy_from_ip6(Remote, Peer);
        ip6_addr_assign_zone(ip_2_ip6(&Remote), IP6_UNICAST, (struct netif *)IF->TCPContext);
        if (tcp_connect(Pcb, &Remote, 40690, StNopConnected) == ERR_OK)
            Taken = TRUE;
        else
            tcp_abort(Pcb);
    }
    if (Taken)
    {
        UCHAR Error[8 + 40 + 20];
        PUCHAR Inner = Error + 8;
        struct pbuf *Q;

        RtlZeroMemory(Error, sizeof(Error));
        Error[0] = 1; Error[1] = 4;     /* destination unreachable, port unreachable */
        Inner[0] = 0x60; Inner[5] = 20; Inner[6] = 6; Inner[7] = 64;
        RtlCopyMemory(Inner + 8, ip_2_ip6(&Pcb->local_ip)->addr, 16);
        RtlCopyMemory(Inner + 24, Peer.addr, 16);
        StTcpHeader(Inner + 40, Pcb->local_port, 40690, 0x02);
        UNLOCK_TCPIP_CORE();
        Q = StPacket(&Peer, Dest, 58, 64, Error, sizeof(Error));
        StDropped(IF, Q, FALSE, "ICMPv6 error for our own TCP connection passes", FALSE);
        /* the same error for a port we have no connection on */
        StTcpHeader(Inner + 40, (u16_t)(Pcb->local_port + 1), 40690, 0x02);
        Q = StPacket(&Peer, Dest, 58, 64, Error, sizeof(Error));
        StDropped(IF, Q, FALSE, "ICMPv6 error for a connection we do not have dropped", TRUE);
        /* from a source address that is not ours */
        Inner[8] ^= 0x01;
        StTcpHeader(Inner + 40, Pcb->local_port, 40690, 0x02);
        Q = StPacket(&Peer, Dest, 58, 64, Error, sizeof(Error));
        StDropped(IF, Q, FALSE, "ICMPv6 error about a packet that was not ours dropped", TRUE);
        LOCK_TCPIP_CORE();
        tcp_abort(Pcb);
    }
    UNLOCK_TCPIP_CORE();
    if (!Taken)
        StResult(FALSE, "ICMPv6 error related to our TCP connection", "connect failed");

    /* the rate limit (RFC 4443 2.4(f)): datagrams the firewall admits and lwIP answers with a destination
       unreachable (UDP has no socket in lwIP); the answers are bounded by the burst plus the refill, the
       rest are counted as limited. The bucket is refilled first */
    StSleep(1500);
    SentBefore = TCP6IcmpErrorsSent;
    LimitedBefore = TCP6IcmpErrorsLimited;
    NitroFwTestCounters(&DropBefore, &PassBefore);
    Start = KeQueryPerformanceCounter(NULL);
    for (i = 0; i < 200; i++)
        StInject(IF, StUdp(&Peer, Dest, ST_PORT_ALLOWED_UDP), FALSE);
    Micro = StMicroseconds(Start);
    SentDelta = TCP6IcmpErrorsSent - SentBefore;
    LimitedDelta = TCP6IcmpErrorsLimited - LimitedBefore;
    NitroFwTestCounters(&DropAfter, &PassAfter);
    _snprintf(Detail, sizeof(Detail), "200 datagrams in %lu us: %ld errors sent, %ld limited, firewall passed %ld",
              Micro, SentDelta, LimitedDelta, (LONG)(PassAfter - PassBefore));
    StResult(PassAfter - PassBefore == 200 && SentDelta >= 1 &&
             (ULONG)SentDelta <= ST_ICMP_BURST + (ULONG)ST_ICMP_RATE * Micro / 1000000 + 1 &&
             SentDelta + LimitedDelta >= 150,
             "ICMPv6 error rate limit holds under a flood", Detail);
    /* it refills: a second later errors flow again */
    StSleep(1200);
    SentBefore = TCP6IcmpErrorsSent;
    StInject(IF, StUdp(&Peer, Dest, ST_PORT_ALLOWED_UDP), FALSE);
    StResult(TCP6IcmpErrorsSent == SentBefore + 1, "ICMPv6 errors flow again after the bucket refills", NULL);

cleanup:
    LOCK_TCPIP_CORE();
    if (ListenerBlocked)
        tcp_close(ListenerBlocked);
    if (ListenerAllowed)
        tcp_close(ListenerAllowed);
    UNLOCK_TCPIP_CORE();
}

/* Under the policy (default block, no rule for the port), TCP between our own addresses still works: those
   frames are our own send path's looped-back ones */
static VOID
StTestFirewall6Own(const ip_addr_t *LinkLocal)
{
    StTransfer("tcp own link-local echo 4096 under the firewall policy (no rule for the port)", LinkLocal, LinkLocal,
               40660, TRUE, 4096, 8000);
}

static VOID
StTestFirewall6End(VOID)
{
    NitroFwTestSetPolicy(NULL, 0);
}

/* ---- the receive path's bounds ---- */

static BOOLEAN
StReceiveFrame(PIP_INTERFACE IF, const UCHAR *Frame, UINT Length)
{
    PNDIS_PACKET NdisPacket;
    IP_PACKET Packet;
    PCHAR Data;
    UINT Size;
    LONG Before = TCP6ReceiveDropped;

    if (AllocatePacketWithBuffer(&NdisPacket, NULL, Length) != NDIS_STATUS_SUCCESS)
        return FALSE;
    GetDataPtr(NdisPacket, 0, &Data, &Size);
    RtlCopyMemory(Data, Frame, Length);

    IPInitializePacket(&Packet, IP_ADDRESS_V6);
    Packet.NdisPacket = NdisPacket;
    Packet.Position = 0;
    Packet.TotalSize = Length;
    Packet.FromOwnLink = FALSE;
    TCPReceive6(IF, &Packet);
    FreeNdisPacket(NdisPacket);

    return TCP6ReceiveDropped == Before + 1;
}

static VOID
StTestReceiveBounds(PIP_INTERFACE IF)
{
    UCHAR Frame[64];
    BOOLEAN Long, Short, Version, Loopback6, Other;

    /* A header that claims 1000 bytes of payload in a 64-byte frame */
    RtlZeroMemory(Frame, sizeof(Frame));
    Frame[0] = 0x60;
    Frame[4] = 0x03; Frame[5] = 0xE8;
    Frame[6] = 59;  /* no next header */
    Frame[7] = 64;
    Frame[8] = 0xFE; Frame[9] = 0x80; Frame[23] = 1;
    Frame[24] = 0xFE; Frame[25] = 0x80; Frame[39] = 2;
    Long = StReceiveFrame(IF, Frame, sizeof(Frame));

    /* Shorter than the fixed header */
    Short = StReceiveFrame(IF, Frame, 20);

    /* An IPv4 header in an IPv6 frame */
    Frame[0] = 0x45;
    Version = StReceiveFrame(IF, Frame, sizeof(Frame));

    StResult(Long && Short && Version, "receive drops a datagram longer than its frame, a runt, a wrong version",
             NULL);

    /* A well-formed empty datagram from ::1 (never on a link), and the same from fe80::1 (taken: the counter
       stays) */
    RtlZeroMemory(Frame, sizeof(Frame));
    Frame[0] = 0x60;
    Frame[6] = 59;
    Frame[7] = 64;
    Frame[23] = 1;
    Frame[24] = 0xFE; Frame[25] = 0x80; Frame[39] = 2;
    Loopback6 = StReceiveFrame(IF, Frame, 40);
    Frame[8] = 0xFE; Frame[9] = 0x80;
    Other = !StReceiveFrame(IF, Frame, 40);
    StResult(Loopback6 && Other, "receive drops a datagram from ::1 off the wire (control: fe80::1 taken)", NULL);
}

/* An MTU a router advertisement lowered stays when the interface's IPv4 side is refreshed (reconfiguration,
   address change) */
static VOID
StTestMtu6(PIP_INTERFACE IF)
{
    struct netif *netif = IF->TCPContext;
    u16_t Mtu, Before, After;
    CHAR Detail[64];

    LOCK_TCPIP_CORE();
    Mtu = netif->mtu;
    Before = netif->mtu6;
    netif->mtu6 = 1280;
    UNLOCK_TCPIP_CORE();

    TCPUpdateInterfaceIPInformation(IF);

    LOCK_TCPIP_CORE();
    After = netif->mtu6;
    netif->mtu6 = Before;
    UNLOCK_TCPIP_CORE();

    _snprintf(Detail, sizeof(Detail), "mtu %u, mtu6 %u -> 1280 -> %u after the refresh", Mtu, Before, After);
    StResult(After == 1280 && Before == Mtu, "IPv6 MTU lowered (as by a router advertisement) survives an interface refresh", Detail);
}

/* ---- main ---- */

static BOOLEAN
StReadValue(PCWSTR Name, ULONG Type, PVOID Data, ULONG Size)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters");
    UNICODE_STRING ValueName;
    OBJECT_ATTRIBUTES Attributes;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 128];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    HANDLE Key;
    ULONG Length;
    BOOLEAN Found = FALSE;

    RtlInitUnicodeString(&ValueName, Name);
    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attributes)))
        return FALSE;
    if (NT_SUCCESS(ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length)) &&
        Info->Type == Type && Info->DataLength <= Size)
    {
        RtlCopyMemory(Data, Info->Data, Info->DataLength);
        Found = TRUE;
    }
    ZwClose(Key);
    return Found;
}

static VOID NTAPI
StThread(PVOID Context)
{
    PIP_INTERFACE Eth = NULL;
    struct netif *Lo, *En;
    ip_addr_t Address, LinkLocal;
    WCHAR PeerW[64];
    CHAR PeerA[64];
    ULONG PeerPort = 0, i, Seconds = 0;
    ip_addr_t Slaac;
    BOOLEAN Preferred;
    CHAR Detail[96];

    for (i = 0; i < sizeof(StPattern); i++)
        StPattern[i] = (UCHAR)(i * 7 + 1);

    StPrint("start");

    /* ::1 */
    for (i = 0; i < 600 && !(Loopback && Loopback->TCPContext); i++)
        StSleep(100);
    if (!Loopback || !Loopback->TCPContext)
    {
        StResult(FALSE, "loopback interface", NULL);
        goto done;
    }
    Lo = Loopback->TCPContext;
    LOCK_TCPIP_CORE();
    StDescribeAddresses(Lo, "loopback");
    Preferred = netif_ip6_addr_state(Lo, 0) == IP6_ADDR_PREFERRED && ip6_addr_isloopback(netif_ip6_addr(Lo, 0));
    UNLOCK_TCPIP_CORE();
    StResult(Preferred, "::1 on the loopback interface, preferred", NULL);

    ipaddr_aton("127.0.0.1", &Address);
    StTransfer("tcp 127.0.0.1 echo 4096 (IPv4 control)", &Address, &Address, 40610, TRUE, 4096, 5000);
    ipaddr_aton("::1", &Address);
    StTransfer("tcp ::1 echo 4096", &Address, &Address, 40611, TRUE, 4096, 5000);
    StTransfer("tcp ::1 stream 1 MB", &Address, &Address, 40612, FALSE, 1024 * 1024, 20000);
    StTransfer("tcp ::1 echo 4096 again", &Address, &Address, 40613, TRUE, 4096, 5000);
    /* Nobody listens: lwIP answers the SYN with a reset, the connect fails at once */
    StTransferEx("tcp ::1 to a closed port is refused", NULL, &Address, 40614, TRUE, 16, 5000, TRUE);

    /* The first Ethernet interface: link-local address, DAD */
    for (i = 0; i < 1200 && !(Eth = StFindEthernet()); i++)
        StSleep(100);
    if (!Eth)
    {
        StResult(FALSE, "an Ethernet interface with its link up", NULL);
        goto done;
    }
    En = Eth->TCPContext;
    for (i = 0; i < 200; i++)
    {
        LOCK_TCPIP_CORE();
        Preferred = netif_is_up(En) && netif_ip6_addr_state(En, 0) == IP6_ADDR_PREFERRED;
        UNLOCK_TCPIP_CORE();
        if (Preferred)
            break;
        StSleep(100);
    }
    LOCK_TCPIP_CORE();
    StDescribeAddresses(En, "ethernet");
    ip_addr_copy_from_ip6(LinkLocal, *netif_ip6_addr(En, 0));
    UNLOCK_TCPIP_CORE();
    _snprintf(Detail, sizeof(Detail), "after about %lu ms (interface up=%d)", i * 100, (int)netif_is_up(En));
    StResult(Preferred && ip6_addr_islinklocal(ip_2_ip6(&LinkLocal)), "link-local address passed DAD", Detail);

    if (Preferred)
    {
        StTransfer("tcp own link-local echo 4096", &LinkLocal, &LinkLocal, 40615, TRUE, 4096, 5000);
        StTransfer("tcp own link-local echo 4096 again", &LinkLocal, &LinkLocal, 40618, TRUE, 4096, 5000);
        StTransfer("tcp own link-local stream 256 KB", &LinkLocal, &LinkLocal, 40616, FALSE, 256 * 1024, 20000);
        StTestFirewall6(Eth, &LinkLocal, 40617);
        StTestFirewall6Own(&LinkLocal);
        StTestFirewall6End();
    }
    StTestReceiveBounds(Eth);
    StTestMtu6(Eth);

    /* Multicast reception: the adapter's list, then what reaches us through it */
    StPrintReceived("before the multicast checks");
    StTestMulticastList(Eth, &LinkLocal);
    if (StReadValue(L"Ipv6SelfTestInboundWait", REG_DWORD, &Seconds, sizeof(Seconds)) && Seconds)
        StTestInbound(min(Seconds, 600));
    if (StReadValue(L"Ipv6SelfTestSlaacWait", REG_DWORD, &Seconds, sizeof(Seconds)) && Seconds &&
        StTestSlaac(En, min(Seconds, 600), &Slaac))
    {
        if (StReadAddress(L"Ipv6SelfTestSlaacPeer", En, &Address, PeerA, sizeof(PeerA)) &&
            StReadValue(L"Ipv6SelfTestSlaacPeerPort", REG_DWORD, &PeerPort, sizeof(PeerPort)) && PeerPort && PeerPort < 65536)
        {
            StPrint("SLAAC peer %s port %lu", PeerA, PeerPort);
            StTransfer("tcp echo 4096 from the SLAAC address to the peer", NULL, &Address, (u16_t)PeerPort, TRUE, 4096, 10000);
        }
        PeerPort = 0;
    }

    /* IPv4 to the interface's own address takes the same way (a frame to our own MAC): the control for the
       link-local timings above */
    LOCK_TCPIP_CORE();
    ip_addr_copy_from_ip4(Address, *netif_ip4_addr(En));
    UNLOCK_TCPIP_CORE();
    if (!ip_addr_isany(&Address))
    {
        StTransfer("tcp own IPv4 address echo 4096 (IPv4 control)", &Address, &Address, 40619, TRUE, 4096, 5000);
        StTransfer("tcp own IPv4 address echo 4096 again (IPv4 control)", &Address, &Address, 40621, TRUE, 4096, 5000);
    }

    /* A peer on the link, through neighbour discovery */
    RtlZeroMemory(PeerW, sizeof(PeerW));
    if (StReadValue(L"Ipv6SelfTestPeer", REG_SZ, PeerW, sizeof(PeerW) - sizeof(WCHAR)) &&
        StReadValue(L"Ipv6SelfTestPeerPort", REG_DWORD, &PeerPort, sizeof(PeerPort)) && PeerPort && PeerPort < 65536)
    {
        for (i = 0; i < 63 && PeerW[i]; i++)
            PeerA[i] = (CHAR)PeerW[i];
        PeerA[i] = 0;
        if (ip6addr_aton(PeerA, ip_2_ip6(&Address)))
        {
            IP_SET_TYPE_VAL(Address, IPADDR_TYPE_V6);
            ip6_addr_assign_zone(ip_2_ip6(&Address), IP6_UNICAST, En);
            StPrint("peer %s port %lu", PeerA, PeerPort);
            StTransfer("tcp echo 4096 to the peer on the link", NULL, &Address, (u16_t)PeerPort, TRUE, 4096, 10000);
        }
    }

    StPrint("counters: receive dropped %ld, listener refused %ld, firewall dropped %ld, ICMPv6 errors sent %ld limited %ld",
            TCP6ReceiveDropped, TCP6ListenerRefused, TCP6FilterDropped, TCP6IcmpErrorsSent, TCP6IcmpErrorsLimited);
    IPDereferenceInterface(Eth);

done:
    StPrint("DONE pass=%lu fail=%lu", StPass, StFail);
    StFlush();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID
TCPStartIpv6SelfTest(VOID)
{
    HANDLE Thread;
    ULONG Run = 0;

    if (!TCPIpv6Enabled || !StReadValue(L"Ipv6SelfTest", REG_DWORD, &Run, sizeof(Run)) || !Run)
        return;

    StLog = ExAllocatePoolWithTag(NonPagedPool, ST_LOG_SIZE, ST_TAG);
    if (!StLog)
        return;

    if (NT_SUCCESS(PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, StThread, NULL)))
        ZwClose(Thread);
}

#endif /* DBG || TCPIP_IPV6_SELFTEST */
