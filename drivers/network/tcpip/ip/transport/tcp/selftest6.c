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
#include "lwip/mld6.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/inet_chksum.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/priv/nd6_priv.h"
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
/* RtlEqualMemory is memcmp, which a driver does not link */
#define StSame(a, b, n) (RtlCompareMemory((a), (b), (n)) == (n))
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

static struct pbuf *
StMakeSynFrom(const ip6_addr_t *Src, const ip6_addr_t *Dest, u16_t SrcPort, u16_t Port);

/* A SYN from Src (an address on the link) to Dest:Port, as a datagram fresh from the adapter */
static struct pbuf *
StMakeSyn(const ip6_addr_t *Src, const ip6_addr_t *Dest, u16_t Port)
{
    return StMakeSynFrom(Src, Dest, 50001, Port);
}

/* The same from SrcPort */
static struct pbuf *
StMakeSynFrom(const ip6_addr_t *Src, const ip6_addr_t *Dest, u16_t SrcPort, u16_t Port)
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
    Tcp[0] = (UCHAR)(SrcPort >> 8); Tcp[1] = (UCHAR)SrcPort;
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
    const UCHAR *S = (const UCHAR *)Src->addr, *D = (const UCHAR *)Dest->addr;
    ULONG Sum, i;

    RtlZeroMemory(Udp, sizeof(Udp));
    Udp[0] = 0xC3; Udp[1] = 0x52;
    Udp[2] = (UCHAR)(DstPort >> 8); Udp[3] = (UCHAR)DstPort;
    Udp[5] = 8;

    /* The checksum is mandatory over IPv6 (RFC 8200 8.1; udp6.c drops a datagram without one): the pseudo header
       (both addresses, the length, the next header) and the header itself */
    Sum = 8 + 17;
    for (i = 0; i < 16; i += 2)
        Sum += ((ULONG)S[i] << 8 | S[i + 1]) + ((ULONG)D[i] << 8 | D[i + 1]);
    for (i = 0; i < sizeof(Udp); i += 2)
        Sum += (ULONG)Udp[i] << 8 | Udp[i + 1];
    while (Sum >> 16)
        Sum = (Sum & 0xFFFF) + (Sum >> 16);
    Sum = ~Sum & 0xFFFF;
    if (Sum == 0)
        Sum = 0xFFFF;
    Udp[6] = (UCHAR)(Sum >> 8);
    Udp[7] = (UCHAR)Sum;
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

    /* ICMPv6 echo: a request is unsolicited (default block); so is a reply, as nothing here sends a request
       (logged as a reply with no request behind it) */
    StDropped(IF, StIcmp(&Peer, Dest, 128, 0, 64, 8), FALSE, "ICMPv6 echo request dropped (default block)", TRUE);
    StDropped(IF, StIcmp(&Peer, Dest, 129, 0, 64, 8), FALSE, "ICMPv6 echo reply with no request of ours dropped", TRUE);
    Last = StLastDrop();
    StResult(Last && Last->Protocol == 58 && Last->IcmpType == 129 && Last->Reason == NITROFW_DROP_ICMP_REPLY,
             "...and logged as an unsolicited reply", NULL);

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
    /* RFC 6980: neighbour discovery and MLD are never fragmented; a Fragment header inside a Fragment header
       is not a form a sender needs. Both dropped and logged as invalid; the unfragmented forms pass (above).
       The drop log records 20 a second: a new second first, so the checks of the log below see their records */
    StSleep(1100);
    {
        UCHAR Frag[8 + 24];

        RtlZeroMemory(Frag, sizeof(Frag));
        Frag[0] = 58;
        Frag[3] = 0x01;         /* offset 0, more fragments */
        Frag[7] = 1;
        Frag[8] = 135;          /* neighbour solicitation, hop limit 255, link-local source: valid unfragmented */
        StDropped(IF, StPacket(&Peer, Dest, 44, 255, Frag, sizeof(Frag)), FALSE,
                  "fragmented neighbour solicitation dropped", TRUE);
        Last = StLastDrop();
        StResult(Last && Last->Protocol == 58 && Last->IcmpType == 135 && Last->Reason == NITROFW_DROP_V6_INVALID,
                 "...and logged as invalid", NULL);
        Frag[3] = 0;            /* an atomic fragment (offset 0, no more fragments) is the same */
        StDropped(IF, StPacket(&Peer, Dest, 44, 255, Frag, sizeof(Frag)), FALSE,
                  "atomic-fragment neighbour advertisement dropped", TRUE);
        Frag[3] = 0x01;
        Frag[8] = 134;
        StDropped(IF, StPacket(&Router, Dest, 44, 255, Frag, sizeof(Frag)), FALSE,
                  "fragmented router advertisement dropped", TRUE);
        Frag[8] = 130;
        StDropped(IF, StPacket(&Router, Dest, 44, 1, Frag, sizeof(Frag)), FALSE,
                  "fragmented MLD query dropped", TRUE);
    }
    {
        UCHAR Frag[8 + 8 + 20];

        RtlZeroMemory(Frag, sizeof(Frag));
        Frag[0] = 44;           /* a Fragment header whose next header is a Fragment header */
        Frag[7] = 1;
        Frag[8] = 6;            /* the inner one: offset 0 */
        Frag[8 + 7] = 2;
        StTcpHeader(Frag + 16, 50001, ST_PORT_ALLOWED_TCP, 0x10);
        StDropped(IF, StPacket(&Peer, Dest, 44, 64, Frag, sizeof(Frag)), FALSE,
                  "nested Fragment headers (inner offset 0) dropped", TRUE);
        Last = StLastDrop();
        StResult(Last && Last->Reason == NITROFW_DROP_V6_INVALID, "...and logged as invalid", NULL);
        Frag[8 + 3] = 0x09;     /* the inner one: offset 8 (used to pass as a later fragment) */
        StDropped(IF, StPacket(&Peer, Dest, 44, 64, Frag, sizeof(Frag)), FALSE,
                  "nested Fragment headers (inner offset 8) dropped", TRUE);
        Frag[3] = 0x09;         /* the outer one at offset 8 is still a later fragment: passes */
        Frag[8 + 3] = 0;
        StDropped(IF, StPacket(&Peer, Dest, 44, 64, Frag, sizeof(Frag)), FALSE,
                  "a later fragment (offset 8) still passes", FALSE);
    }
    /* the walk follows 8 extension headers and the transport header after them, not 9 (a non-SYN TCP segment
       passes the filter whenever the walk succeeds; a failed walk is an invalid datagram) */
    {
        UCHAR Chain[9 * 8 + 20];
        ULONG n;

        for (n = 8; n <= 9; n++)
        {
            ULONG k;

            RtlZeroMemory(Chain, sizeof(Chain));
            for (k = 0; k < n; k++)
            {
                Chain[k * 8] = (UCHAR)(k + 1 < n ? 60 : 6);     /* destination options, the last one -> TCP */
                Chain[k * 8 + 2] = 1; Chain[k * 8 + 3] = 4;     /* PadN of 4 */
            }
            StTcpHeader(Chain + n * 8, 50001, ST_PORT_ALLOWED_TCP, 0x10);
            p = StPacket(&Peer, Dest, 60, 64, Chain, n * 8 + 20);
            StDropped(IF, p, FALSE, n == 8 ? "8 extension headers then TCP ACK pass" : "9 extension headers dropped",
                      n == 9);
            if (n == 9)
            {
                Last = StLastDrop();
                StResult(Last && Last->Reason == NITROFW_DROP_V6_INVALID, "...and logged as invalid", NULL);
            }
        }
    }

    /* reassembly: the protocol of the datagram is the one its offset-0 fragment states, the one the firewall
       judged (RFC 8200 4.5). A SYN (valid checksum) in two fragments: 16 bytes at offset 0 (the flags are in
       them, so the firewall can judge it), 4 bytes at offset 16 */
    {
        static const struct
        {
            const char *Name;
            u16_t SrcPort, DstPort;
            UCHAR FirstNh;
            BOOLEAN LastFirst, WantTaken;
            UCHAR Id;
        } Cases[] =
        {
            /* the control: both say TCP, a rule admits the port: the datagram completes, the request is taken */
            { "fragmented SYN to an allowed port reassembled and taken (control)", 50001, ST_PORT_ALLOWED_TCP, 6, TRUE, TRUE, 0x21 },
            /* the later fragment arrives first and says TCP; the offset-0 one says UDP to the port a rule admits
               for UDP (the ports are the first bytes of both headers), which the firewall passes: the datagram
               must not complete as TCP to that port, which no rule admits for TCP */
            { "fragments that disagree on the protocol do not make a SYN past the firewall", 50002, ST_PORT_ALLOWED_UDP, 17, TRUE, FALSE, 0x22 },
            /* the same in order: the first fragment creates the entry as UDP, the TCP one is dropped */
            { "...nor in the other order", 50002, ST_PORT_ALLOWED_UDP, 17, FALSE, FALSE, 0x23 },
        };
        UCHAR First[8 + 16], Second[8 + 8];
        PUCHAR Tcp;
        struct pbuf *Syn;
        struct tcp_pcb *UdpPortListener = NULL;
        ULONG c;

        /* A TCP listener on the port that only UDP may reach */
        LOCK_TCPIP_CORE();
        Pcb = tcp_new_ip_type(IPADDR_TYPE_V6);
        if (Pcb && tcp_bind(Pcb, Local, ST_PORT_ALLOWED_UDP) == ERR_OK)
            UdpPortListener = tcp_listen(Pcb);
        else if (Pcb)
            tcp_close(Pcb);
        if (UdpPortListener)
            tcp_accept(UdpPortListener, StServerAccept);
        UNLOCK_TCPIP_CORE();
        StResult(UdpPortListener != NULL, "a TCP listener on the UDP-only port", NULL);

        for (c = 0; c < RTL_NUMBER_OF(Cases); c++)
        {
            Syn = StMakeSynFrom(&Peer, Dest, Cases[c].SrcPort, Cases[c].DstPort);
            if (!Syn)
            {
                StResult(FALSE, Cases[c].Name, "no memory");
                continue;
            }
            Tcp = (PUCHAR)Syn->payload + 40;

            RtlZeroMemory(First, sizeof(First));
            First[0] = Cases[c].FirstNh;
            First[3] = 0x01;                    /* offset 0, more fragments */
            First[7] = Cases[c].Id;
            RtlCopyMemory(First + 8, Tcp, 16);

            RtlZeroMemory(Second, sizeof(Second));
            Second[0] = 6;
            Second[3] = 0x10;                   /* offset 16, the last fragment */
            Second[7] = Cases[c].Id;
            RtlCopyMemory(Second + 8, Tcp + 16, 4);
            pbuf_free(Syn);

            if (Cases[c].LastFirst)
            {
                StInject(IF, StPacket(&Peer, Dest, 44, 64, Second, 8 + 4), FALSE);
                StInject(IF, StPacket(&Peer, Dest, 44, 64, First, sizeof(First)), FALSE);
            }
            else
            {
                StInject(IF, StPacket(&Peer, Dest, 44, 64, First, sizeof(First)), FALSE);
                StInject(IF, StPacket(&Peer, Dest, 44, 64, Second, 8 + 4), FALSE);
            }

            LOCK_TCPIP_CORE();
            Half = StFindSynReceived(Cases[c].DstPort);
            Taken = Half != NULL;
            if (Half)
                tcp_abort(Half);
            UNLOCK_TCPIP_CORE();
            _snprintf(Detail, sizeof(Detail), "half-open=%d", (int)Taken);
            StResult(Taken == Cases[c].WantTaken, Cases[c].Name, Detail);
        }

        if (UdpPortListener)
        {
            LOCK_TCPIP_CORE();
            tcp_close(UdpPortListener);
            UNLOCK_TCPIP_CORE();
        }
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
       unreachable (no socket has the port: udp6.c answers port unreachable); the answers are bounded by the burst plus the refill, the
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

/* ---- Packet Too Big (RFC 8201 4): the path MTU of a destination goes down to what a router says, never up
   and never below 1280 ---- */

/* A Packet Too Big from Router to Us, advertising Mtu, quoting a SYN of our connection (Local:LocalPort to
   Peer:PeerPort), with a valid checksum, as it arrives from the adapter */
static struct pbuf *
StPtb(const ip6_addr_t *Router, const ip6_addr_t *Us, const ip6_addr_t *Peer, u16_t LocalPort, u16_t PeerPort, ULONG Mtu)
{
    UCHAR Msg[8 + 40 + 20];
    PUCHAR Inner = Msg + 8;
    struct pbuf *p;
    u16_t Sum;

    RtlZeroMemory(Msg, sizeof(Msg));
    Msg[0] = 2;     /* packet too big */
    Msg[4] = (UCHAR)(Mtu >> 24); Msg[5] = (UCHAR)(Mtu >> 16); Msg[6] = (UCHAR)(Mtu >> 8); Msg[7] = (UCHAR)Mtu;
    Inner[0] = 0x60; Inner[5] = 20; Inner[6] = 6; Inner[7] = 64;
    RtlCopyMemory(Inner + 8, Us->addr, 16);
    RtlCopyMemory(Inner + 24, Peer->addr, 16);
    StTcpHeader(Inner + 40, LocalPort, PeerPort, 0x02);
    p = StPacket(Router, Us, 58, 64, Msg, sizeof(Msg));
    if (!p)
        return NULL;
    pbuf_remove_header(p, 40);
    Sum = ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, sizeof(Msg), Router, Us);
    pbuf_add_header(p, 40);
    RtlCopyMemory((PUCHAR)p->payload + 40 + 2, &Sum, 2);
    return p;
}

static VOID
StTestPtb(PIP_INTERFACE IF, const ip_addr_t *LinkLocal)
{
    struct netif *netif = IF->TCPContext;
    static const ULONG Steps[] = { 1400, 9000, 65535, 1000, 1400, 0 };
    static const ULONG Want[]  = { 1400, 1400, 1400, 1280, 1280, 1280 };
    struct tcp_pcb *Pcb;
    ip_addr_t Remote;
    ip6_addr_t Router, Us;
    BOOLEAN Taken = FALSE;
    u16_t Initial = 0, Now = 0, LocalPort = 0;
    CHAR Detail[96];
    ULONG i;

    ip6_addr_copy(Us, *ip_2_ip6(LinkLocal));
    ip6_addr_copy(Router, *ip_2_ip6(LinkLocal));
    Router.addr[3] ^= 0x0A000000;       /* a neighbour with another link-local address: the sender of the messages */
    ip_addr_copy_from_ip6(Remote, *ip_2_ip6(LinkLocal));
    ip_2_ip6(&Remote)->addr[3] ^= 0x0B000000;   /* the destination of the connection (a peer that does not answer) */
    ip6_addr_assign_zone(ip_2_ip6(&Remote), IP6_UNICAST, netif);

    LOCK_TCPIP_CORE();
    Pcb = tcp_new_ip_type(IPADDR_TYPE_V6);
    if (Pcb && tcp_connect(Pcb, &Remote, 40695, StNopConnected) == ERR_OK)
    {
        Taken = TRUE;
        LocalPort = Pcb->local_port;
        Initial = nd6_get_destination_mtu(ip_2_ip6(&Remote), netif);
    }
    else if (Pcb)
        tcp_abort(Pcb);
    UNLOCK_TCPIP_CORE();
    if (!Taken)
    {
        StResult(FALSE, "Packet Too Big: a connection to a silent peer", "connect failed");
        return;
    }

    _snprintf(Detail, sizeof(Detail), "starts at %u (the link MTU %u)", Initial, netif->mtu6);
    StResult(Initial == netif->mtu6 && Initial > 1280, "path MTU of a new destination is the link MTU", Detail);

    for (i = 0; Steps[i]; i++)
    {
        StInject(IF, StPtb(&Router, &Us, ip_2_ip6(&Remote), LocalPort, 40695, Steps[i]), FALSE);
        LOCK_TCPIP_CORE();
        Now = nd6_get_destination_mtu(ip_2_ip6(&Remote), netif);
        UNLOCK_TCPIP_CORE();
        _snprintf(Detail, sizeof(Detail), "advertised %lu -> path MTU %u (want %lu)", Steps[i], Now, Want[i]);
        StResult(Now == Want[i], "Packet Too Big lowers the path MTU, never raises it, never below 1280", Detail);
    }

    LOCK_TCPIP_CORE();
    tcp_abort(Pcb);
    UNLOCK_TCPIP_CORE();
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

/* ---- stable random identifiers (iid6.c) ---- */

BOOLEAN TCP6StableAddress(struct netif *netif, const ip6_addr_t *Prefix, UCHAR Counter, ip6_addr_t *Address);

/* An unsolicited neighbour advertisement (override flag, to all nodes, hop limit 255) for Target from Src,
   with its checksum: what another node that has the address sends during our DAD */
static struct pbuf *
StNa(const ip6_addr_t *Src, const ip6_addr_t *Target)
{
    ip6_addr_t AllNodes;
    UCHAR Na[24];
    const UCHAR *S, *D;
    ULONG Sum, i;

    ip6_addr_set_allnodes_linklocal(&AllNodes);
    RtlZeroMemory(Na, sizeof(Na));
    Na[0] = 136;
    Na[4] = 0x20;       /* O */
    RtlCopyMemory(Na + 8, Target->addr, 16);

    S = (const UCHAR *)Src->addr;
    D = (const UCHAR *)AllNodes.addr;
    Sum = sizeof(Na) + 58;
    for (i = 0; i < 16; i += 2)
        Sum += ((ULONG)S[i] << 8 | S[i + 1]) + ((ULONG)D[i] << 8 | D[i + 1]);
    for (i = 0; i < sizeof(Na); i += 2)
        Sum += (ULONG)Na[i] << 8 | Na[i + 1];
    while (Sum >> 16)
        Sum = (Sum & 0xFFFF) + (Sum >> 16);
    Sum = ~Sum & 0xFFFF;
    Na[2] = (UCHAR)(Sum >> 8);
    Na[3] = (UCHAR)Sum;
    return StPacket(Src, &AllNodes, 58, 255, Na, sizeof(Na));
}

/* Whether the identifier of Address is the modified EUI-64 of the 6-byte Mac */
static BOOLEAN
StIsEui64(const ip6_addr_t *Address, const UCHAR *Mac)
{
    const UCHAR *Iid = (const UCHAR *)Address->addr + 8;

    return Iid[0] == (Mac[0] ^ 0x02) && Iid[1] == Mac[1] && Iid[2] == Mac[2] && Iid[3] == 0xff &&
           Iid[4] == 0xfe && Iid[5] == Mac[3] && Iid[6] == Mac[4] && Iid[7] == Mac[5];
}

static VOID
StTestStableIds(PIP_INTERFACE Eth)
{
    struct netif *En = Eth->TCPContext;
    ip6_addr_t Prefix, Want, Now, Peer;
    CHAR Text[IP6ADDR_STRLEN_MAX], Detail[160];
    UCHAR Mac[6];
    ULONG Eui = 0, Other = 0, Round;
    BOOLEAN LinkLocalOk = FALSE, Ok;
    s8_t i, Free = -1;
    u8_t State = 0;
#if LWIP_IPV6_MLD
    ip6_addr_t OldGroup, NewGroup;
    BOOLEAN GroupJoined = FALSE, GroupsOk = FALSE;
#endif

    LOCK_TCPIP_CORE();
    RtlCopyMemory(Mac, En->hwaddr, 6);
    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        if (ip6_addr_isinvalid(netif_ip6_addr_state(En, i)))
        {
            if (Free < 0)
                Free = i;
            continue;
        }
        if (StIsEui64(netif_ip6_addr(En, i), Mac))
            Eui++;
        else
            Other++;
    }
    /* The link-local address is the generator's, counter 0 (QEMU's network answers no DAD) */
    IP6_ADDR(&Prefix, PP_HTONL(0xfe800000UL), 0, 0, 0);
    if (TCP6RandomizeIdentifiers)
        LinkLocalOk = TCP6StableAddress(En, &Prefix, 0, &Want) && ip6_addr_zoneless_eq(&Want, netif_ip6_addr(En, 0));
    else
        LinkLocalOk = StIsEui64(netif_ip6_addr(En, 0), Mac);
    ip6addr_ntoa_r(netif_ip6_addr(En, 0), Text, sizeof(Text));
    UNLOCK_TCPIP_CORE();

    _snprintf(Detail, sizeof(Detail), "randomize=%d; addresses with the MAC's EUI-64 identifier %lu, others %lu; link-local %s",
              (int)TCP6RandomizeIdentifiers, Eui, Other, Text);
    if (TCP6RandomizeIdentifiers)
        StResult(Eui == 0 && Other > 0 && LinkLocalOk, "identifiers: no address carries the MAC, link-local = F(fe80::/64, counter 0)", Detail);
    else
        StResult(Eui > 0 && Other == 0 && LinkLocalOk, "identifiers: RandomizeIdentifiers=0 gives the MAC's EUI-64", Detail);

    /* DAD conflict on a tentative address of ours (RFC 7217 section 6): a free slot gets the address of a test
       prefix, tentative; another node's advertisement for it makes the next counter's address, three times,
       then the address stays duplicated */
    if (Free < 0)
    {
        StPrint("identifiers: no free address slot, DAD regeneration not tested");
        return;
    }
    IP6_ADDR(&Prefix, PP_HTONL(0x20010db8UL), PP_HTONL(0x00060007UL), 0, 0);
    ip6_addr_copy(Peer, *netif_ip6_addr(En, 0));
    Peer.addr[3] ^= 0x0C000000;     /* another node on the link */

    LOCK_TCPIP_CORE();
    if (TCP6RandomizeIdentifiers)
        TCP6StableAddress(En, &Prefix, 0, &Want);
    else
        IP6_ADDR(&Want, Prefix.addr[0], Prefix.addr[1], netif_ip6_addr(En, 0)->addr[2], netif_ip6_addr(En, 0)->addr[3]);
    netif_ip6_addr_set(En, Free, &Want);
    netif_ip6_addr_set_valid_life(En, Free, 600);
    netif_ip6_addr_set_pref_life(En, Free, 600);
#if LWIP_IPV6_MLD
    /* One probe sent (TENTATIVE_1), as when the DAD of a real address is under way: with MLD the address's
       solicited-node group is joined from here on, and the conflict below must leave that group (the address
       of the slot then) and not join the next address's group before its own probe */
    netif_ip6_addr_set_state(En, Free, IP6_ADDR_TENTATIVE_1);
    ip6_addr_set_solicitednode(&OldGroup, Want.addr[3]);
    ip6_addr_assign_zone(&OldGroup, IP6_MULTICAST, En);
    GroupJoined = (En->flags & NETIF_FLAG_MLD6) && mld6_lookfor_group(En, &OldGroup) != NULL;
#else
    netif_ip6_addr_set_state(En, Free, IP6_ADDR_TENTATIVE);
#endif
    UNLOCK_TCPIP_CORE();

    for (Round = 1; Round <= 4; Round++)
    {
        ip6_addr_t Target = Want;

        StInject(Eth, StNa(&Peer, &Target), FALSE);
        LOCK_TCPIP_CORE();
        ip6_addr_copy(Now, *netif_ip6_addr(En, Free));
        State = netif_ip6_addr_state(En, Free);
#if LWIP_IPV6_MLD
        if (Round == 1)
        {
            ip6_addr_set_solicitednode(&NewGroup, Now.addr[3]);
            ip6_addr_assign_zone(&NewGroup, IP6_MULTICAST, En);
            GroupsOk = GroupJoined && mld6_lookfor_group(En, &OldGroup) == NULL &&
                       mld6_lookfor_group(En, &NewGroup) == NULL;
        }
#endif
        if (TCP6RandomizeIdentifiers && Round <= 3)
            Ok = TCP6StableAddress(En, &Prefix, (UCHAR)Round, &Want) && ip6_addr_zoneless_eq(&Now, &Want) &&
                 ip6_addr_istentative(State);
        else
            Ok = ip6_addr_zoneless_eq(&Now, &Target) && ip6_addr_isduplicated(State);
        UNLOCK_TCPIP_CORE();
        ip6addr_ntoa_r(&Now, Text, sizeof(Text));
        _snprintf(Detail, sizeof(Detail), "round %lu: %s state 0x%x", Round, Text, (UINT)State);
        StResult(Ok, TCP6RandomizeIdentifiers ?
                     (Round <= 3 ? "identifiers: DAD conflict on a tentative address gives the next counter's address" :
                                   "identifiers: after 3 new identifiers the address stays duplicated") :
                     "identifiers: RandomizeIdentifiers=0, a DAD conflict marks the address duplicated", Detail);
        if (!TCP6RandomizeIdentifiers || Round > 3 || !Ok)
            break;
    }

    /* What the address table says now: every address DAD found in use is listed as a duplicate (the replaced ones
       from the list iid6.c keeps, the last one from its slot), the one that took over is not */
    {
        ULONG Size = TCPQueryIpv6Table(NULL, 0), Dups = 0, Others = 0, Want_ = TCP6RandomizeIdentifiers ? 4 : 1;
        PUCHAR Buffer = Size ? ExAllocatePoolWithTag(NonPagedPool, Size + 4096, ST_TAG) : NULL;

        if (Buffer)
        {
            PTCP_IPV6_TABLE_HEADER Header;
            PTCP_IPV6_ADDRESS_ROW Rows;
            ULONG k;

            Size = TCPQueryIpv6Table(Buffer, Size + 4096);
            Header = (PTCP_IPV6_TABLE_HEADER)Buffer;
            Rows = (PTCP_IPV6_ADDRESS_ROW)((PUCHAR)(Header + 1) + Header->InterfaceCount * sizeof(TCP_IPV6_INTERFACE_ROW));
            for (k = 0; k < Header->AddressCount; k++)
            {
                if (!StSame(Rows[k].Address, Prefix.addr, 8))
                    continue;
                if (Rows[k].DadState == 2)
                    Dups++;
                else
                    Others++;
            }
            ExFreePoolWithTag(Buffer, ST_TAG);
        }
        _snprintf(Detail, sizeof(Detail), "%lu duplicate rows (want %lu), %lu other rows of the test prefix", Dups, Want_, Others);
        StResult(Buffer && Dups == Want_ && Others == 0,
                 "DAD: addresses found in use are listed as Duplicate in the address table", Detail);
    }

#if LWIP_IPV6_MLD
    if (En->flags & NETIF_FLAG_MLD6)
        StResult(GroupsOk, "MLD: a DAD conflict after the first probe leaves the old address's solicited-node group "
                           "and does not join the next one's before its probe",
                 GroupJoined ? (GroupsOk ? "left, none joined" : "old group still joined or new group joined early")
                             : "the group was not joined at TENTATIVE_1");
#endif

    LOCK_TCPIP_CORE();
    netif_ip6_addr_set_state(En, Free, IP6_ADDR_INVALID);
    netif_ip6_addr_set_valid_life(En, Free, 0);
    netif_ip6_addr_set_pref_life(En, Free, 0);
    TCP6DuplicateClear(En);     /* the replaced addresses of the test */
    UNLOCK_TCPIP_CORE();
}


/* ---- what router advertisements carry (ra6.c, route6.c, nd6.c): DNSSL, route information, router preference, current
   hop limit, M and O flags, a preferred lifetime of 0 ---- */

#include <lwip_hooks.h>

/* The ICMPv6 checksum of Msg (Len bytes, checksum field zero) from Src to Dest */
static USHORT
StIcmpSum(const ip6_addr_t *Src, const ip6_addr_t *Dest, const UCHAR *Msg, UINT Len)
{
    const UCHAR *S = (const UCHAR *)Src->addr, *D = (const UCHAR *)Dest->addr;
    ULONG Sum = Len + 58, i;

    for (i = 0; i < 16; i += 2)
        Sum += ((ULONG)S[i] << 8 | S[i + 1]) + ((ULONG)D[i] << 8 | D[i + 1]);
    for (i = 0; i + 1 < Len; i += 2)
        Sum += (ULONG)Msg[i] << 8 | Msg[i + 1];
    if (Len & 1)
        Sum += (ULONG)Msg[Len - 1] << 8;
    while (Sum >> 16)
        Sum = (Sum & 0xFFFF) + (Sum >> 16);
    return (USHORT)(~Sum & 0xFFFF);
}

/* A router advertisement from Router (link-local): header with CurHopLimit, Flags (M 0x80, O 0x40, preference 0x18) and
   router Lifetime, then the options (OptLen bytes), hop limit 255, to all nodes, checksummed. NULL: no memory */
static struct pbuf *
StRa(const ip6_addr_t *Router, UCHAR CurHop, UCHAR Flags, USHORT Lifetime, const UCHAR *Opts, UINT OptLen)
{
    ip6_addr_t AllNodes;
    UCHAR Msg[16 + 1024];
    USHORT Sum;

    if (OptLen > 1024)
        return NULL;
    ip6_addr_set_allnodes_linklocal(&AllNodes);
    RtlZeroMemory(Msg, 16);
    Msg[0] = 134;
    Msg[4] = CurHop;
    Msg[5] = Flags;
    Msg[6] = (UCHAR)(Lifetime >> 8);
    Msg[7] = (UCHAR)Lifetime;
    if (OptLen)
        RtlCopyMemory(Msg + 16, Opts, OptLen);
    Sum = StIcmpSum(Router, &AllNodes, Msg, 16 + OptLen);
    Msg[2] = (UCHAR)(Sum >> 8);
    Msg[3] = (UCHAR)Sum;
    return StPacket(Router, &AllNodes, 58, 255, Msg, 16 + OptLen);
}

static UINT
StOptSlla(PUCHAR Out, const UCHAR *Mac)
{
    Out[0] = 1; Out[1] = 1;
    RtlCopyMemory(Out + 2, Mac, 6);
    return 8;
}

/* A DNSSL option with the names in Names (Len bytes of label encoding), padded to 8 */
static UINT
StOptDnssl(PUCHAR Out, ULONG Lifetime, const UCHAR *Names, UINT Len)
{
    UINT Total = (8 + Len + 7) & ~7U;

    RtlZeroMemory(Out, Total);
    Out[0] = 31; Out[1] = (UCHAR)(Total / 8);
    Out[4] = (UCHAR)(Lifetime >> 24); Out[5] = (UCHAR)(Lifetime >> 16); Out[6] = (UCHAR)(Lifetime >> 8); Out[7] = (UCHAR)Lifetime;
    RtlCopyMemory(Out + 8, Names, Len);
    return Total;
}

/* A route information option for Prefix (16 bytes) / Plen, preference Prf (the 2-bit field), Lifetime, Units 8-byte units
   long (1 to 3) */
static UINT
StOptRio(PUCHAR Out, UCHAR Units, UCHAR Plen, UCHAR Prf, ULONG Lifetime, const UCHAR *Prefix)
{
    RtlZeroMemory(Out, Units * 8);
    Out[0] = 24; Out[1] = Units; Out[2] = Plen; Out[3] = (UCHAR)(Prf << 3);
    Out[4] = (UCHAR)(Lifetime >> 24); Out[5] = (UCHAR)(Lifetime >> 16); Out[6] = (UCHAR)(Lifetime >> 8); Out[7] = (UCHAR)Lifetime;
    if (Units > 1)
        RtlCopyMemory(Out + 8, Prefix, (Units - 1) * 8);
    return Units * 8;
}

/* A prefix information option: on-link and autonomous, a /64 */
static UINT
StOptPrefix(PUCHAR Out, ULONG Valid, ULONG Preferred, const UCHAR *Prefix)
{
    RtlZeroMemory(Out, 32);
    Out[0] = 3; Out[1] = 4; Out[2] = 64; Out[3] = 0xC0;
    Out[4] = (UCHAR)(Valid >> 24); Out[5] = (UCHAR)(Valid >> 16); Out[6] = (UCHAR)(Valid >> 8); Out[7] = (UCHAR)Valid;
    Out[8] = (UCHAR)(Preferred >> 24); Out[9] = (UCHAR)(Preferred >> 16); Out[10] = (UCHAR)(Preferred >> 8); Out[11] = (UCHAR)Preferred;
    RtlCopyMemory(Out + 16, Prefix, 16);
    return 32;
}

/* The rows of IP_IPV6_ROUTE_ENTRY_ID: allocated, ST_TAG, caller frees; NULL on failure */
static PTCP_IPV6_ROUTE_HEADER
StRoutes(PULONG Count)
{
    ULONG Size = 24 * 1024, Need;
    PTCP_IPV6_ROUTE_HEADER Header = ExAllocatePoolWithTag(NonPagedPool, Size, ST_TAG);

    if (!Header)
        return NULL;
    Need = TCPQueryIpv6Routes(Header, Size);
    if (Need > Size)
    {
        ExFreePoolWithTag(Header, ST_TAG);
        return NULL;
    }
    *Count = Header->Count;
    return Header;
}

static const TCP_IPV6_ROUTE_ROW *
StFindRoute(PTCP_IPV6_ROUTE_HEADER Header, const UCHAR *Prefix, ULONG Length, const UCHAR *NextHop)
{
    const TCP_IPV6_ROUTE_ROW *Rows = (const TCP_IPV6_ROUTE_ROW *)(Header + 1);
    ULONG i;

    for (i = 0; i < Header->Count; i++)
    {
        if (Rows[i].PrefixLength == Length && (!Prefix || StSame(Rows[i].Prefix, Prefix, 16)) &&
            (!NextHop || StSame(Rows[i].NextHop, NextHop, 16)))
            return &Rows[i];
    }
    return NULL;
}

/* How many search domains of that name the stack has (Name NULL: how many it has at all) */
static ULONG
StRaSuffixCount(const char *Name, ULONG *Lifetime)
{
    ULONG Size = 8 * 1024, Count = 0, i;
    PTCP_IPV6_RA_HEADER Header = ExAllocatePoolWithTag(NonPagedPool, Size, ST_TAG);
    PTCP_IPV6_RA_ROW Rows;

    if (!Header)
        return 0xFFFFFFFF;
    if (TCPQueryIpv6Ra(Header, Size) > Size)
    {
        ExFreePoolWithTag(Header, ST_TAG);
        return 0xFFFFFFFF;
    }
    Rows = (PTCP_IPV6_RA_ROW)(Header + 1);
    for (i = 0; i < Header->Count; i++)
    {
        if (!Name || !_stricmp(Rows[i].Name, Name))
        {
            Count++;
            if (Lifetime)
                *Lifetime = Rows[i].Lifetime;
        }
    }
    ExFreePoolWithTag(Header, ST_TAG);
    return Count;
}

/* The slot of the public SLAAC address of this /64 prefix on netif (core lock NOT held), or -1; *State gets its
   state. The temporary addresses made beside it (temp6.c) are not it */
static s8_t
StFindPrefixAddress(struct netif *En, const UCHAR *P, u8_t *State)
{
    s8_t Found = -1, k;

    LOCK_TCPIP_CORE();
    for (k = 1; k < LWIP_IPV6_NUM_ADDRESSES; k++)
    {
        if (!ip6_addr_isinvalid(netif_ip6_addr_state(En, k)) && StSame(netif_ip6_addr(En, k)->addr, P, 8) &&
            !TCP6TemporarySlot(En, k))
        {
            Found = k;
            *State = netif_ip6_addr_state(En, k);
        }
    }
    UNLOCK_TCPIP_CORE();
    return Found;
}

/* Every address of the prefix goes: the public one and its temporary addresses */
static VOID
StDropPrefixAddress(struct netif *En, const UCHAR *P)
{
    s8_t k;

    LOCK_TCPIP_CORE();
    for (k = 1; k < LWIP_IPV6_NUM_ADDRESSES; k++)
    {
        if (!ip6_addr_isinvalid(netif_ip6_addr_state(En, k)) && StSame(netif_ip6_addr(En, k)->addr, P, 8))
        {
            netif_ip6_addr_set_state(En, k, IP6_ADDR_INVALID);
            netif_ip6_addr_set_valid_life(En, k, 0);
            netif_ip6_addr_set_pref_life(En, k, 0);
        }
    }
    UNLOCK_TCPIP_CORE();
}

/* The per-interface parameters (ifcfg.c, SetIpInterfaceEntry) */
static VOID
StTestInterfaceParams(PIP_INTERFACE Eth, const ip6_addr_t *R1, const UCHAR *Mac1)
{
    struct netif *En = Eth->TCPContext;
    TCP_IP_INTERFACE_REQUEST Req;
    UCHAR Opts[64], P3[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x70, 0x03 }, P4[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x70, 0x04 };
    UINT n, Link = Eth->LinkMtu ? Eth->LinkMtu : Eth->MTU;
    NTSTATUS St;
    BOOLEAN Ok;
    CHAR Detail[96];
    u8_t State = 0;
    ULONG i, Ms;
    LARGE_INTEGER Start;

    RtlZeroMemory(&Req, sizeof(Req));
    Req.Family = TCP_IPIF_IPV6;
    Req.Store = TCP_IPV6_STORE_ACTIVE;
    Req.IfIndex = Eth->Index;

    /* MTU: each family has its own, below the link MTU; IPv6 not below 1280, IPv4 not below 576 */
    Req.Fields = TCP_IPIF_SET_MTU;
    Req.Mtu = 1280;
    St = TCP6InterfaceConfigure(Eth, &Req);
    _snprintf(Detail, sizeof(Detail), "status 0x%lx mtu6 %u mtu %u link %u", St, (UINT)En->mtu6, (UINT)En->mtu, Link);
    StResult(St == STATUS_SUCCESS && En->mtu6 == 1280 && En->mtu == Link, "interface parameters: IPv6 MTU 1280 changes mtu6 only", Detail);
    Req.Mtu = 1279;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_INVALID_PARAMETER && En->mtu6 == 1280, "interface parameters: IPv6 MTU 1279 is refused, nothing changes", NULL);
    Req.Mtu = Link + 1;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_INVALID_PARAMETER && En->mtu6 == 1280, "interface parameters: an IPv6 MTU above the link MTU is refused", NULL);
    Req.Family = TCP_IPIF_IPV4;
    Req.Mtu = 575;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_INVALID_PARAMETER, "interface parameters: IPv4 MTU 575 is refused", NULL);
    Req.Mtu = 1000;
    St = TCP6InterfaceConfigure(Eth, &Req);
    _snprintf(Detail, sizeof(Detail), "status 0x%lx mtu %u (interface %u) mtu6 %u", St, (UINT)En->mtu, Eth->MTU, (UINT)En->mtu6);
    StResult(St == STATUS_SUCCESS && En->mtu == 1000 && Eth->MTU == 1000 && En->mtu6 == 1280,
             "interface parameters: IPv4 MTU 1000 changes the IPv4 MTU, IPv6 keeps its own", Detail);
    Req.Mtu = Link;
    St = TCP6InterfaceConfigure(Eth, &Req);
    Req.Family = TCP_IPIF_IPV6;
    St |= TCP6InterfaceConfigure(Eth, &Req);
    _snprintf(Detail, sizeof(Detail), "mtu %u mtu6 %u", (UINT)En->mtu, (UINT)En->mtu6);
    StResult(St == STATUS_SUCCESS && En->mtu == Link && En->mtu6 == Link, "interface parameters: both MTUs back to the link MTU", Detail);

    /* the MTU option of a router advertisement lowers the IPv6 MTU at most to its own value: an IPv4 MTU set lower
       (576, below the IPv6 minimum) is not the IPv6 one */
    Req.Family = TCP_IPIF_IPV4;
    Req.Mtu = 576;
    St = TCP6InterfaceConfigure(Eth, &Req);
    n = StOptSlla(Opts, Mac1);
    RtlZeroMemory(Opts + n, 8);
    Opts[n] = 5; Opts[n + 1] = 1;
    Opts[n + 4] = (UCHAR)(Link >> 24); Opts[n + 5] = (UCHAR)(Link >> 16); Opts[n + 6] = (UCHAR)(Link >> 8); Opts[n + 7] = (UCHAR)Link;
    n += 8;
    StInject(Eth, StRa(R1, 0, 0, 0, Opts, n), FALSE);
    StSleep(300);
    _snprintf(Detail, sizeof(Detail), "status 0x%lx mtu %u mtu6 %u link %u", St, (UINT)En->mtu, (UINT)En->mtu6, Link);
    Ok = (St == STATUS_SUCCESS && En->mtu == 576 && En->mtu6 == Link);
    Req.Mtu = Link;
    St = TCP6InterfaceConfigure(Eth, &Req);
    Req.Family = TCP_IPIF_IPV6;
    StResult(Ok && St == STATUS_SUCCESS && En->mtu == Link && En->mtu6 == Link,
             "interface parameters: an advertised MTU is not bounded by a lower IPv4 MTU", Detail);

    /* metric: the IPv6 one is added to the route metrics, 0 is automatic */
    Req.Fields = TCP_IPIF_SET_METRIC;
    Req.Metric = 50;
    St = TCP6InterfaceConfigure(Eth, &Req);
    Ok = St == STATUS_SUCCESS && Eth->Ip6Metric == 50;
    LOCK_TCPIP_CORE();
    Ok = Ok && TCP6InterfaceMetric(En) == 50;
    UNLOCK_TCPIP_CORE();
    StResult(Ok, "interface parameters: IPv6 metric 50 is what the route table adds", NULL);
    Req.Metric = 10000;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_INVALID_PARAMETER && Eth->Ip6Metric == 50, "interface parameters: a metric above 9999 is refused", NULL);
    Req.Metric = 0;
    St = TCP6InterfaceConfigure(Eth, &Req);
    LOCK_TCPIP_CORE();
    n = TCP6InterfaceMetric(En);
    UNLOCK_TCPIP_CORE();
    _snprintf(Detail, sizeof(Detail), "automatic metric %u", n);
    StResult(St == STATUS_SUCCESS && Eth->Ip6Metric == 0 && n >= 15 && n <= 40, "interface parameters: metric 0 is automatic again", Detail);

    /* what the stack cannot do */
    Req.Fields = TCP_IPIF_SET_FORWARDING;
    Req.Forwarding = 1;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_NOT_SUPPORTED, "interface parameters: forwarding on is refused (IPv6)", NULL);
    Req.Forwarding = 0;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_SUCCESS, "interface parameters: forwarding off is accepted", NULL);
    Req.Family = TCP_IPIF_IPV4;
    Req.Fields = TCP_IPIF_SET_DAD_TRANSMITS;
    Req.DadTransmits = 1;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_NOT_SUPPORTED, "interface parameters: IPv4 DAD transmits are refused", NULL);
    Req.Fields = TCP_IPIF_SET_ROUTER_DISCOVERY;
    Req.RouterDiscovery = 0;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_NOT_SUPPORTED, "interface parameters: IPv4 router discovery is refused", NULL);
    Req.Family = TCP_IPIF_IPV6;
    Req.Fields = TCP_IPIF_SET_DAD_TRANSMITS;
    Req.DadTransmits = 8;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_INVALID_PARAMETER, "interface parameters: DAD transmits 8 are refused", NULL);
    Req.Fields = TCP_IPIF_SET_MTU | TCP_IPIF_SET_METRIC;
    Req.Mtu = 1300;
    Req.Metric = 20000;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_INVALID_PARAMETER && En->mtu6 == Link, "interface parameters: a request with one wrong field changes nothing", NULL);

    /* DAD transmits: 0 makes an address usable at the next timer tick, 3 takes about three seconds more */
    Req.Fields = TCP_IPIF_SET_DAD_TRANSMITS;
    Req.DadTransmits = 0;
    St = TCP6InterfaceConfigure(Eth, &Req);
    StResult(St == STATUS_SUCCESS && LibNd6DadAttempts(En) == 0, "interface parameters: DAD transmits 0 set", NULL);
    n = StOptSlla(Opts, Mac1);
    n += StOptPrefix(Opts + n, 3600, 1800, P3);
    Start = KeQueryPerformanceCounter(NULL);
    StInject(Eth, StRa(R1, 0, 0, 0, Opts, n), FALSE);
    for (i = 0; i < 60; i++)
    {
        if (StFindPrefixAddress(En, P3, &State) >= 0 && ip6_addr_ispreferred(State))
            break;
        StSleep(50);
    }
    Ms = StMicroseconds(Start) / 1000;
    _snprintf(Detail, sizeof(Detail), "preferred after %lu ms", Ms);
    StResult(ip6_addr_ispreferred(State) && Ms <= 1600, "interface parameters: with 0 DAD transmits a SLAAC address is preferred at the next tick", Detail);
    StDropPrefixAddress(En, P3);

    Req.DadTransmits = 3;
    St = TCP6InterfaceConfigure(Eth, &Req);
    State = 0;
    Start = KeQueryPerformanceCounter(NULL);
    n = StOptSlla(Opts, Mac1);
    n += StOptPrefix(Opts + n, 3600, 1800, P3);
    StInject(Eth, StRa(R1, 0, 0, 0, Opts, n), FALSE);
    for (i = 0; i < 160; i++)
    {
        if (StFindPrefixAddress(En, P3, &State) >= 0 && ip6_addr_ispreferred(State))
            break;
        StSleep(50);
    }
    Ms = StMicroseconds(Start) / 1000;
    _snprintf(Detail, sizeof(Detail), "preferred after %lu ms", Ms);
    StResult(St == STATUS_SUCCESS && LibNd6DadAttempts(En) == 3 && ip6_addr_ispreferred(State) && Ms >= 2900,
             "interface parameters: with 3 DAD transmits it takes three probe intervals", Detail);
    StDropPrefixAddress(En, P3);
    Req.DadTransmits = 1;
    TCP6InterfaceConfigure(Eth, &Req);

    /* router discovery off: advertisements are ignored (no address of the prefix), on: they work again */
    Req.Fields = TCP_IPIF_SET_ROUTER_DISCOVERY;
    Req.RouterDiscovery = 0;
    St = TCP6InterfaceConfigure(Eth, &Req);
    n = StOptSlla(Opts, Mac1);
    n += StOptPrefix(Opts + n, 3600, 1800, P4);
    StInject(Eth, StRa(R1, 0, 0, 0, Opts, n), FALSE);
    StSleep(2500);
    StResult(St == STATUS_SUCCESS && !LibNd6RaAccept(En) && StFindPrefixAddress(En, P4, &State) < 0,
             "interface parameters: router discovery off ignores a router advertisement (no address of its prefix)", NULL);
    Req.RouterDiscovery = 1;
    St = TCP6InterfaceConfigure(Eth, &Req);
    n = StOptSlla(Opts, Mac1);
    n += StOptPrefix(Opts + n, 3600, 1800, P4);
    StInject(Eth, StRa(R1, 0, 0, 0, Opts, n), FALSE);
    StSleep(300);
    StResult(St == STATUS_SUCCESS && LibNd6RaAccept(En) && StFindPrefixAddress(En, P4, &State) >= 0,
             "interface parameters: router discovery on takes the advertisement again", NULL);
    StDropPrefixAddress(En, P4);
    n = StOptPrefix(Opts, 0, 0, P4);
    StInject(Eth, StRa(R1, 0, 0, 0, Opts, n), FALSE);

    /* the table user mode reads */
    {
        ULONG Size = 8 * 1024;
        PTCP_IP_INTERFACE_HEADER Table = ExAllocatePoolWithTag(NonPagedPool, Size, ST_TAG);
        PTCP_IP_INTERFACE_ROW Rows;
        ULONG Dad = 99, Rd = 99, Flags = 0;

        Req.Fields = TCP_IPIF_SET_DAD_TRANSMITS | TCP_IPIF_SET_METRIC;
        Req.DadTransmits = 2;
        Req.Metric = 77;
        TCP6InterfaceConfigure(Eth, &Req);
        if (Table && TCPQueryIpInterfaces(Table, Size) <= Size)
        {
            Rows = (PTCP_IP_INTERFACE_ROW)(Table + 1);
            for (i = 0; i < Table->Count; i++)
            {
                if (Rows[i].IfIndex == Eth->Index)
                {
                    Dad = Rows[i].Ip6DadTransmits;
                    Rd = Rows[i].Ip6RouterDiscovery;
                    Flags = Rows[i].Flags;
                    n = Rows[i].Ip6Metric;
                }
            }
        }
        if (Table)
            ExFreePoolWithTag(Table, ST_TAG);
        _snprintf(Detail, sizeof(Detail), "flags 0x%lx dad %lu rd %lu metric %u", Flags, Dad, Rd, n);
        StResult((Flags & TCP_IPIF_ROW_IP6) && Dad == 2 && Rd == 1 && n == 77,
                 "interface parameters: the interface table reports the values in force", Detail);
        Req.DadTransmits = 1;
        Req.Metric = 0;
        TCP6InterfaceConfigure(Eth, &Req);
    }
}

static VOID
StTestRaExtras(PIP_INTERFACE Eth)
{
    struct netif *En = Eth->TCPContext;
    ip6_addr_t R1, R2, Dest;
    UCHAR Opts[640], Prefix[16], Mac1[6] = {0x02, 0x00, 0x00, 0x7a, 0x00, 0x01}, Mac2[6] = {0x02, 0x00, 0x00, 0x7a, 0x00, 0x02};
    UINT n;
    ULONG Life = 0, Count, i, k, Metric1, Metric2;
    CHAR Detail[200];
    BOOLEAN Ok;
    PTCP_IPV6_ROUTE_HEADER Routes;
    const TCP_IPV6_ROUTE_ROW *Row;
    UCHAR OldFlags, OldHop;
    static const UCHAR GoodNames[] = { 2, 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 1, 'a', 3, 'b', 'c', 'd', 0 };
    /* label of 64, label with a space, compression pointer, no terminating zero length, a name of 254 characters */
    static const UCHAR BadNames[] = { 64, 'a' };

    ip6addr_aton("fe80::7a:1", &R1);
    ip6addr_aton("fe80::7a:2", &R2);
    ip6addr_aton("2001:db8:7000::1", &Dest);

    /* --- DNSSL --- */
    n = StOptDnssl(Opts, 100, GoodNames, sizeof(GoodNames));
    StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
    Ok = StRaSuffixCount("st.example", &Life) == 1 && Life > 90 && Life <= 100 && StRaSuffixCount("a.bcd", NULL) == 1;
    _snprintf(Detail, sizeof(Detail), "st.example lifetime %lu", Life);
    StResult(Ok, "RA DNSSL: two names of one option are kept with their lifetime", Detail);

    n = StOptDnssl(Opts, 0, GoodNames, 12);       /* only st.example, lifetime 0 */
    StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
    StResult(StRaSuffixCount("st.example", NULL) == 0 && StRaSuffixCount("a.bcd", NULL) == 1,
             "RA DNSSL: lifetime 0 removes the name", NULL);

    n = StOptDnssl(Opts, 50, GoodNames, 12);
    StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
    StResult(StRaSuffixCount("st.example", NULL) == 1, "RA DNSSL: a name comes back", NULL);

    {
        /* names the stack must not keep, each in an option of its own (lifetime 60) */
        static const UCHAR Space[] = { 3, 'a', ' ', 'b', 0 };
        static const UCHAR Compressed[] = { 0xC0, 0x0C };
        /* a name with no zero length after it, up to the end of an option that has no padding (a shorter one is ended by the
           zero padding and is a good name) */
        static const UCHAR Unterminated[] = { 7, 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
        static const UCHAR Escape[] = { 4, 'e', '.', 'x', 'y', 0 };
        static const UCHAR NonAscii[] = { 2, 0xC3, 0xA9, 0 };
        UCHAR Long[300];
        UINT Total = 0, Used = 0, Label;
        ULONG Before = StRaSuffixCount(NULL, NULL), After;

        Total += StOptDnssl(Opts + Total, 60, Space, sizeof(Space));
        Total += StOptDnssl(Opts + Total, 60, Compressed, sizeof(Compressed));
        Total += StOptDnssl(Opts + Total, 60, Unterminated, sizeof(Unterminated));
        Total += StOptDnssl(Opts + Total, 60, Escape, sizeof(Escape));
        Total += StOptDnssl(Opts + Total, 60, NonAscii, sizeof(NonAscii));
        Total += StOptDnssl(Opts + Total, 60, BadNames, sizeof(BadNames));
        StInject(Eth, StRa(&R1, 0, 0, 0, Opts, Total), FALSE);
        After = StRaSuffixCount(NULL, NULL);
        _snprintf(Detail, sizeof(Detail), "%lu names before, %lu after", Before, After);
        StResult(Before == 2 && After == Before, "RA DNSSL: names with a space, a compression pointer, a dot inside a label, no end, "
                 "a non-ASCII character or a label of 64 are not kept", Detail);

        /* a name of 254 characters (five labels of 50) */
        for (Label = 0; Label < 5; Label++)
        {
            Long[Used++] = 50;
            RtlFillMemory(Long + Used, 50, (UCHAR)('a' + Label));
            Used += 50;
        }
        Long[Used++] = 0;
        Total = StOptDnssl(Opts, 60, Long, Used);
        StInject(Eth, StRa(&R1, 0, 0, 0, Opts, Total), FALSE);
        After = StRaSuffixCount(NULL, NULL);
        StResult(After == Before, "RA DNSSL: a name over 253 characters is not kept", NULL);
    }
    /* remove what the test added */
    n = StOptDnssl(Opts, 0, GoodNames, sizeof(GoodNames));
    StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
    StResult(StRaSuffixCount("st.example", NULL) == 0 && StRaSuffixCount("a.bcd", NULL) == 0,
             "RA DNSSL: both names removed again", NULL);

    /* --- route information --- */
    {
        ip6_addr_t Pfx;

        ip6addr_aton("2001:db8:7000::", &Pfx);
        RtlCopyMemory(Prefix, Pfx.addr, 16);
    }
    n = StOptSlla(Opts, Mac1);
    n += StOptRio(Opts + n, 2, 48, 1, 300, Prefix);                /* high preference */
    StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
    Routes = StRoutes(&Count);
    Row = Routes ? StFindRoute(Routes, Prefix, 48, (const UCHAR *)R1.addr) : NULL;
    Ok = Row && Row->Origin == 3 && (Row->Flags & TCP_IPV6_ROUTE_FROM_RA) && Row->Metric == 128 && Row->ValidLifetime > 290 &&
         Row->ValidLifetime <= 300 && Row->IfIndex == Eth->Index;
    _snprintf(Detail, sizeof(Detail), "%s, metric %lu origin %lu valid %lu", Row ? "row found" : "no row",
              Row ? Row->Metric : 0, Row ? Row->Origin : 0, Row ? Row->ValidLifetime : 0);
    StResult(Ok, "RA route information: a /48 through the advertising router, origin router advertisement, high preference", Detail);
    if (Routes)
        ExFreePoolWithTag(Routes, ST_TAG);

    LOCK_TCPIP_CORE();
    Ok = LibIp6Route(NULL, &Dest) == En;
    {
        const ip6_addr_t *Gw;

        Gw = LibNd6GetGw(En, &Dest);
        Ok = Ok && Gw && ip6_addr_zoneless_eq(Gw, &R1);
    }
    UNLOCK_TCPIP_CORE();
    StResult(Ok, "RA route information: the stack routes by it (interface and next hop of a destination in the prefix)", NULL);

    /* a refresh with another preference moves the metric, not the number of routes */
    n = StOptSlla(Opts, Mac1);
    n += StOptRio(Opts + n, 2, 48, 3, 300, Prefix);                /* low */
    StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
    Routes = StRoutes(&Count);
    Row = Routes ? StFindRoute(Routes, Prefix, 48, (const UCHAR *)R1.addr) : NULL;
    Ok = Row && Row->Metric == 512;
    if (Routes)
        ExFreePoolWithTag(Routes, ST_TAG);
    StResult(Ok, "RA route information: a refresh with low preference changes the metric", NULL);

    /* ignored: reserved preference, a /100 in an option of 2 units, a /8 prefix longer option of 4 units (not built) */
    n = StOptRio(Opts, 2, 100, 0, 300, Prefix);
    Prefix[8] = 0x11;
    n += StOptRio(Opts + n, 2, 48, 2, 300, Prefix);                /* preference 10 = reserved */
    Prefix[8] = 0;
    {
        UCHAR Other[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x77, 0x01 };

        n += StOptRio(Opts + n, 2, 48, 2, 300, Other);
        StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
        Routes = StRoutes(&Count);
        Ok = Routes && !StFindRoute(Routes, Other, 48, NULL) && !StFindRoute(Routes, NULL, 100, NULL);
        if (Routes)
            ExFreePoolWithTag(Routes, ST_TAG);
        StResult(Ok, "RA route information: the reserved preference value and a prefix longer than the option holds are ignored", NULL);
    }

    /* lifetime 0 removes it */
    n = StOptRio(Opts, 2, 48, 3, 0, Prefix);
    StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
    Routes = StRoutes(&Count);
    Ok = Routes && !StFindRoute(Routes, Prefix, 48, NULL);
    if (Routes)
        ExFreePoolWithTag(Routes, ST_TAG);
    StResult(Ok, "RA route information: lifetime 0 removes the route", NULL);

    /* at most 32: 40 different prefixes, the table keeps 32 of this router's */
    for (k = 0; k < 40; k++)
    {
        UCHAR P[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x7e, 0x00 };

        P[5] = (UCHAR)k;
        n = StOptRio(Opts, 2, 48, 0, 600, P);
        StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
    }
    Routes = StRoutes(&Count);
    for (i = 0, k = 0; Routes && i < Routes->Count; i++)
    {
        const TCP_IPV6_ROUTE_ROW *Rows = (const TCP_IPV6_ROUTE_ROW *)(Routes + 1);

        if ((Rows[i].Flags & TCP_IPV6_ROUTE_FROM_RA) && Rows[i].PrefixLength == 48 && Rows[i].Prefix[4] == 0x7e)
            k++;
    }
    _snprintf(Detail, sizeof(Detail), "%lu route information routes kept of 40 sent", k);
    StResult(Routes && k == 32, "RA route information: no more than 32 are kept", Detail);
    /* remove them again */
    for (i = 0; i < 40; i++)
    {
        UCHAR P[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x7e, 0x00 };

        P[5] = (UCHAR)i;
        n = StOptRio(Opts, 2, 48, 0, 0, P);
        StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
    }
    if (Routes)
        ExFreePoolWithTag(Routes, ST_TAG);

    /* --- default router preference: two routers with a source link-layer address are reachable at once --- */
    ip6addr_aton("2001:db8:7100::7", &Dest);
    {
        const u8_t *Hw = NULL;
        err_t Err;

        n = StOptSlla(Opts, Mac1);
        StInject(Eth, StRa(&R1, 0, 0x18, 1800, Opts, n), FALSE);       /* r1: low */
        n = StOptSlla(Opts, Mac2);
        StInject(Eth, StRa(&R2, 0, 0x08, 1800, Opts, n), FALSE);       /* r2: high */
        LOCK_TCPIP_CORE();
        Err = nd6_get_next_hop_addr_or_queue(En, NULL, &Dest, &Hw);
        Ok = Err == ERR_OK && Hw && StSame(Hw, Mac2, 6);
        UNLOCK_TCPIP_CORE();
        StResult(Ok, "router preference: the high preference router is the next hop of a destination off the link",
                 Err == ERR_OK ? (Hw && StSame(Hw, Mac2, 6) ? "r2" : "another router") : "no next hop");

        /* r1 becomes high, r2 low: the next hops lwIP kept are found again */
        n = StOptSlla(Opts, Mac1);
        StInject(Eth, StRa(&R1, 0, 0x08, 1800, Opts, n), FALSE);
        n = StOptSlla(Opts, Mac2);
        StInject(Eth, StRa(&R2, 0, 0x18, 1800, Opts, n), FALSE);
        Hw = NULL;
        LOCK_TCPIP_CORE();
        Err = nd6_get_next_hop_addr_or_queue(En, NULL, &Dest, &Hw);
        Ok = Err == ERR_OK && Hw && StSame(Hw, Mac1, 6);
        UNLOCK_TCPIP_CORE();
        StResult(Ok, "router preference: a changed preference moves the destination to the other router", NULL);

        Routes = StRoutes(&Count);
        Row = Routes ? StFindRoute(Routes, NULL, 0, (const UCHAR *)R1.addr) : NULL;
        Metric1 = Row ? Row->Metric : 0;
        Row = Routes ? StFindRoute(Routes, NULL, 0, (const UCHAR *)R2.addr) : NULL;
        Metric2 = Row ? Row->Metric : 0;
        if (Routes)
            ExFreePoolWithTag(Routes, ST_TAG);
        _snprintf(Detail, sizeof(Detail), "metrics: r1 %lu, r2 %lu", Metric1, Metric2);
        StResult(Metric1 == 128 && Metric2 == 512, "router preference: the route table shows the metrics of the preferences", Detail);

        /* r1 medium; r2 says high with router lifetime 0, a preference the receiver ignores (RFC 4191 2.2): r2 is not
           the next hop for as long as its entry is there (a medium router of the link, r1 or QEMU's, is) */
        n = StOptSlla(Opts, Mac1);
        StInject(Eth, StRa(&R1, 0, 0x00, 1800, Opts, n), FALSE);
        n = StOptSlla(Opts, Mac2);
        StInject(Eth, StRa(&R2, 0, 0x08, 0, Opts, n), FALSE);
        Hw = NULL;
        LOCK_TCPIP_CORE();
        Err = nd6_get_next_hop_addr_or_queue(En, NULL, &Dest, &Hw);
        Ok = Err == ERR_OK && Hw && !StSame(Hw, Mac2, 6);
        UNLOCK_TCPIP_CORE();
        StResult(Ok, "router preference: a high preference with router lifetime 0 is ignored",
                 Err == ERR_OK ? (Hw && StSame(Hw, Mac2, 6) ? "r2" : Hw && StSame(Hw, Mac1, 6) ? "r1" : "another router") :
                 "no next hop");

        /* the routers go (lifetime 0) */
        n = StOptSlla(Opts, Mac1);
        StInject(Eth, StRa(&R1, 0, 0x08, 0, Opts, n), FALSE);
        n = StOptSlla(Opts, Mac2);
        StInject(Eth, StRa(&R2, 0, 0x18, 0, Opts, n), FALSE);
        StSleep(2500);
    }

    /* --- current hop limit, M and O flags --- */
    OldFlags = Eth->Ra6Flags;
    OldHop = Eth->Ra6HopLimit;
    n = StOptSlla(Opts, Mac1);
    StInject(Eth, StRa(&R1, 33, 0xC0, 0, Opts, n), FALSE);
    LOCK_TCPIP_CORE();
    Ok = Eth->Ra6HopLimit == 33 && LibIp6HopLimit(En, IP_DEFAULT_TTL) == 33 && LibIp6HopLimit(En, 64) == 64 &&
         LibIp6HopLimit(En, 255) == 255;
    UNLOCK_TCPIP_CORE();
    StResult(Ok, "RA current hop limit: 33 replaces the default 128 and nothing else", NULL);
    n = StOptSlla(Opts, Mac1);
    StInject(Eth, StRa(&R1, 0, 0xC0, 0, Opts, n), FALSE);
    StResult(Eth->Ra6HopLimit == 33, "RA current hop limit: 0 (unspecified) leaves it", NULL);

    {
        ULONG Size = 16 * 1024;
        PTCP_IPV6_TABLE_HEADER Table = ExAllocatePoolWithTag(NonPagedPool, Size, ST_TAG);
        PTCP_IPV6_INTERFACE_ROW Rows;
        ULONG Flags = 0, Hop = 0;

        if (Table && TCPQueryIpv6Table(Table, Size) <= Size)
        {
            Rows = (PTCP_IPV6_INTERFACE_ROW)(Table + 1);
            for (i = 0; i < Table->InterfaceCount; i++)
            {
                if (Rows[i].IfIndex == Eth->Index)
                {
                    Flags = Rows[i].Flags;
                    Hop = Rows[i].CurHopLimit;
                }
            }
        }
        if (Table)
            ExFreePoolWithTag(Table, ST_TAG);
        _snprintf(Detail, sizeof(Detail), "flags 0x%lx hop limit %lu", Flags, Hop);
        StResult((Flags & (TCP_IPV6_IF_RA_MANAGED | TCP_IPV6_IF_RA_OTHER)) == (TCP_IPV6_IF_RA_MANAGED | TCP_IPV6_IF_RA_OTHER) &&
                 Hop == 33, "RA M and O flags and the hop limit are in the interface row of the IPv6 table", Detail);
    }
    n = StOptSlla(Opts, Mac1);
    StInject(Eth, StRa(&R1, 0, 0x40, 0, Opts, n), FALSE);
    StResult(Eth->Ra6Flags == TCP_IPV6_IF_RA_OTHER, "RA M and O flags: the next advertisement replaces them (O only)", NULL);
    n = StOptSlla(Opts, Mac1);
    StInject(Eth, StRa(&R1, 0, 0x00, 0, Opts, n), FALSE);
    StResult(Eth->Ra6Flags == 0, "RA M and O flags: both off again", NULL);
    LOCK_TCPIP_CORE();
    Eth->Ra6Flags = OldFlags;
    Eth->Ra6HopLimit = OldHop;
    UNLOCK_TCPIP_CORE();

    /* --- a prefix advertised again with preferred lifetime 0 --- */
    {
        UCHAR P[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x70, 0x02 };
        u8_t State = 0;
        ULONG Pref = 0xDEAD, Size = 16 * 1024;
        s8_t Found = -1;
        PTCP_IPV6_TABLE_HEADER Table;
        PTCP_IPV6_ADDRESS_ROW Addr;

        n = StOptSlla(Opts, Mac1);
        n += StOptPrefix(Opts + n, 3600, 1800, P);
        StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
        for (i = 0; i < 100; i++)
        {
            LOCK_TCPIP_CORE();
            for (k = 1; k < LWIP_IPV6_NUM_ADDRESSES; k++)
            {
                /* the address stateless autoconfiguration formed, not its temporary address (temp6.c) */
                if (!ip6_addr_isinvalid(netif_ip6_addr_state(En, (s8_t)k)) && StSame(netif_ip6_addr(En, (s8_t)k)->addr, P, 8) &&
                    !TCP6TemporarySlot(En, (s8_t)k))
                {
                    Found = (s8_t)k;
                    State = netif_ip6_addr_state(En, Found);
                }
            }
            UNLOCK_TCPIP_CORE();
            if (Found >= 0 && ip6_addr_ispreferred(State))
                break;
            StSleep(100);
        }
        StResult(Found >= 0 && ip6_addr_ispreferred(State), "prefix change: the address of an advertised prefix becomes preferred", NULL);

        if (Found >= 0)
        {
            n = StOptSlla(Opts, Mac1);
            n += StOptPrefix(Opts + n, 0, 0, P);                /* valid 0, preferred 0 (the valid lifetime stays: RFC 4862 5.5.3 e) */
            StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
            LOCK_TCPIP_CORE();
            State = netif_ip6_addr_state(En, Found);
            Pref = netif_ip6_addr_pref_life(En, Found);
            Ok = ip6_addr_isdeprecated(State) && Pref == 0 && netif_ip6_addr_valid_life(En, Found) > 3000;
            UNLOCK_TCPIP_CORE();
            _snprintf(Detail, sizeof(Detail), "state 0x%x preferred lifetime %lu", (UINT)State, Pref);
            StResult(Ok, "prefix change: preferred lifetime 0 deprecates the address at once and keeps its valid lifetime", Detail);

            Table = ExAllocatePoolWithTag(NonPagedPool, Size, ST_TAG);
            Pref = 0xDEAD;
            State = 0;
            if (Table && TCPQueryIpv6Table(Table, Size) <= Size)
            {
                Addr = (PTCP_IPV6_ADDRESS_ROW)((PTCP_IPV6_INTERFACE_ROW)(Table + 1) + Table->InterfaceCount);
                for (i = 0; i < Table->AddressCount; i++)
                {
                    if (StSame(Addr[i].Address, P, 8) && Addr[i].SuffixOrigin != 5)
                    {
                        Pref = Addr[i].PreferredLifetime;
                        State = (u8_t)Addr[i].DadState;
                    }
                }
            }
            if (Table)
                ExFreePoolWithTag(Table, ST_TAG);
            _snprintf(Detail, sizeof(Detail), "dad state %u preferred lifetime %lu", (UINT)State, Pref);
            StResult(State == 3 && Pref == 0, "prefix change: the address table reports Deprecated and a preferred lifetime of 0", Detail);
        }

        /* take the test addresses (with a temporary one) and the on-link prefix away */
        n = StOptPrefix(Opts, 0, 0, P);
        StInject(Eth, StRa(&R1, 0, 0, 0, Opts, n), FALSE);
        LOCK_TCPIP_CORE();
        for (k = 1; k < LWIP_IPV6_NUM_ADDRESSES; k++)
        {
            if (!ip6_addr_isinvalid(netif_ip6_addr_state(En, (s8_t)k)) && StSame(netif_ip6_addr(En, (s8_t)k)->addr, P, 8))
            {
                netif_ip6_addr_set_state(En, (s8_t)k, IP6_ADDR_INVALID);
                netif_ip6_addr_set_valid_life(En, (s8_t)k, 0);
                netif_ip6_addr_set_pref_life(En, (s8_t)k, 0);
            }
        }
        UNLOCK_TCPIP_CORE();
    }

    StTestInterfaceParams(Eth, &R1, Mac1);

    StPrint("tables: neighbours %d, destinations %d, prefixes %d, routers %d; entry sizes %u, %u, %u, %u bytes",
            LWIP_ND6_NUM_NEIGHBORS, LWIP_ND6_NUM_DESTINATIONS, LWIP_ND6_NUM_PREFIXES, LWIP_ND6_NUM_ROUTERS,
            (UINT)sizeof(struct nd6_neighbor_cache_entry), (UINT)sizeof(struct nd6_destination_cache_entry),
            (UINT)sizeof(struct nd6_prefix_list_entry), (UINT)sizeof(struct nd6_router_list_entry));
}

/* ---- temporary addresses (temp6.c, RFC 8981) ---- */

/* The slots of En in the 64-bit prefix P (core lock held): the public address's (*Public, -1: none) and the temporary
   ones (Temp[*Count]) */
static VOID
StPrefixSlots(struct netif *En, const UCHAR *P, s8_t *Public, s8_t *Temp, ULONG *Count)
{
    s8_t k;

    *Public = -1;
    *Count = 0;
    for (k = 1; k < LWIP_IPV6_NUM_ADDRESSES; k++)
    {
        if (ip6_addr_isinvalid(netif_ip6_addr_state(En, k)) || !StSame(netif_ip6_addr(En, k)->addr, P, 8))
            continue;
        if (TCP6TemporarySlot(En, k))
            Temp[(*Count)++] = k;
        else
            *Public = k;
    }
}

/* The row of Address in the address table: its origins; FALSE: no row */
static BOOLEAN
StAddressRow(const ip6_addr_t *Address, PULONG PrefixOrigin, PULONG SuffixOrigin, PULONG PrefixLength)
{
    ULONG Size = 16 * 1024, i;
    PTCP_IPV6_TABLE_HEADER Table = ExAllocatePoolWithTag(NonPagedPool, Size, ST_TAG);
    PTCP_IPV6_ADDRESS_ROW Addr;
    BOOLEAN Found = FALSE;

    if (!Table)
        return FALSE;
    if (TCPQueryIpv6Table(Table, Size) <= Size)
    {
        Addr = (PTCP_IPV6_ADDRESS_ROW)((PTCP_IPV6_INTERFACE_ROW)(Table + 1) + Table->InterfaceCount);
        for (i = 0; i < Table->AddressCount && !Found; i++)
        {
            if (StSame(Addr[i].Address, Address->addr, 16))
            {
                *PrefixOrigin = Addr[i].PrefixOrigin;
                *SuffixOrigin = Addr[i].SuffixOrigin;
                *PrefixLength = Addr[i].PrefixLength;
                Found = TRUE;
            }
        }
    }
    ExFreePoolWithTag(Table, ST_TAG);
    return Found;
}

static VOID
StTestTemporary(PIP_INTERFACE Eth)
{
    struct netif *En = Eth->TCPContext;
    UCHAR Opts[64], P[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x70, 0x09 }, Mac[6] = { 0x02, 0x00, 0x00, 0x7a, 0x00, 0x09 };
    ip6_addr_t R, Dest, First, Second, Now, Stable;
    s8_t Public = -1, Temp[LWIP_IPV6_NUM_ADDRESSES], k;
    ULONG Count = 0, i, n, Valid = 0, Pref = 0, MaxPref, PrefixOrigin = 0, SuffixOrigin = 0, PrefixLength = 0;
    u8_t State = 0, NewPreferred = 0;
    const ip_addr_t *Source;
    CHAR Text[IP6ADDR_STRLEN_MAX], Text2[IP6ADDR_STRLEN_MAX], Detail[220];
    BOOLEAN Ok, Same;
    UCHAR Counter;

    ip6addr_aton("fe80::7a:9", &R);
    ip6addr_aton("2001:db8:7009::99", &Dest);

    n = StOptSlla(Opts, Mac);
    n += StOptPrefix(Opts + n, 3600, 1800, P);
    StInject(Eth, StRa(&R, 0, 0, 0, Opts, n), FALSE);

    if (!TCP6UseTemporaryAddresses)
    {
        StSleep(3000);
        LOCK_TCPIP_CORE();
        StPrefixSlots(En, P, &Public, Temp, &Count);
        UNLOCK_TCPIP_CORE();
        _snprintf(Detail, sizeof(Detail), "public slot %d, %lu temporary", (int)Public, Count);
        StResult(Public >= 0 && Count == 0, "temporary: UseTemporaryAddresses=0, a SLAAC prefix gets no temporary address", Detail);
        goto cleanup;
    }

    /* --- one temporary address per prefix, preferred, with a random identifier --- */
    for (i = 0; i < 50; i++)
    {
        LOCK_TCPIP_CORE();
        StPrefixSlots(En, P, &Public, Temp, &Count);
        Ok = Public >= 0 && ip6_addr_ispreferred(netif_ip6_addr_state(En, Public)) && Count == 1 &&
             ip6_addr_ispreferred(netif_ip6_addr_state(En, Temp[0]));
        UNLOCK_TCPIP_CORE();
        if (Ok)
            break;
        StSleep(100);
    }
    _snprintf(Detail, sizeof(Detail), "after %lu ms: public slot %d, %lu temporary", i * 100, (int)Public, Count);
    StResult(Ok, "temporary: a SLAAC prefix gets one temporary address next to its public one, both preferred", Detail);
    if (!Ok)
        goto cleanup;

    MaxPref = TCP6TempMaxPreferred - TCP6TempDesync;
    LOCK_TCPIP_CORE();
    ip6_addr_copy(First, *netif_ip6_addr(En, Temp[0]));
    ip6_addr_copy(Stable, *netif_ip6_addr(En, Public));
    Valid = netif_ip6_addr_valid_life(En, Temp[0]);
    Pref = netif_ip6_addr_pref_life(En, Temp[0]);
    Same = FALSE;
    for (Counter = 0; Counter <= 3; Counter++)
    {
        ip6_addr_t Want;

        if (TCP6StableAddress(En, (const ip6_addr_t *)&Stable, Counter, &Want) && ip6_addr_zoneless_eq(&Want, &First))
            Same = TRUE;
    }
    Source = ip6_select_source_address(En, &Dest);
    UNLOCK_TCPIP_CORE();
    ip6addr_ntoa_r(&First, Text, sizeof(Text));
    ip6addr_ntoa_r(&Stable, Text2, sizeof(Text2));
    _snprintf(Detail, sizeof(Detail), "temporary %s public %s; valid %lu (<= 3600), preferred %lu (<= min(1800, %lu))", Text, Text2,
              Valid, Pref, MaxPref);
    StResult(!ip6_addr_zoneless_eq(&First, &Stable) && !Same && Valid <= 3600 && Valid >= 3590 && Pref <= min(1800, MaxPref) &&
             Pref + 10 >= min(1800, MaxPref),
             "temporary: its identifier is not the stable one, its lifetimes are the prefix's within the temporary maximums", Detail);

    Ok = StAddressRow(&First, &PrefixOrigin, &SuffixOrigin, &PrefixLength) && PrefixOrigin == 4 && SuffixOrigin == 5 &&
         PrefixLength == 64;
    _snprintf(Detail, sizeof(Detail), "prefix origin %lu, suffix origin %lu, /%lu", PrefixOrigin, SuffixOrigin, PrefixLength);
    StResult(Ok, "temporary: the address table reports RouterAdvertisement / Random", Detail);
    Ok = StAddressRow(&Stable, &PrefixOrigin, &SuffixOrigin, &PrefixLength) && PrefixOrigin == 4 && SuffixOrigin == 4;
    _snprintf(Detail, sizeof(Detail), "prefix origin %lu, suffix origin %lu", PrefixOrigin, SuffixOrigin);
    StResult(Ok, "temporary: the public address stays RouterAdvertisement / Link", Detail);

    ip6addr_ntoa_r(Source ? ip_2_ip6(Source) : &Dest, Text2, sizeof(Text2));
    StResult(Source && ip6_addr_zoneless_eq(ip_2_ip6(Source), &First),
             "temporary: source address selection prefers it (RFC 6724 rule 7)", Source ? Text2 : "no source");

    /* --- regeneration RegenerateTime before it is deprecated, and DAD of the new one --- */
    LOCK_TCPIP_CORE();
    Ok = TCP6TemporaryAge(En, Temp[0], MaxPref > TCP6TempRegenerate ? MaxPref - TCP6TempRegenerate : 0);
    UNLOCK_TCPIP_CORE();
    k = -1;
    for (i = 0; Ok && i < 40 && k < 0; i++)
    {
        StSleep(100);
        LOCK_TCPIP_CORE();
        StPrefixSlots(En, P, &Public, Temp, &Count);
        for (n = 0; n < Count; n++)
        {
            if (!ip6_addr_zoneless_eq(netif_ip6_addr(En, Temp[n]), &First) &&
                ip6_addr_istentative(netif_ip6_addr_state(En, Temp[n])))
            {
                k = Temp[n];
                ip6_addr_copy(Second, *netif_ip6_addr(En, k));
            }
        }
        UNLOCK_TCPIP_CORE();
    }
    _snprintf(Detail, sizeof(Detail), "after %lu ms, %lu temporary addresses", i * 100, Count);
    StResult(k >= 0, "temporary: a new one is made RegenerateTime before the current one is deprecated", Detail);
    if (k < 0)
        goto cleanup;

    /* another node has the new one: it gets another random identifier and DAD again */
    StInject(Eth, StNa(&R, &Second), FALSE);
    LOCK_TCPIP_CORE();
    ip6_addr_copy(Now, *netif_ip6_addr(En, k));
    State = netif_ip6_addr_state(En, k);
    Ok = TCP6TemporarySlot(En, k) && !ip6_addr_zoneless_eq(&Now, &Second) && StSame(Now.addr, P, 8) && ip6_addr_istentative(State);
    UNLOCK_TCPIP_CORE();
    ip6addr_ntoa_r(&Now, Text, sizeof(Text));
    _snprintf(Detail, sizeof(Detail), "now %s state 0x%x", Text, (UINT)State);
    StResult(Ok, "temporary: a DAD conflict gives it a new random identifier, tentative again", Detail);

    /* the old one is deprecated when its preferred lifetime ends and stays (valid); the new one is preferred and is the source */
    for (i = 0; i < 100; i++)
    {
        LOCK_TCPIP_CORE();
        StPrefixSlots(En, P, &Public, Temp, &Count);
        Ok = FALSE;
        State = 0;
        for (n = 0; n < Count; n++)
        {
            if (ip6_addr_zoneless_eq(netif_ip6_addr(En, Temp[n]), &First))
                State = netif_ip6_addr_state(En, Temp[n]);
        }
        NewPreferred = ip6_addr_ispreferred(netif_ip6_addr_state(En, k)) ? 1 : 0;
        Ok = Count == 2 && ip6_addr_isdeprecated(State) && NewPreferred;
        Source = ip6_select_source_address(En, &Dest);
        UNLOCK_TCPIP_CORE();
        if (Ok)
            break;
        StSleep(100);
    }
    _snprintf(Detail, sizeof(Detail), "after %lu ms: %lu temporary, old state 0x%x, new preferred %u", i * 100, Count, (UINT)State,
              (UINT)NewPreferred);
    StResult(Ok, "temporary: the old one is deprecated and kept, the new one preferred", Detail);
    LOCK_TCPIP_CORE();
    ip6_addr_copy(Now, *netif_ip6_addr(En, k));
    UNLOCK_TCPIP_CORE();
    StResult(Ok && Source && ip6_addr_zoneless_eq(ip_2_ip6(Source), &Now), "temporary: the source is the new one", NULL);

    /* --- the router deprecates the prefix: its temporary addresses follow, no new one is made --- */
    n = StOptSlla(Opts, Mac);
    n += StOptPrefix(Opts + n, 3600, 0, P);
    StInject(Eth, StRa(&R, 0, 0, 0, Opts, n), FALSE);
    StSleep(3000);
    LOCK_TCPIP_CORE();
    StPrefixSlots(En, P, &Public, Temp, &Count);
    Ok = Public >= 0 && ip6_addr_isdeprecated(netif_ip6_addr_state(En, Public)) && Count == 2;
    for (n = 0; n < Count; n++)
        Ok = Ok && ip6_addr_isdeprecated(netif_ip6_addr_state(En, Temp[n]));
    UNLOCK_TCPIP_CORE();
    _snprintf(Detail, sizeof(Detail), "%lu temporary", Count);
    StResult(Ok, "temporary: a prefix advertised with preferred lifetime 0 deprecates them, none is made", Detail);

cleanup:
    /* the test prefix and its addresses go */
    n = StOptPrefix(Opts, 0, 0, P);
    StInject(Eth, StRa(&R, 0, 0, 0, Opts, n), FALSE);
    LOCK_TCPIP_CORE();
    for (k = 1; k < LWIP_IPV6_NUM_ADDRESSES; k++)
    {
        if (!ip6_addr_isinvalid(netif_ip6_addr_state(En, k)) && StSame(netif_ip6_addr(En, k)->addr, P, 8))
        {
            netif_ip6_addr_set_state(En, k, IP6_ADDR_INVALID);
            netif_ip6_addr_set_valid_life(En, k, 0);
            netif_ip6_addr_set_pref_life(En, k, 0);
        }
    }
    UNLOCK_TCPIP_CORE();
}

/* ---- address slots (LWIP_IPV6_NUM_ADDRESSES, the temp6.c reserve) ---- */

/* Nanoseconds of one source address selection to Dest on En (core lock taken here), and how many of its addresses
   are valid then */
static ULONG
StSourceNs(struct netif *En, const ip6_addr_t *Dest, PULONG Valid)
{
    LARGE_INTEGER Start, End, Frequency;
    ULONG i, Sink = 0;
    s8_t j;

    LOCK_TCPIP_CORE();
    *Valid = 0;
    for (j = 0; j < LWIP_IPV6_NUM_ADDRESSES; j++)
    {
        if (ip6_addr_isvalid(netif_ip6_addr_state(En, j)))
            (*Valid)++;
    }
    Start = KeQueryPerformanceCounter(&Frequency);
    for (i = 0; i < 100000; i++)
        Sink += (ULONG)(ULONG_PTR)ip6_select_source_address(En, Dest);
    End = KeQueryPerformanceCounter(NULL);
    UNLOCK_TCPIP_CORE();
    if (!Sink)
        return 0;
    return (ULONG)((End.QuadPart - Start.QuadPart) * 1000000000 / Frequency.QuadPart / 100000);
}

/* The addresses of En in the first Bytes bytes of the prefix P (core lock taken here): stable, temporary, and free slots */
static VOID
StCountSlots(struct netif *En, const UCHAR *P, ULONG Bytes, PULONG Stable, PULONG Temps, PULONG Free)
{
    s8_t j;

    *Stable = *Temps = *Free = 0;
    LOCK_TCPIP_CORE();
    for (j = 1; j < LWIP_IPV6_NUM_ADDRESSES; j++)
    {
        if (ip6_addr_isinvalid(netif_ip6_addr_state(En, j)))
            (*Free)++;
        else if (StSame(netif_ip6_addr(En, j)->addr, P, Bytes))
        {
            if (TCP6TemporarySlot(En, j))
                (*Temps)++;
            else
                (*Stable)++;
        }
    }
    UNLOCK_TCPIP_CORE();
}

/* Prefixes advertised one by one, slowly (a stable address and, while room is left, a temporary one for each): no
   stable address is lost (the temporary ones give way), a temporary address is made only while at least
   TCP6_TEMP_RESERVE slots stay free afterwards, the table answer fits */
#define ST_SLOT_PREFIXES 9

static VOID
StTestSlots(PIP_INTERFACE Eth)
{
    struct netif *En = Eth->TCPContext;
    UCHAR Opts[64], P[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x71, 0x00 }, Mac[6] = { 0x02, 0x00, 0x00, 0x7a, 0x00, 0x0a };
    ip6_addr_t R, Dest;
    ULONG k, n, Stable = 0, Temps = 0, PrevTemps, FirstStable = 0, FirstTemps = 0, Free2 = 0, Free = 0, Others = 0, Expect, Valid1 = 0, Valid2 = 0, Ns1, Ns2, Size;
    CHAR Detail[260];
    s8_t j;
    BOOLEAN Ok, ReserveBroken = FALSE;

    StPrint("address slots: %d per interface; their arrays %u bytes (struct netif %u bytes), reserve %d for temporaries",
            LWIP_IPV6_NUM_ADDRESSES,
            (UINT)(sizeof(En->ip6_addr) + sizeof(En->ip6_addr_state) + sizeof(En->ip6_addr_valid_life) +
                   sizeof(En->ip6_addr_pref_life)), (UINT)sizeof(*En), TCP6_TEMP_RESERVE);

    ip6addr_aton("fe80::7a:a", &R);
    ip6addr_aton("2001:db8:7100::99", &Dest);

    LOCK_TCPIP_CORE();
    for (j = 1; j < LWIP_IPV6_NUM_ADDRESSES; j++)
    {
        if (!ip6_addr_isinvalid(netif_ip6_addr_state(En, j)))
            Others++;
    }
    UNLOCK_TCPIP_CORE();

    for (k = 0; k < ST_SLOT_PREFIXES; k++)
    {
        P[5] = (UCHAR)k;
        n = StOptSlla(Opts, Mac);
        n += StOptPrefix(Opts + n, 3600, 1800, P);
        StInject(Eth, StRa(&R, 0, 0, 0, Opts, n), FALSE);
        StSleep(1500);
        /* a temporary address is made only while more than the reserve stays free afterwards */
        PrevTemps = Temps;
        StCountSlots(En, P, 5, &Stable, &Temps, &Free);
        if (Temps > PrevTemps && Free < TCP6_TEMP_RESERVE)
            ReserveBroken = TRUE;
    }
    StSleep(3000);
    StCountSlots(En, P, 5, &Stable, &Temps, &Free);
    P[5] = 0;
    StCountSlots(En, P, 6, &FirstStable, &FirstTemps, &Free2);
    StCountSlots(En, P, 5, &Stable, &Temps, &Free);
    Expect = (LWIP_IPV6_NUM_ADDRESSES - 1 - Others) < ST_SLOT_PREFIXES ? (LWIP_IPV6_NUM_ADDRESSES - 1 - Others) : ST_SLOT_PREFIXES;
    /* the temporary addresses of the first prefixes gave way for the stable address of the last one */
    Ok = Stable == Expect && !ReserveBroken && (!TCP6UseTemporaryAddresses || Temps > 0 || Expect + Others >= LWIP_IPV6_NUM_ADDRESSES - 1) &&
         FirstStable == 1 && (!TCP6UseTemporaryAddresses || FirstTemps == 1);
    _snprintf(Detail, sizeof(Detail), "%lu prefixes: %lu stable (expected %lu), %lu temporary, %lu free, %lu other addresses, reserve %s; first prefix %lu + %lu",
              (ULONG)ST_SLOT_PREFIXES, Stable, Expect, Temps, Free, Others, ReserveBroken ? "broken" : "kept", FirstStable, FirstTemps);
    StResult(Ok, "slots: stable addresses all kept, temporary ones made only above the reserve, the newest give way for them", Detail);

    Size = TCPQueryIpv6Table(NULL, 0);
    _snprintf(Detail, sizeof(Detail), "table answer %lu bytes", Size);
    StResult(Size > 0 && Size < 0x10000, "slots: the address table answer is below its cap", Detail);

    Ns1 = StSourceNs(En, &Dest, &Valid1);

    /* the test prefixes go */
    for (k = 0; k < ST_SLOT_PREFIXES; k++)
    {
        P[5] = (UCHAR)k;
        n = StOptPrefix(Opts, 0, 0, P);
        StInject(Eth, StRa(&R, 0, 0, 0, Opts, n), FALSE);
    }
    LOCK_TCPIP_CORE();
    for (j = 1; j < LWIP_IPV6_NUM_ADDRESSES; j++)
    {
        if (!ip6_addr_isinvalid(netif_ip6_addr_state(En, j)) && StSame(netif_ip6_addr(En, j)->addr, P, 5))
        {
            netif_ip6_addr_set_state(En, j, IP6_ADDR_INVALID);
            netif_ip6_addr_set_valid_life(En, j, 0);
            netif_ip6_addr_set_pref_life(En, j, 0);
        }
    }
    UNLOCK_TCPIP_CORE();
    StSleep(1500);
    Ns2 = StSourceNs(En, &Dest, &Valid2);
    StPrint("source address selection: %lu ns with %lu valid addresses, %lu ns with %lu", Ns1, Valid1, Ns2, Valid2);
}

/* A temporary address that DAD keeps finding in use is duplicated after MaxDadAttempts new identifiers, holds its
   slot for TCP6TempDupHold seconds, then goes and the prefix gets a new temporary address */
static VOID
StTestDupHold(PIP_INTERFACE Eth)
{
    struct netif *En = Eth->TCPContext;
    UCHAR Opts[64], P[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x72, 0x00 }, Mac[6] = { 0x02, 0x00, 0x00, 0x7a, 0x00, 0x0b };
    ip6_addr_t R, Dup, Target;
    ULONG i, n, Temps = 0, OldHold = TCP6TempDupHold;
    s8_t j, DupSlot = -1;
    BOOLEAN Ok = FALSE, Found;
    u8_t State = 0;
    CHAR Detail[160];

    if (!TCP6UseTemporaryAddresses)
        return;
    ip6addr_aton("fe80::7a:b", &R);
    n = StOptSlla(Opts, Mac);
    n += StOptPrefix(Opts + n, 3600, 1800, P);
    StInject(Eth, StRa(&R, 0, 0, 0, Opts, n), FALSE);
    TCP6TempDupHold = 4;

    /* every new temporary address of the prefix is answered for by another node (a new one is tentative for a tick) */
    for (i = 0; i < 120 && DupSlot < 0; i++)
    {
        Found = FALSE;
        LOCK_TCPIP_CORE();
        for (j = 1; j < LWIP_IPV6_NUM_ADDRESSES; j++)
        {
            State = netif_ip6_addr_state(En, j);
            if (ip6_addr_isinvalid(State) || !StSame(netif_ip6_addr(En, j)->addr, P, 6) || !TCP6TemporarySlot(En, j))
                continue;
            if (ip6_addr_isduplicated(State))
                DupSlot = j;
            else if (ip6_addr_istentative(State))
            {
                ip6_addr_copy(Target, *netif_ip6_addr(En, j));
                Found = TRUE;
            }
        }
        UNLOCK_TCPIP_CORE();
        if (Found)
            StInject(Eth, StNa(&R, &Target), FALSE);
        StSleep(250);
    }
    if (DupSlot >= 0)
    {
        LOCK_TCPIP_CORE();
        ip6_addr_copy(Dup, *netif_ip6_addr(En, DupSlot));
        UNLOCK_TCPIP_CORE();
    }
    _snprintf(Detail, sizeof(Detail), "slot %d after %lu ms", (int)DupSlot, i * 250);
    StResult(DupSlot >= 0, "temporary: repeated DAD conflicts leave it duplicated", Detail);

    if (DupSlot >= 0)
    {
        /* it holds its slot for the hold time, then it goes and a new one is made for the prefix */
        for (i = 0; i < 200 && !Ok; i++)
        {
            StSleep(250);
            LOCK_TCPIP_CORE();
            Ok = FALSE;
            Temps = 0;
            for (j = 1; j < LWIP_IPV6_NUM_ADDRESSES; j++)
            {
                if (ip6_addr_isinvalid(netif_ip6_addr_state(En, j)) || !StSame(netif_ip6_addr(En, j)->addr, P, 6) ||
                    !TCP6TemporarySlot(En, j))
                    continue;
                Temps++;
                if (!ip6_addr_zoneless_eq(netif_ip6_addr(En, j), &Dup) && !ip6_addr_isduplicated(netif_ip6_addr_state(En, j)))
                    Ok = TRUE;
            }
            UNLOCK_TCPIP_CORE();
        }
        _snprintf(Detail, sizeof(Detail), "after %lu ms (hold %lu s), %lu temporary", i * 250, TCP6TempDupHold, Temps);
        StResult(Ok, "temporary: a duplicated one is dropped after its hold time and the prefix gets a new one", Detail);
    }
    TCP6TempDupHold = OldHold;

    /* the test prefix goes */
    n = StOptPrefix(Opts, 0, 0, P);
    StInject(Eth, StRa(&R, 0, 0, 0, Opts, n), FALSE);
    LOCK_TCPIP_CORE();
    for (j = 1; j < LWIP_IPV6_NUM_ADDRESSES; j++)
    {
        if (!ip6_addr_isinvalid(netif_ip6_addr_state(En, j)) && StSame(netif_ip6_addr(En, j)->addr, P, 6))
        {
            netif_ip6_addr_set_state(En, j, IP6_ADDR_INVALID);
            netif_ip6_addr_set_valid_life(En, j, 0);
            netif_ip6_addr_set_pref_life(En, j, 0);
        }
    }
    UNLOCK_TCPIP_CORE();
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
        StTestPtb(Eth, &LinkLocal);
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
    StTestStableIds(Eth);
    StTestRaExtras(Eth);
    StTestTemporary(Eth);
    StTestSlots(Eth);
    StTestDupHold(Eth);

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
