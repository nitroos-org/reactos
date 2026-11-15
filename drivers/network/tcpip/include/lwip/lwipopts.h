/*
   ------------------------------------
   ---------- Memory options ----------
   ------------------------------------
*/

/* This combo allows us to implement malloc, free, and realloc ourselves */
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1

/* Define LWIP_COMPAT_MUTEX if the port has no mutexes and binary semaphores
 should be used instead */
#define LWIP_COMPAT_MUTEX               1
#define LWIP_COMPAT_MUTEX_ALLOWED       1

#define MEM_ALIGNMENT                   4

/* The core lock is ours (sys_arch.c): it tracks its owner and keeps
   the owner from being suspended while it holds the lock */
#define LOCK_TCPIP_CORE()               sys_lock_tcpip_core()
#define UNLOCK_TCPIP_CORE()             sys_unlock_tcpip_core()

/* Received packets enter lwIP on the receive worker of their adapter, under
   the core lock, instead of being posted to the tcpip thread. tcpip_input is
   only called from those workers, at PASSIVE_LEVEL with no lock held */
#define LWIP_TCPIP_CORE_LOCKING_INPUT   1

/* A SYN can reopen a connection in TIME-WAIT (ip/lwip_glue/tcp.c) */
#define LWIP_HOOK_FILENAME              "lwip_hooks.h"
#define LWIP_HOOK_IP4_INPUT(p, inp)     LibTCPReopenTimeWait(p, inp)
#define LWIP_HOOK_TCP_ISN(local_ip, local_port, remote_ip, remote_port) \
    LibTCPNextIss(local_ip, local_port, remote_ip, remote_port)

#define LWIP_ARP                        0

#define ETH_PAD_SIZE                    2

#define IP_REASS_MAX_PBUFS              0xFFFFFFFF

#define IP_DEFAULT_TTL                  128

#define IP_SOF_BROADCAST                1

#define IP_SOF_BROADCAST_RECV           1

/* The IPv6 core (ip_addr_t is a tagged union). It is used only with Tcpip\Parameters\Ipv6Enable on
 * (ip/transport/tcp/if6.c); off, no interface has an IPv6 address and no IPv6 frame reaches lwIP */
#define LWIP_IPV6                       1
/* MLD (MLDv1, RFC 2710): the solicited-node groups of the addresses and the groups sockets joined (udp6.c) are
 * reported, queries answered, a done message sent on the last leave, so switches that snoop MLD forward them to us.
 * Ethernet interfaces only (NETIF_FLAG_MLD6, if6.c). The adapter's multicast list stays ours (if6.c, no
 * mld_mac_filter). No cyclic 100 ms timer: one timeout while a report is pending, none on an idle machine (mld6.c).
 * The random report delay comes from udp6.c, so lwIP's LWIP_RAND users (port numbers) do not change. With MLD,
 * ip6_input takes the groups MLD has (udp6.c joins a socket's group there): LWIP_HOOK_IP6_MCAST_ACCEPT below is
 * used only with LWIP_IPV6_MLD 0 */
#define LWIP_IPV6_MLD                   1
#define MLD6_TMR_ON_DEMAND              1
#define MLD6_RAND()                     LibMld6Random()
/* Router advertisement DNS servers (RFC 8106, up to 3 per advertisement) go to the stack's list for the resolver
 * (rdnss6.c); lwIP's own DNS client is not part of this tree */
#define LWIP_ND6_RDNSS_MAX_DNS_SERVERS  3
#define LWIP_HOOK_ND6_RDNSS(netif, addr, lifetime) LibTCPRdnss6Input(netif, addr, lifetime)
/* Stable random interface identifiers (RFC 7217, iid6.c): the SLAAC address of a prefix, and a new identifier
 * when DAD finds one in use (NitroOS hooks in nd6.c) */
#define LWIP_HOOK_ND6_SLAAC_ADDRESS(netif, prefix, addr) LibNd6SlaacAddress(netif, prefix, addr)
#define LWIP_HOOK_ND6_DAD_FAILED(netif, index) LibNd6DadFailed(netif, index)
/* The IPv6 counters (nd6info.c): every datagram that enters ip6_input */
#define LWIP_HOOK_IP6_INPUT(p, inp)     LibIp6CountInput(p, inp)
/* A router or on-link prefix that came or went is a route change for user mode (NotifyRouteChange2) */
#define LWIP_HOOK_ND6_ROUTES_CHANGED()  LibTCPRoutes6Changed()
/* The IPv6 route table (route6.c): the configured routes choose the interface and the next hop where they are the
 * best match; the ND timer ends their lifetimes (NitroOS hook in nd6.c) */
#define LWIP_HOOK_IP6_ROUTE(src, dest)  LibIp6Route(src, dest)
#define LWIP_HOOK_ND6_GET_GW(netif, dest) LibNd6GetGw(netif, dest)
#define LWIP_HOOK_ND6_TMR()             LibNd6Timer()
/* Configured addresses (addr6.c): router advertisements and the DAD of the link-local address leave them alone, and
 * one marked skip-as-source is not chosen as a source (NitroOS hooks in nd6.c and ip6.c) */
#define LWIP_HOOK_ND6_ADDR_CONFIGURED(netif, i) LibNd6AddrConfigured(netif, i)
#define LWIP_HOOK_IP6_SKIP_SOURCE(netif, i) LibIp6SkipSource(netif, i)
/* Address slots per interface: the link-local address, SLAAC addresses of the advertised prefixes, and configured
 * ones (lwIP's default is 3). A slot costs about 30 bytes per interface (address with zone, state, two lifetimes);
 * the loops over the slots are per datagram for the source and route choice (ip6.c), per interface */
#define LWIP_IPV6_NUM_ADDRESSES         8
/* Interface events: with IPv6 on, address changes set the adapter's multicast list (if6.c). Nothing listens
 * with it off */
#define LWIP_NETIF_EXT_STATUS_CALLBACK  1
/* Reassembly keeps its bookkeeping (a pointer and two offsets) in place of each fragment's 8-byte fragment
 * header; with 64-bit pointers it does not fit there, so it borrows room from the header before it instead
 * (ip6_frag.c asserts this once a second from ip6_reass_tmr otherwise) */
#define IPV6_FRAG_COPYHEADER            1
/* Fragments waiting for reassembly, over all IPv6 datagrams (IP_REASS_MAX_PBUFS stays the IPv4 one): a sender
 * that never completes its datagrams holds at most this many for IPV6_REASS_MAXAGE, and a 64K datagram in
 * 1280-byte fragments still fits */
#define IP6_REASS_MAX_PBUFS             128
/* A segment to an IPv6 listener is taken only if it came from this machine or passed the firewall (if6.c) */
#define LWIP_HOOK_TCP_INPACKET_PCB(pcb, hdr, optlen, opt1len, opt2, p) \
    (((pcb)->state == LISTEN && ip_current_is_v6()) ? LibTCPListenerInput6() : ERR_OK)
/* ICMPv6 error messages (destination unreachable, parameter problem...) are rate limited (if6.c) */
#define LWIP_HOOK_ICMP6_ERROR_ALLOWED() LibIcmp6ErrorAllowed()
/* NitroOS hooks in ip6_input (ip/transport/udp/udp6.c): UDP datagrams go to our datagram sockets (lwIP's UDP is
   off), and the multicast groups sockets joined are taken (only with LWIP_IPV6_MLD 0: MLD holds them otherwise) */
#define LWIP_HOOK_IP6_NEXTH_INPUT(p, inp, nexth) (LibIp6CountDelivered(p, inp, nexth), LibIp6NexthInput(p, inp, nexth))
#define LWIP_HOOK_IP6_MCAST_ACCEPT(inp, dest) LibIp6McastAccept(inp, dest)
#define LWIP_ICMP                       0

#define LWIP_RAW                        0

#define LWIP_UDP                        0

#define SO_REUSE                        1

#define SO_REUSE_RXTOALL                1

/* FIXME: These MSS and TCP Window definitions assume an MTU
 * of 1500. We need to add some code to lwIP which would allow us
 * to change these values based upon the interface we are
 * using. Currently ReactOS only supports Ethernet so we're
 * fine for now but it does need to be fixed later when we
 * add support for other transport mediums */
#define TCP_MSS                         1460
/* The loopback interface has an MTU of 16384: its connections use segments of 16344 bytes instead of
 * 11 segments of 1460 (each one a packet, a work item and an acknowledgement). An Ethernet connection
 * is still cut to its MTU (tcp_eff_send_mss_netif) */
#define TCP_MSS_LIMIT                   16344

/* The receive window is per connection (tcp_pcb.rcv_wnd_max). A connection starts with
 * TCP_WND_DEFAULT (what the SYN can announce); once AFD owns it, LibTCPSetReceiveWindow gives it the
 * window of its SO_RCVBUF, or LIBTCP_DEFAULT_WINDOW (2 MB) that autotunes up to TCP_WND (32 MB) if there
 * is none. Window scaling (shift 9: windows up to 32 MB, 512-byte steps) carries windows above 64K */
#define LWIP_WND_SCALE                  1

#define TCP_RCV_SCALE                   9

#define TCP_WND                         0x1FFFE00

#define TCP_WND_DEFAULT                 0x10000

/* The send buffer does not follow TCP_WND. It holds a whole AFD send window (64K, what SO_SNDBUF reads on
 * Windows) and a little more, so a window goes down in one TdiSend. At 0xFFFF a window left one byte over,
 * which stayed in flight until the next ACK and made the next non-blocking send fail as WSAEWOULDBLOCK.
 * (lwIP wants TCP_SNDLOWAT, half of it, below 0xFFFF - 4 * TCP_MSS) */
#define TCP_SND_BUF                     0x12000

#define TCP_MAXRTX                      8

#define TCP_SYNMAXRTX                   4

#define TCP_LISTEN_BACKLOG              1

/* thousands of connections sit in TIME-WAIT while a client loop runs: find them by hash, not by walking the list */
#define LWIP_TCP_TW_HASH                1

#define LWIP_TCP_TIMESTAMPS             1

#define LWIP_SOCKET                     0

#define LWIP_NETCONN                    0

#define LWIP_STATS                      0

#define ICMP_STATS                      0

/*
   ---------------------------------------
   ---------- Debugging options ----------
   ---------------------------------------
*/

/**
 * TCP_DEBUG: Enable debugging for TCP.
 */
/* The debug checks walk every TCP control block on each segment and each removal (tcp_pcbs_sane);
 * with thousands of connections in TIME-WAIT they slowed the connect rate of a loop to a fifth */
#if DBG
#define TCP_DEBUG                       LWIP_DBG_ON
#else
#define TCP_DEBUG                       LWIP_DBG_OFF
#endif
