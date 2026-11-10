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

/* The send buffer stays 64K: it does not follow TCP_WND */
#define TCP_SND_BUF                     0xFFFF

#define TCP_MAXRTX                      8

#define TCP_SYNMAXRTX                   4

#define TCP_LISTEN_BACKLOG              1

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
