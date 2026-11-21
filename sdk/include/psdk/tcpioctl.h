/*
 * tcpioctl.h
 *
 * Set and query ioctl constants for tcpip.sys
 *
 * Contributors:
 *   Created by Art Yerkes (ayerkes@speakeasy.net) from
 *    drivers/net/tcpip/include/ticonsts.h
 *
 * THIS SOFTWARE IS NOT COPYRIGHTED
 *
 * This source code is offered for use in the public domain. You may
 * use, modify or distribute it freely.
 *
 * This code is distributed in the hope that it will be useful but
 * WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 * DISCLAIMED. This includes but is not limited to warranties of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef _TCPIOCTL_H
#define _TCPIOCTL_H

#define DD_TCP_DEVICE_NAME L"\\Device\\Tcp"

/* TCP/UDP/RawIP IOCTL code definitions */

#define FSCTL_TCP_BASE     FILE_DEVICE_NETWORK

#define _TCP_CTL_CODE(Function, Method, Access) \
    CTL_CODE(FSCTL_TCP_BASE, Function, Method, Access)

#define IOCTL_TCP_QUERY_INFORMATION_EX \
    _TCP_CTL_CODE(0, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_TCP_SET_INFORMATION_EX \
    _TCP_CTL_CODE(1, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUERY_IP_HW_ADDRESS \
    _TCP_CTL_CODE(15, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SET_IP_ADDRESS \
    _TCP_CTL_CODE(14, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_DELETE_IP_ADDRESS \
    _TCP_CTL_CODE(16, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#ifdef __REACTOS__
/* Pends until the address table changes. Input (optional): a ULONG mask of the address families the request waits
   for, TCP_CHANGE_FAMILY_IPV4 and/or TCP_CHANGE_FAMILY_IPV6; without input it waits for IPv4 changes only, as
   NotifyAddrChange and an AF_INET socket do on Windows. Output (optional): a ULONG with the families that changed
   (the part of the input mask), written when the output buffer holds it */
#define IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST \
    _TCP_CTL_CODE(0x17, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TCP_CHANGE_FAMILY_IPV4  0x1
#define TCP_CHANGE_FAMILY_IPV6  0x2
/* Completes the waiting IOCTL_IP_ADDCHANGE_NOTIFY_REQUESTs of the file object with STATUS_CANCELLED */
#define IOCTL_IP_ADDCHANGE_CANCEL_REQUEST \
    _TCP_CTL_CODE(0x18, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* Pends until the route table changes; input and output as for IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST (IPv4 only without
   input); the cancel request above cancels it too */
#define IOCTL_IP_ROUTECHANGE_NOTIFY_REQUEST \
    _TCP_CTL_CODE(0x19, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* Adds, changes or removes a unicast IPv6 address of an interface: input one TCP_IPV6_ADDRESS_REQUEST, no output.
   Administrators only, as IOCTL_SET_IP_ADDRESS */
#define IOCTL_IP6_ADDRESS_CONFIG \
    _TCP_CTL_CODE(0x1A, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* Adds, changes or removes a route of the IPv6 route table: input one TCP_IPV6_ROUTE_REQUEST, no output.
   Administrators only, as IOCTL_SET_IP_ADDRESS */
#define IOCTL_IP6_ROUTE_CONFIG \
    _TCP_CTL_CODE(0x1B, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* Sets per-interface parameters of the IPv4 or the IPv6 interface (SetIpInterfaceEntry): input one
   TCP_IP_INTERFACE_REQUEST, no output. Administrators only, as IOCTL_SET_IP_ADDRESS */
#define IOCTL_IP_INTERFACE_CONFIG \
    _TCP_CTL_CODE(0x1C, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* Asks the link of an interface for the link address of an IPv6 neighbour with neighbour solicitations alone (no
   data packet): input one TCP_IPV6_SOLICIT_REQUEST, no output. Not privileged, as ResolveIpNetEntry2 is not. An
   address without a neighbour cache entry gets an incomplete one that is asked for up to three times, one second
   apart; the answer shows in the neighbour table (IP_IPV6_ND_ENTRY_ID) */
#define IOCTL_IP6_SOLICIT \
    _TCP_CTL_CODE(0x1D, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _TCP_IPV6_SOLICIT_REQUEST
{
    ULONG IfIndex;
    UCHAR Address[16];
} TCP_IPV6_SOLICIT_REQUEST, *PTCP_IPV6_SOLICIT_REQUEST;

/* Reads the IPv6 prefix policy table (Tcpip6\Parameters\PrefixPolicies, see sdk/include/reactos/addrsel.h) again
   for source address selection: no input, no output. Administrators only, as the table can only be changed by
   them; iphlpapi's NitroSetPrefixPolicies sends it after every change */
#define IOCTL_IP6_POLICY_RELOAD \
    _TCP_CTL_CODE(0x1E, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#endif

#define IOCTL_ICMP_ECHO_REQUEST \
    _TCP_CTL_CODE(0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IF_MIB_STATS_ID                 1
#define IP_MIB_STATS_ID                 1
#define IP_MIB_ARPTABLE_ENTRY_ID        0x101
#define IP_MIB_ADDRTABLE_ENTRY_ID       0x102
#define IP_INTFC_INFO_ID                0x103
/* Non public TOIID used to query modules info */
#ifdef __REACTOS__
#define IP_SPECIFIC_MODULE_ENTRY_ID     0x110
/* Non public TOIID: the connections in TIME_WAIT, which have no address file and so no entity of
   their own. Asked of the TCP entity (CO_TL_ENTITY, instance 0); the answer is an array of
   TCP_TIMEWAIT_ROW, with the addresses and ports in network byte order */
#define IP_TCP_TIMEWAIT_ENTRY_ID        0x111

typedef struct _TCP_TIMEWAIT_ROW
{
    ULONG LocalAddr;
    ULONG LocalPort;
    ULONG RemoteAddr;
    ULONG RemotePort;
} TCP_TIMEWAIT_ROW, *PTCP_TIMEWAIT_ROW;

/* Non public TOIID: the IPv6 state of the stack, for iphlpapi and ws2_32. Asked of any network layer entity
   (CL_NL_ENTITY, instance 0); the answer is a TCP_IPV6_TABLE_HEADER, then InterfaceCount
   TCP_IPV6_INTERFACE_ROW, then AddressCount TCP_IPV6_ADDRESS_ROW. Enabled 0 (and both counts 0), or a
   stack that does not know the request, is the only thing user mode may take as "this system has no IPv6"; this
   stack always answers TCP_IPV6_STATE_ON (Tcpip\Parameters\Ipv6Enable = 0 and Tcpip6\Parameters\DisabledComponents
   0x10 clear only TCP_IPV6_STATE_LINKS). The sizes are the whole answer, as for the other tables: a caller whose buffer is too
   small gets the size that does and asks again */
#define IP_IPV6_TABLE_ENTRY_ID          0x112

typedef struct _TCP_IPV6_TABLE_HEADER
{
    ULONG Enabled;          /* 0, or TCP_IPV6_STATE_ON with the other TCP_IPV6_STATE_ flags */
    ULONG InterfaceCount;
    ULONG AddressCount;
} TCP_IPV6_TABLE_HEADER, *PTCP_IPV6_TABLE_HEADER;

/* Enabled: IPv6 is on */
#define TCP_IPV6_STATE_ON               0x1
/* Enabled: the transport takes IPv6 addresses for TCP (address files, connections, listeners): only then are
   AF_INET6 sockets made and the IPv6 protocols listed in the Winsock catalog */
#define TCP_IPV6_STATE_SOCKETS          0x2
/* Enabled: the transport takes IPv6 addresses for UDP too (datagram sockets: send, receive, dual stack, the IPv6
   options and multicast groups): only then are AF_INET6 datagram sockets made */
#define TCP_IPV6_STATE_DATAGRAMS        0x4
/* Enabled: the transport takes IPv6 addresses for raw IP: only then are AF_INET6 raw sockets made */
#define TCP_IPV6_STATE_RAW              0x8
/* Enabled: IPv6 is on the non-loopback interfaces too. Without it (Tcpip6\Parameters\DisabledComponents with the
   0x10 bit, or Tcpip\Parameters\Ipv6Enable = 0) only the loopback interface has IPv6 (::1), and name resolution asks for no IPv6 addresses */
#define TCP_IPV6_STATE_LINKS            0x10

/* IPv6 is usable on the interface */
#define TCP_IPV6_IF_ENABLED             0x1
/* the loopback interface */
#define TCP_IPV6_IF_LOOPBACK            0x2
/* the last router advertisement on the interface had the managed address configuration flag (M) / the other
   configuration flag (O) set (RFC 4861 4.2): the DHCPv6 client starts by them */
#define TCP_IPV6_IF_RA_MANAGED          0x4
#define TCP_IPV6_IF_RA_OTHER            0x8

typedef struct _TCP_IPV6_INTERFACE_ROW
{
    ULONG IfIndex;
    ULONG Flags;
    ULONG Mtu;
    ULONG CurHopLimit;      /* the current hop limit the routers on the link advertise (0: none): datagrams whose sender
                               chose no hop limit leave with it */
} TCP_IPV6_INTERFACE_ROW, *PTCP_IPV6_INTERFACE_ROW;

/* DadState, PrefixOrigin and SuffixOrigin use the values of NL_DAD_STATE, NL_PREFIX_ORIGIN and
   NL_SUFFIX_ORIGIN; the lifetimes are in seconds, 0xffffffff is infinite */
typedef struct _TCP_IPV6_ADDRESS_ROW
{
    ULONG IfIndex;
    UCHAR Address[16];
    ULONG PrefixLength;
    ULONG DadState;
    ULONG PrefixOrigin;
    ULONG SuffixOrigin;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG Flags;            /* TCP_IPV6_ADDRESS_ flags */
} TCP_IPV6_ADDRESS_ROW, *PTCP_IPV6_ADDRESS_ROW;

/* Flags of an address (row and request): it is not chosen as the source of a datagram (SkipAsSource) */
#define TCP_IPV6_ADDRESS_SKIP_AS_SOURCE 0x1
/* row: the address was configured (IOCTL_IP6_ADDRESS_CONFIG), not formed by the stack */
#define TCP_IPV6_ADDRESS_CONFIGURED     0x2
/* row: the address is kept in the persistent store too */
#define TCP_IPV6_ADDRESS_PERSISTENT     0x4

/* Operation of a configuration request: CREATE fails if the entry exists, SET if it does not, DELETE removes it */
#define TCP_IPV6_CONFIG_CREATE          1
#define TCP_IPV6_CONFIG_SET             2
#define TCP_IPV6_CONFIG_DELETE          3

/* Store of a configuration request: the active store only (gone at the next start, or when the interface goes), or
   the persistent store as well (the stack applies it again whenever the interface starts) */
#define TCP_IPV6_STORE_ACTIVE           0
#define TCP_IPV6_STORE_PERSISTENT       1

/* IOCTL_IP6_ADDRESS_CONFIG. The address names the entry (with IfIndex); the other fields are what it becomes
   (CREATE, SET; DELETE only takes Store). Lifetimes in seconds, 0xffffffff infinite; PrefixOrigin and
   SuffixOrigin are NL_PREFIX_ORIGIN and NL_SUFFIX_ORIGIN values. A created address is tentative until duplicate
   address detection passes */
typedef struct _TCP_IPV6_ADDRESS_REQUEST
{
    ULONG Operation;        /* TCP_IPV6_CONFIG_ */
    ULONG Store;            /* TCP_IPV6_STORE_ */
    ULONG IfIndex;
    UCHAR Address[16];
    ULONG PrefixLength;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG PrefixOrigin;
    ULONG SuffixOrigin;
    ULONG Flags;            /* TCP_IPV6_ADDRESS_SKIP_AS_SOURCE */
} TCP_IPV6_ADDRESS_REQUEST, *PTCP_IPV6_ADDRESS_REQUEST;

/* Flags of a route (row and request); Publish and Immortal are kept and reported, they change nothing else */
#define TCP_IPV6_ROUTE_PUBLISH          0x1
#define TCP_IPV6_ROUTE_IMMORTAL         0x2
/* row: the route is kept in the persistent store too */
#define TCP_IPV6_ROUTE_PERSISTENT       0x4
/* row: the on-link prefix of a configured address (it comes and goes with the address) */
#define TCP_IPV6_ROUTE_FROM_ADDRESS     0x8
/* row: a router advertisement gave it (an on-link prefix or a default router) */
#define TCP_IPV6_ROUTE_FROM_RA          0x10
/* request and row: the route is one that does not autoconfigure an address (MIB_IPFORWARD_ROW2::AutoconfigureAddress
   FALSE); kept and reported only */
#define TCP_IPV6_ROUTE_NO_AUTOCONFIGURE 0x20

/* IOCTL_IP6_ROUTE_CONFIG. Prefix, PrefixLength, NextHop (all zero: on-link) and IfIndex name the entry; the other
   fields are what it becomes. Origin is an NL_ROUTE_ORIGIN value, Protocol an NL_ROUTE_PROTOCOL one */
typedef struct _TCP_IPV6_ROUTE_REQUEST
{
    ULONG Operation;        /* TCP_IPV6_CONFIG_ */
    ULONG Store;            /* TCP_IPV6_STORE_ */
    ULONG IfIndex;
    UCHAR Prefix[16];
    ULONG PrefixLength;
    UCHAR NextHop[16];
    ULONG Metric;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG Origin;
    ULONG Protocol;
    ULONG Flags;            /* TCP_IPV6_ROUTE_PUBLISH, TCP_IPV6_ROUTE_IMMORTAL, TCP_IPV6_ROUTE_NO_AUTOCONFIGURE */
} TCP_IPV6_ROUTE_REQUEST, *PTCP_IPV6_ROUTE_REQUEST;

/* IOCTL_IP_INTERFACE_CONFIG. Family is TCP_IPIF_IPV4 or TCP_IPIF_IPV6; Fields names what the request changes (the
   rest of the interface is left as it is); Store as for the other requests (the persistent one is written under
   the adapter's key and read when the adapter first starts). Mtu: bytes, 576..the link MTU for IPv4, 1280..the link
   MTU for IPv6. Metric: 1..9999, 0 = automatic. RouterDiscovery: an NL_ROUTER_DISCOVERY_BEHAVIOR value (IPv6:
   disabled, enabled, controlled by DHCP; IPv4: only the value it already has). DadTransmits: 0..7 (IPv6 only).
   Forwarding: 0 (the stack does not forward) */
#define TCP_IPIF_IPV4                   4
#define TCP_IPIF_IPV6                   6

#define TCP_IPIF_SET_MTU                0x01
#define TCP_IPIF_SET_METRIC             0x02
#define TCP_IPIF_SET_ROUTER_DISCOVERY   0x04
#define TCP_IPIF_SET_DAD_TRANSMITS      0x08
#define TCP_IPIF_SET_FORWARDING         0x10

typedef struct _TCP_IP_INTERFACE_REQUEST
{
    ULONG Family;           /* TCP_IPIF_ */
    ULONG Store;            /* TCP_IPV6_STORE_ */
    ULONG IfIndex;
    ULONG Fields;           /* TCP_IPIF_SET_ */
    ULONG Mtu;
    ULONG Metric;
    ULONG RouterDiscovery;
    ULONG DadTransmits;
    ULONG Forwarding;
} TCP_IP_INTERFACE_REQUEST, *PTCP_IP_INTERFACE_REQUEST;

/* Non public TOIID: the per-interface parameters of both families, for GetIpInterfaceEntry and GetIpInterfaceTable.
   Asked as IP_IPV6_TABLE_ENTRY_ID is (CL_NL_ENTITY, instance 0); the answer is a TCP_IP_INTERFACE_HEADER, then Count
   TCP_IP_INTERFACE_ROW. Sizes as for the other tables */
#define IP_INTERFACE_CONFIG_ENTRY_ID    0x11B

typedef struct _TCP_IP_INTERFACE_HEADER
{
    ULONG Count;
} TCP_IP_INTERFACE_HEADER, *PTCP_IP_INTERFACE_HEADER;

/* Ip6Valid: the interface has IPv6 (the IPv6 fields mean something); Loopback: the loopback interface */
#define TCP_IPIF_ROW_IP6                0x1
#define TCP_IPIF_ROW_LOOPBACK           0x2

typedef struct _TCP_IP_INTERFACE_ROW
{
    ULONG IfIndex;
    ULONG Flags;            /* TCP_IPIF_ROW_ */
    ULONG Ip4Mtu;           /* in force */
    ULONG Ip4Metric;        /* set by hand, 0 = automatic */
    ULONG Ip6Mtu;           /* in force (a router advertisement may lower it) */
    ULONG Ip6Metric;        /* set by hand, 0 = automatic */
    ULONG Ip6RouterDiscovery;   /* NL_ROUTER_DISCOVERY_BEHAVIOR */
    ULONG Ip6DadTransmits;
    ULONG LinkSpeed;        /* the link speed as the stack has it, in units of 100 bit/s (a 32-bit bit/s value saturates at 4.29 Gbit/s) */
} TCP_IP_INTERFACE_ROW, *PTCP_IP_INTERFACE_ROW;

/* Non public TOIID: the IPv6 route table of the stack (route6.c), apart from the routes every address and interface
   has (the host routes, fe80::/64, ff00::/8: user mode adds those): the configured routes, the on-link prefixes of
   configured addresses, and what router advertisements gave (on-link prefixes, default routers). It is the table the stack routes by. Asked as IP_IPV6_TABLE_ENTRY_ID is (CL_NL_ENTITY, instance 0); the answer is a
   TCP_IPV6_ROUTE_HEADER, then Count TCP_IPV6_ROUTE_ROW. Enabled is 0 (and Count 0) while the IPv6 switch is off.
   Sizes as for the other tables */
#define IP_IPV6_ROUTE_ENTRY_ID          0x119

typedef struct _TCP_IPV6_ROUTE_HEADER
{
    ULONG Enabled;
    ULONG Count;
} TCP_IPV6_ROUTE_HEADER, *PTCP_IPV6_ROUTE_HEADER;

/* NextHop all zero: on-link (a router's is its link-local address, the scope is IfIndex). Lifetimes: seconds left,
   0xffffffff infinite. Age: seconds since the route came (0 when the stack does not know) */
typedef struct _TCP_IPV6_ROUTE_ROW
{
    ULONG IfIndex;
    UCHAR Prefix[16];
    ULONG PrefixLength;
    UCHAR NextHop[16];
    ULONG Metric;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG Origin;
    ULONG Protocol;
    ULONG Flags;            /* TCP_IPV6_ROUTE_ */
    ULONG Age;
} TCP_IPV6_ROUTE_ROW, *PTCP_IPV6_ROUTE_ROW;

/* Non public TOIID: the IPv6 DNS servers that router advertisements gave (RFC 8106) and the default routers
   (router advertisements with a lifetime), for iphlpapi. Asked as IP_IPV6_TABLE_ENTRY_ID is (CL_NL_ENTITY, instance
   0); the answer is a TCP_IPV6_DNS_HEADER, then Count TCP_IPV6_DNS_ROW, DNS servers first. Enabled is 0 (and Count 0)
   while the IPv6 switch is off. Sizes as for the other tables: a caller whose buffer is too small gets the size that
   does and asks again */
#define IP_IPV6_DNS_ENTRY_ID            0x116

typedef struct _TCP_IPV6_DNS_HEADER
{
    ULONG Enabled;
    ULONG Count;
} TCP_IPV6_DNS_HEADER, *PTCP_IPV6_DNS_HEADER;

#define TCP_IPV6_DNS_SERVER             1
#define TCP_IPV6_DNS_ROUTER             2

/* Address: a router's is its link-local address, the scope is IfIndex; Lifetime: seconds left, 0xffffffff infinite */
typedef struct _TCP_IPV6_DNS_ROW
{
    ULONG IfIndex;
    ULONG Kind;
    UCHAR Address[16];
    ULONG Lifetime;
} TCP_IPV6_DNS_ROW, *PTCP_IPV6_DNS_ROW;

/* Non public TOIID: what router advertisements carry besides DNS servers and routers (ra6.c), for iphlpapi: the DNS
   search domains of the DNSSL option (RFC 8106). Asked as IP_IPV6_TABLE_ENTRY_ID is (CL_NL_ENTITY, instance 0); the
   answer is a TCP_IPV6_RA_HEADER, then Count TCP_IPV6_RA_ROW. Enabled is 0 (and Count 0) while the IPv6 switch is off.
   Sizes as for the other tables: a caller whose buffer is too small gets the size that does and asks again */
#define IP_IPV6_RA_ENTRY_ID             0x11A

typedef struct _TCP_IPV6_RA_HEADER
{
    ULONG Enabled;
    ULONG Count;
} TCP_IPV6_RA_HEADER, *PTCP_IPV6_RA_HEADER;

/* A search domain: the name in the dotted form without a final dot (ASCII letters, digits, '-' and '_' only, at most
   253 characters), Lifetime in seconds left, 0xffffffff infinite */
typedef struct _TCP_IPV6_RA_ROW
{
    ULONG IfIndex;
    ULONG Lifetime;
    CHAR Name[256];
} TCP_IPV6_RA_ROW, *PTCP_IPV6_RA_ROW;

/* Non public TOIID: the neighbour cache and the on-link prefixes of neighbour discovery, for iphlpapi. Asked as
   IP_IPV6_TABLE_ENTRY_ID is (CL_NL_ENTITY, instance 0); the answer is a TCP_IPV6_ND_HEADER, then NeighborCount
   TCP_IPV6_NEIGHBOR_ROW, then PrefixCount TCP_IPV6_PREFIX_ROW. Enabled is 0 (and both counts 0) while the IPv6
   switch is off. Sizes as for the other tables: a caller whose buffer is too small gets the size that does and
   asks again */
#define IP_IPV6_ND_ENTRY_ID             0x117

typedef struct _TCP_IPV6_ND_HEADER
{
    ULONG Enabled;
    ULONG NeighborCount;
    ULONG PrefixCount;
} TCP_IPV6_ND_HEADER, *PTCP_IPV6_ND_HEADER;

/* Flags of a neighbour */
#define TCP_IPV6_NEIGHBOR_ROUTER        0x1

/* State: the values of NL_NEIGHBOR_STATE (Incomplete 1, Probe 2, Delay 3, Stale 4, Reachable 5) */
typedef struct _TCP_IPV6_NEIGHBOR_ROW
{
    ULONG IfIndex;
    UCHAR Address[16];
    ULONG State;
    ULONG Flags;            /* TCP_IPV6_NEIGHBOR_ROUTER */
    ULONG LinkLength;       /* 0 while the neighbour has not answered */
    UCHAR LinkAddress[8];
    ULONG LastReachable;    /* ms since it was last confirmed reachable (Reachable and Stale; 0 otherwise) */
} TCP_IPV6_NEIGHBOR_ROW, *PTCP_IPV6_NEIGHBOR_ROW;

/* An on-link prefix a router advertisement gave; Lifetime: seconds left of its valid lifetime */
typedef struct _TCP_IPV6_PREFIX_ROW
{
    ULONG IfIndex;
    UCHAR Prefix[16];
    ULONG PrefixLength;
    ULONG Lifetime;
} TCP_IPV6_PREFIX_ROW, *PTCP_IPV6_PREFIX_ROW;

/* Non public TOIID: the counters of the IPv6 path (what GetIpStatisticsEx, GetTcpStatisticsEx and
   GetIcmpStatisticsEx report for AF_INET6), as one TCP_IPV6_STATS asked as IP_IPV6_TABLE_ENTRY_ID is. They count
   what crossed lwIP's IPv6 layer since the stack started; Enabled is 0 (and every counter 0) while the IPv6 switch
   is off. IcmpIn and IcmpOut are indexed by the ICMPv6 type; only a type that follows the fixed header directly is
   counted. The counters the stack does not keep (errors, resets, retransmissions) are not in it */
#define IP_IPV6_STATS_ENTRY_ID          0x118

typedef struct _TCP_IPV6_STATS
{
    ULONG Enabled;
    ULONG IpInReceives;     /* datagrams handed to the IPv6 layer */
    ULONG IpInDelivers;     /* ... that reached an upper layer protocol */
    ULONG IpOutRequests;    /* datagrams the IPv6 layer sent */
    ULONG TcpInSegs;
    ULONG TcpOutSegs;
    ULONG TcpActiveOpens;
    ULONG TcpPassiveOpens;
    ULONG IcmpInMsgs;
    ULONG IcmpOutMsgs;
    ULONG IcmpIn[256];
    ULONG IcmpOut[256];
} TCP_IPV6_STATS, *PTCP_IPV6_STATS;

/* Non public TOIID: the row of an IPv6 TCP socket (an AF_INET6 one, dual stack ones too), asked of its transport
   entity (CO_TL_ENTITY) as the IPv4 rows are; an entity of an IPv4 socket has none. The layout of
   MIB_TCP6ROW_OWNER_PID: the IPv4 side of a dual stack socket as ::ffff:a.b.c.d, ports in network order */
#define IP_TCP6_ROW_ENTRY_ID            0x113

typedef struct _TCP6_ROW_OWNER_PID
{
    UCHAR LocalAddr[16];
    ULONG LocalScopeId;
    ULONG LocalPort;
    UCHAR RemoteAddr[16];
    ULONG RemoteScopeId;
    ULONG RemotePort;
    ULONG State;
    ULONG OwningPid;
} TCP6_ROW_OWNER_PID, *PTCP6_ROW_OWNER_PID;

/* Non public TOIID: the row of an IPv6 UDP socket (an AF_INET6 one, dual stack ones too), asked of its transport
   entity (CL_TL_ENTITY); an entity of an IPv4 socket has none. The layout of MIB_UDP6ROW_OWNER_PID: a dual stack
   socket bound to an IPv4 address as ::ffff:a.b.c.d, the port in network order */
#define IP_UDP6_ROW_ENTRY_ID            0x114

typedef struct _UDP6_ROW_OWNER_PID
{
    UCHAR LocalAddr[16];
    ULONG LocalScopeId;
    ULONG LocalPort;
    ULONG OwningPid;
} UDP6_ROW_OWNER_PID, *PUDP6_ROW_OWNER_PID;
#endif
#define MAX_PHYSADDR_SIZE               8

#define TCP_MIB_STAT_ID                 1
#define UDP_MIB_STAT_ID                 1

/* Address Object Options */
#define AO_OPTION_TTL                1
#define AO_OPTION_MCASTTTL           2
#define AO_OPTION_MCASTIF            3
#define AO_OPTION_XSUM               4
#define AO_OPTION_IPOPTIONS          5
#define AO_OPTION_ADD_MCAST          6
#define AO_OPTION_DEL_MCAST          7
#define AO_OPTION_TOS                8
#define AO_OPTION_IP_DONTFRAGMENT    9
#define AO_OPTION_MCASTLOOP         10
#define AO_OPTION_BROADCAST         11
#define AO_OPTION_IP_HDRINCL        12
#define AO_OPTION_RCVALL            13
#define AO_OPTION_RCVALL_MCAST      14
#define AO_OPTION_RCVALL_IGMPMCAST  15
#define AO_OPTION_UNNUMBEREDIF      16
#define AO_OPTION_IP_UCASTIF        17
#define AO_OPTION_ABSORB_RTRALERT   18
#define AO_OPTION_LIMIT_BCASTS      19
#define AO_OPTION_INDEX_BIND        20
#define AO_OPTION_INDEX_MCASTIF     21
#define AO_OPTION_INDEX_ADD_MCAST   22
#define AO_OPTION_INDEX_DEL_MCAST   23
#define AO_OPTION_IFLIST            24
#define AO_OPTION_ADD_IFLIST        25
#define AO_OPTION_DEL_IFLIST        26
#define AO_OPTION_IP_PKTINFO        27
#define AO_OPTION_ADD_MCAST_SRC     28
#define AO_OPTION_DEL_MCAST_SRC     29
#define AO_OPTION_MCAST_FILTER      30
#define AO_OPTION_BLOCK_MCAST_SRC   31
#define AO_OPTION_UNBLOCK_MCAST_SRC 32
#define AO_OPTION_UDP_CKSUM_COVER   33
#define AO_OPTION_WINDOW            34
#define AO_OPTION_SCALE_CWIN        35
#define AO_OPTION_RCV_HOPLIMIT      36
#define AO_OPTION_UNBIND            37
#define AO_OPTION_PROTECT           38

/* TCP connection options */
#define TCP_SOCKET_NODELAY 1

/* ReactOS specific */
#define TCP_SOCKET_KEEPALIVE 2
#define TCP_SOCKET_KEEPALIVEVALS 3
/* The largest receive window of the connection in bytes (SO_RCVBUF; a ULONG) */
#define TCP_SOCKET_WINDOW 4

typedef struct IFEntry
{
    ULONG if_index;
    ULONG if_type;
    ULONG if_mtu;
    ULONG if_speed;
    ULONG if_physaddrlen;
    UCHAR if_physaddr[MAX_PHYSADDR_SIZE];
    ULONG if_adminstatus;
    ULONG if_operstatus;
    ULONG if_lastchange;
    ULONG if_inoctets;
    ULONG if_inucastpkts;
    ULONG if_innucastpkts;
    ULONG if_indiscards;
    ULONG if_inerrors;
    ULONG if_inunknownprotos;
    ULONG if_outoctets;
    ULONG if_outucastpkts;
    ULONG if_outnucastpkts;
    ULONG if_outdiscards;
    ULONG if_outerrors;
    ULONG if_outqlen;
    ULONG if_descrlen;
    UCHAR if_descr[1];
} IFEntry;

typedef struct IPSNMPInfo
{
    ULONG ipsi_forwarding;
    ULONG ipsi_defaultttl;
    ULONG ipsi_inreceives;
    ULONG ipsi_inhdrerrors;
    ULONG ipsi_inaddrerrors;
    ULONG ipsi_forwdatagrams;
    ULONG ipsi_inunknownprotos;
    ULONG ipsi_indiscards;
    ULONG ipsi_indelivers;
    ULONG ipsi_outrequests;
    ULONG ipsi_routingdiscards;
    ULONG ipsi_outdiscards;
    ULONG ipsi_outnoroutes;
    ULONG ipsi_reasmtimeout;
    ULONG ipsi_reasmreqds;
    ULONG ipsi_reasmoks;
    ULONG ipsi_reasmfails;
    ULONG ipsi_fragoks;
    ULONG ipsi_fragfails;
    ULONG ipsi_fragcreates;
    ULONG ipsi_numif;
    ULONG ipsi_numaddr;
    ULONG ipsi_numroutes;
} IPSNMPInfo;

typedef struct IPAddrEntry
{
    ULONG iae_addr;
    ULONG iae_index;
    ULONG iae_mask;
    ULONG iae_bcastaddr;
    ULONG iae_reasmsize;
    USHORT iae_context;
    USHORT iae_pad;
} IPAddrEntry;

typedef struct IPInterfaceInfo
{
    ULONG iii_flags;
    ULONG iii_mtu;
    ULONG iii_speed;
    ULONG iii_addrlength;
    UCHAR iii_addr[1];
} IPInterfaceInfo;

#endif/*_TCPIOCTL_H*/
