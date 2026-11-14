/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Contract between the user-mode firewall service (mpssvc) and the
 *              kernel packet filter (tcpip.sys, ticket NET-firewall-inbound-filter)
 *
 * Include <winioctl.h> (user mode) or <ntddk.h> (kernel) before this header: it needs CTL_CODE.
 *
 * ============================================================================
 *  HOW THE PIECES FIT
 * ============================================================================
 *  netsh advfirewall / INetFwPolicy2 (hnetcfg)  --write-->  registry (Windows' own layout):
 *      HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy
 *          {DomainProfile,StandardProfile,PublicProfile}   EnableFirewall, DefaultInboundAction, ...
 *          FirewallRules                                   "v2.30|Action=Allow|Active=TRUE|Dir=In|..."
 *  mpssvc  --RegNotifyChangeKeyValue-->  rebuilds the policy and sends it to the kernel:
 *      CreateFile(NITROFW_USER_PATH) + DeviceIoControl(IOCTL_NITROFW_SET_POLICY, NITROFW_POLICY blob)
 *
 *  The kernel side owns a device object named NITROFW_DEVICE_NAME (symbolic link NITROFW_DOS_NAME).
 *  If CreateFile on NITROFW_USER_PATH fails the service keeps the rules in the registry and retries
 *  on the next change and every NITROFW_RETRY_SECONDS; rules are then stored but not enforced.
 *
 * ============================================================================
 *  IOCTLs (all METHOD_BUFFERED, administrators/SYSTEM only: the device ACL must deny everyone else)
 * ============================================================================
 *  IOCTL_NITROFW_GET_VERSION   out: NITROFW_VERSION_INFO
 *  IOCTL_NITROFW_SET_POLICY    in : NITROFW_POLICY (see below). Replaces the whole policy atomically:
 *                              the kernel validates the blob completely first and on any error keeps the
 *                              old policy and fails with STATUS_INVALID_PARAMETER. A policy whose Generation
 *                              is not larger than the installed one is rejected with STATUS_REVISION_MISMATCH
 *                              (the service increments it on every push; it restarts from a boot-time value).
 *  IOCTL_NITROFW_GET_STATUS    out: NITROFW_STATUS
 *  IOCTL_NITROFW_CLEAR_POLICY  no data. Removes all rules and disables filtering (service stop / uninstall).
 *  IOCTL_NITROFW_GET_DROPLOG   in : optional ULONGLONG, first sequence number wanted (0 or absent = oldest kept)
 *                              out: NITROFW_DROPLOG followed by Count NITROFW_DROP_RECORD (see below)
 *  IOCTL_NITROFW_GET_LISTENERS no input
 *                              out: NITROFW_LISTENERS followed by Count NITROFW_LISTENER (see below). The block
 *                              prompt (mpssvc) polls it: a snapshot of the local endpoints that accept traffic.
 *
 *  A new open handle starts with whatever policy the previous service instance installed: the policy
 *  belongs to the device, not to the handle. A service crash therefore leaves the last policy in force
 *  (fail-closed for a firewall); IOCTL_NITROFW_CLEAR_POLICY is the explicit way out.
 *
 * ============================================================================
 *  MATCHING SEMANTICS the filter implements (mirrors Windows Defender Firewall's documented behaviour)
 * ============================================================================
 *  1. Loopback always passes: packets that arrive on the loopback interface. The address is not looked at:
 *     a 127.0.0.0/8 source or destination on any other interface is not loopback and is filtered like
 *     any other packet. Traffic from one of the host's own addresses to one of its own addresses (LAN IP to
 *     LAN IP) is local too, as on Windows: the stack sends it out through the adapter and NDIS loops it
 *     back up from inside the send call. tcpip tags exactly those frames on its own send path; a packet
 *     from the wire that carries a local source address, or even our MAC and IP, is not tagged and is
 *     filtered like any other inbound packet.
 *  2. If NITROFW_POLICY_ENFORCE is clear in Policy.Flags, nothing is filtered (the service clears it when
 *     the registry kill switch says so). Counters may still run.
 *  3. A packet is evaluated against the profiles in Policy.ActiveProfiles. Profile[i] covers profile
 *     bit (1 << i). If no active profile has NITROFW_PROFILE_ENABLED the packet passes.
 *  4. Traffic belonging to a connection or exchange the local host started passes (TCP established,
 *     UDP/ICMP replies from the peer the host sent to): the filter keeps a small flow table, fed while the
 *     filter is loaded, so exchanges in flight when enforcement starts continue. A send to a broadcast or
 *     multicast address admits unicast replies from any peer for 3 seconds (Windows' documented window,
 *     FW_BCAST_TIMEOUT), and the first reply gives that peer an exchange of its own. DHCP client
 *     replies (UDP source port 67, destination port 68) always pass: they answer our own request, and
 *     losing the lease would take the network down. With NITROFW_PROFILE_NO_UNICAST_RESPONSES set in an
 *     enabled active profile, replies to a broadcast or multicast send (UDP or ICMP) are not admitted
 *     (Windows' DisableUnicastResponsesToMulticastBroadcast); replies to unicast sends still are.
 *     ICMP: the reply to a request the host sent (echo, timestamp, information request, address mask
 *     request; matched on the peer address and the identifier) passes; an echo, timestamp, information
 *     or address mask reply with no such request is unsolicited and goes through the rules like a request
 *     (dropped by default, as on Windows). ICMP errors (types 3, 4, 11, 12) pass.
 *  5. Otherwise: if the profile has NITROFW_PROFILE_BLOCK_ALL_INBOUND, an inbound packet is dropped.
 *     Else the rules whose ProfileMask includes the active profile and whose Direction matches are
 *     tested. A matching Block rule drops the packet (block beats allow); else a matching Allow rule passes
 *     it; else DefaultInbound / DefaultOutbound of the profile decides.
 *  6. A rule matches when ALL of its non-empty conditions match: Protocol, local ports, remote ports,
 *     local addresses, remote addresses, ICMP type/code, interface types, and (inbound TCP/UDP) the
 *     image path of the process that owns the local endpoint, matching AppPath case-insensitively.
 *     An empty list means "any". Port lists apply to TCP and UDP only; ICMP entries to protocol 1/58.
 *     A rule with ICMP entries must have Protocol 1 (ICMPv4) or 58 (ICMPv6); the kernel rejects the policy
 *     otherwise (with Protocol ANY the entries would match every non-ICMP packet).
 *     Interface types: IfTypes must be non-zero and use only NITROFW_IFTYPE_* bits (else the policy is
 *     rejected). A rule applies to a packet when its IfTypes includes the type of the interface the packet
 *     came in on: Wireless for 802.11 adapters (NDIS physical medium WirelessLan or Native802_11), RemoteAccess
 *     for WAN adapters (medium Wan/CoWan, physical medium WiredWAN/WiredCoWan; this stack binds only 802.3
 *     adapters, so none exists today), LAN for everything else and for an adapter that does not answer the
 *     physical medium query. A Block or Allow rule restricted to a type the interface does not have is skipped.
 *  7. Outbound rules are carried for completeness; a filter that only implements the inbound path ignores
 *     rules with Direction == NITROFW_DIR_OUT and reports NITROFW_FEATURE_OUTBOUND clear in GET_VERSION.
 *  8. Service-name conditions (ServiceNameOffset) are advisory: a filter that cannot resolve the
 *     owning service ignores the condition and reports NITROFW_FEATURE_SERVICE_MATCH clear. The service
 *     never relies on it for Block rules.
 *  9. IPv6 (only while tcpip has IPv6 on, Tcpip\Parameters\Ipv6Enable; NITROFW_FEATURE_IPV6 says so): the same
 *     rules, profiles and defaults apply to IPv6 packets. A rule's address lists are per family: a rule with
 *     only IPv4 addresses never matches an IPv6 packet, one with only IPv6 addresses never matches an IPv4
 *     packet, one with no addresses matches both. Protocol 58 is ICMPv6 (ICMP entries as for protocol 1).
 *     Without rule evaluation: loopback, frames the host looped back to itself, neighbour discovery and MLD
 *     that meet their RFCs (a violation is dropped and logged as NITROFW_DROP_V6_INVALID), ICMPv6 errors
 *     that answer a TCP segment the host sent, echo replies, and TCP segments that are not a connection
 *     request. Connection requests, UDP, other ICMPv6 types and other protocols are evaluated (default block).
 *     Program-image conditions do not match IPv6 packets yet.
 *
 * ============================================================================
 *  ENCODING
 * ============================================================================
 *  Little endian, natural alignment, every structure size is a multiple of 8, every offset is in bytes
 *  from the START OF THE STRUCTURE it is stored in and is 8-aligned, strings are NUL terminated WCHAR.
 *  The kernel must bounds-check every offset, count and size against TotalSize/Size (the blob comes from
 *  user mode) and reject overlapping or overflowing values. Limits: TotalSize <= NITROFW_MAX_POLICY_SIZE,
 *  at most NITROFW_MAX_RULES rules, at most NITROFW_MAX_LIST entries per list.
 *  IPv4 addresses and ports are HOST byte order values in the blob (the service converts).
 */

#pragma once

#define NITROFW_DEVICE_NAME      L"\\Device\\NitroFw"
#define NITROFW_DOS_NAME         L"\\DosDevices\\NitroFw"
#define NITROFW_USER_PATH        L"\\\\.\\NitroFw"
#define NITROFW_RETRY_SECONDS    30

#define NITROFW_ABI_VERSION      1
#define NITROFW_POLICY_MAGIC     0x3157464E   /* 'N','F','W','1' */
#define NITROFW_MAX_POLICY_SIZE  (4 * 1024 * 1024)
#define NITROFW_MAX_RULES        4096
#define NITROFW_MAX_LIST         256

#define IOCTL_NITROFW_GET_VERSION   CTL_CODE(FILE_DEVICE_NETWORK, 0x840, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_NITROFW_SET_POLICY    CTL_CODE(FILE_DEVICE_NETWORK, 0x841, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_NITROFW_GET_STATUS    CTL_CODE(FILE_DEVICE_NETWORK, 0x842, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_NITROFW_CLEAR_POLICY  CTL_CODE(FILE_DEVICE_NETWORK, 0x843, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_NITROFW_GET_DROPLOG   CTL_CODE(FILE_DEVICE_NETWORK, 0x844, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_NITROFW_GET_LISTENERS CTL_CODE(FILE_DEVICE_NETWORK, 0x845, METHOD_BUFFERED, FILE_READ_ACCESS)

/* NITROFW_VERSION_INFO.Features */
#define NITROFW_FEATURE_INBOUND        0x00000001
#define NITROFW_FEATURE_OUTBOUND       0x00000002
#define NITROFW_FEATURE_SERVICE_MATCH  0x00000004
#define NITROFW_FEATURE_IPV6           0x00000008

typedef struct _NITROFW_VERSION_INFO
{
    ULONG AbiVersion;       /* NITROFW_ABI_VERSION the driver implements */
    ULONG Features;         /* NITROFW_FEATURE_* */
    ULONG MaxRules;
    ULONG Reserved;
} NITROFW_VERSION_INFO, *PNITROFW_VERSION_INFO;

/* Profile bits, identical to NET_FW_PROFILE2_DOMAIN/PRIVATE/PUBLIC */
#define NITROFW_PROFILE_DOMAIN   0x00000001
#define NITROFW_PROFILE_PRIVATE  0x00000002
#define NITROFW_PROFILE_PUBLIC   0x00000004
#define NITROFW_PROFILE_ALL      0x00000007
#define NITROFW_PROFILE_COUNT    3

/* NITROFW_PROFILE_SETTINGS.Flags */
#define NITROFW_PROFILE_ENABLED            0x00000001   /* EnableFirewall */
#define NITROFW_PROFILE_BLOCK_ALL_INBOUND  0x00000002   /* DoNotAllowExceptions */
#define NITROFW_PROFILE_NO_UNICAST_RESPONSES 0x00000004 /* DisableUnicastResponsesToMulticastBroadcast */
#define NITROFW_PROFILE_LOG_DROPPED        0x00000008   /* Logging\LogDroppedPackets: keep the drop log */

#define NITROFW_ACTION_ALLOW  0
#define NITROFW_ACTION_BLOCK  1

#define NITROFW_DIR_IN   1
#define NITROFW_DIR_OUT  2

#define NITROFW_PROTO_ANY  256

/* NITROFW_RULE.IfTypes */
#define NITROFW_IFTYPE_LAN           0x00000001
#define NITROFW_IFTYPE_WIRELESS      0x00000002
#define NITROFW_IFTYPE_REMOTEACCESS  0x00000004
#define NITROFW_IFTYPE_ALL           0x00000007

typedef struct _NITROFW_PROFILE_SETTINGS
{
    ULONG Flags;            /* NITROFW_PROFILE_* */
    UCHAR DefaultInbound;   /* NITROFW_ACTION_*, Windows default: block */
    UCHAR DefaultOutbound;  /* NITROFW_ACTION_*, Windows default: allow */
    USHORT Reserved;
} NITROFW_PROFILE_SETTINGS, *PNITROFW_PROFILE_SETTINGS;

typedef struct _NITROFW_PORT_RANGE
{
    USHORT Low;
    USHORT High;            /* == Low for a single port */
} NITROFW_PORT_RANGE, *PNITROFW_PORT_RANGE;

typedef struct _NITROFW_ADDR4_RANGE
{
    ULONG Low;              /* host byte order, inclusive */
    ULONG High;
} NITROFW_ADDR4_RANGE, *PNITROFW_ADDR4_RANGE;

typedef struct _NITROFW_ADDR6_RANGE
{
    UCHAR Low[16];          /* network order byte strings, inclusive */
    UCHAR High[16];
} NITROFW_ADDR6_RANGE, *PNITROFW_ADDR6_RANGE;

#define NITROFW_ICMP_ANY  0xFF

typedef struct _NITROFW_ICMP_ENTRY
{
    UCHAR Type;             /* NITROFW_ICMP_ANY = every type */
    UCHAR Code;             /* NITROFW_ICMP_ANY = every code */
} NITROFW_ICMP_ENTRY, *PNITROFW_ICMP_ENTRY;

/*
 * One rule. Only rules that are Active in the store are sent. Variable part: the lists and strings
 * live inside [this, this + Size) at the offsets below (0 offset = list absent/empty = "any").
 * Size is a multiple of 8; the next rule starts at (BYTE *)rule + Size.
 */
typedef struct _NITROFW_RULE
{
    ULONG Size;
    ULONG Flags;                /* reserved, 0 */
    UCHAR Action;               /* NITROFW_ACTION_* */
    UCHAR Direction;            /* NITROFW_DIR_* */
    USHORT Protocol;            /* 0..255 or NITROFW_PROTO_ANY */
    ULONG ProfileMask;          /* NITROFW_PROFILE_*, never 0 */
    ULONG IfTypes;              /* NITROFW_IFTYPE_*, NITROFW_IFTYPE_ALL = any */

    ULONG LocalPortCount;       ULONG LocalPortOffset;      /* NITROFW_PORT_RANGE[] */
    ULONG RemotePortCount;      ULONG RemotePortOffset;     /* NITROFW_PORT_RANGE[] */
    ULONG LocalAddr4Count;      ULONG LocalAddr4Offset;     /* NITROFW_ADDR4_RANGE[] */
    ULONG RemoteAddr4Count;     ULONG RemoteAddr4Offset;
    ULONG LocalAddr6Count;      ULONG LocalAddr6Offset;     /* NITROFW_ADDR6_RANGE[] */
    ULONG RemoteAddr6Count;     ULONG RemoteAddr6Offset;
    ULONG IcmpCount;            ULONG IcmpOffset;           /* NITROFW_ICMP_ENTRY[] */
    ULONG AppPathOffset;        /* WCHAR[]: NT path of the image, e.g. \Device\HarddiskVolume1\Windows\x.exe */
    ULONG ServiceNameOffset;    /* WCHAR[]: service short name, advisory (see rule 8) */
    ULONG Reserved[3];
    /* variable part follows; sizeof(NITROFW_RULE) == 96 */
} NITROFW_RULE, *PNITROFW_RULE;

/*
 * The whole policy. Rules follow the header at RulesOffset, back to back, RuleCount of them.
 * TotalSize covers the header and all rules.
 */
#define NITROFW_MAX_GENERATION  0x4000000000000000ULL  /* a larger Generation is rejected (it would lock out every later push) */
#define NITROFW_POLICY_ENFORCE  0x00000001  /* clear = observe only, nothing is dropped */

typedef struct _NITROFW_POLICY
{
    ULONG Magic;                /* NITROFW_POLICY_MAGIC */
    ULONG AbiVersion;           /* NITROFW_ABI_VERSION */
    ULONG TotalSize;
    ULONG Flags;                /* NITROFW_POLICY_* */
    ULONGLONG Generation;       /* strictly increasing per push */
    ULONG ActiveProfiles;       /* NITROFW_PROFILE_* of the profile(s) currently in force */
    ULONG RuleCount;
    ULONG RulesOffset;
    ULONG Reserved;
    NITROFW_PROFILE_SETTINGS Profile[NITROFW_PROFILE_COUNT];   /* [0]=domain [1]=private [2]=public */
    ULONG Reserved2[2];     /* sizeof(NITROFW_POLICY) == 72 */
} NITROFW_POLICY, *PNITROFW_POLICY;

/*
 * NITROFW_STATUS.KernelState. The filter enforces by default: the kernel drops packets when a policy is
 * installed that has NITROFW_POLICY_ENFORCE and an enabled active profile, unless the REG_DWORD
 * HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters NitroFwEnforce is 0 when the policy arrives (an absent value means 1).
 * NitroFwDisable=1 there, or the boot option /NOFIREWALL, removes the device and the filter entirely at
 * driver load (kill switch).
 */
#define NITROFW_KSTATE_OPTIN      0x00000001   /* NitroFwEnforce was on (default) at the last push */
#define NITROFW_KSTATE_ENFORCING  0x00000002   /* packets are being dropped per the installed policy */

typedef struct _NITROFW_STATUS
{
    ULONGLONG Generation;       /* of the installed policy, 0 = none */
    ULONG Flags;                /* NITROFW_POLICY_* of the installed policy */
    ULONG RuleCount;
    ULONG ActiveProfiles;
    ULONG KernelState;          /* NITROFW_KSTATE_*: what the kernel does with the installed policy */
    ULONGLONG DroppedInbound;
    ULONGLONG DroppedOutbound;
    ULONGLONG PassedInbound;
    ULONGLONG ImagesCaptured;   /* test counter: program-image resolutions attempted (0 while not enforcing a
                                   policy with program rules). Optional: the kernel fills it only if the
                                   output buffer is at least sizeof(NITROFW_STATUS), else the V1 size. */
} NITROFW_STATUS, *PNITROFW_STATUS;
#define NITROFW_STATUS_V1_SIZE  FIELD_OFFSET(NITROFW_STATUS, ImagesCaptured)

/*
 * Drop log. While an enabled active profile has NITROFW_PROFILE_LOG_DROPPED, every dropped inbound packet
 * is recorded in a ring of NITROFW_DROPLOG_RECORDS entries (the oldest are overwritten), at most
 * NITROFW_DROPLOG_RATE records per second (the drops beyond that are counted in Suppressed, and still
 * counted in DroppedInbound). Nothing is recorded, and nothing costs anything, while no profile asks for it.
 * IOCTL_NITROFW_GET_DROPLOG returns the records with Sequence >= the requested one that fit in the output
 * buffer; the caller continues at NextSequence. The ring survives a policy change.
 */
#define NITROFW_DROPLOG_RECORDS  128
#define NITROFW_DROPLOG_RATE     20

#define NITROFW_DROP_DEFAULT     1   /* no rule admitted it, the profile's default is Block */
#define NITROFW_DROP_BLOCK_RULE  2   /* a Block rule matched */
#define NITROFW_DROP_BLOCK_ALL   3   /* the profile blocks all inbound (DoNotAllowExceptions) */
#define NITROFW_DROP_ICMP_REPLY  4   /* an ICMP reply with no outstanding request, and no rule admitted it */
#define NITROFW_DROP_V6_INVALID  5   /* IPv6: malformed, or a neighbour discovery / MLD message RFC 4861 / 2710 do not allow
                                        (hop limit, source address); no rule is consulted */

typedef struct _NITROFW_DROP_RECORD
{
    ULONGLONG Sequence;         /* 1, 2, 3 ... never reused */
    LONGLONG Time;              /* KeQuerySystemTime (100 ns since 1601, UTC) */
    ULONG SrcAddr;              /* IPv4, host byte order */
    ULONG DstAddr;
    USHORT SrcPort;             /* TCP/UDP, host order; 0 otherwise */
    USHORT DstPort;
    UCHAR Protocol;
    UCHAR IcmpType;             /* ICMP only */
    UCHAR IcmpCode;
    UCHAR Reason;               /* NITROFW_DROP_* */
    ULONG Size;                 /* IP datagram size in bytes */
    ULONG Flags;                /* NITROFW_DROP_F_*; 0 for IPv4 */
    UCHAR SrcAddr6[16];         /* IPv6 (NITROFW_DROP_F_IPV6), network order; zero for IPv4 (SrcAddr/DstAddr are 0 for IPv6) */
    UCHAR DstAddr6[16];
} NITROFW_DROP_RECORD, *PNITROFW_DROP_RECORD;   /* 72 bytes */

#define NITROFW_DROP_F_IPV6  0x00000001   /* the record is an IPv6 packet: SrcAddr6/DstAddr6 are valid, Size is the datagram length incl. the 40-byte header */

#define NITROFW_DROPLOG_ON  0x00000001   /* NITROFW_DROPLOG.Flags: logging is on in the installed policy */

typedef struct _NITROFW_DROPLOG
{
    ULONGLONG NextSequence;     /* Sequence the next recorded drop gets */
    ULONGLONG Suppressed;       /* drops not recorded because of the rate limit, since load */
    ULONG Count;                /* NITROFW_DROP_RECORD entries that follow this header */
    ULONG Flags;                /* NITROFW_DROPLOG_* */
} NITROFW_DROPLOG, *PNITROFW_DROPLOG;           /* 24 bytes; the records follow */

/*
 * Listener snapshot (the "NitroOS Firewall has blocked some features of this app" prompt). The kernel does not
 * decide whether a listener is blocked, and does not resolve anything: it reports who accepts traffic, mpssvc
 * (which owns the rules, the profile settings and the notification setting) decides, once per program and
 * profile. Reported: TCP address files that have a listener (a listen was issued on them), and UDP address
 * files bound to an explicit port (a port the application chose, not the ephemeral one an unbound send gets).
 * Endpoints whose handles are all closed are not reported. At most NITROFW_MAX_LISTENERS records are returned
 * (Total says how many there were). Nothing is recorded or kept: the cost is one walk of the address file list
 * per call, and nothing at all while nobody calls.
 */
#define NITROFW_MAX_LISTENERS  256

#define NITROFW_LISTENER_TCP   0x01   /* NITROFW_LISTENER.Flags: a TCP listener (else UDP) */

typedef struct _NITROFW_LISTENER
{
    ULONG ProcessId;            /* creator of the address file */
    USHORT Port;                /* host order */
    UCHAR Protocol;             /* 6 TCP, 17 UDP */
    UCHAR Flags;                /* NITROFW_LISTENER_* */
    ULONG Addr;                 /* local IPv4, host order, 0 = any */
    ULONG Reserved;
    LONGLONG CreationTime;      /* of the address file (KeQuerySystemTime): with ProcessId and Port it identifies the endpoint */
} NITROFW_LISTENER, *PNITROFW_LISTENER;     /* 24 bytes */

typedef struct _NITROFW_LISTENERS
{
    ULONG Count;                /* NITROFW_LISTENER entries that follow this header */
    ULONG Total;                /* endpoints found (>= Count when the output buffer or the limit cut the list) */
} NITROFW_LISTENERS, *PNITROFW_LISTENERS;   /* 8 bytes; the records follow */
