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
 *
 *  A new open handle starts with whatever policy the previous service instance installed: the policy
 *  belongs to the device, not to the handle. A service crash therefore leaves the last policy in force
 *  (fail-closed for a firewall); IOCTL_NITROFW_CLEAR_POLICY is the explicit way out.
 *
 * ============================================================================
 *  MATCHING SEMANTICS the filter implements (mirrors Windows Defender Firewall's documented behaviour)
 * ============================================================================
 *  1. Loopback (127.0.0.0/8, ::1) always passes.
 *  2. If NITROFW_POLICY_ENFORCE is clear in Policy.Flags, nothing is filtered (the service clears it when
 *     the registry kill switch says so). Counters may still run.
 *  3. A packet is evaluated against the profiles in Policy.ActiveProfiles. Profile[i] covers profile
 *     bit (1 << i). If no active profile has NITROFW_PROFILE_ENABLED the packet passes.
 *  4. Traffic belonging to a connection or exchange the local host started passes (TCP established,
 *     UDP/ICMP replies from the peer the host sent to): the filter keeps a small flow table.
 *  5. Otherwise: if the profile has NITROFW_PROFILE_BLOCK_ALL_INBOUND, an inbound packet is dropped.
 *     Else the rules whose ProfileMask includes the active profile and whose Direction matches are
 *     tested. A matching Block rule drops the packet (block beats allow); else a matching Allow rule passes
 *     it; else DefaultInbound / DefaultOutbound of the profile decides.
 *  6. A rule matches when ALL of its non-empty conditions match: Protocol, local ports, remote ports,
 *     local addresses, remote addresses, ICMP type/code, interface types, and (inbound TCP/UDP) the
 *     image path of the process that owns the local endpoint, matching AppPath case-insensitively.
 *     An empty list means "any". Port lists apply to TCP and UDP only; ICMP entries to protocol 1/58.
 *  7. Outbound rules are carried for completeness; a filter that only implements the inbound path ignores
 *     rules with Direction == NITROFW_DIR_OUT and reports NITROFW_FEATURE_OUTBOUND clear in GET_VERSION.
 *  8. Service-name conditions (ServiceNameOffset) are advisory: a filter that cannot resolve the
 *     owning service ignores the condition and reports NITROFW_FEATURE_SERVICE_MATCH clear. The service
 *     never relies on it for Block rules.
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
 * NITROFW_STATUS.KernelState. The first release ships the filter compiled in but NOT enforcing: the kernel
 * only drops packets when HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters NitroFwEnforce
 * (REG_DWORD) is 1 when a policy arrives (opt-in), the policy has NITROFW_POLICY_ENFORCE and an active
 * profile is enabled. NitroFwDisable=1 there, or the boot option /NOFIREWALL, removes the device and the
 * filter entirely at driver load (kill switch).
 */
#define NITROFW_KSTATE_OPTIN      0x00000001   /* NitroFwEnforce opt-in was set at the last push */
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
} NITROFW_STATUS, *PNITROFW_STATUS;
