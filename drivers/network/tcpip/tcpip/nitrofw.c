/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Inbound packet filter in tcpip.sys: the \Device\NitroFw control device, policy
 *              validation and installation, the UDP reply flow table and the per-datagram decision.
 *
 * Contract with the rule service (mpssvc): sdk/include/reactos/nitrofw.h.
 *
 * Switches (HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters, REG_DWORD):
 *   NitroFwDisable = 1   kill switch, read once at driver load: no device, no filtering at all.
 *                        The boot option /NOFIREWALL does the same (SystemStartOptions).
 *   NitroFwEnforce       default 1 (enforcement on). NitroFwEnforce = 0 turns it off: a policy is accepted
 *                        and reported by IOCTL_NITROFW_GET_STATUS but nothing is dropped. An absent value
 *                        means 1. Read at load and on every IOCTL_NITROFW_SET_POLICY, so a change takes
 *                        effect at the service's next push.
 * The policy's own NITROFW_POLICY_ENFORCE flag (mpssvc: HKLM\SOFTWARE\ReactOS\Nitro\Firewall Enforce)
 * must be set as well.
 *
 * Reading NitroFwEnforce at SET time: a value that is absent counts as 1 (on). Any other failure to read it
 * (no memory, wrong type, registry error) keeps the opt-in the previous push established (at load: on), so a
 * transient registry fault or a malformed value cannot silently turn enforcement off (or on); it is logged.
 *
 * Scope: IPv4 inbound only (the IP layer has no IPv6). Dropped: unsolicited TCP SYNs, unsolicited UDP,
 * ICMP requests and other protocols that no Allow rule admits, or that a Block rule matches. Passed
 * without rule evaluation: loopback, TCP segments that are not a connection request (established
 * connections, the stack answers the rest as before), UDP replies from a peer the host sent to recently
 * (flow table), DHCP client replies (UDP 67 -> 68), ICMP errors, ICMP replies to a request the host sent
 * (echo, timestamp, information, address mask; an ICMP reply with no such request is unsolicited and is
 * evaluated like a request), and traffic the host sent to itself over a real address (the frames our own
 * send path looped back, see NitroFwInboundAllowed).
 *
 * DisableUnicastResponsesToMulticastBroadcast (NITROFW_PROFILE_NO_UNICAST_RESPONSES): replies to a
 * broadcast/multicast send are not admitted. Drop log: see NITROFW_DROPLOG in nitrofw.h.
 */

#include "precomp.h"

#include <ntifs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/obfuncs.h>
#include <reactos/nitrofw.h>
#include <nitrofwk.h>

/* ZwQueryInformationProcess is not in the DDK headers this driver uses */
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                                  PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                  PULONG ReturnLength);

#define NITROFW_TAG       'wFiN'
#define NITROFW_IMG_TAG   'iFiN'

#define FW_PARAMS_KEY     L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define FW_CONTROL_KEY    L"\\Registry\\Machine\\System\\CurrentControlSet\\Control"

/* UDP flow table: 4-way set associative, replies pass for FW_UDP_TIMEOUT seconds after the last packet.
   A send to a broadcast or multicast address admits unicast replies from any peer for FW_BCAST_TIMEOUT
   seconds (Windows' documented 3 s window for unicast responses to broadcast/multicast; replies that
   come later are dropped, as on Windows), and the first such reply turns into an exact flow for that
   peer so its follow-up packets from the same address and port pass for FW_UDP_TIMEOUT. The flow
   table is fed whenever the filter is loaded (NitroFwTracking), not only while enforcing, so exchanges
   already in flight when enforcement starts keep working. */
#define FW_FLOW_SETS        256
#define FW_FLOW_WAYS        4
#define FW_UDP_TIMEOUT      60
#define FW_BCAST_TIMEOUT    3
#define FW_FLOW_LOCKS       16      /* the flow table's locks: set index modulo this */

/* Outstanding ICMP requests (the host's own pings and the like): the reply passes for FW_ICMP_TIMEOUT
   seconds, matched on peer address, identifier and reply type. A request to a broadcast/multicast address
   keeps a wildcard peer for FW_BCAST_TIMEOUT. Same table shape and locks as the UDP flows. */
#define FW_ICMP_SETS        64
#define FW_ICMP_TIMEOUT     60

typedef struct _FW_IMAGE
{
    LONG RefCount;
    USHORT Length;              /* in WCHARs, no terminator */
    WCHAR Path[ANYSIZE_ARRAY];  /* upcased NT path, or "SYSTEM" for the System process */
} FW_IMAGE, *PFW_IMAGE;

typedef struct _FW_POLICY
{
    LONG RefCount;
    ULONG Flags;                /* NITROFW_POLICY_* as sent */
    ULONGLONG Generation;
    ULONG ActiveProfiles;
    ULONG RuleCount;
    ULONG EnabledProfiles;      /* active AND enabled */
    BOOLEAN BlockAllInbound;
    BOOLEAN DefaultBlockInbound;
    BOOLEAN HasAppRules;        /* an inbound rule has a program condition */
    BOOLEAN NoUnicastResponses; /* an enabled active profile has DisableUnicastResponsesToMulticastBroadcast */
    BOOLEAN LogDropped;         /* an enabled active profile logs dropped packets */
    ULONG InRuleCount;
    PULONG InRuleOffsets;       /* offsets of the inbound rules in Blob */
    ULONG BlobSize;
    DECLSPEC_ALIGN(8) UCHAR Blob[ANYSIZE_ARRAY];  /* validated copy of the NITROFW_POLICY sent by the service */
} FW_POLICY, *PFW_POLICY;

/* the blob starts 8-aligned, so every 8-aligned offset inside it (Generation, the rules) is 8-aligned in memory */
C_ASSERT((FIELD_OFFSET(FW_POLICY, Blob) & 7) == 0);

typedef struct _FW_FLOW
{
    ULONG RemoteAddr;           /* network order, 0 = any (reply to a broadcast/multicast send) */
    USHORT LocalPort;           /* network order */
    USHORT RemotePort;          /* network order, 0 = any */
    ULONG Expiry;               /* FwNow() seconds, 0 = free */
} FW_FLOW, *PFW_FLOW;

typedef struct _FW_ICMPFLOW
{
    ULONG RemoteAddr;           /* network order, 0 = any (reply to a broadcast/multicast request) */
    USHORT Ident;               /* as in the packet (network order) */
    UCHAR ReplyType;
    UCHAR Reserved;
    ULONG Expiry;               /* FwNow() seconds, 0 = free */
} FW_ICMPFLOW, *PFW_ICMPFLOW;

volatile LONG NitroFwEnforcing = 0;
volatile LONG NitroFwTracking = 0;      /* filter loaded: outbound UDP sends feed the flow table (also while not enforcing) */
volatile LONG NitroFwWantImages = 0;     /* enforced policy with program rules: address files need their image */

static BOOLEAN FwKilled = TRUE;         /* until NitroFwInitialize decides otherwise */
static BOOLEAN FwOptIn = TRUE;   /* NitroFwEnforce default: on (an absent value, or a value that cannot be read at load) */
static PDEVICE_OBJECT FwDevice = NULL;
static BOOLEAN FwSymlink = FALSE;
static PSECURITY_DESCRIPTOR FwSD = NULL;
static PDRIVER_DISPATCH FwNext[IRP_MJ_MAXIMUM_FUNCTION + 1];

static KSPIN_LOCK FwPolicyLock;
static PFW_POLICY FwPolicy = NULL;      /* under FwPolicyLock */
static FAST_MUTEX FwSetMutex;           /* serializes SET/CLEAR */
static ULONGLONG FwLastGeneration = 0;  /* high-water mark, survives CLEAR */

static KSPIN_LOCK FwFlowLocks[FW_FLOW_LOCKS];
static FW_FLOW FwFlows[FW_FLOW_SETS][FW_FLOW_WAYS];
static FW_ICMPFLOW FwIcmpFlows[FW_ICMP_SETS][FW_FLOW_WAYS];

/* Set from the installed policy while it is enforced (under FwPolicyLock; read without a lock) */
static volatile LONG FwNoUnicast = 0;   /* replies to broadcast/multicast sends are not admitted */
static volatile LONG FwLogEnabled = 0;  /* record dropped packets */

/* The drop log: a ring of the last NITROFW_DROPLOG_RECORDS drops, NITROFW_DROPLOG_RATE records per second */
static KSPIN_LOCK FwLogLock;
static NITROFW_DROP_RECORD FwLog[NITROFW_DROPLOG_RECORDS];
static ULONGLONG FwLogNext = 1;         /* sequence of the next record */
static ULONGLONG FwLogSuppressed = 0;
static ULONG FwLogWindow = 0;           /* FwNow() second the counter below belongs to */
static ULONG FwLogInWindow = 0;

static LONG64 FwDroppedInbound = 0;
static LONG64 FwPassedInbound = 0;
static LONG64 FwImagesCaptured = 0;     /* image resolutions attempted (test counter: stays flat when not enforcing) */

static ULONG FwNow(VOID)
{
    /* seconds since boot, never 0 */
    return (ULONG)(KeQueryInterruptTime() / 10000000ULL) + 1;
}

static ULONG FwNtohl(ULONG v)
{
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | (v >> 24);
}

/* ------------------------------------------------------------------------------------------------
 * Registry switches
 * ---------------------------------------------------------------------------------------------- */

static NTSTATUS FwQueryValue(PCWSTR KeyPath, PCWSTR Name, ULONG Type, PVOID Data, PULONG DataLength)
{
    UNICODE_STRING KeyName, ValueName;
    OBJECT_ATTRIBUTES Attr;
    HANDLE Key;
    NTSTATUS Status;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    ULONG InfoLen, Len;

    PAGED_CODE();
    RtlInitUnicodeString(&KeyName, KeyPath);
    RtlInitUnicodeString(&ValueName, Name);
    InitializeObjectAttributes(&Attr, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attr);
    if (!NT_SUCCESS(Status))
        return Status;

    InfoLen = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + *DataLength;
    Info = ExAllocatePoolWithTag(PagedPool, InfoLen, NITROFW_TAG);
    if (!Info)
    {
        ZwClose(Key);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, InfoLen, &Len);
    if (NT_SUCCESS(Status))
    {
        if (Info->Type != Type || Info->DataLength > *DataLength)
            Status = STATUS_OBJECT_TYPE_MISMATCH;
        else
        {
            RtlCopyMemory(Data, Info->Data, Info->DataLength);
            *DataLength = Info->DataLength;
        }
    }
    ExFreePoolWithTag(Info, NITROFW_TAG);
    ZwClose(Key);
    return Status;
}

/* Read a REG_DWORD switch. An absent key or value is a definite answer, the switch default (returns TRUE,
   *Value = Default); any other failure returns FALSE and leaves *Value alone: the caller decides what an
   unreadable switch means. */
static BOOLEAN FwReadSwitchEx(PCWSTR Name, BOOLEAN Default, PBOOLEAN Value)
{
    ULONG Data = 0, Len = sizeof(Data);
    NTSTATUS Status = FwQueryValue(FW_PARAMS_KEY, Name, REG_DWORD, &Data, &Len);

    if (NT_SUCCESS(Status))
    {
        if (Len != sizeof(Data))
            return FALSE;
        *Value = Data != 0;
        return TRUE;
    }
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND)
    {
        *Value = Default;
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN FwReadSwitch(PCWSTR Name)
{
    BOOLEAN Value = FALSE;
    return FwReadSwitchEx(Name, FALSE, &Value) && Value;
}

/* /NOFIREWALL on the boot entry; the kernel stores the options without slashes */
static BOOLEAN FwBootOptionOff(VOID)
{
    static const WCHAR Option[] = L"NOFIREWALL";
    const ULONG OptLen = RTL_NUMBER_OF(Option) - 1;
    WCHAR Buf[512];
    ULONG Len = sizeof(Buf) - sizeof(WCHAR), Count, i, Start;

    if (!NT_SUCCESS(FwQueryValue(FW_CONTROL_KEY, L"SystemStartOptions", REG_SZ, Buf, &Len)))
        return FALSE;
    Count = Len / sizeof(WCHAR);
    Buf[Count] = 0;
    for (i = 0; i < Count; )
    {
        while (i < Count && (Buf[i] == L' ' || Buf[i] == L'/' || Buf[i] == 0))
            i++;
        Start = i;
        while (i < Count && Buf[i] != L' ' && Buf[i] != L'/' && Buf[i] != 0)
            i++;
        if (i - Start == OptLen)
        {
            ULONG j;
            for (j = 0; j < OptLen && RtlUpcaseUnicodeChar(Buf[Start + j]) == Option[j]; j++)
                ;
            if (j == OptLen)
                return TRUE;
        }
    }
    return FALSE;
}

/* ------------------------------------------------------------------------------------------------
 * Policy reference counting and the enforcing flag
 * ---------------------------------------------------------------------------------------------- */

static VOID FwFreePolicy(PFW_POLICY Policy)
{
    if (Policy->InRuleOffsets)
        ExFreePoolWithTag(Policy->InRuleOffsets, NITROFW_TAG);
    ExFreePoolWithTag(Policy, NITROFW_TAG);
}

static PFW_POLICY FwRefPolicy(VOID)
{
    KIRQL OldIrql;
    PFW_POLICY Policy;

    KeAcquireSpinLock(&FwPolicyLock, &OldIrql);
    Policy = FwPolicy;
    if (Policy)
        InterlockedIncrement(&Policy->RefCount);
    KeReleaseSpinLock(&FwPolicyLock, OldIrql);
    return Policy;
}

static VOID FwDerefPolicy(PFW_POLICY Policy)
{
    if (InterlockedDecrement(&Policy->RefCount) == 0)
        FwFreePolicy(Policy);
}

static BOOLEAN FwPolicyEnforced(PFW_POLICY Policy)
{
    return Policy && FwOptIn && (Policy->Flags & NITROFW_POLICY_ENFORCE) && Policy->EnabledProfiles != 0;
}

/* Install NewPolicy (may be NULL) and drop the reference on the old one. Caller holds FwSetMutex. */
static VOID FwInstallPolicy(PFW_POLICY NewPolicy)
{
    KIRQL OldIrql;
    PFW_POLICY Old;

    KeAcquireSpinLock(&FwPolicyLock, &OldIrql);
    Old = FwPolicy;
    FwPolicy = NewPolicy;
    InterlockedExchange((PLONG)&NitroFwEnforcing, FwPolicyEnforced(NewPolicy) ? 1 : 0);
    InterlockedExchange((PLONG)&NitroFwWantImages, (FwPolicyEnforced(NewPolicy) && NewPolicy->HasAppRules) ? 1 : 0);
    InterlockedExchange((PLONG)&FwNoUnicast, (FwPolicyEnforced(NewPolicy) && NewPolicy->NoUnicastResponses) ? 1 : 0);
    InterlockedExchange((PLONG)&FwLogEnabled, (FwPolicyEnforced(NewPolicy) && NewPolicy->LogDropped) ? 1 : 0);
    KeReleaseSpinLock(&FwPolicyLock, OldIrql);

    if (Old)
        FwDerefPolicy(Old);
}

/* ------------------------------------------------------------------------------------------------
 * Policy validation. Everything in the blob comes from user mode: every count, offset, size and
 * string is checked against the enclosing structure before anything is read through it.
 * ---------------------------------------------------------------------------------------------- */

typedef struct _FW_SPAN { ULONG Start, End; } FW_SPAN;

static int FwCompare16(const UCHAR *a, const UCHAR *b)
{
    ULONG i;
    for (i = 0; i < 16; i++)
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    return 0;
}

/* A list inside a rule: Count elements of ElemSize at Offset, within [sizeof(NITROFW_RULE), RuleSize) */
static BOOLEAN FwCheckList(ULONG RuleSize, ULONG Count, ULONG Offset, ULONG ElemSize, FW_SPAN *Spans, PULONG SpanCount)
{
    ULONG Bytes;

    if (Count == 0)
        return Offset == 0;
    if (Count > NITROFW_MAX_LIST || Offset < sizeof(NITROFW_RULE) || (Offset & 7) || Offset >= RuleSize)
        return FALSE;
    Bytes = Count * ElemSize;                  /* <= 256 * 32, cannot overflow */
    if (Bytes > RuleSize - Offset)
        return FALSE;
    Spans[*SpanCount].Start = Offset;
    Spans[*SpanCount].End = Offset + Bytes;
    (*SpanCount)++;
    return TRUE;
}

/* A NUL-terminated WCHAR string inside a rule; empty strings are rejected */
static BOOLEAN FwCheckString(PUCHAR Rule, ULONG RuleSize, ULONG Offset, FW_SPAN *Spans, PULONG SpanCount)
{
    ULONG i, Chars;
    PWCHAR s;

    if (Offset == 0)
        return TRUE;
    if (Offset < sizeof(NITROFW_RULE) || (Offset & 7) || Offset >= RuleSize)
        return FALSE;
    s = (PWCHAR)(Rule + Offset);
    Chars = (RuleSize - Offset) / sizeof(WCHAR);
    for (i = 0; i < Chars && s[i] != 0; i++)
        ;
    if (i == Chars || i == 0 || i > 32767)
        return FALSE;
    Spans[*SpanCount].Start = Offset;
    Spans[*SpanCount].End = Offset + (i + 1) * sizeof(WCHAR);
    (*SpanCount)++;
    return TRUE;
}

static BOOLEAN FwValidateRule(PUCHAR RulePtr, ULONG RuleSize)
{
    PNITROFW_RULE Rule = (PNITROFW_RULE)RulePtr;
    FW_SPAN Spans[9];
    ULONG SpanCount = 0, i, j;
    PNITROFW_PORT_RANGE Ports;
    PNITROFW_ADDR4_RANGE A4;
    PNITROFW_ADDR6_RANGE A6;

    if (Rule->Action != NITROFW_ACTION_ALLOW && Rule->Action != NITROFW_ACTION_BLOCK)
        return FALSE;
    if (Rule->Direction != NITROFW_DIR_IN && Rule->Direction != NITROFW_DIR_OUT)
        return FALSE;
    if (Rule->Protocol > NITROFW_PROTO_ANY)
        return FALSE;
    if ((Rule->ProfileMask & NITROFW_PROFILE_ALL) == 0)
        return FALSE;
    /* interface types: at least one, only known bits (see NITROFW_RULE.IfTypes in nitrofw.h) */
    if (Rule->IfTypes == 0 || (Rule->IfTypes & ~NITROFW_IFTYPE_ALL))
        return FALSE;
    /* ICMP type/code entries only make sense on an ICMP rule (1 = ICMPv4, 58 = ICMPv6, which never
       matches this IPv4-only filter): with Protocol ANY they would match every non-ICMP packet */
    if (Rule->IcmpCount && Rule->Protocol != 1 && Rule->Protocol != 58)
        return FALSE;

    if (!FwCheckList(RuleSize, Rule->LocalPortCount, Rule->LocalPortOffset, sizeof(NITROFW_PORT_RANGE), Spans, &SpanCount) ||
        !FwCheckList(RuleSize, Rule->RemotePortCount, Rule->RemotePortOffset, sizeof(NITROFW_PORT_RANGE), Spans, &SpanCount) ||
        !FwCheckList(RuleSize, Rule->LocalAddr4Count, Rule->LocalAddr4Offset, sizeof(NITROFW_ADDR4_RANGE), Spans, &SpanCount) ||
        !FwCheckList(RuleSize, Rule->RemoteAddr4Count, Rule->RemoteAddr4Offset, sizeof(NITROFW_ADDR4_RANGE), Spans, &SpanCount) ||
        !FwCheckList(RuleSize, Rule->LocalAddr6Count, Rule->LocalAddr6Offset, sizeof(NITROFW_ADDR6_RANGE), Spans, &SpanCount) ||
        !FwCheckList(RuleSize, Rule->RemoteAddr6Count, Rule->RemoteAddr6Offset, sizeof(NITROFW_ADDR6_RANGE), Spans, &SpanCount) ||
        !FwCheckList(RuleSize, Rule->IcmpCount, Rule->IcmpOffset, sizeof(NITROFW_ICMP_ENTRY), Spans, &SpanCount) ||
        !FwCheckString(RulePtr, RuleSize, Rule->AppPathOffset, Spans, &SpanCount) ||
        !FwCheckString(RulePtr, RuleSize, Rule->ServiceNameOffset, Spans, &SpanCount))
        return FALSE;

    /* no two variable parts may overlap */
    for (i = 0; i < SpanCount; i++)
        for (j = i + 1; j < SpanCount; j++)
            if (Spans[i].Start < Spans[j].End && Spans[j].Start < Spans[i].End)
                return FALSE;

    /* ranges must be ordered */
    Ports = (PNITROFW_PORT_RANGE)(RulePtr + Rule->LocalPortOffset);
    for (i = 0; i < Rule->LocalPortCount; i++)
        if (Ports[i].Low > Ports[i].High) return FALSE;
    Ports = (PNITROFW_PORT_RANGE)(RulePtr + Rule->RemotePortOffset);
    for (i = 0; i < Rule->RemotePortCount; i++)
        if (Ports[i].Low > Ports[i].High) return FALSE;
    A4 = (PNITROFW_ADDR4_RANGE)(RulePtr + Rule->LocalAddr4Offset);
    for (i = 0; i < Rule->LocalAddr4Count; i++)
        if (A4[i].Low > A4[i].High) return FALSE;
    A4 = (PNITROFW_ADDR4_RANGE)(RulePtr + Rule->RemoteAddr4Offset);
    for (i = 0; i < Rule->RemoteAddr4Count; i++)
        if (A4[i].Low > A4[i].High) return FALSE;
    A6 = (PNITROFW_ADDR6_RANGE)(RulePtr + Rule->LocalAddr6Offset);
    for (i = 0; i < Rule->LocalAddr6Count; i++)
        if (FwCompare16(A6[i].Low, A6[i].High) > 0) return FALSE;
    A6 = (PNITROFW_ADDR6_RANGE)(RulePtr + Rule->RemoteAddr6Offset);
    for (i = 0; i < Rule->RemoteAddr6Count; i++)
        if (FwCompare16(A6[i].Low, A6[i].High) > 0) return FALSE;

    return TRUE;
}

/* Validate the captured blob and build the lookup data. Returns STATUS_INVALID_PARAMETER on any error. */
static NTSTATUS FwCompilePolicy(PFW_POLICY Policy)
{
    PNITROFW_POLICY Hdr = (PNITROFW_POLICY)Policy->Blob;
    ULONG Size = Policy->BlobSize, Cursor, i, Bit, nIn = 0;

    if (Size < sizeof(NITROFW_POLICY) || Size > NITROFW_MAX_POLICY_SIZE)
        return STATUS_INVALID_PARAMETER;
    if (Hdr->Magic != NITROFW_POLICY_MAGIC || Hdr->AbiVersion != NITROFW_ABI_VERSION || Hdr->TotalSize != Size)
        return STATUS_INVALID_PARAMETER;
    if (Hdr->RuleCount > NITROFW_MAX_RULES)
        return STATUS_INVALID_PARAMETER;
    /* a Generation near 2^64 would lock out every later push (the high-water mark only moves up) until
       reboot; the service starts from seconds since 1601 and adds one per push, so 2^62 is never reached */
    if (Hdr->Generation == 0 || Hdr->Generation >= NITROFW_MAX_GENERATION)
        return STATUS_INVALID_PARAMETER;
    for (i = 0; i < NITROFW_PROFILE_COUNT; i++)
    {
        if (Hdr->Profile[i].DefaultInbound > NITROFW_ACTION_BLOCK || Hdr->Profile[i].DefaultOutbound > NITROFW_ACTION_BLOCK)
            return STATUS_INVALID_PARAMETER;
    }
    if (Hdr->RuleCount)
    {
        /* the rules start right behind the header: no gap that carries unvalidated bytes */
        if (Hdr->RulesOffset != sizeof(NITROFW_POLICY))
            return STATUS_INVALID_PARAMETER;
        Cursor = Hdr->RulesOffset;
    }
    else
    {
        /* no rules: nothing may follow the header */
        if (Size != sizeof(NITROFW_POLICY))
            return STATUS_INVALID_PARAMETER;
        Cursor = Size;
    }

    /* pass 1: walk and validate every rule */
    for (i = 0; i < Hdr->RuleCount; i++)
    {
        PNITROFW_RULE Rule;
        if (Size - Cursor < sizeof(NITROFW_RULE))
            return STATUS_INVALID_PARAMETER;
        Rule = (PNITROFW_RULE)(Policy->Blob + Cursor);
        if (Rule->Size < sizeof(NITROFW_RULE) || (Rule->Size & 7) || Rule->Size > Size - Cursor)
            return STATUS_INVALID_PARAMETER;
        if (!FwValidateRule((PUCHAR)Rule, Rule->Size))
            return STATUS_INVALID_PARAMETER;
        if (Rule->Direction == NITROFW_DIR_IN)
            nIn++;
        Cursor += Rule->Size;
    }
    /* the rules fill the blob exactly */
    if (Cursor != Size)
        return STATUS_INVALID_PARAMETER;

    /* pass 2: inbound rule index, upcased program paths (compared at DISPATCH_LEVEL byte for byte) */
    if (nIn)
    {
        Policy->InRuleOffsets = ExAllocatePoolWithTag(NonPagedPool, nIn * sizeof(ULONG), NITROFW_TAG);
        if (!Policy->InRuleOffsets)
            return STATUS_INSUFFICIENT_RESOURCES;
    }
    Cursor = Hdr->RuleCount ? Hdr->RulesOffset : Size;
    for (i = 0; i < Hdr->RuleCount; i++)
    {
        PNITROFW_RULE Rule = (PNITROFW_RULE)(Policy->Blob + Cursor);
        if (Rule->Direction == NITROFW_DIR_IN)
        {
            Policy->InRuleOffsets[Policy->InRuleCount++] = Cursor;
            if (Rule->AppPathOffset)
            {
                PWCHAR s = (PWCHAR)((PUCHAR)Rule + Rule->AppPathOffset);
                Policy->HasAppRules = TRUE;
                for (; *s; s++)
                    *s = RtlUpcaseUnicodeChar(*s);
            }
        }
        Cursor += Rule->Size;
    }

    Policy->Flags = Hdr->Flags;
    Policy->Generation = Hdr->Generation;
    Policy->ActiveProfiles = Hdr->ActiveProfiles & NITROFW_PROFILE_ALL;
    Policy->RuleCount = Hdr->RuleCount;
    for (i = 0, Bit = 1; i < NITROFW_PROFILE_COUNT; i++, Bit <<= 1)
    {
        if (!(Policy->ActiveProfiles & Bit) || !(Hdr->Profile[i].Flags & NITROFW_PROFILE_ENABLED))
            continue;
        Policy->EnabledProfiles |= Bit;
        if (Hdr->Profile[i].Flags & NITROFW_PROFILE_BLOCK_ALL_INBOUND)
            Policy->BlockAllInbound = TRUE;
        if (Hdr->Profile[i].DefaultInbound == NITROFW_ACTION_BLOCK)
            Policy->DefaultBlockInbound = TRUE;
        if (Hdr->Profile[i].Flags & NITROFW_PROFILE_NO_UNICAST_RESPONSES)
            Policy->NoUnicastResponses = TRUE;
        if (Hdr->Profile[i].Flags & NITROFW_PROFILE_LOG_DROPPED)
            Policy->LogDropped = TRUE;
    }
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------------------------------
 * IOCTLs
 * ---------------------------------------------------------------------------------------------- */

static VOID FwBackfillImages(VOID);
static NTSTATUS FwGetDropLog(PVOID Buf, ULONG InLen, ULONG OutLen, PULONG_PTR Information);

static NTSTATUS FwSetPolicy(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    ULONG InLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    PFW_POLICY Policy;
    NTSTATUS Status;
    BOOLEAN OptIn = FALSE, OptInRead;
    ULONGLONG Generation;
    ULONG RuleCount, InRuleCount, ActiveProfiles, EnabledProfiles, Flags;
    LONG Enforcing;

    if (InLen < sizeof(NITROFW_POLICY) || InLen > NITROFW_MAX_POLICY_SIZE || !Irp->AssociatedIrp.SystemBuffer)
        return STATUS_INVALID_PARAMETER;

    /* capture: METHOD_BUFFERED already copied it out of user memory; the copy becomes the policy */
    Policy = ExAllocatePoolWithTag(NonPagedPool, FIELD_OFFSET(FW_POLICY, Blob) + InLen, NITROFW_TAG);
    if (!Policy)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Policy, FIELD_OFFSET(FW_POLICY, Blob));
    RtlCopyMemory(Policy->Blob, Irp->AssociatedIrp.SystemBuffer, InLen);
    Policy->BlobSize = InLen;
    Policy->RefCount = 1;

    Status = FwCompilePolicy(Policy);
    if (!NT_SUCCESS(Status))
    {
        FwFreePolicy(Policy);
        return Status;
    }

    /* registry access (Zw calls) before the APC_LEVEL mutex is taken */
    OptInRead = FwReadSwitchEx(L"NitroFwEnforce", TRUE, &OptIn);

    ExAcquireFastMutex(&FwSetMutex);
    if (Policy->Generation <= FwLastGeneration)
    {
        ExReleaseFastMutex(&FwSetMutex);
        FwFreePolicy(Policy);
        return STATUS_REVISION_MISMATCH;
    }
    FwLastGeneration = Policy->Generation;
    if (OptInRead)
        FwOptIn = OptIn;
    else
        OptIn = FwOptIn;    /* unreadable: keep what the last push established (never silently flip) */
    /* the policy is owned by FwPolicy from here on (and may be replaced or freed by the next SET/CLEAR
       as soon as the mutex is gone): everything logged below is copied while still under the mutex */
    Generation = Policy->Generation;
    RuleCount = Policy->RuleCount;
    InRuleCount = Policy->InRuleCount;
    ActiveProfiles = Policy->ActiveProfiles;
    EnabledProfiles = Policy->EnabledProfiles;
    Flags = Policy->Flags;
    FwInstallPolicy(Policy);
    Enforcing = NitroFwEnforcing;
    ExReleaseFastMutex(&FwSetMutex);

    /* sockets that exist already need their image when program rules are now in force */
    if (NitroFwWantImages)
        FwBackfillImages();

    if (!OptInRead)
        DbgPrint("NitroFw: NitroFwEnforce could not be read, opt-in kept at %u\n", OptIn);
    DbgPrint("NitroFw: policy %I64u installed, %lu rules (%lu inbound), profiles 0x%lx enabled 0x%lx, flags 0x%lx, opt-in %u, enforcing %ld\n",
            Generation, RuleCount, InRuleCount, ActiveProfiles, EnabledProfiles, Flags, OptIn, Enforcing);
    return STATUS_SUCCESS;
}

static NTSTATUS FwDeviceControl(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    ULONG OutLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID Buf = Irp->AssociatedIrp.SystemBuffer;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_NITROFW_GET_VERSION:
        {
            PNITROFW_VERSION_INFO Info = Buf;
            if (OutLen < sizeof(*Info) || !Buf)
                return STATUS_BUFFER_TOO_SMALL;
            RtlZeroMemory(Info, sizeof(*Info));
            Info->AbiVersion = NITROFW_ABI_VERSION;
            Info->Features = NITROFW_FEATURE_INBOUND;
            Info->MaxRules = NITROFW_MAX_RULES;
            Irp->IoStatus.Information = sizeof(*Info);
            return STATUS_SUCCESS;
        }

        case IOCTL_NITROFW_SET_POLICY:
            return FwSetPolicy(Irp, IrpSp);

        case IOCTL_NITROFW_GET_STATUS:
        {
            PNITROFW_STATUS St = Buf;
            PFW_POLICY Policy;
            ULONG StSize = OutLen >= sizeof(*St) ? sizeof(*St) : NITROFW_STATUS_V1_SIZE;
            if (OutLen < NITROFW_STATUS_V1_SIZE || !Buf)
                return STATUS_BUFFER_TOO_SMALL;
            RtlZeroMemory(St, StSize);
            Policy = FwRefPolicy();
            if (Policy)
            {
                St->Generation = Policy->Generation;
                St->Flags = Policy->Flags;
                St->RuleCount = Policy->RuleCount;
                St->ActiveProfiles = Policy->ActiveProfiles;
                FwDerefPolicy(Policy);
            }
            St->KernelState = (FwOptIn ? NITROFW_KSTATE_OPTIN : 0) | (NitroFwEnforcing ? NITROFW_KSTATE_ENFORCING : 0);
            St->DroppedInbound = (ULONGLONG)InterlockedCompareExchange64(&FwDroppedInbound, 0, 0);
            St->PassedInbound = (ULONGLONG)InterlockedCompareExchange64(&FwPassedInbound, 0, 0);
            if (StSize >= sizeof(*St))
                St->ImagesCaptured = (ULONGLONG)InterlockedCompareExchange64(&FwImagesCaptured, 0, 0);
            Irp->IoStatus.Information = StSize;
            return STATUS_SUCCESS;
        }

        case IOCTL_NITROFW_GET_DROPLOG:
        {
            ULONG_PTR Info = 0;
            NTSTATUS Status = FwGetDropLog(Buf, IrpSp->Parameters.DeviceIoControl.InputBufferLength, OutLen, &Info);
            Irp->IoStatus.Information = Info;
            return Status;
        }

        case IOCTL_NITROFW_CLEAR_POLICY:
            ExAcquireFastMutex(&FwSetMutex);
            FwInstallPolicy(NULL);
            ExReleaseFastMutex(&FwSetMutex);
            DbgPrint("NitroFw: policy cleared\n");
            return STATUS_SUCCESS;
    }
    return STATUS_INVALID_DEVICE_REQUEST;
}

/* Only SYSTEM and Administrators may open the device (the device ACL says the same; this re-checks
   against the caller's token in case the object manager did not apply it) */
static NTSTATUS FwCheckCreate(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    PIO_SECURITY_CONTEXT Sc = IrpSp->Parameters.Create.SecurityContext;
    ACCESS_MASK Granted;
    NTSTATUS AccessStatus;
    BOOLEAN Allowed;

    if (IrpSp->FileObject && IrpSp->FileObject->FileName.Length != 0)
        return STATUS_OBJECT_NAME_NOT_FOUND;
    if (Irp->RequestorMode == KernelMode)
        return STATUS_SUCCESS;
    if (!FwSD || !Sc || !Sc->AccessState)
        return STATUS_ACCESS_DENIED;

    SeLockSubjectContext(&Sc->AccessState->SubjectSecurityContext);
    Allowed = SeAccessCheck(FwSD, &Sc->AccessState->SubjectSecurityContext, TRUE,
                            FILE_READ_DATA | FILE_WRITE_DATA, 0, NULL,
                            IoGetFileObjectGenericMapping(), UserMode, &Granted, &AccessStatus);
    SeUnlockSubjectContext(&Sc->AccessState->SubjectSecurityContext);
    return Allowed ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}

static NTSTATUS NTAPI FwDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;

    if (DeviceObject != FwDevice || !FwDevice)
        return FwNext[IrpSp->MajorFunction](DeviceObject, Irp);

    Irp->IoStatus.Information = 0;
    switch (IrpSp->MajorFunction)
    {
        case IRP_MJ_CREATE:
            Status = FwCheckCreate(Irp, IrpSp);
            if (NT_SUCCESS(Status))
                Irp->IoStatus.Information = FILE_OPENED;
            break;
        case IRP_MJ_CLEANUP:
        case IRP_MJ_CLOSE:
            Status = STATUS_SUCCESS;
            break;
        case IRP_MJ_DEVICE_CONTROL:
            Status = FwDeviceControl(Irp, IrpSp);
            break;
        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static VOID FwFreeSD(VOID)
{
    if (FwSD)
        ExFreePoolWithTag(FwSD, NITROFW_TAG);
    FwSD = NULL;
}

/* D:P(A;;GA;;;SY)(A;;GA;;;BA), owner BA, group SY */
static NTSTATUS FwCreateSD(VOID)
{
    SECURITY_DESCRIPTOR AbsSD;
    ULONG DaclSize, RelSize = 0;
    PACL Dacl;
    NTSTATUS Status;

    DaclSize = sizeof(ACL) + 2 * sizeof(ACCESS_ALLOWED_ACE) +
               RtlLengthSid(SeExports->SeLocalSystemSid) + RtlLengthSid(SeExports->SeAliasAdminsSid);
    Dacl = ExAllocatePoolWithTag(PagedPool, DaclSize, NITROFW_TAG);
    if (!Dacl)
        return STATUS_INSUFFICIENT_RESOURCES;
    Status = RtlCreateSecurityDescriptor(&AbsSD, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status)) Status = RtlCreateAcl(Dacl, DaclSize, ACL_REVISION);
    if (NT_SUCCESS(Status)) Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, SeExports->SeLocalSystemSid);
    if (NT_SUCCESS(Status)) Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, SeExports->SeAliasAdminsSid);
    if (NT_SUCCESS(Status)) Status = RtlSetDaclSecurityDescriptor(&AbsSD, TRUE, Dacl, FALSE);
    if (NT_SUCCESS(Status)) Status = RtlSetOwnerSecurityDescriptor(&AbsSD, SeExports->SeAliasAdminsSid, FALSE);
    if (NT_SUCCESS(Status)) Status = RtlSetGroupSecurityDescriptor(&AbsSD, SeExports->SeLocalSystemSid, FALSE);
    if (NT_SUCCESS(Status))
    {
        Status = RtlAbsoluteToSelfRelativeSD(&AbsSD, NULL, &RelSize);
        if (Status == STATUS_BUFFER_TOO_SMALL)
        {
            FwSD = ExAllocatePoolWithTag(PagedPool, RelSize, NITROFW_TAG);
            Status = FwSD ? RtlAbsoluteToSelfRelativeSD(&AbsSD, FwSD, &RelSize) : STATUS_INSUFFICIENT_RESOURCES;
            if (!NT_SUCCESS(Status) && FwSD)
            {
                ExFreePoolWithTag(FwSD, NITROFW_TAG);
                FwSD = NULL;
            }
        }
        else if (NT_SUCCESS(Status))
            Status = STATUS_UNSUCCESSFUL;
    }
    ExFreePoolWithTag(Dacl, NITROFW_TAG);
    return Status;
}

/* Called from DriverEntry after the dispatch table is set. A failure here never fails the driver:
   networking keeps working, unfiltered. */
NTSTATUS NitroFwInitialize(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING DevName = RTL_CONSTANT_STRING(NITROFW_DEVICE_NAME);
    UNICODE_STRING DosName = RTL_CONSTANT_STRING(NITROFW_DOS_NAME);
    NTSTATUS Status;
    ULONG i;

    KeInitializeSpinLock(&FwPolicyLock);
    for (i = 0; i < FW_FLOW_LOCKS; i++)
        KeInitializeSpinLock(&FwFlowLocks[i]);
    KeInitializeSpinLock(&FwLogLock);
    ExInitializeFastMutex(&FwSetMutex);

    if (FwReadSwitch(L"NitroFwDisable") || FwBootOptionOff())
    {
        DbgPrint("NitroFw: disabled by the kill switch (NitroFwDisable or /NOFIREWALL)\n");
        return STATUS_SUCCESS;
    }
    FwReadSwitchEx(L"NitroFwEnforce", TRUE, &FwOptIn);   /* unreadable: stays at the default (on) */

    Status = FwCreateSD();
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("NitroFw: no security descriptor (0x%lx), filter not available\n", Status);
        FwFreeSD();
        return Status;
    }

    Status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &FwDevice);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("NitroFw: IoCreateDevice failed (0x%lx), filter not available\n", Status);
        FwDevice = NULL;
        FwFreeSD();
        return Status;
    }
    Status = ObSetSecurityObjectByPointer(FwDevice,
                                          OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                          FwSD);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("NitroFw: cannot secure the device (0x%lx), filter not available\n", Status);
        IoDeleteDevice(FwDevice);
        FwDevice = NULL;
        FwFreeSD();
        return Status;
    }
    FwSymlink = NT_SUCCESS(IoCreateSymbolicLink(&DosName, &DevName));

    /* route our device's IRPs here, everything else to the TDI dispatchers as before */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        FwNext[i] = DriverObject->MajorFunction[i];
    DriverObject->MajorFunction[IRP_MJ_CREATE] = FwDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = FwDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FwDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FwDispatch;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = FwDispatch;

    FwDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    FwKilled = FALSE;
    InterlockedExchange((PLONG)&NitroFwTracking, 1);
    DbgPrint("NitroFw: filter ready, enforcement opt-in %u\n", FwOptIn);
    return STATUS_SUCCESS;
}

VOID NitroFwUnload(VOID)
{
    UNICODE_STRING DosName = RTL_CONSTANT_STRING(NITROFW_DOS_NAME);

    if (FwKilled)
        return;
    InterlockedExchange((PLONG)&NitroFwEnforcing, 0);
    InterlockedExchange((PLONG)&NitroFwTracking, 0);
    InterlockedExchange((PLONG)&NitroFwWantImages, 0);
    if (FwSymlink)
        IoDeleteSymbolicLink(&DosName);
    if (FwDevice)
        IoDeleteDevice(FwDevice);
    FwDevice = NULL;
    FwInstallPolicy(NULL);   /* swaps FwPolicy out under FwPolicyLock and drops the reference */
    FwFreeSD();
    FwKilled = TRUE;
}

/* ------------------------------------------------------------------------------------------------
 * Process image of an address file's creator
 * ---------------------------------------------------------------------------------------------- */

static PFW_IMAGE FwMakeSystemImage(VOID)
{
    static const WCHAR System[] = L"SYSTEM";
    const ULONG Chars = RTL_NUMBER_OF(System) - 1;
    PFW_IMAGE Image;

    Image = ExAllocatePoolWithTag(NonPagedPool, FIELD_OFFSET(FW_IMAGE, Path) + Chars * sizeof(WCHAR), NITROFW_IMG_TAG);
    if (!Image)
        return NULL;
    RtlCopyMemory(Image->Path, System, Chars * sizeof(WCHAR));
    Image->Length = (USHORT)Chars;
    Image->RefCount = 1;
    return Image;
}

/* Image path of the process behind Process (a handle with PROCESS_QUERY_INFORMATION), upcased NT path */
static PFW_IMAGE FwImageFromHandle(HANDLE Process)
{
    PFW_IMAGE Image = NULL;
    PUNICODE_STRING Name;
    ULONG Len = 0, i, Chars;
    NTSTATUS Status;

    InterlockedIncrement64(&FwImagesCaptured);
    Status = ZwQueryInformationProcess(Process, ProcessImageFileName, NULL, 0, &Len);
    if (Status != STATUS_INFO_LENGTH_MISMATCH || Len < sizeof(UNICODE_STRING) || Len > 0x10000 + sizeof(UNICODE_STRING))
        return NULL;
    Name = ExAllocatePoolWithTag(PagedPool, Len, NITROFW_IMG_TAG);
    if (!Name)
        return NULL;
    Status = ZwQueryInformationProcess(Process, ProcessImageFileName, Name, Len, &Len);
    if (NT_SUCCESS(Status) && Name->Buffer && Name->Length >= sizeof(WCHAR))
    {
        Chars = Name->Length / sizeof(WCHAR);
        Image = ExAllocatePoolWithTag(NonPagedPool, FIELD_OFFSET(FW_IMAGE, Path) + Chars * sizeof(WCHAR), NITROFW_IMG_TAG);
        if (Image)
        {
            for (i = 0; i < Chars; i++)
                Image->Path[i] = RtlUpcaseUnicodeChar(Name->Buffer[i]);
            Image->Length = (USHORT)Chars;
            Image->RefCount = 1;
        }
    }
    ExFreePoolWithTag(Name, NITROFW_IMG_TAG);
    return Image;
}

/* Image of the calling process (PASSIVE_LEVEL, in the creator's context) */
static PFW_IMAGE FwImageOfCurrent(VOID)
{
    if (PsGetCurrentProcess() == PsInitialSystemProcess)
        return FwMakeSystemImage();
    return FwImageFromHandle(NtCurrentProcess());
}

/* Image of the process with the given id, which need not be the caller; NULL if it is gone (PASSIVE_LEVEL) */
static PFW_IMAGE FwImageOfPid(HANDLE Pid)
{
    PEPROCESS Process;
    HANDLE Handle;
    PFW_IMAGE Image = NULL;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &Process)))
        return NULL;
    if (Process == PsInitialSystemProcess)
        Image = FwMakeSystemImage();
    else if (NT_SUCCESS(ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_QUERY_INFORMATION,
                                              *PsProcessType, KernelMode, &Handle)))
    {
        Image = FwImageFromHandle(Handle);
        ZwClose(Handle);
    }
    ObDereferenceObject(Process);
    return Image;
}

/* Attach Image (reference transferred) to the address file if it is still on the list and has none;
   otherwise release it. AddrFile is only compared, never dereferenced, unless found on the list; the
   creator id and creation time guard against the structure having been freed and reused meanwhile. */
static VOID FwAttachImage(PADDRESS_FILE AddrFile, HANDLE Pid, LONGLONG Created, PFW_IMAGE Image)
{
    KIRQL OldIrql;
    PLIST_ENTRY Entry;

    if (!Image)
        return;
    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
    for (Entry = AddressFileListHead.Flink; Entry != &AddressFileListHead; Entry = Entry->Flink)
    {
        if (CONTAINING_RECORD(Entry, ADDRESS_FILE, ListEntry) == AddrFile)
        {
            if (!AddrFile->FwImage && AddrFile->ProcessId == Pid && AddrFile->CreationTime.QuadPart == Created)
            {
                AddrFile->FwImage = Image;
                Image = NULL;
            }
            break;
        }
    }
    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);
    NitroFwReleaseImage(Image);
}

/* An address file was just put on the global list (NITROFW_ADDRFILE_CREATED: only called while a
   program rule is in force). Resolution is lazy: when the filter is off or no rule names a program
   nothing is looked up for the socket. */
VOID NitroFwAddressFileCreated(PADDRESS_FILE AddrFile)
{
    if (FwKilled || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    FwAttachImage(AddrFile, AddrFile->ProcessId, AddrFile->CreationTime.QuadPart, FwImageOfCurrent());
}

/* Called after a policy that has program rules came into force: sockets opened before that (listeners
   that were already there) have no image yet; resolve it from the creator's process id. PASSIVE_LEVEL. */
static VOID FwBackfillImages(VOID)
{
    for (;;)
    {
        KIRQL OldIrql;
        PLIST_ENTRY Entry;
        PADDRESS_FILE Todo = NULL;
        HANDLE Pid = NULL;
        LONGLONG Created = 0;
        PFW_IMAGE Image;

        TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
        for (Entry = AddressFileListHead.Flink; Entry != &AddressFileListHead; Entry = Entry->Flink)
        {
            PADDRESS_FILE A = CONTAINING_RECORD(Entry, ADDRESS_FILE, ListEntry);
            if (!A->FwImage && !A->FwImageTried)
            {
                A->FwImageTried = TRUE;   /* one attempt per address file, success or not */
                Todo = A;
                Pid = A->ProcessId;
                Created = A->CreationTime.QuadPart;
                break;
            }
        }
        TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);
        if (!Todo)
            return;

        Image = FwImageOfPid(Pid);
        FwAttachImage(Todo, Pid, Created, Image);   /* Todo may be gone by now; it is looked up on the list again */
    }
}

VOID NitroFwReleaseImage(PVOID Image)
{
    PFW_IMAGE Img = Image;
    if (Img && InterlockedDecrement(&Img->RefCount) == 0)
        ExFreePoolWithTag(Img, NITROFW_IMG_TAG);
}

/* The image of the process owning the local endpoint (TCP: prefer the listener), referenced */
static PFW_IMAGE FwFindOwner(UINT Protocol, USHORT PortN, PIP_ADDRESS Local)
{
    KIRQL OldIrql;
    PLIST_ENTRY Entry;
    PFW_IMAGE Found = NULL;
    BOOLEAN FoundListener = FALSE;

    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
    for (Entry = AddressFileListHead.Flink; Entry != &AddressFileListHead; Entry = Entry->Flink)
    {
        PADDRESS_FILE AddrFile = CONTAINING_RECORD(Entry, ADDRESS_FILE, ListEntry);
        BOOLEAN IsListener;

        if (AddrFile->Protocol != Protocol || AddrFile->Port != PortN || !AddrFile->FwImage)
            continue;
        if (!AddrIsUnspecified(&AddrFile->Address) && !AddrIsEqual(&AddrFile->Address, Local))
            continue;
        IsListener = (Protocol == IPPROTO_TCP && AddrFile->Listener != NULL);
        if (Found && (FoundListener || !IsListener))
            continue;
        if (Found)
            NitroFwReleaseImage(Found);
        Found = AddrFile->FwImage;
        InterlockedIncrement(&Found->RefCount);
        FoundListener = IsListener;
        if (FoundListener || Protocol != IPPROTO_TCP)
            break;
    }
    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);
    return Found;
}

/* ------------------------------------------------------------------------------------------------
 * UDP flow table
 * ---------------------------------------------------------------------------------------------- */

static ULONG FwFlowSet(USHORT LocalPort, ULONG RemoteAddr, USHORT RemotePort)
{
    ULONG h = LocalPort * 0x9E3779B1u;
    h ^= RemoteAddr * 0x85EBCA6Bu;
    h ^= RemotePort * 0xC2B2AE35u;
    h ^= h >> 15;
    return h % FW_FLOW_SETS;
}

static VOID FwFlowInsert(USHORT LocalPort, ULONG RemoteAddr, USHORT RemotePort, ULONG Timeout)
{
    ULONG SetIndex = FwFlowSet(LocalPort, RemoteAddr, RemotePort);
    PFW_FLOW Set = FwFlows[SetIndex], Victim = NULL;
    ULONG Now = FwNow(), i;
    KIRQL OldIrql;

    KeAcquireSpinLock(&FwFlowLocks[SetIndex % FW_FLOW_LOCKS], &OldIrql);
    /* the same exchange again, else a free or expired way, else the way that expires first */
    for (i = 0; i < FW_FLOW_WAYS; i++)
    {
        if (Set[i].Expiry && Set[i].LocalPort == LocalPort && Set[i].RemoteAddr == RemoteAddr && Set[i].RemotePort == RemotePort)
        {
            Victim = &Set[i];
            break;
        }
    }
    for (i = 0; !Victim && i < FW_FLOW_WAYS; i++)
    {
        if (Set[i].Expiry == 0 || (LONG)(Set[i].Expiry - Now) < 0)
            Victim = &Set[i];
    }
    if (!Victim)
    {
        Victim = &Set[0];
        for (i = 1; i < FW_FLOW_WAYS; i++)
        {
            if ((LONG)(Set[i].Expiry - Victim->Expiry) < 0)
                Victim = &Set[i];
        }
    }
    Victim->LocalPort = LocalPort;
    Victim->RemoteAddr = RemoteAddr;
    Victim->RemotePort = RemotePort;
    Victim->Expiry = Now + Timeout;
    KeReleaseSpinLock(&FwFlowLocks[SetIndex % FW_FLOW_LOCKS], OldIrql);
}

/* One lookup of (LocalPort, Ra, Rp); an exact peer (Ra != 0) entry is kept alive by traffic */
static BOOLEAN FwFlowFind(USHORT LocalPort, ULONG Ra, USHORT Rp)
{
    ULONG SetIndex = FwFlowSet(LocalPort, Ra, Rp), Now = FwNow(), i;
    PFW_FLOW Set = FwFlows[SetIndex];
    BOOLEAN Hit = FALSE;
    KIRQL OldIrql;

    KeAcquireSpinLock(&FwFlowLocks[SetIndex % FW_FLOW_LOCKS], &OldIrql);
    for (i = 0; i < FW_FLOW_WAYS; i++)
    {
        if (Set[i].Expiry && (LONG)(Set[i].Expiry - Now) >= 0 &&
            Set[i].LocalPort == LocalPort && Set[i].RemoteAddr == Ra && Set[i].RemotePort == Rp)
        {
            if (Ra != 0)    /* concrete peers only: the wildcard entry is never extended by traffic */
                Set[i].Expiry = Now + FW_UDP_TIMEOUT;
            Hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&FwFlowLocks[SetIndex % FW_FLOW_LOCKS], OldIrql);
    return Hit;
}

static BOOLEAN FwFlowLookup(USHORT LocalPort, ULONG RemoteAddr, USHORT RemotePort)
{
    if (FwFlowFind(LocalPort, RemoteAddr, RemotePort))
        return TRUE;
    /* a reply to a broadcast/multicast send: the wildcard entry. The sender (a concrete peer) now has an
       exchange of its own, so its next packets (a second DHCP/SSDP message, the follow-up of a slow
       responder) pass without needing the wildcard window to still be open. 0.0.0.0 never promotes. */
    if (!FwNoUnicast && FwFlowFind(LocalPort, 0, 0))
    {
        if (RemoteAddr != 0)
            FwFlowInsert(LocalPort, RemoteAddr, RemotePort, FW_UDP_TIMEOUT);
        return TRUE;
    }
    return FALSE;
}

VOID NitroFwNoteUdpSend(USHORT LocalPort, PIP_ADDRESS Remote, USHORT RemotePort, BOOLEAN NonUnicast)
{
    ULONG Ra;

    if (!Remote || Remote->Type != IP_ADDRESS_V4)
        return;
    Ra = Remote->Address.IPv4Address;
    if ((FwNtohl(Ra) >> 28) == 0xE)
        NonUnicast = TRUE;   /* 224.0.0.0/4 */
    if (NonUnicast)
        FwFlowInsert(LocalPort, 0, 0, FW_BCAST_TIMEOUT);
    else
        FwFlowInsert(LocalPort, Ra, RemotePort, FW_UDP_TIMEOUT);
}

/* ------------------------------------------------------------------------------------------------
 * Outstanding ICMP requests
 * ---------------------------------------------------------------------------------------------- */

static ULONG FwIcmpSet(ULONG RemoteAddr, USHORT Ident, UCHAR ReplyType)
{
    ULONG h = RemoteAddr * 0x9E3779B1u;
    h ^= (ULONG)Ident * 0x85EBCA6Bu;
    h ^= (ULONG)ReplyType * 0xC2B2AE35u;
    h ^= h >> 15;
    return h % FW_ICMP_SETS;
}

static VOID FwIcmpInsert(ULONG RemoteAddr, USHORT Ident, UCHAR ReplyType, ULONG Timeout)
{
    ULONG SetIndex = FwIcmpSet(RemoteAddr, Ident, ReplyType);
    PFW_ICMPFLOW Set = FwIcmpFlows[SetIndex], Victim = NULL;
    ULONG Now = FwNow(), i;
    KIRQL OldIrql;

    KeAcquireSpinLock(&FwFlowLocks[SetIndex % FW_FLOW_LOCKS], &OldIrql);
    for (i = 0; i < FW_FLOW_WAYS; i++)
    {
        if (Set[i].Expiry && Set[i].RemoteAddr == RemoteAddr && Set[i].Ident == Ident && Set[i].ReplyType == ReplyType)
        {
            Victim = &Set[i];
            break;
        }
    }
    for (i = 0; !Victim && i < FW_FLOW_WAYS; i++)
    {
        if (Set[i].Expiry == 0 || (LONG)(Set[i].Expiry - Now) < 0)
            Victim = &Set[i];
    }
    if (!Victim)
    {
        Victim = &Set[0];
        for (i = 1; i < FW_FLOW_WAYS; i++)
        {
            if ((LONG)(Set[i].Expiry - Victim->Expiry) < 0)
                Victim = &Set[i];
        }
    }
    Victim->RemoteAddr = RemoteAddr;
    Victim->Ident = Ident;
    Victim->ReplyType = ReplyType;
    Victim->Expiry = Now + Timeout;
    KeReleaseSpinLock(&FwFlowLocks[SetIndex % FW_FLOW_LOCKS], OldIrql);
}

static BOOLEAN FwIcmpFind(ULONG RemoteAddr, USHORT Ident, UCHAR ReplyType)
{
    ULONG SetIndex = FwIcmpSet(RemoteAddr, Ident, ReplyType), Now = FwNow(), i;
    PFW_ICMPFLOW Set = FwIcmpFlows[SetIndex];
    BOOLEAN Hit = FALSE;
    KIRQL OldIrql;

    KeAcquireSpinLock(&FwFlowLocks[SetIndex % FW_FLOW_LOCKS], &OldIrql);
    for (i = 0; i < FW_FLOW_WAYS; i++)
    {
        if (Set[i].Expiry && (LONG)(Set[i].Expiry - Now) >= 0 &&
            Set[i].RemoteAddr == RemoteAddr && Set[i].Ident == Ident && Set[i].ReplyType == ReplyType)
        {
            Hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&FwFlowLocks[SetIndex % FW_FLOW_LOCKS], OldIrql);
    return Hit;
}

/* The reply type that answers an ICMP request type, 0xFF if the type is not a request we track */
static UCHAR FwIcmpReplyFor(UCHAR RequestType)
{
    switch (RequestType)
    {
        case 8:  return 0;      /* echo */
        case 13: return 14;     /* timestamp */
        case 15: return 16;     /* information */
        case 17: return 18;     /* address mask */
    }
    return 0xFF;
}

static BOOLEAN FwIsBroadcastAddress(ULONG AddrN)
{
    KIRQL OldIrql;
    BOOLEAN Bcast = AddrN == 0xFFFFFFFF;
    IF_LIST_ITER(CurrentIF);

    if (Bcast)
        return TRUE;
    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);
    ForEachInterface(CurrentIF) {
        if (CurrentIF != Loopback && CurrentIF->Broadcast.Type == IP_ADDRESS_V4 &&
            CurrentIF->Broadcast.Address.IPv4Address == AddrN)
        {
            Bcast = TRUE;
            break;
        }
    } EndFor(CurrentIF);
    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);
    return Bcast;
}

/* A raw ICMP message the host sends: remember a request so that its reply passes the inbound filter */
VOID NitroFwNoteIcmpSend(PIP_ADDRESS Remote, PUCHAR Icmp, ULONG Length)
{
    ULONG Ra;
    UCHAR Reply;
    USHORT Ident;
    BOOLEAN NonUnicast;

    if (!Remote || Remote->Type != IP_ADDRESS_V4 || !Icmp || Length < 8)
        return;
    Reply = FwIcmpReplyFor(Icmp[0]);
    if (Reply == 0xFF)
        return;
    Ra = Remote->Address.IPv4Address;
    Ident = *(USHORT UNALIGNED *)(Icmp + 4);
    NonUnicast = (FwNtohl(Ra) >> 28) == 0xE || FwIsBroadcastAddress(Ra);
    if (NonUnicast)
        FwIcmpInsert(0, Ident, Reply, FW_BCAST_TIMEOUT);
    else
        FwIcmpInsert(Ra, Ident, Reply, FW_ICMP_TIMEOUT);
}

/* Is this an ICMP reply to a request the host sent? */
static BOOLEAN FwIcmpReplyExpected(ULONG SrcAddrN, PUCHAR Icmp, ULONG Length)
{
    USHORT Ident;

    if (Length < 8)
        return FALSE;
    Ident = *(USHORT UNALIGNED *)(Icmp + 4);
    if (FwIcmpFind(SrcAddrN, Ident, Icmp[0]))
        return TRUE;
    return !FwNoUnicast && FwIcmpFind(0, Ident, Icmp[0]);
}

/* ------------------------------------------------------------------------------------------------
 * The inbound decision
 * ---------------------------------------------------------------------------------------------- */

/* Is Address the unicast address of one of the host's interfaces? */
static BOOLEAN FwIsOwnUnicast(PIP_ADDRESS Address)
{
    KIRQL OldIrql;
    BOOLEAN Own = FALSE;
    IF_LIST_ITER(CurrentIF);

    if (Address->Type != IP_ADDRESS_V4 || AddrIsUnspecified(Address))
        return FALSE;
    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);
    ForEachInterface(CurrentIF) {
        if (AddrIsEqual(&CurrentIF->Unicast, Address))
        {
            Own = TRUE;
            break;
        }
    } EndFor(CurrentIF);
    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);
    return Own;
}

typedef struct _FW_PKT
{
    UINT Protocol;
    BOOLEAN HasPorts;       /* TCP or UDP */
    BOOLEAN IsIcmp;
    USHORT LocalPort;       /* host order */
    USHORT RemotePort;
    USHORT LocalPortN;      /* network order */
    ULONG LocalAddr;        /* host order */
    ULONG RemoteAddr;
    UCHAR IcmpType, IcmpCode;
    PIP_ADDRESS Dst;
    PFW_IMAGE Owner;
    BOOLEAN OwnerLooked;
    BOOLEAN IcmpUnsolicitedReply;   /* an ICMP reply with no request of ours behind it */
} FW_PKT, *PFW_PKT;

/* ------------------------------------------------------------------------------------------------
 * Drop log
 * ---------------------------------------------------------------------------------------------- */

static VOID FwLogDrop(PFW_PKT Pkt, ULONG Size, UCHAR Reason)
{
    KIRQL OldIrql;
    ULONG Now = FwNow();
    PNITROFW_DROP_RECORD Rec;

    KeAcquireSpinLock(&FwLogLock, &OldIrql);
    if (FwLogWindow != Now)
    {
        FwLogWindow = Now;
        FwLogInWindow = 0;
    }
    if (FwLogInWindow >= NITROFW_DROPLOG_RATE)
    {
        FwLogSuppressed++;
        KeReleaseSpinLock(&FwLogLock, OldIrql);
        return;
    }
    FwLogInWindow++;
    Rec = &FwLog[(FwLogNext - 1) % NITROFW_DROPLOG_RECORDS];
    RtlZeroMemory(Rec, sizeof(*Rec));
    Rec->Sequence = FwLogNext++;
    KeQuerySystemTime((PLARGE_INTEGER)&Rec->Time);
    Rec->SrcAddr = Pkt->RemoteAddr;
    Rec->DstAddr = Pkt->LocalAddr;
    Rec->SrcPort = Pkt->RemotePort;
    Rec->DstPort = Pkt->LocalPort;
    Rec->Protocol = (UCHAR)Pkt->Protocol;
    Rec->Reason = Reason;
    Rec->Size = Size;
    if (Pkt->IsIcmp)
    {
        Rec->IcmpType = Pkt->IcmpType;
        Rec->IcmpCode = Pkt->IcmpCode;
    }
    KeReleaseSpinLock(&FwLogLock, OldIrql);
}

/* IOCTL_NITROFW_GET_DROPLOG: Buf is both the (optional) ULONGLONG input and the output */
static NTSTATUS FwGetDropLog(PVOID Buf, ULONG InLen, ULONG OutLen, PULONG_PTR Information)
{
    PNITROFW_DROPLOG Hdr = Buf;
    PNITROFW_DROP_RECORD Out;
    ULONGLONG From = 0, Oldest, Start;
    ULONG Fit, Count = 0, i;
    KIRQL OldIrql;

    if (!Buf || OutLen < sizeof(NITROFW_DROPLOG))
        return STATUS_BUFFER_TOO_SMALL;
    if (InLen >= sizeof(ULONGLONG))
        From = *(PULONGLONG)Buf;
    Out = (PNITROFW_DROP_RECORD)(Hdr + 1);
    Fit = (OutLen - sizeof(NITROFW_DROPLOG)) / sizeof(NITROFW_DROP_RECORD);

    KeAcquireSpinLock(&FwLogLock, &OldIrql);
    Oldest = FwLogNext > NITROFW_DROPLOG_RECORDS ? FwLogNext - NITROFW_DROPLOG_RECORDS : 1;
    Start = From > Oldest ? From : Oldest;
    for (i = 0; Start + i < FwLogNext && Count < Fit; i++)
    {
        Out[Count++] = FwLog[(Start + i - 1) % NITROFW_DROPLOG_RECORDS];
    }
    Hdr->NextSequence = FwLogNext;
    Hdr->Suppressed = FwLogSuppressed;
    KeReleaseSpinLock(&FwLogLock, OldIrql);

    Hdr->Count = Count;
    Hdr->Flags = FwLogEnabled ? NITROFW_DROPLOG_ON : 0;
    *Information = sizeof(NITROFW_DROPLOG) + (ULONG_PTR)Count * sizeof(NITROFW_DROP_RECORD);
    return STATUS_SUCCESS;
}

static BOOLEAN FwPortIn(PUCHAR Rule, ULONG Count, ULONG Offset, USHORT Port)
{
    PNITROFW_PORT_RANGE R = (PNITROFW_PORT_RANGE)(Rule + Offset);
    ULONG i;
    for (i = 0; i < Count; i++)
        if (Port >= R[i].Low && Port <= R[i].High)
            return TRUE;
    return FALSE;
}

static BOOLEAN FwAddrIn(PUCHAR Rule, ULONG Count, ULONG Offset, ULONG Addr)
{
    PNITROFW_ADDR4_RANGE R = (PNITROFW_ADDR4_RANGE)(Rule + Offset);
    ULONG i;
    for (i = 0; i < Count; i++)
        if (Addr >= R[i].Low && Addr <= R[i].High)
            return TRUE;
    return FALSE;
}

static BOOLEAN FwRuleMatches(PNITROFW_RULE Rule, PFW_PKT Pkt)
{
    PUCHAR R = (PUCHAR)Rule;

    if (Rule->Protocol != NITROFW_PROTO_ANY && Rule->Protocol != Pkt->Protocol)
        return FALSE;
    /* Interface types cannot be resolved yet: every interface counts as LAN. A rule that includes LAN
       applies; a rule without it never matches if it Allows, but a Block rule applies anyway (fail
       closed: a Block restricted to Wireless/RemoteAccess is not silently ignored). */
    if (!(Rule->IfTypes & NITROFW_IFTYPE_LAN) && Rule->Action == NITROFW_ACTION_ALLOW)
        return FALSE;

    if (Rule->LocalPortCount || Rule->RemotePortCount)
    {
        if (!Pkt->HasPorts)
            return FALSE;
        if (Rule->LocalPortCount && !FwPortIn(R, Rule->LocalPortCount, Rule->LocalPortOffset, Pkt->LocalPort))
            return FALSE;
        if (Rule->RemotePortCount && !FwPortIn(R, Rule->RemotePortCount, Rule->RemotePortOffset, Pkt->RemotePort))
            return FALSE;
    }

    /* an address condition given only for IPv6 never matches an IPv4 packet */
    if (Rule->LocalAddr4Count || Rule->LocalAddr6Count)
    {
        if (!Rule->LocalAddr4Count || !FwAddrIn(R, Rule->LocalAddr4Count, Rule->LocalAddr4Offset, Pkt->LocalAddr))
            return FALSE;
    }
    if (Rule->RemoteAddr4Count || Rule->RemoteAddr6Count)
    {
        if (!Rule->RemoteAddr4Count || !FwAddrIn(R, Rule->RemoteAddr4Count, Rule->RemoteAddr4Offset, Pkt->RemoteAddr))
            return FALSE;
    }

    if (Rule->IcmpCount && Pkt->IsIcmp)
    {
        PNITROFW_ICMP_ENTRY E = (PNITROFW_ICMP_ENTRY)(R + Rule->IcmpOffset);
        ULONG i;
        for (i = 0; i < Rule->IcmpCount; i++)
        {
            if ((E[i].Type == NITROFW_ICMP_ANY || E[i].Type == Pkt->IcmpType) &&
                (E[i].Code == NITROFW_ICMP_ANY || E[i].Code == Pkt->IcmpCode))
                break;
        }
        if (i == Rule->IcmpCount)
            return FALSE;
    }

    if (Rule->AppPathOffset)
    {
        PWCHAR App = (PWCHAR)(R + Rule->AppPathOffset);
        SIZE_T Len;
        if (!Pkt->HasPorts)
            return FALSE;
        if (!Pkt->OwnerLooked)
        {
            Pkt->Owner = FwFindOwner(Pkt->Protocol, Pkt->LocalPortN, Pkt->Dst);
            Pkt->OwnerLooked = TRUE;
        }
        if (!Pkt->Owner)
            return FALSE;
        for (Len = 0; App[Len]; Len++)
            ;
        if (Len != Pkt->Owner->Length || RtlCompareMemory(App, Pkt->Owner->Path, Len * sizeof(WCHAR)) != Len * sizeof(WCHAR))
            return FALSE;
    }

    /* ServiceNameOffset: advisory, not resolved (NITROFW_FEATURE_SERVICE_MATCH clear) */
    return TRUE;
}

BOOLEAN NitroFwInboundAllowed(PIP_INTERFACE Interface, PIP_PACKET IPPacket, UINT Protocol)
{
    PFW_POLICY Policy;
    FW_PKT Pkt;
    PUCHAR Data;
    ULONG DataLen, i;
    BOOLEAN Allow, AllowRule = FALSE, Decided = FALSE;
    UCHAR DropReason = NITROFW_DROP_DEFAULT;

    /* loopback passes: by interface only. A 127/8 address on a real interface is not loopback
       (spoofed or misrouted) and goes through the rules or the default like any other packet. */
    if (Interface == Loopback || IPPacket->Type != IP_ADDRESS_V4)
        return TRUE;

    /* Host to itself over a real address (LAN IP to LAN IP): the stack sends it out through the adapter
       and NDIS loops it back up from inside the send call. Source and destination both being ours is not
       enough on its own, and neither is the frame's source MAC (a peer on the wire can send a frame with
       our MAC and our IP): the frame must be one our own send path tagged as looped back
       (IP_PACKET.FromOwnLink, carried through reassembly: every fragment must have been tagged). */
    if (IPPacket->FromOwnLink && FwIsOwnUnicast(&IPPacket->SrcAddr) && FwIsOwnUnicast(&IPPacket->DstAddr))
        goto PassCounted;

    RtlZeroMemory(&Pkt, sizeof(Pkt));
    Pkt.Protocol = Protocol;
    Pkt.RemoteAddr = FwNtohl(IPPacket->SrcAddr.Address.IPv4Address);
    Pkt.LocalAddr = FwNtohl(IPPacket->DstAddr.Address.IPv4Address);
    Pkt.Dst = &IPPacket->DstAddr;

    /* the reassembled datagram is contiguous: header, then TotalSize - HeaderSize payload bytes */
    if (!IPPacket->Header || IPPacket->TotalSize < IPPacket->HeaderSize)
        return TRUE;
    Data = (PUCHAR)IPPacket->Header + IPPacket->HeaderSize;
    DataLen = IPPacket->TotalSize - IPPacket->HeaderSize;

    switch (Protocol)
    {
        case IPPROTO_TCP:
            if (DataLen < 20)
                return TRUE;    /* the transport discards it */
            /* only a connection request (SYN without ACK) is unsolicited; everything else belongs to a
               connection or is answered by the stack as before */
            if ((Data[13] & 0x12) != 0x02)
                goto PassCounted;
            Pkt.HasPorts = TRUE;
            break;
        case IPPROTO_UDP:
            if (DataLen < 8)
                return TRUE;
            Pkt.HasPorts = TRUE;
            break;
        case IPPROTO_ICMP:
            if (DataLen < 2)
                return TRUE;
            Pkt.IsIcmp = TRUE;
            Pkt.IcmpType = Data[0];
            Pkt.IcmpCode = Data[1];
            switch (Pkt.IcmpType)
            {
                case 3: case 4: case 11: case 12:
                    goto PassCounted;   /* errors */
                case 0: case 14: case 16: case 18:
                    /* a reply: it passes if the host sent the request; else it is unsolicited and is
                       evaluated like a request (the rules, then the profile default) */
                    if (FwIcmpReplyExpected(IPPacket->SrcAddr.Address.IPv4Address, Data, DataLen))
                        goto PassCounted;
                    Pkt.IcmpUnsolicitedReply = TRUE;
                    break;
            }
            break;
    }
    if (Pkt.HasPorts)
    {
        Pkt.RemotePort = (USHORT)((Data[0] << 8) | Data[1]);
        Pkt.LocalPort = (USHORT)((Data[2] << 8) | Data[3]);
        Pkt.LocalPortN = *(USHORT UNALIGNED *)(Data + 2);
        if (Protocol == IPPROTO_UDP)
        {
            /* DHCP client replies (the server answers from 67 to our 68) */
            if (Pkt.RemotePort == 67 && Pkt.LocalPort == 68)
                goto PassCounted;
            if (FwFlowLookup(Pkt.LocalPortN, IPPacket->SrcAddr.Address.IPv4Address, *(USHORT UNALIGNED *)Data))
                goto PassCounted;
        }
    }

    Policy = FwRefPolicy();
    if (!FwPolicyEnforced(Policy))
    {
        if (Policy)
            FwDerefPolicy(Policy);
        return TRUE;
    }

    if (Policy->BlockAllInbound)
    {
        Allow = FALSE;
        Decided = TRUE;
        DropReason = NITROFW_DROP_BLOCK_ALL;
    }
    for (i = 0; !Decided && i < Policy->InRuleCount; i++)
    {
        PNITROFW_RULE Rule = (PNITROFW_RULE)(Policy->Blob + Policy->InRuleOffsets[i]);
        if (!(Rule->ProfileMask & Policy->EnabledProfiles))
            continue;
        if (Rule->Action == NITROFW_ACTION_ALLOW && AllowRule)
            continue;   /* already allowed; only a Block rule can change the outcome */
        if (!FwRuleMatches(Rule, &Pkt))
            continue;
        if (Rule->Action == NITROFW_ACTION_BLOCK)
        {
            Allow = FALSE;      /* block beats allow */
            Decided = TRUE;
            DropReason = NITROFW_DROP_BLOCK_RULE;
        }
        else
            AllowRule = TRUE;
    }
    if (!Decided)
        Allow = AllowRule || !Policy->DefaultBlockInbound;

    FwDerefPolicy(Policy);
    if (Pkt.Owner)
        NitroFwReleaseImage(Pkt.Owner);

    if (!Allow)
    {
        InterlockedIncrement64(&FwDroppedInbound);
        if (FwLogEnabled)
            FwLogDrop(&Pkt, IPPacket->TotalSize, (DropReason == NITROFW_DROP_DEFAULT && Pkt.IcmpUnsolicitedReply) ? NITROFW_DROP_ICMP_REPLY : DropReason);
        return FALSE;
    }

PassCounted:
    InterlockedIncrement64(&FwPassedInbound);
    return TRUE;
}
