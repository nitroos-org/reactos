/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Configuration Manager - registry access control audit mode (shadow access check)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The configuration manager does not enforce key security yet: the open
 * check in CmpDoOpen runs against the synthetic Everyone:GENERIC_ALL
 * descriptor of CmpQuerySecurityDescriptor, and a create checks nothing on
 * the parent. Audit mode runs a second, shadow access check next to the
 * real one, against the descriptor the key would have on Windows 10, and
 * records every open or create that Windows would deny. It never changes a
 * result: the shadow check runs after the real decision, its outcome is only
 * counted and logged, and none of its failures reach the caller.
 *
 * Mode (CmpRegistryAclMode): 0 legacy (no shadow check), 1 audit (default),
 * 2 enforce (accepted, and behaves as audit until enforcement exists). The
 * boot option /REGACL=LEGACY|AUDIT|ENFORCE wins over the REG_DWORD value
 * Control\Session Manager\Configuration Manager\RegistryAclMode.
 *
 * Effective descriptor of a key (CmpGetEffectiveKeySd):
 *  1. the key's stored 'sk' cell;
 *  2. otherwise the nearest ancestor's stored descriptor, inherited (as the
 *     kernel would assign it for a key created by SYSTEM);
 *  3. otherwise a descriptor synthesised from the key's place in the
 *     namespace, with the Windows 10 22H2 values (oracle capture of the
 *     registry ACL design, section 4.1).
 *
 * Output: one DbgPrintEx line per distinct denial (image, key, operation,
 * access), a JSON-lines file \SystemRoot\System32\LogFiles\RegAcl\audit.log
 * (UTC) and counters in the volatile key Control\RegAcl\AuditStats. Both are
 * written by a delayed work item, never from the open path and never under
 * a registry lock. Distinct denials, file size and the bytes written per
 * boot are capped.
 *
 * Everything the check reads from user mode (the name, the desired access,
 * the token) is treated as untrusted: names come from the KCB tree, never
 * from the caller's buffers, and the descriptor read from a hive is
 * validated before use.
 */

/* INCLUDES ******************************************************************/

#include "ntoskrnl.h"
#define NDEBUG
#include "debug.h"

/* DEFINITIONS ***************************************************************/

#define TAG_CM_ACL                  'aAmC'

/* Distinct denials kept per boot, and the dedup table that finds them */
#define CMP_ACL_TABLE_SIZE          4096
#define CMP_ACL_TABLE_PROBE         16
#define CMP_ACL_MAX_ENTRIES         2048

/* Log file limits */
#define CMP_ACL_FILE_ROTATE_SIZE    (8 * 1024 * 1024)
#define CMP_ACL_BOOT_WRITE_LIMIT    (4 * 1024 * 1024)
#define CMP_ACL_LINE_SIZE           2048
#define CMP_ACL_FILE_RETRIES        30

/* Worker timing, in seconds */
#define CMP_ACL_FLUSH_DELAY         10
#define CMP_ACL_COUNT_INTERVAL      600
#define CMP_ACL_PUBLISH_INTERVAL    60

/* Longest strings an entry keeps (characters): bounds the pool an entry pins */
#define CMP_ACL_MAX_KEY_CHARS       512
#define CMP_ACL_MAX_NAME_CHARS      256

/*
 * Encoded bytes a string takes in a log line (a non-ASCII character takes six): the four
 * together and the fixed text of a line stay under CMP_ACL_LINE_SIZE
 */
#define CMP_ACL_LINE_KEY_BYTES      880
#define CMP_ACL_LINE_NAME_BYTES     280
#define CMP_ACL_LINE_USER_BYTES     120

/* Levels of a key path the policy table looks at (\REGISTRY is level 0) */
#define CMP_ACL_LEVELS              8

/* Room for a synthesised descriptor (the largest has six ACEs) */
#define CMP_ACL_SD_BUFFER           512

/* Rules that produced the effective descriptor (logged by name) */
typedef enum _CMP_ACL_RULE
{
    CmpAclRuleCell = 0,
    CmpAclRuleInherited,
    CmpAclRuleMaster,
    CmpAclRuleHardware,
    CmpAclRuleHiveRoot,
    CmpAclRuleSamSecurity,
    CmpAclRuleTaskCache,
    CmpAclRuleEventLog,
    CmpAclRuleDefault,
    CmpAclRuleUser,
    CmpAclRuleUserUnknown,
    CmpAclRuleOther,
    CmpAclRuleMax
} CMP_ACL_RULE;

static const PCSTR CmpAclRuleNames[CmpAclRuleMax] =
{
    "cell", "inherited", "master", "hardware", "hive-root", "sam-security",
    "taskcache", "eventlog", "default", "user", "user-unknown", "other"
};

static const PCSTR CmpAclOpNames[] = { "open", "create", "createlink", "linknode" };
static const PCSTR CmpAclModeNames[] = { "legacy", "audit", "enforce" };
static const PCSTR CmpAclSourceNames[] = { "default", "registry", "bootoption" };

/* Well-known SIDs the policy descriptors use */
typedef enum _CMP_ACL_SID
{
    CmpAclSidSystem = 0,        /* SY  S-1-5-18 */
    CmpAclSidAdmins,            /* BA  S-1-5-32-544 */
    CmpAclSidUsers,             /* BU  S-1-5-32-545 */
    CmpAclSidWorld,             /* WD  S-1-1-0 */
    CmpAclSidRestricted,        /* RC  S-1-5-12 */
    CmpAclSidCreatorOwner,      /* CO  S-1-3-0 */
    CmpAclSidAppPackages,       /* AC  S-1-15-2-1 */
    CmpAclSidLpacCapability,    /* the capability SID Windows 10 puts on the roots */
    CmpAclSidAuthenticated,     /* AU  S-1-5-11 */
    CmpAclSidServerOperators,   /* SO  S-1-5-32-549 */
    CmpAclSidMax,
    CmpAclSidUser = 0xFF        /* the SID taken from \REGISTRY\USER\<SID> */
} CMP_ACL_SID;

typedef struct _CMP_ACL_SID_SPEC
{
    UCHAR Authority;
    UCHAR Count;
    ULONG SubAuthority[10];
} CMP_ACL_SID_SPEC;

static const CMP_ACL_SID_SPEC CmpAclSidSpecs[CmpAclSidMax] =
{
    { 5, 1, { 18 } },
    { 5, 2, { 32, 544 } },
    { 5, 2, { 32, 545 } },
    { 1, 1, { 0 } },
    { 5, 1, { 12 } },
    { 3, 1, { 0 } },
    { 15, 2, { 2, 1 } },
    /* S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-
       3232135806-4053264122-3456934681, copied from the oracle capture */
    { 15, 10, { 3, 1024, 1065365936, 1281604716, 3511738428u, 1654721687,
                432734479, 3232135806u, 4053264122u, 3456934681u } },
    { 5, 1, { 11 } },
    { 5, 2, { 32, 549 } },
};

typedef struct _CMP_ACL_ACE_SPEC
{
    UCHAR Flags;
    UCHAR Sid;
    ACCESS_MASK Mask;
} CMP_ACL_ACE_SPEC;

typedef struct _CMP_ACL_SD_SPEC
{
    UCHAR Owner;
    UCHAR Group;
    USHORT Control;
    ULONG AceCount;
    CMP_ACL_ACE_SPEC Aces[8];
} CMP_ACL_SD_SPEC;

#define KA  KEY_ALL_ACCESS
#define KR  KEY_READ
#define CI  CONTAINER_INHERIT_ACE
#define OICI (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)

/*
 * Windows 10 22H2 descriptors (oracle capture). A synthesised descriptor
 * stands for the whole subtree below the key it was measured on: for every
 * token nitro can build, an inherited child grants the same access as the
 * root (the CI ACEs carry over unchanged, CREATOR OWNER never matches a
 * token, AC and the LPAC capability are never evaluated).
 */
static const CMP_ACL_SD_SPEC CmpAclSdMaster =
{
    /* \REGISTRY, \REGISTRY\MACHINE, \REGISTRY\USER, HKLM\HARDWARE:
       O:SYG:SYD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)(A;CI;KR;;;AC)(A;CI;KR;;;LPAC) */
    CmpAclSidSystem, CmpAclSidSystem, 0, 6,
    {
        { CI, CmpAclSidSystem, KA },
        { CI, CmpAclSidAdmins, KA },
        { CI, CmpAclSidWorld, KR },
        { CI, CmpAclSidRestricted, KR },
        { CI, CmpAclSidAppPackages, KR },
        { CI, CmpAclSidLpacCapability, KR },
    }
};

static const CMP_ACL_SD_SPEC CmpAclSdHiveRoot =
{
    /* HKLM\SYSTEM, HKLM\SOFTWARE, HKLM\SAM:
       O:BAG:SYD:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)(A;CI;KR;;;AC)(A;CI;KR;;;LPAC) */
    CmpAclSidAdmins, CmpAclSidSystem, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED, 6,
    {
        { CI, CmpAclSidUsers, KR },
        { CI, CmpAclSidAdmins, KA },
        { CI, CmpAclSidSystem, KA },
        { CI, CmpAclSidCreatorOwner, KA },
        { CI, CmpAclSidAppPackages, KR },
        { CI, CmpAclSidLpacCapability, KR },
    }
};

static const CMP_ACL_SD_SPEC CmpAclSdSamSecurity =
{
    /* HKLM\SAM\SAM, HKLM\SECURITY: O:BAG:SYD:(A;CI;KA;;;SY)(A;CI;RCWD;;;BA) */
    CmpAclSidAdmins, CmpAclSidSystem, 0, 2,
    {
        { CI, CmpAclSidSystem, KA },
        { CI, CmpAclSidAdmins, READ_CONTROL | WRITE_DAC },
    }
};

static const CMP_ACL_SD_SPEC CmpAclSdTaskCache =
{
    /* ...\Windows NT\CurrentVersion\Schedule\TaskCache: D:PAI(A;OICI;CCSWRPSDRC;;;BA)(A;OICI;KA;;;SY).
       The owner is not in the capture; an admin's MAXIMUM_ALLOWED there was 0x30019 (no WRITE_DAC),
       so it is not BA: SY is used. */
    CmpAclSidSystem, CmpAclSidSystem, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED, 2,
    {
        { OICI, CmpAclSidAdmins, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | DELETE | READ_CONTROL },
        { OICI, CmpAclSidSystem, KA },
    }
};

static const CMP_ACL_SD_SPEC CmpAclSdEventLog =
{
    /* SYSTEM\<ControlSet>\Services\EventLog:
       D:PAI(A;;KR;;;AU)(A;CIIO;GR;;;AU)(A;;KR;;;SO)(A;CIIO;GR;;;SO)(A;;KA;;;BA)(A;CIIO;GA;;;BA)(A;;KA;;;SY)(A;CIIO;GA;;;SY)
       in its effective form for the key and its subkeys (GR and GA map to KR and KA) */
    CmpAclSidSystem, CmpAclSidSystem, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED, 4,
    {
        { CI, CmpAclSidAuthenticated, KR },
        { CI, CmpAclSidServerOperators, KR },
        { CI, CmpAclSidAdmins, KA },
        { CI, CmpAclSidSystem, KA },
    }
};

static const CMP_ACL_SD_SPEC CmpAclSdDefault =
{
    /* HKU\.DEFAULT (and the S-1-5-18 link):
       O:BAG:SYD:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)(A;;KR;;;AC)(A;;KR;;;LPAC) */
    CmpAclSidAdmins, CmpAclSidSystem, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED, 6,
    {
        { CI, CmpAclSidUsers, KR },
        { CI, CmpAclSidAdmins, KA },
        { CI, CmpAclSidSystem, KA },
        { CI, CmpAclSidCreatorOwner, KA },
        { 0, CmpAclSidAppPackages, KR },
        { 0, CmpAclSidLpacCapability, KR },
    }
};

static const CMP_ACL_SD_SPEC CmpAclSdUser =
{
    /* HKU\<SID> (HKCU root, HKCU\Software, and S-1-5-19/20 with LS/NS):
       O:BAG:SYD:P(A;OICI;KA;;;<SID>)(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KR;;;RC)(A;;KR;;;AC)(A;;KR;;;LPAC) */
    CmpAclSidAdmins, CmpAclSidSystem, SE_DACL_PROTECTED, 6,
    {
        { OICI, CmpAclSidUser, KA },
        { OICI, CmpAclSidSystem, KA },
        { OICI, CmpAclSidAdmins, KA },
        { OICI, CmpAclSidRestricted, KR },
        { 0, CmpAclSidAppPackages, KR },
        { 0, CmpAclSidLpacCapability, KR },
    }
};

#undef KA
#undef KR
#undef CI
#undef OICI

/* One distinct denial */
typedef struct _CMP_ACL_ENTRY
{
    SLIST_ENTRY QueueEntry;
    ULONG Id;
    ULONG Slot;
    ULONG Operation;
    ULONG Rule;
    ACCESS_MASK Desired;
    ACCESS_MASK Granted;
    NTSTATUS ShadowStatus;
    ULONG Pid;
    ULONG IntegrityRid;
    BOOLEAN Admin;
    BOOLEAN Restricted;
    BOOLEAN Impersonating;
    LONG WrittenCount;
    LARGE_INTEGER Time;
    USHORT KeyChars;
    USHORT ChildChars;
    USHORT ImageChars;
    USHORT UserChars;
    WCHAR Strings[ANYSIZE_ARRAY];
} CMP_ACL_ENTRY, *PCMP_ACL_ENTRY;

/* GLOBALS *******************************************************************/

/* Read by CmGetSystemControlValues (phase 0) from the SYSTEM hive */
ULONG CmpRegistryAclModeValue = MAXULONG;
ULONG CmpRegistryAclModeValueLength = sizeof(ULONG);
ULONG CmpRegistryAclModeValueType = REG_NONE;

/* Configured mode, the mode that runs, and where it came from */
ULONG CmpRegistryAclMode = CM_REGACL_MODE_AUDIT;
ULONG CmpRegistryAclEffectiveMode = CM_REGACL_MODE_LEGACY;
static ULONG CmpRegistryAclModeSource;

/* Counters (published in AuditStats) */
static LONG CmpAclChecks;
static LONG CmpAclDenials;
static LONG CmpAclEntryCount;
static LONG CmpAclDropped;
static LONG CmpAclErrors;
static LONG CmpAclMaxAllowedReduced;
static LONG CmpAclLinesWritten;
static LONG CmpAclFileErrors;
static LONG CmpAclSaturated;
static LONG CmpAclNextId;

/* Synthesised descriptors, built once */
static PSECURITY_DESCRIPTOR CmpAclSdTable[CmpAclRuleMax];
static PSID CmpAclSids[CmpAclSidMax];
static SECURITY_SUBJECT_CONTEXT CmpAclSystemSubject;
static BOOLEAN CmpAclReady;

/* Dedup table */
static LONG64 CmpAclSlotKey[CMP_ACL_TABLE_SIZE];
static LONG CmpAclSlotCount[CMP_ACL_TABLE_SIZE];
static PCMP_ACL_ENTRY CmpAclSlotEntry[CMP_ACL_TABLE_SIZE];

/* New entries for the worker */
static SLIST_HEADER CmpAclQueue;
static KSPIN_LOCK CmpAclQueueLock;

/*
 * The HKU\<SID> descriptors last built, by the name of the hive key (the
 * same name always gives the same descriptor): parsing the SID and building
 * the descriptor on every HKCU open costs more than the access check.
 */
#define CMP_ACL_USER_CACHE          8
#define CMP_ACL_USER_NAME_CHARS     200
typedef struct _CMP_ACL_USER_SD
{
    ULONG ConvKey;
    USHORT NameChars;
    WCHAR Name[CMP_ACL_USER_NAME_CHARS];
    ULONG SdLength;
    ULONG Sd[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
} CMP_ACL_USER_SD;
static CMP_ACL_USER_SD CmpAclUserCache[CMP_ACL_USER_CACHE];
static EX_PUSH_LOCK CmpAclUserCacheLock;
static ULONG CmpAclUserCacheNext;

/* Worker */
static KTIMER CmpAclTimer;
static KDPC CmpAclDpc;
static WORK_QUEUE_ITEM CmpAclWorkItem;
static LONG CmpAclTimerArmed;

/*
 * Shutdown: the worker writes a file, and the file systems are flushed and shut down after
 * the configuration manager. CmpAclShutdownSystem stops the timer, waits for the work item
 * (queued or running) to end, and writes what is pending itself, while the file systems
 * still run. After it nothing arms the timer, queues the work item or touches a file.
 */
static volatile LONG CmpAclShutdown;
static volatile LONG CmpAclWorkItems;       /* queued or running work items */
static KEVENT CmpAclWorkIdle;

/* Worker-only state (one worker instance runs at a time) */
static SLIST_ENTRY CmpAclPending;           /* written in order, oldest first */
static PSLIST_ENTRY CmpAclPendingTail;
static ULONG CmpAclFileTries;
static BOOLEAN CmpAclFileGivenUp;
static BOOLEAN CmpAclBootHeaderWritten;
static BOOLEAN CmpAclSaturationLogged;
static BOOLEAN CmpAclCapLogged;
static ULONG CmpAclBootBytes;
static LONG CmpAclLastDenials;
static LARGE_INTEGER CmpAclLastCountPass;
static LARGE_INTEGER CmpAclLastPublish;

/* PRIVATE FUNCTIONS *********************************************************/

static
PSID
CmpAclAllocateSid(
    _In_ UCHAR Authority,
    _In_ UCHAR Count,
    _In_reads_(Count) const ULONG *SubAuthority)
{
    SID_IDENTIFIER_AUTHORITY Auth = {{0, 0, 0, 0, 0, Authority}};
    PSID Sid;
    ULONG i;

    Sid = ExAllocatePoolWithTag(PagedPool, RtlLengthRequiredSid(Count), TAG_CM_ACL);
    if (!Sid)
        return NULL;
    RtlInitializeSid(Sid, &Auth, Count);
    for (i = 0; i < Count; i++)
        *RtlSubAuthoritySid(Sid, i) = SubAuthority[i];
    return Sid;
}

/*
 * Build a self-relative descriptor from a spec into Buffer. UserSid stands in
 * for CmpAclSidUser. Fails (returns FALSE) if the buffer is too small.
 */
static
BOOLEAN
CmpAclBuildSd(
    _In_ const CMP_ACL_SD_SPEC *Spec,
    _In_opt_ PSID UserSid,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize)
{
    PISECURITY_DESCRIPTOR_RELATIVE Sd = Buffer;
    PSID Owner, Group, AceSid;
    ULONG Offset, OwnerLength, GroupLength, AclLength, i;
    PACL Acl;

    Owner = CmpAclSids[Spec->Owner];
    Group = CmpAclSids[Spec->Group];
    OwnerLength = RtlLengthSid(Owner);
    GroupLength = RtlLengthSid(Group);

    AclLength = sizeof(ACL);
    for (i = 0; i < Spec->AceCount; i++)
    {
        AceSid = (Spec->Aces[i].Sid == CmpAclSidUser) ? UserSid : CmpAclSids[Spec->Aces[i].Sid];
        if (!AceSid)
            return FALSE;
        AclLength += FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(AceSid);
    }

    if (sizeof(*Sd) + OwnerLength + GroupLength + AclLength > BufferSize)
        return FALSE;

    RtlZeroMemory(Sd, sizeof(*Sd));
    Sd->Revision = SECURITY_DESCRIPTOR_REVISION;
    Sd->Control = SE_SELF_RELATIVE | SE_DACL_PRESENT | Spec->Control;

    Offset = sizeof(*Sd);
    Sd->Owner = Offset;
    RtlCopyMemory((PUCHAR)Sd + Offset, Owner, OwnerLength);
    Offset += OwnerLength;
    Sd->Group = Offset;
    RtlCopyMemory((PUCHAR)Sd + Offset, Group, GroupLength);
    Offset += GroupLength;
    Sd->Dacl = Offset;

    Acl = (PACL)((PUCHAR)Sd + Offset);
    if (!NT_SUCCESS(RtlCreateAcl(Acl, AclLength, ACL_REVISION)))
        return FALSE;
    for (i = 0; i < Spec->AceCount; i++)
    {
        AceSid = (Spec->Aces[i].Sid == CmpAclSidUser) ? UserSid : CmpAclSids[Spec->Aces[i].Sid];
        if (!NT_SUCCESS(RtlAddAccessAllowedAceEx(Acl,
                                                 ACL_REVISION,
                                                 Spec->Aces[i].Flags,
                                                 Spec->Aces[i].Mask,
                                                 AceSid)))
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* Number of characters of a KCB's own name */
static
ULONG
CmpAclNameChars(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb)
{
    PCM_NAME_CONTROL_BLOCK Ncb = Kcb->NameBlock;

    if (!Ncb)
        return 0;
    return Ncb->Compressed ? Ncb->NameLength : Ncb->NameLength / sizeof(WCHAR);
}

static
WCHAR
CmpAclNameChar(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_ ULONG Index)
{
    PCM_NAME_CONTROL_BLOCK Ncb = Kcb->NameBlock;

    if (Ncb->Compressed)
        return (WCHAR)((PUCHAR)Ncb->Name)[Index];
    return Ncb->Name[Index];
}

/* Is the KCB's name Upper (case-insensitive; Upper is upper-case ASCII)? With
   Prefix, a name that starts with Upper also matches. */
static
BOOLEAN
CmpAclNameMatches(
    _In_opt_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_ PCSTR Upper,
    _In_ BOOLEAN Prefix)
{
    ULONG Chars, Length, i;

    if (!Kcb || !Kcb->NameBlock)
        return FALSE;
    Chars = CmpAclNameChars(Kcb);
    Length = (ULONG)strlen(Upper);
    if (Prefix ? (Chars < Length) : (Chars != Length))
        return FALSE;
    for (i = 0; i < Length; i++)
    {
        if (RtlUpcaseUnicodeChar(CmpAclNameChar(Kcb, i)) != (WCHAR)Upper[i])
            return FALSE;
    }
    return TRUE;
}

/*
 * Parse "S-1-<authority>-<sub>..." (optionally followed by "_Classes") from a
 * key name into Sid (room for SID_MAX_SUB_AUTHORITIES). The name comes from
 * the hive, not from the caller, but is still checked character by character.
 */
static
BOOLEAN
CmpAclParseUserSid(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _Out_writes_bytes_(SECURITY_MAX_SID_SIZE) PSID Sid)
{
    ULONG Chars, i, Count = 0;
    ULONGLONG Value;
    ULONG Values[2 + SID_MAX_SUB_AUTHORITIES];
    ULONG ValueCount = 0;
    WCHAR c;
    BOOLEAN Digit;
    SID_IDENTIFIER_AUTHORITY Auth;
    static const CHAR Classes[] = "_CLASSES";

    Chars = CmpAclNameChars(Kcb);
    if (Chars > sizeof(Classes) - 1 && Chars > 2)
    {
        /* Drop a _Classes suffix */
        BOOLEAN Suffix = TRUE;
        for (i = 0; i < sizeof(Classes) - 1; i++)
        {
            if (RtlUpcaseUnicodeChar(CmpAclNameChar(Kcb, Chars - (sizeof(Classes) - 1) + i)) != (WCHAR)Classes[i])
            {
                Suffix = FALSE;
                break;
            }
        }
        if (Suffix)
            Chars -= sizeof(Classes) - 1;
    }

    if (Chars < 5 || Chars > 200)
        return FALSE;
    if (RtlUpcaseUnicodeChar(CmpAclNameChar(Kcb, 0)) != L'S' || CmpAclNameChar(Kcb, 1) != L'-')
        return FALSE;

    /* Numbers separated by '-' */
    i = 2;
    while (i <= Chars)
    {
        Value = 0;
        Digit = FALSE;
        while (i < Chars)
        {
            c = CmpAclNameChar(Kcb, i);
            if (c < L'0' || c > L'9')
                break;
            Value = Value * 10 + (c - L'0');
            if (Value > MAXULONG)
                return FALSE;
            Digit = TRUE;
            i++;
        }
        if (!Digit || ValueCount >= RTL_NUMBER_OF(Values))
            return FALSE;
        Values[ValueCount++] = (ULONG)Value;
        if (i == Chars)
            break;
        if (CmpAclNameChar(Kcb, i) != L'-')
            return FALSE;
        i++;
        if (i == Chars)
            return FALSE;
    }

    /* Revision, authority, then 1..15 subauthorities */
    if (ValueCount < 3 || Values[0] != SID_REVISION)
        return FALSE;
    Count = ValueCount - 2;
    if (Count > SID_MAX_SUB_AUTHORITIES)
        return FALSE;

    Auth.Value[0] = 0;
    Auth.Value[1] = 0;
    Auth.Value[2] = (UCHAR)(Values[1] >> 24);
    Auth.Value[3] = (UCHAR)(Values[1] >> 16);
    Auth.Value[4] = (UCHAR)(Values[1] >> 8);
    Auth.Value[5] = (UCHAR)Values[1];
    RtlInitializeSid(Sid, &Auth, (UCHAR)Count);
    for (i = 0; i < Count; i++)
        *RtlSubAuthoritySid(Sid, i) = Values[2 + i];
    return TRUE;
}

/* Is Entry the cached descriptor of the hive key Kcb (same hash, same name)? */
static
BOOLEAN
CmpAclUserCacheMatch(
    _In_ const CMP_ACL_USER_SD *Entry,
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_ ULONG Chars)
{
    ULONG i;

    if (Entry->SdLength == 0 || Entry->ConvKey != Kcb->ConvKey || Entry->NameChars != Chars)
        return FALSE;
    for (i = 0; i < Chars; i++)
    {
        if (Entry->Name[i] != RtlUpcaseUnicodeChar(CmpAclNameChar(Kcb, i)))
            return FALSE;
    }
    return TRUE;
}

static
BOOLEAN
CmpAclCachedUserSd(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize)
{
    ULONG Chars = CmpAclNameChars(Kcb), i;
    BOOLEAN Found = FALSE;

    if (Chars == 0 || Chars > CMP_ACL_USER_NAME_CHARS)
        return FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&CmpAclUserCacheLock);
    for (i = 0; i < CMP_ACL_USER_CACHE; i++)
    {
        if (CmpAclUserCacheMatch(&CmpAclUserCache[i], Kcb, Chars) &&
            CmpAclUserCache[i].SdLength <= BufferSize)
        {
            RtlCopyMemory(Buffer, CmpAclUserCache[i].Sd, CmpAclUserCache[i].SdLength);
            Found = TRUE;
            break;
        }
    }
    ExReleasePushLockShared(&CmpAclUserCacheLock);
    KeLeaveCriticalRegion();
    return Found;
}

static
VOID
CmpAclCacheUserSd(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_ PSECURITY_DESCRIPTOR Sd)
{
    ULONG Chars = CmpAclNameChars(Kcb), Length = RtlLengthSecurityDescriptor(Sd), i;
    CMP_ACL_USER_SD *Entry;

    if (Chars == 0 || Chars > CMP_ACL_USER_NAME_CHARS || Length > sizeof(Entry->Sd))
        return;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&CmpAclUserCacheLock);
    Entry = &CmpAclUserCache[CmpAclUserCacheNext++ % CMP_ACL_USER_CACHE];
    Entry->ConvKey = Kcb->ConvKey;
    Entry->NameChars = (USHORT)Chars;
    for (i = 0; i < Chars; i++)
        Entry->Name[i] = RtlUpcaseUnicodeChar(CmpAclNameChar(Kcb, i));
    RtlCopyMemory(Entry->Sd, Sd, Length);
    Entry->SdLength = Length;
    ExReleasePushLockExclusive(&CmpAclUserCacheLock);
    KeLeaveCriticalRegion();
}

/*
 * Pick the synthesised descriptor for a key from its place in the namespace.
 * UserBuffer receives the descriptor when it depends on the key (HKU\<SID>).
 */
static
PSECURITY_DESCRIPTOR
CmpAclSynthesizeSd(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _Out_writes_bytes_(UserBufferSize) PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _Out_ PULONG Rule)
{
    PCM_KEY_CONTROL_BLOCK Path[CMP_ACL_LEVELS] = {0};
    PCM_KEY_CONTROL_BLOCK Walk;
    ULONG Depth = 0, Level;
    ULONG SidBuffer[SECURITY_MAX_SID_SIZE / sizeof(ULONG)];

    for (Walk = Kcb; Walk; Walk = Walk->ParentKcb)
        Depth++;
    Level = Depth;
    for (Walk = Kcb; Walk; Walk = Walk->ParentKcb)
    {
        Level--;
        if (Level < CMP_ACL_LEVELS)
            Path[Level] = Walk;
    }

    /* \REGISTRY and its first level */
    if (Depth <= 2)
    {
        *Rule = CmpAclRuleMaster;
        goto Done;
    }

    if (CmpAclNameMatches(Path[1], "MACHINE", FALSE))
    {
        if (CmpAclNameMatches(Path[2], "HARDWARE", FALSE))
        {
            *Rule = CmpAclRuleHardware;
        }
        else if (CmpAclNameMatches(Path[2], "SECURITY", FALSE) ||
                 (CmpAclNameMatches(Path[2], "SAM", FALSE) &&
                  Depth >= 4 && CmpAclNameMatches(Path[3], "SAM", FALSE)))
        {
            *Rule = CmpAclRuleSamSecurity;
        }
        else if (CmpAclNameMatches(Path[2], "SOFTWARE", FALSE) && Depth >= 8 &&
                 CmpAclNameMatches(Path[3], "MICROSOFT", FALSE) &&
                 CmpAclNameMatches(Path[4], "WINDOWS NT", FALSE) &&
                 CmpAclNameMatches(Path[5], "CURRENTVERSION", FALSE) &&
                 CmpAclNameMatches(Path[6], "SCHEDULE", FALSE) &&
                 CmpAclNameMatches(Path[7], "TASKCACHE", FALSE))
        {
            *Rule = CmpAclRuleTaskCache;
        }
        else if (CmpAclNameMatches(Path[2], "SYSTEM", FALSE) && Depth >= 6 &&
                 CmpAclNameMatches(Path[3], "CONTROLSET", TRUE) &&
                 CmpAclNameMatches(Path[4], "SERVICES", FALSE) &&
                 CmpAclNameMatches(Path[5], "EVENTLOG", FALSE))
        {
            *Rule = CmpAclRuleEventLog;
        }
        else
        {
            /* SYSTEM, SOFTWARE, the SAM hive root, and hives loaded by others */
            *Rule = CmpAclRuleHiveRoot;
        }
    }
    else if (CmpAclNameMatches(Path[1], "USER", FALSE))
    {
        if (CmpAclNameMatches(Path[2], ".DEFAULT", FALSE) ||
            CmpAclNameMatches(Path[2], "S-1-5-18", FALSE))
        {
            *Rule = CmpAclRuleDefault;
        }
        else if (CmpAclCachedUserSd(Path[2], UserBuffer, UserBufferSize))
        {
            *Rule = CmpAclRuleUser;
            return UserBuffer;
        }
        else if (CmpAclParseUserSid(Path[2], (PSID)SidBuffer) &&
                 CmpAclBuildSd(&CmpAclSdUser, (PSID)SidBuffer, UserBuffer, UserBufferSize))
        {
            CmpAclCacheUserSd(Path[2], UserBuffer);
            *Rule = CmpAclRuleUser;
            return UserBuffer;
        }
        else
        {
            /* Not a SID: as inherited from \REGISTRY\USER */
            *Rule = CmpAclRuleUserUnknown;
        }
    }
    else
    {
        *Rule = CmpAclRuleOther;
    }

Done:
    return CmpAclSdTable[*Rule];
}

/* The key's stored descriptor, if it has a sane one */
static
PSECURITY_DESCRIPTOR
CmpAclStoredSd(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb)
{
    PCM_KEY_NODE Node;
    HCELL_INDEX SecurityCell;
    PCM_KEY_SECURITY Security;

    if (!Kcb->KeyHive || Kcb->KeyCell == HCELL_NIL ||
        (Kcb->ExtFlags & CM_KCB_KEY_NON_EXIST) || Kcb->Delete)
    {
        return NULL;
    }

    /*
     * A hive whose root names no usable 'sk' cell has an empty security cache
     * (CmpBuildSecurityCache at load): every installed hive today. Nothing to
     * read there, and this skips a cell lookup per ancestor on every open.
     */
    if (((PCMHIVE)Kcb->KeyHive)->SecurityCount == 0)
        return NULL;

    Node = (PCM_KEY_NODE)HvGetCell(Kcb->KeyHive, Kcb->KeyCell);
    if (!Node)
        return NULL;
    SecurityCell = (Node->Signature == CM_KEY_NODE_SIGNATURE) ? Node->Security : HCELL_NIL;
    HvReleaseCell(Kcb->KeyHive, Kcb->KeyCell);
    if (SecurityCell == HCELL_NIL)
        return NULL;

    /* The hive is untrusted: the cell and the descriptor are both checked */
    Security = CmpGetCheckedSecurityCell(Kcb->KeyHive, SecurityCell, NULL);
    if (!Security || Security->DescriptorLength < sizeof(SECURITY_DESCRIPTOR_RELATIVE))
        return NULL;
    if (!RtlValidRelativeSecurityDescriptor(&Security->Descriptor,
                                            Security->DescriptorLength,
                                            0))
    {
        return NULL;
    }
    return &Security->Descriptor;
}

/*
 * The descriptor a key would be checked against on Windows (see the top of
 * the file). *ToFree receives a descriptor the caller frees with
 * SeDeassignSecurity. Returns NULL if none could be built.
 */
static
PSECURITY_DESCRIPTOR
CmpGetEffectiveKeySd(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _Out_writes_bytes_(UserBufferSize) PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _Out_ PULONG Rule,
    _Out_ PSECURITY_DESCRIPTOR *ToFree)
{
    PSECURITY_DESCRIPTOR Sd, NewSd = NULL;
    PCM_KEY_CONTROL_BLOCK Parent;

    *ToFree = NULL;

    /* 1. Stored */
    Sd = CmpAclStoredSd(Kcb);
    if (Sd)
    {
        *Rule = CmpAclRuleCell;
        return Sd;
    }

    /* 2. The nearest ancestor that has one, inherited as SYSTEM would get it */
    for (Parent = Kcb->ParentKcb; Parent; Parent = Parent->ParentKcb)
    {
        Sd = CmpAclStoredSd(Parent);
        if (!Sd)
            continue;
        if (!NT_SUCCESS(SeAssignSecurity(Sd,
                                         NULL,
                                         &NewSd,
                                         TRUE,
                                         &CmpAclSystemSubject,
                                         &CmpKeyObjectType->TypeInfo.GenericMapping,
                                         PagedPool)))
        {
            break;
        }
        *Rule = CmpAclRuleInherited;
        *ToFree = NewSd;
        return NewSd;
    }

    /* 3. Synthesised */
    return CmpAclSynthesizeSd(Kcb, UserBuffer, UserBufferSize, Rule);
}

static
ULONG64
CmpAclMix(
    _In_ ULONG64 Hash,
    _In_ ULONG Value)
{
    /* FNV-1a over the four bytes */
    ULONG i;

    for (i = 0; i < 4; i++)
    {
        Hash ^= (UCHAR)(Value >> (i * 8));
        Hash *= 0x100000001B3ULL;
    }
    return Hash;
}

static
VOID
CmpAclArmTimer(VOID)
{
    LARGE_INTEGER Due;

    /* Nothing is written once the system shuts down */
    if (CmpAclShutdown)
        return;
    if (InterlockedCompareExchange(&CmpAclTimerArmed, 1, 0) != 0)
        return;
    Due.QuadPart = -(LONGLONG)CMP_ACL_FLUSH_DELAY * 10 * 1000 * 1000;
    KeSetTimer(&CmpAclTimer, Due, &CmpAclDpc);
}

/*
 * Give back a claimed slot whose entry could not be made, so the next identical
 * denial claims it again (and counts as an entry, or as dropped, then). The
 * denials that matched the claimed key meanwhile found no entry to count on:
 * they are dropped too.
 */
static
VOID
CmpAclReleaseSlot(
    _In_ ULONG Slot)
{
    LONG Lost;

    Lost = InterlockedExchange(&CmpAclSlotCount[Slot], 0);
    InterlockedExchange64(&CmpAclSlotKey[Slot], 0);
    if (Lost > 0)
        InterlockedExchangeAdd(&CmpAclDropped, Lost);
    else
        InterlockedIncrement(&CmpAclDropped);
}

/* Copy a counted string into the entry's string area */
static
PWCHAR
CmpAclPutString(
    _Inout_ PWCHAR Target,
    _In_reads_(Chars) PCWCH Source,
    _In_ USHORT Chars)
{
    if (Chars)
        RtlCopyMemory(Target, Source, Chars * sizeof(WCHAR));
    return Target + Chars;
}

/*
 * Record a denial: count it, and on its first occurrence build the entry the
 * worker writes. Runs in the open/create path with the KCB lock held, so it
 * does no I/O and takes no Cm lock; it allocates and reads the token.
 */
static
VOID
CmpAclRecordDenial(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_opt_ PCUNICODE_STRING ChildName,
    _In_ ULONG Operation,
    _In_ PSECURITY_SUBJECT_CONTEXT Subject,
    _In_ ACCESS_MASK Desired,
    _In_ ACCESS_MASK Granted,
    _In_ NTSTATUS ShadowStatus,
    _In_ ULONG Rule)
{
    PEPROCESS Process = PsGetCurrentProcess();
    PCSTR ShortImage = (PCSTR)Process->ImageFileName;
    PTOKEN Token;
    ULONG64 Fingerprint = 0xCBF29CE484222325ULL;
    ULONG Slot, Probe, i, Chars;
    PCMP_ACL_ENTRY Entry;
    PUNICODE_STRING KeyName = NULL;
    UNICODE_STRING UserString = {0};
    WCHAR UserBuffer[192];
    PUNICODE_STRING ImageName = NULL;
    USHORT KeyChars, ChildChars, ImageChars;
    ULONG Size;
    PWCHAR p;
    LONG64 Previous;

    InterlockedIncrement(&CmpAclDenials);

    /* Fingerprint: key path hash, depth and last component, operation, access, image, user */
    Fingerprint = CmpAclMix(Fingerprint, Kcb->ConvKey);
    Fingerprint = CmpAclMix(Fingerprint, Kcb->TotalLevels);
    /*
     * A bounded prefix and the length of each name: a caller can make a child name 32K
     * characters long, and the entry keeps no more than CMP_ACL_MAX_NAME_CHARS of it anyway
     */
    Chars = CmpAclNameChars(Kcb);
    Fingerprint = CmpAclMix(Fingerprint, Chars);
    for (i = 0; i < min(Chars, CMP_ACL_MAX_NAME_CHARS); i++)
        Fingerprint = CmpAclMix(Fingerprint, RtlUpcaseUnicodeChar(CmpAclNameChar(Kcb, i)));
    if (ChildName)
    {
        Chars = ChildName->Length / sizeof(WCHAR);
        Fingerprint = CmpAclMix(Fingerprint, Chars);
        for (i = 0; i < min(Chars, CMP_ACL_MAX_NAME_CHARS); i++)
            Fingerprint = CmpAclMix(Fingerprint, RtlUpcaseUnicodeChar(ChildName->Buffer[i]));
    }
    Fingerprint = CmpAclMix(Fingerprint, Operation);
    Fingerprint = CmpAclMix(Fingerprint, Desired);
    for (i = 0; ShortImage && i < 16 && ShortImage[i]; i++)
        Fingerprint = CmpAclMix(Fingerprint, (UCHAR)ShortImage[i]);

    SeLockSubjectContext(Subject);
    Token = (PTOKEN)SeQuerySubjectContextToken(Subject);
    if (Token && Token->UserAndGroups && Token->UserAndGroupCount)
    {
        PSID UserSid = Token->UserAndGroups[0].Sid;
        PUCHAR Bytes = UserSid;
        ULONG Length = RtlLengthSid(UserSid);
        for (i = 0; i < Length; i++)
            Fingerprint = CmpAclMix(Fingerprint, Bytes[i]);
    }
    SeUnlockSubjectContext(Subject);
    if (Fingerprint == 0)
        Fingerprint = 1;

    /* Find or claim the slot */
    Slot = (ULONG)(Fingerprint ^ (Fingerprint >> 32)) & (CMP_ACL_TABLE_SIZE - 1);
    for (Probe = 0; Probe < CMP_ACL_TABLE_PROBE; Probe++)
    {
        i = (Slot + Probe) & (CMP_ACL_TABLE_SIZE - 1);
        Previous = InterlockedCompareExchange64(&CmpAclSlotKey[i], (LONG64)Fingerprint, 0);
        if (Previous == (LONG64)Fingerprint)
        {
            /* Seen before: count it, the worker writes the count later */
            InterlockedIncrement(&CmpAclSlotCount[i]);
            CmpAclArmTimer();
            return;
        }
        if (Previous == 0)
            break;
    }
    if (Probe == CMP_ACL_TABLE_PROBE)
    {
        InterlockedIncrement(&CmpAclDropped);
        return;
    }
    Slot = i;
    InterlockedIncrement(&CmpAclSlotCount[Slot]);

    /* A new distinct denial */
    if (InterlockedIncrement(&CmpAclEntryCount) > CMP_ACL_MAX_ENTRIES)
    {
        InterlockedDecrement(&CmpAclEntryCount);
        CmpAclReleaseSlot(Slot);
        InterlockedExchange(&CmpAclSaturated, 1);
        CmpAclArmTimer();
        return;
    }

    /* Long names are cut: a caller can make paths up to 32K characters */
    KeyName = CmpConstructName(Kcb);
    KeyChars = KeyName ? (USHORT)min(KeyName->Length / sizeof(WCHAR), CMP_ACL_MAX_KEY_CHARS) : 0;
    ChildChars = ChildName ? (USHORT)min(ChildName->Length / sizeof(WCHAR), CMP_ACL_MAX_NAME_CHARS) : 0;

    /* The image path captured at process creation (an NT path), or the short name */
    if (Process->SeAuditProcessCreationInfo.ImageFileName)
        ImageName = &Process->SeAuditProcessCreationInfo.ImageFileName->Name;
    ImageChars = ImageName ? (USHORT)min(ImageName->Length / sizeof(WCHAR), CMP_ACL_MAX_NAME_CHARS) : 0;
    if (!ImageChars && ShortImage)
    {
        while (ImageChars < 15 && ShortImage[ImageChars])
            ImageChars++;
    }

    /* The token's user, integrity level and kind */
    RtlInitEmptyUnicodeString(&UserString, UserBuffer, sizeof(UserBuffer));
    SeLockSubjectContext(Subject);
    Token = (PTOKEN)SeQuerySubjectContextToken(Subject);

    Size = FIELD_OFFSET(CMP_ACL_ENTRY, Strings) +
           (KeyChars + ChildChars + ImageChars +
            RTL_NUMBER_OF(UserBuffer)) * sizeof(WCHAR);
    Entry = ExAllocatePoolWithTag(PagedPool, Size, TAG_CM_ACL);
    if (!Entry)
    {
        SeUnlockSubjectContext(Subject);
        if (KeyName)
            CmpFree(KeyName, 0);
        InterlockedDecrement(&CmpAclEntryCount);
        CmpAclReleaseSlot(Slot);
        CmpAclArmTimer();
        return;
    }
    RtlZeroMemory(Entry, FIELD_OFFSET(CMP_ACL_ENTRY, Strings));

    if (Token && Token->UserAndGroups && Token->UserAndGroupCount)
    {
        if (!NT_SUCCESS(RtlConvertSidToUnicodeString(&UserString, Token->UserAndGroups[0].Sid, FALSE)))
            UserString.Length = 0;
        Entry->IntegrityRid = Token->IntegrityLevel;
    }
    Entry->Impersonating = (Subject->ClientToken != NULL);
    SeUnlockSubjectContext(Subject);
    if (Token)
    {
        /* These lock the token themselves; it stays referenced by the subject context */
        Entry->Admin = SeTokenIsAdmin(Token);
        Entry->Restricted = SeTokenIsRestricted(Token);
    }

    Entry->Id = (ULONG)InterlockedIncrement(&CmpAclNextId);
    Entry->Slot = Slot;
    Entry->Operation = Operation;
    Entry->Rule = Rule;
    Entry->Desired = Desired;
    Entry->Granted = Granted;
    Entry->ShadowStatus = ShadowStatus;
    Entry->Pid = HandleToUlong(PsGetCurrentProcessId());
    KeQuerySystemTime(&Entry->Time);

    p = Entry->Strings;
    if (KeyName)
    {
        Entry->KeyChars = KeyChars;
        p = CmpAclPutString(p, KeyName->Buffer, Entry->KeyChars);
        CmpFree(KeyName, 0);
    }
    if (ChildChars)
    {
        Entry->ChildChars = ChildChars;
        p = CmpAclPutString(p, ChildName->Buffer, ChildChars);
    }
    if (ImageName && ImageName->Length)
    {
        Entry->ImageChars = ImageChars;
        p = CmpAclPutString(p, ImageName->Buffer, ImageChars);
    }
    else if (ImageChars)
    {
        Entry->ImageChars = ImageChars;
        for (i = 0; i < ImageChars; i++)
            *p++ = (WCHAR)(UCHAR)ShortImage[i];
    }
    Entry->UserChars = UserString.Length / sizeof(WCHAR);
    CmpAclPutString(p, UserString.Buffer, Entry->UserChars);

    InterlockedExchangePointer((PVOID*)&CmpAclSlotEntry[Slot], Entry);
    ExInterlockedPushEntrySList(&CmpAclQueue, &Entry->QueueEntry, &CmpAclQueueLock);
    CmpAclArmTimer();
}

/* Is a privilege enabled in the subject's effective token */
static
BOOLEAN
CmpAclPrivilegeEnabled(
    _In_ PSECURITY_SUBJECT_CONTEXT Subject,
    _In_ ULONG Privilege)
{
    PRIVILEGE_SET Set;
    BOOLEAN Result;

    Set.PrivilegeCount = 1;
    Set.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Set.Privilege[0].Luid = RtlConvertUlongToLuid(Privilege);
    Set.Privilege[0].Attributes = 0;

    SeLockSubjectContext(Subject);
    Result = SePrivilegeCheck(&Set, Subject, UserMode);
    SeUnlockSubjectContext(Subject);
    return Result;
}

/* JSON string output into a bounded line buffer (ASCII, \u escapes) */
typedef struct _CMP_ACL_LINE
{
    PCHAR Buffer;
    ULONG Size;
    ULONG Length;
    BOOLEAN Overflow;
    ULONG Lines;
} CMP_ACL_LINE, *PCMP_ACL_LINE;

static
VOID
CmpAclLineAppend(
    _Inout_ PCMP_ACL_LINE Line,
    _In_ PCSTR Text)
{
    while (*Text)
    {
        if (Line->Length + 1 >= Line->Size)
        {
            Line->Overflow = TRUE;
            return;
        }
        Line->Buffer[Line->Length++] = *Text++;
    }
    Line->Buffer[Line->Length] = ANSI_NULL;
}

static
VOID
CmpAclLineFormat(
    _Inout_ PCMP_ACL_LINE Line,
    _In_ PCSTR Format,
    ...)
{
    CHAR Text[256];
    va_list Args;

    va_start(Args, Format);
    _vsnprintf(Text, sizeof(Text) - 1, Format, Args);
    va_end(Args);
    Text[sizeof(Text) - 1] = ANSI_NULL;
    CmpAclLineAppend(Line, Text);
}

/*
 * A JSON string of at most MaxBytes encoded bytes (not counting the quotes). A character is
 * written whole or not at all: an escape is never cut, so the string is always closed.
 */
static
VOID
CmpAclLineString(
    _Inout_ PCMP_ACL_LINE Line,
    _In_reads_(Chars) PCWCH String,
    _In_ ULONG Chars,
    _In_ ULONG MaxBytes)
{
    ULONG i, Used = 0, Length;
    WCHAR c;
    CHAR Text[8];

    CmpAclLineAppend(Line, "\"");
    for (i = 0; i < Chars; i++)
    {
        c = String[i];
        if (c == L'"' || c == L'\\')
        {
            Text[0] = '\\';
            Text[1] = (CHAR)c;
            Text[2] = ANSI_NULL;
            Length = 2;
        }
        else if (c >= 0x20 && c < 0x7F)
        {
            Text[0] = (CHAR)c;
            Text[1] = ANSI_NULL;
            Length = 1;
        }
        else
        {
            _snprintf(Text, sizeof(Text), "\\u%04x", c);
            Text[sizeof(Text) - 1] = ANSI_NULL;
            Length = 6;
        }
        if (Used + Length > MaxBytes)
            break;
        Used += Length;
        CmpAclLineAppend(Line, Text);
    }
    CmpAclLineAppend(Line, "\"");
}

static
VOID
CmpAclLineTime(
    _Inout_ PCMP_ACL_LINE Line,
    _In_ PCSTR Name,
    _In_ PLARGE_INTEGER Time)
{
    TIME_FIELDS Fields;

    RtlTimeToTimeFields(Time, &Fields);
    CmpAclLineFormat(Line, "\"%s\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\"",
                     Name, Fields.Year, Fields.Month, Fields.Day,
                     Fields.Hour, Fields.Minute, Fields.Second, Fields.Milliseconds);
}

static
VOID
CmpAclLineStart(
    _Inout_ PCMP_ACL_LINE Line,
    _In_ PLARGE_INTEGER Now)
{
    LARGE_INTEGER Boot = KeBootTime;

    Line->Length = 0;
    Line->Overflow = FALSE;
    Line->Buffer[0] = ANSI_NULL;
    CmpAclLineAppend(Line, "{");
    CmpAclLineTime(Line, "boot", &Boot);
    CmpAclLineAppend(Line, ",");
    CmpAclLineTime(Line, "t", Now);
}

/* Open (and on the first write of a boot, rotate) the log file */
static
NTSTATUS
CmpAclOpenLog(
    _Out_ PHANDLE Handle)
{
    static UNICODE_STRING LogFiles = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\LogFiles");
    static UNICODE_STRING Directory = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\LogFiles\\RegAcl");
    static UNICODE_STRING FileName = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\LogFiles\\RegAcl\\audit.log");
    static const WCHAR OldName[] = L"\\SystemRoot\\System32\\LogFiles\\RegAcl\\audit.log.1";
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Dir;
    NTSTATUS Status;
    FILE_STANDARD_INFORMATION Standard;
    UCHAR SdBuffer[CMP_ACL_SD_BUFFER];
    CMP_ACL_SD_SPEC DirSpec =
    {
        /* Only SYSTEM and administrators read the log: it names other users' keys and processes */
        CmpAclSidAdmins, CmpAclSidSystem, SE_DACL_PROTECTED, 2,
        {
            { OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, CmpAclSidSystem, FILE_ALL_ACCESS },
            { OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, CmpAclSidAdmins, FILE_ALL_ACCESS },
        }
    };
    PSECURITY_DESCRIPTOR DirSd = NULL;

    if (CmpAclBuildSd(&DirSpec, NULL, SdBuffer, sizeof(SdBuffer)))
        DirSd = SdBuffer;

    InitializeObjectAttributes(&Attributes, &LogFiles, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateFile(&Dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &Attributes, &Iosb, NULL,
                          FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;
    ZwClose(Dir);

    InitializeObjectAttributes(&Attributes, &Directory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, DirSd);
    Status = ZwCreateFile(&Dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &Attributes, &Iosb, NULL,
                          FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;
    ZwClose(Dir);

    InitializeObjectAttributes(&Attributes, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateFile(Handle, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE, &Attributes,
                          &Iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;

    /* Keep the file bounded across boots: at this boot's first write move a full one aside */
    if (!CmpAclBootHeaderWritten &&
        NT_SUCCESS(ZwQueryInformationFile(*Handle, &Iosb, &Standard, sizeof(Standard), FileStandardInformation)) &&
        Standard.EndOfFile.QuadPart >= CMP_ACL_FILE_ROTATE_SIZE)
    {
        UCHAR RenameBuffer[sizeof(FILE_RENAME_INFORMATION) + sizeof(OldName)];
        PFILE_RENAME_INFORMATION Rename = (PFILE_RENAME_INFORMATION)RenameBuffer;

        RtlZeroMemory(RenameBuffer, sizeof(RenameBuffer));
        Rename->ReplaceIfExists = TRUE;
        Rename->RootDirectory = NULL;
        Rename->FileNameLength = sizeof(OldName) - sizeof(WCHAR);
        RtlCopyMemory(Rename->FileName, OldName, Rename->FileNameLength);
        Status = ZwSetInformationFile(*Handle, &Iosb, Rename, sizeof(RenameBuffer), FileRenameInformation);
        ZwClose(*Handle);
        if (!NT_SUCCESS(Status))
        {
            /* Could not move it: start over in place */
            Status = ZwCreateFile(Handle, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &Attributes, &Iosb, NULL,
                                  FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SUPERSEDE,
                                  FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        }
        else
        {
            Status = ZwCreateFile(Handle, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &Attributes, &Iosb, NULL,
                                  FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                                  FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        }
    }
    return Status;
}

static
VOID
CmpAclSetDword(
    _In_ HANDLE Key,
    _In_ PCWSTR Name,
    _In_ ULONG Value)
{
    UNICODE_STRING ValueName;

    RtlInitUnicodeString(&ValueName, Name);
    ZwSetValueKey(Key, &ValueName, 0, REG_DWORD, &Value, sizeof(Value));
}

/* Write the mode and the counters to Control\RegAcl\AuditStats (volatile) */
static
VOID
CmpAclPublish(VOID)
{
    static UNICODE_STRING RegAcl =
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\RegAcl");
    static UNICODE_STRING Stats = RTL_CONSTANT_STRING(L"AuditStats");
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Parent, Key;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, &RegAcl, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateKey(&Parent, KEY_CREATE_SUB_KEY, &Attributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
    if (!NT_SUCCESS(Status))
        return;
    InitializeObjectAttributes(&Attributes, &Stats, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, Parent, NULL);
    Status = ZwCreateKey(&Key, KEY_SET_VALUE, &Attributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
    ZwClose(Parent);
    if (!NT_SUCCESS(Status))
        return;

    CmpAclSetDword(Key, L"Mode", CmpRegistryAclEffectiveMode);
    CmpAclSetDword(Key, L"ConfiguredMode", CmpRegistryAclMode);
    CmpAclSetDword(Key, L"ModeSource", CmpRegistryAclModeSource);
    CmpAclSetDword(Key, L"Checks", (ULONG)CmpAclChecks);
    CmpAclSetDword(Key, L"Denials", (ULONG)CmpAclDenials);
    CmpAclSetDword(Key, L"Entries", (ULONG)CmpAclEntryCount);
    CmpAclSetDword(Key, L"Dropped", (ULONG)CmpAclDropped);
    CmpAclSetDword(Key, L"Errors", (ULONG)CmpAclErrors);
    CmpAclSetDword(Key, L"MaxAllowedReduced", (ULONG)CmpAclMaxAllowedReduced);
    CmpAclSetDword(Key, L"LinesWritten", (ULONG)CmpAclLinesWritten);
    CmpAclSetDword(Key, L"FileErrors", (ULONG)CmpAclFileErrors);
    ZwClose(Key);
}

/* Format one entry: Line gets the JSON line, Serial the debug print */
static
VOID
CmpAclFormatEntry(
    _In_ PCMP_ACL_ENTRY Entry,
    _Inout_ PCMP_ACL_LINE Line)
{
    PWCHAR p = Entry->Strings;

    CmpAclLineStart(Line, &Entry->Time);
    CmpAclLineFormat(Line, ",\"id\":%lu,\"op\":\"%s\",\"key\":", Entry->Id, CmpAclOpNames[Entry->Operation]);
    CmpAclLineString(Line, p, Entry->KeyChars, CMP_ACL_LINE_KEY_BYTES);
    p += Entry->KeyChars;
    if (Entry->Operation != CM_REGACL_OP_OPEN)
    {
        CmpAclLineAppend(Line, ",\"child\":");
        CmpAclLineString(Line, p, Entry->ChildChars, CMP_ACL_LINE_NAME_BYTES);
    }
    p += Entry->ChildChars;
    CmpAclLineFormat(Line, ",\"desired\":\"0x%08lx\",\"granted\":\"0x%08lx\",\"status\":\"0x%08lx\",\"rule\":\"%s\",\"image\":",
                     Entry->Desired, Entry->Granted, (ULONG)Entry->ShadowStatus, CmpAclRuleNames[Entry->Rule]);
    CmpAclLineString(Line, p, Entry->ImageChars, CMP_ACL_LINE_NAME_BYTES);
    p += Entry->ImageChars;
    CmpAclLineFormat(Line, ",\"pid\":%lu,\"user\":", Entry->Pid);
    CmpAclLineString(Line, p, Entry->UserChars, CMP_ACL_LINE_USER_BYTES);
    CmpAclLineFormat(Line, ",\"il\":\"0x%04lx\",\"admin\":%u,\"restricted\":%u,\"imp\":%u,\"mode\":\"%s\"}\n",
                     Entry->IntegrityRid, Entry->Admin, Entry->Restricted, Entry->Impersonating,
                     CmpAclModeNames[CmpRegistryAclMode]);
}

/* Append a line to the output buffer; FALSE when the buffer is full */
static
BOOLEAN
CmpAclOut(
    _Inout_ PCMP_ACL_LINE Out,
    _In_ PCMP_ACL_LINE Line)
{
    if (Line->Overflow)
    {
        /* The string budgets keep this from happening; a line that was cut is not written, it would not be JSON */
        InterlockedIncrement(&CmpAclFileErrors);
        return TRUE;
    }
    if (Out->Length + Line->Length >= Out->Size)
        return FALSE;
    RtlCopyMemory(Out->Buffer + Out->Length, Line->Buffer, Line->Length);
    Out->Length += Line->Length;
    Out->Lines++;
    return TRUE;
}

/* One pass of the worker; TRUE when it wants to run again soon. Final: the shutdown pass. */
static
BOOLEAN
CmpAclRun(
    _In_ BOOLEAN Final)
{
    PSLIST_ENTRY List, Next, Reversed = NULL;
    PCMP_ACL_ENTRY Entry;
    CHAR LineBuffer[CMP_ACL_LINE_SIZE];
    CMP_ACL_LINE Line = { LineBuffer, sizeof(LineBuffer), 0, FALSE, 0 };
    CMP_ACL_LINE Out = { NULL, 64 * 1024, 0, FALSE, 0 };
    LARGE_INTEGER Now;
    HANDLE File;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    ULONG i;
    LONG Count;
    BOOLEAN CountPass, Again = FALSE;

    KeQuerySystemTime(&Now);

    /* Move new entries to the pending list, oldest first */
    List = ExInterlockedFlushSList(&CmpAclQueue);
    while (List)
    {
        Next = List->Next;
        List->Next = Reversed;
        Reversed = List;
        List = Next;
    }
    if (Reversed)
    {
        if (CmpAclPendingTail)
            CmpAclPendingTail->Next = Reversed;
        else
            CmpAclPending.Next = Reversed;
        for (CmpAclPendingTail = Reversed; CmpAclPendingTail->Next; CmpAclPendingTail = CmpAclPendingTail->Next)
            ;
    }

    /* The debug channel: one line per distinct denial, printed once */
    for (Next = Reversed; Next; Next = Next->Next)
    {
        Entry = CONTAINING_RECORD(Next, CMP_ACL_ENTRY, QueueEntry);
        CmpAclFormatEntry(Entry, &Line);
        DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL, "CM-ACL-AUDIT: %s", Line.Buffer);
    }
    if (CmpAclSaturated && !CmpAclSaturationLogged)
    {
        DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL,
                   "CM-ACL-AUDIT: saturated, %u distinct denials recorded, later ones only counted\n",
                   CMP_ACL_MAX_ENTRIES);
    }

    /* The last pass writes the counts too */
    CountPass = Final || (Now.QuadPart - CmpAclLastCountPass.QuadPart) >= (LONGLONG)CMP_ACL_COUNT_INTERVAL * 10000000;

    /* The file (never from an ordinary pass once the system shuts down) */
    if ((Final || !CmpAclShutdown) &&
        !CmpAclFileGivenUp && CmpAclBootBytes < CMP_ACL_BOOT_WRITE_LIMIT &&
        (CmpAclPending.Next || CountPass || (CmpAclSaturated && !CmpAclSaturationLogged)))
    {
        Out.Buffer = ExAllocatePoolWithTag(PagedPool, Out.Size, TAG_CM_ACL);
        if (Out.Buffer)
        {
            if (!CmpAclBootHeaderWritten)
            {
                CmpAclLineStart(&Line, &Now);
                CmpAclLineFormat(&Line, ",\"event\":\"start\",\"mode\":\"%s\",\"configured\":\"%s\",\"source\":\"%s\"}\n",
                                 CmpAclModeNames[CmpRegistryAclEffectiveMode],
                                 CmpAclModeNames[CmpRegistryAclMode],
                                 CmpAclSourceNames[CmpRegistryAclModeSource]);
                CmpAclOut(&Out, &Line);
            }

            /* New entries */
            Next = CmpAclPending.Next;
            while (Next)
            {
                Entry = CONTAINING_RECORD(Next, CMP_ACL_ENTRY, QueueEntry);
                CmpAclFormatEntry(Entry, &Line);
                if (!CmpAclOut(&Out, &Line))
                    break;
                Entry->WrittenCount = 1;
                Next = Next->Next;
            }
            List = Next;

            /* Counts that moved since they were last written */
            if (CountPass && !List)
            {
                for (i = 0; i < CMP_ACL_TABLE_SIZE; i++)
                {
                    Entry = CmpAclSlotEntry[i];
                    if (!Entry || !Entry->WrittenCount)
                        continue;
                    Count = CmpAclSlotCount[i];
                    if (Count == Entry->WrittenCount)
                        continue;
                    CmpAclLineStart(&Line, &Now);
                    CmpAclLineFormat(&Line, ",\"id\":%lu,\"count\":%ld}\n", Entry->Id, Count);
                    if (!CmpAclOut(&Out, &Line))
                        break;
                    Entry->WrittenCount = Count;
                }
            }

            if (CmpAclSaturated && !CmpAclSaturationLogged)
            {
                CmpAclLineStart(&Line, &Now);
                CmpAclLineFormat(&Line, ",\"event\":\"saturated\",\"entries\":%u}\n", CMP_ACL_MAX_ENTRIES);
                CmpAclOut(&Out, &Line);
            }

            if (Out.Length && CmpAclBootBytes + Out.Length > CMP_ACL_BOOT_WRITE_LIMIT)
            {
                /* This boot's share is used up: say so once and stop */
                CmpAclLineStart(&Line, &Now);
                CmpAclLineAppend(&Line, ",\"event\":\"capped\"}\n");
                Out.Length = 0;
                Out.Lines = 0;
                CmpAclOut(&Out, &Line);
                CmpAclBootBytes = CMP_ACL_BOOT_WRITE_LIMIT;
                if (!CmpAclCapLogged)
                {
                    CmpAclCapLogged = TRUE;
                    DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL, "CM-ACL-AUDIT: log file limit reached for this boot\n");
                }
            }

            Status = CmpAclOpenLog(&File);
            if (NT_SUCCESS(Status))
            {
                FILE_STANDARD_INFORMATION Standard;
                LARGE_INTEGER Offset;

                /* Append at the end the file system reports (not every one honours append-only handles) */
                Status = ZwQueryInformationFile(File, &Iosb, &Standard, sizeof(Standard), FileStandardInformation);
                if (NT_SUCCESS(Status))
                {
                    Offset = Standard.EndOfFile;
                    Status = ZwWriteFile(File, NULL, NULL, NULL, &Iosb, Out.Buffer, Out.Length, &Offset, NULL);
                }
                ZwClose(File);
            }
            if (NT_SUCCESS(Status))
            {
                InterlockedExchangeAdd(&CmpAclLinesWritten, (LONG)Out.Lines);
                if (CmpAclBootBytes < CMP_ACL_BOOT_WRITE_LIMIT)
                    CmpAclBootBytes += Out.Length;
                CmpAclBootHeaderWritten = TRUE;
                CmpAclFileTries = 0;
                if (CmpAclSaturated)
                    CmpAclSaturationLogged = TRUE;
                if (CountPass && !List)
                    CmpAclLastCountPass = Now;

                /* Written entries leave the pending list (they stay in the table for counts) */
                CmpAclPending.Next = List;
                if (!List)
                    CmpAclPendingTail = NULL;
                else
                    Again = TRUE;
            }
            else
            {
                /* \SystemRoot not writable yet (or at all: a CD) */
                InterlockedIncrement(&CmpAclFileErrors);
                if (++CmpAclFileTries >= CMP_ACL_FILE_RETRIES)
                {
                    CmpAclFileGivenUp = TRUE;
                    DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL,
                               "CM-ACL-AUDIT: cannot write the audit log (0x%08lx), debug output only\n", Status);
                }
                else
                {
                    Again = TRUE;
                }
            }
            ExFreePoolWithTag(Out.Buffer, TAG_CM_ACL);
        }
        else
        {
            Again = TRUE;
        }
    }
    else if (CmpAclSaturated)
    {
        CmpAclSaturationLogged = TRUE;
    }

    if (CmpAclFileGivenUp || CmpAclBootBytes >= CMP_ACL_BOOT_WRITE_LIMIT)
    {
        /* Nothing more goes to the file; keep the list empty */
        CmpAclPending.Next = NULL;
        CmpAclPendingTail = NULL;
    }

    /* Counters: with new entries, else at most once a minute */
    if (Final || Reversed || (Now.QuadPart - CmpAclLastPublish.QuadPart) >= (LONGLONG)CMP_ACL_PUBLISH_INTERVAL * 10000000)
    {
        CmpAclPublish();
        CmpAclLastPublish = Now;
        CmpAclLastDenials = CmpAclDenials;
    }
    else if (CmpAclDenials != CmpAclLastDenials)
    {
        Again = TRUE;
    }

    /* Counts not in the file yet: come back until the next count pass writes them */
    if (!Again && !CmpAclFileGivenUp && CmpAclBootBytes < CMP_ACL_BOOT_WRITE_LIMIT)
    {
        for (i = 0; i < CMP_ACL_TABLE_SIZE; i++)
        {
            Entry = CmpAclSlotEntry[i];
            if (Entry && Entry->WrittenCount && CmpAclSlotCount[i] != Entry->WrittenCount)
            {
                Again = TRUE;
                break;
            }
        }
    }

    if (Final)
        return Again;

    /* Let the next denial arm the timer again, then catch what arrived meanwhile */
    InterlockedExchange(&CmpAclTimerArmed, 0);
    if (Again || ExQueryDepthSList(&CmpAclQueue) || CmpAclDenials != CmpAclLastDenials)
        CmpAclArmTimer();
    return Again;
}

static
VOID
NTAPI
CmpAclWorker(
    _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    /* Once the system shuts down the shutdown pass has the work */
    if (!CmpAclShutdown)
        CmpAclRun(FALSE);

    if (InterlockedDecrement(&CmpAclWorkItems) == 0)
        KeSetEvent(&CmpAclWorkIdle, IO_NO_INCREMENT, FALSE);
}

static
VOID
NTAPI
CmpAclTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    /*
     * Only one timer is ever armed, so only one work item is queued or running. Count it
     * before looking at the shutdown flag: the shutdown waits for the count to reach zero.
     */
    InterlockedIncrement(&CmpAclWorkItems);
    KeClearEvent(&CmpAclWorkIdle);
    if (CmpAclShutdown)
    {
        if (InterlockedDecrement(&CmpAclWorkItems) == 0)
            KeSetEvent(&CmpAclWorkIdle, IO_NO_INCREMENT, FALSE);
        return;
    }
    ExQueueWorkItem(&CmpAclWorkItem, DelayedWorkQueue);
}

/*
 * The system is shutting down (before the hives are flushed and before the file systems are):
 * stop the worker, then write what is pending and the counters once, ourselves.
 */
VOID
NTAPI
CmpAclShutdownSystem(VOID)
{
    LARGE_INTEGER Timeout;
    ULONG Pass;

    if (!CmpAclReady || InterlockedExchange(&CmpAclShutdown, 1) != 0)
        return;

    /* No new timer expiry (one that is running counts its work item before it looks at the flag) */
    KeCancelTimer(&CmpAclTimer);
    KeFlushQueuedDpcs();

    /* A queued or running work item ends without touching a file; wait for it, but not for ever */
    Timeout.QuadPart = -(LONGLONG)10 * 10 * 1000 * 1000;
    if (CmpAclWorkItems != 0 &&
        KeWaitForSingleObject(&CmpAclWorkIdle, Executive, KernelMode, FALSE, &Timeout) == STATUS_TIMEOUT)
    {
        /* The work item is stuck: write nothing, it must not race the pass below */
        DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL, "CM-ACL-AUDIT: worker did not end at shutdown, nothing written\n");
        return;
    }

    /* Nothing runs but this thread: the last pass (a few at most when more than a buffer is pending) */
    for (Pass = 0; Pass < 4; Pass++)
    {
        if (!CmpAclRun(TRUE))
            break;
    }
}

/* Find /REGACL=<mode> in the (upper-cased) load options */
static
BOOLEAN
CmpAclParseBootOption(
    _In_opt_ PCSTR Options,
    _Out_ PULONG Mode)
{
    static const CHAR Name[] = "REGACL=";
    PCSTR p = Options, Value;
    SIZE_T Length;

    if (!p)
        return FALSE;
    while (*p)
    {
        while (*p == ' ' || *p == '\t' || *p == '/')
            p++;
        if (_strnicmp(p, Name, sizeof(Name) - 1) == 0)
        {
            Value = p + sizeof(Name) - 1;
            for (Length = 0; Value[Length] && Value[Length] != ' ' && Value[Length] != '\t' && Value[Length] != '/'; Length++)
                ;
            if (Length == 6 && !_strnicmp(Value, "LEGACY", 6))
                *Mode = CM_REGACL_MODE_LEGACY;
            else if (Length == 5 && !_strnicmp(Value, "AUDIT", 5))
                *Mode = CM_REGACL_MODE_AUDIT;
            else if (Length == 7 && !_strnicmp(Value, "ENFORCE", 7))
                *Mode = CM_REGACL_MODE_ENFORCE;
            else
                return FALSE;
            return TRUE;
        }
        while (*p && *p != ' ' && *p != '\t' && *p != '/')
            p++;
    }
    return FALSE;
}

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * Decide the mode and prepare the shadow check. Called at the end of
 * CmInitSystem1 (system process, SYSTEM hive and CurrentControlSet present).
 * Never fails the boot: anything missing leaves the legacy behaviour.
 */
VOID
NTAPI
CmpAclInitialize(VOID)
{
    ULONG Mode, i;
    ULONG Rule;
    UCHAR Buffer[CMP_ACL_SD_BUFFER];
    const CMP_ACL_SD_SPEC *Spec;
    PVOID Copy;

    /* Mode: the default, then the registry value, then the boot option */
    CmpRegistryAclMode = CM_REGACL_MODE_AUDIT;
    CmpRegistryAclModeSource = 0;
    if (CmpRegistryAclModeValueType == REG_DWORD &&
        CmpRegistryAclModeValueLength == sizeof(ULONG) &&
        CmpRegistryAclModeValue <= CM_REGACL_MODE_ENFORCE)
    {
        CmpRegistryAclMode = CmpRegistryAclModeValue;
        CmpRegistryAclModeSource = 1;
    }
    if (KeLoaderBlock && CmpAclParseBootOption(KeLoaderBlock->LoadOptions, &Mode))
    {
        CmpRegistryAclMode = Mode;
        CmpRegistryAclModeSource = 2;
    }

    /* Enforcement does not exist yet: ENFORCE audits */
    Mode = (CmpRegistryAclMode == CM_REGACL_MODE_LEGACY) ? CM_REGACL_MODE_LEGACY : CM_REGACL_MODE_AUDIT;

    /* The SIDs and descriptors */
    for (i = 0; i < CmpAclSidMax; i++)
    {
        CmpAclSids[i] = CmpAclAllocateSid(CmpAclSidSpecs[i].Authority, CmpAclSidSpecs[i].Count,
                                          CmpAclSidSpecs[i].SubAuthority);
        if (!CmpAclSids[i])
            Mode = CM_REGACL_MODE_LEGACY;
    }

    for (Rule = CmpAclRuleMaster; Rule < CmpAclRuleMax && Mode != CM_REGACL_MODE_LEGACY; Rule++)
    {
        switch (Rule)
        {
            case CmpAclRuleHiveRoot: Spec = &CmpAclSdHiveRoot; break;
            case CmpAclRuleSamSecurity: Spec = &CmpAclSdSamSecurity; break;
            case CmpAclRuleTaskCache: Spec = &CmpAclSdTaskCache; break;
            case CmpAclRuleEventLog: Spec = &CmpAclSdEventLog; break;
            case CmpAclRuleDefault: Spec = &CmpAclSdDefault; break;
            case CmpAclRuleUser: continue; /* per key */
            default: Spec = &CmpAclSdMaster; break; /* master, hardware, user-unknown, other */
        }
        Copy = NULL;
        if (CmpAclBuildSd(Spec, NULL, Buffer, sizeof(Buffer)))
        {
            Copy = ExAllocatePoolWithTag(PagedPool, RtlLengthSecurityDescriptor(Buffer), TAG_CM_ACL);
            if (Copy)
                RtlCopyMemory(Copy, Buffer, RtlLengthSecurityDescriptor(Buffer));
        }
        CmpAclSdTable[Rule] = Copy;
        if (!Copy)
            Mode = CM_REGACL_MODE_LEGACY;
    }

    if (Mode != CM_REGACL_MODE_LEGACY)
    {
        /* Inheritance from a stored ancestor is computed as for a key SYSTEM creates */
        SeCaptureSubjectContext(&CmpAclSystemSubject);
        KeInitializeSpinLock(&CmpAclQueueLock);
        ExInitializePushLock(&CmpAclUserCacheLock);
        InitializeSListHead(&CmpAclQueue);
        KeInitializeTimer(&CmpAclTimer);
        KeInitializeDpc(&CmpAclDpc, CmpAclTimerDpc, NULL);
        ExInitializeWorkItem(&CmpAclWorkItem, CmpAclWorker, NULL);
        KeInitializeEvent(&CmpAclWorkIdle, NotificationEvent, TRUE);
        CmpAclReady = TRUE;
    }
    else if (CmpRegistryAclMode != CM_REGACL_MODE_LEGACY)
    {
        DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL, "CM-ACL-AUDIT: cannot set up audit mode, legacy\n");
    }

    CmpRegistryAclEffectiveMode = Mode;
    DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL, "CM-ACL-AUDIT: mode %s (configured %s, from %s)\n",
               CmpAclModeNames[CmpRegistryAclEffectiveMode],
               CmpAclModeNames[CmpRegistryAclMode],
               CmpAclSourceNames[CmpRegistryAclModeSource]);

    /* Publish the mode now; the worker refreshes the counters */
    CmpAclPublish();
}

/* The check itself, out of line so that the kernel-mode path does not pay its stack */
static
DECLSPEC_NOINLINE
VOID
CmpAclShadowCheckWorker(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_opt_ PCUNICODE_STRING ChildName,
    _In_ ULONG Operation,
    _In_ PACCESS_STATE AccessState,
    _In_ ACCESS_MASK Desired,
    _In_ ACCESS_MASK Previous,
    _In_ ACCESS_MASK LegacyGranted,
    _In_ ULONG Options)
{
    ULONG SdBuffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    PSECURITY_DESCRIPTOR Sd, ToFree;
    ULONG Rule;
    ACCESS_MASK Granted = 0;
    NTSTATUS AccessStatus = STATUS_ACCESS_DENIED;
    PPRIVILEGE_SET Privileges = NULL;
    BOOLEAN Result;

    /* Publish the counters now and then even when nothing is denied (the worker does it at most once a minute) */
    if ((InterlockedIncrement(&CmpAclChecks) & 0xFFF) == 0)
        CmpAclArmTimer();

    /* REG_OPTION_BACKUP_RESTORE with SeBackup or SeRestore enabled bypasses the DACL (oracle table) */
    if ((Options & REG_OPTION_BACKUP_RESTORE) &&
        (CmpAclPrivilegeEnabled(&AccessState->SubjectSecurityContext, SE_BACKUP_PRIVILEGE) ||
         CmpAclPrivilegeEnabled(&AccessState->SubjectSecurityContext, SE_RESTORE_PRIVILEGE)))
    {
        return;
    }

    Sd = CmpGetEffectiveKeySd(Kcb, SdBuffer, sizeof(SdBuffer), &Rule, &ToFree);
    if (!Sd)
    {
        InterlockedIncrement(&CmpAclErrors);
        return;
    }

    Result = SeAccessCheck(Sd,
                           &AccessState->SubjectSecurityContext,
                           FALSE,
                           Desired,
                           Previous,
                           &Privileges,
                           &CmpKeyObjectType->TypeInfo.GenericMapping,
                           UserMode,
                           &Granted,
                           &AccessStatus);
    if (Privileges)
        SeFreePrivileges(Privileges);

    if (!Result)
    {
        CmpAclRecordDenial(Kcb, ChildName, Operation, &AccessState->SubjectSecurityContext,
                           Desired, Granted, AccessStatus, Rule);
    }
    else if ((Desired & MAXIMUM_ALLOWED) && LegacyGranted && (Granted & LegacyGranted) != LegacyGranted)
    {
        /* Opened for MAXIMUM_ALLOWED: Windows hands out less (counted, not logged) */
        InterlockedIncrement(&CmpAclMaxAllowedReduced);
    }

    if (ToFree)
        SeDeassignSecurity(&ToFree);
}

/*
 * The shadow access check. Called after the real decision granted the open or
 * create; records what Windows would have decided. Never fails, never changes
 * the caller's result or the access state.
 *
 *  Kcb       the key opened, or the parent of a key being created
 *  ChildName the new key's name (creates)
 *  Desired   access checked: the open's remaining desired access as it was
 *            before the real check, or KEY_CREATE_SUB_KEY/KEY_CREATE_LINK
 *  Previous  access granted before the real check
 *  LegacyGranted what the real check granted (for MAXIMUM_ALLOWED opens)
 *  Options   REG_OPTION_BACKUP_RESTORE of the open or create
 */
VOID
NTAPI
CmpShadowAccessCheck(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_opt_ PCUNICODE_STRING ChildName,
    _In_ ULONG Operation,
    _In_ PACCESS_STATE AccessState,
    _In_ ACCESS_MASK Desired,
    _In_ ACCESS_MASK Previous,
    _In_ ACCESS_MASK LegacyGranted,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ ULONG Options)
{
    /* Kernel-mode callers are not checked on Windows either */
    if (CmpRegistryAclEffectiveMode == CM_REGACL_MODE_LEGACY || !CmpAclReady || AccessMode == KernelMode)
        return;
    if (!Kcb || !AccessState || Operation > CM_REGACL_OP_LINKNODE)
        return;

    CmpAclShadowCheckWorker(Kcb, ChildName, Operation, AccessState, Desired, Previous, LegacyGranted, Options);
}

/* EOF */
