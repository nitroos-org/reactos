/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Configuration Manager - registry access control audit mode (shadow access check)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Key access control. One function (CmpAclDecide) takes the access decision
 * on a key's own descriptor (its effective one, below) for a user-mode open
 * (the desired access) or create (KEY_CREATE_SUB_KEY, or KEY_CREATE_LINK for
 * a link, on the parent), with Windows' REG_OPTION_BACKUP_RESTORE rules. What
 * happens with the decision depends on the mode:
 *
 * - Audit (1, the default): the decision is only recorded. Opens are decided
 *   by CmpCheckKeyOpenAccess against the legacy Everyone:GENERIC_ALL
 *   descriptor, creates check nothing on the parent, and every open or create
 *   that the key's descriptor denies is logged after the real decision (the
 *   shadow check); none of its outcomes reaches the caller.
 * - Enforce (2): the decision stands (CmpAclCheckKeyOpen before the handle,
 *   CmpAclCheckKeyCreate before anything is created) and every denial is
 *   logged the same way, so an audit log of a workload lists what enforcement
 *   denies. Kernel-mode callers (previous mode KernelMode without
 *   OBJ_FORCE_ACCESS_CHECK) are not checked, as on Windows. Everything else a
 *   handle does (set value, delete, enumerate, notify, rename, save, set
 *   security) is checked against the access granted at the open, as always.
 *   If SYSTEM would not get full control of a key the boot needs, the stored
 *   descriptor responsible is replaced (CmpAclSystemHasFullControl); only if
 *   that fails does the boot fall back to audit. The first enforcing boot after
 *   boots that did not enforce checks the machine hives for descriptors only a
 *   non-administrator could have stored meanwhile (CmpAclTransition).
 * - Legacy (0): no decision on key descriptors at all, nothing stored.
 *
 * The boot option /REGACL=LEGACY|AUDIT|ENFORCE wins over the REG_DWORD value
 * Control\Session Manager\Configuration Manager\RegistryAclMode, which is
 * honoured only from a key only administrators can change (see below), and
 * never below enforcement where enforcement is the compiled default.
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
 * from the caller's buffers, and a descriptor stored in a hive is copied
 * under the hive's security lock and only the copy is validated and used.
 *
 * Keys created while the mode is not legacy get a stored descriptor: the
 * effective descriptor of their parent, inherited (CmpCaptureParentSecurity,
 * used by CmpDoCreateChild). /REGACL=LEGACY turns that off too.
 *
 * Two switches change storage, the audit or enforcement for a whole boot,
 * and both are read at boot: the mode (above) and setup
 * (CmpAclSetupRunning). The boot option and text-mode setup come from the
 * loader block, which only an administrator can change. The two registry
 * values (RegistryAclMode, any value; SYSTEM\Setup\SystemSetupInProgress != 0) are
 * honoured only when the key that holds the value has an effective
 * descriptor that lets nobody but SYSTEM and Administrators (and
 * TrustedInstaller) change it (CmpAclKeyAdminWriteOnly): no allow ACE for
 * anyone else with KEY_SET_VALUE, DELETE, WRITE_DAC or WRITE_OWNER, an owner
 * from that set, a DACL. Otherwise the value is ignored, storage (and the
 * audit) stay on, and the boot log, the debug output and AuditStats
 * (SwitchesIgnored) say so. The effective descriptor of those keys is the
 * Windows one (the policy table) unless a descriptor was stored for them or
 * an ancestor, so this changes nothing on an installed system; it stops a
 * descriptor that a non-administrator could plant on such a key (delete and
 * re-create it with an explicit descriptor, which works while access is not
 * enforced) from carrying the switch into the time when it is. In audit mode
 * anyone can still write the values themselves; under enforcement the keys'
 * descriptors keep non-administrators from writing them.
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

static const PCSTR CmpAclOpNames[] = { "open", "create", "createlink", "linknode", "followlink", "restamp" };
C_ASSERT(RTL_NUMBER_OF(CmpAclOpNames) == CM_REGACL_OP_RESTAMP + 1);
static const PCSTR CmpAclModeNames[] = { "legacy", "audit", "enforce" };
static const PCSTR CmpAclSourceNames[] = { "default", "registry", "bootoption" };

/* AuditStats SwitchesIgnored: a registry value that would turn storage off was not honoured */
#define CMP_ACL_IGNORED_MODE_VALUE  0x1
#define CMP_ACL_IGNORED_SETUP_VALUE 0x2
/* RegistryAclMode asked for less than enforcement where enforcement is the default */
#define CMP_ACL_IGNORED_MODE_LOWER  0x4

/* AuditStats EnforceFallback: why a boot that should enforce does not */
#define CMP_ACL_FALLBACK_SYSTEM     0x1     /* a SYSTEM-hive boot key: SYSTEM lacks full control, not repaired */
#define CMP_ACL_FALLBACK_HIVES      0x2     /* the same for a key of another machine hive */

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
/* A present NULL SACL, auto-inherited (SDDL S:AINO_ACCESS_CONTROL): what these keys report on Windows (oracle) */
#define CMP_ACL_NULL_SACL_AI (SE_SACL_PRESENT | SE_SACL_AUTO_INHERITED)

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
       O:BAG:SYD:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)(A;CI;KR;;;AC)(A;CI;KR;;;LPAC)S:AINO_ACCESS_CONTROL */
    CmpAclSidAdmins, CmpAclSidSystem, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | CMP_ACL_NULL_SACL_AI, 6,
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
    /* HKLM\SAM\SAM, HKLM\SECURITY: O:BAG:SYD:(A;CI;KA;;;SY)(A;CI;RCWD;;;BA) (control 0x8804 and
       0x8814: SE_SACL_AUTO_INHERITED both, the NULL SACL present on SECURITY only) */
    CmpAclSidAdmins, CmpAclSidSystem, SE_SACL_AUTO_INHERITED, 2,
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
    CmpAclSidSystem, CmpAclSidSystem, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | CMP_ACL_NULL_SACL_AI, 2,
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
    CmpAclSidSystem, CmpAclSidSystem, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | CMP_ACL_NULL_SACL_AI, 4,
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
    CmpAclSidAdmins, CmpAclSidSystem, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | CMP_ACL_NULL_SACL_AI, 6,
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
    CmpAclSidAdmins, CmpAclSidSystem, SE_DACL_PROTECTED | CMP_ACL_NULL_SACL_AI, 6,
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

/*
 * The mode without a boot option or an honoured RegistryAclMode value. Audit:
 * key access is not enforced unless asked for (mode 2).
 */
#define CMP_REGACL_DEFAULT_MODE     CM_REGACL_MODE_AUDIT

/* Configured mode, the mode that runs, and where it came from */
ULONG CmpRegistryAclMode = CMP_REGACL_DEFAULT_MODE;
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

/* Setup is running (text mode, or SYSTEM\Setup\SystemSetupInProgress at boot): no stored descriptors */
static BOOLEAN CmpAclSetupRunning;

/* CMP_ACL_IGNORED_*: switches read at boot and not honoured (see the top of the file) */
static ULONG CmpAclSwitchesIgnored;

/* Enforcement was asked for, but SYSTEM would not get full control of a boot key: audit runs */
static ULONG CmpAclEnforceFallback;      /* CMP_ACL_FALLBACK_* */

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

static VOID CmpAclPublish(VOID);
static VOID CmpAclRepairSystemAccess(_In_ PCUNICODE_STRING Path);
static BOOLEAN CmpAclTrustedSid(_In_ PSID Sid);

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

/*
 * A copy of the key's stored descriptor, or NULL if it has none that is sane.
 *
 * The cell is read under the hive's security lock, so that it cannot be
 * released (and its storage reused) while it is copied, and only the copy is
 * validated and used: the hive is untrusted input, and the cell may change
 * once the lock is dropped (its key's descriptor replaced). The copy goes to
 * Buffer when it fits, otherwise to pool (*PoolCopy, freed with
 * CmpAclFreeCopy).
 *
 * Shortcut: a hive whose security cache is empty has no stored descriptor to
 * find (every hive installed before keys got one, until a key is created in
 * it). The audit path takes it; creates read exactly.
 */
static
PSECURITY_DESCRIPTOR
CmpAclCopyStoredSd(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PVOID *PoolCopy,
    _In_ BOOLEAN Shortcut)
{
    PHHIVE Hive;
    PCM_KEY_NODE Node;
    HCELL_INDEX SecurityCell;
    PCM_KEY_SECURITY Security;
    PVOID Copy = NULL;
    ULONG Length = 0;
    BOOLEAN Acquired;

    *PoolCopy = NULL;
    if (!Kcb->KeyHive || Kcb->KeyCell == HCELL_NIL ||
        (Kcb->ExtFlags & CM_KCB_KEY_NON_EXIST) || Kcb->Delete)
    {
        return NULL;
    }
    Hive = Kcb->KeyHive;
    if (Shortcut && ((PCMHIVE)Hive)->SecurityCount == 0)
        return NULL;

    /* A look without the lock first: most keys of an installed hive have none */
    Node = (PCM_KEY_NODE)HvGetCell(Hive, Kcb->KeyCell);
    if (!Node)
        return NULL;
    SecurityCell = (Node->Signature == CM_KEY_NODE_SIGNATURE) ? Node->Security : HCELL_NIL;
    HvReleaseCell(Hive, Kcb->KeyCell);
    if (SecurityCell == HCELL_NIL)
        return NULL;

    /* Read again and copy under the lock: the cell named then is the one copied */
    Acquired = CmpAcquireHiveSecurityLock(Hive);
    Node = (PCM_KEY_NODE)HvGetCell(Hive, Kcb->KeyCell);
    if (Node)
    {
        SecurityCell = (Node->Signature == CM_KEY_NODE_SIGNATURE) ? Node->Security : HCELL_NIL;
        HvReleaseCell(Hive, Kcb->KeyCell);

        /* The cell is checked against its bin (CmpGetCheckedSecurityCell) */
        Security = CmpGetCheckedSecurityCell(Hive, SecurityCell, NULL);
        if (Security &&
            Security->DescriptorLength >= sizeof(SECURITY_DESCRIPTOR_RELATIVE) &&
            Security->DescriptorLength <= CMP_MAX_STORED_SD_LENGTH)
        {
            Length = Security->DescriptorLength;
            if (Length <= BufferSize)
                Copy = Buffer;
            else
                Copy = *PoolCopy = ExAllocatePoolWithTag(PagedPool, Length, TAG_CM_ACL);
            if (Copy)
                RtlCopyMemory(Copy, &Security->Descriptor, Length);
        }
    }
    CmpReleaseHiveSecurityLock(Hive, Acquired);
    if (!Copy)
        return NULL;

    /*
     * The copy is what is checked (offsets, SIDs, ACLs and their ACEs) and used. Callers copy
     * RtlLengthSecurityDescriptor() bytes of it, the sum of its parts: a descriptor whose parts
     * lie beyond that sum (a gap before one of them) or add up to more than it was stored with
     * (overlapping parts) is not sound either, so the parts must also fit the sum.
     */
    if (!RtlValidRelativeSecurityDescriptor(Copy, Length, 0) ||
        RtlLengthSecurityDescriptor(Copy) > Length ||
        !RtlValidRelativeSecurityDescriptor(Copy, RtlLengthSecurityDescriptor(Copy), 0))
    {
        if (*PoolCopy)
        {
            ExFreePoolWithTag(*PoolCopy, TAG_CM_ACL);
            *PoolCopy = NULL;
        }
        return NULL;
    }
    return Copy;
}

/* What CmpGetEffectiveKeySd handed out besides its buffer */
static
VOID
CmpAclFreeEffectiveSd(
    _In_opt_ PSECURITY_DESCRIPTOR ToFree,
    _In_opt_ PVOID PoolCopy)
{
    if (ToFree)
        SeDeassignSecurity(&ToFree);
    if (PoolCopy)
        ExFreePoolWithTag(PoolCopy, TAG_CM_ACL);
}

/* Does an ACL of the (validated) descriptor hold an ACE flagged NO_PROPAGATE_INHERIT_ACE? */
static
BOOLEAN
CmpAclSdHasNoPropagate(
    _In_ PSECURITY_DESCRIPTOR Sd)
{
    BOOLEAN Present, Defaulted;
    PACL Acl;
    PACE_HEADER Ace;
    ULONG Which, i;

    for (Which = 0; Which < 2; Which++)
    {
        Acl = NULL;
        if (Which == 0)
        {
            if (!NT_SUCCESS(RtlGetDaclSecurityDescriptor(Sd, &Present, &Acl, &Defaulted)) || !Present)
                continue;
        }
        else
        {
            if (!NT_SUCCESS(RtlGetSaclSecurityDescriptor(Sd, &Present, &Acl, &Defaulted)) || !Present)
                continue;
        }
        if (!Acl)
            continue;
        for (i = 0; i < Acl->AceCount; i++)
        {
            if (!NT_SUCCESS(RtlGetAce(Acl, i, (PVOID *)&Ace)))
                return TRUE;    /* cannot tell: take the exact path */
            if (Ace->AceFlags & NO_PROPAGATE_INHERIT_ACE)
                return TRUE;
        }
    }
    return FALSE;
}

/*
 * The descriptor a key would be checked against on Windows (see the top of
 * the file), in Buffer or in what *ToFree / *PoolCopy receive (free both with
 * CmpAclFreeEffectiveSd). A stored descriptor is always a validated copy.
 * Returns NULL if none could be built.
 */
static
PSECURITY_DESCRIPTOR
CmpGetEffectiveKeySd(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG Rule,
    _Out_ PSECURITY_DESCRIPTOR *ToFree,
    _Out_ PVOID *PoolCopy,
    _In_ BOOLEAN Shortcut)
{
    PSECURITY_DESCRIPTOR Sd, NewSd = NULL, Intermediate;
    PCM_KEY_CONTROL_BLOCK Parent;
    PVOID AncestorCopy;
    NTSTATUS Status;
    ULONG Distance = 0;
    BOOLEAN NoPropagate;

    *ToFree = NULL;
    *PoolCopy = NULL;

    /* 1. Stored */
    Sd = CmpAclCopyStoredSd(Kcb, Buffer, BufferSize, PoolCopy, Shortcut);
    if (Sd)
    {
        *Rule = CmpAclRuleCell;
        return Sd;
    }

    /* 2. The nearest ancestor that has one, inherited as SYSTEM would get it */
    for (Parent = Kcb->ParentKcb; Parent; Parent = Parent->ParentKcb)
    {
        Distance++;
        Sd = CmpAclCopyStoredSd(Parent, Buffer, BufferSize, &AncestorCopy, Shortcut);
        if (!Sd)
            continue;
        /*
         * Under an auto-inherited DACL the key's own is auto-inherited too (its
         * inherited ACEs are flagged, control AI), as on Windows, where the keys
         * setup creates below such a key inherit that way. A key created under it
         * later gets the same (CmpDoCreateChild).
         */
        Status = SeAssignSecurityEx(Sd,
                                    NULL,
                                    &NewSd,
                                    NULL,
                                    TRUE,
                                    (((PISECURITY_DESCRIPTOR)Sd)->Control & SE_DACL_AUTO_INHERITED) ?
                                        SEF_DACL_AUTO_INHERIT : 0,
                                    &CmpAclSystemSubject,
                                    &CmpKeyObjectType->TypeInfo.GenericMapping,
                                    PagedPool);
        NoPropagate = (Distance >= 2) && CmpAclSdHasNoPropagate(Sd);
        if (AncestorCopy)
            ExFreePoolWithTag(AncestorCopy, TAG_CM_ACL);

        /*
         * The ancestor is further up than the parent: the keys between have no
         * descriptor of their own and stand for what they would have inherited.
         * One more inheritance step gives what a key two or more levels down
         * gets: an ACE with NO_PROPAGATE_INHERIT_ACE reaches the first level
         * only. After two steps the result does not change any more (what
         * still passes on reproduces itself), so two steps cover any distance;
         * without such an ACE the second step changes nothing and is skipped.
         */
        if (NT_SUCCESS(Status) && NoPropagate)
        {
            Intermediate = NewSd;
            NewSd = NULL;
            Status = SeAssignSecurityEx(Intermediate,
                                        NULL,
                                        &NewSd,
                                        NULL,
                                        TRUE,
                                        (((PISECURITY_DESCRIPTOR)Intermediate)->Control & SE_DACL_AUTO_INHERITED) ?
                                            SEF_DACL_AUTO_INHERIT : 0,
                                        &CmpAclSystemSubject,
                                        &CmpKeyObjectType->TypeInfo.GenericMapping,
                                        PagedPool);
            SeDeassignSecurity(&Intermediate);
        }

        /*
         * No descriptor rather than the policy one: the policy descriptor of
         * the place may give more than the stored ancestor does (fail closed)
         */
        if (!NT_SUCCESS(Status))
            return NULL;
        *Rule = CmpAclRuleInherited;
        *ToFree = NewSd;
        return NewSd;
    }

    /* 3. Synthesised */
    return CmpAclSynthesizeSd(Kcb, Buffer, BufferSize, Rule);
}

/* SYSTEM, Administrators, TrustedInstaller: who may hold the switches */
static
BOOLEAN
CmpAclIsAdminSid(
    _In_ PSID Sid)
{
    static const struct
    {
        UCHAR Revision;
        UCHAR SubAuthorityCount;
        SID_IDENTIFIER_AUTHORITY Authority;
        ULONG SubAuthority[6];
    } TrustedInstaller =
    {
        SID_REVISION, 6, {SECURITY_NT_AUTHORITY},
        { 80, 956008885, 3418522649u, 1831038044, 1853292631, 2271478464u }
    };

    return RtlEqualSid(Sid, CmpAclSids[CmpAclSidSystem]) ||
           RtlEqualSid(Sid, CmpAclSids[CmpAclSidAdmins]) ||
           RtlEqualSid(Sid, (PSID)&TrustedInstaller);
}

/*
 * Can only SYSTEM and Administrators change a key with this descriptor (a
 * validated copy): a DACL, an owner (implicit WRITE_DAC) from that set, and
 * no ACE that applies to the key and allows a change of its values, its
 * descriptor or its existence to anyone else. Deny ACEs are not counted (a
 * deny never makes the answer yes), and an allow ACE of a type other than the
 * plain one is taken to grant everything. CREATOR OWNER / CREATOR GROUP in an
 * effective ACE never match a token; OWNER RIGHTS is the owner, checked. A
 * descriptor without an owner is not judged admin-only: nothing the kernel
 * stores lacks one, so it came from somewhere else (an edited hive file).
 */
static
BOOLEAN
CmpAclSdAdminWriteOnly(
    _In_ PSECURITY_DESCRIPTOR Sd)
{
    static const ACCESS_MASK Write = KEY_SET_VALUE | DELETE | WRITE_DAC | WRITE_OWNER;
    static SID_IDENTIFIER_AUTHORITY CreatorAuthority = {SECURITY_CREATOR_SID_AUTHORITY};
    BOOLEAN Present, Defaulted;
    PACL Dacl;
    PSID Owner, Sid;
    PACE_HEADER Ace;
    ACCESS_MASK Mask;
    ULONG i;

    if (!NT_SUCCESS(RtlGetOwnerSecurityDescriptor(Sd, &Owner, &Defaulted)) ||
        !Owner || !CmpAclIsAdminSid(Owner))
    {
        return FALSE;
    }
    if (!NT_SUCCESS(RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted)) || !Present || !Dacl)
        return FALSE;

    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)))
            return FALSE;
        if (Ace->AceFlags & INHERIT_ONLY_ACE)
            continue;
        if (Ace->AceType == ACCESS_DENIED_ACE_TYPE ||
            Ace->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
            Ace->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE ||
            Ace->AceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE)
        {
            continue;
        }
        if (Ace->AceType != ACCESS_ALLOWED_ACE_TYPE)
            return FALSE;

        Mask = ((PACCESS_ALLOWED_ACE)Ace)->Mask;
        Sid = (PSID)&((PACCESS_ALLOWED_ACE)Ace)->SidStart;
        RtlMapGenericMask(&Mask, &CmpKeyObjectType->TypeInfo.GenericMapping);
        if (!(Mask & (Write | MAXIMUM_ALLOWED)))
            continue;
        if (CmpAclIsAdminSid(Sid))
            continue;
        /* S-1-3-0, S-1-3-1 (never a token's) and S-1-3-4 (the owner, checked above) */
        if (*RtlSubAuthorityCountSid(Sid) == 1 &&
            RtlEqualMemory(RtlIdentifierAuthoritySid(Sid), &CreatorAuthority, sizeof(CreatorAuthority)) &&
            (*RtlSubAuthoritySid(Sid, 0) == SECURITY_CREATOR_OWNER_RID ||
             *RtlSubAuthoritySid(Sid, 0) == SECURITY_CREATOR_GROUP_RID ||
             *RtlSubAuthoritySid(Sid, 0) == 4 /* SECURITY_CREATOR_OWNER_RIGHTS_RID */))
        {
            continue;
        }
        return FALSE;
    }
    return TRUE;
}

/* Does the SYSTEM subject get KEY_ALL_ACCESS from this descriptor, as a user-mode open would */
static
BOOLEAN
CmpAclSdGivesSystemFullControl(
    _In_ PSECURITY_DESCRIPTOR Sd)
{
    ACCESS_MASK Granted = 0;
    NTSTATUS AccessStatus;
    PPRIVILEGE_SET Privileges = NULL;
    BOOLEAN Result;

    Result = SeAccessCheck(Sd,
                           &CmpAclSystemSubject,
                           FALSE,
                           KEY_ALL_ACCESS,
                           0,
                           &Privileges,
                           &CmpKeyObjectType->TypeInfo.GenericMapping,
                           UserMode,
                           &Granted,
                           &AccessStatus);
    if (Privileges)
        SeFreePrivileges(Privileges);
    return Result && (Granted & KEY_ALL_ACCESS) == KEY_ALL_ACCESS;
}

typedef enum _CMP_ACL_JUDGEMENT
{
    CmpAclJudgeAdminWriteOnly,
    CmpAclJudgeSystemFullControl
} CMP_ACL_JUDGEMENT;

/*
 * Judge the key at Path (a kernel path) by its effective descriptor (stored,
 * inherited or the policy table, as enforcement reads it):
 *  CmpAclJudgeAdminWriteOnly     only SYSTEM and Administrators can change it
 *                                (CmpAclSdAdminWriteOnly); FALSE if it cannot be
 *                                opened or judged;
 *  CmpAclJudgeSystemFullControl  SYSTEM gets KEY_ALL_ACCESS; a key that does not
 *                                exist passes (nothing to lock out of).
 * Boot only (CmpAclInitialize), after the descriptors and CmpAclSystemSubject are set up.
 */
static
BOOLEAN
CmpAclJudgeKey(
    _In_ PCUNICODE_STRING Path,
    _In_ CMP_ACL_JUDGEMENT Judgement)
{
    ULONG Buffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    OBJECT_ATTRIBUTES ObjectAttributes;
    PSECURITY_DESCRIPTOR Sd, ToFree;
    PCM_KEY_CONTROL_BLOCK Kcb;
    PCM_KEY_BODY KeyBody;
    PVOID PoolCopy;
    BOOLEAN Result = FALSE;
    HANDLE Key;
    ULONG Rule;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, (PUNICODE_STRING)Path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenKey(&Key, KEY_QUERY_VALUE, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        return (Judgement == CmpAclJudgeSystemFullControl &&
                (Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND));
    }
    if (NT_SUCCESS(ObReferenceObjectByHandle(Key, 0, CmpKeyObjectType, KernelMode, (PVOID *)&KeyBody, NULL)))
    {
        CmpLockRegistry();
        Kcb = KeyBody->KeyControlBlock;
        if (Kcb)
        {
            CmpAcquireKcbLockShared(Kcb);
            Sd = CmpGetEffectiveKeySd(Kcb, Buffer, sizeof(Buffer), &Rule, &ToFree, &PoolCopy, FALSE);
            if (Sd)
            {
                if (Judgement == CmpAclJudgeAdminWriteOnly)
                {
                    Result = CmpAclSdAdminWriteOnly(Sd);
                    if (!Result)
                    {
                        DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL,
                                   "CM-ACL-AUDIT: %wZ: non-administrators may change it (descriptor from %s)\n",
                                   Path, CmpAclRuleNames[Rule]);
                    }
                }
                else
                {
                    Result = CmpAclSdGivesSystemFullControl(Sd);
                    if (!Result)
                    {
                        DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL,
                                   "CM-ACL: %wZ: SYSTEM does not get full control (descriptor from %s)\n",
                                   Path, CmpAclRuleNames[Rule]);
                    }
                }
            }
            CmpAclFreeEffectiveSd(ToFree, PoolCopy);
            CmpReleaseKcbLock(Kcb);
        }
        CmpUnlockRegistry();
        ObDereferenceObject(KeyBody);
    }
    ZwClose(Key);
    return Result;
}

/*
 * The boot-time self-check before enforcement is switched on: SYSTEM must
 * get full control of the keys the boot and the services need (the policy
 * and setup descriptors all give it; a hive edited to say otherwise must not
 * make the system unbootable). The other hives are not loaded yet at this
 * point: their policy and setup descriptors give SYSTEM full control too.
 */
static
BOOLEAN
CmpAclSystemHasFullControl(
    _In_ BOOLEAN Repair)
{
    static const PCWSTR Keys[] =
    {
        L"\\Registry",
        L"\\Registry\\Machine",
        L"\\Registry\\User",
        L"\\Registry\\Machine\\HARDWARE",
        L"\\Registry\\Machine\\SYSTEM",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum",
        L"\\Registry\\Machine\\SYSTEM\\Setup",
    };
    UNICODE_STRING Path;
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Keys); i++)
    {
        RtlInitUnicodeString(&Path, Keys[i]);
        if (CmpAclJudgeKey(&Path, CmpAclJudgeSystemFullControl))
            continue;
        /*
         * A stored descriptor that shuts SYSTEM out of a boot key is repaired
         * (CmpAclRepairSystemAccess) rather than trusted: while a boot runs
         * without enforcement any user can store one, and falling back to audit
         * for it would hand that user the switch out of enforcement.
         */
        if (!Repair)
            return FALSE;
        CmpAclRepairSystemAccess(&Path);
        if (!CmpAclJudgeKey(&Path, CmpAclJudgeSystemFullControl))
            return FALSE;
    }
    return TRUE;
}

/*
 * The key at Path (a kernel path) can only be changed by SYSTEM and
 * Administrators, judged by its effective descriptor (stored, inherited or
 * the policy table). FALSE if it cannot be opened or judged. Boot only
 * (CmpAclInitialize), after the descriptors and CmpAclSystemSubject are set up.
 */
static
BOOLEAN
CmpAclKeyAdminWriteOnly(
    _In_ PCUNICODE_STRING Path)
{
    return CmpAclJudgeKey(Path, CmpAclJudgeAdminWriteOnly);
}

/*
 * New keys get a stored descriptor while the mode is not legacy and the
 * policy table exists (CmInitSystem1 on), except while setup runs (see
 * CmpAclInitialize). /REGACL=LEGACY gives the old behaviour back: keys are
 * created without one, as before audit mode.
 */
BOOLEAN
NTAPI
CmpStoreKeySecurity(VOID)
{
    return CmpAclReady && !CmpAclSetupRunning && CmpRegistryAclEffectiveMode != CM_REGACL_MODE_LEGACY;
}

/*
 * A descriptor the creator names is stored even while setup runs (the inherited ones are
 * not): setup gives the roots of the hives it builds the Windows descriptors this way. Only
 * legacy mode (nothing stored) and the time before the policy table exists are excluded.
 */
BOOLEAN
NTAPI
CmpStoreExplicitKeySecurity(VOID)
{
    return CmpAclReady && CmpRegistryAclEffectiveMode != CM_REGACL_MODE_LEGACY;
}

/* SYSTEM\Setup\SystemSetupInProgress (REG_DWORD) is not zero: second-stage setup */
static
BOOLEAN
CmpAclSystemSetupInProgress(VOID)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\Setup");
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"SystemSetupInProgress");
    OBJECT_ATTRIBUTES ObjectAttributes;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    ULONG Length;
    HANDLE Key;
    BOOLEAN InProgress = FALSE;

    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &ObjectAttributes)))
        return FALSE;
    if (NT_SUCCESS(ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length)) &&
        Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG))
    {
        InProgress = (*(PULONG)Info->Data != 0);
    }
    ZwClose(Key);
    return InProgress;
}

/*
 * The descriptor a key created under ParentKcb inherits from: the parent's
 * effective descriptor (stored, else inherited from the nearest ancestor that
 * has one, else the Windows policy for its place), so that a key created
 * under a key without one gets what it would get on Windows. Returns a pool
 * copy for CmpFreeParentSecurity, or NULL: the key is then created without a
 * stored descriptor. The caller holds the parent's KCB lock.
 */
DECLSPEC_NOINLINE
PSECURITY_DESCRIPTOR
NTAPI
CmpCaptureParentSecurity(
    _In_ PCM_KEY_CONTROL_BLOCK ParentKcb)
{
    if (!CmpStoreKeySecurity() || !ParentKcb)
        return NULL;

    return CmpCaptureKeySecurity(ParentKcb);
}

/*
 * A pool copy (self-relative, validated) of the descriptor of the key: its
 * stored one, else the one it would have on Windows (inherited from the
 * nearest ancestor that has one, else the policy for its place). It is what
 * the key reports (NtQuerySecurityObject) and what a set merges into. Free
 * it with CmpFreeParentSecurity. NULL before the tables exist (early boot,
 * legacy mode) or without memory. The caller holds the KCB lock.
 */
DECLSPEC_NOINLINE
PSECURITY_DESCRIPTOR
NTAPI
CmpCaptureKeySecurity(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb)
{
    ULONG Buffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    PSECURITY_DESCRIPTOR Sd, ToFree, Copy = NULL;
    PVOID PoolCopy;
    ULONG Rule, Length;

    if (!CmpAclReady || !Kcb)
        return NULL;

    Sd = CmpGetEffectiveKeySd(Kcb, Buffer, sizeof(Buffer), &Rule, &ToFree, &PoolCopy, FALSE);
    if (Sd)
    {
        Length = RtlLengthSecurityDescriptor(Sd);
        Copy = ExAllocatePoolWithTag(PagedPool, Length, TAG_CM_ACL);
        if (Copy)
            RtlCopyMemory(Copy, Sd, Length);
    }
    CmpAclFreeEffectiveSd(ToFree, PoolCopy);
    if (!Copy)
        InterlockedIncrement(&CmpAclErrors);
    return Copy;
}

VOID
NTAPI
CmpFreeParentSecurity(
    _In_ PSECURITY_DESCRIPTOR ParentSd)
{
    ExFreePoolWithTag(ParentSd, TAG_CM_ACL);
}

/*
 * The hive roots the kernel stamps (registry ACL plan R5): the root of a hive
 * linked at \REGISTRY\MACHINE\SAM or \REGISTRY\MACHINE\SECURITY, and of a user
 * hive linked at \REGISTRY\USER\<SID> (no _Classes suffix, not the system
 * profile, which is the DEFAULT hive). The kernel creates the SAM and SECURITY
 * hives at the first boot after setup, and userenv mounts a profile copied
 * from the Default User hive, whose root has no descriptor on purpose: their
 * roots have none of their own, and report (and are judged by) the policy
 * descriptor for their place. Expected rule: the one that place gets.
 */
static
BOOLEAN
CmpAclStampTarget(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _Out_ PULONG ExpectedRule)
{
    static const CHAR Classes[] = "_CLASSES";
    PCM_KEY_CONTROL_BLOCK Parent = Kcb->ParentKcb;
    ULONG SidBuffer[SECURITY_MAX_SID_SIZE / sizeof(ULONG)];
    ULONG Chars, i;

    /* \REGISTRY\<MACHINE|USER>\<hive>: three levels, nothing above \REGISTRY */
    if (!Parent || !Parent->ParentKcb || Parent->ParentKcb->ParentKcb)
        return FALSE;

    if (CmpAclNameMatches(Parent, "MACHINE", FALSE))
    {
        if (CmpAclNameMatches(Kcb, "SAM", FALSE))
        {
            *ExpectedRule = CmpAclRuleHiveRoot;
            return TRUE;
        }
        if (CmpAclNameMatches(Kcb, "SECURITY", FALSE))
        {
            *ExpectedRule = CmpAclRuleSamSecurity;
            return TRUE;
        }
        return FALSE;
    }

    if (!CmpAclNameMatches(Parent, "USER", FALSE) ||
        CmpAclNameMatches(Kcb, "S-1-5-18", FALSE))
    {
        return FALSE;
    }
    /* The classes hive of a user: its Windows root descriptor is not measured */
    Chars = CmpAclNameChars(Kcb);
    if (Chars > sizeof(Classes) - 1)
    {
        for (i = 0; i < sizeof(Classes) - 1; i++)
        {
            if (RtlUpcaseUnicodeChar(CmpAclNameChar(Kcb, Chars - (sizeof(Classes) - 1) + i)) != (WCHAR)Classes[i])
                break;
        }
        if (i == sizeof(Classes) - 1)
            return FALSE;
    }
    if (!CmpAclParseUserSid(Kcb, (PSID)SidBuffer))
        return FALSE;
    *ExpectedRule = CmpAclRuleUser;
    return TRUE;
}

/*
 * Store the root descriptor of a hive just linked (CmpLinkHiveToMaster) when
 * the root has none: the policy descriptor of its place (see CmpAclStampTarget),
 * which is what the root already reports and is judged by, so no access
 * decision and no query result of the root changes; the descriptor now goes
 * with the hive file. Keys below without a descriptor of their own inherit
 * from the stored root from then on (CmpGetEffectiveKeySd, rule 2), with the
 * same access for every token. Only while new keys get stored descriptors
 * (not in legacy mode, not while setup runs). Never fails the link.
 */
VOID
NTAPI
CmpAclStampHiveRoot(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb)
{
    ULONG Buffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    PSECURITY_DESCRIPTOR Sd, ToFree;
    PVOID PoolCopy;
    ULONG Rule, ExpectedRule;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PUNICODE_STRING Name;
    UNICODE_STRING EmptyName = RTL_CONSTANT_STRING(L"?");

    if (!Kcb || !CmpStoreKeySecurity())
        return;

    /* Only the boot hives and the profile service's loads (review F16) */
    if (Kcb->KeyHive && (CONTAINING_RECORD(Kcb->KeyHive, CMHIVE, Hive)->Flags & CMHIVE_FLAG_NO_ROOT_STAMP))
        return;

    CmpLockRegistry();
    CmpAcquireKcbLockExclusive(Kcb);
    if (!Kcb->Delete && Kcb->KeyHive && !Kcb->KeyHive->ReadOnly &&
        !(Kcb->KeyHive->HiveFlags & HIVE_VOLATILE) &&
        !(Kcb->ExtFlags & (CM_KCB_KEY_NON_EXIST | CM_KCB_READ_ONLY_KEY)) &&
        CmpAclStampTarget(Kcb, &ExpectedRule))
    {
        Sd = CmpGetEffectiveKeySd(Kcb, Buffer, sizeof(Buffer), &Rule, &ToFree, &PoolCopy, FALSE);
        if (Sd && Rule == ExpectedRule)
        {
            Status = CmpStampKeySecurity(Kcb, Sd);
            Name = CmpConstructName(Kcb);
            DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL,
                       "CM-ACL: hive root %wZ: %s descriptor stored (0x%lx)\n",
                       Name ? Name : &EmptyName, CmpAclRuleNames[Rule], Status);
            if (Name)
                CmpFree(Name, 0);
        }
        CmpAclFreeEffectiveSd(ToFree, PoolCopy);
    }
    CmpReleaseKcbLock(Kcb);
    CmpUnlockRegistry();

    if (!NT_SUCCESS(Status) && Status != STATUS_UNSUCCESSFUL && Status != STATUS_OBJECT_NAME_EXISTS)
        InterlockedIncrement(&CmpAclErrors);
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
 * The audit log's distinct entries per boot are bounded (CMP_ACL_MAX_ENTRIES).
 * A standard user can make denials at will (any key it may not open), so
 * without a share of its own it could use the whole budget up and keep later
 * denials (an administrator's, a service's, another user's) out of the log.
 * Tokens of users that are not administrators and not trusted service
 * principals (CmpAclTrustedSid) get at most CMP_ACL_USER_ENTRIES distinct
 * entries each per boot, and all such users together at most half of the
 * budget; the rest is kept for administrators, SYSTEM and services. Denials
 * over a share are counted (Denials, Dropped, ShareDropped), not logged.
 */
#define CMP_ACL_USER_ENTRIES        128
#define CMP_ACL_UNTRUSTED_ENTRIES   (CMP_ACL_MAX_ENTRIES / 2)
#define CMP_ACL_SHARE_SLOTS         64

static LONG64 CmpAclShareKey[CMP_ACL_SHARE_SLOTS];
static LONG CmpAclShareCount[CMP_ACL_SHARE_SLOTS];
static LONG CmpAclUntrustedEntries;
static LONG CmpAclShareDropped;

static
BOOLEAN
CmpAclWithinUserShare(
    _In_ PSECURITY_SUBJECT_CONTEXT Subject)
{
    ULONG64 Hash = 0xCBF29CE484222325ULL;
    PTOKEN Token;
    PSID UserSid;
    PUCHAR Bytes;
    ULONG Length, i, Slot;
    LONG64 Previous;
    BOOLEAN Trusted = TRUE;

    SeLockSubjectContext(Subject);
    Token = (PTOKEN)SeQuerySubjectContextToken(Subject);
    if (Token && Token->UserAndGroups && Token->UserAndGroupCount)
    {
        UserSid = Token->UserAndGroups[0].Sid;
        Trusted = CmpAclTrustedSid(UserSid);
        Bytes = UserSid;
        Length = RtlLengthSid(UserSid);
        for (i = 0; i < Length; i++)
            Hash = CmpAclMix(Hash, Bytes[i]);
    }
    SeUnlockSubjectContext(Subject);
    /* An administrator's token (it locks the token itself; the subject context keeps it referenced) */
    if (!Trusted && Token && SeTokenIsAdmin(Token))
        Trusted = TRUE;
    if (Trusted)
        return TRUE;

    if (Hash == 0)
        Hash = 1;
    /* The user's counter; with every slot taken the last one is shared by the rest */
    Slot = (ULONG)(Hash ^ (Hash >> 32)) & (CMP_ACL_SHARE_SLOTS - 1);
    for (i = 0; i < CMP_ACL_SHARE_SLOTS; i++)
    {
        Previous = InterlockedCompareExchange64(&CmpAclShareKey[(Slot + i) & (CMP_ACL_SHARE_SLOTS - 1)],
                                                (LONG64)Hash, 0);
        if (Previous == 0 || Previous == (LONG64)Hash)
            break;
    }
    Slot = (i == CMP_ACL_SHARE_SLOTS) ? (CMP_ACL_SHARE_SLOTS - 1) : ((Slot + i) & (CMP_ACL_SHARE_SLOTS - 1));

    if (InterlockedIncrement(&CmpAclShareCount[Slot]) > CMP_ACL_USER_ENTRIES)
    {
        InterlockedDecrement(&CmpAclShareCount[Slot]);
        return FALSE;
    }
    if (InterlockedIncrement(&CmpAclUntrustedEntries) > CMP_ACL_UNTRUSTED_ENTRIES)
    {
        InterlockedDecrement(&CmpAclUntrustedEntries);
        InterlockedDecrement(&CmpAclShareCount[Slot]);
        return FALSE;
    }
    return TRUE;
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

    /* A new distinct denial: within its user's share (CmpAclWithinUserShare) */
    if (!CmpAclWithinUserShare(Subject))
    {
        CmpAclReleaseSlot(Slot);
        InterlockedIncrement(&CmpAclShareDropped);
        CmpAclArmTimer();
        return;
    }
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

/*
 * Descriptors that only a non-administrator could have put there, and their
 * repair (boot self-check, CmpAclSystemHasFullControl and CmpAclBootHivesLoaded;
 * transition to enforcement, CmpAclTransition).
 *
 * While a boot runs without enforcement (audit or legacy mode, every install
 * released before enforcement became the default) every user can open every
 * key for WRITE_DAC and WRITE_OWNER and so store any DACL on it (the owner can
 * only become the user itself: SepCheckOwnerSid), and create keys anywhere
 * (owned by the user). Such a descriptor outlives the switch to enforcement
 * and keeps granting what it was planted to grant (write access to a service's
 * key, a Run key), or makes the boot self-check fall back to audit. Who stored a
 * descriptor is not recorded anywhere; what it grants is. A stored descriptor
 * of a machine key is "planted" (CMP_ACL_PLANTED_*) when
 *  - its owner is not a trusted principal (CmpAclTrustedSid), or
 *  - an allow ACE that applies to the key or is inherited by its subkeys grants
 *    a right that changes the key, its values, its subkeys or its descriptor to
 *    an untrusted principal, or is of an allow type the kernel never stores on
 *    a key, or
 *  - SYSTEM does not get full control from it.
 * The repair replaces it with the descriptor a key in that place gets on
 * Windows (CmpAclDefaultKeySd): inherited from the parent as for a key SYSTEM
 * creates, or the policy table's descriptor where the place has its own (hive
 * roots, EventLog, TaskCache, SAM\SAM, SECURITY). Key contents (values) cannot
 * be judged this way: a value a user wrote before enforcement looks like any
 * other.
 */
#define CMP_ACL_PLANTED_OWNER       0x1
#define CMP_ACL_PLANTED_WRITE       0x2
#define CMP_ACL_PLANTED_SYSTEM      0x4
#define CMP_ACL_PLANTED_ACETYPE     0x8
/* Boot self-check only: what an ancestor passes on shuts SYSTEM out, the key got its policy descriptor */
#define CMP_ACL_PLANTED_INHERIT     0x10
/* A symbolic link that a non-administrator created in a machine hive: deleted, not restamped */
#define CMP_ACL_PLANTED_LINK        0x20
/* Not a reason: the link was deleted (the walk's index of its parent moves back by one) */
#define CMP_ACL_LINK_DELETED        0x40

/* Restamped keys printed to the debug channel per boot (all are counted and logged to the file) */
#define CMP_ACL_RESTAMP_PRINT_MAX   256

/*
 * Deepest key the walks follow: every key that can be opened at all. A KCB is
 * created only for a key fewer than 512 levels below \REGISTRY
 * (CmpCreateKeyControlBlock), so no walk root has a key that can be opened
 * 512 or more levels below it. A smaller bound
 * left the keys below it unchecked (fail-open): while a boot did not enforce,
 * any user could create a chain that deep anywhere and plant there.
 */
#define CMP_ACL_WALK_MAX_DEPTH      512

/* AuditStats Transition: what the transition check did this boot */
#define CMP_ACL_TRANSITION_NONE     0   /* not enforcing, or before the machine hives were loaded */
#define CMP_ACL_TRANSITION_WALKED   1   /* the machine hives were checked and the marker written */
#define CMP_ACL_TRANSITION_TRUSTED  2   /* the marker says enforcement ran since the last check */
#define CMP_ACL_TRANSITION_SETUP    3   /* setup runs: checked after it */
#define CMP_ACL_TRANSITION_NOMARKER 4   /* checked, but the marker could not be written (checked again next boot) */

static LONG CmpAclRestamped;
static LONG CmpAclRestampUserOwned;
static LONG CmpAclRestampFailed;
static LONG CmpAclRestampPrinted;
static ULONG CmpAclTransitionState;
static ULONG CmpAclTransitionMs;     /* how long the check took (boot time it cost) */

/*
 * Principals a standard user cannot be or become: SYSTEM, LocalService,
 * NetworkService, the SERVICE group, the builtin groups only administrators can
 * add members to (all of S-1-5-32 but Users, Guests and Remote Desktop Users),
 * service and virtual-account SIDs (S-1-5-80, S-1-5-83, S-1-5-90, S-1-5-96),
 * the local Administrator account (RID 500), and the creator placeholders
 * (CREATOR OWNER and CREATOR GROUP never match a token; OWNER RIGHTS is the
 * owner, judged as the owner). Everything else (Everyone, Authenticated
 * Users, INTERACTIVE, RESTRICTED, logon SIDs, local and domain accounts and
 * groups, application packages and capabilities) is untrusted.
 */
static
BOOLEAN
CmpAclTrustedSid(
    _In_ PSID Sid)
{
    static const SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    static const SID_IDENTIFIER_AUTHORITY CreatorAuthority = {SECURITY_CREATOR_SID_AUTHORITY};
    PSID_IDENTIFIER_AUTHORITY Authority = RtlIdentifierAuthoritySid(Sid);
    UCHAR Count = *RtlSubAuthorityCountSid(Sid);
    ULONG First;

    if (Count == 0)
        return FALSE;
    First = *RtlSubAuthoritySid(Sid, 0);

    if (RtlEqualMemory(Authority, &CreatorAuthority, sizeof(CreatorAuthority)))
    {
        return Count == 1 &&
               (First == SECURITY_CREATOR_OWNER_RID || First == SECURITY_CREATOR_GROUP_RID ||
                First == 4 /* SECURITY_CREATOR_OWNER_RIGHTS_RID */);
    }
    if (!RtlEqualMemory(Authority, &NtAuthority, sizeof(NtAuthority)))
        return FALSE;

    switch (First)
    {
        case SECURITY_LOCAL_SYSTEM_RID:         /* S-1-5-18 */
        case SECURITY_LOCAL_SERVICE_RID:        /* S-1-5-19 */
        case SECURITY_NETWORK_SERVICE_RID:      /* S-1-5-20 */
        case SECURITY_SERVICE_RID:              /* S-1-5-6 */
            return Count == 1;

        case SECURITY_BUILTIN_DOMAIN_RID:       /* S-1-5-32-x */
            if (Count != 2)
                return FALSE;
            switch (*RtlSubAuthoritySid(Sid, 1))
            {
                case DOMAIN_ALIAS_RID_USERS:
                case DOMAIN_ALIAS_RID_GUESTS:
                case DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS:
                    return FALSE;
                default:
                    return TRUE;
            }

        case 80:                                /* S-1-5-80-x: service SIDs, TrustedInstaller */
        case 83:                                /* S-1-5-83-x: virtual machines */
        case 90:                                /* S-1-5-90-x: window manager */
        case 96:                                /* S-1-5-96-x: font driver host */
            return Count >= 2;

        case SECURITY_NT_NON_UNIQUE:            /* S-1-5-21-a-b-c-RID */
            return Count == 5 && *RtlSubAuthoritySid(Sid, 4) == DOMAIN_USER_RID_ADMIN;

        default:
            return FALSE;
    }
}

/*
 * Judge a stored descriptor (a validated copy): 0, or the CMP_ACL_PLANTED_*
 * reasons. *Owner points into Sd (NULL if it has none).
 */
static
ULONG
CmpAclSdPlanted(
    _In_ PSECURITY_DESCRIPTOR Sd,
    _Out_ PSID *Owner)
{
    static const ACCESS_MASK Write = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK |
                                     DELETE | WRITE_DAC | WRITE_OWNER | MAXIMUM_ALLOWED;
    BOOLEAN Present, Defaulted;
    PACL Dacl;
    PACE_HEADER Ace;
    ACCESS_MASK Mask;
    ULONG Reasons = 0, i;

    *Owner = NULL;
    if (!NT_SUCCESS(RtlGetOwnerSecurityDescriptor(Sd, Owner, &Defaulted)) || !*Owner ||
        !CmpAclTrustedSid(*Owner))
    {
        Reasons |= CMP_ACL_PLANTED_OWNER;
    }

    if (NT_SUCCESS(RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted)) && Present)
    {
        if (!Dacl)
        {
            /* A NULL DACL grants everything to everyone */
            Reasons |= CMP_ACL_PLANTED_WRITE;
        }
        else
        {
            for (i = 0; i < Dacl->AceCount; i++)
            {
                if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)))
                {
                    Reasons |= CMP_ACL_PLANTED_ACETYPE;
                    break;
                }
                switch (Ace->AceType)
                {
                    case ACCESS_DENIED_ACE_TYPE:
                    case ACCESS_DENIED_OBJECT_ACE_TYPE:
                    case ACCESS_DENIED_CALLBACK_ACE_TYPE:
                    case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                        /* A deny never grants; one that shuts SYSTEM out is found below */
                        continue;
                    case ACCESS_ALLOWED_ACE_TYPE:
                        break;
                    default:
                        Reasons |= CMP_ACL_PLANTED_ACETYPE;
                        continue;
                }
                /* What applies to the key, or flows to its subkeys */
                if ((Ace->AceFlags & INHERIT_ONLY_ACE) && !(Ace->AceFlags & CONTAINER_INHERIT_ACE))
                    continue;
                Mask = ((PACCESS_ALLOWED_ACE)Ace)->Mask;
                RtlMapGenericMask(&Mask, &CmpKeyObjectType->TypeInfo.GenericMapping);
                if ((Mask & Write) && !CmpAclTrustedSid((PSID)&((PACCESS_ALLOWED_ACE)Ace)->SidStart))
                    Reasons |= CMP_ACL_PLANTED_WRITE;
            }
        }
    }

    if (!CmpAclSdGivesSystemFullControl(Sd))
        Reasons |= CMP_ACL_PLANTED_SYSTEM;
    return Reasons;
}

/* Record a key whose stored descriptor was replaced: counted, printed (capped) and logged */
static
VOID
CmpAclRecordRestamp(
    _In_ PCUNICODE_STRING KeyName,
    _In_ ULONG Reasons,
    _In_opt_ PSID OldOwner,
    _In_ NTSTATUS Status)
{
    PCMP_ACL_ENTRY Entry;
    UNICODE_STRING Owner = {0};
    WCHAR OwnerBuffer[96];
    USHORT KeyChars;
    PWCHAR p;

    if (NT_SUCCESS(Status))
        InterlockedIncrement(&CmpAclRestamped);
    else
        InterlockedIncrement(&CmpAclRestampFailed);
    if (Reasons & CMP_ACL_PLANTED_OWNER)
        InterlockedIncrement(&CmpAclRestampUserOwned);

    RtlInitEmptyUnicodeString(&Owner, OwnerBuffer, sizeof(OwnerBuffer));
    if (!OldOwner || !NT_SUCCESS(RtlConvertSidToUnicodeString(&Owner, OldOwner, FALSE)))
        Owner.Length = 0;

    if (InterlockedIncrement(&CmpAclRestampPrinted) <= CMP_ACL_RESTAMP_PRINT_MAX)
    {
        DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL,
                   "CM-ACL: %wZ: stored descriptor replaced (reasons 0x%lx, owner was %wZ): 0x%lx\n",
                   KeyName, Reasons, &Owner, Status);
    }

    /* The file log: one entry per key, never deduplicated, within the boot's entry budget */
    if (InterlockedIncrement(&CmpAclEntryCount) > CMP_ACL_MAX_ENTRIES)
    {
        InterlockedDecrement(&CmpAclEntryCount);
        InterlockedExchange(&CmpAclSaturated, 1);
        return;
    }
    KeyChars = (USHORT)min(KeyName->Length / sizeof(WCHAR), CMP_ACL_MAX_KEY_CHARS);
    Entry = ExAllocatePoolWithTag(PagedPool,
                                  FIELD_OFFSET(CMP_ACL_ENTRY, Strings) + (KeyChars + RTL_NUMBER_OF(OwnerBuffer)) * sizeof(WCHAR),
                                  TAG_CM_ACL);
    if (!Entry)
    {
        InterlockedDecrement(&CmpAclEntryCount);
        InterlockedIncrement(&CmpAclDropped);
        return;
    }
    RtlZeroMemory(Entry, FIELD_OFFSET(CMP_ACL_ENTRY, Strings));
    Entry->Id = (ULONG)InterlockedIncrement(&CmpAclNextId);
    Entry->Slot = MAXULONG;
    Entry->Operation = CM_REGACL_OP_RESTAMP;
    Entry->Rule = CmpAclRuleCell;
    Entry->Desired = Reasons;
    Entry->ShadowStatus = Status;
    KeQuerySystemTime(&Entry->Time);
    p = CmpAclPutString(Entry->Strings, KeyName->Buffer, KeyChars);
    Entry->KeyChars = KeyChars;
    Entry->UserChars = Owner.Length / sizeof(WCHAR);
    CmpAclPutString(p, Owner.Buffer, Entry->UserChars);
    ExInterlockedPushEntrySList(&CmpAclQueue, &Entry->QueueEntry, &CmpAclQueueLock);
    CmpAclArmTimer();
}

/*
 * The descriptor the key gets back (pool, TAG_CM_ACL): the policy descriptor
 * where its place has one of its own (a hive root, or a key whose policy rule
 * differs from its parent's: EventLog, TaskCache, SAM\SAM, SECURITY,
 * HKU\.DEFAULT), else the parent's effective descriptor inherited as for a
 * key SYSTEM creates. NULL without memory. The caller holds the registry lock.
 */
static
PSECURITY_DESCRIPTOR
CmpAclDefaultKeySd(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb)
{
    ULONG Buffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    ULONG ParentBuffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    PCM_KEY_CONTROL_BLOCK Parent = Kcb->ParentKcb;
    PSECURITY_DESCRIPTOR Sd, ParentSd, NewSd = NULL, Copy = NULL;
    ULONG Rule, ParentRule, Length;
    NTSTATUS Status;

    Sd = CmpAclSynthesizeSd(Kcb, Buffer, sizeof(Buffer), &Rule);
    if (Parent)
        CmpAclSynthesizeSd(Parent, ParentBuffer, sizeof(ParentBuffer), &ParentRule);
    if (!Parent || Parent->KeyHive != Kcb->KeyHive || Rule != ParentRule)
    {
        if (!Sd)
            return NULL;
        Length = RtlLengthSecurityDescriptor(Sd);
        Copy = ExAllocatePoolWithTag(PagedPool, Length, TAG_CM_ACL);
        if (Copy)
            RtlCopyMemory(Copy, Sd, Length);
        return Copy;
    }

    CmpAcquireKcbLockShared(Parent);
    ParentSd = CmpCaptureKeySecurity(Parent);
    CmpReleaseKcbLock(Parent);
    if (!ParentSd)
        return NULL;
    Status = SeAssignSecurityEx(ParentSd,
                                NULL,
                                &NewSd,
                                NULL,
                                TRUE,
                                (((PISECURITY_DESCRIPTOR)ParentSd)->Control & SE_DACL_AUTO_INHERITED) ?
                                    SEF_DACL_AUTO_INHERIT : 0,
                                &CmpAclSystemSubject,
                                &CmpKeyObjectType->TypeInfo.GenericMapping,
                                PagedPool);
    CmpFreeParentSecurity(ParentSd);
    if (!NT_SUCCESS(Status))
        return NULL;
    Length = RtlLengthSecurityDescriptor(NewSd);
    Copy = ExAllocatePoolWithTag(PagedPool, Length, TAG_CM_ACL);
    if (Copy)
        RtlCopyMemory(Copy, NewSd, Length);
    SeDeassignSecurity(&NewSd);
    return Copy;
}

/*
 * Look at the stored descriptor of the key behind Key (a kernel handle opened
 * with WRITE_DAC, WRITE_OWNER and ACCESS_SYSTEM_SECURITY) and replace it when
 * it is planted (above), or whatever it is with Force (the boot self-check's
 * repair). With OwnerOnly, only a descriptor whose owner is not trusted counts
 * as planted (a key a non-administrator created): a descriptor that an
 * administrator's installer stored, owner Administrators, is kept even when it
 * lets users write (some programs grant that on their own keys on purpose). A
 * key without a stored descriptor is left alone (it inherits). Returns the
 * reasons found (0: nothing done).
 */
static
ULONG
CmpAclCheckStoredKey(
    _In_ HANDLE Key,
    _In_ BOOLEAN Force,
    _In_ BOOLEAN OwnerOnly)
{
    ULONG Buffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    ULONG OwnerBuffer[SECURITY_MAX_SID_SIZE / sizeof(ULONG)];
    PCM_KEY_BODY KeyBody;
    PCM_KEY_CONTROL_BLOCK Kcb;
    PSECURITY_DESCRIPTOR Sd, NewSd = NULL;
    PUNICODE_STRING Name = NULL;
    PVOID PoolCopy = NULL;
    PSID Owner = NULL;
    ULONG Reasons = 0;
    BOOLEAN Link = FALSE;
    NTSTATUS Status;

    if (!NT_SUCCESS(ObReferenceObjectByHandle(Key, 0, CmpKeyObjectType, KernelMode, (PVOID *)&KeyBody, NULL)))
        return 0;

    CmpLockRegistry();
    Kcb = KeyBody->KeyControlBlock;
    if (Kcb && !Kcb->Delete)
    {
        CmpAcquireKcbLockShared(Kcb);
        Link = (Kcb->Flags & KEY_SYM_LINK) != 0;
        Sd = CmpAclCopyStoredSd(Kcb, Buffer, sizeof(Buffer), &PoolCopy, FALSE);
        if (Sd)
        {
            Reasons = CmpAclSdPlanted(Sd, &Owner);
            if (OwnerOnly && !(Reasons & CMP_ACL_PLANTED_OWNER))
                Reasons = 0;
            /* The boot self-check's repair: this descriptor is what shuts SYSTEM out of a boot key */
            if (Force && !Reasons)
                Reasons = CMP_ACL_PLANTED_SYSTEM | CMP_ACL_PLANTED_INHERIT;
            if (Owner && RtlLengthSid(Owner) <= sizeof(OwnerBuffer))
            {
                RtlCopySid(sizeof(OwnerBuffer), (PSID)OwnerBuffer, Owner);
                Owner = (PSID)OwnerBuffer;
            }
            else
            {
                Owner = NULL;
            }
        }
        CmpAclFreeEffectiveSd(NULL, PoolCopy);
        CmpReleaseKcbLock(Kcb);
        /*
         * A symbolic link owned by a non-administrator: no Windows component lets a
         * standard user create one in a machine hive (KEY_CREATE_LINK on the parent),
         * so it was made while a boot did not enforce. A new descriptor would leave
         * its target (a value, SymbolicLinkValue) as the user chose it, for example a
         * key of the user's own hive that every program opening the link's path then
         * reads, and the user still writes. It is deleted instead.
         */
        if (Link && !Force && (Reasons & CMP_ACL_PLANTED_OWNER))
            Reasons |= CMP_ACL_PLANTED_LINK;
        if (Reasons)
        {
            if (!(Reasons & CMP_ACL_PLANTED_LINK))
                NewSd = CmpAclDefaultKeySd(Kcb);
            Name = CmpConstructName(Kcb);
        }
    }
    CmpUnlockRegistry();
    ObDereferenceObject(KeyBody);

    if (!Reasons)
        return 0;

    if (Reasons & CMP_ACL_PLANTED_LINK)
    {
        /* The handle was opened with OBJ_OPENLINK: it is the link key itself */
        Status = ZwDeleteKey(Key);
        if (NT_SUCCESS(Status))
            Reasons |= CMP_ACL_LINK_DELETED;
        if (Name)
        {
            CmpAclRecordRestamp(Name, Reasons & ~CMP_ACL_LINK_DELETED, Owner, Status);
            CmpFree(Name, 0);
        }
        return Reasons;
    }

    Status = STATUS_INSUFFICIENT_RESOURCES;
    if (NewSd)
    {
        Status = ZwSetSecurityObject(Key,
                                     OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                     DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
                                     NewSd);
        ExFreePoolWithTag(NewSd, TAG_CM_ACL);
    }
    if (Name)
    {
        CmpAclRecordRestamp(Name, Reasons, Owner, Status);
        CmpFree(Name, 0);
    }
    return Reasons;
}

#define CMP_ACL_RESET_ACCESS (KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | READ_CONTROL | WRITE_DAC | \
                              WRITE_OWNER | ACCESS_SYSTEM_SECURITY | DELETE)

/*
 * Check every key from the key at Path down (or only that key): stored
 * descriptors that are planted are replaced, top-down, so that a key's
 * replacement inherits from an already repaired parent. Links are looked at
 * (their own descriptor) but not followed; one a non-administrator owns is
 * deleted (CmpAclCheckStoredKey). OwnerOnly: only keys a non-administrator
 * owns count (see CmpAclCheckStoredKey). Boot only; kernel handles.
 */
static
VOID
CmpAclWalk(
    _In_ PCWSTR Path,
    _In_ BOOLEAN Subtree,
    _In_ BOOLEAN OwnerOnly)
{
    typedef struct _CMP_ACL_WALK_LEVEL
    {
        HANDLE Key;
        ULONG Index;
    } CMP_ACL_WALK_LEVEL;
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    CMP_ACL_WALK_LEVEL *Stack;
    ULONG Depth = 0, Length;
    UCHAR InfoBuffer[sizeof(KEY_BASIC_INFORMATION) + 256 * sizeof(WCHAR)];
    PKEY_BASIC_INFORMATION Info = (PKEY_BASIC_INFORMATION)InfoBuffer;
    HANDLE Child;
    NTSTATUS Status;

    Stack = ExAllocatePoolWithTag(PagedPool, CMP_ACL_WALK_MAX_DEPTH * sizeof(*Stack), TAG_CM_ACL);
    if (!Stack)
    {
        InterlockedIncrement(&CmpAclErrors);
        return;
    }

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_OPENLINK, NULL, NULL);
    Status = ZwOpenKey(&Stack[0].Key, CMP_ACL_RESET_ACCESS, &Attributes);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Stack, TAG_CM_ACL);
        return;
    }
    CmpAclCheckStoredKey(Stack[0].Key, FALSE, OwnerOnly);
    Stack[0].Index = 0;
    if (!Subtree)
    {
        ZwClose(Stack[0].Key);
        ExFreePoolWithTag(Stack, TAG_CM_ACL);
        return;
    }

    for (;;)
    {
        Status = ZwEnumerateKey(Stack[Depth].Key, Stack[Depth].Index, KeyBasicInformation,
                                Info, sizeof(InfoBuffer) - sizeof(WCHAR), &Length);
        if (!NT_SUCCESS(Status))
        {
            /* Done with this key (or its subkey's name does not fit, which no name does) */
            ZwClose(Stack[Depth].Key);
            if (Depth == 0)
                break;
            Depth--;
            continue;
        }
        Stack[Depth].Index++;

        Name.Buffer = Info->Name;
        Name.Length = Name.MaximumLength = (USHORT)Info->NameLength;
        InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_OPENLINK,
                                   Stack[Depth].Key, NULL);
        Status = ZwOpenKey(&Child, CMP_ACL_RESET_ACCESS, &Attributes);
        if (!NT_SUCCESS(Status))
            continue;
        if (CmpAclCheckStoredKey(Child, FALSE, OwnerOnly) & CMP_ACL_LINK_DELETED)
        {
            /* A deleted link: the next subkey now has its index */
            ZwClose(Child);
            Stack[Depth].Index--;
            continue;
        }
        if (Depth + 1 >= CMP_ACL_WALK_MAX_DEPTH)
        {
            ZwClose(Child);
            continue;
        }
        Depth++;
        Stack[Depth].Key = Child;
        Stack[Depth].Index = 0;
    }
    ExFreePoolWithTag(Stack, TAG_CM_ACL);
}

/*
 * Store the policy descriptor of its place (CmpAclSynthesizeSd: the Windows
 * one, which gives SYSTEM full control) on the key at Path, whatever its
 * ancestors pass on. Boot self-check only (CmpAclRepairSystemAccess).
 */
static
VOID
CmpAclStampPolicySd(
    _In_ PCUNICODE_STRING Path)
{
    ULONG Buffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    OBJECT_ATTRIBUTES Attributes;
    PCM_KEY_BODY KeyBody;
    PCM_KEY_CONTROL_BLOCK Kcb;
    PSECURITY_DESCRIPTOR Sd, Copy = NULL;
    PUNICODE_STRING Name = NULL;
    HANDLE Key;
    ULONG Rule;
    NTSTATUS Status;

    /* The object the self-check judged (links followed, as there) */
    InitializeObjectAttributes(&Attributes, (PUNICODE_STRING)Path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&Key, CMP_ACL_RESET_ACCESS, &Attributes)))
        return;
    if (!NT_SUCCESS(ObReferenceObjectByHandle(Key, 0, CmpKeyObjectType, KernelMode, (PVOID *)&KeyBody, NULL)))
    {
        ZwClose(Key);
        return;
    }

    CmpLockRegistry();
    Kcb = KeyBody->KeyControlBlock;
    if (Kcb && !Kcb->Delete)
    {
        Sd = CmpAclSynthesizeSd(Kcb, Buffer, sizeof(Buffer), &Rule);
        if (Sd)
        {
            Copy = ExAllocatePoolWithTag(PagedPool, RtlLengthSecurityDescriptor(Sd), TAG_CM_ACL);
            if (Copy)
                RtlCopyMemory(Copy, Sd, RtlLengthSecurityDescriptor(Sd));
        }
        Name = CmpConstructName(Kcb);
    }
    CmpUnlockRegistry();
    ObDereferenceObject(KeyBody);

    Status = STATUS_INSUFFICIENT_RESOURCES;
    if (Copy)
    {
        Status = ZwSetSecurityObject(Key,
                                     OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                     DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
                                     Copy);
        ExFreePoolWithTag(Copy, TAG_CM_ACL);
    }
    ZwClose(Key);
    if (Name)
    {
        CmpAclRecordRestamp(Name, CMP_ACL_PLANTED_SYSTEM | CMP_ACL_PLANTED_INHERIT, NULL, Status);
        CmpFree(Name, 0);
    }
}

/*
 * The name of the key Level levels above the key behind Key (0: the key
 * itself) if it has a stored descriptor, else NULL (CmpFree it).
 */
static
PUNICODE_STRING
CmpAclStoredAncestorName(
    _In_ HANDLE Key,
    _In_ ULONG Level)
{
    ULONG Buffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    PCM_KEY_BODY KeyBody;
    PCM_KEY_CONTROL_BLOCK Walk;
    PUNICODE_STRING Name = NULL;
    PVOID PoolCopy;
    ULONG i;

    if (!NT_SUCCESS(ObReferenceObjectByHandle(Key, 0, CmpKeyObjectType, KernelMode, (PVOID *)&KeyBody, NULL)))
        return NULL;
    CmpLockRegistry();
    Walk = KeyBody->KeyControlBlock;
    for (i = 0; Walk && i < Level; i++)
        Walk = Walk->ParentKcb;
    if (Walk && !Walk->Delete)
    {
        CmpAcquireKcbLockShared(Walk);
        if (CmpAclCopyStoredSd(Walk, Buffer, sizeof(Buffer), &PoolCopy, FALSE))
        {
            CmpAclFreeEffectiveSd(NULL, PoolCopy);
            Name = CmpConstructName(Walk);
        }
        CmpReleaseKcbLock(Walk);
    }
    CmpUnlockRegistry();
    ObDereferenceObject(KeyBody);
    return Name;
}

/* Replace the stored descriptor of the key named Name by its default (CmpAclDefaultKeySd), whatever it is */
static
BOOLEAN
CmpAclForceDefault(
    _In_ PUNICODE_STRING Name)
{
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key;
    ULONG Reasons;

    InitializeObjectAttributes(&Attributes, Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_OPENLINK, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&Key, CMP_ACL_RESET_ACCESS, &Attributes)))
        return FALSE;
    Reasons = CmpAclCheckStoredKey(Key, TRUE, FALSE);
    ZwClose(Key);
    return Reasons != 0;
}

/*
 * The boot self-check found that SYSTEM does not get full control of the key
 * at Path. What it is judged by is its own stored descriptor, or what the
 * nearest ancestor with a stored descriptor passes on. Replace the key's own
 * descriptor by its default (inherited from its parent, or the policy one of
 * its place); if that still shuts SYSTEM out, the fault is an ancestor's:
 * replace the nearest stored ancestor's (the next one up each round), then
 * every stored descriptor below it down to the key again, top-down, so that
 * each inherits from a repaired parent. Such an ancestor's own descriptor can
 * be sound by the planted rule (a trusted owner, no untrusted grant, SYSTEM has
 * full control of the ancestor itself) and still pass nothing on, or deny its
 * subkeys to SYSTEM: falling back to audit for it handed whoever could store
 * it while a boot did not enforce the switch out of enforcement. An
 * administrator's own descriptor that does this to a boot key is replaced by
 * the same rule: the boot would not work with it either. If nothing of that
 * helps, the key gets the policy descriptor of its place.
 */
static
VOID
CmpAclRepairSystemAccess(
    _In_ PCUNICODE_STRING Path)
{
    ULONG Buffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    OBJECT_ATTRIBUTES Attributes;
    PCM_KEY_BODY KeyBody;
    PCM_KEY_CONTROL_BLOCK Kcb, Walk;
    PSECURITY_DESCRIPTOR Sd, ToFree;
    PUNICODE_STRING Name;
    PVOID PoolCopy;
    HANDLE Key;
    ULONG Rule, Round, Level, Depth, Above = 0;
    BOOLEAN Lacks;

    /* The object the self-check judged (links followed, as there); the handle keeps its ancestors */
    InitializeObjectAttributes(&Attributes, (PUNICODE_STRING)Path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attributes)))
        return;

    for (Round = 0; Round <= CMP_ACL_WALK_MAX_DEPTH; Round++)
    {
        /* Does SYSTEM still lack full control, and how deep is the key */
        Lacks = FALSE;
        Depth = 0;
        if (!NT_SUCCESS(ObReferenceObjectByHandle(Key, 0, CmpKeyObjectType, KernelMode, (PVOID *)&KeyBody, NULL)))
            break;
        CmpLockRegistry();
        Kcb = KeyBody->KeyControlBlock;
        if (Kcb && !Kcb->Delete)
        {
            for (Walk = Kcb->ParentKcb; Walk; Walk = Walk->ParentKcb)
                Depth++;
            CmpAcquireKcbLockShared(Kcb);
            Sd = CmpGetEffectiveKeySd(Kcb, Buffer, sizeof(Buffer), &Rule, &ToFree, &PoolCopy, FALSE);
            Lacks = Sd && !CmpAclSdGivesSystemFullControl(Sd);
            CmpAclFreeEffectiveSd(ToFree, PoolCopy);
            CmpReleaseKcbLock(Kcb);
        }
        CmpUnlockRegistry();
        ObDereferenceObject(KeyBody);
        if (!Lacks)
        {
            ZwClose(Key);
            return;
        }

        if (Round > 0)
        {
            /* The nearest stored ancestor above the ones replaced so far */
            Name = NULL;
            for (Level = Above + 1; Level <= Depth && !Name; Level++)
                Name = CmpAclStoredAncestorName(Key, Level);
            if (!Name)
                break;
            Above = Level - 1;
            CmpAclForceDefault(Name);
            CmpFree(Name, 0);
        }

        /* Below it (or from the parent in the first round) down to the key, top-down */
        for (Level = Above; Level-- > 0;)
        {
            Name = CmpAclStoredAncestorName(Key, Level);
            if (Name)
            {
                CmpAclForceDefault(Name);
                CmpFree(Name, 0);
            }
        }
        if (Round == 0)
        {
            Name = CmpAclStoredAncestorName(Key, 0);
            if (Name)
            {
                CmpAclForceDefault(Name);
                CmpFree(Name, 0);
            }
        }
    }
    ZwClose(Key);

    /* Nothing of that helped (a policy descriptor always gives SYSTEM full control) */
    CmpAclStampPolicySd(Path);
}

/*
 * The marker that enforcement has protected the machine hives since they were
 * last checked: \SystemRoot\System32\Config\RegAclEnforced, created by the
 * kernel after the check with a descriptor only SYSTEM and Administrators can
 * change, and deleted by every boot that does not enforce. It counts only with
 * a trusted owner and a DACL that grants no untrusted principal a change
 * (CmpAclFileSdTrusted): a standard user can neither create a file with such
 * an owner nor change the DACL of one, whatever the directory allows. On a
 * volume without file security no file passes, and the check runs at every
 * boot.
 */
static UNICODE_STRING CmpAclMarkerName = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\Config\\RegAclEnforced");

static
BOOLEAN
CmpAclFileSdTrusted(
    _In_ PSECURITY_DESCRIPTOR Sd)
{
    static const ACCESS_MASK Write = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                                     FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | MAXIMUM_ALLOWED |
                                     GENERIC_WRITE | GENERIC_ALL;
    BOOLEAN Present, Defaulted;
    PSID Owner;
    PACL Dacl;
    PACE_HEADER Ace;
    ULONG i;

    if (!NT_SUCCESS(RtlGetOwnerSecurityDescriptor(Sd, &Owner, &Defaulted)) || !Owner || !CmpAclTrustedSid(Owner))
        return FALSE;
    if (!NT_SUCCESS(RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted)) || !Present || !Dacl)
        return FALSE;
    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)))
            return FALSE;
        if (Ace->AceType == ACCESS_DENIED_ACE_TYPE)
            continue;
        if (Ace->AceType != ACCESS_ALLOWED_ACE_TYPE)
            return FALSE;
        if (Ace->AceFlags & INHERIT_ONLY_ACE)
            continue;
        if ((((PACCESS_ALLOWED_ACE)Ace)->Mask & Write) &&
            !CmpAclTrustedSid((PSID)&((PACCESS_ALLOWED_ACE)Ace)->SidStart))
        {
            return FALSE;
        }
    }
    return TRUE;
}

static
BOOLEAN
CmpAclMarkerPresent(VOID)
{
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE File;
    PSECURITY_DESCRIPTOR Sd;
    ULONG Length = 0;
    BOOLEAN Trusted = FALSE;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, &CmpAclMarkerName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenFile(&File, READ_CONTROL | SYNCHRONIZE, &Attributes, &Iosb, FILE_SHARE_READ,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Status = ZwQuerySecurityObject(File, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0, &Length);
    if (Status == STATUS_BUFFER_TOO_SMALL && Length && Length <= 0x10000)
    {
        Sd = ExAllocatePoolWithTag(PagedPool, Length, TAG_CM_ACL);
        if (Sd)
        {
            if (NT_SUCCESS(ZwQuerySecurityObject(File, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                                 Sd, Length, &Length)) &&
                RtlValidRelativeSecurityDescriptor(Sd, Length, 0))
            {
                Trusted = CmpAclFileSdTrusted(Sd);
            }
            ExFreePoolWithTag(Sd, TAG_CM_ACL);
        }
    }
    ZwClose(File);
    return Trusted;
}

static
VOID
CmpAclMarkerDelete(VOID)
{
    OBJECT_ATTRIBUTES Attributes;

    InitializeObjectAttributes(&Attributes, &CmpAclMarkerName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ZwDeleteFile(&Attributes);
}

static
BOOLEAN
CmpAclMarkerWrite(VOID)
{
    static const CHAR Text[] = "Registry key security was enforced on the machine hives since this file was written.\r\n";
    CMP_ACL_SD_SPEC Spec =
    {
        CmpAclSidSystem, CmpAclSidSystem, SE_DACL_PROTECTED, 2,
        {
            { 0, CmpAclSidSystem, FILE_ALL_ACCESS },
            { 0, CmpAclSidAdmins, FILE_ALL_ACCESS },
        }
    };
    UCHAR SdBuffer[CMP_ACL_SD_BUFFER];
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE File;
    NTSTATUS Status;

    if (!CmpAclBuildSd(&Spec, NULL, SdBuffer, sizeof(SdBuffer)))
        return FALSE;

    /* A file of that name that is not ours goes first (its descriptor would stay with a supersede) */
    CmpAclMarkerDelete();
    InitializeObjectAttributes(&Attributes, &CmpAclMarkerName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, SdBuffer);
    Status = ZwCreateFile(&File, FILE_WRITE_DATA | SYNCHRONIZE, &Attributes, &Iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                          0, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH,
                          NULL, 0);
    if (!NT_SUCCESS(Status))
        return FALSE;
    ZwWriteFile(File, NULL, NULL, NULL, &Iosb, (PVOID)Text, sizeof(Text) - 1, NULL, NULL);
    ZwClose(File);

    /* It counts only if the volume kept the descriptor */
    return CmpAclMarkerPresent();
}

/*
 * The transition to enforcement: the first boot that enforces after boots
 * that did not (or after the marker went missing) checks the stored
 * descriptors of the machine hives' security-relevant keys and replaces the
 * planted ones (see above). The whole SYSTEM, SAM, SECURITY and DEFAULT hives;
 * of SOFTWARE the keys whose contents decide what runs, with what rights, or
 * how security is configured. Programs' own keys elsewhere in SOFTWARE may
 * carry grants their installers made, as on Windows: there only keys that a
 * non-administrator owns are replaced (created while nothing was enforced,
 * for example HKLM\SOFTWARE\<vendor> before an administrator installed that
 * vendor's program, which then reads its settings from a key the user still
 * writes). Every key replaced is logged (op "restamp", the old owner as
 * "user").
 */
static
VOID
CmpAclTransition(VOID)
{
    static const struct
    {
        PCWSTR Path;
        BOOLEAN Subtree;
    } Keys[] =
    {
        { L"\\Registry\\Machine\\SYSTEM", TRUE },
        { L"\\Registry\\Machine\\SAM", TRUE },
        { L"\\Registry\\Machine\\SECURITY", TRUE },
        { L"\\Registry\\User\\.DEFAULT", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE", FALSE },
        { L"\\Registry\\Machine\\SOFTWARE\\Classes", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Policies", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\ReactOS", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft", FALSE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows", FALSE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT", FALSE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Active Setup", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Command Processor", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\NetSh", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Ole", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Rpc", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\.NETFramework", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Script Host", TRUE },
        /*
         * Also what decides what is trusted or loaded into other users' and the
         * system's processes: the machine certificate stores (crypt32's
         * LocalMachine Root, CA, TrustedPublisher, Disallowed...), WinRT
         * activatable classes (DllPath), text services (CTF TIP), the mail
         * client MAPI loads (Clients\Mail DLLPath), and Windows Error Reporting
         * (LocalDumps: where and whose dumps are written).
         */
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\SystemCertificates", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\EnterpriseCertificates", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\WindowsRuntime", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\CTF", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Clients", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node", FALSE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Clients", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Classes", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Policies", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft", FALSE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows", FALSE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT", FALSE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\Command Processor", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\Ole", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\WindowsRuntime", TRUE },
        { L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\CTF", TRUE },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Keys); i++)
        CmpAclWalk(Keys[i].Path, Keys[i].Subtree, FALSE);

    /* The rest of SOFTWARE (and again the parts above, which have nothing left to find): keys a non-administrator owns */
    CmpAclWalk(L"\\Registry\\Machine\\SOFTWARE", TRUE, TRUE);
}

/*
 * The machine hives other than SYSTEM are linked (NtInitializeRegistry, before
 * any process but smss runs), and the file system is there: the self-check of
 * their keys that SYSTEM needs (the rule of the SYSTEM hive's at CmInitSystem1:
 * a stored descriptor that keeps SYSTEM from full control is replaced, and
 * only if that fails does the boot fall back to audit), then the transition
 * check. Not for a setup boot (text mode: the hives are setup's own).
 */
VOID
NTAPI
CmpAclBootHivesLoaded(
    _In_ BOOLEAN SetupBoot)
{
    static const PCWSTR Keys[] =
    {
        L"\\Registry\\Machine\\SOFTWARE",
        L"\\Registry\\Machine\\SOFTWARE\\Classes",
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft",
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows",
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT",
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
        L"\\Registry\\Machine\\SAM",
        L"\\Registry\\Machine\\SAM\\SAM",
        L"\\Registry\\Machine\\SECURITY",
        L"\\Registry\\User\\.DEFAULT",
    };
    UNICODE_STRING Path;
    ULONG i;
    BOOLEAN Failed = FALSE;

    if (SetupBoot)
        return;

    if (CmpAclReady && CmpRegistryAclEffectiveMode == CM_REGACL_MODE_ENFORCE)
    {
        for (i = 0; i < RTL_NUMBER_OF(Keys); i++)
        {
            RtlInitUnicodeString(&Path, Keys[i]);
            if (CmpAclJudgeKey(&Path, CmpAclJudgeSystemFullControl))
                continue;
            CmpAclRepairSystemAccess(&Path);
            if (!CmpAclJudgeKey(&Path, CmpAclJudgeSystemFullControl))
                Failed = TRUE;
        }
        if (Failed)
        {
            CmpAclEnforceFallback |= CMP_ACL_FALLBACK_HIVES;
            CmpRegistryAclEffectiveMode = CM_REGACL_MODE_AUDIT;
            DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL,
                       "CM-ACL-AUDIT: NOT ENFORCED: SYSTEM lacks full control of a machine hive key\n");
        }
    }

    if (!CmpAclReady || CmpRegistryAclEffectiveMode != CM_REGACL_MODE_ENFORCE)
    {
        /* Legacy or audit: users may change keys from now on, the next enforcing boot checks again */
        CmpAclMarkerDelete();
        CmpAclTransitionState = CMP_ACL_TRANSITION_NONE;
        if (!CmpAclReady)
            return;
    }
    else if (CmpAclSetupRunning)
    {
        CmpAclTransitionState = CMP_ACL_TRANSITION_SETUP;
    }
    else if (CmpAclMarkerPresent())
    {
        CmpAclTransitionState = CMP_ACL_TRANSITION_TRUSTED;
    }
    else
    {
        LARGE_INTEGER Start, End;

        KeQuerySystemTime(&Start);
        CmpAclTransition();
        KeQuerySystemTime(&End);
        CmpAclTransitionMs = (ULONG)((End.QuadPart - Start.QuadPart) / 10000);
        CmpAclTransitionState = CmpAclMarkerWrite() ? CMP_ACL_TRANSITION_WALKED : CMP_ACL_TRANSITION_NOMARKER;
        DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL,
                   "CM-ACL: transition check: %ld stored descriptors replaced (%ld owned by non-administrators), "
                   "%ld failed, marker %s\n",
                   CmpAclRestamped, CmpAclRestampUserOwned, CmpAclRestampFailed,
                   CmpAclTransitionState == CMP_ACL_TRANSITION_WALKED ? "written" : "NOT written");
    }
    CmpAclPublish();
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
    CmpAclSetDword(Key, L"StoresDescriptors", CmpStoreKeySecurity() ? 1 : 0);
    CmpAclSetDword(Key, L"SetupExclusion", CmpAclSetupRunning ? 1 : 0);
    CmpAclSetDword(Key, L"SwitchesIgnored", CmpAclSwitchesIgnored);
    CmpAclSetDword(Key, L"EnforceFallback", CmpAclEnforceFallback);
    CmpAclSetDword(Key, L"ShareDropped", (ULONG)CmpAclShareDropped);
    CmpAclSetDword(Key, L"Transition", CmpAclTransitionState);
    CmpAclSetDword(Key, L"TransitionMs", CmpAclTransitionMs);
    CmpAclSetDword(Key, L"Restamped", (ULONG)CmpAclRestamped);
    CmpAclSetDword(Key, L"RestampUserOwned", (ULONG)CmpAclRestampUserOwned);
    CmpAclSetDword(Key, L"RestampFailed", (ULONG)CmpAclRestampFailed);
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
    if (Entry->Operation == CM_REGACL_OP_RESTAMP)
    {
        /* A stored descriptor replaced at boot: why (CMP_ACL_PLANTED_*), its owner, the set's status */
        CmpAclLineFormat(Line, ",\"reasons\":\"0x%lx\",\"status\":\"0x%08lx\",\"oldowner\":",
                         Entry->Desired, (ULONG)Entry->ShadowStatus);
        CmpAclLineString(Line, p, Entry->UserChars, CMP_ACL_LINE_USER_BYTES);
        CmpAclLineFormat(Line, ",\"mode\":\"%s\"}\n", CmpAclModeNames[CmpRegistryAclMode]);
        return;
    }
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
                CmpAclLineFormat(&Line, ",\"event\":\"start\",\"mode\":\"%s\",\"configured\":\"%s\",\"source\":\"%s\","
                                 "\"setup\":%s,\"switchesIgnored\":%lu}\n",
                                 CmpAclModeNames[CmpRegistryAclEffectiveMode],
                                 CmpAclModeNames[CmpRegistryAclMode],
                                 CmpAclSourceNames[CmpRegistryAclModeSource],
                                 CmpAclSetupRunning ? "true" : "false",
                                 CmpAclSwitchesIgnored);
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
    static UNICODE_STRING ModeKey = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager");
    static UNICODE_STRING SetupKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\Setup");
    ULONG Mode, BootMode, i;
    ULONG Rule;
    UCHAR Buffer[CMP_ACL_SD_BUFFER];
    const CMP_ACL_SD_SPEC *Spec;
    PVOID Copy;
    BOOLEAN BootOption, Tables = TRUE;

    /* The boot option decides alone; legacy from it builds nothing, as before */
    BootOption = KeLoaderBlock && CmpAclParseBootOption(KeLoaderBlock->LoadOptions, &BootMode);
    if (BootOption && BootMode == CM_REGACL_MODE_LEGACY)
        Tables = FALSE;

    /* The SIDs and descriptors */
    for (i = 0; i < CmpAclSidMax && Tables; i++)
    {
        CmpAclSids[i] = CmpAclAllocateSid(CmpAclSidSpecs[i].Authority, CmpAclSidSpecs[i].Count,
                                          CmpAclSidSpecs[i].SubAuthority);
        if (!CmpAclSids[i])
            Tables = FALSE;
    }

    for (Rule = CmpAclRuleMaster; Rule < CmpAclRuleMax && Tables; Rule++)
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
            Tables = FALSE;
    }

    /* Inheritance from a stored ancestor is computed as for a key SYSTEM creates */
    if (Tables)
    {
        SeCaptureSubjectContext(&CmpAclSystemSubject);
        ExInitializePushLock(&CmpAclUserCacheLock);
    }

    /*
     * Mode: the default, then the registry value, then the boot option. The
     * value is honoured, whatever it is, only if the key that holds it is one
     * only administrators can change (see the top of the file): any value
     * other than the compiled default could lower the mode (legacy below
     * audit, and audit below enforce once enforce is the default), and a value
     * a non-administrator could have planted is no switch at all. The boot
     * option (loader block) always wins.
     */
    CmpRegistryAclMode = CMP_REGACL_DEFAULT_MODE;
    CmpRegistryAclModeSource = 0;
    if (CmpRegistryAclModeValueType == REG_DWORD &&
        CmpRegistryAclModeValueLength == sizeof(ULONG) &&
        CmpRegistryAclModeValue <= CM_REGACL_MODE_ENFORCE &&
        !BootOption)
    {
        /*
         * Where enforcement is the default, the value never takes the mode below it: the
         * value lives in the registry, which every user could write while an earlier boot
         * ran without enforcement (an install that ran audit mode), and nothing tells a
         * value an administrator set from one a user planted then. Leaving enforcement is
         * the boot option's job (/REGACL=AUDIT or LEGACY in the boot configuration, which
         * only administrators can change). The value can still ask for enforcement where
         * audit is the default.
         */
        if (CMP_REGACL_DEFAULT_MODE == CM_REGACL_MODE_ENFORCE &&
            CmpRegistryAclModeValue < CM_REGACL_MODE_ENFORCE)
        {
            CmpAclSwitchesIgnored |= CMP_ACL_IGNORED_MODE_LOWER;
        }
        else if (Tables && CmpAclKeyAdminWriteOnly(&ModeKey))
        {
            CmpRegistryAclMode = CmpRegistryAclModeValue;
            CmpRegistryAclModeSource = 1;
        }
        else
        {
            CmpAclSwitchesIgnored |= CMP_ACL_IGNORED_MODE_VALUE;
        }
    }
    if (BootOption)
    {
        CmpRegistryAclMode = BootMode;
        CmpRegistryAclModeSource = 2;
    }

    Mode = CmpRegistryAclMode;
    if (!Tables)
        Mode = CM_REGACL_MODE_LEGACY;

    /*
     * While setup runs, new keys get no stored descriptor, as before. Setup's
     * keys would otherwise inherit what the setup hives carry today: mkhive's
     * SYSTEM root descriptor (an older Windows one, with Power Users) into
     * every key of the installed SYSTEM, SOFTWARE and DEFAULT hives (and so
     * every new profile), and the master key's Everyone-read descriptor into
     * the SAM and SECURITY hives that setup creates; the stamping of keys
     * without a descriptor and the setup-time descriptors are later slices of
     * this work (registry ACL plan R5, R6). A key without one is judged by its
     * place in the namespace (the policy table above), which is the Windows
     * value. Text-mode setup comes from the loader block; the second stage
     * (SystemSetupInProgress) only counts from a SYSTEM\Setup key that only
     * administrators can change. Decided before the mode is published (and
     * before CmpAclReady), so that no create sees the one without the other.
     */
    if (Mode != CM_REGACL_MODE_LEGACY)
    {
        if (ExpInTextModeSetup)
        {
            CmpAclSetupRunning = TRUE;
        }
        else if (CmpAclSystemSetupInProgress())
        {
            if (CmpAclKeyAdminWriteOnly(&SetupKey))
                CmpAclSetupRunning = TRUE;
            else
                CmpAclSwitchesIgnored |= CMP_ACL_IGNORED_SETUP_VALUE;
        }
    }

    if (Mode != CM_REGACL_MODE_LEGACY)
    {
        KeInitializeSpinLock(&CmpAclQueueLock);
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

    /*
     * Enforcement must never lock SYSTEM out of the keys the boot needs: if
     * the descriptor of one of them (as enforcement would read it) does not
     * give SYSTEM full control, the stored descriptor responsible is replaced
     * (stores are on from here, no user-mode process runs yet); only if that
     * fails does the boot run in audit mode, and say so.
     */
    CmpRegistryAclEffectiveMode = Mode;
    if (Mode == CM_REGACL_MODE_ENFORCE && !CmpAclSystemHasFullControl(TRUE))
    {
        Mode = CM_REGACL_MODE_AUDIT;
        CmpAclEnforceFallback |= CMP_ACL_FALLBACK_SYSTEM;
    }

    CmpRegistryAclEffectiveMode = Mode;
    DbgPrintEx(DPFLTR_CONFIG_ID, DPFLTR_ERROR_LEVEL, "CM-ACL-AUDIT: mode %s (configured %s, from %s)%s%s%s%s%s\n",
               CmpAclModeNames[CmpRegistryAclEffectiveMode],
               CmpAclModeNames[CmpRegistryAclMode],
               CmpAclSourceNames[CmpRegistryAclModeSource],
               CmpAclEnforceFallback ? ", NOT ENFORCED: SYSTEM lacks full control of a boot key" : "",
               CmpAclSetupRunning ? ", setup: keys get no stored descriptor" : "",
               (CmpAclSwitchesIgnored & CMP_ACL_IGNORED_MODE_LOWER) ?
                   ", RegistryAclMode below enforce ignored (use the boot option)" : "",
               (CmpAclSwitchesIgnored & CMP_ACL_IGNORED_MODE_VALUE) ?
                   ", RegistryAclMode ignored (its key is not administrators-only)" : "",
               (CmpAclSwitchesIgnored & CMP_ACL_IGNORED_SETUP_VALUE) ?
                   ", SystemSetupInProgress ignored (its key is not administrators-only)" : "");

    /* Publish the mode now; the worker refreshes the counters */
    CmpAclPublish();
}

/*
 * REG_OPTION_BACKUP_RESTORE with SeBackupPrivilege and/or SeRestorePrivilege
 * enabled: the rights the open gets whatever its desired access and the DACL
 * say (oracle table, registry ACL design 2.2, measured on HKLM\SAM\SAM): 0 if
 * the option is not given or neither privilege is enabled (holding it is not
 * enough).
 */
#define CMP_ACL_BACKUP_ACCESS   (KEY_READ | ACCESS_SYSTEM_SECURITY)     /* 0x01020019 */
#define CMP_ACL_RESTORE_ACCESS  (KEY_WRITE | DELETE | WRITE_DAC | WRITE_OWNER | READ_CONTROL | \
                                 ACCESS_SYSTEM_SECURITY)                /* 0x010F0006 */
C_ASSERT(CMP_ACL_BACKUP_ACCESS == 0x01020019);
C_ASSERT(CMP_ACL_RESTORE_ACCESS == 0x010F0006);
C_ASSERT((CMP_ACL_BACKUP_ACCESS | CMP_ACL_RESTORE_ACCESS) == 0x010F001F);

static
ACCESS_MASK
CmpAclBackupRestoreAccess(
    _In_ PSECURITY_SUBJECT_CONTEXT Subject,
    _In_ ULONG Options)
{
    ACCESS_MASK Access = 0;

    if (!(Options & REG_OPTION_BACKUP_RESTORE))
        return 0;
    if (CmpAclPrivilegeEnabled(Subject, SE_BACKUP_PRIVILEGE))
        Access |= CMP_ACL_BACKUP_ACCESS;
    if (CmpAclPrivilegeEnabled(Subject, SE_RESTORE_PRIVILEGE))
        Access |= CMP_ACL_RESTORE_ACCESS;
    return Access;
}

/*
 * Mandatory integrity (registry ACL design 2.4): a key without a label ACE
 * has an implicit Medium label with NO_WRITE_UP; a token below the key's
 * level gets only the generic rights the label's policy leaves (read and
 * execute for NO_WRITE_UP), whatever the DACL says: measured on Windows 10,
 * a Low token cannot create HKCU\Software\x but can create below a key
 * labelled S:(ML;OICI;NW;;;LW). SeAccessCheck does not apply labels yet, so
 * the key decision does. Returns the rights the label allows the subject,
 * MAXULONG when it does not restrict it. The caller holds the subject
 * context locked.
 */
static
ACCESS_MASK
CmpAclMandatoryAllowed(
    _In_ PSECURITY_DESCRIPTOR Sd,
    _In_ PSECURITY_SUBJECT_CONTEXT Subject)
{
    PGENERIC_MAPPING Mapping = &CmpKeyObjectType->TypeInfo.GenericMapping;
    ULONG Level = SECURITY_MANDATORY_MEDIUM_RID;
    ACCESS_MASK Policy = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
    ACCESS_MASK Allowed = 0;
    BOOLEAN Present, Defaulted;
    PACL Sacl = NULL;
    PACE_HEADER Ace;
    PISID LabelSid;
    PTOKEN Token;
    ULONG i;

    Token = (PTOKEN)SeQuerySubjectContextToken(Subject);
    if (!Token)
        return MAXULONG;

    /* The first label ACE that applies to the key itself (not inherit-only) */
    if (NT_SUCCESS(RtlGetSaclSecurityDescriptor(Sd, &Present, &Sacl, &Defaulted)) && Present && Sacl)
    {
        for (i = 0; i < Sacl->AceCount; i++)
        {
            if (!NT_SUCCESS(RtlGetAce(Sacl, i, (PVOID *)&Ace)))
                break;
            if (Ace->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE || (Ace->AceFlags & INHERIT_ONLY_ACE))
                continue;
            LabelSid = (PISID)&((PSYSTEM_MANDATORY_LABEL_ACE)Ace)->SidStart;
            if (Ace->AceSize < FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart) + FIELD_OFFSET(SID, SubAuthority) + sizeof(ULONG) ||
                LabelSid->SubAuthorityCount != 1 ||
                LabelSid->IdentifierAuthority.Value[0] || LabelSid->IdentifierAuthority.Value[1] ||
                LabelSid->IdentifierAuthority.Value[2] || LabelSid->IdentifierAuthority.Value[3] ||
                LabelSid->IdentifierAuthority.Value[4] ||
                LabelSid->IdentifierAuthority.Value[5] != 16 /* SECURITY_MANDATORY_LABEL_AUTHORITY */)
            {
                continue;
            }
            Level = LabelSid->SubAuthority[0];
            Policy = ((PSYSTEM_MANDATORY_LABEL_ACE)Ace)->Mask;
            break;
        }
    }

    if (Token->IntegrityLevel >= Level)
        return MAXULONG;

    if (!(Policy & SYSTEM_MANDATORY_LABEL_NO_READ_UP))
        Allowed |= Mapping->GenericRead;
    if (!(Policy & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP))
        Allowed |= Mapping->GenericWrite;
    if (!(Policy & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP))
        Allowed |= Mapping->GenericExecute;
    return Allowed;
}

/*
 * The access decision on a key's own descriptor, the one function behind
 * both the audit (mode 1: the result is only recorded) and enforcement
 * (mode 2: the result stands), so that the audit log lists exactly what
 * enforcement denies.
 *
 *  Kcb        the key opened, or the parent of a key being created
 *  ChildName  the new key's name (creates), for the log
 *  Operation  CM_REGACL_OP_*
 *  Desired    the access asked for: an open's remaining desired access (mapped,
 *             MAXIMUM_ALLOWED possible), or KEY_CREATE_SUB_KEY / KEY_CREATE_LINK
 *             on the parent of a create
 *  Previous   access granted before (an open's PreviouslyGrantedAccess)
 *  Options    REG_OPTION_BACKUP_RESTORE of the open or create
 *  Object     the key body of an open (for the open audit alarm), else NULL
 *  Privileges receives the privileges the check used (SeSecurity, SeTakeOwnership),
 *             for the caller to append to the access state; NULL: freed here
 *
 * The descriptor is the key's effective one (stored, inherited, policy:
 * CmpGetEffectiveKeySd), the mapping the key type's (Windows 10 values), the
 * subject the access state's, the mode UserMode (callers skip kernel mode).
 * A denial goes to the log in both modes. Returns TRUE with *Granted if access
 * is granted, else FALSE with *AccessStatus (STATUS_ACCESS_DENIED, or
 * STATUS_PRIVILEGE_NOT_HELD for ACCESS_SYSTEM_SECURITY without SeSecurity, or
 * STATUS_INSUFFICIENT_RESOURCES when no descriptor could be built: nothing is
 * logged then).
 */
static
DECLSPEC_NOINLINE
BOOLEAN
CmpAclDecide(
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _In_opt_ PCUNICODE_STRING ChildName,
    _In_ ULONG Operation,
    _In_ PACCESS_STATE AccessState,
    _In_ ACCESS_MASK Desired,
    _In_ ACCESS_MASK Previous,
    _In_ ULONG Options,
    _In_opt_ PVOID Object,
    _Out_ PACCESS_MASK Granted,
    _Out_ PNTSTATUS AccessStatus,
    _Out_opt_ PPRIVILEGE_SET *Privileges)
{
    ULONG SdBuffer[CMP_ACL_SD_BUFFER / sizeof(ULONG)];
    PSECURITY_DESCRIPTOR Sd, ToFree;
    PVOID PoolCopy;
    ULONG Rule;
    ACCESS_MASK BackupAccess, MandatoryAllowed;
    PPRIVILEGE_SET Used = NULL;
    BOOLEAN Result;

    *Granted = 0;
    *AccessStatus = STATUS_ACCESS_DENIED;
    if (Privileges)
        *Privileges = NULL;

    /* Publish the counters now and then even when nothing is denied (the worker does it at most once a minute) */
    if ((InterlockedIncrement(&CmpAclChecks) & 0xFFF) == 0)
        CmpAclArmTimer();

    /*
     * Backup/restore semantics. An open gets the fixed rights whatever it asked
     * for (measured). The create of a subkey (the right is checked on the parent)
     * is allowed when those rights include the one needed: an inference from the
     * open rule, VERIFY ON PEER (create under HKLM\SAM\SAM with
     * REG_OPTION_BACKUP_RESTORE, SeRestore only / SeBackup only, as an
     * administrator); otherwise the DACL decides.
     */
    BackupAccess = CmpAclBackupRestoreAccess(&AccessState->SubjectSecurityContext, Options);
    if (BackupAccess)
    {
        if (Operation == CM_REGACL_OP_OPEN)
        {
            *Granted = BackupAccess;
            *AccessStatus = STATUS_SUCCESS;
            return TRUE;
        }
        if ((Desired & ~BackupAccess) == 0)
        {
            *Granted = Desired;
            *AccessStatus = STATUS_SUCCESS;
            return TRUE;
        }
    }

    /*
     * Exact lookup (no shortcut on an empty hive security cache): a cell that
     * could not be cached must still be found, or a stricter stored descriptor
     * would be passed over for the policy one
     */
    Sd = CmpGetEffectiveKeySd(Kcb, SdBuffer, sizeof(SdBuffer), &Rule, &ToFree, &PoolCopy, FALSE);
    if (!Sd)
    {
        InterlockedIncrement(&CmpAclErrors);
        *AccessStatus = STATUS_INSUFFICIENT_RESOURCES;
        return FALSE;
    }

    SeLockSubjectContext(&AccessState->SubjectSecurityContext);

    /* The integrity label first: rights it does not allow are not granted, whatever the DACL says */
    MandatoryAllowed = CmpAclMandatoryAllowed(Sd, &AccessState->SubjectSecurityContext);
    if (MandatoryAllowed != MAXULONG &&
        (Desired & ~(MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY) & ~MandatoryAllowed))
    {
        Result = FALSE;
        *Granted = 0;
        *AccessStatus = STATUS_ACCESS_DENIED;
    }
    else
    {
        Result = SeAccessCheck(Sd,
                               &AccessState->SubjectSecurityContext,
                               TRUE,
                               Desired,
                               Previous,
                               &Used,
                               &CmpKeyObjectType->TypeInfo.GenericMapping,
                               UserMode,
                               Granted,
                               AccessStatus);
        if (Result && MandatoryAllowed != MAXULONG)
        {
            /* MAXIMUM_ALLOWED: what the DACL gives, within the label */
            *Granted &= MandatoryAllowed | ACCESS_SYSTEM_SECURITY | Previous;
            if (!*Granted)
            {
                Result = FALSE;
                *AccessStatus = STATUS_ACCESS_DENIED;
            }
        }
    }

    /* What CmpCheckKeyOpenAccess (and ObCheckObjectAccess) do with the descriptor checked */
    if (Object)
    {
        SeOpenObjectAuditAlarm(&CmpKeyObjectType->Name,
                               Object,
                               NULL,
                               Sd,
                               AccessState,
                               FALSE,
                               Result,
                               UserMode,
                               &AccessState->GenerateOnClose);
    }
    SeUnlockSubjectContext(&AccessState->SubjectSecurityContext);

    if (Used)
    {
        if (Privileges)
            *Privileges = Used;
        else
            SeFreePrivileges(Used);
    }

    if (!Result)
    {
        CmpAclRecordDenial(Kcb, ChildName, Operation, &AccessState->SubjectSecurityContext,
                           Desired, *Granted, *AccessStatus, Rule);
    }

    CmpAclFreeEffectiveSd(ToFree, PoolCopy);
    return Result;
}

/* Key access is enforced (mode 2 running): the decision above stands */
static
BOOLEAN
CmpAclEnforcing(VOID)
{
    return CmpAclReady && CmpRegistryAclEffectiveMode == CM_REGACL_MODE_ENFORCE;
}

/*
 * Is the subject of an open a restricted token (restricting SIDs, or write restricted) while key access
 * is not enforced but not off (audit mode)? The legacy descriptor that the open is otherwise decided
 * against grants Everyone and nobody else, so a second pass over restricting SIDs that are not Everyone
 * (S-1-5-33, the logon SID, a group of the account) would refuse every open, where Windows decides by
 * the key's own descriptor (measured on Windows Server 2022: a key that grants S-1-5-33 is opened by a
 * restricted and by a write restricted token holding that restricting SID, with every access mask). The
 * open of such a subject is therefore decided like an enforced one. Legacy mode has no decision on key
 * descriptors at all and is left alone.
 */
static
BOOLEAN
CmpAclRestrictedSubject(
    _In_ PACCESS_STATE AccessState)
{
    PACCESS_TOKEN Token;

    if (!CmpAclReady || CmpRegistryAclEffectiveMode == CM_REGACL_MODE_LEGACY)
        return FALSE;

    Token = SeQuerySubjectContextToken(&AccessState->SubjectSecurityContext);
    return Token && SeTokenIsRestricted(Token);
}

/*
 * The access decision of a key open (CmpDoOpen). Kernel-mode opens, and every
 * open unless key access is enforced, are decided by CmpCheckKeyOpenAccess
 * (the descriptor keys always had: it grants what it always granted), and the
 * audit records what the key's own descriptor would decide. When it is
 * enforced (mode 2), the key's own descriptor decides (CmpAclDecide, the same
 * function the audit uses), with the same steps as CmpCheckKeyOpenAccess:
 * the privileges used go into the access state, the granted access moves
 * from the remaining to the granted mask, ACCESS_SYSTEM_SECURITY without
 * SeSecurityPrivilege fails with STATUS_ACCESS_DENIED.
 */
BOOLEAN
NTAPI
CmpAclCheckKeyOpen(
    _In_ PVOID Object,
    _In_ PCM_KEY_CONTROL_BLOCK Kcb,
    _Inout_ PACCESS_STATE AccessState,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ ULONG Options,
    _Out_ PNTSTATUS AccessStatus)
{
    ACCESS_MASK Desired = AccessState->RemainingDesiredAccess;
    ACCESS_MASK Previous = AccessState->PreviouslyGrantedAccess;
    ACCESS_MASK Granted;
    PPRIVILEGE_SET Privileges;
    BOOLEAN Result;

    if (AccessMode == KernelMode || !(CmpAclEnforcing() || CmpAclRestrictedSubject(AccessState)))
    {
        Result = CmpCheckKeyOpenAccess(Object, AccessState, AccessMode, AccessStatus);
        if (Result)
        {
            /* Registry ACL audit: what the key's own descriptor decides (logged only, the open stands) */
            CmpShadowAccessCheck(Kcb, NULL, CM_REGACL_OP_OPEN, AccessState, Desired, Previous,
                                 AccessState->PreviouslyGrantedAccess, AccessMode, Options);
        }
        return Result;
    }

    Result = CmpAclDecide(Kcb, NULL, CM_REGACL_OP_OPEN, AccessState, Desired, Previous,
                          Options, Object, &Granted, AccessStatus, &Privileges);
    if (Privileges)
    {
        SeAppendPrivileges(AccessState, Privileges);
        SeFreePrivileges(Privileges);
    }
    if (Result)
    {
        /*
         * Everything asked for is granted (a backup/restore open: the fixed
         * rights, and nothing else it asked for): the handle gets Granted
         */
        AccessState->RemainingDesiredAccess = 0;
        AccessState->PreviouslyGrantedAccess |= Granted;
    }
    else if (*AccessStatus == STATUS_PRIVILEGE_NOT_HELD)
    {
        /* As CmpCheckKeyOpenAccess: the oracle's status for ACCESS_SYSTEM_SECURITY without the privilege */
        *AccessStatus = STATUS_ACCESS_DENIED;
    }
    return Result;
}

/*
 * The right a create needs on the parent key, when key access is enforced:
 * KEY_CREATE_SUB_KEY, or KEY_CREATE_LINK for a symbolic link (Operation
 * CM_REGACL_OP_CREATELINK); CM_REGACL_OP_LINKNODE (a hive link) needs
 * KEY_CREATE_SUB_KEY. Checked before anything is created. The creator then
 * gets the access it asked for on the new key, whatever the new key's DACL
 * says (oracle, design 2.2): the handle of a new key is not checked again.
 * STATUS_SUCCESS when allowed or not enforced (mode 1: the create checks
 * nothing, except for a restricted token, which is decided like its opens,
 * and the audit records the decision after it), else the status of the
 * denial.
 */
NTSTATUS
NTAPI
CmpAclCheckKeyCreate(
    _In_ PCM_KEY_CONTROL_BLOCK ParentKcb,
    _In_ PCUNICODE_STRING ChildName,
    _In_ ULONG Operation,
    _In_ PACCESS_STATE AccessState,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ ULONG Options)
{
    ACCESS_MASK Granted;
    NTSTATUS AccessStatus;

    if (AccessMode == KernelMode || !ParentKcb || !AccessState)
        return STATUS_SUCCESS;

    /* A restricted token is decided by the descriptor also while key access is not enforced, as its opens are */
    if (!CmpAclEnforcing() && !CmpAclRestrictedSubject(AccessState))
        return STATUS_SUCCESS;

    if (CmpAclDecide(ParentKcb, ChildName, Operation, AccessState,
                     (Operation == CM_REGACL_OP_CREATELINK) ? KEY_CREATE_LINK : KEY_CREATE_SUB_KEY,
                     0, Options, NULL, &Granted, &AccessStatus, NULL))
    {
        return STATUS_SUCCESS;
    }
    return (AccessStatus == STATUS_INSUFFICIENT_RESOURCES) ? AccessStatus : STATUS_ACCESS_DENIED;
}

/*
 * May the parse follow the symbolic link LinkKcb to Target (the full name the
 * reparse starts over with)? A user can make links in its own hives; the target
 * of an open through such a link is checked with the opener's token, but a
 * kernel-mode opener is not checked at all (win32k writes the user's settings
 * that way) and a SYSTEM opener passes any check, so a link in a user's hive
 * could carry their writes into keys the user cannot write. Like a trust class
 * (NtLoadKeyEx's TrustClassKey: a user hive and its classes hive), a link in a
 * hive loaded at \REGISTRY\USER\<name> (not .DEFAULT, not S-1-5-18) is followed
 * only to \REGISTRY\USER\<name> or \REGISTRY\USER\<name>_Classes and below
 * (<name> without a _Classes suffix). Links elsewhere (machine hives, which only
 * administrators can change) are not judged. A refused link is logged in both
 * modes and refused only when key access is enforced (mode 2). The caller holds
 * the registry lock (names cannot change).
 */
BOOLEAN
NTAPI
CmpAclCheckLinkFollow(
    _In_ PCM_KEY_CONTROL_BLOCK LinkKcb,
    _In_ PCUNICODE_STRING Target)
{
    static const WCHAR Prefix[] = L"\\REGISTRY\\USER\\";
    static const CHAR Classes[] = "_CLASSES";
    const ULONG PrefixChars = RTL_NUMBER_OF(Prefix) - 1;
    const ULONG ClassesChars = sizeof(Classes) - 1;
    SECURITY_SUBJECT_CONTEXT Subject;
    PCM_KEY_CONTROL_BLOCK Walk, HiveKey;
    ULONG Depth = 0, Chars, BaseChars, TargetChars, Pos, i;

    if (!CmpAclReady || CmpRegistryAclEffectiveMode == CM_REGACL_MODE_LEGACY || !LinkKcb || !Target)
        return TRUE;

    /* The key at \REGISTRY\<USER>\<name> above the link */
    for (Walk = LinkKcb; Walk; Walk = Walk->ParentKcb)
        Depth++;
    if (Depth < 3)
        return TRUE;
    HiveKey = LinkKcb;
    for (i = Depth; i > 3; i--)
        HiveKey = HiveKey->ParentKcb;
    if (!CmpAclNameMatches(HiveKey->ParentKcb, "USER", FALSE) ||
        CmpAclNameMatches(HiveKey, ".DEFAULT", FALSE) ||
        CmpAclNameMatches(HiveKey, "S-1-5-18", FALSE))
    {
        return TRUE;
    }

    /* <name> without a _Classes suffix */
    Chars = CmpAclNameChars(HiveKey);
    BaseChars = Chars;
    if (Chars > ClassesChars)
    {
        for (i = 0; i < ClassesChars; i++)
        {
            if (RtlUpcaseUnicodeChar(CmpAclNameChar(HiveKey, Chars - ClassesChars + i)) != (WCHAR)Classes[i])
                break;
        }
        if (i == ClassesChars)
            BaseChars = Chars - ClassesChars;
    }

    /* Target: \REGISTRY\USER\<base>, optionally _Classes, then the end or a separator */
    TargetChars = Target->Length / sizeof(WCHAR);
    if (TargetChars < PrefixChars + BaseChars)
        goto Refuse;
    for (i = 0; i < PrefixChars; i++)
    {
        if (RtlUpcaseUnicodeChar(Target->Buffer[i]) != Prefix[i])
            goto Refuse;
    }
    for (i = 0; i < BaseChars; i++)
    {
        if (RtlUpcaseUnicodeChar(Target->Buffer[PrefixChars + i]) != RtlUpcaseUnicodeChar(CmpAclNameChar(HiveKey, i)))
            goto Refuse;
    }
    Pos = PrefixChars + BaseChars;
    if (Pos == TargetChars || Target->Buffer[Pos] == OBJ_NAME_PATH_SEPARATOR)
        return TRUE;
    if (TargetChars - Pos >= ClassesChars)
    {
        for (i = 0; i < ClassesChars; i++)
        {
            if (RtlUpcaseUnicodeChar(Target->Buffer[Pos + i]) != (WCHAR)Classes[i])
                goto Refuse;
        }
        Pos += ClassesChars;
        if (Pos == TargetChars || Target->Buffer[Pos] == OBJ_NAME_PATH_SEPARATOR)
            return TRUE;
    }

Refuse:
    SeCaptureSubjectContext(&Subject);
    CmpAclRecordDenial(LinkKcb, Target, CM_REGACL_OP_FOLLOWLINK, &Subject, 0, 0, STATUS_ACCESS_DENIED, CmpAclRuleUser);
    SeReleaseSubjectContext(&Subject);
    return !CmpAclEnforcing();
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
    ACCESS_MASK Granted;
    NTSTATUS AccessStatus;

    /*
     * Kernel-mode callers are not checked on Windows either. When access is
     * enforced, the decision was taken (and logged) before the operation by
     * the same function (CmpAclCheckKeyOpen, CmpAclCheckKeyCreate).
     */
    if (CmpRegistryAclEffectiveMode != CM_REGACL_MODE_AUDIT || !CmpAclReady || AccessMode == KernelMode)
        return;
    if (!Kcb || !AccessState || Operation > CM_REGACL_OP_LINKNODE)
        return;

    if (CmpAclDecide(Kcb, ChildName, Operation, AccessState, Desired, Previous, Options, NULL,
                     &Granted, &AccessStatus, NULL) &&
        (Desired & MAXIMUM_ALLOWED) && LegacyGranted && (Granted & LegacyGranted) != LegacyGranted)
    {
        /* Opened for MAXIMUM_ALLOWED: Windows hands out less (counted, not logged) */
        InterlockedIncrement(&CmpAclMaxAllowedReduced);
    }
}

/* EOF */
