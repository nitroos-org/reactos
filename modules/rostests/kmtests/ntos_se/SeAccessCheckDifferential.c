/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Differential test of SeAccessCheck over a generated matrix of descriptors,
 *              owners and desired accesses. It checks nothing itself: it prints a hash per
 *              section (and the rows of the first descriptors in full), so that the output
 *              of two kernels can be compared byte for byte.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/*
 * Descriptors: no DACL, an empty DACL, every DACL of one or two ACEs of a reduced alphabet,
 * and a fixed number of pseudo-random DACLs of one to six ACEs of the full alphabet (fixed
 * seed). Owners: the caller's user, another SID, Administrators, and none (a kernel-only
 * case). Modes: UserMode and KernelMode. The subject is the caller's own token.
 */

#define AD_RC READ_CONTROL
#define AD_WD WRITE_DAC

#define AD_EX_TYPES     4
#define AD_EX_FLAGS     2
#define AD_EX_SIDS      3
#define AD_EX_MASKS     4
#define AD_RANDOM_DACLS 1500
#define AD_VERBOSE      40
#define AD_MAX_ACES     6
#define AD_ACL_SIZE     1024

enum { AD_SID_OW, AD_SID_USER, AD_SID_WORLD, AD_SID_OTHER, AD_SID_ADMINS, AD_SID_COUNT };
enum { AD_OWNER_USER, AD_OWNER_OTHER, AD_OWNER_ADMINS, AD_OWNER_NONE, AD_OWNER_COUNT };

enum
{
    AD_A_ALLOW, AD_A_DENY,
    AD_A_OBJ_ALLOW, AD_A_OBJ_DENY,
    AD_A_OBJ_ALLOW_TYPE, AD_A_OBJ_DENY_TYPE,
    AD_A_OBJ_ALLOW_INH, AD_A_OBJ_DENY_INH,
    AD_A_OBJ_ALLOW_BOTH,
    AD_A_CALLBACK_ALLOW, AD_A_CALLBACK_DENY,
    AD_A_AUDIT,
    AD_A_TYPE_COUNT
};

typedef struct _AD_ACE
{
    UCHAR Type;
    UCHAR Flags;
    UCHAR SidIndex;
    ACCESS_MASK Mask;
} AD_ACE;

typedef struct _AD_DACL
{
    BOOLEAN HasDacl;
    ULONG AceCount;
    AD_ACE Aces[AD_MAX_ACES];
} AD_DACL;

static GENERIC_MAPPING AdMappings[2] =
{
    { STANDARD_RIGHTS_READ | 1, STANDARD_RIGHTS_WRITE | 2, STANDARD_RIGHTS_EXECUTE | 4, STANDARD_RIGHTS_ALL | 7 },
    { STANDARD_RIGHTS_READ | 1, STANDARD_RIGHTS_WRITE | 2, STANDARD_RIGHTS_EXECUTE | 4, STANDARD_RIGHTS_ALL | 0x1f }
};

static const ACCESS_MASK AdAllMasks[] =
{
    AD_RC, AD_WD, AD_RC | AD_WD, 1, 2, AD_RC | 1, AD_WD | 2, AD_RC | AD_WD | 1, 4, 0x80000000,
    0x10000000, 0x1f, MAXIMUM_ALLOWED, 0, SYNCHRONIZE | 1
};
static const ACCESS_MASK AdReducedMasks[AD_EX_MASKS] = { AD_RC, AD_WD | 1, 1, AD_RC | AD_WD | 2 };
static const ACCESS_MASK AdDesired[] =
{
    0, AD_RC, AD_WD, AD_RC | AD_WD, MAXIMUM_ALLOWED, 1, AD_RC | 1, AD_WD | 2, AD_RC | AD_WD | 1,
    MAXIMUM_ALLOWED | 1, 0x80000000, 0x10000000, 0x80000000 | AD_RC, SYNCHRONIZE | 4,
    ACCESS_SYSTEM_SECURITY, WRITE_OWNER, AD_RC | WRITE_OWNER, AD_RC | 1 | ACCESS_SYSTEM_SECURITY,
    AD_WD | WRITE_OWNER | 2, MAXIMUM_ALLOWED | WRITE_OWNER
};
static const UCHAR AdReducedTypes[AD_EX_TYPES] = { AD_A_ALLOW, AD_A_DENY, AD_A_OBJ_ALLOW_TYPE, AD_A_OBJ_DENY };
static const UCHAR AdReducedFlags[AD_EX_FLAGS] = { 0, INHERIT_ONLY_ACE };
static const UCHAR AdReducedSids[AD_EX_SIDS] = { AD_SID_OW, AD_SID_USER, AD_SID_WORLD };
static const UCHAR AdAllFlags[] =
{
    0, 0, 0, INHERIT_ONLY_ACE, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE, INHERITED_ACE,
    INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE
};

static const GUID AdGuid = { 0x5d2f8a31, 0x41c7, 0x4b0e, { 0x8e, 0x33, 0x52, 0x0c, 0x6a, 0x10, 0x00, 0x03 } };
static SID AdOwnerRightsSid = { SID_REVISION, 1, { SECURITY_CREATOR_SID_AUTHORITY }, { SECURITY_CREATOR_OWNER_RIGHTS_RID } };

static PSID AdSids[AD_SID_COUNT];
static ULONG AdRng = 0x9e3779b9;

typedef struct _AD_SECTION
{
    ULONG HashA;
    ULONG HashB;
    ULONG Rows;
} AD_SECTION;

static AD_SECTION AdSections[AD_OWNER_COUNT][2];
static BOOLEAN AdVerbose;

static
ULONG
AdNextRandom(
    _In_ ULONG Modulus)
{
    /* xorshift32: fixed seed, so every run builds the same matrix */
    AdRng ^= AdRng << 13;
    AdRng ^= AdRng >> 17;
    AdRng ^= AdRng << 5;
    return (AdRng >> 4) % Modulus;
}

static
VOID
AdHash(
    _Inout_ AD_SECTION *Section,
    _In_ ULONG Value)
{
    ULONG i;

    for (i = 0; i < 4; i++)
    {
        Section->HashA = (Section->HashA ^ (UCHAR)(Value >> (i * 8))) * 16777619UL;
        Section->HashB = (Section->HashB + (UCHAR)(Value >> (i * 8)) + 1) * 2654435761UL;
    }
}

static
BOOLEAN
AdAppendAce(
    _Inout_ PACL Acl,
    _In_ const AD_ACE *Desc)
{
    PUCHAR Ace = (PUCHAR)Acl + Acl->AclSize;
    PUCHAR Cursor;
    PSID Sid = AdSids[Desc->SidIndex];
    ULONG SidLength = RtlLengthSid(Sid);
    ULONG ObjectFlags = 0;
    BOOLEAN IsObject = FALSE, WithType = FALSE, WithInherited = FALSE;
    UCHAR Type;
    ULONG Size;

    switch (Desc->Type)
    {
        case AD_A_ALLOW: Type = ACCESS_ALLOWED_ACE_TYPE; break;
        case AD_A_DENY: Type = ACCESS_DENIED_ACE_TYPE; break;
        case AD_A_CALLBACK_ALLOW: Type = ACCESS_ALLOWED_CALLBACK_ACE_TYPE; break;
        case AD_A_CALLBACK_DENY: Type = ACCESS_DENIED_CALLBACK_ACE_TYPE; break;
        case AD_A_AUDIT: Type = SYSTEM_AUDIT_ACE_TYPE; break;
        default:
            IsObject = TRUE;
            Type = (Desc->Type & 1) ? ACCESS_DENIED_OBJECT_ACE_TYPE : ACCESS_ALLOWED_OBJECT_ACE_TYPE;
            WithType = (Desc->Type == AD_A_OBJ_ALLOW_TYPE || Desc->Type == AD_A_OBJ_DENY_TYPE ||
                        Desc->Type == AD_A_OBJ_ALLOW_BOTH);
            WithInherited = (Desc->Type == AD_A_OBJ_ALLOW_INH || Desc->Type == AD_A_OBJ_DENY_INH ||
                             Desc->Type == AD_A_OBJ_ALLOW_BOTH);
            break;
    }

    Size = IsObject ? (12 + (WithType ? sizeof(GUID) : 0) + (WithInherited ? sizeof(GUID) : 0) + SidLength)
                    : (8 + SidLength);
    if ((ULONG)Acl->AclSize + Size > AD_ACL_SIZE)
        return FALSE;

    Ace[0] = Type;
    Ace[1] = Desc->Flags;
    *(PUSHORT)(Ace + 2) = (USHORT)Size;
    *(PULONG)(Ace + 4) = Desc->Mask;
    Cursor = Ace + 8;
    if (IsObject)
    {
        if (WithType)
            ObjectFlags |= ACE_OBJECT_TYPE_PRESENT;
        if (WithInherited)
            ObjectFlags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
        *(PULONG)Cursor = ObjectFlags;
        Cursor += 4;
        if (WithType)
        {
            RtlCopyMemory(Cursor, &AdGuid, sizeof(GUID));
            Cursor += sizeof(GUID);
        }
        if (WithInherited)
        {
            RtlCopyMemory(Cursor, &AdGuid, sizeof(GUID));
            Cursor += sizeof(GUID);
        }
    }
    RtlCopyMemory(Cursor, Sid, SidLength);
    Acl->AclSize = (USHORT)(Acl->AclSize + Size);
    Acl->AceCount++;
    return TRUE;
}

typedef struct _AD_SD
{
    SECURITY_DESCRIPTOR Sd;
    ULONG_PTR Align;
    UCHAR AclBuffer[AD_ACL_SIZE];
} AD_SD;

static
VOID
AdRunDescriptor(
    _In_ PSECURITY_SUBJECT_CONTEXT Subject,
    _In_ ULONG DaclIndex,
    _In_ const AD_DACL *Desc,
    _In_ AD_SD *AdSd)
{
    PACL Acl = (PACL)AdSd->AclBuffer;
    PSID Owners[AD_OWNER_COUNT];
    ULONG Owner, Mode, d, i;
    NTSTATUS Status;

    Owners[AD_OWNER_USER] = AdSids[AD_SID_USER];
    Owners[AD_OWNER_OTHER] = AdSids[AD_SID_OTHER];
    Owners[AD_OWNER_ADMINS] = AdSids[AD_SID_ADMINS];
    Owners[AD_OWNER_NONE] = NULL;

    AdVerbose = DaclIndex < AD_VERBOSE;

    if (Desc->HasDacl)
    {
        Status = RtlCreateAcl(Acl, AD_ACL_SIZE, ACL_REVISION4);
        if (!NT_SUCCESS(Status))
        {
            KmtOk(FALSE, __FILE__ ":" KMT_STRINGIZE(__LINE__), "RtlCreateAcl failed 0x%lx\n", Status);
            return;
        }
        /* AclSize is the part in use from here on: the ACEs are appended to it */
        Acl->AclSize = sizeof(ACL);
        for (i = 0; i < Desc->AceCount; i++)
        {
            if (!AdAppendAce(Acl, &Desc->Aces[i]))
            {
                KmtOk(FALSE, __FILE__ ":" KMT_STRINGIZE(__LINE__), "ACE does not fit\n");
                return;
            }
        }
    }

    for (Owner = 0; Owner < AD_OWNER_COUNT; Owner++)
    {
        RtlCreateSecurityDescriptor(&AdSd->Sd, SECURITY_DESCRIPTOR_REVISION);
        RtlSetOwnerSecurityDescriptor(&AdSd->Sd, Owners[Owner], FALSE);
        RtlSetGroupSecurityDescriptor(&AdSd->Sd, Owners[Owner], FALSE);
        RtlSetDaclSecurityDescriptor(&AdSd->Sd, Desc->HasDacl, Desc->HasDacl ? Acl : NULL, FALSE);

        for (Mode = 0; Mode < 2; Mode++)
        {
            AD_SECTION *Section = &AdSections[Owner][Mode];

            for (d = 0; d < RTL_NUMBER_OF(AdDesired); d++)
            {
                ACCESS_MASK Desired = AdDesired[d];
                ACCESS_MASK Granted = 0xdeadbeef;
                NTSTATUS AccessStatus = 0xdeadbeef;
                PPRIVILEGE_SET Privileges = NULL;
                BOOLEAN Result;

                Result = SeAccessCheck(&AdSd->Sd,
                                       Subject,
                                       FALSE,
                                       Desired,
                                       0,
                                       &Privileges,
                                       &AdMappings[DaclIndex & 1],
                                       Mode ? KernelMode : UserMode,
                                       &Granted,
                                       &AccessStatus);
                if (Privileges)
                    SeFreePrivileges(Privileges);

                AdHash(Section, DaclIndex);
                AdHash(Section, Desired);
                AdHash(Section, Result);
                AdHash(Section, Granted);
                AdHash(Section, AccessStatus);
                Section->Rows++;
                if (AdVerbose)
                {
                    trace("row %lu %lu %lu %08lx %u %08lx:%08lx\n",
                          DaclIndex, Owner, Mode, Desired, Result, Granted, AccessStatus);
                }
            }
        }
    }
}

START_TEST(SeAccessCheckDifferential)
{
    SECURITY_SUBJECT_CONTEXT Subject;
    PTOKEN_USER UserInfo = NULL;
    PACCESS_TOKEN Token;
    NTSTATUS Status;
    AD_DACL Desc;
    AD_SD *AdSd;
    AD_ACE Pool[AD_EX_TYPES * AD_EX_FLAGS * AD_EX_SIDS * AD_EX_MASKS];
    ULONG PoolCount = RTL_NUMBER_OF(Pool);
    ULONG Index = 0, a, b, c, m, i, Owner, Mode, TotalRows = 0, TotalA = 0, TotalB = 0;

    SeCaptureSubjectContext(&Subject);
    Token = SeQuerySubjectContextToken(&Subject);
    Status = SeQueryInformationToken(Token, TokenUser, (PVOID*)&UserInfo);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status) && UserInfo, "No token user\n"))
    {
        SeReleaseSubjectContext(&Subject);
        return;
    }

    AdSids[AD_SID_OW] = &AdOwnerRightsSid;
    AdSids[AD_SID_USER] = UserInfo->User.Sid;
    AdSids[AD_SID_WORLD] = SeExports->SeWorldSid;
    AdSids[AD_SID_OTHER] = SeExports->SeLocalServiceSid;
    AdSids[AD_SID_ADMINS] = SeExports->SeAliasAdminsSid;

    for (Owner = 0; Owner < AD_OWNER_COUNT; Owner++)
        for (Mode = 0; Mode < 2; Mode++)
        {
            AdSections[Owner][Mode].HashA = 2166136261UL;
            AdSections[Owner][Mode].HashB = 0x12345;
            AdSections[Owner][Mode].Rows = 0;
        }

    AdSd = ExAllocatePoolWithTag(PagedPool, sizeof(*AdSd), 'dAmK');
    if (skip(AdSd != NULL, "No memory\n"))
    {
        ExFreePool(UserInfo);
        SeReleaseSubjectContext(&Subject);
        return;
    }

    i = 0;
    for (a = 0; a < AD_EX_TYPES; a++)
        for (b = 0; b < AD_EX_FLAGS; b++)
            for (c = 0; c < AD_EX_SIDS; c++)
                for (m = 0; m < AD_EX_MASKS; m++)
                {
                    Pool[i].Type = AdReducedTypes[a];
                    Pool[i].Flags = AdReducedFlags[b];
                    Pool[i].SidIndex = AdReducedSids[c];
                    Pool[i].Mask = AdReducedMasks[m];
                    i++;
                }

    RtlZeroMemory(&Desc, sizeof(Desc));
    Desc.HasDacl = FALSE;
    AdRunDescriptor(&Subject, Index++, &Desc, AdSd);
    Desc.HasDacl = TRUE;
    AdRunDescriptor(&Subject, Index++, &Desc, AdSd);

    for (a = 0; a < PoolCount; a++)
    {
        Desc.AceCount = 1;
        Desc.Aces[0] = Pool[a];
        AdRunDescriptor(&Subject, Index++, &Desc, AdSd);
    }
    for (a = 0; a < PoolCount; a++)
    {
        for (b = 0; b < PoolCount; b++)
        {
            Desc.AceCount = 2;
            Desc.Aces[0] = Pool[a];
            Desc.Aces[1] = Pool[b];
            AdRunDescriptor(&Subject, Index++, &Desc, AdSd);
        }
    }

    for (i = 0; i < AD_RANDOM_DACLS; i++)
    {
        ULONG n = 1 + AdNextRandom(AD_MAX_ACES);

        Desc.AceCount = n;
        for (a = 0; a < n; a++)
        {
            ULONG SidPick = AdNextRandom(8);

            Desc.Aces[a].Type = (UCHAR)AdNextRandom(AD_A_TYPE_COUNT);
            Desc.Aces[a].Flags = AdAllFlags[AdNextRandom(sizeof(AdAllFlags))];
            Desc.Aces[a].SidIndex = SidPick < 3 ? AD_SID_OW : (UCHAR)(SidPick - 3);
            Desc.Aces[a].Mask = AdAllMasks[AdNextRandom(RTL_NUMBER_OF(AdAllMasks))];
        }
        AdRunDescriptor(&Subject, Index++, &Desc, AdSd);
    }

    for (Owner = 0; Owner < AD_OWNER_COUNT; Owner++)
    {
        for (Mode = 0; Mode < 2; Mode++)
        {
            AD_SECTION *Section = &AdSections[Owner][Mode];

            trace("section %lu %lu %lu %08lx%08lx\n", Owner, Mode, Section->Rows, Section->HashA, Section->HashB);
            TotalA += Section->HashA;
            TotalB += Section->HashB;
            TotalRows += Section->Rows;
        }
    }
    trace("total descriptors %lu rows %lu hash %08lx%08lx\n", Index, TotalRows, TotalA, TotalB);

    ExFreePoolWithTag(AdSd, 'dAmK');
    ExFreePool(UserInfo);
    SeReleaseSubjectContext(&Subject);
}

static
VOID
AdBench(
    _In_ PSECURITY_SUBJECT_CONTEXT Subject,
    _In_ PCSTR Name,
    _In_ PSECURITY_DESCRIPTOR Sd,
    _In_ ACCESS_MASK Desired)
{
    LARGE_INTEGER Frequency, Start, End;
    ULONG i, Loops = 1000000, Passed = 0;
    ACCESS_MASK Granted;
    NTSTATUS AccessStatus;
    PPRIVILEGE_SET Privileges;
    ULONGLONG Ns;

    Start = KeQueryPerformanceCounter(&Frequency);
    for (i = 0; i < Loops; i++)
    {
        Privileges = NULL;
        if (SeAccessCheck(Sd, Subject, FALSE, Desired, 0, &Privileges, &AdMappings[0], UserMode, &Granted, &AccessStatus))
            Passed++;
        if (Privileges)
            SeFreePrivileges(Privileges);
    }
    End = KeQueryPerformanceCounter(NULL);

    Ns = (ULONGLONG)(End.QuadPart - Start.QuadPart) * 1000000000ULL / (ULONGLONG)Frequency.QuadPart;
    trace("ORBENCH %s: %lu calls, %lu granted, %I64u ns total, %I64u ps/call\n",
          Name, Loops, Passed, Ns, Ns * 1000ULL / Loops);
}

/*
 * Cost of SeAccessCheck for the owner on DACLs with an OWNER RIGHTS ACE (the check
 * that finds one is the slow case of the scan folded into the DACL walk): the ACE first
 * or last in a DACL of five. Not run with the others (trace only).
 */
START_TEST(SeAccessCheckDifferentialPerf)
{
    SECURITY_SUBJECT_CONTEXT Subject;
    PTOKEN_USER UserInfo = NULL;
    PACCESS_TOKEN Token;
    NTSTATUS Status;
    AD_SD *First, *Last;
    ULONG i, Round;
    /* SYSTEM, Administrators, user, Everyone and OWNER RIGHTS: SYSTEM is the local service SID here (any other SID) */
    static const UCHAR Order[2][5] =
    {
        { AD_SID_OW, AD_SID_OTHER, AD_SID_ADMINS, AD_SID_USER, AD_SID_WORLD },
        { AD_SID_OTHER, AD_SID_ADMINS, AD_SID_USER, AD_SID_WORLD, AD_SID_OW }
    };

    SeCaptureSubjectContext(&Subject);
    Token = SeQuerySubjectContextToken(&Subject);
    Status = SeQueryInformationToken(Token, TokenUser, (PVOID*)&UserInfo);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status) && UserInfo, "No token user\n"))
    {
        SeReleaseSubjectContext(&Subject);
        return;
    }

    AdSids[AD_SID_OW] = &AdOwnerRightsSid;
    AdSids[AD_SID_USER] = UserInfo->User.Sid;
    AdSids[AD_SID_WORLD] = SeExports->SeWorldSid;
    AdSids[AD_SID_OTHER] = SeExports->SeLocalServiceSid;
    AdSids[AD_SID_ADMINS] = SeExports->SeAliasAdminsSid;

    First = ExAllocatePoolWithTag(PagedPool, sizeof(*First), 'dAmK');
    Last = ExAllocatePoolWithTag(PagedPool, sizeof(*Last), 'dAmK');
    if (!skip(First != NULL && Last != NULL, "No memory\n"))
    {
        for (Round = 0; Round < 2; Round++)
        {
            AD_SD *AdSd = Round ? Last : First;
            PACL Acl = (PACL)AdSd->AclBuffer;

            RtlCreateAcl(Acl, AD_ACL_SIZE, ACL_REVISION4);
            Acl->AclSize = sizeof(ACL);
            for (i = 0; i < 5; i++)
            {
                AD_ACE Ace;

                Ace.Type = AD_A_ALLOW;
                Ace.Flags = 0;
                Ace.SidIndex = Order[Round][i];
                Ace.Mask = (Ace.SidIndex == AD_SID_OW || Ace.SidIndex == AD_SID_WORLD) ? 0x80000000 : 0x10000000;
                AdAppendAce(Acl, &Ace);
            }
            RtlCreateSecurityDescriptor(&AdSd->Sd, SECURITY_DESCRIPTOR_REVISION);
            RtlSetOwnerSecurityDescriptor(&AdSd->Sd, AdSids[AD_SID_USER], FALSE);
            RtlSetGroupSecurityDescriptor(&AdSd->Sd, AdSids[AD_SID_USER], FALSE);
            RtlSetDaclSecurityDescriptor(&AdSd->Sd, TRUE, Acl, FALSE);
        }

        for (Round = 0; Round < 3; Round++)
        {
            AdBench(&Subject, "ow-first-RC", &First->Sd, AD_RC);
            AdBench(&Subject, "ow-first-RC|1", &First->Sd, AD_RC | 1);
            AdBench(&Subject, "ow-first-MAX", &First->Sd, MAXIMUM_ALLOWED);
            AdBench(&Subject, "ow-last-RC", &Last->Sd, AD_RC);
            AdBench(&Subject, "ow-last-RC|1", &Last->Sd, AD_RC | 1);
            AdBench(&Subject, "ow-last-MAX", &Last->Sd, MAXIMUM_ALLOWED);
        }
    }

    if (First)
        ExFreePoolWithTag(First, 'dAmK');
    if (Last)
        ExFreePoolWithTag(Last, 'dAmK');
    ExFreePool(UserInfo);
    SeReleaseSubjectContext(&Subject);
}
