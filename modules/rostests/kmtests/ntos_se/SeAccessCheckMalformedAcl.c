/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SeAccessCheck with DACLs that RtlValidAcl would refuse, and with large DACLs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * SeAccessCheck takes the descriptor of its kernel-mode caller as it is: one that a file
 * system read from the disk is not validated again. Its DACL walk takes, for each index,
 * the ACE RtlGetAce gives. These rows fix what it does with malformed DACLs whose every
 * index RtlGetAce resolves (ACEs of size 0, sizes that are not a multiple of 4, an ACE that
 * runs past AclSize, an AceCount larger than the ACEs that fit, with slack in the ACL): the
 * same before and after the walk became one pass. A DACL where RtlGetAce fails for an index
 * (an ACE at or beyond AclSize, a bad revision) makes the checked kernel assert, before as
 * after; the free kernel stops the walk there (before, it read the memory behind the ACL):
 * that row runs on free builds only.
 *
 * The matrix: MA_MATRIX pseudo-random malformed DACLs (fixed seed, only shapes whose every
 * index RtlGetAce resolves and whose ACEs lie within the test's buffer), each checked for
 * five desired accesses; the hash of the results is compared with the value of the kernel
 * before the change (MA_MATRIX_GOLDEN). SeAccessCheckLargeDaclPerf (hidden) prints the cost
 * of one check against DACLs of 2 to about 3 270 ACEs.
 */

#include <kmt_test.h>

static GENERIC_MAPPING MaMapping =
{
    STANDARD_RIGHTS_READ    | 0x0001,
    STANDARD_RIGHTS_WRITE   | 0x0002,
    STANDARD_RIGHTS_EXECUTE | 0x0004,
    STANDARD_RIGHTS_ALL     | 0x0007,
};

#define MA_BUFFER       1024
#define MA_MATRIX       4000
#define MA_MATRIX_SEED  0x5eed1234UL
/* Rows and hash of the matrix on the kernel before the one-pass walk (main 7d343f320d1) */
#define MA_MATRIX_GOLDEN_ROWS   17955UL
#define MA_MATRIX_GOLDEN_HASH   0x5bcb9997UL

typedef struct _MA_SD
{
    SECURITY_DESCRIPTOR Sd;
    ULONG_PTR Align;
    UCHAR Buffer[MA_BUFFER];
} MA_SD, *PMA_SD;

static PSID MaWorld, MaOther;
static SID MaOtherSid = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_LOCAL_SERVICE_RID } };

/* An ACE at Offset of the buffer: header, mask, SID (no size check: the rows make malformed ACLs on purpose) */
static
VOID
MaPutAce(
    _Inout_ PUCHAR Buffer,
    _In_ ULONG Offset,
    _In_ UCHAR Type,
    _In_ USHORT AceSize,
    _In_ ACCESS_MASK Mask,
    _In_ PSID Sid)
{
    PACCESS_ALLOWED_ACE Ace = (PACCESS_ALLOWED_ACE)(Buffer + Offset);

    Ace->Header.AceType = Type;
    Ace->Header.AceFlags = 0;
    Ace->Header.AceSize = AceSize;
    RtlCopyMemory(&Ace->Mask, &Mask, sizeof(Mask));
    RtlCopyMemory((PUCHAR)Ace + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart), Sid, RtlLengthSid(Sid));
}

static
VOID
MaInitSd(
    _Out_ PMA_SD MaSd,
    _In_ USHORT AclSize,
    _In_ USHORT AceCount,
    _In_ UCHAR Revision)
{
    PACL Acl = (PACL)MaSd->Buffer;

    RtlZeroMemory(MaSd, sizeof(*MaSd));
    Acl->AclRevision = Revision;
    Acl->AclSize = AclSize;
    Acl->AceCount = AceCount;
    RtlCreateSecurityDescriptor(&MaSd->Sd, SECURITY_DESCRIPTOR_REVISION);
    /* An owner the caller is not: no implicit owner rights */
    RtlSetOwnerSecurityDescriptor(&MaSd->Sd, MaOther, FALSE);
    RtlSetGroupSecurityDescriptor(&MaSd->Sd, MaOther, FALSE);
    RtlSetDaclSecurityDescriptor(&MaSd->Sd, TRUE, Acl, FALSE);
}

static
BOOLEAN
MaCheck(
    _In_ PSECURITY_SUBJECT_CONTEXT SubjectContext,
    _In_ PMA_SD MaSd,
    _In_ ACCESS_MASK Desired,
    _Out_ PACCESS_MASK Granted,
    _Out_ PNTSTATUS AccessStatus)
{
    PPRIVILEGE_SET Privileges = NULL;
    BOOLEAN Result;

    *Granted = 0xdeadbeef;
    *AccessStatus = 0xdeadbeef;
    Result = SeAccessCheck(&MaSd->Sd, SubjectContext, FALSE, Desired, 0, &Privileges, &MaMapping, UserMode,
                           Granted, AccessStatus);
    if (Privileges)
        SeFreePrivileges(Privileges);
    return Result;
}

#define MA_STRINGIZE(x) KMT_STRINGIZE(x)
#define MaExpect(Ctx, Sd, Desired, ExpResult, ExpGranted) MaExpect_(__FILE__ ":" MA_STRINGIZE(__LINE__), Ctx, Sd, Desired, ExpResult, ExpGranted)
static
VOID
MaExpect_(
    _In_ PCSTR FileAndLine,
    _In_ PSECURITY_SUBJECT_CONTEXT SubjectContext,
    _In_ PMA_SD MaSd,
    _In_ ACCESS_MASK Desired,
    _In_ BOOLEAN ExpectedResult,
    _In_ ACCESS_MASK ExpectedGranted)
{
    ACCESS_MASK Granted;
    NTSTATUS AccessStatus;
    BOOLEAN Result = MaCheck(SubjectContext, MaSd, Desired, &Granted, &AccessStatus);

    KmtOk(Result == ExpectedResult, FileAndLine, "desired 0x%lx: result %u, expected %u\n", Desired, Result, ExpectedResult);
    if (ExpectedResult)
    {
        KmtOk(Granted == ExpectedGranted, FileAndLine, "desired 0x%lx: granted 0x%lx, expected 0x%lx\n", Desired, Granted, ExpectedGranted);
        KmtOk(AccessStatus == STATUS_SUCCESS, FileAndLine, "desired 0x%lx: status 0x%lx\n", Desired, AccessStatus);
    }
    else
    {
        KmtOk(AccessStatus == STATUS_ACCESS_DENIED, FileAndLine, "desired 0x%lx: status 0x%lx\n", Desired, AccessStatus);
    }
}

/* The ACE RtlGetAce gives for every index of the ACL, and it lies (with a SID of up to 15 sub-authorities) in the buffer */
static
BOOLEAN
MaEveryIndexResolves(
    _In_ PMA_SD MaSd)
{
    PACL Acl = (PACL)MaSd->Buffer;
    PUCHAR Ace;
    ULONG i;

    for (i = 0; i < Acl->AceCount; i++)
    {
        if (!NT_SUCCESS(RtlGetAce(Acl, i, (PVOID *)&Ace)))
            return FALSE;
        if (Ace + sizeof(ACCESS_ALLOWED_OBJECT_ACE) + 2 * sizeof(GUID) + SECURITY_MAX_SID_SIZE > MaSd->Buffer + MA_BUFFER)
            return FALSE;
    }
    return TRUE;
}

static ULONG MaSeed;

static
ULONG
MaRandom(VOID)
{
    MaSeed = MaSeed * 1103515245UL + 12345UL;
    return (MaSeed >> 8) & 0xFFFFFF;
}

static
VOID
MaMatrix(
    _In_ PSECURITY_SUBJECT_CONTEXT SubjectContext,
    _In_ PSID User,
    _Out_ PULONG Rows,
    _Out_ PULONG Hash,
    _Out_ PULONG Skipped)
{
    static const ACCESS_MASK Desired[] = { 0x1, 0x2, 0x3, READ_CONTROL, MAXIMUM_ALLOWED };
    static const UCHAR Types[] = { ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                                   ACCESS_DENIED_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, 0x7f };
    PMA_SD MaSd;
    PSID Sids[3];
    ULONG n, i, d, Offset, Count;
    ACCESS_MASK Granted;
    NTSTATUS AccessStatus;
    BOOLEAN Result;

    *Rows = 0;
    *Hash = 2166136261UL;
    *Skipped = 0;
    MaSd = ExAllocatePoolWithTag(NonPagedPool, sizeof(*MaSd), 'aMmK');
    if (!MaSd)
        return;
    Sids[0] = MaWorld;
    Sids[1] = User;
    Sids[2] = MaOther;
    MaSeed = MA_MATRIX_SEED;

    for (n = 0; n < MA_MATRIX; n++)
    {
        Count = 1 + MaRandom() % 6;
        MaInitSd(MaSd, 0, 0, ACL_REVISION);
        Offset = sizeof(ACL);
        for (i = 0; i < Count; i++)
        {
            PSID Sid = Sids[MaRandom() % 3];
            USHORT Size = (USHORT)(FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(Sid));
            ULONG Shape = MaRandom() % 8;

            /* the size the ACE claims: right, 0, odd, a little short or long */
            if (Shape == 1) Size = 0;
            else if (Shape == 2) Size = (USHORT)(Size + 1 + MaRandom() % 3);
            else if (Shape == 3) Size = (USHORT)(MaRandom() % Size);
            else if (Shape == 4) Size = (USHORT)(Size + 4 + MaRandom() % 16);
            MaPutAce(MaSd->Buffer, Offset, Types[MaRandom() % RTL_NUMBER_OF(Types)], Size,
                     (MaRandom() & 1) ? (0x1 << (MaRandom() % 3)) : (0x3 | READ_CONTROL), Sid);
            Offset += (Size ? Size : FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(Sid));
            if (Offset > 600)
                break;
        }
        /* AclSize: what the ACEs take, or a little less (the last runs past it) or more (slack); AceCount: maybe more */
        switch (MaRandom() % 4)
        {
            case 0: ((PACL)MaSd->Buffer)->AclSize = (USHORT)Offset; break;
            case 1: ((PACL)MaSd->Buffer)->AclSize = (USHORT)(Offset - min(Offset - sizeof(ACL) - 1, 1 + MaRandom() % 12)); break;
            default: ((PACL)MaSd->Buffer)->AclSize = (USHORT)(Offset + MaRandom() % 32); break;
        }
        ((PACL)MaSd->Buffer)->AceCount = (USHORT)(Count + ((MaRandom() % 3 == 0) ? MaRandom() % 4 : 0));

        if (!MaEveryIndexResolves(MaSd))
        {
            (*Skipped)++;
            continue;
        }

        for (d = 0; d < RTL_NUMBER_OF(Desired); d++)
        {
            Result = MaCheck(SubjectContext, MaSd, Desired[d], &Granted, &AccessStatus);
            *Hash = (*Hash ^ (Result ? 1 : 0)) * 16777619UL;
            *Hash = (*Hash ^ (Result ? Granted : 0)) * 16777619UL;
            *Hash = (*Hash ^ (ULONG)AccessStatus) * 16777619UL;
            (*Rows)++;
        }
    }
    ExFreePoolWithTag(MaSd, 'aMmK');
}

START_TEST(SeAccessCheckMalformedAcl)
{
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PTOKEN_USER UserInfo = NULL;
    PMA_SD MaSd;
    PSID World;
    ULONG Rows, Hash, Skipped;
    USHORT Ace;
    NTSTATUS Status;

    SeCaptureSubjectContext(&SubjectContext);
    Status = SeQueryInformationToken(SeQuerySubjectContextToken(&SubjectContext), TokenUser, (PVOID *)&UserInfo);
    ok_eq_hex(Status, STATUS_SUCCESS);
    MaSd = ExAllocatePoolWithTag(NonPagedPool, sizeof(*MaSd), 'aMmK');
    if (skip(NT_SUCCESS(Status) && UserInfo && MaSd, "No token user or memory\n"))
        goto done;

    World = MaWorld = SeExports->SeWorldSid;
    MaOther = &MaOtherSid;
    Ace = (USHORT)(FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(World));   /* 20 */

    /* 1. Well formed: Everyone 0x1 */
    MaInitSd(MaSd, sizeof(ACL) + Ace, 1, ACL_REVISION);
    MaPutAce(MaSd->Buffer, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, World);
    MaExpect(&SubjectContext, MaSd, 0x1, TRUE, 0x1);
    MaExpect(&SubjectContext, MaSd, 0x2, FALSE, 0);
    MaExpect(&SubjectContext, MaSd, MAXIMUM_ALLOWED, TRUE, 0x1);

    /* 2. An allow ACE of size 0, AceCount 2: every index gives the same ACE, which grants */
    MaInitSd(MaSd, sizeof(ACL) + Ace, 2, ACL_REVISION);
    MaPutAce(MaSd->Buffer, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, 0, 0x1, World);
    MaExpect(&SubjectContext, MaSd, 0x1, TRUE, 0x1);
    MaExpect(&SubjectContext, MaSd, MAXIMUM_ALLOWED, TRUE, 0x1);

    /* 3. A deny ACE of size 0 */
    MaInitSd(MaSd, sizeof(ACL) + Ace, 3, ACL_REVISION);
    MaPutAce(MaSd->Buffer, sizeof(ACL), ACCESS_DENIED_ACE_TYPE, 0, 0x1, World);
    MaExpect(&SubjectContext, MaSd, 0x1, FALSE, 0);
    MaExpect(&SubjectContext, MaSd, MAXIMUM_ALLOWED, FALSE, 0);

    /* 4. AceSize 22 (not a multiple of 4): the next ACE starts at offset 30 and counts */
    MaInitSd(MaSd, sizeof(ACL) + 22 + Ace, 2, ACL_REVISION);
    MaPutAce(MaSd->Buffer, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, 22, 0x2, World);
    MaPutAce(MaSd->Buffer, sizeof(ACL) + 22, ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, World);
    MaExpect(&SubjectContext, MaSd, 0x1, TRUE, 0x1);
    MaExpect(&SubjectContext, MaSd, 0x3, TRUE, 0x3);
    MaExpect(&SubjectContext, MaSd, MAXIMUM_ALLOWED, TRUE, 0x3);

    /* 5. The same with a deny first: denied */
    MaInitSd(MaSd, sizeof(ACL) + 22 + Ace, 2, ACL_REVISION);
    MaPutAce(MaSd->Buffer, sizeof(ACL), ACCESS_DENIED_ACE_TYPE, 22, 0x1, World);
    MaPutAce(MaSd->Buffer, sizeof(ACL) + 22, ACCESS_ALLOWED_ACE_TYPE, Ace, 0x3, World);
    MaExpect(&SubjectContext, MaSd, 0x1, FALSE, 0);
    MaExpect(&SubjectContext, MaSd, 0x2, TRUE, 0x2);
    MaExpect(&SubjectContext, MaSd, MAXIMUM_ALLOWED, TRUE, 0x2);

    /* 6. Truncated: the only ACE starts inside the ACL and runs 4 bytes past AclSize (its SID's last bytes): it counts */
    MaInitSd(MaSd, sizeof(ACL) + Ace - 4, 1, ACL_REVISION);
    MaPutAce(MaSd->Buffer, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, World);
    MaExpect(&SubjectContext, MaSd, 0x1, TRUE, 0x1);

    /* 7. AceCount 3, one ACE and 12 bytes of zeros in the ACL: the zero ACE (size 0) is evaluated twice and grants nothing */
    MaInitSd(MaSd, sizeof(ACL) + Ace + 12, 3, ACL_REVISION);
    MaPutAce(MaSd->Buffer, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, World);
    MaExpect(&SubjectContext, MaSd, 0x1, TRUE, 0x1);
    MaExpect(&SubjectContext, MaSd, 0x2, FALSE, 0);
    MaExpect(&SubjectContext, MaSd, MAXIMUM_ALLOWED, TRUE, 0x1);

    /* 8. An ACE of size 4 (shorter than an ACE): the next index starts at its mask */
    MaInitSd(MaSd, sizeof(ACL) + Ace + Ace, 2, ACL_REVISION);
    MaPutAce(MaSd->Buffer, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, 4, 0x1, World);
    MaPutAce(MaSd->Buffer, sizeof(ACL) + Ace, ACCESS_ALLOWED_ACE_TYPE, Ace, 0x2, World);
    MaExpect(&SubjectContext, MaSd, 0x1, TRUE, 0x1);
    MaExpect(&SubjectContext, MaSd, 0x2, FALSE, 0);

#if !DBG
    /* 9. AceCount 2, one ACE that ends exactly at AclSize: index 1 is not an ACE (RtlGetAce fails; a checked kernel asserts) */
    MaInitSd(MaSd, sizeof(ACL) + Ace, 2, ACL_REVISION);
    MaPutAce(MaSd->Buffer, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, World);
    MaExpect(&SubjectContext, MaSd, 0x1, TRUE, 0x1);
    MaExpect(&SubjectContext, MaSd, MAXIMUM_ALLOWED, TRUE, 0x1);
#endif

    /* The matrix */
    MaMatrix(&SubjectContext, UserInfo->User.Sid, &Rows, &Hash, &Skipped);
    trace("MAMATRIX rows %lu hash 0x%08lx skipped %lu\n", Rows, Hash, Skipped);
    if (MA_MATRIX_GOLDEN_ROWS != 0)
    {
        ok(Rows == MA_MATRIX_GOLDEN_ROWS, "matrix rows %lu, expected %lu\n", Rows, MA_MATRIX_GOLDEN_ROWS);
        ok(Hash == MA_MATRIX_GOLDEN_HASH, "matrix hash 0x%08lx, expected 0x%08lx\n", Hash, MA_MATRIX_GOLDEN_HASH);
    }

done:
    if (MaSd)
        ExFreePoolWithTag(MaSd, 'aMmK');
    if (UserInfo)
        ExFreePool(UserInfo);
    SeReleaseSubjectContext(&SubjectContext);
}

/* The cost of one check against a DACL: the caller's user full, then N allow ACEs for SIDs nobody has */
START_TEST(SeAccessCheckLargeDaclPerf)
{
    static const ULONG Counts[] = { 0, 100, 1700, 3270 };
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PTOKEN_USER UserInfo = NULL;
    PSECURITY_DESCRIPTOR Sd;
    PACL Acl;
    SID Unknown = { SID_REVISION, 1, { {0, 0, 0, 0, 0, 9} }, { 0 } };
    LARGE_INTEGER Frequency, Start, End;
    ULONG c, i, Loops, Passed;
    ACCESS_MASK Granted;
    NTSTATUS Status, AccessStatus;
    PPRIVILEGE_SET Privileges;

    SeCaptureSubjectContext(&SubjectContext);
    Status = SeQueryInformationToken(SeQuerySubjectContextToken(&SubjectContext), TokenUser, (PVOID *)&UserInfo);
    Sd = ExAllocatePoolWithTag(PagedPool, sizeof(SECURITY_DESCRIPTOR) + 0xFFFC, 'aMmK');
    if (skip(NT_SUCCESS(Status) && UserInfo && Sd, "No token user or memory\n"))
        goto done;
    Acl = (PACL)((PUCHAR)Sd + sizeof(SECURITY_DESCRIPTOR));

    for (c = 0; c < RTL_NUMBER_OF(Counts); c++)
    {
        RtlCreateAcl(Acl, 0xFFFC, ACL_REVISION);
        RtlAddAccessAllowedAce(Acl, ACL_REVISION, 0x3, UserInfo->User.Sid);
        for (i = 0; i < Counts[c]; i++)
        {
            Unknown.SubAuthority[0] = 1000 + i;
            if (!NT_SUCCESS(RtlAddAccessAllowedAce(Acl, ACL_REVISION, 0x1, &Unknown)))
                break;
        }
        RtlCreateSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
        RtlSetOwnerSecurityDescriptor(Sd, &MaOtherSid, FALSE);
        RtlSetGroupSecurityDescriptor(Sd, &MaOtherSid, FALSE);
        RtlSetDaclSecurityDescriptor(Sd, TRUE, Acl, FALSE);

        Loops = Counts[c] > 1000 ? 200 : 20000;
        Passed = 0;
        Start = KeQueryPerformanceCounter(&Frequency);
        for (i = 0; i < Loops; i++)
        {
            Privileges = NULL;
            if (SeAccessCheck(Sd, &SubjectContext, FALSE, 0x1, 0, &Privileges, &MaMapping, UserMode, &Granted, &AccessStatus))
                Passed++;
            if (Privileges)
                SeFreePrivileges(Privileges);
        }
        End = KeQueryPerformanceCounter(NULL);
        trace("MAPERF aces %u aclsize %u loops %lu granted %lu ns-per-check %I64u\n", Acl->AceCount, Acl->AclSize, Loops,
              Passed, (ULONGLONG)(End.QuadPart - Start.QuadPart) * 1000000000ULL / (ULONGLONG)Frequency.QuadPart / Loops);
    }

done:
    if (Sd)
        ExFreePoolWithTag(Sd, 'aMmK');
    if (UserInfo)
        ExFreePool(UserInfo);
    SeReleaseSubjectContext(&SubjectContext);
}
