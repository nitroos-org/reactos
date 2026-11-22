/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Differential test of the access check: AccessCheck, AccessCheckByType and
 *              AccessCheckByTypeResultList over a generated matrix of descriptors, tokens
 *              and desired accesses. By default it runs a small sample of the matrix and
 *              compares the hash of the results with a stored one. With the environment
 *              variable ACCESSCHECK_DIFFERENTIAL=full it runs the whole matrix and only prints
 *              the results (a hash per section and the rows of the first descriptors), so
 *              that the output of two kernels can be compared byte for byte.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Matrix: descriptors x owners x tokens x desired accesses x call kinds.
 *
 * Descriptors: no DACL (NULL), an empty DACL, all DACLs of one or two ACEs from a reduced
 * alphabet, and a fixed number of pseudo-random DACLs of one to six ACEs from the full
 * alphabet (generated with a fixed seed). An ACE has a type (allow, deny, object allow or
 * deny without and with an object type, with an inherited object type, callback and audit
 * types the check does not evaluate), flags (none, INHERIT_ONLY, inheritance and INHERITED),
 * a SID (OWNER RIGHTS, the token user, Everyone, another SID, Administrators) and a mask.
 *
 * Owners: the token user, another SID, Administrators (a group of the token).
 * Tokens: the plain one, restricted to {user, Everyone}, to {Everyone}, to {OWNER RIGHTS},
 * and one with Administrators set to deny-only.
 *
 * Default run (quiet): a sample of the descriptors, the first DACLS_SAMPLE_HEAD and then every
 * DACLS_SAMPLE_STRIDE-th one, every owner, token, call kind and desired access of those. The
 * total hash is compared with SAMPLE_GOLDEN_HASH by ok(); it is the same on x64, x86 (WoW64
 * or native) and i386. It assumes the usual test token: an administrator (the user is a member
 * of Administrators). A change of the access check that alters any result of the sample fails
 * the test. If the change is meant, run the full matrix before and after, compare the output
 * (below) and replace the golden values with the new total of the sample.
 *
 * Full run: ACCESSCHECK_DIFFERENTIAL=full (set in the shell that starts the test), e.g.
 *     set ACCESSCHECK_DIFFERENTIAL=full
 *     advapi32_apitest.exe AccessCheckDifferential > full.txt
 * It checks nothing itself. Output: "section <d> <o> <t> <k> <rows> <hash>" for every (owner,
 * token, kind), a total line, and "row" lines for the first DACLS_VERBOSE descriptors. Rows:
 * descriptor, owner, token, kind, desired, then return value, error (when it failed), granted
 * access and status of every result. Run it with the kernel before and after the change and
 * compare the two outputs (the section hashes, or every line). On a checked i386 build boot
 * with /NODEBUG: the kernel prints a line and a dump for each denial, millions of them.
 */

/* Sample mode: descriptors run and the expected result */
#define DACLS_SAMPLE_HEAD   4
#define DACLS_SAMPLE_STRIDE 389
#define SAMPLE_GOLDEN_ROWS  42480UL
/* The rows with a DesiredAccess of 0 are denied (as on Windows Server 2022): before that change 0xba617c3863a2ebba */
#define SAMPLE_GOLDEN_HASH  0x4b8d4b8864de503aULL

#define RC READ_CONTROL
#define WD WRITE_DAC

#define EXHAUSTIVE_TYPES    4
#define EXHAUSTIVE_FLAGS    2
#define EXHAUSTIVE_SIDS     3
#define EXHAUSTIVE_MASKS    4
#define RANDOM_DACLS        2500
#define DACLS_VERBOSE       160
#define MAX_ACES            6
#define MAX_ACL_SIZE        1024

enum { SID_OW, SID_USER, SID_EVERYONE, SID_OTHER, SID_ADMINS, SID_COUNT };
enum { TOKEN_PLAIN, TOKEN_RESTR_USER_EVERYONE, TOKEN_RESTR_EVERYONE, TOKEN_RESTR_OW, TOKEN_DENYONLY_ADMINS, TOKEN_ENABLED_PRIVS, TOKEN_COUNT };
enum { OWNER_USER, OWNER_OTHER, OWNER_ADMINS, OWNER_COUNT };
enum { CALL_PLAIN, CALL_BYTYPE_NOLIST, CALL_BYTYPE_LIST, CALL_RESULTLIST, CALL_COUNT };

/* ACE types of the matrix */
enum
{
    A_ALLOW, A_DENY,
    A_OBJ_ALLOW, A_OBJ_DENY,                    /* object ACEs without a GUID */
    A_OBJ_ALLOW_ROOT, A_OBJ_DENY_ROOT,          /* with the object type of the list root */
    A_OBJ_ALLOW_CHILD, A_OBJ_DENY_CHILD,        /* with the object type of the second entry */
    A_OBJ_ALLOW_UNKNOWN, A_OBJ_DENY_UNKNOWN,    /* with an object type not in the list */
    A_OBJ_ALLOW_INH, A_OBJ_DENY_INH,            /* only an inherited object type */
    A_OBJ_ALLOW_BOTH,                           /* object type and inherited object type */
    A_CALLBACK_ALLOW, A_CALLBACK_DENY,          /* callback types (not evaluated) */
    A_AUDIT,                                    /* a SACL type in a DACL */
    A_TYPE_COUNT
};

typedef struct
{
    UCHAR Type;
    UCHAR Flags;
    UCHAR SidIndex;
    ACCESS_MASK Mask;
} ACE_DESC;

typedef struct
{
    BOOLEAN HasDacl;
    ULONG AceCount;
    ACE_DESC Aces[MAX_ACES];
} DACL_DESC;

static const GENERIC_MAPPING Mappings[2] =
{
    { STANDARD_RIGHTS_READ | 1, STANDARD_RIGHTS_WRITE | 2, STANDARD_RIGHTS_EXECUTE | 4, STANDARD_RIGHTS_ALL | 7 },
    { STANDARD_RIGHTS_READ | 1, STANDARD_RIGHTS_WRITE | 2, STANDARD_RIGHTS_EXECUTE | 4, STANDARD_RIGHTS_ALL | 0x1f }
};

static const ACCESS_MASK AllMasks[] =
{
    RC, WD, RC | WD, 1, 2, RC | 1, WD | 2, RC | WD | 1, 4, 0x80000000 /* GENERIC_READ */,
    0x10000000 /* GENERIC_ALL */, 0x1f, MAXIMUM_ALLOWED, 0, SYNCHRONIZE | 1
};

static const ACCESS_MASK ReducedMasks[EXHAUSTIVE_MASKS] = { RC, WD | 1, 1, RC | WD | 2 };

static const ACCESS_MASK DesiredList[] =
{
    0, RC, WD, RC | WD, MAXIMUM_ALLOWED, 1, RC | 1, WD | 2, RC | WD | 1, MAXIMUM_ALLOWED | 1,
    SYNCHRONIZE | 4, ACCESS_SYSTEM_SECURITY, WRITE_OWNER, RC | WRITE_OWNER, RC | 1 | ACCESS_SYSTEM_SECURITY,
    WD | WRITE_OWNER | 2, MAXIMUM_ALLOWED | WRITE_OWNER,
    /*
     * Generic rights in the request: the system calls refuse them (the caller maps them first), and a
     * checked kernel prints a line for each refusal, so only the first descriptors get these rows
     */
    0x80000000 /* GENERIC_READ */, 0x10000000 /* GENERIC_ALL */, 0x80000000 | RC
};

#define GENERIC_DESIRED_ROWS 3

static const UCHAR ReducedTypes[EXHAUSTIVE_TYPES] = { A_ALLOW, A_DENY, A_OBJ_ALLOW_ROOT, A_OBJ_DENY };
static const UCHAR ReducedFlags[EXHAUSTIVE_FLAGS] = { 0, INHERIT_ONLY_ACE };
static const UCHAR ReducedSids[EXHAUSTIVE_SIDS] = { SID_OW, SID_USER, SID_EVERYONE };
static const UCHAR AllFlags[] = { 0, 0, 0, INHERIT_ONLY_ACE, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE, INHERITED_ACE, INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE };

static GUID RootGuid = { 0x5d2f8a31, 0x41c7, 0x4b0e, { 0x8e, 0x33, 0x52, 0x0c, 0x6a, 0x10, 0x00, 0x01 } };
static GUID ChildGuid = { 0x5d2f8a31, 0x41c7, 0x4b0e, { 0x8e, 0x33, 0x52, 0x0c, 0x6a, 0x10, 0x00, 0x02 } };
static GUID OtherGuid = { 0x5d2f8a31, 0x41c7, 0x4b0e, { 0x8e, 0x33, 0x52, 0x0c, 0x6a, 0x10, 0x00, 0x03 } };

static PSID Sids[SID_COUNT];
static HANDLE Tokens[TOKEN_COUNT];
static ULONGLONG Rng = 0x9e3779b97f4a7c15ULL;

static ULONG NextRandom(ULONG Modulus)
{
    /* xorshift64*: fixed seed, so every run builds the same matrix */
    Rng ^= Rng >> 12;
    Rng ^= Rng << 25;
    Rng ^= Rng >> 27;
    return (ULONG)(((Rng * 0x2545f4914f6cdd1dULL) >> 33) % Modulus);
}

static void Fnv(ULONGLONG *Hash, ULONG Value)
{
    int i;

    for (i = 0; i < 4; i++)
    {
        *Hash ^= (UCHAR)(Value >> (i * 8));
        *Hash *= 0x100000001b3ULL;
    }
}

/* Appends one ACE; returns FALSE if it does not fit */
static BOOL AppendAce(PACL Acl, const ACE_DESC *Desc)
{
    PUCHAR Ace = (PUCHAR)Acl + Acl->AclSize;
    PUCHAR Cursor;
    PSID Sid = Sids[Desc->SidIndex];
    ULONG SidLength = GetLengthSid(Sid);
    ULONG ObjectFlags = 0;
    const GUID *ObjectType = NULL, *InheritedType = NULL;
    UCHAR Type;
    BOOL IsObject = FALSE;
    ULONG Size;

    switch (Desc->Type)
    {
        case A_ALLOW: Type = ACCESS_ALLOWED_ACE_TYPE; break;
        case A_DENY: Type = ACCESS_DENIED_ACE_TYPE; break;
        case A_CALLBACK_ALLOW: Type = ACCESS_ALLOWED_CALLBACK_ACE_TYPE; break;
        case A_CALLBACK_DENY: Type = ACCESS_DENIED_CALLBACK_ACE_TYPE; break;
        case A_AUDIT: Type = SYSTEM_AUDIT_ACE_TYPE; break;
        default:
            IsObject = TRUE;
            Type = (Desc->Type & 1) ? ACCESS_DENIED_OBJECT_ACE_TYPE : ACCESS_ALLOWED_OBJECT_ACE_TYPE;
            switch (Desc->Type)
            {
                case A_OBJ_ALLOW_ROOT: case A_OBJ_DENY_ROOT: ObjectType = &RootGuid; break;
                case A_OBJ_ALLOW_CHILD: case A_OBJ_DENY_CHILD: ObjectType = &ChildGuid; break;
                case A_OBJ_ALLOW_UNKNOWN: case A_OBJ_DENY_UNKNOWN: ObjectType = &OtherGuid; break;
                case A_OBJ_ALLOW_INH: case A_OBJ_DENY_INH: InheritedType = &OtherGuid; break;
                case A_OBJ_ALLOW_BOTH: ObjectType = &RootGuid; InheritedType = &OtherGuid; break;
                default: break;
            }
            break;
    }

    if (IsObject)
    {
        Size = 4 + 4 + 4 + (ObjectType ? sizeof(GUID) : 0) + (InheritedType ? sizeof(GUID) : 0) + SidLength;
    }
    else
    {
        Size = 4 + 4 + SidLength;
    }
    if ((ULONG)Acl->AclSize + Size > MAX_ACL_SIZE)
        return FALSE;

    Ace[0] = Type;
    Ace[1] = Desc->Flags;
    *(PUSHORT)(Ace + 2) = (USHORT)Size;
    *(PULONG)(Ace + 4) = Desc->Mask;
    Cursor = Ace + 8;
    if (IsObject)
    {
        if (ObjectType)
            ObjectFlags |= ACE_OBJECT_TYPE_PRESENT;
        if (InheritedType)
            ObjectFlags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
        *(PULONG)Cursor = ObjectFlags;
        Cursor += 4;
        if (ObjectType)
        {
            memcpy(Cursor, ObjectType, sizeof(GUID));
            Cursor += sizeof(GUID);
        }
        if (InheritedType)
        {
            memcpy(Cursor, InheritedType, sizeof(GUID));
            Cursor += sizeof(GUID);
        }
    }
    memcpy(Cursor, Sid, SidLength);
    Acl->AclSize = (WORD)(Acl->AclSize + Size);
    Acl->AceCount++;
    return TRUE;
}

typedef struct
{
    ULONGLONG Hash;
    ULONG Rows;
} SECTION;

static SECTION Sections[OWNER_COUNT][TOKEN_COUNT][CALL_COUNT];
static ULONG Verbose;
static BOOL Full;

static void Record(SECTION *Section, ULONG Dacl, ULONG Owner, ULONG Token, ULONG Kind, ACCESS_MASK Desired,
                   BOOL Ret, DWORD Error, const DWORD *Granted, const DWORD *Status, int Entries,
                   const PRIVILEGE_SET *Privileges, DWORD PrivilegeSetLength)
{
    int i;
    ULONG Used = Ret ? Privileges->PrivilegeCount : 0;

    Fnv(&Section->Hash, Dacl);
    Fnv(&Section->Hash, Desired);
    Fnv(&Section->Hash, Ret);
    Fnv(&Section->Hash, Ret ? 0 : Error);
    /* The privileges the check used (ACCESS_SYSTEM_SECURITY, WRITE_OWNER) */
    Fnv(&Section->Hash, Used);
    Fnv(&Section->Hash, Ret ? PrivilegeSetLength : 0);
    for (i = 0; i < (int)Used && i < 2; i++)
        Fnv(&Section->Hash, Privileges->Privilege[i].Luid.LowPart);
    for (i = 0; i < Entries; i++)
    {
        Fnv(&Section->Hash, Ret ? Granted[i] : 0);
        Fnv(&Section->Hash, Ret ? Status[i] : 0);
    }
    Section->Rows++;

    if (Verbose)
    {
        printf("row %lu %lu %lu %lu %08lx %d %lu p%lu", Dacl, Owner, Token, Kind, Desired, Ret, Ret ? 0 : Error, Used);
        for (i = 0; i < Entries; i++)
            printf(" %08lx:%lu", Ret ? Granted[i] : 0, Ret ? Status[i] : 0);
        printf("\n");
    }
}

static void RunDescriptor(ULONG DaclIndex, const DACL_DESC *Desc)
{
    union { ACL Acl; BYTE Buffer[MAX_ACL_SIZE]; } AclBuffer;
    SECURITY_DESCRIPTOR Sd;
    union { PRIVILEGE_SET Set; ULONG_PTR Align; BYTE Buffer[256]; } PrivilegeSet;
    OBJECT_TYPE_LIST List[2];
    const GENERIC_MAPPING *Mapping = &Mappings[DaclIndex & 1];
    ULONG Owner, Token, Kind, d, i;
    ULONG OwnerIndex[OWNER_COUNT] = { SID_USER, SID_OTHER, SID_ADMINS };
    BOOL HaveAcl = FALSE;

    List[0].Level = ACCESS_OBJECT_GUID;
    List[0].Sbz = 0;
    List[0].ObjectType = &RootGuid;
    List[1].Level = ACCESS_PROPERTY_SET_GUID;
    List[1].Sbz = 0;
    List[1].ObjectType = &ChildGuid;

    /* The sample mode skips the descriptors in between (the generator still advances) */
    if (!Full && DaclIndex >= DACLS_SAMPLE_HEAD && DaclIndex % DACLS_SAMPLE_STRIDE != 0)
        return;

    Verbose = Full && DaclIndex < DACLS_VERBOSE;

    if (Desc->HasDacl)
    {
        if (!InitializeAcl(&AclBuffer.Acl, sizeof(AclBuffer), ACL_REVISION_DS))
        {
            ok(0, "InitializeAcl failed\n");
            return;
        }
        /* AclSize is the part in use from here on: the ACEs are appended to it */
        AclBuffer.Acl.AclSize = sizeof(ACL);
        for (i = 0; i < Desc->AceCount; i++)
        {
            if (!AppendAce(&AclBuffer.Acl, &Desc->Aces[i]))
            {
                ok(0, "ACE does not fit\n");
                return;
            }
        }
        HaveAcl = TRUE;
    }

    for (Owner = 0; Owner < OWNER_COUNT; Owner++)
    {
        InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorOwner(&Sd, Sids[OwnerIndex[Owner]], FALSE);
        SetSecurityDescriptorGroup(&Sd, Sids[OwnerIndex[Owner]], FALSE);
        SetSecurityDescriptorDacl(&Sd, HaveAcl, HaveAcl ? &AclBuffer.Acl : NULL, FALSE);

        for (Token = 0; Token < TOKEN_COUNT; Token++)
        {
            if (!Tokens[Token])
                continue;
            for (Kind = 0; Kind < CALL_COUNT; Kind++)
            {
                ULONG DesiredCount = sizeof(DesiredList) / sizeof(DesiredList[0]);

                if (!(Full ? DaclIndex < DACLS_VERBOSE : DaclIndex < DACLS_SAMPLE_HEAD))
                    DesiredCount -= GENERIC_DESIRED_ROWS;
                for (d = 0; d < DesiredCount; d++)
                {
                    DWORD Granted[2] = { 0xdeadbeef, 0xdeadbeef };
                    DWORD Status[2] = { 7, 7 };
                    DWORD PrivilegeSetLength = sizeof(PrivilegeSet);
                    ACCESS_MASK Desired = DesiredList[d];
                    BOOL Ret;
                    DWORD Error;
                    int Entries = 1;

                    SetLastError(0xdead);
                    switch (Kind)
                    {
                        case CALL_PLAIN:
                            Ret = AccessCheck(&Sd, Tokens[Token], Desired, (PGENERIC_MAPPING)Mapping,
                                              &PrivilegeSet.Set, &PrivilegeSetLength, &Granted[0], (PBOOL)&Status[0]);
                            break;
                        case CALL_BYTYPE_NOLIST:
                            Ret = AccessCheckByType(&Sd, NULL, Tokens[Token], Desired, NULL, 0, (PGENERIC_MAPPING)Mapping,
                                                    &PrivilegeSet.Set, &PrivilegeSetLength, &Granted[0], (PBOOL)&Status[0]);
                            break;
                        case CALL_BYTYPE_LIST:
                            Ret = AccessCheckByType(&Sd, NULL, Tokens[Token], Desired, List, 2, (PGENERIC_MAPPING)Mapping,
                                                    &PrivilegeSet.Set, &PrivilegeSetLength, &Granted[0], (PBOOL)&Status[0]);
                            break;
                        default:
                            Ret = AccessCheckByTypeResultList(&Sd, NULL, Tokens[Token], Desired, List, 2, (PGENERIC_MAPPING)Mapping,
                                                              &PrivilegeSet.Set, &PrivilegeSetLength, Granted, (void *)Status);
                            Entries = 2;
                            break;
                    }
                    Error = GetLastError();
                    Record(&Sections[Owner][Token][Kind], DaclIndex, Owner, Token, Kind, Desired, Ret, Error,
                           Granted, Status, Entries, &PrivilegeSet.Set, PrivilegeSetLength);
                }
            }
        }
    }
}

static void MakeTokens(void)
{
    HANDLE Process, Primary;
    SID_AND_ATTRIBUTES Restrict[2];
    SID_AND_ATTRIBUTES Disable[1];
    PTOKEN_USER User;
    DWORD Length = 0;
    SID_IDENTIFIER_AUTHORITY World = { SECURITY_WORLD_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY Creator = { SECURITY_CREATOR_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY Nt = { SECURITY_NT_AUTHORITY };
    ULONG t;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process))
    {
        skip("OpenProcessToken failed: %lu\n", GetLastError());
        return;
    }

    GetTokenInformation(Process, TokenUser, NULL, 0, &Length);
    User = HeapAlloc(GetProcessHeap(), 0, Length);
    ok(GetTokenInformation(Process, TokenUser, User, Length, &Length), "TokenUser failed\n");
    Sids[SID_USER] = User->User.Sid;
    ok(AllocateAndInitializeSid(&Creator, 1, 4, 0, 0, 0, 0, 0, 0, 0, &Sids[SID_OW]), "SID failed\n");
    ok(AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Sids[SID_EVERYONE]), "SID failed\n");
    ok(AllocateAndInitializeSid(&Nt, 1, SECURITY_LOCAL_SERVICE_RID, 0, 0, 0, 0, 0, 0, 0, &Sids[SID_OTHER]), "SID failed\n");
    ok(AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                &Sids[SID_ADMINS]), "SID failed\n");

    Restrict[0].Sid = Sids[SID_USER];
    Restrict[0].Attributes = 0;
    Restrict[1].Sid = Sids[SID_EVERYONE];
    Restrict[1].Attributes = 0;
    Disable[0].Sid = Sids[SID_ADMINS];
    Disable[0].Attributes = 0;

    ok(DuplicateToken(Process, SecurityImpersonation, &Tokens[TOKEN_PLAIN]), "DuplicateToken failed\n");
    for (t = TOKEN_RESTR_USER_EVERYONE; t < TOKEN_COUNT; t++)
    {
        BOOL Created = FALSE;

        Primary = NULL;
        switch (t)
        {
            case TOKEN_RESTR_USER_EVERYONE:
                Created = CreateRestrictedToken(Process, 0, 0, NULL, 0, NULL, 2, Restrict, &Primary);
                break;
            case TOKEN_RESTR_EVERYONE:
                Created = CreateRestrictedToken(Process, 0, 0, NULL, 0, NULL, 1, &Restrict[1], &Primary);
                break;
            case TOKEN_RESTR_OW:
            {
                SID_AND_ATTRIBUTES OwRestrict;
                OwRestrict.Sid = Sids[SID_OW];
                OwRestrict.Attributes = 0;
                Created = CreateRestrictedToken(Process, 0, 0, NULL, 0, NULL, 1, &OwRestrict, &Primary);
                break;
            }
            case TOKEN_DENYONLY_ADMINS:
                Created = CreateRestrictedToken(Process, 0, 1, Disable, 0, NULL, 0, NULL, &Primary);
                break;
            case TOKEN_ENABLED_PRIVS:
            {
                /* SeSecurityPrivilege and SeTakeOwnershipPrivilege enabled: ACCESS_SYSTEM_SECURITY and WRITE_OWNER */
                struct { DWORD PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[2]; } Privileges;

                Created = DuplicateTokenEx(Process, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                                           TokenImpersonation, &Primary);
                if (Created)
                {
                    Privileges.PrivilegeCount = 2;
                    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    Privileges.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
                    if (!LookupPrivilegeValueA(NULL, SE_SECURITY_NAME, &Privileges.Privileges[0].Luid) ||
                        !LookupPrivilegeValueA(NULL, SE_TAKE_OWNERSHIP_NAME, &Privileges.Privileges[1].Luid) ||
                        !AdjustTokenPrivileges(Primary, FALSE, (PTOKEN_PRIVILEGES)&Privileges, 0, NULL, NULL))
                    {
                        skip("enabling privileges failed: %lu\n", GetLastError());
                        CloseHandle(Primary);
                        Created = FALSE;
                        SetLastError(0);
                    }
                }
                break;
            }
        }
        if (!Created)
        {
            skip("CreateRestrictedToken %lu failed: %lu\n", t, GetLastError());
            continue;
        }
        ok(DuplicateToken(Primary, SecurityImpersonation, &Tokens[t]), "DuplicateToken failed\n");
        CloseHandle(Primary);
    }
    CloseHandle(Process);
}

START_TEST(AccessCheckDifferential)
{
    ULONG Owner, Token, Kind, Index = 0, a, b, c, i;
    ULONGLONG Total = 0;
    ULONG TotalRows = 0;
    DACL_DESC Desc;
    ULONG ExhaustiveAces = EXHAUSTIVE_TYPES * EXHAUSTIVE_FLAGS * EXHAUSTIVE_SIDS * EXHAUSTIVE_MASKS;
    ACE_DESC Pool[EXHAUSTIVE_TYPES * EXHAUSTIVE_FLAGS * EXHAUSTIVE_SIDS * EXHAUSTIVE_MASKS];

    char Mode[16];

    Full = GetEnvironmentVariableA("ACCESSCHECK_DIFFERENTIAL", Mode, sizeof(Mode)) > 0 &&
           !strcmp(Mode, "full");

    MakeTokens();
    if (!Tokens[TOKEN_PLAIN])
        return;

    /* No DACL, empty DACL */
    memset(&Desc, 0, sizeof(Desc));
    Desc.HasDacl = FALSE;
    RunDescriptor(Index++, &Desc);
    Desc.HasDacl = TRUE;
    RunDescriptor(Index++, &Desc);

    /* The reduced alphabet: every ACE */
    i = 0;
    for (a = 0; a < EXHAUSTIVE_TYPES; a++)
        for (b = 0; b < EXHAUSTIVE_FLAGS; b++)
            for (c = 0; c < EXHAUSTIVE_SIDS; c++)
            {
                ULONG m;
                for (m = 0; m < EXHAUSTIVE_MASKS; m++)
                {
                    Pool[i].Type = ReducedTypes[a];
                    Pool[i].Flags = ReducedFlags[b];
                    Pool[i].SidIndex = ReducedSids[c];
                    Pool[i].Mask = ReducedMasks[m];
                    i++;
                }
            }

    /* One ACE, then two */
    for (a = 0; a < ExhaustiveAces; a++)
    {
        Desc.AceCount = 1;
        Desc.Aces[0] = Pool[a];
        RunDescriptor(Index++, &Desc);
    }
    for (a = 0; a < ExhaustiveAces; a++)
    {
        for (b = 0; b < ExhaustiveAces; b++)
        {
            Desc.AceCount = 2;
            Desc.Aces[0] = Pool[a];
            Desc.Aces[1] = Pool[b];
            RunDescriptor(Index++, &Desc);
        }
    }

    /* Random: full alphabet, one to six ACEs */
    for (i = 0; i < RANDOM_DACLS; i++)
    {
        ULONG n = 1 + NextRandom(MAX_ACES);

        Desc.AceCount = n;
        for (a = 0; a < n; a++)
        {
            /* OWNER RIGHTS is picked more often than the others */
            ULONG SidPick = NextRandom(8);

            Desc.Aces[a].Type = (UCHAR)NextRandom(A_TYPE_COUNT);
            Desc.Aces[a].Flags = AllFlags[NextRandom(sizeof(AllFlags))];
            Desc.Aces[a].SidIndex = SidPick < 3 ? SID_OW : (UCHAR)(SidPick - 3);
            Desc.Aces[a].Mask = AllMasks[NextRandom(sizeof(AllMasks) / sizeof(AllMasks[0]))];
        }
        RunDescriptor(Index++, &Desc);
    }

    for (Owner = 0; Owner < OWNER_COUNT; Owner++)
        for (Token = 0; Token < TOKEN_COUNT; Token++)
            for (Kind = 0; Kind < CALL_COUNT; Kind++)
            {
                SECTION *Section = &Sections[Owner][Token][Kind];

                if (!Tokens[Token])
                    continue;
                if (Full)
                    printf("section %lu %lu %lu %lu %016I64x\n", Owner, Token, Kind, Section->Rows, Section->Hash);
                Total += Section->Hash;
                TotalRows += Section->Rows;
            }
    if (Full)
    {
        printf("total descriptors %lu rows %lu hash %016I64x\n", Index, TotalRows, Total);
    }
    else
    {
        ok(TotalRows == SAMPLE_GOLDEN_ROWS, "sample rows %lu, expected %lu\n", TotalRows, SAMPLE_GOLDEN_ROWS);
        ok(Total == SAMPLE_GOLDEN_HASH, "sample hash %016I64x, expected %016I64x\n", Total, (ULONGLONG)SAMPLE_GOLDEN_HASH);
    }
}
