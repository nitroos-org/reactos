/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite: key security descriptors stored in the hive
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A key gets a security descriptor when it is created: the parent's,
 * inherited, or the caller's explicit one. Keys with the same descriptor
 * share one 'sk' cell whose ReferenceCount is the number of keys that name
 * it; the last key to go frees it. Query still reports the legacy descriptor,
 * so this test looks at the hive itself: it loads a hive file of its own,
 * works in it, unloads it and reads the file back.
 *
 * The expected descriptors are the Windows 10 22H2 results for the same
 * create sequence (oracle probe of the registry ACL R3 slice):
 *  - inherited DACL ACEs carry no INHERITED_ACE; the DACL is not protected;
 *  - a CREATOR OWNER or generic ACE that is inherited by a container is split
 *    in place into an effective ACE (owner SID, mapped access, no inherit
 *    flags) followed by the inherit-only original;
 *  - ACEs that do not inherit (no CI) are dropped;
 *  - an explicit DACL is stored as given; an explicit descriptor without a
 *    DACL inherits;
 *  - owner and group are the creator's token owner and primary group;
 *  - the stored control has SE_SACL_AUTO_INHERITED (0x8804, 0x9804 when the
 *    DACL is protected).
 * In legacy mode (/REGACL=LEGACY) nothing is stored: every key has none.
 */

#include <kmt_test.h>

#if (NTDDI_VERSION < NTDDI_WIN7)
NTSYSAPI
NTSTATUS
NTAPI
ZwRenameKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING NewName);
#endif

/* Exported by the kernel, not declared by the DDK headers */
NTSYSAPI NTSTATUS NTAPI ZwSaveKey(_In_ HANDLE KeyHandle, _In_ HANDLE FileHandle);
NTSYSAPI NTSTATUS NTAPI ZwLoadKey(_In_ POBJECT_ATTRIBUTES KeyObjectAttributes, _In_ POBJECT_ATTRIBUTES FileObjectAttributes);
NTSYSAPI NTSTATUS NTAPI ZwUnloadKey(_In_ POBJECT_ATTRIBUTES KeyObjectAttributes);

#define SEED_KEY    L"\\Registry\\Machine\\SOFTWARE\\ReactOS kmtest CmSkStore"
#define MOUNT1      L"\\Registry\\Machine\\CmSkStore1"
#define MOUNT2      L"\\Registry\\Machine\\CmSkStore2"
#define FILE1       L"\\SystemRoot\\Temp\\CmSkStore1.hiv"
#define FILE2       L"\\SystemRoot\\Temp\\CmSkStore2.hiv"
#define FILE3       L"\\SystemRoot\\Temp\\CmSkStore3.hiv"
#define STATS_KEY   L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\RegAcl\\AuditStats"

/* Evaluates the call once (ok_eq_hex evaluates its argument twice) */
#define CHK(Call) do { NTSTATUS Chk_ = (Call); ok(Chk_ == STATUS_SUCCESS, "%s = 0x%08lx\n", #Call, Chk_); } while (0)

#define KA  KEY_ALL_ACCESS
#define KR  KEY_READ
#define CI  CONTAINER_INHERIT_ACE
#define OI  OBJECT_INHERIT_ACE
#define IO  INHERIT_ONLY_ACE

/* SIDs by role */
enum { S_SY, S_BA, S_BU, S_WD, S_CO, S_OWNER, S_GROUP, S_MAX };
static PSID g_Sid[S_MAX];
static ULONG g_SidBuf[5][4];

typedef struct _ACE_SPEC { UCHAR Flags; ACCESS_MASK Mask; UCHAR Sid; } ACE_SPEC;

/* ---- descriptors ---- */

static
PSID
WellKnown(
    _In_ ULONG Index,
    _In_ UCHAR Authority,
    _In_ ULONG Rid1,
    _In_ ULONG Rid2)
{
    SID_IDENTIFIER_AUTHORITY Auth = {{0, 0, 0, 0, 0, Authority}};
    PSID Sid = g_SidBuf[Index];

    RtlInitializeSid(Sid, &Auth, Rid2 ? 2 : 1);
    *RtlSubAuthoritySid(Sid, 0) = Rid1;
    if (Rid2)
        *RtlSubAuthoritySid(Sid, 1) = Rid2;
    return Sid;
}

/* An absolute descriptor with this DACL (or none), for ZwCreateKey */
static
PSECURITY_DESCRIPTOR
MakeExplicit(
    _Out_ PSECURITY_DESCRIPTOR Sd,
    _Out_writes_bytes_(AclSize) PACL Acl,
    _In_ ULONG AclSize,
    _In_ const ACE_SPEC *Aces,
    _In_ ULONG Count,
    _In_ BOOLEAN DaclPresent,
    _In_ BOOLEAN Protected)
{
    ULONG i;

    RtlCreateSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
    if (!DaclPresent)
        return Sd;
    RtlCreateAcl(Acl, AclSize, ACL_REVISION);
    for (i = 0; i < Count; i++)
        CHK(RtlAddAccessAllowedAceEx(Acl, ACL_REVISION, Aces[i].Flags, Aces[i].Mask, g_Sid[Aces[i].Sid]));
    RtlSetDaclSecurityDescriptor(Sd, TRUE, Acl, FALSE);
    if (Protected)
        ((PISECURITY_DESCRIPTOR)Sd)->Control |= SE_DACL_PROTECTED;
    return Sd;
}

static
PSID
SdSid(
    _In_ PISECURITY_DESCRIPTOR_RELATIVE Sd,
    _In_ ULONG Length,
    _In_ ULONG Offset)
{
    if (!Offset || Offset + 8 > Length)
        return NULL;
    return (PUCHAR)Sd + Offset;
}

/* Does the stored descriptor match: owner, group, control, and the DACL ACE by ACE */
static
BOOLEAN
SdMatches(
    _In_ PVOID Stored,
    _In_ ULONG Length,
    _In_ USHORT Control,
    _In_ const ACE_SPEC *Aces,
    _In_ ULONG Count,
    _In_ PCSTR What)
{
    PISECURITY_DESCRIPTOR_RELATIVE Sd = Stored;
    PSID Owner, Group;
    PACL Dacl;
    PACE_HEADER Ace;
    ULONG i;
    BOOLEAN Match = TRUE;

    if (!RtlValidRelativeSecurityDescriptor(Stored, Length, 0))
    {
        ok(0, "%s: stored descriptor not valid\n", What);
        return FALSE;
    }
    Owner = SdSid(Sd, Length, Sd->Owner);
    Group = SdSid(Sd, Length, Sd->Group);
    ok(Owner && RtlEqualSid(Owner, g_Sid[S_OWNER]), "%s: owner is not the creator's token owner\n", What);
    ok(Group && RtlEqualSid(Group, g_Sid[S_GROUP]), "%s: group is not the creator's primary group\n", What);
    ok(Sd->Control == Control, "%s: control 0x%04x, expected 0x%04x\n", What, Sd->Control, Control);
    if (!Owner || !Group || !RtlEqualSid(Owner, g_Sid[S_OWNER]) || !RtlEqualSid(Group, g_Sid[S_GROUP]) ||
        Sd->Control != Control || !Sd->Dacl)
    {
        Match = FALSE;
    }
    if (!Sd->Dacl)
    {
        ok(0, "%s: no DACL\n", What);
        return FALSE;
    }
    Dacl = (PACL)((PUCHAR)Sd + Sd->Dacl);
    ok(Dacl->AceCount == Count, "%s: %u ACEs, expected %lu\n", What, Dacl->AceCount, Count);
    if (Dacl->AceCount != Count)
        return FALSE;
    for (i = 0; i < Count; i++)
    {
        PACCESS_ALLOWED_ACE Allowed;

        if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)))
            return FALSE;
        Allowed = (PACCESS_ALLOWED_ACE)Ace;
        if (Ace->AceType != ACCESS_ALLOWED_ACE_TYPE || Ace->AceFlags != Aces[i].Flags ||
            Allowed->Mask != Aces[i].Mask || !RtlEqualSid(&Allowed->SidStart, g_Sid[Aces[i].Sid]))
        {
            ok(0, "%s: ACE %lu is type %u flags 0x%x mask 0x%lx, expected flags 0x%x mask 0x%lx sid %u\n",
               What, i, Ace->AceType, Ace->AceFlags, Allowed->Mask, Aces[i].Flags, Aces[i].Mask, Aces[i].Sid);
            Match = FALSE;
        }
    }
    return Match;
}

/* ---- keys and files ---- */

static
NTSTATUS
CreateKey(
    _Out_ PHANDLE Key,
    _In_opt_ HANDLE Root,
    _In_ PCWSTR Name,
    _In_ ULONG Options,
    _In_opt_ PSECURITY_DESCRIPTOR Sd)
{
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&ObjectAttributes, &String, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, Root, Sd);
    *Key = NULL;
    return ZwCreateKey(Key, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, Options, NULL);
}

static
VOID
DeleteKeyByName(
    _In_opt_ HANDLE Root,
    _In_ PCWSTR Name)
{
    HANDLE Key;
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&ObjectAttributes, &String, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, Root, NULL);
    if (NT_SUCCESS(ZwOpenKey(&Key, DELETE, &ObjectAttributes)))
    {
        CHK(ZwDeleteKey(Key));
        ZwClose(Key);
    }
}

static
VOID
DeleteFileByName(
    _In_ PCWSTR Name)
{
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&ObjectAttributes, &String, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    ZwDeleteFile(&ObjectAttributes);
}

static
NTSTATUS
SaveKeyToFile(
    _In_ HANDLE Key,
    _In_ PCWSTR Name)
{
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK Io;
    HANDLE File;
    NTSTATUS Status;

    DeleteFileByName(Name);
    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&ObjectAttributes, &String, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateFile(&File, GENERIC_WRITE | SYNCHRONIZE, &ObjectAttributes, &Io, NULL, FILE_ATTRIBUTE_NORMAL,
                          0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = ZwSaveKey(Key, File);
    ZwClose(File);
    return Status;
}

static
NTSTATUS
LoadHive(
    _In_ PCWSTR Mount,
    _In_ PCWSTR File)
{
    UNICODE_STRING KeyName, FileName;
    OBJECT_ATTRIBUTES KeyAttributes, FileAttributes;

    RtlInitUnicodeString(&KeyName, Mount);
    RtlInitUnicodeString(&FileName, File);
    InitializeObjectAttributes(&KeyAttributes, &KeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&FileAttributes, &FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    return ZwLoadKey(&KeyAttributes, &FileAttributes);
}

/*
 * Unload, retried for up to ten seconds: right after keys were created and
 * their handles closed, an unload can still find them referenced (the closed
 * keys wait in the delayed-close cache) and fail with STATUS_CANNOT_DELETE;
 * the same happens without stored descriptors.
 */
static
NTSTATUS
UnloadHive(
    _In_ PCWSTR Mount)
{
    UNICODE_STRING KeyName;
    OBJECT_ATTRIBUTES KeyAttributes;
    LARGE_INTEGER Delay;
    NTSTATUS Status;
    ULONG Try;

    RtlInitUnicodeString(&KeyName, Mount);
    InitializeObjectAttributes(&KeyAttributes, &KeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    for (Try = 0; ; Try++)
    {
        Status = ZwUnloadKey(&KeyAttributes);
        if (Status != STATUS_CANNOT_DELETE || Try == 20)
            return Status;
        Delay.QuadPart = -5 * 1000 * 1000;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }
}

/* ---- the hive file, read back ---- */

#define MAX_CELLS 64

/* Key node and security cell layout in a hive file */
#define NK_FLAGS        2
#define NK_PARENT       16
#define NK_SECURITY     44
#define NK_NAME_LENGTH  72
#define NK_NAME         76
#define NK_HIVE_ENTRY   0x0004
#define NK_COMP_NAME    0x0020
#define SK_FLINK        4
#define SK_BLINK        8
#define SK_REFS         12
#define SK_LENGTH       16
#define SK_DESCRIPTOR   20
#define NIL_CELL        0xFFFFFFFF
typedef struct _NK { ULONG Off; ULONG Parent; ULONG Security; USHORT Flags; WCHAR Name[32]; } NK;
typedef struct _SK { ULONG Off; ULONG Flink; ULONG Blink; ULONG Refs; ULONG Length; PUCHAR Sd; } SK;
typedef struct _HIVE_IMAGE
{
    PUCHAR Data;
    ULONG Size;
    ULONG NkCount, SkCount;
    NK Nk[MAX_CELLS];
    SK Sk[MAX_CELLS];
} HIVE_IMAGE, *PHIVE_IMAGE;

static NK *FindNk(PHIVE_IMAGE Image, ULONG Off)
{
    ULONG i;
    for (i = 0; i < Image->NkCount; i++)
        if (Image->Nk[i].Off == Off) return &Image->Nk[i];
    return NULL;
}

static SK *FindSk(PHIVE_IMAGE Image, ULONG Off)
{
    ULONG i;
    for (i = 0; i < Image->SkCount; i++)
        if (Image->Sk[i].Off == Off) return &Image->Sk[i];
    return NULL;
}

/* The key named Path below the root ("" is the root), e.g. L"E\\C" */
static
NK *
FindKeyByPath(
    _In_ PHIVE_IMAGE Image,
    _In_ PCWSTR Path)
{
    ULONG i;
    NK *Node;
    WCHAR Built[128];

    for (i = 0; i < Image->NkCount; i++)
    {
        WCHAR Tmp[128];
        Node = &Image->Nk[i];
        Built[0] = 0;
        while (Node && !(Node->Flags & NK_HIVE_ENTRY))
        {
            RtlStringCbCopyW(Tmp, sizeof(Tmp), Node->Name);
            if (Built[0])
            {
                RtlStringCbCatW(Tmp, sizeof(Tmp), L"\\");
                RtlStringCbCatW(Tmp, sizeof(Tmp), Built);
            }
            RtlStringCbCopyW(Built, sizeof(Built), Tmp);
            Node = FindNk(Image, Node->Parent);
        }
        if (Node && !_wcsicmp(Built, Path))
            return &Image->Nk[i];
    }
    return NULL;
}

static
BOOLEAN
ReadHiveImage(
    _In_ PCWSTR Name,
    _Out_ PHIVE_IMAGE Image)
{
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK Io;
    FILE_STANDARD_INFORMATION Info;
    HANDLE File;
    NTSTATUS Status;
    ULONG BinOff, BinSize, Off;

    RtlZeroMemory(Image, sizeof(*Image));
    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&ObjectAttributes, &String, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateFile(&File, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &Io, NULL, 0, FILE_SHARE_READ,
                          FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return FALSE;
    Status = ZwQueryInformationFile(File, &Io, &Info, sizeof(Info), FileStandardInformation);
    if (!NT_SUCCESS(Status) || Info.EndOfFile.QuadPart < 0x2000 || Info.EndOfFile.QuadPart > 0x100000)
    {
        ok(0, "hive file %S: size not usable\n", Name);
        ZwClose(File);
        return FALSE;
    }
    Image->Size = Info.EndOfFile.LowPart;
    Image->Data = ExAllocatePoolWithTag(PagedPool, Image->Size, 'kSmC');
    if (!Image->Data)
    {
        ZwClose(File);
        return FALSE;
    }
    Status = ZwReadFile(File, NULL, NULL, NULL, &Io, Image->Data, Image->Size, NULL, NULL);
    ZwClose(File);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status) || RtlCompareMemory(Image->Data, "regf", 4) != 4)
        return FALSE;

    for (BinOff = 0x1000; BinOff + 0x20 <= Image->Size; BinOff += BinSize)
    {
        if (RtlCompareMemory(Image->Data + BinOff, "hbin", 4) != 4)
            break;
        BinSize = *(PULONG)(Image->Data + BinOff + 8);
        if (BinSize < 0x1000 || BinOff + BinSize > Image->Size)
            break;
        for (Off = BinOff + 0x20; Off + 4 <= BinOff + BinSize;)
        {
            LONG Size = *(PLONG)(Image->Data + Off);
            ULONG Abs = Size < 0 ? (ULONG)-Size : (ULONG)Size;
            PUCHAR Cell = Image->Data + Off + 4;

            if (Abs < 8 || Off + Abs > BinOff + BinSize)
                break;
            /* 'nk' and 'sk' cells, by their documented offsets (regf) */
            if (Size < 0 && Cell[0] == 'n' && Cell[1] == 'k' && Image->NkCount < MAX_CELLS && Abs >= 4 + NK_NAME)
            {
                NK *k = &Image->Nk[Image->NkCount++];
                USHORT Flags = *(PUSHORT)(Cell + NK_FLAGS), NameLength = *(PUSHORT)(Cell + NK_NAME_LENGTH);
                ULONG i, Chars;

                k->Off = Off - 0x1000;
                k->Flags = Flags;
                k->Parent = *(PULONG)(Cell + NK_PARENT);
                k->Security = *(PULONG)(Cell + NK_SECURITY);
                Chars = (Flags & NK_COMP_NAME) ? NameLength : NameLength / sizeof(WCHAR);
                for (i = 0; i < Chars && i < 31 && NK_NAME + (i + 1) * 2 <= Abs - 4; i++)
                    k->Name[i] = (Flags & NK_COMP_NAME) ? Cell[NK_NAME + i] : ((PWCHAR)(Cell + NK_NAME))[i];
                k->Name[i] = 0;
            }
            else if (Size < 0 && Cell[0] == 's' && Cell[1] == 'k' && Image->SkCount < MAX_CELLS && Abs >= 4 + SK_DESCRIPTOR)
            {
                SK *s = &Image->Sk[Image->SkCount++];

                s->Off = Off - 0x1000;
                s->Flink = *(PULONG)(Cell + SK_FLINK);
                s->Blink = *(PULONG)(Cell + SK_BLINK);
                s->Refs = *(PULONG)(Cell + SK_REFS);
                s->Length = *(PULONG)(Cell + SK_LENGTH);
                s->Sd = (s->Length && SK_DESCRIPTOR + s->Length <= Abs - 4) ? Cell + SK_DESCRIPTOR : NULL;
            }
            Off += Abs;
        }
    }
    return TRUE;
}

static VOID FreeHiveImage(PHIVE_IMAGE Image)
{
    if (Image->Data)
        ExFreePoolWithTag(Image->Data, 'kSmC');
    Image->Data = NULL;
}

/* One ring holding every 'sk' cell, each referenced by exactly the keys that name it */
static
VOID
CheckRingAndCounts(
    _In_ PHIVE_IMAGE Image,
    _In_ ULONG ExpectedCells,
    _In_ PCSTR What)
{
    ULONG i, j, Walk, Steps;
    SK *s;

    ok(Image->SkCount == ExpectedCells, "%s: %lu sk cells, expected %lu\n", What, Image->SkCount, ExpectedCells);
    for (i = 0; i < Image->SkCount; i++)
    {
        ULONG Count = 0;
        SK *f = FindSk(Image, Image->Sk[i].Flink), *b = FindSk(Image, Image->Sk[i].Blink);

        for (j = 0; j < Image->NkCount; j++)
            if (Image->Nk[j].Security == Image->Sk[i].Off) Count++;
        ok(Count == Image->Sk[i].Refs, "%s: sk 0x%lx ReferenceCount %lu, %lu keys name it\n",
           What, Image->Sk[i].Off, Image->Sk[i].Refs, Count);
        ok(f && b && f->Blink == Image->Sk[i].Off && b->Flink == Image->Sk[i].Off,
           "%s: sk 0x%lx: ring links do not agree\n", What, Image->Sk[i].Off);
    }
    /* A single ring: from the first cell, every cell is reached */
    if (Image->SkCount)
    {
        Walk = Image->Sk[0].Off;
        for (Steps = 0; Steps < MAX_CELLS; Steps++)
        {
            s = FindSk(Image, Walk);
            if (!s) break;
            Walk = s->Flink;
            if (Walk == Image->Sk[0].Off) break;
        }
        ok(Steps + 1 == Image->SkCount, "%s: the ring has %lu cells of %lu\n", What, Steps + 1, Image->SkCount);
    }
}

static
SK *
KeySk(
    _In_ PHIVE_IMAGE Image,
    _In_ PCWSTR Path)
{
    NK *Node = FindKeyByPath(Image, Path);

    ok(Node != NULL, "key '%S' not in the hive file\n", Path);
    if (!Node)
        return NULL;
    return FindSk(Image, Node->Security);
}

/* ---- expected descriptors (the oracle's, for the same sequence) ---- */

/* The root: explicit D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KA;;;CO) */
static const ACE_SPEC RootAces[] = { { CI, KA, S_SY }, { CI, KA, S_BA }, { CI, KA, S_CO } };
/* A child of it: (A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;;KA;;;<owner>)(A;CIIO;KA;;;CO) */
static const ACE_SPEC ChildAces[] = { { CI, KA, S_SY }, { CI, KA, S_BA }, { 0, KA, S_OWNER }, { CI | IO, KA, S_CO } };
/* E: explicit D:(A;CI;KA;;;BA)(A;CIIO;GA;;;CO)(A;OICIIO;GR;;;BU)(A;;KR;;;WD)(A;CI;KR;;;SY) */
static const ACE_SPEC EAces[] = { { CI, KA, S_BA }, { CI | IO, GENERIC_ALL, S_CO }, { OI | CI | IO, GENERIC_READ, S_BU },
                                  { 0, KR, S_WD }, { CI, KR, S_SY } };
/* E\C and E\C\D: (A;CI;KA;;;BA)(A;;KA;;;<owner>)(A;CIIO;GA;;;CO)(A;;KR;;;BU)(A;OICIIO;GR;;;BU)(A;CI;KR;;;SY) */
static const ACE_SPEC ECAces[] = { { CI, KA, S_BA }, { 0, KA, S_OWNER }, { CI | IO, GENERIC_ALL, S_CO }, { 0, KR, S_BU },
                                   { OI | CI | IO, GENERIC_READ, S_BU }, { CI, KR, S_SY } };

#define CTL         (SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_DACL_PRESENT)
#define CTL_P       (CTL | SE_DACL_PROTECTED)

static const PCWSTR Children[] = { L"K1", L"K2", L"K3", L"K4", L"K5", L"K6", L"K7", L"K8" };

/* Every key of the image has the descriptor of the same path in the other image */
static
VOID
CompareImages(
    _In_ PHIVE_IMAGE A,
    _In_ PHIVE_IMAGE B,
    _In_ PCSTR What)
{
    ULONG i;

    ok(A->NkCount == B->NkCount, "%s: %lu keys vs %lu\n", What, A->NkCount, B->NkCount);
    for (i = 0; i < A->NkCount; i++)
    {
        SK *Sa = FindSk(A, A->Nk[i].Security);
        NK *Nb = NULL;
        SK *Sb;
        ULONG j;

        for (j = 0; j < B->NkCount; j++)
        {
            if (!_wcsicmp(B->Nk[j].Name, A->Nk[i].Name) &&
                ((B->Nk[j].Flags & NK_HIVE_ENTRY) == (A->Nk[i].Flags & NK_HIVE_ENTRY)))
            {
                Nb = &B->Nk[j];
            }
        }
        ok(Nb != NULL, "%s: key %S missing\n", What, A->Nk[i].Name);
        if (!Nb || !Sa)
            continue;
        Sb = FindSk(B, Nb->Security);
        ok(Sb && Sb->Sd && Sa->Sd && Sa->Length == Sb->Length &&
           RtlCompareMemory(Sa->Sd, Sb->Sd, Sa->Length) == Sa->Length,
           "%s: key %S: the descriptor differs\n", What, A->Nk[i].Name);
    }
}

static
VOID
GetTokenSids(VOID)
{
    SECURITY_SUBJECT_CONTEXT Context;
    PTOKEN_OWNER Owner = NULL;
    PTOKEN_PRIMARY_GROUP Group = NULL;
    PACCESS_TOKEN Token;
    static ULONG OwnerBuf[17], GroupBuf[17];

    SeCaptureSubjectContext(&Context);
    Token = SeQuerySubjectContextToken(&Context);
    CHK(SeQueryInformationToken(Token, TokenOwner, (PVOID *)&Owner));
    CHK(SeQueryInformationToken(Token, TokenPrimaryGroup, (PVOID *)&Group));
    if (Owner)
    {
        RtlCopySid(sizeof(OwnerBuf), OwnerBuf, Owner->Owner);
        ExFreePool(Owner);
    }
    if (Group)
    {
        RtlCopySid(sizeof(GroupBuf), GroupBuf, Group->PrimaryGroup);
        ExFreePool(Group);
    }
    SeReleaseSubjectContext(&Context);
    g_Sid[S_OWNER] = OwnerBuf;
    g_Sid[S_GROUP] = GroupBuf;
}

static
ULONG
StoreMode(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(STATS_KEY), ValueName = RTL_CONSTANT_STRING(L"Mode");
    OBJECT_ATTRIBUTES ObjectAttributes;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    HANDLE Key;
    ULONG Length, Mode = MAXULONG;

    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &ObjectAttributes)))
    {
        if (NT_SUCCESS(ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length)) &&
            Info->Type == REG_DWORD)
        {
            Mode = *(PULONG)Info->Data;
        }
        ZwClose(Key);
    }
    return Mode;
}

static HIVE_IMAGE g_Image, g_Image2, g_Image3;

START_TEST(CmSkStore)
{
    SECURITY_DESCRIPTOR SdRoot, SdE, SdEmpty;
    ULONG AclRoot[64], AclE[96];
    HANDLE Seed, Root, Key, Sub, Sub2, Vol, Vol2;
    UNICODE_STRING NewName = RTL_CONSTANT_STRING(L"K8r");
    NTSTATUS Status;
    BOOLEAN Legacy;
    SK *Sk, *ChildSk;
    ULONG i;

    g_Sid[S_SY] = WellKnown(0, 5, SECURITY_LOCAL_SYSTEM_RID, 0);
    g_Sid[S_BA] = WellKnown(1, 5, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS);
    g_Sid[S_BU] = WellKnown(2, 5, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS);
    g_Sid[S_WD] = WellKnown(3, 1, SECURITY_WORLD_RID, 0);
    g_Sid[S_CO] = WellKnown(4, 3, SECURITY_CREATOR_OWNER_RID, 0);
    GetTokenSids();
    Legacy = (StoreMode() == 0);
    trace("registry ACL mode %lu: %s\n", StoreMode(), Legacy ? "legacy, nothing is stored" : "descriptors are stored");

    /* Leftovers of an earlier run */
    UnloadHive(MOUNT2);
    UnloadHive(MOUNT1);
    DeleteKeyByName(NULL, SEED_KEY);

    /* The hive file: one key with an explicit protected DACL, saved */
    Status = CreateKey(&Seed, NULL, SEED_KEY, REG_OPTION_NON_VOLATILE,
                       MakeExplicit(&SdRoot, (PACL)AclRoot, sizeof(AclRoot), RootAces, RTL_NUMBER_OF(RootAces), TRUE, TRUE));
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    CHK(SaveKeyToFile(Seed, FILE1));
    CHK(ZwDeleteKey(Seed));
    ZwClose(Seed);

    /* Work in it: children that inherit, explicit descriptors, volatile keys, a rename */
    Status = LoadHive(MOUNT1, FILE1);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    CHK(CreateKey(&Root, NULL, MOUNT1, REG_OPTION_NON_VOLATILE, NULL));
    for (i = 0; i < RTL_NUMBER_OF(Children); i++)
    {
        CHK(CreateKey(&Key, Root, Children[i], REG_OPTION_NON_VOLATILE, NULL));
        if (i == 7)
            CHK(ZwRenameKey(Key, &NewName));
        ZwClose(Key);
    }
    CHK(CreateKey(&Key, Root, L"E", REG_OPTION_NON_VOLATILE,
                        MakeExplicit(&SdE, (PACL)AclE, sizeof(AclE), EAces, RTL_NUMBER_OF(EAces), TRUE, FALSE)));
    CHK(CreateKey(&Sub, Key, L"C", REG_OPTION_NON_VOLATILE, NULL));
    CHK(CreateKey(&Sub2, Sub, L"D", REG_OPTION_NON_VOLATILE, NULL));
    ZwClose(Sub2);
    ZwClose(Sub);
    ZwClose(Key);
    /* An explicit descriptor without a DACL inherits like none */
    RtlCreateSecurityDescriptor(&SdEmpty, SECURITY_DESCRIPTOR_REVISION);
    CHK(CreateKey(&Key, Root, L"N", REG_OPTION_NON_VOLATILE, &SdEmpty));
    ZwClose(Key);
    CHK(CreateKey(&Vol, Root, L"V", REG_OPTION_VOLATILE, NULL));
    CHK(CreateKey(&Vol2, Vol, L"W", REG_OPTION_VOLATILE, NULL));

    /* A volatile key has a descriptor too: a save copies it (and the hive file never sees it) */
    CHK(SaveKeyToFile(Vol, FILE2));
    CHK(ZwDeleteKey(Vol2));
    CHK(ZwDeleteKey(Vol));
    ZwClose(Vol2);
    ZwClose(Vol);
    if (ReadHiveImage(FILE2, &g_Image2))
    {
        Sk = KeySk(&g_Image2, L"");
        if (Legacy)
            ok(Sk == NULL, "legacy: the volatile key has a stored descriptor\n");
        else if (Sk && Sk->Sd)
            SdMatches(Sk->Sd, Sk->Length, CTL, ChildAces, RTL_NUMBER_OF(ChildAces), "volatile V");
        else
            ok(0, "the volatile key has no descriptor\n");
        FreeHiveImage(&g_Image2);
    }
    ZwClose(Root);

    /* The live hive as written: unload, read the file */
    CHK(UnloadHive(MOUNT1));
    if (ReadHiveImage(FILE1, &g_Image))
    {
        if (Legacy)
        {
            for (i = 0; i < g_Image.NkCount; i++)
            {
                if (!(g_Image.Nk[i].Flags & NK_HIVE_ENTRY))
                    ok(g_Image.Nk[i].Security == NIL_CELL, "legacy: key %S has a descriptor\n", g_Image.Nk[i].Name);
            }
        }
        else
        {
            /* root, child, E, E\C: four cells; the eight children (one renamed) and N share one */
            CheckRingAndCounts(&g_Image, 4, "after create");
            Sk = KeySk(&g_Image, L"");
            if (Sk && Sk->Sd) SdMatches(Sk->Sd, Sk->Length, CTL_P, RootAces, RTL_NUMBER_OF(RootAces), "root");
            ChildSk = KeySk(&g_Image, L"K1");
            if (ChildSk && ChildSk->Sd)
            {
                SdMatches(ChildSk->Sd, ChildSk->Length, CTL, ChildAces, RTL_NUMBER_OF(ChildAces), "K1");
                ok(ChildSk->Refs == 9, "the children's cell: ReferenceCount %lu, expected 9 (K1-K7, K8r, N)\n", ChildSk->Refs);
            }
            ok(KeySk(&g_Image, L"K8r") == ChildSk, "the renamed key does not keep its cell\n");
            ok(KeySk(&g_Image, L"N") == ChildSk, "N (explicit descriptor without a DACL) does not share the children's cell\n");
            Sk = KeySk(&g_Image, L"E");
            if (Sk && Sk->Sd) SdMatches(Sk->Sd, Sk->Length, CTL, EAces, RTL_NUMBER_OF(EAces), "E");
            Sk = KeySk(&g_Image, L"E\\C");
            if (Sk && Sk->Sd)
            {
                SdMatches(Sk->Sd, Sk->Length, CTL, ECAces, RTL_NUMBER_OF(ECAces), "E\\C");
                ok(Sk->Refs == 2 && KeySk(&g_Image, L"E\\C\\D") == Sk, "E\\C and E\\C\\D do not share one cell (refs %lu)\n", Sk->Refs);
            }
            ok(FindKeyByPath(&g_Image, L"V") == NULL, "the volatile key is in the hive file\n");
        }
        FreeHiveImage(&g_Image);
    }

    /* Deletes give the references back; the last one frees the cell */
    CHK(LoadHive(MOUNT1, FILE1));
    CHK(CreateKey(&Root, NULL, MOUNT1, REG_OPTION_NON_VOLATILE, NULL));
    for (i = 0; i < 7; i++)
        DeleteKeyByName(Root, Children[i]);
    DeleteKeyByName(Root, L"N");
    /* A key created after the reload shares the cell found again in the ring */
    CHK(CreateKey(&Key, Root, L"K9", REG_OPTION_NON_VOLATILE, NULL));
    ZwClose(Key);
    ZwClose(Root);
    CHK(UnloadHive(MOUNT1));
    if (!Legacy && ReadHiveImage(FILE1, &g_Image))
    {
        CheckRingAndCounts(&g_Image, 4, "after deleting 8 of 10");
        ChildSk = KeySk(&g_Image, L"K8r");
        ok(ChildSk && ChildSk->Refs == 2 && KeySk(&g_Image, L"K9") == ChildSk,
           "K8r and K9: one cell with ReferenceCount 2 (got %lu)\n", ChildSk ? ChildSk->Refs : 0);
        FreeHiveImage(&g_Image);
    }
    CHK(LoadHive(MOUNT1, FILE1));
    CHK(CreateKey(&Root, NULL, MOUNT1, REG_OPTION_NON_VOLATILE, NULL));
    DeleteKeyByName(Root, L"K8r");
    DeleteKeyByName(Root, L"K9");
    ZwClose(Root);
    CHK(UnloadHive(MOUNT1));
    if (!Legacy && ReadHiveImage(FILE1, &g_Image))
    {
        /* The children's cell is gone from the ring and from the file's allocated cells */
        CheckRingAndCounts(&g_Image, 3, "after deleting all children");
        FreeHiveImage(&g_Image);
    }

    /* Save -> load -> save: the same descriptor on every key */
    CHK(LoadHive(MOUNT1, FILE1));
    CHK(CreateKey(&Root, NULL, MOUNT1, REG_OPTION_NON_VOLATILE, NULL));
    CHK(CreateKey(&Key, Root, L"S1", REG_OPTION_NON_VOLATILE, NULL));
    ZwClose(Key);
    CHK(SaveKeyToFile(Root, FILE2));
    ZwClose(Root);
    CHK(LoadHive(MOUNT2, FILE2));
    CHK(CreateKey(&Root, NULL, MOUNT2, REG_OPTION_NON_VOLATILE, NULL));
    CHK(SaveKeyToFile(Root, FILE3));
    ZwClose(Root);
    CHK(UnloadHive(MOUNT2));
    CHK(UnloadHive(MOUNT1));
    if (ReadHiveImage(FILE1, &g_Image) && ReadHiveImage(FILE2, &g_Image2) && ReadHiveImage(FILE3, &g_Image3))
    {
        if (!Legacy)
        {
            /* root, E, E\C and S1's (the children's) descriptor */
            CheckRingAndCounts(&g_Image2, 4, "saved copy");
            CheckRingAndCounts(&g_Image3, 4, "saved copy of the reloaded copy");
        }
        CompareImages(&g_Image, &g_Image2, "live vs saved");
        CompareImages(&g_Image2, &g_Image3, "saved vs saved again");
    }
    FreeHiveImage(&g_Image);
    FreeHiveImage(&g_Image2);
    FreeHiveImage(&g_Image3);

Cleanup:
    UnloadHive(MOUNT2);
    UnloadHive(MOUNT1);
    DeleteFileByName(FILE1);
    DeleteFileByName(FILE2);
    DeleteFileByName(FILE3);
}
