/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the NtQueryInformationToken parity gaps with Windows 10:
 *              buffer lengths, the classes TokenAccessInformation (22), TokenCapabilities (30),
 *              TokenAppContainerSid (31), TokenAppContainerNumber (32), TokenIsRestricted (40),
 *              TokenProcessTrustLevel (41), the WoW64 services NtPrivilegeCheck and
 *              NtCompareTokens, and NtFilterToken with LUA_TOKEN
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expectations were measured on Windows 10 22H2 (build 19045), x64 native and 32-bit under
 * WOW64, with an elevated administrator's token (tqprobe, evidence/token-query-parity).
 * Built for amd64 and i386; the i386 build also runs under WoW64.
 */

#include "precomp.h"

#define CLS_SESSIONID       12
#define CLS_GROUPSANDPRIVS  13
#define CLS_SANDBOXINERT    15
#define CLS_ORIGIN          17
#define CLS_ELEVATION       20
#define CLS_HASRESTRICTIONS 21
#define CLS_ACCESSINFO      22
#define CLS_CAPABILITIES    30
#define CLS_APPCONTAINERSID 31
#define CLS_APPCONTAINERNUM 32
#define CLS_ISRESTRICTED    40
#define CLS_TRUSTLEVEL      41

#ifndef LUA_TOKEN
#define LUA_TOKEN 0x4
#endif

/* The TOKEN_ACCESS_INFORMATION of Windows 10 (the header of this tree has the short Vista one) */
typedef struct _TQ_ACCESS_INFORMATION
{
    PSID_AND_ATTRIBUTES_HASH SidHash;
    PSID_AND_ATTRIBUTES_HASH RestrictedSidHash;
    PTOKEN_PRIVILEGES Privileges;
    LUID AuthenticationId;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    ULONG MandatoryPolicy;
    ULONG Flags;
    ULONG AppContainerNumber;
    PSID PackageSid;
    PSID_AND_ATTRIBUTES_HASH CapabilitiesHash;
    PSID TrustLevelSid;
    PVOID SecurityAttributes;
} TQ_ACCESS_INFORMATION, *PTQ_ACCESS_INFORMATION;

#define TQ_NOT_LOW      0x2000
#define TQ_IS_FILTERED  0x0800

static NTSTATUS Query(HANDLE Token, ULONG Class, PVOID Buffer, ULONG Length, PULONG ReturnLength)
{
    return NtQueryInformationToken(Token, (TOKEN_INFORMATION_CLASS)Class, Buffer, Length, ReturnLength);
}

/* The result of a variable-size class in a fresh heap block (NULL on failure) */
static PVOID QueryAlloc(HANDLE Token, ULONG Class, PULONG Size)
{
    ULONG Length = 0;
    PVOID Buffer;
    NTSTATUS Status;

    Status = Query(Token, Class, NULL, 0, &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    if (Status != STATUS_BUFFER_TOO_SMALL || !Length)
        return NULL;
    Buffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Length);
    if (!Buffer)
        return NULL;
    Status = Query(Token, Class, Buffer, Length, &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        return NULL;
    }
    if (Size)
        *Size = Length;
    return Buffer;
}

static BOOLEAN InBuffer(PVOID Buffer, ULONG Size, PVOID Pointer, ULONG Length)
{
    return (ULONG_PTR)Pointer >= (ULONG_PTR)Buffer &&
           (ULONG_PTR)Pointer + Length <= (ULONG_PTR)Buffer + Size;
}

/* A fixed-size class: smaller buffers fail with the size, larger ones work and only the size is written */
static void CheckFixedLength(HANDLE Token, ULONG Class, ULONG Size, const char *Name)
{
    ULONGLONG Storage[8];
    PUCHAR Buffer = (PUCHAR)Storage;
    ULONG ReturnLength, i;
    NTSTATUS Status;

    ReturnLength = 0xdeadbeef;
    Status = Query(Token, Class, NULL, 0, &ReturnLength);
    ok(Status == STATUS_BUFFER_TOO_SMALL, "%s: size query returned 0x%lx\n", Name, Status);
    ok(ReturnLength == Size, "%s: size query reported %lu, expected %lu\n", Name, ReturnLength, Size);

    ReturnLength = 0xdeadbeef;
    RtlFillMemory(Buffer, sizeof(Storage), 0xCC);
    Status = Query(Token, Class, Buffer, Size - 1, &ReturnLength);
    ok(Status == STATUS_BUFFER_TOO_SMALL, "%s: short buffer returned 0x%lx\n", Name, Status);
    ok(ReturnLength == Size, "%s: short buffer reported %lu\n", Name, ReturnLength);

    ReturnLength = 0xdeadbeef;
    RtlFillMemory(Buffer, sizeof(Storage), 0xCC);
    Status = Query(Token, Class, Buffer, Size, &ReturnLength);
    ok(Status == STATUS_SUCCESS, "%s: exact buffer returned 0x%lx\n", Name, Status);
    ok(ReturnLength == Size, "%s: exact buffer reported %lu\n", Name, ReturnLength);

    ReturnLength = 0xdeadbeef;
    RtlFillMemory(Buffer, sizeof(Storage), 0xCC);
    Status = Query(Token, Class, Buffer, sizeof(Storage), &ReturnLength);
    ok(Status == STATUS_SUCCESS, "%s: larger buffer returned 0x%lx\n", Name, Status);
    ok(ReturnLength == Size, "%s: larger buffer reported %lu, expected %lu\n", Name, ReturnLength, Size);
    for (i = Size; i < sizeof(Storage); i++)
    {
        if (Buffer[i] != 0xCC)
        {
            ok(FALSE, "%s: larger buffer was written past %lu bytes (offset %lu)\n", Name, Size, i);
            break;
        }
    }
}

static HANDLE Dup(HANDLE Token, TOKEN_TYPE Type)
{
    HANDLE New = NULL;
    OBJECT_ATTRIBUTES Attributes;
    SECURITY_QUALITY_OF_SERVICE Qos;
    NTSTATUS Status;

    Qos.Length = sizeof(Qos);
    Qos.ImpersonationLevel = SecurityImpersonation;
    Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    Qos.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);
    Attributes.SecurityQualityOfService = &Qos;
    Status = NtDuplicateToken(Token, TOKEN_ALL_ACCESS, &Attributes, FALSE, Type, &New);
    ok_hex(Status, STATUS_SUCCESS);
    return New;
}

static void TestBufferLengths(HANDLE Primary)
{
    HANDLE Impersonation;
    ULONGLONG Storage[8];
    PUCHAR Buffer = (PUCHAR)Storage;
    ULONG ReturnLength;
    NTSTATUS Status;

    CheckFixedLength(Primary, CLS_SESSIONID, sizeof(ULONG), "TokenSessionId");
    CheckFixedLength(Primary, CLS_SANDBOXINERT, sizeof(ULONG), "TokenSandBoxInert");
    CheckFixedLength(Primary, CLS_ORIGIN, sizeof(TOKEN_ORIGIN), "TokenOrigin");

    /* The impersonation level of a primary token is not a thing, whatever the buffer */
    ReturnLength = 0xdeadbeef;
    Status = Query(Primary, TokenImpersonationLevel, Buffer, sizeof(Storage), &ReturnLength);
    ok_hex(Status, STATUS_INVALID_INFO_CLASS);
    ok(ReturnLength == 0xdeadbeef, "ReturnLength changed to %lu\n", ReturnLength);

    Impersonation = Dup(Primary, TokenImpersonation);
    if (Impersonation)
    {
        PSECURITY_IMPERSONATION_LEVEL Level = (PSECURITY_IMPERSONATION_LEVEL)Buffer;

        CheckFixedLength(Impersonation, TokenImpersonationLevel, sizeof(ULONG), "TokenImpersonationLevel");
        RtlFillMemory(Buffer, sizeof(Storage), 0xCC);
        Status = Query(Impersonation, TokenImpersonationLevel, Buffer, sizeof(Storage), &ReturnLength);
        ok_hex(Status, STATUS_SUCCESS);
        ok(*Level == SecurityImpersonation, "Level %d\n", *Level);
        CheckFixedLength(Impersonation, CLS_SESSIONID, sizeof(ULONG), "TokenSessionId (impersonation)");
        NtClose(Impersonation);
    }

    /* TokenHasRestrictions is one byte on Windows */
    ReturnLength = 0xdeadbeef;
    Status = Query(Primary, CLS_HASRESTRICTIONS, NULL, 0, &ReturnLength);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok(ReturnLength == 1, "TokenHasRestrictions size %lu\n", ReturnLength);
    RtlFillMemory(Buffer, sizeof(Storage), 0xCC);
    ReturnLength = 0xdeadbeef;
    Status = Query(Primary, CLS_HASRESTRICTIONS, Buffer, sizeof(Storage), &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    ok(ReturnLength == 1, "TokenHasRestrictions length %lu\n", ReturnLength);
    ok(Buffer[0] == 0, "TokenHasRestrictions of the process token is %u\n", Buffer[0]);
    ok(Buffer[1] == 0xCC, "TokenHasRestrictions wrote more than one byte\n");
}

static void TestSmallClasses(HANDLE Primary)
{
    ULONGLONG Storage[8];
    PUCHAR Buffer = (PUCHAR)Storage;
    ULONG ReturnLength;
    NTSTATUS Status;
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;

    /* TokenCapabilities: a TOKEN_GROUPS without groups; only the count is written */
    ReturnLength = 0xdeadbeef;
    Status = Query(Primary, CLS_CAPABILITIES, NULL, 0, &ReturnLength);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok(ReturnLength == FIELD_OFFSET(TOKEN_GROUPS, Groups), "TokenCapabilities size %lu\n", ReturnLength);
    RtlFillMemory(Buffer, sizeof(Storage), 0xCC);
    Status = Query(Primary, CLS_CAPABILITIES, Buffer, sizeof(Storage), &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Groups->GroupCount == 0, "TokenCapabilities has %lu groups\n", Groups->GroupCount);
    ok(Buffer[sizeof(ULONG)] == 0xCC, "TokenCapabilities wrote past the count\n");

    /* No AppContainer, no protected process */
    CheckFixedLength(Primary, CLS_APPCONTAINERSID, sizeof(PVOID), "TokenAppContainerSid");
    RtlFillMemory(Buffer, sizeof(Storage), 0xCC);
    Status = Query(Primary, CLS_APPCONTAINERSID, Buffer, sizeof(PVOID), &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    ok(*(PVOID *)Buffer == NULL, "TokenAppContainerSid is not NULL\n");

    CheckFixedLength(Primary, CLS_APPCONTAINERNUM, sizeof(ULONG), "TokenAppContainerNumber");
    CheckFixedLength(Primary, CLS_ISRESTRICTED, sizeof(ULONG), "TokenIsRestricted");
    RtlFillMemory(Buffer, sizeof(Storage), 0xCC);
    Status = Query(Primary, CLS_ISRESTRICTED, Buffer, sizeof(ULONG), &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    ok(*(PULONG)Buffer == 0, "TokenIsRestricted is %lu\n", *(PULONG)Buffer);

    CheckFixedLength(Primary, CLS_TRUSTLEVEL, sizeof(PVOID), "TokenProcessTrustLevel");
    RtlFillMemory(Buffer, sizeof(Storage), 0xCC);
    Status = Query(Primary, CLS_TRUSTLEVEL, Buffer, sizeof(PVOID), &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    ok(*(PVOID *)Buffer == NULL, "TokenProcessTrustLevel is not NULL\n");
}

static void TestSource(void)
{
    HANDLE Token = NULL;
    TOKEN_SOURCE Source;
    ULONG ReturnLength = 0;
    NTSTATUS Status;

    Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &Token);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    RtlFillMemory(&Source, sizeof(Source), 0xCC);
    Status = Query(Token, TokenSource, &Source, sizeof(Source), &ReturnLength);
    ok_hex(Status, STATUS_SUCCESS);
    ok(ReturnLength == sizeof(TOKEN_SOURCE), "TokenSource length %lu\n", ReturnLength);
    ok(Source.SourceName[0] != (CHAR)0xCC, "TokenSource not written\n");
    NtClose(Token);
}

static void TestGroupsAndPrivileges(HANDLE Token)
{
    ULONG Size = 0, GroupsSize, i;
    PTOKEN_GROUPS_AND_PRIVILEGES Info;
    PTOKEN_GROUPS Groups;
    PTOKEN_PRIVILEGES Privileges;
    PTOKEN_USER User;
    TOKEN_STATISTICS Statistics;
    ULONG Length;

    Info = QueryAlloc(Token, CLS_GROUPSANDPRIVS, &Size);
    Groups = QueryAlloc(Token, TokenGroups, &GroupsSize);
    Privileges = QueryAlloc(Token, TokenPrivileges, NULL);
    User = QueryAlloc(Token, TokenUser, NULL);
    ok_hex(Query(Token, TokenStatistics, &Statistics, sizeof(Statistics), &Length), STATUS_SUCCESS);
    if (Info && Groups && Privileges && User)
    {
        ok(Info->SidCount == Groups->GroupCount + 1, "SidCount %lu, groups %lu\n", Info->SidCount, Groups->GroupCount);
        ok(Info->PrivilegeCount == Privileges->PrivilegeCount, "PrivilegeCount %lu, expected %lu\n",
           Info->PrivilegeCount, Privileges->PrivilegeCount);
        ok(Info->PrivilegeLength == Info->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES), "PrivilegeLength %lu\n", Info->PrivilegeLength);
        ok(Info->AuthenticationId.LowPart == Statistics.AuthenticationId.LowPart &&
           Info->AuthenticationId.HighPart == Statistics.AuthenticationId.HighPart, "AuthenticationId differs\n");
        ok(Info->RestrictedSidCount == 0, "RestrictedSidCount %lu\n", Info->RestrictedSidCount);
        if (InBuffer(Info, Size, Info->Sids, Info->SidCount * sizeof(SID_AND_ATTRIBUTES)))
        {
            ok(RtlEqualSid(Info->Sids[0].Sid, User->User.Sid), "First SID is not the user\n");
            for (i = 0; i < Groups->GroupCount; i++)
            {
                ok(InBuffer(Info, Size, Info->Sids[i + 1].Sid, RtlLengthSid(Info->Sids[i + 1].Sid)), "SID %lu outside the buffer\n", i);
                ok(RtlEqualSid(Info->Sids[i + 1].Sid, Groups->Groups[i].Sid), "SID %lu differs\n", i);
                ok(Info->Sids[i + 1].Attributes == Groups->Groups[i].Attributes, "SID %lu attributes differ\n", i);
            }
        }
        else
            ok(FALSE, "Sids %p outside the buffer %p (%lu)\n", Info->Sids, Info, Size);
        if (Info->PrivilegeCount)
        {
            ok(InBuffer(Info, Size, Info->Privileges, Info->PrivilegeLength), "Privileges outside the buffer\n");
            ok(!memcmp(Info->Privileges, Privileges->Privileges, Info->PrivilegeLength), "Privileges differ\n");
        }
    }
    if (Info) RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
    if (Groups) RtlFreeHeap(RtlGetProcessHeap(), 0, Groups);
    if (Privileges) RtlFreeHeap(RtlGetProcessHeap(), 0, Privileges);
    if (User) RtlFreeHeap(RtlGetProcessHeap(), 0, User);
}

static void CheckHash(PVOID Buffer, ULONG Size, PSID_AND_ATTRIBUTES_HASH Hash, ULONG ExpectedCount,
                      PTOKEN_USER User, PTOKEN_GROUPS Groups, const char *Name)
{
    ULONG i;

    ok(InBuffer(Buffer, Size, Hash, sizeof(*Hash)), "%s hash outside the buffer\n", Name);
    if (!InBuffer(Buffer, Size, Hash, sizeof(*Hash)))
        return;
    ok(Hash->SidCount == ExpectedCount, "%s hash has %lu SIDs, expected %lu\n", Name, Hash->SidCount, ExpectedCount);
    if (!ExpectedCount || Hash->SidCount != ExpectedCount)
        return;
    if (!InBuffer(Buffer, Size, Hash->SidAttr, ExpectedCount * sizeof(SID_AND_ATTRIBUTES)))
    {
        ok(FALSE, "%s SidAttr outside the buffer\n", Name);
        return;
    }
    if (User)
    {
        ok(RtlEqualSid(Hash->SidAttr[0].Sid, User->User.Sid), "%s first SID is not the user\n", Name);
        for (i = 0; i < Groups->GroupCount; i++)
        {
            ok(InBuffer(Buffer, Size, Hash->SidAttr[i + 1].Sid, RtlLengthSid(Hash->SidAttr[i + 1].Sid)), "%s SID %lu outside the buffer\n", Name, i);
            ok(RtlEqualSid(Hash->SidAttr[i + 1].Sid, Groups->Groups[i].Sid), "%s SID %lu differs\n", Name, i);
            ok(Hash->SidAttr[i + 1].Attributes == Groups->Groups[i].Attributes, "%s SID %lu attributes differ\n", Name, i);
        }
    }
}

static void TestAccessInformation(HANDLE Token)
{
    ULONG Size = 0, Needed = 0, i, Length;
    PTQ_ACCESS_INFORMATION Info;
    PTOKEN_GROUPS Groups;
    PTOKEN_PRIVILEGES Privileges;
    PTOKEN_USER User;
    TOKEN_STATISTICS Statistics;
    ULONGLONG SmallStorage[2];
    PUCHAR Small = (PUCHAR)SmallStorage;
    NTSTATUS Status;

    /* A short buffer gets the size and is left alone */
    RtlFillMemory(Small, sizeof(SmallStorage), 0xCC);
    Status = Query(Token, CLS_ACCESSINFO, Small, sizeof(SmallStorage), &Needed);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok(Needed > sizeof(TQ_ACCESS_INFORMATION), "TokenAccessInformation size %lu\n", Needed);
    ok(Small[0] == 0xCC && Small[sizeof(SmallStorage) - 1] == 0xCC, "TokenAccessInformation wrote into a short buffer\n");

    Info = QueryAlloc(Token, CLS_ACCESSINFO, &Size);
    Groups = QueryAlloc(Token, TokenGroups, NULL);
    Privileges = QueryAlloc(Token, TokenPrivileges, NULL);
    User = QueryAlloc(Token, TokenUser, NULL);
    ok_hex(Query(Token, TokenStatistics, &Statistics, sizeof(Statistics), &Length), STATUS_SUCCESS);
    ok(Size == Needed, "Size %lu, size query said %lu\n", Size, Needed);
    if (Info && Groups && Privileges && User)
    {
        ok(Info->AuthenticationId.LowPart == Statistics.AuthenticationId.LowPart &&
           Info->AuthenticationId.HighPart == Statistics.AuthenticationId.HighPart, "AuthenticationId differs\n");
        ok(Info->TokenType == TokenPrimary, "TokenType %d\n", Info->TokenType);
        ok(Info->ImpersonationLevel == 0, "ImpersonationLevel %d\n", Info->ImpersonationLevel);
        ok(Info->MandatoryPolicy == 3, "MandatoryPolicy 0x%lx\n", Info->MandatoryPolicy);
        ok(Info->AppContainerNumber == 0, "AppContainerNumber %lu\n", Info->AppContainerNumber);
        ok(Info->PackageSid == NULL, "PackageSid %p\n", Info->PackageSid);
        ok(Info->TrustLevelSid == NULL, "TrustLevelSid %p\n", Info->TrustLevelSid);
        ok(Info->Flags & TQ_NOT_LOW, "Flags 0x%lx lack TOKEN_NOT_LOW\n", Info->Flags);
        ok(!(Info->Flags & TQ_IS_FILTERED), "Flags 0x%lx has TOKEN_IS_FILTERED\n", Info->Flags);
        CheckHash(Info, Size, Info->SidHash, Groups->GroupCount + 1, User, Groups, "SidHash");
        CheckHash(Info, Size, Info->RestrictedSidHash, 0, NULL, NULL, "RestrictedSidHash");
        CheckHash(Info, Size, Info->CapabilitiesHash, 0, NULL, NULL, "CapabilitiesHash");
        ok(InBuffer(Info, Size, Info->Privileges, FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[Privileges->PrivilegeCount])),
           "Privileges outside the buffer\n");
        if (InBuffer(Info, Size, Info->Privileges, sizeof(ULONG)))
        {
            ok(Info->Privileges->PrivilegeCount == Privileges->PrivilegeCount, "PrivilegeCount %lu, expected %lu\n",
               Info->Privileges->PrivilegeCount, Privileges->PrivilegeCount);
            for (i = 0; i < Privileges->PrivilegeCount && i < Info->Privileges->PrivilegeCount; i++)
            {
                ok(RtlEqualLuid(&Info->Privileges->Privileges[i].Luid, &Privileges->Privileges[i].Luid) &&
                   Info->Privileges->Privileges[i].Attributes == Privileges->Privileges[i].Attributes, "Privilege %lu differs\n", i);
            }
        }
#ifndef _WIN64
        /* The 32-bit layout is the one Windows reports, byte for byte in size: 1068 bytes for 13 groups and 24 privileges */
        {
            ULONG Sids = 0;
            for (i = 0; i < Groups->GroupCount; i++)
                Sids += (RtlLengthSid(Groups->Groups[i].Sid) + 3) & ~3UL;
            Sids += (RtlLengthSid(User->User.Sid) + 3) & ~3UL;
            Sids += (Groups->GroupCount + 1) * sizeof(SID_AND_ATTRIBUTES);
            ok(Size == 56 + 3 * 136 + Sids + (4 + Privileges->PrivilegeCount * 12), "32-bit size %lu\n", Size);
        }
#endif
    }
    if (Info) RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
    if (Groups) RtlFreeHeap(RtlGetProcessHeap(), 0, Groups);
    if (Privileges) RtlFreeHeap(RtlGetProcessHeap(), 0, Privileges);
    if (User) RtlFreeHeap(RtlGetProcessHeap(), 0, User);
}

/*
 * A thread of the caller rewrites the output buffer while the call runs. The kernel must build the answer
 * on its own side and never take a destination from that memory: every pointer-sized slot of the first
 * part of the buffer (where the pointers of the answer are) is pointed at a canary block, which must come
 * out untouched, and the call itself must stay well-behaved.
 */
typedef struct _TQ_RACE
{
    volatile LONG Stop;
    PVOID *Slots;
    ULONG SlotCount;
    PVOID Target;
} TQ_RACE;

static DWORD WINAPI RaceThread(PVOID Parameter)
{
    TQ_RACE *Race = Parameter;
    ULONG i;

    while (!Race->Stop)
    {
        for (i = 0; i < Race->SlotCount; i++)
            ((volatile PVOID *)Race->Slots)[i] = Race->Target;
    }
    return 0;
}

static void TestAccessInformationRace(HANDLE Token)
{
    ULONG Size = 0, i, Round, Bad = 0;
    PUCHAR Output, Canary;
    ULONG CanarySize = 0x10000;
    TQ_RACE Race;
    HANDLE Thread;
    NTSTATUS Status;

    Status = Query(Token, CLS_ACCESSINFO, NULL, 0, &Size);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    if (!Size)
        return;
    Output = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size + 64);
    Canary = RtlAllocateHeap(RtlGetProcessHeap(), 0, CanarySize);
    if (!Output || !Canary)
    {
        skip("No memory\n");
        return;
    }
    RtlFillMemory(Canary, CanarySize, 0xAA);
    Race.Stop = 0;
    Race.Slots = (PVOID *)Output;
    /* the header and the first hash: where the pointers of the answer are stored */
    Race.SlotCount = min(Size, 0x400) / sizeof(PVOID);
    Race.Target = Canary + CanarySize / 2;
    Thread = CreateThread(NULL, 0, RaceThread, &Race, 0, NULL);
    if (!Thread)
    {
        skip("CreateThread failed\n");
        return;
    }
    for (Round = 0; Round < 3000; Round++)
    {
        ULONG Returned = 0;

        Status = Query(Token, CLS_ACCESSINFO, Output, Size, &Returned);
        if (Status != STATUS_SUCCESS || Returned != Size)
            Bad++;
    }
    Race.Stop = 1;
    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);
    ok(Bad == 0, "%lu calls failed during the race\n", Bad);
    for (i = 0; i < CanarySize; i++)
    {
        if (Canary[i] != 0xAA)
        {
            ok(FALSE, "The kernel wrote into memory a racing thread pointed the answer at (offset %lu)\n", i);
            break;
        }
    }
    /* the 64 bytes after the answer are not part of it */
    for (i = Size; i < Size + 64; i++)
    {
        if (Output[i] != 0)
        {
            ok(FALSE, "The kernel wrote past the answer (offset %lu)\n", i);
            break;
        }
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, Output);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Canary);
}

static void TestPrivilegeCheckAndCompare(HANDLE Primary)
{
    HANDLE Filtered = NULL, FilteredImp = NULL, Imp;
    PRIVILEGE_SET Set;
    BOOLEAN Result, Equal;
    NTSTATUS Status;

    /* NtCompareTokens used to be missing under WoW64 (STATUS_INVALID_SYSTEM_SERVICE) */
    Equal = 0xAA;
    Status = NtCompareTokens(Primary, Primary, &Equal);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Equal == TRUE, "A token differs from itself (%u)\n", Equal);

    Status = NtFilterToken(Primary, DISABLE_MAX_PRIVILEGE, NULL, NULL, NULL, &Filtered);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Equal = 0xAA;
    Status = NtCompareTokens(Primary, Filtered, &Equal);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Equal == FALSE, "A token without privileges equals the original (%u)\n", Equal);

    /* NtPrivilegeCheck: an impersonation token, SeChangeNotifyPrivilege is kept, SeDebugPrivilege is not */
    Imp = Dup(Primary, TokenImpersonation);
    FilteredImp = Dup(Filtered, TokenImpersonation);
    if (FilteredImp)
    {
        Set.PrivilegeCount = 1;
        Set.Control = PRIVILEGE_SET_ALL_NECESSARY;
        Set.Privilege[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
        Set.Privilege[0].Luid.HighPart = 0;
        Set.Privilege[0].Attributes = 0;
        Result = 0xAA;
        Status = NtPrivilegeCheck(FilteredImp, &Set, &Result);
        ok_hex(Status, STATUS_SUCCESS);
        ok(Result == TRUE, "SeChangeNotifyPrivilege check %u\n", Result);
        ok(Set.Privilege[0].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS, "Attributes 0x%lx\n", Set.Privilege[0].Attributes);

        Set.Privilege[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        Set.Privilege[0].Attributes = 0;
        Result = 0xAA;
        Status = NtPrivilegeCheck(FilteredImp, &Set, &Result);
        ok_hex(Status, STATUS_SUCCESS);
        ok(Result == FALSE, "SeDebugPrivilege check %u\n", Result);
        NtClose(FilteredImp);
    }
    if (Imp)
        NtClose(Imp);
    NtClose(Filtered);
}

static PTOKEN_GROUPS GroupsOf(HANDLE Token)
{
    return QueryAlloc(Token, TokenGroups, NULL);
}

static PSID_AND_ATTRIBUTES FindGroup(PTOKEN_GROUPS Groups, PSID Sid)
{
    ULONG i;

    for (i = 0; Groups && i < Groups->GroupCount; i++)
    {
        if (RtlEqualSid(Groups->Groups[i].Sid, Sid))
            return &Groups->Groups[i];
    }
    return NULL;
}

static ULONG ElevationOf(HANDLE Token)
{
    ULONG Value = 0xdeadbeef, Length;

    ok_hex(Query(Token, CLS_ELEVATION, &Value, sizeof(Value), &Length), STATUS_SUCCESS);
    return Value;
}

static BOOLEAN HasRestrictionsOf(HANDLE Token)
{
    ULONG Value = 0xCCCCCC00;
    ULONG Length;

    /* the class is one byte; the buffer is aligned like the others */
    ok_hex(Query(Token, CLS_HASRESTRICTIONS, &Value, 1, &Length), STATUS_SUCCESS);
    ok(Length == 1 && (Value & 0xFFFFFF00) == 0xCCCCCC00, "TokenHasRestrictions wrote 0x%lx (length %lu)\n", Value, Length);
    return (Value & 0xFF) != 0;
}

static BOOLEAN KeptByLua(ULONG Privilege)
{
    return Privilege == SE_SHUTDOWN_PRIVILEGE || Privilege == SE_CHANGE_NOTIFY_PRIVILEGE ||
           Privilege == SE_UNDOCK_PRIVILEGE || Privilege == SE_INC_WORKING_SET_PRIVILEGE ||
           Privilege == SE_TIME_ZONE_PRIVILEGE;
}

static void TestLuaToken(HANDLE Primary)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID AdminsSid = NULL, LocalAdminSid = NULL;
    PTOKEN_GROUPS Groups, LuaGroups;
    PSID_AND_ATTRIBUTES Admins, LocalAdmin;
    PTOKEN_PRIVILEGES Privileges, LuaPrivileges;
    PTOKEN_OWNER Owner, LuaOwner;
    PTOKEN_USER User;
    HANDLE Lua = NULL, LuaMax = NULL, Max = NULL, Copy;
    ULONG i, Elevation, Length, IsRestricted = 0xdeadbeef;
    ULONGLONG IntegrityStorage[8], LuaIntegrityStorage[8];
    PUCHAR Integrity = (PUCHAR)IntegrityStorage, LuaIntegrity = (PUCHAR)LuaIntegrityStorage;
    BOOLEAN WasOwner;
    NTSTATUS Status;

    RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminsSid);
    RtlAllocateAndInitializeSid(&NtAuthority, 1, 114, 0, 0, 0, 0, 0, 0, 0, &LocalAdminSid);
    Groups = GroupsOf(Primary);
    Admins = FindGroup(Groups, AdminsSid);
    if (!Admins || !(Admins->Attributes & SE_GROUP_ENABLED) || (Admins->Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
    {
        skip("The test does not run elevated: no enabled Administrators group\n");
        goto Cleanup;
    }
    LocalAdmin = FindGroup(Groups, LocalAdminSid);
    Elevation = ElevationOf(Primary);
    ok(Elevation == 1, "The original token's elevation is %lu\n", Elevation);
    ok(!HasRestrictionsOf(Primary), "The original token reports restrictions\n");
    Privileges = QueryAlloc(Primary, TokenPrivileges, NULL);
    Owner = QueryAlloc(Primary, TokenOwner, NULL);
    User = QueryAlloc(Primary, TokenUser, NULL);
    WasOwner = Owner && RtlEqualSid(Owner->Owner, AdminsSid);

    /* A plain copy is not filtered */
    Copy = Dup(Primary, TokenPrimary);
    if (Copy)
    {
        ok(!HasRestrictionsOf(Copy), "A duplicate reports restrictions\n");
        NtClose(Copy);
    }

    Status = NtFilterToken(Primary, LUA_TOKEN, NULL, NULL, NULL, &Lua);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        LuaGroups = GroupsOf(Lua);
        LuaPrivileges = QueryAlloc(Lua, TokenPrivileges, NULL);
        LuaOwner = QueryAlloc(Lua, TokenOwner, NULL);
        if (LuaGroups)
        {
            PSID_AND_ATTRIBUTES Group = FindGroup(LuaGroups, AdminsSid);

            ok(LuaGroups->GroupCount == Groups->GroupCount, "A LUA token has %lu groups, expected %lu\n", LuaGroups->GroupCount, Groups->GroupCount);
            ok(Group && Group->Attributes == SE_GROUP_USE_FOR_DENY_ONLY, "Administrators attributes 0x%lx\n", Group ? Group->Attributes : 0);
            if (LocalAdmin)
            {
                Group = FindGroup(LuaGroups, LocalAdminSid);
                ok(Group && Group->Attributes == SE_GROUP_USE_FOR_DENY_ONLY, "S-1-5-114 attributes 0x%lx\n", Group ? Group->Attributes : 0);
            }
            /* every other group is as it was */
            for (i = 0; i < Groups->GroupCount; i++)
            {
                if (RtlEqualSid(Groups->Groups[i].Sid, AdminsSid) || RtlEqualSid(Groups->Groups[i].Sid, LocalAdminSid))
                    continue;
                Group = FindGroup(LuaGroups, Groups->Groups[i].Sid);
                ok(Group && Group->Attributes == Groups->Groups[i].Attributes, "Group %lu attributes changed\n", i);
            }
            RtlFreeHeap(RtlGetProcessHeap(), 0, LuaGroups);
        }
        if (LuaPrivileges && Privileges)
        {
            ULONG Kept = 0;

            for (i = 0; i < LuaPrivileges->PrivilegeCount; i++)
                ok(KeptByLua(LuaPrivileges->Privileges[i].Luid.LowPart), "LUA token kept privilege %lu\n", LuaPrivileges->Privileges[i].Luid.LowPart);
            for (i = 0; i < Privileges->PrivilegeCount; i++)
                if (KeptByLua(Privileges->Privileges[i].Luid.LowPart))
                    Kept++;
            ok(LuaPrivileges->PrivilegeCount == Kept, "LUA token has %lu privileges, expected %lu\n", LuaPrivileges->PrivilegeCount, Kept);
        }
        if (LuaOwner && User && WasOwner)
            ok(RtlEqualSid(LuaOwner->Owner, User->User.Sid), "The owner of a LUA token is not the user\n");
        ok(HasRestrictionsOf(Lua), "A LUA token does not report restrictions\n");
        ok(ElevationOf(Lua) == 0, "A LUA token is elevated\n");
        ok_hex(Query(Lua, CLS_ISRESTRICTED, &IsRestricted, sizeof(IsRestricted), &Length), STATUS_SUCCESS);
        ok(IsRestricted == 0, "TokenIsRestricted of a LUA token is %lu\n", IsRestricted);
        {
            PTOKEN_GROUPS Restricted = QueryAlloc(Lua, TokenRestrictedSids, NULL);
            ok(Restricted && Restricted->GroupCount == 0, "A LUA token has restricted SIDs\n");
            if (Restricted) RtlFreeHeap(RtlGetProcessHeap(), 0, Restricted);
        }
        /* the integrity level is kept */
        RtlFillMemory(Integrity, sizeof(IntegrityStorage), 0);
        RtlFillMemory(LuaIntegrity, sizeof(LuaIntegrityStorage), 0);
        ok_hex(Query(Primary, TokenIntegrityLevel, Integrity, sizeof(IntegrityStorage), &Length), STATUS_SUCCESS);
        ok_hex(Query(Lua, TokenIntegrityLevel, LuaIntegrity, sizeof(LuaIntegrityStorage), &Length), STATUS_SUCCESS);
        ok(RtlEqualSid(((PTOKEN_MANDATORY_LABEL)Integrity)->Label.Sid, ((PTOKEN_MANDATORY_LABEL)LuaIntegrity)->Label.Sid),
           "The integrity level of a LUA token changed\n");
        if (LuaPrivileges) RtlFreeHeap(RtlGetProcessHeap(), 0, LuaPrivileges);
        if (LuaOwner) RtlFreeHeap(RtlGetProcessHeap(), 0, LuaOwner);
        NtClose(Lua);
    }

    /* LUA_TOKEN with DISABLE_MAX_PRIVILEGE keeps only SeChangeNotifyPrivilege */
    Status = NtFilterToken(Primary, LUA_TOKEN | DISABLE_MAX_PRIVILEGE, NULL, NULL, NULL, &LuaMax);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        LuaPrivileges = QueryAlloc(LuaMax, TokenPrivileges, NULL);
        ok(LuaPrivileges && LuaPrivileges->PrivilegeCount == 1 && LuaPrivileges->Privileges[0].Luid.LowPart == SE_CHANGE_NOTIFY_PRIVILEGE,
           "LUA with DISABLE_MAX_PRIVILEGE has %lu privileges\n", LuaPrivileges ? LuaPrivileges->PrivilegeCount : 0);
        if (LuaPrivileges) RtlFreeHeap(RtlGetProcessHeap(), 0, LuaPrivileges);
        ok(ElevationOf(LuaMax) == 0, "LUA with DISABLE_MAX_PRIVILEGE is elevated\n");
        NtClose(LuaMax);
    }

    /* Without LUA_TOKEN, DISABLE_MAX_PRIVILEGE alone leaves the Administrators group and the owner (and the token elevated) */
    Status = NtFilterToken(Primary, DISABLE_MAX_PRIVILEGE, NULL, NULL, NULL, &Max);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        PTOKEN_GROUPS MaxGroups = GroupsOf(Max);
        PSID_AND_ATTRIBUTES Group = FindGroup(MaxGroups, AdminsSid);

        ok(Group && Group->Attributes == Admins->Attributes, "Administrators attributes 0x%lx\n", Group ? Group->Attributes : 0);
        ok(HasRestrictionsOf(Max), "A filtered token does not report restrictions\n");
        ok(ElevationOf(Max) == Elevation, "The elevation changed to %lu\n", ElevationOf(Max));
        if (MaxGroups) RtlFreeHeap(RtlGetProcessHeap(), 0, MaxGroups);
        NtClose(Max);
    }

    if (Privileges) RtlFreeHeap(RtlGetProcessHeap(), 0, Privileges);
    if (Owner) RtlFreeHeap(RtlGetProcessHeap(), 0, Owner);
    if (User) RtlFreeHeap(RtlGetProcessHeap(), 0, User);

Cleanup:
    if (Groups) RtlFreeHeap(RtlGetProcessHeap(), 0, Groups);
    if (AdminsSid) RtlFreeSid(AdminsSid);
    if (LocalAdminSid) RtlFreeSid(LocalAdminSid);
}

START_TEST(NtTokenQueryParity)
{
    HANDLE Token = NULL;
    NTSTATUS Status;

    Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &Token);
    if (!NT_SUCCESS(Status))
    {
        skip("Cannot open the process token (0x%lx)\n", Status);
        return;
    }

    TestBufferLengths(Token);
    TestSmallClasses(Token);
    TestSource();
    TestGroupsAndPrivileges(Token);
    TestAccessInformation(Token);
    TestAccessInformationRace(Token);
    TestPrivilegeCheckAndCompare(Token);
    TestLuaToken(Token);

    NtClose(Token);
}
