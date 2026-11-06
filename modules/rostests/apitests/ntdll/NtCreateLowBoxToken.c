/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for NtCreateLowBoxToken and the AppContainer token information classes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * From the documented contract (CreateAppContainerToken, NtCreateLowBoxToken, TOKEN_INFORMATION_CLASS):
 *  - the new token is a copy of the existing one that belongs to the AppContainer of the package SID:
 *    TokenIsAppContainer 1, TokenAppContainerSid a TOKEN_APPCONTAINER_INFORMATION whose pointer points at a copy of
 *    the package SID that follows it, TokenAppContainerNumber not 0, TokenCapabilities the capabilities with their
 *    attributes, low integrity; the existing token is unchanged.
 *  - a token that is no lowbox token reports 0, a NULL SID, number 0 and no capabilities (measured before, see
 *    NtTokenQueryParity).
 *  - the token keeps the objects of the handles passed with it: a named object whose last handle is closed stays
 *    reachable by name while the token lives.
 * Not measured on Windows, checked as this implementation answers: a SID that is no package SID and more than 64
 * handles are STATUS_INVALID_PARAMETER, an invalid handle in the array is STATUS_INVALID_HANDLE, the AppContainer
 * number is the same for the same package and differs between packages.
 * Runs as a native and as a WoW64 (32-bit) process.
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PFN_CreateLowBox)(PHANDLE, HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PSID, ULONG,
                                           PSID_AND_ATTRIBUTES, ULONG, HANDLE *);

#define TokenIsAppContainer_     ((TOKEN_INFORMATION_CLASS)29)
#define TokenCapabilities_       ((TOKEN_INFORMATION_CLASS)30)
#define TokenAppContainerSid_    ((TOKEN_INFORMATION_CLASS)31)
#define TokenAppContainerNumber_ ((TOKEN_INFORMATION_CLASS)32)

static PFN_CreateLowBox pNtCreateLowBoxToken;

/* S-1-15-2-1-2-3-4-5-6-7 and S-1-15-2-11-12-13-14-15-16-17 (packages), S-1-15-3-1 and S-1-15-3-3 (capabilities) */
static struct { UCHAR Revision, Count, Authority[6]; ULONG Sub[8]; } Package1 =
    { 1, 8, { 0, 0, 0, 0, 0, 15 }, { 2, 1, 2, 3, 4, 5, 6, 7 } };
static struct { UCHAR Revision, Count, Authority[6]; ULONG Sub[8]; } Package2 =
    { 1, 8, { 0, 0, 0, 0, 0, 15 }, { 2, 11, 12, 13, 14, 15, 16, 17 } };
static struct { UCHAR Revision, Count, Authority[6]; ULONG Sub[2]; } Capability1 =
    { 1, 2, { 0, 0, 0, 0, 0, 15 }, { 3, 1 } };
static struct { UCHAR Revision, Count, Authority[6]; ULONG Sub[2]; } Capability2 =
    { 1, 2, { 0, 0, 0, 0, 0, 15 }, { 3, 3 } };
static struct { UCHAR Revision, Count, Authority[6]; ULONG Sub[1]; } Everyone =
    { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };

static HANDLE OpenOwnToken(ACCESS_MASK Access)
{
    HANDLE Token = NULL;
    NTSTATUS Status = NtOpenProcessToken(NtCurrentProcess(), Access, &Token);
    ok_hex(Status, STATUS_SUCCESS);
    return Token;
}

static ULONG QueryUlong(HANDLE Token, TOKEN_INFORMATION_CLASS Class)
{
    ULONG Value = 0xDEADBEEF, Length = 0;
    NTSTATUS Status = NtQueryInformationToken(Token, Class, &Value, sizeof(Value), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_long(Length, sizeof(ULONG));
    return Value;
}

static ULONG QueryIntegrity(HANDLE Token)
{
    UCHAR Buffer[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE];
    PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)Buffer;
    ULONG Length;
    NTSTATUS Status = NtQueryInformationToken(Token, TokenIntegrityLevel, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return 0;
    return *RtlSubAuthoritySid(Label->Label.Sid, 0);
}

/* What a token that is not an AppContainer's reports */
static void CheckNotAppContainer(HANDLE Token)
{
    PVOID Pointer = (PVOID)(ULONG_PTR)0xDEADBEEF;
    TOKEN_GROUPS Groups;
    ULONG Length = 0;
    NTSTATUS Status;

    ok_long(QueryUlong(Token, TokenIsAppContainer_), 0);
    ok_long(QueryUlong(Token, TokenAppContainerNumber_), 0);
    Status = NtQueryInformationToken(Token, TokenAppContainerSid_, &Pointer, sizeof(Pointer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_long(Length, sizeof(PVOID));
    ok(Pointer == NULL, "AppContainer SID pointer %p\n", Pointer);
    Groups.GroupCount = 0xDEADBEEF;
    Status = NtQueryInformationToken(Token, TokenCapabilities_, &Groups, sizeof(Groups), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_long(Groups.GroupCount, 0);
}

static NTSTATUS CreateLowBox(HANDLE Existing, PSID Package, ULONG CapabilityCount, PSID_AND_ATTRIBUTES Capabilities,
                             ULONG HandleCount, HANDLE *Handles, PHANDLE Token)
{
    *Token = (HANDLE)(ULONG_PTR)0xDEADBEEF;
    return pNtCreateLowBoxToken(Token, Existing, TOKEN_ALL_ACCESS, NULL, Package, CapabilityCount, Capabilities,
                                HandleCount, Handles);
}

static void TestParameters(void)
{
    HANDLE Existing = OpenOwnToken(TOKEN_ALL_ACCESS), QueryOnly = OpenOwnToken(TOKEN_QUERY), Token;
    HANDLE Many[65], Bad = (HANDLE)(ULONG_PTR)0x7FFC;
    SID_AND_ATTRIBUTES Capability;
    UCHAR BadSid[sizeof(Package1)];
    NTSTATUS Status;
    ULONG i;

    /* No package SID, or a SID that is no package SID */
    Status = CreateLowBox(Existing, NULL, 0, NULL, 0, NULL, &Token);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    Status = CreateLowBox(Existing, &Everyone, 0, NULL, 0, NULL, &Token);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    Status = CreateLowBox(Existing, &Capability1, 0, NULL, 0, NULL, &Token);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    /* A malformed SID: revision 2 */
    memcpy(BadSid, &Package1, sizeof(BadSid));
    BadSid[0] = 2;
    Status = CreateLowBox(Existing, BadSid, 0, NULL, 0, NULL, &Token);
    ok_hex(Status, STATUS_INVALID_SID);

    /* Bad pointers */
    Status = CreateLowBox(Existing, (PSID)(ULONG_PTR)0x10, 0, NULL, 0, NULL, &Token);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = pNtCreateLowBoxToken((PHANDLE)(ULONG_PTR)0x10, Existing, TOKEN_ALL_ACCESS, NULL, &Package1, 0, NULL, 0, NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = CreateLowBox(Existing, &Package1, 1, (PSID_AND_ATTRIBUTES)(ULONG_PTR)0x10, 0, NULL, &Token);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Capability.Sid = (PSID)(ULONG_PTR)0x10;
    Capability.Attributes = SE_GROUP_ENABLED;
    Status = CreateLowBox(Existing, &Package1, 1, &Capability, 0, NULL, &Token);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = CreateLowBox(Existing, &Package1, 0, NULL, 1, (HANDLE *)(ULONG_PTR)0x10, &Token);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    /* A malformed capability */
    Capability.Sid = BadSid;
    Status = CreateLowBox(Existing, &Package1, 1, &Capability, 0, NULL, &Token);
    ok_hex(Status, STATUS_INVALID_SID);

    /* The existing token: invalid, no token, no TOKEN_DUPLICATE */
    Status = CreateLowBox(NULL, &Package1, 0, NULL, 0, NULL, &Token);
    ok_hex(Status, STATUS_INVALID_HANDLE);
    Status = CreateLowBox(NtCurrentProcess(), &Package1, 0, NULL, 0, NULL, &Token);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    Status = CreateLowBox(QueryOnly, &Package1, 0, NULL, 0, NULL, &Token);
    ok_hex(Status, STATUS_ACCESS_DENIED);

    /* Handles: too many, an invalid one */
    for (i = 0; i < RTL_NUMBER_OF(Many); i++) Many[i] = Existing;
    Status = CreateLowBox(Existing, &Package1, 0, NULL, RTL_NUMBER_OF(Many), Many, &Token);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    Status = CreateLowBox(Existing, &Package1, 0, NULL, 1, &Bad, &Token);
    ok_hex(Status, STATUS_INVALID_HANDLE);

    /* 64 handles are accepted */
    Status = CreateLowBox(Existing, &Package1, 0, NULL, 64, Many, &Token);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status)) NtClose(Token);

    NtClose(QueryOnly);
    NtClose(Existing);
}

static void TestRoundTrip(void)
{
    HANDLE Existing = OpenOwnToken(TOKEN_ALL_ACCESS), Token, Token2, Token3, Duplicate;
    SID_AND_ATTRIBUTES Capabilities[2];
    UCHAR Buffer[512];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    struct { PSID TokenAppContainer; } *AcInfo = (PVOID)Buffer; /* TOKEN_APPCONTAINER_INFORMATION */
    OBJECT_ATTRIBUTES Attributes;
    TOKEN_TYPE Type;
    ULONG Length, Number, Expected;
    NTSTATUS Status;

    Capabilities[0].Sid = &Capability1;
    Capabilities[0].Attributes = SE_GROUP_ENABLED;
    Capabilities[1].Sid = &Capability2;
    Capabilities[1].Attributes = SE_GROUP_ENABLED;

    Status = CreateLowBox(Existing, &Package1, 2, Capabilities, 0, NULL, &Token);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        NtClose(Existing);
        return;
    }

    /* The AppContainer classes */
    ok_long(QueryUlong(Token, TokenIsAppContainer_), 1);
    Number = QueryUlong(Token, TokenAppContainerNumber_);
    ok(Number != 0, "AppContainer number 0\n");

    Expected = sizeof(PVOID) + RtlLengthSid(&Package1);
    Length = 0;
    Status = NtQueryInformationToken(Token, TokenAppContainerSid_, Buffer, sizeof(PVOID), &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok_long(Length, Expected);
    memset(Buffer, 0xCC, sizeof(Buffer));
    Status = NtQueryInformationToken(Token, TokenAppContainerSid_, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_long(Length, Expected);
    ok(AcInfo->TokenAppContainer == (PSID)(Buffer + sizeof(PVOID)), "SID at %p, buffer %p\n", AcInfo->TokenAppContainer, Buffer);
    ok(RtlEqualSid(AcInfo->TokenAppContainer, &Package1), "not the package SID\n");

    Expected = FIELD_OFFSET(TOKEN_GROUPS, Groups) + 2 * sizeof(SID_AND_ATTRIBUTES) +
               RtlLengthSid(&Capability1) + RtlLengthSid(&Capability2);
    Status = NtQueryInformationToken(Token, TokenCapabilities_, Buffer, sizeof(ULONG), &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok_long(Length, Expected);
    memset(Buffer, 0xCC, sizeof(Buffer));
    Status = NtQueryInformationToken(Token, TokenCapabilities_, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_long(Length, Expected);
    ok_long(Groups->GroupCount, 2);
    if (Groups->GroupCount == 2)
    {
        ok(RtlEqualSid(Groups->Groups[0].Sid, &Capability1), "capability 0\n");
        ok(RtlEqualSid(Groups->Groups[1].Sid, &Capability2), "capability 1\n");
        ok_long(Groups->Groups[0].Attributes, SE_GROUP_ENABLED);
        ok_long(Groups->Groups[1].Attributes, SE_GROUP_ENABLED);
        ok((PUCHAR)Groups->Groups[0].Sid > Buffer && (PUCHAR)Groups->Groups[1].Sid < Buffer + Length,
           "capability SIDs outside the buffer\n");
    }

    /* Low integrity, same type; the existing token is unchanged */
    ok_long(QueryIntegrity(Token), SECURITY_MANDATORY_LOW_RID);
    Status = NtQueryInformationToken(Token, TokenType, &Type, sizeof(Type), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_long(Type, TokenPrimary);
    CheckNotAppContainer(Existing);
    ok(QueryIntegrity(Existing) > SECURITY_MANDATORY_LOW_RID, "existing token lowered\n");

    /* Same package: same number; another package: another number */
    Status = CreateLowBox(Existing, &Package1, 0, NULL, 0, NULL, &Token2);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_long(QueryUlong(Token2, TokenAppContainerNumber_), Number);
        Status = NtQueryInformationToken(Token2, TokenCapabilities_, Buffer, sizeof(Buffer), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        ok_long(Groups->GroupCount, 0);
        NtClose(Token2);
    }
    Status = CreateLowBox(Existing, &Package2, 0, NULL, 0, NULL, &Token2);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ULONG Other = QueryUlong(Token2, TokenAppContainerNumber_);
        ok(Other != 0 && Other != Number, "numbers %lu and %lu\n", Number, Other);

        /* A lowbox token made from a lowbox token gets the new package */
        Status = CreateLowBox(Token2, &Package1, 0, NULL, 0, NULL, &Token3);
        ok_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            ok_long(QueryUlong(Token3, TokenAppContainerNumber_), Number);
            NtClose(Token3);
        }
        NtClose(Token2);
    }

    /* A copy of a lowbox token is one too */
    InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);
    Status = NtDuplicateToken(Token, TOKEN_QUERY, &Attributes, FALSE, TokenPrimary, &Duplicate);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_long(QueryUlong(Duplicate, TokenIsAppContainer_), 1);
        ok_long(QueryUlong(Duplicate, TokenAppContainerNumber_), Number);
        Status = NtQueryInformationToken(Duplicate, TokenCapabilities_, Buffer, sizeof(Buffer), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        ok_long(Groups->GroupCount, 2);
        NtClose(Duplicate);
    }

    /* A restricted copy as well */
    Status = NtFilterToken(Token, 0, NULL, NULL, NULL, &Duplicate);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_long(QueryUlong(Duplicate, TokenIsAppContainer_), 1);
        ok_long(QueryUlong(Duplicate, TokenAppContainerNumber_), Number);
        NtClose(Duplicate);
    }

    NtClose(Token);
    NtClose(Existing);
}

/* The token keeps the objects of the handles: a named event stays reachable while the token exists */
static void TestHandles(void)
{
    HANDLE Existing = OpenOwnToken(TOKEN_ALL_ACCESS), Token, Event, Again;
    WCHAR Name[64];
    NTSTATUS Status;

    StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"Local\\LowBoxTokenTest%lu", GetCurrentProcessId());
    Event = CreateEventW(NULL, TRUE, FALSE, Name);
    ok(Event != NULL, "CreateEventW failed: %lu\n", GetLastError());
    if (!Event)
    {
        NtClose(Existing);
        return;
    }

    Status = CreateLowBox(Existing, &Package1, 0, NULL, 1, &Event, &Token);
    ok_hex(Status, STATUS_SUCCESS);
    CloseHandle(Event);
    if (!NT_SUCCESS(Status))
    {
        NtClose(Existing);
        return;
    }

    Again = OpenEventW(SYNCHRONIZE, FALSE, Name);
    ok(Again != NULL, "event gone while the token holds it: %lu\n", GetLastError());
    if (Again) CloseHandle(Again);

    NtClose(Token);
    Again = OpenEventW(SYNCHRONIZE, FALSE, Name);
    ok(Again == NULL, "event still there after the token was closed\n");
    ok_long(GetLastError(), ERROR_FILE_NOT_FOUND);
    if (Again) CloseHandle(Again);
    NtClose(Existing);
}

/* Not every token class of a lowbox token: the access information carries the number, package and capabilities */
static void TestAccessInformation(void)
{
    HANDLE Existing = OpenOwnToken(TOKEN_ALL_ACCESS), Token;
    SID_AND_ATTRIBUTES Capability;
    PUCHAR Buffer;
    ULONG Length = 0, Number;
    NTSTATUS Status;
    /* The header of TOKEN_ACCESS_INFORMATION up to TrustLevelSid (Windows 8 and later) */
    struct
    {
        PSID_AND_ATTRIBUTES_HASH SidHash, RestrictedSidHash;
        PTOKEN_PRIVILEGES Privileges;
        LUID AuthenticationId;
        TOKEN_TYPE TokenType;
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        TOKEN_MANDATORY_POLICY MandatoryPolicy;
        ULONG Flags, AppContainerNumber;
        PSID PackageSid;
        PSID_AND_ATTRIBUTES_HASH CapabilitiesHash;
    } *Info;

    Capability.Sid = &Capability1;
    Capability.Attributes = SE_GROUP_ENABLED;
    Status = CreateLowBox(Existing, &Package1, 1, &Capability, 0, NULL, &Token);
    ok_hex(Status, STATUS_SUCCESS);
    NtClose(Existing);
    if (!NT_SUCCESS(Status)) return;

    Number = QueryUlong(Token, TokenAppContainerNumber_);
    Status = NtQueryInformationToken(Token, TokenAccessInformation, NULL, 0, &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    Buffer = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Buffer)
    {
        Status = NtQueryInformationToken(Token, TokenAccessInformation, Buffer, Length, &Length);
        ok_hex(Status, STATUS_SUCCESS);
        Info = (PVOID)Buffer;
        if (NT_SUCCESS(Status))
        {
            ok_long(Info->AppContainerNumber, Number);
            ok(Info->PackageSid && RtlEqualSid(Info->PackageSid, &Package1), "package SID\n");
            ok(Info->CapabilitiesHash != NULL, "no capability hash\n");
            if (Info->CapabilitiesHash)
            {
                ok_long(Info->CapabilitiesHash->SidCount, 1);
                if (Info->CapabilitiesHash->SidCount == 1)
                {
                    ok(RtlEqualSid(Info->CapabilitiesHash->SidAttr[0].Sid, &Capability1), "capability\n");
                    ok_long(Info->CapabilitiesHash->SidAttr[0].Attributes, SE_GROUP_ENABLED);
                }
            }
            ok((Info->Flags & 0x4000) != 0, "TOKEN_LOWBOX not in flags 0x%lx\n", Info->Flags);
            ok((Info->Flags & 0x2000) == 0, "TOKEN_NOT_LOW in flags 0x%lx\n", Info->Flags);
        }
        HeapFree(GetProcessHeap(), 0, Buffer);
    }
    NtClose(Token);
}

START_TEST(NtCreateLowBoxToken)
{
    HANDLE Token;

    pNtCreateLowBoxToken = (PFN_CreateLowBox)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateLowBoxToken");
    if (!pNtCreateLowBoxToken)
    {
        skip("NtCreateLowBoxToken is not exported\n");
        return;
    }

    Token = OpenOwnToken(TOKEN_QUERY);
    CheckNotAppContainer(Token);
    NtClose(Token);

    TestParameters();
    TestRoundTrip();
    TestHandles();
    TestAccessInformation();
}
