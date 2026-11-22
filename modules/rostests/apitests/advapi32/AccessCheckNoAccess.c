/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for an access check that asks for no access
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/obfuncs.h>
#include <ndk/exfuncs.h>

/*
 * Measured on Windows Server 2022: AccessCheck, AccessCheckByTypeResultList (NtAccessCheck*) with a
 * DesiredAccess of 0 return TRUE with the access status FALSE (ERROR_ACCESS_DENIED) and nothing
 * granted, whatever the descriptor (also a NULL DACL) and the token; what was granted before (the
 * implicit READ_CONTROL of the owner) is still the result when nothing else is asked for. Object opens
 * with an access of 0 are refused (STATUS_ACCESS_DENIED).
 */

static GENERIC_MAPPING Mapping = {0x1 | READ_CONTROL, 0x2 | WRITE_DAC, 0x4 | SYNCHRONIZE, 0x3F | STANDARD_RIGHTS_REQUIRED};

static PSECURITY_DESCRIPTOR MakeSd(BOOL NullDacl, PSID Owner)
{
    static BYTE Buffer[512];
    static SID_IDENTIFIER_AUTHORITY World = {SECURITY_WORLD_SID_AUTHORITY};
    BYTE AbsBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH], DaclBuffer[64];
    PSECURITY_DESCRIPTOR Abs = (PSECURITY_DESCRIPTOR)AbsBuffer;
    PACL Dacl = (PACL)DaclBuffer;
    PSID Everyone;
    DWORD Length = sizeof(Buffer);

    AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone);
    InitializeSecurityDescriptor(Abs, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(Abs, Owner ? Owner : Everyone, FALSE);
    SetSecurityDescriptorGroup(Abs, Everyone, FALSE);
    if (NullDacl)
    {
        SetSecurityDescriptorDacl(Abs, TRUE, NULL, FALSE);
    }
    else
    {
        InitializeAcl(Dacl, sizeof(DaclBuffer), ACL_REVISION);
        AddAccessAllowedAce(Dacl, ACL_REVISION, 0x1, Everyone);
        SetSecurityDescriptorDacl(Abs, TRUE, Dacl, FALSE);
    }
    ok(MakeSelfRelativeSD(Abs, Buffer, &Length), "MakeSelfRelativeSD failed: %lu\n", GetLastError());
    FreeSid(Everyone);
    return (PSECURITY_DESCRIPTOR)Buffer;
}

static void Check(int Line, HANDLE Token, PSECURITY_DESCRIPTOR Sd, DWORD Desired, BOOL ExpectStatus, DWORD ExpectGranted)
{
    BYTE PrivBuffer[256];
    DWORD PrivLength = sizeof(PrivBuffer), Granted = 0xCCCCCCCC;
    BOOL Status = 0xCC, Result;

    SetLastError(0xDEADBEEF);
    Result = AccessCheck(Sd, Token, Desired, &Mapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, &Granted, &Status);
    ok_(__FILE__, Line)(Result, "AccessCheck failed: %lu\n", GetLastError());
    ok_(__FILE__, Line)(Status == ExpectStatus, "Access status %d, expected %d\n", Status, ExpectStatus);
    ok_(__FILE__, Line)(Granted == ExpectGranted, "Granted 0x%lx, expected 0x%lx\n", Granted, ExpectGranted);
    if (!ExpectStatus)
        ok_(__FILE__, Line)(GetLastError() == ERROR_ACCESS_DENIED, "Error %lu\n", GetLastError());
}
#define CHECK(t, sd, d, s, g) Check(__LINE__, t, sd, d, s, g)

START_TEST(AccessCheckNoAccess)
{
    static GUID Guids[3] = {{0x11111111, 0x1111, 0x1111, {1, 1, 1, 1, 1, 1, 1, 1}},
                            {0xaaaaaaaa, 0xaaaa, 0xaaaa, {1, 2, 3, 4, 5, 6, 7, 8}},
                            {0xcccccccc, 0xcccc, 0xcccc, {1, 2, 3, 4, 5, 6, 7, 8}}};
    OBJECT_TYPE_LIST List[3] = {{0, 0, &Guids[0]}, {1, 0, &Guids[1]}, {1, 0, &Guids[2]}};
    BYTE PrivBuffer[256], UserBuffer[256];
    DWORD PrivLength = sizeof(PrivBuffer), Granted[3], Status[3], i, Length;
    HANDLE Process, Token, Event;
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    WCHAR Path[128];
    NTSTATUS NtStatus;
    PSID User;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process), "OpenProcessToken failed: %lu\n", GetLastError());
    ok(DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Token), "DuplicateTokenEx failed: %lu\n", GetLastError());
    ok(GetTokenInformation(Process, TokenUser, UserBuffer, sizeof(UserBuffer), &Length), "TokenUser failed: %lu\n", GetLastError());
    User = ((PTOKEN_USER)UserBuffer)->User.Sid;
    CloseHandle(Process);

    /* Nothing asked for, nothing granted before: denied, also with a NULL DACL */
    CHECK(Token, MakeSd(TRUE, NULL), 0, FALSE, 0);
    CHECK(Token, MakeSd(FALSE, NULL), 0, FALSE, 0);
    CHECK(Token, MakeSd(FALSE, NULL), 1, TRUE, 1);
    /* The owner's implicit READ_CONTROL is granted before the DACL is looked at */
    CHECK(Token, MakeSd(FALSE, User), READ_CONTROL, TRUE, READ_CONTROL);
    CHECK(Token, MakeSd(FALSE, User), 0, FALSE, 0);

    /* Every entry of a result list */
    ok(AccessCheckByTypeResultList(MakeSd(TRUE, NULL), NULL, Token, 0, List, 3, &Mapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, Granted, (LPBOOL)Status),
       "AccessCheckByTypeResultList failed: %lu\n", GetLastError());
    for (i = 0; i < 3; i++)
    {
        ok(Status[i] == ERROR_ACCESS_DENIED, "Entry %lu: status %lu\n", i, Status[i]);
        ok(Granted[i] == 0, "Entry %lu: granted 0x%lx\n", i, Granted[i]);
    }
    CloseHandle(Token);

    /* An object open with an access of 0 is refused (unchanged; Windows the same) */
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"Global\\AccessCheckNoAccess_%lu", GetCurrentProcessId());
    Event = CreateEventW(NULL, FALSE, FALSE, Path);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"\\BaseNamedObjects\\AccessCheckNoAccess_%lu", GetCurrentProcessId());
    ok(Event != NULL, "CreateEvent failed: %lu\n", GetLastError());
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Token = NULL;
    NtStatus = NtOpenEvent(&Token, 0, &Attributes);
    ok(NtStatus == STATUS_ACCESS_DENIED, "NtOpenEvent(0): 0x%lx\n", NtStatus);
    if (NT_SUCCESS(NtStatus))
        CloseHandle(Token);
    CloseHandle(Event);
}
