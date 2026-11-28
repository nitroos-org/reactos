/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A mandatory label in the descriptor of a new token may not be above the creator's level
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <aclapi.h>
#include <tlhelp32.h>
#include <ndk/obfuncs.h>
#include <ndk/sefuncs.h>

/*
 * A token duplicate (and a token made with NtCreateToken) whose security descriptor carries a mandatory
 * label above the integrity level of the creator is refused with ERROR_PRIVILEGE_NOT_HELD /
 * STATUS_PRIVILEGE_NOT_HELD unless SeRelabelPrivilege is enabled in the creator's token; a label equal to
 * or below the creator's level is accepted. Measured on Windows Server 2022 for DuplicateTokenEx (an
 * administrator and a standard user, every privilege combination probed: ERROR_PRIVILEGE_NOT_HELD). The
 * subject is the client token of an impersonating creator. The rows of NtCreateToken, of the creator that
 * holds SeRelabelPrivilege and of the Low creator follow the same rule (no Windows row of their own).
 *
 * Creators: the caller's token copied at Medium, Low and High level; and, when the caller can take the
 * token of winlogon (SeDebugPrivilege, SeImpersonatePrivilege) and so make tokens with NtCreateToken, new
 * Medium tokens that hold SeCreateTokenPrivilege and, in one of them, SeRelabelPrivilege.
 *
 * The process and thread rows (CreateProcess, CreateThread with such a descriptor) are in ProcessThreadLabel.
 */

static NTSTATUS (NTAPI *pRtlAddMandatoryAce)(PACL, ULONG, ULONG, PSID, UCHAR, ULONG);

typedef struct
{
    SECURITY_DESCRIPTOR Sd;
    ULONG AclBuffer[16];
} LABELSD;

static VOID MakeLabelSd(LABELSD *Label, DWORD Level)
{
    SID Sid = {SID_REVISION, 1, {SECURITY_MANDATORY_LABEL_AUTHORITY}, {0}};

    Sid.SubAuthority[0] = Level;
    ok(InitializeAcl((PACL)Label->AclBuffer, sizeof(Label->AclBuffer), ACL_REVISION), "InitializeAcl\n");
    ok_hex(pRtlAddMandatoryAce((PACL)Label->AclBuffer, ACL_REVISION, 0, &Sid,
                               SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP), STATUS_SUCCESS);
    InitializeSecurityDescriptor(&Label->Sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorSacl(&Label->Sd, TRUE, (PACL)Label->AclBuffer, FALSE);
}

static DWORD ObjectLabel(HANDLE Object)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Sacl = NULL;
    PSYSTEM_MANDATORY_LABEL_ACE Ace;
    DWORD Level = MAXDWORD;

    if (GetSecurityInfo(Object, SE_KERNEL_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &Sacl, &Sd) != ERROR_SUCCESS)
        return MAXDWORD;
    if (Sacl && Sacl->AceCount == 1 && GetAce(Sacl, 0, (PVOID *)&Ace))
        Level = *GetSidSubAuthority(&Ace->SidStart, 0);
    LocalFree(Sd);
    return Level;
}

static BOOL SetPrivilege(HANDLE Token, PCWSTR Name, BOOL Enable, BOOL *Held)
{
    TOKEN_PRIVILEGES Privileges;

    Privileges.PrivilegeCount = 1;
    LookupPrivilegeValueW(NULL, Name, &Privileges.Privileges[0].Luid);
    Privileges.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;
    SetLastError(0xdeadbeef);
    if (!AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL))
        return FALSE;
    *Held = (GetLastError() == ERROR_SUCCESS);
    return TRUE;
}

static DWORD TokenLevel(HANDLE Token)
{
    BYTE Buffer[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE];
    DWORD Length;

    if (!GetTokenInformation(Token, TokenIntegrityLevel, Buffer, sizeof(Buffer), &Length))
        return 0;
    return *GetSidSubAuthority(((PTOKEN_MANDATORY_LABEL)Buffer)->Label.Sid, 0);
}

/* An impersonation copy of Token with its integrity level lowered to Level */
static BOOL MakeCreator(HANDLE Token, DWORD Level, HANDLE *Creator)
{
    TOKEN_MANDATORY_LABEL Label;
    SID Sid = {SID_REVISION, 1, {SECURITY_MANDATORY_LABEL_AUTHORITY}, {0}};
    BOOL Ret;

    *Creator = NULL;
    Ret = DuplicateTokenEx(Token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, Creator);
    ok(Ret, "DuplicateTokenEx: %lu\n", GetLastError());
    if (!Ret) return FALSE;
    Sid.SubAuthority[0] = Level;
    Label.Label.Sid = &Sid;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    Ret = SetTokenInformation(*Creator, TokenIntegrityLevel, &Label, sizeof(Label));
    ok(Ret, "SetTokenInformation(%lx): %lu\n", Level, GetLastError());
    if (!Ret)
    {
        CloseHandle(*Creator);
        *Creator = NULL;
    }
    return Ret;
}

/* The token of winlogon as an impersonation token (SYSTEM), for a caller with SeDebugPrivilege */
static HANDLE GetSystemToken(HANDLE OwnToken)
{
    PROCESSENTRY32W Entry;
    HANDLE Snapshot, Process, Token, Duplicate = NULL;
    BOOL More, Held;

    SetPrivilege(OwnToken, L"SeDebugPrivilege", TRUE, &Held);
    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
        return NULL;
    Entry.dwSize = sizeof(Entry);
    for (More = Process32FirstW(Snapshot, &Entry); More && !Duplicate; More = Process32NextW(Snapshot, &Entry))
    {
        if (_wcsicmp(Entry.szExeFile, L"winlogon.exe") != 0)
            continue;
        Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Entry.th32ProcessID);
        if (!Process)
            continue;
        if (OpenProcessToken(Process, TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
        {
            if (!DuplicateTokenEx(Token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Duplicate))
                Duplicate = NULL;
            CloseHandle(Token);
        }
        CloseHandle(Process);
    }
    CloseHandle(Snapshot);
    return Duplicate;
}

/*
 * NtCreateToken from the data of Source (a SYSTEM impersonation token), as the thread that impersonates Maker,
 * with an integrity group of Level, SeCreateTokenPrivilege enabled, SeRelabelPrivilege enabled when Relabel,
 * and Sd as the descriptor of the new token (NULL: none). Type is the type of the new token.
 */
static NTSTATUS CreateToken(HANDLE Source, HANDLE Maker, DWORD Level, BOOL Relabel, TOKEN_TYPE Type,
                            PSECURITY_DESCRIPTOR Sd, HANDLE *Token)
{
    BYTE UserBuffer[256], PrimaryBuffer[256], OwnerBuffer[256];
    TOKEN_GROUPS *Source_Groups = NULL, *Groups = NULL;
    TOKEN_PRIVILEGES *Source_Privileges = NULL, *Privileges = NULL;
    TOKEN_USER *User = (TOKEN_USER *)UserBuffer;
    TOKEN_PRIMARY_GROUP *Primary = (TOKEN_PRIMARY_GROUP *)PrimaryBuffer;
    TOKEN_OWNER *Owner = (TOKEN_OWNER *)OwnerBuffer;
    TOKEN_STATISTICS Statistics;
    TOKEN_SOURCE TokenSource = {{'T', 'k', 'C', 'L', 'b', 'l', 0, 0}, {1, 0}};
    OBJECT_ATTRIBUTES Oa;
    SECURITY_QUALITY_OF_SERVICE Qos = {sizeof(Qos), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE};
    SID IntegritySid = {SID_REVISION, 1, {SECURITY_MANDATORY_LABEL_AUTHORITY}, {0}};
    LARGE_INTEGER Expiration;
    DWORD Length, i;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    LUID Create, RelabelLuid;

    *Token = NULL;
    GetTokenInformation(Source, TokenGroups, NULL, 0, &Length);
    Source_Groups = HeapAlloc(GetProcessHeap(), 0, Length);
    Groups = HeapAlloc(GetProcessHeap(), 0, Length + sizeof(SID_AND_ATTRIBUTES));
    if (!Source_Groups || !Groups || !GetTokenInformation(Source, TokenGroups, Source_Groups, Length, &Length))
        goto Done;
    GetTokenInformation(Source, TokenPrivileges, NULL, 0, &Length);
    Source_Privileges = HeapAlloc(GetProcessHeap(), 0, Length);
    Privileges = HeapAlloc(GetProcessHeap(), 0, Length + 2 * sizeof(LUID_AND_ATTRIBUTES));
    if (!Source_Privileges || !Privileges ||
        !GetTokenInformation(Source, TokenPrivileges, Source_Privileges, Length, &Length) ||
        !GetTokenInformation(Source, TokenUser, UserBuffer, sizeof(UserBuffer), &Length) ||
        !GetTokenInformation(Source, TokenPrimaryGroup, PrimaryBuffer, sizeof(PrimaryBuffer), &Length) ||
        !GetTokenInformation(Source, TokenOwner, OwnerBuffer, sizeof(OwnerBuffer), &Length) ||
        !GetTokenInformation(Source, TokenStatistics, &Statistics, sizeof(Statistics), &Length))
        goto Done;

    /* The groups of the source, and an integrity group of Level */
    *Groups = *Source_Groups;
    for (i = 0; i < Source_Groups->GroupCount; i++)
        Groups->Groups[i] = Source_Groups->Groups[i];
    IntegritySid.SubAuthority[0] = Level;
    Groups->Groups[i].Sid = &IntegritySid;
    Groups->Groups[i].Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
    Groups->GroupCount = i + 1;

    /* The privileges of the source, SeCreateTokenPrivilege and (if asked) SeRelabelPrivilege enabled */
    LookupPrivilegeValueW(NULL, L"SeCreateTokenPrivilege", &Create);
    LookupPrivilegeValueW(NULL, L"SeRelabelPrivilege", &RelabelLuid);
    Privileges->PrivilegeCount = 0;
    for (i = 0; i < Source_Privileges->PrivilegeCount; i++)
    {
        LUID_AND_ATTRIBUTES Entry = Source_Privileges->Privileges[i];

        if (!memcmp(&Entry.Luid, &Create, sizeof(LUID)) || !memcmp(&Entry.Luid, &RelabelLuid, sizeof(LUID)))
            continue;
        Privileges->Privileges[Privileges->PrivilegeCount++] = Entry;
    }
    Privileges->Privileges[Privileges->PrivilegeCount].Luid = Create;
    Privileges->Privileges[Privileges->PrivilegeCount++].Attributes = SE_PRIVILEGE_ENABLED;
    if (Relabel)
    {
        Privileges->Privileges[Privileges->PrivilegeCount].Luid = RelabelLuid;
        Privileges->Privileges[Privileges->PrivilegeCount++].Attributes = SE_PRIVILEGE_ENABLED;
    }

    Expiration.QuadPart = -1;
    InitializeObjectAttributes(&Oa, NULL, 0, NULL, Sd);
    Oa.SecurityQualityOfService = &Qos;

    if (!SetThreadToken(NULL, Maker))
    {
        Status = STATUS_NO_TOKEN;
        goto Done;
    }
    Status = NtCreateToken(Token, TOKEN_ALL_ACCESS, &Oa, Type, &Statistics.AuthenticationId, &Expiration,
                           User, Groups, Privileges, Owner, Primary, NULL, &TokenSource);
    RevertToSelf();
    if (!NT_SUCCESS(Status))
        *Token = NULL;

Done:
    HeapFree(GetProcessHeap(), 0, Source_Groups);
    HeapFree(GetProcessHeap(), 0, Groups);
    HeapFree(GetProcessHeap(), 0, Source_Privileges);
    HeapFree(GetProcessHeap(), 0, Privileges);
    return Status;
}

/* DuplicateTokenEx of Source, as a thread that impersonates Creator, with a label of Level in the descriptor */
static VOID TestDuplicate(HANDLE Source, HANDLE Creator, PCSTR Name, DWORD Level, BOOL Expect)
{
    LABELSD Label;
    SECURITY_ATTRIBUTES Attributes = {sizeof(Attributes), &Label.Sd, FALSE};
    HANDLE Token = NULL;
    DWORD Error;
    BOOL Ret;

    MakeLabelSd(&Label, Level);
    ok(SetThreadToken(NULL, Creator), "SetThreadToken: %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    Ret = DuplicateTokenEx(Source, MAXIMUM_ALLOWED, &Attributes, SecurityImpersonation, TokenPrimary, &Token);
    Error = GetLastError();
    ok(RevertToSelf(), "RevertToSelf\n");
    if (Expect)
    {
        ok(Ret, "%s, label %lx: DuplicateTokenEx failed with %lu\n", Name, Level, Error);
        if (Ret)
            ok(ObjectLabel(Token) == Level, "%s, label %lx: the token has label %lx\n", Name, Level, ObjectLabel(Token));
    }
    else
    {
        ok(!Ret && Error == ERROR_PRIVILEGE_NOT_HELD, "%s, label %lx: DuplicateTokenEx returned %d, error %lu\n",
           Name, Level, Ret, Error);
        ok(Token == NULL, "%s, label %lx: a token was returned\n", Name, Level);
    }
    if (Token) CloseHandle(Token);
}

/* NtCreateToken as a thread that impersonates Creator, with a label of Level in the descriptor */
static VOID TestCreate(HANDLE System, HANDLE Creator, PCSTR Name, DWORD Level, BOOL Expect)
{
    LABELSD Label;
    HANDLE Token;
    NTSTATUS Status;

    MakeLabelSd(&Label, Level);
    Status = CreateToken(System, Creator, SECURITY_MANDATORY_MEDIUM_RID, FALSE, TokenPrimary, &Label.Sd, &Token);
    if (Expect)
    {
        ok(NT_SUCCESS(Status), "%s, label %lx: NtCreateToken failed with %lx\n", Name, Level, Status);
        if (NT_SUCCESS(Status))
            ok(ObjectLabel(Token) == Level, "%s, label %lx: the token has label %lx\n", Name, Level, ObjectLabel(Token));
    }
    else
    {
        ok(Status == STATUS_PRIVILEGE_NOT_HELD, "%s, label %lx: NtCreateToken returned %lx\n", Name, Level, Status);
    }
    if (NT_SUCCESS(Status))
        CloseHandle(Token);
}

START_TEST(TokenCreateLabel)
{
    HANDLE Token, Medium = NULL, Low = NULL, High = NULL, System = NULL, MakerMedium = NULL, MakerRelabel = NULL;
    NTSTATUS Status;
    BOOL Held;

    pRtlAddMandatoryAce = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddMandatoryAce");
    if (!pRtlAddMandatoryAce)
    {
        skip("RtlAddMandatoryAce is not available\n");
        return;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES, &Token))
    {
        ok(0, "OpenProcessToken: %lu\n", GetLastError());
        return;
    }

    /* A creator without SeRelabelPrivilege: a label above is refused, equal and below accepted */
    if (!MakeCreator(Token, SECURITY_MANDATORY_MEDIUM_RID, &Medium) ||
        !MakeCreator(Token, SECURITY_MANDATORY_LOW_RID, &Low))
        goto Done;
    ok(SetPrivilege(Medium, L"SeRelabelPrivilege", FALSE, &Held), "Disable SeRelabelPrivilege\n");
    TestDuplicate(Token, Medium, "Medium creator", SECURITY_MANDATORY_HIGH_RID, FALSE);
    TestDuplicate(Token, Medium, "Medium creator", SECURITY_MANDATORY_SYSTEM_RID, FALSE);
    TestDuplicate(Token, Medium, "Medium creator", SECURITY_MANDATORY_MEDIUM_RID, TRUE);
    TestDuplicate(Token, Medium, "Medium creator", SECURITY_MANDATORY_LOW_RID, TRUE);
    TestDuplicate(Token, Medium, "Medium creator", SECURITY_MANDATORY_UNTRUSTED_RID, TRUE);

    /* A Low creator */
    ok(SetPrivilege(Low, L"SeRelabelPrivilege", FALSE, &Held), "Disable SeRelabelPrivilege\n");
    TestDuplicate(Token, Low, "Low creator", SECURITY_MANDATORY_MEDIUM_RID, FALSE);
    TestDuplicate(Token, Low, "Low creator", SECURITY_MANDATORY_HIGH_RID, FALSE);
    TestDuplicate(Token, Low, "Low creator", SECURITY_MANDATORY_LOW_RID, TRUE);
    TestDuplicate(Token, Low, "Low creator", SECURITY_MANDATORY_UNTRUSTED_RID, TRUE);

    /* A High creator: High and below accepted, System refused */
    if (TokenLevel(Token) >= SECURITY_MANDATORY_HIGH_RID && MakeCreator(Token, SECURITY_MANDATORY_HIGH_RID, &High))
    {
        ok(SetPrivilege(High, L"SeRelabelPrivilege", FALSE, &Held), "Disable SeRelabelPrivilege\n");
        TestDuplicate(Token, High, "High creator", SECURITY_MANDATORY_HIGH_RID, TRUE);
        TestDuplicate(Token, High, "High creator", SECURITY_MANDATORY_MEDIUM_RID, TRUE);
        TestDuplicate(Token, High, "High creator", SECURITY_MANDATORY_SYSTEM_RID, FALSE);
    }
    else
    {
        skip("The caller is not at High integrity\n");
    }

    /* A caller's own SeRelabelPrivilege, if its token holds it */
    if (SetPrivilege(Medium, L"SeRelabelPrivilege", TRUE, &Held) && Held)
        TestDuplicate(Token, Medium, "Medium creator with SeRelabelPrivilege", SECURITY_MANDATORY_HIGH_RID, TRUE);

    /* NtCreateToken, and a creator that holds SeRelabelPrivilege, need tokens that the caller can make with the token of winlogon */
    System = GetSystemToken(Token);
    if (!System)
    {
        skip("Cannot take the token of winlogon\n");
        goto Done;
    }
    SetPrivilege(System, L"SeCreateTokenPrivilege", TRUE, &Held);
    Status = CreateToken(System, System, SECURITY_MANDATORY_MEDIUM_RID, FALSE, TokenImpersonation, NULL, &MakerMedium);
    if (!NT_SUCCESS(Status))
    {
        skip("Cannot make a token with NtCreateToken: %lx\n", Status);
        goto Done;
    }
    Status = CreateToken(System, System, SECURITY_MANDATORY_MEDIUM_RID, TRUE, TokenImpersonation, NULL, &MakerRelabel);
    ok(NT_SUCCESS(Status), "NtCreateToken for the creator with SeRelabelPrivilege: %lx\n", Status);
    ok(TokenLevel(MakerMedium) == SECURITY_MANDATORY_MEDIUM_RID, "The made creator has level %lx\n", TokenLevel(MakerMedium));

    /* The made Medium creator holds SeCreateTokenPrivilege and not SeRelabelPrivilege */
    TestCreate(System, MakerMedium, "Medium creator", SECURITY_MANDATORY_HIGH_RID, FALSE);
    TestCreate(System, MakerMedium, "Medium creator", SECURITY_MANDATORY_SYSTEM_RID, FALSE);
    TestCreate(System, MakerMedium, "Medium creator", SECURITY_MANDATORY_MEDIUM_RID, TRUE);
    TestCreate(System, MakerMedium, "Medium creator", SECURITY_MANDATORY_LOW_RID, TRUE);
    TestDuplicate(Token, MakerMedium, "Medium creator made with NtCreateToken", SECURITY_MANDATORY_HIGH_RID, FALSE);
    TestDuplicate(Token, MakerMedium, "Medium creator made with NtCreateToken", SECURITY_MANDATORY_MEDIUM_RID, TRUE);

    /* With SeRelabelPrivilege enabled the label above is accepted; disabled again, refused again */
    if (MakerRelabel)
    {
        TestCreate(System, MakerRelabel, "Medium creator with SeRelabelPrivilege", SECURITY_MANDATORY_HIGH_RID, TRUE);
        TestCreate(System, MakerRelabel, "Medium creator with SeRelabelPrivilege", SECURITY_MANDATORY_SYSTEM_RID, TRUE);
        TestDuplicate(Token, MakerRelabel, "Medium creator with SeRelabelPrivilege", SECURITY_MANDATORY_HIGH_RID, TRUE);
        TestDuplicate(Token, MakerRelabel, "Medium creator with SeRelabelPrivilege", SECURITY_MANDATORY_SYSTEM_RID, TRUE);
        ok(SetPrivilege(MakerRelabel, L"SeRelabelPrivilege", FALSE, &Held) && Held, "Disable SeRelabelPrivilege\n");
        TestDuplicate(Token, MakerRelabel, "Medium creator, SeRelabelPrivilege disabled", SECURITY_MANDATORY_HIGH_RID, FALSE);
        TestCreate(System, MakerRelabel, "Medium creator, SeRelabelPrivilege disabled", SECURITY_MANDATORY_HIGH_RID, FALSE);
    }

Done:
    if (MakerMedium) CloseHandle(MakerMedium);
    if (MakerRelabel) CloseHandle(MakerRelabel);
    if (System) CloseHandle(System);
    if (High) CloseHandle(High);
    if (Medium) CloseHandle(Medium);
    if (Low) CloseHandle(Low);
    CloseHandle(Token);
}
