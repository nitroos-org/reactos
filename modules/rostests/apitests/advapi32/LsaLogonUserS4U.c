/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for LsaLogonUser with MSV1_0_S4U_LOGON (MsV1_0S4ULogon), the logon of a local
 *              account without its password that OpenSSH's sshd uses for public-key logins
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>
#include <tlhelp32.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif

/* The public layout of NTSecAPI.h */
#define S4U_MESSAGE_TYPE 12
#define S4U_FLAG_CHECK_LOGONHOURS 0x2
typedef struct
{
    ULONG MessageType;
    ULONG Flags;
    UNICODE_STRING UserPrincipalName;
    UNICODE_STRING DomainName;
} S4U_LOGON;

#define NT_STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#define NT_STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006D)
#define NT_STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006E)
#define NT_STATUS_ACCOUNT_DISABLED ((NTSTATUS)0xC0000072)
#define NT_STATUS_INVALID_LOGON_HOURS ((NTSTATUS)0xC000006F)
#define NT_STATUS_ACCOUNT_EXPIRED ((NTSTATUS)0xC0000193)
#define NT_STATUS_BAD_VALIDATION_CLASS ((NTSTATUS)0xC00000A7)
#define NT_STATUS_INVALID_LOGON_TYPE ((NTSTATUS)0xC000010B)
#define NT_STATUS_LOGON_TYPE_NOT_GRANTED ((NTSTATUS)0xC000015B)
#define NT_STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000D)

typedef NTSTATUS (NTAPI *LSACONNECTUNTRUSTED)(PHANDLE);
typedef NTSTATUS (NTAPI *LSAREGISTERLOGONPROCESS)(PLSA_STRING, PHANDLE, PLSA_OPERATIONAL_MODE);
typedef NTSTATUS (NTAPI *LSADEREGISTERLOGONPROCESS)(HANDLE);
typedef NTSTATUS (NTAPI *LSALOOKUPAUTHENTICATIONPACKAGE)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS (NTAPI *LSALOGONUSER)(HANDLE, PLSA_STRING, SECURITY_LOGON_TYPE, ULONG, PVOID, ULONG,
                                       PTOKEN_GROUPS, PTOKEN_SOURCE, PVOID *, PULONG, PLUID, PHANDLE,
                                       PQUOTA_LIMITS, PNTSTATUS);
typedef NTSTATUS (NTAPI *LSAGETLOGONSESSIONDATA)(PLUID, PSECURITY_LOGON_SESSION_DATA *);
typedef NTSTATUS (NTAPI *LSAFREERETURNBUFFER)(PVOID);

static LSACONNECTUNTRUSTED pLsaConnectUntrusted;
static LSAREGISTERLOGONPROCESS pLsaRegisterLogonProcess;
static LSADEREGISTERLOGONPROCESS pLsaDeregisterLogonProcess;
static LSALOOKUPAUTHENTICATIONPACKAGE pLsaLookupAuthenticationPackage;
static LSALOGONUSER pLsaLogonUser;
static LSAGETLOGONSESSIONDATA pLsaGetLogonSessionData;
static LSAFREERETURNBUFFER pLsaFreeReturnBuffer;

static WCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
static WCHAR Password[] = L"S4u-Test-Pass-2026!";

typedef struct
{
    PCWSTR Name;
    NTSTATUS Status;
    NTSTATUS SubStatus;
    HANDLE Token;
    PVOID Profile;
    ULONG ProfileLength;
    LUID LogonId;
} S4U_RESULT;

static BOOL CreateUser(PCWSTR Name, DWORD Flags)
{
    USER_INFO_1 Info;
    DWORD Err;
    NET_API_STATUS Status;

    ZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = (PWSTR)Name;
    Info.usri1_password = Password;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | Flags;
    Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    if (Status == NERR_UserExists)
    {
        NetUserDel(NULL, Name);
        Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    }
    ok(Status == NERR_Success, "NetUserAdd(%ls) failed: %lu\n", Name, Status);
    return Status == NERR_Success;
}

/* Submit an S4U logon. Relative: the string pointers are offsets from the start of the buffer */
static void S4ULogon(HANDLE Lsa, ULONG Package, SECURITY_LOGON_TYPE Type, PCWSTR User, PCWSTR Domain,
                     ULONG Flags, BOOL Relative, S4U_RESULT *Result)
{
    ULONG UserBytes = User ? (ULONG)wcslen(User) * sizeof(WCHAR) : 0;
    ULONG DomainBytes = Domain ? (ULONG)wcslen(Domain) * sizeof(WCHAR) : 0;
    ULONG Size = sizeof(S4U_LOGON) + UserBytes + DomainBytes;
    S4U_LOGON *Logon = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    PBYTE Strings = (PBYTE)(Logon + 1);
    TOKEN_SOURCE Source;
    LSA_STRING Origin;
    QUOTA_LIMITS Quotas;

    ZeroMemory(Result, sizeof(*Result));
    Result->Name = User;
    Logon->MessageType = S4U_MESSAGE_TYPE;
    Logon->Flags = Flags;
    if (User)
    {
        CopyMemory(Strings, User, UserBytes);
        Logon->UserPrincipalName.Length = Logon->UserPrincipalName.MaximumLength = (USHORT)UserBytes;
        Logon->UserPrincipalName.Buffer = Relative ? (PWSTR)(ULONG_PTR)(Strings - (PBYTE)Logon) : (PWSTR)Strings;
    }
    if (Domain)
    {
        CopyMemory(Strings + UserBytes, Domain, DomainBytes);
        Logon->DomainName.Length = Logon->DomainName.MaximumLength = (USHORT)DomainBytes;
        Logon->DomainName.Buffer = Relative ? (PWSTR)(ULONG_PTR)(Strings + UserBytes - (PBYTE)Logon)
                                            : (PWSTR)(Strings + UserBytes);
    }

    ZeroMemory(&Source, sizeof(Source));
    CopyMemory(Source.SourceName, "S4UTest", 8);
    AllocateLocallyUniqueId(&Source.SourceIdentifier);
    Origin.Buffer = (PCHAR)"S4UTest";
    Origin.Length = 7;
    Origin.MaximumLength = 8;

    Result->Status = pLsaLogonUser(Lsa, &Origin, Type, Package, Logon, Size, NULL, &Source,
                                   &Result->Profile, &Result->ProfileLength, &Result->LogonId,
                                   &Result->Token, &Quotas, &Result->SubStatus);
    HeapFree(GetProcessHeap(), 0, Logon);
}

static void Release(S4U_RESULT *Result)
{
    if (Result->Profile)
        pLsaFreeReturnBuffer(Result->Profile);
    if (Result->Token)
        CloseHandle(Result->Token);
    Result->Profile = NULL;
    Result->Token = NULL;
}

static void ExpectFailure(HANDLE Lsa, ULONG Package, PCWSTR What, SECURITY_LOGON_TYPE Type, PCWSTR User,
                          PCWSTR Domain, ULONG Flags, NTSTATUS Expected, NTSTATUS ExpectedSub)
{
    S4U_RESULT Result;

    S4ULogon(Lsa, Package, Type, User, Domain, Flags, FALSE, &Result);
    ok(Result.Status == Expected, "%ls: status 0x%08lx, expected 0x%08lx\n", What, Result.Status, Expected);
    if (ExpectedSub)
        ok(Result.SubStatus == ExpectedSub, "%ls: substatus 0x%08lx, expected 0x%08lx\n", What,
           Result.SubStatus, ExpectedSub);
    ok(Result.Token == NULL || !NT_SUCCESS(Result.Status), "%ls: a token was returned\n", What);
    Release(&Result);
}

static BOOL HasGroup(PTOKEN_GROUPS Groups, PSID Sid)
{
    DWORD i;

    for (i = 0; i < Groups->GroupCount; i++)
        if (EqualSid(Groups->Groups[i].Sid, Sid))
            return TRUE;
    return FALSE;
}

static BOOL HasWellKnownGroup(PTOKEN_GROUPS Groups, WELL_KNOWN_SID_TYPE Type)
{
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    DWORD Size = sizeof(Sid);

    if (!CreateWellKnownSid(Type, NULL, Sid, &Size))
    {
        ok(0, "CreateWellKnownSid(%d) failed: %lu\n", Type, GetLastError());
        return FALSE;
    }
    return HasGroup(Groups, Sid);
}

static BOOL HasPrivilege(PTOKEN_PRIVILEGES Privileges, PCWSTR Name)
{
    LUID Luid;
    DWORD i;

    if (!LookupPrivilegeValueW(NULL, Name, &Luid))
        return FALSE;
    for (i = 0; i < Privileges->PrivilegeCount; i++)
        if (Privileges->Privileges[i].Luid.LowPart == Luid.LowPart &&
            Privileges->Privileges[i].Luid.HighPart == Luid.HighPart)
            return TRUE;
    return FALSE;
}

/* The token of a successful S4U network logon of User */
static void CheckToken(PCWSTR What, S4U_RESULT *Result, PCWSTR User, SECURITY_IMPERSONATION_LEVEL Level)
{
    BYTE UserSid[SECURITY_MAX_SID_SIZE], Buffer[8192];
    WCHAR Domain[256];
    DWORD SidLength = sizeof(UserSid), DomainLength = RTL_NUMBER_OF(Domain), Length;
    SID_NAME_USE Use;
    TOKEN_TYPE Type;
    SECURITY_IMPERSONATION_LEVEL TokenLevel;
    TOKEN_STATISTICS Statistics;
    PSECURITY_LOGON_SESSION_DATA Session = NULL;
    NTSTATUS Status;
    BOOL Ok;

    ok(Result->Token != NULL, "%ls: no token\n", What);
    if (!Result->Token)
        return;

    Ok = LookupAccountNameW(NULL, User, UserSid, &SidLength, Domain, &DomainLength, &Use);
    ok(Ok, "%ls: LookupAccountName failed: %lu\n", What, GetLastError());

    /* A network logon yields an impersonation token (a server makes a primary one of it) */
    Ok = GetTokenInformation(Result->Token, TokenType, &Type, sizeof(Type), &Length);
    ok(Ok, "%ls: TokenType failed: %lu\n", What, GetLastError());
    if (Ok)
        ok(Type == TokenImpersonation, "%ls: token type %d, expected an impersonation token\n", What, Type);
    Ok = GetTokenInformation(Result->Token, TokenImpersonationLevel, &TokenLevel, sizeof(TokenLevel), &Length);
    ok(Ok, "%ls: TokenImpersonationLevel failed: %lu\n", What, GetLastError());
    if (Ok)
        ok(TokenLevel == Level, "%ls: impersonation level %d, expected %d\n", What, TokenLevel, Level);

    Ok = GetTokenInformation(Result->Token, TokenUser, Buffer, sizeof(Buffer), &Length);
    ok(Ok, "%ls: TokenUser failed: %lu\n", What, GetLastError());
    if (Ok && SidLength)
        ok(EqualSid(((PTOKEN_USER)Buffer)->User.Sid, UserSid), "%ls: the token is of another user\n", What);

    Ok = GetTokenInformation(Result->Token, TokenGroups, Buffer, sizeof(Buffer), &Length);
    ok(Ok, "%ls: TokenGroups failed: %lu\n", What, GetLastError());
    if (Ok)
    {
        PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;

        ok(HasWellKnownGroup(Groups, WinWorldSid), "%ls: no Everyone\n", What);
        ok(HasWellKnownGroup(Groups, WinBuiltinUsersSid), "%ls: no Users\n", What);
        ok(HasWellKnownGroup(Groups, WinNetworkSid), "%ls: no NETWORK\n", What);
        ok(HasWellKnownGroup(Groups, WinAuthenticatedUserSid), "%ls: no Authenticated Users\n", What);
        ok(!HasWellKnownGroup(Groups, WinInteractiveSid), "%ls: INTERACTIVE\n", What);
        ok(!HasWellKnownGroup(Groups, WinBatchSid), "%ls: BATCH\n", What);
        ok(!HasWellKnownGroup(Groups, WinServiceSid), "%ls: SERVICE\n", What);
        ok(!HasWellKnownGroup(Groups, WinBuiltinAdministratorsSid), "%ls: Administrators\n", What);
        ok(!HasWellKnownGroup(Groups, WinLocalSystemSid), "%ls: SYSTEM\n", What);

        /*
         * The LSA gives the logon a logon SID of its own, the caller having passed none (Windows Server 2022,
         * measured: one S-1-5-5-0-<n>, attributes 0xc0000007, also through an untrusted connection)
         */
        {
            ULONG i, Found = 0, Attributes = 0;
            TOKEN_STATISTICS LogonStats;

            for (i = 0; i < Groups->GroupCount; i++)
            {
                if (Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID)
                {
                    PSID Sid = Groups->Groups[i].Sid;
                    Found++;
                    Attributes = Groups->Groups[i].Attributes;
                    ok(*GetSidSubAuthorityCount(Sid) == SECURITY_LOGON_IDS_RID_COUNT &&
                       *GetSidSubAuthority(Sid, 0) == SECURITY_LOGON_IDS_RID, "%ls: the logon SID is no S-1-5-5-x-y\n", What);
                }
            }
            ok(Found == 1 && Attributes == 0xc0000007, "%ls: %lu logon SIDs, attributes 0x%lx, expected one, 0xc0000007\n",
               What, Found, Attributes);
            if (GetTokenInformation(Result->Token, TokenLogonSid, Buffer + 4096, 4096, &Length))
                ok(((PTOKEN_GROUPS)(Buffer + 4096))->GroupCount == 1, "%ls: TokenLogonSid has %lu SIDs\n", What,
                   ((PTOKEN_GROUPS)(Buffer + 4096))->GroupCount);
            else
                ok(0, "%ls: TokenLogonSid failed: %lu\n", What, GetLastError());
            if (GetTokenInformation(Result->Token, TokenStatistics, &LogonStats, sizeof(LogonStats), &Length))
            {
                for (i = 0; i < Groups->GroupCount; i++)
                {
                    PSID Sid = Groups->Groups[i].Sid;
                    if ((Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) && *GetSidSubAuthorityCount(Sid) == 3)
                        ok(*GetSidSubAuthority(Sid, 1) != (ULONG)LogonStats.AuthenticationId.HighPart ||
                           *GetSidSubAuthority(Sid, 2) != LogonStats.AuthenticationId.LowPart,
                           "%ls: the logon SID names the logon session\n", What);
                }
            }
        }
    }

    Ok = GetTokenInformation(Result->Token, TokenPrivileges, Buffer, sizeof(Buffer), &Length);
    ok(Ok, "%ls: TokenPrivileges failed: %lu\n", What, GetLastError());
    if (Ok)
    {
        PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;

        ok(HasPrivilege(Privileges, L"SeChangeNotifyPrivilege"), "%ls: no SeChangeNotifyPrivilege\n", What);
        ok(!HasPrivilege(Privileges, L"SeTcbPrivilege"), "%ls: SeTcbPrivilege\n", What);
        ok(!HasPrivilege(Privileges, L"SeDebugPrivilege"), "%ls: SeDebugPrivilege\n", What);
        ok(!HasPrivilege(Privileges, L"SeAssignPrimaryTokenPrivilege"), "%ls: SeAssignPrimaryTokenPrivilege\n", What);
    }

    /* The logon session */
    Ok = GetTokenInformation(Result->Token, TokenStatistics, &Statistics, sizeof(Statistics), &Length);
    ok(Ok, "%ls: TokenStatistics failed: %lu\n", What, GetLastError());
    if (Ok)
    {
        ok(Statistics.AuthenticationId.LowPart == Result->LogonId.LowPart &&
           Statistics.AuthenticationId.HighPart == Result->LogonId.HighPart,
           "%ls: the token is in logon session %lx:%lx, not %lx:%lx\n", What,
           Statistics.AuthenticationId.HighPart, Statistics.AuthenticationId.LowPart,
           Result->LogonId.HighPart, Result->LogonId.LowPart);

        Status = pLsaGetLogonSessionData(&Statistics.AuthenticationId, &Session);
        ok(Status == STATUS_SUCCESS, "%ls: LsaGetLogonSessionData failed: 0x%08lx\n", What, Status);
        if (Status == STATUS_SUCCESS && Session)
        {
            ok(Session->LogonType == Network, "%ls: logon type %lu, expected Network\n", What,
               (ULONG)Session->LogonType);
            ok(Session->UserName.Length == wcslen(User) * sizeof(WCHAR) &&
               _wcsnicmp(Session->UserName.Buffer, User, wcslen(User)) == 0,
               "%ls: session user name '%.*ls'\n", What, Session->UserName.Length / 2, Session->UserName.Buffer);
            ok(Session->LogonDomain.Length == wcslen(ComputerName) * sizeof(WCHAR) &&
               _wcsnicmp(Session->LogonDomain.Buffer, ComputerName, wcslen(ComputerName)) == 0,
               "%ls: session domain '%.*ls'\n", What, Session->LogonDomain.Length / 2, Session->LogonDomain.Buffer);
            ok(Session->Sid && SidLength && EqualSid(Session->Sid, UserSid), "%ls: session SID\n", What);
            pLsaFreeReturnBuffer(Session);
        }
    }

    /* The token can be used as a server uses it: duplicated to a primary token, if it can impersonate */
    if (Level >= SecurityImpersonation)
    {
        HANDLE Primary = NULL;

        Ok = DuplicateTokenEx(Result->Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &Primary);
        ok(Ok, "%ls: DuplicateTokenEx to a primary token failed: %lu\n", What, GetLastError());
        if (Ok)
            CloseHandle(Primary);
    }
}

/* The profile of an S4U logon is an MSV1_0_LM20_LOGON_PROFILE naming the computer */
static void CheckProfile(PCWSTR What, S4U_RESULT *Result)
{
    PMSV1_0_LM20_LOGON_PROFILE Profile = Result->Profile;

    ok(Profile != NULL, "%ls: no profile\n", What);
    if (!Profile)
        return;
    ok(Result->ProfileLength >= sizeof(*Profile), "%ls: profile length %lu\n", What, Result->ProfileLength);
    ok(Profile->MessageType == MsV1_0Lm20LogonProfile, "%ls: profile type %d\n", What, Profile->MessageType);
    ok(Profile->LogonDomainName.Length == wcslen(ComputerName) * sizeof(WCHAR) &&
       _wcsnicmp(Profile->LogonDomainName.Buffer, ComputerName, wcslen(ComputerName)) == 0,
       "%ls: profile domain '%.*ls'\n", What, Profile->LogonDomainName.Length / 2, Profile->LogonDomainName.Buffer);
    ok(Profile->LogonServer.Length == wcslen(ComputerName) * sizeof(WCHAR) &&
       _wcsnicmp(Profile->LogonServer.Buffer, ComputerName, wcslen(ComputerName)) == 0,
       "%ls: profile server '%.*ls'\n", What, Profile->LogonServer.Length / 2, Profile->LogonServer.Buffer);
}

static BOOL EnablePrivilege(PCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    BOOL Ok;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Ok = LookupPrivilegeValueW(NULL, Name, &Privileges.Privileges[0].Luid);
    if (Ok)
    {
        AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL);
        Ok = GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(Token);
    return Ok;
}

/* The calling thread impersonates the SYSTEM token of winlogon, for a caller that holds SeTcbPrivilege */
static BOOL ImpersonateSystem(void)
{
    PROCESSENTRY32W Entry;
    HANDLE Snapshot, Process, Token, Duplicate;
    BOOL Done = FALSE, More;

    EnablePrivilege(L"SeDebugPrivilege");
    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
        return FALSE;
    Entry.dwSize = sizeof(Entry);
    for (More = Process32FirstW(Snapshot, &Entry); More && !Done; More = Process32NextW(Snapshot, &Entry))
    {
        if (_wcsicmp(Entry.szExeFile, L"winlogon.exe") != 0)
            continue;
        Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Entry.th32ProcessID);
        if (!Process)
            continue;
        if (OpenProcessToken(Process, TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
        {
            if (DuplicateTokenEx(Token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Duplicate))
            {
                Done = SetThreadToken(NULL, Duplicate);
                CloseHandle(Duplicate);
            }
            CloseHandle(Token);
        }
        CloseHandle(Process);
    }
    CloseHandle(Snapshot);
    return Done;
}

static void TestCommon(HANDLE Lsa, ULONG Package, PCWSTR Tag, SECURITY_IMPERSONATION_LEVEL Level, BOOL Full)
{
    static const WCHAR User[] = L"s4utest1";
    S4U_RESULT Result;
    WCHAR Lower[MAX_COMPUTERNAME_LENGTH + 1];
    WCHAR What[64];
    DWORD i;

    StringCchPrintfW(What, RTL_NUMBER_OF(What), L"%ls computer name", Tag);
    S4ULogon(Lsa, Package, Network, User, ComputerName, 0, FALSE, &Result);
    ok(Result.Status == STATUS_SUCCESS, "%ls: S4U logon failed: 0x%08lx (sub 0x%08lx)\n", What, Result.Status, Result.SubStatus);
    if (Result.Status == STATUS_SUCCESS)
    {
        CheckToken(What, &Result, User, Level);
        CheckProfile(What, &Result);
    }
    Release(&Result);

    /* Offsets from the start of the buffer instead of addresses */
    StringCchPrintfW(What, RTL_NUMBER_OF(What), L"%ls relative pointers", Tag);
    S4ULogon(Lsa, Package, Network, User, ComputerName, 0, TRUE, &Result);
    ok(Result.Status == STATUS_SUCCESS, "%ls: status 0x%08lx\n", What, Result.Status);
    if (Result.Status == STATUS_SUCCESS)
        CheckToken(What, &Result, User, Level);
    Release(&Result);

    if (!Full)
        return;

    /* Each logon is a session of its own */
    {
        S4U_RESULT Second;

        S4ULogon(Lsa, Package, Network, User, L".", 0, FALSE, &Result);
        S4ULogon(Lsa, Package, Network, User, L".", 0, FALSE, &Second);
        ok(Result.Status == STATUS_SUCCESS, "%ls: domain '.': status 0x%08lx\n", Tag, Result.Status);
        ok(Second.Status == STATUS_SUCCESS, "%ls: second logon: status 0x%08lx\n", Tag, Second.Status);
        if (Result.Status == STATUS_SUCCESS && Second.Status == STATUS_SUCCESS)
            ok(Result.LogonId.LowPart != Second.LogonId.LowPart || Result.LogonId.HighPart != Second.LogonId.HighPart,
               "%ls: both logons are in session %lx:%lx\n", Tag, Result.LogonId.HighPart, Result.LogonId.LowPart);
        Release(&Result);
        Release(&Second);
    }

    /* The names are not case sensitive */
    for (i = 0; ComputerName[i]; i++)
        Lower[i] = (WCHAR)towlower(ComputerName[i]);
    Lower[i] = 0;
    S4ULogon(Lsa, Package, Network, L"S4UTEST1", Lower, 0, FALSE, &Result);
    ok(Result.Status == STATUS_SUCCESS, "%ls: upper case user, lower case domain: status 0x%08lx\n", Tag, Result.Status);
    Release(&Result);

    /* Flags: no logon hours are set, so the check passes */
    S4ULogon(Lsa, Package, Network, User, ComputerName, S4U_FLAG_CHECK_LOGONHOURS, FALSE, &Result);
    ok(Result.Status == STATUS_SUCCESS, "%ls: CHECK_LOGONHOURS: status 0x%08lx\n", Tag, Result.Status);
    Release(&Result);

    /* The domain of a local account is the computer, or "." */
    ExpectFailure(Lsa, Package, L"foreign domain", Network, User, L"NOSUCHDOMAIN-2026", 0, NT_STATUS_NOT_SUPPORTED, 0);
    ExpectFailure(Lsa, Package, L"no domain", Network, User, NULL, 0, NT_STATUS_NOT_SUPPORTED, 0);
    ExpectFailure(Lsa, Package, L"NT AUTHORITY", Network, L"SYSTEM", L"NT AUTHORITY", 0, NT_STATUS_NOT_SUPPORTED, 0);

    /* A user that does not exist, and an empty name, are refused alike */
    ExpectFailure(Lsa, Package, L"missing user", Network, L"s4u-no-such-user-2026", ComputerName, 0, NT_STATUS_LOGON_FAILURE, 0);
    ExpectFailure(Lsa, Package, L"user@computer", Network, L"s4utest1@S4UWORKGROUP", ComputerName, 0, NT_STATUS_LOGON_FAILURE, 0);
    ExpectFailure(Lsa, Package, L"empty user", Network, L"", ComputerName, 0, NT_STATUS_LOGON_FAILURE, 0);
    ExpectFailure(Lsa, Package, L"no user", Network, NULL, ComputerName, 0, NT_STATUS_INVALID_PARAMETER, 0);

    /* Account restrictions */
    ExpectFailure(Lsa, Package, L"disabled account", Network, L"s4udis", ComputerName, 0,
                  NT_STATUS_ACCOUNT_RESTRICTION, NT_STATUS_ACCOUNT_DISABLED);
    ExpectFailure(Lsa, Package, L"expired account", Network, L"s4uexp", ComputerName, 0, NT_STATUS_ACCOUNT_EXPIRED, 0);

    /* No password is looked at: an expired one or a restriction to other workstations does not matter */
    S4ULogon(Lsa, Package, Network, L"s4upwexp", ComputerName, 0, FALSE, &Result);
    ok(Result.Status == STATUS_SUCCESS, "%ls: expired password: status 0x%08lx\n", Tag, Result.Status);
    Release(&Result);
    S4ULogon(Lsa, Package, Network, L"s4uwks", ComputerName, 0, FALSE, &Result);
    ok(Result.Status == STATUS_SUCCESS, "%ls: workstation restriction: status 0x%08lx\n", Tag, Result.Status);
    Release(&Result);

    /* Only a network logon is possible; the other types are refused */
    ExpectFailure(Lsa, Package, L"interactive", Interactive, User, ComputerName, 0, NT_STATUS_BAD_VALIDATION_CLASS, 0);
    ExpectFailure(Lsa, Package, L"service", Service, User, ComputerName, 0, NT_STATUS_BAD_VALIDATION_CLASS, 0);
    ExpectFailure(Lsa, Package, L"network cleartext", NetworkCleartext, User, ComputerName, 0, NT_STATUS_BAD_VALIDATION_CLASS, 0);
    ExpectFailure(Lsa, Package, L"unlock", Unlock, User, ComputerName, 0, NT_STATUS_BAD_VALIDATION_CLASS, 0);
    ExpectFailure(Lsa, Package, L"new credentials", NewCredentials, User, ComputerName, 0, NT_STATUS_INVALID_LOGON_TYPE, 0);
    /* The user does not hold the batch logon right */
    ExpectFailure(Lsa, Package, L"batch", Batch, User, ComputerName, 0, NT_STATUS_LOGON_TYPE_NOT_GRANTED, 0);

    /* A submit buffer that is too short */
    {
        ULONG Short[2] = { S4U_MESSAGE_TYPE, 0 };
        TOKEN_SOURCE Source;
        LSA_STRING Origin;
        QUOTA_LIMITS Quotas;
        PVOID Profile = NULL;
        ULONG ProfileLength = 0;
        LUID LogonId;
        HANDLE Token = NULL;
        NTSTATUS Status, Sub = 0;

        ZeroMemory(&Source, sizeof(Source));
        CopyMemory(Source.SourceName, "S4UTest", 8);
        Origin.Buffer = (PCHAR)"S4UTest";
        Origin.Length = 7;
        Origin.MaximumLength = 8;
        Status = pLsaLogonUser(Lsa, &Origin, Network, Package, Short, sizeof(Short), NULL, &Source,
                               &Profile, &ProfileLength, &LogonId, &Token, &Quotas, &Sub);
        ok(Status == NT_STATUS_INVALID_PARAMETER, "%ls: short buffer: status 0x%08lx\n", Tag, Status);
        ok(Token == NULL, "%ls: short buffer: a token was returned\n", Tag);
    }
}

START_TEST(LsaLogonUserS4U)
{
    HMODULE Sspicli = LoadLibraryW(L"sspicli.dll");
    LSA_STRING PackageName, ProcessName;
    LSA_OPERATIONAL_MODE Mode;
    HANDLE Untrusted = NULL, Trusted = NULL;
    ULONG Package = 0, Package2 = 0;
    DWORD Size = RTL_NUMBER_OF(ComputerName), Err;
    NTSTATUS Status;
    BOOL Impersonating = FALSE;

    ok(Sspicli != NULL, "sspicli.dll could not be loaded: %lu\n", GetLastError());
    if (!Sspicli)
        return;

    pLsaConnectUntrusted = (LSACONNECTUNTRUSTED)GetProcAddress(Sspicli, "LsaConnectUntrusted");
    pLsaRegisterLogonProcess = (LSAREGISTERLOGONPROCESS)GetProcAddress(Sspicli, "LsaRegisterLogonProcess");
    pLsaDeregisterLogonProcess = (LSADEREGISTERLOGONPROCESS)GetProcAddress(Sspicli, "LsaDeregisterLogonProcess");
    pLsaLookupAuthenticationPackage = (LSALOOKUPAUTHENTICATIONPACKAGE)GetProcAddress(Sspicli, "LsaLookupAuthenticationPackage");
    pLsaLogonUser = (LSALOGONUSER)GetProcAddress(Sspicli, "LsaLogonUser");
    pLsaGetLogonSessionData = (LSAGETLOGONSESSIONDATA)GetProcAddress(Sspicli, "LsaGetLogonSessionData");
    pLsaFreeReturnBuffer = (LSAFREERETURNBUFFER)GetProcAddress(Sspicli, "LsaFreeReturnBuffer");
    if (!pLsaConnectUntrusted || !pLsaRegisterLogonProcess || !pLsaDeregisterLogonProcess ||
        !pLsaLookupAuthenticationPackage || !pLsaLogonUser || !pLsaGetLogonSessionData || !pLsaFreeReturnBuffer)
    {
        skip("an LSA function is missing\n");
        return;
    }
    GetComputerNameW(ComputerName, &Size);

    /* The accounts: a normal one, a disabled, an expired one, one with an expired password, one with a workstation restriction */
    if (!CreateUser(L"s4utest1", 0))
    {
        skip("NetUserAdd needs an elevated administrator\n");
        return;
    }
    CreateUser(L"s4udis", UF_ACCOUNTDISABLE);
    CreateUser(L"s4uexp", 0);
    CreateUser(L"s4upwexp", 0);
    CreateUser(L"s4uwks", 0);
    {
        USER_INFO_1017 Expires;
        USER_INFO_1014 Workstations;
        LPBYTE Info = NULL;

        Expires.usri1017_acct_expires = 1000000000;
        Err = NetUserSetInfo(NULL, L"s4uexp", 1017, (PBYTE)&Expires, NULL);
        ok(Err == NERR_Success, "expiring the account failed: %lu\n", Err);
        if (NetUserGetInfo(NULL, L"s4upwexp", 3, &Info) == NERR_Success)
        {
            ((PUSER_INFO_3)Info)->usri3_password_expired = 1;
            Err = NetUserSetInfo(NULL, L"s4upwexp", 3, Info, NULL);
            ok(Err == NERR_Success, "expiring the password failed: %lu\n", Err);
            NetApiBufferFree(Info);
        }
        Workstations.usri1014_workstations = (PWSTR)L"NOTTHISCOMPUTER";
        Err = NetUserSetInfo(NULL, L"s4uwks", 1014, (PBYTE)&Workstations, NULL);
        ok(Err == NERR_Success, "restricting the workstations failed: %lu\n", Err);
    }

    RtlInitString((PSTRING)&PackageName, MSV1_0_PACKAGE_NAME);

    /* Without SeTcbPrivilege (LsaConnectUntrusted): an identification token */
    Status = pLsaConnectUntrusted(&Untrusted);
    ok(Status == STATUS_SUCCESS, "LsaConnectUntrusted failed: 0x%08lx\n", Status);
    if (Status == STATUS_SUCCESS)
    {
        Status = pLsaLookupAuthenticationPackage(Untrusted, &PackageName, &Package);
        ok(Status == STATUS_SUCCESS, "LsaLookupAuthenticationPackage failed: 0x%08lx\n", Status);
        if (Status == STATUS_SUCCESS)
            TestCommon(Untrusted, Package, L"untrusted", SecurityIdentification, FALSE);
        pLsaDeregisterLogonProcess(Untrusted);
    }

    /* As a logon process, the caller holds SeTcbPrivilege (as the thread's token): an impersonation token.
       Windows judges a caller by its impersonation token, and refuses a logon process without the privilege. */
    RtlInitString((PSTRING)&ProcessName, "S4UTestLogonProcess");
    Impersonating = ImpersonateSystem();
    if (!Impersonating)
    {
        skip("the thread cannot impersonate SYSTEM, the trusted caller is not tested\n");
    }
    else
    {
        Status = pLsaRegisterLogonProcess(&ProcessName, &Trusted, &Mode);
        ok(Status == STATUS_SUCCESS, "LsaRegisterLogonProcess failed: 0x%08lx\n", Status);
        if (Status == STATUS_SUCCESS)
        {
            Status = pLsaLookupAuthenticationPackage(Trusted, &PackageName, &Package2);
            ok(Status == STATUS_SUCCESS, "LsaLookupAuthenticationPackage failed: 0x%08lx\n", Status);
            if (Status == STATUS_SUCCESS)
                TestCommon(Trusted, Package2, L"trusted", SecurityImpersonation, TRUE);
            pLsaDeregisterLogonProcess(Trusted);
        }
        RevertToSelf();
    }

    NetUserDel(NULL, L"s4utest1");
    NetUserDel(NULL, L"s4udis");
    NetUserDel(NULL, L"s4uexp");
    NetUserDel(NULL, L"s4upwexp");
    NetUserDel(NULL, L"s4uwks");
}
