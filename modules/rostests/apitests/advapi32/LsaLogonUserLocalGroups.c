/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LsaLogonUser with LocalGroups: only for a caller that holds SeTcbPrivilege
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>
#include <tlhelp32.h>

/*
 * The groups a caller passes to LsaLogonUser (LocalGroups; LogonUserExExW's pTokenGroups) go into the new
 * token as they are given, so only a caller that holds SeTcbPrivilege may pass them. Measured on Windows
 * Server 2022: over an untrusted connection (LsaConnectUntrusted, an administrator without SeTcbPrivilege),
 * an interactive logon of a local user with LocalGroups {Administrators, S-1-5-80-1-2-3-4-5} returns
 * STATUS_ACCESS_DENIED, and the same logon without LocalGroups succeeds and has neither group.
 *
 * Our advapi32 LogonUser passes the logon SID it makes and LOCAL as LocalGroups (Windows' LSA makes the logon
 * SID), so the LSA accepts exactly those two from an untrusted caller and replaces the logon SID's value:
 * LogonUser keeps working without SeTcbPrivilege, and nobody can name another session's logon SID.
 */

typedef NTSTATUS (NTAPI *LSACONNECTUNTRUSTED)(PHANDLE);
typedef NTSTATUS (NTAPI *LSAREGISTERLOGONPROCESS)(PLSA_STRING, PHANDLE, PLSA_OPERATIONAL_MODE);
typedef NTSTATUS (NTAPI *LSADEREGISTERLOGONPROCESS)(HANDLE);
typedef NTSTATUS (NTAPI *LSALOOKUPAUTHENTICATIONPACKAGE)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS (NTAPI *LSALOGONUSER)(HANDLE, PLSA_STRING, SECURITY_LOGON_TYPE, ULONG, PVOID, ULONG,
                                       PTOKEN_GROUPS, PTOKEN_SOURCE, PVOID *, PULONG, PLUID, PHANDLE,
                                       PQUOTA_LIMITS, PNTSTATUS);
typedef NTSTATUS (NTAPI *LSAFREERETURNBUFFER)(PVOID);

static LSACONNECTUNTRUSTED pLsaConnectUntrusted;
static LSAREGISTERLOGONPROCESS pLsaRegisterLogonProcess;
static LSADEREGISTERLOGONPROCESS pLsaDeregisterLogonProcess;
static LSALOOKUPAUTHENTICATIONPACKAGE pLsaLookupAuthenticationPackage;
static LSALOGONUSER pLsaLogonUser;
static LSAFREERETURNBUFFER pLsaFreeReturnBuffer;

static WCHAR TestUser[] = L"lsalgtest";
static WCHAR TestPassword[] = L"Lsa-Groups-Test-2026!";

static NTSTATUS
InteractiveLogon(HANDLE Lsa, PTOKEN_GROUPS Groups, PHANDLE Token)
{
    BYTE Buffer[sizeof(MSV1_0_INTERACTIVE_LOGON) + 128 * sizeof(WCHAR)];
    PMSV1_0_INTERACTIVE_LOGON Logon = (PMSV1_0_INTERACTIVE_LOGON)Buffer;
    PWCHAR Ptr = (PWCHAR)(Logon + 1);
    LSA_STRING PackageName, Origin;
    TOKEN_SOURCE Source;
    PVOID Profile = NULL;
    ULONG ProfileLength = 0, Package = 0;
    LUID LogonId;
    QUOTA_LIMITS Quotas;
    NTSTATUS Status, SubStatus = 0;

    *Token = NULL;
    RtlZeroMemory(Buffer, sizeof(Buffer));
    Logon->MessageType = MsV1_0InteractiveLogon;
    Logon->LogonDomainName.Buffer = Ptr;
    Logon->LogonDomainName.Length = sizeof(WCHAR);
    Logon->LogonDomainName.MaximumLength = 2 * sizeof(WCHAR);
    *Ptr = L'.';
    Ptr += 2;
    Logon->UserName.Buffer = Ptr;
    Logon->UserName.Length = (USHORT)(wcslen(TestUser) * sizeof(WCHAR));
    Logon->UserName.MaximumLength = Logon->UserName.Length + sizeof(WCHAR);
    RtlCopyMemory(Ptr, TestUser, Logon->UserName.MaximumLength);
    Ptr += wcslen(TestUser) + 1;
    Logon->Password.Buffer = Ptr;
    Logon->Password.Length = (USHORT)(wcslen(TestPassword) * sizeof(WCHAR));
    Logon->Password.MaximumLength = Logon->Password.Length + sizeof(WCHAR);
    RtlCopyMemory(Ptr, TestPassword, Logon->Password.MaximumLength);
    Ptr += wcslen(TestPassword) + 1;

    RtlInitString((PSTRING)&PackageName, MSV1_0_PACKAGE_NAME);
    Status = pLsaLookupAuthenticationPackage(Lsa, &PackageName, &Package);
    if (Status != STATUS_SUCCESS)
        return Status;

    RtlInitString((PSTRING)&Origin, "LsaLgTest");
    RtlCopyMemory(Source.SourceName, "LsaLgTst", 8);
    AllocateLocallyUniqueId(&Source.SourceIdentifier);
    Status = pLsaLogonUser(Lsa, &Origin, Interactive, Package, Logon, (ULONG)((PBYTE)Ptr - Buffer),
                           Groups, &Source, &Profile, &ProfileLength, &LogonId, Token, &Quotas, &SubStatus);
    SecureZeroMemory(Buffer, sizeof(Buffer));
    if (Profile)
        pLsaFreeReturnBuffer(Profile);
    return Status;
}

/* The attributes of Sid among the groups of Token; ~0 when the token does not have it */
static DWORD
GroupAttributes(HANDLE Token, PSID Sid)
{
    BYTE Buffer[8192];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    DWORD Length, i;

    if (!GetTokenInformation(Token, TokenGroups, Buffer, sizeof(Buffer), &Length))
        return ~0UL - 1;
    for (i = 0; i < Groups->GroupCount; i++)
    {
        if (EqualSid(Groups->Groups[i].Sid, Sid))
            return Groups->Groups[i].Attributes;
    }
    return ~0UL;
}

/* The SE_GROUP_LOGON_ID SID of Token, copied into Buffer; FALSE if it has none */
static BOOL
CopyTokenLogonSid(HANDLE Token, PSID Buffer, DWORD Size)
{
    BYTE Groups[8192];
    PTOKEN_GROUPS G = (PTOKEN_GROUPS)Groups;
    DWORD Length, i;

    if (!GetTokenInformation(Token, TokenGroups, Groups, sizeof(Groups), &Length))
        return FALSE;
    for (i = 0; i < G->GroupCount; i++)
    {
        if (G->Groups[i].Attributes & SE_GROUP_LOGON_ID)
            return CopySid(Size, Buffer, G->Groups[i].Sid);
    }
    return FALSE;
}

/* The thread impersonates the SYSTEM token of winlogon, the caller that holds SeTcbPrivilege */
static BOOL
ImpersonateSystem(VOID)
{
    PROCESSENTRY32W Entry;
    HANDLE Snapshot, Process, Token, Duplicate, Self;
    TOKEN_PRIVILEGES Privileges;
    BOOL Done = FALSE, More;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Self))
    {
        Privileges.PrivilegeCount = 1;
        Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &Privileges.Privileges[0].Luid))
            AdjustTokenPrivileges(Self, FALSE, &Privileges, 0, NULL, NULL);
        CloseHandle(Self);
    }
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

START_TEST(LsaLogonUserLocalGroups)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    BYTE GroupBuffer[sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES)];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)GroupBuffer;
    PSID Admins = NULL, Fake = NULL;
    USER_INFO_1 Info;
    LSA_STRING ProcessName;
    LSA_OPERATIONAL_MODE Mode;
    HANDLE Lsa = NULL, Token = NULL;
    HMODULE Secur32;
    NTSTATUS Status;
    DWORD Err = 0, Attributes;
    NET_API_STATUS NetStatus;

    Secur32 = LoadLibraryW(L"secur32.dll");
    ok(Secur32 != NULL, "secur32 not loaded: %lu\n", GetLastError());
    if (!Secur32)
        return;
    pLsaConnectUntrusted = (LSACONNECTUNTRUSTED)GetProcAddress(Secur32, "LsaConnectUntrusted");
    pLsaRegisterLogonProcess = (LSAREGISTERLOGONPROCESS)GetProcAddress(Secur32, "LsaRegisterLogonProcess");
    pLsaDeregisterLogonProcess = (LSADEREGISTERLOGONPROCESS)GetProcAddress(Secur32, "LsaDeregisterLogonProcess");
    pLsaLookupAuthenticationPackage = (LSALOOKUPAUTHENTICATIONPACKAGE)GetProcAddress(Secur32, "LsaLookupAuthenticationPackage");
    pLsaLogonUser = (LSALOGONUSER)GetProcAddress(Secur32, "LsaLogonUser");
    pLsaFreeReturnBuffer = (LSAFREERETURNBUFFER)GetProcAddress(Secur32, "LsaFreeReturnBuffer");
    if (!pLsaConnectUntrusted || !pLsaRegisterLogonProcess || !pLsaDeregisterLogonProcess ||
        !pLsaLookupAuthenticationPackage || !pLsaLogonUser || !pLsaFreeReturnBuffer)
    {
        skip("LSA functions missing\n");
        return;
    }

    RtlZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = TestUser;
    Info.usri1_password = TestPassword;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    NetUserDel(NULL, TestUser);
    NetStatus = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    if (NetStatus == ERROR_ACCESS_DENIED)
    {
        skip("NetUserAdd needs an elevated administrator\n");
        return;
    }
    ok(NetStatus == NERR_Success, "NetUserAdd failed: %lu (parm %lu)\n", NetStatus, Err);
    if (NetStatus != NERR_Success)
        return;

    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &Admins);
    AllocateAndInitializeSid(&NtAuthority, 6, SECURITY_SERVICE_ID_BASE_RID, 1, 2, 3, 4, 5, 0, 0, &Fake);
    Groups->GroupCount = 2;
    Groups->Groups[0].Sid = Admins;
    Groups->Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    Groups->Groups[1].Sid = Fake;
    Groups->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;

    /* Untrusted connection: the logon works, the groups are refused */
    Status = pLsaConnectUntrusted(&Lsa);
    ok(Status == STATUS_SUCCESS, "LsaConnectUntrusted returned 0x%08lx\n", Status);
    if (Status == STATUS_SUCCESS)
    {
        Status = InteractiveLogon(Lsa, NULL, &Token);
        ok(Status == STATUS_SUCCESS, "untrusted logon without groups returned 0x%08lx\n", Status);
        if (Token)
        {
            ok(GroupAttributes(Token, Admins) == ~0UL, "the plain logon has Administrators\n");
            CloseHandle(Token);
            Token = NULL;
        }

        Status = InteractiveLogon(Lsa, Groups, &Token);
        ok(Status == STATUS_ACCESS_DENIED, "untrusted logon with LocalGroups returned 0x%08lx, expected 0x%08lx\n",
           Status, STATUS_ACCESS_DENIED);
        ok(Token == NULL, "untrusted logon with LocalGroups returned a token\n");
        if (Token)
        {
            ok(GroupAttributes(Token, Admins) == ~0UL, "Administrators added for an untrusted caller: 0x%lx\n",
               GroupAttributes(Token, Admins));
            ok(GroupAttributes(Token, Fake) == ~0UL, "S-1-5-80-1-2-3-4-5 added for an untrusted caller: 0x%lx\n",
               GroupAttributes(Token, Fake));
            CloseHandle(Token);
            Token = NULL;
        }
        /* The logon SID and LOCAL that our LogonUser passes: accepted, the logon SID replaced */
        {
            static SID_IDENTIFIER_AUTHORITY LocalAuthority = {SECURITY_LOCAL_SID_AUTHORITY};
            BYTE PairBuffer[sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES)];
            PTOKEN_GROUPS Pair = (PTOKEN_GROUPS)PairBuffer;
            BYTE Got[SECURITY_MAX_SID_SIZE];
            PSID Local = NULL, Logon = NULL;

            AllocateAndInitializeSid(&LocalAuthority, 1, SECURITY_LOCAL_RID, 0, 0, 0, 0, 0, 0, 0, &Local);
            AllocateAndInitializeSid(&NtAuthority, 3, SECURITY_LOGON_IDS_RID, 0, 0x4242, 0, 0, 0, 0, 0, &Logon);
            Pair->GroupCount = 2;
            Pair->Groups[0].Sid = Logon;
            Pair->Groups[0].Attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_LOGON_ID;
            Pair->Groups[1].Sid = Local;
            Pair->Groups[1].Attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT;
            Status = InteractiveLogon(Lsa, Pair, &Token);
            ok(Status == STATUS_SUCCESS, "untrusted logon with the logon SID and LOCAL returned 0x%08lx\n", Status);
            if (Token)
            {
                ok(GroupAttributes(Token, Local) != ~0UL, "LOCAL missing\n");
                ok(CopyTokenLogonSid(Token, Got, sizeof(Got)), "no logon SID in the token\n");
                ok(!EqualSid(Got, Logon), "the caller's logon SID S-1-5-5-0-16962 was kept\n");
                CloseHandle(Token);
                Token = NULL;
            }

            /* ... but nothing else next to them */
            Pair->Groups[1].Sid = Fake;
            Status = InteractiveLogon(Lsa, Pair, &Token);
            ok(Status == STATUS_ACCESS_DENIED, "untrusted logon with the logon SID and S-1-5-80-1-2-3-4-5 returned 0x%08lx\n", Status);
            if (Token)
            {
                CloseHandle(Token);
                Token = NULL;
            }
            FreeSid(Local);
            FreeSid(Logon);
        }
        pLsaDeregisterLogonProcess(Lsa);
        Lsa = NULL;
    }

    /* LogonUser of a caller without SeTcbPrivilege works (it passes the logon SID and LOCAL) */
    Token = NULL;
    ok(LogonUserW(TestUser, L".", TestPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token),
       "LogonUser failed: %lu\n", GetLastError());
    if (Token)
    {
        CloseHandle(Token);
        Token = NULL;
    }

    /* A caller that holds SeTcbPrivilege (registered logon process, as SYSTEM): the groups are added */
    if (ImpersonateSystem())
    {
        RtlInitString((PSTRING)&ProcessName, "LsaLgTestLogonProcess");
        Status = pLsaRegisterLogonProcess(&ProcessName, &Lsa, &Mode);
        RevertToSelf();
        ok(Status == STATUS_SUCCESS, "LsaRegisterLogonProcess as SYSTEM returned 0x%08lx\n", Status);
        if (Status == STATUS_SUCCESS)
        {
            Status = InteractiveLogon(Lsa, Groups, &Token);
            ok(Status == STATUS_SUCCESS, "trusted logon with LocalGroups returned 0x%08lx\n", Status);
            if (Token)
            {
                Attributes = GroupAttributes(Token, Fake);
                ok(Attributes != ~0UL && (Attributes & SE_GROUP_ENABLED),
                   "S-1-5-80-1-2-3-4-5 of a trusted caller: 0x%lx\n", Attributes);
                CloseHandle(Token);
            }
            pLsaDeregisterLogonProcess(Lsa);
        }
    }
    else
    {
        skip("cannot impersonate SYSTEM: no trusted row\n");
    }

    FreeSid(Admins);
    FreeSid(Fake);
    NetStatus = NetUserDel(NULL, TestUser);
    ok(NetStatus == NERR_Success, "NetUserDel failed: %lu\n", NetStatus);
}
