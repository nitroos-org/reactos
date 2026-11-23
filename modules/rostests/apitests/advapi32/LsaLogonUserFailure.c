/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A failed LsaLogonUser leaves the logon sessions of others alone
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>
#include <tlhelp32.h>
#include <ndk/lpctypes.h>
#include <subsys/lsass/lsass.h>

/*
 * The reply of an LsaLogonUser message overlays its request. When a logon failed, the LSA ended the logon
 * session named by the reply's LogonId (the package's "logon terminated" notice, then the delete) even when
 * the package had failed before it wrote one: LogonId then still held bytes of the request (the logon type
 * and its neighbours), chosen by the caller. The package's state of that session (msv1_0's user name, the
 * hashes single sign-on uses) was dropped, whatever session it was.
 *
 * Contract: a failed logon request, from any caller, changes no logon session but one it made itself.
 * The failing request is one msv1_0 refuses before it logs anybody on (an unknown logon type); it is sent
 * over an untrusted connection, as any user can. MsV1_0GetUserInfo (a trusted call) shows whether msv1_0
 * still knows the other logon session.
 */

typedef NTSTATUS (NTAPI *LSACONNECTUNTRUSTED)(PHANDLE);
typedef NTSTATUS (NTAPI *LSAREGISTERLOGONPROCESS)(PLSA_STRING, PHANDLE, PLSA_OPERATIONAL_MODE);
typedef NTSTATUS (NTAPI *LSADEREGISTERLOGONPROCESS)(HANDLE);
typedef NTSTATUS (NTAPI *LSALOOKUPAUTHENTICATIONPACKAGE)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS (NTAPI *LSALOGONUSER)(HANDLE, PLSA_STRING, SECURITY_LOGON_TYPE, ULONG, PVOID, ULONG,
                                       PTOKEN_GROUPS, PTOKEN_SOURCE, PVOID *, PULONG, PLUID, PHANDLE,
                                       PQUOTA_LIMITS, PNTSTATUS);
typedef NTSTATUS (NTAPI *LSACALLAUTHENTICATIONPACKAGE)(HANDLE, ULONG, PVOID, ULONG, PVOID *, PULONG, PNTSTATUS);
typedef NTSTATUS (NTAPI *LSAFREERETURNBUFFER)(PVOID);

static LSACONNECTUNTRUSTED pLsaConnectUntrusted;
static LSAREGISTERLOGONPROCESS pLsaRegisterLogonProcess;
static LSADEREGISTERLOGONPROCESS pLsaDeregisterLogonProcess;
static LSALOOKUPAUTHENTICATIONPACKAGE pLsaLookupAuthenticationPackage;
static LSALOGONUSER pLsaLogonUser;
static LSACALLAUTHENTICATIONPACKAGE pLsaCallAuthenticationPackage;
static LSAFREERETURNBUFFER pLsaFreeReturnBuffer;

static WCHAR TestUser[] = L"lsafailtest";
static WCHAR TestPassword[] = L"Lsa-Fail-Test-2026!";

/* MsV1_0GetUserInfo (ntmsv1_0.h is a kernel-mode header) */
typedef struct _TEST_GETUSERINFO_REQUEST
{
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
} TEST_GETUSERINFO_REQUEST;

typedef struct _TEST_GETUSERINFO_RESPONSE
{
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    PSID UserSid;
    UNICODE_STRING UserName;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING LogonServer;
    SECURITY_LOGON_TYPE LogonType;
} TEST_GETUSERINFO_RESPONSE;

static NTSTATUS
InteractiveLogon(HANDLE Lsa, ULONG Package, PCWSTR Password, PHANDLE Token)
{
    BYTE Buffer[sizeof(MSV1_0_INTERACTIVE_LOGON) + 128 * sizeof(WCHAR)];
    PMSV1_0_INTERACTIVE_LOGON Logon = (PMSV1_0_INTERACTIVE_LOGON)Buffer;
    PWCHAR Ptr = (PWCHAR)(Logon + 1);
    LSA_STRING Origin;
    TOKEN_SOURCE Source;
    PVOID Profile = NULL;
    ULONG ProfileLength = 0;
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
    Logon->Password.Length = (USHORT)(wcslen(Password) * sizeof(WCHAR));
    Logon->Password.MaximumLength = Logon->Password.Length + sizeof(WCHAR);
    RtlCopyMemory(Ptr, Password, Logon->Password.MaximumLength);
    Ptr += wcslen(Password) + 1;

    RtlInitString((PSTRING)&Origin, "LsaFailTest");
    RtlCopyMemory(Source.SourceName, "LsaFlTst", 8);
    AllocateLocallyUniqueId(&Source.SourceIdentifier);
    Status = pLsaLogonUser(Lsa, &Origin, Interactive, Package, Logon, (ULONG)((PBYTE)Ptr - Buffer),
                           NULL, &Source, &Profile, &ProfileLength, &LogonId, Token, &Quotas, &SubStatus);
    SecureZeroMemory(Buffer, sizeof(Buffer));
    if (Profile)
        pLsaFreeReturnBuffer(Profile);
    return Status;
}

/*
 * A logon request msv1_0 refuses before it logs anybody on: the logon type is no type it knows. Its other
 * fields are those whose bytes lie under the reply's LogonId (lsass.h), set to Luid. Returns FALSE when that
 * cannot be sent: the LUID's bytes would have to name another package than msv1_0.
 */
static BOOL
FailingLogon(HANDLE Lsa, ULONG Package, PLUID Luid, NTSTATUS *Status)
{
    LSA_LOGON_USER_MSG Msg;
    BYTE Auth[16];
    TOKEN_SOURCE Source;
    PVOID Profile = NULL;
    ULONG ProfileLength = 0;
    LUID LogonId;
    HANDLE Token = NULL;
    QUOTA_LIMITS Quotas;
    NTSTATUS SubStatus = 0;

    const ULONG IdStart = FIELD_OFFSET(LSA_LOGON_USER_MSG, Reply.LogonId);
    const ULONG PackageStart = FIELD_OFFSET(LSA_LOGON_USER_MSG, Request.AuthenticationPackage);

    RtlZeroMemory(&Msg, sizeof(Msg));
    Msg.Reply.LogonId = *Luid;
    if (PackageStart + sizeof(ULONG) > IdStart && PackageStart < IdStart + sizeof(LUID))
    {
        /* the package id is part of the LUID's bytes (i386): it must be msv1_0's already */
        if (Msg.Request.AuthenticationPackage != Package)
            return FALSE;
    }
    else
    {
        Msg.Request.AuthenticationPackage = Package;
    }
    /* Logon types msv1_0 handles are below 16 (LUIDs of logon sessions are above 0x3e3): never one of them */
    if ((ULONG)Msg.Request.LogonType >= Interactive && (ULONG)Msg.Request.LogonType <= 16)
        return FALSE;

    RtlZeroMemory(Auth, sizeof(Auth));
    RtlCopyMemory(Source.SourceName, "LsaFlTst", 8);
    AllocateLocallyUniqueId(&Source.SourceIdentifier);
    *Status = pLsaLogonUser(Lsa, &Msg.Request.OriginName, Msg.Request.LogonType, Msg.Request.AuthenticationPackage,
                            Auth, sizeof(Auth),
                            NULL, &Source, &Profile, &ProfileLength, &LogonId, &Token, &Quotas, &SubStatus);
    if (NT_SUCCESS(*Status))
    {
        if (Token)
            CloseHandle(Token);
        if (Profile)
            pLsaFreeReturnBuffer(Profile);
    }
    return TRUE;
}

/* What msv1_0 knows of the logon session Luid (MsV1_0GetUserInfo); STATUS_SUCCESS with the user's name */
static NTSTATUS
GetUserInfo(HANDLE TrustedLsa, ULONG Package, PLUID Luid, PWSTR Name, ULONG NameChars)
{
    TEST_GETUSERINFO_REQUEST Request;
    TEST_GETUSERINFO_RESPONSE *Response = NULL;
    ULONG Length = 0;
    NTSTATUS Status, ProtocolStatus = 0;

    Name[0] = UNICODE_NULL;
    Request.MessageType = MsV1_0GetUserInfo;
    Request.LogonId = *Luid;
    Status = pLsaCallAuthenticationPackage(TrustedLsa, Package, &Request, sizeof(Request),
                                           (PVOID *)&Response, &Length, &ProtocolStatus);
    if (NT_SUCCESS(Status))
        Status = ProtocolStatus;
    if (NT_SUCCESS(Status) && Response != NULL)
    {
        StringCchCopyNW(Name, NameChars, Response->UserName.Buffer, Response->UserName.Length / sizeof(WCHAR));
    }
    if (Response)
        pLsaFreeReturnBuffer(Response);
    return Status;
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

START_TEST(LsaLogonUserFailure)
{
    LSA_STRING ProcessName, PackageName;
    LSA_OPERATIONAL_MODE Mode;
    HANDLE Lsa = NULL, Trusted = NULL, Victim = NULL, Token = NULL;
    TOKEN_STATISTICS Statistics;
    WCHAR Name[64];
    USER_INFO_1 Info;
    HMODULE Secur32;
    ULONG Package = 0, i;
    DWORD Err = 0, Length;
    BOOL Wow64 = FALSE;
    NTSTATUS Status, FailStatus;
    NET_API_STATUS NetStatus;

    if (IsWow64Process(GetCurrentProcess(), &Wow64) && Wow64)
    {
        skip("the LSA message layout of a 32-bit process under WoW64 differs from lsass'\n");
        return;
    }

    Secur32 = LoadLibraryW(L"secur32.dll");
    ok(Secur32 != NULL, "secur32 not loaded: %lu\n", GetLastError());
    if (!Secur32)
        return;
    pLsaConnectUntrusted = (LSACONNECTUNTRUSTED)GetProcAddress(Secur32, "LsaConnectUntrusted");
    pLsaRegisterLogonProcess = (LSAREGISTERLOGONPROCESS)GetProcAddress(Secur32, "LsaRegisterLogonProcess");
    pLsaDeregisterLogonProcess = (LSADEREGISTERLOGONPROCESS)GetProcAddress(Secur32, "LsaDeregisterLogonProcess");
    pLsaLookupAuthenticationPackage = (LSALOOKUPAUTHENTICATIONPACKAGE)GetProcAddress(Secur32, "LsaLookupAuthenticationPackage");
    pLsaLogonUser = (LSALOGONUSER)GetProcAddress(Secur32, "LsaLogonUser");
    pLsaCallAuthenticationPackage = (LSACALLAUTHENTICATIONPACKAGE)GetProcAddress(Secur32, "LsaCallAuthenticationPackage");
    pLsaFreeReturnBuffer = (LSAFREERETURNBUFFER)GetProcAddress(Secur32, "LsaFreeReturnBuffer");
    if (!pLsaConnectUntrusted || !pLsaRegisterLogonProcess || !pLsaDeregisterLogonProcess ||
        !pLsaLookupAuthenticationPackage || !pLsaLogonUser || !pLsaCallAuthenticationPackage || !pLsaFreeReturnBuffer)
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

    /* The trusted connection that observes msv1_0 */
    if (!ImpersonateSystem())
    {
        skip("cannot impersonate SYSTEM: msv1_0's state cannot be read\n");
        goto cleanup;
    }
    RtlInitString((PSTRING)&ProcessName, "LsaFailTestLogonProcess");
    Status = pLsaRegisterLogonProcess(&ProcessName, &Trusted, &Mode);
    RevertToSelf();
    ok(Status == STATUS_SUCCESS, "LsaRegisterLogonProcess as SYSTEM returned 0x%08lx\n", Status);
    if (Status != STATUS_SUCCESS)
        goto cleanup;

    Status = pLsaConnectUntrusted(&Lsa);
    ok(Status == STATUS_SUCCESS, "LsaConnectUntrusted returned 0x%08lx\n", Status);
    if (Status != STATUS_SUCCESS)
        goto cleanup;
    RtlInitString((PSTRING)&PackageName, MSV1_0_PACKAGE_NAME);
    Status = pLsaLookupAuthenticationPackage(Lsa, &PackageName, &Package);
    ok(Status == STATUS_SUCCESS, "LsaLookupAuthenticationPackage returned 0x%08lx\n", Status);
    if (Status != STATUS_SUCCESS)
        goto cleanup;

    /* The other logon session: the test user's, its token kept open */
    Status = InteractiveLogon(Lsa, Package, TestPassword, &Victim);
    ok(Status == STATUS_SUCCESS, "logon of %S returned 0x%08lx\n", TestUser, Status);
    if (Victim == NULL)
        goto cleanup;
    ok(GetTokenInformation(Victim, TokenStatistics, &Statistics, sizeof(Statistics), &Length),
       "TokenStatistics: %lu\n", GetLastError());

    Status = GetUserInfo(Trusted, Package, &Statistics.AuthenticationId, Name, ARRAYSIZE(Name));
    ok(Status == STATUS_SUCCESS, "GetUserInfo of the new logon session returned 0x%08lx\n", Status);
    ok(_wcsicmp(Name, TestUser) == 0, "GetUserInfo user %S, expected %S\n", Name, TestUser);

    /* Failed logons that are no business of that session: a wrong password ... */
    Status = InteractiveLogon(Lsa, Package, L"not-the-password", &Token);
    ok(Status == STATUS_LOGON_FAILURE, "logon with a wrong password returned 0x%08lx\n", Status);
    if (Token)
        CloseHandle(Token);
    Status = GetUserInfo(Trusted, Package, &Statistics.AuthenticationId, Name, ARRAYSIZE(Name));
    ok(Status == STATUS_SUCCESS && _wcsicmp(Name, TestUser) == 0,
       "after a wrong password: GetUserInfo 0x%08lx, user %S\n", Status, Name);

    /* ... and a request msv1_0 refuses at once, whose request bytes spell that session's LUID */
    for (i = 0; i < 3; i++)
    {
        FailStatus = STATUS_SUCCESS;
        if (!FailingLogon(Lsa, Package, &Statistics.AuthenticationId, &FailStatus))
        {
            skip("the LUID 0x%lx:0x%lx cannot be spelled by a request for msv1_0\n",
                 Statistics.AuthenticationId.HighPart, Statistics.AuthenticationId.LowPart);
            break;
        }
        ok(!NT_SUCCESS(FailStatus), "the request with an unknown logon type returned 0x%08lx\n", FailStatus);

        Status = GetUserInfo(Trusted, Package, &Statistics.AuthenticationId, Name, ARRAYSIZE(Name));
        ok(Status == STATUS_SUCCESS, "round %lu: msv1_0 lost the other logon session: GetUserInfo 0x%08lx\n", i, Status);
        ok(_wcsicmp(Name, TestUser) == 0, "round %lu: GetUserInfo user '%S', expected %S\n", i, Name, TestUser);
    }

cleanup:
    if (Victim)
        CloseHandle(Victim);
    if (Lsa)
        pLsaDeregisterLogonProcess(Lsa);
    if (Trusted)
        pLsaDeregisterLogonProcess(Trusted);
    NetStatus = NetUserDel(NULL, TestUser);
    ok(NetStatus == NERR_Success, "NetUserDel failed: %lu\n", NetStatus);
}
