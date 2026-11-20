/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     An account whose password is blank (never set, or set to "") accepts only the empty password,
 *              and only for the logon dialog on the console while Lsa\LimitBlankPasswordUse is 1. Measured on
 *              Windows Server 2022 (10.0.20348) on scratch accounts, from a WinRM caller (session 0), from
 *              LocalSystem and from a process in the console session alike:
 *              - LimitBlankPasswordUse 1: the empty password gives 1327 (ERROR_ACCOUNT_RESTRICTION) for
 *                LogonUser INTERACTIVE, NETWORK, BATCH, SERVICE, UNLOCK and NETWORK_CLEARTEXT (before the
 *                logon right is looked at); LsaLogonUser returns STATUS_ACCOUNT_RESTRICTION with the same
 *                substatus; CreateProcessWithLogonW 1327; such an attempt is not a bad password;
 *              - a wrong password gives 1326 for every type and counts as a bad password;
 *              - NEW_CREDENTIALS does not check the password;
 *              - LimitBlankPasswordUse 0: the empty password logs on (BATCH and SERVICE: 1385, no right);
 *              - UF_PASSWD_NOTREQD on an account with a password changes nothing: wrong and empty give 1326.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>

#define NT_STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006D)
#define NT_STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006E)
#define NT_STATUS_SUCCESS ((NTSTATUS)0x00000000)

static WCHAR TestPassword[] = L"Blank-Pw-Test-2026!";
static WCHAR WrongPassword[] = L"Not-The-Password-7";
static const WCHAR LsaKey[] = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";

typedef NTSTATUS (NTAPI *LSACONNECTUNTRUSTED)(PHANDLE);
typedef NTSTATUS (NTAPI *LSALOOKUPAUTHENTICATIONPACKAGE)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS (NTAPI *LSALOGONUSER)(HANDLE, PLSA_STRING, SECURITY_LOGON_TYPE, ULONG, PVOID, ULONG, PTOKEN_GROUPS,
                                       PTOKEN_SOURCE, PVOID *, PULONG, PLUID, PHANDLE, PQUOTA_LIMITS, PNTSTATUS);
typedef NTSTATUS (NTAPI *LSAFREERETURNBUFFER)(PVOID);
typedef NTSTATUS (NTAPI *LSADEREGISTERLOGONPROCESS)(HANDLE);

static LSACONNECTUNTRUSTED pLsaConnectUntrusted;
static LSALOOKUPAUTHENTICATIONPACKAGE pLsaLookupAuthenticationPackage;
static LSALOGONUSER pLsaLogonUser;
static LSAFREERETURNBUFFER pLsaFreeReturnBuffer;
static LSADEREGISTERLOGONPROCESS pLsaDeregisterLogonProcess;

static const DWORD PasswordTypes[] = { LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK, LOGON32_LOGON_BATCH,
                                       LOGON32_LOGON_SERVICE, LOGON32_LOGON_UNLOCK, LOGON32_LOGON_NETWORK_CLEARTEXT };

static DWORD Logon(PCWSTR User, PCWSTR Password, DWORD Type)
{
    HANDLE Token = NULL;

    SetLastError(0xdeadbeef);
    if (LogonUserW((LPWSTR)User, (LPWSTR)L".", (LPWSTR)Password, Type,
                   Type == LOGON32_LOGON_NEW_CREDENTIALS ? LOGON32_PROVIDER_WINNT50 : LOGON32_PROVIDER_DEFAULT, &Token))
    {
        CloseHandle(Token);
        return ERROR_SUCCESS;
    }
    return GetLastError();
}

/* LsaLogonUser through an untrusted connection, MSV1_0 interactive logon buffer */
static NTSTATUS LsaLogon(PCWSTR User, PCWSTR Password, SECURITY_LOGON_TYPE Type, PNTSTATUS SubStatus)
{
    HANDLE Lsa = NULL, Token = NULL;
    LSA_STRING Package, Origin;
    ULONG PackageId = 0, Size, ProfileLength = 0;
    SIZE_T UserBytes = wcslen(User) * sizeof(WCHAR), PwBytes = wcslen(Password) * sizeof(WCHAR);
    PMSV1_0_INTERACTIVE_LOGON Buffer;
    PBYTE p;
    TOKEN_SOURCE Source;
    PVOID Profile = NULL;
    LUID LogonId;
    QUOTA_LIMITS Quotas;
    NTSTATUS Status;

    *SubStatus = (NTSTATUS)0xdeadbeef;
    if (!pLsaConnectUntrusted || pLsaConnectUntrusted(&Lsa) != NT_STATUS_SUCCESS)
        return (NTSTATUS)0xdeadbeef;

    Package.Buffer = (PCHAR)MSV1_0_PACKAGE_NAME;
    Package.Length = (USHORT)strlen(MSV1_0_PACKAGE_NAME);
    Package.MaximumLength = Package.Length + 1;
    pLsaLookupAuthenticationPackage(Lsa, &Package, &PackageId);

    Size = (ULONG)(sizeof(MSV1_0_INTERACTIVE_LOGON) + sizeof(WCHAR) + UserBytes + PwBytes);
    Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!Buffer)
    {
        pLsaDeregisterLogonProcess(Lsa);
        return (NTSTATUS)0xdeadbeef;
    }
    p = (PBYTE)(Buffer + 1);
    Buffer->MessageType = MsV1_0InteractiveLogon;
    memcpy(p, L".", sizeof(WCHAR));
    Buffer->LogonDomainName.Buffer = (PWSTR)p;
    Buffer->LogonDomainName.Length = Buffer->LogonDomainName.MaximumLength = sizeof(WCHAR);
    p += sizeof(WCHAR);
    memcpy(p, User, UserBytes);
    Buffer->UserName.Buffer = (PWSTR)p;
    Buffer->UserName.Length = Buffer->UserName.MaximumLength = (USHORT)UserBytes;
    p += UserBytes;
    memcpy(p, Password, PwBytes);
    Buffer->Password.Buffer = (PWSTR)p;
    Buffer->Password.Length = Buffer->Password.MaximumLength = (USHORT)PwBytes;

    Origin.Buffer = (PCHAR)"BlankPw";
    Origin.Length = 7;
    Origin.MaximumLength = 8;
    memcpy(Source.SourceName, "BlankPw ", 8);
    AllocateLocallyUniqueId(&Source.SourceIdentifier);

    Status = pLsaLogonUser(Lsa, &Origin, Type, PackageId, Buffer, Size, NULL, &Source,
                           &Profile, &ProfileLength, &LogonId, &Token, &Quotas, SubStatus);
    if (Profile)
        pLsaFreeReturnBuffer(Profile);
    if (Token)
        CloseHandle(Token);
    HeapFree(GetProcessHeap(), 0, Buffer);
    pLsaDeregisterLogonProcess(Lsa);
    return Status;
}

static BOOL SetLimitBlank(DWORD Value)
{
    HKEY Key;
    LONG Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, LsaKey, 0, KEY_SET_VALUE, &Key);
    if (Error != ERROR_SUCCESS)
        return FALSE;
    Error = RegSetValueExW(Key, L"LimitBlankPasswordUse", 0, REG_DWORD, (const BYTE *)&Value, sizeof(Value));
    RegCloseKey(Key);
    return Error == ERROR_SUCCESS;
}

static BOOL GetLimitBlank(PDWORD Value)
{
    DWORD Size = sizeof(*Value), Type;
    HKEY Key;
    LONG Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, LsaKey, 0, KEY_QUERY_VALUE, &Key);
    if (Error != ERROR_SUCCESS)
        return FALSE;
    Error = RegQueryValueExW(Key, L"LimitBlankPasswordUse", NULL, &Type, (PBYTE)Value, &Size);
    RegCloseKey(Key);
    return Error == ERROR_SUCCESS && Type == REG_DWORD;
}

static DWORD BadCount(PCWSTR User)
{
    USER_INFO_3 *Info = NULL;
    DWORD Count;

    if (NetUserGetInfo(NULL, User, 3, (PBYTE *)&Info) != NERR_Success)
        return 0xdeadbeef;
    Count = Info->usri3_bad_pw_count;
    NetApiBufferFree(Info);
    return Count;
}

/* The call net.exe makes for "net user NAME [PASSWORD] /add" (level 4, no password = NULL) */
static BOOL AddUser(PCWSTR Name, PWSTR Password, DWORD Priv)
{
    USER_INFO_4 Info;
    DWORD Error = 0;
    NET_API_STATUS Status;

    ZeroMemory(&Info, sizeof(Info));
    Info.usri4_name = (PWSTR)Name;
    Info.usri4_password = Password;
    Info.usri4_priv = Priv;
    Info.usri4_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    Info.usri4_acct_expires = TIMEQ_FOREVER;
    Info.usri4_primary_group_id = DOMAIN_GROUP_RID_USERS;
    Status = NetUserAdd(NULL, 4, (PBYTE)&Info, &Error);
    ok(Status == NERR_Success, "NetUserAdd(%ls) failed: %lu (parameter %lu)\n", Name, Status, Error);
    return Status == NERR_Success;
}

/* The rows of one blank-password account with the policy on */
static void TestBlankPolicyOn(PCWSTR User)
{
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Process;
    WCHAR CommandLine[] = L"cmd.exe /c exit 7";
    NTSTATUS Status, SubStatus;
    DWORD Before, Error;
    ULONG i;

    Before = BadCount(User);

    for (i = 0; i < RTL_NUMBER_OF(PasswordTypes); i++)
    {
        Error = Logon(User, L"", PasswordTypes[i]);
        ok(Error == ERROR_ACCOUNT_RESTRICTION, "%ls, empty password, type %lu: %lu, expected 1327\n",
           User, PasswordTypes[i], Error);
    }
    ok_dec(BadCount(User), Before);

    for (i = 0; i < RTL_NUMBER_OF(PasswordTypes); i++)
    {
        Error = Logon(User, WrongPassword, PasswordTypes[i]);
        ok(Error == ERROR_LOGON_FAILURE, "%ls, wrong password, type %lu: %lu, expected 1326\n",
           User, PasswordTypes[i], Error);
    }
    ok_dec(Logon(User, L"", LOGON32_LOGON_NEW_CREDENTIALS), ERROR_SUCCESS);

    Status = LsaLogon(User, L"", Interactive, &SubStatus);
    ok(Status == NT_STATUS_ACCOUNT_RESTRICTION, "%ls: LsaLogonUser empty: 0x%08lx\n", User, Status);
    ok(SubStatus == NT_STATUS_ACCOUNT_RESTRICTION, "%ls: LsaLogonUser empty: substatus 0x%08lx\n", User, SubStatus);
    Status = LsaLogon(User, WrongPassword, Interactive, &SubStatus);
    ok(Status == NT_STATUS_LOGON_FAILURE, "%ls: LsaLogonUser wrong: 0x%08lx\n", User, Status);

    SetLastError(0xdeadbeef);
    if (CreateProcessWithLogonW(User, L".", L"", 0, NULL, CommandLine, CREATE_NO_WINDOW, NULL, NULL,
                                &Startup, &Process))
    {
        ok(0, "%ls: CreateProcessWithLogonW with the empty password succeeded\n", User);
        WaitForSingleObject(Process.hProcess, 10000);
        CloseHandle(Process.hProcess);
        CloseHandle(Process.hThread);
    }
    else
    {
        Error = GetLastError();
        if (Error == ERROR_FILE_NOT_FOUND || Error == ERROR_SERVICE_DISABLED || Error == ERROR_SERVICE_DOES_NOT_EXIST)
            skip("CreateProcessWithLogonW is not usable here (%lu)\n", Error);
        else
            ok(Error == ERROR_ACCOUNT_RESTRICTION, "%ls: CreateProcessWithLogonW empty: %lu, expected 1327\n", User, Error);
    }
}

static void TestBlankPolicyOff(PCWSTR User)
{
    DWORD Error;

    ok_dec(Logon(User, L"", LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
    ok_dec(Logon(User, L"", LOGON32_LOGON_NETWORK), ERROR_SUCCESS);
    ok_dec(Logon(User, L"", LOGON32_LOGON_UNLOCK), ERROR_SUCCESS);
    ok_dec(Logon(User, L"", LOGON32_LOGON_NETWORK_CLEARTEXT), ERROR_SUCCESS);
    /* a standard user has no batch or service logon right */
    Error = Logon(User, L"", LOGON32_LOGON_BATCH);
    ok(Error == ERROR_LOGON_TYPE_NOT_GRANTED, "%ls, policy off, batch: %lu, expected 1385\n", User, Error);
    Error = Logon(User, L"", LOGON32_LOGON_SERVICE);
    ok(Error == ERROR_LOGON_TYPE_NOT_GRANTED, "%ls, policy off, service: %lu, expected 1385\n", User, Error);
    /* still only the empty password */
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_NETWORK), ERROR_LOGON_FAILURE);
    ok_dec(Logon(User, L" ", LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
}

START_TEST(LogonUserBlankPassword)
{
    HMODULE Secur32 = LoadLibraryW(L"secur32.dll");
    WCHAR Never[32], Empty[32], WithPw[32];
    USER_INFO_1008 Flags;
    DWORD Old = 0, Error = 0;
    BOOL HadOld, HaveNever, HaveEmpty, HaveWithPw;
    ULONG Tag = GetTickCount() & 0xfffff;

    if (Secur32)
    {
        pLsaConnectUntrusted = (LSACONNECTUNTRUSTED)GetProcAddress(Secur32, "LsaConnectUntrusted");
        pLsaLookupAuthenticationPackage = (LSALOOKUPAUTHENTICATIONPACKAGE)GetProcAddress(Secur32, "LsaLookupAuthenticationPackage");
        pLsaLogonUser = (LSALOGONUSER)GetProcAddress(Secur32, "LsaLogonUser");
        pLsaFreeReturnBuffer = (LSAFREERETURNBUFFER)GetProcAddress(Secur32, "LsaFreeReturnBuffer");
        pLsaDeregisterLogonProcess = (LSADEREGISTERLOGONPROCESS)GetProcAddress(Secur32, "LsaDeregisterLogonProcess");
    }

    HadOld = GetLimitBlank(&Old);
    if (!SetLimitBlank(1))
    {
        skip("Lsa\\LimitBlankPasswordUse cannot be written: needs an elevated administrator\n");
        return;
    }

    StringCchPrintfW(Never, RTL_NUMBER_OF(Never), L"blkn%05lx", Tag);
    StringCchPrintfW(Empty, RTL_NUMBER_OF(Empty), L"blke%05lx", Tag);
    StringCchPrintfW(WithPw, RTL_NUMBER_OF(WithPw), L"blkp%05lx", Tag);

    /* "net user x /add" (no password) and "net user x "" /add" */
    HaveNever = AddUser(Never, NULL, USER_PRIV_USER);
    HaveEmpty = AddUser(Empty, (PWSTR)L"", USER_PRIV_USER);
    HaveWithPw = AddUser(WithPw, TestPassword, USER_PRIV_USER);

    if (HaveNever)
        TestBlankPolicyOn(Never);
    if (HaveEmpty)
        TestBlankPolicyOn(Empty);

    /* an account with a password: the policy changes nothing */
    if (HaveWithPw)
    {
        ok_dec(Logon(WithPw, TestPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
        ok_dec(Logon(WithPw, L"", LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
        ok_dec(Logon(WithPw, WrongPassword, LOGON32_LOGON_NETWORK), ERROR_LOGON_FAILURE);

        /* UF_PASSWD_NOTREQD does not switch the password check off */
        Flags.usri1008_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD;
        ok_dec(NetUserSetInfo(NULL, WithPw, 1008, (PBYTE)&Flags, &Error), NERR_Success);
        ok_dec(Logon(WithPw, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
        ok_dec(Logon(WithPw, WrongPassword, LOGON32_LOGON_NETWORK), ERROR_LOGON_FAILURE);
        ok_dec(Logon(WithPw, WrongPassword, LOGON32_LOGON_NETWORK_CLEARTEXT), ERROR_LOGON_FAILURE);
        ok_dec(Logon(WithPw, L"", LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
        ok_dec(Logon(WithPw, TestPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
    }

    /* The password change of a blank account (policy on), measured on Windows Server 2022: a standard user gets 5 with
       the empty and with a wrong old password, not counted; the policy off: 0; the Administrator: 0 */
    if (HaveNever && HaveEmpty && HaveWithPw)
    {
        HANDLE Token = NULL;
        DWORD Before = BadCount(Never);

        if (LogonUserW(WithPw, L".", TestPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token) &&
            ImpersonateLoggedOnUser(Token))
        {
            ok_dec(NetUserChangePassword(NULL, Never, L"", TestPassword), ERROR_ACCESS_DENIED);
            ok_dec(NetUserChangePassword(NULL, Never, WrongPassword, TestPassword), ERROR_ACCESS_DENIED);
            RevertToSelf();
            ok_dec(BadCount(Never), Before);
            ok_dec(Logon(Never, TestPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);

            ok(SetLimitBlank(0), "cannot set LimitBlankPasswordUse 0\n");
            ok(ImpersonateLoggedOnUser(Token), "impersonation failed: %lu\n", GetLastError());
            ok_dec(NetUserChangePassword(NULL, Never, L"", TestPassword), NERR_Success);
            RevertToSelf();
            ok_dec(Logon(Never, TestPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
            /* back to the blank password for the rows below */
            ok_dec(NetUserChangePassword(NULL, Never, TestPassword, L""), NERR_Success);
            ok(SetLimitBlank(1), "cannot set LimitBlankPasswordUse 1\n");
        }
        else
            skip("cannot log on and impersonate %ls: %lu\n", WithPw, GetLastError());
        if (Token != NULL)
            CloseHandle(Token);

        /* the caller of this test, an administrator: allowed (it can reset the password anyway) */
        ok_dec(NetUserChangePassword(NULL, Empty, L"", TestPassword), NERR_Success);
        ok_dec(Logon(Empty, TestPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
        ok_dec(NetUserChangePassword(NULL, Empty, TestPassword, L""), NERR_Success);
    }

    /* the policy off: the empty password logs on, a wrong one still does not */
    ok(SetLimitBlank(0), "cannot set LimitBlankPasswordUse 0\n");
    if (HaveNever)
        TestBlankPolicyOff(Never);
    if (HaveEmpty)
        TestBlankPolicyOff(Empty);

    /* restore */
    if (HadOld)
        SetLimitBlank(Old);
    else
    {
        HKEY Key;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LsaKey, 0, KEY_SET_VALUE, &Key) == ERROR_SUCCESS)
        {
            RegDeleteValueW(Key, L"LimitBlankPasswordUse");
            RegCloseKey(Key);
        }
    }

    if (HaveNever)
        NetUserDel(NULL, Never);
    if (HaveEmpty)
        NetUserDel(NULL, Empty);
    if (HaveWithPw)
        NetUserDel(NULL, WithPw);
}
