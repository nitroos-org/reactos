/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Account lockout: NetUserModalsSet/Get level 3, the bad password count, the locked state and its end.
 *              Measured on Windows Server 2022 (10.0.20348) with threshold 3, observation window 60 s, duration
 *              120 s, on scratch accounts (rows marked "rule" follow [MS-SAMR] 3.1.5.13.7.1 with short times):
 *              - a wrong password counts for LogonUser INTERACTIVE, NETWORK, BATCH, SERVICE, UNLOCK and
 *                NETWORK_CLEARTEXT, the empty password of an account with a password too, a wrong old password
 *                of NetUserChangePassword (86) too; NEW_CREDENTIALS does not; any successful logon sets it to 0;
 *              - the third wrong password locks: usri3_flags has UF_LOCKOUT, usri3_bad_pw_count 3; then every
 *                logon, the right password too, gives 1909, LsaLogonUser STATUS_ACCOUNT_LOCKED_OUT, the count
 *                stays; NetUserChangePassword with the right old password 1909; an unknown user still 1326;
 *              - a standard user reads UF_LOCKOUT and the count of another user but cannot clear UF_LOCKOUT (5),
 *                not even his own, and cannot set the policy (5);
 *              - an administrator's level 1008 write without UF_LOCKOUT unlocks and the count is 0; a write
 *                that keeps UF_LOCKOUT keeps the lock; setting UF_LOCKOUT does not lock;
 *              - NetUserModalsSet level 3: a duration shorter than the window is 87 with parm_err 10;
 *                TIMEQ_FOREVER as the duration keeps the account locked until an administrator unlocks it;
 *              - the built-in Administrator counts and shows UF_LOCKOUT, but its logons are not refused.
 *              - the opt-in policy "Allow Administrator account lockout" (KB5020282, here Lsa\AllowAdministratorLockout,
 *                default off) locks it out for the network logons only (documented, not measurable on this build).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <sspi.h>

#define NT_STATUS_ACCOUNT_LOCKED_OUT ((NTSTATUS)0xC0000234)
#define NT_STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006D)
#define NT_STATUS_SUCCESS ((NTSTATUS)0x00000000)

static WCHAR UserPassword[] = L"Lockout-Test-2026!a";
static WCHAR OtherPassword[] = L"Lockout-Test-2026!b";
static WCHAR NewPassword[] = L"Lockout-Test-2026!c";
static WCHAR WrongPassword[] = L"Not-The-Password-7";

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

/* LsaLogonUser through an untrusted connection; the substatus of the last call in LastSubStatus */
static NTSTATUS LastSubStatus;

static NTSTATUS LsaLogon(PCWSTR User, PCWSTR Password)
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
    NTSTATUS Status, SubStatus;

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

    Origin.Buffer = (PCHAR)"Lockout";
    Origin.Length = 7;
    Origin.MaximumLength = 8;
    memcpy(Source.SourceName, "Lockout ", 8);
    AllocateLocallyUniqueId(&Source.SourceIdentifier);

    Status = pLsaLogonUser(Lsa, &Origin, Interactive, PackageId, Buffer, Size, NULL, &Source,
                           &Profile, &ProfileLength, &LogonId, &Token, &Quotas, &SubStatus);
    LastSubStatus = SubStatus;
    if (Profile)
        pLsaFreeReturnBuffer(Profile);
    if (Token)
        CloseHandle(Token);
    HeapFree(GetProcessHeap(), 0, Buffer);
    pLsaDeregisterLogonProcess(Lsa);
    return Status;
}

/* An NTLM exchange on this machine with explicit credentials (the network logon of the NTLM server of secur32):
   the status of the last AcceptSecurityContext */
static PSecurityFunctionTableW Sspi;

static SECURITY_STATUS NtlmLogon(PCWSTR User, PCWSTR Password)
{
    SEC_WINNT_AUTH_IDENTITY_W Identity;
    CredHandle Client, Server;
    CtxtHandle ClientCtx, ServerCtx;
    BOOL HaveClient = FALSE, HaveServer = FALSE;
    BYTE In[4096], Out[4096];
    SecBuffer InBuf, OutBuf;
    SecBufferDesc InDesc, OutDesc;
    SECURITY_STATUS ClientStatus, ServerStatus = SEC_E_INTERNAL_ERROR;
    TimeStamp Expiry;
    ULONG Attributes, Round;

    if (!Sspi)
        return SEC_E_INTERNAL_ERROR;

    ZeroMemory(&Identity, sizeof(Identity));
    Identity.User = (unsigned short *)User;
    Identity.UserLength = (ULONG)wcslen(User);
    Identity.Domain = (unsigned short *)L".";
    Identity.DomainLength = 1;
    Identity.Password = (unsigned short *)Password;
    Identity.PasswordLength = (ULONG)wcslen(Password);
    Identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    if (Sspi->AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, &Identity, NULL, NULL,
                                        &Client, &Expiry) != SEC_E_OK)
        return SEC_E_INTERNAL_ERROR;
    if (Sspi->AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL,
                                        &Server, &Expiry) != SEC_E_OK)
    {
        Sspi->FreeCredentialsHandle(&Client);
        return SEC_E_INTERNAL_ERROR;
    }

    InDesc.ulVersion = OutDesc.ulVersion = SECBUFFER_VERSION;
    InDesc.cBuffers = OutDesc.cBuffers = 1;
    InDesc.pBuffers = &InBuf;
    OutDesc.pBuffers = &OutBuf;
    InBuf.BufferType = OutBuf.BufferType = SECBUFFER_TOKEN;
    InBuf.cbBuffer = 0;
    InBuf.pvBuffer = In;

    for (Round = 0; Round < 3; Round++)
    {
        OutBuf.cbBuffer = sizeof(Out);
        OutBuf.pvBuffer = Out;
        ClientStatus = Sspi->InitializeSecurityContextW(&Client, HaveClient ? &ClientCtx : NULL, (SEC_WCHAR *)L"localhost",
                                                        ISC_REQ_CONNECTION, 0, SECURITY_NATIVE_DREP,
                                                        HaveClient ? &InDesc : NULL, 0, &ClientCtx, &OutDesc,
                                                        &Attributes, &Expiry);
        HaveClient = TRUE;
        if (ClientStatus != SEC_E_OK && ClientStatus != SEC_I_CONTINUE_NEEDED)
            break;
        if (OutBuf.cbBuffer == 0)
            break;

        memcpy(In, Out, OutBuf.cbBuffer);
        InBuf.cbBuffer = OutBuf.cbBuffer;
        OutBuf.cbBuffer = sizeof(Out);
        OutBuf.pvBuffer = Out;
        ServerStatus = Sspi->AcceptSecurityContext(&Server, HaveServer ? &ServerCtx : NULL, &InDesc, ASC_REQ_CONNECTION,
                                                   SECURITY_NATIVE_DREP, &ServerCtx, &OutDesc, &Attributes, &Expiry);
        HaveServer = TRUE;
        if (ServerStatus != SEC_I_CONTINUE_NEEDED)
            break;
        memcpy(In, Out, OutBuf.cbBuffer);
        InBuf.cbBuffer = OutBuf.cbBuffer;
    }

    if (HaveClient)
        Sspi->DeleteSecurityContext(&ClientCtx);
    if (HaveServer)
        Sspi->DeleteSecurityContext(&ServerCtx);
    Sspi->FreeCredentialsHandle(&Client);
    Sspi->FreeCredentialsHandle(&Server);
    return ServerStatus;
}

/* usri3_flags and usri3_bad_pw_count */
static BOOL State(PCWSTR User, PDWORD Locked, PDWORD Count)
{
    USER_INFO_3 *Info = NULL;

    *Locked = *Count = 0xdeadbeef;
    if (NetUserGetInfo(NULL, User, 3, (PBYTE *)&Info) != NERR_Success)
        return FALSE;
    *Locked = (Info->usri3_flags & UF_LOCKOUT) ? 1 : 0;
    *Count = Info->usri3_bad_pw_count;
    NetApiBufferFree(Info);
    return TRUE;
}

#define ok_state(User, ExpLocked, ExpCount) \
    do { DWORD l_, c_; State(User, &l_, &c_); \
         ok(l_ == (ExpLocked), "line %d: %ls locked %lu, expected %u\n", __LINE__, User, l_, (ExpLocked)); \
         ok(c_ == (ExpCount), "line %d: %ls bad password count %lu, expected %u\n", __LINE__, User, c_, (ExpCount)); } while (0)

static NET_API_STATUS SetLockFlag(PCWSTR User, BOOL Keep)
{
    USER_INFO_1 *Info = NULL;
    USER_INFO_1008 Flags;
    DWORD Error = 0;
    NET_API_STATUS Status = NetUserGetInfo(NULL, User, 1, (PBYTE *)&Info);

    if (Status != NERR_Success)
        return Status;
    Flags.usri1008_flags = Keep ? (Info->usri1_flags | UF_LOCKOUT) : (Info->usri1_flags & ~UF_LOCKOUT);
    NetApiBufferFree(Info);
    return NetUserSetInfo(NULL, User, 1008, (PBYTE)&Flags, &Error);
}

static NET_API_STATUS SetPolicy(DWORD Duration, DWORD Window, DWORD Threshold, PDWORD ParmErr)
{
    USER_MODALS_INFO_3 Info;

    Info.usrmod3_lockout_duration = Duration;
    Info.usrmod3_lockout_observation_window = Window;
    Info.usrmod3_lockout_threshold = Threshold;
    *ParmErr = 0xdeadbeef;
    return NetUserModalsSet(NULL, 3, (PBYTE)&Info, ParmErr);
}

static BOOL AddUser(PCWSTR Name, PWSTR Password)
{
    USER_INFO_1 Info;
    DWORD Error = 0;
    NET_API_STATUS Status;

    ZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = (PWSTR)Name;
    Info.usri1_password = Password;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Error);
    ok(Status == NERR_Success, "NetUserAdd(%ls) failed: %lu\n", Name, Status);
    return Status == NERR_Success;
}

/* What counts: one wrong attempt, the count is 1, a right logon, the count is 0 */
static void TestCounting(PCWSTR User)
{
    static const DWORD Types[] = { LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK, LOGON32_LOGON_BATCH,
                                   LOGON32_LOGON_SERVICE, LOGON32_LOGON_UNLOCK, LOGON32_LOGON_NETWORK_CLEARTEXT };
    ULONG i;

    ok_state(User, 0, 0);
    for (i = 0; i < RTL_NUMBER_OF(Types); i++)
    {
        ok_dec(Logon(User, WrongPassword, Types[i]), ERROR_LOGON_FAILURE);
        ok_state(User, 0, 1);
        ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
        ok_state(User, 0, 0);
    }

    /* the empty password of an account with a password is a wrong password */
    ok_dec(Logon(User, L"", LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_state(User, 0, 1);
    /* a successful network logon resets the count too */
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_NETWORK), ERROR_SUCCESS);
    ok_state(User, 0, 0);

    /* the network logon of the NTLM server (secur32) counts and resets like the others */
    ok_hex(NtlmLogon(User, WrongPassword), SEC_E_LOGON_DENIED);
    ok_state(User, 0, 1);
    ok_hex(NtlmLogon(User, UserPassword), SEC_E_OK);
    ok_state(User, 0, 0);

    /* LsaLogonUser: a wrong password and an unknown account look the same, substatus included (measured) */
    ok_hex(LsaLogon(User, WrongPassword), NT_STATUS_LOGON_FAILURE);
    ok_hex(LastSubStatus, NT_STATUS_SUCCESS);
    ok_state(User, 0, 1);
    ok_hex(LsaLogon(L"nosuchuser9z", WrongPassword), NT_STATUS_LOGON_FAILURE);
    ok_hex(LastSubStatus, NT_STATUS_SUCCESS);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
    ok_state(User, 0, 0);

    /* NEW_CREDENTIALS does not check the password */
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_NEW_CREDENTIALS), ERROR_SUCCESS);
    ok_state(User, 0, 0);

    /* a wrong old password of a password change */
    ok_dec(NetUserChangePassword(NULL, User, WrongPassword, NewPassword), ERROR_INVALID_PASSWORD);
    ok_state(User, 0, 1);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
    ok_state(User, 0, 0);
}

static void LockIt(PCWSTR User)
{
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_NETWORK), ERROR_LOGON_FAILURE);
    /* the attempt that reaches the threshold still reports the wrong password */
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_state(User, 1, 3);
}

static void TestLocked(PCWSTR User, PCWSTR Other)
{
    HANDLE Token = NULL;
    DWORD ParmErr;
    NTSTATUS Status;

    LockIt(User);

    /* every logon is refused, the right password too, and nothing more is counted */
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_ACCOUNT_LOCKED_OUT);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_NETWORK), ERROR_ACCOUNT_LOCKED_OUT);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_NETWORK_CLEARTEXT), ERROR_ACCOUNT_LOCKED_OUT);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_UNLOCK), ERROR_ACCOUNT_LOCKED_OUT);
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_ACCOUNT_LOCKED_OUT);
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_NETWORK), ERROR_ACCOUNT_LOCKED_OUT);
    ok_dec(Logon(User, L"", LOGON32_LOGON_INTERACTIVE), ERROR_ACCOUNT_LOCKED_OUT);
    Status = LsaLogon(User, UserPassword);
    ok(Status == NT_STATUS_ACCOUNT_LOCKED_OUT, "LsaLogonUser of the locked account: 0x%08lx\n", Status);
    ok_hex(LastSubStatus, NT_STATUS_SUCCESS);
    ok_dec(NetUserChangePassword(NULL, User, UserPassword, NewPassword), ERROR_ACCOUNT_LOCKED_OUT);
    ok_hex(NtlmLogon(User, UserPassword), SEC_E_LOGON_DENIED);
    ok_hex(NtlmLogon(User, WrongPassword), SEC_E_LOGON_DENIED);
    ok_state(User, 1, 3);

    /* an account that does not exist still gives the wrong-password error */
    ok_dec(Logon(L"nosuchuser9z", WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);

    /* a standard user sees the lock and the count but cannot clear it or change the policy */
    if (LogonUserW((LPWSTR)Other, (LPWSTR)L".", OtherPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        ok(ImpersonateLoggedOnUser(Token), "ImpersonateLoggedOnUser failed: %lu\n", GetLastError());
        ok_state(User, 1, 3);
        ok_dec(SetLockFlag(User, FALSE), ERROR_ACCESS_DENIED);
        ok_dec(SetLockFlag(Other, FALSE), ERROR_ACCESS_DENIED);
        ok_dec(SetPolicy(1800, 1800, 0, &ParmErr), ERROR_ACCESS_DENIED);
        RevertToSelf();
        CloseHandle(Token);
    }
    else
    {
        ok(0, "logon of the second user failed: %lu\n", GetLastError());
    }
    ok_state(User, 1, 3);

    /* an administrator's write that keeps UF_LOCKOUT keeps the lock */
    ok_dec(SetLockFlag(User, TRUE), NERR_Success);
    ok_state(User, 1, 3);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_ACCOUNT_LOCKED_OUT);

    /* clearing UF_LOCKOUT unlocks, the count is 0 */
    ok_dec(SetLockFlag(User, FALSE), NERR_Success);
    ok_state(User, 0, 0);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);

    /* setting UF_LOCKOUT does not lock */
    ok_dec(SetLockFlag(User, TRUE), NERR_Success);
    ok_state(User, 0, 0);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
}

/* Short windows and durations: the [MS-SAMR] rules ("rule" rows) */
static void TestTimes(PCWSTR User)
{
    DWORD ParmErr;

    /* the count starts again after the observation window */
    ok_dec(SetPolicy(4, 2, 3, &ParmErr), NERR_Success);
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_state(User, 0, 2);
    Sleep(3000);
    ok_state(User, 0, 0);
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_state(User, 0, 1);

    /* the lock ends by itself after the duration */
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_dec(Logon(User, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_state(User, 1, 3);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_ACCOUNT_LOCKED_OUT);
    Sleep(5000);
    ok_state(User, 0, 0);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);

    /* TIMEQ_FOREVER: locked until an administrator unlocks */
    ok_dec(SetPolicy(TIMEQ_FOREVER, 2, 3, &ParmErr), NERR_Success);
    LockIt(User);
    Sleep(5000);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_ACCOUNT_LOCKED_OUT);
    {
        DWORD Locked, Count;
        State(User, &Locked, &Count);
        ok(Locked == 1, "TIMEQ_FOREVER: the lock ended by itself\n");
    }
    ok_dec(SetLockFlag(User, FALSE), NERR_Success);
    ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
}

static void TestPolicyValues(void)
{
    USER_MODALS_INFO_3 *Info = NULL;
    DWORD ParmErr;

    ok_dec(SetPolicy(60, 120, 3, &ParmErr), ERROR_INVALID_PARAMETER);
    ok_dec(ParmErr, MODALS_LOCKOUT_DURATION_PARMNUM);
    ok_dec(SetPolicy(0, 60, 3, &ParmErr), ERROR_INVALID_PARAMETER);
    ok_dec(ParmErr, MODALS_LOCKOUT_DURATION_PARMNUM);
    ok_dec(SetPolicy(120, 0, 3, &ParmErr), NERR_Success);
    ok_dec(SetPolicy(120, 60, 1000, &ParmErr), NERR_Success);
    ok_dec(SetPolicy(TIMEQ_FOREVER, 60, 3, &ParmErr), NERR_Success);
    if (NetUserModalsGet(NULL, 3, (PBYTE *)&Info) == NERR_Success)
    {
        ok_dec(Info->usrmod3_lockout_duration, TIMEQ_FOREVER);
        ok_dec(Info->usrmod3_lockout_observation_window, 60);
        ok_dec(Info->usrmod3_lockout_threshold, 3);
        NetApiBufferFree(Info);
    }
    else
    {
        ok(0, "NetUserModalsGet level 3 failed\n");
    }
}

/* The name of the built-in Administrator (RID 500) of this machine */
static BOOL GetAdministratorName(PWSTR Name, DWORD NameChars)
{
    PPOLICY_ACCOUNT_DOMAIN_INFO DomainInfo = NULL;
    LSA_OBJECT_ATTRIBUTES Attributes = { sizeof(Attributes) };
    LSA_HANDLE Policy = NULL;
    BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
    PSID Sid = (PSID)SidBuffer;
    WCHAR Domain[256];
    DWORD DomainLength = RTL_NUMBER_OF(Domain);
    SID_NAME_USE Use;
    UCHAR SubCount;

    if (LsaOpenPolicy(NULL, &Attributes, POLICY_VIEW_LOCAL_INFORMATION, &Policy) != NT_STATUS_SUCCESS)
    {
        skip("LsaOpenPolicy failed\n");
        return FALSE;
    }
    if (LsaQueryInformationPolicy(Policy, PolicyAccountDomainInformation, (PVOID *)&DomainInfo) != NT_STATUS_SUCCESS)
    {
        LsaClose(Policy);
        skip("no account domain\n");
        return FALSE;
    }
    SubCount = *GetSidSubAuthorityCount(DomainInfo->DomainSid);
    CopySid(sizeof(SidBuffer), Sid, DomainInfo->DomainSid);
    *GetSidSubAuthorityCount(Sid) = SubCount + 1;
    *GetSidSubAuthority(Sid, SubCount) = DOMAIN_USER_RID_ADMIN;
    LsaFreeMemory(DomainInfo);
    LsaClose(Policy);
    if (!LookupAccountSidW(NULL, Sid, Name, &NameChars, Domain, &DomainLength, &Use))
    {
        skip("LookupAccountSid of RID 500 failed: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

/* The built-in Administrator (RID 500) counts and shows UF_LOCKOUT but is not locked out */
static void TestAdministrator(void)
{
    WCHAR Name[256];
    DWORD Locked, Count, ParmErr, i;

    if (!GetAdministratorName(Name, RTL_NUMBER_OF(Name)))
        return;

    ok_dec(SetPolicy(120, 60, 3, &ParmErr), NERR_Success);
    for (i = 0; i < 4; i++)
        ok_dec(Logon(Name, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    State(Name, &Locked, &Count);
    ok(Locked == 1, "Administrator: UF_LOCKOUT not shown (%lu)\n", Locked);
    ok(Count == 4, "Administrator: count %lu, expected 4\n", Count);
    /* still only the wrong password, not the lock, refuses it */
    ok_dec(Logon(Name, WrongPassword, LOGON32_LOGON_NETWORK), ERROR_LOGON_FAILURE);

    /* a right logon is not refused: with a blank-password Administrator only with the policy off */
    {
        HKEY Key;
        DWORD Old = 1, Size = sizeof(Old), Type, Zero = 0, Error;
        BOOL Had = FALSE;

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0,
                          KEY_QUERY_VALUE | KEY_SET_VALUE, &Key) == ERROR_SUCCESS)
        {
            Had = RegQueryValueExW(Key, L"LimitBlankPasswordUse", NULL, &Type, (PBYTE)&Old, &Size) == ERROR_SUCCESS;
            RegSetValueExW(Key, L"LimitBlankPasswordUse", 0, REG_DWORD, (const BYTE *)&Zero, sizeof(Zero));
            Error = Logon(Name, L"", LOGON32_LOGON_INTERACTIVE);
            if (Error == ERROR_SUCCESS)
            {
                ok_state(Name, 0, 0);
            }
            else
            {
                ok(Error == ERROR_LOGON_FAILURE, "Administrator with the empty password: %lu (1909 = locked out)\n", Error);
                skip("the Administrator has a password: the right-password row is not run\n");
            }
            if (Had)
                RegSetValueExW(Key, L"LimitBlankPasswordUse", 0, REG_DWORD, (const BYTE *)&Old, sizeof(Old));
            else
                RegDeleteValueW(Key, L"LimitBlankPasswordUse");
            RegCloseKey(Key);
        }
    }
    SetLockFlag(Name, FALSE);
}

/* The opt-in policy "Allow Administrator account lockout" (KB5020282; here HKLM\SYSTEM\CurrentControlSet\Control\Lsa
   AllowAdministratorLockout, default off). KB5020282: with it on the built-in Administrator is locked out for network
   logons ("such as RDP attempts") and console logons stay possible. The rows run with the policy value on and off; the
   Administrator's own blank password is used (LimitBlankPasswordUse 0 for the duration of the test), no row is run when
   it has a password. */
static void LockAdministrator(PCWSTR Name)
{
    ok_dec(Logon(Name, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_dec(Logon(Name, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_dec(Logon(Name, WrongPassword, LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);
    ok_state(Name, 1, 3);
}

static void SaveLsaDword(HKEY Key, PCWSTR Value, PBOOL Had, PDWORD Old)
{
    DWORD Size = sizeof(*Old), Type;

    *Old = 0;
    *Had = RegQueryValueExW(Key, Value, NULL, &Type, (PBYTE)Old, &Size) == ERROR_SUCCESS && Type == REG_DWORD;
}

static void SetLsaDword(HKEY Key, PCWSTR Value, DWORD Data)
{
    ok_dec(RegSetValueExW(Key, Value, 0, REG_DWORD, (const BYTE *)&Data, sizeof(Data)), ERROR_SUCCESS);
}

static void RestoreLsaDword(HKEY Key, PCWSTR Value, BOOL Had, DWORD Old)
{
    if (Had)
        RegSetValueExW(Key, Value, 0, REG_DWORD, (const BYTE *)&Old, sizeof(Old));
    else
        RegDeleteValueW(Key, Value);
}

static void TestAdministratorPolicy(void)
{
    static const PCWSTR Policy = L"AllowAdministratorLockout";
    static const PCWSTR Limit = L"LimitBlankPasswordUse";
    WCHAR Name[256];
    HKEY Key;
    BOOL HadLimit, HadPolicy;
    DWORD OldLimit, OldPolicy, ParmErr;
    NTSTATUS Status;

    if (!GetAdministratorName(Name, RTL_NUMBER_OF(Name)))
        return;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0,
                      KEY_QUERY_VALUE | KEY_SET_VALUE, &Key) != ERROR_SUCCESS)
    {
        skip("cannot open the Lsa key for writing\n");
        return;
    }
    SaveLsaDword(Key, Limit, &HadLimit, &OldLimit);
    SaveLsaDword(Key, Policy, &HadPolicy, &OldPolicy);
    SetLsaDword(Key, Limit, 0);
    SetLsaDword(Key, Policy, 0);

    if (Logon(Name, L"", LOGON32_LOGON_INTERACTIVE) != ERROR_SUCCESS)
    {
        skip("the Administrator has a password: the policy rows are not run\n");
        goto done;
    }

    ok_dec(SetPolicy(120, 60, 3, &ParmErr), NERR_Success);

    /* policy off: not locked for any logon (the rows of TestAdministrator) */
    LockAdministrator(Name);
    ok_dec(Logon(Name, L"", LOGON32_LOGON_NETWORK), ERROR_SUCCESS);
    ok_state(Name, 0, 0);

    /* policy on: locked for the network logons, the right password as well, nothing more is counted */
    SetLsaDword(Key, Policy, 1);
    LockAdministrator(Name);
    ok_dec(Logon(Name, L"", LOGON32_LOGON_NETWORK), ERROR_ACCOUNT_LOCKED_OUT);
    ok_dec(Logon(Name, L"", LOGON32_LOGON_NETWORK_CLEARTEXT), ERROR_ACCOUNT_LOCKED_OUT);
    ok_dec(Logon(Name, WrongPassword, LOGON32_LOGON_NETWORK), ERROR_ACCOUNT_LOCKED_OUT);
    ok_state(Name, 1, 3);

    /* the console logons are not refused (KB5020282), and the one that succeeds clears the flag and the count, as
       every successful logon of the Administrator did before */
    ok_dec(Logon(Name, L"", LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
    ok_state(Name, 0, 0);
    LockAdministrator(Name);
    ok_dec(Logon(Name, L"", LOGON32_LOGON_UNLOCK), ERROR_SUCCESS);
    ok_state(Name, 0, 0);
    LockAdministrator(Name);
    Status = LsaLogon(Name, L"");
    ok(Status == NT_STATUS_SUCCESS, "LsaLogonUser (interactive) of the locked Administrator: 0x%08lx\n", Status);
    ok_state(Name, 0, 0);

    /* an administrator's write without UF_LOCKOUT unlocks it as it does any account */
    LockAdministrator(Name);
    ok_dec(SetLockFlag(Name, FALSE), NERR_Success);
    ok_state(Name, 0, 0);
    ok_dec(Logon(Name, L"", LOGON32_LOGON_NETWORK), ERROR_SUCCESS);

    /* the lock ends by itself after the duration */
    ok_dec(SetPolicy(4, 2, 3, &ParmErr), NERR_Success);
    LockAdministrator(Name);
    ok_dec(Logon(Name, L"", LOGON32_LOGON_NETWORK), ERROR_ACCOUNT_LOCKED_OUT);
    Sleep(5000);
    ok_state(Name, 0, 0);
    ok_dec(Logon(Name, L"", LOGON32_LOGON_NETWORK), ERROR_SUCCESS);

    /* back to off: the same state of the account is not refused any more */
    ok_dec(SetPolicy(120, 60, 3, &ParmErr), NERR_Success);
    LockAdministrator(Name);
    SetLsaDword(Key, Policy, 0);
    ok_dec(Logon(Name, L"", LOGON32_LOGON_NETWORK), ERROR_SUCCESS);
    ok_state(Name, 0, 0);

    /* a value that is not 0 counts as on */
    SetLsaDword(Key, Policy, 7);
    LockAdministrator(Name);
    ok_dec(Logon(Name, L"", LOGON32_LOGON_NETWORK), ERROR_ACCOUNT_LOCKED_OUT);
    SetLsaDword(Key, Policy, 0);
    ok_dec(Logon(Name, L"", LOGON32_LOGON_NETWORK), ERROR_SUCCESS);

done:
    SetLockFlag(Name, FALSE);
    RestoreLsaDword(Key, Limit, HadLimit, OldLimit);
    RestoreLsaDword(Key, Policy, HadPolicy, OldPolicy);
    RegCloseKey(Key);
}

/* "net accounts /maxpwage:unlimited": NetUserModalsSet level 0 with TIMEQ_FOREVER. It reads back as TIMEQ_FOREVER and
   the passwords do not expire ([MS-SAMR] 3.1.5.14.4: "never" for a maximum age that does not end) */
static void TestMaxPasswordAgeUnlimited(PCWSTR User)
{
    USER_MODALS_INFO_0 *Saved = NULL, *Now = NULL, New;
    DWORD ParmErr = 0;
    NET_API_STATUS Status;

    Status = NetUserModalsGet(NULL, 0, (PBYTE *)&Saved);
    ok_dec(Status, NERR_Success);
    if (Status != NERR_Success)
        return;

    New = *Saved;
    New.usrmod0_max_passwd_age = TIMEQ_FOREVER;
    Status = NetUserModalsSet(NULL, 0, (PBYTE)&New, &ParmErr);
    ok_dec(Status, NERR_Success);
    if (Status == NERR_Success)
    {
        Status = NetUserModalsGet(NULL, 0, (PBYTE *)&Now);
        ok_dec(Status, NERR_Success);
        if (Status == NERR_Success)
        {
            ok_hex(Now->usrmod0_max_passwd_age, TIMEQ_FOREVER);
            NetApiBufferFree(Now);
        }

        ok_dec(Logon(User, UserPassword, LOGON32_LOGON_INTERACTIVE), ERROR_SUCCESS);
        ok_dec(Logon(User, UserPassword, LOGON32_LOGON_NETWORK), ERROR_SUCCESS);

        Status = NetUserModalsSet(NULL, 0, (PBYTE)Saved, &ParmErr);
        ok_dec(Status, NERR_Success);
    }
    NetApiBufferFree(Saved);
}

START_TEST(AccountLockout)
{
    HMODULE Secur32 = LoadLibraryW(L"secur32.dll");
    USER_MODALS_INFO_3 *Saved = NULL;
    WCHAR User[32], Other[32];
    DWORD ParmErr;
    BOOL HaveUser, HaveOther;
    ULONG Tag = GetTickCount() & 0xfffff;
    NET_API_STATUS Status;

    if (Secur32)
    {
        pLsaConnectUntrusted = (LSACONNECTUNTRUSTED)GetProcAddress(Secur32, "LsaConnectUntrusted");
        pLsaLookupAuthenticationPackage = (LSALOOKUPAUTHENTICATIONPACKAGE)GetProcAddress(Secur32, "LsaLookupAuthenticationPackage");
        pLsaLogonUser = (LSALOGONUSER)GetProcAddress(Secur32, "LsaLogonUser");
        pLsaFreeReturnBuffer = (LSAFREERETURNBUFFER)GetProcAddress(Secur32, "LsaFreeReturnBuffer");
        pLsaDeregisterLogonProcess = (LSADEREGISTERLOGONPROCESS)GetProcAddress(Secur32, "LsaDeregisterLogonProcess");
        {
            INIT_SECURITY_INTERFACE_W pInit = (INIT_SECURITY_INTERFACE_W)GetProcAddress(Secur32, "InitSecurityInterfaceW");
            if (pInit)
                Sspi = pInit();
        }
    }

    Status = NetUserModalsGet(NULL, 3, (PBYTE *)&Saved);
    ok_dec(Status, NERR_Success);
    if (Status != NERR_Success)
        return;

    /* threshold 3, window 60 s, duration 120 s, as measured */
    Status = SetPolicy(120, 60, 3, &ParmErr);
    ok_dec(Status, NERR_Success);
    if (Status != NERR_Success)
    {
        NetApiBufferFree(Saved);
        return;
    }

    StringCchPrintfW(User, RTL_NUMBER_OF(User), L"lkout%05lx", Tag);
    StringCchPrintfW(Other, RTL_NUMBER_OF(Other), L"lkoth%05lx", Tag);
    HaveUser = AddUser(User, UserPassword);
    HaveOther = AddUser(Other, OtherPassword);

    if (HaveUser)
    {
        TestCounting(User);
        if (HaveOther)
            TestLocked(User, Other);
        TestTimes(User);
        TestMaxPasswordAgeUnlimited(User);
    }
    TestPolicyValues();
    TestAdministrator();
    TestAdministratorPolicy();

    /* restore the policy */
    Status = SetPolicy(Saved->usrmod3_lockout_duration, Saved->usrmod3_lockout_observation_window,
                       Saved->usrmod3_lockout_threshold, &ParmErr);
    ok_dec(Status, NERR_Success);
    NetApiBufferFree(Saved);

    if (HaveUser)
        NetUserDel(NULL, User);
    if (HaveOther)
        NetUserDel(NULL, Other);
}
