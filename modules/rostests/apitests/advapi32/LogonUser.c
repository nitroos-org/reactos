/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for LogonUser of a new non-administrator user in several processes, and for the other
 *              LSA client calls: logon sessions, policy change notification, NetUserChangePassword
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>

#define CHILD_COUNT 20
#define CALL_TIMEOUT_MS 120000

static WCHAR TestPassword[] = L"Logon-User-Test-2026!";

typedef struct _NET_CALL
{
    BOOL Add;
    PWSTR Name;
    NET_API_STATUS Status;
} NET_CALL, *PNET_CALL;

static DWORD WINAPI NetCallThread(PVOID Param)
{
    PNET_CALL Call = Param;
    USER_INFO_1 Info;
    DWORD Err;

    if (!Call->Add)
    {
        Call->Status = NetUserDel(NULL, Call->Name);
        return 0;
    }
    ZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = Call->Name;
    Info.usri1_password = TestPassword;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    Call->Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    return 0;
}

/* A SAM call that does not return is a failure, not a hang of the test.
 * Call must outlive a thread that does not return, so callers keep it static. */
static BOOL TimedNetCall(PNET_CALL Call)
{
    HANDLE Thread;
    DWORD Wait;

    Thread = CreateThread(NULL, 0, NetCallThread, Call, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!Thread)
        return FALSE;
    Wait = WaitForSingleObject(Thread, CALL_TIMEOUT_MS);
    CloseHandle(Thread);
    ok(Wait == WAIT_OBJECT_0, "%s(%ls) did not return: %lu\n", Call->Add ? "NetUserAdd" : "NetUserDel", Call->Name, Wait);
    return Wait == WAIT_OBJECT_0;
}

static BOOL CreateTestUser(PWSTR Name, SIZE_T NameLength)
{
    static NET_CALL Call;
    DWORD Try;

    for (Try = 0; Try < 5; Try++)
    {
        StringCchPrintfW(Name, NameLength, L"lgtest%lx", (GetTickCount() + Try * 7919) & 0xffffff);
        Call.Add = TRUE;
        Call.Name = Name;
        if (!TimedNetCall(&Call))
            return FALSE;
        if (Call.Status == NERR_Success)
            return TRUE;
        if (Call.Status != NERR_UserExists)
            break;
    }
    if (Call.Status == ERROR_ACCESS_DENIED)
    {
        skip("NetUserAdd needs an elevated administrator\n");
        return FALSE;
    }
    ok(0, "NetUserAdd(%ls) failed: %lu\n", Name, Call.Status);
    return FALSE;
}

static BOOL IsMember(HANDLE Token, WELL_KNOWN_SID_TYPE Type)
{
    UCHAR Sid[SECURITY_MAX_SID_SIZE];
    DWORD Size = sizeof(Sid);
    BOOL Member = FALSE;

    if (!CreateWellKnownSid(Type, NULL, Sid, &Size))
    {
        ok(0, "CreateWellKnownSid(%d) failed: %lu\n", Type, GetLastError());
        return FALSE;
    }
    if (!CheckTokenMembership(Token, Sid, &Member))
    {
        ok(0, "CheckTokenMembership(%d) failed: %lu\n", Type, GetLastError());
        return FALSE;
    }
    return Member;
}

/* Logs the user on, runs as it and checks the token. */
static VOID LogonAndCheck(PWSTR User)
{
    WCHAR Name[64], Domain[64];
    UCHAR Buffer[256];
    HANDLE Token, Ident, Thread;
    DWORD Length, DomainLength;
    SID_NAME_USE Use;
    BOOL Ok;

    Ok = LogonUserW(User, L".", TestPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token);
    ok(Ok, "LogonUserW(%ls) failed: %lu\n", User, GetLastError());
    if (!Ok)
        return;

    /* The groups, checked on an identification copy of the token. */
    Ok = DuplicateToken(Token, SecurityIdentification, &Ident);
    ok(Ok, "DuplicateToken failed: %lu\n", GetLastError());
    if (Ok)
    {
        ok(!IsMember(Ident, WinBuiltinAdministratorsSid), "The new user is an administrator\n");
        ok(IsMember(Ident, WinBuiltinUsersSid), "The new user is not in the Users group\n");
        ok(IsMember(Ident, WinInteractiveSid), "The token has no INTERACTIVE group\n");
        CloseHandle(Ident);
    }

    Ok = ImpersonateLoggedOnUser(Token);
    ok(Ok, "ImpersonateLoggedOnUser failed: %lu\n", GetLastError());
    if (Ok)
    {
        Ok = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &Thread);
        ok(Ok, "OpenThreadToken failed: %lu\n", GetLastError());
        RevertToSelf();
        if (Ok)
        {
            Ok = GetTokenInformation(Thread, TokenUser, Buffer, sizeof(Buffer), &Length);
            ok(Ok, "GetTokenInformation failed: %lu\n", GetLastError());
            CloseHandle(Thread);
        }
        if (Ok)
        {
            Length = RTL_NUMBER_OF(Name);
            DomainLength = RTL_NUMBER_OF(Domain);
            Ok = LookupAccountSidW(NULL, ((PTOKEN_USER)Buffer)->User.Sid, Name, &Length, Domain, &DomainLength, &Use);
            ok(Ok, "LookupAccountSidW failed: %lu\n", GetLastError());
            if (Ok)
            {
                ok(!_wcsicmp(Name, User), "Impersonated %ls, expected %ls\n", Name, User);
                ok(Use == SidTypeUser, "SID type %d\n", Use);
            }
        }
    }
    CloseHandle(Token);
}

/* A wrong password is refused with ERROR_LOGON_FAILURE and gives no token */
static VOID WrongPassword(PWSTR User)
{
    WCHAR Wrong[] = L"Not-The-Password-2026!";
    HANDLE Token = (HANDLE)(ULONG_PTR)0xdeadbeef;
    BOOL Ok;

    SetLastError(0xdeadbeef);
    Ok = LogonUserW(User, L".", Wrong, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token);
    ok(!Ok, "LogonUserW(%ls) with a wrong password succeeded\n", User);
    ok(GetLastError() == ERROR_LOGON_FAILURE, "LogonUserW with a wrong password: error %lu\n", GetLastError());
    ok(Token == NULL, "LogonUserW with a wrong password returned the token %p\n", Token);
    if (Ok && Token)
        CloseHandle(Token);
}

typedef NTSTATUS (NTAPI *LSA_CONNECT)(PHANDLE);
typedef NTSTATUS (NTAPI *LSA_LOOKUP)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS (NTAPI *LSA_CALL)(HANDLE, ULONG, PVOID, ULONG, PVOID *, PULONG, PNTSTATUS);
typedef NTSTATUS (NTAPI *LSA_CLOSE)(PVOID);

/* LsaCallAuthenticationPackage carries package specific buffers that may hold pointers. The WoW64 layer
 * translates MsV1_0ChangePassword only (NetUserChangePassword); any other message type, such as this
 * challenge request, gets STATUS_NOT_SUPPORTED in a 32-bit process, which Windows 10 also returns there.
 * A known gap. */
static VOID CallAuthenticationPackage(VOID)
{
    HMODULE Secur32 = LoadLibraryW(L"secur32.dll");
    LSA_CONNECT Connect = Secur32 ? (LSA_CONNECT)GetProcAddress(Secur32, "LsaConnectUntrusted") : NULL;
    LSA_LOOKUP Lookup = Secur32 ? (LSA_LOOKUP)GetProcAddress(Secur32, "LsaLookupAuthenticationPackage") : NULL;
    LSA_CALL Call = Secur32 ? (LSA_CALL)GetProcAddress(Secur32, "LsaCallAuthenticationPackage") : NULL;
    LSA_CLOSE Deregister = Secur32 ? (LSA_CLOSE)GetProcAddress(Secur32, "LsaDeregisterLogonProcess") : NULL;
    LSA_CLOSE FreeBuffer = Secur32 ? (LSA_CLOSE)GetProcAddress(Secur32, "LsaFreeReturnBuffer") : NULL;
    MSV1_0_PROTOCOL_MESSAGE_TYPE Submit;
    LSA_STRING Name;
    HANDLE Lsa;
    ULONG Package, Length = 0;
    PVOID Buffer = NULL;
    NTSTATUS Status, ProtocolStatus = 0;
    BOOL Wow = FALSE;

    if (!Connect || !Lookup || !Call || !Deregister || !FreeBuffer)
    {
        skip("secur32 has no LSA client functions\n");
        return;
    }
    Status = Connect(&Lsa);
    if (!NT_SUCCESS(Status))
    {
        skip("LsaConnectUntrusted failed: %08lx\n", Status);
        return;
    }
    RtlInitString((PSTRING)&Name, MSV1_0_PACKAGE_NAME);
    Status = Lookup(Lsa, &Name, &Package);
    ok(Status == STATUS_SUCCESS, "LsaLookupAuthenticationPackage returned %08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        Submit = MsV1_0Lm20ChallengeRequest;
        Status = Call(Lsa, Package, &Submit, sizeof(Submit), &Buffer, &Length, &ProtocolStatus);
        IsWow64Process(GetCurrentProcess(), &Wow);
        if (Wow)
            ok(Status == STATUS_NOT_SUPPORTED, "LsaCallAuthenticationPackage in WoW64 returned %08lx\n", Status);
        else
            trace("LsaCallAuthenticationPackage returned %08lx\n", Status);
        if (NT_SUCCESS(Status) && Buffer)
            FreeBuffer(Buffer);
    }
    Deregister(Lsa);
}

static VOID ChildLogon(PCSTR UserA)
{
    WCHAR User[32];

    MultiByteToWideChar(CP_ACP, 0, UserA, -1, User, RTL_NUMBER_OF(User));
    LogonAndCheck(User);
    WrongPassword(User);
    CallAuthenticationPackage();
}

START_TEST(LogonUser)
{
    static WCHAR User[32];
    CHAR UserA[32], CommandLine[MAX_PATH + 64];
    STARTUPINFOA Si;
    PROCESS_INFORMATION Pi;
    static NET_CALL Call;
    DWORD Wait, Code, i;
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3)
    {
        ChildLogon(argv[2]);
        return;
    }

    if (!CreateTestUser(User, RTL_NUMBER_OF(User)))
        return;
    WideCharToMultiByte(CP_ACP, 0, User, -1, UserA, sizeof(UserA), NULL, NULL);

    /* One process after another, each logging the new user on and exiting.
     * Each logon follows the exit of the previous process. The test process
     * itself does not log on, so its own exit cannot wait for the LSA. */
    for (i = 0; i < CHILD_COUNT; i++)
    {
        StringCchPrintfA(CommandLine, RTL_NUMBER_OF(CommandLine), "\"%s\" LogonUser %s", argv[0], UserA);
        ZeroMemory(&Si, sizeof(Si));
        Si.cb = sizeof(Si);
        if (!CreateProcessA(NULL, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
        {
            ok(0, "CreateProcessA failed: %lu\n", GetLastError());
            break;
        }
        CloseHandle(Pi.hThread);
        Wait = WaitForSingleObject(Pi.hProcess, CALL_TIMEOUT_MS);
        ok(Wait == WAIT_OBJECT_0, "Process %lu did not finish: %lu\n", i + 1, Wait);
        if (Wait != WAIT_OBJECT_0)
        {
            TerminateProcess(Pi.hProcess, 1);
            CloseHandle(Pi.hProcess);
            break;
        }
        if (!GetExitCodeProcess(Pi.hProcess, &Code))
            Code = MAXDWORD;
        ok(Code == 0, "Process %lu: exit code %lu\n", i + 1, Code);
        CloseHandle(Pi.hProcess);
    }

    Call.Add = FALSE;
    Call.Name = User;
    if (TimedNetCall(&Call))
        ok(Call.Status == NERR_Success, "NetUserDel(%ls) failed: %lu\n", User, Call.Status);
}


/* LsaGetLogonSessionData, LsaEnumerateLogonSessions and the policy change notification, which a 32-bit
 * process reaches through the WoW64 translation of the LSA port. */
typedef NTSTATUS (NTAPI *LSA_ENUM_SESSIONS)(PULONG, PLUID *);
typedef NTSTATUS (NTAPI *LSA_GET_SESSION)(PLUID, PSECURITY_LOGON_SESSION_DATA *);
typedef NTSTATUS (NTAPI *LSA_POLICY_NOTIFY)(POLICY_NOTIFICATION_INFORMATION_CLASS, HANDLE);

static FARPROC GetLsaProc(PCSTR Name)
{
    FARPROC Proc = NULL;
    HMODULE Module = LoadLibraryW(L"secur32.dll");

    if (Module)
        Proc = GetProcAddress(Module, Name);
    if (!Proc)
    {
        Module = LoadLibraryW(L"advapi32.dll");
        if (Module)
            Proc = GetProcAddress(Module, Name);
    }
    return Proc;
}

static BOOL StringInBlock(PCUNICODE_STRING String, PVOID Block)
{
    PWCHAR Chars = String->Buffer;
    ULONG i;

    if (!String->MaximumLength)
        return String->Length == 0;
    if (String->Length > String->MaximumLength || !Chars)
        return FALSE;
    for (i = 0; i < String->Length / sizeof(WCHAR); i++)
        if (Chars[i] == UNICODE_NULL)
            return FALSE;
    return (ULONG_PTR)Chars > (ULONG_PTR)Block;
}

static VOID CheckSessionData(PLUID LogonId, LSA_GET_SESSION GetSession, LSA_CLOSE FreeBuffer, BOOL Trace)
{
    PSECURITY_LOGON_SESSION_DATA Data = NULL;
    NTSTATUS Status;

    Status = GetSession(LogonId, &Data);
    ok(Status == STATUS_SUCCESS, "LsaGetLogonSessionData(%lx:%lx) returned %08lx\n", LogonId->HighPart, LogonId->LowPart, Status);
    if (!NT_SUCCESS(Status) || !Data)
        return;
    ok(Data->Size == sizeof(*Data), "Size is %lu, expected %lu\n", Data->Size, (ULONG)sizeof(*Data));
    ok(Data->LogonId.LowPart == LogonId->LowPart && Data->LogonId.HighPart == LogonId->HighPart, "LogonId %lx:%lx\n",
       Data->LogonId.HighPart, Data->LogonId.LowPart);
    ok(StringInBlock(&Data->UserName, Data), "UserName %p %u/%u\n", Data->UserName.Buffer, Data->UserName.Length, Data->UserName.MaximumLength);
    ok(StringInBlock(&Data->LogonDomain, Data), "LogonDomain %p\n", Data->LogonDomain.Buffer);
    ok(StringInBlock(&Data->AuthenticationPackage, Data), "AuthenticationPackage %p\n", Data->AuthenticationPackage.Buffer);
    ok(StringInBlock(&Data->LogonServer, Data), "LogonServer %p\n", Data->LogonServer.Buffer);
    ok(StringInBlock(&Data->DnsDomainName, Data), "DnsDomainName %p\n", Data->DnsDomainName.Buffer);
    ok(StringInBlock(&Data->Upn, Data), "Upn %p\n", Data->Upn.Buffer);
    ok(!Data->Sid || (IsValidSid(Data->Sid) && (ULONG_PTR)Data->Sid > (ULONG_PTR)Data), "Sid %p\n", Data->Sid);
    if (Trace)
        trace("session %lx:%lx user '%.*ls' domain '%.*ls' package '%.*ls' type %lu session %lu sid %s server '%.*ls'\n",
              LogonId->HighPart, LogonId->LowPart,
              Data->UserName.Length / 2, Data->UserName.Buffer ? Data->UserName.Buffer : L"",
              Data->LogonDomain.Length / 2, Data->LogonDomain.Buffer ? Data->LogonDomain.Buffer : L"",
              Data->AuthenticationPackage.Length / 2, Data->AuthenticationPackage.Buffer ? Data->AuthenticationPackage.Buffer : L"",
              Data->LogonType, Data->Session, Data->Sid ? "yes" : "no",
              Data->LogonServer.Length / 2, Data->LogonServer.Buffer ? Data->LogonServer.Buffer : L"");
    FreeBuffer(Data);
}

START_TEST(LsaLogonSession)
{
    LSA_ENUM_SESSIONS Enum = (LSA_ENUM_SESSIONS)GetLsaProc("LsaEnumerateLogonSessions");
    LSA_GET_SESSION GetSession = (LSA_GET_SESSION)GetLsaProc("LsaGetLogonSessionData");
    LSA_CLOSE FreeBuffer = (LSA_CLOSE)GetLsaProc("LsaFreeReturnBuffer");
    LSA_POLICY_NOTIFY Register = (LSA_POLICY_NOTIFY)GetLsaProc("LsaRegisterPolicyChangeNotification");
    LSA_POLICY_NOTIFY Unregister = (LSA_POLICY_NOTIFY)GetLsaProc("LsaUnregisterPolicyChangeNotification");
    TOKEN_STATISTICS Statistics;
    HANDLE Token, Event;
    PLUID Sessions = NULL;
    ULONG Count = 0, Length, i;
    NTSTATUS Status;
    BOOL FoundOwn = FALSE;
    LUID Bad = { 0xdead, 0x7eef };
    PSECURITY_LOGON_SESSION_DATA Data = NULL;

    if (!Enum || !GetSession || !FreeBuffer)
    {
        skip("The LSA logon session functions are missing\n");
        return;
    }

    Status = Enum(&Count, &Sessions);
    ok(Status == STATUS_SUCCESS, "LsaEnumerateLogonSessions returned %08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        ok(Count > 0 && Sessions != NULL, "%lu sessions, list %p\n", Count, Sessions);
        ok(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token), "OpenProcessToken failed\n");
        ok(GetTokenInformation(Token, TokenStatistics, &Statistics, sizeof(Statistics), &Length),
           "GetTokenInformation failed: %lu\n", GetLastError());
        for (i = 0; Sessions && i < Count; i++)
        {
            if (Sessions[i].LowPart == Statistics.AuthenticationId.LowPart &&
                Sessions[i].HighPart == Statistics.AuthenticationId.HighPart)
                FoundOwn = TRUE;
            CheckSessionData(&Sessions[i], GetSession, FreeBuffer, TRUE);
        }
        ok(FoundOwn, "The session %lx:%lx of this process is not listed\n", Statistics.AuthenticationId.HighPart,
           Statistics.AuthenticationId.LowPart);
        CloseHandle(Token);
        if (Sessions)
            FreeBuffer(Sessions);
    }

    Status = GetSession(&Bad, &Data);
    ok(Status == STATUS_NO_SUCH_LOGON_SESSION, "LsaGetLogonSessionData of a bad LUID returned %08lx\n", Status);

    if (!Register || !Unregister)
    {
        skip("The policy change notification functions are missing\n");
        return;
    }
    Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    Status = Register(PolicyNotifyAuditEventsInformation, Event);
    ok(Status == STATUS_SUCCESS, "LsaRegisterPolicyChangeNotification returned %08lx\n", Status);
    Status = Unregister(PolicyNotifyAuditEventsInformation, Event);
    ok(Status == STATUS_SUCCESS, "LsaUnregisterPolicyChangeNotification returned %08lx\n", Status);
    Status = Unregister(PolicyNotifyAuditEventsInformation, Event);
    trace("a second LsaUnregisterPolicyChangeNotification returned %08lx\n", Status);
    CloseHandle(Event);
}

static WCHAR NewPassword[] = L"Logon-User-New-2026!";
static WCHAR BadOldPassword[] = L"Logon-User-Wrong-2026!";

/*
 * MsV1_0ChangePassword with an old password that is not right. Measured on Windows 10 22H2, a
 * 64-bit and a 32-bit process alike: the call returns STATUS_SUCCESS and the protocol status is
 * STATUS_WRONG_PASSWORD (it is the same for an account that does not exist). ReactOS changed
 * nothing but answered STATUS_SUCCESS for both.
 */
static VOID ChangePasswordPackage(PCWSTR Computer, PCWSTR User)
{
    HMODULE Secur32 = LoadLibraryW(L"secur32.dll");
    LSA_CONNECT Connect = Secur32 ? (LSA_CONNECT)GetProcAddress(Secur32, "LsaConnectUntrusted") : NULL;
    LSA_LOOKUP Lookup = Secur32 ? (LSA_LOOKUP)GetProcAddress(Secur32, "LsaLookupAuthenticationPackage") : NULL;
    LSA_CALL Call = Secur32 ? (LSA_CALL)GetProcAddress(Secur32, "LsaCallAuthenticationPackage") : NULL;
    LSA_CLOSE Deregister = Secur32 ? (LSA_CLOSE)GetProcAddress(Secur32, "LsaDeregisterLogonProcess") : NULL;
    LSA_CLOSE FreeBuffer = Secur32 ? (LSA_CLOSE)GetProcAddress(Secur32, "LsaFreeReturnBuffer") : NULL;
    PMSV1_0_CHANGEPASSWORD_REQUEST Request;
    UCHAR RequestBuffer[sizeof(MSV1_0_CHANGEPASSWORD_REQUEST) + 4 * 64 * sizeof(WCHAR)];
    PWSTR Next;
    LSA_STRING Name;
    HANDLE Lsa;
    ULONG Package, Length = 0;
    PVOID Buffer = NULL;
    NTSTATUS Status, ProtocolStatus;

    if (!Connect || !Lookup || !Call || !Deregister || !FreeBuffer)
    {
        skip("secur32 has no LSA client functions\n");
        return;
    }
    Status = Connect(&Lsa);
    ok(Status == STATUS_SUCCESS, "LsaConnectUntrusted returned %08lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;
    RtlInitString((PSTRING)&Name, MSV1_0_PACKAGE_NAME);
    Status = Lookup(Lsa, &Name, &Package);
    ok(Status == STATUS_SUCCESS, "LsaLookupAuthenticationPackage returned %08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        ZeroMemory(RequestBuffer, sizeof(RequestBuffer));
        Request = (PMSV1_0_CHANGEPASSWORD_REQUEST)RequestBuffer;
        Request->MessageType = MsV1_0ChangePassword;
        Request->Impersonating = TRUE;
        Next = (PWSTR)(Request + 1);
#define PACK_STRING(Field, Text) \
        do { \
            StringCchCopyW(Next, 64, Text); \
            RtlInitUnicodeString(&Request->Field, Next); \
            Next += 64; \
        } while (0)
        PACK_STRING(DomainName, Computer);
        PACK_STRING(AccountName, User);
        PACK_STRING(OldPassword, BadOldPassword);
        PACK_STRING(NewPassword, NewPassword);
#undef PACK_STRING
        ProtocolStatus = 0x12345678;
        Status = Call(Lsa, Package, Request, sizeof(RequestBuffer), &Buffer, &Length, &ProtocolStatus);
        ok(Status == STATUS_SUCCESS, "MsV1_0ChangePassword(wrong old password) returned %08lx\n", Status);
        ok(ProtocolStatus == STATUS_WRONG_PASSWORD, "MsV1_0ChangePassword(wrong old password): protocol status %08lx\n",
           ProtocolStatus);
        if (Buffer)
            FreeBuffer(Buffer);
        SecureZeroMemory(RequestBuffer, sizeof(RequestBuffer));
    }
    Deregister(Lsa);
}

static VOID ChildChangePassword(PCSTR UserA)
{
    WCHAR User[32], Computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD Size = RTL_NUMBER_OF(Computer);
    HANDLE Token;
    NET_API_STATUS Status;
    BOOL Ok;

    MultiByteToWideChar(CP_ACP, 0, UserA, -1, User, RTL_NUMBER_OF(User));
    ok(GetComputerNameW(Computer, &Size), "GetComputerNameW failed\n");

    /* A wrong old password is refused and changes nothing; an unknown account gets the same answer */
    Status = NetUserChangePassword(Computer, User, BadOldPassword, NewPassword);
    ok(Status == ERROR_INVALID_PASSWORD, "NetUserChangePassword(wrong old password) returned %lu\n", Status);
    Status = NetUserChangePassword(Computer, L"logon-user-no-such-1", BadOldPassword, NewPassword);
    ok(Status == ERROR_INVALID_PASSWORD, "NetUserChangePassword(unknown account) returned %lu\n", Status);
    ChangePasswordPackage(Computer, User);
    Token = NULL;
    Ok = LogonUserW(User, L".", TestPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token);
    ok(Ok, "LogonUserW with the unchanged password failed: %lu\n", GetLastError());
    if (Ok)
        CloseHandle(Token);

    Status = NetUserChangePassword(Computer, User, TestPassword, NewPassword);
    ok(Status == NERR_Success, "NetUserChangePassword returned %lu\n", Status);
    if (Status != NERR_Success)
        return;

    Token = NULL;
    Ok = LogonUserW(User, L".", NewPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token);
    ok(Ok, "LogonUserW with the new password failed: %lu\n", GetLastError());
    if (Ok)
        CloseHandle(Token);
    SetLastError(0xdeadbeef);
    Ok = LogonUserW(User, L".", TestPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token);
    ok(!Ok, "LogonUserW with the old password succeeded\n");
    ok(GetLastError() == ERROR_LOGON_FAILURE, "LogonUserW with the old password: error %lu\n", GetLastError());
    if (Ok)
        CloseHandle(Token);
}

START_TEST(NetUserChangePassword)
{
    static WCHAR User[32];
    CHAR UserA[32], CommandLine[MAX_PATH + 64];
    STARTUPINFOA Si;
    PROCESS_INFORMATION Pi;
    static NET_CALL Call;
    DWORD Wait, Code;
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3)
    {
        ChildChangePassword(argv[2]);
        return;
    }

    if (!CreateTestUser(User, RTL_NUMBER_OF(User)))
        return;
    WideCharToMultiByte(CP_ACP, 0, User, -1, UserA, sizeof(UserA), NULL, NULL);

    /* In a process of its own, as for LogonUser */
    StringCchPrintfA(CommandLine, RTL_NUMBER_OF(CommandLine), "\"%s\" NetUserChangePassword %s", argv[0], UserA);
    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    if (CreateProcessA(NULL, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
    {
        CloseHandle(Pi.hThread);
        Wait = WaitForSingleObject(Pi.hProcess, CALL_TIMEOUT_MS);
        ok(Wait == WAIT_OBJECT_0, "The child did not finish: %lu\n", Wait);
        if (Wait != WAIT_OBJECT_0)
            TerminateProcess(Pi.hProcess, 1);
        else if (GetExitCodeProcess(Pi.hProcess, &Code))
            ok(Code == 0, "The child's exit code is %lu\n", Code);
        CloseHandle(Pi.hProcess);
    }
    else
        ok(0, "CreateProcessA failed: %lu\n", GetLastError());

    Call.Add = FALSE;
    Call.Name = User;
    if (TimedNetCall(&Call))
        ok(Call.Status == NERR_Success, "NetUserDel(%ls) failed: %lu\n", User, Call.Status);
}
