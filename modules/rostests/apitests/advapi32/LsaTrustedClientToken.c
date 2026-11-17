/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The authentication port decides whether a client is trusted (it holds SeTcbPrivilege) by the identity of
 *              the connecting thread: the token it impersonates, the token of its process only for a thread that
 *              impersonates nobody. A thread token the LSA cannot open (it impersonates at the anonymous level, or its
 *              DACL denies SYSTEM) must not make the process token decide.
 *              The rows run in a service of LocalSystem (a process that holds SeTcbPrivilege) whose threads impersonate
 *              a plain user. A trusted logon process gets an impersonation token from an S4U logon, any other client an
 *              identification token: that is what shows the decision of the port.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * "LsaTrustedClientToken probe" prints the statuses of LsaRegisterLogonProcess and LsaConnectUntrusted for the cases of
 * the token of the calling process (no user is created, nothing is changed) for a run on Windows.
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>
#include <sddl.h>

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

/* The public layout of NTSecAPI.h */
#define S4U_MESSAGE_TYPE 12
typedef struct
{
    ULONG MessageType;
    ULONG Flags;
    UNICODE_STRING UserPrincipalName;
    UNICODE_STRING DomainName;
} S4U_LOGON;

typedef enum
{
    CASE_NONE,          /* the thread impersonates nobody: judged by its process (the service: trusted) */
    CASE_USER,          /* it impersonates a plain user: not trusted */
    CASE_USER_ANON,     /* ... at the anonymous level: the LSA cannot open that token */
    CASE_USER_NODACL,   /* ... with a token whose DACL denies SYSTEM: the LSA cannot open that token either */
    CASE_COUNT
} CASE;

static const char *const CaseNames[CASE_COUNT] =
{
    "no impersonation",
    "user token",
    "user token at the anonymous level",
    "user token that denies SYSTEM"
};

enum { VIA_REGISTER, VIA_CONNECT, VIA_COUNT };
static const char *const ViaNames[VIA_COUNT] = { "LsaRegisterLogonProcess", "LsaConnectUntrusted" };

typedef struct
{
    BOOL Failed;                /* the case could not be set up */
    NTSTATUS Status[VIA_COUNT]; /* of the connection */
    LONG Level[VIA_COUNT];      /* impersonation level of the token of an S4U logon (0: none made, -1: it failed) */
} RESULT;

/*
 * THE EXPECTED VALUES (the only place): for the thread of a trusted (SeTcbPrivilege) process in each case, the status
 * of LsaRegisterLogonProcess and LsaConnectUntrusted and the impersonation level of the token that an S4U logon over
 * that connection returns (SecurityImpersonation = 2 for a trusted logon process, SecurityIdentification = 1 for any other
 * client). They are the design of this test: the identity that counts is the one of the thread, an identity that cannot
 * be read is not trusted.
 *
 * VERIFY ON ORACLE: what Windows returns for CASE_USER_ANON and CASE_USER_NODACL (all four values of each row) is not
 * known. In CASE_USER and CASE_USER_NODACL Windows may refuse LsaRegisterLogonProcess (the status below is what ReactOS
 * answers for a client without SeTcbPrivilege), only the level column is the decision of the port.
 */
static const struct
{
    NTSTATUS Status[VIA_COUNT];
    LONG Level[VIA_COUNT];
} Expected[CASE_COUNT] =
{
    /* CASE_NONE        */ { { STATUS_SUCCESS, STATUS_SUCCESS }, { 2, 1 } },
    /* CASE_USER        */ { { STATUS_SUCCESS, STATUS_SUCCESS }, { 1, 1 } },
    /* CASE_USER_ANON   */ { { STATUS_PRIVILEGE_NOT_HELD, STATUS_PRIVILEGE_NOT_HELD }, { 0, 0 } },  /* VERIFY ON ORACLE */
    /* CASE_USER_NODACL */ { { STATUS_SUCCESS, STATUS_SUCCESS }, { 1, 1 } },                        /* VERIFY ON ORACLE */
};

#define USER_NAME   L"lsatrusted1"
#define USER_PASS   L"Lsa#Trusted1pw"

static BOOL LoadLsa(void)
{
    HMODULE Sspicli = LoadLibraryW(L"sspicli.dll");

    if (!Sspicli)
        return FALSE;
    pLsaConnectUntrusted = (LSACONNECTUNTRUSTED)GetProcAddress(Sspicli, "LsaConnectUntrusted");
    pLsaRegisterLogonProcess = (LSAREGISTERLOGONPROCESS)GetProcAddress(Sspicli, "LsaRegisterLogonProcess");
    pLsaDeregisterLogonProcess = (LSADEREGISTERLOGONPROCESS)GetProcAddress(Sspicli, "LsaDeregisterLogonProcess");
    pLsaLookupAuthenticationPackage = (LSALOOKUPAUTHENTICATIONPACKAGE)GetProcAddress(Sspicli, "LsaLookupAuthenticationPackage");
    pLsaLogonUser = (LSALOGONUSER)GetProcAddress(Sspicli, "LsaLogonUser");
    pLsaFreeReturnBuffer = (LSAFREERETURNBUFFER)GetProcAddress(Sspicli, "LsaFreeReturnBuffer");
    return pLsaConnectUntrusted && pLsaRegisterLogonProcess && pLsaDeregisterLogonProcess &&
           pLsaLookupAuthenticationPackage && pLsaLogonUser && pLsaFreeReturnBuffer;
}

/* The impersonation level of the token of an S4U logon of the test user over the connection; -1: the logon failed */
static LONG S4ULevel(HANDLE Lsa)
{
    static WCHAR Computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD Size = _countof(Computer), Length;
    LSA_STRING PackageName, Origin;
    ULONG Package;
    S4U_LOGON *Logon;
    TOKEN_SOURCE Source;
    QUOTA_LIMITS Quotas;
    PVOID Profile = NULL;
    ULONG ProfileLength = 0;
    LUID LogonId;
    HANDLE Token = NULL;
    NTSTATUS Status, SubStatus;
    SECURITY_IMPERSONATION_LEVEL Level;
    ULONG UserBytes = (ULONG)wcslen(USER_NAME) * sizeof(WCHAR), DomainBytes;
    LONG Ret = -1;
    PBYTE Strings;

    GetComputerNameW(Computer, &Size);
    DomainBytes = (ULONG)wcslen(Computer) * sizeof(WCHAR);
    RtlInitString((PSTRING)&PackageName, MSV1_0_PACKAGE_NAME);
    if (pLsaLookupAuthenticationPackage(Lsa, &PackageName, &Package) != STATUS_SUCCESS)
        return -1;

    Logon = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Logon) + UserBytes + DomainBytes);
    Strings = (PBYTE)(Logon + 1);
    Logon->MessageType = S4U_MESSAGE_TYPE;
    CopyMemory(Strings, USER_NAME, UserBytes);
    Logon->UserPrincipalName.Length = Logon->UserPrincipalName.MaximumLength = (USHORT)UserBytes;
    Logon->UserPrincipalName.Buffer = (PWSTR)Strings;
    CopyMemory(Strings + UserBytes, Computer, DomainBytes);
    Logon->DomainName.Length = Logon->DomainName.MaximumLength = (USHORT)DomainBytes;
    Logon->DomainName.Buffer = (PWSTR)(Strings + UserBytes);

    ZeroMemory(&Source, sizeof(Source));
    CopyMemory(Source.SourceName, "TrustTst", 8);
    AllocateLocallyUniqueId(&Source.SourceIdentifier);
    Origin.Buffer = (PCHAR)"TrustTest";
    Origin.Length = 9;
    Origin.MaximumLength = 10;

    Status = pLsaLogonUser(Lsa, &Origin, Network, Package, Logon, sizeof(*Logon) + UserBytes + DomainBytes, NULL,
                           &Source, &Profile, &ProfileLength, &LogonId, &Token, &Quotas, &SubStatus);
    if (Status == STATUS_SUCCESS && GetTokenInformation(Token, TokenImpersonationLevel, &Level, sizeof(Level), &Length))
        Ret = (LONG)Level;
    if (Profile)
        pLsaFreeReturnBuffer(Profile);
    if (Token)
        CloseHandle(Token);
    HeapFree(GetProcessHeap(), 0, Logon);
    return Ret;
}

/* One connection of the calling thread; WithLogon: also the S4U logon of the test user */
static void TrySession(int Via, BOOL WithLogon, NTSTATUS *Status, LONG *Level)
{
    LSA_STRING Name;
    LSA_OPERATIONAL_MODE Mode;
    HANDLE Lsa = NULL;

    *Level = 0;
    if (Via == VIA_REGISTER)
    {
        RtlInitString((PSTRING)&Name, "LsaTrustedClientTokenProcess");
        *Status = pLsaRegisterLogonProcess(&Name, &Lsa, &Mode);
    }
    else
    {
        *Status = pLsaConnectUntrusted(&Lsa);
    }
    if (*Status != STATUS_SUCCESS)
        return;
    if (WithLogon)
        *Level = S4ULevel(Lsa);
    pLsaDeregisterLogonProcess(Lsa);
}

/* The token the thread impersonates in a case (NULL: none, or the setup failed: *Failed) */
static HANDLE MakeToken(CASE Case, HANDLE Base, BOOL *Failed)
{
    HANDLE Token = NULL;
    PSECURITY_DESCRIPTOR Sd = NULL;
    SECURITY_IMPERSONATION_LEVEL Level = SecurityImpersonation;

    *Failed = FALSE;
    if (Case == CASE_NONE)
        return NULL;
    if (Case == CASE_USER_ANON)
        Level = SecurityAnonymous;
    if (!DuplicateTokenEx(Base, TOKEN_ALL_ACCESS, NULL, Level, TokenImpersonation, &Token))
    {
        *Failed = TRUE;
        return NULL;
    }
    if (Case == CASE_USER_NODACL)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(D;;GA;;;SY)(A;;GA;;;WD)(A;;GA;;;BA)",
                                                                  SDDL_REVISION_1, &Sd, NULL) ||
            !SetKernelObjectSecurity(Token, DACL_SECURITY_INFORMATION, Sd))
        {
            *Failed = TRUE;
            CloseHandle(Token);
            Token = NULL;
        }
        if (Sd)
            LocalFree(Sd);
    }
    return Token;
}

/* Runs the cases on the calling thread; Base is the token whose copies the thread impersonates */
static void RunCases(HANDLE Base, BOOL WithLogon, RESULT Results[CASE_COUNT])
{
    int i, via;

    for (i = 0; i < CASE_COUNT; i++)
    {
        HANDLE Token = MakeToken(i, Base, &Results[i].Failed);

        for (via = 0; via < VIA_COUNT; via++)
        {
            Results[i].Status[via] = STATUS_UNSUCCESSFUL;
            Results[i].Level[via] = 0;
        }
        if (Results[i].Failed)
            continue;
        if (Token && !SetThreadToken(NULL, Token))
        {
            Results[i].Failed = TRUE;
            CloseHandle(Token);
            continue;
        }
        for (via = 0; via < VIA_COUNT; via++)
            TrySession(via, WithLogon, &Results[i].Status[via], &Results[i].Level[via]);
        if (Token)
        {
            SetThreadToken(NULL, NULL);
            CloseHandle(Token);
        }
    }
}

static BOOL HasTcb(void)
{
    HANDLE Token;
    BYTE Buffer[2048];
    DWORD Length, i;
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;
    LUID Tcb;
    BOOL Ret = FALSE;

    LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &Tcb);
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    if (GetTokenInformation(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Length))
    {
        for (i = 0; i < Privileges->PrivilegeCount; i++)
        {
            if (Privileges->Privileges[i].Luid.LowPart == Tcb.LowPart &&
                Privileges->Privileges[i].Luid.HighPart == Tcb.HighPart)
                Ret = TRUE;
        }
    }
    CloseHandle(Token);
    return Ret;
}

/* The service side: a process of LocalSystem. The result goes into a file, one line per case */
static WCHAR ServiceName[64];
static WCHAR ResultFile[MAX_PATH];
static SERVICE_STATUS_HANDLE StatusHandle;

static void ServiceWork(void)
{
    USER_INFO_1 Info;
    DWORD Err;
    HANDLE Logon = NULL, File;
    RESULT Results[CASE_COUNT];
    char Line[160];
    DWORD Written;
    int i;

    NetUserDel(NULL, USER_NAME);
    memset(&Info, 0, sizeof(Info));
    Info.usri1_name = (LPWSTR)USER_NAME;
    Info.usri1_password = (LPWSTR)USER_PASS;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;

    File = CreateFileW(ResultFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return;

    if (!LoadLsa())
        WriteFile(File, "NOLSA\r\n", 7, &Written, NULL);
    else if (!HasTcb())
        WriteFile(File, "NOTCB\r\n", 7, &Written, NULL);
    else if (NetUserAdd(NULL, 1, (LPBYTE)&Info, &Err) != NERR_Success)
        WriteFile(File, "NOUSER\r\n", 8, &Written, NULL);
    else
    {
        if (!LogonUserW((LPWSTR)USER_NAME, L".", (LPWSTR)USER_PASS, LOGON32_LOGON_INTERACTIVE,
                        LOGON32_PROVIDER_DEFAULT, &Logon))
        {
            WriteFile(File, "NOLOGON\r\n", 9, &Written, NULL);
        }
        else
        {
            RunCases(Logon, TRUE, Results);
            for (i = 0; i < CASE_COUNT; i++)
            {
                _snprintf(Line, sizeof(Line), "%d %d 0x%08lx %ld 0x%08lx %ld\r\n", i, Results[i].Failed,
                          (ULONG)Results[i].Status[VIA_REGISTER], Results[i].Level[VIA_REGISTER],
                          (ULONG)Results[i].Status[VIA_CONNECT], Results[i].Level[VIA_CONNECT]);
                WriteFile(File, Line, (DWORD)strlen(Line), &Written, NULL);
            }
            CloseHandle(Logon);
        }
        NetUserDel(NULL, USER_NAME);
    }
    CloseHandle(File);
}

static void ReportState(DWORD State)
{
    SERVICE_STATUS Status;

    RtlZeroMemory(&Status, sizeof(Status));
    Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    Status.dwCurrentState = State;
    Status.dwControlsAccepted = (State == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    Status.dwWaitHint = (State == SERVICE_RUNNING || State == SERVICE_STOPPED) ? 0 : 5000;
    SetServiceStatus(StatusHandle, &Status);
}

static DWORD WINAPI ServiceHandler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    return NO_ERROR;
}

static VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
    StatusHandle = RegisterServiceCtrlHandlerExW(ServiceName, ServiceHandler, NULL);
    if (!StatusHandle)
        return;
    ReportState(SERVICE_RUNNING);
    ServiceWork();
    ReportState(SERVICE_STOPPED);
}

static void ServiceProcess(PCSTR Name, PCSTR File)
{
    SERVICE_TABLE_ENTRYW Table[2];

    MultiByteToWideChar(CP_ACP, 0, Name, -1, ServiceName, _countof(ServiceName));
    MultiByteToWideChar(CP_ACP, 0, File, -1, ResultFile, _countof(ResultFile));
    Table[0].lpServiceName = ServiceName;
    Table[0].lpServiceProc = ServiceMain;
    Table[1].lpServiceName = NULL;
    Table[1].lpServiceProc = NULL;
    StartServiceCtrlDispatcherW(Table);
}

/* "probe": the cases of the token of this process; nothing is created. For a run on Windows (as SYSTEM). */
static void Probe(void)
{
    HANDLE Token;
    RESULT Results[CASE_COUNT];
    int i;

    if (!LoadLsa() || !OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
    {
        printf("PROBE setup failed\n");
        return;
    }
    printf("PROBE process holds SeTcbPrivilege: %d\n", HasTcb());
    RunCases(Token, FALSE, Results);
    for (i = 0; i < CASE_COUNT; i++)
    {
        printf("PROBE %-36s setup_failed=%d LsaRegisterLogonProcess=0x%08lx LsaConnectUntrusted=0x%08lx\n",
               CaseNames[i], Results[i].Failed, (ULONG)Results[i].Status[VIA_REGISTER],
               (ULONG)Results[i].Status[VIA_CONNECT]);
    }
    CloseHandle(Token);
}

static BOOL WaitStopped(SC_HANDLE hService)
{
    SERVICE_STATUS_PROCESS Status;
    DWORD Needed, Waited;

    for (Waited = 0; Waited <= 60000; Waited += 200)
    {
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status, sizeof(Status), &Needed) &&
            Status.dwCurrentState == SERVICE_STOPPED)
            return TRUE;
        Sleep(200);
    }
    return FALSE;
}

START_TEST(LsaTrustedClientToken)
{
    CHAR FileName[MAX_PATH], Command[2 * MAX_PATH + 128], Name[64], Result[MAX_PATH], Temp[MAX_PATH];
    WCHAR CommandW[2 * MAX_PATH + 128], NameW[64];
    SC_HANDLE hScm, hService;
    HANDLE File;
    char Text[1024];
    DWORD Read = 0;
    int argc, i;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "service"))
    {
        ServiceProcess(argv[3], argv[4]);
        return;
    }
    if (argc >= 3 && !strcmp(argv[2], "probe"))
    {
        Probe();
        return;
    }

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm)
    {
        skip("OpenSCManager failed with %lu\n", GetLastError());
        return;
    }

    GetModuleFileNameA(NULL, FileName, _countof(FileName));
    GetTempPathA(_countof(Temp), Temp);
    StringCbPrintfA(Name, sizeof(Name), "RosLsaTrust%lu", GetTickCount());
    StringCbPrintfA(Result, sizeof(Result), "%s%s.txt", Temp, Name);
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" LsaTrustedClientToken service %s \"%s\"", FileName, Name, Result);
    MultiByteToWideChar(CP_ACP, 0, Command, -1, CommandW, _countof(CommandW));
    MultiByteToWideChar(CP_ACP, 0, Name, -1, NameW, _countof(NameW));

    DeleteFileA(Result);
    hService = CreateServiceW(hScm, NameW, NameW, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                              SERVICE_ERROR_IGNORE, CommandW, NULL, NULL, NULL, NULL, NULL);
    if (!hService)
    {
        skip("CreateService failed with %lu\n", GetLastError());
        CloseServiceHandle(hScm);
        return;
    }

    ok(StartServiceW(hService, 0, NULL), "StartService failed with %lu\n", GetLastError());
    ok(WaitStopped(hService), "the service did not finish\n");
    DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);

    File = CreateFileA(Result, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "the service wrote no result (%lu)\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    ReadFile(File, Text, sizeof(Text) - 1, &Read, NULL);
    Text[Read] = 0;
    CloseHandle(File);
    DeleteFileA(Result);

    if (!strncmp(Text, "NO", 2))
    {
        skip("the service could not run the cases: %.8s\n", Text);
        return;
    }

    for (i = 0; i < CASE_COUNT; i++)
    {
        int Case = -1, Failed = 1, n;
        ULONG RegisterStatus = 0, ConnectStatus = 0;
        LONG RegisterLevel = 0, ConnectLevel = 0;
        const char *Line = Text;

        /* the line of the case */
        for (n = 0; n < i && Line; n++)
        {
            Line = strchr(Line, '\n');
            if (Line)
                Line++;
        }
        if (!Line || sscanf(Line, "%d %d 0x%lx %ld 0x%lx %ld", &Case, &Failed, &RegisterStatus, &RegisterLevel,
                            &ConnectStatus, &ConnectLevel) != 6 || Case != i)
        {
            ok(0, "%s: no result line\n", CaseNames[i]);
            continue;
        }
        if (Failed)
        {
            skip("%s: the case could not be set up\n", CaseNames[i]);
            continue;
        }
        ok(RegisterStatus == (ULONG)Expected[i].Status[VIA_REGISTER],
           "%s: %s returned 0x%08lx, expected 0x%08lx\n", CaseNames[i], ViaNames[VIA_REGISTER], RegisterStatus,
           (ULONG)Expected[i].Status[VIA_REGISTER]);
        ok(RegisterLevel == Expected[i].Level[VIA_REGISTER],
           "%s: the S4U token over %s has the impersonation level %ld, expected %ld\n", CaseNames[i],
           ViaNames[VIA_REGISTER], RegisterLevel, Expected[i].Level[VIA_REGISTER]);
        ok(ConnectStatus == (ULONG)Expected[i].Status[VIA_CONNECT],
           "%s: %s returned 0x%08lx, expected 0x%08lx\n", CaseNames[i], ViaNames[VIA_CONNECT], ConnectStatus,
           (ULONG)Expected[i].Status[VIA_CONNECT]);
        ok(ConnectLevel == Expected[i].Level[VIA_CONNECT],
           "%s: the S4U token over %s has the impersonation level %ld, expected %ld\n", CaseNames[i],
           ViaNames[VIA_CONNECT], ConnectLevel, Expected[i].Level[VIA_CONNECT]);
    }
}
