/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     CreateProcessAsUser and NtSetInformationProcess(ProcessAccessToken) for every combination of token
 *              type, impersonation level and the handle rights TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_ASSIGN_PRIMARY
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows Server 2022 (64 and 32 bit alike), for the administrator (no
 * SeAssignPrimaryTokenPrivilege), a standard user, and a LocalSystem service with the privilege as it has it
 * (present, disabled), enabled, and removed; tokens of the caller itself and of another user.
 *
 * CreateProcessAsUser, in this order: a handle without TOKEN_ASSIGN_PRIMARY fails with ERROR_ACCESS_DENIED (also at
 * the Identification level); an impersonation token below SecurityImpersonation fails with
 * ERROR_BAD_IMPERSONATION_LEVEL; another user's token without the privilege fails with ERROR_PRIVILEGE_NOT_HELD (a
 * service that holds it disabled succeeds); then a handle without TOKEN_QUERY fails with ERROR_ACCESS_DENIED.
 * TOKEN_DUPLICATE is not needed. The process gets a new token object every time, also for a primary token that is
 * not in use, with the token's user, groups, privileges, logon session, integrity level and session.
 *
 * ProcessAccessToken on a suspended child (the kernel call alone): the primary token object itself is assigned
 * (the same token id); a primary token another process uses fails with STATUS_TOKEN_ALREADY_IN_USE, an impersonation
 * token with STATUS_BAD_TOKEN_TYPE, below SecurityImpersonation with STATUS_BAD_IMPERSONATION_LEVEL before the
 * privilege is looked at; the privilege must be enabled (STATUS_PRIVILEGE_NOT_HELD when it is only present).
 */

#include "precomp.h"
#include <lm.h>
#include <ndk/psfuncs.h>
#include <ndk/obfuncs.h>

#define CHILD_EXIT 7

/* the kinds of token and the handle rights of every row */
typedef enum { K_INUSE, K_COPY, K_IMP, K_IDENT, K_ANON, K_COUNT } KIND;
static const PCSTR KindName[K_COUNT] = { "in-use primary", "primary copy", "impersonation", "identification", "anonymous" };
#define R_QAP  (TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY)
#define R_QAPD (TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE)
#define R_QD   (TOKEN_QUERY | TOKEN_DUPLICATE)
#define R_Q    (TOKEN_QUERY)
#define R_AP   (TOKEN_ASSIGN_PRIMARY)
static const DWORD Rights[] = { R_QAP, R_QAPD, R_QD, R_Q, R_AP };
static const PCSTR RightsName[] = { "Q|AP", "Q|AP|D", "Q|D", "Q", "AP" };

/* in service mode the results go to a file and the test process reports them */
static FILE *g_Out;
static VOID Check(BOOL Ok, PCSTR Format, ...)
{
    CHAR Text[512];
    va_list Args;

    va_start(Args, Format);
    StringCbVPrintfA(Text, sizeof(Text), Format, Args);
    va_end(Args);
    if (g_Out)
        fprintf(g_Out, "CHECK %d %s\n", Ok ? 1 : 0, Text);
    else
        ok(Ok, "%s\n", Text);
}

/* The CreateProcessAsUser result Windows gives: 0 = success */
static DWORD ExpectedCreate(KIND Kind, DWORD Right, BOOL Other, BOOL Privilege)
{
    if (!(Right & TOKEN_ASSIGN_PRIMARY)) return ERROR_ACCESS_DENIED;
    if (Kind == K_IDENT || Kind == K_ANON) return ERROR_BAD_IMPERSONATION_LEVEL;
    if (Other && !Privilege) return ERROR_PRIVILEGE_NOT_HELD;
    if (!(Right & TOKEN_QUERY)) return ERROR_ACCESS_DENIED;
    return 0;
}

/* The ProcessAccessToken result Windows gives (PrivilegeEnabled: enabled at the call) */
static NTSTATUS ExpectedAssign(KIND Kind, DWORD Right, BOOL Other, BOOL PrivilegeEnabled)
{
    if (!(Right & TOKEN_ASSIGN_PRIMARY)) return STATUS_ACCESS_DENIED;
    if (Kind == K_IDENT || Kind == K_ANON) return STATUS_BAD_IMPERSONATION_LEVEL;
    if (Other && !PrivilegeEnabled) return STATUS_PRIVILEGE_NOT_HELD;
    if (Kind == K_IMP) return STATUS_BAD_TOKEN_TYPE;
    if (Kind == K_INUSE) return STATUS_TOKEN_ALREADY_IN_USE;
    return STATUS_SUCCESS;
}

static BOOL Statistics(HANDLE Token, PTOKEN_STATISTICS Stats)
{
    DWORD Length;
    return GetTokenInformation(Token, TokenStatistics, Stats, sizeof(*Stats), &Length);
}

/* A handle with exactly Right to the token Kind is made from (Process: its token is the source) */
static HANDLE MakeToken(HANDLE Process, KIND Kind, DWORD Right, PTOKEN_STATISTICS Passed)
{
    static const SECURITY_IMPERSONATION_LEVEL Level[K_COUNT] =
        { SecurityImpersonation, SecurityImpersonation, SecurityImpersonation, SecurityIdentification, SecurityAnonymous };
    HANDLE Source = NULL, Full = NULL, Narrow = NULL;

    if (Kind == K_INUSE)
    {
        if (!OpenProcessToken(Process, Right | TOKEN_QUERY, &Full))
            return NULL;
    }
    else
    {
        if (!OpenProcessToken(Process, TOKEN_DUPLICATE | TOKEN_QUERY, &Source))
            return NULL;
        if (!DuplicateTokenEx(Source, Right | TOKEN_QUERY, NULL, Level[Kind],
                              Kind == K_COPY ? TokenPrimary : TokenImpersonation, &Full))
            Full = NULL;
        CloseHandle(Source);
        if (!Full)
            return NULL;
    }
    Statistics(Full, Passed);
    if (!DuplicateHandle(GetCurrentProcess(), Full, GetCurrentProcess(), &Narrow, Right, FALSE, 0))
        Narrow = NULL;
    CloseHandle(Full);
    return Narrow;
}

static VOID CreateRow(PCSTR Caller, HANDLE Process, BOOL Other, BOOL Privilege, KIND Kind, ULONG r)
{
    WCHAR Command[] = L"cmd.exe /c exit 7";
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    TOKEN_STATISTICS Passed, Child;
    HANDLE Token, ChildToken;
    DWORD Expected = ExpectedCreate(Kind, Rights[r], Other, Privilege), Error, Exit = 0;
    BOOL Ret;

    Token = MakeToken(Process, Kind, Rights[r], &Passed);
    Check(Token != NULL, "%s, %s token, %s, %s: no token (%lu)", Caller, Other ? "another user's" : "own",
          KindName[Kind], RightsName[r], GetLastError());
    if (!Token)
        return;
    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    SetLastError(0xdeadbeef);
    Ret = CreateProcessAsUserW(Token, NULL, Command, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL,
                               NULL, &Si, &Pi);
    Error = Ret ? 0 : GetLastError();
    Check(Error == Expected, "%s, %s token, %s, %s: CreateProcessAsUser %d error %lu, expected %lu", Caller,
          Other ? "another user's" : "own", KindName[Kind], RightsName[r], Ret, Error, Expected);
    if (Ret)
    {
        /* the process has a new token object of the same logon session */
        if (OpenProcessToken(Pi.hProcess, TOKEN_QUERY, &ChildToken))
        {
            Statistics(ChildToken, &Child);
            Check(Child.TokenId.LowPart != Passed.TokenId.LowPart || Child.TokenId.HighPart != Passed.TokenId.HighPart,
                  "%s, %s token, %s, %s: the process has the token object itself", Caller,
                  Other ? "another user's" : "own", KindName[Kind], RightsName[r]);
            Check(Child.TokenType == TokenPrimary &&
                  Child.AuthenticationId.LowPart == Passed.AuthenticationId.LowPart &&
                  Child.AuthenticationId.HighPart == Passed.AuthenticationId.HighPart,
                  "%s, %s token, %s, %s: the process token has the type %d and another logon session", Caller,
                  Other ? "another user's" : "own", KindName[Kind], RightsName[r], Child.TokenType);
            CloseHandle(ChildToken);
        }
        ResumeThread(Pi.hThread);
        Check(WaitForSingleObject(Pi.hProcess, 30000) == WAIT_OBJECT_0 && GetExitCodeProcess(Pi.hProcess, &Exit) &&
              Exit == CHILD_EXIT, "%s, %s token, %s, %s: the child exited with %lu", Caller,
              Other ? "another user's" : "own", KindName[Kind], RightsName[r], Exit);
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);
    }
    CloseHandle(Token);
}

static VOID AssignRow(PCSTR Caller, HANDLE Process, BOOL Other, BOOL PrivilegeEnabled, KIND Kind, ULONG r)
{
    WCHAR Command[] = L"cmd.exe /c exit 7";
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    PROCESS_ACCESS_TOKEN Access;
    TOKEN_STATISTICS Passed, Child;
    HANDLE Token, ChildToken;
    NTSTATUS Expected = ExpectedAssign(Kind, Rights[r], Other, PrivilegeEnabled), Status;

    Token = MakeToken(Process, Kind, Rights[r], &Passed);
    if (!Token)
        return;
    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    if (!CreateProcessW(NULL, Command, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &Si, &Pi))
    {
        Check(FALSE, "%s: CreateProcess failed (%lu)", Caller, GetLastError());
        CloseHandle(Token);
        return;
    }
    Access.Token = Token;
    Access.Thread = Pi.hThread;
    Status = NtSetInformationProcess(Pi.hProcess, ProcessAccessToken, &Access, sizeof(Access));
    Check(Status == Expected, "%s, %s token, %s, %s: ProcessAccessToken 0x%lx, expected 0x%lx", Caller,
          Other ? "another user's" : "own", KindName[Kind], RightsName[r], Status, Expected);
    if (NT_SUCCESS(Status) && OpenProcessToken(Pi.hProcess, TOKEN_QUERY, &ChildToken))
    {
        /* the kernel call assigns the token object itself */
        Statistics(ChildToken, &Child);
        Check(Child.TokenId.LowPart == Passed.TokenId.LowPart && Child.TokenId.HighPart == Passed.TokenId.HighPart,
              "%s, %s token, %s, %s: ProcessAccessToken assigned another token object", Caller,
              Other ? "another user's" : "own", KindName[Kind], RightsName[r]);
        CloseHandle(ChildToken);
    }
    TerminateProcess(Pi.hProcess, 0);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    CloseHandle(Token);
}

static BOOL SetAssignPrivilege(DWORD Attributes)
{
    TOKEN_PRIVILEGES Tp;
    HANDLE Token;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
        return FALSE;
    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = Attributes;
    Ret = LookupPrivilegeValueW(NULL, L"SeAssignPrimaryTokenPrivilege", &Tp.Privileges[0].Luid) &&
          AdjustTokenPrivileges(Token, FALSE, &Tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Ret;
}

static VOID Matrix(PCSTR Caller, HANDLE Process, BOOL Other, BOOL Privilege, BOOL Create)
{
    ULONG k, r;

    for (k = 0; k < K_COUNT; k++)
        for (r = 0; r < _countof(Rights); r++)
        {
            if (Create)
                CreateRow(Caller, Process, Other, Privilege, (KIND)k, r);
            else
                AssignRow(Caller, Process, Other, Privilege, (KIND)k, r);
        }
}

/*
 * The service part (LocalSystem): the rows with the privilege as the service has it, enabled and removed, for its
 * own token and for the token of a process of another user (a suspended process it creates with that user's logon)
 */
static VOID ServiceRows(PWSTR User, PWSTR Password)
{
    WCHAR Command[] = L"cmd.exe /c exit 7";
    STARTUPINFOW Si;
    PROCESS_INFORMATION Other = { 0 };
    HANDLE Logon = NULL;

    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    if (!LogonUserW(User, L".", Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Logon) ||
        !CreateProcessAsUserW(Logon, NULL, Command, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL,
                              &Si, &Other))
    {
        Check(FALSE, "service: no process of the other user (%lu)", GetLastError());
        Other.hProcess = NULL;
    }
    if (Logon)
        CloseHandle(Logon);

    /* the privilege as LocalSystem has it: present, disabled */
    Matrix("LocalSystem", GetCurrentProcess(), FALSE, TRUE, TRUE);
    if (Other.hProcess)
    {
        Matrix("LocalSystem", Other.hProcess, TRUE, TRUE, TRUE);
        Matrix("LocalSystem, privilege disabled", Other.hProcess, TRUE, FALSE, FALSE);
        Check(SetAssignPrivilege(SE_PRIVILEGE_ENABLED), "service: the privilege was not enabled");
        Matrix("LocalSystem, privilege enabled", Other.hProcess, TRUE, TRUE, FALSE);
        Check(SetAssignPrivilege(SE_PRIVILEGE_REMOVED), "service: the privilege was not removed");
        Matrix("LocalSystem without the privilege", Other.hProcess, TRUE, FALSE, TRUE);
        Matrix("LocalSystem without the privilege", Other.hProcess, TRUE, FALSE, FALSE);
        TerminateProcess(Other.hProcess, 0);
        CloseHandle(Other.hThread);
        CloseHandle(Other.hProcess);
    }
    Matrix("LocalSystem without the privilege", GetCurrentProcess(), FALSE, FALSE, TRUE);
    Matrix("LocalSystem without the privilege", GetCurrentProcess(), FALSE, FALSE, FALSE);
}

static SERVICE_STATUS_HANDLE g_Status;
static CHAR g_Name[64], g_File[MAX_PATH];
static WCHAR g_User[32], g_Password[64];

static VOID Report(DWORD State)
{
    SERVICE_STATUS Status = { SERVICE_WIN32_OWN_PROCESS, State, 0, 0, 0, 0, 0 };
    SetServiceStatus(g_Status, &Status);
}

static DWORD WINAPI Handler(DWORD Control, DWORD Type, PVOID Data, PVOID Context)
{
    return NO_ERROR;
}

static VOID WINAPI SvcMain(DWORD argc, LPSTR *argv)
{
    g_Status = RegisterServiceCtrlHandlerExA(argv[0], Handler, NULL);
    if (!g_Status)
        return;
    Report(SERVICE_RUNNING);
    g_Out = fopen(g_File, "w");
    if (g_Out)
    {
        ServiceRows(g_User, g_Password);
        fprintf(g_Out, "END\n");
        fclose(g_Out);
        g_Out = NULL;
    }
    Report(SERVICE_STOPPED);
}

static VOID RunService(PCWSTR User, PCWSTR Password)
{
    CHAR Exe[MAX_PATH], Command[3 * MAX_PATH], Dir[MAX_PATH], File[MAX_PATH], Name[64], Line[600];
    SC_HANDLE hScm, hService;
    SERVICE_STATUS_PROCESS Status;
    DWORD Needed, Waited, Checks = 0;
    BOOL Ended = FALSE;
    FILE *f;

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm)
    {
        skip("OpenSCManager failed with %lu\n", GetLastError());
        return;
    }
    GetEnvironmentVariableA("SystemRoot", Dir, sizeof(Dir));
    StringCbCatA(Dir, sizeof(Dir), "\\Temp");
    StringCbPrintfA(Name, sizeof(Name), "RosCpauRights_%lu", GetTickCount() & 0xffff);
    StringCbPrintfA(File, sizeof(File), "%s\\%s.txt", Dir, Name);
    DeleteFileA(File);
    GetModuleFileNameA(NULL, Exe, sizeof(Exe));
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" CreateProcessAsUserRights service %s \"%s\" %S %S", Exe, Name,
                    File, User, Password);
    hService = CreateServiceA(hScm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                              SERVICE_ERROR_IGNORE, Command, NULL, NULL, NULL, NULL, NULL);
    ok(hService != NULL, "CreateService failed with %lu\n", GetLastError());
    if (hService)
    {
        ok(StartServiceA(hService, 0, NULL), "StartService failed with %lu\n", GetLastError());
        for (Waited = 0; Waited < 240000; Waited += 200)
        {
            if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status, sizeof(Status), &Needed) ||
                Status.dwCurrentState == SERVICE_STOPPED)
                break;
            Sleep(200);
        }
        f = fopen(File, "r");
        ok(f != NULL, "the service wrote no results\n");
        while (f && fgets(Line, sizeof(Line), f))
        {
            Line[strcspn(Line, "\r\n")] = 0;
            if (!strncmp(Line, "CHECK ", 6))
            {
                ok(Line[6] == '1', "%s\n", Line + 8);
                Checks++;
            }
            else if (!strcmp(Line, "END"))
                Ended = TRUE;
        }
        if (f)
            fclose(f);
        ok(Ended && Checks > 100, "the service rows ended %d after %lu checks\n", Ended, Checks);
        DeleteService(hService);
        CloseServiceHandle(hService);
    }
    DeleteFileA(File);
    CloseServiceHandle(hScm);
}

START_TEST(CreateProcessAsUserRights)
{
    WCHAR User[32], Password[64];
    USER_INFO_1 Info;
    NET_API_STATUS Status = NERR_UserExists;
    DWORD Err, Try;
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 7 && !strcmp(argv[2], "service"))
    {
        SERVICE_TABLE_ENTRYA Table[2];

        StringCbCopyA(g_Name, sizeof(g_Name), argv[3]);
        StringCbCopyA(g_File, sizeof(g_File), argv[4]);
        MultiByteToWideChar(CP_ACP, 0, argv[5], -1, g_User, _countof(g_User));
        MultiByteToWideChar(CP_ACP, 0, argv[6], -1, g_Password, _countof(g_Password));
        Table[0].lpServiceName = g_Name;
        Table[0].lpServiceProc = SvcMain;
        Table[1].lpServiceName = NULL;
        Table[1].lpServiceProc = NULL;
        StartServiceCtrlDispatcherA(Table);
        return;
    }

    /* the caller's own tokens, without SeAssignPrimaryTokenPrivilege (the administrator) */
    Matrix("caller", GetCurrentProcess(), FALSE, FALSE, TRUE);
    Matrix("caller", GetCurrentProcess(), FALSE, FALSE, FALSE);

    /* the service part needs another user: a throw-away account of this test */
    StringCbPrintfW(Password, sizeof(Password), L"Cpau-%08lx-%08lx!", GetTickCount(), GetCurrentProcessId() * 2654435761u);
    for (Try = 0; Try < 5 && Status == NERR_UserExists; Try++)
    {
        StringCchPrintfW(User, _countof(User), L"cparights%lx", (GetTickCount() + Try * 7919) & 0xffffff);
        ZeroMemory(&Info, sizeof(Info));
        Info.usri1_name = User;
        Info.usri1_password = Password;
        Info.usri1_priv = USER_PRIV_USER;
        Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
        Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    }
    if (Status != NERR_Success)
    {
        skip("NetUserAdd failed: %lu\n", Status);
        return;
    }
    RunService(User, Password);
    NetUserDel(NULL, User);
}
