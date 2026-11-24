/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test the token of a process that hosts several services (SERVICE_WIN32_SHARE_PROCESS)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Expected values measured on Windows Server 2022 (two scratch services in one process of my own, LocalService
 * and LocalSystem, both start orders): the token has the service SIDs of ALL services of the process whose
 * ServiceSidType is not NONE (the one that starts has the attributes 0xe, the others 0xa until theirs starts); a
 * RESTRICTED service starts with ERROR_INCOMPATIBLE_SERVICE_SID_TYPE (1290) when another service of the process
 * is not RESTRICTED, running or not, and two RESTRICTED services share one write restricted token; the privileges
 * are filtered only when EVERY service has a RequiredPrivileges list, to the union of the lists and
 * SeChangeNotifyPrivilege; a list with a privilege the account does not hold fails the start of that service
 * only (ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE, 1297).
 */

#include "precomp.h"
#include <wincrypt.h>
#include <sddl.h>
#include <winuser.h>

/* advapi32 export, not declared in our SDK headers */
BOOL WINAPI IsTokenRestricted(HANDLE TokenHandle);

#define MAX_LINES 64

typedef struct _DUMP
{
    BOOL Valid;
    BOOL Restricted;
    ULONG RestrictCount;
    ULONG GroupCount;
    CHAR Groups[MAX_LINES][128];
    ULONG GroupAttrs[MAX_LINES];
    ULONG PrivCount;
    CHAR Privs[MAX_LINES][64];
} DUMP, *PDUMP;

/* Service side: one host process, two services A and B; each writes the facts of the process token when it starts */
static CHAR HostDir[MAX_PATH];

static PVOID
QueryToken(HANDLE hToken, TOKEN_INFORMATION_CLASS Class)
{
    DWORD Length = 0;
    PVOID Buffer;

    GetTokenInformation(hToken, Class, NULL, 0, &Length);
    if (Length == 0)
        return NULL;
    Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
    if (Buffer && !GetTokenInformation(hToken, Class, Buffer, Length, &Length))
    {
        HeapFree(GetProcessHeap(), 0, Buffer);
        Buffer = NULL;
    }
    return Buffer;
}

static VOID
WriteFacts(PCSTR Name)
{
    CHAR File[MAX_PATH], Temp[MAX_PATH], Priv[64];
    PTOKEN_GROUPS Groups;
    PTOKEN_PRIVILEGES Privs;
    HANDLE hToken;
    LPSTR Str;
    DWORD i, cPriv;
    FILE *f;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return;
    StringCbPrintfA(File, sizeof(File), "%s\\%s.txt", HostDir, Name);
    StringCbPrintfA(Temp, sizeof(Temp), "%s.tmp", File);
    f = fopen(Temp, "w");
    if (f)
    {
        Groups = QueryToken(hToken, TokenGroups);
        Privs = QueryToken(hToken, TokenPrivileges);
        for (i = 0; Groups && i < Groups->GroupCount; i++)
        {
            if (ConvertSidToStringSidA(Groups->Groups[i].Sid, &Str))
            {
                fprintf(f, "G %s %lx\n", Str, Groups->Groups[i].Attributes);
                LocalFree(Str);
            }
        }
        for (i = 0; Privs && i < Privs->PrivilegeCount; i++)
        {
            cPriv = sizeof(Priv);
            if (LookupPrivilegeNameA(NULL, &Privs->Privileges[i].Luid, Priv, &cPriv))
                fprintf(f, "P %s\n", Priv);
        }
        fprintf(f, "R %d\n", IsTokenRestricted(hToken) ? 1 : 0);
        fprintf(f, "END\n");
        fclose(f);
        MoveFileExA(Temp, File, MOVEFILE_REPLACE_EXISTING);
        HeapFree(GetProcessHeap(), 0, Groups);
        HeapFree(GetProcessHeap(), 0, Privs);
    }
    CloseHandle(hToken);
}

typedef struct _SVC
{
    SERVICE_STATUS_HANDLE Handle;
} SVC, *PSVC;

static VOID
SvcReport(SERVICE_STATUS_HANDLE hStatus, DWORD State)
{
    SERVICE_STATUS Status;

    RtlZeroMemory(&Status, sizeof(Status));
    Status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    Status.dwCurrentState = State;
    Status.dwControlsAccepted = (State == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    Status.dwWaitHint = 5000;
    SetServiceStatus(hStatus, &Status);
}

static DWORD WINAPI
SvcHandler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    PSVC Svc = Context;

    if (Control == SERVICE_CONTROL_STOP)
    {
        SvcReport(Svc->Handle, SERVICE_STOP_PENDING);
        SvcReport(Svc->Handle, SERVICE_STOPPED);
    }
    return NO_ERROR;
}

static VOID WINAPI
SvcMain(DWORD argc, LPSTR *argv)
{
    PSVC Svc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Svc));

    Svc->Handle = RegisterServiceCtrlHandlerExA(argv[0], SvcHandler, Svc);
    if (!Svc->Handle)
        return;
    WriteFacts(argv[0]);
    SvcReport(Svc->Handle, SERVICE_RUNNING);
}

static VOID
ServiceSide(PCSTR NameA, PCSTR NameB, PCSTR Dir)
{
    SERVICE_TABLE_ENTRYA Table[3];
    CHAR A[64], B[64];

    StringCbCopyA(HostDir, sizeof(HostDir), Dir);
    StringCbCopyA(A, sizeof(A), NameA);
    StringCbCopyA(B, sizeof(B), NameB);
    Table[0].lpServiceName = A;
    Table[0].lpServiceProc = SvcMain;
    Table[1].lpServiceName = B;
    Table[1].lpServiceProc = SvcMain;
    Table[2].lpServiceName = NULL;
    Table[2].lpServiceProc = NULL;
    StartServiceCtrlDispatcherA(Table);
}

/* Tester side */

static BOOL
ServiceSidString(PCSTR Name, PSTR Buffer, SIZE_T Size)
{
    WCHAR Upper[256];
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE Digest[20];
    DWORD cbDigest = sizeof(Digest), i;
    ULONG Sub[5];
    INT Chars;
    BOOL Ret = FALSE;

    Chars = MultiByteToWideChar(CP_ACP, 0, Name, -1, Upper, _countof(Upper)) - 1;
    if (Chars <= 0 || !CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return FALSE;
    CharUpperBuffW(Upper, Chars);
    if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
    {
        if (CryptHashData(hHash, (const BYTE *)Upper, Chars * sizeof(WCHAR), 0) &&
            CryptGetHashParam(hHash, HP_HASHVAL, Digest, &cbDigest, 0))
        {
            for (i = 0; i < 5; i++)
                Sub[i] = Digest[4 * i] | (Digest[4 * i + 1] << 8) | (Digest[4 * i + 2] << 16) |
                         ((ULONG)Digest[4 * i + 3] << 24);
            StringCbPrintfA(Buffer, Size, "S-1-5-80-%lu-%lu-%lu-%lu-%lu", Sub[0], Sub[1], Sub[2], Sub[3], Sub[4]);
            Ret = TRUE;
        }
        CryptDestroyHash(hHash);
    }
    CryptReleaseContext(hProv, 0);
    return Ret;
}

static BOOL
ReadDump(PCSTR File, PDUMP Dump)
{
    CHAR Line[300], Name[128];
    ULONG Attr;
    FILE *f;
    DWORD Waited;

    RtlZeroMemory(Dump, sizeof(*Dump));
    for (Waited = 0; Waited < 15000 && GetFileAttributesA(File) == INVALID_FILE_ATTRIBUTES; Waited += 100)
        Sleep(100);
    f = fopen(File, "r");
    if (!f)
        return FALSE;
    while (fgets(Line, sizeof(Line), f))
    {
        Line[strcspn(Line, "\r\n")] = 0;
        if (!strncmp(Line, "R ", 2))
            Dump->Restricted = atoi(Line + 2);
        else if (!strncmp(Line, "G ", 2) && Dump->GroupCount < MAX_LINES && sscanf(Line + 2, "%127s %lx", Name, &Attr) == 2)
        {
            StringCbCopyA(Dump->Groups[Dump->GroupCount], sizeof(Dump->Groups[0]), Name);
            Dump->GroupAttrs[Dump->GroupCount++] = Attr;
        }
        else if (!strncmp(Line, "P ", 2) && Dump->PrivCount < MAX_LINES)
            StringCbCopyA(Dump->Privs[Dump->PrivCount++], sizeof(Dump->Privs[0]), Line + 2);
        else if (!strcmp(Line, "END"))
            Dump->Valid = TRUE;
    }
    fclose(f);
    return Dump->Valid;
}

static INT
FindGroup(PDUMP Dump, PCSTR Sid)
{
    ULONG i;

    for (i = 0; i < Dump->GroupCount; i++)
        if (!_stricmp(Dump->Groups[i], Sid))
            return (INT)i;
    return -1;
}

static BOOL
HasPriv(PDUMP Dump, PCSTR Name)
{
    ULONG i;

    for (i = 0; i < Dump->PrivCount; i++)
        if (!_stricmp(Dump->Privs[i], Name))
            return TRUE;
    return FALSE;
}

static BOOL
WaitState(SC_HANDLE hService, DWORD State)
{
    SERVICE_STATUS_PROCESS Status;
    DWORD Needed, Waited;

    for (Waited = 0; Waited <= 15000; Waited += 100)
    {
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status, sizeof(Status), &Needed))
            return FALSE;
        if (Status.dwCurrentState == State)
            return TRUE;
        Sleep(100);
    }
    return FALSE;
}

static SC_HANDLE
CreateShared(SC_HANDLE hScm, PCSTR Name, PCSTR Command, DWORD SidType, PCSTR Privileges)
{
    struct { DWORD dwServiceSidType; } SidInfo;     /* SERVICE_SID_INFO (not in our SDK headers) */
    SERVICE_REQUIRED_PRIVILEGES_INFOA PrivInfo;
    CHAR Multi[256];
    SC_HANDLE hService;
    SIZE_T i, n;

    hService = CreateServiceA(hScm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_SHARE_PROCESS,
                              SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, Command, NULL, NULL, NULL,
                              "NT AUTHORITY\\LocalService", "");
    ok(hService != NULL, "%s: CreateService failed with %lu\n", Name, GetLastError());
    if (!hService)
        return NULL;
    if (SidType != SERVICE_SID_TYPE_NONE)
    {
        SidInfo.dwServiceSidType = SidType;
        ok(ChangeServiceConfig2A(hService, SERVICE_CONFIG_SERVICE_SID_INFO, &SidInfo),
           "%s: SERVICE_SID_INFO failed with %lu\n", Name, GetLastError());
    }
    if (Privileges)
    {
        n = strlen(Privileges);
        for (i = 0; i <= n && i < sizeof(Multi) - 2; i++)
            Multi[i] = (Privileges[i] == ',') ? 0 : Privileges[i];
        Multi[n + 1] = 0;
        PrivInfo.pmszRequiredPrivileges = Multi;
        ok(ChangeServiceConfig2A(hService, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &PrivInfo),
           "%s: REQUIRED_PRIVILEGES_INFO failed with %lu\n", Name, GetLastError());
    }
    return hService;
}

/* One scenario: services A and B of one process, A started first. Returns the start errors and the dumps */
static VOID
RunPair(SC_HANDLE hScm, PCSTR Dir, PCSTR Base, DWORD SidA, PCSTR PrivA, DWORD SidB, PCSTR PrivB,
        PDWORD ErrA, PDWORD ErrB, PDUMP DumpA, PDUMP DumpB)
{
    CHAR Exe[MAX_PATH], Command[2 * MAX_PATH + 64], NameA[64], NameB[64], File[MAX_PATH];
    SC_HANDLE hA, hB;
    SERVICE_STATUS Status;

    RtlZeroMemory(DumpA, sizeof(*DumpA));
    RtlZeroMemory(DumpB, sizeof(*DumpB));
    *ErrA = *ErrB = ERROR_SUCCESS;
    StringCbPrintfA(NameA, sizeof(NameA), "%sA", Base);
    StringCbPrintfA(NameB, sizeof(NameB), "%sB", Base);
    GetModuleFileNameA(NULL, Exe, sizeof(Exe));
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" ServiceSharedToken service %s %s \"%s\"", Exe, NameA, NameB, Dir);
    hA = CreateShared(hScm, NameA, Command, SidA, PrivA);
    hB = CreateShared(hScm, NameB, Command, SidB, PrivB);
    if (hA && hB)
    {
        if (!StartServiceA(hA, 0, NULL))
            *ErrA = GetLastError();
        else
        {
            ok(WaitState(hA, SERVICE_RUNNING), "%s: not running\n", NameA);
            StringCbPrintfA(File, sizeof(File), "%s\\%s.txt", Dir, NameA);
            ok(ReadDump(File, DumpA), "%s: no token dump\n", NameA);
        }
        if (!StartServiceA(hB, 0, NULL))
            *ErrB = GetLastError();
        else
        {
            ok(WaitState(hB, SERVICE_RUNNING), "%s: not running\n", NameB);
            StringCbPrintfA(File, sizeof(File), "%s\\%s.txt", Dir, NameB);
            ok(ReadDump(File, DumpB), "%s: no token dump\n", NameB);
        }
    }
    if (hB)
    {
        ControlService(hB, SERVICE_CONTROL_STOP, &Status);
        WaitState(hB, SERVICE_STOPPED);
        DeleteService(hB);
        CloseServiceHandle(hB);
    }
    if (hA)
    {
        ControlService(hA, SERVICE_CONTROL_STOP, &Status);
        WaitState(hA, SERVICE_STOPPED);
        DeleteService(hA);
        CloseServiceHandle(hA);
    }
}

/* Every scenario has services of its own (a service that was running when it was deleted lingers, marked for deletion,
 * and its name cannot be used again at once): the base name and the service SIDs of this scenario */
static PCSTR
Scenario(PCSTR Prefix, PSTR Base, SIZE_T Size, PSTR SidA, PSTR SidB)
{
    static ULONG Count;
    CHAR Name[64];

    StringCbPrintfA(Base, Size, "%s_%lu", Prefix, ++Count);
    StringCbPrintfA(Name, sizeof(Name), "%sA", Base);
    ServiceSidString(Name, SidA, 128);
    StringCbPrintfA(Name, sizeof(Name), "%sB", Base);
    ServiceSidString(Name, SidB, 128);
    return Base;
}

#define SID_NONE    SERVICE_SID_TYPE_NONE
#define SID_UNR     SERVICE_SID_TYPE_UNRESTRICTED
#define SID_RES     SERVICE_SID_TYPE_RESTRICTED

START_TEST(ServiceSharedToken)
{
    CHAR SidA[128], SidB[128], Prefix[32], Base[48], Dir[MAX_PATH], DirSddl[64];
    SECURITY_ATTRIBUTES Sa;
    DUMP A, B;
    SC_HANDLE hScm;
    DWORD ErrA, ErrB;
    INT ga, gb;
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 6 && !strcmp(argv[2], "service"))
    {
        ServiceSide(argv[3], argv[4], argv[5]);
        return;
    }

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm)
    {
        skip("OpenSCManager failed with %lu (not an administrator)\n", GetLastError());
        return;
    }

    GetEnvironmentVariableA("ALLUSERSPROFILE", Dir, sizeof(Dir));
    StringCbPrintfA(Prefix, sizeof(Prefix), "RosShSid%lu", GetTickCount());
    StringCbCatA(Dir, sizeof(Dir), "\\");
    StringCbCatA(Dir, sizeof(Dir), Prefix);
    StringCbCopyA(DirSddl, sizeof(DirSddl), "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)");
    Sa.nLength = sizeof(Sa);
    Sa.bInheritHandle = FALSE;
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorA(DirSddl, SDDL_REVISION_1, &Sa.lpSecurityDescriptor, NULL),
       "SDDL failed\n");
    ok(CreateDirectoryA(Dir, &Sa), "CreateDirectory(%s) failed with %lu\n", Dir, GetLastError());
    LocalFree(Sa.lpSecurityDescriptor);

    if (!ServiceSidString("probe", SidA, sizeof(SidA)))
    {
        skip("SHA-1 not available\n");
        goto cleanup;
    }

    /* UNRESTRICTED / NONE: the SID of A, in the token of both */
    RunPair(hScm, Dir, Scenario(Prefix, Base, sizeof(Base), SidA, SidB), SID_UNR, NULL, SID_NONE, NULL, &ErrA, &ErrB, &A, &B);
    ok(ErrA == ERROR_SUCCESS && ErrB == ERROR_SUCCESS, "UNR/NONE: start errors %lu, %lu\n", ErrA, ErrB);
    ga = FindGroup(&A, SidA);
    ok(ga >= 0 && A.GroupAttrs[ga] == 0xe, "UNR/NONE: A's SID in A's token: %d attributes 0x%lx\n", ga, ga >= 0 ? A.GroupAttrs[ga] : 0);
    ok(FindGroup(&A, SidB) < 0, "UNR/NONE: the SID of B (type none) is in the token\n");
    ok(FindGroup(&B, SidA) >= 0, "UNR/NONE: the token of B's start has no SID of A\n");

    /* NONE / UNRESTRICTED: the SID of B is in the token though A started the process */
    RunPair(hScm, Dir, Scenario(Prefix, Base, sizeof(Base), SidA, SidB), SID_NONE, NULL, SID_UNR, NULL, &ErrA, &ErrB, &A, &B);
    ok(ErrA == ERROR_SUCCESS && ErrB == ERROR_SUCCESS, "NONE/UNR: start errors %lu, %lu\n", ErrA, ErrB);
    gb = FindGroup(&A, SidB);
    ok(gb >= 0, "NONE/UNR: A's token has no SID of B\n");
    ok(FindGroup(&A, SidA) < 0, "NONE/UNR: the SID of A (type none) is in the token\n");

    /* UNRESTRICTED / UNRESTRICTED: both SIDs; the SID of the service that starts is enabled (0xe) */
    RunPair(hScm, Dir, Scenario(Prefix, Base, sizeof(Base), SidA, SidB), SID_UNR, NULL, SID_UNR, NULL, &ErrA, &ErrB, &A, &B);
    ok(ErrA == ERROR_SUCCESS && ErrB == ERROR_SUCCESS, "UNR/UNR: start errors %lu, %lu\n", ErrA, ErrB);
    ga = FindGroup(&A, SidA);
    gb = FindGroup(&A, SidB);
    ok(ga >= 0 && gb >= 0, "UNR/UNR: A's token has the SIDs %d, %d\n", ga, gb);
    if (ga >= 0 && gb >= 0)
        ok(A.GroupAttrs[ga] == 0xe && A.GroupAttrs[gb] == 0xa, "UNR/UNR: A's token: 0x%lx 0x%lx, expected 0xe 0xa\n",
           A.GroupAttrs[ga], A.GroupAttrs[gb]);
    ga = FindGroup(&B, SidA);
    gb = FindGroup(&B, SidB);
    ok(ga >= 0 && gb >= 0, "UNR/UNR: B's token has the SIDs %d, %d\n", ga, gb);
    if (ga >= 0 && gb >= 0)
    {
        /* the SID of a service that joins a running process is enabled when it starts (0xe 0xe) */
        ok(B.GroupAttrs[ga] == 0xe && B.GroupAttrs[gb] == 0xe, "UNR/UNR: B's token: 0x%lx 0x%lx, expected 0xe 0xe\n",
           B.GroupAttrs[ga], B.GroupAttrs[gb]);
    }

    /* RESTRICTED / NONE: the restricted service does not start, the other does and has its SID */
    RunPair(hScm, Dir, Scenario(Prefix, Base, sizeof(Base), SidA, SidB), SID_RES, NULL, SID_NONE, NULL, &ErrA, &ErrB, &A, &B);
    ok(ErrA == ERROR_INCOMPATIBLE_SERVICE_SID_TYPE, "RES/NONE: A start error %lu, expected 1290\n", ErrA);
    ok(ErrB == ERROR_SUCCESS, "RES/NONE: B start error %lu\n", ErrB);
    ok(B.Valid && FindGroup(&B, SidA) >= 0 && !B.Restricted, "RES/NONE: B's token %d %d %d\n", B.Valid,
       FindGroup(&B, SidA), B.Restricted);

    /* UNRESTRICTED / RESTRICTED: B does not start, A does with an unrestricted token with both SIDs */
    RunPair(hScm, Dir, Scenario(Prefix, Base, sizeof(Base), SidA, SidB), SID_UNR, NULL, SID_RES, NULL, &ErrA, &ErrB, &A, &B);
    ok(ErrA == ERROR_SUCCESS, "UNR/RES: A start error %lu\n", ErrA);
    ok(ErrB == ERROR_INCOMPATIBLE_SERVICE_SID_TYPE, "UNR/RES: B start error %lu, expected 1290\n", ErrB);
    ok(A.Valid && FindGroup(&A, SidA) >= 0 && FindGroup(&A, SidB) >= 0 && !A.Restricted, "UNR/RES: A's token\n");

    /* RESTRICTED / RESTRICTED: one write restricted token, both start */
    RunPair(hScm, Dir, Scenario(Prefix, Base, sizeof(Base), SidA, SidB), SID_RES, NULL, SID_RES, NULL, &ErrA, &ErrB, &A, &B);
    ok(ErrA == ERROR_SUCCESS && ErrB == ERROR_SUCCESS, "RES/RES: start errors %lu, %lu\n", ErrA, ErrB);
    ok(A.Valid && A.Restricted, "RES/RES: A's token not restricted\n");
    ok(B.Valid && B.Restricted && FindGroup(&B, SidA) >= 0 && FindGroup(&B, SidB) >= 0, "RES/RES: B's token\n");

    /* A list and none: nothing is removed */
    RunPair(hScm, Dir, Scenario(Prefix, Base, sizeof(Base), SidA, SidB), SID_NONE, "SeCreateGlobalPrivilege", SID_NONE, NULL, &ErrA, &ErrB, &A, &B);
    ok(ErrA == ERROR_SUCCESS && ErrB == ERROR_SUCCESS, "list/none: start errors %lu, %lu\n", ErrA, ErrB);
    ok(A.Valid && HasPriv(&A, "SeImpersonatePrivilege") && HasPriv(&A, "SeCreateGlobalPrivilege"),
       "list/none: the token is filtered although B has no list\n");

    /* Two lists: the union and SeChangeNotifyPrivilege */
    RunPair(hScm, Dir, Scenario(Prefix, Base, sizeof(Base), SidA, SidB), SID_NONE, "SeCreateGlobalPrivilege", SID_NONE, "SeImpersonatePrivilege",
            &ErrA, &ErrB, &A, &B);
    ok(ErrA == ERROR_SUCCESS && ErrB == ERROR_SUCCESS, "list/list: start errors %lu, %lu\n", ErrA, ErrB);
    ok(A.Valid && A.PrivCount == 3 && HasPriv(&A, "SeCreateGlobalPrivilege") && HasPriv(&A, "SeImpersonatePrivilege") &&
       HasPriv(&A, "SeChangeNotifyPrivilege"), "list/list: A's token has %lu privileges\n", A.PrivCount);
    ok(B.Valid && B.PrivCount == 3, "list/list: B's token has %lu privileges\n", B.PrivCount);

    /* A privilege LocalService does not hold: that service fails, the other has all of the account */
    RunPair(hScm, Dir, Scenario(Prefix, Base, sizeof(Base), SidA, SidB), SID_NONE, "SeDebugPrivilege", SID_NONE, NULL, &ErrA, &ErrB, &A, &B);
    ok(ErrA == ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE, "unheld/none: A start error %lu, expected 1297\n", ErrA);
    ok(ErrB == ERROR_SUCCESS, "unheld/none: B start error %lu\n", ErrB);
    ok(B.Valid && HasPriv(&B, "SeImpersonatePrivilege") && HasPriv(&B, "SeCreateGlobalPrivilege"),
       "unheld/none: B's token is filtered\n");

    /* A held list, then a list with an unheld privilege: the union of the held ones, and 1297 for the second */
    RunPair(hScm, Dir, Scenario(Prefix, Base, sizeof(Base), SidA, SidB), SID_NONE, "SeCreateGlobalPrivilege", SID_NONE, "SeDebugPrivilege",
            &ErrA, &ErrB, &A, &B);
    ok(ErrA == ERROR_SUCCESS, "held/unheld: A start error %lu\n", ErrA);
    ok(ErrB == ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE, "held/unheld: B start error %lu, expected 1297\n", ErrB);
    ok(A.Valid && A.PrivCount == 2 && HasPriv(&A, "SeCreateGlobalPrivilege") && HasPriv(&A, "SeChangeNotifyPrivilege"),
       "held/unheld: A's token has %lu privileges\n", A.PrivCount);

cleanup:
    CloseServiceHandle(hScm);
    {
        CHAR Pattern[MAX_PATH];
        WIN32_FIND_DATAA Find;
        HANDLE hFind;

        StringCbPrintfA(Pattern, sizeof(Pattern), "%s\\*", Dir);
        hFind = FindFirstFileA(Pattern, &Find);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                CHAR Path[MAX_PATH];

                StringCbPrintfA(Path, sizeof(Path), "%s\\%s", Dir, Find.cFileName);
                DeleteFileA(Path);
            } while (FindNextFileA(hFind, &Find));
            FindClose(hFind);
        }
        RemoveDirectoryA(Dir);
    }
}
