/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test the token of a service that sets a service SID type and required privileges
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Expected values measured on Windows Server 2022 (scratch services, own process, LocalService and
 * NetworkService): a service SID type adds NT SERVICE\<name> (S-1-5-80-<SHA-1 of the upper-case name>)
 * with the attributes ENABLED | ENABLED_BY_DEFAULT | OWNER and makes the default DACL
 * D:(A;;GA;;;SY)(A;;RC;;;OW)(A;;GA;;;<service SID>); a required-privileges list removes every other
 * privilege except SeChangeNotifyPrivilege and keeps the attributes of the listed ones; a listed
 * privilege the account lacks fails the start with ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE. A LocalSystem service
 * has the service SID as well (type none: not). Type RESTRICTED (LocalService, NetworkService, LocalSystem): also the
 * group NT AUTHORITY\WRITE RESTRICTED (S-1-5-33, 0x7), IsTokenRestricted = 1 and the restricting SIDs, in this order, the
 * service SID, Everyone, the logon session SID and S-1-5-33 (all 0x7); writes to an object need an ACE for one of them
 * (an object that grants only the account: write refused with 5, a new file in a directory that grants only the
 * account too), reads are not restricted.
 */

#include "precomp.h"
#include <wincrypt.h>
#include <sddl.h>
#include <winuser.h>

/* advapi32 export, not declared in our SDK headers */
BOOL WINAPI IsTokenRestricted(HANDLE TokenHandle);

#define MAX_LINES 96

typedef struct _TOKEN_DUMP
{
    BOOL Valid;
    CHAR User[128];
    CHAR Owner[128];
    CHAR Dacl[512];
    CHAR ProcessSd[512];
    BOOL Restricted;
    ULONG RestrictCount;
    CHAR Restrict[8][128];
    ULONG RestrictAttrs[8];
    ULONG WriteCount;
    CHAR WriteFile[8][MAX_PATH];
    ULONG WriteError[8];
    ULONG GroupCount;
    CHAR Groups[MAX_LINES][128];
    ULONG GroupAttrs[MAX_LINES];
    ULONG PrivCount;
    CHAR Privs[MAX_LINES][64];
    ULONG PrivAttrs[MAX_LINES];
} TOKEN_DUMP, *PTOKEN_DUMP;

static CHAR OutDir[MAX_PATH];

/* Service side: write the facts of the process token into <dir>\<name>.txt */
static CHAR SvcName[64], SvcFile[MAX_PATH];
static PSTR *SvcTargets;
static INT SvcTargetCount;
static SERVICE_STATUS_HANDLE SvcStatusHandle;
static HANDLE SvcStop;

static VOID
SvcReport(DWORD State)
{
    SERVICE_STATUS Status;

    RtlZeroMemory(&Status, sizeof(Status));
    Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    Status.dwCurrentState = State;
    Status.dwControlsAccepted = (State == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    Status.dwWaitHint = 5000;
    SetServiceStatus(SvcStatusHandle, &Status);
}

static DWORD WINAPI
SvcHandler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    if (Control == SERVICE_CONTROL_STOP)
    {
        SvcReport(SERVICE_STOP_PENDING);
        SetEvent(SvcStop);
    }
    return NO_ERROR;
}

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
WriteTokenFacts(FILE *f, HANDLE hToken)
{
    PTOKEN_USER User = QueryToken(hToken, TokenUser);
    PTOKEN_GROUPS Groups = QueryToken(hToken, TokenGroups);
    PTOKEN_PRIVILEGES Privs = QueryToken(hToken, TokenPrivileges);
    PTOKEN_OWNER Owner = QueryToken(hToken, TokenOwner);
    PTOKEN_DEFAULT_DACL Dacl = QueryToken(hToken, TokenDefaultDacl);
    SECURITY_DESCRIPTOR Sd;
    LPSTR Str;
    CHAR Name[64];
    DWORD i, cName;

    if (User && ConvertSidToStringSidA(User->User.Sid, &Str))
    {
        fprintf(f, "U %s\n", Str);
        LocalFree(Str);
    }
    if (Owner && ConvertSidToStringSidA(Owner->Owner, &Str))
    {
        fprintf(f, "O %s\n", Str);
        LocalFree(Str);
    }
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
        cName = sizeof(Name);
        if (LookupPrivilegeNameA(NULL, &Privs->Privileges[i].Luid, Name, &cName))
            fprintf(f, "P %s %lx\n", Name, Privs->Privileges[i].Attributes);
    }
    if (Dacl && Dacl->DefaultDacl)
    {
        InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&Sd, TRUE, Dacl->DefaultDacl, FALSE);
        if (ConvertSecurityDescriptorToStringSecurityDescriptorA(&Sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                                                                 &Str, NULL))
        {
            fprintf(f, "D %s\n", Str);
            LocalFree(Str);
        }
    }
    fprintf(f, "R %d\n", IsTokenRestricted(hToken) ? 1 : 0);
    {
        PTOKEN_GROUPS Restricting = QueryToken(hToken, TokenRestrictedSids);

        for (i = 0; Restricting && i < Restricting->GroupCount; i++)
        {
            if (ConvertSidToStringSidA(Restricting->Groups[i].Sid, &Str))
            {
                fprintf(f, "X %s %lx\n", Str, Restricting->Groups[i].Attributes);
                LocalFree(Str);
            }
        }
        HeapFree(GetProcessHeap(), 0, Restricting);
    }
    /* open each target for writing: a file that exists is opened, a name in a directory is created */
    for (i = 0; (INT)i < SvcTargetCount; i++)
    {
        HANDLE hFile = CreateFileA(SvcTargets[i], GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        fprintf(f, "W %s %lu\n", SvcTargets[i], hFile != INVALID_HANDLE_VALUE ? 0 : GetLastError());
        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
    }
    fprintf(f, "END\n");
    HeapFree(GetProcessHeap(), 0, User);
    HeapFree(GetProcessHeap(), 0, Groups);
    HeapFree(GetProcessHeap(), 0, Privs);
    HeapFree(GetProcessHeap(), 0, Owner);
    HeapFree(GetProcessHeap(), 0, Dacl);
}

static VOID WINAPI
SvcMain(DWORD argc, LPSTR *argv)
{
    CHAR Temp[MAX_PATH];
    HANDLE hToken;
    FILE *f;

    SvcStatusHandle = RegisterServiceCtrlHandlerExA(SvcName, SvcHandler, NULL);
    if (!SvcStatusHandle)
        return;
    /* write to a temporary name, then rename: the tester never reads half a file */
    StringCbPrintfA(Temp, sizeof(Temp), "%s.tmp", SvcFile);
    f = fopen(Temp, "w");
    if (f)
    {
        BYTE SdBuffer[2048];
        DWORD SdLength;
        LPSTR SdString;

        /* the descriptor of this process */
        if (GetKernelObjectSecurity(GetCurrentProcess(), OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                    SdBuffer, sizeof(SdBuffer), &SdLength) &&
            ConvertSecurityDescriptorToStringSecurityDescriptorA(SdBuffer, SDDL_REVISION_1,
                                                                 OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                                                 &SdString, NULL))
        {
            fprintf(f, "S %s\n", SdString);
            LocalFree(SdString);
        }
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            WriteTokenFacts(f, hToken);
            CloseHandle(hToken);
        }
        fclose(f);
        MoveFileExA(Temp, SvcFile, MOVEFILE_REPLACE_EXISTING);
    }
    SvcReport(SERVICE_RUNNING);
    WaitForSingleObject(SvcStop, 60000);
    SvcReport(SERVICE_STOPPED);
}

static VOID
ServiceSide(PCSTR Name, PCSTR File, INT TargetCount, PSTR *Targets)
{
    SERVICE_TABLE_ENTRYA Table[2];

    SvcTargetCount = TargetCount;
    SvcTargets = Targets;
    StringCbCopyA(SvcName, sizeof(SvcName), Name);
    StringCbCopyA(SvcFile, sizeof(SvcFile), File);
    SvcStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    Table[0].lpServiceName = SvcName;
    Table[0].lpServiceProc = SvcMain;
    Table[1].lpServiceName = NULL;
    Table[1].lpServiceProc = NULL;
    StartServiceCtrlDispatcherA(Table);
}

/* Tester side */

/* The documented service SID: S-1-5-80 followed by the five little-endian DWORDs of the SHA-1 of the
 * upper-case name in UTF-16LE */
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
    if (Chars <= 0)
        return FALSE;
    CharUpperBuffW(Upper, Chars);
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return FALSE;
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
ReadDump(PCSTR File, PTOKEN_DUMP Dump)
{
    CHAR Line[600], Sid[128];
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
        if (!strncmp(Line, "U ", 2))
            StringCbCopyA(Dump->User, sizeof(Dump->User), Line + 2);
        else if (!strncmp(Line, "O ", 2))
            StringCbCopyA(Dump->Owner, sizeof(Dump->Owner), Line + 2);
        else if (!strncmp(Line, "D ", 2))
            StringCbCopyA(Dump->Dacl, sizeof(Dump->Dacl), Line + 2);
        else if (!strncmp(Line, "S ", 2))
            StringCbCopyA(Dump->ProcessSd, sizeof(Dump->ProcessSd), Line + 2);
        else if (!strncmp(Line, "R ", 2))
            Dump->Restricted = atoi(Line + 2);
        else if (!strncmp(Line, "X ", 2) && Dump->RestrictCount < 8 &&
                 sscanf(Line + 2, "%127s %lx", Sid, &Attr) == 2)
        {
            StringCbCopyA(Dump->Restrict[Dump->RestrictCount], sizeof(Dump->Restrict[0]), Sid);
            Dump->RestrictAttrs[Dump->RestrictCount++] = Attr;
        }
        else if (!strncmp(Line, "W ", 2) && Dump->WriteCount < 8)
        {
            PSTR Space = strrchr(Line, ' ');

            if (Space && Space > Line + 2)
            {
                Attr = strtoul(Space + 1, NULL, 10);
                *Space = 0;
                StringCbCopyA(Dump->WriteFile[Dump->WriteCount], sizeof(Dump->WriteFile[0]), Line + 2);
                Dump->WriteError[Dump->WriteCount++] = Attr;
            }
        }
        else if (!strncmp(Line, "G ", 2) && Dump->GroupCount < MAX_LINES &&
                 sscanf(Line + 2, "%127s %lx", Sid, &Attr) == 2)
        {
            StringCbCopyA(Dump->Groups[Dump->GroupCount], sizeof(Dump->Groups[0]), Sid);
            Dump->GroupAttrs[Dump->GroupCount++] = Attr;
        }
        else if (!strncmp(Line, "P ", 2) && Dump->PrivCount < MAX_LINES &&
                 sscanf(Line + 2, "%63s %lx", Sid, &Attr) == 2)
        {
            StringCbCopyA(Dump->Privs[Dump->PrivCount], sizeof(Dump->Privs[0]), Sid);
            Dump->PrivAttrs[Dump->PrivCount++] = Attr;
        }
        else if (!strcmp(Line, "END"))
            Dump->Valid = TRUE;
    }
    fclose(f);
    return Dump->Valid;
}

/* Two SDDL strings that differ only in the logon SIDs (S-1-5-5-x-y: one per logon) */
static BOOL
SameDaclButLogonSid(PCSTR a, PCSTR b)
{
    while (*a && *b)
    {
        if (!strncmp(a, "S-1-5-5-", 8) && !strncmp(b, "S-1-5-5-", 8))
        {
            a += 8; b += 8;
            while (*a == '-' || (*a >= '0' && *a <= '9')) a++;
            while (*b == '-' || (*b >= '0' && *b <= '9')) b++;
            continue;
        }
        if (*a++ != *b++)
            return FALSE;
    }
    return *a == *b;
}

static INT
FindGroup(PTOKEN_DUMP Dump, PCSTR Sid)
{
    ULONG i;
    for (i = 0; i < Dump->GroupCount; i++)
        if (!_stricmp(Dump->Groups[i], Sid))
            return (INT)i;
    return -1;
}

static INT
FindServiceGroup(PTOKEN_DUMP Dump)
{
    ULONG i;
    for (i = 0; i < Dump->GroupCount; i++)
        if (!_strnicmp(Dump->Groups[i], "S-1-5-80-", 9))
            return (INT)i;
    return -1;
}

static INT
FindPriv(PTOKEN_DUMP Dump, PCSTR Name)
{
    ULONG i;
    for (i = 0; i < Dump->PrivCount; i++)
        if (!_stricmp(Dump->Privs[i], Name))
            return (INT)i;
    return -1;
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

static VOID
StopAndDelete(SC_HANDLE hService)
{
    SERVICE_STATUS Status;

    if (!hService)
        return;
    ControlService(hService, SERVICE_CONTROL_STOP, &Status);
    WaitState(hService, SERVICE_STOPPED);
    DeleteService(hService);
    CloseServiceHandle(hService);
}

/* A scratch LocalService service whose RequiredPrivileges value is written to the registry as it is (a type or a content
 * the API cannot make); returns the StartService error. The controller reads the value when the service starts. Measured
 * on Windows Server 2022 after a reload of its database: REG_SZ and REG_BINARY 87, only unknown names 87, known and unknown
 * names 13, an empty or zero length REG_MULTI_SZ no filter. */
static DWORD
StartWithRawPrivileges(SC_HANDLE hScm, PCSTR Name, DWORD Type, const VOID *Data, DWORD Size)
{
    CHAR Exe[MAX_PATH], Command[2 * MAX_PATH + 64], File[MAX_PATH], Key[256];
    SC_HANDLE hService;
    HKEY hKey;
    DWORD Error = ERROR_SUCCESS;
    LONG Result;

    GetModuleFileNameA(NULL, Exe, sizeof(Exe));
    StringCbPrintfA(File, sizeof(File), "%s\\%s.txt", OutDir, Name);
    DeleteFileA(File);
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" ServiceSidToken service %s \"%s\"", Exe, Name, File);
    hService = CreateServiceA(hScm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                              SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, Command, NULL, NULL, NULL,
                              "NT AUTHORITY\\LocalService", "");
    ok(hService != NULL, "%s: CreateService failed with %lu\n", Name, GetLastError());
    if (!hService)
        return GetLastError();
    StringCbPrintfA(Key, sizeof(Key), "SYSTEM\\CurrentControlSet\\Services\\%s", Name);
    Result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, Key, 0, KEY_SET_VALUE, &hKey);
    ok(Result == ERROR_SUCCESS, "%s: RegOpenKeyEx failed with %ld\n", Name, Result);
    if (Result == ERROR_SUCCESS)
    {
        Result = RegSetValueExA(hKey, "RequiredPrivileges", 0, Type, Data, Size);
        ok(Result == ERROR_SUCCESS, "%s: RegSetValueEx failed with %ld\n", Name, Result);
        RegCloseKey(hKey);
    }
    if (!StartServiceA(hService, 0, NULL))
    {
        SERVICE_STATUS Status;

        Error = GetLastError();
        /* the start never reached the service: the win32 exit code is 0, not ERROR_SERVICE_NEVER_STARTED (Windows Server 2022) */
        ok(QueryServiceStatus(hService, &Status), "%s: QueryServiceStatus failed with %lu\n", Name, GetLastError());
        ok(Status.dwWin32ExitCode == ERROR_SUCCESS, "%s: win32 exit code %lu after the failed start (error %lu), expected 0\n",
           Name, Status.dwWin32ExitCode, Error);
    }
    StopAndDelete(hService);
    DeleteFileA(File);
    return Error;
}

/* Create, configure and start a scratch service; its token facts into Dump. Returns the StartService error */
static CHAR WriteTargets[4 * MAX_PATH];     /* quoted paths the service opens for writing, appended to its command line */

static DWORD
RunService(SC_HANDLE hScm, PCSTR Name, PCSTR Account, DWORD SidType, PCSTR Privileges, PTOKEN_DUMP Dump)
{
    CHAR Exe[MAX_PATH], Command[6 * MAX_PATH + 64], File[MAX_PATH], Multi[512];
    struct { DWORD dwServiceSidType; } SidInfo;     /* SERVICE_SID_INFO (not in our SDK headers) */
    SERVICE_REQUIRED_PRIVILEGES_INFOA PrivInfo;
    SC_HANDLE hService;
    DWORD Error = ERROR_SUCCESS;
    SIZE_T i, n;

    RtlZeroMemory(Dump, sizeof(*Dump));
    GetModuleFileNameA(NULL, Exe, sizeof(Exe));
    StringCbPrintfA(File, sizeof(File), "%s\\%s.txt", OutDir, Name);
    DeleteFileA(File);
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" ServiceSidToken service %s \"%s\"%s", Exe, Name, File, WriteTargets);
    hService = CreateServiceA(hScm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                              SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, Command, NULL, NULL, NULL,
                              Account, Account ? "" : NULL);
    ok(hService != NULL, "%s: CreateService failed with %lu\n", Name, GetLastError());
    if (!hService)
        return GetLastError();

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

    if (!StartServiceA(hService, 0, NULL))
    {
        SERVICE_STATUS Status;

        Error = GetLastError();
        if (Error == ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE)
        {
            ok(QueryServiceStatus(hService, &Status), "%s: QueryServiceStatus failed with %lu\n", Name, GetLastError());
            ok(Status.dwWin32ExitCode == ERROR_SUCCESS, "%s: win32 exit code %lu after the failed start, expected 0\n",
               Name, Status.dwWin32ExitCode);
        }
    }
    else
    {
        ok(WaitState(hService, SERVICE_RUNNING), "%s: not running\n", Name);
        ok(ReadDump(File, Dump), "%s: no token dump in %s\n", Name, File);
    }
    StopAndDelete(hService);
    DeleteFileA(File);
    return Error;
}

static VOID
CheckLookup(PCSTR Name, PCSTR ExpectedSid)
{
    CHAR Account[128], Domain[64], Back[128];
    BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD cbSid = sizeof(SidBuffer), cchDomain = sizeof(Domain), cchBack = sizeof(Back);
    SID_NAME_USE Use;
    LPSTR Str = NULL;
    BOOL Ret;

    StringCbPrintfA(Account, sizeof(Account), "NT SERVICE\\%s", Name);
    Ret = LookupAccountNameA(NULL, Account, SidBuffer, &cbSid, Domain, &cchDomain, &Use);
    ok(Ret, "LookupAccountName(%s) failed with %lu\n", Account, GetLastError());
    if (!Ret)
        return;
    ConvertSidToStringSidA(SidBuffer, &Str);
    ok(Str && !_stricmp(Str, ExpectedSid), "LookupAccountName(%s) = %s, expected %s\n", Account, Str, ExpectedSid);
    ok(Use == SidTypeWellKnownGroup, "LookupAccountName(%s) use %d\n", Account, Use);
    ok(!_stricmp(Domain, "NT SERVICE"), "LookupAccountName(%s) domain %s\n", Account, Domain);
    LocalFree(Str);
    cchDomain = sizeof(Domain);
    Ret = LookupAccountSidA(NULL, SidBuffer, Back, &cchBack, Domain, &cchDomain, &Use);
    ok(Ret, "LookupAccountSid(%s) failed with %lu\n", ExpectedSid, GetLastError());
    if (Ret)
        ok(!_stricmp(Back, Name) && !_stricmp(Domain, "NT SERVICE"),
           "LookupAccountSid(%s) = %s\\%s\n", ExpectedSid, Domain, Back);
}

static VOID
CheckServiceSid(PCSTR Name, PTOKEN_DUMP Dump, PCSTR Account)
{
    CHAR Sid[128], Dacl[256];
    INT g;

    if (!ServiceSidString(Name, Sid, sizeof(Sid)))
    {
        skip("%s: SHA-1 not available\n", Name);
        return;
    }
    g = FindGroup(Dump, Sid);
    ok(g >= 0, "%s: no group %s in the token\n", Name, Sid);
    if (g >= 0)
        ok(Dump->GroupAttrs[g] == (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER),
           "%s: service SID attributes 0x%lx, expected 0xe\n", Name, Dump->GroupAttrs[g]);
    StringCbPrintfA(Dacl, sizeof(Dacl), "D:(A;;GA;;;SY)(A;;RC;;;OW)(A;;GA;;;%s)", Sid);
    ok(!strcmp(Dump->Dacl, Dacl), "%s: default DACL %s, expected %s\n", Name, Dump->Dacl, Dacl);
    ok(!_stricmp(Dump->Owner, Account), "%s: owner %s, expected %s\n", Name, Dump->Owner, Account);

    /* The process admits its logon, not its account: no ACE for the account, the owner limited by OWNER RIGHTS
     * (Windows: another process of the account opens it with no access) */
    {
        CHAR AccountAce[160];
        PCSTR Alias = !strcmp(Account, "S-1-5-19") ? ";;;LS)" : !strcmp(Account, "S-1-5-20") ? ";;;NS)" : ";;;SY)";

        StringCbPrintfA(AccountAce, sizeof(AccountAce), ";;;%s)", Account);
        ok(Dump->ProcessSd[0] != 0, "%s: no process descriptor\n", Name);
        ok(strstr(Dump->ProcessSd, Alias) == NULL && strstr(Dump->ProcessSd, AccountAce) == NULL,
           "%s: process descriptor %s admits the account\n", Name, Dump->ProcessSd);
        ok(strstr(Dump->ProcessSd, "(A;;RC;;;OW)") != NULL, "%s: process descriptor %s without OWNER RIGHTS\n",
           Name, Dump->ProcessSd);
    }
}


/* The SID of the logon session of a dump: the group with SE_GROUP_LOGON_ID (0x40000000) */
static INT
FindLogonGroup(PTOKEN_DUMP Dump)
{
    ULONG i;
    for (i = 0; i < Dump->GroupCount; i++)
        if ((Dump->GroupAttrs[i] & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
            return (INT)i;
    return -1;
}

/*
 * The token of a service with ServiceSidType RESTRICTED. Measured on Windows Server 2022 (LocalService, NetworkService,
 * LocalSystem own-process services): the service SID (0xe), the group S-1-5-33 (0x7), IsTokenRestricted = 1 and four
 * restricting SIDs with the attributes 0x7: the service SID, Everyone, the logon session SID and S-1-5-33. A LocalSystem
 * token made here has no logon group (it stays in the logon session of the controller): its logon SID is not checked.
 */
static VOID
CheckRestrictedToken(PCSTR Name, PTOKEN_DUMP Dump, BOOL HasLogonGroup)
{
    CHAR Sid[128];
    INT g;

    ok(Dump->Restricted, "%s: token not restricted\n", Name);
    g = FindGroup(Dump, "S-1-5-33");
    ok(g >= 0, "%s: no WRITE RESTRICTED group\n", Name);
    if (g >= 0)
        ok(Dump->GroupAttrs[g] == 7, "%s: WRITE RESTRICTED attributes 0x%lx, expected 0x7\n", Name, Dump->GroupAttrs[g]);
    ok(Dump->RestrictCount == 4, "%s: %lu restricting SIDs, expected 4\n", Name, Dump->RestrictCount);
    if (Dump->RestrictCount != 4)
        return;
    if (ServiceSidString(Name, Sid, sizeof(Sid)))
        ok(!_stricmp(Dump->Restrict[0], Sid), "%s: first restricting SID %s, expected %s\n", Name, Dump->Restrict[0], Sid);
    ok(!strcmp(Dump->Restrict[1], "S-1-1-0"), "%s: second restricting SID %s\n", Name, Dump->Restrict[1]);
    if (HasLogonGroup)
    {
        g = FindLogonGroup(Dump);
        ok(g >= 0, "%s: no logon group\n", Name);
        if (g >= 0)
            ok(!_stricmp(Dump->Restrict[2], Dump->Groups[g]), "%s: third restricting SID %s, logon SID %s\n",
               Name, Dump->Restrict[2], Dump->Groups[g]);
    }
    else
    {
        ok(!_strnicmp(Dump->Restrict[2], "S-1-5-5-", 8), "%s: third restricting SID %s\n", Name, Dump->Restrict[2]);
    }
    ok(!strcmp(Dump->Restrict[3], "S-1-5-33"), "%s: fourth restricting SID %s\n", Name, Dump->Restrict[3]);
    ok(Dump->RestrictAttrs[0] == 7 && Dump->RestrictAttrs[1] == 7 && Dump->RestrictAttrs[2] == 7 && Dump->RestrictAttrs[3] == 7,
       "%s: restricting attributes 0x%lx 0x%lx 0x%lx 0x%lx, expected 0x7\n", Name, Dump->RestrictAttrs[0],
       Dump->RestrictAttrs[1], Dump->RestrictAttrs[2], Dump->RestrictAttrs[3]);
}

/* A token that is not restricted: no restricting SIDs, no WRITE RESTRICTED group */
static VOID
CheckNotRestricted(PCSTR Name, PTOKEN_DUMP Dump)
{
    ok(!Dump->Restricted, "%s: restricted token\n", Name);
    ok(Dump->RestrictCount == 0, "%s: %lu restricting SIDs\n", Name, Dump->RestrictCount);
    ok(FindGroup(Dump, "S-1-5-33") < 0, "%s: WRITE RESTRICTED group\n", Name);
}

/* Files for the write rows of a service: one that grants only the account of the service, one that grants the service SID (plus
 * Administrators and SYSTEM, which the SYSTEM and Administrators groups of a LocalSystem token would pass anyway), one that grants
 * Everyone, one with Administrators and SYSTEM only, one with the account and the service SID, and a directory that grants
 * only the account (a file is made in it). Needs a file system that keeps ACLs. */
enum { W_ACCT, W_SVC, W_EV, W_ADM, W_BOTH, W_NEW, W_COUNT };

static BOOL
MakeWriteTargets(PCSTR Name, PCSTR AccountAlias)
{
    static const PCSTR Kinds[W_COUNT] = { "acct", "svc", "ev", "adm", "both", "dir" };
    CHAR Sid[128], Sddl[512], Path[MAX_PATH], Quoted[MAX_PATH + 8];
    SECURITY_ATTRIBUTES Sa;
    HANDLE hFile;
    INT k;

    if (!ServiceSidString(Name, Sid, sizeof(Sid)))
        return FALSE;
    WriteTargets[0] = 0;
    Sa.nLength = sizeof(Sa);
    Sa.bInheritHandle = FALSE;
    for (k = 0; k < W_COUNT; k++)
    {
        switch (k)
        {
            case W_ACCT: StringCbPrintfA(Sddl, sizeof(Sddl), "D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;%s)", AccountAlias); break;
            case W_SVC:  StringCbPrintfA(Sddl, sizeof(Sddl), "D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;%s)", Sid); break;
            case W_EV:   StringCbCopyA(Sddl, sizeof(Sddl), "D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;WD)"); break;
            case W_ADM:  StringCbCopyA(Sddl, sizeof(Sddl), "D:P(A;;FA;;;BA)(A;;FA;;;SY)"); break;
            case W_BOTH: StringCbPrintfA(Sddl, sizeof(Sddl), "D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;%s)(A;;FA;;;%s)", AccountAlias, Sid); break;
            default:     StringCbPrintfA(Sddl, sizeof(Sddl), "D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;%s)", AccountAlias); break;
        }
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(Sddl, SDDL_REVISION_1, &Sa.lpSecurityDescriptor, NULL))
            return FALSE;
        StringCbPrintfA(Path, sizeof(Path), "%s\\%s_%s", OutDir, Name, Kinds[k]);
        if (k == W_NEW)
        {
            CreateDirectoryA(Path, &Sa);
            StringCbCatA(Path, sizeof(Path), "\\new.txt");
        }
        else
        {
            hFile = CreateFileA(Path, GENERIC_WRITE, 0, &Sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE)
                CloseHandle(hFile);
        }
        LocalFree(Sa.lpSecurityDescriptor);
        StringCbPrintfA(Quoted, sizeof(Quoted), " \"%s\"", Path);
        StringCbCatA(WriteTargets, sizeof(WriteTargets), Quoted);
    }
    return TRUE;
}

static VOID
RemoveWriteTargets(PCSTR Name)
{
    static const PCSTR Kinds[W_COUNT] = { "acct", "svc", "ev", "adm", "both", "dir" };
    CHAR Path[MAX_PATH];
    INT k;

    for (k = 0; k < W_COUNT; k++)
    {
        StringCbPrintfA(Path, sizeof(Path), "%s\\%s_%s", OutDir, Name, Kinds[k]);
        if (k == W_NEW)
        {
            StringCbCatA(Path, sizeof(Path), "\\new.txt");
            DeleteFileA(Path);
            StringCbPrintfA(Path, sizeof(Path), "%s\\%s_%s", OutDir, Name, Kinds[k]);
            RemoveDirectoryA(Path);
        }
        else
        {
            DeleteFileA(Path);
        }
    }
    WriteTargets[0] = 0;
}

/* Expected write errors (0 = open succeeded, 5 = ERROR_ACCESS_DENIED). Measured on Windows Server 2022: with a
 * write restricted token only the objects that also grant the service SID or Everyone can be written; the account alone, and
 * Administrators and SYSTEM alone, do not; a new file in a directory that grants the account only is refused; without
 * the restriction the account's own entry is enough, Administrators and SYSTEM alone do not admit LocalService or NetworkService
 * (their tokens do not have those groups) and do admit LocalSystem. */
static VOID
CheckWrites(PCSTR Name, PTOKEN_DUMP Dump, BOOL Restricted, BOOL IsSystem)
{
    DWORD Expected[W_COUNT];
    INT k;

    Expected[W_ACCT] = Restricted ? ERROR_ACCESS_DENIED : 0;
    Expected[W_SVC] = 0;
    Expected[W_EV] = 0;
    Expected[W_ADM] = (Restricted || !IsSystem) ? ERROR_ACCESS_DENIED : 0;
    Expected[W_BOTH] = 0;
    Expected[W_NEW] = Restricted ? ERROR_ACCESS_DENIED : 0;
    ok(Dump->WriteCount == W_COUNT, "%s: %lu write rows, expected %d\n", Name, Dump->WriteCount, W_COUNT);
    for (k = 0; k < W_COUNT && (ULONG)k < Dump->WriteCount; k++)
        ok(Dump->WriteError[k] == Expected[k], "%s: write row %d (%s): error %lu, expected %lu\n", Name, k,
           Dump->WriteFile[k], Dump->WriteError[k], Expected[k]);
}

static BOOL
FileSystemKeepsAcls(PCSTR Dir)
{
    CHAR Root[4];
    DWORD Flags = 0;

    Root[0] = Dir[0]; Root[1] = ':'; Root[2] = '\\'; Root[3] = 0;
    return GetVolumeInformationA(Root, NULL, 0, NULL, NULL, &Flags, NULL, 0) && (Flags & FILE_PERSISTENT_ACLS);
}

START_TEST(ServiceSidToken)
{
    CHAR Sid[128], Name[64], Base[32], DirSddl[64];
    SECURITY_ATTRIBUTES Sa;
    TOKEN_DUMP Plain, Dump;
    SC_HANDLE hScm;
    DWORD Error;
    INT p;
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "service"))
    {
        ServiceSide(argv[3], argv[4], argc - 5, argv + 5);
        return;
    }

    /* The documented derivation, against a SID measured on Windows Server 2022 (NT SERVICE\tpA) */
    ok(ServiceSidString("tpA", Sid, sizeof(Sid)), "SHA-1 failed\n");
    ok(!strcmp(Sid, "S-1-5-80-2837236123-2027499108-4134861053-363406921-4229334143"), "tpA -> %s\n", Sid);

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm)
    {
        skip("OpenSCManager failed with %lu (not an administrator)\n", GetLastError());
        return;
    }

    /* A directory the service accounts can write their dumps into */
    GetEnvironmentVariableA("ALLUSERSPROFILE", OutDir, sizeof(OutDir));
    StringCbPrintfA(Base, sizeof(Base), "RosSvcSid%lu", GetTickCount());
    StringCbCatA(OutDir, sizeof(OutDir), "\\");
    StringCbCatA(OutDir, sizeof(OutDir), Base);
    StringCbCopyA(DirSddl, sizeof(DirSddl), "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)");
    Sa.nLength = sizeof(Sa);
    Sa.bInheritHandle = FALSE;
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorA(DirSddl, SDDL_REVISION_1, &Sa.lpSecurityDescriptor, NULL),
       "SDDL failed\n");
    ok(CreateDirectoryA(OutDir, &Sa), "CreateDirectory(%s) failed with %lu\n", OutDir, GetLastError());
    LocalFree(Sa.lpSecurityDescriptor);

    /* 1. LocalService, nothing set: no service SID, the account's privileges */
    StringCbPrintfA(Name, sizeof(Name), "%sa", Base);
    Error = RunService(hScm, Name, "NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_NONE, NULL, &Plain);
    ok(Error == ERROR_SUCCESS, "plain: StartService failed with %lu\n", Error);
    ok(Plain.Valid, "plain: no dump\n");
    ok(!strcmp(Plain.User, "S-1-5-19"), "plain: user %s\n", Plain.User);
    ok(FindServiceGroup(&Plain) < 0, "plain: unexpected service SID %s\n",
       FindServiceGroup(&Plain) >= 0 ? Plain.Groups[FindServiceGroup(&Plain)] : "");
    ok(FindPriv(&Plain, "SeImpersonatePrivilege") >= 0, "plain: no SeImpersonatePrivilege\n");
    ok(FindPriv(&Plain, "SeChangeNotifyPrivilege") >= 0, "plain: no SeChangeNotifyPrivilege\n");
    ok(strstr(Plain.Dacl, "S-1-5-80-") == NULL, "plain: default DACL %s\n", Plain.Dacl);

    /* 2. LocalService, UNRESTRICTED: the service SID, its default DACL, the account's privileges */
    StringCbPrintfA(Name, sizeof(Name), "%sb", Base);
    Error = RunService(hScm, Name, "NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_UNRESTRICTED, NULL, &Dump);
    ok(Error == ERROR_SUCCESS, "sid: StartService failed with %lu\n", Error);
    if (Dump.Valid)
    {
        CheckServiceSid(Name, &Dump, "S-1-5-19");
        ok(Dump.PrivCount == Plain.PrivCount, "sid: %lu privileges, plain %lu\n", Dump.PrivCount, Plain.PrivCount);
        ok(!Dump.Restricted, "sid: restricted token\n");
    }

    /* 2b. The account name must exist (Windows Server 2022: ERROR_INVALID_SERVICE_ACCOUNT from CreateService and
     * from ChangeServiceConfig for the short names LocalService and NetworkService and for a name nobody has) */
    {
        SC_HANDLE hAcct;
        PCSTR Bad[] = { "LocalService", "NetworkService", ".\\NoSuchAccountXYZ", "NoSuchAccountXYZ" };
        SIZE_T k;

        StringCbPrintfA(Name, sizeof(Name), "%sx", Base);
        for (k = 0; k < ARRAYSIZE(Bad); k++)
        {
            hAcct = CreateServiceA(hScm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                                   SERVICE_ERROR_IGNORE, "C:\\nothing.exe", NULL, NULL, NULL, Bad[k], "x");
            Error = hAcct ? ERROR_SUCCESS : GetLastError();
            ok(Error == ERROR_INVALID_SERVICE_ACCOUNT, "CreateService(%s): error %lu, expected %d\n", Bad[k], Error,
               ERROR_INVALID_SERVICE_ACCOUNT);
            if (hAcct)
            {
                DeleteService(hAcct);
                CloseServiceHandle(hAcct);
            }
        }
        /* ".\\user" is a local account (Windows Server 2022: CreateService succeeds) */
        hAcct = CreateServiceA(hScm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                               SERVICE_ERROR_IGNORE, "C:\\nothing.exe", NULL, NULL, NULL, ".\\Administrator", "x");
        ok(hAcct != NULL, "CreateService(.\\Administrator) failed with %lu\n", GetLastError());
        if (hAcct)
        {
            DeleteService(hAcct);
            CloseServiceHandle(hAcct);
        }
        hAcct = CreateServiceA(hScm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                               SERVICE_ERROR_IGNORE, "C:\\nothing.exe", NULL, NULL, NULL, NULL, NULL);
        ok(hAcct != NULL, "CreateService(LocalSystem) failed with %lu\n", GetLastError());
        if (hAcct)
        {
            for (k = 0; k < ARRAYSIZE(Bad); k++)
            {
                SetLastError(0xdeadbeef);
                ok(!ChangeServiceConfigA(hAcct, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL,
                                         Bad[k], "x", NULL) && GetLastError() == ERROR_INVALID_SERVICE_ACCOUNT,
                   "ChangeServiceConfig(%s): error %lu, expected %d\n", Bad[k], GetLastError(), ERROR_INVALID_SERVICE_ACCOUNT);
            }
            ok(ChangeServiceConfigA(hAcct, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL,
                                    "NT AUTHORITY\\LocalService", "", NULL),
               "ChangeServiceConfig(NT AUTHORITY\\LocalService) failed with %lu\n", GetLastError());
            ok(ChangeServiceConfigA(hAcct, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL,
                                    "NT AUTHORITY\\System", "", NULL),
               "ChangeServiceConfig(NT AUTHORITY\\System) failed with %lu\n", GetLastError());
            DeleteService(hAcct);
            CloseServiceHandle(hAcct);
        }
    }

    /* 3. LocalService, UNRESTRICTED + SeImpersonatePrivilege: that one and SeChangeNotifyPrivilege */
    StringCbPrintfA(Name, sizeof(Name), "%sc", Base);
    Error = RunService(hScm, Name, "NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_UNRESTRICTED,
                       "SeImpersonatePrivilege", &Dump);
    ok(Error == ERROR_SUCCESS, "sid+priv: StartService failed with %lu\n", Error);
    if (Dump.Valid)
    {
        CheckServiceSid(Name, &Dump, "S-1-5-19");
        ok(Dump.PrivCount == 2, "sid+priv: %lu privileges, expected 2\n", Dump.PrivCount);
        ok(FindPriv(&Dump, "SeImpersonatePrivilege") >= 0, "sid+priv: no SeImpersonatePrivilege\n");
        ok(FindPriv(&Dump, "SeChangeNotifyPrivilege") >= 0, "sid+priv: no SeChangeNotifyPrivilege\n");
        ok(FindPriv(&Dump, "SeCreateGlobalPrivilege") < 0, "sid+priv: SeCreateGlobalPrivilege kept\n");
    }

    /* 4. LocalService, privileges only (no SID type): removed as well, no service SID, DACL as plain */
    StringCbPrintfA(Name, sizeof(Name), "%sd", Base);
    Error = RunService(hScm, Name, "NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_NONE,
                       "SeImpersonatePrivilege", &Dump);
    ok(Error == ERROR_SUCCESS, "priv: StartService failed with %lu\n", Error);
    if (Dump.Valid)
    {
        ok(FindServiceGroup(&Dump) < 0, "priv: unexpected service SID\n");
        ok(Dump.PrivCount == 2, "priv: %lu privileges, expected 2\n", Dump.PrivCount);
        ok(FindPriv(&Dump, "SeImpersonatePrivilege") >= 0, "priv: no SeImpersonatePrivilege\n");
        ok(SameDaclButLogonSid(Dump.Dacl, Plain.Dacl), "priv: default DACL %s, plain %s\n", Dump.Dacl, Plain.Dacl);
    }

    /* 5. The listed privileges keep their attributes */
    StringCbPrintfA(Name, sizeof(Name), "%se", Base);
    Error = RunService(hScm, Name, "NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_UNRESTRICTED,
                       "SeCreateGlobalPrivilege", &Dump);
    ok(Error == ERROR_SUCCESS, "attrs: StartService failed with %lu\n", Error);
    if (Dump.Valid && (p = FindPriv(&Plain, "SeCreateGlobalPrivilege")) >= 0)
    {
        INT q = FindPriv(&Dump, "SeCreateGlobalPrivilege");
        ok(q >= 0, "attrs: no SeCreateGlobalPrivilege\n");
        if (q >= 0)
            ok(Dump.PrivAttrs[q] == Plain.PrivAttrs[p], "attrs: 0x%lx, plain 0x%lx\n", Dump.PrivAttrs[q], Plain.PrivAttrs[p]);
        ok(Dump.PrivCount == 2, "attrs: %lu privileges, expected 2\n", Dump.PrivCount);
    }

    /* 6. A listed privilege the account does not hold: the start fails */
    StringCbPrintfA(Name, sizeof(Name), "%sf", Base);
    Error = RunService(hScm, Name, "NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_UNRESTRICTED,
                       "SeDebugPrivilege,SeImpersonatePrivilege", &Dump);
    ok(Error == ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE, "missing priv: StartService error %lu, expected %d\n",
       Error, ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE);

    /* 6b. A RequiredPrivileges value that is malformed stops the start as on Windows Server 2022 */
    {
        static const CHAR Unknown[] = "SeNoSuchPrivilege\0";
        static const CHAR Mixed[] = "SeImpersonatePrivilege\0SeNoSuchPrivilege\0";
        static const BYTE Bin[] = { 1, 2, 3, 4, 5 };

        StringCbPrintfA(Name, sizeof(Name), "%sj", Base);
        Error = StartWithRawPrivileges(hScm, Name, REG_SZ, "SeImpersonatePrivilege", 23);
        ok(Error == ERROR_INVALID_PARAMETER, "REG_SZ: StartService error %lu, expected %d\n", Error, ERROR_INVALID_PARAMETER);
        Error = StartWithRawPrivileges(hScm, Name, REG_SZ, "", 1);
        ok(Error == ERROR_INVALID_PARAMETER, "empty REG_SZ: StartService error %lu, expected %d\n", Error, ERROR_INVALID_PARAMETER);
        Error = StartWithRawPrivileges(hScm, Name, REG_BINARY, Bin, sizeof(Bin));
        ok(Error == ERROR_INVALID_PARAMETER, "REG_BINARY: StartService error %lu, expected %d\n", Error, ERROR_INVALID_PARAMETER);
        Error = StartWithRawPrivileges(hScm, Name, REG_MULTI_SZ, Unknown, sizeof(Unknown) + 1);
        ok(Error == ERROR_INVALID_PARAMETER, "unknown name: StartService error %lu, expected %d\n", Error, ERROR_INVALID_PARAMETER);
        Error = StartWithRawPrivileges(hScm, Name, REG_MULTI_SZ, Mixed, sizeof(Mixed) + 1);
        ok(Error == ERROR_INVALID_DATA, "known and unknown names: StartService error %lu, expected %d\n", Error, ERROR_INVALID_DATA);
    }

    /* 7. NetworkService */
    StringCbPrintfA(Name, sizeof(Name), "%sg", Base);
    Error = RunService(hScm, Name, "NT AUTHORITY\\NetworkService", SERVICE_SID_TYPE_UNRESTRICTED,
                       "SeImpersonatePrivilege,SeChangeNotifyPrivilege", &Dump);
    ok(Error == ERROR_SUCCESS, "network: StartService failed with %lu\n", Error);
    if (Dump.Valid)
    {
        ok(!strcmp(Dump.User, "S-1-5-20"), "network: user %s\n", Dump.User);
        CheckServiceSid(Name, &Dump, "S-1-5-20");
        ok(Dump.PrivCount == 2, "network: %lu privileges, expected 2\n", Dump.PrivCount);
    }

    /* 8. LocalService, RESTRICTED: the service SID, WRITE RESTRICTED, the four restricting SIDs, write rows */
    {
        BOOL Acls = FileSystemKeepsAcls(OutDir);

        StringCbPrintfA(Name, sizeof(Name), "%sh", Base);
        WriteTargets[0] = 0;
        if (Acls)
            MakeWriteTargets(Name, "LS");
        Error = RunService(hScm, Name, "NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_RESTRICTED, NULL, &Dump);
        ok(Error == ERROR_SUCCESS, "restricted: StartService failed with %lu\n", Error);
        if (Dump.Valid)
        {
            ok(!strcmp(Dump.User, "S-1-5-19"), "restricted: user %s\n", Dump.User);
            CheckServiceSid(Name, &Dump, "S-1-5-19");
            CheckRestrictedToken(Name, &Dump, TRUE);
            ok(Dump.PrivCount == Plain.PrivCount, "restricted: %lu privileges, plain %lu\n", Dump.PrivCount, Plain.PrivCount);
            if (Acls)
                CheckWrites(Name, &Dump, TRUE, FALSE);
        }
        if (Acls)
            RemoveWriteTargets(Name);

        /* the same service with UNRESTRICTED: not restricted, the account's entry is enough */
        StringCbPrintfA(Name, sizeof(Name), "%sk", Base);
        if (Acls)
            MakeWriteTargets(Name, "LS");
        Error = RunService(hScm, Name, "NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_UNRESTRICTED, NULL, &Dump);
        ok(Error == ERROR_SUCCESS, "unrestricted writes: StartService failed with %lu\n", Error);
        if (Dump.Valid)
        {
            CheckNotRestricted(Name, &Dump);
            if (Acls)
                CheckWrites(Name, &Dump, FALSE, FALSE);
        }
        if (Acls)
            RemoveWriteTargets(Name);

        /* NetworkService, RESTRICTED */
        StringCbPrintfA(Name, sizeof(Name), "%sl", Base);
        if (Acls)
            MakeWriteTargets(Name, "NS");
        Error = RunService(hScm, Name, "NT AUTHORITY\\NetworkService", SERVICE_SID_TYPE_RESTRICTED, NULL, &Dump);
        ok(Error == ERROR_SUCCESS, "network restricted: StartService failed with %lu\n", Error);
        if (Dump.Valid)
        {
            ok(!strcmp(Dump.User, "S-1-5-20"), "network restricted: user %s\n", Dump.User);
            CheckServiceSid(Name, &Dump, "S-1-5-20");
            CheckRestrictedToken(Name, &Dump, TRUE);
            if (Acls)
                CheckWrites(Name, &Dump, TRUE, FALSE);
        }
        if (Acls)
            RemoveWriteTargets(Name);
    }

    /* 9. LocalSystem: UNRESTRICTED has the service SID (0xe) and no WRITE RESTRICTED, NONE has none; RESTRICTED is restricted.
     * The SYSTEM token keeps the privileges it had. */
    {
        BOOL Acls = FileSystemKeepsAcls(OutDir);
        TOKEN_DUMP System;

        StringCbPrintfA(Name, sizeof(Name), "%sm", Base);
        Error = RunService(hScm, Name, NULL, SERVICE_SID_TYPE_NONE, NULL, &System);
        ok(Error == ERROR_SUCCESS, "system none: StartService failed with %lu\n", Error);
        ok(System.Valid, "system none: no dump\n");
        ok(!strcmp(System.User, "S-1-5-18"), "system none: user %s\n", System.User);
        ok(FindServiceGroup(&System) < 0, "system none: unexpected service SID\n");
        CheckNotRestricted(Name, &System);

        StringCbPrintfA(Name, sizeof(Name), "%si", Base);
        if (Acls)
            MakeWriteTargets(Name, "SY");
        Error = RunService(hScm, Name, NULL, SERVICE_SID_TYPE_UNRESTRICTED, NULL, &Dump);
        ok(Error == ERROR_SUCCESS, "system: StartService failed with %lu\n", Error);
        ok(Dump.Valid, "system: no dump\n");
        if (Dump.Valid)
        {
            INT g = FindServiceGroup(&Dump);
            CHAR Expected[128];

            ok(!strcmp(Dump.User, "S-1-5-18"), "system: user %s\n", Dump.User);
            ok(g >= 0, "system: no service SID\n");
            if (g >= 0 && ServiceSidString(Name, Expected, sizeof(Expected)))
            {
                ok(!_stricmp(Dump.Groups[g], Expected), "system: service SID %s, expected %s\n", Dump.Groups[g], Expected);
                ok(Dump.GroupAttrs[g] == (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER),
                   "system: service SID attributes 0x%lx, expected 0xe\n", Dump.GroupAttrs[g]);
            }
            CheckNotRestricted(Name, &Dump);
            ok(Dump.PrivCount == System.PrivCount, "system: %lu privileges, without a service SID %lu\n",
               Dump.PrivCount, System.PrivCount);
            ok(FindPriv(&Dump, "SeTcbPrivilege") >= 0, "system: no SeTcbPrivilege\n");
            if (Acls)
                CheckWrites(Name, &Dump, FALSE, TRUE);
        }
        if (Acls)
            RemoveWriteTargets(Name);

        StringCbPrintfA(Name, sizeof(Name), "%sn", Base);
        if (Acls)
            MakeWriteTargets(Name, "SY");
        Error = RunService(hScm, Name, NULL, SERVICE_SID_TYPE_RESTRICTED, NULL, &Dump);
        ok(Error == ERROR_SUCCESS, "system restricted: StartService failed with %lu\n", Error);
        ok(Dump.Valid, "system restricted: no dump\n");
        if (Dump.Valid)
        {
            INT g = FindServiceGroup(&Dump);
            CHAR Expected[128];

            ok(!strcmp(Dump.User, "S-1-5-18"), "system restricted: user %s\n", Dump.User);
            ok(g >= 0, "system restricted: no service SID\n");
            if (g >= 0 && ServiceSidString(Name, Expected, sizeof(Expected)))
            {
                ok(!_stricmp(Dump.Groups[g], Expected), "system restricted: service SID %s, expected %s\n", Dump.Groups[g], Expected);
                ok(Dump.GroupAttrs[g] == (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER),
                   "system restricted: service SID attributes 0x%lx, expected 0xe\n", Dump.GroupAttrs[g]);
            }
            CheckRestrictedToken(Name, &Dump, FALSE);
            ok(Dump.PrivCount == System.PrivCount, "system restricted: %lu privileges, without a service SID %lu\n",
               Dump.PrivCount, System.PrivCount);
            if (Acls)
                CheckWrites(Name, &Dump, TRUE, TRUE);
        }
        if (Acls)
            RemoveWriteTargets(Name);
    }

    /* 10. NT SERVICE\<name> names and SIDs of an existing service */
    {
        SC_HANDLE hService;
        CHAR Exe[MAX_PATH];

        StringCbPrintfA(Name, sizeof(Name), "%sj", Base);
        GetModuleFileNameA(NULL, Exe, sizeof(Exe));
        hService = CreateServiceA(hScm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                  SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, Exe, NULL, NULL, NULL, NULL, NULL);
        ok(hService != NULL, "lookup: CreateService failed with %lu\n", GetLastError());
        if (hService && ServiceSidString(Name, Sid, sizeof(Sid)))
            CheckLookup(Name, Sid);
        if (hService)
        {
            DeleteService(hService);
            CloseServiceHandle(hService);
        }
    }
    {
        BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
        CHAR Domain[64];
        DWORD cbSid = sizeof(SidBuffer), cchDomain = sizeof(Domain);
        SID_NAME_USE Use;

        SetLastError(0xdeadbeef);
        ok(!LookupAccountNameA(NULL, "NT SERVICE\\RosNoSuchService0", SidBuffer, &cbSid, Domain, &cchDomain, &Use),
           "lookup of a service that does not exist succeeded\n");
        ok(GetLastError() == ERROR_NONE_MAPPED, "lookup of a missing service: error %lu\n", GetLastError());
    }

    RemoveDirectoryA(OutDir);
    CloseServiceHandle(hScm);
}
