/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The token of an own-process service: NT AUTHORITY\SERVICE, owner, default DACL and the descriptor of the token
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Expected values measured on Windows Server 2022 (scratch own-process services of my own; 32 and 64 bit alike):
 *  - LocalSystem without a service SID runs with the token of the service controller: no NT AUTHORITY\SERVICE, owner the
 *    Administrators; the descriptor of the token is that of the system processes, (SY all)(BA read).
 *  - LocalSystem with a service SID, LocalService and NetworkService with or without one: the group NT AUTHORITY\SERVICE
 *    (S-1-5-6, attributes 0x7); the owner is the account (SYSTEM too); the descriptor of the token is
 *    O:<account>G:<account>D:(A;;0xf01ff;;;SY)(A;;0xf01ff;;;<account>)(A;;0x8;;;BA) without a service SID, and with one
 *    O:<account>G:<account>D:(A;;0xf01ff;;;SY)(A;;0x20000;;;OW)(A;;0xf01ff;;;<service SID>)(A;;0x8;;;BA): the account
 *    itself has no access besides READ_CONTROL through OWNER RIGHTS, the Administrators may query it;
 *    the default DACL is (SY GENERIC_ALL)(<account> GENERIC_ALL), with a service SID (SY GENERIC_ALL)(OW READ_CONTROL)
 *    (<service SID> GENERIC_ALL).
 *  - The logon SID: none for LocalSystem without a service SID; one of its own (S-1-5-5-0-<n>, a new value for each
 *    process, not a logon session of the LSA: a LocalSystem token stays in the SYSTEM logon session) for the others,
 *    attributes 0xc000000f with a service SID and 0xc0000007 without one.
 */

#include "precomp.h"
#include <wincrypt.h>
#include <sddl.h>
#include <winuser.h>

#define MAX_LINES 64

typedef struct _FACTS
{
    BOOL Valid;
    ULONG GroupCount;
    CHAR Groups[MAX_LINES][128];
    ULONG GroupAttrs[MAX_LINES];
    CHAR Owner[128];
    CHAR DefaultDacl[512];
    CHAR TokenSd[512];
} FACTS, *PFACTS;

static CHAR g_Dir[MAX_PATH];

static VOID
WriteFacts(PCSTR Name)
{
    CHAR File[MAX_PATH], Temp[MAX_PATH];
    HANDLE hToken;
    DWORD Length = 0, i;
    PTOKEN_GROUPS Groups = NULL;
    PTOKEN_OWNER Owner = NULL;
    PTOKEN_DEFAULT_DACL Dacl = NULL;
    SECURITY_DESCRIPTOR Sd;
    PSECURITY_DESCRIPTOR TokenSd = NULL;
    LPSTR Str;
    FILE *f;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | READ_CONTROL, &hToken))
        return;
    StringCbPrintfA(File, sizeof(File), "%s\\%s.txt", g_Dir, Name);
    StringCbPrintfA(Temp, sizeof(Temp), "%s.tmp", File);
    f = fopen(Temp, "w");
    if (!f)
        goto done;

    GetTokenInformation(hToken, TokenGroups, NULL, 0, &Length);
    Groups = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Groups && GetTokenInformation(hToken, TokenGroups, Groups, Length, &Length))
    {
        for (i = 0; i < Groups->GroupCount; i++)
            if (ConvertSidToStringSidA(Groups->Groups[i].Sid, &Str))
            {
                fprintf(f, "G %s %lx\n", Str, Groups->Groups[i].Attributes);
                LocalFree(Str);
            }
    }
    Length = 0;
    GetTokenInformation(hToken, TokenOwner, NULL, 0, &Length);
    Owner = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Owner && GetTokenInformation(hToken, TokenOwner, Owner, Length, &Length) && ConvertSidToStringSidA(Owner->Owner, &Str))
    {
        fprintf(f, "O %s\n", Str);
        LocalFree(Str);
    }
    Length = 0;
    GetTokenInformation(hToken, TokenDefaultDacl, NULL, 0, &Length);
    Dacl = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Dacl && GetTokenInformation(hToken, TokenDefaultDacl, Dacl, Length, &Length) &&
        InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION) && SetSecurityDescriptorDacl(&Sd, TRUE, Dacl->DefaultDacl, FALSE) &&
        ConvertSecurityDescriptorToStringSecurityDescriptorA(&Sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &Str, NULL))
    {
        fprintf(f, "D %s\n", Str);
        LocalFree(Str);
    }
    Length = 0;
    GetKernelObjectSecurity(hToken, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0, &Length);
    TokenSd = HeapAlloc(GetProcessHeap(), 0, Length);
    if (TokenSd && GetKernelObjectSecurity(hToken, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                           TokenSd, Length, &Length) &&
        ConvertSecurityDescriptorToStringSecurityDescriptorA(TokenSd, SDDL_REVISION_1,
                                                             OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                                             &Str, NULL))
    {
        fprintf(f, "S %s\n", Str);
        LocalFree(Str);
    }
    fprintf(f, "END\n");
    fclose(f);
    MoveFileExA(Temp, File, MOVEFILE_REPLACE_EXISTING);

done:
    HeapFree(GetProcessHeap(), 0, Groups);
    HeapFree(GetProcessHeap(), 0, Owner);
    HeapFree(GetProcessHeap(), 0, Dacl);
    HeapFree(GetProcessHeap(), 0, TokenSd);
    CloseHandle(hToken);
}

static SERVICE_STATUS_HANDLE g_Status;

static VOID
Report(DWORD State)
{
    SERVICE_STATUS Status;

    RtlZeroMemory(&Status, sizeof(Status));
    Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    Status.dwCurrentState = State;
    Status.dwControlsAccepted = (State == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    Status.dwWaitHint = 5000;
    SetServiceStatus(g_Status, &Status);
}

static DWORD WINAPI
Handler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    if (Control == SERVICE_CONTROL_STOP)
    {
        Report(SERVICE_STOP_PENDING);
        Report(SERVICE_STOPPED);
    }
    return NO_ERROR;
}

static CHAR g_Name[64];

static VOID WINAPI
SvcMain(DWORD argc, LPSTR *argv)
{
    g_Status = RegisterServiceCtrlHandlerExA(argv[0], Handler, NULL);
    if (!g_Status)
        return;
    WriteFacts(argv[0]);
    Report(SERVICE_RUNNING);
}

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
                Sub[i] = Digest[4 * i] | (Digest[4 * i + 1] << 8) | (Digest[4 * i + 2] << 16) | ((ULONG)Digest[4 * i + 3] << 24);
            StringCbPrintfA(Buffer, Size, "S-1-5-80-%lu-%lu-%lu-%lu-%lu", Sub[0], Sub[1], Sub[2], Sub[3], Sub[4]);
            Ret = TRUE;
        }
        CryptDestroyHash(hHash);
    }
    CryptReleaseContext(hProv, 0);
    return Ret;
}

static BOOL
ReadFacts(PCSTR File, PFACTS Facts)
{
    CHAR Line[700], Name[128];
    ULONG Attr, Waited;
    FILE *f;

    RtlZeroMemory(Facts, sizeof(*Facts));
    for (Waited = 0; Waited < 15000 && GetFileAttributesA(File) == INVALID_FILE_ATTRIBUTES; Waited += 100)
        Sleep(100);
    f = fopen(File, "r");
    if (!f)
        return FALSE;
    while (fgets(Line, sizeof(Line), f))
    {
        Line[strcspn(Line, "\r\n")] = 0;
        if (!strncmp(Line, "G ", 2) && Facts->GroupCount < MAX_LINES && sscanf(Line + 2, "%127s %lx", Name, &Attr) == 2)
        {
            StringCbCopyA(Facts->Groups[Facts->GroupCount], sizeof(Facts->Groups[0]), Name);
            Facts->GroupAttrs[Facts->GroupCount++] = Attr;
        }
        else if (!strncmp(Line, "O ", 2))
            StringCbCopyA(Facts->Owner, sizeof(Facts->Owner), Line + 2);
        else if (!strncmp(Line, "D ", 2))
            StringCbCopyA(Facts->DefaultDacl, sizeof(Facts->DefaultDacl), Line + 2);
        else if (!strncmp(Line, "S ", 2))
            StringCbCopyA(Facts->TokenSd, sizeof(Facts->TokenSd), Line + 2);
        else if (!strcmp(Line, "END"))
            Facts->Valid = TRUE;
    }
    fclose(f);
    return Facts->Valid;
}

static INT
FindGroup(PFACTS Facts, PCSTR Sid)
{
    ULONG i;

    for (i = 0; i < Facts->GroupCount; i++)
        if (!_stricmp(Facts->Groups[i], Sid))
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

/* Replace every occurrence of From in Text by To (the service SID is a hash of the name: the rows name it SVC) */
static VOID
Replace(PSTR Text, SIZE_T Size, PCSTR From, PCSTR To)
{
    CHAR Out[1024];
    PSTR Found, Start = Text;
    SIZE_T Len = strlen(From);

    Out[0] = 0;
    while (Len != 0 && (Found = strstr(Text, From)) != NULL)
    {
        *Found = 0;
        StringCbCatA(Out, sizeof(Out), Text);
        StringCbCatA(Out, sizeof(Out), To);
        Text = Found + Len;
    }
    StringCbCatA(Out, sizeof(Out), Text);
    StringCbCopyA(Start, Size, Out);
}

typedef struct _ROW
{
    PCSTR Tag;
    PCSTR Account;      /* the account name for CreateService, NULL: LocalSystem */
    DWORD SidType;
    BOOL ExpectService; /* NT AUTHORITY\SERVICE in the token */
    PCSTR Owner;        /* TokenOwner */
    PCSTR DefaultDacl;  /* the SIDs named as in SDDL; SVC is the service SID */
    PCSTR TokenSd;
    DWORD LogonSid;     /* the attributes of the one logon SID S-1-5-5-x-y, 0: none */
} ROW;

#define SD_ALL "CCDCLCSWRPWPDTLOCRSDRCWDWO"

static const ROW s_Rows[] =
{
    { "LocalSystem", NULL, SERVICE_SID_TYPE_NONE, FALSE, "S-1-5-32-544", NULL,
      "O:BAG:SYD:(A;;" SD_ALL ";;;SY)(A;;CCDCLCSWRPRC;;;BA)", 0 },
    { "LocalSystem+sid", NULL, SERVICE_SID_TYPE_UNRESTRICTED, TRUE, "S-1-5-18", "D:(A;;GA;;;SY)(A;;RC;;;OW)(A;;GA;;;SVC)",
      "O:SYG:SYD:(A;;" SD_ALL ";;;SY)(A;;RC;;;OW)(A;;" SD_ALL ";;;SVC)(A;;SW;;;BA)", 0xc000000f },
    { "LocalService", "NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_NONE, TRUE, "S-1-5-19", "D:(A;;GA;;;SY)(A;;GA;;;LS)",
      "O:LSG:LSD:(A;;" SD_ALL ";;;SY)(A;;" SD_ALL ";;;LS)(A;;SW;;;BA)", 0xc0000007 },
    { "LocalService+sid", "NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_UNRESTRICTED, TRUE, "S-1-5-19", "D:(A;;GA;;;SY)(A;;RC;;;OW)(A;;GA;;;SVC)",
      "O:LSG:LSD:(A;;" SD_ALL ";;;SY)(A;;RC;;;OW)(A;;" SD_ALL ";;;SVC)(A;;SW;;;BA)", 0xc000000f },
    { "NetworkService", "NT AUTHORITY\\NetworkService", SERVICE_SID_TYPE_NONE, TRUE, "S-1-5-20", "D:(A;;GA;;;SY)(A;;GA;;;NS)",
      "O:NSG:NSD:(A;;" SD_ALL ";;;SY)(A;;" SD_ALL ";;;NS)(A;;SW;;;BA)", 0xc0000007 },
    { "NetworkService+sid", "NT AUTHORITY\\NetworkService", SERVICE_SID_TYPE_UNRESTRICTED, TRUE, "S-1-5-20", "D:(A;;GA;;;SY)(A;;RC;;;OW)(A;;GA;;;SVC)",
      "O:NSG:NSD:(A;;" SD_ALL ";;;SY)(A;;RC;;;OW)(A;;" SD_ALL ";;;SVC)(A;;SW;;;BA)", 0xc000000f },
};

static VOID
RunRow(SC_HANDLE hScm, PCSTR Dir, const ROW *Row, ULONG Number)
{
    CHAR Exe[MAX_PATH], Command[2 * MAX_PATH + 64], Name[64], File[MAX_PATH], Sid[128], Text[512];
    SC_HANDLE hService;
    SERVICE_STATUS Status;
    FACTS Facts;
    INT g;

    StringCbPrintfA(Name, sizeof(Name), "RosTokSd_%lu", Number);
    ServiceSidString(Name, Sid, sizeof(Sid));
    GetModuleFileNameA(NULL, Exe, sizeof(Exe));
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" ServiceTokenSd service %s \"%s\"", Exe, Name, Dir);
    hService = CreateServiceA(hScm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                              SERVICE_ERROR_IGNORE, Command, NULL, NULL, NULL, Row->Account, Row->Account ? "" : NULL);
    ok(hService != NULL, "%s: CreateService failed with %lu\n", Row->Tag, GetLastError());
    if (!hService)
        return;
    if (Row->SidType != SERVICE_SID_TYPE_NONE)
    {
        struct { DWORD dwServiceSidType; } SidInfo = { Row->SidType };

        ok(ChangeServiceConfig2A(hService, SERVICE_CONFIG_SERVICE_SID_INFO, &SidInfo), "%s: SID info failed with %lu\n", Row->Tag, GetLastError());
    }
    ok(StartServiceA(hService, 0, NULL), "%s: StartService failed with %lu\n", Row->Tag, GetLastError());
    ok(WaitState(hService, SERVICE_RUNNING), "%s: not running\n", Row->Tag);
    StringCbPrintfA(File, sizeof(File), "%s\\%s.txt", Dir, Name);
    ok(ReadFacts(File, &Facts), "%s: no token facts\n", Row->Tag);
    if (Facts.Valid)
    {
        g = FindGroup(&Facts, "S-1-5-6");
        if (Row->ExpectService)
            ok(g >= 0 && Facts.GroupAttrs[g] == 0x7, "%s: NT AUTHORITY\\SERVICE %d, attributes 0x%lx\n", Row->Tag, g, g >= 0 ? Facts.GroupAttrs[g] : 0);
        else
            ok(g < 0, "%s: NT AUTHORITY\\SERVICE is in the token\n", Row->Tag);
        ok(!strcmp(Facts.Owner, Row->Owner), "%s: owner %s, expected %s\n", Row->Tag, Facts.Owner, Row->Owner);
        {
            /* one logon SID of its own (a new LUID, not the logon session's: the SYSTEM session is S-1-5-5-0-999) */
            ULONG Logon = 0, Found = 0, i;

            for (i = 0; i < Facts.GroupCount; i++)
            {
                if (!strncmp(Facts.Groups[i], "S-1-5-5-", 8))
                {
                    Found++;
                    Logon = Facts.GroupAttrs[i];
                    ok(strcmp(Facts.Groups[i], "S-1-5-5-0-999") != 0, "%s: the logon SID is that of the SYSTEM logon session\n", Row->Tag);
                }
            }
            ok(Found == (Row->LogonSid ? 1 : 0), "%s: %lu logon SIDs\n", Row->Tag, Found);
            /* LocalService/NetworkService with a service SID: Windows sets SE_GROUP_OWNER on the logon SID, the logon here
             * does not (ticket SCM-service-logon-sessions-and-logon-sid-attributes-differ) */
            todo_ros_if(Row->Account != NULL && Row->SidType != SERVICE_SID_TYPE_NONE)
                ok(Logon == Row->LogonSid, "%s: logon SID attributes 0x%lx, expected 0x%lx\n", Row->Tag, Logon, Row->LogonSid);
        }
        if (Row->DefaultDacl)
        {
            StringCbCopyA(Text, sizeof(Text), Facts.DefaultDacl);
            Replace(Text, sizeof(Text), Sid, "SVC");
            ok(!strcmp(Text, Row->DefaultDacl), "%s: default DACL %s, expected %s\n", Row->Tag, Text, Row->DefaultDacl);
        }
        StringCbCopyA(Text, sizeof(Text), Facts.TokenSd);
        Replace(Text, sizeof(Text), Sid, "SVC");
        ok(!strcmp(Text, Row->TokenSd), "%s: the descriptor of the token is %s, expected %s\n", Row->Tag, Text, Row->TokenSd);
    }
    ControlService(hService, SERVICE_CONTROL_STOP, &Status);
    WaitState(hService, SERVICE_STOPPED);
    DeleteService(hService);
    CloseServiceHandle(hService);
    DeleteFileA(File);
}

START_TEST(ServiceTokenSd)
{
    CHAR Dir[MAX_PATH];
    SECURITY_ATTRIBUTES Sa;
    SC_HANDLE hScm;
    ULONG i;
    int argc;
    char **argv;
    static const CHAR DirSddl[] = "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)";

    argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "service"))
    {
        SERVICE_TABLE_ENTRYA Table[2];

        StringCbCopyA(g_Name, sizeof(g_Name), argv[3]);
        StringCbCopyA(g_Dir, sizeof(g_Dir), argv[4]);
        Table[0].lpServiceName = g_Name;
        Table[0].lpServiceProc = SvcMain;
        Table[1].lpServiceName = NULL;
        Table[1].lpServiceProc = NULL;
        StartServiceCtrlDispatcherA(Table);
        return;
    }

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm)
    {
        skip("OpenSCManager failed with %lu (not an administrator)\n", GetLastError());
        return;
    }
    GetEnvironmentVariableA("ALLUSERSPROFILE", Dir, sizeof(Dir));
    StringCbCatA(Dir, sizeof(Dir), "\\RosTokSd");
    Sa.nLength = sizeof(Sa);
    Sa.bInheritHandle = FALSE;
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorA(DirSddl, SDDL_REVISION_1, &Sa.lpSecurityDescriptor, NULL), "SDDL failed\n");
    CreateDirectoryA(Dir, &Sa);
    LocalFree(Sa.lpSecurityDescriptor);

    for (i = 0; i < _countof(s_Rows); i++)
        RunRow(hScm, Dir, &s_Rows[i], (GetTickCount() & 0xffff) * 16 + i);

    RemoveDirectoryA(Dir);
    CloseServiceHandle(hScm);
}
