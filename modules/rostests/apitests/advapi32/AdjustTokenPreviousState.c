/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The previous state AdjustTokenGroups and AdjustTokenPrivileges return
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 with a LocalSystem own-process service that has an unrestricted service SID (the
 * group NT SERVICE\<name>, attributes 0xe, which may be disabled), 64 and 32 bit:
 *  - AdjustTokenGroups lays the previous state out as a TokenGroups query does: the array, then the SIDs, which the
 *    Sid members point to, inside the caller's buffer. ReturnLength is the array and the SIDs: 56 bytes for one group
 *    with a SID of 32 bytes on 64 bit, 44 bytes on 32 bit, 8 or 4 bytes when nothing changes.
 *  - A buffer that is too small fails with ERROR_INSUFFICIENT_BUFFER and changes nothing. A 32-bit caller on 64-bit
 *    Windows needs a buffer of the 64-bit size: 44 bytes fail with the ReturnLength 56; a call that succeeds returns
 *    the 32-bit length 44.
 *  - A mandatory group in the list, before or after a group that could be changed: ERROR_CANT_DISABLE_MANDATORY,
 *    ReturnLength 0, no group changed. A SID the token does not have, with a group it has: success with
 *    ERROR_NOT_ALL_ASSIGNED, the other group changed and returned.
 *  - AdjustTokenPrivileges: ReturnLength is never below sizeof(TOKEN_PRIVILEGES): 16 bytes when no privilege or one
 *    changes, 28 for two; 15 bytes fail with ERROR_INSUFFICIENT_BUFFER for one change and change nothing.
 * On ReactOS the kernel copied the token's own SID_AND_ATTRIBUTES entries out (kernel addresses in the caller's
 * buffer) and counted the array only.
 */

#include "precomp.h"
#include <sddl.h>

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

static DWORD GroupAttributes(HANDLE Token, PSID Sid)
{
    UCHAR Buffer[4096];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    DWORD Length, i;

    if (!GetTokenInformation(Token, TokenGroups, Buffer, sizeof(Buffer), &Length))
        return MAXDWORD;
    for (i = 0; i < Groups->GroupCount; i++)
        if (EqualSid(Groups->Groups[i].Sid, Sid))
            return Groups->Groups[i].Attributes;
    return MAXDWORD - 1;
}

/* The previous state in Buffer names exactly Sid with the attributes Attributes, inside the buffer */
static VOID CheckPrevious(PCSTR Row, PUCHAR Buffer, DWORD Length, PSID Sid, DWORD Attributes)
{
    PTOKEN_GROUPS Previous = (PTOKEN_GROUPS)Buffer;
    PUCHAR SidAt;

    Check(Previous->GroupCount == 1, "%s: %lu groups in the previous state", Row, Previous->GroupCount);
    if (Previous->GroupCount != 1)
        return;
    SidAt = (PUCHAR)Previous->Groups[0].Sid;
    Check(SidAt == Buffer + FIELD_OFFSET(TOKEN_GROUPS, Groups[1]),
          "%s: the SID is not right behind the array, inside the buffer (%s)", Row,
          (SidAt >= Buffer && SidAt < Buffer + Length) ? "inside" : "outside");
    if (SidAt >= Buffer && SidAt < Buffer + Length)
        Check(EqualSid(SidAt, Sid), "%s: the previous state names another SID", Row);
    Check(Previous->Groups[0].Attributes == Attributes, "%s: attributes 0x%lx, expected 0x%lx", Row,
          Previous->Groups[0].Attributes, Attributes);
}

static BOOL IsWow64(VOID)
{
    BOOL Wow64 = FALSE;
    return IsWow64Process(GetCurrentProcess(), &Wow64) && Wow64;
}

static VOID GroupRows(HANDLE Token, PSID ServiceSid, PSID MandatorySid)
{
    UCHAR Buffer[4096], Two[sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES)];
    PTOKEN_GROUPS List = (PTOKEN_GROUPS)Two;
    TOKEN_GROUPS One;
    DWORD SidLength = GetLengthSid(ServiceSid), Own, Native, Length, Error, i;
    DWORD Sizes[5];
    UCHAR GuestsSid[SECURITY_MAX_SID_SIZE];
    BOOL Ret;

    /* this process' layout, and the native one the length check uses (8 + 16 per group on 64-bit Windows) */
    Own = FIELD_OFFSET(TOKEN_GROUPS, Groups[1]) + SidLength;
    Native = IsWow64() ? 8 + 16 + SidLength : Own;

    One.GroupCount = 1;
    One.Groups[0].Sid = ServiceSid;
    One.Groups[0].Attributes = 0;
    memset(Buffer, 0xcc, sizeof(Buffer));
    Length = 0xdeadbeef;
    Ret = AdjustTokenGroups(Token, FALSE, &One, sizeof(Buffer), (PTOKEN_GROUPS)Buffer, &Length);
    Check(Ret && GetLastError() == ERROR_SUCCESS, "disable: %d, error %lu", Ret, GetLastError());
    Check(Length == Own, "disable: ReturnLength %lu, expected %lu", Length, Own);
    if (Ret)
        CheckPrevious("disable", Buffer, sizeof(Buffer), ServiceSid, 0xe);
    Check(GroupAttributes(Token, ServiceSid) == 0xa, "disable: the group has 0x%lx", GroupAttributes(Token, ServiceSid));

    /* buffers that are too small change nothing and give the native length */
    Sizes[0] = 0; Sizes[1] = 4; Sizes[2] = FIELD_OFFSET(TOKEN_GROUPS, Groups[1]); Sizes[3] = Native - 1; Sizes[4] = Own - 1;
    One.Groups[0].Attributes = SE_GROUP_ENABLED;
    for (i = 0; i < _countof(Sizes); i++)
    {
        memset(Buffer, 0xcc, sizeof(Buffer));
        Length = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        Ret = AdjustTokenGroups(Token, FALSE, &One, Sizes[i], (PTOKEN_GROUPS)Buffer, &Length);
        Error = GetLastError();
        Check(!Ret && Error == ERROR_INSUFFICIENT_BUFFER, "enable, %lu bytes: %d, error %lu", Sizes[i], Ret, Error);
        Check(Length == Native, "enable, %lu bytes: ReturnLength %lu, expected %lu", Sizes[i], Length, Native);
        Check(GroupAttributes(Token, ServiceSid) == 0xa, "enable, %lu bytes: the group has 0x%lx", Sizes[i],
              GroupAttributes(Token, ServiceSid));
    }

    /* the native size is enough; the length returned is this process' */
    memset(Buffer, 0xcc, sizeof(Buffer));
    Length = 0xdeadbeef;
    Ret = AdjustTokenGroups(Token, FALSE, &One, Native, (PTOKEN_GROUPS)Buffer, &Length);
    Check(Ret && GetLastError() == ERROR_SUCCESS, "enable, %lu bytes: %d, error %lu", Native, Ret, GetLastError());
    Check(Length == Own, "enable, %lu bytes: ReturnLength %lu, expected %lu", Native, Length, Own);
    if (Ret)
        CheckPrevious("enable", Buffer, Native, ServiceSid, 0xa);
    Check(GroupAttributes(Token, ServiceSid) == 0xe, "enable: the group has 0x%lx", GroupAttributes(Token, ServiceSid));

    /* nothing changes: the empty array */
    Length = 0xdeadbeef;
    Ret = AdjustTokenGroups(Token, FALSE, &One, sizeof(Buffer), (PTOKEN_GROUPS)Buffer, &Length);
    Check(Ret && ((PTOKEN_GROUPS)Buffer)->GroupCount == 0 && Length == FIELD_OFFSET(TOKEN_GROUPS, Groups[0]),
          "no change: %d, %lu groups, ReturnLength %lu", Ret, ((PTOKEN_GROUPS)Buffer)->GroupCount, Length);

    /*
     * reset to the defaults after a disable: the service SID comes back (on Windows the only group that changes;
     * here the controller's token also has LOCAL enabled but not enabled by default, which the reset disables: the
     * layout is checked for every entry)
     */
    One.Groups[0].Attributes = 0;
    AdjustTokenGroups(Token, FALSE, &One, 0, NULL, NULL);
    memset(Buffer, 0xcc, sizeof(Buffer));
    Length = 0xdeadbeef;
    Ret = AdjustTokenGroups(Token, TRUE, NULL, sizeof(Buffer), (PTOKEN_GROUPS)Buffer, &Length);
    Check(Ret, "reset: %d, error %lu", Ret, GetLastError());
    if (Ret)
    {
        PTOKEN_GROUPS Previous = (PTOKEN_GROUPS)Buffer;
        PUCHAR Next = Buffer + FIELD_OFFSET(TOKEN_GROUPS, Groups[Previous->GroupCount]);
        BOOL Found = FALSE;

        Check(Previous->GroupCount >= 1, "reset: %lu groups in the previous state", Previous->GroupCount);
        for (i = 0; i < Previous->GroupCount && i < 16; i++)
        {
            /* every SID right after the one before, behind the array, inside the buffer */
            Check((PUCHAR)Previous->Groups[i].Sid == Next, "reset: SID %lu is not where the layout puts it (%s)", i,
                  ((PUCHAR)Previous->Groups[i].Sid >= Buffer && (PUCHAR)Previous->Groups[i].Sid < Buffer + sizeof(Buffer)) ?
                  "inside" : "outside");
            if ((PUCHAR)Previous->Groups[i].Sid != Next)
                break;
            if (EqualSid(Next, ServiceSid))
                Found = Previous->Groups[i].Attributes == 0xa;
            Next += GetLengthSid(Next);
        }
        Check(Found, "reset: the service SID (0xa) is not in the previous state");
        Check(Length == (DWORD)(Next - Buffer), "reset: ReturnLength %lu, the layout %lu", Length, (DWORD)(Next - Buffer));
    }

    /* a mandatory group in the list fails the whole call, in either order */
    if (MandatorySid)
    {
        for (i = 0; i < 2; i++)
        {
            List->GroupCount = 2;
            List->Groups[i].Sid = ServiceSid;
            List->Groups[i].Attributes = 0;
            List->Groups[1 - i].Sid = MandatorySid;
            List->Groups[1 - i].Attributes = 0;
            Length = 0xdeadbeef;
            SetLastError(0xdeadbeef);
            Ret = AdjustTokenGroups(Token, FALSE, List, sizeof(Buffer), (PTOKEN_GROUPS)Buffer, &Length);
            Error = GetLastError();
            Check(!Ret && Error == ERROR_CANT_DISABLE_MANDATORY && Length == 0,
                  "mandatory group %s: %d, error %lu, ReturnLength %lu", i ? "first" : "second", Ret, Error, Length);
            Check(GroupAttributes(Token, ServiceSid) == 0xe, "mandatory group %s: the other group has 0x%lx",
                  i ? "first" : "second", GroupAttributes(Token, ServiceSid));
        }
    }

    /* a SID the token does not have: the other group is changed and returned */
    Length = sizeof(GuestsSid);
    CreateWellKnownSid(WinBuiltinGuestsSid, NULL, GuestsSid, &Length);
    List->GroupCount = 2;
    List->Groups[0].Sid = ServiceSid;
    List->Groups[0].Attributes = 0;
    List->Groups[1].Sid = GuestsSid;
    List->Groups[1].Attributes = 0;
    memset(Buffer, 0xcc, sizeof(Buffer));
    Length = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Ret = AdjustTokenGroups(Token, FALSE, List, sizeof(Buffer), (PTOKEN_GROUPS)Buffer, &Length);
    Error = GetLastError();
    Check(Ret && Error == ERROR_NOT_ALL_ASSIGNED && Length == Own, "absent SID: %d, error %lu, ReturnLength %lu", Ret,
          Error, Length);
    if (Ret)
        CheckPrevious("absent SID", Buffer, sizeof(Buffer), ServiceSid, 0xe);
    AdjustTokenGroups(Token, TRUE, NULL, 0, NULL, NULL);
}

static VOID PrivilegeRows(HANDLE Token)
{
    UCHAR Buffer[256], Two[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];
    PTOKEN_PRIVILEGES Previous = (PTOKEN_PRIVILEGES)Buffer, List = (PTOKEN_PRIVILEGES)Two;
    TOKEN_PRIVILEGES One;
    DWORD Length, Error;
    BOOL Ret;

    One.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, L"SeTimeZonePrivilege", &One.Privileges[0].Luid))
        return;
    One.Privileges[0].Attributes = 0;
    AdjustTokenPrivileges(Token, FALSE, &One, 0, NULL, NULL);

    One.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Length = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Ret = AdjustTokenPrivileges(Token, FALSE, &One, sizeof(TOKEN_PRIVILEGES) - 1, Previous, &Length);
    Error = GetLastError();
    Check(!Ret && Error == ERROR_INSUFFICIENT_BUFFER && Length == sizeof(TOKEN_PRIVILEGES),
          "privilege, 15 bytes: %d, error %lu, ReturnLength %lu", Ret, Error, Length);
    Length = 0xdeadbeef;
    Ret = AdjustTokenPrivileges(Token, FALSE, &One, sizeof(TOKEN_PRIVILEGES), Previous, &Length);
    /* the previous state: disabled (Windows: 0x1, enabled by default, for SeTimeZonePrivilege of SYSTEM) */
    Check(Ret && Length == sizeof(TOKEN_PRIVILEGES) && Previous->PrivilegeCount == 1 &&
          !(Previous->Privileges[0].Attributes & SE_PRIVILEGE_ENABLED),
          "privilege, 16 bytes: %d, ReturnLength %lu, %lu entries, attributes 0x%lx", Ret, Length,
          Previous->PrivilegeCount, Previous->Privileges[0].Attributes);

    /* no change: still the length of one entry */
    Length = 0xdeadbeef;
    Ret = AdjustTokenPrivileges(Token, FALSE, &One, sizeof(Buffer), Previous, &Length);
    Check(Ret && Length == sizeof(TOKEN_PRIVILEGES) && Previous->PrivilegeCount == 0,
          "privilege, no change: %d, ReturnLength %lu, %lu entries", Ret, Length, Previous->PrivilegeCount);

    /* two that change */
    List->PrivilegeCount = 2;
    List->Privileges[0] = One.Privileges[0];
    List->Privileges[0].Attributes = 0;
    if (!LookupPrivilegeValueW(NULL, L"SeChangeNotifyPrivilege", &List->Privileges[1].Luid))
        return;
    List->Privileges[1].Attributes = 0;
    Length = 0xdeadbeef;
    Ret = AdjustTokenPrivileges(Token, FALSE, List, sizeof(Buffer), Previous, &Length);
    Check(Ret && Length == FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[2]) && Previous->PrivilegeCount == 2,
          "two privileges: %d, ReturnLength %lu, %lu entries", Ret, Length, Previous->PrivilegeCount);
    List->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(Token, FALSE, List, 0, NULL, NULL);
}

static VOID ServiceRows(VOID)
{
    UCHAR Buffer[4096], ServiceSid[SECURITY_MAX_SID_SIZE], MandatorySid[SECURITY_MAX_SID_SIZE];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    BOOL HaveService = FALSE, HaveMandatory = FALSE;
    DWORD Length, i;
    HANDLE Token;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_PRIVILEGES, &Token))
    {
        Check(FALSE, "OpenProcessToken failed (%lu)", GetLastError());
        return;
    }
    if (GetTokenInformation(Token, TokenGroups, Buffer, sizeof(Buffer), &Length))
    {
        for (i = 0; i < Groups->GroupCount; i++)
        {
            PSID Sid = Groups->Groups[i].Sid;
            if (!HaveService && *GetSidSubAuthorityCount(Sid) == 6 && *GetSidSubAuthority(Sid, 0) == SECURITY_SERVICE_ID_BASE_RID)
            {
                CopySid(sizeof(ServiceSid), ServiceSid, Sid);
                HaveService = Groups->Groups[i].Attributes == 0xe;
            }
            if (!HaveMandatory && (Groups->Groups[i].Attributes & SE_GROUP_MANDATORY) &&
                (Groups->Groups[i].Attributes & SE_GROUP_ENABLED))
            {
                CopySid(sizeof(MandatorySid), MandatorySid, Sid);
                HaveMandatory = TRUE;
            }
        }
    }
    Check(HaveService, "the token has no service SID with the attributes 0xe");
    if (HaveService)
        GroupRows(Token, ServiceSid, HaveMandatory ? MandatorySid : NULL);
    PrivilegeRows(Token);
    CloseHandle(Token);
}

static SERVICE_STATUS_HANDLE g_Status;
static CHAR g_Name[64], g_File[MAX_PATH];

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
        ServiceRows();
        fprintf(g_Out, "END\n");
        fclose(g_Out);
        g_Out = NULL;
    }
    Report(SERVICE_STOPPED);
}

START_TEST(AdjustTokenPreviousState)
{
    CHAR Exe[MAX_PATH], Command[3 * MAX_PATH], File[MAX_PATH], Name[64], Line[600];
    struct { DWORD dwServiceSidType; } SidInfo = { SERVICE_SID_TYPE_UNRESTRICTED };
    SERVICE_STATUS_PROCESS Status;
    SC_HANDLE hScm, hService;
    DWORD Needed, Waited, Checks = 0;
    BOOL Ended = FALSE;
    int argc;
    char **argv;
    FILE *f;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "service"))
    {
        SERVICE_TABLE_ENTRYA Table[2];

        StringCbCopyA(g_Name, sizeof(g_Name), argv[3]);
        StringCbCopyA(g_File, sizeof(g_File), argv[4]);
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
    GetEnvironmentVariableA("SystemRoot", File, sizeof(File));
    StringCbPrintfA(Name, sizeof(Name), "RosTokPrev_%lu", GetTickCount() & 0xffff);
    StringCbCatA(File, sizeof(File), "\\Temp\\");
    StringCbCatA(File, sizeof(File), Name);
    StringCbCatA(File, sizeof(File), ".txt");
    DeleteFileA(File);
    GetModuleFileNameA(NULL, Exe, sizeof(Exe));
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" AdjustTokenPreviousState service %s \"%s\"", Exe, Name, File);
    hService = CreateServiceA(hScm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                              SERVICE_ERROR_IGNORE, Command, NULL, NULL, NULL, NULL, NULL);
    ok(hService != NULL, "CreateService failed with %lu\n", GetLastError());
    if (hService)
    {
        ok(ChangeServiceConfig2A(hService, SERVICE_CONFIG_SERVICE_SID_INFO, &SidInfo), "SID info failed with %lu\n",
           GetLastError());
        ok(StartServiceA(hService, 0, NULL), "StartService failed with %lu\n", GetLastError());
        for (Waited = 0; Waited < 60000; Waited += 200)
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
        ok(Ended && Checks > 20, "the service rows ended %d after %lu checks\n", Ended, Checks);
        DeleteService(hService);
        CloseServiceHandle(hService);
    }
    DeleteFileA(File);
    CloseServiceHandle(hScm);
}
