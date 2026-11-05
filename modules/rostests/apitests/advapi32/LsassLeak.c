/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     lsass.exe gives back what a client call took: private bytes, handles and logon sessions stay
 *              flat over a loop of logons, SAM and LSA calls
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <tlhelp32.h>
#include <lm.h>
#include <ntsecapi.h>
#include <ndk/psfuncs.h>

#define WARMUP_ITERATIONS   30
#define LOOP_ITERATIONS     200

static WCHAR UserName[] = L"lsassleaktest";
static WCHAR UserPassword[] = L"Lsass#Leak12x";

static HANDLE LsassProcess;
static PSID UserSid;
static LSA_HANDLE Policy;

typedef NTSTATUS (NTAPI *PFN_LSAENUMERATELOGONSESSIONS)(PULONG, PLUID *);
typedef NTSTATUS (NTAPI *PFN_LSAFREERETURNBUFFER)(PVOID);
typedef NTSTATUS (NTAPI *PFN_LSACONNECTUNTRUSTED)(PHANDLE);
typedef NTSTATUS (NTAPI *PFN_LSADEREGISTERLOGONPROCESS)(HANDLE);
static PFN_LSACONNECTUNTRUSTED pLsaConnectUntrusted;
static PFN_LSADEREGISTERLOGONPROCESS pLsaDeregisterLogonProcess;
static PFN_LSAENUMERATELOGONSESSIONS pLsaEnumerateLogonSessions;
static PFN_LSAFREERETURNBUFFER pLsaFreeReturnBuffer;

typedef struct _LSASS_USAGE
{
    SIZE_T PrivateBytes;
    DWORD Handles;
    ULONG Sessions;
} LSASS_USAGE;

typedef void (*LOOP_FUNC)(void);

static ULONG CountLogonSessions(void)
{
    ULONG Count = 0;
    PLUID List = NULL;

    if (pLsaEnumerateLogonSessions == NULL)
        return 0;
    if (pLsaEnumerateLogonSessions(&Count, &List) != STATUS_SUCCESS)
        return 0;
    pLsaFreeReturnBuffer(List);
    return Count;
}

static void QueryUsage(LSASS_USAGE *Usage)
{
    VM_COUNTERS_EX Counters;
    NTSTATUS Status;

    RtlZeroMemory(&Counters, sizeof(Counters));
    Status = NtQueryInformationProcess(LsassProcess, ProcessVmCounters, &Counters, sizeof(Counters), NULL);
    ok(NT_SUCCESS(Status), "NtQueryInformationProcess returned 0x%lx\n", Status);
    Usage->PrivateBytes = Counters.PrivateUsage;
    Usage->Handles = 0;
    GetProcessHandleCount(LsassProcess, &Usage->Handles);
    Usage->Sessions = CountLogonSessions();
}

static DWORD FindProcessId(PCWSTR Name)
{
    PROCESSENTRY32W Entry;
    HANDLE Snapshot;
    DWORD Pid = 0;

    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
        return 0;
    Entry.dwSize = sizeof(Entry);
    if (Process32FirstW(Snapshot, &Entry))
    {
        do
        {
            if (!_wcsicmp(Entry.szExeFile, Name))
            {
                Pid = Entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(Snapshot, &Entry));
    }
    CloseHandle(Snapshot);
    return Pid;
}

/*
 * Run the loop. A logon session is deleted when the SRM tells lsass that the last token is closed, which
 * happens asynchronously, so the session count is given a moment to settle.
 */
static void MeasureLoop(PCSTR Name, LOOP_FUNC Func, SIZE_T MaxGrowth)
{
    LSASS_USAGE Before, After;
    ULONG i, Wait;

    for (i = 0; i < WARMUP_ITERATIONS; i++)
        Func();

    for (Wait = 0; Wait < 50; Wait++)
    {
        QueryUsage(&Before);
        Sleep(20);
        QueryUsage(&After);
        if (Before.Sessions == After.Sessions)
            break;
    }

    QueryUsage(&Before);
    for (i = 0; i < LOOP_ITERATIONS; i++)
        Func();

    for (Wait = 0; Wait < 100; Wait++)
    {
        QueryUsage(&After);
        if (After.Sessions <= Before.Sessions + 1)
            break;
        Sleep(50);
    }

    trace("%s: lsass private %Iu -> %Iu bytes, handles %lu -> %lu, logon sessions %lu -> %lu after %d iterations\n",
          Name, Before.PrivateBytes, After.PrivateBytes, Before.Handles, After.Handles,
          Before.Sessions, After.Sessions, LOOP_ITERATIONS);

    ok(After.Handles <= Before.Handles + 3, "%s: lsass handles grew from %lu to %lu\n",
       Name, Before.Handles, After.Handles);
    ok(After.Sessions <= Before.Sessions + 1, "%s: logon sessions grew from %lu to %lu\n",
       Name, Before.Sessions, After.Sessions);
    ok(After.PrivateBytes <= Before.PrivateBytes + MaxGrowth, "%s: lsass private bytes grew from %Iu to %Iu\n",
       Name, Before.PrivateBytes, After.PrivateBytes);
}

static void LogonLoop(DWORD LogonType)
{
    HANDLE Token = NULL;

    if (LogonUserW(UserName, L".", UserPassword, LogonType, LOGON32_PROVIDER_DEFAULT, &Token))
        CloseHandle(Token);
}

static void LogonInteractive(void) { LogonLoop(LOGON32_LOGON_INTERACTIVE); }
static void LogonBatch(void) { LogonLoop(LOGON32_LOGON_BATCH); }
static void LogonService(void) { LogonLoop(LOGON32_LOGON_SERVICE); }

/* The token of a logon session is duplicated and impersonated before it is closed */
static void LogonDuplicate(void)
{
    HANDLE Token = NULL, Impersonation = NULL;

    if (!LogonUserW(UserName, L".", UserPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
        return;
    if (DuplicateTokenEx(Token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Impersonation))
        CloseHandle(Impersonation);
    CloseHandle(Token);
}

static void LogonFailure(void)
{
    HANDLE Token = NULL;

    if (LogonUserW(UserName, L".", L"wrong password", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
        CloseHandle(Token);
}

static void SamQueries(void)
{
    LPBYTE Buffer;
    DWORD Read, Total;

    if (NetUserGetInfo(NULL, UserName, 2, &Buffer) == NERR_Success)
        NetApiBufferFree(Buffer);
    if (NetUserGetLocalGroups(NULL, UserName, 0, 0, &Buffer, MAX_PREFERRED_LENGTH, &Read, &Total) == NERR_Success)
        NetApiBufferFree(Buffer);
    if (NetUserGetGroups(NULL, UserName, 0, &Buffer, MAX_PREFERRED_LENGTH, &Read, &Total) == NERR_Success)
        NetApiBufferFree(Buffer);
    if (NetLocalGroupGetMembers(NULL, L"Administrators", 1, &Buffer, MAX_PREFERRED_LENGTH,
                                &Read, &Total, NULL) == NERR_Success)
        NetApiBufferFree(Buffer);
}

static void SamSetInfo(void)
{
    USER_INFO_1011 Info;

    Info.usri1011_full_name = L"Lsass Leak Test";
    NetUserSetInfo(NULL, UserName, 1011, (LPBYTE)&Info, NULL);
}

static void SamCreateDelete(void)
{
    LOCALGROUP_INFO_1 Group;
    USER_INFO_1 User;
    DWORD ParmErr;

    Group.lgrpi1_name = L"lsassleakgrp";
    Group.lgrpi1_comment = L"lsass leak test";
    if (NetLocalGroupAdd(NULL, 1, (LPBYTE)&Group, &ParmErr) == NERR_Success)
        NetLocalGroupDel(NULL, L"lsassleakgrp");

    RtlZeroMemory(&User, sizeof(User));
    User.usri1_name = L"lsassleaktmp";
    User.usri1_password = L"Tmp#Pass12x";
    User.usri1_priv = USER_PRIV_USER;
    User.usri1_flags = UF_SCRIPT;
    if (NetUserAdd(NULL, 1, (LPBYTE)&User, &ParmErr) == NERR_Success)
        NetUserDel(NULL, L"lsassleaktmp");
}

static void LsaCalls(void)
{
    LSA_UNICODE_STRING Right, Backup;
    PLSA_ENUMERATION_INFORMATION Accounts;
    PLSA_UNICODE_STRING Rights;
    ULONG Count;

    RtlInitUnicodeString((PUNICODE_STRING)&Backup, L"SeBackupPrivilege");
    RtlInitUnicodeString((PUNICODE_STRING)&Right, L"SeBatchLogonRight");

    if (LsaEnumerateAccountsWithUserRight(Policy, &Backup, (PVOID *)&Accounts, &Count) == STATUS_SUCCESS)
        LsaFreeMemory(Accounts);

    /* An account that only holds an account right has no privilege set */
    LsaAddAccountRights(Policy, UserSid, &Right, 1);
    if (LsaEnumerateAccountRights(Policy, UserSid, &Rights, &Count) == STATUS_SUCCESS)
        LsaFreeMemory(Rights);
    LsaRemoveAccountRights(Policy, UserSid, FALSE, &Right, 1);
}

static void LsaConnections(void)
{
    HANDLE Connection = NULL;

    /* Both ways to end a connection: LsaDeregisterLogonProcess, and a client that only closes the handle */
    if (pLsaConnectUntrusted(&Connection) == STATUS_SUCCESS)
        pLsaDeregisterLogonProcess(Connection);
    if (pLsaConnectUntrusted(&Connection) == STATUS_SUCCESS)
        CloseHandle(Connection);
}

static void LsaPolicyOpenClose(void)
{
    LSA_OBJECT_ATTRIBUTES Attributes = {sizeof(Attributes)};
    LSA_HANDLE Handle;

    if (LsaOpenPolicy(NULL, &Attributes, POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION, &Handle) == STATUS_SUCCESS)
        LsaClose(Handle);
}

static void LookupAccounts(void)
{
    WCHAR Name[256], Domain[256];
    DWORD NameLength = 256, DomainLength = 256;
    SID_NAME_USE Use;
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    DWORD SidLength = sizeof(Sid);

    LookupAccountSidW(NULL, UserSid, Name, &NameLength, Domain, &DomainLength, &Use);
    DomainLength = 256;
    LookupAccountNameW(NULL, UserName, Sid, &SidLength, Domain, &DomainLength, &Use);
}

static BOOL LogonWorks(DWORD LogonType)
{
    HANDLE Token = NULL;

    if (!LogonUserW(UserName, L".", UserPassword, LogonType, LOGON32_PROVIDER_DEFAULT, &Token))
        return FALSE;
    CloseHandle(Token);
    return TRUE;
}

START_TEST(LsassLeak)
{
    LSA_OBJECT_ATTRIBUTES Attributes = {sizeof(Attributes)};
    USER_INFO_1 User;
    HMODULE Secur32;
    DWORD Pid, ParmErr, SidLength = SECURITY_MAX_SID_SIZE, DomainLength = 256;
    WCHAR Domain[256];
    SID_NAME_USE Use;
    BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
    NET_API_STATUS NetStatus;
    NTSTATUS Status;

    Pid = FindProcessId(L"lsass.exe");
    if (Pid == 0)
    {
        skip("lsass.exe not found\n");
        return;
    }
    LsassProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Pid);
    if (LsassProcess == NULL)
    {
        skip("Cannot open lsass.exe: %lu\n", GetLastError());
        return;
    }

    Secur32 = LoadLibraryW(L"secur32.dll");
    if (Secur32 != NULL)
    {
        pLsaEnumerateLogonSessions = (PVOID)GetProcAddress(Secur32, "LsaEnumerateLogonSessions");
        pLsaFreeReturnBuffer = (PVOID)GetProcAddress(Secur32, "LsaFreeReturnBuffer");
        pLsaConnectUntrusted = (PVOID)GetProcAddress(Secur32, "LsaConnectUntrusted");
        pLsaDeregisterLogonProcess = (PVOID)GetProcAddress(Secur32, "LsaDeregisterLogonProcess");
        if (pLsaFreeReturnBuffer == NULL)
            pLsaEnumerateLogonSessions = NULL;
    }

    Status = LsaOpenPolicy(NULL, &Attributes, POLICY_ALL_ACCESS, &Policy);
    if (Status != STATUS_SUCCESS)
    {
        skip("LsaOpenPolicy failed: 0x%lx\n", Status);
        CloseHandle(LsassProcess);
        return;
    }

    RtlZeroMemory(&User, sizeof(User));
    User.usri1_name = UserName;
    User.usri1_password = UserPassword;
    User.usri1_priv = USER_PRIV_USER;
    User.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    NetStatus = NetUserAdd(NULL, 1, (LPBYTE)&User, &ParmErr);
    if (NetStatus != NERR_Success && NetStatus != NERR_UserExists)
    {
        skip("NetUserAdd failed: %lu\n", NetStatus);
        LsaClose(Policy);
        CloseHandle(LsassProcess);
        return;
    }

    if (!LookupAccountNameW(NULL, UserName, SidBuffer, &SidLength, Domain, &DomainLength, &Use))
    {
        skip("LookupAccountName failed: %lu\n", GetLastError());
        goto done;
    }
    UserSid = SidBuffer;

    /* Reference counted logon sessions: every successful logon ends with the last token closed */
    if (LogonWorks(LOGON32_LOGON_INTERACTIVE))
    {
        MeasureLoop("LogonUser interactive", LogonInteractive, 24 * 1024);
        MeasureLoop("LogonUser batch", LogonBatch, 24 * 1024);
        MeasureLoop("LogonUser service", LogonService, 24 * 1024);
        MeasureLoop("LogonUser, duplicated token", LogonDuplicate, 24 * 1024);
    }
    else
    {
        skip("LogonUser failed: %lu\n", GetLastError());
    }
    MeasureLoop("failed LogonUser", LogonFailure, 24 * 1024);

    MeasureLoop("SAM queries", SamQueries, 24 * 1024);
    MeasureLoop("SAM set information", SamSetInfo, 24 * 1024);
    MeasureLoop("SAM create and delete", SamCreateDelete, 24 * 1024);
    MeasureLoop("LSA account rights", LsaCalls, 24 * 1024);
    if (pLsaConnectUntrusted != NULL && pLsaDeregisterLogonProcess != NULL)
        MeasureLoop("LSA connections", LsaConnections, 24 * 1024);
    MeasureLoop("LSA policy open and close", LsaPolicyOpenClose, 24 * 1024);
    MeasureLoop("account lookups", LookupAccounts, 24 * 1024);

done:
    NetUserDel(NULL, UserName);
    LsaClose(Policy);
    CloseHandle(LsassProcess);
}
