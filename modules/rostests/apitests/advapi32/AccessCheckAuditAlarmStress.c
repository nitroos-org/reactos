/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Opt-in stress of the access check and audit alarm system services
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Runs only when ACAA_STRESS_SECONDS is set in the environment (otherwise it returns at once).
 *
 * Four caller threads call the four access check and audit alarm services with random arguments,
 * most of them valid, some bad (NULL, inaccessible memory, wrong sizes, wrong handles, bad levels):
 * two in this process (an administrator, no SeAuditPrivilege) and two in a service of LocalSystem
 * (SeAuditPrivilege enabled, so NtAccessCheckAndAuditAlarm runs its whole path). In each process one
 * more thread keeps changing a shared descriptor, list and string while the callers pass them.
 *
 * Every 5 minutes, and at the end, this process prints the paged and non-paged pool pages of the
 * system and its own handle count; the service reports its handle count at the start and the end.
 * The test fails only if a process stops (the service does not report) or its handle count grows.
 */

#include "precomp.h"
#include <stdio.h>
#include <ndk/sefuncs.h>
#include <ndk/exfuncs.h>
#include <ndk/obfuncs.h>

#define MAX_LIST 0x1000

static GENERIC_MAPPING Mapping = { 0x1 | READ_CONTROL, 0x2, 0x4, 0xf | STANDARD_RIGHTS_REQUIRED };
static GUID Guids[4] =
{
    {0x2c4e0001, 0x5f10, 0x4a2b, {0x83, 0x0d, 0x11, 0x42, 0x6e, 0x9a, 0x70, 0x01}},
    {0x2c4e0002, 0x5f10, 0x4a2b, {0x83, 0x0d, 0x11, 0x42, 0x6e, 0x9a, 0x70, 0x02}},
    {0x2c4e0003, 0x5f10, 0x4a2b, {0x83, 0x0d, 0x11, 0x42, 0x6e, 0x9a, 0x70, 0x03}},
    {0x2c4e0004, 0x5f10, 0x4a2b, {0x83, 0x0d, 0x11, 0x42, 0x6e, 0x9a, 0x70, 0x04}},
};

static volatile LONG Stop;
static PUCHAR Page, NoAccess;
static PSID Everyone, Admins;
static PSECURITY_DESCRIPTOR Descriptors[4];
static ULONG DescriptorCount;
static PUCHAR Shared;           /* the self-relative descriptor that the mutator changes */
static ULONG SharedLength;
static OBJECT_TYPE_LIST SharedList[4];
static UNICODE_STRING SharedName;
static WCHAR SharedNameBuffer[32];
static HANDLE Tokens[8];        /* impersonation, identification, anonymous, primary, no TOKEN_QUERY, event, ... */
static ULONG TokenCount;

typedef struct
{
    ULONG Seed;
    ULONG Calls, Successes, Granted, Faults;
    ACCESS_MASK *GrantedList;
    NTSTATUS *StatusList;
} STRESS_THREAD;

static ULONG Random(STRESS_THREAD *Thread)
{
    ULONG x = Thread->Seed;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    Thread->Seed = x;
    return x;
}
#define CHANCE(T, N) ((Random(T) % 100) < (N))

static PSECURITY_DESCRIPTOR MakeDescriptor(int Kind)
{
    SECURITY_DESCRIPTOR Absolute;
    BYTE AclBuffer[256];
    PACL Acl = (PACL)AclBuffer;
    PSECURITY_DESCRIPTOR Relative;
    DWORD Length = 0;

    InitializeSecurityDescriptor(&Absolute, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&Absolute, Admins, FALSE);
    SetSecurityDescriptorGroup(&Absolute, Everyone, FALSE);
    InitializeAcl(Acl, sizeof(AclBuffer), 4);
    switch (Kind)
    {
        case 0:
            SetSecurityDescriptorDacl(&Absolute, TRUE, NULL, FALSE);
            break;
        case 1:
            SetSecurityDescriptorDacl(&Absolute, TRUE, Acl, FALSE);
            break;
        case 2:
            AddAccessAllowedAce(Acl, ACL_REVISION, 0x1, Everyone);
            AddAccessDeniedAce(Acl, ACL_REVISION, 0x2, Admins);
            SetSecurityDescriptorDacl(&Absolute, TRUE, Acl, FALSE);
            break;
        default:
            AddAccessAllowedObjectAce(Acl, 4, 0, 0x2, &Guids[1], NULL, Everyone);
            AddAccessDeniedObjectAce(Acl, 4, 0, 0x4, &Guids[2], NULL, Everyone);
            AddAccessAllowedAce(Acl, 4, 0x5, Admins);
            SetSecurityDescriptorDacl(&Absolute, TRUE, Acl, FALSE);
            break;
    }
    MakeSelfRelativeSD(&Absolute, NULL, &Length);
    Relative = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Relative && !MakeSelfRelativeSD(&Absolute, Relative, &Length))
        return NULL;
    if (Kind == 3)
        SharedLength = Length;
    return Relative;
}

static BOOL Setup(void)
{
    SID_IDENTIFIER_AUTHORITY World = {SECURITY_WORLD_SID_AUTHORITY}, Nt = {SECURITY_NT_AUTHORITY};
    HANDLE Process;
    DWORD Old;
    ULONG i;

    if (!AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone) ||
        !AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &Admins))
        return FALSE;
    for (i = 0; i < 4; i++)
    {
        Descriptors[i] = MakeDescriptor(i);
        if (!Descriptors[i])
            return FALSE;
    }
    DescriptorCount = 4;
    Shared = HeapAlloc(GetProcessHeap(), 0, SharedLength);
    if (!Shared)
        return FALSE;
    memcpy(Shared, Descriptors[3], SharedLength);
    for (i = 0; i < 4; i++)
    {
        SharedList[i].Level = (WORD)(i ? 1 : 0);
        SharedList[i].Sbz = 0;
        SharedList[i].ObjectType = &Guids[i];
    }
    wcscpy(SharedNameBuffer, L"SharedObjectName");
    RtlInitUnicodeString(&SharedName, SharedNameBuffer);

    Page = VirtualAlloc(NULL, 2 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Page)
        return FALSE;
    NoAccess = Page + 4096;
    VirtualProtect(NoAccess, 4096, PAGE_NOACCESS, &Old);

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Process))
        return FALSE;
    DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Tokens[0]);
    DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenImpersonation, &Tokens[1]);
    DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityAnonymous, TokenImpersonation, &Tokens[2]);
    DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &Tokens[3]);
    DuplicateHandle(GetCurrentProcess(), Process, GetCurrentProcess(), &Tokens[4], TOKEN_IMPERSONATE, FALSE, 0);
    Tokens[5] = CreateEventW(NULL, FALSE, FALSE, NULL);
    Tokens[6] = (HANDLE)(LONG_PTR)-6; /* NtCurrentEffectiveToken */
    Tokens[7] = (HANDLE)(ULONG_PTR)0x7ffc;
    TokenCount = 8;
    CloseHandle(Process);
    return Tokens[0] && Tokens[1] && Tokens[3];
}

/* Changes the shared inputs while the callers use them */
static DWORD WINAPI Mutator(LPVOID Context)
{
    STRESS_THREAD *Thread = Context;
    PISECURITY_DESCRIPTOR_RELATIVE Relative = (PISECURITY_DESCRIPTOR_RELATIVE)Shared;

    while (!Stop)
    {
        switch (Random(Thread) % 8)
        {
            case 0: Relative->Owner = Random(Thread) % (SharedLength + 64); break;
            case 1: Relative->Dacl = Random(Thread) % (SharedLength + 64); break;
            case 2: Relative->Control ^= (SECURITY_DESCRIPTOR_CONTROL)(1 << (Random(Thread) % 16)); break;
            case 3: Shared[Random(Thread) % SharedLength] = (UCHAR)Random(Thread); break;
            case 4: memcpy(Shared, Descriptors[3], SharedLength); break;
            case 5: SharedList[Random(Thread) % 4].Level = (WORD)(Random(Thread) % 6); break;
            case 6: SharedList[Random(Thread) % 4].ObjectType = CHANCE(Thread, 80) ? &Guids[Random(Thread) % 4] :
                                                                (GUID *)(NoAccess - 8); break;
            default: SharedName.Length = (USHORT)(Random(Thread) % 80); break;
        }
    }
    return 0;
}

static PUNICODE_STRING PickString(STRESS_THREAD *Thread, PUNICODE_STRING Valid)
{
    switch (Random(Thread) % 20)
    {
        case 0: return NULL;
        case 1: return (PUNICODE_STRING)(NoAccess - 4);
        case 2: return &SharedName;
        default: return Valid;
    }
}

static PSECURITY_DESCRIPTOR PickDescriptor(STRESS_THREAD *Thread)
{
    switch (Random(Thread) % 16)
    {
        case 0: return NULL;
        case 1: return (PSECURITY_DESCRIPTOR)(NoAccess - 2);
        case 2: case 3: return Shared;
        default: return Descriptors[Random(Thread) % DescriptorCount];
    }
}

static DWORD WINAPI Caller(LPVOID Context)
{
    STRESS_THREAD *Thread = Context;
    UNICODE_STRING Subsystem, TypeName, Name;
    OBJECT_TYPE_LIST List[4];
    BOOLEAN OnClose;
    static const ACCESS_MASK Requests[] =
    {
        0, 0x1, 0x2, 0x4, 0x7, MAXIMUM_ALLOWED, ACCESS_SYSTEM_SECURITY, WRITE_OWNER, READ_CONTROL | WRITE_DAC,
        GENERIC_READ,
    };

    RtlInitUnicodeString(&Subsystem, L"Stress");
    RtlInitUnicodeString(&TypeName, L"StressObject");
    RtlInitUnicodeString(&Name, L"Object");

    while (!Stop)
    {
        PUNICODE_STRING S = PickString(Thread, &Subsystem), T = PickString(Thread, &TypeName),
                        N = PickString(Thread, &Name);
        PSECURITY_DESCRIPTOR Sd = PickDescriptor(Thread);
        PSID Self = CHANCE(Thread, 70) ? NULL : (CHANCE(Thread, 80) ? Everyone : (PSID)(NoAccess - 4));
        ACCESS_MASK Desired = CHANCE(Thread, 90) ? Requests[Random(Thread) % ARRAYSIZE(Requests)] : Random(Thread);
        AUDIT_EVENT_TYPE AuditType = CHANCE(Thread, 95) ? (AUDIT_EVENT_TYPE)(Random(Thread) % 2) :
                                                          (AUDIT_EVENT_TYPE)Random(Thread);
        ULONG Flags = CHANCE(Thread, 85) ? AUDIT_ALLOW_NO_PRIVILEGE : (CHANCE(Thread, 50) ? 0 : Random(Thread));
        POBJECT_TYPE_LIST ListArg;
        ULONG Count, i, Form = Random(Thread) % 4;
        PGENERIC_MAPPING MappingArg = CHANCE(Thread, 95) ? &Mapping :
                                      (CHANCE(Thread, 50) ? NULL : (PGENERIC_MAPPING)(NoAccess - 8));
        PACCESS_MASK GrantedArg = CHANCE(Thread, 97) ? Thread->GrantedList : (PACCESS_MASK)(NoAccess - 4);
        PNTSTATUS StatusArg = CHANCE(Thread, 97) ? Thread->StatusList : NULL;
        PBOOLEAN OnCloseArg = CHANCE(Thread, 98) ? &OnClose : (PBOOLEAN)NoAccess;
        HANDLE Token = Tokens[CHANCE(Thread, 70) ? 0 : Random(Thread) % TokenCount];
        HANDLE Impersonated = CHANCE(Thread, 85) ? Tokens[CHANCE(Thread, 80) ? 0 : Random(Thread) % 3] : NULL;
        NTSTATUS Result;

        /* the list: none, a valid one, the shared one, or a bad one; counts up to the result list limit */
        Count = Random(Thread) % 5;
        for (i = 0; i < Count; i++)
        {
            List[i].Level = (WORD)(i ? 1 + (Random(Thread) % 2) * (i > 1) : 0);
            List[i].Sbz = 0;
            List[i].ObjectType = &Guids[i];
        }
        ListArg = List;
        switch (Random(Thread) % 12)
        {
            case 0: ListArg = NULL; break;
            case 1: ListArg = SharedList; Count = 4; break;
            case 2: ListArg = (POBJECT_TYPE_LIST)(NoAccess - sizeof(OBJECT_TYPE_LIST)); Count = 2; break;
            case 3: Count = CHANCE(Thread, 50) ? MAX_LIST + (Random(Thread) % 2) : Random(Thread); break;
            default: break;
        }

        if (Impersonated)
            SetThreadToken(NULL, Impersonated);
        switch (Form)
        {
            case 0:
                Result = NtAccessCheckAndAuditAlarm(S, (PVOID)1, T, N, Sd, Desired, MappingArg, FALSE, GrantedArg,
                                                    StatusArg, OnCloseArg);
                break;
            case 1:
                Result = NtAccessCheckByTypeAndAuditAlarm(S, (PVOID)1, T, N, Sd, Self, Desired, AuditType, Flags,
                                                          ListArg, Count, MappingArg, FALSE, GrantedArg, StatusArg,
                                                          OnCloseArg);
                break;
            case 2:
                Result = NtAccessCheckByTypeResultListAndAuditAlarm(S, (PVOID)1, T, N, Sd, Self, Desired, AuditType,
                                                                    Flags, ListArg, Count, MappingArg, FALSE,
                                                                    GrantedArg, StatusArg, OnCloseArg);
                break;
            default:
                Result = NtAccessCheckByTypeResultListAndAuditAlarmByHandle(S, (PVOID)1, Token, T, N, Sd, Self,
                                                                            Desired, AuditType, Flags, ListArg, Count,
                                                                            MappingArg, FALSE, GrantedArg, StatusArg,
                                                                            OnCloseArg);
                break;
        }
        if (Impersonated)
            RevertToSelf();

        Thread->Calls++;
        if (NT_SUCCESS(Result))
        {
            Thread->Successes++;
            if (StatusArg && NT_SUCCESS(StatusArg[0]))
                Thread->Granted++;
        }
        else if (Result == STATUS_ACCESS_VIOLATION || Result == STATUS_DATATYPE_MISALIGNMENT)
        {
            Thread->Faults++;
        }
    }
    return 0;
}

static void PoolPages(ULONG *Paged, ULONG *NonPaged)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;

    *Paged = *NonPaged = 0;
    if (NT_SUCCESS(NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL)))
    {
        *Paged = Info.PagedPoolPages;
        *NonPaged = Info.NonPagedPoolPages;
    }
}

static void PrintReport(const char *Format, ...);

/* Runs the callers for Seconds; Report receives the lines (printf in this process, a file in the service) */
static void RunStress(ULONG Seconds, ULONG Seed, void (*Report)(const char *, ...))
{
    STRESS_THREAD Threads[3];
    HANDLE Handles[3];
    DWORD HandlesBefore = 0, HandlesAfter = 0, Start, Elapsed, NextSample = 300;
    ULONG Paged, NonPaged, i, Calls = 0, Successes = 0, Granted = 0, Faults = 0;

    GetProcessHandleCount(GetCurrentProcess(), &HandlesBefore);
    PoolPages(&Paged, &NonPaged);
    Report("start seconds %lu handles %lu pool paged %lu nonpaged %lu pages\n", Seconds, HandlesBefore, Paged,
           NonPaged);

    Stop = 0;
    for (i = 0; i < 3; i++)
    {
        Threads[i].Seed = Seed * 7919 + i * 104729 + 1;
        Threads[i].Calls = Threads[i].Successes = Threads[i].Granted = Threads[i].Faults = 0;
        Threads[i].GrantedList = HeapAlloc(GetProcessHeap(), 0, (MAX_LIST + 1) * sizeof(ACCESS_MASK));
        Threads[i].StatusList = HeapAlloc(GetProcessHeap(), 0, (MAX_LIST + 1) * sizeof(NTSTATUS));
        Handles[i] = CreateThread(NULL, 0, i ? Caller : Mutator, &Threads[i], 0, NULL);
    }

    Start = GetTickCount();
    while ((Elapsed = (GetTickCount() - Start) / 1000) < Seconds)
    {
        Sleep(1000);
        if (Elapsed >= NextSample)
        {
            DWORD Now = 0;

            NextSample += 300;
            GetProcessHandleCount(GetCurrentProcess(), &Now);
            PoolPages(&Paged, &NonPaged);
            Report("at %lu s calls %lu handles %lu pool paged %lu nonpaged %lu pages\n", Elapsed,
                   Threads[1].Calls + Threads[2].Calls, Now, Paged, NonPaged);
        }
    }
    Stop = 1;
    WaitForMultipleObjects(3, Handles, TRUE, INFINITE);
    for (i = 0; i < 3; i++)
    {
        CloseHandle(Handles[i]);
        if (i)
        {
            Calls += Threads[i].Calls;
            Successes += Threads[i].Successes;
            Granted += Threads[i].Granted;
            Faults += Threads[i].Faults;
        }
        HeapFree(GetProcessHeap(), 0, Threads[i].GrantedList);
        HeapFree(GetProcessHeap(), 0, Threads[i].StatusList);
    }

    GetProcessHandleCount(GetCurrentProcess(), &HandlesAfter);
    PoolPages(&Paged, &NonPaged);
    Report("end calls %lu succeeded %lu granted %lu faults %lu handles %lu -> %lu pool paged %lu nonpaged %lu pages\n",
           Calls, Successes, Granted, Faults, HandlesBefore, HandlesAfter, Paged, NonPaged);
    Report("HANDLES %lu %lu\n", HandlesBefore, HandlesAfter);
    if (Report == PrintReport)
        ok(HandlesAfter <= HandlesBefore + 2, "handle count %lu -> %lu\n", HandlesBefore, HandlesAfter);
}

/* This process */
static void PrintReport(const char *Format, ...)
{
    va_list Args;

    va_start(Args, Format);
    printf("AccessCheckAuditAlarmStress: ");
    vprintf(Format, Args);
    va_end(Args);
}

/* The service */
static WCHAR ServiceName[64];
static WCHAR ResultFileName[MAX_PATH];
static ULONG ServiceSeconds;
static SERVICE_STATUS_HANDLE StatusHandle;
static HANDLE ResultFile = INVALID_HANDLE_VALUE;

static void FileReport(const char *Format, ...)
{
    char Text[300];
    va_list Args;
    DWORD Written;

    va_start(Args, Format);
    _vsnprintf(Text, sizeof(Text) - 1, Format, Args);
    Text[sizeof(Text) - 1] = 0;
    va_end(Args);
    WriteFile(ResultFile, Text, (DWORD)strlen(Text), &Written, NULL);
    FlushFileBuffers(ResultFile);
}

static void ReportState(DWORD State)
{
    SERVICE_STATUS Status;

    RtlZeroMemory(&Status, sizeof(Status));
    Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    Status.dwCurrentState = State;
    SetServiceStatus(StatusHandle, &Status);
}

static DWORD WINAPI ServiceHandler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    return NO_ERROR;
}

static VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
    HANDLE Process;
    TOKEN_PRIVILEGES Privileges;

    StatusHandle = RegisterServiceCtrlHandlerExW(ServiceName, ServiceHandler, NULL);
    if (!StatusHandle)
        return;
    ReportState(SERVICE_RUNNING);
    ResultFile = CreateFileW(ResultFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (ResultFile != INVALID_HANDLE_VALUE)
    {
        Privileges.PrivilegeCount = 1;
        Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Process) &&
            LookupPrivilegeValueA(NULL, SE_AUDIT_NAME, &Privileges.Privileges[0].Luid))
        {
            AdjustTokenPrivileges(Process, FALSE, &Privileges, 0, NULL, NULL);
            CloseHandle(Process);
        }
        if (Setup())
            RunStress(ServiceSeconds, 2, FileReport);
        else
            FileReport("NOSETUP\n");
        FileReport("DONE\n");
        CloseHandle(ResultFile);
    }
    ReportState(SERVICE_STOPPED);
}

static BOOL WaitStopped(SC_HANDLE Service, DWORD Milliseconds)
{
    SERVICE_STATUS_PROCESS Status;
    DWORD Needed, Waited;

    for (Waited = 0; Waited <= Milliseconds; Waited += 500)
    {
        if (QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status, sizeof(Status), &Needed) &&
            Status.dwCurrentState == SERVICE_STOPPED)
            return TRUE;
        Sleep(500);
    }
    return FALSE;
}

START_TEST(AccessCheckAuditAlarmStress)
{
    CHAR FileName[MAX_PATH], Command[2 * MAX_PATH + 128], Name[64], Result[MAX_PATH], Temp[MAX_PATH], Value[32];
    WCHAR CommandW[2 * MAX_PATH + 128], NameW[64];
    SC_HANDLE Scm, Service = NULL;
    ULONG Seconds;
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 6 && !strcmp(argv[2], "service"))
    {
        SERVICE_TABLE_ENTRYW Table[2] = {{ServiceName, ServiceMain}, {NULL, NULL}};

        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, ServiceName, _countof(ServiceName));
        MultiByteToWideChar(CP_ACP, 0, argv[4], -1, ResultFileName, _countof(ResultFileName));
        ServiceSeconds = strtoul(argv[5], NULL, 10);
        StartServiceCtrlDispatcherW(Table);
        return;
    }

    if (!GetEnvironmentVariableA("ACAA_STRESS_SECONDS", Value, sizeof(Value)))
    {
        skip("set ACAA_STRESS_SECONDS to run the stress\n");
        return;
    }
    Seconds = strtoul(Value, NULL, 10);
    if (!Seconds || !Setup())
    {
        skip("no stress (seconds %lu)\n", Seconds);
        return;
    }

    /* The privileged half */
    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    GetModuleFileNameA(NULL, FileName, _countof(FileName));
    GetTempPathA(_countof(Temp), Temp);
    StringCbPrintfA(Name, sizeof(Name), "RosAcAuditStress%lu", GetTickCount());
    StringCbPrintfA(Result, sizeof(Result), "%s%s.txt", Temp, Name);
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" AccessCheckAuditAlarmStress service %s \"%s\" %lu", FileName,
                    Name, Result, Seconds);
    MultiByteToWideChar(CP_ACP, 0, Command, -1, CommandW, _countof(CommandW));
    MultiByteToWideChar(CP_ACP, 0, Name, -1, NameW, _countof(NameW));
    if (Scm)
        Service = CreateServiceW(Scm, NameW, NameW, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                 SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, CommandW, NULL, NULL, NULL, NULL, NULL);
    ok(Service != NULL, "CreateService failed with %lu\n", GetLastError());
    if (Service)
        ok(StartServiceW(Service, 0, NULL), "StartService failed with %lu\n", GetLastError());

    RunStress(Seconds, 1, PrintReport);

    if (Service)
    {
        HANDLE File;
        char Text[4096];
        DWORD Read = 0;
        ULONG Before = 0, After = 0;
        char *Line;

        ok(WaitStopped(Service, 120000), "the stress service did not stop\n");
        DeleteService(Service);
        CloseServiceHandle(Service);

        File = CreateFileA(Result, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        ok(File != INVALID_HANDLE_VALUE, "the stress service wrote no report\n");
        if (File != INVALID_HANDLE_VALUE)
        {
            ReadFile(File, Text, sizeof(Text) - 1, &Read, NULL);
            Text[Read] = 0;
            CloseHandle(File);
            printf("AccessCheckAuditAlarmStress service:\n%s", Text);
            ok(strstr(Text, "DONE") != NULL, "the stress service did not finish\n");
            Line = strstr(Text, "HANDLES ");
            ok(Line && sscanf(Line + 8, "%lu %lu", &Before, &After) == 2 && After <= Before + 2,
               "service handle count %lu -> %lu\n", Before, After);
        }
        DeleteFileA(Result);
    }
    if (Scm)
        CloseServiceHandle(Scm);
}
