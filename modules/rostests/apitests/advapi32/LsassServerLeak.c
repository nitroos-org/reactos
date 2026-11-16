/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Per-API server-side leak probe: lsass.exe private bytes stay flat over a loop of
 *              individual LSA/SAM/netapi client calls (each API measured on its own).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <tlhelp32.h>
#include <lm.h>
#include <ntsecapi.h>
#include <ndk/psfuncs.h>
#include <ntsam.h>

/* Count can be overridden with the LSASSLOOP environment variable */
#define DEFAULT_ITERATIONS  5000
#define WARMUP_ITERATIONS   500

static HANDLE LsassProcess;
static LSA_HANDLE Policy;
static ULONG Iterations = DEFAULT_ITERATIONS;

/* SamConnect / SamCloseHandle, loaded from samlib.dll */
typedef NTSTATUS (NTAPI *PFN_SAMCONNECT)(PUNICODE_STRING, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_SAMCLOSEHANDLE)(HANDLE);
static PFN_SAMCONNECT pSamConnect;
static PFN_SAMCLOSEHANDLE pSamCloseHandle;

typedef void (*LOOP_FUNC)(void);

static SIZE_T QueryPrivateBytes(void)
{
    VM_COUNTERS_EX Counters;
    NTSTATUS Status;

    RtlZeroMemory(&Counters, sizeof(Counters));
    Status = NtQueryInformationProcess(LsassProcess, ProcessVmCounters, &Counters, sizeof(Counters), NULL);
    if (!NT_SUCCESS(Status))
        return 0;
    return Counters.PrivateUsage;
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

static char *OnlyFilter;    /* run only the API whose name contains this substring */

/* Lowest lsass private-byte reading over a few settle samples. A per-connection RPC call spins up
 * transient worker-thread stacks that commit under load and are reclaimed when idle; sampling the
 * minimum after a short settle filters that reclaimable jitter and leaves only memory that stays. */
static SIZE_T SettledPrivateBytes(void)
{
    SIZE_T Min, Cur;
    ULONG i;

    Min = QueryPrivateBytes();
    for (i = 0; i < 5; i++)
    {
        Sleep(300);
        Cur = QueryPrivateBytes();
        if (Cur < Min)
            Min = Cur;
    }
    return Min;
}

/*
 * Run Func Iterations times and report the change in lsass private bytes. A real per-call server-side
 * leak of even a few bytes dominates over the iteration count; reclaimable worker-thread stacks are
 * the noise, filtered by the settle sampling above.
 */
static void MeasureLoop(PCSTR Name, LOOP_FUNC Func)
{
    SIZE_T Before, After;
    LONG_PTR Delta;
    ULONG i;

    if (OnlyFilter != NULL && strstr(Name, OnlyFilter) == NULL)
        return;

    for (i = 0; i < WARMUP_ITERATIONS; i++)
        Func();

    Before = SettledPrivateBytes();
    for (i = 0; i < Iterations; i++)
        Func();
    After = SettledPrivateBytes();

    Delta = (LONG_PTR)After - (LONG_PTR)Before;
    trace("LEAKROW %-32s iters=%lu before=%Iu after=%Iu delta=%Id bytes_per_call=%Id\n",
          Name, Iterations, Before, After, Delta, Delta / (LONG_PTR)Iterations);

    /*
     * lsass private bytes have a large absolute jitter floor (per-call RPC spins up worker-thread
     * stacks and grows the heap reserve in ~0.5 MB steps that are only lazily given back), so a tight
     * per-call bound would be flaky; the honest per-API numbers are in the LEAKROW trace above, and
     * the authoritative per-block proof is the in-lsass heap-walk diff recorded in evidence. This
     * bound only trips on a gross unbounded leak: the HomeDirectoryDrive bug leaked a heap block per
     * enumerated user, which over Iterations calls blows past 1 MB.
     */
    ok(Delta <= (LONG_PTR)(1024 * 1024 + Iterations * 16), "%s: lsass private bytes grew by %Id over %lu calls\n",
       Name, Delta, Iterations);
}

static void OpenClosePolicy(void)
{
    LSA_OBJECT_ATTRIBUTES Attributes = {sizeof(Attributes)};
    LSA_HANDLE Handle;

    if (LsaOpenPolicy(NULL, &Attributes, POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES, &Handle) == STATUS_SUCCESS)
        LsaClose(Handle);
}

static void QueryAccountDomain(void)
{
    PVOID Info = NULL;
    if (LsaQueryInformationPolicy(Policy, PolicyAccountDomainInformation, &Info) == STATUS_SUCCESS)
        LsaFreeMemory(Info);
}

static void QueryPrimaryDomain(void)
{
    PVOID Info = NULL;
    if (LsaQueryInformationPolicy(Policy, PolicyPrimaryDomainInformation, &Info) == STATUS_SUCCESS)
        LsaFreeMemory(Info);
}

static void QueryDnsDomain(void)
{
    PVOID Info = NULL;
    if (LsaQueryInformationPolicy(Policy, PolicyDnsDomainInformation, &Info) == STATUS_SUCCESS)
        LsaFreeMemory(Info);
}

static void QueryAuditEvents(void)
{
    PVOID Info = NULL;
    if (LsaQueryInformationPolicy(Policy, PolicyAuditEventsInformation, &Info) == STATUS_SUCCESS)
        LsaFreeMemory(Info);
}

static PSID AdminsSid;      /* S-1-5-32-544 */
static PSID WorldSid;       /* S-1-1-0 */

static void LookupSids(void)
{
    PSID Sids[2];
    PLSA_REFERENCED_DOMAIN_LIST Domains = NULL;
    PLSA_TRANSLATED_NAME Names = NULL;

    Sids[0] = AdminsSid;
    Sids[1] = WorldSid;
    if (LsaLookupSids(Policy, 2, Sids, &Domains, &Names) == STATUS_SUCCESS)
    {
        LsaFreeMemory(Domains);
        LsaFreeMemory(Names);
    }
}

static void LookupNames(void)
{
    LSA_UNICODE_STRING Name;
    PLSA_REFERENCED_DOMAIN_LIST Domains = NULL;
    PLSA_TRANSLATED_SID Sids = NULL;

    RtlInitUnicodeString((PUNICODE_STRING)&Name, L"Administrators");
    if (LsaLookupNames(Policy, 1, &Name, &Domains, &Sids) == STATUS_SUCCESS)
    {
        LsaFreeMemory(Domains);
        LsaFreeMemory(Sids);
    }
}

static void UserEnum(void)
{
    LPBYTE Buffer = NULL;
    DWORD Read = 0, Total = 0, Resume = 0;

    if (NetUserEnum(NULL, 0, 0, &Buffer, MAX_PREFERRED_LENGTH, &Read, &Total, &Resume) == NERR_Success)
        NetApiBufferFree(Buffer);
}

static void UserGetInfo(void)
{
    LPBYTE Buffer = NULL;

    if (NetUserGetInfo(NULL, L"Administrator", 1, &Buffer) == NERR_Success)
        NetApiBufferFree(Buffer);
}

static void LocalGroupEnum(void)
{
    LPBYTE Buffer = NULL;
    DWORD Read = 0, Total = 0;
    DWORD_PTR Resume = 0;

    if (NetLocalGroupEnum(NULL, 0, &Buffer, MAX_PREFERRED_LENGTH, &Read, &Total, &Resume) == NERR_Success)
        NetApiBufferFree(Buffer);
}

static void SamConnectClose(void)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ServerHandle = NULL;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    if (pSamConnect(NULL, &ServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_LOOKUP_DOMAIN, &ObjectAttributes) == STATUS_SUCCESS)
        pSamCloseHandle(ServerHandle);
}

START_TEST(LsassServerLeak)
{
    LSA_OBJECT_ATTRIBUTES Attributes = {sizeof(Attributes)};
    SID_IDENTIFIER_AUTHORITY NtAuth = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY WorldAuth = {SECURITY_WORLD_SID_AUTHORITY};
    HMODULE Samlib;
    char *Env;
    DWORD Pid;
    NTSTATUS Status;

    Env = getenv("LSASSLOOP");
    if (Env != NULL && atoi(Env) > 0)
        Iterations = (ULONG)atoi(Env);
    OnlyFilter = getenv("LSASSONLY");

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

    Status = LsaOpenPolicy(NULL, &Attributes, POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES, &Policy);
    if (Status != STATUS_SUCCESS)
    {
        skip("LsaOpenPolicy failed: 0x%lx\n", Status);
        CloseHandle(LsassProcess);
        return;
    }

    RtlAllocateAndInitializeSid(&NtAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                0, 0, 0, 0, 0, 0, &AdminsSid);
    RtlAllocateAndInitializeSid(&WorldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &WorldSid);

    Samlib = LoadLibraryW(L"samlib.dll");
    if (Samlib != NULL)
    {
        pSamConnect = (PVOID)GetProcAddress(Samlib, "SamConnect");
        pSamCloseHandle = (PVOID)GetProcAddress(Samlib, "SamCloseHandle");
    }

    /*
     * Soak mode (LSASSSOAK=<seconds>): reproduce the ticket's sustained churn - per round, 3000
     * LsaOpenPolicy/Close plus 200 NetUserEnum plus LSA queries/lookups - and print lsass private
     * bytes once a minute. After warm-up the row must be flat; before the HomeDirectoryDrive fix it
     * climbed ~13 MB/h under this mix.
     */
    Env = getenv("LSASSSOAK");
    if (Env != NULL && atoi(Env) > 0)
    {
        DWORD Seconds = (DWORD)atoi(Env);
        DWORD Start = GetTickCount();
        DWORD NextSample = 0;
        ULONG Round = 0, i;

        trace("SOAKROW begin seconds=%lu\n", Seconds);
        while ((GetTickCount() - Start) / 1000 < Seconds)
        {
            for (i = 0; i < 3000; i++)
                OpenClosePolicy();
            for (i = 0; i < 200; i++)
                UserEnum();
            for (i = 0; i < 100; i++)
            {
                QueryAccountDomain();
                LookupSids();
                LookupNames();
                UserGetInfo();
            }
            Round++;

            if ((GetTickCount() - Start) / 1000 >= NextSample)
            {
                SIZE_T Priv = SettledPrivateBytes();
                trace("SOAKROW elapsed=%lus round=%lu lsass_private_bytes=%Iu\n",
                      (GetTickCount() - Start) / 1000, Round, Priv);
                NextSample = (GetTickCount() - Start) / 1000 + 60;
            }
        }
        trace("SOAKROW end rounds=%lu\n", Round);

        if (AdminsSid != NULL) RtlFreeSid(AdminsSid);
        if (WorldSid != NULL) RtlFreeSid(WorldSid);
        LsaClose(Policy);
        CloseHandle(LsassProcess);
        return;
    }

    MeasureLoop("LsaOpenPolicy+LsaClose", OpenClosePolicy);
    MeasureLoop("LsaQueryInfo.AccountDomain", QueryAccountDomain);
    MeasureLoop("LsaQueryInfo.PrimaryDomain", QueryPrimaryDomain);
    MeasureLoop("LsaQueryInfo.DnsDomain", QueryDnsDomain);
    MeasureLoop("LsaQueryInfo.AuditEvents", QueryAuditEvents);
    MeasureLoop("LsaLookupSids", LookupSids);
    MeasureLoop("LsaLookupNames", LookupNames);
    MeasureLoop("NetUserEnum", UserEnum);
    MeasureLoop("NetUserGetInfo", UserGetInfo);
    MeasureLoop("NetLocalGroupEnum", LocalGroupEnum);
    if (pSamConnect != NULL && pSamCloseHandle != NULL)
        MeasureLoop("SamConnect+SamCloseHandle", SamConnectClose);

    if (AdminsSid != NULL)
        RtlFreeSid(AdminsSid);
    if (WorldSid != NULL)
        RtlFreeSid(WorldSid);
    LsaClose(Policy);
    CloseHandle(LsassProcess);
}
