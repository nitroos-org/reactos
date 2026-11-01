/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that lookups through the Dnscache service do not leak handles in it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <winsock2.h>
#include <windns.h>
#include <stdio.h>
#include <apitest.h>

/* SystemExtendedHandleInformation (64) entry layout */
typedef struct _TEST_HANDLE_ENTRY_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} TEST_HANDLE_ENTRY_EX;

typedef struct _TEST_HANDLE_INFO_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    TEST_HANDLE_ENTRY_EX Handles[1];
} TEST_HANDLE_INFO_EX;

typedef LONG (NTAPI *PFN_NTQSI)(ULONG, PVOID, ULONG, PULONG);

static PFN_NTQSI pNtQuerySystemInformation;

static DWORD GetDnscachePid(void)
{
    SC_HANDLE Scm, Service;
    SERVICE_STATUS_PROCESS Status;
    DWORD Needed = 0, Pid = 0;

    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!Scm)
        return 0;
    Service = OpenServiceW(Scm, L"Dnscache", SERVICE_QUERY_STATUS);
    if (Service)
    {
        if (QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO, (BYTE *)&Status, sizeof(Status), &Needed) &&
            Status.dwCurrentState == SERVICE_RUNNING)
        {
            Pid = Status.dwProcessId;
        }
        CloseServiceHandle(Service);
    }
    CloseServiceHandle(Scm);
    return Pid;
}

/* Handle count of a process from the system handle table; needs no access to the process */
static LONG GetHandleCount(DWORD Pid)
{
    ULONG Size = 1 << 20, Returned = 0;
    TEST_HANDLE_INFO_EX *Info;
    ULONG_PTR i;
    LONG Count = 0, Status;

    for (;;)
    {
        Info = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Info)
            return -1;
        Status = pNtQuerySystemInformation(64, Info, Size, &Returned);
        if (Status >= 0)
            break;
        HeapFree(GetProcessHeap(), 0, Info);
        if (Status != (LONG)0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */ || Size >= (64 << 20))
            return -1;
        Size = max(Size * 2, Returned + 0x10000);
    }
    for (i = 0; i < Info->NumberOfHandles; i++)
    {
        if (Info->Handles[i].UniqueProcessId == Pid)
            Count++;
    }
    HeapFree(GetProcessHeap(), 0, Info);
    return Count;
}

/* Every lookup of a name the cache cannot answer makes the service resolve it
 * itself; the handle count of its process must not grow with the number of lookups. */
START_TEST(DnscacheHandles)
{
    DWORD Pid, Start;
    LONG Before, After;
    PDNS_RECORD Record;
    DNS_STATUS DnsStatus;
    WCHAR Name[64] = { 0 };
    int i, Queries = 0;

    pNtQuerySystemInformation = (PFN_NTQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation)
    {
        skip("NtQuerySystemInformation not found\n");
        return;
    }
    Pid = GetDnscachePid();
    if (!Pid)
    {
        skip("Dnscache service is not running\n");
        return;
    }

    /* Warm-up: the first lookups start the RPC and resolver threads of the service */
    for (i = 0; i < 3; i++)
    {
        Record = NULL;
        _snwprintf(Name, _countof(Name) - 1, L"rostest-warm%lu-%d.invalid", GetTickCount(), i);
        DnsQuery_W(Name, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &Record, NULL);
        if (Record)
            DnsRecordListFree(Record, DnsFreeRecordList);
    }
    Sleep(2000);
    Before = GetHandleCount(Pid);
    ok(Before > 0, "Handle count of Dnscache (pid %lu) is %ld\n", Pid, Before);

    /* Unique names in the reserved .invalid domain: nothing caches them, so each
     * one is resolved (and fails) inside the service. Bounded in time for
     * machines whose DNS server does not answer. */
    Start = GetTickCount();
    for (i = 0; i < 40 && GetTickCount() - Start < 30000; i++)
    {
        Record = NULL;
        _snwprintf(Name, _countof(Name) - 1, L"rostest-leak%lu-%d.invalid", Start, i);
        DnsStatus = DnsQuery_W(Name, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &Record, NULL);
        ok(DnsStatus != ERROR_SUCCESS, "Lookup of %ls succeeded\n", Name);
        if (Record)
            DnsRecordListFree(Record, DnsFreeRecordList);
        Queries++;
    }

    /* Let the connections of the calls above close */
    Sleep(3000);
    After = GetHandleCount(Pid);
    trace("%d lookups: Dnscache (pid %lu) handles %ld -> %ld\n", Queries, Pid, Before, After);
    if (Queries < 10)
    {
        skip("Only %d lookups completed in time\n", Queries);
        return;
    }
    ok(After - Before <= 4 + Queries / 5,
       "Dnscache handle count grew by %ld over %d lookups (%ld -> %ld)\n",
       After - Before, Queries, Before, After);
}
