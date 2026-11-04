/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Registry change notify requests (pool tag CmNn) are released on every path:
 *              completion, key close, thread exit and process exit
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define SystemPoolTagInformationClass   22
#define CYCLES                          100
#define SLACK                           8
#define TAG_CMNN                        ('C' | ('m' << 8) | ('N' << 16) | ((ULONG)'n' << 24))
#define FILTER                          (REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET)

typedef LONG (WINAPI *PNT_QUERY_SYSTEM_INFORMATION)(ULONG, PVOID, ULONG, PULONG);
typedef VOID (NTAPI *PIO_APC)(PVOID, PVOID, ULONG);
typedef LONG (NTAPI *PNT_NOTIFY_CHANGE_KEY)(HANDLE, HANDLE, PIO_APC, PVOID, PVOID, ULONG, BOOLEAN,
                                            PVOID, ULONG, BOOLEAN);

typedef struct _POOL_TAG_ENTRY
{
    ULONG TagUlong;
    ULONG PagedAllocs;
    ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
} POOL_TAG_ENTRY;

static const WCHAR KeyName[] = L"Software\\ReactOS_RegNotifyLeak";
static PNT_NOTIFY_CHANGE_KEY pNtNotifyChangeKey;
static PNT_QUERY_SYSTEM_INFORMATION pNtQuerySystemInformation;
static volatile LONG ApcCount;

/* Outstanding CmNn allocations; FALSE if the pool tags cannot be read */
static BOOL QueryCmNn(LONG *Live)
{
    ULONG Size = 256 * 1024, Returned = 0, Count, i;
    PUCHAR Buffer;
    LONG Status;

    for (;;)
    {
        Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Buffer)
            return FALSE;
        Status = pNtQuerySystemInformation(SystemPoolTagInformationClass, Buffer, Size, &Returned);
        if (Status != (LONG)0xC0000004 || Size >= 16 * 1024 * 1024)
            break;
        HeapFree(GetProcessHeap(), 0, Buffer);
        Size *= 2;
    }
    if (Status < 0)
    {
        HeapFree(GetProcessHeap(), 0, Buffer);
        return FALSE;
    }

    Count = *(PULONG)Buffer;
    *Live = 0;
    for (i = 0; i < Count; i++)
    {
        POOL_TAG_ENTRY *Entry = (POOL_TAG_ENTRY *)(Buffer + sizeof(SIZE_T) + i * sizeof(POOL_TAG_ENTRY));
        if (Entry->TagUlong == TAG_CMNN)
            *Live += (LONG)(Entry->PagedAllocs - Entry->PagedFrees) +
                     (LONG)(Entry->NonPagedAllocs - Entry->NonPagedFrees);
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
    return TRUE;
}

static HKEY OpenTestKey(void)
{
    HKEY hKey = NULL;
    LONG Err = RegCreateKeyExW(HKEY_CURRENT_USER, KeyName, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    ok_dec(Err, ERROR_SUCCESS);
    return hKey;
}

static void Touch(HKEY hKey)
{
    static DWORD Value;
    Value++;
    RegSetValueExW(hKey, L"v", 0, REG_DWORD, (BYTE *)&Value, sizeof(Value));
}

static VOID NTAPI CountApc(PVOID Context, PVOID Iosb, ULONG Reserved)
{
    InterlockedIncrement(&ApcCount);
}

typedef struct _ARM
{
    HKEY hKey;
    HANDLE hEvent;
    BOOL UseApc;
    DWORD Linger;       /* thread stays alive this long after arming */
    BOOL Alertable;     /* ... and sleeps alertably */
    HANDLE hArmed;
} ARM;

/* Arm one request on the calling thread; thread exits right after */
static DWORD WINAPI ArmThread(PVOID Param)
{
    ARM *Arm = Param;
    static struct { ULONG_PTR Status; ULONG_PTR Info; } Iosb;   /* never read back, shared */
    LONG Status;

    if (Arm->UseApc)
        Status = pNtNotifyChangeKey(Arm->hKey, NULL, CountApc, NULL, &Iosb, FILTER, FALSE, NULL, 0, TRUE);
    else
        Status = RegNotifyChangeKeyValue(Arm->hKey, FALSE, FILTER, Arm->hEvent, TRUE);
    ok(Status == 0x103 || Status == 0, "arm returned 0x%lx\n", (long)Status);
    SetEvent(Arm->hArmed);
    if (Arm->Linger)
        SleepEx(Arm->Linger, Arm->Alertable);
    return 0;
}

/* thread arms (event or APC), lingers, exits; then the main thread acts on the key */
enum { END_CLOSE, END_CHANGE_CLOSE, END_CHANGE_ONLY };

static void RunThreadCycle(BOOL UseApc, DWORD Linger, BOOL Alertable, int End)
{
    ARM Arm = {0};
    HANDLE hThread;

    Arm.hKey = OpenTestKey();
    Arm.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    Arm.hArmed = CreateEventW(NULL, TRUE, FALSE, NULL);
    Arm.UseApc = UseApc;
    Arm.Linger = Linger;
    Arm.Alertable = Alertable;
    hThread = CreateThread(NULL, 0, ArmThread, &Arm, 0, NULL);
    WaitForSingleObject(Arm.hArmed, 5000);
    if (End != END_CLOSE)
        Touch(Arm.hKey);
    WaitForSingleObject(hThread, 5000);
    if (End != END_CHANGE_ONLY)
        Touch(Arm.hKey);
    RegCloseKey(Arm.hKey);
    CloseHandle(hThread);
    CloseHandle(Arm.hEvent);
    CloseHandle(Arm.hArmed);
}

static void RunSameThreadCycle(BOOL Change, BOOL ThreadAgnostic)
{
    HKEY hKey = OpenTestKey();
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    LONG Err;

    Err = RegNotifyChangeKeyValue(hKey, FALSE, FILTER | (ThreadAgnostic ? 0x10000000 : 0), hEvent, TRUE);
    ok_dec(Err, ERROR_SUCCESS);
    if (Change)
    {
        Touch(hKey);
        WaitForSingleObject(hEvent, 5000);
    }
    RegCloseKey(hKey);
    CloseHandle(hEvent);
}

typedef struct _SYNCWAIT { HKEY hKey; HANDLE hStarted; } SYNCWAIT;

static DWORD WINAPI SyncThread(PVOID Param)
{
    SYNCWAIT *Wait = Param;
    SetEvent(Wait->hStarted);
    RegNotifyChangeKeyValue(Wait->hKey, FALSE, FILTER, NULL, FALSE);
    return 0;
}

/* A synchronous wait ended by the key handle closing */
static void RunSyncCycle(void)
{
    SYNCWAIT Wait;
    HANDLE hThread;

    Wait.hKey = OpenTestKey();
    Wait.hStarted = CreateEventW(NULL, TRUE, FALSE, NULL);
    hThread = CreateThread(NULL, 0, SyncThread, &Wait, 0, NULL);
    WaitForSingleObject(Wait.hStarted, 5000);
    Sleep(20);
    /* The waiting thread uses the same handle; closing it from here cancels the wait */
    RegCloseKey(Wait.hKey);
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(Wait.hStarted);
}

typedef void (*CYCLE_FN)(void);
static void Check(const char *Name, LONG *Before, void (*Fn)(PVOID), PVOID Arg)
{
    LONG After;
    int i;

    for (i = 0; i < CYCLES; i++)
        Fn(Arg);
    Sleep(300);
    if (!QueryCmNn(&After))
        return;
    trace("%s: CmNn %ld -> %ld\n", Name, (long)*Before, (long)After);
    ok(After - *Before <= SLACK, "%s: CmNn grew by %ld over %d cycles (%ld -> %ld)\n",
       Name, (long)(After - *Before), CYCLES, (long)*Before, (long)After);
    *Before = After;
}

static void FnThread(PVOID Arg)
{
    ULONG_PTR V = (ULONG_PTR)Arg;
    RunThreadCycle(!!(V & 1), (V & 2) ? 50 : 0, !!(V & 4), (int)(V >> 4));
}
static void FnSame(PVOID Arg)  { RunSameThreadCycle(!!((ULONG_PTR)Arg & 1), !!((ULONG_PTR)Arg & 2)); }
static void FnSync(PVOID Arg)  { RunSyncCycle(); }

/* Requests armed again on the same handle while one is pending are all kept, and one change completes them all
 * (what makes a service that re-arms on a poll timeout pile them up) */
static void TestStackedRequests(void)
{
    HKEY hKey = OpenTestKey();
    HANDLE Events[3];
    int i;

    for (i = 0; i < 3; i++)
    {
        Events[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        ok_dec(RegNotifyChangeKeyValue(hKey, FALSE, FILTER, Events[i], TRUE), ERROR_SUCCESS);
    }
    Touch(hKey);
    for (i = 0; i < 3; i++)
    {
        ok_hex(WaitForSingleObject(Events[i], 5000), WAIT_OBJECT_0);
        CloseHandle(Events[i]);
    }
    RegCloseKey(hKey);
}

/* Child: arm requests from worker threads and die without releasing anything */
static void ChildMain(int Mode)
{
    int i;

    for (i = 0; i < 20; i++)
    {
        ARM *Arm = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Arm));
        Arm->hKey = OpenTestKey();
        Arm->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        Arm->hArmed = CreateEventW(NULL, TRUE, FALSE, NULL);
        Arm->UseApc = (Mode == 1);
        Arm->Linger = (i & 1) ? 0 : 30000;      /* half of the threads stay alive to the end */
        Arm->Alertable = FALSE;
        CreateThread(NULL, 0, ArmThread, Arm, 0, NULL);
        WaitForSingleObject(Arm->hArmed, 5000);
    }
    if (Mode == 2)
        ExitProcess(0);
    TerminateProcess(GetCurrentProcess(), 0);
}

static void FnProcess(PVOID Arg)
{
    WCHAR Cmd[MAX_PATH + 64], Path[MAX_PATH];
    STARTUPINFOW Si = {sizeof(Si)};
    PROCESS_INFORMATION Pi;

    GetModuleFileNameW(NULL, Path, MAX_PATH);
    StringCbPrintfW(Cmd, sizeof(Cmd), L"\"%s\" RegNotifyLeak child%d", Path, (int)(ULONG_PTR)Arg);
    if (!CreateProcessW(NULL, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
    {
        skip("CreateProcess failed %lu\n", GetLastError());
        return;
    }
    WaitForSingleObject(Pi.hProcess, 20000);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
}

START_TEST(RegNotifyLeak)
{
    LONG Live;
    PCWSTR Cmd = GetCommandLineW();
    PCWSTR Child = wcsstr(Cmd, L"RegNotifyLeak child");

    pNtNotifyChangeKey = (PNT_NOTIFY_CHANGE_KEY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtNotifyChangeKey");
    pNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                                             "NtQuerySystemInformation");
    if (Child)
    {
        ChildMain(Child[wcslen(L"RegNotifyLeak child")] - L'0');
        return;
    }

    if (!pNtNotifyChangeKey || !pNtQuerySystemInformation)
    {
        skip("Native API missing\n");
        return;
    }

    RegDeleteKeyW(HKEY_CURRENT_USER, KeyName);

    /* Warm up, then take the baseline */
    FnSame((PVOID)0);
    FnThread((PVOID)0);
    Sleep(200);
    if (!QueryCmNn(&Live))
    {
        skip("SystemPoolTagInformation is not available\n");
        return;
    }

    /* Same thread, event only */
    Check("close while pending", &Live, FnSame, (PVOID)0);
    Check("change then close", &Live, FnSame, (PVOID)1);
    Check("thread agnostic, close while pending", &Live, FnSame, (PVOID)2);
    Check("thread agnostic, change then close", &Live, FnSame, (PVOID)3);
    /* arg bits: 1 = APC routine, 2 = thread lingers, 4 = alertable, (End << 4) */
    Check("event, thread exits pending, key closed", &Live, FnThread, (PVOID)(0 | (END_CLOSE << 4)));
    Check("event, thread exits pending, key changed then closed", &Live, FnThread, (PVOID)(0 | (END_CHANGE_CLOSE << 4)));
    Check("event, key changed while thread alive, then exits", &Live, FnThread, (PVOID)(2 | (END_CHANGE_ONLY << 4)));
    Check("APC, alertable thread, key changed", &Live, FnThread, (PVOID)(1 | 2 | 4 | (END_CHANGE_ONLY << 4)));
    Check("APC, thread exits pending, key closed", &Live, FnThread, (PVOID)(1 | (END_CLOSE << 4)));
    Check("APC, thread exits pending, key changed", &Live, FnThread, (PVOID)(1 | (END_CHANGE_CLOSE << 4)));
    Check("APC, non alertable thread, key changed, thread exits", &Live, FnThread, (PVOID)(1 | 2 | (END_CHANGE_ONLY << 4)));
    Check("synchronous wait ended by key close", &Live, FnSync, NULL);
    Check("process terminated with pending requests", &Live, FnProcess, (PVOID)0);
    Check("process terminated with pending APC requests", &Live, FnProcess, (PVOID)1);
    Check("process exits with pending requests", &Live, FnProcess, (PVOID)2);

    TestStackedRequests();

    /* A service that watches a key and also polls must not arm again on every timeout: each request stays queued
     * on its handle (iphlpsvc did, every 10 seconds, about 360 an hour) */
    if (QueryCmNn(&Live))
    {
        LONG After;

        Sleep(65000);
        if (QueryCmNn(&After))
        {
            trace("idle for 65 s: CmNn %ld -> %ld\n", (long)Live, (long)After);
            ok(After - Live <= 2, "CmNn grew by %ld while the system was idle (%ld -> %ld)\n",
               (long)(After - Live), (long)Live, (long)After);
        }
    }

    RegDeleteKeyW(HKEY_CURRENT_USER, KeyName);
}
