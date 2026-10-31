/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for RtlFlsGetValue and RtlFlsSetValue as seen through the API, with the kernel32 FLS functions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PFN_FlsGet)(ULONG, PVOID *);
typedef NTSTATUS (NTAPI *PFN_FlsSet)(ULONG, PVOID);
typedef NTSTATUS (NTAPI *PFN_FlsAlloc)(PVOID, PULONG);
typedef NTSTATUS (NTAPI *PFN_FlsFree)(ULONG);

static PFN_FlsGet pGet;
static PFN_FlsSet pSet;
static ULONG ThreadIndex;
static NTSTATUS ThreadGetStatus, ThreadSetStatus;
static PVOID ThreadFirstValue, ThreadSecondValue;

static DWORD WINAPI ThreadProc(LPVOID Param)
{
    PVOID Value = (PVOID)(ULONG_PTR)0xDEADBEEF;

    /* a thread that never touched FLS: the main thread's value is not visible, and the call is the first use */
    ThreadGetStatus = pGet(ThreadIndex, &Value);
    ThreadFirstValue = Value;
    ThreadSetStatus = pSet(ThreadIndex, (PVOID)(ULONG_PTR)0x5678);
    Value = NULL;
    pGet(ThreadIndex, &Value);
    ThreadSecondValue = Value;
    return 0;
}

START_TEST(RtlFlsValue)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_FlsAlloc pAlloc = (PFN_FlsAlloc)GetProcAddress(Ntdll, "RtlFlsAlloc");
    PFN_FlsFree pFree = (PFN_FlsFree)GetProcAddress(Ntdll, "RtlFlsFree");
    NTSTATUS Status;
    PVOID Value;
    ULONG Index;
    DWORD Fls;
    HANDLE Thread;

    pGet = (PFN_FlsGet)GetProcAddress(Ntdll, "RtlFlsGetValue");
    pSet = (PFN_FlsSet)GetProcAddress(Ntdll, "RtlFlsSetValue");
    if (!pGet || !pSet || !pAlloc || !pFree)
    {
        ok(!is_reactos(), "RtlFlsGetValue, RtlFlsSetValue, RtlFlsAlloc or RtlFlsFree is not exported by ntdll.dll\n");
        skip("the FLS value functions are not available\n");
        return;
    }

    Status = pAlloc(NULL, &Index);
    ok(Status == STATUS_SUCCESS && Index != 0, "RtlFlsAlloc: %lx %lu\n", Status, Index);

    Status = pSet(Index, (PVOID)(ULONG_PTR)0x1234);
    ok(Status == STATUS_SUCCESS, "RtlFlsSetValue: %lx\n", Status);
    Value = NULL;
    Status = pGet(Index, &Value);
    ok(Status == STATUS_SUCCESS && Value == (PVOID)(ULONG_PTR)0x1234, "RtlFlsGetValue: %lx %p\n", Status, Value);
    ok(FlsGetValue(Index) == (PVOID)(ULONG_PTR)0x1234, "FlsGetValue sees the value of RtlFlsSetValue\n");

    ok(FlsSetValue(Index, (PVOID)(ULONG_PTR)0x4321), "FlsSetValue failed with %lu\n", GetLastError());
    Value = NULL;
    Status = pGet(Index, &Value);
    ok(Status == STATUS_SUCCESS && Value == (PVOID)(ULONG_PTR)0x4321, "RtlFlsGetValue sees the value of FlsSetValue: %lx %p\n", Status, Value);

    Fls = FlsAlloc(NULL);
    ok(Fls != FLS_OUT_OF_INDEXES, "FlsAlloc failed\n");
    Value = (PVOID)(ULONG_PTR)0xDEADBEEF;
    Status = pGet(Fls, &Value);
    ok(Status == STATUS_SUCCESS && Value == NULL, "a fresh index of FlsAlloc: %lx %p\n", Status, Value);
    FlsFree(Fls);

    /* the indexes 0 and 4080 and up are refused, the output is not touched */
    Value = (PVOID)(ULONG_PTR)0xDEADBEEF;
    Status = pGet(0, &Value);
    ok(Status == STATUS_INVALID_PARAMETER && Value == (PVOID)(ULONG_PTR)0xDEADBEEF, "get index 0: %lx %p\n", Status, Value);
    Status = pSet(0, (PVOID)(ULONG_PTR)1);
    ok(Status == STATUS_INVALID_PARAMETER, "set index 0: %lx\n", Status);
    Status = pGet(4080, &Value);
    ok(Status == STATUS_INVALID_PARAMETER && Value == (PVOID)(ULONG_PTR)0xDEADBEEF, "get index 4080: %lx %p\n", Status, Value);
    Status = pSet(4080, (PVOID)(ULONG_PTR)1);
    ok(Status == STATUS_INVALID_PARAMETER, "set index 4080: %lx\n", Status);
    Status = pGet(5000, &Value);
    ok(Status == STATUS_INVALID_PARAMETER, "get index 5000: %lx\n", Status);
    Status = pSet(4079, (PVOID)(ULONG_PTR)0x77);
    ok(Status == STATUS_SUCCESS, "set index 4079, which was never allocated: %lx\n", Status);
    Value = NULL;
    Status = pGet(4079, &Value);
    ok(Status == STATUS_SUCCESS && Value == (PVOID)(ULONG_PTR)0x77, "get index 4079: %lx %p\n", Status, Value);
    pSet(4079, NULL);

    /* the values are per thread */
    ThreadIndex = Index;
    Thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (Thread)
    {
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
        ok(ThreadGetStatus == STATUS_SUCCESS && ThreadFirstValue == NULL,
           "a thread's first read: %lx %p\n", ThreadGetStatus, ThreadFirstValue);
        ok(ThreadSetStatus == STATUS_SUCCESS, "a thread's first write: %lx\n", ThreadSetStatus);
        ok(ThreadSecondValue == (PVOID)(ULONG_PTR)0x5678, "a thread's own value: %p\n", ThreadSecondValue);
    }
    Value = NULL;
    pGet(Index, &Value);
    ok(Value == (PVOID)(ULONG_PTR)0x4321, "the main thread's value is unchanged: %p\n", Value);

    pFree(Index);
}
