/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the counter value calls of the PerfLib V2 provider API: Perf{Set,Increment,Decrement}
 *              {ULong,ULongLong}CounterValue, PerfQueryInstance, and the layout of an instance block
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results are those of Windows 10 22H2 (x64 and x86). An unregistered provider works there too.
 */

#include "precomp.h"

typedef struct { GUID CounterSetGuid, ProviderGuid; ULONG NumCounters, InstanceType; } CSET;
typedef struct { ULONG CounterId, Type; ULONGLONG Attrib; ULONG Size, DetailLevel; LONG Scale; ULONG Offset; } CCTR;
typedef struct { GUID CounterSetGuid; ULONG dwSize, InstanceId, InstanceNameOffset, InstanceNameSize; } CINST;

typedef ULONG (WINAPI *FN_START)(GUID *, void *, HANDLE *);
typedef ULONG (WINAPI *FN_STOP)(HANDLE);
typedef ULONG (WINAPI *FN_SETINFO)(HANDLE, CSET *, ULONG);
typedef CINST *(WINAPI *FN_CREATE)(HANDLE, const GUID *, const WCHAR *, ULONG);
typedef ULONG (WINAPI *FN_DELETE)(HANDLE, CINST *);
typedef ULONG (WINAPI *FN_U4)(HANDLE, CINST *, ULONG, ULONG);
typedef ULONG (WINAPI *FN_U8)(HANDLE, CINST *, ULONG, ULONGLONG);
typedef CINST *(WINAPI *FN_QUERY)(HANDLE, const GUID *, const WCHAR *, ULONG);

#define PENDING 0xdeadf00d

static const GUID ProviderGuid = { 0x7a1f3c20, 0x2222, 0x4333, { 0x94, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa } };
static const GUID SetGuid      = { 0x7a1f3c21, 0x2222, 0x4333, { 0x94, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa } };

START_TEST(PerfCounterValues)
{
    HMODULE h = GetModuleHandleW(L"advapi32.dll");
    FN_START pStart = (FN_START)GetProcAddress(h, "PerfStartProviderEx");
    FN_STOP pStop = (FN_STOP)GetProcAddress(h, "PerfStopProvider");
    FN_SETINFO pSetInfo = (FN_SETINFO)GetProcAddress(h, "PerfSetCounterSetInfo");
    FN_CREATE pCreate = (FN_CREATE)GetProcAddress(h, "PerfCreateInstance");
    FN_DELETE pDelete = (FN_DELETE)GetProcAddress(h, "PerfDeleteInstance");
    FN_U4 pSetU4 = (FN_U4)GetProcAddress(h, "PerfSetULongCounterValue");
    FN_U4 pInc4 = (FN_U4)GetProcAddress(h, "PerfIncrementULongCounterValue");
    FN_U4 pDec4 = (FN_U4)GetProcAddress(h, "PerfDecrementULongCounterValue");
    FN_U8 pSetU8 = (FN_U8)GetProcAddress(h, "PerfSetULongLongCounterValue");
    FN_U8 pInc8 = (FN_U8)GetProcAddress(h, "PerfIncrementULongLongCounterValue");
    FN_U8 pDec8 = (FN_U8)GetProcAddress(h, "PerfDecrementULongLongCounterValue");
    FN_QUERY pQuery = (FN_QUERY)GetProcAddress(h, "PerfQueryInstance");
    GUID Provider = ProviderGuid;
    HANDLE Handle = NULL;
    struct { CSET Set; CCTR Counters[3]; } Template;
    CINST *Instance, *Found, *Second;
    ULONG Error;
    BYTE *Base;
    static int Target;

    if (!pSetU4 && is_reactos() && !GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount64"))
    {
        skip("No NT 6 exports\n");
        return;
    }
    ok(pStart && pStop && pSetInfo && pCreate && pDelete && pSetU4 && pInc4 && pDec4 && pSetU8 && pInc8 && pDec8 && pQuery,
       "not exported: %p %p %p %p %p %p %p %p %p %p %p %p\n",
       pStart, pStop, pSetInfo, pCreate, pDelete, pSetU4, pInc4, pDec4, pSetU8, pInc8, pDec8, pQuery);
    if (!pStart || !pStop || !pSetInfo || !pCreate || !pDelete || !pSetU4 || !pInc4 || !pDec4 || !pSetU8 || !pInc8 || !pDec8 || !pQuery)
        return;

    Error = pStart(&Provider, NULL, &Handle);
    ok(Error == ERROR_SUCCESS && Handle, "PerfStartProviderEx: %lu\n", Error);
    if (Error != ERROR_SUCCESS)
        return;

    ZeroMemory(&Template, sizeof(Template));
    Template.Set.CounterSetGuid = SetGuid;
    Template.Set.ProviderGuid = ProviderGuid;
    Template.Set.NumCounters = 3;
    Template.Set.InstanceType = 2; /* PERF_COUNTERSET_MULTI_INSTANCES */
    Template.Counters[0].CounterId = 1;
    Template.Counters[0].Type = 0x10000;   /* PERF_COUNTER_RAWCOUNT */
    Template.Counters[0].Size = 4;
    Template.Counters[1].CounterId = 2;
    Template.Counters[1].Type = 0x10100;   /* PERF_COUNTER_LARGE_RAWCOUNT */
    Template.Counters[1].Size = 8;
    Template.Counters[2].CounterId = 3;
    Template.Counters[2].Type = 0x10000;
    Template.Counters[2].Attrib = 1;       /* PERF_ATTRIB_BY_REFERENCE */
    Template.Counters[2].Size = sizeof(PVOID);

    Error = pSetInfo(Handle, &Template.Set, sizeof(Template));
    ok(Error == ERROR_SUCCESS, "PerfSetCounterSetInfo: %lu\n", Error);
    /* the system writes the offsets (from the start of the instance block) into the caller's template */
    ok(Template.Counters[0].Offset == 32 && Template.Counters[1].Offset == 40 && Template.Counters[2].Offset == 48,
       "offsets %lu %lu %lu\n", Template.Counters[0].Offset, Template.Counters[1].Offset, Template.Counters[2].Offset);

    SetLastError(PENDING);
    Instance = pCreate(Handle, &SetGuid, L"inst1", 7);
    ok(Instance != NULL && GetLastError() == PENDING, "PerfCreateInstance: %p, %lu\n", Instance, GetLastError());
    if (!Instance)
    {
        pStop(Handle);
        return;
    }
    Base = (BYTE *)Instance;
    ok(Instance->dwSize == 72 && Instance->InstanceId == 7 && Instance->InstanceNameOffset == 56 && Instance->InstanceNameSize == 12,
       "instance block: size %lu, id %lu, name at %lu (%lu bytes)\n", Instance->dwSize, Instance->InstanceId,
       Instance->InstanceNameOffset, Instance->InstanceNameSize);
    ok(!wcscmp((WCHAR *)(Base + Instance->InstanceNameOffset), L"inst1"), "instance name\n");

    /* 32-bit counter */
    Error = pSetU4(Handle, Instance, 1, 0x11223344);
    ok(Error == ERROR_SUCCESS && *(ULONG *)(Base + 32) == 0x11223344, "set: %lu, %lx\n", Error, *(ULONG *)(Base + 32));
    Error = pInc4(Handle, Instance, 1, 5);
    ok(Error == ERROR_SUCCESS && *(ULONG *)(Base + 32) == 0x11223349, "increment: %lu, %lx\n", Error, *(ULONG *)(Base + 32));
    Error = pDec4(Handle, Instance, 1, 2);
    ok(Error == ERROR_SUCCESS && *(ULONG *)(Base + 32) == 0x11223347, "decrement: %lu, %lx\n", Error, *(ULONG *)(Base + 32));
    Error = pDec4(Handle, Instance, 1, 0x20000000);
    ok(Error == ERROR_SUCCESS && *(ULONG *)(Base + 32) == 0xf1223347, "decrement below zero wraps: %lu, %lx\n", Error, *(ULONG *)(Base + 32));

    /* 64-bit counter */
    Error = pSetU8(Handle, Instance, 2, 0x1122334455667788ULL);
    ok(Error == ERROR_SUCCESS && *(ULONGLONG *)(Base + 40) == 0x1122334455667788ULL, "set 64: %lu\n", Error);
    Error = pInc8(Handle, Instance, 2, 0x100000000ULL);
    ok(Error == ERROR_SUCCESS && *(ULONGLONG *)(Base + 40) == 0x1122334555667788ULL, "increment 64: %lu\n", Error);
    Error = pDec8(Handle, Instance, 2, 1);
    ok(Error == ERROR_SUCCESS && *(ULONGLONG *)(Base + 40) == 0x1122334555667787ULL, "decrement 64: %lu\n", Error);

    /* the wrong width, a by-reference counter, an unknown counter, a bad handle, no instance */
    ok(pSetU8(Handle, Instance, 1, 1) == ERROR_INVALID_PARAMETER, "64-bit call on a 32-bit counter\n");
    ok(pSetU4(Handle, Instance, 2, 1) == ERROR_INVALID_PARAMETER, "32-bit call on a 64-bit counter\n");
    ok(pSetU4(Handle, Instance, 3, 1) == ERROR_INVALID_PARAMETER, "32-bit call on a by-reference counter\n");
    ok(pInc4(Handle, Instance, 3, 1) == ERROR_INVALID_PARAMETER, "increment of a by-reference counter\n");
    ok(pSetU4(Handle, Instance, 99, 1) == ERROR_NOT_FOUND, "unknown counter\n");
    ok(pSetU4(Handle, NULL, 1, 1) == ERROR_INVALID_PARAMETER, "NULL instance\n");
    Error = pSetU4((HANDLE)(ULONG_PTR)0x1234, Instance, 1, 1);
    ok(Error == ERROR_SUCCESS && *(ULONG *)(Base + 32) == 1, "the provider handle is not looked at: %lu\n", Error);
    ok(*(ULONGLONG *)(Base + 40) == 0x1122334555667787ULL, "the neighbour counter is untouched\n");
    (void)Target;

    /* PerfQueryInstance: the name (not case sensitive) and the identifier both have to match */
    SetLastError(PENDING);
    Found = pQuery(Handle, &SetGuid, L"inst1", 7);
    ok(Found == Instance && GetLastError() == PENDING, "query: %p, %lu\n", Found, GetLastError());
    Found = pQuery(Handle, &SetGuid, L"INST1", 7);
    ok(Found == Instance, "query, other case: %p\n", Found);
    SetLastError(PENDING);
    Found = pQuery(Handle, &SetGuid, L"inst1", 8);
    ok(Found == NULL && GetLastError() == ERROR_NOT_FOUND, "query, wrong id: %p, %lu\n", Found, GetLastError());
    SetLastError(PENDING);
    Found = pQuery(Handle, &SetGuid, L"nosuch", 7);
    ok(Found == NULL && GetLastError() == ERROR_NOT_FOUND, "query, wrong name: %p, %lu\n", Found, GetLastError());
    SetLastError(PENDING);
    Found = pQuery(Handle, &ProviderGuid, L"inst1", 7);
    ok(Found == NULL && GetLastError() == ERROR_NOT_FOUND, "query, a counter set that is not set: %p, %lu\n", Found, GetLastError());

    Second = pCreate(Handle, &SetGuid, L"inst2", 8);
    ok(Second != NULL, "second instance: %lu\n", GetLastError());
    if (Second)
    {
        ok(pQuery(Handle, &SetGuid, L"inst2", 8) == Second, "query of the second instance\n");
        ok(pQuery(Handle, &SetGuid, L"inst1", 7) == Instance, "query of the first instance still\n");
    }

    Error = pDelete(Handle, Instance);
    ok(Error == ERROR_SUCCESS, "PerfDeleteInstance: %lu\n", Error);
    SetLastError(PENDING);
    Found = pQuery(Handle, &SetGuid, L"inst1", 7);
    ok(Found == NULL && GetLastError() == ERROR_NOT_FOUND, "query after the delete: %p, %lu\n", Found, GetLastError());

    Error = pStop(Handle);
    ok(Error == ERROR_SUCCESS, "PerfStopProvider: %lu\n", Error);
}
