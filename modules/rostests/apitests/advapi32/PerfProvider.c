/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the PerfLib V2 provider API: PerfStartProvider(Ex), PerfStopProvider,
 *              PerfSetCounterSetInfo, PerfCreateInstance, PerfSetCounterRefValue, PerfDeleteInstance
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Checks marked "winref10" were measured on Windows 10 22H2 (build 19045). The rest follows the
 * documented behaviour and is only checked on ReactOS.
 */

#include "precomp.h"

typedef struct { GUID CounterSetGuid, ProviderGuid; ULONG NumCounters, InstanceType; } CSET;
typedef struct { ULONG CounterId, Type; ULONGLONG Attrib; ULONG Size, DetailLevel; LONG Scale; ULONG Offset; } CCTR;
typedef struct { GUID CounterSetGuid; ULONG dwSize, InstanceId, InstanceNameOffset, InstanceNameSize; } CINST;
typedef struct { DWORD ContextSize, Reserved; void *Control, *Alloc, *Free, *MemContext; } CCTX;

typedef ULONG (WINAPI *FN_StartEx)(GUID *, CCTX *, HANDLE *);
typedef ULONG (WINAPI *FN_Start)(GUID *, void *, HANDLE *);
typedef ULONG (WINAPI *FN_SetInfo)(HANDLE, CSET *, ULONG);
typedef CINST *(WINAPI *FN_Create)(HANDLE, const GUID *, const WCHAR *, ULONG);
typedef ULONG (WINAPI *FN_Delete)(HANDLE, CINST *);
typedef ULONG (WINAPI *FN_RefValue)(HANDLE, CINST *, ULONG, void *);
typedef ULONG (WINAPI *FN_Stop)(HANDLE);

static const GUID ProviderGuid = { 0x7a1f3c10, 0x1111, 0x4222, { 0x93, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 } };
static const GUID SetGuid      = { 0x7a1f3c11, 0x1111, 0x4222, { 0x93, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 } };

static LONG AllocCalls, FreeCalls;
static void *CDECL TestAlloc(SIZE_T Size, void *Context)
{
    InterlockedIncrement(&AllocCalls);
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}
static void CDECL TestFree(void *Ptr, void *Context)
{
    InterlockedIncrement(&FreeCalls);
    HeapFree(GetProcessHeap(), 0, Ptr);
}

START_TEST(PerfProvider)
{
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    FN_StartEx pStartEx = (FN_StartEx)GetProcAddress(hAdvapi32, "PerfStartProviderEx");
    FN_Start pStart = (FN_Start)GetProcAddress(hAdvapi32, "PerfStartProvider");
    FN_SetInfo pSetInfo = (FN_SetInfo)GetProcAddress(hAdvapi32, "PerfSetCounterSetInfo");
    FN_Create pCreate = (FN_Create)GetProcAddress(hAdvapi32, "PerfCreateInstance");
    FN_Delete pDelete = (FN_Delete)GetProcAddress(hAdvapi32, "PerfDeleteInstance");
    FN_RefValue pRefValue = (FN_RefValue)GetProcAddress(hAdvapi32, "PerfSetCounterRefValue");
    FN_Stop pStop = (FN_Stop)GetProcAddress(hAdvapi32, "PerfStopProvider");
    GUID Guid = ProviderGuid;
    CCTX Context = { sizeof(Context) }, Zero = { 0 };
    HANDLE Provider, Provider2;
    ULONG Error;
    struct { CSET Set; CCTR Counters[2]; } Template;
    CINST *Instance, *Instance2;
    static int Target;

    if (!pStartEx && is_reactos() && !GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount64"))
    {
        skip("No NT 6 exports\n");
        return;
    }
    ok(pStartEx && pStart && pSetInfo && pCreate && pDelete && pRefValue && pStop,
       "Perf provider functions are not exported: %p %p %p %p %p %p %p\n",
       pStartEx, pStart, pSetInfo, pCreate, pDelete, pRefValue, pStop);
    if (!pStartEx || !pStart || !pSetInfo || !pCreate || !pDelete || !pRefValue || !pStop)
        return;

    /* winref10 */
    Provider = (HANDLE)(ULONG_PTR)0x1234;
    Error = pStartEx(&Guid, &Context, &Provider);
    ok(Error == ERROR_SUCCESS, "PerfStartProviderEx returned %lu\n", Error);
    ok(Provider && Provider != (HANDLE)(ULONG_PTR)0x1234, "no provider handle: %p\n", Provider);

    Provider2 = (HANDLE)(ULONG_PTR)0x1234;
    Error = pStartEx(NULL, &Context, &Provider2);
    ok(Error == ERROR_INVALID_PARAMETER, "NULL guid: %lu\n", Error);
    ok(Provider2 == (HANDLE)(ULONG_PTR)0x1234, "handle written on failure: %p\n", Provider2);

    Error = pStartEx(&Guid, &Context, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "NULL handle pointer: %lu\n", Error);

    Provider2 = (HANDLE)(ULONG_PTR)0x1234;
    Error = pStartEx(&Guid, &Zero, &Provider2);
    ok(Error == ERROR_INVALID_PARAMETER, "ContextSize 0: %lu\n", Error);
    ok(Provider2 == (HANDLE)(ULONG_PTR)0x1234, "handle written on failure: %p\n", Provider2);

    Provider2 = (HANDLE)(ULONG_PTR)0x1234;
    Error = pStartEx(&Guid, NULL, &Provider2);
    ok(Error == ERROR_SUCCESS, "NULL context: %lu\n", Error);
    ok(Provider2 && Provider2 != (HANDLE)(ULONG_PTR)0x1234, "no handle for a NULL context: %p\n", Provider2);
    if (Error == ERROR_SUCCESS && Provider2 != (HANDLE)(ULONG_PTR)0x1234)
    {
        Error = pStop(Provider2);
        ok(Error == ERROR_SUCCESS, "PerfStopProvider returned %lu\n", Error);
    }

    if (is_reactos())
    {
        /* documented, not measured: the V1-style entry point, a user allocator, instances and templates */
        Provider2 = NULL;
        Error = pStart(&Guid, NULL, &Provider2);
        ok(Error == ERROR_SUCCESS && Provider2, "PerfStartProvider: %lu, %p\n", Error, Provider2);
        if (Error == ERROR_SUCCESS)
            pStop(Provider2);

        ZeroMemory(&Template, sizeof(Template));
        Template.Set.CounterSetGuid = SetGuid;
        Template.Set.ProviderGuid = ProviderGuid;
        Template.Set.NumCounters = 2;
        Template.Set.InstanceType = 2; /* PERF_COUNTERSET_MULTI_INSTANCES */
        Template.Counters[0].CounterId = 1;
        Template.Counters[0].Type = 0x10000;
        Template.Counters[0].Size = 4;
        Template.Counters[1].CounterId = 2;
        Template.Counters[1].Type = 0x10000;
        Template.Counters[1].Attrib = 1; /* PERF_ATTRIB_BY_REFERENCE */
        Template.Counters[1].Size = sizeof(PVOID);
        Template.Counters[1].Offset = 8;

        ok(pSetInfo(Provider, &Template.Set, 0) == ERROR_INVALID_PARAMETER, "size 0\n");
        ok(pSetInfo(Provider, &Template.Set, sizeof(CSET)) == ERROR_INVALID_PARAMETER, "header only\n");
        ok(pSetInfo(Provider, NULL, sizeof(Template)) == ERROR_INVALID_PARAMETER, "NULL template\n");
        ok(pSetInfo(NULL, &Template.Set, sizeof(Template)) == ERROR_INVALID_PARAMETER, "NULL provider\n");

        SetLastError(0xdeadbeef);
        Instance = pCreate(Provider, &SetGuid, L"early", 1);
        ok(Instance == NULL && GetLastError() == ERROR_NOT_FOUND, "instance of an unset counter set: %p, %lu\n",
           Instance, GetLastError());

        Error = pSetInfo(Provider, &Template.Set, sizeof(Template));
        ok(Error == ERROR_SUCCESS, "PerfSetCounterSetInfo returned %lu\n", Error);
        Error = pSetInfo(Provider, &Template.Set, sizeof(Template));
        ok(Error == ERROR_ALREADY_EXISTS, "second PerfSetCounterSetInfo returned %lu\n", Error);

        Instance = pCreate(Provider, &SetGuid, L"alpha", 1);
        ok(Instance != NULL, "PerfCreateInstance failed: %lu\n", GetLastError());
        if (Instance)
        {
            ok(IsEqualGUID(&Instance->CounterSetGuid, &SetGuid), "wrong guid in the instance\n");
            ok(Instance->InstanceId == 1, "id %lu\n", Instance->InstanceId);
            ok(Instance->InstanceNameSize == 6 * sizeof(WCHAR), "name size %lu\n", Instance->InstanceNameSize);
            ok(Instance->InstanceNameOffset >= sizeof(CINST) && Instance->InstanceNameOffset < Instance->dwSize,
               "name offset %lu, size %lu\n", Instance->InstanceNameOffset, Instance->dwSize);
            ok(!wcscmp((WCHAR *)((BYTE *)Instance + Instance->InstanceNameOffset), L"alpha"), "name\n");

            Error = pRefValue(Provider, Instance, 2, &Target);
            ok(Error == ERROR_SUCCESS, "PerfSetCounterRefValue returned %lu\n", Error);
            Error = pRefValue(Provider, Instance, 1, &Target);
            ok(Error == ERROR_INVALID_PARAMETER, "not a by-reference counter: %lu\n", Error);
            Error = pRefValue(Provider, Instance, 99, &Target);
            ok(Error == ERROR_NOT_FOUND, "unknown counter: %lu\n", Error);
            Error = pRefValue(Provider, NULL, 2, &Target);
            ok(Error == ERROR_INVALID_PARAMETER, "NULL instance: %lu\n", Error);

            SetLastError(0xdeadbeef);
            Instance2 = pCreate(Provider, &SetGuid, L"ALPHA", 2);
            ok(Instance2 == NULL && GetLastError() == ERROR_ALREADY_EXISTS, "duplicate name: %p, %lu\n",
               Instance2, GetLastError());
            SetLastError(0xdeadbeef);
            Instance2 = pCreate(Provider, &SetGuid, NULL, 2);
            ok(Instance2 == NULL && GetLastError() == ERROR_INVALID_PARAMETER, "NULL name: %p, %lu\n",
               Instance2, GetLastError());

            Error = pDelete(Provider, Instance);
            ok(Error == ERROR_SUCCESS, "PerfDeleteInstance returned %lu\n", Error);
            Error = pDelete(Provider, NULL);
            ok(Error == ERROR_INVALID_PARAMETER, "PerfDeleteInstance(NULL): %lu\n", Error);

            Instance = pCreate(Provider, &SetGuid, L"alpha", 1);
            ok(Instance != NULL, "the name is free again after PerfDeleteInstance: %lu\n", GetLastError());
            /* PerfStopProvider releases what is left */
        }

        Error = pStop(NULL);
        ok(Error == ERROR_INVALID_PARAMETER, "PerfStopProvider(NULL): %lu\n", Error);

        /* the allocator pair is used for the provider and the instances, and balanced after the stop */
        Context.Alloc = (void *)TestAlloc;
        Context.Free = (void *)TestFree;
        Provider2 = NULL;
        Error = pStartEx(&Guid, &Context, &Provider2);
        ok(Error == ERROR_SUCCESS && Provider2, "PerfStartProviderEx with an allocator: %lu\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            Error = pSetInfo(Provider2, &Template.Set, sizeof(Template));
            ok(Error == ERROR_SUCCESS, "PerfSetCounterSetInfo: %lu\n", Error);
            Instance = pCreate(Provider2, &SetGuid, L"beta", 7);
            ok(Instance != NULL, "PerfCreateInstance: %lu\n", GetLastError());
            ok(AllocCalls >= 1, "allocator not used\n");
            Error = pStop(Provider2);
            ok(Error == ERROR_SUCCESS, "PerfStopProvider: %lu\n", Error);
            ok(FreeCalls == AllocCalls, "alloc %ld, free %ld\n", AllocCalls, FreeCalls);
        }
    }

    Error = pStop(Provider);
    ok(Error == ERROR_SUCCESS, "PerfStopProvider returned %lu\n", Error);
}
