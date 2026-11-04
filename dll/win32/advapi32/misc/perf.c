/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     advapi32.dll Performance Counters provider API (PerfLib V2, provider side)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * There are no counter consumers in this system (no PerfQueryCounterData backend), so a provider
 * only keeps its own bookkeeping: counter set templates and counter set instances live in the
 * provider, nothing is published to a consumer. This is what an application sees on Windows when
 * nobody queries the counters, which is all that Edge/Chromium (msedge.dll delay-loads these
 * exports at start-up) needs.
 */

#include <advapi32.h>

#if (DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA)

#include <perflib.h>

WINE_DEFAULT_DEBUG_CHANNEL(advapi);

#define PERF_PROVIDER_MAGIC 0x50667250 /* 'PrfP' */

typedef struct _PERF_SET_NODE
{
    LIST_ENTRY Entry;
    LIST_ENTRY Instances;
    ULONG TemplateSize;
    PERF_COUNTERSET_INFO Info; /* followed by Info.NumCounters PERF_COUNTER_INFO, TemplateSize bytes in all */
} PERF_SET_NODE;

typedef struct _PERF_INSTANCE_NODE
{
    LIST_ENTRY Entry;
    PERF_SET_NODE *Set;
    ULONG DataOffset; /* from the start of Instance */
    ULONG DataSize;
    ULONG64 Pad;      /* keeps Instance 8-byte aligned */
    PERF_COUNTERSET_INSTANCE Instance;
} PERF_INSTANCE_NODE;

typedef struct _PERF_PROVIDER
{
    LIST_ENTRY Entry;
    ULONG Magic;
    GUID Guid;
    PERF_PROVIDER_CONTEXT Context;
    LIST_ENTRY Sets;
} PERF_PROVIDER;

static LIST_ENTRY PerfProviders = { &PerfProviders, &PerfProviders };
static CRITICAL_SECTION PerfLock;
static CRITICAL_SECTION_DEBUG PerfLockDebug =
{
    0, 0, &PerfLock,
    { &PerfLockDebug.ProcessLocksList, &PerfLockDebug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": PerfLock") }
};
static CRITICAL_SECTION PerfLock = { &PerfLockDebug, -1, 0, 0, 0, 0 };

static PERF_PROVIDER *PerfFindProvider(HANDLE Handle)
{
    LIST_ENTRY *e;
    for (e = PerfProviders.Flink; e != &PerfProviders; e = e->Flink)
        if ((HANDLE)e == Handle) /* Entry is the first member */
            return CONTAINING_RECORD(e, PERF_PROVIDER, Entry);
    return NULL;
}

static PERF_COUNTER_INFO *PerfCounters(PERF_SET_NODE *Set)
{
    return (PERF_COUNTER_INFO *)(&Set->Info + 1);
}

static void *PerfAlloc(PERF_PROVIDER *Prov, SIZE_T Size)
{
    if (Prov->Context.MemAllocRoutine && Prov->Context.MemFreeRoutine)
        return Prov->Context.MemAllocRoutine(Size, Prov->Context.pMemContext);
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

static void PerfFree(PERF_PROVIDER *Prov, void *Ptr)
{
    if (Prov->Context.MemAllocRoutine && Prov->Context.MemFreeRoutine)
        Prov->Context.MemFreeRoutine(Ptr, Prov->Context.pMemContext);
    else
        HeapFree(GetProcessHeap(), 0, Ptr);
}

static void PerfFreeInstance(PERF_PROVIDER *Prov, PERF_INSTANCE_NODE *Node)
{
    RemoveEntryList(&Node->Entry);
    PerfFree(Prov, Node);
}

static void PerfFreeProvider(PERF_PROVIDER *Prov)
{
    while (!IsListEmpty(&Prov->Sets))
    {
        PERF_SET_NODE *Set = CONTAINING_RECORD(RemoveHeadList(&Prov->Sets), PERF_SET_NODE, Entry);
        while (!IsListEmpty(&Set->Instances))
            PerfFreeInstance(Prov, CONTAINING_RECORD(Set->Instances.Flink, PERF_INSTANCE_NODE, Entry));
        HeapFree(GetProcessHeap(), 0, Set);
    }
    Prov->Magic = 0;
    PerfFree(Prov, Prov);
}

ULONG
WINAPI
PerfStartProviderEx(
    _In_ LPGUID ProviderGuid,
    _In_opt_ PPERF_PROVIDER_CONTEXT ProviderContext,
    _Out_ PHANDLE Provider)
{
    PERF_PROVIDER *Prov;
    PERF_PROVIDER_CONTEXT Context;

    TRACE("(%s, %p, %p)\n", wine_dbgstr_guid(ProviderGuid), ProviderContext, Provider);

    if (!ProviderGuid || !Provider)
        return ERROR_INVALID_PARAMETER;

    /* Windows 10: a NULL context is accepted (no callbacks, default allocator), a zero ContextSize is not */
    RtlZeroMemory(&Context, sizeof(Context));
    if (ProviderContext)
    {
        if (ProviderContext->ContextSize < sizeof(Context))
            return ERROR_INVALID_PARAMETER;
        Context = *ProviderContext;
    }

    if (Context.MemAllocRoutine && Context.MemFreeRoutine)
        Prov = Context.MemAllocRoutine(sizeof(*Prov), Context.pMemContext);
    else
        Prov = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Prov));
    if (!Prov)
        return ERROR_NOT_ENOUGH_MEMORY;

    RtlZeroMemory(Prov, sizeof(*Prov));
    Prov->Magic = PERF_PROVIDER_MAGIC;
    Prov->Guid = *ProviderGuid;
    Prov->Context = Context;
    InitializeListHead(&Prov->Sets);

    EnterCriticalSection(&PerfLock);
    InsertTailList(&PerfProviders, &Prov->Entry);
    LeaveCriticalSection(&PerfLock);

    *Provider = (HANDLE)Prov;
    return ERROR_SUCCESS;
}

ULONG
WINAPI
PerfStartProvider(
    _In_ LPGUID ProviderGuid,
    _In_opt_ PERFLIBREQUEST ControlCallback,
    _Out_ PHANDLE Provider)
{
    PERF_PROVIDER_CONTEXT Context;

    TRACE("(%s, %p, %p)\n", wine_dbgstr_guid(ProviderGuid), ControlCallback, Provider);

    RtlZeroMemory(&Context, sizeof(Context));
    Context.ContextSize = sizeof(Context);
    Context.ControlCallback = ControlCallback;
    return PerfStartProviderEx(ProviderGuid, &Context, Provider);
}

ULONG
WINAPI
PerfStopProvider(
    _In_ HANDLE ProviderHandle)
{
    PERF_PROVIDER *Prov;

    TRACE("(%p)\n", ProviderHandle);

    EnterCriticalSection(&PerfLock);
    Prov = PerfFindProvider(ProviderHandle);
    if (Prov)
        RemoveEntryList(&Prov->Entry);
    LeaveCriticalSection(&PerfLock);

    if (!Prov)
        return ERROR_INVALID_PARAMETER;

    PerfFreeProvider(Prov);
    return ERROR_SUCCESS;
}

ULONG
WINAPI
PerfSetCounterSetInfo(
    _In_ HANDLE ProviderHandle,
    _Inout_ PPERF_COUNTERSET_INFO Template,
    _In_ ULONG TemplateSize)
{
    PERF_PROVIDER *Prov;
    PERF_SET_NODE *Set, *Old;
    ULONG64 Needed;
    LIST_ENTRY *e;
    ULONG Ret = ERROR_SUCCESS;

    TRACE("(%p, %p, %lu)\n", ProviderHandle, Template, TemplateSize);

    if (!Template || TemplateSize < sizeof(*Template))
        return ERROR_INVALID_PARAMETER;
    Needed = sizeof(*Template) + (ULONG64)Template->NumCounters * sizeof(PERF_COUNTER_INFO);
    if (Needed > TemplateSize)
        return ERROR_INVALID_PARAMETER;

    Set = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FIELD_OFFSET(PERF_SET_NODE, Info) + (SIZE_T)Needed);
    if (!Set)
        return ERROR_NOT_ENOUGH_MEMORY;
    Set->TemplateSize = (ULONG)Needed;
    RtlCopyMemory(&Set->Info, Template, (SIZE_T)Needed);
    InitializeListHead(&Set->Instances);

    EnterCriticalSection(&PerfLock);
    Prov = PerfFindProvider(ProviderHandle);
    if (!Prov)
        Ret = ERROR_INVALID_PARAMETER;
    else
    {
        for (e = Prov->Sets.Flink; e != &Prov->Sets; e = e->Flink)
        {
            Old = CONTAINING_RECORD(e, PERF_SET_NODE, Entry);
            if (IsEqualGUID(&Old->Info.CounterSetGuid, &Template->CounterSetGuid))
            {
                Ret = ERROR_ALREADY_EXISTS;
                break;
            }
        }
        if (Ret == ERROR_SUCCESS)
            InsertTailList(&Prov->Sets, &Set->Entry);
    }
    LeaveCriticalSection(&PerfLock);

    if (Ret != ERROR_SUCCESS)
        HeapFree(GetProcessHeap(), 0, Set);
    return Ret;
}

PPERF_COUNTERSET_INSTANCE
WINAPI
PerfCreateInstance(
    _In_ HANDLE ProviderHandle,
    _In_ LPCGUID CounterSetGuid,
    _In_ PCWSTR Name,
    _In_ ULONG InstanceId)
{
    PERF_PROVIDER *Prov;
    PERF_SET_NODE *Set = NULL;
    PERF_INSTANCE_NODE *Node;
    PERF_COUNTER_INFO *Counters;
    LIST_ENTRY *e;
    SIZE_T NameBytes, DataSize = 0, Total;
    ULONG i, NameOffset, DataOffset, Err = ERROR_SUCCESS;
    PPERF_COUNTERSET_INSTANCE Result = NULL;

    TRACE("(%p, %s, %s, %lu)\n", ProviderHandle, wine_dbgstr_guid(CounterSetGuid), debugstr_w(Name), InstanceId);

    if (!CounterSetGuid || !Name)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    NameBytes = (wcslen(Name) + 1) * sizeof(WCHAR);

    EnterCriticalSection(&PerfLock);
    Prov = PerfFindProvider(ProviderHandle);
    if (!Prov)
        Err = ERROR_INVALID_PARAMETER;
    else
    {
        for (e = Prov->Sets.Flink; e != &Prov->Sets; e = e->Flink)
        {
            PERF_SET_NODE *Cand = CONTAINING_RECORD(e, PERF_SET_NODE, Entry);
            if (IsEqualGUID(&Cand->Info.CounterSetGuid, CounterSetGuid))
            {
                Set = Cand;
                break;
            }
        }
        if (!Set)
            Err = ERROR_NOT_FOUND;
    }

    if (Err == ERROR_SUCCESS)
    {
        for (e = Set->Instances.Flink; e != &Set->Instances; e = e->Flink)
        {
            Node = CONTAINING_RECORD(e, PERF_INSTANCE_NODE, Entry);
            if (!_wcsicmp((PCWSTR)((PBYTE)&Node->Instance + Node->Instance.InstanceNameOffset), Name))
            {
                Err = ERROR_ALREADY_EXISTS;
                break;
            }
        }
    }

    if (Err == ERROR_SUCCESS)
    {
        Counters = PerfCounters(Set);
        for (i = 0; i < Set->Info.NumCounters; i++)
            DataSize += (Counters[i].Size + 7) & ~7;
        NameOffset = sizeof(PERF_COUNTERSET_INSTANCE);
        DataOffset = (NameOffset + (ULONG)NameBytes + 7) & ~7;
        Total = FIELD_OFFSET(PERF_INSTANCE_NODE, Instance) + DataOffset + DataSize;

        Node = PerfAlloc(Prov, Total);
        if (!Node)
            Err = ERROR_NOT_ENOUGH_MEMORY;
        else
        {
            RtlZeroMemory(Node, Total);
            Node->Set = Set;
            Node->DataOffset = DataOffset;
            Node->DataSize = (ULONG)DataSize;
            Node->Instance.CounterSetGuid = *CounterSetGuid;
            Node->Instance.dwSize = DataOffset + (ULONG)DataSize;
            Node->Instance.InstanceId = InstanceId;
            Node->Instance.InstanceNameOffset = NameOffset;
            Node->Instance.InstanceNameSize = (ULONG)NameBytes;
            RtlCopyMemory((PBYTE)&Node->Instance + NameOffset, Name, NameBytes);
            InsertTailList(&Set->Instances, &Node->Entry);
            Result = &Node->Instance;
        }
    }
    LeaveCriticalSection(&PerfLock);

    if (!Result)
        SetLastError(Err);
    return Result;
}

/* Called with the lock held. */
static PERF_INSTANCE_NODE *PerfFindInstance(PERF_PROVIDER *Prov, PPERF_COUNTERSET_INSTANCE Instance)
{
    LIST_ENTRY *s, *i;

    if (!Instance)
        return NULL;
    for (s = Prov->Sets.Flink; s != &Prov->Sets; s = s->Flink)
    {
        PERF_SET_NODE *Set = CONTAINING_RECORD(s, PERF_SET_NODE, Entry);
        for (i = Set->Instances.Flink; i != &Set->Instances; i = i->Flink)
        {
            PERF_INSTANCE_NODE *Node = CONTAINING_RECORD(i, PERF_INSTANCE_NODE, Entry);
            if (&Node->Instance == Instance)
                return Node;
        }
    }
    return NULL;
}

ULONG
WINAPI
PerfDeleteInstance(
    _In_ HANDLE ProviderHandle,
    _In_ PPERF_COUNTERSET_INSTANCE InstanceBlock)
{
    PERF_PROVIDER *Prov;
    PERF_INSTANCE_NODE *Node = NULL;
    ULONG Ret = ERROR_INVALID_PARAMETER;

    TRACE("(%p, %p)\n", ProviderHandle, InstanceBlock);

    EnterCriticalSection(&PerfLock);
    Prov = PerfFindProvider(ProviderHandle);
    if (Prov)
        Node = PerfFindInstance(Prov, InstanceBlock);
    if (Node)
    {
        PerfFreeInstance(Prov, Node);
        Ret = ERROR_SUCCESS;
    }
    LeaveCriticalSection(&PerfLock);
    return Ret;
}

ULONG
WINAPI
PerfSetCounterRefValue(
    _In_ HANDLE ProviderHandle,
    _In_ PPERF_COUNTERSET_INSTANCE Instance,
    _In_ ULONG CounterId,
    _In_ PVOID Address)
{
    PERF_PROVIDER *Prov;
    PERF_INSTANCE_NODE *Node = NULL;
    PERF_COUNTER_INFO *Counters;
    ULONG i, Ret = ERROR_INVALID_PARAMETER;

    TRACE("(%p, %p, %lu, %p)\n", ProviderHandle, Instance, CounterId, Address);

    EnterCriticalSection(&PerfLock);
    Prov = PerfFindProvider(ProviderHandle);
    if (Prov)
        Node = PerfFindInstance(Prov, Instance);
    if (Node)
    {
        Ret = ERROR_NOT_FOUND;
        Counters = PerfCounters(Node->Set);
        for (i = 0; i < Node->Set->Info.NumCounters; i++)
        {
            if (Counters[i].CounterId != CounterId)
                continue;
            if (!(Counters[i].Attrib & PERF_ATTRIB_BY_REFERENCE) ||
                Counters[i].Offset > Node->DataSize ||
                Node->DataSize - Counters[i].Offset < sizeof(PVOID))
            {
                Ret = ERROR_INVALID_PARAMETER;
                break;
            }
            *(PVOID *)((PBYTE)Instance + Node->DataOffset + Counters[i].Offset) = Address;
            Ret = ERROR_SUCCESS;
            break;
        }
    }
    LeaveCriticalSection(&PerfLock);
    return Ret;
}

#endif /* DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA */
