/*
 * PROJECT:         ReactOS Run-Time Library
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * PURPOSE:         Rtl Trace Routines
 */

/* INCLUDES *******************************************************************/

#include <rtl.h>
#define NDEBUG
#include <debug.h>

/*
 * Windows keeps two lists: the legacy 16-entry array returned by
 * RtlGetUnloadEventTrace, and (Vista+) a 64-entry array reported by
 * RtlGetUnloadEventTraceEx. The Ex out parameter is the address of a POINTER
 * to the array (ntdll's RtlpUnloadEventTraceEx variable), not the array
 * itself; callers dereference it once (verified on Windows 10 22H2).
 */
#define RTL_UNLOAD_EVENT_TRACE_EX_NUMBER 64

static RTL_UNLOAD_EVENT_TRACE RtlpUnloadEventTrace[RTL_UNLOAD_EVENT_TRACE_NUMBER];
static RTL_UNLOAD_EVENT_TRACE RtlpUnloadEventTraceExArray[RTL_UNLOAD_EVENT_TRACE_EX_NUMBER];
static PRTL_UNLOAD_EVENT_TRACE RtlpUnloadEventTraceEx = RtlpUnloadEventTraceExArray;
static UINT RtlpUnloadEventTraceIndex = 0;
static ULONG RtlpUnloadEventTraceElementSize = sizeof(RTL_UNLOAD_EVENT_TRACE);
static ULONG RtlpUnloadEventTraceElementCount = RTL_UNLOAD_EVENT_TRACE_EX_NUMBER;

/* FUNCTIONS ******************************************************************/

PRTL_UNLOAD_EVENT_TRACE
NTAPI
RtlGetUnloadEventTrace(VOID)
{
    /* Just return a pointer to an array, according to MSDN */
    return RtlpUnloadEventTrace;
}

VOID
NTAPI
RtlGetUnloadEventTraceEx(
    _Out_ PULONG *ElementSize,
    _Out_ PULONG *ElementCount,
    _Out_ PVOID *EventTrace)
{
    /*
     * Return pointers to the element size, element count and to the variable
     * holding the trace array base (one level of indirection, as on Windows).
     * Callers (e.g. Chromium, which only probes this on Vista+) read
     * *ElementCount entries of *ElementSize bytes from **EventTrace and skip
     * entries whose BaseAddress is NULL.
     */
    *ElementSize = &RtlpUnloadEventTraceElementSize;
    *ElementCount = &RtlpUnloadEventTraceElementCount;
    *EventTrace = &RtlpUnloadEventTraceEx;
}

static
VOID
RtlpFillUnloadEvent(
    _Out_ PRTL_UNLOAD_EVENT_TRACE Event,
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry,
    _In_ UINT Sequence)
{
    PIMAGE_NT_HEADERS NtHeaders;
    USHORT StringLen;

    Event->BaseAddress = LdrEntry->DllBase;
    Event->SizeOfImage = LdrEntry->SizeOfImage;
    Event->Sequence = Sequence;

    NtHeaders = RtlImageNtHeader(LdrEntry->DllBase);

    if (NtHeaders)
    {
        Event->TimeDateStamp = NtHeaders->FileHeader.TimeDateStamp;
        Event->CheckSum = NtHeaders->OptionalHeader.CheckSum;
    }
    else
    {
        Event->TimeDateStamp = 0;
        Event->CheckSum = 0;
    }

    StringLen = min(LdrEntry->BaseDllName.Length / sizeof(WCHAR), RTL_NUMBER_OF(Event->ImageName));
    RtlCopyMemory(Event->ImageName, LdrEntry->BaseDllName.Buffer, StringLen * sizeof(WCHAR));
    if (StringLen < RTL_NUMBER_OF(Event->ImageName))
        Event->ImageName[StringLen] = 0;
}

VOID
NTAPI
LdrpRecordUnloadEvent(_In_ PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    UINT Sequence = RtlpUnloadEventTraceIndex++;

    DPRINT("LdrpRecordUnloadEvent(%wZ, %p - %p)\n", &LdrEntry->BaseDllName, LdrEntry->DllBase,
        (ULONG_PTR)LdrEntry->DllBase + LdrEntry->SizeOfImage);

    RtlpFillUnloadEvent(&RtlpUnloadEventTrace[Sequence % RTL_UNLOAD_EVENT_TRACE_NUMBER], LdrEntry, Sequence);
    RtlpFillUnloadEvent(&RtlpUnloadEventTraceEx[Sequence % RTL_UNLOAD_EVENT_TRACE_EX_NUMBER], LdrEntry, Sequence);
}

BOOLEAN
NTAPI
RtlTraceDatabaseAdd(IN PRTL_TRACE_DATABASE Database,
                    IN ULONG Count,
                    IN PVOID *Trace,
                    OUT OPTIONAL PRTL_TRACE_BLOCK *TraceBlock)
{
    UNIMPLEMENTED;
    return FALSE;
}

PRTL_TRACE_DATABASE
NTAPI
RtlTraceDatabaseCreate(IN ULONG Buckets,
                       IN OPTIONAL SIZE_T MaximumSize,
                       IN ULONG Flags,
                       IN ULONG Tag,
                       IN OPTIONAL RTL_TRACE_HASH_FUNCTION HashFunction)
{
    UNIMPLEMENTED;
    return NULL;
}

BOOLEAN
NTAPI
RtlTraceDatabaseDestroy(IN PRTL_TRACE_DATABASE Database)
{
    UNIMPLEMENTED;
    return FALSE;
}

BOOLEAN
NTAPI
RtlTraceDatabaseEnumerate(IN PRTL_TRACE_DATABASE Database,
                          IN PRTL_TRACE_ENUMERATE TraceEnumerate,
                          IN OUT PRTL_TRACE_BLOCK *TraceBlock)
{
    UNIMPLEMENTED;
    return FALSE;
}


BOOLEAN
NTAPI
RtlTraceDatabaseFind(IN PRTL_TRACE_DATABASE Database,
                     IN ULONG Count,
                     IN PVOID *Trace,
                     OUT OPTIONAL PRTL_TRACE_BLOCK *TraceBlock)
{
    UNIMPLEMENTED;
    return FALSE;
}

BOOLEAN
NTAPI
RtlTraceDatabaseLock(IN PRTL_TRACE_DATABASE Database)
{
    UNIMPLEMENTED;
    return FALSE;
}

BOOLEAN
NTAPI
RtlTraceDatabaseUnlock(IN PRTL_TRACE_DATABASE Database)
{
    UNIMPLEMENTED;
    return FALSE;
}

BOOLEAN
NTAPI
RtlTraceDatabaseValidate(IN PRTL_TRACE_DATABASE Database)
{
    UNIMPLEMENTED;
    return FALSE;
}
