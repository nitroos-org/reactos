/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for RtlGetUnloadEventTrace
 * COPYRIGHT:   Copyright 2020 Mark Jansen (mark.jansen@reactos.org)
 */

#include "precomp.h"

PRTL_UNLOAD_EVENT_TRACE
NTAPI
RtlGetUnloadEventTrace(VOID);

typedef VOID (NTAPI *PFN_RtlGetUnloadEventTraceEx)(PULONG *, PULONG *, PVOID *);

/*
 * The on-disk / cross-process layout of RTL_UNLOAD_EVENT_TRACE must match
 * Windows exactly: SizeOfImage is pointer-wide (SIZE_T), not ULONG. Out-of-process
 * debuggers / crash handlers (e.g. Crashpad) read *ElementSize from the target and
 * reject the unloaded-module list when it is smaller than their own sizeof of this
 * struct. On x64 that expectation is 96 bytes; a ULONG SizeOfImage made it 88 and
 * tripped "unexpected unloaded module list element size". See CORE / T100.
 */
#ifndef _WIN64
C_ASSERT(sizeof(RTL_UNLOAD_EVENT_TRACE) == 84);
C_ASSERT(sizeof(RTL_UNLOAD_EVENT_TRACE) * RTL_UNLOAD_EVENT_TRACE_NUMBER == 0x540);
#else
C_ASSERT(sizeof(RTL_UNLOAD_EVENT_TRACE) == 96);
#endif

static void Test_Dump()
{
    PRTL_UNLOAD_EVENT_TRACE TraceHead, Trace;
    UINT n;

    TraceHead = RtlGetUnloadEventTrace();
    for (n = 0; n < RTL_UNLOAD_EVENT_TRACE_NUMBER; ++n)
    {
        ULONG ExpectSequence = n ? n : RTL_UNLOAD_EVENT_TRACE_NUMBER;

        Trace = TraceHead + n;

        ok(Trace->BaseAddress != NULL, "Got no BaseAddress for %u\n", n);
        ok(Trace->SizeOfImage != 0, "Got no SizeOfImage for %u\n", n);
        ok(Trace->Sequence == ExpectSequence,
           "Wrong Sequence: %lu instead of %lu for %u\n", Trace->Sequence, ExpectSequence, n);
        ok(Trace->TimeDateStamp != 0, "Got no TimeDateStamp for %u\n", n);
        ok(Trace->CheckSum != 0, "Got no CheckSum for %u\n", n);
        ok(!wcscmp(Trace->ImageName, L"GetUName.dLl"), "Wrong ImageName for %u: %S\n", n, Trace->ImageName);
    }
}

/*
 * RtlGetUnloadEventTraceEx reports the element size, element count and the trace
 * array base. The element size it reports MUST equal sizeof(RTL_UNLOAD_EVENT_TRACE)
 * so that a cross-process consumer using the same (Windows-accurate) struct accepts
 * the data instead of rejecting it as too small. The array is reached through one
 * pointer indirection and is not the legacy RtlGetUnloadEventTrace() array.
 */
static void Test_Ex()
{
    PULONG ElementSize = NULL;
    PULONG ElementCount = NULL;
    PVOID EventTrace = NULL;
    PFN_RtlGetUnloadEventTraceEx pRtlGetUnloadEventTraceEx;

    /* Vista+ API: not exported by the 2003-targeted ntdll */
    pRtlGetUnloadEventTraceEx = (PFN_RtlGetUnloadEventTraceEx)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetUnloadEventTraceEx");
    if (!pRtlGetUnloadEventTraceEx)
    {
        skip("RtlGetUnloadEventTraceEx is not available\n");
        return;
    }

    pRtlGetUnloadEventTraceEx(&ElementSize, &ElementCount, &EventTrace);

    ok(ElementSize != NULL, "ElementSize not set\n");
    ok(ElementCount != NULL, "ElementCount not set\n");
    ok(EventTrace != NULL, "EventTrace not set\n");

    if (ElementSize)
    {
        ok(*ElementSize == sizeof(RTL_UNLOAD_EVENT_TRACE),
           "ElementSize %lu != sizeof(RTL_UNLOAD_EVENT_TRACE) %lu\n",
           *ElementSize, (ULONG)sizeof(RTL_UNLOAD_EVENT_TRACE));
    }
    if (ElementCount)
    {
        /* Windows 10 reports 64 elements here, the legacy array has 16 */
        ok(*ElementCount == 64, "ElementCount %lu != 64\n", *ElementCount);
    }
    /* EventTrace is the address of a pointer to the array (one more
     * indirection than RtlGetUnloadEventTrace), not the legacy array itself. */
    if (EventTrace)
    {
        PVOID Array = *(PVOID *)EventTrace;
        ok(Array != NULL, "Array pointer not set\n");
        ok(EventTrace != RtlGetUnloadEventTrace() && Array != RtlGetUnloadEventTrace(),
           "EventTrace %p / %p must differ from RtlGetUnloadEventTrace() %p\n",
           EventTrace, Array, RtlGetUnloadEventTrace());
    }
}

#define TESTDLL "GetUName.dLl"
static void Test_LoadUnload()
{
    HMODULE mod;
    static char Buffer[MAX_PATH] = {0};

    mod = GetModuleHandleA(TESTDLL);
    ok(mod == NULL, "ERROR, %s already loaded\n", TESTDLL);

    mod = LoadLibraryA(Buffer[0] ? Buffer :TESTDLL);
    ok(mod != NULL, "ERROR, %s not loaded\n", TESTDLL);

    if (!Buffer[0])
    {
        GetModuleFileNameA(mod, Buffer, _countof(Buffer));
    }
    else
    {
        Buffer[0] = '\0';
    }

    FreeLibrary(mod);

    mod = GetModuleHandleA(TESTDLL);
    ok(mod == NULL, "ERROR, %s still loaded\n", TESTDLL);
}

START_TEST(RtlGetUnloadEventTrace)
{
    int n;
    HMODULE Ignore;

    Ignore = LoadLibrary("user32.dll");

    for (n = 0; n <= RTL_UNLOAD_EVENT_TRACE_NUMBER; ++n)
    {
        trace("Num: %u\n", n);
        Test_LoadUnload();
    }
    Test_Dump();
    Test_Ex();

    FreeLibrary(Ignore);
}
