/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test CONTEXT_EXCEPTION_REQUEST/REPORTING/SERVICE_ACTIVE/EXCEPTION_ACTIVE of
 *              NtGetContextThread/NtSetContextThread (Windows 7+). Expected values measured on Windows 10.
 */

#include "precomp.h"

#if defined(_M_IX86) || defined(_M_AMD64)

#define CTX_EXCEPTION_ACTIVE    0x08000000
#define CTX_SERVICE_ACTIVE      0x10000000
#define CTX_EXCEPTION_REQUEST   0x40000000
#define CTX_EXCEPTION_REPORTING 0x80000000
#define CTX_ALL_BITS (CTX_EXCEPTION_ACTIVE | CTX_SERVICE_ACTIVE | CTX_EXCEPTION_REQUEST | CTX_EXCEPTION_REPORTING)

static volatile LONG g_Sync;
static HANDLE g_Event;

static
ULONG
NTAPI
WaitThread(PVOID Param)
{
    UNREFERENCED_PARAMETER(Param);
    g_Sync = 1;
    while (g_Sync != 2)
        ;
    NtWaitForSingleObject(g_Event, FALSE, NULL);
    g_Sync = 3;
    RtlExitUserThread(STATUS_SUCCESS);
    return 0;
}

static
VOID
CheckGet(
    _In_ PCSTR Where,
    _In_ HANDLE Thread,
    _In_ ULONG In,
    _In_ ULONG Expected)
{
    CONTEXT Context;
    NTSTATUS Status;

    RtlZeroMemory(&Context, sizeof(Context));
    Context.ContextFlags = In;
    Status = NtGetContextThread(Thread, &Context);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Context.ContextFlags == Expected, "%s: in %#lx, got %#lx, expected %#lx\n",
       Where, In, Context.ContextFlags, Expected);
}

/* Get with all combinations of the exception bits */
static
VOID
CheckAllGets(
    _In_ PCSTR Where,
    _In_ HANDLE Thread,
    _In_ ULONG Active)
{
    ULONG Base = CONTEXT_CONTROL;

    /* Without the request nothing is reported and the bits are removed from the flags */
    CheckGet(Where, Thread, Base, Base);
    CheckGet(Where, Thread, Base | CTX_EXCEPTION_REPORTING, Base);
    CheckGet(Where, Thread, Base | CTX_SERVICE_ACTIVE, Base);
    CheckGet(Where, Thread, Base | CTX_EXCEPTION_ACTIVE, Base);
    CheckGet(Where, Thread, Base | CTX_EXCEPTION_REPORTING | CTX_SERVICE_ACTIVE | CTX_EXCEPTION_ACTIVE, Base);

    /* With the request the answer does not depend on the other bits */
    CheckGet(Where, Thread, Base | CTX_EXCEPTION_REQUEST,
             Base | CTX_EXCEPTION_REQUEST | CTX_EXCEPTION_REPORTING | Active);
    CheckGet(Where, Thread, Base | CTX_ALL_BITS,
             Base | CTX_EXCEPTION_REQUEST | CTX_EXCEPTION_REPORTING | Active);
    CheckGet(Where, Thread, CONTEXT_CONTROL | CONTEXT_INTEGER | CTX_EXCEPTION_REQUEST,
             CONTEXT_CONTROL | CONTEXT_INTEGER | CTX_EXCEPTION_REQUEST | CTX_EXCEPTION_REPORTING | Active);
}

/* Sets with the bits are accepted and do not change what is reported */
static
VOID
CheckSets(
    _In_ PCSTR Where,
    _In_ HANDLE Thread,
    _In_ ULONG Active)
{
    CONTEXT Context;
    NTSTATUS Status;
    ULONG i;
    static const ULONG Bits[] =
    {
        CTX_EXCEPTION_REQUEST,
        CTX_EXCEPTION_REPORTING,
        CTX_SERVICE_ACTIVE,
        CTX_EXCEPTION_ACTIVE,
        CTX_ALL_BITS,
    };

    for (i = 0; i < RTL_NUMBER_OF(Bits); i++)
    {
        RtlZeroMemory(&Context, sizeof(Context));
        Context.ContextFlags = CONTEXT_CONTROL;
        Status = NtGetContextThread(Thread, &Context);
        ok_hex(Status, STATUS_SUCCESS);
        Context.ContextFlags = CONTEXT_CONTROL | Bits[i];
        Status = NtSetContextThread(Thread, &Context);
        ok(Status == STATUS_SUCCESS, "%s: set with %#lx returned %#lx\n", Where, Bits[i], Status);
        CheckGet(Where, Thread, CONTEXT_CONTROL | CTX_EXCEPTION_REQUEST,
                 CONTEXT_CONTROL | CTX_EXCEPTION_REQUEST | CTX_EXCEPTION_REPORTING | Active);
    }
}

START_TEST(ContextExceptionRequest)
{
    OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(NULL, 0);
    HANDLE Thread;
    CLIENT_ID ClientId;
    LARGE_INTEGER Timeout;
    NTSTATUS Status;
    ULONG Spin;

    /* The thread is inside the system call that gets its context */
    CheckAllGets("current thread", NtCurrentThread(), CTX_SERVICE_ACTIVE);

    Status = NtCreateEvent(&g_Event, EVENT_ALL_ACCESS, &ObjectAttributes, SynchronizationEvent, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    g_Sync = 0;
    Status = RtlCreateUserThread(NtCurrentProcess(), NULL, TRUE, 0, 0, 0, WaitThread, NULL, &Thread, &ClientId);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* Not started: the thread is as if inside an exception */
    CheckAllGets("not started", Thread, CTX_EXCEPTION_ACTIVE);

    Status = NtResumeThread(Thread, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    for (Spin = 0; g_Sync != 1 && Spin < 1000; Spin++)
        NtYieldExecution();
    ok_long(g_Sync, 1);

    /* In user mode (interrupted): nothing active */
    Status = NtSuspendThread(Thread, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    CheckAllGets("user mode", Thread, 0);
    CheckSets("user mode", Thread, 0);
    Status = NtResumeThread(Thread, NULL);
    ok_hex(Status, STATUS_SUCCESS);

    /* Waiting in a system call */
    g_Sync = 2;
    Timeout.QuadPart = -100 * 10000;
    NtDelayExecution(FALSE, &Timeout);
    CheckAllGets("waiting", Thread, CTX_SERVICE_ACTIVE);
    CheckSets("waiting", Thread, CTX_SERVICE_ACTIVE);

    NtSetEvent(g_Event, NULL);
    Timeout.QuadPart = -5000 * 10000;
    Status = NtWaitForSingleObject(Thread, FALSE, &Timeout);
    ok(Status == STATUS_WAIT_0, "wait for the thread returned %#lx, sync %ld\n", Status, g_Sync);
    if (Status != STATUS_WAIT_0)
        NtTerminateThread(Thread, 0);
    NtClose(Thread);
    NtClose(g_Event);
}

#else
START_TEST(ContextExceptionRequest)
{
    skip("Not supported on this architecture\n");
}
#endif
