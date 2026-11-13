/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A routine started with RtlCreateUserThread that returns ends its thread
 *              with its return value as the exit status
 */

#include "precomp.h"

#ifdef _M_AMD64

static volatile LONG g_Started;
static volatile ULONG_PTR g_Parameter;

static
ULONG
NTAPI
ReturningRoutine(PVOID Parameter)
{
    g_Parameter = (ULONG_PTR)Parameter;
    InterlockedIncrement(&g_Started);
    return (ULONG)(ULONG_PTR)Parameter + 1;
}

static
VOID
TestReturn(BOOLEAN Suspended, ULONG_PTR Parameter)
{
    NTSTATUS Status;
    HANDLE Thread;
    CLIENT_ID ClientId;
    THREAD_BASIC_INFORMATION Info;
    LARGE_INTEGER Timeout;

    g_Started = 0;
    g_Parameter = 0;
    Status = RtlCreateUserThread(NtCurrentProcess(), NULL, Suspended, 0, 0, 0,
                                 ReturningRoutine, (PVOID)Parameter, &Thread, &ClientId);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    if (Suspended)
    {
        Status = NtResumeThread(Thread, NULL);
        ok_hex(Status, STATUS_SUCCESS);
    }

    Timeout.QuadPart = -300 * 10000 * 1000LL; /* 30 s */
    Status = NtWaitForSingleObject(Thread, FALSE, &Timeout);
    ok_hex(Status, STATUS_WAIT_0);
    ok_long(g_Started, 1);
    ok_eq_hex64((ULONG64)g_Parameter, (ULONG64)Parameter);

    Status = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    ok_hex(Info.ExitStatus, (NTSTATUS)((ULONG)Parameter + 1));
    NtClose(Thread);
}

START_TEST(RtlCreateUserThreadReturn)
{
    TestReturn(FALSE, 0x1233);
    TestReturn(TRUE, 0x41);
    /* A parameter wider than 32 bits is passed whole */
    TestReturn(FALSE, 0x123400007FFFull);
    /* The exit status is the whole ULONG: an NTSTATUS error code comes through unchanged */
    TestReturn(FALSE, 0xC0000121 - 1);
}

#else

START_TEST(RtlCreateUserThreadReturn)
{
    skip("amd64 only: the i386 thread start has no return address\n");
}

#endif
