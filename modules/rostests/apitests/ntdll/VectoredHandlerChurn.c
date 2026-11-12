/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Vectored handlers added and removed while other threads dispatch exceptions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define CHURN_CODE 0xE0000002

static volatile LONG Stop;
static volatile LONG Raised, Handled, SelfCalls, Churns;
static PVOID volatile SelfHandle;

static LONG NTAPI SearchHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Removes itself while the dispatcher is calling it */
static LONG NTAPI SelfRemovingHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    PVOID Handle = InterlockedExchangePointer((PVOID *)&SelfHandle, NULL);

    InterlockedIncrement(&SelfCalls);
    if (Handle)
        RtlRemoveVectoredExceptionHandler(Handle);
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG NTAPI ContinueHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != CHURN_CODE)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&Handled);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI RaiseThread(PVOID Parameter)
{
    while (!Stop)
    {
        RaiseException(CHURN_CODE, 0, 0, NULL);
        InterlockedIncrement(&Raised);
    }
    return 0;
}

static DWORD WINAPI ChurnThread(PVOID Parameter)
{
    PVOID First, Last, Continue, Self;

    while (!Stop)
    {
        First = RtlAddVectoredExceptionHandler(TRUE, SearchHandler);
        Last = RtlAddVectoredExceptionHandler(FALSE, SearchHandler);
        Continue = RtlAddVectoredContinueHandler(FALSE, SearchHandler);
        if (!SelfHandle)
        {
            Self = RtlAddVectoredExceptionHandler(TRUE, SelfRemovingHandler);
            if (InterlockedCompareExchangePointer((PVOID *)&SelfHandle, Self, NULL) != NULL)
                RtlRemoveVectoredExceptionHandler(Self);
        }
        RtlRemoveVectoredExceptionHandler(First);
        RtlRemoveVectoredExceptionHandler(Last);
        RtlRemoveVectoredContinueHandler(Continue);
        InterlockedIncrement(&Churns);
    }
    return 0;
}

START_TEST(VectoredHandlerChurn)
{
    HANDLE Threads[5];
    PVOID Handler, Self;
    ULONG i;

    Handler = RtlAddVectoredExceptionHandler(FALSE, ContinueHandler);
    ok(Handler != NULL, "RtlAddVectoredExceptionHandler failed\n");
    if (!Handler)
        return;

    for (i = 0; i < 4; i++)
        Threads[i] = CreateThread(NULL, 0, RaiseThread, NULL, 0, NULL);
    Threads[4] = CreateThread(NULL, 0, ChurnThread, NULL, 0, NULL);
    for (i = 0; i < 5; i++)
        ok(Threads[i] != NULL, "CreateThread %lu failed: %lu\n", i, GetLastError());

    Sleep(2000);
    InterlockedExchange(&Stop, 1);
    for (i = 0; i < 5; i++)
    {
        if (Threads[i])
        {
            ok(WaitForSingleObject(Threads[i], 30000) == WAIT_OBJECT_0, "Thread %lu did not finish\n", i);
            CloseHandle(Threads[i]);
        }
    }

    Self = InterlockedExchangePointer((PVOID *)&SelfHandle, NULL);
    if (Self)
        RtlRemoveVectoredExceptionHandler(Self);
    ok(RtlRemoveVectoredExceptionHandler(Handler) != 0, "RtlRemoveVectoredExceptionHandler failed\n");

    /* Every exception was handled once, by the handler that stayed registered */
    ok(Raised == Handled, "Raised %ld, handled %ld\n", Raised, Handled);
    ok(Raised > 1000, "Only %ld exceptions\n", Raised);
    ok(Churns > 100, "Only %ld handler changes\n", Churns);
    ok(SelfCalls > 0, "The self-removing handler was never called\n");
    trace("%ld exceptions, %ld handler changes, %ld self-removing calls\n", Raised, Churns, SelfCalls);
}
