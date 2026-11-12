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

/* ---- Lifetime of a handler that is removed while exception dispatch is inside it ---- */

#define LIFE_CODE 0xE0000003
#define WAIT_MS 10000

static HANDLE BlockEntered, BlockRelease;
static volatile LONG BlockerThreadId;
static volatile LONG BlockerCalls, OtherCalls, FallbackCalls;

/* The thread that raised first stays inside this handler until it is released; any other thread that gets here
   means a handler that was removed was called */
static LONG NTAPI BlockingHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != LIFE_CODE)
        return EXCEPTION_CONTINUE_SEARCH;

    if (GetCurrentThreadId() == (DWORD)BlockerThreadId)
    {
        InterlockedIncrement(&BlockerCalls);
        SetEvent(BlockEntered);
        WaitForSingleObject(BlockRelease, WAIT_MS);
    }
    else
    {
        InterlockedIncrement(&OtherCalls);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG NTAPI FallbackHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != LIFE_CODE)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&FallbackCalls);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI LifeRaiser(PVOID Parameter)
{
    if (Parameter)
        InterlockedExchange(&BlockerThreadId, (LONG)GetCurrentThreadId());
    RaiseException(LIFE_CODE, 0, 0, NULL);
    return 0;
}

/* Whether the heap hands out the block of a freed handler entry again: the entry was freed */
static BOOLEAN HeapReusedBlock(PVOID Handle)
{
    PVOID Blocks[32];
    SIZE_T Size;
    ULONG i, n = 0;
    BOOLEAN Reused = FALSE;

    for (Size = 16; Size <= 80; Size += 8)
    {
        for (i = 0; i < 2 && n < _countof(Blocks); i++)
        {
            Blocks[n] = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
            if (Blocks[n] == Handle)
                Reused = TRUE;
            if (Blocks[n])
                n++;
        }
    }
    while (n)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Blocks[--n]);
    return Reused;
}

/* A walk is inside the handler; the handler is removed (twice: the caller's bug, but real); the walk comes back */
static void TestRemoveWhileCalled(BOOLEAN SecondRemove)
{
    PVOID Blocking, Fallback;
    HANDLE Walker, Other;
    ULONG Ret;

    BlockerThreadId = 0;
    BlockerCalls = OtherCalls = FallbackCalls = 0;
    ResetEvent(BlockEntered);
    ResetEvent(BlockRelease);

    Fallback = RtlAddVectoredExceptionHandler(FALSE, FallbackHandler);
    Blocking = RtlAddVectoredExceptionHandler(TRUE, BlockingHandler);
    ok(Fallback && Blocking, "RtlAddVectoredExceptionHandler failed\n");
    if (!Fallback || !Blocking)
        return;

    Walker = CreateThread(NULL, 0, LifeRaiser, (PVOID)1, 0, NULL);
    ok(WaitForSingleObject(BlockEntered, WAIT_MS) == WAIT_OBJECT_0, "The handler was not entered\n");

    Ret = RtlRemoveVectoredExceptionHandler(Blocking);
    ok(Ret != 0, "Remove returned %lu\n", Ret);
    if (SecondRemove)
    {
        /* The registration is gone, the walk still uses the entry */
        Ret = RtlRemoveVectoredExceptionHandler(Blocking);
        ok(Ret == 0, "Second remove returned %lu\n", Ret);
        ok(!HeapReusedBlock(Blocking), "The handler entry was freed while a walk is inside the handler\n");
    }

    /* The removal has returned: no exception may call the handler any more, though the walk is still inside */
    Other = CreateThread(NULL, 0, LifeRaiser, NULL, 0, NULL);
    ok(WaitForSingleObject(Other, WAIT_MS) == WAIT_OBJECT_0, "The second raiser did not finish\n");
    CloseHandle(Other);
    ok(OtherCalls == 0, "A handler that was removed was called %ld times after Remove returned\n", OtherCalls);
    ok(FallbackCalls == 1, "Fallback handler calls: %ld\n", FallbackCalls);

    SetEvent(BlockRelease);
    ok(WaitForSingleObject(Walker, WAIT_MS) == WAIT_OBJECT_0, "The walker did not come back\n");
    CloseHandle(Walker);
    ok(BlockerCalls == 1, "The walker called the handler %ld times\n", BlockerCalls);
    ok(FallbackCalls == 2, "Fallback handler calls: %ld\n", FallbackCalls);

    /* Nobody is in the entry now */
    ok(RtlRemoveVectoredExceptionHandler(Blocking) == 0, "Remove of a handler that is gone succeeded\n");
    ok(RtlRemoveVectoredExceptionHandler(Fallback) != 0, "Remove of the fallback failed\n");
}

static PVOID SelfHandle2;
static volatile LONG SelfCalls2;
static ULONG SelfRet1, SelfRet2;

static LONG NTAPI SelfRemoveTwiceHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != LIFE_CODE)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&SelfCalls2);
    SelfRet1 = RtlRemoveVectoredExceptionHandler(SelfHandle2);
    SelfRet2 = RtlRemoveVectoredExceptionHandler(SelfHandle2);
    return EXCEPTION_CONTINUE_SEARCH;
}

/* A handler that removes itself, twice, in its own call (what a DLL that detaches inside its handler does) */
static void TestSelfRemove(void)
{
    PVOID Fallback;

    FallbackCalls = 0;
    SelfCalls2 = 0;
    Fallback = RtlAddVectoredExceptionHandler(FALSE, FallbackHandler);
    SelfHandle2 = RtlAddVectoredExceptionHandler(TRUE, SelfRemoveTwiceHandler);
    ok(Fallback && SelfHandle2, "RtlAddVectoredExceptionHandler failed\n");
    if (!Fallback || !SelfHandle2)
        return;

    BlockerThreadId = 0;
    LifeRaiser(NULL);
    ok(SelfCalls2 == 1, "Calls: %ld\n", SelfCalls2);
    ok(SelfRet1 != 0, "First remove returned %lu\n", SelfRet1);
    ok(SelfRet2 == 0, "Second remove returned %lu\n", SelfRet2);

    LifeRaiser(NULL);
    ok(SelfCalls2 == 1, "The handler was called again after it removed itself: %ld\n", SelfCalls2);
    ok(FallbackCalls == 2, "Fallback handler calls: %ld\n", FallbackCalls);
    ok(RtlRemoveVectoredExceptionHandler(Fallback) != 0, "Remove of the fallback failed\n");
}

/* A handler that adds another while the walk runs; the new one works for the next exception */
static volatile LONG AddedCalls;
static PVOID AddedHandle;

static LONG NTAPI AddedHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == LIFE_CODE)
        InterlockedIncrement(&AddedCalls);
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG NTAPI AddingHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == LIFE_CODE && !AddedHandle)
        AddedHandle = RtlAddVectoredExceptionHandler(TRUE, AddedHandler);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void TestAddWhileCalled(void)
{
    PVOID Fallback, Adding;

    FallbackCalls = 0;
    AddedCalls = 0;
    AddedHandle = NULL;
    Fallback = RtlAddVectoredExceptionHandler(FALSE, FallbackHandler);
    Adding = RtlAddVectoredExceptionHandler(TRUE, AddingHandler);
    ok(Fallback && Adding, "RtlAddVectoredExceptionHandler failed\n");
    if (!Fallback || !Adding)
        return;

    BlockerThreadId = 0;
    LifeRaiser(NULL);
    ok(AddedHandle != NULL, "The handler was not added\n");
    LifeRaiser(NULL);
    ok(AddedCalls >= 1, "The handler that was added during a walk was not called: %ld\n", AddedCalls);
    ok(FallbackCalls == 2, "Fallback handler calls: %ld\n", FallbackCalls);

    ok(RtlRemoveVectoredExceptionHandler(Adding) != 0, "Remove failed\n");
    if (AddedHandle)
        ok(RtlRemoveVectoredExceptionHandler(AddedHandle) != 0, "Remove failed\n");
    ok(RtlRemoveVectoredExceptionHandler(Fallback) != 0, "Remove failed\n");
}

/* ---- Order: first handlers newest first, last handlers in order of adding ---- */

#define ORDER_CODE 0xE0000004
static volatile LONG Order[16];
static volatile LONG OrderCount;

static void Note(LONG Id, PEXCEPTION_POINTERS ExceptionInfo)
{
    LONG n;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode != ORDER_CODE)
        return;
    n = InterlockedIncrement(&OrderCount) - 1;
    if (n < (LONG)_countof(Order))
        Order[n] = Id;
}

#define ORDER_HANDLER(n) \
    static LONG NTAPI OrderHandler##n(PEXCEPTION_POINTERS ep) { Note(n, ep); return EXCEPTION_CONTINUE_SEARCH; }
ORDER_HANDLER(1)
ORDER_HANDLER(2)
ORDER_HANDLER(3)
ORDER_HANDLER(4)

static LONG NTAPI OrderEnd(PEXCEPTION_POINTERS ep)
{
    Note(9, ep);
    return ep->ExceptionRecord->ExceptionCode == ORDER_CODE ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

static void ExpectOrder(const char *What, const LONG *Expected, ULONG Count)
{
    ULONG i;

    OrderCount = 0;
    RaiseException(ORDER_CODE, 0, 0, NULL);
    ok(OrderCount == (LONG)Count, "%s: %ld handlers called, expected %lu\n", What, OrderCount, Count);
    for (i = 0; i < Count && i < _countof(Order); i++)
        ok(Order[i] == Expected[i], "%s: call %lu was handler %ld, expected %ld\n", What, i, Order[i], Expected[i]);
}

static void TestOrder(void)
{
    PVOID h1, h2, h3, h4;
    static const LONG All[] = { 4, 2, 1, 3, 9 };
    static const LONG Without2[] = { 4, 1, 3, 9 };
    static const LONG Without4[] = { 1, 3, 9 };

    /* The last one added with "last" runs after every other: 9 ends the walk, so it is the last to be called */
    h1 = RtlAddVectoredExceptionHandler(FALSE, OrderHandler1);
    h2 = RtlAddVectoredExceptionHandler(TRUE, OrderHandler2);
    h3 = RtlAddVectoredExceptionHandler(FALSE, OrderHandler3);
    h4 = RtlAddVectoredExceptionHandler(TRUE, OrderHandler4);
    ok(h1 && h2 && h3 && h4, "RtlAddVectoredExceptionHandler failed\n");
    if (!(h1 && h2 && h3 && h4))
        return;
    {
        PVOID End = RtlAddVectoredExceptionHandler(FALSE, OrderEnd);

        ExpectOrder("all", All, _countof(All));
        ok(RtlRemoveVectoredExceptionHandler(h2) != 0, "Remove failed\n");
        ExpectOrder("without 2", Without2, _countof(Without2));
        ok(RtlRemoveVectoredExceptionHandler(h4) != 0, "Remove failed\n");
        ExpectOrder("without 2 and 4", Without4, _countof(Without4));
        ok(RtlRemoveVectoredExceptionHandler(h1) != 0, "Remove failed\n");
        ok(RtlRemoveVectoredExceptionHandler(h3) != 0, "Remove failed\n");
        ok(RtlRemoveVectoredExceptionHandler(End) != 0, "Remove failed\n");
    }
}


START_TEST(VectoredHandlerChurn)
{
    HANDLE Threads[5];
    PVOID Handler, Self;
    ULONG i;

    /* A failing build may crash after it reported: do not lose the report */
    setvbuf(stdout, NULL, _IONBF, 0);

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

    BlockEntered = CreateEventW(NULL, TRUE, FALSE, NULL);
    BlockRelease = CreateEventW(NULL, TRUE, FALSE, NULL);
    TestOrder();
    TestAddWhileCalled();
    TestRemoveWhileCalled(FALSE);
    TestRemoveWhileCalled(TRUE);
    TestSelfRemove();
    CloseHandle(BlockEntered);
    CloseHandle(BlockRelease);
}
