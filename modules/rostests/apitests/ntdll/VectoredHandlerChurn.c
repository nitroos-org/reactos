/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Vectored handlers added and removed while other threads dispatch exceptions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <setjmp.h>

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


/* ---- Handlers that remove others or themselves while one exception walks the list ---- */

#define WALK_CODE 0xE0000005

static PVOID WalkHandles[4];
static char WalkCalls[16];
static ULONG WalkCount;
static LONG WalkRemove;   /* What handler 0 removes: -1 none, else the index */

static LONG WalkCall(ULONG Index, PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != WALK_CODE)
        return EXCEPTION_CONTINUE_SEARCH;
    if (WalkCount < sizeof(WalkCalls) - 1)
        WalkCalls[WalkCount++] = (char)('0' + Index);
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG NTAPI WalkHandler0(PEXCEPTION_POINTERS ExceptionInfo)
{
    if ((ExceptionInfo->ExceptionRecord->ExceptionCode == WALK_CODE) && (WalkRemove >= 0) && WalkHandles[WalkRemove])
    {
        ok(RtlRemoveVectoredExceptionHandler(WalkHandles[WalkRemove]) != 0, "Remove %ld failed\n", WalkRemove);
        WalkHandles[WalkRemove] = NULL;
    }
    return WalkCall(0, ExceptionInfo);
}
static LONG NTAPI WalkHandler1(PEXCEPTION_POINTERS ExceptionInfo) { return WalkCall(1, ExceptionInfo); }
static LONG NTAPI WalkHandler2(PEXCEPTION_POINTERS ExceptionInfo) { return WalkCall(2, ExceptionInfo); }
static LONG NTAPI WalkHandler3(PEXCEPTION_POINTERS ExceptionInfo)
{
    WalkCall(3, ExceptionInfo);
    return (ExceptionInfo->ExceptionRecord->ExceptionCode == WALK_CODE) ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

static void TestRemoveDuringWalk(LONG Remove, const char *Expected, const char *ExpectedAfter)
{
    ULONG i;

    /* Order on the list: 0 (first), 2, 1, 3 (last, handles the exception) */
    WalkHandles[1] = RtlAddVectoredExceptionHandler(FALSE, WalkHandler1);
    WalkHandles[3] = RtlAddVectoredExceptionHandler(FALSE, WalkHandler3);
    WalkHandles[2] = RtlAddVectoredExceptionHandler(TRUE, WalkHandler2);
    WalkHandles[0] = RtlAddVectoredExceptionHandler(TRUE, WalkHandler0);

    WalkRemove = Remove;
    WalkCount = 0;
    RaiseException(WALK_CODE, 0, 0, NULL);
    WalkCalls[WalkCount] = 0;
    ok(!strcmp(WalkCalls, Expected), "Remove %ld: calls '%s', expected '%s'\n", Remove, WalkCalls, Expected);

    /* The removed handler stays removed */
    WalkRemove = -1;
    WalkCount = 0;
    RaiseException(WALK_CODE, 0, 0, NULL);
    WalkCalls[WalkCount] = 0;
    ok(!strcmp(WalkCalls, ExpectedAfter), "Remove %ld, again: calls '%s', expected '%s'\n", Remove, WalkCalls, ExpectedAfter);

    for (i = 0; i < 4; i++)
    {
        if (WalkHandles[i])
            ok(RtlRemoveVectoredExceptionHandler(WalkHandles[i]) != 0, "Remove %lu failed\n", i);
        WalkHandles[i] = NULL;
    }
}

/* ---- Walks that do not return: the entries removed after them are freed all the same ---- */

#define LEFT_CODE 0xE0000006
#define LEFT_JUMPS 10000
#define LEFT_CHURNS 200000
#define LEFT_GROWTH (1024 * 1024)

/* Private bytes: a removed entry that is never freed costs a heap block (16-32 bytes plus the heap's header),
   LEFT_CHURNS of them several MB */
static SIZE_T PrivateBytes(void)
{
    VM_COUNTERS Counters;

    if (!NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(), ProcessVmCounters, &Counters, sizeof(Counters), NULL)))
        return 0;
    return Counters.PagefileUsage;
}

static void Churn(ULONG Count)
{
    PVOID Handle;
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        Handle = RtlAddVectoredExceptionHandler(i & 1, SearchHandler);
        if (Handle)
            RtlRemoveVectoredExceptionHandler(Handle);
    }
}

static DWORD WINAPI ChurnThreadCount(PVOID Parameter)
{
    Churn(PtrToUlong(Parameter));
    return 0;
}

/* Churns in the calling thread; whether the private bytes stayed (nearly) the same */
static void ExpectChurnFlat(const char *What)
{
    SIZE_T Before, After;

    Churn(1000);
    Before = PrivateBytes();
    Churn(LEFT_CHURNS);
    After = PrivateBytes();
    ok(After < Before + LEFT_GROWTH, "%s: %lu handler changes grew the private bytes by %ld KB\n",
       What, (ULONG)LEFT_CHURNS, (LONG)((SSIZE_T)(After - Before) / 1024));
    trace("%s: private bytes %lu KB -> %lu KB\n", What, (ULONG)(Before / 1024), (ULONG)(After / 1024));
}

static LONG NTAPI LeftContinue(PEXCEPTION_POINTERS ExceptionInfo)
{
    return ExceptionInfo->ExceptionRecord->ExceptionCode == LEFT_CODE ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

/* A handler that longjmps out of the dispatcher, LEFT_JUMPS times and more, while another thread adds and removes
   handlers */
static jmp_buf LeftJump;
static volatile LONG LeftJumpCalls;

static LONG NTAPI JumpingHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != LEFT_CODE)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&LeftJumpCalls);
    longjmp(LeftJump, 1);
}

static void TestLeftByLongjmp(void)
{
    volatile ULONG Jumps = 0, Returns = 0;
    PVOID Jumping, Continue;
    HANDLE Churner;
    SIZE_T Before, After;

    LeftJumpCalls = 0;
    Continue = RtlAddVectoredExceptionHandler(FALSE, LeftContinue);
    Jumping = RtlAddVectoredExceptionHandler(TRUE, JumpingHandler);
    ok(Continue && Jumping, "RtlAddVectoredExceptionHandler failed\n");
    if (!Continue || !Jumping)
        return;

    Churn(1000);
    Before = PrivateBytes();
    Churner = CreateThread(NULL, 0, ChurnThreadCount, UlongToPtr(LEFT_CHURNS), 0, NULL);
    ok(Churner != NULL, "CreateThread failed: %lu\n", GetLastError());
    while (Jumps < LEFT_JUMPS || (Churner && WaitForSingleObject(Churner, 0) == WAIT_TIMEOUT))
    {
        if (setjmp(LeftJump) == 0)
        {
            RaiseException(LEFT_CODE, 0, 0, NULL);
            Returns++;
        }
        else
        {
            Jumps++;
        }
    }
    After = PrivateBytes();
    if (Churner)
        CloseHandle(Churner);

    ok(Returns == 0, "The exception returned %lu times\n", Returns);
    ok(Jumps == (ULONG)LeftJumpCalls, "Jumps %lu, handler calls %ld\n", Jumps, LeftJumpCalls);
    ok(After < Before + LEFT_GROWTH, "%lu jumps out of a handler while %lu handler changes grew the private bytes by %ld KB\n",
       Jumps, (ULONG)LEFT_CHURNS, (LONG)((SSIZE_T)(After - Before) / 1024));
    trace("longjmp: %lu jumps, private bytes %lu KB -> %lu KB\n", Jumps, (ULONG)(Before / 1024), (ULONG)(After / 1024));

    ok(RtlRemoveVectoredExceptionHandler(Jumping) != 0, "Remove failed\n");

    /* The walk the last jump left: this thread's next exception drops it */
    RaiseException(LEFT_CODE, 0, 0, NULL);
    ExpectChurnFlat("after the last jump");
    ok(RtlRemoveVectoredExceptionHandler(Continue) != 0, "Remove failed\n");
}

/* A handler that raises again and longjmps out of the inner dispatch, back into itself: the outer walk returns */
static jmp_buf InnerJump;
#define LEFT_INNER_CODE 0xE0000007

static LONG NTAPI NestingHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == LEFT_INNER_CODE)
        longjmp(InnerJump, 1);
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != LEFT_CODE)
        return EXCEPTION_CONTINUE_SEARCH;
    if (setjmp(InnerJump) == 0)
        RaiseException(LEFT_INNER_CODE, 0, 0, NULL);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void TestLeftNested(void)
{
    PVOID Nesting;
    ULONG i;

    Nesting = RtlAddVectoredExceptionHandler(TRUE, NestingHandler);
    ok(Nesting != NULL, "RtlAddVectoredExceptionHandler failed\n");
    if (!Nesting)
        return;
    for (i = 0; i < 100; i++)
        RaiseException(LEFT_CODE, 0, 0, NULL);
    ExpectChurnFlat("after inner walks that were left");
    ok(RtlRemoveVectoredExceptionHandler(Nesting) != 0, "Remove failed\n");
}

/* A thread that exits inside a handler */
#define LEFT_EXIT_CODE 0xE0000008

static LONG NTAPI ExitingHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == LEFT_EXIT_CODE)
        ExitThread(7);
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI ExitRaiser(PVOID Parameter)
{
    RaiseException(LEFT_EXIT_CODE, 0, 0, NULL);
    return 1;
}

static void TestLeftByExitThread(void)
{
    PVOID Exiting;
    HANDLE Thread;
    DWORD Code;
    ULONG i;

    Exiting = RtlAddVectoredExceptionHandler(TRUE, ExitingHandler);
    ok(Exiting != NULL, "RtlAddVectoredExceptionHandler failed\n");
    if (!Exiting)
        return;
    for (i = 0; i < 20; i++)
    {
        Thread = CreateThread(NULL, 0, ExitRaiser, NULL, 0, NULL);
        ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (!Thread)
            break;
        ok(WaitForSingleObject(Thread, WAIT_MS) == WAIT_OBJECT_0, "The thread did not exit\n");
        Code = 0;
        GetExitCodeThread(Thread, &Code);
        ok(Code == 7, "Exit code %lu\n", Code);
        CloseHandle(Thread);
    }
    ok(RtlRemoveVectoredExceptionHandler(Exiting) != 0, "Remove failed\n");
    ExpectChurnFlat("after ExitThread in a handler");
}

/* A thread that is terminated inside a handler (no LdrShutdownThread); and one that stays inside a handler, whose
   entry must stay allocated whatever is removed meanwhile */
#define LEFT_BLOCK_CODE 0xE0000009

static LONG NTAPI ParkingHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != LEFT_BLOCK_CODE)
        return EXCEPTION_CONTINUE_SEARCH;
    SetEvent(BlockEntered);
    WaitForSingleObject(BlockRelease, INFINITE);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI BlockRaiser(PVOID Parameter)
{
    RaiseException(LEFT_BLOCK_CODE, 0, 0, NULL);
    return 3;
}

static void TestLeftByTerminateThread(void)
{
    PVOID Parking;
    HANDLE Thread;
    DWORD Code;

    ResetEvent(BlockEntered);
    ResetEvent(BlockRelease);
    Parking = RtlAddVectoredExceptionHandler(TRUE, ParkingHandler);
    ok(Parking != NULL, "RtlAddVectoredExceptionHandler failed\n");
    if (!Parking)
        return;

    /* Alive inside the handler: its walk holds the entry of the handler, which is removed and stays allocated
       while other removals pile up */
    Thread = CreateThread(NULL, 0, BlockRaiser, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!Thread)
        return;
    ok(WaitForSingleObject(BlockEntered, WAIT_MS) == WAIT_OBJECT_0, "The handler was not entered\n");
    ok(RtlRemoveVectoredExceptionHandler(Parking) != 0, "Remove failed\n");
    Churn(5000);
    ok(!HeapReusedBlock(Parking), "The entry of a handler a live walk is inside was freed\n");

    /* Terminated there: its walk is dropped once removals pile up */
    ok(TerminateThread(Thread, 9), "TerminateThread failed: %lu\n", GetLastError());
    ok(WaitForSingleObject(Thread, WAIT_MS) == WAIT_OBJECT_0, "The thread did not end\n");
    Code = 0;
    GetExitCodeThread(Thread, &Code);
    ok(Code == 9, "Exit code %lu\n", Code);
    CloseHandle(Thread);
    ExpectChurnFlat("after TerminateThread in a handler");
}

/* Walks on two stacks: a fiber switches away inside a handler, the other fiber takes exceptions meanwhile; the
   fiber's walk is still on, so its handler's entry must stay allocated */
#define LEFT_FIBER_CODE 0xE000000A
static PVOID MainFiber, OtherFiber;
static volatile LONG FiberCalls, FiberDone;
static PVOID FiberHandle;

static LONG NTAPI FiberHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != LEFT_FIBER_CODE)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&FiberCalls);
    if (GetCurrentFiber() == OtherFiber)
        SwitchToFiber(MainFiber);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static VOID WINAPI FiberProc(PVOID Parameter)
{
    RaiseException(LEFT_FIBER_CODE, 0, 0, NULL);
    FiberDone = 1;
    SwitchToFiber(MainFiber);
}

static DWORD WINAPI FiberTestThread(PVOID Parameter)
{
    ULONG i;

    MainFiber = ConvertThreadToFiber(NULL);
    OtherFiber = CreateFiber(0, FiberProc, NULL);
    ok(MainFiber && OtherFiber, "Fibers: %p %p, %lu\n", MainFiber, OtherFiber, GetLastError());
    if (!MainFiber || !OtherFiber)
        return 1;

    /* The other fiber is inside the handler now */
    SwitchToFiber(OtherFiber);
    ok(FiberCalls == 1, "Calls %ld\n", FiberCalls);
    for (i = 0; i < 10; i++)
        RaiseException(LEFT_FIBER_CODE, 0, 0, NULL);
    ok(RtlRemoveVectoredExceptionHandler(FiberHandle) != 0, "Remove failed\n");
    Churn(5000);
    ok(!HeapReusedBlock(FiberHandle), "The entry of a handler a fiber's walk is inside was freed\n");

    /* Back into the handler: its walk ends */
    SwitchToFiber(OtherFiber);
    ok(FiberDone == 1, "The fiber did not finish\n");
    DeleteFiber(OtherFiber);
    ConvertFiberToThread();
    return 0;
}

static void TestFibers(void)
{
    HANDLE Thread;

    FiberHandle = RtlAddVectoredExceptionHandler(TRUE, FiberHandler);
    ok(FiberHandle != NULL, "RtlAddVectoredExceptionHandler failed\n");
    if (!FiberHandle)
        return;
    Thread = CreateThread(NULL, 0, FiberTestThread, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!Thread)
        return;
    ok(WaitForSingleObject(Thread, WAIT_MS) == WAIT_OBJECT_0, "The fiber thread did not finish\n");
    CloseHandle(Thread);
    ok(FiberCalls == 11, "Calls %ld\n", FiberCalls);
    ExpectChurnFlat("after walks on two fibers");
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
    TestRemoveDuringWalk(-1, "0213", "0213");
    TestRemoveDuringWalk(1, "023", "023");   /* a later one: not called */
    TestRemoveDuringWalk(2, "013", "013");   /* the next one */
    TestRemoveDuringWalk(0, "0213", "213");  /* itself: the walk goes on */
    TestFibers();
    TestLeftNested();
    TestLeftByExitThread();
    TestLeftByTerminateThread();
    TestLeftByLongjmp();
    CloseHandle(BlockEntered);
    CloseHandle(BlockRelease);
}
