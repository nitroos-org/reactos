/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for the heap front end (HeapCompatibilityInformation 2) and for the contended critical section
 */

#include "precomp.h"

static ULONG
QueryFrontEnd(HANDLE Heap)
{
    ULONG Type = 0xDEAD;
    SIZE_T Length = 0;

    if (!HeapQueryInformation(Heap, HeapCompatibilityInformation, &Type, sizeof(Type), &Length))
        return 0xFFFF;
    return Type;
}

static BOOL
SetFrontEnd(HANDLE Heap, ULONG Value)
{
    return HeapSetInformation(Heap, HeapCompatibilityInformation, &Value, sizeof(Value));
}

static ULONG
Next(ULONG *Seed)
{
    *Seed = *Seed * 1664525u + 1013904223u;
    return *Seed >> 8;
}

static void
TestInformation(void)
{
    HANDLE Heap;
    BOOL Ret;

    /* Windows Vista and later: the process heap has the low-fragmentation heap from the start */
    ok_eq_ulong(QueryFrontEnd(GetProcessHeap()), 2);

    Heap = HeapCreate(0, 0, 0);
    ok(Heap != NULL, "HeapCreate failed\n");
    SetLastError(0xDEADBEEF);
    Ret = SetFrontEnd(Heap, 2);
    ok(Ret, "HeapSetInformation(2) failed, error %lu\n", GetLastError());
    ok_eq_ulong(QueryFrontEnd(Heap), 2);
    Ret = SetFrontEnd(Heap, 2);
    ok(Ret, "HeapSetInformation(2) again failed, error %lu\n", GetLastError());

    /* Other values are refused, also on a heap that has it */
    SetLastError(0xDEADBEEF);
    Ret = SetFrontEnd(Heap, 0);
    ok(!Ret, "HeapSetInformation(0) succeeded\n");
    ok_eq_ulong(GetLastError(), ERROR_GEN_FAILURE);
    ok_eq_ulong(QueryFrontEnd(Heap), 2);
    HeapDestroy(Heap);

    /* A heap without a lock cannot have it */
    Heap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0);
    SetLastError(0xDEADBEEF);
    Ret = SetFrontEnd(Heap, 2);
    ok(!Ret, "HeapSetInformation(2) succeeded on a HEAP_NO_SERIALIZE heap\n");
    ok_eq_ulong(GetLastError(), ERROR_INVALID_PARAMETER);
    ok_eq_ulong(QueryFrontEnd(Heap), 0);
    HeapDestroy(Heap);

    /* nor a fixed size heap */
    Heap = HeapCreate(0, 0x100000, 0x100000);
    SetLastError(0xDEADBEEF);
    Ret = SetFrontEnd(Heap, 2);
    ok(!Ret, "HeapSetInformation(2) succeeded on a fixed size heap\n");
    ok_eq_ulong(GetLastError(), ERROR_INVALID_PARAMETER);
    HeapDestroy(Heap);
}

static void
TestBlocks(HANDLE Heap, PCSTR Name)
{
    ULONG Seed = 99, i, Size, Bad = 0, Bad2 = 0;
    PUCHAR Blocks[1500];
    PUCHAR Block;
    BOOL Ret;

    /* The size of a block is the size asked for, whatever block was reused for it */
    for (i = 0; i < _countof(Blocks); i++)
    {
        Size = Next(&Seed) % 3000;
        Blocks[i] = HeapAlloc(Heap, 0, Size);
        if (!Blocks[i] || HeapSize(Heap, 0, Blocks[i]) != Size)
            Bad++;
        else
            memset(Blocks[i], 0xAA, Size);
    }
    for (i = 0; i < _countof(Blocks); i++)
        HeapFree(Heap, 0, Blocks[i]);

    Seed = 99;
    for (i = 0; i < _countof(Blocks); i++)
    {
        ULONG k;

        Size = Next(&Seed) % 3000;
        Blocks[i] = HeapAlloc(Heap, HEAP_ZERO_MEMORY, Size);
        if (!Blocks[i] || HeapSize(Heap, 0, Blocks[i]) != Size)
        {
            Bad2++;
            continue;
        }
        for (k = 0; k < Size; k++)
        {
            if (Blocks[i][k])
            {
                Bad2++;
                break;
            }
        }
    }
    for (i = 0; i < _countof(Blocks); i++)
        HeapFree(Heap, 0, Blocks[i]);
    ok(Bad == 0, "%s: %lu blocks of a wrong size\n", Name, Bad);
    ok(Bad2 == 0, "%s: %lu zeroed blocks wrong\n", Name, Bad2);

    /* A freed block is free for the caller, and cannot be freed again */
    Block = HeapAlloc(Heap, 0, 60);
    ok(HeapValidate(Heap, 0, Block), "%s: live block not valid\n", Name);
    ok(HeapFree(Heap, 0, Block), "%s: HeapFree failed\n", Name);
    SetLastError(0xDEADBEEF);
    ok(HeapSize(Heap, 0, Block) == (SIZE_T)-1, "%s: HeapSize of a freed block\n", Name);
    ok(!HeapValidate(Heap, 0, Block), "%s: freed block is valid\n", Name);
    Block = HeapAlloc(Heap, 0, 60);
    HeapFree(Heap, 0, Block);
    SetLastError(0xDEADBEEF);
    Ret = HeapFree(Heap, 0, Block);
    ok(!Ret, "%s: freeing a block twice succeeded\n", Name);
}

static int
CountBusy(HANDLE Heap)
{
    PROCESS_HEAP_ENTRY Entry;
    int Count = 0;

    RtlZeroMemory(&Entry, sizeof(Entry));
    HeapLock(Heap);
    while (HeapWalk(Heap, &Entry))
    {
        if (Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
            Count++;
    }
    HeapUnlock(Heap);
    return Count;
}

static void
TestWalk(void)
{
    HANDLE Heap = HeapCreate(0, 0, 0);
    PVOID Blocks[400];
    int i, Before, After;

    SetFrontEnd(Heap, 2);
    for (i = 0; i < _countof(Blocks); i++)
        Blocks[i] = HeapAlloc(Heap, 0, 100 + (i & 63));
    Before = CountBusy(Heap);
    for (i = 0; i < _countof(Blocks); i += 2)
        HeapFree(Heap, 0, Blocks[i]);
    After = CountBusy(Heap);
    ok_eq_int(Before - After, _countof(Blocks) / 2);
    for (i = 1; i < _countof(Blocks); i += 2)
        HeapFree(Heap, 0, Blocks[i]);
    HeapDestroy(Heap);
}

typedef struct _LOCK_TEST
{
    HANDLE Heap;
    volatile LONG State;
} LOCK_TEST;

static DWORD WINAPI
LockThread(PVOID Param)
{
    LOCK_TEST *Test = Param;
    PVOID Block = HeapAlloc(Test->Heap, 0, 64);

    Test->State = 1;
    HeapFree(Test->Heap, 0, Block);
    Test->State = 2;
    return 0;
}

static void
TestLock(void)
{
    LOCK_TEST Test;
    HANDLE Thread;
    LONG During;
    int i;

    Test.Heap = HeapCreate(0, 0, 0);
    Test.State = 0;
    SetFrontEnd(Test.Heap, 2);
    for (i = 0; i < 100; i++)
        HeapFree(Test.Heap, 0, HeapAlloc(Test.Heap, 0, 64));

    /* The holder of the heap lock excludes the allocations of other threads */
    HeapLock(Test.Heap);
    Thread = CreateThread(NULL, 0, LockThread, &Test, 0, NULL);
    Sleep(300);
    During = Test.State;
    HeapUnlock(Test.Heap);
    WaitForSingleObject(Thread, 10000);
    CloseHandle(Thread);
    ok_eq_long(During, 0);
    ok_eq_long(Test.State, 2);
    HeapDestroy(Test.Heap);
}

#define SLOTS 1024
static PVOID volatile g_Slots[SLOTS];
static volatile LONG g_Errors;
static volatile LONG g_Run;

static DWORD WINAPI
StressThread(PVOID Param)
{
    HANDLE Heap = Param;
    ULONG Seed = GetCurrentThreadId(), Op, Index, Size, k;
    PUCHAR Block, Old;

    while (g_Run)
    {
        Index = Next(&Seed) % SLOTS;
        Op = Next(&Seed) % 3;
        if (Op < 2)
        {
            /* a block is filled with a byte that depends on its size; whoever frees it checks that */
            Size = 1 + Next(&Seed) % 1800;
            Block = HeapAlloc(Heap, 0, Size);
            if (!Block || HeapSize(Heap, 0, Block) != Size)
            {
                InterlockedIncrement(&g_Errors);
                continue;
            }
            memset(Block, (UCHAR)(Size ^ (Size >> 8) ^ 0x5B), Size);
            Old = InterlockedExchangePointer((PVOID *)&g_Slots[Index], Block);
        }
        else
        {
            Old = InterlockedExchangePointer((PVOID *)&g_Slots[Index], NULL);
        }

        if (Old)
        {
            Size = (ULONG)HeapSize(Heap, 0, Old);
            for (k = 0; k < Size; k++)
            {
                if (Old[k] != (UCHAR)(Size ^ (Size >> 8) ^ 0x5B))
                {
                    InterlockedIncrement(&g_Errors);
                    break;
                }
            }
            HeapFree(Heap, 0, Old);
        }
    }
    return 0;
}

static void
TestStress(HANDLE Heap, PCSTR Name)
{
    HANDLE Threads[6];
    ULONG i;

    g_Errors = 0;
    g_Run = 1;
    for (i = 0; i < _countof(Threads); i++)
        Threads[i] = CreateThread(NULL, 0, StressThread, Heap, 0, NULL);
    Sleep(2000);
    g_Run = 0;
    WaitForMultipleObjects(_countof(Threads), Threads, TRUE, INFINITE);
    for (i = 0; i < _countof(Threads); i++)
        CloseHandle(Threads[i]);
    for (i = 0; i < SLOTS; i++)
    {
        if (g_Slots[i])
            HeapFree(Heap, 0, g_Slots[i]);
        g_Slots[i] = NULL;
    }
    ok(g_Errors == 0, "%s: %ld errors under contention\n", Name, (long)g_Errors);
}

static RTL_CRITICAL_SECTION g_Section;
static volatile LONG g_Counter;
static volatile LONG g_BadRecursion;

static DWORD WINAPI
SectionThread(PVOID Param)
{
    int i;

    for (i = 0; i < 100000; i++)
    {
        RtlEnterCriticalSection(&g_Section);
        if (g_Section.RecursionCount != 1)
            InterlockedIncrement(&g_BadRecursion);
        g_Counter++;
        if ((i & 1023) == 0)
        {
            RtlEnterCriticalSection(&g_Section);
            if (g_Section.RecursionCount != 2)
                InterlockedIncrement(&g_BadRecursion);
            RtlLeaveCriticalSection(&g_Section);
        }
        RtlLeaveCriticalSection(&g_Section);
    }
    return 0;
}

static void
TestSection(void)
{
    HANDLE Threads[6];
    ULONG i;

    RtlInitializeCriticalSection(&g_Section);
    g_Counter = 0;
    g_BadRecursion = 0;
    for (i = 0; i < _countof(Threads); i++)
        Threads[i] = CreateThread(NULL, 0, SectionThread, NULL, 0, NULL);
    WaitForMultipleObjects(_countof(Threads), Threads, TRUE, INFINITE);
    for (i = 0; i < _countof(Threads); i++)
        CloseHandle(Threads[i]);
    ok_eq_long(g_Counter, 6 * 100000);
    ok_eq_long(g_BadRecursion, 0);
    ok_eq_long(g_Section.LockCount, -1);
    ok_eq_long(g_Section.RecursionCount, 0);
    ok(g_Section.OwningThread == NULL, "OwningThread %p\n", g_Section.OwningThread);
    RtlDeleteCriticalSection(&g_Section);
}

START_TEST(RtlHeapFrontEnd)
{
    HANDLE Heap;

    TestInformation();

    Heap = HeapCreate(0, 0, 0);
    SetFrontEnd(Heap, 2);
    TestBlocks(Heap, "front end heap");
    TestStress(Heap, "front end heap");
    HeapDestroy(Heap);

    Heap = HeapCreate(0, 0, 0);
    TestBlocks(Heap, "plain heap");
    HeapDestroy(Heap);

    TestBlocks(GetProcessHeap(), "process heap");
    TestStress(GetProcessHeap(), "process heap");
    TestWalk();
    TestLock();
    TestSection();
}
