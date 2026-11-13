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

/* Size classes: every size around the class boundaries is served whole, is reused for the same size, and
   a block moved between classes by HeapReAlloc keeps its contents */
static void
TestClasses(HANDLE Heap, PCSTR Name)
{
    ULONG Size, Pass, Bad = 0, BadReuse = 0, BadRealloc = 0, Reused = 0, Tries = 0;
    SIZE_T Cur;
    PUCHAR Block, Block2, Other;
    ULONG k;

    for (Pass = 0; Pass < 3; Pass++)
    {
        for (Size = 0; Size <= 4200; Size++)
        {
            Block = HeapAlloc(Heap, Pass == 2 ? HEAP_ZERO_MEMORY : 0, Size);
            if (!Block || HeapSize(Heap, 0, Block) != Size || !HeapValidate(Heap, 0, Block))
            {
                Bad++;
                if (Block)
                    HeapFree(Heap, 0, Block);
                continue;
            }
            if (Pass == 2)
            {
                for (k = 0; k < Size; k++)
                    if (Block[k])
                    {
                        Bad++;
                        break;
                    }
            }
            memset(Block, (UCHAR)Size, Size);

            /* A neighbour of the same size must not overlap */
            Other = HeapAlloc(Heap, 0, Size);
            if (!Other || Other == Block ||
                (Other < Block + Size && Block < Other + Size))
                Bad++;
            if (Other)
            {
                memset(Other, 0x55, Size);
                HeapFree(Heap, 0, Other);
            }
            for (k = 0; k < Size; k++)
                if (Block[k] != (UCHAR)Size)
                {
                    Bad++;
                    break;
                }

            /* Resize up and down: contents survive, sizes are as asked */
            Cur = Size;
            for (k = 0; k < 3; k++)
            {
                static const LONG Delta[3] = { 1, 70, -63 };
                SIZE_T NewSize = ((LONG)Cur + Delta[k] < 0) ? 0 : Cur + Delta[k];
                SIZE_T Keep = min(Cur, NewSize), j;

                Block2 = HeapReAlloc(Heap, 0, Block, NewSize);
                if (!Block2)
                {
                    BadRealloc++;
                    break;
                }
                Block = Block2;
                if (HeapSize(Heap, 0, Block) != NewSize)
                    BadRealloc++;
                for (j = 0; j < Keep; j++)
                    if (Block[j] != (UCHAR)Size)
                    {
                        BadRealloc++;
                        break;
                    }
                memset(Block, (UCHAR)Size, NewSize);
                Cur = NewSize;
            }
            HeapFree(Heap, 0, Block);
        }
    }

    /* A block freed and asked for again at the same size comes back (the heap keeps it for that size) */
    for (Size = 24; Size <= 3000; Size += 37)
    {
        Block = HeapAlloc(Heap, 0, Size);
        HeapFree(Heap, 0, Block);
        Block2 = HeapAlloc(Heap, 0, Size);
        Tries++;
        if (Block2 == Block)
            Reused++;
        else if (Block2 && Size)
            BadReuse += HeapSize(Heap, 0, Block2) != Size;
        HeapFree(Heap, 0, Block2);
    }
    ok(Bad == 0, "%s: %lu size/overlap/contents errors over the sizes 0..4200\n", Name, Bad);
    ok(BadRealloc == 0, "%s: %lu HeapReAlloc errors\n", Name, BadRealloc);
    ok(BadReuse == 0, "%s: %lu reused blocks of a wrong size\n", Name, BadReuse);
    if (QueryFrontEnd(Heap) == 2)
        ok(Reused * 4 >= Tries * 3, "%s: only %lu of %lu same-size blocks came back\n", Name, Reused, Tries);
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

/* How many allocations of one size a fresh heap takes before it reports the front end (type 2), measured on
   Windows 10 x64: 18 when nothing is freed, 33 with a free after every second allocation, 2041 when every block
   is freed at once, about 797 for 4000 byte blocks (3.2 MB in use). Mode: 0 keep, 1 free at once, 2 two
   allocations and one free. Returns 0 when it did not happen within Max. */
static ULONG
CountToFrontEnd(HANDLE Heap, SIZE_T Size, ULONG Mode, ULONG Max)
{
    PVOID *Held = HeapAlloc(GetProcessHeap(), 0, Max * sizeof(PVOID));
    ULONG Held2 = 0, i, Result = 0;

    for (i = 0; i < Max; i++)
    {
        PVOID Block = HeapAlloc(Heap, 0, Size);

        if (!Block)
            break;
        if (Mode == 1)
            HeapFree(Heap, 0, Block);
        else
        {
            Held[Held2++] = Block;
            if (Mode == 2 && (i & 1))
                HeapFree(Heap, 0, Held[--Held2]);
        }
        if (QueryFrontEnd(Heap) == 2)
        {
            Result = i + 1;
            break;
        }
    }
    while (Held2)
        HeapFree(Heap, 0, Held[--Held2]);
    HeapFree(GetProcessHeap(), 0, Held);
    return Result;
}

static void
TestActivation(void)
{
    static const SIZE_T Sizes[] = { 8, 16, 24, 64, 100, 256, 1000, 2000 };
    HANDLE Heap;
    ULONG Count, i;

    for (i = 0; i < RTL_NUMBER_OF(Sizes); i++)
    {
        Heap = HeapCreate(0, 0, 0);
        Count = CountToFrontEnd(Heap, Sizes[i], 0, 4000);
        ok(Count >= 17 && Count <= 18, "size %lu: front end after %lu allocations\n", (ULONG)Sizes[i], Count);
        HeapDestroy(Heap);

        Heap = HeapCreate(0, 0, 0);
        Count = CountToFrontEnd(Heap, Sizes[i], 2, 4000);
        ok(Count >= 31 && Count <= 35, "size %lu: front end after %lu allocations (two, one freed)\n", (ULONG)Sizes[i], Count);
        HeapDestroy(Heap);
    }

    /* Allocate and free at once: Windows took 2041 for every size from 16 bytes */
    Heap = HeapCreate(0, 0, 0);
    Count = CountToFrontEnd(Heap, 64, 1, 4000);
    ok(Count == 2041, "alloc and free: front end after %lu allocations\n", Count);
    HeapDestroy(Heap);

    /* Big blocks count by bytes in use */
    Heap = HeapCreate(0, 0, 0);
    Count = CountToFrontEnd(Heap, 8000, 0, 4000);
    ok(Count >= 380 && Count <= 420, "8000 byte blocks: front end after %lu allocations\n", Count);
    HeapDestroy(Heap);

    /* Heaps that cannot have it never do */
    Heap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0);
    Count = CountToFrontEnd(Heap, 64, 0, 3000);
    ok(Count == 0, "HEAP_NO_SERIALIZE heap: front end after %lu allocations\n", Count);
    HeapDestroy(Heap);

    Heap = HeapCreate(0, 0x100000, 0x100000);
    Count = CountToFrontEnd(Heap, 64, 0, 3000);
    ok(Count == 0, "fixed size heap: front end after %lu allocations\n", Count);
    HeapDestroy(Heap);

    /* HeapSetInformation(2) on a fresh heap still works, and on one that has it already */
    Heap = HeapCreate(0, 0, 0);
    ok_eq_ulong(QueryFrontEnd(Heap), 0);
    ok(SetFrontEnd(Heap, 2), "HeapSetInformation(2) failed\n");
    ok_eq_ulong(QueryFrontEnd(Heap), 2);
    HeapDestroy(Heap);
}

START_TEST(RtlHeapFrontEnd)
{
    HANDLE Heap;

    TestInformation();
    TestActivation();

    Heap = HeapCreate(0, 0, 0);
    SetFrontEnd(Heap, 2);
    TestBlocks(Heap, "front end heap");
    TestClasses(Heap, "front end heap");
    TestStress(Heap, "front end heap");
    HeapDestroy(Heap);

    Heap = HeapCreate(0, 0, 0);
    TestBlocks(Heap, "plain heap");
    TestClasses(Heap, "plain heap");
    HeapDestroy(Heap);

    TestBlocks(GetProcessHeap(), "process heap");
    TestStress(GetProcessHeap(), "process heap");
    TestWalk();
    TestLock();
    TestSection();
}
