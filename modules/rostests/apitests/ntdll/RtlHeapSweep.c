/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Heap paths that changed together, exercised together: the free-page cache and its quiet-time
 *              trim, the extension into an uncommitted range next to free blocks, the release of lone committed
 *              runs, resizing in place and the small-block front end; and what a heap of a 32-bit process does
 *              when the address space runs out and comes back
 */

#include "precomp.h"

#define SLOTS 700

typedef struct _SWEEP_BLOCK
{
    PUCHAR Ptr;
    SIZE_T Size;
    UCHAR Tag;
} SWEEP_BLOCK;

static ULONG
Next(ULONG *Seed)
{
    *Seed = *Seed * 1664525u + 1013904223u;
    return *Seed >> 8;
}

/* Sizes around what the changed paths look at: a little more or less than a whole number of pages, the 29000 byte
   block of the console server, blocks near the largest one the heap keeps, and blocks above it */
static SIZE_T
PickSize(ULONG *Seed, BOOLEAN Big)
{
    ULONG Class = Next(Seed) % 100;

    if (Class < 45)
        return 1 + Next(Seed) % 600;
    if (Class < 65)
        return 600 + Next(Seed) % 7000;
    if (Class < 80)
        return (1 + Next(Seed) % 12) * PAGE_SIZE - 96 + Next(Seed) % 192;
    if (Class < 88)
        return 28944 + Next(Seed) % 64;
    if (Class < 96 || !Big)
        return 8192 + Next(Seed) % (120 * 1024);
    if (Class < 99)
        return 0x7F000 - 4096 + Next(Seed) % 4000;
    return 0x80000 + Next(Seed) % 0x40000;
}

static VOID
FillBlock(PUCHAR Block, SIZE_T Size, UCHAR Tag)
{
    if (Size <= 2 * PAGE_SIZE)
    {
        memset(Block, Tag, Size);
    }
    else
    {
        /* both ends and one byte in every page */
        SIZE_T i;
        memset(Block, Tag, PAGE_SIZE);
        memset(Block + Size - PAGE_SIZE, Tag, PAGE_SIZE);
        for (i = PAGE_SIZE; i < Size - PAGE_SIZE; i += PAGE_SIZE)
            Block[i] = Tag;
    }
}

static BOOLEAN
CheckBlock(PUCHAR Block, SIZE_T Size, UCHAR Tag)
{
    SIZE_T i;

    if (Size <= 2 * PAGE_SIZE)
    {
        for (i = 0; i < Size; i++)
            if (Block[i] != Tag) return FALSE;
        return TRUE;
    }
    for (i = 0; i < PAGE_SIZE; i++)
        if (Block[i] != Tag || Block[Size - PAGE_SIZE + i] != Tag) return FALSE;
    for (i = PAGE_SIZE; i < Size - PAGE_SIZE; i += PAGE_SIZE)
        if (Block[i] != Tag) return FALSE;
    return TRUE;
}

/* The first Common bytes of a block that was filled at OldSize and then resized: the bytes FillBlock wrote there */
static BOOLEAN
CheckPrefix(PUCHAR Block, SIZE_T OldSize, SIZE_T Common, UCHAR Tag)
{
    SIZE_T i;

    if (OldSize <= 2 * PAGE_SIZE)
    {
        for (i = 0; i < Common; i++)
            if (Block[i] != Tag) return FALSE;
        return TRUE;
    }
    for (i = 0; i < PAGE_SIZE && i < Common; i++)
        if (Block[i] != Tag) return FALSE;
    for (i = PAGE_SIZE; i < OldSize - PAGE_SIZE && i < Common; i += PAGE_SIZE)
        if (Block[i] != Tag) return FALSE;
    return TRUE;
}

static VOID
SleepMs(ULONG Ms)
{
    LARGE_INTEGER Interval;
    Interval.QuadPart = -(LONGLONG)Ms * 10000;
    NtDelayExecution(FALSE, &Interval);
}

typedef struct _SWEEP_RUN
{
    HANDLE Heap;
    ULONG Seed;
    ULONG Ops;
    BOOLEAN Big;
    BOOLEAN MayFail;        /* a heap that cannot grow may refuse */
    BOOLEAN Validate;
    ULONG QuietEvery;       /* a pause of more than a second every so many operations (0: none) */
    ULONG Corrupt, Short, Refused, Invalid, Lost;
    SWEEP_BLOCK Blocks[SLOTS];
} SWEEP_RUN;

/* Where a run is, for the report of a fault inside the heap (single-threaded runs) */
static volatile ULONG LastCase, LastOp, LastKind;
static volatile SIZE_T LastSize, LastOldSize;
static volatile PVOID LastPtr;

static LONG WINAPI
SweepFault(PEXCEPTION_POINTERS Info)
{
    static LONG Reported;
    PEXCEPTION_RECORD Rec = Info->ExceptionRecord;

    if (Rec->ExceptionCode == STATUS_ACCESS_VIOLATION && InterlockedIncrement(&Reported) == 1)
    {
        HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
        PVOID Frames[12];
        USHORT n, k;

        printf("FAULT at %p (ntdll %p, rva %lx) %s address %p; case %lu op %lu kind %lu size %lu old size %lu block %p\n",
               Rec->ExceptionAddress, Ntdll,
               (ULONG)((ULONG_PTR)Rec->ExceptionAddress - (ULONG_PTR)Ntdll),
               Rec->ExceptionInformation[0] ? "writing" : "reading", (PVOID)Rec->ExceptionInformation[1],
               LastCase, LastOp, LastKind, (ULONG)LastSize, (ULONG)LastOldSize, LastPtr);
        n = RtlCaptureStackBackTrace(0, 12, Frames, NULL);
        for (k = 0; k < n; k++)
            printf("  frame %u: %p (ntdll rva %lx)\n", k, Frames[k], (ULONG)((ULONG_PTR)Frames[k] - (ULONG_PTR)Ntdll));
        fflush(stdout);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static VOID
SweepRun(SWEEP_RUN *Run)
{
    ULONG i, Slot, Op;
    SIZE_T Live = 0;

    for (i = 0; i < Run->Ops; i++)
    {
        SWEEP_BLOCK *B;

        Slot = Next(&Run->Seed) % SLOTS;
        B = &Run->Blocks[Slot];
        Op = Next(&Run->Seed) % 100;
        LastOp = i;
        LastKind = !B->Ptr ? 0 : (Op < 50 ? 1 : (Op < 60 ? 2 : (Op < 85 ? 3 : 4)));
        LastPtr = B->Ptr;
        LastOldSize = B->Size;

        if (!B->Ptr)
        {
            SIZE_T Size = PickSize(&Run->Seed, Run->Big);

            /* keep the live total modest, so that a refusal is the heap's doing */
            if (Live + Size > 48 * 1024 * 1024)
                continue;
            LastSize = Size;
            B->Ptr = RtlAllocateHeap(Run->Heap, 0, Size);
            if (!B->Ptr)
            {
                Run->Refused++;
                continue;
            }
            if (RtlSizeHeap(Run->Heap, 0, B->Ptr) < Size)
                Run->Short++;
            B->Size = Size;
            B->Tag = (UCHAR)(1 + Next(&Run->Seed) % 250);
            FillBlock(B->Ptr, Size, B->Tag);
            Live += Size;
        }
        else if (Op < 50)
        {
            if (!CheckBlock(B->Ptr, B->Size, B->Tag))
                Run->Corrupt++;
            if (!RtlFreeHeap(Run->Heap, 0, B->Ptr))
                Run->Lost++;
            Live -= B->Size;
            B->Ptr = NULL;
        }
        else if (Op < 85)
        {
            SIZE_T Size = PickSize(&Run->Seed, Run->Big), Common = min(Size, B->Size);
            ULONG Flags = (Op < 60) ? HEAP_REALLOC_IN_PLACE_ONLY : 0;
            PUCHAR New;

            if (Live - B->Size + Size > 48 * 1024 * 1024)
                continue;
            if (!CheckBlock(B->Ptr, B->Size, B->Tag))
                Run->Corrupt++;
            LastSize = Size;
            New = RtlReAllocateHeap(Run->Heap, Flags, B->Ptr, Size);
            if (!New)
            {
                /* the old block must be untouched */
                if (!CheckBlock(B->Ptr, B->Size, B->Tag))
                    Run->Corrupt++;
                if (!Flags)
                    Run->Refused++;
                continue;
            }
            if (RtlSizeHeap(Run->Heap, 0, New) < Size)
                Run->Short++;
            /* the common part moved with the block */
            if (!CheckPrefix(New, B->Size, Common, B->Tag))
                Run->Corrupt++;
            Live = Live - B->Size + Size;
            B->Ptr = New;
            B->Size = Size;
            FillBlock(New, Size, B->Tag);
        }
        else
        {
            if (!CheckBlock(B->Ptr, B->Size, B->Tag))
                Run->Corrupt++;
        }

        if (Run->Validate && i % 2000 == 1999 && !RtlValidateHeap(Run->Heap, 0, NULL))
        {
            Run->Invalid++;
            break;
        }

        if (Run->QuietEvery && i % Run->QuietEvery == Run->QuietEvery - 1)
        {
            /* a quiet second: the next frees trim the cache, the allocations after them extend again */
            SleepMs(1150);
        }
    }

    for (i = 0; i < SLOTS; i++)
    {
        SWEEP_BLOCK *B = &Run->Blocks[i];
        if (!B->Ptr)
            continue;
        if (!CheckBlock(B->Ptr, B->Size, B->Tag))
            Run->Corrupt++;
        if (!RtlFreeHeap(Run->Heap, 0, B->Ptr))
            Run->Lost++;
        B->Ptr = NULL;
    }
}

static VOID
ReportRun(const char *What, ULONG Case, SWEEP_RUN *Run)
{
    ok(Run->Corrupt == 0, "%s %lu: %lu blocks lost their contents\n", What, Case, Run->Corrupt);
    ok(Run->Short == 0, "%s %lu: %lu blocks shorter than asked for\n", What, Case, Run->Short);
    ok(Run->Invalid == 0, "%s %lu: the heap did not validate\n", What, Case);
    ok(Run->Lost == 0, "%s %lu: %lu frees failed\n", What, Case, Run->Lost);
    if (!Run->MayFail)
        ok(Run->Refused == 0, "%s %lu: %lu requests refused by a heap that can grow\n", What, Case, Run->Refused);
}

static VOID
TestSingle(VOID)
{
    static const struct { ULONG Flags; SIZE_T Reserve, Commit; BOOLEAN Big; ULONG Quiet; ULONG Ops; } Cases[] =
    {
        { HEAP_GROWABLE, 0, 0, TRUE, 0, 150000 },
        { HEAP_GROWABLE, 0, 0, TRUE, 12000, 120000 },
        { HEAP_GROWABLE, 0x40000, 0x2000, FALSE, 9000, 90000 },
        { HEAP_GROWABLE | HEAP_NO_SERIALIZE, 0x80000, 0x1000, TRUE, 15000, 90000 },
        /* fixed size: nowhere to grow, the trim-and-retry of the extension runs */
        { 0, 0x600000, 0x10000, FALSE, 10000, 100000 },
        { 0, 0x200000, 0x200000, FALSE, 10000, 60000 },
    };
    static SWEEP_RUN Run;
    ULONG i;

    for (i = 0; i < _countof(Cases); i++)
    {
        RtlZeroMemory(&Run, sizeof(Run));
        Run.Heap = RtlCreateHeap(Cases[i].Flags, NULL, Cases[i].Reserve, Cases[i].Commit, NULL, NULL);
        ok(Run.Heap != NULL, "case %lu: RtlCreateHeap failed\n", i);
        if (!Run.Heap)
            continue;
        LastCase = i;
        Run.Seed = 0x5EED0000 + i * 7919;
        Run.Ops = Cases[i].Ops;
        Run.Big = Cases[i].Big;
        Run.MayFail = !(Cases[i].Flags & HEAP_GROWABLE);
        Run.Validate = TRUE;
        Run.QuietEvery = Cases[i].Quiet;
        SweepRun(&Run);
        ReportRun("single", i, &Run);
        trace("single %lu: refused %lu\n", i, Run.Refused);
        ok(RtlValidateHeap(Run.Heap, 0, NULL), "case %lu: heap invalid at the end\n", i);
        RtlDestroyHeap(Run.Heap);
    }
}

#define THREADS 4

static DWORD WINAPI
SweepThread(PVOID Param)
{
    SweepRun((SWEEP_RUN *)Param);
    return 0;
}

static VOID
TestThreads(VOID)
{
    static SWEEP_RUN Runs[THREADS];
    HANDLE Heap, Threads[THREADS];
    ULONG i, Round;

    for (Round = 0; Round < 2; Round++)
    {
        Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
        ok(Heap != NULL, "RtlCreateHeap failed\n");
        if (!Heap)
            return;

        for (i = 0; i < THREADS; i++)
        {
            RtlZeroMemory(&Runs[i], sizeof(Runs[i]));
            Runs[i].Heap = Heap;
            Runs[i].Seed = 0xABCD0000 + Round * 104729 + i * 31;
            Runs[i].Ops = 120000;
            Runs[i].Big = (i == 0);
            /* one thread validates the whole heap while the others run */
            Runs[i].Validate = (i == 1);
            Runs[i].QuietEvery = (Round == 1 && i >= 2) ? 20000 : 0;
            Threads[i] = CreateThread(NULL, 0, SweepThread, &Runs[i], 0, NULL);
            ok(Threads[i] != NULL, "CreateThread failed\n");
        }
        for (i = 0; i < THREADS; i++)
        {
            if (Threads[i])
            {
                WaitForSingleObject(Threads[i], INFINITE);
                CloseHandle(Threads[i]);
            }
            ReportRun(Round ? "threads+quiet" : "threads", i, &Runs[i]);
        }
        ok(RtlValidateHeap(Heap, 0, NULL), "round %lu: heap invalid at the end\n", Round);
        RtlDestroyHeap(Heap);
    }
}

/* Fills a heap with blocks of one size until it refuses or Limit bytes are held. Returns the bytes held. */
static ULONGLONG
FillHeap(HANDLE Heap, SIZE_T Size, ULONGLONG Limit, PVOID **List, ULONG *Count)
{
    ULONG Max = (ULONG)(Limit / Size) + 1, n = 0;
    PVOID *Blocks = VirtualAlloc(NULL, Max * sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    *List = Blocks;
    *Count = 0;
    if (!Blocks)
        return 0;
    while (n < Max)
    {
        PUCHAR P = RtlAllocateHeap(Heap, 0, Size);
        if (!P)
            break;
        P[0] = 0xA5;
        P[Size - 1] = 0x5A;
        Blocks[n++] = P;
    }
    *Count = n;
    return (ULONGLONG)n * Size;
}

static ULONG
DrainHeap(HANDLE Heap, SIZE_T Size, PVOID *Blocks, ULONG Count, ULONG Step, ULONG Phase)
{
    ULONG i, Bad = 0;

    for (i = Phase; i < Count; i += Step)
    {
        PUCHAR P = Blocks[i];
        if (!P)
            continue;
        if (P[0] != 0xA5 || P[Size - 1] != 0x5A)
            Bad++;
        RtlFreeHeap(Heap, 0, P);
        Blocks[i] = NULL;
    }
    return Bad;
}

/* The address space of the process is the limit of a growable heap. A heap that was filled to that limit and emptied
   again must be able to hold as much a second time, also with blocks of another size, and must stay valid when the
   system refused it memory. On a 64-bit process the fill stops at Limit, so only the reuse is tested. */
static VOID
TestAddressSpace(VOID)
{
    static const SIZE_T Sizes[] = { 400 * 1024, 100 * 1024, 28944, 330 * 1024 };
    ULONGLONG Limit, First = 0, Got;
    HANDLE Heap;
    PVOID *Blocks;
    ULONG Count, i, Bad;
    SYSTEM_BASIC_INFORMATION Sbi;
    BOOLEAN Is32 = (sizeof(PVOID) == 4);

    NtQuerySystemInformation(SystemBasicInformation, &Sbi, sizeof(Sbi), NULL);
    Limit = Is32 ? 0xFFFFFFFFull : 1536ull * 1024 * 1024;

    Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;

    for (i = 0; i < _countof(Sizes); i++)
    {
        Got = FillHeap(Heap, Sizes[i], Limit, &Blocks, &Count);
        trace("fill %lu: %lu blocks of %lu bytes = %lu MB\n", i, Count, (ULONG)Sizes[i], (ULONG)(Got >> 20));
        ok(RtlValidateHeap(Heap, 0, NULL), "fill %lu: heap invalid when full\n", i);
        if (i == 0)
        {
            First = Got;
            /* a 32-bit process has 2 GB of user address space: half of it is not much to ask */
            ok(Got >= 1024ull * 1024 * 1024, "first fill holds only %lu MB\n", (ULONG)(Got >> 20));
        }
        else
        {
            ok(Got >= First - First / 8, "fill %lu holds %lu MB, the first held %lu MB\n",
               i, (ULONG)(Got >> 20), (ULONG)(First >> 20));
        }

        /* every other block first, a quiet second, then the rest: decommit, cache, trim and island paths */
        Bad = DrainHeap(Heap, Sizes[i], Blocks, Count, 2, 0);
        ok(RtlValidateHeap(Heap, 0, NULL), "fill %lu: heap invalid half empty\n", i);
        SleepMs(1150);
        Bad += DrainHeap(Heap, Sizes[i], Blocks, Count, 2, 1);
        ok(Bad == 0, "fill %lu: %lu blocks lost their contents\n", i, Bad);
        ok(RtlValidateHeap(Heap, 0, NULL), "fill %lu: heap invalid when emptied\n", i);
        VirtualFree(Blocks, 0, MEM_RELEASE);
    }

    RtlDestroyHeap(Heap);
}

START_TEST(RtlHeapSweep)
{
    AddVectoredExceptionHandler(1, SweepFault);
    TestSingle();
    TestThreads();
    TestAddressSpace();
}
