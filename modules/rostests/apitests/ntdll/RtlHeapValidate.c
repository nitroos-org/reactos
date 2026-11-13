/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Whole-heap HeapValidate on a consistent heap, and allocation failure on a fixed-size heap
 */

#include "precomp.h"

#define LIVE 64

static ULONG
Next(ULONG *Seed)
{
    *Seed = *Seed * 1664525u + 1013904223u;
    return *Seed >> 8;
}

static SIZE_T
PickSize(ULONG *Seed)
{
    if (Next(Seed) % 3)
        return 16 + Next(Seed) % 300;
    /* 2000 .. 11000 bytes: crosses the decommit threshold of a page */
    return 2000 + Next(Seed) % 9000;
}

static void
RandomValidate(DWORD HeapFlags, ULONG Seed, ULONG Ops, SIZE_T MaxSize, ULONG FrontEnd)
{
    HANDLE Heap;
    PUCHAR Block[LIVE] = { 0 };
    SIZE_T Size[LIVE] = { 0 };
    ULONG i, k, Failures = 0;
    SIZE_T Cut = 0;

    Heap = HeapCreate(HeapFlags, 0, MaxSize);
    ok(Heap != NULL, "HeapCreate failed\n");
    if (!Heap)
        return;
    if (FrontEnd)
    {
        ULONG Value = 2;
        HeapSetInformation(Heap, HeapCompatibilityInformation, &Value, sizeof(Value));
    }
    ok(HeapValidate(Heap, 0, NULL), "fresh heap does not validate\n");

    for (i = 0; i < Ops; i++)
    {
        k = Next(&Seed) % LIVE;
        if (Block[k])
        {
            SIZE_T j;
            for (j = 0; j < Size[k]; j++)
            {
                if (Block[k][j] != (UCHAR)(k + 1))
                {
                    Cut++;
                    break;
                }
            }
            ok(HeapFree(Heap, 0, Block[k]), "HeapFree failed at step %lu\n", i);
            Block[k] = NULL;
        }
        else
        {
            Size[k] = PickSize(&Seed);
            Block[k] = HeapAlloc(Heap, 0, Size[k]);
            if (Block[k])
                memset(Block[k], k + 1, Size[k]);
        }
        if (!HeapValidate(Heap, 0, NULL))
        {
            if (++Failures <= 3)
                ok(0, "whole-heap validation failed at step %lu (flags %lx, front end %lu)\n", i, HeapFlags, FrontEnd);
        }
    }
    ok_eq_ulong(Cut, 0);
    for (k = 0; k < LIVE; k++)
    {
        if (Block[k])
        {
            ok(HeapValidate(Heap, 0, Block[k]), "block %lu does not validate\n", k);
            HeapFree(Heap, 0, Block[k]);
        }
    }
    ok(HeapValidate(Heap, 0, NULL), "emptied heap does not validate\n");
    ok(HeapDestroy(Heap), "HeapDestroy failed\n");
}

static void
TestFixedHeapSweep(void)
{
    HANDLE Heap;
    PVOID Block[256];
    SIZE_T Size;
    ULONG i, Count, Failed = 0;

    Heap = HeapCreate(0, 0x10000, 4 * 1024 * 1024);
    ok(Heap != NULL, "HeapCreate failed\n");
    if (!Heap)
        return;

    /* Sweep sizes: allocate until the fixed heap says no (NULL, never a hang), free everything, validate */
    for (Size = 16; Size <= 0x80000; Size = Size + Size / 3 + 8)
    {
        Count = 0;
        for (i = 0; i < RTL_NUMBER_OF(Block); i++)
        {
            Block[i] = HeapAlloc(Heap, 0, Size);
            if (!Block[i])
            {
                Failed++;
                break;
            }
            Count++;
        }
        ok(Count > 0, "size %Iu: not even one block from a 4 MB heap\n", Size);
        ok(HeapValidate(Heap, 0, NULL), "size %Iu: heap does not validate with %lu blocks\n", Size, Count);
        while (Count--)
            ok(HeapFree(Heap, 0, Block[Count]), "HeapFree failed\n");
        ok(HeapValidate(Heap, 0, NULL), "size %Iu: heap does not validate after freeing\n", Size);
    }

    /* A single request larger than the whole heap fails */
    SetLastError(0xDEADBEEF);
    ok(HeapAlloc(Heap, 0, 8 * 1024 * 1024) == NULL, "8 MB from a 4 MB fixed heap\n");
    ok(Failed > 0, "no allocation ever failed\n");
    ok(HeapDestroy(Heap), "HeapDestroy failed\n");
}

START_TEST(RtlHeapValidate)
{
    ULONG Seed;

    for (Seed = 5; Seed < 8; Seed++)
    {
        RandomValidate(0, Seed, 3000, 0, 0);
        RandomValidate(HEAP_NO_SERIALIZE, Seed, 3000, 0, 0);
        RandomValidate(0, Seed, 3000, 0, 1);
    }
    TestFixedHeapSweep();
}
