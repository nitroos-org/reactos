/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A polygon region of a few points very far apart does not take the paged pool of the session
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The scan conversion of a polygon buffers two points for every row it crosses. A triangle that spans 2^28 rows
 * asked for gigabytes of paged pool and, on a machine with a small pool, took all of it: every other call of the
 * system that needs paged pool failed until the call ended. The call must come back with a region or with a failure,
 * having used a bounded amount of memory; a drawing of a few thousand rows still makes its region.
 */

#include "precomp.h"

#define PEAK_LIMIT_BYTES (128u * 1024 * 1024)

typedef LONG (WINAPI *PFN_QSI)(ULONG, PVOID, ULONG, PULONG);

typedef struct
{
    ULONG Tag;
    ULONG PagedAllocs, PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs, NonPagedFrees;
    SIZE_T NonPagedUsed;
} POOLTAG_ENTRY;

static PFN_QSI g_Qsi;
static volatile LONG g_Stop;
static volatile SIZE_T g_Peak;
static SIZE_T g_Base;
static BOOL g_HaveSample;

/* Paged pool bytes in use under the tag of the GDI region lookaside ("Gla4") */
static BOOL SampleRegionTag(SIZE_T *pUsed)
{
    ULONG Need = 0, Count, i;
    BYTE *Buffer;
    POOLTAG_ENTRY *Entries;
    LONG Status;
    BOOL Found = FALSE;

    Buffer = HeapAlloc(GetProcessHeap(), 0, 8 << 20);
    if (!Buffer)
        return FALSE;
    Status = g_Qsi(22, Buffer, 8 << 20, &Need);
    if (Status >= 0)
    {
        Count = *(ULONG *)Buffer;
        Entries = (POOLTAG_ENTRY *)(Buffer + sizeof(ULONG_PTR));
        for (i = 0; i < Count; i++)
        {
            if (!memcmp(&Entries[i].Tag, "Gla4", 4))
            {
                *pUsed = Entries[i].PagedUsed;
                Found = TRUE;
                break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
    return Found;
}

static DWORD WINAPI SamplerThread(LPVOID Param)
{
    SIZE_T Used;

    while (!g_Stop)
    {
        if (SampleRegionTag(&Used) && Used > g_Peak)
            g_Peak = Used;
        Sleep(15);
    }
    return 0;
}

static void TestFarTriangle(void)
{
    POINT Points[3];
    HANDLE Thread;
    HRGN Region;
    DWORD Start = GetTickCount();

    Points[0].x = 0;
    Points[0].y = -(1 << 27);
    Points[1].x = 100;
    Points[1].y = 1 << 27;
    Points[2].x = 200;
    Points[2].y = 0;

    g_Stop = 0;
    g_Peak = 0;
    Thread = g_HaveSample ? CreateThread(NULL, 0, SamplerThread, NULL, 0, NULL) : NULL;

    SetLastError(0xDEADBEEF);
    Region = CreatePolygonRgn(Points, 3, ALTERNATE);
    trace("CreatePolygonRgn of the far triangle: %p, error %lu, %lu ms\n", Region, GetLastError(),
          GetTickCount() - Start);

    g_Stop = 1;
    if (Thread)
    {
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
    }
    if (Region)
        DeleteObject(Region);

    if (g_HaveSample)
    {
        ok(g_Peak < g_Base + PEAK_LIMIT_BYTES, "the far triangle held %lu MB of region pool at most\n",
           (ULONG)((g_Peak - g_Base) >> 20));
    }
    else
    {
        skip("the pool tags cannot be read\n");
    }
}

static void TestOrdinaryPolygons(void)
{
    POINT Points[5];
    HRGN Region;
    RECT Box;
    int i;

    /* A drawing as tall as the largest display, and one of ten thousand rows */
    for (i = 0; i < 2; i++)
    {
        LONG Height = i ? 10000 : 16384;

        Points[0].x = 0;      Points[0].y = 0;
        Points[1].x = 1000;   Points[1].y = Height / 2;
        Points[2].x = 0;      Points[2].y = Height;
        Points[3].x = 500;    Points[3].y = Height / 2;
        Points[4].x = 250;    Points[4].y = Height / 4;
        Region = CreatePolygonRgn(Points, 5, WINDING);
        ok(Region != NULL, "CreatePolygonRgn of a %ld rows high polygon failed, error %lu\n", Height, GetLastError());
        if (Region)
        {
            ok(GetRgnBox(Region, &Box) != ERROR, "GetRgnBox failed\n");
            /* The apexes are thin: the first and last rows of a pointed polygon can be empty */
            ok(Box.top >= 0 && Box.top <= Height / 100 && Box.bottom >= Height - Height / 100 && Box.bottom <= Height,
               "box %ld..%ld of a %ld rows high polygon\n", Box.top, Box.bottom, Height);
            DeleteObject(Region);
        }
    }
}

START_TEST(PolygonRegionBound)
{
    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    SIZE_T Used;

    g_Qsi = (PFN_QSI)GetProcAddress(Ntdll, "NtQuerySystemInformation");
    g_HaveSample = g_Qsi && SampleRegionTag(&Used);
    if (g_HaveSample)
        g_Base = Used;

    TestOrdinaryPolygons();
    TestFarTriangle();
    TestOrdinaryPolygons();
}
