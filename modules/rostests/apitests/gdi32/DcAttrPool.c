/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the user mode DC_ATTR pool of win32k (GdiPoolAllocate/GdiPoolFree)
 *
 * Every DC gets a DC_ATTR from a per-process pool of 64 KB sections. The pool must hand its slots back
 * when a DC is deleted and also when it fails to commit the pages of a slot (commit limit reached).
 * It used to keep the slot marked as used in that case, so a short lack of commit charge made a process
 * lose DC_ATTR slots for good, until its pool section was full of dead slots and every new DC came
 * back without a DC_ATTR (kbswitch.exe in a long soak).
 */

#include "precomp.h"

#include "../gditools/gditools.h"

#define CYCLES      50000
#define BATCH       64
#define MAX_DCS     2048
#define MAX_PRESSURE_DCS 512
#define MAX_HOG     4096
#define MAX_SLOTS   4096

typedef struct
{
    ULONG cNoAttr;
    ULONG cDCs;
    ULONG cSections;
    ULONG cDuplicates;
} BATCHRESULT;

static PVOID gapvSlots[MAX_SLOTS];
static ULONG gcSlots;
static HDC gahdc[MAX_DCS];
static PVOID gapvAttr[MAX_DCS];
static HANDLE gahHog[MAX_HOG];

static
BOOL
AddSlot(PVOID pv)
{
    ULONG i;

    for (i = 0; i < gcSlots; i++)
    {
        if (gapvSlots[i] == pv)
            return TRUE;
    }
    if (gcSlots >= MAX_SLOTS)
        return FALSE;
    gapvSlots[gcSlots++] = pv;
    return TRUE;
}

/* Create a DC, report whether it has a DC_ATTR and remember where it is */
static
HDC
CreateTrackedDC(UINT uKind, PULONG pcNoAttr, PULONG pcFail)
{
    HDC hdc = NULL;
    PVOID pvAttr;

    switch (uKind)
    {
        case 0: hdc = CreateCompatibleDC(NULL); break;
        case 1: hdc = CreateDCW(L"DISPLAY", NULL, NULL, NULL); break;
        default: hdc = GetDC(NULL); break;
    }

    if (!hdc)
    {
        (*pcFail)++;
        return NULL;
    }

    pvAttr = GdiGetHandleUserData(hdc);
    if (!pvAttr)
        (*pcNoAttr)++;
    else
        AddSlot(pvAttr);
    return hdc;
}

static
void
DeleteTrackedDC(UINT uKind, HDC hdc)
{
    if (uKind >= 2)
        ReleaseDC(NULL, hdc);
    else
        DeleteDC(hdc);
}

/* Create cCount DCs at once, check them and delete them again */
static
void
MeasureBatch(ULONG cCount, BATCHRESULT *pres)
{
    ULONG i, j, cNoAttr = 0, cFail = 0;
    PVOID apvSection[MAX_DCS];

    RtlZeroMemory(pres, sizeof(*pres));
    for (i = 0; i < cCount; i++)
    {
        gahdc[i] = CreateCompatibleDC(NULL);
        if (!gahdc[i])
        {
            cFail++;
            continue;
        }
        pres->cDCs++;
        gapvAttr[i] = GdiGetHandleUserData(gahdc[i]);
        if (!gapvAttr[i])
        {
            cNoAttr++;
            continue;
        }
        for (j = 0; j < i; j++)
        {
            if (gapvAttr[j] == gapvAttr[i])
            {
                pres->cDuplicates++;
                break;
            }
        }
        apvSection[i] = (PVOID)((ULONG_PTR)gapvAttr[i] & ~(ULONG_PTR)0xFFFF);
        for (j = 0; j < i; j++)
        {
            if (gapvAttr[j] && apvSection[j] == apvSection[i])
                break;
        }
        if (j == i)
            pres->cSections++;
    }
    pres->cNoAttr = cNoAttr;

    for (i = 0; i < cCount; i++)
    {
        if (gahdc[i])
            DeleteDC(gahdc[i]);
    }
}

static
void
Test_Cycle(void)
{
    ULONG i, j, cNoAttr = 0, cFail = 0, cCycles = 0;
    HDC ahdc[BATCH];
    HDC hdc;

    gcSlots = 0;
    for (i = 0; i < CYCLES; i++)
    {
        UINT uKind = i % 3;

        hdc = CreateTrackedDC(uKind, &cNoAttr, &cFail);
        if (hdc)
            DeleteTrackedDC(uKind, hdc);
        cCycles++;

        if ((i % 16) == 0)
        {
            /* Delete in a scrambled order so that slots are freed out of order */
            for (j = 0; j < BATCH; j++)
                ahdc[j] = CreateTrackedDC(0, &cNoAttr, &cFail);
            for (j = 0; j < BATCH; j++)
            {
                HDC hdcDel = ahdc[(j * 37 + i) % BATCH];
                if (hdcDel)
                    DeleteDC(hdcDel);
            }
        }
    }

    trace("%lu cycles, %lu distinct DC_ATTR slots used\n", cCycles, gcSlots);
    ok(cFail == 0, "%lu DCs could not be created\n", cFail);
    ok(cNoAttr == 0, "%lu DCs had no DC_ATTR\n", cNoAttr);
    /* One batch plus the DC of the cycle at a time. Slots that are never given back would make
       this grow with the number of cycles. */
    ok(gcSlots <= 4 * BATCH, "DC_ATTR slots are not reused, %lu distinct slots\n", gcSlots);
}

static
void
Test_CommitPressure(void)
{
    BATCHRESULT before, after;
    ULONG cHog = 0, cPressure = 0, cNoAttrPressure = 0, cFailPressure = 0, i;
    SIZE_T cjChunk;
    HDC *ahdc = gahdc;

    /* Fill the pool section with a known state first */
    MeasureBatch(MAX_DCS, &before);
    ok(before.cNoAttr == 0, "%lu of %u DCs had no DC_ATTR before the test\n", before.cNoAttr, MAX_DCS);
    ok(before.cDuplicates == 0, "%lu DCs share a DC_ATTR\n", before.cDuplicates);

    /* Use up the commit charge with pagefile backed sections, they need no address space and the pool
       section is already reserved. Then every page that the pool wants to commit fails, until the
       sections are closed again. Keep the time under pressure short and do nothing but create DCs. */
    for (cjChunk = (SIZE_T)1 << 27; cjChunk >= 0x1000 && cHog < MAX_HOG; cjChunk >>= 1)
    {
        HANDLE hSection;

        while (cHog < MAX_HOG &&
               (hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                                              (DWORD)cjChunk, NULL)) != NULL)
        {
            gahHog[cHog++] = hSection;
        }
    }

    for (i = 0; i < MAX_PRESSURE_DCS; i++)
    {
        ahdc[cPressure] = CreateTrackedDC(0, &cNoAttrPressure, &cFailPressure);
        if (ahdc[cPressure])
            cPressure++;
    }

    for (i = 0; i < cHog; i++)
        CloseHandle(gahHog[i]);
    for (i = 0; i < cPressure; i++)
        DeleteDC(ahdc[i]);

    trace("%lu sections, %lu DCs under pressure, %lu without DC_ATTR, %lu failed\n",
          cHog, cPressure, cNoAttrPressure, cFailPressure);
    if (cNoAttrPressure == 0)
        skip("Could not make win32k fail to commit DC_ATTR memory\n");

    /* Whatever happened under pressure, the pool must be as good as before once the pressure is gone */
    MeasureBatch(MAX_DCS, &after);
    ok(after.cNoAttr == 0, "%lu of %u DCs have no DC_ATTR after the commit failures\n",
       after.cNoAttr, MAX_DCS);
    ok(after.cDuplicates == 0, "%lu DCs share a DC_ATTR after the commit failures\n", after.cDuplicates);
    ok(after.cSections == before.cSections, "DC_ATTR sections: %lu before, %lu after\n",
       before.cSections, after.cSections);
}

START_TEST(DcAttrPool)
{
    Test_Cycle();
    Test_CommitPressure();
}
