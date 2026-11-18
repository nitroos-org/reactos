/*
 * PROJECT:     NitroOS win32k
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Saved bits of windows of a class with CS_SAVEBITS
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A top-level window of a class with CS_SAVEBITS (menus, tooltips, drop-down lists; toolkits register their
 * own popup windows with it too) saves what the screen shows under it when it is shown. When it is hidden,
 * the saved pixels go back onto the screen at once, through the part of the window that was visible. The
 * windows below are still invalidated as usual, so whatever changed under the popup is painted again; the
 * saved pixels only keep the screen right until they do. Without them the popup's pixels stay on the
 * screen for as long as the owner is slow to repaint (a toolkit that paints from a timer of its own does not
 * paint while a modal dialog of the system runs: the lower part of a closed menu stayed below the dialog that
 * its command opened).
 *
 * What is put back is only what nothing touched since the save: a record keeps the rectangles of windows that
 * were invalidated, asked for a DC (the GetDC family, BeginPaint) or were moved, shown or hidden under it, and
 * those parts are left to the normal repaint, as without saved bits. Records belong to the input desktop: none
 * is made for a window of another desktop, and all are dropped when the input desktop or the display mode
 * changes. What cannot be seen: drawing through a DC that was obtained before the popup was shown and is
 * still in use (a CS_OWNDC window, a DC held by a thread), which the popup's visible region clips away anyway.
 *
 * A saved rectangle is used only when the window is hidden at the rectangle it was shown at. A record that
 * is older than another one that overlaps it is not touched; when a record is used, the records saved after
 * it that overlap it are dropped (they hold pixels of this window). The pixels are held in a surface that
 * only win32k reaches (GreRedirCreateSurface), not in a bitmap a process could read. All of it runs under
 * the USER lock. Not used while windows are redirected (NitroRedirection), which keeps what is covered.
 */

#include <win32k.h>

/* Entries kept at once (menus nest a few levels, tooltips and lists come and go) and the largest window saved */
#define SPB_MAX_ENTRIES 16
#define SPB_MAX_PIXELS  (2 * 1024 * 1024)

#define SPB_DIRTY_RECTS 8

typedef struct _SPB
{
    LIST_ENTRY Entry;       /* gSpbList, the newest first */
    HWND hwnd;
    RECTL rcWnd;            /* the window rectangle when it was shown, screen coordinates */
    PSURFACE psurf;         /* 32 bpp, the size of rcWnd; our reference */
    ULONG cDirty;           /* rectangles (screen coordinates) touched since the save; all of rcWnd when more than there is room for */
    RECTL arcDirty[SPB_DIRTY_RECTS];
} SPB, *PSPB;

static LIST_ENTRY gSpbList = { &gSpbList, &gSpbList };
ULONG gSpbCount;

/*
 * Surfaces of records that ended are kept for the next ones (a menu is shown many times and a section is a costly
 * thing to make): a surface is used for a window it is at least as large as in both directions and at most twice
 * the area of. Only the part of the window that is on the screen is ever written and read, so what an earlier user
 * left elsewhere in the surface is never presented. Small surfaces only; the cache is emptied when the input
 * desktop or the display mode changes.
 */
#define SPB_CACHE_ENTRIES 4
#define SPB_CACHE_MAX_PIXELS (512 * 1024)
static PSURFACE gSpbCache[SPB_CACHE_ENTRIES];

static
PSURFACE
SpbGetSurface(LONG cx, LONG cy)
{
    ULONG i, iBest = SPB_CACHE_ENTRIES;
    LONGLONG areaBest = 0;

    for (i = 0; i < SPB_CACHE_ENTRIES; i++)
    {
        PSURFACE p = gSpbCache[i];
        LONGLONG a;

        if (!p || p->SurfObj.sizlBitmap.cx < cx || p->SurfObj.sizlBitmap.cy < cy)
            continue;
        a = (LONGLONG)p->SurfObj.sizlBitmap.cx * p->SurfObj.sizlBitmap.cy;
        if (a > 2 * (LONGLONG)cx * cy)
            continue;
        if (iBest == SPB_CACHE_ENTRIES || a < areaBest)
        {
            iBest = i;
            areaBest = a;
        }
    }
    if (iBest != SPB_CACHE_ENTRIES)
    {
        PSURFACE p = gSpbCache[iBest];

        gSpbCache[iBest] = NULL;
        return p;
    }
    return GreRedirCreateSurface(cx, cy, NULL);
}

static
VOID
SpbPutSurface(PSURFACE psurf)
{
    ULONG i;

    if ((ULONGLONG)psurf->SurfObj.sizlBitmap.cx * psurf->SurfObj.sizlBitmap.cy <= SPB_CACHE_MAX_PIXELS)
    {
        for (i = 0; i < SPB_CACHE_ENTRIES; i++)
        {
            if (!gSpbCache[i])
            {
                gSpbCache[i] = psurf;
                return;
            }
        }
    }
    GreRedirDeleteSurface(psurf);
}

static
VOID
SpbFree(PSPB pspb)
{
    RemoveEntryList(&pspb->Entry);
    gSpbCount--;
    SpbPutSurface(pspb->psurf);
    ExFreePoolWithTag(pspb, USERTAG_SPB);
}

static
PSPB
SpbFind(HWND hwnd)
{
    PLIST_ENTRY pe;

    for (pe = gSpbList.Flink; pe != &gSpbList; pe = pe->Flink)
    {
        PSPB pspb = CONTAINING_RECORD(pe, SPB, Entry);

        if (pspb->hwnd == hwnd)
            return pspb;
    }
    return NULL;
}

/* A window that would keep a record: a top-level window of a CS_SAVEBITS class on the desktop that is displayed */
static
BOOL
SpbEligible(PWND Wnd)
{
    return gRedirLevel == 0 && !gbHeadlessSession &&
           Wnd->pcls != NULL && (Wnd->pcls->style & CS_SAVEBITS) &&
           !(Wnd->style & WS_CHILD) && !(Wnd->ExStyle & WS_EX_LAYERED) &&
           Wnd->spwndParent != NULL && UserIsDesktopWindow(Wnd->spwndParent) &&
           Wnd->head.rpdesk == gpdeskInputDesktop;
}

/* Every record goes: the input desktop or the display mode changed */
VOID
FASTCALL
UserSpbDropAll(VOID)
{
    ULONG i;

    while (!IsListEmpty(&gSpbList))
        SpbFree(CONTAINING_RECORD(gSpbList.Flink, SPB, Entry));
    for (i = 0; i < SPB_CACHE_ENTRIES; i++)
    {
        if (gSpbCache[i])
        {
            GreRedirDeleteSurface(gSpbCache[i]);
            gSpbCache[i] = NULL;
        }
    }
}

/* prc (screen coordinates) was changed: no saved pixels there can be used */
static
VOID
SpbMark(const RECTL *prc)
{
    PLIST_ENTRY pe;

    for (pe = gSpbList.Flink; pe != &gSpbList; pe = pe->Flink)
    {
        PSPB pspb = CONTAINING_RECORD(pe, SPB, Entry);
        RECTL rc;

        if (!RECTL_bIntersectRect(&rc, prc, &pspb->rcWnd))
            continue;
        if (pspb->cDirty >= SPB_DIRTY_RECTS)
        {
            pspb->cDirty = 1;
            pspb->arcDirty[0] = pspb->rcWnd;
        }
        else
        {
            pspb->arcDirty[pspb->cDirty++] = rc;
        }
    }
}

/* prc (screen coordinates) was changed or may have been drawn on by Wnd */
VOID
FASTCALL
UserSpbNoteRect(PWND Wnd, const RECTL *prc)
{
    PWND Root = Wnd;

    if (gSpbCount == 0)
        return;

    /* A popup of such a class puts back what it covered (or, without a record, marks it itself): no change for the others */
    if (Root)
    {
        while (Root->spwndParent && !UserIsDesktopWindow(Root->spwndParent))
            Root = Root->spwndParent;
        if (SpbEligible(Root))
            return;
    }
    SpbMark(prc);
}

/* Wnd asks for a DC (all of the screen for the desktop DC) */
VOID
FASTCALL
UserSpbNoteDC(PWND Wnd)
{
    RECTL rc;

    if (Wnd)
        rc = Wnd->rcWindow;
    else
    {
        rc.left = rc.top = MINLONG / 2;
        rc.right = rc.bottom = MAXLONG / 2;
    }
    UserSpbNoteRect(Wnd, &rc);
}

/* The window is destroyed, shown again or moved: whatever was saved for it is of no use */
VOID
FASTCALL
UserSpbDrop(PWND Wnd)
{
    PSPB pspb = SpbFind(UserHMGetHandle(Wnd));

    if (pspb)
        SpbFree(pspb);
}

/* The window has just been made visible and has not drawn anything yet: save what the screen shows under it */
VOID
FASTCALL
UserSpbSave(PWND Wnd)
{
    PSPB pspb;
    PSURFACE psurf;
    PREGION prgn;
    RECTL rc;
    LONG cx, cy;

    UserSpbDrop(Wnd);

    /* Top-level windows of such a class on the displayed desktop only; layered windows and redirected windows keep what is under them */
    if (!SpbEligible(Wnd))
    {
        /* An ordinary window shown: what it covers changed on the screen */
        UserSpbNoteRect(Wnd, &Wnd->rcWindow);
        return;
    }

    rc = Wnd->rcWindow;
    cx = rc.right - rc.left;
    cy = rc.bottom - rc.top;
    if (cx <= 0 || cy <= 0 || (ULONGLONG)cx * cy > SPB_MAX_PIXELS)
        goto nokeep;

    if (gSpbCount >= SPB_MAX_ENTRIES)
        SpbFree(CONTAINING_RECORD(gSpbList.Blink, SPB, Entry));

    pspb = ExAllocatePoolWithTag(PagedPool, sizeof(*pspb), USERTAG_SPB);
    if (!pspb)
        goto nokeep;

    psurf = SpbGetSurface(cx, cy);
    if (!psurf)
    {
        ExFreePoolWithTag(pspb, USERTAG_SPB);
        goto nokeep;
    }

    /* The part of the window that is on the screen is copied; the rest of the surface is zero and is never used */
    prgn = IntSysCreateRectpRgnIndirect(&rc);
    if (!prgn || !GreRedirSeedFromScreen(psurf, prgn, rc.left, rc.top))
    {
        if (prgn)
            REGION_Delete(prgn);
        SpbPutSurface(psurf);
        ExFreePoolWithTag(pspb, USERTAG_SPB);
        goto nokeep;
    }
    REGION_Delete(prgn);

    pspb->hwnd = UserHMGetHandle(Wnd);
    pspb->rcWnd = rc;
    pspb->psurf = psurf;
    pspb->cDirty = 0;
    InsertHeadList(&gSpbList, &pspb->Entry);
    gSpbCount++;
    return;

nokeep:
    /* Nothing kept for this window: it still changes what older records hold */
    SpbMark(&rc);
}

/*
 * The window has just been hidden. prgnExposed is the part of it that was visible, relative to the window.
 * Puts the saved pixels back there. Returns TRUE when it did.
 */
BOOL
FASTCALL
UserSpbRestore(PWND Wnd, PREGION prgnExposed)
{
    PSPB pspb, pspbOther;
    PLIST_ENTRY pe, peNext;
    PREGION prgn;
    BOOL bRet = FALSE;

    pspb = SpbFind(UserHMGetHandle(Wnd));
    if (!pspb)
        return FALSE;

    /* Moved, resized or shown elsewhere since: the pixels are not those under the window any more */
    if (!RtlEqualMemory(&pspb->rcWnd, &Wnd->rcWindow, sizeof(RECTL)))
    {
        SpbFree(pspb);
        return FALSE;
    }

    /* Another desktop is displayed now (the switch drops all records; this is the window of one that is not) */
    if (Wnd->head.rpdesk != gpdeskInputDesktop)
    {
        SpbFree(pspb);
        return FALSE;
    }

    prgn = IntSysCreateRectpRgn(0, 0, 0, 0);
    if (prgn && REGION_bCopy(prgn, prgnExposed))
    {
        ULONG i;
        BOOL bAny = TRUE;

        REGION_bOffsetRgn(prgn, pspb->rcWnd.left, pspb->rcWnd.top);
        /* Not what was touched since the save: that is left to the repaint */
        for (i = 0; i < pspb->cDirty && bAny; i++)
        {
            PREGION prgnDirty = IntSysCreateRectpRgnIndirect(&pspb->arcDirty[i]);

            if (!prgnDirty)
            {
                bAny = FALSE;
                break;
            }
            bAny = IntGdiCombineRgn(prgn, prgn, prgnDirty, RGN_DIFF) > NULLREGION;
            REGION_Delete(prgnDirty);
        }
        if (bAny)
            bRet = GreRedirPresent(pspb->psurf, prgn, pspb->rcWnd.left, pspb->rcWnd.top);
    }
    if (prgn)
        REGION_Delete(prgn);

    /* Records saved later (nearer the front of the list) that overlap hold pixels of this window: drop them */
    for (pe = gSpbList.Flink; pe != &pspb->Entry; pe = peNext)
    {
        RECTL rcCommon;

        peNext = pe->Flink;
        pspbOther = CONTAINING_RECORD(pe, SPB, Entry);
        if (RECTL_bIntersectRect(&rcCommon, &pspbOther->rcWnd, &pspb->rcWnd))
            SpbFree(pspbOther);
    }

    SpbFree(pspb);
    return bRet;
}
