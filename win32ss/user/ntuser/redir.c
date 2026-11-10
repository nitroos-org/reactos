/*
 * PROJECT:     NitroOS win32k
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Redirected window surfaces, stage R0 (fes/2026-11-09-win32k-redirected-window-surfaces.md)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\NitroRedirection (DWORD, amd64 only):
 * 0 (default) = windows draw on the screen as always; 1 = every eligible top-level window draws into a
 * surface of its own (its DCs and its children's DCs select it, in window coordinates), and what it drew
 * there is copied onto the screen through the window's visible region when a DC is released or ends a
 * paint, within a frame for DCs that stay in use, and all of it when the window moved. Covered content
 * is kept: GetDC/GetWindowDC of a covered window reads it. Level 2 (translucency) is not implemented
 * yet and behaves as 1. The boot option /NOREDIRECTION forces 0.
 *
 * Not redirected: the desktop window, message-only windows, layered windows, glass windows
 * (NitroSetWindowGlass), hidden windows, windows past the memory budget. They draw as always.
 * R0 keeps USER's painting rules (WM_PAINT on uncover); R1 changes them.
 *
 * Lifetime: a record lives while its window has it or a DCE is bound to it (cRefs, USER lock). A DC
 * whose binding could not be changed (another process draws with it) keeps its binding and the
 * reference, and is bound again later (windc.c, DCE_REDIR_RETRY): a record is never freed while a DC
 * can still mark it dirty. The surface has no owner a process could match: only win32k reaches it,
 * by the pointer held here.
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(UserPainting);

#define REDIR_MAGIC 0x52444952 /* "RIDR" */

typedef struct _REDIR
{
    ULONG Magic;
    LIST_ENTRY Link;
    LONG cRefs;             /* the window's while attached, plus one per bound DCE (USER lock) */
    PWND pwnd;              /* the top-level window; NULL once detached */
    PSURFACE psurf;         /* 32 bpp surface the size of the window rectangle; our reference */
    LONG cx, cy;
    SIZE_T cjBits;
    KSPIN_LOCK DirtyLock;
    RECTL rcDirty;          /* what DCs drew since the last present (surface coordinates), DirtyLock */
    volatile LONG Dirty;    /* rcDirty is not empty (counted in gRedirDirtyCount) */
} REDIR, *PREDIR;

ULONG gRedirLevel = 0;
PKTIMER gRedirTimer = NULL;
static LIST_ENTRY gRedirList = { &gRedirList, &gRedirList };
static SIZE_T gRedirBytes, gRedirBudget;
static ATOM AtomRedir;
static volatile LONG gRedirTimerArmed;
static volatile LONG gRedirDirtyCount;   /* records with Dirty set: the timer takes the USER lock only then */
static ULONG gRedirCreated, gRedirRefused, gRedirPresents;
static volatile LONG gRedirRetries;     /* DCEs with DCE_REDIR_RETRY (windc.c) */

/* A DC that could not be unbound when its DCE was freed: its reference to the record waits here */
typedef struct _REDIR_ORPHAN
{
    LIST_ENTRY Link;
    HDC hdc;
    struct _REDIR *r;
} REDIR_ORPHAN, *PREDIR_ORPHAN;
static LIST_ENTRY gRedirOrphans = { &gRedirOrphans, &gRedirOrphans };

#define REDIR_MAX_SIDE      16384
#define REDIR_FRAME_100NS   (16 * 10000)
#define REDIR_RETRY_100NS   (100 * 10000)

static VOID
RedirArmTimer(LONGLONG Due100ns)
{
    if (gRedirTimer && InterlockedExchange(&gRedirTimerArmed, 1) == 0)
    {
        LARGE_INTEGER Due;

        Due.QuadPart = -Due100ns;
        KeSetTimer(gRedirTimer, Due, NULL);
    }
}

#ifdef _M_AMD64
/* Whether the loader options (rewritten by the kernel at every boot) carry the token NOREDIRECTION */
static BOOL
RedirBootOptionOff(VOID)
{
    HKEY hKey;
    WCHAR Buffer[512];
    ULONG cb = sizeof(Buffer) - sizeof(WCHAR);
    PWSTR p;
    BOOL bOff = FALSE;

    if (!NT_SUCCESS(RegOpenKey(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control", &hKey)))
        return FALSE;
    RtlZeroMemory(Buffer, sizeof(Buffer));
    if (NT_SUCCESS(RegQueryValue(hKey, L"SystemStartOptions", REG_SZ, Buffer, &cb)))
    {
        for (p = Buffer; *p; )
        {
            PWSTR Token;
            SIZE_T Len;

            while (*p == L' ' || *p == L'\t' || *p == L'/')
                p++;
            Token = p;
            while (*p && *p != L' ' && *p != L'\t' && *p != L'/')
                p++;
            Len = p - Token;
            if (Len == 13 && _wcsnicmp(Token, L"NOREDIRECTION", 13) == 0)
            {
                bOff = TRUE;
                break;
            }
        }
    }
    ZwClose(hKey);
    return bOff;
}
#endif

VOID
NTAPI
UserRedirInit(VOID)
{
#ifdef _M_AMD64
    HKEY hKey;
    DWORD Value = 0;
    SYSTEM_BASIC_INFORMATION Sbi;

    if (NT_SUCCESS(RegOpenKey(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers", &hKey)))
    {
        if (RegReadDWORD(hKey, L"NitroRedirection", &Value))
            gRedirLevel = Value;
        ZwClose(hKey);
    }
    if (gRedirLevel > 2)
    {
        DbgPrint("win32k: NitroRedirection %lu is not a level (0, 1, 2): window redirection off\n", gRedirLevel);
        gRedirLevel = 0;
    }
    if (gRedirLevel && RedirBootOptionOff())
    {
        DbgPrint("win32k: window redirection off (/NOREDIRECTION)\n");
        gRedirLevel = 0;
    }
    if (!gRedirLevel)
        return;

    /* A quarter of RAM, at most 256 MB, of surfaces per session */
    gRedirBudget = 256 * 1024 * 1024;
    if (NT_SUCCESS(ZwQuerySystemInformation(SystemBasicInformation, &Sbi, sizeof(Sbi), NULL)))
    {
        SIZE_T Quarter = ((SIZE_T)Sbi.NumberOfPhysicalPages * Sbi.PageSize) / 4;
        if (Quarter < gRedirBudget)
            gRedirBudget = Quarter;
    }

    gRedirTimer = ExAllocatePoolWithTag(NonPagedPool, sizeof(KTIMER), USERTAG_REDIRSURF);
    AtomRedir = IntAddGlobalAtom(L"NitroRedir", TRUE);
    if (!gRedirTimer || !AtomRedir)
    {
        ERR("Redirection: no timer or atom, staying off\n");
        gRedirLevel = 0;
        return;
    }
    /* A synchronization timer: the wait of the raw input thread resets it (a notification timer stays signaled) */
    KeInitializeTimerEx(gRedirTimer, SynchronizationTimer);
    DbgPrint("win32k: window redirection level %lu (NitroRedirection%s), surface budget %Iu MB\n",
             gRedirLevel, gRedirLevel == 2 ? ", level 2 not implemented: composed as 1" : "", gRedirBudget >> 20);
#endif
}

/* The top-level window whose surface a DC of Wnd draws into, or NULL (not redirected) */
PWND
FASTCALL
UserRedirRootFor(PWND Wnd)
{
    PWND Root = Wnd;

    if (!gRedirLevel || !Wnd)
        return NULL;
    while (Root->spwndParent && !UserIsDesktopWindow(Root->spwndParent))
        Root = Root->spwndParent;
    if (!Root->spwndParent || UserIsDesktopWindow(Root) || UserIsMessageWindow(Root))
        return NULL;
    if (!(Root->style & WS_VISIBLE) || (Root->state & WNDS_DESTROYED) || (Root->state2 & WNDS2_INDESTROY))
        return NULL;
    if (Root->ExStyle & WS_EX_LAYERED)
        return NULL;
    if (UserGetProp(Root, gpsi->atomFrostedWindowProp, TRUE) != NULL)
        return NULL;
    return Root;
}

/* Takes what was drawn since the last present (FALSE: nothing) */
static BOOL
RedirTakeDirty(PREDIR r, PRECTL prc)
{
    KIRQL OldIrql;

    /* The flag first: a draw that comes after it counts again and is presented again */
    if (InterlockedExchange(&r->Dirty, 0))
        InterlockedDecrement(&gRedirDirtyCount);
    KeAcquireSpinLock(&r->DirtyLock, &OldIrql);
    *prc = r->rcDirty;
    RECTL_vSetEmptyRect(&r->rcDirty);
    KeReleaseSpinLock(&r->DirtyLock, OldIrql);
    return !RECTL_bIsEmptyRect(prc);
}

static VOID
RedirRelease(PREDIR r)
{
    RECTL rc;

    ASSERT(r->cRefs > 0);
    if (--r->cRefs > 0)
        return;
    ASSERT(r->pwnd == NULL);
    RedirTakeDirty(r, &rc);
    RemoveEntryList(&r->Link);
    gRedirBytes -= r->cjBits;
    if (r->psurf)
        GreRedirDeleteSurface(r->psurf);
    r->Magic = 0;
    ExFreePoolWithTag(r, USERTAG_REDIRSURF);
}

VOID FASTCALL UserRedirAddRef(PVOID pv) { ((PREDIR)pv)->cRefs++; }
VOID FASTCALL UserRedirRelease(PVOID pv) { RedirRelease((PREDIR)pv); }
PSURFACE FASTCALL UserRedirSurface(PVOID pv) { return ((PREDIR)pv)->psurf; }
PWND FASTCALL UserRedirWindow(PVOID pv) { return ((PREDIR)pv)->pwnd; }

/* The window no longer has a surface (hidden, destroyed, no longer eligible): its DCs draw on the screen again */
VOID
FASTCALL
UserRedirDetachWindow(PWND Wnd)
{
    PREDIR r;

    if (!gRedirLevel || !Wnd)
        return;
    r = UserGetProp(Wnd, AtomRedir, TRUE);
    if (!r)
        return;
    UserRemoveProp(Wnd, AtomRedir, TRUE);
    /* A DC that cannot be unbound now keeps the record (and the surface) until it is bound again */
    DceRedirUnbindAll(r);
    r->pwnd = NULL;
    RedirRelease(r);
}

/* The window is redirected and has a surface of its window size (no new surface is made) */
BOOL
FASTCALL
UserRedirHasSurface(PWND Wnd)
{
    PREDIR r;

    if (!gRedirLevel || !Wnd)
        return FALSE;
    r = UserGetProp(Wnd, AtomRedir, TRUE);
    if (!r || !r->psurf ||
        r->cx != Wnd->rcWindow.right - Wnd->rcWindow.left ||
        r->cy != Wnd->rcWindow.bottom - Wnd->rcWindow.top)
    {
        return FALSE;
    }
    return UserRedirRootFor(Wnd) == Wnd;
}

/*
 * A new surface for a window that is already on the screen and is not about to paint all of itself
 * (it became eligible again, or its first DC is not its first paint): what the screen shows of it is
 * copied in, and the rest of the window is invalidated, so no part of the surface is shown before the
 * window drew it.
 */
static VOID
RedirSeed(PREDIR r, PWND Root)
{
    PREGION Vis = NULL, Rest;
    BOOL bWhole = FALSE;

    if (Root->hrgnUpdate == HRGN_WINDOW)
    {
        bWhole = TRUE;
    }
    else if (Root->hrgnUpdate)
    {
        PREGION RgnUpdate = REGION_LockRgn(Root->hrgnUpdate);
        RECTL rcBox;

        if (RgnUpdate)
        {
            if (REGION_GetRgnBox(RgnUpdate, &rcBox) == SIMPLEREGION &&
                rcBox.left <= Root->rcWindow.left && rcBox.top <= Root->rcWindow.top &&
                rcBox.right >= Root->rcWindow.right && rcBox.bottom >= Root->rcWindow.bottom)
            {
                bWhole = TRUE;
            }
            REGION_UnlockRgn(RgnUpdate);
        }
    }
    if (bWhole)
        return;

    if (Root->head.rpdesk == gpdeskInputDesktop)
    {
        Vis = VIS_ComputeVisibleRegion(Root, FALSE, FALSE, TRUE);
        if (Vis)
            GreRedirSeedFromScreen(r->psurf, Vis, Root->rcWindow.left, Root->rcWindow.top);
    }
    Rest = IntSysCreateRectpRgnIndirect(&Root->rcWindow);
    if (Rest)
    {
        if (Vis)
            IntGdiCombineRgn(Rest, Rest, Vis, RGN_DIFF);
        if (REGION_Complexity(Rest) > NULLREGION)
            IntInvalidateWindows(Root, Rest, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
        REGION_Delete(Rest);
    }
    if (Vis)
        REGION_Delete(Vis);
}

/*
 * The record of the redirected top-level window Root, created or resized to the window rectangle.
 * NULL when it cannot have one (size, budget, no memory); it then draws on the screen.
 */
PVOID
FASTCALL
UserRedirGet(PWND Root)
{
    PREDIR r = UserGetProp(Root, AtomRedir, TRUE);
    LONG cx = Root->rcWindow.right - Root->rcWindow.left;
    LONG cy = Root->rcWindow.bottom - Root->rcWindow.top;
    SIZE_T cjNew;
    PSURFACE psurf;

    if (r && r->cx == cx && r->cy == cy)
        return r;

    cjNew = (SIZE_T)max(cx, 0) * max(cy, 0) * 4;
    if (cx <= 0 || cy <= 0 || cx > REDIR_MAX_SIDE || cy > REDIR_MAX_SIDE ||
        gRedirBytes - (r ? r->cjBits : 0) + cjNew > gRedirBudget)
    {
        TRACE("Redirection: %p (%ld x %ld) not redirected, %Iu of %Iu bytes in use\n", Root, cx, cy, gRedirBytes, gRedirBudget);
        gRedirRefused++;
        if (r)
            UserRedirDetachWindow(Root);
        return NULL;
    }

    psurf = GreRedirCreateSurface(cx, cy, r ? r->psurf : NULL);
    if (!psurf)
    {
        gRedirRefused++;
        if (r)
            UserRedirDetachWindow(Root);
        return NULL;
    }

    if (r)
    {
        PSURFACE psurfOld = r->psurf;

        gRedirBytes += cjNew - r->cjBits;
        r->psurf = psurf;
        r->cx = cx;
        r->cy = cy;
        r->cjBits = cjNew;
        /* Every DC on the old surface moves to the new one; one that cannot yet keeps its own reference to the old one */
        DceRedirRebindAll(r, psurf);
        GreRedirDeleteSurface(psurfOld);
        return r;
    }

    r = ExAllocatePoolWithTag(NonPagedPool, sizeof(REDIR), USERTAG_REDIRSURF);
    if (!r)
    {
        GreRedirDeleteSurface(psurf);
        gRedirRefused++;
        return NULL;
    }
    RtlZeroMemory(r, sizeof(REDIR));
    r->Magic = REDIR_MAGIC;
    r->cRefs = 1;
    r->pwnd = Root;
    r->psurf = psurf;
    r->cx = cx;
    r->cy = cy;
    r->cjBits = cjNew;
    KeInitializeSpinLock(&r->DirtyLock);
    RECTL_vSetEmptyRect(&r->rcDirty);
    if (!UserSetProp(Root, AtomRedir, r, TRUE))
    {
        GreRedirDeleteSurface(psurf);
        r->Magic = 0;
        ExFreePoolWithTag(r, USERTAG_REDIRSURF);
        gRedirRefused++;
        return NULL;
    }
    InsertTailList(&gRedirList, &r->Link);
    gRedirBytes += cjNew;
    gRedirCreated++;
    RedirSeed(r, Root);
    return r;
}

/* Copies prcSurf (surface coordinates; NULL: all) of the window's surface onto the screen through its visible region */
static VOID
RedirPresentRect(PREDIR r, const RECTL *prcSurf)
{
    PWND Root = r->pwnd;
    PREGION Rgn, Clip;
    RECTL rc;

    if (!Root || Root->head.rpdesk != gpdeskInputDesktop)
        return;
    if (UserRedirRootFor(Root) != Root)
    {
        /* Hidden, layered or glass now: it draws on the screen again */
        UserRedirDetachWindow(Root);
        return;
    }
    Rgn = VIS_ComputeVisibleRegion(Root, FALSE, FALSE, TRUE);
    if (!Rgn)
        return;
    if (prcSurf)
    {
        rc = *prcSurf;
        RECTL_vOffsetRect(&rc, Root->rcWindow.left, Root->rcWindow.top);
        Clip = IntSysCreateRectpRgnIndirect(&rc);
        if (Clip)
        {
            IntGdiCombineRgn(Rgn, Rgn, Clip, RGN_AND);
            REGION_Delete(Clip);
        }
    }
    GreRedirPresent(r->psurf, Rgn, Root->rcWindow.left, Root->rcWindow.top);
    REGION_Delete(Rgn);
    gRedirPresents++;
}

/* What was drawn goes to the screen (bWholeIfClean: an EndPaint that drew through no tracked primitive presents all) */
static VOID
RedirPresentDirty(PREDIR r, BOOL bWholeIfClean)
{
    RECTL rc;

    if (RedirTakeDirty(r, &rc))
        RedirPresentRect(r, &rc);
    else if (bWholeIfClean)
        RedirPresentRect(r, NULL);
}

/* A DC bound to the record is released (EndPaint: the window painted) */
VOID
FASTCALL
UserRedirReleased(PVOID pv, BOOL bEndPaint)
{
    PREDIR r = pv;

    if (r->pwnd)
        RedirPresentDirty(r, bEndPaint);
}

/* The window moved: all of its content goes to its new place */
VOID
FASTCALL
UserRedirWindowMoved(PWND Wnd)
{
    PREDIR r;
    RECTL rc;

    if (!gRedirLevel || !Wnd)
        return;
    r = UserGetProp(Wnd, AtomRedir, TRUE);
    if (r)
    {
        RedirTakeDirty(r, &rc);
        RedirPresentRect(r, NULL);
    }
}

/*
 * GDI: a DC bound to the record draws, or finished drawing, into prcl (device = surface coordinates).
 * Any thread, the DC is locked, no USER lock. Marked at the start and at the end of a primitive, so a
 * present that runs in between never loses the end of it. Presented within a frame if nothing else does.
 */
VOID
FASTCALL
UserRedirMarkDirty(PVOID pv, const RECTL *prcl)
{
    PREDIR r = pv;
    RECTL rc;
    KIRQL OldIrql;

    if (!r || r->Magic != REDIR_MAGIC)
    {
        ASSERT(FALSE);
        return;
    }
    if (prcl)
    {
        rc = *prcl;
        RECTL_vMakeWellOrdered(&rc);
        rc.left = max(rc.left, 0);
        rc.top = max(rc.top, 0);
        rc.right = min(rc.right, r->cx);
        rc.bottom = min(rc.bottom, r->cy);
        if (rc.left >= rc.right || rc.top >= rc.bottom)
            return;
    }
    else
    {
        RECTL_vSetRect(&rc, 0, 0, r->cx, r->cy);
    }

    KeAcquireSpinLock(&r->DirtyLock, &OldIrql);
    if (RECTL_bIsEmptyRect(&r->rcDirty))
        r->rcDirty = rc;
    else
        RECTL_bUnionRect(&r->rcDirty, &r->rcDirty, &rc);
    KeReleaseSpinLock(&r->DirtyLock, OldIrql);

    if (InterlockedExchange(&r->Dirty, 1) != 0)
        return;
    InterlockedIncrement(&gRedirDirtyCount);
    RedirArmTimer(REDIR_FRAME_100NS);
}

/* windc.c: a DCE starts or stops waiting for a binding (USER lock) */
VOID
FASTCALL
UserRedirRetryCount(LONG Delta)
{
    InterlockedExchangeAdd(&gRedirRetries, Delta);
    if (Delta > 0)
        RedirArmTimer(REDIR_RETRY_100NS);
}

/* windc.c: a DCE is freed while its DC still holds the record (busy or being deleted); USER lock */
VOID
FASTCALL
UserRedirOrphan(HDC hdc, PVOID pvRedir)
{
    PREDIR_ORPHAN o = ExAllocatePoolWithTag(NonPagedPool, sizeof(*o), USERTAG_REDIRSURF);

    if (!o)
    {
        /* Without memory to wait: keep the reference for good, never free under a DC */
        ERR("Redirection: DC %p keeps record %p for good\n", hdc, pvRedir);
        return;
    }
    o->hdc = hdc;
    o->r = pvRedir;
    InsertTailList(&gRedirOrphans, &o->Link);
    RedirArmTimer(REDIR_RETRY_100NS);
}

/* Orphans whose DC is gone or now unbound release their record */
static VOID
RedirReapOrphans(VOID)
{
    PLIST_ENTRY Entry;
    PVOID pvOld;

    for (Entry = gRedirOrphans.Flink; Entry != &gRedirOrphans; )
    {
        PREDIR_ORPHAN o = CONTAINING_RECORD(Entry, REDIR_ORPHAN, Link);

        Entry = Entry->Flink;
        if (GreRedirBindDC(o->hdc, NULL, NULL, &pvOld) == REDIRBIND_BUSY)
            continue;
        RemoveEntryList(&o->Link);
        RedirRelease(o->r);
        ExFreePoolWithTag(o, USERTAG_REDIRSURF);
    }
}

/* The raw input thread, when gRedirTimer fired: present what DCs still in use drew */
VOID
FASTCALL
UserRedirPresentPending(VOID)
{
    PLIST_ENTRY Entry;

    InterlockedExchange(&gRedirTimerArmed, 0);
    /* Released DCs present at once: usually nothing is left, and the USER lock is not taken for nothing */
    if (gRedirDirtyCount == 0 && gRedirRetries == 0 && IsListEmpty(&gRedirOrphans))
        return;
    UserEnterExclusive();
    for (Entry = gRedirList.Flink; Entry != &gRedirList; )
    {
        PREDIR r = CONTAINING_RECORD(Entry, REDIR, Link);

        Entry = Entry->Flink;
        if (r->Dirty && r->pwnd)
        {
            /* RedirPresentDirty may detach r; the next entry was taken first, and r stays alive while a DC holds it */
            r->cRefs++;
            RedirPresentDirty(r, FALSE);
            RedirRelease(r);
        }
        else if (r->Dirty)
        {
            /* Detached, still held by a DC not unbound yet: nothing to show */
            RECTL rc;
            RedirTakeDirty(r, &rc);
        }
    }
    /* Bindings that could not be changed, and DCs of freed DCEs, are tried again */
    if (gRedirRetries)
        DceRedirRetryAll();
    if (!IsListEmpty(&gRedirOrphans))
        RedirReapOrphans();
    if (gRedirRetries || !IsListEmpty(&gRedirOrphans))
        RedirArmTimer(REDIR_RETRY_100NS);
    UserLeave();
}

/*
 * Part of the screen of the desktop window DesktopWnd was uncovered (RgnScreen, screen coordinates).
 * Every redirected top-level window shows its part from its surface, without WM_PAINT, as on Windows
 * with DWM; what it still has to paint (its update region) is left out. Those parts leave RgnScreen:
 * what is left is painted as always (the desktop, windows that are not redirected).
 */
VOID
FASTCALL
UserRedirExpose(PWND DesktopWnd, PREGION RgnScreen)
{
    PWND Child;

    if (!gRedirLevel || !DesktopWnd || !RgnScreen || DesktopWnd->head.rpdesk != gpdeskInputDesktop)
        return;

    for (Child = DesktopWnd->spwndChild; Child; Child = Child->spwndNext)
    {
        PREDIR r;
        PREGION Vis, Part;
        RECTL rcBox;

        if (REGION_GetRgnBox(RgnScreen, &rcBox) == NULLREGION)
            break;
        if (!(Child->style & WS_VISIBLE) || !RECTL_bIntersectRect(&rcBox, &rcBox, &Child->rcWindow))
            continue;
        if (!UserRedirHasSurface(Child) || Child->hrgnUpdate == HRGN_WINDOW)
            continue;
        r = UserGetProp(Child, AtomRedir, TRUE);

        Vis = VIS_ComputeVisibleRegion(Child, FALSE, FALSE, TRUE);
        if (!Vis)
            continue;
        Part = IntSysCreateRectpRgn(0, 0, 0, 0);
        if (Part && IntGdiCombineRgn(Part, Vis, RgnScreen, RGN_AND) > NULLREGION)
        {
            if (Child->hrgnUpdate)
            {
                PREGION RgnUpdate = REGION_LockRgn(Child->hrgnUpdate);
                if (RgnUpdate)
                {
                    IntGdiCombineRgn(Part, Part, RgnUpdate, RGN_DIFF);
                    REGION_UnlockRgn(RgnUpdate);
                }
            }
            if (REGION_Complexity(Part) > NULLREGION)
            {
                GreRedirPresent(r->psurf, Part, Child->rcWindow.left, Child->rcWindow.top);
                IntGdiCombineRgn(RgnScreen, RgnScreen, Part, RGN_DIFF);
                gRedirPresents++;
            }
        }
        if (Part)
            REGION_Delete(Part);
        REGION_Delete(Vis);
    }
}

/* PrintWindow: copies cx x cy of the window's surface at xSrc, ySrc (window coordinates) to hdc at 0, 0 */
BOOL
FASTCALL
UserRedirCopyToDC(PWND Wnd, HDC hdc, LONG xSrc, LONG ySrc, LONG cx, LONG cy)
{
    PREDIR r = UserGetProp(Wnd, AtomRedir, TRUE);

    if (!r || !r->psurf)
        return FALSE;
    return GreRedirCopyToDC(r->psurf, hdc, xSrc, ySrc, cx, cy);
}
