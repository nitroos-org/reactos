/*
 * PROJECT:     NitroOS win32k
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Redirected window surfaces, stages R0-R2 (fes/2026-11-09-win32k-redirected-window-surfaces.md)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\NitroRedirection (DWORD, amd64 only):
 * 0 (default) = windows draw on the screen as always; 1 = every eligible top-level window draws into a
 * surface of its own (its DCs and its children's DCs select it, in window coordinates), and what it drew
 * there is copied onto the screen through the window's visible region when a DC is released or ends a
 * paint, within a frame for DCs that stay in use, and all of it when the window moved. Covered content
 * is kept: GetDC/GetWindowDC of a covered window reads it. The boot option /NOREDIRECTION forces 0.
 *
 * Not redirected: the desktop window, message-only windows, hidden windows, windows past the memory
 * budget, and at level 1 layered windows and glass windows (NitroSetWindowGlass). They draw as always.
 * R0 keeps USER's painting rules (WM_PAINT on uncover); R1 changes them.
 *
 * Level 2 also redirects layered and glass windows ("translucent" records, bTrans) and composes them:
 * what the screen shows where one of them is is built bottom up in a frame buffer from the surfaces of
 * the windows there (copied, or blended for the translucent ones) and copied to the screen in one blit
 * (RedirCompose). SetLayeredWindowAttributes alpha and colour key apply to what the window paints;
 * UpdateLayeredWindow replaces the surface content (premultiplied alpha), and GDI drawing into such a
 * window then shows nothing; a glass window is blended with its pixels' alpha. A layered window that has
 * had neither call is not shown and gets no WM_PAINT (Windows 10, oracle W3). The screen snapshots of
 * glassblt.c and the UpdateLayeredWindow blend on the screen are then not used for redirected windows.
 * Windows below a translucent one that have no surface (not painted yet, past the budget) are read from
 * the screen there.
 *
 * Lifetime: a record lives while its window has it, a DCE is bound to it, or a DC object is bound to
 * it (cRefs). A DC holds a reference of its own from its binding until it is bound elsewhere or freed,
 * so a record is never freed while a DC can still mark it dirty, also after the DC's handle is gone (a
 * thread that still holds the DC frees it at its last unlock). A DC whose binding could not be changed
 * (another process draws with it) keeps its binding and is bound again later (windc.c,
 * DCE_REDIR_RETRY). The count changes atomically; a record is freed under the USER lock (when a DC
 * freed without it drops the last reference, the frame timer frees the record). The surface has no owner a process could match: only win32k reaches it,
 * by the pointer held here.
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(UserPainting);

#define REDIR_MAGIC 0x52444952 /* "RIDR" */

typedef struct _REDIR
{
    ULONG Magic;
    LIST_ENTRY Link;
    volatile LONG cRefs;    /* the window's while attached, one per bound DCE, one per bound DC object */
    LIST_ENTRY DeferLink;   /* in gRedirDeferred: the last reference went without the USER lock */
    PWND pwnd;              /* the top-level window; NULL once detached */
    PSURFACE psurf;         /* 32 bpp surface the size of the window rectangle; our reference */
    LONG cx, cy;
    SIZE_T cjBits;
    KSPIN_LOCK DirtyLock;
    RECTL rcDirty;          /* what DCs drew since the last present (surface coordinates), DirtyLock */
    volatile LONG Dirty;    /* rcDirty is not empty (counted in gRedirDirtyCount) */
    /* Level 2 */
    BOOLEAN bTrans;         /* layered or glass when the record was made: composed (blended), never copied as it is */
    BOOLEAN bUlw;           /* the content is UpdateLayeredWindow's; GDI drawing into the window shows nothing */
    BOOLEAN bUlwAlpha;      /* that content has per-pixel alpha (a 32 bpp source) */
    DWORD UlwFlags;         /* ULW_ALPHA, ULW_COLORKEY, ULW_OPAQUE */
    BLENDFUNCTION UlwBlend;
    COLORREF UlwKey;
} REDIR, *PREDIR;

ULONG gRedirLevel = 0;
PKTIMER gRedirTimer = NULL;
static LIST_ENTRY gRedirList = { &gRedirList, &gRedirList };
static SIZE_T gRedirBytes, gRedirBudget;
static ATOM AtomRedir;
static ATOM AtomUlwSeen;     /* level 2: the window has had UpdateLayeredWindow content (with or without a surface) */
static volatile LONG gRedirTimerArmed;
static volatile LONG gRedirDirtyCount;   /* records with Dirty set: the timer takes the USER lock only then */
static ULONG gRedirCreated, gRedirRefused, gRedirPresents;
static volatile LONG gRedirRetries;     /* DCEs with DCE_REDIR_RETRY (windc.c) */
static ULONG gRedirComposes, gRedirDebug;
static PSURFACE gRedirFB;               /* frame buffer of the compose passes (USER lock) */

/* Records whose last reference a DC dropped without the USER lock: the frame timer frees them */
static LIST_ENTRY gRedirDeferred = { &gRedirDeferred, &gRedirDeferred };
static KSPIN_LOCK gRedirDeferLock;

#define REDIR_MAX_SIDE      16384
#define REDIR_FRAME_100NS   (16 * 10000)
#define REDIR_RETRY_100NS   (100 * 10000)
#define REDIR_RETRY_BUDGET  8               /* busy DCs tried per frame-timer pass */

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
        /* 1: a debug line per compose pass (level 2) */
        if (RegReadDWORD(hKey, L"NitroRedirectionDebug", &Value))
            gRedirDebug = Value;
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
    /* Only level 2 uses this atom: without it level 2 is not offered, the level below it is unaffected */
    if (gRedirLevel >= 2)
    {
        AtomUlwSeen = IntAddGlobalAtom(L"NitroUlwSeen", TRUE);
        if (!AtomUlwSeen)
        {
            ERR("Redirection: no atom for level 2, staying at level 1\n");
            gRedirLevel = 1;
        }
    }
    /* A synchronization timer: the wait of the raw input thread resets it (a notification timer stays signaled) */
    KeInitializeTimerEx(gRedirTimer, SynchronizationTimer);
    DbgPrint("win32k: window redirection level %lu (NitroRedirection), surface budget %Iu MB\n",
             gRedirLevel, gRedirBudget >> 20);
#endif
}

static BOOL
RedirIsGlass(PWND Wnd)
{
    return UserGetProp(Wnd, gpsi->atomFrostedWindowProp, TRUE) != NULL;
}

/* Level 2: a layered or glass window, composed by blending */
static BOOL
RedirIsTransWnd(PWND Wnd)
{
    return gRedirLevel >= 2 && ((Wnd->ExStyle & WS_EX_LAYERED) || RedirIsGlass(Wnd));
}

/* Level 2: a top-level window whose content UpdateLayeredWindow gave (kept while it is hidden) */
static BOOL
RedirIsUlwWnd(PWND Wnd)
{
    PREDIR r;

    if (gRedirLevel < 2 || !(Wnd->ExStyle & WS_EX_LAYERED))
        return FALSE;
    r = UserGetProp(Wnd, AtomRedir, TRUE);
    return r && r->bUlw;
}

/*
 * Level 2: a layered window that has had neither SetLayeredWindowAttributes nor UpdateLayeredWindow. Windows
 * shows nothing of it (what is below shows through) and sends it no WM_PAINT (oracle W3).
 */
static BOOL
RedirIsLayeredUnset(PWND Wnd)
{
    return gRedirLevel >= 2 && (Wnd->ExStyle & WS_EX_LAYERED) && !GetLayeredStatus(Wnd) && !RedirIsUlwWnd(Wnd) &&
           !UserGetProp(Wnd, AtomUlwSeen, TRUE);
}

/* layered.c: UpdateLayeredWindow gave the window content (a window past the budget draws it on the screen: it is shown) */
VOID
FASTCALL
UserRedirUlwSeen(PWND Wnd)
{
    if (gRedirLevel >= 2 && Wnd && !UserGetProp(Wnd, AtomUlwSeen, TRUE))
        UserSetProp(Wnd, AtomUlwSeen, (HANDLE)1, TRUE);
}

/*
 * Whether a window with record r (or none) can have a surface of cx x cy: its size is in range and, unless r already
 * has that size, the surfaces of the session plus this one stay within the budget. UserRedirGet and
 * UserRedirLayeredFits both ask this, so they never disagree.
 */
static BOOL
RedirSizeAllowed(PREDIR r, LONG cx, LONG cy)
{
    if (r && r->cx == cx && r->cy == cy)
        return TRUE;
    if (cx <= 0 || cy <= 0 || cx > REDIR_MAX_SIDE || cy > REDIR_MAX_SIDE)
        return FALSE;
    return gRedirBytes - (r ? r->cjBits : 0) + (SIZE_T)cx * cy * 4 <= gRedirBudget;
}

/* window.c, level 2: WS_EX_LAYERED was cleared: its UpdateLayeredWindow history ends (a later WS_EX_LAYERED starts as "not set") */
VOID
FASTCALL
UserRedirUlwForget(PWND Wnd)
{
    if (gRedirLevel >= 2 && Wnd)
        UserRemoveProp(Wnd, AtomUlwSeen, TRUE);
}

/* layered.c, level 2: whether a top-level window of cx x cy can have a surface (else UpdateLayeredWindow keeps the snapshot path) */
BOOL
FASTCALL
UserRedirLayeredFits(PWND Wnd, LONG cx, LONG cy)
{
    if (gRedirLevel < 2 || !Wnd || !Wnd->spwndParent || !UserIsDesktopWindow(Wnd->spwndParent) || UserIsMessageWindow(Wnd))
        return FALSE;
    return RedirSizeAllowed(UserGetProp(Wnd, AtomRedir, TRUE), cx, cy);
}

/* layered.c, level 2: Wnd has a record with a surface of exactly cx x cy (UserRedirGet allocates nothing for it) */
BOOL
FASTCALL
UserRedirLayeredHasSize(PWND Wnd, LONG cx, LONG cy)
{
    PREDIR r;

    if (gRedirLevel < 2 || !Wnd)
        return FALSE;
    r = UserGetProp(Wnd, AtomRedir, TRUE);
    return r && r->psurf && r->cx == cx && r->cy == cy;
}

/*
 * layered.c, level 2: UpdateLayeredWindow takes the snapshot path for Wnd (no surface of the new size is possible). A
 * record it has holds an older picture of the window: drop it, or compose would draw that over the blend on the screen.
 */
VOID
FASTCALL
UserRedirLayeredNoSurface(PWND Wnd)
{
    if (gRedirLevel >= 2)
        UserRedirDetachWindow(Wnd);
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
    if ((Root->state & WNDS_DESTROYED) || (Root->state2 & WNDS2_INDESTROY))
        return NULL;
    /* Level 2: a hidden UpdateLayeredWindow window keeps its content (it has no other) */
    if (!(Root->style & WS_VISIBLE) && !RedirIsUlwWnd(Root))
        return NULL;
    if (gRedirLevel < 2)
    {
        if (Root->ExStyle & WS_EX_LAYERED)
            return NULL;
        if (RedirIsGlass(Root))
            return NULL;
    }
    return Root;
}

/* Level 2: GDI drawing through a DC bound to the record shows nothing (windc.c gives it an empty visible region) */
BOOL
FASTCALL
UserRedirIsUlw(PVOID pv)
{
    return pv && ((PREDIR)pv)->bUlw;
}

/* Level 2: no WM_PAINT for what of the window becomes visible (a layered window not set yet, or UpdateLayeredWindow's) */
BOOL
FASTCALL
UserRedirNoPaint(PWND Wnd)
{
    if (gRedirLevel < 2 || !Wnd || !Wnd->spwndParent || !UserIsDesktopWindow(Wnd->spwndParent))
        return FALSE;
    return RedirIsLayeredUnset(Wnd) || RedirIsUlwWnd(Wnd);
}

/* Level 2: a hidden window keeps its record (UpdateLayeredWindow's content) */
BOOL
FASTCALL
UserRedirKeepOnHide(PWND Wnd)
{
    return Wnd && RedirIsUlwWnd(Wnd);
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

/* No reference is left: the record goes (USER lock) */
static VOID
RedirFree(PREDIR r)
{
    RECTL rc;

    ASSERT(r->cRefs == 0);
    ASSERT(r->pwnd == NULL);
    RedirTakeDirty(r, &rc);
    RemoveEntryList(&r->Link);
    gRedirBytes -= r->cjBits;
    if (r->psurf)
        GreRedirDeleteSurface(r->psurf);
    r->Magic = 0;
    ExFreePoolWithTag(r, USERTAG_REDIRSURF);
}

/* USER lock held */
static VOID
RedirRelease(PREDIR r)
{
    ASSERT(r->cRefs > 0);
    if (InterlockedDecrement(&r->cRefs) == 0)
        RedirFree(r);
}

VOID FASTCALL UserRedirAddRef(PVOID pv) { InterlockedIncrement(&((PREDIR)pv)->cRefs); }
VOID FASTCALL UserRedirRelease(PVOID pv) { RedirRelease((PREDIR)pv); }

/*
 * A DC object lets go of the record it was bound to (GreRedirBindDC, or the DC is freed), with or without
 * the USER lock: without it, a last reference leaves the record to the frame timer.
 */
VOID
FASTCALL
UserRedirDcRelease(PVOID pv)
{
    PREDIR r = pv;
    KIRQL OldIrql;

    ASSERT(r->Magic == REDIR_MAGIC);
    ASSERT(r->cRefs > 0);
    if (InterlockedDecrement(&r->cRefs) != 0)
        return;
    if (UserIsEnteredExclusive())
    {
        RedirFree(r);
        return;
    }
    KeAcquireSpinLock(&gRedirDeferLock, &OldIrql);
    InsertTailList(&gRedirDeferred, &r->DeferLink);
    KeReleaseSpinLock(&gRedirDeferLock, OldIrql);
    RedirArmTimer(REDIR_RETRY_100NS);
}

/* The frame timer, USER lock held: records whose last reference went without it */
static VOID
RedirFreeDeferred(VOID)
{
    PLIST_ENTRY Entry;
    KIRQL OldIrql;

    for (;;)
    {
        KeAcquireSpinLock(&gRedirDeferLock, &OldIrql);
        Entry = IsListEmpty(&gRedirDeferred) ? NULL : RemoveHeadList(&gRedirDeferred);
        KeReleaseSpinLock(&gRedirDeferLock, OldIrql);
        if (!Entry)
            break;
        RedirFree(CONTAINING_RECORD(Entry, REDIR, DeferLink));
    }
}
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

    /*
     * Level 2, layered or glass: the screen does not show its content as it is (blended, or not shown at all).
     * It paints all of itself, unless it does not paint (not set yet, or UpdateLayeredWindow's content).
     */
    if (r->bTrans)
    {
        if (!RedirIsLayeredUnset(Root) && !r->bUlw)
        {
            Rest = IntSysCreateRectpRgnIndirect(&Root->rcWindow);
            if (Rest)
            {
                IntInvalidateWindows(Root, Rest, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
                REGION_Delete(Rest);
            }
        }
        return;
    }

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
    if (!RedirSizeAllowed(r, cx, cy))
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
    r->bTrans = RedirIsTransWnd(Root);
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


/*
 * Level 2 composition. Where a translucent window is (layered or glass with a surface, or a layered window not
 * set yet, which shows nothing), what the screen shows is built in a frame buffer: the windows there are walked
 * from the top down to find which of them shows where (an opaque one hides what is below it), then drawn from
 * the bottom up (the desktop, opaque windows copied, translucent ones blended) and the result copied to the
 * screen in one blit. Elsewhere windows present on their own (RedirPresentRect), as at level 1. USER lock,
 * exclusive (the frame buffer is shared).
 */
#define TK_NONE     0   /* opaque */
#define TK_BLEND    1   /* composed with blending */
#define TK_HIDDEN   2   /* layered and not set yet: shows what is below */

static ULONG
RedirTransKind(PWND Wnd, PREDIR *pr)
{
    PREDIR r;

    *pr = NULL;
    if (gRedirLevel < 2 || !((Wnd->ExStyle & WS_EX_LAYERED) || RedirIsGlass(Wnd)))
        return TK_NONE;
    r = UserGetProp(Wnd, AtomRedir, TRUE);
    if ((Wnd->ExStyle & WS_EX_LAYERED) && !(r && r->bUlw) && !GetLayeredStatus(Wnd) && !UserGetProp(Wnd, AtomUlwSeen, TRUE))
        return TK_HIDDEN;
    if (r && r->bTrans && r->psurf)
    {
        *pr = r;
        return TK_BLEND;
    }
    /* Not redirected (past the budget): it draws on the screen as at level 1 */
    return TK_NONE;
}

/* The window rectangle, cut by the window region, on the screen */
static PREGION
RedirWindowRgn(PWND Wnd)
{
    PREGION Rgn = IntSysCreateRectpRgnIndirect(&Wnd->rcWindow);

    if (Rgn && Wnd->hrgnClip && !(Wnd->style & WS_MINIMIZE))
    {
        PREGION WndRgn = REGION_LockRgn(Wnd->hrgnClip);
        if (WndRgn)
        {
            REGION_bOffsetRgn(Rgn, -Wnd->rcWindow.left, -Wnd->rcWindow.top);
            IntGdiCombineRgn(Rgn, Rgn, WndRgn, RGN_AND);
            REGION_bOffsetRgn(Rgn, Wnd->rcWindow.left, Wnd->rcWindow.top);
            REGION_UnlockRgn(WndRgn);
        }
    }
    return Rgn;
}

static ULONG
RedirKeyPixel(COLORREF Key)
{
    return ((Key & 0xFF) << 16) | (Key & 0xFF00) | ((Key >> 16) & 0xFF);
}

/* How a translucent window's surface is drawn */
static VOID
RedirLayerFor(PWND Wnd, PREDIR r, PREDIR_LAYER pl)
{
    RtlZeroMemory(pl, sizeof(*pl));
    pl->psurf = r->psurf;
    pl->x = Wnd->rcWindow.left;
    pl->y = Wnd->rcWindow.top;
    pl->Mode = REDIRMODE_COPY;
    pl->Alpha = 255;
    if (r->bUlw)
    {
        if (!(r->UlwFlags & ULW_OPAQUE) && (r->UlwFlags & ULW_ALPHA))
        {
            pl->Alpha = r->UlwBlend.SourceConstantAlpha;
            pl->Mode = ((r->UlwBlend.AlphaFormat & AC_SRC_ALPHA) && r->bUlwAlpha) ? REDIRMODE_PREMUL : REDIRMODE_ALPHA;
        }
        if (!(r->UlwFlags & ULW_OPAQUE) && (r->UlwFlags & ULW_COLORKEY))
        {
            pl->Mode |= REDIRMODE_KEY;
            pl->Key = RedirKeyPixel(r->UlwKey);
        }
    }
    else if (Wnd->ExStyle & WS_EX_LAYERED)
    {
        COLORREF Key = 0;
        BYTE Alpha = 255;
        DWORD Flags = 0;

        IntGetLayeredAttributes(Wnd, &Key, &Alpha, &Flags);
        if (Flags & LWA_ALPHA)
        {
            pl->Alpha = Alpha;
            pl->Mode = REDIRMODE_ALPHA;
        }
        if (Flags & LWA_COLORKEY)
        {
            pl->Mode |= REDIRMODE_KEY;
            pl->Key = RedirKeyPixel(Key);
        }
    }
    else
    {
        pl->Mode = REDIRMODE_GLASS;
    }
    if ((pl->Mode & REDIRMODE_MASK) == REDIRMODE_ALPHA && pl->Alpha == 255)
        pl->Mode = (pl->Mode & ~REDIRMODE_MASK) | REDIRMODE_COPY;
}

/* The desktop window's background where no window is (it is not redirected): painted into a bitmap, then copied */
static BOOL
RedirComposeDesktop(PSURFACE psurfFB, LONG xFB, LONG yFB, PREGION Rgn)
{
    RECTL rc;
    HDC hdc;
    HBITMAP hbm, hbmOld = NULL;
    PSURFACE psurf;
    REDIR_LAYER Layer;
    BOOL bRet = FALSE;

    if (REGION_GetRgnBox(Rgn, &rc) == NULLREGION)
        return TRUE;
    hdc = GreCreateCompatibleDC(NULL, FALSE);
    if (!hdc)
        return FALSE;
    hbm = GreCreateBitmap(rc.right - rc.left, rc.bottom - rc.top, 1, 32, NULL);
    if (hbm)
        hbmOld = NtGdiSelectBitmap(hdc, hbm);
    if (hbmOld)
    {
        GreSetViewportOrgEx(hdc, -rc.left, -rc.top, NULL);
        IntPaintDesktop(hdc);
        NtGdiSelectBitmap(hdc, hbmOld);
        psurf = SURFACE_ShareLockSurface(hbm);
        if (psurf)
        {
            RtlZeroMemory(&Layer, sizeof(Layer));
            Layer.psurf = psurf;
            Layer.x = rc.left;
            Layer.y = rc.top;
            Layer.Mode = REDIRMODE_COPY;
            bRet = GreRedirComposeLayer(psurfFB, xFB, yFB, &Layer, Rgn);
            SURFACE_ShareUnlockSurface(psurf);
        }
    }
    IntGdiDeleteDC(hdc, TRUE);
    if (hbm)
        GreDeleteObject(hbm);
    return bRet;
}

/* The compose frame buffer goes (desktop switch, display mode change): no pixel of it outlives what it showed */
VOID
FASTCALL
UserRedirFreeFrameBuffer(VOID)
{
    if (!gRedirFB || !UserIsEnteredExclusive())
        return;
    gRedirBytes -= (SIZE_T)gRedirFB->SurfObj.sizlBitmap.cx * gRedirFB->SurfObj.sizlBitmap.cy * 4;
    GreRedirDeleteSurface(gRedirFB);
    gRedirFB = NULL;
}

#define RCE_COPY    0
#define RCE_BLEND   2
#define RCE_DESKTOP 3

typedef struct _REDIR_COMPOSE_ENTRY
{
    PWND Wnd;
    PREDIR r;
    PREGION Rgn;    /* what of the window shows in the pass (screen) */
    ULONG Kind;
} REDIR_COMPOSE_ENTRY, *PREDIR_COMPOSE_ENTRY;

/* Composes Damage (screen) on the desktop of the desktop window Desk where translucent windows are; Damage is kept */
static VOID
RedirCompose(PWND Desk, PREGION Damage)
{
    PWND Child;
    PREDIR r;
    PREGION Trans = NULL, D = NULL, Remaining = NULL, ScreenRgn = NULL, ScreenOut = NULL, W;
    PREDIR_COMPOSE_ENTRY Entries = NULL;
    ULONG cEntries = 0, cMax = 0, i, Kind;
    RECTL rcDamage, rcBox, rcScreen;
    LONG cx, cy;

    if (gRedirLevel < 2 || !Desk || !Damage || Desk->head.rpdesk != gpdeskInputDesktop || !UserIsEnteredExclusive())
        return;
    if (REGION_GetRgnBox(Damage, &rcDamage) == NULLREGION)
        return;

    /* Where the translucent windows are, in the damage */
    for (Child = Desk->spwndChild; Child; Child = Child->spwndNext)
    {
        if (!(Child->style & WS_VISIBLE))
            continue;
        cMax++;
        if (!RECTL_bIntersectRect(&rcBox, &rcDamage, &Child->rcWindow))
            continue;
        if (RedirTransKind(Child, &r) == TK_NONE)
            continue;
        W = RedirWindowRgn(Child);
        if (!W)
            continue;
        if (!Trans)
        {
            Trans = W;
            continue;
        }
        IntGdiCombineRgn(Trans, Trans, W, RGN_OR);
        REGION_Delete(W);
    }
    if (!Trans)
        return;

    D = IntSysCreateRectpRgn(0, 0, 0, 0);
    rcScreen = Desk->rcWindow;
    ScreenRgn = IntSysCreateRectpRgnIndirect(&rcScreen);
    if (!D || !ScreenRgn || IntGdiCombineRgn(D, Trans, Damage, RGN_AND) <= NULLREGION ||
        IntGdiCombineRgn(D, D, ScreenRgn, RGN_AND) <= NULLREGION)
    {
        goto done;
    }
    REGION_GetRgnBox(D, &rcBox);
    cx = rcBox.right - rcBox.left;
    cy = rcBox.bottom - rcBox.top;

    /* Top down: which window shows where */
    Entries = ExAllocatePoolWithTag(PagedPool, (cMax + 1) * sizeof(REDIR_COMPOSE_ENTRY), USERTAG_REDIRSURF);
    Remaining = IntSysCreateRectpRgn(0, 0, 0, 0);
    if (!Entries || !Remaining || IntGdiCombineRgn(Remaining, D, NULL, RGN_COPY) == ERROR)
        goto done;
    for (Child = Desk->spwndChild; Child && cEntries < cMax; Child = Child->spwndNext)
    {
        RECTL rcRemaining;

        if (!(Child->style & WS_VISIBLE))
            continue;
        if (REGION_GetRgnBox(Remaining, &rcRemaining) == NULLREGION)
            break;
        if (!RECTL_bIntersectRect(&rcRemaining, &rcRemaining, &Child->rcWindow))
            continue;
        Kind = RedirTransKind(Child, &r);
        if (Kind == TK_HIDDEN)
            continue;
        W = RedirWindowRgn(Child);
        if (!W)
            continue;
        if (IntGdiCombineRgn(W, W, Remaining, RGN_AND) <= NULLREGION)
        {
            REGION_Delete(W);
            continue;
        }
        Entries[cEntries].Wnd = Child;
        Entries[cEntries].Rgn = W;
        if (Kind == TK_BLEND)
        {
            Entries[cEntries].Kind = RCE_BLEND;
            Entries[cEntries].r = r;
        }
        else
        {
            r = UserGetProp(Child, AtomRedir, TRUE);
            if (r && !r->bTrans && UserRedirHasSurface(Child))
            {
                Entries[cEntries].Kind = RCE_COPY;
                Entries[cEntries].r = r;
            }
            else
            {
                /*
                 * No surface of its size (not painted yet, resized and not drawn since, past the budget). The screen
                 * there can already hold a blend of the translucent windows above it: reading it back would blend them
                 * again. The pass leaves that part of the screen alone; the window presents (and composes) when it
                 * paints.
                 *
                 * Tradeoff (kept on purpose): the part is cut out of the pass for every translucent window above it
                 * too, so for as long as the window has no surface (just resized and not repainted, never drawn, or
                 * past the budget for good) a translucent window over it is not drawn there: the screen keeps its
                 * previous pixels (an earlier blend, or the window's old pixels). The alternative, reading the screen
                 * back, blends the same translucent windows twice.
                 */
                IntGdiCombineRgn(Remaining, Remaining, W, RGN_DIFF);
                if (!ScreenOut)
                    ScreenOut = W;
                else
                {
                    IntGdiCombineRgn(ScreenOut, ScreenOut, W, RGN_OR);
                    REGION_Delete(W);
                }
                continue;
            }
            IntGdiCombineRgn(Remaining, Remaining, W, RGN_DIFF);
        }
        cEntries++;
    }
    if (ScreenOut)
    {
        if (IntGdiCombineRgn(D, D, ScreenOut, RGN_DIFF) <= NULLREGION)
            goto done;
        for (i = 0; i < cEntries; i++)
            IntGdiCombineRgn(Entries[i].Rgn, Entries[i].Rgn, ScreenOut, RGN_DIFF);
        REGION_GetRgnBox(D, &rcBox);
        cx = rcBox.right - rcBox.left;
        cy = rcBox.bottom - rcBox.top;
    }
    if (REGION_Complexity(Remaining) > NULLREGION)
    {
        Entries[cEntries].Wnd = Desk;
        Entries[cEntries].r = NULL;
        Entries[cEntries].Rgn = Remaining;
        Entries[cEntries].Kind = RCE_DESKTOP;
        Remaining = NULL;
        cEntries++;
    }

    /* The frame buffer: one, kept, as large as the largest pass so far */
    if (!gRedirFB || gRedirFB->SurfObj.sizlBitmap.cx < cx || gRedirFB->SurfObj.sizlBitmap.cy < cy)
    {
        PSURFACE psurfNew = GreRedirCreateSurface(max(cx, gRedirFB ? gRedirFB->SurfObj.sizlBitmap.cx : 0),
                                                  max(cy, gRedirFB ? gRedirFB->SurfObj.sizlBitmap.cy : 0), NULL);
        if (!psurfNew)
            goto done;
        UserRedirFreeFrameBuffer();
        gRedirFB = psurfNew;
        /* Counted like a surface: windows are refused first when it does not fit */
        gRedirBytes += (SIZE_T)psurfNew->SurfObj.sizlBitmap.cx * psurfNew->SurfObj.sizlBitmap.cy * 4;
    }

    /* Nothing of an earlier pass (or desktop) is left where no layer draws (a surface smaller than its window) */
    if (!GreRedirClearRect(gRedirFB, cx, cy))
        goto done;

    /* Bottom up; a layer that cannot be drawn ends the pass (nothing half drawn goes to the screen) */
    for (i = cEntries; i-- > 0; )
    {
        PREDIR_COMPOSE_ENTRY e = &Entries[i];
        REDIR_LAYER Layer;
        BOOL bOk = TRUE;

        switch (e->Kind)
        {
            case RCE_COPY:
                RtlZeroMemory(&Layer, sizeof(Layer));
                Layer.psurf = e->r->psurf;
                Layer.x = e->Wnd->rcWindow.left;
                Layer.y = e->Wnd->rcWindow.top;
                Layer.Mode = REDIRMODE_COPY;
                bOk = GreRedirComposeLayer(gRedirFB, rcBox.left, rcBox.top, &Layer, e->Rgn);
                break;
            case RCE_BLEND:
                RedirLayerFor(e->Wnd, e->r, &Layer);
                bOk = GreRedirComposeLayer(gRedirFB, rcBox.left, rcBox.top, &Layer, e->Rgn);
                break;
            default: /* RCE_DESKTOP */
                if (!RedirComposeDesktop(gRedirFB, rcBox.left, rcBox.top, e->Rgn))
                {
                    /* The background could not be painted (no memory): that part of the screen is left as it is
                       (never black, never read back); the windows over it wait for the next pass */
                    if (IntGdiCombineRgn(D, D, e->Rgn, RGN_DIFF) <= NULLREGION)
                        goto done;
                }
                break;
        }
        if (!bOk)
            goto done;
    }

    /* To the screen, in one blit */
    GreRedirPresent(gRedirFB, D, rcBox.left, rcBox.top);
    gRedirComposes++;
    if (gRedirDebug)
    {
        DbgPrint("win32k: redirection compose %lu: (%ld,%ld)-(%ld,%ld), %lu layers, %Iu of %Iu bytes in use\n", gRedirComposes,
                 rcBox.left, rcBox.top, rcBox.right, rcBox.bottom, cEntries, gRedirBytes, gRedirBudget);
    }

done:
    if (Entries)
    {
        for (i = 0; i < cEntries; i++)
            REGION_Delete(Entries[i].Rgn);
        ExFreePoolWithTag(Entries, USERTAG_REDIRSURF);
    }
    if (Remaining)
        REGION_Delete(Remaining);
    if (ScreenRgn)
        REGION_Delete(ScreenRgn);
    if (ScreenOut)
        REGION_Delete(ScreenOut);
    if (D)
        REGION_Delete(D);
    REGION_Delete(Trans);
}

/* Whether a translucent window (or a layered one not set yet) of the desktop window Desk overlaps prc: no pass is needed otherwise */
static BOOL
RedirTransNear(PWND Desk, const RECTL *prc)
{
    PWND Child;
    PREDIR r;
    RECTL rc;

    for (Child = Desk->spwndChild; Child; Child = Child->spwndNext)
    {
        if ((Child->style & WS_VISIBLE) && RECTL_bIntersectRect(&rc, prc, &Child->rcWindow) &&
            RedirTransKind(Child, &r) != TK_NONE)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* Composes a rectangle of the screen on Wnd's desktop (level 2) */
static VOID
RedirComposeRect(PWND Wnd, const RECTL *prc)
{
    PREGION Rgn;
    PWND Desk = Wnd ? Wnd->spwndParent : NULL;

    if (gRedirLevel < 2 || !Desk || !UserIsDesktopWindow(Desk) || RECTL_bIsEmptyRect(prc) || !RedirTransNear(Desk, prc))
        return;
    Rgn = IntSysCreateRectpRgnIndirect(prc);
    if (Rgn)
    {
        RedirCompose(Desk, Rgn);
        REGION_Delete(Rgn);
    }
}

/* winpos.c, level 2: a top-level window moved, changed size, z-order or region, or was shown or hidden */
VOID
FASTCALL
UserRedirLayoutChanged(PWND Wnd, const RECTL *prcOld)
{
    PREGION Rgn, New;
    RECTL rcBoth;

    if (gRedirLevel < 2 || !Wnd || !Wnd->spwndParent || !UserIsDesktopWindow(Wnd->spwndParent))
        return;
    RECTL_bUnionRect(&rcBoth, prcOld, &Wnd->rcWindow);
    if (!RedirTransNear(Wnd->spwndParent, &rcBoth))
        return;
    Rgn = IntSysCreateRectpRgnIndirect(prcOld);
    New = IntSysCreateRectpRgnIndirect(&Wnd->rcWindow);
    if (Rgn && New && IntGdiCombineRgn(Rgn, Rgn, New, RGN_OR) != ERROR)
        RedirCompose(Wnd->spwndParent, Rgn);
    if (New)
        REGION_Delete(New);
    if (Rgn)
        REGION_Delete(Rgn);
}

/* layered.c, level 2: SetLayeredWindowAttributes (bFirst: the window was not set before; it paints first) */
VOID
FASTCALL
UserRedirLayeredSet(PWND Wnd, BOOL bFirst)
{
    PREDIR r;

    if (gRedirLevel < 2 || !Wnd)
        return;
    r = UserGetProp(Wnd, AtomRedir, TRUE);
    if (r && r->bUlw)
    {
        /* Its content comes from painting again (the caller invalidates it) */
        r->bUlw = FALSE;
        bFirst = TRUE;
    }
    if (!bFirst && (Wnd->style & WS_VISIBLE))
        RedirComposeRect(Wnd, &Wnd->rcWindow);
}

/*
 * layered.c, level 2: UpdateLayeredWindow, after the window was moved and sized (prcOld: its rectangle
 * before). The content of hdcSrc (or prcDirty of it) replaces the surface's; it is blended with what is below
 * at every compose pass. FALSE: not done here (a child window, or no surface), the caller draws as before.
 */
BOOL
FASTCALL
UserRedirUpdateLayered(
    PWND Wnd,
    const RECTL *prcOld,
    HDC hdcSrc,
    const POINT *pptSrc,
    const RECT *prcDirty,
    const BLENDFUNCTION *pBlend,
    COLORREF crKey,
    DWORD dwFlags,
    PBOOL pbRet)
{
    PREDIR r;
    RECTL rc;
    BOOL bAlpha = FALSE, bCopied;

    *pbRet = FALSE;
    if (gRedirLevel < 2 || !Wnd || !Wnd->spwndParent || !UserIsDesktopWindow(Wnd->spwndParent) ||
        UserIsMessageWindow(Wnd) || (Wnd->state & WNDS_DESTROYED) || (Wnd->state2 & WNDS2_INDESTROY))
    {
        return FALSE;
    }
    r = UserRedirGet(Wnd);
    if (!r)
        return FALSE;
    if (hdcSrc)
    {
        BOOL bWhole;

        RECTL_vSetRect(&rc, 0, 0, r->cx, r->cy);
        bWhole = !prcDirty;
        if (prcDirty && !RECTL_bIntersectRect(&rc, &rc, (const RECTL *)prcDirty))
            RECTL_vSetEmptyRect(&rc);
        if (prcDirty && rc.left == 0 && rc.top == 0 && rc.right == r->cx && rc.bottom == r->cy)
            bWhole = TRUE;
        if (!RECTL_bIsEmptyRect(&rc))
        {
            if (!GreRedirLoadFromDC(r->psurf, hdcSrc, pptSrc ? pptSrc->x : 0, pptSrc ? pptSrc->y : 0, &rc, &bAlpha, &bCopied))
            {
                /* Not a memory DC with a bitmap, or its bits could not be read (verify the error code on the oracle) */
                EngSetLastError(ERROR_INVALID_PARAMETER);
                return TRUE;
            }
            /* The alpha of the whole content: taken from a full update, or the first one; a partial update of
               another format does not change how the rest is blended. A source range wholly outside the source
               bitmap copied nothing: the content (and how it is blended) stays as it was */
            if (bCopied && (bWhole || !r->bUlw))
                r->bUlwAlpha = (BOOLEAN)bAlpha;
        }
    }
    if (!r->bUlw)
    {
        /* No content given yet (hdcSrc NULL): nothing is shown, as for a layered window not set */
        if (!hdcSrc)
        {
            *pbRet = TRUE;
            return TRUE;
        }
        /* From now on GDI drawing into it shows nothing: its DCs get an empty visible region (windc.c) */
        r->bUlw = TRUE;
    }
    r->UlwFlags = dwFlags;
    r->UlwBlend = *pBlend;
    r->UlwKey = crKey;
    *pbRet = TRUE;

    if (Wnd->style & WS_VISIBLE)
    {
        PREGION Rgn = IntSysCreateRectpRgnIndirect(prcOld);
        PREGION New = IntSysCreateRectpRgnIndirect(&Wnd->rcWindow);

        if (Rgn && New && IntGdiCombineRgn(Rgn, Rgn, New, RGN_OR) != ERROR)
            RedirCompose(Wnd->spwndParent, Rgn);
        if (New)
            REGION_Delete(New);
        if (Rgn)
            REGION_Delete(Rgn);
    }
    return TRUE;
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
    if (prcSurf)
    {
        rc = *prcSurf;
        RECTL_vOffsetRect(&rc, Root->rcWindow.left, Root->rcWindow.top);
    }
    else
    {
        rc = Root->rcWindow;
    }
    /* Level 2: a translucent window is composed with what is below it */
    if (r->bTrans)
    {
        if (Root->style & WS_VISIBLE)
            RedirComposeRect(Root, &rc);
        gRedirPresents++;
        return;
    }
    Rgn = VIS_ComputeVisibleRegion(Root, FALSE, FALSE, TRUE);
    if (!Rgn)
        return;
    if (prcSurf)
    {
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
    /* Level 2: translucent windows over what it drew show it through them */
    RedirComposeRect(Root, &rc);
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

/* The raw input thread, when gRedirTimer fired: present what DCs still in use drew */
VOID
FASTCALL
UserRedirPresentPending(VOID)
{
    PLIST_ENTRY Entry;
    /* Busy DCs tried per pass: each try can wait about 1 ms with the USER lock held (rvr0c 3) */
    LONG lBudget = REDIR_RETRY_BUDGET;

    InterlockedExchange(&gRedirTimerArmed, 0);
    /* Released DCs present at once: usually nothing is left, and the USER lock is not taken for nothing */
    if (gRedirDirtyCount == 0 && gRedirRetries == 0 && IsListEmpty(&gRedirDeferred))
        return;
    UserEnterExclusive();
    RedirFreeDeferred();
    for (Entry = gRedirList.Flink; Entry != &gRedirList; )
    {
        PREDIR r = CONTAINING_RECORD(Entry, REDIR, Link);

        Entry = Entry->Flink;
        if (r->Dirty && r->pwnd)
        {
            /* RedirPresentDirty may detach r; the next entry was taken first, and r stays alive while a DC holds it */
            InterlockedIncrement(&r->cRefs);
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
        DceRedirRetryAll(&lBudget);
    if (gRedirRetries)
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
        /* Level 2: where a translucent window is, the compositor draws it and what is below it */
        if (gRedirLevel >= 2 && RedirTransKind(Child, &r) != TK_NONE)
        {
            Vis = VIS_ComputeVisibleRegion(Child, FALSE, FALSE, TRUE);
            if (!Vis)
                continue;
            Part = IntSysCreateRectpRgn(0, 0, 0, 0);
            if (Part && IntGdiCombineRgn(Part, Vis, RgnScreen, RGN_AND) > NULLREGION)
            {
                RedirCompose(DesktopWnd, Part);
                IntGdiCombineRgn(RgnScreen, RgnScreen, Part, RGN_DIFF);
            }
            if (Part)
                REGION_Delete(Part);
            REGION_Delete(Vis);
            continue;
        }
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
