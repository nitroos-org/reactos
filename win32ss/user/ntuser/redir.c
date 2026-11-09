/*
 * PROJECT:     NitroOS win32k
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Redirected window surfaces, stage R0 (fes/2026-11-09-win32k-redirected-window-surfaces.md)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\NitroRedirection (DWORD, amd64 only):
 * 0 (default) = windows draw on the screen as always; 1 = every eligible top-level window draws into a
 * surface of its own (its DCs and its children's DCs select it, in window coordinates), and that
 * surface is copied onto the screen through the window's visible region when the window has drawn
 * (released DC, EndPaint, or within a frame for DCs that stay in use) and when it moved. Covered
 * content is kept: GetDC/GetWindowDC of a covered window reads it. Level 2 (translucency) is not
 * implemented yet and behaves as 1. The boot option /NOREDIRECTION forces 0.
 *
 * Not redirected: the desktop window, message-only windows, layered windows, glass windows
 * (NitroSetWindowGlass), hidden windows, windows past the memory budget. They draw as always.
 * R0 keeps USER's painting rules (WM_PAINT on uncover); R1 changes them.
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(UserPainting);

typedef struct _REDIR
{
    LIST_ENTRY Link;
    LONG cRefs;             /* the window's while attached, plus one per bound DCE (USER lock) */
    PWND pwnd;              /* the top-level window; NULL once detached */
    HBITMAP hbm;            /* 32 bpp surface the size of the window rectangle */
    LONG cx, cy;
    SIZE_T cjBits;
    volatile LONG Dirty;    /* a bound DC drew (GDI, any thread) */
} REDIR, *PREDIR;

ULONG gRedirLevel = 0;
PKTIMER gRedirTimer = NULL;
static LIST_ENTRY gRedirList = { &gRedirList, &gRedirList };
static SIZE_T gRedirBytes, gRedirBudget;
static ATOM AtomRedir;
static volatile LONG gRedirTimerArmed;
static volatile LONG gRedirDirtyCount;   /* records with Dirty set: the timer takes the USER lock only then */
static ULONG gRedirCreated, gRedirRefused, gRedirPresents;

#define REDIR_MAX_SIDE      16384
#define REDIR_FRAME_100NS   (16 * 10000)

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
        gRedirLevel = 0;
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

    gRedirTimer = ExAllocatePoolWithTag(NonPagedPool, sizeof(KTIMER), USERTAG_REDIRECT);
    AtomRedir = IntAddGlobalAtom(L"NitroRedir", TRUE);
    if (!gRedirTimer || !AtomRedir)
    {
        ERR("Redirection: no timer or atom, staying off\n");
        gRedirLevel = 0;
        return;
    }
    KeInitializeTimer(gRedirTimer);
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

static VOID
RedirRelease(PREDIR r)
{
    ASSERT(r->cRefs > 0);
    if (--r->cRefs > 0)
        return;
    ASSERT(r->pwnd == NULL);
    if (InterlockedExchange(&r->Dirty, 0))
        InterlockedDecrement(&gRedirDirtyCount);
    RemoveEntryList(&r->Link);
    gRedirBytes -= r->cjBits;
    if (r->hbm)
        EngDeleteSurface((HSURF)r->hbm);
    ExFreePoolWithTag(r, USERTAG_REDIRECT);
}

VOID FASTCALL UserRedirAddRef(PVOID pv) { ((PREDIR)pv)->cRefs++; }
VOID FASTCALL UserRedirRelease(PVOID pv) { RedirRelease((PREDIR)pv); }
HBITMAP FASTCALL UserRedirSurface(PVOID pv) { return ((PREDIR)pv)->hbm; }
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
    DceRedirUnbindAll(r);
    r->pwnd = NULL;
    RedirRelease(r);
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
    HBITMAP hbm;

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

    hbm = GreRedirCreateSurface(cx, cy, r ? r->hbm : NULL);
    if (!hbm)
    {
        gRedirRefused++;
        if (r)
            UserRedirDetachWindow(Root);
        return NULL;
    }

    if (r)
    {
        HBITMAP hbmOld = r->hbm;

        gRedirBytes += cjNew - r->cjBits;
        r->hbm = hbm;
        r->cx = cx;
        r->cy = cy;
        r->cjBits = cjNew;
        /* Every DC still on the old surface moves to the new one, then the old one can go */
        DceRedirRebindAll(r, hbm);
        EngDeleteSurface((HSURF)hbmOld);
        return r;
    }

    r = ExAllocatePoolWithTag(PagedPool, sizeof(REDIR), USERTAG_REDIRECT);
    if (!r)
    {
        EngDeleteSurface((HSURF)hbm);
        gRedirRefused++;
        return NULL;
    }
    RtlZeroMemory(r, sizeof(REDIR));
    r->cRefs = 1;
    r->pwnd = Root;
    r->hbm = hbm;
    r->cx = cx;
    r->cy = cy;
    r->cjBits = cjNew;
    if (!UserSetProp(Root, AtomRedir, r, TRUE))
    {
        EngDeleteSurface((HSURF)hbm);
        ExFreePoolWithTag(r, USERTAG_REDIRECT);
        gRedirRefused++;
        return NULL;
    }
    InsertTailList(&gRedirList, &r->Link);
    gRedirBytes += cjNew;
    gRedirCreated++;
    return r;
}

/* Copies the window's surface onto the screen through its visible region (USER lock held) */
static VOID
RedirPresent(PREDIR r)
{
    PWND Root = r->pwnd;
    PREGION Rgn;

    if (InterlockedExchange(&r->Dirty, 0))
        InterlockedDecrement(&gRedirDirtyCount);
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
    GreRedirPresent(r->hbm, Rgn, Root->rcWindow.left, Root->rcWindow.top);
    REGION_Delete(Rgn);
    gRedirPresents++;
}

/* A DC bound to the record is released (EndPaint: always present, the window painted) */
VOID
FASTCALL
UserRedirReleased(PVOID pv, BOOL bForce)
{
    PREDIR r = pv;

    if (r->pwnd && (bForce || r->Dirty))
        RedirPresent(r);
}

/* The window moved or its z-order or visibility changed: show its content where it is now */
VOID
FASTCALL
UserRedirWindowMoved(PWND Wnd)
{
    PREDIR r;

    if (!gRedirLevel || !Wnd)
        return;
    r = UserGetProp(Wnd, AtomRedir, TRUE);
    if (r)
        RedirPresent(r);
}

/* GDI: a DC bound to the record drew (any thread, DC locked, no USER lock): present within a frame */
VOID
FASTCALL
UserRedirMarkDirty(PVOID pv)
{
    PREDIR r = pv;

    if (InterlockedExchange(&r->Dirty, 1) != 0)
        return;
    InterlockedIncrement(&gRedirDirtyCount);
    if (InterlockedExchange(&gRedirTimerArmed, 1) == 0)
    {
        LARGE_INTEGER Due;

        Due.QuadPart = -REDIR_FRAME_100NS;
        KeSetTimer(gRedirTimer, Due, NULL);
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
    if (gRedirDirtyCount == 0)
        return;
    UserEnterExclusive();
    for (Entry = gRedirList.Flink; Entry != &gRedirList; )
    {
        PREDIR r = CONTAINING_RECORD(Entry, REDIR, Link);

        Entry = Entry->Flink;
        if (r->Dirty && r->pwnd)
        {
            /* RedirPresent may detach r; the next entry was taken first, and r stays alive while a DC holds it */
            r->cRefs++;
            RedirPresent(r);
            RedirRelease(r);
        }
    }
    UserLeave();
}
