/*
 * PROJECT:         ReactOS Win32k subsystem
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            win32ss/user/ntuser/windc.c
 * PURPOSE:         Window DC management
 * COPYRIGHT:       Copyright 2007 ReactOS Team
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(UserDce);

/* GLOBALS *******************************************************************/

/* NOTE: I think we should store this per window station (including GDI objects) */
/* Answer: No, use the DCE pMonitor to compare with! */

static LIST_ENTRY LEDce;
static INT DCECount = 0; // Count of DCE in system.

#define DCX_CACHECOMPAREMASK (DCX_CLIPSIBLINGS | DCX_CLIPCHILDREN | \
                              DCX_NORESETATTRS | DCX_LOCKWINDOWUPDATE | \
                              DCX_LAYEREDWIN | DCX_CACHE | DCX_WINDOW | \
                              DCX_PARENTCLIP)

/* FUNCTIONS *****************************************************************/

CODE_SEG("INIT")
NTSTATUS
NTAPI
InitDCEImpl(VOID)
{
    InitializeListHead(&LEDce);
    return STATUS_SUCCESS;
}

//
// This should be moved to dc.c or dcutil.c.
//
HDC FASTCALL
DceCreateDisplayDC(VOID)
{
  UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"DISPLAY");

  if (!co_IntGraphicsCheck(TRUE))
    KeBugCheckEx(VIDEO_DRIVER_INIT_FAILURE, 0, 0, 0, USER_VERSION);

  return IntGdiCreateDC(&DriverName, NULL, NULL, NULL, FALSE);
}

/* Returns the DCE pointer from the HDC handle */
DCE*
FASTCALL
DceGetDceFromDC(HDC hdc)
{
    PLIST_ENTRY ListEntry;
    DCE* dce;

    ListEntry = LEDce.Flink;
    while (ListEntry != &LEDce)
    {
        dce = CONTAINING_RECORD(ListEntry, DCE, List);
        ListEntry = ListEntry->Flink;
        if (dce->hDC == hdc)
            return dce;
    }

    return NULL;
}

static
PREGION FASTCALL
DceGetVisRgn(PWND Window, ULONG Flags, HWND hWndChild, ULONG CFlags, PWND Root)
{
    PREGION Rgn;
    Rgn = VIS_ComputeVisibleRegionEx( Window,
                                      0 == (Flags & DCX_WINDOW),
                                      0 != (Flags & DCX_CLIPCHILDREN),
                                      0 != (Flags & DCX_CLIPSIBLINGS),
                                      Root);
    /* Caller expects a non-null region */
    if (!Rgn)
        Rgn = IntSysCreateRectpRgn(0, 0, 0, 0);
    return Rgn;
}

PDCE FASTCALL
DceAllocDCE(PWND Window OPTIONAL, DCE_TYPE Type)
{
  PDCE pDce;

  pDce = ExAllocatePoolWithTag(PagedPool, sizeof(DCE), USERTAG_DCE);
  if(!pDce)
        return NULL;

  pDce->hDC = DceCreateDisplayDC();
  if (!pDce->hDC)
  {
      ExFreePoolWithTag(pDce, USERTAG_DCE);
      return NULL;
  }
  DCECount++;
  TRACE("Alloc DCE's! %d\n",DCECount);
  pDce->hwndCurrent = (Window ? UserHMGetHandle(Window) : NULL);
  pDce->pwndOrg  = Window;
  pDce->pwndClip = Window;
  pDce->hrgnClip = NULL;
  pDce->hrgnClipPublic = NULL;
  pDce->hrgnSavedVis = NULL;
  pDce->ppiOwner = NULL;
  pDce->bGlass = FALSE;
  pDce->pRedir = NULL;
  pDce->RedirFlags = 0;

  InsertTailList(&LEDce, &pDce->List);

  DCU_SetDcUndeletable(pDce->hDC);

  if (Type == DCE_WINDOW_DC || Type == DCE_CLASS_DC) // Window DCE have ownership.
  {
     pDce->ptiOwner = GetW32ThreadInfo();
  }
  else
  {
     TRACE("FREE DCATTR!!!! NOT DCE_WINDOW_DC!!!!! hDC-> %p\n", pDce->hDC);
     GreSetDCOwner(pDce->hDC, GDI_OBJ_HMGR_NONE);
     pDce->ptiOwner = NULL;
  }

  if (Type == DCE_CACHE_DC)
  {
     pDce->DCXFlags = DCX_CACHE | DCX_DCEEMPTY;
  }
  else
  {
     pDce->DCXFlags = DCX_DCEBUSY;
     if (Window)
     {
        if (Type == DCE_WINDOW_DC)
        {
          if (Window->style & WS_CLIPCHILDREN) pDce->DCXFlags |= DCX_CLIPCHILDREN;
          if (Window->style & WS_CLIPSIBLINGS) pDce->DCXFlags |= DCX_CLIPSIBLINGS;
        }
     }
  }
  return(pDce);
}

static VOID APIENTRY
DceSetDrawable( PWND Window OPTIONAL,
                HDC hDC,
                ULONG Flags,
                BOOL SetClipOrigin,
                PWND Root OPTIONAL)
{
  RECTL rect = {0,0,0,0};

  if (Window)
  {
      if (Flags & DCX_WINDOW)
      {
         rect = Window->rcWindow;
      }
      else
      {
         rect = Window->rcClient;
      }
  }

  /* A redirected window draws into its top-level window's surface, in window coordinates */
  if (Root)
      RECTL_vOffsetRect(&rect, -Root->rcWindow.left, -Root->rcWindow.top);

  /* Set DC Origin and Window Rectangle */
  GreSetDCOrg( hDC, rect.left, rect.top, &rect);
}


static VOID FASTCALL
DceDeleteClipRgn(DCE* Dce)
{
   Dce->DCXFlags &= ~(DCX_EXCLUDERGN | DCX_INTERSECTRGN);

   if (Dce->DCXFlags & DCX_KEEPCLIPRGN )
   {
      Dce->DCXFlags &= ~DCX_KEEPCLIPRGN;
   }
   else if (Dce->hrgnClip != NULL)
   {
      GreDeleteObject(Dce->hrgnClip);
   }

   Dce->hrgnClip = NULL;

   /* Make it dirty so that the vis rgn gets recomputed next time */
   Dce->DCXFlags |= DCX_DCEDIRTY;
   IntGdiSetHookFlags(Dce->hDC, DCHF_INVALIDATEVISRGN);
}

/* The region that clips a DC, to make its visible region. The DC of a paint in progress
 * holds the update region of its window, which belongs to the process that paints, and
 * REGION_LockRgn cannot reach it from the process of a window that moved. Such a region is
 * read as it is in the kernel: its attributes are in the other process, and are not touched.
 * The update region is not changed by the application. */
static PREGION
DceLockClipRgn(HRGN hrgn, PBOOL pbForeign)
{
   PREGION prgn = REGION_LockRgn(hrgn);

   *pbForeign = FALSE;
   if (prgn == NULL)
   {
      prgn = (PREGION)GDIOBJ_LockObjectEx(hrgn, GDIObjType_RGN_TYPE, GDIOBJFLAG_IGNOREPID);
      *pbForeign = (prgn != NULL);
   }
   return prgn;
}

static VOID
DceUnlockClipRgn(PREGION prgn, BOOL bForeign)
{
   if (bForeign)
      GDIOBJ_vUnlockObject(&prgn->BaseObject);
   else
      REGION_UnlockRgn(prgn);
}

VOID
FASTCALL
DceUpdateVisRgn(DCE *Dce, PWND Window, ULONG Flags)
{
   PREGION RgnVisible = NULL;
   ULONG DcxFlags;
   PWND DesktopWindow = NULL;
   PWND Root = Dce->pRedir ? UserRedirWindow(Dce->pRedir) : NULL;

   if (Flags & DCX_PARENTCLIP)
   {
      PWND Parent;

      Parent = Window->spwndParent;
      if (!Parent)
      {
         RgnVisible = NULL;
         goto noparent;
      }

      if (Parent->style & WS_CLIPSIBLINGS)
      {
         DcxFlags = DCX_CLIPSIBLINGS |
                    (Flags & ~(DCX_CLIPCHILDREN | DCX_WINDOW));
      }
      else
      {
         DcxFlags = Flags & ~(DCX_CLIPSIBLINGS | DCX_CLIPCHILDREN | DCX_WINDOW);
      }
      RgnVisible = DceGetVisRgn(Parent, DcxFlags, UserHMGetHandle(Window), Flags, Root);
   }
   else if (Window == NULL)
   {
      DesktopWindow = UserGetWindowObject(IntGetDesktopWindow());
      if (NULL != DesktopWindow)
      {
         RgnVisible = IntSysCreateRectpRgnIndirect(&DesktopWindow->rcWindow);
      }
      else
      {
         RgnVisible = NULL;
      }
   }
   else
   {
      RgnVisible = DceGetVisRgn(Window, Flags, 0, 0, Root);
   }

noparent:
   if (Flags & DCX_INTERSECTRGN)
   {
      PREGION RgnClip = NULL;
      BOOL bForeign = FALSE;

      if (Dce->hrgnClip != NULL)
          RgnClip = DceLockClipRgn(Dce->hrgnClip, &bForeign);

      if (RgnClip)
      {
         IntGdiCombineRgn(RgnVisible, RgnVisible, RgnClip, RGN_AND);
         DceUnlockClipRgn(RgnClip, bForeign);
      }
      else
      {
         if (RgnVisible != NULL)
         {
            REGION_Delete(RgnVisible);
         }
         RgnVisible = IntSysCreateRectpRgn(0, 0, 0, 0);
      }
   }
   else if ((Flags & DCX_EXCLUDERGN) && Dce->hrgnClip != NULL)
   {
       BOOL bForeign;
       PREGION RgnClip = DceLockClipRgn(Dce->hrgnClip, &bForeign);
       if (RgnClip)
       {
           IntGdiCombineRgn(RgnVisible, RgnVisible, RgnClip, RGN_DIFF);
           DceUnlockClipRgn(RgnClip, bForeign);
       }
   }

   /* Clip regions are in screen coordinates; the DC of a redirected window draws in its surface's */
   if (Root && RgnVisible)
      REGION_bOffsetRgn(RgnVisible, -Root->rcWindow.left, -Root->rcWindow.top);

   /* A failed allocation must not select the whole surface: select the empty default region */
   if (!RgnVisible && (Window || DesktopWindow))
      RgnVisible = prgnDefault;

   Dce->DCXFlags &= ~DCX_DCEDIRTY;
   GdiSelectVisRgn(Dce->hDC, RgnVisible);
   /* Tell GDI driver */
   if (Window)
       IntEngWindowChanged(Window, WOC_RGN_CLIENT);

   if (RgnVisible != NULL)
   {
      REGION_Delete(RgnVisible);
   }
}

/*
 * Binds the DCE's DC to a redirection record (its window's surface) or, with NULL, back to the screen.
 * FALSE: the DC is held by another process for now; the DCE keeps its binding and its reference to the
 * record (DCE_REDIR_RETRY), and is bound again at its next GetDC, release or move. A record is never
 * released while a DC may still draw into it.
 */
static VOID
DceRedirSetRetry(PDCE Dce, BOOL bRetry)
{
   if (bRetry && !(Dce->RedirFlags & DCE_REDIR_RETRY))
   {
      Dce->RedirFlags |= DCE_REDIR_RETRY;
      UserRedirRetryCount(1);
   }
   else if (!bRetry && (Dce->RedirFlags & DCE_REDIR_RETRY))
   {
      Dce->RedirFlags &= ~(DCE_REDIR_RETRY | DCE_REDIR_TRIED);
      UserRedirRetryCount(-1);
   }
}

/* A DC in use that draws on the screen again: its screen origin, also when another process owns it */
static VOID
DceRedirSetScreenDrawable(PDCE Dce)
{
   RECTL rect = (Dce->DCXFlags & DCX_WINDOW) ? Dce->pwndOrg->rcWindow : Dce->pwndOrg->rcClient;

   GreRedirSetDCOrg(Dce->hDC, rect.left, rect.top, &rect);
}

static BOOL
DceRedirBind(PDCE Dce, PVOID pRedir)
{
   PVOID pvOld;
   ULONG Status;

   if (Dce->pRedir == pRedir && !(Dce->RedirFlags & DCE_REDIR_RETRY))
      return TRUE;
   Status = GreRedirBindDC(Dce->hDC, pRedir, pRedir ? UserRedirSurface(pRedir) : NULL, &pvOld);
   /* A DC that is gone draws nothing: unbinding it is done */
   if (Status == REDIRBIND_GONE && !pRedir)
      Status = REDIRBIND_OK;
   if (Status != REDIRBIND_OK)
   {
      /* Tried again at its next GetDC, release or move, and from the frame timer */
      DceRedirSetRetry(Dce, TRUE);
      return FALSE;
   }
   DceRedirSetRetry(Dce, FALSE);
   if (Dce->pRedir != pRedir)
   {
      if (pRedir)
         UserRedirAddRef(pRedir);
      if (Dce->pRedir)
         UserRedirRelease(Dce->pRedir);
      Dce->pRedir = pRedir;
      /* Its visible region and origin were for the other binding */
      Dce->RedirFlags |= DCE_REDIR_VISSTALE;
   }
   return TRUE;
}

/* The record's window lets go of its surface: every DC on it draws on the screen again */
VOID
FASTCALL
DceRedirUnbindAll(PVOID pRedir)
{
   PLIST_ENTRY ListEntry;
   PDCE Dce;

   for (ListEntry = LEDce.Flink; ListEntry != &LEDce; )
   {
      Dce = CONTAINING_RECORD(ListEntry, DCE, List);
      ListEntry = ListEntry->Flink;
      if (Dce->pRedir != pRedir)
         continue;
      if (!DceRedirBind(Dce, NULL))
         continue;
      /* A DC in use keeps drawing: its screen origin and visible region now (the others at their next GetDC) */
      if ((Dce->DCXFlags & DCX_DCEBUSY) && Dce->pwndOrg)
      {
         DceRedirSetScreenDrawable(Dce);
         DceUpdateVisRgn(Dce, Dce->pwndOrg, Dce->DCXFlags);
         Dce->RedirFlags &= ~DCE_REDIR_VISSTALE;
      }
   }
}

/* The record has a new surface (the window was resized): every DC on it moves there, or keeps the old one until it can */
VOID
FASTCALL
DceRedirRebindAll(PVOID pRedir, PSURFACE psurf)
{
   PLIST_ENTRY ListEntry;
   PDCE Dce;
   PVOID pvOld;

   for (ListEntry = LEDce.Flink; ListEntry != &LEDce; )
   {
      Dce = CONTAINING_RECORD(ListEntry, DCE, List);
      ListEntry = ListEntry->Flink;
      if (Dce->pRedir != pRedir)
         continue;
      DceRedirSetRetry(Dce, GreRedirBindDC(Dce->hDC, pRedir, psurf, &pvOld) != REDIRBIND_OK);
   }
}

/*
 * The frame timer: DCs whose binding could not be changed are tried again. Each try of a DC that is still
 * busy waits a little (GDIOBJ_LockObjectEx) with the USER lock held, so a pass tries at most *plBudget of
 * them, round robin (DCE_REDIR_TRIED): the others get their turn at the next tick.
 */
VOID
FASTCALL
DceRedirRetryAll(_Inout_ PLONG plBudget)
{
   PLIST_ENTRY ListEntry;
   PDCE Dce;
   PVOID Target;
   ULONG Round;

   for (Round = 0; Round < 2; Round++)
   {
      if (Round)
      {
         /* Every DC waiting had its turn in this round: a new round with what is left of the budget */
         for (ListEntry = LEDce.Flink; ListEntry != &LEDce; ListEntry = ListEntry->Flink)
            CONTAINING_RECORD(ListEntry, DCE, List)->RedirFlags &= ~DCE_REDIR_TRIED;
      }
      for (ListEntry = LEDce.Flink; ListEntry != &LEDce; )
      {
         Dce = CONTAINING_RECORD(ListEntry, DCE, List);
         ListEntry = ListEntry->Flink;
         if (!(Dce->RedirFlags & DCE_REDIR_RETRY) || (Dce->RedirFlags & DCE_REDIR_TRIED))
            continue;
         if (*plBudget <= 0)
            return;
         (*plBudget)--;
         Dce->RedirFlags |= DCE_REDIR_TRIED;
         /* Its record if the window still has it (a new surface after a resize), else the screen */
         Target = (Dce->pRedir && UserRedirWindow(Dce->pRedir)) ? Dce->pRedir : NULL;
         if (DceRedirBind(Dce, Target) && !Dce->pRedir && (Dce->DCXFlags & DCX_DCEBUSY) && Dce->pwndOrg)
         {
            DceRedirSetScreenDrawable(Dce);
            DceUpdateVisRgn(Dce, Dce->pwndOrg, Dce->DCXFlags);
            Dce->RedirFlags &= ~DCE_REDIR_VISSTALE;
         }
      }
   }
}

static INT FASTCALL
DceReleaseDC(DCE* dce, BOOL EndPaint)
{
   if (DCX_DCEBUSY != (dce->DCXFlags & (DCX_INDESTROY | DCX_DCEEMPTY | DCX_DCEBUSY)))
   {
      return 0;
   }

   /* What a redirected window drew goes to the screen now; a cache DC lets go of its surface */
   if (dce->pRedir)
   {
      UserRedirReleased(dce->pRedir, EndPaint);
      if (dce->DCXFlags & DCX_CACHE)
         DceRedirBind(dce, NULL);
   }

   /* Restore previous visible region */
   if (EndPaint)
   {
      DceUpdateVisRgn(dce, dce->pwndOrg, dce->DCXFlags);
   }

   if ((dce->DCXFlags & (DCX_INTERSECTRGN | DCX_EXCLUDERGN)) &&
         ((dce->DCXFlags & DCX_CACHE) || EndPaint))
   {
      DceDeleteClipRgn(dce);
   }

   if (dce->DCXFlags & DCX_CACHE)
   {
      if (!(dce->DCXFlags & DCX_NORESETATTRS))
      {
         // Clean the DC
         if (!IntGdiCleanDC(dce->hDC)) return 0;

         if (dce->DCXFlags & DCX_DCEDIRTY)
         {
           /* Don't keep around invalidated entries
            * because SetDCState() disables hVisRgn updates
            * by removing dirty bit. */
           dce->hwndCurrent = 0;
           dce->pwndOrg  = NULL;
           dce->pwndClip = NULL;
           dce->DCXFlags &= DCX_CACHE;
           dce->DCXFlags |= DCX_DCEEMPTY;
         }
      }
      dce->DCXFlags &= ~DCX_DCEBUSY;
      TRACE("Exit!!!!! DCX_CACHE!!!!!!   hDC-> %p \n", dce->hDC);
      if (!GreSetDCOwner(dce->hDC, GDI_OBJ_HMGR_NONE))
         return 0;
      dce->ptiOwner = NULL; // Reset ownership.
      dce->ppiOwner = NULL;

#if 0 // Need to research and fix before this is a "growing" issue.
      if (++DCECache > 32)
      {
         ListEntry = LEDce.Flink;
         while (ListEntry != &LEDce)
         {
            pDCE = CONTAINING_RECORD(ListEntry, DCE, List);
            ListEntry = ListEntry->Flink;
            if (!(pDCE->DCXFlags & DCX_DCEBUSY))
            {  /* Free the unused cache DCEs. */
               DceFreeDCE(pDCE, TRUE);
            }
         }
      }
#endif
   }
   return 1; // Released!
}


HDC FASTCALL
UserGetDCEx(PWND Wnd OPTIONAL, HANDLE ClipRegion, ULONG Flags)
{
   PWND Parent;
   ULONG DcxFlags;
   DCE* Dce = NULL;
   BOOL UpdateClipOrigin = FALSE;
   BOOL bUpdateVisRgn = TRUE;
   BOOL bRedirLost = FALSE;
   HDC hDC = NULL;
   PPROCESSINFO ppi;
   PLIST_ENTRY ListEntry;

   if (NULL == Wnd)
   {
      Flags &= ~DCX_USESTYLE;
      Flags |= DCX_CACHE;
   }

   if (Flags & DCX_PARENTCLIP) Flags |= DCX_CACHE;

   // When GetDC is called with hWnd nz, DCX_CACHE & _WINDOW are clear w _USESTYLE set.
   if (Flags & DCX_USESTYLE)
   {
      Flags &= ~(DCX_CLIPCHILDREN | DCX_CLIPSIBLINGS | DCX_PARENTCLIP);
      if (!(Flags & DCX_WINDOW)) // Not window rectangle
      {
         if (Wnd->pcls->style & CS_PARENTDC)
         {
            Flags |= DCX_PARENTCLIP;
         }

         if (!(Flags & DCX_CACHE) && // Not on the cheap wine list.
             !(Wnd->pcls->style & CS_OWNDC) )
         {
            if (!(Wnd->pcls->style & CS_CLASSDC))
            // The window is not POWNED or has any CLASS, so we are looking for cheap wine.
               Flags |= DCX_CACHE;
            else
            {
               if (Wnd->pcls->pdce) hDC = ((PDCE)Wnd->pcls->pdce)->hDC;
               TRACE("We have CLASS!!\n");
            }
         }

         if (Wnd->style & WS_CLIPSIBLINGS)
         {
            Flags |= DCX_CLIPSIBLINGS;
         }

         if (Wnd->style & WS_CLIPCHILDREN &&
             !(Wnd->style & WS_MINIMIZE))
         {
            Flags |= DCX_CLIPCHILDREN;
         }
         /* If minized with icon in the set, we are forced to be cheap! */
         if (Wnd->style & WS_MINIMIZE && Wnd->pcls->spicn)
         {
            Flags |= DCX_CACHE;
         }
      }
      else
      {
         if (Wnd->style & WS_CLIPSIBLINGS) Flags |= DCX_CLIPSIBLINGS;
         Flags |= DCX_CACHE;
      }
   }

   if (Flags & DCX_WINDOW) Flags &= ~DCX_CLIPCHILDREN;

   if (Flags & DCX_NOCLIPCHILDREN)
   {
      Flags |= DCX_CACHE;
      Flags &= ~(DCX_PARENTCLIP | DCX_CLIPCHILDREN);
   }

   Parent = (Wnd ? Wnd->spwndParent : NULL);

   if (NULL == Wnd || !(Wnd->style & WS_CHILD) || NULL == Parent)
   {
      Flags &= ~DCX_PARENTCLIP;
      Flags |= DCX_CLIPSIBLINGS;
   }

   /* It seems parent clip is ignored when clipping siblings or children */
   if (Flags & (DCX_CLIPSIBLINGS | DCX_CLIPCHILDREN)) Flags &= ~DCX_PARENTCLIP;

   if (Flags & DCX_PARENTCLIP)
   {
      if ((Wnd->style & WS_VISIBLE) &&
          (Parent->style & WS_VISIBLE))
      {
         Flags &= ~DCX_CLIPCHILDREN;
         if (Parent->style & WS_CLIPSIBLINGS)
         {
            Flags |= DCX_CLIPSIBLINGS;
         }
      }
   }

   // Window nz, check to see if we still own this or it is just cheap wine tonight.
   if (!(Flags & DCX_CACHE))
   {
      if ( Wnd->head.pti != GetW32ThreadInfo())
         Flags |= DCX_CACHE; // Ah~ Not Powned! Forced to be cheap~
   }

   DcxFlags = Flags & DCX_CACHECOMPAREMASK;

   if (Flags & DCX_CACHE)
   { // Scan the cheap wine list for our match.
      DCE* DceEmpty = NULL;
      DCE* DceUnused = NULL;
      KeEnterCriticalRegion();
      ListEntry = LEDce.Flink;
      while (ListEntry != &LEDce)
      {
         Dce = CONTAINING_RECORD(ListEntry, DCE, List);
         ListEntry = ListEntry->Flink;
//
// The way I understand this, you can have more than one DC per window.
// Only one Owned if one was requested and saved and one Cached.
//
         if ((Dce->DCXFlags & (DCX_CACHE | DCX_DCEBUSY)) == DCX_CACHE)
         {
            DceUnused = Dce;
            if (Dce->DCXFlags & DCX_DCEEMPTY)
            {
               DceEmpty = Dce;
            }
            else if (Dce->hwndCurrent == (Wnd ? UserHMGetHandle(Wnd) : NULL) &&
                     ((Dce->DCXFlags & DCX_CACHECOMPAREMASK) == DcxFlags))
            {
               UpdateClipOrigin = TRUE;
               break;
            }
         }
         Dce = NULL; // Loop issue?
      }
      KeLeaveCriticalRegion();

      Dce = (DceEmpty == NULL) ? DceUnused : DceEmpty;

      if (Dce == NULL)
      {
         Dce = DceAllocDCE(NULL, DCE_CACHE_DC);
      }
      if (Dce == NULL) return NULL;

      Dce->hwndCurrent = (Wnd ? UserHMGetHandle(Wnd) : NULL);
      Dce->pwndOrg = Dce->pwndClip = Wnd;
   }
   else // If we are here, we are POWNED or having CLASS.
   {
      KeEnterCriticalRegion();
      ListEntry = LEDce.Flink;
      while (ListEntry != &LEDce)
      {
          Dce = CONTAINING_RECORD(ListEntry, DCE, List);
          ListEntry = ListEntry->Flink;

          // Skip Cache DCE entries.
          if (!(Dce->DCXFlags & DCX_CACHE))
          {
             // Check for Window handle than HDC match for CLASS.
             if (Dce->hwndCurrent == UserHMGetHandle(Wnd))
             {
                bUpdateVisRgn = FALSE;
                break;
             }
             else if (Dce->hDC == hDC) break;
          }
          Dce = NULL; // Loop issue?
      }
      KeLeaveCriticalRegion();

      if (Dce == NULL)
      {
         return(NULL);
      }

      if ( (Flags & (DCX_INTERSECTRGN|DCX_EXCLUDERGN)) &&
           (Dce->DCXFlags & (DCX_INTERSECTRGN|DCX_EXCLUDERGN)) )
      {
         DceDeleteClipRgn(Dce);
      }
   }
// First time use hax, need to use DceAllocDCE during window display init.
   if (NULL == Dce)
   {
      return(NULL);
   }

   if (!GreIsHandleValid(Dce->hDC))
   {
      ERR("FIXME: Got DCE with invalid hDC! %p\n", Dce->hDC);
      Dce->hDC = DceCreateDisplayDC();
      /* FIXME: Handle error */
   }

   Dce->DCXFlags = Flags | DCX_DCEBUSY;

   /*
    * Bump it up! This prevents the random errors in wine dce tests and with
    * proper bits set in DCX_CACHECOMPAREMASK.
    * Reference:
    *   https://reactos.org/archives/public/ros-dev/2008-July/010498.html
    *   https://reactos.org/archives/public/ros-dev/2008-July/010499.html
    */
   RemoveEntryList(&Dce->List);
   InsertHeadList(&LEDce, &Dce->List);

   /* Introduced in rev 6691 and modified later. */
   if ( (Flags & DCX_INTERSECTUPDATE) && !ClipRegion )
   {
      Flags |= DCX_INTERSECTRGN | DCX_KEEPCLIPRGN;
      Dce->DCXFlags |= DCX_INTERSECTRGN | DCX_KEEPCLIPRGN;
      ClipRegion = Wnd->hrgnUpdate;
      bUpdateVisRgn = TRUE;
   }

   if (ClipRegion == HRGN_WINDOW)
   {
      if (!(Flags & DCX_WINDOW))
      {
         Dce->hrgnClip = NtGdiCreateRectRgn(
             Wnd->rcClient.left,
             Wnd->rcClient.top,
             Wnd->rcClient.right,
             Wnd->rcClient.bottom);
      }
      else
      {
          Dce->hrgnClip = NtGdiCreateRectRgn(
              Wnd->rcWindow.left,
              Wnd->rcWindow.top,
              Wnd->rcWindow.right,
              Wnd->rcWindow.bottom);
      }
      Dce->DCXFlags &= ~DCX_KEEPCLIPRGN;
      bUpdateVisRgn = TRUE;
   }
   else if (ClipRegion != NULL)
   {
      if (Dce->hrgnClip != NULL)
      {
         ERR("Should not be called!!\n");
         GreDeleteObject(Dce->hrgnClip);
         Dce->hrgnClip = NULL;
      }
      Dce->hrgnClip = ClipRegion;
      bUpdateVisRgn = TRUE;
   }

   if (IntGdiSetHookFlags(Dce->hDC, DCHF_VALIDATEVISRGN)) bUpdateVisRgn = TRUE;

   /* NitroRedirection: a DC of a redirected window draws into its top-level window's surface */
   if (gRedirLevel || Dce->pRedir)
   {
      PWND RedirRoot = UserRedirRootFor(Wnd);
      PVOID pRedir = RedirRoot ? UserRedirGet(RedirRoot) : NULL;

      /* Not eligible now (hidden, layered, glass): a surface it had no longer holds what it shows */
      if (!RedirRoot && Wnd)
      {
         PWND Top = Wnd;
         while (Top->spwndParent && !UserIsDesktopWindow(Top->spwndParent))
            Top = Top->spwndParent;
         UserRedirDetachWindow(Top);
      }

      /* Still bound to another surface (its DC is held elsewhere): it draws nothing this time, not at a wrong place */
      if ((Dce->pRedir != pRedir || (Dce->RedirFlags & DCE_REDIR_RETRY)) &&
          !DceRedirBind(Dce, pRedir) && Dce->pRedir != pRedir)
      {
         bRedirLost = TRUE;
      }
      /* Bound otherwise since its region was computed (here or when its window let go of its surface) */
      if (Dce->RedirFlags & DCE_REDIR_VISSTALE)
      {
         Dce->RedirFlags &= ~DCE_REDIR_VISSTALE;
         bUpdateVisRgn = TRUE;
      }
   }

   DceSetDrawable(Wnd, Dce->hDC, Flags, UpdateClipOrigin, Dce->pRedir ? UserRedirWindow(Dce->pRedir) : NULL);

   if (bUpdateVisRgn) DceUpdateVisRgn(Dce, Wnd, Flags);

   if (bRedirLost)
   {
      PREGION RgnEmpty = IntSysCreateRectpRgn(0, 0, 0, 0);
      if (RgnEmpty)
      {
         GdiSelectVisRgn(Dce->hDC, RgnEmpty);
         REGION_Delete(RgnEmpty);
      }
      Dce->RedirFlags |= DCE_REDIR_VISSTALE;
   }

   /* A window marked as glass (HWNDPARAM_ROUTINE_ROS_SETGLASS): its DC blends 32 bpp DIB copies with alpha */
   {
      BOOL bGlass = Wnd && UserGetProp(Wnd, gpsi->atomFrostedWindowProp, TRUE) != NULL;

      if (bGlass || Dce->bGlass)
      {
         PDC pdcGlass = DC_LockDc(Dce->hDC);

         if (pdcGlass)
         {
            pdcGlass->hwndGlass = bGlass ? UserHMGetHandle(Wnd) : NULL;
            if (bGlass)
               pdcGlass->rclGlass = *(PRECTL)&Wnd->rcWindow;
            DC_UnlockDc(pdcGlass);
         }
         Dce->bGlass = bGlass;
      }
   }

   if (Dce->DCXFlags & DCX_CACHE)
   {
      TRACE("ENTER!!!!!! DCX_CACHE!!!!!!   hDC-> %p\n", Dce->hDC);
      // Need to set ownership so Sync dcattr will work.
      GreSetDCOwner(Dce->hDC, GDI_OBJ_HMGR_POWNED);
      Dce->ptiOwner = GetW32ThreadInfo(); // Set the temp owning
   }

   if ( Wnd &&
        Wnd->ExStyle & WS_EX_LAYOUTRTL &&
       !(Flags & DCX_KEEPLAYOUT) )
   {
      NtGdiSetLayout(Dce->hDC, -1, LAYOUT_RTL);
   }

   if (Dce->DCXFlags & DCX_PROCESSOWNED)
   {
      ppi = PsGetCurrentProcessWin32Process();
      ppi->W32PF_flags |= W32PF_OWNDCCLEANUP;
      Dce->ptiOwner = NULL;
      Dce->ppiOwner = ppi;
   }

   return(Dce->hDC);
}

/***********************************************************************
 *           DceFreeDCE
 */
void FASTCALL
DceFreeDCE(PDCE pdce, BOOLEAN Force)
{
  BOOL Hit = FALSE;

  ASSERT(pdce != NULL);
  if (NULL == pdce) return;

  pdce->DCXFlags |= DCX_INDESTROY;

  if (Force &&
      GreGetObjectOwner(pdce->hDC) != GDI_OBJ_HMGR_POWNED)
  {
     TRACE("Change ownership for DCE! -> %p\n" , pdce);
     // NOTE: Windows sets W32PF_OWNDCCLEANUP and moves on.
     if (GreIsHandleValid(pdce->hDC))
     {
         GreSetDCOwner(pdce->hDC, GDI_OBJ_HMGR_POWNED);
     }
     else
     {
         ERR("Attempted to change ownership of an DCEhDC %p currently being destroyed!!!\n",
             pdce->hDC);
         Hit = TRUE;
     }
  }
  else
  {
     if (GreGetObjectOwner(pdce->hDC) == GDI_OBJ_HMGR_PUBLIC)
        GreSetDCOwner(pdce->hDC, GDI_OBJ_HMGR_POWNED);
  }

  if (pdce->pRedir)
  {
     if (Hit || !DceRedirBind(pdce, NULL))
     {
        /* The DC may still draw (and mark the record) while it goes: the timer releases the record once it is gone or unbound */
        UserRedirOrphan(pdce->hDC, pdce->pRedir);
        pdce->pRedir = NULL;
     }
  }
  DceRedirSetRetry(pdce, FALSE);

  if (!Hit) IntGdiDeleteDC(pdce->hDC, TRUE);

  if (pdce->hrgnClip && !(pdce->DCXFlags & DCX_KEEPCLIPRGN))
  {
      GreDeleteObject(pdce->hrgnClip);
      pdce->hrgnClip = NULL;
  }

  RemoveEntryList(&pdce->List);

  ExFreePoolWithTag(pdce, USERTAG_DCE);

  DCECount--;
  TRACE("Freed DCE's! %d \n", DCECount);
}

/***********************************************************************
 *           DceFreeWindowDCE
 *
 * Remove owned DCE and reset unreleased cache DCEs.
 */
void FASTCALL
DceFreeWindowDCE(PWND Window)
{
  PDCE pDCE;
  PLIST_ENTRY ListEntry;

  if (DCECount <= 0)
  {
     ERR("FreeWindowDCE No Entry! %d\n",DCECount);
     return;
  }

  ListEntry = LEDce.Flink;
  while (ListEntry != &LEDce)
  {
     pDCE = CONTAINING_RECORD(ListEntry, DCE, List);
     ListEntry = ListEntry->Flink;
     if ( pDCE->hwndCurrent == UserHMGetHandle(Window) &&
          !(pDCE->DCXFlags & DCX_DCEEMPTY) )
     {
        if (!(pDCE->DCXFlags & DCX_CACHE)) /* Owned or Class DCE */
        {
           if (Window->pcls->style & CS_CLASSDC) /* Test Class first */
           {
              if (pDCE->DCXFlags & (DCX_INTERSECTRGN | DCX_EXCLUDERGN)) /* Class DCE */
                 DceDeleteClipRgn(pDCE);
              // Update and reset Vis Rgn and clear the dirty bit.
              // Should release VisRgn than reset it to default.
              DceUpdateVisRgn(pDCE, Window, pDCE->DCXFlags);
              pDCE->DCXFlags = DCX_DCEEMPTY|DCX_CACHE;
              pDCE->hwndCurrent = 0;
              pDCE->pwndOrg = pDCE->pwndClip = NULL;

              TRACE("POWNED DCE going Cheap!! DCX_CACHE!! hDC-> %p \n",
                    pDCE->hDC);
              if (!GreSetDCOwner( pDCE->hDC, GDI_OBJ_HMGR_NONE))
              {
                  ERR("Fail Owner Switch hDC-> %p \n", pDCE->hDC);
                  break;
              }
              /* Do not change owner so thread can clean up! */
           }
           else if (Window->pcls->style & CS_OWNDC) /* Owned DCE */
           {
              DceFreeDCE(pDCE, FALSE);
              continue;
           }
           else
           {
              ERR("Not POWNED or CLASSDC hwndCurrent -> %p \n",
                  pDCE->hwndCurrent);
              // ASSERT(FALSE); /* bug 5320 */
           }
        }
        else
        {
           if (pDCE->DCXFlags & DCX_DCEBUSY) /* Shared cache DCE */
           {
              /* FIXME: AFAICS we are doing the right thing here so
               * this should be a TRACE. But this is best left as an ERR
               * because the 'application error' is likely to come from
               * another part of Wine (i.e. it's our fault after all).
               * We should change this to TRACE when ReactOS is more stable
               * (for 1.0?).
               */
              ERR("[%p] GetDC() without ReleaseDC()!\n", UserHMGetHandle(Window));
              DceReleaseDC(pDCE, FALSE);
           }
           pDCE->DCXFlags |= DCX_DCEEMPTY;
           pDCE->hwndCurrent = 0;
           pDCE->pwndOrg = pDCE->pwndClip = NULL;
        }
     }
  }
}

void FASTCALL
DceFreeClassDCE(PDCE pdceClass)
{
   PDCE pDCE;
   PLIST_ENTRY ListEntry;

   ListEntry = LEDce.Flink;
   while (ListEntry != &LEDce)
   {
       pDCE = CONTAINING_RECORD(ListEntry, DCE, List);
       ListEntry = ListEntry->Flink;
       if (pDCE == pdceClass)
       {
          DceFreeDCE(pDCE, TRUE); // Might have gone cheap!
       }
   }
}

void FASTCALL
DceFreeThreadDCE(PTHREADINFO pti)
{
   PDCE pDCE;
   PLIST_ENTRY ListEntry;

   ListEntry = LEDce.Flink;
   while (ListEntry != &LEDce)
   {
       pDCE = CONTAINING_RECORD(ListEntry, DCE, List);
       ListEntry = ListEntry->Flink;
       if (pDCE->ptiOwner == pti)
       {
          if (pDCE->DCXFlags & DCX_CACHE)
          {
             DceFreeDCE(pDCE, TRUE);
          }
       }
   }
}

VOID FASTCALL
DceEmptyCache(VOID)
{
   PDCE pDCE;
   PLIST_ENTRY ListEntry;

   ListEntry = LEDce.Flink;
   while (ListEntry != &LEDce)
   {
      pDCE = CONTAINING_RECORD(ListEntry, DCE, List);
      ListEntry = ListEntry->Flink;
      DceFreeDCE(pDCE, TRUE);
   }
}

VOID FASTCALL
DceResetActiveDCEs(PWND Window)
{
   DCE *pDCE;
   PDC dc;
   PWND CurrentWindow;
   INT DeltaX;
   INT DeltaY;
   PLIST_ENTRY ListEntry;
   PWND Root;
   LONG RootX, RootY;

   if (NULL == Window)
   {
      return;
   }

   ListEntry = LEDce.Flink;
   while (ListEntry != &LEDce)
   {
      pDCE = CONTAINING_RECORD(ListEntry, DCE, List);
      ListEntry = ListEntry->Flink;
      if (0 == (pDCE->DCXFlags & (DCX_DCEEMPTY|DCX_INDESTROY)))
      {
         if (UserHMGetHandle(Window) == pDCE->hwndCurrent)
         {
            CurrentWindow = Window;
         }
         else
         {
            if (!pDCE->hwndCurrent)
               CurrentWindow = NULL;
            else
               CurrentWindow = UserGetWindowObject(pDCE->hwndCurrent);
            if (NULL == CurrentWindow)
            {
               continue;
            }
         }

         /* A record whose window let go of its surface: this DC draws on the screen again; a pending binding is tried again */
         if (pDCE->pRedir && !UserRedirWindow(pDCE->pRedir))
            DceRedirBind(pDCE, NULL);
         else if (pDCE->RedirFlags & DCE_REDIR_RETRY)
            DceRedirBind(pDCE, pDCE->pRedir);
         Root = pDCE->pRedir ? UserRedirWindow(pDCE->pRedir) : NULL;
         RootX = Root ? Root->rcWindow.left : 0;
         RootY = Root ? Root->rcWindow.top : 0;

         /* A DC that another process is using right now is owned by that process.
          * Its visible region must follow this window as well, or the process paints
          * over the window that moved over it. DC_LockDcAnyOwner also tells a handle
          * that is gone, which GreIsHandleValid would not for a foreign DC. */
         if ((dc = DC_LockDcAnyOwner(pDCE->hDC)) == NULL)
         {
            continue;
         }
         if (Window == CurrentWindow || IntIsChildWindow(Window, CurrentWindow))
         {
            if (pDCE->DCXFlags & DCX_WINDOW)
            {
               DeltaX = CurrentWindow->rcWindow.left - RootX - dc->ptlDCOrig.x;
               DeltaY = CurrentWindow->rcWindow.top - RootY - dc->ptlDCOrig.y;
               dc->ptlDCOrig.x = CurrentWindow->rcWindow.left - RootX;
               dc->ptlDCOrig.y = CurrentWindow->rcWindow.top - RootY;
            }
            else
            {
               DeltaX = CurrentWindow->rcClient.left - RootX - dc->ptlDCOrig.x;
               DeltaY = CurrentWindow->rcClient.top - RootY - dc->ptlDCOrig.y;
               dc->ptlDCOrig.x = CurrentWindow->rcClient.left - RootX;
               dc->ptlDCOrig.y = CurrentWindow->rcClient.top - RootY;
            }

            if (NULL != dc->dclevel.prgnClip)
            {
               REGION_bOffsetRgn(dc->dclevel.prgnClip, DeltaX, DeltaY);
               dc->fs |= DC_DIRTY_RAO;
            }
            if (NULL != pDCE->hrgnClip)
            {
               NtGdiOffsetRgn(pDCE->hrgnClip, DeltaX, DeltaY);
            }
         }
         DC_UnlockDc(dc);

         DceUpdateVisRgn(pDCE, CurrentWindow, pDCE->DCXFlags);
         IntGdiSetHookFlags(pDCE->hDC, DCHF_VALIDATEVISRGN);
      }
   }
}

HWND FASTCALL
IntWindowFromDC(HDC hDc)
{
  DCE *Dce;
  PLIST_ENTRY ListEntry;
  HWND Ret = NULL;

  ListEntry = LEDce.Flink;
  while (ListEntry != &LEDce)
  {
      Dce = CONTAINING_RECORD(ListEntry, DCE, List);
      ListEntry = ListEntry->Flink;
      if (Dce->hDC == hDc)
      {
         if (Dce->DCXFlags & DCX_INDESTROY)
            Ret = NULL;
         else
         {
            /* GetDC(NULL) returns the cached, windowless screen DC (hwndCurrent == NULL).
             * On Windows that DC belongs to the desktop window, so WindowFromDC() returns
             * it. Report the desktop window here too: ANGLE (Chromium/Electron) validates
             * an HDC native-display via WindowFromDC() and rejects it when NULL, which was
             * failing EGL/GL display bring-up under the compositor. Window DCs are
             * unaffected; memory DCs are not in this list and still yield NULL. */
            /* (GetDesktopWindow() of the caller: the desktop window of its own desktop) */
            if (Dce->hwndCurrent)
               Ret = Dce->hwndCurrent;
            else
            {
               PWND pwndDesk = UserGetThreadDesktopWindow();
               Ret = pwndDesk ? UserHMGetHandle(pwndDesk) : NULL;
            }
         }
         break;
      }
  }
  return Ret;
}

INT FASTCALL
UserReleaseDC(PWND Window, HDC hDc, BOOL EndPaint)
{
  PDCE dce;
  PLIST_ENTRY ListEntry;
  INT nRet = 0;
  BOOL Hit = FALSE;

  TRACE("%p %p\n", Window, hDc);
  ListEntry = LEDce.Flink;
  while (ListEntry != &LEDce)
  {
     dce = CONTAINING_RECORD(ListEntry, DCE, List);
     ListEntry = ListEntry->Flink;
     if (dce->hDC == hDc)
     {
        Hit = TRUE;
        break;
     }
  }

  if ( Hit && (dce->DCXFlags & DCX_DCEBUSY))
  {
     nRet = DceReleaseDC(dce, EndPaint);
  }

  return nRet;
}

HDC FASTCALL
UserGetWindowDC(PWND Wnd)
{
  return UserGetDCEx(Wnd, 0, DCX_USESTYLE | DCX_WINDOW);
}

HWND FASTCALL
UserGethWnd( HDC hdc, PWNDOBJ *pwndo)
{
  EWNDOBJ* Clip;
  PWND Wnd;
  HWND hWnd;

  hWnd = IntWindowFromDC(hdc);

  if (hWnd && (Wnd = UserGetWindowObject(hWnd)))
  {
     Clip = (EWNDOBJ*)UserGetProp(Wnd, AtomWndObj, TRUE);

     if ( Clip && Clip->Hwnd == hWnd )
     {
        if (pwndo) *pwndo = (PWNDOBJ)Clip;
     }
  }
  return hWnd;
}

HDC APIENTRY
NtUserGetDCEx(HWND hWnd OPTIONAL, HANDLE ClipRegion, ULONG Flags)
{
  PWND Wnd=NULL;
  HDC Ret = NULL;

  TRACE("Enter NtUserGetDCEx: hWnd %p, ClipRegion %p, Flags %x.\n",
      hWnd, ClipRegion, Flags);
  UserEnterExclusive();

  if (hWnd && !(Wnd = UserGetWindowObject(hWnd)))
  {
      goto Exit; // Return NULL
  }
  Ret = UserGetDCEx(Wnd, ClipRegion, Flags);

Exit:
  TRACE("Leave NtUserGetDCEx, ret=%p\n", Ret);
  UserLeave();
  return Ret;
}

/*
 * NtUserGetWindowDC
 *
 * The NtUserGetWindowDC function retrieves the device context (DC) for the
 * entire window, including title bar, menus, and scroll bars. A window device
 * context permits painting anywhere in a window, because the origin of the
 * device context is the upper-left corner of the window instead of the client
 * area.
 *
 * Status
 *    @implemented
 */
HDC APIENTRY
NtUserGetWindowDC(HWND hWnd)
{
  return NtUserGetDCEx(hWnd, 0, DCX_USESTYLE | DCX_WINDOW);
}

HDC APIENTRY
NtUserGetDC(HWND hWnd)
{
 TRACE("NtUGetDC -> %p:%x\n", hWnd, !hWnd ? DCX_CACHE | DCX_WINDOW : DCX_USESTYLE);

  return NtUserGetDCEx(hWnd, NULL, NULL == hWnd ? DCX_CACHE | DCX_WINDOW : DCX_USESTYLE);
}

/*!
 * Select logical palette into device context.
 * \param	hDC 				handle to the device context
 * \param	hpal				handle to the palette
 * \param	ForceBackground 	If this value is FALSE the logical palette will be copied to the device palette only when the application
 * 								is in the foreground. If this value is TRUE then map the colors in the logical palette to the device
 * 								palette colors in the best way.
 * \return	old palette
 *
 * \todo	implement ForceBackground == TRUE
*/
HPALETTE
APIENTRY
NtUserSelectPalette(HDC  hDC,
              HPALETTE  hpal,
       BOOL  ForceBackground)
{
    HPALETTE oldPal;
    UserEnterExclusive();
    // Implement window checks
    oldPal = GdiSelectPalette( hDC, hpal, ForceBackground);
    UserLeave();
    return oldPal;
}

/* EOF */
