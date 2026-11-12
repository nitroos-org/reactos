/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS Win32k subsystem
 * PURPOSE:          Layered window support
 * FILE:             win32ss/user/ntuser/layered.c
 * PROGRAMER:
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(UserMisc);


typedef struct _LRD_PROP
{ 
   COLORREF Key;
   BYTE     Alpha;
   BYTE     is_Layered;
   BYTE     NoUsed[2];
   DWORD    Flags;
} LRD_PROP, *PLRD_PROP;

BOOL FASTCALL
GetLayeredStatus(PWND pWnd)
{
   PLRD_PROP pLrdProp = UserGetProp(pWnd, AtomLayer, TRUE);
   if (pLrdProp)
   {
      return pLrdProp->is_Layered;
   }
   return FALSE;
}

/* The SetLayeredWindowAttributes values (FALSE: not set) */
BOOL FASTCALL
IntGetLayeredAttributes(PWND pWnd, COLORREF *pcrKey, BYTE *pbAlpha, DWORD *pdwFlags)
{
   PLRD_PROP pLrdProp = UserGetProp(pWnd, AtomLayer, TRUE);
   if (!pLrdProp || !pLrdProp->is_Layered)
      return FALSE;
   *pcrKey = pLrdProp->Key;
   *pbAlpha = pLrdProp->Alpha;
   *pdwFlags = pLrdProp->Flags;
   return TRUE;
}

BOOL FASTCALL
SetLayeredStatus(PWND pWnd, BYTE set)
{
   PLRD_PROP pLrdProp = UserGetProp(pWnd, AtomLayer, TRUE);
   if (pLrdProp)
   {
      pLrdProp->is_Layered = set;
      return TRUE;
   }
   return FALSE;
}

BOOL FASTCALL
IntSetLayeredWindowAttributes(PWND pWnd,
                              COLORREF crKey,
                              BYTE bAlpha,
                              DWORD dwFlags)
{
   PLRD_PROP pLrdProp;
   INT was_Layered;

   if (!(pWnd->ExStyle & WS_EX_LAYERED) )
   {
      ERR("Not a Layered Window!\n");
      return FALSE;
   }

   pLrdProp = UserGetProp(pWnd, AtomLayer, TRUE);

   if (!pLrdProp)
   {
      pLrdProp = ExAllocatePoolWithTag(PagedPool, sizeof(LRD_PROP), USERTAG_REDIRECT);
      if (pLrdProp == NULL)
      {
         ERR("failed to allocate LRD_PROP\n");
         return FALSE;
      }
      RtlZeroMemory(pLrdProp, sizeof(LRD_PROP));
      UserSetProp(pWnd, AtomLayer, (HANDLE)pLrdProp, TRUE);
   }

   if (pLrdProp)
   {
      was_Layered = pLrdProp->is_Layered;

      pLrdProp->Key = crKey;

      if (dwFlags & LWA_ALPHA)
      {
         pLrdProp->Alpha = bAlpha;
      }
      else
      {
         if (!pLrdProp->is_Layered) pLrdProp->Alpha = 0;
      }

      pLrdProp->Flags = dwFlags;

      pLrdProp->is_Layered = 1;

      /* Level 2 (redir.c): the compositor applies the alpha and the colour key to what the window paints */
      UserRedirLayeredSet(pWnd, !was_Layered);

      if (!was_Layered)
         co_UserRedrawWindow(pWnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME );
   }
   /* Levels 0 and 1: nothing applies them (no backing store); level 2 composes them */
   return TRUE;
}

/*
 * Blend the source (hdcBuffer, a copy of the caller's bitmap at 0,0) over the snapshot of what is below the window
 * (glassblt.c), then replace the window's pixels with the result. The blend is made off screen, so the window is
 * never shown half way. Returns FALSE when the snapshot is not available; nothing is drawn then.
 */
static BOOL
IntUlwBlendOnBackdrop(PWND pWnd,
                      HDC hdc,
                      HDC hdcBuffer,
                      const RECT *Rect,
                      BLENDFUNCTION blend)
{
   LONG cx = Rect->right - Rect->left, cy = Rect->bottom - Rect->top;
   HDC hdcWork;
   HBITMAP hbmWork, hOldWork = NULL;
   SURFACE *psurf;
   BOOL ok = FALSE, haveBase = FALSE;

   hdcWork = NtGdiCreateCompatibleDC(hdc);
   hbmWork = NtGdiCreateCompatibleBitmap(hdc, cx, cy);
   if (hdcWork && hbmWork)
      hOldWork = (HBITMAP)NtGdiSelectBitmap(hdcWork, hbmWork);
   if (hOldWork)
   {
      psurf = SURFACE_ShareLockSurface(hbmWork);
      if (psurf)
      {
         haveBase = GlassBackdropCopyTo(UserHMGetHandle(pWnd), (PRECTL)&pWnd->rcWindow, psurf);
         SURFACE_ShareUnlockSurface(psurf);
      }
   }
   if (haveBase &&
       NtGdiAlphaBlend(hdcWork, 0, 0, cx, cy, hdcBuffer, 0, 0, cx, cy, blend, 0) &&
       NtGdiBitBlt(hdc, 0, 0, cx, cy, hdcWork, 0, 0, SRCCOPY, 0, 0))
   {
      ok = TRUE;
   }

   if (hOldWork) NtGdiSelectBitmap(hdcWork, hOldWork);
   if (hbmWork) GreDeleteObject(hbmWork);
   if (hdcWork) IntGdiDeleteDC(hdcWork, FALSE);
   return ok;
}

BOOL FASTCALL
IntUpdateLayeredWindowI( PWND pWnd,
                         UPDATELAYEREDWINDOWINFO *info )
{
   PWND Parent;
   RECT Window, Client;
   RECTL OldWindow = pWnd->rcWindow;
   BOOL Moved = FALSE, PointerCrossed = FALSE, UseBackdrop = FALSE;
   /* Level 2 (redir.c): a top-level window keeps the content in its surface, composed with what is below
      (decided once the new size is known: a window that cannot have a surface keeps the snapshot path) */
   BOOL Redirect = FALSE;
   RECT NewRect = { 0 };
   SIZE Offset;
   BOOL ret = FALSE;
   DWORD flags = SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOREDRAW | SWP_DEFERERASE;
   USER_REFERENCE_ENTRY Ref;

   Window = pWnd->rcWindow;
   Client = pWnd->rcClient;

   Parent = pWnd->spwndParent;
   if (pWnd->style & WS_CHILD && Parent)
   {
      RECTL_vOffsetRect(&Window, - Parent->rcClient.left, - Parent->rcClient.top);
      RECTL_vOffsetRect(&Client, - Parent->rcClient.left, - Parent->rcClient.top);
   }

   if (info->pptDst)
   {
      Offset.cx = info->pptDst->x - Window.left;
      Offset.cy = info->pptDst->y - Window.top;
      RECTL_vOffsetRect( &Client, Offset.cx, Offset.cy );
      RECTL_vOffsetRect( &Window, Offset.cx, Offset.cy );
      if (Offset.cx || Offset.cy)
         flags &= ~SWP_NOMOVE;
   }
   if (info->psize)
   {
      Offset.cx = info->psize->cx - (Window.right  - Window.left);
      Offset.cy = info->psize->cy - (Window.bottom - Window.top);
      if (info->psize->cx <= 0 || info->psize->cy <= 0)
      {
          ERR("Update Layered Invalid Parameters\n");
          EngSetLastError( ERROR_INVALID_PARAMETER );
          return FALSE;
      }
      if ((info->dwFlags & ULW_EX_NORESIZE) && (Offset.cx || Offset.cy))
      {
          ERR("Wrong Size\n");
          EngSetLastError( ERROR_INCORRECT_SIZE );
          return FALSE;
      }
      Client.right  += Offset.cx;
      Client.bottom += Offset.cy;
      Window.right  += Offset.cx;
      Window.bottom += Offset.cy;
      if (Offset.cx || Offset.cy)
         flags &= ~SWP_NOSIZE;
   }

   /*
    * Each UpdateLayeredWindow(ULW_ALPHA) replaces the content of the window: the source is blended once with what
    * lies below the window, not with what the window showed after the previous call (nothing keeps the window
    * apart from the screen here). The screen under the window is kept as a snapshot (glassblt.c) that is taken
    * before the window moves onto it or draws. A window that is a child or hidden, or a screen that cannot be captured,
    * leaves the blend on the screen.
    */
   Redirect = UserRedirLayeredFits(pWnd, Window.right - Window.left, Window.bottom - Window.top);

   if (!Redirect && (info->dwFlags & ULW_ALPHA) && info->hdcSrc && (pWnd->style & WS_VISIBLE) && !(pWnd->style & WS_CHILD))
   {
      NewRect = Window;
      UseBackdrop = GlassBackdropPrepare(UserHMGetHandle(pWnd), (PRECTL)&NewRect);
   }

   /*
    * The geometry and the content change as one unit, with no callback into
    * user mode in between: UpdateLayeredWindow calls no window procedure (the
    * caller is often a renderer thread that the window's own thread waits
    * for), and a hook run halfway could destroy the window or interleave
    * another update. The notifications follow at the end.
    */
   UserRefObjectCo(pWnd, &Ref);
   if ((flags & (SWP_NOMOVE | SWP_NOSIZE)) != (SWP_NOMOVE | SWP_NOSIZE))
   {
      BOOL ClipSiblings = (pWnd->style & WS_CLIPSIBLINGS) ? TRUE : FALSE;
      PREGION VisBefore = VIS_ComputeVisibleRegion(pWnd, FALSE, FALSE, ClipSiblings);
      BOOL PointerWasIn = IntPtInWindow(pWnd, gpsi->ptCursor.x, gpsi->ptCursor.y);

      /* It fails only for a window that no longer exists: nothing is drawn onto it */
      Moved = co_WinPosSetWindowPosEx(pWnd, 0, Window.left, Window.top, Window.right - Window.left, Window.bottom - Window.top, flags, TRUE);
      if (!Moved)
      {
         if (VisBefore) REGION_Delete(VisBefore);
         goto Exit;
      }
      PointerCrossed = (PointerWasIn != IntPtInWindow(pWnd, gpsi->ptCursor.x, gpsi->ptCursor.y));

      /* Repaint what the window really uncovered (window region included): parent and siblings */
      if (VisBefore)
      {
         PREGION VisAfter = VIS_ComputeVisibleRegion(pWnd, FALSE, FALSE, ClipSiblings);
         INT Type = VisAfter ? IntGdiCombineRgn(VisBefore, VisBefore, VisAfter, RGN_DIFF) : REGION_Complexity(VisBefore);
         if (Type != ERROR && Type != NULLREGION)
         {
            REGION_bOffsetRgn(VisBefore, -pWnd->rcWindow.left, -pWnd->rcWindow.top);
            co_VIS_WindowLayoutChanged(pWnd, VisBefore);
         }
         if (VisAfter) REGION_Delete(VisAfter);
         REGION_Delete(VisBefore);
      }
   }

   if (Redirect &&
       UserRedirUpdateLayered(pWnd, &OldWindow, info->hdcSrc, info->pptSrc, info->prcDirty, info->pblend,
                              info->crKey, info->dwFlags, &ret))
   {
      /* Done in the window's surface */
   }
   else if (info->hdcSrc)
   {
      HDC hdc, hdcBuffer;
      BOOL bOwnDc;
      RECT Rect;
      BLENDFUNCTION blend = { AC_SRC_OVER, 0, 255, 0 };
      COLORREF color_key = (info->dwFlags & ULW_COLORKEY) ? info->crKey : CLR_INVALID;
      HBITMAP hOldBitmap, hOldBitmap1, hbmSrc, hbmDst;
      DIBSECTION dibs;

      /* Level 2, no surface after all (no memory): a snapshot taken now, as at level 1 */
      if (Redirect && !UseBackdrop && (info->dwFlags & ULW_ALPHA) && (pWnd->style & WS_VISIBLE) && !(pWnd->style & WS_CHILD))
      {
         NewRect = pWnd->rcWindow;
         UseBackdrop = GlassBackdropPrepare(UserHMGetHandle(pWnd), (PRECTL)&NewRect);
      }

      Rect = Window;

      RECTL_vOffsetRect( &Rect, -Window.left, -Window.top );

      TRACE("H %d W %d\n",Rect.bottom - Rect.top,Rect.right - Rect.left);

      /* hdcDst is the screen DC, for palette matching only: with a snapshot the window's own DC is drawn */
      bOwnDc = !info->hdcDst || UseBackdrop;
      if (bOwnDc) hdc = UserGetDCEx(pWnd, NULL, DCX_USESTYLE);
      else hdc = info->hdcDst;

      hbmSrc = NtGdiCreateCompatibleBitmap(info->hdcSrc, Rect.right - Rect.left, Rect.bottom - Rect.top);
      hbmDst = NtGdiCreateCompatibleBitmap(info->hdcSrc, Rect.right - Rect.left, Rect.bottom - Rect.top);

      GreGetObject(hbmSrc, sizeof(DIBSECTION), &dibs);

      TRACE("Source Bitmap bc %d\n",dibs.dsBmih.biBitCount);

      hdcBuffer = NtGdiCreateCompatibleDC(hdc);

      hOldBitmap = (HBITMAP)NtGdiSelectBitmap(hdcBuffer, hbmSrc);
      hOldBitmap1 = (HBITMAP)NtGdiSelectBitmap(hdc, hbmDst);

      NtGdiStretchBlt( hdcBuffer,
                       Rect.left,
                       Rect.top,
                       Rect.right - Rect.left,
                       Rect.bottom - Rect.top,
                       info->hdcSrc,
                       Rect.left + (info->pptSrc ? info->pptSrc->x : 0),
                       Rect.top  + (info->pptSrc ? info->pptSrc->y : 0),
                       Rect.right - Rect.left,
                       Rect.bottom - Rect.top,
                       SRCCOPY,
                       color_key );

      // Need to test this, Dirty before or after StretchBlt?
      if (info->prcDirty)
      {
         ERR("prcDirty\n");
         RECTL_bIntersectRect( &Rect, &Rect, info->prcDirty );
         NtGdiPatBlt( hdc, Rect.left, Rect.top, Rect.right - Rect.left, Rect.bottom - Rect.top, BLACKNESS );
      }

      if (info->dwFlags & ULW_ALPHA)
      {
         blend = *info->pblend;
         TRACE("ULW_ALPHA bop %d Alpha %d aF %d\n", blend.BlendOp, blend.SourceConstantAlpha, blend.AlphaFormat);
      }

      /* Onto a copy of what is below the window, else (no snapshot) onto the screen */
      ret = UseBackdrop && IntUlwBlendOnBackdrop(pWnd, hdc, hdcBuffer, &Rect, blend);
      if (!ret)
         ret = NtGdiAlphaBlend( hdc,
                                Rect.left,
                                Rect.top,
                                Rect.right - Rect.left,
                                Rect.bottom - Rect.top,
                                hdcBuffer,
                                Rect.left + (info->pptSrc ? info->pptSrc->x : 0),
                                Rect.top  + (info->pptSrc ? info->pptSrc->y : 0),
                                Rect.right - Rect.left,
                                Rect.bottom - Rect.top,
                                blend,
                                0);

      NtGdiSelectBitmap(hdc, hOldBitmap1);
      NtGdiSelectBitmap(hdcBuffer, hOldBitmap);
      if (hbmSrc) GreDeleteObject(hbmSrc);
      if (hbmDst) GreDeleteObject(hbmDst);
      if (hdcBuffer) IntGdiDeleteDC(hdcBuffer, FALSE);
      if (bOwnDc) UserReleaseDC(pWnd, hdc, FALSE);
   }
   else
      ret = TRUE;

   /* Level 2: it has had content from UpdateLayeredWindow (also drawn on the screen, without a surface) */
   if (ret && info->hdcSrc)
      UserRedirUlwSeen(pWnd);

   if (Moved)
      co_WinPosNoMessagesNotify(pWnd, PointerCrossed);
Exit:
   UserDerefObjectCo(pWnd);
   return ret;
}


/*
 * @implemented
 */
BOOL
APIENTRY
NtUserGetLayeredWindowAttributes(
    HWND hwnd,
    COLORREF *pcrKey,
    BYTE *pbAlpha,
    DWORD *pdwFlags)
{
   PLRD_PROP pLrdProp;
   PWND pWnd;
   BOOL Ret = FALSE;

   TRACE("Enter NtUserGetLayeredWindowAttributes\n");
   UserEnterShared();

   if (!(pWnd = UserGetWindowObject(hwnd)) ||
       !(pWnd->ExStyle & WS_EX_LAYERED) )
   {
      ERR("Not a Layered Window!\n");
      goto Exit;
   }

   pLrdProp = UserGetProp(pWnd, AtomLayer, TRUE);

   if (!pLrdProp)
   {
      TRACE("No Prop!\n");
      goto Exit;
   }

   if (pLrdProp->is_Layered == 0)
   {
      goto Exit;
   }

   _SEH2_TRY
   {
      if (pcrKey)
      {
          ProbeForWrite(pcrKey, sizeof(*pcrKey), 1);
          *pcrKey = pLrdProp->Key;
      }
      if (pbAlpha)
      {
          ProbeForWrite(pbAlpha, sizeof(*pbAlpha), 1);
          *pbAlpha = pLrdProp->Alpha;
      }
      if (pdwFlags)
      {
          ProbeForWrite(pdwFlags, sizeof(*pdwFlags), 1);
          *pdwFlags = pLrdProp->Flags;
      }
   }
   _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
   {
      SetLastNtError(_SEH2_GetExceptionCode());
      _SEH2_YIELD(goto Exit);
   }
   _SEH2_END;

   Ret = TRUE;

Exit:
   TRACE("Leave NtUserGetLayeredWindowAttributes, ret=%i\n", Ret);
   UserLeave();
   return Ret;
}

/*
 * @implemented
 */
BOOL APIENTRY
NtUserSetLayeredWindowAttributes(HWND hwnd,
			   COLORREF crKey,
			   BYTE bAlpha,
			   DWORD dwFlags)
{
   PWND pWnd;
   BOOL Ret = FALSE;

   TRACE("Enter NtUserSetLayeredWindowAttributes\n");
   UserEnterExclusive();

   if (!(pWnd = UserGetWindowObject(hwnd)) ||
       !(pWnd->ExStyle & WS_EX_LAYERED) )
   {
      ERR("Not a Layered Window!\n");
      goto Exit;
   }

   Ret = IntSetLayeredWindowAttributes(pWnd, crKey, bAlpha, dwFlags);
Exit:
   TRACE("Leave NtUserSetLayeredWindowAttributes, ret=%i\n", Ret);
   UserLeave();
   return Ret;
}

/*
 * @implemented
 */
BOOL
APIENTRY
NtUserUpdateLayeredWindow(
   HWND hwnd,
   HDC hdcDst,
   POINT *pptDst,
   SIZE *psize,
   HDC hdcSrc,
   POINT *pptSrc,
   COLORREF crKey,
   BLENDFUNCTION *pblend,
   DWORD dwFlags,
   RECT *prcDirty)
{
   UPDATELAYEREDWINDOWINFO info;
   POINT Dst, Src; 
   SIZE Size;
   RECT Dirty;
   BLENDFUNCTION blend = { AC_SRC_OVER, 0, 255, 0 };
   PWND pWnd;
   BOOL Ret = FALSE;

   TRACE("Enter NtUserUpdateLayeredWindow\n");
   UserEnterExclusive();

   if (!(pWnd = UserGetWindowObject(hwnd)))
   {
      goto Exit;
   }

   _SEH2_TRY
   {
      if (pptDst)
      {
         ProbeForRead(pptDst, sizeof(POINT), 1);
         Dst = *pptDst;
      }
      if (pptSrc)
      {
         ProbeForRead(pptSrc, sizeof(POINT), 1);
         Src = *pptSrc;
      }
      if (psize)
      {
         ProbeForRead(psize, sizeof(SIZE), 1);
         Size = *psize;
      }
      if (pblend)
      {
         ProbeForRead(pblend, sizeof(BLENDFUNCTION), 1);
         blend = *pblend;
      }
      if (prcDirty)
      {
         ProbeForRead(prcDirty, sizeof(RECT), 1);
         Dirty = *prcDirty;
      }
   }
   _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
   {
      EngSetLastError( ERROR_INVALID_PARAMETER );
      _SEH2_YIELD(goto Exit);
   }
   _SEH2_END;

   if ( GetLayeredStatus(pWnd) ||
        dwFlags & ~(ULW_COLORKEY | ULW_ALPHA | ULW_OPAQUE | ULW_EX_NORESIZE) ||
       !(pWnd->ExStyle & WS_EX_LAYERED) )
   {
      ERR("Layered Window Invalid Parameters\n");
      EngSetLastError( ERROR_INVALID_PARAMETER );
      goto Exit;
   }

   info.cbSize   = sizeof(info);
   info.hdcDst   = hdcDst;
   info.pptDst   = pptDst? &Dst : NULL;
   info.psize    = psize ? &Size : NULL;
   info.hdcSrc   = hdcSrc;
   info.pptSrc   = pptSrc ? &Src : NULL;
   info.crKey    = crKey;
   info.pblend   = &blend;
   info.dwFlags  = dwFlags;
   info.prcDirty = prcDirty ? &Dirty : NULL;
   Ret = IntUpdateLayeredWindowI( pWnd, &info );
Exit:
   TRACE("Leave NtUserUpdateLayeredWindow, ret=%i\n", Ret);
   UserLeave();
   return Ret;
}

/* EOF */
