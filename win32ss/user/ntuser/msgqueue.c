/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS Win32k subsystem
 * PURPOSE:          Message queues
 * FILE:             win32ss/user/ntuser/msgqueue.c
 * PROGRAMER:        Casper S. Hornstrup (chorns@users.sourceforge.net)
                     Alexandre Julliard
                     Maarten Lankhorst
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(UserMsgQ);

/* GLOBALS *******************************************************************/

static PPAGED_LOOKASIDE_LIST pgMessageLookasideList;
static PPAGED_LOOKASIDE_LIST pgSendMsgLookasideList;
INT PostMsgCount = 0;
INT SendMsgCount = 0;
PUSER_MESSAGE_QUEUE gpqCursor;
ULONG_PTR gdwMouseMoveExtraInfo = 0;
DWORD gdwMouseMoveTimeStamp = 0;
LIST_ENTRY usmList;

/* FUNCTIONS *****************************************************************/

CODE_SEG("INIT")
NTSTATUS
NTAPI
MsqInitializeImpl(VOID)
{
   // Setup Post Messages
   pgMessageLookasideList = ExAllocatePoolWithTag(NonPagedPool, sizeof(PAGED_LOOKASIDE_LIST), TAG_USRMSG);
   if (!pgMessageLookasideList)
      return STATUS_NO_MEMORY;
   ExInitializePagedLookasideList(pgMessageLookasideList,
                                  NULL,
                                  NULL,
                                  0,
                                  sizeof(USER_MESSAGE),
                                  TAG_USRMSG,
                                  256);
   // Setup Send Messages
   pgSendMsgLookasideList = ExAllocatePoolWithTag(NonPagedPool, sizeof(PAGED_LOOKASIDE_LIST), TAG_USRMSG);
   if (!pgSendMsgLookasideList)
      return STATUS_NO_MEMORY;
   ExInitializePagedLookasideList(pgSendMsgLookasideList,
                                  NULL,
                                  NULL,
                                  0,
                                  sizeof(USER_SENT_MESSAGE),
                                  TAG_USRMSG,
                                  16);

   InitializeListHead(&usmList);

   return(STATUS_SUCCESS);
}

PWND FASTCALL
IntTopLevelWindowFromPoint(INT x, INT y)
{
    PWND pWnd, pwndDesktop;

    /* Get the desktop window */
    pwndDesktop = UserGetDesktopWindow();
    if (!pwndDesktop)
        return NULL;

    /* Loop all top level windows */
    for (pWnd = pwndDesktop->spwndChild;
         pWnd != NULL;
         pWnd = pWnd->spwndNext)
    {
        if (pWnd->state2 & WNDS2_INDESTROY || pWnd->state & WNDS_DESTROYED)
        {
            TRACE("The Window is in DESTROY!\n");
            continue;
        }

        if ((pWnd->style & WS_VISIBLE) &&
            (pWnd->ExStyle & (WS_EX_LAYERED|WS_EX_TRANSPARENT)) != (WS_EX_LAYERED|WS_EX_TRANSPARENT) &&
            IntPtInWindow(pWnd, x, y))
            return pWnd;
    }

    /* Window has not been found */
    return pwndDesktop;
}

PCURICON_OBJECT
FASTCALL
UserSetCursor(
    PCURICON_OBJECT NewCursor,
    BOOL ForceChange)
{
    PCURICON_OBJECT OldCursor;
    HDC hdcScreen;
    PTHREADINFO pti;
    PUSER_MESSAGE_QUEUE MessageQueue;
    PWND pWnd;

    pti = PsGetCurrentThreadWin32Thread();
    MessageQueue = pti->MessageQueue;

    OldCursor = MessageQueue->CursorObject;

    /* Check if cursors are different */
    if (OldCursor == NewCursor)
        return OldCursor;

    /* Update cursor for this message queue */
    MessageQueue->CursorObject = NewCursor;

    /* If cursor is not visible we have nothing to do */
    if (MessageQueue->iCursorLevel < 0)
        return OldCursor;

    // Fixes the error message "Not the same cursor!".
    if (gpqCursor == NULL)
    {
       gpqCursor = MessageQueue;
    }

    /* Update cursor if this message queue controls it */
    pWnd = IntTopLevelWindowFromPoint(gpsi->ptCursor.x, gpsi->ptCursor.y);
    if (pWnd && pWnd->head.pti->MessageQueue == MessageQueue)
    {
       /* Get the screen DC */
        if (!(hdcScreen = IntGetScreenDC()))
        {
            return NULL;
        }

        if (NewCursor)
        {
            /* Call GDI to set the new screen cursor */
            PCURICON_OBJECT CursorFrame = NewCursor;
            if(NewCursor->CURSORF_flags & CURSORF_ACON)
            {
                FIXME("Should animate the cursor, using only the first frame now.\n");
                CursorFrame = ((PACON)NewCursor)->aspcur[0];
            }
            GreSetPointerShape(hdcScreen,
                               CursorFrame->hbmAlpha ? NULL : NewCursor->hbmMask,
                               CursorFrame->hbmAlpha ? NewCursor->hbmAlpha : NewCursor->hbmColor,
                               CursorFrame->xHotspot,
                               CursorFrame->yHotspot,
                               gpsi->ptCursor.x,
                               gpsi->ptCursor.y,
                               CursorFrame->hbmAlpha ? SPS_ALPHA : 0);
        }
        else /* Note: OldCursor != NewCursor so we have to hide cursor */
        {
            /* Remove the cursor */
            GreMovePointer(hdcScreen, -1, -1);
            TRACE("Removing pointer!\n");
        }
        IntGetSysCursorInfo()->CurrentCursorObject = NewCursor;
    }

    /* Return the old cursor */
    return OldCursor;
}

/* Called from NtUserCallOneParam with Routine ONEPARAM_ROUTINE_SHOWCURSOR
 * User32 macro NtUserShowCursor */
int UserShowCursor(BOOL bShow)
{
    HDC hdcScreen;
    PTHREADINFO pti;
    PUSER_MESSAGE_QUEUE MessageQueue;
    PWND pWnd;

    if (!(hdcScreen = IntGetScreenDC()))
    {
        return -1; /* No mouse */
    }

    pti = PsGetCurrentThreadWin32Thread();
    MessageQueue = pti->MessageQueue;

    /* Update counter */
    MessageQueue->iCursorLevel += bShow ? 1 : -1;
    pti->iCursorLevel += bShow ? 1 : -1;

    /* Check for trivial cases */
    if ((bShow && MessageQueue->iCursorLevel != 0) ||
        (!bShow && MessageQueue->iCursorLevel != -1))
    {
        /* Note: w don't update global info here because it is used only
          internally to check if cursor is visible */
        return MessageQueue->iCursorLevel;
    }

    /* Check if cursor is above window owned by this MessageQueue */
    pWnd = IntTopLevelWindowFromPoint(gpsi->ptCursor.x, gpsi->ptCursor.y);
    if (pWnd && pWnd->head.pti->MessageQueue == MessageQueue)
    {
        if (bShow)
        {
            /* Show the pointer */
            GreMovePointer(hdcScreen, gpsi->ptCursor.x, gpsi->ptCursor.y);
            TRACE("Showing pointer!\n");
        }
        else
        {
            /* Remove the pointer */
            GreMovePointer(hdcScreen, -1, -1);
            TRACE("Removing pointer!\n");
        }

        /* Update global info */
        IntGetSysCursorInfo()->ShowingCursor = MessageQueue->iCursorLevel;
    }

    return MessageQueue->iCursorLevel;
}

DWORD FASTCALL
UserGetKeyState(DWORD dwKey)
{
   DWORD dwRet = 0;
   PTHREADINFO pti;
   PUSER_MESSAGE_QUEUE MessageQueue;

   pti = PsGetCurrentThreadWin32Thread();
   MessageQueue = pti->MessageQueue;

   if (dwKey < 0x100)
   {
       if (IS_KEY_DOWN(MessageQueue->afKeyState, dwKey))
           dwRet |= 0xFF80; // If down, windows returns 0xFF80.
       if (IS_KEY_LOCKED(MessageQueue->afKeyState, dwKey))
           dwRet |= 0x1;
   }
   else
   {
      EngSetLastError(ERROR_INVALID_PARAMETER);
   }
   return dwRet;
}

/* change the input key state for a given key */
static VOID
UpdateKeyState(PUSER_MESSAGE_QUEUE MessageQueue, WORD wVk, BOOL bIsDown)
{
    TRACE("UpdateKeyState wVk: %u, bIsDown: %d\n", wVk, bIsDown);

    if (bIsDown)
    {
        /* If it's first key down event, xor lock bit */
        if (!IS_KEY_DOWN(MessageQueue->afKeyState, wVk))
            SET_KEY_LOCKED(MessageQueue->afKeyState, wVk, !IS_KEY_LOCKED(MessageQueue->afKeyState, wVk));

        SET_KEY_DOWN(MessageQueue->afKeyState, wVk, TRUE);
        MessageQueue->afKeyRecentDown[wVk / 8] |= (1 << (wVk % 8));
    }
    else
        SET_KEY_DOWN(MessageQueue->afKeyState, wVk, FALSE);
}

/* update the input key state for a keyboard message */
static VOID
UpdateKeyStateFromMsg(PUSER_MESSAGE_QUEUE MessageQueue, MSG* msg)
{
    UCHAR key;
    BOOL down = FALSE;

    TRACE("UpdateKeyStateFromMsg message:%u\n", msg->message);

    switch (msg->message)
    {
    case WM_LBUTTONDOWN:
        down = TRUE;
        /* fall through */
    case WM_LBUTTONUP:
        UpdateKeyState(MessageQueue, VK_LBUTTON, down);
        break;
    case WM_MBUTTONDOWN:
        down = TRUE;
        /* fall through */
    case WM_MBUTTONUP:
        UpdateKeyState(MessageQueue, VK_MBUTTON, down);
        break;
    case WM_RBUTTONDOWN:
        down = TRUE;
        /* fall through */
    case WM_RBUTTONUP:
        UpdateKeyState(MessageQueue, VK_RBUTTON, down);
        break;
    case WM_XBUTTONDOWN:
        down = TRUE;
        /* fall through */
    case WM_XBUTTONUP:
        if (msg->wParam == XBUTTON1)
            UpdateKeyState(MessageQueue, VK_XBUTTON1, down);
        else if (msg->wParam == XBUTTON2)
            UpdateKeyState(MessageQueue, VK_XBUTTON2, down);
        break;
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
        down = TRUE;
        /* fall through */
    case WM_KEYUP:
    case WM_SYSKEYUP:
        key = (UCHAR)msg->wParam;
        UpdateKeyState(MessageQueue, key, down);
        switch(key)
        {
        case VK_LCONTROL:
        case VK_RCONTROL:
            down = IS_KEY_DOWN(MessageQueue->afKeyState, VK_LCONTROL) || IS_KEY_DOWN(MessageQueue->afKeyState, VK_RCONTROL);
            UpdateKeyState(MessageQueue, VK_CONTROL, down);
            break;
        case VK_LMENU:
        case VK_RMENU:
            down = IS_KEY_DOWN(MessageQueue->afKeyState, VK_LMENU) || IS_KEY_DOWN(MessageQueue->afKeyState, VK_RMENU);
            UpdateKeyState(MessageQueue, VK_MENU, down);
            break;
        case VK_LSHIFT:
        case VK_RSHIFT:
            down = IS_KEY_DOWN(MessageQueue->afKeyState, VK_LSHIFT) || IS_KEY_DOWN(MessageQueue->afKeyState, VK_RSHIFT);
            UpdateKeyState(MessageQueue, VK_SHIFT, down);
            break;
        }
        break;
    }
}

/*
    Get down key states from the queue of prior processed input message key states.

    This fixes the left button dragging on the desktop and release sticking outline issue.
    USB Tablet pointer seems to stick the most and leaves the box outline displayed.
 */
WPARAM FASTCALL
MsqGetDownKeyState(PUSER_MESSAGE_QUEUE MessageQueue)
{
    WPARAM ret = 0;

    if (gspv.bMouseBtnSwap)
    {
       if (IS_KEY_DOWN(MessageQueue->afKeyState, VK_RBUTTON)) ret |= MK_LBUTTON;
       if (IS_KEY_DOWN(MessageQueue->afKeyState, VK_LBUTTON)) ret |= MK_RBUTTON;
    }
    else
    {
       if (IS_KEY_DOWN(MessageQueue->afKeyState, VK_LBUTTON)) ret |= MK_LBUTTON;
       if (IS_KEY_DOWN(MessageQueue->afKeyState, VK_RBUTTON)) ret |= MK_RBUTTON;
    }

    if (IS_KEY_DOWN(MessageQueue->afKeyState, VK_MBUTTON))  ret |= MK_MBUTTON;
    if (IS_KEY_DOWN(MessageQueue->afKeyState, VK_SHIFT))    ret |= MK_SHIFT;
    if (IS_KEY_DOWN(MessageQueue->afKeyState, VK_CONTROL))  ret |= MK_CONTROL;
    if (IS_KEY_DOWN(MessageQueue->afKeyState, VK_XBUTTON1)) ret |= MK_XBUTTON1;
    if (IS_KEY_DOWN(MessageQueue->afKeyState, VK_XBUTTON2)) ret |= MK_XBUTTON2;
    return ret;
}

HANDLE FASTCALL
IntMsqSetWakeMask(DWORD WakeMask)
{
   PTHREADINFO Win32Thread;
   HANDLE MessageEventHandle;
   DWORD dwFlags = HIWORD(WakeMask);

   Win32Thread = PsGetCurrentThreadWin32Thread();
   if (Win32Thread == NULL || Win32Thread->MessageQueue == NULL)
      return 0;

// Win32Thread->pEventQueueServer; IntMsqSetWakeMask returns Win32Thread->hEventQueueClient
   MessageEventHandle = Win32Thread->hEventQueueClient;

   if (Win32Thread->pcti)
   {
      if ( (Win32Thread->pcti->fsChangeBits & LOWORD(WakeMask)) ||
           ( (dwFlags & MWMO_INPUTAVAILABLE) && (Win32Thread->pcti->fsWakeBits & LOWORD(WakeMask)) ) )
      {
         KeSetEvent(Win32Thread->pEventQueueServer, IO_NO_INCREMENT, FALSE); // Wake it up!
         return MessageEventHandle;
      }
   }

   IdlePing();

   /* The wait is done by the caller, out of reach of win32k: it gets no exemption (see co_MsqMsgWait) */
   if (Win32Thread->pcti && (LOWORD(WakeMask) & QS_INPUT))
      Win32Thread->pcti->timeLastRead = EngGetTickCount32();

   return MessageEventHandle;
}

BOOL FASTCALL
IntMsqClearWakeMask(VOID)
{
   PTHREADINFO Win32Thread;

   Win32Thread = PsGetCurrentThreadWin32Thread();
   if (Win32Thread == NULL || Win32Thread->MessageQueue == NULL)
      return FALSE;
   IdlePong();

   return TRUE;
}

/*
 * MsgWaitForMultipleObjectsEx: the wait for the caller's objects and the queue event. win32k does it so
 * that the "waiting for input" state of the thread (fsWakeMask, which keeps it from counting as hung)
 * lasts exactly as long as the wait: the foreground-idle hook runs before the state is set and before
 * anything is acquired, and the state is cleared, with the read time refreshed, before the thread
 * returns to user mode, so before an APC runs. The wait itself is NtWaitForMultipleObjects on the
 * caller's handle array, so handles, objects and status codes are those of WaitForMultipleObjectsEx.
 */
NTSTATUS FASTCALL
co_MsqMsgWait(PMSGWAITINFO pUserInfo)
{
    PTHREADINFO pti = PsGetCurrentThreadWin32Thread();
    ULONG Count, Flags;
    UINT WakeMask;
    BOOLEAN HasTimeout, WaitForInput;
    NTSTATUS Status;

    if (pti == NULL || pti->MessageQueue == NULL || pti->pcti == NULL)
        return STATUS_INVALID_PARAMETER;

    _SEH2_TRY
    {
        ProbeForWrite(pUserInfo, sizeof(*pUserInfo), sizeof(ULONG));
        Count = pUserInfo->nCount;
        WakeMask = LOWORD(pUserInfo->dwWakeMask);
        Flags = pUserInfo->dwFlags;
        HasTimeout = (pUserInfo->bTimeout != FALSE);
        /* The queue event follows the caller's handles; a count that leaves no room fails in the wait */
        if (Count < MSGWAIT_MAX_OBJECTS)
            pUserInfo->Handles[Count] = pti->hEventQueueClient;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    if ((pti->pcti->fsChangeBits & WakeMask) ||
        ((Flags & MWMO_INPUTAVAILABLE) && (pti->pcti->fsWakeBits & WakeMask)))
    {
        /* Input is already there: the queue event takes part signalled and the thread does not wait for input */
        KeSetEvent(pti->pEventQueueServer, IO_NO_INCREMENT, FALSE);
        WaitForInput = FALSE;
    }
    else
    {
        /* Nothing is held here, so a hook that ends the thread leaves nothing behind */
        IdlePing();
        WaitForInput = TRUE;
        if (WakeMask & QS_INPUT)
            pti->pcti->timeLastRead = EngGetTickCount32();
        pti->pcti->fsWakeMask = WakeMask;
    }

    UserLeaveCo();
    do
    {
        Status = NtWaitForMultipleObjects(Count + 1,
                                          (PHANDLE)pUserInfo->Handles,
                                          (Flags & MWMO_WAITALL) ? WaitAll : WaitAny,
                                          (Flags & MWMO_ALERTABLE) != 0,
                                          HasTimeout ? &pUserInfo->Timeout : NULL);
    }
    while (Status == STATUS_ALERTED && (Flags & MWMO_ALERTABLE));
    UserEnterCo();

    if (WaitForInput)
    {
        if (pti->pcti->fsWakeMask & QS_INPUT)
            pti->pcti->timeLastRead = EngGetTickCount32();
        pti->pcti->fsWakeMask = 0;
    }
    IdlePong();

    return Status;
}

/*
   Due to the uncertainty of knowing what was set in our multilevel message queue,
   and even if the bits are all cleared. The same as cTimers/cPaintsReady.
   I think this is the best solution... (jt) */
VOID FASTCALL
MsqWakeQueue(PTHREADINFO pti, DWORD MessageBits, BOOL KeyEvent)
{
   PUSER_MESSAGE_QUEUE Queue;

   Queue = pti->MessageQueue;

   if (Queue->QF_flags & QF_INDESTROY)
   {
      /* The queue is being torn down: its wake event (pEventQueueServer) may already
         be dereferenced and no thread is left to service it, so signalling it is a
         use-after-free (T131). Drop the wake. */
      ERR("This Message Queue is in Destroy!\n");
      return;
   }
   pti->pcti->fsWakeBits |= MessageBits;
   pti->pcti->fsChangeBits |= MessageBits;

   // Start bit accounting to help clear the main set of bits.
   if (MessageBits & QS_KEY)
   {
      pti->nCntsQBits[QSRosKey]++;
   }
   if (MessageBits & QS_MOUSE)
   {
      if (MessageBits & QS_MOUSEMOVE)   pti->nCntsQBits[QSRosMouseMove]++;
      if (MessageBits & QS_MOUSEBUTTON) pti->nCntsQBits[QSRosMouseButton]++;
   }
   if (MessageBits & QS_POSTMESSAGE) pti->nCntsQBits[QSRosPostMessage]++;
   if (MessageBits & QS_SENDMESSAGE) pti->nCntsQBits[QSRosSendMessage]++;
   if (MessageBits & QS_HOTKEY)      pti->nCntsQBits[QSRosHotKey]++;
   if (MessageBits & QS_EVENT)       pti->nCntsQBits[QSRosEvent]++;
   if (MessageBits & QS_RAWINPUT)    pti->nCntsQBits[QSRosRawInput]++;

   if (KeyEvent)
      KeSetEvent(pti->pEventQueueServer, IO_NO_INCREMENT, FALSE);
}

/* A count that is already zero stays zero, so an extra clear cannot wrap it and leave the bit set for good */
static BOOL FASTCALL
DropQBitCount(DWORD *pCount)
{
   if (*pCount) --*pCount;
   return *pCount == 0;
}

VOID FASTCALL
ClearMsgBitsMask(PTHREADINFO pti, UINT MessageBits)
{
   UINT ClrMask = 0;

   if (MessageBits & QS_KEY)
   {
      if (DropQBitCount(&pti->nCntsQBits[QSRosKey])) ClrMask |= QS_KEY;
   }
   if (MessageBits & QS_MOUSEMOVE)
   {  // Account for tracking mouse moves..
      if (pti->nCntsQBits[QSRosMouseMove])
      {
         pti->nCntsQBits[QSRosMouseMove] = 0; // Throttle down count. Up to > 3:1 entries are ignored.
         ClrMask |= QS_MOUSEMOVE;
      }
   }
   if (MessageBits & QS_MOUSEBUTTON)
   {
      if (DropQBitCount(&pti->nCntsQBits[QSRosMouseButton])) ClrMask |= QS_MOUSEBUTTON;
   }
   if (MessageBits & QS_POSTMESSAGE)
   {
      if (DropQBitCount(&pti->nCntsQBits[QSRosPostMessage])) ClrMask |= QS_POSTMESSAGE;
   }
   if (MessageBits & QS_TIMER) // ReactOS hard coded.
   {  // Handle timer bits here.
      if ( pti->cTimersReady )
      {
         if (--pti->cTimersReady == 0) ClrMask |= QS_TIMER;
      }
   }
   if (MessageBits & QS_PAINT) // ReactOS hard coded.
   {  // Handle paint bits here.
      if ( pti->cPaintsReady )
      {
         if (--pti->cPaintsReady == 0) ClrMask |= QS_PAINT;
      }
   }
   if (MessageBits & QS_SENDMESSAGE)
   {
      if (DropQBitCount(&pti->nCntsQBits[QSRosSendMessage])) ClrMask |= QS_SENDMESSAGE;
   }
   if (MessageBits & QS_HOTKEY)
   {
      if (DropQBitCount(&pti->nCntsQBits[QSRosHotKey])) ClrMask |= QS_HOTKEY;
   }
   if (MessageBits & QS_EVENT)
   {
      if (DropQBitCount(&pti->nCntsQBits[QSRosEvent])) ClrMask |= QS_EVENT;
   }
   if (MessageBits & QS_RAWINPUT)
   {
      if (pti->nCntsQBits[QSRosRawInput] == 0 || --pti->nCntsQBits[QSRosRawInput] == 0) ClrMask |= QS_RAWINPUT;
   }

   /* A posted message sets QS_POSTMESSAGE and QS_ALLPOSTMESSAGE together; the last one out clears both */
   if (ClrMask & QS_POSTMESSAGE) ClrMask |= QS_ALLPOSTMESSAGE;

   pti->pcti->fsWakeBits &= ~ClrMask;
   pti->pcti->fsChangeBits &= ~ClrMask;
}

VOID FASTCALL
MsqIncPaintCountQueue(PTHREADINFO pti)
{
   pti->cPaintsReady++;
   MsqWakeQueue(pti, QS_PAINT, TRUE);
}

VOID FASTCALL
MsqDecPaintCountQueue(PTHREADINFO pti)
{
   ClearMsgBitsMask(pti, QS_PAINT);
}

/*
    Post the move or update the message still pending to be processed.
    Do not overload the queue with mouse move messages.
 */
VOID FASTCALL
MsqPostMouseMove(PTHREADINFO pti, MSG* Msg, LONG_PTR ExtraInfo)
{
    PUSER_MESSAGE Message;
    PLIST_ENTRY ListHead;
    PUSER_MESSAGE_QUEUE MessageQueue = pti->MessageQueue;

    ListHead = &MessageQueue->HardwareMessagesListHead;

    // Do nothing if empty.
    if (!IsListEmpty(ListHead->Flink))
    {
       // Look at the end of the list,
       Message = CONTAINING_RECORD(ListHead->Blink, USER_MESSAGE, ListEntry);

       // If the mouse move message is existing on the list,
       if (Message->Msg.message == WM_MOUSEMOVE)
       {
          // Overwrite the message with updated data!
          Message->Msg = *Msg;

          MsqWakeQueue(pti, QS_MOUSEMOVE, TRUE);
          return;
       }
    }

    MsqPostMessage(pti, Msg, TRUE, QS_MOUSEMOVE, 0, ExtraInfo);
}

/*
    Bring together the mouse move message.
    Named "Coalesce" from Amine email ;^) (jt).
 */
VOID FASTCALL
IntCoalesceMouseMove(PTHREADINFO pti)
{
    MSG Msg;

    // Force time stamp to update, keeping message time in sync.
    if (gdwMouseMoveTimeStamp == 0)
    {
        gdwMouseMoveTimeStamp = EngGetTickCount32();
    }

    // Build mouse move message.
    Msg.hwnd    = NULL;
    Msg.message = WM_MOUSEMOVE;
    Msg.wParam  = 0;
    Msg.lParam  = MAKELONG(gpsi->ptCursor.x, gpsi->ptCursor.y);
    Msg.time    = gdwMouseMoveTimeStamp;
    Msg.pt      = gpsi->ptCursor;

    // Post the move.
    MsqPostMouseMove(pti, &Msg, gdwMouseMoveExtraInfo);

    // Zero the time stamp.
    gdwMouseMoveTimeStamp = 0;

    // Clear flag since the move was posted.
    pti->MessageQueue->QF_flags &= ~QF_MOUSEMOVED;
}

VOID FASTCALL
co_MsqInsertMouseMessage(MSG* Msg, DWORD flags, ULONG_PTR dwExtraInfo, BOOL Hook)
{
   co_MsqInsertMouseMessageEx(Msg, flags, dwExtraInfo, Hook, 0);
}

/* dwHookTime: the time SendInput or mouse_event supplied for the event, for the low-level hook; zero is the time of
   the event itself */
VOID FASTCALL
co_MsqInsertMouseMessageEx(MSG* Msg, DWORD flags, ULONG_PTR dwExtraInfo, BOOL Hook, DWORD dwHookTime)
{
   MSLLHOOKSTRUCT MouseHookData;
//   PDESKTOP pDesk;
   PWND pwnd, pwndDesktop;
   HDC hdcScreen;
   PTHREADINFO pti;
   PUSER_MESSAGE_QUEUE MessageQueue;
   PSYSTEM_CURSORINFO CurInfo;

   Msg->time = EngGetTickCount32();

   RtlZeroMemory(&MouseHookData, sizeof(MouseHookData));
   MouseHookData.pt.x = LOWORD(Msg->lParam);
   MouseHookData.pt.y = HIWORD(Msg->lParam);
   switch (Msg->message)
   {
      case WM_MOUSEWHEEL:
      case WM_MOUSEHWHEEL:
         MouseHookData.mouseData = MAKELONG(0, GET_WHEEL_DELTA_WPARAM(Msg->wParam));
         break;
      case WM_XBUTTONDOWN:
      case WM_XBUTTONUP:
      case WM_XBUTTONDBLCLK:
      case WM_NCXBUTTONDOWN:
      case WM_NCXBUTTONUP:
      case WM_NCXBUTTONDBLCLK:
         MouseHookData.mouseData = MAKELONG(0, HIWORD(Msg->wParam));
         break;
      default:
         MouseHookData.mouseData = 0;
         break;
   }

   MouseHookData.flags = flags; // LLMHF_INJECTED
   MouseHookData.time = dwHookTime ? dwHookTime : Msg->time;
   MouseHookData.dwExtraInfo = dwExtraInfo;

   /* If the hook procedure returned non zero, dont send the message */
   if (Hook)
   {
      if (co_HOOK_CallHooks(WH_MOUSE_LL, HC_ACTION, Msg->message, (LPARAM) &MouseHookData))
         return;
   }

   /* Get the desktop window */
   pwndDesktop = UserGetDesktopWindow();
   if (!pwndDesktop) return;
//   pDesk = pwndDesktop->head.rpdesk;

   /* Check if the mouse is captured */
   Msg->hwnd = IntGetCaptureWindow();
   if (Msg->hwnd != NULL)
   {
       pwnd = UserGetWindowObject(Msg->hwnd);
   }
   else
   {
       pwnd = IntTopLevelWindowFromPoint(Msg->pt.x, Msg->pt.y);
       if (pwnd) Msg->hwnd = UserHMGetHandle(pwnd);
   }

   hdcScreen = IntGetScreenDC();
   CurInfo = IntGetSysCursorInfo();

   /* Check if we found a window */
   if (Msg->hwnd != NULL && pwnd != NULL)
   {
       pti = pwnd->head.pti;
       MessageQueue = pti->MessageQueue;

       if (MessageQueue->QF_flags & QF_INDESTROY)
       {
          ERR("Mouse is over a Window with a Dead Message Queue!\n");
          return;
       }

       // Check to see if this is attached.
       if ( pti != MessageQueue->ptiMouse &&
            MessageQueue->cThreads > 1 )
       {
          // Set the send pti to the message queue mouse pti.
          pti = MessageQueue->ptiMouse;
       }

       if (Msg->message == WM_MOUSEMOVE)
       {
          /* Check if cursor should be visible */
           if(hdcScreen &&
              MessageQueue->CursorObject &&
              MessageQueue->iCursorLevel >= 0)
           {
               /* Check if shape has changed */
               if(CurInfo->CurrentCursorObject != MessageQueue->CursorObject)
               {
                   /* Call GDI to set the new screen cursor */
                    GreSetPointerShape(hdcScreen,
                                       MessageQueue->CursorObject->hbmAlpha ?
                                           NULL : MessageQueue->CursorObject->hbmMask,
                                       MessageQueue->CursorObject->hbmAlpha ?
                                           MessageQueue->CursorObject->hbmAlpha : MessageQueue->CursorObject->hbmColor,
                                       MessageQueue->CursorObject->xHotspot,
                                       MessageQueue->CursorObject->yHotspot,
                                       gpsi->ptCursor.x,
                                       gpsi->ptCursor.y,
                                       MessageQueue->CursorObject->hbmAlpha ? SPS_ALPHA : 0);

               } else
                   GreMovePointer(hdcScreen, Msg->pt.x, Msg->pt.y);
           }
           /* Check if we have to hide cursor */
           else if (CurInfo->ShowingCursor >= 0)
               GreMovePointer(hdcScreen, -1, -1);

           /* Update global cursor info */
           CurInfo->ShowingCursor = MessageQueue->iCursorLevel;
           CurInfo->CurrentCursorObject = MessageQueue->CursorObject;
           gpqCursor = MessageQueue;

           /* Mouse move is a special case */
           if (!UserRawInputNoLegacy(pwnd->head.pti->ppi, RIM_TYPEMOUSE))
           {
              MessageQueue->QF_flags |= QF_MOUSEMOVED;
              gdwMouseMoveExtraInfo = dwExtraInfo;
              gdwMouseMoveTimeStamp = Msg->time;
              MsqWakeQueue(pti, QS_MOUSEMOVE, TRUE);
           }
       }
       else if (UserRawInputNoLegacy(pwnd->head.pti->ppi, RIM_TYPEMOUSE))
       {
           /* The process gets raw input instead of mouse messages */
       }
       else
       {
           if (!IntGetCaptureWindow())
           {
             // ERR("ptiLastInput is set\n");
             // ptiLastInput = pti; // Once this is set during Reboot or Shutdown, this prevents the exit window having foreground.
             // Find all the Move Mouse calls and fix mouse set active focus issues......
           }

           // Post mouse move before posting mouse buttons, keep it in sync.
           if (pti->MessageQueue->QF_flags & QF_MOUSEMOVED)
           {
              IntCoalesceMouseMove(pti);
           }

           TRACE("Posting mouse message to hwnd=%p!\n", UserHMGetHandle(pwnd));
           MsqPostMessage(pti, Msg, TRUE, QS_MOUSEBUTTON, 0, dwExtraInfo);
       }
   }
   else if (hdcScreen)
   {
       /* always show cursor on background; FIXME: set default pointer */
       GreMovePointer(hdcScreen, Msg->pt.x, Msg->pt.y);
       CurInfo->ShowingCursor = 0;
   }
}

PUSER_MESSAGE FASTCALL
MsqCreateMessage(LPMSG Msg)
{
   PUSER_MESSAGE Message;

   Message = ExAllocateFromPagedLookasideList(pgMessageLookasideList);
   if (!Message)
   {
      return NULL;
   }

   RtlZeroMemory(Message, sizeof(*Message));
   RtlMoveMemory(&Message->Msg, Msg, sizeof(MSG));
   PostMsgCount++;
   return Message;
}

VOID FASTCALL
MsqDestroyMessage(PUSER_MESSAGE Message)
{
   TRACE("Post Destroy %d\n",PostMsgCount);
   if (Message->pti == NULL)
   {
      ERR("Double Free Message\n");
      return;
   }
   RemoveEntryList(&Message->ListEntry);
   Message->pti = NULL;
   ExFreeToPagedLookasideList(pgMessageLookasideList, Message);
   PostMsgCount--;
}

PUSER_SENT_MESSAGE FASTCALL
AllocateUserMessage(BOOL KEvent)
{
   PUSER_SENT_MESSAGE Message;

   if(!(Message = ExAllocateFromPagedLookasideList(pgSendMsgLookasideList)))
   {
       ERR("AllocateUserMessage(): Not enough memory to allocate a message\n");
       return NULL;
   }
   RtlZeroMemory(Message, sizeof(USER_SENT_MESSAGE));

   if (KEvent)
   {
      Message->pkCompletionEvent = &Message->CompletionEvent;

      KeInitializeEvent(Message->pkCompletionEvent, NotificationEvent, FALSE);
   }
   SendMsgCount++;
   TRACE("AUM pti %p msg %p\n",PsGetCurrentThreadWin32Thread(),Message);
   return Message;
}

VOID FASTCALL
FreeUserMessage(PUSER_SENT_MESSAGE Message)
{
   Message->pkCompletionEvent = NULL;

   /* Remove it from the list */
   RemoveEntryList(&Message->ListEntry);

   ExFreeToPagedLookasideList(pgSendMsgLookasideList, Message);
   SendMsgCount--;
}

VOID APIENTRY
MsqRemoveWindowMessagesFromQueue(PWND Window)
{
   PTHREADINFO pti;
   PUSER_SENT_MESSAGE SentMessage;
   PUSER_MESSAGE PostedMessage;
   PLIST_ENTRY CurrentEntry, ListHead;

   ASSERT(Window);

   pti = Window->head.pti;

   /* remove the posted messages for this window */
   CurrentEntry = pti->PostedMessagesListHead.Flink;
   ListHead = &pti->PostedMessagesListHead;
   while (CurrentEntry != ListHead)
   {
      PostedMessage = CONTAINING_RECORD(CurrentEntry, USER_MESSAGE, ListEntry);

      if (PostedMessage->Msg.hwnd == UserHMGetHandle(Window))
      {
         if (PostedMessage->Msg.message == WM_QUIT && pti->QuitPosted == 0)
         {
            pti->QuitPosted = 1;
            pti->exitCode = PostedMessage->Msg.wParam;
         }
         ClearMsgBitsMask(pti, PostedMessage->QS_Flags);
         MsqDestroyMessage(PostedMessage);
         CurrentEntry = pti->PostedMessagesListHead.Flink;
      }
      else
      {
         CurrentEntry = CurrentEntry->Flink;
      }
   }

   /* remove the sent messages for this window */
   CurrentEntry = pti->SentMessagesListHead.Flink;
   ListHead = &pti->SentMessagesListHead;
   while (CurrentEntry != ListHead)
   {
      SentMessage = CONTAINING_RECORD(CurrentEntry, USER_SENT_MESSAGE, ListEntry);

      if(SentMessage->Msg.hwnd == UserHMGetHandle(Window))
      {
         ERR("Remove Window Messages %p From Sent Queue\n",SentMessage);
#if 0 // Should mark these as invalid and allow the rest clean up, so far no harm by just commenting out. See CORE-9210.
         ClearMsgBitsMask(pti, SentMessage->QS_Flags);

         /* wake the sender's thread */
         if (SentMessage->pkCompletionEvent != NULL)
         {
            KeSetEvent(SentMessage->pkCompletionEvent, IO_NO_INCREMENT, FALSE);
         }

         if (SentMessage->HasPackedLParam)
         {
            if (SentMessage->Msg.lParam)
               ExFreePool((PVOID)SentMessage->Msg.lParam);
         }

         /* free the message */
         FreeUserMessage(SentMessage);

         CurrentEntry = pti->SentMessagesListHead.Flink;
#endif
         CurrentEntry = CurrentEntry->Flink;
      }
      else
      {
         CurrentEntry = CurrentEntry->Flink;
      }
   }
}

BOOLEAN FASTCALL
co_MsqDispatchOneSentMessage(
    _In_ PTHREADINFO pti)
{
   PUSER_SENT_MESSAGE SaveMsg, Message;
   PLIST_ENTRY Entry;
   BOOL Ret;
   LRESULT Result = 0;

   ASSERT(pti == PsGetCurrentThreadWin32Thread());

   if (IsListEmpty(&pti->SentMessagesListHead))
   {
      return(FALSE);
   }

   /* remove it from the list of pending messages */
   Entry = RemoveHeadList(&pti->SentMessagesListHead);
   Message = CONTAINING_RECORD(Entry, USER_SENT_MESSAGE, ListEntry);

   // Signal this message is being processed.
   Message->flags |= SMF_RECEIVERBUSY|SMF_RECEIVEDMESSAGE;

   SaveMsg = pti->pusmCurrent;
   pti->pusmCurrent = Message;

   // Processing a message sent to it from another thread.
   if ( ( Message->ptiSender && pti != Message->ptiSender) ||
        ( Message->ptiCallBackSender && pti != Message->ptiCallBackSender ))
   {  // most likely, but, to be sure.
      pti->pcti->CTI_flags |= CTI_INSENDMESSAGE; // Let the user know...
   }

   /* Now insert it to the global list of messages that can be removed Justin Case there's Trouble */
   InsertTailList(&usmList, &Message->ListEntry);

   ClearMsgBitsMask(pti, Message->QS_Flags);

   if (Message->HookMessage == MSQ_ISHOOK)
   {  // Direct Hook Call processor
      Result = co_CallHook( Message->Msg.message,           // HookId
                            HandleToLong(Message->Msg.hwnd), // Code
                            Message->Msg.wParam,
                            Message->Msg.lParam);
   }
   else if(Message->HookMessage == MSQ_INJECTMODULE)
   {
       Result = IntLoadHookModule(Message->Msg.message,
                                  (HHOOK)Message->Msg.lParam,
                                  Message->Msg.wParam);
   }
   else if ((Message->CompletionCallback) &&
            (Message->ptiCallBackSender == pti))
   {   /* Call the callback routine */
      if (Message->QS_Flags & QS_SMRESULT)
      {
         co_IntCallSentMessageCallback(Message->CompletionCallback,
                                       Message->Msg.hwnd,
                                       Message->Msg.message,
                                       Message->CompletionCallbackContext,
                                       Message->lResult);
         /* Set callback to NULL to prevent reentry */
         Message->CompletionCallback = NULL;
      }
      else
      {
         /* The message has not been processed yet, reinsert it. */
         RemoveEntryList(&Message->ListEntry);
         InsertTailList(&Message->ptiCallBackSender->SentMessagesListHead, &Message->ListEntry);
         // List is occupied need to set the bit.
         MsqWakeQueue(Message->ptiCallBackSender, QS_SENDMESSAGE, TRUE);
         ERR("Callback Message not processed yet. Requeuing the message\n"); //// <---- Need to see if this happens.
         Ret = FALSE;
         goto Exit;
      }
   }
   else
   {  /* Call the window procedure. */
      Result = co_IntSendMessage( Message->Msg.hwnd,
                                  Message->Msg.message,
                                  Message->Msg.wParam,
                                  Message->Msg.lParam);
   }

   /* If the message is a callback, insert it in the callback senders MessageQueue */
   if (Message->CompletionCallback)
   {
      /* The callback sender can be torn down while we run the receiver's window
         procedure, because that callout drops the USER lock. Its THREADINFO and its
         wake event (pEventQueueServer) are then freed, so requeuing the result to it
         and waking it is a use-after-free (T131). SMF_SENDERDIED is raised by the
         sender's own teardown while this in-flight message sits on the trouble list;
         once it is set there is no live sender left to hand the result to. */
      if (Message->ptiCallBackSender && !(Message->flags & SMF_SENDERDIED))
      {
         Message->lResult = Result;
         Message->QS_Flags |= QS_SMRESULT;

         /* insert it in the callers message queue */
         RemoveEntryList(&Message->ListEntry);
         InsertTailList(&Message->ptiCallBackSender->SentMessagesListHead, &Message->ListEntry);
         MsqWakeQueue(Message->ptiCallBackSender, QS_SENDMESSAGE, TRUE);
      }
      else if (Message->flags & SMF_RECEIVERFREE)
      {
         /* No live sender to collect the result: drop the message here. */
         if (Message->HasPackedLParam && Message->Msg.lParam)
            ExFreePool((PVOID)Message->Msg.lParam);
         FreeUserMessage(Message);
      }
      Ret = TRUE;
      goto Exit;
   }

   // Retrieve the result from callback.
   if (Message->QS_Flags & QS_SMRESULT)
   {
      Result = Message->lResult;
   }

   /* Let the sender know the result. */
   Message->lResult = Result;

   if (Message->HasPackedLParam)
   {
      if (Message->Msg.lParam)
         ExFreePool((PVOID)Message->Msg.lParam);
   }

   // Clear busy signal.
   Message->flags &= ~SMF_RECEIVERBUSY;

   /* Notify the sender. */
   if (Message->pkCompletionEvent != NULL)
   {
      KeSetEvent(Message->pkCompletionEvent, IO_NO_INCREMENT, FALSE);
   }

   /* free the message */
   if (Message->flags & SMF_RECEIVERFREE)
   {
      TRACE("Receiver Freeing Message %p\n",Message);
      FreeUserMessage(Message);
   }

   Ret = TRUE;
Exit:
   /* do not hangup on the user if this is reentering */
   if (!SaveMsg) pti->pcti->CTI_flags &= ~CTI_INSENDMESSAGE;
   pti->pusmCurrent = SaveMsg;

   return Ret;
}

BOOL FASTCALL
co_MsqSendMessageAsync(PTHREADINFO ptiReceiver,
                       HWND hwnd,
                       UINT Msg,
                       WPARAM wParam,
                       LPARAM lParam,
                       SENDASYNCPROC CompletionCallback,
                       ULONG_PTR CompletionCallbackContext,
                       BOOL HasPackedLParam,
                       INT HookMessage)
{
    PTHREADINFO ptiSender;
    PUSER_SENT_MESSAGE Message;

    if(!(Message = AllocateUserMessage(FALSE)))
    {
        ERR("MsqSendMessageAsync(): Not enough memory to allocate a message\n");
        return FALSE;
    }

    ptiSender = PsGetCurrentThreadWin32Thread();

    Message->Msg.hwnd = hwnd;
    Message->Msg.message = Msg;
    Message->Msg.wParam = wParam;
    Message->Msg.lParam = lParam;
    Message->pkCompletionEvent = NULL; // No event needed.
    Message->ptiReceiver = ptiReceiver;
    Message->ptiCallBackSender = ptiSender;
    Message->CompletionCallback = CompletionCallback;
    Message->CompletionCallbackContext = CompletionCallbackContext;
    Message->HookMessage = HookMessage;
    Message->HasPackedLParam = HasPackedLParam;
    Message->QS_Flags = QS_SENDMESSAGE;
    Message->flags = SMF_RECEIVERFREE;

    InsertTailList(&ptiReceiver->SentMessagesListHead, &Message->ListEntry);
    MsqWakeQueue(ptiReceiver, QS_SENDMESSAGE, TRUE);

    return TRUE;
}

/* Take a queued sent message back from its receiver: nobody may dispatch it or complete it */
static VOID
MsqUnqueueSentMessage(
    _In_ PTHREADINFO ptirec,
    _In_ PUSER_SENT_MESSAGE Message)
{
   Message->pkCompletionEvent = NULL;
   RemoveEntryList(&Message->ListEntry);
   ClearMsgBitsMask(ptirec, Message->QS_Flags);
   InsertTailList(&usmList, &Message->ListEntry);
}

/* Returns TRUE when the message was still queued: then nothing but the trouble list holds it */
static BOOLEAN
MsqWithdrawSentMessage(
    _In_ PTHREADINFO ptirec,
    _In_ PUSER_SENT_MESSAGE Message)
{
   PLIST_ENTRY Entry;

   for (Entry = ptirec->SentMessagesListHead.Flink;
        Entry != &ptirec->SentMessagesListHead;
        Entry = Entry->Flink)
   {
      if (CONTAINING_RECORD(Entry, USER_SENT_MESSAGE, ListEntry) == Message)
      {
         MsqUnqueueSentMessage(ptirec, Message);
         return TRUE;
      }
   }
   return FALSE;
}

/* A terminated thread can leave its message queued on a receiver without ever returning to
   co_MsqSendMessage, for instance when the termination lands inside a window procedure it
   called while it waited. The message's lParam can point into the dead thread's stack. */
VOID FASTCALL
MsqWithdrawSentMessagesOf(
    _In_ PTHREADINFO ptiSender)
{
   PPROCESSINFO ppi;
   PTHREADINFO pti;
   PLIST_ENTRY Entry, Next;
   PUSER_SENT_MESSAGE Message;

   for (ppi = gppiList; ppi; ppi = ppi->ppiNext)
   {
      for (pti = ppi->ptiList; pti; pti = pti->ptiSibling)
      {
         for (Entry = pti->SentMessagesListHead.Flink;
              Entry != &pti->SentMessagesListHead;
              Entry = Next)
         {
            Next = Entry->Flink;
            Message = CONTAINING_RECORD(Entry, USER_SENT_MESSAGE, ListEntry);
            /* T131 withdrew every message whose ptiCallBackSender was the dying thread,
               but SendMessageCallback and SendNotifyMessage share ptiCallBackSender and
               differ only in CompletionCallback. The UAF is dispatch-side and callback-only:
               co_MsqDispatchOneSentMessage requeues the result to ptiCallBackSender and wakes
               it ONLY under "if (Message->CompletionCallback)", so a genuine callback left on
               the receiver would touch the freed sender THREADINFO / wake event. A pure notify
               (CompletionCallback == NULL) has no result to hand back, no wake, and never
               dereferences ptiCallBackSender on dispatch, so it must stay queued and be
               delivered to the receiver even after its sender exits (T144). Withdraw a
               synchronous sender's message (ptiSender match) and a genuine callback message
               whose callback sender is dying; leave a pure notify for the receiver. */
            if (Message->ptiSender == ptiSender ||
                (Message->ptiCallBackSender == ptiSender &&
                 Message->CompletionCallback != NULL))
            {
               MsqUnqueueSentMessage(pti, Message);
               Message->flags |= SMF_SENDERDIED;

               if (Message->ptiSender == NULL)
               {
                  /* A withdrawn genuine callback message (no ptiSender, no completion event)
                     is now on no thread list and not in flight, and its only owner is the
                     dying sender. Neither the receiver cleanup nor the sender cleanup branches
                     free it (RECEIVERFREE is set from birth), so free it and its packed lParam
                     here instead of leaking it on the trouble list (P2-2). */
                  if (Message->HasPackedLParam && Message->Msg.lParam)
                     ExFreePool((PVOID)Message->Msg.lParam);
                  FreeUserMessage(Message);
               }
            }
         }
      }
   }
}

NTSTATUS FASTCALL
co_MsqSendMessage(PTHREADINFO ptirec,
                  HWND Wnd,
                  UINT Msg,
                  WPARAM wParam,
                  LPARAM lParam,
                  UINT uTimeout,
                  BOOL Block,
                  INT HookMessage,
                  ULONG_PTR *uResult)
{
   PTHREADINFO pti;
   PUSER_SENT_MESSAGE SaveMsg, Message;
   NTSTATUS WaitStatus;
   LARGE_INTEGER Timeout;
   PWND pWnd;
   BOOLEAN SwapStateEnabled;
   LRESULT Result = 0;   //// Result could be trashed. ////

   pti = PsGetCurrentThreadWin32Thread();
   ASSERT(pti != ptirec);
   ASSERT(ptirec->pcti); // Send must have a client side to receive it!!!!

   /* Don't send from or to a dying thread */
   if (pti->TIF_flags & TIF_INCLEANUP || ptirec->TIF_flags & TIF_INCLEANUP)
   {
       // Unless we are dying and need to tell our parents.
       if (pti->TIF_flags & TIF_INCLEANUP && !(ptirec->TIF_flags & TIF_INCLEANUP))
       {
           // Parent notify is the big one. Fire and forget!
           TRACE("Send message from dying thread %u\n", Msg);
           co_MsqSendMessageAsync(ptirec, Wnd, Msg, wParam, lParam, NULL, 0, FALSE, HookMessage);
       }
       if (uResult) *uResult = -1;
       TRACE("MsqSM: Msg %u Current pti %lu or Rec pti %lu\n", Msg, pti->TIF_flags & TIF_INCLEANUP, ptirec->TIF_flags & TIF_INCLEANUP);
       return STATUS_UNSUCCESSFUL;
   }

   if (IsThreadSuspended(ptirec))
   {
      ERR("Sending to Suspended Thread Msg %lx\n",Msg);
      if (uResult) *uResult = -1;
      return STATUS_UNSUCCESSFUL;
   }

   // Should we do the same for No Wait?
   if ( HookMessage == MSQ_NORMAL )
   {
      pWnd = ValidateHwndNoErr(Wnd);

      // These can not cross International Border lines!
      if ( pti->ppi != ptirec->ppi && pWnd )
      {
         switch(Msg)
         {
             // Handle the special case when working with password transfers across bordering processes.
             case EM_GETLINE:
             case EM_SETPASSWORDCHAR:
             case WM_GETTEXT:
                // Look for edit controls setup for passwords.
                if ( gpsi->atomSysClass[ICLS_EDIT] == pWnd->pcls->atomClassName && // Use atomNVClassName.
                     pWnd->style & ES_PASSWORD )
                {
                   if (uResult) *uResult = -1;
                   ERR("Running across the border without a passport!\n");
                   EngSetLastError(ERROR_ACCESS_DENIED);
                   return STATUS_UNSUCCESSFUL;
                }
                break;
             case WM_NOTIFY:
                if (uResult) *uResult = -1;
                ERR("Running across the border without a passport!\n");
                return STATUS_UNSUCCESSFUL;
         }
      }

      // These can not cross State lines!
      if ( Msg == WM_CREATE || Msg == WM_NCCREATE )
      {
         if (uResult) *uResult = -1;
         ERR("Can not tell the other State we have Create!\n");
         return STATUS_UNSUCCESSFUL;
      }
   }

   if(!(Message = AllocateUserMessage(TRUE)))
   {
      ERR("MsqSendMessage(): Not enough memory to allocate a message\n");
      if (uResult) *uResult = -1;
      return STATUS_INSUFFICIENT_RESOURCES;
   }

   Timeout.QuadPart = Int32x32To64(-10000,uTimeout); // Pass SMTO test with a TO of 0x80000000.
   TRACE("Timeout val %lld\n",Timeout.QuadPart);

   Message->Msg.hwnd = Wnd;
   Message->Msg.message = Msg;
   Message->Msg.wParam = wParam;
   Message->Msg.lParam = lParam;
   Message->ptiReceiver = ptirec;
   Message->ptiSender = pti;
   Message->HookMessage = HookMessage;
   Message->QS_Flags = QS_SENDMESSAGE;

   SaveMsg = pti->pusmSent;
   pti->pusmSent = Message;

   /* Queue it in the destination's message queue */
   InsertTailList(&ptirec->SentMessagesListHead, &Message->ListEntry);

   MsqWakeQueue(ptirec, QS_SENDMESSAGE, TRUE);

   // First time in, turn off swapping of the stack.
   if (pti->cEnterCount == 0)
   {
      SwapStateEnabled = KeSetKernelStackSwapEnable(FALSE);
   }
   pti->cEnterCount++;

   if (Block)
   {
      PVOID WaitObjects[2];

      WaitObjects[0] = Message->pkCompletionEvent; // Wait 0
      WaitObjects[1] = ptirec->pEThread;           // Wait 1

      UserLeaveCo();

      WaitStatus = KeWaitForMultipleObjects( 2,
                                             WaitObjects,
                                             WaitAny,
                                             UserRequest,
                                             UserMode,
                                             FALSE,
                                            (uTimeout ? &Timeout : NULL),
                                             NULL );

      UserEnterCo();

      if (WaitStatus == STATUS_TIMEOUT)
      {
         /* If the message has not yet dispatched, make sure it can't pass a result
            and it must not set the completion event anymore */
         if (MsqWithdrawSentMessage(ptirec, Message))
         {
            /* Nobody can reach it any more: do not leave it to the receiver's cleanup */
            FreeUserMessage(Message);
            Message = NULL;
         }

         ERR("MsqSendMessage (blocked) timed out 1 Status %lx\n", WaitStatus);
      }
      // Receiving thread passed on and left us hanging with issues still pending.
      else if (WaitStatus == STATUS_WAIT_1)
      {
         ERR("Bk Receiving Thread woken up dead!\n");
         Message->flags |= SMF_RECEIVERDIED;
      }

      while (co_MsqDispatchOneSentMessage(pti))
         ;
   }
   else
   {
      PVOID WaitObjects[3];

      WaitObjects[0] = Message->pkCompletionEvent; // Wait 0
      WaitObjects[1] = pti->pEventQueueServer;     // Wait 1
      WaitObjects[2] = ptirec->pEThread;           // Wait 2

      do
      {
         UserLeaveCo();

         WaitStatus = KeWaitForMultipleObjects( 3,
                                                WaitObjects,
                                                WaitAny,
                                                UserRequest,
                                                UserMode,
                                                FALSE,
                                               (uTimeout ? &Timeout : NULL),
                                                NULL);

         UserEnterCo();

         if (WaitStatus == STATUS_TIMEOUT)
         {
            /* If the message has not yet been dispatched, make sure it can't pass a result
               and it must not set the completion event anymore */
            if (MsqWithdrawSentMessage(ptirec, Message))
            {
               FreeUserMessage(Message);
               Message = NULL;
            }

            WARN("MsqSendMessage timed out 2 Status %lx\n", WaitStatus);
            break;
         }
         // Receiving thread passed on and left us hanging with issues still pending.
         else if (WaitStatus == STATUS_WAIT_2)
         {
            ERR("NB Receiving Thread woken up dead!\n");
            Message->flags |= SMF_RECEIVERDIED;
            break;
         }

         if (WaitStatus == STATUS_USER_APC) break;

         while (co_MsqDispatchOneSentMessage(pti))
            ;
      } while (WaitStatus == STATUS_WAIT_1);
   }

   // Count is nil, restore swapping of the stack.
   if (--pti->cEnterCount == 0 )
   {
      KeSetKernelStackSwapEnable(SwapStateEnabled);
   }

   // Handle User APC
   if (WaitStatus == STATUS_USER_APC)
   {
     // The current thread is dying!
     TRACE("User APC\n");

     // The Message will be on the Trouble list until Thread cleanup. An undispatched
     // message must leave the receiver's list: its lParam can point into this thread's stack.
     MsqWithdrawSentMessage(ptirec, Message);
     Message->flags |= SMF_SENDERDIED;

     co_IntDeliverUserAPC();
     ERR("User APC Returned\n"); // Should not see this message.
   }

   // Force this thread to wake up for the next go around.
   KeSetEvent(pti->pEventQueueServer, IO_NO_INCREMENT, FALSE);

   // A message withdrawn on timeout is already freed.
   if (Message)
   {
      Result = Message->lResult;

      // Determine whether this message is being processed or not.
      if ((Message->flags & (SMF_RECEIVERBUSY|SMF_RECEIVEDMESSAGE)) != SMF_RECEIVEDMESSAGE)
      {
         Message->flags |= SMF_RECEIVERFREE;
      }

      if (!(Message->flags & SMF_RECEIVERFREE))
      {
         TRACE("Sender Freeing Message %p ptirec %p bit %d list empty %d\n",Message,ptirec,!!(ptirec->pcti->fsChangeBits & QS_SENDMESSAGE),IsListEmpty(&ptirec->SentMessagesListHead));
         // Make it to this point, the message was received.
         FreeUserMessage(Message);
      }
   }

   pti->pusmSent = SaveMsg;

   TRACE("MSM Allocation Count %d Status %lx Result %d\n",SendMsgCount,WaitStatus,Result);

   if (WaitStatus != STATUS_TIMEOUT)
   {
      if (uResult)
      {
         *uResult = (STATUS_WAIT_0 == WaitStatus ? Result : 0);
      }
   }

   return WaitStatus;
}

BOOL FASTCALL
MsqPostMessage(PTHREADINFO pti,
               MSG* Msg,
               BOOLEAN HardwareMessage,
               DWORD MessageBits,
               DWORD dwQEvent,
               LONG_PTR ExtraInfo)
{
   PUSER_MESSAGE Message;
   PUSER_MESSAGE_QUEUE MessageQueue;

   MessageQueue = pti->MessageQueue;

   if ((pti->TIF_flags & TIF_INCLEANUP) || (MessageQueue->QF_flags & QF_INDESTROY))
   {
      ERR("Post Msg; Thread or Q is Dead!\n");
      return FALSE;
   }

   Message = MsqCreateMessage(Msg);
   if (!Message)
      return FALSE;

   if (Msg->message == WM_HOTKEY)
      MessageBits |= QS_HOTKEY;

   Message->dwQEvent = dwQEvent;
   Message->ExtraInfo = ExtraInfo;
   Message->QS_Flags = MessageBits;
   Message->pti = pti;

   if (!HardwareMessage)
   {
       InsertTailList(&pti->PostedMessagesListHead, &Message->ListEntry);
   }
   else
   {
       InsertTailList(&MessageQueue->HardwareMessagesListHead, &Message->ListEntry);
   }

   MsqWakeQueue(pti, MessageBits, TRUE);
   TRACE("Post Message %d\n", PostMsgCount);
   return TRUE;
}

VOID FASTCALL
MsqPostQuitMessage(PTHREADINFO pti, ULONG ExitCode)
{
   BOOL WasPosted = pti->QuitPosted;

   pti->QuitPosted = TRUE;
   pti->exitCode = ExitCode;
   /* The flag holds one count; a repeated quit adds none but still refreshes the bits and signals */
   if (!WasPosted)
   {
      MsqWakeQueue(pti, QS_POSTMESSAGE|QS_ALLPOSTMESSAGE, TRUE);
   }
   else
   {
      pti->pcti->fsWakeBits |= QS_POSTMESSAGE|QS_ALLPOSTMESSAGE;
      pti->pcti->fsChangeBits |= QS_POSTMESSAGE|QS_ALLPOSTMESSAGE;
      KeSetEvent(pti->pEventQueueServer, IO_NO_INCREMENT, FALSE);
   }
}

/***********************************************************************
 *           MsqSendParentNotify
 *
 * Send a WM_PARENTNOTIFY to all ancestors of the given window, unless
 * the window has the WS_EX_NOPARENTNOTIFY style.
 */
static void MsqSendParentNotify( PWND pwnd, WORD event, WORD idChild, POINT pt )
{
    PWND pwndDesktop = UserGetDesktopWindow();

    /* pt has to be in the client coordinates of the parent window */
    pt.x += pwndDesktop->rcClient.left - pwnd->rcClient.left;
    pt.y += pwndDesktop->rcClient.top - pwnd->rcClient.top;

    for (;;)
    {
        PWND pwndParent;

        if (!(pwnd->style & WS_CHILD)) break;
        if (pwnd->ExStyle & WS_EX_NOPARENTNOTIFY) break;
        if (!(pwndParent = IntGetParent(pwnd))) break;
        if (pwndParent == pwndDesktop) break;
        pt.x += pwnd->rcClient.left - pwndParent->rcClient.left;
        pt.y += pwnd->rcClient.top - pwndParent->rcClient.top;

        pwnd = pwndParent;
        co_IntSendMessage( UserHMGetHandle(pwnd), WM_PARENTNOTIFY,
                      MAKEWPARAM( event, idChild ), MAKELPARAM( pt.x, pt.y ) );
    }
}

VOID
FASTCALL
IntTrackMouseMove(PWND pwndTrack, PDESKTOP pDesk, PMSG msg, USHORT hittest)
{
//   PWND pwndTrack = IntChildrenWindowFromPoint(pwndMsg, msg->pt.x, msg->pt.y);
//   hittest = (USHORT)GetNCHitEx(pwndTrack, msg->pt); /// @todo WTF is this???

   if ( pDesk->spwndTrack != pwndTrack || // Change with tracking window or
        msg->message != WM_MOUSEMOVE   || // Mouse click changes or
        pDesk->htEx != hittest)           // Change in current hit test states.
   {
      TRACE("ITMM: Track Mouse Move!\n");

      /* Handle only the changing window track and mouse move across a border. */
      if ( pDesk->spwndTrack != pwndTrack ||
          (pDesk->htEx == HTCLIENT) ^ (hittest == HTCLIENT) )
      {
         TRACE("ITMM: Another Wnd %d or Across Border %d\n",
              pDesk->spwndTrack != pwndTrack,(pDesk->htEx == HTCLIENT) ^ (hittest == HTCLIENT));

         if ( pDesk->dwDTFlags & DF_TME_LEAVE )
            UserPostMessage( UserHMGetHandle(pDesk->spwndTrack),
                            (pDesk->htEx != HTCLIENT) ? WM_NCMOUSELEAVE : WM_MOUSELEAVE,
                             0, 0);

         if ( pDesk->dwDTFlags & DF_TME_HOVER )
            IntKillTimer(pDesk->spwndTrack, ID_EVENT_SYSTIMER_MOUSEHOVER, TRUE);

         /* Clear the flags to sign a change. */
         pDesk->dwDTFlags &= ~(DF_TME_LEAVE|DF_TME_HOVER);
      }
      /* Set the Track window and hit test. */
      pDesk->spwndTrack = pwndTrack;
      pDesk->htEx = hittest;
   }

   /* Reset, Same Track window, Hover set and Mouse Clicks or Clobbered Hover box. */
   if ( pDesk->spwndTrack == pwndTrack &&
       ( msg->message != WM_MOUSEMOVE || !RECTL_bPointInRect(&pDesk->rcMouseHover, msg->pt.x, msg->pt.y)) &&
        pDesk->dwDTFlags & DF_TME_HOVER )
   {
      TRACE("ITMM: Reset Hover points!\n");
      // Restart timer for the hover period.
      IntSetTimer(pDesk->spwndTrack, ID_EVENT_SYSTIMER_MOUSEHOVER, pDesk->dwMouseHoverTime, SystemTimerProc, TMRF_SYSTEM);
      // Reset desktop mouse hover from the system default hover rectangle.
      RECTL_vSetRect(&pDesk->rcMouseHover,
                      msg->pt.x - gspv.iMouseHoverWidth  / 2,
                      msg->pt.y - gspv.iMouseHoverHeight / 2,
                      msg->pt.x + gspv.iMouseHoverWidth  / 2,
                      msg->pt.y + gspv.iMouseHoverHeight / 2);
   }
}

BOOL co_IntProcessMouseMessage(MSG* msg, BOOL* RemoveMessages, BOOL* NotForUs, LONG_PTR ExtraInfo, UINT first, UINT last)
{
    MSG clk_msg;
    POINT pt;
    UINT message;
    USHORT hittest;
    EVENTMSG event;
    MOUSEHOOKSTRUCTEX hook;
    BOOL eatMsg = FALSE;

    PWND pwndMsg, pwndDesktop;
    PUSER_MESSAGE_QUEUE MessageQueue;
    PTHREADINFO pti;
    PSYSTEM_CURSORINFO CurInfo;
    PDESKTOP pDesk;

    pti = PsGetCurrentThreadWin32Thread();
    pwndDesktop = UserGetDesktopWindow();
    if (pwndDesktop == NULL)
    {
        ERR("No desktop window!\n");
        return FALSE;
    }

    MessageQueue = pti->MessageQueue;
    CurInfo = IntGetSysCursorInfo();
    pwndMsg = ValidateHwndNoErr(msg->hwnd);
    clk_msg = MessageQueue->msgDblClk;
    pDesk = pwndDesktop->head.rpdesk;

    /* find the window to dispatch this mouse message to */
    if (MessageQueue->spwndCapture)
    {
        hittest = HTCLIENT;
        pwndMsg = MessageQueue->spwndCapture;
    }
    else
    {
        /*
           Start with null window. See wine win.c:test_mouse_input:WM_COMMAND tests.
        */
        pwndMsg = co_WinPosWindowFromPoint( NULL, &msg->pt, &hittest, FALSE);
    }

    TRACE("Got mouse message for %p, hittest: 0x%x\n", msg->hwnd, hittest);

    // Null window or not the same "Hardware" message queue.
    if (pwndMsg == NULL || pwndMsg->head.pti->MessageQueue != MessageQueue)
    {
        // Crossing a boundary, so set cursor. See default message queue cursor.
        IntSystemSetCursor(SYSTEMCUR(ARROW));
        /* Remove and ignore the message */
        *RemoveMessages = TRUE;
        return FALSE;
    }

    // Check to see if this is attached,
    if ( pwndMsg->head.pti != pti &&  // window thread is not current,
         MessageQueue->cThreads > 1 ) // and is attached...
    {
        // This is not for us and we should leave so the other thread can check for messages!!!
        *NotForUs = TRUE;
        *RemoveMessages = FALSE;
        return FALSE;
    }

    if ( MessageQueue == gpqCursor ) // Cursor must use the same Queue!
    {
       IntTrackMouseMove(pwndMsg, pDesk, msg, hittest);
    }
    else
    {
       WARN("Not the same cursor!\n");
    }

    msg->hwnd = UserHMGetHandle(pwndMsg);

    pt = msg->pt;
    message = msg->message;

    /* Note: windows has no concept of a non-client wheel message */
    if (message != WM_MOUSEWHEEL && message != WM_MOUSEHWHEEL)
    {
        if (hittest != HTCLIENT)
        {
            message += WM_NCMOUSEMOVE - WM_MOUSEMOVE;
            msg->wParam = hittest; // Caution! This might break wParam check in DblClk.
        }
        else
        {
            /* coordinates don't get translated while tracking a menu */
            /* FIXME: should differentiate popups and top-level menus */
            if (!(MessageQueue->MenuOwner))
            {
                pt.x += pwndDesktop->rcClient.left - pwndMsg->rcClient.left;
                pt.y += pwndDesktop->rcClient.top - pwndMsg->rcClient.top;
            }
        }
    }
    msg->lParam = MAKELONG( pt.x, pt.y );

    /* translate double-clicks */

    if ((msg->message == WM_LBUTTONDOWN) ||
        (msg->message == WM_RBUTTONDOWN) ||
        (msg->message == WM_MBUTTONDOWN) ||
        (msg->message == WM_XBUTTONDOWN))
    {
        BOOL update = *RemoveMessages;

        /* translate double-clicks -
         * note that ...MOUSEMOVEs can slip in between
         * ...BUTTONDOWN and ...BUTTONDBLCLK messages */

        if ((MessageQueue->MenuOwner || MessageQueue->MoveSize) ||
            hittest != HTCLIENT ||
            (pwndMsg->pcls->style & CS_DBLCLKS))
        {
           if ((msg->message == clk_msg.message) &&
               (msg->hwnd == clk_msg.hwnd) &&
               // Only worry about XButton wParam.
               (msg->message != WM_XBUTTONDOWN || GET_XBUTTON_WPARAM(msg->wParam) == GET_XBUTTON_WPARAM(clk_msg.wParam)) &&
               ((msg->time - clk_msg.time) < (ULONG)gspv.iDblClickTime) &&
               (abs(msg->pt.x - clk_msg.pt.x) < UserGetSystemMetrics(SM_CXDOUBLECLK)/2) &&
               (abs(msg->pt.y - clk_msg.pt.y) < UserGetSystemMetrics(SM_CYDOUBLECLK)/2))
           {
               message += (WM_LBUTTONDBLCLK - WM_LBUTTONDOWN);
               if (update)
               {
                   MessageQueue->msgDblClk.message = 0;  /* clear the double-click conditions */
                   update = FALSE;
               }
           }
        }

        if (!((first ==  0 && last == 0) || (message >= first || message <= last)))
        {
            TRACE("Message out of range!!!\n");
            return FALSE;
        }

        /* update static double-click conditions */
        if (update) MessageQueue->msgDblClk = *msg;
    }
    else
    {
        if (!((first ==  0 && last == 0) || (message >= first || message <= last)))
        {
            TRACE("Message out of range!!!\n");
            return FALSE;
        }

        // Update mouse move down keys.
        if (message == WM_MOUSEMOVE)
        {
           msg->wParam = MsqGetDownKeyState(MessageQueue);
        }
    }

    if (gspv.bMouseClickLock)
    {
        BOOL IsClkLck = FALSE;

        if(msg->message == WM_LBUTTONUP)
        {
            IsClkLck = ((msg->time - CurInfo->ClickLockTime) >= gspv.dwMouseClickLockTime);
            if (IsClkLck && (!CurInfo->ClickLockActive))
            {
                CurInfo->ClickLockActive = TRUE;
            }
        }
        else if (msg->message == WM_LBUTTONDOWN)
        {
            if (CurInfo->ClickLockActive)
            {
                IsClkLck = TRUE;
                CurInfo->ClickLockActive = FALSE;
            }

            CurInfo->ClickLockTime = msg->time;
        }

        if(IsClkLck)
        {
            /* Remove and ignore the message */
            *RemoveMessages = TRUE;
            TRACE("Remove and ignore the message\n");
            return FALSE;
        }
    }

    if (pti->TIF_flags & TIF_MSGPOSCHANGED)
    {
        pti->TIF_flags &= ~TIF_MSGPOSCHANGED;
        IntNotifyWinEvent(EVENT_OBJECT_LOCATIONCHANGE, NULL, OBJID_CLIENT, CHILDID_SELF, 0);
    }

    /* message is accepted now (but still get dropped) */

    event.message = msg->message;
    event.time    = msg->time;
    event.hwnd    = msg->hwnd;
    event.paramL  = msg->pt.x;
    event.paramH  = msg->pt.y;
    co_HOOK_CallHooks( WH_JOURNALRECORD, HC_ACTION, 0, (LPARAM)&event );

    RtlZeroMemory(&hook, sizeof(hook));
    hook.MOUSEHOOKSTRUCT.pt           = msg->pt;
    hook.MOUSEHOOKSTRUCT.hwnd         = msg->hwnd;
    hook.MOUSEHOOKSTRUCT.wHitTestCode = hittest;
    hook.MOUSEHOOKSTRUCT.dwExtraInfo  = ExtraInfo;
    hook.mouseData    = 0;
    if (message == WM_MOUSEWHEEL || message == WM_MOUSEHWHEEL)
    {
        /* A wheel is not tied to a window part */
        hook.MOUSEHOOKSTRUCT.wHitTestCode = 0;
        hook.mouseData = MAKELONG(0, GET_WHEEL_DELTA_WPARAM(msg->wParam));
    }
    else if (message == WM_XBUTTONDOWN || message == WM_XBUTTONUP || message == WM_XBUTTONDBLCLK ||
             message == WM_NCXBUTTONDOWN || message == WM_NCXBUTTONUP || message == WM_NCXBUTTONDBLCLK)
    {
        hook.mouseData = MAKELONG(0, GET_XBUTTON_WPARAM(msg->wParam));
    }
    if (co_HOOK_CallHooks( WH_MOUSE, *RemoveMessages ? HC_ACTION : HC_NOREMOVE,
                        message, (LPARAM)&hook ))
    {
        hook.MOUSEHOOKSTRUCT.pt           = msg->pt;
        hook.MOUSEHOOKSTRUCT.hwnd         = msg->hwnd;
        hook.MOUSEHOOKSTRUCT.wHitTestCode = hittest;
        hook.MOUSEHOOKSTRUCT.dwExtraInfo  = ExtraInfo;
        co_HOOK_CallHooks( WH_CBT, HCBT_CLICKSKIPPED, message, (LPARAM)&hook );

        ERR("WH_MOUSE dropped mouse message!\n");

        /* Remove and skip message */
        *RemoveMessages = TRUE;
        return FALSE;
    }

    if ((hittest == (USHORT)HTERROR) || (hittest == (USHORT)HTNOWHERE))
    {
        co_IntSendMessage( msg->hwnd, WM_SETCURSOR, (WPARAM)msg->hwnd, MAKELONG( hittest, msg->message ));

        /* Remove and skip message */
        *RemoveMessages = TRUE;
        return FALSE;
    }

    if ((*RemoveMessages == FALSE) || MessageQueue->spwndCapture)
    {
        /* Accept the message */
        msg->message = message;
        return TRUE;
    }

    if ((msg->message == WM_LBUTTONDOWN) ||
        (msg->message == WM_RBUTTONDOWN) ||
        (msg->message == WM_MBUTTONDOWN) ||
        (msg->message == WM_XBUTTONDOWN))
    {
        /* Send the WM_PARENTNOTIFY,
         * note that even for double/nonclient clicks
         * notification message is still WM_L/M/RBUTTONDOWN.
         */
        MsqSendParentNotify(pwndMsg, msg->message, 0, msg->pt );

        /* Activate the window if needed */

        if (pwndMsg != MessageQueue->spwndActive)
        {
            PWND pwndTop = pwndMsg;
            pwndTop = IntGetNonChildAncestor(pwndTop);

            TRACE("Mouse pti %p pwndMsg pti %p pwndTop pti %p\n",MessageQueue->ptiMouse,pwndMsg->head.pti,pwndTop->head.pti);

            if (pwndTop && pwndTop != pwndDesktop)
            {
                LONG ret = co_IntSendMessage( msg->hwnd,
                                              WM_MOUSEACTIVATE,
                                              (WPARAM)UserHMGetHandle(pwndTop),
                                              MAKELONG( hittest, msg->message));
                switch(ret)
                {
                case MA_NOACTIVATEANDEAT:
                    eatMsg = TRUE;
                    /* fall through */
                case MA_NOACTIVATE:
                    break;
                case MA_ACTIVATEANDEAT:
                    eatMsg = TRUE;
                    /* fall through */
                case MA_ACTIVATE:
                case 0:
                    if (!co_IntMouseActivateWindow( pwndTop )) eatMsg = TRUE;
                    break;
                default:
                    ERR( "unknown WM_MOUSEACTIVATE code %d\n", ret );
                    break;
                }
            }
        }
    }

    /* send the WM_SETCURSOR message */

    /* Windows sends the normal mouse message as the message parameter
       in the WM_SETCURSOR message even if it's non-client mouse message */
    co_IntSendMessage( msg->hwnd, WM_SETCURSOR, (WPARAM)msg->hwnd, MAKELONG( hittest, msg->message ));

    msg->message = message;
    return !eatMsg;
}

BOOL co_IntProcessKeyboardMessage(MSG* Msg, BOOL* RemoveMessages)
{
    EVENTMSG Event;
    USER_REFERENCE_ENTRY Ref;
    PWND pWnd;
    UINT ImmRet;
    BOOL Ret = TRUE, bKeyUpDown = FALSE;
    PTHREADINFO pti = PsGetCurrentThreadWin32Thread();
    const UINT uMsg = Msg->message;

    if (uMsg == VK_PACKET)
        pti->wchInjected = HIWORD(Msg->wParam);

    if (uMsg == WM_KEYDOWN || uMsg == WM_SYSKEYDOWN || uMsg == WM_KEYUP || uMsg == WM_SYSKEYUP)
    {
        bKeyUpDown = TRUE;
        switch (Msg->wParam)
        {
            case VK_LSHIFT: case VK_RSHIFT:
                Msg->wParam = VK_SHIFT;
                break;
            case VK_LCONTROL: case VK_RCONTROL:
                Msg->wParam = VK_CONTROL;
                break;
            case VK_LMENU: case VK_RMENU:
                Msg->wParam = VK_MENU;
                break;
        }
    }

    pWnd = ValidateHwndNoErr(Msg->hwnd);
    if (pWnd) UserRefObjectCo(pWnd, &Ref);

    Event.message = uMsg;
    Event.hwnd    = Msg->hwnd;
    Event.time    = Msg->time;
    Event.paramL  = (Msg->wParam & 0xFF) | (HIWORD(Msg->lParam) << 8);
    Event.paramH  = Msg->lParam & 0x7FFF;
    if (HIWORD(Msg->lParam) & 0x0100) Event.paramH |= 0x8000;
    co_HOOK_CallHooks( WH_JOURNALRECORD, HC_ACTION, 0, (LPARAM)&Event);

    if (*RemoveMessages)
    {
        if ((uMsg == WM_KEYDOWN) &&
            (Msg->hwnd != IntGetDesktopWindow()))
        {
            /* Handle F1 key by sending out WM_HELP message */
            if (Msg->wParam == VK_F1)
            {
                UserPostMessage( Msg->hwnd, WM_KEYF1, 0, 0 );
            }
            else if (Msg->wParam >= VK_BROWSER_BACK &&
                     Msg->wParam <= VK_LAUNCH_APP2)
            {
                /* FIXME: Process keystate */
                co_IntSendMessage(Msg->hwnd, WM_APPCOMMAND, (WPARAM)Msg->hwnd, MAKELPARAM(0, (FAPPCOMMAND_KEY | (Msg->wParam - VK_BROWSER_BACK + 1))));
            }
        }
        else if (uMsg == WM_KEYUP)
        {
            /* Handle VK_APPS key by posting a WM_CONTEXTMENU message */
            if (Msg->wParam == VK_APPS && pti->MessageQueue->MenuOwner == NULL)
                UserPostMessage( Msg->hwnd, WM_CONTEXTMENU, (WPARAM)Msg->hwnd, -1 );
        }
    }

    //// Key Down!
    if (*RemoveMessages && uMsg == WM_SYSKEYDOWN)
    {
        if ( HIWORD(Msg->lParam) & KF_ALTDOWN )
        {
            if ( Msg->wParam == VK_ESCAPE || Msg->wParam == VK_TAB ) // Alt-Tab/ESC Alt-Shift-Tab/ESC
            {
                WPARAM wParamTmp;

                wParamTmp = UserGetKeyState(VK_SHIFT) & 0x8000 ? SC_PREVWINDOW : SC_NEXTWINDOW;
                TRACE("Send WM_SYSCOMMAND Alt-Tab/ESC Alt-Shift-Tab/ESC\n");
                co_IntSendMessage( Msg->hwnd, WM_SYSCOMMAND, wParamTmp, Msg->wParam );

                //// Keep looping.
                Ret = FALSE;
                //// Skip the rest.
                goto Exit;
            }
        }
    }

    if (co_HOOK_CallHooks( WH_KEYBOARD,
                          *RemoveMessages ? HC_ACTION : HC_NOREMOVE,
                           LOWORD(Msg->wParam),
                           Msg->lParam))
    {
        /* skip this message */
        co_HOOK_CallHooks( WH_CBT,
                           HCBT_KEYSKIPPED,
                           LOWORD(Msg->wParam),
                           Msg->lParam );

        ERR("KeyboardMessage WH_KEYBOARD Call Hook return!\n");

        *RemoveMessages = TRUE;

        Ret = FALSE;
    }

    if (pWnd && Ret && *RemoveMessages && bKeyUpDown && !(pti->TIF_flags & TIF_DISABLEIME))
    {
        ImmRet = IntImmProcessKey(pti->MessageQueue, pWnd, uMsg, Msg->wParam, Msg->lParam);
        if (ImmRet)
        {
            if ( ImmRet & (IPHK_HOTKEY|IPHK_SKIPTHISKEY) )
            {
               ImmRet = 0;
            }
            if ( ImmRet & IPHK_PROCESSBYIME )
            {
               Msg->wParam = VK_PROCESSKEY;
            }
        }
    }
Exit:
    if (pWnd) UserDerefObjectCo(pWnd);
    return Ret;
}

BOOL co_IntProcessHardwareMessage(MSG* Msg, BOOL* RemoveMessages, BOOL* NotForUs, LONG_PTR ExtraInfo, UINT first, UINT last)
{
    if ( IS_MOUSE_MESSAGE(Msg->message))
    {
        return co_IntProcessMouseMessage(Msg, RemoveMessages, NotForUs, ExtraInfo, first, last);
    }
    else if ( IS_KBD_MESSAGE(Msg->message))
    {
        return co_IntProcessKeyboardMessage(Msg, RemoveMessages);
    }

    return TRUE;
}

/* check whether a message filter contains at least one potential hardware message */
static INT FASTCALL
filter_contains_hw_range( UINT first, UINT last )
{
   /* hardware message ranges are (in numerical order):
    *   WM_NCMOUSEFIRST .. WM_NCMOUSELAST
    *   WM_INPUT .. WM_KEYLAST
    *   WM_MOUSEFIRST .. WM_MOUSELAST
    */
    if (!last) --last;
    if (last < WM_NCMOUSEFIRST) return 0;
    if (first > WM_NCMOUSELAST && last < WM_INPUT) return 0;
    if (first > WM_KEYLAST && last < WM_MOUSEFIRST) return 0;
    if (first > WM_MOUSELAST) return 0;
    return 1;
}

/* check whether message is in the range of mouse messages */
static inline BOOL is_mouse_message( UINT message )
{
    return ( //( message >= WM_NCMOUSEFIRST && message <= WM_NCMOUSELAST )   || This seems to break tests...
             ( message >= WM_MOUSEFIRST   && message <= WM_MOUSELAST )     ||
             ( message >= WM_XBUTTONDOWN  && message <= WM_XBUTTONDBLCLK ) ||
             ( message >= WM_MBUTTONDOWN  && message <= WM_MBUTTONDBLCLK ) ||
             ( message >= WM_LBUTTONDOWN  && message <= WM_RBUTTONDBLCLK ) );
}

static VOID
MsqBeginHardwareWalk(PTHREADINFO pti, PUSER_MESSAGE_QUEUE MessageQueue, PMSQ_HW_WALK Walk)
{
   /* The queue outlives the walk even if the thread attaches away and the queue is destroyed */
   IntReferenceMessageQueue(MessageQueue);
   Walk->MessageQueue = MessageQueue;
   Walk->pNext = MessageQueue->HardwareMessagesListHead.Flink;
   Walk->pCurrent = NULL;
   InsertHeadList(&MessageQueue->HwWalkListHead, &Walk->QueueLink);
   Walk->pPrevOfThread = pti->pHwWalks;
   pti->pHwWalks = Walk;
}

static VOID
MsqEndHardwareWalk(PTHREADINFO pti, PMSQ_HW_WALK Walk)
{
   PUSER_MESSAGE_QUEUE MessageQueue = Walk->MessageQueue;

   ASSERT(pti->pHwWalks == Walk);
   pti->pHwWalks = Walk->pPrevOfThread;
   RemoveEntryList(&Walk->QueueLink);
   IntDereferenceMessageQueue(MessageQueue);
}

/* A thread that ends inside a callout of a peek leaves its walks behind on its stack
   (thread cleanup resets cEnterCount and the stack swap state itself) */
VOID FASTCALL
MsqRundownHardwareWalks(PTHREADINFO pti)
{
   PMSQ_HW_WALK Walk;

   while ((Walk = pti->pHwWalks) != NULL)
   {
      PUSER_MESSAGE_QUEUE MessageQueue = Walk->MessageQueue;

      pti->pHwWalks = Walk->pPrevOfThread;
      if (MessageQueue->ptiSysLock == pti)
         MessageQueue->ptiSysLock = NULL;
      RemoveEntryList(&Walk->QueueLink);
      IntDereferenceMessageQueue(MessageQueue);
   }
}

/* Is the message held by a walk (any thread, any nesting level) while it calls out? */
BOOL FASTCALL
MsqHardwareMessageInPlay(PUSER_MESSAGE_QUEUE MessageQueue, PUSER_MESSAGE Message)
{
   PLIST_ENTRY Entry;

   for (Entry = MessageQueue->HwWalkListHead.Flink;
        Entry != &MessageQueue->HwWalkListHead;
        Entry = Entry->Flink)
   {
      if (CONTAINING_RECORD(Entry, MSQ_HW_WALK, QueueLink)->pCurrent == Message)
         return TRUE;
   }
   return FALSE;
}

/* The only way a node leaves a hardware message list: the walks step over it first */
VOID FASTCALL
MsqDestroyHardwareMessage(PUSER_MESSAGE_QUEUE MessageQueue, PUSER_MESSAGE Message)
{
   PLIST_ENTRY Entry;

   for (Entry = MessageQueue->HwWalkListHead.Flink;
        Entry != &MessageQueue->HwWalkListHead;
        Entry = Entry->Flink)
   {
      PMSQ_HW_WALK Walk = CONTAINING_RECORD(Entry, MSQ_HW_WALK, QueueLink);

      if (Walk->pNext == &Message->ListEntry)
         Walk->pNext = Message->ListEntry.Flink;
      if (Walk->pCurrent == Message)
         Walk->pCurrent = NULL;
   }
   MsqDestroyMessage(Message);
}

BOOL APIENTRY
co_MsqPeekHardwareMessage(IN PTHREADINFO pti,
                         IN BOOL Remove,
                         IN PWND Window,
                         IN UINT MsgFilterLow,
                         IN UINT MsgFilterHigh,
                         IN UINT QSflags,
                         OUT MSG* pMsg)
{
   BOOL AcceptMessage, NotForUs;
   PUSER_MESSAGE CurrentMessage;
   MSG msg;
   DWORD QS_Flags;
   LONG_PTR ExtraInfo;
   MSG clk_msg;
   BOOL Ret = FALSE;
   PTHREADINFO ptiOwner;
   MSQ_HW_WALK Walk;
   PUSER_MESSAGE_QUEUE MessageQueue = pti->MessageQueue;

   if (!filter_contains_hw_range( MsgFilterLow, MsgFilterHigh )) return FALSE;

   if (IsListEmpty(&MessageQueue->HardwareMessagesListHead)) return FALSE;

   if (!MessageQueue->ptiSysLock)
   {
      MessageQueue->ptiSysLock = pti;
      pti->pcti->CTI_flags |= CTI_THREADSYSLOCK;
   }

   if (MessageQueue->ptiSysLock != pti)
   {
      ERR("Thread Q is locked to ptiSysLock 0x%p pti 0x%p\n",MessageQueue->ptiSysLock,pti);
      return FALSE;
   }

   MsqBeginHardwareWalk(pti, MessageQueue, &Walk);

   while (Walk.pNext != &MessageQueue->HardwareMessagesListHead)
   {
      CurrentMessage = CONTAINING_RECORD(Walk.pNext, USER_MESSAGE, ListEntry);
      Walk.pNext = Walk.pNext->Flink;

      /* An outer peek (or another thread's) is processing it */
      if (MsqHardwareMessageInPlay(MessageQueue, CurrentMessage))
      {
         TRACE("Skip this message due to it is in play!\n");
         continue;
      }
/*
 MSDN:
 1: any window that belongs to the current thread, and any messages on the current thread's message queue whose hwnd value is NULL.
 2: retrieves only messages on the current thread's message queue whose hwnd value is NULL.
 3: handle to the window whose messages are to be retrieved.
 */
      if ( ( !Window || // 1
            ( Window == PWND_BOTTOM && CurrentMessage->Msg.hwnd == NULL ) || // 2
            ( Window != PWND_BOTTOM && UserHMGetHandle(Window) == CurrentMessage->Msg.hwnd ) || // 3
            ( is_mouse_message(CurrentMessage->Msg.message) ) ) && // Null window for anything mouse.
            ( CurrentMessage->QS_Flags & QSflags ) )
      {
         Walk.pCurrent = CurrentMessage;

         msg = CurrentMessage->Msg;
         ExtraInfo = CurrentMessage->ExtraInfo;
         QS_Flags = CurrentMessage->QS_Flags;
         clk_msg = MessageQueue->msgDblClk;

         NotForUs = FALSE;

         UpdateKeyStateFromMsg(MessageQueue, &msg);
         /* Hooks and sent messages run here: nested peeks, retirements, attaching and the
            thread's end can all remove nodes, this one included */
         AcceptMessage = co_IntProcessHardwareMessage(&msg, &Remove, &NotForUs, ExtraInfo, MsgFilterLow, MsgFilterHigh);

         CurrentMessage = Walk.pCurrent;
         Walk.pCurrent = NULL;

         if (pti->MessageQueue != MessageQueue)
         {
            /* The thread attached to or detached from another queue meanwhile: what is
               left in this one is no longer its input */
            Ret = FALSE;
            break;
         }

         if (!CurrentMessage)
         {
            /* Taken by a nested peek or dropped: whoever removed it did its accounting */
            continue;
         }

         if (!NotForUs && (MsgFilterLow != 0 || MsgFilterHigh != 0))
         {
             /* Don't return message if not in range */
             if (msg.message < MsgFilterLow || msg.message > MsgFilterHigh)
             {
                 MessageQueue->msgDblClk = clk_msg;
                 continue;
             }
         }

         if (Remove)
         {
             /* The raw input wake bit was counted for the thread the message was posted to,
                which differs from the reader when threads share an attached queue */
             ptiOwner = CurrentMessage->pti ? CurrentMessage->pti : pti;
             MsqDestroyHardwareMessage(MessageQueue, CurrentMessage);
             ClearMsgBitsMask(pti, QS_Flags & ~QS_RAWINPUT);
             if (QS_Flags & QS_RAWINPUT)
                ClearMsgBitsMask(ptiOwner, QS_RAWINPUT);
         }

         if (NotForUs)
         {
            Ret = FALSE;
            break;
         }

         if (AcceptMessage)
         {
            *pMsg = msg;
            // Fix all but one wine win:test_GetMessagePos WM_TIMER tests. See PostTimerMessages.
            if (!RtlEqualMemory(&pti->ptLast, &msg.pt, sizeof(POINT)))
            {
               pti->TIF_flags |= TIF_MSGPOSCHANGED;
            }
            pti->timeLast = msg.time;
            pti->ptLast   = msg.pt;
            MessageQueue->ExtraInfo = ExtraInfo;
            Ret = TRUE;
            break;
         }
      }
   }

   if (MessageQueue->ptiSysLock == pti)
      MessageQueue->ptiSysLock = NULL;
   pti->pcti->CTI_flags &= ~CTI_THREADSYSLOCK;

   MsqEndHardwareWalk(pti, &Walk);

   return Ret;
}

BOOLEAN APIENTRY
MsqPeekMessage(IN PTHREADINFO pti,
                  IN BOOLEAN Remove,
                  IN PWND Window,
                  IN UINT MsgFilterLow,
                  IN UINT MsgFilterHigh,
                  IN UINT QSflags,
                  OUT LONG_PTR *ExtraInfo,
                  OUT DWORD *dwQEvent,
                  OUT PMSG Message)
{
   PUSER_MESSAGE CurrentMessage;
   PLIST_ENTRY ListHead;
   DWORD QS_Flags;
   BOOL Ret = FALSE;

   ListHead = pti->PostedMessagesListHead.Flink;

   if (IsListEmpty(ListHead)) return FALSE;

   while(ListHead != &pti->PostedMessagesListHead)
   {
      CurrentMessage = CONTAINING_RECORD(ListHead, USER_MESSAGE, ListEntry);
      ListHead = ListHead->Flink;
/*
 MSDN:
 1: any window that belongs to the current thread, and any messages on the current thread's message queue whose hwnd value is NULL.
 2: retrieves only messages on the current thread's message queue whose hwnd value is NULL.
 3: handle to the window whose messages are to be retrieved.
 */
      if ( ( !Window || // 1
            ( Window == PWND_BOTTOM && CurrentMessage->Msg.hwnd == NULL ) || // 2
            ( Window != PWND_BOTTOM && UserHMGetHandle(Window) == CurrentMessage->Msg.hwnd ) ) && // 3
            ( ( ( MsgFilterLow == 0 && MsgFilterHigh == 0 ) && CurrentMessage->QS_Flags & QSflags ) ||
              ( MsgFilterLow <= CurrentMessage->Msg.message && MsgFilterHigh >= CurrentMessage->Msg.message ) ) )
      {
         *Message   = CurrentMessage->Msg;
         *ExtraInfo = CurrentMessage->ExtraInfo;
         QS_Flags   = CurrentMessage->QS_Flags;
         if (dwQEvent) *dwQEvent = CurrentMessage->dwQEvent;

         if (Remove)
         {
             if (CurrentMessage->pti != NULL)
             {
                MsqDestroyMessage(CurrentMessage);
             }
             ClearMsgBitsMask(pti, QS_Flags);
         }
         Ret = TRUE;
         break;
      }
   }

   return Ret;
}

NTSTATUS FASTCALL
co_MsqWaitForNewMessages(PTHREADINFO pti, PWND WndFilter,
                         UINT MsgFilterMin, UINT MsgFilterMax)
{
   NTSTATUS ret = STATUS_SUCCESS;

   // Post mouse moves before waiting for messages.
   if (pti->MessageQueue->QF_flags & QF_MOUSEMOVED)
   {
      IntCoalesceMouseMove(pti);
   }

   /* The queue has nothing for the caller and the thread is about to wait for input: the foreground
    * idle hook runs now, before the wait state is set, as it does in MsgWaitForMultipleObjectsEx */
   IdlePing();

   /* The thread waits for input from here until it owns the lock again */
   pti->pcti->fsWakeMask = GetWakeMask(MsgFilterMin, MsgFilterMax);

   UserLeaveCo();

   ZwYieldExecution(); // Let someone else run!

   ret = KeWaitForSingleObject( pti->pEventQueueServer,
                                UserRequest,
                                UserMode,
                                FALSE,
                                NULL );
   UserEnterCo();

   if (pti->pcti->fsWakeMask & QS_INPUT)
      pti->pcti->timeLastRead = EngGetTickCount32();
   pti->pcti->fsWakeMask = 0;
   if ( ret == STATUS_USER_APC )
   {
      TRACE("MWFNW User APC\n");
      co_IntDeliverUserAPC();
   }
   return ret;
}

BOOL FASTCALL
MsqIsHung(PTHREADINFO pti, DWORD TimeOut)
{
    DWORD dwTimeStamp = EngGetTickCount32();
    if (dwTimeStamp - pti->pcti->timeLastRead > TimeOut &&
       !(pti->pcti->fsWakeMask & QS_INPUT) &&
       !PsGetThreadFreezeCount(pti->pEThread))
    {
        TRACE("\nMsqIsHung(pti %p, TimeOut %lu)\n"
            "pEThread %p, ThreadsProcess %p, ImageFileName '%s'\n"
            "dwTimeStamp = %lu\n"
            "pti->pcti->timeLastRead = %lu\n"
            "pti->timeLast = %lu\n"
            "PsGetThreadFreezeCount(pti->pEThread) = %lu\n",
            pti, TimeOut,
            pti->pEThread,
            pti->pEThread ? pti->pEThread->ThreadsProcess : NULL,
            (pti->pEThread && pti->pEThread->ThreadsProcess)
                ? pti->pEThread->ThreadsProcess->ImageFileName : "(None)",
            dwTimeStamp,
            pti->pcti->timeLastRead,
            pti->timeLast,
            PsGetThreadFreezeCount(pti->pEThread));

        return TRUE;
    }

   return FALSE;
}

/*
 * SMTO_ABORTIFHUNG and SMTO_NOTIMEOUTIFNOTHUNG give a starting process the first
 * MSQ_APPSTARTING_TIMEOUT ms. After that its clock runs from the end of that
 * time at the earliest, as MsqIsHung does from then on. IsHungAppWindow does not
 * make this exception. Elapsed times are unsigned so that a tick count wrap is harmless.
 */
BOOL FASTCALL
MsqIsHungForSend(PTHREADINFO pti, DWORD TimeOut)
{
    PPROCESSINFO ppi = pti->ppi;
    DWORD dwNow = EngGetTickCount32();
    DWORD dwSinceRead = dwNow - pti->pcti->timeLastRead;

    if (ppi->W32PF_flags & W32PF_APPSTARTING)
    {
        DWORD dwAge = dwNow - ppi->AppStartTick;

        if (dwAge < MSQ_APPSTARTING_TIMEOUT)
            return FALSE;

        /* Time since the end of the startup time, if that is shorter */
        if (dwAge - MSQ_APPSTARTING_TIMEOUT < dwSinceRead)
            dwSinceRead = dwAge - MSQ_APPSTARTING_TIMEOUT;

        /* From here on the startup time makes no difference for any thread */
        if (dwAge - MSQ_APPSTARTING_TIMEOUT > MSQ_HUNG)
            ppi->W32PF_flags &= ~W32PF_APPSTARTING;
    }

    return (dwSinceRead > TimeOut) &&
           !(pti->pcti->fsWakeMask & QS_INPUT) &&
           !PsGetThreadFreezeCount(pti->pEThread);
}

BOOL FASTCALL
IsThreadSuspended(PTHREADINFO pti)
{
   if (pti->pEThread)
   {
      BOOL Ret = TRUE;
      if (!(pti->pEThread->Tcb.SuspendCount) && !PsGetThreadFreezeCount(pti->pEThread)) Ret = FALSE;
      return Ret;
   }
   return FALSE;
}

VOID
CALLBACK
HungAppSysTimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
   DoTheScreenSaver();
   TRACE("HungAppSysTimerProc\n");
   // Process list of windows that are hung and waiting.
}

BOOLEAN FASTCALL
MsqInitializeMessageQueue(PTHREADINFO pti, PUSER_MESSAGE_QUEUE MessageQueue)
{
   InitializeListHead(&MessageQueue->HardwareMessagesListHead); // Keep here!
   InitializeListHead(&MessageQueue->HwWalkListHead);
   InitializeListHead(&MessageQueue->RawInputListHead);
   MessageQueue->cRawInput = 0;
   MessageQueue->spwndFocus = NULL;
   MessageQueue->iCursorLevel = 0;
   MessageQueue->CursorObject = SYSTEMCUR(WAIT); // See test_initial_cursor.
   if (MessageQueue->CursorObject)
   {
      TRACE("Default cursor hcur %p\n",UserHMGetHandle(MessageQueue->CursorObject));
      UserReferenceObject(MessageQueue->CursorObject);
   }
   RtlCopyMemory(MessageQueue->afKeyState, gafAsyncKeyState, sizeof(gafAsyncKeyState));
   MessageQueue->ptiMouse = pti;
   MessageQueue->ptiKeyboard = pti;
   MessageQueue->cThreads++;

   return TRUE;
}

VOID FASTCALL
MsqCleanupThreadMsgs(PTHREADINFO pti)
{
   PLIST_ENTRY CurrentEntry;
   PUSER_MESSAGE CurrentMessage;
   PUSER_SENT_MESSAGE CurrentSentMessage;

   TRACE("MsqCleanupThreadMsgs %p\n",pti);

   // Clear it all out.
   if (pti->pcti)
   {
       pti->pcti->fsWakeBits = 0;
       pti->pcti->fsChangeBits = 0;
   }

   pti->nCntsQBits[QSRosKey] = 0;
   pti->nCntsQBits[QSRosMouseMove] = 0;
   pti->nCntsQBits[QSRosMouseButton] = 0;
   pti->nCntsQBits[QSRosPostMessage] = 0;
   pti->nCntsQBits[QSRosSendMessage] = 0;
   pti->nCntsQBits[QSRosHotKey] = 0;
   pti->nCntsQBits[QSRosEvent] = 0;

   /* cleanup posted messages */
   while (!IsListEmpty(&pti->PostedMessagesListHead))
   {
      CurrentEntry = pti->PostedMessagesListHead.Flink;
      CurrentMessage = CONTAINING_RECORD(CurrentEntry, USER_MESSAGE, ListEntry);
      ERR("Thread Cleanup Post Messages %p\n",CurrentMessage);
      if (CurrentMessage->dwQEvent)
      {
         if (CurrentMessage->dwQEvent == POSTEVENT_NWE)
         {
            ExFreePoolWithTag( (PVOID)CurrentMessage->ExtraInfo, TAG_HOOK);
         }
      }
      MsqDestroyMessage(CurrentMessage);
   }

   /* remove the messages that have not yet been dispatched */
   while (!IsListEmpty(&pti->SentMessagesListHead))
   {
      CurrentEntry = pti->SentMessagesListHead.Flink;
      CurrentSentMessage = CONTAINING_RECORD(CurrentEntry, USER_SENT_MESSAGE, ListEntry);

      ERR("Thread Cleanup Sent Messages %p\n",CurrentSentMessage);

      /* wake the sender's thread */
      if (CurrentSentMessage->pkCompletionEvent != NULL)
      {
         KeSetEvent(CurrentSentMessage->pkCompletionEvent, IO_NO_INCREMENT, FALSE);
      }

      if (CurrentSentMessage->HasPackedLParam)
      {
         if (CurrentSentMessage->Msg.lParam)
            ExFreePool((PVOID)CurrentSentMessage->Msg.lParam);
      }

      /* free the message */
      FreeUserMessage(CurrentSentMessage);
   }

   // Process Trouble Message List
   if (!IsListEmpty(&usmList))
   {
      CurrentEntry = usmList.Flink;
      while (CurrentEntry != &usmList)
      {
         CurrentSentMessage = CONTAINING_RECORD(CurrentEntry, USER_SENT_MESSAGE, ListEntry);
         CurrentEntry = CurrentEntry->Flink;

         TRACE("Found troubled messages %p on the list\n",CurrentSentMessage);

         if ( pti == CurrentSentMessage->ptiReceiver )
         {
            if (CurrentSentMessage->HasPackedLParam)
            {
               if (CurrentSentMessage->Msg.lParam)
                  ExFreePool((PVOID)CurrentSentMessage->Msg.lParam);
            }

            /* free the message */
            FreeUserMessage(CurrentSentMessage);
         }
         else if ( pti == CurrentSentMessage->ptiSender &&
                   !(CurrentSentMessage->flags & SMF_RECEIVEDMESSAGE) )
         {
            /* Withdrawn before the receiver took it (timeout or sender death): it is on no
               receiver's list, so only this list still knows it. Do not leave it to the
               receiver's own cleanup, a long-lived receiver would collect them. */
            FreeUserMessage(CurrentSentMessage);
         }
         else if ( pti == CurrentSentMessage->ptiSender ||
                   pti == CurrentSentMessage->ptiCallBackSender )
         {
            /* This thread sent the message and is dying while the receiver still holds
               it in flight. Mark it so the receiver does not hand the result back to a
               thread that no longer exists (T131). */
            CurrentSentMessage->flags |= SMF_SENDERDIED;

            // Determine whether this message is being processed or not.
            if ((CurrentSentMessage->flags & (SMF_RECEIVERBUSY|SMF_RECEIVEDMESSAGE)) != SMF_RECEIVEDMESSAGE)
            {
               CurrentSentMessage->flags |= SMF_RECEIVERFREE;
            }

            if (!(CurrentSentMessage->flags & SMF_RECEIVERFREE))
            {

               if (CurrentSentMessage->HasPackedLParam)
               {
                  if (CurrentSentMessage->Msg.lParam)
                     ExFreePool((PVOID)CurrentSentMessage->Msg.lParam);
               }

               /* free the message */
               FreeUserMessage(CurrentSentMessage);
            }
         }
      }
   }
}

/*
   Retire one WM_INPUT message of a queue: free its packet, give its wake bit back to the
   thread it was posted to, and drop the message (walks in progress step over it).
   Called under the USER lock.
 */
VOID FASTCALL
MsqRetireRawInputMessage(PUSER_MESSAGE_QUEUE MessageQueue, PUSER_MESSAGE Message)
{
   ClearMsgBitsMask(Message->pti, QS_RAWINPUT);
   UserFreeRawInput(MessageQueue, (HRAWINPUT)Message->Msg.lParam);
   MsqDestroyHardwareMessage(MessageQueue, Message);
}

/* Drop the WM_INPUT messages posted to a thread from the queue it leaves */
VOID FASTCALL
MsqPurgeRawInputOfThread(PTHREADINFO pti)
{
   PUSER_MESSAGE_QUEUE MessageQueue = pti->MessageQueue;
   PLIST_ENTRY CurrentEntry = MessageQueue->HardwareMessagesListHead.Flink;
   PUSER_MESSAGE CurrentMessage;

   if (pti->hPrevRawInput)
   {
      UserFreeRawInput(MessageQueue, pti->hPrevRawInput);
      pti->hPrevRawInput = NULL;
   }

   while (CurrentEntry != &MessageQueue->HardwareMessagesListHead)
   {
      CurrentMessage = CONTAINING_RECORD(CurrentEntry, USER_MESSAGE, ListEntry);
      CurrentEntry = CurrentEntry->Flink;

      if (CurrentMessage->pti == pti && CurrentMessage->Msg.message == WM_INPUT &&
          (CurrentMessage->QS_Flags & QS_RAWINPUT))
      {
         MsqRetireRawInputMessage(MessageQueue, CurrentMessage);
      }
   }
}

VOID FASTCALL
MsqCleanupMessageQueue(PTHREADINFO pti)
{
   PUSER_MESSAGE_QUEUE MessageQueue;
   PLIST_ENTRY CurrentEntry;
   PUSER_MESSAGE CurrentMessage;

   MessageQueue = pti->MessageQueue;
   MessageQueue->cThreads--;

   if (pti->hPrevRawInput)
   {
      UserFreeRawInput(MessageQueue, pti->hPrevRawInput);
      pti->hPrevRawInput = NULL;
   }

   if (MessageQueue->cThreads)
   {
      if (MessageQueue->ptiSysLock == pti) MessageQueue->ptiSysLock = NULL;

      /* Raw input messages keep a pointer to the thread they were posted to
         (wake bit accounting), so none may outlive that thread */
      MsqPurgeRawInputOfThread(pti);
   }

   if (MessageQueue->cThreads == 0) //// Fix a crash related to CORE-10471 testing.
   {
      /* cleanup posted messages */
      while (!IsListEmpty(&MessageQueue->HardwareMessagesListHead))
      {
         CurrentEntry = MessageQueue->HardwareMessagesListHead.Flink;
         CurrentMessage = CONTAINING_RECORD(CurrentEntry, USER_MESSAGE, ListEntry);
         ERR("MQ Cleanup Post Messages %p\n",CurrentMessage);
         MsqDestroyHardwareMessage(MessageQueue, CurrentMessage);
      }

      UserCleanupRawInput(MessageQueue);
   } ////

   if (MessageQueue->CursorObject)
   {
       PCURICON_OBJECT pCursor = MessageQueue->CursorObject;

       /* Change to another cursor if we going to dereference current one
          Note: we can't use UserSetCursor because it uses current thread
                message queue instead of queue given for cleanup */
       if (IntGetSysCursorInfo()->CurrentCursorObject == pCursor)
       {
           HDC hdcScreen;

           /* Get the screen DC */
           hdcScreen = IntGetScreenDC();
           if (hdcScreen)
               GreMovePointer(hdcScreen, -1, -1);
           IntGetSysCursorInfo()->CurrentCursorObject = NULL;
       }

       TRACE("DereferenceObject pCursor\n");
       UserDereferenceObject(pCursor);
   }

   if (gpqForeground == MessageQueue)
   {
      IntSetFocusMessageQueue(NULL);
   }
   if (gpqForegroundPrev == MessageQueue)
   {
      gpqForegroundPrev = NULL;
   }
   if (gpqCursor == MessageQueue)
   {
      gpqCursor = NULL;
   }
}

PUSER_MESSAGE_QUEUE FASTCALL
MsqCreateMessageQueue(PTHREADINFO pti)
{
   PUSER_MESSAGE_QUEUE MessageQueue;

   MessageQueue = ExAllocatePoolWithTag(NonPagedPool,
                                        sizeof(*MessageQueue),
                                        USERTAG_Q);

   if (!MessageQueue)
   {
      return NULL;
   }

   RtlZeroMemory(MessageQueue, sizeof(*MessageQueue));
   /* hold at least one reference until it'll be destroyed */
   IntReferenceMessageQueue(MessageQueue);
   /* initialize the queue */
   if (!MsqInitializeMessageQueue(pti, MessageQueue))
   {
      IntDereferenceMessageQueue(MessageQueue);
      return NULL;
   }

   return MessageQueue;
}

VOID FASTCALL
MsqDestroyMessageQueue(_In_ PTHREADINFO pti)
{
   PDESKTOP desk;
   PUSER_MESSAGE_QUEUE MessageQueue = pti->MessageQueue;

   NT_ASSERT(MessageQueue != NULL);
   MessageQueue->QF_flags |= QF_INDESTROY;

   /* remove the message queue from any desktops */
   if ((desk = InterlockedExchangePointer((PVOID*)&MessageQueue->Desktop, 0)))
   {
      (void)InterlockedExchangePointer((PVOID*)&desk->ActiveMessageQueue, 0);
      IntDereferenceMessageQueue(MessageQueue);
   }

   /* clean it up */
   MsqCleanupMessageQueue(pti);

   /* decrease the reference counter, if it hits zero, the queue will be freed */
   _PRAGMA_WARNING_SUPPRESS(__WARNING_USING_UNINIT_VAR);
   IntDereferenceMessageQueue(MessageQueue);
}

LPARAM FASTCALL
MsqSetMessageExtraInfo(LPARAM lParam)
{
   LPARAM Ret;
   PTHREADINFO pti;
   PUSER_MESSAGE_QUEUE MessageQueue;

   pti = PsGetCurrentThreadWin32Thread();
   MessageQueue = pti->MessageQueue;
   if(!MessageQueue)
   {
      return 0;
   }

   Ret = MessageQueue->ExtraInfo;
   MessageQueue->ExtraInfo = lParam;

   return Ret;
}

LPARAM FASTCALL
MsqGetMessageExtraInfo(VOID)
{
   PTHREADINFO pti;
   PUSER_MESSAGE_QUEUE MessageQueue;

   pti = PsGetCurrentThreadWin32Thread();
   MessageQueue = pti->MessageQueue;
   if(!MessageQueue)
   {
      return 0;
   }

   return MessageQueue->ExtraInfo;
}

// ReplyMessage is called by the thread receiving the window message.
BOOL FASTCALL
co_MsqReplyMessage( LRESULT lResult )
{
   PUSER_SENT_MESSAGE Message;
   PTHREADINFO pti;

   pti = PsGetCurrentThreadWin32Thread();
   Message = pti->pusmCurrent;

   if (!Message) return FALSE;

   if (Message->QS_Flags & QS_SMRESULT) return FALSE;

   //     SendMessageXxx  || Callback msg and not a notify msg
   if (Message->ptiSender || Message->CompletionCallback)
   {
      Message->lResult = lResult;
      Message->QS_Flags |= QS_SMRESULT;
   // See co_MsqDispatchOneSentMessage, change bits already accounted for and cleared and this msg is going away..
   }
   return TRUE;
}

HWND FASTCALL
MsqSetStateWindow(PTHREADINFO pti, ULONG Type, HWND hWnd)
{
   HWND Prev;
   PUSER_MESSAGE_QUEUE MessageQueue;

   MessageQueue = pti->MessageQueue;

   switch(Type)
   {
      case MSQ_STATE_CAPTURE:
         Prev = MessageQueue->spwndCapture ? UserHMGetHandle(MessageQueue->spwndCapture) : 0;
         MessageQueue->spwndCapture = ValidateHwndNoErr(hWnd);
         return Prev;
      case MSQ_STATE_ACTIVE:
         Prev = MessageQueue->spwndActive ? UserHMGetHandle(MessageQueue->spwndActive) : 0;
         MessageQueue->spwndActive = ValidateHwndNoErr(hWnd);
         return Prev;
      case MSQ_STATE_FOCUS:
         Prev = MessageQueue->spwndFocus ? UserHMGetHandle(MessageQueue->spwndFocus) : 0;
         MessageQueue->spwndFocus = ValidateHwndNoErr(hWnd);
         return Prev;
      case MSQ_STATE_MENUOWNER:
         Prev = MessageQueue->MenuOwner;
         MessageQueue->MenuOwner = hWnd;
         return Prev;
      case MSQ_STATE_MOVESIZE:
         Prev = MessageQueue->MoveSize;
         MessageQueue->MoveSize = hWnd;
         return Prev;
      case MSQ_STATE_CARET:
         Prev = MessageQueue->CaretInfo.hWnd;
         MessageQueue->CaretInfo.hWnd = hWnd;
         return Prev;
   }

   return NULL;
}

VOID FASTCALL
MsqReleaseModifierKeys(PUSER_MESSAGE_QUEUE MessageQueue)
{
    WORD ModifierKeys[] = { VK_LCONTROL, VK_RCONTROL, VK_CONTROL,
                            VK_LMENU,    VK_RMENU,    VK_MENU,
                            VK_LSHIFT,   VK_RSHIFT,   VK_SHIFT };
    UINT i;

    for (i = 0; i < _countof(ModifierKeys); ++i)
    {
        if (IS_KEY_DOWN(MessageQueue->afKeyState, ModifierKeys[i]))
            SET_KEY_DOWN(MessageQueue->afKeyState, ModifierKeys[i], FALSE);
    }
}

SHORT
APIENTRY
NtUserGetKeyState(INT key)
{
   DWORD Ret;

   UserEnterShared();

   Ret = UserGetKeyState(key);

   UserLeave();

   return (SHORT)Ret;
}


DWORD
APIENTRY
NtUserGetKeyboardState(LPBYTE lpKeyState)
{
   DWORD i, ret = TRUE;
   PTHREADINFO pti;
   PUSER_MESSAGE_QUEUE MessageQueue;

   UserEnterShared();

   pti = PsGetCurrentThreadWin32Thread();
   MessageQueue = pti->MessageQueue;

   _SEH2_TRY
   {
       /* Probe and copy key state to an array */
       ProbeForWrite(lpKeyState, 256 * sizeof(BYTE), 1);
       for (i = 0; i < 256; ++i)
       {
           lpKeyState[i] = 0;
           if (IS_KEY_DOWN(MessageQueue->afKeyState, i))
               lpKeyState[i] |= KS_DOWN_BIT;
           if (IS_KEY_LOCKED(MessageQueue->afKeyState, i))
               lpKeyState[i] |= KS_LOCK_BIT;
       }
   }
   _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
   {
       SetLastNtError(_SEH2_GetExceptionCode());
       ret = FALSE;
   }
   _SEH2_END;

   UserLeave();

   return ret;
}

BOOL
APIENTRY
NtUserSetKeyboardState(LPBYTE pKeyState)
{
   UINT i;
   BOOL bRet = TRUE;
   PTHREADINFO pti;
   PUSER_MESSAGE_QUEUE MessageQueue;

   UserEnterExclusive();

   pti = PsGetCurrentThreadWin32Thread();
   MessageQueue = pti->MessageQueue;

   _SEH2_TRY
   {
       ProbeForRead(pKeyState, 256 * sizeof(BYTE), 1);
       for (i = 0; i < 256; ++i)
       {
            SET_KEY_DOWN(MessageQueue->afKeyState, i, pKeyState[i] & KS_DOWN_BIT);
            SET_KEY_LOCKED(MessageQueue->afKeyState, i, pKeyState[i] & KS_LOCK_BIT);
       }
   }
   _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
   {
       SetLastNtError(_SEH2_GetExceptionCode());
       bRet = FALSE;
   }
   _SEH2_END;

   UserLeave();

   return bRet;
}

/* EOF */
