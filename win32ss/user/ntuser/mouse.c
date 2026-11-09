/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * PURPOSE:          Mouse functions
 * FILE:             win32ss/user/ntuser/mouse.c
 * PROGRAMERS:       Casper S. Hornstrup (chorns@users.sourceforge.net)
 *                   Rafal Harabien (rafalh@reactos.org)
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(UserInput);

MOUSEMOVEPOINT gMouseHistoryOfMoves[64];
INT gcMouseHistoryOfMoves = 0;

/*
 * UserGetMouseButtonsState
 *
 * Returns bitfield of MK_* flags used in mouse messages
 */
WORD FASTCALL
UserGetMouseButtonsState(VOID)
{
    WORD wRet = 0;

    wRet = IntGetSysCursorInfo()->ButtonsDown;

    if (IS_KEY_DOWN(gafAsyncKeyState, VK_SHIFT)) wRet |= MK_SHIFT;
    if (IS_KEY_DOWN(gafAsyncKeyState, VK_CONTROL)) wRet |= MK_CONTROL;

    return wRet;
}

VOID NTAPI
UserRawInputMouseProcess(PINPUT_DEVICE_INFO pDeviceInfo, PMOUSE_INPUT_DATA mid)
{
    RAWMOUSE rm = {0};

    /* MOUSE_MOVE_* and the button flags use the same values as the raw input ones */
    rm.usFlags = mid->Flags & (MOUSE_MOVE_ABSOLUTE | MOUSE_VIRTUAL_DESKTOP);
    rm.usButtonFlags = mid->ButtonFlags;
    rm.usButtonData = mid->ButtonData;
    rm.ulRawButtons = mid->RawButtons;
    rm.lLastX = mid->LastX;
    rm.lLastY = mid->LastY;
    rm.ulExtraInformation = mid->ExtraInformation;

    UserRawInputDeliver(RIM_TYPEMOUSE, pDeviceInfo ? pDeviceInfo->hRawDevice : NULL, &rm, sizeof(rm));
}

/*
 * UserProcessMouseInput
 *
 * Process raw mouse input data
 */
VOID NTAPI
UserProcessMouseInput(PINPUT_DEVICE_INFO pDeviceInfo, PMOUSE_INPUT_DATA mid)
{
    MOUSEINPUT mi;

    /* Convert MOUSE_INPUT_DATA to MOUSEINPUT. First init all fields. */
    mi.dx = mid->LastX;
    mi.dy = mid->LastY;
    mi.mouseData = 0;
    mi.dwFlags = 0;
    mi.time = 0;
    mi.dwExtraInfo = mid->ExtraInformation;

    if (RawInputEnabled == TRUE)
        UserRawInputMouseProcess(pDeviceInfo, mid);

    /* Mouse position; an absolute report always carries a position, (0, 0) included */
    if (mi.dx != 0 || mi.dy != 0 || (mid->Flags & MOUSE_MOVE_ABSOLUTE))
        mi.dwFlags |= MOUSEEVENTF_MOVE;

    /* Flags for absolute move */
    if (mid->Flags & MOUSE_MOVE_ABSOLUTE)
        mi.dwFlags |= MOUSEEVENTF_ABSOLUTE;
    if (mid->Flags & MOUSE_VIRTUAL_DESKTOP)
        mi.dwFlags |= MOUSEEVENTF_VIRTUALDESK;

    /* Left button */
    if (mid->ButtonFlags & MOUSE_LEFT_BUTTON_DOWN)
        mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
    if (mid->ButtonFlags & MOUSE_LEFT_BUTTON_UP)
        mi.dwFlags |= MOUSEEVENTF_LEFTUP;

    /* Middle button */
    if (mid->ButtonFlags & MOUSE_MIDDLE_BUTTON_DOWN)
        mi.dwFlags |= MOUSEEVENTF_MIDDLEDOWN;
    if (mid->ButtonFlags & MOUSE_MIDDLE_BUTTON_UP)
        mi.dwFlags |= MOUSEEVENTF_MIDDLEUP;

    /* Right button */
    if (mid->ButtonFlags & MOUSE_RIGHT_BUTTON_DOWN)
        mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN;
    if (mid->ButtonFlags & MOUSE_RIGHT_BUTTON_UP)
        mi.dwFlags |= MOUSEEVENTF_RIGHTUP;

    /* Note: Next buttons use mouseData field so they cannot be sent in one call */

    /* Button 4 */
    if (mid->ButtonFlags & MOUSE_BUTTON_4_DOWN)
    {
        mi.dwFlags |= MOUSEEVENTF_XDOWN;
        mi.mouseData |= XBUTTON1;
    }
    if (mid->ButtonFlags & MOUSE_BUTTON_4_UP)
    {
        mi.dwFlags |= MOUSEEVENTF_XUP;
        mi.mouseData |= XBUTTON1;
    }

    /* If mouseData is used by button 4, send input and clear mi */
    if (mi.dwFlags & (MOUSEEVENTF_XDOWN | MOUSEEVENTF_XUP))
    {
        UserSendMouseInput(&mi, FALSE);
        RtlZeroMemory(&mi, sizeof(mi));
    }

    /* Button 5 */
    if (mid->ButtonFlags & MOUSE_BUTTON_5_DOWN)
    {
        mi.mouseData |= XBUTTON2;
        mi.dwFlags |= MOUSEEVENTF_XDOWN;
    }
    if (mid->ButtonFlags & MOUSE_BUTTON_5_UP)
    {
        mi.mouseData |= XBUTTON2;
        mi.dwFlags |= MOUSEEVENTF_XUP;
    }

    /* If mouseData is used by button 5, send input and clear mi */
    if (mi.dwFlags & (MOUSEEVENTF_XDOWN | MOUSEEVENTF_XUP))
    {
        UserSendMouseInput(&mi, FALSE);
        RtlZeroMemory(&mi, sizeof(mi));
    }

    /* Mouse wheel */
    if (mid->ButtonFlags & MOUSE_WHEEL)
    {
        mi.mouseData = (DWORD)(LONG)(SHORT)mid->ButtonData;
        mi.dwFlags |= MOUSEEVENTF_WHEEL;
    }

    /* If something has changed, send input to user */
    if (mi.dwFlags)
        UserSendMouseInput(&mi, FALSE);

    /* The horizontal wheel uses mouseData as well, so it is sent on its own */
    if (mid->ButtonFlags & MOUSE_HWHEEL)
    {
        RtlZeroMemory(&mi, sizeof(mi));
        mi.mouseData = (DWORD)(LONG)(SHORT)mid->ButtonData;
        mi.dwFlags = MOUSEEVENTF_HWHEEL;
        UserSendMouseInput(&mi, FALSE);
    }
}

/*
 * IntFixMouseInputButtons
 *
 * Helper function for supporting mouse button swap function
 */
DWORD
IntFixMouseInputButtons(DWORD dwFlags)
{
    DWORD dwNewFlags;

    if (!gspv.bMouseBtnSwap)
        return dwFlags;

    /* Buttons other than left and right are not affected */
    dwNewFlags = dwFlags & ~(MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP |
                             MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_RIGHTUP);

    /* Swap buttons */
    if (dwFlags & MOUSEEVENTF_LEFTDOWN)
        dwNewFlags |= MOUSEEVENTF_RIGHTDOWN;
    if (dwFlags & MOUSEEVENTF_LEFTUP)
        dwNewFlags |= MOUSEEVENTF_RIGHTUP;
    if (dwFlags & MOUSEEVENTF_RIGHTDOWN)
        dwNewFlags |= MOUSEEVENTF_LEFTDOWN;
    if (dwFlags & MOUSEEVENTF_RIGHTUP)
        dwNewFlags |= MOUSEEVENTF_LEFTUP;

    return dwNewFlags;
}

/*
 * UserStripMouseDataFlags
 *
 * The two wheels and the X buttons all use mouseData. A call that asks for more than one of them
 * gets none of them (Windows ignores them and SendInput still counts the call); the other flags stay.
 */
DWORD FASTCALL
UserStripMouseDataFlags(DWORD dwFlags)
{
    if (((dwFlags & MOUSEEVENTF_WHEEL) != 0) + ((dwFlags & MOUSEEVENTF_HWHEEL) != 0) +
        ((dwFlags & (MOUSEEVENTF_XDOWN | MOUSEEVENTF_XUP)) != 0) > 1)
    {
        dwFlags &= ~(MOUSEEVENTF_WHEEL | MOUSEEVENTF_HWHEEL | MOUSEEVENTF_XDOWN | MOUSEEVENTF_XUP);
    }

    return dwFlags;
}

/*
 * UserClampWheelDelta
 *
 * The distance of a wheel is a signed 16 bit value, whatever the caller put into mouseData.
 */
SHORT FASTCALL
UserClampWheelDelta(DWORD mouseData)
{
    LONG lDelta = (LONG)mouseData;

    if (lDelta > 32767)
        return 32767;
    if (lDelta < -32768)
        return -32768;
    return (SHORT)lDelta;
}

/* The distance of a mouse_event / SendInput move is caller-controlled: it must not
   wrap the position (signed overflow) */
static LONG
UserSaturateAdd(LONG lPos, LONG lDelta)
{
    LONGLONG llSum = (LONGLONG)lPos + lDelta;

    if (llSum > MAXLONG)
        return MAXLONG;
    /* (MINLONG is unsigned) */
    if (llSum < -(LONGLONG)MAXLONG - 1)
        return -MAXLONG - 1;
    return (LONG)llSum;
}

/* Absolute coordinates are 0..65535 over the screen; a value outside that range is scaled
   in 64 bits, as 32 bits wrap */
static LONG
UserScaleAbsolute(LONG lCoord, int cScreen)
{
    return (LONG)(((LONGLONG)lCoord * cScreen) >> 16);
}

/*
 * UserSendMouseInput
 *
 * Process mouse input from input devices and SendInput API
 */
BOOL NTAPI
UserSendMouseInput(MOUSEINPUT *pmi, BOOL bInjected)
{
    POINT ptCursor;
    PSYSTEM_CURSORINFO pCurInfo;
    MSG Msg;
    DWORD dwFlags;

    ASSERT(pmi);

    pCurInfo = IntGetSysCursorInfo();
    ptCursor = gpsi->ptCursor;

    gppiInputProvider = ((PTHREADINFO)PsGetCurrentThreadWin32Thread())->ppi;

    /* The wheels and the X buttons all use mouseData: a call that asks for more than one of them gets none */
    dwFlags = IntFixMouseInputButtons(UserStripMouseDataFlags(pmi->dwFlags));

    /* Raw input gets the same call, stripped and clamped the same way */
    if (bInjected)
        UserRawInputSendMouse(pmi);

    if (pmi->dwFlags & MOUSEEVENTF_MOVE)
    {
        /* Mouse has changes position */
        if (!(pmi->dwFlags & MOUSEEVENTF_ABSOLUTE))
        {
            /* Relative move */
            ptCursor.x = UserSaturateAdd(ptCursor.x, pmi->dx);
            ptCursor.y = UserSaturateAdd(ptCursor.y, pmi->dy);
        }
        else if (pmi->dwFlags & MOUSEEVENTF_VIRTUALDESK)
        {
            /* Absolute move in virtual screen units */
            ptCursor.x = UserScaleAbsolute(pmi->dx, UserGetSystemMetrics(SM_CXVIRTUALSCREEN));
            ptCursor.y = UserScaleAbsolute(pmi->dy, UserGetSystemMetrics(SM_CYVIRTUALSCREEN));
        }
        else
        {
            /* Absolute move in primary monitor units */
            ptCursor.x = UserScaleAbsolute(pmi->dx, UserGetSystemMetrics(SM_CXSCREEN));
            ptCursor.y = UserScaleAbsolute(pmi->dy, UserGetSystemMetrics(SM_CYSCREEN));
        }
    }

    /* Init message fields */
    Msg.wParam = UserGetMouseButtonsState();
    Msg.lParam = MAKELPARAM(ptCursor.x, ptCursor.y);
    Msg.pt = ptCursor;
    Msg.time = pmi->time;
    if (!Msg.time)
    {
        Msg.time = EngGetTickCount32();
    }

    /* Do GetMouseMovePointsEx FIFO. */
    gMouseHistoryOfMoves[gcMouseHistoryOfMoves].x = ptCursor.x;
    gMouseHistoryOfMoves[gcMouseHistoryOfMoves].y = ptCursor.y;
    gMouseHistoryOfMoves[gcMouseHistoryOfMoves].time = Msg.time;
    gMouseHistoryOfMoves[gcMouseHistoryOfMoves].dwExtraInfo = pmi->dwExtraInfo;
    if (++gcMouseHistoryOfMoves == ARRAYSIZE(gMouseHistoryOfMoves))
       gcMouseHistoryOfMoves = 0; // 0 - 63 is 64, FIFO forwards.

    /* Update cursor position */
    if (dwFlags & MOUSEEVENTF_MOVE)
    {
        UserSetCursorPosEx(ptCursor.x, ptCursor.y, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
    }

    if (IS_KEY_DOWN(gafAsyncKeyState, VK_SHIFT))
        pCurInfo->ButtonsDown |= MK_SHIFT;
    else
        pCurInfo->ButtonsDown &= ~MK_SHIFT;

    if (IS_KEY_DOWN(gafAsyncKeyState, VK_CONTROL))
        pCurInfo->ButtonsDown |= MK_CONTROL;
    else
        pCurInfo->ButtonsDown &= ~MK_CONTROL;

    /* Left button */
    if (dwFlags & MOUSEEVENTF_LEFTDOWN)
    {
        SET_KEY_DOWN(gafAsyncKeyState, VK_LBUTTON, TRUE);
        Msg.message = WM_LBUTTONDOWN;
        pCurInfo->ButtonsDown |= MK_LBUTTON;
        Msg.wParam |= MK_LBUTTON;
        co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
    }
    else if (dwFlags & MOUSEEVENTF_LEFTUP)
    {
        SET_KEY_DOWN(gafAsyncKeyState, VK_LBUTTON, FALSE);
        Msg.message = WM_LBUTTONUP;
        pCurInfo->ButtonsDown &= ~MK_LBUTTON;
        Msg.wParam &= ~MK_LBUTTON;
        co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
    }

    /* Middle button */
    if (dwFlags & MOUSEEVENTF_MIDDLEDOWN)
    {
        SET_KEY_DOWN(gafAsyncKeyState, VK_MBUTTON, TRUE);
        Msg.message = WM_MBUTTONDOWN;
        pCurInfo->ButtonsDown |= MK_MBUTTON;
        Msg.wParam |= MK_MBUTTON;
        co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
    }
    else if (dwFlags & MOUSEEVENTF_MIDDLEUP)
    {
        SET_KEY_DOWN(gafAsyncKeyState, VK_MBUTTON, FALSE);
        Msg.message = WM_MBUTTONUP;
        pCurInfo->ButtonsDown &= ~MK_MBUTTON;
        Msg.wParam &= ~MK_MBUTTON;
        co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
    }

    /* Right button */
    if (dwFlags & MOUSEEVENTF_RIGHTDOWN)
    {
        SET_KEY_DOWN(gafAsyncKeyState, VK_RBUTTON, TRUE);
        Msg.message = WM_RBUTTONDOWN;
        pCurInfo->ButtonsDown |= MK_RBUTTON;
        Msg.wParam |= MK_RBUTTON;
        co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
    }
    else if (dwFlags & MOUSEEVENTF_RIGHTUP)
    {
        SET_KEY_DOWN(gafAsyncKeyState, VK_RBUTTON, FALSE);
        Msg.message = WM_RBUTTONUP;
        pCurInfo->ButtonsDown &= ~MK_RBUTTON;
        Msg.wParam &= ~MK_RBUTTON;
        co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
    }

    /* X-Button (4 or 5) */
    if (dwFlags & MOUSEEVENTF_XDOWN)
    {
        Msg.message = WM_XBUTTONDOWN;
        if (pmi->mouseData & XBUTTON1)
        {
            SET_KEY_DOWN(gafAsyncKeyState, VK_XBUTTON1, TRUE);
            pCurInfo->ButtonsDown |= MK_XBUTTON1;
            Msg.wParam |= MAKEWPARAM(MK_XBUTTON1, XBUTTON1);
            co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
        }
        if (pmi->mouseData & XBUTTON2)
        {
            SET_KEY_DOWN(gafAsyncKeyState, VK_XBUTTON2, TRUE);
            pCurInfo->ButtonsDown |= MK_XBUTTON2;
            Msg.wParam |= MAKEWPARAM(MK_XBUTTON2, XBUTTON2);
            co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
        }
    }
    else if (dwFlags & MOUSEEVENTF_XUP)
    {
        Msg.message = WM_XBUTTONUP;
        if(pmi->mouseData & XBUTTON1)
        {
            SET_KEY_DOWN(gafAsyncKeyState, VK_XBUTTON1, FALSE);
            pCurInfo->ButtonsDown &= ~MK_XBUTTON1;
            Msg.wParam &= ~MK_XBUTTON1;
            Msg.wParam |= MAKEWPARAM(0, XBUTTON1);
            co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
        }
        if (pmi->mouseData & XBUTTON2)
        {
            SET_KEY_DOWN(gafAsyncKeyState, VK_XBUTTON2, FALSE);
            pCurInfo->ButtonsDown &= ~MK_XBUTTON2;
            Msg.wParam &= ~MK_XBUTTON2;
            Msg.wParam |= MAKEWPARAM(0, XBUTTON2);
            co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
        }
    }

    /* Mouse wheels: a call that moves nothing posts nothing */
    if (dwFlags & (MOUSEEVENTF_WHEEL | MOUSEEVENTF_HWHEEL))
    {
        SHORT sDelta = UserClampWheelDelta(pmi->mouseData);

        if (sDelta != 0)
        {
            Msg.message = (dwFlags & MOUSEEVENTF_WHEEL) ? WM_MOUSEWHEEL : WM_MOUSEHWHEEL;
            Msg.wParam = MAKEWPARAM(pCurInfo->ButtonsDown, (WORD)sDelta);
            co_MsqInsertMouseMessageEx(&Msg, bInjected, pmi->dwExtraInfo, TRUE, bInjected ? pmi->time : 0);
        }
    }

    return TRUE;
}

VOID
FASTCALL
IntRemoveTrackMouseEvent(
    PDESKTOP pDesk)
{
    /* Generate a leave message */
    if (pDesk->dwDTFlags & DF_TME_LEAVE)
    {
        UINT uMsg = (pDesk->htEx != HTCLIENT) ? WM_NCMOUSELEAVE : WM_MOUSELEAVE;
        UserPostMessage(UserHMGetHandle(pDesk->spwndTrack), uMsg, 0, 0);
    }
    /* Kill the timer */
    if (pDesk->dwDTFlags & DF_TME_HOVER)
        IntKillTimer(pDesk->spwndTrack, ID_EVENT_SYSTIMER_MOUSEHOVER, TRUE);

    /* Reset state */
    pDesk->dwDTFlags &= ~(DF_TME_LEAVE|DF_TME_HOVER);
    pDesk->spwndTrack = NULL;
}

BOOL
FASTCALL
IntQueryTrackMouseEvent(
    LPTRACKMOUSEEVENT lpEventTrack)
{
    PDESKTOP pDesk;
    PTHREADINFO pti;

    pti = PsGetCurrentThreadWin32Thread();
    pDesk = pti->rpdesk;

    /* Always cleared with size set and return true. */
    RtlZeroMemory(lpEventTrack , sizeof(TRACKMOUSEEVENT));
    lpEventTrack->cbSize = sizeof(TRACKMOUSEEVENT);

    if (pDesk->dwDTFlags & (DF_TME_LEAVE | DF_TME_HOVER) &&
        pDesk->spwndTrack &&
        pti->MessageQueue == pDesk->spwndTrack->head.pti->MessageQueue)
    {
        if (pDesk->htEx != HTCLIENT)
            lpEventTrack->dwFlags |= TME_NONCLIENT;

        if (pDesk->dwDTFlags & DF_TME_LEAVE)
            lpEventTrack->dwFlags |= TME_LEAVE;

        if (pDesk->dwDTFlags & DF_TME_HOVER)
        {
            lpEventTrack->dwFlags |= TME_HOVER;
            lpEventTrack->dwHoverTime = pDesk->dwMouseHoverTime;
        }
        lpEventTrack->hwndTrack = UserHMGetHandle(pDesk->spwndTrack);
    }
    return TRUE;
}

BOOL
FASTCALL
IntTrackMouseEvent(
    LPTRACKMOUSEEVENT lpEventTrack)
{
    PDESKTOP pDesk;
    PTHREADINFO pti;
    PWND pWnd;
    POINT point;

    pti = PsGetCurrentThreadWin32Thread();
    pDesk = pti->rpdesk;

    if (!(pWnd = UserGetWindowObject(lpEventTrack->hwndTrack)))
        return FALSE;

    if ( pDesk->spwndTrack != pWnd ||
            (pDesk->htEx != HTCLIENT) ^ !!(lpEventTrack->dwFlags & TME_NONCLIENT) )
    {
        if ( lpEventTrack->dwFlags & TME_LEAVE && !(lpEventTrack->dwFlags & TME_CANCEL) )
        {
            UserPostMessage( lpEventTrack->hwndTrack,
                             lpEventTrack->dwFlags & TME_NONCLIENT ? WM_NCMOUSELEAVE : WM_MOUSELEAVE,
                             0, 0);
        }
        TRACE("IntTrackMouseEvent spwndTrack %p pwnd %p\n", pDesk->spwndTrack, pWnd);
        return TRUE;
    }

    /* Tracking spwndTrack same as pWnd */
    if (lpEventTrack->dwFlags & TME_CANCEL) // Canceled mode.
    {
        if (lpEventTrack->dwFlags & TME_LEAVE)
            pDesk->dwDTFlags &= ~DF_TME_LEAVE;

        if (lpEventTrack->dwFlags & TME_HOVER)
        {
            if (pDesk->dwDTFlags & DF_TME_HOVER)
            {   // Kill hover timer.
                IntKillTimer(pWnd, ID_EVENT_SYSTIMER_MOUSEHOVER, TRUE);
                pDesk->dwDTFlags &= ~DF_TME_HOVER;
            }
        }
    }
    else // Not Canceled.
    {
        if (lpEventTrack->dwFlags & TME_LEAVE)
            pDesk->dwDTFlags |= DF_TME_LEAVE;

        if (lpEventTrack->dwFlags & TME_HOVER)
        {
            pDesk->dwDTFlags |= DF_TME_HOVER;

            if (!lpEventTrack->dwHoverTime || lpEventTrack->dwHoverTime == HOVER_DEFAULT)
                pDesk->dwMouseHoverTime = gspv.iMouseHoverTime; // use the system default hover time-out.
            else
                pDesk->dwMouseHoverTime = lpEventTrack->dwHoverTime;
            // Start timer for the hover period.
            IntSetTimer(pWnd, ID_EVENT_SYSTIMER_MOUSEHOVER, pDesk->dwMouseHoverTime, SystemTimerProc, TMRF_SYSTEM);
            // Get windows thread message points.
            point = pWnd->head.pti->ptLast;
            // Set desktop mouse hover from the system default hover rectangle.
            RECTL_vSetRect(&pDesk->rcMouseHover,
                           point.x - gspv.iMouseHoverWidth  / 2,
                           point.y - gspv.iMouseHoverHeight / 2,
                           point.x + gspv.iMouseHoverWidth  / 2,
                           point.y + gspv.iMouseHoverHeight / 2);
        }
    }
    return TRUE;
}

BOOL
APIENTRY
NtUserTrackMouseEvent(
    LPTRACKMOUSEEVENT lpEventTrack)
{
    TRACKMOUSEEVENT SafeTME;
    BOOL bRet = FALSE;

    TRACE("Enter NtUserTrackMouseEvent\n");

    _SEH2_TRY
    {
        ProbeForRead(lpEventTrack, sizeof(TRACKMOUSEEVENT), 1);
        RtlCopyMemory(&SafeTME, lpEventTrack, sizeof(TRACKMOUSEEVENT));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
        _SEH2_YIELD(return FALSE);
    }
    _SEH2_END;

    if (SafeTME.cbSize != sizeof(TRACKMOUSEEVENT))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (SafeTME.dwFlags & ~(TME_CANCEL | TME_QUERY | TME_NONCLIENT | TME_LEAVE | TME_HOVER) )
    {
        EngSetLastError(ERROR_INVALID_FLAGS);
        return FALSE;
    }

    UserEnterExclusive();

    if (SafeTME.dwFlags & TME_QUERY)
    {
        bRet = IntQueryTrackMouseEvent(&SafeTME);
        _SEH2_TRY
        {
            ProbeForWrite(lpEventTrack, sizeof(TRACKMOUSEEVENT), 1);
            RtlCopyMemory(lpEventTrack, &SafeTME, sizeof(TRACKMOUSEEVENT));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            SetLastNtError(_SEH2_GetExceptionCode());
            bRet = FALSE;
        }
        _SEH2_END;
    }
    else
    {
        bRet = IntTrackMouseEvent(&SafeTME);
    }

    TRACE("Leave NtUserTrackMouseEvent, ret=%i\n", bRet);
    UserLeave();
    return bRet;
}

DWORD
APIENTRY
NtUserGetMouseMovePointsEx(
    UINT cbSize,
    LPMOUSEMOVEPOINT lpptIn,
    LPMOUSEMOVEPOINT lpptOut,
    int nBufPoints,
    DWORD resolution)
{
    MOUSEMOVEPOINT Safeppt;
    //BOOL Hit;
    INT iRet = -1;

    TRACE("Enter NtUserGetMouseMovePointsEx\n");

    if ((cbSize != sizeof(MOUSEMOVEPOINT)) || (nBufPoints < 0) || (nBufPoints > 64))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return (DWORD)-1;
    }

    if (!lpptIn || (!lpptOut && nBufPoints))
    {
        EngSetLastError(ERROR_NOACCESS);
        return (DWORD)-1;
    }

    _SEH2_TRY
    {
        ProbeForRead(lpptIn, cbSize, 1);
        RtlCopyMemory(&Safeppt, lpptIn, cbSize);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
        _SEH2_YIELD(return (DWORD)-1);
    }
    _SEH2_END;

    UserEnterShared();

    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmousemovepointsex
    // This explains the math issues in transforming points.
    iRet = gcMouseHistoryOfMoves; // FIFO is forward so retrieve backward.
    //Hit = FALSE;
    do
    {
        if (Safeppt.x == 0 && Safeppt.y == 0)
            break; // No test.
        // Finds the point, it returns the last nBufPoints prior to and including the supplied point.
        if (gMouseHistoryOfMoves[iRet].x == Safeppt.x && gMouseHistoryOfMoves[iRet].y == Safeppt.y)
        {
            if (Safeppt.time) // Now test time and it seems to be absolute.
            {
                if (Safeppt.time == gMouseHistoryOfMoves[iRet].time)
                {
                    //Hit = TRUE;
                    break;
                }
                else
                {
                    if (--iRet < 0) iRet = 63;
                    continue;
                }
            }
            //Hit = TRUE;
            break;
        }
        if (--iRet < 0) iRet = 63;
    }
    while (iRet != gcMouseHistoryOfMoves);

    switch(resolution)
    {
        case GMMP_USE_DISPLAY_POINTS:
            if (nBufPoints)
            {
                _SEH2_TRY
                {
                    ProbeForWrite(lpptOut, cbSize, 1);
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    SetLastNtError(_SEH2_GetExceptionCode());
                    iRet = -1;
                    _SEH2_YIELD(goto cleanup);
                }
                _SEH2_END;
            }
            iRet = nBufPoints;
            break;
        case GMMP_USE_HIGH_RESOLUTION_POINTS:
            break;
        default:
            EngSetLastError(ERROR_POINT_NOT_FOUND);
            iRet = -1;
    }

cleanup:
    TRACE("Leave NtUserGetMouseMovePointsEx, ret=%i\n", iRet);
    UserLeave();
    return (DWORD)iRet;
}
