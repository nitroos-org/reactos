/* Private USER arguments used by dialogs and common controls.
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64win.h"
#include <undocuser.h>

typedef struct { ULONG cbSize, fMask, dwStyle, cyMax, hbrBack, dwContextHelpID, dwMenuData; } MENUINFO32;
typedef struct {
    ULONG cbSize, fMask, fType, fState, wID, hSubMenu, hbmpChecked, hbmpUnchecked;
    ULONG dwItemData, dwTypeData, cch, hbmpItem;
} MENUITEM32;
typedef struct { ULONG cbSize, dwFlags, hwndTrack, dwHoverTime; } TRACK32;
typedef struct { ULONG cbSize; RECT rcItem, rcButton; ULONG stateButton, hwndCombo, hwndItem, hwndList; } COMBO32;
typedef struct { ULONG cbSize, flags, hwndActive, hwndFocus, hwndCapture, hwndMenuOwner, hwndMoveSize, hwndCaret; RECT rcCaret; } GUITHREAD32;
typedef struct { ULONG cbSize; RECT rcBar; ULONG hMenu, hwndMenu, flags; } MENUBAR32;
typedef struct { ULONG cbSize, flags, hCursor; POINT pt; } CURSOR32;
typedef struct { BOOL fIcon; DWORD xHotspot, yHotspot; ULONG hbmMask, hbmColor; } ICON32;
C_ASSERT(sizeof(MENUINFO32) == 28);
C_ASSERT(sizeof(MENUITEM32) == 48);
C_ASSERT(sizeof(COMBO32) == 52);
C_ASSERT(sizeof(GUITHREAD32) == 48);
C_ASSERT(sizeof(MENUBAR32) == 32);
C_ASSERT(sizeof(CURSOR32) == 20);
C_ASSERT(sizeof(ICON32) == 20);
typedef struct {
    ULONG lpName, lpModName; USHORT rt, dummy; ULONG Flags; SHORT xHotspot, yHotspot;
    ULONG hbmMask, hbmColor, hbmAlpha; RECT rcBounds; ULONG hbmUserAlpha, bpp, cx, cy;
    UINT cpcur, cicur; ULONG aspcur, aicur, ajifRate; UINT iicur;
} CURSORDATA32;
C_ASSERT(sizeof(CURSORDATA32) == 88);

static VOID CursorIn(CURSORDATA *Native, const CURSORDATA32 *Guest)
{
    Native->lpName = P32(Guest->lpName); Native->lpModName = P32(Guest->lpModName);
    Native->rt = Guest->rt; Native->dummy = Guest->dummy; Native->CURSORF_flags = Guest->Flags;
    Native->xHotspot = Guest->xHotspot; Native->yHotspot = Guest->yHotspot;
    Native->hbmMask = P32(Guest->hbmMask); Native->hbmColor = P32(Guest->hbmColor); Native->hbmAlpha = P32(Guest->hbmAlpha);
    Native->rcBounds = Guest->rcBounds; Native->hbmUserAlpha = P32(Guest->hbmUserAlpha); Native->bpp = Guest->bpp;
    Native->cx = Guest->cx; Native->cy = Guest->cy; Native->cpcur = Guest->cpcur; Native->cicur = Guest->cicur;
    Native->aspcur = NULL; Native->aicur = P32(Guest->aicur); Native->ajifRate = P32(Guest->ajifRate); Native->iicur = Guest->iicur;
}

static VOID StringIn(UNICODE_STRING *Native, ULONG Address)
{
    const STRING32 *Guest = P32(Address);
    Native->Length = Guest->Length;
    Native->MaximumLength = Guest->MaximumLength;
    Native->Buffer = P32(Guest->Buffer);
}

static VOID StringOut(ULONG Address, const UNICODE_STRING *Native)
{
    STRING32 *Guest = P32(Address);
    Guest->Length = Native->Length;
    Guest->MaximumLength = Native->MaximumLength;
    Guest->Buffer = PtrToUlong(Native->Buffer);
}

static BOOL CheckSize(ULONG Address, ULONG Size)
{
    if (!Address || *(ULONG *)P32(Address) != Size)
    {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

/* 0 when a guest hook may target ThreadId (0: global), else the Win32 error */
static ULONG HookThreadError(ULONG ThreadId)
{
    OBJECT_ATTRIBUTES Attributes;
    CLIENT_ID Client;
    THREAD_BASIC_INFORMATION Info;
    HANDLE Thread;
    NTSTATUS Status;
    if (!ThreadId || ThreadId == HandleToUlong(NtCurrentTeb()->ClientId.UniqueThread)) return 0;
    InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);
    Client.UniqueProcess = NULL;
    Client.UniqueThread = UlongToHandle(ThreadId);
    Status = NtOpenThread(&Thread, THREAD_QUERY_INFORMATION, &Attributes, &Client);
    /* win32k's error for a thread that does not exist */
    if (Status == STATUS_INVALID_CID || Status == STATUS_INVALID_PARAMETER) return ERROR_INVALID_PARAMETER;
    if (!NT_SUCCESS(Status)) return ERROR_CALL_NOT_IMPLEMENTED;
    Status = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), NULL);
    NtClose(Thread);
    if (!NT_SUCCESS(Status) || Info.ClientId.UniqueProcess != NtCurrentTeb()->ClientId.UniqueProcess)
        return ERROR_CALL_NOT_IMPLEMENTED;
    return 0;
}

static ULONG_PTR SystemParameters(ULONG *a)
{
    switch (a[0])
    {
    case SPI_GETDEFAULTINPUTLANG:
    {
        HKL Layout; BOOL Ret = NtUserSystemParametersInfo(a[0], a[1], &Layout, a[3]);
        if (Ret) *(ULONG *)P(2) = HandleToUlong(Layout);
        return Ret;
    }
    case SPI_SETDEFAULTINPUTLANG:
    {
        HKL Layout = H32(*(ULONG *)P(2));
        return NtUserSystemParametersInfo(a[0], a[1], &Layout, a[3]);
    }
    case SPI_SETDESKWALLPAPER:
    {
        UNICODE_STRING Name;
        if (a[2]) StringIn(&Name, a[2]);
        return NtUserSystemParametersInfo(a[0], a[1], a[2] ? &Name : NULL, a[3]);
    }
    case SPI_GETHIGHCONTRAST: case SPI_SETHIGHCONTRAST:
    {
        HIGHCONTRASTW Contrast; ULONG *Guest = P(2); BOOL Ret;
        if (!CheckSize(a[2], 12)) return FALSE;
        Contrast.cbSize = sizeof(Contrast); Contrast.dwFlags = Guest[1]; Contrast.lpszDefaultScheme = P32(Guest[2]);
        Ret = NtUserSystemParametersInfo(a[0], sizeof(Contrast), &Contrast, a[3]);
        if (Ret && a[0] == SPI_GETHIGHCONTRAST)
        { Guest[1] = Contrast.dwFlags; Guest[2] = PtrToUlong(Contrast.lpszDefaultScheme); }
        return Ret;
    }
    case SPI_GETSERIALKEYS: case SPI_SETSERIALKEYS:
    case SPI_GETSOUNDSENTRY: case SPI_SETSOUNDSENTRY:
        RtlSetLastWin32Error(ERROR_CALL_NOT_IMPLEMENTED); return FALSE;
    default:
        /* The remaining implemented selectors in ntuser/sysparams.c carry
         * integers, fixed-width arrays, LOGFONT/metrics, or RECT. Their size
         * gates and input/output probing remain in the native service. */
        return NtUserSystemParametersInfo(a[0], a[1], P(2), a[3]);
    }
}

ULONG_PTR Wow64WinExtraService(ULONG Number, ULONG *a)
{
    switch (Number)
    {
    case W64_NtUserEnumDisplayMonitors:
    {
        HMONITOR *Monitors = NULL;
        INT Count;
        ULONG i;
        if (a[4] > MAXLONG / sizeof(HMONITOR))
        {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return (ULONG_PTR)-1;
        }
        if (a[2] && a[4])
        {
            Monitors = RtlAllocateHeap(RtlGetProcessHeap(), 0, a[4] * sizeof(HMONITOR));
            if (!Monitors)
            {
                RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
                return (ULONG_PTR)-1;
            }
        }
        _SEH2_TRY
        {
            Count = NtUserEnumDisplayMonitors(G(0), P(1), Monitors, P(3), a[4]);
            if (Monitors && Count > 0)
                for (i = 0; i < min((ULONG)Count, a[4]); ++i)
                    ((ULONG *)P(2))[i] = HandleToUlong(Monitors[i]);
        }
        _SEH2_FINALLY
        {
            if (Monitors) RtlFreeHeap(RtlGetProcessHeap(), 0, Monitors);
        }
        _SEH2_END;
        return (LONG_PTR)Count;
    }
    case W64_NtUserSetWindowsHookEx:
    {
        UNICODE_STRING Module;
        ULONG Error;
        /* callback.c translates every family win32k calls back with
         * (win32k never calls journal or WH_DEBUG procedures), and win32k
         * gives the errors for the hook id. A guest procedure must run only
         * on guest threads: this process's threads, which a global hook also
         * reaches (low-level, mouse and keyboard hooks run on the setter's
         * thread). Threads of another process need the bitness-aware
         * cross-process path. */
        Error = HookThreadError(a[2]);
        if (Error)
        {
            RtlSetLastWin32Error(Error);
            return 0;
        }
        if (a[1]) StringIn(&Module, a[1]);
        return (ULONG_PTR)NtUserSetWindowsHookEx(P(0), a[1] ? &Module : NULL,
                                               a[2], a[3], P(4), a[5]);
    }
    case W64_NtUserCallNextHookEx:
        return Wow64WinCallNextHook(a);
    case W64_NtUserBuildHwndList:
    {
        HWND *List = NULL; ULONG Needed = 0, i; NTSTATUS Status;
        if (!a[6]) return STATUS_INVALID_PARAMETER;
        if (a[4] > MAXULONG / sizeof(HWND)) return STATUS_INVALID_PARAMETER;
        if (a[4] && a[5])
        {
            List = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)a[4] * sizeof(HWND));
            if (!List) return STATUS_NO_MEMORY;
        }
        _SEH2_TRY
        {
            Status = NtUserBuildHwndList(H(0), H(1), a[2], a[3], a[4], List, &Needed);
            *(ULONG *)P(6) = Needed;
            if (List) for (i = 0; i < min(Needed, a[4]); ++i) ((ULONG *)P(5))[i] = HandleToUlong(List[i]);
        }
        _SEH2_FINALLY { if (List) RtlFreeHeap(RtlGetProcessHeap(), 0, List); }
        _SEH2_END;
        return Status;
    }
    case W64_NtUserFindWindowEx:
    {
        UNICODE_STRING Class, Title;
        if (a[2]) StringIn(&Class, a[2]);
        if (a[3]) StringIn(&Title, a[3]);
        return (ULONG_PTR)NtUserFindWindowEx(H(0), H(1), a[2] ? &Class : NULL, a[3] ? &Title : NULL, a[4]);
    }
    case W64_NtUserGetAtomName: case W64_NtUserGetClassName: case W64_NtUserGetKeyboardLayoutName:
    {
        ULONG Index = Number == W64_NtUserGetAtomName ? 1 : Number == W64_NtUserGetClassName ? 2 : 0;
        UNICODE_STRING Name; ULONG Ret;
        StringIn(&Name, a[Index]);
        if (Number == W64_NtUserGetAtomName) Ret = NtUserGetAtomName(a[0], &Name);
        else if (Number == W64_NtUserGetClassName) Ret = NtUserGetClassName(H(0), a[1], &Name);
        else Ret = NtUserGetKeyboardLayoutName(&Name);
        if (Ret) ((STRING32 *)P32(a[Index]))->Length = Name.Length;
        return Ret;
    }
    case W64_NtUserRegisterWindowMessage:
    {
        UNICODE_STRING Name; StringIn(&Name, a[0]);
        return NtUserRegisterWindowMessage(&Name);
    }
    case W64_NtUserGetClipboardData:
    {
        GETCLIPBDATA Data = {0}; HANDLE Value;
        Value = NtUserGetClipboardData(a[0], a[1] ? &Data : NULL);
        if (Value && a[1])
        {
            ULONG *Guest = P(1);
            Guest[0] = Data.uFmtRet; Guest[1] = Data.fGlobalHandle; Guest[2] = HandleToUlong(Data.hLocale);
        }
        return (ULONG_PTR)Value;
    }
    case W64_NtUserGetComboBoxInfo:
    {
        COMBOBOXINFO Info = {sizeof(Info)}; COMBO32 *Guest = P(1); BOOL Ret;
        if (!CheckSize(a[1], sizeof(*Guest))) return FALSE;
        Ret = NtUserGetComboBoxInfo(H(0), &Info);
        if (Ret)
        {
            Guest->rcItem = Info.rcItem; Guest->rcButton = Info.rcButton; Guest->stateButton = Info.stateButton;
            Guest->hwndCombo = HandleToUlong(Info.hwndCombo); Guest->hwndItem = HandleToUlong(Info.hwndItem);
            Guest->hwndList = HandleToUlong(Info.hwndList);
        }
        return Ret;
    }
    case W64_NtUserGetCursorInfo:
    {
        CURSORINFO Info = {sizeof(Info)}; CURSOR32 *Guest = P(0); BOOL Ret;
        if (!CheckSize(a[0], sizeof(*Guest))) return FALSE;
        Ret = NtUserGetCursorInfo(&Info);
        if (Ret) { Guest->flags = Info.flags; Guest->hCursor = HandleToUlong(Info.hCursor); Guest->pt = Info.ptScreenPos; }
        return Ret;
    }
    case W64_NtUserGetGUIThreadInfo:
    {
        GUITHREADINFO Info = {sizeof(Info)}; GUITHREAD32 *Guest = P(1); BOOL Ret;
        if (!CheckSize(a[1], sizeof(*Guest))) return FALSE;
        Ret = NtUserGetGUIThreadInfo(a[0], &Info);
        if (Ret)
        {
            Guest->flags = Info.flags; Guest->hwndActive = HandleToUlong(Info.hwndActive);
            Guest->hwndFocus = HandleToUlong(Info.hwndFocus); Guest->hwndCapture = HandleToUlong(Info.hwndCapture);
            Guest->hwndMenuOwner = HandleToUlong(Info.hwndMenuOwner); Guest->hwndMoveSize = HandleToUlong(Info.hwndMoveSize);
            Guest->hwndCaret = HandleToUlong(Info.hwndCaret); Guest->rcCaret = Info.rcCaret;
        }
        return Ret;
    }
    case W64_NtUserGetMenuBarInfo:
    {
        MENUBARINFO Info = {sizeof(Info)}; MENUBAR32 *Guest = P(3); BOOL Ret;
        if (!CheckSize(a[3], sizeof(*Guest))) return FALSE;
        Ret = NtUserGetMenuBarInfo(H(0), a[1], a[2], &Info);
        if (Ret)
        {
            Guest->rcBar = Info.rcBar; Guest->hMenu = HandleToUlong(Info.hMenu); Guest->hwndMenu = HandleToUlong(Info.hwndMenu);
            Guest->flags = (Info.fBarFocused != 0) | ((Info.fFocused != 0) << 1);
        }
        return Ret;
    }
    case W64_NtUserGetIconInfo:
    {
        ICONINFO Info; UNICODE_STRING Instance, Resource; BOOL Ret;
        if (a[2]) StringIn(&Instance, a[2]);
        if (a[3]) StringIn(&Resource, a[3]);
        Ret = NtUserGetIconInfo(H(0), a[1] ? &Info : NULL, a[2] ? &Instance : NULL, a[3] ? &Resource : NULL, P(4), a[5]);
        /* The sizing call updates MaximumLength; integer resources replace
         * Buffer with the atom. Copying Length alone makes CopyImage allocate
         * an empty buffer and then terminate beyond it. */
        if (a[2]) StringOut(a[2], &Instance);
        if (a[3]) StringOut(a[3], &Resource);
        if (Ret)
        {
            if (a[1])
            {
                ICON32 *Guest = P(1);
                Guest->fIcon = Info.fIcon; Guest->xHotspot = Info.xHotspot; Guest->yHotspot = Info.yHotspot;
                Guest->hbmMask = HandleToUlong(Info.hbmMask); Guest->hbmColor = HandleToUlong(Info.hbmColor);
            }
        }
        return Ret;
    }
    case W64_NtUserGetKeyboardLayoutList:
    {
        HKL *List; INT Ret, i;
        if ((LONG)a[0] <= 0 || !a[1]) return NtUserGetKeyboardLayoutList(a[0], NULL);
        if (a[0] > MAXULONG / sizeof(HKL)) return 0;
        List = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)a[0] * sizeof(HKL));
        if (!List) return 0;
        _SEH2_TRY
        {
            Ret = NtUserGetKeyboardLayoutList(a[0], List);
            for (i = 0; i < min(Ret, (INT)a[0]); ++i) ((ULONG *)P(1))[i] = HandleToUlong(List[i]);
        }
        _SEH2_FINALLY { RtlFreeHeap(RtlGetProcessHeap(), 0, List); }
        _SEH2_END;
        return Ret;
    }
    case W64_NtUserSystemParametersInfo: return SystemParameters(a);
    case W64_NtUserSetCursorIconData:
    {
        CURSORDATA Data, *Frames = NULL; UNICODE_STRING Module, Resource; BOOL Ret; ULONG i;
        const CURSORDATA32 *Guest = P(3);
        CursorIn(&Data, Guest);
        if (a[1]) StringIn(&Module, a[1]);
        if (a[2]) StringIn(&Resource, a[2]);
        if (Data.CURSORF_flags & CURSORF_ACON)
        {
            if (!Data.cpcur || Data.cpcur > 1000 || !Data.cicur || Data.cicur > 1000) return FALSE;
            Frames = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Data.cpcur * sizeof(*Frames));
            if (!Frames) return FALSE;
        }
        _SEH2_TRY
        {
            if (Frames)
            {
                for (i = 0; i < Data.cpcur; ++i) CursorIn(&Frames[i], (CURSORDATA32 *)P32(Guest->aspcur) + i);
                Data.aspcur = Frames;
            }
            Ret = NtUserSetCursorIconData(H(0), a[1] ? &Module : NULL, a[2] ? &Resource : NULL, &Data);
        }
        _SEH2_FINALLY { if (Frames) RtlFreeHeap(RtlGetProcessHeap(), 0, Frames); }
        _SEH2_END;
        return Ret;
    }
    case W64_NtUserThunkedMenuInfo:
    {
        MENUINFO Info; const MENUINFO32 *Guest = P(1);
        if (!CheckSize(a[1], sizeof(*Guest))) return FALSE;
        Info.cbSize = sizeof(Info); Info.fMask = Guest->fMask; Info.dwStyle = Guest->dwStyle; Info.cyMax = Guest->cyMax;
        Info.hbrBack = P32(Guest->hbrBack); Info.dwContextHelpID = Guest->dwContextHelpID; Info.dwMenuData = Guest->dwMenuData;
        return NtUserThunkedMenuInfo(H(0), &Info);
    }
    case W64_NtUserThunkedMenuItemInfo:
    {
        MENUITEMINFOW Info = {sizeof(Info)}; const MENUITEM32 *Guest = P(4); UNICODE_STRING Caption;
        if (!Guest || (Guest->cbSize != sizeof(*Guest) && Guest->cbSize != FIELD_OFFSET(MENUITEM32, hbmpItem)))
        { RtlSetLastWin32Error(ERROR_INVALID_PARAMETER); return FALSE; }
        Info.fMask = Guest->fMask; Info.fType = Guest->fType; Info.fState = Guest->fState; Info.wID = Guest->wID;
        Info.hSubMenu = H32(Guest->hSubMenu); Info.hbmpChecked = P32(Guest->hbmpChecked); Info.hbmpUnchecked = P32(Guest->hbmpUnchecked);
        Info.dwItemData = Guest->dwItemData; Info.dwTypeData = P32(Guest->dwTypeData); Info.cch = Guest->cch;
        if (Guest->cbSize == sizeof(*Guest)) Info.hbmpItem = P32(Guest->hbmpItem);
        else Info.cbSize = FIELD_OFFSET(MENUITEMINFOW, hbmpItem);
        if (a[5]) StringIn(&Caption, a[5]);
        return NtUserThunkedMenuItemInfo(H(0), a[1], a[2], a[3], &Info, a[5] ? &Caption : NULL);
    }
    case W64_NtUserTrackMouseEvent:
    {
        TRACKMOUSEEVENT Track; TRACK32 *Guest = P(0); BOOL Ret;
        if (!CheckSize(a[0], sizeof(*Guest))) return FALSE;
        Track.cbSize = sizeof(Track); Track.dwFlags = Guest->dwFlags; Track.hwndTrack = H32(Guest->hwndTrack); Track.dwHoverTime = Guest->dwHoverTime;
        Ret = NtUserTrackMouseEvent(&Track);
        if (Ret) { Guest->dwFlags = Track.dwFlags; Guest->hwndTrack = HandleToUlong(Track.hwndTrack); Guest->dwHoverTime = Track.dwHoverTime; }
        return Ret;
    }
    case W64_NtUserTranslateAccelerator:
    { MSG Message; Msg32ToNative(&Message, P(2)); return NtUserTranslateAccelerator(H(0), H(1), &Message); }
    case W64_NtUserCallMsgFilter:
    {
        MSG Message; BOOL Ret; Msg32ToNative(&Message, P(0));
        Ret = NtUserCallMsgFilter(&Message, a[1]); MsgNativeTo32(P(0), &Message); return Ret;
    }
    case W64_NtUserFlashWindowEx:
    {
        FLASHWINFO Info; ULONG *Guest = P(0);
        if (!CheckSize(a[0], 20)) return FALSE;
        Info.cbSize = sizeof(Info); Info.hwnd = H32(Guest[1]); Info.dwFlags = Guest[2]; Info.uCount = Guest[3]; Info.dwTimeout = Guest[4];
        return NtUserFlashWindowEx(&Info);
    }
    case W64_NtUserQueryInputContext:
        if (a[1] > QIC_DEFAULTIMC) return 0;
        return NtUserQueryInputContext(H(0), a[1]);
    case W64_NtUserUpdateInputContext:
        if (a[1] == UIC_CLIENTIMCDATA)
            return NtUserUpdateInputContext(H(0), a[1], (ULONG_PTR)P(2));
        if (a[1] == UIC_IMEWINDOW)
            return NtUserUpdateInputContext(H(0), a[1], (ULONG_PTR)H(2));
        return FALSE;
    default:
        return Wow64WinGdiService(Number, a);
    }
}
