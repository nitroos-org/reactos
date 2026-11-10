/* ReactOS WoW64 USER structure and selector translation.
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64win.h"

static VOID ProbeOutput(ULONG Address, ULONG Size)
{
    volatile BYTE *Bytes=P32(Address);
    ULONG i;
    if (Address > MAXULONG - Size) RtlRaiseStatus(STATUS_ACCESS_VIOLATION);
    for (i=0;i<Size;++i) Bytes[i]=Bytes[i];
}

static VOID String32(UNICODE_STRING *To, const STRING32 *From)
{
    To->Length = From->Length;
    To->MaximumLength = From->MaximumLength;
    To->Buffer = P32(From->Buffer);
}

static PLARGE_STRING LargeString32(LARGE_STRING *To, ULONG Address)
{
    const LARGE_STRING32 *From = P32(Address);
    if (Address < 0x10000) return P32(Address); /* atom, including NULL */
    To->Length = From->Length;
    To->MaximumLength = From->MaximumLength & 0x7fffffff;
    To->bAnsi = From->MaximumLength >> 31;
    To->Buffer = P32(From->Buffer);
    return To;
}

VOID Msg32ToNative(MSG *To, const MSG32 *From)
{
    To->hwnd = H32(From->hwnd); To->message = From->message;
    To->wParam = From->wParam; To->lParam = (LONG)From->lParam;
    if (From->message == WM_TIMER || From->message == 0x118 /* WM_SYSTIMER */)
        To->lParam = (ULONG_PTR)From->lParam;
    To->time = From->time; To->pt = From->pt;
}
VOID MsgNativeTo32(MSG32 *To, const MSG *From)
{
    To->hwnd = HandleToUlong(From->hwnd); To->message = From->message;
    To->wParam = From->wParam; To->lParam = From->lParam;
    To->time = From->time; To->pt = From->pt;
}
VOID Create32ToNative(CREATESTRUCTW *To, const CREATE32 *From)
{
    To->lpCreateParams = P32(From->lpCreateParams); To->hInstance = P32(From->hInstance);
    To->hMenu = H32(From->hMenu); To->hwndParent = H32(From->hwndParent);
    To->cy = From->cy; To->cx = From->cx; To->y = From->y; To->x = From->x;
    To->style = From->style; To->lpszName = P32(From->lpszName);
    To->lpszClass = P32(From->lpszClass); To->dwExStyle = From->dwExStyle;
}
VOID CreateNativeTo32(CREATE32 *To, const CREATESTRUCTW *From)
{
    To->lpCreateParams = PtrToUlong(From->lpCreateParams); To->hInstance = HandleToUlong(From->hInstance);
    To->hMenu = HandleToUlong(From->hMenu); To->hwndParent = HandleToUlong(From->hwndParent);
    To->cy = From->cy; To->cx = From->cx; To->y = From->y; To->x = From->x;
    To->style = From->style; To->lpszName = PtrToUlong(From->lpszName);
    To->lpszClass = PtrToUlong(From->lpszClass); To->dwExStyle = From->dwExStyle;
}
VOID WindowPos32ToNative(WINDOWPOS *To, const WINDOWPOS32 *From)
{
    To->hwnd = H32(From->hwnd); To->hwndInsertAfter = H32(From->hwndInsertAfter);
    To->x = From->x; To->y = From->y; To->cx = From->cx; To->cy = From->cy; To->flags = From->flags;
}
VOID WindowPosNativeTo32(WINDOWPOS32 *To, const WINDOWPOS *From)
{
    To->hwnd = HandleToUlong(From->hwnd); To->hwndInsertAfter = HandleToUlong(From->hwndInsertAfter);
    To->x = From->x; To->y = From->y; To->cx = From->cx; To->cy = From->cy; To->flags = From->flags;
}
static VOID Class32ToNative(WNDCLASSEXW *To, const CLASS32 *From)
{
    To->cbSize = sizeof(*To); To->style = From->style;
    To->lpfnWndProc = P32(From->lpfnWndProc); To->cbClsExtra = From->cbClsExtra; To->cbWndExtra = From->cbWndExtra;
    To->hInstance = P32(From->hInstance); To->hIcon = H32(From->hIcon); To->hCursor = H32(From->hCursor);
    To->hbrBackground = P32(From->hbrBackground); To->lpszMenuName = P32(From->lpszMenuName);
    To->lpszClassName = P32(From->lpszClassName); To->hIconSm = H32(From->hIconSm);
}
static VOID ClassNativeTo32(CLASS32 *To, const WNDCLASSEXW *From)
{
    To->cbSize = sizeof(*To); To->style = From->style;
    To->lpfnWndProc = PtrToUlong(From->lpfnWndProc); To->cbClsExtra = From->cbClsExtra; To->cbWndExtra = From->cbWndExtra;
    To->hInstance = HandleToUlong(From->hInstance); To->hIcon = HandleToUlong(From->hIcon); To->hCursor = HandleToUlong(From->hCursor);
    To->hbrBackground = HandleToUlong(From->hbrBackground); To->lpszMenuName = PtrToUlong(From->lpszMenuName);
    To->lpszClassName = PtrToUlong(From->lpszClassName); To->hIconSm = HandleToUlong(From->hIconSm);
}
static VOID Paint32ToNative(PAINTSTRUCT *To, const PAINT32 *From)
{
    To->hdc = P32(From->hdc); To->fErase = From->fErase; To->rcPaint = From->rcPaint;
    To->fRestore = From->fRestore; To->fIncUpdate = From->fIncUpdate;
    RtlCopyMemory(To->rgbReserved, From->rgbReserved, sizeof(To->rgbReserved));
}
static VOID PaintNativeTo32(PAINT32 *To, const PAINTSTRUCT *From)
{
    To->hdc = HandleToUlong(From->hdc); To->fErase = From->fErase; To->rcPaint = From->rcPaint;
    To->fRestore = From->fRestore; To->fIncUpdate = From->fIncUpdate;
    RtlCopyMemory(To->rgbReserved, From->rgbReserved, sizeof(To->rgbReserved));
}

static ULONG_PTR MessageCall(ULONG *a)
{
    LRESULT Result = 0;
    BOOL Ret;
    LPARAM Param = S(3);
    union
    {
        CREATESTRUCTW Create; WINDOWPOS Pos; struct { NCCALCSIZE_PARAMS Params; WINDOWPOS Pos; } Nc;
        MEASUREITEMSTRUCT Measure; DRAWITEMSTRUCT Draw;
    } Buffer;
    DOSENDMESSAGE Timeout;
    CALL_BACK_INFO Callback;
    ULONG_PTR ResultInfo = a[4] ? (ULONG_PTR)&Result : 0;
    COPYDATASTRUCT *Copy = NULL;
    /* WM_NOTIFY is an application-defined record beginning with NMHDR.
     * The kernel does not inspect or capture it. On the same guest thread,
     * keep that guest record intact through both hooks and the window proc.
     * Cross-thread/broadcast delivery still needs its own lifetime contract. */
    if (a[1] == WM_NOTIFY)
    {
        if (NtUserQueryWindow(H(0), QUERY_WINDOW_UNIQUE_THREAD_ID) !=
            (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread)
        {
            RtlSetLastWin32Error(ERROR_CALL_NOT_IMPLEMENTED);
            return FALSE;
        }
        Param = (LPARAM)P(3);
    }
    else if (a[1] == WM_GETDLGCODE)
    {
        /* lParam is NULL or the MSG the dialog manager is about to handle. The
         * kernel does not inspect it and the window procedure reads the guest
         * layout, so on the calling thread it travels as the guest pointer
         * (zero-extended: a pointer above 2 GB is not a negative number). */
        if (a[3])
        {
            if (NtUserQueryWindow(H(0), QUERY_WINDOW_UNIQUE_THREAD_ID) !=
                (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread)
            {
                RtlSetLastWin32Error(ERROR_CALL_NOT_IMPLEMENTED);
                return FALSE;
            }
            Param = (LPARAM)P(3);
        }
    }
    else switch (a[1])
    {
#include "messages-unsupported.inc"
        /* A NULL lParam has no guest layout to translate: the message travels
         * as it is (the 32-bit user32 sends such a message to DefWindowProc and
         * to the SCROLLBAR window procedure, e.g. WM_HELP or WM_MDICREATE
         * with nothing attached). */
        if (!a[3]) break;
        RtlSetLastWin32Error(ERROR_CALL_NOT_IMPLEMENTED); return FALSE;
    default: break;
    }
    if (a[4]) ProbeOutput(a[4], sizeof(ULONG));
    switch (a[5])
    {
    case FNID_DEFWINDOWPROC: case FNID_SCROLLBAR: case FNID_DESKTOP: case FNID_MENU:
    case FNID_SENDMESSAGE: case FNID_SENDNOTIFYMESSAGE:
    case FNID_CALLWNDPROC: case FNID_CALLWNDPROCRET: break;
    case FNID_SENDMESSAGECALLBACK:
        if (!a[4]) return FALSE;
        Callback.CallBack = P32(((ULONG *)P(4))[0]); Callback.Context = ((ULONG *)P(4))[1];
        ResultInfo = (ULONG_PTR)&Callback; break;
    case FNID_SENDMESSAGEFF: case FNID_SENDMESSAGEWTOOPTION:
        if (!a[4]) return FALSE;
        ProbeOutput(a[4],3*sizeof(ULONG));
        Timeout.uFlags = ((ULONG *)P(4))[0]; Timeout.uTimeout = ((ULONG *)P(4))[1]; Timeout.Result = 0;
        ResultInfo = (ULONG_PTR)&Timeout; break;
    default:
        RtlSetLastWin32Error(ERROR_CALL_NOT_IMPLEMENTED); return FALSE;
    }
    /* Pointer-bearing messages used during creation and resizing. Plain
     * integer LPARAMs retain signed transport; flat buffers retain their address. */
    if (a[3]) switch (a[1])
    {
    case WM_CREATE: case WM_NCCREATE:
        Create32ToNative(&Buffer.Create, P(3)); Param = (LPARAM)&Buffer.Create; break;
    case WM_WINDOWPOSCHANGING: case WM_WINDOWPOSCHANGED:
        WindowPos32ToNative(&Buffer.Pos, P(3)); Param = (LPARAM)&Buffer.Pos; break;
    case WM_NCCALCSIZE:
        if (a[2])
        {
            const NCCALCSIZE32 *From = P(3);
            RtlCopyMemory(Buffer.Nc.Params.rgrc, From->rgrc, sizeof(From->rgrc));
            WindowPos32ToNative(&Buffer.Nc.Pos, P32(From->lppos));
            Buffer.Nc.Params.lppos = &Buffer.Nc.Pos; Param = (LPARAM)&Buffer.Nc.Params;
        }
        else Param = (LPARAM)P(3);
        break;
    case WM_MEASUREITEM:
    {
        const MEASUREITEM32 *From = P(3);
        RtlZeroMemory(&Buffer.Measure, sizeof(Buffer.Measure));
        Buffer.Measure.CtlType = From->CtlType; Buffer.Measure.CtlID = From->CtlID;
        Buffer.Measure.itemID = From->itemID; Buffer.Measure.itemWidth = From->itemWidth;
        Buffer.Measure.itemHeight = From->itemHeight; Buffer.Measure.itemData = From->itemData;
        Param = (LPARAM)&Buffer.Measure; break;
    }
    case WM_DRAWITEM:
    {
        /* hwndItem is the HMENU for ODT_MENU */
        const DRAWITEM32 *From = P(3);
        RtlZeroMemory(&Buffer.Draw, sizeof(Buffer.Draw));
        Buffer.Draw.CtlType = From->CtlType; Buffer.Draw.CtlID = From->CtlID;
        Buffer.Draw.itemID = From->itemID; Buffer.Draw.itemAction = From->itemAction;
        Buffer.Draw.itemState = From->itemState; Buffer.Draw.hwndItem = H32(From->hwndItem);
        Buffer.Draw.hDC = (HDC)(ULONG_PTR)From->hDC; Buffer.Draw.rcItem = From->rcItem;
        Buffer.Draw.itemData = From->itemData;
        Param = (LPARAM)&Buffer.Draw; break;
    }
    case WM_COPYDATA:
    {
        /* user32 packed the record and its data into one guest block. The
         * kernel copies sizeof(COPYDATASTRUCT) + cbData bytes from lParam,
         * ignoring lpData, so take the data from behind the guest record and
         * put it right behind the native one. */
        const COPYDATA32 *From = P(3);
        ULONG Bytes = From->cbData;
        if (Bytes > MAXLONG - sizeof(COPYDATASTRUCT))
        {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        Copy = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Copy) + Bytes);
        if (!Copy)
        {
            RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        _SEH2_TRY
        {
            Copy->dwData = From->dwData;
            Copy->cbData = Bytes;
            Copy->lpData = Copy + 1;
            RtlCopyMemory(Copy + 1, From + 1, Bytes);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, Copy);
            Copy = NULL;
        }
        _SEH2_END;
        if (!Copy)
        {
            RtlSetLastWin32Error(ERROR_NOACCESS);
            return FALSE;
        }
        Param = (LPARAM)Copy;
        break;
    }
    case WM_SETTEXT: case WM_GETTEXT: case WM_SETTINGCHANGE: case WM_GETMINMAXINFO: case WM_STYLECHANGING:
    case WM_STYLECHANGED: case WM_SIZING: case WM_MOVING:
    case EM_GETRECT: case EM_SETRECT: case EM_SETRECTNP: case EM_REPLACESEL: case EM_GETLINE:
    case LB_ADDSTRING: case LB_INSERTSTRING: case LB_FINDSTRING: case LB_FINDSTRINGEXACT:
    case LB_SELECTSTRING: case LB_GETTEXT: case LB_GETITEMRECT:
    case CB_ADDSTRING: case CB_INSERTSTRING: case CB_FINDSTRING: case CB_FINDSTRINGEXACT:
    case CB_SELECTSTRING: case CB_GETLBTEXT: case CB_GETDROPPEDCONTROLRECT: case WM_ASKCBFORMATNAME:
        Param = (LPARAM)P(3); break;
    }
    Ret = NtUserMessageCall(H(0), a[1], a[2], Param, ResultInfo, a[5], a[6]);
    if (Copy) RtlFreeHeap(RtlGetProcessHeap(), 0, Copy);
    if (a[3]) switch (a[1])
    {
    case WM_WINDOWPOSCHANGING: WindowPosNativeTo32(P(3), &Buffer.Pos); break;
    case WM_MEASUREITEM:
    {
        MEASUREITEM32 *To = P(3);
        To->CtlType = Buffer.Measure.CtlType; To->CtlID = Buffer.Measure.CtlID;
        To->itemID = Buffer.Measure.itemID; To->itemWidth = Buffer.Measure.itemWidth;
        To->itemHeight = Buffer.Measure.itemHeight; To->itemData = (ULONG)Buffer.Measure.itemData;
        break;
    }
    case WM_NCCALCSIZE:
        if (a[2])
        {
            NCCALCSIZE32 *To = P(3);
            RtlCopyMemory(To->rgrc, Buffer.Nc.Params.rgrc, sizeof(To->rgrc));
            WindowPosNativeTo32(P32(To->lppos), &Buffer.Nc.Pos);
        }
        break;
    }
    if (a[4])
    {
        if (a[5] == FNID_SENDMESSAGEFF || a[5] == FNID_SENDMESSAGEWTOOPTION)
            ((ULONG *)P(4))[2] = Timeout.Result;
        else if (a[5] != FNID_SENDMESSAGECALLBACK) *(ULONG *)P(4) = Result;
    }
    return Ret;
}

ULONG_PTR Wow64WinUserService(ULONG Number, ULONG *a)
{
    switch (Number)
    {
    case W64_NtGdiOpenDCW:
    {
        UNICODE_STRING Device, Log; PVOID Driver = NULL; HDC Dc;
        if (a[0]) String32(&Device,P(0));
        if (a[2]) String32(&Log,P(2));
        if (a[6]) ProbeOutput(a[6],sizeof(ULONG));
        Dc = NtGdiOpenDCW(a[0] ? &Device : NULL,P(1),a[2] ? &Log : NULL,a[3],a[4],H(5),a[6] ? &Driver : NULL);
        if (Dc && a[6]) *(ULONG *)P(6) = PtrToUlong(Driver);
        return (ULONG_PTR)Dc;
    }
    case W64_NtUserFindExistingCursorIcon:
    {
        UNICODE_STRING Module, Resource;
        if (a[0]) String32(&Module,P(0));
        if (a[1]) String32(&Resource,P(1));
        return (ULONG_PTR)NtUserFindExistingCursorIcon(a[0] ? &Module : NULL,a[1] ? &Resource : NULL,P(2));
    }
    case W64_NtUserDefSetText:
    { LARGE_STRING Text; return NtUserDefSetText(H(0),LargeString32(&Text,a[1])); }
    case W64_NtUserQueryWindow: return NtUserQueryWindow(H(0),a[1]);
    case W64_NtUserSetClipboardData:
    {
        SETCLIPBDATA Data = *(PSETCLIPBDATA)P(2);
        /* Converted global data uses a USER TYPE_CLIPDATA handle. Bitmap,
         * palette and opaque data retain unsigned GDI/address transport. */
        return (ULONG_PTR)NtUserSetClipboardData(a[0],Data.fGlobalHandle ? H(1) : G(1),&Data);
    }
    case W64_NtUserProcessConnect:
    {
        USERCONNECT Connect;
        NTSTATUS Status;
        if (!a[1] || a[2] != sizeof(Connect)) return STATUS_UNSUCCESSFUL;
        if (a[1] & (sizeof(ULONG) - 1)) RtlRaiseStatus(STATUS_DATATYPE_MISALIGNMENT);
        ProbeOutput(a[1], sizeof(Connect));
        /* Wide guest fields retain their native layout, but i386 callers
         * only promise four-byte alignment, including on a replaced stack. */
        RtlCopyMemory(&Connect, P(1), sizeof(Connect));
        Status = NtUserProcessConnect(H(0), &Connect, sizeof(Connect));
        if (NT_SUCCESS(Status)) RtlCopyMemory(P(1), &Connect, sizeof(Connect));
        return Status;
    }
    case W64_NtUserInitializeClientPfnArrays: return NtUserInitializeClientPfnArrays(P(0), P(1), P(2), P(3));
    case W64_NtUserRegisterClassExWOW:
    {
        WNDCLASSEXW Class;
        UNICODE_STRING Name, Version, MenuString;
        CLSMENUNAME Menu;
        const ULONG *Menu32 = P(3);
        if (((CLASS32 *)P(0))->cbSize != sizeof(CLASS32)) { RtlSetLastWin32Error(ERROR_INVALID_PARAMETER); return 0; }
        Class32ToNative(&Class, P(0)); String32(&Name, P(1)); String32(&Version, P(2));
        if (Menu32)
        {
            Menu.pszClientAnsiMenuName = P32(Menu32[0]); Menu.pwszClientUnicodeMenuName = P32(Menu32[1]);
            Menu.pusMenuName = NULL;
            if (Menu32[2]) { String32(&MenuString, P32(Menu32[2])); Menu.pusMenuName = &MenuString; }
        }
        return NtUserRegisterClassExWOW(&Class, &Name, &Version, Menu32 ? &Menu : NULL, a[4], a[5], P(6));
    }
    case W64_NtUserUnregisterClass:
    {
        UNICODE_STRING Name; CLSMENUNAME Menu = {0}; BOOL Ret;
        String32(&Name,P(0));
        Ret = NtUserUnregisterClass(&Name,P(1),a[2] ? &Menu : NULL);
        if (Ret && a[2])
        {
            ULONG *To=P(2);
            To[0]=PtrToUlong(Menu.pszClientAnsiMenuName);
            To[1]=PtrToUlong(Menu.pwszClientUnicodeMenuName);
            To[2]=PtrToUlong(Menu.pusMenuName);
        }
        return Ret;
    }
    case W64_NtUserGetClassInfo:
    {
        WNDCLASSEXW Class = {0}; UNICODE_STRING Name; LPWSTR Menu = NULL; BOOL Ret;
        ULONG GuestSize;
        ProbeOutput(a[2],sizeof(CLASS32));
        if (a[3]) ProbeOutput(a[3],sizeof(ULONG));
        String32(&Name, P(1)); Class32ToNative(&Class, P(2));
        GuestSize = ((CLASS32 *)P(2))->cbSize;
        Ret = NtUserGetClassInfo(P(0), &Name, &Class, a[3] ? &Menu : NULL, a[4]);
        if (Ret)
        {
            ClassNativeTo32(P(2), &Class);
            ((CLASS32 *)P(2))->cbSize = GuestSize;
            if (a[3]) *(ULONG *)P(3) = PtrToUlong(Menu);
        }
        return Ret;
    }
    case W64_NtUserCreateWindowEx:
    {
        LARGE_STRING Class, Version, Title;
        PLARGE_STRING pc = LargeString32(&Class,a[1]), pv = LargeString32(&Version,a[2]), pt = LargeString32(&Title,a[3]);
        return (ULONG_PTR)NtUserCreateWindowEx(a[0],pc,pv,pt,a[4],a[5],a[6],a[7],a[8],H(9),H(10),P(11),P(12),a[13],P(14));
    }
    case W64_NtUserGetMessage: case W64_NtUserPeekMessage:
    {
        MSG Msg = {0}; BOOL Ret;
        ProbeOutput(a[0],sizeof(MSG32));
        Ret = Number == W64_NtUserGetMessage ? NtUserGetMessage(&Msg,H(1),a[2],a[3]) : NtUserPeekMessage(&Msg,H(1),a[2],a[3],a[4]);
        if (Number == W64_NtUserGetMessage ? Ret != -1 : Ret) MsgNativeTo32(P(0), &Msg);
        return Ret;
    }
    case W64_NtUserDispatchMessage: case W64_NtUserTranslateMessage:
    {
        MSG Msg; Msg32ToNative(&Msg,P(0));
        return Number == W64_NtUserDispatchMessage ? NtUserDispatchMessage(&Msg) : NtUserTranslateMessage(&Msg,a[1]);
    }
    case W64_NtUserBeginPaint:
    {
        PAINTSTRUCT Paint = {0}; HDC Dc;
        ProbeOutput(a[1],sizeof(PAINT32));
        Dc = NtUserBeginPaint(H(0), &Paint);
        if (Dc) PaintNativeTo32(P(1), &Paint);
        return (ULONG_PTR)Dc;
    }
    case W64_NtUserEndPaint:
    {
        PAINTSTRUCT Paint; Paint32ToNative(&Paint,P(1)); return NtUserEndPaint(H(0), &Paint);
    }
    case W64_NtUserMessageCall: return MessageCall(a);
    case W64_NtUserCallNoParam: return NtUserCallNoParam(a[0]);
    case W64_NtUserCallHwnd: return NtUserCallHwnd(H(0),a[1]);
    case W64_NtUserCallHwndLock: return NtUserCallHwndLock(H(0),a[1]);
    case W64_NtUserCallHwndOpt: return (ULONG_PTR)NtUserCallHwndOpt(H(0),a[1]);
    case W64_NtUserGetThreadState: return NtUserGetThreadState(a[0]);
    case W64_NtUserCallOneParam:
    {
        ULONG_PTR Param = a[0];
        if (a[1] == ONEPARAM_ROUTINE_GETDESKTOPMAPPING)
        {
            PCLIENTINFO ci = (PCLIENTINFO)NtCurrentTeb()->Win32ClientInfo;
            if (!ci->pDeskInfo) return 0;
            Param |= (ULONG_PTR)ci->pDeskInfo->pvDesktopBase & ~((ULONG_PTR)MAXULONG);
        }
        else if (a[1] == ONEPARAM_ROUTINE_REPLYMESSAGE || a[1] == ONEPARAM_ROUTINE_SETMESSAGEEXTRAINFO)
            Param = S(0);
        return NtUserCallOneParam(Param,a[1]);
    }
    case W64_NtUserCallTwoParam:
    {
        ULONG_PTR p1 = a[0], p2 = a[1];
        switch (a[2])
        {
        case TWOPARAM_ROUTINE_ENABLEWINDOW: case TWOPARAM_ROUTINE_REDRAWTITLE:
        case TWOPARAM_ROUTINE_SHOWOWNEDPOPUPS: case TWOPARAM_ROUTINE_SWITCHTOTHISWINDOW:
        case TWOPARAM_ROUTINE_SETMENUBARHEIGHT: case TWOPARAM_ROUTINE_ROS_UPDATEUISTATE: p1 = S(0); break;
        case TWOPARAM_ROUTINE_SETGUITHRDHANDLE: p2 = S(1); break;
        }
        return NtUserCallTwoParam(p1,p2,a[2]);
    }
    case W64_NtUserCallHwndParam: return NtUserCallHwndParam(H(0),a[1],a[2]);
    case W64_NtUserCallHwndParamLock: return NtUserCallHwndParamLock(H(0),a[1],a[2]);
    case W64_NtUserGetObjectInformation: return NtUserGetObjectInformation(H(0),a[1],P(2),a[3],P(4));
    case W64_NtUserSetWindowLong:
        switch ((LONG)a[1])
        {
        case GWL_WNDPROC: case GWL_HINSTANCE: return NtUserSetWindowLongPtr(H(0),a[1],a[2],a[3]);
        case GWL_HWNDPARENT: return NtUserSetWindowLongPtr(H(0),a[1],S(2),a[3]);
        default: return NtUserSetWindowLong(H(0),a[1],a[2],a[3]);
        }
    case W64_NtUserSetClassLong:
        if ((LONG)a[1] >= 0) return NtUserSetClassLong(H(0),a[1],a[2],a[3]);
        if ((LONG)a[1] == GCL_MENUNAME || (LONG)a[1] == GCW_ATOM)
        {
            UNICODE_STRING Name;
            if (!a[2]) return NtUserSetClassLongPtr(H(0),a[1],0,a[3]);
            String32(&Name,P(2));
            return NtUserSetClassLongPtr(H(0),a[1],(ULONG_PTR)&Name,a[3]);
        }
        return NtUserSetClassLongPtr(H(0),a[1],
               ((LONG)a[1] == GCL_HICON || (LONG)a[1] == GCL_HICONSM || (LONG)a[1] == GCL_HCURSOR) ? S(2) : a[2],a[3]);
    case W64_NtUserMonitorFromPoint:
    { POINT Pt = {a[0],a[1]}; return (ULONG_PTR)NtUserMonitorFromPoint(Pt,a[2]); }
    case W64_NtUserDragDetect:
    { POINT Pt = {a[1],a[2]}; return NtUserDragDetect(H(0),Pt); }
    case W64_NtUserWindowFromPoint: return (ULONG_PTR)NtUserWindowFromPoint(a[0],a[1]);
    default:
        return Wow64WinExtraService(Number, a);
    }
}
