/* ReactOS WoW64 kernel-to-user32 callbacks.
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64win.h"

static PVOID GuestDispatcher;
typedef struct { STRING32 Library, Init; BOOL Unload, ApiHook; } LIBRARY32;
C_ASSERT(sizeof(LIBRARY32) == 24);
typedef struct { ULONG String, Dc; INT x, y; UINT Flags; RECT Rect; UINT Count; BOOL HasRect; } LPK32;
C_ASSERT(sizeof(LPK32) == 44);
typedef struct
{
    INT HookId, Code;
    ULONG wParam, lParam, Proc;
    INT Mod;
    ULONG offPfn;
    BOOLEAN Ansi;
    LONG Result;
    UINT lParamSize;
    WCHAR ModuleName[512];
} HOOK32;
typedef struct { ULONG lParam, wParam, message, hwnd; } CWP32;
typedef struct { LONG Result; CWP32 Cwp; } CWPR32;
typedef struct { HOOK32 Header; CWP32 Cwp; ULONG Extra[4]; } CWPCALL32;
typedef struct { HOOK32 Header; CWPR32 Cwp; ULONG Extra[4]; } CWPRCALL32;
C_ASSERT(sizeof(HOOK32) == 1064);
C_ASSERT(sizeof(CWPCALL32) == 1096);
C_ASSERT(sizeof(CWPRCALL32) == 1100);
/* i386 layouts of the records the other hook families carry after the header */
typedef struct { CREATE32 Cs; ULONG WndInsertAfter; } CBTCREATE32;
typedef struct { ULONG lpcs, hwndInsertAfter; } CBTCREATEWND32;
typedef struct { BOOL fMouse; ULONG hWndActive; } CBTACTIVATE32;
typedef struct { POINT pt; ULONG hwnd; UINT wHitTestCode; ULONG dwExtraInfo; } MOUSEHOOK32;
typedef struct { MOUSEHOOK32 Base; DWORD mouseData; } MOUSEHOOKEX32;
typedef struct { DWORD idThread, idThreadInstaller; ULONG lParam, wParam; INT code; } DEBUGHOOK32;
typedef struct { DWORD vkCode, scanCode, flags, time; ULONG dwExtraInfo; } KBDLL32;
typedef struct { POINT pt; DWORD mouseData, flags, time; ULONG dwExtraInfo; } MSLL32;
C_ASSERT(sizeof(CBTCREATE32) == 52);
C_ASSERT(sizeof(CBTACTIVATE32) == 8);
C_ASSERT(sizeof(MOUSEHOOK32) == 20);
C_ASSERT(sizeof(MOUSEHOOKEX32) == 24);
C_ASSERT(sizeof(KBDLL32) == 20);
C_ASSERT(sizeof(DEBUGHOOK32) == 20);
C_ASSERT(sizeof(MSLL32) == 24);
typedef struct
{
    WOW64_CPU_STATE *Previous;
    PVOID Native;
    ULONG NativeLength, GuestLength, Id, ExceptionList;
    /* HOOKPROC callbacks: the hook the callback runs, read once from the native buffer */
    INT HookId, Code;
    ULONG64 Handles[7];
} CALLBACK_FRAME;

static VOID ProbeGuestStack(ULONG Top, ULONG_PTR Bottom)
{
    TEB32 *Teb = WOW64_TEB32(NtCurrentTeb());
    ULONG_PTR Address, Reserve = Teb->DeallocationStack, Base = Teb->NtTib.StackBase;
    SIZE_T Guarantee;
    if (Base <= Reserve || Top > Base || Bottom > Top || Bottom < Reserve)
        RtlRaiseStatus(STATUS_STACK_OVERFLOW);
    Guarantee = ROUND_TO_PAGES(min((SIZE_T)Teb->GuaranteedStackBytes, Base - Reserve));
    if (Bottom - Reserve <= PAGE_SIZE + Guarantee)
        RtlRaiseStatus(STATUS_STACK_OVERFLOW);
    /* Fault each guard page in order, like _chkstk. MiCheckForUserStackOverflow
     * identifies the guest stack by its address even though this code is 64-bit. */
    Address = (Top - 1) & ~(ULONG_PTR)(PAGE_SIZE - 1);
    while (Address > Bottom)
    {
        *(volatile BYTE *)Address = *(volatile BYTE *)Address;
        Address -= PAGE_SIZE;
    }
    *(volatile BYTE *)Bottom = *(volatile BYTE *)Bottom;
}

static LONG PayloadSize(UINT Msg, WPARAM Wparam, LONG Size)
{
    if (Size < 0) return Size;
    switch (Msg)
    {
    case WM_CREATE: case WM_NCCREATE:
        return Size >= sizeof(CREATESTRUCTW) ? Size - sizeof(CREATESTRUCTW) + sizeof(CREATE32) : -2;
    case WM_WINDOWPOSCHANGING: case WM_WINDOWPOSCHANGED:
        return Size == sizeof(WINDOWPOS) ? sizeof(WINDOWPOS32) : -2;
    case WM_NCCALCSIZE:
        if (!Wparam) return Size == sizeof(RECT) ? Size : -2;
        return Size == sizeof(NCCALCSIZE_PARAMS) + sizeof(WINDOWPOS) ? sizeof(NCCALCSIZE32) + sizeof(WINDOWPOS32) : -2;
    case WM_GETMINMAXINFO: case WM_GETTEXT: case WM_SETTEXT: case WM_SETTINGCHANGE:
    case WM_STYLECHANGING: case WM_STYLECHANGED: case WM_SIZING: case WM_MOVING:
    case WM_ERASEBKGND: case WM_PAINT: case WM_NCPAINT:
        return Size;
    case WM_MEASUREITEM:
        return Size == sizeof(MEASUREITEMSTRUCT) ? sizeof(MEASUREITEM32) : -2;
    case WM_DRAWITEM:
        return Size == sizeof(DRAWITEMSTRUCT) ? sizeof(DRAWITEM32) : -2;
    case WM_HELP:
        return Size == sizeof(HELPINFO) ? sizeof(HELPINFO32) : -2;
    case WM_NEXTMENU:
        return Size == sizeof(MDINEXTMENU) ? sizeof(MDINEXTMENU32) : -2;
    case WM_COPYGLOBALDATA:
        /* wParam bytes of the sender's global block, opaque to the kernel and to this layer */
        return Size;
    case WM_COPYDATA:
        /* The record is followed by its cbData bytes */
        return Size >= sizeof(COPYDATASTRUCT) ? Size - sizeof(COPYDATASTRUCT) + sizeof(COPYDATA32) : -2;
    default: return -2;
    }
}

static VOID PackPayload(PVOID To, const PVOID From, UINT Msg, WPARAM Wparam, ULONG Size)
{
    switch (Msg)
    {
    case WM_CREATE: case WM_NCCREATE:
    {
        const CREATESTRUCTW *Native = From;
        CREATE32 *Guest = To;
        ULONG Tail = Size - sizeof(*Native);
        /* The strings are offsets into this packed block, not addresses. */
        if ((ULONG_PTR)Native->lpszName < sizeof(*Native) ||
            (ULONG_PTR)Native->lpszName >= Size ||
            (ULONG_PTR)Native->lpszClass < sizeof(*Native) ||
            (ULONG_PTR)Native->lpszClass >= Size)
            RtlRaiseStatus(STATUS_INVALID_PARAMETER);
        CreateNativeTo32(Guest, Native);
        Guest->lpszName -= sizeof(*Native) - sizeof(*Guest);
        Guest->lpszClass -= sizeof(*Native) - sizeof(*Guest);
        RtlCopyMemory(Guest + 1, Native + 1, Tail);
        break;
    }
    case WM_WINDOWPOSCHANGING: case WM_WINDOWPOSCHANGED:
        WindowPosNativeTo32(To, From); break;
    case WM_MEASUREITEM:
    {
        /* win32k's menu code measures owner-drawn items this way; the item
         * data of a guest's menu item is a guest value. */
        const MEASUREITEMSTRUCT *Native = From;
        MEASUREITEM32 *Guest = To;
        Guest->CtlType = Native->CtlType; Guest->CtlID = Native->CtlID; Guest->itemID = Native->itemID;
        Guest->itemWidth = Native->itemWidth; Guest->itemHeight = Native->itemHeight;
        Guest->itemData = (ULONG)Native->itemData;
        break;
    }
    case WM_DRAWITEM:
    {
        /* hwndItem is the HMENU for ODT_MENU */
        const DRAWITEMSTRUCT *Native = From;
        DRAWITEM32 *Guest = To;
        Guest->CtlType = Native->CtlType; Guest->CtlID = Native->CtlID; Guest->itemID = Native->itemID;
        Guest->itemAction = Native->itemAction; Guest->itemState = Native->itemState;
        Guest->hwndItem = HandleToUlong(Native->hwndItem); Guest->hDC = HandleToUlong(Native->hDC);
        Guest->rcItem = Native->rcItem; Guest->itemData = (ULONG)Native->itemData;
        break;
    }
    case WM_HELP:
        HelpNativeTo32(To, From); break;
    case WM_NEXTMENU:
        NextMenuNativeTo32(To, From); break;
    case WM_COPYDATA:
    {
        const COPYDATASTRUCT *Native = From;
        COPYDATA32 *Guest = To;
        ULONG Tail = Size - sizeof(*Native);
        /* Read-only for the receiver: nothing is copied back. A sender's
         * pointer-sized dwData keeps its low 32 bits. */
        if (Native->cbData != Tail) RtlRaiseStatus(STATUS_INVALID_PARAMETER);
        Guest->dwData = (ULONG)Native->dwData;
        Guest->cbData = Tail;
        Guest->lpData = PtrToUlong(Guest + 1);
        RtlCopyMemory(Guest + 1, Native + 1, Tail);
        break;
    }
    case WM_NCCALCSIZE:
        if (Wparam)
        {
            NCCALCSIZE32 *Guest = To;
            NCCALCSIZE_PARAMS *Native = From;
            RtlCopyMemory(Guest->rgrc, Native->rgrc, sizeof(Guest->rgrc));
            Guest->lppos = PtrToUlong(Guest + 1);
            WindowPosNativeTo32((PVOID)(Guest + 1), (PVOID)(Native + 1));
            break;
        }
        /* fall through */
    default: RtlCopyMemory(To, From, Size); break;
    }
}

static VOID UnpackPayload(PVOID To, const PVOID From, UINT Msg, WPARAM Wparam, ULONG Size)
{
    switch (Msg)
    {
    case WM_CREATE: case WM_NCCREATE:
        /* The guest dispatcher has changed the packed string offsets to
         * addresses, just as native user32 does. Preserve the reply fields. */
        Create32ToNative(To, From);
        break;
    case WM_WINDOWPOSCHANGING:
        WindowPos32ToNative(To, From); break;
    case WM_NCCALCSIZE:
        if (Wparam)
        {
            NCCALCSIZE_PARAMS *Native = To;
            const NCCALCSIZE32 *Guest = From;
            RtlCopyMemory(Native->rgrc, Guest->rgrc, sizeof(Native->rgrc));
            WindowPos32ToNative((PVOID)(Native + 1), (PVOID)(Guest + 1));
        }
        else RtlCopyMemory(To, From, sizeof(RECT));
        break;
    case WM_MEASUREITEM:
    {
        /* The whole record is the reply, as win32k copies it back. A
         * native itemData keeps its high bits unless the guest changed it. */
        MEASUREITEMSTRUCT *Native = To;
        const MEASUREITEM32 *Guest = From;
        Native->CtlType = Guest->CtlType; Native->CtlID = Guest->CtlID; Native->itemID = Guest->itemID;
        Native->itemWidth = Guest->itemWidth;
        Native->itemHeight = Guest->itemHeight;
        if (Guest->itemData != (ULONG)Native->itemData) Native->itemData = Guest->itemData;
        break;
    }
    case WM_HELP:
        /* the whole record is the reply, as win32k copies it back */
        Help32ToNative(To, From); break;
    case WM_NEXTMENU:
        /* win32k copies the record back: the menu loop reads hmenuNext and hwndNext from it */
        NextMenu32ToNative(To, From); break;
    case WM_GETMINMAXINFO: case WM_GETTEXT: case WM_STYLECHANGING: case WM_SIZING: case WM_MOVING:
        RtlCopyMemory(To, From, Size); break;
    }
}

/* CALLWND hooks receive a CWP structure followed by the message buffer.
 * Unlike WINDOWPROC's CREATE packet, these are ordinary CREATESTRUCT fields,
 * not offsets. Other pointer messages use the same kernel packing rules. */
/* A message whose payload has no translation (size -2): one debug line per process and message */
static VOID ReportMessage(UINT Message, LONG Size)
{
    if (Wow64WinFirstReport(1, Message))
        DbgPrint("WoW64win: unsupported callback message %x size %ld, pid %lx\n", Message, Size,
                 HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess));
}

static LONG HookPayloadSize(const HOOKPROC_CALLBACK_ARGUMENTS *Header)
{
    const CWPSTRUCT *Cwp;
    LONG Size;
    if (Header->HookId == WH_CALLWNDPROC)
        Cwp = &((const CWP_Struct *)Header)->cwps;
    else
        Cwp = (const CWPSTRUCT *)&((const CWPR_Struct *)Header)->cwprs.lParam;
    if (!Header->lParamSize) return 0;
    if (Cwp->message == WM_CREATE || Cwp->message == WM_NCCREATE)
        Size = Header->lParamSize == sizeof(CREATESTRUCTW) ? sizeof(CREATE32) : -2;
    else
        Size = PayloadSize(Cwp->message, Cwp->wParam, Header->lParamSize);
    if (Size == -2) ReportMessage(Cwp->message, Header->lParamSize);
    return Size;
}

/* Sizes of the record that win32k's co_IntCallHookProc places after the
 * header (lParam is then its offset) for the non-CALLWND families. A zero
 * size means lParam is a plain value. FALSE: no translation. */
static BOOL HookRecordSizes(INT HookId, INT Code, ULONG *Native, ULONG *Guest)
{
    *Native = *Guest = 0;
    switch (HookId)
    {
    case WH_GETMESSAGE: case WH_MSGFILTER: case WH_SYSMSGFILTER:
        *Native = sizeof(MSG); *Guest = sizeof(MSG32); return TRUE;
    case WH_KEYBOARD_LL:
        *Native = sizeof(KBDLLHOOKSTRUCT); *Guest = sizeof(KBDLL32); return TRUE;
    case WH_MOUSE_LL:
        *Native = sizeof(MSLLHOOKSTRUCT); *Guest = sizeof(MSLL32); return TRUE;
    case WH_MOUSE:
        *Native = sizeof(MOUSEHOOKSTRUCTEX); *Guest = sizeof(MOUSEHOOKEX32); return TRUE;
    case WH_KEYBOARD: case WH_SHELL: case WH_FOREGROUNDIDLE:
        return TRUE;
    case WH_CBT:
        switch (Code)
        {
        case HCBT_CREATEWND:
            *Native = sizeof(HOOKPROC_CBT_CREATEWND_EXTRA_ARGUMENTS); *Guest = sizeof(CBTCREATE32); return TRUE;
        case HCBT_MOVESIZE:
            *Native = *Guest = sizeof(RECTL); return TRUE;
        case HCBT_ACTIVATE:
            *Native = sizeof(CBTACTIVATESTRUCT); *Guest = sizeof(CBTACTIVATE32); return TRUE;
        case HCBT_CLICKSKIPPED:
            *Native = sizeof(MOUSEHOOKSTRUCT); *Guest = sizeof(MOUSEHOOK32); return TRUE;
        case HCBT_KEYSKIPPED: case HCBT_MINMAX: case HCBT_SETFOCUS: case HCBT_SYSCOMMAND:
        case HCBT_DESTROYWND: case HCBT_QS:
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

static VOID MouseNativeTo32(MOUSEHOOK32 *To, const MOUSEHOOKSTRUCT *From)
{
    To->pt = From->pt; To->hwnd = HandleToUlong(From->hwnd);
    To->wHitTestCode = From->wHitTestCode; To->dwExtraInfo = (ULONG)From->dwExtraInfo;
}

static VOID Mouse32ToNative(MOUSEHOOKSTRUCT *To, const MOUSEHOOK32 *From)
{
    To->pt = From->pt; To->hwnd = H32(From->hwnd);
    To->wHitTestCode = From->wHitTestCode; To->dwExtraInfo = From->dwExtraInfo;
}

static VOID KeyboardLl32ToNative(KBDLLHOOKSTRUCT *To, const KBDLL32 *From)
{
    To->vkCode = From->vkCode; To->scanCode = From->scanCode; To->flags = From->flags;
    To->time = From->time; To->dwExtraInfo = From->dwExtraInfo;
}

static VOID MouseLl32ToNative(MSLLHOOKSTRUCT *To, const MSLL32 *From)
{
    To->pt = From->pt; To->mouseData = From->mouseData; To->flags = From->flags;
    To->time = From->time; To->dwExtraInfo = From->dwExtraInfo;
}

/* The record win32k puts at Input for the hook HookId and code Code, as the i386 record at Output */
static VOID PackRecord(INT HookId, INT Code, PVOID Output, const VOID *Input)
{
    switch (HookId)
    {
    case WH_GETMESSAGE: case WH_MSGFILTER: case WH_SYSMSGFILTER:
        MsgNativeTo32(Output, Input);
        break;
    case WH_KEYBOARD_LL:
    {
        const KBDLLHOOKSTRUCT *Native = Input;
        KBDLL32 *Guest = Output;
        Guest->vkCode = Native->vkCode; Guest->scanCode = Native->scanCode; Guest->flags = Native->flags;
        Guest->time = Native->time; Guest->dwExtraInfo = (ULONG)Native->dwExtraInfo;
        break;
    }
    case WH_MOUSE_LL:
    {
        const MSLLHOOKSTRUCT *Native = Input;
        MSLL32 *Guest = Output;
        Guest->pt = Native->pt; Guest->mouseData = Native->mouseData; Guest->flags = Native->flags;
        Guest->time = Native->time; Guest->dwExtraInfo = (ULONG)Native->dwExtraInfo;
        break;
    }
    case WH_MOUSE:
    {
        const MOUSEHOOKSTRUCTEX *Native = Input;
        MOUSEHOOKEX32 *Guest = Output;
        MouseNativeTo32(&Guest->Base, &Native->MOUSEHOOKSTRUCT);
        Guest->mouseData = Native->mouseData;
        break;
    }
    case WH_CBT:
        switch (Code)
        {
        case HCBT_CREATEWND:
        {
            const HOOKPROC_CBT_CREATEWND_EXTRA_ARGUMENTS *Native = Input;
            CBTCREATE32 *Guest = Output;
            /* The class and window name are the creator's pointers, desktop
             * heap copies or atoms; all are guest addresses here. */
            if ((ULONG_PTR)Native->Cs.lpszName > MAXULONG || (ULONG_PTR)Native->Cs.lpszClass > MAXULONG)
                RtlRaiseStatus(STATUS_NOT_SUPPORTED);
            CreateNativeTo32(&Guest->Cs, &Native->Cs);
            Guest->WndInsertAfter = HandleToUlong(Native->WndInsertAfter);
            break;
        }
        case HCBT_MOVESIZE:
            RtlCopyMemory(Output, Input, sizeof(RECTL));
            break;
        case HCBT_ACTIVATE:
        {
            const CBTACTIVATESTRUCT *Native = Input;
            CBTACTIVATE32 *Guest = Output;
            Guest->fMouse = Native->fMouse; Guest->hWndActive = HandleToUlong(Native->hWndActive);
            break;
        }
        case HCBT_CLICKSKIPPED:
            MouseNativeTo32(Output, Input);
            break;
        }
        break;
    }
}

static VOID PackHookRecord(HOOK32 *To, const HOOKPROC_CALLBACK_ARGUMENTS *From)
{
    PackRecord(From->HookId, From->Code, To + 1, From + 1);
}

/* The records a WH_DEBUG call carries behind its DEBUGHOOKINFO: those of the hooks whose lParam win32k's
 * IntDebugHookRecordSize copies. Their sizes are those of the hook itself. */
static VOID DebugRecordSizes(INT HookId, INT Code, ULONG *Native, ULONG *Guest)
{
    *Native = *Guest = 0;
    switch (HookId)
    {
    case WH_MSGFILTER: case WH_SYSMSGFILTER: case WH_GETMESSAGE: case WH_MOUSE:
        HookRecordSizes(HookId, Code, Native, Guest);
        break;
    case WH_CBT:
        if (Code == HCBT_MOVESIZE || Code == HCBT_ACTIVATE || Code == HCBT_CLICKSKIPPED || Code == HCBT_CREATEWND)
            HookRecordSizes(HookId, Code, Native, Guest);
        break;
    }
}

/* The record of a CALLWNDPROC(RET) debug call is the CWPSTRUCT or CWPRETSTRUCT and the data the lParam of its
 * message points to; Native is the debug call's buffer, whose lParamSize is the size of all that. Returns the size
 * of the i386 record, or -1 if there is none that can be converted. */
static LONG DebugCwpGuestSize(const HOOKPROC_CALLBACK_ARGUMENTS *Native, const DEBUGHOOKINFO *Info)
{
    BOOL Ret = Native->wParam == WH_CALLWNDPROCRET;
    ULONG Base = Ret ? sizeof(CWPRETSTRUCT) : sizeof(CWPSTRUCT), GuestBase = Ret ? sizeof(CWPR32) : sizeof(CWP32);
    const CWPSTRUCT *Cwp = Ret ? (const CWPSTRUCT *)&((const CWPRETSTRUCT *)(Info + 1))->lParam : (const CWPSTRUCT *)(Info + 1);
    ULONG Extra;
    LONG Size;
    if (Native->lParamSize < Base) return -1;
    Extra = Native->lParamSize - Base;
    if (!Extra) return GuestBase;
    if (Cwp->message == WM_CREATE || Cwp->message == WM_NCCREATE)
        return Extra == sizeof(CREATESTRUCTW) ? GuestBase + sizeof(CREATE32) : -1;
    Size = PayloadSize(Cwp->message, Cwp->wParam, Extra);
    if (Size < 0) return -1;
    return GuestBase + Size;
}

/* A CWPSTRUCT as the i386 CWP32, the data its lParam points to (NativePayload bytes at Input) as the GuestPayload
 * bytes at Output */
static VOID PackCwp(const CWPSTRUCT *Native, const VOID *Input, CWP32 *Guest, PVOID Output, ULONG NativePayload, LONG GuestPayload)
{
    Guest->lParam = Native->lParam; Guest->wParam = Native->wParam;
    Guest->message = Native->message; Guest->hwnd = HandleToUlong(Native->hwnd);
    if (GuestPayload)
    {
        if (Native->message == WM_CREATE || Native->message == WM_NCCREATE)
        {
            const CREATESTRUCTW *Create = Input;
            /* Original guest strings/pointers are retained by the kernel. */
            if ((ULONG_PTR)Create->lpszName > MAXULONG || (ULONG_PTR)Create->lpszClass > MAXULONG)
                RtlRaiseStatus(STATUS_NOT_SUPPORTED);
            CreateNativeTo32(Output, Input);
        }
        else PackPayload(Output, Input, Native->message, Native->wParam, NativePayload);
    }
}

static VOID PackHook(HOOK32 *To, const HOOKPROC_CALLBACK_ARGUMENTS *From, LONG Size)
{
    const CWPSTRUCT *Native;
    CWP32 *Guest;
    PVOID Input, Output;
    ULONG NativeRecord, GuestRecord;
    To->HookId = From->HookId; To->Code = From->Code;
    To->wParam = From->wParam; To->lParam = From->lParam;
    To->Proc = PtrToUlong(From->Proc); To->Mod = From->Mod;
    To->offPfn = From->offPfn; To->Ansi = From->Ansi;
    To->Result = 0; To->lParamSize = Size;
    RtlCopyMemory(To->ModuleName, From->ModuleName, sizeof(To->ModuleName));
    if (From->HookId == WH_DEBUG)
    {
        /* The DEBUGHOOKINFO follows the header; a record, when there is one, follows that */
        const DEBUGHOOKINFO *NativeInfo = (const DEBUGHOOKINFO *)(From + 1);
        DEBUGHOOK32 *GuestInfo = (DEBUGHOOK32 *)(To + 1);
        To->lParam = sizeof(*To);
        GuestInfo->idThread = NativeInfo->idThread;
        GuestInfo->idThreadInstaller = NativeInfo->idThreadInstaller;
        GuestInfo->wParam = (ULONG)NativeInfo->wParam;
        GuestInfo->code = NativeInfo->code;
        if (Size)
        {
            GuestInfo->lParam = sizeof(*To) + sizeof(*GuestInfo);
            if (From->wParam == WH_CALLWNDPROC)
            {
                const CWPSTRUCT *Cwp = (const CWPSTRUCT *)(NativeInfo + 1);
                CWP32 *GuestCwp = (CWP32 *)(GuestInfo + 1);
                PackCwp(Cwp, Cwp + 1, GuestCwp, GuestCwp + 1, From->lParamSize - sizeof(CWPSTRUCT), Size - sizeof(CWP32));
            }
            else if (From->wParam == WH_CALLWNDPROCRET)
            {
                const CWPRETSTRUCT *Cwpr = (const CWPRETSTRUCT *)(NativeInfo + 1);
                CWPR32 *GuestCwpr = (CWPR32 *)(GuestInfo + 1);
                GuestCwpr->Result = (LONG)Cwpr->lResult;
                PackCwp((const CWPSTRUCT *)&Cwpr->lParam, Cwpr + 1, &GuestCwpr->Cwp, GuestCwpr + 1,
                        From->lParamSize - sizeof(CWPRETSTRUCT), Size - sizeof(CWPR32));
            }
            else
                PackRecord((INT)From->wParam, NativeInfo->code, GuestInfo + 1, NativeInfo + 1);
        }
        else GuestInfo->lParam = (ULONG)NativeInfo->lParam;
        return;
    }
    if (From->HookId != WH_CALLWNDPROC && From->HookId != WH_CALLWNDPROCRET)
    {
        /* The callback validated the family and its record size */
        HookRecordSizes(From->HookId, From->Code, &NativeRecord, &GuestRecord);
        if (NativeRecord)
        {
            To->lParam = sizeof(*To);
            PackHookRecord(To, From);
        }
        return;
    }
    if (From->HookId == WH_CALLWNDPROC)
    {
        Native = &((const CWP_Struct *)From)->cwps;
        Input = (PVOID)&((const CWP_Struct *)From)->Extra;
        Guest = &((CWPCALL32 *)To)->Cwp;
        Output = &((CWPCALL32 *)To)->Extra;
    }
    else
    {
        Native = (const CWPSTRUCT *)&((const CWPR_Struct *)From)->cwprs.lParam;
        Input = (PVOID)&((const CWPR_Struct *)From)->Extra;
        Guest = &((CWPRCALL32 *)To)->Cwp.Cwp;
        ((CWPRCALL32 *)To)->Cwp.Result = ((const CWPR_Struct *)From)->cwprs.lResult;
        Output = &((CWPRCALL32 *)To)->Extra;
    }
    PackCwp(Native, Input, Guest, Output, From->lParamSize, Size);
}

static NTSTATUS Callback(ULONG Id, PVOID Buffer, ULONG Length)
{
    WOW64_CPU_STATE *Previous = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU];
    WOW64_CPU_STATE Cpu;
    CALLBACK_FRAME Frame;
    ULONG GuestLength = Length, *Stack;
    PVOID Guest;
    LONG Payload = -1;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;
    if (!Previous || !GuestDispatcher) return Status;
    Frame.Previous = Previous; Frame.Native = Buffer;
    Frame.NativeLength = Length; Frame.Id = Id;
    Frame.HookId = Frame.Code = 0;
    Frame.ExceptionList = WOW64_TEB32(NtCurrentTeb())->NtTib.ExceptionList;
    _SEH2_TRY
    {
        switch (Id)
        {
        case USER32_CALLBACK_HOOKPROC:
        {
            HOOKPROC_CALLBACK_ARGUMENTS *Native = Buffer;
            ULONG Base, NativeRecord, GuestRecord;
            if (Length < sizeof(*Native)) break;
            Frame.HookId = Native->HookId; Frame.Code = Native->Code;
            if (Native->HookId == WH_DEBUG)
            {
                const DEBUGHOOKINFO *Info = (const DEBUGHOOKINFO *)(Native + 1);
                if (Length < sizeof(*Native) + sizeof(*Info) || (ULONG_PTR)Native->lParam != sizeof(*Native)) break;
                DebugRecordSizes((INT)Native->wParam, Info->code, &NativeRecord, &GuestRecord);
                if ((Native->wParam == WH_CALLWNDPROC || Native->wParam == WH_CALLWNDPROCRET) && Native->lParamSize)
                {
                    LONG Record = DebugCwpGuestSize(Native, Info);
                    if (Record < 0) break;
                    NativeRecord = Native->lParamSize; GuestRecord = Record;
                }
                /* No record: the lParam of the hook was a plain value or not passed on */
                if (Native->lParamSize && Native->lParamSize != NativeRecord) break;
                if (Length != sizeof(*Native) + sizeof(*Info) + Native->lParamSize) break;
                Payload = Native->lParamSize ? GuestRecord : 0;
                GuestLength = sizeof(HOOK32) + sizeof(DEBUGHOOK32) + Payload;
                Status = STATUS_SUCCESS;
                break;
            }
            if (Native->HookId != WH_CALLWNDPROC && Native->HookId != WH_CALLWNDPROCRET)
            {
                if (!HookRecordSizes(Native->HookId, Native->Code, &NativeRecord, &GuestRecord))
                {
                    if (Wow64WinFirstReport(2, (ULONG)(Native->HookId + 1) << 16 | (USHORT)Native->Code))
                        DbgPrint("WoW64win: unsupported hook callback %d code %d\n", Native->HookId, Native->Code);
                    Payload = -2;
                    break;
                }
                if (Length != sizeof(*Native) + NativeRecord || Native->lParamSize ||
                    (NativeRecord && (ULONG_PTR)Native->lParam != sizeof(*Native))) break;
                GuestLength = sizeof(HOOK32) + GuestRecord;
                Payload = 0;
                Status = STATUS_SUCCESS;
                break;
            }
            if (Native->HookId == WH_CALLWNDPROC) Base = sizeof(CWP_Struct);
            else Base = sizeof(CWPR_Struct);
            if (Length < Base || Native->lParamSize != Length - Base) break;
            Payload = HookPayloadSize(Native);
            if (Payload < 0) break;
            GuestLength = (Native->HookId == WH_CALLWNDPROC ? sizeof(CWPCALL32) : sizeof(CWPRCALL32)) + Payload;
            Status = STATUS_SUCCESS;
            break;
        }
        case USER32_CALLBACK_WINDOWPROC:
        {
            WINDOWPROC_CALLBACK_ARGUMENTS *Native = Buffer;
            if (Length < sizeof(*Native) || Native->lParamBufferSize < -1) break;
            if (Length != sizeof(*Native) + max(Native->lParamBufferSize, 0)) break;
            Payload = PayloadSize(Native->Msg, Native->wParam, Native->lParamBufferSize);
            if (Payload == -2) { ReportMessage(Native->Msg, Native->lParamBufferSize); break; }
            GuestLength = sizeof(WINDOWPROC32) + max(Payload,0); Status = STATUS_SUCCESS; break;
        }
        case USER32_CALLBACK_SENDASYNCPROC:
            if (Length == sizeof(SENDASYNCPROC_CALLBACK_ARGUMENTS)) { GuestLength = 20; Status = STATUS_SUCCESS; } break;
        case USER32_CALLBACK_CLIENTTHREADSTARTUP: case USER32_CALLBACK_LOADSYSMENUTEMPLATE:
        case USER32_CALLBACK_DELIVERUSERAPC:
            if (!Length) Status = STATUS_SUCCESS;
            break;
        case USER32_CALLBACK_LOADDEFAULTCURSORS:
            if (Length == sizeof(BOOL)) Status = STATUS_SUCCESS;
            break;
        case USER32_CALLBACK_GETCHARSETINFO:
            if (Length == sizeof(GET_CHARSET_INFO)) Status = STATUS_SUCCESS;
            break;
        case USER32_CALLBACK_SETOBM:
            if (Length == sizeof(SETOBM_CALLBACK_ARGUMENTS)) Status = STATUS_SUCCESS;
            break;
        case USER32_CALLBACK_CLIENTLOADLIBRARY:
            if (Length >= sizeof(CLIENT_LOAD_LIBRARY_ARGUMENTS))
            { GuestLength = Length-sizeof(CLIENT_LOAD_LIBRARY_ARGUMENTS)+sizeof(LIBRARY32); Status=STATUS_SUCCESS; } break;
        case USER32_CALLBACK_SETWNDICONS:
            if (Length == sizeof(SETWNDICONS_CALLBACK_ARGUMENTS)) { GuestLength = 7*sizeof(ULONG); Status = STATUS_SUCCESS; } break;
        case USER32_CALLBACK_LOADMENU:
            if (Length >= FIELD_OFFSET(LOADMENU_CALLBACK_ARGUMENTS, MenuName))
            { GuestLength = Length - FIELD_OFFSET(LOADMENU_CALLBACK_ARGUMENTS, MenuName) + 8; Status = STATUS_SUCCESS; } break;
        case USER32_CALLBACK_COPYIMAGE:
            if (Length == sizeof(COPYIMAGE_CALLBACK_ARGUMENTS)) { GuestLength = 20; Status = STATUS_SUCCESS; } break;
        case USER32_CALLBACK_LPK:
            if (Length >= sizeof(LPK_CALLBACK_ARGUMENTS))
            {
                LPK_CALLBACK_ARGUMENTS *Native = Buffer;
                ULONG_PTR Offset = (ULONG_PTR)Native->lpString;
                if (Offset >= sizeof(*Native) && Offset <= Length && Native->count <= (Length - Offset) / sizeof(WCHAR))
                { GuestLength = Length - sizeof(*Native) + sizeof(LPK32); Status = STATUS_SUCCESS; }
            }
            break;
        }
        if (NT_SUCCESS(Status))
        {
            /* Guest stack storage survives nested syscalls and callbacks. The
             * native frame stays live until NtCallbackReturn unwinds this call. */
            if (GuestLength > 1024 * 1024 || Previous->Esp < GuestLength + 256)
                RtlRaiseStatus(STATUS_STACK_OVERFLOW);
            /* The arguments end within 15 bytes of the guest ESP, as in the layout Windows 10 gives its WoW64 callbacks
             * (ntdll_winetest exception test_KiUserCallbackDispatcher) */
            Guest = P32((Previous->Esp - GuestLength) & ~15);
            Stack = (ULONG *)Guest - 8;
            ProbeGuestStack(Previous->Esp, (ULONG_PTR)Stack);
            Frame.GuestLength = GuestLength;
            switch (Id)
            {
            case USER32_CALLBACK_HOOKPROC:
                PackHook(Guest, Buffer, Payload);
                break;
            case USER32_CALLBACK_WINDOWPROC:
            {
                WINDOWPROC_CALLBACK_ARGUMENTS *Native = Buffer;
                WINDOWPROC32 *Target = Guest;
                Target->Proc = PtrToUlong(Native->Proc); Target->IsAnsiProc = Native->IsAnsiProc;
                Target->Wnd = HandleToUlong(Native->Wnd); Target->Msg = Native->Msg;
                Target->wParam = Native->wParam; Target->lParam = Native->lParam;
                Target->lParamBufferSize = Payload; Target->Result = 0;
                if (Payload >= 0) PackPayload(Target+1,Native+1,Native->Msg,Native->wParam,Native->lParamBufferSize);
                break;
            }
            case USER32_CALLBACK_SENDASYNCPROC:
            {
                SENDASYNCPROC_CALLBACK_ARGUMENTS *Native = Buffer; ULONG *Target = Guest;
                Target[0]=PtrToUlong(Native->Callback); Target[1]=HandleToUlong(Native->Wnd);
                Target[2]=Native->Msg; Target[3]=Native->Context; Target[4]=Native->Result; break;
            }
            case USER32_CALLBACK_LOADMENU:
            {
                LOADMENU_CALLBACK_ARGUMENTS *Native = Buffer; ULONG *Target = Guest;
                Target[0]=HandleToUlong(Native->hModule); Target[1]=PtrToUlong(Native->InterSource);
                RtlCopyMemory(Target+2,Native->MenuName,GuestLength-8); break;
            }
            case USER32_CALLBACK_COPYIMAGE:
            {
                COPYIMAGE_CALLBACK_ARGUMENTS *Native = Buffer; ULONG *Target = Guest;
                Target[0]=HandleToUlong(Native->hImage); Target[1]=Native->uType;
                Target[2]=Native->cxDesired; Target[3]=Native->cyDesired; Target[4]=Native->fuFlags; break;
            }
            case USER32_CALLBACK_CLIENTLOADLIBRARY:
            {
                CLIENT_LOAD_LIBRARY_ARGUMENTS *Native=Buffer;
                LIBRARY32 *Target=Guest;
                const UNICODE_STRING *Src[2]={&Native->strLibraryName,&Native->strInitFuncName};
                STRING32 *Dst[2]={&Target->Library,&Target->Init};
                ULONG i;
                RtlZeroMemory(Target,sizeof(*Target));
                for (i=0;i<2;++i) if (Src[i]->Buffer)
                {
                    ULONG_PTR Offset=(ULONG_PTR)Src[i]->Buffer;
                    if (Offset < sizeof(*Native) || Offset > Length || Src[i]->MaximumLength > Length-Offset ||
                        Src[i]->Length > Src[i]->MaximumLength) RtlRaiseStatus(STATUS_INVALID_PARAMETER);
                    Dst[i]->Length=Src[i]->Length; Dst[i]->MaximumLength=Src[i]->MaximumLength;
                    Dst[i]->Buffer=Offset-sizeof(*Native)+sizeof(*Target);
                }
                Target->Unload=Native->Unload; Target->ApiHook=Native->ApiHook;
                RtlCopyMemory(Target+1,Native+1,Length-sizeof(*Native)); break;
            }
            case USER32_CALLBACK_SETWNDICONS:
                RtlZeroMemory(Guest,GuestLength); break;
            case USER32_CALLBACK_LPK:
            {
                LPK_CALLBACK_ARGUMENTS *Native = Buffer; LPK32 *Target = Guest;
                Target->String = (ULONG_PTR)Native->lpString - sizeof(*Native) + sizeof(*Target);
                Target->Dc = HandleToUlong(Native->hdc); Target->x = Native->x; Target->y = Native->y;
                Target->Flags = Native->flags; Target->Rect = Native->rect; Target->Count = Native->count; Target->HasRect = Native->bRect;
                RtlCopyMemory(Target + 1, Native + 1, Length - sizeof(*Native));
                break;
            }
            default: RtlCopyMemory(Guest,Buffer,GuestLength); break;
            }
            /* i386 KiUserCallbackDispatcher: return, index, buffer, length,
             * followed by the two-word exception registration. */
            RtlZeroMemory(Stack,8*sizeof(ULONG));
            Stack[1]=Id; Stack[2]=PtrToUlong(Guest); Stack[3]=GuestLength;
            /* the guest ESP of the interrupted code and the first argument word follow the two unknowns, where
             * Windows 10 keeps them (the 32-bit KiUserCallbackDispatcher hook of the winetest reads both) */
            Stack[6]=Previous->Esp; Stack[7]=GuestLength >= sizeof(ULONG) ? *(ULONG *)Guest : 0;
            WOW64_TEB32(NtCurrentTeb())->LastErrorValue = NtCurrentTeb()->LastErrorValue;
            Cpu = *Previous; Cpu.CallbackFrame = &Frame;
            Cpu.Esp = PtrToUlong(Stack); Cpu.Eip = PtrToUlong(GuestDispatcher);
            Wow64CpuRun(&Cpu);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    /* An unsupported message was already reported by name */
    if (Payload != -2) DbgPrint("WoW64win: callback %lu failed %lx\n",Id,Status);
    return NtCallbackReturn(NULL,0,Status);
}

NTSTATUS NTAPI Wow64WinCallbackReturn(PVOID Buffer, ULONG Length, NTSTATUS Status)
{
    WOW64_CPU_STATE *Cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU];
    CALLBACK_FRAME *Frame = Cpu ? Cpu->CallbackFrame : NULL;
    PVOID Output = NULL;
    ULONG OutputLength = 0, i;
    if (!Frame) return STATUS_NO_CALLBACK_ACTIVE;
    if (Status == STATUS_CALLBACK_POP_STACK)
    {
        WOW64_CPU_STATE *Previous = Frame->Previous;
        ULONG64 NativeStack = Previous->NativeStack;
        PVOID ApcFrame = Previous->ApcFrame;
        PVOID CallbackFrame = Previous->CallbackFrame;

        /* POP_STACK resumes this native NtCallbackReturn call after win32k
         * has unwound its callout. The guest must then resume the i386 stub
         * inside KiUserCallbackExceptionHandler, not the interrupted USER
         * syscall. Move that continuation to the surviving simulation frame;
         * the next guest syscall uses its original native stack. Each nested
         * callback is popped separately as i386 RtlUnwind walks the SEH chain.
         * Leave ExceptionList alone: RtlUnwind owns its removal here.
         * The nested frame is inside this service, so its guard is clear,
         * and Wow64SystemService closes the transition only on that stale
         * frame. Close it before the copy, so the frame the guest resumes on
         * keeps the guard and no context request sees a partial copy. */
        InterlockedExchange(&Cpu->InTransition, 1);
        *Previous = *Cpu;
        Previous->NativeStack = NativeStack;
        Previous->ApcFrame = ApcFrame;
        Previous->CallbackFrame = CallbackFrame;
        NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU] = Previous;
        NtCurrentTeb()->LastErrorValue = WOW64_TEB32(NtCurrentTeb())->LastErrorValue;
        /* Likewise the service result belongs to the surviving frame. */
        Status = NtCallbackReturn(NULL, 0, Status);
        if (!Previous->ContextEaxChanged) Previous->Eax = Status;
        return Status;
    }
    _SEH2_TRY
    {
        if (NT_SUCCESS(Status)) switch (Frame->Id)
        {
        case USER32_CALLBACK_HOOKPROC:
        {
            HOOKPROC_CALLBACK_ARGUMENTS *Native = Frame->Native;
            if (!Buffer || Length != Frame->GuestLength) { Status = STATUS_INFO_LENGTH_MISMATCH; break; }
            Native->Result = ((HOOK32 *)Buffer)->Result;
            /* The records win32k copies back; CALLWND hooks have no
             * message-buffer writeback contract. */
            if (Frame->HookId == WH_GETMESSAGE)
                Msg32ToNative((MSG *)(Native + 1), (const MSG32 *)((HOOK32 *)Buffer + 1));
            else if (Frame->HookId == WH_CBT && Frame->Code == HCBT_CREATEWND)
            {
                HOOKPROC_CBT_CREATEWND_EXTRA_ARGUMENTS *Create = (PVOID)(Native + 1);
                const CBTCREATE32 *Guest = (const VOID *)((HOOK32 *)Buffer + 1);
                Create->Cs.x = Guest->Cs.x; Create->Cs.y = Guest->Cs.y;
                Create->Cs.cx = Guest->Cs.cx; Create->Cs.cy = Guest->Cs.cy;
                /* HWND_TOPMOST and HWND_NOTOPMOST are negative */
                Create->WndInsertAfter = H32(Guest->WndInsertAfter);
            }
            else if (Frame->HookId == WH_CBT && Frame->Code == HCBT_MOVESIZE)
                RtlCopyMemory(Native + 1, (HOOK32 *)Buffer + 1, sizeof(RECTL));
            Output = Native; OutputLength = Frame->NativeLength;
            break;
        }
        case USER32_CALLBACK_WINDOWPROC:
        {
            WINDOWPROC_CALLBACK_ARGUMENTS *Native = Frame->Native;
            WINDOWPROC32 *Guest = Buffer;
            if (!Buffer || Length != Frame->GuestLength) { Status = STATUS_INFO_LENGTH_MISMATCH; break; }
            Native->Result = Guest->Result;
            if (Native->lParamBufferSize >= 0)
                UnpackPayload(Native+1,Guest+1,Native->Msg,Native->wParam,Native->lParamBufferSize);
            Output = Native; OutputLength = Frame->NativeLength; break;
        }
        case USER32_CALLBACK_CLIENTLOADLIBRARY:
            if (!Buffer || Length != sizeof(BOOL)) { Status = STATUS_INFO_LENGTH_MISMATCH; break; }
            Frame->Handles[0] = *(ULONG *)Buffer;
            Output = Frame->Handles; OutputLength = sizeof(HINSTANCE); break;
        case USER32_CALLBACK_LOADMENU: case USER32_CALLBACK_LOADSYSMENUTEMPLATE:
        case USER32_CALLBACK_LOADDEFAULTCURSORS: case USER32_CALLBACK_COPYIMAGE:
            if (!Buffer || Length != sizeof(ULONG)) { Status = STATUS_INFO_LENGTH_MISMATCH; break; }
            /* COPYIMAGE's image type determines whether this is a GDI handle. */
            Frame->Handles[0] = (Frame->Id == USER32_CALLBACK_COPYIMAGE &&
                ((COPYIMAGE_CALLBACK_ARGUMENTS *)Frame->Native)->uType == IMAGE_BITMAP) ?
                *(ULONG *)Buffer : (ULONG64)(LONG64)*(LONG *)Buffer;
            Output=Frame->Handles; OutputLength=sizeof(ULONG64); break;
        case USER32_CALLBACK_SETWNDICONS:
            if (!Buffer || Length != 7*sizeof(ULONG)) { Status = STATUS_INFO_LENGTH_MISMATCH; break; }
            for (i=0;i<7;++i) Frame->Handles[i] = (LONG64)((LONG *)Buffer)[i];
            Output=Frame->Handles; OutputLength=sizeof(Frame->Handles); break;
        case USER32_CALLBACK_GETCHARSETINFO: case USER32_CALLBACK_SETOBM:
            if (!Buffer || Length != Frame->NativeLength) { Status=STATUS_INFO_LENGTH_MISMATCH; break; }
            RtlCopyMemory(Frame->Native,Buffer,Length);
            Output=Frame->Native; OutputLength=Frame->NativeLength; break;
        case USER32_CALLBACK_LPK:
            if (!Buffer || Length != sizeof(BOOL)) { Status = STATUS_INFO_LENGTH_MISMATCH; break; }
            Frame->Handles[0] = *(ULONG *)Buffer;
            Output = Frame->Handles; OutputLength = sizeof(BOOL); break;
        default: break;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode(); Output=NULL; OutputLength=0;
    }
    _SEH2_END;
    NtCurrentTeb()->LastErrorValue = WOW64_TEB32(NtCurrentTeb())->LastErrorValue;
    Frame->Previous->FsRedirectionDisabled = Cpu->FsRedirectionDisabled;
    /* Callback changes to the floating-point environment survive the USER
     * call. Keep the outer register data, but propagate its control state. */
    *(USHORT *)Frame->Previous->ExtendedRegisters = *(USHORT *)Cpu->ExtendedRegisters;
    *(ULONG *)(Frame->Previous->ExtendedRegisters + 24) = *(ULONG *)(Cpu->ExtendedRegisters + 24);
    NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU] = Frame->Previous;
    WOW64_TEB32(NtCurrentTeb())->NtTib.ExceptionList = Frame->ExceptionList;
    return NtCallbackReturn(Output,OutputLength,Status);
}

ULONG_PTR Wow64WinCallNextHook(ULONG *a)
{
    WOW64_CPU_STATE *Cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU];
    CALLBACK_FRAME *Frame = Cpu ? Cpu->CallbackFrame : NULL;
    union
    {
        MSG Message;
        KBDLLHOOKSTRUCT KeyboardLl;
        MSLLHOOKSTRUCT MouseLl;
        MOUSEHOOKSTRUCTEX Mouse;
        CBTACTIVATESTRUCT Activate;
        struct { CBT_CREATEWNDW Cbt; CREATESTRUCTW Cs; } Create;
    } Native;
    INT HookId, Code = (INT)a[0];
    LPARAM Lparam = a[2];
    LRESULT Result;
    /* The callback, not a caller-supplied selector, determines lParam's ABI:
     * win32k chains the hook that this callback runs. */
    if (!Frame || Frame->Id != USER32_CALLBACK_HOOKPROC)
    {
        RtlSetLastWin32Error(ERROR_CALL_NOT_IMPLEMENTED);
        return 0;
    }
    HookId = Frame->HookId;
    /* Padding and unread fields must not carry stack garbage to the next hook */
    RtlZeroMemory(&Native, sizeof(Native));
    switch (HookId)
    {
    case WH_GETMESSAGE: case WH_MSGFILTER: case WH_SYSMSGFILTER:
        if (!a[2]) break;
        Msg32ToNative(&Native.Message, P32(a[2]));
        Result = NtUserCallNextHookEx(Code, a[1], (LPARAM)&Native.Message, a[3]);
        /* Only GETMESSAGE hooks may change the message */
        if (HookId == WH_GETMESSAGE) MsgNativeTo32(P32(a[2]), &Native.Message);
        return (LONG_PTR)Result;
    case WH_KEYBOARD_LL:
        if (!a[2]) break;
        KeyboardLl32ToNative(&Native.KeyboardLl, P32(a[2]));
        Lparam = (LPARAM)&Native.KeyboardLl;
        break;
    case WH_MOUSE_LL:
        if (!a[2]) break;
        MouseLl32ToNative(&Native.MouseLl, P32(a[2]));
        Lparam = (LPARAM)&Native.MouseLl;
        break;
    case WH_MOUSE:
        if (!a[2]) break;
        Mouse32ToNative(&Native.Mouse.MOUSEHOOKSTRUCT, P32(a[2]));
        /* Windows reads the MOUSEHOOKSTRUCTEX; a caller may have chained the plain 20-byte record
         * whose end is the end of its memory. Like win32k, keep mouseData zero when it is not there. */
        _SEH2_TRY
        {
            Native.Mouse.mouseData = ((MOUSEHOOKEX32 *)P32(a[2]))->mouseData;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Native.Mouse.mouseData = 0;
        }
        _SEH2_END;
        Lparam = (LPARAM)&Native.Mouse;
        break;
    case WH_KEYBOARD: case WH_SHELL: case WH_FOREGROUNDIDLE:
        break;
    case WH_CBT:
        if (!a[2]) break;
        switch (Code)
        {
        case HCBT_CREATEWND:
        {
            CBTCREATEWND32 *Guest = P32(a[2]);
            CREATE32 *GuestCs = P32(Guest->lpcs);
            /* win32k reads the strings and writes the position back */
            Create32ToNative(&Native.Create.Cs, GuestCs);
            Native.Create.Cbt.lpcs = &Native.Create.Cs;
            Native.Create.Cbt.hwndInsertAfter = H32(Guest->hwndInsertAfter);
            Result = NtUserCallNextHookEx(Code, a[1], (LPARAM)&Native.Create.Cbt, a[3]);
            GuestCs->x = Native.Create.Cs.x; GuestCs->y = Native.Create.Cs.y;
            GuestCs->cx = Native.Create.Cs.cx; GuestCs->cy = Native.Create.Cs.cy;
            Guest->hwndInsertAfter = HandleToUlong(Native.Create.Cbt.hwndInsertAfter);
            return (LONG_PTR)Result;
        }
        case HCBT_ACTIVATE:
        {
            CBTACTIVATE32 *Guest = P32(a[2]);
            Native.Activate.fMouse = Guest->fMouse;
            Native.Activate.hWndActive = H32(Guest->hWndActive);
            Lparam = (LPARAM)&Native.Activate;
            break;
        }
        case HCBT_CLICKSKIPPED:
            /* win32k accepts the record without mouseData */
            RtlZeroMemory(&Native.Mouse, sizeof(Native.Mouse));
            Mouse32ToNative(&Native.Mouse.MOUSEHOOKSTRUCT, P32(a[2]));
            Lparam = (LPARAM)&Native.Mouse;
            break;
        /* HCBT_MOVESIZE: a RECT has the same layout. The other codes pass values. */
        }
        break;
    default:
        /* CALLWND chaining goes through NtUserMessageCall. */
        RtlSetLastWin32Error(ERROR_CALL_NOT_IMPLEMENTED);
        return 0;
    }
    return (LONG_PTR)NtUserCallNextHookEx(Code, a[1], Lparam, a[3]);
}

#define DEFINE_USER32_CALLBACK(id, value, fn) \
    static NTSTATUS NTAPI Win64_##fn(PVOID Buffer, ULONG Length) { return Callback(value,Buffer,Length); }
#include <u32cb.h>
#undef DEFINE_USER32_CALLBACK
static PVOID NativeCallbacks[] = {
#define DEFINE_USER32_CALLBACK(id, value, fn) Win64_##fn,
#include <u32cb.h>
#undef DEFINE_USER32_CALLBACK
};

NTSTATUS NTAPI Wow64WinInitialize(PVOID Dispatcher)
{
    if (!Dispatcher) return STATUS_INVALID_PARAMETER;
    GuestDispatcher = Dispatcher;
    NtCurrentPeb()->KernelCallbackTable = NativeCallbacks;
    return STATUS_SUCCESS;
}
