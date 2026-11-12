/* ReactOS WoW64 win32k translation. SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#define NTOS_MODE_USER
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <objbase.h>
#include <winuser.h>
#include <imm.h>
#include <immdev.h>
#include <imm32_undoc.h>
#include <ndk/ntndk.h>
#include <winddi.h>
#include <prntfont.h>
#include <ddrawi.h>
#include <d3dkmthk.h>
#include <ntusrtyp.h>
#include <ntuser.h>
#include <ntgdityp.h>
#include <ntgdi.h>
#include <ntgdibad.h>
#include <callback.h>
#include <pseh/pseh2.h>
#include <reactos/wow64.h>

#define P32(v) ((PVOID)(ULONG_PTR)(ULONG)(v))
#define H32(v) ((HANDLE)(LONG_PTR)(LONG)(v))
#define P(i) P32(a[i])
#define H(i) H32(a[i])
#define G(i) ((HANDLE)(ULONG_PTR)a[i])
#define S(i) ((LONG_PTR)(LONG)a[i])

enum {
    W64_Base = 0xfff,
#define SVC_(name, count) W64_Nt##name,
#undef _WIN64
#include <w32ksvc32.h>
#define _WIN64 1
#undef SVC_
};

/* The guest's win32k syscall numbers come from the SysWOW64 win32u, generated
 * from this same w32ksvc32.h; the name-based dispatch above is correct only
 * while the W64_ enum reproduces that numbering. These assertions pin the shared
 * syscall base and the size of the checked-build-only block, so a reordered
 * header, a changed base, or a DBG skew against the win32k that assigned the
 * numbers fails this build instead of silently misrouting the trailing
 * syscalls (everything after the checked-build block). */
C_ASSERT(W64_NtGdiAbortDoc == 0x1000); /* win32ss/napi.h MIN_SYSCALL_NUMBER */
#if DBG
C_ASSERT(W64_NtGdiMakeObjectXferable == W64_NtGdiDrawStream + 6);
#else
C_ASSERT(W64_NtGdiMakeObjectXferable == W64_NtGdiDrawStream + 1);
#endif

typedef struct { ULONG Length, MaximumLength, Buffer; } LARGE_STRING32;
typedef struct { ULONG hwnd, message, wParam, lParam, time; POINT pt; } MSG32;
typedef struct { ULONG hdc; BOOL fErase; RECT rcPaint; BOOL fRestore, fIncUpdate; BYTE rgbReserved[32]; } PAINT32;
typedef struct {
    ULONG cbSize, style, lpfnWndProc; INT cbClsExtra, cbWndExtra;
    ULONG hInstance, hIcon, hCursor, hbrBackground, lpszMenuName, lpszClassName, hIconSm;
} CLASS32;
typedef struct {
    ULONG lpCreateParams, hInstance, hMenu, hwndParent;
    INT cy, cx, y, x; LONG style; ULONG lpszName, lpszClass; DWORD dwExStyle;
} CREATE32;
typedef struct { ULONG hwnd, hwndInsertAfter; INT x, y, cx, cy; UINT flags; } WINDOWPOS32;
typedef struct { RECT rgrc[3]; ULONG lppos; } NCCALCSIZE32;
typedef struct { ULONG Proc; BOOL IsAnsiProc; ULONG Wnd, Msg, wParam, lParam; INT lParamBufferSize; LONG Result; } WINDOWPROC32;
typedef struct { ULONG dwData, cbData, lpData; } COPYDATA32;
typedef struct { UINT CtlType, CtlID, itemID, itemWidth, itemHeight; ULONG itemData; } MEASUREITEM32;
typedef struct
{
    UINT CtlType, CtlID, itemID, itemAction, itemState;
    ULONG hwndItem, hDC; RECT rcItem; ULONG itemData;
} DRAWITEM32;
typedef struct { UINT cbSize; INT iContextType, iCtrlId; ULONG hItemHandle, dwContextId; POINT MousePos; } HELPINFO32;
C_ASSERT(sizeof(HELPINFO32) == 28);
#ifndef WM_COPYGLOBALDATA
#define WM_COPYGLOBALDATA 0x0049 /* undocuser.h */
#endif
typedef struct { ULONG hmenuIn, hmenuNext, hwndNext; } MDINEXTMENU32;
C_ASSERT(sizeof(MDINEXTMENU32) == 12);
C_ASSERT(sizeof(STRING32) == 8);
C_ASSERT(sizeof(MSG32) == 28);
C_ASSERT(sizeof(PAINT32) == 64);
C_ASSERT(sizeof(CLASS32) == 48);
C_ASSERT(sizeof(CREATE32) == 48);
C_ASSERT(sizeof(WINDOWPOS32) == 28);
C_ASSERT(sizeof(NCCALCSIZE32) == 52);
C_ASSERT(sizeof(WINDOWPROC32) == 32);
C_ASSERT(sizeof(COPYDATA32) == 12);
C_ASSERT(sizeof(MEASUREITEM32) == 24);
C_ASSERT(sizeof(DRAWITEM32) == 48);
C_ASSERT(sizeof(USERCONNECT) == 576);
C_ASSERT(sizeof(WINDOWPROC_CALLBACK_ARGUMENTS) == 64);

VOID Msg32ToNative(MSG *To, const MSG32 *From);
VOID MsgNativeTo32(MSG32 *To, const MSG *From);
VOID Create32ToNative(CREATESTRUCTW *To, const CREATE32 *From);
VOID CreateNativeTo32(CREATE32 *To, const CREATESTRUCTW *From);
VOID WindowPos32ToNative(WINDOWPOS *To, const WINDOWPOS32 *From);
VOID WindowPosNativeTo32(WINDOWPOS32 *To, const WINDOWPOS *From);
VOID Help32ToNative(HELPINFO *To, const HELPINFO32 *From);
VOID HelpNativeTo32(HELPINFO32 *To, const HELPINFO *From);
VOID NextMenu32ToNative(MDINEXTMENU *To, const MDINEXTMENU32 *From);
VOID NextMenuNativeTo32(MDINEXTMENU32 *To, const MDINEXTMENU *From);
ULONG_PTR Wow64WinUserService(ULONG Number, ULONG *a);
ULONG_PTR Wow64WinExtraService(ULONG Number, ULONG *a);
ULONG_PTR Wow64WinGdiService(ULONG Number, ULONG *a);
ULONG_PTR Wow64WinGdiExtraService(ULONG Number, ULONG *a);
ULONG_PTR Wow64WinD3dkmtService(ULONG Number, ULONG *a);
ULONG_PTR Wow64WinUserInputService(ULONG Number, ULONG *a);
ULONG_PTR Wow64WinUserImeService(ULONG Number, ULONG *a);
ULONG_PTR Wow64WinUserDisplayService(ULONG Number, ULONG *a);
ULONG_PTR Wow64WinUserMiscService(ULONG Number, ULONG *a);
NTSTATUS NTAPI Wow64WinInitialize(PVOID Dispatcher);
NTSTATUS NTAPI Wow64WinCallbackReturn(PVOID Buffer, ULONG Length, NTSTATUS Status);
ULONG_PTR Wow64WinCallNextHook(ULONG *Arguments);

BOOL NTAPI NtGdiGetRealizationInfo(HDC hdc, PREALIZATION_INFO Info, HFONT Font);
DWORD NTAPI NtDxEngGetRedirectionBitmap(DWORD Unknown);

ULONG_PTR Wow64WinFailure(ULONG Number, NTSTATUS Status);
/* Kind 0: service number, 1: callback message, 2: hook id and code. TRUE the first time in the process */
BOOLEAN Wow64WinFirstReport(ULONG Kind, ULONG Value);
