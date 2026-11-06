#pragma once

typedef struct _CLIP
{
    UINT   fmt;
    HANDLE hData;
    BOOL   fGlobalHandle;
    /* hData is a GDI object the clipboard took over (it deletes it when it drops the format) */
    BOOL   fOwned;
} CLIP, *PCLIP;

UINT APIENTRY
UserEnumClipboardFormats(UINT uFormat);

VOID FASTCALL
UserClipboardRelease(PWND pWindow);

VOID FASTCALL
UserClipboardFreeWindow(PWND pWindow);

BOOL NTAPI
UserOpenClipboard(HWND hWnd);

BOOL NTAPI
UserCloseClipboard(VOID);

BOOL NTAPI
UserEmptyClipboard(VOID);

VOID NTAPI
UserEmptyClipboardData(struct _WINSTATION_OBJECT *pWinSta);

VOID NTAPI
UserClipboardFreeListeners(struct _WINSTATION_OBJECT *pWinSta);

HANDLE NTAPI
UserSetClipboardData(UINT fmt, HANDLE hData, PSETCLIPBDATA scd);
