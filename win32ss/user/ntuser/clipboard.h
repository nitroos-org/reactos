#pragma once

typedef struct _CLIP
{
    UINT   fmt;
    HANDLE hData;
    BOOL   fGlobalHandle;
    /* hData is a GDI object the clipboard took over (it deletes it when it drops the format) */
    BOOL   fOwned;
    /* The bytes of paged pool the bitmap in hData was charged against the clipboard limit (a bitmap the
       clipboard made itself), given back when the format is dropped */
    SIZE_T cbCharge;
} CLIP, *PCLIP;

/* What the clipboard may hold in paged pool, for every format of every window station: the data objects
   (what a program puts on it and what is made from that) and the bitmaps made for CF_BITMAP. An object over the
   limit is refused as an out of memory is: NULL and ERROR_NOT_ENOUGH_MEMORY. */
PVOID FASTCALL
UserClipDataAlloc(SIZE_T Size);

VOID FASTCALL
UserClipDataFree(PVOID Object);

/* A data object a program made with NtUserConvertMemHandle belongs to nobody until the clipboard takes it
   (UserSetClipboardData): it is the program's to give up when the call that should take it fails, and it is freed
   with the program when it never makes that call */
VOID FASTCALL
UserClipDataMarkUnclaimed(PVOID Object);

VOID FASTCALL
UserClipDataClaim(PVOID Object);

VOID FASTCALL
UserClipDataProcessExit(PPROCESSINFO ppi);

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
