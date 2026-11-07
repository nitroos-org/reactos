/******************************************************************************
 *
 * Common definitions (resource ids and global variables)
 *
 * Copyright 1999 Thuy Nguyen
 * Copyright 1999 Eric Kohl
 * Copyright 2002 Dimitrie O. Paun
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINE_COMCTL32_H
#define __WINE_COMCTL32_H

#ifndef RC_INVOKED
#include <stdarg.h>
#endif

#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "winnls.h"
#include "commctrl.h"
#include "windowsx.h"

#ifdef __REACTOS__
// This is really ComCtl32 v5.82, the last one not supporting SxS
#undef  COMCTL32_VERSION // Undefines what the PSDK gave to us
#define COMCTL32_VERSION        5
#define COMCTL32_VERSION_MINOR 82
#endif

/* NitroOS/ReactOS: one binary serves both the v5 and the v6 (SxS) classes, with the
 * theming of the v6 classes done by uxtheme at run time; the Wine code is built as v6 */
#ifndef __WINE_COMCTL32_VERSION
#define __WINE_COMCTL32_VERSION 6
#endif

#if __WINE_COMCTL32_VERSION == 6 || defined(__REACTOS__)
#include "uxtheme.h"
#include "vsstyle.h"
#include "vssym32.h"
#endif
#if __WINE_COMCTL32_VERSION == 5 && defined(__REACTOS__)
/* the v5 controls never have a theme (ReactOS's own theme code for them is dead code there) */
#define GetWindowTheme(hwnd) ((HTHEME)NULL)
#endif

#ifdef __REACTOS__
/* ReactOS ships one comctl32.dll that is both the v5 (5.82) and the v6 (SxS, themed) common controls, where
 * Wine builds two DLLs from the same sources. The controls whose code differs between the two are compiled twice:
 * v5/<control>.c defines __WINE_COMCTL32_VERSION as 5, renames the entry points below with the _v5 suffix and
 * includes the ../<control>.c of the v6 build. commctrl.c registers the _v5 classes in the v5 activation context. */
#if __WINE_COMCTL32_VERSION == 5
#define COMCTL32_CloseThemeForWindow COMCTL32_CloseThemeForWindow_v5
#define COMCTL32_IsThemed            COMCTL32_IsThemed_v5
#define COMCTL32_NCPaint             COMCTL32_NCPaint_v5
#define COMCTL32_OpenThemeForWindow  COMCTL32_OpenThemeForWindow_v5
#define COMCTL32_SetVersion          COMCTL32_SetVersion_v5
#define COMCTL32_ThemeChanged        COMCTL32_ThemeChanged_v5
#define DATETIME_Register            DATETIME_Register_v5
#define HEADER_Register              HEADER_Register_v5
#define IPADDRESS_Register           IPADDRESS_Register_v5
#define LISTVIEW_Register            LISTVIEW_Register_v5
#define MONTHCAL_Register            MONTHCAL_Register_v5
#define MONTHCAL_MonthLength         MONTHCAL_MonthLength_v5
#define MONTHCAL_CalculateDayOfWeek  MONTHCAL_CalculateDayOfWeek_v5
#define MONTHCAL_CompareSystemTime   MONTHCAL_CompareSystemTime_v5
#define PROGRESS_Register            PROGRESS_Register_v5
#define REBAR_Register               REBAR_Register_v5
#define STATUS_Register              STATUS_Register_v5
#define TAB_Register                 TAB_Register_v5
#define TRACKBAR_Register            TRACKBAR_Register_v5
#define TREEVIEW_Register            TREEVIEW_Register_v5
#define UPDOWN_Register              UPDOWN_Register_v5
#endif
#endif /* __REACTOS__ */

extern HMODULE COMCTL32_hModule;
extern HBRUSH  COMCTL32_hPattern55AABrush;

/* Property sheet / Wizard */
#define IDD_PROPSHEET 1006
#define IDD_WIZARD    1020

#define IDC_TABCONTROL   12320
#define IDC_APPLY_BUTTON 12321
#define IDC_BACK_BUTTON  12323
#define IDC_NEXT_BUTTON  12324
#define IDC_FINISH_BUTTON 12325
#define IDC_SUNKEN_LINE   12326
#define IDC_SUNKEN_LINEHEADER 12327

#define IDS_CLOSE	  4160

/* Toolbar customization dialog */
#define IDD_TBCUSTOMIZE     200

#define IDC_AVAILBTN_LBOX   201
#define IDC_RESET_BTN       202
#define IDC_TOOLBARBTN_LBOX 203
#define IDC_REMOVE_BTN      204
#define IDC_HELP_BTN        205
#define IDC_MOVEUP_BTN      206
#define IDC_MOVEDN_BTN      207

#define IDS_SEPARATOR      1024

/* Toolbar imagelist bitmaps */
#define IDB_STD_SMALL       120
#define IDB_STD_LARGE       121
#define IDB_VIEW_SMALL      124
#define IDB_VIEW_LARGE      125
#define IDB_HIST_SMALL      130
#define IDB_HIST_LARGE      131

#define IDM_TODAY                      4163
#define IDM_GOTODAY                    4164

/* Treeview Checkboxes */

#define IDT_CHECK        401

/* Command Link arrow */
#define IDB_CMDLINK      402


/* Cursors */
#define IDC_MOVEBUTTON                  102
#define IDC_COPY                        104
#define IDC_DIVIDER                     106
#define IDC_DIVIDEROPEN                 107


/* DragList resources */
#define IDI_DRAGARROW                   501

/* HOTKEY internal strings */
#define HKY_NONE                        2048

/* Tooltip icons */
#define IDI_TT_INFO_SM                   22
#define IDI_TT_WARN_SM                   25
#define IDI_TT_ERROR_SM                  28
#define IDI_TT_INFO_MD                   20
#define IDI_TT_WARN_MD                   23
#define IDI_TT_ERROR_MD                  26

/* Taskdialog strings */
#define IDS_BUTTON_YES    3000
#define IDS_BUTTON_NO     3001
#define IDS_BUTTON_RETRY  3002
#define IDS_BUTTON_OK     3003
#define IDS_BUTTON_CANCEL 3004
#define IDS_BUTTON_CLOSE  3005

#define IDS_TD_EXPANDED   3020
#define IDS_TD_COLLAPSED  3021

#ifndef __REACTOS__
#define WM_SYSTIMER     0x0118
#endif

enum combobox_state_flags
{
    CBF_DROPPED      = 0x0001,
    CBF_BUTTONDOWN   = 0x0002,
    CBF_NOROLLUP     = 0x0004,
    CBF_MEASUREITEM  = 0x0008,
    CBF_FOCUSED      = 0x0010,
    CBF_CAPTURE      = 0x0020,
    CBF_EDIT         = 0x0040,
    CBF_NORESIZE     = 0x0080,
    CBF_NOTIFY       = 0x0100,
    CBF_NOREDRAW     = 0x0200,
    CBF_SELCHANGE    = 0x0400,
    CBF_HOT          = 0x0800,
    CBF_NOEDITNOTIFY = 0x1000,
    CBF_NOLBSELECT   = 0x2000, /* do not change current selection */
    CBF_BEENFOCUSED  = 0x4000, /* has it ever had focus           */
    CBF_EUI          = 0x8000,
};

typedef struct
{
   HWND           self;
   HWND           owner;
   UINT           dwStyle;
   HWND           hWndEdit;
   HWND           hWndLBox;
   UINT           wState;
   HFONT          hFont;
   RECT           textRect;
   RECT           buttonRect;
   RECT           droppedRect;
   INT            droppedIndex;
   INT            fixedOwnerDrawHeight;
   INT            droppedWidth;   /* not used unless set explicitly */
   INT            item_height;
   INT            visibleItems;
} HEADCOMBO, *LPHEADCOMBO;

extern BOOL COMBO_FlipListbox(HEADCOMBO *lphc, BOOL ok, BOOL bRedrawButton);

typedef struct
{
    COLORREF clrBtnHighlight;       /* COLOR_BTNHIGHLIGHT                  */
    COLORREF clrBtnShadow;          /* COLOR_BTNSHADOW                     */
    COLORREF clrBtnText;            /* COLOR_BTNTEXT                       */
    COLORREF clrBtnFace;            /* COLOR_BTNFACE                       */
    COLORREF clrHighlight;          /* COLOR_HIGHLIGHT                     */
    COLORREF clrHighlightText;      /* COLOR_HIGHLIGHTTEXT                 */
    COLORREF clrHotTrackingColor;   /* COLOR_HOTLIGHT                      */
    COLORREF clr3dHilight;          /* COLOR_3DHILIGHT                     */
    COLORREF clr3dShadow;           /* COLOR_3DSHADOW                      */
    COLORREF clr3dDkShadow;         /* COLOR_3DDKSHADOW                    */
    COLORREF clr3dFace;             /* COLOR_3DFACE                        */
    COLORREF clrWindow;             /* COLOR_WINDOW                        */
    COLORREF clrWindowText;         /* COLOR_WINDOWTEXT                    */
    COLORREF clrGrayText;           /* COLOR_GREYTEXT                      */
    COLORREF clrActiveCaption;      /* COLOR_ACTIVECAPTION                 */
    COLORREF clrInfoBk;             /* COLOR_INFOBK                        */
    COLORREF clrInfoText;           /* COLOR_INFOTEXT                      */
} COMCTL32_SysColor;

extern COMCTL32_SysColor  comctl32_color;

/* Internal function */
void COMCTL32_CloseThemeForWindow(HWND hwnd);
HWND COMCTL32_CreateToolTip(HWND);
void COMCTL32_DrawStatusText(HDC hdc, LPCRECT lprc, LPCWSTR text, UINT style, BOOL draw_background);
void COMCTL32_OpenThemeForWindow(HWND hwnd, const WCHAR *theme_class);
VOID COMCTL32_RefreshSysColors(void);
void COMCTL32_DrawInsertMark(HDC hDC, const RECT *lpRect, COLORREF clrInsertMark, BOOL bHorizontal);
void COMCTL32_EnsureBitmapSize(HBITMAP *pBitmap, int cxMinWidth, int cyMinHeight, COLORREF crBackground);
void COMCTL32_GetFontMetrics(HFONT hFont, TEXTMETRICW *ptm);
BOOL COMCTL32_IsReflectedMessage(UINT uMsg);
BOOL COMCTL32_IsThemed(HWND hwnd);
LRESULT COMCTL32_NCPaint(HWND hwnd, WPARAM wp, LPARAM lp, const WCHAR *theme_class);
LRESULT COMCTL32_SetVersion(INT *current_version, INT new_version);
LRESULT COMCTL32_ThemeChanged(HWND hwnd, const WCHAR *theme_class, BOOL invalidate, BOOL erase);
INT  Str_GetPtrWtoA(LPCWSTR lpSrc, LPSTR lpDest, INT nMaxLen);
INT  Str_GetPtrAtoW(LPCSTR lpSrc, LPWSTR lpDest, INT nMaxLen);
BOOL Str_SetPtrAtoW(LPWSTR *lppDest, LPCSTR lpSrc);
BOOL Str_SetPtrWtoA(LPSTR *lppDest, LPCWSTR lpSrc);
BOOL imagelist_has_alpha(HIMAGELIST, UINT);

/* Our internal stack structure of the window procedures to subclass */
typedef struct _SUBCLASSPROCS {
    SUBCLASSPROC subproc;
    UINT_PTR id;
    DWORD_PTR ref;
    struct _SUBCLASSPROCS *next;
} SUBCLASSPROCS, *LPSUBCLASSPROCS;

typedef struct
{
   SUBCLASSPROCS *SubclassProcs;
   SUBCLASSPROCS *stackpos;
   WNDPROC origproc;
   int is_unicode;
   int running;
} SUBCLASS_INFO, *LPSUBCLASS_INFO;

/* WM_NOTIFY unicode to ansi conversion and forwarding stuff */

LRESULT COMCTL32_forward_notify_to_ansi_window(HWND hwnd_notify, NMHDR *hdr, WCHAR **unicode_buffer, DWORD *unicode_buffer_size);

/* undocumented functions */

BOOL   WINAPI Free (LPVOID);
void * WINAPI Alloc (DWORD) __WINE_ALLOC_SIZE(1) __WINE_DEALLOC(Free) __WINE_MALLOC;
void * WINAPI ReAlloc (void *, DWORD) __WINE_ALLOC_SIZE(2) __WINE_DEALLOC(Free);
DWORD  WINAPI GetSize (LPVOID);

INT  WINAPI Str_GetPtrA (LPCSTR, LPSTR, INT);
INT  WINAPI Str_GetPtrW (LPCWSTR, LPWSTR, INT);

LRESULT WINAPI SetPathWordBreakProc(HWND hwnd, BOOL bSet);
BOOL WINAPI MirrorIcon(HICON *phicon1, HICON *phicon2);

HRGN set_control_clipping(HDC hdc, const RECT *rect);

#if __WINE_COMCTL32_VERSION == 6
extern void BUTTON_Register(void);
extern void COMBO_Register(void);
extern void COMBOLBOX_Register(void);
extern void EDIT_Register(void);
extern void LISTBOX_Register(void);
extern void SYSLINK_Register(void);
extern void STATIC_Register(void);
#endif
extern void ANIMATE_Register(void);
extern void COMBOEX_Register(void);
extern void DATETIME_Register(void);
extern void HEADER_Register(void);
extern void HOTKEY_Register(void);
extern void IPADDRESS_Register(void);
extern void LISTVIEW_Register(void);
extern void MONTHCAL_Register(void);
extern void NATIVEFONT_Register(void);
extern void PAGER_Register(void);
extern void PROGRESS_Register(void);
extern void REBAR_Register(void);
extern void STATUS_Register(void);
extern void TAB_Register(void);
extern void TOOLBAR_Register(void);
extern void TOOLTIPS_Register(void);
extern void TRACKBAR_Register(void);
extern void TREEVIEW_Register(void);
extern void UPDOWN_Register(void);
#ifdef __REACTOS__
/* the v5 (5.82) flavours of the controls compiled twice, see above */
extern void DATETIME_Register_v5(void);
extern void HEADER_Register_v5(void);
extern void IPADDRESS_Register_v5(void);
extern void LISTVIEW_Register_v5(void);
extern void MONTHCAL_Register_v5(void);
extern void PROGRESS_Register_v5(void);
extern void REBAR_Register_v5(void);
extern void STATUS_Register_v5(void);
extern void TAB_Register_v5(void);
extern void TRACKBAR_Register_v5(void);
extern void TREEVIEW_Register_v5(void);
extern void UPDOWN_Register_v5(void);
/* classes whose code is ReactOS's own (not in step with Wine): unregistered one by one */
extern void BUTTON_Unregister(void);
extern void COMBO_Unregister(void);
extern void COMBOLBOX_Unregister(void);
extern void EDIT_Unregister(void);
extern void LISTBOX_Unregister(void);
extern void STATIC_Unregister(void);
extern void SYSLINK_Unregister(void);
extern void TOOLBARv6_Register(void);
extern void TOOLBARv6_Unregister(void);
#endif /* __REACTOS__ */

int MONTHCAL_MonthLength(int month, int year);
int MONTHCAL_CalculateDayOfWeek(SYSTEMTIME *date, BOOL inplace);
LONG MONTHCAL_CompareSystemTime(const SYSTEMTIME *first, const SYSTEMTIME *second);

#ifdef __REACTOS__
extern void THEMING_Initialize(HANDLE hActCtx5, HANDLE hActCtx6);
#else
extern void THEMING_Initialize(void);
#endif
extern void THEMING_Uninitialize(void);
extern LRESULT THEMING_CallOriginalClass(HWND, UINT, WPARAM, LPARAM);

#ifdef __REACTOS__
/* Items of newer Wine headers/uxtheme that the ReactOS PSDK headers and uxtheme.dll do not have */
#define OpenThemeDataForDpi(hwnd, cls, dpi) OpenThemeData((hwnd), (cls))
HDPA WINAPI DPA_Clone(const HDPA hdpa, HDPA hdpaNew);
#ifndef LVM_GETNEXTITEMINDEX
typedef struct tagLVITEMINDEX
{
    int iItem;
    int iGroup;
} LVITEMINDEX, *PLVITEMINDEX;
#define LVM_GETNEXTITEMINDEX (LVM_FIRST + 211)
#endif
#ifndef TVN_ITEMCHANGINGW
typedef struct tagNMTVITEMCHANGE
{
    NMHDR hdr;
    UINT uChanged;
    HTREEITEM hItem;
    UINT uStateNew;
    UINT uStateOld;
    LPARAM lParam;
} NMTVITEMCHANGE;
#define TVN_ITEMCHANGINGA (TVN_FIRST - 16)
#define TVN_ITEMCHANGINGW (TVN_FIRST - 17)
#define TVN_ITEMCHANGEDA  (TVN_FIRST - 18)
#define TVN_ITEMCHANGEDW  (TVN_FIRST - 19)
#endif
#define IDI_SHIELD  32518
#define wcsnicmp _wcsnicmp
#define GetDpiForWindow(PVOID) 96
#endif

#endif  /* __WINE_COMCTL32_H */
