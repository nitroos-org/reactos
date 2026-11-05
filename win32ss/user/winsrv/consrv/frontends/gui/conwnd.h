/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Console Server DLL
 * FILE:            win32ss/user/winsrv/consrv/frontends/gui/conwnd.h
 * PURPOSE:         GUI Console Window Class
 * PROGRAMMERS:     Gé van Geldorp
 *                  Johannes Anderwald
 *                  Jeffrey Morlan
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

#pragma once

/* GUI Console Window Class name */
#define GUI_CONWND_CLASS L"ConsoleWindowClass"

#ifndef WM_APP
    #define WM_APP 0x8000
#endif
#define PM_RESIZE_TERMINAL      (WM_APP + 3)
#define PM_CONSOLE_BEEP         (WM_APP + 4)
#define PM_CONSOLE_SET_TITLE    (WM_APP + 5)

/* GUI_CONSOLE_DATA.PendingWork */
#define GUI_WORK_UPDATE         0x0001  /* Dirty cells, view or caret */
#define GUI_WORK_RESIZE         0x0002  /* Rebuild the framebuffer and resize the window */
#define GUI_WORK_TITLE          0x0004
#define GUI_WORK_CURSOR         0x0008  /* Mouse cursor shape or visibility */
#define GUI_WORK_BEEP           0x0010
#define GUI_WORK_LEADER         0x0020  /* Console leader process changed */
#define GUI_WORK_DISPLAY_MODE   0x0040  /* Switch to RequestedFullScreen */
#define GUI_WORK_CLOSE_MENU     0x0080  /* Enable or gray the Close menu item */

/* Flags for GetKeyState */
#define KEY_TOGGLED 0x0001
#define KEY_PRESSED 0x8000

/*
typedef struct _CONSOLE_FONT
{
    HFONT Font;
    ULONG Flag;
} CONSOLE_FONT, *PCONSOLE_FONT;
*/
#define FONT_NORMAL     0x00
#define FONT_BOLD       0x01
#define FONT_UNDERLINE  0x02
#define FONT_MAXNO      0x04

typedef struct _GUI_CONSOLE_DATA
{
    CRITICAL_SECTION Lock;
    BOOL WindowSizeLock;
    HANDLE hGuiInitEvent;
    HANDLE hGuiTermEvent;

    // HANDLE InputThreadHandle;
    ULONG_PTR InputThreadId;
    HWINSTA WinSta;
    HDESK   Desktop;

    BOOLEAN IsWindowVisible;
    BOOLEAN IsWindowActive;

    /*
     * Work for the window thread (see "Locking" in guiterm.c). Writers and the
     * frontend callbacks record it here and set hWakeEvent; they never call
     * USER. The dirty state, ShowCaret and RequestedFullScreen are protected
     * by the console lock; PendingWork is updated with interlocked operations.
     */
    SMALL_RECT DirtyRegion;     /* In screen buffer coordinates, valid if DirtyCells */
    BOOLEAN DirtyCells;
    BOOLEAN DirtyView;          /* The whole view needs repainting */
    BOOLEAN ShowCaret;          /* Output moved the caret: show it, restart the blink */
    BOOLEAN ViewMoved;          /* The view followed the cursor: move the scroll bars */
    BOOLEAN InitEventSet;       /* hGuiInitEvent was set (window thread only) */
    LONG PendingWork;           /* GUI_WORK_* */
    BOOL RequestedFullScreen;   /* For GUI_WORK_DISPLAY_MODE */
    LONG DisplayModeRequest;    /* Number of the last display mode request */
    LONG DisplayModeDone;       /* Number of the last one the window thread handled */
    HANDLE hDisplayModeEvent;   /* Set when DisplayModeDone changes */
    HANDLE hWakeEvent;          /* The input thread's wake event, set by PM_CREATE_CONSOLE */
    LIST_ENTRY InputThreadLink; /* In the input thread's window list (that thread only) */
    DWORD BlinkRestartTick;     /* When the blink timer was last (re)started (window thread only) */
    DWORD PaintCost;            /* Milliseconds the last paint took (window thread only) */
    DWORD PaintEndTick;         /* When it ended (window thread only) */
    DWORD DeferredSince;        /* When the pending repaint was first deferred, if WorkDeferred (window thread only) */
    BOOLEAN WorkDeferred;

    LONG_PTR WndStyle;
    LONG_PTR WndStyleEx;
    BOOL IsWndMax;
    WINDOWPLACEMENT WndPl;

    HWND hWindow;               /* Handle to the console's window            */
    HDC  hMemDC;                /* Memory DC holding the console framebuffer */
    HBITMAP  hBitmap;           /* Console framebuffer: the view, not the whole screen buffer */
    int FrameWidth, FrameHeight; /* Size of hBitmap in pixels (window thread only) */
    HPALETTE hSysPalette;       /* Handle to the original system palette     */

    HICON hIcon;                /* Handle to the console's icon (big)   */
    HICON hIconSm;              /* Handle to the console's icon (small) */

/*** The following may be put per-screen-buffer !! ***/
    HCURSOR hCursor;            /* Handle to the mouse cursor */
    INT  MouseCursorRefCount;   /* The reference counter associated with the mouse cursor. >= 0 and the cursor is shown; < 0 and the cursor is hidden. */
    BOOL IgnoreNextMouseEvent;  /* Used when we need to not process a mouse event */

    BOOL HackCORE8394IgnoreNextMove; /* HACK FOR CORE-8394. See conwnd.c!OnMouse for more details. */

    HMENU hSysMenu;             /* Handle to the console window system menu */
    BOOL IsCloseButtonEnabled;  /* TRUE if the Close button and the corresponding system menu item are enabled (default), FALSE otherwise */
    UINT CmdIdLow ;             /* Lowest menu id of the user-reserved menu id range */
    UINT CmdIdHigh;             /* Highest menu id of the user-reserved menu id range */

//  COLORREF Colors[16];

//  PVOID   ScreenBuffer;       /* Hardware screen buffer */

    HFONT Font[FONT_MAXNO];
    UINT CharWidth;     /* The character width and height should be the same for */
    UINT CharHeight;    /* both normal and bold/underlined fonts...              */
/*****************************************************/

    PCONSRV_CONSOLE Console;           /* Pointer to the owned console */
    PCONSOLE_SCREEN_BUFFER ActiveBuffer;    /* Pointer to the active screen buffer (then maybe the previous Console member is redundant?? Or not...) */
    CONSOLE_SELECTION_INFO Selection;       /* Contains information about the selection */
    COORD dwSelectionCursor;                /* Selection cursor position, most of the time different from Selection.dwSelectionAnchor */
    BOOL  LineSelection;                    /* TRUE if line-oriented selection (a la *nix terminals), FALSE if block-oriented selection (default on Windows) */
    BOOL  CopyNoTrim;                       /* The copy being made (Ctrl+Shift+C) keeps the blanks that end the lines */
    WORD  SwallowKey;                       /* Virtual key whose WM_CHAR and key-up belong to a shortcut the window took (Ctrl+C, Ctrl+V...) and must not reach the program; 0 if none */

    GUI_CONSOLE_INFO GuiInfo;   /* GUI terminal settings */
} GUI_CONSOLE_DATA, *PGUI_CONSOLE_DATA;
