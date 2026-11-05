/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Console Server DLL
 * FILE:            win32ss/user/winsrv/concfg/settings.h
 * PURPOSE:         Public Console Settings Management Interface
 * PROGRAMMERS:     Johannes Anderwald
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

#pragma once

/* STRUCTURES *****************************************************************/

/*
 * Undocumented message and structure used by Windows' console.dll
 * for setting console info.
 * See https://web.archive.org/web/20160307053337/https://www.catch22.net/sites/default/source/files/setconsoleinfo.c
 * and https://dl.packetstormsecurity.net/papers/win/MSBugPaper.pdf
 * for more information.
 */
#define WM_SETCONSOLEINFO   (WM_USER + 201)

// This shared structure has alignment requirements
// in order to be compatible with the Windows one.
#pragma pack(push, 4)

typedef struct _CONSOLE_STATE_INFO
{
    ULONG       cbSize; // Real length of this structure, at least sizeof(_CONSOLE_STATE_INFO).
                        // The real length takes into account for the real size of the console title.

    COORD       ScreenBufferSize;
    COORD       WindowSize;
    POINT       WindowPosition;

    COORD       FontSize;
    ULONG       FontFamily;
    ULONG       FontWeight;
    WCHAR       FaceName[LF_FACESIZE];

    ULONG       CursorSize;
    BOOL        FullScreen;
    BOOL        QuickEdit;
    BOOL        AutoPosition;
    BOOL        InsertMode;

    USHORT      ScreenAttributes;
    USHORT      PopupAttributes;
    BOOL        HistoryNoDup;
    ULONG       HistoryBufferSize;
    ULONG       NumberOfHistoryBuffers;

    COLORREF    ColorTable[16];

    ULONG       CodePage;
    HWND        hWnd;

    WCHAR       ConsoleTitle[ANYSIZE_ARRAY];
} CONSOLE_STATE_INFO, *PCONSOLE_STATE_INFO;

#ifdef _M_IX86
C_ASSERT(sizeof(CONSOLE_STATE_INFO) == 0xD0);
#endif

/*
 * Settings added after the layout above was fixed (it is what Windows' console.dll
 * sends and expects, with the title as its tail). Windows' newer console property
 * structure carries these two settings as fCtrlKeyShortcutsDisabled and fLineSelection
 * in a different tail (its titles are pointers), so they cannot be appended to
 * CONSOLE_STATE_INFO itself without moving the title. They travel as a self-describing
 * block in the LAST sizeof(CONSOLE_STATE_INFO_EX) bytes of the buffer that cbSize
 * covers, after the title: a sender that does not know it (a Windows console.dll)
 * simply leaves it out and the receiver keeps its current values.
 * Use ConCfgGetStateInfoEx(); never read the block directly.
 */
#define CONSOLE_STATE_INFO_EX_SIGNATURE 0x58454343  // 'CCEX'

typedef struct _CONSOLE_STATE_INFO_EX
{
    ULONG   Signature;                  // CONSOLE_STATE_INFO_EX_SIGNATURE
    ULONG   Size;                       // sizeof(CONSOLE_STATE_INFO_EX)
    BOOL    CtrlKeyShortcutsDisabled;   // HKCU\Console CtrlKeyShortcutsDisabled (default FALSE)
    BOOL    LineSelection;              // HKCU\Console LineSelection (default TRUE)
    BOOL    FilterOnPaste;              // HKCU\Console FilterOnPaste (default TRUE)
} CONSOLE_STATE_INFO_EX, *PCONSOLE_STATE_INFO_EX;

#pragma pack(pop)

/*
 * Number of WCHARs (without the terminating NUL) that fit in ConsoleTitle of a
 * buffer of cbSize bytes that also carries the CONSOLE_STATE_INFO_EX block.
 */
#define CONSOLE_STATE_INFO_TITLE_CCH(cbSize) \
    (((cbSize) - FIELD_OFFSET(CONSOLE_STATE_INFO, ConsoleTitle) - \
      sizeof(CONSOLE_STATE_INFO_EX) - sizeof(UNICODE_NULL)) / sizeof(WCHAR))

/*
 * BYTE Foreground = LOBYTE(Attributes) & 0x0F;
 * BYTE Background = (LOBYTE(Attributes) & 0xF0) >> 4;
 */
#define RGBFromAttrib(Console, Attribute)   ((Console)->Colors[(Attribute) & 0xF])
#define TextAttribFromAttrib(Attribute)     ( !((Attribute) & COMMON_LVB_REVERSE_VIDEO) ? (Attribute) & 0xF : ((Attribute) >> 4) & 0xF )
#define BkgdAttribFromAttrib(Attribute)     ( !((Attribute) & COMMON_LVB_REVERSE_VIDEO) ? ((Attribute) >> 4) & 0xF : (Attribute) & 0xF )
#define MakeAttrib(TextAttrib, BkgdAttrib)  (USHORT)((((BkgdAttrib) & 0xF) << 4) | ((TextAttrib) & 0xF))

/* FUNCTIONS ******************************************************************/

BOOLEAN
ConCfgOpenUserSettings(
    IN  LPCWSTR ConsoleTitle,
    OUT PHKEY phSubKey,
    IN  REGSAM samDesired,
    IN  BOOLEAN Create);

BOOLEAN
ConCfgReadUserSettings(
    IN OUT PCONSOLE_STATE_INFO ConsoleInfo,
    IN BOOLEAN DefaultSettings);

BOOLEAN
ConCfgWriteUserSettings(
    IN PCONSOLE_STATE_INFO ConsoleInfo,
    IN BOOLEAN DefaultSettings);

/*
 * The CONSOLE_STATE_INFO_EX block of ConsoleInfo, or NULL if the buffer has none.
 * InfoSize is the number of bytes that are really readable (at most cbSize).
 */
PCONSOLE_STATE_INFO_EX
ConCfgGetStateInfoEx(
    IN PCONSOLE_STATE_INFO ConsoleInfo,
    IN SIZE_T InfoSize);

/* Reserve and initialise the block at the end of a buffer of cbSize bytes */
VOID
ConCfgInitStateInfoEx(
    IN OUT PCONSOLE_STATE_INFO ConsoleInfo);

VOID
ConCfgInitDefaultSettings(
    IN OUT PCONSOLE_STATE_INFO ConsoleInfo);

VOID
ConCfgGetDefaultSettings(
    IN OUT PCONSOLE_STATE_INFO ConsoleInfo);

/* EOF */
