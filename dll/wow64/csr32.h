/* Explicit i386 CSR layouts, from ReactOS base.h and conmsg.h.
 * SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once


typedef struct _WOW64_BASE_DATA
{
    WOW64_STRING WindowsDirectory;
    WOW64_STRING WindowsSystemDirectory;
    WOW64_STRING NamedObjectDirectory;
    USHORT WindowsMajorVersion;
    USHORT WindowsMinorVersion;
    USHORT BuildNumber;
    USHORT CSDNumber;
    USHORT RCNumber;
    WCHAR CSDVersion[128];
    WOW64_SYSTEM_BASIC_INFORMATION SysInfo;
    SYSTEM_TIMEOFDAY_INFORMATION TimeOfDay;
    ULONG IniFileMapping;
    NLS_USER_INFO NlsUserInfo;
    BOOLEAN DefaultSeparateVDM;
    BOOLEAN IsWowTaskReady;
    WOW64_STRING WindowsSys32x86Directory;
    BOOLEAN fTermsrvAppInstallMode;
    TIME_ZONE_INFORMATION tziTermsrvClientTimeZone;
    KSYSTEM_TIME ktTermsrvClientBias;
    ULONG TermsrvClientTimeZoneId;
    BOOLEAN LUIDDeviceMapsEnabled;
    ULONG TermsrvClientTimeZoneChangeNum;
} WOW64_BASE_DATA, *PWOW64_BASE_DATA;

typedef struct _WOW64_CONSOLE_PROPERTIES
{
    INT   IconIndex;
    ULONG hIcon;
    ULONG hIconSm;
    DWORD dwHotKey;
    DWORD dwStartupFlags;

    // NT_CONSOLE_PROPS
    WORD wFillAttribute;
    WORD wPopupFillAttribute;

    //
    // Not on MSDN, but show up in binary
    //
    WORD wShowWindow;
    WORD wUnknown;

    COORD dwScreenBufferSize;
    COORD dwWindowSize;
    COORD dwWindowOrigin;
    DWORD nFont;
    DWORD nInputBufferSize;
    COORD dwFontSize;
    UINT  uFontFamily;
    UINT  uFontWeight;
    WCHAR FaceName[LF_FACESIZE];
    UINT  uCursorSize;
    BOOL  bFullScreen;
    BOOL  bQuickEdit;
    BOOL  bInsertMode;
    BOOL  bAutoPosition;
    UINT  uHistoryBufferSize;
    UINT  uNumberOfHistoryBuffers;
    BOOL  bHistoryNoDup;
    COLORREF ColorTable[16];

    // NT_FE_CONSOLE_PROPS
    UINT uCodePage;
} WOW64_CONSOLE_PROPERTIES;

typedef struct
{
    ULONG ConsoleHandle, InputWaitHandle, InputHandle, OutputHandle, ErrorHandle;
    ULONG InitEvents[MAX_INIT_EVENTS];
    WOW64_CONSOLE_PROPERTIES;
} WOW64_CONSOLE_START;
typedef struct _WOW64_CONSOLE_CONNECT
{
    WOW64_CONSOLE_START ConsoleStartInfo;

    BOOLEAN IsConsoleApp;
    BOOLEAN IsWindowVisible;

    // USHORT Padding;

    ULONG CtrlRoutine;
    ULONG PropRoutine;
    ULONG ImeRoutine;

    ULONG  TitleLength;
    WCHAR  ConsoleTitle[MAX_PATH + 1];  // Console title or full path to the startup shortcut
    ULONG  DesktopLength;
    ULONG Desktop;                     // Contrary to the case of CONSOLE_ALLOCCONSOLE, the
                                        // desktop string is allocated in the process' heap,
                                        // and CSR will read it via NtReadVirtualMemory.
    ULONG  AppNameLength;
    WCHAR  AppName[128];                // Full path of the launched app
    ULONG  CurDirLength;
    WCHAR  CurDir[MAX_PATH + 1];
} WOW64_CONSOLE_CONNECT, *PWOW64_CONSOLE_CONNECT;


C_ASSERT(sizeof(WOW64_BASE_DATA) == 0x1ac8);
C_ASSERT(sizeof(WOW64_CONSOLE_START) == 0xfc);
C_ASSERT(sizeof(WOW64_CONSOLE_CONNECT) == 0x638);

typedef struct
{
    ULONG ConsoleHandle, OutputHandle;
    CHAR StaticBuffer[80];
    ULONG Buffer, NumBytes, Reserved1;
    BOOLEAN UsingStaticBuffer, Unicode;
    CHAR Reserved2[6];
} WOW64_CONSOLE_WRITE;

/* Console and base server requests without capture buffers */
typedef struct
{
    ULONG ConsoleHandle, OutputHandle;
    COORD ScreenBufferSize, CursorPosition, ViewOrigin;
    WORD Attributes;
    COORD ViewSize, MaximumViewSize;
} WOW64_CONSOLE_SCREEN_BUFFER_INFO;
C_ASSERT(sizeof(WOW64_CONSOLE_SCREEN_BUFFER_INFO) == 32);
C_ASSERT(FIELD_OFFSET(WOW64_CONSOLE_SCREEN_BUFFER_INFO, ViewSize) == 22); /* COORD is 2-byte aligned */

typedef struct { ULONG ConsoleHandle; UINT CodePage; BOOL OutputCP; } WOW64_CONSOLE_GET_CP;
typedef struct { ULONG ConsoleHandle; UINT CodePage; BOOL OutputCP; ULONG EventHandle; } WOW64_CONSOLE_SET_CP;
typedef struct { ULONG ConsoleHandle; LANGID LangId; } WOW64_CONSOLE_LANGID;
C_ASSERT(sizeof(WOW64_CONSOLE_GET_CP) == 12 && sizeof(WOW64_CONSOLE_SET_CP) == 16);
C_ASSERT(sizeof(WOW64_CONSOLE_LANGID) == 8);
typedef struct { ULONG ConsoleHandle, HandleType, DesiredAccess, InheritHandle, ShareMode, Handle; }
    WOW64_CONSOLE_OPENCONSOLE;
C_ASSERT(sizeof(WOW64_CONSOLE_OPENCONSOLE) == 24);
typedef struct { ULONG ConsoleHandle, DesiredAccess, InheritHandle, ShareMode, ScreenBufferType;
                 UCHAR GraphicsBufferInfo[20]; ULONG hMutex, lpBitMap, OutputHandle; }
    WOW64_CONSOLE_CREATESCREENBUFFER;
C_ASSERT(sizeof(WOW64_CONSOLE_CREATESCREENBUFFER) == 52);
C_ASSERT(sizeof(BASE_GETSET_PROCESS_SHUTDOWN_PARAMS) == 8);

/* ConsolepAttach: the start info is a pointer into the guest capture buffer */
typedef struct { ULONG ProcessId, ConsoleStartInfo, CtrlRoutine, PropRoutine; } WOW64_CONSOLE_ATTACH;
C_ASSERT(sizeof(WOW64_CONSOLE_ATTACH) == 16);

/* ConsolepFree, ConsolepGetConsoleWindow and ConsolepGetProcessList. The process list is a
 * pointer into the guest capture buffer. */
typedef struct { ULONG ConsoleHandle; } WOW64_CONSOLE_FREE;
C_ASSERT(sizeof(WOW64_CONSOLE_FREE) == 4);
typedef struct { ULONG ConsoleHandle, WindowHandle; } WOW64_CONSOLE_GETWINDOW;
C_ASSERT(sizeof(WOW64_CONSOLE_GETWINDOW) == 8);
typedef struct { ULONG ConsoleHandle, ProcessCount, ProcessIdsList; } WOW64_CONSOLE_GETPROCESSLIST;
C_ASSERT(sizeof(WOW64_CONSOLE_GETPROCESSLIST) == 12);

/* Console requests translated member by member (csr.c). Each mirrors the native structure of
 * the same name with ULONG for HANDLE and pointer members; every other member has the same type,
 * size and alignment on i386 and amd64, so equal i386 sizes (asserted for the i386 build in
 * conmsg.h) give equal layouts. Pointers address the guest's capture buffer. */
C_ASSERT(sizeof(INPUT_RECORD) == 20 && sizeof(CHAR_INFO) == 4 && sizeof(CONSOLE_FONT_INFO) == 8);
C_ASSERT(sizeof(CONSOLE_CURSOR_INFO) == 8 && sizeof(CONSOLE_SELECTION_INFO) == 16);
C_ASSERT(sizeof(CODE_TYPE) == 4 && sizeof(CODE_ELEMENT) == 2);

typedef struct { ULONG ConsoleHandle; ULONG NumFonts; } WOW64_CONSOLE_GETNUMFONTS;
typedef struct { ULONG ConsoleHandle, InputHandle; ULONG NumberOfEvents; } WOW64_CONSOLE_GETNUMINPUTEVENTS;
typedef struct { ULONG ConsoleHandle, OutputHandle; CONSOLE_CURSOR_INFO Info; } WOW64_CONSOLE_GETSETCURSORINFO;
typedef struct { ULONG ConsoleHandle; ULONG NumButtons; } WOW64_CONSOLE_GETMOUSEINFO;
typedef struct { ULONG ConsoleHandle, OutputHandle; BOOLEAN MaximumWindow; ULONG FontInfo; ULONG NumFonts; }
    WOW64_CONSOLE_GETFONTINFO;
typedef struct { ULONG ConsoleHandle, OutputHandle; ULONG FontIndex; COORD FontSize; } WOW64_CONSOLE_GETFONTSIZE;
typedef struct { ULONG ConsoleHandle, OutputHandle; BOOLEAN MaximumWindow; ULONG FontIndex; COORD FontSize; }
    WOW64_CONSOLE_GETCURRENTFONT;
typedef struct { ULONG ConsoleHandle, OutputHandle; } WOW64_CONSOLE_SETACTIVESCREENBUFFER;
typedef struct { ULONG ConsoleHandle, InputHandle; } WOW64_CONSOLE_FLUSHINPUTBUFFER;
typedef struct { ULONG ConsoleHandle, OutputHandle; COORD Size; } WOW64_CONSOLE_GETLARGESTWINDOWSIZE;
typedef struct { ULONG ConsoleHandle, OutputHandle; COORD Size; } WOW64_CONSOLE_SETSCREENBUFFERSIZE;
typedef struct { ULONG ConsoleHandle, OutputHandle; COORD Position; } WOW64_CONSOLE_SETCURSORPOSITION;
typedef struct { ULONG ConsoleHandle, OutputHandle; BOOL Absolute; SMALL_RECT WindowRect; } WOW64_CONSOLE_SETWINDOWINFO;
typedef struct
{
    ULONG ConsoleHandle, OutputHandle;
    SMALL_RECT ScrollRectangle, ClipRectangle;
    BOOL UseClipRectangle;
    COORD DestinationOrigin;
    CHAR_INFO Fill;
    BOOLEAN Unicode;
} WOW64_CONSOLE_SCROLLSCREENBUFFER;
typedef struct { ULONG ConsoleHandle, OutputHandle; WORD Attributes; } WOW64_CONSOLE_SETTEXTATTRIB;
typedef struct { ULONG ConsoleHandle, OutputHandle; ULONG FontIndex; } WOW64_CONSOLE_SETFONT;
typedef struct { ULONG ConsoleHandle, OutputHandle; BOOL Show; INT RefCount; } WOW64_CONSOLE_SHOWCURSOR;
typedef struct
{
    ULONG ConsoleHandle, SourceHandle;
    ULONG DesiredAccess;
    BOOLEAN InheritHandle;
    ULONG Options;
    ULONG TargetHandle;
} WOW64_CONSOLE_DUPLICATEHANDLE;
typedef struct { ULONG ConsoleHandle, Handle; ULONG Flags; } WOW64_CONSOLE_GETHANDLEINFO;
typedef struct { ULONG ConsoleHandle, Handle; ULONG Mask, Flags; } WOW64_CONSOLE_SETHANDLEINFO;
typedef struct { ULONG ConsoleHandle, Handle; } WOW64_CONSOLE_CLOSEHANDLE;
typedef struct { ULONG ConsoleHandle; ULONG DisplayMode; } WOW64_CONSOLE_GETDISPLAYMODE;
typedef struct { ULONG ConsoleHandle, OutputHandle; ULONG DisplayMode; COORD NewSBDim; ULONG EventHandle; }
    WOW64_CONSOLE_SETDISPLAYMODE;
typedef struct { ULONG ConsoleHandle; BOOL Enable; } WOW64_CONSOLE_SETMENUCLOSE;
typedef struct { ULONG ConsoleHandle; } WOW64_CONSOLE_NOTIFYLASTCLOSE;
typedef struct { ULONG ConsoleHandle; ULONG CtrlEvent, ProcessGroupId; } WOW64_CONSOLE_GENERATECTRLEVENT;
typedef struct { ULONG ConsoleHandle; CHAR LayoutBuffer[KL_NAMELENGTH * sizeof(WCHAR)]; BOOL Ansi; }
    WOW64_CONSOLE_GETKBDLAYOUTNAME;
typedef struct { ULONG ConsoleHandle; CONSOLE_SELECTION_INFO Info; } WOW64_CONSOLE_GETSELECTIONINFO;
typedef struct { ULONG ConsoleHandle; ULONG Mode; } WOW64_CONSOLE_SETHISTORYMODE;
typedef CONSOLE_GETSETHISTORYINFO WOW64_CONSOLE_GETSETHISTORYINFO; /* no handles or pointers */
typedef struct { ULONG ConsoleHandle; ULONG Length; ULONG Title; BOOLEAN Unicode; } WOW64_CONSOLE_GETSETCONSOLETITLE;
typedef struct
{
    ULONG ConsoleHandle;
    USHORT SourceLength, TargetLength, ExeLength;
    ULONG Source, Target, ExeName;
    BOOLEAN Unicode, Unicode2;
} WOW64_CONSOLE_ADDGETALIAS;
typedef struct
{
    ULONG ConsoleHandle;
    USHORT ExeLength;
    ULONG ExeName;
    BOOLEAN Unicode, Unicode2;
    ULONG AliasesBufferLength;
    ULONG AliasesBuffer;
} WOW64_CONSOLE_GETALLALIASES;
typedef struct { ULONG ConsoleHandle; USHORT ExeLength; ULONG ExeName; ULONG Length; BOOLEAN Unicode, Unicode2; }
    WOW64_CONSOLE_GETALLALIASESLENGTH;
typedef struct { ULONG ConsoleHandle; ULONG Length; ULONG ExeNames; BOOLEAN Unicode; } WOW64_CONSOLE_GETALIASESEXES;
typedef struct { ULONG ConsoleHandle; ULONG Length; BOOLEAN Unicode; } WOW64_CONSOLE_GETALIASESEXESLENGTH;
typedef struct
{
    ULONG ConsoleHandle;
    ULONG HistoryLength;
    ULONG History;
    USHORT ExeLength;
    ULONG ExeName;
    BOOLEAN Unicode, Unicode2;
} WOW64_CONSOLE_GETCOMMANDHISTORY;
typedef struct { ULONG ConsoleHandle; ULONG HistoryLength; USHORT ExeLength; ULONG ExeName; BOOLEAN Unicode, Unicode2; }
    WOW64_CONSOLE_GETCOMMANDHISTORYLENGTH;
typedef struct { ULONG ConsoleHandle; USHORT ExeLength; ULONG ExeName; BOOLEAN Unicode, Unicode2; }
    WOW64_CONSOLE_EXPUNGECOMMANDHISTORY;
typedef struct { ULONG ConsoleHandle; ULONG NumCommands; USHORT ExeLength; ULONG ExeName; BOOLEAN Unicode, Unicode2; }
    WOW64_CONSOLE_SETHISTORYNUMBERCOMMANDS;
typedef struct
{
    ULONG ConsoleHandle, OutputHandle;
    COORD WriteCoord;
    CODE_TYPE CodeType;
    CODE_ELEMENT Code;
    ULONG NumCodes;
} WOW64_CONSOLE_FILLOUTPUTCODE;

C_ASSERT(sizeof(WOW64_CONSOLE_GETNUMFONTS) == 8 && sizeof(WOW64_CONSOLE_GETNUMINPUTEVENTS) == 12);
C_ASSERT(sizeof(WOW64_CONSOLE_GETSETCURSORINFO) == 16 && sizeof(WOW64_CONSOLE_GETMOUSEINFO) == 8);
C_ASSERT(sizeof(WOW64_CONSOLE_GETFONTINFO) == 20 && sizeof(WOW64_CONSOLE_GETFONTSIZE) == 16);
C_ASSERT(sizeof(WOW64_CONSOLE_GETCURRENTFONT) == 20 && sizeof(WOW64_CONSOLE_SETACTIVESCREENBUFFER) == 8);
C_ASSERT(sizeof(WOW64_CONSOLE_FLUSHINPUTBUFFER) == 8 && sizeof(WOW64_CONSOLE_GETLARGESTWINDOWSIZE) == 12);
C_ASSERT(sizeof(WOW64_CONSOLE_SETSCREENBUFFERSIZE) == 12 && sizeof(WOW64_CONSOLE_SETCURSORPOSITION) == 12);
C_ASSERT(sizeof(WOW64_CONSOLE_SETWINDOWINFO) == 20 && sizeof(WOW64_CONSOLE_SCROLLSCREENBUFFER) == 40);
C_ASSERT(sizeof(WOW64_CONSOLE_SETTEXTATTRIB) == 12 && sizeof(WOW64_CONSOLE_SETFONT) == 12);
C_ASSERT(sizeof(WOW64_CONSOLE_SHOWCURSOR) == 16 && sizeof(WOW64_CONSOLE_DUPLICATEHANDLE) == 24);
C_ASSERT(sizeof(WOW64_CONSOLE_GETHANDLEINFO) == 12 && sizeof(WOW64_CONSOLE_SETHANDLEINFO) == 16);
C_ASSERT(sizeof(WOW64_CONSOLE_CLOSEHANDLE) == 8 && sizeof(WOW64_CONSOLE_GETDISPLAYMODE) == 8);
C_ASSERT(sizeof(WOW64_CONSOLE_SETDISPLAYMODE) == 20 && sizeof(WOW64_CONSOLE_SETMENUCLOSE) == 8);
C_ASSERT(sizeof(WOW64_CONSOLE_NOTIFYLASTCLOSE) == 4 && sizeof(WOW64_CONSOLE_GENERATECTRLEVENT) == 12);
C_ASSERT(sizeof(WOW64_CONSOLE_GETKBDLAYOUTNAME) == 28 && sizeof(WOW64_CONSOLE_GETSELECTIONINFO) == 20);
C_ASSERT(sizeof(WOW64_CONSOLE_SETHISTORYMODE) == 8 && sizeof(WOW64_CONSOLE_GETSETHISTORYINFO) == 12);
C_ASSERT(sizeof(WOW64_CONSOLE_GETSETCONSOLETITLE) == 16 && sizeof(WOW64_CONSOLE_ADDGETALIAS) == 28);
C_ASSERT(sizeof(WOW64_CONSOLE_GETALLALIASES) == 24 && sizeof(WOW64_CONSOLE_GETALLALIASESLENGTH) == 20);
C_ASSERT(sizeof(WOW64_CONSOLE_GETALIASESEXES) == 16 && sizeof(WOW64_CONSOLE_GETALIASESEXESLENGTH) == 12);
C_ASSERT(sizeof(WOW64_CONSOLE_GETCOMMANDHISTORY) == 24 && sizeof(WOW64_CONSOLE_GETCOMMANDHISTORYLENGTH) == 20);
C_ASSERT(sizeof(WOW64_CONSOLE_EXPUNGECOMMANDHISTORY) == 16 && sizeof(WOW64_CONSOLE_SETHISTORYNUMBERCOMMANDS) == 20);
C_ASSERT(sizeof(WOW64_CONSOLE_FILLOUTPUTCODE) == 24);

/* Requests with an inline buffer used instead of the capture buffer for small transfers; the
 * server picks the inline buffer by size, as the client does (csr.c) */
typedef struct
{
    ULONG ConsoleHandle, InputHandle;
    USHORT ExeLength;
    CHAR StaticBuffer[80];
    ULONG Buffer;
    ULONG NumBytes;
    ULONG CaptureBufferSize;
    ULONG InitialNumBytes, CtrlWakeupMask, ControlKeyState;
    BOOLEAN Unicode;
} WOW64_CONSOLE_READCONSOLE;
typedef struct
{
    ULONG ConsoleHandle, InputHandle;
    INPUT_RECORD RecordStaticBuffer[5];
    ULONG RecordBufPtr;
    ULONG NumRecords;
    WORD Flags;
    BOOLEAN Unicode;
} WOW64_CONSOLE_GETINPUT;
typedef struct
{
    ULONG ConsoleHandle, InputHandle;
    INPUT_RECORD RecordStaticBuffer[5];
    ULONG RecordBufPtr;
    ULONG NumRecords;
    BOOLEAN Unicode, AppendToEnd;
} WOW64_CONSOLE_WRITEINPUT;
typedef struct
{
    ULONG ConsoleHandle, OutputHandle;
    CHAR_INFO StaticBuffer;
    ULONG CharInfo;
    SMALL_RECT Region; /* ReadRegion or WriteRegion */
    BOOLEAN Unicode;
    BOOLEAN UseVirtualMemory; /* write only */
} WOW64_CONSOLE_READWRITEOUTPUT;
typedef struct
{
    ULONG ConsoleHandle, OutputHandle;
    COORD Coord;
    CODE_TYPE CodeType;
    CHAR CodeStaticBuffer[80];
    ULONG pCode;
    ULONG NumCodes;
} WOW64_CONSOLE_OUTPUTCODE;
typedef struct
{
    ULONG ConsoleStartInfo;
    ULONG TitleLength, ConsoleTitle;
    ULONG DesktopLength, Desktop;
    ULONG AppNameLength, AppName;
    ULONG CurDirLength, CurDir;
    ULONG CtrlRoutine, PropRoutine;
} WOW64_CONSOLE_ALLOCCONSOLE;

typedef struct
{
    ULONG LastError, Flags, Success;
} WOW64_USER_EXIT_REACTOS;

/* More console requests with handles and values only, and a base and a user request, translated
 * member by member (csr.c). The window, icon, cursor, palette and menu handles are USER and GDI
 * handles, 32 bits wide in both bitnesses and widened like the others. */
typedef struct { ULONG ConsoleHandle, IconHandle; } WOW64_CONSOLE_SETICON;
typedef struct { ULONG ConsoleHandle, OutputHandle, CursorHandle; } WOW64_CONSOLE_SETCURSOR;
typedef struct { ULONG ConsoleHandle, OutputHandle, PaletteHandle; UINT Usage; } WOW64_CONSOLE_SETPALETTE;
typedef struct { ULONG ConsoleHandle, OutputHandle; ULONG CmdIdLow, CmdIdHigh; ULONG MenuHandle; }
    WOW64_CONSOLE_MENUCONTROL;
typedef struct { ULONG ConsoleHandle, OutputHandle; SMALL_RECT Region; } WOW64_CONSOLE_INVALIDATEDIBITS;
typedef struct { ULONG ConsoleHandle, OutputHandle; ULONG Flags, State; } WOW64_CONSOLE_GETSETHWSTATE;
typedef struct { ULONG VideoMode; } WOW64_BASE_SOUND_SENTRY;
typedef struct { ULONG ImageHandle; ULONG ImageNameLength; ULONG ImageName; } WOW64_BASE_APPCOMPAT_CACHE_UPDATE;
typedef struct { DWORD LastError; ULONG WndHandle; BOOL Force, Success; } WOW64_USER_END_TASK;
C_ASSERT(sizeof(WOW64_CONSOLE_SETICON) == 8 && sizeof(WOW64_CONSOLE_SETCURSOR) == 12);
C_ASSERT(sizeof(WOW64_CONSOLE_SETPALETTE) == 16 && sizeof(WOW64_CONSOLE_MENUCONTROL) == 20);
C_ASSERT(sizeof(WOW64_CONSOLE_INVALIDATEDIBITS) == 16 && sizeof(WOW64_CONSOLE_GETSETHWSTATE) == 16);
C_ASSERT(sizeof(WOW64_BASE_APPCOMPAT_CACHE_UPDATE) == 12);
C_ASSERT(sizeof(WOW64_BASE_SOUND_SENTRY) == 4 && sizeof(WOW64_USER_END_TASK) == 16);

C_ASSERT(sizeof(WOW64_USER_EXIT_REACTOS) == sizeof(USER_EXIT_REACTOS));
C_ASSERT(sizeof(WOW64_CONSOLE_READCONSOLE) == 120 && FIELD_OFFSET(WOW64_CONSOLE_READCONSOLE, Buffer) == 92);
C_ASSERT(sizeof(WOW64_CONSOLE_GETINPUT) == 120 && sizeof(WOW64_CONSOLE_WRITEINPUT) == 120);
C_ASSERT(sizeof(WOW64_CONSOLE_READWRITEOUTPUT) == 28 && sizeof(WOW64_CONSOLE_OUTPUTCODE) == 104);
C_ASSERT(sizeof(WOW64_CONSOLE_ALLOCCONSOLE) == 44);
C_ASSERT(FIELD_OFFSET(WOW64_CONSOLE_GETINPUT, RecordBufPtr) == 108 && FIELD_OFFSET(WOW64_CONSOLE_WRITEINPUT, RecordBufPtr) == 108);
C_ASSERT(FIELD_OFFSET(WOW64_CONSOLE_READWRITEOUTPUT, Unicode) == 24 &&
         FIELD_OFFSET(WOW64_CONSOLE_READWRITEOUTPUT, UseVirtualMemory) == 25);
C_ASSERT(FIELD_OFFSET(WOW64_CONSOLE_OUTPUTCODE, pCode) == 96);
