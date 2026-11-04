/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Headless console host: console screen buffer to VT and VT to input records.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <wincon.h>
#include <winuser.h>
#define NTOS_MODE_USER
#include <ndk/ntndk.h>
#include <wingdi.h>
#include <wincon_undoc.h>
#include <subsys/csr/csr.h>
#include <subsys/win/conmsg.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif

typedef struct _HOST
{
    HANDLE PipeIn, PipeOut, Signal, ConsoleIn, ConsoleOut, Client;
    SHORT Width, Height;
    CHAR_INFO *Previous, *Current;
    CONSOLE_EXT_CELL *PreviousExt, *CurrentExt; /* 256-color / 24-bit colors of the cells, same index */
    BOOL ExtPresent;            /* the server holds extended colors for the buffer */
    BOOL Painted, CursorVisible, SawClient;
    BOOL ScrollbackSeen;        /* ScrollbackTotal says how many rows had scrolled off at the last look */
    ULONGLONG ScrollbackTotal;
    COORD Cursor;
    BYTE Utf8[4], Utf8Count, Utf8Length;
    CHAR Sequence[32];
    BYTE SequenceLength, Escape;
    DWORD EscapeTime;
} HOST;

static BOOL
HostWrite(HOST *Host, const CHAR *Text, DWORD Length)
{
    DWORD Written, Available;

    /* A caller such as node-pty hands over named-pipe server ends and only connects
     * the client ends afterwards. Until then a write fails with ERROR_PIPE_LISTENING;
     * the Windows host waits for the terminal, so do the same (unless the owner is gone). */
    for (;;)
    {
        if (WriteFile(Host->PipeOut, Text, Length, &Written, NULL))
            return Written == Length;
        if (GetLastError() != ERROR_PIPE_LISTENING) return FALSE;
        if (Host->Signal && !PeekNamedPipe(Host->Signal, NULL, 0, NULL, &Available, NULL))
            return FALSE;
        Sleep(10);
    }
}

static SHORT
HostParseDimension(const WCHAR *Text, SHORT DefaultValue)
{
    WCHAR *End;
    LONG Value = wcstol(Text, &End, 10);

    if (End == Text || *End || Value <= 0 || Value > 32767)
        return DefaultValue;
    return (SHORT)Value;
}

/*
 * The terminal keeps its own scrollback, but only of the rows that scroll off the top of its
 * screen. The console buffer is as large as the window, so text that scrolls off the top is
 * gone from it at once, and a client can scroll hundreds of rows between two looks of the host.
 * The console server therefore keeps the rows that scrolled off the top of the host's buffer
 * (ConsolepGetScrollback) and the host feeds them to the terminal as lines scrolling off its
 * screen. Returns FALSE when the buffer keeps no such rows (a screen buffer of the client's own,
 * which is a full-screen application's screen and has no scrollback, as an alternate screen).
 */
static BOOL
HostScrollbackCall(HOST *Host, HANDLE ConsoleOut, DWORD Flags, ULONGLONG First, DWORD Count,
                   CHAR_INFO *Cells, ULONGLONG *Total, ULONGLONG *Returned, DWORD *Rows)
{
    CONSOLE_API_MESSAGE Message;
    PCONSOLE_SCROLLBACK Request = &Message.Data.ScrollbackRequest;
    PCSR_CAPTURE_BUFFER Capture = NULL;
    SIZE_T Size = (SIZE_T)Count * Host->Width * sizeof(CHAR_INFO);
    BOOL Enabled;

    RtlZeroMemory(&Message, sizeof(Message));
    if (Count)
    {
        Capture = CsrAllocateCaptureBuffer(1, (ULONG)Size);
        if (!Capture) return FALSE;
        CsrAllocateMessagePointer(Capture, (ULONG)Size, (PVOID *)&Request->CharInfo);
    }
    Request->ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Request->OutputHandle = ConsoleOut;
    Request->Flags = Flags;
    Request->First = First;
    Request->Width = Host->Width;
    Request->Count = Count;
    CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture,
                        CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepGetScrollback),
                        sizeof(*Request));
    Enabled = NT_SUCCESS(Message.Status) && (Request->Flags & CONSOLE_SCROLLBACK_ENABLED);
    if (NT_SUCCESS(Message.Status))
        Host->ExtPresent = (Request->Flags & CONSOLE_SCROLLBACK_EXTCOLORS) != 0;
    if (Enabled)
    {
        *Total = Request->Total;
        *Returned = Request->First;
        *Rows = Request->Count;
        if (Count && Request->Count)
            CopyMemory(Cells, Request->CharInfo, (SIZE_T)Request->Count * Host->Width * sizeof(CHAR_INFO));
    }
    if (Capture) CsrFreeCaptureBuffer(Capture);
    return Enabled;
}

/*
 * The cells of the console buffer only have the 16 console colors. A buffer that was written with
 * 256-color or 24-bit color sequences also has the exact colors (ConsolepGetExtColors), which the
 * terminal gets as the same sequences. Rows is the number of rows wanted from First (rows of the
 * buffer, or rows scrolled off with CONSOLE_EXTCOLORS_SCROLLBACK); the colors of the Host->Width
 * columns from column Left of a buffer BufferWidth wide go to Cells. What the server has no
 * colors for stays 0.
 */
static VOID
HostFetchExt(HOST *Host, DWORD Flags, HANDLE ConsoleOut, ULONGLONG First, DWORD Rows,
             DWORD BufferWidth, DWORD Left, CONSOLE_EXT_CELL *Cells)
{
    DWORD Row = 0, Chunk;

    ZeroMemory(Cells, (SIZE_T)Rows * Host->Width * sizeof(*Cells));
    /* One request carries at most 64 KiB (CSR capture buffer) */
    if (!BufferWidth || BufferWidth > 32768 / sizeof(CONSOLE_EXT_CELL)) return;
    Chunk = 32768 / (BufferWidth * sizeof(CONSOLE_EXT_CELL));
    while (Row < Rows)
    {
        CONSOLE_API_MESSAGE Message;
        PCONSOLE_EXTCOLORS Request = &Message.Data.ExtColorsRequest;
        PCSR_CAPTURE_BUFFER Capture;
        DWORD Want = min(Chunk, Rows - Row), Got = 0, Index, Column;
        SIZE_T Size = (SIZE_T)Want * BufferWidth * sizeof(CONSOLE_EXT_CELL);

        Capture = CsrAllocateCaptureBuffer(1, (ULONG)Size);
        if (!Capture) return;
        RtlZeroMemory(&Message, sizeof(Message));
        CsrAllocateMessagePointer(Capture, (ULONG)Size, (PVOID *)&Request->Cells);
        Request->ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
        Request->OutputHandle = ConsoleOut;
        Request->Flags = Flags;
        Request->First = First + Row;
        Request->Width = BufferWidth;
        Request->Count = Want;
        CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture,
                            CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepGetExtColors),
                            sizeof(*Request));
        if (NT_SUCCESS(Message.Status) && Request->Count && Request->Count <= Want &&
            Request->First == First + Row && Request->Width == BufferWidth)
        {
            Got = Request->Count;
            for (Index = 0; Index < Got; ++Index)
            {
                const CONSOLE_EXT_CELL *Source = Request->Cells + (SIZE_T)Index * BufferWidth;
                CONSOLE_EXT_CELL *Destination = Cells + (SIZE_T)(Row + Index) * Host->Width;

                for (Column = 0; Column < (DWORD)Host->Width && Left + Column < BufferWidth; ++Column)
                    Destination[Column] = Source[Left + Column];
            }
        }
        CsrFreeCaptureBuffer(Capture);
        if (!Got) return;
        Row += Got;
    }
}

/* A color counts for a cell only while the cell has the 16-color attribute it was written with
 * (the server cannot see every writer of a cell); what is kept is the kind and the value. */
static VOID
HostNormalizeExt(const CHAR_INFO *Cells, CONSOLE_EXT_CELL *Ext, SIZE_T Count)
{
    SIZE_T Index;

    for (Index = 0; Index < Count; ++Index)
    {
        ULONG Fore = Ext[Index].Fore, Back = Ext[Index].Back;
        WORD Attribute = Cells[Index].Attributes;

        if (!CONSOLE_EXTCOLOR_KIND(Fore) || CONSOLE_EXTCOLOR_SNAP(Fore) != (ULONG)(Attribute & 0x0F) ||
            (CONSOLE_EXTCOLOR_KIND(Fore) == CONSOLE_EXTCOLOR_INDEX && CONSOLE_EXTCOLOR_VALUE(Fore) > 255))
            Fore = 0;
        if (!CONSOLE_EXTCOLOR_KIND(Back) || CONSOLE_EXTCOLOR_SNAP(Back) != (ULONG)((Attribute >> 4) & 0x0F) ||
            (CONSOLE_EXTCOLOR_KIND(Back) == CONSOLE_EXTCOLOR_INDEX && CONSOLE_EXTCOLOR_VALUE(Back) > 255))
            Back = 0;
        Ext[Index].Fore = Fore ? CONSOLE_EXTCOLOR_MAKE(CONSOLE_EXTCOLOR_KIND(Fore), CONSOLE_EXTCOLOR_VALUE(Fore), 0) : 0;
        Ext[Index].Back = Back ? CONSOLE_EXTCOLOR_MAKE(CONSOLE_EXTCOLOR_KIND(Back), CONSOLE_EXTCOLOR_VALUE(Back), 0) : 0;
    }
}

static BOOL
HostResize(HOST *Host, SHORT Width, SHORT Height)
{
    SMALL_RECT Window;
    COORD Size;
    CHAR_INFO *Previous, *Current;
    CONSOLE_EXT_CELL *PreviousExt, *CurrentExt;
    SIZE_T Count;

    if (Width <= 0 || Height <= 0 || (SIZE_T)Width * Height > 1000000)
        return FALSE;
    Count = (SIZE_T)Width * Height;
    Previous = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Count * sizeof(*Previous));
    Current = HeapAlloc(GetProcessHeap(), 0, Count * sizeof(*Current));
    PreviousExt = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Count * sizeof(*PreviousExt));
    CurrentExt = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Count * sizeof(*CurrentExt));
    if (!Previous || !Current || !PreviousExt || !CurrentExt)
    {
        if (Previous) HeapFree(GetProcessHeap(), 0, Previous);
        if (Current) HeapFree(GetProcessHeap(), 0, Current);
        if (PreviousExt) HeapFree(GetProcessHeap(), 0, PreviousExt);
        if (CurrentExt) HeapFree(GetProcessHeap(), 0, CurrentExt);
        return FALSE;
    }

    Window.Left = Window.Top = 0;
    Window.Right = Width - 1;
    Window.Bottom = Height - 1;
    Size.X = Width;
    Size.Y = Height;
    SetConsoleWindowInfo(Host->ConsoleOut, TRUE, &Window);
    if (!SetConsoleScreenBufferSize(Host->ConsoleOut, Size))
    {
        HeapFree(GetProcessHeap(), 0, Previous);
        HeapFree(GetProcessHeap(), 0, Current);
        HeapFree(GetProcessHeap(), 0, PreviousExt);
        HeapFree(GetProcessHeap(), 0, CurrentExt);
        return FALSE;
    }
    SetConsoleWindowInfo(Host->ConsoleOut, TRUE, &Window);
    {
        /* A client's own active screen buffer follows the terminal size too */
        HANDLE Active = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (Active != INVALID_HANDLE_VALUE)
        {
            SetConsoleWindowInfo(Active, TRUE, &Window);
            SetConsoleScreenBufferSize(Active, Size);
            SetConsoleWindowInfo(Active, TRUE, &Window);
            CloseHandle(Active);
        }
    }
    if (Host->Previous) HeapFree(GetProcessHeap(), 0, Host->Previous);
    if (Host->Current) HeapFree(GetProcessHeap(), 0, Host->Current);
    if (Host->PreviousExt) HeapFree(GetProcessHeap(), 0, Host->PreviousExt);
    if (Host->CurrentExt) HeapFree(GetProcessHeap(), 0, Host->CurrentExt);
    Host->Previous = Previous;
    Host->Current = Current;
    Host->PreviousExt = PreviousExt;
    Host->CurrentExt = CurrentExt;
    Host->Width = Width;
    Host->Height = Height;
    Host->Painted = FALSE;
    Host->ScrollbackSeen = FALSE;
    {
        ULONGLONG Total = 0, First;
        DWORD Rows;

        /* From now on the server keeps the rows that scroll off the top of this buffer. The count
         * at this moment is where the terminal's history starts: a client that prints before the
         * host paints for the first time (a terminal starts its child as soon as the pseudoconsole
         * exists) has its first rows in the server's ring, and the first paint hands them over. */
        if (HostScrollbackCall(Host, Host->ConsoleOut, CONSOLE_SCROLLBACK_ENABLE, 0, 0, NULL, &Total, &First, &Rows))
        {
            Host->ScrollbackTotal = Total;
            Host->ScrollbackSeen = TRUE;
        }
    }
    return TRUE;
}

/* A surrogate pair occupies two cells of the console buffer (a UTF-16 unit each); the
 * terminal needs the pair as one UTF-8 sequence. */
#define HOST_IS_HIGH_SURROGATE(c)   ((c) >= 0xD800 && (c) <= 0xDBFF)
#define HOST_IS_LOW_SURROGATE(c)    ((c) >= 0xDC00 && (c) <= 0xDFFF)

/* A wide character occupies two cells: a leading and a trailing byte. The terminal shows it as one
 * glyph over two columns, so the pair is diffed and painted as a unit. */
#define HOST_IS_LEADING(c)          (((c)->Attributes & COMMON_LVB_LEADING_BYTE) != 0)
#define HOST_IS_TRAILING(c)         (((c)->Attributes & COMMON_LVB_TRAILING_BYTE) != 0)

/* A cell differs from what the terminal shows of it (Ref NULL: nothing is known of the row) */
#define HOST_DIFFERS(a, b, ea, eb) ((a)->Char.UnicodeChar != (b)->Char.UnicodeChar || (a)->Attributes != (b)->Attributes || \
                                    (ea)->Fore != (eb)->Fore || (ea)->Back != (eb)->Back)

static BOOL
HostCellChanged(HOST *Host, const CHAR_INFO *Cells, const CONSOLE_EXT_CELL *Ext,
                const CHAR_INFO *Ref, const CONSOLE_EXT_CELL *RefExt, DWORD Column)
{
    if (!Ref) return TRUE;
    if (HOST_DIFFERS(&Cells[Column], &Ref[Column], &Ext[Column], &RefExt[Column])) return TRUE;
    /* Both halves of a pair are painted together, so a change of either repaints both */
    if (HOST_IS_HIGH_SURROGATE(Cells[Column].Char.UnicodeChar) && Column + 1 < (DWORD)Host->Width &&
        HOST_IS_LOW_SURROGATE(Cells[Column + 1].Char.UnicodeChar))
        return HOST_DIFFERS(&Cells[Column + 1], &Ref[Column + 1], &Ext[Column + 1], &RefExt[Column + 1]);
    if (HOST_IS_LOW_SURROGATE(Cells[Column].Char.UnicodeChar) && Column > 0 &&
        HOST_IS_HIGH_SURROGATE(Cells[Column - 1].Char.UnicodeChar))
        return HOST_DIFFERS(&Cells[Column - 1], &Ref[Column - 1], &Ext[Column - 1], &RefExt[Column - 1]);
    /* The same for a wide character */
    if (HOST_IS_LEADING(&Cells[Column]) && Column + 1 < (DWORD)Host->Width && HOST_IS_TRAILING(&Cells[Column + 1]))
        return HOST_DIFFERS(&Cells[Column + 1], &Ref[Column + 1], &Ext[Column + 1], &RefExt[Column + 1]);
    if (HOST_IS_TRAILING(&Cells[Column]) && Column > 0 && HOST_IS_LEADING(&Cells[Column - 1]))
        return HOST_DIFFERS(&Cells[Column - 1], &Ref[Column - 1], &Ext[Column - 1], &RefExt[Column - 1]);
    return FALSE;
}

/* The SGR parameter that sets a color: Base is 30 (foreground) or 40 (background) */
static DWORD
HostFormatColor(CHAR *Out, UINT Base, WORD Attribute, UINT Shift, ULONG Ext)
{
    static const BYTE Palette[8] = {0, 4, 2, 6, 1, 5, 3, 7};

    if (CONSOLE_EXTCOLOR_KIND(Ext) == CONSOLE_EXTCOLOR_INDEX)
        return sprintf(Out, "%u;5;%lu", Base + 8, (ULONG)CONSOLE_EXTCOLOR_VALUE(Ext));
    if (CONSOLE_EXTCOLOR_KIND(Ext) == CONSOLE_EXTCOLOR_RGB)
        return sprintf(Out, "%u;2;%lu;%lu;%lu", Base + 8, (ULONG)((Ext >> 16) & 0xFF),
                       (ULONG)((Ext >> 8) & 0xFF), (ULONG)(Ext & 0xFF));
    return sprintf(Out, "%u", (UINT)(Base + Palette[(Attribute >> Shift) & 7] + (((Attribute >> Shift) & 8) ? 60 : 0)));
}

/* The escape sequences that paint the cells of one terminal row that differ from Ref, appended to
 * Line at Used; the new length is returned. */
static DWORD
HostPaintRow(HOST *Host, DWORD Row, const CHAR_INFO *Cells, const CONSOLE_EXT_CELL *Ext,
             const CHAR_INFO *Ref, const CONSOLE_EXT_CELL *RefExt, CHAR *Line, DWORD Used, BOOL *Changed)
{
    DWORD Column, Length;
    WORD Attribute = 0xffff;
    ULONG Fore = 0, Back = 0;
    CHAR Utf8[8];

    for (Column = 0; Column < (DWORD)Host->Width; ++Column)
    {
        if (!HostCellChanged(Host, Cells, Ext, Ref, RefExt, Column))
            continue;

        *Changed = TRUE;
        Used += sprintf(Line + Used, "\033[%lu;%luH", Row + 1, Column + 1);
        do
        {
            WCHAR Character;
            WORD Cell = Cells[Column].Attributes & ~COMMON_LVB_SBCSDBCS;
            if (!HostCellChanged(Host, Cells, Ext, Ref, RefExt, Column))
                break;
            if (Attribute != Cell || Fore != Ext[Column].Fore || Back != Ext[Column].Back)
            {
                Attribute = Cell;
                Fore = Ext[Column].Fore;
                Back = Ext[Column].Back;
                Used += sprintf(Line + Used, "\033[");
                Used += HostFormatColor(Line + Used, 30, Attribute, 0, Fore);
                Line[Used++] = ';';
                Used += HostFormatColor(Line + Used, 40, Attribute, 4, Back);
                Line[Used++] = 'm';
            }
            Character = Cells[Column].Char.UnicodeChar;
            if (!Character || Character < 32) Character = L' ';
            if (HOST_IS_LEADING(&Cells[Column]) && Column + 1 < (DWORD)Host->Width &&
                HOST_IS_TRAILING(&Cells[Column + 1]))
            {
                /* One glyph over two columns: the trailing cell is part of it */
                Length = WideCharToMultiByte(CP_UTF8, 0, &Character, 1, Utf8, sizeof(Utf8), NULL, NULL);
                if (Length)
                    ++Column;
            }
            else if (HOST_IS_LEADING(&Cells[Column]) || HOST_IS_TRAILING(&Cells[Column]))
            {
                /* Half of a wide character: a blank, which also clears what the terminal shows there */
                Utf8[0] = ' ';
                Length = 1;
            }
            else if (HOST_IS_HIGH_SURROGATE(Character) && Column + 1 < (DWORD)Host->Width &&
                HOST_IS_LOW_SURROGATE(Cells[Column + 1].Char.UnicodeChar))
            {
                WCHAR Pair[2];

                Pair[0] = Character;
                Pair[1] = Cells[Column + 1].Char.UnicodeChar;
                Length = WideCharToMultiByte(CP_UTF8, 0, Pair, 2, Utf8, sizeof(Utf8), NULL, NULL);
                if (Length)
                    ++Column;   /* the low half is part of this character */
            }
            else
                Length = WideCharToMultiByte(CP_UTF8, 0, &Character, 1,
                                             Utf8, sizeof(Utf8), NULL, NULL);
            if (!Length)
            {
                Utf8[0] = ' ';
                Length = 1;
            }
            CopyMemory(Line + Used, Utf8, Length);
            Used += Length;
            ++Column;
        } while (Column < (DWORD)Host->Width);
        --Column;
    }
    return Used;
}

#define HOST_LINE_SIZE(Host)    ((SIZE_T)(Host)->Width * 64 + 256)

/* Rows scrolled off the top of the console buffer since the last look (Rows of them in History,
 * oldest first) go to the terminal as rows that scroll off its screen, then the screen shows
 * the current frame. Lost: older rows were dropped by the server before the host asked, the
 * terminal's screen then goes to its scrollback as it is. Fresh: nothing is known of the
 * terminal's screen (first paint, cleared just now), so it is painted whole and no row of it is
 * pushed away: the history is exactly the rows. */
static BOOL
HostPaintScrolled(HOST *Host, const CHAR_INFO *History, const CONSOLE_EXT_CELL *HistoryExt, DWORD Rows, BOOL Lost,
                  BOOL Fresh, CHAR *Line)
{
    DWORD Row, Used, Height = (DWORD)Host->Height;
    BOOL Changed = FALSE;

#define HOST_FRAME_ROW(Index) ((Index) < Rows ? History + (SIZE_T)(Index) * Host->Width \
                                              : Host->Current + (SIZE_T)((Index) - Rows) * Host->Width)
#define HOST_FRAME_EXT(Index) ((Index) < Rows ? HistoryExt + (SIZE_T)(Index) * Host->Width \
                                              : Host->CurrentExt + (SIZE_T)((Index) - Rows) * Host->Width)
    if (Lost && !Fresh)
    {
        /* Not a single row of what the terminal shows is known to be among the new ones */
        Used = sprintf(Line, "\033[0m\033[%lu;1H", Height);
        for (Row = 0; Row < Height; ++Row) Line[Used++] = '\n';
        if (!HostWrite(Host, Line, Used)) return FALSE;
    }
    /* The terminal's screen becomes the rows that stay in view until the first one scrolls away... */
    Used = 0;
    for (Row = 0; Row < Height; ++Row)
        Used = HostPaintRow(Host, Row, HOST_FRAME_ROW(Row), HOST_FRAME_EXT(Row),
                            (Lost || Fresh) ? NULL : Host->Previous + (SIZE_T)Row * Host->Width,
                            Host->PreviousExt + (SIZE_T)Row * Host->Width, Line, Used, &Changed);
    if (Used && !HostWrite(Host, Line, Used)) return FALSE;
    /* ...and every row that scrolled off pushes the top row into the terminal's scrollback and brings the next in */
    for (Row = 0; Row < Rows; ++Row)
    {
        /* The default colours first: a terminal may fill the row that scrolls in with the current background */
        Used = sprintf(Line, "\033[0m\033[%lu;1H\n", Height);
        Used = HostPaintRow(Host, Height - 1, HOST_FRAME_ROW(Row + Height), HOST_FRAME_EXT(Row + Height),
                            NULL, NULL, Line, Used, &Changed);
        if (!HostWrite(Host, Line, Used)) return FALSE;
    }
#undef HOST_FRAME_ROW
#undef HOST_FRAME_EXT
    return TRUE;
}

/* ReadConsoleOutput leaves out the leading and trailing byte flags of wide characters (as Windows
 * before 8 does); ReadConsoleOutputAttribute has them. Without them the host could not tell the two
 * cells of a wide character from two characters. The flags of the frame in Host->Current are filled in. */
static VOID
HostReadWideFlags(HOST *Host, HANDLE ConsoleOut, const SMALL_RECT *Region, SHORT BufferWidth)
{
    WORD *Attributes;
    DWORD Row, Index, Count, Got, Rows = Region->Bottom - Region->Top + 1, Columns = Region->Right - Region->Left + 1;
    /* A frame as wide as its buffer is a run of cells: one request for as many as fit */
    BOOL Whole = !Region->Left && Columns == (DWORD)BufferWidth && Columns == (DWORD)Host->Width;
    DWORD Run = Whole ? Rows * Columns : Columns, Cells = Whole ? 1 : Rows;

    Attributes = HeapAlloc(GetProcessHeap(), 0, 16384 * sizeof(*Attributes));
    if (!Attributes) return;
    for (Row = 0; Row < Cells; ++Row)
    {
        for (Index = 0; Index < Run; Index += Got)
        {
            CHAR_INFO *Cell = Host->Current + (SIZE_T)Row * Host->Width + Index;
            COORD Start;

            Count = min(Run - Index, 16384);
            Got = 0;
            if (Whole)
            {
                Start.X = (SHORT)(Index % Columns);
                Start.Y = (SHORT)(Region->Top + Index / Columns);
            }
            else
            {
                Start.X = (SHORT)(Region->Left + Index);
                Start.Y = (SHORT)(Region->Top + Row);
            }
            if (!ReadConsoleOutputAttribute(ConsoleOut, Attributes, Count, Start, &Got) || !Got)
                break;
            for (Count = 0; Count < Got; ++Count)
                Cell[Count].Attributes = (Cell[Count].Attributes & ~COMMON_LVB_SBCSDBCS) |
                                         (Attributes[Count] & COMMON_LVB_SBCSDBCS);
        }
    }
    HeapFree(GetProcessHeap(), 0, Attributes);
}

static BOOL
HostReadFrame(HOST *Host, HANDLE ConsoleOut, const CONSOLE_SCREEN_BUFFER_INFO *Info)
{
    COORD BufferSize, BufferOrigin = {0, 0};
    SMALL_RECT Region;
    DWORD Row, BandRows;

    BufferSize.X = Host->Width;
    BufferSize.Y = Host->Height;
    Region.Left = Info->srWindow.Left;
    Region.Top = Info->srWindow.Top;
    Region.Right = Region.Left + Host->Width - 1;
    Region.Bottom = Region.Top + Host->Height - 1;
    if (Region.Right >= Info->dwSize.X) Region.Right = Info->dwSize.X - 1;
    if (Region.Bottom >= Info->dwSize.Y) Region.Bottom = Info->dwSize.Y - 1;
    ZeroMemory(Host->Current, (SIZE_T)Host->Width * Host->Height * sizeof(*Host->Current));
    /* One ReadConsoleOutput request carries at most 64 KiB of cells (CSR capture
     * buffer), as on Windows; a 250x70 terminal is 70000 bytes. Read in bands of rows. */
    BandRows = 32768 / ((DWORD)Host->Width * sizeof(CHAR_INFO));
    if (!BandRows) BandRows = 1;
    for (Row = 0; Row < (DWORD)Host->Height; Row += BandRows)
    {
        SMALL_RECT Band = Region;
        COORD BandSize = BufferSize;

        Band.Top = (SHORT)(Region.Top + Row);
        if (Band.Top > Region.Bottom) break;
        BandSize.Y = (SHORT)min(BandRows, (DWORD)Host->Height - Row);
        Band.Bottom = (SHORT)min(Band.Top + BandSize.Y - 1, Region.Bottom);
        if (!ReadConsoleOutputW(ConsoleOut, Host->Current + (SIZE_T)Row * Host->Width,
                                BandSize, BufferOrigin, &Band)) return FALSE;
    }
    HostReadWideFlags(Host, ConsoleOut, &Region, Info->dwSize.X);
    return TRUE;
}

static BOOL
HostPaintBuffer(HOST *Host, HANDLE ConsoleOut)
{
    CONSOLE_SCREEN_BUFFER_INFO Info;
    CONSOLE_CURSOR_INFO CursorInfo;
    CHAR_INFO *History = NULL;
    CONSOLE_EXT_CELL *HistoryExt = NULL;
    CHAR *Line;
    DWORD Row, Rows = 0, Attempt, Chunk, Got;
    BOOL Changed = FALSE, Keeps, Lost = FALSE;
    ULONGLONG Total = 0, Again, First = 0;

    if (!GetConsoleScreenBufferInfo(ConsoleOut, &Info)) return FALSE;
    if (!Host->Painted && !HostWrite(Host, "\033[?25l\033[2J", 10)) return FALSE;

    /* The frame and the count of rows scrolled off must belong together: look again when more
     * rows scrolled off while the frame was read. */
    for (Attempt = 0; ; ++Attempt)
    {
        Keeps = HostScrollbackCall(Host, ConsoleOut, 0, 0, 0, NULL, &Total, &First, &Got);
        if (!HostReadFrame(Host, ConsoleOut, &Info)) return FALSE;
        if (!Keeps || Attempt >= 8) break;
        if (!HostScrollbackCall(Host, ConsoleOut, 0, 0, 0, NULL, &Again, &First, &Got) || Again == Total) break;
    }
    /* The exact colors of what the frame shows (the cells have the nearest 16 colors) */
    if (Host->ExtPresent)
    {
        HostFetchExt(Host, 0, ConsoleOut, (ULONGLONG)(ULONG)Info.srWindow.Top, Host->Height,
                     (DWORD)Info.dwSize.X, (DWORD)Info.srWindow.Left, Host->CurrentExt);
        HostNormalizeExt(Host->Current, Host->CurrentExt, (SIZE_T)Host->Width * Host->Height);
    }
    else
        ZeroMemory(Host->CurrentExt, (SIZE_T)Host->Width * Host->Height * sizeof(*Host->CurrentExt));
    if (Keeps)
    {
        if (Host->ScrollbackSeen && Total > Host->ScrollbackTotal)
        {
            ULONGLONG Wanted = Total - Host->ScrollbackTotal;

            /* Rows the server no longer holds come back as a later first row */
            if (HostScrollbackCall(Host, ConsoleOut, 0, Total - Wanted, 0, NULL, &Again, &First, &Got) && First < Total)
            {
                Lost = First != Total - Wanted;
                Wanted = Total - First;
                History = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Wanted * Host->Width * sizeof(*History));
                HistoryExt = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Wanted * Host->Width * sizeof(*HistoryExt));
                if (History && !HistoryExt)
                {
                    HeapFree(GetProcessHeap(), 0, History);
                    History = NULL;
                }
                if (History)
                {
                    Chunk = 32768 / ((DWORD)Host->Width * sizeof(CHAR_INFO));
                    if (!Chunk) Chunk = 1;
                    while (Rows < Wanted)
                    {
                        ULONGLONG Start;

                        if (!HostScrollbackCall(Host, ConsoleOut, 0, First + Rows, (DWORD)min(Chunk, Wanted - Rows),
                                                History + (SIZE_T)Rows * Host->Width, &Again, &Start, &Got) ||
                            !Got || Start != First + Rows)
                            break;
                        Rows += Got;
                    }
                    if (Rows < Wanted)
                    {
                        /* The rows could not be read whole: paint the frame in place */
                        HeapFree(GetProcessHeap(), 0, History);
                        History = NULL;
                        Rows = 0;
                    }
                    else if (Host->ExtPresent)
                    {
                        HostFetchExt(Host, CONSOLE_EXTCOLORS_SCROLLBACK, ConsoleOut, First, Rows,
                                     Host->Width, 0, HistoryExt);
                        HostNormalizeExt(History, HistoryExt, (SIZE_T)Rows * Host->Width);
                    }
                    else
                        ZeroMemory(HistoryExt, (SIZE_T)Rows * Host->Width * sizeof(*HistoryExt));
                }
            }
        }
        Host->ScrollbackTotal = Total;
        Host->ScrollbackSeen = TRUE;
    }
    else
        Host->ScrollbackSeen = FALSE;

    if (!Rows && HistoryExt)
    {
        HeapFree(GetProcessHeap(), 0, HistoryExt);
        HistoryExt = NULL;
    }

    Line = HeapAlloc(GetProcessHeap(), 0, HOST_LINE_SIZE(Host));
    if (!Line)
    {
        if (History) HeapFree(GetProcessHeap(), 0, History);
        if (HistoryExt) HeapFree(GetProcessHeap(), 0, HistoryExt);
        return FALSE;
    }
    if (Rows)
    {
        BOOL Result = HostPaintScrolled(Host, History, HistoryExt, Rows, Lost, !Host->Painted, Line);

        HeapFree(GetProcessHeap(), 0, History);
        HeapFree(GetProcessHeap(), 0, HistoryExt);
        if (!Result)
        {
            HeapFree(GetProcessHeap(), 0, Line);
            return FALSE;
        }
        Changed = TRUE;
    }
    else
    {
        for (Row = 0; Row < (DWORD)Host->Height; ++Row)
        {
            DWORD Used = HostPaintRow(Host, Row, Host->Current + (SIZE_T)Row * Host->Width,
                                      Host->CurrentExt + (SIZE_T)Row * Host->Width,
                                      Host->Painted ? Host->Previous + (SIZE_T)Row * Host->Width : NULL,
                                      Host->PreviousExt + (SIZE_T)Row * Host->Width,
                                      Line, 0, &Changed);

            if (Used && !HostWrite(Host, Line, Used))
            {
                HeapFree(GetProcessHeap(), 0, Line);
                return FALSE;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Line);
    CopyMemory(Host->Previous, Host->Current,
               (SIZE_T)Host->Width * Host->Height * sizeof(*Host->Current));
    CopyMemory(Host->PreviousExt, Host->CurrentExt,
               (SIZE_T)Host->Width * Host->Height * sizeof(*Host->CurrentExt));
    Host->Painted = TRUE;
    if (GetConsoleCursorInfo(ConsoleOut, &CursorInfo))
    {
        CHAR Position[64];
        DWORD Count = 0;
        if (CursorInfo.bVisible != Host->CursorVisible)
        {
            Count += sprintf(Position + Count, CursorInfo.bVisible ? "\033[?25h" : "\033[?25l");
            Host->CursorVisible = CursorInfo.bVisible;
        }
        if (Info.dwCursorPosition.X != Host->Cursor.X ||
            Info.dwCursorPosition.Y != Host->Cursor.Y || Count || Changed)
        {
            Count += sprintf(Position + Count, "\033[%u;%uH",
                             (UINT)(Info.dwCursorPosition.Y - Info.srWindow.Top + 1),
                             (UINT)(Info.dwCursorPosition.X - Info.srWindow.Left + 1));
            Host->Cursor = Info.dwCursorPosition;
        }
        if (Count && !HostWrite(Host, Position, Count)) return FALSE;
    }
    return TRUE;
}

/* The terminal shows the ACTIVE screen buffer (CONOUT$ opens it), which is not the one
 * the host started with once a client calls SetConsoleActiveScreenBuffer (curses
 * programs such as nano for Windows do, and draw nothing in the original buffer). */
static BOOL
HostPaint(HOST *Host)
{
    HANDLE Active = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    BOOL Result;

    if (Active == INVALID_HANDLE_VALUE)
        return HostPaintBuffer(Host, Host->ConsoleOut);
    Result = HostPaintBuffer(Host, Active);
    CloseHandle(Active);
    return Result;
}

static WORD
HostScanCode(WORD Key)
{
    static const BYTE LetterScanCodes[26] =
    {
        0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17,
        0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13,
        0x1f, 0x14, 0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c
    };
    static const BYTE DigitScanCodes[10] =
    {
        0x0b, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a
    };
    static const BYTE FunctionScanCodes[12] =
    {
        0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x57, 0x58
    };

    if (Key >= 'A' && Key <= 'Z')
        return LetterScanCodes[Key - 'A'];
    if (Key >= '0' && Key <= '9')
        return DigitScanCodes[Key - '0'];
    if (Key >= VK_F1 && Key <= VK_F12)
        return FunctionScanCodes[Key - VK_F1];

    switch (Key)
    {
        case VK_ESCAPE: return 0x01;
        case VK_BACK: return 0x0e;
        case VK_TAB: return 0x0f;
        case VK_RETURN: return 0x1c;
        case VK_SPACE: return 0x39;
        case VK_HOME: return 0x47;
        case VK_UP: return 0x48;
        case VK_PRIOR: return 0x49;
        case VK_LEFT: return 0x4b;
        case VK_RIGHT: return 0x4d;
        case VK_END: return 0x4f;
        case VK_DOWN: return 0x50;
        case VK_NEXT: return 0x51;
        case VK_INSERT: return 0x52;
        case VK_DELETE: return 0x53;
        default: return 0;
    }
}

static VOID
HostKey(HOST *Host, WORD Key, WCHAR Character, DWORD Modifiers)
{
    INPUT_RECORD Record[2];
    DWORD Written;
    ZeroMemory(Record, sizeof(Record));
    Record[0].EventType = Record[1].EventType = KEY_EVENT;
    Record[0].Event.KeyEvent.bKeyDown = TRUE;
    Record[0].Event.KeyEvent.wRepeatCount = 1;
    Record[0].Event.KeyEvent.wVirtualKeyCode = Key;
    Record[0].Event.KeyEvent.wVirtualScanCode = HostScanCode(Key);
    Record[0].Event.KeyEvent.uChar.UnicodeChar = Character;
    Record[0].Event.KeyEvent.dwControlKeyState = Modifiers;
    Record[1].Event.KeyEvent = Record[0].Event.KeyEvent;
    Record[1].Event.KeyEvent.bKeyDown = FALSE;
    WriteConsoleInputW(Host->ConsoleIn, Record, 2, &Written);
}

static VOID
HostSequence(HOST *Host, CHAR Final, BOOL Ss3)
{
    WORD Key = 0;
    int Number = atoi(Host->Sequence);
    switch (Final)
    {
        case 'A': Key = VK_UP; break;
        case 'B': Key = VK_DOWN; break;
        case 'C': Key = VK_RIGHT; break;
        case 'D': Key = VK_LEFT; break;
        case 'H': Key = VK_HOME; break;
        case 'F': Key = VK_END; break;
        case 'P': if (Ss3) Key = VK_F1; break;
        case 'Q': if (Ss3) Key = VK_F2; break;
        case 'R': if (Ss3) Key = VK_F3; break;
        case 'S': if (Ss3) Key = VK_F4; break;
        case '~':
            switch (Number)
            {
                case 1: case 7: Key = VK_HOME; break;
                case 2: Key = VK_INSERT; break;
                case 3: Key = VK_DELETE; break;
                case 4: case 8: Key = VK_END; break;
                case 5: Key = VK_PRIOR; break;
                case 6: Key = VK_NEXT; break;
                case 11: Key = VK_F1; break;
                case 12: Key = VK_F2; break;
                case 13: Key = VK_F3; break;
                case 14: Key = VK_F4; break;
                case 15: Key = VK_F5; break;
                case 17: Key = VK_F6; break;
                case 18: Key = VK_F7; break;
                case 19: Key = VK_F8; break;
                case 20: Key = VK_F9; break;
                case 21: Key = VK_F10; break;
                case 23: Key = VK_F11; break;
                case 24: Key = VK_F12; break;
            }
    }
    if (Key) HostKey(Host, Key, 0, 0);
}

static BOOL HostCtrlC(HOST *Host);

static VOID
HostInput(HOST *Host, BYTE Byte)
{
    DWORD Modifiers = 0;
    WCHAR Character, Pair[2];
    WORD Key, ControlKey = 0;

    if (Host->Escape >= 2)
    {
        if (Byte >= 0x40 && Byte <= 0x7e)
        {
            Host->Sequence[Host->SequenceLength] = 0;
            HostSequence(Host, Byte, Host->Escape == 3);
            Host->Escape = Host->SequenceLength = 0;
        }
        else if ((SIZE_T)Host->SequenceLength + 1 < sizeof(Host->Sequence))
            Host->Sequence[Host->SequenceLength++] = Byte;
        else
            Host->Escape = Host->SequenceLength = 0;
        return;
    }
    if (Host->Escape)
    {
        Host->Escape = 0;
        if (Byte == '[' || Byte == 'O')
        {
            Host->Escape = Byte == '[' ? 2 : 3;
            Host->SequenceLength = 0;
            return;
        }
        Modifiers = LEFT_ALT_PRESSED;
    }
    else if (Byte == 0x1b)
    {
        Host->Escape = 1;
        Host->EscapeTime = GetTickCount();
        return;
    }

    if (Host->Utf8Length || Byte >= 0x80)
    {
        if (!Host->Utf8Length)
            Host->Utf8Length = Byte >= 0xf0 ? 4 : Byte >= 0xe0 ? 3 : Byte >= 0xc0 ? 2 : 1;
        Host->Utf8[Host->Utf8Count++] = Byte;
        if (Host->Utf8Count < Host->Utf8Length) return;
        if (MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)Host->Utf8,
                                Host->Utf8Count, Pair, 2) == 2)
        {
            /* A character outside the BMP is two key events, one per UTF-16 unit, as on Windows */
            Host->Utf8Length = Host->Utf8Count = 0;
            HostKey(Host, 0, Pair[0], Modifiers);
            HostKey(Host, 0, Pair[1], Modifiers);
            return;
        }
        if (MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)Host->Utf8,
                                Host->Utf8Count, &Character, 1) != 1)
            Character = 0xfffd;
        Host->Utf8Length = Host->Utf8Count = 0;
    }
    else
    {
        Character = Byte;
        if (Byte == 3 && HostCtrlC(Host)) return;
        if (Byte >= 1 && Byte <= 26 && Byte != '\r' && Byte != '\t')
        {
            /* Ctrl+letter: virtual key of the letter, the character is the control code (Ctrl+O is
             * 0x0F), as Windows reports it; programs reading key events (curses) use the character */
            Modifiers |= LEFT_CTRL_PRESSED;
            ControlKey = L'A' + Byte - 1;
        }
    }
    Key = Character >= L'A' && Character <= L'Z' ? Character :
          Character >= L'a' && Character <= L'z' ? Character - L'a' + L'A' :
          Character >= L'0' && Character <= L'9' ? Character :
          Character == L' ' ? VK_SPACE : 0;
    if (ControlKey)
        Key = ControlKey;
    if (Byte == '\r' || Byte == '\n') Key = VK_RETURN, Character = L'\r';
    else if (Byte == '\b' || Byte == 0x7f) Key = VK_BACK, Character = L'\b';
    else if (Byte == '\t') Key = VK_TAB;
    else if (Byte == 0x1b) Key = VK_ESCAPE;
    HostKey(Host, Key, Character, Modifiers);
}

/* ENABLE_VIRTUAL_TERMINAL_INPUT: the application reads and parses the VT sequences
 * itself, so every byte from the terminal is queued as it came, as a character
 * event. Translating it to key events here would lose what the key events cannot
 * say (modifier parameters, unknown sequences) and the console would translate
 * the key events back to sequences. */
static BOOL
HostRawMode(HOST *Host)
{
    DWORD Mode;
    return GetConsoleMode(Host->ConsoleIn, &Mode) && (Mode & ENABLE_VIRTUAL_TERMINAL_INPUT);
}

static VOID
HostRawCharacter(INPUT_RECORD *Records, DWORD *Used, WCHAR Character)
{
    INPUT_RECORD *Down = &Records[(*Used)++], *Up = &Records[(*Used)++];
    ZeroMemory(Down, sizeof(*Down));
    Down->EventType = KEY_EVENT;
    Down->Event.KeyEvent.bKeyDown = TRUE;
    Down->Event.KeyEvent.wRepeatCount = 1;
    Down->Event.KeyEvent.uChar.UnicodeChar = Character;
    *Up = *Down;
    Up->Event.KeyEvent.bKeyDown = FALSE;
}

static VOID
HostRawInput(HOST *Host, const BYTE *Bytes, DWORD Count)
{
    INPUT_RECORD Records[2 * (256 + 40)];
    WCHAR Characters[2];
    DWORD Index, Used = 0, Written;
    int Converted;

    /* A sequence that was half read when the application switched the mode */
    if (Host->Escape)
    {
        HostRawCharacter(Records, &Used, L'\x1b');
        if (Host->Escape >= 2) HostRawCharacter(Records, &Used, Host->Escape == 2 ? L'[' : L'O');
        for (Index = 0; Index < Host->SequenceLength; ++Index)
            HostRawCharacter(Records, &Used, (BYTE)Host->Sequence[Index]);
        Host->Escape = Host->SequenceLength = 0;
    }
    for (Index = 0; Index < Count; ++Index)
    {
        BYTE Byte = Bytes[Index];

        if (Host->Utf8Length || Byte >= 0x80)
        {
            if (!Host->Utf8Length)
                Host->Utf8Length = Byte >= 0xf0 ? 4 : Byte >= 0xe0 ? 3 : Byte >= 0xc0 ? 2 : 1;
            Host->Utf8[Host->Utf8Count++] = Byte;
            if (Host->Utf8Count < Host->Utf8Length) continue;
            Converted = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)Host->Utf8,
                                            Host->Utf8Count, Characters, 2);
            Host->Utf8Length = Host->Utf8Count = 0;
            if (Converted < 1 || Converted > 2)
            {
                Characters[0] = 0xfffd;
                Converted = 1;
            }
            HostRawCharacter(Records, &Used, Characters[0]);
            if (Converted == 2) HostRawCharacter(Records, &Used, Characters[1]);
        }
        else
        {
            if (Byte == 3 && HostCtrlC(Host)) continue;
            HostRawCharacter(Records, &Used, Byte);
        }
    }
    if (Used) WriteConsoleInputW(Host->ConsoleIn, Records, Used, &Written);
}

#define HOST_SIGNAL_RESIZE 8
#define HOST_SIGNAL_CLIENT 0x4e50 /* nitro private: argument = client process id */

static BOOL WINAPI
HostCtrlHandler(DWORD Event)
{
    /* Ctrl+C generated for the clients must not end the host itself. */
    return Event == CTRL_C_EVENT;
}

/* Ctrl+C typed on the terminal: with processed input the console does not
 * queue a key, it raises CTRL_C_EVENT for the attached processes. */
static BOOL
HostCtrlC(HOST *Host)
{
    DWORD Mode;
    if (!GetConsoleMode(Host->ConsoleIn, &Mode) || !(Mode & ENABLE_PROCESSED_INPUT))
        return FALSE;
    return GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
}

static VOID
HostStopClients(VOID)
{
    DWORD Pids[256], Count, Index;
    HANDLE Process;
    Count = GetConsoleProcessList(Pids, ARRAYSIZE(Pids));
    for (Index = 0; Index < Count && Index < ARRAYSIZE(Pids); ++Index)
    {
        if (Pids[Index] == GetCurrentProcessId()) continue;
        Process = OpenProcess(PROCESS_TERMINATE, FALSE, Pids[Index]);
        if (Process)
        {
            TerminateProcess(Process, CONTROL_C_EXIT);
            CloseHandle(Process);
        }
    }
}

int wmain(int argc, WCHAR **argv)
{
    HOST Host;
    SECURITY_ATTRIBUTES Security = {sizeof(Security), NULL, TRUE};
    STARTUPINFOW Startup;
    PROCESS_INFORMATION Process;
    ULONGLONG Ready[3];
    HANDLE ReadyPipe = NULL;
    WCHAR *Command;
    DWORD Available, Read, Written, Pids[256], Count;
    WORD Message[3];
    BYTE Bytes[256];
    int Index;

    ZeroMemory(&Host, sizeof(Host));
    Host.Width = 80;
    Host.Height = 25;
    SetConsoleCtrlHandler(HostCtrlHandler, TRUE);
    Host.PipeIn = GetStdHandle(STD_INPUT_HANDLE);
    Host.PipeOut = GetStdHandle(STD_OUTPUT_HANDLE);
    for (Index = 1; Index < argc; ++Index)
    {
        if (!wcscmp(argv[Index], L"--width") && Index + 1 < argc)
            Host.Width = HostParseDimension(argv[++Index], 80);
        else if (!wcscmp(argv[Index], L"--height") && Index + 1 < argc)
            Host.Height = HostParseDimension(argv[++Index], 25);
        else if (!wcscmp(argv[Index], L"--signal") && Index + 1 < argc)
            Host.Signal = (HANDLE)(ULONG_PTR)_wcstoui64(argv[++Index], NULL, 0);
        else if (!wcscmp(argv[Index], L"--ready") && Index + 1 < argc)
            ReadyPipe = (HANDLE)(ULONG_PTR)_wcstoui64(argv[++Index], NULL, 0);
    }
    Host.ConsoleIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, &Security, OPEN_EXISTING, 0, NULL);
    Host.ConsoleOut = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, &Security, OPEN_EXISTING, 0, NULL);
    if (Host.ConsoleIn == INVALID_HANDLE_VALUE || Host.ConsoleOut == INVALID_HANDLE_VALUE)
        return 1;
    if (!HostResize(&Host, Host.Width, Host.Height)) return 1;
    Ready[0] = (ULONG_PTR)NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Ready[1] = (ULONG_PTR)Host.ConsoleIn;
    Ready[2] = (ULONG_PTR)Host.ConsoleOut;
    if (ReadyPipe)
    {
        WriteFile(ReadyPipe, Ready, sizeof(Ready), &Written, NULL);
        CloseHandle(ReadyPipe);
    }

    Command = wcsstr(GetCommandLineW(), L" -- ");
    if (Command)
    {
        Command += 4;
        ZeroMemory(&Startup, sizeof(Startup));
        Startup.cb = sizeof(Startup);
        Startup.dwFlags = STARTF_USESTDHANDLES;
        Startup.hStdInput = Host.ConsoleIn;
        Startup.hStdOutput = Host.ConsoleOut;
        Startup.hStdError = Host.ConsoleOut;
        if (CreateProcessW(NULL, Command, NULL, NULL, TRUE, 0,
                           NULL, NULL, &Startup, &Process))
        {
            Host.Client = Process.hProcess;
            CloseHandle(Process.hThread);
            Host.SawClient = TRUE;
        }
    }
    for (;;)
    {
        if (!HostPaint(&Host)) break;
        if (Host.Signal)
        {
            Available = 0;
            if (!PeekNamedPipe(Host.Signal, NULL, 0, NULL, &Available, NULL))
            {
                HostStopClients();
                break;
            }
            while (Available >= sizeof(Message))
            {
                if (!ReadFile(Host.Signal, Message, sizeof(Message), &Read, NULL) ||
                    Read != sizeof(Message)) break;
                /* Frames are three WORDs: type, then two WORD arguments (the Windows
                 * pseudoconsole signal protocol that sshd also speaks). */
                if (Message[0] == HOST_SIGNAL_RESIZE && Message[1] <= 32767 && Message[2] <= 32767)
                {
                    /* What the client printed so far goes to the terminal before the buffer is
                     * resized: a new width drops the rows the server kept for the old one. */
                    HostPaint(&Host);
                    HostResize(&Host, (SHORT)Message[1], (SHORT)Message[2]);
                }
                else if (Message[0] == HOST_SIGNAL_CLIENT && !Host.Client)
                {
                    Host.Client = OpenProcess(SYNCHRONIZE, FALSE, Message[1] | ((DWORD)Message[2] << 16));
                    Host.SawClient = TRUE;
                }
                Available -= sizeof(Message);
            }
        }
        Available = 0;
        if (PeekNamedPipe(Host.PipeIn, NULL, 0, NULL, &Available, NULL))
        {
            while (Available)
            {
                DWORD Chunk = Available < sizeof(Bytes) ? Available : sizeof(Bytes);
                if (!ReadFile(Host.PipeIn, Bytes, Chunk, &Read, NULL) || !Read) break;
                if (HostRawMode(&Host))
                    HostRawInput(&Host, Bytes, Read);
                else
                    for (Index = 0; Index < (int)Read; ++Index)
                        HostInput(&Host, Bytes[Index]);
                Available -= Read;
            }
        }
        if (Host.Escape == 1 && GetTickCount() - Host.EscapeTime > 40)
        {
            Host.Escape = 0;
            HostKey(&Host, VK_ESCAPE, 0x1b, 0);
        }
        Count = GetConsoleProcessList(Pids, ARRAYSIZE(Pids));
        if (Count > 1) Host.SawClient = TRUE;
        if ((Host.Client && WaitForSingleObject(Host.Client, 0) == WAIT_OBJECT_0) ||
            (!Host.Client && Host.SawClient && Count <= 1))
        {
            HostPaint(&Host);
            break;
        }
        Sleep(15);
    }
    if (Host.Client) CloseHandle(Host.Client);
    if (Host.Signal) CloseHandle(Host.Signal);
    CloseHandle(Host.ConsoleIn);
    CloseHandle(Host.ConsoleOut);
    if (Host.Previous) HeapFree(GetProcessHeap(), 0, Host.Previous);
    if (Host.Current) HeapFree(GetProcessHeap(), 0, Host.Current);
    return 0;
}
