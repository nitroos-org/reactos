/*
 * PROJECT:     ReactOS Console Server DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Virtual terminal sequences in the output of text-mode screen buffers
 *              (ENABLE_VIRTUAL_TERMINAL_PROCESSING)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The sequences and their effects follow the "Console Virtual Terminal
 * Sequences" documentation and the behaviour of the Windows 10 console
 * measured with kernel32_apitest:ConsoleVirtualTerminal:
 *  - positions are relative to the view (the console window), which they
 *    cannot leave; columns are those of the buffer;
 *  - SGR maps the colors to the 16 attribute colors; 256 colors and 24-bit
 *    colors take the nearest color of the console color table; bold is a
 *    rendition of its own that brightens the foreground; SGR 0, 39 and 49
 *    restore the default colors of the console, not the current attribute;
 *  - ED 2 keeps the screen contents in the scrollback: the view moves below
 *    the last line that has text and is cleared there; ED 3 drops the
 *    scrollback;
 *  - DECSC / DECRC (ESC 7 / ESC 8, CSI s / CSI u) save and restore only the
 *    cursor position, relative to the view;
 *  - at most 16 parameters are used, the rest are ignored;
 *  - the parser state belongs to the screen buffer, so a sequence can be
 *    split over several writes; an OSC string lasts until BEL or ST (also
 *    over other processes' output), CAN and SUB cancel it;
 *  - ESC P, ESC X, ESC ^ and ESC _ do not start strings; the 8-bit CSI
 *    (U+009B) and ST (U+009C) work in WriteConsoleW, other C1 controls are
 *    text, and a C1 control in the middle of a sequence cancels it.
 */

/* INCLUDES *******************************************************************/

#include <consrv.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* Parser states (CONSOLE_VT_STATE::State); the ground state is 0 */
#define VT_GROUND           0
#define VT_ESCAPE           1
#define VT_ESCAPE_INTER     2
#define VT_CSI_PARAM        3
#define VT_CSI_INTER        4
#define VT_CSI_IGNORE       5
#define VT_OSC              6
#define VT_OSC_ESC          7

#define VT_ESC  0x1B
#define VT_CSI  0x9B    /* 8-bit CSI */
#define VT_ST   0x9C    /* 8-bit string terminator */
#define VT_BEL  0x07
#define VT_CAN  0x18
#define VT_SUB  0x1A

#define VT_MAX_PARAM        32767
#define VT_OSC_INVALID      0xFFFF
#define VT_TAB_WIDTH        8

/*
 * A report (DSR, DA) is dropped while this many input events are pending,
 * so that a program that floods the console with requests and never reads
 * them cannot make the console server queue input without bound. Windows
 * queues them all; nothing reads a report after 1024 unread events.
 */
#define VT_REPORT_MAX_PENDING   1024

/* ANSI color number -> attribute color (the attribute has red and blue swapped) */
static const UCHAR VtAnsiToAttrib[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };

/* DEC special graphics character set, characters 0x5F to 0x7E */
static const WCHAR VtDecGraphics[] =
{
    0x00A0, 0x25C6, 0x2592, 0x2409, 0x240C, 0x240D, 0x240A, 0x00B0,
    0x00B1, 0x2424, 0x240B, 0x2518, 0x2510, 0x250C, 0x2514, 0x253C,
    0x23BA, 0x23BB, 0x2500, 0x23BC, 0x23BD, 0x251C, 0x2524, 0x2534,
    0x252C, 0x2502, 0x2264, 0x2265, 0x03C0, 0x2260, 0x00A3, 0x00B7
};

/* PRIVATE FUNCTIONS **********************************************************/

static BOOLEAN
VtIsActive(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff)
{
    return ((PCONSOLE_SCREEN_BUFFER)Buff == FrontEnd->Console->ActiveBuffer);
}

static SHORT
VtViewTop(PTEXTMODE_SCREEN_BUFFER Buff)
{
    return Buff->ViewOrigin.Y;
}

static SHORT
VtViewBottom(PTEXTMODE_SCREEN_BUFFER Buff)
{
    return (SHORT)(min(Buff->ViewOrigin.Y + Buff->ViewSize.Y, Buff->ScreenBufferSize.Y) - 1);
}

static SHORT
VtRight(PTEXTMODE_SCREEN_BUFFER Buff)
{
    return Buff->ScreenBufferSize.X - 1;
}

static SHORT
VtClamp(LONG Value, SHORT Low, SHORT High)
{
    if (Value < Low) return Low;
    if (Value > High) return High;
    return (SHORT)Value;
}

/* Parameter Index, or Default if it is missing or 0 */
static USHORT
VtParam(PCONSOLE_VT_STATE Vt, UINT Index, USHORT Default)
{
    if (Index < min(Vt->NumParams, CONSOLE_VT_MAX_PARAMS) && Vt->Params[Index] != 0)
        return Vt->Params[Index];
    return Default;
}

/* Rows Top to Bottom of the scrolling region that contains Row, or of the view */
static BOOLEAN
VtRegion(PTEXTMODE_SCREEN_BUFFER Buff, SHORT Row, PSHORT Top, PSHORT Bottom)
{
    SHORT ViewTop = VtViewTop(Buff);

    if (Buff->Vt.MarginsSet)
    {
        *Top    = ViewTop + Buff->Vt.MarginTop;
        *Bottom = min(ViewTop + Buff->Vt.MarginBottom, VtViewBottom(Buff));
        /* The view may have become smaller than the region: then there is none */
        if (*Top <= *Bottom)
            return (Row >= *Top && Row <= *Bottom);
    }
    *Top    = ViewTop;
    *Bottom = VtViewBottom(Buff);
    return (Row >= *Top && Row <= *Bottom);
}

static VOID
VtFillCells(PTEXTMODE_SCREEN_BUFFER Buff, SHORT X, SHORT Y, LONG Count, WORD Attrib)
{
    PCHAR_INFO Ptr;

    if (Y < 0 || Y >= Buff->ScreenBufferSize.Y || X < 0) return;
    Count = min(Count, (LONG)Buff->ScreenBufferSize.X - X);
    if (Count <= 0) return;

    Ptr = ConioCoordToPointer(Buff, X, Y);
    while (Count-- > 0)
    {
        Ptr->Char.UnicodeChar = L' ';
        Ptr->Attributes = Attrib;
        /* Erased with the current colors, which may be extended ones */
        if (Attrib == Buff->ScreenDefaultAttrib)
            ConioStampExt(Buff, Ptr);
        else
            ConioClearExt(Buff, Ptr, 1);
        ++Ptr;
    }
}

static VOID
VtFillRows(PTEXTMODE_SCREEN_BUFFER Buff, SHORT Top, SHORT Bottom, WORD Attrib)
{
    SHORT Y;
    for (Y = Top; Y <= Bottom; ++Y)
        VtFillCells(Buff, 0, Y, Buff->ScreenBufferSize.X, Attrib);
}

/* Scroll rows Top to Bottom up by Lines (down if Lines < 0); the rows that come in are blank */
static VOID
VtScrollRows(PTEXTMODE_SCREEN_BUFFER Buff, SHORT Top, SHORT Bottom, LONG Lines, WORD Attrib)
{
    LONG Height = Bottom - Top + 1;
    SHORT Y;
    SIZE_T RowSize = Buff->ScreenBufferSize.X * sizeof(CHAR_INFO);

    if (Height <= 0 || Lines == 0) return;

    if (Lines >= Height || -Lines >= Height)
    {
        VtFillRows(Buff, Top, Bottom, Attrib);
        return;
    }

    if (Lines > 0)
    {
        for (Y = Top; Y <= Bottom - Lines; ++Y)
        {
            RtlMoveMemory(ConioCoordToPointer(Buff, 0, Y),
                          ConioCoordToPointer(Buff, 0, Y + Lines), RowSize);
            ConioMoveExt(Buff, ConioCoordToPointer(Buff, 0, Y),
                         ConioCoordToPointer(Buff, 0, Y + Lines), Buff->ScreenBufferSize.X);
        }
        VtFillRows(Buff, (SHORT)(Bottom - Lines + 1), Bottom, Attrib);
    }
    else
    {
        Lines = -Lines;
        for (Y = Bottom; Y >= Top + Lines; --Y)
        {
            RtlMoveMemory(ConioCoordToPointer(Buff, 0, Y),
                          ConioCoordToPointer(Buff, 0, Y - Lines), RowSize);
            ConioMoveExt(Buff, ConioCoordToPointer(Buff, 0, Y),
                         ConioCoordToPointer(Buff, 0, Y - Lines), Buff->ScreenBufferSize.X);
        }
        VtFillRows(Buff, Top, (SHORT)(Top + Lines - 1), Attrib);
    }
}

/* Scroll the whole buffer up by Lines: the top lines are dropped, blank ones come in at the bottom */
static VOID
VtScrollBuffer(PTEXTMODE_SCREEN_BUFFER Buff, LONG Lines, WORD Attrib)
{
    if (Lines <= 0) return;
    ConioRecordScrolledRows(Buff, Lines);
    if (Lines >= Buff->ScreenBufferSize.Y)
    {
        VtFillRows(Buff, 0, Buff->ScreenBufferSize.Y - 1, Attrib);
        return;
    }
    Buff->VirtualY = (USHORT)((Buff->VirtualY + Lines) % Buff->ScreenBufferSize.Y);
    VtFillRows(Buff, (SHORT)(Buff->ScreenBufferSize.Y - Lines), Buff->ScreenBufferSize.Y - 1, Attrib);
}

/* Show the cells Left..Right of rows Top..Bottom again */
static VOID
VtRedraw(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff,
         SHORT Left, SHORT Top, SHORT Right, SHORT Bottom)
{
    SMALL_RECT Region;

    if (!VtIsActive(FrontEnd, Buff) || Left > Right || Top > Bottom) return;

    Region.Left   = max(Left, 0);
    Region.Top    = max(Top, 0);
    Region.Right  = min(Right, VtRight(Buff));
    Region.Bottom = min(Bottom, Buff->ScreenBufferSize.Y - 1);
    FrontEnd->Vtbl->DrawRegion(FrontEnd, &Region);
}

static VOID
VtRedrawRows(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff, SHORT Top, SHORT Bottom)
{
    VtRedraw(FrontEnd, Buff, 0, Top, VtRight(Buff), Bottom);
}

/* The cursor moved from Old: show it, and keep it in the view */
static VOID
VtCursorMoved(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff, COORD Old)
{
    if (Old.X == Buff->CursorPosition.X && Old.Y == Buff->CursorPosition.Y) return;

    if (VtIsActive(FrontEnd, Buff))
        FrontEnd->Vtbl->SetScreenInfo(FrontEnd, (PCONSOLE_SCREEN_BUFFER)Buff, Old.X, Old.Y);
    else
        ConioVtFollowCursor(Buff);
}

/* The view origin, the buffer size or the whole contents changed */
static VOID
VtViewChanged(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff)
{
    if (!VtIsActive(FrontEnd, Buff)) return;

    FrontEnd->Vtbl->ResizeTerminal(FrontEnd);
    VtRedrawRows(FrontEnd, Buff, VtViewTop(Buff), VtViewBottom(Buff));
    FrontEnd->Vtbl->SetCursorInfo(FrontEnd, (PCONSOLE_SCREEN_BUFFER)Buff);
}

static BOOLEAN
VtRowIsBlank(PTEXTMODE_SCREEN_BUFFER Buff, SHORT Y)
{
    PCHAR_INFO Ptr = ConioCoordToPointer(Buff, 0, Y);
    SHORT X;

    for (X = 0; X < Buff->ScreenBufferSize.X; ++X, ++Ptr)
    {
        if (Ptr->Char.UnicodeChar != L' ' && Ptr->Char.UnicodeChar != UNICODE_NULL)
            return FALSE;
    }
    return TRUE;
}

/* ED 2: the view moves below the last line with text (scrolling the buffer if needed) and is cleared */
static VOID
VtEraseAll(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff)
{
    SHORT Height = min(Buff->ViewSize.Y, Buff->ScreenBufferSize.Y);
    SHORT OldTop = VtViewTop(Buff);
    LONG LastRow, NewTop, Overflow;
    WORD Attrib = Buff->ScreenDefaultAttrib;

    for (LastRow = Buff->ScreenBufferSize.Y - 1; LastRow > 0; --LastRow)
    {
        if (!VtRowIsBlank(Buff, (SHORT)LastRow)) break;
    }

    NewTop = LastRow + 1;
    Overflow = NewTop + Height - Buff->ScreenBufferSize.Y;
    if (Overflow > 0)
    {
        VtScrollBuffer(Buff, Overflow, Attrib);
        NewTop -= Overflow;
    }

    Buff->ViewOrigin.Y = (SHORT)NewTop;
    VtFillRows(Buff, VtViewTop(Buff), VtViewBottom(Buff), Attrib);

    /* The cursor keeps its place in the view */
    Buff->CursorPosition.Y = VtClamp(NewTop + (Buff->CursorPosition.Y - OldTop),
                                     VtViewTop(Buff), VtViewBottom(Buff));

    VtViewChanged(FrontEnd, Buff);
}

/* ED 3: the scrollback (all but the view) is erased; the view moves to the top of the buffer */
static VOID
VtEraseScrollback(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff)
{
    SHORT OldTop = VtViewTop(Buff);

    if (OldTop > 0)
    {
        Buff->VirtualY = (USHORT)((Buff->VirtualY + OldTop) % Buff->ScreenBufferSize.Y);
        Buff->CursorPosition.Y = max(Buff->CursorPosition.Y - OldTop, 0);
        Buff->ViewOrigin.Y = 0;
    }
    if (Buff->ViewSize.Y < Buff->ScreenBufferSize.Y)
        VtFillRows(Buff, Buff->ViewSize.Y, Buff->ScreenBufferSize.Y - 1, Buff->ScreenDefaultAttrib);

    VtViewChanged(FrontEnd, Buff);
}

static UCHAR
VtNearestColor(PCONSRV_CONSOLE Console, LONG R, LONG G, LONG B)
{
    UCHAR i, Best = 0;
    ULONG Distance, BestDistance = MAXULONG;

    for (i = 0; i < 16; ++i)
    {
        LONG dR = GetRValue(Console->Colors[i]) - R;
        LONG dG = GetGValue(Console->Colors[i]) - G;
        LONG dB = GetBValue(Console->Colors[i]) - B;

        /* Weighted for the eye's sensitivity */
        Distance = (ULONG)(2 * dR * dR + 4 * dG * dG + 3 * dB * dB);
        if (Distance < BestDistance)
        {
            BestDistance = Distance;
            Best = i;
        }
    }
    return Best;
}

/* Attribute color of entry Index of the 256-color palette */
static UCHAR
VtColorFrom256(PCONSRV_CONSOLE Console, USHORT Index)
{
    LONG R, G, B;

    if (Index < 8)
        return VtAnsiToAttrib[Index];
    if (Index < 16)
        return VtAnsiToAttrib[Index - 8] | FOREGROUND_INTENSITY;

    if (Index < 232)
    {
        /* 6x6x6 color cube */
        Index -= 16;
        R = Index / 36;
        G = (Index / 6) % 6;
        B = Index % 6;
        R = R ? 55 + R * 40 : 0;
        G = G ? 55 + G * 40 : 0;
        B = B ? 55 + B * 40 : 0;
    }
    else
    {
        /* Gray ramp */
        R = G = B = 8 + (Index - 232) * 10;
    }
    return VtNearestColor(Console, R, G, B);
}

/* SGR */
static VOID
VtSetGraphicsRendition(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff)
{
    PCONSOLE_VT_STATE Vt = &Buff->Vt;
    WORD Attrib = Buff->ScreenDefaultAttrib;
    WORD Default = Vt->DefaultAttrib;
    UCHAR Fore = Attrib & 0x0F, Back = (Attrib >> 4) & 0x0F;
    WORD Flags = Attrib & 0xFF00 & ~COMMON_LVB_SBCSDBCS;
    BOOLEAN Bold = Vt->Bold;
    UINT Count = min(Vt->NumParams, CONSOLE_VT_MAX_PARAMS);
    UINT i;
    ULONG ExtFore = Vt->ExtFore, ExtBack = Vt->ExtBack;

    /* Extended colors that the attribute lost (it was set by other means) are gone */
    if (ExtFore && CONSOLE_EXTCOLOR_SNAP(ExtFore) != (ULONG)(Fore & 0x0F)) ExtFore = 0;
    if (ExtBack && CONSOLE_EXTCOLOR_SNAP(ExtBack) != (ULONG)(Back & 0x0F)) ExtBack = 0;

    /* The intensity that bold added is not part of the color */
    if (Vt->Bold && Vt->BoldBright)
        Fore &= ~FOREGROUND_INTENSITY;

    /* No parameter is SGR 0 */
    if (Count == 0)
    {
        Vt->Params[0] = 0;
        Count = 1;
    }

    for (i = 0; i < Count; ++i)
    {
        USHORT Param = Vt->Params[i];

        if (Param >= 30 && Param <= 37)
        {
            Fore = VtAnsiToAttrib[Param - 30];
            ExtFore = 0;
        }
        else if (Param >= 40 && Param <= 47)
        {
            Back = VtAnsiToAttrib[Param - 40];
            ExtBack = 0;
        }
        else if (Param >= 90 && Param <= 97)
        {
            Fore = VtAnsiToAttrib[Param - 90] | FOREGROUND_INTENSITY;
            ExtFore = 0;
        }
        else if (Param >= 100 && Param <= 107)
        {
            Back = VtAnsiToAttrib[Param - 100] | FOREGROUND_INTENSITY;
            ExtBack = 0;
        }
        else switch (Param)
        {
        case 0:
            Fore  = Default & 0x0F;
            Back  = (Default >> 4) & 0x0F;
            Flags = 0;
            Bold  = FALSE;
            ExtFore = ExtBack = 0;
            break;
        case 1:  Bold = TRUE; break;
        case 22: Bold = FALSE; break;
        case 4:  Flags |= COMMON_LVB_UNDERSCORE; break;
        case 24: Flags &= ~COMMON_LVB_UNDERSCORE; break;
        case 7:  Flags |= COMMON_LVB_REVERSE_VIDEO; break;
        case 27: Flags &= ~COMMON_LVB_REVERSE_VIDEO; break;
        case 39: Fore = Default & 0x0F; ExtFore = 0; break;
        case 49: Back = (Default >> 4) & 0x0F; ExtBack = 0; break;

        case 38:
        case 48:
        {
            UCHAR Color;

            if (i + 2 < Count && Vt->Params[i + 1] == 5)
            {
                /* 38;5;N: 256-color palette; an index out of range is ignored */
                if (Vt->Params[i + 2] <= 255)
                {
                    ULONG Ext = 0;

                    Color = VtColorFrom256(FrontEnd->Console, Vt->Params[i + 2]);
                    /* The first 16 are the console colors; the others are kept exactly */
                    if (Vt->Params[i + 2] >= 16)
                        Ext = CONSOLE_EXTCOLOR_MAKE(CONSOLE_EXTCOLOR_INDEX, Vt->Params[i + 2], 0);
                    if (Param == 38) { Fore = Color; ExtFore = Ext; } else { Back = Color; ExtBack = Ext; }
                }
                i += 2;
            }
            else if (i + 4 < Count && Vt->Params[i + 1] == 2)
            {
                /* 38;2;R;G;B: 24-bit color */
                ULONG Ext = CONSOLE_EXTCOLOR_MAKE(CONSOLE_EXTCOLOR_RGB,
                                                  (min(Vt->Params[i + 2], 255) << 16) |
                                                  (min(Vt->Params[i + 3], 255) << 8) |
                                                  min(Vt->Params[i + 4], 255), 0);

                Color = VtNearestColor(FrontEnd->Console,
                                       min(Vt->Params[i + 2], 255),
                                       min(Vt->Params[i + 3], 255),
                                       min(Vt->Params[i + 4], 255));
                if (Param == 38) { Fore = Color; ExtFore = Ext; } else { Back = Color; ExtBack = Ext; }
                i += 4;
            }
            else
            {
                /* Incomplete: the rest of the sequence is not interpreted */
                i = Count;
            }
            break;
        }

        default:
            /* Renditions the console does not have (faint, italic, blink, ...) */
            break;
        }
    }

    Vt->Bold = Bold;
    Vt->BoldBright = (Bold && !(Fore & FOREGROUND_INTENSITY));
    if (Vt->BoldBright)
        Fore |= FOREGROUND_INTENSITY;

    Buff->ScreenDefaultAttrib = Flags | (Back << 4) | Fore;

    /* The extended colors are valid as long as the attribute keeps the colors they were made for */
    Vt->ExtFore = ExtFore ? CONSOLE_EXTCOLOR_MAKE(CONSOLE_EXTCOLOR_KIND(ExtFore), CONSOLE_EXTCOLOR_VALUE(ExtFore), Fore) : 0;
    Vt->ExtBack = ExtBack ? CONSOLE_EXTCOLOR_MAKE(CONSOLE_EXTCOLOR_KIND(ExtBack), CONSOLE_EXTCOLOR_VALUE(ExtBack), Back) : 0;
}

static VOID
VtSetTitle(PFRONTEND FrontEnd, PCWSTR Title, USHORT Length)
{
    PCONSRV_CONSOLE Console = FrontEnd->Console;
    PWCHAR Buffer;

    Buffer = ConsoleAllocHeap(HEAP_ZERO_MEMORY, (Length + 1) * sizeof(WCHAR));
    if (!Buffer) return;
    RtlCopyMemory(Buffer, Title, Length * sizeof(WCHAR));

    if (Console->Title.Buffer)
        ConsoleFreeHeap(Console->Title.Buffer);
    Console->Title.Buffer = Buffer;
    Console->Title.Length = Length * sizeof(WCHAR);
    Console->Title.MaximumLength = Console->Title.Length + sizeof(WCHAR);

    TermChangeTitle(Console);
}

/* Send a report (DSR, DA) to the console input, as typed characters */
static VOID
VtReport(PFRONTEND FrontEnd, PCWSTR Report)
{
    INPUT_RECORD Event;

    if (FrontEnd->Console->InputBuffer.NumberOfEvents > VT_REPORT_MAX_PENDING)
        return;

    RtlZeroMemory(&Event, sizeof(Event));
    Event.EventType = KEY_EVENT;
    Event.Event.KeyEvent.wRepeatCount = 1;

    for (; *Report; ++Report)
    {
        Event.Event.KeyEvent.uChar.UnicodeChar = *Report;
        Event.Event.KeyEvent.bKeyDown = TRUE;
        ConioProcessInputEvent(FrontEnd->Console, &Event);
        Event.Event.KeyEvent.bKeyDown = FALSE;
        ConioProcessInputEvent(FrontEnd->Console, &Event);
    }
}

static PWCHAR
VtFormatNumber(PWCHAR Out, ULONG Number)
{
    WCHAR Digits[10];
    UINT n = 0;

    do
    {
        Digits[n++] = L'0' + (WCHAR)(Number % 10);
        Number /= 10;
    } while (Number && n < ARRAYSIZE(Digits));
    while (n) *Out++ = Digits[--n];
    return Out;
}

static VOID
VtSaveCursor(PTEXTMODE_SCREEN_BUFFER Buff)
{
    Buff->Vt.SavedCursorValid = TRUE;
    Buff->Vt.SavedCursor.X = Buff->CursorPosition.X;
    Buff->Vt.SavedCursor.Y = Buff->CursorPosition.Y - VtViewTop(Buff);
}

static VOID
VtRestoreCursor(PTEXTMODE_SCREEN_BUFFER Buff)
{
    if (!Buff->Vt.SavedCursorValid)
    {
        Buff->CursorPosition.X = 0;
        Buff->CursorPosition.Y = VtViewTop(Buff);
        return;
    }
    Buff->CursorPosition.X = VtClamp(Buff->Vt.SavedCursor.X, 0, VtRight(Buff));
    Buff->CursorPosition.Y = VtClamp(VtViewTop(Buff) + Buff->Vt.SavedCursor.Y,
                                     VtViewTop(Buff), VtViewBottom(Buff));
}

/* RI: up one line; at the top of the scrolling region, the region scrolls down */
static VOID
VtReverseIndex(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff)
{
    SHORT Top, Bottom;

    VtRegion(Buff, Buff->CursorPosition.Y, &Top, &Bottom);
    if (Buff->CursorPosition.Y == Top)
    {
        VtScrollRows(Buff, Top, Bottom, -1, Buff->ScreenDefaultAttrib);
        VtRedrawRows(FrontEnd, Buff, Top, Bottom);
    }
    else if (Buff->CursorPosition.Y > VtViewTop(Buff))
    {
        Buff->CursorPosition.Y--;
    }
}

/* DECSET / DECRST 1049: the alternate screen buffer, of the size of the view */
static VOID
VtAlternateBuffer(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff, BOOLEAN Enable)
{
    PCONSOLE_VT_STATE Vt = &Buff->Vt;

    if (Enable)
    {
        COORD Size = Buff->ViewSize;
        PCHAR_INFO Cells;

        if (Vt->InAltBuffer)
        {
            /* Already there: start from a clean alternate screen */
            VtFillRows(Buff, 0, Buff->ScreenBufferSize.Y - 1, Buff->ScreenDefaultAttrib);
            Buff->CursorPosition.X = Buff->CursorPosition.Y = 0;
            VtViewChanged(FrontEnd, Buff);
            return;
        }

        Cells = ConsoleAllocHeap(0, Size.X * Size.Y * sizeof(CHAR_INFO));
        if (!Cells) return;

        Vt->AltMainExt        = Buff->ExtCells;
        Vt->AltMainExtCount   = Buff->ExtCount;
        Buff->ExtCells = NULL;
        Buff->ExtCount = 0;
        Vt->AltMainBuffer     = Buff->Buffer;
        Vt->AltMainSize       = Buff->ScreenBufferSize;
        Vt->AltMainVirtualY   = Buff->VirtualY;
        Vt->AltMainCursor     = Buff->CursorPosition;
        Vt->AltMainViewOrigin = Buff->ViewOrigin;
        Vt->InAltBuffer = TRUE;

        Buff->Buffer = Cells;
        Buff->ScreenBufferSize = Size;
        Buff->VirtualY = 0;
        Buff->ViewOrigin.X = Buff->ViewOrigin.Y = 0;
        Buff->CursorPosition.X = Buff->CursorPosition.Y = 0;
        VtFillRows(Buff, 0, Size.Y - 1, Buff->ScreenDefaultAttrib);
    }
    else
    {
        if (!Vt->InAltBuffer) return;

        ConsoleFreeHeap(Buff->Buffer);
        ConioFreeExtra(Buff, Buff->ExtCells, (SIZE_T)Buff->ExtCount * sizeof(CONSOLE_EXT_CELL));
        Buff->ExtCells         = Vt->AltMainExt;
        Buff->ExtCount         = Vt->AltMainExtCount;
        Vt->AltMainExt = NULL;
        Vt->AltMainExtCount = 0;
        Buff->Buffer           = Vt->AltMainBuffer;
        Buff->ScreenBufferSize = Vt->AltMainSize;
        Buff->VirtualY         = Vt->AltMainVirtualY;
        Buff->CursorPosition   = Vt->AltMainCursor;
        Buff->ViewOrigin       = Vt->AltMainViewOrigin;
        Vt->AltMainBuffer = NULL;
        Vt->InAltBuffer = FALSE;

        /* The view may have been resized meanwhile: keep it in the main buffer */
        Buff->ViewSize.X = min(Buff->ViewSize.X, Buff->ScreenBufferSize.X);
        Buff->ViewSize.Y = min(Buff->ViewSize.Y, Buff->ScreenBufferSize.Y);
        Buff->ViewOrigin.X = VtClamp(Buff->ViewOrigin.X, 0, Buff->ScreenBufferSize.X - Buff->ViewSize.X);
        Buff->ViewOrigin.Y = VtClamp(Buff->ViewOrigin.Y, 0, Buff->ScreenBufferSize.Y - Buff->ViewSize.Y);
        Buff->CursorPosition.X = VtClamp(Buff->CursorPosition.X, 0, Buff->ScreenBufferSize.X - 1);
        Buff->CursorPosition.Y = VtClamp(Buff->CursorPosition.Y, 0, Buff->ScreenBufferSize.Y - 1);
    }

    Vt->MarginsSet = FALSE;
    Vt->DelayedWrap = FALSE;
    VtViewChanged(FrontEnd, Buff);
}

static VOID
VtSetCursorVisible(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff, BOOLEAN Visible)
{
    if (!!Buff->CursorInfo.bVisible == Visible) return;
    Buff->CursorInfo.bVisible = Visible;
    if (VtIsActive(FrontEnd, Buff))
        FrontEnd->Vtbl->SetCursorInfo(FrontEnd, (PCONSOLE_SCREEN_BUFFER)Buff);
}

/* DECSTR (soft reset) */
static VOID
VtSoftReset(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff)
{
    Buff->ScreenDefaultAttrib = Buff->Vt.DefaultAttrib;
    Buff->Vt.ExtFore = Buff->Vt.ExtBack = 0;
    Buff->Vt.Bold = Buff->Vt.BoldBright = FALSE;
    Buff->Vt.DecGraphics = FALSE;
    Buff->Vt.MarginsSet = FALSE;
    Buff->Vt.SavedCursorValid = FALSE;
    FrontEnd->Console->InputBuffer.VtCursorKeysApp = FALSE;
    VtSetCursorVisible(FrontEnd, Buff, TRUE);
}

/* RIS (full reset): also leaves the alternate buffer and clears everything */
static VOID
VtFullReset(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff)
{
    VtAlternateBuffer(FrontEnd, Buff, FALSE);
    VtSoftReset(FrontEnd, Buff);
    VtFillRows(Buff, 0, Buff->ScreenBufferSize.Y - 1, Buff->ScreenDefaultAttrib);
    Buff->CursorPosition.X = Buff->CursorPosition.Y = 0;
    Buff->ViewOrigin.X = Buff->ViewOrigin.Y = 0;
    VtViewChanged(FrontEnd, Buff);
}

static VOID
VtDispatchEscape(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff, WCHAR Final)
{
    PCONSOLE_VT_STATE Vt = &Buff->Vt;
    COORD Old = Buff->CursorPosition;

    if (Vt->Intermediate == L'(')
    {
        /* Designate G0: DEC special graphics, or back to ASCII */
        if (Final == L'0') Vt->DecGraphics = TRUE;
        else if (Final == L'B') Vt->DecGraphics = FALSE;
        return;
    }
    if (Vt->Intermediate != 0)
        return;

    switch (Final)
    {
    case L'7': /* DECSC */
        VtSaveCursor(Buff);
        return;
    case L'8': /* DECRC */
        Vt->DelayedWrap = FALSE;
        VtRestoreCursor(Buff);
        break;
    case L'M': /* RI */
        Vt->DelayedWrap = FALSE;
        VtReverseIndex(FrontEnd, Buff);
        break;
    /*
     * Simple cursor positioning, as measured on Windows 10: ESC D moves the
     * cursor left (it is not IND) and ESC E does nothing (it is not NEL).
     */
    case L'A':
        Vt->DelayedWrap = FALSE;
        Buff->CursorPosition.Y = max(Buff->CursorPosition.Y - 1, VtViewTop(Buff));
        break;
    case L'B':
        Vt->DelayedWrap = FALSE;
        Buff->CursorPosition.Y = min(Buff->CursorPosition.Y + 1, VtViewBottom(Buff));
        break;
    case L'C':
        Vt->DelayedWrap = FALSE;
        Buff->CursorPosition.X = min(Buff->CursorPosition.X + 1, VtRight(Buff));
        break;
    case L'D':
        Vt->DelayedWrap = FALSE;
        Buff->CursorPosition.X = max(Buff->CursorPosition.X - 1, 0);
        break;
    case L'c': /* RIS */
        Vt->DelayedWrap = FALSE;
        VtFullReset(FrontEnd, Buff);
        return;
    default:
        /* DECKPAM, DECKPNM, HTS, ...: nothing to do for the output */
        return;
    }
    VtCursorMoved(FrontEnd, Buff, Old);
}

static VOID
VtDispatchPrivateMode(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff, BOOLEAN Set)
{
    PCONSOLE_VT_STATE Vt = &Buff->Vt;
    UINT Count = min(Vt->NumParams, CONSOLE_VT_MAX_PARAMS);
    UINT i;

    for (i = 0; i < Count; ++i)
    {
        switch (Vt->Params[i])
        {
        case 1:     /* DECCKM: application cursor keys, for ENABLE_VIRTUAL_TERMINAL_INPUT */
            FrontEnd->Console->InputBuffer.VtCursorKeysApp = Set;
            break;
        case 25:    /* DECTCEM: cursor visibility */
            VtSetCursorVisible(FrontEnd, Buff, Set);
            break;
        case 1049:  /* Alternate screen buffer */
            VtAlternateBuffer(FrontEnd, Buff, Set);
            break;
        default:
            /* Cursor keys, blinking, columns, mouse, ...: not for the output */
            break;
        }
    }
}

/* Number of parameters a CSI function takes (empty ones count) */
static UCHAR
VtMaxParams(WCHAR Final)
{
    switch (Final)
    {
    case L'm':
        /* SGR uses the first 16 and ignores the others */
        return 0xFF;
    case L'H':
    case L'f':
    case L'r':
        return 2;
    case L's':
    case L'u':
        return 0;
    default:
        return 1;
    }
}

static VOID
VtDispatchCsi(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff, WCHAR Final)
{
    PCONSOLE_VT_STATE Vt = &Buff->Vt;
    COORD Old = Buff->CursorPosition;
    SHORT Top = VtViewTop(Buff), Bottom = VtViewBottom(Buff), Right = VtRight(Buff);
    SHORT X = Buff->CursorPosition.X, Y = Buff->CursorPosition.Y;
    SHORT RegionTop, RegionBottom;
    WORD Attrib = Buff->ScreenDefaultAttrib;
    USHORT n;

    if (Vt->Private == L'?')
    {
        if (Vt->Intermediate == 0 && (Final == L'h' || Final == L'l'))
            VtDispatchPrivateMode(FrontEnd, Buff, (Final == L'h'));
        return;
    }
    if (Vt->Private != 0)
        return;

    if (Vt->Intermediate == L'!')
    {
        if (Final == L'p') VtSoftReset(FrontEnd, Buff);
        return;
    }
    if (Vt->Intermediate != 0)
        return;

    /* As on Windows, a sequence with more parameters than its function takes is ignored */
    if (Vt->NumParams > VtMaxParams(Final))
        return;

    switch (Final)
    {
    case L'm': /* SGR */
        VtSetGraphicsRendition(FrontEnd, Buff);
        return;

    case L'A': /* CUU: up, stopping at the top margin when inside the scrolling region */
    case L'F': /* CPL */
        n = VtParam(Vt, 0, 1);
        if (VtRegion(Buff, Y, &RegionTop, &RegionBottom)) Top = RegionTop;
        Buff->CursorPosition.Y = (Y < Top) ? Y : VtClamp((LONG)Y - n, Top, Bottom);
        if (Final == L'F') Buff->CursorPosition.X = 0;
        break;

    case L'B': /* CUD */
    case L'E': /* CNL */
        n = VtParam(Vt, 0, 1);
        if (VtRegion(Buff, Y, &RegionTop, &RegionBottom)) Bottom = RegionBottom;
        Buff->CursorPosition.Y = (Y > Bottom) ? Y : VtClamp((LONG)Y + n, Top, Bottom);
        if (Final == L'E') Buff->CursorPosition.X = 0;
        break;

    case L'C': /* CUF */
        Buff->CursorPosition.X = VtClamp((LONG)X + VtParam(Vt, 0, 1), 0, Right);
        break;

    case L'D': /* CUB */
        Buff->CursorPosition.X = VtClamp((LONG)X - VtParam(Vt, 0, 1), 0, Right);
        break;

    case L'G': /* CHA */
        Buff->CursorPosition.X = VtClamp((LONG)VtParam(Vt, 0, 1) - 1, 0, Right);
        break;

    case L'd': /* VPA */
        Buff->CursorPosition.Y = VtClamp((LONG)Top + VtParam(Vt, 0, 1) - 1, Top, Bottom);
        break;

    case L'H': /* CUP */
    case L'f': /* HVP */
        Buff->CursorPosition.Y = VtClamp((LONG)Top + VtParam(Vt, 0, 1) - 1, Top, Bottom);
        Buff->CursorPosition.X = VtClamp((LONG)VtParam(Vt, 1, 1) - 1, 0, Right);
        break;

    case L'I': /* CHT */
        for (n = VtParam(Vt, 0, 1); n > 0 && X < Right; --n)
            X = min((X + VT_TAB_WIDTH) & ~(VT_TAB_WIDTH - 1), Right);
        Buff->CursorPosition.X = X;
        break;

    case L'Z': /* CBT */
        for (n = VtParam(Vt, 0, 1); n > 0 && X > 0; --n)
            X = ((X - 1) / VT_TAB_WIDTH) * VT_TAB_WIDTH;
        Buff->CursorPosition.X = X;
        break;

    case L'J': /* ED */
        switch (VtParam(Vt, 0, 0))
        {
        case 0:
            VtFillCells(Buff, X, Y, Right - X + 1, Attrib);
            VtFillRows(Buff, (SHORT)(max(Y, Top - 1) + 1), Bottom, Attrib);
            VtRedrawRows(FrontEnd, Buff, Y, Bottom);
            break;
        case 1:
            VtFillRows(Buff, Top, (SHORT)(min(Y, Bottom + 1) - 1), Attrib);
            VtFillCells(Buff, 0, Y, X + 1, Attrib);
            VtRedrawRows(FrontEnd, Buff, Top, Y);
            break;
        case 2:
            VtEraseAll(FrontEnd, Buff);
            break;
        case 3:
            VtEraseScrollback(FrontEnd, Buff);
            break;
        }
        break;

    case L'K': /* EL */
        switch (VtParam(Vt, 0, 0))
        {
        case 0: VtFillCells(Buff, X, Y, Right - X + 1, Attrib); break;
        case 1: VtFillCells(Buff, 0, Y, X + 1, Attrib); break;
        case 2: VtFillCells(Buff, 0, Y, Right + 1, Attrib); break;
        }
        VtRedrawRows(FrontEnd, Buff, Y, Y);
        break;

    case L'X': /* ECH */
        VtFillCells(Buff, X, Y, VtParam(Vt, 0, 1), Attrib);
        VtRedraw(FrontEnd, Buff, X, Y, Right, Y);
        break;

    case L'@': /* ICH */
    case L'P': /* DCH */
    {
        PCHAR_INFO Row = ConioCoordToPointer(Buff, 0, Y);
        LONG Count = min(VtParam(Vt, 0, 1), Right - X + 1);
        LONG Moved = Right - X + 1 - Count;

        if (Final == L'@')
        {
            RtlMoveMemory(&Row[X + Count], &Row[X], Moved * sizeof(CHAR_INFO));
            ConioMoveExt(Buff, &Row[X + Count], &Row[X], Moved);
            VtFillCells(Buff, X, Y, Count, Attrib);
        }
        else
        {
            RtlMoveMemory(&Row[X], &Row[X + Count], Moved * sizeof(CHAR_INFO));
            ConioMoveExt(Buff, &Row[X], &Row[X + Count], Moved);
            VtFillCells(Buff, (SHORT)(X + Moved), Y, Count, Attrib);
        }
        VtRedraw(FrontEnd, Buff, X, Y, Right, Y);
        break;
    }

    case L'L': /* IL */
    case L'M': /* DL */
        if (!VtRegion(Buff, Y, &RegionTop, &RegionBottom))
            return;
        n = VtParam(Vt, 0, 1);
        VtScrollRows(Buff, Y, RegionBottom, (Final == L'L') ? -(LONG)n : (LONG)n, Attrib);
        VtRedrawRows(FrontEnd, Buff, Y, RegionBottom);
        Buff->CursorPosition.X = 0;
        break;

    case L'S': /* SU */
    case L'T': /* SD */
        VtRegion(Buff, Y, &RegionTop, &RegionBottom);
        n = VtParam(Vt, 0, 1);
        VtScrollRows(Buff, RegionTop, RegionBottom, (Final == L'S') ? (LONG)n : -(LONG)n, Attrib);
        VtRedrawRows(FrontEnd, Buff, RegionTop, RegionBottom);
        return;

    case L'b': /* REP: repeat the last printed character */
        if (Vt->LastChar)
        {
            WCHAR Chars[64];
            /* More than a view of repetitions would only scroll it off */
            ULONG Left = min((ULONG)VtParam(Vt, 0, 1),
                             (ULONG)Buff->ScreenBufferSize.X * Buff->ViewSize.Y);
            UINT i;

            for (i = 0; i < ARRAYSIZE(Chars); ++i) Chars[i] = Vt->LastChar;
            while (Left)
            {
                ULONG Chunk = min(Left, ARRAYSIZE(Chars));
                ConioWriteText(FrontEnd, Buff, Chars, Chunk, TRUE, TRUE);
                Left -= Chunk;
            }
        }
        return;

    case L'r': /* DECSTBM */
    {
        USHORT Height = Buff->ViewSize.Y;
        USHORT MarginTop = VtParam(Vt, 0, 1), MarginBottom = VtParam(Vt, 1, Height);

        if (MarginTop >= MarginBottom || MarginBottom > Height)
            return;
        Vt->MarginsSet = !(MarginTop == 1 && MarginBottom == Height);
        Vt->MarginTop = MarginTop - 1;
        Vt->MarginBottom = MarginBottom - 1;
        /* The cursor goes home */
        Buff->CursorPosition.X = 0;
        Buff->CursorPosition.Y = Top;
        break;
    }

    case L's': /* SCP */
        VtSaveCursor(Buff);
        return;

    case L'u': /* RCP */
        VtRestoreCursor(Buff);
        break;

    case L'n': /* DSR */
        if (VtParam(Vt, 0, 0) == 6)
        {
            WCHAR Report[32], *p = Report;
            *p++ = VT_ESC; *p++ = L'[';
            p = VtFormatNumber(p, max(Y - Top + 1, 1));
            *p++ = L';';
            p = VtFormatNumber(p, X + 1);
            *p++ = L'R'; *p = UNICODE_NULL;
            VtReport(FrontEnd, Report);
        }
        return;

    case L'c': /* DA */
        if (VtParam(Vt, 0, 0) == 0)
        {
            static const WCHAR DeviceAttributes[] = { VT_ESC, L'[', L'?', L'1', L';', L'0', L'c', 0 };
            VtReport(FrontEnd, DeviceAttributes);
        }
        return;

    default:
        /* Not supported: ignored */
        return;
    }

    Vt->DelayedWrap = FALSE;
    VtCursorMoved(FrontEnd, Buff, Old);
}

static VOID
VtDispatchOsc(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff)
{
    PCONSOLE_VT_STATE Vt = &Buff->Vt;

    /* OSC 0, 1, 2: window title; an empty title changes nothing */
    if (Vt->OscHasCommand && Vt->OscCommand <= 2 && Vt->OscLength > 0)
        VtSetTitle(FrontEnd, Vt->OscString, Vt->OscLength);
}

static VOID
VtEnter(PCONSOLE_VT_STATE Vt, UCHAR State)
{
    Vt->State = State;
    if (State == VT_ESCAPE || State == VT_CSI_PARAM)
    {
        Vt->Private = Vt->Intermediate = 0;
        Vt->NumParams = 0;
        RtlZeroMemory(Vt->Params, sizeof(Vt->Params));
    }
    else if (State == VT_OSC)
    {
        Vt->OscCommand = 0;
        Vt->OscLength = 0;
        Vt->OscHasCommand = FALSE;
    }
}

/* Handle a character that is part of a sequence */
static VOID
VtProcessChar(PFRONTEND FrontEnd, PTEXTMODE_SCREEN_BUFFER Buff, WCHAR Char, BOOL Attrib)
{
    PCONSOLE_VT_STATE Vt = &Buff->Vt;

    /* An escape starts a new sequence, or terminates an OSC string (ESC \) */
    if (Char == VT_ESC)
    {
        if (Vt->State == VT_OSC)
            Vt->State = VT_OSC_ESC;
        else
            VtEnter(Vt, VT_ESCAPE);
        return;
    }

    switch (Vt->State)
    {
    case VT_OSC_ESC:
        if (Char == L'\\')
        {
            VtDispatchOsc(FrontEnd, Buff);
            Vt->State = VT_GROUND;
            return;
        }
        /* The string is abandoned; this is an escape sequence */
        VtEnter(Vt, VT_ESCAPE);
        break;

    case VT_OSC:
        /*
         * As on Windows, the string goes on until BEL or ST, also over later
         * writes and other processes' output; CAN and SUB cancel it.
         */
        if (Char == VT_BEL || Char == VT_ST)
        {
            VtDispatchOsc(FrontEnd, Buff);
            Vt->State = VT_GROUND;
        }
        else if (Char == VT_CAN || Char == VT_SUB)
        {
            Vt->State = VT_GROUND;
            ConioWriteText(FrontEnd, Buff, &Char, 1, Attrib, TRUE);
        }
        else if (Char >= 0x20)
        {
            if (!Vt->OscHasCommand)
            {
                if (Char >= L'0' && Char <= L'9')
                    Vt->OscCommand = (USHORT)min(Vt->OscCommand * 10 + (Char - L'0'), 9999);
                else if (Char == L';')
                    Vt->OscHasCommand = TRUE;
                else
                {
                    Vt->OscCommand = VT_OSC_INVALID;
                    Vt->OscHasCommand = TRUE;
                }
            }
            else if (Vt->OscLength < CONSOLE_VT_MAX_OSC)
            {
                Vt->OscString[Vt->OscLength++] = Char;
            }
        }
        return;
    }

    /* Escape and control sequences */
    if (Char == VT_CAN || Char == VT_SUB)
    {
        /* Cancel the sequence; the character itself is output */
        Vt->State = VT_GROUND;
        ConioWriteText(FrontEnd, Buff, &Char, 1, Attrib, TRUE);
        return;
    }
    if (Char < 0x20)
    {
        /* Control characters are executed in the middle of a sequence */
        ConioWriteText(FrontEnd, Buff, &Char, 1, Attrib, TRUE);
        return;
    }
    if (Char == 0x7F)
        return;
    if (Char >= 0x80 && Char <= 0x9F)
    {
        /* A C1 control (8-bit CSI included) cancels the sequence and is dropped, as on Windows */
        Vt->State = VT_GROUND;
        return;
    }
    if (Char > 0x7E)
    {
        /* Not part of a sequence: cancel it and output the character */
        Vt->State = VT_GROUND;
        ConioWriteText(FrontEnd, Buff, &Char, 1, Attrib, TRUE);
        return;
    }

    switch (Vt->State)
    {
    case VT_ESCAPE:
        if (Char == L'[')
            VtEnter(Vt, VT_CSI_PARAM);
        else if (Char == L']')
            VtEnter(Vt, VT_OSC);
        else if (Char < 0x30)
        {
            Vt->Intermediate = (UCHAR)Char;
            Vt->State = VT_ESCAPE_INTER;
        }
        else
        {
            Vt->State = VT_GROUND;
            VtDispatchEscape(FrontEnd, Buff, Char);
        }
        break;

    case VT_ESCAPE_INTER:
        if (Char < 0x30)
        {
            Vt->Intermediate = (UCHAR)Char;
        }
        else
        {
            Vt->State = VT_GROUND;
            VtDispatchEscape(FrontEnd, Buff, Char);
        }
        break;

    case VT_CSI_PARAM:
        if (Char >= L'0' && Char <= L'9')
        {
            if (Vt->NumParams == 0) Vt->NumParams = 1;
            if (Vt->NumParams <= CONSOLE_VT_MAX_PARAMS)
            {
                PUSHORT Param = &Vt->Params[Vt->NumParams - 1];
                *Param = (USHORT)min(*Param * 10 + (Char - L'0'), VT_MAX_PARAM);
            }
        }
        else if (Char == L';')
        {
            if (Vt->NumParams == 0) Vt->NumParams = 1;
            if (Vt->NumParams <= CONSOLE_VT_MAX_PARAMS) Vt->NumParams++;
        }
        else if (Char == L':')
        {
            /* Sub-parameters are not supported: the sequence is ignored */
            Vt->State = VT_CSI_IGNORE;
        }
        else if (Char >= L'<' && Char <= L'?')
        {
            if (Vt->NumParams == 0 && Vt->Private == 0)
                Vt->Private = (UCHAR)Char;
            else
                Vt->State = VT_CSI_IGNORE;
        }
        else if (Char < 0x30)
        {
            Vt->Intermediate = (UCHAR)Char;
            Vt->State = VT_CSI_INTER;
        }
        else
        {
            Vt->State = VT_GROUND;
            VtDispatchCsi(FrontEnd, Buff, Char);
        }
        break;

    case VT_CSI_INTER:
        if (Char < 0x30)
            Vt->Intermediate = (UCHAR)Char;
        else if (Char < 0x40)
            Vt->State = VT_CSI_IGNORE;
        else
        {
            Vt->State = VT_GROUND;
            VtDispatchCsi(FrontEnd, Buff, Char);
        }
        break;

    case VT_CSI_IGNORE:
        if (Char >= 0x40)
            Vt->State = VT_GROUND;
        break;

    default:
        Vt->State = VT_GROUND;
        break;
    }
}

/* PUBLIC FUNCTIONS ***********************************************************/

/* A character of the DEC special graphics set, when it is designated */
WCHAR
ConioVtTranslateChar(PTEXTMODE_SCREEN_BUFFER Buff, WCHAR Char)
{
    if (Buff->Vt.DecGraphics && Char >= 0x5F && Char <= 0x7E)
        return VtDecGraphics[Char - 0x5F];
    return Char;
}

/*
 * A line feed on the bottom line of the scrolling region scrolls the region
 * up. Returns FALSE if there is no region or the cursor is not on its bottom
 * line: the line feed is then the usual one.
 */
BOOLEAN
ConioVtLineFeedInRegion(PTEXTMODE_SCREEN_BUFFER Buff, PSMALL_RECT UpdateRect)
{
    SHORT Top, Bottom;

    if (!Buff->Vt.MarginsSet)
        return FALSE;
    if (!VtRegion(Buff, Buff->CursorPosition.Y, &Top, &Bottom) || Buff->CursorPosition.Y != Bottom ||
        (Top == VtViewTop(Buff) && Bottom == VtViewBottom(Buff)))
    {
        return FALSE;
    }

    VtScrollRows(Buff, Top, Bottom, 1, Buff->ScreenDefaultAttrib);

    UpdateRect->Left   = 0;
    UpdateRect->Right  = VtRight(Buff);
    UpdateRect->Top    = min(UpdateRect->Top, Top);
    UpdateRect->Bottom = max(UpdateRect->Bottom, Bottom);
    return TRUE;
}

/*
 * Bring the cursor into the view of a buffer that is not shown, as the
 * frontend does for the active one (GuiShowCursorInView).
 */
VOID
ConioVtFollowCursor(PTEXTMODE_SCREEN_BUFFER Buff)
{
    COORD Origin = Buff->ViewOrigin;

    if (Buff->CursorPosition.X < Origin.X)
        Origin.X = Buff->CursorPosition.X;
    else if (Buff->CursorPosition.X >= Origin.X + Buff->ViewSize.X)
        Origin.X = Buff->CursorPosition.X - Buff->ViewSize.X + 1;

    if (Buff->CursorPosition.Y < Origin.Y)
        Origin.Y = Buff->CursorPosition.Y;
    else if (Buff->CursorPosition.Y >= Origin.Y + Buff->ViewSize.Y)
        Origin.Y = Buff->CursorPosition.Y - Buff->ViewSize.Y + 1;

    Buff->ViewOrigin = Origin;
}

/*
 * WriteConsole / WriteFile to a buffer in virtual terminal mode: the text
 * between the sequences goes to ConioWriteText, the sequences are executed.
 */
NTSTATUS
ConioVtWriteConsole(PFRONTEND FrontEnd,
                    PTEXTMODE_SCREEN_BUFFER Buff,
                    PWCHAR Buffer,
                    DWORD Length,
                    BOOL Attrib)
{
    PCONSOLE_VT_STATE Vt = &Buff->Vt;
    DWORD i, Start = 0;

    for (i = 0; i < Length; i++)
    {
        WCHAR Char = Buffer[i];

        if (Vt->State == VT_GROUND)
        {
            /* Text: collected and written together */
            if (Char != VT_ESC && Char != VT_CSI)
                continue;

            if (i > Start)
                ConioWriteText(FrontEnd, Buff, &Buffer[Start], i - Start, Attrib, TRUE);
            VtEnter(Vt, (Char == VT_ESC) ? VT_ESCAPE : VT_CSI_PARAM);
        }
        else
        {
            VtProcessChar(FrontEnd, Buff, Char, Attrib);
        }
        Start = i + 1;
    }

    if (Length > Start)
        ConioWriteText(FrontEnd, Buff, &Buffer[Start], Length - Start, Attrib, TRUE);

    return STATUS_SUCCESS;
}

/* EOF */
