/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Console Server DLL
 * FILE:            win32ss/user/winsrv/consrv/frontends/gui/text.c
 * PURPOSE:         GUI Terminal Front-End - Support for text-mode screen-buffers
 * PROGRAMMERS:     Gé van Geldorp
 *                  Johannes Anderwald
 *                  Jeffrey Morlan
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

/* INCLUDES *******************************************************************/

#include <consrv.h>

#define NDEBUG
#include <debug.h>

#include "guiterm.h"

/* GLOBALS ********************************************************************/

#define IS_WHITESPACE(c)    ((c) == L'\0' || (c) == L' ' || (c) == L'\t')

/* FUNCTIONS ******************************************************************/

static COLORREF
PaletteRGBFromAttrib(PCONSRV_CONSOLE Console, WORD Attribute)
{
    HPALETTE hPalette = Console->ActiveBuffer->PaletteHandle;
    PALETTEENTRY pe;

    if (hPalette == NULL) return RGBFromAttrib(Console, Attribute);

    GetPaletteEntries(hPalette, Attribute, 1, &pe);
    return PALETTERGB(pe.peRed, pe.peGreen, pe.peBlue);
}

static HANDLE
CopyBlock(PTEXTMODE_SCREEN_BUFFER Buffer,
          PSMALL_RECT Selection)
{
    /*
     * Pressing the Shift key while copying text, allows us to copy
     * text without newline characters (inline-text copy mode).
     */
    BOOL InlineCopyMode = !!(GetKeyState(VK_SHIFT) & KEY_PRESSED);

    HANDLE hData;
    PCHAR_INFO ptr;
    LPWSTR data, dstPos;
    ULONG selWidth, selHeight;
    ULONG xPos, yPos;
    ULONG size;

    DPRINT("CopyBlock(%u, %u, %u, %u)\n",
           Selection->Left, Selection->Top, Selection->Right, Selection->Bottom);

    /* Prevent against empty blocks */
    if ((Selection == NULL) || ConioIsRectEmpty(Selection))
        return NULL;

    selWidth  = ConioRectWidth(Selection);
    selHeight = ConioRectHeight(Selection);

    /* Basic size for one line... */
    size = selWidth;
    /* ... and for the other lines, add newline characters if needed. */
    if (selHeight > 0)
    {
        /*
         * If we are not in inline-text copy mode, each selected line must
         * finish with \r\n . Otherwise, the lines will be just concatenated.
         */
        size += (selWidth + (!InlineCopyMode ? 2 : 0)) * (selHeight - 1);
    }
    else
    {
        DPRINT1("This case must never happen, because selHeight is at least == 1\n");
    }

    size++; /* Null-termination */
    size *= sizeof(WCHAR);

    /* Allocate some memory area to be given to the clipboard, so it will not be freed here */
    hData = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size);
    if (hData == NULL) return NULL;

    data = GlobalLock(hData);
    if (data == NULL)
    {
        GlobalFree(hData);
        return NULL;
    }

    DPRINT("Copying %dx%d selection\n", selWidth, selHeight);
    dstPos = data;

    for (yPos = 0; yPos < selHeight; yPos++)
    {
        ULONG length = selWidth;

        ptr = ConioCoordToPointer(Buffer,
                                  Selection->Left,
                                  Selection->Top + yPos);

        /* Trim whitespace from the right */
        while (length > 0)
        {
            if (IS_WHITESPACE(ptr[length-1].Char.UnicodeChar))
                --length;
            else
                break;
        }

        /* Copy only the characters, leave attributes alone */
        for (xPos = 0; xPos < length; xPos++)
        {
            /*
             * Sometimes, applications can put NULL chars into the screen-buffer
             * (this behaviour is allowed). Detect this and replace by a space.
             * For full-width characters: copy only the character specified
             * in the leading-byte cell, skipping the trailing-byte cell.
             */
            if (!(ptr[xPos].Attributes & COMMON_LVB_TRAILING_BYTE))
            {
                *dstPos++ = (ptr[xPos].Char.UnicodeChar ? ptr[xPos].Char.UnicodeChar : L' ');
            }
        }

        /* Add newline characters if we are not in inline-text copy mode */
        if (!InlineCopyMode)
        {
            if (yPos != (selHeight - 1))
            {
                wcscat(dstPos, L"\r\n");
                dstPos += 2;
            }
        }
    }

    DPRINT("Copied <%S>\n", data);
    GlobalUnlock(hData);
    return hData;
}

static HANDLE
CopyLines(PTEXTMODE_SCREEN_BUFFER Buffer,
          PCOORD Begin,
          PCOORD End,
          BOOL NoTrim)
{
    HANDLE hData;
    PCHAR_INFO ptr;
    LPWSTR data, dstPos;
    ULONG Width, Rows, size;
    ULONG xPos, yPos, xBeg, xEnd, length;

    DPRINT("CopyLines((%u, %u) ; (%u, %u))\n",
           Begin->X, Begin->Y, End->X, End->Y);

    /* Prevent against empty blocks... */
    if (Begin == NULL || End == NULL) return NULL;
    /* ... or malformed blocks */
    if (Begin->Y > End->Y || (Begin->Y == End->Y && Begin->X > End->X)) return NULL;
    if (Begin->X < 0 || End->X < 0 || Begin->Y < 0 ||
        End->Y >= Buffer->ScreenBufferSize.Y || Begin->X >= Buffer->ScreenBufferSize.X ||
        End->X >= Buffer->ScreenBufferSize.X)
        return NULL;

    Width = Buffer->ScreenBufferSize.X;
    Rows  = End->Y - Begin->Y + 1;

    /* At most a full row and a line break per row, and the NUL */
    size = (Rows * (Width + 2) + 1) * sizeof(WCHAR);

    /* Allocate some memory area to be given to the clipboard, so it will not be freed here */
    hData = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size);
    if (hData == NULL) return NULL;

    data = GlobalLock(hData);
    if (data == NULL)
    {
        GlobalFree(hData);
        return NULL;
    }

    dstPos = data;

    /*
     * Walk per row, as the selection follows the line wraps like text: the blanks
     * that end a row are not copied, and a row break is a line break unless the
     * row is filled up to the right edge (the text goes on in the next row).
     */
    for (yPos = Begin->Y; yPos <= (ULONG)End->Y; yPos++)
    {
        xBeg = (yPos == (ULONG)Begin->Y ? Begin->X : 0);
        xEnd = (yPos == (ULONG)End->Y   ? End->X   : Width - 1);

        ptr = ConioCoordToPointer(Buffer, 0, yPos);

        /* Trim whitespace from the right */
        length = xEnd - xBeg + 1;
        while (!NoTrim && length > 0 && IS_WHITESPACE(ptr[xBeg + length - 1].Char.UnicodeChar))
            --length;

        /* Copy only the characters, leave attributes alone */
        for (xPos = xBeg; xPos < xBeg + length; xPos++)
        {
            /*
             * Sometimes, applications can put NULL chars into the screen-buffer
             * (this behaviour is allowed). Detect this and replace by a space.
             * For full-width characters: copy only the character specified
             * in the leading-byte cell, skipping the trailing-byte cell.
             */
            if (!(ptr[xPos].Attributes & COMMON_LVB_TRAILING_BYTE))
            {
                *dstPos++ = (ptr[xPos].Char.UnicodeChar ? ptr[xPos].Char.UnicodeChar : L' ');
            }
        }

        if (yPos != (ULONG)End->Y)
        {
            BOOL Wrapped = (xEnd == Width - 1) &&
                           !IS_WHITESPACE(ptr[Width - 1].Char.UnicodeChar);
            if (!Wrapped)
            {
                *dstPos++ = L'\r';
                *dstPos++ = L'\n';
            }
        }
    }
    *dstPos = UNICODE_NULL;

    DPRINT("Copied <%S>\n", data);
    GlobalUnlock(hData);
    return hData;
}


VOID
PasteText(
    IN PCONSRV_CONSOLE Console,
    IN PWCHAR Buffer,
    IN SIZE_T cchSize)
{
    USHORT VkKey; // MAKEWORD(low = vkey_code, high = shift_state);
    INPUT_RECORD er;
    WCHAR CurChar = 0;

    /* Do nothing if we have nothing to paste */
    if (!Buffer || (cchSize <= 0))
        return;

    er.EventType = KEY_EVENT;
    er.Event.KeyEvent.wRepeatCount = 1;
    while (cchSize--)
    {
        /* \r or \n characters. Go to the line only if we get "\r\n" sequence. */
        if (CurChar == L'\r' && *Buffer == L'\n')
        {
            ++Buffer;
            continue;
        }
        CurChar = *Buffer++;

        /* Get the key code (+ shift state) corresponding to the character */
        VkKey = VkKeyScanW(CurChar);
        if (VkKey == 0xFFFF)
        {
            DPRINT1("FIXME: TODO: VkKeyScanW failed - Should simulate the key!\n");
            /*
             * We don't really need the scan/key code because we actually only
             * use the UnicodeChar for output purposes. It may pose few problems
             * later on but it's not of big importance. One trick would be to
             * convert the character to OEM / multibyte and use MapVirtualKey()
             * on each byte (simulating an Alt-0xxx OEM keyboard press).
             */
        }

        /* Pressing some control keys */

        /* Pressing the character key, with the control keys maintained pressed */
        er.Event.KeyEvent.bKeyDown = TRUE;
        er.Event.KeyEvent.wVirtualKeyCode = LOBYTE(VkKey);
        er.Event.KeyEvent.wVirtualScanCode = MapVirtualKeyW(LOBYTE(VkKey), MAPVK_VK_TO_VSC);
        er.Event.KeyEvent.uChar.UnicodeChar = CurChar;
        er.Event.KeyEvent.dwControlKeyState = 0;
        if (HIBYTE(VkKey) & 1)
            er.Event.KeyEvent.dwControlKeyState |= SHIFT_PRESSED;
        if (HIBYTE(VkKey) & 2)
            er.Event.KeyEvent.dwControlKeyState |= LEFT_CTRL_PRESSED; // RIGHT_CTRL_PRESSED;
        if (HIBYTE(VkKey) & 4)
            er.Event.KeyEvent.dwControlKeyState |= LEFT_ALT_PRESSED; // RIGHT_ALT_PRESSED;

        ConioProcessInputEvent(Console, &er);

        /* Up all the character and control keys */
        er.Event.KeyEvent.bKeyDown = FALSE;
        ConioProcessInputEvent(Console, &er);
    }
}

VOID
GetSelectionBeginEnd(PCOORD Begin, PCOORD End,
                     PCOORD SelectionAnchor,
                     PSMALL_RECT SmallRect);

/*
 * The selected text as CF_UNICODETEXT data for the clipboard, or NULL.
 * The console must be locked; the clipboard is not touched.
 */
HANDLE
GuiCopyFromTextModeBuffer(PTEXTMODE_SCREEN_BUFFER Buffer,
                          PGUI_CONSOLE_DATA GuiData)
{
    BOOL LineSelection = GuiData->LineSelection;

    DPRINT("Selection is (%d|%d) to (%d|%d) in %s mode\n",
           GuiData->Selection.srSelection.Left,
           GuiData->Selection.srSelection.Top,
           GuiData->Selection.srSelection.Right,
           GuiData->Selection.srSelection.Bottom,
           (LineSelection ? "line" : "block"));

    if (!LineSelection)
    {
        return CopyBlock(Buffer, &GuiData->Selection.srSelection);
    }
    else
    {
        COORD Begin, End;

        GetSelectionBeginEnd(&Begin, &End,
                             &GuiData->Selection.dwSelectionAnchor,
                             &GuiData->Selection.srSelection);

        return CopyLines(Buffer, &Begin, &End, GuiData->CopyNoTrim);
    }
}


static VOID
GuiPaintCaret(
    PTEXTMODE_SCREEN_BUFFER Buffer,
    PGUI_CONSOLE_DATA GuiData,
    ULONG TopLine,
    ULONG BottomLine,
    ULONG LeftColumn,
    ULONG RightColumn,
    LONG OriginX,
    LONG OriginY)
{
    PCONSRV_CONSOLE Console = (PCONSRV_CONSOLE)Buffer->Header.Console;

    ULONG CursorX, CursorY, CursorHeight;
    HBRUSH CursorBrush, OldBrush;
    WORD Attribute;

    if (Buffer->CursorInfo.bVisible &&
        Buffer->CursorBlinkOn &&
        !Buffer->ForceCursorOff)
    {
        CursorX = Buffer->CursorPosition.X;
        CursorY = Buffer->CursorPosition.Y;
        if (LeftColumn <= CursorX && CursorX <= RightColumn &&
            TopLine    <= CursorY && CursorY <= BottomLine)
        {
            CursorHeight = ConioEffectiveCursorSize(Console, GuiData->CharHeight);

            Attribute = ConioCoordToPointer(Buffer, Buffer->CursorPosition.X, Buffer->CursorPosition.Y)->Attributes;
            if (Attribute == DEFAULT_SCREEN_ATTRIB)
                Attribute = Buffer->ScreenDefaultAttrib;

            CursorBrush = CreateSolidBrush(PaletteRGBFromAttrib(Console, TextAttribFromAttrib(Attribute)));
            OldBrush    = SelectObject(GuiData->hMemDC, CursorBrush);

            if (Attribute & COMMON_LVB_LEADING_BYTE)
            {
                /* The caret is on the leading byte */
                PatBlt(GuiData->hMemDC,
                       (LONG)(CursorX * GuiData->CharWidth) - OriginX,
                       (LONG)(CursorY * GuiData->CharHeight + (GuiData->CharHeight - CursorHeight)) - OriginY,
                       GuiData->CharWidth * 2,
                       CursorHeight,
                       PATCOPY);
            }
            else if (Attribute & COMMON_LVB_TRAILING_BYTE)
            {
                /* The caret is on the trailing byte */
                PatBlt(GuiData->hMemDC,
                       (LONG)((CursorX - 1) * GuiData->CharWidth) - OriginX,
                       (LONG)(CursorY * GuiData->CharHeight + (GuiData->CharHeight - CursorHeight)) - OriginY,
                       GuiData->CharWidth * 2,
                       CursorHeight,
                       PATCOPY);
            }
            else
            {
                PatBlt(GuiData->hMemDC,
                       (LONG)(CursorX * GuiData->CharWidth) - OriginX,
                       (LONG)(CursorY * GuiData->CharHeight + (GuiData->CharHeight - CursorHeight)) - OriginY,
                       GuiData->CharWidth,
                       CursorHeight,
                       PATCOPY);
            }

            SelectObject(GuiData->hMemDC, OldBrush);
            DeleteObject(CursorBrush);
        }
    }
}

/*
 * Compose the framebuffer. The console must be locked.
 * The framebuffer holds the view only: the cells are drawn at their position in the view
 * and rcFramebuffer, the part to send to the screen, is in view coordinates (rcView).
 */
BOOL
GuiPaintTextModeBuffer(PTEXTMODE_SCREEN_BUFFER Buffer,
                       PGUI_CONSOLE_DATA GuiData,
                       PRECT rcView,
                       PRECT rcFramebuffer)
{
    PCONSRV_CONSOLE Console = (PCONSRV_CONSOLE)Buffer->Header.Console;
    ULONG TopLine, BottomLine, LeftColumn, RightColumn;
    ULONG Line, Char, Start;
    PCHAR_INFO From;
    PWCHAR To;
    WORD LastAttribute, Attribute;
    HFONT OldFont, NewFont;
    BOOLEAN IsUnderline;
    BOOLEAN bWide;
    LONG OriginX, OriginY;

    // ASSERT(Console == GuiData->Console);

    ConioInitLongRect(rcFramebuffer, 0, 0, 0, 0);

    if (Buffer->Buffer == NULL)
        return FALSE;

    ConioInitLongRect(rcFramebuffer,
                      Buffer->ViewOrigin.Y * GuiData->CharHeight + rcView->top,
                      Buffer->ViewOrigin.X * GuiData->CharWidth  + rcView->left,
                      Buffer->ViewOrigin.Y * GuiData->CharHeight + rcView->bottom,
                      Buffer->ViewOrigin.X * GuiData->CharWidth  + rcView->right);

    /* Where the view starts, in the buffer's pixels */
    OriginX = Buffer->ViewOrigin.X * GuiData->CharWidth;
    OriginY = Buffer->ViewOrigin.Y * GuiData->CharHeight;

    LeftColumn  = rcFramebuffer->left  / GuiData->CharWidth;
    RightColumn = rcFramebuffer->right / GuiData->CharWidth;
    if (RightColumn >= (ULONG)Buffer->ScreenBufferSize.X)
        RightColumn  = Buffer->ScreenBufferSize.X - 1;

    TopLine    = rcFramebuffer->top    / GuiData->CharHeight;
    BottomLine = rcFramebuffer->bottom / GuiData->CharHeight;
    if (BottomLine >= (ULONG)Buffer->ScreenBufferSize.Y)
        BottomLine  = Buffer->ScreenBufferSize.Y - 1;

    LastAttribute = ConioCoordToPointer(Buffer, LeftColumn, TopLine)->Attributes;

    SetTextColor(GuiData->hMemDC, PaletteRGBFromAttrib(Console, TextAttribFromAttrib(LastAttribute)));
    SetBkColor(GuiData->hMemDC, PaletteRGBFromAttrib(Console, BkgdAttribFromAttrib(LastAttribute)));

    /* We use the underscore flag as a underline flag */
    IsUnderline = !!(LastAttribute & COMMON_LVB_UNDERSCORE);
    /* Select the new font */
    NewFont = GuiData->Font[IsUnderline ? FONT_BOLD : FONT_NORMAL];
    OldFont = SelectObject(GuiData->hMemDC, NewFont);

    /* Wide characters take two cells in every code page: a trailing cell is not drawn, and each
     * character goes to its own cell column */
    bWide = Console->IsCJK;
    for (Line = TopLine; !bWide && Line <= BottomLine; Line++)
    {
        From = ConioCoordToPointer(Buffer, LeftColumn, Line);
        for (Char = LeftColumn; Char <= RightColumn; Char++, From++)
        {
            if (From->Attributes & (COMMON_LVB_LEADING_BYTE | COMMON_LVB_TRAILING_BYTE))
            {
                bWide = TRUE;
                break;
            }
        }
    }

    if (bWide)
    {
        for (Line = TopLine; Line <= BottomLine; Line++)
        {
            for (Char = LeftColumn; Char <= RightColumn; Char++)
            {
                From = ConioCoordToPointer(Buffer, Char, Line);
                Attribute = From->Attributes;
                SetTextColor(GuiData->hMemDC, PaletteRGBFromAttrib(Console, TextAttribFromAttrib(Attribute)));
                SetBkColor(GuiData->hMemDC, PaletteRGBFromAttrib(Console, BkgdAttribFromAttrib(Attribute)));

                /* Change underline state if needed */
                if (!!(Attribute & COMMON_LVB_UNDERSCORE) != IsUnderline)
                {
                    IsUnderline = !!(Attribute & COMMON_LVB_UNDERSCORE);

                    /* Select the new font */
                    NewFont = GuiData->Font[IsUnderline ? FONT_BOLD : FONT_NORMAL];
                    SelectObject(GuiData->hMemDC, NewFont);
                }

                {
                    /* A wide character fills the two cells of its pair, whatever the font's glyph width;
                     * half of a pair (the other half was overwritten) is a blank cell */
                    static const WCHAR Blank = L' ';
                    BOOLEAN bPair = FALSE, bOrphan = FALSE;
                    RECT CellRect;

                    if (Attribute & COMMON_LVB_TRAILING_BYTE)
                    {
                        if (Char > 0 && (ConioCoordToPointer(Buffer, Char - 1, Line)->Attributes & COMMON_LVB_LEADING_BYTE))
                            continue;
                        bOrphan = TRUE;
                    }
                    else if (Attribute & COMMON_LVB_LEADING_BYTE)
                    {
                        if (Char + 1 < (ULONG)Buffer->ScreenBufferSize.X &&
                            (ConioCoordToPointer(Buffer, Char + 1, Line)->Attributes & COMMON_LVB_TRAILING_BYTE))
                            bPair = TRUE;
                        else
                            bOrphan = TRUE;
                    }

                    CellRect.left   = (LONG)(Char * GuiData->CharWidth) - OriginX;
                    CellRect.top    = (LONG)(Line * GuiData->CharHeight) - OriginY;
                    CellRect.right  = CellRect.left + GuiData->CharWidth * (bPair ? 2 : 1);
                    CellRect.bottom = CellRect.top + GuiData->CharHeight;
                    ExtTextOutW(GuiData->hMemDC, CellRect.left, CellRect.top, ETO_OPAQUE, &CellRect,
                                bOrphan ? &Blank : &From->Char.UnicodeChar, 1, NULL);
                }
            }
        }
    }
    else
    {
        for (Line = TopLine; Line <= BottomLine; Line++)
        {
            WCHAR LineBuffer[80];   // Buffer containing a part or all the line to be displayed
            From  = ConioCoordToPointer(Buffer, LeftColumn, Line);  // Get the first code of the line
            Start = LeftColumn;
            To    = LineBuffer;

            for (Char = LeftColumn; Char <= RightColumn; Char++)
            {
                /*
                 * We flush the buffer if the new attribute is different
                 * from the current one, or if the buffer is full.
                 */
                if (From->Attributes != LastAttribute || (Char - Start == sizeof(LineBuffer) / sizeof(WCHAR)))
                {
                    TextOutW(GuiData->hMemDC,
                             (LONG)(Start * GuiData->CharWidth) - OriginX,
                             (LONG)(Line  * GuiData->CharHeight) - OriginY,
                             LineBuffer,
                             Char - Start);
                    Start = Char;
                    To    = LineBuffer;
                    Attribute = From->Attributes;
                    if (Attribute != LastAttribute)
                    {
                        LastAttribute = Attribute;
                        SetTextColor(GuiData->hMemDC, PaletteRGBFromAttrib(Console, TextAttribFromAttrib(LastAttribute)));
                        SetBkColor(GuiData->hMemDC, PaletteRGBFromAttrib(Console, BkgdAttribFromAttrib(LastAttribute)));

                        /* Change underline state if needed */
                        if (!!(LastAttribute & COMMON_LVB_UNDERSCORE) != IsUnderline)
                        {
                            IsUnderline = !!(LastAttribute & COMMON_LVB_UNDERSCORE);
                            /* Select the new font */
                            NewFont = GuiData->Font[IsUnderline ? FONT_BOLD : FONT_NORMAL];
                            SelectObject(GuiData->hMemDC, NewFont);
                        }
                    }
                }

                *(To++) = (From++)->Char.UnicodeChar;
            }

            TextOutW(GuiData->hMemDC,
                     (LONG)(Start * GuiData->CharWidth) - OriginX,
                     (LONG)(Line  * GuiData->CharHeight) - OriginY,
                     LineBuffer,
                     RightColumn - Start + 1);
        }
    }

    /* Restore the old font */
    SelectObject(GuiData->hMemDC, OldFont);

    /* Draw the caret */
    GuiPaintCaret(Buffer, GuiData, TopLine, BottomLine, LeftColumn, RightColumn, OriginX, OriginY);

    /* What goes to the screen is the same rectangle of the view */
    *rcFramebuffer = *rcView;

    return TRUE;
}

/* EOF */
