/*
 * PROJECT:     ReactOS Console Server DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Virtual terminal sequences in the input of the console
 *              (ENABLE_VIRTUAL_TERMINAL_INPUT)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * With ENABLE_VIRTUAL_TERMINAL_INPUT the key-down events that enter the input
 * buffer (from the keyboard, WriteConsoleInput, or a pseudoconsole host) are
 * replaced by the VT sequence of the key, as a series of key-down events that
 * carry one character each (virtual key, scan code and control key state are
 * zero, repeat count is one). Key-up events and all other events are queued
 * unchanged. The rules follow the "Console Virtual Terminal Sequences"
 * documentation (input sequences) and the behaviour of the Windows 10 console
 * (build 19045) measured with kernel32_apitest:ConsoleVirtualTerminalInput:
 *  - the repeat count of the event is not used: one sequence per event;
 *  - cursor keys, Home and End are ESC [ A.. / ESC [ H / ESC [ F, or ESC O ..
 *    when the application set DECCKM (ESC [ ? 1 h) and no modifier is held;
 *    PgUp, PgDn, Insert, Delete and F5..F12 are ESC [ n ~; F1..F4 are ESC O P..S;
 *  - with Shift (1), Alt (2) or Ctrl (4) the sequence is ESC [ 1 ; m final
 *    (ESC [ n ; m ~ for the tilde keys) with m = 1 + the sum of the modifiers;
 *  - Shift+Tab is ESC [ Z; Backspace is DEL (BS with Ctrl but not Shift);
 *  - Alt (not AltGr) in front of a character, Tab, Backspace, Escape, or
 *    Ctrl+Space sends ESC first; Alt+Enter sends ESC CR;
 *  - Ctrl+Space and Ctrl+2 are NUL, which is the event of virtual key '2'
 *    with the control key state of the key and no character; Pause is SUB;
 *  - letters and digits without a character are dropped (only Ctrl+Alt gives
 *    ESC and the control character of the letter);
 *  - keys that have no sequence (modifiers alone, F13.., the numeric keypad,
 *    Enter, Space, characters of keys other than letters and digits) stay as
 *    they are.
 */

/* INCLUDES *******************************************************************/

#include "consrv.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

#define VTI_ESC     L'\x1B'

#ifndef VK_OEM_2
#define VK_OEM_2    0xBF
#endif

/* PRIVATE FUNCTIONS **********************************************************/

typedef struct _VTI_OUT
{
    PINPUT_RECORD Records;
    ULONG Count;
} VTI_OUT;

static VOID
VtiChar(VTI_OUT *Out, WCHAR Char)
{
    PINPUT_RECORD Record = &Out->Records[Out->Count++];

    RtlZeroMemory(Record, sizeof(*Record));
    Record->EventType = KEY_EVENT;
    Record->Event.KeyEvent.bKeyDown = TRUE;
    Record->Event.KeyEvent.wRepeatCount = 1;
    Record->Event.KeyEvent.uChar.UnicodeChar = Char;
}

/* NUL: virtual key '2' with the control key state of the key (Ctrl), no character */
static VOID
VtiNul(VTI_OUT *Out, DWORD State)
{
    PINPUT_RECORD Record = &Out->Records[Out->Count++];

    RtlZeroMemory(Record, sizeof(*Record));
    Record->EventType = KEY_EVENT;
    Record->Event.KeyEvent.bKeyDown = TRUE;
    Record->Event.KeyEvent.wRepeatCount = 1;
    Record->Event.KeyEvent.wVirtualKeyCode = L'2';
    Record->Event.KeyEvent.dwControlKeyState = State;
}

static VOID
VtiNumber(VTI_OUT *Out, ULONG Number)
{
    if (Number >= 10) VtiChar(Out, (WCHAR)(L'0' + Number / 10));
    VtiChar(Out, (WCHAR)(L'0' + Number % 10));
}

/* ESC [ 1 ; m Final, or ESC [ Final / ESC O Final without a modifier */
static VOID
VtiFinal(VTI_OUT *Out, WCHAR Final, ULONG Modifier, BOOLEAN Ss3)
{
    VtiChar(Out, VTI_ESC);
    if (Modifier == 1)
    {
        VtiChar(Out, Ss3 ? L'O' : L'[');
    }
    else
    {
        VtiChar(Out, L'[');
        VtiChar(Out, L'1');
        VtiChar(Out, L';');
        VtiNumber(Out, Modifier);
    }
    VtiChar(Out, Final);
}

/* ESC [ n ~, or ESC [ n ; m ~ */
static VOID
VtiTilde(VTI_OUT *Out, ULONG Number, ULONG Modifier)
{
    VtiChar(Out, VTI_ESC);
    VtiChar(Out, L'[');
    VtiNumber(Out, Number);
    if (Modifier != 1)
    {
        VtiChar(Out, L';');
        VtiNumber(Out, Modifier);
    }
    VtiChar(Out, L'~');
}

/*
 * Translates one key-down event. Returns FALSE when the event stays as it is;
 * otherwise Out receives the replacement (possibly nothing).
 */
static BOOLEAN
VtiTranslateKey(const KEY_EVENT_RECORD *Key, BOOLEAN AppCursorKeys, VTI_OUT *Out)
{
    WORD Vk = Key->wVirtualKeyCode;
    WCHAR Char = Key->uChar.UnicodeChar;
    DWORD State = Key->dwControlKeyState;
    BOOLEAN Shift = !!(State & SHIFT_PRESSED);
    BOOLEAN Alt = !!(State & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED));
    BOOLEAN Ctrl = !!(State & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED));
    BOOLEAN AltGr = (State & RIGHT_ALT_PRESSED) && (State & LEFT_CTRL_PRESSED);
    BOOLEAN Prefix = (Alt && !AltGr);   /* ESC in front of the character */
    ULONG Modifier = 1 + (Shift ? 1 : 0) + (Alt ? 2 : 0) + (Ctrl ? 4 : 0);
    BOOLEAN IsLetter = (Vk >= L'A' && Vk <= L'Z');
    BOOLEAN IsDigit = (Vk >= L'0' && Vk <= L'9');

    /* Cursor keys, Home, End */
    switch (Vk)
    {
        case VK_UP:     VtiFinal(Out, L'A', Modifier, AppCursorKeys); return TRUE;
        case VK_DOWN:   VtiFinal(Out, L'B', Modifier, AppCursorKeys); return TRUE;
        case VK_RIGHT:  VtiFinal(Out, L'C', Modifier, AppCursorKeys); return TRUE;
        case VK_LEFT:   VtiFinal(Out, L'D', Modifier, AppCursorKeys); return TRUE;
        case VK_HOME:   VtiFinal(Out, L'H', Modifier, AppCursorKeys); return TRUE;
        case VK_END:    VtiFinal(Out, L'F', Modifier, AppCursorKeys); return TRUE;
        case VK_INSERT: VtiTilde(Out, 2, Modifier); return TRUE;
        case VK_DELETE: VtiTilde(Out, 3, Modifier); return TRUE;
        case VK_PRIOR:  VtiTilde(Out, 5, Modifier); return TRUE;
        case VK_NEXT:   VtiTilde(Out, 6, Modifier); return TRUE;
        default:        break;
    }

    /* Function keys */
    if (Vk >= VK_F1 && Vk <= VK_F12)
    {
        static const UCHAR FunctionTilde[] = { 15, 17, 18, 19, 20, 21, 23, 24 }; /* F5..F12 */

        if (Vk <= VK_F4)
        {
            VtiFinal(Out, (WCHAR)(L'P' + (Vk - VK_F1)), Modifier, TRUE);
        }
        else
        {
            VtiTilde(Out, FunctionTilde[Vk - VK_F5], Modifier);
        }
        return TRUE;
    }

    switch (Vk)
    {
        case VK_TAB:
            if (Shift && !Alt && !Ctrl)
            {
                VtiChar(Out, VTI_ESC);
                VtiChar(Out, L'[');
                VtiChar(Out, L'Z');
            }
            else
            {
                if (Prefix) VtiChar(Out, VTI_ESC);
                VtiChar(Out, L'\t');
            }
            return TRUE;

        case VK_BACK:
            if (Prefix) VtiChar(Out, VTI_ESC);
            VtiChar(Out, (Ctrl && !Shift) ? L'\b' : L'\x7F');
            return TRUE;

        case VK_ESCAPE:
            if (Prefix) VtiChar(Out, VTI_ESC);
            VtiChar(Out, VTI_ESC);
            return TRUE;

        case VK_PAUSE:
            VtiChar(Out, L'\x1A');
            return TRUE;

        case VK_RETURN:
            /* Enter itself is a character the application already gets */
            if (!Prefix) return FALSE;
            VtiChar(Out, VTI_ESC);
            VtiChar(Out, Char ? Char : L'\r');
            return TRUE;

        case VK_SPACE:
            if (!Ctrl) break;
            if (Prefix)
            {
                VtiChar(Out, VTI_ESC);
                VtiChar(Out, L'\0');
                return TRUE;
            }
            if (Char != L' ') return FALSE;
            VtiNul(Out, State);
            return TRUE;

        default:
            break;
    }

    if (Char == 0)
    {
        if (IsLetter)
        {
            /* Only Ctrl+Alt names the control character of the letter */
            if (Ctrl && Alt && !AltGr)
            {
                VtiChar(Out, VTI_ESC);
                VtiChar(Out, (WCHAR)(Vk - L'@'));
            }
            return TRUE;
        }
        if (IsDigit)
        {
            if (Vk == L'2' && Ctrl)
            {
                if (Prefix) VtiChar(Out, VTI_ESC);
                VtiNul(Out, State);
            }
            return TRUE;
        }
        if (Vk == VK_OEM_2 && Ctrl)
        {
            /* Ctrl+/ and Ctrl+? */
            VtiChar(Out, L'\x1F');
            return TRUE;
        }
        return FALSE;
    }

    /* A character */
    if (Prefix)
    {
        VtiChar(Out, VTI_ESC);
        VtiChar(Out, Char);
        return TRUE;
    }
    if (IsLetter || IsDigit)
    {
        VtiChar(Out, Char);
        return TRUE;
    }
    return FALSE;
}

/* The longest sequence is ESC [ 2 4 ; 8 ~ (7 characters), ESC + NUL is 2 */
#define VTI_MAX_EVENTS  8

/*
 * Counts (Out == NULL) or fills the events that replace the Count events
 * of In. Returns the number of events.
 */
static ULONG
VtiWalk(PINPUT_RECORD In, ULONG Count, BOOLEAN AppCursorKeys, PINPUT_RECORD Out, ULONG Limit)
{
    ULONG i, Total = 0;
    INPUT_RECORD Scratch[VTI_MAX_EVENTS];
    VTI_OUT Piece;

    for (i = 0; i < Count; ++i)
    {
        Piece.Records = Scratch;
        Piece.Count = 0;
        if (In[i].EventType == KEY_EVENT && In[i].Event.KeyEvent.bKeyDown &&
            VtiTranslateKey(&In[i].Event.KeyEvent, AppCursorKeys, &Piece))
        {
            if (Out)
            {
                ASSERT(Total + Piece.Count <= Limit);
                RtlCopyMemory(&Out[Total], Scratch, Piece.Count * sizeof(INPUT_RECORD));
            }
            Total += Piece.Count;
        }
        else
        {
            if (Out)
            {
                ASSERT(Total + 1 <= Limit);
                Out[Total] = In[i];
            }
            ++Total;
        }
    }
    return Total;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * Returns the events to queue instead of In[0..Count-1]: In itself when
 * nothing changes, else a block from the console heap that the caller frees
 * (ConsoleFreeHeap) when the result differs from In.
 */
PINPUT_RECORD
ConSrvVtInputTranslate(PCONSRV_CONSOLE Console,
                       PINPUT_RECORD In,
                       ULONG Count,
                       PULONG OutCount)
{
    BOOLEAN App = Console->InputBuffer.VtCursorKeysApp;
    PINPUT_RECORD Out;
    ULONG Total, i;

    *OutCount = Count;
    for (i = 0; i < Count; ++i)
    {
        if (In[i].EventType == KEY_EVENT && In[i].Event.KeyEvent.bKeyDown)
            break;
    }
    if (i == Count) return In;

    Total = VtiWalk(In, Count, App, NULL, 0);
    if (Total == 0)
    {
        *OutCount = 0;
        return In;
    }
    Out = ConsoleAllocHeap(0, Total * sizeof(INPUT_RECORD));
    if (!Out) return In;    /* out of memory: queue the keys as they are */
    VtiWalk(In, Count, App, Out, Total);
    *OutCount = Total;
    return Out;
}

/* The number of events of In[0..Count-1] whose replacement fits in Written events */
ULONG
ConSrvVtInputSourceCount(PCONSRV_CONSOLE Console,
                         PINPUT_RECORD In,
                         ULONG Count,
                         ULONG Written)
{
    BOOLEAN App = Console->InputBuffer.VtCursorKeysApp;
    ULONG i, Sum = 0;

    for (i = 0; i < Count; ++i)
    {
        Sum += VtiWalk(&In[i], 1, App, NULL, 0);
        if (Sum > Written) break;
    }
    return i;
}
