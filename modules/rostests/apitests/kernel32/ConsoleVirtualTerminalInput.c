/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test ENABLE_VIRTUAL_TERMINAL_INPUT: key events become VT sequences
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows 10 22H2 (build 19045) with the
 * same table (this file built with mingw and run there).
 */

#include "precomp.h"
#include <winuser.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT       0x0200
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING  0x0004
#endif
#ifndef ENABLE_INSERT_MODE
#define ENABLE_INSERT_MODE                  0x0020
#endif
#ifndef ENABLE_EXTENDED_FLAGS
#define ENABLE_EXTENDED_FLAGS               0x0080
#endif

#define LC  LEFT_CTRL_PRESSED
#define RC  RIGHT_CTRL_PRESSED
#define LA  LEFT_ALT_PRESSED
#define RA  RIGHT_ALT_PRESSED
#define SH  SHIFT_PRESSED
#define EN  ENHANCED_KEY
#define NL  NUMLOCK_ON

/* Seq markers */
#define PASS        NULL            /* the event is queued unchanged */
#define DROP        L""             /* the key-down event is removed */
#define NULREC      L"\xE000"       /* the NUL event: virtual key '2', the state of the key, no character */
#define NULCH       L"\xE001"       /* a character event for U+0000 */

static HANDLE hIn, hOut;

typedef struct _KEYCASE
{
    PCSTR Name;
    WORD Vk, Scan;
    WCHAR Char;
    DWORD State;
    PCWSTR Seq;
} KEYCASE;

static VOID
MakeKey(PINPUT_RECORD Record, BOOL Down, WORD Vk, WORD Scan, WCHAR Char, DWORD State)
{
    ZeroMemory(Record, sizeof(*Record));
    Record->EventType = KEY_EVENT;
    Record->Event.KeyEvent.bKeyDown = Down;
    Record->Event.KeyEvent.wRepeatCount = 1;
    Record->Event.KeyEvent.wVirtualKeyCode = Vk;
    Record->Event.KeyEvent.wVirtualScanCode = Scan;
    Record->Event.KeyEvent.uChar.UnicodeChar = Char;
    Record->Event.KeyEvent.dwControlKeyState = State;
}

static BOOL
SameKey(const INPUT_RECORD *A, const INPUT_RECORD *B)
{
    return A->EventType == KEY_EVENT && B->EventType == KEY_EVENT &&
           A->Event.KeyEvent.bKeyDown == B->Event.KeyEvent.bKeyDown &&
           A->Event.KeyEvent.wRepeatCount == B->Event.KeyEvent.wRepeatCount &&
           A->Event.KeyEvent.wVirtualKeyCode == B->Event.KeyEvent.wVirtualKeyCode &&
           A->Event.KeyEvent.wVirtualScanCode == B->Event.KeyEvent.wVirtualScanCode &&
           A->Event.KeyEvent.uChar.UnicodeChar == B->Event.KeyEvent.uChar.UnicodeChar &&
           A->Event.KeyEvent.dwControlKeyState == B->Event.KeyEvent.dwControlKeyState;
}

static DWORD
Pending(VOID)
{
    DWORD Count = 0;
    GetNumberOfConsoleInputEvents(hIn, &Count);
    return Count;
}

static DWORD
ReadAll(PINPUT_RECORD Records, DWORD Max)
{
    DWORD Count = Pending(), Read = 0;

    if (Count > Max) Count = Max;
    if (Count && !ReadConsoleInputW(hIn, Records, Count, &Read)) Read = 0;
    return Read;
}

/* Printable form of a character string for the failure messages */
static PCSTR
Show(PCWSTR Text, DWORD Count, PSTR Buffer, DWORD Size)
{
    DWORD i, Used = 0;

    Buffer[0] = 0;
    for (i = 0; i < Count && Used + 8 < Size; ++i)
    {
        if (Text[i] >= 0x21 && Text[i] < 0x7F)
            Used += wsprintfA(Buffer + Used, "%c", (CHAR)Text[i]);
        else
            Used += wsprintfA(Buffer + Used, "<%X>", Text[i]);
    }
    return Buffer;
}

/*
 * Writes the key-down and key-up events of the key; with ReadW it reads the
 * characters with ReadConsoleW, else the events with ReadConsoleInputW.
 */
static VOID
CheckKey(const KEYCASE *Case, BOOL ReadW)
{
    INPUT_RECORD In[2], Out[64];
    DWORD Written = 0, Count, i, Length;
    BOOL Success;
    PCWSTR Seq = Case->Seq;
    CHAR Shown[128], Shown2[128];

    FlushConsoleInputBuffer(hIn);
    MakeKey(&In[0], TRUE, Case->Vk, Case->Scan, Case->Char, Case->State);
    MakeKey(&In[1], FALSE, Case->Vk, Case->Scan, Case->Char, Case->State);
    Success = WriteConsoleInputW(hIn, In, 2, &Written);
    ok(Success && Written == 2, "%s: WriteConsoleInputW returned %d, %lu events, error %lu\n",
       Case->Name, Success, Written, GetLastError());

    if (ReadW)
    {
        WCHAR Text[64], Want[16];
        DWORD Read = 0, Wanted = 0;

        /* The NUL events are not characters for ReadConsoleW */
        for (i = 0; Seq != PASS && Seq[i]; ++i)
            if (Seq[i] == 0xE000 || Seq[i] == 0xE001) return;

        /* Only call ReadConsoleW when it has something to return */
        Count = 0;
        PeekConsoleInputW(hIn, Out, _countof(Out), &Count);
        if (Seq == PASS)
        {
            if (Case->Char) Want[Wanted++] = Case->Char;
        }
        else
        {
            for (i = 0; Seq[i]; ++i) Want[Wanted++] = Seq[i];
        }
        {
            /* key-down events with a character */
            DWORD Chars = 0;
            for (i = 0; i < Count; ++i)
                if (Out[i].EventType == KEY_EVENT && Out[i].Event.KeyEvent.bKeyDown &&
                    Out[i].Event.KeyEvent.uChar.UnicodeChar) ++Chars;
            if (!Chars)
            {
                ok(Wanted == 0, "%s: no character was queued, expected %lu\n", Case->Name, Wanted);
                FlushConsoleInputBuffer(hIn);
                return;
            }
        }
        Success = ReadConsoleW(hIn, Text, _countof(Text), &Read, NULL);
        ok(Success, "%s: ReadConsoleW failed: %lu\n", Case->Name, GetLastError());
        ok(Read == Wanted && !memcmp(Text, Want, Wanted * sizeof(WCHAR)),
           "%s: ReadConsoleW returned '%s', expected '%s'\n", Case->Name,
           Show(Text, Read, Shown, sizeof(Shown)), Show(Want, Wanted, Shown2, sizeof(Shown2)));
        FlushConsoleInputBuffer(hIn);
        return;
    }

    Count = ReadAll(Out, _countof(Out));
    if (Seq == PASS)
    {
        ok(Count == 2, "%s: %lu events queued, expected the 2 written\n", Case->Name, Count);
        if (Count == 2)
        {
            ok(SameKey(&Out[0], &In[0]), "%s: key-down event was changed\n", Case->Name);
            ok(SameKey(&Out[1], &In[1]), "%s: key-up event was changed\n", Case->Name);
        }
        return;
    }

    Length = lstrlenW(Seq);
    ok(Count == Length + 1, "%s: %lu events queued, expected %lu\n", Case->Name, Count, Length + 1);
    if (Count != Length + 1) return;
    for (i = 0; i < Length; ++i)
    {
        INPUT_RECORD Expected;

        if (Seq[i] == 0xE000)
        {
            MakeKey(&Expected, TRUE, '2', 0, 0, Case->State);
        }
        else
        {
            MakeKey(&Expected, TRUE, 0, 0, (Seq[i] == 0xE001) ? 0 : Seq[i], 0);
        }
        ok(SameKey(&Out[i], &Expected),
           "%s: event %lu is down=%d vk=%02X scan=%02X char=%04X state=%lX repeat=%u, expected char %04X\n",
           Case->Name, i, Out[i].Event.KeyEvent.bKeyDown, Out[i].Event.KeyEvent.wVirtualKeyCode,
           Out[i].Event.KeyEvent.wVirtualScanCode, Out[i].Event.KeyEvent.uChar.UnicodeChar,
           Out[i].Event.KeyEvent.dwControlKeyState, Out[i].Event.KeyEvent.wRepeatCount,
           Expected.Event.KeyEvent.uChar.UnicodeChar);
    }
    ok(SameKey(&Out[Length], &In[1]), "%s: the key-up event was changed\n", Case->Name);
}

static VOID
CheckKeys(const KEYCASE *Cases, ULONG Count)
{
    ULONG i;

    for (i = 0; i < Count; ++i)
    {
        CheckKey(&Cases[i], FALSE);
        CheckKey(&Cases[i], TRUE);
    }
}

static PCWSTR
Sequence(PCWSTR Format, ULONG Modifier)
{
    /* Format has one %u that becomes the modifier */
    static WCHAR Text[8][32];
    static ULONG Slot;
    PWSTR Out = Text[Slot++ % 8];

    wsprintfW(Out, Format, Modifier);
    return Out;
}

/* ReactOS adds ENABLE_EXTENDED_FLAGS (and ENABLE_INSERT_MODE) when the mode is read; Windows 10
 * returns what was set. That is not what this test is about. */
static DWORD
InputMode(VOID)
{
    DWORD Mode = 0;

    GetConsoleMode(hIn, &Mode);
    return Mode & ~(ENABLE_INSERT_MODE | ENABLE_EXTENDED_FLAGS);
}

static VOID
TestMode(VOID)
{
    DWORD Saved, Mode;
    BOOL Success;

    ok(GetConsoleMode(hIn, &Saved), "GetConsoleMode failed: %lu\n", GetLastError());

    Success = SetConsoleMode(hIn, ENABLE_VIRTUAL_TERMINAL_INPUT);
    ok(Success, "SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_INPUT) failed: %lu\n", GetLastError());
    Mode = InputMode();
    ok(Mode == ENABLE_VIRTUAL_TERMINAL_INPUT, "Mode is %lX, expected 200\n", Mode);

    Success = SetConsoleMode(hIn, ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_WINDOW_INPUT |
                                  ENABLE_MOUSE_INPUT);
    ok(Success, "SetConsoleMode(200|1|8|10) failed: %lu\n", GetLastError());
    Mode = InputMode();
    ok(Mode == (ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT),
       "Mode is %lX, expected 219\n", Mode);

    Success = SetConsoleMode(hIn, ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
    ok(Success, "SetConsoleMode(200|LINE|ECHO) failed: %lu\n", GetLastError());
    Mode = InputMode();
    ok(Mode == (ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT),
       "Mode is %lX, expected 206\n", Mode);

    /* The bit is not for screen buffers */
    Success = SetConsoleMode(hOut, ENABLE_VIRTUAL_TERMINAL_INPUT);
    ok(!Success, "SetConsoleMode(output, 0x200) succeeded\n");

    SetConsoleMode(hIn, Saved);
}

static VOID
TestNavigation(VOID)
{
    static const struct { PCSTR Name; WORD Vk, Scan; PCWSTR Format; PCWSTR Plain; } Keys[] =
    {
        { "Up",     VK_UP,     0x48, L"\x1B[1;%uA", L"\x1B[A" },
        { "Down",   VK_DOWN,   0x50, L"\x1B[1;%uB", L"\x1B[B" },
        { "Right",  VK_RIGHT,  0x4D, L"\x1B[1;%uC", L"\x1B[C" },
        { "Left",   VK_LEFT,   0x4B, L"\x1B[1;%uD", L"\x1B[D" },
        { "Home",   VK_HOME,   0x47, L"\x1B[1;%uH", L"\x1B[H" },
        { "End",    VK_END,    0x4F, L"\x1B[1;%uF", L"\x1B[F" },
        { "PgUp",   VK_PRIOR,  0x49, L"\x1B[5;%u~", L"\x1B[5~" },
        { "PgDn",   VK_NEXT,   0x51, L"\x1B[6;%u~", L"\x1B[6~" },
        { "Insert", VK_INSERT, 0x52, L"\x1B[2;%u~", L"\x1B[2~" },
        { "Delete", VK_DELETE, 0x53, L"\x1B[3;%u~", L"\x1B[3~" },
    };
    static const struct { PCSTR Name; DWORD State; ULONG Modifier; } Modifiers[] =
    {
        { "",                  0,           1 },
        { "Shift+",            SH,          2 },
        { "Alt+",              LA,          3 },
        { "Shift+Alt+",        SH | LA,     4 },
        { "Ctrl+",             LC,          5 },
        { "Ctrl+Shift+",       LC | SH,     6 },
        { "Ctrl+Alt+",         LC | LA,     7 },
        { "Ctrl+Alt+Shift+",   LC | LA | SH, 8 },
        { "RightAlt+",         RA,          3 },
        { "RightCtrl+",        RC,          5 },
    };
    ULONG i, m;
    CHAR Name[64];
    KEYCASE Case;

    for (i = 0; i < _countof(Keys); ++i)
    {
        for (m = 0; m < _countof(Modifiers); ++m)
        {
            wsprintfA(Name, "%s%s", Modifiers[m].Name, Keys[i].Name);
            Case.Name = Name;
            Case.Vk = Keys[i].Vk;
            Case.Scan = Keys[i].Scan;
            Case.Char = 0;
            Case.State = Modifiers[m].State | EN;
            Case.Seq = Modifiers[m].Modifier == 1 ? Keys[i].Plain : Sequence(Keys[i].Format, Modifiers[m].Modifier);
            CheckKey(&Case, FALSE);
            CheckKey(&Case, TRUE);
        }
    }
}

static VOID
TestFunctionKeys(VOID)
{
    static const struct { WORD Scan; PCWSTR Plain; PCWSTR Format; } Keys[12] =
    {
        { 0x3B, L"\x1BOP", L"\x1B[1;%uP" }, { 0x3C, L"\x1BOQ", L"\x1B[1;%uQ" },
        { 0x3D, L"\x1BOR", L"\x1B[1;%uR" }, { 0x3E, L"\x1BOS", L"\x1B[1;%uS" },
        { 0x3F, L"\x1B[15~", L"\x1B[15;%u~" }, { 0x40, L"\x1B[17~", L"\x1B[17;%u~" },
        { 0x41, L"\x1B[18~", L"\x1B[18;%u~" }, { 0x42, L"\x1B[19~", L"\x1B[19;%u~" },
        { 0x43, L"\x1B[20~", L"\x1B[20;%u~" }, { 0x44, L"\x1B[21~", L"\x1B[21;%u~" },
        { 0x57, L"\x1B[23~", L"\x1B[23;%u~" }, { 0x58, L"\x1B[24~", L"\x1B[24;%u~" },
    };
    static const struct { PCSTR Name; DWORD State; ULONG Modifier; } Modifiers[] =
    {
        { "", 0, 1 }, { "Shift+", SH, 2 }, { "Alt+", LA, 3 }, { "Ctrl+", LC, 5 },
        { "Ctrl+Shift+", LC | SH, 6 }, { "Ctrl+Alt+", LC | LA, 7 }, { "Ctrl+Alt+Shift+", LC | LA | SH, 8 },
    };
    ULONG i, m;
    CHAR Name[64];
    KEYCASE Case;

    for (i = 0; i < 12; ++i)
    {
        for (m = 0; m < _countof(Modifiers); ++m)
        {
            wsprintfA(Name, "%sF%lu", Modifiers[m].Name, i + 1);
            Case.Name = Name;
            Case.Vk = (WORD)(VK_F1 + i);
            Case.Scan = Keys[i].Scan;
            Case.Char = 0;
            Case.State = Modifiers[m].State;
            Case.Seq = Modifiers[m].Modifier == 1 ? Keys[i].Plain : Sequence(Keys[i].Format, Modifiers[m].Modifier);
            CheckKey(&Case, FALSE);
            CheckKey(&Case, TRUE);
        }
    }
}

static VOID
TestCharacters(VOID)
{
    static const KEYCASE Cases[] =
    {
        /* characters */
        { "a",                  'A', 0x1E, L'a',    0,       L"a" },
        { "Shift+a",            'A', 0x1E, L'A',    SH,      L"A" },
        { "CapsLock a",         'A', 0x1E, L'A',    CAPSLOCK_ON, L"A" },
        { "Alt+x",              'X', 0x2D, L'x',    LA,      L"\x1Bx" },
        { "RightAlt+x",         'X', 0x2D, L'x',    RA,      L"\x1Bx" },
        { "Alt+Shift+X",        'X', 0x2D, L'X',    LA | SH, L"\x1BX" },
        { "Alt+1",              '1', 0x02, L'1',    LA,      L"\x1B" L"1" },
        { "Alt+!",              '1', 0x02, L'!',    LA | SH, L"\x1B!" },
        { "Alt+Space",          VK_SPACE, 0x39, L' ', LA,    L"\x1B " },
        { "Alt+e-acute",        0,   0,    0xE9,    LA,      L"\x1B\xE9" },
        { "e-acute",            0,   0,    0xE9,    0,       L"\xE9" },
        { "AltGr @ (RA+LC)",    'Q', 0x10, L'@',    RA | LC | EN, L"@" },
        { "LA+LC @",            'Q', 0x10, L'@',    LA | LC, L"\x1B@" },
        /* control characters */
        { "Ctrl+a",             'A', 0x1E, 1,       LC,      L"\x01" },
        { "RightCtrl+a",        'A', 0x1E, 1,       RC,      L"\x01" },
        { "Ctrl+Shift+a",       'A', 0x1E, 1,       LC | SH, L"\x01" },
        { "Ctrl+Alt+a",         'A', 0x1E, 1,       LC | LA, L"\x1B\x01" },
        { "Ctrl+z",             'Z', 0x2C, 0x1A,    LC,      L"\x1A" },
        { "Ctrl+C",             'C', 0x2E, 3,       LC,      L"\x03" },
        { "Ctrl+^",             '6', 0x07, 0x1E,    LC | SH, L"\x1E" },
        { "Ctrl+[",             0xDB, 0x1A, 0x1B,   LC,      PASS },
        { "Ctrl+\\",            0xDC, 0x2B, 0x1C,   LC,      PASS },
        { "Ctrl+]",             0xDD, 0x1B, 0x1D,   LC,      PASS },
        { "Ctrl+_",             0xBD, 0x0C, 0x1F,   LC | SH, PASS },
        { "Ctrl+/ no char",     0xBF, 0x35, 0,      LC,      L"\x1F" },
        { "Ctrl+? no char",     0xBF, 0x35, 0,      LC | SH, L"\x1F" },
        { "Ctrl+Space",         VK_SPACE, 0x39, L' ', LC,    NULREC },
        { "Ctrl+2 no char",     '2', 0x03, 0,       LC,      NULREC },
        { "Ctrl+@ no char",     '2', 0x03, 0,       LC | SH, NULREC },
        { "Ctrl+Alt+Space",     VK_SPACE, 0x39, 0,  LC | LA, L"\x1B" NULCH },
        /* letters and digits without a character */
        { "a no char",          'A', 0x1E, 0,       0,       DROP },
        { "Shift+a no char",    'A', 0x1E, 0,       SH,      DROP },
        { "Alt+x no char",      'X', 0x2D, 0,       LA,      DROP },
        { "Ctrl+a no char",     'A', 0x1E, 0,       LC,      DROP },
        { "Ctrl+Alt+x no char", 'X', 0x2D, 0,       LC | LA, L"\x1B\x18" },
        { "Ctrl+Alt+Shift+a no char", 'A', 0x1E, 0, LC | LA | SH, L"\x1B\x01" },
        { "Ctrl+3 no char",     '3', 0x04, 0,       LC,      DROP },
        { "Ctrl+8 no char",     '8', 0x09, 0,       LC,      DROP },
        /* editing keys */
        { "Tab",                VK_TAB, 0x0F, L'\t', 0,      L"\t" },
        { "Tab no char",        VK_TAB, 0x0F, 0,    0,       L"\t" },
        { "Shift+Tab",          VK_TAB, 0x0F, L'\t', SH,     L"\x1B[Z" },
        { "Ctrl+Tab",           VK_TAB, 0x0F, L'\t', LC,     L"\t" },
        { "Ctrl+Shift+Tab",     VK_TAB, 0x0F, L'\t', LC | SH, L"\t" },
        { "Alt+Tab",            VK_TAB, 0x0F, L'\t', LA,     L"\x1B\t" },
        { "Alt+Shift+Tab",      VK_TAB, 0x0F, L'\t', LA | SH, L"\x1B\t" },
        { "Backspace",          VK_BACK, 0x0E, L'\b', 0,     L"\x7F" },
        { "Backspace no char",  VK_BACK, 0x0E, 0,   0,       L"\x7F" },
        { "Shift+Backspace",    VK_BACK, 0x0E, L'\b', SH,    L"\x7F" },
        { "Ctrl+Backspace",     VK_BACK, 0x0E, 0x7F, LC,     L"\b" },
        { "Ctrl+Shift+Backspace", VK_BACK, 0x0E, 0x7F, LC | SH, L"\x7F" },
        { "Alt+Backspace",      VK_BACK, 0x0E, L'\b', LA,    L"\x1B\x7F" },
        { "Ctrl+Alt+Backspace", VK_BACK, 0x0E, 0x7F, LC | LA, L"\x1B\b" },
        { "Escape",             VK_ESCAPE, 0x01, 0x1B, 0,    L"\x1B" },
        { "Escape no char",     VK_ESCAPE, 0x01, 0, 0,       L"\x1B" },
        { "Alt+Escape",         VK_ESCAPE, 0x01, 0x1B, LA,   L"\x1B\x1B" },
        { "Pause",              VK_PAUSE, 0x45, 0,  0,       L"\x1A" },
        { "Enter",              VK_RETURN, 0x1C, L'\r', 0,   PASS },
        { "Shift+Enter",        VK_RETURN, 0x1C, L'\r', SH,  PASS },
        { "Ctrl+Enter",         VK_RETURN, 0x1C, L'\n', LC,  PASS },
        { "Numpad Enter",       VK_RETURN, 0x1C, L'\r', EN,  PASS },
        { "Alt+Enter",          VK_RETURN, 0x1C, L'\r', LA,  L"\x1B\r" },
        { "Alt+Ctrl+Enter",     VK_RETURN, 0x1C, L'\n', LC | LA, L"\x1B\n" },
        { "Space",              VK_SPACE, 0x39, L' ', 0,     PASS },
        { "Ctrl+Space no char", VK_SPACE, 0x39, 0,  LC,      PASS },
        /* keys without a sequence */
        { "Shift",              VK_SHIFT, 0x2A, 0,  SH,      PASS },
        { "Ctrl",               VK_CONTROL, 0x1D, 0, LC,     PASS },
        { "Alt",                VK_MENU, 0x38, 0,   LA,      PASS },
        { "Win",                VK_LWIN, 0x5B, 0,   EN,      PASS },
        { "Apps",               VK_APPS, 0x5D, 0,   EN,      PASS },
        { "F13",                VK_F13, 0x64, 0,    0,       PASS },
        { "Clear",              VK_CLEAR, 0x4C, 0,  0,       PASS },
        { "Numpad 8",           VK_NUMPAD8, 0x48, L'8', NL,  PASS },
        { "Numpad *",           VK_MULTIPLY, 0x37, L'*', 0,  PASS },
        { "Numpad /",           VK_DIVIDE, 0x35, L'/', EN,   PASS },
        { "Numpad .",           VK_DECIMAL, 0x53, L'.', NL,  PASS },
        { "Ctrl+Space ch=0 +Shift", VK_SPACE, 0x39, 0, LC | SH, PASS },
        { "Up with character",  VK_UP, 0x48, L'A',  EN,      L"\x1B[A" },
        { "F1 with character",  VK_F1, 0x3B, L'p',  0,       L"\x1BOP" },
        { "Delete with 7F",     VK_DELETE, 0x53, 0x7F, EN,   L"\x1B[3~" },
        { "Home no EN",         VK_HOME, 0x47, 0,   0,       L"\x1B[H" },
        { "Up numlock",         VK_UP, 0x48, 0,     EN | NL, L"\x1B[A" },
    };

    CheckKeys(Cases, _countof(Cases));
}

static VOID
Say(PCSTR Text)
{
    DWORD Written;
    WriteFile(hOut, Text, lstrlenA(Text), &Written, NULL);
}

static VOID
TestApplicationCursorKeys(VOID)
{
    static const KEYCASE On[] =
    {
        { "DECCKM Up",          VK_UP, 0x48, 0,     EN,      L"\x1BOA" },
        { "DECCKM Down",        VK_DOWN, 0x50, 0,   EN,      L"\x1BOB" },
        { "DECCKM Right",       VK_RIGHT, 0x4D, 0,  EN,      L"\x1BOC" },
        { "DECCKM Left",        VK_LEFT, 0x4B, 0,   EN,      L"\x1BOD" },
        { "DECCKM Home",        VK_HOME, 0x47, 0,   EN,      L"\x1BOH" },
        { "DECCKM End",         VK_END, 0x4F, 0,    EN,      L"\x1BOF" },
        { "DECCKM PgUp",        VK_PRIOR, 0x49, 0,  EN,      L"\x1B[5~" },
        { "DECCKM Insert",      VK_INSERT, 0x52, 0, EN,      L"\x1B[2~" },
        { "DECCKM Delete",      VK_DELETE, 0x53, 0, EN,      L"\x1B[3~" },
        { "DECCKM F1",          VK_F1, 0x3B, 0,     0,       L"\x1BOP" },
        { "DECCKM F5",          VK_F5, 0x3F, 0,     0,       L"\x1B[15~" },
        { "DECCKM Ctrl+Right",  VK_RIGHT, 0x4D, 0,  LC | EN, L"\x1B[1;5C" },
        { "DECCKM Shift+Up",    VK_UP, 0x48, 0,     SH | EN, L"\x1B[1;2A" },
        { "DECCKM Alt+Home",    VK_HOME, 0x47, 0,   LA | EN, L"\x1B[1;3H" },
    };
    static const KEYCASE Off[] =
    {
        { "no DECCKM Up",       VK_UP, 0x48, 0,     EN,      L"\x1B[A" },
        { "no DECCKM Home",     VK_HOME, 0x47, 0,   EN,      L"\x1B[H" },
    };
    DWORD OutMode = 0;
    INPUT_RECORD In[2], Out[16];
    DWORD Written, Count;

    GetConsoleMode(hOut, &OutMode);
    SetConsoleMode(hOut, OutMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT);
    Say("\x1B[?1h");
    CheckKeys(On, _countof(On));

    /* The state belongs to the console, not to the input mode */
    SetConsoleMode(hIn, 0);
    MakeKey(&In[0], TRUE, VK_UP, 0x48, 0, EN);
    FlushConsoleInputBuffer(hIn);
    WriteConsoleInputW(hIn, In, 1, &Written);
    Count = ReadAll(Out, _countof(Out));
    ok(Count == 1 && SameKey(&Out[0], &In[0]), "Without the mode the Up event changed (%lu events)\n", Count);
    SetConsoleMode(hIn, ENABLE_VIRTUAL_TERMINAL_INPUT);
    CheckKey(&On[0], FALSE);

    Say("\x1B[?1l");
    CheckKeys(Off, _countof(Off));

    Say("\x1B[?1h");
    Say("\x1B" "c");    /* RIS: also resets the cursor keys mode */
    CheckKeys(Off, _countof(Off));
    SetConsoleMode(hOut, OutMode);
}

static VOID
TestEventHandling(VOID)
{
    INPUT_RECORD In[4], Out[32];
    DWORD Written = 0, Count, i, Read;
    CHAR Text[64];
    BOOL Success;

    /* key-up events and other events pass unchanged, in order */
    FlushConsoleInputBuffer(hIn);
    MakeKey(&In[0], TRUE, VK_UP, 0x48, 0, EN);
    ZeroMemory(&In[1], sizeof(In[1]));
    In[1].EventType = FOCUS_EVENT;
    In[1].Event.FocusEvent.bSetFocus = TRUE;
    MakeKey(&In[2], TRUE, 'A', 0x1E, L'a', 0);
    MakeKey(&In[3], FALSE, VK_UP, 0x48, 0, EN);
    Success = WriteConsoleInputW(hIn, In, 4, &Written);
    ok(Success && Written == 4, "WriteConsoleInputW of 4 events returned %d, %lu\n", Success, Written);
    Count = ReadAll(Out, _countof(Out));
    ok(Count == 6, "%lu events queued, expected 3 + 1 + 1 + 1\n", Count);
    if (Count == 6)
    {
        ok(Out[0].Event.KeyEvent.uChar.UnicodeChar == 0x1B && Out[1].Event.KeyEvent.uChar.UnicodeChar == '[' &&
           Out[2].Event.KeyEvent.uChar.UnicodeChar == 'A', "The first three events are not ESC [ A\n");
        ok(Out[3].EventType == FOCUS_EVENT, "The focus event is event type %u\n", Out[3].EventType);
        ok(Out[4].EventType == KEY_EVENT && Out[4].Event.KeyEvent.uChar.UnicodeChar == 'a', "Event 4 is not 'a'\n");
        ok(SameKey(&Out[5], &In[3]), "The key-up event was changed\n");
    }

    /* Peek and count see the translated events; one at a time they come in order */
    FlushConsoleInputBuffer(hIn);
    MakeKey(&In[0], TRUE, VK_UP, 0x48, 0, EN);
    MakeKey(&In[1], FALSE, VK_UP, 0x48, 0, EN);
    WriteConsoleInputW(hIn, In, 2, &Written);
    ok(Pending() == 4, "%lu events pending, expected 4\n", Pending());
    Read = 0;
    Success = PeekConsoleInputW(hIn, Out, _countof(Out), &Read);
    ok(Success && Read == 4, "PeekConsoleInputW returned %d, %lu events\n", Success, Read);
    for (i = 0; i < 4; ++i)
    {
        Read = 0;
        Success = ReadConsoleInputW(hIn, Out, 1, &Read);
        ok(Success && Read == 1, "Single read %lu returned %d, %lu\n", i, Success, Read);
        if (i < 3)
            ok(Out[0].Event.KeyEvent.bKeyDown && Out[0].Event.KeyEvent.wVirtualKeyCode == 0 &&
               Out[0].Event.KeyEvent.uChar.UnicodeChar == (i == 0 ? 0x1B : (i == 1 ? '[' : 'A')),
               "Single read %lu returned char %04X\n", i, Out[0].Event.KeyEvent.uChar.UnicodeChar);
        else
            ok(!Out[0].Event.KeyEvent.bKeyDown && Out[0].Event.KeyEvent.wVirtualKeyCode == VK_UP,
               "The last event is not the Up key-up event\n");
    }

    /* ReadConsoleW with a small buffer returns the rest later */
    FlushConsoleInputBuffer(hIn);
    WriteConsoleInputW(hIn, In, 1, &Written);
    {
        WCHAR Chars[8];
        DWORD First = 0, Second = 0;

        Success = ReadConsoleW(hIn, Chars, 2, &First, NULL);
        ok(Success && First == 2 && Chars[0] == 0x1B && Chars[1] == '[', "First ReadConsoleW: %d, %lu chars\n", Success, First);
        Success = ReadConsoleW(hIn, Chars, 8, &Second, NULL);
        ok(Success && Second == 1 && Chars[0] == 'A', "Second ReadConsoleW: %d, %lu chars\n", Success, Second);
    }

    /* The ANSI functions */
    FlushConsoleInputBuffer(hIn);
    Success = WriteConsoleInputA(hIn, In, 1, &Written);
    ok(Success && Written == 1, "WriteConsoleInputA returned %d, %lu\n", Success, Written);
    Read = 0;
    Success = ReadConsoleInputA(hIn, Out, _countof(Out), &Read);
    ok(Success && Read == 3, "ReadConsoleInputA returned %d, %lu events\n", Success, Read);
    if (Read == 3)
    {
        Text[0] = Out[0].Event.KeyEvent.uChar.AsciiChar;
        Text[1] = Out[1].Event.KeyEvent.uChar.AsciiChar;
        Text[2] = Out[2].Event.KeyEvent.uChar.AsciiChar;
        ok(Text[0] == 0x1B && Text[1] == '[' && Text[2] == 'A', "ReadConsoleInputA characters are %02X %02X %02X\n",
           Text[0], Text[1], Text[2]);
    }
    FlushConsoleInputBuffer(hIn);
}

START_TEST(ConsoleVirtualTerminalInput)
{
    DWORD SavedIn = 0, SavedOut = 0;

    hIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING, 0, NULL);
    hOut = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE)
    {
        skip("No console (error %lu)\n", GetLastError());
        return;
    }
    GetConsoleMode(hIn, &SavedIn);
    GetConsoleMode(hOut, &SavedOut);

    TestMode();
    if (!SetConsoleMode(hIn, ENABLE_VIRTUAL_TERMINAL_INPUT))
    {
        skip("ENABLE_VIRTUAL_TERMINAL_INPUT is not supported\n");
    }
    else
    {
        TestNavigation();
        TestFunctionKeys();
        TestCharacters();
        TestEventHandling();
        TestApplicationCursorKeys();
    }

    SetConsoleMode(hIn, SavedIn);
    SetConsoleMode(hOut, SavedOut);
    FlushConsoleInputBuffer(hIn);
    CloseHandle(hIn);
    CloseHandle(hOut);
}
