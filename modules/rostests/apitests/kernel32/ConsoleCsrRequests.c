/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test one call of each console request a console program makes, in a console of its own
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/pstypes.h>

/*
 * Every console request goes through CSR, and under WoW64 through a translation of the i386
 * request into the native one. Each request is called once with an inline-sized and, where
 * the request has one, a capture-buffer-sized transfer, and the effect is read back. The
 * expectations are those of Windows 10, for both PE32 and PE32+ builds. The calls run in a
 * child process with a new console, so the test does not depend on (or change) the console of
 * the test runner.
 *
 * The requests that reach the console window (icon, cursor, palette, menu, DIB bits, hardware
 * state) are the exception: the Windows 10 22H2 console host fails all of them with error 16385,
 * for a 32-bit and a 64-bit process alike, and ReactOS does not. Their expected results are
 * given for both systems (TestWindowRequests). A 32-bit process under WoW64 on ReactOS used to
 * get error 50 (ERROR_NOT_SUPPORTED) from each, as the request was not passed to the server.
 */
#define CHILD_TIMEOUT_MS 60000

#ifndef VK_RETURN
#define VK_RETURN 0x0D
#endif

/* Vista+ (CONSOLE_HISTORY_INFO) */
typedef struct
{
    UINT cbSize;
    UINT HistoryBufferSize;
    UINT NumberOfHistoryBuffers;
    DWORD dwFlags;
} HISTORY_INFO;

/* The child's standard handles are the report pipe: the console is reached by name */
static HANDLE hOut, hIn, hFirst;

static
VOID
WriteKeys(
    _In_ PCSTR Keys)
{
    /* A key down and a key up record per character, written in batches */
    while (*Keys)
    {
        INPUT_RECORD Records[32];
        DWORD Count = 0, Written;

        for (; *Keys && Count < _countof(Records); Keys++)
        {
            RtlZeroMemory(&Records[Count], sizeof(Records[Count]));
            Records[Count].EventType = KEY_EVENT;
            Records[Count].Event.KeyEvent.bKeyDown = TRUE;
            Records[Count].Event.KeyEvent.wRepeatCount = 1;
            Records[Count].Event.KeyEvent.wVirtualKeyCode =
                (*Keys == '\r') ? VK_RETURN : (WORD)((*Keys >= 'a' && *Keys <= 'z') ? *Keys - 'a' + 'A' : *Keys);
            Records[Count].Event.KeyEvent.uChar.UnicodeChar = (WCHAR)*Keys;
            Count++;
            Records[Count] = Records[Count - 1];
            Records[Count].Event.KeyEvent.bKeyDown = FALSE;
            Count++;
        }
        ok(WriteConsoleInputW(hIn, Records, Count, &Written), "WriteConsoleInputW failed with %lu\n", GetLastError());
        ok(Written == Count, "WriteConsoleInputW wrote %lu of %lu records\n", Written, Count);
    }
}

static
VOID
TestScreenBuffer(VOID)
{
    CONSOLE_SCREEN_BUFFER_INFO Info;
    CONSOLE_CURSOR_INFO Cursor;
    COORD Size = { 130, 200 }, Position = { 7, 12 }, Largest;
    SMALL_RECT Window = { 0, 10, 39, 19 };
    BOOL Success;

    Success = SetConsoleScreenBufferSize(hOut, Size);
    ok(Success, "SetConsoleScreenBufferSize failed with %lu\n", GetLastError());
    ok(GetConsoleScreenBufferInfo(hOut, &Info), "GetConsoleScreenBufferInfo failed with %lu\n", GetLastError());
    ok(Info.dwSize.X == 130 && Info.dwSize.Y == 200, "Buffer size %dx%d\n", Info.dwSize.X, Info.dwSize.Y);

    Success = SetConsoleWindowInfo(hOut, TRUE, &Window);
    ok(Success, "SetConsoleWindowInfo failed with %lu\n", GetLastError());
    GetConsoleScreenBufferInfo(hOut, &Info);
    ok(Info.srWindow.Left == 0 && Info.srWindow.Top == 10 && Info.srWindow.Right == 39 && Info.srWindow.Bottom == 19,
       "Window %d,%d,%d,%d\n", Info.srWindow.Left, Info.srWindow.Top, Info.srWindow.Right, Info.srWindow.Bottom);

    Largest = GetLargestConsoleWindowSize(hOut);
    ok(Largest.X > 0 && Largest.Y > 0, "Largest window %dx%d, error %lu\n", Largest.X, Largest.Y, GetLastError());

    Success = SetConsoleCursorPosition(hOut, Position);
    ok(Success, "SetConsoleCursorPosition failed with %lu\n", GetLastError());
    GetConsoleScreenBufferInfo(hOut, &Info);
    ok(Info.dwCursorPosition.X == 7 && Info.dwCursorPosition.Y == 12, "Cursor at %d,%d\n",
       Info.dwCursorPosition.X, Info.dwCursorPosition.Y);

    Cursor.dwSize = 0;
    ok(GetConsoleCursorInfo(hOut, &Cursor), "GetConsoleCursorInfo failed with %lu\n", GetLastError());
    ok(Cursor.dwSize >= 1 && Cursor.dwSize <= 100, "Cursor size %lu\n", Cursor.dwSize);
    Cursor.dwSize = 50;
    Cursor.bVisible = FALSE;
    ok(SetConsoleCursorInfo(hOut, &Cursor), "SetConsoleCursorInfo failed with %lu\n", GetLastError());
    Cursor.dwSize = 0;
    Cursor.bVisible = TRUE;
    GetConsoleCursorInfo(hOut, &Cursor);
    ok(Cursor.dwSize == 50 && !Cursor.bVisible, "Cursor size %lu, visible %d\n", Cursor.dwSize, Cursor.bVisible);

    ok(SetConsoleTextAttribute(hOut, 0x1e), "SetConsoleTextAttribute failed with %lu\n", GetLastError());
    GetConsoleScreenBufferInfo(hOut, &Info);
    ok(Info.wAttributes == 0x1e, "Attributes 0x%x\n", Info.wAttributes);
}

static
VOID
TestOutputStrings(VOID)
{
    COORD Origin = { 0, 0 }, At;
    CHAR Chars[160];
    WCHAR WChars[130];
    WORD Attributes[200];
    DWORD Count, i;

    ok(FillConsoleOutputCharacterA(hOut, 'x', 300, Origin, &Count) && Count == 300,
       "FillConsoleOutputCharacterA: %lu, error %lu\n", Count, GetLastError());
    ok(FillConsoleOutputCharacterW(hOut, L'y', 100, Origin, &Count) && Count == 100,
       "FillConsoleOutputCharacterW: %lu, error %lu\n", Count, GetLastError());
    ok(FillConsoleOutputAttribute(hOut, 0x2a, 150, Origin, &Count) && Count == 150,
       "FillConsoleOutputAttribute: %lu, error %lu\n", Count, GetLastError());
    At.X = 99; At.Y = 0;
    ok(ReadConsoleOutputCharacterA(hOut, Chars, 2, At, &Count) && Count == 2 && Chars[0] == 'y' && Chars[1] == 'x',
       "Filled cells '%.2s' (%lu)\n", Chars, Count);
    ok(ReadConsoleOutputAttribute(hOut, Attributes, 1, At, &Count) && Attributes[0] == 0x2a,
       "Filled attribute 0x%x\n", Attributes[0]);

    /* 5 characters fit in the request; 150 bytes do not */
    At.X = 0; At.Y = 1;
    ok(WriteConsoleOutputCharacterA(hOut, "hello", 5, At, &Count) && Count == 5,
       "WriteConsoleOutputCharacterA(5): %lu, error %lu\n", Count, GetLastError());
    RtlFillMemory(Chars, 150, 'Q');
    At.Y = 2;
    ok(WriteConsoleOutputCharacterA(hOut, Chars, 150, At, &Count) && Count == 150,
       "WriteConsoleOutputCharacterA(150): %lu, error %lu\n", Count, GetLastError());
    At.Y = 4;
    ok(WriteConsoleOutputCharacterW(hOut, L"world", 5, At, &Count) && Count == 5,
       "WriteConsoleOutputCharacterW(5): %lu, error %lu\n", Count, GetLastError());
    for (i = 0; i < 120; i++)
        WChars[i] = L'a' + (WCHAR)(i % 26);
    At.Y = 5;
    ok(WriteConsoleOutputCharacterW(hOut, WChars, 120, At, &Count) && Count == 120,
       "WriteConsoleOutputCharacterW(120): %lu, error %lu\n", Count, GetLastError());
    for (i = 0; i < 200; i++)
        Attributes[i] = (WORD)(i & 0xff);
    At.Y = 7;
    ok(WriteConsoleOutputAttribute(hOut, Attributes + 1, 3, At, &Count) && Count == 3,
       "WriteConsoleOutputAttribute(3): %lu, error %lu\n", Count, GetLastError());
    At.Y = 8;
    ok(WriteConsoleOutputAttribute(hOut, Attributes, 200, At, &Count) && Count == 200,
       "WriteConsoleOutputAttribute(200): %lu, error %lu\n", Count, GetLastError());

    RtlZeroMemory(Chars, sizeof(Chars));
    At.Y = 1;
    ok(ReadConsoleOutputCharacterA(hOut, Chars, 5, At, &Count) && Count == 5 && !strcmp(Chars, "hello"),
       "ReadConsoleOutputCharacterA(5): '%s' (%lu), error %lu\n", Chars, Count, GetLastError());
    RtlZeroMemory(Chars, sizeof(Chars));
    At.Y = 2;
    ok(ReadConsoleOutputCharacterA(hOut, Chars, 150, At, &Count) && Count == 150 && strspn(Chars, "Q") == 150,
       "ReadConsoleOutputCharacterA(150): %Iu Qs (%lu), error %lu\n", strspn(Chars, "Q"), Count, GetLastError());
    RtlZeroMemory(WChars, sizeof(WChars));
    At.Y = 4;
    ok(ReadConsoleOutputCharacterW(hOut, WChars, 5, At, &Count) && Count == 5 && !wcscmp(WChars, L"world"),
       "ReadConsoleOutputCharacterW(5): '%ls' (%lu), error %lu\n", WChars, Count, GetLastError());
    RtlZeroMemory(WChars, sizeof(WChars));
    At.Y = 5;
    ok(ReadConsoleOutputCharacterW(hOut, WChars, 120, At, &Count) && Count == 120 &&
       WChars[0] == L'a' && WChars[119] == L'p',
       "ReadConsoleOutputCharacterW(120): '%lc'..'%lc' (%lu), error %lu\n", WChars[0], WChars[119], Count, GetLastError());
    RtlZeroMemory(Attributes, sizeof(Attributes));
    At.Y = 7;
    ok(ReadConsoleOutputAttribute(hOut, Attributes, 3, At, &Count) && Count == 3 &&
       Attributes[0] == 1 && Attributes[1] == 2 && Attributes[2] == 3,
       "ReadConsoleOutputAttribute(3): %x %x %x (%lu), error %lu\n", Attributes[0], Attributes[1], Attributes[2],
       Count, GetLastError());
    RtlZeroMemory(Attributes, sizeof(Attributes));
    At.Y = 8;
    ok(ReadConsoleOutputAttribute(hOut, Attributes, 200, At, &Count) && Count == 200 &&
       Attributes[150] == 150 && Attributes[199] == 199,
       "ReadConsoleOutputAttribute(200): %x %x (%lu), error %lu\n", Attributes[150], Attributes[199],
       Count, GetLastError());
}

static
VOID
TestOutputRegions(VOID)
{
    static CHAR_INFO Large[200 * 100];
    CHAR_INFO Cells[30 * 4], One;
    COORD BufferSize = { 30, 4 }, OneCell = { 1, 1 }, Origin = { 0, 0 }, Size = { 200, 100 }, At = { 199, 99 };
    SMALL_RECT Region = { 2, 10, 31, 13 }, Scroll = { 0, 1, 9, 1 }, Clip = { 0, 0, 199, 99 };
    CHAR_INFO Fill;
    CHAR Chars[8] = "";
    DWORD Count, i;

    for (i = 0; i < _countof(Cells); i++)
    {
        Cells[i].Char.UnicodeChar = L'A' + (WCHAR)(i % 26);
        Cells[i].Attributes = 0x4f;
    }
    ok(WriteConsoleOutputW(hOut, Cells, BufferSize, Origin, &Region), "WriteConsoleOutputW(30x4) failed with %lu\n",
       GetLastError());
    ok(Region.Left == 2 && Region.Top == 10 && Region.Right == 31 && Region.Bottom == 13,
       "Written region %d,%d,%d,%d\n", Region.Left, Region.Top, Region.Right, Region.Bottom);
    One.Char.AsciiChar = '#';
    One.Attributes = 0x5e;
    Region.Left = Region.Right = 5;
    Region.Top = Region.Bottom = 15;
    ok(WriteConsoleOutputA(hOut, &One, OneCell, Origin, &Region), "WriteConsoleOutputA(1x1) failed with %lu\n",
       GetLastError());

    RtlZeroMemory(Cells, sizeof(Cells));
    Region.Left = 2; Region.Top = 10; Region.Right = 31; Region.Bottom = 13;
    ok(ReadConsoleOutputW(hOut, Cells, BufferSize, Origin, &Region), "ReadConsoleOutputW(30x4) failed with %lu\n",
       GetLastError());
    ok(Region.Left == 2 && Region.Top == 10 && Region.Right == 31 && Region.Bottom == 13,
       "Read region %d,%d,%d,%d\n", Region.Left, Region.Top, Region.Right, Region.Bottom);
    ok(Cells[0].Char.UnicodeChar == L'A' && Cells[0].Attributes == 0x4f && Cells[119].Char.UnicodeChar == L'P',
       "Read cells '%lc' 0x%x .. '%lc'\n", Cells[0].Char.UnicodeChar, Cells[0].Attributes, Cells[119].Char.UnicodeChar);
    RtlZeroMemory(&One, sizeof(One));
    Region.Left = Region.Right = 5;
    Region.Top = Region.Bottom = 15;
    ok(ReadConsoleOutputA(hOut, &One, OneCell, Origin, &Region), "ReadConsoleOutputA(1x1) failed with %lu\n",
       GetLastError());
    ok(One.Char.AsciiChar == '#' && One.Attributes == 0x5e, "Read cell '%c' 0x%x\n", One.Char.AsciiChar, One.Attributes);

    /* 80000 bytes: more than a CSR capture buffer holds */
    ok(SetConsoleScreenBufferSize(hOut, Size), "SetConsoleScreenBufferSize failed with %lu\n", GetLastError());
    for (i = 0; i < _countof(Large); i++)
    {
        Large[i].Char.UnicodeChar = L'0' + (WCHAR)(i % 10);
        Large[i].Attributes = 7;
    }
    Region.Left = 0; Region.Top = 0; Region.Right = 199; Region.Bottom = 99;
    ok(WriteConsoleOutputW(hOut, Large, Size, Origin, &Region), "WriteConsoleOutputW(200x100) failed with %lu\n",
       GetLastError());
    ok(Region.Right == 199 && Region.Bottom == 99, "Written region %d,%d\n", Region.Right, Region.Bottom);
    ok(ReadConsoleOutputCharacterA(hOut, Chars, 1, At, &Count) && Chars[0] == '9', "Last cell '%c'\n", Chars[0]);

    Fill.Char.UnicodeChar = L'.';
    Fill.Attributes = 7;
    At.X = 0; At.Y = 20;
    ok(ScrollConsoleScreenBufferW(hOut, &Scroll, &Clip, At, &Fill), "ScrollConsoleScreenBufferW failed with %lu\n",
       GetLastError());
    RtlZeroMemory(Chars, sizeof(Chars));
    ReadConsoleOutputCharacterA(hOut, Chars, 5, At, &Count);
    ok(!strcmp(Chars, "01234"), "Scrolled to '%s'\n", Chars);
    Fill.Char.AsciiChar = ',';
    At.Y = 21;
    ok(ScrollConsoleScreenBufferA(hOut, &Scroll, NULL, At, &Fill), "ScrollConsoleScreenBufferA failed with %lu\n",
       GetLastError());
    At.X = 0; At.Y = 1;
    ReadConsoleOutputCharacterA(hOut, Chars, 1, At, &Count);
    ok(Chars[0] == ',', "Scroll source filled with '%c'\n", Chars[0]);
}

static
VOID
TestTitle(VOID)
{
    CHAR Title[64] = "";
    WCHAR WTitle[64] = L"";

    ok(SetConsoleTitleA("console csr title A"), "SetConsoleTitleA failed with %lu\n", GetLastError());
    ok(GetConsoleTitleA(Title, sizeof(Title)) == 19 && !strcmp(Title, "console csr title A"),
       "GetConsoleTitleA: '%s'\n", Title);
    ok(SetConsoleTitleW(L"console csr title W"), "SetConsoleTitleW failed with %lu\n", GetLastError());
    ok(GetConsoleTitleW(WTitle, _countof(WTitle)) == 19 && !wcscmp(WTitle, L"console csr title W"),
       "GetConsoleTitleW: '%ls'\n", WTitle);
}

static
VOID
TestInput(VOID)
{
    INPUT_RECORD Records[16];
    CHAR Chars[32] = "";
    WCHAR WChars[200];
    DWORD Count, Mode;

    ok(FlushConsoleInputBuffer(hIn), "FlushConsoleInputBuffer failed with %lu\n", GetLastError());
    ok(GetNumberOfConsoleInputEvents(hIn, &Count) && Count == 0, "%lu input events, error %lu\n", Count, GetLastError());
    WriteKeys("ab"); /* 4 records fit in the request */
    ok(GetNumberOfConsoleInputEvents(hIn, &Count) && Count == 4, "%lu input events\n", Count);
    RtlZeroMemory(Records, sizeof(Records));
    ok(PeekConsoleInputW(hIn, Records, 16, &Count) && Count == 4 && Records[0].Event.KeyEvent.uChar.UnicodeChar == L'a',
       "PeekConsoleInputW: %lu, error %lu\n", Count, GetLastError());
    RtlZeroMemory(Records, sizeof(Records));
    ok(ReadConsoleInputW(hIn, Records, 16, &Count) && Count == 4 && Records[2].Event.KeyEvent.uChar.UnicodeChar == L'b',
       "ReadConsoleInputW: %lu, error %lu\n", Count, GetLastError());
    WriteKeys("abcd"); /* 8 records do not */
    RtlZeroMemory(Records, sizeof(Records));
    ok(ReadConsoleInputA(hIn, Records, 3, &Count) && Count == 3 && Records[0].Event.KeyEvent.uChar.AsciiChar == 'a',
       "ReadConsoleInputA: %lu, error %lu\n", Count, GetLastError());
    RtlZeroMemory(Records, sizeof(Records));
    ok(ReadConsoleInputW(hIn, Records, 16, &Count) && Count == 5 && Records[4].Event.KeyEvent.uChar.UnicodeChar == L'd',
       "ReadConsoleInputW: %lu, error %lu\n", Count, GetLastError());

    GetConsoleMode(hIn, &Mode);
    ok(SetConsoleMode(hIn, ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT), "SetConsoleMode failed with %lu\n", GetLastError());
    FlushConsoleInputBuffer(hIn);
    WriteKeys("hi\r");
    ok(ReadConsoleA(hIn, Chars, 20, &Count, NULL) && Count == 4 && !memcmp(Chars, "hi\r\n", 4),
       "ReadConsoleA: %lu '%.2s', error %lu\n", Count, Chars, GetLastError());
    WriteKeys("0123456789012345678901234567890123456789012345678901234567890\r");
    RtlZeroMemory(WChars, sizeof(WChars));
    ok(ReadConsoleW(hIn, WChars, _countof(WChars), &Count, NULL) && Count == 63 &&
       WChars[0] == L'0' && WChars[60] == L'0' && WChars[62] == L'\n',
       "ReadConsoleW: %lu, error %lu\n", Count, GetLastError());
    SetConsoleMode(hIn, Mode);
    FlushConsoleInputBuffer(hIn);
}

static
VOID
TestHandles(VOID)
{
    HANDLE hDup = NULL;
    DWORD Flags = 0xdead;

    ok(SetConsoleActiveScreenBuffer(hOut), "SetConsoleActiveScreenBuffer failed with %lu\n", GetLastError());
    ok(SetConsoleActiveScreenBuffer(hFirst), "SetConsoleActiveScreenBuffer failed with %lu\n", GetLastError());
    ok(DuplicateHandle(GetCurrentProcess(), hOut, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS),
       "DuplicateHandle failed with %lu\n", GetLastError());
    ok(GetHandleInformation(hDup, &Flags) && Flags == 0, "GetHandleInformation: 0x%lx, error %lu\n", Flags, GetLastError());
    ok(SetHandleInformation(hDup, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT), "SetHandleInformation failed with %lu\n",
       GetLastError());
    Flags = 0;
    GetHandleInformation(hDup, &Flags);
    ok(Flags == HANDLE_FLAG_INHERIT, "Flags 0x%lx\n", Flags);
    ok(CloseHandle(hDup), "CloseHandle failed with %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ok(!CloseHandle(hDup) && GetLastError() == ERROR_INVALID_HANDLE, "Second CloseHandle: error %lu\n", GetLastError());
}

static
VOID
TestMisc(VOID)
{
    CONSOLE_FONT_INFO Font;
    CONSOLE_SELECTION_INFO Selection;
    HISTORY_INFO History = { sizeof(History) };
    BOOL (WINAPI *pGetHistoryInfo)(HISTORY_INFO *);
    BOOL (WINAPI *pSetHistoryInfo)(HISTORY_INFO *);
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    DWORD Mode = 0xdead, Buttons;

    ok(GetCurrentConsoleFont(hFirst, FALSE, &Font), "GetCurrentConsoleFont failed with %lu\n",
       GetLastError());
    ok(GetConsoleDisplayMode(&Mode) && Mode == 0, "GetConsoleDisplayMode: %lu, error %lu\n", Mode, GetLastError());
    ok(GetNumberOfConsoleMouseButtons(&Buttons), "GetNumberOfConsoleMouseButtons failed with %lu\n", GetLastError());
    Selection.dwFlags = 0xdead;
    ok(GetConsoleSelectionInfo(&Selection) && Selection.dwFlags == 0, "GetConsoleSelectionInfo: 0x%lx, error %lu\n",
       Selection.dwFlags, GetLastError());
    pGetHistoryInfo = (PVOID)GetProcAddress(hKernel32, "GetConsoleHistoryInfo");
    pSetHistoryInfo = (PVOID)GetProcAddress(hKernel32, "SetConsoleHistoryInfo");
    if (!pGetHistoryInfo || !pSetHistoryInfo)
    {
        skip("No GetConsoleHistoryInfo/SetConsoleHistoryInfo\n");
        return;
    }
    ok(pGetHistoryInfo(&History), "GetConsoleHistoryInfo failed with %lu\n", GetLastError());
    ok(History.HistoryBufferSize != 0, "History buffer size %u\n", History.HistoryBufferSize);
    ok(pSetHistoryInfo(&History), "SetConsoleHistoryInfo failed with %lu\n", GetLastError());
}

static
VOID
TestAliasesAndHistory(VOID)
{
    static const WCHAR Expected[] = L"csrx=echo alias\0csry=echo aliasW";
    DWORD (WINAPI *pGetHistoryLength)(LPCWSTR);
    BOOL (WINAPI *pSetNumberOfCommands)(DWORD, LPCWSTR);
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    CHAR Target[64] = "";
    WCHAR WTarget[64] = L"", Aliases[128];
    DWORD Length;

    ok(AddConsoleAliasA("csrx", "echo alias", "csrtest.exe"), "AddConsoleAliasA failed with %lu\n", GetLastError());
    ok(AddConsoleAliasW(L"csry", L"echo aliasW", L"csrtest.exe"), "AddConsoleAliasW failed with %lu\n", GetLastError());
    ok(GetConsoleAliasA("csrx", Target, sizeof(Target), "csrtest.exe") && !strcmp(Target, "echo alias"),
       "GetConsoleAliasA: '%s', error %lu\n", Target, GetLastError());
    ok(GetConsoleAliasW(L"csry", WTarget, sizeof(WTarget), L"csrtest.exe") && !wcscmp(WTarget, L"echo aliasW"),
       "GetConsoleAliasW: '%ls', error %lu\n", WTarget, GetLastError());
    Length = GetConsoleAliasesLengthW(L"csrtest.exe");
    ok(Length == sizeof(Expected), "GetConsoleAliasesLengthW: %lu\n", Length);
    RtlZeroMemory(Aliases, sizeof(Aliases));
    Length = GetConsoleAliasesW(Aliases, sizeof(Aliases), L"csrtest.exe");
    ok(Length == sizeof(Expected) && !memcmp(Aliases, Expected, sizeof(Expected)), "GetConsoleAliasesW: %lu '%ls'\n",
       Length, Aliases);
    Length = GetConsoleAliasExesLengthW();
    ok(Length == sizeof(L"csrtest.exe"), "GetConsoleAliasExesLengthW: %lu\n", Length);
    RtlZeroMemory(Aliases, sizeof(Aliases));
    Length = GetConsoleAliasExesW(Aliases, sizeof(Aliases));
    ok(Length == sizeof(L"csrtest.exe") && !wcscmp(Aliases, L"csrtest.exe"), "GetConsoleAliasExesW: %lu '%ls'\n",
       Length, Aliases);
    ok(GetConsoleAliasExesLengthA() == sizeof("csrtest.exe"), "GetConsoleAliasExesLengthA: %lu\n",
       GetConsoleAliasExesLengthA());
    ok(AddConsoleAliasA("csrx", NULL, "csrtest.exe"), "Removing an alias failed with %lu\n", GetLastError());
    ok(AddConsoleAliasW(L"csry", NULL, L"csrtest.exe"), "Removing an alias failed with %lu\n", GetLastError());

    /* Undocumented */
    pGetHistoryLength = (PVOID)GetProcAddress(hKernel32, "GetConsoleCommandHistoryLengthW");
    pSetNumberOfCommands = (PVOID)GetProcAddress(hKernel32, "SetConsoleNumberOfCommandsW");
    if (pSetNumberOfCommands)
        ok(pSetNumberOfCommands(50, L"csrtest.exe"), "SetConsoleNumberOfCommandsW failed with %lu\n", GetLastError());
    if (pGetHistoryLength)
    {
        SetLastError(0xdeadbeef);
        Length = pGetHistoryLength(L"csrtest.exe");
        ok(Length == 0 && GetLastError() == 0xdeadbeef, "GetConsoleCommandHistoryLengthW: %lu, error %lu\n",
           Length, GetLastError());
    }
}

/* Results of the console window requests: ERR_KEEP is a last error that stays as set before the call */
#define ERR_KEEP 0xdeadbeef
#define ERR_WIN10 16385

static
VOID
CheckBool(
    _In_ PCSTR Name,
    _In_ BOOL Ret,
    _In_ DWORD Error,
    _In_ BOOL ReactOSRet,
    _In_ DWORD ReactOSError,
    _In_ DWORD WindowsError)
{
    BOOL ExpectedRet = is_reactos() ? ReactOSRet : FALSE;
    DWORD ExpectedError = is_reactos() ? ReactOSError : WindowsError;

    ok(Ret == ExpectedRet, "%s returned %d\n", Name, Ret);
    ok(Error == ExpectedError, "%s: error %lu, expected %lu\n", Name, Error, ExpectedError);
}

static
VOID
TestWindowRequests(VOID)
{
    typedef HICON (WINAPI *PLOADICON)(HINSTANCE, LPCWSTR);
    typedef HCURSOR (WINAPI *PLOADCURSOR)(HINSTANCE, LPCWSTR);
    typedef HMENU (WINAPI *PGETSYSTEMMENU)(HWND, BOOL);
    BOOL (WINAPI *pSetConsoleIcon)(HICON);
    BOOL (WINAPI *pSetConsoleCursor)(HANDLE, HCURSOR);
    HMENU (WINAPI *pConsoleMenuControl)(HANDLE, DWORD, DWORD);
    BOOL (WINAPI *pSetConsolePalette)(HANDLE, HPALETTE, UINT);
    BOOL (WINAPI *pInvalidateConsoleDIBits)(HANDLE, PSMALL_RECT);
    BOOL (WINAPI *pGetConsoleHardwareState)(HANDLE, PDWORD, PDWORD);
    BOOL (WINAPI *pSetConsoleHardwareState)(HANDLE, DWORD, DWORD);
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll"), hUser32 = LoadLibraryW(L"user32.dll");
    PLOADICON pLoadIconW = hUser32 ? (PLOADICON)GetProcAddress(hUser32, "LoadIconW") : NULL;
    PLOADCURSOR pLoadCursorW = hUser32 ? (PLOADCURSOR)GetProcAddress(hUser32, "LoadCursorW") : NULL;
    PGETSYSTEMMENU pGetSystemMenu = hUser32 ? (PGETSYSTEMMENU)GetProcAddress(hUser32, "GetSystemMenu") : NULL;
    HANDLE hBad = (HANDLE)(ULONG_PTR)0x1234;
    SMALL_RECT Rect = { 0, 0, 3, 3 };
    DWORD Flags = 0x11111111, State = 0x22222222;
    HICON hIcon;
    HCURSOR hCursor;
    HMENU hMenu;
    HWND hWnd;
    BOOL Ret;

    pSetConsoleIcon = (PVOID)GetProcAddress(hKernel32, "SetConsoleIcon");
    pSetConsoleCursor = (PVOID)GetProcAddress(hKernel32, "SetConsoleCursor");
    pConsoleMenuControl = (PVOID)GetProcAddress(hKernel32, "ConsoleMenuControl");
    pSetConsolePalette = (PVOID)GetProcAddress(hKernel32, "SetConsolePalette");
    pInvalidateConsoleDIBits = (PVOID)GetProcAddress(hKernel32, "InvalidateConsoleDIBits");
    pGetConsoleHardwareState = (PVOID)GetProcAddress(hKernel32, "GetConsoleHardwareState");
    pSetConsoleHardwareState = (PVOID)GetProcAddress(hKernel32, "SetConsoleHardwareState");

    if (pSetConsoleIcon)
    {
        SetLastError(ERR_KEEP);
        Ret = pSetConsoleIcon(NULL);
        CheckBool("SetConsoleIcon(NULL)", Ret, GetLastError(), TRUE, ERR_KEEP, ERR_WIN10);
        if (pLoadIconW && (hIcon = pLoadIconW(NULL, ((LPCWSTR)(ULONG_PTR)32512) /* IDI_APPLICATION */)))
        {
            SetLastError(ERR_KEEP);
            Ret = pSetConsoleIcon(hIcon);
            CheckBool("SetConsoleIcon(IDI_APPLICATION)", Ret, GetLastError(), TRUE, ERR_KEEP, ERR_WIN10);
        }
        SetLastError(ERR_KEEP);
        Ret = pSetConsoleIcon((HICON)hBad);
        CheckBool("SetConsoleIcon(invalid)", Ret, GetLastError(), FALSE, ERROR_GEN_FAILURE, ERR_WIN10);
    }
    if (pSetConsoleCursor)
    {
        hCursor = pLoadCursorW ? pLoadCursorW(NULL, ((LPCWSTR)(ULONG_PTR)32512) /* IDC_ARROW */) : NULL;
        /* Only graphics screen buffers take a cursor */
        SetLastError(ERR_KEEP);
        Ret = pSetConsoleCursor(hOut, hCursor);
        CheckBool("SetConsoleCursor(text buffer)", Ret, GetLastError(), FALSE, ERROR_INVALID_HANDLE, ERR_WIN10);
        SetLastError(ERR_KEEP);
        Ret = pSetConsoleCursor(hBad, hCursor);
        CheckBool("SetConsoleCursor(invalid handle)", Ret, GetLastError(), FALSE, ERROR_INVALID_HANDLE,
                  ERROR_INVALID_HANDLE);
    }
    if (pConsoleMenuControl)
    {
        hWnd = GetConsoleWindow();
        hMenu = pConsoleMenuControl(hOut, 0, 0);
        if (is_reactos())
        {
            /* The console window's own system menu */
            if (hWnd && pGetSystemMenu)
                ok(hMenu && hMenu == pGetSystemMenu(hWnd, FALSE), "ConsoleMenuControl returned %p\n", hMenu);
        }
        else
            ok(hMenu == NULL, "ConsoleMenuControl returned %p\n", hMenu);
        hMenu = pConsoleMenuControl(hBad, 0, 0);
        ok(hMenu == NULL, "ConsoleMenuControl(invalid handle) returned %p\n", hMenu);
    }
    if (pSetConsolePalette)
    {
        SetLastError(ERR_KEEP);
        Ret = pSetConsolePalette(hOut, NULL, 1 /* SYSPAL_STATIC */);
        CheckBool("SetConsolePalette(NULL)", Ret, GetLastError(), FALSE, ERROR_GEN_FAILURE, ERR_WIN10);
        SetLastError(ERR_KEEP);
        Ret = pSetConsolePalette(hBad, NULL, 1 /* SYSPAL_STATIC */);
        CheckBool("SetConsolePalette(invalid handle)", Ret, GetLastError(), FALSE, ERROR_INVALID_HANDLE,
                  ERROR_INVALID_HANDLE);
    }
    if (pInvalidateConsoleDIBits)
    {
        SetLastError(ERR_KEEP);
        Ret = pInvalidateConsoleDIBits(hOut, &Rect);
        CheckBool("InvalidateConsoleDIBits", Ret, GetLastError(), TRUE, ERR_KEEP, ERR_WIN10);
        SetLastError(ERR_KEEP);
        Ret = pInvalidateConsoleDIBits(hBad, &Rect);
        CheckBool("InvalidateConsoleDIBits(invalid handle)", Ret, GetLastError(), FALSE, ERROR_INVALID_HANDLE,
                  ERROR_INVALID_HANDLE);
    }
    if (pGetConsoleHardwareState)
    {
        SetLastError(ERR_KEEP);
        Ret = pGetConsoleHardwareState(hOut, &Flags, &State);
        CheckBool("GetConsoleHardwareState", Ret, GetLastError(), FALSE, ERROR_INVALID_FUNCTION, ERR_WIN10);
        ok(Flags == 0x11111111 && State == 0x22222222, "Hardware state %lx %lx\n", Flags, State);
    }
    if (pSetConsoleHardwareState)
    {
        SetLastError(ERR_KEEP);
        Ret = pSetConsoleHardwareState(hOut, 0, 1);
        CheckBool("SetConsoleHardwareState", Ret, GetLastError(), FALSE, ERROR_INVALID_FUNCTION, ERR_WIN10);
    }
}

/* Beep tells the base server's sound sentry (BasepSoundSentryNotification) and ignores the answer.
 * The request is also sent raw, with the numbering of ReactOS: it must be accepted. */
static
VOID
TestBeep(VOID)
{
    typedef LONG (NTAPI *PCSRCALL)(PVOID, PVOID, ULONG, ULONG);
    struct
    {
        CHAR Header[sizeof(PVOID) == 8 ? 40 : 24]; /* PORT_MESSAGE */
        PVOID CaptureData;
        ULONG ApiNumber;
        LONG Status;
        ULONG Reserved;
        ULONGLONG Data[32];
    } Message;
    PCSRCALL pCsrClientCallServer = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrClientCallServer");
    LONG Status;
    BOOL Ret;

    SetLastError(0xdeadbeef);
    Ret = Beep(0, 0);
    ok(Ret, "Beep(0, 0) failed with %lu\n", GetLastError());

    if (!is_reactos() || !pCsrClientCallServer)
    {
        skip("The raw sound sentry request is for ReactOS\n");
        return;
    }
    RtlZeroMemory(&Message, sizeof(Message));
    /* BASESRV_SERVERDLL_INDEX 1, BasepSoundSentryNotification 21, one ULONG (VideoMode: windowed) */
    Status = pCsrClientCallServer(&Message, NULL, (1 << 16) | 21, sizeof(ULONG));
    ok(Status == 0, "BasepSoundSentryNotification returned %08lx\n", Status);
}

/*
 * A request whose API number no server serves (a server index nobody loaded, or a number that is not
 * in the table of a loaded server) is answered with an error. An unanswered request leaves the
 * calling thread in NtRequestWaitReplyPort for good, which is what a client newer than its server
 * would get for a request the server does not know. Each request is sent from a thread of its own and
 * waited for with a limit, so a server that drops it fails the test instead of hanging it.
 */
#define BADAPI_WAIT_MS 8000

typedef struct
{
    CHAR Header[sizeof(PVOID) == 8 ? 40 : 24]; /* PORT_MESSAGE */
    PVOID CaptureData;
    ULONG ApiNumber;
    LONG Status;
    ULONG Reserved;
    ULONGLONG Data[32];
} BADAPI_MESSAGE;

typedef struct
{
    LONG (NTAPI *Call)(PVOID, PVOID, ULONG, ULONG);
    ULONG ApiNumber;
    LONG Status;
    BADAPI_MESSAGE Message;
} BADAPI_CALL;

static
DWORD
WINAPI
BadApiThread(
    _In_ PVOID Parameter)
{
    BADAPI_CALL *Call = Parameter;

    Call->Status = Call->Call(&Call->Message, NULL, Call->ApiNumber, sizeof(ULONG));
    return 0;
}

static
VOID
TestBadApiNumbers(VOID)
{
    static const struct
    {
        ULONG ApiNumber;
        PCSTR Name;
    } Cases[] =
    {
        { (3 << 16) | 0,        "server 3, API 0" },
        { (7 << 16) | 0,        "server 7, beyond the servers" },
        { (0 << 16) | 0x1000,   "CSRSRV, beyond its table" },
        { (1 << 16) | 0x1000,   "BASESRV, beyond its table" },
        { (2 << 16) | 0x7FFF,   "console server, beyond its table" },
    };
    PVOID pCall = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrClientCallServer");
    BADAPI_CALL *Call;
    HANDLE hThread;
    DWORD Wait;
    ULONG Index;
    BOOL IsWow64 = FALSE;

    IsWow64Process(GetCurrentProcess(), &IsWow64);
    if (!is_reactos() || IsWow64 || !pCall)
    {
        skip("The raw requests with a bad API number are for the native ReactOS server\n");
        return;
    }

    for (Index = 0; Index < _countof(Cases); ++Index)
    {
        /* The block is not freed after a timeout: the thread is still in the call */
        Call = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Call));
        Call->Call = pCall;
        Call->ApiNumber = Cases[Index].ApiNumber;
        Call->Status = 0x7FFFFFFF;
        hThread = CreateThread(NULL, 0, BadApiThread, Call, 0, NULL);
        ok(hThread != NULL, "CreateThread failed with %lu\n", GetLastError());
        if (!hThread)
            continue;
        Wait = WaitForSingleObject(hThread, BADAPI_WAIT_MS);
        ok(Wait == WAIT_OBJECT_0, "%s: the request was not answered\n", Cases[Index].Name);
        if (Wait == WAIT_OBJECT_0)
        {
            ok(Call->Status == (LONG)0xC00000AF /* STATUS_ILLEGAL_FUNCTION */,
               "%s: returned %08lx\n", Cases[Index].Name, Call->Status);
            HeapFree(GetProcessHeap(), 0, Call);
        }
        CloseHandle(hThread);
    }

    /* the console server still works after the requests that were refused */
    ok(GetConsoleCP() != 0, "GetConsoleCP failed with %lu\n", GetLastError());
}

/*
 * The private requests of NitroOS with which a console host reads what the buffer cannot give
 * through the Windows API: the rows that scrolled off (ConsolepGetScrollback) and the 256-color
 * and 24-bit colors of the cells (ConsolepGetExtColors). A client can send any request of the
 * console server, so each is sent raw, well-formed and forged (counts, flags, widths, a missing
 * or short capture buffer, a bad handle), and the memory a console may make the server spend on
 * them is probed. ReactOS only; the layout is that of the native request, so not under WoW64.
 */
#define RAW_GETSCROLLBACK   ((2 << 16) | 599)   /* CONSRV_SERVERDLL_INDEX, ConsolepGetScrollback */
#define RAW_GETEXTCOLORS    ((2 << 16) | 600)   /* ConsolepGetExtColors */

typedef struct
{
    HANDLE ConsoleHandle;
    HANDLE OutputHandle;
    ULONGLONG First;
    ULONGLONG Total;
    ULONG Flags;
    ULONG Width;
    ULONG Count;
    PVOID Cells;
} RAW_SCROLLBACK;

typedef struct
{
    HANDLE ConsoleHandle;
    HANDLE OutputHandle;
    ULONGLONG First;
    ULONG Flags;
    ULONG Width;
    ULONG Count;
    PVOID Cells;
} RAW_EXTCOLORS;

typedef struct
{
    ULONG Fore;
    ULONG Back;
} RAW_EXTCELL;

typedef PVOID (NTAPI *PALLOCCAPTURE)(ULONG, ULONG);
typedef ULONG (NTAPI *PALLOCPOINTER)(PVOID, ULONG, PVOID *);
typedef VOID (NTAPI *PFREECAPTURE)(PVOID);
typedef LONG (NTAPI *PCSRCALL)(PVOID, PVOID, ULONG, ULONG);

static PALLOCCAPTURE pAllocCapture;
static PALLOCPOINTER pAllocPointer;
static PFREECAPTURE pFreeCapture;
static PCSRCALL pCall;

/* Send Request (RequestSize bytes) with a capture buffer of CaptureSize bytes (0: none) that the
 * pointer at DataOffset of the request points into; ReplyShort says how much of it comes back in Data. */
static
LONG
RawConsoleCall(
    _In_ ULONG Api,
    _Inout_ PVOID Request,
    _In_ ULONG RequestSize,
    _In_ ULONG DataOffset,
    _In_ ULONG CaptureSize,
    _Out_opt_ PVOID Data,
    _In_ ULONG DataSize)
{
    struct
    {
        CHAR Header[sizeof(PVOID) == 8 ? 40 : 24]; /* PORT_MESSAGE */
        PVOID CaptureData;
        ULONG ApiNumber;
        LONG Status;
        ULONG Reserved;
        ULONGLONG Data[32];
    } Message;
    PVOID Capture = NULL;
    LONG Status;

    RtlZeroMemory(&Message, sizeof(Message));
    RtlCopyMemory(Message.Data, Request, RequestSize);
    if (CaptureSize)
    {
        Capture = pAllocCapture(1, CaptureSize);
        if (!Capture) return (LONG)0xC0000017;
        pAllocPointer(Capture, CaptureSize, (PVOID *)((PUCHAR)Message.Data + DataOffset));
    }
    Status = pCall(&Message, Capture, Api, RequestSize);
    RtlCopyMemory(Request, Message.Data, RequestSize);
    if (Status >= 0 && Capture && Data && DataSize)
        RtlCopyMemory(Data, *(PVOID *)((PUCHAR)Request + DataOffset), DataSize);
    if (Capture) pFreeCapture(Capture);
    return Status;
}

#define RAW_STATUS_INVALID_PARAMETER ((LONG)0xC000000D)

static
LONG
RawExtColors(
    _In_ HANDLE Output,
    _In_ ULONG Flags,
    _In_ ULONGLONG First,
    _In_ ULONG Width,
    _In_ ULONG Count,
    _In_ ULONG CaptureSize,
    _Out_opt_ RAW_EXTCELL *Cells,
    _Out_opt_ ULONG *Returned)
{
    RAW_EXTCOLORS Request;
    LONG Status;

    RtlZeroMemory(&Request, sizeof(Request));
    Request.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Request.OutputHandle = Output;
    Request.Flags = Flags;
    Request.First = First;
    Request.Width = Width;
    Request.Count = Count;
    Status = RawConsoleCall(RAW_GETEXTCOLORS, &Request, sizeof(Request), FIELD_OFFSET(RAW_EXTCOLORS, Cells),
                            CaptureSize, Cells, Cells ? CaptureSize : 0);
    if (Returned) *Returned = Request.Count;
    return Status;
}

static
LONG
RawScrollback(
    _In_ HANDLE Output,
    _In_ ULONG Flags,
    _In_ ULONG Width,
    _In_ ULONG Count,
    _In_ ULONG CaptureSize,
    _Out_ ULONG *OutFlags)
{
    RAW_SCROLLBACK Request;
    LONG Status;

    RtlZeroMemory(&Request, sizeof(Request));
    Request.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Request.OutputHandle = Output;
    Request.Flags = Flags;
    Request.Width = Width;
    Request.Count = Count;
    Status = RawConsoleCall(RAW_GETSCROLLBACK, &Request, sizeof(Request), FIELD_OFFSET(RAW_SCROLLBACK, Cells),
                            CaptureSize, NULL, 0);
    *OutFlags = Request.Flags;
    return Status;
}

static
VOID
TestExtColorsRequests(VOID)
{
    CONSOLE_SCREEN_BUFFER_INFO Info;
    static const CHAR Text[] = "\x1b[38;2;10;20;30mA\x1b[48;5;200mB\x1b[0mC\x1b[38;5;9mD";
    RAW_EXTCELL *Cells;
    HANDLE Buffers[8];
    WORD Attributes[4];
    COORD Origin = {0, 0};
    DWORD Written, Mode, Index, Enabled = 0, Flags;
    ULONG Width, Returned, Size, Fore, Back;
    LONG Status;
    BOOL IsWow64 = FALSE;

    pAllocCapture = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrAllocateCaptureBuffer");
    pAllocPointer = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrAllocateMessagePointer");
    pFreeCapture = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrFreeCaptureBuffer");
    pCall = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrClientCallServer");
    IsWow64Process(GetCurrentProcess(), &IsWow64);
    if (!is_reactos() || IsWow64 || !pAllocCapture || !pAllocPointer || !pFreeCapture || !pCall)
    {
        skip("The raw requests of the pseudoconsole host are for the native ReactOS server\n");
        return;
    }

    /* The colors a client sets with the sequences are kept per cell... */
    ok(GetConsoleMode(hOut, &Mode), "GetConsoleMode failed with %lu\n", GetLastError());
    ok(SetConsoleMode(hOut, Mode | 0x0004), "SetConsoleMode(VT) failed with %lu\n", GetLastError());
    SetConsoleTextAttribute(hOut, 0x07);
    ok(SetConsoleCursorPosition(hOut, Origin), "SetConsoleCursorPosition failed with %lu\n", GetLastError());
    ok(WriteConsoleA(hOut, Text, lstrlenA(Text), &Written, NULL), "WriteConsoleA failed with %lu\n", GetLastError());
    GetConsoleScreenBufferInfo(hOut, &Info);
    Width = Info.dwSize.X;
    Size = Width * sizeof(RAW_EXTCELL);
    Cells = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);

    /* ...with the nearest console color left in the cell */
    ok(ReadConsoleOutputAttribute(hOut, Attributes, 4, Origin, &Written) && Written == 4,
       "ReadConsoleOutputAttribute failed with %lu\n", GetLastError());
    ok(((Attributes[1] >> 4) & 0x0F) != 0, "The 256-color background left no console color in the cell: %04x\n", Attributes[1]);
    ok(Attributes[2] == 0x07, "Colors leaked into the cell after SGR 0: %04x\n", Attributes[2]);
    ok((Attributes[3] & 0x0F) == 0x0C, "38;5;9 is not bright red: %04x\n", Attributes[3]);

    Returned = 0;
    Status = RawExtColors(hOut, 0, 0, Width, 1, Size, Cells, &Returned);
    ok(Status == 0, "ConsolepGetExtColors returned %08lx\n", Status);
    ok(Returned == 1, "ConsolepGetExtColors returned %lu rows\n", Returned);
    Fore = Cells[0].Fore;
    Back = Cells[1].Back;
    ok(((Fore >> 24) & 3) == 2 && (Fore & 0xFFFFFF) == 0x0A141E, "A: foreground %08lx\n", Fore);
    ok(((Fore >> 26) & 0xF) == (ULONG)(Attributes[0] & 0x0F), "A: foreground does not carry the color of the cell: %08lx %04x\n", Fore, Attributes[0]);
    ok(((Back >> 24) & 3) == 1 && (Back & 0xFFFFFF) == 200, "B: background %08lx\n", Back);
    ok(Cells[2].Fore == 0 && Cells[2].Back == 0, "C (after SGR 0) has colors %08lx %08lx\n", Cells[2].Fore, Cells[2].Back);
    ok(Cells[3].Fore == 0, "D (palette entry 9) has an extended color %08lx\n", Cells[3].Fore);

    /* a legacy writer of the cells takes their extended colors away */
    ok(WriteConsoleOutputAttribute(hOut, Attributes, 2, Origin, &Written), "WriteConsoleOutputAttribute failed\n");
    Status = RawExtColors(hOut, 0, 0, Width, 1, Size, Cells, &Returned);
    ok(Status == 0 && Cells[0].Fore == 0 && Cells[1].Back == 0, "Extended colors survived WriteConsoleOutputAttribute: %08lx %08lx\n",
       Cells[0].Fore, Cells[1].Back);

    /* the colors move with the cells: ScrollConsoleScreenBuffer, then a larger buffer */
    {
        static const CHAR Move[] = "\x1b[38;2;7;8;9mS\x1b[0m";
        COORD Row5 = {0, 5};
        SMALL_RECT Source = {0, 5, 0, 5};
        COORD Row7 = {0, 7}, NewSize;
        CHAR_INFO Fill;

        Fill.Char.UnicodeChar = L' ';
        Fill.Attributes = 0x07;
        ok(SetConsoleCursorPosition(hOut, Row5) && WriteConsoleA(hOut, Move, lstrlenA(Move), &Written, NULL),
           "Writing a colored cell failed with %lu\n", GetLastError());
        Status = RawExtColors(hOut, 0, 5, Width, 1, Size, Cells, &Returned);
        ok(Status == 0 && Returned == 1 && (Cells[0].Fore & 0xFFFFFF) == 0x070809 && ((Cells[0].Fore >> 24) & 3) == 2,
           "The colored cell has %08lx (%08lx, %lu rows)\n", Cells[0].Fore, Status, Returned);
        ok(ScrollConsoleScreenBufferW(hOut, &Source, NULL, Row7, &Fill), "ScrollConsoleScreenBuffer failed with %lu\n", GetLastError());
        Status = RawExtColors(hOut, 0, 7, Width, 1, Size, Cells, &Returned);
        ok(Status == 0 && Returned == 1 && (Cells[0].Fore & 0xFFFFFF) == 0x070809,
           "The color did not move with the cell: %08lx (%08lx)\n", Cells[0].Fore, Status);
        Status = RawExtColors(hOut, 0, 5, Width, 1, Size, Cells, &Returned);
        ok(Status == 0 && Cells[0].Fore == 0, "The vacated cell kept its color: %08lx\n", Cells[0].Fore);

        NewSize.X = (SHORT)Width + 1;
        NewSize.Y = Info.dwSize.Y;
        ok(SetConsoleScreenBufferSize(hOut, NewSize), "SetConsoleScreenBufferSize failed with %lu\n", GetLastError());
        Status = RawExtColors(hOut, 0, 7, Width + 1, 1, (Width + 1) * sizeof(RAW_EXTCELL), NULL, &Returned);
        ok(Status == 0, "ConsolepGetExtColors after the resize: %08lx\n", Status);
        {
            RAW_EXTCELL *Wider = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (Width + 1) * sizeof(RAW_EXTCELL));

            Status = RawExtColors(hOut, 0, 7, Width + 1, 1, (Width + 1) * sizeof(RAW_EXTCELL), Wider, &Returned);
            ok(Status == 0 && Returned == 1 && (Wider[0].Fore & 0xFFFFFF) == 0x070809,
               "The color did not survive the resize: %08lx (%08lx, %lu rows)\n", Wider[0].Fore, Status, Returned);
            HeapFree(GetProcessHeap(), 0, Wider);
        }
        /* the old width is not the buffer's any more */
        Status = RawExtColors(hOut, 0, 7, Width, 1, Size, NULL, &Returned);
        ok(Status == RAW_STATUS_INVALID_PARAMETER, "The width before the resize was accepted: %08lx\n", Status);
        NewSize.X = (SHORT)Width;
        SetConsoleScreenBufferSize(hOut, NewSize);
    }

    /* forged requests */
    Status = RawExtColors(hOut, 0, 0, Width, 0, 0, NULL, &Returned);
    ok(Status == 0 && Returned == 0, "Count 0: %08lx, %lu rows\n", Status, Returned);
    Status = RawExtColors(hOut, 0, 0, Width, 2049, Size, NULL, &Returned);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "Count over the limit: %08lx\n", Status);
    Status = RawExtColors(hOut, 0x80, 0, Width, 1, Size, NULL, &Returned);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "Unknown flag: %08lx\n", Status);
    Status = RawExtColors(hOut, 0, 0, Width + 1, 1, (Width + 1) * sizeof(RAW_EXTCELL), NULL, &Returned);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "Wrong width: %08lx\n", Status);
    Status = RawExtColors(hOut, 0, 0, Width, 1, 0, NULL, &Returned);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "No capture buffer: %08lx\n", Status);
    Status = RawExtColors(hOut, 0, 0, Width, 3, Size, NULL, &Returned);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "A capture buffer too short for the rows: %08lx\n", Status);
    Status = RawExtColors(hOut, 0, 0, 0xFFFFFFFF, 2048, Size, NULL, &Returned);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "Overflowing size: %08lx\n", Status);
    Status = RawExtColors((HANDLE)(ULONG_PTR)0x7FFC, 0, 0, Width, 1, Size, NULL, &Returned);
    ok(Status != 0, "A bad handle succeeded\n");
    Status = RawExtColors(hOut, 0, 0x7FFFFFFFFFFFFFFFULL, Width, 1, Size, Cells, &Returned);
    ok(Status == 0 && Returned == 0, "A first row beyond the buffer: %08lx, %lu rows\n", Status, Returned);
    Status = RawExtColors(hOut, 1, 0x7FFFFFFFFFFFFFFFULL, Width, 1, Size, Cells, &Returned);
    ok(Status == 0 && Returned == 0, "A first scrollback row beyond the buffer: %08lx, %lu rows\n", Status, Returned);

    /* the same for the scrollback request */
    Status = RawScrollback(hOut, 0, Width, 2049, Size, &Flags);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "Scrollback, count over the limit: %08lx\n", Status);
    Status = RawScrollback(hOut, 0x80, Width, 1, Size, &Flags);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "Scrollback, unknown flag: %08lx\n", Status);
    Status = RawScrollback(hOut, 0, Width + 1, 1, (Width + 1) * sizeof(CHAR_INFO), &Flags);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "Scrollback, wrong width: %08lx\n", Status);
    Status = RawScrollback(hOut, 0, Width, 1, 0, &Flags);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "Scrollback, no capture buffer: %08lx\n", Status);
    Status = RawScrollback(hOut, 0, Width, 3, Width * sizeof(CHAR_INFO), &Flags);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "Scrollback, a capture buffer too short: %08lx\n", Status);
    Status = RawScrollback((HANDLE)(ULONG_PTR)0x7FFC, 0, Width, 0, 0, &Flags);
    ok(Status != 0, "Scrollback, a bad handle succeeded\n");

    /* what a console may make the server keep is limited: rows for 1024 columns are 8 MB, a console
     * has room for four of those (and the colors of the cells count too) */
    for (Index = 0; Index < _countof(Buffers); ++Index)
    {
        COORD Wide = {1024, 200};

        Buffers[Index] = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                   NULL, CONSOLE_TEXTMODE_BUFFER, NULL);
        if (Buffers[Index] == INVALID_HANDLE_VALUE) continue;
        ok(SetConsoleScreenBufferSize(Buffers[Index], Wide), "SetConsoleScreenBufferSize failed with %lu\n", GetLastError());
        Flags = 0;
        Status = RawScrollback(Buffers[Index], 1, 1024, 0, 0, &Flags);
        if (Status == 0 && (Flags & 1)) ++Enabled;
    }
    trace("%lu of %u wide buffers got scrollback rows\n", Enabled, (UINT)_countof(Buffers));
    ok(Enabled >= 1 && Enabled <= 4, "%lu buffers of one console were given 8 MB of scrollback rows each\n", Enabled);
    for (Index = 0; Index < _countof(Buffers); ++Index)
        if (Buffers[Index] != INVALID_HANDLE_VALUE) CloseHandle(Buffers[Index]);
    HeapFree(GetProcessHeap(), 0, Cells);
}

/*
 * Console server requests carry sizes of their own: the characters of ReadConsole are read into the
 * buffer the request came with (80 bytes inline, otherwise the capture buffer), a region of cells is
 * a width times a height, and a count of codes times the size of a code. Each is the client's number,
 * and a request that does not agree with itself is refused whole (ReactOS' server; Windows' console
 * host has no such request, so this is for ReactOS only). A request that does agree is served.
 */
#define RAW_READOUTPUT      ((2 << 16) | 515)   /* ConsolepReadConsoleOutput */
#define RAW_WRITEOUTPUT     ((2 << 16) | 516)   /* ConsolepWriteConsoleOutput */
#define RAW_READOUTPUTCODE  ((2 << 16) | 517)   /* ConsolepReadConsoleOutputString */
#define RAW_WRITEOUTPUTCODE ((2 << 16) | 518)   /* ConsolepWriteConsoleOutputString */
#define RAW_READCONSOLE     ((2 << 16) | 541)   /* ConsolepReadConsole */
#define RAW_CODE_UNICODE    2

typedef struct
{
    HANDLE ConsoleHandle;
    HANDLE InputHandle;
    USHORT ExeLength;
    CHAR StaticBuffer[80];
    PVOID Buffer;
    ULONG NumBytes;
    ULONG CaptureBufferSize;
    ULONG InitialNumBytes;
    ULONG CtrlWakeupMask;
    ULONG ControlKeyState;
    BOOLEAN Unicode;
} RAW_READREQ;

typedef struct
{
    HANDLE ConsoleHandle;
    HANDLE OutputHandle;
    COORD Coord;
    ULONG CodeType;
    CHAR CodeStaticBuffer[80];
    PVOID pCode;
    ULONG NumCodes;
} RAW_OUTPUTCODE;

typedef struct
{
    HANDLE ConsoleHandle;
    HANDLE OutputHandle;
    CHAR_INFO StaticBuffer;
    PVOID CharInfo;
    SMALL_RECT Region;
    BOOLEAN Unicode;
    BOOLEAN UseVirtualMemory;
} RAW_OUTPUT;

static
VOID
TestRawRequestSizes(VOID)
{
    RAW_READREQ Read;
    RAW_OUTPUTCODE Code;
    RAW_OUTPUT Cells;
    COORD Origin = {0, 0};
    DWORD Mode;
    LONG Status;
    BOOL IsWow64 = FALSE;
    static const struct { ULONG NumCodes; } BadCodes[] = { { 0x80000028 }, { 0x80000014 }, { 0xFFFFFFFF } };
    ULONG i;

    pAllocCapture = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrAllocateCaptureBuffer");
    pAllocPointer = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrAllocateMessagePointer");
    pFreeCapture = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrFreeCaptureBuffer");
    pCall = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrClientCallServer");
    IsWow64Process(GetCurrentProcess(), &IsWow64);
    if (!is_reactos() || IsWow64 || !pAllocCapture || !pAllocPointer || !pFreeCapture || !pCall)
    {
        skip("The raw request sizes are for the native ReactOS server\n");
        return;
    }

    /* ReadConsole: more bytes than the 80 of the inline buffer, or than the capture buffer, are refused */
    RtlZeroMemory(&Read, sizeof(Read));
    Read.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Read.InputHandle = hIn;
    Read.Unicode = TRUE;
    Read.NumBytes = 4000;
    Read.CaptureBufferSize = 80;
    Status = RawConsoleCall(RAW_READCONSOLE, &Read, sizeof(Read), FIELD_OFFSET(RAW_READREQ, Buffer), 0, NULL, 0);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "ReadConsole of 4000 bytes into 80 returned %08lx\n", Status);
    Read.NumBytes = 100;
    Read.CaptureBufferSize = 80;
    Status = RawConsoleCall(RAW_READCONSOLE, &Read, sizeof(Read), FIELD_OFFSET(RAW_READREQ, Buffer), 0, NULL, 0);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "ReadConsole of 100 bytes into 80 returned %08lx\n", Status);
    Read.NumBytes = 4000;
    Read.CaptureBufferSize = 200;
    Status = RawConsoleCall(RAW_READCONSOLE, &Read, sizeof(Read), FIELD_OFFSET(RAW_READREQ, Buffer), 200, NULL, 0);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "ReadConsole of 4000 bytes into a capture buffer of 200 returned %08lx\n", Status);

    /* ...and one that agrees with itself is read: a line of input comes back in the inline buffer */
    ok(GetConsoleMode(hIn, &Mode), "GetConsoleMode failed with %lu\n", GetLastError());
    ok(SetConsoleMode(hIn, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT),
       "SetConsoleMode failed with %lu\n", GetLastError());
    FlushConsoleInputBuffer(hIn);
    WriteKeys("a\r");
    RtlZeroMemory(&Read, sizeof(Read));
    Read.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Read.InputHandle = hIn;
    Read.Unicode = TRUE;
    Read.NumBytes = 80;
    Read.CaptureBufferSize = 80;
    Status = RawConsoleCall(RAW_READCONSOLE, &Read, sizeof(Read), FIELD_OFFSET(RAW_READREQ, Buffer), 0, NULL, 0);
    ok(Status == 0, "ReadConsole of a line into 80 bytes returned %08lx\n", Status);
    ok(Read.NumBytes == 3 * sizeof(WCHAR) && ((WCHAR *)Read.StaticBuffer)[0] == L'a' &&
       ((WCHAR *)Read.StaticBuffer)[1] == L'\r',
       "ReadConsole returned %lu bytes, %04x %04x\n", Read.NumBytes, ((WCHAR *)Read.StaticBuffer)[0],
       ((WCHAR *)Read.StaticBuffer)[1]);
    SetConsoleMode(hIn, Mode);

    /* codes: a count whose size in bytes wraps 32 bits must not pick the inline buffer */
    for (i = 0; i < _countof(BadCodes); ++i)
    {
        RtlZeroMemory(&Code, sizeof(Code));
        Code.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
        Code.OutputHandle = hOut;
        Code.CodeType = RAW_CODE_UNICODE;
        Code.NumCodes = BadCodes[i].NumCodes;
        Status = RawConsoleCall(RAW_WRITEOUTPUTCODE, &Code, sizeof(Code), FIELD_OFFSET(RAW_OUTPUTCODE, pCode), 0, NULL, 0);
        ok(Status == RAW_STATUS_INVALID_PARAMETER, "WriteConsoleOutputCharacter of %08lx codes returned %08lx\n",
           BadCodes[i].NumCodes, Status);
        RtlZeroMemory(&Code, sizeof(Code));
        Code.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
        Code.OutputHandle = hOut;
        Code.CodeType = RAW_CODE_UNICODE;
        Code.NumCodes = BadCodes[i].NumCodes;
        Status = RawConsoleCall(RAW_READOUTPUTCODE, &Code, sizeof(Code), FIELD_OFFSET(RAW_OUTPUTCODE, pCode), 0, NULL, 0);
        ok(Status == RAW_STATUS_INVALID_PARAMETER, "ReadConsoleOutputCharacter of %08lx codes returned %08lx\n",
           BadCodes[i].NumCodes, Status);
    }

    /* ...three codes are written and read back through the inline buffer */
    RtlZeroMemory(&Code, sizeof(Code));
    Code.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Code.OutputHandle = hOut;
    Code.Coord = Origin;
    Code.CodeType = RAW_CODE_UNICODE;
    Code.NumCodes = 3;
    RtlCopyMemory(Code.CodeStaticBuffer, L"ABC", 3 * sizeof(WCHAR));
    Status = RawConsoleCall(RAW_WRITEOUTPUTCODE, &Code, sizeof(Code), FIELD_OFFSET(RAW_OUTPUTCODE, pCode), 0, NULL, 0);
    ok(Status == 0 && Code.NumCodes == 3, "WriteConsoleOutputCharacter of 3 codes returned %08lx, %lu\n", Status,
       Code.NumCodes);
    RtlZeroMemory(&Code, sizeof(Code));
    Code.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Code.OutputHandle = hOut;
    Code.Coord = Origin;
    Code.CodeType = RAW_CODE_UNICODE;
    Code.NumCodes = 3;
    Status = RawConsoleCall(RAW_READOUTPUTCODE, &Code, sizeof(Code), FIELD_OFFSET(RAW_OUTPUTCODE, pCode), 0, NULL, 0);
    ok(Status == 0 && Code.NumCodes == 3 && !memcmp(Code.CodeStaticBuffer, L"ABC", 3 * sizeof(WCHAR)),
       "ReadConsoleOutputCharacter of 3 codes returned %08lx, %lu\n", Status, Code.NumCodes);

    /* cells: a region whose width times height wraps 32 bits must not pick the one-cell inline buffer */
    RtlZeroMemory(&Cells, sizeof(Cells));
    Cells.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Cells.OutputHandle = hOut;
    Cells.Unicode = TRUE;
    Cells.Region.Left = Cells.Region.Top = -32768;
    Cells.Region.Right = Cells.Region.Bottom = 32767;
    Status = RawConsoleCall(RAW_READOUTPUT, &Cells, sizeof(Cells), FIELD_OFFSET(RAW_OUTPUT, CharInfo), 0, NULL, 0);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "ReadConsoleOutput of 65536 x 65536 cells returned %08lx\n", Status);
    Status = RawConsoleCall(RAW_WRITEOUTPUT, &Cells, sizeof(Cells), FIELD_OFFSET(RAW_OUTPUT, CharInfo), 0, NULL, 0);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "WriteConsoleOutput of 65536 x 65536 cells returned %08lx\n", Status);
    Cells.UseVirtualMemory = TRUE;
    Status = RawConsoleCall(RAW_WRITEOUTPUT, &Cells, sizeof(Cells), FIELD_OFFSET(RAW_OUTPUT, CharInfo), 0, NULL, 0);
    ok(Status == RAW_STATUS_INVALID_PARAMETER, "WriteConsoleOutput of 65536 x 65536 cells from the heap returned %08lx\n",
       Status);

    /* ...one cell is written and read back through the inline buffer */
    RtlZeroMemory(&Cells, sizeof(Cells));
    Cells.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Cells.OutputHandle = hOut;
    Cells.Unicode = TRUE;
    Cells.StaticBuffer.Char.UnicodeChar = L'Z';
    Cells.StaticBuffer.Attributes = 0x1E;
    Status = RawConsoleCall(RAW_WRITEOUTPUT, &Cells, sizeof(Cells), FIELD_OFFSET(RAW_OUTPUT, CharInfo), 0, NULL, 0);
    ok(Status == 0, "WriteConsoleOutput of one cell returned %08lx\n", Status);
    RtlZeroMemory(&Cells, sizeof(Cells));
    Cells.ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    Cells.OutputHandle = hOut;
    Cells.Unicode = TRUE;
    Status = RawConsoleCall(RAW_READOUTPUT, &Cells, sizeof(Cells), FIELD_OFFSET(RAW_OUTPUT, CharInfo), 0, NULL, 0);
    ok(Status == 0 && Cells.StaticBuffer.Char.UnicodeChar == L'Z' && Cells.StaticBuffer.Attributes == 0x1E,
       "ReadConsoleOutput of one cell returned %08lx, %04x %04x\n", Status, Cells.StaticBuffer.Char.UnicodeChar,
       Cells.StaticBuffer.Attributes);
}

static
VOID
TestAllocConsole(VOID)
{
    CONSOLE_SCREEN_BUFFER_INFO Info;
    HANDLE hNew;
    DWORD Written;

    ok(FreeConsole(), "FreeConsole failed with %lu\n", GetLastError());
    ok(AllocConsole(), "AllocConsole failed with %lu\n", GetLastError());
    hNew = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, 0, NULL);
    ok(hNew != INVALID_HANDLE_VALUE, "CONOUT$ of the new console failed with %lu\n", GetLastError());
    ok(GetConsoleScreenBufferInfo(hNew, &Info), "GetConsoleScreenBufferInfo on the new console failed with %lu\n",
       GetLastError());
    ok(WriteConsoleA(hNew, "new console\n", 12, &Written, NULL) && Written == 12,
       "WriteConsoleA on the new console failed with %lu\n", GetLastError());
    CloseHandle(hNew);
    ok(FreeConsole(), "FreeConsole failed with %lu\n", GetLastError());
}

static
VOID
RunChild(VOID)
{
    hIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      OPEN_EXISTING, 0, NULL);
    hFirst = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, NULL);
    hOut = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                     CONSOLE_TEXTMODE_BUFFER, NULL);
    ok(hIn != INVALID_HANDLE_VALUE, "CONIN$ failed with %lu\n", GetLastError());
    ok(hFirst != INVALID_HANDLE_VALUE, "CONOUT$ failed with %lu\n", GetLastError());
    ok(hOut != INVALID_HANDLE_VALUE, "CreateConsoleScreenBuffer failed with %lu\n", GetLastError());
    if (hIn == INVALID_HANDLE_VALUE || hFirst == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE)
        return;

    TestScreenBuffer();
    TestOutputStrings();
    TestOutputRegions();
    TestTitle();
    TestInput();
    TestHandles();
    TestMisc();
    TestAliasesAndHistory();
    TestWindowRequests();
    TestBeep();
    TestBadApiNumbers();
    TestExtColorsRequests();
    TestRawRequestSizes();

    ok(CloseHandle(hOut), "CloseHandle(screen buffer) failed with %lu\n", GetLastError());
    ok(CloseHandle(hIn), "CloseHandle(CONIN$) failed with %lu\n", GetLastError());
    ok(CloseHandle(hFirst), "CloseHandle(CONOUT$) failed with %lu\n", GetLastError());
    TestAllocConsole();
}

START_TEST(ConsoleCsrRequests)
{
    int argc;
    char **argv;
    WCHAR FileName[MAX_PATH];
    WCHAR CommandLine[MAX_PATH + 40];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    HANDLE hRead, hWrite;
    CHAR Output[4096];
    DWORD Wait, Count;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "child"))
    {
        RunChild();
        return;
    }

    if (!CreatePipe(&hRead, &hWrite, &Sa, 0x10000))
    {
        skip("CreatePipe failed with %lu\n", GetLastError());
        return;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" ConsoleCsrRequests child", FileName);
    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    StartupInfo.hStdOutput = hWrite;
    StartupInfo.hStdError = hWrite;
    StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL,
                        &StartupInfo, &ProcessInfo))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        CloseHandle(hWrite);
        CloseHandle(hRead);
        return;
    }
    CloseHandle(hWrite);
    CloseHandle(ProcessInfo.hThread);

    Wait = WaitForSingleObject(ProcessInfo.hProcess, CHILD_TIMEOUT_MS);
    ok(Wait == WAIT_OBJECT_0, "The child process did not exit: %lu\n", Wait);
    if (Wait != WAIT_OBJECT_0)
        TerminateProcess(ProcessInfo.hProcess, 1);

    /* The child's report (its failures and its summary line) */
    while (ReadFile(hRead, Output, sizeof(Output) - 1, &Count, NULL) && Count)
    {
        Output[Count] = 0;
        printf("%s", Output);
    }
    CloseHandle(hRead);
    if (Wait == WAIT_OBJECT_0)
        wait_child_process(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hProcess);
}
