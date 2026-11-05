/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test the Ctrl key shortcuts and the keyboard selection of a console window
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows 10 22H2 (build 19045), with HKCU\Console
 * CtrlKeyShortcutsDisabled = 0 (the default): while the program has ENABLE_PROCESSED_INPUT,
 * Shift+arrows select from the cursor, Ctrl+C copies a selection (and is the break key when there
 * is none), Ctrl+V pastes, Ctrl+A selects all. A program that turned processed input off, or
 * (for Ctrl+V and Ctrl+A) asked for virtual terminal input, gets all of them as keys.
 *
 * Pasting (Ctrl+V) goes through HKCU\Console FilterOnPaste = 1 (the default): tabs are dropped, the
 * typographic double quotes and the en/em dashes become the ASCII ones, the no-break space becomes a
 * space; trailing blanks and line endings are left alone. Digits and the other main-keyboard
 * characters are pasted as the keys of the main keyboard, not of the numeric keypad.
 *
 * The keys are sent with SendInput to a console window of its own, which the test starts as a child
 * process: it reports the number of failed checks as its exit code, and says which in a file.
 */

#include "precomp.h"

#include <stdarg.h>
#include <stdio.h>
#include <winuser.h>

#ifndef ENABLE_INSERT_MODE
#define ENABLE_INSERT_MODE      0x0020
#endif
#ifndef ENABLE_QUICK_EDIT_MODE
#define ENABLE_QUICK_EDIT_MODE  0x0040
#endif
#ifndef ENABLE_EXTENDED_FLAGS
#define ENABLE_EXTENDED_FLAGS   0x0080
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif

#define BASE_MODE (ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE)

#define SHIFT 1
#define CTRL  2

static HANDLE hIn, hOut;
static HWND hWnd;
static FILE *Report;
static int Failures;
static volatile LONG CtrlCCount;

static BOOL WINAPI CtrlHandler(DWORD Type)
{
    if (Type != CTRL_C_EVENT) return FALSE;
    InterlockedIncrement(&CtrlCCount);
    return TRUE;
}

static VOID Fail(const char *Format, ...)
{
    va_list Args;

    Failures++;
    va_start(Args, Format);
    vfprintf(Report, Format, Args);
    va_end(Args);
    fputc('\n', Report);
    fflush(Report);
}

#define CHECK(cond, ...) do { if (!(cond)) Fail(__VA_ARGS__); } while (0)

static BOOL IsExtendedKey(WORD Vk)
{
    switch (Vk)
    {
        case VK_LEFT: case VK_RIGHT: case VK_UP: case VK_DOWN:
        case VK_HOME: case VK_END: case VK_PRIOR: case VK_NEXT:
        case VK_INSERT: case VK_DELETE: return TRUE;
    }
    return FALSE;
}

static VOID SendKey(WORD Vk, BOOL Up)
{
    INPUT Input;

    ZeroMemory(&Input, sizeof(Input));
    Input.type = INPUT_KEYBOARD;
    Input.ki.wVk = Vk;
    Input.ki.wScan = (WORD)MapVirtualKeyW(Vk, MAPVK_VK_TO_VSC);
    Input.ki.dwFlags = (IsExtendedKey(Vk) ? KEYEVENTF_EXTENDEDKEY : 0) | (Up ? KEYEVENTF_KEYUP : 0);
    SendInput(1, &Input, sizeof(Input));
    Sleep(30);
}

static VOID Press(WORD Vk, int Mods)
{
    int i;

    for (i = 0; i < 5 && GetForegroundWindow() != hWnd; i++)
    {
        keybd_event(VK_MENU, 0, 0, 0);
        keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);
        ShowWindow(hWnd, SW_RESTORE);
        SetForegroundWindow(hWnd);
        Sleep(150);
    }
    if (Mods & CTRL) SendKey(VK_CONTROL, FALSE);
    if (Mods & SHIFT) SendKey(VK_SHIFT, FALSE);
    SendKey(Vk, FALSE);
    SendKey(Vk, TRUE);
    if (Mods & SHIFT) SendKey(VK_SHIFT, TRUE);
    if (Mods & CTRL) SendKey(VK_CONTROL, TRUE);
    Sleep(250);
}

static BOOL GetSel(CONSOLE_SELECTION_INFO *Info)
{
    ZeroMemory(Info, sizeof(*Info));
    return GetConsoleSelectionInfo(Info) && (Info->dwFlags & CONSOLE_SELECTION_IN_PROGRESS);
}

static VOID CheckSel(const char *What, SHORT AnchorX, SHORT AnchorY, SHORT Left, SHORT Top, SHORT Right, SHORT Bottom)
{
    CONSOLE_SELECTION_INFO Info;

    if (!GetSel(&Info))
    {
        Fail("%s: no selection", What);
        return;
    }
    CHECK(Info.dwSelectionAnchor.X == AnchorX && Info.dwSelectionAnchor.Y == AnchorY &&
          Info.srSelection.Left == Left && Info.srSelection.Top == Top &&
          Info.srSelection.Right == Right && Info.srSelection.Bottom == Bottom,
          "%s: anchor (%d,%d) rect (%d,%d)-(%d,%d), expected anchor (%d,%d) rect (%d,%d)-(%d,%d)", What,
          Info.dwSelectionAnchor.X, Info.dwSelectionAnchor.Y,
          Info.srSelection.Left, Info.srSelection.Top, Info.srSelection.Right, Info.srSelection.Bottom,
          AnchorX, AnchorY, Left, Top, Right, Bottom);
}

static VOID SetClip(PCWSTR Text)
{
    HGLOBAL hMem;
    PWSTR p;

    if (!OpenClipboard(NULL)) return;
    EmptyClipboard();
    hMem = GlobalAlloc(GMEM_MOVEABLE, (wcslen(Text) + 1) * sizeof(WCHAR));
    p = GlobalLock(hMem);
    wcscpy(p, Text);
    GlobalUnlock(hMem);
    SetClipboardData(CF_UNICODETEXT, hMem);
    CloseClipboard();
}

static BOOL ClipIs(PCWSTR Text)
{
    HANDLE hMem;
    BOOL Same = FALSE;

    if (!OpenClipboard(NULL)) return FALSE;
    hMem = GetClipboardData(CF_UNICODETEXT);
    if (hMem)
    {
        PCWSTR p = GlobalLock(hMem);
        Same = !wcscmp(p, Text);
        GlobalUnlock(hMem);
    }
    CloseClipboard();
    return Same;
}

/* A screen with known text, the cursor at (10,5) */
static VOID Screen(VOID)
{
    CONSOLE_SCREEN_BUFFER_INFO Info;
    COORD c = {0, 0};
    DWORD Written;

    GetConsoleScreenBufferInfo(hOut, &Info);
    FillConsoleOutputCharacterW(hOut, L' ', (DWORD)Info.dwSize.X * 12, c, &Written);
    WriteConsoleOutputCharacterA(hOut, "line one alpha beta", 19, c, &Written);
    c.X = 10; c.Y = 5;
    SetConsoleCursorPosition(hOut, c);
    FlushConsoleInputBuffer(hIn);
}

static VOID Clear(VOID)
{
    int i;
    CONSOLE_SELECTION_INFO Info;

    for (i = 0; i < 3 && GetSel(&Info); i++) Press(VK_ESCAPE, 0);
    FlushConsoleInputBuffer(hIn);
}

/* The key-down events waiting in the input buffer: their virtual key codes, 0 for none */
static DWORD Events(WORD *Vks, DWORD Max)
{
    INPUT_RECORD Records[128];
    DWORD Count = 0, i, n = 0;

    PeekConsoleInputW(hIn, Records, _countof(Records), &Count);
    for (i = 0; i < Count && n < Max; i++)
    {
        if (Records[i].EventType == KEY_EVENT && Records[i].Event.KeyEvent.bKeyDown &&
            Records[i].Event.KeyEvent.wVirtualKeyCode != VK_SHIFT &&
            Records[i].Event.KeyEvent.wVirtualKeyCode != VK_CONTROL)
        {
            Vks[n++] = Records[i].Event.KeyEvent.wVirtualKeyCode;
        }
    }
    return n;
}

static VOID TestSelectionKeys(VOID)
{
    CONSOLE_SCREEN_BUFFER_INFO Info;
    SHORT Last;
    WORD Vks[16];

    GetConsoleScreenBufferInfo(hOut, &Info);
    Last = Info.dwSize.X - 1;

    /* processed input on: Shift+arrows select from the cursor; the first key selects the cursor cell */
    SetConsoleMode(hIn, BASE_MODE | ENABLE_PROCESSED_INPUT);
    Screen();
    Press(VK_RIGHT, SHIFT);
    CheckSel("Shift+Right 1", 10, 5, 10, 5, 10, 5);
    Press(VK_RIGHT, SHIFT);
    Press(VK_RIGHT, SHIFT);
    CheckSel("Shift+Right 3", 10, 5, 10, 5, 12, 5);
    Press(VK_LEFT, SHIFT);
    CheckSel("Shift+Left", 10, 5, 10, 5, 11, 5);
    Press(VK_DOWN, SHIFT);
    CheckSel("Shift+Down", 10, 5, 10, 5, 11, 6);
    Press(VK_UP, SHIFT);
    CheckSel("Shift+Up", 10, 5, 10, 5, 11, 5);
    Press(VK_END, SHIFT);
    CheckSel("Shift+End", 10, 5, 10, 5, Last, 5);
    Press(VK_HOME, SHIFT);
    CheckSel("Shift+Home", 10, 5, 0, 5, 10, 5);

    /* a plain arrow ends the selection and reaches the program */
    FlushConsoleInputBuffer(hIn);
    Press(VK_LEFT, 0);
    {
        CONSOLE_SELECTION_INFO Sel;
        DWORD n;

        CHECK(!GetSel(&Sel), "a plain arrow did not end the selection");
        n = Events(Vks, _countof(Vks));
        CHECK(n == 1 && Vks[0] == VK_LEFT, "the plain arrow did not reach the program (%lu keys)", n);
    }
    Clear();

    /* processed input off: no selection, the keys are the program's */
    SetConsoleMode(hIn, BASE_MODE);
    Screen();
    Press(VK_RIGHT, SHIFT);
    {
        CONSOLE_SELECTION_INFO Sel;
        DWORD n;

        CHECK(!GetSel(&Sel), "Shift+Right selected with processed input off");
        n = Events(Vks, _countof(Vks));
        CHECK(n == 1 && Vks[0] == VK_RIGHT, "Shift+Right did not reach the program (%lu keys)", n);
    }
    Clear();

    /* virtual terminal input does not stop the keyboard selection */
    SetConsoleMode(hIn, BASE_MODE | ENABLE_PROCESSED_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT);
    Screen();
    Press(VK_RIGHT, SHIFT);
    CheckSel("Shift+Right with VT input", 10, 5, 10, 5, 10, 5);
    Clear();
}

static VOID TestCtrlC(VOID)
{
    CONSOLE_SELECTION_INFO Sel;
    LONG Before;
    WORD Vks[16];
    DWORD n;

    /* with a selection it copies: no break, the selection ends, the text is on the clipboard */
    SetConsoleMode(hIn, BASE_MODE | ENABLE_PROCESSED_INPUT);
    Screen();
    SetClip(L"CLIPMARK");
    Press(VK_RIGHT, SHIFT);         /* the first key selects the cursor cell... */
    Press(VK_LEFT, SHIFT);          /* ...the next ones move the end */
    Press(VK_UP, SHIFT);
    Before = CtrlCCount;
    Press('C', CTRL);
    CHECK(CtrlCCount == Before, "Ctrl+C with a selection was a break");
    CHECK(!GetSel(&Sel), "Ctrl+C did not end the selection");
    CHECK(!ClipIs(L"CLIPMARK"), "Ctrl+C with a selection did not copy it");
    FlushConsoleInputBuffer(hIn);

    /* without one it is the break key */
    Before = CtrlCCount;
    Press('C', CTRL);
    CHECK(CtrlCCount == Before + 1, "Ctrl+C without a selection was not a break (%ld)", CtrlCCount - Before);

    /* with processed input off it is a key */
    SetConsoleMode(hIn, BASE_MODE);
    Screen();
    Before = CtrlCCount;
    Press('C', CTRL);
    CHECK(CtrlCCount == Before, "Ctrl+C was a break with processed input off");
    n = Events(Vks, _countof(Vks));
    CHECK(n == 1 && Vks[0] == 'C', "Ctrl+C did not reach the program as a key (%lu keys)", n);
}

static VOID TestCtrlV(VOID)
{
    WORD Vks[16];
    DWORD n;

    SetClip(L"PASTE");

    /* processed input on: pasted as keys */
    SetConsoleMode(hIn, BASE_MODE | ENABLE_PROCESSED_INPUT);
    Screen();
    Press('V', CTRL);
    n = Events(Vks, _countof(Vks));
    CHECK(n >= 5 && Vks[0] == 'P' && Vks[1] == 'A' && Vks[4] == 'E', "Ctrl+V did not paste (%lu keys)", n);

    /* Ctrl+Shift+V is not a paste */
    Screen();
    Press('V', CTRL | SHIFT);
    n = Events(Vks, _countof(Vks));
    CHECK(n == 1 && Vks[0] == 'V', "Ctrl+Shift+V pasted or was lost (%lu keys)", n);

    /* Shift+Insert pastes */
    Screen();
    Press(VK_INSERT, SHIFT);
    n = Events(Vks, _countof(Vks));
    CHECK(n >= 5 && Vks[0] == 'P', "Shift+Insert did not paste (%lu keys)", n);

    /* processed input off, or virtual terminal input: the program gets the key */
    SetConsoleMode(hIn, BASE_MODE);
    Screen();
    Press('V', CTRL);
    n = Events(Vks, _countof(Vks));
    CHECK(n == 1 && Vks[0] == 'V', "Ctrl+V with processed input off: %lu keys", n);

    SetConsoleMode(hIn, BASE_MODE | ENABLE_PROCESSED_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT);
    Screen();
    Press('V', CTRL);
    n = Events(Vks, _countof(Vks));
    CHECK(n >= 1 && Vks[n - 1] != 'P' && n < 5, "Ctrl+V with VT input pasted (%lu keys)", n);
}

static VOID TestCtrlA(VOID)
{
    WORD Vks[16];
    DWORD n;

    /* processed input on: selects everything up to the cursor, and the key is not the program's */
    SetConsoleMode(hIn, BASE_MODE | ENABLE_PROCESSED_INPUT);
    Screen();
    Press('A', CTRL);
    CheckSel("Ctrl+A", 0, 0, 0, 0, 10, 5);
    n = Events(Vks, _countof(Vks));
    CHECK(n == 0, "Ctrl+A reached the program (%lu keys)", n);
    Clear();

    /* processed input off: a key */
    SetConsoleMode(hIn, BASE_MODE);
    Screen();
    Press('A', CTRL);
    {
        CONSOLE_SELECTION_INFO Sel;

        CHECK(!GetSel(&Sel), "Ctrl+A selected with processed input off");
        n = Events(Vks, _countof(Vks));
        CHECK(n == 1 && Vks[0] == 'A', "Ctrl+A with processed input off: %lu keys", n);
    }
    Clear();
}

/*
 * Paste Text with Ctrl+V and collect the characters and virtual key codes of the key-down events
 * that arrive, without the modifier keys (they differ in number between the implementations).
 */
static DWORD PasteOf(PCWSTR Text, WCHAR *Chars, WORD *Vks, DWORD Max)
{
    INPUT_RECORD Records[256];
    DWORD Count = 0, i, n = 0;

    SetClip(Text);
    SetConsoleMode(hIn, BASE_MODE | ENABLE_PROCESSED_INPUT);
    Screen();
    Press('V', CTRL);
    PeekConsoleInputW(hIn, Records, _countof(Records), &Count);
    for (i = 0; i < Count && n < Max; i++)
    {
        KEY_EVENT_RECORD *Key;

        if (Records[i].EventType != KEY_EVENT) continue;
        Key = &Records[i].Event.KeyEvent;
        if (!Key->bKeyDown || Key->wVirtualKeyCode == VK_SHIFT ||
            Key->wVirtualKeyCode == VK_CONTROL || Key->wVirtualKeyCode == VK_MENU)
            continue;
        Chars[n] = Key->uChar.UnicodeChar;
        Vks[n] = Key->wVirtualKeyCode;
        n++;
    }
    FlushConsoleInputBuffer(hIn);
    return n;
}

static VOID CheckPaste(PCWSTR What, PCWSTR Text, PCWSTR Expected)
{
    WCHAR Chars[64];
    WORD Vks[64];
    DWORD n = PasteOf(Text, Chars, Vks, _countof(Chars) - 1);
    DWORD i;
    WCHAR Got[64], Shown[256];
    PWSTR p = Shown;

    for (i = 0; i < n; i++) Got[i] = Chars[i];
    Got[n] = UNICODE_NULL;
    *p = UNICODE_NULL;
    for (i = 0; i < n; i++)
    {
        StringCchPrintfW(p, Shown + _countof(Shown) - p, L"%02x ", Got[i]);
        p += wcslen(p);
    }
    CHECK(n == wcslen(Expected) && !wcsncmp(Got, Expected, n),
          "%ls: pasted %lu characters: %ls", What, n, Shown);
}

static VOID CheckPasteVks(PCWSTR What, PCWSTR Text, const WORD *Expected, DWORD Count)
{
    WCHAR Chars[64];
    WORD Vks[64];
    DWORD n = PasteOf(Text, Chars, Vks, _countof(Chars));
    DWORD i;

    if (n != Count)
    {
        Fail("%ls: pasted %lu keys, expected %lu", What, n, Count);
        return;
    }
    for (i = 0; i < n; i++)
        CHECK(Vks[i] == Expected[i], "%ls: key %lu has virtual key 0x%x, expected 0x%x", What, i, Vks[i], Expected[i]);
}

static VOID TestPasteFilter(VOID)
{
    static const WORD Digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    static const WORD Quotes[] = { 'A', 0xDE, 'B', 0xDE };
    static const WORD Dashes[] = { 'A', 0xBD, 'B', 0xBD };
    static const WORD Punct[] = { 0xBB, 0xBD, '8', 0xBF, 0xBE, 0xBB };

    /* what the filter does */
    CheckPaste(L"tabs", L"a\tb\t", L"ab");
    CheckPaste(L"double quotes", L"a\x201C" L"b\x201D", L"a\"b\"");
    CheckPasteVks(L"double quotes keys", L"a\x201C" L"b\x201D", Quotes, _countof(Quotes));
    CheckPaste(L"dashes", L"a\x2013" L"b\x2014", L"a-b-");
    CheckPasteVks(L"dashes keys", L"a\x2013" L"b\x2014", Dashes, _countof(Dashes));
    CheckPaste(L"no-break space", L"a\x00A0" L"b", L"a b");

    /* what it leaves alone */
    CheckPaste(L"trailing blanks", L"abc  \r\ndef  ", L"abc  \rdef  ");
    CheckPaste(L"CRLF pair", L"a\r\n\r\nb", L"a\r\rb");
    CheckPaste(L"LF alone", L"a\nb", L"a\nb");
    CheckPaste(L"CR alone", L"a\rb", L"a\rb");
    CheckPaste(L"leading blanks", L"   a", L"   a");

    /* the keys of the main keyboard, not the numeric keypad (needs the US layout) */
    if (LOWORD(GetKeyboardLayout(0)) == 0x0409)
    {
        CheckPaste(L"digits", L"0123456789", L"0123456789");
        CheckPasteVks(L"digit keys", L"0123456789", Digits, _countof(Digits));
        CheckPasteVks(L"punctuation keys", L"+-*/.=", Punct, _countof(Punct));
    }
}

/* VkKeyScanW is not a console function but it decides what a pasted character looks like */
static VOID TestVkKeyScan(VOID)
{
    if (LOWORD(GetKeyboardLayout(0)) != 0x0409)
    {
        skip("VkKeyScanW values are for the US keyboard layout\n");
        return;
    }
    ok(VkKeyScanW(L'1') == 0x0031, "VkKeyScanW('1') = 0x%04x\n", VkKeyScanW(L'1'));
    ok(VkKeyScanW(L'0') == 0x0030, "VkKeyScanW('0') = 0x%04x\n", VkKeyScanW(L'0'));
    ok(VkKeyScanW(L'9') == 0x0039, "VkKeyScanW('9') = 0x%04x\n", VkKeyScanW(L'9'));
    ok(VkKeyScanW(L'+') == 0x01BB, "VkKeyScanW('+') = 0x%04x\n", VkKeyScanW(L'+'));
    ok(VkKeyScanW(L'-') == 0x00BD, "VkKeyScanW('-') = 0x%04x\n", VkKeyScanW(L'-'));
    ok(VkKeyScanW(L'*') == 0x0138, "VkKeyScanW('*') = 0x%04x\n", VkKeyScanW(L'*'));
    ok(VkKeyScanW(L'/') == 0x00BF, "VkKeyScanW('/') = 0x%04x\n", VkKeyScanW(L'/'));
    ok(VkKeyScanW(L'.') == 0x00BE, "VkKeyScanW('.') = 0x%04x\n", VkKeyScanW(L'.'));
    ok(VkKeyScanW(L'=') == 0x00BB, "VkKeyScanW('=') = 0x%04x\n", VkKeyScanW(L'='));
}

/* The child: its own console window; the report goes to a file */
static BOOL FilterOnPaste(VOID);

static DWORD ChildMain(PCWSTR ReportFile)
{
    DWORD Saved = 0;
    CHAR Narrow[MAX_PATH];

    WideCharToMultiByte(CP_ACP, 0, ReportFile, -1, Narrow, sizeof(Narrow), NULL, NULL);
    Report = fopen(Narrow, "w");
    if (!Report) return 0xFFFF;
    hIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    hOut = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    hWnd = GetConsoleWindow();
    if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE || !hWnd)
    {
        fprintf(Report, "SKIP no console window\n");
        fclose(Report);
        return 0;
    }
    SetForegroundWindow(hWnd);
    Sleep(500);
    if (GetForegroundWindow() != hWnd)
    {
        keybd_event(VK_MENU, 0, 0, 0);
        keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);
        SetForegroundWindow(hWnd);
        Sleep(500);
    }
    if (GetForegroundWindow() != hWnd)
    {
        fprintf(Report, "SKIP the console window cannot take the keyboard focus\n");
        fclose(Report);
        return 0;
    }

    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    GetConsoleMode(hIn, &Saved);
    TestSelectionKeys();
    TestCtrlC();
    TestCtrlV();
    TestCtrlA();
    if (FilterOnPaste())
        TestPasteFilter();
    SetConsoleMode(hIn, Saved);
    fclose(Report);
    return Failures;
}

/* The value of a DWORD in HKCU\Console, Default when it is not there */
static BOOL ConsoleFlag(PCWSTR Name, BOOL Default)
{
    HKEY Key;
    DWORD Value, Size = sizeof(Value), Type;
    BOOL Flag = Default;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Console", 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return Default;
    if (RegQueryValueExW(Key, Name, NULL, &Type, (PBYTE)&Value, &Size) == ERROR_SUCCESS && Type == REG_DWORD)
        Flag = (Value != 0);
    RegCloseKey(Key);
    return Flag;
}

static BOOL ShortcutsDisabled(VOID)
{
    return ConsoleFlag(L"CtrlKeyShortcutsDisabled", FALSE);
}

static BOOL FilterOnPaste(VOID)
{
    return ConsoleFlag(L"FilterOnPaste", TRUE);
}

START_TEST(ConsoleKeyShortcuts)
{
    int argc;
    char **argv;
    WCHAR FileName[MAX_PATH], TempPath[MAX_PATH], ReportFile[MAX_PATH], CommandLine[3 * MAX_PATH];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    DWORD ExitCode = 0, Wait;
    FILE *File;
    char Line[512];

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        WCHAR Wide[MAX_PATH];

        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, Wide, _countof(Wide));
        ExitProcess(ChildMain(Wide));
    }

    TestVkKeyScan();

    if (ShortcutsDisabled())
    {
        skip("HKCU\\Console turns the Ctrl key shortcuts off\n");
        return;
    }

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    GetTempPathW(_countof(TempPath), TempPath);
    StringCbPrintfW(ReportFile, sizeof(ReportFile), L"%lsckshort-%lu.txt", TempPath, GetCurrentProcessId());
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" ConsoleKeyShortcuts child \"%ls\"", FileName, ReportFile);
    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                        NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        skip("CreateProcessW failed with %lu\n", GetLastError());
        return;
    }
    CloseHandle(ProcessInfo.hThread);
    Wait = WaitForSingleObject(ProcessInfo.hProcess, 120000);
    ok(Wait == WAIT_OBJECT_0, "the child did not end\n");
    if (Wait != WAIT_OBJECT_0)
    {
        TerminateProcess(ProcessInfo.hProcess, 1);
        CloseHandle(ProcessInfo.hProcess);
        DeleteFileW(ReportFile);
        return;
    }
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    CloseHandle(ProcessInfo.hProcess);

    File = _wfopen(ReportFile, L"r");
    if (File)
    {
        while (fgets(Line, sizeof(Line), File))
        {
            if (!strncmp(Line, "SKIP", 4))
            {
                skip("%s", Line + 5);
                ExitCode = 0;
            }
            else
            {
                ok(0, "%s", Line);
            }
        }
        fclose(File);
    }
    DeleteFileW(ReportFile);
    ok(ExitCode == 0, "%lu checks failed\n", ExitCode);
}
