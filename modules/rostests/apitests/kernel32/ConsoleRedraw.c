/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that the console window shows what the screen buffer holds: cells that the program
 *              erased must show the background, with the default font and with large ones
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <wingdi.h>
#include <winuser.h>

#ifndef SW_SHOWNOACTIVATE
#define SW_SHOWNOACTIVATE 4
#endif

/*
 * The parent sets the console defaults in the registry (font face and height, window and buffer size) and
 * starts the child in a console of its own. The child fills the rows with colored text and erases it (as the
 * progress bar of a download does), writes a line that wraps and erases it, and draws a colored block and
 * erases it. After each step it compares the pixels of the window with the screen buffer: a cell that holds a
 * blank on the default background must show nothing but the background. The child reports the number of cells
 * that do not.
 */
#define CHILD_TIMEOUT_MS    120000
#define VIEW_COLUMNS        50
#define VIEW_ROWS           10

static const WCHAR ConsoleKeyName[] = L"Console";

typedef struct _SAVED_VALUE
{
    PCWSTR Name;
    BOOL Existed;
    DWORD Type;
    DWORD Size;
    BYTE Data[128];
} SAVED_VALUE;

static SAVED_VALUE Saved[] =
{
    { L"FaceName" }, { L"FontSize" }, { L"FontFamily" }, { L"FontWeight" },
    { L"WindowSize" }, { L"ScreenBufferSize" },
};

static
VOID
SaveConsoleDefaults(HKEY hKey)
{
    ULONG i;

    for (i = 0; i < _countof(Saved); i++)
    {
        Saved[i].Size = sizeof(Saved[i].Data);
        Saved[i].Existed = RegQueryValueExW(hKey, Saved[i].Name, NULL, &Saved[i].Type,
                                            Saved[i].Data, &Saved[i].Size) == ERROR_SUCCESS;
    }
}

static
VOID
RestoreConsoleDefaults(HKEY hKey)
{
    ULONG i;

    for (i = 0; i < _countof(Saved); i++)
    {
        if (Saved[i].Existed)
            RegSetValueExW(hKey, Saved[i].Name, 0, Saved[i].Type, Saved[i].Data, Saved[i].Size);
        else
            RegDeleteValueW(hKey, Saved[i].Name);
    }
}

static
VOID
SetDword(HKEY hKey, PCWSTR Name, DWORD Value)
{
    RegSetValueExW(hKey, Name, 0, REG_DWORD, (PBYTE)&Value, sizeof(Value));
}

/* The window's client pixels, 32 bits per pixel, top down */
static
PBYTE
CaptureClient(HWND hWnd, PLONG Width, PLONG Height)
{
    RECT Client;
    BITMAPINFO Info;
    HDC hWndDC, hMemDC;
    HBITMAP hBitmap;
    PVOID Bits = NULL;
    PBYTE Copy = NULL;

    if (!GetClientRect(hWnd, &Client) || Client.right <= 0 || Client.bottom <= 0)
        return NULL;
    hWndDC = GetDC(hWnd);
    if (!hWndDC)
        return NULL;
    hMemDC = CreateCompatibleDC(hWndDC);
    RtlZeroMemory(&Info, sizeof(Info));
    Info.bmiHeader.biSize = sizeof(Info.bmiHeader);
    Info.bmiHeader.biWidth = Client.right;
    Info.bmiHeader.biHeight = -Client.bottom;
    Info.bmiHeader.biPlanes = 1;
    Info.bmiHeader.biBitCount = 32;
    Info.bmiHeader.biCompression = BI_RGB;
    hBitmap = CreateDIBSection(hWndDC, &Info, DIB_RGB_COLORS, &Bits, NULL, 0);
    if (hMemDC && hBitmap && Bits)
    {
        SelectObject(hMemDC, hBitmap);
        if (BitBlt(hMemDC, 0, 0, Client.right, Client.bottom, hWndDC, 0, 0, SRCCOPY))
        {
            Copy = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Client.right * Client.bottom * 4);
            if (Copy)
                RtlCopyMemory(Copy, Bits, (SIZE_T)Client.right * Client.bottom * 4);
        }
    }
    if (hBitmap)
        DeleteObject(hBitmap);
    if (hMemDC)
        DeleteDC(hMemDC);
    ReleaseDC(hWnd, hWndDC);
    *Width = Client.right;
    *Height = Client.bottom;
    return Copy;
}

/* The number of cells that hold a blank on the default background and do not look like it; the caret cell is left out */
static
LONG
CountStaleCells(HWND hWnd, HANDLE hCon, PLONG CellWidthOut, PLONG CellHeightOut)
{
    CONSOLE_SCREEN_BUFFER_INFO Info;
    CHAR_INFO Cells[VIEW_COLUMNS * VIEW_ROWS];
    COORD Size, Origin = { 0, 0 };
    SMALL_RECT Rect;
    PBYTE Pixels;
    LONG Width, Height, Columns, Rows, CellWidth, CellHeight, X, Y, PX, PY, Bad = 0;

    Sleep(700); /* the window thread paints after the output */
    if (!GetConsoleScreenBufferInfo(hCon, &Info))
        return -1;
    Columns = Info.srWindow.Right - Info.srWindow.Left + 1;
    Rows = Info.srWindow.Bottom - Info.srWindow.Top + 1;
    if (Columns > VIEW_COLUMNS || Rows > VIEW_ROWS)
        return -1;
    Pixels = CaptureClient(hWnd, &Width, &Height);
    if (!Pixels)
        return -1;
    /* The cell size is what the window shows: its client area over the cells */
    CellWidth = (Width + Columns / 2) / Columns;
    CellHeight = (Height + Rows / 2) / Rows;
    *CellWidthOut = CellWidth;
    *CellHeightOut = CellHeight;

    Size.X = (SHORT)Columns;
    Size.Y = (SHORT)Rows;
    Rect = Info.srWindow;
    if (!ReadConsoleOutputW(hCon, Cells, Size, Origin, &Rect))
    {
        HeapFree(GetProcessHeap(), 0, Pixels);
        return -1;
    }

    for (Y = 0; Y < Rows; Y++)
    {
        for (X = 0; X < Columns; X++)
        {
            CHAR_INFO *Cell = &Cells[Y * Columns + X];
            BOOL Stale = FALSE;

            if ((Cell->Char.UnicodeChar != L' ' && Cell->Char.UnicodeChar != 0) || (Cell->Attributes & 0xFF) != 7)
                continue;
            if (X == Info.dwCursorPosition.X - Info.srWindow.Left &&
                Y == Info.dwCursorPosition.Y - Info.srWindow.Top)
                continue;
            for (PY = Y * CellHeight; PY < (Y + 1) * CellHeight && PY < Height && !Stale; PY++)
            {
                PBYTE Row = Pixels + (SIZE_T)PY * Width * 4;

                for (PX = X * CellWidth; PX < (X + 1) * CellWidth && PX < Width; PX++)
                {
                    if (Row[PX * 4] | Row[PX * 4 + 1] | Row[PX * 4 + 2])
                    {
                        Stale = TRUE;
                        break;
                    }
                }
            }
            if (Stale)
                Bad++;
        }
    }
    HeapFree(GetProcessHeap(), 0, Pixels);
    return Bad;
}

static
VOID
EraseAll(HANDLE hCon)
{
    CONSOLE_SCREEN_BUFFER_INFO Info;
    COORD Home = { 0, 0 };
    DWORD Written;

    GetConsoleScreenBufferInfo(hCon, &Info);
    FillConsoleOutputCharacterW(hCon, L' ', Info.dwSize.X * Info.dwSize.Y, Home, &Written);
    FillConsoleOutputAttribute(hCon, 7, Info.dwSize.X * Info.dwSize.Y, Home, &Written);
    SetConsoleCursorPosition(hCon, Home);
}

static
VOID
RunChild(VOID)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE), hCon;
    HWND hWnd = GetConsoleWindow();
    CONSOLE_SCREEN_BUFFER_INFO Info;
    CHAR Line[160], Text[400];
    LONG Bad[4], CellWidth = 0, CellHeight = 0, Count, Total, Y, i;
    DWORD Written;
    COORD At, Home = { 0, 0 };

    hCon = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
    if (hCon == INVALID_HANDLE_VALUE || !hWnd || !IsWindowVisible(hWnd))
    {
        StringCbPrintfA(Line, sizeof(Line), "noconsole\n");
        WriteFile(hOut, Line, (DWORD)strlen(Line), &Written, NULL);
        return;
    }

    /* 1. every row filled with colored text, then erased */
    EraseAll(hCon);
    GetConsoleScreenBufferInfo(hCon, &Info);
    for (Y = Info.srWindow.Top; Y <= Info.srWindow.Bottom; Y++)
    {
        At.X = 0;
        At.Y = (SHORT)Y;
        FillMemory(Text, sizeof(Text), 'W');
        WriteConsoleOutputCharacterA(hCon, Text, VIEW_COLUMNS, At, &Written);
        FillConsoleOutputAttribute(hCon, (WORD)(0x1E + (Y & 1) * 0x10), VIEW_COLUMNS, At, &Written);
    }
    Sleep(300);
    EraseAll(hCon);
    Bad[0] = CountStaleCells(hWnd, hCon, &CellWidth, &CellHeight);

    /* 2. a line longer than the window, wrapped, then erased */
    for (i = 0; i < 160; i++)
        Text[i] = (CHAR)('a' + i % 26);
    SetConsoleCursorPosition(hCon, Home);
    WriteConsoleA(hCon, Text, 160, &Written, NULL);
    Sleep(300);
    EraseAll(hCon);
    Bad[1] = CountStaleCells(hWnd, hCon, &CellWidth, &CellHeight);

    /* 3. a progress bar: a colored block that grows, then erased */
    GetConsoleScreenBufferInfo(hCon, &Info);
    for (i = 4; i <= 40; i += 6)
    {
        At.X = 0;
        At.Y = Info.srWindow.Bottom;
        FillConsoleOutputCharacterA(hCon, ' ', VIEW_COLUMNS, At, &Written);
        FillConsoleOutputAttribute(hCon, 0xE0, i, At, &Written);
        At.Y--;
        StringCbPrintfA(Text, sizeof(Text), "Downloading %ld%% [", i * 2);
        WriteConsoleOutputCharacterA(hCon, Text, (DWORD)strlen(Text), At, &Written);
        Sleep(20);
    }
    Sleep(300);
    EraseAll(hCon);
    Bad[2] = CountStaleCells(hWnd, hCon, &CellWidth, &CellHeight);

    /* 4. the view scrolls under numbered lines, then everything is erased */
    SetConsoleCursorPosition(hCon, Home);
    for (i = 0; i < 40; i++)
    {
        StringCbPrintfA(Text, sizeof(Text), "line %03ld the quick brown fox jumps over the lazy dog\r\n", i);
        WriteConsoleA(hCon, Text, (DWORD)strlen(Text), &Written, NULL);
    }
    Sleep(300);
    EraseAll(hCon);
    GetConsoleScreenBufferInfo(hCon, &Info);
    {
        SMALL_RECT Top = { 0, 0, (SHORT)(VIEW_COLUMNS - 1), (SHORT)(VIEW_ROWS - 1) };
        SetConsoleWindowInfo(hCon, TRUE, &Top);
    }
    Bad[3] = CountStaleCells(hWnd, hCon, &CellWidth, &CellHeight);

    Total = 0;
    for (i = 0; i < 4; i++)
        Total += (Bad[i] < 0) ? 0 : Bad[i];
    Count = (Bad[0] < 0 || Bad[1] < 0 || Bad[2] < 0 || Bad[3] < 0) ? 1 : 0;
    StringCbPrintfA(Line, sizeof(Line), "cell=%ldx%ld unreadable=%ld stale=%ld,%ld,%ld,%ld\n",
                    CellWidth, CellHeight, Count, Bad[0], Bad[1], Bad[2], Bad[3]);
    WriteFile(hOut, Line, (DWORD)strlen(Line), &Written, NULL);
    CloseHandle(hCon);
}

/* Runs the child with the console defaults of FontHeight (0: whatever the system has) and reads its report */
static
VOID
TestFontHeight(HKEY hKey, DWORD FontHeight)
{
    WCHAR FileName[MAX_PATH];
    WCHAR CommandLine[MAX_PATH + 40];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    HANDLE hRead, hWrite;
    CHAR Output[160];
    DWORD Wait, Count, Used = 0;
    LONG CellWidth = 0, CellHeight = 0, Unreadable = 0, Stale[4] = { -1, -1, -1, -1 };
    BOOL Success;

    RestoreConsoleDefaults(hKey);
    if (FontHeight)
    {
        RegSetValueExW(hKey, L"FaceName", 0, REG_SZ, (PBYTE)L"Fixedsys Excelsior 3.01", sizeof(L"Fixedsys Excelsior 3.01"));
        SetDword(hKey, L"FontSize", FontHeight << 16);
        SetDword(hKey, L"FontFamily", 0x36);
        SetDword(hKey, L"FontWeight", 400);
    }
    SetDword(hKey, L"WindowSize", (VIEW_ROWS << 16) | VIEW_COLUMNS);
    SetDword(hKey, L"ScreenBufferSize", (300 << 16) | VIEW_COLUMNS);

    if (!CreatePipe(&hRead, &hWrite, &Sa, 0))
    {
        skip("CreatePipe failed with %lu\n", GetLastError());
        return;
    }
    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" ConsoleRedraw child", FileName);
    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    StartupInfo.wShowWindow = SW_SHOWNOACTIVATE;
    StartupInfo.hStdOutput = hWrite;
    StartupInfo.hStdError = hWrite;
    StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
    Success = CreateProcessW(FileName, CommandLine, NULL, NULL, TRUE, CREATE_NEW_CONSOLE,
                             NULL, NULL, &StartupInfo, &ProcessInfo);
    CloseHandle(hWrite);
    if (!Success)
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        CloseHandle(hRead);
        return;
    }

    Wait = WaitForSingleObject(ProcessInfo.hProcess, CHILD_TIMEOUT_MS);
    ok(Wait == WAIT_OBJECT_0, "The child did not finish (%lu)\n", Wait);
    if (Wait != WAIT_OBJECT_0)
        TerminateProcess(ProcessInfo.hProcess, 1);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);

    RtlZeroMemory(Output, sizeof(Output));
    while (Used < sizeof(Output) - 1 && ReadFile(hRead, Output + Used, sizeof(Output) - 1 - Used, &Count, NULL) && Count)
        Used += Count;
    CloseHandle(hRead);

    if (strstr(Output, "noconsole"))
    {
        skip("No visible console window\n");
        return;
    }
    if (sscanf(Output, "cell=%ldx%ld unreadable=%ld stale=%ld,%ld,%ld,%ld", &CellWidth, &CellHeight, &Unreadable,
               &Stale[0], &Stale[1], &Stale[2], &Stale[3]) != 7)
    {
        ok(0, "Unexpected report \"%s\"\n", Output);
        return;
    }
    if (Unreadable)
    {
        skip("The console window could not be read back\n");
        return;
    }
    ok(Stale[0] == 0, "Font %lu (cell %ldx%ld): %ld erased cells still show text after full rows\n",
       FontHeight, CellWidth, CellHeight, Stale[0]);
    ok(Stale[1] == 0, "Font %lu (cell %ldx%ld): %ld erased cells still show text after a wrapped line\n",
       FontHeight, CellWidth, CellHeight, Stale[1]);
    ok(Stale[2] == 0, "Font %lu (cell %ldx%ld): %ld erased cells still show a progress bar\n",
       FontHeight, CellWidth, CellHeight, Stale[2]);
    ok(Stale[3] == 0, "Font %lu (cell %ldx%ld): %ld erased cells still show scrolled output\n",
       FontHeight, CellWidth, CellHeight, Stale[3]);
}

START_TEST(ConsoleRedraw)
{
    int argc;
    char **argv;
    HKEY hKey;
    DWORD Disposition;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "child"))
    {
        RunChild();
        return;
    }

    if (RegCreateKeyExW(HKEY_CURRENT_USER, ConsoleKeyName, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &hKey,
                        &Disposition) != ERROR_SUCCESS)
    {
        skip("The console key is not available\n");
        return;
    }
    SaveConsoleDefaults(hKey);

    TestFontHeight(hKey, 0);
    TestFontHeight(hKey, 16);
    TestFontHeight(hKey, 24);

    RestoreConsoleDefaults(hKey);
    RegCloseKey(hKey);
}
