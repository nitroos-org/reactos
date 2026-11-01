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

typedef struct _HOST
{
    HANDLE PipeIn, PipeOut, Signal, ConsoleIn, ConsoleOut, Client;
    SHORT Width, Height;
    CHAR_INFO *Previous, *Current;
    BOOL Painted, CursorVisible, SawClient;
    COORD Cursor;
    BYTE Utf8[4], Utf8Count, Utf8Length;
    CHAR Sequence[32];
    BYTE SequenceLength, Escape;
    DWORD EscapeTime;
} HOST;

static BOOL
HostWrite(HOST *Host, const CHAR *Text, DWORD Length)
{
    DWORD Written;
    return WriteFile(Host->PipeOut, Text, Length, &Written, NULL) && Written == Length;
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

static BOOL
HostResize(HOST *Host, SHORT Width, SHORT Height)
{
    SMALL_RECT Window;
    COORD Size;
    CHAR_INFO *Previous, *Current;
    SIZE_T Count;

    if (Width <= 0 || Height <= 0 || (SIZE_T)Width * Height > 1000000)
        return FALSE;
    Count = (SIZE_T)Width * Height;
    Previous = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Count * sizeof(*Previous));
    Current = HeapAlloc(GetProcessHeap(), 0, Count * sizeof(*Current));
    if (!Previous || !Current)
    {
        if (Previous) HeapFree(GetProcessHeap(), 0, Previous);
        if (Current) HeapFree(GetProcessHeap(), 0, Current);
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
        return FALSE;
    }
    SetConsoleWindowInfo(Host->ConsoleOut, TRUE, &Window);
    if (Host->Previous) HeapFree(GetProcessHeap(), 0, Host->Previous);
    if (Host->Current) HeapFree(GetProcessHeap(), 0, Host->Current);
    Host->Previous = Previous;
    Host->Current = Current;
    Host->Width = Width;
    Host->Height = Height;
    Host->Painted = FALSE;
    return TRUE;
}

static BOOL
HostPaint(HOST *Host)
{
    CONSOLE_SCREEN_BUFFER_INFO Info;
    CONSOLE_CURSOR_INFO CursorInfo;
    COORD BufferSize, BufferOrigin = {0, 0};
    SMALL_RECT Region;
    CHAR *Line;
    DWORD Index, Row, Column, Length, Used;
    BOOL Changed = FALSE;
    WORD Attribute;
    CHAR Utf8[8];
    static const BYTE Palette[8] = {0, 4, 2, 6, 1, 5, 3, 7};

    if (!GetConsoleScreenBufferInfo(Host->ConsoleOut, &Info)) return FALSE;
    if (!Host->Painted && !HostWrite(Host, "\033[?25l\033[2J", 10)) return FALSE;
    BufferSize.X = Host->Width;
    BufferSize.Y = Host->Height;
    Region.Left = Info.srWindow.Left;
    Region.Top = Info.srWindow.Top;
    Region.Right = Region.Left + Host->Width - 1;
    Region.Bottom = Region.Top + Host->Height - 1;
    if (Region.Right >= Info.dwSize.X) Region.Right = Info.dwSize.X - 1;
    if (Region.Bottom >= Info.dwSize.Y) Region.Bottom = Info.dwSize.Y - 1;
    ZeroMemory(Host->Current, (SIZE_T)Host->Width * Host->Height * sizeof(*Host->Current));
    if (!ReadConsoleOutputW(Host->ConsoleOut, Host->Current, BufferSize,
                            BufferOrigin, &Region)) return FALSE;

    Line = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Host->Width * 64 + 128);
    if (!Line) return FALSE;
    for (Row = 0; Row < (DWORD)Host->Height; ++Row)
    {
        Used = 0;
        Attribute = 0xffff;
        for (Column = 0; Column < (DWORD)Host->Width; ++Column)
        {
            Index = Row * Host->Width + Column;
            if (Host->Painted &&
                Host->Previous[Index].Char.UnicodeChar == Host->Current[Index].Char.UnicodeChar &&
                Host->Previous[Index].Attributes == Host->Current[Index].Attributes)
                continue;

            Changed = TRUE;
            Used += sprintf(Line + Used, "\033[%lu;%luH", Row + 1, Column + 1);
            do
            {
                WCHAR Character;
                Index = Row * Host->Width + Column;
                if (Host->Painted &&
                    Host->Previous[Index].Char.UnicodeChar == Host->Current[Index].Char.UnicodeChar &&
                    Host->Previous[Index].Attributes == Host->Current[Index].Attributes)
                    break;
                if (Attribute != Host->Current[Index].Attributes)
                {
                    Attribute = Host->Current[Index].Attributes;
                    Used += sprintf(Line + Used, "\033[%u;%um",
                                    (UINT)(30 + Palette[Attribute & 7] + ((Attribute & 8) ? 60 : 0)),
                                    (UINT)(40 + Palette[(Attribute >> 4) & 7] + ((Attribute & 128) ? 60 : 0)));
                }
                Character = Host->Current[Index].Char.UnicodeChar;
                if (!Character || Character < 32) Character = L' ';
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
        if (Used && !HostWrite(Host, Line, Used))
        {
            HeapFree(GetProcessHeap(), 0, Line);
            return FALSE;
        }
    }
    HeapFree(GetProcessHeap(), 0, Line);
    CopyMemory(Host->Previous, Host->Current,
               (SIZE_T)Host->Width * Host->Height * sizeof(*Host->Current));
    Host->Painted = TRUE;
    if (GetConsoleCursorInfo(Host->ConsoleOut, &CursorInfo))
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
                             (UINT)(Info.dwCursorPosition.Y - Region.Top + 1),
                             (UINT)(Info.dwCursorPosition.X - Region.Left + 1));
            Host->Cursor = Info.dwCursorPosition;
        }
        if (Count && !HostWrite(Host, Position, Count)) return FALSE;
    }
    return TRUE;
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

static VOID
HostInput(HOST *Host, BYTE Byte)
{
    DWORD Modifiers = 0;
    WCHAR Character;
    WORD Key;

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
                                Host->Utf8Count, &Character, 1) != 1)
            Character = 0xfffd;
        Host->Utf8Length = Host->Utf8Count = 0;
    }
    else
    {
        Character = Byte;
        if (Byte >= 1 && Byte <= 26 && Byte != '\r' && Byte != '\t')
        {
            Modifiers |= LEFT_CTRL_PRESSED;
            Character = L'A' + Byte - 1;
        }
    }
    Key = Character >= L'A' && Character <= L'Z' ? Character :
          Character >= L'a' && Character <= L'z' ? Character - L'a' + L'A' :
          Character >= L'0' && Character <= L'9' ? Character :
          Character == L' ' ? VK_SPACE : 0;
    if (Modifiers & LEFT_CTRL_PRESSED)
        Key = Character;
    if (Byte == '\r' || Byte == '\n') Key = VK_RETURN, Character = L'\r';
    else if (Byte == '\b' || Byte == 0x7f) Key = VK_BACK, Character = L'\b';
    else if (Byte == '\t') Key = VK_TAB;
    else if (Byte == 0x1b) Key = VK_ESCAPE;
    HostKey(Host, Key, Character, Modifiers);
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
    DWORD Available, Read, Written, Message[3], Pids[256], Count;
    BYTE Bytes[256];
    int Index;

    ZeroMemory(&Host, sizeof(Host));
    Host.Width = 80;
    Host.Height = 25;
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
                if (Message[0] == 8 && Message[1] <= 32767 && Message[2] <= 32767)
                    HostResize(&Host, (SHORT)Message[1], (SHORT)Message[2]);
                else if (Message[0] == 1 && !Host.Client)
                {
                    Host.Client = OpenProcess(SYNCHRONIZE, FALSE, Message[1]);
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
