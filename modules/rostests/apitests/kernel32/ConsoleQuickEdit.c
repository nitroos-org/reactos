/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test the QuickEdit and insert input modes of a console
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows 10 22H2 (build 19045): a new
 * console starts with QuickEdit, insert and mouse input on, and an input mode
 * set without ENABLE_EXTENDED_FLAGS turns QuickEdit and insert mode off.
 */

#include "precomp.h"

#ifndef ENABLE_INSERT_MODE
#define ENABLE_INSERT_MODE      0x0020
#endif
#ifndef ENABLE_QUICK_EDIT_MODE
#define ENABLE_QUICK_EDIT_MODE  0x0040
#endif
#ifndef ENABLE_EXTENDED_FLAGS
#define ENABLE_EXTENDED_FLAGS   0x0080
#endif
#ifndef ENABLE_AUTO_POSITION
#define ENABLE_AUTO_POSITION    0x0100
#endif

#define BASIC_MODES  (ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_MOUSE_INPUT)
#define DEFAULT_MODE (BASIC_MODES | ENABLE_INSERT_MODE | ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS)

/* Windows adds ENABLE_AUTO_POSITION to a new console: not part of this test */
#define MODE_MASK    (~(DWORD)ENABLE_AUTO_POSITION)

static VOID
CheckMode(HANDLE hIn, DWORD Set, DWORD Expected)
{
    DWORD Mode = 0;
    BOOL Ret;

    Ret = SetConsoleMode(hIn, Set);
    ok(Ret, "SetConsoleMode(0x%lx) failed with %lu\n", Set, GetLastError());
    Ret = GetConsoleMode(hIn, &Mode);
    ok(Ret, "GetConsoleMode failed with %lu\n", GetLastError());
    Mode &= MODE_MASK;
    ok(Mode == Expected, "after SetConsoleMode(0x%lx) the mode is 0x%lx, expected 0x%lx\n", Set, Mode, Expected);
}

static VOID
TestSetMode(VOID)
{
    HANDLE hIn;
    DWORD Saved = 0;

    hIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE)
    {
        skip("No console (error %lu)\n", GetLastError());
        return;
    }
    GetConsoleMode(hIn, &Saved);

    /* The control modes only take effect with ENABLE_EXTENDED_FLAGS, and each one is set by its flag alone */
    CheckMode(hIn, ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE,
              ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE);
    CheckMode(hIn, ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS,
              ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS);
    CheckMode(hIn, ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE,
              ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE);
    CheckMode(hIn, ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE,
              ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE);

    /* A mode without ENABLE_EXTENDED_FLAGS turns QuickEdit and insert mode off */
    CheckMode(hIn, ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE,
              ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE);
    CheckMode(hIn, ENABLE_MOUSE_INPUT, ENABLE_MOUSE_INPUT);
    CheckMode(hIn, ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE,
              ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE);
    CheckMode(hIn, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT,
              ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
    CheckMode(hIn, 0, 0);

    /* The saved mode, with its control modes, comes back whole */
    CheckMode(hIn, Saved & MODE_MASK, Saved & MODE_MASK);

    SetConsoleMode(hIn, Saved);
    CloseHandle(hIn);
}

static BOOL
DefaultsAreCustomized(VOID)
{
    HKEY Key;
    DWORD Value, Size, Type;
    BOOL Customized = FALSE;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Console", 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return FALSE;
    Size = sizeof(Value);
    if (RegQueryValueExW(Key, L"QuickEdit", NULL, &Type, (PBYTE)&Value, &Size) == ERROR_SUCCESS &&
        Type == REG_DWORD && Value == 0)
        Customized = TRUE;
    Size = sizeof(Value);
    if (RegQueryValueExW(Key, L"InsertMode", NULL, &Type, (PBYTE)&Value, &Size) == ERROR_SUCCESS &&
        Type == REG_DWORD && Value == 0)
        Customized = TRUE;
    RegCloseKey(Key);
    return Customized;
}

/* The child runs in a console of its own and reports the input mode it starts with */
static DWORD
ChildMode(VOID)
{
    HANDLE hIn;
    DWORD Mode = 0;

    hIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING, 0, NULL);
    if (hIn == INVALID_HANDLE_VALUE || !GetConsoleMode(hIn, &Mode))
        return 0xFFFF;
    return Mode & MODE_MASK;
}

static VOID
TestNewConsole(VOID)
{
    WCHAR FileName[MAX_PATH], CommandLine[MAX_PATH + 64];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    DWORD ExitCode = 0, Wait;

    if (DefaultsAreCustomized())
    {
        skip("HKCU\\Console turns QuickEdit or insert mode off\n");
        return;
    }

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" ConsoleQuickEdit child", FileName);
    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                        NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        skip("CreateProcessW failed with %lu\n", GetLastError());
        return;
    }
    CloseHandle(ProcessInfo.hThread);
    Wait = WaitForSingleObject(ProcessInfo.hProcess, 30000);
    ok(Wait == WAIT_OBJECT_0, "the child did not end\n");
    if (Wait != WAIT_OBJECT_0)
    {
        TerminateProcess(ProcessInfo.hProcess, 1);
        CloseHandle(ProcessInfo.hProcess);
        return;
    }
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    CloseHandle(ProcessInfo.hProcess);
    ok(ExitCode == DEFAULT_MODE, "the mode of a new console is 0x%lx, expected 0x%x\n", ExitCode, DEFAULT_MODE);
}

START_TEST(ConsoleQuickEdit)
{
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "child"))
        ExitProcess(ChildMode());

    TestSetMode();
    TestNewConsole();
}
