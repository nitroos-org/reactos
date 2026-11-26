/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The security cookie the loader makes for every image that has a slot for one: the executable, a DLL
 *              imported statically, a DLL found by LoadLibrary, one loaded by delay load, one loaded by a forwarder,
 *              one without an entry point; not the default, not shared by two images or two processes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Child processes (loadconfig_cookie_exe.exe) write what they see to a file; this test reads the files.
 * 20 processes load loadconfig_cookie2.dll 100 times each: the 2000 cookies are all different. The old recipe made
 * the cookie from the performance counter, the ids and the tick count (32-bit terms: on a 64-bit system the upper
 * half was always zero, and two loads within a tick repeat).
 */

#include "loadconfig.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>

#ifdef _WIN64
#define DEFAULT_COOKIE 0x00002B992DDFA232ull
#else
#define DEFAULT_COOKIE 0xBB40E64E
#endif

#define PROCESSES 20
#define LOADS 100
#define MAX_VALUES (PROCESSES * (LOADS * 2 + 8))

typedef struct
{
    char Name[16];
    ULONGLONG Value;
} VALUE;

static VALUE Values[MAX_VALUES];
static ULONG ValueCount;

/* runs the child with the mode; its lines are added to Values. FALSE when the child did not finish */
static BOOL RunChild(const WCHAR *Mode, ULONG Index)
{
    WCHAR Dir[MAX_PATH], Path[MAX_PATH], File[MAX_PATH], Command[2 * MAX_PATH + 64];
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Info;
    DWORD Code = 1;
    FILE *Input;
    char Line[128], Name[32], Text[64];

    GetModuleFileNameW(NULL, Dir, _countof(Dir));
    *wcsrchr(Dir, L'\\') = 0;
    StringCbPrintfW(Path, sizeof(Path), L"%s\\loadconfig_cookie_exe.exe", Dir);
    GetTempPathW(_countof(File), File);
    StringCbPrintfW(File + wcslen(File), sizeof(File) - wcslen(File) * sizeof(WCHAR),
                    L"lccookie-%lu-%lu.txt", GetCurrentProcessId(), Index);
    StringCbPrintfW(Command, sizeof(Command), L"\"%s\" \"%s\" %s", Path, File, Mode);

    if (!CreateProcessW(NULL, Command, NULL, NULL, FALSE, 0, NULL, Dir, &Startup, &Info))
    {
        ok(0, "CreateProcess(%ls) failed %lu\n", Command, GetLastError());
        return FALSE;
    }
    WaitForSingleObject(Info.hProcess, 60000);
    GetExitCodeProcess(Info.hProcess, &Code);
    CloseHandle(Info.hProcess);
    CloseHandle(Info.hThread);
    ok(Code == 0, "child (%ls) exit code %lu\n", Mode, Code);

    Input = _wfopen(File, L"r");
    if (!Input)
    {
        ok(0, "no output of the child (%ls)\n", Mode);
        return FALSE;
    }
    while (fgets(Line, sizeof(Line), Input))
    {
        ULONGLONG Value;

        if (sscanf(Line, "%31s %63s", Name, Text) != 2)
            continue;
        if (!strcmp(Text, "error") || !strcmp(Text, "noexport"))
        {
            ok(0, "child (%ls): %s", Mode, Line);
            continue;
        }
        if (sscanf(Text, "%I64x", &Value) != 1)
            continue;
        if (ValueCount < MAX_VALUES)
        {
            StringCbCopyA(Values[ValueCount].Name, sizeof(Values[ValueCount].Name), Name);
            Values[ValueCount].Value = Value;
            ValueCount++;
        }
    }
    fclose(Input);
    DeleteFileW(File);
    return TRUE;
}

static void CheckValue(const VALUE *Value)
{
    if (!strncmp(Value->Name, "saw", 3))
    {
        ok(Value->Value == 0, "%s: the entry point ran before the cookie was made\n", Value->Name);
        return;
    }
    ok(Value->Value != DEFAULT_COOKIE, "%s: the loader left the default cookie\n", Value->Name);
    ok(Value->Value != 0, "%s: cookie is zero\n", Value->Name);
#ifdef _WIN64
    /* the upper 16 bits are zero, as in the default (and in the values measured on Windows Server 2022) */
    ok((Value->Value >> 48) == 0, "%s: the upper 16 bits are not zero: %I64x\n", Value->Name, Value->Value);
#endif
}

START_TEST(cookie)
{
    ULONG i, j, Checked = 0, Repeats = 0, Dll2 = 0;
    ULONG Seen[8] = { 0 };
    static const char *Names[] = { "exe", "dll1", "dll4", "dll3", "fwd" };

    /* the executable, a static import, a delay load */
    ok(RunChild(L"static", 0), "static child\n");
    /* the other load paths, in many processes */
    for (i = 1; i <= PROCESSES; i++)
        RunChild(L"dynamic", i);

    for (i = 0; i < ValueCount; i++)
    {
        CheckValue(&Values[i]);
        Checked++;
        for (j = 0; j < _countof(Names); j++)
            if (!strcmp(Values[i].Name, Names[j]))
                Seen[j]++;
        if (!strcmp(Values[i].Name, "dll2"))
            Dll2++;
    }
    trace("%lu values, %lu of dll2\n", Checked, Dll2);
    ok(Seen[0] == 1, "exe cookie reported %lu times\n", Seen[0]);
    ok(Seen[1] == 1, "dll1 (static import) reported %lu times\n", Seen[1]);
    ok(Seen[2] == 1, "dll4 (delay load) reported %lu times\n", Seen[2]);
    ok(Seen[3] == PROCESSES, "dll3 (no entry point) reported %lu times\n", Seen[3]);
    ok(Seen[4] == PROCESSES, "fwd (forwarder) reported %lu times\n", Seen[4]);
    ok(Dll2 == PROCESSES * LOADS, "dll2 reported %lu times\n", Dll2);

    /* no value is shared by two loads or two images: not in a process, not between processes */
    for (i = 0; i < ValueCount; i++)
    {
        if (!strncmp(Values[i].Name, "saw", 3))
            continue;
        for (j = 0; j < i; j++)
        {
            if (!strncmp(Values[j].Name, "saw", 3))
                continue;
            if (Values[i].Value == Values[j].Value)
            {
                Repeats++;
                if (Repeats <= 5)
                    trace("repeat: %s and %s: %I64x\n", Values[j].Name, Values[i].Name, Values[i].Value);
            }
        }
    }
    ok(Repeats == 0, "%lu cookies repeat\n", Repeats);

#ifdef _WIN64
    /* the old recipe (32-bit terms) left bits 32 to 47 clear in every cookie; a random value has them set in all but
       one of 65536 */
    {
        ULONG Cookies = 0, High = 0;

        for (i = 0; i < ValueCount; i++)
        {
            if (!strncmp(Values[i].Name, "saw", 3))
                continue;
            Cookies++;
            if ((Values[i].Value >> 32) & 0xFFFF)
                High++;
        }
        ok(High * 100 >= Cookies * 99, "only %lu of %lu cookies have bits 32 to 47 set\n", High, Cookies);
    }
#endif
}
