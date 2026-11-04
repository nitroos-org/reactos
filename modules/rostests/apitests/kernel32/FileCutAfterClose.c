/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A file written and closed, reopened and cut in the middle of a page keeps the bytes before the cut
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The close leaves the dirty data to the lazy writer (the cache map is kept); the cut then purges from the
 * file size, which is not page aligned, and must not drop the page that holds the last kept bytes.
 * The test uses the volume of the temporary directory, or the directory named by FILECUTAFTERCLOSE_DIR.
 */

#include "precomp.h"

#define MAX_LEN 1600000

static BYTE Pattern(DWORD Offset, DWORD Seed)
{
    BYTE Value = (BYTE)(Offset * 7 + Offset / 251 + Seed * 13);
    return Value ? Value : 1;
}

static void TestCase(PCWSTR Path, DWORD Length, DWORD Cut, DWORD SleepMs, DWORD Seed)
{
    static BYTE Buffer[MAX_LEN];
    HANDLE File;
    DWORD i, Done, Bad;

    for (i = 0; i < Length; i++)
        Buffer[i] = Pattern(i, Seed);

    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "create failed %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    ok(WriteFile(File, Buffer, Length, &Done, NULL) && Done == Length, "write failed %lu\n", GetLastError());
    CloseHandle(File);
    if (SleepMs)
        Sleep(SleepMs);

    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "reopen failed %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    ok(SetFilePointer(File, Cut, NULL, FILE_BEGIN) == Cut && SetEndOfFile(File), "cut failed %lu\n", GetLastError());
    CloseHandle(File);

    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "open for read failed %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    {
        static BYTE Got[MAX_LEN];

        ok(ReadFile(File, Got, Length, &Done, NULL), "read failed %lu\n", GetLastError());
        ok(Done == Cut, "length %lu, expected %lu (length %lu, seed %lu)\n", Done, Cut, Length, Seed);
        for (i = 0, Bad = 0; i < Done && i < Cut; i++)
        {
            if (Got[i] != Pattern(i, Seed))
            {
                if (!Bad)
                    ok(0, "byte %lu is %02x, expected %02x (length %lu, cut %lu)\n", i, Got[i], Pattern(i, Seed), Length, Cut);
                Bad++;
            }
        }
        ok(Bad == 0, "%lu bytes of the first %lu are wrong (length %lu)\n", Bad, Cut, Length);
    }
    CloseHandle(File);
    DeleteFileW(Path);
}

START_TEST(FileCutAfterClose)
{
    static const struct { DWORD Length, Cut, Sleep; } Cases[] =
    {
        { 100000, 30000, 0 },
        { 300000, 100000, 0 },
        { 1500000, 700000, 0 },
        { 1500000, 1000000, 3000 },
        { 70000, 4096, 0 },
        { 70000, 4097, 0 },
        { 70000, 8191, 0 },
        { 8000, 3000, 0 },
        { 1500000, 7, 0 },
    };
    WCHAR Temp[MAX_PATH], Dir[MAX_PATH], Path[MAX_PATH];
    DWORD Length, i;

    Length = GetEnvironmentVariableW(L"FILECUTAFTERCLOSE_DIR", Temp, _countof(Temp));
    if (Length == 0 || Length >= _countof(Temp))
        GetTempPathW(_countof(Temp), Temp);
    StringCchPrintfW(Dir, _countof(Dir), L"%s\\fca%lu", Temp, GetCurrentProcessId());
    if (!CreateDirectoryW(Dir, NULL))
    {
        skip("cannot create %ls: %lu\n", Dir, GetLastError());
        return;
    }
    StringCchPrintfW(Path, _countof(Path), L"%s\\cut.bin", Dir);

    for (i = 0; i < _countof(Cases); i++)
        TestCase(Path, Cases[i].Length, Cases[i].Cut, Cases[i].Sleep, i + 1);

    RemoveDirectoryW(Dir);
}
