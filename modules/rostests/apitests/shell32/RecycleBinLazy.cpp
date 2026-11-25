/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Looking at the recycle bin of a volume writes nothing to the volume
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "shelltest.h"

/* Windows Server 2022: no $Recycle.Bin exists on a volume until the first delete to the bin there (the delete side is
 * RecycleBinOtherVolume). The test needs a fixed volume other than the system volume that has no bin folder yet; without
 * one it skips. The size and the contents of such a bin are read, and the bin is emptied: the volume must not change. */

static DWORD CountEntries(PCWSTR Root)
{
    WCHAR Pattern[MAX_PATH];
    WIN32_FIND_DATAW Data;
    HANDLE Find;
    DWORD Count = 0;

    wsprintfW(Pattern, L"%ls*", Root);
    Find = FindFirstFileW(Pattern, &Data);
    if (Find == INVALID_HANDLE_VALUE)
        return 0;
    do
    {
        Count++;
    } while (FindNextFileW(Find, &Data));
    FindClose(Find);
    return Count;
}

static BOOL BinExists(WCHAR Letter)
{
    static const PCWSTR Names[] = { L"RECYCLER", L"RECYCLED", L"$Recycle.Bin" };
    WCHAR Path[MAX_PATH];
    UINT i;

    for (i = 0; i < _countof(Names); i++)
    {
        wsprintfW(Path, L"%lc:\\%ls", Letter, Names[i]);
        if (GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
            return TRUE;
    }
    return FALSE;
}

START_TEST(RecycleBinLazy)
{
    WCHAR SystemDrive[MAX_PATH], Root[4];
    DWORD Drives = GetLogicalDrives(), Letter, Before, After;
    SHQUERYRBINFO Info = { sizeof(Info) };
    WCHAR Chosen = 0;
    HRESULT hr;

    if (!GetEnvironmentVariableW(L"SystemDrive", SystemDrive, _countof(SystemDrive)))
        SystemDrive[0] = L'C';

    for (Letter = 0; Letter < 26 && !Chosen; Letter++)
    {
        if (!(Drives & (1 << Letter)) || (WCHAR)(L'A' + Letter) == (WCHAR)towupper(SystemDrive[0]))
            continue;
        Root[0] = (WCHAR)(L'A' + Letter); Root[1] = L':'; Root[2] = L'\\'; Root[3] = 0;
        if (GetDriveTypeW(Root) != DRIVE_FIXED || BinExists(Root[0]))
            continue;
        Chosen = Root[0];
    }
    if (!Chosen)
    {
        skip("no fixed volume other than the system volume that has no recycle bin yet\n");
        return;
    }
    Root[0] = Chosen;

    Before = CountEntries(Root);
    hr = SHQueryRecycleBinW(Root, &Info);
    ok(SUCCEEDED(hr), "SHQueryRecycleBin returned 0x%lx\n", hr);
    ok(Info.i64NumItems == 0, "%I64d items in a bin that was never used\n", Info.i64NumItems);
    ok(!BinExists(Chosen), "reading the size made a bin folder\n");
    hr = SHEmptyRecycleBinW(NULL, Root, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
    ok(SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "SHEmptyRecycleBin returned 0x%lx\n", hr);
    ok(!BinExists(Chosen), "emptying the bin made a bin folder\n");
    After = CountEntries(Root);
    ok(After == Before, "the volume has %lu entries, it had %lu\n", After, Before);
}
