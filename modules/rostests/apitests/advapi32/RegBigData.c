/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Hives of format 1.5 with big data values (data longer than
 *              16344 bytes stored as a 'db' record and segments): loaded with
 *              RegLoadKeyW, every byte reads back through the query and the
 *              enumeration paths (also into buffers that are too small), the
 *              file is unchanged after load + read + unload (but for what the
 *              kernel writes into any hive it links: the root's Parent and the
 *              base block's sequence numbers, time stamp, file name, checksum;
 *              the same for the 1.3 hive of the same values), and values that
 *              change, are saved, deleted and loaded again keep their data
 *              and leave no cell behind.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The 1.5 hive is written by the test (hivegen.h, after the public format
 * description; no binary file). Needs the backup and restore privileges
 * (an administrator).
 */

#include "precomp.h"
#include <winbase.h>
#include <ndk/cmfuncs.h>
#include <ndk/obfuncs.h>
#include "hivegen.h"

#define MOUNT       L"ReactOSBigData"
#define MOUNT_PATH  L"\\Registry\\Machine\\ReactOSBigData"
#define MOUNT2      L"ReactOSBigDataSaved"

static LSTATUS (WINAPI *pRegDeleteTreeW)(HKEY, LPCWSTR);

static BOOL EnablePrivilege(PCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    BOOL Success;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
        return FALSE;
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Success = LookupPrivilegeValueW(NULL, Name, &Privileges.Privileges[0].Luid) &&
              AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Success;
}

static BOOL WriteWholeFile(PCWSTR Path, const void *Data, DWORD Size)
{
    HANDLE File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD Done = 0;
    BOOL Ok;

    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Ok = WriteFile(File, Data, Size, &Done, NULL) && Done == Size;
    CloseHandle(File);
    return Ok;
}

static PBYTE ReadWholeFile(PCWSTR Path, PDWORD Size)
{
    HANDLE File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    PBYTE Buf = NULL;
    DWORD Done = 0;

    *Size = 0;
    if (File == INVALID_HANDLE_VALUE)
        return NULL;
    *Size = GetFileSize(File, NULL);
    Buf = HeapAlloc(GetProcessHeap(), 0, *Size ? *Size : 1);
    if (Buf && (!ReadFile(File, Buf, *Size, &Done, NULL) || Done != *Size))
    {
        HeapFree(GetProcessHeap(), 0, Buf);
        Buf = NULL;
    }
    CloseHandle(File);
    return Buf;
}

static void Wide(PCSTR Narrow, PWSTR Out, ULONG Chars)
{
    ULONG i;

    for (i = 0; Narrow[i] && i + 1 < Chars; i++)
        Out[i] = (WCHAR)(UCHAR)Narrow[i];
    Out[i] = 0;
}

/* The data a value of the fixture holds; Length bytes */
static PBYTE Expected(const HG_VALUE *V, DWORD Length)
{
    PBYTE Buf = HeapAlloc(GetProcessHeap(), 0, Length ? Length : 1);
    DWORD i;

    for (i = 0; i < Length; i++)
        Buf[i] = HgByte(V->Type, i, V->Length, V->Seed);
    return Buf;
}

/* ---- every way a program reads a value ---- */

static void CheckValue(HKEY Key, PCWSTR KeyPath, const HG_VALUE *V)
{
    WCHAR Name[64];
    DWORD Length = (V->Form == HG_NO_CELL) ? 0 : V->Length, Type, Size, Half;
    PBYTE Want = Expected(V, Length), Buf = HeapAlloc(GetProcessHeap(), 0, Length + 64);
    LONG Error;
    NTSTATUS Status;
    UNICODE_STRING Us;
    ULONG Result;
    PKEY_VALUE_PARTIAL_INFORMATION Partial;
    PKEY_VALUE_FULL_INFORMATION Full;
    HANDLE Handle = (HANDLE)Key;

    Wide(V->Name, Name, _countof(Name));

    /* the size */
    Size = 0;
    Error = RegQueryValueExW(Key, Name, NULL, &Type, NULL, &Size);
    ok(Error == ERROR_SUCCESS && Size == Length && Type == V->Type,
       "%S\\%S: size query %ld, size %lu, type %lu (want %lu, %u)\n", KeyPath, Name, Error, Size, Type, Length, V->Type);

    /* all of it */
    Size = Length + 64;
    memset(Buf, 0xCC, Length + 64);
    Error = RegQueryValueExW(Key, Name, NULL, &Type, Buf, &Size);
    ok(Error == ERROR_SUCCESS && Size == Length && memcmp(Buf, Want, Length) == 0,
       "%S\\%S: read %ld, size %lu: the data differs\n", KeyPath, Name, Error, Size);

    /* one byte short: ERROR_MORE_DATA and the size */
    if (Length > 0)
    {
        Size = Length - 1;
        Error = RegQueryValueExW(Key, Name, NULL, &Type, Buf, &Size);
        ok(Error == ERROR_MORE_DATA && Size == Length, "%S\\%S: short buffer %ld, size %lu\n", KeyPath, Name, Error, Size);
    }

    /* the native query into buffers that hold half of the data: the first half is copied */
    RtlInitUnicodeString(&Us, Name);
    Half = Length / 2;
    Partial = HeapAlloc(GetProcessHeap(), 0, FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + Length + 8);
    Full = HeapAlloc(GetProcessHeap(), 0, sizeof(KEY_VALUE_FULL_INFORMATION) + 256 + Length + 8);
    if (Partial && Full)
    {
        Status = NtQueryValueKey(Handle, &Us, KeyValuePartialInformation, Partial,
                                 FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + Half, &Result);
        ok((Length == 0 ? Status == STATUS_SUCCESS : Status == STATUS_BUFFER_OVERFLOW) &&
           Result == FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + Length &&
           Partial->DataLength == Length && memcmp(Partial->Data, Want, Half) == 0,
           "%S\\%S: partial information, half a buffer: 0x%lx, %lu\n", KeyPath, Name, Status, Result);
        Status = NtQueryValueKey(Handle, &Us, KeyValueFullInformation, Full,
                                 sizeof(KEY_VALUE_FULL_INFORMATION) + 256 + Length, &Result);
        ok(Status == STATUS_SUCCESS && Full->DataLength == Length &&
           (Length == 0 || memcmp((PBYTE)Full + Full->DataOffset, Want, Length) == 0),
           "%S\\%S: full information: 0x%lx\n", KeyPath, Name, Status);
        if (Length > 0)
        {
            ULONG Offset = Full->DataOffset;
            Status = NtQueryValueKey(Handle, &Us, KeyValueFullInformation, Full, Offset + Half, &Result);
            ok(Status == STATUS_BUFFER_OVERFLOW && memcmp((PBYTE)Full + Offset, Want, Half) == 0,
               "%S\\%S: full information, half a buffer: 0x%lx\n", KeyPath, Name, Status);
        }
    }
    HeapFree(GetProcessHeap(), 0, Partial);
    HeapFree(GetProcessHeap(), 0, Full);

    /* text through the ANSI API: the same characters */
    if (V->Type == REG_SZ && Length > 2)
    {
        PSTR A = HeapAlloc(GetProcessHeap(), 0, Length);
        DWORD i, Bad = 0;
        char NameA[64];

        WideCharToMultiByte(CP_ACP, 0, Name, -1, NameA, sizeof(NameA), NULL, NULL);
        Size = Length;
        Error = RegQueryValueExA(Key, NameA, NULL, &Type, (PBYTE)A, &Size);
        ok(Error == ERROR_SUCCESS && Size == Length / 2, "%S\\%S: ANSI read %ld, size %lu\n", KeyPath, Name, Error, Size);
        for (i = 0; Error == ERROR_SUCCESS && i + 1 < Length / 2; i++)
            if ((BYTE)A[i] != Want[2 * i])
                Bad++;
        ok(Bad == 0, "%S\\%S: %lu ANSI characters differ\n", KeyPath, Name, Bad);
        HeapFree(GetProcessHeap(), 0, A);
    }

    HeapFree(GetProcessHeap(), 0, Want);
    HeapFree(GetProcessHeap(), 0, Buf);
}

/* Every value of the key, by name and by enumeration */
static void CheckKey(HKEY Root, PCWSTR KeyPath, const HG_VALUE *Values, ULONG Count)
{
    HKEY Key;
    LONG Error;
    ULONG i, j, Seen = 0;
    DWORD MaxData = 0, NValues = 0;

    Error = RegOpenKeyExW(Root, KeyPath, 0, KEY_READ, &Key);
    ok(Error == ERROR_SUCCESS, "open %S: %ld\n", KeyPath, Error);
    if (Error != ERROR_SUCCESS)
        return;
    for (i = 0; i < Count; i++)
        CheckValue(Key, KeyPath, &Values[i]);

    Error = RegQueryInfoKeyW(Key, NULL, NULL, NULL, NULL, NULL, NULL, &NValues, NULL, &MaxData, NULL, NULL);
    ok(Error == ERROR_SUCCESS && NValues == Count, "%S: %lu values, want %lu\n", KeyPath, NValues, Count);
    for (i = 0; i < Count; i++)
        ok(Values[i].Form == HG_NO_CELL || Values[i].Length <= MaxData,
           "%S: the longest data is %lu bytes, a value has %u\n", KeyPath, MaxData, Values[i].Length);

    for (i = 0; ; i++)
    {
        WCHAR Name[64];
        DWORD NameLen = _countof(Name), Type, Size = 0;
        PBYTE Buf;

        Error = RegEnumValueW(Key, i, Name, &NameLen, NULL, &Type, NULL, &Size);
        if (Error == ERROR_NO_MORE_ITEMS)
            break;
        ok(Error == ERROR_SUCCESS, "%S: enum %lu: %ld\n", KeyPath, i, Error);
        if (Error != ERROR_SUCCESS)
            break;
        for (j = 0; j < Count; j++)
        {
            WCHAR Want[64];
            Wide(Values[j].Name, Want, _countof(Want));
            if (!_wcsicmp(Want, Name))
                break;
        }
        ok(j < Count, "%S: enumerated %S is not in the fixture\n", KeyPath, Name);
        if (j == Count)
            continue;
        Seen++;
        Buf = HeapAlloc(GetProcessHeap(), 0, Size + 16);
        NameLen = _countof(Name);
        Error = RegEnumValueW(Key, i, Name, &NameLen, NULL, &Type, Buf, &Size);
        {
            DWORD Length = (Values[j].Form == HG_NO_CELL) ? 0 : Values[j].Length;
            PBYTE Want = Expected(&Values[j], Length);
            ok(Error == ERROR_SUCCESS && Size == Length && Type == Values[j].Type && memcmp(Buf, Want, Length) == 0,
               "%S: enum %S: %ld, size %lu: the data differs\n", KeyPath, Name, Error, Size);
            HeapFree(GetProcessHeap(), 0, Want);
            if (Length > 1)
            {
                /* the data into a buffer one byte short */
                Size = Length - 1;
                NameLen = _countof(Name);
                Error = RegEnumValueW(Key, i, Name, &NameLen, NULL, &Type, Buf, &Size);
                ok(Error == ERROR_MORE_DATA && Size == Length, "%S: enum %S short: %ld, %lu\n", KeyPath, Name, Error, Size);
            }
        }
        HeapFree(GetProcessHeap(), 0, Buf);
    }
    ok(Seen == Count, "%S: enumerated %lu of %lu values\n", KeyPath, Seen, Count);
    RegCloseKey(Key);
}

static void CheckFixture(HKEY Root)
{
    CheckKey(Root, L"", HgRootValues, _countof(HgRootValues));
    CheckKey(Root, L"BigData", HgBigDataValues, _countof(HgBigDataValues));
    CheckKey(Root, L"Sub", HgSubValues, _countof(HgSubValues));
}

/* ---- the file ---- */

/* Allocated cells of the hive file: how many are 'db' cells, how many hold a whole segment or more */
static void CountCells(PBYTE File, DWORD Size, PULONG BigDataCells, PULONG LongCells, PULONG Minor)
{
    DWORD Off = HG_BLOCK, End, BinEnd;

    *BigDataCells = *LongCells = 0;
    *Minor = (Size >= HG_BLOCK) ? *(PULONG)(File + 0x18) : 0;
    End = (Size >= HG_BLOCK) ? min(Size, HG_BLOCK + *(PULONG)(File + 0x28)) : 0;
    while (Off + 32 <= End && *(PULONG)(File + Off) == 0x6E696268)
    {
        DWORD C = Off + 32;
        BinEnd = Off + *(PULONG)(File + Off + 8);
        if (BinEnd > End || BinEnd <= Off)
            break;
        while (C + 8 <= BinEnd)
        {
            LONG S = *(PLONG)(File + C);
            DWORD A = S < 0 ? (DWORD)-S : (DWORD)S;
            if (A < 8 || C + A > BinEnd)
                break;
            if (S < 0 && A == 16 && *(PUSHORT)(File + C + 4) == 0x6264)
                (*BigDataCells)++;
            if (S < 0 && A - 4 >= HG_SEGMENT)
                (*LongCells)++;
            C += A;
        }
        Off = BinEnd;
    }
}

/* Is offset Off of the hive file inside the data of a free cell (positive size) of File */
static BOOL InFreeCell(const BYTE *File, DWORD Size, DWORD Off)
{
    DWORD Bin = HG_BLOCK, End = min(Size, HG_BLOCK + *(const DWORD *)(File + 0x28)), BinSize, C;
    LONG S;

    while (Bin + 32 <= End && *(const DWORD *)(File + Bin) == 0x6E696268)
    {
        BinSize = *(const DWORD *)(File + Bin + 8);
        if (BinSize == 0 || Bin + BinSize > End)
            return FALSE;
        if (Off < Bin + BinSize)
        {
            for (C = Bin + 32; C + 8 <= Bin + BinSize; C += (DWORD)(S < 0 ? -S : S))
            {
                S = *(const LONG *)(File + C);
                if (S == 0)
                    return FALSE;
                if (Off >= C && Off < C + (DWORD)(S < 0 ? -S : S))
                    return S > 0 && Off >= C + 4;
            }
            return FALSE;
        }
        Bin += BinSize;
    }
    return FALSE;
}

/*
 * Bytes of Now that differ from Was, other than what the kernel writes into every hive it links into the
 * registry (CmpCreateLinkNode marks the root dirty and sets its Parent to the link node of the master hive; the
 * write of that cell then rewrites the base block's sequence numbers, time stamp, file name and checksum, and the
 * free-list links the kernel keeps inside free cells of the blocks it writes). Those are traced; the count of every
 * other differing byte is returned.
 */
static ULONG Changed(const BYTE *Was, const BYTE *Now, DWORD Size, PCSTR What)
{
    DWORD Root = *(const DWORD *)(Was + 0x24), i, Other = 0, Header = 0, Parent = 0, Free = 0, First = (DWORD)-1;
    DWORD ParentAt = HG_BLOCK + Root + 4 + 0x10;

    for (i = 0; i < Size; i++)
    {
        if (Now[i] == Was[i])
            continue;
        if ((i >= 0x04 && i < 0x14) || (i >= 0x30 && i < 0x70) || (i >= 0x1FC && i < 0x200))
            Header++;
        else if (i >= ParentAt && i < ParentAt + 4)
            Parent++;
        else if (InFreeCell(Was, Size, i))
            Free++;
        else
        {
            if (First == (DWORD)-1)
                First = i;
            Other++;
        }
    }
    trace("%s: after load + read + unload: %lu bytes of the base block's sequence/time stamp/file name/checksum, "
          "%lu of the root's Parent, %lu inside free cells, %lu other bytes differ%s\n",
          What, Header, Parent, Free, Other, Other ? "" : " (none)");
    if (Other)
        trace("%s: the first other difference at 0x%lx\n", What, First);
    return Other;
}

static LONG Load(PCWSTR Mount, PCWSTR File)
{
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, Mount);
    return RegLoadKeyW(HKEY_LOCAL_MACHINE, Mount, File);
}

static void SetData(HKEY Key, PCWSTR Name, DWORD Length, DWORD Seed)
{
    HG_VALUE V = { "", REG_BINARY, Length, Seed, HG_AUTO };
    PBYTE Data = Expected(&V, Length);
    LONG Error = RegSetValueExW(Key, Name, 0, REG_BINARY, Data, Length);

    ok(Error == ERROR_SUCCESS, "set %S to %lu bytes: %ld\n", Name, Length, Error);
    HeapFree(GetProcessHeap(), 0, Data);
}

static void CheckData(HKEY Key, PCWSTR Name, DWORD Length, DWORD Seed)
{
    char Narrow[64];
    HG_VALUE V = { Narrow, REG_BINARY, Length, Seed, HG_AUTO };

    WideCharToMultiByte(CP_ACP, 0, Name, -1, Narrow, sizeof(Narrow), NULL, NULL);
    CheckValue(Key, L"(changed)", &V);
}

START_TEST(RegBigData)
{
    WCHAR Dir[MAX_PATH], File[MAX_PATH], Saved[MAX_PATH], Old[MAX_PATH];
    PBYTE Hive, Now;
    unsigned HiveSize;
    DWORD NowSize, Size;
    ULONG Db, Long, Minor;
    HKEY Root, Key, Saved2;
    LONG Error;
    static const DWORD Steps[] = { 2, 50000, 3, 16344, 16345, 100, 32689, 0, 40000 };
    ULONG i;

    pRegDeleteTreeW = (PVOID)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "RegDeleteTreeW");
    if (!EnablePrivilege(L"SeBackupPrivilege") || !EnablePrivilege(L"SeRestorePrivilege"))
    {
        skip("The backup and restore privileges are needed (run as an administrator)\n");
        return;
    }
    GetTempPathW(_countof(Dir), Dir);
    StringCchPrintfW(File, _countof(File), L"%sRegBigData15.hiv", Dir);
    StringCchPrintfW(Saved, _countof(Saved), L"%sRegBigDataSaved.hiv", Dir);
    StringCchPrintfW(Old, _countof(Old), L"%sRegBigData13.hiv", Dir);
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT);
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT2);

    /* 1. load, read every byte every way, unload: the file is the same but for what linking writes (Changed) */
    Hive = HgBuildBigData(5, &HiveSize);
    DeleteFileW(File);
    ok(WriteWholeFile(File, Hive, HiveSize), "write the hive file\n");
    CountCells(Hive, HiveSize, &Db, &Long, &Minor);
    trace("fixture: %u bytes, format 1.%lu, %lu 'db' cells\n", HiveSize, Minor, Db);
    Error = Load(MOUNT, File);
    ok(Error == ERROR_SUCCESS, "RegLoadKeyW(1.5 hive with big data): %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        goto Cleanup;
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, MOUNT, 0, KEY_READ, &Root);
    ok(Error == ERROR_SUCCESS, "open the mount: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        CheckFixture(Root);
        RegCloseKey(Root);
    }
    Error = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT);
    ok(Error == ERROR_SUCCESS, "RegUnLoadKeyW: %ld\n", Error);
    Now = ReadWholeFile(File, &NowSize);
    ok(Now && NowSize == HiveSize && Changed(Hive, Now, HiveSize, "1.5 fixture") == 0,
       "the hive file changed after load + read + unload (%lu bytes, was %u)\n", NowSize, HiveSize);
    if (Now)
        HeapFree(GetProcessHeap(), 0, Now);

    /* the same values in a 1.3 hive (one cell each, no big data): what the kernel rewrites there, for comparison */
    {
        unsigned Size13;
        PBYTE Hive13 = HgBuildBigData(3, &Size13);
        ok(WriteWholeFile(Old, Hive13, Size13), "write the 1.3 file\n");
        Error = Load(MOUNT, Old);
        ok(Error == ERROR_SUCCESS, "RegLoadKeyW(1.3 hive): %ld\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MOUNT, 0, KEY_READ, &Root) == ERROR_SUCCESS)
            {
                CheckFixture(Root);
                RegCloseKey(Root);
            }
            ok(RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT) == ERROR_SUCCESS, "unload the 1.3 hive\n");
            Now = ReadWholeFile(Old, &NowSize);
            ok(Now && NowSize == Size13 && Changed(Hive13, Now, Size13, "1.3 fixture") == 0,
               "the 1.3 hive file changed after load + read + unload\n");
            if (Now)
                HeapFree(GetProcessHeap(), 0, Now);
        }
        free(Hive13);
        DeleteFileW(Old);
    }

    /* 2. changes: small -> big -> small -> one cell -> big ..., a new big value, a save, deletes */
    Error = Load(MOUNT, File);
    ok(Error == ERROR_SUCCESS, "RegLoadKeyW again: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        goto Cleanup;
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, MOUNT L"\\BigData", 0, KEY_ALL_ACCESS, &Key);
    ok(Error == ERROR_SUCCESS, "open BigData: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        for (i = 0; i < _countof(Steps); i++)
        {
            SetData(Key, L"b100", Steps[i], 40 + i);
            CheckData(Key, L"b100", Steps[i], 40 + i);
        }
        SetData(Key, L"new", 70000, 60);
        SetData(Key, L"b40000", 16344, 61);     /* big data -> one cell */
        SetData(Key, L"legacy", 30001, 62);     /* one cell (as an older ReactOS wrote it) -> big data */
        Error = RegDeleteValueW(Key, L"b16345");
        ok(Error == ERROR_SUCCESS, "delete b16345: %ld\n", Error);
        CheckData(Key, L"new", 70000, 60);
        CheckData(Key, L"b40000", 16344, 61);
        CheckData(Key, L"legacy", 30001, 62);
        CheckData(Key, L"b100", 40000, 40 + _countof(Steps) - 1);
        Error = RegQueryValueExW(Key, L"b16345", NULL, NULL, NULL, &Size);
        ok(Error == ERROR_FILE_NOT_FOUND, "b16345 still there: %ld\n", Error);
        ok(RegFlushKey(Key) == ERROR_SUCCESS, "flush\n");

        /* a save (the kernel writes format 1.3: one cell per value) and its load */
        DeleteFileW(Saved);
        Error = RegSaveKeyW(Key, Saved, NULL);
        ok(Error == ERROR_SUCCESS, "RegSaveKeyW: %ld\n", Error);
        Now = ReadWholeFile(Saved, &NowSize);
        if (Now)
        {
            CountCells(Now, NowSize, &Db, &Long, &Minor);
            trace("saved copy: format 1.%lu, %lu 'db' cells, %lu cells of a segment or more\n", Minor, Db, Long);
            ok(Minor >= 4 || Db == 0, "a 1.%lu hive holds %lu 'db' cells\n", Minor, Db);
            HeapFree(GetProcessHeap(), 0, Now);
        }
        Error = Load(MOUNT2, Saved);
        ok(Error == ERROR_SUCCESS, "RegLoadKeyW(saved copy): %ld\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, MOUNT2, 0, KEY_READ, &Saved2);
            if (Error == ERROR_SUCCESS)
            {
                CheckData(Saved2, L"new", 70000, 60);
                CheckData(Saved2, L"legacy", 30001, 62);
                CheckData(Saved2, L"b100", 40000, 40 + _countof(Steps) - 1);
                CheckValue(Saved2, L"(saved)", &HgBigDataValues[5]);    /* b81720, untouched */
                CheckValue(Saved2, L"(saved)", &HgBigDataValues[7]);    /* sz */
                CheckValue(Saved2, L"(saved)", &HgBigDataValues[9]);    /* empty */
                RegCloseKey(Saved2);
            }
            ok(RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT2) == ERROR_SUCCESS, "unload the saved copy\n");
        }

        /* delete every long value and the subkey: no segment and no 'db' cell may stay allocated */
        for (i = 0; i < _countof(HgBigDataValues); i++)
        {
            WCHAR Name[64];
            Wide(HgBigDataValues[i].Name, Name, _countof(Name));
            if (HgBigDataValues[i].Length >= HG_SEGMENT)
                RegDeleteValueW(Key, Name);
        }
        RegDeleteValueW(Key, L"new");
        RegDeleteValueW(Key, L"b100");
        RegCloseKey(Key);
    }
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, MOUNT, 0, KEY_ALL_ACCESS, &Root);
    if (Error == ERROR_SUCCESS)
    {
        ok(RegDeleteValueW(Root, L"rootbig") == ERROR_SUCCESS, "delete rootbig\n");
        ok(pRegDeleteTreeW && pRegDeleteTreeW(Root, L"Sub") == ERROR_SUCCESS, "delete Sub\n");
        RegCloseKey(Root);
    }
    Error = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT);
    ok(Error == ERROR_SUCCESS, "RegUnLoadKeyW after the changes: %ld\n", Error);
    Now = ReadWholeFile(File, &NowSize);
    if (Now)
    {
        CountCells(Now, NowSize, &Db, &Long, &Minor);
        ok(Minor == 5, "the loaded hive is format 1.%lu after the changes\n", Minor);
        ok(Db == 0 && Long == 0, "after the deletes: %lu 'db' cells and %lu cells of a segment or more still allocated\n",
           Db, Long);
        HeapFree(GetProcessHeap(), 0, Now);
    }

    /* 3. what the kernel wrote loads, and loads unchanged */
    Now = ReadWholeFile(File, &NowSize);
    Error = Load(MOUNT, File);
    ok(Error == ERROR_SUCCESS, "RegLoadKeyW after the changes: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, MOUNT L"\\BigData", 0, KEY_READ, &Key);
        if (Error == ERROR_SUCCESS)
        {
            CheckValue(Key, L"BigData", &HgBigDataValues[8]);   /* dw */
            CheckValue(Key, L"BigData", &HgBigDataValues[9]);   /* empty */
            RegCloseKey(Key);
        }
        ok(RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT) == ERROR_SUCCESS, "unload\n");
        {
            PBYTE After = ReadWholeFile(File, &Size);
            ok(Now && After && Size == NowSize && Changed(Now, After, Size, "kernel-written 1.5 hive") == 0,
               "the kernel-written hive changed at its next load\n");
            if (After)
                HeapFree(GetProcessHeap(), 0, After);
        }
    }
    if (Now)
        HeapFree(GetProcessHeap(), 0, Now);

    /* 4. format 1.3 (what ReactOS makes): 20 KB and 2 MB are one cell each, no big data */
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ReactOSBigData13", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "create the 1.3 key: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        SetData(Key, L"20k", 20 * 1024, 70);
        SetData(Key, L"2m", 2 * 1024 * 1024, 71);
        CheckData(Key, L"20k", 20 * 1024, 70);
        CheckData(Key, L"2m", 2 * 1024 * 1024, 71);
        DeleteFileW(Old);
        Error = RegSaveKeyW(Key, Old, NULL);
        ok(Error == ERROR_SUCCESS, "RegSaveKeyW(1.3): %ld\n", Error);
        RegCloseKey(Key);
        RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\ReactOSBigData13");
        Now = ReadWholeFile(Old, &NowSize);
        if (Now)
        {
            CountCells(Now, NowSize, &Db, &Long, &Minor);
            trace("saved 1.3 key: format 1.%lu, %lu 'db' cells, %lu long cells\n", Minor, Db, Long);
            ok(Minor < 4 ? (Db == 0 && Long == 2) : TRUE, "1.%lu: %lu 'db' cells, %lu long cells (want 0, 2)\n",
               Minor, Db, Long);
            HeapFree(GetProcessHeap(), 0, Now);
        }
        Error = Load(MOUNT2, Old);
        ok(Error == ERROR_SUCCESS, "load the 1.3 save: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MOUNT2, 0, KEY_READ, &Key) == ERROR_SUCCESS)
            {
                CheckData(Key, L"20k", 20 * 1024, 70);
                CheckData(Key, L"2m", 2 * 1024 * 1024, 71);
                RegCloseKey(Key);
            }
            RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT2);
        }
    }

Cleanup:
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT);
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT2);
    free(Hive);
    DeleteFileW(File);
    DeleteFileW(Saved);
    DeleteFileW(Old);
}
