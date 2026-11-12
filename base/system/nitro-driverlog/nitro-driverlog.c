/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Prints what the kernel recorded about drivers that asked for
 *              more than the system provides:
 *
 *   nitro-driverlog [/i] [/s] [/c]
 *      /i  only the missing imports: drivers that failed to load because
 *          they import routines no loaded module exports
 *          (HKLM\SYSTEM\CurrentControlSet\Control\NitroOS\MissingDriverImports,
 *          one REG_MULTI_SZ value per driver file, entries "module!name")
 *      /s  only the stub hits: exported but unimplemented routines that were
 *          called, with the first module that called them
 *          (HKLM\SYSTEM\CurrentControlSet\Control\NitroOS\StubHits)
 *      /c  clear both logs after printing them
 *   With neither /i nor /s both are printed. Exit code 0 when something was
 *   printed or the logs are empty, 1 for a usage or registry error.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>

#define KEY_IMPORTS L"SYSTEM\\CurrentControlSet\\Control\\NitroOS\\MissingDriverImports"
#define KEY_STUBS   L"SYSTEM\\CurrentControlSet\\Control\\NitroOS\\StubHits"

static int g_Cleared;

static VOID Usage(VOID)
{
    wprintf(L"Usage: nitro-driverlog [/i] [/s] [/c]\n"
            L"  /i  missing driver imports only\n"
            L"  /s  stub hits only (unimplemented exports that were called)\n"
            L"  /c  clear the printed logs\n");
}

/* Opens KeyPath; returns FALSE with *Absent set when it does not exist */
static BOOL OpenLog(PCWSTR KeyPath, REGSAM Access, HKEY *Key, BOOL *Absent)
{
    LONG Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, KeyPath, 0, Access, Key);

    *Absent = (Error == ERROR_FILE_NOT_FOUND || Error == ERROR_PATH_NOT_FOUND);
    if (Error != ERROR_SUCCESS && !*Absent)
        fwprintf(stderr, L"nitro-driverlog: cannot open HKLM\\%ls (error %lu)\n", KeyPath, Error);
    return Error == ERROR_SUCCESS;
}

/* Reads every value of the open key: calls Print for each, returns the count (-1 on error) */
typedef VOID (*PRINT_FN)(PCWSTR Name, DWORD Type, const WCHAR *Data, DWORD Chars);

static int EnumLog(HKEY Key, PRINT_FN Print)
{
    DWORD Index = 0, MaxName = 0, MaxData = 0;
    WCHAR *Name = NULL;
    BYTE *Data = NULL;
    int Count = 0;
    LONG Error;

    Error = RegQueryInfoKeyW(Key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &MaxName, &MaxData, NULL, NULL);
    if (Error != ERROR_SUCCESS)
        return -1;
    Name = malloc((MaxName + 2) * sizeof(WCHAR));
    Data = malloc(MaxData + 2 * sizeof(WCHAR));
    if (!Name || !Data)
    {
        free(Name);
        free(Data);
        return -1;
    }

    for (;;)
    {
        DWORD NameLen = MaxName + 1, DataLen = MaxData, Type;

        Error = RegEnumValueW(Key, Index++, Name, &NameLen, NULL, &Type, Data, &DataLen);
        if (Error == ERROR_NO_MORE_ITEMS)
            break;
        if (Error != ERROR_SUCCESS)
        {
            Count = -1;
            break;
        }
        /* keep the data terminated, whatever was stored */
        ((WCHAR *)Data)[DataLen / sizeof(WCHAR)] = UNICODE_NULL;
        ((WCHAR *)Data)[DataLen / sizeof(WCHAR) + 1] = UNICODE_NULL;
        Print(Name, Type, (WCHAR *)Data, DataLen / sizeof(WCHAR));
        Count++;
    }

    free(Name);
    free(Data);
    return Count;
}

static VOID PrintImports(PCWSTR Name, DWORD Type, const WCHAR *Data, DWORD Chars)
{
    const WCHAR *Entry;
    DWORD Count = 0;

    if (Type != REG_MULTI_SZ)
    {
        wprintf(L"%ls: (unexpected value type %lu)\n", Name, Type);
        return;
    }
    for (Entry = Data; *Entry; Entry += wcslen(Entry) + 1)
        Count++;
    wprintf(L"%ls: %lu unresolved import%ls\n", Name, Count, Count == 1 ? L"" : L"s");
    for (Entry = Data; *Entry; Entry += wcslen(Entry) + 1)
        wprintf(L"    %ls\n", Entry);
    (VOID)Chars;
}

static VOID PrintStubs(PCWSTR Name, DWORD Type, const WCHAR *Data, DWORD Chars)
{
    if (Type != REG_SZ)
    {
        wprintf(L"%ls: (unexpected value type %lu)\n", Name, Type);
        return;
    }
    wprintf(L"    %-40ls first called by %ls\n", Name, Data);
    (VOID)Chars;
}

static BOOL ClearLog(PCWSTR KeyPath)
{
    HKEY Key;
    BOOL Absent;
    DWORD NameLen, MaxName = 0;
    WCHAR *Name;
    BOOL Ok = TRUE;

    if (!OpenLog(KeyPath, KEY_QUERY_VALUE | KEY_SET_VALUE, &Key, &Absent))
        return Absent;
    if (RegQueryInfoKeyW(Key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &MaxName, NULL, NULL, NULL) != ERROR_SUCCESS)
    {
        RegCloseKey(Key);
        return FALSE;
    }
    Name = malloc((MaxName + 2) * sizeof(WCHAR));
    if (!Name)
    {
        RegCloseKey(Key);
        return FALSE;
    }
    for (;;)
    {
        LONG Error;

        NameLen = MaxName + 1;
        /* always index 0: the value is deleted, the next one moves up */
        Error = RegEnumValueW(Key, 0, Name, &NameLen, NULL, NULL, NULL, NULL);
        if (Error == ERROR_NO_MORE_ITEMS)
            break;
        if (Error != ERROR_SUCCESS || RegDeleteValueW(Key, Name) != ERROR_SUCCESS)
        {
            fwprintf(stderr, L"nitro-driverlog: cannot clear HKLM\\%ls\n", KeyPath);
            Ok = FALSE;
            break;
        }
        g_Cleared++;
    }
    free(Name);
    RegCloseKey(Key);
    return Ok;
}

int wmain(int argc, WCHAR **argv)
{
    BOOL WantImports = FALSE, WantStubs = FALSE, Clear = FALSE, Absent;
    int i, Status = 0, Count;
    HKEY Key;

    for (i = 1; i < argc; i++)
    {
        PCWSTR Arg = argv[i];

        if ((Arg[0] != L'/' && Arg[0] != L'-') || Arg[1] == UNICODE_NULL || Arg[2] != UNICODE_NULL)
        {
            Usage();
            return 1;
        }
        switch (Arg[1] | 0x20)
        {
            case L'i': WantImports = TRUE; break;
            case L's': WantStubs = TRUE; break;
            case L'c': Clear = TRUE; break;
            default: Usage(); return 1;
        }
    }
    if (!WantImports && !WantStubs)
        WantImports = WantStubs = TRUE;

    if (WantImports)
    {
        wprintf(L"Drivers that could not load (missing imports):\n");
        if (OpenLog(KEY_IMPORTS, KEY_QUERY_VALUE, &Key, &Absent))
        {
            Count = EnumLog(Key, PrintImports);
            RegCloseKey(Key);
            if (Count < 0) Status = 1;
            else if (Count == 0) wprintf(L"    none\n");
        }
        else if (Absent) wprintf(L"    none\n");
        else Status = 1;
    }

    if (WantStubs)
    {
        wprintf(L"Unimplemented exports that were called:\n");
        if (OpenLog(KEY_STUBS, KEY_QUERY_VALUE, &Key, &Absent))
        {
            Count = EnumLog(Key, PrintStubs);
            RegCloseKey(Key);
            if (Count < 0) Status = 1;
            else if (Count == 0) wprintf(L"    none\n");
        }
        else if (Absent) wprintf(L"    none\n");
        else Status = 1;
    }

    if (Clear)
    {
        if (WantImports && !ClearLog(KEY_IMPORTS)) Status = 1;
        if (WantStubs && !ClearLog(KEY_STUBS)) Status = 1;
        wprintf(L"Cleared %d entr%ls.\n", g_Cleared, g_Cleared == 1 ? L"y" : L"ies");
    }

    return Status;
}
