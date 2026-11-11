/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Values found by name in keys with many values (a table of the names is kept per key), through
 *                  sets, deletes, name case, names that are and are not stored compressed; RegEnumValueA and
 *                  RegQueryValueExA against the wide functions
 * COPYRIGHT:     Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define MAX_VALUES  600

static const WCHAR ScratchKey[] = L"Software\\ReactOS_apitest_RegValueLookup";

static unsigned int g_Seed;

static unsigned int NextRandom(void)
{
    g_Seed = g_Seed * 1103515245u + 12345u;
    return (g_Seed >> 8) & 0xFFFFFF;
}

static void MakeName(WCHAR *Name, int Index, int Variant)
{
    if (Variant == 0)
        _snwprintf(Name, 63, L"Value_%05d", Index);                       /* stored compressed */
    else if (Variant == 1)
        _snwprintf(Name, 63, L"\x0416\x0417_%05d_\x00e9", Index);         /* stored as it is */
    else
        _snwprintf(Name, 63, L"mixedCase\x00e9_%d_END", Index);
}

static void FlipCase(WCHAR *Name)
{
    for (; *Name; Name++)
    {
        if (*Name >= L'a' && *Name <= L'z') *Name -= 32;
        else if (*Name >= L'A' && *Name <= L'Z') *Name += 32;
        else if (*Name == 0x00e9) *Name = 0x00c9;
    }
}

static BOOL QueryDword(HKEY hKey, const WCHAR *Name, DWORD *pValue)
{
    DWORD Type = 0, Size = sizeof(DWORD);
    LONG Ret = RegQueryValueExW(hKey, Name, NULL, &Type, (BYTE *)pValue, &Size);
    return Ret == ERROR_SUCCESS && Type == REG_DWORD && Size == sizeof(DWORD);
}

static void TestLookups(int Count, int Variant)
{
    HKEY hKey;
    DWORD Disposition, Value, Present = 0, Enumerated, Step;
    DWORD *Values = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_VALUES * sizeof(DWORD));
    BOOL *Exists = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_VALUES * sizeof(BOOL));
    WCHAR Name[64];
    LONG Ret;
    int i;

    RegDeleteKeyW(HKEY_CURRENT_USER, ScratchKey);
    Ret = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchKey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, &Disposition);
    ok_dec(Ret, ERROR_SUCCESS);
    if (Ret != ERROR_SUCCESS) goto Done;

    /* Add, and look up while adding: the table is made part way and has to follow the appends */
    for (i = 0; i < Count; i++)
    {
        MakeName(Name, i, Variant);
        Values[i] = i * 3 + 1;
        Ret = RegSetValueExW(hKey, Name, 0, REG_DWORD, (BYTE *)&Values[i], sizeof(DWORD));
        ok_dec(Ret, ERROR_SUCCESS);
        Exists[i] = TRUE;
        if (i % 5 == 0)
        {
            int j = NextRandom() % (i + 1);
            MakeName(Name, j, Variant);
            ok(QueryDword(hKey, Name, &Value) && Value == Values[j], "Count %d variant %d: value %d not found\n", Count, Variant, j);
            _snwprintf(Name, 63, L"absent_%d", i);
            ok(!QueryDword(hKey, Name, &Value), "absent value found\n");
        }
    }

    /* Random mix of changes and lookups */
    for (Step = 0; Step < (DWORD)Count * 4; Step++)
    {
        BOOL Found;

        i = NextRandom() % Count;
        MakeName(Name, i, Variant);
        switch (NextRandom() % 5)
        {
            case 0: /* set a new or an existing value */
                Values[i] = NextRandom();
                Ret = RegSetValueExW(hKey, Name, 0, REG_DWORD, (BYTE *)&Values[i], sizeof(DWORD));
                ok_dec(Ret, ERROR_SUCCESS);
                Exists[i] = TRUE;
                break;

            case 1: /* delete */
                Ret = RegDeleteValueW(hKey, Name);
                ok_dec(Ret, Exists[i] ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND);
                Exists[i] = FALSE;
                break;

            case 2: /* look up */
                Found = QueryDword(hKey, Name, &Value);
                ok(Found == Exists[i] && (!Found || Value == Values[i]), "Count %d variant %d: lookup of %d wrong\n", Count, Variant, i);
                break;

            case 3: /* look up with the case of the name changed */
                FlipCase(Name);
                Found = QueryDword(hKey, Name, &Value);
                ok(Found == Exists[i] && (!Found || Value == Values[i]), "Count %d variant %d: lookup of %d in other case wrong\n", Count, Variant, i);
                break;

            case 4: /* set an existing value under a name of other case: no new value */
                if (Exists[i])
                {
                    FlipCase(Name);
                    Values[i] = NextRandom();
                    Ret = RegSetValueExW(hKey, Name, 0, REG_DWORD, (BYTE *)&Values[i], sizeof(DWORD));
                    ok_dec(Ret, ERROR_SUCCESS);
                }
                break;
        }
    }

    /* The values left, by lookup, by count and by enumeration */
    for (i = 0; i < Count; i++)
    {
        BOOL Found;
        MakeName(Name, i, Variant);
        Found = QueryDword(hKey, Name, &Value);
        ok(Found == Exists[i] && (!Found || Value == Values[i]), "Count %d variant %d: final lookup of %d wrong\n", Count, Variant, i);
        if (Exists[i]) Present++;
    }

    Value = 0;
    Ret = RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &Value, NULL, NULL, NULL, NULL);
    ok_dec(Ret, ERROR_SUCCESS);
    ok_dec(Value, Present);

    for (Enumerated = 0; ; Enumerated++)
    {
        WCHAR EnumName[64];
        DWORD Chars = RTL_NUMBER_OF(EnumName);
        if (RegEnumValueW(hKey, Enumerated, EnumName, &Chars, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
    }
    ok_dec(Enumerated, Present);

    /* A closed and opened key is still searched right */
    RegCloseKey(hKey);
    Ret = RegOpenKeyExW(HKEY_CURRENT_USER, ScratchKey, 0, KEY_ALL_ACCESS, &hKey);
    ok_dec(Ret, ERROR_SUCCESS);
    if (Ret == ERROR_SUCCESS)
    {
        for (i = 0; i < Count; i++)
        {
            BOOL Found;
            MakeName(Name, i, Variant);
            Found = QueryDword(hKey, Name, &Value);
            ok(Found == Exists[i] && (!Found || Value == Values[i]), "Count %d variant %d: lookup of %d after reopening wrong\n", Count, Variant, i);
        }
        RegCloseKey(hKey);
    }

Done:
    RegDeleteKeyW(HKEY_CURRENT_USER, ScratchKey);
    HeapFree(GetProcessHeap(), 0, Values);
    HeapFree(GetProcessHeap(), 0, Exists);
}

/* RegEnumValueA gives what RegEnumValueW gives, converted */
static void TestEnumAnsi(void)
{
    static const struct { const WCHAR *Name; DWORD Type; const void *Data; DWORD Size; } Values[] =
    {
        { L"sz",     REG_SZ,        L"hello",     12 },
        { L"empty",  REG_SZ,        L"",          2 },
        { L"noterm", REG_SZ,        L"abcd",      8 },
        { L"multi",  REG_MULTI_SZ,  L"a\0bc\0\0", 14 },
        { L"dword",  REG_DWORD,     "\x78\x56\x34\x12", 4 },
        { L"bin",    REG_BINARY,    "\1\2\3\4\5\6\7", 7 },
    };
    HKEY hKey;
    DWORD Disposition, Index;
    LONG Ret;
    int Size;

    RegDeleteKeyW(HKEY_CURRENT_USER, ScratchKey);
    Ret = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchKey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, &Disposition);
    ok_dec(Ret, ERROR_SUCCESS);
    if (Ret != ERROR_SUCCESS) return;
    for (Index = 0; Index < RTL_NUMBER_OF(Values); Index++)
        RegSetValueExW(hKey, Values[Index].Name, 0, Values[Index].Type, Values[Index].Data, Values[Index].Size);

    for (Index = 0; Index < RTL_NUMBER_OF(Values); Index++)
    {
        for (Size = 0; Size <= 20; Size += 4)
        {
            CHAR NameA[32], DataA[32];
            WCHAR NameW[32];
            BYTE DataW[64];
            DWORD CharsA = sizeof(NameA), CharsW = RTL_NUMBER_OF(NameW), TypeA = 99, TypeW = 98;
            DWORD CountA = Size, CountW = sizeof(DataW);
            LONG RetA, RetW;

            memset(DataA, 0x55, sizeof(DataA));
            RetA = RegEnumValueA(hKey, Index, NameA, &CharsA, NULL, &TypeA, (BYTE *)DataA, &CountA);
            RetW = RegEnumValueW(hKey, Index, NameW, &CharsW, NULL, &TypeW, DataW, &CountW);
            ok_dec(RetW, ERROR_SUCCESS);
            ok_int(TypeA, TypeW);
            if (RetA == ERROR_SUCCESS)
            {
                ok_dec(CharsA, CharsW);
                ok(NameA[CharsA] == 0, "Name not terminated\n");
                if (Values[Index].Type == REG_SZ || Values[Index].Type == REG_MULTI_SZ || Values[Index].Type == REG_EXPAND_SZ)
                    ok_dec(CountA, CountW / sizeof(WCHAR));
                else
                {
                    ok_dec(CountA, CountW);
                    ok(!memcmp(DataA, DataW, CountW), "Binary data differs\n");
                }
            }
            else
            {
                ok_dec(RetA, ERROR_MORE_DATA);
                ok(CountA > (DWORD)Size, "Size asked for %lu, buffer %d\n", CountA, Size);
            }

            /* No data buffer: only the size */
            CharsA = sizeof(NameA);
            CountA = 0;
            RetA = RegEnumValueA(hKey, Index, NameA, &CharsA, NULL, &TypeA, NULL, &CountA);
            ok_dec(RetA, ERROR_SUCCESS);
        }
    }

    {
        CHAR NameA[32];
        DWORD Chars = sizeof(NameA);
        ok_dec(RegEnumValueA(hKey, RTL_NUMBER_OF(Values), NameA, &Chars, NULL, NULL, NULL, NULL), ERROR_NO_MORE_ITEMS);
        Chars = 2;
        ok_dec(RegEnumValueA(hKey, 1, NameA, &Chars, NULL, NULL, NULL, NULL), ERROR_MORE_DATA);
    }

    RegCloseKey(hKey);
    RegDeleteKeyW(HKEY_CURRENT_USER, ScratchKey);
}

START_TEST(RegValueLookup)
{
    static const int Counts[] = { 5, 16, 17, 40, 300 };
    int Variant, i;

    for (Variant = 0; Variant < 3; Variant++)
    {
        for (i = 0; i < (int)RTL_NUMBER_OF(Counts); i++)
        {
            g_Seed = 777 + i + Variant * 100;
            TestLookups(Counts[i], Variant);
        }
    }

    TestEnumAnsi();
}
