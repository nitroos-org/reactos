/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     RegQueryMultipleValuesW with several value types and a buffer that is too small.
 *              The same PE32 image runs natively on i386 and under WoW64.
 */

#include "precomp.h"

#define TEST_KEY L"Software\\RegQueryMultipleValues_apitest"

START_TEST(RegQueryMultipleValues)
{
    static const WCHAR Text[] = L"hello";
    static const DWORD Number = 0x12345678;
    static const BYTE Blob[5] = {1, 2, 3, 4, 5};
    static const WCHAR Multi[] = L"a\0b\0";
    static WCHAR Names[4][8] = {L"Text", L"Number", L"Blob", L"Multi"};
    DWORD Types[4] = {REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ};
    DWORD Sizes[4] = {sizeof(Text), sizeof(Number), sizeof(Blob), sizeof(Multi)};
    const void *Data[4] = {Text, &Number, Blob, Multi};
    VALENTW Values[4];
    BYTE Buffer[256];
    DWORD Total = sizeof(Text) + sizeof(Number) + sizeof(Blob) + sizeof(Multi);
    DWORD Size, i;
    HKEY Key;
    LONG Error;

    Error = RegCreateKeyExW(HKEY_CURRENT_USER, TEST_KEY, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS,
                            NULL, &Key, NULL);
    ok_dec(Error, ERROR_SUCCESS);
    if (Error)
    {
        skip("Cannot create the test key\n");
        return;
    }
    RegSetValueExW(Key, Names[0], 0, REG_SZ, (const BYTE *)Text, sizeof(Text));
    RegSetValueExW(Key, Names[1], 0, REG_DWORD, (const BYTE *)&Number, sizeof(Number));
    RegSetValueExW(Key, Names[2], 0, REG_BINARY, Blob, sizeof(Blob));
    RegSetValueExW(Key, Names[3], 0, REG_MULTI_SZ, (const BYTE *)Multi, sizeof(Multi));

    for (i = 0; i < 4; i++)
    {
        Values[i].ve_valuename = Names[i];
        Values[i].ve_valuelen = 0x55555555;
        Values[i].ve_valueptr = 0;
        Values[i].ve_type = 0x66666666;
    }

    /* Enough room */
    memset(Buffer, 0xAA, sizeof(Buffer));
    Size = sizeof(Buffer);
    Error = RegQueryMultipleValuesW(Key, Values, 4, (LPWSTR)Buffer, &Size);
    ok_dec(Error, ERROR_SUCCESS);
    ok(Size == Total, "Size = %lu, expected %lu\n", Size, Total);
    for (i = 0; i < 4; i++)
    {
        ok(Values[i].ve_type == Types[i], "[%lu] type %lu\n", i, Values[i].ve_type);
        ok(Values[i].ve_valuelen == Sizes[i], "[%lu] length %lu\n", i, Values[i].ve_valuelen);
#ifndef _WIN64 /* ve_valueptr is a DWORD in the SDK header: too narrow for a 64-bit pointer */
        ok(Values[i].ve_valueptr >= (DWORD_PTR)Buffer &&
           Values[i].ve_valueptr + Sizes[i] <= (DWORD_PTR)Buffer + sizeof(Buffer),
           "[%lu] pointer %p outside the buffer\n", i, (void *)Values[i].ve_valueptr);
        ok(!memcmp((const void *)Values[i].ve_valueptr, Data[i], Sizes[i]), "[%lu] data differs\n", i);
#endif
    }

    /* Too small: ERROR_MORE_DATA and the size needed */
    Size = 10;
    Error = RegQueryMultipleValuesW(Key, Values, 4, (LPWSTR)Buffer, &Size);
    ok_dec(Error, ERROR_MORE_DATA);
    ok(Size == Total, "Size = %lu, expected %lu\n", Size, Total);

    /* No buffer at all: the size only */
    Size = 0;
    Error = RegQueryMultipleValuesW(Key, Values, 4, NULL, &Size);
    ok_dec(Error, ERROR_MORE_DATA);
    ok(Size == Total, "Size = %lu, expected %lu\n", Size, Total);

    /* A value that does not exist */
    wcscpy(Names[1], L"Missing");
    Size = sizeof(Buffer);
    Error = RegQueryMultipleValuesW(Key, Values, 4, (LPWSTR)Buffer, &Size);
    ok_dec(Error, ERROR_FILE_NOT_FOUND);

    RegCloseKey(Key);
    RegDeleteKeyW(HKEY_CURRENT_USER, TEST_KEY);
}
