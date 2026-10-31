/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for IdnToAscii, IdnToUnicode and IdnToNameprepUnicode of kernel32
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every row was measured on Windows 10 22H2 (x64): the size query, the conversion, a buffer one too small and the
 * conversion of a string that ends in a NUL (the length -1). Git imports IdnToAscii and IdnToUnicode from kernel32.
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>

#define UNTOUCHED 0xbadbad00

enum { IDN_ASCII, IDN_UNICODE, IDN_NAMEPREP };

typedef int (WINAPI *IdnFunc)(DWORD, LPCWSTR, int, LPWSTR, int);

static const struct
{
    int func;
    DWORD flags;
    const WCHAR *input;
    int size;               /* the size query: the length of the result */
    DWORD size_error;
    int length;             /* the conversion: -2 where the size query failed */
    DWORD error;
    const WCHAR *output;
    int short_length;       /* a buffer that is one too small */
    DWORD short_error;
    int nul_length;         /* the length of the input is -1 */
    DWORD nul_error;
} cases[] =
{
    { IDN_ASCII, 0, L"example.com", 11, UNTOUCHED, 11, UNTOUCHED, L"example.com", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 0, L"b" L"\x00fc" L"cher.example", 21, UNTOUCHED, 21, UNTOUCHED, L"xn--bcher-kva.example", 0, 122, 22, UNTOUCHED },
    { IDN_ASCII, 0, L"\x65e5" L"\x672c" L"\x8a9e" L".jp", 17, UNTOUCHED, 17, UNTOUCHED, L"xn--wgv71a119e.jp", 0, 122, 18, UNTOUCHED },
    { IDN_ASCII, 0, L"fa" L"\x00df" L".de", 7, UNTOUCHED, 7, UNTOUCHED, L"fass.de", 0, 122, 8, UNTOUCHED },
    { IDN_ASCII, 0, L"EXAMPLE.COM", 11, UNTOUCHED, 11, UNTOUCHED, L"EXAMPLE.COM", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 0, L"a_b.com", 7, UNTOUCHED, 7, UNTOUCHED, L"a_b.com", 0, 122, 8, UNTOUCHED },
    { IDN_ASCII, 0, L"-a.com", 6, UNTOUCHED, 6, UNTOUCHED, L"-a.com", 0, 122, 7, UNTOUCHED },
    { IDN_ASCII, 0, L"a-.com", 6, UNTOUCHED, 6, UNTOUCHED, L"a-.com", 0, 122, 7, UNTOUCHED },
    { IDN_ASCII, 0, L"", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 0, L".", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 0, L"..", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 0, L"a..b", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 0, L"\xff45" L"\xff58" L"\xff41" L"\xff4d" L"\xff50" L"\xff4c" L"\xff45" L".com", 11, UNTOUCHED, 11, UNTOUCHED, L"example.com", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 0, L"x" L"\x00ad" L".com", 5, UNTOUCHED, 5, UNTOUCHED, L"x.com", 0, 122, 6, UNTOUCHED },
    { IDN_ASCII, 0, L"\x0627" L"\x0644", 9, UNTOUCHED, 9, UNTOUCHED, L"xn--mgb2d", 0, 122, 10, UNTOUCHED },
    { IDN_ASCII, 0, L"www." L"\x00e4" L".de", 14, UNTOUCHED, 14, UNTOUCHED, L"www.xn--4ca.de", 0, 122, 15, UNTOUCHED },
    { IDN_ASCII, 0, L"\x4e2d" L"\x6587" L".com.", 16, UNTOUCHED, 16, UNTOUCHED, L"xn--fiq228c.com.", 0, 122, 17, UNTOUCHED },
    { IDN_ASCII, 0, L"m" L"\x00fc" L"nchen", 14, UNTOUCHED, 14, UNTOUCHED, L"xn--mnchen-3ya", 0, 122, 15, UNTOUCHED },
    { IDN_ASCII, 0, L"a.b.c.d", 7, UNTOUCHED, 7, UNTOUCHED, L"a.b.c.d", 0, 122, 8, UNTOUCHED },
    { IDN_ASCII, 0, L"\x0430" L"\x0431" L"\x0432", 9, UNTOUCHED, 9, UNTOUCHED, L"xn--80acd", 0, 122, 10, UNTOUCHED },
    { IDN_ASCII, 0, L"abc" L"\x0627", 11, UNTOUCHED, 11, UNTOUCHED, L"xn--abc-qze", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 0, L"xn--bcher-kva.example", 21, UNTOUCHED, 21, UNTOUCHED, L"xn--bcher-kva.example", 0, 122, 22, UNTOUCHED },
    { IDN_ASCII, 0, L"xn--n3h.com", 11, UNTOUCHED, 11, UNTOUCHED, L"xn--n3h.com", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 0, L"XN--BCHER-KVA.example", 21, UNTOUCHED, 21, UNTOUCHED, L"XN--BCHER-KVA.example", 0, 122, 22, UNTOUCHED },
    { IDN_ASCII, 0, L"xn--", 4, UNTOUCHED, 4, UNTOUCHED, L"xn--", 0, 122, 5, UNTOUCHED },
    { IDN_ASCII, 0, L"xn--a", 5, UNTOUCHED, 5, UNTOUCHED, L"xn--a", 0, 122, 6, UNTOUCHED },
    { IDN_ASCII, 0, L"xn---.com", 9, UNTOUCHED, 9, UNTOUCHED, L"xn---.com", 0, 122, 10, UNTOUCHED },
    { IDN_ASCII, 0, L"a b.com", 7, UNTOUCHED, 7, UNTOUCHED, L"a b.com", 0, 122, 8, UNTOUCHED },
    { IDN_ASCII, 0, L"caf" L"\x00e9", 11, UNTOUCHED, 11, UNTOUCHED, L"xn--caf-dma", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 0, L"CAF" L"\x00c9", 11, UNTOUCHED, 11, UNTOUCHED, L"xn--caf-dma", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 3, L"example.com", 11, UNTOUCHED, 11, UNTOUCHED, L"example.com", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 3, L"b" L"\x00fc" L"cher.example", 21, UNTOUCHED, 21, UNTOUCHED, L"xn--bcher-kva.example", 0, 122, 22, UNTOUCHED },
    { IDN_ASCII, 3, L"\x65e5" L"\x672c" L"\x8a9e" L".jp", 17, UNTOUCHED, 17, UNTOUCHED, L"xn--wgv71a119e.jp", 0, 122, 18, UNTOUCHED },
    { IDN_ASCII, 3, L"fa" L"\x00df" L".de", 7, UNTOUCHED, 7, UNTOUCHED, L"fass.de", 0, 122, 8, UNTOUCHED },
    { IDN_ASCII, 3, L"EXAMPLE.COM", 11, UNTOUCHED, 11, UNTOUCHED, L"EXAMPLE.COM", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 3, L"a_b.com", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 3, L"-a.com", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 3, L"a-.com", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 3, L"", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 3, L".", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 3, L"..", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 3, L"a..b", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 3, L"\xff45" L"\xff58" L"\xff41" L"\xff4d" L"\xff50" L"\xff4c" L"\xff45" L".com", 11, UNTOUCHED, 11, UNTOUCHED, L"example.com", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 3, L"x" L"\x00ad" L".com", 5, UNTOUCHED, 5, UNTOUCHED, L"x.com", 0, 122, 6, UNTOUCHED },
    { IDN_ASCII, 3, L"\x0627" L"\x0644", 9, UNTOUCHED, 9, UNTOUCHED, L"xn--mgb2d", 0, 122, 10, UNTOUCHED },
    { IDN_ASCII, 3, L"www." L"\x00e4" L".de", 14, UNTOUCHED, 14, UNTOUCHED, L"www.xn--4ca.de", 0, 122, 15, UNTOUCHED },
    { IDN_ASCII, 3, L"\x4e2d" L"\x6587" L".com.", 16, UNTOUCHED, 16, UNTOUCHED, L"xn--fiq228c.com.", 0, 122, 17, UNTOUCHED },
    { IDN_ASCII, 3, L"m" L"\x00fc" L"nchen", 14, UNTOUCHED, 14, UNTOUCHED, L"xn--mnchen-3ya", 0, 122, 15, UNTOUCHED },
    { IDN_ASCII, 3, L"a.b.c.d", 7, UNTOUCHED, 7, UNTOUCHED, L"a.b.c.d", 0, 122, 8, UNTOUCHED },
    { IDN_ASCII, 3, L"\x0430" L"\x0431" L"\x0432", 9, UNTOUCHED, 9, UNTOUCHED, L"xn--80acd", 0, 122, 10, UNTOUCHED },
    { IDN_ASCII, 3, L"abc" L"\x0627", 11, UNTOUCHED, 11, UNTOUCHED, L"xn--abc-qze", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 3, L"xn--bcher-kva.example", 21, UNTOUCHED, 21, UNTOUCHED, L"xn--bcher-kva.example", 0, 122, 22, UNTOUCHED },
    { IDN_ASCII, 3, L"xn--n3h.com", 11, UNTOUCHED, 11, UNTOUCHED, L"xn--n3h.com", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 3, L"XN--BCHER-KVA.example", 21, UNTOUCHED, 21, UNTOUCHED, L"XN--BCHER-KVA.example", 0, 122, 22, UNTOUCHED },
    { IDN_ASCII, 3, L"xn--", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 3, L"xn--a", 5, UNTOUCHED, 5, UNTOUCHED, L"xn--a", 0, 122, 6, UNTOUCHED },
    { IDN_ASCII, 3, L"xn---.com", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 3, L"a b.com", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_ASCII, 3, L"caf" L"\x00e9", 11, UNTOUCHED, 11, UNTOUCHED, L"xn--caf-dma", 0, 122, 12, UNTOUCHED },
    { IDN_ASCII, 3, L"CAF" L"\x00c9", 11, UNTOUCHED, 11, UNTOUCHED, L"xn--caf-dma", 0, 122, 12, UNTOUCHED },
    { IDN_UNICODE, 0, L"xn--bcher-kva.example", 14, UNTOUCHED, 14, UNTOUCHED, L"b" L"\x00fc" L"cher.example", 0, 122, 15, UNTOUCHED },
    { IDN_UNICODE, 0, L"xn--wgv71a119e.jp", 6, UNTOUCHED, 6, UNTOUCHED, L"\x65e5" L"\x672c" L"\x8a9e" L".jp", 0, 122, 7, UNTOUCHED },
    { IDN_UNICODE, 0, L"xn--fa-hia.de", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_UNICODE, 0, L"example.com", 11, UNTOUCHED, 11, UNTOUCHED, L"example.com", 0, 122, 12, UNTOUCHED },
    { IDN_UNICODE, 0, L"EXAMPLE.COM", 11, UNTOUCHED, 11, UNTOUCHED, L"EXAMPLE.COM", 0, 122, 12, UNTOUCHED },
    { IDN_UNICODE, 0, L"xn--", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_UNICODE, 0, L"xn--a", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_UNICODE, 0, L"xn--n3h.com", 5, UNTOUCHED, 5, UNTOUCHED, L"\x2603" L".com", 0, 122, 6, UNTOUCHED },
    { IDN_UNICODE, 0, L"xn--bcher-kva", 6, UNTOUCHED, 6, UNTOUCHED, L"b" L"\x00fc" L"cher", 0, 122, 7, UNTOUCHED },
    { IDN_UNICODE, 0, L"xn--zzzz", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_UNICODE, 0, L"xn--bcher-kva.", 7, UNTOUCHED, 7, UNTOUCHED, L"b" L"\x00fc" L"cher.", 0, 122, 8, UNTOUCHED },
    { IDN_UNICODE, 0, L"xn--caf-dma", 4, UNTOUCHED, 4, UNTOUCHED, L"caf" L"\x00e9", 0, 122, 5, UNTOUCHED },
    { IDN_UNICODE, 0, L"a..b", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_UNICODE, 0, L"", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_UNICODE, 0, L"xn--mnchen-3ya", 7, UNTOUCHED, 7, UNTOUCHED, L"m" L"\x00fc" L"nchen", 0, 122, 8, UNTOUCHED },
    { IDN_UNICODE, 0, L"b" L"\x00fc" L"cher.example", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_UNICODE, 0, L"xn--bcher-kva.xn--bcher-kva", 13, UNTOUCHED, 13, UNTOUCHED, L"b" L"\x00fc" L"cher.b" L"\x00fc" L"cher", 0, 122, 14, UNTOUCHED },
    { IDN_UNICODE, 0, L"XN--MNCHEN-3YA", 7, UNTOUCHED, 7, UNTOUCHED, L"m" L"\x00fc" L"nchen", 0, 122, 8, UNTOUCHED },
    { IDN_UNICODE, 0, L"-a.com", 6, UNTOUCHED, 6, UNTOUCHED, L"-a.com", 0, 122, 7, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"example.com", 11, UNTOUCHED, 11, UNTOUCHED, L"example.com", 0, 122, 12, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"b" L"\x00fc" L"cher.example", 14, UNTOUCHED, 14, UNTOUCHED, L"b" L"\x00fc" L"cher.example", 0, 122, 15, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"\x65e5" L"\x672c" L"\x8a9e" L".jp", 6, UNTOUCHED, 6, UNTOUCHED, L"\x65e5" L"\x672c" L"\x8a9e" L".jp", 0, 122, 7, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"fa" L"\x00df" L".de", 7, UNTOUCHED, 7, UNTOUCHED, L"fass.de", 0, 122, 8, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"EXAMPLE.COM", 11, UNTOUCHED, 11, UNTOUCHED, L"EXAMPLE.COM", 0, 122, 12, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"a_b.com", 7, UNTOUCHED, 7, UNTOUCHED, L"a_b.com", 0, 122, 8, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"-a.com", 6, UNTOUCHED, 6, UNTOUCHED, L"-a.com", 0, 122, 7, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"a-.com", 6, UNTOUCHED, 6, UNTOUCHED, L"a-.com", 0, 122, 7, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_NAMEPREP, 0, L".", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_NAMEPREP, 0, L"..", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_NAMEPREP, 0, L"a..b", 0, 123, -2, 0, NULL, -2, 0, 0, 123 },
    { IDN_NAMEPREP, 0, L"\xff45" L"\xff58" L"\xff41" L"\xff4d" L"\xff50" L"\xff4c" L"\xff45" L".com", 11, UNTOUCHED, 11, UNTOUCHED, L"example.com", 0, 122, 12, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"x" L"\x00ad" L".com", 5, UNTOUCHED, 5, UNTOUCHED, L"x.com", 0, 122, 6, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"\x0627" L"\x0644", 2, UNTOUCHED, 2, UNTOUCHED, L"\x0627" L"\x0644", 0, 122, 3, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"www." L"\x00e4" L".de", 8, UNTOUCHED, 8, UNTOUCHED, L"www." L"\x00e4" L".de", 0, 122, 9, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"\x4e2d" L"\x6587" L".com.", 7, UNTOUCHED, 7, UNTOUCHED, L"\x4e2d" L"\x6587" L".com.", 0, 122, 8, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"m" L"\x00fc" L"nchen", 7, UNTOUCHED, 7, UNTOUCHED, L"m" L"\x00fc" L"nchen", 0, 122, 8, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"a.b.c.d", 7, UNTOUCHED, 7, UNTOUCHED, L"a.b.c.d", 0, 122, 8, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"\x0430" L"\x0431" L"\x0432", 3, UNTOUCHED, 3, UNTOUCHED, L"\x0430" L"\x0431" L"\x0432", 0, 122, 4, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"abc" L"\x0627", 4, UNTOUCHED, 4, UNTOUCHED, L"abc" L"\x0627", 0, 122, 5, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"xn--bcher-kva.example", 21, UNTOUCHED, 21, UNTOUCHED, L"xn--bcher-kva.example", 0, 122, 22, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"xn--n3h.com", 11, UNTOUCHED, 11, UNTOUCHED, L"xn--n3h.com", 0, 122, 12, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"XN--BCHER-KVA.example", 21, UNTOUCHED, 21, UNTOUCHED, L"XN--BCHER-KVA.example", 0, 122, 22, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"xn--", 4, UNTOUCHED, 4, UNTOUCHED, L"xn--", 0, 122, 5, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"xn--a", 5, UNTOUCHED, 5, UNTOUCHED, L"xn--a", 0, 122, 6, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"xn---.com", 9, UNTOUCHED, 9, UNTOUCHED, L"xn---.com", 0, 122, 10, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"a b.com", 7, UNTOUCHED, 7, UNTOUCHED, L"a b.com", 0, 122, 8, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"caf" L"\x00e9", 4, UNTOUCHED, 4, UNTOUCHED, L"caf" L"\x00e9", 0, 122, 5, UNTOUCHED },
    { IDN_NAMEPREP, 0, L"CAF" L"\x00c9", 4, UNTOUCHED, 4, UNTOUCHED, L"caf" L"\x00e9", 0, 122, 5, UNTOUCHED },
};

static void test_cases(IdnFunc funcs[3])
{
    WCHAR buffer[512];
    unsigned int i;
    int ret, len;
    DWORD error;

    for (i = 0; i < ARRAYSIZE(cases); i++)
    {
        IdnFunc func = funcs[cases[i].func];
        int input_length = lstrlenW(cases[i].input);

        SetLastError(UNTOUCHED);
        ret = func(cases[i].flags, cases[i].input, input_length, NULL, 0);
        error = GetLastError();
        ok(ret == cases[i].size, "%u (%d %lx): size query returned %d, expected %d\n", i, cases[i].func, cases[i].flags, ret, cases[i].size);
        ok(error == cases[i].size_error, "%u (%d %lx): size query error %lu, expected %lu\n", i, cases[i].func, cases[i].flags, error, cases[i].size_error);

        if (cases[i].length != -2)
        {
            memset(buffer, 0xaa, sizeof(buffer));
            SetLastError(UNTOUCHED);
            ret = func(cases[i].flags, cases[i].input, input_length, buffer, ARRAYSIZE(buffer));
            error = GetLastError();
            ok(ret == cases[i].length, "%u (%d %lx): returned %d, expected %d\n", i, cases[i].func, cases[i].flags, ret, cases[i].length);
            ok(error == cases[i].error, "%u (%d %lx): error %lu, expected %lu\n", i, cases[i].func, cases[i].flags, error, cases[i].error);
            len = cases[i].output ? lstrlenW(cases[i].output) : 0;
            if (ret > 0 && ret == len)
                ok(!memcmp(buffer, cases[i].output, len * sizeof(WCHAR)), "%u (%d %lx): wrong result\n", i, cases[i].func, cases[i].flags);
        }

        if (cases[i].short_length != -2)
        {
            memset(buffer, 0xaa, sizeof(buffer));
            SetLastError(UNTOUCHED);
            ret = func(cases[i].flags, cases[i].input, input_length, buffer, cases[i].size - 1);
            error = GetLastError();
            ok(ret == cases[i].short_length, "%u (%d %lx): short buffer returned %d, expected %d\n", i, cases[i].func, cases[i].flags, ret, cases[i].short_length);
            ok(error == cases[i].short_error, "%u (%d %lx): short buffer error %lu, expected %lu\n", i, cases[i].func, cases[i].flags, error, cases[i].short_error);
        }

        memset(buffer, 0xaa, sizeof(buffer));
        SetLastError(UNTOUCHED);
        ret = func(cases[i].flags, cases[i].input, -1, buffer, ARRAYSIZE(buffer));
        error = GetLastError();
        ok(ret == cases[i].nul_length, "%u (%d %lx): NUL terminated returned %d, expected %d\n", i, cases[i].func, cases[i].flags, ret, cases[i].nul_length);
        ok(error == cases[i].nul_error, "%u (%d %lx): NUL terminated error %lu, expected %lu\n", i, cases[i].func, cases[i].flags, error, cases[i].nul_error);
    }
}

static void test_parameters(IdnFunc funcs[3])
{
    WCHAR buffer[64];
    int ret;

    SetLastError(UNTOUCHED);
    ret = funcs[IDN_ASCII](0, NULL, 5, buffer, ARRAYSIZE(buffer));
    ok(ret == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "no source: %d %lu\n", ret, GetLastError());
    SetLastError(UNTOUCHED);
    ret = funcs[IDN_ASCII](0, L"abc", 0, buffer, ARRAYSIZE(buffer));
    ok(ret == 0 && GetLastError() == ERROR_INVALID_NAME, "length 0: %d %lu\n", ret, GetLastError());
    SetLastError(UNTOUCHED);
    ret = funcs[IDN_ASCII](0, L"abc", -2, buffer, ARRAYSIZE(buffer));
    ok(ret == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "length -2: %d %lu\n", ret, GetLastError());
    SetLastError(UNTOUCHED);
    ret = funcs[IDN_ASCII](0, L"abc", -1, NULL, 5);
    ok(ret == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "no destination: %d %lu\n", ret, GetLastError());
    SetLastError(UNTOUCHED);
    ret = funcs[IDN_ASCII](0, L"abc", -1, buffer, -1);
    ok(ret == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "destination length -1: %d %lu\n", ret, GetLastError());

    /* flags other than IDN_ALLOW_UNASSIGNED (1) and IDN_USE_STD3_ASCII_RULES (2) */
    SetLastError(UNTOUCHED);
    ret = funcs[IDN_ASCII](0x10, L"abc", -1, buffer, ARRAYSIZE(buffer));
    ok(ret == 0 && GetLastError() == ERROR_INVALID_FLAGS, "ToAscii flags: %d %lu\n", ret, GetLastError());
    SetLastError(UNTOUCHED);
    ret = funcs[IDN_UNICODE](0x10, L"abc", -1, buffer, ARRAYSIZE(buffer));
    ok(ret == 0 && GetLastError() == ERROR_INVALID_FLAGS, "ToUnicode flags: %d %lu\n", ret, GetLastError());
    SetLastError(UNTOUCHED);
    ret = funcs[IDN_NAMEPREP](0x10, L"abc", -1, buffer, ARRAYSIZE(buffer));
    ok(ret == 0 && GetLastError() == ERROR_INVALID_FLAGS, "Nameprep flags: %d %lu\n", ret, GetLastError());
}

START_TEST(IdnTo)
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE normaliz = LoadLibraryA("normaliz.dll");
    IdnFunc funcs[3], normaliz_funcs[3];

    funcs[IDN_ASCII] = (IdnFunc)GetProcAddress(kernel32, "IdnToAscii");
    funcs[IDN_UNICODE] = (IdnFunc)GetProcAddress(kernel32, "IdnToUnicode");
    funcs[IDN_NAMEPREP] = (IdnFunc)GetProcAddress(kernel32, "IdnToNameprepUnicode");
    ok(funcs[IDN_ASCII] && funcs[IDN_UNICODE] && funcs[IDN_NAMEPREP], "kernel32 does not export the IDN functions\n");
    if (!funcs[IDN_ASCII] || !funcs[IDN_UNICODE] || !funcs[IDN_NAMEPREP])
        return;

    test_cases(funcs);
    test_parameters(funcs);

    /* normaliz.dll has the same functions (it forwards to kernel32 on Windows 10) */
    if (!normaliz)
    {
        skip("normaliz.dll is not available\n");
        return;
    }
    normaliz_funcs[IDN_ASCII] = (IdnFunc)GetProcAddress(normaliz, "IdnToAscii");
    normaliz_funcs[IDN_UNICODE] = (IdnFunc)GetProcAddress(normaliz, "IdnToUnicode");
    normaliz_funcs[IDN_NAMEPREP] = (IdnFunc)GetProcAddress(normaliz, "IdnToNameprepUnicode");
    ok(normaliz_funcs[IDN_ASCII] && normaliz_funcs[IDN_UNICODE] && normaliz_funcs[IDN_NAMEPREP], "normaliz does not export the IDN functions\n");
    if (normaliz_funcs[IDN_ASCII] && normaliz_funcs[IDN_UNICODE] && normaliz_funcs[IDN_NAMEPREP])
        test_cases(normaliz_funcs);
    FreeLibrary(normaliz);
}
