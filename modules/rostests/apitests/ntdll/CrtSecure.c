/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the bounds-checking string functions exported by ntdll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#include <errno.h>
#include <stdarg.h>

#ifndef STRUNCATE
#define STRUNCATE 80
#endif
#ifndef _TRUNCATE
#define _TRUNCATE ((size_t)-1)
#endif

typedef int (__cdecl *PFN_strcat_s)(char *, size_t, const char *);
typedef int (__cdecl *PFN_strncat_s)(char *, size_t, const char *, size_t);
typedef int (__cdecl *PFN_strncpy_s)(char *, size_t, const char *, size_t);
typedef int (__cdecl *PFN_wcscpy_s)(WCHAR *, size_t, const WCHAR *);
typedef int (__cdecl *PFN_wcscat_s)(WCHAR *, size_t, const WCHAR *);
typedef int (__cdecl *PFN_wcsncat_s)(WCHAR *, size_t, const WCHAR *, size_t);
typedef int (__cdecl *PFN_wcsncpy_s)(WCHAR *, size_t, const WCHAR *, size_t);
typedef int (__cdecl *PFN_memcpy_s)(void *, size_t, const void *, size_t);
typedef int (__cdecl *PFN_str_s)(char *, size_t);
typedef int (__cdecl *PFN_wcs_s)(WCHAR *, size_t);
typedef char *(__cdecl *PFN_strtok_s)(char *, const char *, char **);
typedef WCHAR *(__cdecl *PFN_wcstok_s)(WCHAR *, const WCHAR *, WCHAR **);
typedef size_t (__cdecl *PFN_strnlen)(const char *, size_t);
typedef size_t (__cdecl *PFN_wcsnlen)(const WCHAR *, size_t);
typedef int (__cdecl *PFN_i64toa_s)(__int64, char *, size_t, int);
typedef int (__cdecl *PFN_ui64toa_s)(unsigned __int64, char *, size_t, int);
typedef int (__cdecl *PFN_itoa_s)(int, char *, size_t, int);
typedef int (__cdecl *PFN_ltoa_s)(long, char *, size_t, int);
typedef int (__cdecl *PFN_ultoa_s)(unsigned long, char *, size_t, int);
typedef int (__cdecl *PFN_i64tow_s)(__int64, WCHAR *, size_t, int);
typedef int (__cdecl *PFN_ui64tow_s)(unsigned __int64, WCHAR *, size_t, int);
typedef int (__cdecl *PFN_itow_s)(int, WCHAR *, size_t, int);
typedef int (__cdecl *PFN_ltow_s)(long, WCHAR *, size_t, int);
typedef int (__cdecl *PFN_ultow_s)(unsigned long, WCHAR *, size_t, int);
typedef int (__cdecl *PFN_splitpath_s)(const char *, char *, size_t, char *, size_t, char *, size_t, char *, size_t);
typedef int (__cdecl *PFN_wsplitpath_s)(const WCHAR *, WCHAR *, size_t, WCHAR *, size_t, WCHAR *, size_t, WCHAR *, size_t);
typedef int (__cdecl *PFN_makepath_s)(char *, size_t, const char *, const char *, const char *, const char *);
typedef int (__cdecl *PFN_wmakepath_s)(WCHAR *, size_t, const WCHAR *, const WCHAR *, const WCHAR *, const WCHAR *);
typedef __int64 (__cdecl *PFN_wcstoi64)(const WCHAR *, WCHAR **, int);
typedef int (__cdecl *PFN_isw)(WCHAR);
typedef int (__cdecl *PFN_cmp_s)(void *, const void *, const void *);
typedef void (__cdecl *PFN_qsort_s)(void *, size_t, size_t, PFN_cmp_s, void *);
typedef void *(__cdecl *PFN_bsearch_s)(const void *, const void *, size_t, size_t, PFN_cmp_s, void *);
typedef int (__cdecl *PFN_vsnprintf_s)(char *, size_t, size_t, const char *, va_list);
typedef int (__cdecl *PFN_snprintf_s)(char *, size_t, size_t, const char *, ...);
typedef int (__cdecl *PFN_snwprintf_s)(WCHAR *, size_t, size_t, const WCHAR *, ...);
typedef int (__cdecl *PFN_sprintf_s)(char *, size_t, const char *, ...);
typedef int (__cdecl *PFN_swprintf_s)(WCHAR *, size_t, const WCHAR *, ...);
typedef int (__cdecl *PFN_vsprintf_s)(char *, size_t, const char *, va_list);
typedef int (__cdecl *PFN_vscprintf)(const char *, va_list);

static HMODULE Ntdll;

#define GET(name) PFN_##name p##name = (PFN_##name)GetProcAddress(Ntdll, "" #name)

static BOOL Have(const char *name, void *p)
{
    if (!p)
    {
        ok(!is_reactos(), "%s is not exported by ntdll.dll\n", name);
        return FALSE;
    }
    return TRUE;
}

static int __cdecl cmp_int_ctx(void *ctx, const void *a, const void *b)
{
    int *calls = ctx;
    (*calls)++;
    return *(const int *)a - *(const int *)b;
}

static void Test_string(void)
{
    GET(strcat_s); GET(strncat_s); GET(strncpy_s); GET(memcpy_s); GET(strnlen);
    GET(wcscpy_s); GET(wcscat_s); GET(wcsncat_s); GET(wcsncpy_s); GET(wcsnlen);
    char buf[16];
    WCHAR wbuf[16];
    int r;

    if (Have("strcat_s", pstrcat_s))
    {
        strcpy(buf, "ab");
        r = pstrcat_s(buf, sizeof(buf), "cd");
        ok(r == 0 && !strcmp(buf, "abcd"), "strcat_s: %d '%s'\n", r, buf);
        r = pstrcat_s(NULL, 4, "x");
        ok(r == EINVAL, "strcat_s NULL dst: %d\n", r);
        r = pstrcat_s(buf, 0, "x");
        ok(r == EINVAL, "strcat_s zero size: %d\n", r);
        strcpy(buf, "ab");
        r = pstrcat_s(buf, sizeof(buf), NULL);
        ok(r == EINVAL && buf[0] == 0, "strcat_s NULL src: %d '%s'\n", r, buf);
        strcpy(buf, "abc");
        r = pstrcat_s(buf, 5, "def");
        ok(r == ERANGE && buf[0] == 0, "strcat_s overflow: %d '%s'\n", r, buf);
    }
    if (Have("strncat_s", pstrncat_s))
    {
        strcpy(buf, "ab");
        r = pstrncat_s(buf, sizeof(buf), "cdef", 2);
        ok(r == 0 && !strcmp(buf, "abcd"), "strncat_s: %d '%s'\n", r, buf);
        strcpy(buf, "ab");
        r = pstrncat_s(buf, 5, "cdef", _TRUNCATE);
        ok(r == STRUNCATE && !strcmp(buf, "abcd"), "strncat_s truncate: %d '%s'\n", r, buf);
        strcpy(buf, "ab");
        r = pstrncat_s(buf, sizeof(buf), "cd", 0);
        ok(r == 0 && !strcmp(buf, "ab"), "strncat_s zero count: %d '%s'\n", r, buf);
        strcpy(buf, "abcd");
        r = pstrncat_s(buf, 4, "e", 1);
        ok(r == EINVAL && buf[0] == 0, "strncat_s unterminated dst: %d '%s'\n", r, buf);
        strcpy(buf, "ab");
        r = pstrncat_s(buf, 4, "cdef", 3);
        ok(r == ERANGE && buf[0] == 0, "strncat_s overflow: %d '%s'\n", r, buf);
    }
    if (Have("strncpy_s", pstrncpy_s))
    {
        memset(buf, 'x', sizeof(buf));
        r = pstrncpy_s(buf, sizeof(buf), "abcdef", 3);
        ok(r == 0 && !strcmp(buf, "abc"), "strncpy_s: %d '%s'\n", r, buf);
        r = pstrncpy_s(buf, 4, "abcdef", _TRUNCATE);
        ok(r == STRUNCATE && !strcmp(buf, "abc"), "strncpy_s truncate: %d '%s'\n", r, buf);
        r = pstrncpy_s(buf, 4, "abcdef", 5);
        ok(r == ERANGE && buf[0] == 0, "strncpy_s overflow: %d '%s'\n", r, buf);
        r = pstrncpy_s(buf, 4, NULL, 2);
        ok(r == EINVAL && buf[0] == 0, "strncpy_s NULL src: %d\n", r);
        r = pstrncpy_s(NULL, 4, "a", 0);
        ok(r == EINVAL, "strncpy_s zero count NULL dst: %d\n", r);
        memset(buf, 'x', sizeof(buf));
        r = pstrncpy_s(buf, 4, NULL, 0);
        ok(r == 0 && buf[0] == 0, "strncpy_s zero count NULL src: %d\n", r);
        r = pstrncpy_s(buf, 0, "a", 0);
        ok(r == EINVAL, "strncpy_s zero size: %d\n", r);
        r = pstrncpy_s(NULL, 0, NULL, 0);
        ok(r == 0, "strncpy_s all empty: %d\n", r);
    }
    if (Have("memcpy_s", pmemcpy_s))
    {
        memset(buf, 'x', sizeof(buf));
        r = pmemcpy_s(buf, 4, "abcd", 4);
        ok(r == 0 && !memcmp(buf, "abcd", 4), "memcpy_s: %d\n", r);
        r = pmemcpy_s(buf, 4, "abcdef", 6);
        ok(r == ERANGE && !buf[0] && !buf[3], "memcpy_s overflow: %d\n", r);
        memset(buf, 'x', sizeof(buf));
        r = pmemcpy_s(buf, 4, NULL, 2);
        ok(r == EINVAL && !buf[0] && !buf[3], "memcpy_s NULL src: %d\n", r);
        r = pmemcpy_s(NULL, 4, "a", 1);
        ok(r == EINVAL, "memcpy_s NULL dst: %d\n", r);
        r = pmemcpy_s(NULL, 0, NULL, 0);
        ok(r == 0, "memcpy_s zero count: %d\n", r);
    }
    if (Have("strnlen", pstrnlen))
    {
        ok(pstrnlen("abc", 10) == 3, "strnlen\n");
        ok(pstrnlen("abc", 2) == 2, "strnlen limit\n");
        ok(pstrnlen("", 5) == 0, "strnlen empty\n");
    }
    if (Have("wcsnlen", pwcsnlen))
    {
        ok(pwcsnlen(L"abc", 10) == 3, "wcsnlen\n");
        ok(pwcsnlen(L"abc", 2) == 2, "wcsnlen limit\n");
    }
    if (Have("wcscpy_s", pwcscpy_s) && Have("wcscat_s", pwcscat_s) &&
        Have("wcsncat_s", pwcsncat_s) && Have("wcsncpy_s", pwcsncpy_s))
    {
        r = pwcscpy_s(wbuf, 16, L"ab");
        ok(r == 0 && !wcscmp(wbuf, L"ab"), "wcscpy_s: %d\n", r);
        r = pwcscpy_s(wbuf, 2, L"abc");
        ok(r == ERANGE && wbuf[0] == 0, "wcscpy_s overflow: %d\n", r);
        r = pwcscpy_s(wbuf, 16, NULL);
        ok(r == EINVAL && wbuf[0] == 0, "wcscpy_s NULL src: %d\n", r);
        r = pwcscpy_s(NULL, 16, L"a");
        ok(r == EINVAL, "wcscpy_s NULL dst: %d\n", r);
        wcscpy(wbuf, L"ab");
        r = pwcscat_s(wbuf, 16, L"cd");
        ok(r == 0 && !wcscmp(wbuf, L"abcd"), "wcscat_s: %d\n", r);
        r = pwcscat_s(wbuf, 5, L"e");
        ok(r == ERANGE && wbuf[0] == 0, "wcscat_s overflow: %d\n", r);
        wcscpy(wbuf, L"ab");
        r = pwcsncat_s(wbuf, 16, L"cdef", 2);
        ok(r == 0 && !wcscmp(wbuf, L"abcd"), "wcsncat_s: %d\n", r);
        wcscpy(wbuf, L"ab");
        r = pwcsncat_s(wbuf, 5, L"cdef", _TRUNCATE);
        ok(r == STRUNCATE && !wcscmp(wbuf, L"abcd"), "wcsncat_s truncate: %d\n", r);
        r = pwcsncpy_s(wbuf, 16, L"abcdef", 3);
        ok(r == 0 && !wcscmp(wbuf, L"abc"), "wcsncpy_s: %d\n", r);
        r = pwcsncpy_s(wbuf, 4, L"abcdef", _TRUNCATE);
        ok(r == STRUNCATE && !wcscmp(wbuf, L"abc"), "wcsncpy_s truncate: %d\n", r);
        r = pwcsncpy_s(wbuf, 4, L"abcdef", 5);
        ok(r == ERANGE && wbuf[0] == 0, "wcsncpy_s overflow: %d\n", r);
    }
}

static void Test_case_tok(void)
{
    PFN_str_s p_strupr_s = (PFN_str_s)GetProcAddress(Ntdll, "_strupr_s");
    PFN_str_s p_strlwr_s = (PFN_str_s)GetProcAddress(Ntdll, "_strlwr_s");
    PFN_wcs_s p_wcsupr_s = (PFN_wcs_s)GetProcAddress(Ntdll, "_wcsupr_s");
    PFN_wcs_s p_wcslwr_s = (PFN_wcs_s)GetProcAddress(Ntdll, "_wcslwr_s");
    GET(strtok_s); GET(wcstok_s);
    char buf[16], *ctx, *tok;
    WCHAR wbuf[16], *wctx, *wtok;
    int r;

    if (Have("_strupr_s", p_strupr_s) && Have("_strlwr_s", p_strlwr_s))
    {
        strcpy(buf, "aBc1");
        r = p_strupr_s(buf, sizeof(buf));
        ok(r == 0 && !strcmp(buf, "ABC1"), "_strupr_s: %d '%s'\n", r, buf);
        r = p_strlwr_s(buf, sizeof(buf));
        ok(r == 0 && !strcmp(buf, "abc1"), "_strlwr_s: %d '%s'\n", r, buf);
        r = p_strupr_s(NULL, 4);
        ok(r == EINVAL, "_strupr_s NULL: %d\n", r);
        strcpy(buf, "abcd");
        r = p_strupr_s(buf, 4);
        ok(r == EINVAL && buf[0] == 0, "_strupr_s unterminated: %d '%s'\n", r, buf);
    }
    if (Have("_wcsupr_s", p_wcsupr_s) && Have("_wcslwr_s", p_wcslwr_s))
    {
        wcscpy(wbuf, L"aBc1");
        r = p_wcsupr_s(wbuf, 16);
        ok(r == 0 && !wcscmp(wbuf, L"ABC1"), "_wcsupr_s: %d\n", r);
        r = p_wcslwr_s(wbuf, 16);
        ok(r == 0 && !wcscmp(wbuf, L"abc1"), "_wcslwr_s: %d\n", r);
        r = p_wcsupr_s(NULL, 4);
        ok(r == EINVAL, "_wcsupr_s NULL: %d\n", r);
        wcscpy(wbuf, L"abcd");
        r = p_wcslwr_s(wbuf, 4);
        ok(r == EINVAL && wbuf[0] == 0, "_wcslwr_s unterminated: %d\n", r);
    }
    if (Have("strtok_s", pstrtok_s))
    {
        strcpy(buf, ",a,,bc;d");
        tok = pstrtok_s(buf, ",;", &ctx);
        ok(tok && !strcmp(tok, "a"), "strtok_s 1: %s\n", tok);
        tok = pstrtok_s(NULL, ",;", &ctx);
        ok(tok && !strcmp(tok, "bc"), "strtok_s 2: %s\n", tok);
        tok = pstrtok_s(NULL, ",;", &ctx);
        ok(tok && !strcmp(tok, "d"), "strtok_s 3: %s\n", tok);
        tok = pstrtok_s(NULL, ",;", &ctx);
        ok(tok == NULL, "strtok_s end: %s\n", tok);
        ok(pstrtok_s(buf, NULL, &ctx) == NULL, "strtok_s NULL delim\n");
    }
    if (Have("wcstok_s", pwcstok_s))
    {
        wcscpy(wbuf, L",a,,bc;d");
        wtok = pwcstok_s(wbuf, L",;", &wctx);
        ok(wtok && !wcscmp(wtok, L"a"), "wcstok_s 1\n");
        wtok = pwcstok_s(NULL, L",;", &wctx);
        ok(wtok && !wcscmp(wtok, L"bc"), "wcstok_s 2\n");
        wtok = pwcstok_s(NULL, L",;", &wctx);
        ok(wtok && !wcscmp(wtok, L"d"), "wcstok_s 3\n");
        ok(pwcstok_s(NULL, L",;", &wctx) == NULL, "wcstok_s end\n");
    }
}

static void Test_set(void)
{
    PFN_str_s p_unused = NULL;
    typedef int (__cdecl *PFN_strset_s)(char *, size_t, int);
    typedef int (__cdecl *PFN_strnset_s)(char *, size_t, int, size_t);
    typedef int (__cdecl *PFN_wcsset_s)(WCHAR *, size_t, WCHAR);
    typedef int (__cdecl *PFN_wcsnset_s)(WCHAR *, size_t, WCHAR, size_t);
    PFN_strset_s p_strset_s = (PFN_strset_s)GetProcAddress(Ntdll, "_strset_s");
    PFN_strnset_s p_strnset_s = (PFN_strnset_s)GetProcAddress(Ntdll, "_strnset_s");
    PFN_wcsset_s p_wcsset_s = (PFN_wcsset_s)GetProcAddress(Ntdll, "_wcsset_s");
    PFN_wcsnset_s p_wcsnset_s = (PFN_wcsnset_s)GetProcAddress(Ntdll, "_wcsnset_s");
    char buf[16];
    WCHAR wbuf[16];
    int r;

    (void)p_unused;
    if (Have("_strset_s", p_strset_s) && Have("_strnset_s", p_strnset_s))
    {
        strcpy(buf, "abc");
        r = p_strset_s(buf, sizeof(buf), 'x');
        ok(r == 0 && !strcmp(buf, "xxx"), "_strset_s: %d '%s'\n", r, buf);
        r = p_strset_s(NULL, 4, 'x');
        ok(r == EINVAL, "_strset_s NULL: %d\n", r);
        r = p_strset_s(buf, 0, 'x');
        ok(r == EINVAL, "_strset_s zero size: %d\n", r);
        memset(buf, 'a', 4);
        r = p_strset_s(buf, 4, 'x');
        ok(r == EINVAL && buf[0] == 0, "_strset_s unterminated: %d\n", r);
        strcpy(buf, "abcdef");
        r = p_strnset_s(buf, sizeof(buf), 'x', 2);
        ok(r == 0 && !strcmp(buf, "xxcdef"), "_strnset_s: %d '%s'\n", r, buf);
        strcpy(buf, "ab");
        r = p_strnset_s(buf, sizeof(buf), 'x', 5);
        ok(r == 0 && !strcmp(buf, "xx"), "_strnset_s count beyond string: %d '%s'\n", r, buf);
        r = p_strnset_s(buf, sizeof(buf), 'x', 0);
        ok(r == 0 && !strcmp(buf, "xx"), "_strnset_s zero count: %d '%s'\n", r, buf);
        r = p_strnset_s(NULL, 0, 'x', 0);
        ok(r == 0, "_strnset_s all empty: %d\n", r);
        r = p_strnset_s(NULL, 4, 'x', 1);
        ok(r == EINVAL, "_strnset_s NULL: %d\n", r);
    }
    if (Have("_wcsset_s", p_wcsset_s) && Have("_wcsnset_s", p_wcsnset_s))
    {
        wcscpy(wbuf, L"abc");
        r = p_wcsset_s(wbuf, 16, L'x');
        ok(r == 0 && !wcscmp(wbuf, L"xxx"), "_wcsset_s: %d\n", r);
        r = p_wcsset_s(NULL, 4, L'x');
        ok(r == EINVAL, "_wcsset_s NULL: %d\n", r);
        wcscpy(wbuf, L"abcdef");
        r = p_wcsnset_s(wbuf, 16, L'x', 2);
        ok(r == 0 && !wcscmp(wbuf, L"xxcdef"), "_wcsnset_s: %d\n", r);
    }
}

static void Test_numbers(void)
{
    PFN_i64toa_s p_i64toa_s = (PFN_i64toa_s)GetProcAddress(Ntdll, "_i64toa_s");
    PFN_ui64toa_s p_ui64toa_s = (PFN_ui64toa_s)GetProcAddress(Ntdll, "_ui64toa_s");
    PFN_itoa_s p_itoa_s = (PFN_itoa_s)GetProcAddress(Ntdll, "_itoa_s");
    PFN_ltoa_s p_ltoa_s = (PFN_ltoa_s)GetProcAddress(Ntdll, "_ltoa_s");
    PFN_ultoa_s p_ultoa_s = (PFN_ultoa_s)GetProcAddress(Ntdll, "_ultoa_s");
    PFN_i64tow_s p_i64tow_s = (PFN_i64tow_s)GetProcAddress(Ntdll, "_i64tow_s");
    PFN_ui64tow_s p_ui64tow_s = (PFN_ui64tow_s)GetProcAddress(Ntdll, "_ui64tow_s");
    PFN_itow_s p_itow_s = (PFN_itow_s)GetProcAddress(Ntdll, "_itow_s");
    PFN_ltow_s p_ltow_s = (PFN_ltow_s)GetProcAddress(Ntdll, "_ltow_s");
    PFN_ultow_s p_ultow_s = (PFN_ultow_s)GetProcAddress(Ntdll, "_ultow_s");
    PFN_wcstoi64 p_wcstoi64 = (PFN_wcstoi64)GetProcAddress(Ntdll, "_wcstoi64");
    char buf[70];
    WCHAR wbuf[70], *end;
    int r;

    if (Have("_i64toa_s", p_i64toa_s) && Have("_ui64toa_s", p_ui64toa_s) && Have("_itoa_s", p_itoa_s) &&
        Have("_ltoa_s", p_ltoa_s) && Have("_ultoa_s", p_ultoa_s))
    {
        r = p_i64toa_s(-1234567890123LL, buf, sizeof(buf), 10);
        ok(r == 0 && !strcmp(buf, "-1234567890123"), "_i64toa_s: %d '%s'\n", r, buf);
        r = p_i64toa_s(-255, buf, sizeof(buf), 16);
        ok(r == 0 && !strcmp(buf, "ffffffffffffff01"), "_i64toa_s -255 base 16: %d '%s'\n", r, buf);
        r = p_ui64toa_s(0xfedcba9876543210ULL, buf, sizeof(buf), 16);
        ok(r == 0 && !strcmp(buf, "fedcba9876543210"), "_ui64toa_s: %d '%s'\n", r, buf);
        r = p_ui64toa_s(35, buf, sizeof(buf), 36);
        ok(r == 0 && !strcmp(buf, "z"), "_ui64toa_s base 36: %d '%s'\n", r, buf);
        r = p_itoa_s(-42, buf, sizeof(buf), 10);
        ok(r == 0 && !strcmp(buf, "-42"), "_itoa_s: %d '%s'\n", r, buf);
        r = p_itoa_s(-1, buf, sizeof(buf), 16);
        ok(r == 0 && !strcmp(buf, "ffffffff"), "_itoa_s -1 base 16: %d '%s'\n", r, buf);
        r = p_ltoa_s(-7, buf, sizeof(buf), 2);
        ok(r == 0 && !strcmp(buf, "11111111111111111111111111111001"), "_ltoa_s: %d '%s'\n", r, buf);
        r = p_ultoa_s(4000000000UL, buf, sizeof(buf), 10);
        ok(r == 0 && !strcmp(buf, "4000000000"), "_ultoa_s: %d '%s'\n", r, buf);
        r = p_itoa_s(12345, buf, 5, 10);
        ok(r == ERANGE && buf[0] == 0, "_itoa_s overflow: %d '%s'\n", r, buf);
        r = p_itoa_s(12345, buf, 6, 10);
        ok(r == 0 && !strcmp(buf, "12345"), "_itoa_s exact fit: %d '%s'\n", r, buf);
        r = p_itoa_s(1, buf, sizeof(buf), 1);
        ok(r == EINVAL && buf[0] == 0, "_itoa_s radix 1: %d '%s'\n", r, buf);
        r = p_itoa_s(1, buf, sizeof(buf), 37);
        ok(r == EINVAL, "_itoa_s radix 37: %d\n", r);
        r = p_ui64toa_s(12345, buf, 5, 10);
        ok(r == ERANGE && buf[0] == 0, "_ui64toa_s overflow: %d '%s'\n", r, buf);
        r = p_ui64toa_s(1, buf, sizeof(buf), 1);
        ok(r == EINVAL && buf[0] == 0, "_ui64toa_s radix 1: %d '%s'\n", r, buf);
        r = p_itoa_s(1, NULL, 10, 10);
        ok(r == EINVAL, "_itoa_s NULL: %d\n", r);
        r = p_itoa_s(1, buf, 0, 10);
        ok(r == EINVAL, "_itoa_s size 0: %d\n", r);
    }
    if (Have("_i64tow_s", p_i64tow_s) && Have("_ui64tow_s", p_ui64tow_s) && Have("_itow_s", p_itow_s) &&
        Have("_ltow_s", p_ltow_s) && Have("_ultow_s", p_ultow_s))
    {
        r = p_i64tow_s(-1234567890123LL, wbuf, 70, 10);
        ok(r == 0 && !wcscmp(wbuf, L"-1234567890123"), "_i64tow_s: %d\n", r);
        r = p_ui64tow_s(0xfedcba9876543210ULL, wbuf, 70, 16);
        ok(r == 0 && !wcscmp(wbuf, L"fedcba9876543210"), "_ui64tow_s: %d\n", r);
        r = p_itow_s(-42, wbuf, 70, 10);
        ok(r == 0 && !wcscmp(wbuf, L"-42"), "_itow_s: %d\n", r);
        r = p_ltow_s(-7, wbuf, 70, 16);
        ok(r == 0 && !wcscmp(wbuf, L"fffffff9"), "_ltow_s: %d\n", r);
        r = p_ultow_s(4000000000UL, wbuf, 70, 10);
        ok(r == 0 && !wcscmp(wbuf, L"4000000000"), "_ultow_s: %d\n", r);
        r = p_itow_s(12345, wbuf, 5, 10);
        ok(r == ERANGE && wbuf[0] == 0, "_itow_s overflow: %d\n", r);
        r = p_ui64tow_s(12345, wbuf, 5, 10);
        ok(r == ERANGE && wbuf[0] == 0, "_ui64tow_s overflow: %d\n", r);
        r = p_ui64tow_s(1, wbuf, 70, 1);
        ok(r == EINVAL && wbuf[0] == 0, "_ui64tow_s radix 1: %d\n", r);
        r = p_itow_s(1, wbuf, 70, 40);
        ok(r == EINVAL, "_itow_s radix 40: %d\n", r);
    }
    if (Have("_wcstoi64", p_wcstoi64))
    {
        ok(p_wcstoi64(L"  -123abc", &end, 10) == -123 && !wcscmp(end, L"abc"), "_wcstoi64 decimal\n");
        ok(p_wcstoi64(L"0x1f", &end, 0) == 31 && !*end, "_wcstoi64 hex\n");
        ok(p_wcstoi64(L"010", &end, 0) == 8, "_wcstoi64 octal\n");
        ok(p_wcstoi64(L"9223372036854775808", &end, 10) == 0x7fffffffffffffffLL, "_wcstoi64 overflow\n");
        ok(p_wcstoi64(L"-9223372036854775809", &end, 10) == (-0x7fffffffffffffffLL - 1), "_wcstoi64 underflow\n");
        ok(p_wcstoi64(L"zz", &end, 10) == 0 && !wcscmp(end, L"zz"), "_wcstoi64 no digits\n");
    }
}

static void Test_paths(void)
{
    PFN_splitpath_s p_splitpath_s = (PFN_splitpath_s)GetProcAddress(Ntdll, "_splitpath_s");
    PFN_wsplitpath_s p_wsplitpath_s = (PFN_wsplitpath_s)GetProcAddress(Ntdll, "_wsplitpath_s");
    PFN_makepath_s p_makepath_s = (PFN_makepath_s)GetProcAddress(Ntdll, "_makepath_s");
    PFN_wmakepath_s p_wmakepath_s = (PFN_wmakepath_s)GetProcAddress(Ntdll, "_wmakepath_s");
    char d[8], dir[32], f[16], e[8], path[64];
    WCHAR wd[8], wdir[32], wf[16], we[8], wpath[64];
    int r;

    if (Have("_splitpath_s", p_splitpath_s))
    {
        r = p_splitpath_s("C:\\dir\\sub/name.ext", d, 8, dir, 32, f, 16, e, 8);
        ok(r == 0 && !strcmp(d, "C:") && !strcmp(dir, "\\dir\\sub/") && !strcmp(f, "name") && !strcmp(e, ".ext"),
           "_splitpath_s: %d '%s' '%s' '%s' '%s'\n", r, d, dir, f, e);
        r = p_splitpath_s("name", d, 8, dir, 32, f, 16, e, 8);
        ok(r == 0 && !d[0] && !dir[0] && !strcmp(f, "name") && !e[0], "_splitpath_s bare name: %d\n", r);
        r = p_splitpath_s("a.b.c", NULL, 0, NULL, 0, f, 16, e, 8);
        ok(r == 0 && !strcmp(f, "a.b") && !strcmp(e, ".c"), "_splitpath_s last dot: %d\n", r);
        r = p_splitpath_s("C:\\verylongname.ext", d, 8, dir, 32, f, 4, e, 8);
        ok(r == ERANGE && !f[0] && !d[0], "_splitpath_s small buffer: %d\n", r);
        r = p_splitpath_s(NULL, d, 8, dir, 32, f, 16, e, 8);
        ok(r == EINVAL, "_splitpath_s NULL path: %d\n", r);
        r = p_splitpath_s("x", NULL, 8, dir, 32, f, 16, e, 8);
        ok(r == EINVAL, "_splitpath_s NULL buffer with size: %d\n", r);
    }
    if (Have("_wsplitpath_s", p_wsplitpath_s))
    {
        r = p_wsplitpath_s(L"C:\\dir\\sub/name.ext", wd, 8, wdir, 32, wf, 16, we, 8);
        ok(r == 0 && !wcscmp(wd, L"C:") && !wcscmp(wdir, L"\\dir\\sub/") && !wcscmp(wf, L"name") && !wcscmp(we, L".ext"),
           "_wsplitpath_s: %d\n", r);
        r = p_wsplitpath_s(L"C:\\verylongname.ext", wd, 8, wdir, 32, wf, 4, we, 8);
        ok(r == ERANGE && !wf[0], "_wsplitpath_s small buffer: %d\n", r);
    }
    if (Have("_makepath_s", p_makepath_s))
    {
        r = p_makepath_s(path, 64, "C", "dir\\sub", "name", "ext");
        ok(r == 0 && !strcmp(path, "C:dir\\sub\\name.ext"), "_makepath_s: %d '%s'\n", r, path);
        r = p_makepath_s(path, 64, NULL, "dir/", "name", ".ext");
        ok(r == 0 && !strcmp(path, "dir/name.ext"), "_makepath_s trailing sep: %d '%s'\n", r, path);
        r = p_makepath_s(path, 5, "C", "dir", "name", "ext");
        ok(r == ERANGE && !path[0], "_makepath_s small buffer: %d '%s'\n", r, path);
        r = p_makepath_s(NULL, 5, "C", "dir", "name", "ext");
        ok(r == EINVAL, "_makepath_s NULL: %d\n", r);
    }
    if (Have("_wmakepath_s", p_wmakepath_s))
    {
        r = p_wmakepath_s(wpath, 64, L"C", L"dir\\sub", L"name", L"ext");
        ok(r == 0 && !wcscmp(wpath, L"C:dir\\sub\\name.ext"), "_wmakepath_s: %d\n", r);
        r = p_wmakepath_s(wpath, 5, L"C", L"dir", L"name", L"ext");
        ok(r == ERANGE && !wpath[0], "_wmakepath_s small buffer: %d\n", r);
    }
}

static void Test_wctype(void)
{
    PFN_isw pisw[4];
    static const char *Names[4] = { "iswalnum", "iswascii", "iswgraph", "iswprint" };
    int i;

    for (i = 0; i < 4; i++)
    {
        pisw[i] = (PFN_isw)GetProcAddress(Ntdll, Names[i]);
        if (!Have(Names[i], pisw[i])) return;
    }
    ok(pisw[0]('a') && pisw[0]('Z') && pisw[0]('5') && !pisw[0]('-') && !pisw[0](' '), "iswalnum\n");
    ok(pisw[1]('a') && pisw[1](0x7f) && !pisw[1](0x80) && !pisw[1](0x3b1), "iswascii\n");
    ok(pisw[2]('a') && pisw[2]('-') && !pisw[2](' ') && !pisw[2]('\n'), "iswgraph\n");
    ok(pisw[3]('a') && pisw[3]('-') && pisw[3](' ') && !pisw[3]('\n') && !pisw[3](0x7), "iswprint\n");
}

static void Test_sort(void)
{
    GET(qsort_s); GET(bsearch_s);
    int a[11] = { 9, 3, 7, 1, 8, 2, 6, 4, 10, 5, 0 };
    int calls, key, i;
    int *found;

    if (Have("qsort_s", pqsort_s) && Have("bsearch_s", pbsearch_s))
    {
        calls = 0;
        pqsort_s(a, 11, sizeof(int), cmp_int_ctx, &calls);
        for (i = 0; i < 11; i++)
            ok(a[i] == i, "qsort_s: a[%d] = %d\n", i, a[i]);
        ok(calls > 0, "the context was not passed to the comparison function\n");
        calls = 0;
        key = 7;
        found = pbsearch_s(&key, a, 11, sizeof(int), cmp_int_ctx, &calls);
        ok(found == &a[7] && calls > 0, "bsearch_s: %p calls %d\n", found, calls);
        key = 70;
        found = pbsearch_s(&key, a, 11, sizeof(int), cmp_int_ctx, &calls);
        ok(found == NULL, "bsearch_s missing key: %p\n", found);
        found = pbsearch_s(&key, a, 11, 0, cmp_int_ctx, &calls);
        ok(found == NULL, "bsearch_s zero size: %p\n", found);
    }
}

static int __cdecl CallVsnprintfS(PFN_vsnprintf_s Pfn, char *Buf, size_t Size, size_t Len, const char *Fmt, ...)
{
    va_list args;
    int r;

    va_start(args, Fmt);
    r = Pfn(Buf, Size, Len, Fmt, args);
    va_end(args);
    return r;
}

static int __cdecl CallVscprintf(PFN_vscprintf Pfn, const char *Fmt, ...)
{
    va_list args;
    int r;

    va_start(args, Fmt);
    r = Pfn(Fmt, args);
    va_end(args);
    return r;
}

static void Test_printf(void)
{
    GET(sprintf_s); GET(swprintf_s);
    PFN_snprintf_s p_snprintf_s = (PFN_snprintf_s)GetProcAddress(Ntdll, "_snprintf_s");
    PFN_snwprintf_s p_snwprintf_s = (PFN_snwprintf_s)GetProcAddress(Ntdll, "_snwprintf_s");
    PFN_vsnprintf_s p_vsnprintf_s = (PFN_vsnprintf_s)GetProcAddress(Ntdll, "_vsnprintf_s");
    PFN_vscprintf p_vscprintf = (PFN_vscprintf)GetProcAddress(Ntdll, "_vscprintf");
    char buf[16];
    WCHAR wbuf[16];
    int r;

    if (Have("sprintf_s", psprintf_s))
    {
        memset(buf, 'x', sizeof(buf));
        r = psprintf_s(buf, sizeof(buf), "%d-%s", 42, "ab");
        ok(r == 5 && !strcmp(buf, "42-ab"), "sprintf_s: %d '%s'\n", r, buf);
        memset(buf, 'x', sizeof(buf));
        r = psprintf_s(buf, 5, "%s", "abcdef");
        ok(r == -1 && buf[0] == 0, "sprintf_s overflow: %d '%s'\n", r, buf);
        memset(buf, 'x', sizeof(buf));
        r = psprintf_s(buf, 5, "%s", "abcd");
        ok(r == 4 && !strcmp(buf, "abcd"), "sprintf_s exact fit: %d '%s'\n", r, buf);
        r = psprintf_s(buf, 4, "%s", "abcd");
        ok(r == -1 && buf[0] == 0, "sprintf_s needs the terminator: %d '%s'\n", r, buf);
    }
    if (Have("swprintf_s", pswprintf_s))
    {
        r = pswprintf_s(wbuf, 16, L"%d-%s", 42, L"ab");
        ok(r == 5 && !wcscmp(wbuf, L"42-ab"), "swprintf_s: %d\n", r);
        r = pswprintf_s(wbuf, 3, L"%s", L"abcdef");
        ok(r == -1 && wbuf[0] == 0, "swprintf_s overflow: %d\n", r);
    }
    if (Have("_snprintf_s", p_snprintf_s))
    {
        memset(buf, 'x', sizeof(buf));
        r = p_snprintf_s(buf, sizeof(buf), 3, "%s", "abcdef");
        ok(r == -1 && !strcmp(buf, "abc"), "_snprintf_s count: %d '%s'\n", r, buf);
        memset(buf, 'x', sizeof(buf));
        r = p_snprintf_s(buf, 4, _TRUNCATE, "%s", "abcdef");
        ok(r == -1 && !strcmp(buf, "abc"), "_snprintf_s truncate: %d '%s'\n", r, buf);
        memset(buf, 'x', sizeof(buf));
        r = p_snprintf_s(buf, 8, 5, "%s", "abc");
        ok(r == 3 && !strcmp(buf, "abc"), "_snprintf_s fits: %d '%s'\n", r, buf);
        memset(buf, 'x', sizeof(buf));
        r = p_snprintf_s(buf, 4, 8, "%s", "abcdef");
        ok(r == -1 && buf[0] == 0, "_snprintf_s size overflow: %d '%s'\n", r, buf);
    }
    if (Have("_snwprintf_s", p_snwprintf_s))
    {
        r = p_snwprintf_s(wbuf, 16, 3, L"%s", L"abcdef");
        ok(r == -1 && !wcscmp(wbuf, L"abc"), "_snwprintf_s count: %d\n", r);
    }
    if (Have("_vsnprintf_s", p_vsnprintf_s))
    {
        r = CallVsnprintfS(p_vsnprintf_s, buf, sizeof(buf), sizeof(buf), "%d", 1234);
        ok(r == 4 && !strcmp(buf, "1234"), "_vsnprintf_s: %d '%s'\n", r, buf);
    }
    if (Have("_vscprintf", p_vscprintf))
    {
        r = CallVscprintf(p_vscprintf, "%s=%d", "abc", 12);
        ok(r == 6, "_vscprintf: %d\n", r);
    }
}

START_TEST(CrtSecure)
{
    Ntdll = GetModuleHandleW(L"ntdll.dll");
    Test_string();
    Test_case_tok();
    Test_set();
    Test_numbers();
    Test_paths();
    Test_wctype();
    Test_sort();
    Test_printf();
}
