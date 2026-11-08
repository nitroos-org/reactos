/*
 * lcprobe: read-only locale dump for the nlscldr parity report.
 * Calls only GetLocaleInfoEx, GetDateFormatEx, GetTimeFormatEx, GetNumberFormatEx, GetCurrencyFormatEx,
 * GetCalendarInfoEx, CompareStringEx and prints ASCII (non-ASCII as \uXXXX). It writes nothing but stdout.
 * Build: x86_64-w64-mingw32-gcc -O1 -D_WIN32_WINNT=0x0601 -static -o lcprobe.exe lcprobe.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const WCHAR *g_loc;

static void esc(const WCHAR *s, int n)
{
    int i;
    putchar('"');
    for (i = 0; i < n; i++)
    {
        WCHAR c = s[i];
        if (c == '\\') printf("\\\\");
        else if (c == '"') printf("\\\"");
        else if (c >= 0x20 && c < 0x7f) putchar((char)c);
        else printf("\\u%04X", c);
    }
    putchar('"');
}

static void lstr(const WCHAR *s) { esc(s, (int)wcslen(s)); }

static int cmpw(const void *a, const void *b)
{
    const WCHAR *x = *(const WCHAR * const *)a, *y = *(const WCHAR * const *)b;
    return CompareStringEx(g_loc, 0, x, -1, y, -1, NULL, NULL, 0) - 2;
}

static const WCHAR *words[] = {
    L"a", L"A", L"b", L"c", L"C", L"ch", L"cz", L"d", L"e", L"E", L"f", L"h", L"i", L"n", L"o", L"s", L"ss", L"t", L"z", L"Z",
    L"\x00e4", L"\x00c4", L"\x00e9", L"\x00e8", L"\x00f1", L"\x00f6", L"\x00df", L"\x010d", L"\x0159", L"\x0161", L"\x017e",
    L"1", L"2", L"10", L"-a", L"a-b", L"ab", L"a b",
    L"\x0430", L"\x0431", L"\x0436", L"\x044f", L"\x3042", L"\x30a2", L"\x6f22", L"\x5b57", L"\x0627", L"\x0628", L"\x062a"
};

int wmain(int argc, WCHAR **argv)
{
    static const WCHAR *locs[] = { L"en-US", L"en-GB", L"cs-CZ", L"de-DE", L"fr-FR", L"es-ES", L"ja-JP", L"zh-CN", L"ru-RU", L"ar-SA" };
    unsigned li, t, i;
    SYSTEMTIME st = { 2026, 3, 3, 4, 13, 5, 9, 7 };   /* Wednesday 2026-03-04 13:05:09.007 */
    SYSTEMTIME st2 = { 2026, 11, 0, 25, 0, 30, 0, 0 }; /* 25 Nov 2026, 00:30 */
    SYSTEMTIME *sts[2] = { &st, &st2 };
    static const WCHAR *numtests[] = { L"1234567.891", L"-1234.5", L"0.5", L"1000000" };

    printf("lcprobe 1\n");
    for (li = 0; li < sizeof(locs) / sizeof(locs[0]); li++)
    {
        const WCHAR *loc = locs[li];
        WCHAR buf[1024];
        int n;
        g_loc = loc;
        printf("== ");
        lstr(loc);
        printf("\n");
        for (t = 0; t < 0x100; t++)
        {
            DWORD flags[2] = { 0, LOCALE_RETURN_GENITIVE_NAMES };
            int f;
            for (f = 0; f < 2; f++)
            {
                if (f && !((t >= 0x38 && t <= 0x44) || (t >= 0x57 && t <= 0x63))) continue;   /* month names only */
                SetLastError(0);
                n = GetLocaleInfoEx(loc, t | flags[f], buf, 1024);
                if (!n) continue;
                printf("LI %s0x%04x ", f ? "G" : "", t);
                esc(buf, n - 1);
                printf("\n");
            }
        }
        for (i = 0; i < 2; i++)
        {
            static const struct { DWORD fl; const char *nm; } df[] = { {0, "def"}, {DATE_SHORTDATE, "short"}, {DATE_LONGDATE, "long"}, {DATE_YEARMONTH, "ym"}, {0x80, "md"} };
            static const struct { DWORD fl; const char *nm; } tf[] = { {0, "def"}, {TIME_NOSECONDS, "nosec"}, {TIME_FORCE24HOURFORMAT, "h24"}, {TIME_NOMINUTESORSECONDS, "h"} };
            unsigned k;
            for (k = 0; k < 5; k++)
            {
                n = GetDateFormatEx(loc, df[k].fl, sts[i], NULL, buf, 1024, NULL);
                printf("DATE%u %s ", i, df[k].nm);
                if (n) esc(buf, n - 1); else printf("ERR%lu", GetLastError());
                printf("\n");
            }
            n = GetDateFormatEx(loc, 0, sts[i], L"dddd d MMMM yyyy ddd d MMM yy gg", buf, 1024, NULL);
            printf("DATE%u custom ", i);
            if (n) esc(buf, n - 1); else printf("ERR%lu", GetLastError());
            printf("\n");
            for (k = 0; k < 4; k++)
            {
                n = GetTimeFormatEx(loc, tf[k].fl, sts[i], NULL, buf, 1024);
                printf("TIME%u %s ", i, tf[k].nm);
                if (n) esc(buf, n - 1); else printf("ERR%lu", GetLastError());
                printf("\n");
            }
        }
        for (i = 0; i < sizeof(numtests) / sizeof(numtests[0]); i++)
        {
            n = GetNumberFormatEx(loc, 0, numtests[i], NULL, buf, 1024);
            printf("NUM %u ", i);
            if (n) esc(buf, n - 1); else printf("ERR%lu", GetLastError());
            printf("\n");
            n = GetCurrencyFormatEx(loc, 0, numtests[i], NULL, buf, 1024);
            printf("CUR %u ", i);
            if (n) esc(buf, n - 1); else printf("ERR%lu", GetLastError());
            printf("\n");
        }
        {
            DWORD cal = 0;
            CALID c;
            if (GetLocaleInfoEx(loc, LOCALE_ICALENDARTYPE | LOCALE_RETURN_NUMBER, (LPWSTR)&cal, 2))
            {
                for (c = 1; c <= 23; c++)
                {
                    n = GetCalendarInfoEx(loc, c, NULL, CAL_SCALNAME, buf, 1024, NULL);
                    if (n) { printf("CAL %lu name ", (unsigned long)c); esc(buf, n - 1); printf("\n"); }
                }
            }
        }
        {
            const WCHAR *sorted[sizeof(words) / sizeof(words[0])];
            unsigned nw = sizeof(words) / sizeof(words[0]);
            memcpy(sorted, words, sizeof(words));
            qsort(sorted, nw, sizeof(sorted[0]), cmpw);
            printf("SORT");
            for (i = 0; i < nw; i++) { printf(" "); lstr(sorted[i]); }
            printf("\n");
        }
    }
    return 0;
}
