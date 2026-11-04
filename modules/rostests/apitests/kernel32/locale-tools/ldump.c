/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ldump
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* ldump: dump locale/calendar data via the public NLS API, one line per value, for oracle-vs-nitro diffing.
 * Build: x86_64-w64-mingw32-gcc -O1 -o ldump.exe ldump.c   (system mingw; not the RosBE cross compiler)
 * Usage: ldump [-o file] [locale...]   (default: the representative set) */
#define WINVER 0x0601
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef LOCALE_RETURN_NUMBER
#define LOCALE_RETURN_NUMBER 0x20000000
#endif
#ifndef CAL_RETURN_NUMBER
#define CAL_RETURN_NUMBER 0x20000000
#endif
#ifndef CAL_NOUSEROVERRIDE
#define CAL_NOUSEROVERRIDE LOCALE_NOUSEROVERRIDE
#endif

static FILE *out;
typedef BOOL (CALLBACK *CALINFOENUMPROCEXEX_)(LPWSTR, CALID, LPWSTR, LPARAM);
typedef BOOL (CALLBACK *DATEFMTENUMPROCEXEX_)(LPWSTR, CALID, LPARAM);
typedef BOOL (CALLBACK *TIMEFMTENUMPROCEX_)(LPWSTR, LPARAM);
static int (WINAPI *pGetLocaleInfoEx)(LPCWSTR, LCTYPE, LPWSTR, int);
static int (WINAPI *pGetCalendarInfoEx)(LPCWSTR, CALID, LPCWSTR, CALTYPE, LPWSTR, int, LPDWORD);
static BOOL (WINAPI *pEnumCalendarInfoExEx)(CALINFOENUMPROCEXEX_, LPCWSTR, CALID, LPCWSTR, CALTYPE, LPARAM);
static BOOL (WINAPI *pEnumDateFormatsExEx)(DATEFMTENUMPROCEXEX_, LPCWSTR, DWORD, LPARAM);
static BOOL (WINAPI *pEnumTimeFormatsEx)(TIMEFMTENUMPROCEX_, LPCWSTR, DWORD, LPARAM);
static int (WINAPI *pGetUserDefaultLocaleName)(LPWSTR, int);
static int (WINAPI *pGetSystemDefaultLocaleName)(LPWSTR, int);
static LCID (WINAPI *pLocaleNameToLCID)(LPCWSTR, DWORD);
static int (WINAPI *pLCIDToLocaleName)(LCID, LPWSTR, int, DWORD);
static int (WINAPI *pResolveLocaleName)(LPCWSTR, LPWSTR, int);
static BOOL (WINAPI *pIsValidLocaleName)(LPCWSTR);
static BOOL (WINAPI *pEnumSystemLocalesEx)(BOOL (CALLBACK *)(LPWSTR, DWORD, LPARAM), DWORD, LPARAM, LPVOID);

static void esc(const WCHAR *s, char *d)
{
    for (; *s; s++)
    {
        if (*s >= 0x20 && *s < 0x7f && *s != '\\') *d++ = (char)*s;
        else d += sprintf(d, "\\u%04x", *s);
    }
    *d = 0;
}
/* escape a counted string (embedded NULs shown as \u0000), n = number of chars without the terminator */
static char *EN(const WCHAR *s, int n)
{
    static char b[4][8192];
    static int i;
    char *r = b[i++ & 3], *d = r;
    for (; n > 0; n--, s++)
    {
        if (*s >= 0x20 && *s < 0x7f && *s != '\\') *d++ = (char)*s;
        else d += sprintf(d, "\\u%04x", *s);
    }
    *d = 0;
    return r;
}
static char *E(const WCHAR *s)
{
    static char b[8][4096];
    static int i;
    char *r = b[i++ & 7];
    esc(s, r);
    return r;
}

static const char *g_namefile;
static WCHAR g_name[64];
static CALID g_cals[32];
static int g_ncals;

static BOOL CALLBACK enum_cals(LPWSTR s, CALID id, LPWSTR r, LPARAM p)
{
    if (g_ncals < 32) g_cals[g_ncals++] = id;
    return TRUE;
}
struct enumctx { const char *tag; int n; };
static BOOL CALLBACK enum_cal_cb(LPWSTR s, CALID id, LPWSTR r, LPARAM p)
{
    struct enumctx *c = (struct enumctx *)p;
    fprintf(out, "ECI\t%ls\t%s\t%u\t%d\t%s\t%s\n", g_name, c->tag, (unsigned)id, c->n++, E(s), r ? E(r) : "(null)");
    return TRUE;
}
static BOOL CALLBACK enum_date_cb(LPWSTR s, CALID id, LPARAM p)
{
    struct enumctx *c = (struct enumctx *)p;
    fprintf(out, "EDF\t%ls\t%s\t%u\t%d\t%s\n", g_name, c->tag, (unsigned)id, c->n++, E(s));
    return TRUE;
}
static BOOL CALLBACK enum_time_cb(LPWSTR s, LPARAM p)
{
    struct enumctx *c = (struct enumctx *)p;
    fprintf(out, "ETF\t%ls\t%s\t%d\t%s\n", g_name, c->tag, c->n++, E(s));
    return TRUE;
}

static void dump_locale(const WCHAR *name)
{
    WCHAR buf[1024];
    int t, i, ret;
    DWORD num;
    static const int ranges[][2] = { {0, 0x80}, {0x1000, 0x1020} };
    int rg;
    lstrcpynW(g_name, name, 64);
    fprintf(out, "VALID\t%ls\t%d\n", name, pIsValidLocaleName ? pIsValidLocaleName(name) : -1);
    for (rg = 0; rg < 2; rg++)
    for (t = ranges[rg][0]; t < ranges[rg][1]; t++)
    {
        if (t == 0x1000) continue;
        SetLastError(0);
        buf[0] = 0;
        ret = pGetLocaleInfoEx(name, t | LOCALE_NOUSEROVERRIDE, buf, 1024);
        if (ret > 0)
            fprintf(out, "LI\t%ls\t0x%x\t%d\t%s\n", name, t, ret, EN(buf, ret - 1));
        else
        {
            DWORD e = GetLastError();
            if (e != ERROR_INVALID_FLAGS && e != ERROR_INVALID_PARAMETER)
                fprintf(out, "LI\t%ls\t0x%x\tERR\t%lu\n", name, t, e);
        }
        if ((t >= 0x38 && t <= 0x43) || (t >= 0x44 && t <= 0x4f) || t == 0x100e || t == 0x100f)
        {
            buf[0] = 0;
            ret = pGetLocaleInfoEx(name, t | 0x10000000 /*LOCALE_RETURN_GENITIVE_NAMES*/ | LOCALE_NOUSEROVERRIDE, buf, 1024);
            if (ret > 0) fprintf(out, "LG\t%ls\t0x%x\t%d\t%s\n", name, t, ret, E(buf));
        }
        num = 0xdead;
        SetLastError(0);
        ret = pGetLocaleInfoEx(name, t | LOCALE_RETURN_NUMBER | LOCALE_NOUSEROVERRIDE, (LPWSTR)&num, 2);
        if (ret == 2)
            fprintf(out, "LN\t%ls\t0x%x\t%lu\n", name, t, (unsigned long)num);
    }

    /* supported calendars, as .NET enumerates them */
    g_ncals = 0;
    if (pEnumCalendarInfoExEx)
        pEnumCalendarInfoExEx(enum_cals, name, ENUM_ALL_CALENDARS, NULL, CAL_ICALINTVALUE, 0);
    fprintf(out, "CALS\t%ls\t", name);
    for (i = 0; i < g_ncals; i++) fprintf(out, "%s%u", i ? "," : "", (unsigned)g_cals[i]);
    fprintf(out, "\n");

    for (i = 0; i < g_ncals; i++)
    {
        CALID cal = g_cals[i];
        for (t = 1; t <= 58; t++)
        {
            SetLastError(0);
            buf[0] = 0;
            ret = pGetCalendarInfoEx(name, cal, NULL, t | CAL_NOUSEROVERRIDE, buf, 1024, NULL);
            if (ret > 0)
                fprintf(out, "CI\t%ls\t%u\t%d\t%d\t%s\n", name, (unsigned)cal, t, ret, E(buf));
            else
                fprintf(out, "CI\t%ls\t%u\t%d\tERR\t%lu\n", name, (unsigned)cal, t, GetLastError());
            num = 0xdead;
            SetLastError(0);
            if (t == 1 || t == 3 || t == 48)
            ret = pGetCalendarInfoEx(name, cal, NULL, t | CAL_RETURN_NUMBER | CAL_NOUSEROVERRIDE, NULL, 0, &num);
            else ret = 0;
            if (ret > 0)
                fprintf(out, "CN\t%ls\t%u\t%d\t%lu\n", name, (unsigned)cal, t, (unsigned long)num);
        }
        {
            static const struct { const char *tag; int t; } et[] = {
                {"SERASTRING", 4}, {"SABBREVERASTRING", 57}, {"SSHORTDATE", 5}, {"SLONGDATE", 6},
                {"SYEARMONTH", 47}, {"IYEAROFFSETRANGE", 3}, {"SCALNAME", 2}, {"SMONTHDAY", 56},
            };
            int k;
            for (k = 0; k < (int)(sizeof(et) / sizeof(et[0])); k++)
            {
                struct enumctx c; c.tag = et[k].tag; c.n = 0;
                SetLastError(0);
                if (!pEnumCalendarInfoExEx(enum_cal_cb, name, cal, NULL, et[k].t, (LPARAM)&c))
                    fprintf(out, "ECI\t%ls\t%s\t%u\tERR\t%lu\n", name, et[k].tag, (unsigned)cal, GetLastError());
            }
        }
    }
    {
        static const struct { const char *tag; DWORD f; } df[] = {
            {"SHORT", DATE_SHORTDATE}, {"LONG", DATE_LONGDATE}, {"YEARMONTH", DATE_YEARMONTH},
        };
        int k;
        for (k = 0; k < 3; k++)
        {
            struct enumctx c; c.tag = df[k].tag; c.n = 0;
            SetLastError(0);
            if (!pEnumDateFormatsExEx(enum_date_cb, name, df[k].f, (LPARAM)&c))
                fprintf(out, "EDF\t%ls\t%s\tERR\t%lu\n", name, df[k].tag, GetLastError());
        }
        {
            struct enumctx c; c.tag = "TIME"; c.n = 0;
            if (!pEnumTimeFormatsEx(enum_time_cb, name, 0, (LPARAM)&c))
                fprintf(out, "ETF\t%ls\tTIME\tERR\t%lu\n", name, GetLastError());
        }
    }
}

static const WCHAR *defset[] = {
    L"en-US", L"de-DE", L"fr-FR", L"es-ES", L"it-IT", L"ja-JP", L"zh-CN", L"zh-TW", L"ko-KR", L"ru-RU", L"pl-PL",
    L"cs-CZ", L"pt-BR", L"en-GB", L"ar-SA", L"he-IL", L"th-TH", L"tr-TR", L"sv-SE", L"nl-NL", L"hi-IN",
    /* neutral and script-tagged names */
    L"zh-Hans", L"zh-Hant", L"zh", L"de", L"en", L"fr", L"zh-HK", L"zh-SG", L"zh-MO", L"zh-CHS", L"zh-CHT",
    L"sr-Latn-RS", L"sr-Cyrl-RS", L"", NULL
};
static const WCHAR *nameset[] = {
    L"en-US", L"zh-Hans", L"zh-Hant", L"zh-CN", L"zh-TW", L"zh-HK", L"zh-SG", L"zh-MO", L"zh", L"zh-CHS", L"zh-CHT",
    L"zh-Hans-CN", L"zh-Hant-TW", L"zh-Hans-HK", L"zh-Hant-HK", L"de", L"de-DE", L"en", L"sr-Latn-RS", L"sr-Cyrl-RS",
    L"invariant", L"", L"xx-XX", L"es-ES_tradnl", L"pt-PT", L"nb-NO", L"nn-NO", L"no", NULL
};
static const LCID lcidset[] = { 0x0409, 0x0407, 0x0804, 0x0004, 0x7c04, 0x0404, 0x7804, 0x0c04, 0x1004, 0x1404, 0x0c0a, 0x040a,
    0x0127, 0x007f, 0x0000, 0x0800, 0x0400, 0x0414, 0x7c1a, 0x2c1a, 0x081a, 0x0c1a };

static BOOL CALLBACK enum_all_names(LPWSTR name, DWORD flags, LPARAM p)
{
    WCHAR buf[256];
    LCID a, b;
    int r;
    SetLastError(0);
    a = pLocaleNameToLCID(name, 0);
    b = pLocaleNameToLCID(name, LOCALE_ALLOW_NEUTRAL_NAMES);
    buf[0] = 0;
    r = pResolveLocaleName(name, buf, 256);
    fprintf(out, "ALL\t%s\t0x%lx\t0x%lx\t%d\t%s\n", E(name), (unsigned long)a, (unsigned long)b, r, E(buf));
    if (b)
    {
        WCHAR n2[256]; int r2, r3; WCHAR n3[256];
        n2[0] = n3[0] = 0;
        r2 = pLCIDToLocaleName(b, n2, 256, 0);
        r3 = pLCIDToLocaleName(b, n3, 256, LOCALE_ALLOW_NEUTRAL_NAMES);
        fprintf(out, "ALL2\t%s\t%d\t%s\t%d\t%s\n", E(name), r2, E(n2), r3, E(n3));
    }
    return TRUE;
}

static void dump_names(void)
{
    WCHAR buf[256];
    int i, ret;
    LCID l;
    WCHAR *p;
    if (g_namefile)
    {
        FILE *f = fopen(g_namefile, "r");
        char line[256];
        while (f && fgets(line, sizeof(line), f))
        {
            WCHAR w[256];
            line[strcspn(line, "\r\n")] = 0;
            MultiByteToWideChar(CP_ACP, 0, line, -1, w, 256);
            enum_all_names(w, 0, 0);
        }
        if (f) fclose(f);
    }
    else if (pEnumSystemLocalesEx) pEnumSystemLocalesEx(enum_all_names, 0 /*LOCALE_ALL*/, 0, NULL);
    ret = pGetUserDefaultLocaleName(buf, 256);
    fprintf(out, "GUDLN\t%d\t%s\n", ret, E(buf));
    ret = pGetSystemDefaultLocaleName(buf, 256);
    fprintf(out, "GSDLN\t%d\t%s\n", ret, E(buf));
    fprintf(out, "GUDLCID\t0x%lx\nGSDLCID\t0x%lx\nGTL\t0x%lx\n", (unsigned long)GetUserDefaultLCID(),
            (unsigned long)GetSystemDefaultLCID(), (unsigned long)GetThreadLocale());
    for (i = 0; nameset[i]; i++)
    {
        SetLastError(0);
        l = pLocaleNameToLCID(nameset[i], 0);
        fprintf(out, "LN2L\t%ls\t0x%lx\t%lu\n", nameset[i], (unsigned long)l, l ? 0UL : GetLastError());
        SetLastError(0);
        buf[0] = 0;
        ret = pResolveLocaleName(nameset[i], buf, 256);
        fprintf(out, "RLN\t%ls\t%d\t%s\t%lu\n", nameset[i], ret, E(buf), ret ? 0UL : GetLastError());
    }
    for (i = 0; i < (int)(sizeof(lcidset) / sizeof(lcidset[0])); i++)
    {
        SetLastError(0);
        buf[0] = 0;
        ret = pLCIDToLocaleName(lcidset[i], buf, 256, 0);
        fprintf(out, "L2LN\t0x%lx\t%d\t%s\t%lu\n", (unsigned long)lcidset[i], ret, E(buf), ret ? 0UL : GetLastError());
    }
    (void)p;
}

static LONG WINAPI crash(EXCEPTION_POINTERS *ep)
{
    fprintf(out, "CRASH\t0x%lx\t%p\tafter locale %ls\n", (unsigned long)ep->ExceptionRecord->ExceptionCode,
            ep->ExceptionRecord->ExceptionAddress, g_name);
    ExitProcess(3);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, char **argv)
{
    SetUnhandledExceptionFilter(crash);
    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    int i;
    const char *outname = NULL, *namefile = NULL;
    out = stdout;
#define G(n) *(FARPROC *)&p##n = GetProcAddress(k, #n)
    G(GetLocaleInfoEx); G(GetCalendarInfoEx); G(EnumCalendarInfoExEx); G(EnumDateFormatsExEx); G(EnumTimeFormatsEx);
    G(GetUserDefaultLocaleName); G(GetSystemDefaultLocaleName); G(LocaleNameToLCID); G(LCIDToLocaleName);
    G(ResolveLocaleName); G(IsValidLocaleName); G(EnumSystemLocalesEx);
    if (argc > 2 && !strcmp(argv[1], "-N")) { namefile = argv[2]; argc -= 2; argv += 2; }
    if (argc > 2 && !strcmp(argv[1], "-o")) { outname = argv[2]; argc -= 2; argv += 2; }
    g_namefile = namefile;
    if (outname) out = fopen(outname, "wb");
    if (!out) return 2;
    setvbuf(out, NULL, _IONBF, 0);
    dump_names();
    if (argc > 1)
    {
        for (i = 1; i < argc; i++)
        {
            WCHAR w[64];
            MultiByteToWideChar(CP_ACP, 0, argv[i], -1, w, 64);
            dump_locale(w);
        }
    }
    else
        for (i = 0; defset[i]; i++) dump_locale(defset[i]);
    fflush(out);
    if (outname) fclose(out);
    return 0;
}
