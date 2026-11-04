/*
 * PROJECT:     ReactOS Command-Line Utilities
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     typeperf.exe: write performance counter data to the console or a log file
 *
 * The output (banner, usage text, messages, CSV/TSV layout, exit codes) follows
 * typeperf.exe of Windows 10 22H2 byte for byte; see modules/rostests/apitests/cmd/typeperf.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <pdh.h>
#include <pdhmsg.h>

#include "usage.h"

#define EXIT_BADFORMAT      11              /* ERROR_BAD_FORMAT */
#define EXIT_INVALID_FORMAT ((int)0xF0000001)
#define EXIT_NO_COUNTERS    ((int)0xF0000002)

typedef enum { FMT_CSV, FMT_TSV, FMT_BIN, FMT_SQL } LOGFMT;

/* The text is padded so that it erases the spinner of the line when it is printed over it. */
static const WCHAR g_Exiting[] = L"Exiting, please wait...                         \r\n";

static HANDLE g_hOut, g_hStop;
static BOOL g_OutIsConsole;
static BOOL g_Spinner, g_SpinnerLive;
static UINT g_SpinTicks;

/* ---------------------------------------------------------------- output */

static void OutStr(const WCHAR *s)
{
    DWORD cch = (DWORD)wcslen(s), written;
    char *buf;
    int n;

    if (!cch)
        return;
    if (g_OutIsConsole)
    {
        WriteConsoleW(g_hOut, s, cch, &written, NULL);
        return;
    }
    n = WideCharToMultiByte(CP_OEMCP, 0, s, cch, NULL, 0, NULL, NULL);
    buf = HeapAlloc(GetProcessHeap(), 0, n + 1);
    if (!buf)
        return;
    WideCharToMultiByte(CP_OEMCP, 0, s, cch, buf, n, NULL, NULL);
    WriteFile(g_hOut, buf, n, &written, NULL);
    HeapFree(GetProcessHeap(), 0, buf);
}

static void FileStr(HANDLE hFile, const WCHAR *s)
{
    DWORD cch = (DWORD)wcslen(s), written;
    char *buf;
    int n;

    n = WideCharToMultiByte(CP_ACP, 0, s, cch, NULL, 0, NULL, NULL);
    buf = HeapAlloc(GetProcessHeap(), 0, n + 1);
    if (!buf)
        return;
    WideCharToMultiByte(CP_ACP, 0, s, cch, buf, n, NULL, NULL);
    WriteFile(hFile, buf, n, &written, NULL);
    HeapFree(GetProcessHeap(), 0, buf);
}

/* ------------------------------------------------------------- messages */

/* The texts of the PDH statuses typeperf shows; others come from the message table of pdh.dll. */
static void PrintStatusText(PDH_STATUS st)
{
    const WCHAR *text = NULL;
    WCHAR *msg = NULL;
    HMODULE hPdh;
    WCHAR num[32];

    switch (st)
    {
        case PDH_CSTATUS_NO_OBJECT:
            text = L"The specified object was not found on the computer.";
            break;
        case PDH_LOG_FILE_CREATE_ERROR:
            text = L"Unable to create the specified log file.";
            break;
    }
    if (text)
    {
        OutStr(text);
        return;
    }
    hPdh = LoadLibraryExW(L"pdh.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (hPdh)
    {
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE |
                       FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                       hPdh, st, 0, (LPWSTR)&msg, 0, NULL);
        FreeLibrary(hPdh);
    }
    if (msg)
    {
        OutStr(msg);
        LocalFree(msg);
        return;
    }
    _swprintf(num, L"0x%08X", (UINT)st);
    OutStr(num);
}

/* "Exiting, please wait..." + "Error:" + the text of status st; returns the exit code */
static int FailPdh(PDH_STATUS st)
{
    OutStr(g_Exiting);
    OutStr(L"\r\nError:\r\n");
    PrintStatusText(st);
    OutStr(L"\r\n\r\n\r\r");
    return (int)st;
}

static int FailSimple(const WCHAR *line, int code)
{
    OutStr(g_Exiting);
    OutStr(line);
    OutStr(L"\r\n\r\r");
    return code;
}

static int SyntaxError(const WCHAR *first, BOOL missingList)
{
    if (first)
        OutStr(first);
    if (missingList)
        OutStr(L"Missing parameter: <counter [counter ...]>\r\n"
               L"Missing parameter: -cf <filename>\r\n"
               L"Missing parameter: -q [object]\r\n"
               L"Missing parameter: -qx [object]\r\n");
    OutStr(L"\r\nThe syntax of the command is incorrect.\r\n");
    return EXIT_BADFORMAT;
}

/* ------------------------------------------------------------ ctrl+c */

static BOOL WINAPI CtrlHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT)
    {
        SetEvent(g_hStop);
        return TRUE;
    }
    return FALSE;
}

/* ------------------------------------------------------------ options */

typedef struct
{
    WCHAR **Counters;
    UINT    nCounters;
    const WCHAR *CounterFile;
    BOOL    Query, QueryX;
    const WCHAR *Object;
    const WCHAR *OutFile;
    const WCHAR *FormatName;
    const WCHAR *Machine;
    long    Samples;            /* 0: until ctrl+c */
    DWORD   IntervalMs;
    BOOL    Yes;
    BOOL    Help;
} OPTIONS;

static BOOL IsSwitch(const WCHAR *a)
{
    return a[0] == L'-' || a[0] == L'/';
}

static DWORD ParseInterval(const WCHAR *s)
{
    /* [[hh:]mm:]ss; text that is not a number counts as 0 */
    DWORD part[3] = {0, 0, 0}, n = 0, total = 0, i;
    const WCHAR *p = s;

    for (;;)
    {
        WCHAR *end;
        long v = wcstol(p, &end, 10);
        if (n < 3)
            part[n++] = v < 0 ? 0 : (DWORD)v;
        if (*end != L':' || n >= 3)
            break;
        p = end + 1;
    }
    for (i = 0; i < n; i++)
        total = total * 60 + part[i];
    return total * 1000;
}

static int ParseArgs(int argc, WCHAR **argv, OPTIONS *o)
{
    int i;
    BOOL syntax = FALSE;
    const WCHAR *unknown = NULL;
    WCHAR line[256];

    memset(o, 0, sizeof(*o));
    o->IntervalMs = 1000;
    o->Counters = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (argc + 1) * sizeof(WCHAR *));

    for (i = 1; i < argc; i++)
    {
        const WCHAR *a = argv[i];
        const WCHAR *sw = a + 1;
        const WCHAR **target = NULL;
        const WCHAR *form = NULL;

        if (!IsSwitch(a) || !a[1])
        {
            o->Counters[o->nCounters++] = argv[i];
            continue;
        }
        if (!wcscmp(sw, L"?"))
        {
            o->Help = TRUE;
            return 0;
        }
        if (!_wcsicmp(sw, L"y"))
        {
            o->Yes = TRUE;
            continue;
        }
        if (!_wcsicmp(sw, L"q") || !_wcsicmp(sw, L"qx"))
        {
            o->Query = TRUE;
            o->QueryX = (sw[1] != 0);
            if (i + 1 < argc && !IsSwitch(argv[i + 1]))
                o->Object = argv[++i];
            continue;
        }
        if (!_wcsicmp(sw, L"cf"))      { target = &o->CounterFile; form = L"-cf <filename>"; }
        else if (!_wcsicmp(sw, L"o"))  { target = &o->OutFile;     form = L"-o <filename>"; }
        else if (!_wcsicmp(sw, L"f"))  { target = &o->FormatName;  form = L"-f <CSV|TSV|BIN|SQL>"; }
        else if (!_wcsicmp(sw, L"s"))  { target = &o->Machine;     form = L"-s <computer_name>"; }
        else if (!_wcsicmp(sw, L"sc")) { form = L"-sc <samples>"; }
        else if (!_wcsicmp(sw, L"si")) { form = L"-si <[[hh:]mm:]ss>"; }
        else if (!_wcsicmp(sw, L"config")) { form = L"-config <filename>"; }
        else
        {
            if (!unknown)
                unknown = a;
            syntax = TRUE;
            continue;
        }

        if (i + 1 >= argc)
        {
            _snwprintf(line, 255, L"Invalid syntax: %s\r\n", form);
            return SyntaxError(line, FALSE);
        }
        i++;
        if (target)
            *target = argv[i];
        else if (!_wcsicmp(sw, L"sc"))
        {
            WCHAR *end;
            long v = wcstol(argv[i], &end, 10);
            o->Samples = (end == argv[i] || v < 1) ? 1 : v;     /* not a number: one sample */
        }
        else if (!_wcsicmp(sw, L"si"))
            o->IntervalMs = ParseInterval(argv[i]);
        else
        {
            /* -config: the options of the settings file are not read */
        }
    }

    if (o->Machine && !(o->Machine[0] == L'\\' && o->Machine[1] == L'\\'))
    {
        WCHAR *m = HeapAlloc(GetProcessHeap(), 0, (wcslen(o->Machine) + 3) * sizeof(WCHAR));
        m[0] = m[1] = L'\\';
        wcscpy(m + 2, o->Machine);
        o->Machine = m;
    }
    if (unknown)
    {
        _snwprintf(line, 255, L"Unknown parameter \"%s\"\r\n", unknown);
        return SyntaxError(line, !(o->nCounters || o->CounterFile || o->Query));
    }
    if (!o->nCounters && !o->CounterFile && !o->Query)
        return SyntaxError(NULL, TRUE);
    (void)syntax;
    return -1;
}

/* ------------------------------------------------------------ queries */

/* Calls an enumeration function until the multi-string fits; returns NULL on failure. */
static PDH_STATUS EnumObjectItems(const WCHAR *machine, const WCHAR *object,
                                  WCHAR **counters, WCHAR **instances)
{
    DWORD cl = 0, il = 0;
    PDH_STATUS st;
    int tries;

    *counters = *instances = NULL;
    st = PdhEnumObjectItemsW(NULL, machine, object, NULL, &cl, NULL, &il, PERF_DETAIL_WIZARD, 0);
    for (tries = 0; tries < 4 && (st == PDH_MORE_DATA || st == ERROR_SUCCESS); tries++)
    {
        *counters = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cl + 2) * sizeof(WCHAR));
        *instances = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (il + 2) * sizeof(WCHAR));
        if (!*counters || !*instances)
            return PDH_MEMORY_ALLOCATION_FAILURE;
        st = PdhEnumObjectItemsW(NULL, machine, object, *counters, &cl, *instances, &il,
                                 PERF_DETAIL_WIZARD, 0);
        if (st == ERROR_SUCCESS)
            return st;
        HeapFree(GetProcessHeap(), 0, *counters);
        HeapFree(GetProcessHeap(), 0, *instances);
        *counters = *instances = NULL;
        if (st != PDH_MORE_DATA)
            break;
    }
    return st;
}

typedef void (*LINE_SINK)(void *ctx, const WCHAR *line);

static void SinkConsole(void *ctx, const WCHAR *line)
{
    OutStr(line);
    OutStr(L"\r\n");
}

static void SinkFile(void *ctx, const WCHAR *line)
{
    FileStr((HANDLE)ctx, line);
    FileStr((HANDLE)ctx, L"\r\n");
}

static PDH_STATUS ListObject(const WCHAR *machine, const WCHAR *object, BOOL withInstances,
                             LINE_SINK sink, void *ctx)
{
    WCHAR *counters, *instances, *c, *n;
    PDH_STATUS st = EnumObjectItems(machine, object, &counters, &instances);
    SIZE_T len;
    WCHAR *line;

    if (st != ERROR_SUCCESS)
        return st;
    len = wcslen(object) + 8;
    for (c = counters; *c; c += wcslen(c) + 1)
    {
        for (n = instances; *n; n += wcslen(n) + 1)
            len = max(len, wcslen(object) + wcslen(c) + wcslen(n) + 8);
        len = max(len, wcslen(object) + wcslen(c) + 8);
    }
    len += machine ? wcslen(machine) : 0;
    line = HeapAlloc(GetProcessHeap(), 0, (len + 8) * sizeof(WCHAR));
    for (c = counters; *c; c += wcslen(c) + 1)
    {
        if (!*instances)
        {
            _swprintf(line, L"\\%s\\%s", object, c);
            sink(ctx, line);
        }
        else if (!withInstances)
        {
            _swprintf(line, L"\\%s(*)\\%s", object, c);
            sink(ctx, line);
        }
        else
        {
            for (n = instances; *n; n += wcslen(n) + 1)
            {
                _swprintf(line, L"\\%s(%s)\\%s", object, n, c);
                sink(ctx, line);
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, line);
    HeapFree(GetProcessHeap(), 0, counters);
    HeapFree(GetProcessHeap(), 0, instances);
    return ERROR_SUCCESS;
}

static PDH_STATUS ListAll(const OPTIONS *o, LINE_SINK sink, void *ctx)
{
    PDH_STATUS st;
    DWORD len = 0;
    WCHAR *objs, *p;

    if (o->Object)
        return ListObject(o->Machine, o->Object, o->QueryX, sink, ctx);

    st = PdhEnumObjectsW(NULL, o->Machine, NULL, &len, PERF_DETAIL_WIZARD, FALSE);
    if (st != PDH_MORE_DATA && st != ERROR_SUCCESS)
        return st;
    objs = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (len + 2) * sizeof(WCHAR));
    st = PdhEnumObjectsW(NULL, o->Machine, objs, &len, PERF_DETAIL_WIZARD, FALSE);
    if (st != ERROR_SUCCESS)
        return st;
    for (p = objs; *p; p += wcslen(p) + 1)
    {
        st = ListObject(o->Machine, p, o->QueryX, sink, ctx);
        if (st != ERROR_SUCCESS)
            break;
    }
    HeapFree(GetProcessHeap(), 0, objs);
    return st;
}

/* ------------------------------------------------------- output file */

static HANDLE OpenOutputFile(const OPTIONS *o, int *rc)
{
    HANDLE h;

    if (!o->Yes && GetFileAttributesW(o->OutFile) != INVALID_FILE_ATTRIBUTES)
    {
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        WCHAR *q = HeapAlloc(GetProcessHeap(), 0, (wcslen(o->OutFile) + 64) * sizeof(WCHAR));
        char ch = 0;
        DWORD got;

        _swprintf(q, L"The file \"%s\" already exists, overwrite? [y/n] ", o->OutFile);
        OutStr(q);
        HeapFree(GetProcessHeap(), 0, q);
        for (;;)
        {
            if (!ReadFile(hIn, &ch, 1, &got, NULL) || !got)
            {
                ch = 'n';       /* no answer: do not overwrite */
                break;
            }
            if (ch == 'y' || ch == 'Y' || ch == 'n' || ch == 'N')
                break;
        }
        if (ch != 'y' && ch != 'Y')
        {
            OutStr(L"\r\n");
            *rc = 1;
            return INVALID_HANDLE_VALUE;
        }
    }
    h = CreateFileW(o->OutFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        *rc = FailPdh(PDH_LOG_FILE_CREATE_ERROR);
    return h;
}

/* ------------------------------------------------- the counter list */

static WCHAR *ReadCounterFile(const WCHAR *path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, 0, NULL);
    DWORD size, got;
    BYTE *raw;
    WCHAR *text;

    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    size = GetFileSize(h, NULL);
    raw = HeapAlloc(GetProcessHeap(), 0, size + 2);
    if (!raw || !ReadFile(h, raw, size, &got, NULL))
    {
        CloseHandle(h);
        return NULL;
    }
    CloseHandle(h);
    raw[got] = raw[got + 1] = 0;
    if (got >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
    {
        text = HeapAlloc(GetProcessHeap(), 0, got + 2);
        memcpy(text, raw + 2, got - 2);
        text[(got - 2) / 2] = 0;
    }
    else
    {
        BYTE *src = raw;
        DWORD n = got;
        if (n >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF)
        {
            src += 3;
            n -= 3;
        }
        text = HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR));
        n = MultiByteToWideChar(CP_ACP, 0, (char *)src, n, text, n);
        text[n] = 0;
    }
    HeapFree(GetProcessHeap(), 0, raw);
    return text;
}

typedef struct
{
    PDH_HQUERY   Query;
    PDH_HCOUNTER *Counters;
    WCHAR        **Names;
    UINT         nCounters, Cap;
    const WCHAR  *Machine;
    WCHAR        Computer[MAX_COMPUTERNAME_LENGTH + 4];
} COUNTERSET;

static WCHAR *DupStr(const WCHAR *s)
{
    WCHAR *d = HeapAlloc(GetProcessHeap(), 0, (wcslen(s) + 1) * sizeof(WCHAR));
    if (d)
        wcscpy(d, s);
    return d;
}

/* The path as printed in the header: always with the computer name. */
static WCHAR *FullName(COUNTERSET *cs, PDH_HCOUNTER hc, const WCHAR *path)
{
    DWORD size = 0;
    PDH_COUNTER_INFO_W *info = NULL;
    WCHAR *name = NULL;

    if (PdhGetCounterInfoW(hc, FALSE, &size, NULL) == PDH_MORE_DATA && size)
    {
        info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        if (info && PdhGetCounterInfoW(hc, FALSE, &size, info) == ERROR_SUCCESS &&
            info->szFullPath && info->szFullPath[0] == L'\\' && info->szFullPath[1] == L'\\')
            name = DupStr(info->szFullPath);
        HeapFree(GetProcessHeap(), 0, info);
    }
    if (!name)
    {
        if (path[0] == L'\\' && path[1] == L'\\')
            name = DupStr(path);
        else
        {
            name = HeapAlloc(GetProcessHeap(), 0,
                             (wcslen(cs->Computer) + wcslen(path) + 1) * sizeof(WCHAR));
            if (name)
            {
                wcscpy(name, cs->Computer);
                wcscat(name, path);
            }
        }
    }
    return name;
}

static void AddOnePath(COUNTERSET *cs, const WCHAR *path)
{
    PDH_HCOUNTER hc;

    if (PdhAddCounterW(cs->Query, path, 0, &hc) != ERROR_SUCCESS)
        return;                 /* invalid counters are skipped */
    if (cs->nCounters == cs->Cap)
    {
        UINT cap = cs->Cap ? cs->Cap * 2 : 16;
        PDH_HCOUNTER *c = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap * sizeof(*c));
        WCHAR **n = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap * sizeof(*n));
        if (!c || !n)
            return;
        if (cs->nCounters)
        {
            memcpy(c, cs->Counters, cs->nCounters * sizeof(*c));
            memcpy(n, cs->Names, cs->nCounters * sizeof(*n));
        }
        HeapFree(GetProcessHeap(), 0, cs->Counters);
        HeapFree(GetProcessHeap(), 0, cs->Names);
        cs->Counters = c;
        cs->Names = n;
        cs->Cap = cap;
    }
    cs->Counters[cs->nCounters] = hc;
    cs->Names[cs->nCounters] = FullName(cs, hc, path);
    cs->nCounters++;
}

static void AddPath(COUNTERSET *cs, const WCHAR *path)
{
    WCHAR *exp, *full = NULL;
    DWORD len = 0;
    PDH_STATUS st;
    const WCHAR *p;

    /* -s: counters without a computer name belong to that computer */
    if (cs->Machine && !(path[0] == L'\\' && path[1] == L'\\'))
    {
        full = HeapAlloc(GetProcessHeap(), 0,
                         (wcslen(cs->Machine) + wcslen(path) + 4) * sizeof(WCHAR));
        wcscpy(full, cs->Machine);
        wcscat(full, path);
        path = full;
    }
    st = PdhExpandWildCardPathW(NULL, path, NULL, &len, 0);
    if (st == PDH_MORE_DATA || st == ERROR_SUCCESS)
    {
        exp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (len + 2) * sizeof(WCHAR));
        if (exp)
        {
            st = PdhExpandWildCardPathW(NULL, path, exp, &len, 0);
            if (st == ERROR_SUCCESS)
                for (p = exp; *p; p += wcslen(p) + 1)
                    AddOnePath(cs, p);
            HeapFree(GetProcessHeap(), 0, exp);
        }
    }
    HeapFree(GetProcessHeap(), 0, full);
}

static void AddCounterFile(COUNTERSET *cs, const WCHAR *file)
{
    WCHAR *text = ReadCounterFile(file), *p, *eol;

    if (!text)
        return;
    for (p = text; *p; p = eol)
    {
        WCHAR *b, *e;
        eol = p;
        while (*eol && *eol != L'\n')
            eol++;
        if (*eol)
            *eol++ = 0;
        b = p;
        while (*b == L' ' || *b == L'\t' || *b == L'\r')
            b++;
        e = b + wcslen(b);
        while (e > b && (e[-1] == L' ' || e[-1] == L'\t' || e[-1] == L'\r'))
            *--e = 0;
        if (e - b >= 2 && b[0] == L'"' && e[-1] == L'"')
        {
            b++;
            *--e = 0;
        }
        if (*b)
            AddPath(cs, b);
    }
    HeapFree(GetProcessHeap(), 0, text);
}

/* ------------------------------------------------------------ sampling */

static void Spin(void)
{
    static const WCHAR chars[] = L"|/-\\";
    WCHAR s[8];

    if (!g_Spinner)
        return;
    _swprintf(s, L"\r[%c]", chars[g_SpinTicks++ & 3]);
    if (g_SpinnerLive)
        OutStr(s);
}

/* Waits for the interval; returns TRUE if ctrl+c came. */
static BOOL WaitInterval(DWORD ms)
{
    DWORD slice;

    while (ms)
    {
        slice = (g_Spinner && ms > 250) ? 250 : ms;
        if (WaitForSingleObject(g_hStop, slice) == WAIT_OBJECT_0)
            return TRUE;
        ms -= slice;
        if (ms)
            Spin();
    }
    return FALSE;
}

static void QuoteJoin(WCHAR *dst, const WCHAR *src, BOOL first)
{
    (void)first;
    _swprintf(dst + wcslen(dst), L"\"%s\"", src);
}

static int RunSampling(const OPTIONS *o, LOGFMT fmt)
{
    COUNTERSET cs;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    const WCHAR sep = (fmt == FMT_TSV) ? L'\t' : L',';
    const WCHAR *tag = (fmt == FMT_TSV) ? L"PDH-TSV 4.0" : L"PDH-CSV 4.0";
    int rc = 0;
    UINT i;
    SIZE_T cap;
    WCHAR *line;
    long done = 0;
    DWORD sz;
    PDH_STATUS st;
    BOOL stopped = FALSE;

    memset(&cs, 0, sizeof(cs));
    cs.Machine = o->Machine;
    sz = MAX_COMPUTERNAME_LENGTH + 1;
    if (o->Machine)
        wcsncpy(cs.Computer, o->Machine, MAX_COMPUTERNAME_LENGTH + 2);
    else
    {
        cs.Computer[0] = cs.Computer[1] = L'\\';
        GetComputerNameW(cs.Computer + 2, &sz);
    }

    OutStr(L"\r\n");

    if (o->OutFile)
    {
        hFile = OpenOutputFile(o, &rc);
        if (hFile == INVALID_HANDLE_VALUE)
            return rc;
        g_Spinner = TRUE;
        g_SpinnerLive = g_OutIsConsole;
    }

    if (PdhOpenQueryW(NULL, 0, &cs.Query) != ERROR_SUCCESS)
        return FailSimple(L"Error: No valid counters.", EXIT_NO_COUNTERS);

    if (o->CounterFile)
        AddCounterFile(&cs, o->CounterFile);
    else
        for (i = 0; i < o->nCounters; i++)
            AddPath(&cs, o->Counters[i]);

    if (!cs.nCounters)
    {
        PdhCloseQuery(cs.Query);
        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
        return FailSimple(L"Error: No valid counters.", EXIT_NO_COUNTERS);
    }

    cap = 128;
    for (i = 0; i < cs.nCounters; i++)
        cap += wcslen(cs.Names[i]) + 8;
    line = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cap + 64) * sizeof(WCHAR));

    /* header */
    if (hFile != INVALID_HANDLE_VALUE)
    {
        TIME_ZONE_INFORMATION tz;
        DWORD id = GetTimeZoneInformation(&tz);
        LONG bias = tz.Bias;
        const WCHAR *name = tz.StandardName;
        if (id == TIME_ZONE_ID_DAYLIGHT)
        {
            bias += tz.DaylightBias;
            name = tz.DaylightName;
        }
        else
            bias += tz.StandardBias;
        _swprintf(line, L"\"(%s) (%s)(%ld)\"", tag, name, (long)bias);
    }
    else
        _swprintf(line, L"\"(%s)\"", tag);
    for (i = 0; i < cs.nCounters; i++)
    {
        WCHAR s[2] = { sep, 0 };
        wcscat(line, s);
        QuoteJoin(line, cs.Names[i], FALSE);
    }
    wcscat(line, L"\r\n");
    if (hFile != INVALID_HANDLE_VALUE)
        FileStr(hFile, line);
    else
        OutStr(line);

    Spin();
    PdhCollectQueryData(cs.Query);

    for (;;)
    {
        SYSTEMTIME t;

        if (WaitInterval(o->IntervalMs))
        {
            stopped = TRUE;
            break;
        }
        st = PdhCollectQueryData(cs.Query);
        GetLocalTime(&t);
        _swprintf(line, L"\"%02u/%02u/%04u %02u:%02u:%02u.%03u\"", t.wMonth, t.wDay, t.wYear,
                 t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
        for (i = 0; i < cs.nCounters; i++)
        {
            PDH_FMT_COUNTERVALUE v;
            WCHAR s[64];
            WCHAR sp[2] = { sep, 0 };

            wcscat(line, sp);
            if (st == ERROR_SUCCESS &&
                PdhGetFormattedCounterValue(cs.Counters[i], PDH_FMT_DOUBLE, NULL, &v) == ERROR_SUCCESS &&
                (v.CStatus == PDH_CSTATUS_VALID_DATA || v.CStatus == PDH_CSTATUS_NEW_DATA))
            {
                /* the console shows 6 decimals, the log keeps the value */
                if (hFile != INVALID_HANDLE_VALUE)
                    _swprintf(s, L"\"%.15g\"", v.doubleValue);
                else
                    _swprintf(s, L"\"%f\"", v.doubleValue);
            }
            else
                wcscpy(s, L"\" \"");
            wcscat(line, s);
        }
        wcscat(line, L"\r\n");
        if (hFile != INVALID_HANDLE_VALUE)
            FileStr(hFile, line);
        else
            OutStr(line);
        done++;
        if (o->Samples && done >= o->Samples)
            break;
        Spin();
    }
    (void)stopped;

    PdhCloseQuery(cs.Query);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, line);

    if (g_SpinnerLive)
        OutStr(L"\r");
    OutStr(g_Exiting);
    OutStr(L"The command completed successfully.\r\n");
    if (g_Spinner && !g_SpinnerLive)
    {
        /* redirected output: the spinner steps follow the last message */
        g_SpinnerLive = TRUE;
        for (i = 0; i < g_SpinTicks; i++)
        {
            static const WCHAR chars[] = L"|/-\\";
            WCHAR s[8];
            _swprintf(s, L"\r[%c]", chars[i & 3]);
            OutStr(s);
        }
    }
    OutStr(L"\r\r");
    return 0;
}

static int RunQuery(const OPTIONS *o)
{
    PDH_STATUS st;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    int rc = 0;

    if (o->OutFile)
    {
        hFile = OpenOutputFile(o, &rc);
        if (hFile == INVALID_HANDLE_VALUE)
            return rc;
        st = ListAll(o, SinkFile, hFile);
        CloseHandle(hFile);
    }
    else
        st = ListAll(o, SinkConsole, NULL);
    if (st != ERROR_SUCCESS)
        return FailPdh(st);
    OutStr(g_Exiting);
    OutStr(L"The command completed successfully.\r\n\r\r");
    return 0;
}

int wmain(int argc, WCHAR **argv)
{
    OPTIONS o;
    LOGFMT fmt = FMT_CSV;
    DWORD mode;
    int rc;

    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    g_OutIsConsole = GetConsoleMode(g_hOut, &mode);
    g_hStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    rc = ParseArgs(argc, argv, &o);
    if (o.Help)
    {
        OutStr(g_Usage);
        return 0;
    }
    if (rc >= 0)
        return rc;

    if (o.FormatName)
    {
        if (!_wcsicmp(o.FormatName, L"CSV"))
            fmt = FMT_CSV;
        else if (!_wcsicmp(o.FormatName, L"TSV"))
            fmt = FMT_TSV;
        else if (!_wcsicmp(o.FormatName, L"BIN"))
            fmt = FMT_BIN;
        else if (!_wcsicmp(o.FormatName, L"SQL"))
            fmt = FMT_SQL;
        else
        {
            WCHAR msg[256];
            _snwprintf(msg, 255, L"\"%s\" is not a valid format.", o.FormatName);
            return FailSimple(msg, EXIT_INVALID_FORMAT);
        }
    }

    if (o.Query)
        return RunQuery(&o);

    if (fmt == FMT_BIN || fmt == FMT_SQL)
    {
        /* binary and SQL logs are not supported */
        OutStr(L"\r\n");
        return FailPdh(PDH_LOG_FILE_CREATE_ERROR);
    }
    return RunSampling(&o, fmt);
}
