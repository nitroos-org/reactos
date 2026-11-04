/*
 * Internet Explorer wrapper
 *
 * Copyright 2006 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <windows.h>
#include <advpub.h>
#include <ole2.h>
#include <rpcproxy.h>
#ifdef __REACTOS__
#include <stdlib.h>
#include <shlwapi.h>
#include <strsafe.h>
#endif

#include "wine/unicode.h"
#include "wine/debug.h"

extern DWORD WINAPI IEWinMain(const WCHAR*, int);

static BOOL check_native_ie(void)
{
    DWORD handle, size;
    LPWSTR file_desc;
    UINT bytes;
    void* buf;
    BOOL ret = TRUE;
    LPWORD translation;

    static const WCHAR browseui_dllW[] = {'b','r','o','w','s','e','u','i','.','d','l','l',0};
    static const WCHAR wineW[] = {'W','i','n','e',0};
    static const WCHAR translationW[] =
        {'\\','V','a','r','F','i','l','e','I','n','f','o',
         '\\','T','r','a','n','s','l','a','t','i','o','n',0};
    static const WCHAR file_desc_fmtW[] =
        {'\\','S','t','r','i','n','g','F','i','l','e','I','n','f','o',
         '\\','%','0','4','x','%','0','4','x',
         '\\','F','i','l','e','D','e','s','c','r','i','p','t','i','o','n',0};
    WCHAR file_desc_strW[48];

    size = GetFileVersionInfoSizeW(browseui_dllW, &handle);
    if(!size)
        return TRUE;

    buf = HeapAlloc(GetProcessHeap(), 0, size);
    GetFileVersionInfoW(browseui_dllW, 0, size,buf);
    if (VerQueryValueW(buf, translationW, (void **)&translation, &bytes))
    {
        wsprintfW(file_desc_strW, file_desc_fmtW, translation[0], translation[1]);
        ret = !VerQueryValueW(buf, file_desc_strW, (void**)&file_desc, &bytes) || !strstrW(file_desc, wineW);
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return ret;
}

static DWORD register_iexplore(BOOL doregister)
{
    HRESULT hres;

    if (check_native_ie()) {
        WINE_MESSAGE("Native IE detected, not doing registration\n");
        return 0;
    }

    hres = RegInstallA(NULL, doregister ? "RegisterIE" : "UnregisterIE", NULL);
    return FAILED(hres);
}

#ifdef __REACTOS__
/* Without Wine Gecko every page stays blank and nothing says why */
static BOOL is_gecko_installed(void)
{
    WCHAR path[MAX_PATH];
    DWORD size = sizeof(path) - sizeof(WCHAR), type, attr;
    HKEY hkey;
    LONG res;

    /* The version must match GECKO_VERSION in mshtml */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Wine\\MSHTML\\2.40", 0, KEY_QUERY_VALUE, &hkey) != ERROR_SUCCESS)
        return FALSE;
    res = RegQueryValueExW(hkey, L"GeckoPath", NULL, &type, (BYTE *)path, &size);
    RegCloseKey(hkey);
    if (res != ERROR_SUCCESS || type != REG_SZ)
        return FALSE;
    path[size / sizeof(WCHAR)] = 0;

    attr = GetFileAttributesW(path);
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

/* The leading switches, parsed as IEWinMain does */
static BOOL is_com_activation(const WCHAR *cmdline)
{
    while (*cmdline)
    {
        int length = 0;

        while (*cmdline == ' ' || *cmdline == '\t') cmdline++;
        if (*cmdline != '-') break;
        while (cmdline[length] && cmdline[length] != ' ' && cmdline[length] != '\t') length++;

        if ((length == 10 && !strncmpiW(cmdline, L"-embedding", 10)) ||
            (length == 13 && !strncmpiW(cmdline, L"-startmanager", 13)))
            return TRUE;
        cmdline += length;
    }
    return FALSE;
}

static void install_gecko(void)
{
    static const WCHAR rundllW[] = L"\\rundll32.exe";
    WCHAR app[MAX_PATH], cmdline[MAX_PATH + 64];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    UINT len;

    len = GetSystemDirectoryW(app, MAX_PATH - sizeof(rundllW) / sizeof(WCHAR));
    if (!len || len >= MAX_PATH - sizeof(rundllW) / sizeof(WCHAR))
        return;
    lstrcpyW(app + len, rundllW);
    wsprintfW(cmdline, L"\"%s\" shell32.dll,Control_RunDLL appwiz.cpl,,install_gecko", app);

    /* appwiz explains what is missing and offers the download; control.exe would not
     * wait for it, rundll32 returns when the dialog closes */
    if (CreateProcessW(app, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
    }
}

/*
 * NitroOS: Internet Explorer is retired as an app, as on Windows 11, where iexplore.exe hands the page to Edge.
 * Here starting iexplore.exe (Start menu, "start iexplore <url>", ShellExecute("iexplore.exe", url), an .html file
 * or a URL still registered to it) opens the user's default web browser: with the URL when there is one, else with
 * no arguments. COM activation (-embedding for InternetExplorer.Application, -startmanager) keeps the built-in
 * browser object, as Windows 11 does, and so does a system where iexplore itself is the http handler (no other
 * browser registered), which would otherwise start itself over and over, and so does an iexplore that the
 * browser's own handler started again (see is_reentry). The WebBrowser control, mshtml and HTML help do not go
 * through iexplore.exe at all.
 */
typedef struct
{
    BOOL nohome;        /* -nohome: no home page; the default browser decides what it shows */
    BOOL kiosk;         /* -k: passed on as the browser's kiosk switch when it is one we know */
    BOOL inprivate;     /* -private: passed on as the browser's private window switch when it is one we know */
    const WCHAR *url;   /* the rest of the command line, as IEWinMain reads it */
} IE_CMDLINE;

/* Set in the environment of the browser we start, to the GetTickCount() of the start. An iexplore that finds it set
 * and recent was started by that handler again (a handler such as "cmd /c start iexplore %1" or a wrapper script):
 * it opens the built-in browser instead of starting the handler over and over. A stale value (an iexplore started
 * from the browser a while later) does not count. */
static const WCHAR redirect_var[] = L"NITRO_IEXPLORE_REDIRECT";
#define REDIRECT_WINDOW_MS 60000

static BOOL is_reentry(void)
{
    WCHAR value[32];
    WCHAR *end;
    DWORD length, start;

    length = GetEnvironmentVariableW(redirect_var, value, ARRAYSIZE(value));
    if (!length)
        return FALSE;
    if (length >= ARRAYSIZE(value))
        return TRUE;
    start = wcstoul(value, &end, 10);
    if (end == value || *end)
        return TRUE;
    return GetTickCount() - start < REDIRECT_WINDOW_MS;
}

static BOOL is_switch(const WCHAR *arg, int length, const WCHAR *name)
{
    return length == lstrlenW(name) && !strncmpiW(arg, name, length);
}

/* The leading switches, as IEWinMain reads them; the first word not starting with '-' starts the URL. Switches other
 * than -k, -private and -nohome (-nosessionmerging, -noframemerging, -extoff, -clearcache, ...) mean nothing to
 * another browser and are dropped. */
static void parse_ie_cmdline(const WCHAR *cmdline, IE_CMDLINE *args)
{
    ZeroMemory(args, sizeof(*args));
    for (;;)
    {
        int length = 0;

        while (*cmdline == ' ' || *cmdline == '\t') cmdline++;
        if (*cmdline != '-') break;
        while (cmdline[length] && cmdline[length] != ' ' && cmdline[length] != '\t') length++;

        if (is_switch(cmdline, length, L"-k"))
            args->kiosk = TRUE;
        else if (is_switch(cmdline, length, L"-private"))
            args->inprivate = TRUE;
        else if (is_switch(cmdline, length, L"-nohome"))
            args->nohome = TRUE;
        cmdline += length;
    }
    args->url = cmdline;
}

/*
 * The URL to pass on (empty: none). Without a scheme and not a path it is a web address, as Internet Explorer reads
 * "example.com". A '"' would end the quoted argument of the browser's command line and so could add switches to it;
 * it is not valid in a URL or a file name, and goes on as %22. HeapFree the result.
 */
static WCHAR *get_url(const WCHAR *in)
{
    static const WCHAR httpW[] = L"http://";
    const WCHAR *end;
    WCHAR *raw, *url, *o;
    int length, i;

    while (*in == ' ' || *in == '\t') in++;
    end = in + lstrlenW(in);
    while (end > in && (end[-1] == ' ' || end[-1] == '\t')) end--;
    if (end - in >= 2 && *in == '"' && end[-1] == '"')
    {
        in++;
        end--;
    }
    length = end - in;

    raw = HeapAlloc(GetProcessHeap(), 0, (length + 1) * sizeof(WCHAR));
    url = HeapAlloc(GetProcessHeap(), 0, (length * 3 + ARRAYSIZE(httpW) + 1) * sizeof(WCHAR));
    if (!raw || !url)
    {
        HeapFree(GetProcessHeap(), 0, raw);
        HeapFree(GetProcessHeap(), 0, url);
        return NULL;
    }
    memcpy(raw, in, length * sizeof(WCHAR));
    raw[length] = 0;

    o = url;
    if (length && !PathIsURLW(raw) && !(length >= 2 && raw[1] == ':') && !(raw[0] == '\\' && raw[1] == '\\'))
    {
        lstrcpyW(o, httpW);
        o += lstrlenW(httpW);
    }
    for (i = 0; i < length; i++)
    {
        if (raw[i] == '"')
        {
            *o++ = '%'; *o++ = '2'; *o++ = '2';
        }
        else
            *o++ = raw[i];
    }
    *o = 0;
    HeapFree(GetProcessHeap(), 0, raw);
    return url;
}

static BOOL is_absolute_file(const WCHAR *path)
{
    DWORD attr;

    if (!((path[0] && path[1] == ':' && path[2] == '\\') || (path[0] == '\\' && path[1] == '\\')))
        return FALSE;
    attr = GetFileAttributesW(path);
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

/*
 * Split an open command into its executable and the rest. A quoted first word is the executable. An unquoted one
 * with blanks in the path ("C:\Program Files\x\y.exe -a %1") is the longest prefix ending at a blank that names an
 * existing file (also with .exe added), so that C:\Program.exe is never picked over it; else the first word.
 */
static BOOL split_command(const WCHAR *command, WCHAR *exe, DWORD cch_exe, const WCHAR **rest)
{
    const WCHAR *p = command, *q, *best = NULL;
    WCHAR candidate[MAX_PATH];

    exe[0] = 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"')
    {
        for (q = ++p; *q && *q != '"'; q++);
        if (q == p || FAILED(StringCchCopyNW(exe, cch_exe, p, q - p)))
            return FALSE;
        *rest = *q ? q + 1 : q;
        return TRUE;
    }

    for (q = p; ; q++)
    {
        if (!*q || *q == ' ' || *q == '\t')
        {
            if (q > p && SUCCEEDED(StringCchCopyNW(candidate, ARRAYSIZE(candidate), p, q - p)))
            {
                if (is_absolute_file(candidate) ||
                    (SUCCEEDED(StringCchCatW(candidate, ARRAYSIZE(candidate), L".exe")) && is_absolute_file(candidate)))
                {
                    if (SUCCEEDED(StringCchCopyW(exe, cch_exe, candidate)))
                        best = q;
                }
            }
            if (!*q) break;
        }
    }
    if (!best)
    {
        for (q = p; *q && *q != ' ' && *q != '\t'; q++);
        if (q == p || FAILED(StringCchCopyNW(exe, cch_exe, p, q - p)))
            return FALSE;
        best = q;
    }
    *rest = best;
    return TRUE;
}

/* The open command of the default browser, read the way ShellExecute does for an http URL: the ProgId of the user's
 * choice (UserChoice), else HKCR\http itself (CQueryAssociations does both), with the environment strings expanded.
 * FALSE when there is none or it does not fit the buffers: the built-in browser then does it. */
static BOOL get_default_browser(WCHAR *command, DWORD cch_command)
{
    static const WCHAR *const protocols[] = { L"http", L"https" };
    WCHAR buffer[MAX_PATH * 2];
    DWORD cch, expanded;
    UINT i;

    for (i = 0; i < ARRAYSIZE(protocols); i++)
    {
        ZeroMemory(buffer, sizeof(buffer));
        ZeroMemory(command, cch_command * sizeof(WCHAR));
        cch = ARRAYSIZE(buffer);
        if (FAILED(AssocQueryStringW(ASSOCF_NOTRUNCATE, ASSOCSTR_COMMAND, protocols[i], L"open", buffer, &cch)) ||
            !buffer[0])
            continue;
        expanded = ExpandEnvironmentStringsW(buffer, command, cch_command);
        if (!expanded || expanded > cch_command)
            return FALSE;   /* does not fit: no half command, and not the next protocol's handler either */
        if (command[0])
            return TRUE;
    }
    return FALSE;
}

/* The handler is iexplore.exe itself (also a renamed copy): starting it would start us again */
static BOOL is_self(const WCHAR *exe)
{
    WCHAR self[MAX_PATH];
    const WCHAR *name = PathFindFileNameW(exe);

    if (!lstrcmpiW(name, L"iexplore.exe") || !lstrcmpiW(name, L"iexplore"))
        return TRUE;
    if (!GetModuleFileNameW(NULL, self, ARRAYSIZE(self)))
        return FALSE;
    return !lstrcmpiW(exe, self) || !lstrcmpiW(name, PathFindFileNameW(self));
}

/* -k and -private for the browsers whose switches we know; FALSE: open it the usual way */
static BOOL get_browser_switches(const WCHAR *exe, const IE_CMDLINE *args, const WCHAR **kiosk, const WCHAR **inprivate)
{
    static const struct { const WCHAR *exe, *kiosk, *inprivate; } browsers[] =
    {
        { L"firefox.exe",  L"--kiosk", L"-private-window" },
        { L"chrome.exe",   L"--kiosk", L"--incognito" },
        { L"chromium.exe", L"--kiosk", L"--incognito" },
        { L"brave.exe",    L"--kiosk", L"--incognito" },
        { L"msedge.exe",   L"--kiosk", L"--inprivate" },
    };
    const WCHAR *name = PathFindFileNameW(exe);
    UINT i;

    if (!args->kiosk && !args->inprivate)
        return FALSE;
    for (i = 0; i < ARRAYSIZE(browsers); i++)
    {
        if (!lstrcmpiW(name, browsers[i].exe))
        {
            *kiosk = args->kiosk ? browsers[i].kiosk : NULL;
            *inprivate = args->inprivate ? browsers[i].inprivate : NULL;
            return TRUE;
        }
    }
    return FALSE;
}

/* Copy the URL; before a closing quote its trailing backslashes are doubled, else the last one would escape the
 * quote (CommandLineToArgvW rules) and the rest of the command line would join the URL argument */
static WCHAR *append_url(WCHAR *o, const WCHAR *url, BOOL before_quote)
{
    int length = lstrlenW(url), i;

    memcpy(o, url, length * sizeof(WCHAR));
    o += length;
    if (before_quote)
        for (i = length; i > 0 && url[i - 1] == '\\'; i--)
            *o++ = '\\';
    return o;
}

/* The browser's command line: the quoted executable, then the rest of its open command with the URL for %1 / %L,
 * as ShellExecute fills it in. HeapFree it. */
static WCHAR *build_browser_command(const WCHAR *exe, const WCHAR *rest, const WCHAR *url, const IE_CMDLINE *args)
{
    const WCHAR *kiosk = NULL, *inprivate = NULL, *p;
    BOOL done = FALSE, quote;
    SIZE_T cch, url_length = lstrlenW(url);
    WCHAR *out, *o;

    cch = lstrlenW(exe) + lstrlenW(rest) + 64 + 2 * url_length + 4;
    for (p = rest; *p; p++)
        if (*p == '%') cch += 2 * url_length + 2;
    quote = url[0] && (strchrW(url, ' ') || strchrW(url, '\t'));

    out = HeapAlloc(GetProcessHeap(), 0, cch * sizeof(WCHAR));
    if (!out)
        return NULL;
    StringCchPrintfW(out, cch, L"\"%s\"", exe);
    o = out + lstrlenW(out);

    if (get_browser_switches(exe, args, &kiosk, &inprivate))
    {
        StringCchPrintfW(o, cch - (o - out), L"%s%s%s%s", kiosk ? L" " : L"", kiosk ? kiosk : L"",
                         inprivate ? L" " : L"", inprivate ? inprivate : L"");
        o += lstrlenW(o);
        if (url[0])
        {
            *o++ = ' ';
            *o++ = '"';
            o = append_url(o, url, TRUE);
            *o++ = '"';
        }
        *o = 0;
        return out;
    }
    if (!url[0])
    {
        /* no URL: the browser alone, not its "open a URL" switches with an empty argument */
        return out;
    }

    for (p = rest; *p; p++)
    {
        if (*p != '%')
        {
            *o++ = *p;
            continue;
        }
        switch (p[1])
        {
        case '1': case 'L': case 'l':
        {
            /* a URL with blanks in an unquoted %1 is quoted, so that it stays one argument */
            BOOL add_quotes = quote && o[-1] != '"';

            if (add_quotes) *o++ = '"';
            o = append_url(o, url, add_quotes || p[2] == '"');
            if (add_quotes) *o++ = '"';
            done = TRUE;
            p++;
            break;
        }
        case '%':
            *o++ = '%';
            p++;
            break;
        case '*': case '0': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
            /* no further arguments */
            p++;
            break;
        default:
            *o++ = '%';
            break;
        }
    }
    if (!done)
    {
        /* a command without %1 gets the URL appended, as ShellExecute does */
        *o++ = ' ';
        *o++ = '"';
        o = append_url(o, url, TRUE);
        *o++ = '"';
    }
    *o = 0;
    return out;
}

/* FALSE: the built-in browser has to do it (iexplore is the http handler, or the browser did not start) */
static BOOL open_in_default_browser(const IE_CMDLINE *args, int show)
{
    WCHAR command[MAX_PATH * 2], exe[MAX_PATH], stamp[16];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    const WCHAR *rest;
    WCHAR *url, *line;
    BOOL ret = FALSE;

    ZeroMemory(exe, sizeof(exe));
    if (!get_default_browser(command, ARRAYSIZE(command)))
        return FALSE;
    if (!split_command(command, exe, ARRAYSIZE(exe), &rest) || is_self(exe))
        return FALSE;
    url = get_url(args->url);
    if (!url)
        return FALSE;
    line = build_browser_command(exe, rest, url, args);
    if (line)
    {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = show;
        wsprintfW(stamp, L"%lu", GetTickCount());
        SetEnvironmentVariableW(redirect_var, stamp);
        /* a full path is started as itself, not searched for along the blanks of an unquoted command */
        if (CreateProcessW(is_absolute_file(exe) ? exe : NULL, line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            AllowSetForegroundWindow(pi.dwProcessId);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            ret = TRUE;
        }
        SetEnvironmentVariableW(redirect_var, NULL);
        HeapFree(GetProcessHeap(), 0, line);
    }
    HeapFree(GetProcessHeap(), 0, url);
    return ret;
}
#endif

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE prev, WCHAR *cmdline, int show)
{
    static const WCHAR regserverW[] = {'r','e','g','s','e','r','v','e','r',0};
    static const WCHAR unregserverW[] = {'u','n','r','e','g','s','e','r','v','e','r',0};

    if(*cmdline == '-' || *cmdline == '/') {
        if(!strcmpiW(cmdline+1, regserverW))
            return register_iexplore(TRUE);
        if(!strcmpiW(cmdline+1, unregserverW))
            return register_iexplore(FALSE);
    }

#ifdef __REACTOS__
    /* Not for COM activation, which has no user waiting for a window */
    if (!is_com_activation(cmdline))
    {
        IE_CMDLINE args;
        WCHAR *legacy;
        SIZE_T cch;
        DWORD ret;

        parse_ie_cmdline(cmdline, &args);
        if (!is_reentry() && open_in_default_browser(&args, show))
            return 0;

        /* the built-in browser, without the switches it does not know */
        if (!is_gecko_installed())
            install_gecko();
        cch = lstrlenW(args.url) + 16;
        legacy = HeapAlloc(GetProcessHeap(), 0, cch * sizeof(WCHAR));
        if (!legacy)
            return IEWinMain(cmdline, show);
        StringCchPrintfW(legacy, cch, L"%s%s", args.nohome ? L"-nohome " : L"", args.url);
        ret = IEWinMain(legacy, show);
        HeapFree(GetProcessHeap(), 0, legacy);
        return ret;
    }
#endif

    return IEWinMain(cmdline, show);
}
