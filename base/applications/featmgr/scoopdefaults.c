/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager (FEATMGMT-01)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NitroOS per-app defaults for Scoop apps installed or updated through featmgr.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * THIS FILE IS THE ONE PLACE that carries the NitroOS default below. To remove it: delete this file,
 * its two entries in CMakeLists.txt, the FmScoopAppDefaults declaration in featmgr.h and the three
 * calls in engine.c (SoftwareInstall, FmUpdateInner, FmUpdateAll).
 *
 * Default 1: VS Code (Scoop apps "vscode" and "vscode-insiders") gets
 *     "terminal.integrated.windowsUseConptyDll": false
 * VS Code's own default is true; that path loads the bundled conpty.dll, whose
 * ConptyCreatePseudoConsole opens \Device\ConDrv\Server. NitroOS has no such device yet, so the
 * integrated terminal fails with "Cannot launch conpty". With the setting false VS Code uses
 * kernel32's CreatePseudoConsole, which works (ade562701a0).
 * TODO(CONSOLE-condrv-device): delete this default once \Device\ConDrv and an NT10 console-server
 * conhost exist and the bundled conpty.dll path works.
 *
 * How: Scoop's vscode is portable; its settings live in
 *     <scoop>\persist\<app>\data\user-data\User\settings.json
 * (apps\<app>\current\data is a link to persist\<app>\data). The key is added ONLY when the file does
 * not already contain it at the top level, so a value the user (or VS Code) wrote, true or false, is never
 * touched. settings.json is JSON with comments: the file is not parsed into a tree and written back.
 * The text is scanned (strings, // and block comments skipped) and one member is spliced in before
 * the closing brace; everything else stays byte for byte (BOM, comments, indentation, line ends,
 * trailing commas). A file that does not look like one JSON object is left alone.
 * "scoop install" typed in a shell does not run featmgr. So when featmgr installs Scoop itself it also
 * seeds the persist directory of each app in the table (FmScoopAppDefaultsSeed): Scoop's persist step
 * reuses an existing persist\<app>\data, so a later plain "scoop install extras/vscode" finds the setting
 * already in place. The seeded file stays after "scoop uninstall" (Scoop keeps persist data), as any
 * persisted setting does.
 */

#include "featmgr.h"
#include <strsafe.h>

#define LOGF(log, ...) do { if (log) { fwprintf((log), __VA_ARGS__); fflush(log); } } while (0)

typedef struct { const WCHAR *App; const char *Key; const char *Value; } APP_DEFAULT;

static const APP_DEFAULT g_Defaults[] =
{
    { L"vscode",          "terminal.integrated.windowsUseConptyDll", "false" },
    { L"vscode-insiders", "terminal.integrated.windowsUseConptyDll", "false" },
};

#define NITRO_NOTE "NitroOS default (featmgr): VS Code's conpty.dll path needs \\Device\\ConDrv, which NitroOS lacks (TODO CONSOLE-condrv-device). Set it to true to use the VS Code default."

/* ---- JSON-with-comments splice ------------------------------------------------ */

/* Skips whitespace and comments at s[*i]. Returns FALSE on an unterminated block comment. */
static BOOL SkipBlank(const char *s, size_t n, size_t *i)
{
    for (;;)
    {
        while (*i < n && (s[*i] == ' ' || s[*i] == '\t' || s[*i] == '\r' || s[*i] == '\n')) (*i)++;
        if (*i + 1 < n && s[*i] == '/' && s[*i + 1] == '/')
        {
            while (*i < n && s[*i] != '\n') (*i)++;
        }
        else if (*i + 1 < n && s[*i] == '/' && s[*i + 1] == '*')
        {
            *i += 2;
            while (*i + 1 < n && !(s[*i] == '*' && s[*i + 1] == '/')) (*i)++;
            if (*i + 1 >= n) return FALSE;
            *i += 2;
        }
        else
            return TRUE;
    }
}

/* s[*i] == '"': advance past the string. FALSE when unterminated (or a raw newline: invalid JSON). */
static BOOL SkipString(const char *s, size_t n, size_t *i)
{
    (*i)++;
    while (*i < n)
    {
        if (s[*i] == '\\') { *i += 2; continue; }
        if (s[*i] == '\n') return FALSE;
        if (s[*i] == '"') { (*i)++; return TRUE; }
        (*i)++;
    }
    return FALSE;
}

typedef enum { ED_ADDED = 0, ED_PRESENT, ED_BAD } ED_RESULT;

/* Ensure the top-level object of in[0..n) has a member "key". On ED_ADDED the out pointer and length describe a
 * HeapAlloc'd edited copy. Tested through the install hook (tests\roundtrip.cmd), not directly. */
static ED_RESULT EnsureKey(const char *in, size_t n, const char *key, const char *value, char **out, size_t *outLen)
{
    size_t i = 0, lastTok = (size_t)-1, closeAt = 0, klen = strlen(key);
    int depth = 0;
    BOOL crlf = (memchr(in, '\r', n) != NULL), haveMember = FALSE, expectKey = FALSE;
    const char *eol = crlf ? "\r\n" : "\n";
    char *o, *p;
    size_t ins;
    char entry[512];
    BOOL emptyDoc;

    *out = NULL; *outLen = 0;
    /* locate the opening brace; an empty or comment-only file gets a fresh object */
    if (!SkipBlank(in, n, &i)) return ED_BAD;
    emptyDoc = (i >= n);
    if (!emptyDoc && in[i] != '{') return ED_BAD;

    if (!emptyDoc)
    {
        for (;;)
        {
            if (!SkipBlank(in, n, &i)) return ED_BAD;
            if (i >= n) return ED_BAD;               /* no closing brace */
            if (in[i] == '"')
            {
                size_t b = i;
                if (!SkipString(in, n, &i)) return ED_BAD;
                if (depth == 1 && expectKey)
                {
                    /* raw comparison: the key has no characters that JSON would escape */
                    if (i - b - 2 == klen && !memcmp(in + b + 1, key, klen)) return ED_PRESENT;
                    expectKey = FALSE;
                }
                if (depth == 1) haveMember = TRUE;
                lastTok = i - 1;
                continue;
            }
            if (in[i] == '{' || in[i] == '[')
            {
                depth++;
                if (depth == 1) expectKey = TRUE;
                else if (depth == 2) haveMember = TRUE;
                lastTok = i++;
                continue;
            }
            if (in[i] == '}' || in[i] == ']')
            {
                depth--;
                if (depth == 0)
                {
                    size_t t = i + 1;
                    closeAt = i;
                    /* only blanks may follow the document */
                    if (!SkipBlank(in, n, &t) || t < n) return ED_BAD;
                    break;
                }
                if (depth < 0) return ED_BAD;
                lastTok = i++;
                continue;
            }
            if (in[i] == ',')
            {
                if (depth == 1) expectKey = TRUE;
                lastTok = i++;
                continue;
            }
            /* number / literal / ':' */
            if (depth == 1 && in[i] != ':') haveMember = TRUE;
            lastTok = i++;
        }
    }

    {
        /* the entry: a note line (JSONC allows comments) + the member */
        BOOL multiline = TRUE;
        BOOL needComma;
        size_t ls = closeAt, el, total;

        if (!emptyDoc)
        {
            while (ls > 0 && (in[ls - 1] == ' ' || in[ls - 1] == '\t')) ls--;
            multiline = (ls == 0 || in[ls - 1] == '\n');
        }
        if (multiline)
            StringCchPrintfA(entry, sizeof(entry), "    // " NITRO_NOTE "%s    \"%s\": %s%s", eol, key, value, eol);
        else
            StringCchPrintfA(entry, sizeof(entry), " \"%s\": %s", key, value);
        el = strlen(entry);

        if (emptyDoc)
        {
            /* keep what is there (blank / comments), then a fresh object */
            size_t eln = strlen(eol);
            total = n + eln + el + 2 * eln + 4;
            o = (char *)HeapAlloc(GetProcessHeap(), 0, total);
            if (!o) return ED_BAD;
            memcpy(o, in, n); p = o + n;
            if (n && in[n - 1] != '\n') { memcpy(p, eol, eln); p += eln; }
            *p++ = '{'; memcpy(p, eol, eln); p += eln;
            memcpy(p, entry, el); p += el;
            *p++ = '}'; memcpy(p, eol, eln); p += eln;
            *out = o; *outLen = (size_t)(p - o);
            return ED_ADDED;
        }

        ins = multiline ? ls : closeAt;
        /* a comma after the last token unless the object has no member or that token already is a comma */
        needComma = haveMember && lastTok != (size_t)-1 && in[lastTok] != ',' && in[lastTok] != '{';
        total = n + el + 2;
        o = (char *)HeapAlloc(GetProcessHeap(), 0, total);
        if (!o) return ED_BAD;
        p = o;
        if (needComma)
        {
            memcpy(p, in, lastTok + 1); p += lastTok + 1;
            *p++ = ',';
            memcpy(p, in + lastTok + 1, ins - (lastTok + 1)); p += ins - (lastTok + 1);
        }
        else
        {
            memcpy(p, in, ins); p += ins;
        }
        memcpy(p, entry, el); p += el;
        memcpy(p, in + ins, n - ins); p += n - ins;
        *out = o; *outLen = (size_t)(p - o);
        return ED_ADDED;
    }
}

/* ---- file side ------------------------------------------------------------------ */

static BOOL MakeDirs(LPWSTR path)    /* creates every missing directory of path (a directory path) */
{
    WCHAR *p;
    for (p = path + 3; *p; p++)
    {
        if (*p == L'\\')
        {
            *p = L'\0';
            if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) { *p = L'\\'; return FALSE; }
            *p = L'\\';
        }
    }
    return CreateDirectoryW(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

static BOOL ReadFileAll(LPCWSTR path, char **buf, size_t *len, BOOL *exists)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER sz;
    DWORD got = 0;
    *buf = NULL; *len = 0; *exists = FALSE;
    if (h == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
    *exists = TRUE;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart > 4 * 1024 * 1024) { CloseHandle(h); return FALSE; }
    *buf = (char *)HeapAlloc(GetProcessHeap(), 0, (size_t)sz.QuadPart + 1);
    if (!*buf) { CloseHandle(h); return FALSE; }
    if (sz.QuadPart && (!ReadFile(h, *buf, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart))
    {
        CloseHandle(h); HeapFree(GetProcessHeap(), 0, *buf); *buf = NULL; return FALSE;
    }
    CloseHandle(h);
    *len = got;
    return TRUE;
}

static BOOL WriteFileReplace(LPCWSTR path, const char *bom, size_t nbom, const char *data, size_t len)
{
    WCHAR tmp[MAX_PATH];
    HANDLE h;
    DWORD w;
    BOOL ok;
    if (FAILED(StringCchPrintfW(tmp, MAX_PATH, L"%s.nitro-tmp", path))) return FALSE;
    h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = (!nbom || (WriteFile(h, bom, (DWORD)nbom, &w, NULL) && w == nbom))
      && (!len || (WriteFile(h, data, (DWORD)len, &w, NULL) && w == (DWORD)len));
    CloseHandle(h);
    if (ok) ok = MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING);
    if (!ok) DeleteFileW(tmp);
    return ok;
}

static void ApplyOne(LPCWSTR root, const APP_DEFAULT *d, FILE *log)
{
    WCHAR dir[MAX_PATH], file[MAX_PATH];
    char *buf, *edited = NULL;
    size_t len, elen = 0, skip = 0;
    BOOL exists;
    ED_RESULT r;

    StringCchPrintfW(dir, MAX_PATH, L"%s\\persist\\%s\\data\\user-data\\User", root, d->App);
    StringCchPrintfW(file, MAX_PATH, L"%s\\settings.json", dir);
    if (!ReadFileAll(file, &buf, &len, &exists))
    {
        LOGF(log, L"  note: cannot read %s; its default was not set\n", file);
        return;
    }
    if (exists && len >= 2 && ((BYTE)buf[0] == 0xFF || (BYTE)buf[0] == 0xFE))   /* UTF-16: VS Code never writes it */
    {
        LOGF(log, L"  note: %s is UTF-16; left unchanged\n", file);
        HeapFree(GetProcessHeap(), 0, buf);
        return;
    }
    if (exists && len >= 3 && (BYTE)buf[0] == 0xEF && (BYTE)buf[1] == 0xBB && (BYTE)buf[2] == 0xBF) skip = 3;
    r = EnsureKey(buf ? buf + skip : "", len - skip, d->Key, d->Value, &edited, &elen);
    if (r == ED_PRESENT)
        LOGF(log, L"  %s keeps its own %S\n", file, d->Key);
    else if (r == ED_BAD)
        LOGF(log, L"  note: %s is not a JSON object; left unchanged (set %S to %S by hand)\n", file, d->Key, d->Value);
    else
    {
        if (!exists && !MakeDirs(dir))
            LOGF(log, L"  note: cannot create %s\n", dir);
        else if (WriteFileReplace(file, buf, skip, edited, elen))
            LOGF(log, L"  NitroOS default: %S = %S in %s (VS Code terminal; TODO CONSOLE-condrv-device)\n", d->Key, d->Value, file);
        else
            LOGF(log, L"  note: cannot write %s; its default was not set\n", file);
    }
    if (edited) HeapFree(GetProcessHeap(), 0, edited);
    if (buf) HeapFree(GetProcessHeap(), 0, buf);
}

/* After featmgr installed or updated Scoop app `app` (a NULL/unknown app is a no-op). */
void FmScoopAppDefaults(LPCWSTR app, FILE *log)
{
    WCHAR root[MAX_PATH], cur[MAX_PATH];
    size_t k;

    if (!app || !FmScoopValidApp(app) || !FmScoopRoot(root, MAX_PATH)) return;
    for (k = 0; k < ARRAYSIZE(g_Defaults); k++)
    {
        if (_wcsicmp(app, g_Defaults[k].App)) continue;
        StringCchPrintfW(cur, MAX_PATH, L"%s\\apps\\%s\\current", root, app);
        if (GetFileAttributesW(cur) == INVALID_FILE_ATTRIBUTES) continue;   /* not installed */
        ApplyOne(root, &g_Defaults[k], log);
    }
}

void FmScoopAppDefaultsAll(FILE *log)
{
    size_t k;
    for (k = 0; k < ARRAYSIZE(g_Defaults); k++) FmScoopAppDefaults(g_Defaults[k].App, log);
}

/* After featmgr installed Scoop itself: write the defaults ahead of any plain "scoop install <app>". */
void FmScoopAppDefaultsSeed(FILE *log)
{
    WCHAR root[MAX_PATH];
    size_t k;
    if (!FmScoopRoot(root, MAX_PATH)) return;
    for (k = 0; k < ARRAYSIZE(g_Defaults); k++) ApplyOne(root, &g_Defaults[k], log);
}
