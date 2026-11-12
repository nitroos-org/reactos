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
 * Nothing under persist\<app> is trusted (the tree is writable by standard users): no link is followed
 * (see WalkChain); a link anywhere on the path skips that app with a log line.
 * Default 2: WezTerm ("wezterm", "wezterm-nightly"): its bundled conpty.dll/OpenConsole.exe are renamed to
 * *.off so it uses the system ConPTY (same ConDrv reason; TODO CONSOLE-condrv-device). Default 3:
 * Alacritty gets %APPDATA%\alacritty\alacritty.toml (font the image ships, pwsh/cmd) when the user has none;
 * WezTerm also gets ~\.wezterm.lua (default_prog = pwsh) when the user has no WezTerm config.
 * Both are in the "Default 2 and 3" section below; they never follow links (reparse-point checks, CREATE_NEW).
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

#define EK_MAXDEPTH 64      /* deeper than this is not a settings file */

/* Ensure the top-level object of in[0..n) has a member "key". On ED_ADDED the out pointer and length describe a
 * HeapAlloc'd edited copy. Tested through the install hook (tests\roundtrip.cmd), not directly. */
static ED_RESULT EnsureKey(const char *in, size_t n, const char *key, const char *value, char **out, size_t *outLen)
{
    size_t i = 0, lastTok = (size_t)-1, closeAt = 0, klen = strlen(key);
    int depth = 0;
    char stack[EK_MAXDEPTH];                          /* the bracket that opened each level: '{' or '[' */
    BOOL crlf = (memchr(in, '\r', n) != NULL), haveMember = FALSE, expectKey = FALSE;
    const char *eol = crlf ? "\r\n" : "\n";
    char *o, *p;
    size_t ins;
    char entry[512];
    BOOL emptyDoc;

    *out = NULL; *outLen = 0;
    if (n && memchr(in, '\0', n)) return ED_BAD;      /* a NUL is never JSON text (UTF-16 without a BOM looks like this) */
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
                if (depth >= EK_MAXDEPTH) return ED_BAD;
                stack[depth] = in[i];
                depth++;
                if (depth == 1) expectKey = TRUE;
                else if (depth == 2) haveMember = TRUE;
                lastTok = i++;
                continue;
            }
            if (in[i] == '}' || in[i] == ']')
            {
                /* '}' closes only '{' and ']' only '[': a mismatch is not a JSON object */
                if (depth <= 0 || stack[depth - 1] != (in[i] == '}' ? '{' : '[')) return ED_BAD;
                depth--;
                if (depth == 0)
                {
                    size_t t = i + 1;
                    closeAt = i;
                    /* only blanks may follow the document */
                    if (!SkipBlank(in, n, &t) || t < n) return ED_BAD;
                    break;
                }
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

/* C:\scoop inherits the ACL of C:\ (a standard user may create folders there) and featmgr runs elevated, so
 * persist\<app> and everything below it is not trusted: a junction, symbolic link or mount point planted there
 * must not redirect a create, read, write or rename. Every component from "persist" down to the file is checked
 * (GetFileAttributes does not follow a link at the last component); a link anywhere refuses the whole app,
 * which is logged and skipped (first boot never fails because of it). What remains is the window between the
 * check and the use; the temp file is therefore created with CREATE_NEW and the chain is checked again right
 * before the rename. */

typedef enum { WALK_OK = 0, WALK_MISSING, WALK_LINK, WALK_ERR } WALK_RESULT;

/* Check (and with create: create) every directory of path below root, then the leaf. path must start with
 * root + '\\'. leafDir: the leaf is a directory (created when create is set), else a file (never created here,
 * and it must not be a directory). WALK_MISSING: something does not exist (only without create). */
static WALK_RESULT WalkChain(LPCWSTR root, LPCWSTR path, BOOL create, BOOL leafDir)
{
    WCHAR buf[MAX_PATH];
    size_t rl = wcslen(root), pl = wcslen(path), k;
    DWORD a;

    if (pl >= MAX_PATH || pl <= rl + 1 || _wcsnicmp(path, root, rl) || path[rl] != L'\\') return WALK_ERR;
    StringCchCopyW(buf, MAX_PATH, path);
    for (k = rl + 1; k <= pl; k++)
    {
        BOOL leaf = (k == pl);
        if (!leaf && buf[k] != L'\\') continue;
        if (!leaf) buf[k] = L'\0';
        a = GetFileAttributesW(buf);
        if (a == INVALID_FILE_ATTRIBUTES)
        {
            DWORD e = GetLastError();
            if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) return WALK_ERR;
            if (!create || (leaf && !leafDir)) return create ? WALK_OK : WALK_MISSING;
            if (!CreateDirectoryW(buf, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return WALK_ERR;
            a = GetFileAttributesW(buf);                    /* what was really created */
            if (a == INVALID_FILE_ATTRIBUTES) return WALK_ERR;
        }
        if (a & FILE_ATTRIBUTE_REPARSE_POINT) return WALK_LINK;
        if ((!leaf || leafDir) && !(a & FILE_ATTRIBUTE_DIRECTORY)) return WALK_ERR;
        if (leaf && !leafDir && (a & FILE_ATTRIBUTE_DIRECTORY)) return WALK_ERR;
        if (!leaf) buf[k] = L'\\';
    }
    return WALK_OK;
}

static void LogWalk(FILE *log, WALK_RESULT w, LPCWSTR path)
{
    if (w == WALK_LINK)
        LOGF(log, L"  note: %s is or lies below a link (junction/symbolic link); refused, its default was not set\n", path);
    else
        LOGF(log, L"  note: %s is not a plain folder/file chain; its default was not set\n", path);
}

/* *exists is FALSE when the file is not there. A link at the leaf is refused (WALK_LINK is checked by the caller;
 * the handle is opened with FILE_FLAG_OPEN_REPARSE_POINT and its attributes checked as well). */
static BOOL ReadFileAll(LPCWSTR path, char **buf, size_t *len, BOOL *exists)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BY_HANDLE_FILE_INFORMATION bi;
    LARGE_INTEGER sz;
    DWORD got = 0;
    *buf = NULL; *len = 0; *exists = FALSE;
    if (h == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
    *exists = TRUE;
    if (!GetFileInformationByHandle(h, &bi) || (bi.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)))
    { CloseHandle(h); return FALSE; }
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

/* Writes path through <path>.nitro-tmp. Refuses (FALSE, logged) when the folder chain, the temp name or the
 * target is a link. A leftover plain temp file from an interrupted run is removed first; a link there is not
 * touched. */
static BOOL WriteFileReplace(LPCWSTR root, LPCWSTR path, const char *bom, size_t nbom, const char *data, size_t len, FILE *log)
{
    WCHAR tmp[MAX_PATH];
    HANDLE h;
    DWORD w, a;
    WALK_RESULT wr;
    BOOL ok;

    if (FAILED(StringCchPrintfW(tmp, MAX_PATH, L"%s.nitro-tmp", path))) return FALSE;
    wr = WalkChain(root, tmp, FALSE, FALSE);               /* folders, and the temp name if it exists */
    if (wr == WALK_LINK || wr == WALK_ERR) { LogWalk(log, wr, tmp); return FALSE; }
    if (wr == WALK_OK && !DeleteFileW(tmp)) return FALSE;  /* a plain leftover of an earlier run */
    h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = (!nbom || (WriteFile(h, bom, (DWORD)nbom, &w, NULL) && w == nbom))
      && (!len || (WriteFile(h, data, (DWORD)len, &w, NULL) && w == (DWORD)len));
    CloseHandle(h);
    if (ok)
    {
        /* the chain and the target once more right before the rename */
        wr = WalkChain(root, tmp, FALSE, FALSE);
        if (wr != WALK_OK) { LogWalk(log, wr == WALK_MISSING ? WALK_ERR : wr, tmp); ok = FALSE; }
        else
        {
            wr = WalkChain(root, path, FALSE, FALSE);
            if (wr == WALK_LINK || wr == WALK_ERR) { LogWalk(log, wr, path); ok = FALSE; }
            else
            {
                a = GetFileAttributesW(path);
                ok = !(a != INVALID_FILE_ATTRIBUTES && (a & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)))
                     && MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING);
            }
        }
    }
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
    WALK_RESULT wr;

    if (FAILED(StringCchPrintfW(dir, MAX_PATH, L"%s\\persist\\%s\\data\\user-data\\User", root, d->App))
        || FAILED(StringCchPrintfW(file, MAX_PATH, L"%s\\settings.json", dir)))
    {
        LOGF(log, L"  note: the settings path of %s is too long; its default was not set\n", d->App);
        return;
    }
    wr = WalkChain(root, file, FALSE, FALSE);
    if (wr == WALK_LINK || wr == WALK_ERR)
    {
        LogWalk(log, wr, file);
        return;
    }
    if (!ReadFileAll(file, &buf, &len, &exists))
    {
        LOGF(log, L"  note: cannot read %s; its default was not set\n", file);
        return;
    }
    /* UTF-16: VS Code never writes it. With a BOM (FF FE / FE FF), and without one: JSON starts with an ASCII
     * character, so a NUL in the first two bytes is UTF-16LE or BE. */
    if (exists && len >= 2 && ((BYTE)buf[0] == 0xFF || (BYTE)buf[0] == 0xFE || buf[0] == 0 || buf[1] == 0))
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
        wr = WalkChain(root, dir, !exists, TRUE);          /* create what is missing, link by link; no link is followed */
        if (wr == WALK_LINK || wr == WALK_ERR)
            LogWalk(log, wr, dir);
        else if (wr == WALK_MISSING)
            LOGF(log, L"  note: %s vanished; its default was not set\n", dir);
        else if (WriteFileReplace(root, file, buf, skip, edited, elen, log))
            LOGF(log, L"  NitroOS default: %S = %S in %s (VS Code terminal; TODO CONSOLE-condrv-device)\n", d->Key, d->Value, file);
        else
            LOGF(log, L"  note: cannot write %s; its default was not set\n", file);
    }
    if (edited) HeapFree(GetProcessHeap(), 0, edited);
    if (buf) HeapFree(GetProcessHeap(), 0, buf);
}

/* ---- Default 2 and 3: WezTerm (system ConPTY) and Alacritty (font + shell) -------------------------
 *
 * These two change files that are NOT under persist, so a link or junction planted by an unprivileged
 * user must not redirect them: none of the operations below follows a reparse point. Every directory on
 * the way is checked for FILE_ATTRIBUTE_REPARSE_POINT first, files are created with CREATE_NEW (plus
 * FILE_FLAG_OPEN_REPARSE_POINT), and only regular files directly inside an app's version directory are
 * renamed. (The VS Code path above does the same for persist\<app> and below: WalkChain.)
 */

#define ATTR_BAD (INVALID_FILE_ATTRIBUTES)

/* TRUE when path exists and is a real directory (not a junction/link). */
static BOOL IsPlainDir(LPCWSTR path)
{
    DWORD a = GetFileAttributesW(path);
    return a != ATTR_BAD && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT);
}

/* TRUE when path exists as a regular file (not a directory, not a link). */
static BOOL IsPlainFile(LPCWSTR path)
{
    DWORD a = GetFileAttributesW(path);
    return a != ATTR_BAD && !(a & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}

/* Default 2: WezTerm loads the conpty.dll next to wezterm-gui.exe; that one opens \Device\ConDrv\Server,
 * which NitroOS lacks, so no shell can start ("failed to create psuedo console"). Without the file (and
 * its OpenConsole.exe) WezTerm uses kernel32's CreatePseudoConsole, which works. WezTerm has no setting
 * that selects the system ConPTY, so the two files are renamed to <name>.off, in every real version
 * directory of the app (the "current" junction is skipped: it leads to one of them). A scoop update puts
 * the files back in the NEW version directory; featmgr re-applies after each update it runs.
 * TODO(CONSOLE-condrv-device): delete this default together with the VS Code one. */
static void DisableBundledFile(LPCWSTR verDir, LPCWSTR name, FILE *log)
{
    WCHAR src[MAX_PATH], dst[MAX_PATH];

    if (FAILED(StringCchPrintfW(src, MAX_PATH, L"%s\\%s", verDir, name))
        || FAILED(StringCchPrintfW(dst, MAX_PATH, L"%s.off", src)))
        return;
    if (GetFileAttributesW(src) == ATTR_BAD) return;          /* already off, or this build has none */
    if (!IsPlainFile(src))
    {
        LOGF(log, L"  note: %s is not a regular file; left alone\n", src);
        return;
    }
    if (GetFileAttributesW(dst) != ATTR_BAD)
    {
        /* a leftover .off from an earlier version of the same directory: replace it only if it is a plain file */
        if (!IsPlainFile(dst) || !DeleteFileW(dst))
        {
            LOGF(log, L"  note: cannot replace %s; %s was not disabled\n", dst, src);
            return;
        }
    }
    if (MoveFileW(src, dst))
        LOGF(log, L"  NitroOS default: %s -> %s (WezTerm uses the system ConPTY; TODO CONSOLE-condrv-device)\n", src, dst);
    else
        LOGF(log, L"  note: cannot rename %s (error %lu; is WezTerm running?)\n", src, GetLastError());
}

/* PowerShell 7 path as UTF-8 when pwsh.exe is installed as a regular file (no quote or line break in it). */
static BOOL PwshUtf8(char *out, int cb)
{
    WCHAR pwsh[MAX_PATH];
    if (!FmPwshPath(pwsh, MAX_PATH) || !IsPlainFile(pwsh) || wcspbrk(pwsh, L"'\"\r\n]")) return FALSE;
    return WideCharToMultiByte(CP_UTF8, 0, pwsh, -1, out, cb, NULL, NULL) > 0;
}

/* Create path with CREATE_NEW (never overwrites, never follows a link at the last component) and write text. */
static BOOL WriteNewFile(LPCWSTR path, const char *text, FILE *log)
{
    DWORD w, n = (DWORD)strlen(text);
    BOOL ok;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        LOGF(log, L"  note: %s not written (error %lu)\n", path, GetLastError());
        return FALSE;
    }
    ok = WriteFile(h, text, n, &w, NULL) && w == n;
    CloseHandle(h);
    if (!ok) { DeleteFileW(path); LOGF(log, L"  note: cannot write %s\n", path); }
    return ok;
}

/* WezTerm's default shell is cmd.exe. When the user has no WezTerm config at all (WEZTERM_CONFIG_FILE,
 * ~\.config\wezterm\wezterm.lua, ~\.wezterm.lua) and pwsh is installed, write ~\.wezterm.lua that starts pwsh. */
static void WezTermConfig(FILE *log)
{
    WCHAR home[MAX_PATH], lua[MAX_PATH], xdg[MAX_PATH], tmp[8];
    char u8[MAX_PATH * 4], text[1024 + MAX_PATH * 4];

    if (GetEnvironmentVariableW(L"WEZTERM_CONFIG_FILE", tmp, ARRAYSIZE(tmp))) return;
    if (!GetEnvironmentVariableW(L"USERPROFILE", home, MAX_PATH) || !home[0]) return;
    if (FAILED(StringCchPrintfW(lua, MAX_PATH, L"%s\\.wezterm.lua", home))
        || FAILED(StringCchPrintfW(xdg, MAX_PATH, L"%s\\.config\\wezterm\\wezterm.lua", home)))
        return;
    if (GetFileAttributesW(lua) != ATTR_BAD || GetFileAttributesW(xdg) != ATTR_BAD)
    {
        LOGF(log, L"  WezTerm config present; left unchanged\n");
        return;
    }
    if (!IsPlainDir(home))
    {
        LOGF(log, L"  note: %s is a link; WezTerm shell default not written\n", home);
        return;
    }
    if (!PwshUtf8(u8, sizeof(u8))) return;                              /* no pwsh: WezTerm's cmd default is right */
    StringCchPrintfA(text, sizeof(text),
        "-- NitroOS default (featmgr), written because no WezTerm config existed. Replace it freely;\r\n"
        "-- featmgr never overwrites an existing config.\r\n"
        "local wezterm = require 'wezterm'\r\n"
        "local config = wezterm.config_builder()\r\n"
        "config.default_prog = { [[%s]] }\r\n"
        "return config\r\n", u8);
    if (WriteNewFile(lua, text, log))
        LOGF(log, L"  NitroOS default: %s (WezTerm starts pwsh)\n", lua);
}

static void HookWezTerm(LPCWSTR root, LPCWSTR app, FILE *log)
{
    WCHAR apps[MAX_PATH], appDir[MAX_PATH], pat[MAX_PATH], ver[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;

    if (FAILED(StringCchPrintfW(apps, MAX_PATH, L"%s\\apps", root))
        || FAILED(StringCchPrintfW(appDir, MAX_PATH, L"%s\\%s", apps, app))
        || FAILED(StringCchPrintfW(pat, MAX_PATH, L"%s\\*", appDir)))
        return;
    if (GetFileAttributesW(appDir) == ATTR_BAD) return;                /* not installed */
    if (!IsPlainDir(apps) || !IsPlainDir(appDir))
    {
        LOGF(log, L"  note: %s or its parent is a link; WezTerm default not applied\n", appDir);
        return;
    }
    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do
    {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            continue;                                                   /* files, and "current" (a junction) */
        if (FAILED(StringCchPrintfW(ver, MAX_PATH, L"%s\\%s", appDir, fd.cFileName))) continue;
        DisableBundledFile(ver, L"conpty.dll", log);
        DisableBundledFile(ver, L"OpenConsole.exe", log);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    WezTermConfig(log);
}

/* Default 3: Alacritty's default font on Windows is Consolas and its default shell is "powershell";
 * NitroOS has neither, so it prints "font ... not found" and exits. Write %APPDATA%\alacritty\alacritty.toml
 * when the user has no config (alacritty.toml or the legacy alacritty.yml) with a font the image ships
 * and pwsh (PowerShell 7) when installed, else cmd. An existing config is never touched: the file is
 * created with CREATE_NEW and the pre-checks only decide whether to try. */
static void HookAlacritty(LPCWSTR root, LPCWSTR app, FILE *log)
{
    WCHAR appdata[MAX_PATH], dir[MAX_PATH], toml[MAX_PATH], yml[MAX_PATH], fonts[MAX_PATH], f[MAX_PATH];
    const char *family = "Courier New";
    char text[1024 + MAX_PATH * 4], shell[MAX_PATH * 4 + 32];
    char u8[MAX_PATH * 4];
    DWORD adAttr;

    (void)root; (void)app;
    if (!GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH) || !appdata[0]) return;
    if (FAILED(StringCchPrintfW(dir, MAX_PATH, L"%s\\alacritty", appdata))
        || FAILED(StringCchPrintfW(toml, MAX_PATH, L"%s\\alacritty.toml", dir))
        || FAILED(StringCchPrintfW(yml, MAX_PATH, L"%s\\alacritty.yml", dir)))
        return;

    /* the user's own config, in any form (even a link): leave it */
    if (GetFileAttributesW(toml) != ATTR_BAD || GetFileAttributesW(yml) != ATTR_BAD)
    {
        LOGF(log, L"  %s: Alacritty config present; left unchanged\n", dir);
        return;
    }
    adAttr = GetFileAttributesW(dir);
    if (adAttr == ATTR_BAD)
    {
        if (!IsPlainDir(appdata))
        {
            LOGF(log, L"  note: %s is missing or a link; Alacritty default not written\n", appdata);
            return;
        }
        if (!CreateDirectoryW(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        {
            LOGF(log, L"  note: cannot create %s\n", dir);
            return;
        }
    }
    if (!IsPlainDir(dir))
    {
        LOGF(log, L"  note: %s is not a plain directory; Alacritty default not written\n", dir);
        return;
    }

    if (GetEnvironmentVariableW(L"SystemRoot", fonts, MAX_PATH) && fonts[0])
    {
        if (SUCCEEDED(StringCchPrintfW(f, MAX_PATH, L"%s\\Fonts\\lucon.ttf", fonts)) && IsPlainFile(f))
            family = "Lucida Console";
    }
    StringCchCopyA(shell, sizeof(shell), "program = \"cmd\"\r\n");
    if (PwshUtf8(u8, sizeof(u8)))
        StringCchPrintfA(shell, sizeof(shell), "program = '%s'\r\n", u8);   /* TOML literal string: no escapes */

    StringCchPrintfA(text, sizeof(text),
        "# NitroOS default (featmgr), written because no config existed. Delete this file or replace it freely;\r\n"
        "# featmgr never overwrites an existing alacritty.toml.\r\n"
        "# Alacritty's own defaults (font Consolas, shell powershell) are not on NitroOS.\r\n"
        "[font]\r\n"
        "normal = { family = \"%s\" }\r\n"
        "size = 9.0\r\n"
        "\r\n"
        "[terminal.shell]\r\n"
        "%s", family, shell);

    if (!WriteNewFile(toml, text, log)) return;
    LOGF(log, L"  NitroOS default: %s (font %S, %S)\n", toml, family, strstr(shell, "pwsh") ? "pwsh" : "cmd");
}

/* Default 4: Firefox from Scoop ("firefox", "firefox-esr", ...): the same Preferences policy as the MSI install gets
 * (media.wmf.media-engine.enabled = false as a default, see shelldefaults.c: no H.264 MFT, so mp4 plays through the
 * OpenH264 plugin). Merged into an existing distribution\policies.json. The apps\<app>\current folder is a new
 * version folder after a Scoop update: featmgr's update runs this hook again; a plain "scoop update" typed in a shell
 * does not (a featmgr /shell-defaults does not look into Scoop either). */
static void HookFirefox(LPCWSTR root, LPCWSTR app, FILE *log)
{
    WCHAR cur[MAX_PATH];
    StringCchPrintfW(cur, MAX_PATH, L"%s\\apps\\%s\\current", root, app);
    FmFirefoxPoliciesIn(cur, log);
}

typedef void (*APP_HOOK)(LPCWSTR root, LPCWSTR app, FILE *log);
static const struct { const WCHAR *App; APP_HOOK Fn; } g_Hooks[] =
{
    { L"wezterm",         HookWezTerm },
    { L"wezterm-nightly", HookWezTerm },
    { L"alacritty",       HookAlacritty },
    { L"firefox",         HookFirefox },
    { L"firefox-esr",     HookFirefox },
    { L"firefox-developer", HookFirefox },
};

/* After featmgr installed or updated Scoop app `app` (a NULL/unknown app is a no-op). */
void FmScoopAppDefaults(LPCWSTR app, FILE *log)
{
    WCHAR root[MAX_PATH], cur[MAX_PATH];
    size_t k;

    if (!app || !FmScoopValidApp(app) || !FmScoopRoot(root, MAX_PATH)) return;
    for (k = 0; k < ARRAYSIZE(g_Defaults); k++)
    {
        if (_wcsicmp(app, g_Defaults[k].App)) continue;
        if (FAILED(StringCchPrintfW(cur, MAX_PATH, L"%s\\apps\\%s\\current", root, app))) continue;
        if (GetFileAttributesW(cur) == INVALID_FILE_ATTRIBUTES) continue;   /* not installed */
        ApplyOne(root, &g_Defaults[k], log);
    }
    for (k = 0; k < ARRAYSIZE(g_Hooks); k++)
    {
        if (_wcsicmp(app, g_Hooks[k].App)) continue;
        if (FAILED(StringCchPrintfW(cur, MAX_PATH, L"%s\\apps\\%s\\current", root, app))) continue;
        if (GetFileAttributesW(cur) == INVALID_FILE_ATTRIBUTES) continue;   /* not installed */
        g_Hooks[k].Fn(root, g_Hooks[k].App, log);
    }
}

void FmScoopAppDefaultsAll(FILE *log)
{
    size_t k;
    for (k = 0; k < ARRAYSIZE(g_Defaults); k++) FmScoopAppDefaults(g_Defaults[k].App, log);
    for (k = 0; k < ARRAYSIZE(g_Hooks); k++) FmScoopAppDefaults(g_Hooks[k].App, log);
}

/* After featmgr installed Scoop itself: write the defaults ahead of any plain "scoop install <app>". */
void FmScoopAppDefaultsSeed(FILE *log)
{
    WCHAR root[MAX_PATH];
    size_t k;
    if (!FmScoopRoot(root, MAX_PATH)) return;
    for (k = 0; k < ARRAYSIZE(g_Defaults); k++) ApplyOne(root, &g_Defaults[k], log);
    /* only the Alacritty config can be written ahead of the app; the WezTerm files do not exist yet */
    for (k = 0; k < ARRAYSIZE(g_Hooks); k++)
        if (!_wcsicmp(g_Hooks[k].App, L"alacritty")) g_Hooks[k].Fn(root, g_Hooks[k].App, log);
}
