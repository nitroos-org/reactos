/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager (FEATMGMT-01)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Scoop integration (SCOOP-FEATMGR-01): Scoop root/state helpers and the
 *              bucket -> software-tier catalog converter (featmgr /import-scoop).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * featmgr does not interpret or download Scoop payloads. It reads the JSON manifests of a
 * bucket that already exists on disk (<root>\buckets\<bucket>\bucket\*.json), keeps only
 * the descriptive fields, and writes one Catalog\Software\<id>.ini per app:
 *
 *   [Feature]  Id Name Description Version Tier=software Dependencies=scoop
 *   [Install]  Provider=scoop
 *   [Scoop]    App Bucket Homepage License Verified
 *
 * Install / uninstall of such an entry shells out to "scoop install|uninstall <bucket>/<app>"
 * (engine.c), so Scoop's own hash verification, extraction and shims stay in charge.
 */

#include "featmgr.h"
#include <shlwapi.h>
#include <shlobj.h>
#include <strsafe.h>

#define LOGF(log, ...) do { if (log) { fwprintf((log), __VA_ARGS__); fflush(log); } } while (0)
/* an error goes to the log stream (CLI) and to the last-message buffer (GUI) */
#define ERRF(log, ...) do { LOGF(log, __VA_ARGS__); FmSetLastMessage(__VA_ARGS__); } while (0)

#if defined(_M_AMD64)
#define FM_SCOOP_SUPPORTED 1
#else
#define FM_SCOOP_SUPPORTED 0
#endif

static const WCHAR ENV_KEY[] = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";

/* ---- root / layout ------------------------------------------------------- */

BOOL FmScoopSupported(void)
{
    return FM_SCOOP_SUPPORTED;
}

/* Scoop root: FEATMGR_SCOOP_ROOT (test hook, checked builds), else the machine SCOOP variable that the
 * scoop feature sets, else %SystemDrive%\scoop. The per-user environment is ignored on
 * purpose: the root must be the same for every user and for the featmgr process. */
BOOL FmScoopRoot(LPWSTR buf, DWORD cch)
{
    WCHAR v[MAX_PATH], x[MAX_PATH];
    HKEY k;
    DWORD cb, type;

    if (FmTestEnv(L"FEATMGR_SCOOP_ROOT", v, MAX_PATH) && v[0])
        return SUCCEEDED(StringCchCopyW(buf, cch, v));

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ENV_KEY, 0, KEY_READ, &k) == ERROR_SUCCESS)
    {
        cb = sizeof(v) - sizeof(WCHAR);
        v[0] = L'\0';
        if (RegQueryValueExW(k, L"SCOOP", NULL, &type, (LPBYTE)v, &cb) == ERROR_SUCCESS
            && (type == REG_SZ || type == REG_EXPAND_SZ) && v[0])
        {
            v[ARRAYSIZE(v) - 1] = L'\0';
            RegCloseKey(k);
            if (type == REG_EXPAND_SZ && ExpandEnvironmentStringsW(v, x, MAX_PATH))
                return SUCCEEDED(StringCchCopyW(buf, cch, x));
            return SUCCEEDED(StringCchCopyW(buf, cch, v));
        }
        RegCloseKey(k);
    }
    if (!GetEnvironmentVariableW(L"SystemDrive", v, MAX_PATH) || !v[0])
    {
        if (!GetWindowsDirectoryW(v, MAX_PATH) || !v[0] || v[1] != L':') return FALSE;
        v[2] = L'\0';
    }
    return SUCCEEDED(StringCchPrintfW(buf, cch, L"%s\\scoop", v));
}

BOOL FmPwshPath(LPWSTR buf, DWORD cch)
{
    WCHAR pf[MAX_PATH];
    if (!GetEnvironmentVariableW(L"ProgramFiles", pf, MAX_PATH) || !pf[0]) return FALSE;
    return SUCCEEDED(StringCchPrintfW(buf, cch, L"%s\\PowerShell\\7\\pwsh.exe", pf));
}

/* An app name / bucket name ends up in a file name, an id and a command line. */
static BOOL ValidName(LPCWSTR s, size_t maxLen)
{
    size_t n = wcslen(s), i;
    if (!n || n > maxLen) return FALSE;
    for (i = 0; i < n; i++)
    {
        WCHAR c = s[i];
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9')
              || c == L'-' || c == L'_' || c == L'.' || c == L'+'))
            return FALSE;
    }
    return s[0] != L'.';
}

BOOL FmScoopValidApp(LPCWSTR s)    { return ValidName(s, 48); }
BOOL FmScoopValidBucket(LPCWSTR s) { return ValidName(s, 24); }

static BOOL IsOfficialBucket(LPCWSTR b)
{
    return !_wcsicmp(b, L"main") || !_wcsicmp(b, L"extras");
}

/* <root>\apps\<app>\current : the junction Scoop keeps for an installed app. */
BOOL FmScoopAppInstalled(LPCWSTR app)
{
    WCHAR root[MAX_PATH], p[MAX_PATH];
    if (!FmScoopValidApp(app) || !FmScoopRoot(root, MAX_PATH)) return FALSE;
    StringCchPrintfW(p, MAX_PATH, L"%s\\apps\\%s\\current", root, app);
    return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
}

/* "scoop install" works once the Scoop shim exists, or when the scoop feature is in the
 * catalog (installing the app then installs Scoop first through the dependency). */
BOOL FmScoopUsable(void)
{
    WCHAR root[MAX_PATH], p[MAX_PATH];
    if (!FM_SCOOP_SUPPORTED) return FALSE;
    if (FmScoopRoot(root, MAX_PATH))
    {
        StringCchPrintfW(p, MAX_PATH, L"%s\\shims\\scoop.cmd", root);
        if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES) return TRUE;
    }
    if (FmGetCatalogDir(root, MAX_PATH))
    {
        StringCchPrintfW(p, MAX_PATH, L"%s\\scoop.ini", root);
        if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES) return TRUE;
    }
    return FALSE;
}

/* The command line that runs "scoop <args>". Production: PowerShell 7 runs Scoop's own shim
 * script directly. (M1 avoided Scoop's scoop.cmd shim because nitro's cmd did not return the
 * code of "exit /b"; that is fixed on main now, but the .ps1 entry point is still simpler and
 * stricter: no cmd.exe layer, no batch quoting, one process less. Kept on purpose.) Test hook (checked builds):
 * FEATMGR_SCOOP_RUNNER = a .cmd that stands in for Scoop (used by tests\roundtrip.cmd).
 * args is built by the callers from validated parts only (app / bucket names, https URLs). */
BOOL FmScoopCommandArgs(LPCWSTR args, LPWSTR out, DWORD cch)
{
    WCHAR root[MAX_PATH], runner[MAX_PATH], pwsh[MAX_PATH];
    if (!FmScoopRoot(root, MAX_PATH) || wcspbrk(root, L"\"%\r\n")) return FALSE;
    if (!args[0] || wcspbrk(args, L"\"%\r\n&|<>^")) return FALSE;
    if (FmTestEnv(L"FEATMGR_SCOOP_RUNNER", runner, MAX_PATH) && runner[0] && !wcspbrk(runner, L"\"%\r\n"))
        return SUCCEEDED(StringCchPrintfW(out, cch, L"cmd.exe /c \"\"%s\" %s\"", runner, args));
    if (!FmPwshPath(pwsh, MAX_PATH)) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch,
        L"\"%s\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%s\\shims\\scoop.ps1\" %s",
        pwsh, root, args));
}

/* "scoop <verb> <bucket>/<app>" */
BOOL FmScoopCommand(LPCWSTR verb, LPCWSTR bucket, LPCWSTR app, LPWSTR out, DWORD cch)
{
    WCHAR args[160];
    if (!FmScoopValidApp(app) || !FmScoopValidBucket(bucket)) return FALSE;
    if (FAILED(StringCchPrintfW(args, ARRAYSIZE(args), L"%s %s/%s", verb, bucket, app))) return FALSE;
    return FmScoopCommandArgs(args, out, cch);
}

/* https URL for "scoop bucket add <name> <url>": a conservative character set, nothing a shell
 * or a command line would treat specially. */
BOOL FmScoopValidUrl(LPCWSTR url)
{
    size_t n = wcslen(url), i;
    if (n < 12 || n > 200 || _wcsnicmp(url, L"https://", 8)) return FALSE;
    for (i = 0; i < n; i++)
    {
        WCHAR c = url[i];
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9')
              || wcschr(L"._~:/?#@!*+,=-", c)))
            return FALSE;
    }
    return TRUE;
}

/* featmgr's own environment is stale right after it installed PowerShell 7 / Scoop
 * (the registry PATH changed, this process did not see it): give the child what it needs. */
void FmScoopPrepareEnv(void)
{
    WCHAR root[MAX_PATH], pw[MAX_PATH], old[32768], np[32768 + 2 * MAX_PATH];
    DWORD n;

    if (!FmScoopRoot(root, MAX_PATH)) return;
    SetEnvironmentVariableW(L"SCOOP", root);
    old[0] = L'\0';
    n = GetEnvironmentVariableW(L"PATH", old, ARRAYSIZE(old));
    if (n >= ARRAYSIZE(old)) old[0] = L'\0';
    StringCchPrintfW(np, ARRAYSIZE(np), L"%s\\shims;", root);
    if (FmPwshPath(pw, MAX_PATH))
    {
        PathRemoveFileSpecW(pw);
        StringCchCatW(np, ARRAYSIZE(np), pw);
        StringCchCatW(np, ARRAYSIZE(np), L";");
    }
    StringCchCatW(np, ARRAYSIZE(np), old);
    SetEnvironmentVariableW(L"PATH", np);
}

/* TRUE if the volume that holds path is NTFS (Scoop needs junctions). fs receives the name. */
BOOL FmVolumeIsNtfs(LPCWSTR path, LPWSTR fs, DWORD cchFs)
{
    WCHAR vol[4];
    WCHAR name[32];
    if (fs && cchFs) fs[0] = L'\0';
    if (!path[0] || path[1] != L':') return TRUE;       /* UNC / unknown: do not block */
    vol[0] = path[0]; vol[1] = L':'; vol[2] = L'\\'; vol[3] = L'\0';
    name[0] = L'\0';
    if (!GetVolumeInformationW(vol, NULL, 0, NULL, NULL, NULL, name, ARRAYSIZE(name)))
        return TRUE;                                     /* cannot tell: let the installer decide */
    if (fs && cchFs) StringCchCopyW(fs, cchFs, name);
    return !_wcsicmp(name, L"NTFS");
}

/* ---- minimal JSON reader (UTF-8) ---------------------------------------- */

typedef struct _JS { const char *p, *e; } JS;
typedef BOOL (*MEMBER_CB)(void *ctx, const char *key, JS *j, int depth);

#define JS_MAXDEPTH 32

static void JWs(JS *j)
{
    while (j->p < j->e && (*j->p == ' ' || *j->p == '\t' || *j->p == '\r' || *j->p == '\n')) j->p++;
}

static void PutUtf8(unsigned cp, char *out, size_t cap, size_t *n)
{
    char t[4];
    int l, i;
    if (cp < 0x80) { t[0] = (char)cp; l = 1; }
    else if (cp < 0x800) { t[0] = (char)(0xC0 | (cp >> 6)); t[1] = (char)(0x80 | (cp & 0x3F)); l = 2; }
    else if (cp < 0x10000) { t[0] = (char)(0xE0 | (cp >> 12)); t[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
                             t[2] = (char)(0x80 | (cp & 0x3F)); l = 3; }
    else { t[0] = (char)(0xF0 | (cp >> 18)); t[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
           t[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); t[3] = (char)(0x80 | (cp & 0x3F)); l = 4; }
    if (!out) return;
    if (*n + l >= cap) return;             /* truncate, always keep room for the NUL */
    for (i = 0; i < l; i++) out[(*n)++] = t[i];
}

static int Hex4(const char *p, const char *e, unsigned *v)
{
    int i;
    *v = 0;
    if (e - p < 4) return 0;
    for (i = 0; i < 4; i++)
    {
        char c = p[i];
        *v <<= 4;
        if (c >= '0' && c <= '9') *v |= c - '0';
        else if (c >= 'a' && c <= 'f') *v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') *v |= c - 'A' + 10;
        else return 0;
    }
    return 1;
}

/* Parse a string at j->p ('"'). out == NULL skips it. */
static BOOL JStr(JS *j, char *out, size_t cap)
{
    size_t n = 0;
    if (j->p >= j->e || *j->p != '"') return FALSE;
    j->p++;
    while (j->p < j->e && *j->p != '"')
    {
        unsigned char c = (unsigned char)*j->p++;
        if (c == '\\')
        {
            char x;
            if (j->p >= j->e) return FALSE;
            x = *j->p++;
            switch (x)
            {
                case 'n': PutUtf8('\n', out, cap, &n); break;
                case 't': PutUtf8('\t', out, cap, &n); break;
                case 'r': PutUtf8('\r', out, cap, &n); break;
                case 'b': PutUtf8('\b', out, cap, &n); break;
                case 'f': PutUtf8('\f', out, cap, &n); break;
                case 'u':
                {
                    unsigned u, lo;
                    if (!Hex4(j->p, j->e, &u)) return FALSE;
                    j->p += 4;
                    if (u >= 0xD800 && u < 0xDC00 && j->e - j->p >= 6 && j->p[0] == '\\' && j->p[1] == 'u'
                        && Hex4(j->p + 2, j->e, &lo) && lo >= 0xDC00 && lo < 0xE000)
                    {
                        u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                        j->p += 6;
                    }
                    PutUtf8(u, out, cap, &n);
                    break;
                }
                default: PutUtf8((unsigned char)x, out, cap, &n); break;   /* \" \\ \/ */
            }
        }
        else if (out)
        {
            if (n + 1 < cap) out[n++] = (char)c;
        }
    }
    if (j->p >= j->e) return FALSE;
    j->p++;                                   /* closing quote */
    if (out && cap) out[n < cap ? n : cap - 1] = '\0';
    return TRUE;
}

static BOOL JSkip(JS *j, int depth);

static BOOL JObject(JS *j, MEMBER_CB cb, void *ctx, int depth)
{
    char key[96];
    if (depth > JS_MAXDEPTH || j->p >= j->e || *j->p != '{') return FALSE;
    j->p++;
    JWs(j);
    if (j->p < j->e && *j->p == '}') { j->p++; return TRUE; }
    for (;;)
    {
        JWs(j);
        if (!JStr(j, key, sizeof(key))) return FALSE;
        JWs(j);
        if (j->p >= j->e || *j->p != ':') return FALSE;
        j->p++;
        JWs(j);
        if (cb ? !cb(ctx, key, j, depth + 1) : !JSkip(j, depth + 1)) return FALSE;
        JWs(j);
        if (j->p >= j->e) return FALSE;
        if (*j->p == ',') { j->p++; continue; }
        if (*j->p == '}') { j->p++; return TRUE; }
        return FALSE;
    }
}

static BOOL JSkip(JS *j, int depth)
{
    if (depth > JS_MAXDEPTH) return FALSE;
    JWs(j);
    if (j->p >= j->e) return FALSE;
    switch (*j->p)
    {
        case '"': return JStr(j, NULL, 0);
        case '{': return JObject(j, NULL, NULL, depth);
        case '[':
            j->p++;
            JWs(j);
            if (j->p < j->e && *j->p == ']') { j->p++; return TRUE; }
            for (;;)
            {
                if (!JSkip(j, depth + 1)) return FALSE;
                JWs(j);
                if (j->p >= j->e) return FALSE;
                if (*j->p == ',') { j->p++; continue; }
                if (*j->p == ']') { j->p++; return TRUE; }
                return FALSE;
            }
        default:
        {
            const char *s = j->p;
            while (j->p < j->e && *j->p != ',' && *j->p != '}' && *j->p != ']'
                   && *j->p != ' ' && *j->p != '\t' && *j->p != '\r' && *j->p != '\n')
                j->p++;
            return j->p > s;                          /* number / true / false / null */
        }
    }
}

/* Is the value at j non-empty (string with text, or a non-empty array/object)? Consumes it. */
static BOOL JNonEmpty(JS *j, BOOL *nonEmpty)
{
    const char *s;
    JWs(j);
    s = j->p;
    if (!JSkip(j, 1)) return FALSE;
    JWs(j);
    if (j->p - s <= 2 && (s[0] == '"' || s[0] == '[' || s[0] == '{')) *nonEmpty = FALSE;
    else *nonEmpty = TRUE;
    return TRUE;
}

typedef struct _ARCHINFO { BOOL url, hash; } ARCHINFO;

typedef struct _MANI
{
    char version[64], desc[1024], homepage[512], license[128];
    BOOL topUrl, topHash;
    ARCHINFO a[3];                     /* 64bit, 32bit, arm64 */
} MANI;

static BOOL CbArchBlock(void *ctx, const char *key, JS *j, int depth)
{
    ARCHINFO *a = (ARCHINFO *)ctx;
    BOOL ne;
    UNREFERENCED_PARAMETER(depth);
    if (!strcmp(key, "url"))  { if (!JNonEmpty(j, &ne)) return FALSE; if (ne) a->url = TRUE; return TRUE; }
    if (!strcmp(key, "hash")) { if (!JNonEmpty(j, &ne)) return FALSE; if (ne) a->hash = TRUE; return TRUE; }
    return JSkip(j, depth);
}

static BOOL CbArch(void *ctx, const char *key, JS *j, int depth)
{
    MANI *m = (MANI *)ctx;
    int idx = !strcmp(key, "64bit") ? 0 : !strcmp(key, "32bit") ? 1 : !strcmp(key, "arm64") ? 2 : -1;
    if (idx >= 0 && j->p < j->e && *j->p == '{')
        return JObject(j, CbArchBlock, &m->a[idx], depth);
    return JSkip(j, depth);
}

static BOOL CbLicense(void *ctx, const char *key, JS *j, int depth)
{
    MANI *m = (MANI *)ctx;
    if (!strcmp(key, "identifier") && j->p < j->e && *j->p == '"')
        return JStr(j, m->license, sizeof(m->license));
    return JSkip(j, depth);
}

static BOOL CbTop(void *ctx, const char *key, JS *j, int depth)
{
    MANI *m = (MANI *)ctx;
    BOOL ne;
    BOOL isStr = (j->p < j->e && *j->p == '"');

    if (!strcmp(key, "version") && isStr)     return JStr(j, m->version, sizeof(m->version));
    if (!strcmp(key, "description") && isStr) return JStr(j, m->desc, sizeof(m->desc));
    if (!strcmp(key, "homepage") && isStr)    return JStr(j, m->homepage, sizeof(m->homepage));
    if (!strcmp(key, "license"))
    {
        if (isStr) return JStr(j, m->license, sizeof(m->license));
        if (j->p < j->e && *j->p == '{') return JObject(j, CbLicense, m, depth);
        return JSkip(j, depth);
    }
    if (!strcmp(key, "url"))  { if (!JNonEmpty(j, &ne)) return FALSE; if (ne) m->topUrl = TRUE; return TRUE; }
    if (!strcmp(key, "hash")) { if (!JNonEmpty(j, &ne)) return FALSE; if (ne) m->topHash = TRUE; return TRUE; }
    if (!strcmp(key, "architecture") && j->p < j->e && *j->p == '{')
        return JObject(j, CbArch, m, depth);
    return JSkip(j, depth);
}

static BOOL ParseManifest(const char *buf, size_t len, MANI *m)
{
    JS j;
    ZeroMemory(m, sizeof(*m));
    if (len >= 3 && (unsigned char)buf[0] == 0xEF && (unsigned char)buf[1] == 0xBB && (unsigned char)buf[2] == 0xBF)
    { buf += 3; len -= 3; }
    j.p = buf; j.e = buf + len;
    JWs(&j);
    if (!JObject(&j, CbTop, m, 0)) return FALSE;
    JWs(&j);
    return j.p == j.e;
}

/* 1 usable and hash present, 0 usable but nothing to verify the download against, -1 no
 * download for this machine (arm64-only, or no url at all). Same preference as Scoop on a
 * 64-bit machine: architecture.64bit, then the top level, then 32bit (WoW64). */
static int Classify(const MANI *m)
{
    if (m->a[0].url)  return (m->a[0].hash || m->topHash) ? 1 : 0;
    if (m->topUrl)    return m->topHash ? 1 : 0;
    if (m->a[1].url)  return (m->a[1].hash || m->topHash) ? 1 : 0;
    return -1;
}

static BOOL ReadAllMax(LPCWSTR path, char **out, size_t *len, LONGLONG maxBytes)
{
    HANDLE h;
    LARGE_INTEGER sz;
    DWORD got = 0;
    char *b;

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > maxBytes)
    { CloseHandle(h); return FALSE; }
    b = (char *)HeapAlloc(GetProcessHeap(), 0, (size_t)sz.QuadPart + 1);
    if (!b) { CloseHandle(h); return FALSE; }
    if (!ReadFile(h, b, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart)
    { HeapFree(GetProcessHeap(), 0, b); CloseHandle(h); return FALSE; }
    CloseHandle(h);
    b[got] = '\0';
    *out = b; *len = got;
    return TRUE;
}

static BOOL ReadAll(LPCWSTR path, char **out, size_t *len)
{
    return ReadAllMax(path, out, len, 4 << 20);
}

/* UTF-8 -> wide, control characters to spaces, truncated (not blanked) to cch. */
static void Utf8NToW(const char *s, size_t len, LPWSTR out, int cch)
{
    WCHAR tmp[1200];
    int n, i;
    out[0] = L'\0';
    if (len > 1100) len = 1100;
    n = len ? MultiByteToWideChar(CP_UTF8, 0, s, (int)len, tmp, ARRAYSIZE(tmp) - 1) : 0;
    if (n <= 0) return;
    if (n > cch - 1) n = cch - 1;
    for (i = 0; i < n; i++)
        out[i] = (tmp[i] == L'\r' || tmp[i] == L'\n' || tmp[i] == L'\t') ? L' ' : tmp[i];
    out[n] = L'\0';
}

static void Utf8ToW(const char *s, LPWSTR out, int cch)
{
    Utf8NToW(s, strlen(s), out, cch);
}

static BOOL BucketManifestDir(LPCWSTR root, LPCWSTR bucket, LPWSTR out, DWORD cch)
{
    WCHAR b[MAX_PATH];
    StringCchPrintfW(b, MAX_PATH, L"%s\\buckets\\%s\\bucket", root, bucket);
    if (GetFileAttributesW(b) != INVALID_FILE_ATTRIBUTES)
        return SUCCEEDED(StringCchCopyW(out, cch, b));
    StringCchPrintfW(b, MAX_PATH, L"%s\\buckets\\%s", root, bucket);
    if (GetFileAttributesW(b) != INVALID_FILE_ATTRIBUTES)
        return SUCCEEDED(StringCchCopyW(out, cch, b));
    return FALSE;
}

/* ---- per-bucket index file -------------------------------------------------
 * Catalog\Software\scoop-<bucket>.idx, UTF-8, one line per app:
 *   #featmgr-scoop-index <TAB> 1 <TAB> bucket=<b> <TAB> trust=0|1 <TAB> unverified=0|1 <TAB> limit=<n> <TAB> count=<n> <TAB> generated=<UTC>
 *   id <TAB> app <TAB> version <TAB> verified(0|1) <TAB> license <TAB> homepage <TAB> description
 * Control characters in the values are replaced by spaces when it is written, so the format has
 * no escaping. It is always rewritten as a whole (write to a temp file, then replace), so a
 * re-import after "scoop update" refreshes it and a failed import never leaves half a file. */

#define IDX_MAGIC "#featmgr-scoop-index"

typedef struct _CBUF { char *p; size_t len, cap; BOOL fail; } CBUF;

static void CbAppend(CBUF *b, const char *s, size_t n)
{
    if (b->fail) return;
    if (b->len + n + 1 > b->cap)
    {
        size_t nc = b->cap ? b->cap : 65536;
        char *np;
        while (nc < b->len + n + 1) nc *= 2;
        np = b->p ? (char *)HeapReAlloc(GetProcessHeap(), 0, b->p, nc) : (char *)HeapAlloc(GetProcessHeap(), 0, nc);
        if (!np) { b->fail = TRUE; return; }
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void CbField(CBUF *b, const char *s, char sep)
{
    size_t i, start = b->len, n = strlen(s);
    CbAppend(b, s, n);
    if (!b->fail)
        for (i = start; i < b->len; i++)
            if ((unsigned char)b->p[i] < 0x20) b->p[i] = ' ';
    CbAppend(b, &sep, 1);
}

static BOOL WriteWhole(LPCWSTR path, const char *a, size_t na, const char *b, size_t nb)
{
    WCHAR tmp[MAX_PATH];
    HANDLE h;
    DWORD w;
    BOOL ok;

    StringCchPrintfW(tmp, MAX_PATH, L"%s.tmp", path);
    h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = (!na || (WriteFile(h, a, (DWORD)na, &w, NULL) && w == na))
      && (!nb || (WriteFile(h, b, (DWORD)nb, &w, NULL) && w == nb));
    CloseHandle(h);
    if (ok) ok = MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING);
    if (!ok) DeleteFileW(tmp);
    return ok;
}

static BOOL IndexPath(LPCWSTR swDir, LPCWSTR bucket, LPWSTR out)
{
    return SUCCEEDED(StringCchPrintfW(out, MAX_PATH, L"%s\\scoop-%s.idx", swDir, bucket));
}

/* header "#featmgr-scoop-index\t1\tbucket=main\t..." -> value of key (or def) */
static int HdrInt(const char *h, const char *he, const char *key, int def)
{
    size_t kl = strlen(key);
    const char *p = h;
    while (p < he)
    {
        const char *q = p;
        while (q < he && *q != '\t') q++;
        if ((size_t)(q - p) > kl && !strncmp(p, key, kl) && p[kl] == '=') return atoi(p + kl + 1);
        p = q + 1;
    }
    return def;
}

static BOOL HdrBucket(const char *h, const char *he, WCHAR *out, int cch)
{
    const char *p = h;
    out[0] = L'\0';
    while (p < he)
    {
        const char *q = p;
        while (q < he && *q != '\t') q++;
        if ((q - p) > 7 && !strncmp(p, "bucket=", 7)) { Utf8NToW(p + 7, (size_t)(q - p - 7), out, cch); return out[0] != 0; }
        p = q + 1;
    }
    return FALSE;
}

/* One record line -> FM_FEATURE (catalog fields only). */
static BOOL ParseRecord(const char *ls, const char *le, LPCWSTR bucket, FM_FEATURE *f)
{
    const char *fp[8], *p = ls;
    size_t fl[8];
    int n = 0;
    WCHAR d[FM_MAX_DESC];

    while (n < 7)
    {
        const char *q = p;
        while (q < le && *q != '\t') q++;
        fp[n] = p; fl[n] = (size_t)(q - p); n++;
        if (q >= le) break;
        p = q + 1;
        if (n == 6) { fp[n] = p; fl[n] = (size_t)(le - p); n++; break; }   /* the description: rest of the line */
    }
    if (n < 7 || !fl[0] || !fl[1]) return FALSE;
    ZeroMemory(f, sizeof(*f));
    Utf8NToW(fp[0], fl[0], f->Id, FM_MAX_ID);
    Utf8NToW(fp[1], fl[1], f->App, ARRAYSIZE(f->App));
    if (!f->Id[0] || !f->App[0]) return FALSE;
    StringCchCopyW(f->Name, FM_MAX_NAME, f->App);
    Utf8NToW(fp[2], fl[2], f->Version, FM_MAX_VER);
    if (!f->Version[0]) StringCchCopyW(f->Version, FM_MAX_VER, L"-");
    f->Verified = (fl[3] && fp[3][0] == '1');
    Utf8NToW(fp[4], fl[4], f->License, ARRAYSIZE(f->License));
    Utf8NToW(fp[5], fl[5], f->Homepage, ARRAYSIZE(f->Homepage));
    f->Description[0] = L'\0';
    if (!f->Verified)
        StringCchCopyW(f->Description, FM_MAX_DESC, L"[No hash in the manifest: Scoop cannot verify this download] ");
    if (fl[6])
    {
        Utf8NToW(fp[6], fl[6], d, ARRAYSIZE(d));
        StringCchCatW(f->Description, FM_MAX_DESC, d);
    }
    else
    {
        StringCchPrintfW(d, ARRAYSIZE(d), L"Scoop app from the %s bucket.", bucket);
        StringCchCatW(f->Description, FM_MAX_DESC, d);
    }
    StringCchCopyW(f->Dependencies, FM_MAX_DEPS, L"scoop");
    f->Tier = FM_TIER_SOFTWARE;
    f->Removable = TRUE;
    StringCchCopyW(f->Provider, ARRAYSIZE(f->Provider), L"scoop");
    StringCchCopyW(f->Bucket, ARRAYSIZE(f->Bucket), bucket);
    StringCchPrintfW(f->Source, ARRAYSIZE(f->Source), L"scoop/%s", bucket);
    return TRUE;
}

#define IDX_MAXBYTES (32 << 20)

/* Calls cb for every record of one index file. Returns the record count, -1 if unusable. */
static int IndexFileEnum(LPCWSTR path, FM_REC_CB cb, void *ctx)
{
    char *buf = NULL;
    size_t len = 0;
    const char *p, *e, *hdrEnd;
    WCHAR bucket[FM_BUCKET_MAX];
    int cnt = 0;
    FM_FEATURE *f;

    if (!ReadAllMax(path, &buf, &len, IDX_MAXBYTES)) return -1;
    p = buf; e = buf + len;
    hdrEnd = (const char *)memchr(p, '\n', len);
    if (!hdrEnd || strncmp(p, IDX_MAGIC "\t1\t", sizeof(IDX_MAGIC) + 2 - 1) || !HdrBucket(p, hdrEnd, bucket, ARRAYSIZE(bucket)))
    { HeapFree(GetProcessHeap(), 0, buf); return -1; }
    f = (FM_FEATURE *)HeapAlloc(GetProcessHeap(), 0, sizeof(*f));
    if (!f) { HeapFree(GetProcessHeap(), 0, buf); return -1; }
    p = hdrEnd + 1;
    while (p < e)
    {
        const char *le = (const char *)memchr(p, '\n', (size_t)(e - p));
        const char *nx;
        if (!le) le = e;
        nx = le < e ? le + 1 : e;
        if (le > p && le[-1] == '\r') le--;
        if (le > p && *p != '#' && ParseRecord(p, le, bucket, f))
        {
            StringCchCopyW(f->ManifestPath, MAX_PATH, path);
            cnt++;
            if (cb && !cb(ctx, f)) break;
        }
        p = nx;
    }
    HeapFree(GetProcessHeap(), 0, f);
    HeapFree(GetProcessHeap(), 0, buf);
    return cnt;
}

int FmScoopIndexEnum(LPCWSTR swDir, FM_REC_CB cb, void *ctx)
{
    WCHAR glob[MAX_PATH], path[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int total = 0;

    StringCchPrintfW(glob, MAX_PATH, L"%s\\scoop-*.idx", swDir);
    h = FindFirstFileW(glob, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do
    {
        int n;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        StringCchPrintfW(path, MAX_PATH, L"%s\\%s", swDir, fd.cFileName);
        n = IndexFileEnum(path, cb, ctx);
        if (n > 0) total += n;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return total;
}

/* id of a record line vs a NUL-terminated id: case-insensitive, a TAB ends the stored id */
static int IdCmp(const char *a, const char *b)
{
    for (;;)
    {
        int ca = (unsigned char)*a++, cb = (unsigned char)*b++;
        if (ca == '\t') ca = 0;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return ca - cb;
        if (!ca) return 0;
    }
}

BOOL FmScoopIndexFind(LPCWSTR swDir, LPCWSTR id, FM_FEATURE *out)
{
    WCHAR glob[MAX_PATH], path[MAX_PATH], bucket[FM_BUCKET_MAX];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    char nid[FM_MAX_ID + 1];
    size_t i, n = wcslen(id);
    BOOL found = FALSE;

    if (!n || n > FM_MAX_ID) return FALSE;
    for (i = 0; i < n; i++)
    {
        if (id[i] > 0x7E || id[i] < 0x21) return FALSE;      /* ids are plain ASCII names */
        nid[i] = (char)id[i];
    }
    nid[n] = '\0';
    StringCchPrintfW(glob, MAX_PATH, L"%s\\scoop-*.idx", swDir);
    h = FindFirstFileW(glob, &fd);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    do
    {
        char *buf = NULL;
        size_t len = 0;
        const char *p, *e, *hdrEnd;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        StringCchPrintfW(path, MAX_PATH, L"%s\\%s", swDir, fd.cFileName);
        if (!ReadAllMax(path, &buf, &len, IDX_MAXBYTES)) continue;
        p = buf; e = buf + len;
        hdrEnd = (const char *)memchr(p, '\n', len);
        if (hdrEnd && !strncmp(p, IDX_MAGIC "\t1\t", sizeof(IDX_MAGIC) + 2 - 1) && HdrBucket(p, hdrEnd, bucket, ARRAYSIZE(bucket)))
        {
            for (p = hdrEnd + 1; p < e; )
            {
                const char *le = (const char *)memchr(p, '\n', (size_t)(e - p)), *nx;
                if (!le) le = e;
                nx = le < e ? le + 1 : e;
                if (le > p && le[-1] == '\r') le--;
                if (le > p && *p != '#' && !IdCmp(p, nid) && ParseRecord(p, le, bucket, out))
                {
                    StringCchCopyW(out->ManifestPath, MAX_PATH, path);
                    found = TRUE;
                    break;
                }
                p = nx;
            }
        }
        HeapFree(GetProcessHeap(), 0, buf);
    } while (!found && FindNextFileW(h, &fd));
    FindClose(h);
    return found;
}

/* trust/unverified/limit the bucket was imported with, from its index header */
BOOL FmScoopIndexInfo(LPCWSTR swDir, LPCWSTR bucket, DWORD *flags, int *limit)
{
    WCHAR path[MAX_PATH];
    HANDLE h;
    char hb[512];
    DWORD got = 0;
    const char *he;

    if (!FmScoopValidBucket(bucket) || !IndexPath(swDir, bucket, path)) return FALSE;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!ReadFile(h, hb, sizeof(hb) - 1, &got, NULL)) got = 0;
    CloseHandle(h);
    hb[got] = '\0';
    he = (const char *)memchr(hb, '\n', got);
    if (!he || strncmp(hb, IDX_MAGIC "\t1\t", sizeof(IDX_MAGIC) + 2 - 1)) return FALSE;
    *flags = 0;
    if (HdrInt(hb, he, "trust", 0)) *flags |= FM_SCOOP_TRUST;
    if (HdrInt(hb, he, "unverified", 0)) *flags |= FM_SCOOP_UNVERIFIED;
    *limit = HdrInt(hb, he, "limit", 0);
    return TRUE;
}

/* ---- import -------------------------------------------------------------- */

/* Ids that other buckets' indexes already hold (sorted pointers into the loaded index text). */
typedef struct _IDSET { const char **v; int n, cap; char *texts[8]; int ntext; } IDSET;

static int IdSortCmp(const void *x, const void *y)
{
    return IdCmp(*(const char *const *)x, *(const char *const *)y);
}

static void IdSetLoad(IDSET *s, LPCWSTR swDir, LPCWSTR exceptBucket)
{
    WCHAR glob[MAX_PATH], path[MAX_PATH], mine[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;

    ZeroMemory(s, sizeof(*s));
    IndexPath(swDir, exceptBucket, mine);
    StringCchPrintfW(glob, MAX_PATH, L"%s\\scoop-*.idx", swDir);
    h = FindFirstFileW(glob, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do
    {
        char *buf = NULL;
        size_t len = 0;
        const char *p, *e;
        StringCchPrintfW(path, MAX_PATH, L"%s\\%s", swDir, fd.cFileName);
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || !_wcsicmp(path, mine) || s->ntext >= 8) continue;
        if (!ReadAllMax(path, &buf, &len, IDX_MAXBYTES)) continue;
        s->texts[s->ntext++] = buf;
        p = (const char *)memchr(buf, '\n', len);
        for (p = p ? p + 1 : buf + len, e = buf + len; p < e; )
        {
            const char *le = (const char *)memchr(p, '\n', (size_t)(e - p));
            if (!le) le = e;
            if (le > p && *p != '#')
            {
                if (s->n == s->cap)
                {
                    int nc = s->cap ? s->cap * 2 : 4096;
                    const char **nv = s->v ? (const char **)HeapReAlloc(GetProcessHeap(), 0, (void *)s->v, nc * sizeof(*nv))
                                          : (const char **)HeapAlloc(GetProcessHeap(), 0, nc * sizeof(*nv));
                    if (!nv) break;
                    s->v = nv; s->cap = nc;
                }
                s->v[s->n++] = p;
            }
            p = le < e ? le + 1 : e;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (s->n > 1) qsort((void *)s->v, s->n, sizeof(*s->v), IdSortCmp);
}

static BOOL IdSetHas(const IDSET *s, const char *id)
{
    int lo = 0, hi = s->n - 1;
    while (lo <= hi)
    {
        int mid = (lo + hi) / 2, c = IdCmp(s->v[mid], id);
        if (!c) return TRUE;
        if (c < 0) lo = mid + 1; else hi = mid - 1;
    }
    return FALSE;
}

static void IdSetFree(IDSET *s)
{
    int i;
    for (i = 0; i < s->ntext; i++) HeapFree(GetProcessHeap(), 0, s->texts[i]);
    if (s->v) HeapFree(GetProcessHeap(), 0, (void *)s->v);
}

/* Id for an app: its own name, unless that is taken by an image catalog entry, by an older
 * per-app entry of another bucket or by another bucket's index, then <bucket>-<app>. */
static BOOL ChooseId(LPCWSTR bucket, LPCWSTR app, LPCWSTR catDir, LPCWSTR swDir, const IDSET *others, LPWSTR id)
{
    WCHAR p[MAX_PATH], b[64];
    char napp[FM_MAX_ID + 1];
    BOOL clash = FALSE;
    size_t i, n = wcslen(app);

    StringCchCopyW(id, FM_MAX_ID, app);
    StringCchPrintfW(p, MAX_PATH, L"%s\\%s.ini", catDir, app);
    if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES) clash = TRUE;
    if (!clash)
    {
        StringCchPrintfW(p, MAX_PATH, L"%s\\%s.ini", swDir, app);
        if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES)
        {
            FmIniGetFast(p, L"Scoop", L"Bucket", b, ARRAYSIZE(b));
            if (_wcsicmp(b, bucket)) clash = TRUE;
        }
    }
    if (!clash && n <= FM_MAX_ID)
    {
        for (i = 0; i < n; i++) napp[i] = (char)app[i];    /* app names are validated ASCII */
        napp[n] = '\0';
        if (IdSetHas(others, napp)) clash = TRUE;
    }
    if (clash)
    {
        if (FAILED(StringCchPrintfW(id, FM_MAX_ID, L"%s-%s", bucket, app))) return FALSE;
    }
    return TRUE;
}

/* Delete this bucket's per-app entries of an M1-style import (the index replaces them). */
static void CleanBucket(LPCWSTR swDir, LPCWSTR bucket)
{
    WCHAR glob[MAX_PATH], f[MAX_PATH], v[64];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    StringCchPrintfW(glob, MAX_PATH, L"%s\\*.ini", swDir);
    h = FindFirstFileW(glob, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do
    {
        if (!_wcsnicmp(fd.cFileName, L"rapps-", 6)) continue;
        StringCchPrintfW(f, MAX_PATH, L"%s\\%s", swDir, fd.cFileName);
        FmIniGetFast(f, L"Scoop", L"Bucket", v, ARRAYSIZE(v));
        if (v[0] && !_wcsicmp(v, bucket)) DeleteFileW(f);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

typedef struct _IMPSTAT { int written, skipped, nohash, noarch, invalid; } IMPSTAT;

static int ImportOneBucket(LPCWSTR root, LPCWSTR bucket, LPCWSTR dirOverride, DWORD flags, int limit,
                           IMPSTAT *st, FILE *log)
{
    WCHAR dir[MAX_PATH], catDir[MAX_PATH], swDir[MAX_PATH], glob[MAX_PATH], file[MAX_PATH], idxPath[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    IDSET others;
    CBUF body = { NULL, 0, 0, FALSE }, head = { NULL, 0, 0, FALSE };
    int before = st->written;
    char bucketA[FM_BUCKET_MAX + 1], hdr[256], now[32];
    SYSTEMTIME t;
    BOOL wrote;

    if (!FmScoopValidBucket(bucket))
    {
        ERRF(log, L"error: '%s' is not a valid bucket name\n", bucket);
        return -1;
    }
    if (!IsOfficialBucket(bucket) && !(flags & FM_SCOOP_TRUST))
    {
        ERRF(log, L"error: bucket '%s' is not an official Scoop bucket (main, extras). A bucket's manifests can run "
                  L"PowerShell as administrator, so importing a third-party bucket needs your explicit consent: "
                  L"add /trust if you added it to Scoop yourself and trust its maintainers.\n", bucket);
        return -1;
    }
    if (dirOverride && dirOverride[0])
        StringCchCopyW(dir, MAX_PATH, dirOverride);
    else if (!BucketManifestDir(root, bucket, dir, MAX_PATH))
    {
        WCHAR probe[MAX_PATH];
        StringCchPrintfW(probe, MAX_PATH, L"%s\\apps\\scoop", root);
        if (GetFileAttributesW(probe) == INVALID_FILE_ATTRIBUTES)
            ERRF(log, L"error: Scoop is not installed (no %s). Install it first: featmgr /install scoop\n", probe);
        else
            ERRF(log, L"error: bucket '%s' is not added to Scoop (%s\\buckets\\%s is missing). Add it first: "
                      L"featmgr /add-bucket %s   (or yourself: scoop bucket add %s; both need git: featmgr /install git)\n",
                 bucket, root, bucket, bucket, bucket);
        return -1;
    }
    PathRemoveBackslashW(dir);
    if (!FmGetCatalogDir(catDir, MAX_PATH) || !FmGetSoftwareCatalogDir(swDir, MAX_PATH)) return -1;
    SHCreateDirectoryExW(NULL, swDir, NULL);

    StringCchPrintfW(glob, MAX_PATH, L"%s\\*.json", dir);
    h = FindFirstFileW(glob, &fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        ERRF(log, L"error: no manifests (*.json) in '%s'\n", dir);
        return -1;
    }
    CleanBucket(swDir, bucket);           /* M1-style per-app entries of this bucket: the index replaces them */
    IdSetLoad(&others, swDir, bucket);
    do
    {
        WCHAR app[MAX_PATH], id[FM_MAX_ID];
        char idA[FM_MAX_ID + 1], appA[MAX_PATH];
        MANI *m;
        char *buf = NULL;
        size_t len = 0;
        int cls, i;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (limit > 0 && st->written - before >= limit) break;
        StringCchCopyW(app, MAX_PATH, fd.cFileName);
        PathRemoveExtensionW(app);
        if (!FmScoopValidApp(app))
        {
            st->skipped++; st->invalid++;
            LOGF(log, L"skip: '%s' (unusable app name)\n", fd.cFileName);
            continue;
        }
        StringCchPrintfW(file, MAX_PATH, L"%s\\%s", dir, fd.cFileName);
        if (!ReadAll(file, &buf, &len))
        {
            st->skipped++; st->invalid++;
            LOGF(log, L"skip: %s (cannot read the manifest)\n", app);
            continue;
        }
        m = (MANI *)HeapAlloc(GetProcessHeap(), 0, sizeof(*m));
        if (!m) { HeapFree(GetProcessHeap(), 0, buf); break; }
        if (!ParseManifest(buf, len, m))
        {
            st->skipped++; st->invalid++;
            LOGF(log, L"skip: %s (malformed JSON)\n", app);
            HeapFree(GetProcessHeap(), 0, m); HeapFree(GetProcessHeap(), 0, buf);
            continue;
        }
        HeapFree(GetProcessHeap(), 0, buf);
        cls = Classify(m);
        if (cls < 0)
        {
            st->skipped++; st->noarch++;
            LOGF(log, L"skip: %s (no download for this architecture)\n", app);
            HeapFree(GetProcessHeap(), 0, m);
            continue;
        }
        if (cls == 0 && !(flags & FM_SCOOP_UNVERIFIED))
        {
            st->skipped++; st->nohash++;
            LOGF(log, L"skip: %s (manifest has no hash, Scoop could not verify the download; /unverified to include)\n", app);
            HeapFree(GetProcessHeap(), 0, m);
            continue;
        }
        if (!ChooseId(bucket, app, catDir, swDir, &others, id))
        {
            st->skipped++; st->invalid++;
            LOGF(log, L"skip: %s (id too long)\n", app);
            HeapFree(GetProcessHeap(), 0, m);
            continue;
        }
        for (i = 0; id[i] && i < FM_MAX_ID; i++) idA[i] = (char)id[i];     /* validated ASCII */
        idA[i] = '\0';
        for (i = 0; app[i] && i < MAX_PATH - 1; i++) appA[i] = (char)app[i];
        appA[i] = '\0';

        CbField(&body, idA, '\t');
        CbField(&body, appA, '\t');
        CbField(&body, m->version, '\t');
        CbField(&body, cls == 1 ? "1" : "0", '\t');
        CbField(&body, m->license, '\t');
        CbField(&body, m->homepage, '\t');
        CbField(&body, m->desc, '\n');
        st->written++;
        HeapFree(GetProcessHeap(), 0, m);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    IdSetFree(&others);

    GetSystemTime(&t);
    sprintf(now, "%04u-%02u-%02uT%02u:%02u:%02uZ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    {
        int i;
        for (i = 0; bucket[i] && i < FM_BUCKET_MAX; i++) bucketA[i] = (char)bucket[i];
        bucketA[i] = '\0';
    }
    sprintf(hdr, IDX_MAGIC "\t1\tbucket=%s\ttrust=%d\tunverified=%d\tlimit=%d\tcount=%d\tgenerated=%s\n", bucketA,
            (flags & FM_SCOOP_TRUST) ? 1 : 0, (flags & FM_SCOOP_UNVERIFIED) ? 1 : 0, limit > 0 ? limit : 0,
            st->written - before, now);
    CbAppend(&head, hdr, strlen(hdr));
    IndexPath(swDir, bucket, idxPath);
    wrote = !body.fail && !head.fail && WriteWhole(idxPath, head.p, head.len, body.p, body.len);
    if (body.p) HeapFree(GetProcessHeap(), 0, body.p);
    if (head.p) HeapFree(GetProcessHeap(), 0, head.p);
    if (!wrote)
    {
        ERRF(log, L"error: cannot write the index %s (%lu)\n", idxPath, GetLastError());
        st->written = before;
        return -1;
    }
    LOGF(log, L"bucket '%s': %d imported from %s\n", bucket, st->written - before, dir);
    return st->written - before;
}

/* Buckets that already have an index and are not main/extras (added with /trust or from the GUI list):
 * refreshed with the flags they were imported with. skipOfficial: main/extras are handled by the caller. */
static int ReimportIndexed(LPCWSTR root, BOOL skipOfficial, IMPSTAT *st, FILE *log, int *rc)
{
    WCHAR swDir[MAX_PATH], glob[MAX_PATH], b[FM_BUCKET_MAX + 8], d[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int found = 0;

    if (!FmGetSoftwareCatalogDir(swDir, MAX_PATH)) return 0;
    StringCchPrintfW(glob, MAX_PATH, L"%s\\scoop-*.idx", swDir);
    h = FindFirstFileW(glob, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do
    {
        size_t n = wcslen(fd.cFileName);
        DWORD fl;
        int lim;
        if (n <= 11 || n - 11 >= ARRAYSIZE(b)) continue;
        memcpy(b, fd.cFileName + 6, (n - 11) * sizeof(WCHAR));    /* strip "scoop-" and ".idx" */
        b[n - 11] = L'\0';
        if (!FmScoopValidBucket(b) || (skipOfficial && IsOfficialBucket(b))) continue;
        if (!FmScoopIndexInfo(swDir, b, &fl, &lim) || !BucketManifestDir(root, b, d, MAX_PATH)) continue;
        found++;
        if (ImportOneBucket(root, b, NULL, fl, lim, st, log) < 0) *rc = -1;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return found;
}

int FmImportScoop(LPCWSTR bucket, LPCWSTR dirOverride, DWORD flags, int limit, int *skipped, FILE *log)
{
    WCHAR root[MAX_PATH];
    IMPSTAT st = { 0, 0, 0, 0, 0 };
    BOOL all = (!bucket || !bucket[0] || !wcscmp(bucket, L"*"));
    int rc = 0;

    if (skipped) *skipped = 0;
    if (!FM_SCOOP_SUPPORTED)
    {
        ERRF(log, L"error: Scoop needs 64-bit PowerShell 7, which is not available on this architecture (x86)\n");
        return -2;
    }
    if (!FmScoopRoot(root, MAX_PATH)) return -1;

    if (all)
    {
        static const LPCWSTR official[] = { L"main", L"extras" };
        int i, found = 0;
        for (i = 0; i < 2; i++)
        {
            WCHAR d[MAX_PATH];
            if (!BucketManifestDir(root, official[i], d, MAX_PATH)) continue;
            found++;
            if (ImportOneBucket(root, official[i], NULL, flags, limit, &st, log) < 0) rc = -1;
        }
        found += ReimportIndexed(root, TRUE, &st, log, &rc);
        if (!found)
        {
            WCHAR probe[MAX_PATH];
            StringCchPrintfW(probe, MAX_PATH, L"%s\\apps\\scoop", root);
            if (GetFileAttributesW(probe) == INVALID_FILE_ATTRIBUTES)
                ERRF(log, L"error: Scoop is not installed (no %s). Install it first: featmgr /install scoop\n", probe);
            else
                ERRF(log, L"error: no Scoop bucket found under %s\\buckets\n", root);
            return -1;
        }
    }
    else if (ImportOneBucket(root, bucket, dirOverride, flags, limit, &st, log) < 0)
        rc = -1;

    if (skipped) *skipped = st.skipped;
    LOGF(log, L"imported %d Scoop app(s) (%d skipped: %d without hash, %d without a download for this machine, "
              L"%d invalid)\n", st.written, st.skipped, st.nohash, st.noarch, st.invalid);
    return (rc < 0 && !st.written) ? -1 : st.written;
}

/* Re-read one bucket (or all that were imported) with the flags of the earlier import. */
int FmScoopReimport(LPCWSTR bucket, FILE *log)
{
    WCHAR root[MAX_PATH], swDir[MAX_PATH];
    IMPSTAT st = { 0, 0, 0, 0, 0 };
    DWORD fl;
    int lim;

    if (!FM_SCOOP_SUPPORTED || !FmScoopRoot(root, MAX_PATH) || !FmGetSoftwareCatalogDir(swDir, MAX_PATH)) return -1;
    if (!FmScoopIndexInfo(swDir, bucket, &fl, &lim)) return -1;       /* never imported: nothing to refresh */
    return ImportOneBucket(root, bucket, NULL, fl, lim, &st, log);
}

int FmScoopReimportAll(FILE *log)
{
    WCHAR root[MAX_PATH], d[MAX_PATH];
    IMPSTAT st = { 0, 0, 0, 0, 0 };
    int rc = 0, i;
    static const LPCWSTR official[] = { L"main", L"extras" };

    if (!FM_SCOOP_SUPPORTED || !FmScoopRoot(root, MAX_PATH)) return -1;
    for (i = 0; i < 2; i++)
    {
        WCHAR swDir[MAX_PATH];
        DWORD fl;
        int lim;
        if (!FmGetSoftwareCatalogDir(swDir, MAX_PATH) || !FmScoopIndexInfo(swDir, official[i], &fl, &lim)
            || !BucketManifestDir(root, official[i], d, MAX_PATH)) continue;
        if (ImportOneBucket(root, official[i], NULL, fl, lim, &st, log) < 0) rc = -1;
    }
    ReimportIndexed(root, TRUE, &st, log, &rc);
    return (rc < 0 && !st.written) ? -1 : st.written;
}

/* ---- installed version ----------------------------------------------------- */

/* apps\<app>\current\manifest.json is what "scoop list" reads. If it is missing (a hand-made
 * install), the newest version directory next to "current" names the version. */
BOOL FmScoopInstalledVersion(LPCWSTR app, LPWSTR out, DWORD cch)
{
    WCHAR root[MAX_PATH], p[MAX_PATH];
    char *buf = NULL;
    size_t len = 0;

    if (cch) out[0] = L'\0';
    if (!FmScoopValidApp(app) || !FmScoopRoot(root, MAX_PATH)) return FALSE;
    StringCchPrintfW(p, MAX_PATH, L"%s\\apps\\%s\\current\\manifest.json", root, app);
    if (ReadAll(p, &buf, &len))
    {
        MANI *m = (MANI *)HeapAlloc(GetProcessHeap(), 0, sizeof(*m));
        if (m)
        {
            if (ParseManifest(buf, len, m) && m->version[0])
            {
                WCHAR v[FM_MAX_VER];
                Utf8ToW(m->version, v, FM_MAX_VER);
                StringCchCopyW(out, cch, v);
            }
            HeapFree(GetProcessHeap(), 0, m);
        }
        HeapFree(GetProcessHeap(), 0, buf);
        if (out[0]) return TRUE;
    }
    {
        WIN32_FIND_DATAW fd;
        HANDLE h;
        FILETIME best = { 0, 0 };
        StringCchPrintfW(p, MAX_PATH, L"%s\\apps\\%s\\*", root, app);
        h = FindFirstFileW(p, &fd);
        if (h == INVALID_HANDLE_VALUE) return FALSE;
        do
        {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == L'.'
                || !_wcsicmp(fd.cFileName, L"current") || fd.cFileName[0] == L'_') continue;
            if (!out[0] || CompareFileTime(&fd.ftLastWriteTime, &best) > 0)
            {
                StringCchCopyW(out, cch, fd.cFileName);
                best = fd.ftLastWriteTime;
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return out[0] != L'\0';
}

/* ---- version order ----------------------------------------------------------- */

static BOOL IsSepCh(WCHAR c) { return c == L'.' || c == L'-' || c == L'+' || c == L'_' || c == L' '; }

/* Next token: a run of digits, or a run of other non-separator characters. */
static const WCHAR *NextTok(const WCHAR *s, const WCHAR **b, size_t *n, BOOL *num)
{
    while (*s && IsSepCh(*s)) s++;
    *b = s; *n = 0; *num = FALSE;
    if (!*s) return s;
    *num = (*s >= L'0' && *s <= L'9');
    while (*s && !IsSepCh(*s) && ((*s >= L'0' && *s <= L'9') == *num)) { s++; (*n)++; }
    return s;
}

/* Numbers compare as numbers (1.10 > 1.9), a missing token counts as 0, a word (beta, rc,
 * nightly) sorts below the same version without it (1.0 > 1.0-beta) and below any number. */
int FmCompareVersions(LPCWSTR a, LPCWSTR b)
{
    for (;;)
    {
        const WCHAR *ta, *tb;
        size_t na, nb;
        BOOL xa, xb;
        a = NextTok(a, &ta, &na, &xa);
        b = NextTok(b, &tb, &nb, &xb);
        if (!na && !nb) return 0;
        if (!na) { if (xb) { while (nb && *tb == L'0') { tb++; nb--; } if (nb) return -1; continue; } return 1; }
        if (!nb) { if (xa) { while (na && *ta == L'0') { ta++; na--; } if (na) return 1; continue; } return -1; }
        if (xa && xb)
        {
            int c;
            while (na && *ta == L'0') { ta++; na--; }
            while (nb && *tb == L'0') { tb++; nb--; }
            if (na != nb) return na < nb ? -1 : 1;
            c = wcsncmp(ta, tb, na);
            if (c) return c < 0 ? -1 : 1;
        }
        else if (xa != xb)
            return xa ? 1 : -1;
        else
        {
            size_t m = na < nb ? na : nb;
            int c = _wcsnicmp(ta, tb, m);
            if (c) return c < 0 ? -1 : 1;
            if (na != nb) return na < nb ? -1 : 1;
        }
    }
}

/* ---- known buckets ------------------------------------------------------------- */

typedef struct _KCTX { FM_BUCKET *out; int n, max; } KCTX;

static BOOL CbKnown(void *ctx, const char *key, JS *j, int depth)
{
    KCTX *k = (KCTX *)ctx;
    if (j->p < j->e && *j->p == '"')
    {
        char url[160];
        if (!JStr(j, url, sizeof(url))) return FALSE;
        if (k->n < k->max)
        {
            WCHAR nm[FM_BUCKET_MAX];
            Utf8ToW(key, nm, ARRAYSIZE(nm));
            if (FmScoopValidBucket(nm))
            {
                StringCchCopyW(k->out[k->n].Name, ARRAYSIZE(k->out[k->n].Name), nm);
                Utf8ToW(url, k->out[k->n].Url, ARRAYSIZE(k->out[k->n].Url));
                k->n++;
            }
        }
        return TRUE;
    }
    return JSkip(j, depth);
}

int FmScoopKnownBuckets(FM_BUCKET *out, int max)
{
    WCHAR root[MAX_PATH], p[MAX_PATH], d[MAX_PATH];
    char *buf = NULL;
    size_t len = 0;
    KCTX k;
    int i;
    static const LPCWSTR builtin[] = { L"main", L"extras", L"versions", L"nirsoft", L"sysinternals", L"php",
                                       L"nerd-fonts", L"nonportable", L"java", L"games" };

    k.out = out; k.n = 0; k.max = max;
    ZeroMemory(out, sizeof(*out) * max);
    if (!FmScoopRoot(root, MAX_PATH)) return 0;
    StringCchPrintfW(p, MAX_PATH, L"%s\\apps\\scoop\\current\\buckets.json", root);
    if (ReadAll(p, &buf, &len))
    {
        JS j;
        j.p = buf; j.e = buf + len;
        JWs(&j);
        if (!JObject(&j, CbKnown, &k, 0)) k.n = 0;
        HeapFree(GetProcessHeap(), 0, buf);
    }
    if (!k.n)       /* Scoop's file is not there (not installed yet, or an offline test root): its built-in names */
    {
        ZeroMemory(out, sizeof(*out) * max);
        for (i = 0; i < (int)ARRAYSIZE(builtin) && k.n < max; i++)
            StringCchCopyW(out[k.n++].Name, ARRAYSIZE(out[0].Name), builtin[i]);
    }
    for (i = 0; i < k.n; i++)
        out[i].Added = BucketManifestDir(root, out[i].Name, d, MAX_PATH);
    return k.n;
}

BOOL FmScoopBucketIsKnown(LPCWSTR name)
{
    FM_BUCKET kb[FM_BUCKET_MAX];
    int n = FmScoopKnownBuckets(kb, FM_BUCKET_MAX), i;
    for (i = 0; i < n; i++)
        if (!_wcsicmp(kb[i].Name, name)) return TRUE;
    return FALSE;
}

/* featmgr /scoop-buckets */
int FmScoopListBuckets(FILE *log)
{
    WCHAR root[MAX_PATH], glob[MAX_PATH], dir[MAX_PATH], jg[MAX_PATH];
    WIN32_FIND_DATAW fd, jf;
    HANDLE h, hj;
    int n = 0;

    if (!FmScoopRoot(root, MAX_PATH)) return -1;
    StringCchPrintfW(glob, MAX_PATH, L"%s\\buckets\\*", root);
    h = FindFirstFileW(glob, &fd);
    LOGF(log, L"Scoop root: %s\n", root);
    LOGF(log, L"%-16s %-9s %-10s\n", L"BUCKET", L"OFFICIAL", L"MANIFESTS");
    if (h == INVALID_HANDLE_VALUE)
    {
        LOGF(log, L"(no buckets: Scoop is not installed or has no bucket directory)\n");
        return 0;
    }
    do
    {
        int cnt = 0;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == L'.') continue;
        if (BucketManifestDir(root, fd.cFileName, dir, MAX_PATH))
        {
            StringCchPrintfW(jg, MAX_PATH, L"%s\\*.json", dir);
            hj = FindFirstFileW(jg, &jf);
            if (hj != INVALID_HANDLE_VALUE)
            {
                do { if (!(jf.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) cnt++; } while (FindNextFileW(hj, &jf));
                FindClose(hj);
            }
        }
        LOGF(log, L"%-16s %-9s %-10d\n", fd.cFileName, IsOfficialBucket(fd.cFileName) ? L"yes" : L"no", cnt);
        n++;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    {
        FM_BUCKET kb[FM_BUCKET_MAX];
        int kn = FmScoopKnownBuckets(kb, FM_BUCKET_MAX), i;
        LOGF(log, L"\nKnown buckets (scoop bucket known): add one with featmgr /add-bucket <name>\n");
        for (i = 0; i < kn; i++)
            LOGF(log, L"  %-16s %s%s\n", kb[i].Name, kb[i].Added ? L"(added) " : L"", kb[i].Url);
    }
    return n;
}
