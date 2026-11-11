/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager (FEATMGMT-01)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Catalog engine + reversible enable/disable + registry state.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "featmgr.h"
#include <shlwapi.h>
#include <shlobj.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <sddl.h>

/* msiexec exit 1618 (another install running): bounded retry */
#define MSI_BUSY_RETRIES   6
#define MSI_BUSY_WAIT_MS   30000u

/* Persisted feature state lives here (DISM /Get-Features-like, queryable). */
static const WCHAR STATE_KEY[] =
    L"SOFTWARE\\ReactOS\\Nitro\\OptionalFeatures";

#define LOGF(log, ...) do { if (log) { fwprintf((log), __VA_ARGS__); fflush(log); } } while (0)

/* Last failure reason, for callers with no log stream (the GUI). Overwritten by every failure;
 * cleared when a top-level FmEnable/FmDisableEx/FmUninstallEx starts. */
static WCHAR g_LastMsg[2048];
static int   g_OpDepth;

void FmSetLastMessage(LPCWSTR fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(g_LastMsg, ARRAYSIZE(g_LastMsg) - 1, fmt, ap);
    va_end(ap);
    g_LastMsg[ARRAYSIZE(g_LastMsg) - 1] = L'\0';
}

void FmGetLastMessage(LPWSTR buf, DWORD cch)
{
    if (cch) StringCchCopyW(buf, cch, g_LastMsg);
}

#define SetLastMsg FmSetLastMessage

/* ---- layout helpers ------------------------------------------------------ */

BOOL FmGetRootDir(LPWSTR buf, DWORD cch)
{
    WCHAR win[MAX_PATH];
    if (!GetWindowsDirectoryW(win, MAX_PATH))
        return FALSE;
    return SUCCEEDED(StringCchPrintfW(buf, cch, L"%s\\Featmgr", win));
}

BOOL FmGetCatalogDir(LPWSTR buf, DWORD cch)
{
    WCHAR root[MAX_PATH];
    if (!FmGetRootDir(root, MAX_PATH))
        return FALSE;
    return SUCCEEDED(StringCchPrintfW(buf, cch, L"%s\\Catalog", root));
}

BOOL FmGetSoftwareCatalogDir(LPWSTR buf, DWORD cch)
{
    WCHAR cat[MAX_PATH];
    if (!FmGetCatalogDir(cat, MAX_PATH))
        return FALSE;
    return SUCCEEDED(StringCchPrintfW(buf, cch, L"%s\\Software", cat));
}

BOOL FmGetPayloadDir(LPCWSTR id, LPWSTR buf, DWORD cch)
{
    WCHAR root[MAX_PATH];
    if (!FmGetRootDir(root, MAX_PATH))
        return FALSE;
    return SUCCEEDED(StringCchPrintfW(buf, cch, L"%s\\Payload\\%s", root, id));
}

LPCWSTR FmTierStr(FM_TIER t)
{
    return (t == FM_TIER_SOFTWARE) ? L"software" : L"os";
}

LPCWSTR FmStateStr(FM_STATE s)
{
    switch (s)
    {
        case FM_STATE_ENABLED:  return L"Enabled";
        case FM_STATE_DISABLED: return L"Disabled";
        default:                return L"NotInstalled";
    }
}

/* ---- registry state ------------------------------------------------------ */

static LONG OpenStateKey(LPCWSTR id, BOOL create, REGSAM sam, HKEY *out)
{
    WCHAR sub[512];
    StringCchPrintfW(sub, 512, L"%s\\%s", STATE_KEY, id);
    if (create)
        return RegCreateKeyExW(HKEY_LOCAL_MACHINE, sub, 0, NULL, 0,
                               sam, NULL, out, NULL);
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0, sam, out);
}

static FM_STATE RawState(LPCWSTR id)
{
    HKEY k;
    WCHAR v[32];
    DWORD cb = sizeof(v), type = 0;
    FM_STATE s = FM_STATE_NOT_INSTALLED;

    if (OpenStateKey(id, FALSE, KEY_READ, &k) != ERROR_SUCCESS)
        return FM_STATE_NOT_INSTALLED;
    if (RegQueryValueExW(k, L"State", NULL, &type, (LPBYTE)v, &cb) == ERROR_SUCCESS
        && type == REG_SZ)
    {
        if (!_wcsicmp(v, L"Enabled"))  s = FM_STATE_ENABLED;
        else if (!_wcsicmp(v, L"Disabled")) s = FM_STATE_DISABLED;
    }
    RegCloseKey(k);
    return s;
}

static void SetStateSz(HKEY k, LPCWSTR name, LPCWSTR val)
{
    RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)val,
                   (DWORD)((wcslen(val) + 1) * sizeof(WCHAR)));
}

/* UTC ISO-8601 timestamp */
static void UtcNow(LPWSTR buf, DWORD cch)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    StringCchPrintfW(buf, cch, L"%04u-%02u-%02uT%02u:%02u:%02uZ",
                     st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond);
}

/* ---- MULTI_SZ helpers (installed-file + undo lists) ---------------------- */

/* Append one line to a REG_MULTI_SZ value. */
static void MultiSzAppend(HKEY k, LPCWSTR name, LPCWSTR line)
{
    DWORD cb = 0, type = 0;
    BYTE *old = NULL;
    BYTE *buf;
    DWORD oldLen = 0, addLen = (DWORD)((wcslen(line) + 1) * sizeof(WCHAR));

    if (RegQueryValueExW(k, name, NULL, &type, NULL, &cb) == ERROR_SUCCESS
        && type == REG_MULTI_SZ && cb >= sizeof(WCHAR))
    {
        old = (BYTE *)HeapAlloc(GetProcessHeap(), 0, cb);
        if (old && RegQueryValueExW(k, name, NULL, &type, old, &cb) == ERROR_SUCCESS)
            oldLen = (cb >= sizeof(WCHAR)) ? cb - sizeof(WCHAR) : 0; /* drop final NUL */
        else
            oldLen = 0;
    }

    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, oldLen + addLen + sizeof(WCHAR));
    if (buf)
    {
        if (oldLen) memcpy(buf, old, oldLen);
        memcpy(buf + oldLen, line, addLen);
        *(WCHAR *)(buf + oldLen + addLen) = L'\0'; /* terminating empty string */
        RegSetValueExW(k, name, 0, REG_MULTI_SZ, buf, oldLen + addLen + sizeof(WCHAR));
        HeapFree(GetProcessHeap(), 0, buf);
    }
    if (old) HeapFree(GetProcessHeap(), 0, old);
}

/* Read a whole REG_MULTI_SZ; caller frees with HeapFree. NULL if absent. */
static WCHAR *MultiSzRead(HKEY k, LPCWSTR name)
{
    DWORD cb = 0, type = 0;
    WCHAR *buf;
    if (RegQueryValueExW(k, name, NULL, &type, NULL, &cb) != ERROR_SUCCESS
        || type != REG_MULTI_SZ || cb < sizeof(WCHAR))
        return NULL;
    buf = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, cb + sizeof(WCHAR));
    if (!buf) return NULL;
    if (RegQueryValueExW(k, name, NULL, &type, (LPBYTE)buf, &cb) != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }
    buf[cb / sizeof(WCHAR)] = L'\0';
    return buf;
}

/* ---- INI manifest parsing ------------------------------------------------ */

static FM_TIER ParseTier(LPCWSTR s)
{
    return (!_wcsicmp(s, L"software")) ? FM_TIER_SOFTWARE : FM_TIER_OS;
}

/* Read [Payload]/[Registry] style sections: returns a double-NUL buffer of
 * "Key=Value" lines (as from GetPrivateProfileSection). Caller frees. */
static WCHAR *ReadSection(LPCWSTR file, LPCWSTR section)
{
    DWORD cap = 2048, n;
    WCHAR *buf;
    for (;;)
    {
        buf = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, cap * sizeof(WCHAR));
        if (!buf) return NULL;
        n = GetPrivateProfileSectionW(section, buf, cap, file);
        if (n < cap - 2) return buf;
        HeapFree(GetProcessHeap(), 0, buf);
        cap *= 2;
        if (cap > 1 << 20) { return NULL; }
    }
}

/* ---- manifest reading ---------------------------------------------------
 * GetPrivateProfileString re-opens and re-parses the file on nearly every call (its cache
 * holds a few files), which made enumerating a few thousand generated entries (a Scoop
 * bucket) take tens of seconds. Generated entries (Catalog\Software) are therefore read
 * once into memory and queried from there; hand-written image manifests keep the API. */

typedef struct _INI { LPCWSTR path; WCHAR *mem; } INI;

static WCHAR *IniLoadText(LPCWSTR path)
{
    HANDLE h;
    DWORD sz, got = 0;
    BYTE *b;
    WCHAR *w = NULL;

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz < 2 || sz > 256 * 1024) { CloseHandle(h); return NULL; }
    b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sz + 2);
    if (!b) { CloseHandle(h); return NULL; }
    if (!ReadFile(h, b, sz, &got, NULL) || got != sz) { HeapFree(GetProcessHeap(), 0, b); CloseHandle(h); return NULL; }
    CloseHandle(h);
    b[sz] = b[sz + 1] = 0;
    if (b[0] == 0xFF && b[1] == 0xFE)                       /* UTF-16LE with BOM (what we generate) */
    {
        w = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, sz + 2);
        if (w) { memcpy(w, b + 2, sz - 2); w[(sz - 2) / 2] = L'\0'; }
    }
    else
    {
        BYTE *src = b; int len = (int)sz;
        UINT cp = CP_ACP;
        if (sz >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) { src += 3; len -= 3; cp = CP_UTF8; }
        w = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, ((size_t)len + 1) * sizeof(WCHAR));
        if (w)
        {
            int n = MultiByteToWideChar(cp, 0, (LPCSTR)src, len, w, len);
            w[n > 0 ? n : 0] = L'\0';
        }
    }
    HeapFree(GetProcessHeap(), 0, b);
    return w;
}

/* key in [sec] of the in-memory text; same matching rules as GetPrivateProfileString (case
 * insensitive, whitespace around the name and the value trimmed, ';' lines are comments). */
static BOOL IniFind(const WCHAR *t, LPCWSTR sec, LPCWSTR key, LPWSTR out, DWORD cch)
{
    size_t secLen = wcslen(sec), keyLen = wcslen(key);
    BOOL in = FALSE;

    while (*t)
    {
        const WCHAR *ls = t, *le = t, *p;
        while (*le && *le != L'\n') le++;
        t = *le ? le + 1 : le;
        while (le > ls && (le[-1] == L'\r' || le[-1] == L' ' || le[-1] == L'\t')) le--;
        while (ls < le && (*ls == L' ' || *ls == L'\t' || *ls == 0xFEFF)) ls++;
        if (ls >= le || *ls == L';') continue;
        if (*ls == L'[')
        {
            const WCHAR *e = ls + 1;
            while (e < le && *e != L']') e++;
            in = ((size_t)(e - (ls + 1)) == secLen) && !_wcsnicmp(ls + 1, sec, secLen);
            continue;
        }
        if (!in) continue;
        p = ls;
        while (p < le && *p != L'=') p++;
        if (p >= le) continue;
        {
            const WCHAR *ke = p;
            while (ke > ls && (ke[-1] == L' ' || ke[-1] == L'\t')) ke--;
            if ((size_t)(ke - ls) != keyLen || _wcsnicmp(ls, key, keyLen)) continue;
        }
        p++;
        while (p < le && (*p == L' ' || *p == L'\t')) p++;
        if (cch)
        {
            size_t n = (size_t)(le - p);
            if (n >= cch) n = cch - 1;
            memcpy(out, p, n * sizeof(WCHAR));
            out[n] = L'\0';
        }
        return TRUE;
    }
    return FALSE;
}

static void IniOpen(INI *i, LPCWSTR path, BOOL fast)
{
    i->path = path;
    i->mem = fast ? IniLoadText(path) : NULL;
}

static void IniClose(INI *i)
{
    if (i->mem) HeapFree(GetProcessHeap(), 0, i->mem);
    i->mem = NULL;
}

static void IniGet(const INI *i, LPCWSTR sec, LPCWSTR key, LPCWSTR def, LPWSTR out, DWORD cch)
{
    if (i->mem)
    {
        if (!IniFind(i->mem, sec, key, out, cch)) StringCchCopyW(out, cch, def);
        return;
    }
    GetPrivateProfileStringW(sec, key, def, out, cch, i->path);
}

/* One value of a generated manifest, read once from disk (used by the Scoop importer). */
BOOL FmIniGetFast(LPCWSTR path, LPCWSTR sec, LPCWSTR key, LPWSTR out, DWORD cch)
{
    WCHAR *t = IniLoadText(path);
    BOOL ok;
    if (cch) out[0] = L'\0';
    if (!t) return FALSE;
    ok = IniFind(t, sec, key, out, cch);
    HeapFree(GetProcessHeap(), 0, t);
    return ok;
}

/* Load the catalog fields of one manifest into *f (does not set State). fast = read the file once. */
static BOOL LoadManifestEx(LPCWSTR path, FM_FEATURE *f, BOOL fast)
{
    WCHAR tmp[FM_MAX_DESC];
    INI ini;

    ZeroMemory(f, sizeof(*f));
    StringCchCopyW(f->ManifestPath, MAX_PATH, path);
    IniOpen(&ini, path, fast);

    IniGet(&ini, L"Feature", L"Id", L"", f->Id, FM_MAX_ID);
    if (!f->Id[0]) { IniClose(&ini); return FALSE; }
    IniGet(&ini, L"Feature", L"Name", f->Id, f->Name, FM_MAX_NAME);
    IniGet(&ini, L"Feature", L"Description", L"", f->Description, FM_MAX_DESC);
    IniGet(&ini, L"Feature", L"Notice", L"", f->Notice, ARRAYSIZE(f->Notice));
    {   /* "\n" (backslash, n) => line break */
        WCHAR *r = f->Notice, *w = f->Notice;
        for (; *r; r++)
        {
            if (r[0] == L'\\' && r[1] == L'n') { *w++ = L'\n'; r++; }
            else *w++ = *r;
        }
        *w = L'\0';
    }
    IniGet(&ini, L"Feature", L"Version", L"1.0.0", f->Version, FM_MAX_VER);
    IniGet(&ini, L"Feature", L"Dependencies", L"", f->Dependencies, FM_MAX_DEPS);
    IniGet(&ini, L"Feature", L"Group", L"", f->Group, ARRAYSIZE(f->Group));
    IniGet(&ini, L"Feature", L"Tier", L"os", tmp, FM_MAX_DESC);
    f->Tier = ParseTier(tmp);
    IniGet(&ini, L"Feature", L"Removable", L"1", tmp, 16);
    f->Removable = _wtoi(tmp) != 0;
    /* [Install] Provider= selects the software-tier install path. A software-tier
     * manifest without it keeps the OS-tier mechanics ([Payload]/[Registry]/[Service]
     * applied from a staged payload), so older/hand-written manifests still work. */
    if (f->Tier == FM_TIER_SOFTWARE)
    {
        IniGet(&ini, L"Install", L"Provider", L"", f->Provider, ARRAYSIZE(f->Provider));
        IniGet(&ini, L"Install", L"DetectPath", L"", f->Detect, ARRAYSIZE(f->Detect));
        if (!_wcsicmp(f->Provider, L"scoop"))
        {
            WCHAR b[24];
            IniGet(&ini, L"Scoop", L"Bucket", L"", b, ARRAYSIZE(b));
            IniGet(&ini, L"Scoop", L"App", L"", f->App, ARRAYSIZE(f->App));
            StringCchPrintfW(f->Source, ARRAYSIZE(f->Source), L"scoop/%s", b[0] ? b : L"?");
            StringCchCopyW(f->Bucket, ARRAYSIZE(f->Bucket), b);
            IniGet(&ini, L"Scoop", L"Homepage", L"", f->Homepage, ARRAYSIZE(f->Homepage));
            IniGet(&ini, L"Scoop", L"License", L"", f->License, ARRAYSIZE(f->License));
            IniGet(&ini, L"Scoop", L"Verified", L"1", tmp, 16);
            f->Verified = _wtoi(tmp) != 0;
        }
        else
        {
            if (FmNativeIsProvider(f->Provider))
            {
                /* "rapps" is the old spelling of the native provider (caches written before rapps.exe went away) */
                WCHAR pk[8];
                StringCchCopyW(f->Provider, ARRAYSIZE(f->Provider), L"native");
                IniGet(&ini, L"Rapps", L"Pkg", L"", pk, ARRAYSIZE(pk));
                IniGet(&ini, L"Rapps", L"RegName", L"", f->RegName, ARRAYSIZE(f->RegName));
                if (!f->RegName[0]) IniGet(&ini, L"Rapps", L"UninstallName", L"", f->RegName, ARRAYSIZE(f->RegName));
                /* entries from the RAPPS catalog say "rapps", the hand-written ones (PowerShell 7, Claude Desktop) "native" */
                StringCchCopyW(f->Source, ARRAYSIZE(f->Source), pk[0] && !_wcsnicmp(f->Id, L"rapps-", 6) ? L"rapps" : L"native");
            }
            else
                StringCchCopyW(f->Source, ARRAYSIZE(f->Source), f->Provider[0] ? f->Provider : L"payload");
        }
    }
    IniClose(&ini);
    return TRUE;
}

/* ---- software tier: command expansion + availability -------------------- */

/* Expand %PAYLOAD% (the feature's staged payload dir) and %env% variables. */
static void ExpandCmd(LPCWSTR id, LPCWSTR raw, LPWSTR out, DWORD cch)
{
    WCHAR tmp[2048], payload[MAX_PATH], sroot[MAX_PATH];
    LPCWSTR p = raw;
    DWORD n = 0;
    FmGetPayloadDir(id, payload, MAX_PATH);
    if (!FmScoopRoot(sroot, MAX_PATH)) sroot[0] = L'\0';
    while (*p && n + 1 < ARRAYSIZE(tmp))
    {
        if (!_wcsnicmp(p, L"%SCOOPROOT%", 11))
        {
            size_t l = wcslen(sroot);
            if (n + l + 1 >= ARRAYSIZE(tmp)) break;
            memcpy(tmp + n, sroot, l * sizeof(WCHAR));
            n += (DWORD)l;
            p += 11;
            continue;
        }
        if (!_wcsnicmp(p, L"%PAYLOAD%", 9))
        {
            size_t l = wcslen(payload);
            if (n + l + 1 >= ARRAYSIZE(tmp)) break;
            memcpy(tmp + n, payload, l * sizeof(WCHAR));
            n += (DWORD)l;
            p += 9;
        }
        else
            tmp[n++] = *p++;
    }
    tmp[n] = L'\0';
    if (!ExpandEnvironmentStringsW(tmp, out, cch))
        StringCchCopyW(out, cch, tmp);
}

static BOOL IsAbsPath(LPCWSTR s)
{
    return (s[0] && s[1] == L':') || (s[0] == L'\\');
}

static BOOL IsPs1(LPCWSTR path)
{
    return !_wcsicmp(PathFindExtensionW(path), L".ps1");
}

static BOOL IsScript(LPCWSTR path)
{
    LPCWSTR ext = PathFindExtensionW(path);
    return !_wcsicmp(ext, L".cmd") || !_wcsicmp(ext, L".bat");
}

/* Full path of the command-provider installer ([Install] Installer=). */
static BOOL InstallerPath(const FM_FEATURE *f, LPWSTR out, DWORD cch)
{
    WCHAR raw[MAX_PATH], exp[MAX_PATH];
    GetPrivateProfileStringW(L"Install", L"Installer", L"", raw, MAX_PATH, f->ManifestPath);
    if (!raw[0]) return FALSE;
    ExpandCmd(f->Id, raw, exp, MAX_PATH);
    if (IsAbsPath(exp))
        return SUCCEEDED(StringCchCopyW(out, cch, exp));
    FmGetPayloadDir(f->Id, out, cch);
    return SUCCEEDED(StringCchCatW(out, cch, L"\\")) && SUCCEEDED(StringCchCatW(out, cch, exp));
}

/* Can the install be attempted? native provider: the entry has an address and a checksum (the download
 * happens at install time, so there is no staged payload to check). command
 * provider: the installer file is staged. */
static BOOL SoftwareAvailable(const FM_FEATURE *f)
{
    WCHAR p[MAX_PATH];
    if (!_wcsicmp(f->Provider, L"command"))
        return InstallerPath(f, p, MAX_PATH) && GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
    if (!_wcsicmp(f->Provider, L"scoop"))
        return FmScoopUsable();
    if (!_wcsicmp(f->Provider, L"component"))
    {
        FM_COMPONENT c;                                 /* downloaded by featmgr itself: needs only its list entry */
        return FmCompLoad(f->Id, &c) && c.ArchOk && c.Install[0];
    }
    if (FmNativeIsProvider(f->Provider))
        return FmNativeAvailable(f);                    /* a download address and a checksum, for this architecture */
    return FALSE;                                       /* unknown provider */
}

/* ---- hosted payloads ([Download]) ------------------------------------------
 * An OS-tier pack whose files are not in the image lists them in [Download]:
 *     File<N>=<name>|<sha256>|<size in bytes>
 * <name> is the [Payload] source name of the file. At enable time each file that is not already staged (and
 * verified) in the feature's payload dir is fetched over https from
 *     <base>/<[Source] Path>/<name>
 * with the component downloader (progress, retries, cancel), refused unless its SHA-256 matches, and moved into the
 * payload dir; [Payload]/[Registry] are then applied as for any staged pack, and the downloaded copies are deleted.
 * <base> = HKLM\SOFTWARE\ReactOS\Nitro\Featmgr PayloadBaseUrl (REG_SZ) when set, else [Source] BaseUrl of the
 * manifest. A base that still holds the placeholder (REPLACE-WITH-...) means the hosting is not published yet: the
 * pack is listed as not available yet, and enable is refused before anything is changed. */
static const WCHAR SETTINGS_KEY[] = L"SOFTWARE\\ReactOS\\Nitro\\Featmgr";
#define URL_PLACEHOLDER L"REPLACE-WITH-"

static BOOL HostedPack(const FM_FEATURE *f)
{
    WCHAR *sect;
    BOOL any;
    if (f->Tier != FM_TIER_OS) return FALSE;
    sect = ReadSection(f->ManifestPath, L"Download");
    if (!sect) return FALSE;
    any = sect[0] != L'\0';                       /* an absent section reads as an empty buffer */
    HeapFree(GetProcessHeap(), 0, sect);
    return any;
}

/* The pinned SHA-256 of a [Download] file (FALSE: the file has no [Download] line). */
static BOOL DownloadShaFor(LPCWSTR manifest, LPCWSTR name, WCHAR sha[72])
{
    WCHAR *sect, *line;
    size_t l = wcslen(name);
    BOOL found = FALSE;
    if (!(sect = ReadSection(manifest, L"Download"))) return FALSE;
    for (line = sect; *line && !found; line += wcslen(line) + 1)
    {
        WCHAR *eq = wcschr(line, L'='), *bar;
        if (!eq || line[0] == L';') continue;
        if (_wcsnicmp(eq + 1, name, l) || eq[1 + l] != L'|') continue;
        bar = wcschr(eq + 1 + l + 1, L'|');
        if (bar) *bar = L'\0';
        StringCchCopyW(sha, 72, eq + 1 + l + 1);
        found = TRUE;
    }
    HeapFree(GetProcessHeap(), 0, sect);
    return found;
}

/* The base address of hosted payloads (no trailing '/'): the registry setting, else the manifest's default. */
static BOOL HostedBaseUrl(LPCWSTR manifest, LPWSTR out, DWORD cch)
{
    HKEY k;
    DWORD type, cb;
    size_t n;

    out[0] = L'\0';
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SETTINGS_KEY, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS)
    {
        cb = (cch - 1) * sizeof(WCHAR);
        if (RegQueryValueExW(k, L"PayloadBaseUrl", NULL, &type, (LPBYTE)out, &cb) != ERROR_SUCCESS
            || (type != REG_SZ && type != REG_EXPAND_SZ))
            cb = 0;
        out[min(cb / sizeof(WCHAR), cch - 1)] = L'\0';
        RegCloseKey(k);
    }
    StrTrimW(out, L" \t");
    if (!out[0])
        GetPrivateProfileStringW(L"Source", L"BaseUrl", L"", out, cch, manifest);
    StrTrimW(out, L" \t");
    n = wcslen(out);
    while (n && out[n - 1] == L'/') out[--n] = L'\0';
    return out[0] != L'\0';
}

/* Total size of a hosted pack's [Download] files (0: none / not a hosted pack). */
ULONGLONG FmHostedDownloadSize(LPCWSTR manifest)
{
    WCHAR *sect, *line, *last;
    ULONGLONG n = 0;
    if (!(sect = ReadSection(manifest, L"Download"))) return 0;
    for (line = sect; *line; line += wcslen(line) + 1)
        if (line[0] != L';' && (last = wcsrchr(line, L'|')) != NULL) n += _wcstoui64(last + 1, NULL, 10);
    HeapFree(GetProcessHeap(), 0, sect);
    return n;
}

/* Can the hosted files be downloaded? FALSE with the reason (for the UI) when not. */
static BOOL HostedUsable(LPCWSTR manifest, LPWSTR why, DWORD cch)
{
    WCHAR base[512];
    if (!HostedBaseUrl(manifest, base, ARRAYSIZE(base)) || StrStrIW(base, URL_PLACEHOLDER))
    {
        StringCchCopyW(why, cch, L"Not available yet: the download location of this pack has not been published yet.");
        return FALSE;
    }
    if (_wcsnicmp(base, L"https://", 8))
    {
        StringCchPrintfW(why, cch, L"Not available: the download address of this pack (%.200s) is not an https address; "
                                   L"featmgr only downloads over https.", base);
        return FALSE;
    }
    return TRUE;
}

/* [Source] Arch= (x86, amd64): FALSE with the reason when this build is not listed. */
static BOOL ManifestArchOk(LPCWSTR manifest, LPWSTR why, DWORD cch)
{
    WCHAR arch[64];
    GetPrivateProfileStringW(L"Source", L"Arch", L"", arch, ARRAYSIZE(arch), manifest);
    if (FmArchListed(arch)) return TRUE;
    if (!_wcsicmp(arch, L"amd64"))
        StringCchCopyW(why, cch, L"Only for 64-bit (amd64) NitroOS: not available on this 32-bit (x86) system.");
    else
        StringCchPrintfW(why, cch, L"Not available on this architecture (it is for %s only).", arch);
    return FALSE;
}

/* Does every declared [Payload] source file exist on disk? */
static BOOL StagedPayloadPresent(const FM_FEATURE *f)
{
    WCHAR payloadDir[MAX_PATH], src[MAX_PATH];
    WCHAR *sect, *p, *sep;
    BOOL ok = TRUE;

    sect = ReadSection(f->ManifestPath, L"Payload");
    if (!sect) return TRUE; /* no payload section => registry-only, always available */

    if (!FmGetPayloadDir(f->Id, payloadDir, MAX_PATH)) { HeapFree(GetProcessHeap(),0,sect); return FALSE; }

    for (p = sect; *p; p += wcslen(p) + 1)
    {
        /* line is File<N>=<src>|<dest> ; take src (before '|') after '=' */
        WCHAR *eq = wcschr(p, L'=');
        if (!eq) continue;
        sep = wcschr(eq + 1, L'|');
        if (sep) *sep = L'\0';
        StringCchPrintfW(src, MAX_PATH, L"%s\\%s", payloadDir, eq + 1);
        if (GetFileAttributesW(src) == INVALID_FILE_ATTRIBUTES) { ok = FALSE; }
        if (sep) *sep = L'|';
        if (!ok) break;
    }
    HeapFree(GetProcessHeap(), 0, sect);
    return ok;
}

/* Can the feature be turned on: software tier = its provider works; OS tier = this architecture is listed and the
 * payload is staged, or it is a hosted pack whose download location is published. Sets f->Hosted / f->Unavailable. */
static BOOL PayloadPresent(FM_FEATURE *f)
{
    f->Hosted = FALSE;
    f->Unavailable[0] = L'\0';
    if (f->Tier == FM_TIER_SOFTWARE && f->Provider[0])
        return SoftwareAvailable(f);
    if (!ManifestArchOk(f->ManifestPath, f->Unavailable, ARRAYSIZE(f->Unavailable)))
        return FALSE;
    if (StagedPayloadPresent(f))
        return TRUE;
    if (!HostedPack(f))
        return FALSE;
    f->Hosted = TRUE;
    return HostedUsable(f->ManifestPath, f->Unavailable, ARRAYSIZE(f->Unavailable));
}

/* [Feature] BuiltInFile=<path>: the image itself carries what this pack installs (setup put it in place, e.g. an
 * image built with the llvmpipe/lavapipe GPU stack in system32). With no featmgr record for the feature and that file
 * present, the feature is shown Enabled and cannot be turned off here: there is no in-box copy to put back. */
static void ResolveBuiltIn(FM_FEATURE *f)
{
    WCHAR raw[MAX_PATH], path[MAX_PATH];
    HKEY k;

    f->BuiltIn = FALSE;
    if (f->Tier != FM_TIER_OS) return;
    GetPrivateProfileStringW(L"Feature", L"BuiltInFile", L"", raw, ARRAYSIZE(raw), f->ManifestPath);
    if (!raw[0]) return;
    if (OpenStateKey(f->Id, FALSE, KEY_READ, &k) == ERROR_SUCCESS) { RegCloseKey(k); return; }   /* featmgr owns it */
    if (!ExpandEnvironmentStringsW(raw, path, ARRAYSIZE(path)) || GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
        return;
    f->BuiltIn = TRUE;
    f->State = FM_STATE_ENABLED;
    f->Removable = FALSE;
}

static BOOL PendingRebootActive(HKEY state);

/* InstallDate / PendingReboot from the persisted record. */
static void ReadStateExtras(FM_FEATURE *f)
{
    HKEY k;
    DWORD cb, type;
    WCHAR v[32];

    f->InstallDate[0] = L'\0';
    f->InstalledVersion[0] = L'\0';
    f->PendingReboot = FALSE;
    if (OpenStateKey(f->Id, FALSE, KEY_READ, &k) != ERROR_SUCCESS) return;
    cb = sizeof(f->InstalledVersion) - sizeof(WCHAR);
    if (RegQueryValueExW(k, L"Version", NULL, &type, (LPBYTE)f->InstalledVersion, &cb) != ERROR_SUCCESS
        || type != REG_SZ)
        f->InstalledVersion[0] = L'\0';
    f->InstalledVersion[FM_MAX_VER - 1] = L'\0';
    cb = sizeof(f->InstallDate) - sizeof(WCHAR);
    if (RegQueryValueExW(k, L"InstallDate", NULL, &type, (LPBYTE)f->InstallDate, &cb) != ERROR_SUCCESS
        || type != REG_SZ)
        f->InstallDate[0] = L'\0';
    f->InstallDate[31] = L'\0';
    cb = sizeof(v) - sizeof(WCHAR);
    v[0] = L'\0';
    if (RegQueryValueExW(k, L"PendingReboot", NULL, &type, (LPBYTE)v, &cb) == ERROR_SUCCESS
        && type == REG_SZ)
    {
        v[31] = L'\0';
        if (!_wcsicmp(v, L"Yes")) f->PendingReboot = TRUE;
    }
    RegCloseKey(k);
    if (f->PendingReboot && OpenStateKey(f->Id, FALSE, KEY_READ | KEY_WRITE, &k) == ERROR_SUCCESS)
    {
        /* the reboot may have happened: the record is stale once the pending files / services are gone */
        f->PendingReboot = PendingRebootActive(k);
        RegCloseKey(k);
    }
}

/* ---- installed-state detection (software tier) ---------------------------- */

/* A software entry can name a path whose presence means "installed":
 * [Install] DetectPath= (%SCOOPROOT% / %env% expanded), and for Provider=scoop the app's
 * <root>\apps\<app>\current junction. The probe wins over the registry record, so installs
 * and removals done outside featmgr (the scoop CLI) are seen. */
static BOOL DetectPathFor(const FM_FEATURE *f, LPWSTR out, DWORD cch)
{
    if (f->Detect[0])
    {
        ExpandCmd(f->Id, f->Detect, out, cch);
        return TRUE;
    }
    if (!_wcsicmp(f->Provider, L"scoop"))
    {
        WCHAR root[MAX_PATH];
        if (!FmScoopValidApp(f->App) || !FmScoopRoot(root, MAX_PATH)) return FALSE;
        return SUCCEEDED(StringCchPrintfW(out, cch, L"%s\\apps\\%s\\current", root, f->App));
    }
    return FALSE;
}

static void ResolveState(FM_FEATURE *f)
{
    WCHAR p[MAX_PATH];
    BOOL present;
    if (f->Tier == FM_TIER_SOFTWARE && !_wcsicmp(f->Provider, L"component"))
    {
        /* the component list's detect rule decides (an install done outside featmgr is seen too) */
        FM_COMPONENT c;
        if (!FmCompLoad(f->Id, &c)) return;
        if (!c.DetectReg[0] && !c.DetectFile[0]) return;      /* no detect rule: the recorded state stands */
        present = FmCompDetect(&c);
    }
    else if (f->Tier != FM_TIER_SOFTWARE) return;
    else if (DetectPathFor(f, p, MAX_PATH))
        present = GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
    else if (!_wcsicmp(f->Provider, L"native") && (f->RegName[0] || f->Name[0]))
        present = FmNativeIsInstalled(f->RegName, f->Name);       /* the Uninstall keys, as RAPPS saw it; installs done by hand count */
    else return;
    if (present && f->State != FM_STATE_ENABLED)
        f->State = FM_STATE_ENABLED;
    else if (!present && f->State == FM_STATE_ENABLED)
        f->State = FM_STATE_NOT_INSTALLED;
}

/* Installed version: an enabled entry shows the version featmgr recorded when it enabled it
 * (ReadStateExtras); a Scoop app shows what is actually on disk, apps\\<app>\\current\\manifest.json,
 * which also covers installs and updates done with the scoop CLI. UpdateAvailable: the imported
 * catalog (the bucket manifest as of the last import) is newer than that. */
static void ResolveVersion(FM_FEATURE *f)
{
    f->UpdateAvailable = FALSE;
    if (f->State != FM_STATE_ENABLED) { f->InstalledVersion[0] = L'\0'; return; }
    if (!_wcsicmp(f->Provider, L"scoop"))
    {
        WCHAR v[FM_MAX_VER];
        if (FmScoopInstalledVersion(f->App, v, ARRAYSIZE(v)))
            StringCchCopyW(f->InstalledVersion, ARRAYSIZE(f->InstalledVersion), v);
        if (f->InstalledVersion[0] && f->Version[0] && wcscmp(f->Version, L"-")
            && FmCompareVersions(f->Version, f->InstalledVersion) > 0)
            f->UpdateAvailable = TRUE;
    }
}

/* State, availability, installed version of a freshly loaded entry. usable: -1 = ask, else
 * the Provider=scoop answer the caller already has (one lookup per enumeration, not per entry). */
static void FinishEntry(FM_FEATURE *f, int scoopUsable)
{
    f->State = RawState(f->Id);
    ResolveState(f);
    ResolveBuiltIn(f);
    if (scoopUsable >= 0 && !_wcsicmp(f->Provider, L"scoop"))
        f->PayloadAvailable = scoopUsable != 0;
    else
        f->PayloadAvailable = PayloadPresent(f);
    ReadStateExtras(f);
    ResolveVersion(f);
}

/* ---- enumeration --------------------------------------------------------- */

static BOOL AppendFeature(const FM_FEATURE *f, FM_FEATURE **parr, int *pcount, int *pcap)
{
    if (*pcount == *pcap)
    {
        int nc = *pcap ? *pcap * 2 : 8;
        FM_FEATURE *na = *parr
            ? (FM_FEATURE *)HeapReAlloc(GetProcessHeap(), 0, *parr, nc * sizeof(FM_FEATURE))
            : (FM_FEATURE *)HeapAlloc(GetProcessHeap(), 0, nc * sizeof(FM_FEATURE));
        if (!na) return FALSE;
        *parr = na; *pcap = nc;
    }
    (*parr)[(*pcount)++] = *f;
    return TRUE;
}

/* Append every valid manifest in dir (*.ini) to the growing array. */
static void EnumDir(LPCWSTR dir, BOOL fast, FM_FEATURE **parr, int *pcount, int *pcap)
{
    WCHAR glob[MAX_PATH], path[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;

    StringCchPrintfW(glob, MAX_PATH, L"%s\\*.ini", dir);
    h = FindFirstFileW(glob, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do
    {
        FM_FEATURE f;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        StringCchPrintfW(path, MAX_PATH, L"%s\\%s", dir, fd.cFileName);
        if (!LoadManifestEx(path, &f, fast)) continue;
        FinishEntry(&f, -1);
        if (!AppendFeature(&f, parr, pcount, pcap)) break;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

typedef struct _IDXENUM { FM_FEATURE **parr; int *pcount, *pcap; int usable; } IDXENUM;

static BOOL IdxEnumCb(void *ctx, const FM_FEATURE *rec)
{
    IDXENUM *e = (IDXENUM *)ctx;
    FM_FEATURE f = *rec;
    FinishEntry(&f, e->usable);
    return AppendFeature(&f, e->parr, e->pcount, e->pcap);
}

/* Catalog = in-image OS manifests (Catalog\*.ini) + the generated software
 * cache (Catalog\Software\*.ini, written on demand by FmImportRapps). */
int FmEnumFeatures(FM_FEATURE **outArr)
{
    WCHAR catDir[MAX_PATH], swDir[MAX_PATH];
    FM_FEATURE *arr = NULL;
    int count = 0, cap = 0;

    *outArr = NULL;
    FmNativeInvalidate();                 /* installed programs are read once per enumeration */
    if (!FmGetCatalogDir(catDir, MAX_PATH)) return 0;
    EnumDir(catDir, FALSE, &arr, &count, &cap);
    if (FmGetSoftwareCatalogDir(swDir, MAX_PATH))
    {
        IDXENUM e;
        EnumDir(swDir, TRUE, &arr, &count, &cap);
        e.parr = &arr; e.pcount = &count; e.pcap = &cap;
        e.usable = FmScoopUsable() ? 1 : 0;
        FmScoopIndexEnum(swDir, IdxEnumCb, &e);
    }

    *outArr = arr;
    return count;
}

void FmFree(FM_FEATURE *arr)
{
    if (arr) HeapFree(GetProcessHeap(), 0, arr);
}

/* Fast path: the manifest file is named after the id (the software cache can hold
 * thousands of entries, do not parse them all for a single lookup). */
static BOOL FindByName(LPCWSTR id, FM_FEATURE *out)
{
    WCHAR dir[MAX_PATH], path[MAX_PATH];
    int k;

    if (!id[0] || wcspbrk(id, L"\\/:*?\"<>|")) return FALSE;
    for (k = 0; k < 2; k++)
    {
        if (!(k ? FmGetSoftwareCatalogDir(dir, MAX_PATH) : FmGetCatalogDir(dir, MAX_PATH))) continue;
        StringCchPrintfW(path, MAX_PATH, L"%s\\%s.ini", dir, id);
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) continue;
        if (LoadManifestEx(path, out, k == 1) && !_wcsicmp(out->Id, id))
        {
            FinishEntry(out, -1);
            return TRUE;
        }
    }
    if (FmGetSoftwareCatalogDir(dir, MAX_PATH) && FmScoopIndexFind(dir, id, out))
    {
        FinishEntry(out, -1);
        return TRUE;
    }
    return FALSE;
}

BOOL FmFindFeature(LPCWSTR id, FM_FEATURE *out)
{
    FM_FEATURE *arr;
    int n, i;
    BOOL found = FALSE;

    FmNativeInvalidate();
    if (FindByName(id, out)) return TRUE;
    n = FmEnumFeatures(&arr);
    for (i = 0; i < n; i++)
    {
        if (!_wcsicmp(arr[i].Id, id)) { *out = arr[i]; found = TRUE; break; }
    }
    FmFree(arr);
    return found;
}

/* Public state: the registry record merged with the installed-state probe. */
FM_STATE FmGetState(LPCWSTR id)
{
    FM_FEATURE f;
    if (FindByName(id, &f)) return f.State;
    return RawState(id);
}

/* ---- apply / revert ------------------------------------------------------ */

static HKEY HiveFromName(LPCWSTR s)
{
    if (!_wcsicmp(s, L"HKLM")) return HKEY_LOCAL_MACHINE;
    if (!_wcsicmp(s, L"HKCU")) return HKEY_CURRENT_USER;
    if (!_wcsicmp(s, L"HKCR")) return HKEY_CLASSES_ROOT;
    return NULL;
}

/* Copy one payload file; records absolute dest into the state "Files" list.
 * A file that already exists at the destination (e.g. the in-box softpipe
 * libgallium_wgl.dll that the lavapipe pack replaces) is moved aside to
 * <dest>.fmbak first and recorded in "Backups" as "dest|bak", so disable can
 * put the original back instead of just deleting it. */
static HRESULT ApplyPayloadFile(LPCWSTR payloadDir, LPCWSTR srcRel, LPCWSTR destRaw,
                                LPCWSTR wantSha, HKEY state, FILE *log)
{
    WCHAR src[MAX_PATH], dest[MAX_PATH], destDir[MAX_PATH], bak[MAX_PATH + 8], rec[2 * MAX_PATH + 16];
    StringCchPrintfW(src, MAX_PATH, L"%s\\%s", payloadDir, srcRel);
    ExpandEnvironmentStringsW(destRaw, dest, MAX_PATH);

    StringCchCopyW(destDir, MAX_PATH, dest);
    PathRemoveFileSpecW(destDir);
    SHCreateDirectoryExW(NULL, destDir, NULL);

    if (GetFileAttributesW(dest) != INVALID_FILE_ATTRIBUTES)
    {
        StringCchPrintfW(bak, MAX_PATH + 8, L"%s.fmbak", dest);
        DeleteFileW(bak);
        LOGF(log, L"  backup: %s -> %s\n", dest, bak);
        if (!MoveFileW(dest, bak))
        {
            LOGF(log, L"  ERROR: cannot back up existing file (%lu)\n", GetLastError());
            return HRESULT_FROM_WIN32(GetLastError());
        }
        StringCchPrintfW(rec, ARRAYSIZE(rec), L"%s|%s", dest, bak);
        MultiSzAppend(state, L"Backups", rec);
    }

    LOGF(log, L"  file: %s -> %s\n", src, dest);
    MultiSzAppend(state, L"Files", dest);
    if (!CopyFileW(src, dest, FALSE))
    {
        LOGF(log, L"  ERROR: CopyFile failed (%lu)\n", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    if (wantSha)
    {
        /* hosted pack: check what actually landed at the destination against the pinned hash */
        WCHAR got[72];
        if (!FmFileSha256(dest, got) || _wcsicmp(got, wantSha))
        {
            LOGF(log, L"  ERROR: %s does not match its pinned SHA-256 after the copy (expected %s)\n", dest, wantSha);
            SetLastMsg(L"An installed file of this pack does not match its pinned SHA-256 checksum; the change was undone.");
            return HRESULT_FROM_WIN32(ERROR_CRC);
        }
    }
    return S_OK;
}

/* hex text (two digits per byte, no separators) -> bytes; returns the byte count or -1 */
static int HexToBytes(LPCWSTR hex, BYTE *out, int cap)
{
    int n = 0;
    if (!hex) return 0;
    while (hex[0] && hex[1])
    {
        int v = 0, i;
        for (i = 0; i < 2; i++)
        {
            WCHAR c = hex[i];
            int d = (c >= L'0' && c <= L'9') ? c - L'0' : (c >= L'a' && c <= L'f') ? c - L'a' + 10 :
                    (c >= L'A' && c <= L'F') ? c - L'A' + 10 : -1;
            if (d < 0) return -1;
            v = v * 16 + d;
        }
        if (n >= cap) return -1;
        out[n++] = (BYTE)v;
        hex += 2;
    }
    return hex[0] ? -1 : n;
}

static void BytesToHex(const BYTE *b, DWORD cb, LPWSTR out)
{
    static const WCHAR digits[] = L"0123456789abcdef";
    DWORD i;
    for (i = 0; i < cb; i++) { out[i * 2] = digits[b[i] >> 4]; out[i * 2 + 1] = digits[b[i] & 15]; }
    out[cb * 2] = L'\0';
}

/* Set one registry value, recording undo info. Value spec: HIVE|subkey|name|type|data
 * name "@" => default value. type REG_SZ, REG_DWORD or REG_BINARY (data = hex digits, up to 512 bytes).
 * type KEY (name empty, no data) only creates the key; when it did not exist, disable removes it again (if empty). */
static HRESULT ApplyRegAction(LPCWSTR spec, HKEY state, FILE *log)
{
    WCHAR buf[1024];
    WCHAR *tok[5] = {0};
    int ti = 0;
    WCHAR *p, *start;
    HKEY hive, k;
    LPCWSTR valName;
    WCHAR undo[1200];
    WCHAR prev[1024];
    DWORD prevType = 0, prevCb = sizeof(prev);
    LONG r;

    /* expand %VAR% (value names/data such as the Khronos ICD manifest path) */
    if (!ExpandEnvironmentStringsW(spec, buf, 1024))
        StringCchCopyW(buf, 1024, spec);
    /* split on '|' into up to 5 fields (keep empties) */
    start = buf;
    for (p = buf; ; p++)
    {
        if (*p == L'|' || *p == L'\0')
        {
            BOOL end = (*p == L'\0');
            *p = L'\0';
            if (ti < 5) tok[ti++] = start;
            start = p + 1;
            if (end) break;
        }
    }
    if (ti < 4) { LOGF(log, L"  bad reg spec: %s\n", spec); return E_INVALIDARG; }

    hive = HiveFromName(tok[0]);
    if (!hive) { LOGF(log, L"  bad hive: %s\n", tok[0]); return E_INVALIDARG; }
    valName = (!wcscmp(tok[2], L"@")) ? L"" : tok[2];

    {
        DWORD disp = 0;
        if (RegCreateKeyExW(hive, tok[1], 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &k, &disp)
            != ERROR_SUCCESS)
        {
            LOGF(log, L"  ERROR: open/create key %s failed\n", tok[1]);
            return E_FAIL;
        }
        if (!_wcsicmp(tok[3], L"KEY"))
        {
            if (disp == REG_CREATED_NEW_KEY)
            {
                StringCchPrintfW(undo, 1200, L"K|%s|%s", tok[0], tok[1]);
                MultiSzAppend(state, L"RegUndo", undo);
            }
            LOGF(log, L"  reg: key %s\\%s (%s)\n", tok[0], tok[1], disp == REG_CREATED_NEW_KEY ? L"created" : L"existed");
            RegCloseKey(k);
            return S_OK;
        }
    }

    /* record undo: existed? save prior; else mark for delete */
    r = RegQueryValueExW(k, valName, NULL, &prevType, (LPBYTE)prev, &prevCb);
    if (r == ERROR_SUCCESS && prevType == REG_BINARY && prevCb <= 512)
    {
        WCHAR hex[1100];
        BytesToHex((const BYTE *)prev, prevCb, hex);
        StringCchPrintfW(undo, 1200, L"R|%s|%s|%s|REG_BINARY|%s", tok[0], tok[1], tok[2], hex);
    }
    else if (r == ERROR_SUCCESS && prevType == REG_SZ)
        StringCchPrintfW(undo, 1200, L"R|%s|%s|%s|REG_SZ|%s", tok[0], tok[1], tok[2], prev);
    else if (r == ERROR_SUCCESS && prevType == REG_DWORD)
        StringCchPrintfW(undo, 1200, L"R|%s|%s|%s|REG_DWORD|%lu", tok[0], tok[1], tok[2], *(DWORD*)prev);
    else
        StringCchPrintfW(undo, 1200, L"D|%s|%s|%s", tok[0], tok[1], tok[2]);
    MultiSzAppend(state, L"RegUndo", undo);

    LOGF(log, L"  reg: %s\\%s [%s] = %s\n", tok[0], tok[1], tok[2], tok[4] ? tok[4] : L"");
    if (!_wcsicmp(tok[3], L"REG_DWORD"))
    {
        DWORD d = (DWORD)_wtoi(tok[4] ? tok[4] : L"0");
        RegSetValueExW(k, valName, 0, REG_DWORD, (const BYTE *)&d, sizeof(d));
    }
    else if (!_wcsicmp(tok[3], L"REG_BINARY"))
    {
        BYTE bin[512];
        int n = HexToBytes(tok[4], bin, sizeof(bin));
        if (n < 0)
        {
            LOGF(log, L"  bad REG_BINARY data in: %s\n", spec);
            RegCloseKey(k);
            return E_INVALIDARG;
        }
        RegSetValueExW(k, valName, 0, REG_BINARY, bin, (DWORD)n);
    }
    else
    {
        LPCWSTR data = tok[4] ? tok[4] : L"";
        RegSetValueExW(k, valName, 0, REG_SZ, (const BYTE *)data,
                       (DWORD)((wcslen(data) + 1) * sizeof(WCHAR)));
    }
    RegCloseKey(k);
    return S_OK;
}

static void RevertRegUndo(LPCWSTR line, FILE *log)
{
    WCHAR buf[1200];
    WCHAR *tok[6] = {0};
    int ti = 0;
    WCHAR *p, *start;
    HKEY hive, k;
    LPCWSTR valName;

    StringCchCopyW(buf, 1200, line);
    start = buf;
    for (p = buf; ; p++)
    {
        if (*p == L'|' || *p == L'\0')
        {
            BOOL end = (*p == L'\0');
            *p = L'\0';
            if (ti < 6) tok[ti++] = start;
            start = p + 1;
            if (end) break;
        }
    }
    if (ti < 3) return;
    hive = HiveFromName(tok[1]);
    if (!hive) return;
    if (!wcscmp(tok[0], L"K"))
    {
        /* a key this feature created: remove it when it is empty (RegDeleteKey refuses a key with subkeys; a value
         * someone else added afterwards keeps the key too) */
        if (RegOpenKeyExW(hive, tok[2], 0, KEY_READ, &k) == ERROR_SUCCESS)
        {
            DWORD nsub = 0, nval = 0;
            RegQueryInfoKeyW(k, NULL, NULL, NULL, &nsub, NULL, NULL, &nval, NULL, NULL, NULL, NULL);
            RegCloseKey(k);
            if (!nsub && !nval)
            {
                LOGF(log, L"  reg-undo: delete key %s\\%s\n", tok[1], tok[2]);
                RegDeleteKeyW(hive, tok[2]);
            }
        }
        return;
    }
    valName = (!wcscmp(tok[3] ? tok[3] : L"@", L"@")) ? L"" : tok[3];

    if (RegOpenKeyExW(hive, tok[2], 0, KEY_WRITE, &k) != ERROR_SUCCESS)
        return;

    if (!wcscmp(tok[0], L"D"))
    {
        LOGF(log, L"  reg-undo: delete %s\\%s [%s]\n", tok[1], tok[2], tok[3] ? tok[3] : L"@");
        RegDeleteValueW(k, valName);
    }
    else if (!wcscmp(tok[0], L"R") && ti >= 6)
    {
        LOGF(log, L"  reg-undo: restore %s\\%s [%s]=%s\n", tok[1], tok[2], tok[3], tok[5]);
        if (!_wcsicmp(tok[4], L"REG_DWORD"))
        {
            DWORD d = (DWORD)_wtoi(tok[5]);
            RegSetValueExW(k, valName, 0, REG_DWORD, (const BYTE *)&d, sizeof(d));
        }
        else if (!_wcsicmp(tok[4], L"REG_BINARY"))
        {
            BYTE bin[512];
            int n = HexToBytes(tok[5], bin, sizeof(bin));
            if (n >= 0) RegSetValueExW(k, valName, 0, REG_BINARY, bin, (DWORD)n);
        }
        else
        {
            RegSetValueExW(k, valName, 0, REG_SZ, (const BYTE *)tok[5],
                           (DWORD)((wcslen(tok[5]) + 1) * sizeof(WCHAR)));
        }
    }
    RegCloseKey(k);
}

/* ---- driver/service registration ----------------------------------------- */

/* [Service] spec: Name|Type|StartType|ImagePath|DisplayName|Run
 *   Type      = filesys | kernel | win32   (SERVICE_FILE_SYSTEM_DRIVER / KERNEL_DRIVER / WIN32_OWN_PROCESS)
 *   StartType = boot | system | auto | demand | disabled
 *   Run       = 1 => start the service right after creating it (failure is logged, not fatal)
 * Whether we created the service is recorded in the state value "Services"
 * (one service name per line) so disable removes exactly what enable made. */
static DWORD ParseSvcType(LPCWSTR s)
{
    if (!_wcsicmp(s, L"kernel")) return SERVICE_KERNEL_DRIVER;
    if (!_wcsicmp(s, L"win32"))  return SERVICE_WIN32_OWN_PROCESS;
    return SERVICE_FILE_SYSTEM_DRIVER;
}

static DWORD ParseSvcStart(LPCWSTR s)
{
    if (!_wcsicmp(s, L"boot"))     return SERVICE_BOOT_START;
    if (!_wcsicmp(s, L"system"))   return SERVICE_SYSTEM_START;
    if (!_wcsicmp(s, L"auto"))     return SERVICE_AUTO_START;
    if (!_wcsicmp(s, L"disabled")) return SERVICE_DISABLED;
    return SERVICE_DEMAND_START;
}

static HRESULT ApplyServiceAction(LPCWSTR spec, HKEY state, FILE *log)
{
    WCHAR buf[1024];
    WCHAR *tok[6] = {0};
    int ti = 0;
    WCHAR *p, *start;
    SC_HANDLE scm, svc;
    HRESULT hr = S_OK;

    StringCchCopyW(buf, 1024, spec);
    start = buf;
    for (p = buf; ; p++)
    {
        if (*p == L'|' || *p == L'\0')
        {
            BOOL end = (*p == L'\0');
            *p = L'\0';
            if (ti < 6) tok[ti++] = start;
            start = p + 1;
            if (end) break;
        }
    }
    if (ti < 4) { LOGF(log, L"  bad service spec: %s\n", spec); return E_INVALIDARG; }

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) { LOGF(log, L"  ERROR: OpenSCManager (%lu)\n", GetLastError()); return HRESULT_FROM_WIN32(GetLastError()); }

    svc = CreateServiceW(scm, tok[0], (ti > 4 && tok[4][0]) ? tok[4] : tok[0],
                         SERVICE_ALL_ACCESS, ParseSvcType(tok[1]), ParseSvcStart(tok[2]),
                         SERVICE_ERROR_NORMAL, tok[3], NULL, NULL, NULL, NULL, NULL);
    if (!svc)
    {
        DWORD e = GetLastError();
        /* a pre-existing service is not ours: refuse rather than adopt + later delete it */
        LOGF(log, L"  ERROR: CreateService %s failed (%lu)%s\n", tok[0], e,
             e == ERROR_SERVICE_EXISTS ? L" - already registered by something else" : L"");
        hr = HRESULT_FROM_WIN32(e);
    }
    else
    {
        LOGF(log, L"  service: created %s (type=%s start=%s image=%s)\n", tok[0], tok[1], tok[2], tok[3]);
        MultiSzAppend(state, L"Services", tok[0]);
        if (ti > 5 && _wtoi(tok[5]))
        {
            if (StartServiceW(svc, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                LOGF(log, L"  service: %s started\n", tok[0]);
            else
                LOGF(log, L"  warn: StartService %s failed (%lu); it stays registered\n", tok[0], GetLastError());
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return hr;
}

/* Stop (wait up to ~10 s) one service. TRUE if it is stopped / absent / never ran. */
static BOOL StopServiceByName(SC_HANDLE scm, LPCWSTR name, FILE *log)
{
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_ALL_ACCESS);
    SERVICE_STATUS ss;
    int i;
    BOOL ok = TRUE;
    if (!svc) return TRUE;
    if (QueryServiceStatus(svc, &ss) && ss.dwCurrentState != SERVICE_STOPPED)
    {
        LOGF(log, L"  service: stopping %s\n", name);
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        for (i = 0; i < 50; i++)
        {
            if (!QueryServiceStatus(svc, &ss) || ss.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(200);
        }
        if (!QueryServiceStatus(svc, &ss) || ss.dwCurrentState != SERVICE_STOPPED)
        {
            LOGF(log, L"  ERROR: service %s did not stop (state %lu); in use?\n", name, ss.dwCurrentState);
            ok = FALSE;
        }
    }
    CloseServiceHandle(svc);
    return ok;
}

/* Unregister the services enable created. A driver that cannot be unloaded on this
 * system (WinFsp registers a UNC provider with MUP, and an FSD with a live
 * \FileSystem device never stops under ReactOS) is set to Start=disabled and marked
 * for deletion; its name goes into "PendingServices" and removal completes at reboot. */
static void RemoveRecordedServices(HKEY state, FILE *log)
{
    WCHAR *svcs = MultiSzRead(state, L"Services"), *p;
    SC_HANDLE scm, svc;
    if (!svcs) return;
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm)
    {
        for (p = svcs; *p; p += wcslen(p) + 1)
        {
            BOOL stopped = StopServiceByName(scm, p, log);
            svc = OpenServiceW(scm, p, SERVICE_ALL_ACCESS);
            if (!svc) continue;
            if (!stopped)
            {
                LOGF(log, L"  note: %s cannot be unloaded while the system is up; disabling it, removal completes at reboot\n", p);
                ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE,
                                     NULL, NULL, NULL, NULL, NULL, NULL, NULL);
                MultiSzAppend(state, L"PendingServices", p);
            }
            LOGF(log, L"  service: deleting %s\n", p);
            if (!DeleteService(svc))
                LOGF(log, L"  warn: DeleteService %s failed (%lu)\n", p, GetLastError());
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    HeapFree(GetProcessHeap(), 0, svcs);
}

/* Is a previous disable still waiting for a reboot? Clears the markers once nothing is left. */
static BOOL PendingRebootActive(HKEY state)
{
    WCHAR *l, *p;
    BOOL active = FALSE;
    SC_HANDLE scm, svc;

    l = MultiSzRead(state, L"PendingFiles");
    if (l)
    {
        for (p = l; *p; p += wcslen(p) + 1)
            if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES) active = TRUE;
        HeapFree(GetProcessHeap(), 0, l);
    }
    l = MultiSzRead(state, L"PendingServices");
    if (l)
    {
        scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        for (p = l; *p && scm; p += wcslen(p) + 1)
        {
            svc = OpenServiceW(scm, p, SERVICE_QUERY_STATUS);
            if (svc) { active = TRUE; CloseServiceHandle(svc); }
        }
        if (scm) CloseServiceHandle(scm);
        HeapFree(GetProcessHeap(), 0, l);
    }
    if (!active)
    {
        RegDeleteValueW(state, L"PendingFiles");
        RegDeleteValueW(state, L"PendingServices");
        RegDeleteValueW(state, L"PendingReboot");
    }
    return active;
}

/* ---- software tier: run installer / uninstaller ------------------------- */

#define SW_RUN_TIMEOUT_MS (60u * 60u * 1000u)   /* download + install of a big app */

/* An installer or uninstaller may have changed the registry environment (the PowerShell 7 MSI adds its
 * folder to the system PATH). Windows installers broadcast this; explorer re-reads the environment on it,
 * so a command prompt opened afterwards sees the change without a logoff. Bounded: a hung window is skipped. */
static void NotifyEnvironmentChanged(void)
{
    DWORD_PTR res;
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment",
                        SMTO_ABORTIFHUNG | SMTO_NORMAL, 3000, &res);
}

/* ---- PATH change tracking (for the "open a new terminal" hint) ------------------------------------
 * The installer runs in a child process, so the shell that started featmgr keeps the PATH it had (the
 * same on Windows). Compare the registry PATH (machine + user, unexpanded) before and after the install;
 * when it changed, remember which feature did it so the CLI and the GUI can tell the user. */
static WCHAR g_PathChangedName[128];
static BOOL  g_PathChanged;

#define PATHSNAP_CCH 16384

static void ReadRegistryPaths(WCHAR *out, DWORD cch)
{
    static const struct { HKEY Root; LPCWSTR Key; } src[] = {
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" },
        { HKEY_CURRENT_USER, L"Environment" } };
    DWORD i, used = 0;
    out[0] = L'\0';
    for (i = 0; i < ARRAYSIZE(src); i++)
    {
        HKEY k;
        if (RegOpenKeyExW(src[i].Root, src[i].Key, 0, KEY_READ, &k) == ERROR_SUCCESS)
        {
            DWORD type, cb = (cch - used - 2) * sizeof(WCHAR);
            if (RegQueryValueExW(k, L"Path", NULL, &type, (LPBYTE)(out + used), &cb) == ERROR_SUCCESS
                && (type == REG_SZ || type == REG_EXPAND_SZ))
            {
                DWORD n = cb / sizeof(WCHAR);
                out[used + n] = L'\0';
                used += (DWORD)wcslen(out + used);     /* the stored size may or may not include the NUL */
            }
            RegCloseKey(k);
        }
        if (used + 2 >= cch) break;
        out[used++] = L'\n';     /* machine and user entries stay distinguishable */
        out[used] = L'\0';
    }
}

static void NotePathChange(const FM_FEATURE *f, const WCHAR *before)
{
    WCHAR *after = HeapAlloc(GetProcessHeap(), 0, PATHSNAP_CCH * sizeof(WCHAR));
    if (!after) return;
    ReadRegistryPaths(after, PATHSNAP_CCH);
    if (wcscmp(before, after))
    {
        g_PathChanged = TRUE;
        StringCchCopyW(g_PathChangedName, ARRAYSIZE(g_PathChangedName), f->Name[0] ? f->Name : f->Id);
    }
    HeapFree(GetProcessHeap(), 0, after);
}

BOOL FmTakePathChange(LPWSTR name, DWORD cch)
{
    BOOL r = g_PathChanged;
    if (name && cch) StringCchCopyW(name, cch, g_PathChangedName);
    g_PathChanged = FALSE;
    return r;
}

/* ---- refreshenv: bring a running shell's PATH up to date --------------------------------------
 * A child process cannot change its parent's environment (on Windows either), but a script that the shell
 * itself runs can: refreshenv.cmd runs inside cmd.exe, refreshenv.ps1 inside pwsh. Both ship in system32
 * (already on PATH, no profile edits). For PowerShell the .ps1 wins over the .cmd of the same name, so
 * "refreshenv" works in either shell. refreshenv.cmd asks featmgr /print-path for the value to set. */

BOOL FmRefreshEnvAvailable(void)
{
    WCHAR f[MAX_PATH];
    UINT n = GetSystemDirectoryW(f, MAX_PATH);
    if (!n || n + 16 >= MAX_PATH) return FALSE;
    StringCchCatW(f, MAX_PATH, L"\\refreshenv.cmd");
    return GetFileAttributesW(f) != INVALID_FILE_ATTRIBUTES;
}

static int PathKeyLen(const WCHAR *s, int n)
{
    while (n > 1 && s[n - 1] == L'\\') n--;       /* "C:\bin\" and "C:\bin" are the same entry */
    return n;
}

/* Append every entry of the ';'-separated list that the accumulator does not have yet (case-insensitive,
 * trailing backslash ignored, empty entries dropped). Stops, keeping what fits, when out is full. */
static void AddPathEntries(WCHAR *acc, DWORD cch, const WCHAR *list)
{
    const WCHAR *p = list;
    while (*p)
    {
        const WCHAR *e = wcschr(p, L';'), *a, *b;
        int n = e ? (int)(e - p) : (int)wcslen(p), kn, found = 0;
        const WCHAR *tok = p;
        p = e ? e + 1 : p + n;
        while (n > 0 && *tok == L' ') { tok++; n--; }
        while (n > 0 && tok[n - 1] == L' ') n--;
        if (!n) continue;
        kn = PathKeyLen(tok, n);
        for (a = acc; *a && !found; a = b ? b + 1 : a + wcslen(a))
        {
            int an;
            b = wcschr(a, L';');
            an = b ? (int)(b - a) : (int)wcslen(a);
            if (an && PathKeyLen(a, an) == kn && !_wcsnicmp(a, tok, kn)) found = 1;
            if (!b) break;
        }
        if (found) continue;
        {
            size_t used = wcslen(acc);
            if (used + (used ? 1 : 0) + (size_t)n + 1 > cch) return;
            if (used) acc[used++] = L';';
            memcpy(acc + used, tok, (size_t)n * sizeof(WCHAR));
            acc[used + n] = L'\0';
        }
    }
}

/* The PATH a process started now would get: the registry system PATH, then the user PATH (expanded),
 * then whatever the current PATH still has that the registry does not (a session-local addition is kept,
 * like a refresh that only adds). Returns FALSE when out is too small for even the registry part. */
BOOL FmRefreshedPath(WCHAR *out, DWORD cch)
{
    static const struct { HKEY Root; LPCWSTR Key; } src[] = {
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" },
        { HKEY_CURRENT_USER, L"Environment" } };
    WCHAR *raw, *exp, *cur;
    DWORD i, n;
    BOOL ok = FALSE;

    out[0] = L'\0';
    raw = HeapAlloc(GetProcessHeap(), 0, 3 * 32768 * sizeof(WCHAR));
    if (!raw) return FALSE;
    exp = raw + 32768;
    cur = exp + 32768;
    for (i = 0; i < ARRAYSIZE(src); i++)
    {
        HKEY k;
        if (RegOpenKeyExW(src[i].Root, src[i].Key, 0, KEY_READ, &k) != ERROR_SUCCESS) continue;
        {
            DWORD type = 0, cb = (32768 - 2) * sizeof(WCHAR);
            if (RegQueryValueExW(k, L"Path", NULL, &type, (LPBYTE)raw, &cb) == ERROR_SUCCESS
                && (type == REG_SZ || type == REG_EXPAND_SZ))
            {
                raw[cb / sizeof(WCHAR)] = L'\0';
                if (type == REG_EXPAND_SZ)
                {
                    n = ExpandEnvironmentStringsW(raw, exp, 32768);
                    if (!n || n > 32768) { exp[0] = L'\0'; StringCchCopyW(exp, 32768, raw); }
                }
                else StringCchCopyW(exp, 32768, raw);
                AddPathEntries(out, cch, exp);
            }
        }
        RegCloseKey(k);
    }
    n = GetEnvironmentVariableW(L"PATH", cur, 32768);
    if (n && n < 32768) AddPathEntries(out, cch, cur);
    ok = out[0] != L'\0';
    HeapFree(GetProcessHeap(), 0, raw);
    return ok;
}

/* shell: FM_SHELL_OTHER / FM_SHELL_CMD / FM_SHELL_POWERSHELL = what ran featmgr. */
void FmPathHint(LPCWSTR name, int shell, LPWSTR out, DWORD cch)
{
    if (shell != FM_SHELL_OTHER && FmRefreshEnvAvailable())
        StringCchPrintfW(out, cch,
            L"%s is installed. Open a new terminal, or run this in the current one:\n  refreshenv\n", name);
    else if (shell == FM_SHELL_POWERSHELL)
        StringCchPrintfW(out, cch,
            L"%s is installed. Open a new terminal to use it, or refresh this one:\n"
            L"  $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + "
            L"[Environment]::GetEnvironmentVariable('Path','User')\n", name);
    else
        StringCchPrintfW(out, cch,
            L"%s is installed. Open a new terminal window to use it: this one keeps the PATH it started with.\n", name);
}

/* ---- progress and cancel (GUI worker plumbing; see featmgr.h) ------------------
 * The CLI never calls FmOpBegin: no sink and no cancel event, so RunAndWait waits exactly as before. */

static FM_PROGRESS_FN g_ProgFn;
static void          *g_ProgCtx;
static HANDLE         g_hCancelEvt;          /* manual-reset, created by the first FmOpBegin */
static volatile LONG  g_Cancel;
static volatile LONG  g_MayMsi;
static BOOL           g_NoCancel;            /* cleanup after a cancel must itself run to the end */
static BOOL           g_MsiFinished;         /* a cancel let a Windows Installer package run to its end (see RunAndWait) */

void FmOpBegin(FM_PROGRESS_FN fn, void *ctx)
{
    g_ProgFn = fn;
    g_ProgCtx = ctx;
    InterlockedExchange(&g_Cancel, 0);
    InterlockedExchange(&g_MayMsi, 0);
    if (!g_hCancelEvt) g_hCancelEvt = CreateEventW(NULL, TRUE, FALSE, NULL);
    else ResetEvent(g_hCancelEvt);
}

void FmOpEnd(void) { g_ProgFn = NULL; g_ProgCtx = NULL; }

void FmOpCancel(void)
{
    InterlockedExchange(&g_Cancel, 1);
    if (g_hCancelEvt) SetEvent(g_hCancelEvt);
}

BOOL   FmOpCancelled(void) { return g_Cancel != 0 && !g_NoCancel; }
HANDLE FmOpCancelHandle(void) { return g_NoCancel ? NULL : g_hCancelEvt; }
BOOL   FmOpMayBeMsi(void) { return g_MayMsi != 0; }

void FmOpStep(LPCWSTR fmt, ...)
{
    WCHAR t[512];
    va_list ap;
    FM_PROGRESS_FN fn = g_ProgFn;
    if (!fn) return;
    va_start(ap, fmt);
    _vsnwprintf(t, ARRAYSIZE(t) - 1, fmt, ap);
    va_end(ap);
    t[ARRAYSIZE(t) - 1] = L'\0';
    fn(FM_PROG_STEP, t, g_ProgCtx);
}

void FmOpPhase(int phase)
{
    WCHAR t[16];
    FM_PROGRESS_FN fn = g_ProgFn;
    if (!fn) return;
    StringCchPrintfW(t, ARRAYSIZE(t), L"%d", phase);
    fn(FM_PROG_PHASE, t, g_ProgCtx);
}

void FmOpBytes(ULONGLONG done, ULONGLONG total)
{
    WCHAR t[64];
    FM_PROGRESS_FN fn = g_ProgFn;
    if (!fn) return;
    StringCchPrintfW(t, ARRAYSIZE(t), L"%I64u %I64u", done, total);
    fn(FM_PROG_BYTES, t, g_ProgCtx);
}

static volatile LONG g_RebootNeeded;
BOOL FmTakeRebootNeeded(void) { return InterlockedExchange(&g_RebootNeeded, 0) != 0; }

/* The newest non-blank line of a chunk of child output, for the status line. */
static void ReportOutputLine(LPCWSTR text)
{
    WCHAR line[256];
    size_t n = wcslen(text), b, len;
    FM_PROGRESS_FN fn = g_ProgFn;

    if (!fn) return;
    while (n && (text[n - 1] == L'\n' || text[n - 1] == L'\r' || text[n - 1] == L' ' || text[n - 1] == L'\t')) n--;
    if (!n) return;
    for (b = n; b && text[b - 1] != L'\n'; b--) ;
    len = n - b;
    if (len >= ARRAYSIZE(line)) { b = n - (ARRAYSIZE(line) - 1); len = ARRAYSIZE(line) - 1; }
    memcpy(line, text + b, len * sizeof(WCHAR));
    line[len] = L'\0';
    fn(FM_PROG_OUTPUT, line, g_ProgCtx);
}

/* ---- captured child output ------------------------------------------------
 * Installer / Scoop output is captured to a temp file (the child gets NUL as stdin, so it can
 * never block on a prompt), streamed to the log while it runs, and its tail is kept so a
 * failure can be shown to a caller that has no console (the GUI). */

#define TAIL_CHARS 1500
static WCHAR g_Tail[TAIL_CHARS + 1];

static void TailAppend(LPCWSTR text)
{
    size_t n = wcslen(text), cur = wcslen(g_Tail);
    if (n >= TAIL_CHARS) { StringCchCopyW(g_Tail, ARRAYSIZE(g_Tail), text + n - TAIL_CHARS); return; }
    if (cur + n > TAIL_CHARS)
    {
        size_t drop = cur + n - TAIL_CHARS;
        memmove(g_Tail, g_Tail + drop, (cur - drop + 1) * sizeof(WCHAR));
    }
    StringCchCatW(g_Tail, ARRAYSIZE(g_Tail), text);
}

/* bytes -> wide text without ANSI escapes and without carriage-return progress redraws */
static void CleanChunk(const char *b, DWORD n, LPWSTR out, DWORD cch)
{
    WCHAR *w = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR));
    DWORD i, o = 0, wl, lineStart = 0;
    int r;

    out[0] = L'\0';
    if (!w) return;
    r = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, b, (int)n, w, (int)n);
    if (r <= 0) r = MultiByteToWideChar(CP_OEMCP, 0, b, (int)n, w, (int)n);
    wl = r > 0 ? (DWORD)r : 0;
    for (i = 0; i < wl && o + 1 < cch; i++)
    {
        WCHAR c = w[i];
        if (c == 0x1B)                                   /* ESC [ ... final-letter */
        {
            if (i + 1 < wl && w[i + 1] == L'[')
            {
                i += 2;
                while (i < wl && !((w[i] >= L'@' && w[i] <= L'~'))) i++;
            }
            continue;
        }
        if (c == L'\r')
        {
            if (i + 1 < wl && w[i + 1] == L'\n') continue;   /* CRLF: the LF ends the line */
            o = lineStart;                                    /* redraw: drop the partial line */
            continue;
        }
        out[o++] = c;
        if (c == L'\n') lineStart = o;
    }
    out[o] = L'\0';
    HeapFree(GetProcessHeap(), 0, w);
}

static void EmitOutput(const char *b, DWORD n, FILE *log)
{
    WCHAR *t = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR));
    if (!t) return;
    CleanChunk(b, n, t, n + 1);
    if (t[0])
    {
        TailAppend(t);
        ReportOutputLine(t);
        if (log) { fputws(t, log); fflush(log); }
    }
    HeapFree(GetProcessHeap(), 0, t);
}

/* Read what the child wrote since *pos; emit whole lines (all of it when final). */
static void DrainOutput(HANDLE hr, DWORD *pos, char *carry, DWORD *ncarry, DWORD ccap, BOOL final, FILE *log)
{
    char buf[4096];
    DWORD got;
    for (;;)
    {
        if (!ReadFile(hr, buf, sizeof(buf), &got, NULL) || !got) break;
        *pos += got;
        if (*ncarry + got > ccap)
        {
            EmitOutput(carry, *ncarry, log);              /* oversized line: flush as is */
            *ncarry = 0;
        }
        if (got > ccap) { EmitOutput(buf, got, log); continue; }
        memcpy(carry + *ncarry, buf, got);
        *ncarry += got;
        {
            DWORD k = *ncarry;
            while (k && carry[k - 1] != '\n') k--;
            if (k)
            {
                EmitOutput(carry, k, log);
                memmove(carry, carry + k, *ncarry - k);
                *ncarry -= k;
            }
        }
    }
    if (final && *ncarry)
    {
        EmitOutput(carry, *ncarry, log);
        *ncarry = 0;
    }
}

/* Is a Windows Installer package running in the child's job (or is the command msiexec itself)?
 * Killing msiexec part-way leaves a half-installed product that nothing rolls back, so cancel lets
 * it finish and the caller removes it again. */
static BOOL MsiInstalling(LPCWSTR cmdline, HANDLE job)
{
    PROCESSENTRY32W pe;
    HANDLE snap;
    BOOL found = FALSE, more;

    if (wcsstr(cmdline, L"msiexec")) return TRUE;
    if (!job) return FALSE;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(pe);
    for (more = Process32FirstW(snap, &pe); more && !found; more = Process32NextW(snap, &pe))
    {
        if (!_wcsicmp(pe.szExeFile, L"msiexec.exe"))
        {
            HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            BOOL in = FALSE;
            if (h)
            {
                if (IsProcessInJob(h, job, &in) && in) found = TRUE;
                CloseHandle(h);
            }
        }
    }
    CloseHandle(snap);
    return found;
}

/* End the child: its whole job (installer, msiexec, script children) when it was put in one,
 * else just the process (exact handle). Waits until it is gone so its files are released. */
static void KillChild(HANDLE job, HANDLE proc)
{
    if (!job || !TerminateJobObject(job, 1))
        TerminateProcess(proc, 1);
    WaitForSingleObject(proc, 15000);
}

/* Run a command line, wait, return its exit code in *code. A run that exceeds the
 * timeout is terminated (exact process handle) and reported as ERROR_TIMEOUT. While the GUI has
 * armed cancel (FmOpBegin) the wait also watches the cancel event: FmOpCancel ends the child at
 * once and the result is HRESULT_FROM_WIN32(ERROR_CANCELLED). */
static HRESULT RunAndWait(LPCWSTR cmdline, DWORD timeoutMs, DWORD *code, FILE *log)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    WCHAR cl[2048], tmpDir[MAX_PATH], tmpFile[MAX_PATH];
    HANDLE hOut = INVALID_HANDLE_VALUE, hIn = INVALID_HANDLE_VALUE, hRd = INVALID_HANDLE_VALUE;
    HANDLE job = NULL, wh[2];
    DWORD nwh;
    char carry[8192];
    DWORD ncarry = 0, pos = 0, w, flags = 0, start = GetTickCount(), elapsed;
    HRESULT hr = S_OK;
    BOOL ok;

    *code = (DWORD)-1;
    g_Tail[0] = L'\0';
    if (FmOpCancelled())
    {
        SetLastMsg(L"The operation was cancelled.");
        return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    }
    if (wcsstr(cmdline, L"msiexec")) InterlockedExchange(&g_MayMsi, 1);
    g_MsiFinished = FALSE;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    StringCchCopyW(cl, ARRAYSIZE(cl), cmdline);   /* CreateProcessW may modify its buffer */
    LOGF(log, L"  run: %s\n", cl);

    sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    tmpFile[0] = L'\0';
    if (GetTempPathW(MAX_PATH, tmpDir)
        && GetTempFileNameW(tmpDir, L"fmr", 0, tmpFile))
    {
        hOut = CreateFileW(tmpFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY, NULL);
        hRd = CreateFileW(tmpFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        hIn = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    }
    if (hOut != INVALID_HANDLE_VALUE && hRd != INVALID_HANDLE_VALUE && hIn != INVALID_HANDLE_VALUE)
    {
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdInput = hIn; si.hStdOutput = hOut; si.hStdError = hOut;
        if (!GetConsoleWindow()) flags |= CREATE_NO_WINDOW;   /* GUI caller: no console pops up */
    }
    /* a cancelable run starts suspended and joins a job first, so cancel reaches the children too */
    if (FmOpCancelHandle() && (job = CreateJobObjectW(NULL, NULL)) != NULL)
        flags |= CREATE_SUSPENDED;
    ok = CreateProcessW(NULL, cl, NULL, NULL, si.dwFlags & STARTF_USESTDHANDLES ? TRUE : FALSE, flags,
                        NULL, NULL, &si, &pi);
    if (!ok)
    {
        DWORD e = GetLastError();
        LOGF(log, L"  ERROR: cannot start command (%lu)\n", e);
        SetLastMsg(L"Cannot start the command (error %lu): %s", e, cl);
        hr = HRESULT_FROM_WIN32(e);
        goto out;
    }
    if (job)
    {
        if (!AssignProcessToJobObject(job, pi.hProcess)) { CloseHandle(job); job = NULL; }
        ResumeThread(pi.hThread);
    }
    CloseHandle(pi.hThread);
    wh[0] = pi.hProcess;
    wh[1] = FmOpCancelHandle();
    nwh = wh[1] ? 2 : 1;
    for (;;)
    {
        elapsed = GetTickCount() - start;
        if (elapsed >= timeoutMs) { w = WAIT_TIMEOUT; break; }
        w = WaitForMultipleObjects(nwh, wh, FALSE, hRd != INVALID_HANDLE_VALUE ? 500 : timeoutMs - elapsed);
        if (hRd != INVALID_HANDLE_VALUE) DrainOutput(hRd, &pos, carry, &ncarry, sizeof(carry), FALSE, log);
        if (w != WAIT_TIMEOUT) break;
    }
    if (nwh == 2 && w == WAIT_OBJECT_0 + 1)
    {
        if (MsiInstalling(cl, job))
        {
            /* A Windows Installer package cannot be rolled back from outside (msiexec runs the install in its own
             * process and has no cancel hook): killing it leaves a half-installed product. Let it finish (bounded);
             * the caller then removes the finished product again. */
            DWORD t0 = GetTickCount();
            LOGF(log, L"  cancelled: a Windows Installer package is installing; letting it finish, then removing it\n");
            FmOpStep(L"Cancelling: letting the Windows Installer package finish, then removing it");
            do
            {
                w = WaitForSingleObject(pi.hProcess, 500);
                if (hRd != INVALID_HANDLE_VALUE) DrainOutput(hRd, &pos, carry, &ncarry, sizeof(carry), FALSE, log);
            } while (w == WAIT_TIMEOUT && GetTickCount() - t0 < 5u * 60u * 1000u);
            if (w == WAIT_TIMEOUT)
            {
                LOGF(log, L"  the installer did not finish in 5 minutes; terminating it\n");
                KillChild(job, pi.hProcess);
            }
            else
                g_MsiFinished = TRUE;
            if (hRd != INVALID_HANDLE_VALUE) DrainOutput(hRd, &pos, carry, &ncarry, sizeof(carry), TRUE, log);
            CloseHandle(pi.hProcess);
            SetLastMsg(g_MsiFinished ? L"The operation was cancelled. The Windows Installer package was allowed to finish and is removed again."
                                     : L"The operation was cancelled; the Windows Installer package did not finish in time and was stopped, so files can remain.");
            hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
            goto out;
        }
        LOGF(log, L"  cancelled; terminating pid %lu%s\n", pi.dwProcessId, job ? L" and its children" : L"");
        KillChild(job, pi.hProcess);
        if (hRd != INVALID_HANDLE_VALUE) DrainOutput(hRd, &pos, carry, &ncarry, sizeof(carry), TRUE, log);
        CloseHandle(pi.hProcess);
        SetLastMsg(L"The running installer or script was stopped at once.%s",
                   g_MayMsi ? L" An installer stopped part-way is not rolled back: files it had already copied can remain; "
                              L"installing again repairs them." : L"");
        hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        goto out;
    }
    if (hRd != INVALID_HANDLE_VALUE) DrainOutput(hRd, &pos, carry, &ncarry, sizeof(carry), TRUE, log);
    if (w == WAIT_TIMEOUT)
    {
        LOGF(log, L"  ERROR: command still running after %lu s; terminating pid %lu\n",
             timeoutMs / 1000, pi.dwProcessId);
        SetLastMsg(L"The command was still running after %lu s and was terminated.\n%s", timeoutMs / 1000, g_Tail);
        KillChild(job, pi.hProcess);
        CloseHandle(pi.hProcess);
        hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        goto out;
    }
    GetExitCodeProcess(pi.hProcess, code);
    CloseHandle(pi.hProcess);
    LOGF(log, L"  exit code: %lu\n", *code);
out:
    if (job) CloseHandle(job);
    if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
    if (hRd != INVALID_HANDLE_VALUE) CloseHandle(hRd);
    if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);
    if (tmpFile[0]) DeleteFileW(tmpFile);
    return hr;
}

/* Build the install + uninstall command lines for a software feature into
 * inst/uninst (cch each). The uninstall line is recorded in the state key at
 * install time so disable stays data-driven (same as the OS tier's undo lists). */
static HRESULT BuildSoftwareCommands(const FM_FEATURE *f, LPWSTR inst, LPWSTR uninst, DWORD cch, FILE *log)
{
    WCHAR ucmd[1024];

    inst[0] = uninst[0] = L'\0';
    if (!_wcsicmp(f->Provider, L"command"))
    {
        WCHAR path[MAX_PATH], args[512], raw[1024];
        if (!InstallerPath(f, path, MAX_PATH))
        {
            LOGF(log, L"error: '%s' has no [Install] Installer\n", f->Id);
            return E_INVALIDARG;
        }
        GetPrivateProfileStringW(L"Install", L"SilentArgs", L"", raw, ARRAYSIZE(raw), f->ManifestPath);
        ExpandCmd(f->Id, raw, args, ARRAYSIZE(args));
        if (IsPs1(path))
        {
            WCHAR pwsh[MAX_PATH];
            if (!FmPwshPath(pwsh, MAX_PATH) || GetFileAttributesW(pwsh) == INVALID_FILE_ATTRIBUTES)
            {
                LOGF(log, L"error: PowerShell 7 (%s) is required to run %s but is not installed\n", pwsh, path);
                SetLastMsg(L"PowerShell 7 is required but is not installed. Install the 'powershell-7' feature first.");
                return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
            }
            SetEnvironmentVariableW(L"POWERSHELL_TELEMETRY_OPTOUT", L"1");
            SetEnvironmentVariableW(L"POWERSHELL_UPDATECHECK", L"Off");
            StringCchPrintfW(inst, cch, L"\"%s\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%s\" %s",
                             pwsh, path, args);
        }
        else if (IsScript(path))
            StringCchPrintfW(inst, cch, L"cmd.exe /c \"\"%s\" %s\"", path, args);
        else
            StringCchPrintfW(inst, cch, L"\"%s\" %s", path, args);
        GetPrivateProfileStringW(L"Install", L"UninstallCmd", L"", raw, ARRAYSIZE(raw), f->ManifestPath);
        if (raw[0])
        {
            ExpandCmd(f->Id, raw, args, ARRAYSIZE(args));
            StringCchCopyW(uninst, cch, args);
        }
        else
        {
            /* [Install] UninstallScript= : a PowerShell 7 script run like an .ps1 Installer */
            GetPrivateProfileStringW(L"Install", L"UninstallScript", L"", raw, ARRAYSIZE(raw), f->ManifestPath);
            if (raw[0])
            {
                WCHAR pwsh[MAX_PATH];
                ExpandCmd(f->Id, raw, args, ARRAYSIZE(args));
                if (FmPwshPath(pwsh, MAX_PATH))
                    StringCchPrintfW(uninst, cch,
                        L"\"%s\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%s\"", pwsh, args);
            }
        }
        return S_OK;
    }

    if (!_wcsicmp(f->Provider, L"scoop"))
    {
        const WCHAR *app = f->App, *bucket = f->Bucket;
        {
            WCHAR pw[MAX_PATH], runner[MAX_PATH];
            if (!GetEnvironmentVariableW(L"FEATMGR_SCOOP_RUNNER", runner, MAX_PATH)
                && (!FmPwshPath(pw, MAX_PATH) || GetFileAttributesW(pw) == INVALID_FILE_ATTRIBUTES))
            {
                LOGF(log, L"error: PowerShell 7 is required to run Scoop but is not installed\n");
                SetLastMsg(L"PowerShell 7 is required to run Scoop but is not installed. Install the 'powershell-7' feature first.");
                return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
            }
        }
        if (!FmScoopCommand(L"install", bucket, app, inst, cch)
            || !FmScoopCommand(L"uninstall", bucket, app, uninst, cch))
        {
            LOGF(log, L"error: '%s' has no valid [Scoop] App/Bucket\n", f->Id);
            SetLastMsg(L"'%s' has an invalid Scoop app or bucket name.", f->Id);
            return E_INVALIDARG;
        }
        return S_OK;
    }

    if (!_wcsicmp(f->Provider, L"component"))
    {
        /* the install line needs the downloaded file: SoftwareInstall builds it after FmCompDownload; the
         * uninstall line comes from the component list */
        FM_COMPONENT c;
        if (!FmCompLoad(f->Id, &c))
        {
            LOGF(log, L"error: '%s' is not in the component list\n", f->Id);
            SetLastMsg(L"'%s' is not in the component list (components.ini).", f->Id);
            return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        }
        StringCchCopyW(inst, cch, L"(component)");
        if (c.Uninstall[0]) ExpandCmd(f->Id, c.Uninstall, uninst, cch);
        return S_OK;
    }
    if (!FmNativeIsProvider(f->Provider))
    {
        LOGF(log, L"error: '%s' has unknown install provider '%s'\n", f->Id, f->Provider);
        return E_INVALIDARG;
    }
    /* native provider: the install line needs the downloaded file (SoftwareInstallRun builds it after the download);
     * the uninstall line is the entry's own UninstallCmd, else a featmgr child that finds the program's Uninstall key. */
    StringCchCopyW(inst, cch, L"(native)");
#ifdef _WIN64
    GetPrivateProfileStringW(L"Rapps", L"UninstallCmd.amd64", L"", ucmd, ARRAYSIZE(ucmd), f->ManifestPath);
#else
    GetPrivateProfileStringW(L"Rapps", L"UninstallCmd.x86", L"", ucmd, ARRAYSIZE(ucmd), f->ManifestPath);
#endif
    if (!ucmd[0])
        GetPrivateProfileStringW(L"Rapps", L"UninstallCmd", L"", ucmd, ARRAYSIZE(ucmd), f->ManifestPath);
    if (ucmd[0])
    {
        ExpandCmd(f->Id, ucmd, uninst, cch);
        return S_OK;
    }
    if (!FmNativeUninstallLine(f, uninst, cch))
    {
        LOGF(log, L"error: '%s' has an unusable name for the uninstall record\n", f->Id);
        return E_INVALIDARG;
    }
    return S_OK;
}

/* Free space the system volume needs before a native install is attempted, as a multiple of the
 * package size ([Source] SizeBytes): the download (1x) plus the Windows Installer cached copy (1x)
 * plus the unpacked files and rollback data. Measured with PowerShell 7 (105 MB MSI): an 8 GB volume
 * with ~0.5 GB free fails inside msiexec, ~1.4 GB free installs and uses ~0.5 GB. The msiexec
 * failure itself is only a bare "exit code 1", so refuse early with a clear message instead. */
#define SW_DISK_FACTOR 6

/* S_OK: enough space (or the size is unknown); ERROR_DISK_FULL: not enough. */
static HRESULT CheckSoftwareDiskSpace(const FM_FEATURE *f, FILE *log, BOOL failedAlready)
{
    WCHAR sz[40], sys[MAX_PATH], root[4];
    ULARGE_INTEGER avail, total, freeAll;
    ULONGLONG pkg, need;
    PWSTR end;

    if (!_wcsicmp(f->Provider, L"component"))
    {
        FM_COMPONENT c;
        pkg = FmCompLoad(f->Id, &c) ? c.Size : 0;
        if (!pkg) return S_OK;
    }
    else
    {
        GetPrivateProfileStringW(L"Source", L"SizeBytes", L"", sz, ARRAYSIZE(sz), f->ManifestPath);
        if (!sz[0]) return S_OK;
        pkg = _wcstoui64(sz, &end, 10);
        if (!pkg || *end) return S_OK;
    }
    if (pkg > ((ULONGLONG)-1) / SW_DISK_FACTOR) need = (ULONGLONG)-1;
    else need = pkg * SW_DISK_FACTOR;
    if (!GetSystemDirectoryW(sys, MAX_PATH) || sys[1] != L':') return S_OK;
    root[0] = sys[0]; root[1] = L':'; root[2] = L'\\'; root[3] = L'\0';
    if (!GetDiskFreeSpaceExW(root, &avail, &total, &freeAll)) return S_OK;
    if (avail.QuadPart >= need) return S_OK;
    LOGF(log, L"error: not enough disk space on %.2s for '%s': %I64u MB free, about %I64u MB needed%s\n",
         root, f->Id, avail.QuadPart >> 20, need >> 20,
         failedAlready ? L" (the installer probably ran out of space)" : L"");
    SetLastMsg(L"Not enough disk space on %.2s to install '%s': %I64u MB free, about %I64u MB needed "
               L"(download, installer cache and installed files). Free up space on the system volume and try again. "
               L"On a small test volume, a large page file (system-managed size = RAM size) can use most of it.",
               root, f->Id, avail.QuadPart >> 20, need >> 20);
    return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
}

/* Name the step for the status line: what is downloaded (the manifest's [Source] Artifact and
 * SizeBytes, when it has them) and what runs. */
static void ReportInstallStep(const FM_FEATURE *f, LPCWSTR inst)
{
    WCHAR url[300];

    FmOpPhase(FM_PHASE_APPLY);
    if (!_wcsicmp(f->Provider, L"component"))
    {
        FmOpStep(L"Installing %s", f->Name);
        return;
    }
    GetPrivateProfileStringW(L"Source", L"Artifact", L"", url, ARRAYSIZE(url), f->ManifestPath);
    if (FmNativeIsProvider(f->Provider))
    {
        InterlockedExchange(&g_MayMsi, 1);            /* the downloaded (or local) installer is usually an MSI */
        FmOpStep(L"Installing %s", f->Name);
    }
    else if (wcsstr(inst, L"msiexec"))
        FmOpStep(L"Running the installer package for %s (no download needed)", f->Name);
    else if (!_wcsicmp(f->Provider, L"scoop"))
        FmOpStep(L"Installing %s with Scoop", f->Name);
    else if (url[0])
        FmOpStep(L"Installing %s (downloads %s)", f->Name, url);
    else
        FmOpStep(L"Running the installer for %s", f->Name);
}

/* The Scoop root holds nothing yet (missing or empty): a cancelled install can then be removed
 * completely, without touching a Scoop the user already had. */
static BOOL ScoopRootIsFresh(void)
{
    WCHAR root[MAX_PATH], pat[MAX_PATH + 4];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    BOOL fresh = TRUE;

    if (!FmScoopRoot(root, MAX_PATH)) return FALSE;
    if (GetFileAttributesW(root) == INVALID_FILE_ATTRIBUTES) return TRUE;
    if (FAILED(StringCchPrintfW(pat, ARRAYSIZE(pat), L"%s\\*", root))) return FALSE;
    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return TRUE;
    do
    {
        if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) { fresh = FALSE; break; }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return fresh;
}

/* the components whose install or removal changes the desktop / Start menu / default browser (shelldefaults.c) */
static BOOL ShellDefaultsId(LPCWSTR id)
{
    return !_wcsicmp(id, L"powershell-7") || !_wcsicmp(id, L"firefox");
}

/* Download + install (the caller holds the install lock). Returns S_OK only if the installer exited 0;
 * on success the uninstall command line is recorded in the state key. */
static HRESULT SoftwareInstallPiece(const FM_FEATURE *f, HKEY state, FILE *log, WCHAR *uninstOut)
{
    WCHAR inst[2048], uninst[2048], compFile[MAX_PATH];
    DWORD code;
    HRESULT hr;
    BOOL scoopFresh;
    BOOL nat = FmNativeIsProvider(f->Provider);
    BOOL comp = !_wcsicmp(f->Provider, L"component") || nat;
    BOOL keepFile = FALSE;                 /* the file is the image's own payload: never deleted */
    WCHAR *pathBefore = NULL;
    FM_COMPONENT c;                        /* the component list entry (comp, not nat): its detect rule is checked after the install */
    BOOL missing = FALSE;                  /* the installer said success but the detect rule does not hold */
    BOOL restart = FALSE;                  /* the installer asked for a restart (3010 / 1641) */

    compFile[0] = L'\0';
    ZeroMemory(&c, sizeof(c));
    FmOpPhase(FM_PHASE_SEARCH);
    hr = BuildSoftwareCommands(f, inst, uninst, ARRAYSIZE(inst), log);
    if (FAILED(hr)) return hr;
    if (comp)
    {
        /* the component list's own download: progress, SHA-256, cancel; the partial file never stays behind */
        hr = CheckSoftwareDiskSpace(f, log, FALSE);
        if (FAILED(hr)) return hr;
        if (nat ? !FmNativePlan(f, &c) : !FmCompLoad(f->Id, &c)) return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        hr = FmCompDownload(&c, compFile, ARRAYSIZE(compFile), log);
        if (FAILED(hr))
        {
            WCHAR why[1024];
            FmGetLastMessage(why, ARRAYSIZE(why));
            LOGF(log, L"error: %s\n", why);      /* the CLI shows the log; the window shows the last message */
            return hr;
        }
        keepFile = nat && c.LocalFile[0] && !_wcsicmp(compFile, c.LocalFile);
        if (nat)
        {
            hr = FmNativeInstallLine(f, compFile, inst, ARRAYSIZE(inst));
            if (FAILED(hr))
            {
                LOGF(log, L"error: cannot build the installer command line for '%s'\n", f->Id);
                SetLastMsg(L"The catalog entry of '%s' gives an installer command line that cannot be used.", f->Id);
                return hr;
            }
        }
        else
            FmCompInstallLine(&c, compFile, inst, ARRAYSIZE(inst));
    }
    LOGF(log, L"  software install via '%s' provider\n", f->Provider);
    if (!_wcsicmp(f->Provider, L"scoop"))
        FmScoopPrepareEnv();
    ReportInstallStep(f, inst);
    scoopFresh = !_wcsicmp(f->Id, L"scoop") && ScoopRootIsFresh();
    pathBefore = HeapAlloc(GetProcessHeap(), 0, PATHSNAP_CCH * sizeof(WCHAR));
    if (pathBefore) ReadRegistryPaths(pathBefore, PATHSNAP_CCH);
    hr = RunAndWait(inst, SW_RUN_TIMEOUT_MS, &code, log);
    if (SUCCEEDED(hr) && code == ERROR_INSTALL_ALREADY_RUNNING && wcsstr(inst, L"msiexec"))
    {
        /* another Windows Installer install (not featmgr's own: those are serialized by the install lock) holds
         * the installer's single-install lock and msiexec exits 1618: retry a bounded number of times */
        int tries;
        for (tries = 0; tries < MSI_BUSY_RETRIES && SUCCEEDED(hr) && code == ERROR_INSTALL_ALREADY_RUNNING; tries++)
        {
            DWORD w;
            LOGF(log, L"  another Windows Installer install is running (1618), retry %d of %d in %lu s\n",
                 tries + 1, MSI_BUSY_RETRIES, MSI_BUSY_WAIT_MS / 1000);
            FmOpStep(L"Another Windows Installer install is running, waiting to install %s (retry %d of %d)", f->Name, tries + 1, MSI_BUSY_RETRIES);
            if (FmOpCancelHandle()) w = WaitForSingleObject(FmOpCancelHandle(), MSI_BUSY_WAIT_MS);
            else { Sleep(MSI_BUSY_WAIT_MS); w = WAIT_TIMEOUT; }
            if (w != WAIT_TIMEOUT) { hr = HRESULT_FROM_WIN32(ERROR_CANCELLED); SetLastMsg(L"The operation was cancelled."); break; }
            ReportInstallStep(f, inst);
            hr = RunAndWait(inst, SW_RUN_TIMEOUT_MS, &code, log);
        }
    }
    if (comp)
    {
        restart = SUCCEEDED(hr) && (code == 3010 || code == 1641);
        /* An exit code of 0 is not proof: an installer can report success and install nothing (a Windows Installer
         * custom action that could not start, say). "Installed" means the component's detect rule holds, so a
         * rule that does not hold after a success is a failure. Not checked after a restart request (3010 / 1641:
         * the files can be put in place at the restart) and not for the native providers (no rule of their own). */
        if (!nat && SUCCEEDED(hr) && code == 0 && (c.DetectReg[0] || c.DetectFile[0]) && !FmCompDetectOne(&c))
            missing = TRUE;
        /* success and cancel leave no copy of the download behind; a failed installer keeps the verified file for the retry */
        if (!keepFile && !missing && (SUCCEEDED(hr) ? (code == 0 || code == 3010 || code == 1641) : hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)))
            DeleteFileW(compFile);
        if (restart)
        {
            LOGF(log, L"  installer finished, a restart is needed (exit code %lu)\n", code);
            InterlockedExchange(&g_RebootNeeded, 1);
            code = 0;
        }
    }
    if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED) && scoopFresh && uninst[0])
    {
        /* a half-written C:\scoop would make the next install refuse ("exists and is not empty"):
         * remove it with the feature's own uninstall script, which must run to the end */
        DWORD ucode;
        WCHAR why[256];
        LOGF(log, L"  cancelled: removing the partial Scoop install\n");
        FmOpStep(L"Cancelled: removing the partly installed Scoop");
        StringCchCopyW(why, ARRAYSIZE(why), g_LastMsg);
        g_NoCancel = TRUE;
        RunAndWait(uninst, 10u * 60u * 1000u, &ucode, log);
        g_NoCancel = FALSE;
        SetLastMsg(L"%s", why);
    }
    if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED) && g_MsiFinished && uninst[0])
    {
        /* the package ran to its end under cancel: take the finished product out again */
        DWORD ucode;
        WCHAR why[256];
        LOGF(log, L"  cancelled: removing the package that finished\n");
        FmOpStep(L"Cancelled: removing the Windows Installer package again");
        StringCchCopyW(why, ARRAYSIZE(why), g_LastMsg);
        g_NoCancel = TRUE;
        RunAndWait(uninst, 10u * 60u * 1000u, &ucode, log);
        g_NoCancel = FALSE;
        SetLastMsg(L"%s", why);
    }
    if (FAILED(hr)) { if (pathBefore) HeapFree(GetProcessHeap(), 0, pathBefore); return hr; }
    if (missing)
    {
        if (pathBefore) HeapFree(GetProcessHeap(), 0, pathBefore);
        LOGF(log, L"error: installer for '%s' reported success (exit code 0) but it is not installed: %s %s not found\n",
             f->Id, c.DetectFile[0] ? L"file" : L"registry value", c.DetectFile[0] ? c.DetectFile : c.DetectReg);
        SetLastMsg(L"The installer for '%s' finished without an error but did not install it (%s not found).%s%s",
                   f->Id, c.DetectFile[0] ? c.DetectFile : c.DetectReg, g_Tail[0] ? L"\n\n" : L"", g_Tail);
        return HRESULT_FROM_WIN32(ERROR_INSTALL_FAILURE);
    }
    if (code != 0)
    {
        if (pathBefore) HeapFree(GetProcessHeap(), 0, pathBefore);
        LOGF(log, L"error: installer for '%s' failed (exit code %lu)\n", f->Id, code);
        if (comp && FAILED(CheckSoftwareDiskSpace(f, log, TRUE)))
            return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
        SetLastMsg(L"The %s installer for '%s' failed (exit code %lu).\n\n%s",
                   f->Provider, f->Id, code, g_Tail);
        if (scoopFresh && uninst[0])
        {
            /* Scoop's root was empty before this run, so whatever it holds is the failed run's: remove it, or
             * "Try again" meets a half-written C:\scoop (core without shim) and cannot recover */
            DWORD ucode;
            WCHAR why[ARRAYSIZE(g_LastMsg)];
            LOGF(log, L"  failed: removing the partial Scoop install so that a retry starts clean\n");
            FmOpStep(L"Removing the partly installed Scoop");
            StringCchCopyW(why, ARRAYSIZE(why), g_LastMsg);
            g_NoCancel = TRUE;
            RunAndWait(uninst, 10u * 60u * 1000u, &ucode, log);
            g_NoCancel = FALSE;
            SetLastMsg(L"%s", why);
        }
        return HRESULT_FROM_WIN32(ERROR_INSTALL_FAILURE);
    }
    if (!_wcsicmp(f->Provider, L"scoop"))
        FmScoopAppDefaults(f->App, log);        /* NitroOS default for VS Code (scoopdefaults.c) */
    else if (!_wcsicmp(f->Id, L"scoop"))
        FmScoopAppDefaultsSeed(log);            /* ...ready before a later plain "scoop install" */
    if (uninstOut)
        StringCchCopyW(uninstOut, 2048, uninst);          /* a piece of a multi-package component: the caller records the lines */
    else
    {
        SetStateSz(state, L"Provider", f->Provider);
        SetStateSz(state, L"Uninstall", uninst);
    }
    NotifyEnvironmentChanged();
    if (pathBefore)
    {
        NotePathChange(f, pathBefore);
        HeapFree(GetProcessHeap(), 0, pathBefore);
    }
    FmNativeInvalidate();
    if (comp && ShellDefaultsId(f->Id))   /* PowerShell 7 / Firefox: desktop, Start menu, default browser (shelldefaults.c) */
        FmShellDefaults(!_wcsicmp(f->Id, L"firefox") ? FM_SHELL_ADOPT_BROWSER : 0, log);
    return S_OK;
}

static void AppendCleanupLine(const FM_FEATURE *f, LPWSTR uninst, DWORD cch);

/* One catalog entry, several packages (Wine Gecko: the 32-bit package, then the 64-bit one on a 64-bit system; the list's
 * Also= names the next section). Each package is downloaded, verified and installed as a component of its own; one that
 * is already there (its own detect rule holds: installed by appwiz's prompt, say) is skipped. When a later package fails,
 * the earlier ones this run installed are taken out again, so a failed install leaves nothing half-done. The uninstall
 * lines of all packages are recorded together, one per line. A plain component goes straight to the single-package path. */
static HRESULT SoftwareInstallRun(const FM_FEATURE *f, HKEY state, FILE *log)
{
    FM_COMPONENT c, piece, nxt;
    FM_FEATURE *pf;
    WCHAR (*unin)[2048];
    BOOL ran[4];
    WCHAR all[4096];
    int n = 0, i;
    HRESULT hr = S_OK;

    if (_wcsicmp(f->Provider, L"component") || !FmCompLoad(f->Id, &c) || !FmCompNext(&c, &nxt))
        return SoftwareInstallPiece(f, state, log, NULL);

    pf = (FM_FEATURE *)HeapAlloc(GetProcessHeap(), 0, sizeof(*pf));
    unin = (WCHAR (*)[2048])HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4 * sizeof(*unin));
    if (!pf || !unin)
    {
        if (pf) HeapFree(GetProcessHeap(), 0, pf);
        if (unin) HeapFree(GetProcessHeap(), 0, unin);
        return E_OUTOFMEMORY;
    }
    piece = c;
    for (;;)
    {
        *pf = *f;
        StringCchCopyW(pf->Id, ARRAYSIZE(pf->Id), piece.Id);
        StringCchCopyW(pf->Name, ARRAYSIZE(pf->Name), piece.Name);
        ran[n] = FALSE;
        if (FmCompDetectOne(&piece))
        {
            LOGF(log, L"  '%s' is already installed, skipping its package\n", piece.Id);
            ExpandCmd(piece.Id, piece.Uninstall, unin[n], 2048);
        }
        else
        {
            hr = SoftwareInstallPiece(pf, state, log, unin[n]);
            ran[n] = SUCCEEDED(hr);
        }
        if (FAILED(hr)) break;
        n++;
        if (n >= 4 || !FmCompNext(&piece, &nxt)) break;
        piece = nxt;
    }
    if (FAILED(hr))
    {
        WCHAR why[ARRAYSIZE(g_LastMsg)];
        BOOL nc = g_NoCancel;
        StringCchCopyW(why, ARRAYSIZE(why), g_LastMsg);
        for (i = n - 1; i >= 0; i--)
        {
            DWORD ucode;
            if (!ran[i] || !unin[i][0]) continue;
            LOGF(log, L"  a later package failed: removing the package installed before it again\n");
            g_NoCancel = TRUE;
            RunAndWait(unin[i], 10u * 60u * 1000u, &ucode, log);
            g_NoCancel = nc;
        }
        SetLastMsg(L"%s", why);
    }
    else
    {
        all[0] = L'\0';
        for (i = 0; i < n; i++)
        {
            if (!unin[i][0]) continue;
            if (all[0]) StringCchCatW(all, ARRAYSIZE(all), L"\n");
            StringCchCatW(all, ARRAYSIZE(all), unin[i]);
        }
        AppendCleanupLine(f, all, ARRAYSIZE(all));
        SetStateSz(state, L"Provider", f->Provider);
        SetStateSz(state, L"Uninstall", all);
    }
    HeapFree(GetProcessHeap(), 0, pf);
    HeapFree(GetProcessHeap(), 0, unin);
    return hr;
}

/* A multi-package component may name a Cleanup= command (the first section's): it is the last uninstall line, marked with a
 * leading '?' (run only when every line before it succeeded). Wine Gecko: the 32-bit and the 64-bit MSI register one
 * component, so removing both products leaves the files of one of them; the cleanup removes the engine's folders. */
static void AppendCleanupLine(const FM_FEATURE *f, LPWSTR uninst, DWORD cch)
{
    FM_COMPONENT c, nxt;
    size_t len = wcslen(uninst);
    if (_wcsicmp(f->Provider, L"component") || !FmCompLoad(f->Id, &c) || !c.Cleanup[0] || !FmCompNext(&c, &nxt)) return;
    if (len + 3 >= cch) return;
    if (len) uninst[len++] = L'\n';
    uninst[len++] = L'?';
    uninst[len] = L'\0';
    ExpandCmd(f->Id, c.Cleanup, uninst + len, (DWORD)(cch - len));
}

/* The uninstall lines of every package of a multi-package component (Also=), one per text line, for an install that
 * featmgr did not record (appwiz's Gecko prompt). Appends to uninst, which already holds the first package's line. */
static void AppendChainUninstall(const FM_FEATURE *f, LPWSTR uninst, DWORD cch)
{
    FM_COMPONENT piece, nxt;
    int n;
    if (_wcsicmp(f->Provider, L"component") || !FmCompLoad(f->Id, &piece)) return;
    for (n = 1; n < 4 && FmCompNext(&piece, &nxt); n++)
    {
        size_t len = wcslen(uninst);
        if (nxt.Uninstall[0] && len + 2 < cch)
        {
            if (len) uninst[len++] = L'\n';
            ExpandCmd(f->Id, nxt.Uninstall, uninst + len, (DWORD)(cch - len));
        }
        piece = nxt;
    }
    AppendCleanupLine(f, uninst, cch);
}

/* Run a (possibly multi-line) uninstall: one command per line, all of them run; a Windows Installer product that is
 * not there any more (msiexec /x answers 1605) counts as removed. Returns the first failure's HRESULT. */
static HRESULT RunUninstallLines(const FM_FEATURE *f, WCHAR *cmd, FILE *log)
{
    HRESULT first = S_OK;
    WCHAR *line = cmd, *nl;
    DWORD code;

    while (line && *line)
    {
        HRESULT hr;
        nl = wcschr(line, L'\n');
        if (nl) *nl = L'\0';
        if (*line == L'?')
        {
            /* the cleanup line: only after every line before it worked */
            line++;
            if (FAILED(first)) { LOGF(log, L"  skipping the cleanup: an uninstall line failed\n"); *line = L'\0'; }
        }
        if (*line)
        {
            hr = RunAndWait(line, SW_RUN_TIMEOUT_MS, &code, log);
            if (FAILED(hr))
            {
                if (SUCCEEDED(first)) first = hr;
                if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) return hr;
            }
            else if (code == ERROR_UNKNOWN_PRODUCT && wcsstr(line, L"msiexec"))
                LOGF(log, L"  note: the package is not installed any more (1605), nothing to remove\n");
            else if (code != 0)
            {
                LOGF(log, L"error: uninstaller failed (exit code %lu)\n", code);
                SetLastMsg(L"The uninstaller for '%s' failed (exit code %lu).\n\n%s", f ? f->Id : L"?", code, g_Tail);
                if (SUCCEEDED(first)) first = HRESULT_FROM_WIN32(ERROR_INSTALL_FAILURE);
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    return first;
}

/* Run the uninstall command recorded at install time. S_OK if there is none (the caller holds the install lock). */
static HRESULT SoftwareUninstallRun(const FM_FEATURE *f, HKEY state, FILE *log)
{
    WCHAR cmd[2048];
    DWORD cb = sizeof(cmd) - sizeof(WCHAR), type = 0, code;
    HRESULT hr;

    cmd[0] = L'\0';
    if (RegQueryValueExW(state, L"Uninstall", NULL, &type, (LPBYTE)cmd, &cb) != ERROR_SUCCESS
        || type != REG_SZ || !cmd[0])
    {
        cmd[0] = L'\0';
        /* installed outside featmgr (scoop CLI; setup for an image-bundled rapps entry): no recorded line,
         * derive it from the manifest */
        if (f && (!_wcsicmp(f->Provider, L"scoop") || FmNativeIsProvider(f->Provider) || !_wcsicmp(f->Provider, L"component")))
        {
            WCHAR inst[2048];
            hr = BuildSoftwareCommands(f, inst, cmd, ARRAYSIZE(cmd), log);
            if (FAILED(hr)) return hr;
            AppendChainUninstall(f, cmd, ARRAYSIZE(cmd));
        }
        if (!cmd[0])
        {
            LOGF(log, L"  note: no uninstall command recorded; nothing to run\n");
            return S_OK;
        }
    }
    cmd[ARRAYSIZE(cmd) - 1] = L'\0';
    if (f && !_wcsicmp(f->Provider, L"scoop"))
        FmScoopPrepareEnv();
    FmOpPhase(FM_PHASE_APPLY);
    FmOpStep(L"Running the uninstaller for %s", f ? f->Name : L"the feature");
    if (wcschr(cmd, L'\n'))
    {
        /* several packages (Wine Gecko 32-bit + 64-bit) */
        hr = RunUninstallLines(f, cmd, log);
        NotifyEnvironmentChanged();
        if (FAILED(hr)) return hr;
        FmNativeInvalidate();
        return S_OK;
    }
    hr = RunAndWait(cmd, SW_RUN_TIMEOUT_MS, &code, log);
    if (FAILED(hr)) return hr;
    NotifyEnvironmentChanged();
    if (code != 0)
    {
        LOGF(log, L"error: uninstaller failed (exit code %lu)\n", code);
        SetLastMsg(L"The uninstaller for '%s' failed (exit code %lu).\n\n%s", f ? f->Id : L"?", code, g_Tail);
        return HRESULT_FROM_WIN32(ERROR_INSTALL_FAILURE);
    }
    FmNativeInvalidate();
    if (f && (!_wcsicmp(f->Provider, L"component") || FmNativeIsProvider(f->Provider)) && ShellDefaultsId(f->Id))   /* back to Command Prompt / the image's browser defaults when pwsh / Firefox is gone */
        FmShellDefaults(!_wcsicmp(f->Id, L"firefox") ? FM_SHELL_FORGET_BROWSER : 0, log);
    return S_OK;
}

/* ---- cross-process install lock ---------------------------------------------
 * Two featmgr processes (first boot's optfeatures.exe /firstboot window plus a featmgr /install, or two CLI
 * calls) must not run component installers at the same time: a second .NET setup exits 5100 while the first
 * runs. One named mutex in the Global namespace serializes SoftwareInstall/SoftwareUninstall. Its DACL gives
 * full access to SYSTEM and Administrators (installs need admin anyway), so a service, a CLI session and the
 * logon session all open the same object. If the object cannot be created or opened (a foreign DACL), the
 * operation runs unserialized as before rather than failing. */
#define FM_INSTALL_MUTEX   L"Global\\NitroFeatmgrInstall"

static HANDLE OpenInstallMutex(void)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE h;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
                                                              &sa.lpSecurityDescriptor, NULL))
        sa.lpSecurityDescriptor = NULL;
    h = CreateMutexW(sa.lpSecurityDescriptor ? &sa : NULL, FALSE, FM_INSTALL_MUTEX);
    if (sa.lpSecurityDescriptor) LocalFree(sa.lpSecurityDescriptor);
    return h;
}

/* S_OK: lock held (*phMutex set, or NULL when running unserialized); ERROR_CANCELLED when cancelled while waiting.
 * No timeout: an install can take many minutes. WAIT_ABANDONED (the holder died) counts as acquired. */
static HRESULT AcquireInstallLock(LPCWSTR what, HANDLE *phMutex, FILE *log)
{
    HANDLE h, wh[2];
    DWORD r, nwh = 1, start = 0, last = 0;

    *phMutex = NULL;
    h = OpenInstallMutex();
    if (!h)
    {
        LOGF(log, L"  note: cannot open the install lock (%lu); running without it\n", GetLastError());
        return S_OK;
    }
    r = WaitForSingleObject(h, 0);
    if (r == WAIT_TIMEOUT)
    {
        LOGF(log, L"  another install or uninstall is running; waiting for it to finish before %s\n", what);
        start = GetTickCount();
        for (;;)
        {
            DWORD el = (GetTickCount() - start) / 1000;
            if (!last || el >= last + 5)
            {
                last = el ? el : 1;
                FmOpStep(L"Waiting for another install or uninstall to finish (%lu:%02lu), then %s", el / 60, el % 60, what);
            }
            wh[0] = h; nwh = 1;
            if (FmOpCancelHandle()) wh[nwh++] = FmOpCancelHandle();
            r = WaitForMultipleObjects(nwh, wh, FALSE, 1000);
            if (r == WAIT_TIMEOUT) continue;
            break;
        }
        if (nwh == 2 && r == WAIT_OBJECT_0 + 1)
        {
            CloseHandle(h);
            SetLastMsg(L"The operation was cancelled while waiting for another install to finish.");
            return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        }
        LOGF(log, L"  waited %lu s for the other install\n", (GetTickCount() - start) / 1000);
    }
    if (r == WAIT_ABANDONED)
        LOGF(log, L"  note: the previous holder of the install lock ended without releasing it; continuing\n");
    else if (r != WAIT_OBJECT_0)
    {
        LOGF(log, L"  note: waiting for the install lock failed (%lu); running without it\n", GetLastError());
        CloseHandle(h);
        return S_OK;
    }
    *phMutex = h;
    return S_OK;
}

static void ReleaseInstallLock(HANDLE h)
{
    if (!h) return;
    ReleaseMutex(h);
    CloseHandle(h);
}

/* 1 installed, 0 not installed, -1 no detect rule: the component list's rule, or [Install] DetectPath / the scoop app link */
static int DetectInstalledNow(const FM_FEATURE *f)
{
    WCHAR p[MAX_PATH];
    if (!f) return -1;
    if (f->Tier == FM_TIER_SOFTWARE && !_wcsicmp(f->Provider, L"component"))
    {
        FM_COMPONENT c;
        if (!FmCompLoad(f->Id, &c) || (!c.DetectReg[0] && !c.DetectFile[0])) return -1;
        return FmCompDetect(&c) ? 1 : 0;
    }
    if (f->Tier != FM_TIER_SOFTWARE) return -1;
    if (!DetectPathFor(f, p, MAX_PATH))
    {
        if (_wcsicmp(f->Provider, L"native") || !(f->RegName[0] || f->Name[0])) return -1;
        FmNativeInvalidate();
        return FmNativeIsInstalled(f->RegName, f->Name) ? 1 : 0;
    }
    return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES ? 1 : 0;
}

static HRESULT SoftwareInstall(const FM_FEATURE *f, HKEY state, FILE *log)
{
    HANDLE lock;
    HRESULT hr = AcquireInstallLock(L"installing", &lock, log);

    if (FAILED(hr)) return hr;
    if (lock && DetectInstalledNow(f) == 1)
    {
        /* whoever held the lock put it there: do not run the installer again */
        LOGF(log, L"  '%s' is already installed (by the install that just finished)\n", f->Id);
        FmOpStep(L"%s is already installed", f->Name);
        ReleaseInstallLock(lock);
        return S_OK;
    }
    hr = SoftwareInstallRun(f, state, log);
    ReleaseInstallLock(lock);
    return hr;
}

static HRESULT SoftwareUninstall(const FM_FEATURE *f, HKEY state, FILE *log)
{
    HANDLE lock;
    HRESULT hr = AcquireInstallLock(L"uninstalling", &lock, log);

    if (FAILED(hr)) return hr;
    if (lock && DetectInstalledNow(f) == 0)
    {
        LOGF(log, L"  '%s' is already removed (by the uninstall that just finished)\n", f->Id);
        ReleaseInstallLock(lock);
        return S_OK;
    }
    hr = SoftwareUninstallRun(f, state, log);
    ReleaseInstallLock(lock);
    return hr;
}

/* ---- enable / disable ---------------------------------------------------- */

static HRESULT EnableDeps(const FM_FEATURE *f, FILE *log)
{
    WCHAR deps[FM_MAX_DEPS];
    WCHAR *ctx = NULL, *d;
    HRESULT hr = S_OK;
    if (!f->Dependencies[0]) return S_OK;
    StringCchCopyW(deps, FM_MAX_DEPS, f->Dependencies);
    for (d = wcstok_s(deps, L",; ", &ctx); d; d = wcstok_s(NULL, L",; ", &ctx))
    {
        if (!d[0]) continue;
        if (FmGetState(d) == FM_STATE_ENABLED) continue;
        LOGF(log, L"dependency: enabling %s\n", d);
        hr = FmEnable(d, log);
        if (FAILED(hr)) return hr;
    }
    return S_OK;
}

static void RevertState(HKEY state, FILE *log);

/* Apply the manifest's [Registry] actions, recording undo info in the state key. */
static HRESULT ApplyRegistrySection(const FM_FEATURE *f, HKEY state, FILE *log)
{
    WCHAR *sect, *p;
    HRESULT hr = S_OK;

    sect = ReadSection(f->ManifestPath, L"Registry");
    if (!sect) return S_OK;
    for (p = sect; *p; p += wcslen(p) + 1)
    {
        WCHAR *eq = wcschr(p, L'=');
        if (!eq) continue;
        hr = ApplyRegAction(eq + 1, state, log);
        if (FAILED(hr)) break;
    }
    HeapFree(GetProcessHeap(), 0, sect);
    return hr;
}

static HRESULT FmEnableInner(LPCWSTR id, FILE *log);

/* Scoop (and anything that sets [Install] RequireNtfs=<path>) needs an NTFS volume: it builds
 * its "current" version links with junctions, which FAT cannot hold. Refuse up front, before
 * any dependency is downloaded. */
static HRESULT CheckFsRequirement(const FM_FEATURE *f, FILE *log)
{
    WCHAR raw[MAX_PATH], path[MAX_PATH], fs[32];

    path[0] = L'\0';
    GetPrivateProfileStringW(L"Install", L"RequireNtfs", L"", raw, MAX_PATH, f->ManifestPath);
    if (raw[0])
        ExpandCmd(f->Id, raw, path, MAX_PATH);
    else if (!_wcsicmp(f->Provider, L"scoop"))
        FmScoopRoot(path, MAX_PATH);
    if (!path[0] || FmVolumeIsNtfs(path, fs, ARRAYSIZE(fs))) return S_OK;
    LOGF(log, L"error: '%s' needs an NTFS volume but %.2s is %s\n", f->Id, path, fs[0] ? fs : L"not NTFS");
    SetLastMsg(L"'%s' needs an NTFS volume (it relies on junctions) but drive %.2s is %s. "
               L"Nothing was installed. Convert the volume to NTFS first (convert %.2s /fs:ntfs) or "
               L"install on an NTFS disk.", f->Name, path, fs[0] ? fs : L"not NTFS", path);
    return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
}

/* [A-Za-z0-9._-] only (not iswalnum: that depends on the locale and accepts non-ASCII letters) */
static BOOL AsciiNameChar(WCHAR c)
{
    return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') ||
           c == L'.' || c == L'-' || c == L'_';
}

/* A [Download] file name: a plain file name (it becomes part of the URL and of a path). */
static BOOL HostedNameOk(LPCWSTR n)
{
    LPCWSTR q;
    if (!n[0] || n[0] == L'.' || wcslen(n) > 80) return FALSE;
    for (q = n; *q; q++)
        if (!AsciiNameChar(*q)) return FALSE;
    return TRUE;
}

/* [Source] Path: segments of [A-Za-z0-9._-] separated by '/', no "." / ".." segment, no leading or trailing '/'. */
static BOOL HostedPathOk(LPCWSTR p)
{
    LPCWSTR q, seg = p;
    if (!p[0] || wcslen(p) > 200) return FALSE;
    for (q = p; ; q++)
    {
        if (*q == L'/' || !*q)
        {
            size_t l = q - seg;
            if (!l || (l == 1 && seg[0] == L'.') || (l == 2 && seg[0] == L'.' && seg[1] == L'.')) return FALSE;
            if (!*q) return TRUE;
            seg = q + 1;
        }
        else if (!AsciiNameChar(*q))
            return FALSE;
    }
}

/* Hosted pack: put every [Download] file, verified, into the payload dir (download what is missing or does not
 * match). *fetched = files this call downloaded (multi-sz, the caller deletes them after the enable). Nothing outside
 * %SystemRoot%\Featmgr is changed here. S_OK with nothing to do for a pack without [Download]. */
static HRESULT StageHostedPayload(const FM_FEATURE *f, WCHAR **fetched, FILE *log)
{
    WCHAR *sect, *line, payloadDir[MAX_PATH], base[512], path[256], why[256], sys[MAX_PATH], root[4];
    ULONGLONG need = 0;
    BOOL usable;
    HRESULT hr = S_OK;
    size_t cap = 0, used = 0;
    ULARGE_INTEGER avail, total, freeAll;

    *fetched = NULL;
    if (f->Tier != FM_TIER_OS || !(sect = ReadSection(f->ManifestPath, L"Download"))) return S_OK;
    if (!sect[0]) { HeapFree(GetProcessHeap(), 0, sect); return S_OK; }
    why[0] = L'\0';
    usable = HostedUsable(f->ManifestPath, why, ARRAYSIZE(why));
    HostedBaseUrl(f->ManifestPath, base, ARRAYSIZE(base));
    GetPrivateProfileStringW(L"Source", L"Path", L"", path, ARRAYSIZE(path), f->ManifestPath);
    if (usable && !HostedPathOk(path))
    {
        StringCchPrintfW(why, ARRAYSIZE(why), L"The catalog entry of '%s' has an invalid [Source] Path.", f->Id);
        usable = FALSE;
    }
    if (!FmGetPayloadDir(f->Id, payloadDir, MAX_PATH)) { HeapFree(GetProcessHeap(), 0, sect); return E_FAIL; }

    /* every [Payload] source of a hosted pack must have a pinned hash: fail closed before anything is fetched */
    {
        WCHAR *pay = ReadSection(f->ManifestPath, L"Payload"), *q, want[72];
        for (q = pay; q && *q && SUCCEEDED(hr); q += wcslen(q) + 1)
        {
            WCHAR *eq = wcschr(q, L'='), *bar;
            if (!eq || q[0] == L';' || !(bar = wcschr(eq + 1, L'|'))) continue;
            *bar = L'\0';
            if (!DownloadShaFor(f->ManifestPath, eq + 1, want))
            {
                LOGF(log, L"error: [Payload] file %s of hosted pack '%s' has no [Download] hash\n", eq + 1, f->Id);
                SetLastMsg(L"The catalog entry of '%s' lists a file without a pinned checksum, so nothing is downloaded.", f->Id);
                hr = E_INVALIDARG;
            }
            *bar = L'|';
        }
        if (pay) HeapFree(GetProcessHeap(), 0, pay);
        if (FAILED(hr)) { HeapFree(GetProcessHeap(), 0, sect); return hr; }
    }

    /* room for the download, the installed copy and the moved-aside originals */
    for (line = sect; *line; line += wcslen(line) + 1)
    {
        WCHAR *last = wcsrchr(line, L'|');
        if (last && line[0] != L';') need += _wcstoui64(last + 1, NULL, 10);
    }
    if (need && GetSystemDirectoryW(sys, MAX_PATH) && sys[1] == L':')
    {
        root[0] = sys[0]; root[1] = L':'; root[2] = L'\\'; root[3] = L'\0';
        if (GetDiskFreeSpaceExW(root, &avail, &total, &freeAll) && avail.QuadPart < need * 3)
        {
            LOGF(log, L"error: not enough disk space on %.2s for '%s': %I64u MB free, about %I64u MB needed\n",
                 root, f->Id, avail.QuadPart >> 20, (need * 3) >> 20);
            SetLastMsg(L"Not enough disk space on %.2s to install '%s': %I64u MB free, about %I64u MB needed. Nothing was changed.",
                       root, f->Name, avail.QuadPart >> 20, (need * 3) >> 20);
            HeapFree(GetProcessHeap(), 0, sect);
            return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
        }
    }

    for (line = sect; *line && SUCCEEDED(hr); line += wcslen(line) + 1)
    {
        WCHAR spec[400], *eq, *name, *sha, *size, *ctx = NULL, staged[MAX_PATH], got[72], dl[MAX_PATH];
        FM_COMPONENT c;
        size_t i, need2;

        eq = wcschr(line, L'=');
        if (!eq || line[0] == L';') continue;
        StringCchCopyW(spec, ARRAYSIZE(spec), eq + 1);
        name = wcstok_s(spec, L"|", &ctx);
        sha = wcstok_s(NULL, L"|", &ctx);
        size = wcstok_s(NULL, L"|", &ctx);
        for (i = 0; sha && sha[i]; i++)
            if (!iswxdigit(sha[i])) break;
        if (!name || !sha || i != 64 || sha[i] || !HostedNameOk(name))
        {
            LOGF(log, L"error: bad [Download] line in %s: %s\n", f->ManifestPath, line);
            SetLastMsg(L"The catalog entry of '%s' has an invalid [Download] line, so nothing is downloaded.", f->Id);
            hr = E_INVALIDARG;
            break;
        }
        StringCchPrintfW(staged, ARRAYSIZE(staged), L"%s\\%s", payloadDir, name);
        if (GetFileAttributesW(staged) != INVALID_FILE_ATTRIBUTES)
        {
            FmOpPhase(FM_PHASE_SEARCH);
            FmOpStep(L"Checking %s", name);
            if (FmFileSha256(staged, got) && !_wcsicmp(got, sha))
            {
                LOGF(log, L"  staged and verified: %s\n", staged);
                continue;
            }
            if (FmOpCancelled()) { SetLastMsg(L"The operation was cancelled. Nothing was changed."); hr = HRESULT_FROM_WIN32(ERROR_CANCELLED); break; }
            LOGF(log, L"  staged copy does not match its SHA-256, replacing: %s\n", staged);
            if (usable) DeleteFileW(staged);
        }
        if (!usable)
        {
            LOGF(log, L"error: '%s': %s\n", f->Id, why);
            SetLastMsg(L"%s", why);
            hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
            break;
        }
        ZeroMemory(&c, sizeof(c));
        StringCchCopyW(c.Id, ARRAYSIZE(c.Id), f->Id);
        StringCchPrintfW(c.Name, ARRAYSIZE(c.Name), L"%s", name);
        if (FAILED(StringCchPrintfW(c.Url, ARRAYSIZE(c.Url), L"%s/%s/%s", base, path, name)))
        {
            SetLastMsg(L"The download address of '%s' is too long.", f->Id);
            hr = E_INVALIDARG;
            break;
        }
        StringCchCopyW(c.Sha256, ARRAYSIZE(c.Sha256), sha);
        StringCchPrintfW(c.FileName, ARRAYSIZE(c.FileName), L"%s.%s", f->Id, name);
        c.Size = size ? _wcstoui64(size, NULL, 10) : 0;
        c.MaxSize = c.Size;                            /* pinned: a longer answer is aborted as soon as it passes this */
        c.ArchOk = TRUE;
        LOGF(log, L"  download: %s\n", c.Url);
        hr = FmCompDownload(&c, dl, ARRAYSIZE(dl), log);
        if (FAILED(hr))
        {
            WCHAR m[1024];
            FmGetLastMessage(m, ARRAYSIZE(m));
            LOGF(log, L"error: %s\n", m);
            break;
        }
        SHCreateDirectoryExW(NULL, payloadDir, NULL);
        if (!MoveFileExW(dl, staged, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
        {
            DWORD e = GetLastError();
            DeleteFileW(dl);
            SetLastMsg(L"Cannot move the download of %s into %s (error %lu).", name, payloadDir, e);
            hr = HRESULT_FROM_WIN32(e);
            break;
        }
        /* remember it: the caller deletes the downloaded copies once they are installed */
        need2 = used + wcslen(staged) + 2;
        if (need2 > cap)
        {
            size_t nc = max(need2, cap ? cap * 2 : 1024);
            WCHAR *nb = *fetched ? (WCHAR *)HeapReAlloc(GetProcessHeap(), 0, *fetched, nc * sizeof(WCHAR))
                                 : (WCHAR *)HeapAlloc(GetProcessHeap(), 0, nc * sizeof(WCHAR));
            if (!nb) continue;                         /* only the clean-up is lost */
            *fetched = nb; cap = nc;
        }
        StringCchCopyW(*fetched + used, cap - used, staged);
        used += wcslen(staged) + 1;
        (*fetched)[used] = L'\0';
    }
    HeapFree(GetProcessHeap(), 0, sect);
    return hr;
}

/* Delete the payload copies StageHostedPayload downloaded (and the payload dir once empty). */
static void DropFetched(WCHAR *fetched, LPCWSTR id, FILE *log)
{
    WCHAR *p, dir[MAX_PATH];
    if (!fetched) return;
    for (p = fetched; *p; p += wcslen(p) + 1)
    {
        LOGF(log, L"  drop downloaded payload copy: %s\n", p);
        DeleteFileW(p);
    }
    HeapFree(GetProcessHeap(), 0, fetched);
    if (FmGetPayloadDir(id, dir, MAX_PATH)) RemoveDirectoryW(dir);
}

/* [Feature] Conflicts=<id,...> and Replaces=<id,...>: features that own the same files/keys as this one (a newer
 * variant of an add-on). An enabled Replaces feature is turned off first (its files and keys are removed or its backups
 * restored, then this one is applied); an enabled Conflicts feature refuses the enable. Called after the payload is
 * staged, so a failed download leaves the old feature in place. */
static HRESULT ResolveSupersededFeatures(const FM_FEATURE *f, FILE *log)
{
    WCHAR list[FM_MAX_DEPS], *ctx, *d;
    int pass;

    for (pass = 0; pass < 2; pass++)       /* 0: Conflicts (refuse), 1: Replaces (turn off) */
    {
        list[0] = L'\0';
        GetPrivateProfileStringW(L"Feature", pass ? L"Replaces" : L"Conflicts", L"", list, FM_MAX_DEPS, f->ManifestPath);
        ctx = NULL;
        for (d = wcstok_s(list, L",; ", &ctx); d; d = wcstok_s(NULL, L",; ", &ctx))
        {
            FM_FEATURE o;
            HRESULT hr;
            if (!d[0] || !_wcsicmp(d, f->Id) || FmGetState(d) != FM_STATE_ENABLED) continue;
            if (!pass)
            {
                LOGF(log, L"error: cannot turn on '%s' while '%s' is on (they install the same files); turn '%s' off first\n", f->Id, d, d);
                SetLastMsg(L"Cannot turn on '%s' while '%s' is on: they install the same files. Turn '%s' off first.", f->Name, d, d);
                return HRESULT_FROM_WIN32(ERROR_BUSY);
            }
            LOGF(log, L"replacing '%s' with '%s': turning '%s' off first\n", d, f->Id, d);
            hr = FmDisableEx(d, 0, log);
            if (FAILED(hr)) return hr;
            if (FmFindFeature(d, &o) && o.PendingReboot)
            {
                LOGF(log, L"error: '%s' is still being removed (files in use); reboot, then turn '%s' on again\n", d, f->Id);
                SetLastMsg(L"'%s' could not be removed completely while its files are in use (close the programs that play media), then turn '%s' on again.", d, f->Name);
                return HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED);
            }
        }
    }
    return S_OK;
}

HRESULT FmEnable(LPCWSTR id, FILE *log)
{
    HRESULT result;

    if (g_OpDepth++ == 0) { g_LastMsg[0] = L'\0'; g_Tail[0] = L'\0'; }
    result = FmEnableInner(id, log);
    g_OpDepth--;
    return result;
}

static HRESULT FmEnableInner(LPCWSTR id, FILE *log)
{
    FM_FEATURE f;
    HKEY state = NULL;
    WCHAR payloadDir[MAX_PATH], now[32];
    WCHAR *sect, *p, *fetched = NULL, want[72];
    HRESULT hr = S_OK;
    BOOL hosted;

    if (!FmFindFeature(id, &f))
    {
        LOGF(log, L"error: unknown feature '%s'\n", id);
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }
    if (f.State == FM_STATE_ENABLED)
    {
        LOGF(log, L"feature '%s' already enabled\n", id);
        return S_OK;
    }
    if (!f.PayloadAvailable)
    {
        if (!_wcsicmp(f.Provider, L"scoop"))
        {
            LOGF(log, L"error: '%s' is not available: Scoop needs 64-bit PowerShell 7, which this system does not have\n", id);
            SetLastMsg(L"Scoop apps need 64-bit PowerShell 7 and are not available on this system (x86 images have no PowerShell 7 yet).");
        }
        else if (f.Tier == FM_TIER_SOFTWARE && f.Provider[0])
            LOGF(log, L"error: installer for '%s' is not available on this system "
                      L"(provider '%s': no download address or checksum for this system, or the staged installer is missing)\n", id, f.Provider);
        else if (f.Unavailable[0])
        {
            LOGF(log, L"error: '%s' cannot be turned on: %s\n", id, f.Unavailable);
            SetLastMsg(L"%s: %s", f.Name, f.Unavailable);
        }
        else
            LOGF(log, L"error: payload for '%s' is not staged on this system "
                      L"(catalog entry present, payload deferred)\n", id);
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    }

    if (OpenStateKey(id, FALSE, KEY_READ | KEY_WRITE, &state) == ERROR_SUCCESS)
    {
        BOOL pend = PendingRebootActive(state);
        RegCloseKey(state);
        state = NULL;
        if (pend)
        {
            LOGF(log, L"error: '%s' was disabled but is still being removed; reboot, then enable again\n", id);
            return HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED);
        }
    }

    LOGF(log, L"enabling '%s' (%s, tier=%s)\n", f.Id, f.Name, FmTierStr(f.Tier));

    if (f.Tier == FM_TIER_SOFTWARE)
    {
        hr = CheckFsRequirement(&f, log);
        if (FAILED(hr)) return hr;
    }
    hr = EnableDeps(&f, log);
    if (FAILED(hr)) return hr;

    /* hosted pack: download + verify the payload first; until it is complete nothing outside Featmgr changes */
    hr = StageHostedPayload(&f, &fetched, log);
    if (FAILED(hr))
    {
        LOGF(log, L"enable FAILED (0x%08lx): the payload could not be fetched; nothing was changed\n", hr);
        if (fetched) HeapFree(GetProcessHeap(), 0, fetched);      /* verified copies stay for the next try */
        return hr;
    }

    hr = ResolveSupersededFeatures(&f, log);
    if (FAILED(hr))
    {
        if (fetched) HeapFree(GetProcessHeap(), 0, fetched);      /* verified copies stay for the next try */
        return hr;
    }

    if (OpenStateKey(id, TRUE, KEY_READ | KEY_WRITE, &state) != ERROR_SUCCESS)
    {
        DropFetched(fetched, id, log);
        return E_FAIL;
    }

    if (f.Tier == FM_TIER_SOFTWARE && f.Provider[0])
    {
        /* install != enable: fetch + run the installer instead of placing in-image bits */
        hr = SoftwareInstall(&f, state, log);
        if (FAILED(hr))
        {
            WCHAR sub[512];
            LOGF(log, L"install FAILED (0x%08lx)\n", hr);
            RegCloseKey(state);
            if (f.State == FM_STATE_NOT_INSTALLED)  /* drop the empty record we just created */
            {
                StringCchPrintfW(sub, 512, L"%s\\%s", STATE_KEY, id);
                RegDeleteKeyW(HKEY_LOCAL_MACHINE, sub);
            }
            return hr;
        }
        /* per-app configuration the installer cannot do (install-time registry: protocol
         * handlers, compatibility settings), reverted with the app on disable */
        RegDeleteValueW(state, L"RegUndo");
        hr = ApplyRegistrySection(&f, state, log);
        if (FAILED(hr))
        {
            WCHAR sub[512];
            LOGF(log, L"post-install registry FAILED (0x%08lx); uninstalling\n", hr);
            SoftwareUninstall(&f, state, log);
            RevertState(state, log);
            RegCloseKey(state);
            if (f.State == FM_STATE_NOT_INSTALLED)
            {
                StringCchPrintfW(sub, 512, L"%s\\%s", STATE_KEY, id);
                RegDeleteKeyW(HKEY_LOCAL_MACHINE, sub);
            }
            return hr;
        }
        UtcNow(now, 32);
        SetStateSz(state, L"State", L"Enabled");
        SetStateSz(state, L"Name", f.Name);
        SetStateSz(state, L"Version", f.Version);
        SetStateSz(state, L"Tier", FmTierStr(f.Tier));
        SetStateSz(state, L"InstallDate", now);
        LOGF(log, L"'%s' installed.\n", id);
        RegCloseKey(state);
        return S_OK;
    }

    /* fresh undo lists for this activation */
    RegDeleteValueW(state, L"Files");
    RegDeleteValueW(state, L"RegUndo");
    RegDeleteValueW(state, L"Backups");
    RegDeleteValueW(state, L"Services");

    /* payload files (a hosted pack: each one checked against its pinned hash where it lands) */
    hosted = HostedPack(&f);
    FmOpPhase(FM_PHASE_APPLY);
    FmOpStep(L"Installing %s", f.Name);
    FmGetPayloadDir(id, payloadDir, MAX_PATH);
    sect = ReadSection(f.ManifestPath, L"Payload");
    if (sect)
    {
        for (p = sect; *p; p += wcslen(p) + 1)
        {
            WCHAR *eq = wcschr(p, L'='), *sep;
            if (!eq) continue;
            sep = wcschr(eq + 1, L'|');
            if (!sep) continue;
            *sep = L'\0';
            if (hosted && !DownloadShaFor(f.ManifestPath, eq + 1, want))
            {
                LOGF(log, L"error: [Payload] file %s of hosted pack '%s' has no [Download] hash; nothing installed\n", eq + 1, id);
                SetLastMsg(L"The catalog entry of '%s' lists a file without a pinned checksum, so it is not installed.", id);
                *sep = L'|';
                hr = E_INVALIDARG;
                goto done;
            }
            hr = ApplyPayloadFile(payloadDir, eq + 1, sep + 1, hosted ? want : NULL, state, log);
            *sep = L'|';
            if (FAILED(hr)) goto done;
        }
        HeapFree(GetProcessHeap(), 0, sect);
        sect = NULL;
    }

    /* registry actions */
    hr = ApplyRegistrySection(&f, state, log);
    if (FAILED(hr)) goto done;

    /* driver/service registration (after files + registry, so the image exists) */
    sect = ReadSection(f.ManifestPath, L"Service");
    if (sect)
    {
        for (p = sect; *p; p += wcslen(p) + 1)
        {
            WCHAR *eq = wcschr(p, L'=');
            if (!eq) continue;
            hr = ApplyServiceAction(eq + 1, state, log);
            if (FAILED(hr)) goto done;
        }
    }

    UtcNow(now, 32);
    SetStateSz(state, L"State", L"Enabled");
    SetStateSz(state, L"Name", f.Name);
    SetStateSz(state, L"Version", f.Version);
    SetStateSz(state, L"Tier", FmTierStr(f.Tier));
    SetStateSz(state, L"InstallDate", now);
    LOGF(log, L"'%s' enabled.\n", id);

done:
    if (sect) HeapFree(GetProcessHeap(), 0, sect);
    if (FAILED(hr))
    {
        LOGF(log, L"enable FAILED (0x%08lx); rolling back\n", hr);
        if (state) RevertState(state, log);
    }
    if (state) RegCloseKey(state);
    if (SUCCEEDED(hr))
        DropFetched(fetched, id, log);              /* installed: the downloaded copies are not needed any more */
    else if (fetched)
        HeapFree(GetProcessHeap(), 0, fetched);     /* verified copies stay for the next try */
    return hr;
}

/* Is dest one of the "dest|bak" records of the Backups list? */
static BOOL HasBackup(const WCHAR *baks, LPCWSTR dest)
{
    const WCHAR *p;
    size_t l = wcslen(dest);
    if (!baks) return FALSE;
    for (p = baks; *p; p += wcslen(p) + 1)
        if (!_wcsnicmp(p, dest, l) && p[l] == L'|') return TRUE;
    return FALSE;
}

/* Undo everything recorded in the state key: registry, placed files, then
 * restore any backed-up originals. Used by disable and by enable rollback. */
static void RevertState(HKEY state, FILE *log)
{
    WCHAR *files, *undo, *baks, *p;

    /* unregister services first: the driver image must not be in use when deleted */
    RemoveRecordedServices(state, log);

    /* revert registry */
    undo = MultiSzRead(state, L"RegUndo");
    if (undo)
    {
        /* values first, then the keys this feature created, newest first (children before parents) */
        for (p = undo; *p; p += wcslen(p) + 1)
            if (p[0] != L'K') RevertRegUndo(p, log);
        {
            WCHAR *last;
            BOOL more = TRUE;
            WCHAR *stop = NULL;
            while (more)
            {
                last = NULL;
                for (p = undo; *p && p != stop; p += wcslen(p) + 1)
                    if (p[0] == L'K') last = p;
                if (!last) break;
                RevertRegUndo(last, log);
                stop = last;
            }
        }
        HeapFree(GetProcessHeap(), 0, undo);
    }

    /* delete installed files */
    baks = MultiSzRead(state, L"Backups");
    files = MultiSzRead(state, L"Files");
    if (files)
    {
        for (p = files; *p; p += wcslen(p) + 1)
        {
            LOGF(log, L"  remove file: %s\n", p);
            if (!DeleteFileW(p) && GetLastError() != ERROR_FILE_NOT_FOUND)
            {
                DWORD e = GetLastError();
                WCHAR aside[MAX_PATH + 16];
                BOOL moved = FALSE, backedUp = HasBackup(baks, p);
                int n;
                /* in use (a loaded DLL): rename it to a free aside name and delete THAT at reboot, so a backed-up
                 * original can go back under the real name at once. A reboot-delete is never queued for the real
                 * name of a file that has a backup: the restored original would be deleted with it. */
                for (n = 0; n < 10 && !moved; n++)
                {
                    if (n) StringCchPrintfW(aside, ARRAYSIZE(aside), L"%s.fmdel%d", p, n);
                    else StringCchPrintfW(aside, ARRAYSIZE(aside), L"%s.fmdel", p);
                    if (GetFileAttributesW(aside) != INVALID_FILE_ATTRIBUTES && !DeleteFileW(aside))
                        continue;                                   /* an older aside copy, itself still in use */
                    moved = MoveFileExW(p, aside, 0);
                }
                if (moved)
                {
                    if (MoveFileExW(aside, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
                    {
                        LOGF(log, L"  note: %s is in use (%lu); moved to %s, which is deleted at reboot\n", p, e, aside);
                        MultiSzAppend(state, L"PendingFiles", aside);
                    }
                    else
                        LOGF(log, L"  warn: %s moved to %s but its reboot-delete failed (%lu)\n", p, aside, GetLastError());
                }
                else if (backedUp)
                {
                    /* the restore below replaces it at reboot (MOVEFILE_DELAY_UNTIL_REBOOT | REPLACE_EXISTING) */
                    LOGF(log, L"  note: %s is in use (%lu) and cannot be moved aside; the original replaces it at reboot\n", p, e);
                }
                else if (MoveFileExW(p, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
                {
                    LOGF(log, L"  note: %s is in use (%lu); will be deleted at reboot\n", p, e);
                    MultiSzAppend(state, L"PendingFiles", p);
                }
                else
                    LOGF(log, L"  warn: delete failed (%lu), reboot-delete failed (%lu)\n", e, GetLastError());
            }
            else
            {
                /* drop a pack-private directory once it is empty (fails harmlessly if not) */
                WCHAR dir[MAX_PATH];
                StringCchCopyW(dir, MAX_PATH, p);
                PathRemoveFileSpecW(dir);
                RemoveDirectoryW(dir);
            }
        }
        HeapFree(GetProcessHeap(), 0, files);
    }

    /* put back files that enable moved aside ("dest|bak") */
    if (baks)
    {
        for (p = baks; *p; p += wcslen(p) + 1)
        {
            WCHAR *sep = wcschr(p, L'|');
            if (!sep) continue;
            *sep = L'\0';
            LOGF(log, L"  restore file: %s <- %s\n", p, sep + 1);
            DeleteFileW(p);
            if (!MoveFileW(sep + 1, p))
            {
                DWORD e = GetLastError();
                if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES &&
                    MoveFileExW(sep + 1, p, MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING))
                {
                    /* the pack's file is still in place and in use: the original takes its name at the next boot */
                    LOGF(log, L"  note: restore of %s is deferred to the next reboot (%lu)\n", p, e);
                    MultiSzAppend(state, L"PendingFiles", sep + 1);
                }
                else
                    LOGF(log, L"  warn: restore failed (%lu)\n", e);
            }
            *sep = L'|';
        }
        HeapFree(GetProcessHeap(), 0, baks);
    }

    RegDeleteValueW(state, L"Files");
    RegDeleteValueW(state, L"RegUndo");
    RegDeleteValueW(state, L"Backups");
    RegDeleteValueW(state, L"Services");
}

static HRESULT DisableOne(LPCWSTR id, DWORD flags, FILE *log)
{
    HKEY state = NULL;

    /* FmGetState includes the installed-state probe: a Scoop app installed with the scoop CLI is
     * Enabled without a record, so the record is created here when it is missing. */
    if (FmGetState(id) != FM_STATE_ENABLED
        || OpenStateKey(id, TRUE, KEY_READ | KEY_WRITE, &state) != ERROR_SUCCESS)
    {
        LOGF(log, L"feature '%s' is not enabled; nothing to do\n", id);
        if (state) RegCloseKey(state);
        return S_OK;
    }

    LOGF(log, L"disabling '%s'\n", id);
    {
        /* software tier: disable == run the app's uninstaller */
        FM_FEATURE sf;
        if (FmFindFeature(id, &sf) && sf.Tier == FM_TIER_SOFTWARE && sf.Provider[0])
        {
            HRESULT shr = SoftwareUninstall(&sf, state, log);
            if (FAILED(shr))
            {
                if (!(flags & FM_DISABLE_FORCE))
                {
                    LOGF(log, L"'%s' left enabled (use /force to forget it anyway)\n", id);
                    RegCloseKey(state);
                    return shr;
                }
                LOGF(log, L"warn: uninstaller failed but /force given; marking '%s' disabled\n", id);
            }
        }
    }
    RegDeleteValueW(state, L"PendingFiles");
    RegDeleteValueW(state, L"PendingServices");
    RegDeleteValueW(state, L"PendingReboot");
    RevertState(state, log);
    {
        DWORD cb = 0;
        if (RegQueryValueExW(state, L"PendingFiles", NULL, NULL, NULL, &cb) == ERROR_SUCCESS ||
            RegQueryValueExW(state, L"PendingServices", NULL, NULL, NULL, &cb) == ERROR_SUCCESS)
        {
            SetStateSz(state, L"PendingReboot", L"Yes");
            LOGF(log, L"note: some components are in use; removal completes at the next reboot\n");
        }
    }
    SetStateSz(state, L"State", L"Disabled");
    LOGF(log, L"'%s' disabled.\n", id);
    RegCloseKey(state);
    return S_OK;
}

/* ---- dependents / disable policy / uninstall ----------------------------- */

/* Base components (catalog Removable=0) are part of the image: refuse to
 * disable or uninstall them, regardless of dependents or current state. */
static HRESULT CheckRemovable(LPCWSTR id, FILE *log)
{
    FM_FEATURE feat;
    if (FmFindFeature(id, &feat) && !feat.Removable)
    {
        if (feat.BuiltIn)
        {
            LOGF(log, L"error: '%s' is a base component of this image (setup installed it with the system, not featmgr) "
                      L"and cannot be disabled or removed here\n", id);
            SetLastMsg(L"%s is part of this NitroOS image (setup installed it with the system), so it cannot be turned off here.", feat.Name);
        }
        else
        {
            LOGF(log, L"error: '%s' is a base component of the system and cannot be disabled or removed\n", id);
            SetLastMsg(L"%s is a base component of the system and cannot be turned off.", feat.Name);
        }
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }
    return S_OK;
}

static BOOL DepsContain(LPCWSTR deps, LPCWSTR id)
{
    WCHAR tmp[FM_MAX_DEPS];
    WCHAR *ctx = NULL, *d;
    StringCchCopyW(tmp, FM_MAX_DEPS, deps);
    for (d = wcstok_s(tmp, L",; ", &ctx); d; d = wcstok_s(NULL, L",; ", &ctx))
        if (!_wcsicmp(d, id)) return TRUE;
    return FALSE;
}

int FmGetDependentsIn(const FM_FEATURE *arr, int n, LPCWSTR id, LPWSTR buf, DWORD cch)
{
    int i, cnt = 0;
    if (cch) buf[0] = L'\0';
    for (i = 0; i < n; i++)
    {
        if (arr[i].State != FM_STATE_ENABLED || !_wcsicmp(arr[i].Id, id)) continue;
        if (!DepsContain(arr[i].Dependencies, id)) continue;
        if (cnt++ && cch) StringCchCatW(buf, cch, L",");
        if (cch) StringCchCatW(buf, cch, arr[i].Id);
    }
    return cnt;
}

int FmGetDependents(LPCWSTR id, LPWSTR buf, DWORD cch)
{
    FM_FEATURE *arr;
    int n, cnt;
    n = FmEnumFeatures(&arr);
    cnt = FmGetDependentsIn(arr, n, id, buf, cch);
    FmFree(arr);
    return cnt;
}

HRESULT FmDisableEx(LPCWSTR id, DWORD flags, FILE *log)
{
    WCHAR deps[FM_MAX_DEPS * 2];
    WCHAR *ctx = NULL, *d;
    HRESULT hr;

    if (g_OpDepth == 0) { g_LastMsg[0] = L'\0'; g_Tail[0] = L'\0'; }
    hr = CheckRemovable(id, log);      /* first: base component guard (GFX-FU) */
    if (FAILED(hr)) return hr;

    if (FmGetDependents(id, deps, ARRAYSIZE(deps)))
    {
        if (!(flags & FM_DISABLE_CASCADE))
        {
            LOGF(log, L"error: cannot disable '%s': enabled feature(s) depend on it: %s "
                      L"(disable those first, or use /cascade)\n", id, deps);
            SetLastMsg(L"Cannot turn off '%s' while enabled features depend on it: %s (turn those off first, or use /cascade).", id, deps);
            return HRESULT_FROM_WIN32(ERROR_DEPENDENT_SERVICES_RUNNING);
        }
        /* dependents first; each recursive call handles its own dependents */
        for (d = wcstok_s(deps, L",", &ctx); d; d = wcstok_s(NULL, L",", &ctx))
        {
            LOGF(log, L"cascade: disabling dependent '%s'\n", d);
            hr = FmDisableEx(d, flags, log);
            if (FAILED(hr)) return hr;
        }
    }
    return DisableOne(id, flags, log);
}

HRESULT FmDisable(LPCWSTR id, FILE *log)
{
    return FmDisableEx(id, 0, log);
}

HRESULT FmUninstall(LPCWSTR id, FILE *log)
{
    return FmUninstallEx(id, 0, log);
}

HRESULT FmUninstallEx(LPCWSTR id, DWORD flags, FILE *log)
{
    HKEY state;
    HRESULT hr;
    WCHAR sub[512];
    BOOL pending = FALSE;
    LONG rdk;

    hr = CheckRemovable(id, log);
    if (FAILED(hr)) return hr;

    if (FmGetState(id) == FM_STATE_NOT_INSTALLED)
    {
        LOGF(log, L"feature '%s' is not installed; nothing to do\n", id);
        StringCchPrintfW(sub, 512, L"%s\\%s", STATE_KEY, id);
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, sub);          /* a stale record (app removed outside featmgr) */
        return S_OK;
    }
    hr = FmDisableEx(id, flags, log);   /* no-op if already Disabled */
    if (FAILED(hr)) return hr;

    if (OpenStateKey(id, FALSE, KEY_READ | KEY_WRITE, &state) == ERROR_SUCCESS)
    {
        pending = PendingRebootActive(state);
        RegCloseKey(state);
    }
    if (pending)
    {
        LOGF(log, L"note: '%s' still has components pending removal; record kept until reboot\n", id);
        return HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED);
    }
    StringCchPrintfW(sub, 512, L"%s\\%s", STATE_KEY, id);
    rdk = RegDeleteKeyW(HKEY_LOCAL_MACHINE, sub);
    if (rdk != ERROR_SUCCESS && rdk != ERROR_FILE_NOT_FOUND)
    {
        LOGF(log, L"warn: could not delete state record for '%s'\n", id);
        return E_FAIL;
    }
    LOGF(log, L"'%s' uninstalled (state record removed).\n", id);
    return S_OK;
}

/* ---- search ---------------------------------------------------------------- */

BOOL FmMatchSearch(const FM_FEATURE *f, LPCWSTR text)
{
    if (!text || !text[0]) return TRUE;
    return StrStrIW(f->Name, text) != NULL || StrStrIW(f->Description, text) != NULL;
}

/* ---- Scoop operations beyond install/uninstall (SCOOP-FEATMGR-01 M2) ------- */

static HRESULT ScoopPrereq(FILE *log)
{
    WCHAR pw[MAX_PATH], runner[MAX_PATH];

    if (!FmScoopSupported())
    {
        LOGF(log, L"error: Scoop needs 64-bit PowerShell 7, which is not available on this architecture (x86)\n");
        SetLastMsg(L"Scoop needs 64-bit PowerShell 7, which is not available on this architecture (x86).");
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }
    if (!GetEnvironmentVariableW(L"FEATMGR_SCOOP_RUNNER", runner, MAX_PATH)
        && (!FmPwshPath(pw, MAX_PATH) || GetFileAttributesW(pw) == INVALID_FILE_ATTRIBUTES))
    {
        LOGF(log, L"error: PowerShell 7 is required to run Scoop but is not installed\n");
        SetLastMsg(L"PowerShell 7 is required to run Scoop but is not installed. Install the 'powershell-7' feature first.");
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    }
    return S_OK;
}

/* "scoop <args>" (args pre-validated by the caller), output streamed to log. */
static HRESULT RunScoop(LPCWSTR args, FILE *log)
{
    WCHAR cmd[2048];
    DWORD code;
    HRESULT hr;

    hr = ScoopPrereq(log);
    if (FAILED(hr)) return hr;
    if (!FmScoopCommandArgs(args, cmd, ARRAYSIZE(cmd)))
    {
        LOGF(log, L"error: cannot build a Scoop command line for '%s'\n", args);
        SetLastMsg(L"Cannot build a valid Scoop command line for '%s'.", args);
        return E_INVALIDARG;
    }
    FmScoopPrepareEnv();
    FmOpStep(L"Running: scoop %s", args);
    hr = RunAndWait(cmd, SW_RUN_TIMEOUT_MS, &code, log);
    if (FAILED(hr)) return hr;
    if (code != 0)
    {
        LOGF(log, L"error: 'scoop %s' failed (exit code %lu)\n", args, code);
        SetLastMsg(L"'scoop %s' failed (exit code %lu).\n\n%s", args, code, g_Tail);
        return HRESULT_FROM_WIN32(ERROR_INSTALL_FAILURE);
    }
    return S_OK;
}

static HRESULT FmUpdateInner(LPCWSTR id, FILE *log)
{
    FM_FEATURE f, after;
    WCHAR before[FM_MAX_VER], args[128];
    HRESULT hr;

    if (!FmFindFeature(id, &f))
    {
        LOGF(log, L"error: unknown feature '%s'\n", id);
        SetLastMsg(L"Unknown feature '%s'.", id);
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }
    if (_wcsicmp(f.Provider, L"scoop"))
    {
        LOGF(log, L"error: '%s' cannot be updated by featmgr: only Scoop apps have an updater (provider: %s)\n",
             f.Id, f.Provider[0] ? f.Provider : L"none");
        SetLastMsg(L"'%s' cannot be updated by featmgr: only Scoop apps have an updater.", f.Name);
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }
    if (f.State != FM_STATE_ENABLED)
    {
        LOGF(log, L"error: '%s' is not installed\n", f.Id);
        SetLastMsg(L"'%s' is not installed.", f.Name);
        return HRESULT_FROM_WIN32(ERROR_INVALID_STATE);
    }
    if (!FmScoopValidApp(f.App))
    {
        SetLastMsg(L"'%s' has an invalid Scoop app name.", f.Id);
        return E_INVALIDARG;
    }
    StringCchCopyW(before, ARRAYSIZE(before), f.InstalledVersion);
    LOGF(log, L"updating '%s' (installed %s, catalog %s)\n", f.Id, before[0] ? before : L"?", f.Version);
    StringCchPrintfW(args, ARRAYSIZE(args), L"update %s", f.App);
    hr = RunScoop(args, log);
    if (FAILED(hr))
    {
        LOGF(log, L"update FAILED (0x%08lx)\n", hr);
        return hr;
    }
    FmScoopAppDefaults(f.App, log);             /* NitroOS default for VS Code (scoopdefaults.c) */
    /* "scoop update" may have pulled the bucket: read its manifests again */
    if (f.Bucket[0] && FmScoopReimport(f.Bucket, log) < 0)
        LOGF(log, L"  note: the catalog entries of bucket '%s' were not refreshed\n", f.Bucket);
    if (FmFindFeature(id, &after) && after.InstalledVersion[0])
    {
        if (!wcscmp(before, after.InstalledVersion))
            LOGF(log, L"'%s' is at the latest version Scoop has for it (%s).\n", id, after.InstalledVersion);
        else
            LOGF(log, L"'%s' updated: %s -> %s\n", id, before[0] ? before : L"?", after.InstalledVersion);
    }
    else
        LOGF(log, L"'%s' updated.\n", id);
    return S_OK;
}

HRESULT FmUpdate(LPCWSTR id, FILE *log)
{
    HRESULT hr;
    if (g_OpDepth++ == 0) { g_LastMsg[0] = L'\0'; g_Tail[0] = L'\0'; }
    hr = FmUpdateInner(id, log);
    g_OpDepth--;
    return hr;
}

HRESULT FmUpdateAll(FILE *log)
{
    HRESULT hr;

    if (g_OpDepth++ == 0) { g_LastMsg[0] = L'\0'; g_Tail[0] = L'\0'; }
    LOGF(log, L"updating Scoop and its buckets\n");
    hr = RunScoop(L"update", log);
    if (SUCCEEDED(hr))
    {
        int n = FmScoopReimportAll(log);
        LOGF(log, L"catalog refreshed from the updated buckets (%d entries)\n", n < 0 ? 0 : n);
        LOGF(log, L"updating all installed Scoop apps\n");
        hr = RunScoop(L"update *", log);
        if (SUCCEEDED(hr))
        {
            FmScoopAppDefaultsAll(log);                     /* NitroOS defaults (scoopdefaults.c) */
            LOGF(log, L"all Scoop apps are up to date.\n");
        }
    }
    if (FAILED(hr)) LOGF(log, L"update FAILED (0x%08lx)\n", hr);
    g_OpDepth--;
    return hr;
}

/* Add a bucket to Scoop and import it. A bucket on Scoop's own list ("scoop bucket known") is added
 * by name. Anything else, and any explicit URL, is the command-line-only path and needs the
 * trust flag: a bucket's manifests can run PowerShell as administrator. The import that follows
 * is covered by the same consent. */
HRESULT FmScoopAddBucket(LPCWSTR name, LPCWSTR url, DWORD flags, FILE *log)
{
    WCHAR root[MAX_PATH], d[MAX_PATH], args[320];
    BOOL known, haveUrl = url && url[0];
    HRESULT hr;
    int n, skipped = 0;

    if (g_OpDepth++ == 0) { g_LastMsg[0] = L'\0'; g_Tail[0] = L'\0'; }
    hr = ScoopPrereq(log);
    if (FAILED(hr)) goto out;
    if (!FmScoopValidBucket(name))
    {
        LOGF(log, L"error: '%s' is not a valid bucket name\n", name);
        SetLastMsg(L"'%s' is not a valid bucket name.", name);
        hr = E_INVALIDARG; goto out;
    }
    known = FmScoopBucketIsKnown(name);
    if (haveUrl && !FmScoopValidUrl(url))
    {
        LOGF(log, L"error: the bucket URL must be a plain https:// URL (letters, digits and . _ ~ : / ? # @ ! * + , = - only)\n");
        SetLastMsg(L"The bucket URL must be a plain https:// URL.");
        hr = E_INVALIDARG; goto out;
    }
    if ((haveUrl || !known) && !(flags & FM_BUCKET_TRUST))
    {
        if (!known && !haveUrl)
            LOGF(log, L"error: '%s' is not one of Scoop's known buckets (see featmgr /scoop-buckets). To add another bucket "
                      L"give its https URL and /trust: featmgr /add-bucket <name> <url> /trust\n", name);
        else
            LOGF(log, L"error: adding a bucket from a URL needs your explicit consent: its manifests can run PowerShell as "
                      L"administrator. Add /trust if you trust the maintainers.\n");
        SetLastMsg(L"Only Scoop's known buckets can be added without an explicit /trust.");
        hr = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED); goto out;
    }
    if (!known && !haveUrl)
    {
        LOGF(log, L"error: '%s' is not one of Scoop's known buckets; give its https URL: featmgr /add-bucket %s <url> /trust\n", name, name);
        SetLastMsg(L"'%s' is not one of Scoop's known buckets.", name);
        hr = E_INVALIDARG; goto out;
    }
    if (!FmScoopRoot(root, MAX_PATH)) { hr = E_FAIL; goto out; }
    StringCchPrintfW(d, MAX_PATH, L"%s\\buckets\\%s", root, name);
    if (GetFileAttributesW(d) != INVALID_FILE_ATTRIBUTES)
        LOGF(log, L"bucket '%s' is already added to Scoop\n", name);
    else
    {
        if (haveUrl) StringCchPrintfW(args, ARRAYSIZE(args), L"bucket add %s %s", name, url);
        else         StringCchPrintfW(args, ARRAYSIZE(args), L"bucket add %s", name);
        hr = RunScoop(args, log);
        if (FAILED(hr))
        {
            WCHAR g[MAX_PATH];
            StringCchPrintfW(g, MAX_PATH, L"%s\\apps\\git\\current", root);
            if (GetFileAttributesW(g) == INVALID_FILE_ATTRIBUTES)
                LOGF(log, L"hint: Scoop adds buckets with git. If git is not installed: featmgr /install git\n");
            goto out;
        }
        if (GetFileAttributesW(d) == INVALID_FILE_ATTRIBUTES)
        {
            LOGF(log, L"error: scoop reported success but %s does not exist\n", d);
            hr = E_FAIL; goto out;
        }
    }
    n = FmImportScoop(name, NULL, FM_SCOOP_TRUST, 0, &skipped, log);
    hr = n < 0 ? E_FAIL : S_OK;
out:
    g_OpDepth--;
    return hr;
}
