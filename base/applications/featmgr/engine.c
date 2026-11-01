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
    IniGet(&ini, L"Feature", L"Version", L"1.0.0", f->Version, FM_MAX_VER);
    IniGet(&ini, L"Feature", L"Dependencies", L"", f->Dependencies, FM_MAX_DEPS);
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
            StringCchCopyW(f->Source, ARRAYSIZE(f->Source), f->Provider[0] ? f->Provider : L"payload");
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

static BOOL RappsExePath(LPWSTR out, DWORD cch)
{
    WCHAR sys[MAX_PATH];
    if (!GetSystemDirectoryW(sys, MAX_PATH)) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch, L"%s\\rapps.exe", sys));
}

/* [Rapps] Entry= : a RAPPS-format entry that ships in the image (absolute, %SystemRoot% etc.
 * expanded; or relative to the feature's payload dir) for packages that are not in the online
 * RAPPS database. */
static BOOL RappsEntryPath(const FM_FEATURE *f, LPWSTR out, DWORD cch)
{
    WCHAR raw[MAX_PATH], exp[MAX_PATH];
    GetPrivateProfileStringW(L"Rapps", L"Entry", L"", raw, MAX_PATH, f->ManifestPath);
    if (!raw[0]) return FALSE;
    ExpandCmd(f->Id, raw, exp, MAX_PATH);
    if (IsAbsPath(exp))
        return SUCCEEDED(StringCchCopyW(out, cch, exp));
    FmGetPayloadDir(f->Id, out, cch);
    return SUCCEEDED(StringCchCatW(out, cch, L"\\")) && SUCCEEDED(StringCchCatW(out, cch, exp));
}

/* Can the install be attempted? rapps provider: rapps.exe present (the download
 * happens at install time, so there is no staged payload to check). command
 * provider: the installer file is staged. */
static BOOL SoftwareAvailable(const FM_FEATURE *f)
{
    WCHAR p[MAX_PATH];
    if (!_wcsicmp(f->Provider, L"command"))
        return InstallerPath(f, p, MAX_PATH) && GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
    if (!_wcsicmp(f->Provider, L"scoop"))
        return FmScoopUsable();
    if (_wcsicmp(f->Provider, L"rapps"))
        return FALSE;                                   /* unknown provider */
    if (!RappsExePath(p, MAX_PATH) || GetFileAttributesW(p) == INVALID_FILE_ATTRIBUTES)
        return FALSE;
    if (RappsEntryPath(f, p, MAX_PATH))                 /* shipped RAPPS entry must be present */
        return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
    return TRUE;
}

/* Does every declared [Payload] source file exist on disk? */
static BOOL PayloadPresent(const FM_FEATURE *f)
{
    WCHAR payloadDir[MAX_PATH], src[MAX_PATH];
    WCHAR *sect, *p, *sep;
    BOOL ok = TRUE;

    if (f->Tier == FM_TIER_SOFTWARE && f->Provider[0])
        return SoftwareAvailable(f);

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
    if (f->Tier != FM_TIER_SOFTWARE || !DetectPathFor(f, p, MAX_PATH)) return;
    present = GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
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
                                HKEY state, FILE *log)
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
    return S_OK;
}

/* Set one registry value, recording undo info. Value spec: HIVE|subkey|name|type|data
 * name "@" => default value. type REG_SZ or REG_DWORD. */
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

    if (RegCreateKeyExW(hive, tok[1], 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &k, NULL)
        != ERROR_SUCCESS)
    {
        LOGF(log, L"  ERROR: open/create key %s failed\n", tok[1]);
        return E_FAIL;
    }

    /* record undo: existed? save prior; else mark for delete */
    r = RegQueryValueExW(k, valName, NULL, &prevType, (LPBYTE)prev, &prevCb);
    if (r == ERROR_SUCCESS && prevType == REG_SZ)
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

/* Run a command line, wait, return its exit code in *code. A run that exceeds the
 * timeout is terminated (exact process handle) and reported as ERROR_TIMEOUT. */
static HRESULT RunAndWait(LPCWSTR cmdline, DWORD timeoutMs, DWORD *code, FILE *log)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    WCHAR cl[2048], tmpDir[MAX_PATH], tmpFile[MAX_PATH];
    HANDLE hOut = INVALID_HANDLE_VALUE, hIn = INVALID_HANDLE_VALUE, hRd = INVALID_HANDLE_VALUE;
    char carry[8192];
    DWORD ncarry = 0, pos = 0, w, flags = 0, start = GetTickCount(), elapsed;
    HRESULT hr = S_OK;
    BOOL ok;

    *code = (DWORD)-1;
    g_Tail[0] = L'\0';
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
    CloseHandle(pi.hThread);
    for (;;)
    {
        elapsed = GetTickCount() - start;
        if (elapsed >= timeoutMs) { w = WAIT_TIMEOUT; break; }
        w = WaitForSingleObject(pi.hProcess, hRd != INVALID_HANDLE_VALUE ? 500 : timeoutMs - elapsed);
        if (hRd != INVALID_HANDLE_VALUE) DrainOutput(hRd, &pos, carry, &ncarry, sizeof(carry), FALSE, log);
        if (w != WAIT_TIMEOUT) break;
    }
    if (hRd != INVALID_HANDLE_VALUE) DrainOutput(hRd, &pos, carry, &ncarry, sizeof(carry), TRUE, log);
    if (w == WAIT_TIMEOUT)
    {
        LOGF(log, L"  ERROR: command still running after %lu s; terminating pid %lu\n",
             timeoutMs / 1000, pi.dwProcessId);
        SetLastMsg(L"The command was still running after %lu s and was terminated.\n%s", timeoutMs / 1000, g_Tail);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        goto out;
    }
    GetExitCodeProcess(pi.hProcess, code);
    CloseHandle(pi.hProcess);
    LOGF(log, L"  exit code: %lu\n", *code);
out:
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
    WCHAR pkg[128], name[128], rapps[MAX_PATH], ucmd[1024], local[128], lpath[MAX_PATH], lentry[MAX_PATH];

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

    if (_wcsicmp(f->Provider, L"rapps"))
    {
        LOGF(log, L"error: '%s' has unknown install provider '%s'\n", f->Id, f->Provider);
        return E_INVALIDARG;
    }
    /* rapps provider: pkg name from [Rapps] Pkg */
    GetPrivateProfileStringW(L"Rapps", L"Pkg", L"", pkg, ARRAYSIZE(pkg), f->ManifestPath);
    if (!pkg[0] || wcspbrk(pkg, L"\"\r\n"))
    {
        LOGF(log, L"error: '%s' has no valid [Rapps] Pkg\n", f->Id);
        return E_INVALIDARG;
    }
    if (!RappsExePath(rapps, MAX_PATH)) return E_FAIL;
    StringCchPrintfW(inst, cch, L"\"%s\" /install /S \"%s\"", rapps, pkg);
    /* [Rapps] LocalInstaller= : file name of an MSI in the feature's payload dir (the image puts it there). When it
     * exists the install is local-first: msiexec on that file with the entry's MsiProperties, no download, so it
     * works offline. When it is absent rapps downloads the package as usual. */
    GetPrivateProfileStringW(L"Rapps", L"LocalInstaller", L"", local, ARRAYSIZE(local), f->ManifestPath);
    if (local[0] && !wcspbrk(local, L"\\/\"\r\n") && RappsEntryPath(f, lentry, MAX_PATH))
    {
        WCHAR props[1024];
        FmGetPayloadDir(f->Id, lpath, MAX_PATH);
        if (SUCCEEDED(StringCchCatW(lpath, MAX_PATH, L"\\")) && SUCCEEDED(StringCchCatW(lpath, MAX_PATH, local))
            && GetFileAttributesW(lpath) != INVALID_FILE_ATTRIBUTES)
        {
            GetPrivateProfileStringW(L"Section", L"MsiProperties", L"", props, ARRAYSIZE(props), lentry);
            if (!wcspbrk(props, L"\"\r\n") &&
                SUCCEEDED(StringCchPrintfW(inst, cch, L"msiexec.exe /i \"%s\" /qn /norestart %s", lpath, props)))
            {
                LOGF(log, L"  local installer %s\n", lpath);
                /* the same package removes it: no registry lookup and no rapps, which would try to update its
                 * online database first and stop at an error box on a machine without network */
                if (SUCCEEDED(StringCchPrintfW(uninst, cch, L"msiexec.exe /x \"%s\" /qn /norestart", lpath)))
                    return S_OK;
            }
            StringCchPrintfW(inst, cch, L"\"%s\" /install /S \"%s\"", rapps, pkg);
        }
    }
    /* [Rapps] UninstallCmd= : the command line that removes the app, for an installer whose registered uninstall
     * command is not silent (rapps /uninstall starts that one as it is, and the maintenance dialog would wait for
     * a click). UninstallCmd.amd64 / UninstallCmd.x86 (the architecture of this build, as in the RAPPS entry's
     * [Section.amd64]) wins over UninstallCmd. Environment variables are expanded, as for the command provider. */
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
    /* [Rapps] UninstallName= : the installed app's display name. Uninstall then resolves it
     * from the registry, so it keeps working when the entry is no longer in the RAPPS DB. */
    GetPrivateProfileStringW(L"Rapps", L"UninstallName", L"", name, ARRAYSIZE(name), f->ManifestPath);
    if (name[0] && !wcspbrk(name, L"\"\r\n"))
        StringCchPrintfW(uninst, cch, L"\"%s\" /uninstall /S \"%s\"", rapps, name);
    else
        StringCchPrintfW(uninst, cch, L"\"%s\" /uninstall /S \"%s\"", rapps, pkg);
    return S_OK;
}

/* Free space the system volume needs before a [Rapps] install is attempted, as a multiple of the
 * package size ([Source] SizeBytes): the download (1x) plus the Windows Installer cached copy (1x)
 * plus the unpacked files and rollback data. Measured with PowerShell 7 (105 MB MSI): an 8 GB volume
 * with ~0.5 GB free fails inside msiexec, ~1.4 GB free installs and uses ~0.5 GB. The rapps/msiexec
 * failure itself is only a bare "exit code 1", so refuse early with a clear message instead. */
#define SW_DISK_FACTOR 6

/* S_OK: enough space (or the size is unknown); ERROR_DISK_FULL: not enough. */
static HRESULT CheckSoftwareDiskSpace(const FM_FEATURE *f, FILE *log, BOOL failedAlready)
{
    WCHAR sz[40], sys[MAX_PATH], root[4];
    ULARGE_INTEGER avail, total, freeAll;
    ULONGLONG pkg, need;
    PWSTR end;

    GetPrivateProfileStringW(L"Source", L"SizeBytes", L"", sz, ARRAYSIZE(sz), f->ManifestPath);
    if (!sz[0]) return S_OK;
    pkg = _wcstoui64(sz, &end, 10);
    if (!pkg || *end) return S_OK;
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

/* Download + install. Returns S_OK only if the installer exited 0; on success the
 * uninstall command line is recorded in the state key. */
static HRESULT SoftwareInstall(const FM_FEATURE *f, HKEY state, FILE *log)
{
    WCHAR inst[2048], uninst[2048];
    DWORD code;
    HRESULT hr;

    hr = BuildSoftwareCommands(f, inst, uninst, ARRAYSIZE(inst), log);
    if (FAILED(hr)) return hr;
    if (!_wcsicmp(f->Provider, L"rapps"))
    {
        WCHAR entry[MAX_PATH], pkg[128];
        hr = CheckSoftwareDiskSpace(f, log, FALSE);
        if (FAILED(hr)) return hr;
        if (RappsEntryPath(f, entry, MAX_PATH))
        {
            GetPrivateProfileStringW(L"Rapps", L"Pkg", L"", pkg, ARRAYSIZE(pkg), f->ManifestPath);
            if (!FmStageRappsEntry(entry, pkg, log))
                return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        }
    }
    LOGF(log, L"  software install via '%s' provider\n", f->Provider);
    if (!_wcsicmp(f->Provider, L"scoop"))
        FmScoopPrepareEnv();
    hr = RunAndWait(inst, SW_RUN_TIMEOUT_MS, &code, log);
    if (FAILED(hr)) return hr;
    if (code != 0)
    {
        LOGF(log, L"error: installer for '%s' failed (exit code %lu)\n", f->Id, code);
        if (!_wcsicmp(f->Provider, L"rapps") && FAILED(CheckSoftwareDiskSpace(f, log, TRUE)))
            return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
        SetLastMsg(L"The %s installer for '%s' failed (exit code %lu).\n\n%s",
                   f->Provider, f->Id, code, g_Tail);
        return HRESULT_FROM_WIN32(ERROR_INSTALL_FAILURE);
    }
    SetStateSz(state, L"Provider", f->Provider);
    SetStateSz(state, L"Uninstall", uninst);
    NotifyEnvironmentChanged();
    return S_OK;
}

/* Run the uninstall command recorded at install time. S_OK if there is none. */
static HRESULT SoftwareUninstall(const FM_FEATURE *f, HKEY state, FILE *log)
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
        if (f && (!_wcsicmp(f->Provider, L"scoop") || !_wcsicmp(f->Provider, L"rapps")))
        {
            WCHAR inst[2048];
            hr = BuildSoftwareCommands(f, inst, cmd, ARRAYSIZE(cmd), log);
            if (FAILED(hr)) return hr;
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
    hr = RunAndWait(cmd, SW_RUN_TIMEOUT_MS, &code, log);
    if (FAILED(hr)) return hr;
    NotifyEnvironmentChanged();
    if (code != 0)
    {
        LOGF(log, L"error: uninstaller failed (exit code %lu)\n", code);
        SetLastMsg(L"The uninstaller for '%s' failed (exit code %lu).\n\n%s", f ? f->Id : L"?", code, g_Tail);
        return HRESULT_FROM_WIN32(ERROR_INSTALL_FAILURE);
    }
    return S_OK;
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
    WCHAR *sect, *p;
    HRESULT hr = S_OK;

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
                      L"(provider '%s': rapps.exe or the staged installer is missing)\n", id, f.Provider);
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

    if (OpenStateKey(id, TRUE, KEY_READ | KEY_WRITE, &state) != ERROR_SUCCESS)
        return E_FAIL;

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

    /* payload files */
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
            hr = ApplyPayloadFile(payloadDir, eq + 1, sep + 1, state, log);
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
    return hr;
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
        for (p = undo; *p; p += wcslen(p) + 1)
            RevertRegUndo(p, log);
        HeapFree(GetProcessHeap(), 0, undo);
    }

    /* delete installed files */
    files = MultiSzRead(state, L"Files");
    if (files)
    {
        for (p = files; *p; p += wcslen(p) + 1)
        {
            LOGF(log, L"  remove file: %s\n", p);
            if (!DeleteFileW(p) && GetLastError() != ERROR_FILE_NOT_FOUND)
            {
                DWORD e = GetLastError();
                if (MoveFileExW(p, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
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
    baks = MultiSzRead(state, L"Backups");
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
                LOGF(log, L"  warn: restore failed (%lu)\n", GetLastError());
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
        LOGF(log, L"error: '%s' is a base component of the system and cannot be disabled or removed\n", id);
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
        if (SUCCEEDED(hr)) LOGF(log, L"all Scoop apps are up to date.\n");
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
