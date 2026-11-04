/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NitroOS shell defaults that follow the first-boot components: PowerShell 7 is the headline shell on the
 *              desktop and in the Start menu, Firefox is the browser entry and the default browser. Idempotent: it
 *              looks at what is installed and makes the shortcuts match, so it also puts the Command Prompt desktop
 *              shortcut back when pwsh is removed (and while it is not installed yet, which is the image's own state).
 *              Internet Explorer has no entry, as on Windows 11: iexplore.exe opens the default browser, and leftover
 *              shortcuts to it are removed (once, see RemoveIeLinksOnce).
 *              Nothing here removes a program: Command Prompt stays under Start > Windows System, iexplore stays.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#define COBJMACROS
#include "featmgr.h"
#include <shlobj.h>
#include <shlwapi.h>
#include <strsafe.h>

#define LOGF(log, ...) do { if (log) { fwprintf((log), __VA_ARGS__); fflush(log); } } while (0)

/* the names the image's shortcuts.inf uses; other languages only matter for the restore, the removal goes by target */
static const WCHAR NAME_CMD[]  = L"Command Prompt";
static const WCHAR NAME_PWSH[] = L"PowerShell";
static const WCHAR NAME_FF[]   = L"Firefox";
static const WCHAR NAME_WINSYS[] = L"Windows System";

static BOOL FileExists(LPCWSTR p)
{
    DWORD a = GetFileAttributesW(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

/* the Program Files folder from the shell (the registry), not from a caller's environment */
static BOOL ProgFile(LPCWSTR rel, LPWSTR out, DWORD cch)
{
    WCHAR pf[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, pf))) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch, L"%s\\%s", pf, rel));
}

static BOOL MakeLink(LPCWSTR lnk, LPCWSTR target, LPCWSTR workdir, LPCWSTR desc, FILE *log)
{
    IShellLinkW *sl = NULL;
    IPersistFile *pf = NULL;
    HRESULT hr;
    BOOL ok = FALSE;

    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&sl);
    if (FAILED(hr)) { LOGF(log, L"  shortcut: no IShellLink (0x%08lx)\n", (DWORD)hr); return FALSE; }
    IShellLinkW_SetPath(sl, target);
    IShellLinkW_SetIconLocation(sl, target, 0);
    if (workdir && workdir[0]) IShellLinkW_SetWorkingDirectory(sl, workdir);
    if (desc && desc[0]) IShellLinkW_SetDescription(sl, desc);
    hr = IShellLinkW_QueryInterface(sl, &IID_IPersistFile, (void **)&pf);
    if (SUCCEEDED(hr))
    {
        hr = IPersistFile_Save(pf, lnk, TRUE);
        ok = SUCCEEDED(hr);
        IPersistFile_Release(pf);
    }
    IShellLinkW_Release(sl);
    LOGF(log, L"  shortcut: %s -> %s %s\n", lnk, target, ok ? L"ok" : L"FAILED");
    return ok;
}

/* the target of a .lnk, expanded; empty when it cannot be read */
static BOOL LinkTarget(LPCWSTR lnk, LPWSTR out, DWORD cch, LPWSTR args, DWORD cchArgs)
{
    IShellLinkW *sl = NULL;
    IPersistFile *pf = NULL;
    WCHAR raw[MAX_PATH];
    BOOL ok = FALSE;

    out[0] = L'\0';
    args[0] = L'\0';
    if (FAILED(CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&sl))) return FALSE;
    if (SUCCEEDED(IShellLinkW_QueryInterface(sl, &IID_IPersistFile, (void **)&pf)))
    {
        if (SUCCEEDED(IPersistFile_Load(pf, lnk, STGM_READ)) &&
            SUCCEEDED(IShellLinkW_GetPath(sl, raw, MAX_PATH, NULL, 0)) && raw[0])
        {
            if (!ExpandEnvironmentStringsW(raw, out, cch)) StringCchCopyW(out, cch, raw);
            if (FAILED(IShellLinkW_GetArguments(sl, args, cchArgs))) args[0] = L'\0';
            ok = TRUE;
        }
        IPersistFile_Release(pf);
    }
    IShellLinkW_Release(sl);
    return ok;
}

/* the .lnk files of dir whose target's file name is exe; remove (del) or only count them */
static int g_DeleteFailures;   /* shortcuts LinksTo was asked to delete but could not (in use, access denied, unreadable while in use) */

static int LinksTo(LPCWSTR dir, LPCWSTR exe, BOOL del, FILE *log)
{
    WCHAR pat[MAX_PATH], path[MAX_PATH], tgt[MAX_PATH], args[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int n = 0;

    StringCchPrintfW(pat, ARRAYSIZE(pat), L"%s\\*.lnk", dir);
    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do
    {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\%s", dir, fd.cFileName);
        if (!LinkTarget(path, tgt, ARRAYSIZE(tgt), args, ARRAYSIZE(args)))
        {
            /* a shortcut held open without sharing cannot be read: when deleting, it may be one, so not done yet */
            if (del)
            {
                HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                       OPEN_EXISTING, 0, NULL);
                if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
                else if (GetLastError() == ERROR_SHARING_VIOLATION) g_DeleteFailures++;
            }
            continue;
        }
        if (_wcsicmp(PathFindFileNameW(tgt), exe)) continue;
        if (del && args[0]) continue;                /* a shortcut with arguments is the user's own, not the stock entry */
        n++;
        if (del)
        {
            BOOL ok = DeleteFileW(path);
            LOGF(log, L"  shortcut: removed %s %s\n", path, ok ? L"ok" : L"FAILED");
            if (ok) SHChangeNotify(SHCNE_DELETE, SHCNF_PATHW | SHCNF_FLUSH, path, NULL);   /* the open desktop drops the icon */
            else g_DeleteFailures++;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return n;
}

/* Three places hold the shortcuts: the all-users folder (where PowerShell and Firefox are put), the current user's folder,
 * and the Default User's folder (what setup's shortcuts.inf fills and what a new user's profile is copied from). */
#define NDIRS 3
typedef WCHAR DIRSET[NDIRS][MAX_PATH];

static BOOL GetDirSet(int csidlCommon, int csidlUser, DIRSET d)
{
    ZeroMemory(d, sizeof(DIRSET));
    if (FAILED(SHGetFolderPathW(NULL, csidlCommon | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, d[0]))) return FALSE;
    if (FAILED(SHGetFolderPathW(NULL, csidlUser | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, d[1]))) d[1][0] = L'\0';
    if (FAILED(SHGetFolderPathW(NULL, csidlUser, (HANDLE)-1, SHGFP_TYPE_DEFAULT, d[2]))) d[2][0] = L'\0';
    return TRUE;
}

static int LinksToIn(DIRSET d, LPCWSTR sub, LPCWSTR exe, BOOL del, FILE *log)
{
    int i, n = 0;
    WCHAR dir[MAX_PATH];
    for (i = 0; i < NDIRS; i++)
    {
        if (!d[i][0]) continue;
        if (sub) StringCchPrintfW(dir, ARRAYSIZE(dir), L"%s\\%s", d[i], sub);
        else StringCchCopyW(dir, ARRAYSIZE(dir), d[i]);
        n += LinksTo(dir, exe, del, log);
    }
    return n;
}

/*
 * Internet Explorer shortcuts left from an older image (no arguments, target iexplore.exe: the stock entry, which only
 * ever was at the top of Programs) are removed once: from the all-users and Default User folders once per machine,
 * from the user's own folders once per user. A plain IE shortcut someone makes afterwards is theirs and stays.
 * The flag is only set when every such shortcut went (or there was none): one that could not be deleted (in use)
 * is tried again on the next run.
 */
static const WCHAR KEY_SHELLDEFAULTS[] = L"SOFTWARE\\ReactOS\\Nitro\\Featmgr";
static const WCHAR VAL_IE_LINKS_REMOVED[] = L"IeShortcutsRemoved";

static BOOL IeLinksRemoved(HKEY root)
{
    DWORD v = 0, cb = sizeof(v), type;
    HKEY k;
    LONG rc;
    if (RegOpenKeyExW(root, KEY_SHELLDEFAULTS, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return FALSE;
    rc = RegQueryValueExW(k, VAL_IE_LINKS_REMOVED, NULL, &type, (BYTE *)&v, &cb);
    RegCloseKey(k);
    return rc == ERROR_SUCCESS && type == REG_DWORD && v;
}

static void SetIeLinksRemoved(HKEY root)
{
    DWORD v = 1;
    HKEY k;
    if (RegCreateKeyExW(root, KEY_SHELLDEFAULTS, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) != ERROR_SUCCESS) return;
    RegSetValueExW(k, VAL_IE_LINKS_REMOVED, 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
    RegCloseKey(k);
}

static void RemoveIeLinksOnce(DIRSET desk, DIRSET progs, FILE *log)
{
    g_DeleteFailures = 0;
    if (!IeLinksRemoved(HKEY_LOCAL_MACHINE))
    {
        if (desk[0][0]) LinksTo(desk[0], L"iexplore.exe", TRUE, log);
        if (progs[0][0]) LinksTo(progs[0], L"iexplore.exe", TRUE, log);
        if (desk[2][0]) LinksTo(desk[2], L"iexplore.exe", TRUE, log);
        if (progs[2][0]) LinksTo(progs[2], L"iexplore.exe", TRUE, log);
        if (!g_DeleteFailures) SetIeLinksRemoved(HKEY_LOCAL_MACHINE);
    }
    if (!IeLinksRemoved(HKEY_CURRENT_USER))
    {
        g_DeleteFailures = 0;
        if (desk[1][0]) LinksTo(desk[1], L"iexplore.exe", TRUE, log);
        if (progs[1][0]) LinksTo(progs[1], L"iexplore.exe", TRUE, log);
        if (!g_DeleteFailures) SetIeLinksRemoved(HKEY_CURRENT_USER);
    }
}

static void Refresh(DIRSET d)
{
    int i;
    for (i = 0; i < NDIRS; i++)
        if (d[i][0]) SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSH, d[i], NULL);
}

static void EnsureDir(LPCWSTR dir)
{
    CreateDirectoryW(dir, NULL);
}

/* Firefox enterprise policies, written to <Firefox dir>\distribution\policies.json.
 *
 * Full set (the x64 install featmgr itself puts there): never ask to be the default browser, no first-run / what's-new
 * pages, no about:welcome onboarding (its "make default" step), no profile import wizard. The Mozilla Terms of Use / privacy
 * notice consent (policy SkipTermsOfUse) is NOT skipped: accepting it is the user's own act.
 *
 * Preferences policy (every Firefox install found: x64, x86 in Program Files (x86), Scoop): media.wmf.media-engine.enabled
 * = 0 with Status "default" (a default only: the user can change it in about:config, or with their own user.js). The
 * pref is an INTEGER pref in Firefox (0 off, 2 on is the default): a boolean false in the policy is silently not applied
 * ("Not fully applied" in about:policies), so the value must be the number 0.
 * Why: NitroOS has no H.264 Media Foundation decoder, so Firefox's default decoder order ends at the "Utility MF Media
 * Engine CDM", which claims H.264 and then fails to play it; with the pref off the bundled OpenH264 plugin plays mp4.
 * TODO(MF-h264-mft): delete this default once an H.264 decoder MFT exists and the default path works.
 *
 * An existing policies.json is never replaced. The full set is only written into a new file. The Preferences entry is
 * MERGED into an existing file as text (strict JSON: the file is scanned, one member is spliced in, everything else
 * stays byte for byte); an administrator's own value for the pref, or a file that is not a JSON object with an object
 * "policies" (and an object "Preferences", when there is one), is left alone. The distribution folder is not Firefox's
 * own, so a Firefox update (MSI upgrade or the in-app updater) leaves it; a featmgr repair (/shell-defaults) puts the
 * entry back if somebody removed it.
 */
#define FF_PREF_KEY   "media.wmf.media-engine.enabled"
#define FF_PREF_ENTRY "\"" FF_PREF_KEY "\": { \"Value\": 0, \"Status\": \"default\" }"

/* s[*i] == '"': advance past the string (FALSE: unterminated) */
static BOOL JsSkipString(const char *s, size_t n, size_t *i)
{
    (*i)++;
    while (*i < n)
    {
        if (s[*i] == '\\') { *i += 2; continue; }
        if (s[*i] == '"') { (*i)++; return TRUE; }
        (*i)++;
    }
    return FALSE;
}

static void JsBlank(const char *s, size_t n, size_t *i)
{
    while (*i < n && (s[*i] == ' ' || s[*i] == '\t' || s[*i] == '\r' || s[*i] == '\n')) (*i)++;
}

/* skip one value starting at s[*i] (string, object, array, or a bare literal) */
static BOOL JsSkipValue(const char *s, size_t n, size_t *i)
{
    int depth = 0;
    JsBlank(s, n, i);
    if (*i >= n) return FALSE;
    if (s[*i] == '"') return JsSkipString(s, n, i);
    if (s[*i] != '{' && s[*i] != '[')
    {
        size_t b = *i;
        while (*i < n && !strchr(",}] \t\r\n", s[*i])) (*i)++;
        return *i > b;
    }
    for (;;)
    {
        if (*i >= n) return FALSE;
        if (s[*i] == '"') { if (!JsSkipString(s, n, i)) return FALSE; continue; }
        if (s[*i] == '{' || s[*i] == '[') depth++;
        else if (s[*i] == '}' || s[*i] == ']') { depth--; if (depth == 0) { (*i)++; return TRUE; } }
        (*i)++;
    }
}

typedef struct { BOOL Found; size_t ValPos; size_t Close; size_t LastEnd; BOOL Empty; } JS_OBJ;

/* s[start] == '{': find member `key` (raw compare); fills where its value starts, where the object closes and where its
 * last member's value ends. FALSE on anything that is not well-formed enough. */
static BOOL JsObject(const char *s, size_t n, size_t start, const char *key, JS_OBJ *o)
{
    size_t i = start + 1, klen = strlen(key);
    memset(o, 0, sizeof(*o));
    o->Empty = TRUE;
    for (;;)
    {
        size_t b, kb;
        JsBlank(s, n, &i);
        if (i >= n) return FALSE;
        if (s[i] == '}') { o->Close = i; return TRUE; }
        if (s[i] != '"') return FALSE;
        kb = i;
        if (!JsSkipString(s, n, &i)) return FALSE;
        b = i;
        JsBlank(s, n, &i);
        if (i >= n || s[i] != ':') return FALSE;
        i++;
        JsBlank(s, n, &i);
        if (!o->Found && b - kb - 2 == klen && !memcmp(s + kb + 1, key, klen)) { o->Found = TRUE; o->ValPos = i; }
        if (!JsSkipValue(s, n, &i)) return FALSE;
        o->Empty = FALSE;
        o->LastEnd = i;
        JsBlank(s, n, &i);
        if (i < n && s[i] == ',') i++;
        else if (i >= n || s[i] != '}') return FALSE;
    }
}

/* a copy of in[0..n) with `member` added to the object o as its last member: `, member` after the last value
 * (or alone into an empty object) */
static char *JsAddMember(const char *in, size_t n, const JS_OBJ *o, const char *member, size_t *outLen)
{
    size_t at = o->Empty ? o->Close : o->LastEnd, ml = strlen(member);
    const char *pre = o->Empty ? " " : ", ", *post = o->Empty ? " " : "";
    size_t pl = strlen(pre), tl = strlen(post);
    char *r = (char *)HeapAlloc(GetProcessHeap(), 0, n + ml + pl + tl + 1);
    if (!r) return NULL;
    memcpy(r, in, at);
    memcpy(r + at, pre, pl);
    memcpy(r + at + pl, member, ml);
    memcpy(r + at + pl + ml, post, tl);
    memcpy(r + at + pl + ml + tl, in + at, n - at);
    *outLen = n + pl + ml + tl;
    return r;
}

typedef enum { PP_MERGED = 0, PP_PRESENT, PP_BAD, PP_NOMEM } PP_RESULT;

/* put the Preferences entry into the policies.json text in[0..n); on PP_MERGED *out is a HeapAlloc'd copy */
static PP_RESULT MergeFirefoxPref(const char *in, size_t n, char **out, size_t *outLen)
{
    JS_OBJ root, pol, prefs;
    size_t i = 0;
    char *t, *t2;
    size_t tl, t2l;

    *out = NULL;
    JsBlank(in, n, &i);
    if (i >= n || in[i] != '{' || !JsObject(in, n, i, "policies", &root)) return PP_BAD;
    {   /* nothing but blanks after the document */
        size_t e = root.Close + 1;
        JsBlank(in, n, &e);
        if (e < n) return PP_BAD;
    }
    if (!root.Found)
    {
        t = JsAddMember(in, n, &root, "\"policies\": { \"Preferences\": { " FF_PREF_ENTRY " } }", &tl);
        if (!t) return PP_NOMEM;
        *out = t; *outLen = tl;
        return PP_MERGED;
    }
    if (in[root.ValPos] != '{' || !JsObject(in, n, root.ValPos, "Preferences", &pol)) return PP_BAD;
    if (!pol.Found)
    {
        t = JsAddMember(in, n, &pol, "\"Preferences\": { " FF_PREF_ENTRY " }", &tl);
        if (!t) return PP_NOMEM;
        *out = t; *outLen = tl;
        return PP_MERGED;
    }
    if (in[pol.ValPos] != '{' || !JsObject(in, n, pol.ValPos, FF_PREF_KEY, &prefs)) return PP_BAD;
    if (prefs.Found) return PP_PRESENT;
    t2 = JsAddMember(in, n, &prefs, FF_PREF_ENTRY, &t2l);
    if (!t2) return PP_NOMEM;
    *out = t2; *outLen = t2l;
    return PP_MERGED;
}

static BOOL ReplaceFileText(LPCWSTR file, const char *data, size_t len)
{
    WCHAR tmp[MAX_PATH];
    HANDLE h;
    DWORD w;
    BOOL ok;

    StringCchPrintfW(tmp, ARRAYSIZE(tmp), L"%s.nitro-tmp", file);
    h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = WriteFile(h, data, (DWORD)len, &w, NULL) && w == len;
    CloseHandle(h);
    if (ok) ok = MoveFileExW(tmp, file, MOVEFILE_REPLACE_EXISTING);
    if (!ok) DeleteFileW(tmp);
    return ok;
}

/* ffDir = the Firefox install (or Scoop app "current") folder; only acted on when firefox.exe is in it. full = also the
 * default-browser / first-run policies when the file is new. */
static void FirefoxPolicies(LPCWSTR ffDir, BOOL full, FILE *log)
{
    static const char jsonFull[] =
        "{\r\n"
        "  \"policies\": {\r\n"
        "    \"DontCheckDefaultBrowser\": true,\r\n"
        "    \"DisableDefaultBrowserAgent\": true,\r\n"
        "    \"OverrideFirstRunPage\": \"\",\r\n"
        "    \"OverridePostUpdatePage\": \"\",\r\n"
        "    \"DisableProfileImport\": true,\r\n"
        "    \"UserMessaging\": { \"SkipOnboarding\": true },\r\n"
        "    \"Preferences\": {\r\n"
        "      " FF_PREF_ENTRY "\r\n"
        "    }\r\n"
        "  }\r\n"
        "}\r\n";
    static const char jsonPref[] =
        "{\r\n"
        "  \"policies\": {\r\n"
        "    \"Preferences\": {\r\n"
        "      " FF_PREF_ENTRY "\r\n"
        "    }\r\n"
        "  }\r\n"
        "}\r\n";
    WCHAR exe[MAX_PATH], dir[MAX_PATH], file[MAX_PATH];
    HANDLE h;
    DWORD w, size, attr;
    char *buf, *edited = NULL;
    size_t skip = 0, elen = 0;
    PP_RESULT r;

    StringCchPrintfW(exe, ARRAYSIZE(exe), L"%s\\firefox.exe", ffDir);
    if (!FileExists(exe)) return;
    StringCchPrintfW(dir, ARRAYSIZE(dir), L"%s\\distribution", ffDir);
    StringCchPrintfW(file, ARRAYSIZE(file), L"%s\\policies.json", dir);
    attr = GetFileAttributesW(file);
    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        const char *j = full ? jsonFull : jsonPref;
        EnsureDir(dir);
        h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) { LOGF(log, L"  firefox: cannot write %s (error %lu)\n", file, GetLastError()); return; }
        WriteFile(h, j, (DWORD)strlen(j), &w, NULL);
        CloseHandle(h);
        LOGF(log, L"  firefox: wrote %s\n", file);
        return;
    }
    if (attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) { LOGF(log, L"  firefox: %s is not a plain file, left alone\n", file); return; }
    h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { LOGF(log, L"  firefox: cannot read %s (error %lu), left alone\n", file, GetLastError()); return; }
    size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size > 4 * 1024 * 1024) { CloseHandle(h); LOGF(log, L"  firefox: %s is too large, left alone\n", file); return; }
    buf = (char *)HeapAlloc(GetProcessHeap(), 0, size + 1);
    if (!buf || !ReadFile(h, buf, size, &w, NULL) || w != size)
    {
        CloseHandle(h);
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        LOGF(log, L"  firefox: cannot read %s, left alone\n", file);
        return;
    }
    CloseHandle(h);
    if (size >= 3 && (BYTE)buf[0] == 0xEF && (BYTE)buf[1] == 0xBB && (BYTE)buf[2] == 0xBF) skip = 3;
    r = MergeFirefoxPref(buf + skip, size - skip, &edited, &elen);
    if (r == PP_PRESENT)
        LOGF(log, L"  firefox: %s keeps its own %S\n", file, FF_PREF_KEY);
    else if (r == PP_MERGED)
    {
        char *all = (char *)HeapAlloc(GetProcessHeap(), 0, skip + elen);
        if (all)
        {
            memcpy(all, buf, skip);
            memcpy(all + skip, edited, elen);
            if (ReplaceFileText(file, all, skip + elen))
                LOGF(log, L"  firefox: added %S (default 0) to the existing %s\n", FF_PREF_KEY, file);
            else
                LOGF(log, L"  firefox: cannot update %s (error %lu), left alone\n", file, GetLastError());
            HeapFree(GetProcessHeap(), 0, all);
        }
    }
    else
        LOGF(log, L"  firefox: %s is not a JSON object with a policies object, left alone (add %S by hand)\n", file, FF_PREF_KEY);
    if (edited) HeapFree(GetProcessHeap(), 0, edited);
    HeapFree(GetProcessHeap(), 0, buf);
}

/* x64: Program Files; x86: Program Files (x86) (a different folder on a 64-bit system only) */
static void FirefoxPoliciesAll(FILE *log)
{
    WCHAR p64[MAX_PATH], p86[MAX_PATH], d[MAX_PATH];
    BOOL have64 = SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, p64));
    BOOL have86 = SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILESX86, NULL, SHGFP_TYPE_CURRENT, p86));

    if (have64)
    {
        StringCchPrintfW(d, ARRAYSIZE(d), L"%s\\Mozilla Firefox", p64);
        FirefoxPolicies(d, TRUE, log);
    }
    if (have86 && (!have64 || _wcsicmp(p86, p64)))
    {
        StringCchPrintfW(d, ARRAYSIZE(d), L"%s\\Mozilla Firefox", p86);
        FirefoxPolicies(d, FALSE, log);
    }
}

/* Scoop's firefox apps (called from scoopdefaults.c) */
void FmFirefoxPoliciesIn(LPCWSTR ffDir, FILE *log)
{
    FirefoxPolicies(ffDir, FALSE, log);
}

/* bchooser /installfirefox with Firefox on disk = "adopt it": the machine-wide web associations (http, https, .htm,
 * .html, StartMenuInternet) and the UserChoice of the current user, as Windows' Default apps does it. */
static void RunBchooser(LPCWSTR args, FILE *log)
{
    WCHAR sys[MAX_PATH], cmd[MAX_PATH + 64];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = (DWORD)-1;

    if (!GetSystemDirectoryW(sys, MAX_PATH)) return;
    StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"\"%s\\bchooser.exe\" %s", sys, args);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        LOGF(log, L"  default browser: cannot start %s (error %lu)\n", cmd, GetLastError());
        return;
    }
    WaitForSingleObject(pi.hProcess, 120000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    LOGF(log, L"  default browser: %s -> exit code %lu\n", args, code);
}

void FmShellDefaults(DWORD flags, FILE *log)
{
    DIRSET desk, progs;
    WCHAR winsys[MAX_PATH], pwsh[MAX_PATH], ff[MAX_PATH], cmd[MAX_PATH];
    WCHAR lnk[MAX_PATH], sys[MAX_PATH];
    BOOL havePwsh, haveFf, comInit;

    if (!GetDirSet(CSIDL_COMMON_DESKTOPDIRECTORY, CSIDL_DESKTOPDIRECTORY, desk) ||
        !GetDirSet(CSIDL_COMMON_PROGRAMS, CSIDL_PROGRAMS, progs))
    {
        LOGF(log, L"shell defaults: no all-users Desktop / Start menu folder\n");
        return;
    }
    if (!GetSystemDirectoryW(sys, MAX_PATH)) return;
    StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"%s\\cmd.exe", sys);
    if ((flags & FM_SHELL_FORGET_BROWSER) && ProgFile(L"Mozilla Firefox\\firefox.exe", ff, ARRAYSIZE(ff)))
    {
        /* Mozilla's uninstall\helper.exe /S returns while its copy is still removing the files: wait for firefox.exe to go */
        DWORD t0 = GetTickCount();
        while (FileExists(ff) && GetTickCount() - t0 < 90000) Sleep(1000);
    }
    havePwsh = ProgFile(L"PowerShell\\7\\pwsh.exe", pwsh, ARRAYSIZE(pwsh)) && FileExists(pwsh);
    haveFf = ProgFile(L"Mozilla Firefox\\firefox.exe", ff, ARRAYSIZE(ff)) && FileExists(ff);
    StringCchPrintfW(winsys, ARRAYSIZE(winsys), L"%s\\%s", progs[0], NAME_WINSYS);

    LOGF(log, L"shell defaults: pwsh %s, firefox %s\n", havePwsh ? L"installed" : L"absent", haveFf ? L"installed" : L"absent");
    comInit = SUCCEEDED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED));

    /* Command Prompt always has its place under Start > Windows System, whatever the desktop shows */
    if (!LinksToIn(progs, NAME_WINSYS, L"cmd.exe", FALSE, NULL))
    {
        StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", winsys, NAME_CMD);
        EnsureDir(winsys);
        MakeLink(lnk, cmd, L"%HOMEDRIVE%%HOMEPATH%", L"Opens a command prompt window", log);
    }

    /* the headline shell: PowerShell 7 on the desktop and in the Start menu, else Command Prompt */
    if (havePwsh)
    {
        StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", desk[0], NAME_PWSH);
        if (!LinksToIn(desk, NULL, L"pwsh.exe", FALSE, NULL)) MakeLink(lnk, pwsh, L"%HOMEDRIVE%%HOMEPATH%", L"PowerShell 7", log);
        StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", progs[0], NAME_PWSH);
        if (!FileExists(lnk)) MakeLink(lnk, pwsh, L"%HOMEDRIVE%%HOMEPATH%", L"PowerShell 7", log);
        LinksToIn(desk, NULL, L"cmd.exe", TRUE, log);
    }
    else
    {
        StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", desk[0], NAME_PWSH);
        if (DeleteFileW(lnk)) SHChangeNotify(SHCNE_DELETE, SHCNF_PATHW | SHCNF_FLUSH, lnk, NULL);
        StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", progs[0], NAME_PWSH);
        if (DeleteFileW(lnk)) SHChangeNotify(SHCNE_DELETE, SHCNF_PATHW | SHCNF_FLUSH, lnk, NULL);
        if (!LinksToIn(desk, NULL, L"cmd.exe", FALSE, NULL))
        {
            StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", desk[0], NAME_CMD);
            MakeLink(lnk, cmd, L"%HOMEDRIVE%%HOMEPATH%", L"Opens a command prompt window", log);
        }
    }

    /* the browser: Firefox has the entry. Internet Explorer has none in either case, as on Windows 11 (iexplore.exe
     * stays installed and opens the default browser): shortcuts to it left from an older image are removed, once. */
    RemoveIeLinksOnce(desk, progs, log);
    FirefoxPoliciesAll(log);      /* whichever Firefox installs are there (the x86 one has no shortcut here) */
    if (haveFf)
    {
        StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", desk[0], NAME_FF);
        if (!LinksToIn(desk, NULL, L"firefox.exe", FALSE, NULL)) MakeLink(lnk, ff, NULL, L"Mozilla Firefox", log);
        StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", progs[0], NAME_FF);
        if (!LinksToIn(progs, NULL, L"firefox.exe", FALSE, NULL)) MakeLink(lnk, ff, NULL, L"Mozilla Firefox", log);
        if (flags & FM_SHELL_ADOPT_BROWSER) RunBchooser(L"/installfirefox", log);
    }
    else
    {
        LinksToIn(desk, NULL, L"firefox.exe", TRUE, log);
        LinksToIn(progs, NULL, L"firefox.exe", TRUE, log);
        if (flags & FM_SHELL_FORGET_BROWSER) RunBchooser(L"/set IEXPLORE.EXE", log);
    }

    Refresh(desk);
    Refresh(progs);
    if (comInit) CoUninitialize();
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSH, NULL, NULL);
}
