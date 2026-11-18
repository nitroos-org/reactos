/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     featmgr /zip-install <id> <zip> and /zip-uninstall <id>: the installer of a component whose download is a
 *              zip archive of programs (OpenSSH client). Run by the engine as a child process, like /nat-install.
 *
 *              The component's section in components.ini names:
 *                ZipDir    the install folder: a folder of its own directly below System32 or Program Files
 *                ZipFiles  the files to install, "a.exe|b.dll|..." (names inside the archive's one top folder);
 *                          every one must be in the archive, nothing else is unpacked
 *                ZipPath   1 = put ZipDir on the machine PATH (HKLM ...\Session Manager\Environment)
 *              Install never replaces a file: a target that exists makes it fail before anything is written. What it
 *              wrote (folder, files, PATH text) is recorded in HKLM\SOFTWARE\ReactOS\Nitro\Featmgr\Zip\<id>, and
 *              /zip-uninstall removes exactly that and nothing else. A failed install removes what it had written.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "featmgr.h"
#include <shlwapi.h>
#include <shlobj.h>
#include <strsafe.h>

#include "minizip/ioapi.h"
#include "minizip/iowin32.h"
#include "minizip/unzip.h"

#define ZIP_RECORD_KEY L"SOFTWARE\\ReactOS\\Nitro\\Featmgr\\Zip"
#define ZIP_ENV_KEY    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
#define ZIP_MAX_FILES  32
#define ZIP_PATH_CCH   32768

static WCHAR g_comps[MAX_PATH];

static void Rk(LPCWSTR id, LPCWSTR key, LPWSTR out, DWORD cch)
{
    GetPrivateProfileStringW(id, key, L"", out, cch, g_comps);
}

/* a single folder name: no separators, no drive, no stream, not a DOS device, not "." / ".." */
static BOOL LeafOk(LPCWSTR leaf)
{
    if (!leaf[0] || !wcscmp(leaf, L".") || !wcscmp(leaf, L"..")) return FALSE;
    if (wcspbrk(leaf, L"\\/:*?\"<>|")) return FALSE;
    if (leaf[wcslen(leaf) - 1] == L' ' || leaf[wcslen(leaf) - 1] == L'.') return FALSE;
    return !FmHasDeviceName(leaf);
}

/* dir (expanded) must be a folder of its own directly below System32 or Program Files; canon receives it */
static BOOL InstallDirOk(LPCWSTR dir, LPWSTR canon)
{
    WCHAR parent[MAX_PATH], sys[MAX_PATH], pf[MAX_PATH], leaf[MAX_PATH];
    LPCWSTR l;

    if (!FmCanonPath(dir, canon, MAX_PATH)) return FALSE;
    StringCchCopyW(parent, MAX_PATH, canon);
    PathRemoveFileSpecW(parent);
    l = PathFindFileNameW(canon);
    StringCchCopyW(leaf, MAX_PATH, l);
    if (!LeafOk(leaf)) return FALSE;
    if (!GetSystemDirectoryW(sys, MAX_PATH)) return FALSE;
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, 0, pf))) pf[0] = L'\0';
    return !_wcsicmp(parent, sys) || (pf[0] && !_wcsicmp(parent, pf));
}

static BOOL IsReparse(LPCWSTR path)
{
    DWORD a = GetFileAttributesW(path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT);
}

/* ---- the machine PATH --------------------------------------------------------------------------------------------- */

static BOOL SamePathEntry(LPCWSTR a, LPCWSTR b)
{
    WCHAR ea[MAX_PATH * 2], eb[MAX_PATH * 2];
    size_t n;
    if (!ExpandEnvironmentStringsW(a, ea, ARRAYSIZE(ea)) || !ExpandEnvironmentStringsW(b, eb, ARRAYSIZE(eb))) return FALSE;
    for (n = wcslen(ea); n > 3 && ea[n - 1] == L'\\'; ) ea[--n] = L'\0';
    for (n = wcslen(eb); n > 3 && eb[n - 1] == L'\\'; ) eb[--n] = L'\0';
    return !_wcsicmp(ea, eb);
}

/* Read the machine PATH into *buf (ZIP_PATH_CCH wide chars, caller frees). */
static BOOL ReadMachinePath(HKEY k, WCHAR *buf, DWORD *type)
{
    DWORD cb = (ZIP_PATH_CCH - 2) * sizeof(WCHAR);
    LONG r = RegQueryValueExW(k, L"Path", NULL, type, (LPBYTE)buf, &cb);
    if (r == ERROR_FILE_NOT_FOUND) { buf[0] = L'\0'; *type = REG_EXPAND_SZ; return TRUE; }
    if (r != ERROR_SUCCESS || (*type != REG_SZ && *type != REG_EXPAND_SZ)) return FALSE;
    buf[cb / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static BOOL WriteMachinePath(HKEY k, const WCHAR *buf, DWORD type)
{
    return RegSetValueExW(k, L"Path", 0, type, (const BYTE *)buf, (DWORD)((wcslen(buf) + 1) * sizeof(WCHAR))) == ERROR_SUCCESS;
}

/* Add entry (as the catalog gives it, e.g. %SystemRoot%\System32\OpenSSH) unless a PATH entry already names that folder.
 * *added = 1 when the PATH changed; the exact text appended is returned in text. */
static BOOL PathAdd(LPCWSTR entry, DWORD *added, LPWSTR text, DWORD cchText)
{
    HKEY k;
    WCHAR *buf, *tok, *ctx = NULL, *copy;
    DWORD type;
    BOOL ok = FALSE, have = FALSE;
    size_t n;

    *added = 0;
    text[0] = L'\0';
    buf = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, ZIP_PATH_CCH * 2 * sizeof(WCHAR));
    if (!buf) return FALSE;
    copy = buf + ZIP_PATH_CCH;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ZIP_ENV_KEY, 0, KEY_READ | KEY_WRITE, &k) != ERROR_SUCCESS) goto out;
    if (!ReadMachinePath(k, buf, &type)) goto out2;
    StringCchCopyW(copy, ZIP_PATH_CCH, buf);
    for (tok = wcstok_s(copy, L";", &ctx); tok; tok = wcstok_s(NULL, L";", &ctx))
        if (tok[0] && SamePathEntry(tok, entry)) have = TRUE;
    if (have) { ok = TRUE; goto out2; }
    n = wcslen(buf);
    if (n + wcslen(entry) + 4 >= ZIP_PATH_CCH) goto out2;
    {
        WCHAR add[MAX_PATH * 2];
        /* a REG_EXPAND_SZ PATH keeps the variable form (as the Windows default entries do); a REG_SZ one gets the plain path */
        if (type == REG_EXPAND_SZ) StringCchCopyW(add, ARRAYSIZE(add), entry);
        else ExpandEnvironmentStringsW(entry, add, ARRAYSIZE(add));
        if (n && buf[n - 1] != L';') { buf[n++] = L';'; buf[n] = L'\0'; }
        StringCchCatW(buf, ZIP_PATH_CCH, add);
        StringCchCopyW(text, cchText, add);
    }
    if (!WriteMachinePath(k, buf, type)) goto out2;
    *added = 1;
    ok = TRUE;
out2:
    RegCloseKey(k);
out:
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

/* Remove the first PATH entry that is exactly text (as appended by PathAdd); the other entries stay as they are. */
static BOOL PathRemove(LPCWSTR text)
{
    HKEY k;
    WCHAR *buf, *out, *p, *e;
    DWORD type;
    BOOL ok = FALSE, done = FALSE;
    size_t m = wcslen(text);

    buf = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, ZIP_PATH_CCH * 2 * sizeof(WCHAR));
    if (!buf) return FALSE;
    out = buf + ZIP_PATH_CCH;
    out[0] = L'\0';
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ZIP_ENV_KEY, 0, KEY_READ | KEY_WRITE, &k) != ERROR_SUCCESS) goto out;
    if (!ReadMachinePath(k, buf, &type)) goto out2;
    for (p = buf; ; p = e + 1)
    {
        size_t len;
        e = wcschr(p, L';');
        len = e ? (size_t)(e - p) : wcslen(p);
        if (!done && len == m && !_wcsnicmp(p, text, m)) done = TRUE;
        else
        {
            if (wcslen(out) + len + 2 >= ZIP_PATH_CCH) goto out2;
            if (out[0]) StringCchCatW(out, ZIP_PATH_CCH, L";");
            StringCchCatNW(out, ZIP_PATH_CCH, p, len);
        }
        if (!e) break;
    }
    ok = !done || WriteMachinePath(k, out, type);      /* not there any more: nothing to do */
out2:
    RegCloseKey(k);
out:
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

static void NotifyEnvironment(void)
{
    DWORD_PTR res;
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG | SMTO_NORMAL, 3000, &res);
}

/* ---- install ------------------------------------------------------------------------------------------------------ */

static WCHAR g_made[ZIP_MAX_FILES][MAX_PATH];     /* files written so far (for the rollback) */
static int g_nmade;
static WCHAR g_dir[MAX_PATH];
static BOOL g_dirMade;
static DWORD g_pathAdded;
static WCHAR g_pathText[MAX_PATH * 2];

static void Rollback(void)
{
    int i;
    for (i = 0; i < g_nmade; i++) DeleteFileW(g_made[i]);
    g_nmade = 0;
    if (g_dirMade) RemoveDirectoryW(g_dir);
    if (g_pathAdded) { PathRemove(g_pathText); g_pathAdded = 0; NotifyEnvironment(); }
}

static int Fail(LPCWSTR what, DWORD err)
{
    wprintf(L"error: %s (%lu)\n", what, err);
    Rollback();
    return err ? (int)err : 1;
}

/* the file name of an archive entry "<top>/<name>" (exactly one folder level); NULL for anything else */
static LPCWSTR EntryLeaf(WCHAR *name)
{
    WCHAR *s;
    if (!FmSafeTreeName(name)) return NULL;
    s = wcschr(name, L'\\');
    if (!s || !s[1] || wcschr(s + 1, L'\\')) return NULL;
    return s + 1;
}

static BOOL SplitList(LPWSTR list, WCHAR **items, int max, int *n)
{
    WCHAR *tok, *ctx = NULL;
    *n = 0;
    for (tok = wcstok_s(list, L"|", &ctx); tok; tok = wcstok_s(NULL, L"|", &ctx))
    {
        if (*n >= max || !LeafOk(tok)) return FALSE;
        items[(*n)++] = tok;
    }
    return *n > 0;
}

static int ZipInstall(LPCWSTR id, LPCWSTR archive)
{
    WCHAR dirRaw[MAX_PATH], files[1024], pathFlag[8], *want[ZIP_MAX_FILES], expanded[MAX_PATH * 2];
    BOOL got[ZIP_MAX_FILES] = { 0 };
    int nwant, i, zerr, found = 0;
    zlib_filefunc64_def zff;
    unzFile hz;
    HKEY rec = NULL;
    DWORD disp;

    Rk(id, L"ZipDir", dirRaw, ARRAYSIZE(dirRaw));
    Rk(id, L"ZipFiles", files, ARRAYSIZE(files));
    Rk(id, L"ZipPath", pathFlag, ARRAYSIZE(pathFlag));
    if (!dirRaw[0] || !files[0]) return Fail(L"the component list has no ZipDir / ZipFiles for this entry", ERROR_BAD_CONFIGURATION);
    if (!ExpandEnvironmentStringsW(dirRaw, expanded, ARRAYSIZE(expanded)) || wcschr(expanded, L'%'))
        return Fail(L"ZipDir names an unknown variable", ERROR_BAD_PATHNAME);
    if (!InstallDirOk(expanded, g_dir))
        return Fail(L"ZipDir is not a folder of its own directly below System32 or Program Files", ERROR_BAD_PATHNAME);
    if (!SplitList(files, want, ZIP_MAX_FILES, &nwant)) return Fail(L"ZipFiles has an unusable name", ERROR_BAD_PATHNAME);

    /* nothing is replaced: a target that is there stops the install before any file is written */
    if (IsReparse(g_dir)) return Fail(L"the install folder is a link", ERROR_ACCESS_DENIED);
    for (i = 0; i < nwant; i++)
    {
        WCHAR t[MAX_PATH];
        StringCchPrintfW(t, MAX_PATH, L"%s\\%s", g_dir, want[i]);
        if (GetFileAttributesW(t) != INVALID_FILE_ATTRIBUTES)
        {
            wprintf(L"error: %s already exists; it is not replaced (remove it first)\n", t);
            return ERROR_FILE_EXISTS;
        }
    }

    fill_win32_filefunc64W(&zff);
    hz = unzOpen2_64(archive, &zff);
    if (!hz) return Fail(L"the download is not a zip archive", ERROR_BAD_FORMAT);

    if (GetFileAttributesW(g_dir) == INVALID_FILE_ATTRIBUTES)
    {
        if (!CreateDirectoryW(g_dir, NULL)) { unzClose(hz); return Fail(L"cannot create the install folder", GetLastError()); }
        g_dirMade = TRUE;
        if (IsReparse(g_dir)) { unzClose(hz); return Fail(L"the install folder is a link", ERROR_ACCESS_DENIED); }
    }

    for (zerr = unzGoToFirstFile(hz); zerr == UNZ_OK; zerr = unzGoToNextFile(hz))
    {
        unz_file_info64 fi;
        char narrow[1024];
        WCHAR name[MAX_PATH], full[MAX_PATH];
        LPCWSTR leaf;
        HANDLE hf;
        static BYTE buf[64 * 1024];
        int idx = -1, r, cerr;
        UINT cp;

        if (unzGetCurrentFileInfo64(hz, &fi, narrow, sizeof(narrow), NULL, 0, NULL, 0) != UNZ_OK) { unzClose(hz); return Fail(L"the archive is damaged", ERROR_BAD_FORMAT); }
        if (fi.size_filename >= sizeof(narrow)) continue;
        cp = (fi.flag & (1 << 11)) ? CP_UTF8 : 1252;
        if (MultiByteToWideChar(cp, 0, narrow, -1, name, MAX_PATH) <= 0) continue;
        leaf = EntryLeaf(name);
        if (!leaf) continue;
        for (i = 0; i < nwant; i++)
            if (!got[i] && !_wcsicmp(leaf, want[i])) { idx = i; break; }
        if (idx < 0) continue;
        StringCchPrintfW(full, MAX_PATH, L"%s\\%s", g_dir, want[idx]);
        if (unzOpenCurrentFile(hz) != UNZ_OK) { unzClose(hz); return Fail(L"cannot read the archive", ERROR_BAD_FORMAT); }
        hf = CreateFileW(full, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf == INVALID_HANDLE_VALUE)
        {
            DWORD e = GetLastError();
            unzCloseCurrentFile(hz);
            unzClose(hz);
            return Fail(L"cannot create a file", e);
        }
        StringCchCopyW(g_made[g_nmade++], MAX_PATH, full);
        for (;;)
        {
            DWORD w;
            r = unzReadCurrentFile(hz, buf, sizeof(buf));
            if (r <= 0) break;
            if (!WriteFile(hf, buf, r, &w, NULL) || w != (DWORD)r) { r = -1; break; }
        }
        CloseHandle(hf);
        cerr = unzCloseCurrentFile(hz);
        if (r < 0 || cerr != UNZ_OK) { unzClose(hz); return Fail(L"cannot unpack a file (damaged archive or disk full)", r < 0 && GetLastError() ? GetLastError() : ERROR_CRC); }
        got[idx] = TRUE;
        found++;
    }
    unzClose(hz);
    if (found != nwant)
    {
        for (i = 0; i < nwant; i++)
            if (!got[i]) wprintf(L"error: %s is not in the archive\n", want[i]);
        return Fail(L"the archive does not hold every file the entry installs", ERROR_FILE_NOT_FOUND);
    }

    if (pathFlag[0] == L'1')
    {
        if (!PathAdd(dirRaw, &g_pathAdded, g_pathText, ARRAYSIZE(g_pathText))) return Fail(L"cannot update the machine PATH", GetLastError());
    }

    /* the record: what uninstall removes */
    {
        WCHAR key[300], *multi;
        size_t used = 0;
        DWORD dm = g_dirMade;
        LONG r;
        StringCchPrintfW(key, ARRAYSIZE(key), ZIP_RECORD_KEY L"\\%s", id);
        multi = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (ZIP_MAX_FILES * MAX_PATH + 2) * sizeof(WCHAR));
        if (!multi) return Fail(L"out of memory", ERROR_OUTOFMEMORY);
        for (i = 0; i < nwant; i++)
        {
            size_t l = wcslen(want[i]) + 1;
            memcpy(multi + used, want[i], l * sizeof(WCHAR));
            used += l;
        }
        multi[used++] = L'\0';
        r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &rec, &disp);
        if (r == ERROR_SUCCESS)
        {
            r = RegSetValueExW(rec, L"Dir", 0, REG_SZ, (const BYTE *)g_dir, (DWORD)((wcslen(g_dir) + 1) * sizeof(WCHAR)));
            if (r == ERROR_SUCCESS) r = RegSetValueExW(rec, L"Files", 0, REG_MULTI_SZ, (const BYTE *)multi, (DWORD)(used * sizeof(WCHAR)));
            if (r == ERROR_SUCCESS) r = RegSetValueExW(rec, L"DirCreated", 0, REG_DWORD, (const BYTE *)&dm, sizeof(dm));
            if (r == ERROR_SUCCESS) r = RegSetValueExW(rec, L"PathAdded", 0, REG_DWORD, (const BYTE *)&g_pathAdded, sizeof(DWORD));
            if (r == ERROR_SUCCESS) r = RegSetValueExW(rec, L"PathEntry", 0, REG_SZ, (const BYTE *)g_pathText, (DWORD)((wcslen(g_pathText) + 1) * sizeof(WCHAR)));
            RegCloseKey(rec);
            if (r != ERROR_SUCCESS) RegDeleteKeyW(HKEY_LOCAL_MACHINE, key);
        }
        HeapFree(GetProcessHeap(), 0, multi);
        if (r != ERROR_SUCCESS) return Fail(L"cannot write the install record", (DWORD)r);
    }
    wprintf(L"installed %d file(s) into %s%s\n", nwant, g_dir, g_pathAdded ? L" and added it to the PATH" : L"");
    if (g_pathAdded) NotifyEnvironment();
    return 0;
}

/* ---- uninstall ---------------------------------------------------------------------------------------------------- */

static int ZipUninstall(LPCWSTR id)
{
    WCHAR key[300], dir[MAX_PATH], canon[MAX_PATH], pathEntry[MAX_PATH * 2], *multi, *p;
    HKEY rec;
    DWORD type, cb, dirMade = 0, pathAdded = 0, bad = 0;
    int rc = 0;

    StringCchPrintfW(key, ARRAYSIZE(key), ZIP_RECORD_KEY L"\\%s", id);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &rec) != ERROR_SUCCESS)
    {
        wprintf(L"nothing recorded for '%s': nothing was removed\n", id);
        return 0;
    }
    cb = sizeof(dir);
    dir[0] = L'\0';
    if (RegQueryValueExW(rec, L"Dir", NULL, &type, (LPBYTE)dir, &cb) != ERROR_SUCCESS || type != REG_SZ || !InstallDirOk(dir, canon))
    {
        RegCloseKey(rec);
        wprintf(L"error: the install record of '%s' names a folder that is not allowed; nothing was removed\n", id);
        return ERROR_BAD_PATHNAME;
    }
    cb = sizeof(dirMade);
    if (RegQueryValueExW(rec, L"DirCreated", NULL, &type, (LPBYTE)&dirMade, &cb) != ERROR_SUCCESS || type != REG_DWORD) dirMade = 0;
    cb = sizeof(pathAdded);
    if (RegQueryValueExW(rec, L"PathAdded", NULL, &type, (LPBYTE)&pathAdded, &cb) != ERROR_SUCCESS || type != REG_DWORD) pathAdded = 0;
    cb = sizeof(pathEntry) - sizeof(WCHAR);
    pathEntry[0] = L'\0';
    if (RegQueryValueExW(rec, L"PathEntry", NULL, &type, (LPBYTE)pathEntry, &cb) != ERROR_SUCCESS || type != REG_SZ) pathEntry[0] = L'\0';
    pathEntry[ARRAYSIZE(pathEntry) - 1] = L'\0';
    multi = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (ZIP_MAX_FILES * MAX_PATH + 2) * sizeof(WCHAR));
    if (!multi) { RegCloseKey(rec); return ERROR_OUTOFMEMORY; }
    cb = ZIP_MAX_FILES * MAX_PATH * sizeof(WCHAR);
    if (RegQueryValueExW(rec, L"Files", NULL, &type, (LPBYTE)multi, &cb) != ERROR_SUCCESS || type != REG_MULTI_SZ) multi[0] = L'\0';
    RegCloseKey(rec);

    if (IsReparse(canon)) { HeapFree(GetProcessHeap(), 0, multi); wprintf(L"error: %s is a link; nothing was removed\n", canon); return ERROR_ACCESS_DENIED; }
    for (p = multi; *p; p += wcslen(p) + 1)
    {
        WCHAR t[MAX_PATH];
        if (!LeafOk(p)) { wprintf(L"note: the record lists an unusable name '%s'; skipped\n", p); continue; }
        StringCchPrintfW(t, MAX_PATH, L"%s\\%s", canon, p);
        if (IsReparse(t)) { wprintf(L"note: %s is a link; left alone\n", t); bad++; continue; }
        if (!DeleteFileW(t))
        {
            DWORD e = GetLastError();
            if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) continue;
            {
                /* in use (a running ssh.exe): move it out of the way and let the system delete it at the next boot */
                WCHAR t2[MAX_PATH + 16];
                StringCchPrintfW(t2, ARRAYSIZE(t2), L"%s.fmdel", t);
                if (MoveFileExW(t, t2, MOVEFILE_REPLACE_EXISTING))
                {
                    MoveFileExW(t2, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                    wprintf(L"note: %s is in use; it is renamed and deleted at the next restart\n", t);
                    continue;
                }
            }
            wprintf(L"error: cannot delete %s (%lu)\n", t, e);
            rc = (int)e;
        }
    }
    HeapFree(GetProcessHeap(), 0, multi);
    if (rc) return rc;          /* the record stays: a later uninstall continues */

    if (pathAdded && pathEntry[0])
    {
        if (!PathRemove(pathEntry)) { wprintf(L"error: cannot update the machine PATH\n"); return ERROR_ACCESS_DENIED; }
        NotifyEnvironment();
    }
    if (dirMade) RemoveDirectoryW(canon);          /* only when empty: anything the user put there stays */
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, key);
    wprintf(L"removed the files of '%s'%s\n", id, pathAdded ? L" and its PATH entry" : L"");
    return 0;
}

int FmZipMain(int argc, WCHAR **argv)
{
    if (argc < 3 || wcspbrk(argv[2], L"[]=\r\n\\/") || !FmCompFilePath(g_comps, ARRAYSIZE(g_comps)))
    {
        wprintf(L"usage: featmgr /zip-install <id> <zip> | /zip-uninstall <id>\n");
        return 2;
    }
    if (!_wcsicmp(argv[1], L"/zip-install"))
    {
        if (argc < 4) { wprintf(L"usage: featmgr /zip-install <id> <zip>\n"); return 2; }
        return ZipInstall(argv[2], argv[3]);
    }
    return ZipUninstall(argv[2]);
}
