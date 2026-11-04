/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     featmgr /nat-install <id> <file>: the two archive installers of the RAPPS entry format, run in a
 *              featmgr child so the engine keeps one way of running, timing out and cancelling an installer.
 *                Installer=Generate  unpack the zip / cab, move the [Generate] Files into the install directory,
 *                                    write an Add/Remove Programs record (the "RApps" subkey lists what to remove),
 *                                    and make the Start menu shortcut
 *                Installer=ExeInZip  unpack to a temporary directory and run the installer inside, silently
 *              Written for user-writable targets: every path an archive names is checked (no "..", no drive),
 *              files are created CREATE_NEW, and an existing reparse point is never written through.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#define COBJMACROS
#include "featmgr.h"
#include <shlwapi.h>
#include <shlobj.h>
#include <strsafe.h>

#include "minizip/ioapi.h"
#include "minizip/iowin32.h"
#include "minizip/unzip.h"

#define UNINSTALL_SUBKEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
#define GENERATE_ARPSUBKEY L"RApps"
#define NONE L"!"
#define ZIP_MAX_BYTES (4ull * 1024 * 1024 * 1024)
#define ZIP_MAX_FILES 200000

static FM_FEATURE g_f;
static int g_entry;                 /* number of the next record entry */
static HKEY g_entries;              /* the "RApps" subkey of the ARP key */
static WCHAR g_installDir[MAX_PATH];
static size_t g_installLen;
static WCHAR g_mainApp[MAX_PATH];
static int g_err;

static void Rk(LPCWSTR sec, LPCWSTR key, LPWSTR out, DWORD cch)
{
    GetPrivateProfileStringW(sec, key, L"", out, cch, g_f.ManifestPath);
}

static void Fail(LPCWSTR what, DWORD err)
{
    wprintf(L"error: %s (%lu)\n", what, err);
    g_err = err ? (int)err : 1;
}

/* ---- zip ---------------------------------------------------------------------------------------------------- */

static int ExtractZip(LPCWSTR archive, LPCWSTR outDir)
{
    zlib_filefunc64_def zff;
    unzFile hz;
    int zerr, files = 0;
    ULONGLONG bytes = 0;

    fill_win32_filefunc64W(&zff);
    hz = unzOpen2_64(archive, &zff);
    if (!hz) return ERROR_BAD_FORMAT;
    for (zerr = unzGoToFirstFile(hz); zerr == UNZ_OK; zerr = unzGoToNextFile(hz))
    {
        unz_file_info64 fi;
        char narrow[1024];
        WCHAR name[MAX_PATH], full[MAX_PATH];
        HANDLE hf;
        static BYTE buf[64 * 1024];
        int n;
        UINT cp;

        if (unzGetCurrentFileInfo64(hz, &fi, narrow, sizeof(narrow), NULL, 0, NULL, 0) != UNZ_OK) { zerr = UNZ_ERRNO; break; }
        if (fi.size_filename >= sizeof(narrow)) continue;
        cp = (fi.flag & (1 << 11)) ? CP_UTF8 : 1252;
        if (MultiByteToWideChar(cp, 0, narrow, -1, name, MAX_PATH) <= 0) continue;
        n = (int)wcslen(name);
        if (n && (name[n - 1] == L'/' || name[n - 1] == L'\\')) continue;          /* a directory entry */
        if (!FmSafeTreeName(name))
        {
            wprintf(L"skipped an archive entry with an unsafe name\n");
            continue;
        }
        if (++files > ZIP_MAX_FILES || (bytes += fi.uncompressed_size) > ZIP_MAX_BYTES) { zerr = UNZ_ERRNO; SetLastError(ERROR_FILE_TOO_LARGE); break; }
        if (!FmMakeParents(outDir, name)) { zerr = UNZ_ERRNO; break; }
        StringCchPrintfW(full, MAX_PATH, L"%s\\%s", outDir, name);
        if (unzOpenCurrentFile(hz) != UNZ_OK) { zerr = UNZ_BADZIPFILE; break; }
        hf = CreateFileW(full, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf == INVALID_HANDLE_VALUE)
        {
            unzCloseCurrentFile(hz);
            if (GetLastError() == ERROR_FILE_EXISTS) continue;      /* a duplicate name: the first one stays */
            zerr = UNZ_ERRNO;
            break;
        }
        for (;;)
        {
            DWORD w;
            int r = unzReadCurrentFile(hz, buf, sizeof(buf));
            if (r < 0) { zerr = r; break; }
            if (r == 0) break;
            if (!WriteFile(hf, buf, r, &w, NULL) || w != (DWORD)r) { zerr = UNZ_ERRNO; break; }
        }
        CloseHandle(hf);
        unzCloseCurrentFile(hz);
        if (zerr != UNZ_OK && zerr != UNZ_END_OF_LIST_OF_FILE) break;
    }
    unzClose(hz);
    if (zerr == UNZ_END_OF_LIST_OF_FILE) return 0;
    return zerr == UNZ_ERRNO ? (GetLastError() ? GetLastError() : ERROR_WRITE_FAULT) : ERROR_BAD_FORMAT;
}

static DWORD ExtractArchive(LPCWSTR archive, LPCWSTR outDir)
{
    int kind = FmNativeFileKind(archive);
    if (kind == FM_FK_CAB)
    {
        int n;
        return FmExtractCab(archive, outDir, TRUE, &n) ? 0 : ERROR_BAD_FORMAT;
    }
    return ExtractZip(archive, outDir);
}

/* ---- Generate ------------------------------------------------------------------------------------------------- */

static void AddEntry(WCHAR type, LPCWSTR value)
{
    WCHAR name[24];
    StringCchPrintfW(name, ARRAYSIZE(name), L"%c%d", type, ++g_entry);
    RegSetValueExW(g_entries, name, 0, REG_SZ, (const BYTE *)value, (DWORD)((wcslen(value) + 1) * sizeof(WCHAR)));
}

static BOOL IsReparse(LPCWSTR path)
{
    DWORD a = GetFileAttributesW(path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT);
}

/* move the files of one "[dir\]filespec" item from src to dst, recording each; recurses into sub-directories */
static BOOL InstallFiles(LPCWSTR srcBase, LPCWSTR spec, LPCWSTR dstDir)
{
    WCHAR srcDir[MAX_PATH], filespec[MAX_PATH], pat[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    BOOL ok = TRUE;
    WCHAR *sl;

    StringCchCopyW(filespec, MAX_PATH, spec);
    sl = wcsrchr(filespec, L'\\');
    if (sl) { *sl = L'\0'; StringCchPrintfW(srcDir, MAX_PATH, L"%s\\%s", srcBase, filespec); StringCchCopyW(filespec, MAX_PATH, sl + 1); }
    else StringCchCopyW(srcDir, MAX_PATH, srcBase);
    StringCchPrintfW(pat, MAX_PATH, L"%s\\%s", srcDir, filespec);
    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
    do
    {
        WCHAR from[MAX_PATH], to[MAX_PATH];
        StringCchPrintfW(from, MAX_PATH, L"%s\\%s", srcDir, fd.cFileName);
        StringCchPrintfW(to, MAX_PATH, L"%s\\%s", dstDir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
            if (IsReparse(to)) { Fail(L"refusing to install through a link", ERROR_ACCESS_DENIED); ok = FALSE; break; }
            if (!CreateDirectoryW(to, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) { Fail(L"cannot create a directory", GetLastError()); ok = FALSE; break; }
            ok = InstallFiles(from, filespec, to);
            AddEntry(L'd', to + g_installLen);
            if (!ok) break;
        }
        else
        {
            if (IsReparse(to)) { Fail(L"refusing to overwrite a link", ERROR_ACCESS_DENIED); ok = FALSE; break; }
            if (!MoveFileExW(from, to, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) { Fail(L"cannot install a file", GetLastError()); ok = FALSE; break; }
            if (!g_mainApp[0]) StringCchCopyW(g_mainApp, MAX_PATH, to);
            AddEntry(L'F', to + g_installLen);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return ok;
}

/* the entry's Del* lists become record entries; each must stay inside the app's own directory / registry key (native.c) */
static void AddFromDb(LPCWSTR key, WCHAR type, LPCWSTR prefix, BOOL checkOnly)
{
    WCHAR list[1024], *tok, *ctx = NULL, item[MAX_PATH], chk[MAX_PATH];
    Rk(L"Generate", key, list, ARRAYSIZE(list));
    for (tok = wcstok_s(list, L"|", &ctx); tok && !g_err; tok = wcstok_s(NULL, L"|", &ctx))
    {
        BOOL ok;
        if (type == L'd' && (!wcscmp(tok, L".") || !wcscmp(tok, L"..")))
        {
            /* "DelDirEmpty = .|.." (the RAPPS idiom: the install folder and the vendor folder above it, each if empty).
             * "." is the install folder itself, which the record always lists ("d \"). ".." is recorded only when the parent is
             * itself a folder an install could own (strictly below Program Files / LocalAppData\Programs, not protected);
             * otherwise the item is dropped. Only DelDirEmpty: DelDir / DelFile with "." or ".." stay refused. */
            WCHAR par[MAX_PATH];
            if (checkOnly || tok[1] == L'\0') continue;
            StringCchCopyW(par, MAX_PATH, g_installDir);
            PathRemoveFileSpecW(par);
            if (FmInstallDirOk(par, NULL)) AddEntry(L'd', L"\\..");
            else wprintf(L"note: dropped the entry's DelDirEmpty item '..': the parent folder %s is a protected folder\n", par);
            continue;
        }
        if (type == L'K' || type == L'k')
            ok = FmGenRegOk(tok, type == L'K');
        else
        {
            StringCchCopyW(chk, MAX_PATH, tok);
            ok = FmSafeTreeName(chk);                  /* not "." or "..", no drive, not absolute, not empty */
        }
        if (!ok)
        {
            wprintf(L"error: the entry's %s item '%s' is outside the app's own folder or registry key\n", key, tok);
            Fail(L"unsafe cleanup entry", ERROR_BAD_PATHNAME);
            return;
        }
        if (checkOnly) continue;
        StringCchPrintfW(item, MAX_PATH, L"%s%s", prefix, tok);
        AddEntry(type, item);
    }
}

/* a [Generate] Files item: names and wildcards below the unpacked archive, nothing that climbs out of it */
static BOOL SpecOk(LPCWSTR spec)
{
    return spec[0] && spec[0] != L'\\' && !wcsstr(spec, L"..") && !wcschr(spec, L':');
}

static void SetArp(HKEY arp, LPCWSTR name, LPCWSTR value)
{
    RegSetValueExW(arp, name, 0, REG_SZ, (const BYTE *)value, (DWORD)((wcslen(value) + 1) * sizeof(WCHAR)));
}

static HRESULT MakeShortcut(BOOL perUser, LPCWSTR target, LPCWSTR lnkName, LPCWSTR args, LPCWSTR icon)
{
    WCHAR dir[MAX_PATH], path[MAX_PATH], rel[MAX_PATH];
    IShellLinkW *sl = NULL;
    IPersistFile *pf = NULL;
    HRESULT hr;
    WCHAR *p;

    if (!SHGetSpecialFolderPathW(NULL, dir, perUser ? CSIDL_PROGRAMS : CSIDL_COMMON_PROGRAMS, TRUE)) return E_FAIL;
    StringCchCopyW(rel, MAX_PATH, lnkName);
    if (!FmSafeTreeName(rel)) return E_INVALIDARG;
    if (!FmMakeParents(dir, rel)) return HRESULT_FROM_WIN32(GetLastError());
    StringCchPrintfW(path, MAX_PATH, L"%s\\%s", dir, rel);
    if (IsReparse(path)) return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&sl);
    if (FAILED(hr)) return hr;
    IShellLinkW_SetPath(sl, target);
    StringCchCopyW(dir, MAX_PATH, target);
    PathRemoveFileSpecW(dir);
    IShellLinkW_SetWorkingDirectory(sl, dir);
    if (args[0]) IShellLinkW_SetArguments(sl, args);
    if (icon[0])
    {
        WCHAR ip[MAX_PATH];
        int idx;
        StringCchCopyW(ip, MAX_PATH, icon);
        idx = PathParseIconLocationW(ip);
        IShellLinkW_SetIconLocation(sl, ip, idx);
    }
    hr = IShellLinkW_QueryInterface(sl, &IID_IPersistFile, (void **)&pf);
    if (SUCCEEDED(hr))
    {
        hr = IPersistFile_Save(pf, path, FALSE);
        IPersistFile_Release(pf);
    }
    IShellLinkW_Release(sl);
    if (SUCCEEDED(hr))
    {
        AddEntry(L'F', path);
        StringCchCopyW(dir, MAX_PATH, path);
        PathRemoveFileSpecW(dir);
        p = dir;
        AddEntry(L'd', p);
    }
    return hr;
}

static int GenInstall(LPCWSTR archive)
{
    WCHAR files[512], scope[32], dirKey[MAX_PATH], base[MAX_PATH], tmp[MAX_PATH * 2], lnk[MAX_PATH], icon[MAX_PATH], lnkArgs[512];
    WCHAR arpName[128], arpPath[300], version[64], publisher[128], fm[MAX_PATH], tempDir[MAX_PATH];
    BOOL perUser = TRUE;
    HKEY arp = NULL, hRoot;
    DWORD disp;
    SYSTEMTIME st;
    WCHAR *tok, *ctx = NULL;
    LONG r;
    REGSAM sam = KEY_READ | KEY_WRITE;

    Rk(L"Generate", L"Files", files, ARRAYSIZE(files));
    if (!files[0]) StringCchCopyW(files, ARRAYSIZE(files), L"*.exe|*.*");
    Rk(L"Rapps", L"Scope", scope, ARRAYSIZE(scope));
    if (!_wcsicmp(scope, L"Machine")) perUser = FALSE;
    /* check the cleanup lists before anything is created or moved: a bad entry must leave nothing behind */
    AddFromDb(L"DelReg", L'K', L"", TRUE);
    AddFromDb(L"DelRegEmpty", L'k', L"", TRUE);
    AddFromDb(L"DelFile", L'F', L"", TRUE);
    AddFromDb(L"DelDir", L'D', L"", TRUE);
    AddFromDb(L"DelDirEmpty", L'd', L"", TRUE);
    if (g_err) return g_err;
    {
        WCHAR fl[512], *ft, *fc = NULL;
        Rk(L"Generate", L"Files", fl, ARRAYSIZE(fl));
        if (!fl[0]) StringCchCopyW(fl, ARRAYSIZE(fl), L"*.exe|*.*");
        for (ft = wcstok_s(fl, L"|", &fc); ft; ft = wcstok_s(NULL, L"|", &fc))
            if (!SpecOk(ft)) return Fail(L"a [Generate] Files item climbs out of the archive", ERROR_BAD_PATHNAME), g_err;
    }

    if (perUser)
    {
        if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base))) return Fail(L"no profile folder", GetLastError()), g_err;
        StringCchCatW(base, MAX_PATH, L"\\Programs");
        CreateDirectoryW(base, NULL);
    }
    else if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, 0, base))) return Fail(L"no Program Files folder", GetLastError()), g_err;

    Rk(L"Generate", L"Dir", dirKey, ARRAYSIZE(dirKey));
    if (dirKey[0] == L'%')
    {
        DWORD n = ExpandEnvironmentStringsW(dirKey, tmp, ARRAYSIZE(tmp));
        if (!n || n > ARRAYSIZE(tmp) || !tmp[0] || wcschr(tmp, L'%'))
            return Fail(L"the install directory names an unknown variable", ERROR_BAD_PATHNAME), g_err;
        if (FAILED(StringCchCopyW(dirKey, ARRAYSIZE(dirKey), tmp))) return Fail(L"the install directory is too long", ERROR_BAD_PATHNAME), g_err;
    }
    else if (wcscmp(dirKey, NONE))
    {
        /* a name below the base: "Vendor\App"; leading / trailing separators are dropped ("/thepowdertoy/" is "thepowdertoy") */
        WCHAR leaf[MAX_PATH], *l = leaf;
        size_t n;
        StringCchCopyW(leaf, MAX_PATH, dirKey[0] ? dirKey : g_f.Name);
        while (*l == L'\\' || *l == L'/') l++;
        n = wcslen(l);
        while (n && (l[n - 1] == L'\\' || l[n - 1] == L'/')) l[--n] = L'\0';
        if (!FmSafeTreeName(l)) return Fail(L"the install directory name is not valid", ERROR_BAD_PATHNAME), g_err;
        if (FAILED(StringCchPrintfW(dirKey, ARRAYSIZE(dirKey), L"%s\\%s", base, l))) return Fail(L"the install directory is too long", ERROR_BAD_PATHNAME), g_err;
    }
    else
        StringCchCopyW(dirKey, ARRAYSIZE(dirKey), base);
    /* canonical first (8.3 names, doubled or trailing separators, names ending in a space or dot), then the allow-list */
    if (!FmInstallDirOk(dirKey, g_installDir))
    {
        wprintf(L"error: the install directory '%s' is not a folder of its own below Program Files or %%LOCALAPPDATA%%\\Programs\n", dirKey);
        return Fail(L"the install directory is a system or profile folder (or not below Program Files / LocalAppData\\Programs); it must be a folder of its own", ERROR_BAD_PATHNAME), g_err;
    }
    g_installLen = wcslen(g_installDir);
    if (IsReparse(g_installDir)) return Fail(L"the install directory is a link", ERROR_ACCESS_DENIED), g_err;
    if (SHCreateDirectoryExW(NULL, g_installDir, NULL) != ERROR_SUCCESS && GetFileAttributesW(g_installDir) == INVALID_FILE_ATTRIBUTES)
        return Fail(L"cannot create the install directory", GetLastError()), g_err;
    if (IsReparse(g_installDir)) return Fail(L"the install directory is a link", ERROR_ACCESS_DENIED), g_err;

    StringCchPrintfW(tempDir, MAX_PATH, L"%s\\~featmgr%lu.tmp", g_installDir, GetCurrentProcessId());
    FmDeleteTree(tempDir);
    if (!CreateDirectoryW(tempDir, NULL)) return Fail(L"cannot create the temporary directory", GetLastError()), g_err;

    /* the Add/Remove Programs record: <ARP key>\RApps lists what to remove */
    StringCchCopyW(arpName, ARRAYSIZE(arpName), g_f.Name);
    { WCHAR *q; for (q = arpName; *q; q++) if (*q == L'\\' || *q == L'/') *q = L'_'; }
    StringCchPrintfW(arpPath, ARRAYSIZE(arpPath), UNINSTALL_SUBKEY L"\\%s", arpName);
    hRoot = perUser ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
#ifdef _WIN64
    sam |= KEY_WOW64_64KEY;
#endif
    r = RegCreateKeyExW(hRoot, arpPath, 0, NULL, REG_OPTION_NON_VOLATILE, sam, NULL, &arp, &disp);
    if (r == ERROR_SUCCESS)
    {
        SHDeleteKeyW(arp, GENERATE_ARPSUBKEY);
        r = RegCreateKeyExW(arp, GENERATE_ARPSUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, NULL, &g_entries, &disp);
    }
    if (r != ERROR_SUCCESS) { Fail(L"cannot write the Add/Remove Programs record", r); goto out; }

    if ((r = ExtractArchive(archive, tempDir)) != 0) { Fail(L"cannot unpack the download", r); goto out; }

    for (tok = wcstok_s(files, L"|", &ctx); tok && !g_err; tok = wcstok_s(NULL, L"|", &ctx))
    {
        if (!SpecOk(tok)) { Fail(L"a [Generate] Files item climbs out of the archive", ERROR_BAD_PATHNAME); break; }
        InstallFiles(tempDir, tok, g_installDir);
    }
    if (g_err) goto out;
    if (!g_mainApp[0]) { Fail(L"the archive held none of the files the entry installs", ERROR_FILE_NOT_FOUND); goto out; }

    AddFromDb(L"DelReg", L'K', L"", FALSE);
    AddFromDb(L"DelRegEmpty", L'k', L"", FALSE);
    AddFromDb(L"DelFile", L'F', L"\\", FALSE);
    AddFromDb(L"DelDir", L'D', L"\\", FALSE);
    AddFromDb(L"DelDirEmpty", L'd', L"\\", FALSE);
    if (g_err) goto out;
    AddEntry(L'd', L"\\");

    if (!FmFeatmgrExePath(fm, MAX_PATH)) StringCchCopyW(fm, MAX_PATH, L"featmgr.exe");
    SetArp(arp, L"DisplayName", g_f.Name);
    SetArp(arp, L"InstallLocation", g_installDir);
    StringCchPrintfW(tmp, ARRAYSIZE(tmp), L"\"%s\" /nat-uninstall \"%s\" \"%s\" \"-\"", fm, arpName, g_f.Name);
    SetArp(arp, L"UninstallString", tmp);
    SetArp(arp, L"QuietUninstallString", tmp);
    Rk(L"Generate", L"Icon", icon, ARRAYSIZE(icon));
    if (wcscmp(icon, NONE))
    {
        if (icon[0]) { StringCchPrintfW(tmp, ARRAYSIZE(tmp), L"%s\\%s", g_installDir, icon); SetArp(arp, L"DisplayIcon", tmp); }
        else SetArp(arp, L"DisplayIcon", g_mainApp);
    }
    Rk(L"Source", L"Version", version, ARRAYSIZE(version));
    if (!version[0]) StringCchCopyW(version, ARRAYSIZE(version), g_f.Version);
    if (version[0]) SetArp(arp, L"DisplayVersion", version);
    GetSystemTime(&st);
    StringCchPrintfW(tmp, ARRAYSIZE(tmp), L"%04u%02u%02u", st.wYear, st.wMonth, st.wDay);
    SetArp(arp, L"InstallDate", tmp);
    Rk(L"Source", L"Publisher", publisher, ARRAYSIZE(publisher));
    if (publisher[0]) SetArp(arp, L"Publisher", publisher);

    Rk(L"Generate", L"Lnk", lnk, ARRAYSIZE(lnk));
    if (!lnk[0]) StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s.lnk", arpName);
    if (wcscmp(lnk, NONE))
    {
        HRESULT hr;
        WCHAR iconPath[MAX_PATH];
        Rk(L"Generate", L"LnkParameters", lnkArgs, ARRAYSIZE(lnkArgs));
        iconPath[0] = L'\0';
        if (icon[0] && wcscmp(icon, NONE)) StringCchPrintfW(iconPath, MAX_PATH, L"%s\\%s", g_installDir, icon);
        hr = MakeShortcut(perUser, g_mainApp, lnk, lnkArgs, iconPath);
        if (FAILED(hr)) wprintf(L"note: the Start menu shortcut was not made (0x%08lx)\n", (DWORD)hr);
    }
    wprintf(L"installed %d file(s) into %s\n", g_entry, g_installDir);
out:
    if (g_entries) RegCloseKey(g_entries);
    if (arp) RegCloseKey(arp);
    FmDeleteTree(tempDir);
    RemoveDirectoryW(g_installDir);          /* harmless when something was installed (it is not empty) */
    if (g_err && arp == NULL) return g_err;
    if (g_err)
    {
        /* a failed install leaves no record behind that would later delete the wrong thing */
        HKEY un;
        if (RegOpenKeyExW(hRoot, UNINSTALL_SUBKEY, 0, KEY_READ | DELETE | (sam & KEY_WOW64_64KEY), &un) == ERROR_SUCCESS)
        {
            SHDeleteKeyW(un, arpName);
            RegCloseKey(un);
        }
    }
    return g_err;
}

/* ---- ExeInZip -------------------------------------------------------------------------------------------------- */

static int ExeInZip(LPCWSTR archive)
{
    WCHAR tmpBase[MAX_PATH], dir[MAX_PATH], exe[MAX_PATH], nested[32], args[512], cmd[2048], exeName[MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = 1, r;
    int type;

    /* an unpredictable name inside the feature manager's own folder (writable by administrators only), not the user's %TEMP% */
    if (!FmGetRootDir(tmpBase, MAX_PATH)) return 1;
    StringCchCatW(tmpBase, MAX_PATH, L"\\Temp");
    CreateDirectoryW(tmpBase, NULL);
    if (!GetTempFileNameW(tmpBase, L"fmz", 0, dir)) return Fail(L"cannot name a temporary directory", GetLastError()), g_err;
    DeleteFileW(dir);                           /* GetTempFileName made a file; the name is what we wanted */
    if (!CreateDirectoryW(dir, NULL)) return Fail(L"cannot create a temporary directory", GetLastError()), g_err;
    if ((r = ExtractArchive(archive, dir)) != 0) { Fail(L"cannot unpack the download", r); goto out; }
    Rk(L"ExeInZip", L"Exe", exeName, ARRAYSIZE(exeName));
    if (!exeName[0])
    {
        WIN32_FIND_DATAW fd;
        HANDLE h;
        StringCchPrintfW(exe, MAX_PATH, L"%s\\*.exe", dir);
        h = FindFirstFileW(exe, &fd);
        if (h != INVALID_HANDLE_VALUE) { StringCchCopyW(exeName, MAX_PATH, fd.cFileName); FindClose(h); }
    }
    if (!exeName[0] || !FmSafeTreeName(exeName)) { Fail(L"no installer program inside the archive", ERROR_FILE_NOT_FOUND); goto out; }
    StringCchPrintfW(exe, MAX_PATH, L"%s\\%s", dir, exeName);
    Rk(L"Rapps", L"SilentParameters", args, ARRAYSIZE(args));
    if (!args[0])
    {
        Rk(L"ExeInZip", L"Installer", nested, ARRAYSIZE(nested));
        type = !_wcsicmp(nested, L"Inno") ? 1 : !_wcsicmp(nested, L"NSIS") ? 2 : FmNativeGuessInstaller(exe);
        StringCchCopyW(args, ARRAYSIZE(args), FmNativeSilentSwitches(type));
    }
    StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"\"%s\" %s", exe, args);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi)) { Fail(L"cannot start the installer", GetLastError()); goto out; }
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    wprintf(L"installer exit code: %lu\n", code);
    g_err = (int)code;
out:
    FmDeleteTree(dir);
    return g_err;
}

int FmNativeInstallMain(int argc, WCHAR **argv)
{
    WCHAR inst[32];
    HRESULT hrInit;
    int rc;

    if (argc < 4) { wprintf(L"usage: featmgr /nat-install <id> <file>\n"); return 2; }
    if (!FmFindFeature(argv[2], &g_f)) { wprintf(L"error: unknown feature '%s'\n", argv[2]); return 2; }
    hrInit = CoInitialize(NULL);
    Rk(L"Rapps", L"Installer", inst, ARRAYSIZE(inst));
    if (!_wcsicmp(inst, L"Generate")) rc = GenInstall(argv[3]);
    else if (!_wcsicmp(inst, L"ExeInZip")) rc = ExeInZip(argv[3]);
    else { wprintf(L"error: '%s' has no archive installer\n", g_f.Id); rc = 2; }
    if (SUCCEEDED(hrInit)) CoUninitialize();
    return rc;
}
