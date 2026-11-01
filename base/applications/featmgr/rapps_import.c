/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager (FEATMGMT-01)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     RAPPS database -> featmgr software-tier catalog converter.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Field mapping (RAPPS appdb\<pkg>.txt  ->  Catalog\Software\rapps-<pkg>.ini):
 *
 *   RAPPS [Section] key        featmgr manifest
 *   -------------------------  ------------------------------------------------
 *   <file name>.txt            [Feature] Id=rapps-<pkg>   [Rapps] Pkg=<pkg>
 *   Name                       [Feature] Name
 *   Description                [Feature] Description
 *   Version                    [Feature] Version
 *   (fixed)                    [Feature] Tier=software
 *   Dependencies (a|b*x64)     [Feature] Dependencies=rapps-a (only those that
 *                              exist in the imported DB); raw kept in [Rapps]
 *   URLDownload                [Source] Artifact
 *   SHA1                       [Source] ArtifactSHA1   (RAPPS integrity is SHA1)
 *   SizeBytes                  [Source] SizeBytes
 *   License / LicenseType      [Source] License  (Open Source|Freeware|Trial text
 *                              + RAPPS license string, same text RAPPS shows)
 *   Publisher, URLSite         [Source] Publisher, URLSite
 *   Category (1..16)           [Rapps] Category=<name>   (numeric kept in CategoryId)
 *   RegName, Installer,        [Rapps] RegName, Installer, SilentParameters,
 *   SilentParameters, NTVersion,   NTVersion, Scope, SaveAs, LicenseType
 *   Scope, SaveAs              (carried verbatim; rapps.exe remains the executor)
 *   (fixed)                    [Install] Provider=rapps  -> featmgr delegates the
 *                              download + SHA1 check + installer run to rapps.exe
 *
 * Section selection follows RAPPS: [Section.<arch>] overrides [Section]; on
 * non-x86 the generic URLDownload is ignored (RAPPS refuses 32-bit installers
 * there) unless FM_IMPORT_ANYARCH. Locale sections ([Section.0419]) are NOT
 * imported: manifests carry the English/neutral text. Entries without Name or
 * a usable URLDownload are skipped. Nothing is written into the image: the
 * output is a regenerable cache next to the state the user already has.
 */

#include "featmgr.h"
#include <shlwapi.h>
#include <shlobj.h>
#include <strsafe.h>

#define LOGF(log, ...) do { if (log) { fwprintf((log), __VA_ARGS__); fflush(log); } } while (0)

#if defined(_M_IX86)
#define FM_ARCH L"x86"
#elif defined(_M_AMD64)
#define FM_ARCH L"amd64"
#elif defined(_M_ARM64)
#define FM_ARCH L"arm64"
#elif defined(_M_ARM)
#define FM_ARCH L"arm"
#else
#define FM_ARCH L"unknown"
#endif

static const WCHAR NOTFOUND[] = L"\x01";

static const LPCWSTR g_Categories[] = {
    L"Other", L"Audio", L"Video", L"Graphics", L"Games", L"Internet", L"Office",
    L"Development", L"Edutainment", L"Engineering", L"Finance", L"Science",
    L"Tools", L"Drivers", L"Libraries", L"Themes", L"Other"
};

/* Read key from [Section.<arch>] then [Section]. FALSE if absent or empty. */
static BOOL GetKey(LPCWSTR file, LPCWSTR key, LPWSTR out, DWORD cch, DWORD flags)
{
    DWORD n;

    n = GetPrivateProfileStringW(L"Section." FM_ARCH, key, NOTFOUND, out, cch, file);
    if (out[0] && out[0] != 1) return TRUE;

#ifndef _M_IX86
    if (!(flags & FM_IMPORT_ANYARCH) && !_wcsicmp(key, L"URLDownload"))
    {
        out[0] = L'\0';
        return FALSE;
    }
#endif
    n = GetPrivateProfileStringW(L"Section", key, NOTFOUND, out, cch, file);
    (void)n;
    if (out[0] && out[0] != 1) return TRUE;
    out[0] = L'\0';
    return FALSE;
}

/* A package name becomes part of an id, a file name and a command line. */
static BOOL ValidPkgName(LPCWSTR s)
{
    size_t n = wcslen(s), i;
    if (!n || n > FM_MAX_ID - 8) return FALSE;      /* room for the "rapps-" prefix */
    for (i = 0; i < n; i++)
    {
        WCHAR c = s[i];
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9')
              || c == L'-' || c == L'_' || c == L'.' || c == L'+'))
            return FALSE;
    }
    return s[0] != L'.';
}

/* Make a value safe for a one-line "key=value" INI entry. */
static void Flatten(LPWSTR s)
{
    for (; *s; s++)
        if (*s == L'\r' || *s == L'\n' || *s == L'\t') *s = L' ';
}

void FmOutLine(FM_OUTBUF *o, LPCWSTR key, LPCWSTR val)
{
    size_t need = wcslen(key) + wcslen(val) + 4;
    if (o->fail) return;
    if (o->len + need >= o->cap)
    {
        size_t nc = (o->cap + need) * 2;
        WCHAR *nb = o->buf ? (WCHAR *)HeapReAlloc(GetProcessHeap(), 0, o->buf, nc * sizeof(WCHAR))
                           : (WCHAR *)HeapAlloc(GetProcessHeap(), 0, nc * sizeof(WCHAR));
        if (!nb) { o->fail = TRUE; return; }
        o->buf = nb; o->cap = nc;
    }
    if (key[0])
        StringCchPrintfW(o->buf + o->len, o->cap - o->len, L"%s=%s\r\n", key, val);
    else
        StringCchPrintfW(o->buf + o->len, o->cap - o->len, L"%s\r\n", val);   /* raw line (section header) */
    o->len += wcslen(o->buf + o->len);
}

/* Emit "key=<value of RAPPS key>" only when RAPPS has the key. */
static void CopyKey(FM_OUTBUF *o, LPCWSTR file, LPCWSTR rappsKey, LPCWSTR outKey, DWORD flags)
{
    WCHAR v[1024];
    if (GetKey(file, rappsKey, v, ARRAYSIZE(v), flags))
    {
        Flatten(v);
        FmOutLine(o, outKey, v);
    }
}

/* Same text RAPPS shows: license class word + free-text name. */
static void BuildLicense(LPCWSTR file, LPWSTR out, DWORD cch, DWORD flags)
{
    WCHAR lic[256], lt[16];
    int type = 0;
    LPCWSTR cls = NULL;

    lic[0] = lt[0] = L'\0';
    GetKey(file, L"License", lic, ARRAYSIZE(lic), flags);
    if (GetKey(file, L"LicenseType", lt, ARRAYSIZE(lt), flags)) type = _wtoi(lt);
    if (type == 0 && !_wcsicmp(lic, L"Freeware")) { type = 2; lic[0] = L'\0'; }
    if (type == 2 && !_wcsicmp(lic, L"Freeware")) lic[0] = L'\0';
    switch (type)
    {
        case 1: cls = L"Open Source"; break;
        case 2: cls = L"Freeware"; break;
        case 3: cls = L"Trial"; break;
    }
    Flatten(lic);
    if (cls && lic[0]) StringCchPrintfW(out, cch, L"%s (%s)", cls, lic);
    else if (cls)      StringCchCopyW(out, cch, cls);
    else               StringCchCopyW(out, cch, lic);
}

/* RAPPS "a|b*x64|c" -> "rapps-a,rapps-c" for entries present in srcDir. */
static void MapDependencies(LPCWSTR srcDir, LPCWSTR raw, LPWSTR out, DWORD cch)
{
    WCHAR tmp[512], path[MAX_PATH];
    WCHAR *ctx = NULL, *d;

    out[0] = L'\0';
    StringCchCopyW(tmp, ARRAYSIZE(tmp), raw);
    for (d = wcstok_s(tmp, L"|", &ctx); d; d = wcstok_s(NULL, L"|", &ctx))
    {
        WCHAR *e;
        while (*d == L' ') d++;
        e = d + wcscspn(d, L"*<=>:/\\?");        /* strip RAPPS version/arch modifiers */
        while (e > d && e[-1] == L' ') e--;
        *e = L'\0';
        if (!ValidPkgName(d)) continue;
        StringCchPrintfW(path, MAX_PATH, L"%s\\%s.txt", srcDir, d);
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) continue;
        if (out[0]) StringCchCatW(out, cch, L",");
        StringCchCatW(out, cch, L"rapps-");
        StringCchCatW(out, cch, d);
    }
}

BOOL FmWriteManifest(LPCWSTR path, const FM_OUTBUF *o)
{
    HANDLE h;
    DWORD w;
    WORD bom = 0xFEFF;     /* UTF-16LE + BOM: GetPrivateProfile* detects it, keeps non-ASCII names intact */
    BOOL ok;

    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = WriteFile(h, &bom, sizeof(bom), &w, NULL)
      && WriteFile(h, o->buf, (DWORD)(o->len * sizeof(WCHAR)), &w, NULL);
    CloseHandle(h);
    return ok;
}

static BOOL DefaultRappsDir(LPWSTR out, DWORD cch)
{
    WCHAR base[MAX_PATH];
    if (!SHGetSpecialFolderPathW(NULL, base, CSIDL_LOCAL_APPDATA, FALSE)) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch, L"%s\\RApps\\appdb", base));
}

/* TRUE if dir holds at least one RAPPS entry (*.txt). */
static BOOL HasRappsEntries(LPCWSTR dir)
{
    WCHAR glob[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    StringCchPrintfW(glob, MAX_PATH, L"%s\\*.txt", dir);
    h = FindFirstFileW(glob, &fd);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    FindClose(h);
    return TRUE;
}

#define FM_DBFETCH_TIMEOUT_MS (10 * 60 * 1000)

/* No local RAPPS database yet: have rapps.exe download it headless
 * ("rapps /updatedb /S" - the silent mode raises no dialog), then wait for it.
 * Runs on the calling thread (the GUI calls this from its worker thread). */
static BOOL FetchRappsDatabase(FILE *log)
{
    WCHAR sys[MAX_PATH], cmd[MAX_PATH + 40];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD wr, code = 1;

    if (!GetSystemDirectoryW(sys, MAX_PATH)) return FALSE;
    StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"\"%s\\rapps.exe\" /updatedb /S", sys);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    LOGF(log, L"no local RAPPS database; fetching the online catalog: %s\n", cmd);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        LOGF(log, L"error: cannot start rapps.exe (%lu)\n", GetLastError());
        return FALSE;
    }
    FmOpStep(L"Downloading the RAPPS catalog");
    {
        HANDLE wh[2];
        wh[0] = pi.hProcess;
        wh[1] = FmOpCancelHandle();          /* NULL for the CLI: plain wait */
        wr = WaitForMultipleObjects(wh[1] ? 2 : 1, wh, FALSE, FM_DBFETCH_TIMEOUT_MS);
    }
    if (wr == WAIT_OBJECT_0)
        GetExitCodeProcess(pi.hProcess, &code);
    else
    {
        LOGF(log, wr == WAIT_OBJECT_0 + 1 ? L"cancelled: catalog download stopped\n" : L"error: catalog download timed out\n");
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 15000);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return wr == WAIT_OBJECT_0 && code == 0;
}

/* Make a RAPPS-format entry that ships in the image (a catalog manifest's [Rapps] Entry=)
 * resolvable by rapps.exe as package <pkg>: ensure the per-user RAPPS database exists
 * (fetched headless when missing, so staging never leaves a lone entry that would stop
 * rapps from downloading its catalog), then copy the file in as <pkg>.txt. */
BOOL FmStageRappsEntry(LPCWSTR entryFile, LPCWSTR pkg, FILE *log)
{
    WCHAR dir[MAX_PATH], dest[MAX_PATH];

    if (!ValidPkgName(pkg))
    {
        LOGF(log, L"error: invalid RAPPS package name '%s'\n", pkg);
        return FALSE;
    }
    if (!DefaultRappsDir(dir, MAX_PATH))
    {
        LOGF(log, L"error: cannot locate the RAPPS database directory\n");
        return FALSE;
    }
    if (!HasRappsEntries(dir))
        FetchRappsDatabase(log);   /* best effort: offline, the entry is staged alone */
    SHCreateDirectoryExW(NULL, dir, NULL);
    if (FAILED(StringCchPrintfW(dest, MAX_PATH, L"%s\\%s.txt", dir, pkg))
        || !CopyFileW(entryFile, dest, FALSE))
    {
        LOGF(log, L"error: cannot stage RAPPS entry %s (%lu)\n", entryFile, GetLastError());
        return FALSE;
    }
    LOGF(log, L"  staged RAPPS entry: %s\n", dest);
    return TRUE;
}

int FmImportRapps(LPCWSTR srcDir, DWORD flags, int *skipped, FILE *log)
{
    WCHAR src[MAX_PATH], outDir[MAX_PATH], glob[MAX_PATH], file[MAX_PATH], outFile[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int written = 0, skip = 0;

    if (skipped) *skipped = 0;
    if (srcDir && srcDir[0])
        StringCchCopyW(src, MAX_PATH, srcDir);
    else if (!DefaultRappsDir(src, MAX_PATH))
    {
        LOGF(log, L"error: cannot locate the RAPPS database directory\n");
        return -1;
    }
    PathRemoveBackslashW(src);
    /* default location only: an explicit directory is the caller's to populate */
    if (!(srcDir && srcDir[0]) && !HasRappsEntries(src))
        FetchRappsDatabase(log);
    if (FmOpCancelled()) { FmSetLastMessage(L"The operation was cancelled."); return -1; }   /* before anything is rewritten */
    FmOpStep(L"Converting the RAPPS entries into Software-tab entries");
    if (!FmGetSoftwareCatalogDir(outDir, MAX_PATH)) return -1;
    SHCreateDirectoryExW(NULL, outDir, NULL);

    if (flags & FM_IMPORT_CLEAN)
    {
        StringCchPrintfW(glob, MAX_PATH, L"%s\\rapps-*.ini", outDir);
        h = FindFirstFileW(glob, &fd);
        if (h != INVALID_HANDLE_VALUE)
        {
            do {
                StringCchPrintfW(file, MAX_PATH, L"%s\\%s", outDir, fd.cFileName);
                DeleteFileW(file);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }

    StringCchPrintfW(glob, MAX_PATH, L"%s\\*.txt", src);
    h = FindFirstFileW(glob, &fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        LOGF(log, L"error: no RAPPS entries (*.txt) in '%s'. Check the network connection, "
                  L"run rapps once to fetch its database, or pass the directory.\n", src);
        return -1;
    }
    do
    {
        WCHAR pkg[MAX_PATH], name[FM_MAX_NAME], url[1024], v[1024], cat[16], id[FM_MAX_ID];
        FM_OUTBUF o = { NULL, 0, 0, FALSE };
        int catId;

        if (FmOpCancelled())
        {
            FindClose(h);
            FmSetLastMessage(L"The import was cancelled after %d entries; run it again to finish.", written);
            return -1;
        }
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        StringCchCopyW(pkg, MAX_PATH, fd.cFileName);
        PathRemoveExtensionW(pkg);
        if (!ValidPkgName(pkg)) { skip++; LOGF(log, L"skip: '%s' (unusable package name)\n", fd.cFileName); continue; }
        StringCchPrintfW(file, MAX_PATH, L"%s\\%s", src, fd.cFileName);

        if (!GetKey(file, L"Name", name, ARRAYSIZE(name), flags)
            || !GetKey(file, L"URLDownload", url, ARRAYSIZE(url), flags))
        {
            skip++;
            LOGF(log, L"skip: %s (no Name or no usable URLDownload for %s)\n", pkg, FM_ARCH);
            continue;
        }
        Flatten(name); Flatten(url);
        StringCchPrintfW(id, FM_MAX_ID, L"rapps-%s", pkg);

        FmOutLine(&o, L"", L"; Generated by featmgr /import-rapps from the RAPPS database. Do not edit;");
        FmOutLine(&o, L"", L"; regenerate with: featmgr /import-rapps");
        FmOutLine(&o, L"", L"[Feature]");
        FmOutLine(&o, L"Id", id);
        FmOutLine(&o, L"Name", name);
        CopyKey(&o, file, L"Description", L"Description", flags);
        if (GetKey(file, L"Version", v, ARRAYSIZE(v), flags)) { Flatten(v); FmOutLine(&o, L"Version", v); }
        FmOutLine(&o, L"Tier", L"software");
        if (GetKey(file, L"Dependencies", v, ARRAYSIZE(v), flags))
        {
            WCHAR deps[512];
            MapDependencies(src, v, deps, ARRAYSIZE(deps));
            FmOutLine(&o, L"Dependencies", deps);
        }
        else
            FmOutLine(&o, L"Dependencies", L"");

        FmOutLine(&o, L"", L"");
        FmOutLine(&o, L"", L"[Install]");
        FmOutLine(&o, L"Provider", L"rapps");

        FmOutLine(&o, L"", L"");
        FmOutLine(&o, L"", L"[Source]");
        FmOutLine(&o, L"Artifact", url);
        CopyKey(&o, file, L"SHA1", L"ArtifactSHA1", flags);
        CopyKey(&o, file, L"SizeBytes", L"SizeBytes", flags);
        BuildLicense(file, v, ARRAYSIZE(v), flags);
        if (v[0]) FmOutLine(&o, L"License", v);
        CopyKey(&o, file, L"Publisher", L"Publisher", flags);
        CopyKey(&o, file, L"URLSite", L"URLSite", flags);

        FmOutLine(&o, L"", L"");
        FmOutLine(&o, L"", L"[Rapps]");
        FmOutLine(&o, L"Pkg", pkg);
        catId = 0;
        if (GetKey(file, L"Category", cat, ARRAYSIZE(cat), flags)) catId = _wtoi(cat);
        if (catId < 0 || catId >= (int)ARRAYSIZE(g_Categories)) catId = 0;
        StringCchPrintfW(cat, ARRAYSIZE(cat), L"%d", catId);
        FmOutLine(&o, L"CategoryId", cat);
        FmOutLine(&o, L"Category", g_Categories[catId]);
        CopyKey(&o, file, L"RegName", L"RegName", flags);
        CopyKey(&o, file, L"Installer", L"Installer", flags);
        CopyKey(&o, file, L"SilentParameters", L"SilentParameters", flags);
        CopyKey(&o, file, L"NTVersion", L"NTVersion", flags);
        CopyKey(&o, file, L"Scope", L"Scope", flags);
        CopyKey(&o, file, L"SaveAs", L"SaveAs", flags);
        CopyKey(&o, file, L"LicenseType", L"LicenseType", flags);
        CopyKey(&o, file, L"Dependencies", L"Dependencies", flags);

        StringCchPrintfW(outFile, MAX_PATH, L"%s\\%s.ini", outDir, id);
        if (!o.fail && FmWriteManifest(outFile, &o))
            written++;
        else
        {
            skip++;
            LOGF(log, L"skip: %s (cannot write %s, %lu)\n", pkg, outFile, GetLastError());
        }
        if (o.buf) HeapFree(GetProcessHeap(), 0, o.buf);
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    if (skipped) *skipped = skip;
    LOGF(log, L"imported %d RAPPS entr%s into %s (%d skipped)\n", written,
         written == 1 ? L"y" : L"ies", outDir, skip);
    return written;
}
