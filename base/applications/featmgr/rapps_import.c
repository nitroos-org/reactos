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
 *   SHA256, MsiProperties      [Source] ArtifactSHA256, [Rapps] MsiProperties
 *   [Generate], [ExeInZip]     the same sections of the manifest (arch section wins)
 *   (fixed)                    [Install] Provider=native  -> featmgr itself downloads, checks the
 *                              hash and runs the installer (native.c); rapps.exe is not involved
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

/* exactly n hex digits (SHA-256: 64, SHA-1: 40) */
static BOOL IsHexDigest(LPCWSTR s, size_t n)
{
    size_t i;
    if (wcslen(s) != n) return FALSE;
    for (i = 0; i < n; i++)
        if (!((s[i] >= L'0' && s[i] <= L'9') || (s[i] >= L'a' && s[i] <= L'f') || (s[i] >= L'A' && s[i] <= L'F'))) return FALSE;
    return TRUE;
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

/* [<sec>.<arch>] then [<sec>] of a RAPPS entry (the Generate / ExeInZip sections) */
static BOOL GetSecKey(LPCWSTR file, LPCWSTR sec, LPCWSTR key, LPWSTR out, DWORD cch)
{
    WCHAR s[64];
    StringCchPrintfW(s, ARRAYSIZE(s), L"%s.%s", sec, FM_ARCH);
    GetPrivateProfileStringW(s, key, NOTFOUND, out, cch, file);
    if (out[0] && out[0] != 1) return TRUE;
    GetPrivateProfileStringW(sec, key, NOTFOUND, out, cch, file);
    if (out[0] && out[0] != 1) return TRUE;
    out[0] = L'\0';
    return FALSE;
}

static void CopySecKey(FM_OUTBUF *o, LPCWSTR file, LPCWSTR sec, LPCWSTR key)
{
    WCHAR v[1024];
    if (GetSecKey(file, sec, key, v, ARRAYSIZE(v)))
    {
        Flatten(v);
        FmOutLine(o, key, v);
    }
}

/* RAPPS NTVersion: "Max-", "Min-Max", "Min" or "Min+" (major<<8 | minor), as CAvailableApplicationInfo::IsCompatible */
static ULONG NtVersionNow(void)
{
    typedef LONG (WINAPI *PFN_RGV)(PRTL_OSVERSIONINFOW);
    PFN_RGV p = (PFN_RGV)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    RTL_OSVERSIONINFOW v;
    ZeroMemory(&v, sizeof(v));
    v.dwOSVersionInfoSize = sizeof(v);
    if (!p || p(&v)) return 0x0A00;
    return (v.dwMajorVersion << 8) | v.dwMinorVersion;
}

static BOOL NtCompatible(LPCWSTR file, DWORD flags)
{
    WCHAR v[64], *p;
    ULONG minV, maxV, now;
    if (!GetKey(file, L"NTVersion", v, ARRAYSIZE(v), flags)) return TRUE;
    minV = wcstoul(v, &p, 0);
    if (p == v) return TRUE;
    maxV = (*p == L'-') ? wcstoul(p + 1, NULL, 0) : 0xFFFFFFFFu;
    if (maxV == 0) { maxV = minV; minV = 0; }
    now = NtVersionNow();
    return now >= minV && now <= maxV;
}

/* nitro replaces these upstream packages: Firefox is the native "firefox" entry (current release, SHA-256 checked); the two
 * 2016-era Firefox builds and the unpinned "latest ESR" redirect of the old overlay are not offered; WineVDM is the catalog
 * entry "winevdm" (same installer, SHA-256 checked, no catalog download needed), so the RAPPS copy would list it twice */
static BOOL HiddenPkg(LPCWSTR pkg)
{
    static const LPCWSTR hidden[] = { L"firefox", L"firefox-esr", L"firefox28", L"firefox36", L"winevdm" };
    int i;
    for (i = 0; i < (int)ARRAYSIZE(hidden); i++)
        if (!_wcsicmp(pkg, hidden[i])) return TRUE;
    return FALSE;
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
    else if (!FmGetRappsDbDir(src, MAX_PATH))
    {
        LOGF(log, L"error: cannot locate the RAPPS database directory\n");
        return -1;
    }
    PathRemoveBackslashW(src);
    /* default location only (an explicit directory is the caller's to populate): fetch the online catalog ourselves when
     * there is none yet, or when a refresh was asked for. A failed refresh keeps the catalog that is there. */
    if (!(srcDir && srcDir[0]) && (!HasRappsEntries(src) || (flags & FM_IMPORT_REFETCH)))
    {
        HRESULT fh = FmRappsFetchDb(NULL, log);
        if (FAILED(fh))
        {
            WCHAR why[512];
            FmGetLastMessage(why, ARRAYSIZE(why));
            LOGF(log, L"error: could not fetch the RAPPS catalog: %s\n", why);
            if (!HasRappsEntries(src)) return -1;
        }
    }
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
        if (HiddenPkg(pkg)) { skip++; LOGF(log, L"skip: %s (replaced by a native entry)\n", pkg); continue; }
        StringCchPrintfW(file, MAX_PATH, L"%s\\%s", src, fd.cFileName);
        if (!NtCompatible(file, flags)) { skip++; LOGF(log, L"skip: %s (needs another Windows version)\n", pkg); continue; }

        if (!GetKey(file, L"Name", name, ARRAYSIZE(name), flags)
            || !GetKey(file, L"URLDownload", url, ARRAYSIZE(url), flags))
        {
            skip++;
            LOGF(log, L"skip: %s (no Name or no usable URLDownload for %s)\n", pkg, FM_ARCH);
            continue;
        }
        Flatten(name); Flatten(url);
        /* a download is installed only after its hash is checked: an entry with neither SHA-256 nor SHA-1 is not offered */
        {
            WCHAR h256[160], h1[160];
            BOOL has256 = GetKey(file, L"SHA256", h256, ARRAYSIZE(h256), flags);
            BOOL has1 = GetKey(file, L"SHA1", h1, ARRAYSIZE(h1), flags);
            if (!has256 && !has1)
            {
                skip++;
                LOGF(log, L"skip: %s (no SHA-256 or SHA-1 checksum, so it could not be verified)\n", pkg);
                continue;
            }
            /* a checksum that is not a hex string of the right length can never match: the download would only fail later */
            if ((has256 && !IsHexDigest(h256, 64)) || (has1 && !IsHexDigest(h1, 40)))
            {
                skip++;
                LOGF(log, L"skip: %s (the SHA-256 / SHA-1 checksum is malformed: %d / %d hex digits expected)\n", pkg, 64, 40);
                continue;
            }
        }
        StringCchPrintfW(id, FM_MAX_ID, L"rapps-%s", pkg);

        FmOutLine(&o, L"", L"; Generated by featmgr /import-rapps from the RAPPS database. Do not edit;");
        FmOutLine(&o, L"", L"; regenerate with: featmgr /import-rapps");
        FmOutLine(&o, L"", L"[Feature]");
        FmOutLine(&o, L"Id", id);
        FmOutLine(&o, L"Name", name);
        CopyKey(&o, file, L"Description", L"Description", flags);
        if (GetKey(file, L"Version", v, ARRAYSIZE(v), flags)) { Flatten(v); FmOutLine(&o, L"Version", v); }
        FmOutLine(&o, L"Tier", L"software");
        catId = 0;
        if (GetKey(file, L"Category", cat, ARRAYSIZE(cat), flags)) catId = _wtoi(cat);
        if (catId < 0 || catId >= (int)ARRAYSIZE(g_Categories)) catId = 0;
        FmOutLine(&o, L"Group", g_Categories[catId]);
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
        FmOutLine(&o, L"Provider", L"native");

        FmOutLine(&o, L"", L"");
        FmOutLine(&o, L"", L"[Source]");
        FmOutLine(&o, L"Artifact", url);
        CopyKey(&o, file, L"SHA256", L"ArtifactSHA256", flags);
        CopyKey(&o, file, L"SHA1", L"ArtifactSHA1", flags);
        CopyKey(&o, file, L"SizeBytes", L"SizeBytes", flags);
        BuildLicense(file, v, ARRAYSIZE(v), flags);
        if (v[0]) FmOutLine(&o, L"License", v);
        CopyKey(&o, file, L"Publisher", L"Publisher", flags);
        CopyKey(&o, file, L"URLSite", L"URLSite", flags);

        FmOutLine(&o, L"", L"");
        FmOutLine(&o, L"", L"[Rapps]");
        FmOutLine(&o, L"Pkg", pkg);
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
        CopyKey(&o, file, L"MsiProperties", L"MsiProperties", flags);
        /* [Generate] is imported when it has any of its keys: without a Files line the install defaults to "*.exe|*.*", but the
         * Dir and the cleanup lists still apply (27 catalog entries have no Files line) */
        {
            static const LPCWSTR gk[] = { L"Files", L"Dir", L"Icon", L"Lnk", L"LnkParameters", L"DelFile", L"DelDir",
                                          L"DelDirEmpty", L"DelReg", L"DelRegEmpty" };
            int k;
            BOOL any = FALSE;
            for (k = 0; k < (int)ARRAYSIZE(gk) && !any; k++) any = GetSecKey(file, L"Generate", gk[k], v, ARRAYSIZE(v));
            if (any)
            {
            FmOutLine(&o, L"", L"");
            FmOutLine(&o, L"", L"[Generate]");
            for (k = 0; k < (int)ARRAYSIZE(gk); k++) CopySecKey(&o, file, L"Generate", gk[k]);
            }
        }
        if (GetSecKey(file, L"ExeInZip", L"Exe", v, ARRAYSIZE(v)) || GetSecKey(file, L"ExeInZip", L"Installer", v, ARRAYSIZE(v)))
        {
            FmOutLine(&o, L"", L"");
            FmOutLine(&o, L"", L"[ExeInZip]");
            CopySecKey(&o, file, L"ExeInZip", L"Installer");
            CopySecKey(&o, file, L"ExeInZip", L"Exe");
        }

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
