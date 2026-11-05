/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager (FEATMGMT-01)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     featmgr.exe - CLI for automation (/list /query /enable /disable).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "featmgr.h"
#include <reactos/buildno.h>
#include <stdio.h>
#include <strsafe.h>
#include <tlhelp32.h>

/* Write a wide string to stdout as UTF-8 so file-based capture is readable. */
static void Out(LPCWSTR fmt, ...)
{
    WCHAR wbuf[2048];
    char abuf[4096];
    int n;
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(wbuf, 2047, fmt, ap);
    va_end(ap);
    wbuf[2047] = L'\0';
    n = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, abuf, sizeof(abuf), NULL, NULL);
    if (n > 0) fwrite(abuf, 1, n - 1, stdout);
    fflush(stdout);
}

static void Usage(void)
{
    Out(L"featmgr - " BRAND_PRODUCT_NAME_W L" Features manager (FEATMGMT-01)\n\n");
    Out(L"Usage:\n");
    Out(L"  featmgr /list [/state:<Enabled|Disabled|NotInstalled>] [/tier:<os|software>] [/source:<src>]\n");
    Out(L"                [/search:<text>] [/timing]\n");
    Out(L"                               list catalog features + state, version and installed version\n");
    Out(L"                               (optionally filtered; /search = case-insensitive, name + description)\n");
    Out(L"  featmgr /state   <id>        print just the state word (scripting)\n");
    Out(L"  featmgr /query   <id>        show one feature in detail\n");
    Out(L"  featmgr /enable  <id>        enable (install) an optional feature\n");
    Out(L"  featmgr /disable <id> [/cascade] [/force]  disable (revert); refused while enabled\n");
    Out(L"                               features depend on it unless /cascade. Software tier:\n");
    Out(L"                               runs the app's uninstaller; /force = proceed if it fails\n");
    Out(L"  featmgr /install <id>        alias for /enable (software tier: download + run installer)\n");
    Out(L"  featmgr /uninstall <id> [/force]  disable, then forget the record (-> NotInstalled)\n");
    Out(L"  featmgr /shell-defaults [/browser]\n");
    Out(L"                               make the desktop / Start shortcuts match what is installed (PowerShell 7 and\n");
    Out(L"                               Firefox, else Command Prompt; no Internet Explorer entry); /browser = Firefox default\n");
    Out(L"  featmgr /update-catalog      download the RAPPS online catalog (rappmgr2.cab, the address rapps used; certificate-pinned)\n");
    Out(L"                               into %%SystemRoot%%\\Featmgr\\RappsDb and convert it into software entries (Catalog\\Software)\n");
    Out(L"  featmgr /import-rapps [<appdb-dir>] [/clean] [/anyarch] [/refresh]\n");
    Out(L"                               convert a RAPPS database (default: the catalog /update-catalog downloaded; fetched when\n");
    Out(L"                               there is none, or again with /refresh) into Tier=software entries (Catalog\\Software).\n");
    Out(L"                               An entry without a SHA-256 or SHA-1 checksum is not offered.\n");
    Out(L"  featmgr /install <id|package>  a RAPPS package name (7zip) is looked up as rapps-<name>; the catalog is fetched if absent\n");
    Out(L"  featmgr /import-scoop [main|extras|<bucket> /trust] [/dir:<manifest-dir>] [/clean] [/limit:N]\n");
    Out(L"                       [/unverified]\n");
    Out(L"                               convert Scoop bucket manifests (read from the buckets Scoop already\n");
    Out(L"                               has) into Tier=software entries; no bucket = every official bucket\n");
    Out(L"                               present. Install/uninstall then run 'scoop install|uninstall'.\n");
    Out(L"                               /trust = explicit consent for a bucket that is not main/extras;\n");
    Out(L"                               /unverified = also import manifests without a hash\n");
    Out(L"  featmgr /scoop-buckets       list the buckets Scoop has, and Scoop's known (official) buckets\n");
    Out(L"  featmgr /add-bucket <name>   scoop bucket add <name> for one of Scoop's known buckets, then import it\n");
    Out(L"  featmgr /add-bucket <name> <https-url> /trust\n");
    Out(L"                               any other bucket: explicit consent (its manifests run PowerShell as admin)\n");
    Out(L"  featmgr /update <id>         Scoop app: 'scoop update <app>', then refresh its bucket entries\n");
    Out(L"  featmgr /update /all         'scoop update' (Scoop + buckets), re-import the buckets, 'scoop update *'\n");
    Out(L"                               (NitroOS: after a featmgr install/update of the Scoop apps vscode and vscode-insiders,\n");
    Out(L"                               terminal.integrated.windowsUseConptyDll=false is added to their settings if absent)\n");
    Out(L"  featmgr /print-path [/cmd]   the PATH a new process would get (registry machine + user PATH);\n");
    Out(L"                               used by refreshenv, which applies it to the current cmd/pwsh window\n");
    Out(L"  featmgr /help                this text\n");
}

/* featmgr /print-path [/cmd]: the PATH a new process would get, on one line, in the OEM code page (what
 * a cmd "for" or a PowerShell native call reads). /cmd prints it as a batch line: set "PATH=..." with % doubled.
 * refreshenv.cmd runs that line in the calling cmd.exe. */
static int DoPrintPath(int argc, WCHAR **argv)
{
    WCHAR *path = HeapAlloc(GetProcessHeap(), 0, 2 * 32768 * sizeof(WCHAR)), *line;
    char *oem;
    BOOL asCmd = argc > 2 && !_wcsicmp(argv[2], L"/cmd");
    size_t i, k = 0;
    int n;

    if (!path) return 3;
    line = path + 32768;
    if (!FmRefreshedPath(path, 32768)) { HeapFree(GetProcessHeap(), 0, path); return 3; }
    if (asCmd)
    {
        for (i = 0; path[i] && k < 32760; i++)
        {
            if (path[i] == L'%') line[k++] = L'%';
            line[k++] = path[i];
        }
        line[k] = L'\0';
    }
    else
        StringCchCopyW(line, 32768, path);
    oem = HeapAlloc(GetProcessHeap(), 0, 4 * 32768);
    if (!oem) { HeapFree(GetProcessHeap(), 0, path); return 3; }
    n = WideCharToMultiByte(CP_OEMCP, 0, line, -1, oem, 4 * 32768, NULL, NULL);
    if (n > 0)
    {
        if (asCmd) fputs("set \"PATH=", stdout);
        fwrite(oem, 1, n - 1, stdout);
        fputs(asCmd ? "\"\n" : "\n", stdout);
        fflush(stdout);
    }
    HeapFree(GetProcessHeap(), 0, oem);
    HeapFree(GetProcessHeap(), 0, path);
    return n > 0 ? 0 : 3;
}

static int DoList(int argc, WCHAR **argv)
{
    FM_FEATURE *arr;
    int n, i, shown = 0, a;
    int fState = -1, fTier = -1;
    LPCWSTR fSource = NULL, fSearch = NULL;
    BOOL timing = FALSE;
    DWORD t0, t1;

    for (a = 2; a < argc; a++)
    {
        if (!_wcsnicmp(argv[a], L"/state:", 7))
        {
            LPCWSTR v = argv[a] + 7;
            if (!_wcsicmp(v, L"Enabled")) fState = FM_STATE_ENABLED;
            else if (!_wcsicmp(v, L"Disabled")) fState = FM_STATE_DISABLED;
            else if (!_wcsicmp(v, L"NotInstalled")) fState = FM_STATE_NOT_INSTALLED;
            else { Out(L"error: bad state filter '%s'\n", v); return 2; }
        }
        else if (!_wcsnicmp(argv[a], L"/tier:", 6))
        {
            LPCWSTR v = argv[a] + 6;
            if (!_wcsicmp(v, L"os")) fTier = FM_TIER_OS;
            else if (!_wcsicmp(v, L"software")) fTier = FM_TIER_SOFTWARE;
            else { Out(L"error: bad tier filter '%s'\n", v); return 2; }
        }
        else if (!_wcsnicmp(argv[a], L"/source:", 8))
            fSource = argv[a] + 8;       /* "scoop" matches scoop/main and scoop/extras */
        else if (!_wcsnicmp(argv[a], L"/search:", 8))
            fSearch = argv[a] + 8;
        else if (!_wcsicmp(argv[a], L"/timing"))
            timing = TRUE;
        else { Out(L"error: unknown /list option '%s'\n", argv[a]); return 2; }
    }
    t0 = GetTickCount();
    n = FmEnumFeatures(&arr);
    t1 = GetTickCount();
    Out(L"%-18s %-9s %-13s %-12s %-12s %s\n", L"ID", L"TIER", L"STATE", L"VERSION", L"INSTALLED", L"NAME");
    Out(L"%-18s %-9s %-13s %-12s %-12s %s\n", L"------------------", L"---------",
        L"-------------", L"------------", L"------------", L"----");
    for (i = 0; i < n; i++)
    {
        WCHAR state[32];
        if (fState >= 0 && (int)arr[i].State != fState) continue;
        if (fTier >= 0 && (int)arr[i].Tier != fTier) continue;
        if (fSource && _wcsnicmp(arr[i].Source, fSource, wcslen(fSource))) continue;
        if (fSearch && !FmMatchSearch(&arr[i], fSearch)) continue;
        shown++;
        _snwprintf(state, 31, L"%s%s", FmStateStr(arr[i].State),
                   arr[i].PayloadAvailable ? L"" : L"*");
        Out(L"%-18s %-9s %-13s %-12s %-12s %s%s\n",
            arr[i].Id, FmTierStr(arr[i].Tier), state, arr[i].Version,
            arr[i].InstalledVersion[0] ? arr[i].InstalledVersion : L"-", arr[i].Name,
            arr[i].UpdateAvailable ? L"  [update available]" : L"");
    }
    Out(L"\n%d feature(s). '*' = payload not staged (catalog entry only).\n", shown);
    if (timing) Out(L"timing: enumerate %lu ms, %d entries loaded, total %lu ms\n", t1 - t0, n, GetTickCount() - t0);
    FmFree(arr);
    return 0;
}

static int DoQuery(LPCWSTR id)
{
    FM_FEATURE f;
    if (!FmFindFeature(id, &f))
    {
        Out(L"error: unknown feature '%s'\n", id);
        return 1;
    }
    Out(L"Id:           %s\n", f.Id);
    Out(L"Name:         %s\n", f.Name);
    Out(L"Tier:         %s\n", FmTierStr(f.Tier));
    Out(L"Version:      %s\n", f.Version);
    Out(L"InstalledVersion: %s\n", f.InstalledVersion[0] ? f.InstalledVersion : L"(not installed)");
    if (f.UpdateAvailable) Out(L"UpdateAvailable: Yes (%s -> %s)\n", f.InstalledVersion, f.Version);
    Out(L"State:        %s\n", FmStateStr(f.State));
    if (f.InstallDate[0]) Out(L"InstallDate:  %s\n", f.InstallDate);
    if (f.PendingReboot) Out(L"PendingReboot: Yes (removal completes at next reboot)\n");
    {
        WCHAR dep[FM_MAX_DEPS * 2];
        FmGetDependents(f.Id, dep, ARRAYSIZE(dep));
        Out(L"EnabledDependents: %s\n", dep[0] ? dep : L"(none)");
    }
    if (f.BuiltIn)
        Out(L"Payload:      included in this image (installed by setup; not removable here)\n");
    else if (f.Hosted && f.PayloadAvailable)
        Out(L"Payload:      downloaded at enable (%I64u bytes, SHA-256 checked)\n", FmHostedDownloadSize(f.ManifestPath));
    else if (f.Unavailable[0])
        Out(L"Payload:      NOT available: %s\n", f.Unavailable);
    else
        Out(L"Payload:      %s\n", f.PayloadAvailable ? L"staged" : L"NOT staged (deferred)");
    Out(L"Dependencies: %s\n", f.Dependencies[0] ? f.Dependencies : L"(none)");
    Out(L"Manifest:     %s\n", f.ManifestPath);
    Out(L"Description:  %s\n", f.Description);
    {
        WCHAR v[512];
        static const WCHAR *k[] = { L"Artifact", L"ArtifactSHA256", L"ArtifactSHA1", L"SizeBytes",
                                    L"License", L"Publisher", L"URLSite", L"BaseUrl", L"Path", L"Arch" };
        int i;
        if (f.Provider[0]) Out(L"Provider:     %s\n", f.Provider);
        if (f.Source[0]) Out(L"Source:       %s\n", f.Source);
        if (!_wcsicmp(f.Provider, L"scoop"))
        {
            Out(L"Scoop.App: %s\n", f.App);
            Out(L"Scoop.Bucket: %s\n", f.Bucket);
            if (f.Homepage[0]) Out(L"Scoop.Homepage: %s\n", f.Homepage);
            if (f.License[0]) Out(L"Scoop.License: %s\n", f.License);
            Out(L"Scoop.Verified: %d\n", f.Verified ? 1 : 0);
        }
        if (!_wcsicmp(f.Provider, L"scoop") && f.ManifestPath[0]
            && !_wcsicmp(f.ManifestPath + wcslen(f.ManifestPath) - 4, L".idx"))
            return 0;                                    /* index record: nothing else to read from the file */
        GetPrivateProfileStringW(L"Rapps", L"Pkg", L"", v, 512, f.ManifestPath);
        if (v[0]) Out(L"Rapps.Pkg:    %s\n", v);
        GetPrivateProfileStringW(L"Rapps", L"Category", L"", v, 512, f.ManifestPath);
        if (v[0]) Out(L"Category:     %s\n", v);
        for (i = 0; i < (int)ARRAYSIZE(k); i++)
        {
            GetPrivateProfileStringW(L"Source", k[i], L"", v, 512, f.ManifestPath);
            if (v[0]) Out(L"Source.%s: %s\n", k[i], v);
        }
        if (!_wcsicmp(f.Provider, L"component"))
        {
            /* the recipe lives in the component list, not in the manifest */
            FM_COMPONENT c;
            if (FmCompLoad(f.Id, &c))
            {
                Out(L"Source.Artifact: %s\n", c.Url);
                Out(L"Source.ArtifactSHA256: %s\n", c.Sha256);
                if (c.Size) Out(L"Source.SizeBytes: %I64u\n", FmCompTotalSize(&c));
            }
        }
    }
    return 0;
}

static int DoAddBucket(int argc, WCHAR **argv)
{
    LPCWSTR name = NULL, url = NULL;
    DWORD fl = 0;
    int a;

    for (a = 2; a < argc; a++)
    {
        if (!_wcsicmp(argv[a], L"/trust")) fl |= FM_BUCKET_TRUST;
        else if (argv[a][0] != L'/' && !name) name = argv[a];
        else if (argv[a][0] != L'/' && !url) url = argv[a];
        else { Out(L"error: unknown /add-bucket option '%s'\n", argv[a]); return 2; }
    }
    if (!name) { Out(L"error: /add-bucket needs a bucket name\n"); return 2; }
    return SUCCEEDED(FmScoopAddBucket(name, url, fl, stdout)) ? 0 : 3;
}

static int DoImportRapps(int argc, WCHAR **argv)
{
    LPCWSTR dir = NULL;
    DWORD fl = 0;
    int a, n, skipped = 0;

    for (a = 2; a < argc; a++)
    {
        if (!_wcsicmp(argv[a], L"/clean")) fl |= FM_IMPORT_CLEAN;
        else if (!_wcsicmp(argv[a], L"/anyarch")) fl |= FM_IMPORT_ANYARCH;
        else if (!_wcsicmp(argv[a], L"/refresh")) fl |= FM_IMPORT_REFETCH;
        else if (argv[a][0] != L'/' && !dir) dir = argv[a];
        else { Out(L"error: unknown /import-rapps option '%s'\n", argv[a]); return 2; }
    }
    n = FmImportRapps(dir, fl, &skipped, stdout);
    return n < 0 ? 3 : 0;
}

/* featmgr /update-catalog: fetch the online RAPPS catalog again and rebuild the entries */
static int DoUpdateCatalog(void)
{
    int n, skipped = 0;
    n = FmImportRapps(NULL, FM_IMPORT_CLEAN | FM_IMPORT_REFETCH, &skipped, stdout);
    if (n < 0)
    {
        WCHAR why[1024];
        FmGetLastMessage(why, ARRAYSIZE(why));
        if (why[0]) Out(L"error: %s\n", why);
        return 3;
    }
    return 0;
}

/* /install <name>: a feature id, else a RAPPS package name (rapps-<name>); with no catalog yet, fetch it once */
static BOOL ResolveInstallId(LPCWSTR in, WCHAR *out, size_t cch)
{
    FM_FEATURE f;
    WCHAR dir[MAX_PATH], glob[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    BOOL have;

    StringCchCopyW(out, cch, in);
    if (FmFindFeature(in, &f)) return TRUE;
    StringCchPrintfW(out, cch, L"rapps-%s", in);
    if (FmFindFeature(out, &f)) return TRUE;
    if (FmGetRappsDbDir(dir, MAX_PATH))
    {
        StringCchPrintfW(glob, MAX_PATH, L"%s\\*.txt", dir);
        h = FindFirstFileW(glob, &fd);
        have = h != INVALID_HANDLE_VALUE;
        if (have) FindClose(h);
        if (!have)
        {
            Out(L"'%s' is not in the catalog yet; fetching the RAPPS catalog\n", in);
            if (FmImportRapps(NULL, FM_IMPORT_CLEAN, NULL, stdout) > 0 && FmFindFeature(out, &f)) return TRUE;
        }
    }
    StringCchCopyW(out, cch, in);
    return FALSE;
}

static int DoImportScoop(int argc, WCHAR **argv)
{
    LPCWSTR bucket = NULL, dir = NULL;
    DWORD fl = 0;
    int a, n, skipped = 0, limit = 0;
    BOOL timing = FALSE;
    DWORD t0;

    for (a = 2; a < argc; a++)
    {
        if (!_wcsicmp(argv[a], L"/timing")) timing = TRUE;
        else if (!_wcsicmp(argv[a], L"/clean")) fl |= FM_SCOOP_CLEAN;
        else if (!_wcsicmp(argv[a], L"/trust")) fl |= FM_SCOOP_TRUST;
        else if (!_wcsicmp(argv[a], L"/unverified")) fl |= FM_SCOOP_UNVERIFIED;
        else if (!_wcsnicmp(argv[a], L"/dir:", 5)) dir = argv[a] + 5;
        else if (!_wcsnicmp(argv[a], L"/limit:", 7)) limit = _wtoi(argv[a] + 7);
        else if (argv[a][0] != L'/' && !bucket) bucket = argv[a];
        else { Out(L"error: unknown /import-scoop option '%s'\n", argv[a]); return 2; }
    }
    if (dir && !bucket) { Out(L"error: /dir needs a bucket name\n"); return 2; }
    t0 = GetTickCount();
    n = FmImportScoop(bucket, dir, fl, limit, &skipped, stdout);
    if (timing) Out(L"timing: import %lu ms\n", GetTickCount() - t0);
    return n < 0 ? 3 : 0;
}

/* flags after the feature id: /cascade /force */
static DWORD ParseDisableFlags(int argc, WCHAR **argv, int from)
{
    DWORD fl = 0;
    int a;
    for (a = from; a < argc; a++)
    {
        if (!_wcsicmp(argv[a], L"/cascade")) fl |= FM_DISABLE_CASCADE;
        else if (!_wcsicmp(argv[a], L"/force")) fl |= FM_DISABLE_FORCE;
    }
    return fl;
}

/* After an install that changed PATH: say so, once, as the last line(s) of the run. The shell that started
 * featmgr keeps its old PATH (as on Windows, where a child cannot change its parent's environment). */
static int ParentShellKind(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    DWORD me = GetCurrentProcessId(), parent = 0;
    int kind = FM_SHELL_OTHER;

    if (snap == INVALID_HANDLE_VALUE) return FM_SHELL_OTHER;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
    {
        do { if (pe.th32ProcessID == me) { parent = pe.th32ParentProcessID; break; } }
        while (Process32NextW(snap, &pe));
    }
    if (parent && Process32FirstW(snap, &pe))
    {
        do
        {
            if (pe.th32ProcessID == parent)
            {
                if (!_wcsicmp(pe.szExeFile, L"pwsh.exe") || !_wcsicmp(pe.szExeFile, L"powershell.exe"))
                    kind = FM_SHELL_POWERSHELL;
                else if (!_wcsicmp(pe.szExeFile, L"cmd.exe"))
                    kind = FM_SHELL_CMD;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return kind;
}

static void PrintPathHint(void)
{
    WCHAR name[128], text[1024];
    if (!FmTakePathChange(name, ARRAYSIZE(name))) return;
    FmPathHint(name, ParentShellKind(), text, ARRAYSIZE(text));
    Out(L"\n%s", text);
}

int wmain(int argc, WCHAR **argv)
{
    LPCWSTR cmd;
    HRESULT hr;

    if (argc < 2) { Usage(); return 0; }
    cmd = argv[1];

    if (!_wcsicmp(cmd, L"/list") || !_wcsicmp(cmd, L"list"))
        return DoList(argc, argv);

    if (!_wcsicmp(cmd, L"/help") || !_wcsicmp(cmd, L"/?") || !_wcsicmp(cmd, L"help"))
    { Usage(); return 0; }

    if (!_wcsicmp(cmd, L"/shell-defaults"))
    {
        /* repair: shortcuts and Firefox policies match what is installed; /browser also makes Firefox the default */
        FmShellDefaults(argc > 2 && !_wcsicmp(argv[2], L"/browser") ? FM_SHELL_ADOPT_BROWSER : 0, stdout);
        return 0;
    }

    if (!_wcsicmp(cmd, L"/print-path") || !_wcsicmp(cmd, L"print-path"))
        return DoPrintPath(argc, argv);

    if (!_wcsicmp(cmd, L"/import-rapps") || !_wcsicmp(cmd, L"import-rapps"))
        return DoImportRapps(argc, argv);

    if (!_wcsicmp(cmd, L"/update-catalog") || !_wcsicmp(cmd, L"update-catalog"))
        return DoUpdateCatalog();

    /* the native install helpers the engine runs as child processes (native.c, natgen.c): not for people */
    if (!_wcsicmp(cmd, L"/nat-uninstall"))
        return FmNativeUninstallMain(argc, argv);
    if (!_wcsicmp(cmd, L"/nat-install"))
        return FmNativeInstallMain(argc, argv);

    if (!_wcsicmp(cmd, L"/import-scoop") || !_wcsicmp(cmd, L"import-scoop"))
        return DoImportScoop(argc, argv);

    if (!_wcsicmp(cmd, L"/scoop-buckets") || !_wcsicmp(cmd, L"scoop-buckets"))
        return FmScoopListBuckets(stdout) < 0 ? 3 : 0;

    if (!_wcsicmp(cmd, L"/add-bucket") || !_wcsicmp(cmd, L"add-bucket"))
        return DoAddBucket(argc, argv);

    if (!_wcsicmp(cmd, L"/update") || !_wcsicmp(cmd, L"update"))
    {
        if (argc < 3) { Out(L"error: /update needs a feature id or /all\n"); return 2; }
        if (!_wcsicmp(argv[2], L"/all"))
            return SUCCEEDED(FmUpdateAll(stdout)) ? 0 : 3;
        return SUCCEEDED(FmUpdate(argv[2], stdout)) ? 0 : 3;
    }

    if (argc < 3) { Out(L"error: missing feature id\n\n"); Usage(); return 2; }

    if (!_wcsicmp(cmd, L"/query") || !_wcsicmp(cmd, L"query"))
        return DoQuery(argv[2]);

    if (!_wcsicmp(cmd, L"/state") || !_wcsicmp(cmd, L"state"))
    {
        FM_FEATURE f;
        if (!FmFindFeature(argv[2], &f)) { Out(L"Unknown\n"); return 1; }
        Out(L"%s\n", FmStateStr(f.State));
        return 0;
    }

    if (!_wcsicmp(cmd, L"/enable") || !_wcsicmp(cmd, L"/install")
        || !_wcsicmp(cmd, L"enable") || !_wcsicmp(cmd, L"install"))
    {
        WCHAR rid[FM_MAX_ID];
        if (!ResolveInstallId(argv[2], rid, ARRAYSIZE(rid)))
        { Out(L"error: unknown feature '%s'\n", argv[2]); return 3; }
        hr = FmEnable(rid, stdout);
        if (SUCCEEDED(hr)) PrintPathHint();
        return SUCCEEDED(hr) ? 0 : 3;
    }

    if (!_wcsicmp(cmd, L"/disable") || !_wcsicmp(cmd, L"disable"))
    {
        hr = FmDisableEx(argv[2], ParseDisableFlags(argc, argv, 3), stdout);
        return SUCCEEDED(hr) ? 0 : 3;
    }

    if (!_wcsicmp(cmd, L"/uninstall") || !_wcsicmp(cmd, L"uninstall"))
    {
        hr = FmUninstallEx(argv[2], ParseDisableFlags(argc, argv, 3), stdout);
        return SUCCEEDED(hr) ? 0 : 3;
    }

    Out(L"error: unknown command '%s'\n\n", cmd);
    Usage();
    return 2;
}
