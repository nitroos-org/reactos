/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NitroOS shell defaults that follow the first-boot components: PowerShell 7 is the headline shell on the
 *              desktop and in the Start menu, Firefox replaces the Wine Internet Explorer entry and is the default
 *              browser. Idempotent: it looks at what is installed and makes the shortcuts match, so it also puts the
 *              Command Prompt desktop shortcut and the Internet Explorer entry back when pwsh or Firefox is removed
 *              (and while they are not installed yet, which is the image's own state).
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
static const WCHAR NAME_IE[]   = L"Wine Internet Explorer";
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
        if (!LinkTarget(path, tgt, ARRAYSIZE(tgt), args, ARRAYSIZE(args))) continue;
        if (_wcsicmp(PathFindFileNameW(tgt), exe)) continue;
        if (del && args[0]) continue;                /* a shortcut with arguments is the user's own, not the stock entry */
        n++;
        if (del)
        {
            BOOL ok = DeleteFileW(path);
            LOGF(log, L"  shortcut: removed %s %s\n", path, ok ? L"ok" : L"FAILED");
            if (ok) SHChangeNotify(SHCNE_DELETE, SHCNF_PATHW | SHCNF_FLUSH, path, NULL);   /* the open desktop drops the icon */
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

/* Firefox enterprise policies: never ask to be the default browser, no first-run / what's-new pages, no about:welcome
 * onboarding (its "make default" step), no profile import wizard. The Mozilla Terms of Use / privacy notice consent
 * (policy SkipTermsOfUse) is NOT skipped: accepting it is the user's own act. Written only when the file is absent:
 * an administrator's own policies.json is never replaced. */
static void WriteFirefoxPolicies(FILE *log)
{
    static const char json[] =
        "{\r\n"
        "  \"policies\": {\r\n"
        "    \"DontCheckDefaultBrowser\": true,\r\n"
        "    \"DisableDefaultBrowserAgent\": true,\r\n"
        "    \"OverrideFirstRunPage\": \"\",\r\n"
        "    \"OverridePostUpdatePage\": \"\",\r\n"
        "    \"DisableProfileImport\": true,\r\n"
        "    \"UserMessaging\": { \"SkipOnboarding\": true }\r\n"
        "  }\r\n"
        "}\r\n";
    WCHAR dir[MAX_PATH], file[MAX_PATH];
    HANDLE h;
    DWORD w;

    if (!ProgFile(L"Mozilla Firefox\\distribution", dir, ARRAYSIZE(dir))) return;
    StringCchPrintfW(file, ARRAYSIZE(file), L"%s\\policies.json", dir);
    if (FileExists(file)) { LOGF(log, L"  firefox: %s exists, left alone\n", file); return; }
    EnsureDir(dir);
    h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { LOGF(log, L"  firefox: cannot write %s (error %lu)\n", file, GetLastError()); return; }
    WriteFile(h, json, sizeof(json) - 1, &w, NULL);
    CloseHandle(h);
    LOGF(log, L"  firefox: wrote %s\n", file);
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
    WCHAR winsys[MAX_PATH], pwsh[MAX_PATH], ff[MAX_PATH], ie[MAX_PATH], cmd[MAX_PATH];
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
    if (!ProgFile(L"Internet Explorer\\iexplore.exe", ie, ARRAYSIZE(ie))) ie[0] = L'\0';
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

    /* the browser: Firefox replaces the Wine Internet Explorer entry (iexplore stays installed) */
    if (haveFf)
    {
        WriteFirefoxPolicies(log);
        StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", desk[0], NAME_FF);
        if (!LinksToIn(desk, NULL, L"firefox.exe", FALSE, NULL)) MakeLink(lnk, ff, NULL, L"Mozilla Firefox", log);
        StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", progs[0], NAME_FF);
        if (!LinksToIn(progs, NULL, L"firefox.exe", FALSE, NULL)) MakeLink(lnk, ff, NULL, L"Mozilla Firefox", log);
        LinksToIn(progs, NULL, L"iexplore.exe", TRUE, log);
        LinksToIn(desk, NULL, L"iexplore.exe", TRUE, log);
        if (flags & FM_SHELL_ADOPT_BROWSER) RunBchooser(L"/installfirefox", log);
    }
    else
    {
        LinksToIn(desk, NULL, L"firefox.exe", TRUE, log);
        LinksToIn(progs, NULL, L"firefox.exe", TRUE, log);
        if (ie[0] && FileExists(ie) && !LinksToIn(progs, NULL, L"iexplore.exe", FALSE, NULL))
        {
            StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", progs[0], NAME_IE);
            MakeLink(lnk, ie, NULL, L"Wine Internet Explorer", log);
        }
        if (flags & FM_SHELL_FORGET_BROWSER) RunBchooser(L"/set IEXPLORE.EXE", log);
    }

    Refresh(desk);
    Refresh(progs);
    if (comInit) CoUninitialize();
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSH, NULL, NULL);
}
