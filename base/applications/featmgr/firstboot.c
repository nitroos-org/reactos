/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     optfeatures /firstboot: after logon, once the network is up, install the default components (the
 *              Default=1 entries of components.ini, in file order: PowerShell 7, Firefox, .NET Framework 4.8) with the "Installing additional
 *              components" window. Started by a HKLM Run entry. It runs to completion once and records the result;
 *              it never blocks logon (it is its own process), waits quietly and without a window while there is no
 *              network, and comes back at the next logon. Switch it off: HKLM\SOFTWARE\ReactOS\Nitro\Featmgr
 *              AutoInstall=0 (DWORD) or delete the Run value "NitroComponents".
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "featmgr.h"
#include <shellapi.h>
#include <strsafe.h>
#include <stdarg.h>

static const WCHAR KEY_FB[] = L"SOFTWARE\\ReactOS\\Nitro\\Featmgr";
#define MAX_ATTEMPTS 3

BOOL FmGetLogDir(LPWSTR buf, DWORD cch)
{
    WCHAR root[MAX_PATH];
    if (!FmGetRootDir(root, MAX_PATH)) return FALSE;
    CreateDirectoryW(root, NULL);
    if (FAILED(StringCchPrintfW(buf, cch, L"%s\\Logs", root))) return FALSE;
    return CreateDirectoryW(buf, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

void FmLogLine(LPCWSTR logFile, LPCWSTR fmt, ...)
{
    WCHAR text[1200], line[1300];
    char u8[4000];
    SYSTEMTIME st;
    HANDLE h;
    DWORD w;
    int n;
    va_list ap;

    if (!logFile || !logFile[0]) return;
    va_start(ap, fmt);
    _vsnwprintf(text, ARRAYSIZE(text) - 1, fmt, ap);
    va_end(ap);
    text[ARRAYSIZE(text) - 1] = L'\0';
    GetSystemTime(&st);
    StringCchPrintfW(line, ARRAYSIZE(line), L"%04u-%02u-%02uT%02u:%02u:%02uZ %s\r\n",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, text);
    n = WideCharToMultiByte(CP_UTF8, 0, line, -1, u8, sizeof(u8), NULL, NULL);
    if (n <= 1) return;
    h = CreateFileW(logFile, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    WriteFile(h, u8, n - 1, &w, NULL);
    CloseHandle(h);
}

static BOOL GetDw(LPCWSTR name, DWORD *v)
{
    HKEY k;
    DWORD cb = sizeof(*v), type;
    BOOL ok = FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, KEY_FB, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return FALSE;
    ok = RegQueryValueExW(k, name, NULL, &type, (LPBYTE)v, &cb) == ERROR_SUCCESS && type == REG_DWORD;
    RegCloseKey(k);
    return ok;
}

static void SetDw(LPCWSTR name, DWORD v)
{
    HKEY k;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, KEY_FB, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) != ERROR_SUCCESS) return;
    RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
    RegCloseKey(k);
}

static void SetSz(LPCWSTR name, LPCWSTR v)
{
    HKEY k;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, KEY_FB, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) != ERROR_SUCCESS) return;
    RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)v, (DWORD)((wcslen(v) + 1) * sizeof(WCHAR)));
    RegCloseKey(k);
}

static void Stamp(LPCWSTR name)
{
    SYSTEMTIME st;
    WCHAR t[40];
    GetSystemTime(&st);
    StringCchPrintfW(t, ARRAYSIZE(t), L"%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    SetSz(name, t);
}

static BOOL IsAdmin(void)
{
    BOOL is = FALSE;
    PSID sid = NULL;
    SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid))
    {
        if (!CheckTokenMembership(NULL, sid, &is)) is = FALSE;
        FreeSid(sid);
    }
    return is;
}

/* the default components this machine still lacks, as jobs; first URL for the network probe */
static int NeededJobs(FM_JOB *jobs, int max, LPWSTR probeUrl, DWORD cch, LPCWSTR logFile)
{
    FM_COMPONENT *arr;
    int n = FmCompEnum(&arr), i, k = 0;
    probeUrl[0] = L'\0';
    for (i = 0; i < n && k < max; i++)
    {
        FM_FEATURE f;
        if (!arr[i].Default || !arr[i].ArchOk) continue;
        if (FmCompDetect(&arr[i])) { FmLogLine(logFile, L"%s: already installed", arr[i].Id); continue; }
        if (!FmFindFeature(arr[i].Id, &f)) { FmLogLine(logFile, L"%s: no catalog entry, skipped", arr[i].Id); continue; }
        ZeroMemory(&jobs[k], sizeof(jobs[k]));
        StringCchCopyW(jobs[k].id, FM_MAX_ID, arr[i].Id);
        StringCchCopyW(jobs[k].name, FM_MAX_NAME, arr[i].Name);
        jobs[k].action = FM_JOB_INSTALL;
        if (!probeUrl[0]) StringCchCopyW(probeUrl, cch, arr[i].Url);
        k++;
    }
    FmCompFree(arr);
    return k;
}

int FmFirstBootMain(HINSTANCE hInst, LPCWSTR cmd)
{
    WCHAR log[MAX_PATH], url[512], sysdir[MAX_PATH], root[4];
    FM_JOB jobs[8];
    FM_UIRESULT res;
    HANDLE mutex;
    DWORD v = 0, waitMin = 30, attempts = 0, t0;
    BOOL force = cmd && wcsstr(cmd, L"/force");
    int n, rc;
    LPCWSTR wp = cmd ? wcsstr(cmd, L"/waitmin:") : NULL;

    (void)hInst;
    if (wp) waitMin = (DWORD)_wtoi(wp + 9);
    log[0] = L'\0';
    if (FmGetLogDir(log, ARRAYSIZE(log))) StringCchCatW(log, ARRAYSIZE(log), L"\\firstboot.log");

    mutex = CreateMutexW(NULL, FALSE, L"Global\\NitroFeatmgrFirstBoot");
    if (mutex && GetLastError() == ERROR_ALREADY_EXISTS) return 0;       /* another logon already runs it */

    if (GetDw(L"AutoInstall", &v) && v == 0 && !force)
    {
        FmLogLine(log, L"first boot: switched off (AutoInstall=0)");
        return 0;
    }
    if (GetSystemDirectoryW(sysdir, MAX_PATH) && sysdir[1] == L':')
    {
        UINT dt;
        root[0] = sysdir[0]; root[1] = L':'; root[2] = L'\\'; root[3] = L'\0';
        dt = GetDriveTypeW(root);
        if ((dt == DRIVE_CDROM || dt == DRIVE_RAMDISK) && !force)
        {
            FmLogLine(log, L"first boot: running from a CD or RAM disk, nothing to install");
            return 0;
        }
    }
    if (!force && GetDw(L"Done", &v) && v == 1) return 0;                /* quiet: the common case on every later logon */
    if (!IsAdmin())
    {
        FmLogLine(log, L"first boot: this user is not an administrator, will try at the next logon");
        return 0;
    }
    GetDw(L"Attempts", &attempts);
    FmLogLine(log, L"first boot: started (attempt %lu)", attempts + 1);

    n = NeededJobs(jobs, ARRAYSIZE(jobs), url, ARRAYSIZE(url), log);
    if (!n)
    {
        FmLogLine(log, L"first boot: every default component is already installed, no window");
        FmShellDefaults(0, NULL);                                        /* e.g. pwsh installed by hand: desktop matches */
        SetDw(L"Done", 1);
        SetSz(L"Result", L"AlreadyInstalled");
        Stamp(L"CompletedUtc");
        return 0;
    }

    /* wait for the network without a window; the next logon tries again when it never comes up */
    t0 = GetTickCount();
    for (;;)
    {
        if (FmNetProbe(url, 10000)) break;
        if (GetTickCount() - t0 >= waitMin * 60000u)
        {
            FmLogLine(log, L"first boot: no network after %lu minutes, will try again at the next logon", waitMin);
            Stamp(L"LastTryUtc");
            SetSz(L"Result", L"WaitingForNetwork");
            return 0;
        }
        Sleep(15000);
    }
    FmLogLine(log, L"first boot: network is up (%lu s), %d component(s) to install", (GetTickCount() - t0) / 1000, n);
    n = NeededJobs(jobs, ARRAYSIZE(jobs), url, ARRAYSIZE(url), log);     /* somebody may have installed it meanwhile */
    if (!n)
    {
        SetDw(L"Done", 1);
        SetSz(L"Result", L"AlreadyInstalled");
        Stamp(L"CompletedUtc");
        return 0;
    }

    ZeroMemory(&res, sizeof(res));
    rc = FmRunJobsUI(NULL, jobs, n, FM_UI_AUTOCLOSE, log, &res);
    Stamp(L"LastTryUtc");
    if (rc == 0)
    {
        SetDw(L"Done", 1);
        SetSz(L"Result", L"Installed");
        Stamp(L"CompletedUtc");
        FmLogLine(log, L"first boot: finished, %d component(s) installed", res.ok);
    }
    else if (rc == 2)
    {
        /* the user said no: do not ask again at every logon; Turn features on or off installs it later */
        SetDw(L"Done", 1);
        SetSz(L"Result", L"Cancelled");
        Stamp(L"CompletedUtc");
        FmLogLine(log, L"first boot: cancelled by the user, will not run again");
    }
    else
    {
        attempts++;
        SetDw(L"Attempts", attempts);
        SetSz(L"LastError", res.firstError);
        SetSz(L"Result", L"Failed");
        FmLogLine(log, L"first boot: failed (attempt %lu of %d): %s", attempts, MAX_ATTEMPTS, res.firstError);
        if (attempts >= MAX_ATTEMPTS)
        {
            SetDw(L"Done", 1);
            FmLogLine(log, L"first boot: giving up; Turn NitroOS features on or off installs it on demand");
        }
    }
    return rc;
}
