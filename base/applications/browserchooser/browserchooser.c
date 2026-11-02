/*
 * PROJECT:     ReactOS Default Browser Chooser
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     First-login dialog that lets the user pick (and if needed
 *              install) a default web browser, then writes the full set of
 *              default-browser associations and Default-Programs capability
 *              keys.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>
#include <commctrl.h>
#include <objbase.h>
#include <shobjidl.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <wctype.h>
#include <strsafe.h>

#include "resource.h"

#define MAX_BROWSERS 32
#define WM_APP_INSTALLDONE (WM_APP + 1)

/* Bounded wait for the network to come up before a download. */
#define NET_WAIT_TIMEOUT_MS 60000
#define NET_WAIT_POLL_MS    1000

typedef struct _BROWSER_ENTRY
{
    WCHAR szKey[128];   /* StartMenuInternet subkey name, e.g. "IEXPLORE.EXE" */
    WCHAR szName[256];  /* display name, e.g. "Internet Explorer" */
    WCHAR szExe[MAX_PATH]; /* fully expanded path to the browser executable */
    BOOL bUser;         /* registered under HKCU (a per-user install such as Chrome's), not HKLM */
} BROWSER_ENTRY, *PBROWSER_ENTRY;

static HINSTANCE g_hInstance;
static BROWSER_ENTRY g_Browsers[MAX_BROWSERS];
static int g_BrowserCount = 0;
static int g_InstallItemIndex = -1; /* listbox index of the synthetic "install Firefox" item, or -1 */
static HWND g_hDlg = NULL;
static WCHAR g_szPreselect[256]; /* browser to select first (ms-settings:defaultapps?registeredAppUser=...) */

static const WCHAR szStartMenuInternet[] = L"SOFTWARE\\Clients\\StartMenuInternet";
static const WCHAR szRegisteredApps[]    = L"SOFTWARE\\RegisteredApplications";
static const WCHAR szClasses[]           = L"SOFTWARE\\Classes";
static const WCHAR szConfigKey[]         = L"SOFTWARE\\ReactOS\\BrowserChooser";
/* nitro overlay entry (rapps/overlay/firefox.txt): the current Firefox release. "firefox-esr" is the ESR one. */
static const WCHAR szDefaultFfPackage[]  = L"firefox";

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */

static void
LogLine(LPCWSTR fmt, ...)
{
    WCHAR szBuf[1024];
    WCHAR szPath[MAX_PATH];
    va_list args;
    HANDLE hFile;
    char szUtf8[2048];
    int cb;
    DWORD dwWritten;

    va_start(args, fmt);
    StringCchVPrintfW(szBuf, ARRAYSIZE(szBuf), fmt, args);
    va_end(args);

    /* Surface it to any attached kernel debugger / serial log. */
    OutputDebugStringW(L"BROWSERCHOOSER: ");
    OutputDebugStringW(szBuf);
    OutputDebugStringW(L"\n");

    /* Append it to an on-disk log for post-mortem read-back. The log lives in
     * the calling user's own temp directory, never in the shared, predictable
     * %windir%\\Temp (the first-logon process may be elevated). */
    if (GetTempPathW(ARRAYSIZE(szPath), szPath) &&
        SUCCEEDED(StringCchCatW(szPath, ARRAYSIZE(szPath), L"browserchooser.log")))
    {
        hFile = CreateFileW(szPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            cb = WideCharToMultiByte(CP_UTF8, 0, szBuf, -1, szUtf8, sizeof(szUtf8) - 2, NULL, NULL);
            if (cb > 0)
            {
                /* overwrite the terminating NUL with CRLF */
                szUtf8[cb - 1] = '\r';
                szUtf8[cb] = '\n';
                SetFilePointer(hFile, 0, NULL, FILE_END);
                WriteFile(hFile, szUtf8, cb + 1, &dwWritten, NULL);
            }
            CloseHandle(hFile);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Registry helpers                                                   */
/* ------------------------------------------------------------------ */

/* First registry write failure since SetDefaultBrowser/EnsureFirefoxClient
 * started; they report failure instead of claiming success. */
static LONG g_WriteError = ERROR_SUCCESS;

static LONG
SetStringValue(HKEY hRoot, LPCWSTR pszSubKey, LPCWSTR pszValue, LPCWSTR pszData)
{
    HKEY hKey;
    LONG lRet;

    lRet = RegCreateKeyExW(hRoot, pszSubKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                           KEY_WRITE, NULL, &hKey, NULL);
    if (lRet == ERROR_SUCCESS)
    {
        lRet = RegSetValueExW(hKey, pszValue, 0, REG_SZ,
                              (const BYTE *)pszData,
                              (DWORD)((wcslen(pszData) + 1) * sizeof(WCHAR)));
        RegCloseKey(hKey);
    }

    if (lRet != ERROR_SUCCESS)
    {
        LogLine(L"SetStringValue: writing %s [%s] failed err=%ld", pszSubKey,
                pszValue ? pszValue : L"(default)", lRet);
        if (g_WriteError == ERROR_SUCCESS)
            g_WriteError = lRet;
    }
    return lRet;
}

/* Read a REG_SZ/REG_EXPAND_SZ value into pszBuf. The type is checked and the
 * result is always NUL-terminated (registry data carries no such guarantee). */
static BOOL
ReadRegString(HKEY hKey, LPCWSTR pszValue, LPWSTR pszBuf, DWORD cchBuf)
{
    DWORD dwType = 0, cbData;

    if (!cchBuf)
        return FALSE;

    cbData = (cchBuf - 1) * sizeof(WCHAR); /* keep room for our own NUL */
    if (RegQueryValueExW(hKey, pszValue, NULL, &dwType, (LPBYTE)pszBuf, &cbData) != ERROR_SUCCESS)
        return FALSE;
    if (dwType != REG_SZ && dwType != REG_EXPAND_SZ)
        return FALSE;

    pszBuf[cbData / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

/* A browser executable path we are willing to write under HKLM: an absolute
 * drive path (not UNC / relative), no quote or control characters, a .exe
 * name, and an existing regular file. */
static BOOL
IsSafeExePath(LPCWSTR pszExe)
{
    size_t len = wcslen(pszExe);
    DWORD attr;
    size_t i;

    if (len < 7 || len >= MAX_PATH)
        return FALSE;
    if (!((pszExe[0] >= L'A' && pszExe[0] <= L'Z') || (pszExe[0] >= L'a' && pszExe[0] <= L'z')) ||
        pszExe[1] != L':' || pszExe[2] != L'\\')
        return FALSE;
    for (i = 0; i < len; i++)
    {
        if (pszExe[i] == L'"' || pszExe[i] < L' ')
            return FALSE;
    }
    if (StrCmpIW(pszExe + len - 4, L".exe"))
        return FALSE;

    attr = GetFileAttributesW(pszExe);
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

/* A RAPPS package name: letters, digits, '.', '-', '_' only. It is appended to
 * a command line, so nothing that could add an argument is accepted. */
static BOOL
IsSafePackageName(LPCWSTR psz)
{
    size_t i, len = wcslen(psz);

    if (!len || len > 64)
        return FALSE;
    for (i = 0; i < len; i++)
    {
        WCHAR c = psz[i];
        if (!((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
              (c >= L'0' && c <= L'9') || c == L'.' || c == L'-' || c == L'_'))
            return FALSE;
    }
    return TRUE;
}

/* Strip surrounding quotes and any trailing argument list, and expand
 * environment strings, leaving just the executable path. */
static void
ExtractExePath(LPCWSTR pszCommand, LPWSTR pszOut, size_t cchOut)
{
    WCHAR szExpanded[MAX_PATH * 2];
    DWORD cchExp;
    LPWSTR p;

    cchExp = ExpandEnvironmentStringsW(pszCommand, szExpanded, ARRAYSIZE(szExpanded));
    if (cchExp == 0 || cchExp > ARRAYSIZE(szExpanded))
    {
        /* failed or truncated: the buffer content is not usable */
        if (cchOut)
            pszOut[0] = L'\0';
        return;
    }

    p = szExpanded;
    while (*p == L' ')
        p++;

    if (*p == L'"')
    {
        LPWSTR end;
        p++;
        end = wcschr(p, L'"');
        if (end)
            *end = L'\0';
    }
    else
    {
        /* Bare path (StartMenuInternet convention): take the whole trimmed
         * string.  Only cut at a space if what precedes it already ends in
         * ".exe", to tolerate an accidental trailing argument. */
        LPWSTR dotexe = StrStrIW(p, L".exe");
        if (dotexe)
        {
            LPWSTR after = dotexe + 4;
            if (*after == L' ' || *after == L'\0')
                *after = L'\0';
        }
    }

    StringCchCopyW(pszOut, cchOut, p);
}

/* ------------------------------------------------------------------ */
/* Browser enumeration                                                */
/* ------------------------------------------------------------------ */

static BOOL
ReadClientCommand(HKEY hClients, LPCWSTR pszKeyName, LPWSTR pszExe, size_t cchExe)
{
    WCHAR szCmdSub[256];
    WCHAR szCommand[MAX_PATH * 2];
    HKEY hCmd;

    StringCchPrintfW(szCmdSub, ARRAYSIZE(szCmdSub), L"%s\\shell\\open\\command", pszKeyName);
    if (RegOpenKeyExW(hClients, szCmdSub, 0, KEY_READ, &hCmd) != ERROR_SUCCESS)
        return FALSE;

    if (!ReadRegString(hCmd, NULL, szCommand, ARRAYSIZE(szCommand)))
    {
        RegCloseKey(hCmd);
        return FALSE;
    }
    RegCloseKey(hCmd);

    ExtractExePath(szCommand, pszExe, cchExe);
    return IsSafeExePath(pszExe);
}

/* The StartMenuInternet clients of one hive. A client of the user does not hide a machine one of the same name. */
static void
EnumBrowsersIn(HKEY hRoot, BOOL bUser)
{
    HKEY hClients;
    DWORD dwIndex = 0;
    WCHAR szSubKey[128];
    DWORD cchSubKey;

    if (RegOpenKeyExW(hRoot, szStartMenuInternet, 0, KEY_READ, &hClients) != ERROR_SUCCESS)
        return;

    for (;;)
    {
        HKEY hBrowser;
        WCHAR szName[256];
        PBROWSER_ENTRY pEntry;
        int i;
        BOOL bDup = FALSE;

        cchSubKey = ARRAYSIZE(szSubKey);
        if (RegEnumKeyExW(hClients, dwIndex, szSubKey, &cchSubKey, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        dwIndex++;

        if (g_BrowserCount >= MAX_BROWSERS)
            break;

        for (i = 0; i < g_BrowserCount; i++)
        {
            if (!StrCmpIW(g_Browsers[i].szKey, szSubKey))
                bDup = TRUE;
        }
        if (bDup)
            continue;

        pEntry = &g_Browsers[g_BrowserCount];
        ZeroMemory(pEntry, sizeof(*pEntry));

        if (!ReadClientCommand(hClients, szSubKey, pEntry->szExe, ARRAYSIZE(pEntry->szExe)))
            continue;

        StringCchCopyW(pEntry->szKey, ARRAYSIZE(pEntry->szKey), szSubKey);
        pEntry->bUser = bUser;

        /* Friendly name: default value of the client key, fall back to subkey name. */
        szName[0] = L'\0';
        if (RegOpenKeyExW(hClients, szSubKey, 0, KEY_READ, &hBrowser) == ERROR_SUCCESS)
        {
            if (!ReadRegString(hBrowser, NULL, szName, ARRAYSIZE(szName)))
                szName[0] = L'\0';
            RegCloseKey(hBrowser);
        }
        StringCchCopyW(pEntry->szName, ARRAYSIZE(pEntry->szName),
                       szName[0] ? szName : szSubKey);

        g_BrowserCount++;
    }

    RegCloseKey(hClients);
}

static void
EnumBrowsers(void)
{
    g_BrowserCount = 0;
    EnumBrowsersIn(HKEY_LOCAL_MACHINE, FALSE);
    EnumBrowsersIn(HKEY_CURRENT_USER, TRUE);
}

static BOOL
FindFirefoxExe(LPWSTR pszOut, size_t cchOut)
{
    /* Program Files locations come from the shell (registry), not from the
     * caller's environment variables, which a user could have changed. */
    static const int folders[] = { CSIDL_PROGRAM_FILES, CSIDL_PROGRAM_FILESX86 };
    WCHAR szPath[MAX_PATH];
    UINT i;

    for (i = 0; i < ARRAYSIZE(folders); i++)
    {
        if (FAILED(SHGetFolderPathW(NULL, folders[i], NULL, SHGFP_TYPE_CURRENT, szPath)))
            continue;
        if (FAILED(StringCchCatW(szPath, ARRAYSIZE(szPath), L"\\Mozilla Firefox\\firefox.exe")))
            continue;
        if (IsSafeExePath(szPath))
        {
            StringCchCopyW(pszOut, cchOut, szPath);
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL
IsFirefoxPresent(void)
{
    WCHAR szPath[MAX_PATH];
    int i;

    for (i = 0; i < g_BrowserCount; i++)
    {
        if (StrStrIW(g_Browsers[i].szExe, L"firefox.exe") != NULL)
            return TRUE;
    }
    return FindFirefoxExe(szPath, ARRAYSIZE(szPath));
}

/* ------------------------------------------------------------------ */
/* Association + Default-Programs capability writer                   */
/* ------------------------------------------------------------------ */

/* Build a registry-safe token from the client key name, e.g.
 * "FIREFOX.EXE" -> "FIREFOXEXE". */
static void
SanitizeToken(LPCWSTR pszKey, LPWSTR pszOut, size_t cchOut)
{
    size_t i = 0;
    LPCWSTR s = pszKey;

    while (*s && i + 1 < cchOut)
    {
        if ((*s >= L'A' && *s <= L'Z') || (*s >= L'a' && *s <= L'z') ||
            (*s >= L'0' && *s <= L'9'))
        {
            pszOut[i++] = *s;
        }
        s++;
    }
    pszOut[i] = L'\0';
}

static void
WriteProgId(LPCWSTR pszProgId, LPCWSTR pszFriendly, LPCWSTR pszExe)
{
    WCHAR szSub[320];
    WCHAR szCmd[MAX_PATH + 16];
    WCHAR szIcon[MAX_PATH + 8];

    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\%s", szClasses, pszProgId);
    SetStringValue(HKEY_LOCAL_MACHINE, szSub, NULL, pszFriendly);

    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\%s\\DefaultIcon", szClasses, pszProgId);
    StringCchPrintfW(szIcon, ARRAYSIZE(szIcon), L"%s,0", pszExe);
    SetStringValue(HKEY_LOCAL_MACHINE, szSub, NULL, szIcon);

    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\%s\\shell\\open\\command", szClasses, pszProgId);
    StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" \"%%1\"", pszExe);
    SetStringValue(HKEY_LOCAL_MACHINE, szSub, NULL, szCmd);
}

/* Machine wide handler of a protocol: the open command of the browser's own class when it has one. */
static void
WriteProtocolHandler(LPCWSTR pszProto, LPCWSTR pszExe, LPCWSTR pszProgId)
{
    WCHAR szSub[256];
    WCHAR szCmd[MAX_PATH * 2];
    BOOL bHaveCmd = FALSE;

    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\%s", szClasses, pszProto);
    SetStringValue(HKEY_LOCAL_MACHINE, szSub, L"URL Protocol", L"");

    if (pszProgId)
    {
        HKEY hKey;
        StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\%s\\shell\\open\\command", szClasses, pszProgId);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szSub, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            bHaveCmd = ReadRegString(hKey, NULL, szCmd, ARRAYSIZE(szCmd)) && szCmd[0];
            RegCloseKey(hKey);
        }
    }
    if (!bHaveCmd)
        StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" \"%%1\"", pszExe);

    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\%s\\shell\\open\\command", szClasses, pszProto);
    SetStringValue(HKEY_LOCAL_MACHINE, szSub, NULL, szCmd);
}

/* The name a browser is listed under in RegisteredApplications (of the user for a per-user client, else of the
 * machine): the value that points at its Capabilities key. */
static BOOL
FindRegisteredAppName(LPCWSTR pszKey, BOOL bUser, LPWSTR pszOut, size_t cchOut)
{
    WCHAR szWant[320];
    HKEY hKey;
    DWORD i;
    BOOL bFound = FALSE;

    StringCchPrintfW(szWant, ARRAYSIZE(szWant), L"%s\\%s\\Capabilities", szStartMenuInternet, pszKey);
    /* the values are relative to HKLM and may or may not carry the "SOFTWARE\\" casing of ours */
    if (RegOpenKeyExW(bUser ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE, szRegisteredApps, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;

    for (i = 0; !bFound; i++)
    {
        WCHAR szName[256], szData[320];
        DWORD cchName = ARRAYSIZE(szName), cbData = sizeof(szData) - sizeof(WCHAR), dwType;
        LPCWSTR pszData = szData;
        LPCWSTR pszWant = szWant;

        if (RegEnumValueW(hKey, i, szName, &cchName, NULL, &dwType, (LPBYTE)szData, &cbData) != ERROR_SUCCESS)
            break;
        if (dwType != REG_SZ)
            continue;
        szData[cbData / sizeof(WCHAR)] = L'\0';
        if (*pszData == L'\\')
            pszData++;
        if (!StrCmpNIW(pszData, L"SOFTWARE\\", 9))
            pszData += 9;
        pszWant += 9; /* szWant starts with "SOFTWARE\\" */
        if (!StrCmpIW(pszData, pszWant))
        {
            StringCchCopyW(pszOut, cchOut, szName);
            bFound = TRUE;
        }
    }
    RegCloseKey(hKey);
    return bFound;
}

/* The ProgId a browser declares for <pszName> in the <pszGroup> of its own Capabilities, if that class can launch it. */
static BOOL
ReadOwnProgId(LPCWSTR pszKey, LPCWSTR pszGroup, LPCWSTR pszName, LPWSTR pszProgId, size_t cchProgId)
{
    WCHAR szSub[384];
    WCHAR szCmd[MAX_PATH * 2];
    HKEY hKey;
    BOOL bOk;

    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\%s\\Capabilities\\%s", szStartMenuInternet, pszKey, pszGroup);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szSub, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    bOk = ReadRegString(hKey, pszName, pszProgId, (DWORD)cchProgId) && pszProgId[0];
    RegCloseKey(hKey);
    if (!bOk || wcschr(pszProgId, L'\\'))
        return FALSE;

    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\%s\\shell\\open\\command", szClasses, pszProgId);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szSub, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    bOk = ReadRegString(hKey, NULL, szCmd, ARRAYSIZE(szCmd)) && szCmd[0];
    RegCloseKey(hKey);
    return bOk;
}

/*
 * Record the choice for the current user the way Windows' Default Programs does, through
 * IApplicationAssociationRegistration::SetAppAsDefault: the UserChoice of the web associations
 * (http, https, ftp, .htm, .html). The shell (ShellExecute, AssocQueryString) and the browsers' own
 * "am I the default" checks read it back. Not SetAppAsDefaultAll: the Capabilities of a browser also
 * list mailto:, .pdf, .svg and image types, which choosing a web browser must not take over.
 * ftp is only recorded when the browser declares it; the others must succeed.
 */
static BOOL
SetUserChoice(LPCWSTR pszRegisteredApp)
{
    static const struct { LPCWSTR pszName; ASSOCIATIONTYPE type; BOOL bRequired; } s_Assoc[] =
    {
        { L"http",  AT_URLPROTOCOL,   TRUE },
        { L"https", AT_URLPROTOCOL,   TRUE },
        { L"ftp",   AT_URLPROTOCOL,   FALSE },
        { L".htm",  AT_FILEEXTENSION, TRUE },
        { L".html", AT_FILEEXTENSION, TRUE },
    };
    IApplicationAssociationRegistration *pAAR = NULL;
    HRESULT hr, hrAll = S_OK;
    BOOL bInit;
    UINT i;

    bInit = SUCCEEDED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED));
    hr = CoCreateInstance(&CLSID_ApplicationAssociationRegistration, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IApplicationAssociationRegistration, (void **)&pAAR);
    if (SUCCEEDED(hr))
    {
        for (i = 0; i < ARRAYSIZE(s_Assoc); i++)
        {
            hr = pAAR->lpVtbl->SetAppAsDefault(pAAR, pszRegisteredApp, s_Assoc[i].pszName, s_Assoc[i].type);
            LogLine(L"SetUserChoice: SetAppAsDefault(%s, %s) = 0x%08lx", pszRegisteredApp, s_Assoc[i].pszName, hr);
            if (FAILED(hr) && s_Assoc[i].bRequired && SUCCEEDED(hrAll))
                hrAll = hr;
        }
        pAAR->lpVtbl->Release(pAAR);
        hr = hrAll;
    }
    if (bInit)
        CoUninitialize();

    return SUCCEEDED(hr);
}

/*
 * A browser installed for the user alone (its client key is under HKCU, e.g. Chrome from scoop or its own
 * installer) is made the user's default the way Windows' Settings app does it: only the UserChoice of the
 * web associations, through the browser's own Capabilities and ProgIds. Nothing of the machine is touched.
 */
static BOOL
SetUserDefaultBrowser(LPCWSTR pszKey, LPCWSTR pszName)
{
    WCHAR szRegApp[256];
    BOOL bOk;

    LogLine(L"SetUserDefaultBrowser key=%s name=%s", pszKey, pszName);
    if (!FindRegisteredAppName(pszKey, TRUE, szRegApp, ARRAYSIZE(szRegApp)))
    {
        LogLine(L"SetUserDefaultBrowser: %s is not in the RegisteredApplications of the user", pszKey);
        return FALSE;
    }

    g_WriteError = ERROR_SUCCESS;
    bOk = SetUserChoice(szRegApp);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSH, NULL, NULL);
    LogLine(bOk ? L"SetUserDefaultBrowser done for %s" : L"SetUserDefaultBrowser: failed for %s", pszKey);
    return bOk;
}

/*
 * Make <pszKey> the system default browser:
 *  - StartMenuInternet default value
 *  - http/https/ftp protocol handlers (HKLM\Software\Classes)
 *  - .htm/.html file associations through a dedicated ProgID
 *  - Default-Programs capability keys + RegisteredApplications
 */
static BOOL
SetDefaultBrowser(LPCWSTR pszKey, LPCWSTR pszName, LPCWSTR pszExe)
{
    WCHAR szToken[160];
    WCHAR szUrlProgId[224];
    WCHAR szHtmlProgId[224];
    WCHAR szRegApp[256];
    WCHAR szCapBase[320];
    WCHAR szSub[384];
    WCHAR szData[320];
    BOOL bOwnUrl, bOwnHtml;

    LogLine(L"SetDefaultBrowser key=%s name=%s exe=%s", pszKey, pszName, pszExe);

    if (!IsSafeExePath(pszExe))
    {
        LogLine(L"SetDefaultBrowser: refusing unsafe executable path");
        return FALSE;
    }
    g_WriteError = ERROR_SUCCESS;

    SanitizeToken(pszKey, szToken, ARRAYSIZE(szToken));

    /* Browsers such as Chrome and Firefox register their own Default Programs capabilities and
     * ProgIDs (ChromeHTML, FirefoxURL-...). Use those: the browser recognises its own ProgID as
     * "I am the default", and its command line is the one it expects. Clients that do not (the
     * built-in browser) get the nitro ProgIDs and capabilities written below. */
    bOwnUrl = ReadOwnProgId(pszKey, L"URLAssociations", L"http", szUrlProgId, ARRAYSIZE(szUrlProgId));
    bOwnHtml = ReadOwnProgId(pszKey, L"FileAssociations", L".html", szHtmlProgId, ARRAYSIZE(szHtmlProgId));
    if (!bOwnUrl)
        StringCchPrintfW(szUrlProgId, ARRAYSIZE(szUrlProgId), L"Nitro.%s.URL", szToken);
    if (!bOwnHtml)
        StringCchPrintfW(szHtmlProgId, ARRAYSIZE(szHtmlProgId), L"Nitro.%s.HTML", szToken);

    /* 1. StartMenuInternet default = this client */
    SetStringValue(HKEY_LOCAL_MACHINE, szStartMenuInternet, NULL, pszKey);

    /* 2. ProgIDs that actually launch the browser */
    if (!bOwnUrl)
    {
        StringCchPrintfW(szData, ARRAYSIZE(szData), L"%s URL", pszName);
        WriteProgId(szUrlProgId, szData, pszExe);
    }
    if (!bOwnHtml)
    {
        StringCchPrintfW(szData, ARRAYSIZE(szData), L"%s HTML Document", pszName);
        WriteProgId(szHtmlProgId, szData, pszExe);
    }

    /* 3. Machine wide protocol handlers (HKLM\Software\Classes), for software that reads them directly */
    WriteProtocolHandler(L"http", pszExe, szUrlProgId);
    WriteProtocolHandler(L"https", pszExe, szUrlProgId);
    WriteProtocolHandler(L"ftp", pszExe, szUrlProgId);

    /* 4. File associations */
    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\.htm", szClasses);
    SetStringValue(HKEY_LOCAL_MACHINE, szSub, NULL, szHtmlProgId);
    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\.html", szClasses);
    SetStringValue(HKEY_LOCAL_MACHINE, szSub, NULL, szHtmlProgId);

    /* 5. Default-Programs capabilities (shows in Control Panel -> Default Programs) */
    StringCchPrintfW(szCapBase, ARRAYSIZE(szCapBase), L"%s\\%s\\Capabilities",
                     szStartMenuInternet, pszKey);

    if (!bOwnUrl)
    {
        SetStringValue(HKEY_LOCAL_MACHINE, szCapBase, L"ApplicationName", pszName);
        StringCchPrintfW(szData, ARRAYSIZE(szData), L"%s,0", pszExe);
        SetStringValue(HKEY_LOCAL_MACHINE, szCapBase, L"ApplicationIcon", szData);
        StringCchPrintfW(szData, ARRAYSIZE(szData), L"%s web browser", pszName);
        SetStringValue(HKEY_LOCAL_MACHINE, szCapBase, L"ApplicationDescription", szData);

        StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\URLAssociations", szCapBase);
        SetStringValue(HKEY_LOCAL_MACHINE, szSub, L"http", szUrlProgId);
        SetStringValue(HKEY_LOCAL_MACHINE, szSub, L"https", szUrlProgId);
        SetStringValue(HKEY_LOCAL_MACHINE, szSub, L"ftp", szUrlProgId);

        StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\FileAssociations", szCapBase);
        SetStringValue(HKEY_LOCAL_MACHINE, szSub, L".htm", szHtmlProgId);
        SetStringValue(HKEY_LOCAL_MACHINE, szSub, L".html", szHtmlProgId);
    }

    /* 6. RegisteredApplications entry (the browser's own, else ours) */
    if (!FindRegisteredAppName(pszKey, FALSE, szRegApp, ARRAYSIZE(szRegApp)))
    {
        StringCchCopyW(szRegApp, ARRAYSIZE(szRegApp), pszName);
        StringCchPrintfW(szData, ARRAYSIZE(szData), L"%s\\%s\\Capabilities",
                         szStartMenuInternet, pszKey);
        SetStringValue(HKEY_LOCAL_MACHINE, szRegisteredApps, szRegApp, szData);
    }

    /* 7. The current user's choice (UserChoice of http, https, ...), read by the shell and the browsers */
    if (g_WriteError == ERROR_SUCCESS && !SetUserChoice(szRegApp))
        g_WriteError = ERROR_GEN_FAILURE;

    /* Notify the shell that associations changed. */
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSH, NULL, NULL);

    if (g_WriteError != ERROR_SUCCESS)
    {
        LogLine(L"SetDefaultBrowser: failed for %s (err=%ld)", pszKey, g_WriteError);
        return FALSE;
    }

    LogLine(L"SetDefaultBrowser done for %s", pszKey);
    return TRUE;
}

/* Register a StartMenuInternet client entry for a freshly installed Firefox,
 * in case the installer did not create one in the native registry view. */
static BOOL
EnsureFirefoxClient(LPCWSTR pszExe)
{
    WCHAR szSub[256];
    WCHAR szIcon[MAX_PATH + 8];
    WCHAR szCmd[MAX_PATH + 8];

    if (!IsSafeExePath(pszExe))
        return FALSE;
    g_WriteError = ERROR_SUCCESS;

    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\FIREFOX.EXE", szStartMenuInternet);
    SetStringValue(HKEY_LOCAL_MACHINE, szSub, NULL, L"Mozilla Firefox");

    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\FIREFOX.EXE\\DefaultIcon", szStartMenuInternet);
    StringCchPrintfW(szIcon, ARRAYSIZE(szIcon), L"%s,0", pszExe);
    SetStringValue(HKEY_LOCAL_MACHINE, szSub, NULL, szIcon);

    StringCchPrintfW(szSub, ARRAYSIZE(szSub), L"%s\\FIREFOX.EXE\\shell\\open\\command", szStartMenuInternet);
    StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\"", pszExe);
    SetStringValue(HKEY_LOCAL_MACHINE, szSub, NULL, szCmd);
    return g_WriteError == ERROR_SUCCESS;
}

/* The StartMenuInternet client Firefox's own installer registers ("Firefox-<install hash>" with Capabilities and
 * the FirefoxURL-/FirefoxHTML- ProgIds), as opposed to the "FIREFOX.EXE" entry EnsureFirefoxClient writes. The
 * default has to be recorded against this one: Firefox's "am I the default browser" check compares the user's
 * choice with its own ProgIds. */
static BOOL
FindOwnFirefoxClient(LPWSTR pszKey, size_t cchKey, LPWSTR pszName, size_t cchName)
{
    HKEY hClients, hKey;
    DWORD i;
    BOOL bFound = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szStartMenuInternet, 0, KEY_READ, &hClients) != ERROR_SUCCESS)
        return FALSE;

    for (i = 0; !bFound; i++)
    {
        WCHAR szSubKey[256], szCap[320];
        DWORD cchSubKey = ARRAYSIZE(szSubKey);

        if (RegEnumKeyExW(hClients, i, szSubKey, &cchSubKey, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        if (StrCmpNIW(szSubKey, L"Firefox-", 8))
            continue;
        StringCchPrintfW(szCap, ARRAYSIZE(szCap), L"%s\\Capabilities", szSubKey);
        if (RegOpenKeyExW(hClients, szCap, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;
        RegCloseKey(hKey);

        StringCchCopyW(pszKey, cchKey, szSubKey);
        if (RegOpenKeyExW(hClients, szSubKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            if (!ReadRegString(hKey, NULL, pszName, (DWORD)cchName) || !pszName[0])
                StringCchCopyW(pszName, cchName, L"Mozilla Firefox");
            RegCloseKey(hKey);
        }
        else
        {
            StringCchCopyW(pszName, cchName, L"Mozilla Firefox");
        }
        bFound = TRUE;
    }
    RegCloseKey(hClients);
    return bFound;
}

/* Make the installed Firefox the default: through the client Firefox registered itself, else through a
 * client entry written for it. */
static BOOL
AdoptFirefox(LPCWSTR pszExe)
{
    WCHAR szKey[256], szName[256];

    if (FindOwnFirefoxClient(szKey, ARRAYSIZE(szKey), szName, ARRAYSIZE(szName)))
        return SetDefaultBrowser(szKey, szName, pszExe);
    return EnsureFirefoxClient(pszExe) && SetDefaultBrowser(L"FIREFOX.EXE", L"Mozilla Firefox", pszExe);
}

/* ------------------------------------------------------------------ */
/* Network readiness                                                   */
/* ------------------------------------------------------------------ */

/* Parse a dotted-quad into four octets. */
static BOOL
ParseIPv4(const char *psz, UINT *pOct)
{
    return sscanf(psz, "%u.%u.%u.%u", &pOct[0], &pOct[1], &pOct[2], &pOct[3]) == 4
           && pOct[0] < 256 && pOct[1] < 256 && pOct[2] < 256 && pOct[3] < 256;
}

/* TRUE if at least one adapter has a usable IPv4 address (not 0.0.0.0, not
 * APIPA 169.254/16, not loopback) and a non-zero default gateway. */
static BOOL
IsNetworkReady(void)
{
    PIP_ADAPTER_INFO pInfo = NULL, pAd;
    ULONG cb = 0;
    BOOL bReady = FALSE;
    DWORD dwErr;

    dwErr = GetAdaptersInfo(NULL, &cb);
    if (dwErr != ERROR_BUFFER_OVERFLOW || !cb)
        return FALSE;

    pInfo = HeapAlloc(GetProcessHeap(), 0, cb);
    if (!pInfo)
        return FALSE;

    if (GetAdaptersInfo(pInfo, &cb) == NO_ERROR)
    {
        for (pAd = pInfo; pAd && !bReady; pAd = pAd->Next)
        {
            PIP_ADDR_STRING pIp, pGw;
            for (pIp = &pAd->IpAddressList; pIp && !bReady; pIp = pIp->Next)
            {
                UINT ip[4], gw[4];

                if (!ParseIPv4(pIp->IpAddress.String, ip))
                    continue;
                if ((ip[0] | ip[1] | ip[2] | ip[3]) == 0 || ip[0] == 127 ||
                    (ip[0] == 169 && ip[1] == 254))
                    continue;

                for (pGw = &pAd->GatewayList; pGw; pGw = pGw->Next)
                {
                    if (ParseIPv4(pGw->IpAddress.String, gw) && (gw[0] | gw[1] | gw[2] | gw[3]) != 0)
                    {
                        bReady = TRUE;
                        break;
                    }
                }
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, pInfo);
    return bReady;
}

/* A connect fired before DHCP completes fails with WSAENETUNREACH (10051) /
 * wininet 12029, so wait (bounded) for a usable address before downloading. */
static BOOL
WaitForNetwork(DWORD dwTimeoutMs)
{
    DWORD dwStart = GetTickCount();

    for (;;)
    {
        if (IsNetworkReady())
        {
            LogLine(L"WaitForNetwork: network ready after %lu ms", GetTickCount() - dwStart);
            return TRUE;
        }
        if (GetTickCount() - dwStart >= dwTimeoutMs)
            break;
        Sleep(NET_WAIT_POLL_MS);
    }

    LogLine(L"WaitForNetwork: no usable IPv4 address/gateway after %lu ms", dwTimeoutMs);
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Firefox install through RAPPS                                       */
/* ------------------------------------------------------------------ */

static void
GetFirefoxPackage(LPWSTR pszOut, size_t cchOut)
{
    HKEY hKey;

    StringCchCopyW(pszOut, cchOut, szDefaultFfPackage);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szConfigKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        WCHAR szVal[128];
        if (ReadRegString(hKey, L"FirefoxPackage", szVal, ARRAYSIZE(szVal)) && szVal[0])
        {
            if (IsSafePackageName(szVal))
                StringCchCopyW(pszOut, cchOut, szVal);
            else
                LogLine(L"GetFirefoxPackage: ignoring invalid FirefoxPackage value");
        }
        RegCloseKey(hKey);
    }
}

/* Run "rapps.exe /install /S <package>" and wait for it. Returns TRUE if
 * firefox.exe is on disk afterwards. */
static BOOL
InstallFirefox(void)
{
    WCHAR szRapps[MAX_PATH];
    WCHAR szPackage[128];
    WCHAR szCmd[MAX_PATH + 128];
    WCHAR szFfExe[MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD dwExit = (DWORD)-1;

    /* If Firefox is already installed, just adopt it as the default instead of
     * downloading it again (also avoids a redundant RAPPS run). */
    if (FindFirefoxExe(szFfExe, ARRAYSIZE(szFfExe)))
    {
        LogLine(L"InstallFirefox: firefox already present at %s; adopting as default", szFfExe);
        return AdoptFirefox(szFfExe);
    }

    if (!WaitForNetwork(NET_WAIT_TIMEOUT_MS))
    {
        LogLine(L"InstallFirefox: network not ready; not starting download");
        return FALSE;
    }

    if (!GetSystemDirectoryW(szRapps, ARRAYSIZE(szRapps)))
        return FALSE;
    StringCchCatW(szRapps, ARRAYSIZE(szRapps), L"\\rapps.exe");

    GetFirefoxPackage(szPackage, ARRAYSIZE(szPackage));
    StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" /install /S %s", szRapps, szPackage);

    LogLine(L"InstallFirefox: launching %s", szCmd);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(NULL, szCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        LogLine(L"InstallFirefox: CreateProcess failed err=%lu", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &dwExit);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    LogLine(L"InstallFirefox: rapps exit=%lu", dwExit);

    if (FindFirefoxExe(szFfExe, ARRAYSIZE(szFfExe)))
    {
        LogLine(L"InstallFirefox: firefox present at %s", szFfExe);
        return AdoptFirefox(szFfExe);
    }

    LogLine(L"InstallFirefox: firefox.exe not found after install");
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Dialog                                                             */
/* ------------------------------------------------------------------ */

static DWORD WINAPI
InstallThreadProc(LPVOID lpParam)
{
    BOOL bOk = InstallFirefox();
    PostMessageW(g_hDlg, WM_APP_INSTALLDONE, (WPARAM)bOk, 0);
    return 0;
}

static void
LoadDlgString(UINT uId, LPWSTR pszBuf, int cch)
{
    pszBuf[0] = L'\0';
    LoadStringW(g_hInstance, uId, pszBuf, cch);
}

static void
PopulateList(HWND hDlg)
{
    HWND hList = GetDlgItem(hDlg, IDC_BROWSERLIST);
    WCHAR szItem[300];
    int i, idx;

    SendMessageW(hList, LB_RESETCONTENT, 0, 0);
    g_InstallItemIndex = -1;

    EnumBrowsers();

    for (i = 0; i < g_BrowserCount; i++)
    {
        idx = (int)SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)g_Browsers[i].szName);
        SendMessageW(hList, LB_SETITEMDATA, idx, (LPARAM)i);
    }

    /* Offer the Firefox install only when no Firefox is present yet. */
    if (!IsFirefoxPresent())
    {
        LoadDlgString(IDS_INSTALLFIREFOX, szItem, ARRAYSIZE(szItem));
        idx = (int)SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)szItem);
        SendMessageW(hList, LB_SETITEMDATA, idx, (LPARAM)-1);
        g_InstallItemIndex = idx;
    }

    idx = 0;
    if (g_szPreselect[0])
    {
        for (i = 0; i < g_BrowserCount; i++)
        {
            if (!StrCmpIW(g_Browsers[i].szName, g_szPreselect) || !StrCmpIW(g_Browsers[i].szKey, g_szPreselect))
            {
                idx = i;
                break;
            }
        }
    }
    SendMessageW(hList, LB_SETCURSEL, idx, 0);
}

static void
SetBusy(HWND hDlg, BOOL bBusy, UINT uStatusId)
{
    WCHAR szStatus[256];

    EnableWindow(GetDlgItem(hDlg, IDOK), !bBusy);
    EnableWindow(GetDlgItem(hDlg, IDCANCEL), !bBusy);
    EnableWindow(GetDlgItem(hDlg, IDC_BROWSERLIST), !bBusy);

    if (uStatusId)
    {
        LoadDlgString(uStatusId, szStatus, ARRAYSIZE(szStatus));
        SetDlgItemTextW(hDlg, IDC_STATUS, szStatus);
    }
    else
    {
        SetDlgItemTextW(hDlg, IDC_STATUS, L"");
    }

    SetCursor(LoadCursorW(NULL, bBusy ? IDC_WAIT : IDC_ARROW));
}

static void
OnOk(HWND hDlg)
{
    HWND hList = GetDlgItem(hDlg, IDC_BROWSERLIST);
    int sel = (int)SendMessageW(hList, LB_GETCURSEL, 0, 0);
    int data;

    if (sel == LB_ERR)
        return;

    data = (int)SendMessageW(hList, LB_GETITEMDATA, sel, 0);

    if (data == -1)
    {
        /* Install-Firefox item: run RAPPS on a worker thread. */
        HANDLE hThread;
        SetBusy(hDlg, TRUE, IDS_INSTALLING);
        hThread = CreateThread(NULL, 0, InstallThreadProc, NULL, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        else
        {
            SetBusy(hDlg, FALSE, 0);
        }
        return;
    }

    if (data >= 0 && data < g_BrowserCount)
    {
        if (g_Browsers[data].bUser ? SetUserDefaultBrowser(g_Browsers[data].szKey, g_Browsers[data].szName) :
            SetDefaultBrowser(g_Browsers[data].szKey, g_Browsers[data].szName, g_Browsers[data].szExe))
            EndDialog(hDlg, IDOK);
    }
}

/* The chooser window carries this property, so a second start can find the first one. */
static const WCHAR szChooserProp[] = L"NitroBrowserChooser";

static BOOL CALLBACK
FindChooserProc(HWND hWnd, LPARAM lParam)
{
    if (GetPropW(hWnd, szChooserProp))
    {
        *(HWND *)lParam = hWnd;
        return FALSE;
    }
    return TRUE;
}

/*
 * One chooser at a time, as with the Settings app: browsers may ask for the "Default apps" page more
 * than once for one click of "Make default" (Chrome does). The later start brings the first window
 * forward and ends.
 */
static BOOL
ActivateRunningChooser(HANDLE *phMutex)
{
    HWND hWnd = NULL;
    int i;

    *phMutex = CreateMutexW(NULL, FALSE, L"Local\\NitroBrowserChooser");
    if (!*phMutex || GetLastError() != ERROR_ALREADY_EXISTS)
        return FALSE;

    /* the first one may not have created its window yet */
    for (i = 0; i < 30 && !hWnd; i++)
    {
        EnumWindows(FindChooserProc, (LPARAM)&hWnd);
        if (!hWnd)
            Sleep(100);
    }
    if (hWnd)
    {
        LogLine(L"A browser chooser is already open, bringing it forward");
        ShowWindow(hWnd, IsIconic(hWnd) ? SW_RESTORE : SW_SHOW);
        SetForegroundWindow(hWnd);
    }
    return hWnd != NULL;
}

static INT_PTR CALLBACK
DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_INITDIALOG:
            g_hDlg = hDlg;
            SetPropW(hDlg, szChooserProp, (HANDLE)1);
            PopulateList(hDlg);
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDOK:
                    OnOk(hDlg);
                    return TRUE;

                case IDCANCEL:
                    LogLine(L"User chose Skip");
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;

                case IDC_BROWSERLIST:
                    if (HIWORD(wParam) == LBN_DBLCLK)
                    {
                        OnOk(hDlg);
                        return TRUE;
                    }
                    break;
            }
            break;

        case WM_APP_INSTALLDONE:
        {
            BOOL bOk = (BOOL)wParam;
            if (bOk)
            {
                EndDialog(hDlg, IDOK);
            }
            else
            {
                WCHAR szMsg[256], szTitle[128];
                SetBusy(hDlg, FALSE, 0);
                LoadDlgString(IDS_INSTALLFAILED, szMsg, ARRAYSIZE(szMsg));
                LoadDlgString(IDS_APPTITLE, szTitle, ARRAYSIZE(szTitle));
                MessageBoxW(hDlg, szMsg, szTitle, MB_OK | MB_ICONWARNING);
                /* Refresh the list in case something partially registered. */
                PopulateList(hDlg);
            }
            return TRUE;
        }
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */

/*
 * Non-interactive automation entry points (also useful for unattended
 * provisioning scripts):
 *   bchooser.exe /set <key or name>            set that StartMenuInternet client as default
 *   bchooser.exe /installfirefox               install Firefox via RAPPS + set default
 *   bchooser.exe /settings [ms-settings:defaultapps[?registeredAppUser=name]]   the "Default apps" page
 *                                              (what ms-settings: opens): the chooser, that browser selected
 *   bchooser.exe /firstlogon                   the RunOnce launch: show the chooser, except
 *                                              under unattended setup (no dialog, rc 0)
 * Returns 0 on success, 1 on failure (-1: run the GUI).  Without arguments the GUI chooser runs.
 */
/* Same test as syssetup: [Unattend] UnattendSetupEnabled=yes in $winnt$.inf */
static BOOL
IsUnattendedSetup(VOID)
{
    WCHAR szPath[MAX_PATH];
    WCHAR szValue[16];

    if (!GetSystemDirectoryW(szPath, ARRAYSIZE(szPath)))
        return FALSE;
    StringCchCatW(szPath, ARRAYSIZE(szPath), L"\\$winnt$.inf");
    if (!GetPrivateProfileStringW(L"Unattend", L"UnattendSetupEnabled", L"no",
                                  szValue, ARRAYSIZE(szValue), szPath))
        return FALSE;
    return !StrCmpIW(szValue, L"yes");
}

static int
RunAutomation(int argc, LPWSTR *argv)
{
    if (!StrCmpIW(argv[0], L"/firstlogon"))
    {
        /* Never block an automated logon on a dialog nobody will answer. */
        if (IsUnattendedSetup())
        {
            LogLine(L"Automation: /firstlogon under unattended setup, skipping");
            return 0;
        }
        return -1; /* interactive: fall through to the GUI */
    }

    if (!StrCmpIW(argv[0], L"/installfirefox"))
    {
        LogLine(L"Automation: /installfirefox");
        return InstallFirefox() ? 0 : 1;
    }

    if (!StrCmpIW(argv[0], L"/set"))
    {
        int i;
        if (argc < 2)
        {
            LogLine(L"Automation: /set needs a browser key");
            return 1;
        }

        EnumBrowsers();
        for (i = 0; i < g_BrowserCount; i++)
        {
            if (!StrCmpIW(g_Browsers[i].szKey, argv[1]) || !StrCmpIW(g_Browsers[i].szName, argv[1]))
            {
                if (g_Browsers[i].bUser)
                    return SetUserDefaultBrowser(g_Browsers[i].szKey, g_Browsers[i].szName) ? 0 : 1;
                return SetDefaultBrowser(g_Browsers[i].szKey,
                                         g_Browsers[i].szName,
                                         g_Browsers[i].szExe) ? 0 : 1;
            }
        }
        LogLine(L"Automation: /set - browser '%s' not found", argv[1]);
        return 1;
    }

    if (!StrCmpIW(argv[0], L"/settings"))
    {
        /* The "Default apps" page of the Windows settings app: ms-settings:defaultapps[?registeredAppUser=<name>]
         * (what browsers open for "Make default"). Show the chooser with that browser selected. Other pages
         * have nothing to show. */
        LPCWSTR pszUri = argc > 1 ? argv[1] : L"ms-settings:defaultapps"; /* bare /settings: the same page */
        LPCWSTR pszName;

        if (StrCmpNIW(pszUri, L"ms-settings:defaultapps", 23))
        {
            LogLine(L"Automation: /settings - no page for %s", pszUri);
            return 0;
        }
        pszName = StrStrIW(pszUri, L"registeredAppUser=");
        if (pszName)
        {
            LPWSTR pszOut = g_szPreselect;
            pszName += 18;
            while (*pszName && *pszName != L'&' && pszOut < g_szPreselect + ARRAYSIZE(g_szPreselect) - 1)
            {
                if (*pszName == L'%' && iswxdigit(pszName[1]) && iswxdigit(pszName[2]))
                {
                    WCHAR sz[3] = { pszName[1], pszName[2], 0 };
                    *pszOut++ = (WCHAR)wcstoul(sz, NULL, 16);
                    pszName += 3;
                }
                else
                {
                    *pszOut++ = (*pszName == L'+') ? L' ' : *pszName;
                    pszName++;
                }
            }
            *pszOut = L'\0';
        }
        return -1; /* show the chooser */
    }

    LogLine(L"Automation: unknown option '%s'", argv[0]);
    return 1;
}

int WINAPI
wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    INITCOMMONCONTROLSEX icc;
    int argc = 0;
    LPWSTR *argv;
    int ret = 0;
    HANDLE hMutex = NULL;

    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    g_hInstance = hInstance;

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    LogLine(L"Browser chooser starting");

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc > 1)
    {
        ret = RunAutomation(argc - 1, &argv[1]);
        if (ret != -1)
        {
            LocalFree(argv);
            LogLine(L"Browser chooser exiting (automation rc=%d)", ret);
            return ret;
        }
        ret = 0; /* /firstlogon on an interactive setup: show the chooser */
    }
    if (argv)
        LocalFree(argv);

    if (ActivateRunningChooser(&hMutex))
    {
        CloseHandle(hMutex);
        return 0;
    }

    DialogBoxW(hInstance, MAKEINTRESOURCEW(IDD_CHOOSER), NULL, DlgProc);

    if (hMutex)
        CloseHandle(hMutex);
    LogLine(L"Browser chooser exiting");
    return 0;
}
