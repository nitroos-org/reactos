/*
 * PROJECT:     ReactOS system setup
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The answers of an unattended installation (unattend.inf, kept as $winnt$.inf
 *              in the system directory) that the wizard pages do not consume: the extra user
 *              account, automatic logon, the network configuration, the features to install,
 *              the final action, and the setup log. Everything here is non-interactive:
 *              a bad value is written to the log (%SystemRoot%\Panther\unattend.log) and the
 *              documented default is used; nothing opens a box and waits.
 *              The passwords of the file are scrubbed from the installed copy at the end
 *              (UnattendScrubSecrets), and are never written to the log.
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"

#include <stdlib.h>
#include <wchar.h>
#include <winnls.h>
#include <strsafe.h>
#include <ndk/rtlfuncs.h>
#include <lmaccess.h>
#include <lmapibuf.h>
#include <lmerr.h>

#define NDEBUG
#include <debug.h>

/* LOG **********************************************************************/

static BOOL
GetUnattendLogPath(
    _Out_writes_(cchMax) PWSTR pszPath,
    _In_ UINT cchMax)
{
    WCHAR szDir[MAX_PATH];

    if (!GetWindowsDirectoryW(szDir, _countof(szDir)))
        return FALSE;
    if (FAILED(StringCchPrintfW(pszPath, cchMax, L"%s\\Panther", szDir)))
        return FALSE;
    CreateDirectoryW(pszPath, NULL);
    return SUCCEEDED(StringCchCatW(pszPath, cchMax, L"\\unattend.log"));
}

/* One line (UTF-8, CR LF) appended to the setup log. Never pass a password. */
VOID
UnattendLog(
    _In_ PCWSTR pszFormat,
    ...)
{
    WCHAR szText[400], szLine[480], szPath[MAX_PATH];
    CHAR szUtf8[1500];
    SYSTEMTIME st;
    va_list args;
    HANDLE hFile;
    DWORD dwWritten;
    int n;

    va_start(args, pszFormat);
    StringCchVPrintfW(szText, _countof(szText), pszFormat, args);
    va_end(args);

    GetSystemTime(&st);
    StringCchPrintfW(szLine, _countof(szLine), L"%04u-%02u-%02uT%02u:%02u:%02uZ syssetup: %s\r\n",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, szText);
    DPRINT1("%S", szLine);

    if (!GetUnattendLogPath(szPath, _countof(szPath)))
        return;
    n = WideCharToMultiByte(CP_UTF8, 0, szLine, -1, szUtf8, sizeof(szUtf8), NULL, NULL);
    if (n <= 1)
        return;
    hFile = CreateFileW(szPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    SetFilePointer(hFile, 0, NULL, FILE_END);
    WriteFile(hFile, szUtf8, n - 1, &dwWritten, NULL);
    CloseHandle(hFile);
}

/* READING THE FILE *********************************************************/

/* The value of Section/Key in $winnt$.inf: surrounding blanks and one pair of double quotes removed.
 * TRUE when the key is there with a non-empty value. */
BOOL
UnattendGetString(
    _In_ PCWSTR pszSection,
    _In_ PCWSTR pszKey,
    _Out_writes_(cchMax) PWSTR pszValue,
    _In_ DWORD cchMax)
{
    WCHAR szPath[MAX_PATH];
    PWSTR p;
    size_t len;

    pszValue[0] = UNICODE_NULL;
    GetSetupInfPath(szPath, _countof(szPath));
    if (!szPath[0])
        return FALSE;
    GetPrivateProfileStringW(pszSection, pszKey, L"", pszValue, cchMax, szPath);

    p = pszValue;
    while (*p == L' ' || *p == L'\t')
        p++;
    if (p != pszValue)
        memmove(pszValue, p, (wcslen(p) + 1) * sizeof(WCHAR));
    len = wcslen(pszValue);
    while (len && (pszValue[len - 1] == L' ' || pszValue[len - 1] == L'\t'))
        pszValue[--len] = UNICODE_NULL;
    if (len >= 2 && pszValue[0] == L'"' && pszValue[len - 1] == L'"')
    {
        memmove(pszValue, pszValue + 1, (len - 1) * sizeof(WCHAR));
        pszValue[len - 2] = UNICODE_NULL;
    }
    return pszValue[0] != UNICODE_NULL;
}

/* yes/no, true/false, on/off, 1/0; Default when the key is absent or not understood (then it is logged) */
BOOL
UnattendGetBool(
    _In_ PCWSTR pszSection,
    _In_ PCWSTR pszKey,
    _In_ BOOL bDefault)
{
    WCHAR szValue[32];

    if (!UnattendGetString(pszSection, pszKey, szValue, _countof(szValue)))
        return bDefault;
    if (!_wcsicmp(szValue, L"yes") || !_wcsicmp(szValue, L"true") || !_wcsicmp(szValue, L"on") || !wcscmp(szValue, L"1"))
        return TRUE;
    if (!_wcsicmp(szValue, L"no") || !_wcsicmp(szValue, L"false") || !_wcsicmp(szValue, L"off") || !wcscmp(szValue, L"0"))
        return FALSE;
    UnattendLog(L"bad value for [%s] %s (yes or no expected): using %s", pszSection, pszKey,
                bDefault ? L"yes" : L"no");
    return bDefault;
}

/* TIME ZONE ****************************************************************/

/*
 * Time zone ids of the IANA database (the names Linux and cloud tools use) for the Windows
 * time zone name of the registry, for the zones people name most. Source: the public mapping
 * of the Unicode CLDR project (windowsZones), written out here by hand for these zones.
 * Any other zone is given by its Windows name (the key under ...\CurrentVersion\Time Zones)
 * or by TimeZoneIndex.
 */
static const struct { PCWSTR Iana; PCWSTR Windows; } IanaZones[] = {
    {L"UTC", L"UTC"}, {L"Etc/UTC", L"UTC"}, {L"GMT", L"GMT Standard Time"},
    {L"Europe/London", L"GMT Standard Time"}, {L"Europe/Dublin", L"GMT Standard Time"},
    {L"Europe/Lisbon", L"GMT Standard Time"}, {L"Atlantic/Reykjavik", L"Greenwich Standard Time"},
    {L"Europe/Berlin", L"W. Europe Standard Time"}, {L"Europe/Vienna", L"W. Europe Standard Time"},
    {L"Europe/Zurich", L"W. Europe Standard Time"}, {L"Europe/Amsterdam", L"W. Europe Standard Time"},
    {L"Europe/Rome", L"W. Europe Standard Time"}, {L"Europe/Stockholm", L"W. Europe Standard Time"},
    {L"Europe/Oslo", L"W. Europe Standard Time"}, {L"Europe/Copenhagen", L"Romance Standard Time"},
    {L"Europe/Paris", L"Romance Standard Time"}, {L"Europe/Madrid", L"Romance Standard Time"},
    {L"Europe/Brussels", L"Romance Standard Time"}, {L"Europe/Prague", L"Central Europe Standard Time"},
    {L"Europe/Budapest", L"Central Europe Standard Time"}, {L"Europe/Warsaw", L"Central European Standard Time"},
    {L"Europe/Belgrade", L"Central Europe Standard Time"}, {L"Europe/Athens", L"GTB Standard Time"},
    {L"Europe/Bucharest", L"GTB Standard Time"}, {L"Europe/Helsinki", L"FLE Standard Time"},
    {L"Europe/Kiev", L"FLE Standard Time"}, {L"Europe/Kyiv", L"FLE Standard Time"},
    {L"Europe/Istanbul", L"Turkey Standard Time"}, {L"Europe/Moscow", L"Russian Standard Time"},
    {L"Africa/Cairo", L"Egypt Standard Time"}, {L"Africa/Johannesburg", L"South Africa Standard Time"},
    {L"Africa/Lagos", L"W. Central Africa Standard Time"}, {L"Africa/Nairobi", L"E. Africa Standard Time"},
    {L"Asia/Jerusalem", L"Israel Standard Time"}, {L"Asia/Riyadh", L"Arab Standard Time"},
    {L"Asia/Dubai", L"Arabian Standard Time"}, {L"Asia/Tehran", L"Iran Standard Time"},
    {L"Asia/Karachi", L"Pakistan Standard Time"}, {L"Asia/Kolkata", L"India Standard Time"},
    {L"Asia/Calcutta", L"India Standard Time"}, {L"Asia/Dhaka", L"Bangladesh Standard Time"},
    {L"Asia/Bangkok", L"SE Asia Standard Time"}, {L"Asia/Jakarta", L"SE Asia Standard Time"},
    {L"Asia/Shanghai", L"China Standard Time"}, {L"Asia/Hong_Kong", L"China Standard Time"},
    {L"Asia/Singapore", L"Singapore Standard Time"}, {L"Asia/Taipei", L"Taipei Standard Time"},
    {L"Asia/Seoul", L"Korea Standard Time"}, {L"Asia/Tokyo", L"Tokyo Standard Time"},
    {L"Australia/Perth", L"W. Australia Standard Time"}, {L"Australia/Adelaide", L"Cen. Australia Standard Time"},
    {L"Australia/Sydney", L"AUS Eastern Standard Time"}, {L"Australia/Melbourne", L"AUS Eastern Standard Time"},
    {L"Australia/Brisbane", L"E. Australia Standard Time"}, {L"Pacific/Auckland", L"New Zealand Standard Time"},
    {L"Pacific/Honolulu", L"Hawaiian Standard Time"}, {L"America/Anchorage", L"Alaskan Standard Time"},
    {L"America/Los_Angeles", L"Pacific Standard Time"}, {L"America/Vancouver", L"Pacific Standard Time"},
    {L"America/Phoenix", L"US Mountain Standard Time"}, {L"America/Denver", L"Mountain Standard Time"},
    {L"America/Chicago", L"Central Standard Time"}, {L"America/Mexico_City", L"Central Standard Time (Mexico)"},
    {L"America/New_York", L"Eastern Standard Time"}, {L"America/Toronto", L"Eastern Standard Time"},
    {L"America/Halifax", L"Atlantic Standard Time"}, {L"America/Sao_Paulo", L"E. South America Standard Time"},
    {L"America/Argentina/Buenos_Aires", L"Argentina Standard Time"}, {L"America/Bogota", L"SA Pacific Standard Time"},
    {L"America/Lima", L"SA Pacific Standard Time"}, {L"America/Santiago", L"Pacific SA Standard Time"},
};

/* The Index of the time zone with this registry name (the key of ...\Time Zones) */
static BOOL
TimeZoneIndexOfWindowsName(
    _In_ PCWSTR pszName,
    _Out_ PDWORD pdwIndex)
{
    WCHAR szKey[256];
    HKEY hKey;
    DWORD dwType, dwSize = sizeof(*pdwIndex);
    BOOL bOk = FALSE;

    if (FAILED(StringCchPrintfW(szKey, _countof(szKey),
                                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\%s", pszName)))
        return FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, L"Index", NULL, &dwType, (LPBYTE)pdwIndex, &dwSize) == ERROR_SUCCESS &&
        dwType == REG_DWORD)
        bOk = TRUE;
    RegCloseKey(hKey);
    return bOk;
}

/* [Unattend] TimeZone = "W. Europe Standard Time" or "Europe/Berlin": the index the time zone page takes.
 * TRUE and *pdwIndex when the name is known; FALSE (logged) otherwise. */
BOOL
UnattendResolveTimeZone(
    _In_ PCWSTR pszName,
    _Out_ PDWORD pdwIndex)
{
    UINT i;

    if (TimeZoneIndexOfWindowsName(pszName, pdwIndex))
        return TRUE;
    for (i = 0; i < _countof(IanaZones); i++)
    {
        if (!_wcsicmp(pszName, IanaZones[i].Iana))
        {
            if (TimeZoneIndexOfWindowsName(IanaZones[i].Windows, pdwIndex))
                return TRUE;
            break;
        }
    }
    UnattendLog(L"TimeZone \"%s\" is not a known time zone (a Windows time zone name such as"
                L" \"W. Europe Standard Time\", or an id such as \"Europe/Berlin\"): using TimeZoneIndex, or the"
                L" time zone of the language when there is none", pszName);
    return FALSE;
}

/* COMPUTER NAME ************************************************************/

/* A NetBIOS-style computer name: 1..15 characters, none of  " / \ [ ] : | < > + = ; , ? *  and not only digits */
BOOL
UnattendIsValidComputerName(
    _In_ PCWSTR pszName)
{
    size_t i, len = wcslen(pszName);
    BOOL bAllDigits = TRUE;

    if (len == 0 || len > MAX_COMPUTERNAME_LENGTH)
        return FALSE;
    for (i = 0; i < len; i++)
    {
        if (pszName[i] < L' ' || wcschr(L"\"/\\[]:|<>+=;,?*", pszName[i]))
            return FALSE;
        if (pszName[i] < L'0' || pszName[i] > L'9')
            bAllDigits = FALSE;
    }
    return !bAllDigits;
}

/* SECRETS ******************************************************************/

typedef struct _SECRET_KEY
{
    PCSTR Section;
    PCSTR Key;
} SECRET_KEY;

static const SECRET_KEY SecretKeys[] = {
    {"Unattend", "AdminPassword"},
    {"UserAccount", "Password"},
};

/* Case-insensitive compare of `len` characters of text (1 or 2 bytes each, little endian) with an ASCII word */
static BOOL
MatchAt(const BYTE *p, size_t cb, size_t w, PCSTR word)
{
    size_t i, n = strlen(word);

    if (cb < n * w)
        return FALSE;
    for (i = 0; i < n; i++)
    {
        UCHAR c = p[i * w];
        if (w == 2 && p[i * w + 1])
            return FALSE;
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
        if (c != (UCHAR)(word[i] >= 'A' && word[i] <= 'Z' ? word[i] + 'a' - 'A' : word[i]))
            return FALSE;
    }
    return TRUE;
}

/*
 * Overwrite, in place and with blanks, the value of every secret key of the installed copy of
 * the answer file ($winnt$.inf), and save it under the same name. The file is rewritten at the
 * same size in the same place, so the old text does not stay in other disk blocks of it.
 * Windows documents the same concern for its answer files and removes passwords from them
 * after use ("Unattended Windows Setup Reference", Microsoft-Windows-Shell-Setup
 * UserAccounts / AutoLogon: "plain text passwords ... are removed from the answer file after
 * Setup"); ReactOS does the same for $winnt$.inf.
 */
VOID
UnattendScrubSecrets(VOID)
{
    WCHAR szPath[MAX_PATH];
    HANDLE hFile;
    DWORD cb, cbRead = 0, cbWritten;
    BYTE *pb;
    size_t w, i, lineStart, scrubbed = 0;
    CHAR szSection[64] = "";
    BOOL bChanged = FALSE;

    GetSetupInfPath(szPath, _countof(szPath));
    if (!szPath[0])
        return;
    hFile = CreateFileW(szPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        UnattendLog(L"cannot open the installed answer file to remove the passwords (error %lu)", GetLastError());
        return;
    }
    cb = GetFileSize(hFile, NULL);
    if (cb == INVALID_FILE_SIZE || cb == 0 || cb > 4 * 1024 * 1024)
    {
        CloseHandle(hFile);
        return;
    }
    pb = HeapAlloc(GetProcessHeap(), 0, cb);
    if (!pb || !ReadFile(hFile, pb, cb, &cbRead, NULL) || cbRead != cb)
    {
        UnattendLog(L"cannot read the installed answer file to remove the passwords");
        if (pb)
            HeapFree(GetProcessHeap(), 0, pb);
        CloseHandle(hFile);
        return;
    }

    /* UTF-16LE (with the byte order mark) or 8-bit text */
    w = (cb >= 2 && pb[0] == 0xFF && pb[1] == 0xFE) ? 2 : 1;
    i = (w == 2) ? 2 : 0;
    while (i + w <= cb)
    {
        size_t eol, p;

        lineStart = i;
        for (eol = i; eol + w <= cb && !(pb[eol] == '\n' || pb[eol] == '\r'); eol += w)
            ;
        p = lineStart;
        while (p < eol && (pb[p] == ' ' || pb[p] == '\t'))
            p += w;
        if (p < eol && pb[p] == '[')
        {
            size_t n = 0;
            p += w;
            while (p < eol && pb[p] != ']' && n < sizeof(szSection) - 1)
            {
                szSection[n++] = (CHAR)pb[p];
                p += w;
            }
            szSection[n] = ANSI_NULL;
        }
        else if (p < eol && pb[p] != ';')
        {
            UINT k;
            for (k = 0; k < _countof(SecretKeys); k++)
            {
                size_t kl = strlen(SecretKeys[k].Key), q;
                if (_stricmp(szSection, SecretKeys[k].Section) || !MatchAt(pb + p, eol - p, w, SecretKeys[k].Key))
                    continue;
                q = p + kl * w;
                while (q < eol && (pb[q] == ' ' || pb[q] == '\t'))
                    q += w;
                if (q >= eol || pb[q] != '=')
                    continue;
                for (q += w; q < eol; q += w)
                {
                    pb[q] = ' ';
                    if (w == 2)
                        pb[q + 1] = 0;
                }
                bChanged = TRUE;
                scrubbed++;
            }
        }
        /* next line */
        i = eol;
        while (i + w <= cb && (pb[i] == '\n' || pb[i] == '\r'))
            i += w;
        if (i == eol)
            i += w;
    }

    if (bChanged)
    {
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        if (!WriteFile(hFile, pb, cb, &cbWritten, NULL) || cbWritten != cb)
            UnattendLog(L"cannot write the installed answer file back (error %lu)", GetLastError());
        else
            FlushFileBuffers(hFile);
    }
    UnattendLog(L"answer file copy on this system: %u password value(s) removed", (UINT)scrubbed);
    HeapFree(GetProcessHeap(), 0, pb);
    CloseHandle(hFile);
}

/*
 * The passwords are read once, at the start of the second stage, kept in memory only, and removed from the
 * installed copy of the answer file right away: writing the file again later (the setup stage records the
 * source path in it) would leave the old text, passwords included, in the freed disk blocks.
 */
static WCHAR g_szAdminPassword[128];
static WCHAR g_szAccountPassword[128];

VOID
UnattendCaptureSecrets(VOID)
{
    if (!UnattendGetBool(L"Unattend", L"UnattendSetupEnabled", FALSE))
        return;
    UnattendGetString(L"Unattend", L"AdminPassword", g_szAdminPassword, _countof(g_szAdminPassword));
    UnattendGetString(L"UserAccount", L"Password", g_szAccountPassword, _countof(g_szAccountPassword));
    UnattendScrubSecrets();
}

PCWSTR
UnattendGetAdminPassword(VOID)
{
    return g_szAdminPassword;
}

VOID
UnattendForgetSecrets(VOID)
{
    SecureZeroMemory(g_szAdminPassword, sizeof(g_szAdminPassword));
    SecureZeroMemory(g_szAccountPassword, sizeof(g_szAccountPassword));
}

/* USER ACCOUNT *************************************************************/

typedef NET_API_STATUS (WINAPI *PFN_NETUSERADD)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef NET_API_STATUS (WINAPI *PFN_NETLGADDMEMBERS)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
typedef NET_API_STATUS (WINAPI *PFN_NETUSERGETINFO)(LPCWSTR, LPCWSTR, DWORD, LPBYTE *);
typedef NET_API_STATUS (WINAPI *PFN_NETAPIBUFFERFREE)(LPVOID);

/*
 * Add the account to a local group by its SID: the name lookup of the LSA does not know an account that
 * was created seconds ago in the same session (the account domain was renamed to the computer name by
 * this setup), the SID that NetUserGetInfo returns always works.
 * The group names are the English ones setup creates.
 */
static VOID
AddToGroup(
    _In_ HMODULE hNetapi,
    _In_ PCWSTR pszGroup,
    _In_ PCWSTR pszUser)
{
    PFN_NETLGADDMEMBERS pfnAdd = (PFN_NETLGADDMEMBERS)GetProcAddress(hNetapi, "NetLocalGroupAddMembers");
    PFN_NETUSERGETINFO pfnGetInfo = (PFN_NETUSERGETINFO)GetProcAddress(hNetapi, "NetUserGetInfo");
    PFN_NETAPIBUFFERFREE pfnFree = (PFN_NETAPIBUFFERFREE)GetProcAddress(hNetapi, "NetApiBufferFree");
    LOCALGROUP_MEMBERS_INFO_0 member;
    USER_INFO_4 *pUser = NULL;
    NET_API_STATUS st;
    WCHAR szGroup[256], szDomain[256];
    DWORD cchGroup = _countof(szGroup), cchDomain = _countof(szDomain);
    SID_NAME_USE use;
    SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
    PSID pGroupSid = NULL;

    /* The group has the name of the language of the installation ("Benutzer" for "Users"): ask for it by RID */
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 !_wcsicmp(pszGroup, L"Administrators") ? DOMAIN_ALIAS_RID_ADMINS : DOMAIN_ALIAS_RID_USERS,
                                 0, 0, 0, 0, 0, 0, &pGroupSid))
    {
        if (LookupAccountSidW(NULL, pGroupSid, szGroup, &cchGroup, szDomain, &cchDomain, &use))
            pszGroup = szGroup;
        FreeSid(pGroupSid);
    }

    if (!pfnAdd || !pfnGetInfo)
    {
        UnattendLog(L"cannot add \"%s\" to the group %s: netapi32 has no group functions", pszUser, pszGroup);
        return;
    }
    st = pfnGetInfo(NULL, pszUser, 4, (LPBYTE *)&pUser);
    if (st != NERR_Success || !pUser || !pUser->usri4_user_sid)
    {
        UnattendLog(L"cannot find the account \"%s\" to add it to the group %s (error %lu)", pszUser, pszGroup, (ULONG)st);
        if (pUser && pfnFree)
            pfnFree(pUser);
        return;
    }
    member.lgrmi0_sid = pUser->usri4_user_sid;
    st = pfnAdd(NULL, pszGroup, 0, (LPBYTE)&member, 1);
    if (st != NERR_Success && st != ERROR_MEMBER_IN_ALIAS)
        UnattendLog(L"cannot add \"%s\" to the group %s (error %lu)", pszUser, pszGroup, (ULONG)st);
    if (pfnFree)
        pfnFree(pUser);
}

/*
 * [UserAccount]
 *   Name, Password (may be empty), Group = Users | Administrators, FullName
 * Returns TRUE when an account was created; *pbAutoLogon is set when [UserAccount] AutoLogon = yes.
 */
static BOOL
CreateConfiguredAccount(
    _Out_writes_(cchName) PWSTR pszName,
    _In_ DWORD cchName,
    _Out_writes_(cchPassword) PWSTR pszPassword,
    _In_ DWORD cchPassword)
{
    WCHAR szGroup[32], szFullName[128];
    HMODULE hNetapi;
    PFN_NETUSERADD pfnUserAdd;
    PFN_NETLGADDMEMBERS pfnAddMembers;
    USER_INFO_1 ui;
    NET_API_STATUS st;
    DWORD dwParam = 0;
    BOOL bAdmin = FALSE, bOk = FALSE;
    size_t i;

    pszPassword[0] = UNICODE_NULL;
    if (!UnattendGetString(L"UserAccount", L"Name", pszName, cchName))
        return FALSE;

    /* The user name: no control characters and none of  " / \ [ ] : | < > + = ; , ? *  @, at most 20 characters */
    if (wcslen(pszName) > 20)
    {
        UnattendLog(L"[UserAccount] Name is longer than 20 characters: no account created");
        return FALSE;
    }
    for (i = 0; pszName[i]; i++)
    {
        if (pszName[i] < L' ' || wcschr(L"\"/\\[]:|<>+=;,?*@", pszName[i]))
        {
            UnattendLog(L"[UserAccount] Name has a character an account name cannot have: no account created");
            return FALSE;
        }
    }
    if (!_wcsicmp(pszName, L"Administrator") || !_wcsicmp(pszName, L"Guest"))
    {
        UnattendLog(L"[UserAccount] Name \"%s\" is a built-in account (set AdminPassword for the Administrator): no account created",
                    pszName);
        return FALSE;
    }

    StringCchCopyW(pszPassword, cchPassword, g_szAccountPassword);
    UnattendGetString(L"UserAccount", L"FullName", szFullName, _countof(szFullName));
    if (UnattendGetString(L"UserAccount", L"Group", szGroup, _countof(szGroup)))
    {
        if (!_wcsicmp(szGroup, L"Administrators") || !_wcsicmp(szGroup, L"Administrator"))
            bAdmin = TRUE;
        else if (_wcsicmp(szGroup, L"Users") && _wcsicmp(szGroup, L"User"))
            UnattendLog(L"[UserAccount] Group \"%s\" is not Users or Administrators: using Users", szGroup);
    }

    hNetapi = LoadLibraryW(L"netapi32.dll");
    if (!hNetapi)
    {
        UnattendLog(L"cannot load netapi32.dll: no account created");
        return FALSE;
    }
    pfnUserAdd = (PFN_NETUSERADD)GetProcAddress(hNetapi, "NetUserAdd");
    pfnAddMembers = (PFN_NETLGADDMEMBERS)GetProcAddress(hNetapi, "NetLocalGroupAddMembers");
    if (!pfnUserAdd || !pfnAddMembers)
    {
        UnattendLog(L"netapi32.dll has no account functions: no account created");
        FreeLibrary(hNetapi);
        return FALSE;
    }

    ZeroMemory(&ui, sizeof(ui));
    ui.usri1_name = pszName;
    ui.usri1_password = pszPassword;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
    ui.usri1_comment = szFullName[0] ? szFullName : NULL;
    st = pfnUserAdd(NULL, 1, (LPBYTE)&ui, &dwParam);
    if (st == NERR_Success)
    {
        UnattendLog(L"account \"%s\" created (%s)", pszName, bAdmin ? L"Administrators" : L"Users");
        AddToGroup(hNetapi, bAdmin ? L"Administrators" : L"Users", pszName);
        bOk = TRUE;
    }
    else if (st == NERR_UserExists)
    {
        UnattendLog(L"account \"%s\" exists already: left as it is", pszName);
    }
    else
    {
        UnattendLog(L"cannot create the account \"%s\" (error %lu, parameter %lu)", pszName, (ULONG)st, dwParam);
    }
    FreeLibrary(hNetapi);
    return bOk;
}

/* AUTOMATIC LOGON **********************************************************/

/*
 * Winlogon values: AutoAdminLogon, DefaultUserName, DefaultDomainName, DefaultPassword and
 * AutoLogonCount (a number of logons after which msgina stops it and deletes the password;
 * the Windows Winlogon value of the same name). Without a count the logon is permanent and the
 * password stays in the registry: the log says so.
 */
static VOID
SetWinlogonAutoLogon(
    _In_ PCWSTR pszUser,
    _In_ PCWSTR pszPassword,
    _In_ DWORD dwCount)
{
    HKEY hKey;
    WCHAR szComputer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cchComputer = _countof(szComputer);

    /* GetComputerName still returns the name of the first stage until the restart: read the name setup set */
    {
        HKEY hName;
        DWORD cb = sizeof(szComputer), type;

        szComputer[0] = UNICODE_NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", 0,
                          KEY_QUERY_VALUE, &hName) == ERROR_SUCCESS)
        {
            if (RegQueryValueExW(hName, L"ComputerName", NULL, &type, (LPBYTE)szComputer, &cb) != ERROR_SUCCESS || type != REG_SZ)
                szComputer[0] = UNICODE_NULL;
            RegCloseKey(hName);
        }
        (void)cchComputer;
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
    {
        UnattendLog(L"cannot open the Winlogon key: automatic logon not set");
        return;
    }
    RegSetValueExW(hKey, L"AutoAdminLogon", 0, REG_SZ, (const BYTE *)L"1", 2 * sizeof(WCHAR));
    RegSetValueExW(hKey, L"DefaultUserName", 0, REG_SZ, (const BYTE *)pszUser, (DWORD)((wcslen(pszUser) + 1) * sizeof(WCHAR)));
    RegSetValueExW(hKey, L"DefaultDomainName", 0, REG_SZ, (const BYTE *)szComputer, (DWORD)((wcslen(szComputer) + 1) * sizeof(WCHAR)));
    RegSetValueExW(hKey, L"DefaultPassword", 0, REG_SZ, (const BYTE *)pszPassword, (DWORD)((wcslen(pszPassword) + 1) * sizeof(WCHAR)));
    if (dwCount)
        RegSetValueExW(hKey, L"AutoLogonCount", 0, REG_DWORD, (const BYTE *)&dwCount, sizeof(dwCount));
    else
        RegDeleteValueW(hKey, L"AutoLogonCount");
    RegCloseKey(hKey);
    if (dwCount)
        UnattendLog(L"automatic logon of \"%s\" for %lu time(s)", pszUser, dwCount);
    else
        UnattendLog(L"automatic logon of \"%s\" at every start (AutoLogonCount = 0): its password stays in the registry",
                    pszUser);
}

/* NETWORK ******************************************************************/

static BOOL
ParseIPv4(
    _In_ PCWSTR pszText,
    _Out_ PULONG pulAddr)
{
    ULONG ulAddr = 0, ulOctet, i;
    PCWSTR p = pszText;

    /* four decimal octets 0..255 separated by dots, nothing else */
    for (i = 0; i < 4; i++)
    {
        PWSTR pEnd = NULL;

        if (*p < L'0' || *p > L'9')
            return FALSE;
        ulOctet = wcstoul(p, &pEnd, 10);
        if (ulOctet > 255 || pEnd - p > 3)
            return FALSE;
        ulAddr = (ulAddr << 8) | ulOctet;
        p = pEnd;
        if (i < 3)
        {
            if (*p != L'.')
                return FALSE;
            p++;
        }
    }
    if (*p)
        return FALSE;
    *pulAddr = ulAddr;
    return TRUE;
}

/* The mask of a prefix length 1..32 in the order of the text 255.255.255.0 */
static VOID
MaskString(
    _In_ ULONG ulPrefix,
    _Out_writes_(cch) PWSTR pszOut,
    _In_ size_t cch)
{
    ULONG mask = ulPrefix ? (0xFFFFFFFFu << (32 - ulPrefix)) : 0;

    StringCchPrintfW(pszOut, cch, L"%lu.%lu.%lu.%lu", (mask >> 24) & 255, (mask >> 16) & 255, (mask >> 8) & 255, mask & 255);
}

/* The Tcpip\Parameters\Interfaces\{GUID} key of the first adapter (the one with an EnableDHCP value) */
static BOOL
OpenFirstInterfaceKey(
    _Out_ PHKEY phKey)
{
    HKEY hParent;
    WCHAR szName[128];
    DWORD i;
    BOOL bFound = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                      0, KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
        return FALSE;
    for (i = 0; !bFound && RegEnumKeyW(hParent, i, szName, _countof(szName)) == ERROR_SUCCESS; i++)
    {
        HKEY hKey;
        DWORD dwType, dwSize = 0;

        if (RegOpenKeyExW(hParent, szName, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
            continue;
        if (RegQueryValueExW(hKey, L"EnableDHCP", NULL, &dwType, NULL, &dwSize) == ERROR_SUCCESS)
        {
            *phKey = hKey;
            bFound = TRUE;
        }
        else
        {
            RegCloseKey(hKey);
        }
    }
    RegCloseKey(hParent);
    return bFound;
}

static VOID
SetMultiSz(
    _In_ HKEY hKey,
    _In_ PCWSTR pszValue,
    _In_ PCWSTR pszText)
{
    WCHAR szBuf[128];
    size_t len = wcslen(pszText);

    if (len + 2 > _countof(szBuf))
        return;
    memcpy(szBuf, pszText, len * sizeof(WCHAR));
    szBuf[len] = szBuf[len + 1] = UNICODE_NULL;
    RegSetValueExW(hKey, pszValue, 0, REG_MULTI_SZ, (const BYTE *)szBuf, (DWORD)((len + 2) * sizeof(WCHAR)));
}

/*
 * [Network]  Mode = dhcp (default) | static
 *   IPAddress, SubnetMask (or PrefixLength), Gateway, DNS (comma or space separated)
 *   IPv6Address, IPv6Gateway, IPv6DNS: see ApplyIPv6 (not supported by this stack's setup-time configuration)
 */
static VOID
ApplyNetworkConfiguration(VOID)
{
    WCHAR szMode[16], szAddr[64], szMask[64], szGw[64], szDns[256], szPrefix[16];
    ULONG ulAddr, ulMask = 0, ulGw, ulPrefix = 0;
    HKEY hKey;
    WCHAR szMaskText[32];

    if (!UnattendGetString(L"Network", L"Mode", szMode, _countof(szMode)))
        return; /* DHCP: nothing to do */
    if (!_wcsicmp(szMode, L"dhcp"))
        return;
    if (_wcsicmp(szMode, L"static"))
    {
        UnattendLog(L"bad value for [Network] Mode (dhcp or static expected): using dhcp");
        return;
    }

    if (!UnattendGetString(L"Network", L"IPAddress", szAddr, _countof(szAddr)) || !ParseIPv4(szAddr, &ulAddr))
    {
        UnattendLog(L"[Network] Mode = static needs a valid IPv4 IPAddress: using dhcp");
        return;
    }
    if (UnattendGetString(L"Network", L"SubnetMask", szMask, _countof(szMask)))
    {
        if (!ParseIPv4(szMask, &ulMask) || !ulMask)
        {
            UnattendLog(L"bad value for [Network] SubnetMask: using dhcp");
            return;
        }
        StringCchCopyW(szMaskText, _countof(szMaskText), szMask);
    }
    else if (UnattendGetString(L"Network", L"PrefixLength", szPrefix, _countof(szPrefix)))
    {
        ulPrefix = (ULONG)_wtoi(szPrefix);
        if (ulPrefix < 1 || ulPrefix > 32)
        {
            UnattendLog(L"bad value for [Network] PrefixLength (1 to 32 expected): using dhcp");
            return;
        }
        MaskString(ulPrefix, szMaskText, _countof(szMaskText));
    }
    else
    {
        StringCchCopyW(szMaskText, _countof(szMaskText), L"255.255.255.0");
        UnattendLog(L"[Network] has no SubnetMask or PrefixLength: using 255.255.255.0");
    }
    szGw[0] = UNICODE_NULL;
    if (UnattendGetString(L"Network", L"Gateway", szGw, _countof(szGw)) && !ParseIPv4(szGw, &ulGw))
    {
        UnattendLog(L"bad value for [Network] Gateway: no default gateway set");
        szGw[0] = UNICODE_NULL;
    }
    if (!UnattendGetString(L"Network", L"DNS", szDns, _countof(szDns)))
        szDns[0] = UNICODE_NULL;

    if (!OpenFirstInterfaceKey(&hKey))
    {
        UnattendLog(L"no network adapter was found in the registry: the static address is not set");
        return;
    }
    {
        DWORD dwZero = 0;
        PWSTR p;

        RegSetValueExW(hKey, L"EnableDHCP", 0, REG_DWORD, (const BYTE *)&dwZero, sizeof(dwZero));
        SetMultiSz(hKey, L"IPAddress", szAddr);
        SetMultiSz(hKey, L"SubnetMask", szMaskText);
        SetMultiSz(hKey, L"DefaultGateway", szGw[0] ? szGw : L"0.0.0.0");
        /* the DNS servers: comma separated in the registry as Windows keeps them */
        for (p = szDns; *p; p++)
        {
            if (*p == L' ' || *p == L';')
                *p = L',';
        }
        RegSetValueExW(hKey, L"NameServer", 0, REG_SZ, (const BYTE *)szDns, (DWORD)((wcslen(szDns) + 1) * sizeof(WCHAR)));
    }
    RegCloseKey(hKey);
    UnattendLog(L"static IPv4 configuration: %s / %s, gateway %s, DNS %s", szAddr, szMaskText,
                szGw[0] ? szGw : L"none", szDns[0] ? szDns : L"none");
}

/* FEATURES *****************************************************************/

/* TRUE when the output of the feature manager (Panther\feature-<name>.log) says the download could not reach
 * the server: the failure of a missing network, worth trying again later */
static BOOL
FeatureLogSaysNoNetwork(
    _In_ PCWSTR pszName)
{
    WCHAR szPath[MAX_PATH];
    CHAR szBuf[4096];
    HANDLE hFile;
    DWORD cb = 0;
    BOOL bNet;

    if (!GetWindowsDirectoryW(szPath, _countof(szPath)))
        return FALSE;
    StringCchPrintfW(szPath + wcslen(szPath), _countof(szPath) - wcslen(szPath), L"\\Panther\\feature-%s.log", pszName);
    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    ReadFile(hFile, szBuf, sizeof(szBuf) - 1, &cb, NULL);
    CloseHandle(hFile);
    szBuf[cb] = ANSI_NULL;
    /* "unknown feature": the edition has no such feature, waiting does not help */
    bNet = strstr(szBuf, "Cannot reach") != NULL && strstr(szBuf, "unknown feature") == NULL;
    return bNet;
}

/*
 * [Features]  Install = powershell-7, firefox   (names of the feature manager's catalog: featmgr /list)
 * Each is installed by "featmgr /enable <name>" at the end of setup, before the first start; a feature that
 * is not available on this system, or that fails, is logged and setup goes on.
 */
static VOID
InstallConfiguredFeatures(VOID)
{
    WCHAR szList[512], *p, *tok, szCmd[300], szPending[512] = L"";
    HRESULT hr;

    /* [Features] FirstBootDefaults = no: the first-boot installer does not install its default components
     * (HKLM\SOFTWARE\ReactOS\Nitro\Featmgr AutoInstall = 0); the features of Install= below are still installed */
    if (UnattendGetString(L"Features", L"FirstBootDefaults", szCmd, _countof(szCmd)) &&
        !UnattendGetBool(L"Features", L"FirstBootDefaults", TRUE))
    {
        HKEY hKey;
        DWORD dwZero = 0;

        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Featmgr", 0, NULL, 0,
                            KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS)
        {
            RegSetValueExW(hKey, L"AutoInstall", 0, REG_DWORD, (const BYTE *)&dwZero, sizeof(dwZero));
            RegCloseKey(hKey);
            UnattendLog(L"first-boot default components are switched off (FirstBootDefaults = no)");
        }
    }

    if (!UnattendGetString(L"Features", L"Install", szList, _countof(szList)))
        return;
    for (p = szList; *p; p++)
    {
        if (*p == L',' || *p == L';')
            *p = L' ';
    }
    p = szList;
    while (*p)
    {
        size_t i, len;
        BOOL bValid = TRUE;

        while (*p == L' ')
            p++;
        tok = p;
        while (*p && *p != L' ')
            p++;
        len = (size_t)(p - tok);
        if (*p)
            *p++ = UNICODE_NULL;
        if (!len)
            continue;
        /* a catalog name: letters, digits, '-', '_', '.' */
        for (i = 0; i < len; i++)
        {
            if (!((tok[i] >= L'a' && tok[i] <= L'z') || (tok[i] >= L'A' && tok[i] <= L'Z') ||
                  (tok[i] >= L'0' && tok[i] <= L'9') || tok[i] == L'-' || tok[i] == L'_' || tok[i] == L'.'))
                bValid = FALSE;
        }
        if (!bValid || len > 64)
        {
            UnattendLog(L"[Features] \"%s\" is not a feature name: skipped", tok);
            continue;
        }
        {
            WCHAR szWin[MAX_PATH];

            /* the output of the feature manager goes to <windir>\Panther\feature-<name>.log */
            if (!GetWindowsDirectoryW(szWin, _countof(szWin)))
                szWin[0] = UNICODE_NULL;
            StringCchPrintfW(szCmd, _countof(szCmd), L"cmd.exe /c featmgr.exe /enable %s > \"%s\\Panther\\feature-%s.log\" 2>&1",
                             tok, szWin, tok);
        }
        UnattendLog(L"installing feature \"%s\"", tok);
        hr = RunCommandAndWait(szCmd);
        if (SUCCEEDED(hr))
        {
            UnattendLog(L"feature \"%s\" installed", tok);
        }
        else if (FeatureLogSaysNoNetwork(tok))
        {
            /* The network is not up while setup runs: the NitroFirstRun service installs it at the first start */
            UnattendLog(L"feature \"%s\" needs the network, which is not up yet: it is installed at the first start", tok);
            if (wcslen(szPending) + wcslen(tok) + 2 < _countof(szPending))
            {
                if (szPending[0])
                    wcscat(szPending, L" ");
                wcscat(szPending, tok);
            }
        }
        else
        {
            UnattendLog(L"feature \"%s\" could not be installed (0x%08lx): see Panther\\feature-%s.log; setup goes on",
                        tok, (ULONG)hr, tok);
        }
    }

    if (szPending[0])
    {
        HKEY hKey;

        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Unattend", 0, NULL, 0, KEY_SET_VALUE,
                            NULL, &hKey, NULL) == ERROR_SUCCESS)
        {
            RegSetValueExW(hKey, L"PendingFeatures", 0, REG_SZ, (const BYTE *)szPending,
                           (DWORD)((wcslen(szPending) + 1) * sizeof(WCHAR)));
            RegCloseKey(hKey);
        }
    }
}

/* FIRST LOGON COMMANDS *****************************************************/

/*
 * [FirstLogon]  one command line per line (batch syntax).
 * Each command runs once for every user, at that user's first logon, whoever the user is. ([GuiRunOnce] runs
 * once, at the first logon of an administrator: the shell only runs the machine RunOnce list for one.)
 * A line becomes <windir>\Panther\first-logon-<n>.cmd, started from HKLM\...\Run; the batch file marks the
 * user (%APPDATA%\unattend-first-<n>.done) before it runs the line, so it runs once.
 */
static VOID
RegisterFirstLogonCommands(VOID)
{
    WCHAR szPath[MAX_PATH], szWin[MAX_PATH];
    PWSTR pszSection, p;
    HKEY hRun;
    int n = 0;

    GetSetupInfPath(szPath, _countof(szPath));
    if (!szPath[0] || !GetWindowsDirectoryW(szWin, _countof(szWin)))
        return;
    pszSection = HeapAlloc(GetProcessHeap(), 0, 32768 * sizeof(WCHAR));
    if (!pszSection)
        return;
    if (!GetPrivateProfileSectionW(L"FirstLogon", pszSection, 32768, szPath) || !pszSection[0])
    {
        HeapFree(GetProcessHeap(), 0, pszSection);
        return;
    }
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0,
                        KEY_SET_VALUE, NULL, &hRun, NULL) != ERROR_SUCCESS)
    {
        UnattendLog(L"cannot open the Run key: [FirstLogon] commands not registered");
        HeapFree(GetProcessHeap(), 0, pszSection);
        return;
    }

    for (p = pszSection; *p; p += wcslen(p) + 1)
    {
        WCHAR szFile[MAX_PATH], szName[40], szRun[MAX_PATH + 40];
        CHAR szHead[256], szCmd[4096];
        HANDLE hFile;
        DWORD cbWritten;
        int cbCmd;

        if (*p == L';')
            continue;
        n++;
        StringCchPrintfW(szFile, _countof(szFile), L"%s\\Panther\\first-logon-%d.cmd", szWin, n);
        cbCmd = WideCharToMultiByte(CP_ACP, 0, p, -1, szCmd, sizeof(szCmd) - 1, NULL, NULL);
        if (cbCmd <= 1)
        {
            UnattendLog(L"[FirstLogon] line %d is too long or cannot be converted: skipped", n);
            continue;
        }
        _snprintf(szHead, sizeof(szHead),
                  "@echo off\r\nif exist \"%%APPDATA%%\\unattend-first-%d.done\" exit /b 0\r\n"
                  "echo.>\"%%APPDATA%%\\unattend-first-%d.done\"\r\n", n, n);
        hFile = CreateFileW(szFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            UnattendLog(L"cannot write %s (error %lu): [FirstLogon] line %d skipped", szFile, GetLastError(), n);
            continue;
        }
        WriteFile(hFile, szHead, (DWORD)strlen(szHead), &cbWritten, NULL);
        WriteFile(hFile, szCmd, (DWORD)strlen(szCmd), &cbWritten, NULL);
        WriteFile(hFile, "\r\n", 2, &cbWritten, NULL);
        CloseHandle(hFile);

        StringCchPrintfW(szName, _countof(szName), L"UnattendFirstLogon%d", n);
        StringCchPrintfW(szRun, _countof(szRun), L"cmd.exe /c call \"%s\"", szFile);
        RegSetValueExW(hRun, szName, 0, REG_SZ, (const BYTE *)szRun, (DWORD)((wcslen(szRun) + 1) * sizeof(WCHAR)));
        UnattendLog(L"first-logon command %d for every user registered (%s)", n, szFile);
    }
    RegCloseKey(hRun);
    HeapFree(GetProcessHeap(), 0, pszSection);
}

/* ENTRY POINTS *************************************************************/

/*
 * Called by InstallReactOS() after the wizard: the parts of the answer file the wizard pages do not
 * cover. Never blocks, never fails the installation.
 */
VOID
ProcessUnattendedExtras(VOID)
{
    WCHAR szName[64], szPassword[128];
    BOOL bAccount;

    if (!UnattendGetBool(L"Unattend", L"UnattendSetupEnabled", FALSE))
        return;

    UnattendLog(L"second stage: applying the answer file");

    bAccount = CreateConfiguredAccount(szName, _countof(szName), szPassword, _countof(szPassword));
    if (bAccount && UnattendGetBool(L"UserAccount", L"AutoLogon", FALSE))
    {
        WCHAR szCount[16];
        DWORD dwCount = 1;

        if (UnattendGetString(L"UserAccount", L"AutoLogonCount", szCount, _countof(szCount)))
        {
            WCHAR *pEnd = NULL;
            ULONG ulCount = wcstoul(szCount, &pEnd, 10);
            if (*pEnd || ulCount > 100000)
                UnattendLog(L"bad value for [UserAccount] AutoLogonCount (a number from 0 expected): using 1");
            else
                dwCount = ulCount;
        }
        SetWinlogonAutoLogon(szName, szPassword, dwCount);
    }
    SecureZeroMemory(szPassword, sizeof(szPassword));

    /* The features first (they may download, over the DHCP lease setup is running with), then the fixed
     * address, which the TCP/IP stack takes up at the next start */
    RegisterFirstLogonCommands();
    InstallConfiguredFeatures();
    ApplyNetworkConfiguration();
}

/* [Unattend] FinalAction = reboot (default) | shutdown: what setup does when the installation is finished */
BOOL
UnattendWantsShutdown(VOID)
{
    WCHAR szValue[16];

    if (!UnattendGetBool(L"Unattend", L"UnattendSetupEnabled", FALSE))
        return FALSE;
    if (!UnattendGetString(L"Unattend", L"FinalAction", szValue, _countof(szValue)))
        return FALSE;
    if (!_wcsicmp(szValue, L"shutdown") || !_wcsicmp(szValue, L"poweroff"))
    {
        UnattendLog(L"FinalAction = shutdown: the computer is switched off when setup is done");
        return TRUE;
    }
    if (_wcsicmp(szValue, L"reboot") && _wcsicmp(szValue, L"restart"))
        UnattendLog(L"bad value for FinalAction (reboot or shutdown expected): restarting");
    return FALSE;
}

/* EOF */
