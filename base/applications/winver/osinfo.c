/*
 * PROJECT:     ReactOS Version Program
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Retrieve OS name and simple compatibility information
 * COPYRIGHT:   Copyright 2025 Thamatip Chitpong <thamatip.chitpong@reactos.org>
 */

#include "winver_p.h"

#define OSINFO_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

static
VOID
Winver_GetRegValueString(
    _In_ HKEY hKey,
    _In_ LPCWSTR pValue,
    _Out_ LPWSTR pBuffer,
    _In_ DWORD cchSize)
{
    DWORD dwType, dwSize;
    LSTATUS lError;

    /* NOTE: Reserved space for a NULL terminator */
    dwSize = (cchSize - 1) * sizeof(WCHAR);
    lError = RegQueryValueExW(hKey, pValue, NULL, &dwType, (LPBYTE)pBuffer, &dwSize);
    if (lError != ERROR_SUCCESS || dwType != REG_SZ)
    {
        /* Return empty string on failure */
        pBuffer[0] = UNICODE_NULL;
        return;
    }

    /* Ensure the returned string is NULL terminated */
    pBuffer[cchSize - 1] = UNICODE_NULL;
}

static
VOID
Winver_GetFormattedSpkInfo(
    _In_ HKEY hKey,
    _Out_ LPWSTR pBuffer,
    _In_ DWORD cchSize)
{
    WCHAR szRegValue[48];
    WCHAR szFormat[16] = L"";

    Winver_GetRegValueString(hKey, L"CSDVersion", szRegValue, _countof(szRegValue));
    if (!szRegValue[0])
    {
        /* Return empty string on failure */
        pBuffer[0] = UNICODE_NULL;
        return;
    }

    LoadStringW(Winver_hInstance,
                IDS_OSINFO_SPK_FORMAT,
                szFormat,
                _countof(szFormat));

    StringCchPrintfW(pBuffer, cchSize, szFormat, szRegValue);
}

typedef LONG (WINAPI *PRTLGETVERSION)(OSVERSIONINFOW *);

static
BOOL
Winver_GetRtlVersion(
    _Out_ LPWSTR pVersion,
    _In_ DWORD cchVersion,
    _Out_ LPWSTR pBuild,
    _In_ DWORD cchBuild)
{
    OSVERSIONINFOW osvi;
    PRTLGETVERSION pRtlGetVersion;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

    pRtlGetVersion = hNtdll ? (PRTLGETVERSION)GetProcAddress(hNtdll, "RtlGetVersion") : NULL;
    if (!pRtlGetVersion)
        return FALSE;

    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (pRtlGetVersion(&osvi) != 0 || !osvi.dwMajorVersion)
        return FALSE;

    StringCchPrintfW(pVersion, cchVersion, L"%lu.%lu", osvi.dwMajorVersion, osvi.dwMinorVersion);
    StringCchPrintfW(pBuild, cchBuild, L"%lu", osvi.dwBuildNumber);
    return TRUE;
}

static
VOID
Winver_FormatCompatInfo(
    _In_ HKEY hKey,
    _Out_ LPWSTR pBuffer,
    _In_ DWORD cchSize)
{
    WCHAR szNtVersion[16];
    WCHAR szNtBuild[16];
    WCHAR szNtSpk[64];
    WCHAR szFormat[64] = L"";

    /* The version the system reports (RtlGetVersion: the same as the desktop shows). The registry keeps
     * CurrentVersion at 6.3 for the programs that read it. The registry is the fallback. */
    if (!Winver_GetRtlVersion(szNtVersion, _countof(szNtVersion), szNtBuild, _countof(szNtBuild)))
    {
        Winver_GetRegValueString(hKey, L"CurrentVersion", szNtVersion, _countof(szNtVersion));
        Winver_GetRegValueString(hKey, L"CurrentBuildNumber", szNtBuild, _countof(szNtBuild));
    }
    /* NOTE: Required info must be valid */
    if (!szNtVersion[0] || !szNtBuild[0])
    {
        /* Return empty string on failure */
        pBuffer[0] = UNICODE_NULL;
        return;
    }

    /* NOTE: Service pack info is optional */
    Winver_GetFormattedSpkInfo(hKey, szNtSpk, _countof(szNtSpk));

    LoadStringW(Winver_hInstance,
                IDS_OSINFO_COMPAT_FORMAT,
                szFormat,
                _countof(szFormat));

    StringCchPrintfW(pBuffer, cchSize, szFormat, szNtVersion, szNtBuild, szNtSpk);
}

BOOL
Winver_GetOSInfo(
    _Out_ PWINVER_OS_INFO OSInfo)
{
    HKEY hKey;
    LSTATUS lError;

    lError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           OSINFO_KEY,
                           0,
                           KEY_QUERY_VALUE,
                           &hKey);
    if (lError != ERROR_SUCCESS)
        return FALSE;

    /* OS name */
    Winver_GetRegValueString(hKey, L"ProductName", OSInfo->szName, _countof(OSInfo->szName));
    if (!OSInfo->szName[0])
    {
        /* This info must be valid */
        RegCloseKey(hKey);
        return FALSE;
    }

    /* Compatibility information */
    Winver_FormatCompatInfo(hKey, OSInfo->szCompatInfo, _countof(OSInfo->szCompatInfo));

    RegCloseKey(hKey);

    return TRUE;
}
