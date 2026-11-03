/*
 * PROJECT:     ReactOS system setup
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     Initialize native and optional WoW64 Program Files locations
 */
#include "precomp.h"
#define NDEBUG
#include <debug.h>

#if defined(_M_AMD64) && defined(BUILD_WOW64_ENABLED)
/* Windows 10 x64 keeps the same six values in both registry views: the
 * ProgramFilesDir / CommonFilesDir pair of the view's own bitness, the (x86)
 * pair and the W6432 pair. Only the first pair differs between the views. */
static BOOL
SetProgramFilesValues(HKEY Key, PCWSTR Program, PCWSTR Common, PCWSTR Program32,
                      PCWSTR Common32, PCWSTR Program64, PCWSTR Common64)
{
    const struct { PCWSTR Name, Data; } Values[] = {
        {L"ProgramFilesDir", Program}, {L"CommonFilesDir", Common},
        {L"ProgramFilesDir (x86)", Program32}, {L"CommonFilesDir (x86)", Common32},
        {L"ProgramW6432Dir", Program64}, {L"CommonW6432Dir", Common64}
    };
    ULONG i;

    for (i = 0; i < ARRAYSIZE(Values); ++i)
    {
        if (RegSetValueExW(Key, Values[i].Name, 0, REG_SZ, (const BYTE *)Values[i].Data,
                           (wcslen(Values[i].Data) + 1) * sizeof(WCHAR)))
            return FALSE;
    }
    return TRUE;
}

static BOOL
InitializeWow64ProgramFiles(PCWSTR Program, PCWSTR Common)
{
    WCHAR Program32[MAX_PATH], Common32[MAX_PATH];
    HKEY Key;
    LONG Error;
    BOOL Result;
    SIZE_T Length = wcslen(Program);

    if (Length + 6 >= ARRAYSIZE(Program32) || wcslen(Common) + 6 >= ARRAYSIZE(Common32))
        return FALSE;
    wcscpy(Program32, Program);
    wcscat(Program32, L" (x86)");
    wcscpy(Common32, Program32);
    if (wcslen(Common) >= Length && !_wcsnicmp(Common, Program, Length))
    {
        wcscat(Common32, Common + Length);
    }
    else
    {
        if (Length + 6 + ARRAYSIZE(L"\\Common Files") > ARRAYSIZE(Common32))
            return FALSE;
        wcscat(Common32, L"\\Common Files");
    }
    /* 64-bit view (the caller already stored its ProgramFilesDir and CommonFilesDir) */
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                          0, KEY_SET_VALUE, &Key);
    if (Error) return FALSE;
    Result = SetProgramFilesValues(Key, Program, Common, Program32, Common32, Program, Common);
    RegCloseKey(Key);
    if (!Result) return FALSE;
    /* Initialize the physical guest view even before registry redirection is
     * enabled. This also keeps this setup change usable on its own branch.
     * Every value is stored expanded, so shell32 never has to write its
     * "%SystemDrive%\..." defaults for a 32-bit process. */
    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
        0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &Key, NULL);
    if (Error) return FALSE;
    Result = SetProgramFilesValues(Key, Program32, Common32, Program32, Common32, Program, Common);
    RegCloseKey(Key);
    if (!Result) return FALSE;
    if (!CreateDirectoryW(Program32, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return FALSE;
    if (!CreateDirectoryW(Common32, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return FALSE;
    return TRUE;
}
#endif

BOOL
InitializeProgramFilesDir(VOID)
{
    LONG Error;
    HKEY hKey;
    DWORD dwLength;
    WCHAR szProgramFilesDirPath[MAX_PATH];
    WCHAR szCommonFilesDirPath[MAX_PATH];
    WCHAR szBuffer[MAX_PATH];

    /* Load 'Program Files' location */
    if (!LoadStringW(hDllInstance,
                     IDS_PROGRAMFILES,
                     szBuffer,
                     ARRAYSIZE(szBuffer)))
    {
        DPRINT1("Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!LoadStringW(hDllInstance,
                     IDS_COMMONFILES,
                     szCommonFilesDirPath,
                     ARRAYSIZE(szCommonFilesDirPath)))
    {
        DPRINT1("Warning: %lu\n", GetLastError());
    }

    /* Expand it */
    if (!ExpandEnvironmentStringsW(szBuffer,
                                   szProgramFilesDirPath,
                                   ARRAYSIZE(szProgramFilesDirPath)))
    {
        DPRINT1("Error: %lu\n", GetLastError());
        return FALSE;
    }

    wcscpy(szBuffer, szProgramFilesDirPath);
    wcscat(szBuffer, L"\\");
    wcscat(szBuffer, szCommonFilesDirPath);

    if (!ExpandEnvironmentStringsW(szBuffer,
                                   szCommonFilesDirPath,
                                   ARRAYSIZE(szCommonFilesDirPath)))
    {
        DPRINT1("Warning: %lu\n", GetLastError());
    }

    /* Store it */
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                          0,
                          KEY_SET_VALUE,
                          &hKey);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("Error: %lu\n", Error);
        return FALSE;
    }

    dwLength = (wcslen(szProgramFilesDirPath) + 1) * sizeof(WCHAR);
    Error = RegSetValueExW(hKey,
                           L"ProgramFilesDir",
                           0,
                           REG_SZ,
                           (LPBYTE)szProgramFilesDirPath,
                           dwLength);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("Error: %lu\n", Error);
        RegCloseKey(hKey);
        return FALSE;
    }

    dwLength = (wcslen(szCommonFilesDirPath) + 1) * sizeof(WCHAR);
    Error = RegSetValueExW(hKey,
                           L"CommonFilesDir",
                           0,
                           REG_SZ,
                           (LPBYTE)szCommonFilesDirPath,
                           dwLength);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("Warning: %lu\n", Error);
    }

    RegCloseKey(hKey);

    /* Create directory */
    // FIXME: Security!
    if (!CreateDirectoryW(szProgramFilesDirPath, NULL))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            DPRINT1("Error: %lu\n", GetLastError());
            return FALSE;
        }
    }

    /* Create directory */
    // FIXME: Security!
    if (!CreateDirectoryW(szCommonFilesDirPath, NULL))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            DPRINT1("Warning: %lu\n", GetLastError());
            // return FALSE;
        }
    }

#if defined(_M_AMD64) && defined(BUILD_WOW64_ENABLED)
    if (!InitializeWow64ProgramFiles(szProgramFilesDirPath, szCommonFilesDirPath))
        DPRINT1("Warning: could not initialize Program Files (x86)\n");
#endif
    return TRUE;
}
