/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests that the user's choice of handler (UserChoice) wins over the machine wide
 *              default for URL protocols and file extensions (AssocQueryString, FindExecutable)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows 10 only honours a UserChoice that carries a valid "Hash" (written by the shell, not by a program),
 * so this test, which writes plain UserChoice values, only runs on ReactOS.
 * What was measured on Windows 10 (build 19045): AssocQueryString(".html") returns the UserChoice handler
 * (Edge), also with ASSOCF_NOUSERSETTINGS.
 */

#include "shelltest.h"
#include <shlwapi.h>

#define HKLM HKEY_LOCAL_MACHINE
#define HKCU HKEY_CURRENT_USER

#define PROTO       L"rosuctestproto"
#define EXT         L".rosuctestext"
#define CLASS_DEF   L"RosUcTest.Default"
#define CLASS_USER  L"RosUcTest.User"
#define CLASS_NOSH  L"RosUcTest.NoShell"
#define CLASSES     L"SOFTWARE\\Classes\\"
#define URLASSOC    L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\"
#define FILEEXTS    L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\"

static void SetStr(HKEY hRoot, LPCWSTR pszKey, LPCWSTR pszName, LPCWSTR pszData)
{
    HKEY hKey;
    LONG err = RegCreateKeyExW(hRoot, pszKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (err == ERROR_SUCCESS)
    {
        err = RegSetValueExW(hKey, pszName, 0, REG_SZ, (const BYTE *)pszData, (lstrlenW(pszData) + 1) * sizeof(WCHAR));
        RegCloseKey(hKey);
    }
    ok(err == ERROR_SUCCESS, "Setting %ls failed with %ld\n", pszKey, err);
}

static void Cleanup(void)
{
    SHDeleteKeyW(HKLM, CLASSES PROTO);
    SHDeleteKeyW(HKLM, CLASSES EXT);
    SHDeleteKeyW(HKLM, CLASSES CLASS_DEF);
    SHDeleteKeyW(HKLM, CLASSES CLASS_USER);
    SHDeleteKeyW(HKLM, CLASSES CLASS_NOSH);
    SHDeleteKeyW(HKCU, URLASSOC PROTO);
    SHDeleteKeyW(HKCU, FILEEXTS EXT);
}

/* The executable of the handler in <pszSource>'s verb "open", or an empty string */
static HRESULT QueryExe(DWORD flags, LPCWSTR pszSource, LPWSTR pszOut, DWORD cch)
{
    pszOut[0] = UNICODE_NULL;
    return AssocQueryStringW(flags, ASSOCSTR_EXECUTABLE, pszSource, L"open", pszOut, &cch);
}

static void CheckExe(int line, DWORD flags, LPCWSTR pszSource, LPCWSTR pszExpect)
{
    WCHAR szExe[MAX_PATH];
    HRESULT hr = QueryExe(flags, pszSource, szExe, _countof(szExe));
    ok(SUCCEEDED(hr), "%d: AssocQueryString(0x%lx, %ls) failed with 0x%lx\n", line, flags, pszSource, hr);
    if (SUCCEEDED(hr))
        ok(StrStrIW(szExe, pszExpect) != NULL, "%d: AssocQueryString(0x%lx, %ls) returned '%ls', expected %ls\n",
           line, flags, pszSource, szExe, pszExpect);
}

/* ShellExecuteEx of <pszFile> starts a process whose image is <pszExpect> */
static void CheckShellExec(int line, LPCWSTR pszFile, LPCWSTR pszExpect)
{
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    WCHAR szImage[MAX_PATH] = L"";
    DWORD cch = _countof(szImage);
    typedef BOOL (WINAPI *QFPIN)(HANDLE, DWORD, LPWSTR, PDWORD);
    QFPIN pfnQuery = (QFPIN)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "QueryFullProcessImageNameW");

    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    sei.lpVerb = L"open";
    sei.lpFile = pszFile;
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei) || !sei.hProcess)
    {
        ok(0, "%d: ShellExecuteEx(%ls) failed with %lu\n", line, pszFile, GetLastError());
        return;
    }
    if (pfnQuery && pfnQuery(sei.hProcess, 0, szImage, &cch))
        ok(StrStrIW(szImage, pszExpect) != NULL, "%d: ShellExecuteEx(%ls) started '%ls', expected %ls\n",
           line, pszFile, szImage, pszExpect);
    else
        ok(0, "%d: QueryFullProcessImageName not available or failed with %lu\n", line, GetLastError());
    WaitForSingleObject(sei.hProcess, 10000);
    CloseHandle(sei.hProcess);
}

START_TEST(UserChoiceHandlers)
{
    WCHAR szSys[MAX_PATH], szCmdA[MAX_PATH + 32], szCmdB[MAX_PATH + 32], szFile[MAX_PATH], szTemp[MAX_PATH];
    HANDLE hFile;
    HRESULT hrInit;

    if (!is_reactos())
    {
        skip("Windows only honours a UserChoice with the shell's Hash\n");
        return;
    }
    hrInit = CoInitialize(NULL);

    GetSystemDirectoryW(szSys, _countof(szSys));
    wsprintfW(szCmdA, L"\"%ls\\cmd.exe\" /c exit /b 0 \"%%1\"", szSys);
    wsprintfW(szCmdB, L"\"%ls\\ping.exe\" -n 1 127.0.0.1 \"%%1\"", szSys);

    Cleanup();

    /* A URL protocol whose machine wide handler is cmd.exe, and two ProgIds */
    SetStr(HKLM, CLASSES PROTO, NULL, L"URL:RosUcTest");
    SetStr(HKLM, CLASSES PROTO, L"URL Protocol", L"");
    SetStr(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, szCmdA);
    SetStr(HKLM, CLASSES CLASS_USER L"\\shell\\open\\command", NULL, szCmdB);
    SetStr(HKLM, CLASSES CLASS_DEF L"\\shell\\open\\command", NULL, szCmdA);
    SetStr(HKLM, CLASSES CLASS_NOSH, NULL, L"no shell key");

    /* A file extension whose default ProgId opens with cmd.exe */
    SetStr(HKLM, CLASSES EXT, NULL, CLASS_DEF);

    GetTempPathW(_countof(szTemp), szTemp);
    wsprintfW(szFile, L"%lsrosuctest%lu%ls", szTemp, GetCurrentProcessId(), EXT);
    hFile = CreateFileW(szFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "Creating %ls failed with %lu\n", szFile, GetLastError());
    CloseHandle(hFile);

    /* No choice: the machine wide handler */
    CheckExe(__LINE__, 0, PROTO, L"cmd.exe");
    CheckExe(__LINE__, 0, EXT, L"cmd.exe");
    CheckShellExec(__LINE__, szFile, L"cmd.exe");
    CheckShellExec(__LINE__, PROTO L"://test", L"cmd.exe");

    /* The user chose another ProgId */
    SetStr(HKCU, URLASSOC PROTO L"\\UserChoice", L"Progid", CLASS_USER);
    SetStr(HKCU, FILEEXTS EXT L"\\UserChoice", L"ProgId", CLASS_USER);
    CheckExe(__LINE__, 0, PROTO, L"ping.exe");
    CheckExe(__LINE__, 0, EXT, L"ping.exe");
    CheckShellExec(__LINE__, szFile, L"ping.exe");
    CheckShellExec(__LINE__, PROTO L"://test", L"ping.exe");

    /* Windows 10 (build 19045) still returns the chosen handler with ASSOCF_NOUSERSETTINGS */
    CheckExe(__LINE__, ASSOCF_NOUSERSETTINGS, PROTO, L"ping.exe");
    CheckExe(__LINE__, ASSOCF_NOUSERSETTINGS, EXT, L"ping.exe");

    /* A choice naming a class that does not exist or has no shell key (an uninstalled application) is ignored */
    SetStr(HKCU, URLASSOC PROTO L"\\UserChoice", L"Progid", L"RosUcTest.Missing");
    SetStr(HKCU, FILEEXTS EXT L"\\UserChoice", L"ProgId", L"RosUcTest.Missing");
    CheckExe(__LINE__, 0, PROTO, L"cmd.exe");
    CheckExe(__LINE__, 0, EXT, L"cmd.exe");
    CheckShellExec(__LINE__, szFile, L"cmd.exe");
    SetStr(HKCU, URLASSOC PROTO L"\\UserChoice", L"Progid", CLASS_NOSH);
    SetStr(HKCU, FILEEXTS EXT L"\\UserChoice", L"ProgId", CLASS_NOSH);
    CheckExe(__LINE__, 0, PROTO, L"cmd.exe");
    CheckExe(__LINE__, 0, EXT, L"cmd.exe");

    /* Back to no choice */
    SHDeleteKeyW(HKCU, URLASSOC PROTO);
    SHDeleteKeyW(HKCU, FILEEXTS EXT);
    CheckExe(__LINE__, 0, PROTO, L"cmd.exe");
    CheckExe(__LINE__, 0, EXT, L"cmd.exe");

    DeleteFileW(szFile);
    Cleanup();
    if (SUCCEEDED(hrInit))
        CoUninitialize();
}
