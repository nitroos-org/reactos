/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     regedit.exe /s: an import that cannot be done (missing file, malformed file, unknown root key,
 *              key name that cannot be opened) shows no window, ends within a few seconds and ends with
 *              exit code 0, and the keys after the refused one are still imported (measured on Windows)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifdef KB_STANDALONE
#include <windows.h>
#include <stdio.h>
static int g_failures;
#define ok(cond, ...) do { if (!(cond)) { g_failures++; printf("FAIL line %d: ", __LINE__); } else printf("ok: "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define skip(...) do { printf("skip: "); printf(__VA_ARGS__); } while (0)
#define START_TEST(x) int main(void)
#define TEST_RETURN return 1
#else
#include <apitest.h>
#include <winuser.h>
#include <winreg.h>
#define TEST_RETURN return
#endif
#include <stdlib.h>
#include <string.h>

#define LIMIT_MS 15000
#define SCRATCH  L"Software\\RegeditSilentApitest"

static LSTATUS (WINAPI *pRegDeleteTreeW)(HKEY, LPCWSTR);

typedef struct { DWORD Pid; BOOL Seen; WCHAR Title[128]; } WINSEEN;

static BOOL CALLBACK WinProc(HWND hWnd, LPARAM lParam)
{
    WINSEEN *p = (WINSEEN *)lParam;
    DWORD Pid = 0;

    GetWindowThreadProcessId(hWnd, &Pid);
    if (Pid == p->Pid && IsWindowVisible(hWnd))
    {
        p->Seen = TRUE;
        GetWindowTextW(hWnd, p->Title, ARRAYSIZE(p->Title));
    }
    return TRUE;
}

static BOOL WriteFileText(const WCHAR *Path, const char *Text)
{
    HANDLE h = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD n;
    BOOL ret;

    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    ret = WriteFile(h, Text, (DWORD)strlen(Text), &n, NULL);
    CloseHandle(h);
    return ret;
}

/* Runs "regedit.exe /s File"; returns TRUE if it ended by itself within the limit */
static BOOL RunSilent(const WCHAR *File, DWORD *pExit, BOOL *pWindow, WCHAR *Title)
{
    WCHAR Cmd[MAX_PATH + 32];
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    WINSEEN Seen;
    DWORD Start, Wait;
    BOOL Ended = FALSE;

    wsprintfW(Cmd, L"regedit.exe /s \"%ls\"", File);
    *pExit = 0xdeadbeef;
    *pWindow = FALSE;
    Title[0] = 0;
    if (!CreateProcessW(NULL, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
        return FALSE;

    memset(&Seen, 0, sizeof(Seen));
    Seen.Pid = Pi.dwProcessId;
    Start = GetTickCount();
    for (;;)
    {
        Wait = WaitForSingleObject(Pi.hProcess, 200);
        EnumWindows(WinProc, (LPARAM)&Seen);
        if (Wait == WAIT_OBJECT_0)
        {
            Ended = TRUE;
            GetExitCodeProcess(Pi.hProcess, pExit);
            break;
        }
        if (GetTickCount() - Start > LIMIT_MS)
        {
            TerminateProcess(Pi.hProcess, 99);
            WaitForSingleObject(Pi.hProcess, 5000);
            break;
        }
    }
    *pWindow = Seen.Seen;
    wcscpy(Title, Seen.Title);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    return Ended;
}

static BOOL KeyExists(const WCHAR *Sub)
{
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, Sub, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(hKey);
    return TRUE;
}

static void RunCase(const char *Name, const WCHAR *Dir, const char *Content, BOOL Missing)
{
    WCHAR File[MAX_PATH], Title[128];
    DWORD Exit;
    BOOL Window, Ended;

    wsprintfW(File, L"%ls\\%S.reg", Dir, Name);
    if (Missing)
        DeleteFileW(File);
    else if (!WriteFileText(File, Content))
    {
        skip("cannot write %ls\n", File);
        return;
    }
    Ended = RunSilent(File, &Exit, &Window, Title);
    ok(Ended, "%s: regedit /s ended within %d ms\n", Name, LIMIT_MS);
    ok(!Window, "%s: regedit /s showed a window ('%ls')\n", Name, Title);
    if (Ended)
        ok(Exit == 0, "%s: exit code %lu\n", Name, Exit);
    DeleteFileW(File);
}

START_TEST(regedit_silent)
{
    WCHAR Dir[MAX_PATH];
    char Long[400], Content[1024];
    DWORD Len;
    int i;

    Len = GetTempPathW(ARRAYSIZE(Dir), Dir);
    if (!Len)
    {
        skip("no temporary directory\n");
        TEST_RETURN;
    }
    if (Dir[Len - 1] == L'\\')
        Dir[Len - 1] = 0;

    pRegDeleteTreeW = (PVOID)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "RegDeleteTreeW");
    if (pRegDeleteTreeW)
        pRegDeleteTreeW(HKEY_CURRENT_USER, SCRATCH);

    RunCase("missing", Dir, NULL, TRUE);

    RunCase("malformed", Dir,
            "REGEDIT4\r\n\r\nthis is not a registry file\r\n[HKEY_CURRENT_USER\\" "Software\\RegeditSilentApitest\\Broken\r\n\"v\"=\r\n",
            FALSE);

    RunCase("unknownroot", Dir,
            "REGEDIT4\r\n\r\n[HKEY_BOGUS\\RegeditSilentApitest]\r\n\"v\"=\"1\"\r\n"
            "\r\n[HKEY_CURRENT_USER\\Software\\RegeditSilentApitest\\AfterRoot]\r\n\"v\"=\"2\"\r\n",
            FALSE);
    ok(KeyExists(SCRATCH L"\\AfterRoot"), "key after an unknown root key was imported\n");

    for (i = 0; i < 300; i++)
        Long[i] = 'a';
    Long[300] = 0;
    sprintf(Content,
            "REGEDIT4\r\n\r\n[HKEY_CURRENT_USER\\Software\\RegeditSilentApitest\\%s]\r\n\"v\"=\"1\"\r\n"
            "\r\n[HKEY_CURRENT_USER\\Software\\RegeditSilentApitest\\AfterLong]\r\n\"v\"=\"2\"\r\n", Long);
    RunCase("longkey", Dir, Content, FALSE);
    ok(KeyExists(SCRATCH L"\\AfterLong"), "key after a key that cannot be opened was imported\n");

    if (pRegDeleteTreeW)
        pRegDeleteTreeW(HKEY_CURRENT_USER, SCRATCH);
#ifdef KB_STANDALONE
    return g_failures ? 1 : 0;
#endif
}
