/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SystemWow64Directory availability, A/W sizing, canaries and launch path
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* SystemWow64Directory availability, A/W sizing, canaries and launch path. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)
int main(void)
{
    struct { DWORD Before; WCHAR Text[MAX_PATH]; DWORD After; } W;
    struct { DWORD Before; CHAR Text[MAX_PATH]; DWORD After; } A;
    WCHAR Expected[MAX_PATH];
    CHAR ExpectedA[MAX_PATH];
    UINT Length;
    BOOL Wow = FALSE;
    IsWow64Process(GetCurrentProcess(), &Wow);
    memset(&W, 0xa5, sizeof(W)); memset(&A, 0xa5, sizeof(A));
    if (!Wow && sizeof(void*) == 4)
    {
        CHECK(GetSystemWow64DirectoryW(W.Text, MAX_PATH) == 0);
        CHECK(GetLastError() == ERROR_CALL_NOT_IMPLEMENTED);
        CHECK(GetSystemWow64DirectoryA(A.Text, MAX_PATH) == 0);
        CHECK(GetLastError() == ERROR_CALL_NOT_IMPLEMENTED);
    }
    else
    {
        CHECK(GetWindowsDirectoryW(Expected, MAX_PATH));
        wcscat(Expected, L"\\SysWOW64"); Length = wcslen(Expected);
        CHECK(GetSystemWow64DirectoryW(NULL, 0) == Length + 1);
        CHECK(GetSystemWow64DirectoryW(W.Text, Length) == Length + 1);
        CHECK(W.Text[0] == 0xa5a5);
        CHECK(GetSystemWow64DirectoryW(W.Text, Length + 1) == Length);
        CHECK(!wcscmp(W.Text, Expected));
        CHECK(W.Text[Length + 1] == 0xa5a5);
        CHECK(WideCharToMultiByte(CP_ACP, 0, Expected, -1, ExpectedA, MAX_PATH, NULL, NULL));
        Length = strlen(ExpectedA);
        CHECK(GetSystemWow64DirectoryA(NULL, 0) == Length + 1);
        CHECK(GetSystemWow64DirectoryA(A.Text, Length) == Length + 1);
        CHECK((UCHAR)A.Text[0] == 0xa5);
        CHECK(GetSystemWow64DirectoryA(A.Text, Length + 1) == Length);
        CHECK(!strcmp(A.Text, ExpectedA));
        CHECK((UCHAR)A.Text[Length + 1] == 0xa5);
        wcscat(Expected, L"\\msiexec.exe");
        CHECK(GetFileAttributesW(Expected) != INVALID_FILE_ATTRIBUTES);
    }
    CHECK(W.Before == 0xa5a5a5a5 && W.After == 0xa5a5a5a5);
    CHECK(A.Before == 0xa5a5a5a5 && A.After == 0xa5a5a5a5);
    printf("WOW64 DIRECTORY: %u checks, %u failures\n", Checks, Failures);
    return Failures ? 1 : 0;
}
