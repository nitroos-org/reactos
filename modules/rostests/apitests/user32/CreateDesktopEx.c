/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for CreateDesktopExA and CreateDesktopExW
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results were measured on Windows 10 22H2 (x64 and x86): the heap size is in kilobytes, 0 is the
 * default, a size below 16 or above 4194236 is not enough memory, and the reserved parameter is refused
 * by the ANSI version (invalid parameter) and ignored by the wide one.
 */

#include "precomp.h"

typedef HDESK (WINAPI *PFN_CreateDesktopExW)(LPCWSTR, LPCWSTR, DEVMODEW *, DWORD, ACCESS_MASK, LPSECURITY_ATTRIBUTES, ULONG, PVOID);
typedef HDESK (WINAPI *PFN_CreateDesktopExA)(LPCSTR, LPCSTR, DEVMODEA *, DWORD, ACCESS_MASK, LPSECURITY_ATTRIBUTES, ULONG, PVOID);

#define PENDING_ERROR 0xdeadbeef

static PFN_CreateDesktopExW pCreateDesktopExW;
static PFN_CreateDesktopExA pCreateDesktopExA;

static void
CheckCreated(const char *Label, HDESK Desktop, const char *ExpectedName)
{
    CHAR Name[100];
    DWORD Needed;

    ok(Desktop != NULL, "%s: no desktop, error %lu\n", Label, GetLastError());
    if (!Desktop)
        return;
    ZeroMemory(Name, sizeof(Name));
    ok(GetUserObjectInformationA(Desktop, UOI_NAME, Name, sizeof(Name), &Needed), "%s: no name\n", Label);
    ok(strcmp(Name, ExpectedName) == 0, "%s: the desktop is named '%s', expected '%s'\n", Label, Name, ExpectedName);
    ok(CloseDesktop(Desktop), "%s: CloseDesktop failed, error %lu\n", Label, GetLastError());
}

START_TEST(CreateDesktopEx)
{
    HMODULE User32 = GetModuleHandleW(L"user32.dll");
    static const ULONG BadHeaps[] = { 1, 8, 15, 4194237, 0x10000000, 0x7fffffff, 0xffffffff };
    static const ULONG GoodHeaps[] = { 0, 16, 4096 };
    HDESK Desktop;
    CHAR NameA[40];
    WCHAR NameW[40];
    ULONG i;
    static ULONG Counter;

    pCreateDesktopExW = (PFN_CreateDesktopExW)GetProcAddress(User32, "CreateDesktopExW");
    pCreateDesktopExA = (PFN_CreateDesktopExA)GetProcAddress(User32, "CreateDesktopExA");
    if (!pCreateDesktopExW || !pCreateDesktopExA)
    {
        skip("CreateDesktopEx is not exported\n");
        return;
    }

    GetSystemMetrics(SM_CXSCREEN);

    for (i = 0; i < sizeof(GoodHeaps) / sizeof(GoodHeaps[0]); i++)
    {
        wsprintfA(NameA, "DesktopExW%lu_%lu", GetCurrentProcessId(), Counter);
        wsprintfW(NameW, L"DesktopExW%lu_%lu", GetCurrentProcessId(), Counter++);

        SetLastError(PENDING_ERROR);
        Desktop = pCreateDesktopExW(NameW, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL, GoodHeaps[i], NULL);
        CheckCreated("wide", Desktop, NameA);
    }

    for (i = 0; i < sizeof(GoodHeaps) / sizeof(GoodHeaps[0]); i++)
    {
        wsprintfA(NameA, "DesktopExA%lu_%lu", GetCurrentProcessId(), Counter++);
        Desktop = pCreateDesktopExA(NameA, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL, GoodHeaps[i], NULL);
        CheckCreated("ansi", Desktop, NameA);
    }

    for (i = 0; i < sizeof(BadHeaps) / sizeof(BadHeaps[0]); i++)
    {
        wsprintfA(NameA, "DesktopExBad%lu_%lu", GetCurrentProcessId(), Counter);
        wsprintfW(NameW, L"DesktopExBad%lu_%lu", GetCurrentProcessId(), Counter++);

        SetLastError(PENDING_ERROR);
        Desktop = pCreateDesktopExA(NameA, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL, BadHeaps[i], NULL);
        ok(Desktop == NULL, "a desktop with a heap of %lu KB was made (ANSI)\n", BadHeaps[i]);
        ok(GetLastError() == ERROR_NOT_ENOUGH_MEMORY, "heap %lu (ANSI): last error %lu\n", BadHeaps[i], GetLastError());
        if (Desktop)
            CloseDesktop(Desktop);

        SetLastError(PENDING_ERROR);
        Desktop = pCreateDesktopExW(NameW, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL, BadHeaps[i], NULL);
        ok(Desktop == NULL, "a desktop with a heap of %lu KB was made (wide)\n", BadHeaps[i]);
        ok(GetLastError() == ERROR_NOT_ENOUGH_MEMORY, "heap %lu (wide): last error %lu\n", BadHeaps[i], GetLastError());
        if (Desktop)
            CloseDesktop(Desktop);
    }

    /* the reserved parameter */
    wsprintfA(NameA, "DesktopExRes%lu_%lu", GetCurrentProcessId(), Counter);
    wsprintfW(NameW, L"DesktopExRes%lu_%lu", GetCurrentProcessId(), Counter++);
    SetLastError(PENDING_ERROR);
    Desktop = pCreateDesktopExA(NameA, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL, 0, (PVOID)(ULONG_PTR)1);
    ok(Desktop == NULL, "the ANSI version accepts a reserved parameter\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "reserved (ANSI): last error %lu\n", GetLastError());
    if (Desktop)
        CloseDesktop(Desktop);
    Desktop = pCreateDesktopExW(NameW, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL, 0, (PVOID)(ULONG_PTR)1);
    ok(Desktop != NULL, "the wide version refuses a reserved parameter, error %lu\n", GetLastError());
    if (Desktop)
        CloseDesktop(Desktop);
}
