/*
 * PROJECT:     appshim_apitest
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     A process that declares a Windows version in its manifest sees that
 *              version from GetVersion()/RtlGetVersion(); one that does not keeps the
 *              real version. Guards the per-app manifest version lie (T94).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>
#include <stdio.h>
#include "wine/test.h"

#define VER_5_2 0x05020502  /* GetVersion 5.2 / RtlGetVersion 5.2 (real ReactOS base) */
#define VER_6_0 0x06000600  /* GetVersion 6.0 / RtlGetVersion 6.0 (Vista, from manifest) */
#define VER_6_1 0x06010601  /* GetVersion 6.1 / RtlGetVersion 6.1 (Windows 7, from manifest) */
#define VER_10_0 0x0a000a00 /* GetVersion 10.0 / RtlGetVersion 10.0 (Windows 10 identity, as is) */

/* The system version, from the shared user data that no per-process version lie touches (same address on Windows) */
static DWORD system_major_version(void)
{
    return *(volatile ULONG*)(ULONG_PTR)0x7FFE026C;
}

/* HKLM\\SYSTEM\\CurrentControlSet\\Control\\ReactOS\\Settings\\Version\\UnmanifestedVersionLie = 1: a program is told the version
   Windows 10 tells it (6.2 unless its manifest names 8.1 or 10); RtlGetVersion stays 10.0. See versionmatrix.c. */
static BOOL version_lie_switch_on(void)
{
    HKEY hKey;
    DWORD Value = 0, Size = sizeof(Value), Type;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ReactOS\\Settings\\Version",
                      0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, L"UnmanifestedVersionLie", NULL, &Type, (PBYTE)&Value, &Size) != ERROR_SUCCESS ||
        Type != REG_DWORD)
        Value = 0;
    RegCloseKey(hKey);
    return Value == 1;
}

static DWORD run_path(PCWSTR Path)
{
    WCHAR Command[MAX_PATH + 4];
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Process;
    DWORD Code = 0xdeadbeef;

    swprintf(Command, ARRAYSIZE(Command), L"\"%ls\"", Path);
    if (!CreateProcessW(Path, Command, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Process))
    {
        ok(0, "CreateProcess(%ls) failed: %lu\n", Path, GetLastError());
        return Code;
    }
    if (WaitForSingleObject(Process.hProcess, 60000) != WAIT_OBJECT_0)
    {
        ok(0, "%ls did not exit\n", Path);
        TerminateProcess(Process.hProcess, 1);
        WaitForSingleObject(Process.hProcess, 10000);
    }
    else
        GetExitCodeProcess(Process.hProcess, &Code);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
    return Code;
}

static DWORD run_probe(PCWSTR Name)
{
    WCHAR Path[MAX_PATH];
    DWORD Length;
    PWCHAR Slash;

    Length = GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path));
    if (!Length || Length >= ARRAYSIZE(Path))
        return 0xdeadbeef;
    Slash = wcsrchr(Path, L'\\');
    if (!Slash || (size_t)(Slash + 1 - Path) + wcslen(Name) >= ARRAYSIZE(Path))
        return 0xdeadbeef;
    wcscpy(Slash + 1, Name);
    return run_path(Path);
}

START_TEST(manifestcompat)
{
    DWORD None, Vista, Span, VistaWin10;

    None = run_probe(L"appshim_manifestver_none.exe");
    Vista = run_probe(L"appshim_manifestver_vista.exe");
    Span = run_probe(L"appshim_manifestver_span.exe");
    VistaWin10 = run_probe(L"appshim_manifestver_vista_win10.exe");
    trace("none=0x%08lx vista=0x%08lx span=0x%08lx vista_win10=0x%08lx\n", None, Vista, Span, VistaWin10);

    if (is_reactos() && system_major_version() >= 10 && version_lie_switch_on())
    {
        /* Switch on: GetVersion() follows the manifest as on Windows 10 (6.2 for a manifest that names neither
           8.1 nor 10), RtlGetVersion()/RtlGetNtVersionNumbers() stay 10.0 */
        ok(None == 0x06020a00, "no-manifest process reported 0x%08lx, expected 0x06020a00 (6.2/10.0)\n", None);
        ok(Vista == 0x06020a00, "vista-manifest process reported 0x%08lx, expected 0x06020a00 (6.2/10.0)\n", Vista);
        ok(Span == VER_10_0, "vista..win10-manifest process reported 0x%08lx, expected 0x%08lx (10.0/10.0)\n",
           Span, (DWORD)VER_10_0);
        ok(VistaWin10 == VER_10_0, "vista+win10-manifest process reported 0x%08lx, expected 0x%08lx (10.0/10.0)\n",
           VistaWin10, (DWORD)VER_10_0);
    }
    else if (is_reactos() && system_major_version() >= 10)
    {
        /*
         * Windows 10 identity (the default): the system itself is 10.0, and a manifest does not change what a
         * program is told (since Windows 8.1 the supportedOS list does not lower GetVersion()/RtlGetVersion()),
         * so every probe, with or without a manifest, sees 10.0.
         */
        ok(None == VER_10_0, "no-manifest process reported 0x%08lx, expected 0x%08lx (10.0/10.0)\n",
           None, (DWORD)VER_10_0);
        ok(Vista == VER_10_0, "vista-manifest process reported 0x%08lx, expected 0x%08lx (10.0/10.0)\n",
           Vista, (DWORD)VER_10_0);
        ok(Span == VER_10_0, "vista..win10-manifest process reported 0x%08lx, expected 0x%08lx (10.0/10.0)\n",
           Span, (DWORD)VER_10_0);
        ok(VistaWin10 == VER_10_0, "vista+win10-manifest process reported 0x%08lx, expected 0x%08lx (10.0/10.0)\n",
           VistaWin10, (DWORD)VER_10_0);
    }
    else if (is_reactos())
    {
        /* Negative control: no manifest compatibility GUID -> the real NT 5.2 shows
         * through BOTH GetVersion() and RtlGetVersion(). Proves the fix is per-app
         * and did NOT globally bump the OS version. */
        ok(None == VER_5_2, "no-manifest process reported 0x%08lx, expected 0x%08lx (5.2/5.2)\n",
           None, (DWORD)VER_5_2);
        /* Positive control: a Vista supportedOS manifest -> GetVersion() and
         * RtlGetVersion() both report 6.0, so Crashpad-style GetVersion()>=6 gates pass. */
        ok(Vista == VER_6_0, "vista-manifest process reported 0x%08lx, expected 0x%08lx (6.0/6.0)\n",
           Vista, (DWORD)VER_6_0);
        /* And the manifest must raise, never lower, the reported version. */
        ok(Vista > None, "vista-manifest (0x%08lx) must report a higher version than none (0x%08lx)\n",
           Vista, None);
        /* A Vista..Win10 manifest reports the highest supportedOS we emulate (Windows 7,
         * 6.1), as Windows 7 itself would; Burn-based installers gate on VersionNT >= 6.1
         * (T101). It must NOT report 10.0: we do not implement Win10 behavior. */
        ok(Span == VER_6_1, "vista..win10-manifest process reported 0x%08lx, expected 0x%08lx (6.1/6.1)\n",
           Span, (DWORD)VER_6_1);
        /* A manifest declaring only Vista and Win10 (no Win7) keeps the highest at or
         * below the ceiling, Vista. */
        ok(VistaWin10 == VER_6_0, "vista+win10-manifest process reported 0x%08lx, expected 0x%08lx (6.0/6.0)\n",
           VistaWin10, (DWORD)VER_6_0);
    }
    else
    {
        skip("Windows reports its own version through the manifest; ReactOS-specific contract\n");
    }
}
