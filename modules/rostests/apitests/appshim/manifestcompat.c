/*
 * PROJECT:     appshim_apitest
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     A process is told the version Windows 10 tells it: a manifest that names Windows 10 sees 10.0
 *              from GetVersion(), one that does not sees 6.2; RtlGetVersion() always sees the real 10.0.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>
#include <stdio.h>
#include "wine/test.h"

#define VER_10_0 0x0a000a00 /* GetVersion 10.0 / RtlGetVersion 10.0 */

/* The system version, from the shared user data that no per-process version lie touches (same address on Windows) */
static DWORD system_major_version(void)
{
    return *(volatile ULONG*)(ULONG_PTR)0x7FFE026C;
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

    if (is_reactos() && system_major_version() >= 10)
    {
        /* GetVersion() follows the manifest as on Windows 10 (6.2 for a manifest that names neither 8.1 nor 10),
           RtlGetVersion()/RtlGetNtVersionNumbers() stay 10.0. See versionmatrix.c. */
        ok(None == 0x06020a00, "no-manifest process reported 0x%08lx, expected 0x06020a00 (6.2/10.0)\n", None);
        ok(Vista == 0x06020a00, "vista-manifest process reported 0x%08lx, expected 0x06020a00 (6.2/10.0)\n", Vista);
        ok(Span == VER_10_0, "vista..win10-manifest process reported 0x%08lx, expected 0x%08lx (10.0/10.0)\n",
           Span, (DWORD)VER_10_0);
        ok(VistaWin10 == VER_10_0, "vista+win10-manifest process reported 0x%08lx, expected 0x%08lx (10.0/10.0)\n",
           VistaWin10, (DWORD)VER_10_0);
    }
    else
    {
        skip("Windows reports its own version through the manifest; ReactOS-specific contract\n");
    }
}
