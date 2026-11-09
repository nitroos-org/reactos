/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A console process that imports advapi32 does not load the socket and window DLLs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* On Windows 10 such a process holds ntdll, kernel32, KERNELBASE, apphelp, advapi32, msvcrt, sechost and rpcrt4, and none of
 * ws2_32, user32, gdi32, lpk, usp10 and imm32; the child's exit code has one bit for each of those six that it finds loaded. */
START_TEST(AdvapiModules)
{
    WCHAR FileName[MAX_PATH], *Slash;
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DWORD ExitCode = 0xdeadbeef;

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    Slash = wcsrchr(FileName, L'\\');
    if (!Slash || FAILED(StringCbCopyW(Slash + 1, sizeof(FileName) - (Slash + 1 - FileName) * sizeof(WCHAR), L"advapi32_modules_child.exe")) ||
        !CreateProcessW(FileName, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        skip("advapi32_modules_child.exe could not be started\n");
        return;
    }
    WaitForSingleObject(ProcessInfo.hProcess, 60000);
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    ok(!(ExitCode & 0x01), "ws2_32.dll is loaded\n");
    ok(!(ExitCode & 0x02), "user32.dll is loaded\n");
    ok(!(ExitCode & 0x04), "gdi32.dll is loaded\n");
    ok(!(ExitCode & 0x08), "lpk.dll is loaded\n");
    ok(!(ExitCode & 0x10), "usp10.dll is loaded\n");
    ok(!(ExitCode & 0x20), "imm32.dll is loaded\n");
    ok(!(ExitCode & 0x100), "advapi32.dll is not loaded\n");
}
