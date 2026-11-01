/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IoIs32bitProcess test, user-mode part
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * IoIs32bitProcess(Irp) is decided by the process the request comes from, not by what the request carries:
 * TRUE for every request of a WoW64 process (synchronous handle with no event, overlapped handle with an
 * event, APC, completion port; completed in the dispatch routine or later from a system thread), FALSE for
 * a native process and for a kernel-mode request.
 *
 * kmtest.exe sends the requests itself and, when it is a 64-bit process, runs the 32-bit client
 * (iois32bitprocess_client32.exe, the i386 build of iois32bitprocess_client, next to it) that sends the same
 * requests as a WoW64 process: the framework's own control codes cannot be sent from a 32-bit kmtest.exe.
 */

#include <kmt_test.h>
#include "IoIs32bitProcess_cases.h"

static
VOID
Run32bitClient(VOID)
{
    WCHAR Path[MAX_PATH];
    PWCHAR Name;
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DWORD Wait, ExitCode = 0xdeadbeef;

    if (!GetModuleFileNameW(NULL, Path, RTL_NUMBER_OF(Path)) || !(Name = wcsrchr(Path, L'\\')))
        return;
    StringCchCopyW(Name + 1, RTL_NUMBER_OF(Path) - (Name + 1 - Path), L"iois32bitprocess_client32.exe");
    if (skip(GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES, "%ls is not there\n", Path))
        return;

    if (!CreateProcessW(Path, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        ok(0, "CreateProcess(%ls) failed with %lu\n", Path, GetLastError());
        return;
    }
    Wait = WaitForSingleObject(ProcessInfo.hProcess, 120000);
    ok_eq_ulong(Wait, WAIT_OBJECT_0);
    if (Wait != WAIT_OBJECT_0)
        TerminateProcess(ProcessInfo.hProcess, 0xdead);
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    /* the number of failed checks, 0xff when it could not run at all */
    ok_eq_ulong(ExitCode, 0);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
}

START_TEST(IoIs32bitProcess)
{
    BOOLEAN Wow64 = IsWow64Caller();
    DWORD Error;

    trace("running as a %s process, IoIs32bitProcess expected %s\n",
          Wow64 ? "WoW64" : (sizeof(PVOID) == 8 ? "64-bit" : "native 32-bit"), Wow64 ? "TRUE" : "FALSE");

    Error = KmtLoadAndOpenDriver(L"IoIs32bitProcess", TRUE);
    ok_eq_int(Error, ERROR_SUCCESS);
    if (Error)
        return;
    /* the requests use handles of their own: the device accepts several */
    KmtCloseDriver();

    RunIoIs32Requests(Wow64);
    if (sizeof(PVOID) == 8)
        Run32bitClient();

    KmtUnloadDriver();
}
