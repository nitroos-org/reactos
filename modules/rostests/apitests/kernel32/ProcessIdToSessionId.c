/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for kernel32!ProcessIdToSessionId: the session query needs PROCESS_QUERY_LIMITED_INFORMATION and no more
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022: for a process whose DACL grants everybody only PROCESS_QUERY_LIMITED_INFORMATION and
 * SYNCHRONIZE, a standard user's OpenProcess(PROCESS_QUERY_INFORMATION) fails with ERROR_ACCESS_DENIED and
 * ProcessIdToSessionId succeeds with the session of the process. A standard user gets no access at all to the processes
 * of other accounts (ProcessIdToSessionId of services.exe, winlogon.exe, csrss.exe fails with ERROR_ACCESS_DENIED).
 */

#include "precomp.h"
#include <sddl.h>

START_TEST(ProcessIdToSessionId)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    SECURITY_ATTRIBUTES Sa;
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Process;
    WCHAR Path[MAX_PATH];
    DWORD Own = 0xdeadbeef, Other = 0xdeadbeef, Error;
    HANDLE Handle;
    BOOL Ret;

    /* An administrator's SeDebugPrivilege would open every process: test as a standard user's token is, with none enabled */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Handle))
    {
        AdjustTokenPrivileges(Handle, TRUE, NULL, 0, NULL, NULL);
        CloseHandle(Handle);
    }

    SetLastError(0xdeadbeef);
    Ret = ProcessIdToSessionId(GetCurrentProcessId(), &Own);
    ok(Ret, "ProcessIdToSessionId of this process failed: %lu\n", GetLastError());

    /* A process nobody has: the answer is a failure */
    SetLastError(0xdeadbeef);
    Other = 0xdeadbeef;
    Ret = ProcessIdToSessionId(0xfffffffc, &Other);
    ok(!Ret, "ProcessIdToSessionId of an invalid process id succeeded\n");
    ok(Other == 0xdeadbeef, "the session id was written: %lu\n", Other);

    /* A suspended copy of this program whose DACL gives everybody only PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;0x101000;;;WD)", SDDL_REVISION_1, &Sd, NULL))
    {
        skip("no security descriptor: %lu\n", GetLastError());
        return;
    }
    Sa.nLength = sizeof(Sa);
    Sa.lpSecurityDescriptor = Sd;
    Sa.bInheritHandle = FALSE;
    GetModuleFileNameW(NULL, Path, RTL_NUMBER_OF(Path));
    if (!CreateProcessW(Path, NULL, &Sa, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Process))
    {
        skip("CreateProcess failed: %lu\n", GetLastError());
        LocalFree(Sd);
        return;
    }

    /* What this caller may open it with: if it can open it for PROCESS_QUERY_INFORMATION (SeDebugPrivilege enabled)
       the row below proves nothing about the right the call needs */
    Handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Process.dwProcessId);
    Error = Handle ? ERROR_SUCCESS : GetLastError();
    if (Handle)
        CloseHandle(Handle);
    if (Error == ERROR_SUCCESS)
        trace("the caller can open the child for PROCESS_QUERY_INFORMATION: the right of the session query is not tested\n");
    else
        ok(Error == ERROR_ACCESS_DENIED, "OpenProcess(PROCESS_QUERY_INFORMATION) failed with %lu\n", Error);

    Handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Process.dwProcessId);
    ok(Handle != NULL, "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed: %lu\n", GetLastError());
    if (Handle)
        CloseHandle(Handle);

    SetLastError(0xdeadbeef);
    Other = 0xdeadbeef;
    Ret = ProcessIdToSessionId(Process.dwProcessId, &Other);
    ok(Ret, "ProcessIdToSessionId of a process that allows only PROCESS_QUERY_LIMITED_INFORMATION failed: %lu\n", GetLastError());
    if (Ret)
        ok(Other == Own, "the session of the child is %lu, this process's is %lu\n", Other, Own);

    TerminateProcess(Process.hProcess, 0);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
    LocalFree(Sd);
}
