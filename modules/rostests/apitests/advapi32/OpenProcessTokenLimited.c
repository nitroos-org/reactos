/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Which process access right NtOpenProcessToken / OpenProcessToken needs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (10.0.20348), as an elevated administrator, a filtered administrator and a standard user,
 * against a child of the caller (same user), a child of another user, and system processes (smss, wininit, services, lsass,
 * winlogon: SYSTEM; svchost: SYSTEM, LOCAL SERVICE, NETWORK SERVICE):
 *  - the process handle needs PROCESS_QUERY_LIMITED_INFORMATION (a handle with PROCESS_QUERY_INFORMATION has it too). A handle
 *    with PROCESS_VM_READ, PROCESS_DUP_HANDLE, SYNCHRONIZE, PROCESS_SET_INFORMATION or PROCESS_SET_LIMITED_INFORMATION only is
 *    refused with STATUS_ACCESS_DENIED for every token access
 *  - the right does not change what the token open gives: the token's own security descriptor decides. The same user's token (the
 *    caller's child) opens with every access (TOKEN_ALL_ACCESS) through a handle with only the limited right. An elevated
 *    administrator gets from a SYSTEM process's token (through a limited handle, no SeDebugPrivilege) TOKEN_QUERY,
 *    TOKEN_QUERY_SOURCE, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_ASSIGN_PRIMARY and READ_CONTROL, and is refused
 *    TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_DEFAULT, WRITE_DAC and TOKEN_ALL_ACCESS
 */

#include "precomp.h"
#include <tlhelp32.h>

typedef NTSTATUS (NTAPI *PFN_NtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE);

static const struct { DWORD Access; PCSTR Name; } TokenAccesses[] =
{
    { TOKEN_QUERY, "TOKEN_QUERY" }, { TOKEN_QUERY_SOURCE, "TOKEN_QUERY_SOURCE" }, { TOKEN_DUPLICATE, "TOKEN_DUPLICATE" },
    { TOKEN_IMPERSONATE, "TOKEN_IMPERSONATE" }, { TOKEN_ASSIGN_PRIMARY, "TOKEN_ASSIGN_PRIMARY" },
    { TOKEN_ADJUST_PRIVILEGES, "TOKEN_ADJUST_PRIVILEGES" }, { TOKEN_ADJUST_GROUPS, "TOKEN_ADJUST_GROUPS" },
    { TOKEN_ADJUST_DEFAULT, "TOKEN_ADJUST_DEFAULT" }, { READ_CONTROL, "READ_CONTROL" }, { WRITE_DAC, "WRITE_DAC" },
    { MAXIMUM_ALLOWED, "MAXIMUM_ALLOWED" }, { TOKEN_ALL_ACCESS, "TOKEN_ALL_ACCESS" },
};
#define TOKEN_ACCESS_COUNT ARRAYSIZE(TokenAccesses)
/* bit n: TokenAccesses[n] is granted */
#define ALL_GRANTED     0xFFF
#define SYSTEM_GRANTED  0x51F       /* QUERY, QUERY_SOURCE, DUPLICATE, IMPERSONATE, ASSIGN_PRIMARY, READ_CONTROL, MAXIMUM_ALLOWED */

static PFN_NtOpenProcessToken pNtOpenProcessToken;

static VOID
CheckHandle(PCSTR What, HANDLE hProcess, DWORD Granted, BOOL System)
{
    ULONG i;
    HANDLE hToken;
    NTSTATUS Status;

    for (i = 0; i < TOKEN_ACCESS_COUNT; i++)
    {
        hToken = NULL;
        Status = pNtOpenProcessToken(hProcess, TokenAccesses[i].Access, &hToken);
        if (Granted & (1UL << i))
            ok(Status == STATUS_SUCCESS, "%s: %s: 0x%lx, expected success\n", What, TokenAccesses[i].Name, Status);
        else if (System && TokenAccesses[i].Access == WRITE_DAC)
        {
            /* The descriptor of the token of a SYSTEM process grants the administrators WRITE_DAC here (not on Windows) */
            todo_ros
            ok(Status == STATUS_ACCESS_DENIED, "%s: %s: 0x%lx, expected STATUS_ACCESS_DENIED\n", What, TokenAccesses[i].Name, Status);
        }
        else
            ok(Status == STATUS_ACCESS_DENIED, "%s: %s: 0x%lx, expected STATUS_ACCESS_DENIED\n", What, TokenAccesses[i].Name, Status);
        if (NT_SUCCESS(Status))
            CloseHandle(hToken);
    }
}

static HANDLE
Open(DWORD Pid, DWORD Access)
{
    return OpenProcess(Access, FALSE, Pid);
}

static BOOL
ElevatedAdministrator(VOID)
{
    HANDLE hToken;
    TOKEN_ELEVATION Elevation;
    DWORD Length;
    BOOL Ret = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &Length))
            Ret = Elevation.TokenIsElevated;
        CloseHandle(hToken);
    }
    return Ret;
}

static DWORD
FindProcess(PCWSTR Name)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W Entry;
    DWORD Pid = 0;

    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;
    Entry.dwSize = sizeof(Entry);
    if (Process32FirstW(hSnap, &Entry))
    {
        do
        {
            if (!_wcsicmp(Entry.szExeFile, Name))
            {
                Pid = Entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &Entry));
    }
    CloseHandle(hSnap);
    return Pid;
}

START_TEST(OpenProcessTokenLimited)
{
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    WCHAR Cmd[] = L"cmd.exe /c ping -n 30 127.0.0.1";
    static const struct { DWORD Access; PCSTR Name; BOOL Works; } Handles[] =
    {
        { PROCESS_QUERY_LIMITED_INFORMATION, "PROCESS_QUERY_LIMITED_INFORMATION", TRUE },
        { PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION", TRUE },
        { PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, "both query rights", TRUE },
        { PROCESS_VM_READ, "PROCESS_VM_READ", FALSE },
        { PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE", FALSE },
        { SYNCHRONIZE, "SYNCHRONIZE", FALSE },
        { PROCESS_SET_LIMITED_INFORMATION, "PROCESS_SET_LIMITED_INFORMATION", FALSE },
        { PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION", FALSE },
    };
    ULONG i;
    HANDLE hProcess;
    DWORD Pid;
    PCWSTR SystemProcesses[] = { L"wininit.exe", L"services.exe", L"smss.exe", L"lsass.exe", L"winlogon.exe" };

    pNtOpenProcessToken = (PFN_NtOpenProcessToken)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcessToken");
    if (!pNtOpenProcessToken)
    {
        skip("no NtOpenProcessToken\n");
        return;
    }

    /* A child of the caller: the same user, so the token's descriptor lets the caller do everything */
    if (!CreateProcessW(NULL, Cmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &Si, &Pi))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        return;
    }
    Sleep(300);
    for (i = 0; i < ARRAYSIZE(Handles); i++)
    {
        hProcess = Open(Pi.dwProcessId, Handles[i].Access);
        ok(hProcess != NULL, "OpenProcess(%s) failed with %lu\n", Handles[i].Name, GetLastError());
        if (!hProcess)
            continue;
        CheckHandle(Handles[i].Name, hProcess, Handles[i].Works ? ALL_GRANTED : 0, FALSE);
        CloseHandle(hProcess);
    }

    /* the Win32 call, with a limited handle */
    hProcess = Open(Pi.dwProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    if (hProcess)
    {
        HANDLE hToken = NULL;

        SetLastError(0xdeadbeef);
        ok(OpenProcessToken(hProcess, TOKEN_QUERY, &hToken), "OpenProcessToken(limited handle) failed with %lu\n", GetLastError());
        if (hToken)
            CloseHandle(hToken);
        CloseHandle(hProcess);
    }
    hProcess = Open(Pi.dwProcessId, SYNCHRONIZE);
    if (hProcess)
    {
        HANDLE hToken = NULL;

        SetLastError(0xdeadbeef);
        ok(!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken), "OpenProcessToken(SYNCHRONIZE handle) succeeded\n");
        ok(GetLastError() == ERROR_ACCESS_DENIED, "OpenProcessToken(SYNCHRONIZE handle) failed with %lu\n", GetLastError());
        if (hToken)
            CloseHandle(hToken);
        CloseHandle(hProcess);
    }
    TerminateProcess(Pi.hProcess, 0);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);

    /* A SYSTEM process, from an elevated administrator without SeDebugPrivilege enabled */
    if (!ElevatedAdministrator())
    {
        skip("not an elevated administrator: no system process rows\n");
        return;
    }
    for (i = 0; i < ARRAYSIZE(SystemProcesses); i++)
    {
        Pid = FindProcess(SystemProcesses[i]);
        if (!Pid)
            continue;
        hProcess = Open(Pid, PROCESS_QUERY_LIMITED_INFORMATION);
        if (!hProcess)
        {
            trace("%ls: no limited handle (%lu)\n", SystemProcesses[i], GetLastError());
            continue;
        }
        CheckHandle("system process, limited handle", hProcess, SYSTEM_GRANTED, TRUE);
        CloseHandle(hProcess);
    }
}
