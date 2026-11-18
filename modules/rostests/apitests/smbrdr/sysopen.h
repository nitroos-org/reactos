/*
 * PROJECT:     NitroOS SMB mini-redirector tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Open the engine device as SYSTEM from an elevated test tool
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * \Device\NitroSmbEngine admits SYSTEM and NT SERVICE\smbengine only. A test engine started by an
 * administrator opens it while its thread impersonates SYSTEM (a copy of winlogon's token, opened with
 * SeDebugPrivilege), then reverts: the handle keeps the access it was granted.
 */

#pragma once

#include <tlhelp32.h>

static HANDLE
SmbTestOpenAsSystem(LPCWSTR Path, DWORD Access, DWORD Flags)
{
    HANDLE hFile, hSnap, hProcess, hToken = NULL, hDup = NULL, hSelf;
    PROCESSENTRY32W Entry;
    TOKEN_PRIVILEGES Tp;
    DWORD Error;

    hFile = CreateFileW(Path, Access, 0, NULL, OPEN_EXISTING, Flags, NULL);
    if (hFile != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ACCESS_DENIED)
        return hFile;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hSelf))
    {
        Tp.PrivilegeCount = 1;
        Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &Tp.Privileges[0].Luid))
            AdjustTokenPrivileges(hSelf, FALSE, &Tp, 0, NULL, NULL);
        CloseHandle(hSelf);
    }

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Entry.dwSize = sizeof(Entry);
    if (hSnap != INVALID_HANDLE_VALUE && Process32FirstW(hSnap, &Entry))
    {
        do
        {
            if (_wcsicmp(Entry.szExeFile, L"winlogon.exe"))
                continue;
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Entry.th32ProcessID);
            if (hProcess)
            {
                if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
                {
                    DuplicateTokenEx(hToken, TOKEN_IMPERSONATE | TOKEN_QUERY, NULL, SecurityImpersonation,
                                     TokenImpersonation, &hDup);
                    CloseHandle(hToken);
                }
                CloseHandle(hProcess);
            }
            break;
        } while (Process32NextW(hSnap, &Entry));
    }
    if (hSnap != INVALID_HANDLE_VALUE)
        CloseHandle(hSnap);

    if (hDup == NULL || !SetThreadToken(NULL, hDup))
    {
        if (hDup)
            CloseHandle(hDup);
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    hFile = CreateFileW(Path, Access, 0, NULL, OPEN_EXISTING, Flags, NULL);
    Error = GetLastError();
    RevertToSelf();
    CloseHandle(hDup);
    SetLastError(Error);
    return hFile;
}
