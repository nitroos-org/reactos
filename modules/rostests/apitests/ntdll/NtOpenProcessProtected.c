/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The protected system processes (smss, csrss, wininit, services, System) give a caller outside
 *              the protection only the limited rights; the other system processes (lsass, winlogon) are
 *              open to an administrator as before. ProcessProtectionInformation reports the level.
 *              Windows 10 22H2 measured: PPL (level 0x61) allows SYNCHRONIZE, QUERY_LIMITED, SET_LIMITED and
 *              SUSPEND_RESUME; QUERY_INFORMATION, VM_READ, TERMINATE, READ_CONTROL, ALL_ACCESS and
 *              MAXIMUM_ALLOWED are access denied.
 */

#include "precomp.h"
#include <tlhelp32.h>

#ifndef PROCESS_SET_LIMITED_INFORMATION
#define PROCESS_SET_LIMITED_INFORMATION 0x2000
#endif

static BOOL
IsLocalSystem(VOID)
{
    HANDLE Token;
    TOKEN_STATISTICS Stats;
    DWORD Len;
    BOOL Ret = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    {
        if (GetTokenInformation(Token, TokenStatistics, &Stats, sizeof(Stats), &Len))
            Ret = (Stats.AuthenticationId.LowPart == 0x3e7 && Stats.AuthenticationId.HighPart == 0);
        CloseHandle(Token);
    }
    return Ret;
}

static DWORD
FindProcess(PCWSTR Name)
{
    PROCESSENTRY32W Entry;
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD Pid = 0;

    if (Snap == INVALID_HANDLE_VALUE)
        return 0;
    Entry.dwSize = sizeof(Entry);
    if (Process32FirstW(Snap, &Entry))
    {
        do
        {
            if (!_wcsicmp(Entry.szExeFile, Name))
            {
                Pid = Entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(Snap, &Entry));
    }
    CloseHandle(Snap);
    return Pid;
}

static NTSTATUS
OpenPid(DWORD Pid, ACCESS_MASK Access, PHANDLE Handle)
{
    OBJECT_ATTRIBUTES Attr;
    CLIENT_ID Cid;

    InitializeObjectAttributes(&Attr, NULL, 0, NULL, NULL);
    Cid.UniqueProcess = (HANDLE)(ULONG_PTR)Pid;
    Cid.UniqueThread = NULL;
    *Handle = NULL;
    return NtOpenProcess(Handle, Access, &Attr, &Cid);
}

static void
CheckProtected(PCWSTR Name, BOOL Admin)
{
    DWORD Pid = FindProcess(Name);
    NTSTATUS Status;
    HANDLE Handle;
    UCHAR Prot;
    ULONG Ret;

    if (!Pid)
    {
        skip("%ls is not running\n", Name);
        return;
    }
    trace("%ls pid %lu\n", Name, Pid);

    /* the limited rights are open to everyone who could open the process before */
    Status = OpenPid(Pid, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, &Handle);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Prot = 0xEE;
        Ret = 0;
        Status = NtQueryInformationProcess(Handle, 61 /* ProcessProtectionInformation */, &Prot, sizeof(Prot), &Ret);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_eq_ulong(Ret, 1UL);
        ok_hex(Prot, 0x61);
        Status = NtQueryInformationProcess(Handle, 61, &Prot, 4, &Ret);
        ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
        NtClose(Handle);
    }
    Status = OpenPid(Pid, PROCESS_SUSPEND_RESUME | PROCESS_SET_LIMITED_INFORMATION, &Handle);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        NtClose(Handle);

    if (!Admin)
        return;

    /* what is beyond them is refused, privileges or not */
    Status = OpenPid(Pid, PROCESS_QUERY_INFORMATION, &Handle);
    ok_ntstatus(Status, STATUS_ACCESS_DENIED);
    if (NT_SUCCESS(Status)) NtClose(Handle);
    Status = OpenPid(Pid, PROCESS_VM_READ, &Handle);
    ok_ntstatus(Status, STATUS_ACCESS_DENIED);
    if (NT_SUCCESS(Status)) NtClose(Handle);
    Status = OpenPid(Pid, PROCESS_TERMINATE, &Handle);
    ok_ntstatus(Status, STATUS_ACCESS_DENIED);
    if (NT_SUCCESS(Status)) NtClose(Handle);
    Status = OpenPid(Pid, PROCESS_ALL_ACCESS, &Handle);
    ok_ntstatus(Status, STATUS_ACCESS_DENIED);
    if (NT_SUCCESS(Status)) NtClose(Handle);
    Status = OpenPid(Pid, READ_CONTROL, &Handle);
    ok_ntstatus(Status, STATUS_ACCESS_DENIED);
    if (NT_SUCCESS(Status)) NtClose(Handle);
    Status = OpenPid(Pid, MAXIMUM_ALLOWED, &Handle);
    ok_ntstatus(Status, STATUS_ACCESS_DENIED);
    if (NT_SUCCESS(Status)) NtClose(Handle);
}

static void
CheckUnprotected(PCWSTR Name)
{
    DWORD Pid = FindProcess(Name);
    NTSTATUS Status;
    HANDLE Handle;
    UCHAR Prot;
    ULONG Ret;

    if (!Pid)
    {
        skip("%ls is not running\n", Name);
        return;
    }
    Status = OpenPid(Pid, PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, &Handle);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Prot = 0xEE;
        Status = NtQueryInformationProcess(Handle, 61, &Prot, sizeof(Prot), &Ret);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_hex(Prot, 0);
        NtClose(Handle);
    }
}

START_TEST(NtOpenProcessProtected)
{
    BOOL Admin = !IsLocalSystem();
    HANDLE Handle;
    NTSTATUS Status;
    UCHAR Prot = 0xEE;
    ULONG Ret;
    BOOLEAN WasEnabled;

    /* the measurement on Windows was made with SeDebugPrivilege enabled: that is what grants the limited
     * rights on processes whose security descriptor does not */
    Status = RtlAdjustPrivilege(20 /* SE_DEBUG_PRIVILEGE */, TRUE, FALSE, &WasEnabled);
    if (!NT_SUCCESS(Status))
    {
        skip("SeDebugPrivilege is not available (0x%lx)\n", Status);
        return;
    }

    if (!Admin)
        skip("running as LocalSystem: only the limited rights are checked\n");

    CheckProtected(L"smss.exe", Admin);
    CheckProtected(L"csrss.exe", Admin);
    CheckProtected(L"wininit.exe", Admin);
    CheckProtected(L"services.exe", Admin);
    CheckUnprotected(L"lsass.exe");
    CheckUnprotected(L"winlogon.exe");

    /* our own process is not protected, and a process may open itself */
    Status = OpenPid(GetCurrentProcessId(), PROCESS_ALL_ACCESS, &Handle);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = NtQueryInformationProcess(Handle, 61, &Prot, sizeof(Prot), &Ret);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_hex(Prot, 0);
        NtClose(Handle);
    }
}
