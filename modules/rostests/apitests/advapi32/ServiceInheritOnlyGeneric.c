/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that the generic rights of inherit-only ACEs stay as they are set on a service
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>

/*
 * Measured on Windows Server 2022 (x64 and x86 under WoW64, a scratch service): after SetServiceObjectSecurity of
 * (A;OICIIO;GA;;;CO)(A;CIIO;GR;;;BU) the DACL reads back with the generic rights 0x10000000 and 0x80000000 in those
 * ACEs, and an inherit-only audit ACE of a SACL (AU;OICIIOSA;GW;;;WD) with 0x40000000; the effective ACEs of the same
 * descriptors are mapped to the service's rights.
 */

static BOOL EnablePrivilege(PCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    BOOL Ret = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, Name, &Privileges.Privileges[0].Luid))
    {
        AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL);
        Ret = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(Token);
    return Ret;
}

START_TEST(ServiceInheritOnlyGeneric)
{
    static const WCHAR ServiceName[] = L"InheritOnlyGeneric";
    SC_HANDLE Manager, Service;
    PSECURITY_DESCRIPTOR Sd, Read;
    BYTE Buffer[1024];
    DWORD Needed;
    BOOL Present, Defaulted, SaclOk;
    PACL Acl = NULL;

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Manager)
    {
        skip("OpenSCManager: %lu\n", GetLastError());
        return;
    }
    SaclOk = EnablePrivilege(L"SeSecurityPrivilege");
    Service = CreateServiceW(Manager, ServiceName, ServiceName, SERVICE_ALL_ACCESS | READ_CONTROL | WRITE_DAC |
                             (SaclOk ? ACCESS_SYSTEM_SECURITY : 0), SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                             SERVICE_ERROR_IGNORE, L"C:\\Windows\\System32\\none.exe", NULL, NULL, NULL, NULL, NULL);
    if (!Service)
    {
        ok(0, "CreateService: %lu\n", GetLastError());
        CloseServiceHandle(Manager);
        return;
    }

    /* DACL: an effective ACE and inherit-only ACEs with generic rights */
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICIIO;GA;;;CO)(A;CIIO;GR;;;BU)(A;;GR;;;SY)(A;;0x20000;;;BA)",
                                                            SDDL_REVISION_1, &Sd, NULL), "SDDL: %lu\n", GetLastError());
    ok(SetServiceObjectSecurity(Service, DACL_SECURITY_INFORMATION, Sd), "SetServiceObjectSecurity(DACL): %lu\n", GetLastError());
    LocalFree(Sd);
    ok(QueryServiceObjectSecurity(Service, DACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Needed), "Query: %lu\n", GetLastError());
    Read = Buffer;
    ok(GetSecurityDescriptorDacl(Read, &Present, &Acl, &Defaulted), "GetSecurityDescriptorDacl: %lu\n", GetLastError());
    {
        /* the inherit-only ACEs keep 0x10000000 and 0x80000000; GR of an effective ACE is the service's read rights */
        const ULONG Masks[2] = {0x10000000, 0x80000000};
        ULONG Effective = 0;
        ACCESS_ALLOWED_ACE *Ace;

        ok(Present && Acl && Acl->AceCount == 4, "DACL: %u ACEs\n", Acl ? Acl->AceCount : 0);
        if (Present && Acl && Acl->AceCount == 4)
        {
            GetAce(Acl, 0, (PVOID *)&Ace);
            ok(Ace->Mask == Masks[0], "inherit-only GA: mask 0x%08lx\n", Ace->Mask);
            GetAce(Acl, 1, (PVOID *)&Ace);
            ok(Ace->Mask == Masks[1], "inherit-only GR: mask 0x%08lx\n", Ace->Mask);
            GetAce(Acl, 2, (PVOID *)&Ace);
            Effective = Ace->Mask;
            ok((Effective & 0xF0000000) == 0 && Effective != 0, "effective GR is mapped: mask 0x%08lx\n", Effective);
        }
    }

    /* SACL: an inherit-only audit ACE with generic rights */
    if (SaclOk)
    {
        ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(AU;OICIIOSA;GW;;;WD)", SDDL_REVISION_1, &Sd, NULL), "SDDL: %lu\n", GetLastError());
        if (SetServiceObjectSecurity(Service, SACL_SECURITY_INFORMATION, Sd) &&
            QueryServiceObjectSecurity(Service, SACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Needed))
        {
            ACCESS_ALLOWED_ACE *Ace;

            Acl = NULL;
            GetSecurityDescriptorSacl(Buffer, &Present, &Acl, &Defaulted);
            ok(Present && Acl && Acl->AceCount == 1, "SACL: %u ACEs\n", Acl ? Acl->AceCount : 0);
            if (Present && Acl && Acl->AceCount == 1)
            {
                GetAce(Acl, 0, (PVOID *)&Ace);
                ok(Ace->Mask == 0x40000000, "inherit-only audit ACE: mask 0x%08lx, expected 0x40000000\n", Ace->Mask);
            }
        }
        else
            skip("the SACL of a service cannot be set here: %lu\n", GetLastError());
        LocalFree(Sd);
    }
    else
        skip("SeSecurityPrivilege is not available\n");

    DeleteService(Service);
    CloseServiceHandle(Service);
    CloseServiceHandle(Manager);
}
