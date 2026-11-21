/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The descriptor of the devices that anybody may open: Everyone gets read, write and execute, no more
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Windows Server 2022 (measured, descriptors of the device objects, SDDL):
 *   \Device\NamedPipe, \Device\Null, \Device\Afd, \Device\Mailslot, \Device\KsecDD:
 *   O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)
 */

#include "precomp.h"

static PACCESS_ALLOWED_ACE FindAce(PACL Dacl, PSID Sid)
{
    ULONG i;
    PACCESS_ALLOWED_ACE Ace;

    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)) && RtlEqualSid(Sid, &Ace->SidStart))
            return Ace;
    }
    return NULL;
}

static void CheckDevice(PCWSTR Path)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Handle;
    NTSTATUS Status;
    BYTE Buffer[1024];
    ULONG Length;
    PSECURITY_DESCRIPTOR Sd = (PSECURITY_DESCRIPTOR)Buffer;
    PACL Dacl;
    BOOLEAN Present, Defaulted;
    PACCESS_ALLOWED_ACE Ace;
    SID_IDENTIFIER_AUTHORITY WorldAuthority = { SECURITY_WORLD_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
    UCHAR WorldBuffer[16], SystemBuffer[16], AdminsBuffer[16];
    PSID World = (PSID)WorldBuffer, System = (PSID)SystemBuffer, Admins = (PSID)AdminsBuffer;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Handle, READ_CONTROL, &Attributes, &Iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
    if (!NT_SUCCESS(Status))
    {
        skip("%ls: cannot open (0x%08lx)\n", Path, Status);
        return;
    }
    Status = NtQuerySecurityObject(Handle, DACL_SECURITY_INFORMATION, Sd, sizeof(Buffer), &Length);
    NtClose(Handle);
    if (!NT_SUCCESS(Status))
    {
        skip("%ls: cannot read the descriptor (0x%08lx)\n", Path, Status);
        return;
    }

    RtlInitializeSid(World, &WorldAuthority, 1);
    *RtlSubAuthoritySid(World, 0) = SECURITY_WORLD_RID;
    RtlInitializeSid(System, &NtAuthority, 1);
    *RtlSubAuthoritySid(System, 0) = SECURITY_LOCAL_SYSTEM_RID;
    RtlInitializeSid(Admins, &NtAuthority, 2);
    *RtlSubAuthoritySid(Admins, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(Admins, 1) = DOMAIN_ALIAS_RID_ADMINS;

    Status = RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status) || !Present || !Dacl)
    {
        ok(0, "%ls: no DACL\n", Path);
        return;
    }

    Ace = FindAce(Dacl, World);
    ok(Ace != NULL, "%ls: no ACE for Everyone\n", Path);
    if (Ace)
        ok(Ace->Mask == 0x001201bf, "%ls: Everyone has 0x%08lx, expected 0x001201bf\n", Path, Ace->Mask);

    Ace = FindAce(Dacl, System);
    ok(Ace != NULL, "%ls: no ACE for SYSTEM\n", Path);
    if (Ace)
        ok(Ace->Mask == 0x001f01ff, "%ls: SYSTEM has 0x%08lx, expected 0x001f01ff\n", Path, Ace->Mask);

    Ace = FindAce(Dacl, Admins);
    ok(Ace != NULL, "%ls: no ACE for Administrators\n", Path);
    if (Ace)
        ok(Ace->Mask == 0x001f01ff, "%ls: Administrators have 0x%08lx, expected 0x001f01ff\n", Path, Ace->Mask);
}

START_TEST(DeviceOpenDescriptor)
{
    CheckDevice(L"\\Device\\Null");
    CheckDevice(L"\\Device\\NamedPipe");
    CheckDevice(L"\\Device\\Mailslot");
    CheckDevice(L"\\Device\\Afd");
    CheckDevice(L"\\Device\\KsecDD");
}
