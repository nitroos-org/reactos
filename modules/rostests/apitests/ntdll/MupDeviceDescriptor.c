/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     \Device\Mup: the restricted code ACE of its descriptor and FileFsDeviceInformation on handles opened with and without
 *              data access (rows measured on Windows Server 2022, Administrator)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static NTSTATUS OpenMup(ACCESS_MASK Access, PHANDLE Handle)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Mup");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtOpenFile(Handle, Access, &Attributes, &Iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
}

START_TEST(MupDeviceDescriptor)
{
    static const struct { ACCESS_MASK Access; BOOLEAN DataAccess; } Rows[] =
    {
        { 0x00120089, TRUE },   /* FILE_GENERIC_READ */
        { 0x00000001, TRUE },   /* FILE_READ_DATA */
        { 0x00120116, TRUE },   /* FILE_GENERIC_WRITE */
        { 0x001f01ff, TRUE },   /* FILE_ALL_ACCESS */
        { 0x80000000, TRUE },   /* GENERIC_READ */
        { 0x02000000, TRUE },   /* MAXIMUM_ALLOWED */
        { 0x00000080, FALSE },  /* FILE_READ_ATTRIBUTES */
        { 0x00100000, FALSE },  /* SYNCHRONIZE */
        { 0x00020000, FALSE },  /* READ_CONTROL */
        { 0x00020080, FALSE },
    };
    ULONG i;
    HANDLE Handle;
    NTSTATUS Status;
    BYTE Buffer[1024];
    ULONG Length;
    PSECURITY_DESCRIPTOR Sd = (PSECURITY_DESCRIPTOR)Buffer;
    PACL Dacl;
    BOOLEAN Present, Defaulted;
    SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
    UCHAR RestrictedSidBuffer[16];
    PSID RestrictedSid = (PSID)RestrictedSidBuffer;
    BOOLEAN FoundRc = FALSE;

    for (i = 0; i < RTL_NUMBER_OF(Rows); i++)
    {
        FILE_FS_DEVICE_INFORMATION Info;
        IO_STATUS_BLOCK Iosb;

        Status = OpenMup(Rows[i].Access, &Handle);
        ok_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
            continue;
        RtlFillMemory(&Info, sizeof(Info), 0xcc);
        Status = NtQueryVolumeInformationFile(Handle, &Iosb, &Info, sizeof(Info), FileFsDeviceInformation);
        if (Rows[i].DataAccess)
        {
            ok(Status == STATUS_INVALID_DEVICE_REQUEST, "access 0x%08lx: FileFsDeviceInformation 0x%08lx, expected STATUS_INVALID_DEVICE_REQUEST\n",
               Rows[i].Access, Status);
        }
        else
        {
            ok(Status == STATUS_SUCCESS, "access 0x%08lx: FileFsDeviceInformation 0x%08lx\n", Rows[i].Access, Status);
            if (NT_SUCCESS(Status))
            {
                ok(Info.DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM, "access 0x%08lx: device type 0x%lx\n", Rows[i].Access, Info.DeviceType);
                ok(Info.Characteristics == 0x20010, "access 0x%08lx: characteristics 0x%lx\n", Rows[i].Access, Info.Characteristics);
            }
        }
        NtClose(Handle);
    }

    /* the descriptor: restricted code gets FILE_GENERIC_EXECUTE only, as on Windows (not the read access of the public default) */
    Status = OpenMup(READ_CONTROL, &Handle);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = NtQuerySecurityObject(Handle, DACL_SECURITY_INFORMATION, Sd, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    NtClose(Handle);
    if (!NT_SUCCESS(Status))
        return;
    RtlInitializeSid(RestrictedSid, &NtAuthority, 1);
    *RtlSubAuthoritySid(RestrictedSid, 0) = SECURITY_RESTRICTED_CODE_RID;
    Status = RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status) && Present && Dacl)
    {
        for (i = 0; i < Dacl->AceCount; i++)
        {
            PACCESS_ALLOWED_ACE Ace;

            if (NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)) && RtlEqualSid(RestrictedSid, &Ace->SidStart))
            {
                FoundRc = TRUE;
                ok(Ace->Mask == 0x001200a0, "restricted code ACE mask 0x%08lx, expected 0x001200a0\n", Ace->Mask);
            }
        }
    }
    ok(FoundRc, "no ACE for restricted code\n");
}
