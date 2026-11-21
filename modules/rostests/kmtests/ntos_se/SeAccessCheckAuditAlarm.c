/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test for ZwAccessCheckAndAuditAlarm called from kernel mode
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The access check and audit alarm services capture every argument from user memory, and
 * their result is about the impersonation token of a user-mode client. A kernel-mode caller
 * (ZwAccessCheckAndAuditAlarm, exported) is refused with STATUS_NOT_IMPLEMENTED and nothing
 * is written: before, a checked kernel stopped on an assertion and a free kernel probed the
 * kernel buffers as user buffers. What Windows does for a kernel-mode caller is not in the
 * public documentation (verify on Windows); this row pins the clean refusal.
 */

#include <kmt_test.h>

/* Exported by ntoskrnl; ntifs.h declares it only for newer NTDDI versions than the tests are built for */
NTSYSAPI
NTSTATUS
NTAPI
ZwAccessCheckAndAuditAlarm(
    _In_ PUNICODE_STRING SubsystemName,
    _In_opt_ PVOID HandleId,
    _In_ PUNICODE_STRING ObjectTypeName,
    _In_ PUNICODE_STRING ObjectName,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_ BOOLEAN ObjectCreation,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus,
    _Out_ PBOOLEAN GenerateOnClose);

static GENERIC_MAPPING Mapping = { 0x1 | READ_CONTROL, 0x2, 0x4, 0x7 | STANDARD_RIGHTS_REQUIRED };
static SID WorldSid = { SID_REVISION, 1, { SECURITY_WORLD_SID_AUTHORITY }, { SECURITY_WORLD_RID } };

START_TEST(SeAccessCheckAuditAlarm)
{
    SECURITY_DESCRIPTOR Sd;
    UNICODE_STRING Subsystem = RTL_CONSTANT_STRING(L"kmtest");
    UNICODE_STRING TypeName = RTL_CONSTANT_STRING(L"TestObject");
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"Object");
    ACCESS_MASK Granted = 0xa5a5a5a5;
    NTSTATUS AccessStatus = (NTSTATUS)0xa5a5a5a5;
    BOOLEAN OnClose = 0x55;
    NTSTATUS Status;

    RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetOwnerSecurityDescriptor(&Sd, &WorldSid, FALSE);
    RtlSetGroupSecurityDescriptor(&Sd, &WorldSid, FALSE);
    RtlSetDaclSecurityDescriptor(&Sd, TRUE, NULL, FALSE);

    Status = ZwAccessCheckAndAuditAlarm(&Subsystem, NULL, &TypeName, &Name, &Sd, 0x1, &Mapping, FALSE, &Granted,
                                        &AccessStatus, &OnClose);
    ok_eq_hex(Status, STATUS_NOT_IMPLEMENTED);
    ok_eq_hex(Granted, 0xa5a5a5a5);
    ok_eq_hex((ULONG)AccessStatus, 0xa5a5a5a5);
    ok_eq_uint(OnClose, 0x55);
}
