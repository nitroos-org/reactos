/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for IoCreateDeviceSecure (wdmsec library)
 */

#include <kmt_test.h>
#include <wdmsec.h>

static
VOID
CheckDevice(
    _In_ PCWSTR Sddl,
    _In_ ULONG ExpectedAces,
    _In_opt_ PSID ExpectedFirstSid,
    _In_ ACCESS_MASK ExpectedFirstMask)
{
    UNICODE_STRING SddlString;
    PDEVICE_OBJECT Device = NULL;
    PSECURITY_DESCRIPTOR Sd = NULL;
    BOOLEAN Present = FALSE, Defaulted, MemoryAllocated = FALSE;
    PACL Dacl = NULL;
    NTSTATUS Status;

    RtlInitUnicodeString(&SddlString, Sddl);
    Status = IoCreateDeviceSecure(KmtDriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE,
                                  &SddlString, NULL, &Device);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    Status = ObGetObjectSecurity(Device, &Sd, &MemoryAllocated);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(Sd != NULL, "device has no security descriptor\n");
    if (NT_SUCCESS(Status) && Sd)
    {
        Status = RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok(Present, "no DACL present\n");
        if (Present && ExpectedAces == 0)
        {
            /* "D:P": a DACL with no ACE (empty) or NULL both mean no access for user mode */
            ok(Dacl != NULL && Dacl->AceCount == 0, "expected an empty DACL, got %p\n", Dacl);
        }
        else if (Present && Dacl)
        {
            ok_eq_int(Dacl->AceCount, (int)ExpectedAces);
            if (Dacl->AceCount >= 1 && ExpectedFirstSid)
            {
                PACCESS_ALLOWED_ACE Ace = (PACCESS_ALLOWED_ACE)(Dacl + 1);

                ok_eq_int(Ace->Header.AceType, ACCESS_ALLOWED_ACE_TYPE);
                ok(RtlEqualSid(&Ace->SidStart, ExpectedFirstSid), "first ACE has the wrong SID\n");
                ok_eq_hex(Ace->Mask, ExpectedFirstMask);
            }
        }
        ObReleaseObjectSecurity(Sd, MemoryAllocated);
    }
    IoDeleteDevice(Device);
}

START_TEST(IoCreateDeviceSecure)
{
    UCHAR SidBuffer[SECURITY_MAX_SID_SIZE];
    PSID SystemSid = (PSID)SidBuffer;
    SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
    UNICODE_STRING Sddl;
    PDEVICE_OBJECT Device = NULL;
    NTSTATUS Status;

    RtlInitializeSid(SystemSid, &NtAuthority, 1);
    *RtlSubAuthoritySid(SystemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;

    CheckDevice(SDDL_DEVOBJ_SYS_ALL, 1, SystemSid, FILE_ALL_ACCESS);
    CheckDevice(SDDL_DEVOBJ_SYS_ALL_ADM_ALL, 2, SystemSid, FILE_ALL_ACCESS);
    CheckDevice(SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R, 4, SystemSid, FILE_ALL_ACCESS);
    CheckDevice(SDDL_DEVOBJ_KERNEL_ONLY, 0, NULL, 0);
    /* explicit form, numeric SID, hex rights */
    CheckDevice(L"D:P(A;;0x12019f;;;S-1-5-18)(A;;GR;;;WD)", 2, SystemSid, 0x12019f);

    /* invalid strings fail and create nothing */
    RtlInitUnicodeString(&Sddl, L"D:P(A;;GA;;;ZZ)");
    Status = IoCreateDeviceSecure(KmtDriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &Sddl, NULL, &Device);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);
    ok(Device == NULL, "device returned for an invalid string\n");
    RtlInitUnicodeString(&Sddl, L"garbage");
    Status = IoCreateDeviceSecure(KmtDriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &Sddl, NULL, &Device);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);
    ok(Device == NULL, "device returned for an invalid string\n");
}
