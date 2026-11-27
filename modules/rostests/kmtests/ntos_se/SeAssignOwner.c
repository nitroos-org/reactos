/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test for the owner check of SeAssignSecurityEx and of the object manager
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * An owner in an explicit descriptor must be one the subject may assign (its user, a group of it
 * with SE_GROUP_OWNER, or any SID with SeRestorePrivilege enabled) when the request comes from user
 * mode; kernel-mode requests, SEF_AVOID_OWNER_CHECK and descriptors a kernel component built itself
 * (captured in kernel mode by ObCreateObject) are not checked. The user-mode side of the rule was
 * measured on Windows Server 2022 (advapi32_apitest ObjectOwner); the kernel-mode rows are this
 * kernel's contract for its own components.
 */

#include <kmt_test.h>

static SID UnknownSid = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { 0x12345678 } };
static GENERIC_MAPPING Mapping = { STANDARD_RIGHTS_READ | 1, STANDARD_RIGHTS_WRITE | 2, STANDARD_RIGHTS_EXECUTE | 4,
                                   STANDARD_RIGHTS_ALL | 7 };

static NTSTATUS AssignWithOwner(PSID Owner, ULONG Flags, PSECURITY_DESCRIPTOR *New)
{
    SECURITY_DESCRIPTOR Explicit;
    SECURITY_SUBJECT_CONTEXT Subject;
    NTSTATUS Status;

    *New = NULL;
    RtlCreateSecurityDescriptor(&Explicit, SECURITY_DESCRIPTOR_REVISION);
    RtlSetOwnerSecurityDescriptor(&Explicit, Owner, FALSE);
    SeCaptureSubjectContext(&Subject);
    Status = SeAssignSecurityEx(NULL, &Explicit, New, NULL, FALSE, Flags, &Subject, &Mapping, PagedPool);
    SeReleaseSubjectContext(&Subject);
    return Status;
}

static BOOLEAN OwnerIs(PSECURITY_DESCRIPTOR Sd, PSID Sid)
{
    PSID Owner = NULL;
    BOOLEAN Defaulted;

    return Sd && NT_SUCCESS(RtlGetOwnerSecurityDescriptor(Sd, &Owner, &Defaulted)) && Owner && RtlEqualSid(Owner, Sid);
}

typedef struct
{
    NTSTATUS Status;
    BOOLEAN Owned;
} SYSTEM_ROW;

static VOID NTAPI SystemThreadRow(PVOID Context)
{
    SYSTEM_ROW *Row = Context;
    PSECURITY_DESCRIPTOR New;

    Row->Status = AssignWithOwner(&UnknownSid, 0, &New);
    Row->Owned = OwnerIs(New, &UnknownSid);
    if (New)
        SeDeassignSecurity(&New);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

START_TEST(SeAssignOwner)
{
    KPROCESSOR_MODE Mode = ExGetPreviousMode();
    BOOLEAN Restore = SeSinglePrivilegeCheck(SeExports->SeRestorePrivilege, UserMode);
    NTSTATUS Expected, Status;
    PSECURITY_DESCRIPTOR New;
    SECURITY_SUBJECT_CONTEXT Subject;
    PACCESS_TOKEN Token;
    PTOKEN_USER User = NULL;
    SYSTEM_ROW Row = { STATUS_UNSUCCESSFUL, FALSE };
    HANDLE Thread;
    PVOID ThreadObject;
    SECURITY_DESCRIPTOR Sd;
    OBJECT_ATTRIBUTES Attributes;
    PKEVENT Event;
    HANDLE Handle;

    trace("previous mode %d, SeRestorePrivilege enabled %d\n", Mode, Restore);
    Expected = (Mode == UserMode && !Restore) ? STATUS_INVALID_OWNER : STATUS_SUCCESS;

    /* 1. A foreign owner in the requestor's context */
    Status = AssignWithOwner(&UnknownSid, 0, &New);
    ok_eq_hex(Status, Expected);
    if (NT_SUCCESS(Status))
    {
        ok(OwnerIs(New, &UnknownSid), "owner not kept\n");
        SeDeassignSecurity(&New);
    }

    /* 2. The same with SEF_AVOID_OWNER_CHECK */
    Status = AssignWithOwner(&UnknownSid, SEF_AVOID_OWNER_CHECK, &New);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(OwnerIs(New, &UnknownSid), "owner not kept with SEF_AVOID_OWNER_CHECK\n");
    if (New)
        SeDeassignSecurity(&New);

    /* 3. The subject's own user */
    SeCaptureSubjectContext(&Subject);
    Token = SeQuerySubjectContextToken(&Subject);
    Status = SeQueryInformationToken(Token, TokenUser, (PVOID *)&User);
    SeReleaseSubjectContext(&Subject);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = AssignWithOwner(User->User.Sid, 0, &New);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok(OwnerIs(New, User->User.Sid), "own user not kept\n");
        if (New)
            SeDeassignSecurity(&New);
        ExFreePool(User);
    }

    /* 4. A system thread (kernel mode) */
    Status = PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, SystemThreadRow, &Row);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = ObReferenceObjectByHandle(Thread, SYNCHRONIZE, *PsThreadType, KernelMode, &ThreadObject, NULL);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            KeWaitForSingleObject(ThreadObject, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(ThreadObject);
        }
        ZwClose(Thread);
        ok_eq_hex(Row.Status, STATUS_SUCCESS);
        ok(Row.Owned, "system thread: owner not kept\n");
    }

    /* 5. A kernel component's own descriptor, captured in kernel mode, inserted from this thread */
    RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetOwnerSecurityDescriptor(&Sd, &UnknownSid, FALSE);
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, &Sd);
    Status = ObCreateObject(KernelMode, *ExEventObjectType, &Attributes, KernelMode, NULL, sizeof(KEVENT), 0, 0,
                            (PVOID *)&Event);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        KeInitializeEvent(Event, NotificationEvent, FALSE);
        Status = ObInsertObject(Event, NULL, EVENT_ALL_ACCESS, 0, NULL, &Handle);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            UCHAR Buffer[256];
            ULONG Length;

            Status = ZwQuerySecurityObject(Handle, OWNER_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length);
            ok_eq_hex(Status, STATUS_SUCCESS);
            ok(NT_SUCCESS(Status) && OwnerIs(Buffer, &UnknownSid), "kernel descriptor: owner not kept\n");
            ObCloseHandle(Handle, KernelMode);
        }
    }

    /* 6. A kernel-mode Zw create with the same descriptor */
    Status = ZwCreateEvent(&Handle, EVENT_ALL_ACCESS, &Attributes, NotificationEvent, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ZwClose(Handle);
}
