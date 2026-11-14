/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Native mandatory-label security queries on processes and threads
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static VOID TestLabel(HANDLE Object, ULONG Level)
{
    ULONG Buffer[128], Length, i;
    SECURITY_DESCRIPTOR_RELATIVE *Sd = (PVOID)Buffer;
    PSYSTEM_MANDATORY_LABEL_ACE Ace;
    PACL Sacl;
    NTSTATUS Status;
    HANDLE Handle;
    static const ACCESS_MASK Rights[] = {0, READ_CONTROL, WRITE_OWNER};

    Status = NtQuerySecurityObject(Object, LABEL_SECURITY_INFORMATION, NULL, 0, &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok(Length == 48, "Label descriptor length %lu, expected 48\n", Length);
    Status = NtQuerySecurityObject(Object, LABEL_SECURITY_INFORMATION, Sd, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    ok(Sd->Control == (SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT),
       "Control %x\n", Sd->Control);
    ok(!Sd->Owner && !Sd->Group && !Sd->Dacl, "LABEL query returned unrelated security information\n");
    ok(Sd->Sacl != 0, "Missing SACL\n");
    if (Sd->Sacl)
    {
        Sacl = (PACL)((PBYTE)Sd + Sd->Sacl);
        ok(Sacl->AceCount == 1, "ACE count %u\n", Sacl->AceCount);
        Status = RtlGetAce(Sacl, 0, (PVOID *)&Ace);
        ok_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            ok(Ace->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE, "Type %u\n", Ace->Header.AceType);
            ok(Ace->Mask == (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP),
               "Default policy %lx\n", Ace->Mask);
            ok(*RtlSubAuthoritySid(&Ace->SidStart, 0) == Level, "Level %lx, expected %lx\n",
               *RtlSubAuthoritySid(&Ace->SidStart, 0), Level);
        }
    }
    for (i = 0; i < _countof(Rights); ++i)
    {
        Status = NtDuplicateObject(NtCurrentProcess(), Object, NtCurrentProcess(), &Handle, Rights[i], 0, 0);
        ok_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status)) continue;
        Status = NtQuerySecurityObject(Handle, LABEL_SECURITY_INFORMATION, Sd, sizeof(Buffer), &Length);
        ok_hex(Status, (Rights[i] & READ_CONTROL) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED);
        NtClose(Handle);
    }
}

static ULONG QueryControl(HANDLE Object, SECURITY_INFORMATION Information)
{
    ULONG Buffer[128], Length;
    SECURITY_DESCRIPTOR_RELATIVE *Sd = (PVOID)Buffer;
    NTSTATUS Status;

    Status = NtQuerySecurityObject(Object, Information, Sd, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? Sd->Control : 0;
}

/* The SACL of a token and of an object created with an explicit SACL is auto-inherited */
static VOID TestAutoInherited(VOID)
{
    static const SID_IDENTIFIER_AUTHORITY LabelAuthority = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    struct
    {
        ACL Acl;
        SYSTEM_MANDATORY_LABEL_ACE Ace;
        ULONG Sid[4];
    } Sacl;
    SECURITY_DESCRIPTOR Sd;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Token, Event;
    NTSTATUS Status;
    PSID Sid;

    Status = NtOpenProcessToken(NtCurrentProcess(), READ_CONTROL, &Token);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_hex(QueryControl(Token, LABEL_SECURITY_INFORMATION),
               SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT);
        ok_hex(QueryControl(Token, DACL_SECURITY_INFORMATION), SE_SELF_RELATIVE | SE_DACL_PRESENT);
        NtClose(Token);
    }

    RtlZeroMemory(&Sacl, sizeof(Sacl));
    Status = RtlCreateAcl(&Sacl.Acl, sizeof(Sacl), ACL_REVISION);
    ok_hex(Status, STATUS_SUCCESS);
    Sacl.Ace.Header.AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
    Sacl.Ace.Header.AceSize = sizeof(SYSTEM_MANDATORY_LABEL_ACE) + sizeof(Sacl.Sid) - sizeof(ULONG);
    Sacl.Ace.Mask = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
    Sid = (PSID)&Sacl.Ace.SidStart;
    RtlInitializeSid(Sid, (PSID_IDENTIFIER_AUTHORITY)&LabelAuthority, 1);
    *RtlSubAuthoritySid(Sid, 0) = SECURITY_MANDATORY_LOW_RID;
    Sacl.Acl.AceCount = 1;
    Sacl.Acl.AclSize = sizeof(Sacl.Acl) + Sacl.Ace.Header.AceSize;

    RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetSaclSecurityDescriptor(&Sd, TRUE, &Sacl.Acl, FALSE);
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, &Sd);
    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, &ObjectAttributes, NotificationEvent, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_hex(QueryControl(Event, LABEL_SECURITY_INFORMATION),
               SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT);
        NtClose(Event);
    }

    /* Without an explicit descriptor there is no SACL */
    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_hex(QueryControl(Event, LABEL_SECURITY_INFORMATION), SE_SELF_RELATIVE);
        NtClose(Event);
    }
}

START_TEST(NtQuerySecurityObject)
{
    UCHAR Buffer[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE];
    PTOKEN_MANDATORY_LABEL Label = (PVOID)Buffer;
    ULONG Length, Level;
    HANDLE Token;
    NTSTATUS Status;

    Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &Token);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    Status = NtQueryInformationToken(Token, TokenIntegrityLevel, Buffer, sizeof(Buffer), &Length);
    NtClose(Token);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    Level = *RtlSubAuthoritySid(Label->Label.Sid, 0);
    TestLabel(NtCurrentProcess(), Level);
    TestLabel(NtCurrentThread(), Level);
    TestAutoInherited();
}
