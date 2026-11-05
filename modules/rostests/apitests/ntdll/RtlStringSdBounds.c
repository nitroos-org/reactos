/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RtlUpcaseUnicodeStringToAnsiString with a destination that is too small, and
 *              RtlValidRelativeSecurityDescriptor with a descriptor that is cut short
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"
#include <winreg.h>
#include <pseh/pseh2.h>

#define MARKER 0xCC

NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeStringToAnsiString(
    _Inout_ PANSI_STRING DestinationString,
    _In_ PCUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString);

/*
 * Windows: a destination without room for the text and a terminator is not written at all,
 * the call returns STATUS_BUFFER_OVERFLOW and sets the length of the converted text.
 */
static
VOID
TestUpcaseAnsiSmallBuffer(VOID)
{
    static const WCHAR Text[] = L"hello";
    UNICODE_STRING Source;
    ANSI_STRING Dest;
    PUCHAR Buffer;
    NTSTATUS Status;
    USHORT MaximumLength;
    ULONG i;

    RtlInitUnicodeString(&Source, Text);

    for (MaximumLength = 0; MaximumLength <= 8; MaximumLength++)
    {
        /* the buffer ends exactly at its declared size, a guard page follows */
        Buffer = MaximumLength ? AllocateGuarded(MaximumLength) : NULL;
        if (Buffer)
            RtlFillMemory(Buffer, MaximumLength, MARKER);
        Dest.Buffer = (PCHAR)Buffer;
        Dest.Length = 0;
        Dest.MaximumLength = MaximumLength;

        Status = STATUS_UNSUCCESSFUL;
        StartSeh()
            Status = RtlUpcaseUnicodeStringToAnsiString(&Dest, &Source, FALSE);
        EndSeh(STATUS_SUCCESS);

        if (MaximumLength <= 5)
        {
            ok_hex(Status, STATUS_BUFFER_OVERFLOW);
            ok(Dest.Length == 5, "MaximumLength %u: Length = %u\n", MaximumLength, Dest.Length);
            for (i = 0; i < MaximumLength; i++)
                ok(Buffer[i] == MARKER, "MaximumLength %u: byte %lu was written (0x%02x)\n", MaximumLength, i, Buffer[i]);
        }
        else
        {
            ok_hex(Status, STATUS_SUCCESS);
            ok(Dest.Length == 5, "MaximumLength %u: Length = %u\n", MaximumLength, Dest.Length);
            ok(!memcmp(Buffer, "HELLO\0", 6), "MaximumLength %u: wrong text\n", MaximumLength);
        }
        if (Buffer)
            FreeGuarded(Buffer);
    }

    /* an empty string fits a one-byte buffer */
    Buffer = AllocateGuarded(1);
    Buffer[0] = MARKER;
    Source.Length = 0;
    Dest.Buffer = (PCHAR)Buffer;
    Dest.Length = 0;
    Dest.MaximumLength = 1;
    Status = RtlUpcaseUnicodeStringToAnsiString(&Dest, &Source, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    ok_int(Dest.Length, 0);
    ok_int(Buffer[0], 0);
    FreeGuarded(Buffer);

    /* an allocated destination is unaffected */
    RtlInitUnicodeString(&Source, Text);
    Status = RtlUpcaseUnicodeStringToAnsiString(&Dest, &Source, TRUE);
    ok_hex(Status, STATUS_SUCCESS);
    ok_int(Dest.Length, 5);
    ok_int(Dest.MaximumLength, 6);
    ok(!strcmp(Dest.Buffer, "HELLO"), "Allocated: %s\n", Dest.Buffer);
    RtlFreeAnsiString(&Dest);
}

/* A self-relative descriptor of an owner, a group, a DACL and a SACL, laid out by hand */
#define SD_OWNER_OFF    (sizeof(SECURITY_DESCRIPTOR_RELATIVE))
#define SD_GROUP_OFF    (SD_OWNER_OFF + 12)
#define SD_DACL_OFF     (SD_GROUP_OFF + 12)
#define SD_ACL_SIZE     (sizeof(ACL) + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 12)
#define SD_SACL_OFF     (SD_DACL_OFF + SD_ACL_SIZE)
#define SD_LENGTH       (SD_SACL_OFF + SD_ACL_SIZE)

static
VOID
BuildSd(
    _Out_writes_bytes_(SD_LENGTH) PUCHAR Sd)
{
    PISECURITY_DESCRIPTOR_RELATIVE Rel = (PISECURITY_DESCRIPTOR_RELATIVE)Sd;
    SID_IDENTIFIER_AUTHORITY WorldAuthority = { SECURITY_WORLD_SID_AUTHORITY };
    PSID Sid;
    PACL Acl;
    PACCESS_ALLOWED_ACE Ace;
    ULONG i;
    NTSTATUS Status;

    RtlZeroMemory(Sd, SD_LENGTH);
    Rel->Revision = SECURITY_DESCRIPTOR_REVISION;
    Rel->Control = SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT;
    Rel->Owner = SD_OWNER_OFF;
    Rel->Group = SD_GROUP_OFF;
    Rel->Dacl = SD_DACL_OFF;
    Rel->Sacl = SD_SACL_OFF;

    for (i = 0; i < 2; i++)
    {
        Sid = Sd + (i ? SD_GROUP_OFF : SD_OWNER_OFF);
        Status = RtlInitializeSid(Sid, &WorldAuthority, 1);
        ok_hex(Status, STATUS_SUCCESS);
        *RtlSubAuthoritySid(Sid, 0) = SECURITY_WORLD_RID;
    }

    for (i = 0; i < 2; i++)
    {
        Acl = (PACL)(Sd + (i ? SD_SACL_OFF : SD_DACL_OFF));
        Status = RtlCreateAcl(Acl, SD_ACL_SIZE, ACL_REVISION);
        ok_hex(Status, STATUS_SUCCESS);
        Ace = (PACCESS_ALLOWED_ACE)(Acl + 1);
        Ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
        Ace->Header.AceSize = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 12;
        Ace->Mask = GENERIC_ALL;
        RtlCopySid(12, (PSID)&Ace->SidStart, Sd + SD_OWNER_OFF);
        Acl->AceCount = 1;
    }
}

/* Validates the first Length bytes of an SD copy that ends at a guard page */
static
BOOLEAN
ValidateCut(
    _In_ const UCHAR *Sd,
    _In_ ULONG Length,
    _Out_ PBOOLEAN Faulted,
    _In_ ULONG Mutation)
{
    PUCHAR Copy = AllocateGuarded(Length);
    BOOLEAN Result = FALSE;

    RtlCopyMemory(Copy, Sd, Length);
    if (Mutation == 1)  /* the DACL claims more bytes than the descriptor has */
        ((PACL)(Copy + SD_DACL_OFF))->AclSize = (USHORT)(Length - SD_DACL_OFF + 64);
    else if (Mutation == 2)
        ((PACL)(Copy + SD_SACL_OFF))->AclSize = (USHORT)(Length - SD_SACL_OFF + 64);

    *Faulted = FALSE;
    _SEH2_TRY
    {
        Result = RtlValidRelativeSecurityDescriptor(Copy, Length, 0);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        *Faulted = TRUE;
    }
    _SEH2_END;
    FreeGuarded(Copy);
    return Result;
}

static
VOID
TestValidRelativeSd(VOID)
{
    UCHAR Sd[SD_LENGTH];
    static const ULONG Cuts[] =
    {
        SD_LENGTH - 1,
        SD_SACL_OFF + sizeof(ACL),
        SD_SACL_OFF + 2,
        SD_SACL_OFF + SD_ACL_SIZE - 1,
        SD_DACL_OFF + sizeof(ACL),
        SD_DACL_OFF + 4,
        SD_DACL_OFF + SD_ACL_SIZE - 1,
        SD_DACL_OFF + SD_ACL_SIZE,
        SD_GROUP_OFF + 4,
        SD_OWNER_OFF + 4,
        SD_OWNER_OFF,
    };
    BOOLEAN Faulted, Result;
    ULONG i;

    BuildSd(Sd);

    /* the whole descriptor is valid */
    Result = ValidateCut(Sd, SD_LENGTH, &Faulted, 0);
    ok(!Faulted, "full SD faulted\n");
    ok(Result == TRUE, "full SD: %u\n", Result);

    /* a descriptor cut anywhere is rejected, and nothing past its end is read */
    for (i = 0; i < _countof(Cuts); i++)
    {
        Result = ValidateCut(Sd, Cuts[i], &Faulted, 0);
        ok(!Faulted, "SD cut to %lu faulted\n", Cuts[i]);
        ok(Result == FALSE, "SD cut to %lu: %u\n", Cuts[i], Result);
    }

    /* an ACL that claims to be longer than the descriptor */
    Result = ValidateCut(Sd, SD_LENGTH, &Faulted, 1);
    ok(!Faulted, "DACL with a big AclSize faulted\n");
    ok(Result == FALSE, "DACL with a big AclSize: %u\n", Result);
    Result = ValidateCut(Sd, SD_LENGTH, &Faulted, 2);
    ok(!Faulted, "SACL with a big AclSize faulted\n");
    ok(Result == FALSE, "SACL with a big AclSize: %u\n", Result);
}

START_TEST(RtlStringSdBounds)
{
    TestUpcaseAnsiSmallBuffer();
    TestValidRelativeSd();
}
