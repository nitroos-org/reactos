/*
 * PROJECT:     ReactOS wdmsec static library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IoCreateDeviceSecure, written from the public WDK documentation
 *              (wdmsec.h): IoCreateDevice, then the security descriptor given
 *              as an SDDL string is applied to the new device object.
 *
 * SDDL support (the subset device objects use): optional owner "O:", the
 * DACL "D:" with flags P (protected) / AI / AR, and allow / deny ACEs
 * "(A|D;flags;rights;;;sid)" with rights as symbolic pairs (GA GR GW GX,
 * FA FR FW FX, SD RC WD WO) or 0x hex values, and SIDs as the two-letter
 * aliases of wellknown SIDs (WD SY BA BU BG PU AU IU NU NS LS AN RC AC OW
 * CO CG ED) or the S-1-... form. A SACL section "S:" is skipped.
 * FIXME: the documented override from the registry through DeviceClassGuid is
 * not implemented (the default SDDL is always used). VERIFY ON ORACLE.
 * FIXME: domain-relative aliases (DA, DU, ...) are not supported: the
 * routine fails with STATUS_INVALID_PARAMETER for them.
 */

#include <ntifs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/obfuncs.h>
#include <wdmsec.h>

#define TAG_WDMSEC 'cesW'

typedef struct _SDDL_ALIAS
{
    WCHAR Name[2];
    UCHAR SubCount;
    UCHAR Authority;
    ULONG Sub[2];
} SDDL_ALIAS;

static const SDDL_ALIAS SddlAliases[] =
{
    { L"WD", 1, 1, { 0 } },                          /* Everyone S-1-1-0 */
    { L"CO", 1, 3, { 0 } },                          /* Creator Owner */
    { L"CG", 1, 3, { 1 } },                          /* Creator Group */
    { L"NU", 1, 5, { 2 } },                          /* Network */
    { L"AN", 1, 5, { 7 } },                          /* Anonymous */
    { L"IU", 1, 5, { 4 } },                          /* Interactive */
    { L"AU", 1, 5, { 11 } },                         /* Authenticated Users */
    { L"ED", 1, 5, { 9 } },                          /* Enterprise Domain Controllers */
    { L"RC", 1, 5, { 12 } },                         /* Restricted Code */
    { L"SY", 1, 5, { 18 } },                         /* Local System */
    { L"LS", 1, 5, { 19 } },                         /* Local Service */
    { L"NS", 1, 5, { 20 } },                         /* Network Service */
    { L"BA", 2, 5, { 32, 544 } },                    /* Builtin Administrators */
    { L"BU", 2, 5, { 32, 545 } },                    /* Builtin Users */
    { L"BG", 2, 5, { 32, 546 } },                    /* Builtin Guests */
    { L"PU", 2, 5, { 32, 547 } },                    /* Power Users */
};
/* OW (Owner Rights, S-1-3-4) and AC (All Application Packages) are handled in WdmsecParseSid */

typedef struct _SDDL_RIGHT
{
    WCHAR Name[2];
    ACCESS_MASK Mask;
} SDDL_RIGHT;

static const SDDL_RIGHT SddlRights[] =
{
    { L"GA", GENERIC_ALL }, { L"GR", GENERIC_READ }, { L"GW", GENERIC_WRITE }, { L"GX", GENERIC_EXECUTE },
    { L"FA", FILE_ALL_ACCESS }, { L"FR", FILE_GENERIC_READ }, { L"FW", FILE_GENERIC_WRITE },
    { L"FX", FILE_GENERIC_EXECUTE },
    { L"SD", DELETE }, { L"RC", READ_CONTROL }, { L"WD", WRITE_DAC }, { L"WO", WRITE_OWNER },
    /* file specific */
    { L"CC", 0x0001 }, { L"DC", 0x0002 }, { L"LC", 0x0004 }, { L"SW", 0x0008 },
    { L"RP", 0x0010 }, { L"WP", 0x0020 }, { L"DT", 0x0040 }, { L"LO", 0x0080 },
    { L"CR", 0x0100 },
};

typedef struct _SDDL_PARSER
{
    PCWSTR Cur;
    PCWSTR End;
} SDDL_PARSER;

static
GENERIC_MAPPING
WdmsecFileMapping(VOID)
{
    GENERIC_MAPPING Mapping;

    Mapping.GenericRead = FILE_GENERIC_READ;
    Mapping.GenericWrite = FILE_GENERIC_WRITE;
    Mapping.GenericExecute = FILE_GENERIC_EXECUTE;
    Mapping.GenericAll = FILE_ALL_ACCESS;
    return Mapping;
}

static
NTSTATUS
WdmsecParseSid(
    _Inout_ SDDL_PARSER *P,
    _Out_ PSID *OutSid)
{
    UCHAR Buffer[SECURITY_MAX_SID_SIZE];
    PISID Sid = (PISID)Buffer;
    PCWSTR Start = P->Cur;
    SID_IDENTIFIER_AUTHORITY Auth = { { 0, 0, 0, 0, 0, 0 } };
    ULONG i;
    UCHAR Count = 0;
    ULONG Subs[SID_MAX_SUB_AUTHORITIES];
    ULONG Authority = 0;
    PSID Result;

    if (P->End - Start >= 2 && Start[0] == L'O' && Start[1] == L'W')
    {
        Authority = 3; Subs[0] = 4; Count = 1; P->Cur += 2;
    }
    else if (P->End - Start >= 2 && Start[0] == L'A' && Start[1] == L'C')
    {
        Authority = 15; Subs[0] = 2; Subs[1] = 1; Count = 2; P->Cur += 2; /* All Application Packages */
    }
    else if (P->End - Start >= 2 && !(Start[0] == L'S' && Start[1] == L'-'))
    {
        for (i = 0; i < RTL_NUMBER_OF(SddlAliases); i++)
        {
            if (SddlAliases[i].Name[0] == Start[0] && SddlAliases[i].Name[1] == Start[1])
            {
                Authority = SddlAliases[i].Authority;
                Count = SddlAliases[i].SubCount;
                Subs[0] = SddlAliases[i].Sub[0];
                Subs[1] = SddlAliases[i].Sub[1];
                P->Cur += 2;
                break;
            }
        }
        if (Count == 0)
            return STATUS_INVALID_PARAMETER;
    }
    else if (P->End - Start >= 6 && Start[0] == L'S' && Start[1] == L'-' && Start[2] == L'1' && Start[3] == L'-')
    {
        /* S-1-<authority>-<sub>-<sub>... */
        PCWSTR C = Start + 4;
        ULONG64 Value = 0;
        BOOLEAN HaveDigit = FALSE, First = TRUE;

        while (C < P->End)
        {
            if (*C >= L'0' && *C <= L'9')
            {
                Value = Value * 10 + (*C - L'0');
                if (Value > MAXULONG) return STATUS_INVALID_PARAMETER;
                HaveDigit = TRUE;
                C++;
            }
            else if (*C == L'-' || *C == L';' || *C == L')')
            {
                if (!HaveDigit) return STATUS_INVALID_PARAMETER;
                if (First)
                {
                    if (Value > 0xFF) return STATUS_INVALID_PARAMETER;
                    Authority = (ULONG)Value;
                    First = FALSE;
                }
                else
                {
                    if (Count >= SID_MAX_SUB_AUTHORITIES) return STATUS_INVALID_PARAMETER;
                    Subs[Count++] = (ULONG)Value;
                }
                Value = 0;
                HaveDigit = FALSE;
                if (*C != L'-') break;
                C++;
            }
            else
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
        if (C >= P->End && HaveDigit)
        {
            if (First) { Authority = (ULONG)Value; }
            else if (Count < SID_MAX_SUB_AUTHORITIES) Subs[Count++] = (ULONG)Value;
        }
        if (Count == 0)
            return STATUS_INVALID_PARAMETER;
        P->Cur = C;
    }
    else
    {
        return STATUS_INVALID_PARAMETER;
    }

    Auth.Value[5] = (UCHAR)Authority;
    RtlInitializeSid(Sid, &Auth, Count);
    for (i = 0; i < Count; i++)
        *RtlSubAuthoritySid(Sid, i) = Subs[i];

    Result = ExAllocatePoolWithTag(PagedPool, RtlLengthSid(Sid), TAG_WDMSEC);
    if (!Result)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(Result, Sid, RtlLengthSid(Sid));
    *OutSid = Result;
    return STATUS_SUCCESS;
}

static
NTSTATUS
WdmsecParseRights(
    _Inout_ SDDL_PARSER *P,
    _Out_ PACCESS_MASK Mask)
{
    ACCESS_MASK Result = 0;

    if (P->End - P->Cur >= 2 && P->Cur[0] == L'0' && (P->Cur[1] == L'x' || P->Cur[1] == L'X'))
    {
        ULONG64 Value = 0;
        PCWSTR C = P->Cur + 2;
        BOOLEAN Any = FALSE;

        for (; C < P->End; C++)
        {
            ULONG Digit;
            if (*C >= L'0' && *C <= L'9') Digit = *C - L'0';
            else if (*C >= L'a' && *C <= L'f') Digit = *C - L'a' + 10;
            else if (*C >= L'A' && *C <= L'F') Digit = *C - L'A' + 10;
            else break;
            Value = Value * 16 + Digit;
            if (Value > MAXULONG) return STATUS_INVALID_PARAMETER;
            Any = TRUE;
        }
        if (!Any) return STATUS_INVALID_PARAMETER;
        P->Cur = C;
        *Mask = (ACCESS_MASK)Value;
        return STATUS_SUCCESS;
    }

    while (P->End - P->Cur >= 2 && P->Cur[0] != L';')
    {
        ULONG i;
        BOOLEAN Found = FALSE;

        for (i = 0; i < RTL_NUMBER_OF(SddlRights); i++)
        {
            if (SddlRights[i].Name[0] == P->Cur[0] && SddlRights[i].Name[1] == P->Cur[1])
            {
                Result |= SddlRights[i].Mask;
                Found = TRUE;
                break;
            }
        }
        if (!Found) return STATUS_INVALID_PARAMETER;
        P->Cur += 2;
    }
    *Mask = Result;
    return STATUS_SUCCESS;
}

/* Skips to the character after the next ';' (a field end) */
static
BOOLEAN
WdmsecSkipField(
    _Inout_ SDDL_PARSER *P)
{
    if (P->Cur < P->End && *P->Cur == L';')
    {
        P->Cur++;
        return TRUE;
    }
    return FALSE;
}

static
NTSTATUS
WdmsecBuildSecurityDescriptor(
    _In_ PCUNICODE_STRING Sddl,
    _Out_ PSECURITY_DESCRIPTOR *OutSd,
    _Out_ PSID *OutOwner,
    _Out_ PSECURITY_INFORMATION OutInfo)
{
    SDDL_PARSER P;
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Acl = NULL;
    PSID Owner = NULL;
    SECURITY_INFORMATION Info = 0;
    BOOLEAN HaveDacl = FALSE, Protected = FALSE;
    GENERIC_MAPPING Mapping = WdmsecFileMapping();
    ULONG AclSize = sizeof(ACL), AceBudget = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    P.Cur = Sddl->Buffer;
    P.End = Sddl->Buffer + Sddl->Length / sizeof(WCHAR);

    /* one ACE per '(' at most */
    {
        PCWSTR C;
        for (C = P.Cur; C < P.End; C++)
            if (*C == L'(') AceBudget++;
    }
    if (AceBudget > 256)
        return STATUS_INVALID_PARAMETER;
    AclSize += AceBudget * (sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE);

    Sd = ExAllocatePoolWithTag(PagedPool, sizeof(SECURITY_DESCRIPTOR) + AclSize, TAG_WDMSEC);
    if (!Sd)
        return STATUS_INSUFFICIENT_RESOURCES;
    Acl = (PACL)((PUCHAR)Sd + sizeof(SECURITY_DESCRIPTOR));
    RtlCreateSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
    RtlCreateAcl(Acl, AclSize, ACL_REVISION);

    while (P.Cur < P.End)
    {
        WCHAR Section = *P.Cur;

        if (P.End - P.Cur < 2 || P.Cur[1] != L':')
        {
            Status = STATUS_INVALID_PARAMETER;
            goto Fail;
        }
        P.Cur += 2;

        if (Section == L'O' || Section == L'G')
        {
            PSID Sid;
            Status = WdmsecParseSid(&P, &Sid);
            if (!NT_SUCCESS(Status)) goto Fail;
            if (Section == L'O')
            {
                if (Owner) ExFreePoolWithTag(Owner, TAG_WDMSEC);
                Owner = Sid;
                Info |= OWNER_SECURITY_INFORMATION;
            }
            else
            {
                /* the group is accepted and not applied */
                ExFreePoolWithTag(Sid, TAG_WDMSEC);
            }
        }
        else if (Section == L'D')
        {
            HaveDacl = TRUE;
            Info |= DACL_SECURITY_INFORMATION;

            /* flags: P, AI, AR, NO_ACCESS_CONTROL */
            while (P.Cur < P.End && *P.Cur != L'(' && *P.Cur != L'S' && *P.Cur != L'O' && *P.Cur != L'G')
            {
                if (*P.Cur == L'P') Protected = TRUE;
                else if (!(*P.Cur == L'A' || *P.Cur == L'I' || *P.Cur == L'R'))
                {
                    Status = STATUS_INVALID_PARAMETER;
                    goto Fail;
                }
                P.Cur++;
            }

            while (P.Cur < P.End && *P.Cur == L'(')
            {
                UCHAR AceType;
                UCHAR AceFlags = 0;
                ACCESS_MASK Mask;
                PSID Sid;
                PACCESS_ALLOWED_ACE Ace;
                ULONG AceSize;

                P.Cur++;
                if (P.Cur >= P.End) { Status = STATUS_INVALID_PARAMETER; goto Fail; }
                if (*P.Cur == L'A') AceType = ACCESS_ALLOWED_ACE_TYPE;
                else if (*P.Cur == L'D') AceType = ACCESS_DENIED_ACE_TYPE;
                else { Status = STATUS_INVALID_PARAMETER; goto Fail; }
                P.Cur++;
                if (!WdmsecSkipField(&P)) { Status = STATUS_INVALID_PARAMETER; goto Fail; }

                /* ace flags */
                while (P.End - P.Cur >= 2 && *P.Cur != L';')
                {
                    if (P.Cur[0] == L'O' && P.Cur[1] == L'I') AceFlags |= OBJECT_INHERIT_ACE;
                    else if (P.Cur[0] == L'C' && P.Cur[1] == L'I') AceFlags |= CONTAINER_INHERIT_ACE;
                    else if (P.Cur[0] == L'N' && P.Cur[1] == L'P') AceFlags |= NO_PROPAGATE_INHERIT_ACE;
                    else if (P.Cur[0] == L'I' && P.Cur[1] == L'O') AceFlags |= INHERIT_ONLY_ACE;
                    else if (P.Cur[0] == L'I' && P.Cur[1] == L'D') AceFlags |= INHERITED_ACE;
                    else { Status = STATUS_INVALID_PARAMETER; goto Fail; }
                    P.Cur += 2;
                }
                if (!WdmsecSkipField(&P)) { Status = STATUS_INVALID_PARAMETER; goto Fail; }

                Status = WdmsecParseRights(&P, &Mask);
                if (!NT_SUCCESS(Status)) goto Fail;
                if (!WdmsecSkipField(&P)) { Status = STATUS_INVALID_PARAMETER; goto Fail; }

                /* object guid and inherit object guid: not supported, must be empty */
                if (!WdmsecSkipField(&P) || !WdmsecSkipField(&P)) { Status = STATUS_INVALID_PARAMETER; goto Fail; }

                Status = WdmsecParseSid(&P, &Sid);
                if (!NT_SUCCESS(Status)) goto Fail;
                if (P.Cur >= P.End || *P.Cur != L')')
                {
                    ExFreePoolWithTag(Sid, TAG_WDMSEC);
                    Status = STATUS_INVALID_PARAMETER;
                    goto Fail;
                }
                P.Cur++;

                /* device objects are checked with the file generic mapping */
                RtlMapGenericMask(&Mask, &Mapping);

                AceSize = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(Sid);
                Ace = ExAllocatePoolWithTag(PagedPool, AceSize, TAG_WDMSEC);
                if (!Ace)
                {
                    ExFreePoolWithTag(Sid, TAG_WDMSEC);
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto Fail;
                }
                Ace->Header.AceType = AceType;
                Ace->Header.AceFlags = AceFlags;
                Ace->Header.AceSize = (USHORT)AceSize;
                Ace->Mask = Mask;
                RtlCopyMemory(&Ace->SidStart, Sid, RtlLengthSid(Sid));
                ExFreePoolWithTag(Sid, TAG_WDMSEC);

                Status = RtlAddAce(Acl, ACL_REVISION, MAXULONG, Ace, AceSize);
                ExFreePoolWithTag(Ace, TAG_WDMSEC);
                if (!NT_SUCCESS(Status))
                {
                    Status = STATUS_INVALID_PARAMETER;
                    goto Fail;
                }
            }
        }
        else if (Section == L'S')
        {
            /* a SACL is accepted and not applied: skip to the end */
            P.Cur = P.End;
        }
        else
        {
            Status = STATUS_INVALID_PARAMETER;
            goto Fail;
        }
    }

    if (Info == 0)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Fail;
    }

    if (HaveDacl)
    {
        Status = RtlSetDaclSecurityDescriptor(Sd, TRUE, Acl, FALSE);
        if (!NT_SUCCESS(Status)) goto Fail;
        if (Protected)
            ((PISECURITY_DESCRIPTOR)Sd)->Control |= SE_DACL_PROTECTED;
    }
    if (Owner)
    {
        Status = RtlSetOwnerSecurityDescriptor(Sd, Owner, FALSE);
        if (!NT_SUCCESS(Status)) goto Fail;
    }

    *OutSd = Sd;
    *OutOwner = Owner;
    *OutInfo = Info;
    return STATUS_SUCCESS;

Fail:
    if (Owner) ExFreePoolWithTag(Owner, TAG_WDMSEC);
    ExFreePoolWithTag(Sd, TAG_WDMSEC);
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
NTAPI
IoCreateDeviceSecure(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONG DeviceExtensionSize,
    _In_opt_ PUNICODE_STRING DeviceName,
    _In_ DEVICE_TYPE DeviceType,
    _In_ ULONG DeviceCharacteristics,
    _In_ BOOLEAN Exclusive,
    _In_ PCUNICODE_STRING DefaultSDDLString,
    _In_opt_ LPCGUID DeviceClassGuid,
    _Out_ PDEVICE_OBJECT *DeviceObject)
{
    PSECURITY_DESCRIPTOR Sd;
    PSID Owner;
    SECURITY_INFORMATION Info;
    NTSTATUS Status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceClassGuid); /* FIXME: registry override, see the file header */

    if (DefaultSDDLString == NULL || DefaultSDDLString->Buffer == NULL || DefaultSDDLString->Length == 0)
        return STATUS_INVALID_PARAMETER;

    /* Parse first: an invalid string must not leave a device object behind */
    Status = WdmsecBuildSecurityDescriptor(DefaultSDDLString, &Sd, &Owner, &Info);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = IoCreateDevice(DriverObject,
                            DeviceExtensionSize,
                            DeviceName,
                            DeviceType,
                            DeviceCharacteristics,
                            Exclusive,
                            DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        if (Owner) ExFreePoolWithTag(Owner, TAG_WDMSEC);
        ExFreePoolWithTag(Sd, TAG_WDMSEC);
        return Status;
    }

    Status = ObSetSecurityObjectByPointer(*DeviceObject, Info, Sd);
    if (Owner) ExFreePoolWithTag(Owner, TAG_WDMSEC);
    ExFreePoolWithTag(Sd, TAG_WDMSEC);
    if (!NT_SUCCESS(Status))
    {
        IoDeleteDevice(*DeviceObject);
        *DeviceObject = NULL;
        return Status;
    }

    return STATUS_SUCCESS;
}
