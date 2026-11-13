/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Self-relative security descriptors with a present NULL DACL or NULL SACL
 *              (SE_xACL_PRESENT, offset 0) and the other offset checks of
 *              RtlValidRelativeSecurityDescriptor
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The expected values were measured on Windows 10 22H2.
 */

#include "precomp.h"

#define SR  0x8000
#define DP  0x0004
#define SP  0x0010
#define DAI 0x0400
#define SAI 0x0800
#define DPR 0x1000

/* Owner SY at 20 (12 bytes), group BA at 32 (16), DACL with one ACE at 48 (28), empty SACL at 76 (8), 84 in all */
static
ULONG
Build(PUCHAR b, USHORT Control, ULONG Owner, ULONG Group, ULONG Sacl, ULONG Dacl)
{
    static const UCHAR Sy[12] = { 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 };
    static const UCHAR Ba[16] = { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0 };
    PUCHAR a;

    RtlZeroMemory(b, 160);
    b[0] = 1;
    *(PUSHORT)(b + 2) = Control;
    *(PULONG)(b + 4) = Owner;
    *(PULONG)(b + 8) = Group;
    *(PULONG)(b + 12) = Sacl;
    *(PULONG)(b + 16) = Dacl;
    RtlCopyMemory(b + 20, Sy, sizeof(Sy));
    RtlCopyMemory(b + 32, Ba, sizeof(Ba));
    a = b + 48;
    a[0] = 2; a[2] = 28; a[4] = 1;
    a[10] = 20; a[12] = 0x3f; a[14] = 0x0f;
    RtlCopyMemory(a + 16, Sy, sizeof(Sy));
    b[76] = 2; b[78] = 8;
    return 84;
}

static const struct
{
    const char *Name;
    USHORT Control;
    ULONG Owner, Group, Sacl, Dacl;
    ULONG Length;               /* 0: the whole 84 bytes */
    BOOLEAN Valid;              /* RequiredInformation 0 */
    BOOLEAN ValidAll;           /* RequiredInformation owner, group, DACL and SACL */
} s_Cases[] =
{
    { "both ACLs",                 SR|DP|SP,             20, 32, 76, 48,  0, TRUE,  TRUE  },
    { "NULL SACL",                 SR|DP|SP,             20, 32, 0,  48,  0, TRUE,  TRUE  },
    { "NULL DACL",                 SR|DP|SP,             20, 32, 76, 0,   0, TRUE,  TRUE  },
    { "NULL DACL and SACL",        SR|DP|SP,             20, 32, 0,  0,   0, TRUE,  TRUE  },
    { "NULL ACLs, no owner/group", SR|DP|SP,             0,  0,  0,  0,   0, TRUE,  FALSE },
    { "NULL SACL only",            SR|SP,                0,  0,  0,  0,   0, TRUE,  FALSE },
    { "NULL DACL only",            SR|DP,                0,  0,  0,  0,   0, TRUE,  FALSE },
    { "registry root flags",       SR|DP|SP|DAI|SAI|DPR, 20, 32, 0,  48,  0, TRUE,  TRUE  },
    { "header only",               SR,                   0,  0,  0,  0,   20, TRUE,  FALSE },
    { "header cut short",          SR,                   0,  0,  0,  0,   19, FALSE, FALSE },
    { "NULL SACL, header only",    SR|SP,                0,  0,  0,  0,   20, TRUE,  FALSE },
    { "not self-relative",         DP|SP,                20, 32, 0,  0,   0,  FALSE, FALSE },
    { "SACL offset, not present",  SR|DP,                20, 32, 76, 48,  0,  TRUE,  TRUE  },
    { "no SACL, offset 0",         SR|DP,                20, 32, 0,  48,  0,  TRUE,  TRUE  },
    { "no ACL, offsets 0",         SR,                   20, 32, 0,  0,   0,  TRUE,  TRUE  },
    { "SACL offset 4",             SR|DP|SP,             20, 32, 4,  48,  0,  FALSE, FALSE },
    { "SACL offset 19",            SR|DP|SP,             20, 32, 19, 48,  0,  FALSE, FALSE },
    { "SACL inside the owner",     SR|DP|SP,             20, 32, 20, 48,  0,  FALSE, FALSE },
    { "SACL unaligned",            SR|DP|SP,             20, 32, 78, 48,  0,  FALSE, FALSE },
    { "SACL at the end",           SR|DP|SP,             20, 32, 84, 48,  0,  FALSE, FALSE },
    { "SACL past the end",         SR|DP|SP,             20, 32, 200, 48, 0,  FALSE, FALSE },
    { "SACL cut short",            SR|DP|SP,             20, 32, 76, 48,  80, FALSE, FALSE },
    { "DACL offset 4",             SR|DP|SP,             20, 32, 76, 4,   0,  FALSE, FALSE },
    { "DACL cut short",            SR|DP|SP,             20, 32, 76, 48,  60, FALSE, FALSE },
    { "owner offset 4",            SR|DP|SP,             4,  32, 76, 48,  0,  FALSE, FALSE },
};

static
VOID
TestOffsets(VOID)
{
    UCHAR Buffer[160];
    ULONG i, Length;
    BOOLEAN Result;

    for (i = 0; i < RTL_NUMBER_OF(s_Cases); i++)
    {
        Length = Build(Buffer, s_Cases[i].Control, s_Cases[i].Owner, s_Cases[i].Group,
                       s_Cases[i].Sacl, s_Cases[i].Dacl);
        if (s_Cases[i].Length)
            Length = s_Cases[i].Length;

        Result = RtlValidRelativeSecurityDescriptor(Buffer, Length, 0);
        ok(Result == s_Cases[i].Valid, "%s: valid %d, expected %d\n", s_Cases[i].Name, Result, s_Cases[i].Valid);

        Result = RtlValidRelativeSecurityDescriptor(Buffer, Length,
                                                    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                                    DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION);
        ok(Result == s_Cases[i].ValidAll, "%s: valid with all information %d, expected %d\n",
           s_Cases[i].Name, Result, s_Cases[i].ValidAll);
    }
}

static
VOID
TestRoundTrip(VOID)
{
    static const UCHAR Sy[12] = { 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 };
    SECURITY_DESCRIPTOR Absolute;
    UCHAR Relative[256];
    ULONG Length;
    BOOLEAN Present, Defaulted, Result;
    PACL Acl;
    NTSTATUS Status;
    ULONG Mode;

    /* A NULL DACL, a NULL SACL and both, with an owner or without */
    for (Mode = 0; Mode < 3; Mode++)
    {
        Status = RtlCreateSecurityDescriptor(&Absolute, SECURITY_DESCRIPTOR_REVISION);
        ok_ntstatus(Status, STATUS_SUCCESS);
        Status = RtlSetOwnerSecurityDescriptor(&Absolute, (PSID)Sy, FALSE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (Mode != 1)
        {
            Status = RtlSetSaclSecurityDescriptor(&Absolute, TRUE, NULL, FALSE);
            ok_ntstatus(Status, STATUS_SUCCESS);
        }
        if (Mode != 0)
        {
            Status = RtlSetDaclSecurityDescriptor(&Absolute, TRUE, NULL, FALSE);
            ok_ntstatus(Status, STATUS_SUCCESS);
        }

        Result = RtlValidSecurityDescriptor(&Absolute);
        ok(Result, "mode %lu: the absolute descriptor is not valid\n", Mode);

        Length = sizeof(Relative);
        Status = RtlAbsoluteToSelfRelativeSD(&Absolute, Relative, &Length);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
            continue;

        ok(RtlValidRelativeSecurityDescriptor(Relative, Length, 0),
           "mode %lu: the self-relative descriptor is not valid\n", Mode);
        ok(RtlValidSecurityDescriptor(Relative), "mode %lu: RtlValidSecurityDescriptor\n", Mode);

        Present = FALSE; Acl = (PACL)1; Defaulted = TRUE;
        Status = RtlGetSaclSecurityDescriptor(Relative, &Present, &Acl, &Defaulted);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(Present == (Mode != 1), "mode %lu: SACL present %d\n", Mode, Present);
        if (Mode != 1)
            ok(Acl == NULL, "mode %lu: the SACL is %p\n", Mode, Acl);

        Present = FALSE; Acl = (PACL)1;
        Status = RtlGetDaclSecurityDescriptor(Relative, &Present, &Acl, &Defaulted);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(Present == (Mode != 0), "mode %lu: DACL present %d\n", Mode, Present);
        if (Mode != 0)
            ok(Acl == NULL, "mode %lu: the DACL is %p\n", Mode, Acl);
    }
}

START_TEST(RtlNullAcl)
{
    TestOffsets();
    TestRoundTrip();
}
