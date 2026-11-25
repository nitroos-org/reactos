/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests SetPrivateObjectSecurityEx and the auto-inherit flags of a descriptor set
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Rows measured on Windows Server 2022 (x64 and x86 under WoW64, identical; 3024 rows of which
 * these are a selection): what a private descriptor holds after SetPrivateObjectSecurityEx.
 *  - Without an auto-inherit flag the ACEs given are stored mapped, in place; the protected bit of the
 *    modification descriptor is copied, and the auto-inherited bit is set only when the modification
 *    descriptor has both the auto-inherit-required and the auto-inherited bits.
 *  - With SEF_DACL_AUTO_INHERIT (SEF_SACL_AUTO_INHERIT for the SACL) the auto-inherited bit is set,
 *    the stored ACL is the explicit ACEs of the modification ACL followed by the inherited ACEs the object has;
 *    a protected modification ACL is taken whole with its inherited bit cleared. An inheritable ACE that is not
 *    inherit-only and has generic rights is split into an effective ACE and an inherit-only copy.
 * Other flag values (privilege and owner checks, label bits) change nothing in a private set.
 * Row text: control, then DACL and SACL as present flag and [type/flags/mask/W(orld) or S(ystem)].
 */

typedef struct { int Type; UCHAR Flags; ULONG Mask; int System; } ACEDEF;
typedef struct { int Count; ACEDEF Aces[4]; } ACLDEF;

static const ACLDEF Starts[3][2] =
{
    { { 1, {{0, 0, 0x20001, 0}} },                                                  { 1, {{2, 0, 0x20001, 0}} } },
    { { 2, {{0, 0, 0x20001, 0}, {0, 0x10, 0x20002, 1}} },                           { 2, {{2, 0, 0x20001, 0}, {2, 0x10, 0x20004, 1}} } },
    { { 3, {{0, 0x11, 0x20004, 0}, {0, 0, 0x20001, 0}, {0, 0x12, 0x80000000, 1}} }, { 2, {{2, 0x12, 0x20001, 0}, {2, 0, 0x20002, 1}} } },
};

static const ACLDEF Mods[6][2] =
{
    { { 2, {{0, 0, 0x80000000, 0}, {0, 0x12, 0x10000000, 1}} },                     { 1, {{2, 0x10, 0x20004, 1}} } },
    { { 3, {{0, 0x02, 0x10000000, 0}, {0, 0x01, 0x80000000, 1}, {0, 0x03, 0x20000000, 0}} }, { 2, {{2, 0x02, 0x10000000, 1}, {2, 0x01, 0x20004, 0}} } },
    { { 2, {{0, 0x0B, 0x10000000, 0}, {0, 0x11, 0x20001, 1}} },                     { 2, {{2, 0x0B, 0x10000000, 0}, {2, 0x11, 0x20001, 1}} } },
    { { 2, {{1, 0, 0x10000000, 0}, {0, 0x14, 0x20002, 1}} },                        { 1, {{2, 0x1A, 0x20004, 0}} } },
    { { 0, {{0}} },                                                                 { 0, {{0}} } },
    { { 3, {{0, 0x10, 0x20001, 0}, {0, 0x12, 0x20002, 1}, {0, 0, 0x20004, 0}} },    { 2, {{2, 0x10, 0x20001, 0}, {2, 0, 0x20002, 1}} } },
};

static const struct { int Start, Mod; ULONG Control, Flags; const char *Expected; } Rows[] =
{
    { 1, 0, 0x0000, 0x00, "0014 D1[00/00/00020001/W,00/12/001f00ff/S] S1[02/d0/00020004/S]" },
    { 1, 0, 0x0000, 0x01, "0414 D1[00/00/00020001/W,00/10/00020002/S] S1[02/d0/00020004/S]" },
    { 1, 0, 0x0000, 0x03, "0c14 D1[00/00/00020001/W,00/10/00020002/S] S1[02/d0/00020004/S]" },
    { 1, 0, 0x0500, 0x00, "0414 D1[00/00/00020001/W,00/12/001f00ff/S] S1[02/d0/00020004/S]" },
    { 1, 0, 0x1000, 0x01, "1414 D1[00/00/00020001/W,00/00/001f00ff/S,00/0a/10000000/S] S1[02/d0/00020004/S]" },
    { 1, 0, 0x2000, 0x02, "2814 D1[00/00/00020001/W,00/12/001f00ff/S] S1[02/c0/00020004/S]" },
    { 1, 1, 0x0000, 0x00, "0014 D1[00/02/001f00ff/W,00/01/00020001/S,00/03/00020004/W] S1[02/c2/001f00ff/S,02/c1/00020004/W]" },
    { 1, 1, 0x0000, 0x01, "0414 D1[00/00/001f00ff/W,00/0a/10000000/W,00/00/00020001/S,00/09/80000000/S,00/00/00020004/W,00/0b/20000000/W,00/10/00020002/S] S1[02/c2/001f00ff/S,02/c1/00020004/W]" },
    { 1, 1, 0x0000, 0x03, "0c14 D1[00/00/001f00ff/W,00/0a/10000000/W,00/00/00020001/S,00/09/80000000/S,00/00/00020004/W,00/0b/20000000/W,00/10/00020002/S] S1[02/c0/001f00ff/S,02/ca/10000000/S,02/c1/00020004/W,02/d0/00020004/S]" },
    { 1, 1, 0x0500, 0x00, "0414 D1[00/02/001f00ff/W,00/01/00020001/S,00/03/00020004/W] S1[02/c2/001f00ff/S,02/c1/00020004/W]" },
    { 1, 1, 0x1000, 0x01, "1414 D1[00/00/001f00ff/W,00/0a/10000000/W,00/00/00020001/S,00/09/80000000/S,00/00/00020004/W,00/0b/20000000/W] S1[02/c2/001f00ff/S,02/c1/00020004/W]" },
    { 1, 1, 0x2000, 0x02, "2814 D1[00/02/001f00ff/W,00/01/00020001/S,00/03/00020004/W] S1[02/c0/001f00ff/S,02/ca/10000000/S,02/c1/00020004/W]" },
    { 1, 2, 0x0000, 0x00, "0014 D1[00/0b/10000000/W,00/11/00020001/S] S1[02/cb/10000000/W,02/d1/00020001/S]" },
    { 1, 2, 0x0000, 0x01, "0414 D1[00/0b/10000000/W,00/10/00020002/S] S1[02/cb/10000000/W,02/d1/00020001/S]" },
    { 1, 2, 0x0000, 0x03, "0c14 D1[00/0b/10000000/W,00/10/00020002/S] S1[02/cb/10000000/W,02/d0/00020004/S]" },
    { 1, 2, 0x0500, 0x00, "0414 D1[00/0b/10000000/W,00/11/00020001/S] S1[02/cb/10000000/W,02/d1/00020001/S]" },
    { 1, 2, 0x1000, 0x01, "1414 D1[00/0b/10000000/W,00/01/00020001/S] S1[02/cb/10000000/W,02/d1/00020001/S]" },
    { 1, 2, 0x2000, 0x02, "2814 D1[00/0b/10000000/W,00/11/00020001/S] S1[02/cb/10000000/W,02/c1/00020001/S]" },
    { 1, 3, 0x0000, 0x00, "0014 D1[01/00/001f00ff/W,00/14/00020002/S] S1[02/da/00020004/W]" },
    { 1, 3, 0x0000, 0x01, "0414 D1[01/00/001f00ff/W,00/10/00020002/S] S1[02/da/00020004/W]" },
    { 1, 3, 0x0000, 0x03, "0c14 D1[01/00/001f00ff/W,00/10/00020002/S] S1[02/d0/00020004/S]" },
    { 1, 3, 0x0500, 0x00, "0414 D1[01/00/001f00ff/W,00/14/00020002/S] S1[02/da/00020004/W]" },
    { 1, 3, 0x1000, 0x01, "1414 D1[01/00/001f00ff/W,00/00/00020002/S] S1[02/da/00020004/W]" },
    { 1, 3, 0x2000, 0x02, "2814 D1[01/00/001f00ff/W,00/14/00020002/S] S1[02/ca/00020004/W]" },
    { 1, 4, 0x0000, 0x00, "0014 D1[] S1[]" },
    { 1, 4, 0x0000, 0x01, "0414 D1[00/10/00020002/S] S1[]" },
    { 1, 4, 0x0000, 0x03, "0c14 D1[00/10/00020002/S] S1[02/d0/00020004/S]" },
    { 1, 4, 0x0500, 0x00, "0414 D1[] S1[]" },
    { 1, 4, 0x1000, 0x01, "1414 D1[] S1[]" },
    { 1, 4, 0x2000, 0x02, "2814 D1[] S1[]" },
    { 1, 5, 0x0000, 0x00, "0014 D1[00/10/00020001/W,00/12/00020002/S,00/00/00020004/W] S1[02/d0/00020001/W,02/c0/00020002/S]" },
    { 1, 5, 0x0000, 0x01, "0414 D1[00/00/00020004/W,00/10/00020002/S] S1[02/d0/00020001/W,02/c0/00020002/S]" },
    { 1, 5, 0x0000, 0x03, "0c14 D1[00/00/00020004/W,00/10/00020002/S] S1[02/c0/00020002/S,02/d0/00020004/S]" },
    { 1, 5, 0x0500, 0x00, "0414 D1[00/10/00020001/W,00/12/00020002/S,00/00/00020004/W] S1[02/d0/00020001/W,02/c0/00020002/S]" },
    { 1, 5, 0x1000, 0x01, "1414 D1[00/00/00020001/W,00/02/00020002/S,00/00/00020004/W] S1[02/d0/00020001/W,02/c0/00020002/S]" },
    { 1, 5, 0x2000, 0x02, "2814 D1[00/10/00020001/W,00/12/00020002/S,00/00/00020004/W] S1[02/c0/00020001/W,02/c0/00020002/S]" },
    { 2, 0, 0x0000, 0x00, "0014 D1[00/00/00020001/W,00/12/001f00ff/S] S1[02/d0/00020004/S]" },
    { 2, 0, 0x0000, 0x01, "0414 D1[00/00/00020001/W,00/11/00020004/W,00/12/00020001/S] S1[02/d0/00020004/S]" },
    { 2, 0, 0x0000, 0x03, "0c14 D1[00/00/00020001/W,00/11/00020004/W,00/12/00020001/S] S1[02/d2/00020001/W]" },
    { 2, 0, 0x0500, 0x00, "0414 D1[00/00/00020001/W,00/12/001f00ff/S] S1[02/d0/00020004/S]" },
    { 2, 0, 0x1000, 0x01, "1414 D1[00/00/00020001/W,00/00/001f00ff/S,00/0a/10000000/S] S1[02/d0/00020004/S]" },
    { 2, 0, 0x2000, 0x02, "2814 D1[00/00/00020001/W,00/12/001f00ff/S] S1[02/c0/00020004/S]" },
    { 2, 1, 0x0000, 0x01, "0414 D1[00/00/001f00ff/W,00/0a/10000000/W,00/00/00020001/S,00/09/80000000/S,00/00/00020004/W,00/0b/20000000/W,00/11/00020004/W,00/12/00020001/S] S1[02/c2/001f00ff/S,02/c1/00020004/W]" },
    { 2, 1, 0x0000, 0x03, "0c14 D1[00/00/001f00ff/W,00/0a/10000000/W,00/00/00020001/S,00/09/80000000/S,00/00/00020004/W,00/0b/20000000/W,00/11/00020004/W,00/12/00020001/S] S1[02/c0/001f00ff/S,02/ca/10000000/S,02/c1/00020004/W,02/d2/00020001/W]" },
    { 2, 1, 0x1000, 0x01, "1414 D1[00/00/001f00ff/W,00/0a/10000000/W,00/00/00020001/S,00/09/80000000/S,00/00/00020004/W,00/0b/20000000/W] S1[02/c2/001f00ff/S,02/c1/00020004/W]" },
    { 2, 2, 0x0000, 0x00, "0014 D1[00/0b/10000000/W,00/11/00020001/S] S1[02/cb/10000000/W,02/d1/00020001/S]" },
    { 2, 2, 0x0000, 0x01, "0414 D1[00/0b/10000000/W,00/11/00020004/W,00/12/00020001/S] S1[02/cb/10000000/W,02/d1/00020001/S]" },
    { 2, 2, 0x1000, 0x01, "1414 D1[00/0b/10000000/W,00/01/00020001/S] S1[02/cb/10000000/W,02/d1/00020001/S]" },
    { 2, 3, 0x1000, 0x01, "1414 D1[01/00/001f00ff/W,00/00/00020002/S] S1[02/da/00020004/W]" },
    { 2, 4, 0x0000, 0x01, "0414 D1[00/11/00020004/W,00/12/00020001/S] S1[]" },
    { 2, 4, 0x1000, 0x01, "1414 D1[] S1[]" },
    { 2, 5, 0x0000, 0x01, "0414 D1[00/00/00020004/W,00/11/00020004/W,00/12/00020001/S] S1[02/d0/00020001/W,02/c0/00020002/S]" },
    { 2, 5, 0x0000, 0x03, "0c14 D1[00/00/00020004/W,00/11/00020004/W,00/12/00020001/S] S1[02/c0/00020002/S,02/d2/00020001/W]" },
    { 2, 5, 0x1000, 0x01, "1414 D1[00/00/00020001/W,00/02/00020002/S,00/00/00020004/W] S1[02/d0/00020001/W,02/c0/00020002/S]" },
};

static PSID Sid(int System)
{
    static BYTE Sids[2][SECURITY_MAX_SID_SIZE];
    DWORD Size = SECURITY_MAX_SID_SIZE;

    CreateWellKnownSid(System ? WinLocalSystemSid : WinWorldSid, NULL, (PSID)Sids[System], &Size);
    return (PSID)Sids[System];
}

static PACL MakeAcl(const ACLDEF *Def)
{
    PACL Acl = LocalAlloc(LPTR, 1024);
    int i;

    InitializeAcl(Acl, 1024, ACL_REVISION);
    for (i = 0; i < Def->Count; i++)
    {
        const ACEDEF *Ace = &Def->Aces[i];

        if (Ace->Type == 0)
            AddAccessAllowedAceEx(Acl, ACL_REVISION, Ace->Flags, Ace->Mask, Sid(Ace->System));
        else if (Ace->Type == 1)
            AddAccessDeniedAceEx(Acl, ACL_REVISION, Ace->Flags, Ace->Mask, Sid(Ace->System));
        else
            RtlAddAuditAccessAceEx(Acl, ACL_REVISION, Ace->Flags, Ace->Mask, Sid(Ace->System), TRUE, TRUE);
    }
    return Acl;
}

static int DumpAcl(char *Out, PACL Acl, BOOL Present)
{
    int n = sprintf(Out, "%d[", Present);
    DWORD i;

    if (Present && Acl)
    {
        for (i = 0; i < Acl->AceCount; i++)
        {
            ACCESS_ALLOWED_ACE *Ace;

            if (!GetAce(Acl, i, (void **)&Ace))
                break;
            n += sprintf(Out + n, "%s%02x/%02x/%08lx/%c", i ? "," : "", Ace->Header.AceType, Ace->Header.AceFlags,
                         Ace->Mask, EqualSid((PSID)&Ace->SidStart, Sid(1)) ? 'S' : 'W');
        }
    }
    n += sprintf(Out + n, "]");
    return n;
}

static void Dump(char *Out, PSECURITY_DESCRIPTOR Sd)
{
    SECURITY_DESCRIPTOR_CONTROL Control;
    DWORD Revision;
    BOOL Present, Defaulted;
    PACL Acl;
    int n;

    GetSecurityDescriptorControl(Sd, &Control, &Revision);
    n = sprintf(Out, "%04x D", Control & ~SE_SELF_RELATIVE);
    GetSecurityDescriptorDacl(Sd, &Present, &Acl, &Defaulted);
    n += DumpAcl(Out + n, Acl, Present);
    n += sprintf(Out + n, " S");
    GetSecurityDescriptorSacl(Sd, &Present, &Acl, &Defaulted);
    DumpAcl(Out + n, Acl, Present);
}

START_TEST(SetPrivateObjectSecurityEx)
{
    GENERIC_MAPPING Mapping = { 0x20001, 0x20002, 0x20004, 0x1F00FF };
    HANDLE Token;
    ULONG i;
    char Text[1024];
    BYTE Buffer[4096];
    DWORD Needed;
    BOOL (WINAPI *pSetPrivateObjectSecurityEx)(SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *,
                                               ULONG, PGENERIC_MAPPING, HANDLE);

    /* Resolved at run time: a system without the export fails this test instead of the program not starting */
    pSetPrivateObjectSecurityEx = (PVOID)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "SetPrivateObjectSecurityEx");
    ok(pSetPrivateObjectSecurityEx != NULL, "SetPrivateObjectSecurityEx is not exported by advapi32\n");
    if (!pSetPrivateObjectSecurityEx)
        return;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Token))
    {
        skip("OpenProcessToken: %lu\n", GetLastError());
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(Rows); i++)
    {
        SECURITY_DESCRIPTOR Creator, Mod;
        PSECURITY_DESCRIPTOR Object = NULL;
        PACL CreatorDacl = MakeAcl(&Starts[Rows[i].Start][0]), CreatorSacl = MakeAcl(&Starts[Rows[i].Start][1]);
        PACL ModDacl = MakeAcl(&Mods[Rows[i].Mod][0]), ModSacl = MakeAcl(&Mods[Rows[i].Mod][1]);
        BOOL Ok;

        InitializeSecurityDescriptor(&Creator, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorOwner(&Creator, Sid(1), FALSE);
        SetSecurityDescriptorGroup(&Creator, Sid(1), FALSE);
        SetSecurityDescriptorDacl(&Creator, TRUE, CreatorDacl, FALSE);
        SetSecurityDescriptorSacl(&Creator, TRUE, CreatorSacl, FALSE);
        ok(CreatePrivateObjectSecurity(NULL, &Creator, &Object, FALSE, Token, &Mapping),
           "row %lu: CreatePrivateObjectSecurity: %lu\n", i, GetLastError());

        InitializeSecurityDescriptor(&Mod, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorOwner(&Mod, Sid(1), FALSE);
        SetSecurityDescriptorGroup(&Mod, Sid(1), FALSE);
        SetSecurityDescriptorDacl(&Mod, TRUE, ModDacl, FALSE);
        SetSecurityDescriptorSacl(&Mod, TRUE, ModSacl, FALSE);
        if (Rows[i].Control)
            SetSecurityDescriptorControl(&Mod, (SECURITY_DESCRIPTOR_CONTROL)Rows[i].Control,
                                         (SECURITY_DESCRIPTOR_CONTROL)Rows[i].Control);

        if (Object)
        {
            Ok = pSetPrivateObjectSecurityEx(DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, &Mod, &Object,
                                             Rows[i].Flags, &Mapping, Token);
            ok(Ok, "row %lu: SetPrivateObjectSecurityEx: %lu\n", i, GetLastError());
            Text[0] = 0;
            if (Object && GetPrivateObjectSecurity(Object, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                                   DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
                                                   Buffer, sizeof(Buffer), &Needed))
                Dump(Text, Buffer);
            ok(!strcmp(Text, Rows[i].Expected), "row %lu (start %d mod %d control %04lx flags %02lx):\n got  %s\n want %s\n",
               i, Rows[i].Start, Rows[i].Mod, Rows[i].Control, Rows[i].Flags, Text, Rows[i].Expected);
            DestroyPrivateObjectSecurity(&Object);
        }
        LocalFree(CreatorDacl);
        LocalFree(CreatorSacl);
        LocalFree(ModDacl);
        LocalFree(ModSacl);
    }

    CloseHandle(Token);
}
