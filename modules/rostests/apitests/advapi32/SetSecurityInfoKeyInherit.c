/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SetSecurityInfo(SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION) is an auto-inherit request,
 *              as on Windows 10 22H2: the DACL of the key keeps the ACEs of the caller (flags 0x03)
 *              followed by the inheritable ACEs of the parent (flags 0x13), its control is 0x8404
 *              (SE_DACL_AUTO_INHERITED), the change is propagated to the existing subkeys, and keys
 *              created below carry only inherited ACEs. A key nobody set the DACL of reports the
 *              ACEs it inherited as inherited too.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Writes only a scratch key (and three subkeys) under HKCU\Software, deleted at the end.
 */

#include "precomp.h"
#include <aclapi.h>
#include <sddl.h>

#define CONTROL_MASK (SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_DACL_AUTO_INHERIT_REQ | SE_SELF_RELATIVE)
#define AUTO_CONTROL (SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED | SE_SELF_RELATIVE)
#define EXPLICIT_FLAGS (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
#define INHERITED_FLAGS (EXPLICIT_FLAGS | INHERITED_ACE)

static const WCHAR ScratchPath[] = L"Software\\ReactOS-apitest-SetSecurityInfoKeyInherit";

static LSTATUS (WINAPI *pRegDeleteTreeW)(HKEY, LPCWSTR);
#define RegDeleteTreeW pRegDeleteTreeW

typedef struct _ACE_INFO
{
    UCHAR Type;
    UCHAR Flags;
    ACCESS_MASK Mask;
    PSID Sid;
} ACE_INFO;

typedef struct _KEY_DACL
{
    PSECURITY_DESCRIPTOR Sd;
    WORD Control;
    ULONG Count;
    ACE_INFO Aces[64];
    BOOL Ok;
} KEY_DACL;

static void ReadDacl(HKEY Key, KEY_DACL *Out)
{
    PACL Dacl = NULL;
    ULONG i;

    ZeroMemory(Out, sizeof(*Out));
    ok_long(GetSecurityInfo(Key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                            NULL, NULL, &Dacl, NULL, &Out->Sd), ERROR_SUCCESS);
    if (!Out->Sd || !Dacl)
        return;
    Out->Control = *(WORD *)((PUCHAR)Out->Sd + 2) & CONTROL_MASK;
    Out->Count = min(Dacl->AceCount, ARRAYSIZE(Out->Aces));
    for (i = 0; i < Out->Count; i++)
    {
        ACCESS_ALLOWED_ACE *Ace;

        if (!GetAce(Dacl, i, (PVOID *)&Ace))
            return;
        Out->Aces[i].Type = Ace->Header.AceType;
        Out->Aces[i].Flags = Ace->Header.AceFlags;
        Out->Aces[i].Mask = Ace->Mask;
        Out->Aces[i].Sid = (PSID)&Ace->SidStart;
    }
    Out->Ok = TRUE;
}

static void FreeDacl(KEY_DACL *Dacl)
{
    if (Dacl->Sd)
        LocalFree(Dacl->Sd);
    ZeroMemory(Dacl, sizeof(*Dacl));
}

static BOOL AllInherited(const KEY_DACL *Dacl)
{
    ULONG i;

    for (i = 0; i < Dacl->Count; i++)
    {
        if (!(Dacl->Aces[i].Flags & INHERITED_ACE))
            return FALSE;
    }
    return Dacl->Count != 0;
}

/* The number of different ACEs (mask and SID) of an all-allow DACL: a key inherits each of them once */
static ULONG UniqueAces(const KEY_DACL *Dacl)
{
    ULONG i, j, Unique = 0;

    for (i = 0; i < Dacl->Count; i++)
    {
        for (j = 0; j < i; j++)
        {
            if (Dacl->Aces[j].Mask == Dacl->Aces[i].Mask && EqualSid(Dacl->Aces[j].Sid, Dacl->Aces[i].Sid))
                break;
        }
        if (j == i)
            Unique++;
    }
    return Unique;
}

static BOOL HasAce(const KEY_DACL *Dacl, PSID Sid, ACCESS_MASK Mask)
{
    ULONG i;

    for (i = 0; i < Dacl->Count; i++)
    {
        if (Dacl->Aces[i].Mask == Mask && EqualSid(Dacl->Aces[i].Sid, Sid))
            return TRUE;
    }
    return FALSE;
}

static BOOL SetSddlDacl(HKEY Key, SECURITY_INFORMATION Info, PCWSTR Sddl)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    BOOL Present, Defaulted;
    DWORD Error = ERROR_INVALID_DATA;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
    {
        skip("%ls: error %lu\n", Sddl, GetLastError());
        return FALSE;
    }
    if (GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted))
        Error = SetSecurityInfo(Key, SE_REGISTRY_KEY, Info | DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL);
    LocalFree(Sd);
    ok_long(Error, ERROR_SUCCESS);
    return Error == ERROR_SUCCESS;
}

/*
 * What Get-Acl / Set-Acl and the registry permission dialog do: read the DACL by name, add an ACE
 * with SetEntriesInAcl, write it back by name. The inherited ACEs come back as inherited, the new
 * one is explicit and there once, and writing the same DACL again changes nothing.
 */
static void TestNamedRoundTrip(void)
{
    static const WCHAR NamedPath[] = L"CURRENT_USER\\Software\\ReactOS-apitest-SetSecurityInfoKeyInherit";
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL, NewDacl = NULL;
    EXPLICIT_ACCESSW Access;
    KEY_DACL Initial, After, Again;
    PSID Users = NULL;
    HKEY Key = NULL;
    DWORD Error;
    ULONG i, Explicit = 0;

    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &Users);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;
    ReadDacl(Key, &Initial);

    Error = GetNamedSecurityInfoW((LPWSTR)NamedPath, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;

    ZeroMemory(&Access, sizeof(Access));
    Access.grfAccessPermissions = KEY_READ;
    Access.grfAccessMode = GRANT_ACCESS;
    Access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    Access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    Access.Trustee.ptstrName = Users;
    Error = SetEntriesInAclW(1, &Access, Dacl, &NewDacl);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;
    Error = SetNamedSecurityInfoW((LPWSTR)NamedPath, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, NewDacl, NULL);
    ok_long(Error, ERROR_SUCCESS);

    ReadDacl(Key, &After);
    ok_hex(After.Control, AUTO_CONTROL);
    ok(HasAce(&After, Users, KEY_READ), "the new ACE is missing\n");
    for (i = 0; i < After.Count; i++)
    {
        if (!(After.Aces[i].Flags & INHERITED_ACE))
            Explicit++;
    }
    ok(Explicit == 1, "%lu explicit ACEs, expected 1\n", Explicit);
    ok(After.Count == Initial.Count + 1, "%lu ACEs, expected %lu\n", After.Count, Initial.Count + 1);

    /* the same again: what was read goes back, nothing is added or lost */
    LocalFree(Sd);
    Sd = NULL;
    Error = GetNamedSecurityInfoW((LPWSTR)NamedPath, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Error = SetNamedSecurityInfoW((LPWSTR)NamedPath, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL);
        ok_long(Error, ERROR_SUCCESS);
        ReadDacl(Key, &Again);
        ok_hex(Again.Control, AUTO_CONTROL);
        ok(Again.Count == After.Count, "%lu ACEs after writing the same DACL, expected %lu\n", Again.Count, After.Count);
        FreeDacl(&Again);
    }
    FreeDacl(&After);
    FreeDacl(&Initial);

Done:
    if (Sd) LocalFree(Sd);
    if (NewDacl) LocalFree(NewDacl);
    if (Key) RegCloseKey(Key);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (Users) FreeSid(Users);
}

START_TEST(SetSecurityInfoKeyInherit)
{
    pRegDeleteTreeW = (PVOID)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "RegDeleteTreeW");
    if (!pRegDeleteTreeW)
    {
        skip("RegDeleteTreeW is not available\n");
        return;
    }

    TestNamedRoundTrip();

    KEY_DACL Initial, P1, C1a, C1b, P2, C2, G;
    HKEY Key = NULL, Child1 = NULL, Child2 = NULL, Grand = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    PSID Users = NULL, World = NULL;
    DWORD Error;
    ULONG i;

    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &Users);
    AllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &World);

    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;

    /* a key nobody set the DACL of: what it got from its parent is reported as inherited */
    ReadDacl(Key, &Initial);
    ok(Initial.Ok && AllInherited(&Initial), "initial: %lu ACEs, not all inherited\n", Initial.Count);
    for (i = 0; i < Initial.Count; i++)
        ok(Initial.Aces[i].Flags & INHERITED_ACE, "initial ACE %lu: flags 0x%x\n", i, Initial.Aces[i].Flags);
    ok_hex(Initial.Control & SE_DACL_AUTO_INHERITED, 0);

    /* pass 1: the explicit ACEs, then the inherited ones again */
    if (!SetSddlDacl(Key, 0, L"D:(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)(A;OICI;KR;;;WD)"))
        goto Done;
    ReadDacl(Key, &P1);
    ok_hex(P1.Control, AUTO_CONTROL);
    ok(P1.Count == 3 + Initial.Count, "pass 1: %lu ACEs, expected %lu\n", P1.Count, 3 + Initial.Count);
    for (i = 0; i < P1.Count && i < 3; i++)
        ok(P1.Aces[i].Flags == EXPLICIT_FLAGS, "pass 1: ACE %lu has flags 0x%x, expected 0x%x\n", i, P1.Aces[i].Flags, EXPLICIT_FLAGS);
    for (i = 3; i < P1.Count; i++)
    {
        ok(P1.Aces[i].Flags & INHERITED_ACE, "pass 1: ACE %lu has flags 0x%x\n", i, P1.Aces[i].Flags);
        if (i - 3 < Initial.Count)
            ok(P1.Aces[i].Mask == Initial.Aces[i - 3].Mask && EqualSid(P1.Aces[i].Sid, Initial.Aces[i - 3].Sid),
               "pass 1: ACE %lu is not the inherited one it had\n", i);
    }

    /* a key created below has inherited ACEs only */
    Error = RegCreateKeyExW(Key, L"child1", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Child1, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;
    ReadDacl(Child1, &C1a);
    ok_hex(C1a.Control, AUTO_CONTROL);
    ok(AllInherited(&C1a), "child1: %lu ACEs, not all inherited\n", C1a.Count);
    ok(HasAce(&C1a, World, KEY_READ), "child1 has no ACE for Everyone\n");
    /* Windows: 7 ACEs on the parent, 5 on the child (an ACE that the parent has twice is inherited once) */
    ok(C1a.Count == UniqueAces(&P1), "child1: %lu ACEs, expected %lu\n", C1a.Count, UniqueAces(&P1));

    /* pass 2 adds an ACE: the existing child gets it */
    if (!SetSddlDacl(Key, UNPROTECTED_DACL_SECURITY_INFORMATION,
                     L"D:(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)(A;OICI;KR;;;WD)(A;OICI;KR;;;BU)"))
        goto Done;
    ReadDacl(Key, &P2);
    ok_hex(P2.Control, AUTO_CONTROL);
    ok(P2.Count == 4 + Initial.Count, "pass 2: %lu ACEs, expected %lu\n", P2.Count, 4 + Initial.Count);
    for (i = 0; i < P2.Count && i < 4; i++)
        ok(P2.Aces[i].Flags == EXPLICIT_FLAGS, "pass 2: ACE %lu has flags 0x%x\n", i, P2.Aces[i].Flags);
    ReadDacl(Child1, &C1b);
    ok_hex(C1b.Control, AUTO_CONTROL);
    ok(AllInherited(&C1b), "child1 after pass 2: %lu ACEs, not all inherited\n", C1b.Count);
    ok(C1b.Count == C1a.Count + 1, "child1 after pass 2: %lu ACEs, expected %lu\n", C1b.Count, C1a.Count + 1);
    ok(C1b.Count == UniqueAces(&P2), "child1 after pass 2: %lu ACEs, expected %lu\n", C1b.Count, UniqueAces(&P2));
    ok(HasAce(&C1b, Users, KEY_READ) && !HasAce(&C1a, Users, KEY_READ), "the new ACE did not reach child1\n");

    /* new keys: a sibling and a grandchild */
    Error = RegCreateKeyExW(Key, L"child2", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Child2, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        ReadDacl(Child2, &C2);
        ok_hex(C2.Control, AUTO_CONTROL);
        ok(AllInherited(&C2), "child2: %lu ACEs, not all inherited\n", C2.Count);
        ok(C2.Count == C1b.Count, "child2: %lu ACEs, expected %lu\n", C2.Count, C1b.Count);
        FreeDacl(&C2);
    }
    Error = RegCreateKeyExW(Child1, L"grandchild", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Grand, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        ReadDacl(Grand, &G);
        ok_hex(G.Control, AUTO_CONTROL);
        ok(AllInherited(&G), "grandchild: %lu ACEs, not all inherited\n", G.Count);
        ok(G.Count == C1b.Count, "grandchild: %lu ACEs, expected %lu\n", G.Count, C1b.Count);
        FreeDacl(&G);
    }

    /* a protected DACL does not take what the parent passes on */
    if (SetSddlDacl(Key, PROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)"))
    {
        KEY_DACL P3;

        ReadDacl(Key, &P3);
        ok_hex(P3.Control & SE_DACL_PROTECTED, SE_DACL_PROTECTED);
        ok(P3.Count == 2, "protected: %lu ACEs, expected 2\n", P3.Count);
        FreeDacl(&P3);
    }

    FreeDacl(&C1b);
    FreeDacl(&P2);
    FreeDacl(&C1a);
    FreeDacl(&P1);
    FreeDacl(&Initial);

Done:
    if (Grand) RegCloseKey(Grand);
    if (Child2) RegCloseKey(Child2);
    if (Child1) RegCloseKey(Child1);
    if (Key) RegCloseKey(Key);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (Users) FreeSid(Users);
    if (World) FreeSid(World);
}
