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

static BOOL OpenDacl(HKEY Parent, PCWSTR Name, KEY_DACL *Out)
{
    HKEY Key;

    ZeroMemory(Out, sizeof(*Out));
    if (RegOpenKeyExW(Parent, Name, 0, READ_CONTROL, &Key) != ERROR_SUCCESS)
    {
        ok(0, "cannot open %ls\n", Name);
        return FALSE;
    }
    ReadDacl(Key, Out);
    RegCloseKey(Key);
    return Out->Ok;
}

static BOOL MakeKey(HKEY Parent, PCWSTR Name, DWORD Options, HKEY *Key)
{
    DWORD Error = RegCreateKeyExW(Parent, Name, 0, NULL, Options, KEY_ALL_ACCESS, NULL, Key, NULL);

    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        *Key = NULL;
    return Error == ERROR_SUCCESS;
}

/* The target of a link below the scratch key: a key of the user's hive, outside the scratch subtree */
static BOOL MakeLinkTarget(PWSTR Target, ULONG TargetSize, PCWSTR TargetName)
{
    HANDLE Token;
    TOKEN_USER *User = NULL;
    DWORD Size = 0;
    PWSTR SidString = NULL;
    BOOL Ok = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    GetTokenInformation(Token, TokenUser, NULL, 0, &Size);
    User = LocalAlloc(LMEM_FIXED, Size);
    if (User && GetTokenInformation(Token, TokenUser, User, Size, &Size) &&
        ConvertSidToStringSidW(User->User.Sid, &SidString))
    {
        Ok = SUCCEEDED(StringCchPrintfW(Target, TargetSize, L"\\Registry\\User\\%ls\\%ls", SidString, TargetName));
        LocalFree(SidString);
    }
    if (User)
        LocalFree(User);
    CloseHandle(Token);
    return Ok;
}

/*
 * More cases. A DACL set with neither PROTECTED nor UNPROTECTED on a protected key keeps it protected
 * and takes nothing from the parent (Windows is not measured here: VERIFY ON ORACLE; the check is that
 * nothing is widened). A deny ACE is inherited in place. A protected subkey, and what is below it, is not
 * touched. A subkey that cannot be opened does not stop the walk. A link subkey is not followed. A deep
 * tree is walked to its end. Hive roots can be queried.
 */
static void TestExtraCases(void)
{
    static const WCHAR ParentSddl[] = L"D:(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)";
    static const WCHAR ParentSddl2[] = L"D:(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)(A;OICI;KR;;;BU)";
    static const WCHAR TargetName[] = L"Software\\ReactOS-apitest-SetSecurityInfoKeyInherit-target";
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    LONG (WINAPI *pNtDeleteKey)(HANDLE) = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDeleteKey");
    HKEY Key = NULL, Sub = NULL, Link = NULL, Target = NULL, Cur;
    HKEY Prot2 = NULL, Prot2G = NULL, DenyP = NULL, DenyC1 = NULL;
    KEY_DACL D, TargetBefore, TargetAfter;
    PSID Users = NULL;
    WCHAR LinkTarget[300];
    DWORD Error;
    ULONG i, Depth;
    BOOL LinkOk = FALSE, TargetOk = FALSE, Locked = FALSE;
    HKEY Probe;

    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &Users);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    RegDeleteTreeW(HKEY_CURRENT_USER, TargetName);
    if (!MakeKey(HKEY_CURRENT_USER, ScratchPath, 0, &Key))
        goto Done;
    if (!SetSddlDacl(Key, 0, ParentSddl))
        goto Done;

    /* neither flag, protected key: it stays protected and takes nothing from the parent */
    if (MakeKey(Key, L"prot", 0, &Sub))
    {
        if (SetSddlDacl(Sub, PROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)"))
        {
            ReadDacl(Sub, &D);
            ok_hex(D.Control & SE_DACL_PROTECTED, SE_DACL_PROTECTED);
            ok(D.Count == 2, "protected: %lu ACEs, expected 2\n", D.Count);
            FreeDacl(&D);

            if (SetSddlDacl(Sub, 0, L"D:(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)(A;;KR;;;BU)"))
            {
                ReadDacl(Sub, &D);
                ok_hex(D.Control & SE_DACL_PROTECTED, SE_DACL_PROTECTED);
                ok(D.Count == 3, "protected, neither flag: %lu ACEs, expected 3 (nothing from the parent)\n", D.Count);
                for (i = 0; i < D.Count; i++)
                    ok(!(D.Aces[i].Flags & INHERITED_ACE), "protected, neither flag: ACE %lu is inherited\n", i);
                FreeDacl(&D);
            }

            /* UNPROTECTED asks for the parent's ACEs: the key is not protected after it */
            if (SetSddlDacl(Sub, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)(A;;KR;;;BU)"))
            {
                ReadDacl(Sub, &D);
                ok_hex(D.Control & SE_DACL_PROTECTED, 0);
                ok_hex(D.Control & SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERITED);
                FreeDacl(&D);
            }
        }
        RegCloseKey(Sub);
        Sub = NULL;
    }

    /* a protected subkey, and its own subkey, are left alone when the parent changes */
    if (MakeKey(Key, L"prot2", 0, &Prot2) &&
        SetSddlDacl(Prot2, PROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;OICI;KA;;;BA)") &&
        MakeKey(Prot2, L"g", 0, &Prot2G))
    {
        ReadDacl(Prot2G, &D);
        ok(D.Count == 1, "below the protected key: %lu ACEs, expected 1\n", D.Count);
        FreeDacl(&D);
    }

    /* a deny ACE is inherited in place, by the existing subkey and by a new one */
    if (MakeKey(Key, L"denyp", 0, &DenyP) && MakeKey(DenyP, L"c1", 0, &DenyC1) &&
        SetSddlDacl(DenyP, UNPROTECTED_DACL_SECURITY_INFORMATION,
                    L"D:(D;OICI;KW;;;BU)(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)"))
    {
        HKEY C2 = NULL;

        ReadDacl(DenyC1, &D);
        ok(D.Count >= 3, "deny: existing subkey has %lu ACEs\n", D.Count);
        ok(D.Count && D.Aces[0].Type == ACCESS_DENIED_ACE_TYPE, "deny: first ACE of the existing subkey has type %u\n", D.Aces[0].Type);
        ok(D.Count && D.Aces[0].Flags == INHERITED_FLAGS, "deny: flags 0x%x, expected 0x%x\n", D.Aces[0].Flags, INHERITED_FLAGS);
        FreeDacl(&D);
        if (MakeKey(DenyP, L"c2", 0, &C2))
        {
            ReadDacl(C2, &D);
            ok(D.Count >= 3, "deny: new subkey has %lu ACEs\n", D.Count);
            ok(D.Count && D.Aces[0].Type == ACCESS_DENIED_ACE_TYPE, "deny: first ACE of the new subkey has type %u\n", D.Aces[0].Type);
            ok(D.Count && D.Aces[0].Flags == INHERITED_FLAGS, "deny: flags 0x%x, expected 0x%x\n", D.Aces[0].Flags, INHERITED_FLAGS);
            FreeDacl(&D);
            RegCloseKey(C2);
        }
    }

    /* a subkey that cannot be opened for WRITE_DAC: the siblings around it still get the change */
    if (MakeKey(Key, L"a-before", 0, &Sub))
        RegCloseKey(Sub);
    if (MakeKey(Key, L"z-after", 0, &Sub))
        RegCloseKey(Sub);
    if (MakeKey(Key, L"locked", 0, &Sub))
    {
        /* owner rights given explicitly: the owner's implicit READ_CONTROL | WRITE_DAC is gone */
        SetSddlDacl(Sub, PROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;;RCSD;;;OW)(A;;KR;;;BA)(A;;SD;;;BA)");
        RegCloseKey(Sub);
        Sub = NULL;
        if (RegOpenKeyExW(Key, L"locked", 0, WRITE_DAC, &Probe) == ERROR_SUCCESS)
            RegCloseKey(Probe);
        else
            Locked = TRUE;
    }

    /* a link subkey: the key it points to is not changed */
    TargetOk = MakeKey(HKEY_CURRENT_USER, TargetName, 0, &Target);
    if (TargetOk)
    {
        ReadDacl(Target, &TargetBefore);
        if (MakeLinkTarget(LinkTarget, ARRAYSIZE(LinkTarget), TargetName) &&
            MakeKey(Key, L"lnk", REG_OPTION_CREATE_LINK, &Link))
        {
            LONG Err = RegSetValueExW(Link, L"SymbolicLinkValue", 0, REG_LINK, (const BYTE *)LinkTarget,
                                      lstrlenW(LinkTarget) * sizeof(WCHAR));
            ok_long(Err, ERROR_SUCCESS);
            LinkOk = Err == ERROR_SUCCESS;
            RegCloseKey(Link);
            Link = NULL;
        }
    }

    /* a deep tree */
    Cur = Key;
    for (Depth = 0; Depth < 150; Depth++)
    {
        HKEY Next;

        if (!MakeKey(Cur, L"d", 0, &Next))
            break;
        if (Cur != Key)
            RegCloseKey(Cur);
        Cur = Next;
    }
    if (Cur != Key)
        RegCloseKey(Cur);

    /* the change */
    if (!SetSddlDacl(Key, UNPROTECTED_DACL_SECURITY_INFORMATION, ParentSddl2))
        goto Done;

    if (Prot2 && Prot2G)
    {
        ReadDacl(Prot2, &D);
        ok(D.Count == 1 && !HasAce(&D, Users, KEY_READ), "protected subkey changed: %lu ACEs\n", D.Count);
        FreeDacl(&D);
        ReadDacl(Prot2G, &D);
        ok(D.Count == 1 && !HasAce(&D, Users, KEY_READ), "below the protected subkey changed: %lu ACEs\n", D.Count);
        FreeDacl(&D);
    }

    if (OpenDacl(Key, L"a-before", &D))
    {
        ok(HasAce(&D, Users, KEY_READ), "a-before did not get the change\n");
        FreeDacl(&D);
    }
    if (OpenDacl(Key, L"z-after", &D))
    {
        ok(HasAce(&D, Users, KEY_READ), "z-after (after the subkey that cannot be opened) did not get the change\n");
        FreeDacl(&D);
    }
    if (!Locked)
        skip("the owner keeps WRITE_DAC here: no subkey that cannot be opened\n");

    if (TargetOk)
    {
        if (LinkOk)
        {
            if (OpenDacl(HKEY_CURRENT_USER, TargetName, &TargetAfter))
            {
                ok(TargetAfter.Count == TargetBefore.Count && TargetAfter.Control == TargetBefore.Control &&
                   !HasAce(&TargetAfter, Users, KEY_READ),
                   "the key behind the link changed: %lu ACEs, was %lu\n", TargetAfter.Count, TargetBefore.Count);
                FreeDacl(&TargetAfter);
            }
        }
        else
            skip("no link key\n");
        FreeDacl(&TargetBefore);
    }
    /* the link is removed itself, not through the key it points to */
    if (LinkOk && pNtDeleteKey &&
        RegOpenKeyExW(Key, L"lnk", REG_OPTION_OPEN_LINK, DELETE, &Link) == ERROR_SUCCESS)
    {
        pNtDeleteKey(Link);
        RegCloseKey(Link);
        Link = NULL;
    }

    /* the deepest key, opened level by level (a path of 150 names is long) */
    if (Depth == 150)
    {
        Cur = Key;
        for (i = 0; i < 150; i++)
        {
            HKEY Next;

            Error = RegOpenKeyExW(Cur, L"d", 0, READ_CONTROL | KEY_ENUMERATE_SUB_KEYS, &Next);
            ok_long(Error, ERROR_SUCCESS);
            if (Cur != Key)
                RegCloseKey(Cur);
            Cur = Next;
            if (Error)
                break;
        }
        if (i == 150)
        {
            ReadDacl(Cur, &D);
            ok(HasAce(&D, Users, KEY_READ), "the deepest of 150 subkeys did not get the change\n");
            FreeDacl(&D);
            RegCloseKey(Cur);
        }
    }

    /* hive roots (and the keys below them) can be queried; no change is made to them */
    if (OpenDacl(HKEY_CURRENT_USER, L"", &D))
    {
        ok(D.Count != 0, "HKCU root has no ACEs\n");
        FreeDacl(&D);
    }
    if (OpenDacl(HKEY_LOCAL_MACHINE, L"SOFTWARE", &D))
    {
        ok(D.Count != 0, "HKLM\\SOFTWARE has no ACEs\n");
        FreeDacl(&D);
    }

Done:
    if (Prot2G) RegCloseKey(Prot2G);
    if (Prot2) RegCloseKey(Prot2);
    if (DenyC1) RegCloseKey(DenyC1);
    if (DenyP) RegCloseKey(DenyP);
    if (Target) RegCloseKey(Target);
    if (Key) RegCloseKey(Key);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    RegDeleteTreeW(HKEY_CURRENT_USER, TargetName);
    if (Users) FreeSid(Users);
}

/*
 * A parent that holds an ACE twice (an explicit one equal to one it inherits, then more distinct ACEs
 * after it): a key created below inherits everything, in a valid ACL, none of the ACEs is lost.
 */
static void TestDuplicateParent(void)
{
    KEY_DACL Initial, Parent, Child, Grand;
    UCHAR AclBuffer[2048];
    PACL Explicit = (PACL)AclBuffer, ChildDacl = NULL;
    HKEY Key = NULL, ChildKey = NULL, GrandKey = NULL;
    BOOL Present, Defaulted;
    DWORD Error;
    ULONG i;

    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        return;

    ReadDacl(Key, &Initial);
    ok(Initial.Ok && Initial.Count >= 2, "initial: %lu ACEs\n", Initial.Count);
    if (!Initial.Ok)
        goto Done;

    /* the explicit ACEs repeat every ACE the key inherits */
    InitializeAcl(Explicit, sizeof(AclBuffer), ACL_REVISION);
    for (i = 0; i < Initial.Count; i++)
    {
        if (Initial.Aces[i].Type == ACCESS_ALLOWED_ACE_TYPE)
            ok(AddAccessAllowedAceEx(Explicit, ACL_REVISION, Initial.Aces[i].Flags & ~INHERITED_ACE,
                                     Initial.Aces[i].Mask, Initial.Aces[i].Sid), "AddAccessAllowedAceEx %lu\n", i);
    }
    Error = SetSecurityInfo(Key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, Explicit, NULL);
    ok_long(Error, ERROR_SUCCESS);

    ReadDacl(Key, &Parent);
    ok(Parent.Ok, "parent not readable\n");
    ok(Parent.Count == Explicit->AceCount + Initial.Count, "parent: %lu ACEs, expected %lu\n",
       Parent.Count, Explicit->AceCount + Initial.Count);
    for (i = 0; i < Parent.Count && i < Explicit->AceCount; i++)
        ok(!(Parent.Aces[i].Flags & INHERITED_ACE), "parent: ACE %lu is inherited, explicit ACEs come first\n", i);
    for (i = Explicit->AceCount; i < Parent.Count; i++)
        ok(Parent.Aces[i].Flags & INHERITED_ACE, "parent: ACE %lu is not inherited\n", i);

    Error = RegCreateKeyExW(Key, L"child", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &ChildKey, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done1;
    ReadDacl(ChildKey, &Child);
    ok(Child.Ok, "the DACL of the new key cannot be read\n");
    ok_hex(Child.Control, AUTO_CONTROL);
    ok(AllInherited(&Child), "child: %lu ACEs, not all inherited\n", Child.Count);
    ok(Child.Count == Parent.Count, "child: %lu ACEs, expected %lu\n", Child.Count, Parent.Count);
    for (i = 0; i < Parent.Count; i++)
        ok(HasAce(&Child, Parent.Aces[i].Sid, Parent.Aces[i].Mask), "child lacks the ACE %lu of its parent\n", i);
    ok(Child.Sd && GetSecurityDescriptorDacl(Child.Sd, &Present, &ChildDacl, &Defaulted) && Present &&
       ChildDacl && IsValidAcl(ChildDacl), "the DACL of the new key is not a valid ACL\n");

    Error = RegCreateKeyExW(ChildKey, L"grandchild", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &GrandKey, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        ReadDacl(GrandKey, &Grand);
        ok(Grand.Ok && AllInherited(&Grand), "grandchild: %lu ACEs\n", Grand.Count);
        ok(Grand.Count == Child.Count, "grandchild: %lu ACEs, expected %lu\n", Grand.Count, Child.Count);
        FreeDacl(&Grand);
        RegCloseKey(GrandKey);
    }

    FreeDacl(&Child);
    RegCloseKey(ChildKey);
Done1:
    FreeDacl(&Parent);
Done:
    FreeDacl(&Initial);
    RegCloseKey(Key);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
}

/*
 * "Disable inheritance, keep the inherited ACEs": the DACL as read goes back with PROTECTED. The ACEs that
 * were inherited are explicit then, none is lost. A protected DACL without them is the DACL that is set.
 */
static void TestProtectKeepsAces(void)
{
    static const WCHAR NamedGrand[] = L"CURRENT_USER\\Software\\ReactOS-apitest-SetSecurityInfoKeyInherit\\grand";
    KEY_DACL Before, After, Only;
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    HKEY Key = NULL, Child = NULL, Grand = NULL;
    DWORD Error;
    ULONG i;

    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        return;
    if (!SetSddlDacl(Key, 0, L"D:(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)(A;OICI;KR;;;WD)"))
        goto Done;
    if (!MakeKey(Key, L"child", 0, &Child) || !MakeKey(Key, L"grand", 0, &Grand))
        goto Done;

    /* by handle */
    ReadDacl(Child, &Before);
    ok(AllInherited(&Before), "child: %lu ACEs, not all inherited\n", Before.Count);
    Error = GetSecurityInfo(Child, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Error = SetSecurityInfo(Child, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, Dacl, NULL);
        ok_long(Error, ERROR_SUCCESS);
        LocalFree(Sd);
        Sd = NULL;
    }
    ReadDacl(Child, &After);
    ok_hex(After.Control & SE_DACL_PROTECTED, SE_DACL_PROTECTED);
    ok(After.Count == Before.Count, "protected: %lu ACEs, expected %lu\n", After.Count, Before.Count);
    for (i = 0; i < After.Count && i < Before.Count; i++)
    {
        ok(!(After.Aces[i].Flags & INHERITED_ACE), "protected: ACE %lu is still flagged inherited\n", i);
        ok(After.Aces[i].Mask == Before.Aces[i].Mask && EqualSid(After.Aces[i].Sid, Before.Aces[i].Sid),
           "protected: ACE %lu changed\n", i);
    }
    FreeDacl(&After);
    FreeDacl(&Before);

    /* by name, a second subkey of the same parent */
    ReadDacl(Grand, &Before);
    Error = GetNamedSecurityInfoW((LPWSTR)NamedGrand, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Error = SetNamedSecurityInfoW((LPWSTR)NamedGrand, SE_REGISTRY_KEY,
                                      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                      NULL, NULL, Dacl, NULL);
        ok_long(Error, ERROR_SUCCESS);
        LocalFree(Sd);
        Sd = NULL;
    }
    ReadDacl(Grand, &After);
    ok_hex(After.Control & SE_DACL_PROTECTED, SE_DACL_PROTECTED);
    ok(After.Count == Before.Count, "protected by name: %lu ACEs, expected %lu\n", After.Count, Before.Count);
    for (i = 0; i < After.Count; i++)
        ok(!(After.Aces[i].Flags & INHERITED_ACE), "protected by name: ACE %lu is flagged inherited\n", i);
    FreeDacl(&After);
    FreeDacl(&Before);

    /* a protected DACL that does not have them is what is set */
    if (SetSddlDacl(Grand, PROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;;KA;;;BA)"))
    {
        ReadDacl(Grand, &Only);
        ok_hex(Only.Control & SE_DACL_PROTECTED, SE_DACL_PROTECTED);
        ok(Only.Count == 1, "protected, one ACE: %lu ACEs\n", Only.Count);
        ok(Only.Count && !(Only.Aces[0].Flags & INHERITED_ACE), "the ACE is flagged inherited\n");
        FreeDacl(&Only);
    }

Done:
    if (Grand) RegCloseKey(Grand);
    if (Child) RegCloseKey(Child);
    RegCloseKey(Key);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
}

/* a plain RegSetKeySecurity: what a legacy writer does, no auto-inheritance */
static BOOL RawSetSddl(HKEY Parent, PCWSTR Name, PCWSTR Sddl)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    HKEY Key;
    DWORD Error;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
    {
        skip("%ls: error %lu\n", Sddl, GetLastError());
        return FALSE;
    }
    Error = RegOpenKeyExW(Parent, Name, 0, WRITE_DAC, &Key);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Error = RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, Sd);
        ok_long(Error, ERROR_SUCCESS);
        RegCloseKey(Key);
    }
    LocalFree(Sd);
    return Error == ERROR_SUCCESS;
}

/* the stored descriptor, as it is */
static DWORD RawGet(HKEY Parent, PCWSTR Name, PVOID Buffer, DWORD Size)
{
    HKEY Key;
    DWORD Length = Size;

    if (RegOpenKeyExW(Parent, Name, 0, READ_CONTROL, &Key) != ERROR_SUCCESS)
    {
        ok(0, "cannot open %ls\n", Name);
        return 0;
    }
    if (RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, Buffer, &Length) != ERROR_SUCCESS)
        Length = 0;
    RegCloseKey(Key);
    return Length;
}

/* what the permission dialog does to the parent: add Everyone read (inherited by subkeys), by name */
static void AddEveryoneRead(void)
{
    static const WCHAR NamedPath[] = L"CURRENT_USER\\Software\\ReactOS-apitest-SetSecurityInfoKeyInherit";
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL, NewDacl = NULL;
    EXPLICIT_ACCESSW Access;
    PSID World = NULL;
    DWORD Error;

    AllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &World);
    Error = GetNamedSecurityInfoW((LPWSTR)NamedPath, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        ZeroMemory(&Access, sizeof(Access));
        Access.grfAccessPermissions = KEY_READ;
        Access.grfAccessMode = GRANT_ACCESS;
        Access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        Access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        Access.Trustee.ptstrName = World;
        Error = SetEntriesInAclW(1, &Access, Dacl, &NewDacl);
        ok_long(Error, ERROR_SUCCESS);
        if (!Error)
        {
            Error = SetNamedSecurityInfoW((LPWSTR)NamedPath, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, NewDacl, NULL);
            ok_long(Error, ERROR_SUCCESS);
        }
    }
    if (NewDacl) LocalFree(NewDacl);
    if (Sd) LocalFree(Sd);
    if (World) FreeSid(World);
}

/* the position of the first ACE of the type for the SID in the DACL, -1 if there is none */
static LONG FindAce(const KEY_DACL *Dacl, UCHAR Type, PSID Sid)
{
    ULONG i;

    for (i = 0; i < Dacl->Count; i++)
    {
        if (Dacl->Aces[i].Type == Type && EqualSid(Dacl->Aces[i].Sid, Sid))
            return (LONG)i;
    }
    return -1;
}

/*
 * A subkey is only brought up to date if its DACL really is auto-inherited, or ends in exactly the ACEs
 * the parent passed on, after all its explicit ACEs. Anything else is the owner's own DACL and a change of
 * the parent must not touch it, and no round trip may put an allow ACE ahead of a deny ACE:
 *  W1  explicit deny/allow order of a legacy writer, parent changed: the stored descriptor stays as it was
 *  W2  the same key, read and written back by itself: the deny still comes before the allow
 *  W3  an explicit empty DACL, parent changed: it stays empty
 *      explicit ACE before the inherited tail: still updated, the explicit ACE stays first
 *      a DACL that is not valid is refused, not read past its end
 * W1-W3 are the shapes an earlier version got wrong (NETWORK got KEY_WRITE; an empty DACL got
 * Everyone read).
 */
static void TestNoWidening(void)
{
    static const WCHAR NamedChild2[] = L"CURRENT_USER\\Software\\ReactOS-apitest-SetSecurityInfoKeyInherit\\c2";
    static const WCHAR ParentSddl[] = L"D:(D;CI;KW;;;NU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CIIO;KA;;;CO)";
    static const WCHAR Legacy[] = L"D:(D;CI;KW;;;NU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;;KA;;;NU)";
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    SECURITY_ATTRIBUTES Attributes = {sizeof(Attributes), NULL, FALSE};
    BYTE Before[2048], After[2048];
    KEY_DACL Dacl;
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Old = NULL;
    PSID Network = NULL, World = NULL, Users = NULL;
    HKEY Key = NULL, Child = NULL;
    DWORD Error, BeforeSize, AfterSize;
    LONG Deny, Allow;

    AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_NETWORK_RID, 0, 0, 0, 0, 0, 0, 0, &Network);
    AllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &World);
    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &Users);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(ParentSddl, SDDL_REVISION_1, &Attributes.lpSecurityDescriptor, NULL))
    {
        skip("cannot make the parent descriptor: %lu\n", GetLastError());
        goto Done;
    }
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, &Attributes, &Key, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;

    if (!MakeKey(Key, L"c1", 0, &Child))   /* W1 */
        goto Done;
    RegCloseKey(Child);
    if (!MakeKey(Key, L"c2", 0, &Child))   /* W2 */
        goto Done;
    RegCloseKey(Child);
    if (!MakeKey(Key, L"c3", 0, &Child))   /* W3 */
        goto Done;
    RegCloseKey(Child);
    if (!MakeKey(Key, L"c4", 0, &Child))   /* explicit ACE first, inherited tail */
        goto Done;
    RegCloseKey(Child);
    Child = NULL;

    if (!RawSetSddl(Key, L"c1", Legacy) || !RawSetSddl(Key, L"c2", Legacy) || !RawSetSddl(Key, L"c3", L"D:"))
        goto Done;
    BeforeSize = RawGet(Key, L"c1", Before, sizeof(Before));
    ok(BeforeSize != 0, "cannot read c1\n");

    /* W2: a round trip of the key alone */
    Error = GetNamedSecurityInfoW((LPWSTR)NamedChild2, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &Old, NULL, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Error = SetNamedSecurityInfoW((LPWSTR)NamedChild2, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, Old, NULL);
        ok_long(Error, ERROR_SUCCESS);
        LocalFree(Sd);
    }
    ok(OpenDacl(Key, L"c2", &Dacl), "cannot read c2\n");
    Deny = FindAce(&Dacl, ACCESS_DENIED_ACE_TYPE, Network);
    Allow = FindAce(&Dacl, ACCESS_ALLOWED_ACE_TYPE, Network);
    ok(Deny >= 0 && Dacl.Aces[Deny].Mask == KEY_WRITE, "W2: the deny ACE for NETWORK is gone\n");
    ok(Allow < 0 || Deny < Allow, "W2: the allow ACE for NETWORK (%ld) is ahead of the deny ACE (%ld)\n", Allow, Deny);
    FreeDacl(&Dacl);

    /* W1, W3 and the explicit-first key: the parent changes */
    if (!RawSetSddl(Key, L"c4", L"D:(A;;KR;;;NU)(D;CI;KW;;;NU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CIID;KA;;;BA)"))
        goto Done;
    AddEveryoneRead();

    AfterSize = RawGet(Key, L"c1", After, sizeof(After));
    ok(AfterSize == BeforeSize && !memcmp(Before, After, BeforeSize), "W1: the descriptor of c1 changed (%lu, %lu bytes)\n", BeforeSize, AfterSize);
    ok(OpenDacl(Key, L"c1", &Dacl), "cannot read c1\n");
    Deny = FindAce(&Dacl, ACCESS_DENIED_ACE_TYPE, Network);
    Allow = FindAce(&Dacl, ACCESS_ALLOWED_ACE_TYPE, Network);
    ok(Deny >= 0 && Allow > Deny, "W1: deny at %ld, allow at %ld\n", Deny, Allow);
    ok(FindAce(&Dacl, ACCESS_ALLOWED_ACE_TYPE, World) < 0, "W1: c1 got an ACE for Everyone\n");
    FreeDacl(&Dacl);

    ok(OpenDacl(Key, L"c3", &Dacl), "cannot read c3\n");
    ok(Dacl.Count == 0, "W3: the empty DACL of c3 has %lu ACEs\n", Dacl.Count);
    ok_hex(Dacl.Control & SE_DACL_AUTO_INHERITED, 0);
    FreeDacl(&Dacl);

    /* the key is not auto-inherited and does not end in what the parent passed on either (its last ACE is not the parent's) */
    ok(OpenDacl(Key, L"c4", &Dacl), "cannot read c4\n");
    ok(FindAce(&Dacl, ACCESS_ALLOWED_ACE_TYPE, World) < 0, "c4 (not a tail of the parent's ACEs) got an ACE for Everyone\n");
    FreeDacl(&Dacl);

    /* a malformed ACL (more ACEs than its size holds) is refused, and read nowhere past its end */
    {
        union { ACL Header; BYTE Bytes[64]; } Bad;

        ZeroMemory(&Bad, sizeof(Bad));
        Bad.Header.AclRevision = ACL_REVISION;
        Bad.Header.AclSize = sizeof(ACL);
        Bad.Header.AceCount = 5;
        Error = SetSecurityInfo(Key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, &Bad.Header, NULL);
        ok(Error != ERROR_SUCCESS, "a malformed protected DACL was accepted\n");
        Error = SetSecurityInfo(Key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &Bad.Header, NULL);
        ok(Error != ERROR_SUCCESS, "a malformed DACL was accepted\n");
    }

Done:
    if (Attributes.lpSecurityDescriptor) LocalFree(Attributes.lpSecurityDescriptor);
    if (Key) RegCloseKey(Key);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (Network) FreeSid(Network);
    if (World) FreeSid(World);
    if (Users) FreeSid(Users);
}

/*
 * An explicit ACE before an inherited tail: the key is updated, the explicit ACE stays first.
 * The parent here is a plain key whose DACL was set before any subkey existed.
 */
static void TestExplicitBeforeTail(void)
{
    static const WCHAR ParentSddl[] = L"D:(A;CI;KR;;;SY)(A;CI;KA;;;BA)";
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    SECURITY_ATTRIBUTES Attributes = {sizeof(Attributes), NULL, FALSE};
    KEY_DACL Dacl;
    PSID Network = NULL, World = NULL;
    HKEY Key = NULL, Child = NULL;
    DWORD Error;

    AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_NETWORK_RID, 0, 0, 0, 0, 0, 0, 0, &Network);
    AllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &World);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(ParentSddl, SDDL_REVISION_1, &Attributes.lpSecurityDescriptor, NULL))
    {
        skip("cannot make the parent descriptor: %lu\n", GetLastError());
        goto Done;
    }
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, &Attributes, &Key, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error || !MakeKey(Key, L"c", 0, &Child))
        goto Done;
    RegCloseKey(Child);
    Child = NULL;

    /* the key's own ACE first, then exactly the ACEs the parent passes on (a legacy writer's DACL) */
    if (!RawSetSddl(Key, L"c", L"D:(A;;KR;;;NU)(A;CI;KR;;;SY)(A;CI;KA;;;BA)"))
        goto Done;
    /* reported: the tail inherited, the first ACE explicit */
    ok(OpenDacl(Key, L"c", &Dacl), "cannot read c\n");
    ok(Dacl.Count == 3, "c has %lu ACEs\n", Dacl.Count);
    if (Dacl.Count == 3)
    {
        ok(!(Dacl.Aces[0].Flags & INHERITED_ACE), "the explicit ACE is reported inherited\n");
        ok((Dacl.Aces[1].Flags & INHERITED_ACE) && (Dacl.Aces[2].Flags & INHERITED_ACE), "the tail is not reported inherited\n");
    }
    FreeDacl(&Dacl);

    AddEveryoneRead();
    ok(OpenDacl(Key, L"c", &Dacl), "cannot read c\n");
    ok(FindAce(&Dacl, ACCESS_ALLOWED_ACE_TYPE, World) >= 0, "c did not get the new ACE\n");
    ok(Dacl.Count && Dacl.Aces[0].Mask == KEY_READ && EqualSid(Dacl.Aces[0].Sid, Network) && !(Dacl.Aces[0].Flags & INHERITED_ACE),
       "the explicit ACE is not first\n");
    FreeDacl(&Dacl);

Done:
    if (Attributes.lpSecurityDescriptor) LocalFree(Attributes.lpSecurityDescriptor);
    if (Key) RegCloseKey(Key);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (Network) FreeSid(Network);
    if (World) FreeSid(World);
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
    TestExtraCases();
    TestDuplicateParent();
    TestProtectKeepsAces();
    TestNoWidening();
    TestExplicitBeforeTail();

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
    /* every inheritable ACE of the parent is inherited, one that it has twice too (measured raw on Windows) */
    ok(C1a.Count == P1.Count, "child1: %lu ACEs, expected %lu\n", C1a.Count, P1.Count);

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
    ok(C1b.Count == P2.Count, "child1 after pass 2: %lu ACEs, expected %lu\n", C1b.Count, P2.Count);
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
