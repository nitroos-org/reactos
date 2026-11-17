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
 * A subkey is only brought up to date if its DACL is auto-inherited or carries an ACE flagged inherited. Anything
 * else is the owner's own DACL and a change of the parent must not touch its ACEs (it is only flagged protected +
 * auto-inherited), and no round trip may put an allow ACE ahead of a deny ACE:
 *  W1  explicit deny/allow order of a legacy writer, parent changed: the ACEs stay as they were (control 0x9404)
 *  W2  the same key, read and written back by itself: the deny still comes before the allow
 *  W3  an explicit empty DACL, parent changed: it stays empty
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
    /* the ACEs stay as they are; the key is only flagged protected + auto-inherited (the control word, offset 2) */
    ok(AfterSize == BeforeSize && !memcmp(Before, After, 2) && !memcmp(Before + 4, After + 4, BeforeSize - 4),
       "W1: the descriptor of c1 changed beyond its control (%lu, %lu bytes)\n", BeforeSize, AfterSize);
    ok_hex(*(WORD *)(After + 2) & CONTROL_MASK, SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SELF_RELATIVE);
    ok(OpenDacl(Key, L"c1", &Dacl), "cannot read c1\n");
    Deny = FindAce(&Dacl, ACCESS_DENIED_ACE_TYPE, Network);
    Allow = FindAce(&Dacl, ACCESS_ALLOWED_ACE_TYPE, Network);
    ok(Deny >= 0 && Allow > Deny, "W1: deny at %ld, allow at %ld\n", Deny, Allow);
    ok(FindAce(&Dacl, ACCESS_ALLOWED_ACE_TYPE, World) < 0, "W1: c1 got an ACE for Everyone\n");
    FreeDacl(&Dacl);

    ok(OpenDacl(Key, L"c3", &Dacl), "cannot read c3\n");
    ok(Dacl.Count == 0, "W3: the empty DACL of c3 has %lu ACEs\n", Dacl.Count);
    ok_hex(Dacl.Control, SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SELF_RELATIVE);
    FreeDacl(&Dacl);

    /*
     * The key is not auto-inherited, but one of its ACEs is flagged inherited: as on Windows (W6b, measured) it is
     * updated like an auto-inherited key. Its explicit ACEs stay first and in their order, the ACE flagged
     * inherited is replaced by what the parent passes on.
     */
    ok(OpenDacl(Key, L"c4", &Dacl), "cannot read c4\n");
    ok_hex(Dacl.Control, AUTO_CONTROL);
    Allow = FindAce(&Dacl, ACCESS_ALLOWED_ACE_TYPE, World);
    ok(Allow >= 4 && (Dacl.Aces[Allow].Flags & INHERITED_ACE), "c4: the ACE for Everyone is at %ld\n", Allow);
    ok(Dacl.Count >= 4 && Dacl.Aces[0].Type == ACCESS_ALLOWED_ACE_TYPE && Dacl.Aces[0].Flags == 0 &&
       EqualSid(Dacl.Aces[0].Sid, Network) && Dacl.Aces[1].Type == ACCESS_DENIED_ACE_TYPE &&
       Dacl.Aces[1].Flags == CONTAINER_INHERIT_ACE && EqualSid(Dacl.Aces[1].Sid, Network),
       "c4: the explicit ACEs are not first\n");
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
 * An explicit ACE before the ACEs the parent passes on, set by a legacy writer: the key is not auto-inherited but
 * holds the whole set the parent passed on, so when the parent changes it is converted: the explicit ACE stays
 * first, the rest is the parent's inherited set. The parent here is a plain key whose DACL was set before any
 * subkey existed.
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
    /*
     * c holds everything the parent passed on, so it is converted (measured on Windows Server 2022, x64 and x86):
     * those ACEs are the inherited ones now, the new ACE comes with them, c is auto-inherited and not protected and
     * only the ACE of its own is explicit (a parent whose set has a deny ACE is another matter, see TestParentSetMatch).
     */
    ok(FindAce(&Dacl, ACCESS_ALLOWED_ACE_TYPE, World) >= 0, "c did not get the new ACE\n");
    ok_hex(Dacl.Control, SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED | SE_SELF_RELATIVE);
    ok(Dacl.Count && Dacl.Aces[0].Mask == KEY_READ && EqualSid(Dacl.Aces[0].Sid, Network) && !(Dacl.Aces[0].Flags & INHERITED_ACE),
       "the explicit ACE is not first\n");
    {
        ULONG Explicit = 0, k;

        for (k = 0; k < Dacl.Count; k++)
        {
            if (!(Dacl.Aces[k].Flags & INHERITED_ACE))
                Explicit++;
        }
        ok(Explicit == 1, "c has %lu explicit ACEs\n", Explicit);
    }
    FreeDacl(&Dacl);

Done:
    if (Attributes.lpSecurityDescriptor) LocalFree(Attributes.lpSecurityDescriptor);
    if (Key) RegCloseKey(Key);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (Network) FreeSid(Network);
    if (World) FreeSid(World);
}

/*
 * The owner of a key is not the caller's token owner. The parent passes on a CREATOR OWNER ACE, so the
 * ACEs a key inherited depend on its owner: reading the DACL alone must judge them with the owner of the
 * key, as reading the owner with it does, not with the owner of the caller's token.
 */
static ULONG CountInherited(const KEY_DACL *Dacl)
{
    ULONG i, Count = 0;

    for (i = 0; i < Dacl->Count; i++)
    {
        if (Dacl->Aces[i].Flags & INHERITED_ACE)
            Count++;
    }
    return Count;
}

static void TestGetUsesKeyOwner(void)
{
    static const WCHAR ParentSddl[] = L"D:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CIIO;KA;;;CO)";
    SECURITY_ATTRIBUTES Attributes = {sizeof(Attributes), NULL, FALSE};
    BYTE TokenBuffer[256];
    PSECURITY_DESCRIPTOR Sd = NULL, Both = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID Owner = NULL, NewOwner, Admins = NULL;
    PACL Dacl = NULL;
    KEY_DACL Full, Only;
    HKEY Key = NULL, Child = NULL;
    HANDLE Token = NULL;
    DWORD Error, Length;
    ULONG i;

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

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token) ||
        !GetTokenInformation(Token, TokenUser, TokenBuffer, sizeof(TokenBuffer), &Length))
    {
        skip("cannot read the token user: %lu\n", GetLastError());
        goto Done;
    }

    /* the key got CREATOR OWNER replaced by the owner it was created with; read that owner */
    ok_long(GetSecurityInfo(Child, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &Owner, NULL, NULL, NULL, &Sd), ERROR_SUCCESS);
    if (!Owner)
        goto Done;

    /* hand the key to another owner the caller may set: the token user, else Administrators */
    NewOwner = ((TOKEN_USER *)TokenBuffer)->User.Sid;
    if (EqualSid(Owner, NewOwner))
    {
        AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &Admins);
        NewOwner = Admins;
    }
    if (!NewOwner || EqualSid(Owner, NewOwner))
    {
        skip("no other owner to tell apart\n");
        goto Done;
    }
    Error = SetSecurityInfo(Child, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, NewOwner, NULL, NULL, NULL);
    if (Error != ERROR_SUCCESS)
    {
        skip("cannot change the owner: %lu\n", Error);
        goto Done;
    }

    ReadDacl(Child, &Full);
    ok(Full.Ok, "cannot read the DACL with the owner\n");
    ok_long(GetSecurityInfo(Child, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Both), ERROR_SUCCESS);
    ZeroMemory(&Only, sizeof(Only));
    if (Both && Dacl)
    {
        Only.Count = min(Dacl->AceCount, ARRAYSIZE(Only.Aces));
        for (i = 0; i < Only.Count; i++)
        {
            ACCESS_ALLOWED_ACE *Ace;

            if (!GetAce(Dacl, i, (PVOID *)&Ace))
                break;
            Only.Aces[i].Flags = Ace->Header.AceFlags;
        }
        Only.Ok = TRUE;
    }
    ok(Only.Ok && Only.Count == Full.Count, "DACL only: %lu ACEs, with the owner: %lu\n", Only.Count, Full.Count);
    ok(CountInherited(&Only) == CountInherited(&Full),
       "DACL only reports %lu ACEs inherited, with the owner %lu\n", CountInherited(&Only), CountInherited(&Full));
    for (i = 0; i < Only.Count && i < Full.Count; i++)
        ok(Only.Aces[i].Flags == Full.Aces[i].Flags, "ACE %lu: flags 0x%x with the DACL only, 0x%x with the owner\n",
           i, Only.Aces[i].Flags, Full.Aces[i].Flags);

    FreeDacl(&Full);
    if (Both) LocalFree(Both);

Done:
    if (Sd) LocalFree(Sd);
    if (Admins) FreeSid(Admins);
    if (Token) CloseHandle(Token);
    if (Child) RegCloseKey(Child);
    if (Attributes.lpSecurityDescriptor) LocalFree(Attributes.lpSecurityDescriptor);
    if (Key) RegCloseKey(Key);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
}

/*
 * Registry DACL inheritance as measured on Windows 10 22H2 (the daclora probe), parent P created with
 * D:(D;CI;KW;;;AN)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CIIO;KA;;;CO), which is not auto-inherited:
 *  - a DACL set on an empty / explicit-only key merges the parent's ACEs. The inherit-only CREATOR OWNER ACE
 *    adds no owner copy that an inherited ACE covers already (Administrators), and the ACE stays inherit-only;
 *  - when P changes, a subkey that is not auto-inherited (created below P, set by a legacy writer, empty) keeps
 *    its DACL exactly and is only flagged protected + auto-inherited (control 0x9404); an auto-inherited one gets
 *    the new ACE;
 *  - an inherited ACE that an earlier inherited ACE of the same SID covers is kept inherit-only (IO) if it
 *    passes on, dropped if it was the copy for the key alone.
 */
#define FLAGS_CIID (CONTAINER_INHERIT_ACE | INHERITED_ACE)
#define FLAGS_CO   (CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | INHERITED_ACE)

static BOOL AceIs(const KEY_DACL *Dacl, ULONG Index, UCHAR Type, UCHAR Flags, PCWSTR SidString)
{
    PWSTR Text = NULL;
    BOOL Same = FALSE;

    if (Index >= Dacl->Count)
        return FALSE;
    if (ConvertSidToStringSidW(Dacl->Aces[Index].Sid, &Text))
    {
        Same = Dacl->Aces[Index].Type == Type && Dacl->Aces[Index].Flags == Flags && !wcscmp(Text, SidString);
        LocalFree(Text);
    }
    return Same;
}

static BOOL OwnerIsCovered(HKEY Parent, PCWSTR Name)
{
    HKEY Key;
    PSECURITY_DESCRIPTOR Sd = NULL;
    PSID Owner = NULL;
    PWSTR Text = NULL;
    BOOL Covered = FALSE;

    if (RegOpenKeyExW(Parent, Name, 0, READ_CONTROL, &Key) != ERROR_SUCCESS)
        return FALSE;
    if (GetSecurityInfo(Key, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &Owner, NULL, NULL, NULL, &Sd) == ERROR_SUCCESS &&
        Owner && ConvertSidToStringSidW(Owner, &Text))
    {
        Covered = !wcscmp(Text, L"S-1-5-32-544") || !wcscmp(Text, L"S-1-5-18");
        LocalFree(Text);
    }
    if (Sd) LocalFree(Sd);
    RegCloseKey(Key);
    return Covered;
}

static void SetNamedEmpty(PCWSTR Path, SECURITY_INFORMATION Info)
{
    BYTE Buffer[64];
    PACL Empty = (PACL)Buffer;

    InitializeAcl(Empty, sizeof(Buffer), ACL_REVISION);
    ok_long(SetNamedSecurityInfoW((LPWSTR)Path, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | Info, NULL, NULL, Empty, NULL),
            ERROR_SUCCESS);
}

/* Get-Acl then Set-Acl: read DACL and owner by name, write the DACL back by name */
static void NamedRoundTrip(PCWSTR Path)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;

    ok_long(GetNamedSecurityInfoW((LPWSTR)Path, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                                  NULL, NULL, &Dacl, NULL, &Sd), ERROR_SUCCESS);
    if (Sd)
    {
        ok_long(SetNamedSecurityInfoW((LPWSTR)Path, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL),
                ERROR_SUCCESS);
        LocalFree(Sd);
    }
}

static void TestOracleRows(void)
{
    static const WCHAR ParentSddl[] = L"D:(D;CI;KW;;;AN)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CIIO;KA;;;CO)";
    static const WCHAR Base[] = L"CURRENT_USER\\Software\\ReactOS-apitest-SetSecurityInfoKeyInherit";
    static const WCHAR *Names[] = { L"t", L"c3", L"c4", L"c5", L"s9e", L"s9s" };
    SECURITY_ATTRIBUTES Attributes = {sizeof(Attributes), NULL, FALSE};
    WCHAR Path[256];
    KEY_DACL T0, T1, C3, C4, C4b, C5, S9e, S9s, S9sb;
    HKEY Key = NULL, Child = NULL;
    BOOL Covered;
    DWORD Error;
    ULONG i;

    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(ParentSddl, SDDL_REVISION_1, &Attributes.lpSecurityDescriptor, NULL))
    {
        skip("cannot make the parent descriptor: %lu\n", GetLastError());
        return;
    }
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, &Attributes, &Key, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;

    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        if (!MakeKey(Key, Names[i], 0, &Child))
            goto Done;
        RegCloseKey(Child);
    }
    Covered = OwnerIsCovered(Key, L"c4");

    /* c3: a legacy writer's empty DACL; c5: empty and protected; c4: empty, unprotected (W4); s9e / s9s: round trips */
    if (!RawSetSddl(Key, L"c3", L"D:") || !RawSetSddl(Key, L"s9e", L"D:") || !RawSetSddl(Key, L"s9s", L"D:(A;CI;KA;;;SY)"))
        goto Done;
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%ls\\c4", Base);
    SetNamedEmpty(Path, UNPROTECTED_DACL_SECURITY_INFORMATION);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%ls\\c5", Base);
    SetNamedEmpty(Path, PROTECTED_DACL_SECURITY_INFORMATION);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%ls\\s9e", Base);
    NamedRoundTrip(Path);
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%ls\\s9s", Base);
    NamedRoundTrip(Path);

    OpenDacl(Key, L"t", &T0);
    OpenDacl(Key, L"c4", &C4);
    OpenDacl(Key, L"s9e", &S9e);
    OpenDacl(Key, L"s9s", &S9s);

    /* W4 / S9e / S9s: the parent's set, no ACE for the owner that an inherited one covers */
    if (Covered)
    {
        ok(C4.Count == 4, "W4: %lu ACEs, expected 4\n", C4.Count);
        ok(S9e.Count == 4, "S9e: %lu ACEs, expected 4\n", S9e.Count);
        ok(S9s.Count == 5, "S9s: %lu ACEs, expected 5\n", S9s.Count);
    }
    ok_hex(C4.Control, AUTO_CONTROL);
    ok(AceIs(&C4, 0, ACCESS_DENIED_ACE_TYPE, FLAGS_CIID, L"S-1-5-7"), "W4: ACE 0\n");
    ok(AceIs(&C4, 1, ACCESS_ALLOWED_ACE_TYPE, FLAGS_CIID, L"S-1-5-18"), "W4: ACE 1\n");
    ok(AceIs(&C4, 2, ACCESS_ALLOWED_ACE_TYPE, FLAGS_CIID, L"S-1-5-32-544"), "W4: ACE 2\n");
    ok(AceIs(&C4, Covered ? 3 : 4, ACCESS_ALLOWED_ACE_TYPE, FLAGS_CO, L"S-1-3-0"), "W4: the CREATOR OWNER ACE\n");
    ok_hex(S9e.Control, AUTO_CONTROL);
    ok(AceIs(&S9e, 3, ACCESS_ALLOWED_ACE_TYPE, FLAGS_CO, L"S-1-3-0") || !Covered, "S9e: the CREATOR OWNER ACE\n");
    ok_hex(S9s.Control, AUTO_CONTROL);
    ok(AceIs(&S9s, 0, ACCESS_ALLOWED_ACE_TYPE, CONTAINER_INHERIT_ACE, L"S-1-5-18"), "S9s: the explicit ACE first\n");
    ok(AceIs(&S9s, 1, ACCESS_DENIED_ACE_TYPE, FLAGS_CIID, L"S-1-5-7"), "S9s: ACE 1\n");
    ok(AceIs(&S9s, Covered ? 4 : 5, ACCESS_ALLOWED_ACE_TYPE, FLAGS_CO, L"S-1-3-0") || !Covered, "S9s: the CREATOR OWNER ACE\n");

    /* W6: P changes (Everyone read, inherited by subkeys, by name) */
    AddEveryoneRead();

    OpenDacl(Key, L"t", &T1);
    OpenDacl(Key, L"c3", &C3);
    OpenDacl(Key, L"c4", &C4b);
    OpenDacl(Key, L"c5", &C5);
    OpenDacl(Key, L"s9s", &S9sb);

    /* not auto-inherited: untouched except for the control (0x9404), no new ACE, nothing inherited */
    ok_hex(T1.Control, SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SELF_RELATIVE);
    ok(T1.Count == T0.Count, "W6: the plain child went from %lu to %lu ACEs\n", T0.Count, T1.Count);
    for (i = 0; i < T1.Count && i < T0.Count; i++)
        ok((T1.Aces[i].Flags & ~INHERITED_ACE) == (T0.Aces[i].Flags & ~INHERITED_ACE) && T1.Aces[i].Mask == T0.Aces[i].Mask &&
           EqualSid(T1.Aces[i].Sid, T0.Aces[i].Sid), "W6: ACE %lu of the plain child changed\n", i);
    ok_hex(C3.Control, SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SELF_RELATIVE);
    ok(C3.Count == 0, "W3: the empty DACL got %lu ACEs\n", C3.Count);
    ok_hex(C5.Control, SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SELF_RELATIVE);
    ok(C5.Count == 0, "W5: the protected DACL got %lu ACEs\n", C5.Count);

    /* auto-inherited: updated with the new ACE, and no inherited ACE a previous one covers is left effective */
    ok_hex(C4b.Control, AUTO_CONTROL);
    ok(C4b.Count > C4.Count, "c4: %lu ACEs before the change, %lu after\n", C4.Count, C4b.Count);
    for (i = 0; i < C4b.Count; i++)
    {
        ULONG j;

        for (j = 0; j < i; j++)
        {
            if (!(C4b.Aces[j].Flags & INHERIT_ONLY_ACE) && C4b.Aces[j].Type == C4b.Aces[i].Type &&
                (C4b.Aces[j].Mask & C4b.Aces[i].Mask) == C4b.Aces[i].Mask && EqualSid(C4b.Aces[j].Sid, C4b.Aces[i].Sid))
            {
                ok(C4b.Aces[i].Flags & INHERIT_ONLY_ACE, "c4: ACE %lu repeats ACE %lu and is not inherit-only (0x%x)\n",
                   i, j, C4b.Aces[i].Flags);
                break;
            }
        }
    }
    for (i = 0; i < S9sb.Count; i++)
        ok(!(S9sb.Aces[i].Flags & INHERIT_ONLY_ACE) || S9sb.Aces[i].Flags & INHERITED_ACE,
           "s9s: ACE %lu is inherit-only but not inherited\n", i);

    FreeDacl(&S9sb);
    FreeDacl(&C5);
    FreeDacl(&C4b);
    FreeDacl(&C3);
    FreeDacl(&T1);
    FreeDacl(&S9s);
    FreeDacl(&S9e);
    FreeDacl(&C4);
    FreeDacl(&T0);

Done:
    if (Attributes.lpSecurityDescriptor) LocalFree(Attributes.lpSecurityDescriptor);
    if (Key) RegCloseKey(Key);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
}

/*
 * Propagation at the edges of the tree (measured on Windows Server 2022, scratch keys, the caller an administrator):
 *  - a hive root passes its DACL on to its subkeys, and takes the inheritable ACEs of the root of its class;
 *  - a key whose parent cannot be read still becomes auto-inherited and passes its DACL on, but inherits nothing;
 *  - a subkey closed to the caller is skipped with its subtree, the call succeeds and the siblings are updated.
 * The last two need a key the caller cannot open, which a system that does not enforce key security cannot make:
 * they skip there.
 */
static BOOL EnableRestorePrivileges(BOOL Enable)
{
    static const PCWSTR Names[] = {L"SeBackupPrivilege", L"SeRestorePrivilege", L"SeTakeOwnershipPrivilege"};
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    BOOL Ok = TRUE;
    ULONG i;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        Privileges.PrivilegeCount = 1;
        Privileges.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;
        if (!LookupPrivilegeValueW(NULL, Names[i], &Privileges.Privileges[0].Luid))
        {
            Ok = FALSE;
            continue;
        }
        SetLastError(ERROR_SUCCESS);
        AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL);
        if (GetLastError() != ERROR_SUCCESS)
            Ok = FALSE;
    }
    CloseHandle(Token);
    return Ok;
}

/* The owner and DACL of a key by SDDL with backup/restore semantics (the key may be closed to the caller) */
static BOOL RestoreSddl(HKEY Root, PCWSTR Path, SECURITY_INFORMATION Info, PCWSTR Sddl)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    HKEY Key;
    DWORD Error;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
        return FALSE;
    EnableRestorePrivileges(TRUE);
    Error = RegOpenKeyExW(Root, Path, REG_OPTION_BACKUP_RESTORE, WRITE_DAC | WRITE_OWNER | READ_CONTROL, &Key);
    if (Error == ERROR_SUCCESS)
    {
        Error = RegSetKeySecurity(Key, Info, Sd);
        RegCloseKey(Key);
    }
    EnableRestorePrivileges(FALSE);
    LocalFree(Sd);
    return Error == ERROR_SUCCESS;
}

/* Hand the keys back to Administrators so that they can be deleted */
static void RestoreKeys(HKEY Root, PCWSTR Base, const PCWSTR *Names, ULONG Count)
{
    WCHAR Path[300];
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        wsprintfW(Path, L"%ls\\%ls", Base, Names[i]);
        RestoreSddl(Root, Path, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, L"O:BAD:P(A;;KA;;;BA)(A;;KA;;;SY)");
    }
}

static BOOL KeyOpens(HKEY Root, PCWSTR Path, REGSAM Access)
{
    HKEY Key;

    if (RegOpenKeyExW(Root, Path, 0, Access, &Key) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(Key);
    return TRUE;
}

static BOOL OpenSubkey(PCWSTR Name, HKEY Parent, HKEY *Key)
{
    return RegOpenKeyExW(Parent, Name, 0, KEY_ALL_ACCESS, Key) == ERROR_SUCCESS;
}

static void TestHiveRoot(void)
{
    static const WCHAR HiveName[] = L"ReactOSApitestHiveMt";
    static const WCHAR Source[] = L"Software\\ReactOS-apitest-SetSecurityInfoKeyInherit\\src";
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID Auth = NULL;
    WCHAR File[MAX_PATH];
    HKEY Src = NULL, SrcKid = NULL, Hive = NULL, H1 = NULL, G = NULL, H2 = NULL;
    KEY_DACL Before, Root, K1, K1g, K2;
    BOOL Loaded = FALSE;
    DWORD Error;
    ULONG i;

    AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_AUTHENTICATED_USER_RID, 0, 0, 0, 0, 0, 0, 0, &Auth);
    GetTempPathW(ARRAYSIZE(File), File);
    lstrcatW(File, L"ros-apitest-hive-mt.hiv");
    DeleteFileW(File);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);

    Error = RegCreateKeyExW(HKEY_CURRENT_USER, Source, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Src, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error || !Auth || !MakeKey(Src, L"h1", 0, &SrcKid))
        goto Done;
    RegCloseKey(SrcKid);
    if (!MakeKey(Src, L"h1\\g", 0, &SrcKid))
        goto Done;
    RegCloseKey(SrcKid);
    if (!MakeKey(Src, L"h2", 0, &SrcKid))
        goto Done;
    RegCloseKey(SrcKid);

    EnableRestorePrivileges(TRUE);
    Error = RegSaveKeyW(Src, File, NULL);
    if (Error == ERROR_SUCCESS)
    {
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, HiveName);
        Error = RegLoadKeyW(HKEY_LOCAL_MACHINE, HiveName, File);
        Loaded = Error == ERROR_SUCCESS;
    }
    EnableRestorePrivileges(FALSE);
    if (!Loaded)
    {
        skip("cannot save and load a scratch hive: %lu\n", Error);
        goto Done;
    }

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, HiveName, 0, KEY_ALL_ACCESS, &Hive);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;
    if (!OpenSubkey(L"h1", Hive, &H1) || !OpenSubkey(L"h1\\g", Hive, &G) || !OpenSubkey(L"h2", Hive, &H2))
    {
        skip("the loaded hive has not got its keys\n");
        goto Done;
    }

    /* the subkeys are auto-inherited, as an application leaves them */
    ok(SetSddlDacl(H1, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:"), "h1\n");
    ok(SetSddlDacl(G, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:"), "g\n");
    ok(SetSddlDacl(H2, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:"), "h2\n");
    ReadDacl(H1, &Before);
    ok(!HasAce(&Before, Auth, KEY_READ), "h1 has the ACE already\n");

    /* the root of the hive: its own ACEs, then what the root of HKLM passes on; the subkeys follow */
    if (!SetSddlDacl(Hive, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KR;;;AU)"))
        goto Done;
    ReadDacl(Hive, &Root);
    ok_hex(Root.Control, AUTO_CONTROL);
    ok(Root.Count > 3, "hive root: %lu ACEs, the explicit three only\n", Root.Count);
    for (i = 3; i < Root.Count; i++)
        ok(Root.Aces[i].Flags & INHERITED_ACE, "hive root: ACE %lu has flags 0x%x\n", i, Root.Aces[i].Flags);
    ReadDacl(H1, &K1);
    ReadDacl(G, &K1g);
    ReadDacl(H2, &K2);
    ok_hex(K1.Control, AUTO_CONTROL);
    ok(HasAce(&K1, Auth, KEY_READ), "the ACE did not reach h1\n");
    ok(HasAce(&K1g, Auth, KEY_READ), "the ACE did not reach h1\\g\n");
    ok(HasAce(&K2, Auth, KEY_READ), "the ACE did not reach h2\n");
    ok(AllInherited(&K1) && AllInherited(&K1g) && AllInherited(&K2), "a subkey has an ACE that is not inherited\n");
    FreeDacl(&K2);
    FreeDacl(&K1g);
    FreeDacl(&K1);
    FreeDacl(&Root);
    FreeDacl(&Before);

Done:
    if (H2) RegCloseKey(H2);
    if (G) RegCloseKey(G);
    if (H1) RegCloseKey(H1);
    if (Hive) RegCloseKey(Hive);
    if (Loaded)
    {
        EnableRestorePrivileges(TRUE);
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, HiveName);
        EnableRestorePrivileges(FALSE);
    }
    if (Src) RegCloseKey(Src);
    DeleteFileW(File);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (Auth) FreeSid(Auth);
}

static void TestUnreadableParent(void)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID Auth = NULL;
    WCHAR Parent[300];
    HKEY Scratch = NULL, Up = NULL, K = NULL, G = NULL, H = NULL;
    KEY_DACL Dk, Dg, Dh;
    DWORD Error;

    AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_AUTHENTICATED_USER_RID, 0, 0, 0, 0, 0, 0, 0, &Auth);
    wsprintfW(Parent, L"%ls\\U", ScratchPath);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Scratch, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error || !Auth || !MakeKey(Scratch, L"U", 0, &Up))
        goto Done;
    ok(SetSddlDacl(Up, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)"), "U\n");
    if (!MakeKey(Up, L"K", 0, &K) || !MakeKey(K, L"g", 0, &G) || !MakeKey(G, L"h", 0, &H))
        goto Done;
    ok(SetSddlDacl(K, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:"), "K\n");
    ok(SetSddlDacl(G, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:"), "g\n");
    ok(SetSddlDacl(H, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:"), "h\n");

    /* U now belongs to LOCAL SERVICE and lets only it and SYSTEM in */
    RegCloseKey(Up);
    Up = NULL;
    if (!RestoreSddl(HKEY_CURRENT_USER, Parent, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                     L"O:LSD:P(A;CI;KA;;;SY)(A;CI;KA;;;LS)(A;;KA;;;LS)(A;;KA;;;SY)") ||
        KeyOpens(HKEY_CURRENT_USER, Parent, READ_CONTROL))
    {
        skip("a key cannot be shut away from the caller on this system (key security is not enforced)\n");
        goto Done;
    }

    /* the parent cannot be read: the key keeps its own ACEs, is auto-inherited, and its subkeys follow */
    ok(SetSddlDacl(K, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;AU)"), "set K\n");
    ReadDacl(K, &Dk);
    ReadDacl(G, &Dg);
    ReadDacl(H, &Dh);
    ok_hex(Dk.Control, AUTO_CONTROL);
    ok(Dk.Count == 3, "K: %lu ACEs, expected its three explicit ones\n", Dk.Count);
    ok_hex(Dg.Control, AUTO_CONTROL);
    ok(Dg.Count == 3 && AllInherited(&Dg) && HasAce(&Dg, Auth, KEY_READ), "g: %lu ACEs\n", Dg.Count);
    ok(Dh.Count == 3 && AllInherited(&Dh) && HasAce(&Dh, Auth, KEY_READ), "h: %lu ACEs\n", Dh.Count);
    FreeDacl(&Dh);
    FreeDacl(&Dg);
    FreeDacl(&Dk);

    /* protected: the key says it is protected and auto-inherited, the subkeys still follow */
    ok(SetSddlDacl(K, PROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)"), "protect K\n");
    ReadDacl(K, &Dk);
    ReadDacl(G, &Dg);
    ok_hex(Dk.Control, AUTO_CONTROL | SE_DACL_PROTECTED);
    ok(Dg.Count == 3 && AllInherited(&Dg) && !HasAce(&Dg, Auth, KEY_READ), "g after protect: %lu ACEs\n", Dg.Count);
    FreeDacl(&Dg);
    FreeDacl(&Dk);

Done:
    {
        WCHAR Base[300];

        wsprintfW(Base, L"%ls\\U", ScratchPath);
        RestoreSddl(HKEY_CURRENT_USER, Base, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, L"O:BAD:P(A;;KA;;;BA)(A;;KA;;;SY)");
    }
    if (H) RegCloseKey(H);
    if (G) RegCloseKey(G);
    if (K) RegCloseKey(K);
    if (Up) RegCloseKey(Up);
    if (Scratch) RegCloseKey(Scratch);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (Auth) FreeSid(Auth);
}

static void TestClosedSubkey(void)
{
    static const PCWSTR Kids[] = {L"a1", L"a1\\g", L"b1", L"b1\\g", L"b2", L"b2\\g", L"c1", L"c1\\g"};
    static const PCWSTR Locked[] = {L"T\\b1"};
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID Auth = NULL;
    WCHAR Path[320];
    HKEY Scratch = NULL, T = NULL, Key = NULL, B1 = NULL, B2 = NULL;
    KEY_DACL D;
    DWORD Error;
    ULONG i;
    BOOL Reads[8];

    AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_AUTHENTICATED_USER_RID, 0, 0, 0, 0, 0, 0, 0, &Auth);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Scratch, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error || !Auth || !MakeKey(Scratch, L"T", 0, &T))
        goto Done;
    ok(SetSddlDacl(T, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)"), "T\n");
    for (i = 0; i < ARRAYSIZE(Kids); i++)
    {
        if (!MakeKey(T, Kids[i], 0, &Key))
            goto Done;
        RegCloseKey(Key);
    }
    /* T passes on SYSTEM and Everyone read only: nobody of the caller's has WRITE_DAC below it once it is not theirs */
    ok(SetSddlDacl(T, PROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;CI;KA;;;SY)(A;CI;KR;;;WD)"), "restrict T\n");

    /* b1: auto-inherited and owned by LOCAL SERVICE; b2: denies the caller KEY_QUERY_VALUE (CC) */
    if (!OpenSubkey(L"b1", T, &B1) || !OpenSubkey(L"b2", T, &B2))
        goto Done;
    EnableRestorePrivileges(TRUE);
    {
        PSECURITY_DESCRIPTOR Sd = NULL;
        PSID Owner = NULL;
        ACL Empty;
        BOOL Defaulted;

        InitializeAcl(&Empty, sizeof(Empty), ACL_REVISION);
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:LS", SDDL_REVISION_1, &Sd, NULL) &&
            GetSecurityDescriptorOwner(Sd, &Owner, &Defaulted))
            Error = SetSecurityInfo(B1, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                    Owner, NULL, &Empty, NULL);
        else
            Error = ERROR_INVALID_DATA;
        if (Sd) LocalFree(Sd);
    }
    EnableRestorePrivileges(FALSE);
    wsprintfW(Path, L"%ls\\T\\b1", ScratchPath);
    if (Error != ERROR_SUCCESS || KeyOpens(HKEY_CURRENT_USER, Path, READ_CONTROL | WRITE_DAC))
    {
        skip("a key cannot be shut away from the caller on this system (key security is not enforced)\n");
        goto Done;
    }
    ok(SetSddlDacl(B2, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:(D;;CC;;;BA)"), "b2\n");

    /* T gets one more inheritable ACE: the call succeeds, b1 and its subtree stay, the others follow */
    ok(SetSddlDacl(T, PROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;CI;KA;;;SY)(A;CI;KR;;;WD)(A;CI;KR;;;AU)"),
       "set T\n");
    for (i = 0; i < ARRAYSIZE(Kids); i++)
    {
        wsprintfW(Path, L"%ls\\T\\%ls", ScratchPath, Kids[i]);
        Reads[i] = FALSE;
        EnableRestorePrivileges(TRUE);
        Error = RegOpenKeyExW(HKEY_CURRENT_USER, Path, REG_OPTION_BACKUP_RESTORE, READ_CONTROL, &Key);
        EnableRestorePrivileges(FALSE);
        if (Error == ERROR_SUCCESS)
        {
            ReadDacl(Key, &D);
            Reads[i] = HasAce(&D, Auth, KEY_READ);
            FreeDacl(&D);
            RegCloseKey(Key);
        }
    }
    ok(Reads[0] && Reads[1], "a1 and a1\\g were not updated\n");
    ok(!Reads[2] && !Reads[3], "b1 (closed to the caller) or its subkey was updated\n");
    ok(Reads[4], "b2 (denies KEY_QUERY_VALUE) was not updated\n");
    ok(!Reads[5], "the subkey of b2 (denies KEY_QUERY_VALUE) was updated\n");
    ok(Reads[6] && Reads[7], "c1 and c1\\g (siblings after the closed key) were not updated\n");

Done:
    RestoreKeys(HKEY_CURRENT_USER, ScratchPath, Locked, ARRAYSIZE(Locked));
    if (B2) RegCloseKey(B2);
    if (B1) RegCloseKey(B1);
    if (T) RegCloseKey(T);
    if (Scratch) RegCloseKey(Scratch);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    if (Auth) FreeSid(Auth);
}

/* the DACL of Root\Path as SDDL ("D:" and its flags, then the ACEs), compared with what Windows stores */
static void DaclSddlIs(PCWSTR Path, PCWSTR Expected, int Line)
{
    BYTE Buffer[4096];
    DWORD Length = sizeof(Buffer);
    LPWSTR Sddl = NULL;
    HKEY Key;
    DWORD Error;

    Error = RegOpenKeyExW(HKEY_CURRENT_USER, Path, 0, READ_CONTROL, &Key);
    ok_(__FILE__, Line)(Error == ERROR_SUCCESS, "%ls: open error %lu\n", Path, Error);
    if (Error)
        return;
    Error = RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, Buffer, &Length);
    RegCloseKey(Key);
    ok_(__FILE__, Line)(Error == ERROR_SUCCESS, "%ls: RegGetKeySecurity error %lu\n", Path, Error);
    if (Error)
        return;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(Buffer, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &Sddl, NULL))
    {
        ok_(__FILE__, Line)(0, "%ls: no SDDL, error %lu\n", Path, GetLastError());
        return;
    }
    ok_(__FILE__, Line)(!wcscmp(Sddl, Expected), "%ls: %ls, expected %ls\n", Path, Sddl, Expected);
    LocalFree(Sddl);
}
#define DACL_IS(Name, Expected) do { wsprintfW(Path, L"%ls\\T\\%ls", ScratchPath, Name); DaclSddlIs(Path, Expected, __LINE__); } while (0)

/*
 * Subkeys that are not auto-inherited, when their parent's DACL changes (measured on Windows Server 2022, x64 and
 * x86 callers, the same shapes below HKLM; HKCU behaves the same):
 *  W6b  a key with an ACE flagged INHERITED_ACE (a legacy writer copied the flag) is updated like an auto-inherited
 *       one: every ACE flagged inherited is dropped (first or last, allow or deny, passed on by the parent or not),
 *       its explicit ACEs stay, the parent's set follows, it becomes auto-inherited and its subkeys follow;
 *  W6c  a key without one keeps its ACEs and is flagged protected + auto-inherited, and its subtree is rebuilt
 *       from its DACL: what the subkeys had inherited from above it is gone (it granted more than the key passes
 *       on). A key below it that is not auto-inherited either is handled the same way, a protected one and a key
 *       without a DACL are left alone;
 *       a key that does not grant the caller KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS is flagged, its subkeys are
 *       not touched (checked only where key security is enforced).
 */
static void TestLegacySubkeys(void)
{
    static const struct { PCWSTR Name; int How; PCWSTR Sddl; } Tree[] = {
        {L"b4", 1, L"D:(A;;KA;;;BA)(A;ID;KR;;;WD)"}, {L"b4\\g", 0, NULL},
        {L"b4n", 1, L"D:(A;ID;KR;;;WD)(A;;KA;;;BA)"}, {L"b4n\\g", 0, NULL},
        {L"b4d", 1, L"D:(A;;KA;;;BA)(D;ID;KW;;;BU)"}, {L"b4d\\g", 0, NULL},
        {L"b4x", 1, L"D:(A;;KA;;;BA)(A;ID;KA;;;BU)"}, {L"b4x\\g", 0, NULL},
        {L"b4o", 1, L"D:(A;ID;KR;;;WD)"}, {L"b4o\\g", 0, NULL},
        {L"b4c", 1, L"D:(A;;KA;;;BA)(A;CI;KR;;;BU)(A;CIID;KR;;;WD)"}, {L"b4c\\g", 0, NULL}, {L"b4c\\g\\h", 0, NULL},
        {L"b4l", 1, L"D:(A;;KA;;;BA)(A;CIID;KR;;;WD)"}, {L"b4l\\g", 1, L"D:(A;;KA;;;BA)(A;;KR;;;IU)"}, {L"b4l\\g\\h", 0, NULL},
        {L"b5", 1, L"D:(A;;KA;;;BA)(A;;KR;;;WD)"}, {L"b5\\g", 2, L"D:(A;;KR;;;IU)"}, {L"b5\\g\\h", 0, NULL},
        {L"b5c", 1, L"D:(A;;KA;;;BA)(A;CI;KR;;;BU)"}, {L"b5c\\g", 0, NULL}, {L"b5c\\g\\h", 0, NULL},
        {L"b5n", 1, L"D:(A;;KA;;;BA)(A;CI;KR;;;BU)"}, {L"b5n\\g", 1, L"D:(A;;KA;;;BA)(A;;KR;;;IU)"}, {L"b5n\\g\\h", 0, NULL},
        {L"b5p", 1, L"D:(A;;KA;;;BA)(A;CI;KR;;;BU)"}, {L"b5p\\g", 3, L"D:P(A;;KA;;;BA)(A;CI;KR;;;IU)"}, {L"b5p\\g\\h", 0, NULL},
        {L"b5a", 1, L"D:(A;;KR;;;WD)"}, {L"b5a\\g", 0, NULL},
        {L"b5v", 1, L"D:(D;;KW;;;BU)(A;;CCSW;;;BA)"}, {L"b5v\\g", 0, NULL},
        {L"b5e", 1, L"D:"}, {L"b5e\\g", 0, NULL},
        {L"b5z", 1, NULL /* a NULL DACL */}, {L"b5z\\g", 0, NULL},
    };
    static const PCWSTR Stale = L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)";
    static const PCWSTR Updated = L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;AU)";
    static const PCWSTR B4 = L"D:AI(A;;KA;;;BA)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;AU)";
    WCHAR Path[320];
    HKEY Scratch = NULL, T = NULL, Key = NULL;
    DWORD Error;
    ULONG i;

    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Scratch, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error || !MakeKey(Scratch, L"T", 0, &T))
        goto Done;
    ok(SetSddlDacl(T, UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)"), "T\n");
    for (i = 0; i < ARRAYSIZE(Tree); i++)
    {
        if (!MakeKey(T, Tree[i].Name, 0, &Key))
            goto Done;
        RegCloseKey(Key);
    }
    /* T passes on SYSTEM full and Everyone read */
    ok(SetSddlDacl(T, PROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;CI;KA;;;SY)(A;CI;KR;;;WD)"), "restrict T\n");
    /* the SetSecurityInfo setups first (they still inherit from T), then the legacy writes */
    for (i = 0; i < 2 * ARRAYSIZE(Tree); i++)
    {
        ULONG k = i % ARRAYSIZE(Tree);

        if ((i < ARRAYSIZE(Tree)) != (Tree[k].How >= 2) || Tree[k].How == 0)
            continue;
        if (Tree[k].How == 1 && Tree[k].Sddl)
        {
            if (!RawSetSddl(T, Tree[k].Name, Tree[k].Sddl))
                goto Done;
            continue;
        }
        if (Tree[k].How == 1)
        {
            SECURITY_DESCRIPTOR Null;

            InitializeSecurityDescriptor(&Null, SECURITY_DESCRIPTOR_REVISION);
            SetSecurityDescriptorDacl(&Null, TRUE, NULL, FALSE);
            ok_long(RegOpenKeyExW(T, Tree[k].Name, 0, WRITE_DAC, &Key), ERROR_SUCCESS);
            ok_long(RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, &Null), ERROR_SUCCESS);
            RegCloseKey(Key);
            continue;
        }
        /* the caller keeps READ_CONTROL | WRITE_DAC as the owner; T passes it no other right on Windows */
        if (RegOpenKeyExW(T, Tree[k].Name, 0, READ_CONTROL | WRITE_DAC, &Key) != ERROR_SUCCESS)
            goto Done;
        ok(SetSddlDacl(Key, Tree[k].How == 3 ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION,
                       Tree[k].Sddl), "%ls\n", Tree[k].Name);
        RegCloseKey(Key);
    }
    DACL_IS(L"b4", L"D:(A;;KA;;;BA)(A;ID;KR;;;WD)");
    DACL_IS(L"b5\\g", L"D:AI(A;;KR;;;IU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)");
    DACL_IS(L"b5\\g\\h", Stale);

    /* T gets one more inheritable ACE */
    ok(SetSddlDacl(T, PROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;CI;KA;;;SY)(A;CI;KR;;;WD)(A;CI;KR;;;AU)"),
       "set T\n");

    /* W6b */
    DACL_IS(L"b4", B4);
    DACL_IS(L"b4\\g", Updated);
    DACL_IS(L"b4n", B4);
    DACL_IS(L"b4n\\g", Updated);
    DACL_IS(L"b4d", B4);
    DACL_IS(L"b4d\\g", Updated);
    DACL_IS(L"b4x", B4);
    DACL_IS(L"b4x\\g", Updated);
    DACL_IS(L"b4o", Updated);
    DACL_IS(L"b4o\\g", Updated);
    DACL_IS(L"b4c", L"D:AI(A;;KA;;;BA)(A;CI;KR;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;AU)");
    DACL_IS(L"b4c\\g", L"D:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;AU)");
    DACL_IS(L"b4c\\g\\h", L"D:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;AU)");
    DACL_IS(L"b4l", B4);
    DACL_IS(L"b4l\\g", L"D:PAI(A;;KA;;;BA)(A;;KR;;;IU)");
    DACL_IS(L"b4l\\g\\h", L"D:AI");

    /* W6c */
    DACL_IS(L"b5", L"D:PAI(A;;KA;;;BA)(A;;KR;;;WD)");
    DACL_IS(L"b5\\g", L"D:AI(A;;KR;;;IU)");
    DACL_IS(L"b5\\g\\h", L"D:AI");
    DACL_IS(L"b5c", L"D:PAI(A;;KA;;;BA)(A;CI;KR;;;BU)");
    DACL_IS(L"b5c\\g", L"D:AI(A;CIID;KR;;;BU)");
    DACL_IS(L"b5c\\g\\h", L"D:AI(A;CIID;KR;;;BU)");
    DACL_IS(L"b5n", L"D:PAI(A;;KA;;;BA)(A;CI;KR;;;BU)");
    DACL_IS(L"b5n\\g", L"D:PAI(A;;KA;;;BA)(A;;KR;;;IU)");
    DACL_IS(L"b5n\\g\\h", L"D:AI");
    DACL_IS(L"b5p", L"D:PAI(A;;KA;;;BA)(A;CI;KR;;;BU)");
    DACL_IS(L"b5p\\g", L"D:PAI(A;;KA;;;BA)(A;CI;KR;;;IU)");
    DACL_IS(L"b5p\\g\\h", L"D:AI(A;CIID;KR;;;IU)");
    DACL_IS(L"b5a", L"D:PAI(A;;KR;;;WD)");
    DACL_IS(L"b5a\\g", L"D:AI");
    DACL_IS(L"b5v", L"D:PAI(D;;KW;;;BU)(A;;CCSW;;;BA)");
    DACL_IS(L"b5v\\g", L"D:AI");
    DACL_IS(L"b5e", L"D:PAI");
    /* b5z: a NULL DACL, not auto-inherited: untouched (not even flagged), and so is its subtree */
    {
        BYTE Raw[512] = {0};
        PACL Dacl = (PACL)1;
        BOOL Present = FALSE, Defaulted;

        ok(RawGet(T, L"b5z", Raw, sizeof(Raw)) != 0 && GetSecurityDescriptorDacl(Raw, &Present, &Dacl, &Defaulted) &&
           Present && !Dacl, "b5z: the NULL DACL is gone (present %d, %p)\n", Present, Dacl);
        ok_hex(*(WORD *)(Raw + 2) & (SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED), 0);
    }
    DACL_IS(L"b5z\\g", Stale);
    wsprintfW(Path, L"%ls\\T\\b5e", ScratchPath);
    if (KeyOpens(HKEY_CURRENT_USER, Path, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS))
        skip("a key cannot be shut away from the caller on this system (key security is not enforced)\n");
    else
        DACL_IS(L"b5e\\g", Stale);

Done:
    /* hand every key back to Administrators so that the tree can be deleted (b5e, b5a, b5v do not grant DELETE) */
    for (i = ARRAYSIZE(Tree); i-- > 0; )
    {
        wsprintfW(Path, L"%ls\\T\\%ls", ScratchPath, Tree[i].Name);
        RestoreSddl(HKEY_CURRENT_USER, Path, DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)");
    }
    if (T) RegCloseKey(T);
    if (Scratch) RegCloseKey(Scratch);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
}
#undef DACL_IS

/*
 * Subkeys that are not auto-inherited and carry no ACE flagged INHERITED_ACE, when the DACL of their parent changes
 * (measured on Windows Server 2022, x64 and x86 callers). One parent per row: it passes on Old (CI ACEs) while the
 * key s and its subkey g are made, s then gets the raw DACL S (a legacy writer), the parent's DACL becomes New.
 * Windows converts s (those of its ACEs that the old set accounts for become the inherited ones, the others stay
 * explicit, s becomes auto-inherited and g follows) if S holds every ACE the OLD descriptor of the parent passed on
 * to it, compared as explicit ones, in any order and anywhere. It only flags s protected + auto-inherited (the ACEs
 * stay, g is rebuilt from them) if S lacks one, or an allow ACE stands ahead of a deny ACE in S or in what the
 * conversion would give (nothing is checked when the parent passed nothing on). An ACE the parent passed on
 * accounts for one ACE of S: a duplicate stays explicit. The subkey g of D-add-new, G-dup-sy, H-dup-wd-tail and
 * ZC-co-exact-id is not checked: it inherits an ACE twice (explicit and inherited in s), which Windows Server 2022
 * leaves out and the merge keeps as an inherit-only copy (an older row, measured on Windows 10, expects that;
 * Windows 10 not measured now). A parent whose own set repeats an ACE is not a row either, for the same reason.
 * The subkey g of Q-mask-sub and R-type-diff is not checked:
 * Windows does not descend into a key that does not grant the caller KEY_QUERY_VALUE and KEY_ENUMERATE_SUB_KEYS
 * (here the caller has the first only, or is denied), and g keeps what it had; NitroOS does not check the access
 * of key opens yet.
 */
#define SYF L"(A;CI;KA;;;SY)"
#define WDR L"(A;CI;KR;;;WD)"
#define O1 SYF WDR
#define NUR L"(A;;KR;;;NU)"
#define NOR L"(A;CI;KR;;;NO)"
#define BAF L"(A;CI;KA;;;BA)"
#define ANK L"(D;CI;KW;;;AN)"
#define COF L"(A;CIIO;KA;;;CO)"
static void TestParentSetMatch(void)
{
    static const struct { PCWSTR Name, Old, New, S, ExpectedS, ExpectedG; } Rows[] = {
    {L"A-add-set", O1, O1 NOR, L"D:" NUR O1, L"D:AI(A;;KR;;;NU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"B-drop-old", O1, SYF, L"D:" NUR O1, L"D:AI(A;;KR;;;NU)(A;CIID;KA;;;SY)", L"D:AI(A;CIID;KA;;;SY)"},
    {L"C-drop-new", O1, SYF, L"D:" NUR SYF, L"D:PAI(A;;KR;;;NU)(A;CI;KA;;;SY)", L"D:AI(A;CIID;KA;;;SY)"},
    {L"D-add-new", O1, O1 NOR, L"D:" NUR O1 NOR, L"D:AI(A;;KR;;;NU)(A;CI;KR;;;NO)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", NULL},
    {L"E-rev-inter", O1, O1 NOR, L"D:" WDR NUR SYF, L"D:AI(A;;KR;;;NU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"F-expl-after", O1, O1 NOR, L"D:" O1 NUR, L"D:AI(A;;KR;;;NU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"G-dup-sy", O1, O1 NOR, L"D:" NUR SYF SYF WDR, L"D:AI(A;;KR;;;NU)(A;CI;KA;;;SY)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", NULL},
    {L"H-dup-wd-tail", O1, O1 NOR, L"D:" SYF WDR WDR, L"D:AI(A;CI;KR;;;WD)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", NULL},
    {L"I-extra-ci", O1, O1 NOR, L"D:" SYF L"(A;CI;KR;;;BU)" WDR, L"D:AI(A;CI;KR;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"J-deny-before", O1, O1 NOR, L"D:(D;;KW;;;BU)" O1, L"D:AI(D;;KW;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"K-deny-between", O1, O1 NOR, L"D:" SYF L"(D;;KW;;;BU)" WDR, L"D:PAI(A;CI;KA;;;SY)(D;;KW;;;BU)(A;CI;KR;;;WD)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"L-nonci", O1, O1 NOR, L"D:(A;;KA;;;SY)(A;;KR;;;WD)", L"D:PAI(A;;KA;;;SY)(A;;KR;;;WD)", L"D:AI"},
    {L"M-part-nonci", O1, O1 NOR, L"D:" SYF L"(A;;KR;;;WD)", L"D:PAI(A;CI;KA;;;SY)(A;;KR;;;WD)", L"D:AI(A;CIID;KA;;;SY)"},
    {L"N-oici", O1, O1 NOR, L"D:(A;OICI;KA;;;SY)(A;OICI;KR;;;WD)", L"D:PAI(A;OICI;KA;;;SY)(A;OICI;KR;;;WD)", L"D:AI(A;OICIID;KA;;;SY)(A;OICIID;KR;;;WD)"},
    {L"O-ciio", O1, O1 NOR, L"D:(A;CIIO;KA;;;SY)(A;CIIO;KR;;;WD)", L"D:PAI(A;CIIO;KA;;;SY)(A;CIIO;KR;;;WD)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"P-mask-super", O1, O1 NOR, L"D:" SYF L"(A;CI;KA;;;WD)", L"D:PAI(A;CI;KA;;;SY)(A;CI;KA;;;WD)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KA;;;WD)"},
    {L"Q-mask-sub", O1, O1 NOR, L"D:" SYF L"(A;CI;0x1;;;WD)", L"D:PAI(A;CI;KA;;;SY)(A;CI;CC;;;WD)", NULL},
    {L"R-type-diff", O1, O1 NOR, L"D:" SYF L"(D;CI;KR;;;WD)", L"D:PAI(A;CI;KA;;;SY)(D;CI;KR;;;WD)", NULL},
    {L"T-protected", O1, O1 NOR, L"D:P" NUR O1, L"D:P(A;;KR;;;NU)(A;CI;KA;;;SY)(A;CI;KR;;;WD)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"AI-new-empty", O1, L"", L"D:" NUR O1, L"D:AI(A;;KR;;;NU)", L"D:AI"},
    {L"AJ-same-set", O1, O1 L"(A;;KR;;;NU)", L"D:" NUR O1, L"D:AI(A;;KR;;;NU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"AK-set-only", O1, O1 NOR, L"D:" O1, L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"V-pdeny-match", L"(D;CI;KW;;;BU)" O1, L"(D;CI;KW;;;BU)" O1 NOR, L"D:" NUR L"(D;CI;KW;;;BU)" O1, L"D:PAI(A;;KR;;;NU)(D;CI;KW;;;BU)(A;CI;KA;;;SY)(A;CI;KR;;;WD)", L"D:AI(D;CIID;KW;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"W-pdeny-lacks", L"(D;CI;KW;;;BU)" O1, L"(D;CI;KW;;;BU)" O1 NOR, L"D:" NUR O1, L"D:PAI(A;;KR;;;NU)(A;CI;KA;;;SY)(A;CI;KR;;;WD)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"X-pdeny-order", L"(D;CI;KW;;;BU)" O1, L"(D;CI;KW;;;BU)" O1 NOR, L"D:" O1 L"(D;CI;KW;;;BU)", L"D:PAI(A;CI;KA;;;SY)(A;CI;KR;;;WD)(D;CI;KW;;;BU)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(D;CIID;KW;;;BU)"},
    {L"Z-co-owner-ci", L"(A;CI;KA;;;CO)" WDR, L"(A;CI;KA;;;CO)" WDR NOR, L"D:" NUR L"(A;CI;KA;;;BA)" WDR, L"D:PAI(A;;KR;;;NU)(A;CI;KA;;;BA)(A;CI;KR;;;WD)", L"D:AI(A;CIID;KA;;;BA)(A;CIID;KR;;;WD)"},
    {L"ZA-co-owner-nci", L"(A;CI;KA;;;CO)" WDR, L"(A;CI;KA;;;CO)" WDR NOR, L"D:" NUR L"(A;;KA;;;BA)" WDR, L"D:PAI(A;;KR;;;NU)(A;;KA;;;BA)(A;CI;KR;;;WD)", L"D:AI(A;CIID;KR;;;WD)"},
    {L"ZB-co-exact", L"(A;CI;KA;;;CO)" WDR, L"(A;CI;KA;;;CO)" WDR NOR, L"D:(A;;KA;;;BA)(A;CIIO;KA;;;CO)" WDR, L"D:AI(A;ID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(A;ID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"ZC-co-exact-id", L"(A;CI;KA;;;CO)" WDR, L"(A;CI;KA;;;CO)" WDR NOR, L"D:(A;ID;KA;;;BA)(A;CIIOID;KA;;;CO)" WDR, L"D:AI(A;CI;KR;;;WD)(A;ID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", NULL},
    {L"AC-io-flags", O1 L"(A;CIIO;KR;;;BU)", O1 L"(A;CIIO;KR;;;BU)" NOR, L"D:" O1 L"(A;CI;KR;;;BU)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;BU)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;BU)(A;CIID;KR;;;NO)"},
    {L"AD-io-exact", O1 L"(A;CIIO;KR;;;BU)", O1 L"(A;CIIO;KR;;;BU)" NOR, L"D:" O1 L"(A;CIIO;KR;;;BU)", L"D:PAI(A;CI;KA;;;SY)(A;CI;KR;;;WD)(A;CIIO;KR;;;BU)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;BU)"},
    {L"AE-io-missing", O1 L"(A;CIIO;KR;;;BU)", O1 L"(A;CIIO;KR;;;BU)" NOR, L"D:" O1, L"D:PAI(A;CI;KA;;;SY)(A;CI;KR;;;WD)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"AF-np-plain", O1 L"(A;CINP;KR;;;BU)", O1 L"(A;CINP;KR;;;BU)" NOR, L"D:" O1 L"(A;;KR;;;BU)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;ID;KR;;;BU)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"AG-np-same", O1 L"(A;CINP;KR;;;BU)", O1 L"(A;CINP;KR;;;BU)" NOR, L"D:" O1 L"(A;CINP;KR;;;BU)", L"D:PAI(A;CI;KA;;;SY)(A;CI;KR;;;WD)(A;CINP;KR;;;BU)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;ID;KR;;;BU)"},
    {L"AH-oi-parent", O1 L"(A;OI;KR;;;BU)", O1 L"(A;OI;KR;;;BU)" NOR, L"D:" O1, L"D:PAI(A;CI;KA;;;SY)(A;CI;KR;;;WD)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"AL-oi-incl", O1 L"(A;OI;KR;;;BU)", O1 L"(A;OI;KR;;;BU)" NOR, L"D:" O1 L"(A;OI;KR;;;BU)", L"D:PAI(A;CI;KA;;;SY)(A;CI;KR;;;WD)(A;OI;KR;;;BU)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;OIIOID;KR;;;BU)"},
    {L"AM-oi-exact", O1 L"(A;OI;KR;;;BU)", O1 L"(A;OI;KR;;;BU)" NOR, L"D:" O1 L"(A;OIIO;KR;;;BU)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;OIIOID;KR;;;BU)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;OIIOID;KR;;;BU)(A;CIID;KR;;;NO)"},
    {L"N1-pdeny-canon", L"(D;CI;KW;;;BU)" O1, L"(D;CI;KW;;;BU)" O1 NOR, L"D:(D;CI;KW;;;BU)" O1, L"D:AI(D;CIID;KW;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(D;CIID;KW;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"N2-pdeny-expden", L"(D;CI;KW;;;BU)" O1, L"(D;CI;KW;;;BU)" O1 NOR, L"D:(D;;KW;;;NU)(D;CI;KW;;;BU)" O1, L"D:AI(D;;KW;;;NU)(D;CIID;KW;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(D;CIID;KW;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"N3-pdeny-allow", L"(D;CI;KW;;;BU)" O1, L"(D;CI;KW;;;BU)" O1 NOR, L"D:(D;CI;KW;;;BU)" NUR SYF WDR, L"D:PAI(D;CI;KW;;;BU)(A;;KR;;;NU)(A;CI;KA;;;SY)(A;CI;KR;;;WD)", L"D:AI(D;CIID;KW;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"N4-expden-after", O1, O1 NOR, L"D:" O1 L"(D;;KW;;;NU)", L"D:PAI(A;CI;KA;;;SY)(A;CI;KR;;;WD)(D;;KW;;;NU)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"N5-allow-between", O1, O1 NOR, L"D:(D;;KW;;;NU)" SYF L"(A;;KR;;;BU)" WDR, L"D:AI(D;;KW;;;NU)(A;;KR;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    {L"N6-noncanon-lead", O1, O1 NOR, L"D:" NUR L"(D;;KW;;;BU)" O1, L"D:PAI(A;;KR;;;NU)(D;;KW;;;BU)(A;CI;KA;;;SY)(A;CI;KR;;;WD)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"N7-noncanon-trail", O1, O1 NOR, L"D:" NUR O1 L"(D;;KW;;;BU)", L"D:PAI(A;;KR;;;NU)(A;CI;KA;;;SY)(A;CI;KR;;;WD)(D;;KW;;;BU)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"N8-noncanon-nomatch", O1, O1 NOR, L"D:" NUR L"(D;;KW;;;BU)" SYF, L"D:PAI(A;;KR;;;NU)(D;;KW;;;BU)(A;CI;KA;;;SY)", L"D:AI(A;CIID;KA;;;SY)"},
    {L"N9-empty-old", L"", O1, L"D:" NUR, L"D:AI(A;;KR;;;NU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)", NULL},
    {L"N10-empty-old-e", L"", O1, L"D:", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)", NULL},
    {L"N15-empty-old-noncanon", L"", O1, L"D:" NUR L"(D;;KW;;;BU)", L"D:AI(A;;KR;;;NU)(D;;KW;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)", NULL},
    {L"N11-empty-set", L"", O1, L"D:" O1, L"D:AI(A;CI;KA;;;SY)(A;CI;KR;;;WD)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)", NULL},
    {L"N12-deny-mid-pdeny", L"(D;CI;KW;;;BU)" O1, L"(D;CI;KW;;;BU)" O1 NOR, L"D:(D;CI;KW;;;BU)" SYF L"(D;;KW;;;NU)" WDR, L"D:PAI(D;CI;KW;;;BU)(A;CI;KA;;;SY)(D;;KW;;;NU)(A;CI;KR;;;WD)", L"D:AI(D;CIID;KW;;;BU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)"},
    {L"Q1-ba-only", SYF BAF, SYF BAF NOR, L"D:" SYF BAF, L"D:AI(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIID;KR;;;NO)"},
    {L"Q2-ba-exp", SYF BAF, SYF BAF NOR, L"D:" NUR SYF BAF, L"D:AI(A;;KR;;;NU)(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIID;KR;;;NO)"},
    {L"Q3-deny-set", ANK SYF BAF, ANK SYF BAF NOR, L"D:" ANK SYF BAF, L"D:AI(D;CIID;KW;;;AN)(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIID;KR;;;NO)", L"D:AI(D;CIID;KW;;;AN)(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIID;KR;;;NO)"},
    {L"Q4-co-ci-set", SYF BAF COF, SYF BAF COF NOR, L"D:" SYF BAF L"(A;;KA;;;BA)" COF, L"D:AI(A;;KA;;;BA)(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;NO)"},
    {L"Q5-co-set-nu", SYF BAF COF, SYF BAF COF NOR, L"D:" NUR SYF BAF L"(A;;KA;;;BA)" COF, L"D:AI(A;;KR;;;NU)(A;;KA;;;BA)(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;NO)", L"D:AI(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;NO)"},
    {L"Q6-ka-sa", ANK SYF BAF COF, ANK SYF BAF COF NOR, L"D:" ANK SYF BAF L"(A;;KA;;;BA)" COF, L"D:PAI(D;CI;KW;;;AN)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;;KA;;;BA)(A;CIIO;KA;;;CO)", L"D:AI(D;CIID;KW;;;AN)(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIIOID;KA;;;CO)"},
    {L"Q7-ka-sa-nu", ANK SYF BAF COF, ANK SYF BAF COF NOR, L"D:" NUR ANK SYF BAF L"(A;;KA;;;BA)" COF, L"D:PAI(A;;KR;;;NU)(D;CI;KW;;;AN)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;;KA;;;BA)(A;CIIO;KA;;;CO)", L"D:AI(D;CIID;KW;;;AN)(A;CIID;KA;;;SY)(A;CIID;KA;;;BA)(A;CIIOID;KA;;;CO)"},
    {L"Q8-ka-no-ba", ANK SYF COF, ANK SYF COF NOR, L"D:" ANK SYF L"(A;;KA;;;BA)" COF, L"D:AI(D;CIID;KW;;;AN)(A;CIID;KA;;;SY)(A;ID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;NO)", L"D:AI(D;CIID;KW;;;AN)(A;CIID;KA;;;SY)(A;ID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KR;;;NO)"},
    {L"Q9-an-wd", ANK SYF WDR, ANK SYF WDR NOR, L"D:" ANK SYF WDR, L"D:AI(D;CIID;KW;;;AN)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", L"D:AI(D;CIID;KW;;;AN)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)"},
    };
    WCHAR Path[320], Sddl[1024], Name[16];
    BYTE Buffer[512];
    DWORD Length = sizeof(Buffer);
    LPWSTR OwnerSddl = NULL;
    BOOL OwnerIsAdmins = FALSE;
    HKEY Scratch = NULL, P = NULL, S = NULL, G = NULL;
    DWORD Error;
    ULONG i;

    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Scratch, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;
    /* CREATOR OWNER rows name the owner of the keys: Administrators for an elevated Administrator */
    if (RegGetKeySecurity(Scratch, OWNER_SECURITY_INFORMATION, Buffer, &Length) == ERROR_SUCCESS &&
        ConvertSecurityDescriptorToStringSecurityDescriptorW(Buffer, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION, &OwnerSddl, NULL))
    {
        OwnerIsAdmins = !wcsncmp(OwnerSddl, L"O:BA", 4);
        LocalFree(OwnerSddl);
    }

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        if (!OwnerIsAdmins && wcsstr(Rows[i].Old, L";;;CO)"))
        {
            skip("%ls: the keys are not owned by Administrators\n", Rows[i].Name);
            continue;
        }
        wsprintfW(Name, L"p%lu", i);
        if (!MakeKey(Scratch, Name, 0, &P))
            goto Done;
        /* the caller is granted nothing by what the parent passes on in some rows: it may create below the parent first */
        if (!SetSddlDacl(P, PROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;CI;KA;;;BA)") ||
            !MakeKey(P, L"s", 0, &S) || !MakeKey(S, L"g", 0, &G))
            goto Done;
        RegCloseKey(G);
        G = NULL;
        RegCloseKey(S);
        S = NULL;
        wsprintfW(Sddl, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)%ls", Rows[i].Old);
        ok(SetSddlDacl(P, PROTECTED_DACL_SECURITY_INFORMATION, Sddl), "%ls: old\n", Rows[i].Name);
        if (!RawSetSddl(P, L"s", Rows[i].S))
            goto Done;
        wsprintfW(Sddl, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)%ls", Rows[i].New);
        ok(SetSddlDacl(P, PROTECTED_DACL_SECURITY_INFORMATION, Sddl), "%ls: new\n", Rows[i].Name);
        RegCloseKey(P);
        P = NULL;

        wsprintfW(Path, L"%ls\\%ls\\s", ScratchPath, Name);
        trace("%ls\n", Rows[i].Name);
        DaclSddlIs(Path, Rows[i].ExpectedS, __LINE__);
        if (Rows[i].ExpectedG)
        {
            wsprintfW(Path, L"%ls\\%ls\\s\\g", ScratchPath, Name);
            DaclSddlIs(Path, Rows[i].ExpectedG, __LINE__);
        }
    }

Done:
    if (G) RegCloseKey(G);
    if (S) RegCloseKey(S);
    if (P) RegCloseKey(P);
    /* hand every key back to Administrators so that the tree can be deleted */
    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        static const PCWSTR Tails[] = {L"\\s\\g", L"\\s", L""};
        ULONG k;

        for (k = 0; k < ARRAYSIZE(Tails); k++)
        {
            wsprintfW(Path, L"%ls\\p%lu%ls", ScratchPath, i, Tails[k]);
            RestoreSddl(HKEY_CURRENT_USER, Path, DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)");
        }
    }
    if (Scratch) RegCloseKey(Scratch);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
}
#undef SYF
#undef WDR
#undef O1
#undef NUR
#undef NOR
#undef BAF
#undef ANK
#undef COF

/*
 * The same below a key the change converts (s: its subkey t holds the set s passed on, so it is converted too) and
 * below one it only flags (u: its subkey w holds what u passes on, and w is converted, matched against u's old DACL).
 * Measured on Windows Server 2022, x64 and x86.
 */
static void TestParentSetNested(void)
{
    static const PCWSTR Keys[] = {L"q\\s\\t", L"q\\s", L"q\\u\\w", L"q\\u", L"q"};
    WCHAR Path[320];
    HKEY Scratch = NULL, Q = NULL, Key = NULL;
    DWORD Error;
    ULONG i;

    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Scratch, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error || !MakeKey(Scratch, L"q", 0, &Q))
        goto Done;
    if (!SetSddlDacl(Q, PROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;CI;KA;;;BA)") ||
        !MakeKey(Q, L"s", 0, &Key))
        goto Done;
    RegCloseKey(Key);
    if (!MakeKey(Q, L"s\\t", 0, &Key))
        goto Done;
    RegCloseKey(Key);
    if (!MakeKey(Q, L"u", 0, &Key))
        goto Done;
    RegCloseKey(Key);
    if (!MakeKey(Q, L"u\\w", 0, &Key))
        goto Done;
    RegCloseKey(Key);
    ok(SetSddlDacl(Q, PROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;CI;KA;;;SY)(A;CI;KR;;;WD)"), "old\n");
    if (!RawSetSddl(Q, L"s\\t", L"D:(A;;KR;;;NU)(A;CI;KA;;;SY)(A;CI;KR;;;WD)") ||
        !RawSetSddl(Q, L"u", L"D:(A;;KR;;;NU)(A;CI;KR;;;BU)") ||
        !RawSetSddl(Q, L"u\\w", L"D:(A;;KR;;;NU)(A;CI;KR;;;BU)"))
        goto Done;
    ok(SetSddlDacl(Q, PROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;CI;KA;;;SY)(A;CI;KR;;;WD)(A;CI;KR;;;NO)"), "new\n");

    wsprintfW(Path, L"%ls\\q\\s", ScratchPath);
    DaclSddlIs(Path, L"D:AI(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", __LINE__);
    wsprintfW(Path, L"%ls\\q\\s\\t", ScratchPath);
    DaclSddlIs(Path, L"D:AI(A;;KR;;;NU)(A;CIID;KA;;;SY)(A;CIID;KR;;;WD)(A;CIID;KR;;;NO)", __LINE__);
    wsprintfW(Path, L"%ls\\q\\u", ScratchPath);
    DaclSddlIs(Path, L"D:PAI(A;;KR;;;NU)(A;CI;KR;;;BU)", __LINE__);
    wsprintfW(Path, L"%ls\\q\\u\\w", ScratchPath);
    DaclSddlIs(Path, L"D:AI(A;;KR;;;NU)(A;CIID;KR;;;BU)", __LINE__);

Done:
    if (Q) RegCloseKey(Q);
    for (i = 0; i < ARRAYSIZE(Keys); i++)
    {
        wsprintfW(Path, L"%ls\\%ls", ScratchPath, Keys[i]);
        RestoreSddl(HKEY_CURRENT_USER, Path, DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)");
    }
    if (Scratch) RegCloseKey(Scratch);
    RegDeleteTreeW(HKEY_CURRENT_USER, ScratchPath);
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
    TestGetUsesKeyOwner();
    TestOracleRows();
    TestHiveRoot();
    TestUnreadableParent();
    TestClosedSubkey();
    TestLegacySubkeys();
    TestParentSetMatch();
    TestParentSetNested();

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
