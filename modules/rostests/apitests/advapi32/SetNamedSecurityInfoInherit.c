/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for ACE inheritance flags in SetEntriesInAcl and for DACL inheritance in SetNamedSecurityInfo
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <aclapi.h>

#define INHERIT_BOTH (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE)

static PSID CreateSid(WELL_KNOWN_SID_TYPE Type)
{
    DWORD Size = SECURITY_MAX_SID_SIZE;
    PSID Sid = LocalAlloc(LPTR, Size);

    if (Sid && !CreateWellKnownSid(Type, NULL, Sid, &Size))
    {
        LocalFree(Sid);
        Sid = NULL;
    }
    return Sid;
}

static void MakeEntry(PEXPLICIT_ACCESS_W Entry, PSID Sid, DWORD Access, ACCESS_MODE Mode, DWORD Inheritance)
{
    ZeroMemory(Entry, sizeof(*Entry));
    Entry->grfAccessPermissions = Access;
    Entry->grfAccessMode = Mode;
    Entry->grfInheritance = Inheritance;
    Entry->Trustee.TrusteeForm = TRUSTEE_IS_SID;
    Entry->Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    Entry->Trustee.ptstrName = (LPWSTR)Sid;
}

static PACE_HEADER FindAce(PACL Acl, PSID Sid, UCHAR AceFlags, ACCESS_MASK Mask)
{
    DWORD i;

    for (i = 0; i < Acl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE Ace;

        if (GetAce(Acl, i, (PVOID *)&Ace) &&
            Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            Ace->Header.AceFlags == AceFlags &&
            Ace->Mask == Mask &&
            EqualSid((PSID)&Ace->SidStart, Sid))
        {
            return &Ace->Header;
        }
    }
    return NULL;
}

static BOOL HasInheritedEffectiveAce(PACL Acl, PSID Sid, ACCESS_MASK Mask)
{
    DWORD i;

    for (i = 0; i < Acl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE Ace;

        if (GetAce(Acl, i, (PVOID *)&Ace) &&
            Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            (Ace->Header.AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE)) == INHERITED_ACE &&
            Ace->Mask == Mask &&
            EqualSid((PSID)&Ace->SidStart, Sid))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL IsReactOS(void)
{
    HKEY Key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\ReactOS", 0, KEY_READ, &Key) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(Key);
    return TRUE;
}

/* ReactOS does not keep the control bits of a descriptor (known); anywhere else a missing bit is a failure */
static void CheckControl(PSECURITY_DESCRIPTOR Sd, WORD Bits, BOOL Expected, PCSTR What)
{
    SECURITY_DESCRIPTOR_CONTROL Control = 0;
    DWORD Revision;
    BOOL Got;

    if (!Sd || !GetSecurityDescriptorControl(Sd, &Control, &Revision))
    {
        ok(FALSE, "%s: no descriptor control\n", What);
        return;
    }
    Got = (Control & Bits) == Bits;
    if (Got == Expected)
        ok(TRUE, "%s\n", What);
    else if (IsReactOS() && Expected && !Got)
        skip("%s: control 0x%04x, the ReactOS kernel does not keep it (known)\n", What, Control);
    else
        ok(FALSE, "%s: control 0x%04x, bits 0x%04x expected %d\n", What, Control, Bits, Expected);
}

static BOOL DaclSupported(PCWSTR Dir)
{
    WCHAR Root[4] = L"C:\\";
    DWORD Flags = 0;

    Root[0] = Dir[0];
    if (!GetVolumeInformationW(Root, NULL, 0, NULL, NULL, &Flags, NULL, 0))
        return FALSE;

    return (Flags & FILE_PERSISTENT_ACLS) != 0;
}

static void TestSetEntries(PSID Admins, PSID Users)
{
    EXPLICIT_ACCESSW Entries[3];
    PACL Acl = NULL;
    PACCESS_ALLOWED_ACE Ace;
    DWORD Err;

    MakeEntry(&Entries[0], Admins, FILE_ALL_ACCESS, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
    MakeEntry(&Entries[1], Users, FILE_GENERIC_READ, GRANT_ACCESS, SUB_CONTAINERS_ONLY_INHERIT);
    MakeEntry(&Entries[2], Users, FILE_GENERIC_WRITE, DENY_ACCESS, NO_INHERITANCE);
    Err = SetEntriesInAclW(3, Entries, NULL, &Acl);
    ok_dec(Err, ERROR_SUCCESS);
    if (Err != ERROR_SUCCESS || !Acl)
        return;

    ok_dec((int)Acl->AceCount, 3);
    if (Acl->AceCount == 3)
    {
        /* the deny entry comes first */
        GetAce(Acl, 0, (PVOID *)&Ace);
        ok_dec(Ace->Header.AceType, ACCESS_DENIED_ACE_TYPE);
        ok_hex(Ace->Header.AceFlags, 0);
        GetAce(Acl, 1, (PVOID *)&Ace);
        ok_dec(Ace->Header.AceType, ACCESS_ALLOWED_ACE_TYPE);
        ok_hex(Ace->Header.AceFlags, INHERIT_BOTH);
        GetAce(Acl, 2, (PVOID *)&Ace);
        ok_hex(Ace->Header.AceFlags, CONTAINER_INHERIT_ACE);
    }
    LocalFree(Acl);
}

static void TestInheritance(PCWSTR Base, PSID Admins, PSID System, PSID Users)
{
    WCHAR Parent[MAX_PATH], Child[MAX_PATH], Child2[MAX_PATH], File[MAX_PATH], Path[MAX_PATH];
    EXPLICIT_ACCESSW Entries[3];
    PACL Acl = NULL, Dacl = NULL, Empty = NULL;
    ACL EmptyAcl;
    PSECURITY_DESCRIPTOR Sd = NULL;
    HANDLE Handle;
    DWORD Err;

    StringCchPrintfW(Parent, _countof(Parent), L"%ls\\parent", Base);
    StringCchPrintfW(Child, _countof(Child), L"%ls\\child", Parent);
    StringCchPrintfW(Child2, _countof(Child2), L"%ls\\child2", Parent);
    StringCchPrintfW(File, _countof(File), L"%ls\\file.txt", Parent);
    ok(CreateDirectoryW(Parent, NULL), "CreateDirectory failed with %lu\n", GetLastError());

    /* a protected DACL whose ACEs can be inherited */
    MakeEntry(&Entries[0], Admins, FILE_ALL_ACCESS, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
    MakeEntry(&Entries[1], System, FILE_ALL_ACCESS, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
    MakeEntry(&Entries[2], Users, GENERIC_READ | GENERIC_EXECUTE, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
    Err = SetEntriesInAclW(3, Entries, NULL, &Acl);
    ok_dec(Err, ERROR_SUCCESS);
    if (Err != ERROR_SUCCESS)
        return;
    Err = SetNamedSecurityInfoW(Parent, SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, Acl, NULL);
    ok_dec(Err, ERROR_SUCCESS);
    LocalFree(Acl);

    Err = GetNamedSecurityInfoW(Parent, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_dec(Err, ERROR_SUCCESS);
    ok(Dacl != NULL, "the parent has no DACL\n");
    if (Err == ERROR_SUCCESS && Dacl)
    {
        ok(FindAce(Dacl, Admins, INHERIT_BOTH, FILE_ALL_ACCESS) != NULL, "Administrators ACE lost its inheritance flags\n");
        ok(FindAce(Dacl, System, INHERIT_BOTH, FILE_ALL_ACCESS) != NULL, "SYSTEM ACE lost its inheritance flags\n");
    }
    CheckControl(Sd, SE_DACL_PROTECTED, TRUE, "the parent DACL is protected");
    if (Sd)
        LocalFree(Sd);

    /* reset a child directory to the inherited DACL with an empty, unprotected one (what the Burn engine does) */
    ok(CreateDirectoryW(Child, NULL), "CreateDirectory failed with %lu\n", GetLastError());
    InitializeAcl(&EmptyAcl, sizeof(EmptyAcl), ACL_REVISION);
    Err = SetNamedSecurityInfoW(Child, SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, &EmptyAcl, NULL);
    ok_dec(Err, ERROR_SUCCESS);

    Dacl = NULL;
    Sd = NULL;
    Err = GetNamedSecurityInfoW(Child, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_dec(Err, ERROR_SUCCESS);
    ok(Dacl != NULL, "the reset directory has no DACL\n");
    if (Err == ERROR_SUCCESS && Dacl)
    {
        ok(FindAce(Dacl, Admins, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) != NULL,
           "Administrators ACE was not inherited by the directory\n");
        ok(FindAce(Dacl, System, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) != NULL,
           "SYSTEM ACE was not inherited by the directory\n");
        /* Windows splits a generic inheritable ACE into an effective and an inherit-only ACE, ReactOS maps it in place */
        ok(HasInheritedEffectiveAce(Dacl, Users, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) ||
           FindAce(Dacl, Users, INHERIT_BOTH | INHERITED_ACE, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) != NULL,
           "ACE of Users was not inherited by the directory\n");
    }
    CheckControl(Sd, SE_DACL_PROTECTED, FALSE, "the reset directory DACL is not protected");
    CheckControl(Sd, SE_DACL_AUTO_INHERITED, TRUE, "the reset directory DACL is auto-inherited");
    if (Sd)
        LocalFree(Sd);

    /* the directory is usable */
    StringCchPrintfW(Path, _countof(Path), L"%ls\\x.txt", Child);
    Handle = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "creating a file in the reset directory failed with %lu\n", GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
        CloseHandle(Handle);
    DeleteFileW(Path);

    /* the same through an extended-length path */
    {
        WCHAR Child3[MAX_PATH], Extended[MAX_PATH + 8];

        StringCchPrintfW(Child3, _countof(Child3), L"%ls\\child3", Parent);
        StringCchPrintfW(Extended, _countof(Extended), L"\\\\?\\%ls", Child3);
        ok(CreateDirectoryW(Child3, NULL), "CreateDirectory failed with %lu\n", GetLastError());
        Err = SetNamedSecurityInfoW(Extended, SE_FILE_OBJECT,
                                    DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                    NULL, NULL, &EmptyAcl, NULL);
        ok_dec(Err, ERROR_SUCCESS);
        Dacl = NULL;
        Sd = NULL;
        Err = GetNamedSecurityInfoW(Child3, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
        ok_dec(Err, ERROR_SUCCESS);
        ok(Dacl != NULL, "the directory reset through an extended path has no DACL\n");
        if (Err == ERROR_SUCCESS && Dacl)
        {
            ok(FindAce(Dacl, Admins, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) != NULL,
               "Administrators ACE was not inherited through an extended path\n");
        }
        if (Sd)
            LocalFree(Sd);
        RemoveDirectoryW(Child3);
    }

    /* an extended path keeps its components: "p." and "p" are different directories there */
    {
        WCHAR Dir1[MAX_PATH + 8], Dir2[MAX_PATH + 8], Kid[MAX_PATH + 8];
        EXPLICIT_ACCESSW One;
        PACL OneAcl = NULL;

        StringCchPrintfW(Dir1, _countof(Dir1), L"\\\\?\\%ls\\p", Parent);
        StringCchPrintfW(Dir2, _countof(Dir2), L"\\\\?\\%ls\\p.", Parent);
        StringCchPrintfW(Kid, _countof(Kid), L"%ls\\kid", Dir2);
        ok(CreateDirectoryW(Dir1, NULL), "CreateDirectory failed with %lu\n", GetLastError());
        ok(CreateDirectoryW(Dir2, NULL), "CreateDirectory failed with %lu\n", GetLastError());

        /* "p" only grants SYSTEM, "p." only grants Administrators */
        MakeEntry(&One, System, FILE_ALL_ACCESS, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
        Err = SetEntriesInAclW(1, &One, NULL, &OneAcl);
        ok_dec(Err, ERROR_SUCCESS);
        Err = SetNamedSecurityInfoW(Dir1, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                    NULL, NULL, OneAcl, NULL);
        ok_dec(Err, ERROR_SUCCESS);
        LocalFree(OneAcl);
        OneAcl = NULL;
        MakeEntry(&One, Admins, FILE_ALL_ACCESS, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
        Err = SetEntriesInAclW(1, &One, NULL, &OneAcl);
        ok_dec(Err, ERROR_SUCCESS);
        Err = SetNamedSecurityInfoW(Dir2, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                    NULL, NULL, OneAcl, NULL);
        ok_dec(Err, ERROR_SUCCESS);
        LocalFree(OneAcl);

        if (CreateDirectoryW(Kid, NULL))
        {
            Err = SetNamedSecurityInfoW(Kid, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                        NULL, NULL, &EmptyAcl, NULL);
            ok_dec(Err, ERROR_SUCCESS);
            Dacl = NULL;
            Sd = NULL;
            Err = GetNamedSecurityInfoW(Kid, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
            ok_dec(Err, ERROR_SUCCESS);
            if (Err == ERROR_SUCCESS && Dacl)
            {
                ok(FindAce(Dacl, Admins, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) != NULL,
                   "the directory did not inherit from \"p.\"\n");
                ok(FindAce(Dacl, System, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) == NULL,
                   "the directory inherited from \"p\" instead of \"p.\"\n");
            }
            if (Sd)
                LocalFree(Sd);
            RemoveDirectoryW(Kid);
        }
        else
            ok(0, "CreateDirectory(kid) failed with %lu\n", GetLastError());
        RemoveDirectoryW(Dir2);
        RemoveDirectoryW(Dir1);
    }

    /* an empty name is an error, with the last error cleared before the call too */
    SetLastError(ERROR_SUCCESS);
    Err = SetNamedSecurityInfoW(L"", SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, &EmptyAcl, NULL);
    ok(Err != ERROR_SUCCESS, "an empty name succeeded\n");

    /* a relative name is resolved once: it works from the current directory */
    {
        WCHAR OldDir[MAX_PATH], Kid[MAX_PATH];
        DWORD OldLength;

        StringCchPrintfW(Kid, _countof(Kid), L"%ls\\relkid", Parent);
        ok(CreateDirectoryW(Kid, NULL), "CreateDirectory failed with %lu\n", GetLastError());
        OldLength = GetCurrentDirectoryW(_countof(OldDir), OldDir);
        if (OldLength == 0 || OldLength >= _countof(OldDir))
            skip("cannot save the current directory\n");
        else if (SetCurrentDirectoryW(Parent))
        {
            Err = SetNamedSecurityInfoW(L"relkid", SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                        NULL, NULL, &EmptyAcl, NULL);
            ok_dec(Err, ERROR_SUCCESS);
            ok(SetCurrentDirectoryW(OldDir), "cannot restore the current directory: %lu\n", GetLastError());
            Dacl = NULL;
            Sd = NULL;
            Err = GetNamedSecurityInfoW(Kid, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
            ok_dec(Err, ERROR_SUCCESS);
            ok(Dacl != NULL && FindAce(Dacl, Admins, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) != NULL,
               "the directory named relative to the current directory did not inherit\n");
            if (Sd)
                LocalFree(Sd);
        }
        RemoveDirectoryW(Kid);
    }

    /* "p" and "p." are different directories as extended paths. Whatever a DOS name with dots resolves to, the
       DACL must be written to the directory whose parent was read, never to another one */
    {
        WCHAR Dir1[MAX_PATH + 8], Dir2[MAX_PATH + 8], Kid1[MAX_PATH + 8], Kid2[MAX_PATH + 8], Dos[MAX_PATH];
        EXPLICIT_ACCESSW One;
        PACL OneAcl = NULL;
        PACL D1 = NULL, D2 = NULL;
        PSECURITY_DESCRIPTOR S1 = NULL, S2 = NULL;

        StringCchPrintfW(Dir1, _countof(Dir1), L"\\\\?\\%ls\\q", Parent);
        StringCchPrintfW(Dir2, _countof(Dir2), L"\\\\?\\%ls\\q.", Parent);
        StringCchPrintfW(Kid1, _countof(Kid1), L"%ls\\k", Dir1);
        StringCchPrintfW(Kid2, _countof(Kid2), L"%ls\\k", Dir2);
        StringCchPrintfW(Dos, _countof(Dos), L"%ls\\q..\\k", Parent);
        if (CreateDirectoryW(Dir1, NULL) && CreateDirectoryW(Dir2, NULL) && CreateDirectoryW(Kid1, NULL) && CreateDirectoryW(Kid2, NULL))
        {
            EXPLICIT_ACCESSW KidEntry;
            PACL KidAcl = NULL;
            int Changed = 0;
            DWORD DosErr;

            /* "q" grants SYSTEM, "q." grants Administrators; both children start with one distinct ACE of their own */
            MakeEntry(&One, System, FILE_ALL_ACCESS, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
            ok_dec(SetEntriesInAclW(1, &One, NULL, &OneAcl), ERROR_SUCCESS);
            ok_dec(SetNamedSecurityInfoW(Dir1, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                         NULL, NULL, OneAcl, NULL), ERROR_SUCCESS);
            LocalFree(OneAcl);
            OneAcl = NULL;
            MakeEntry(&One, Admins, FILE_ALL_ACCESS, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
            ok_dec(SetEntriesInAclW(1, &One, NULL, &OneAcl), ERROR_SUCCESS);
            ok_dec(SetNamedSecurityInfoW(Dir2, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                         NULL, NULL, OneAcl, NULL), ERROR_SUCCESS);
            LocalFree(OneAcl);

            MakeEntry(&KidEntry, Users, FILE_GENERIC_READ, GRANT_ACCESS, NO_INHERITANCE);
            ok_dec(SetEntriesInAclW(1, &KidEntry, NULL, &KidAcl), ERROR_SUCCESS);
            ok_dec(SetNamedSecurityInfoW(Kid1, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                         NULL, NULL, KidAcl, NULL), ERROR_SUCCESS);
            ok_dec(SetNamedSecurityInfoW(Kid2, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                         NULL, NULL, KidAcl, NULL), ERROR_SUCCESS);
            LocalFree(KidAcl);

            /* Windows finds no such path; either the name fails and nothing changes, or exactly one child changes */
            DosErr = SetNamedSecurityInfoW(Dos, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                           NULL, NULL, &EmptyAcl, NULL);

            ok_dec(GetNamedSecurityInfoW(Kid1, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &D1, NULL, &S1), ERROR_SUCCESS);
            ok_dec(GetNamedSecurityInfoW(Kid2, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &D2, NULL, &S2), ERROR_SUCCESS);
            ok(D1 != NULL && D2 != NULL, "a child has no DACL\n");
            if (D1 && D2)
            {
                BOOL Kid1Changed = D1->AceCount != 1 || FindAce(D1, Users, 0, FILE_GENERIC_READ) == NULL;
                BOOL Kid2Changed = D2->AceCount != 1 || FindAce(D2, Users, 0, FILE_GENERIC_READ) == NULL;

                Changed = Kid1Changed + Kid2Changed;
                ok(Changed == (DosErr == ERROR_SUCCESS ? 1 : 0), "the name returned %lu and %d children changed\n", DosErr, Changed);
                /* the one that changed took its own parent's ACE and only that one */
                if (Kid1Changed)
                {
                    ok(FindAce(D1, System, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) != NULL, "q\\k did not inherit from q\n");
                    ok(FindAce(D1, Admins, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) == NULL, "q\\k got an ACE that only q. grants\n");
                }
                if (Kid2Changed)
                {
                    ok(FindAce(D2, Admins, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) != NULL, "q.\\k did not inherit from q.\n");
                    ok(FindAce(D2, System, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) == NULL, "q.\\k got an ACE that only q grants\n");
                }
            }
            if (S1)
                LocalFree(S1);
            if (S2)
                LocalFree(S2);
        }
        else
            skip("cannot create the q and q. directories: %lu\n", GetLastError());
        RemoveDirectoryW(Kid1);
        RemoveDirectoryW(Kid2);
        RemoveDirectoryW(Dir1);
        RemoveDirectoryW(Dir2);
    }

    /* an explicit ACE with UNPROTECTED comes first and the parent's ACEs follow */
    ok(CreateDirectoryW(Child2, NULL), "CreateDirectory failed with %lu\n", GetLastError());
    MakeEntry(&Entries[0], Users, FILE_GENERIC_READ, GRANT_ACCESS, NO_INHERITANCE);
    Err = SetEntriesInAclW(1, Entries, NULL, &Acl);
    ok_dec(Err, ERROR_SUCCESS);
    Err = SetNamedSecurityInfoW(Child2, SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, Acl, NULL);
    ok_dec(Err, ERROR_SUCCESS);
    LocalFree(Acl);
    Dacl = NULL;
    Sd = NULL;
    Err = GetNamedSecurityInfoW(Child2, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_dec(Err, ERROR_SUCCESS);
    ok(Dacl != NULL, "the directory with an explicit ACE has no DACL\n");
    if (Err == ERROR_SUCCESS && Dacl)
    {
        PACCESS_ALLOWED_ACE First;

        ok(Dacl->AceCount > 1, "only %u ACEs\n", Dacl->AceCount);
        if (GetAce(Dacl, 0, (PVOID *)&First))
        {
            ok_hex(First->Header.AceFlags, 0);
            ok_hex(First->Mask, FILE_GENERIC_READ);
        }
        ok(FindAce(Dacl, Admins, INHERIT_BOTH | INHERITED_ACE, FILE_ALL_ACCESS) != NULL,
           "Administrators ACE was not inherited next to the explicit ACE\n");
    }
    if (Sd)
        LocalFree(Sd);

    /* a file takes only the ACEs that objects inherit, as effective ACEs */
    Handle = CreateFileW(File, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "CreateFile failed with %lu\n", GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(Handle);
        Err = SetNamedSecurityInfoW(File, SE_FILE_OBJECT,
                                    DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                    NULL, NULL, &EmptyAcl, NULL);
        ok_dec(Err, ERROR_SUCCESS);
        Dacl = NULL;
        Sd = NULL;
        Err = GetNamedSecurityInfoW(File, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
        ok_dec(Err, ERROR_SUCCESS);
        ok(Dacl != NULL, "the reset file has no DACL\n");
        if (Err == ERROR_SUCCESS && Dacl)
        {
            ok(FindAce(Dacl, Admins, INHERITED_ACE, FILE_ALL_ACCESS) != NULL, "file did not inherit the Administrators ACE\n");
            ok(HasInheritedEffectiveAce(Dacl, Users, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE),
               "file did not inherit the effective ACE of Users\n");
        }
        if (Sd)
            LocalFree(Sd);
    }

    /* a protected DACL keeps exactly the ACEs given */
    MakeEntry(&Entries[0], Users, FILE_GENERIC_READ, GRANT_ACCESS, NO_INHERITANCE);
    Err = SetEntriesInAclW(1, Entries, NULL, &Empty);
    ok_dec(Err, ERROR_SUCCESS);
    Err = SetNamedSecurityInfoW(Child2, SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, Empty, NULL);
    ok_dec(Err, ERROR_SUCCESS);
    LocalFree(Empty);
    Dacl = NULL;
    Sd = NULL;
    Err = GetNamedSecurityInfoW(Child2, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_dec(Err, ERROR_SUCCESS);
    ok(Dacl != NULL, "the protected directory has no DACL\n");
    if (Err == ERROR_SUCCESS && Dacl)
    {
        ok_dec((int)Dacl->AceCount, 1);
        ok(FindAce(Dacl, Users, 0, FILE_GENERIC_READ) != NULL, "the protected DACL lost its only ACE\n");
    }
    CheckControl(Sd, SE_DACL_PROTECTED, TRUE, "the protected directory DACL is protected");
    if (Sd)
        LocalFree(Sd);

    /* a SACL given with the unprotected DACL keeps its own protection bit */
    {
        HANDLE Token;
        TOKEN_PRIVILEGES Priv;
        ACL Sacl;
        PACL OutSacl = NULL;
        BOOL HavePrivilege = FALSE;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        {
            Priv.PrivilegeCount = 1;
            Priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValueW(NULL, L"SeSecurityPrivilege", &Priv.Privileges[0].Luid))
            {
                AdjustTokenPrivileges(Token, FALSE, &Priv, 0, NULL, NULL);
                HavePrivilege = GetLastError() == ERROR_SUCCESS;
            }
            CloseHandle(Token);
        }

        if (!HavePrivilege)
        {
            skip("no SeSecurityPrivilege\n");
        }
        else
        {
            InitializeAcl(&Sacl, sizeof(Sacl), ACL_REVISION);
            Err = SetNamedSecurityInfoW(Child2, SE_FILE_OBJECT,
                                        DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION |
                                        SACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION,
                                        NULL, NULL, &EmptyAcl, &Sacl);
            ok_dec(Err, ERROR_SUCCESS);
            Sd = NULL;
            Err = GetNamedSecurityInfoW(Child2, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &OutSacl, &Sd);
            ok_dec(Err, ERROR_SUCCESS);
            CheckControl(Sd, SE_SACL_PROTECTED, TRUE, "the SACL is protected");
            if (Sd)
                LocalFree(Sd);
        }
    }

    /* clean up: the parent DACL grants Administrators full control */
    DeleteFileW(File);
    RemoveDirectoryW(Child2);
    RemoveDirectoryW(Child);
    RemoveDirectoryW(Parent);
}

static void TestVolumeRootChild(PCWSTR Base, PSID Admins)
{
    WCHAR Root[4] = L"C:\\";
    WCHAR Child[MAX_PATH];
    ACL EmptyAcl;
    PACL Dacl = NULL;
    PSECURITY_DESCRIPTOR Sd = NULL;
    BOOL RootInherits = FALSE;
    DWORD Err, i;

    Root[0] = Base[0];
    Err = GetNamedSecurityInfoW(Root, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    if (Err != ERROR_SUCCESS || !Dacl)
    {
        skip("cannot read the DACL of %ls: %lu\n", Root, Err);
        if (Sd)
            LocalFree(Sd);
        return;
    }
    for (i = 0; i < Dacl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE Ace;

        if (GetAce(Dacl, i, (PVOID *)&Ace) && Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            (Ace->Header.AceFlags & CONTAINER_INHERIT_ACE) && !(Ace->Header.AceFlags & INHERIT_ONLY_ACE))
        {
            RootInherits = TRUE;
        }
    }
    LocalFree(Sd);
    if (!RootInherits)
    {
        skip("the root of the volume has no inheritable ACE\n");
        return;
    }

    StringCchPrintfW(Child, _countof(Child), L"%lssni-root-%lu-%lu", Root, GetCurrentProcessId(), GetTickCount());
    if (!CreateDirectoryW(Child, NULL))
    {
        skip("cannot create %ls: %lu\n", Child, GetLastError());
        return;
    }

    InitializeAcl(&EmptyAcl, sizeof(EmptyAcl), ACL_REVISION);
    Err = SetNamedSecurityInfoW(Child, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, &EmptyAcl, NULL);
    ok_dec(Err, ERROR_SUCCESS);
    Dacl = NULL;
    Sd = NULL;
    Err = GetNamedSecurityInfoW(Child, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_dec(Err, ERROR_SUCCESS);
    ok(Dacl != NULL && Dacl->AceCount > 0, "a directory in the volume root inherited nothing\n");
    if (Dacl)
    {
        BOOL Inherited = FALSE;

        for (i = 0; i < Dacl->AceCount; i++)
        {
            PACE_HEADER Ace;

            if (GetAce(Dacl, i, (PVOID *)&Ace) && (Ace->AceFlags & INHERITED_ACE))
                Inherited = TRUE;
        }
        ok(Inherited, "no ACE of the directory in the volume root is marked inherited\n");
    }
    if (Sd)
        LocalFree(Sd);
    RemoveDirectoryW(Child);
    UNREFERENCED_PARAMETER(Admins);
}

/*
 * WiX Burn resets the permissions of its cached files with an ACL structure it never initialized (all zero):
 * the call succeeds and the object ends up with the inherited ACEs only.
 */
static void TestZeroAcl(PCWSTR Base, PSID Users)
{
    WCHAR Dir[MAX_PATH];
    EXPLICIT_ACCESSW Entry;
    SECURITY_DESCRIPTOR_CONTROL Control;
    PACL Explicit = NULL, Dacl = NULL;
    PSECURITY_DESCRIPTOR Sd = NULL;
    ACL Zero;
    DWORD Err, Revision, i;
    BOOL AllInherited = TRUE;

    StringCchPrintfW(Dir, _countof(Dir), L"%ls\\zeroacl", Base);
    if (!CreateDirectoryW(Dir, NULL))
    {
        skip("cannot create %ls: %lu\n", Dir, GetLastError());
        return;
    }

    /* the directory has one explicit ACE and no inherited ones */
    MakeEntry(&Entry, Users, FILE_GENERIC_READ, GRANT_ACCESS, NO_INHERITANCE);
    Err = SetEntriesInAclW(1, &Entry, NULL, &Explicit);
    ok_dec(Err, ERROR_SUCCESS);
    if (Err != ERROR_SUCCESS)
        goto Done;
    Err = SetNamedSecurityInfoW(Dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, Explicit, NULL);
    ok_dec(Err, ERROR_SUCCESS);
    LocalFree(Explicit);
    Err = GetNamedSecurityInfoW(Dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_dec(Err, ERROR_SUCCESS);
    if (Err != ERROR_SUCCESS || !Dacl)
        goto Done;
    ok_dec((int)Dacl->AceCount, 1);
    ok(FindAce(Dacl, Users, 0, FILE_GENERIC_READ) != NULL, "the explicit ACE is missing\n");
    LocalFree(Sd);
    Sd = NULL;

    ZeroMemory(&Zero, sizeof(Zero));
    Err = SetNamedSecurityInfoW(Dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, &Zero, NULL);
    ok_dec(Err, ERROR_SUCCESS);

    Dacl = NULL;
    Err = GetNamedSecurityInfoW(Dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok_dec(Err, ERROR_SUCCESS);
    if (Err != ERROR_SUCCESS || !Dacl)
        goto Done;
    ok(Dacl->AceCount > 0, "the directory inherited nothing\n");
    ok(FindAce(Dacl, Users, 0, FILE_GENERIC_READ) == NULL, "the explicit ACE is still there\n");
    for (i = 0; i < Dacl->AceCount; i++)
    {
        PACE_HEADER Ace;

        if (GetAce(Dacl, i, (PVOID *)&Ace) && !(Ace->AceFlags & INHERITED_ACE))
            AllInherited = FALSE;
    }
    ok(AllInherited, "an ACE of the directory is not inherited\n");
    ok(GetSecurityDescriptorControl(Sd, &Control, &Revision), "no descriptor control\n");
    ok(!(Control & SE_DACL_PROTECTED), "the DACL is still protected, control 0x%04x\n", Control);

Done:
    if (Sd)
        LocalFree(Sd);
    RemoveDirectoryW(Dir);
}

START_TEST(SetNamedSecurityInfoInherit)
{
    WCHAR Temp[MAX_PATH], Base[MAX_PATH];
    PSID Admins = CreateSid(WinBuiltinAdministratorsSid);
    PSID System = CreateSid(WinLocalSystemSid);
    PSID Users = CreateSid(WinBuiltinUsersSid);

    if (!Admins || !System || !Users)
    {
        skip("could not create the well-known SIDs\n");
        LocalFree(Admins);
        LocalFree(System);
        LocalFree(Users);
        return;
    }

    TestSetEntries(Admins, Users);

    GetTempPathW(_countof(Temp), Temp);
    StringCchPrintfW(Base, _countof(Base), L"%lssni-%lu-%lu", Temp, GetCurrentProcessId(), GetTickCount());
    if (!CreateDirectoryW(Base, NULL))
    {
        skip("cannot create %ls: %lu\n", Base, GetLastError());
        LocalFree(Admins);
        LocalFree(System);
        LocalFree(Users);
        return;
    }

    if (!DaclSupported(Base))
        skip("the volume of %ls does not keep ACLs\n", Base);
    else
    {
        TestInheritance(Base, Admins, System, Users);
        TestVolumeRootChild(Base, Admins);
        TestZeroAcl(Base, Users);
    }

    RemoveDirectoryW(Base);
    LocalFree(Admins);
    LocalFree(System);
    LocalFree(Users);
}
