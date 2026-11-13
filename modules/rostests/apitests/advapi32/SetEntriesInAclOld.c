/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the entries of the old ACL that SetEntriesInAcl keeps
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <aclapi.h>

typedef struct _EXPECTED_ACE
{
    UCHAR Type;
    UCHAR Flags;
    ACCESS_MASK Mask;
    WELL_KNOWN_SID_TYPE Sid;
} EXPECTED_ACE;

static PSID MakeSid(WELL_KNOWN_SID_TYPE Type)
{
    DWORD Size = SECURITY_MAX_SID_SIZE;
    PSID Sid = LocalAlloc(LPTR, Size);

    if (Sid && !CreateWellKnownSid(Type, NULL, Sid, &Size))
    {
        LocalFree(Sid);
        return NULL;
    }
    return Sid;
}

static void Entry(PEXPLICIT_ACCESSW E, PSID Sid, DWORD Mask, ACCESS_MODE Mode, DWORD Inheritance)
{
    ZeroMemory(E, sizeof(*E));
    E->grfAccessPermissions = Mask;
    E->grfAccessMode = Mode;
    E->grfInheritance = Inheritance;
    E->Trustee.TrusteeForm = TRUSTEE_IS_SID;
    E->Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    E->Trustee.ptstrName = (LPWSTR)Sid;
}

static void Check(PCSTR Name, PACL Acl, const EXPECTED_ACE *Expected, ULONG Count)
{
    ULONG i;

    ok(Acl != NULL, "%s: no ACL\n", Name);
    if (!Acl)
        return;
    ok_dec((int)Acl->AceCount, (int)Count);
    for (i = 0; i < Count && i < Acl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE Ace;
        PSID Sid = MakeSid(Expected[i].Sid);

        ok(GetAce(Acl, i, (PVOID *)&Ace), "%s: GetAce(%lu) failed\n", Name, i);
        ok(Ace->Header.AceType == Expected[i].Type, "%s: ACE %lu has type %u, expected %u\n",
           Name, i, Ace->Header.AceType, Expected[i].Type);
        ok(Ace->Header.AceFlags == Expected[i].Flags, "%s: ACE %lu has flags 0x%x, expected 0x%x\n",
           Name, i, Ace->Header.AceFlags, Expected[i].Flags);
        ok(Ace->Mask == Expected[i].Mask, "%s: ACE %lu has mask 0x%08lx, expected 0x%08lx\n",
           Name, i, Ace->Mask, Expected[i].Mask);
        ok(Sid && EqualSid((PSID)&Ace->SidStart, Sid), "%s: ACE %lu has another SID\n", Name, i);
        LocalFree(Sid);
    }
}

START_TEST(SetEntriesInAclOld)
{
    PSID Admins = MakeSid(WinBuiltinAdministratorsSid);
    PSID System = MakeSid(WinLocalSystemSid);
    PSID Users = MakeSid(WinBuiltinUsersSid);
    PSID World = MakeSid(WinWorldSid);
    EXPLICIT_ACCESSW E[2];
    PACL Old = NULL, New = NULL;
    DWORD Err;

    if (!Admins || !System || !Users || !World)
    {
        skip("could not create the well-known SIDs\n");
        goto Done;
    }

    Entry(&E[0], Admins, FILE_ALL_ACCESS, GRANT_ACCESS, NO_INHERITANCE);
    Entry(&E[1], System, FILE_ALL_ACCESS, GRANT_ACCESS, NO_INHERITANCE);
    Err = SetEntriesInAclW(2, E, NULL, &Old);
    ok_dec(Err, ERROR_SUCCESS);
    if (Err != ERROR_SUCCESS)
        goto Done;

    {
        static const EXPECTED_ACE Expected[] =
        {
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_GENERIC_READ & ~SYNCHRONIZE, WinBuiltinUsersSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinBuiltinAdministratorsSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinLocalSystemSid },
        };

        /* the new entry comes first, the old entries follow */
        Entry(&E[0], Users, FILE_GENERIC_READ & ~SYNCHRONIZE, GRANT_ACCESS, NO_INHERITANCE);
        Err = SetEntriesInAclW(1, E, Old, &New);
        ok_dec(Err, ERROR_SUCCESS);
        Check("grant", New, Expected, _countof(Expected));
        LocalFree(New);
        New = NULL;
    }

    {
        static const EXPECTED_ACE Expected[] =
        {
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_GENERIC_READ & ~SYNCHRONIZE, WinBuiltinAdministratorsSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinLocalSystemSid },
        };

        /* SET_ACCESS replaces the old entries of that trustee */
        Entry(&E[0], Admins, FILE_GENERIC_READ & ~SYNCHRONIZE, SET_ACCESS, NO_INHERITANCE);
        Err = SetEntriesInAclW(1, E, Old, &New);
        ok_dec(Err, ERROR_SUCCESS);
        Check("set", New, Expected, _countof(Expected));
        LocalFree(New);
        New = NULL;
    }

    {
        static const EXPECTED_ACE Expected[] =
        {
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinBuiltinAdministratorsSid },
        };

        /* REVOKE_ACCESS removes them */
        Entry(&E[0], System, 0, REVOKE_ACCESS, NO_INHERITANCE);
        Err = SetEntriesInAclW(1, E, Old, &New);
        ok_dec(Err, ERROR_SUCCESS);
        Check("revoke", New, Expected, _countof(Expected));
        LocalFree(New);
        New = NULL;
    }

    {
        static const EXPECTED_ACE Expected[] =
        {
            { ACCESS_DENIED_ACE_TYPE, 0, FILE_GENERIC_WRITE & ~SYNCHRONIZE, WinBuiltinUsersSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinBuiltinAdministratorsSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinLocalSystemSid },
        };

        Entry(&E[0], Users, FILE_GENERIC_WRITE & ~SYNCHRONIZE, DENY_ACCESS, NO_INHERITANCE);
        Err = SetEntriesInAclW(1, E, Old, &New);
        ok_dec(Err, ERROR_SUCCESS);
        Check("deny", New, Expected, _countof(Expected));
        LocalFree(New);
        New = NULL;
    }

    {
        static const EXPECTED_ACE Expected[] =
        {
            { ACCESS_DENIED_ACE_TYPE, 0, FILE_GENERIC_WRITE & ~SYNCHRONIZE, WinBuiltinUsersSid },
            { ACCESS_ALLOWED_ACE_TYPE, SUB_CONTAINERS_AND_OBJECTS_INHERIT, FILE_GENERIC_READ & ~SYNCHRONIZE, WinWorldSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinBuiltinAdministratorsSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinLocalSystemSid },
        };

        /* new denied, new allowed, then the old entries */
        Entry(&E[0], World, FILE_GENERIC_READ & ~SYNCHRONIZE, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
        Entry(&E[1], Users, FILE_GENERIC_WRITE & ~SYNCHRONIZE, DENY_ACCESS, NO_INHERITANCE);
        Err = SetEntriesInAclW(2, E, Old, &New);
        ok_dec(Err, ERROR_SUCCESS);
        Check("grant and deny", New, Expected, _countof(Expected));
        LocalFree(New);
        New = NULL;
    }

    /* an old denied entry stays before the new allowed one */
    {
        PACL Denied = NULL;
        static const EXPECTED_ACE Expected[] =
        {
            { ACCESS_DENIED_ACE_TYPE, 0, DELETE, WinBuiltinUsersSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_GENERIC_READ & ~SYNCHRONIZE, WinWorldSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinBuiltinAdministratorsSid },
        };

        Entry(&E[0], Users, DELETE, DENY_ACCESS, NO_INHERITANCE);
        Entry(&E[1], Admins, FILE_ALL_ACCESS, GRANT_ACCESS, NO_INHERITANCE);
        Err = SetEntriesInAclW(2, E, NULL, &Denied);
        ok_dec(Err, ERROR_SUCCESS);
        Entry(&E[0], World, FILE_GENERIC_READ & ~SYNCHRONIZE, GRANT_ACCESS, NO_INHERITANCE);
        Err = SetEntriesInAclW(1, E, Denied, &New);
        ok_dec(Err, ERROR_SUCCESS);
        Check("old deny", New, Expected, _countof(Expected));
        LocalFree(New);
        LocalFree(Denied);
        New = NULL;
    }

    /* REVOKE_ACCESS removes the allowed entries of the trustee, its denied entries stay */
    {
        PACL Mixed = NULL;
        static const EXPECTED_ACE Expected[] =
        {
            { ACCESS_DENIED_ACE_TYPE, 0, FILE_GENERIC_WRITE & ~SYNCHRONIZE, WinBuiltinUsersSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinBuiltinAdministratorsSid },
        };
        static const EXPECTED_ACE Unchanged[] =
        {
            { ACCESS_DENIED_ACE_TYPE, 0, FILE_GENERIC_WRITE & ~SYNCHRONIZE, WinBuiltinUsersSid },
            { ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, WinBuiltinAdministratorsSid },
        };

        Entry(&E[0], Users, FILE_GENERIC_WRITE & ~SYNCHRONIZE, DENY_ACCESS, NO_INHERITANCE);
        Entry(&E[1], Users, FILE_GENERIC_READ & ~SYNCHRONIZE, GRANT_ACCESS, NO_INHERITANCE);
        Err = SetEntriesInAclW(2, E, Old, &Mixed);
        ok_dec(Err, ERROR_SUCCESS);
        if (Err == ERROR_SUCCESS)
        {
            ok_dec((int)Mixed->AceCount, 4);

            Entry(&E[0], Users, 0, REVOKE_ACCESS, NO_INHERITANCE);
            Err = SetEntriesInAclW(1, E, Mixed, &New);
            ok_dec(Err, ERROR_SUCCESS);
            /* Old only has Admins and System: remove System as well to compare with Expected */
            if (New)
            {
                LocalFree(Mixed);
                Mixed = New;
                New = NULL;
                Entry(&E[0], System, 0, REVOKE_ACCESS, NO_INHERITANCE);
                Err = SetEntriesInAclW(1, E, Mixed, &New);
                ok_dec(Err, ERROR_SUCCESS);
                Check("revoke keeps deny", New, Expected, _countof(Expected));

                /* a trustee that has only a denied entry loses nothing */
                Entry(&E[0], Users, 0, REVOKE_ACCESS, NO_INHERITANCE);
                LocalFree(Mixed);
                Mixed = New;
                New = NULL;
                Err = SetEntriesInAclW(1, E, Mixed, &New);
                ok_dec(Err, ERROR_SUCCESS);
                Check("revoke deny only", New, Unchanged, _countof(Unchanged));
                LocalFree(New);
                New = NULL;
            }
        }
        LocalFree(Mixed);
    }

Done:
    LocalFree(Old);
    LocalFree(Admins);
    LocalFree(System);
    LocalFree(Users);
    LocalFree(World);
}
