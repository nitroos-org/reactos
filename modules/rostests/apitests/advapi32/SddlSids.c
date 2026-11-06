/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SDDL strings with literal SIDs in any position, and SDDL round trips
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>
#include <strsafe.h>

static const WCHAR *s_Aliases[] =
{
    L"WD", L"CO", L"CG", L"OW", L"NU", L"IU", L"SU", L"AN", L"ED", L"PS", L"AU", L"RC",
    L"SY", L"LS", L"NS", L"BA", L"BU", L"BG", L"PU", L"AO", L"SO", L"PO", L"BO", L"RE",
    L"RU", L"RD", L"NO", L"LW", L"ME", L"HI", L"SI", L"AC"
};

static const WCHAR *s_Literals[] =
{
    L"S-1-5-18",
    L"S-1-5-32-544",
    L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",   /* a service SID */
    L"S-1-5-83-1-123456789-2-3-4",
    L"S-1-5-21-1253675753-2377331658-4097264211-1000",
    L"S-1-15-2-1",
    L"S-1-5-4"
};

static PSID MakeSid(PCWSTR Str)
{
    PSID Sid = NULL;

    ok(ConvertStringSidToSidW(Str, &Sid), "ConvertStringSidToSidW(%ls) failed, error %lu\n", Str, GetLastError());
    return Sid;
}

static void CheckAces(PCWSTR Sddl, PACL Dacl, ULONG Count, PSID *Sids, const ACCESS_MASK *Masks, const BYTE *Flags)
{
    ULONG i;

    ok(Dacl && Dacl->AceCount == Count, "[%ls] %u ACEs, expected %lu\n", Sddl, Dacl ? Dacl->AceCount : 0, Count);
    if (!Dacl || Dacl->AceCount != Count)
        return;

    for (i = 0; i < Count; i++)
    {
        PACCESS_ALLOWED_ACE Ace = NULL;

        ok(GetAce(Dacl, i, (PVOID *)&Ace) && Ace, "[%ls] no ACE %lu\n", Sddl, i);
        if (!Ace)
            continue;
        ok(Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "[%ls] ACE %lu type %u\n", Sddl, i, Ace->Header.AceType);
        ok(Ace->Header.AceFlags == Flags[i], "[%ls] ACE %lu flags 0x%x, expected 0x%x\n", Sddl, i, Ace->Header.AceFlags, Flags[i]);
        ok(Ace->Mask == Masks[i], "[%ls] ACE %lu mask 0x%lx, expected 0x%lx\n", Sddl, i, Ace->Mask, Masks[i]);
        ok(EqualSid((PSID)&Ace->SidStart, Sids[i]), "[%ls] ACE %lu has the wrong SID\n", Sddl, i);
        ok(Ace->Header.AceSize == FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + GetLengthSid(Sids[i]),
           "[%ls] ACE %lu size %u\n", Sddl, i, Ace->Header.AceSize);
    }
}

static void TestMixedAces(void)
{
    ULONG a, l;

    /* every alias next to every literal, in both orders, in first, middle and last position */
    for (a = 0; a < ARRAYSIZE(s_Aliases); a++)
    {
        for (l = 0; l < ARRAYSIZE(s_Literals); l++)
        {
            WCHAR Sddl[512];
            PSID Sids[3];
            static const ACCESS_MASK Masks[3] = { GENERIC_READ, GENERIC_WRITE | 0x1, GENERIC_EXECUTE };
            static const BYTE Flags[3] = { 0, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE };
            PSECURITY_DESCRIPTOR Sd = NULL;
            PACL Dacl = NULL;
            BOOL Present, Defaulted;
            ULONG i;

            Sids[0] = MakeSid(s_Literals[l]);
            Sids[1] = MakeSid(s_Aliases[a]);
            Sids[2] = MakeSid(s_Literals[(l + 1) % ARRAYSIZE(s_Literals)]);

            StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"D:(A;;GR;;;%ls)(A;OICI;GW0x1;;;%ls)(A;CIIO;GX;;;%ls)",
                      s_Literals[l], s_Aliases[a], s_Literals[(l + 1) % ARRAYSIZE(s_Literals)]);
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
            {
                ok(GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted) && Present, "[%ls] no DACL\n", Sddl);
                CheckAces(Sddl, Dacl, 3, Sids, Masks, Flags);
                LocalFree(Sd);
            }
            else
                ok(0, "[%ls] failed, error %lu\n", Sddl, GetLastError());

            /* and literal, literal, alias, literal */
            StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"D:(A;;GR;;;%ls)(A;OICI;GW0x1;;;%ls)(A;CIIO;GX;;;%ls)",
                      s_Aliases[a], s_Literals[l], s_Aliases[(a + 1) % ARRAYSIZE(s_Aliases)]);
            Sids[0] = MakeSid(s_Aliases[a]);
            Sids[1] = MakeSid(s_Literals[l]);
            Sids[2] = MakeSid(s_Aliases[(a + 1) % ARRAYSIZE(s_Aliases)]);
            Sd = NULL;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
            {
                ok(GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted) && Present, "[%ls] no DACL\n", Sddl);
                CheckAces(Sddl, Dacl, 3, Sids, Masks, Flags);
                LocalFree(Sd);
            }
            else
                ok(0, "[%ls] failed, error %lu\n", Sddl, GetLastError());
            for (i = 0; i < 3; i++)
                LocalFree(Sids[i]);
        }
    }
}

static void TestOwnerGroupAndSacl(void)
{
    static const WCHAR Sddl[] =
        L"O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        L"G:S-1-5-32-544"
        L"D:PAI(A;;FA;;;S-1-5-18)(A;;FR;;;S-1-5-32-544)(D;;FW;;;S-1-5-4)"
        L"S:(AU;SAFA;FW;;;S-1-1-0)(AU;FA;FR;;;S-1-5-11)";
    PSECURITY_DESCRIPTOR Sd = NULL;
    PSID Owner, Group, Expected;
    PACL Dacl, Sacl;
    BOOL Present, Defaulted;
    PACCESS_ALLOWED_ACE Ace;

    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL), "failed, error %lu\n", GetLastError());
    if (!Sd)
        return;

    ok(GetSecurityDescriptorOwner(Sd, &Owner, &Defaulted) && Owner, "no owner\n");
    Expected = MakeSid(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    ok(Owner && EqualSid(Owner, Expected), "wrong owner\n");
    LocalFree(Expected);

    ok(GetSecurityDescriptorGroup(Sd, &Group, &Defaulted) && Group, "no group\n");
    Expected = MakeSid(L"S-1-5-32-544");
    ok(Group && EqualSid(Group, Expected), "wrong group\n");
    LocalFree(Expected);

    ok(GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted) && Present && Dacl, "no DACL\n");
    ok(Dacl && Dacl->AceCount == 3, "DACL has %u ACEs\n", Dacl ? Dacl->AceCount : 0);
    if (Dacl && Dacl->AceCount == 3)
    {
        static const WCHAR *Want[3] = { L"S-1-5-18", L"S-1-5-32-544", L"S-1-5-4" };
        ULONG i;

        for (i = 0; i < 3; i++)
        {
            Expected = MakeSid(Want[i]);
            ok(GetAce(Dacl, i, (PVOID *)&Ace) && EqualSid((PSID)&Ace->SidStart, Expected), "DACL ACE %lu has the wrong SID\n", i);
            LocalFree(Expected);
        }
    }

    ok(GetSecurityDescriptorSacl(Sd, &Present, &Sacl, &Defaulted) && Present && Sacl, "no SACL\n");
    ok(Sacl && Sacl->AceCount == 2, "SACL has %u ACEs\n", Sacl ? Sacl->AceCount : 0);
    if (Sacl && Sacl->AceCount == 2)
    {
        static const WCHAR *Want[2] = { L"S-1-1-0", L"S-1-5-11" };
        ULONG i;

        for (i = 0; i < 2; i++)
        {
            Expected = MakeSid(Want[i]);
            ok(GetAce(Sacl, i, (PVOID *)&Ace) && EqualSid((PSID)&Ace->SidStart, Expected), "SACL ACE %lu has the wrong SID\n", i);
            LocalFree(Expected);
        }
    }
    LocalFree(Sd);
}

static void TestRoundTrip(void)
{
    static const WCHAR *Strings[] =
    {
        L"D:(A;;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;GR;;;S-1-5-83-1-123456789-2-3-4)(A;;GX;;;S-1-5-4)",
        L"D:(A;OICI;GA;;;BA)(A;CI;GR;;;S-1-5-21-1253675753-2377331658-4097264211-1000)(D;;GW;;;S-1-5-4)(A;IO;GX;;;SY)",
        L"O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-32-544D:PAI(A;;FA;;;S-1-5-4)",
        L"D:(A;;GA;;;S-1-5-18)(A;;GA;;;S-1-5-19)(A;;GA;;;S-1-5-20)(A;;GR;;;S-1-5-11)(A;;GR;;;S-1-1-0)",
        L"D:P(A;OICIIO;GA;;;CO)(A;OICI;GRGX;;;S-1-5-32-545)(A;CI;WD;;;S-1-5-32-547)",
    };
    ULONG i;

    for (i = 0; i < ARRAYSIZE(Strings); i++)
    {
        PSECURITY_DESCRIPTOR Sd1 = NULL, Sd2 = NULL;
        PWSTR Out1 = NULL, Out2 = NULL;
        SECURITY_INFORMATION Info = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;

        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Strings[i], SDDL_REVISION_1, &Sd1, NULL))
        {
            ok(0, "[%ls] failed, error %lu\n", Strings[i], GetLastError());
            continue;
        }
        ok(ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd1, SDDL_REVISION_1, Info, &Out1, NULL),
           "[%ls] reverse failed, error %lu\n", Strings[i], GetLastError());
        if (Out1)
        {
            ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(Out1, SDDL_REVISION_1, &Sd2, NULL),
               "[%ls] second parse of %ls failed, error %lu\n", Strings[i], Out1, GetLastError());
            if (Sd2)
            {
                ok(ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd2, SDDL_REVISION_1, Info, &Out2, NULL),
                   "[%ls] second reverse failed\n", Strings[i]);
                if (Out2)
                {
                    ok(!lstrcmpW(Out1, Out2), "[%ls] not stable: %ls -> %ls\n", Strings[i], Out1, Out2);
                    LocalFree(Out2);
                }
                ok(GetSecurityDescriptorLength(Sd1) == GetSecurityDescriptorLength(Sd2),
                   "[%ls] lengths differ: %lu vs %lu\n", Strings[i], GetSecurityDescriptorLength(Sd1), GetSecurityDescriptorLength(Sd2));
                LocalFree(Sd2);
            }
            /* literal SIDs without an alias must come back verbatim and in order */
            if (wcsstr(Strings[i], L"S-1-5-83-1-123456789-2-3-4"))
                ok(wcsstr(Out1, L"S-1-5-83-1-123456789-2-3-4") != NULL, "[%ls] SID lost: %ls\n", Strings[i], Out1);
            if (wcsstr(Strings[i], L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"))
                ok(wcsstr(Out1, L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464") != NULL, "[%ls] SID lost: %ls\n", Strings[i], Out1);
            LocalFree(Out1);
        }
        LocalFree(Sd1);
    }

    /* all the aliases survive SDDL -> SD -> SDDL -> SD unchanged */
    for (i = 0; i < ARRAYSIZE(s_Aliases); i++)
    {
        WCHAR Sddl[64];
        PSECURITY_DESCRIPTOR Sd1 = NULL, Sd2 = NULL;
        PWSTR Out = NULL;
        PACL D1 = NULL, D2 = NULL;
        BOOL P, Df;
        PACCESS_ALLOWED_ACE A1 = NULL, A2 = NULL;

        StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"D:(A;;GR;;;%ls)(A;;GW;;;S-1-5-4)", s_Aliases[i]);
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd1, NULL))
        {
            ok(0, "[%ls] failed, error %lu\n", Sddl, GetLastError());
            continue;
        }
        if (ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd1, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &Out, NULL) &&
            ConvertStringSecurityDescriptorToSecurityDescriptorW(Out, SDDL_REVISION_1, &Sd2, NULL))
        {
            GetSecurityDescriptorDacl(Sd1, &P, &D1, &Df);
            GetSecurityDescriptorDacl(Sd2, &P, &D2, &Df);
            ok(D1 && D2 && D1->AceCount == 2 && D2->AceCount == 2, "[%ls] ACE count\n", Sddl);
            if (D1 && D2 && D1->AceCount == 2 && D2->AceCount == 2)
            {
                ULONG k;
                for (k = 0; k < 2; k++)
                {
                    GetAce(D1, k, (PVOID *)&A1);
                    GetAce(D2, k, (PVOID *)&A2);
                    ok(A1->Mask == A2->Mask && A1->Header.AceFlags == A2->Header.AceFlags && EqualSid((PSID)&A1->SidStart, (PSID)&A2->SidStart),
                       "[%ls -> %ls] ACE %lu differs\n", Sddl, Out, k);
                }
            }
        }
        else
            ok(0, "[%ls] round trip failed, error %lu\n", Sddl, GetLastError());
        if (Out) LocalFree(Out);
        if (Sd2) LocalFree(Sd2);
        LocalFree(Sd1);
    }
}

static void TestInvalid(void)
{
    static const WCHAR *Bad[] =
    {
        L"D:(A;;GA;;;)",
        L"D:(A;;GA;;;S-1-5)",
        L"D:(A;;GA;;;S-1-5-x)(A;;GA;;;SY)",
        L"D:(A;;GA;;;S-2-5-18)",
        L"D:(A;;GA;;;S-1-5-18",
        L"D:(A;;GA;;;S-1-5-18)(A;;GR;;;S-1-5-)",
    };
    ULONG i;

    for (i = 0; i < ARRAYSIZE(Bad); i++)
    {
        PSECURITY_DESCRIPTOR Sd = NULL;
        BOOL Ret;

        SetLastError(0xdeadbeef);
        Ret = ConvertStringSecurityDescriptorToSecurityDescriptorW(Bad[i], SDDL_REVISION_1, &Sd, NULL);
        ok(!Ret, "[%ls] unexpectedly succeeded\n", Bad[i]);
        if (Ret)
            LocalFree(Sd);
    }
}

static void TestObjectAces(void)
{
    static const struct
    {
        PCWSTR Sddl;
        PCWSTR Back;      /* NULL: the same */
        BOOL Valid;
        BYTE Types[3];
        DWORD Flags[3];   /* ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT */
        ULONG Aces;
    } Tests[] =
    {
        { L"O:BAG:BAD:(OA;;0x1;22222222-2222-2222-2222-222222222222;;WD)", NULL, TRUE, { ACCESS_ALLOWED_OBJECT_ACE_TYPE }, { 1 }, 1 },
        { L"D:(OD;;CC;;33333333-3333-3333-3333-333333333333;S-1-5-4)", NULL, TRUE, { ACCESS_DENIED_OBJECT_ACE_TYPE }, { 2 }, 1 },
        { L"D:(OA;CI;CC;aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb;cccccccc-3333-4444-5555-dddddddddddd;S-1-5-80-1-2-3)", NULL, TRUE, { ACCESS_ALLOWED_OBJECT_ACE_TYPE }, { 3 }, 1 },
        { L"D:(OA;;0x1;22222222-2222-2222-2222-222222222222;;WD)(OA;;0x2;;;SY)(A;;GA;;;S-1-5-18)", NULL, TRUE,
          { ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_ALLOWED_ACE_TYPE }, { 1, 0, 0 }, 3 },
        { L"D:(OA;;0x1;22222222-2222-2222-2222-222222222222;;WD)(OA;;0x2;11111111-1111-1111-1111-111111111111;;S-1-5-32-544)", NULL, TRUE,
          { ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE }, { 1, 1 }, 2 },
        { L"D:(OA;;0x1;AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE;;WD)", L"D:(OA;;0x1;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;;WD)", TRUE, { ACCESS_ALLOWED_OBJECT_ACE_TYPE }, { 1 }, 1 },
        { L"D:(OA;;0x1;22222222-2222-2222-2222-22222222222;;WD)", NULL, FALSE, { 0 }, { 0 }, 0 },
        { L"D:(OA;;0x1;2222222222222222222222222222222222;;WD)", NULL, FALSE, { 0 }, { 0 }, 0 },
        { L"D:(OA;;0x1;gggggggg-2222-2222-2222-222222222222;;WD)", NULL, FALSE, { 0 }, { 0 }, 0 },
        { L"D:(A;;0x1;22222222-2222-2222-2222-222222222222;;WD)", NULL, FALSE, { 0 }, { 0 }, 0 },
    };
    ULONG i, k;

    for (i = 0; i < ARRAYSIZE(Tests); i++)
    {
        PSECURITY_DESCRIPTOR Sd = NULL;
        PWSTR Out = NULL;
        BOOL Ret;

        SetLastError(0xdeadbeef);
        Ret = ConvertStringSecurityDescriptorToSecurityDescriptorW(Tests[i].Sddl, SDDL_REVISION_1, &Sd, NULL);
        ok(Ret == Tests[i].Valid, "[%ls] returned %d, error %lu\n", Tests[i].Sddl, Ret, GetLastError());
        if (!Ret)
            continue;

        {
            BOOL Present, Defaulted;
            PACL Dacl = NULL;

            ok(GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted) && Present && Dacl, "[%ls] no DACL\n", Tests[i].Sddl);
            ok(Dacl && Dacl->AceCount == Tests[i].Aces, "[%ls] %u ACEs\n", Tests[i].Sddl, Dacl ? Dacl->AceCount : 0);
            for (k = 0; Dacl && k < Dacl->AceCount && k < Tests[i].Aces; k++)
            {
                PACE_HEADER Ace = NULL;

                ok(GetAce(Dacl, k, (PVOID *)&Ace) && Ace, "[%ls] no ACE %lu\n", Tests[i].Sddl, k);
                if (!Ace)
                    continue;
                ok(Ace->AceType == Tests[i].Types[k], "[%ls] ACE %lu type %u\n", Tests[i].Sddl, k, Ace->AceType);
                if (Ace->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE || Ace->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE)
                {
                    PACCESS_ALLOWED_OBJECT_ACE Oa = (PACCESS_ALLOWED_OBJECT_ACE)Ace;
                    ULONG Expect = 12 + 16 * ((Tests[i].Flags[k] & 1) + !!(Tests[i].Flags[k] & 2));
                    ok(Oa->Flags == Tests[i].Flags[k], "[%ls] ACE %lu object flags 0x%lx\n", Tests[i].Sddl, k, Oa->Flags);
                    ok(Ace->AceSize >= Expect + 8, "[%ls] ACE %lu size %u\n", Tests[i].Sddl, k, Ace->AceSize);
                    if (k == 0 && (Oa->Flags & ACE_OBJECT_TYPE_PRESENT) && Tests[i].Back == NULL && i == 0)
                        ok(Oa->ObjectType.Data1 == 0x22222222 && Oa->ObjectType.Data4[7] == 0x22, "[%ls] wrong GUID\n", Tests[i].Sddl);
                }
            }
        }

        ok(ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd, SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Out, NULL),
           "[%ls] reverse failed, error %lu\n", Tests[i].Sddl, GetLastError());
        if (Out)
        {
            /* the text is normalised (rights names, aliases, lower-case GUIDs): it must be stable, keep every GUID and
             * give the same descriptor again */
            PSECURITY_DESCRIPTOR Sd2 = NULL;
            PWSTR Out2 = NULL;
            PCWSTR Guid = Tests[i].Back ? Tests[i].Back : Tests[i].Sddl;

            ok(wcsstr(Out, L"22222222-2222-2222-2222-222222222222") != NULL || !wcsstr(Guid, L"22222222-2222-2222-2222-222222222222"),
               "[%ls] GUID lost: %ls\n", Tests[i].Sddl, Out);
            ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(Out, SDDL_REVISION_1, &Sd2, NULL),
               "[%ls] second parse of %ls failed, error %lu\n", Tests[i].Sddl, Out, GetLastError());
            if (Sd2)
            {
                ok(GetSecurityDescriptorLength(Sd) == GetSecurityDescriptorLength(Sd2),
                   "[%ls] lengths %lu and %lu\n", Tests[i].Sddl, GetSecurityDescriptorLength(Sd), GetSecurityDescriptorLength(Sd2));
                ok(ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd2, SDDL_REVISION_1,
                        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Out2, NULL) &&
                   !lstrcmpW(Out, Out2), "[%ls] not stable: %ls\n", Tests[i].Sddl, Out);
                if (Out2)
                    LocalFree(Out2);
                LocalFree(Sd2);
            }
            LocalFree(Out);
        }
        LocalFree(Sd);
    }
}

START_TEST(SddlSids)
{
    TestMixedAces();
    TestOwnerGroupAndSacl();
    TestRoundTrip();
    TestInvalid();
    TestObjectAces();
}
