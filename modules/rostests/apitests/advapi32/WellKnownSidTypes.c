/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CreateWellKnownSid builds every type, IsWellKnownSid knows the account types
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The rows were measured on Windows Server 2022 (build 20348) that is not joined to a domain: every type from
 * WinNullSid (0) to 110, with and without a domain SID, a too small buffer, and IsWellKnownSid of every built SID.
 */

#include "precomp.h"
#include <sddl.h>

#define DOMAIN L"S-1-5-21-1111-2222-3333"

static const struct
{
    int Type;
    int Domain;             /* the SID is the domain SID plus this RID, built only with a domain SID */
    const WCHAR *Sid;       /* NULL: not built (ERROR_INVALID_PARAMETER); a RID of a domain type */
} g_Rows[] =
{
    {0, 0, L"S-1-0-0"}, {1, 0, L"S-1-1-0"}, {2, 0, L"S-1-2-0"}, {3, 0, L"S-1-3-0"},
    {4, 0, L"S-1-3-1"}, {5, 0, L"S-1-3-2"}, {6, 0, L"S-1-3-3"}, {7, 0, L"S-1-5"},
    {8, 0, L"S-1-5-1"}, {9, 0, L"S-1-5-2"}, {10, 0, L"S-1-5-3"}, {11, 0, L"S-1-5-4"},
    {12, 0, L"S-1-5-6"}, {13, 0, L"S-1-5-7"}, {14, 0, L"S-1-5-8"}, {15, 0, L"S-1-5-9"},
    {16, 0, L"S-1-5-10"}, {17, 0, L"S-1-5-11"}, {18, 0, L"S-1-5-12"}, {19, 0, L"S-1-5-13"},
    {20, 0, L"S-1-5-14"}, {21, 0, NULL}, {22, 0, L"S-1-5-18"}, {23, 0, L"S-1-5-19"},
    {24, 0, L"S-1-5-20"}, {25, 0, L"S-1-5-32"}, {26, 0, L"S-1-5-32-544"}, {27, 0, L"S-1-5-32-545"},
    {28, 0, L"S-1-5-32-546"}, {29, 0, L"S-1-5-32-547"}, {30, 0, L"S-1-5-32-548"}, {31, 0, L"S-1-5-32-549"},
    {32, 0, L"S-1-5-32-550"}, {33, 0, L"S-1-5-32-551"}, {34, 0, L"S-1-5-32-552"}, {35, 0, L"S-1-5-32-554"},
    {36, 0, L"S-1-5-32-555"}, {37, 0, L"S-1-5-32-556"}, {38, 1, L"500"}, {39, 1, L"501"},
    {40, 1, L"502"}, {41, 1, L"512"}, {42, 1, L"513"}, {43, 1, L"514"},
    {44, 1, L"515"}, {45, 1, L"516"}, {46, 1, L"517"}, {47, 1, L"518"},
    {48, 1, L"519"}, {49, 1, L"520"}, {50, 1, L"553"}, {51, 0, L"S-1-5-64-10"},
    {52, 0, L"S-1-5-64-21"}, {53, 0, L"S-1-5-64-14"}, {54, 0, L"S-1-5-15"}, {55, 0, L"S-1-5-1000"},
    {56, 0, L"S-1-5-32-557"}, {57, 0, L"S-1-5-32-558"}, {58, 0, L"S-1-5-32-559"}, {59, 0, L"S-1-5-32-560"},
    {60, 0, L"S-1-5-32-561"}, {61, 0, L"S-1-5-32-562"}, {62, 0, L"S-1-5-32-568"}, {63, 0, L"S-1-5-17"},
    {64, 0, L"S-1-5-32-569"}, {65, 0, L"S-1-16-0"}, {66, 0, L"S-1-16-4096"}, {67, 0, L"S-1-16-8192"},
    {68, 0, L"S-1-16-12288"}, {69, 0, L"S-1-16-16384"}, {70, 0, L"S-1-5-33"}, {71, 0, L"S-1-3-4"},
    {72, 1, L"571"}, {73, 1, L"572"}, {74, 0, L"S-1-5-22"}, {75, 1, L"521"},
    {76, 0, L"S-1-5-32-573"}, {77, 1, L"498"}, {78, 0, L"S-1-5-32-574"}, {79, 0, L"S-1-16-8448"},
    {80, 0, NULL}, {81, 0, L"S-1-2-1"}, {82, 0, L"S-1-5-65-1"}, {83, 0, NULL},
    {84, 0, L"S-1-15-2-1"}, {85, 0, L"S-1-15-3-1"}, {86, 0, L"S-1-15-3-2"}, {87, 0, L"S-1-15-3-3"},
    {88, 0, L"S-1-15-3-4"}, {89, 0, L"S-1-15-3-5"}, {90, 0, L"S-1-15-3-6"}, {91, 0, L"S-1-15-3-7"},
    {92, 0, L"S-1-15-3-9"}, {93, 0, L"S-1-15-3-8"}, {94, 0, L"S-1-15-3-10"}, {95, 0, L"S-1-5-32-575"},
    {96, 0, L"S-1-5-32-576"}, {97, 0, L"S-1-5-32-577"}, {98, 0, L"S-1-5-84-0-0-0-0-0"}, {99, 0, L"S-1-5-32-578"},
    {100, 1, L"522"}, {101, 0, L"S-1-5-32-579"}, {102, 0, L"S-1-5-32-580"}, {103, 0, L"S-1-18-1"},
    {104, 0, L"S-1-18-2"}, {105, 0, L"S-1-5-113"}, {106, 0, L"S-1-5-114"}, {107, 1, L"525"},
    {108, 0, L"S-1-15-3-11"}, {109, 0, L"S-1-15-3-12"}, {110, 1, L"503"},
};

static void ToString(PSID Sid, WCHAR *Out, ULONG Count)
{
    WCHAR *Text = NULL;

    Out[0] = 0;
    if (ConvertSidToStringSidW(Sid, &Text))
    {
        wcsncpy(Out, Text, Count - 1);
        Out[Count - 1] = 0;
        LocalFree(Text);
    }
}

static void TestCreate(void)
{
    PSID Domain = NULL;
    ULONG i;

    ok(ConvertStringSidToSidW(DOMAIN, &Domain), "ConvertStringSidToSid(domain): %lu\n", GetLastError());
    if (!Domain)
        return;

    for (i = 0; i < RTL_NUMBER_OF(g_Rows); i++)
    {
        BYTE Buffer[SECURITY_MAX_SID_SIZE];
        WCHAR Text[100], Expected[100];
        DWORD Size;
        BOOL Ret;

        if (g_Rows[i].Domain)
            swprintf(Expected, RTL_NUMBER_OF(Expected), DOMAIN L"-%ls", g_Rows[i].Sid);
        else if (g_Rows[i].Sid)
            wcscpy(Expected, g_Rows[i].Sid);
        else
            Expected[0] = 0;

        /* With the domain SID */
        Size = sizeof(Buffer);
        SetLastError(0xdeadbeef);
        Ret = CreateWellKnownSid(g_Rows[i].Type, Domain, Buffer, &Size);
        if (!g_Rows[i].Sid)
        {
            ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "type %d: %d, %lu\n", g_Rows[i].Type, Ret, GetLastError());
            continue;
        }
        ok(Ret, "type %d with the domain: %lu\n", g_Rows[i].Type, GetLastError());
        if (Ret)
        {
            ToString(Buffer, Text, RTL_NUMBER_OF(Text));
            ok(!wcscmp(Text, Expected), "type %d with the domain: %ls, expected %ls\n", g_Rows[i].Type, Text, Expected);
            ok(Size == GetLengthSid(Buffer), "type %d: size %lu, SID %lu\n", g_Rows[i].Type, Size, GetLengthSid(Buffer));
            ok(IsWellKnownSid(Buffer, g_Rows[i].Type), "type %d: the SID %ls is not of its type\n", g_Rows[i].Type, Text);
        }

        /* Without a domain SID the account types of a domain cannot be built */
        Size = sizeof(Buffer);
        SetLastError(0xdeadbeef);
        Ret = CreateWellKnownSid(g_Rows[i].Type, NULL, Buffer, &Size);
        if (g_Rows[i].Domain)
        {
            ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "type %d without a domain: %d, %lu\n",
               g_Rows[i].Type, Ret, GetLastError());
        }
        else
        {
            ok(Ret, "type %d without a domain: %lu\n", g_Rows[i].Type, GetLastError());
            if (Ret)
            {
                ToString(Buffer, Text, RTL_NUMBER_OF(Text));
                ok(!wcscmp(Text, Expected), "type %d without a domain: %ls, expected %ls\n", g_Rows[i].Type, Text, Expected);
            }
        }

        /* A buffer one byte too small gets the size */
        if (Ret || g_Rows[i].Domain)
        {
            DWORD Need = GetSidLengthRequired(g_Rows[i].Domain ? 5 : 0);
            DWORD Small;

            Size = sizeof(Buffer);
            if (CreateWellKnownSid(g_Rows[i].Type, Domain, Buffer, &Size))
                Need = Size;
            Small = Need - 1;
            SetLastError(0xdeadbeef);
            Ret = CreateWellKnownSid(g_Rows[i].Type, Domain, Buffer, &Small);
            ok(!Ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER && Small == Need,
               "type %d, a buffer of %lu: %d, %lu, size %lu (expected %lu)\n", g_Rows[i].Type, Need - 1, Ret, GetLastError(), Small, Need);
        }
    }
    LocalFree(Domain);
}

/* IsWellKnownSid of the account types: any domain, five sub authorities, the RID of the type (measured) */
static void TestIsWellKnown(void)
{
    static const struct
    {
        const WCHAR *Sid;
        int Type;
        BOOL Expected;
    } Rows[] =
    {
        { L"S-1-5-21-1111-2222-3333-500", WinAccountAdministratorSid, TRUE },
        { L"S-1-5-21-1-2-3-500", WinAccountAdministratorSid, TRUE },
        { L"S-1-5-21-1-2-3-501", WinAccountAdministratorSid, FALSE },
        { L"S-1-5-21-1-2-3-501", WinAccountGuestSid, TRUE },
        { L"S-1-5-21-1111-2222-3333-512", WinAccountDomainAdminsSid, TRUE },
        { L"S-1-5-21-1111-2222-3333-571", WinCacheablePrincipalsGroupSid, TRUE },
        { L"S-1-5-21-1111-2222-3333-572", WinNonCacheablePrincipalsGroupSid, TRUE },
        { L"S-1-5-21-1111-2222-3333-521", WinAccountReadonlyControllersSid, TRUE },
        { L"S-1-5-21-1111-2222-500", WinAccountAdministratorSid, FALSE },
        { L"S-1-5-21-1111-2222-3333-4444-500", WinAccountAdministratorSid, FALSE },
        { L"S-1-5-21-500", WinAccountAdministratorSid, FALSE },
        { L"S-1-5-5-500", WinAccountAdministratorSid, FALSE },
        { L"S-1-5-32-568", WinBuiltinIUsersSid, TRUE },
        { L"S-1-5-32-568", WinBuiltinUsersSid, FALSE },
        { L"S-1-5-17", WinIUserSid, TRUE },
        { L"S-1-5-32-569", WinBuiltinCryptoOperatorsSid, TRUE },
        { L"S-1-16-0", WinUntrustedLabelSid, TRUE },
        { L"S-1-16-0", WinLowLabelSid, FALSE },
        { L"S-1-5-33", WinWriteRestrictedCodeSid, TRUE },
        { L"S-1-5-22", WinEnterpriseReadonlyControllersSid, TRUE },
        { L"S-1-16-8448", WinMediumPlusLabelSid, TRUE },
        { L"S-1-5-32-573", WinBuiltinEventLogReadersGroup, TRUE },
        { L"S-1-5-84-0-0-0-0-0", WinUserModeDriversSid, TRUE },
        { L"S-1-18-1", WinAuthenticationAuthorityAssertedSid, TRUE },
        { L"S-1-18-2", WinAuthenticationServiceAssertedSid, TRUE },
        { L"S-1-5-32-544", WinBuiltinAdministratorsSid, TRUE },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Rows); i++)
    {
        PSID Sid = NULL;

        ok(ConvertStringSidToSidW(Rows[i].Sid, &Sid), "ConvertStringSidToSid(%ls): %lu\n", Rows[i].Sid, GetLastError());
        if (!Sid)
            continue;
        ok(IsWellKnownSid(Sid, Rows[i].Type) == Rows[i].Expected, "IsWellKnownSid(%ls, %d) is %d, expected %d\n",
           Rows[i].Sid, Rows[i].Type, !Rows[i].Expected, Rows[i].Expected);
        LocalFree(Sid);
    }
}

/* The Administrator and Guest accounts of this machine are the account types, as on Windows */
static void TestMachineAccounts(void)
{
    static const struct { const WCHAR *Name; int Type; } Accounts[] =
    {
        { L"Administrator", WinAccountAdministratorSid },
        { L"Guest", WinAccountGuestSid },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Accounts); i++)
    {
        BYTE Sid[SECURITY_MAX_SID_SIZE];
        WCHAR Domain[100];
        DWORD SidSize = sizeof(Sid), DomainSize = RTL_NUMBER_OF(Domain);
        SID_NAME_USE Use;

        if (!LookupAccountNameW(NULL, Accounts[i].Name, Sid, &SidSize, Domain, &DomainSize, &Use))
        {
            skip("%ls: LookupAccountName %lu\n", Accounts[i].Name, GetLastError());
            continue;
        }
        ok(IsWellKnownSid(Sid, Accounts[i].Type), "%ls is not of type %d\n", Accounts[i].Name, Accounts[i].Type);
        ok(!IsWellKnownSid(Sid, WinAccountDomainAdminsSid), "%ls is a domain administrators SID\n", Accounts[i].Name);
    }
}

START_TEST(WellKnownSidTypes)
{
    TestCreate();
    TestIsWellKnown();
    TestMachineAccounts();
}
