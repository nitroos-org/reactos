/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the two-letter SID aliases of SID strings and security descriptor strings
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * https://learn.microsoft.com/windows/win32/secauthz/sid-strings
 * The rows were measured on Windows Server 2022 that is not joined to a domain.
 */

#include "precomp.h"
#include <sddl.h>
#include <ntsecapi.h>

static const struct
{
    const WCHAR *Alias;
    const WCHAR *Sid;
} g_Aliases[] =
{
    { L"AA", L"S-1-5-32-579" }, { L"AC", L"S-1-15-2-1" },   { L"AN", L"S-1-5-7" },      { L"AO", L"S-1-5-32-548" },
    { L"AS", L"S-1-18-1" },     { L"AU", L"S-1-5-11" },     { L"BA", L"S-1-5-32-544" }, { L"BG", L"S-1-5-32-546" },
    { L"BO", L"S-1-5-32-551" }, { L"BU", L"S-1-5-32-545" }, { L"CD", L"S-1-5-32-574" }, { L"CG", L"S-1-3-1" },
    { L"CO", L"S-1-3-0" },      { L"CY", L"S-1-5-32-569" }, { L"ED", L"S-1-5-9" },      { L"ER", L"S-1-5-32-573" },
    { L"ES", L"S-1-5-32-576" }, { L"HA", L"S-1-5-32-578" }, { L"HI", L"S-1-16-12288" }, { L"IS", L"S-1-5-32-568" },
    { L"IU", L"S-1-5-4" },      { L"LS", L"S-1-5-19" },     { L"LU", L"S-1-5-32-559" }, { L"LW", L"S-1-16-4096" },
    { L"ME", L"S-1-16-8192" },  { L"MP", L"S-1-16-8448" },  { L"MS", L"S-1-5-32-577" }, { L"MU", L"S-1-5-32-558" },
    { L"NO", L"S-1-5-32-556" }, { L"NS", L"S-1-5-20" },     { L"NU", L"S-1-5-2" },      { L"OW", L"S-1-3-4" },
    { L"PO", L"S-1-5-32-550" }, { L"PS", L"S-1-5-10" },     { L"PU", L"S-1-5-32-547" }, { L"RA", L"S-1-5-32-575" },
    { L"RC", L"S-1-5-12" },     { L"RD", L"S-1-5-32-555" }, { L"RE", L"S-1-5-32-552" }, { L"RM", L"S-1-5-32-580" },
    { L"RU", L"S-1-5-32-554" }, { L"SI", L"S-1-16-16384" }, { L"SO", L"S-1-5-32-549" }, { L"SS", L"S-1-18-2" },
    { L"SU", L"S-1-5-6" },      { L"SY", L"S-1-5-18" },     { L"UD", L"S-1-5-84-0-0-0-0-0" },
    { L"WD", L"S-1-1-0" },      { L"WR", L"S-1-5-33" },
};

/* these name accounts of a domain: a machine that is not joined to one refuses them */
static const WCHAR *g_DomainAliases[] =
    { L"CA", L"DA", L"DC", L"DD", L"DG", L"DU", L"EA", L"PA", L"RS", L"SA" };

/* SIDs that have no alias: printed numerically */
static const WCHAR *g_NoAlias[] =
    { L"S-1-5-1", L"S-1-5-3", L"S-1-5-8", L"S-1-5-13", L"S-1-5-14", L"S-1-5-15", L"S-1-5-17", L"S-1-5-113",
      L"S-1-5-64-10", L"S-1-0-0", L"S-1-2-0", L"S-1-16-0", L"S-1-16-28672", L"S-1-15-3-1",
      L"S-1-5-21-1-2-3-500", L"S-1-5-21-1-2-3-512" };

static BOOL GetMachineSid(PSID Buffer, DWORD Size)
{
    LSA_OBJECT_ATTRIBUTES Attributes = { 0 };
    LSA_HANDLE Policy;
    POLICY_ACCOUNT_DOMAIN_INFO *Info = NULL;
    BOOL Ret = FALSE;

    Attributes.Length = sizeof(Attributes);
    if (LsaOpenPolicy(NULL, &Attributes, POLICY_VIEW_LOCAL_INFORMATION, &Policy))
        return FALSE;
    if (!LsaQueryInformationPolicy(Policy, PolicyAccountDomainInformation, (PVOID *)&Info) && Info && Info->DomainSid)
        Ret = CopySid(Size, Buffer, Info->DomainSid);
    if (Info)
        LsaFreeMemory(Info);
    LsaClose(Policy);
    return Ret;
}

static PSID WithRid(PSID Machine, DWORD Rid, BYTE *Buffer)
{
    PSID Sid = (PSID)Buffer;

    CopySid(SECURITY_MAX_SID_SIZE, Sid, Machine);
    *GetSidSubAuthority(Sid, *GetSidSubAuthorityCount(Sid)) = Rid;
    (*GetSidSubAuthorityCount(Sid))++;
    return Sid;
}

static void ExpectOwnerString(const WCHAR *Sddl, const WCHAR *Expected)
{
    PSECURITY_DESCRIPTOR Descriptor = NULL;
    WCHAR *Text = NULL;
    BOOL Ok;

    Ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Descriptor, NULL);
    ok(Ok, "%ls: conversion failed: %lu\n", Sddl, GetLastError());
    if (!Ok)
        return;
    Ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(Descriptor, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION, &Text, NULL);
    ok(Ok, "%ls: back conversion failed: %lu\n", Sddl, GetLastError());
    if (Ok)
    {
        ok(!lstrcmpW(Text, Expected), "%ls: printed as %ls, expected %ls\n", Sddl, Text, Expected);
        LocalFree(Text);
    }
    LocalFree(Descriptor);
}

static void TestAliasTable(void)
{
    size_t i;

    for (i = 0; i < ARRAYSIZE(g_Aliases); i++)
    {
        PSID Sid = NULL;
        WCHAR *Text = NULL;
        WCHAR Owner[64], Expected[128];

        SetLastError(0xdeadbeef);
        ok(ConvertStringSidToSidW(g_Aliases[i].Alias, &Sid), "%ls: ConvertStringSidToSid failed: %lu\n", g_Aliases[i].Alias, GetLastError());
        if (!Sid)
            continue;
        ok(ConvertSidToStringSidW(Sid, &Text), "ConvertSidToStringSid failed: %lu\n", GetLastError());
        if (Text)
        {
            ok(!lstrcmpW(Text, g_Aliases[i].Sid), "%ls: converted to %ls, expected %ls\n", g_Aliases[i].Alias, Text, g_Aliases[i].Sid);
            LocalFree(Text);
        }
        LocalFree(Sid);

        /* and back: a descriptor string with this owner prints the alias */
        StringCchPrintfW(Owner, ARRAYSIZE(Owner), L"O:%ls", g_Aliases[i].Alias);
        StringCchCopyW(Expected, ARRAYSIZE(Expected), Owner);
        ExpectOwnerString(Owner, Expected);
        StringCchPrintfW(Owner, ARRAYSIZE(Owner), L"O:%ls", g_Aliases[i].Sid);
        StringCchPrintfW(Expected, ARRAYSIZE(Expected), L"O:%ls", g_Aliases[i].Alias);
        ExpectOwnerString(Owner, Expected);
    }

    for (i = 0; i < ARRAYSIZE(g_NoAlias); i++)
    {
        WCHAR Sddl[128];

        StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"O:%ls", g_NoAlias[i]);
        ExpectOwnerString(Sddl, Sddl);
    }
}

static void TestDomainAliases(void)
{
    size_t i;

    for (i = 0; i < ARRAYSIZE(g_DomainAliases); i++)
    {
        PSID Sid = (PSID)0x1234;
        PSECURITY_DESCRIPTOR Descriptor = (PSECURITY_DESCRIPTOR)0x1234;
        WCHAR Sddl[64];

        SetLastError(0xdeadbeef);
        ok(!ConvertStringSidToSidW(g_DomainAliases[i], &Sid), "%ls: the alias was converted\n", g_DomainAliases[i]);
        ok(GetLastError() == ERROR_INVALID_SID, "%ls: error %lu\n", g_DomainAliases[i], GetLastError());
        ok(Sid == (PSID)0x1234, "%ls: the output was changed to %p\n", g_DomainAliases[i], Sid);

        StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"O:%lsG:%lsD:(A;;GA;;;%ls)", g_DomainAliases[i], g_DomainAliases[i], g_DomainAliases[i]);
        SetLastError(0xdeadbeef);
        ok(!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Descriptor, NULL),
           "%ls: the descriptor was converted\n", Sddl);
        ok(GetLastError() == ERROR_INVALID_SID, "%ls: error %lu\n", Sddl, GetLastError());
    }

    /* unknown aliases */
    {
        PSID Sid = (PSID)0x1234;

        SetLastError(0xdeadbeef);
        ok(!ConvertStringSidToSidW(L"ZZ", &Sid), "ZZ converted\n");
        ok(GetLastError() == ERROR_INVALID_SID, "ZZ: error %lu\n", GetLastError());
        ok(Sid == (PSID)0x1234, "ZZ: the output was changed to %p\n", Sid);
    }
}

static void TestMachineAccounts(void)
{
    BYTE Machine[SECURITY_MAX_SID_SIZE], Buffer[SECURITY_MAX_SID_SIZE];
    PSID Admin = NULL, Guest = NULL, Expected;
    WCHAR *Text, *ExpectedText;
    PSECURITY_DESCRIPTOR Descriptor = NULL;
    BOOL Present, Defaulted;
    PSID Owner = NULL, Group = NULL;
    PACL Dacl = NULL;
    ACCESS_ALLOWED_ACE *Ace = NULL;
    BYTE LookedUp[SECURITY_MAX_SID_SIZE];
    DWORD LookedUpSize = sizeof(LookedUp), DomainSize = 256;
    WCHAR Domain[256];
    SID_NAME_USE Use;
    BYTE Other[SECURITY_MAX_SID_SIZE];
    PSID OtherSid;

    if (!GetMachineSid(Machine, sizeof(Machine)))
    {
        skip("no machine SID\n");
        return;
    }

    /* LA and LG are the machine's own Administrator and Guest, not a zero domain */
    ok(ConvertStringSidToSidW(L"LA", &Admin), "LA failed: %lu\n", GetLastError());
    ok(ConvertStringSidToSidW(L"LG", &Guest), "LG failed: %lu\n", GetLastError());
    if (Admin)
    {
        Expected = WithRid(Machine, DOMAIN_USER_RID_ADMIN, Buffer);
        ok(EqualSid(Admin, Expected), "LA is not the machine SID plus 500\n");
        ConvertSidToStringSidW(Admin, &Text);
        ok(Text && wcsstr(Text, L"S-1-5-21-0-0-0-") == NULL, "LA has a zero domain: %ls\n", Text);
        LocalFree(Text);
        LocalFree(Admin);
    }
    if (Guest)
    {
        Expected = WithRid(Machine, DOMAIN_USER_RID_GUEST, Buffer);
        ok(EqualSid(Guest, Expected), "LG is not the machine SID plus 501\n");
        LocalFree(Guest);
    }

    /* the descriptor built from a string names the real account: owner, group and ACE */
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:LAG:LGD:(A;;GA;;;LA)(D;;GR;;;LG)", SDDL_REVISION_1, &Descriptor, NULL),
       "conversion failed: %lu\n", GetLastError());
    if (Descriptor)
    {
        BYTE ExpAdmin[SECURITY_MAX_SID_SIZE], ExpGuest[SECURITY_MAX_SID_SIZE];
        PSID A = WithRid(Machine, DOMAIN_USER_RID_ADMIN, ExpAdmin), G = WithRid(Machine, DOMAIN_USER_RID_GUEST, ExpGuest);

        ok(GetSecurityDescriptorOwner(Descriptor, &Owner, &Defaulted) && Owner && EqualSid(Owner, A), "the owner is not the local Administrator\n");
        ok(GetSecurityDescriptorGroup(Descriptor, &Group, &Defaulted) && Group && EqualSid(Group, G), "the group is not the local Guest\n");
        ok(GetSecurityDescriptorDacl(Descriptor, &Present, &Dacl, &Defaulted) && Present && Dacl, "no DACL\n");
        if (Dacl)
        {
            ok(GetAce(Dacl, 0, (void **)&Ace) && Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && EqualSid((PSID)&Ace->SidStart, A), "ACE 0 does not name the local Administrator\n");
            ok(GetAce(Dacl, 1, (void **)&Ace) && Ace->Header.AceType == ACCESS_DENIED_ACE_TYPE && EqualSid((PSID)&Ace->SidStart, G), "ACE 1 does not name the local Guest\n");
        }
        ok(ConvertSecurityDescriptorToStringSecurityDescriptorW(Descriptor, SDDL_REVISION_1,
               OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Text, NULL), "back conversion failed\n");
        ExpectedText = (WCHAR *)L"O:LAG:LGD:(A;;GA;;;LA)(D;;GR;;;LG)";
        if (Text)
        {
            ok(!lstrcmpW(Text, ExpectedText), "printed as %ls\n", Text);
            LocalFree(Text);
        }
        LocalFree(Descriptor);
    }

    /* the real local Administrator: the account with RID 500 of this machine */
    if (LookupAccountNameW(NULL, L"Administrator", (PSID)LookedUp, &LookedUpSize, Domain, &DomainSize, &Use) &&
        *GetSidSubAuthority((PSID)LookedUp, *GetSidSubAuthorityCount((PSID)LookedUp) - 1) == DOMAIN_USER_RID_ADMIN)
    {
        ok(ConvertStringSidToSidW(L"LA", &Admin), "LA failed\n");
        if (Admin)
        {
            ok(EqualSid(Admin, (PSID)LookedUp), "LA is not the SID of the account Administrator\n");
            LocalFree(Admin);
        }
    }
    else
        skip("the local Administrator was not found under that name\n");

    /* the machine SID plus a RID that has no alias, and another domain's RID 500: numeric */
    OtherSid = WithRid(Machine, 512, Other);
    ConvertSidToStringSidW(OtherSid, &Text);
    if (Text)
    {
        WCHAR Sddl[128], Out[128];

        StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"O:%ls", Text);
        StringCchCopyW(Out, ARRAYSIZE(Out), Sddl);
        ExpectOwnerString(Sddl, Out);
        LocalFree(Text);
    }
    Expected = WithRid(Machine, DOMAIN_USER_RID_ADMIN, Buffer);
    ConvertSidToStringSidW(Expected, &Text);
    if (Text)
    {
        WCHAR Sddl[128];

        StringCchPrintfW(Sddl, ARRAYSIZE(Sddl), L"O:%ls", Text);
        ExpectOwnerString(Sddl, L"O:LA");
        LocalFree(Text);
    }
    ExpectOwnerString(L"O:S-1-5-21-1-2-3-500", L"O:S-1-5-21-1-2-3-500");
}

/* Windows Server 2022 reads the aliases in either case, refuses text glued to an alias, and reports a domain alias or an
 * unknown one in an ACE as a bad SID (a glued one as a bad ACL) */
static void ExpectConversion(const WCHAR *Sddl, BOOL Expected, DWORD ExpectedError)
{
    PSECURITY_DESCRIPTOR Descriptor = NULL;
    BOOL Ok;

    SetLastError(0xdeadbeef);
    Ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Descriptor, NULL);
    ok(Ok == Expected, "%ls: conversion %s\n", Sddl, Ok ? "worked" : "failed");
    if (!Ok && !Expected)
        ok(GetLastError() == ExpectedError, "%ls: error %lu, expected %lu\n", Sddl, GetLastError(), ExpectedError);
    if (Descriptor)
        LocalFree(Descriptor);
}

static void TestAliasSyntax(void)
{
    static const WCHAR *Lower[] = { L"la", L"lG", L"Ba", L"wd", L"sy", L"mu", L"wr" };
    size_t i;

    for (i = 0; i < ARRAYSIZE(Lower); i++)
    {
        PSID Sid = NULL;
        WCHAR Upper[3] = { towupper(Lower[i][0]), towupper(Lower[i][1]), 0 }, A[64], B[64];
        PSID SidUpper = NULL;

        SetLastError(0xdeadbeef);
        ok(ConvertStringSidToSidW(Lower[i], &Sid), "%ls: ConvertStringSidToSid failed: %lu\n", Lower[i], GetLastError());
        ok(ConvertStringSidToSidW(Upper, &SidUpper), "%ls: ConvertStringSidToSid failed: %lu\n", Upper, GetLastError());
        if (Sid && SidUpper)
            ok(EqualSid(Sid, SidUpper), "%ls and %ls are not the same SID\n", Lower[i], Upper);
        if (Sid)
            LocalFree(Sid);
        if (SidUpper)
            LocalFree(SidUpper);

        StringCchPrintfW(A, ARRAYSIZE(A), L"O:%ls", Lower[i]);
        StringCchPrintfW(B, ARRAYSIZE(B), L"O:%ls", Upper);
        ExpectOwnerString(A, B);
        StringCchPrintfW(A, ARRAYSIZE(A), L"D:(A;;GA;;;%ls)", Lower[i]);
        ExpectConversion(A, TRUE, 0);
    }

    /* text glued to an alias */
    ExpectConversion(L"O:LAx", FALSE, ERROR_INVALID_PARAMETER);
    ExpectConversion(L"O:BAx", FALSE, ERROR_INVALID_PARAMETER);
    ExpectConversion(L"G:WDX", FALSE, ERROR_INVALID_PARAMETER);
    ExpectConversion(L"D:(A;;GA;;;LAx)", FALSE, ERROR_INVALID_ACL);
    ExpectConversion(L"D:(A;;GA;;;BAD)", FALSE, ERROR_INVALID_ACL);
    ExpectConversion(L"D:(A;;GA;;;WDX)", FALSE, ERROR_INVALID_ACL);
    /* blanks after one are fine */
    ExpectConversion(L"D:(A;;GA;;;LA )", TRUE, 0);
    ExpectConversion(L"O:LA G:BA", TRUE, 0);

    /* an alias that names nothing in an ACE alone */
    ExpectConversion(L"D:(A;;GA;;;DA)", FALSE, ERROR_INVALID_SID);
    ExpectConversion(L"D:(D;;GA;;;EA)", FALSE, ERROR_INVALID_SID);
    ExpectConversion(L"S:(AU;SA;GA;;;DU)", FALSE, ERROR_INVALID_SID);
    ExpectConversion(L"D:(A;;GA;;;ZZ)", FALSE, ERROR_INVALID_SID);
    ExpectConversion(L"D:(A;;GA;;;BA)(A;;GA;;;DA)(A;;GR;;;WD)", FALSE, ERROR_INVALID_SID);
}

START_TEST(SddlSidAliases)
{
    TestAliasTable();
    TestDomainAliases();
    TestMachineAccounts();
    TestAliasSyntax();
}
