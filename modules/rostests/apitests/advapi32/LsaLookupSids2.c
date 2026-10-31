/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for advapi32!LsaLookupSids2
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results are those of Windows 10 22H2 (x64 and x86): the same names as LsaLookupSids, the options change nothing
 * for these accounts, and the failures of no policy handle, no SIDs and no count.
 */

#include "precomp.h"
#include <ntsecapi.h>
#include <sddl.h>

typedef NTSTATUS (WINAPI *FN_LOOKUP2)(LSA_HANDLE, ULONG, ULONG, PSID *, PLSA_REFERENCED_DOMAIN_LIST *, PLSA_TRANSLATED_NAME *);

static void CheckName(PLSA_TRANSLATED_NAME Names, PLSA_REFERENCED_DOMAIN_LIST Domains, ULONG Index, SID_NAME_USE Use,
                      PCWSTR Name, PCWSTR Domain)
{
    ok(Names[Index].Use == Use, "[%lu] use %d, expected %d\n", Index, Names[Index].Use, Use);
    ok(Names[Index].Name.Length == wcslen(Name) * sizeof(WCHAR) && !_wcsnicmp(Names[Index].Name.Buffer, Name, wcslen(Name)),
       "[%lu] name %.*ls, expected %ls\n", Index, Names[Index].Name.Length / 2, Names[Index].Name.Buffer, Name);
    if (Domain)
    {
        LONG Domains_Index = Names[Index].DomainIndex;

        ok(Domains_Index >= 0 && (ULONG)Domains_Index < Domains->Entries, "[%lu] domain index %ld\n", Index, Domains_Index);
        if (Domains_Index >= 0 && (ULONG)Domains_Index < Domains->Entries)
            ok(Domains->Domains[Domains_Index].Name.Length == wcslen(Domain) * sizeof(WCHAR) &&
               !_wcsnicmp(Domains->Domains[Domains_Index].Name.Buffer, Domain, wcslen(Domain)),
               "[%lu] domain %.*ls, expected %ls\n", Index, Domains->Domains[Domains_Index].Name.Length / 2,
               Domains->Domains[Domains_Index].Name.Buffer, Domain);
    }
    else
    {
        ok(Names[Index].DomainIndex == -1, "[%lu] domain index %ld, expected -1\n", Index, Names[Index].DomainIndex);
    }
}

START_TEST(LsaLookupSids2)
{
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    FN_LOOKUP2 pLookup2 = (FN_LOOKUP2)GetProcAddress(hAdvapi32, "LsaLookupSids2");
    LSA_OBJECT_ATTRIBUTES Attributes = { 0 };
    LSA_HANDLE Policy = NULL;
    PSID Sids[4] = { 0 };
    PLSA_REFERENCED_DOMAIN_LIST Domains;
    PLSA_TRANSLATED_NAME Names;
    static const ULONG Options[] = { 0, 0x80000000, 0x40000000, 1 };
    NTSTATUS Status;
    ULONG i;

    if (!pLookup2)
    {
        ok(!is_reactos(), "LsaLookupSids2 is not exported by advapi32.dll\n");
        skip("LsaLookupSids2 is not available\n");
        return;
    }

    Attributes.Length = sizeof(Attributes);
    Status = LsaOpenPolicy(NULL, &Attributes, POLICY_LOOKUP_NAMES, &Policy);
    ok(Status == STATUS_SUCCESS, "LsaOpenPolicy: 0x%lx\n", Status);
    if (Status != STATUS_SUCCESS)
        return;

    ConvertStringSidToSidW(L"S-1-5-18", &Sids[0]);
    ConvertStringSidToSidW(L"S-1-1-0", &Sids[1]);
    ConvertStringSidToSidW(L"S-1-5-32-544", &Sids[2]);
    ConvertStringSidToSidW(L"S-1-5-21-1-2-3-500", &Sids[3]);

    for (i = 0; i < ARRAYSIZE(Options); i++)
    {
        Domains = (PVOID)1;
        Names = (PVOID)1;
        Status = pLookup2(Policy, Options[i], 4, Sids, &Domains, &Names);
        ok(Status == STATUS_SOME_NOT_MAPPED, "options %lx: 0x%lx\n", Options[i], Status);
        ok(Domains != NULL && Domains != (PVOID)1 && Names != NULL && Names != (PVOID)1, "options %lx: results %p %p\n",
           Options[i], Domains, Names);
        if (Domains && Domains != (PVOID)1 && Names && Names != (PVOID)1)
        {
            ok(Domains->Entries == 3, "options %lx: %lu domains\n", Options[i], Domains->Entries);
            CheckName(Names, Domains, 0, SidTypeWellKnownGroup, L"SYSTEM", L"NT AUTHORITY");
            CheckName(Names, Domains, 1, SidTypeWellKnownGroup, L"Everyone", L"");
            CheckName(Names, Domains, 2, SidTypeAlias, L"Administrators", L"BUILTIN");
            /* A domain account that does not exist: Windows answers the SID as a string for the name and no domain;
             * the local authority of ReactOS answers an empty name, as LsaLookupSids does */
            ok(Names[3].Use == SidTypeUnknown, "[3] use %d\n", Names[3].Use);
            ok(Names[3].DomainIndex == -1, "[3] domain index %ld\n", Names[3].DomainIndex);
            if (!is_reactos())
                CheckName(Names, Domains, 3, SidTypeUnknown, L"S-1-5-21-1-2-3-500", NULL);
        }
        if (Domains && Domains != (PVOID)1)
            LsaFreeMemory(Domains);
        if (Names && Names != (PVOID)1)
            LsaFreeMemory(Names);
    }

    /* No count: invalid parameter, the names are cleared, the domains left alone */
    Domains = (PVOID)1;
    Names = (PVOID)1;
    Status = pLookup2(Policy, 0, 0, Sids, &Domains, &Names);
    ok(Status == STATUS_INVALID_PARAMETER, "count 0: 0x%lx\n", Status);
    ok(Domains == (PVOID)1, "count 0: domains %p\n", Domains);
    ok(Names == NULL, "count 0: names %p\n", Names);

    /* No SIDs, no policy handle */
    Domains = (PVOID)1;
    Names = (PVOID)1;
    Status = pLookup2(Policy, 0, 1, NULL, &Domains, &Names);
    ok(Status == STATUS_INVALID_PARAMETER, "no SIDs: 0x%lx\n", Status);
    Status = pLookup2(NULL, 0, 1, Sids, &Domains, &Names);
    ok(Status == STATUS_INVALID_HANDLE, "no policy: 0x%lx\n", Status);

    for (i = 0; i < ARRAYSIZE(Sids); i++)
        LocalFree(Sids[i]);
    LsaClose(Policy);
}
