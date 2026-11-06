/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LsaLookupNames with names that are not mapped, next to names that are
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ntsecapi.h>

/*
 * Measured on Windows 10 22H2, a 64-bit and a 32-bit process alike, LsaLookupNames of
 * Administrators, a name that does not exist, BUILTIN, Everyone and SYSTEM:
 * STATUS_SOME_NOT_MAPPED, and per name (Use, RelativeId, DomainIndex):
 *   Administrators   SidTypeAlias          544         0
 *   (no such name)   SidTypeUnknown        0           -1
 *   BUILTIN          SidTypeDomain         0xFFFFFFFF  0
 *   Everyone         SidTypeWellKnownGroup 0           1
 *   SYSTEM           SidTypeWellKnownGroup 18          2
 * with three referenced domains. LsaLookupNames (the first version, which returns a RID
 * instead of a SID) faulted in lsass on the unmapped name, and the caller got
 * STATUS_ACCESS_VIOLATION. Only names that are all unmapped gave STATUS_NONE_MAPPED.
 */

static const WCHAR NoSuchName[] = L"lsa-lookup-no-such-name-1";

static void InitString(PLSA_UNICODE_STRING String, PCWSTR Text)
{
    String->Buffer = (PWSTR)Text;
    String->Length = (USHORT)(wcslen(Text) * sizeof(WCHAR));
    String->MaximumLength = String->Length + sizeof(WCHAR);
}

static void CheckEntry(PLSA_TRANSLATED_SID Sids, ULONG Index, SID_NAME_USE Use, ULONG Rid, BOOL Mapped)
{
    ok(Sids[Index].Use == Use, "[%lu] Use %d, expected %d\n", Index, Sids[Index].Use, Use);
    ok(Sids[Index].RelativeId == Rid, "[%lu] RelativeId %lx, expected %lx\n", Index, Sids[Index].RelativeId, Rid);
    if (Mapped)
        ok(Sids[Index].DomainIndex >= 0, "[%lu] DomainIndex %ld\n", Index, Sids[Index].DomainIndex);
    else
        ok(Sids[Index].DomainIndex == -1, "[%lu] DomainIndex %ld, expected -1\n", Index, Sids[Index].DomainIndex);
}

START_TEST(LsaLookupNamesUnmapped)
{
    static const PCWSTR Mixed[] = { L"Administrators", NoSuchName, L"BUILTIN", L"Everyone", L"SYSTEM" };
    LSA_OBJECT_ATTRIBUTES Attributes = {0};
    LSA_UNICODE_STRING Names[5];
    PLSA_REFERENCED_DOMAIN_LIST Domains;
    PLSA_TRANSLATED_SID Sids;
    PLSA_TRANSLATED_SID2 Sids2;
    LSA_HANDLE Policy;
    NTSTATUS Status;
    ULONG i, Round;

    Status = LsaOpenPolicy(NULL, &Attributes, POLICY_LOOKUP_NAMES, &Policy);
    ok(Status == STATUS_SUCCESS, "LsaOpenPolicy returned %08lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    for (i = 0; i < 5; i++)
        InitString(&Names[i], Mixed[i]);

    /* The same answer every time: the server keeps serving */
    for (Round = 0; Round < 3; Round++)
    {
        Domains = NULL;
        Sids = NULL;
        Status = LsaLookupNames(Policy, 5, Names, &Domains, &Sids);
        ok(Status == STATUS_SOME_NOT_MAPPED, "Round %lu: LsaLookupNames returned %08lx\n", Round, Status);
        ok(Sids != NULL && Domains != NULL, "Round %lu: Sids %p, Domains %p\n", Round, Sids, Domains);
        if (Sids)
        {
            CheckEntry(Sids, 0, SidTypeAlias, DOMAIN_ALIAS_RID_ADMINS, TRUE);
            CheckEntry(Sids, 1, SidTypeUnknown, 0, FALSE);
            CheckEntry(Sids, 2, SidTypeDomain, 0xFFFFFFFF, TRUE);
            CheckEntry(Sids, 3, SidTypeWellKnownGroup, SECURITY_WORLD_RID, TRUE);
            CheckEntry(Sids, 4, SidTypeWellKnownGroup, SECURITY_LOCAL_SYSTEM_RID, TRUE);
            LsaFreeMemory(Sids);
        }
        if (Domains)
        {
            ok(Domains->Entries == 3, "Round %lu: %lu domains\n", Round, Domains->Entries);
            LsaFreeMemory(Domains);
        }
    }

    /* The unmapped name alone, and one in the middle of the list for the second version */
    Domains = NULL;
    Sids = NULL;
    Status = LsaLookupNames(Policy, 1, &Names[1], &Domains, &Sids);
    ok(Status == STATUS_NONE_MAPPED, "LsaLookupNames(unmapped) returned %08lx\n", Status);
    if (Sids)
        LsaFreeMemory(Sids);
    if (Domains)
        LsaFreeMemory(Domains);

    Domains = NULL;
    Sids2 = NULL;
    Status = LsaLookupNames2(Policy, 0, 5, Names, &Domains, &Sids2);
    ok(Status == STATUS_SOME_NOT_MAPPED, "LsaLookupNames2 returned %08lx\n", Status);
    if (Sids2)
    {
        ok(Sids2[1].Use == SidTypeUnknown, "LsaLookupNames2 [1] Use %d\n", Sids2[1].Use);
        ok(Sids2[1].Sid == NULL, "LsaLookupNames2 [1] Sid %p\n", Sids2[1].Sid);
        ok(Sids2[0].Use == SidTypeAlias && Sids2[0].Sid != NULL, "LsaLookupNames2 [0] Use %d Sid %p\n",
           Sids2[0].Use, Sids2[0].Sid);
        LsaFreeMemory(Sids2);
    }
    if (Domains)
        LsaFreeMemory(Domains);

    /* A lookup of mapped names only still succeeds */
    Domains = NULL;
    Sids = NULL;
    Status = LsaLookupNames(Policy, 1, &Names[0], &Domains, &Sids);
    ok(Status == STATUS_SUCCESS, "LsaLookupNames(Administrators) returned %08lx\n", Status);
    if (Sids)
    {
        CheckEntry(Sids, 0, SidTypeAlias, DOMAIN_ALIAS_RID_ADMINS, TRUE);
        LsaFreeMemory(Sids);
    }
    if (Domains)
        LsaFreeMemory(Domains);

    LsaClose(Policy);
}
