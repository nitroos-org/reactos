/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The descriptor of a token whose DACL derives from the default DACL: (A;;TOKEN_QUERY;;;BA) follows
 *              unless the default DACL has an entry for the Administrators; a descriptor given by the caller stays
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Rows measured on Windows Server 2022 (build 20348), a process whose own token's default DACL was changed with
 * SetTokenInformation(TokenDefaultDacl), the token of its child and of DuplicateTokenEx read with
 * GetKernelObjectSecurity (an administrator, a standard user and a service gave the same):
 *   default DACL (SY GA)(OW GA)             -> (SY all)(OW all)(BA 0x8)
 *   (WD GA)                                 -> (WD all)(BA 0x8)
 *   (SY GA)(OW GA)(BA GA) and (BA GA)       -> no extra entry
 *   (SY GA)(OW GA)(BA RC), (BA GR), (BA 0x8), (deny BA GA) -> no extra entry
 *   (SY GA)(OW GA)(LS GA) and a logon SID   -> the entry is the last one, after them
 *   explicit descriptor for DuplicateTokenEx (D:(A;;GA;;;SY), D:(A;;GA;;;WD), D:) -> as given, no extra entry
 */

#include "precomp.h"
#include <sddl.h>

typedef struct
{
    PCSTR DefaultDacl;      /* SDDL of the default DACL set on the process token */
    INT   ExtraEntry;       /* 1: BA TOKEN_QUERY must be the last ACE, 0: the ACE count equals the entries of the default DACL */
} ROW;

static const ROW Rows[] =
{
    { "D:(A;;GA;;;SY)(A;;GA;;;WD)", 1 },
    { "D:(A;;GA;;;WD)", 1 },
    { "D:(A;;GA;;;SY)(A;;GA;;;LS)", 1 },
    { "D:(A;;GA;;;SY)(A;;GA;;;WD)(A;;GA;;;BA)", 0 },
    { "D:(A;;GA;;;BA)", 0 },
    { "D:(A;;GA;;;SY)(A;;GA;;;WD)(A;;RC;;;BA)", 0 },
    { "D:(A;;GA;;;SY)(A;;GA;;;WD)(A;;GR;;;BA)", 0 },
    { "D:(A;;GA;;;SY)(A;;GA;;;WD)(A;;0x8;;;BA)", 0 },
    { "D:(A;;GA;;;SY)(A;;GA;;;WD)(D;;GA;;;BA)", 0 },
};

static PACL GetTokenDacl(HANDLE Token, PSECURITY_DESCRIPTOR *Sd)
{
    DWORD Needed = 0;
    BOOL Present = FALSE, Defaulted;
    PACL Dacl = NULL;

    *Sd = NULL;
    GetKernelObjectSecurity(Token, DACL_SECURITY_INFORMATION, NULL, 0, &Needed);
    if (Needed == 0)
        return NULL;
    *Sd = HeapAlloc(GetProcessHeap(), 0, Needed);
    if (!*Sd || !GetKernelObjectSecurity(Token, DACL_SECURITY_INFORMATION, *Sd, Needed, &Needed))
        return NULL;
    GetSecurityDescriptorDacl(*Sd, &Present, &Dacl, &Defaulted);
    return Present ? Dacl : NULL;
}

static BOOL IsAdminsAce(PVOID Ace, BOOL *Allow, ACCESS_MASK *Mask)
{
    PACCESS_ALLOWED_ACE Allowed = Ace;
    SID_IDENTIFIER_AUTHORITY Nt = { SECURITY_NT_AUTHORITY };
    PSID Admins = NULL;
    BOOL Equal;

    AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &Admins);
    Equal = EqualSid((PSID)&Allowed->SidStart, Admins);
    FreeSid(Admins);
    *Allow = Allowed->Header.AceType == ACCESS_ALLOWED_ACE_TYPE;
    *Mask = Allowed->Mask;
    return Equal;
}

static ULONG EntriesOf(PCSTR Sddl)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    BOOL Present, Defaulted;
    ULONG Count = 0xffff;

    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(Sddl, SDDL_REVISION_1, &Sd, NULL))
    {
        if (GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted) && Dacl)
            Count = Dacl->AceCount;
        LocalFree(Sd);
    }
    return Count;
}

static void SetDefaultDacl(HANDLE Token, PCSTR Sddl)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    BOOL Present, Defaulted, Ret;
    TOKEN_DEFAULT_DACL Info;

    Ret = ConvertStringSecurityDescriptorToSecurityDescriptorA(Sddl, SDDL_REVISION_1, &Sd, NULL);
    ok(Ret, "ConvertStringSecurityDescriptorToSecurityDescriptor(%s) failed with %lu\n", Sddl, GetLastError());
    if (!Ret)
        return;
    GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted);
    Info.DefaultDacl = Dacl;
    Ret = SetTokenInformation(Token, TokenDefaultDacl, &Info, sizeof(Info));
    ok(Ret, "SetTokenInformation(%s) failed with %lu\n", Sddl, GetLastError());
    LocalFree(Sd);
}

START_TEST(TokenAdminQuery)
{
    HANDLE Process, Duplicate;
    PTOKEN_DEFAULT_DACL Saved = NULL;
    DWORD Needed = 0;
    ULONG i;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | READ_CONTROL, &Process))
    {
        skip("no access to the own token (%lu)\n", GetLastError());
        return;
    }

    GetTokenInformation(Process, TokenDefaultDacl, NULL, 0, &Needed);
    Saved = HeapAlloc(GetProcessHeap(), 0, Needed);
    if (!Saved || !GetTokenInformation(Process, TokenDefaultDacl, Saved, Needed, &Needed))
    {
        skip("cannot save the default DACL (%lu)\n", GetLastError());
        CloseHandle(Process);
        return;
    }

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        PSECURITY_DESCRIPTOR Sd;
        PACL Dacl;
        ULONG Entries = EntriesOf(Rows[i].DefaultDacl);
        BOOL Ret;

        SetDefaultDacl(Process, Rows[i].DefaultDacl);

        Ret = DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &Duplicate);
        ok(Ret, "row %lu: DuplicateTokenEx failed with %lu\n", i, GetLastError());
        if (!Ret)
            continue;

        Dacl = GetTokenDacl(Duplicate, &Sd);
        ok(Dacl != NULL, "row %lu: no DACL\n", i);
        if (Dacl)
        {
            ULONG Expected = Entries + Rows[i].ExtraEntry;

            ok(Dacl->AceCount == Expected, "row %lu (%s): %u entries, expected %lu\n", i, Rows[i].DefaultDacl, Dacl->AceCount, Expected);
            if (Rows[i].ExtraEntry && Dacl->AceCount == Expected)
            {
                PVOID Ace = NULL;
                BOOL Allow;
                ACCESS_MASK Mask;

                ok(GetAce(Dacl, Dacl->AceCount - 1, &Ace), "row %lu: GetAce failed\n", i);
                if (Ace)
                {
                    ok(IsAdminsAce(Ace, &Allow, &Mask), "row %lu: the last entry is not for the Administrators\n", i);
                    ok(Allow && Mask == TOKEN_QUERY, "row %lu: the entry is %s 0x%lx\n", i, Allow ? "allow" : "deny", Mask);
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, Sd);
        CloseHandle(Duplicate);
    }

    /* A descriptor the caller gives is used as it is */
    {
        static const PCSTR Explicit[] = { "D:(A;;GA;;;SY)", "D:(A;;GA;;;WD)", "D:" };

        for (i = 0; i < ARRAYSIZE(Explicit); i++)
        {
            SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, FALSE };
            PSECURITY_DESCRIPTOR Given = NULL, Sd;
            PACL Dacl;

            if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(Explicit[i], SDDL_REVISION_1, &Given, NULL))
                continue;
            Sa.lpSecurityDescriptor = Given;
            if (DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, &Sa, SecurityImpersonation, TokenPrimary, &Duplicate))
            {
                Dacl = GetTokenDacl(Duplicate, &Sd);
                ok(Dacl != NULL && Dacl->AceCount == EntriesOf(Explicit[i]), "explicit %s: %u entries\n", Explicit[i], Dacl ? Dacl->AceCount : 0xffff);
                HeapFree(GetProcessHeap(), 0, Sd);
                CloseHandle(Duplicate);
            }
            else
            {
                ok(0, "explicit %s: DuplicateTokenEx failed with %lu\n", Explicit[i], GetLastError());
            }
            LocalFree(Given);
        }
    }

    SetTokenInformation(Process, TokenDefaultDacl, Saved, Needed);
    HeapFree(GetProcessHeap(), 0, Saved);
    CloseHandle(Process);
}
