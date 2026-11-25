/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     AccessCheck of restricted and write restricted tokens against descriptors with an OWNER RIGHTS ACE
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every row is a measurement on Windows Server 2022 (build 20348): the token of the caller made with
 * CreateRestrictedToken, a descriptor whose owner is the user of the token, a generic mapping of read 1, write 2,
 * execute 4, all 7. An OWNER RIGHTS ACE grants nothing to a write restricted token that has restricting SIDs, also not
 * the read right of a request the restricting SIDs are not asked about; the same token is no owner for the owner
 * rights of the descriptor either.
 */

#include "precomp.h"
#include <sddl.h>

#ifndef WRITE_RESTRICTED
#define WRITE_RESTRICTED 0x8
#endif

enum { TOKEN_RESTRICTED_EVERYONE, TOKEN_WR_EVERYONE, TOKEN_WR_EVERYONE_USERS, TOKEN_WR_RESTRICTED,
       TOKEN_WR_RESTRICTED_EVERYONE, TOKEN_COUNT };
enum { DESC_OWNERRIGHTS1_EVERYONE6, DESC_OWNERRIGHTS1_EVERYONE7, DESC_OWNERRIGHTS7, DESC_COUNT };

static const struct
{
    int Token, Desc;
    DWORD Desired;
    int Allowed;
    DWORD Granted;
} Rows[] =
{
    { TOKEN_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x1, 0, 0x0 },
    { TOKEN_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x2, 1, 0x2 },
    { TOKEN_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x4, 1, 0x4 },
    { TOKEN_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x7, 0, 0x0 },
    { TOKEN_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, MAXIMUM_ALLOWED, 1, 0x6 },
    { TOKEN_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE7, 0x1, 1, 0x1 },
    { TOKEN_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE7, 0x7, 1, 0x7 },
    { TOKEN_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS7, 0x1, 0, 0x0 },
    { TOKEN_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS7, MAXIMUM_ALLOWED, 0, 0x0 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x1, 0, 0x0 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x2, 1, 0x2 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x4, 1, 0x4 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x7, 0, 0x0 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, MAXIMUM_ALLOWED, 1, 0x6 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE7, 0x1, 1, 0x1 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE7, 0x2, 1, 0x2 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE7, 0x4, 1, 0x4 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE7, 0x7, 1, 0x7 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE7, MAXIMUM_ALLOWED, 1, 0x7 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS7, 0x1, 0, 0x0 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS7, 0x2, 0, 0x0 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS7, 0x4, 0, 0x0 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS7, 0x7, 0, 0x0 },
    { TOKEN_WR_EVERYONE, DESC_OWNERRIGHTS7, MAXIMUM_ALLOWED, 0, 0x0 },
    { TOKEN_WR_EVERYONE_USERS, DESC_OWNERRIGHTS1_EVERYONE6, 0x1, 0, 0x0 },
    { TOKEN_WR_EVERYONE_USERS, DESC_OWNERRIGHTS1_EVERYONE6, 0x2, 1, 0x2 },
    { TOKEN_WR_EVERYONE_USERS, DESC_OWNERRIGHTS1_EVERYONE6, 0x4, 1, 0x4 },
    { TOKEN_WR_EVERYONE_USERS, DESC_OWNERRIGHTS1_EVERYONE6, 0x7, 0, 0x0 },
    { TOKEN_WR_EVERYONE_USERS, DESC_OWNERRIGHTS1_EVERYONE6, MAXIMUM_ALLOWED, 1, 0x6 },
    { TOKEN_WR_EVERYONE_USERS, DESC_OWNERRIGHTS1_EVERYONE7, 0x1, 1, 0x1 },
    { TOKEN_WR_EVERYONE_USERS, DESC_OWNERRIGHTS1_EVERYONE7, 0x7, 1, 0x7 },
    { TOKEN_WR_EVERYONE_USERS, DESC_OWNERRIGHTS7, 0x1, 0, 0x0 },
    { TOKEN_WR_EVERYONE_USERS, DESC_OWNERRIGHTS7, 0x4, 0, 0x0 },
    { TOKEN_WR_EVERYONE_USERS, DESC_OWNERRIGHTS7, MAXIMUM_ALLOWED, 0, 0x0 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS1_EVERYONE6, 0x1, 0, 0x0 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS1_EVERYONE6, 0x2, 0, 0x0 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS1_EVERYONE6, 0x4, 1, 0x4 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS1_EVERYONE6, 0x7, 0, 0x0 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS1_EVERYONE6, MAXIMUM_ALLOWED, 1, 0x4 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS1_EVERYONE7, 0x1, 1, 0x1 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS1_EVERYONE7, 0x2, 0, 0x0 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS1_EVERYONE7, 0x4, 1, 0x4 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS1_EVERYONE7, MAXIMUM_ALLOWED, 1, 0x5 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS7, 0x1, 0, 0x0 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS7, 0x4, 0, 0x0 },
    { TOKEN_WR_RESTRICTED, DESC_OWNERRIGHTS7, MAXIMUM_ALLOWED, 0, 0x0 },
    { TOKEN_WR_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x1, 0, 0x0 },
    { TOKEN_WR_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x2, 1, 0x2 },
    { TOKEN_WR_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x4, 1, 0x4 },
    { TOKEN_WR_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, 0x7, 0, 0x0 },
    { TOKEN_WR_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE6, MAXIMUM_ALLOWED, 1, 0x6 },
    { TOKEN_WR_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE7, 0x1, 1, 0x1 },
    { TOKEN_WR_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS1_EVERYONE7, 0x7, 1, 0x7 },
    { TOKEN_WR_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS7, 0x1, 0, 0x0 },
    { TOKEN_WR_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS7, 0x4, 0, 0x0 },
    { TOKEN_WR_RESTRICTED_EVERYONE, DESC_OWNERRIGHTS7, MAXIMUM_ALLOWED, 0, 0x0 },
};

static PSID WellKnown(WELL_KNOWN_SID_TYPE Type)
{
    DWORD Size = SECURITY_MAX_SID_SIZE;
    PSID Sid = LocalAlloc(LPTR, Size);

    CreateWellKnownSid(Type, NULL, Sid, &Size);
    return Sid;
}

static HANDLE MakeToken(HANDLE Process, int Which)
{
    SID_AND_ATTRIBUTES Restricting[2] = { { NULL, 0 }, { NULL, 0 } };
    DWORD Flags = 0, Count = 1;
    HANDLE Restricted = NULL, Impersonation = NULL;

    switch (Which)
    {
        case TOKEN_RESTRICTED_EVERYONE:
            Restricting[0].Sid = WellKnown(WinWorldSid);
            break;
        case TOKEN_WR_EVERYONE:
            Restricting[0].Sid = WellKnown(WinWorldSid);
            Flags = WRITE_RESTRICTED;
            break;
        case TOKEN_WR_EVERYONE_USERS:
            Restricting[0].Sid = WellKnown(WinWorldSid);
            Restricting[1].Sid = WellKnown(WinBuiltinUsersSid);
            Flags = WRITE_RESTRICTED;
            Count = 2;
            break;
        case TOKEN_WR_RESTRICTED:
            Restricting[0].Sid = WellKnown(WinRestrictedCodeSid);
            Flags = WRITE_RESTRICTED;
            break;
        default:
            Restricting[0].Sid = WellKnown(WinRestrictedCodeSid);
            Restricting[1].Sid = WellKnown(WinWorldSid);
            Flags = WRITE_RESTRICTED;
            Count = 2;
            break;
    }

    if (CreateRestrictedToken(Process, Flags, 0, NULL, 0, NULL, Count, Restricting, &Restricted))
    {
        DuplicateTokenEx(Restricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Impersonation);
        CloseHandle(Restricted);
    }
    LocalFree(Restricting[0].Sid);
    LocalFree(Restricting[1].Sid);
    return Impersonation;
}

START_TEST(AccessCheckWriteRestrictedOwner)
{
    static const char *DescFormat[DESC_COUNT] =
    {
        "O:%sG:BAD:(A;;0x1;;;OW)(A;;0x6;;;WD)",
        "O:%sG:BAD:(A;;0x1;;;OW)(A;;0x7;;;WD)",
        "O:%sG:BAD:(A;;0x7;;;OW)",
    };
    GENERIC_MAPPING Mapping = { 1, 2, 4, 7 };
    HANDLE Process = NULL, Tokens[TOKEN_COUNT] = { 0 };
    PSECURITY_DESCRIPTOR Descriptors[DESC_COUNT] = { 0 };
    BYTE UserBuffer[256];
    DWORD Length;
    char *UserString = NULL;
    ULONG i;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Process) ||
        !GetTokenInformation(Process, TokenUser, UserBuffer, sizeof(UserBuffer), &Length) ||
        !ConvertSidToStringSidA(((PTOKEN_USER)UserBuffer)->User.Sid, &UserString))
    {
        skip("no token user: %lu\n", GetLastError());
        return;
    }

    for (i = 0; i < DESC_COUNT; i++)
    {
        char Text[256];

        sprintf(Text, DescFormat[i], UserString);
        ok(ConvertStringSecurityDescriptorToSecurityDescriptorA(Text, 1, &Descriptors[i], NULL),
           "descriptor %lu: %lu\n", i, GetLastError());
    }
    for (i = 0; i < TOKEN_COUNT; i++)
    {
        Tokens[i] = MakeToken(Process, i);
        if (!Tokens[i])
            skip("no restricted token %lu: %lu\n", i, GetLastError());
    }

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        PRIVILEGE_SET Privileges;
        DWORD PrivilegeLength = sizeof(Privileges), Granted = 0xdead;
        BOOL Allowed = FALSE, Result;

        if (!Tokens[Rows[i].Token] || !Descriptors[Rows[i].Desc])
            continue;

        Result = AccessCheck(Descriptors[Rows[i].Desc], Tokens[Rows[i].Token], Rows[i].Desired, &Mapping, &Privileges,
                             &PrivilegeLength, &Granted, &Allowed);
        ok(Result, "row %lu: AccessCheck failed with %lu\n", i, GetLastError());
        ok(Allowed == Rows[i].Allowed, "row %lu (token %d, descriptor %d, 0x%lx): allowed %d, expected %d\n", i,
           Rows[i].Token, Rows[i].Desc, Rows[i].Desired, Allowed, Rows[i].Allowed);
        if (Rows[i].Allowed)
            ok(Granted == Rows[i].Granted, "row %lu (token %d, descriptor %d, 0x%lx): granted 0x%lx, expected 0x%lx\n", i,
               Rows[i].Token, Rows[i].Desc, Rows[i].Desired, Granted, Rows[i].Granted);
    }

    for (i = 0; i < TOKEN_COUNT; i++)
        if (Tokens[i]) CloseHandle(Tokens[i]);
    for (i = 0; i < DESC_COUNT; i++)
        if (Descriptors[i]) LocalFree(Descriptors[i]);
    LocalFree(UserString);
    CloseHandle(Process);
}
