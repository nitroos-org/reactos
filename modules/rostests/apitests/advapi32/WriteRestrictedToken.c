/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Access checks of a restricted and of a write restricted token (CreateRestrictedToken with WRITE_RESTRICTED)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected rows were measured on Windows Server 2022 (10.0.20348) with AccessCheck and the generic mappings of a
 * file, a registry key and an event, for a token without privileges (CreateRestrictedToken(DISABLE_MAX_PRIVILEGE) of
 * the administrator's token, an impersonation token) and its restricted copies:
 *   NORMAL                    no restricting SIDs
 *   RESTRICTED                one restricting SID, S-1-5-33 (both passes for every right)
 *   WRITE_RESTRICTED          the same SID, flag WRITE_RESTRICTED: the second pass for write rights only
 *   WRITE_RESTRICTED_NO_SIDS  the flag and no restricting SID: write rights are never granted, IsTokenRestricted is 0
 *   WRITE_RESTRICTED_2        the flag and two restricting SIDs, S-1-5-33 and Everyone
 * Descriptors (owner and group Administrators; the ACEs hold the specific rights of the mapping):
 *   A  allow all to Administrators              B  A and allow all to S-1-5-33
 *   C  allow read to Everyone                   D  deny write to S-1-5-33, allow all to Administrators and to S-1-5-33
 *   NULL no DACL                                EMPTY a DACL without ACEs
 * The write rights the restricting SIDs have to grant: those of the write mapping, DELETE, WRITE_DAC and WRITE_OWNER;
 * READ_CONTROL, SYNCHRONIZE and everything else are checked against the normal SIDs only.
 */

#include "precomp.h"
#include <sddl.h>

BOOL WINAPI IsTokenRestricted(HANDLE TokenHandle);

#ifndef WRITE_RESTRICTED
#define WRITE_RESTRICTED 0x8
#endif

enum { FILE_KIND, KEY_KIND, EVENT_KIND };
enum { SD_A, SD_B, SD_C, SD_NULL, SD_EMPTY, SD_D };
enum { TOK_NORMAL, TOK_RESTRICTED, TOK_WRITE_RESTRICTED, TOK_WRITE_RESTRICTED_NO_SIDS, TOK_WRITE_RESTRICTED_2 };

static const DWORD Accesses[] = {
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, SYNCHRONIZE,
    READ_CONTROL | SYNCHRONIZE, 0x3, 0x2 | DELETE, GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE, GENERIC_ALL
};

static GENERIC_MAPPING Maps[3] = {
    { 0x120089, 0x120116, 0x1200a0, 0x1f01ff },     /* a file */
    { 0x20019, 0x20006, 0x20019, 0xf003f },         /* a registry key */
    { 0x120000, 0x120002, 0x120000, 0x1f0003 },     /* an event */
};

static const PCSTR SdText[6] = {
    "O:BAG:BAD:P(A;;@A;;;BA)",
    "O:BAG:BAD:P(A;;@A;;;BA)(A;;@A;;;S-1-5-33)",
    "O:BAG:BAD:P(A;;@R;;;WD)",
    "O:BAG:BA",
    "O:BAG:BAD:P",
    "O:BAG:BAD:P(D;;@W;;;S-1-5-33)(A;;@A;;;BA)(A;;@A;;;S-1-5-33)",
};

static const struct
{
    INT Kind;
    INT Sd;
    INT Token;
    DWORD Allowed;      /* bit i: Accesses[i] is granted */
    DWORD MaxGranted;   /* MAXIMUM_ALLOWED, 0 when refused */
} Rows[] =
{
    { FILE_KIND, SD_A, TOK_NORMAL, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_A, TOK_RESTRICTED, 0x00000000, 0x00000000 },
    { FILE_KIND, SD_A, TOK_WRITE_RESTRICTED, 0x000a64e9, 0x001200e9 },
    { FILE_KIND, SD_A, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a6ce9, 0x001600e9 },
    { FILE_KIND, SD_A, TOK_WRITE_RESTRICTED_2, 0x000a64e9, 0x001200e9 },
    { FILE_KIND, SD_B, TOK_NORMAL, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_B, TOK_RESTRICTED, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_B, TOK_WRITE_RESTRICTED, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_B, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a6ce9, 0x001600e9 },
    { FILE_KIND, SD_B, TOK_WRITE_RESTRICTED_2, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_C, TOK_NORMAL, 0x00026c89, 0x00160089 },
    { FILE_KIND, SD_C, TOK_RESTRICTED, 0x00000000, 0x00000000 },
    { FILE_KIND, SD_C, TOK_WRITE_RESTRICTED, 0x00026489, 0x00120089 },
    { FILE_KIND, SD_C, TOK_WRITE_RESTRICTED_NO_SIDS, 0x00026c89, 0x00160089 },
    { FILE_KIND, SD_C, TOK_WRITE_RESTRICTED_2, 0x00026489, 0x00120089 },
    { FILE_KIND, SD_NULL, TOK_NORMAL, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_NULL, TOK_RESTRICTED, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_NULL, TOK_WRITE_RESTRICTED, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_NULL, TOK_WRITE_RESTRICTED_NO_SIDS, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_NULL, TOK_WRITE_RESTRICTED_2, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_EMPTY, TOK_NORMAL, 0x00000c00, 0x00060000 },
    { FILE_KIND, SD_EMPTY, TOK_RESTRICTED, 0x00000000, 0x00000000 },
    { FILE_KIND, SD_EMPTY, TOK_WRITE_RESTRICTED, 0x00000000, 0x00000000 },
    { FILE_KIND, SD_EMPTY, TOK_WRITE_RESTRICTED_NO_SIDS, 0x00000c00, 0x00060000 },
    { FILE_KIND, SD_EMPTY, TOK_WRITE_RESTRICTED_2, 0x00000000, 0x00000000 },
    { FILE_KIND, SD_D, TOK_NORMAL, 0x001fffff, 0x001f01ff },
    { FILE_KIND, SD_D, TOK_RESTRICTED, 0x00001ae9, 0x000d00e9 },
    { FILE_KIND, SD_D, TOK_WRITE_RESTRICTED, 0x000a7ee9, 0x001f00e9 },
    { FILE_KIND, SD_D, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a6ce9, 0x001600e9 },
    { FILE_KIND, SD_D, TOK_WRITE_RESTRICTED_2, 0x000a7ee9, 0x001f00e9 },
    { KEY_KIND, SD_A, TOK_NORMAL, 0x001f9e3f, 0x000f003f },
    { KEY_KIND, SD_A, TOK_RESTRICTED, 0x00000000, 0x00000000 },
    { KEY_KIND, SD_A, TOK_WRITE_RESTRICTED, 0x000a0439, 0x00020039 },
    { KEY_KIND, SD_A, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a0c39, 0x00060039 },
    { KEY_KIND, SD_A, TOK_WRITE_RESTRICTED_2, 0x000a0439, 0x00020039 },
    { KEY_KIND, SD_B, TOK_NORMAL, 0x001f9e3f, 0x000f003f },
    { KEY_KIND, SD_B, TOK_RESTRICTED, 0x001f9e3f, 0x000f003f },
    { KEY_KIND, SD_B, TOK_WRITE_RESTRICTED, 0x001f9e3f, 0x000f003f },
    { KEY_KIND, SD_B, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a0c39, 0x00060039 },
    { KEY_KIND, SD_B, TOK_WRITE_RESTRICTED_2, 0x001f9e3f, 0x000f003f },
    { KEY_KIND, SD_C, TOK_NORMAL, 0x000a0c19, 0x00060019 },
    { KEY_KIND, SD_C, TOK_RESTRICTED, 0x00000000, 0x00000000 },
    { KEY_KIND, SD_C, TOK_WRITE_RESTRICTED, 0x000a0419, 0x00020019 },
    { KEY_KIND, SD_C, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a0c19, 0x00060019 },
    { KEY_KIND, SD_C, TOK_WRITE_RESTRICTED_2, 0x000a0419, 0x00020019 },
    { KEY_KIND, SD_NULL, TOK_NORMAL, 0x001fffff, 0x000f003f },
    { KEY_KIND, SD_NULL, TOK_RESTRICTED, 0x001fffff, 0x000f003f },
    { KEY_KIND, SD_NULL, TOK_WRITE_RESTRICTED, 0x001fffff, 0x000f003f },
    { KEY_KIND, SD_NULL, TOK_WRITE_RESTRICTED_NO_SIDS, 0x001fffff, 0x000f003f },
    { KEY_KIND, SD_NULL, TOK_WRITE_RESTRICTED_2, 0x001fffff, 0x000f003f },
    { KEY_KIND, SD_EMPTY, TOK_NORMAL, 0x00000c00, 0x00060000 },
    { KEY_KIND, SD_EMPTY, TOK_RESTRICTED, 0x00000000, 0x00000000 },
    { KEY_KIND, SD_EMPTY, TOK_WRITE_RESTRICTED, 0x00000000, 0x00000000 },
    { KEY_KIND, SD_EMPTY, TOK_WRITE_RESTRICTED_NO_SIDS, 0x00000c00, 0x00060000 },
    { KEY_KIND, SD_EMPTY, TOK_WRITE_RESTRICTED_2, 0x00000000, 0x00000000 },
    { KEY_KIND, SD_D, TOK_NORMAL, 0x001f9e3f, 0x000f003f },
    { KEY_KIND, SD_D, TOK_RESTRICTED, 0x00001a39, 0x000d0039 },
    { KEY_KIND, SD_D, TOK_WRITE_RESTRICTED, 0x000a1e39, 0x000f0039 },
    { KEY_KIND, SD_D, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a0c39, 0x00060039 },
    { KEY_KIND, SD_D, TOK_WRITE_RESTRICTED_2, 0x000a1e39, 0x000f0039 },
    { EVENT_KIND, SD_A, TOK_NORMAL, 0x001ffe03, 0x001f0003 },
    { EVENT_KIND, SD_A, TOK_RESTRICTED, 0x00000000, 0x00000000 },
    { EVENT_KIND, SD_A, TOK_WRITE_RESTRICTED, 0x000a6401, 0x00120001 },
    { EVENT_KIND, SD_A, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a6c01, 0x00160001 },
    { EVENT_KIND, SD_A, TOK_WRITE_RESTRICTED_2, 0x000a6401, 0x00120001 },
    { EVENT_KIND, SD_B, TOK_NORMAL, 0x001ffe03, 0x001f0003 },
    { EVENT_KIND, SD_B, TOK_RESTRICTED, 0x001ffe03, 0x001f0003 },
    { EVENT_KIND, SD_B, TOK_WRITE_RESTRICTED, 0x001ffe03, 0x001f0003 },
    { EVENT_KIND, SD_B, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a6c01, 0x00160001 },
    { EVENT_KIND, SD_B, TOK_WRITE_RESTRICTED_2, 0x001ffe03, 0x001f0003 },
    { EVENT_KIND, SD_C, TOK_NORMAL, 0x000a6c00, 0x00160000 },
    { EVENT_KIND, SD_C, TOK_RESTRICTED, 0x00000000, 0x00000000 },
    { EVENT_KIND, SD_C, TOK_WRITE_RESTRICTED, 0x000a6400, 0x00120000 },
    { EVENT_KIND, SD_C, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a6c00, 0x00160000 },
    { EVENT_KIND, SD_C, TOK_WRITE_RESTRICTED_2, 0x000a6400, 0x00120000 },
    { EVENT_KIND, SD_NULL, TOK_NORMAL, 0x001fffff, 0x001f0003 },
    { EVENT_KIND, SD_NULL, TOK_RESTRICTED, 0x001fffff, 0x001f0003 },
    { EVENT_KIND, SD_NULL, TOK_WRITE_RESTRICTED, 0x001fffff, 0x001f0003 },
    { EVENT_KIND, SD_NULL, TOK_WRITE_RESTRICTED_NO_SIDS, 0x001fffff, 0x001f0003 },
    { EVENT_KIND, SD_NULL, TOK_WRITE_RESTRICTED_2, 0x001fffff, 0x001f0003 },
    { EVENT_KIND, SD_EMPTY, TOK_NORMAL, 0x00000c00, 0x00060000 },
    { EVENT_KIND, SD_EMPTY, TOK_RESTRICTED, 0x00000000, 0x00000000 },
    { EVENT_KIND, SD_EMPTY, TOK_WRITE_RESTRICTED, 0x00000000, 0x00000000 },
    { EVENT_KIND, SD_EMPTY, TOK_WRITE_RESTRICTED_NO_SIDS, 0x00000c00, 0x00060000 },
    { EVENT_KIND, SD_EMPTY, TOK_WRITE_RESTRICTED_2, 0x00000000, 0x00000000 },
    { EVENT_KIND, SD_D, TOK_NORMAL, 0x001ffe03, 0x001f0003 },
    { EVENT_KIND, SD_D, TOK_RESTRICTED, 0x00001a01, 0x000d0001 },
    { EVENT_KIND, SD_D, TOK_WRITE_RESTRICTED, 0x000a7e01, 0x001f0001 },
    { EVENT_KIND, SD_D, TOK_WRITE_RESTRICTED_NO_SIDS, 0x000a6c01, 0x00160001 },
    { EVENT_KIND, SD_D, TOK_WRITE_RESTRICTED_2, 0x000a7e01, 0x001f0001 },
};

static HANDLE Tokens[5];
static PSECURITY_DESCRIPTOR Sds[3][6];

static VOID
MakeSds(VOID)
{
    INT m, s;
    CHAR Text[256], A[16], R[16], W[16];
    PCSTR p;
    PSTR o;

    for (m = 0; m < 3; m++)
    {
        StringCbPrintfA(A, sizeof(A), "0x%lx", Maps[m].GenericAll);
        StringCbPrintfA(R, sizeof(R), "0x%lx", Maps[m].GenericRead);
        StringCbPrintfA(W, sizeof(W), "0x%lx", Maps[m].GenericWrite);
        for (s = 0; s < 6; s++)
        {
            for (p = SdText[s], o = Text; *p; )
            {
                if (*p == '@')
                {
                    PCSTR x = (p[1] == 'A') ? A : (p[1] == 'R') ? R : W;
                    while (*x)
                        *o++ = *x++;
                    p += 2;
                }
                else
                {
                    *o++ = *p++;
                }
            }
            *o = 0;
            ok(ConvertStringSecurityDescriptorToSecurityDescriptorA(Text, SDDL_REVISION_1, &Sds[m][s], NULL),
               "SDDL %s failed with %lu\n", Text, GetLastError());
        }
    }
}

static BOOL
MakeTokens(VOID)
{
    HANDLE hProcess = NULL, hImp = NULL;
    BYTE Sid33[SECURITY_MAX_SID_SIZE], SidWd[SECURITY_MAX_SID_SIZE];
    DWORD cb = sizeof(Sid33);
    SID_AND_ATTRIBUTES Restrict[2];
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcess))
        return FALSE;
    Ret = DuplicateTokenEx(hProcess, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hImp);
    CloseHandle(hProcess);
    ok(Ret, "DuplicateTokenEx failed with %lu\n", GetLastError());
    if (!Ret)
        return FALSE;
    Ret = CreateRestrictedToken(hImp, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &Tokens[TOK_NORMAL]);
    ok(Ret, "DISABLE_MAX_PRIVILEGE failed with %lu\n", GetLastError());
    CloseHandle(hImp);
    if (!Ret)
        return FALSE;

    {
        SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
        PISID Sid = (PISID)Sid33;

        RtlInitializeSid(Sid, &NtAuthority, 1);
        *RtlSubAuthoritySid(Sid, 0) = 33;
    }
    cb = sizeof(SidWd);
    CreateWellKnownSid(WinWorldSid, NULL, SidWd, &cb);
    Restrict[0].Sid = Sid33;
    Restrict[0].Attributes = 0;
    Restrict[1].Sid = SidWd;
    Restrict[1].Attributes = 0;

    Ret = CreateRestrictedToken(Tokens[TOK_NORMAL], 0, 0, NULL, 0, NULL, 1, Restrict, &Tokens[TOK_RESTRICTED]);
    ok(Ret, "restricted token failed with %lu\n", GetLastError());
    Ret = Ret && CreateRestrictedToken(Tokens[TOK_NORMAL], WRITE_RESTRICTED, 0, NULL, 0, NULL, 1, Restrict,
                                       &Tokens[TOK_WRITE_RESTRICTED]);
    ok(Ret, "write restricted token failed with %lu\n", GetLastError());
    Ret = Ret && CreateRestrictedToken(Tokens[TOK_NORMAL], WRITE_RESTRICTED, 0, NULL, 0, NULL, 0, NULL,
                                       &Tokens[TOK_WRITE_RESTRICTED_NO_SIDS]);
    ok(Ret, "write restricted token without SIDs failed with %lu\n", GetLastError());
    Ret = Ret && CreateRestrictedToken(Tokens[TOK_NORMAL], WRITE_RESTRICTED, 0, NULL, 0, NULL, 2, Restrict,
                                       &Tokens[TOK_WRITE_RESTRICTED_2]);
    ok(Ret, "write restricted token with two SIDs failed with %lu\n", GetLastError());
    return Ret;
}

static VOID
TestRows(VOID)
{
    PRIVILEGE_SET Ps;
    DWORD Psl, Granted, Mask, i, Max;
    BOOL Status, Ok;
    ULONG r;

    for (r = 0; r < ARRAYSIZE(Rows); r++)
    {
        PSECURITY_DESCRIPTOR Sd = Sds[Rows[r].Kind][Rows[r].Sd];
        PGENERIC_MAPPING Map = &Maps[Rows[r].Kind];
        HANDLE hToken = Tokens[Rows[r].Token];

        Mask = 0;
        for (i = 0; i < ARRAYSIZE(Accesses); i++)
        {
            DWORD Desired = Accesses[i];

            MapGenericMask(&Desired, Map);
            Psl = sizeof(Ps);
            Granted = 0;
            Status = FALSE;
            if (AccessCheck(Sd, hToken, Desired, Map, &Ps, &Psl, &Granted, &Status) && Status)
                Mask |= 1u << i;
        }

        Psl = sizeof(Ps);
        Granted = 0;
        Status = FALSE;
        Ok = AccessCheck(Sd, hToken, MAXIMUM_ALLOWED, Map, &Ps, &Psl, &Granted, &Status);
        Max = (Ok && Status) ? Granted : 0;

        ok(Mask == Rows[r].Allowed, "row %lu (kind %d, descriptor %d, token %d): granted 0x%08lx, expected 0x%08lx\n",
           r, Rows[r].Kind, Rows[r].Sd, Rows[r].Token, Mask, Rows[r].Allowed);
        ok(Max == Rows[r].MaxGranted, "row %lu (kind %d, descriptor %d, token %d): MAXIMUM_ALLOWED 0x%08lx, expected 0x%08lx\n",
           r, Rows[r].Kind, Rows[r].Sd, Rows[r].Token, Max, Rows[r].MaxGranted);
    }
}

#define TOKEN_ACCESS_INFORMATION_CLASS ((TOKEN_INFORMATION_CLASS)22)

/* The start of TOKEN_ACCESS_INFORMATION (the header of an older PSDK does not declare it) */
typedef struct _WR_TOKEN_ACCESS_INFORMATION
{
    PVOID SidHash;
    PVOID RestrictedSidHash;
    PVOID Privileges;
    LUID AuthenticationId;
    DWORD TokenType;
    DWORD ImpersonationLevel;
    DWORD MandatoryPolicy;
    DWORD Flags;
} WR_TOKEN_ACCESS_INFORMATION, *PWR_TOKEN_ACCESS_INFORMATION;
#define TOKEN_IS_RESTRICTED_CLASS ((TOKEN_INFORMATION_CLASS)40)

/* TOKEN_ACCESS_INFORMATION.Flags, TokenIsRestricted and the restricting SIDs (up to 4) of a token */
static VOID
QueryToken(
    _In_ HANDLE hToken,
    _Out_ PDWORD AccessFlags,
    _Out_ PDWORD IsRestricted,
    _Out_ PDWORD SidCount,
    _Out_writes_(4) PSID *Sids)
{
    BYTE Buffer[2048];
    DWORD Length, i;
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    static BYTE Copies[4][SECURITY_MAX_SID_SIZE];

    *AccessFlags = 0xdeadbeef;
    *IsRestricted = 0xdeadbeef;
    *SidCount = 0xdeadbeef;
    Length = 0;
    if (GetTokenInformation(hToken, TOKEN_ACCESS_INFORMATION_CLASS, Buffer, sizeof(Buffer), &Length))
        *AccessFlags = ((PWR_TOKEN_ACCESS_INFORMATION)Buffer)->Flags;
    else
        ok(0, "TokenAccessInformation failed with %lu\n", GetLastError());
    Length = 0;
    if (!GetTokenInformation(hToken, TOKEN_IS_RESTRICTED_CLASS, IsRestricted, sizeof(*IsRestricted), &Length))
        ok(0, "TokenIsRestricted failed with %lu\n", GetLastError());
    if (GetTokenInformation(hToken, TokenRestrictedSids, Buffer, sizeof(Buffer), &Length))
    {
        *SidCount = Groups->GroupCount;
        for (i = 0; i < Groups->GroupCount && i < 4; i++)
        {
            CopySid(SECURITY_MAX_SID_SIZE, Copies[i], Groups->Groups[i].Sid);
            Sids[i] = Copies[i];
            ok(Groups->Groups[i].Attributes == 0x7, "restricting SID %lu has attributes 0x%lx\n", i, Groups->Groups[i].Attributes);
        }
    }
    else
        ok(0, "TokenRestrictedSids failed with %lu\n", GetLastError());
}

/* Windows Server 2022: TokenIsRestricted and TOKEN_ACCESS_INFORMATION.Flags (0x8 write restricted, 0x10 restricted) */
static VOID
TestTokenReports(VOID)
{
    static const struct { INT Token; DWORD Flags; DWORD IsRestricted; DWORD Sids; } Expected[] =
    {
        { TOK_NORMAL, 0, 0, 0 },
        { TOK_RESTRICTED, 0x10, 1, 1 },
        { TOK_WRITE_RESTRICTED, 0x18, 1, 1 },
        { TOK_WRITE_RESTRICTED_NO_SIDS, 0x18, 1, 0 },
        { TOK_WRITE_RESTRICTED_2, 0x18, 1, 2 },
    };
    DWORD i, Flags, IsRestricted, Count;
    PSID Sids[4];

    for (i = 0; i < ARRAYSIZE(Expected); i++)
    {
        QueryToken(Tokens[Expected[i].Token], &Flags, &IsRestricted, &Count, Sids);
        ok((Flags & 0x18) == Expected[i].Flags, "token %d: access information flags 0x%lx, expected 0x%lx in 0x18\n",
           Expected[i].Token, Flags, Expected[i].Flags);
        ok(IsRestricted == Expected[i].IsRestricted, "token %d: TokenIsRestricted %lu, expected %lu\n",
           Expected[i].Token, IsRestricted, Expected[i].IsRestricted);
        ok(Count == Expected[i].Sids, "token %d: %lu restricting SIDs, expected %lu\n", Expected[i].Token, Count, Expected[i].Sids);
    }
}

static BOOL
CanOpen(HANDLE hToken, DWORD Desired)
{
    PRIVILEGE_SET Ps;
    DWORD Psl = sizeof(Ps), Granted = 0;
    BOOL Status = FALSE;
    PGENERIC_MAPPING Map = &Maps[FILE_KIND];

    MapGenericMask(&Desired, Map);
    return AccessCheck(Sds[FILE_KIND][SD_A], hToken, Desired, Map, &Ps, &Psl, &Granted, &Status) && Status;
}

/*
 * Windows Server 2022, CreateRestrictedToken on a token that is restricted already: it needs a list of restricting SIDs
 * (also without WRITE_RESTRICTED, DISABLE_MAX_PRIVILEGE or deny-only SIDs on their own: ERROR_INVALID_PARAMETER), WRITE_RESTRICTED
 * is refused, the new token has the SIDs the list and the token have in common in the order of the list (none: refused),
 * and it is a plain restricted token (no 0x8, the reads are compared too). A write restricted token without restricting SIDs
 * is restricted too: filtered it gives a token that is granted nothing (and one that takes a list, which makes it restricted).
 */
static VOID
TestFiltering(VOID)
{
    static const struct
    {
        INT Source;
        DWORD Flags;
        INT List[3];          /* 0 for 33, 1 for Everyone, -1 ends the list */
        DWORD Error;          /* 0: it works */
        INT Result[3];        /* the restricting SIDs of the new token, -1 ends */
    } Cases[] =
    {
        { TOK_RESTRICTED, 0, { -1 }, ERROR_INVALID_PARAMETER },
        { TOK_RESTRICTED, DISABLE_MAX_PRIVILEGE, { -1 }, ERROR_INVALID_PARAMETER },
        { TOK_RESTRICTED, WRITE_RESTRICTED, { -1 }, ERROR_INVALID_PARAMETER },
        { TOK_RESTRICTED, WRITE_RESTRICTED, { 0, -1 }, ERROR_INVALID_PARAMETER },
        { TOK_RESTRICTED, 0, { 1, -1 }, ERROR_INVALID_PARAMETER },
        { TOK_RESTRICTED, 0, { 0, -1 }, 0, { 0, -1 } },
        { TOK_RESTRICTED, 0, { 1, 0, -1 }, 0, { 0, -1 } },
        { TOK_RESTRICTED, DISABLE_MAX_PRIVILEGE, { 0, -1 }, 0, { 0, -1 } },
        { TOK_WRITE_RESTRICTED, 0, { -1 }, ERROR_INVALID_PARAMETER },
        { TOK_WRITE_RESTRICTED, 0, { 1, -1 }, ERROR_INVALID_PARAMETER },
        { TOK_WRITE_RESTRICTED, WRITE_RESTRICTED, { 0, -1 }, ERROR_INVALID_PARAMETER },
        { TOK_WRITE_RESTRICTED, 0, { 0, -1 }, 0, { 0, -1 } },
        { TOK_WRITE_RESTRICTED_2, 0, { -1 }, ERROR_INVALID_PARAMETER },
        { TOK_WRITE_RESTRICTED_2, 0, { 1, -1 }, 0, { 1, -1 } },
        { TOK_WRITE_RESTRICTED_2, 0, { 1, 0, -1 }, 0, { 1, 0, -1 } },
        { TOK_WRITE_RESTRICTED_2, 0, { 0, 1, -1 }, 0, { 0, 1, -1 } },
        { TOK_WRITE_RESTRICTED_NO_SIDS, WRITE_RESTRICTED, { -1 }, ERROR_INVALID_PARAMETER },
        { TOK_WRITE_RESTRICTED_NO_SIDS, WRITE_RESTRICTED, { 1, -1 }, ERROR_INVALID_PARAMETER },
        { TOK_WRITE_RESTRICTED_NO_SIDS, 0, { -1 }, 0, { -1 } },
        { TOK_WRITE_RESTRICTED_NO_SIDS, DISABLE_MAX_PRIVILEGE, { -1 }, 0, { -1 } },
        { TOK_WRITE_RESTRICTED_NO_SIDS, 0, { 1, -1 }, 0, { 1, -1 } },
        { TOK_WRITE_RESTRICTED_NO_SIDS, 0, { 1, 0, -1 }, 0, { 1, 0, -1 } },
    };
    BYTE Sid33[SECURITY_MAX_SID_SIZE], SidWd[SECURITY_MAX_SID_SIZE];
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    DWORD cb = sizeof(SidWd), c, i, n, Flags, IsRestricted, Count;
    SID_AND_ATTRIBUTES List[3];
    PSID Sids[4];
    HANDLE hNew;

    RtlInitializeSid((PSID)Sid33, &NtAuthority, 1);
    *RtlSubAuthoritySid((PSID)Sid33, 0) = 33;
    CreateWellKnownSid(WinWorldSid, NULL, SidWd, &cb);

    for (c = 0; c < ARRAYSIZE(Cases); c++)
    {
        for (n = 0; Cases[c].List[n] != -1; n++)
        {
            List[n].Sid = Cases[c].List[n] ? SidWd : Sid33;
            List[n].Attributes = 0;
        }

        hNew = NULL;
        SetLastError(0xdeadbeef);
        if (!CreateRestrictedToken(Tokens[Cases[c].Source], Cases[c].Flags, 0, NULL, 0, NULL, n, n ? List : NULL, &hNew))
        {
            ok(Cases[c].Error != 0, "case %lu: failed with %lu, expected to work\n", c, GetLastError());
            ok(Cases[c].Error == 0 || GetLastError() == Cases[c].Error, "case %lu: error %lu, expected %lu\n",
               c, GetLastError(), Cases[c].Error);
            continue;
        }

        ok(Cases[c].Error == 0, "case %lu: worked, expected error %lu\n", c, Cases[c].Error);
        QueryToken(hNew, &Flags, &IsRestricted, &Count, Sids);
        for (i = 0; Cases[c].Result[i] != -1; i++)
            ;
        ok(Count == i, "case %lu: %lu restricting SIDs, expected %lu\n", c, Count, i);
        ok((Flags & 0x18) == 0x10, "case %lu: access information flags 0x%lx, expected 0x10 in 0x18\n", c, Flags);
        ok(IsRestricted == 1, "case %lu: TokenIsRestricted %lu\n", c, IsRestricted);
        for (n = 0; n < i && n < Count; n++)
            ok(EqualSid(Sids[n], Cases[c].Result[n] ? SidWd : Sid33), "case %lu: restricting SID %lu is not the expected one\n", c, n);

        /* a restricted token, no longer a write restricted one: the descriptor of the Administrators only is not read */
        ok(!CanOpen(hNew, GENERIC_READ), "case %lu: the new token can read\n", c);
        CloseHandle(hNew);
    }

    /* the write restricted token itself reads and does not write (the descriptor grants the Administrators) */
    ok(CanOpen(Tokens[TOK_WRITE_RESTRICTED_NO_SIDS], GENERIC_READ), "write restricted token without SIDs cannot read\n");
    ok(!CanOpen(Tokens[TOK_WRITE_RESTRICTED_NO_SIDS], GENERIC_WRITE), "write restricted token without SIDs can write\n");
}

START_TEST(WriteRestrictedToken)
{
    INT i;

    if (!MakeTokens())
    {
        skip("no tokens\n");
        return;
    }

    /* Windows Server 2022: the flag does not make a token restricted by itself */
    ok(!IsTokenRestricted(Tokens[TOK_NORMAL]), "normal token restricted\n");
    ok(IsTokenRestricted(Tokens[TOK_RESTRICTED]), "restricted token not restricted\n");
    ok(IsTokenRestricted(Tokens[TOK_WRITE_RESTRICTED]), "write restricted token not restricted\n");
    ok(!IsTokenRestricted(Tokens[TOK_WRITE_RESTRICTED_NO_SIDS]), "write restricted token without SIDs restricted\n");
    ok(IsTokenRestricted(Tokens[TOK_WRITE_RESTRICTED_2]), "write restricted token with two SIDs not restricted\n");

    MakeSds();
    TestTokenReports();
    TestFiltering();
    TestRows();

    /* Windows Server 2022: a copy of a write restricted token (primary, then impersonation again) is write restricted too */
    {
        HANDLE hPrimary = NULL, hCopy = NULL, hOriginal = Tokens[TOK_WRITE_RESTRICTED];

        ok(DuplicateTokenEx(hOriginal, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hPrimary),
           "DuplicateTokenEx(primary) failed with %lu\n", GetLastError());
        ok(hPrimary && DuplicateTokenEx(hPrimary, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hCopy),
           "DuplicateTokenEx(impersonation) failed with %lu\n", GetLastError());
        if (hCopy)
        {
            Tokens[TOK_WRITE_RESTRICTED] = hCopy;
            TestRows();
            Tokens[TOK_WRITE_RESTRICTED] = hOriginal;
            CloseHandle(hCopy);
        }
        if (hPrimary)
            CloseHandle(hPrimary);
    }

    for (i = 0; i < 5; i++)
        if (Tokens[i])
            CloseHandle(Tokens[i]);
}
