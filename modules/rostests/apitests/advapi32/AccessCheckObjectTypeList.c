/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     AccessCheckByType and AccessCheckByTypeResultList with object type lists
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Each case is one call: a token (the caller's token, or a copy restricted to Everyone), a DACL of
 * plain and object ACEs, an object type list, and a desired access. The call is described by one
 * line (return value, last error, granted access and status of each entry) and the line is compared
 * with the one Windows 10 22H2 gave for the same case (AccessCheckObjectTypeList.inc, measured as an
 * elevated administrator; a 64-bit and a 32-bit process gave the same lines, harness evidence
 * acotl-20261106). Built with ACOTL_STANDALONE, the file is the program that printed them (the
 * oracle run used a copy that formatted the lines with sprintf; the lines are the same).
 *
 * The owner and group of the security descriptor are LocalSystem, so no implicit owner rights.
 * The rights are 1, 2 and 4 with a generic mapping of their own.
 */

#ifndef ACOTL_STANDALONE
#include "precomp.h"
#else
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#endif

#ifndef ACL_REVISION_DS
#define ACL_REVISION_DS 4
#endif

static GENERIC_MAPPING Mapping = { 1, 2, 4, 7 };

/* g0 is the root of every list; g9 is in no list */
static GUID Guids[] =
{
    { 0x6b0e2a10, 0x1d1f, 0x4e55, { 0x9a, 0x51, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { 0x6b0e2a10, 0x1d1f, 0x4e55, { 0x9a, 0x51, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01 } },
    { 0x6b0e2a10, 0x1d1f, 0x4e55, { 0x9a, 0x51, 0x30, 0x00, 0x00, 0x00, 0x00, 0x02 } },
    { 0x6b0e2a10, 0x1d1f, 0x4e55, { 0x9a, 0x51, 0x30, 0x00, 0x00, 0x00, 0x00, 0x03 } },
    { 0x6b0e2a10, 0x1d1f, 0x4e55, { 0x9a, 0x51, 0x30, 0x00, 0x00, 0x00, 0x00, 0x09 } },
};
#define G0 0
#define G1 1
#define G2 2
#define G3 3
#define G9 4

typedef struct
{
    char Type;      /* A allow, D deny, a allowed object, d denied object, n allowed object without a type */
    char Sid;       /* U the token user, E Everyone */
    ACCESS_MASK Mask;
    int Guid;
} ACE_SPEC;

#define MAX_ACES 3
typedef struct { ACE_SPEC Aces[MAX_ACES]; } DACL_SPEC;

static const DACL_SPEC Dacls[] =
{
    /*  1 */ {{ { 'A', 'U', 3, -1 } }},
    /*  2 */ {{ { 'a', 'U', 3, G0 } }},
    /*  3 */ {{ { 'a', 'U', 3, G1 } }},
    /*  4 */ {{ { 'a', 'U', 3, G1 }, { 'a', 'U', 3, G2 } }},
    /*  5 */ {{ { 'A', 'U', 3, -1 }, { 'd', 'U', 2, G1 } }},
    /*  6 */ {{ { 'd', 'U', 2, G1 }, { 'A', 'U', 3, -1 } }},
    /*  7 */ {{ { 'D', 'U', 2, -1 }, { 'a', 'U', 3, G1 } }},
    /*  8 */ {{ { 'n', 'U', 1, -1 } }},
    /*  9 */ {{ { 'a', 'U', 3, G9 } }},
    /* 10 */ {{ { 'A', 'U', 1, -1 }, { 'a', 'U', 2, G1 } }},
    /* 11 */ {{ { 'a', 'U', 1, G3 } }},
    /* 12 */ {{ { 'a', 'U', 1, G1 }, { 'a', 'U', 2, G0 } }},
    /* 13 */ {{ { 'd', 'U', 2, G0 }, { 'A', 'U', 3, -1 } }},
    /* 14 */ {{ { 'd', 'U', 1, G2 }, { 'a', 'U', 3, G0 } }},
    /* 15 */ {{ { 'A', 'E', 1, -1 }, { 'A', 'U', 3, -1 } }},
    /* 16 */ {{ { 'A', 'U', 1, -1 } }},
    /* 17 */ {{ { 'a', 'E', 1, G1 }, { 'A', 'U', 3, -1 } }},
    /* 18 */ {{ { 'a', 'E', 3, G1 }, { 'A', 'U', 1, -1 } }},
    /* 19 */ {{ { 'A', 'E', 3, -1 }, { 'd', 'E', 2, G1 } }},
    /* 20 */ {{ { 'a', 'U', 1, G3 }, { 'a', 'U', 1, G2 } }},
    /* 21 */ {{ { 'a', 'U', 1, G1 }, { 'a', 'U', 1, G2 } }},
};

/* Lists: '0' none, A = root, B = root with two children, C = B with a grandchild under the first child */
typedef struct { char Name; int Count; USHORT Level[4]; int Guid[4]; } LIST_SPEC;
static const LIST_SPEC Lists[] =
{
    { '0', 0, { 0 }, { 0 } },
    { 'A', 1, { 0 }, { G0 } },
    { 'B', 3, { 0, 1, 1 }, { G0, G1, G2 } },
    { 'C', 4, { 0, 1, 2, 1 }, { G0, G1, G3, G2 } },
};

static const ACCESS_MASK Wants[] = { MAXIMUM_ALLOWED, 1, 3 };

static BOOL BuildDacl(PACL Acl, DWORD Size, const DACL_SPEC *Spec, PSID User, PSID Everyone)
{
    int i;

    if (!InitializeAcl(Acl, Size, ACL_REVISION_DS))
        return FALSE;
    for (i = 0; i < MAX_ACES && Spec->Aces[i].Type; i++)
    {
        const ACE_SPEC *Ace = &Spec->Aces[i];
        PSID Sid = Ace->Sid == 'E' ? Everyone : User;
        GUID *Guid = Ace->Guid >= 0 ? &Guids[Ace->Guid] : NULL;
        BOOL Ret;

        switch (Ace->Type)
        {
        case 'A': Ret = AddAccessAllowedAceEx(Acl, ACL_REVISION_DS, 0, Ace->Mask, Sid); break;
        case 'D': Ret = AddAccessDeniedAceEx(Acl, ACL_REVISION_DS, 0, Ace->Mask, Sid); break;
        case 'a': case 'n': Ret = AddAccessAllowedObjectAce(Acl, ACL_REVISION_DS, 0, Ace->Mask, Guid, NULL, Sid); break;
        case 'd': Ret = AddAccessDeniedObjectAce(Acl, ACL_REVISION_DS, 0, Ace->Mask, Guid, NULL, Sid); break;
        default: Ret = FALSE; break;
        }
        if (!Ret)
            return FALSE;
    }
    return TRUE;
}

typedef void (*EMIT_LINE)(const char *Line);

static void RunCase(EMIT_LINE Emit, HANDLE Token, char TokenName, int DaclIndex, PSECURITY_DESCRIPTOR Sd,
                    const LIST_SPEC *List, ACCESS_MASK Want, BOOL ResultList)
{
    OBJECT_TYPE_LIST Otl[4];
    BYTE PrivilegeSet[256];
    DWORD PrivilegeSetLength = sizeof(PrivilegeSet);
    DWORD Granted[4];
    BOOL Status[4];
    BOOL Ret;
    DWORD Error;
    char Line[256], Part[32];
    int i;

    for (i = 0; i < List->Count; i++)
    {
        Otl[i].Level = List->Level[i];
        Otl[i].Sbz = 0;
        Otl[i].ObjectType = &Guids[List->Guid[i]];
    }
    for (i = 0; i < 4; i++)
    {
        Granted[i] = 0xdeadbeef;
        Status[i] = 7;
    }

    SetLastError(0xdead);
    if (ResultList)
        Ret = AccessCheckByTypeResultList(Sd, NULL, Token, Want, Otl, List->Count, &Mapping,
                                          (PPRIVILEGE_SET)PrivilegeSet, &PrivilegeSetLength, Granted, (void *)Status);
    else
        Ret = AccessCheckByType(Sd, NULL, Token, Want, List->Count ? Otl : NULL, List->Count, &Mapping,
                                (PPRIVILEGE_SET)PrivilegeSet, &PrivilegeSetLength, Granted, Status);
    Error = GetLastError();

    StringCbPrintfA(Line, sizeof(Line), "%c dacl=%02d list=%c want=%08lx %c ret=%d err=%lu g=", TokenName,
                    DaclIndex + 1, List->Name, Want, ResultList ? 'L' : 'T', Ret, Ret && Error == 0xdead ? 0 : Error);
    for (i = 0; i < (ResultList ? List->Count : 1); i++)
    {
        StringCbPrintfA(Part, sizeof(Part), "%s%lx", i ? "," : "", Granted[i]);
        StringCbCatA(Line, sizeof(Line), Part);
    }
    StringCbCatA(Line, sizeof(Line), " st=");
    for (i = 0; i < (ResultList ? List->Count : 1); i++)
    {
        StringCbPrintfA(Part, sizeof(Part), "%s%d", i ? "," : "", Status[i]);
        StringCbCatA(Line, sizeof(Line), Part);
    }
    Emit(Line);
}

static void RunAll(EMIT_LINE Emit, void (*Fail)(const char *What, DWORD Error))
{
    SID_IDENTIFIER_AUTHORITY World = { SECURITY_WORLD_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY Nt = { SECURITY_NT_AUTHORITY };
    BYTE UserBuffer[512];
    union { ACL Acl; BYTE Buffer[512]; } AclBuffer;
    SECURITY_DESCRIPTOR Sd;
    SID_AND_ATTRIBUTES Restrict;
    PSID Everyone = NULL, System = NULL, User;
    HANDLE Process = NULL, Restricted = NULL, Tokens[2] = { NULL, NULL };
    DWORD Length;
    int t, d, l, w, r;

    if (!AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone) ||
        !AllocateAndInitializeSid(&Nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &System))
    {
        Fail("AllocateAndInitializeSid", GetLastError());
        goto Cleanup;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &Process) ||
        !GetTokenInformation(Process, TokenUser, UserBuffer, sizeof(UserBuffer), &Length))
    {
        Fail("process token", GetLastError());
        goto Cleanup;
    }
    User = ((PTOKEN_USER)UserBuffer)->User.Sid;
    Restrict.Sid = Everyone;
    Restrict.Attributes = 0;
    if (!CreateRestrictedToken(Process, 0, 0, NULL, 0, NULL, 1, &Restrict, &Restricted))
    {
        Fail("CreateRestrictedToken", GetLastError());
        goto Cleanup;
    }
    if (!DuplicateToken(Process, SecurityImpersonation, &Tokens[0]) ||
        !DuplicateToken(Restricted, SecurityImpersonation, &Tokens[1]))
    {
        Fail("DuplicateToken", GetLastError());
        goto Cleanup;
    }

    for (t = 0; t < 2; t++)
    {
        for (d = 0; d < (int)(sizeof(Dacls) / sizeof(Dacls[0])); d++)
        {
            if (!BuildDacl(&AclBuffer.Acl, sizeof(AclBuffer), &Dacls[d], User, Everyone))
            {
                Fail("BuildDacl", GetLastError());
                goto Cleanup;
            }
            InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
            SetSecurityDescriptorOwner(&Sd, System, FALSE);
            SetSecurityDescriptorGroup(&Sd, System, FALSE);
            SetSecurityDescriptorDacl(&Sd, TRUE, &AclBuffer.Acl, FALSE);

            for (l = 0; l < (int)(sizeof(Lists) / sizeof(Lists[0])); l++)
                for (w = 0; w < (int)(sizeof(Wants) / sizeof(Wants[0])); w++)
                    for (r = 0; r < (Lists[l].Count ? 2 : 1); r++)
                        RunCase(Emit, Tokens[t], t ? 'R' : 'U', d, &Sd, &Lists[l], Wants[w], r);
        }
    }

Cleanup:
    if (Tokens[0]) CloseHandle(Tokens[0]);
    if (Tokens[1]) CloseHandle(Tokens[1]);
    if (Restricted) CloseHandle(Restricted);
    if (Process) CloseHandle(Process);
    if (System) FreeSid(System);
    if (Everyone) FreeSid(Everyone);
}

#ifdef ACOTL_STANDALONE

static void PrintLine(const char *Line)
{
    printf("%s\n", Line);
}

static void PrintFail(const char *What, DWORD Error)
{
    printf("FAIL %s %lu\n", What, Error);
}

int main(void)
{
    printf("ACOTL ptr=%u\n", (unsigned)sizeof(void *));
    RunAll(PrintLine, PrintFail);
    printf("ACOTL done\n");
    return 0;
}

#else

static const char *Expected[] =
{
#include "AccessCheckObjectTypeList.inc"
};
static unsigned ExpectedIndex;

static void CompareLine(const char *Line)
{
    if (ExpectedIndex >= sizeof(Expected) / sizeof(Expected[0]))
    {
        ok(0, "unexpected line %s\n", Line);
        return;
    }
    ok(!strcmp(Line, Expected[ExpectedIndex]), "got      %s\n        expected %s\n", Line, Expected[ExpectedIndex]);
    ExpectedIndex++;
}

static void SetupFail(const char *What, DWORD Error)
{
    ok(0, "%s failed: %lu\n", What, Error);
}

START_TEST(AccessCheckObjectTypeList)
{
    RunAll(CompareLine, SetupFail);
    ok(ExpectedIndex == sizeof(Expected) / sizeof(Expected[0]), "%u lines, expected %u\n",
       ExpectedIndex, (unsigned)(sizeof(Expected) / sizeof(Expected[0])));
}

#endif
