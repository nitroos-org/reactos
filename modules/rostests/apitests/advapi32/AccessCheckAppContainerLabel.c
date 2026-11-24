/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The mandatory label and a lowbox (AppContainer) token
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (AccessCheck of a lowbox token, integrity level Low, made from the token of an
 * administrator, against descriptors built in memory; the package ACE and the user's ACE both grant the rights):
 *  - no label (the implicit Medium one), a Low label and a Medium label: the lowbox token is granted all of them
 *    (a plain token at Low is granted them only with the Low label; it is below the implicit Medium label);
 *  - a High label: nothing (the plain Medium token of the same user: the same);
 *  - a descriptor that has only the package ACE: nothing (the normal pass, the user's groups, grants nothing).
 * So what the package ACE grants is not held back by a label of Medium or below (that is what lets an AppContainer
 * process write the key of its own registry storage, which has no label), and is held back by a High one.
 */

#include "precomp.h"
#include <sddl.h>

static UCHAR AcPackage[] = { 1, 8, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0,
                             4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0 };
#define AC_PKG L"S-1-15-2-1-2-3-4-5-6-7"

static GENERIC_MAPPING AcMapping = { 0x1, 0x2, 0x4, 0x7 };
static WCHAR UserSid[128];

/* The rights granted by AccessCheck for a descriptor made of the user's SID, the DACL and the label */
static ACCESS_MASK Check(HANDLE Token, PCWSTR Dacl, PCWSTR Label, ACCESS_MASK Desired)
{
    WCHAR Sddl[1024];
    PSECURITY_DESCRIPTOR Sd;
    UCHAR PrivBuffer[256];
    DWORD PrivLength = sizeof(PrivBuffer);
    ACCESS_MASK Granted = 0;
    BOOL Status = FALSE;

    StringCbPrintfW(Sddl, sizeof(Sddl), L"O:%sG:%s%s%s", UserSid, UserSid, Dacl, Label);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
    {
        ok(0, "%S: SDDL error %lu\n", Sddl, GetLastError());
        return 0xdeadbeef;
    }
    ok(AccessCheck(Sd, Token, Desired, &AcMapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, &Granted, &Status),
       "AccessCheck failed: %lu\n", GetLastError());
    LocalFree(Sd);
    return Status ? Granted : 0;
}

static ULONG LevelOf(HANDLE Token)
{
    UCHAR Buffer[64];
    DWORD Length;
    PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)Buffer;

    if (!GetTokenInformation(Token, TokenIntegrityLevel, Buffer, sizeof(Buffer), &Length))
        return 0xFFFFFFFF;
    return *GetSidSubAuthority(Label->Label.Sid, *GetSidSubAuthorityCount(Label->Label.Sid) - 1);
}

static HANDLE TokenAtLevel(HANDLE Source, ULONG Rid)
{
    SID_IDENTIFIER_AUTHORITY Authority = { SECURITY_MANDATORY_LABEL_AUTHORITY };
    TOKEN_MANDATORY_LABEL Label;
    HANDLE Token = NULL;
    PSID Sid = NULL;

    if (DuplicateTokenEx(Source, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Token) &&
        AllocateAndInitializeSid(&Authority, 1, Rid, 0, 0, 0, 0, 0, 0, 0, &Sid))
    {
        Label.Label.Sid = Sid;
        Label.Label.Attributes = SE_GROUP_INTEGRITY;
        ok(SetTokenInformation(Token, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid(Sid)),
           "SetTokenInformation failed: %lu\n", GetLastError());
        FreeSid(Sid);
    }
    return Token;
}

START_TEST(AccessCheckAppContainerLabel)
{
    typedef NTSTATUS (NTAPI *PFN_CreateLowBox)(PHANDLE, HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PSID, ULONG,
                                               PSID_AND_ATTRIBUTES, ULONG, HANDLE *);
    PFN_CreateLowBox pNtCreateLowBoxToken =
        (PFN_CreateLowBox)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateLowBoxToken");
    static const struct { PCWSTR Name, Label; } Labels[] =
    {
        { L"no label", L"" }, { L"Low", L"S:(ML;;NW;;;LW)" }, { L"Medium", L"S:(ML;;NW;;;ME)" },
        { L"Medium (no policy)", L"S:(ML;;;;;ME)" }, { L"High", L"S:(ML;;NW;;;HI)" }
    };
    /* 0x7 granted by the lowbox token, 0x7 by a Medium token, for a Low plain token only with the Low label */
    static const ACCESS_MASK LowboxRows[5] = { 7, 7, 7, 7, 0 };
    static const ACCESS_MASK MediumRows[5] = { 7, 7, 7, 7, 0 };
    static const ACCESS_MASK LowRows[5] = { 0, 7, 0, 0, 0 };
    UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    HANDLE Process, Medium, Low, Lowbox = NULL;
    WCHAR Dacl[256];
    PWSTR SidString;
    DWORD Length;
    NTSTATUS Status;
    ULONG i;

    if (!pNtCreateLowBoxToken)
    {
        skip("NtCreateLowBoxToken is not available\n");
        return;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process))
    {
        skip("no process token: %lu\n", GetLastError());
        return;
    }
    GetTokenInformation(Process, TokenUser, Buffer, sizeof(Buffer), &Length);
    ConvertSidToStringSidW(((PTOKEN_USER)Buffer)->User.Sid, &SidString);
    StringCbCopyW(UserSid, sizeof(UserSid), SidString);
    LocalFree(SidString);

    Medium = TokenAtLevel(Process, SECURITY_MANDATORY_MEDIUM_RID);
    Low = TokenAtLevel(Process, SECURITY_MANDATORY_LOW_RID);
    Status = pNtCreateLowBoxToken(&Lowbox, Medium, TOKEN_ALL_ACCESS, NULL, (PSID)AcPackage, 0, NULL, 0, NULL);
    ok(Status == STATUS_SUCCESS, "NtCreateLowBoxToken returned %lx\n", Status);
    if (NT_SUCCESS(Status) && Medium && Low)
    {
        trace("integrity levels: process %#lx, Medium copy %#lx, Low copy %#lx, lowbox %#lx\n", LevelOf(Process),
              LevelOf(Medium), LevelOf(Low), LevelOf(Lowbox));
        ok(LevelOf(Lowbox) == SECURITY_MANDATORY_LOW_RID, "the lowbox token is at %#lx, expected Low\n", LevelOf(Lowbox));
        /* the package ACE and the user's ACE both grant everything */
        StringCbPrintfW(Dacl, sizeof(Dacl), L"D:(A;;0x7;;;%s)(A;;0x7;;;" AC_PKG L")", UserSid);
        for (i = 0; i < ARRAYSIZE(Labels); i++)
        {
            ACCESS_MASK Granted = Check(Lowbox, Dacl, Labels[i].Label, 0x7);
            ok(Granted == LowboxRows[i], "lowbox, %S label: granted %#lx, expected %#lx\n", Labels[i].Name,
               Granted, LowboxRows[i]);
            Granted = Check(Lowbox, Dacl, Labels[i].Label, 0x2);
            ok(Granted == (LowboxRows[i] ? 0x2 : 0), "lowbox, %S label, write: granted %#lx\n", Labels[i].Name, Granted);
        }

        /* the user's ACE alone: the same rows for a plain token */
        StringCbPrintfW(Dacl, sizeof(Dacl), L"D:(A;;0x7;;;%s)", UserSid);
        for (i = 0; i < ARRAYSIZE(Labels); i++)
        {
            ACCESS_MASK Granted = Check(Medium, Dacl, Labels[i].Label, 0x7);
            ok(Granted == MediumRows[i], "Medium token, %S label: granted %#lx, expected %#lx\n", Labels[i].Name,
               Granted, MediumRows[i]);
            Granted = Check(Low, Dacl, Labels[i].Label, 0x7);
            ok(Granted == LowRows[i], "Low token, %S label: granted %#lx, expected %#lx\n", Labels[i].Name,
               Granted, LowRows[i]);
        }

        /* the package ACE alone: the user's groups grant nothing, the label does not matter */
        StringCbPrintfW(Dacl, sizeof(Dacl), L"D:(A;;0x7;;;" AC_PKG L")");
        for (i = 0; i < ARRAYSIZE(Labels); i++)
        {
            ACCESS_MASK Granted = Check(Lowbox, Dacl, Labels[i].Label, 0x7);
            ok(Granted == 0, "lowbox, package ACE only, %S label: granted %#lx\n", Labels[i].Name, Granted);
        }
    }
    if (Lowbox)
        CloseHandle(Lowbox);
    if (Medium)
        CloseHandle(Medium);
    if (Low)
        CloseHandle(Low);
    CloseHandle(Process);
}
