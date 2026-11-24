/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ConvertSecurityDescriptorToStringSecurityDescriptor prints a mandatory label ACE
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Rows measured on a Windows Server 2022 reference (32 and 64 bit, identical): a SACL with one mandatory label ACE
 * prints it for LABEL_SECURITY_INFORMATION ("S:(ML;;NW;;;LW)"), prints "S:" alone for SACL_SECURITY_INFORMATION (the
 * label belongs to the other flag), prints it for both, and prints nothing for DACL_SECURITY_INFORMATION. With an audit
 * ACE in front, SACL_SECURITY_INFORMATION prints the audit ACE alone, LABEL_SECURITY_INFORMATION the label alone,
 * both of them print both in order. The level is a well-known alias (LW, ME, MP, HI, SI) or S-1-16-<rid>; the policy
 * NW, NR, NX in that order, or empty for 0; the flags OI, CI, NP, IO, ID in the order of the other ACE types.
 * The parser reads the same strings back.
 */

#include "precomp.h"
#include <sddl.h>
#include <aclapi.h>
#include <strsafe.h>

typedef struct _LABEL_ROW
{
    DWORD Level;
    DWORD Policy;
    BYTE Flags;
    PCSTR Expected;     /* LABEL_SECURITY_INFORMATION */
} LABEL_ROW;

static const LABEL_ROW s_Rows[] =
{
    { 0x0000, 1, 0, "S:(ML;;NW;;;S-1-16-0)" },
    { 0x1000, 1, 0, "S:(ML;;NW;;;LW)" },
    { 0x2000, 1, 0, "S:(ML;;NW;;;ME)" },
    { 0x2100, 1, 0, "S:(ML;;NW;;;MP)" },
    { 0x2500, 1, 0, "S:(ML;;NW;;;S-1-16-9472)" },
    { 0x3000, 1, 0, "S:(ML;;NW;;;HI)" },
    { 0x4000, 1, 0, "S:(ML;;NW;;;SI)" },
    { 0x5000, 1, 0, "S:(ML;;NW;;;S-1-16-20480)" },
    { 0x1fff, 1, 0, "S:(ML;;NW;;;S-1-16-8191)" },
    { 0x2000, 0, 0, "S:(ML;;;;;ME)" },
    { 0x2000, 2, 0, "S:(ML;;NR;;;ME)" },
    { 0x2000, 3, 0, "S:(ML;;NWNR;;;ME)" },
    { 0x2000, 4, 0, "S:(ML;;NX;;;ME)" },
    { 0x2000, 5, 0, "S:(ML;;NWNX;;;ME)" },
    { 0x2000, 6, 0, "S:(ML;;NRNX;;;ME)" },
    { 0x2000, 7, 0, "S:(ML;;NWNRNX;;;ME)" },
    { 0x1000, 1, OBJECT_INHERIT_ACE, "S:(ML;OI;NW;;;LW)" },
    { 0x1000, 1, CONTAINER_INHERIT_ACE, "S:(ML;CI;NW;;;LW)" },
    { 0x1000, 1, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, "S:(ML;OICI;NW;;;LW)" },
    { 0x1000, 1, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE, "S:(ML;OICIIO;NW;;;LW)" },
    { 0x1000, 1, INHERITED_ACE, "S:(ML;ID;NW;;;LW)" },
    { 0x1000, 1, NO_PROPAGATE_INHERIT_ACE, "S:(ML;NP;NW;;;LW)" },
};

static BOOL (WINAPI *pAddMandatoryAce)(PACL, DWORD, DWORD, DWORD, PSID);

static void
Convert(PCSTR Tag, PSECURITY_DESCRIPTOR Sd, SECURITY_INFORMATION Info, PCSTR Expected)
{
    LPSTR Str = NULL;
    BOOL Ret = ConvertSecurityDescriptorToStringSecurityDescriptorA(Sd, SDDL_REVISION_1, Info, &Str, NULL);

    ok(Ret, "%s (info 0x%lx): failed, error %lu\n", Tag, Info, GetLastError());
    if (Ret)
    {
        ok(!strcmp(Str, Expected), "%s (info 0x%lx): got \"%s\", expected \"%s\"\n", Tag, Info, Str, Expected);
        LocalFree(Str);
    }
}

static void
CheckRow(const LABEL_ROW *Row, BOOL WithAudit)
{
    SECURITY_DESCRIPTOR Sd;
    BYTE AclBuffer[512], SidBuffer[SECURITY_MAX_SID_SIZE], WorldBuffer[SECURITY_MAX_SID_SIZE];
    SID_IDENTIFIER_AUTHORITY Authority = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    PACL Acl = (PACL)AclBuffer;
    PSID Sid = (PSID)SidBuffer;
    DWORD cb = sizeof(WorldBuffer);
    char Tag[64], Both[200];

    StringCbPrintfA(Tag, sizeof(Tag), "level 0x%lx policy %lu flags 0x%x%s", Row->Level, Row->Policy, Row->Flags,
                    WithAudit ? " after an audit ACE" : "");
    ok(InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION), "no SD\n");
    ok(InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION), "no ACL\n");
    ok(InitializeSid(Sid, &Authority, 1), "no SID\n");
    *GetSidSubAuthority(Sid, 0) = Row->Level;
    if (WithAudit)
    {
        ok(CreateWellKnownSid(WinWorldSid, NULL, WorldBuffer, &cb), "no world SID\n");
        ok(AddAuditAccessAce(Acl, ACL_REVISION, GENERIC_ALL, WorldBuffer, TRUE, TRUE), "no audit ACE\n");
    }
    if (!pAddMandatoryAce(Acl, ACL_REVISION, Row->Flags, Row->Policy, Sid))
    {
        ok(0, "%s: AddMandatoryAce failed, error %lu\n", Tag, GetLastError());
        return;
    }
    ok(SetSecurityDescriptorSacl(&Sd, TRUE, Acl, FALSE), "no SACL\n");

    Convert(Tag, &Sd, LABEL_SECURITY_INFORMATION, WithAudit ? "S:(ML;;NW;;;HI)" : Row->Expected);
    if (WithAudit)
        return;
    Convert(Tag, &Sd, SACL_SECURITY_INFORMATION, "S:");
    Convert(Tag, &Sd, LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, Row->Expected);
    Convert(Tag, &Sd, DACL_SECURITY_INFORMATION, "");
    (void)Both;
}

static void
CheckParse(PCSTR Text, DWORD Level, DWORD Policy, BYTE Flags, PCSTR Back)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Sacl = NULL;
    BOOL Present = FALSE, Defaulted;
    SYSTEM_MANDATORY_LABEL_ACE *Ace = NULL;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(Text, SDDL_REVISION_1, &Sd, NULL))
    {
        ok(0, "\"%s\" does not parse (error %lu)\n", Text, GetLastError());
        return;
    }
    ok(GetSecurityDescriptorSacl(Sd, &Present, &Sacl, &Defaulted) && Present && Sacl && Sacl->AceCount == 1,
       "\"%s\": no label ACE\n", Text);
    if (Sacl && Sacl->AceCount == 1 && GetAce(Sacl, 0, (PVOID *)&Ace))
    {
        ok(Ace->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE, "\"%s\": type %u\n", Text, Ace->Header.AceType);
        ok(Ace->Header.AceFlags == Flags, "\"%s\": flags 0x%x, expected 0x%x\n", Text, Ace->Header.AceFlags, Flags);
        ok(Ace->Mask == Policy, "\"%s\": policy 0x%lx, expected 0x%lx\n", Text, Ace->Mask, Policy);
        ok(*GetSidSubAuthority((PSID)&Ace->SidStart, 0) == Level, "\"%s\": level 0x%lx, expected 0x%lx\n", Text,
           *GetSidSubAuthority((PSID)&Ace->SidStart, 0), Level);
    }
    Convert(Text, Sd, LABEL_SECURITY_INFORMATION, Back);
    LocalFree(Sd);
}

START_TEST(SddlMandatoryLabel)
{
    UINT i;
    PSECURITY_DESCRIPTOR Sd = NULL;
    SECURITY_DESCRIPTOR Plain;
    BYTE AclBuffer[256], SidBuffer[SECURITY_MAX_SID_SIZE];
    SID_IDENTIFIER_AUTHORITY Authority = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    LPSTR Str = NULL;
    LABEL_ROW Audit = { 0x3000, 1, 0, "" };

    pAddMandatoryAce = (PVOID)GetProcAddress(GetModuleHandleA("advapi32.dll"), "AddMandatoryAce");
    if (!pAddMandatoryAce)
    {
        skip("AddMandatoryAce is not available\n");
        return;
    }

    for (i = 0; i < ARRAYSIZE(s_Rows); i++)
        CheckRow(&s_Rows[i], FALSE);

    /* an audit ACE in front of the label: the flags choose which one is printed (measured), both in order together */
    {
        SECURITY_DESCRIPTOR Mixed;
        BYTE Acl2[512], World[SECURITY_MAX_SID_SIZE], Label[SECURITY_MAX_SID_SIZE];
        DWORD cb = sizeof(World);

        CheckRow(&Audit, TRUE);
        InitializeSecurityDescriptor(&Mixed, SECURITY_DESCRIPTOR_REVISION);
        InitializeAcl((PACL)Acl2, sizeof(Acl2), ACL_REVISION);
        CreateWellKnownSid(WinWorldSid, NULL, World, &cb);
        AddAuditAccessAce((PACL)Acl2, ACL_REVISION, GENERIC_ALL, World, TRUE, TRUE);
        InitializeSid((PSID)Label, &Authority, 1);
        *GetSidSubAuthority((PSID)Label, 0) = 0x3000;
        pAddMandatoryAce((PACL)Acl2, ACL_REVISION, 0, 1, (PSID)Label);
        SetSecurityDescriptorSacl(&Mixed, TRUE, (PACL)Acl2, FALSE);
        Convert("audit and label", &Mixed, SACL_SECURITY_INFORMATION, "S:(AU;SAFA;GA;;;WD)");
        Convert("audit and label", &Mixed, LABEL_SECURITY_INFORMATION, "S:(ML;;NW;;;HI)");
        Convert("audit and label", &Mixed, SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, "S:(AU;SAFA;GA;;;WD)(ML;;NW;;;HI)");
    }

    CheckParse("S:(ML;;NW;;;LW)", 0x1000, 1, 0, "S:(ML;;NW;;;LW)");
    CheckParse("S:(ML;;NWNRNX;;;ME)", 0x2000, 7, 0, "S:(ML;;NWNRNX;;;ME)");
    CheckParse("S:(ML;OICI;NW;;;HI)", 0x3000, 1, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, "S:(ML;OICI;NW;;;HI)");
    CheckParse("S:(ML;OICIIO;NW;;;LW)", 0x1000, 1, 0xb, "S:(ML;OICIIO;NW;;;LW)");
    CheckParse("S:(ML;;NW;;;S-1-16-4096)", 0x1000, 1, 0, "S:(ML;;NW;;;LW)");
    CheckParse("S:(ML;;NW;;;S-1-16-8448)", 0x2100, 1, 0, "S:(ML;;NW;;;MP)");
    CheckParse("S:(ML;;NR;;;SI)", 0x4000, 2, 0, "S:(ML;;NR;;;SI)");
    CheckParse("S:(ML;;0x7;;;ME)", 0x2000, 7, 0, "S:(ML;;NWNRNX;;;ME)");

    /* the SID of a label entry must be a label: refused with ERROR_INVALID_PARAMETER (measured) */
    {
        PSECURITY_DESCRIPTOR Bad = NULL;
        BOOL Ret;

        SetLastError(0xdeadbeef);
        Ret = ConvertStringSecurityDescriptorToSecurityDescriptorA("S:(ML;;NW;;;BA)", SDDL_REVISION_1, &Bad, NULL);
        ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "a label entry for the Administrators: %d, error %lu, expected 0 and %u\n",
           Ret, GetLastError(), ERROR_INVALID_PARAMETER);
        if (Bad)
            LocalFree(Bad);
    }

    /* the label of a real object, read as the shell and the tools do */
    {
        WCHAR Path[MAX_PATH];
        HANDLE hFile;
        PACL Sacl = NULL;

        GetTempPathW(ARRAYSIZE(Path), Path);
        StringCchCatW(Path, ARRAYSIZE(Path), L"sddllabel.tmp");
        hFile = CreateFileW(Path, GENERIC_WRITE | WRITE_OWNER | READ_CONTROL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            PSECURITY_DESCRIPTOR LabelSd = NULL;
            BOOL Present, Defaulted;
            DWORD Error;

            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;LW)", SDDL_REVISION_1, &LabelSd, NULL) &&
                GetSecurityDescriptorSacl(LabelSd, &Present, &Sacl, &Defaulted))
            {
                Error = SetSecurityInfo(hFile, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, Sacl);
                if (Error == ERROR_SUCCESS)
                {
                    PSECURITY_DESCRIPTOR Read = NULL;

                    Error = GetSecurityInfo(hFile, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &Read);
                    ok(Error == ERROR_SUCCESS, "GetSecurityInfo: %lu\n", Error);
                    if (Error == ERROR_SUCCESS)
                    {
                        Convert("a file with a Low label", Read, LABEL_SECURITY_INFORMATION, "S:(ML;;NW;;;LW)");
                        LocalFree(Read);
                    }
                }
                else
                    skip("The label cannot be set on this volume (error %lu)\n", Error);
                LocalFree(LabelSd);
            }
            CloseHandle(hFile);
            DeleteFileW(Path);
        }
        else
            skip("No scratch file (error %lu)\n", GetLastError());
    }
    (void)Sd; (void)Plain; (void)AclBuffer; (void)SidBuffer; (void)Str;
}
