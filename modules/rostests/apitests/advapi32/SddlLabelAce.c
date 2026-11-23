/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     ConvertSecurityDescriptorToStringSecurityDescriptor prints a mandatory label ACE as
 *              (ML;flags;NW|NR|NX;;;LW|ME|HI|SI) and the label is part of the SACL part of the string, also when
 *              only LABEL_SECURITY_INFORMATION is requested
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The strings are the ones Windows Server 2022 (build 20348) prints for the labels of the objects it makes
 * (GetSecurityInfo + ConvertSecurityDescriptorToStringSecurityDescriptor, LABEL_SECURITY_INFORMATION).
 */

#include "precomp.h"
#include <sddl.h>
#include <aclapi.h>

static const PCWSTR Strings[] =
{
    L"S:(ML;;NW;;;LW)",
    L"S:AI(ML;;NW;;;LW)",
    L"S:AI(ML;;NW;;;HI)",
    L"S:AI(ML;OICI;NW;;;LW)",
    L"S:AI(ML;OICIIO;NW;;;HI)",
    L"S:AI(ML;ID;NW;;;LW)",
    L"S:AI(ML;OICIID;NW;;;LW)",
    L"S:(ML;;NWNRNX;;;ME)",
    L"S:(ML;;NR;;;SI)",
    L"S:(ML;;NX;;;ME)",
    L"D:(A;;FA;;;WD)S:AI(ML;;NW;;;ME)",
    L"D:(A;OICI;FA;;;WD)S:AI(ML;OICI;NW;;;LW)",
};

START_TEST(SddlLabelAce)
{
    PSECURITY_DESCRIPTOR Sd;
    PWSTR Text;
    ULONG i;
    BOOL Ret;

    for (i = 0; i < _countof(Strings); i++)
    {
        Sd = NULL;
        Ret = ConvertStringSecurityDescriptorToSecurityDescriptorW(Strings[i], SDDL_REVISION_1, &Sd, NULL);
        ok(Ret, "%ls: parse failed with %lu\n", Strings[i], GetLastError());
        if (!Ret)
            continue;

        Text = NULL;
        SetLastError(0xdeadbeef);
        Ret = ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd, SDDL_REVISION_1,
                                                                   DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                                                                   &Text, NULL);
        ok(Ret, "%ls: conversion failed with %lu\n", Strings[i], GetLastError());
        if (Ret)
        {
            ok(!wcscmp(Text, Strings[i]), "%ls: printed as %ls\n", Strings[i], Text);
            LocalFree(Text);
        }
        LocalFree(Sd);
    }

    /* The label alone: the part of the string that holds it, without the DACL */
    Sd = NULL;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FA;;;WD)S:(ML;;NW;;;LW)", SDDL_REVISION_1, &Sd, NULL))
    {
        Text = NULL;
        Ret = ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &Text, NULL);
        ok(Ret, "label only: conversion failed with %lu\n", GetLastError());
        if (Ret)
        {
            ok(!wcscmp(Text, L"S:(ML;;NW;;;LW)"), "label only: %ls\n", Text);
            LocalFree(Text);
        }
        LocalFree(Sd);
    }

    /* A label ACE made with the API prints the same */
    {
        BYTE Sid[SECURITY_MAX_SID_SIZE];
        DWORD Length = sizeof(Sid);
        BYTE AclBuffer[256];
        PACL Acl = (PACL)AclBuffer;
        SECURITY_DESCRIPTOR Descriptor;

        ok(CreateWellKnownSid(WinLowLabelSid, NULL, Sid, &Length), "CreateWellKnownSid failed with %lu\n", GetLastError());
        ok(InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION), "InitializeAcl failed\n");
        ok(AddMandatoryAce(Acl, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP, Sid),
           "AddMandatoryAce failed with %lu\n", GetLastError());
        ok(InitializeSecurityDescriptor(&Descriptor, SECURITY_DESCRIPTOR_REVISION), "InitializeSecurityDescriptor failed\n");
        ok(SetSecurityDescriptorSacl(&Descriptor, TRUE, Acl, FALSE), "SetSecurityDescriptorSacl failed\n");
        Text = NULL;
        Ret = ConvertSecurityDescriptorToStringSecurityDescriptorW(&Descriptor, SDDL_REVISION_1, SACL_SECURITY_INFORMATION, &Text, NULL);
        ok(Ret, "API label: conversion failed with %lu\n", GetLastError());
        if (Ret)
        {
            ok(!wcscmp(Text, L"S:(ML;;NWNR;;;LW)"), "API label: %ls\n", Text);
            LocalFree(Text);
        }
    }
}
