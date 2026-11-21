/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SDDL text of NULL ACLs and of the SACL control flags, both ways (rows measured on Windows Server 2022)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>

/* descriptor -> text: Dacl and Sacl 0 = absent, 1 = present NULL, 2 = one ACE, 3 = present and empty */
static const struct { PCSTR Name; int Dacl, Sacl; SECURITY_DESCRIPTOR_CONTROL Control; PCWSTR Text; } SdToText[] =
{
    { "none", 0, 0, 0, L"O:SYG:SY" },
    { "dacl-NULL", 1, 0, 0, L"O:SYG:SYD:NO_ACCESS_CONTROL" },
    { "sacl-NULL", 0, 1, 0, L"O:SYG:SYS:NO_ACCESS_CONTROL" },
    { "both-NULL", 1, 1, 0, L"O:SYG:SYD:NO_ACCESS_CONTROLS:NO_ACCESS_CONTROL" },
    { "dacl-empty", 3, 0, 0, L"O:SYG:SYD:" },
    { "sacl-empty", 0, 3, 0, L"O:SYG:SYS:" },
    { "dacl-real", 2, 0, 0, L"O:SYG:SYD:(A;;GA;;;SY)" },
    { "sacl-real", 0, 2, 0, L"O:SYG:SYS:(AU;SAFA;GA;;;BA)" },
    { "both-real", 2, 2, 0, L"O:SYG:SYD:(A;;GA;;;SY)S:(AU;SAFA;GA;;;BA)" },
    { "dacl-real-P", 2, 0, SE_DACL_PROTECTED, L"O:SYG:SYD:P(A;;GA;;;SY)" },
    { "dacl-real-AI", 2, 0, SE_DACL_AUTO_INHERITED, L"O:SYG:SYD:AI(A;;GA;;;SY)" },
    { "dacl-real-AIR", 2, 0, SE_DACL_AUTO_INHERIT_REQ, L"O:SYG:SYD:AR(A;;GA;;;SY)" },
    { "dacl-real-P-AI-AIR", 2, 0, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ, L"O:SYG:SYD:PARAI(A;;GA;;;SY)" },
    { "sacl-real-P", 0, 2, SE_SACL_PROTECTED, L"O:SYG:SYS:P(AU;SAFA;GA;;;BA)" },
    { "sacl-real-AI", 0, 2, SE_SACL_AUTO_INHERITED, L"O:SYG:SYS:AI(AU;SAFA;GA;;;BA)" },
    { "sacl-real-AIR", 0, 2, SE_SACL_AUTO_INHERIT_REQ, L"O:SYG:SYS:AR(AU;SAFA;GA;;;BA)" },
    { "sacl-NULL-AI", 0, 1, SE_SACL_AUTO_INHERITED, L"O:SYG:SYS:AINO_ACCESS_CONTROL" },
    { "sacl-NULL-P-AI", 0, 1, SE_SACL_PROTECTED | SE_SACL_AUTO_INHERITED, L"O:SYG:SYS:PAINO_ACCESS_CONTROL" },
    { "sacl-empty-AI", 0, 3, SE_SACL_AUTO_INHERITED, L"O:SYG:SYS:AI" },
    { "dacl-NULL-P-AI", 1, 0, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED, L"O:SYG:SYD:PAINO_ACCESS_CONTROL" },
    { "dacl-NULL+sacl-NULL-AI", 1, 1, SE_SACL_AUTO_INHERITED | SE_DACL_AUTO_INHERITED, L"O:SYG:SYD:AINO_ACCESS_CONTROLS:AINO_ACCESS_CONTROL" },
};

/* text -> descriptor: result, length, control (without SE_SELF_RELATIVE already included as Windows reports it), text back */
static const struct { PCWSTR In; BOOL Ok; ULONG Length; USHORT Control; PCWSTR Back; } TextToSd[] =
{
    { L"D:NO_ACCESS_CONTROL", 1, 20, 0x8004, L"D:NO_ACCESS_CONTROL" },
    { L"S:NO_ACCESS_CONTROL", 1, 20, 0x8010, L"S:NO_ACCESS_CONTROL" },
    { L"D:NO_ACCESS_CONTROLS:NO_ACCESS_CONTROL", 1, 20, 0x8014, L"D:NO_ACCESS_CONTROLS:NO_ACCESS_CONTROL" },
    { L"D:", 1, 28, 0x8004, L"D:" },
    { L"S:", 1, 28, 0x8010, L"S:" },
    { L"D:S:", 1, 36, 0x8014, L"D:S:" },
    { L"D:AI", 1, 28, 0x8404, L"D:AI" },
    { L"D:P", 1, 28, 0x9004, L"D:P" },
    { L"D:AR", 1, 28, 0x8104, L"D:AR" },
    { L"D:PAIAR", 1, 28, 0x9504, L"D:PARAI" },
    { L"S:AI", 1, 28, 0x8810, L"S:AI" },
    { L"S:P", 1, 28, 0xa010, L"S:P" },
    { L"S:AR", 1, 28, 0x8210, L"S:AR" },
    { L"S:PAIAR", 1, 28, 0xaa10, L"S:PARAI" },
    { L"D:AINO_ACCESS_CONTROL", 1, 20, 0x8404, L"D:AINO_ACCESS_CONTROL" },
    { L"D:PNO_ACCESS_CONTROL", 1, 20, 0x9004, L"D:PNO_ACCESS_CONTROL" },
    { L"S:AINO_ACCESS_CONTROL", 1, 20, 0x8810, L"S:AINO_ACCESS_CONTROL" },
    { L"S:PAINO_ACCESS_CONTROL", 1, 20, 0xa810, L"S:PAINO_ACCESS_CONTROL" },
    { L"O:SYD:NO_ACCESS_CONTROLS:AINO_ACCESS_CONTROL", 1, 32, 0x8814, L"O:SYD:NO_ACCESS_CONTROLS:AINO_ACCESS_CONTROL" },
    { L"O:BAG:SYD:PAI(A;CI;KR;;;BU)S:AINO_ACCESS_CONTROL", 1, 80, 0x9c14, L"O:BAG:SYD:PAI(A;CI;KR;;;BU)S:AINO_ACCESS_CONTROL" },
    { L"D:NO_ACCESS_CONTROL(A;;GA;;;SY)", 0, 0, 0x0000, L"" },
    { L"D:(A;;GA;;;SY)NO_ACCESS_CONTROL", 1, 48, 0x8004, L"D:(A;;GA;;;SY)" },
    { L"D:NO_ACCESS_CONTROLAI", 0, 0, 0x0000, L"" },
    { L"D:no_access_control", 1, 20, 0x8004, L"D:NO_ACCESS_CONTROL" },
    { L"S:(AU;SA;GA;;;WD)", 1, 48, 0x8010, L"S:(AU;SA;GA;;;WD)" },
    { L"S:AI(AU;SA;GA;;;WD)", 1, 48, 0x8810, L"S:AI(AU;SA;GA;;;WD)" },
    { L"D:AI(A;;GA;;;SY)S:AI(AU;SA;GA;;;WD)", 1, 76, 0x8c14, L"D:AI(A;;GA;;;SY)S:AI(AU;SA;GA;;;WD)" },
};

START_TEST(SddlNullAcl)
{
    BYTE Sd[512], DaclBuf[256], SaclBuf[256], Sid[SECURITY_MAX_SID_SIZE], AdminSid[SECURITY_MAX_SID_SIZE];
    PACL Dacl = (PACL)DaclBuf, Sacl = (PACL)SaclBuf, EmptyD = (PACL)(DaclBuf + 128), EmptyS = (PACL)(SaclBuf + 128);
    DWORD SidSize = sizeof(Sid);
    ULONG i;

    CreateWellKnownSid(WinLocalSystemSid, NULL, Sid, &SidSize);
    SidSize = sizeof(AdminSid);
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AdminSid, &SidSize);
    InitializeAcl(Dacl, 120, ACL_REVISION);
    AddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, Sid);
    InitializeAcl(Sacl, 120, ACL_REVISION);
    AddAuditAccessAce(Sacl, ACL_REVISION, GENERIC_ALL, AdminSid, TRUE, TRUE);
    InitializeAcl(EmptyD, 64, ACL_REVISION);
    InitializeAcl(EmptyS, 64, ACL_REVISION);

    for (i = 0; i < ARRAYSIZE(SdToText); i++)
    {
        PSECURITY_DESCRIPTOR Desc = Sd;
        LPWSTR Text = NULL;
        BOOL Ret;
        WCHAR Expected[128];
        PCWSTR Tail = SdToText[i].Text;

        memset(Sd, 0, sizeof(Sd));
        InitializeSecurityDescriptor(Desc, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorOwner(Desc, Sid, FALSE);
        SetSecurityDescriptorGroup(Desc, Sid, FALSE);
        if (SdToText[i].Dacl)
            SetSecurityDescriptorDacl(Desc, TRUE, SdToText[i].Dacl == 1 ? NULL : SdToText[i].Dacl == 2 ? Dacl : EmptyD, FALSE);
        if (SdToText[i].Sacl)
            SetSecurityDescriptorSacl(Desc, TRUE, SdToText[i].Sacl == 1 ? NULL : SdToText[i].Sacl == 2 ? Sacl : EmptyS, FALSE);
        if (SdToText[i].Control)
            SetSecurityDescriptorControl(Desc, SdToText[i].Control, SdToText[i].Control);
        Ret = ConvertSecurityDescriptorToStringSecurityDescriptorW(Desc, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                                                   DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, &Text, NULL);
        ok(Ret, "%s: conversion failed %lu\n", SdToText[i].Name, GetLastError());
        if (Ret)
        {
            wcscpy(Expected, Tail);
            ok(!wcscmp(Text, Expected), "%s: text '%ls', expected '%ls'\n", SdToText[i].Name, Text, Expected);
            LocalFree(Text);
        }
    }

    for (i = 0; i < ARRAYSIZE(TextToSd); i++)
    {
        PSECURITY_DESCRIPTOR Desc = NULL;
        ULONG Size = 0;
        BOOL Ret;

        SetLastError(0xdeadbeef);
        Ret = ConvertStringSecurityDescriptorToSecurityDescriptorW(TextToSd[i].In, SDDL_REVISION_1, &Desc, &Size);
        ok(Ret == TextToSd[i].Ok, "'%ls': result %d, expected %d (error %lu)\n", TextToSd[i].In, Ret, TextToSd[i].Ok, GetLastError());
        if (!Ret)
        {
            if (!TextToSd[i].Ok)
                ok_err(ERROR_INVALID_PARAMETER);
            continue;
        }
        if (!TextToSd[i].Ok)
        {
            LocalFree(Desc);
            continue;
        }
        ok(Size == TextToSd[i].Length, "'%ls': length %lu, expected %lu\n", TextToSd[i].In, Size, TextToSd[i].Length);
        ok(*(USHORT *)((BYTE *)Desc + 2) == TextToSd[i].Control, "'%ls': control 0x%04x, expected 0x%04x\n", TextToSd[i].In,
           *(USHORT *)((BYTE *)Desc + 2), TextToSd[i].Control);
        {
            LPWSTR Back = NULL;

            if (ConvertSecurityDescriptorToStringSecurityDescriptorW(Desc, SDDL_REVISION_1, 0xf, &Back, NULL))
            {
                ok(!wcscmp(Back, TextToSd[i].Back), "'%ls': text back '%ls', expected '%ls'\n", TextToSd[i].In, Back, TextToSd[i].Back);
                LocalFree(Back);
            }
            else
                ok(0, "'%ls': conversion back failed %lu\n", TextToSd[i].In, GetLastError());
        }
        LocalFree(Desc);
    }
}
