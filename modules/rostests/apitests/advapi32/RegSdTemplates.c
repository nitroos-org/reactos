/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The registry security descriptors setup, the hive maker and the profile code build
 *              (<reactos/regacl_sd.h>): each is a valid descriptor, and its SDDL text and control
 *              flags are the Windows 10 ones for the hive roots and override keys
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected strings were read from Windows 10 22H2 (SDDL of the keys, READ_CONTROL access).
 * Windows also marks a NULL SACL present on these keys (S:AINO_ACCESS_CONTROL): the control flags here
 * include SE_SACL_PRESENT, and the SDDL text is asked for without the SACL.
 */

#include "precomp.h"
#include <sddl.h>
#include <reactos/regacl_sd.h>

static const struct
{
    ULONG Template;
    USHORT Control;
    const WCHAR *Sddl;
} s_Cases[] =
{
    { REGSD_T_MASTER, 0x8004,
      L"O:SYG:SYD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)(A;CI;KR;;;AC)(A;CI;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)" },
    { REGSD_T_HIVEROOT, 0x9c14,
      L"O:BAG:SYD:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)(A;CI;KR;;;AC)(A;CI;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)" },
    { REGSD_T_DEFAULT, 0x9c14,
      L"O:BAG:SYD:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)(A;;KR;;;AC)(A;;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)" },
    { REGSD_T_SAMSAM, 0x8804,
      L"O:BAG:SYD:(A;CI;KA;;;SY)(A;CI;RCWD;;;BA)" },
    { REGSD_T_SECURITY, 0x8814,
      L"O:BAG:SYD:(A;CI;KA;;;SY)(A;CI;RCWD;;;BA)" },
    { REGSD_T_BCD, 0x8004,
      L"O:BAG:SYD:(A;;CCSWRPRCWD;;;BA)(A;;KA;;;SY)" },
    { REGSD_T_USER, 0x9814,
      L"O:BAG:SYD:P(A;OICI;KA;;;S-1-5-21-1253675753-2377331658-4097264211-1000)(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KR;;;RC)(A;;KR;;;AC)(A;;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)" },
    { REGSD_T_TASKCACHE, 0x9c14,
      L"O:SYG:SYD:PAI(A;OICI;CCSWRPSDRC;;;BA)(A;OICI;KA;;;SY)" },
    { REGSD_T_EVENTLOG, 0x9c14,
      L"O:BAG:SYD:PAI(A;;KR;;;AU)(A;CIIO;GR;;;AU)(A;;KR;;;SO)(A;CIIO;GR;;;SO)(A;;KA;;;BA)(A;CIIO;GA;;;BA)(A;;KA;;;SY)(A;CIIO;GA;;;SY)" },
    { REGSD_T_POLICIES, 0x9c14,
      L"O:SYG:SYD:PAI(A;;KR;;;AU)(A;;KA;;;SY)(A;;KA;;;BA)(A;OICIIO;GR;;;AU)(A;OICIIO;GA;;;SY)(A;OICIIO;GA;;;BA)(A;;KR;;;AC)(A;OICIIO;GR;;;AC)(A;;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;OICIIO;GR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)" },
    { REGSD_T_TCPIPPARAMS, 0x9c14,
      L"O:SYG:SYD:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;CCDCLCSWRPWPSDRC;;;NS)(A;CI;KR;;;LS)(A;CI;CCDCLCSWRPSDRC;;;NO)(A;CI;CCDCLCSWRPSDRC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)(A;CIIO;RC;;;OW)(A;CI;CCDCLCSWRPRC;;;S-1-5-80-3981856537-581775623-1136376035-2066872258-409572886)(A;CI;KR;;;AC)(A;CI;KR;;;S-1-15-3-1)(A;CI;KR;;;S-1-15-3-2)(A;CI;KR;;;S-1-15-3-3)(A;CI;KR;;;S-1-15-3-4214768333-1334025770-122408079-3919188833)" },
};

/* S-1-5-21-1253675753-2377331658-4097264211-1000 */
static const UCHAR s_UserSid[] =
{
    1, 5, 0, 0, 0, 0, 0, 5,
    0x15, 0, 0, 0,
    0xE9, 0x92, 0xB9, 0x4A,
    0xCA, 0x33, 0xB3, 0x8D,
    0x53, 0x4A, 0x37, 0xF4,
    0xE8, 0x03, 0, 0
};

START_TEST(RegSdTemplates)
{
    UCHAR Buffer[1024];
    ULONG i, Length;
    WORD Control;
    DWORD Revision;
    PWSTR Text;

    for (i = 0; i < _countof(s_Cases); i++)
    {
        Length = RegSdBuild(s_Cases[i].Template, s_UserSid, Buffer, sizeof(Buffer));
        ok(Length != 0, "template %lu: RegSdBuild gave no descriptor\n", s_Cases[i].Template);
        if (!Length)
            continue;

        ok(IsValidSecurityDescriptor(Buffer), "template %lu: not a valid security descriptor\n", s_Cases[i].Template);
        ok(GetSecurityDescriptorControl(Buffer, &Control, &Revision), "template %lu: no control\n", s_Cases[i].Template);
        ok(Control == (s_Cases[i].Control | SE_SELF_RELATIVE), "template %lu: control 0x%04x, expected 0x%04x\n",
           s_Cases[i].Template, Control, s_Cases[i].Control | SE_SELF_RELATIVE);

        Text = NULL;
        ok(ConvertSecurityDescriptorToStringSecurityDescriptorW(Buffer, SDDL_REVISION_1,
                                                                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                                                DACL_SECURITY_INFORMATION, &Text, NULL),
           "template %lu: SDDL conversion failed, error %lu\n", s_Cases[i].Template, GetLastError());
        if (Text)
        {
            ok(!wcscmp(Text, s_Cases[i].Sddl), "template %lu:\n  got      %ls\n  expected %ls\n",
               s_Cases[i].Template, Text, s_Cases[i].Sddl);
            LocalFree(Text);
        }
    }

    /* The user template needs a SID, and every template needs room */
    ok(RegSdBuild(REGSD_T_USER, NULL, Buffer, sizeof(Buffer)) == 0, "no SID: a descriptor was built\n");
    ok(RegSdBuild(REGSD_T_USER, s_UserSid, Buffer, 30) == 0, "a short buffer: a descriptor was built\n");
    ok(RegSdBuild(REGSD_T_COUNT, s_UserSid, Buffer, sizeof(Buffer)) == 0, "no such template: a descriptor was built\n");
    ok(RegSdBuild(REGSD_T_MASTER, NULL, Buffer, sizeof(Buffer)) != 0, "master template needs no SID\n");
}
