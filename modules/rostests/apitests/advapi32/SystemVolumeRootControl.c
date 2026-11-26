/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The root of the system volume is protected and auto-inherited
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (NTFS): the descriptor of C:\ has the control bits SE_DACL_PROTECTED and
 * SE_DACL_AUTO_INHERITED (D:PAI), so that what is created below it carries the auto-inherited mark and
 * INHERITED_ACE on what it inherits. A root without the mark gave every new object a descriptor that was not
 * auto-inherited (a root made by the setup of an older version is not checked: only a volume without
 * ACLs is skipped).
 */

#include "precomp.h"

START_TEST(SystemVolumeRootControl)
{
    CHAR Root[] = "C:\\";
    CHAR Windows[MAX_PATH];
    BYTE Buffer[4096];
    DWORD Length, Flags = 0, Revision;
    SECURITY_DESCRIPTOR_CONTROL Control;

    if (GetWindowsDirectoryA(Windows, sizeof(Windows)) >= 2 && Windows[1] == ':')
        Root[0] = Windows[0];

    if (!GetVolumeInformationA(Root, NULL, 0, NULL, NULL, &Flags, NULL, 0) || !(Flags & FILE_PERSISTENT_ACLS))
    {
        skip("the volume has no access control lists\n");
        return;
    }

    if (!GetFileSecurityA(Root, DACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length))
    {
        skip("GetFileSecurity: %lu\n", GetLastError());
        return;
    }
    ok(GetSecurityDescriptorControl(Buffer, &Control, &Revision), "control: %lu\n", GetLastError());
    ok((Control & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED)) == (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED),
       "control of the root is 0x%04x, expected the bits 0x%04x\n", Control, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED);
}
