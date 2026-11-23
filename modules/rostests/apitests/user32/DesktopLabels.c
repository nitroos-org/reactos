/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The mandatory labels of the interactive window station and its desktops
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (an administrator on the console, GetSecurityInfo with LABEL_SECURITY_INFORMATION,
 * the ACE read directly): WinSta0 and the Default desktop carry one label ACE, Low (S-1-16-4096), policy NO_WRITE_UP,
 * no ACE flags (S:(ML;;NW;;;LW)). The Winlogon desktop is refused to an administrator (access denied, also READ_CONTROL),
 * and the Screen-Saver desktop exists only while a screen saver runs (error 2 otherwise); neither label was measured.
 * Here the Screen-Saver desktop, when it can be opened, has no label.
 */

#include "precomp.h"

#include <aclapi.h>

/* Level of the first label ACE (MAXDWORD: none), its policy and ACE flags */
static DWORD
LabelOf(HANDLE Handle, PDWORD Policy, PBYTE Flags)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Sacl = NULL;
    SYSTEM_MANDATORY_LABEL_ACE *Ace;
    DWORD Level = MAXDWORD, Error, i;

    Error = GetSecurityInfo(Handle, SE_WINDOW_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &Sacl, &Sd);
    ok(Error == ERROR_SUCCESS, "GetSecurityInfo(LABEL): %lu\n", Error);
    if (Error != ERROR_SUCCESS)
        return MAXDWORD - 1;
    for (i = 0; Sacl && i < Sacl->AceCount; i++)
    {
        if (!GetAce(Sacl, i, (PVOID *)&Ace) || Ace->Header.AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
            continue;
        Level = *GetSidSubAuthority((PSID)&Ace->SidStart, 0);
        *Policy = Ace->Mask;
        *Flags = Ace->Header.AceFlags;
        break;
    }
    LocalFree(Sd);
    return Level;
}

START_TEST(DesktopLabels)
{
    WCHAR Name[64];
    HWINSTA Station = GetProcessWindowStation();
    HDESK Desktop;
    DWORD Level, Policy = 0, Length;
    BYTE Flags = 0xff;

    if (!GetUserObjectInformationW(Station, UOI_NAME, Name, sizeof(Name), &Length) || _wcsicmp(Name, L"WinSta0"))
    {
        skip("not on the interactive window station (%ls)\n", Name);
        return;
    }

    Level = LabelOf(Station, &Policy, &Flags);
    ok(Level == SECURITY_MANDATORY_LOW_RID, "WinSta0 level 0x%lx\n", Level);
    ok(Policy == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, "WinSta0 policy 0x%lx\n", Policy);
    ok(Flags == 0, "WinSta0 ACE flags 0x%x\n", Flags);

    Desktop = OpenDesktopW(L"Default", 0, FALSE, READ_CONTROL);
    ok(Desktop != NULL, "OpenDesktop(Default) failed with %lu\n", GetLastError());
    if (Desktop)
    {
        Policy = 0;
        Flags = 0xff;
        Level = LabelOf(Desktop, &Policy, &Flags);
        ok(Level == SECURITY_MANDATORY_LOW_RID, "Default level 0x%lx\n", Level);
        ok(Policy == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, "Default policy 0x%lx\n", Policy);
        ok(Flags == 0, "Default ACE flags 0x%x\n", Flags);
        CloseDesktop(Desktop);
    }

    /* Not labelled (a screen saver desktop exists only while the saver runs) */
    Desktop = OpenDesktopW(L"Screen-Saver", 0, FALSE, READ_CONTROL);
    if (Desktop)
    {
        Level = LabelOf(Desktop, &Policy, &Flags);
        ok(Level == MAXDWORD, "Screen-Saver level 0x%lx, expected no label\n", Level);
        CloseDesktop(Desktop);
    }
}
