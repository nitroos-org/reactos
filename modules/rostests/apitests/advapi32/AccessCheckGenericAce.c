/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests that the access check does not map generic rights inside ACE masks
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>

/*
 * Measured on Windows Server 2022 (x64 and x86 under WoW64): an allow ACE whose mask holds GENERIC_*
 * rights grants nothing for them and a deny ACE denies nothing for them; MAXIMUM_ALLOWED returns the
 * bits as they are. Generic rights are mapped when a descriptor is assigned or set, not by the check.
 * The owner of these descriptors (LOCAL SERVICE) is not in the caller's token: no implicit owner rights.
 */

static GENERIC_MAPPING Mapping = {0x1 | READ_CONTROL, 0x2 | WRITE_DAC, 0x4 | SYNCHRONIZE, 0x3F | STANDARD_RIGHTS_REQUIRED};

static void Check(int Line, HANDLE Token, const WCHAR *Sddl, DWORD Desired, BOOL ExpectStatus, DWORD ExpectGranted)
{
    BYTE PrivBuffer[256];
    DWORD PrivLength = sizeof(PrivBuffer), Granted = 0xCCCCCCCC;
    BOOL Status = 0xCC, Result;
    PSECURITY_DESCRIPTOR Sd = NULL;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
    {
        ok_(__FILE__, Line)(0, "SDDL %ls: %lu\n", Sddl, GetLastError());
        return;
    }
    SetLastError(0xDEADBEEF);
    Result = AccessCheck(Sd, Token, Desired, &Mapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, &Granted, &Status);
    ok_(__FILE__, Line)(Result, "%ls 0x%lx: AccessCheck failed: %lu\n", Sddl, Desired, GetLastError());
    ok_(__FILE__, Line)(Status == ExpectStatus, "%ls 0x%lx: access status %d, expected %d\n", Sddl, Desired, Status, ExpectStatus);
    ok_(__FILE__, Line)(Granted == ExpectGranted, "%ls 0x%lx: granted 0x%lx, expected 0x%lx\n", Sddl, Desired, Granted, ExpectGranted);
    LocalFree(Sd);
}
#define CHECK(t, s, d, st, g) Check(__LINE__, t, s, d, st, g)

START_TEST(AccessCheckGenericAce)
{
    HANDLE Process, Token;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &Process), "OpenProcessToken: %lu\n", GetLastError());
    ok(DuplicateToken(Process, SecurityImpersonation, &Token), "DuplicateToken: %lu\n", GetLastError());
    CloseHandle(Process);

    /* An allow ACE with GENERIC_ALL grants nothing */
    CHECK(Token, L"O:LSG:LSD:(A;;GA;;;WD)", 0x1, FALSE, 0);
    CHECK(Token, L"O:LSG:LSD:(A;;GA;;;WD)", READ_CONTROL, FALSE, 0);
    CHECK(Token, L"O:LSG:LSD:(A;;GA;;;WD)", MAXIMUM_ALLOWED, TRUE, GENERIC_ALL);
    /* GENERIC_READ: neither the specific nor the standard rights of the read mapping */
    CHECK(Token, L"O:LSG:LSD:(A;;GR;;;WD)", 0x1, FALSE, 0);
    CHECK(Token, L"O:LSG:LSD:(A;;GR;;;WD)", MAXIMUM_ALLOWED, TRUE, GENERIC_READ);
    /* A mask with a generic and a specific right: the specific one counts */
    CHECK(Token, L"O:LSG:LSD:(A;;0x10000001;;;WD)", 0x1, TRUE, 0x1);
    CHECK(Token, L"O:LSG:LSD:(A;;0x10000001;;;WD)", 0x2, FALSE, 0);
    CHECK(Token, L"O:LSG:LSD:(A;;0x10000001;;;WD)", MAXIMUM_ALLOWED, TRUE, 0x10000001);
    /* A deny ACE with GENERIC_ALL denies nothing */
    CHECK(Token, L"O:LSG:LSD:(D;;GA;;;WD)(A;;0x3F;;;WD)", 0x1, TRUE, 0x1);
    CHECK(Token, L"O:LSG:LSD:(D;;GA;;;WD)(A;;0x3F;;;WD)", MAXIMUM_ALLOWED, TRUE, 0x3F);
    /* The same rights given specifically are granted */
    CHECK(Token, L"O:LSG:LSD:(A;;0x1F003F;;;WD)", 0x1 | READ_CONTROL, TRUE, 0x1 | READ_CONTROL);

    CloseHandle(Token);
}
