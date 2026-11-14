/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     KUSER_SHARED_DATA.NtBuildNumber (0x7ffe0260) matches the build RtlGetVersion and the PEB report
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The word holds the plain build number (19045 on the Windows 10 identity), without any checked/free flag bits.
 * The page is mapped at the same address for 32-bit processes, so the same check runs for x64, WoW64 and i386.
 * Offsets are used directly: 0x260 NtBuildNumber, 0x26c NtMajorVersion, 0x270 NtMinorVersion (all ULONG).
 */

#include "precomp.h"

#define KUSER_ULONG(Offset) (*(volatile ULONG *)(ULONG_PTR)(0x7ffe0000 + (Offset)))

START_TEST(KUserBuildNumber)
{
    RTL_OSVERSIONINFOW Info;
    NTSTATUS Status;
    ULONG Build = KUSER_ULONG(0x260);

    RtlZeroMemory(&Info, sizeof(Info));
    Info.dwOSVersionInfoSize = sizeof(Info);
    Status = RtlGetVersion(&Info);
    ok(Status == STATUS_SUCCESS, "RtlGetVersion: %08lx\n", Status);
    ok(Build != 0, "NtBuildNumber is 0\n");
    ok(Build == Info.dwBuildNumber, "KUSER build %lu, RtlGetVersion %lu\n", Build, Info.dwBuildNumber);
    ok(Build == NtCurrentPeb()->OSBuildNumber, "KUSER build %lu, PEB %u\n", Build, NtCurrentPeb()->OSBuildNumber);
    ok((Build & 0xFFFF0000) == 0, "flag bits set: %08lx\n", Build);
    ok(KUSER_ULONG(0x26c) == Info.dwMajorVersion && KUSER_ULONG(0x270) == Info.dwMinorVersion,
       "KUSER %lu.%lu, RtlGetVersion %lu.%lu\n", KUSER_ULONG(0x26c), KUSER_ULONG(0x270),
       Info.dwMajorVersion, Info.dwMinorVersion);
}
