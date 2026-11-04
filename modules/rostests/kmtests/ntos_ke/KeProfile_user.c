/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     KeProfile_user
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>
#include <ndk/kefuncs.h>
#include "KeProfile.h"

START_TEST(KeProfile)
{
    KE_PROFILE_TEST_DATA ProfileData;
    HANDLE ProfileHandle;
    PULONG Buffer;
    NTSTATUS Status;
    DWORD Error;

#ifdef _M_AMD64
    Status = NtCreateProfile(&ProfileHandle,
                             NtCurrentProcess(),
                             (PVOID)0x10000,
                             (SIZE_T)0x8000000000000000ULL,
                             31,
                             NULL,
                             sizeof(ULONG),
                             ProfileTime,
                             (KAFFINITY)-1);
    ok_eq_hex(Status, STATUS_BUFFER_TOO_SMALL);
    if (NT_SUCCESS(Status))
        NtClose(ProfileHandle);
#else
    skip(FALSE, "Bucket count cannot overflow ULONG on i386\n");
#endif

    ProfileData.RangeBase = (PVOID)0x10000;
    ProfileData.RangeSize = 0x40;
    ProfileData.BucketSize = 4;
    ProfileData.ProfileSource = ProfileTime;

    Buffer = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Buffer != NULL, "Cannot allocate profile buffer\n");
    if (!Buffer)
        return;

    Status = NtCreateProfile(&ProfileHandle,
                             NtCurrentProcess(),
                             ProfileData.RangeBase,
                             ProfileData.RangeSize,
                             ProfileData.BucketSize,
                             Buffer,
                             4 * sizeof(ULONG),
                             ProfileData.ProfileSource,
                             (KAFFINITY)-1);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    Status = NtStartProfile(ProfileHandle);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Error = KmtRunKernelTestWithData("KeProfile", &ProfileData, sizeof(ProfileData));
        ok_eq_ulong(Error, ERROR_SUCCESS);
        if (Error == ERROR_SUCCESS)
        {
            ok_eq_ulong(Buffer[4], 0);
            ok_eq_ulong(Buffer[3], 1);
        }

        Status = NtStopProfile(ProfileHandle);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }

    NtClose(ProfileHandle);
Cleanup:
    VirtualFree(Buffer, 0, MEM_RELEASE);
}
