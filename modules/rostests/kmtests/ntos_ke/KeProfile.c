/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     KeProfile
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>
#include "KeProfile.h"

VOID
Test_KeProfileWithData(PVOID Data, SIZE_T DataLength)
{
    PKE_PROFILE_TEST_DATA ProfileData = Data;
    KTRAP_FRAME TrapFrame;
    KIRQL OldIrql;
    ULONG_PTR RangeLimit;

    ok(DataLength == sizeof(*ProfileData), "Invalid profile test data length %Iu\n", DataLength);
    if (DataLength != sizeof(*ProfileData))
        return;

    RangeLimit = (ULONG_PTR)ProfileData->RangeBase + ProfileData->RangeSize;
    RtlZeroMemory(&TrapFrame, sizeof(TrapFrame));

    KeRaiseIrql(PROFILE_LEVEL, &OldIrql);
#ifdef _M_AMD64
    TrapFrame.Rip = RangeLimit;
#else
    TrapFrame.Eip = RangeLimit;
#endif
    KeProfileInterruptWithSource(&TrapFrame, ProfileData->ProfileSource);
#ifdef _M_AMD64
    TrapFrame.Rip = RangeLimit - 1;
#else
    TrapFrame.Eip = RangeLimit - 1;
#endif
    KeProfileInterruptWithSource(&TrapFrame, ProfileData->ProfileSource);
    KeLowerIrql(OldIrql);
}

START_TEST(KeProfile)
{
    skip(FALSE, "KeProfile requires a profile created by the user-mode test\n");
}
