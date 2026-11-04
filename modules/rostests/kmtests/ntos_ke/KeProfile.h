/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     KeProfile
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef _KMTEST_KEPROFILE_H_
#define _KMTEST_KEPROFILE_H_

typedef struct _KE_PROFILE_TEST_DATA
{
    PVOID RangeBase;
    SIZE_T RangeSize;
    ULONG BucketSize;
    KPROFILE_SOURCE ProfileSource;
} KE_PROFILE_TEST_DATA, *PKE_PROFILE_TEST_DATA;

#endif
