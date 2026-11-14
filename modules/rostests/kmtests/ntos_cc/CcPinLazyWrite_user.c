/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for the lazy write of ranges pinned for writing, user-mode part
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

#define IOCTL_RUN_TEST 1

START_TEST(CcPinLazyWrite)
{
    DWORD Ret;

    /* The test waits for lazy writes of a stream file of a file system that is
     * not there, which the cache manager of Windows does not issue (see
     * CcLazyWriteDelete); the rule it checks, no lazy write of a range pinned
     * for writing, has not been compared with Windows */
    if (skip(is_reactos(), "The test is specific to the ReactOS cache manager\n"))
        return;

    Ret = KmtLoadAndOpenDriver(L"CcPinLazyWrite", FALSE);
    ok_eq_int(Ret, ERROR_SUCCESS);
    if (Ret)
        return;

    Ret = KmtSendToDriver(IOCTL_RUN_TEST);
    ok(Ret == ERROR_SUCCESS, "KmtSendToDriver failed: %lx\n", Ret);

    KmtCloseDriver();
    KmtUnloadDriver();
}
