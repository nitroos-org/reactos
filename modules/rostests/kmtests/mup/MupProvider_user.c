/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     MUP provider test, user-mode part: runs the driver, which registers and opens
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>
#include "MupProvider.h"

START_TEST(MupProvider)
{
    DWORD Error;

    Error = KmtLoadAndOpenDriver(L"MupProvider", FALSE);
    ok_eq_int(Error, ERROR_SUCCESS);
    if (Error)
        return;

    Error = KmtSendToDriver(IOCTL_RUN_MUP_TEST);
    ok(Error == ERROR_SUCCESS, "Expected ERROR_SUCCESS, got %lx\n", Error);

    KmtCloseDriver();
    KmtUnloadDriver();
}
