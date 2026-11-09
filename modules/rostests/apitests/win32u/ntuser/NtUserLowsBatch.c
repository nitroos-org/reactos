/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Contract tests for the NtUser LOW batch: services only CSRSS may use refuse
 *              any other caller, the API hook can not be unregistered by a process that did not
 *              register it
 */

#include "../win32nt.h"

static void test_setinformationthread(void)
{
    NTSTATUS Status;
    ULONG flags = 0;

    /* the shutdown, desktop and port classes are CSRSS's: a thread of another process is refused,
       whatever the class and the buffer */
    Status = NtUserSetInformationThread(GetCurrentThread(), UserThreadUseActiveDesktop, NULL, 0);
    ok(Status == STATUS_ACCESS_DENIED, "UserThreadUseActiveDesktop: 0x%08lx\n", Status);

    Status = NtUserSetInformationThread(GetCurrentThread(), UserThreadRestoreDesktop, NULL, 0);
    ok(Status == STATUS_ACCESS_DENIED, "UserThreadRestoreDesktop: 0x%08lx\n", Status);

    Status = NtUserSetInformationThread(GetCurrentThread(), UserThreadInitiateShutdown, &flags, sizeof(flags));
    ok(Status == STATUS_ACCESS_DENIED, "UserThreadInitiateShutdown: 0x%08lx\n", Status);

    Status = NtUserSetInformationThread(NULL, (USERTHREADINFOCLASS)0x7fff, (PVOID)(ULONG_PTR)1, 0xffffffff);
    ok(Status == STATUS_ACCESS_DENIED, "bad class, bad buffer: 0x%08lx\n", Status);
}

static void test_unregister_apihook(void)
{
    BOOL ret;

    SetLastError(0xdeadbeef);
    ret = NtUserUnregisterUserApiHook();
    ok(ret == FALSE, "NtUserUnregisterUserApiHook by a process that did not register: %d\n", ret);
}

START_TEST(NtUserLowsBatch)
{
    if (!is_reactos())
    {
        skip("ReactOS win32k behaviour\n");
        return;
    }

    test_setinformationthread();
    test_unregister_apihook();
}
