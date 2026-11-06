/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Clipboard services given handles that are not clipboard data: data that is not on
 *              the clipboard of the window station is not readable, a format kept as a kernel
 *              marker is not returned as a handle
 *              (ReactOS win32k; user32 does not let such handles through, so this is the
 *              service level)
 */

#include "../win32nt.h"

static void test_localmem_handle(void)
{
    static const char data[] = "clipboard data";
    char out[32];
    DWORD cb;
    HANDLE hMem, hRet;
    NTSTATUS Status;
    SETCLIPBDATA scd = {TRUE, TRUE};

    ok(OpenClipboard(NULL), "OpenClipboard failed\n");
    EmptyClipboard();

    hMem = NtUserConvertMemHandle((PVOID)data, sizeof(data));
    ok(hMem != NULL, "NtUserConvertMemHandle failed\n");
    if (!hMem)
        goto done;

    /* data that is not (yet) on the clipboard of this window station cannot be read */
    memset(out, 0, sizeof(out));
    cb = 0;
    Status = NtUserCreateLocalMemHandle(hMem, out, sizeof(out), &cb);
    ok(Status == STATUS_INVALID_HANDLE, "not on the clipboard: 0x%08lx\n", Status);
    ok(out[0] == 0, "data was copied\n");

    hRet = NtUserSetClipboardData(CF_PRIVATEFIRST, hMem, &scd);
    ok(hRet == hMem, "NtUserSetClipboardData returned %p\n", hRet);
    memset(out, 0, sizeof(out));
    cb = 0;
    Status = NtUserCreateLocalMemHandle(hMem, out, sizeof(out), &cb);
    ok(Status == STATUS_SUCCESS, "on the clipboard: 0x%08lx\n", Status);
    ok(cb == sizeof(data), "size %lu\n", cb);
    ok(!memcmp(out, data, sizeof(data)), "data differs\n");

done:
    EmptyClipboard();
    CloseClipboard();
}

static void test_marker_not_a_handle(void)
{
    GETCLIPBDATA gcd;
    SETCLIPBDATA scd = {FALSE, TRUE};
    HANDLE h;

    ok(OpenClipboard(NULL), "OpenClipboard failed\n");
    EmptyClipboard();

    /* 2 is the kernel's mark for "make the bitmap from the DIB later"; with no DIB there is nothing to make */
    NtUserSetClipboardData(CF_BITMAP, (HANDLE)(ULONG_PTR)2, &scd);
    memset(&gcd, 0, sizeof(gcd));
    h = NtUserGetClipboardData(CF_BITMAP, &gcd);
    ok(h == NULL, "NtUserGetClipboardData returned %p\n", h);

    EmptyClipboard();

    /* a format that is not one of the synthesized ones: nothing to resolve, and no assertion */
    NtUserSetClipboardData(CF_PRIVATEFIRST, (HANDLE)(ULONG_PTR)1, &scd);
    memset(&gcd, 0, sizeof(gcd));
    h = NtUserGetClipboardData(CF_PRIVATEFIRST, &gcd);
    ok(h == NULL || h == (HANDLE)(ULONG_PTR)1, "private format: %p\n", h);

    EmptyClipboard();
    CloseClipboard();
}

START_TEST(NtUserClipboardHandles)
{
    if (!is_reactos())
    {
        skip("ReactOS win32k behaviour\n");
        return;
    }

    test_localmem_handle();
    test_marker_not_a_handle();
}
