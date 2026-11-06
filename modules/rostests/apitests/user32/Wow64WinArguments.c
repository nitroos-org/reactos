/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     win32k services whose WoW64 thunks take counts and lengths from the argument list
 *
 * The same PE32 file runs on i386 and under WoW64, where the thunks read the arguments once.
 * Well-formed calls must give what the i386 win32k gives, and the counts the services reject
 * must fail the way they do on Windows 10 x64 (WoW64).
 */

#include "precomp.h"

static BOOL IsWow64(void)
{
    typedef BOOL (WINAPI *PFN)(HANDLE, PBOOL);
    PFN pfn = (PFN)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");
    BOOL wow = FALSE;

    if (pfn)
        pfn(GetCurrentProcess(), &wow);
    return wow;
}

static void test_keyboard_layout_list(void)
{
    HKL list[4];
    HKL one[1];
    int count, ret, i;
    static const int bad[] = { -1, 0x7fffffff, 0x20000000, 0x10000000 };

    count = GetKeyboardLayoutList(0, NULL);
    ok(count >= 0, "count %d\n", count);

    if (count > 0)
    {
        ret = GetKeyboardLayoutList(ARRAYSIZE(list), list);
        ok(ret == min(count, (int)ARRAYSIZE(list)) || ret == count, "list: %d, count %d\n", ret, count);
        ok(list[0] != NULL, "first layout is NULL\n");

        /* a list too short for all of them is filled as far as it goes */
        memset(one, 0, sizeof(one));
        ret = GetKeyboardLayoutList(1, one);
        ok(ret == 1, "list of one: %d\n", ret);
        ok(one[0] == list[0], "first layout %p, expected %p\n", one[0], list[0]);
    }

    /* sizes that are not sizes: nothing, and an error (the thunk allocated for them) */
    for (i = 0; i < ARRAYSIZE(bad); i++)
    {
        memset(list, 0, sizeof(list));
        SetLastError(0xdeadbeef);
        ret = GetKeyboardLayoutList(bad[i], list);
        ok(ret == 0, "size %d: %d\n", bad[i], ret);
        ok(list[0] == NULL, "size %d: the list was written\n", bad[i]);
        /* the error of the WoW64 thunk; the native win32k has its own */
        if (IsWow64())
            ok(GetLastError() == ERROR_NOT_ENOUGH_MEMORY, "size %d: error %lu\n", bad[i], GetLastError());
    }
}

START_TEST(Wow64WinArguments)
{
    test_keyboard_layout_list();
}
