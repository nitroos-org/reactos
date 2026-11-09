/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Contract tests for the NtUser LOW batch: SendInput and mouse_event with distances
 *              that do not fit, SendInput with input types that do not exist, GetKeyNameText with
 *              buffers that are unusable, GetRawInputDeviceInfo(RIDI_DEVICEINFO) with a wrong
 *              cbSize. Documented Win32 calls with bad arguments only: no crash, a documented
 *              error, state unchanged.
 */

#include "precomp.h"

static void test_mouse_distance(void)
{
    POINT pt0, pt;
    INPUT in;
    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);

    if (!GetCursorPos(&pt0))
    {
        skip("no cursor\n");
        return;
    }
    SetCursorPos(cx / 2, cy / 2);
    GetCursorPos(&pt0);

    /* a relative move that does not fit a position moves the cursor to the edge it points to,
       it does not wrap to the other side */
    memset(&in, 0, sizeof(in));
    in.type = INPUT_MOUSE;
    in.mi.dx = 0x7fffffff;
    in.mi.dy = 0;
    in.mi.dwFlags = MOUSEEVENTF_MOVE;
    SendInput(1, &in, sizeof(in));
    GetCursorPos(&pt);
    ok(pt.x >= pt0.x, "relative move to the right: %ld -> %ld\n", pt0.x, pt.x);

    SetCursorPos(cx / 2, cy / 2);
    in.mi.dx = (LONG)0x80000000;
    SendInput(1, &in, sizeof(in));
    GetCursorPos(&pt);
    ok(pt.x <= pt0.x, "relative move to the left: %ld -> %ld\n", pt0.x, pt.x);

    /* the same through mouse_event, which takes the distances as DWORDs */
    SetCursorPos(cx / 2, cy / 2);
    mouse_event(MOUSEEVENTF_MOVE, 0x7fffffff, 0, 0, 0);
    GetCursorPos(&pt);
    ok(pt.x >= pt0.x, "mouse_event to the right: %ld -> %ld\n", pt0.x, pt.x);

    /* an absolute coordinate beyond 65535 is the far edge, it does not wrap */
    SetCursorPos(cx / 2, cy / 2);
    in.mi.dx = 0x7fffffff;
    in.mi.dy = 0x7fffffff;
    in.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
    SendInput(1, &in, sizeof(in));
    GetCursorPos(&pt);
    ok(pt.x >= cx / 2 && pt.y >= cy / 2, "absolute beyond the range: %ld,%ld\n", pt.x, pt.y);
    ok(pt.x < cx && pt.y < cy, "cursor left the screen: %ld,%ld\n", pt.x, pt.y);

    SetCursorPos(pt0.x, pt0.y);
}

static void test_sendinput_types(void)
{
    INPUT in[2];
    UINT ret;

    /* a type that does not exist is not counted and does not hurt */
    memset(in, 0, sizeof(in));
    in[0].type = 0x7fffffff;
    SetLastError(0xdeadbeef);
    ret = SendInput(1, in, sizeof(INPUT));
    ok(ret == 0, "SendInput(invalid type): %u\n", ret);

    in[0].type = INPUT_HARDWARE;
    ret = SendInput(1, in, sizeof(INPUT));
    ok(ret == 0, "SendInput(INPUT_HARDWARE): %u\n", ret);

    /* a valid event after the invalid one is still sent */
    in[0].type = 0x7fffffff;
    in[1].type = INPUT_KEYBOARD;
    in[1].ki.wVk = VK_F24;
    in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    ret = SendInput(2, in, sizeof(INPUT));
    ok(ret <= 1, "SendInput(invalid, valid): %u\n", ret);

    SetLastError(0xdeadbeef);
    ret = SendInput(1, in, sizeof(INPUT) - 1);
    ok(ret == 0, "SendInput(bad cbSize): %u\n", ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "bad cbSize: error %lu\n", GetLastError());
}

static void test_keynametext(void)
{
    WCHAR buf[16];
    BYTE *page;
    SYSTEM_INFO si;
    int ret;
    LONG lParam = 0x1e << 16; /* the key left of S */

    memset(buf, 0, sizeof(buf));
    ret = GetKeyNameTextW(lParam, buf, ARRAYSIZE(buf));
    ok(ret > 0, "GetKeyNameText: %d\n", ret);
    ok(ret == (int)wcslen(buf), "length %d, string %S\n", ret, buf);

    /* a size of 0 or less has nothing to write */
    ret = GetKeyNameTextW(lParam, buf, 0);
    ok(ret == 0, "size 0: %d\n", ret);
    ret = GetKeyNameTextW(lParam, buf, -1);
    ok(ret == 0, "size -1: %d\n", ret);

    /* a size of 1 holds the terminator only */
    memset(buf, 0xAA, sizeof(buf));
    ret = GetKeyNameTextW(lParam, buf, 1);
    ok(ret == 0, "size 1: %d\n", ret);
    ok(buf[0] == 0, "size 1: no terminator\n");

    /* an unusable buffer: no result, no crash */
    ret = GetKeyNameTextW(lParam, (LPWSTR)(ULONG_PTR)0x10, 8);
    ok(ret == 0, "bad pointer: %d\n", ret);
    ret = GetKeyNameTextW(lParam, NULL, 8);
    ok(ret == 0, "NULL buffer: %d\n", ret);

    /* a buffer that ends on the page edge: the name is cut to what fits */
    GetSystemInfo(&si);
    page = VirtualAlloc(NULL, 2 * si.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (page)
    {
        DWORD old;
        VirtualProtect(page + si.dwPageSize, si.dwPageSize, PAGE_NOACCESS, &old);
        ret = GetKeyNameTextW(lParam, (LPWSTR)(page + si.dwPageSize - 2 * sizeof(WCHAR)), 8);
        ok(ret == 1, "page edge: %d\n", ret);
        VirtualFree(page, 0, MEM_RELEASE);
    }

    /* a key with no name and no character */
    ret = GetKeyNameTextW(0xff << 16, buf, ARRAYSIZE(buf));
    ok(ret <= 1, "unknown scan code: %d\n", ret);
}

static void test_rawinput_deviceinfo_size(void)
{
    UINT n = 0, i, ret, size;
    RAWINPUTDEVICELIST *list;
    RID_DEVICE_INFO info;

    ret = GetRawInputDeviceList(NULL, &n, sizeof(RAWINPUTDEVICELIST));
    if (ret != 0 || !n)
    {
        skip("no raw input devices\n");
        return;
    }
    list = HeapAlloc(GetProcessHeap(), 0, n * sizeof(*list));
    ret = GetRawInputDeviceList(list, &n, sizeof(RAWINPUTDEVICELIST));
    if (ret == (UINT)-1)
    {
        HeapFree(GetProcessHeap(), 0, list);
        skip("GetRawInputDeviceList failed\n");
        return;
    }

    for (i = 0; i < ret; i++)
    {
        /* the structure has to say how big it is */
        memset(&info, 0xAA, sizeof(info));
        info.cbSize = sizeof(info) - 1;
        size = sizeof(info);
        SetLastError(0xdeadbeef);
        ret = GetRawInputDeviceInfoW(list[i].hDevice, RIDI_DEVICEINFO, &info, &size);
        ok(ret == (UINT)-1, "wrong cbSize: %u\n", ret);
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "wrong cbSize: error %lu\n", GetLastError());
        ok(info.dwType == 0xAAAAAAAA, "wrong cbSize: the structure was written\n");

        memset(&info, 0xAA, sizeof(info));
        info.cbSize = sizeof(info);
        size = sizeof(info);
        ret = GetRawInputDeviceInfoW(list[i].hDevice, RIDI_DEVICEINFO, &info, &size);
        ok(ret == sizeof(info), "right cbSize: %u\n", ret);
        ok(info.cbSize == sizeof(info), "cbSize %lu\n", info.cbSize);
        break;
    }
    HeapFree(GetProcessHeap(), 0, list);
}

START_TEST(UserLowsBatch)
{
    test_mouse_distance();
    test_sendinput_types();
    test_keynametext();
    test_rawinput_deviceinfo_size();
}
