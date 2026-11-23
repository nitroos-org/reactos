/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     GetLastInputInfo moves after injected input (SendInput key / mouse / unicode, keybd_event,
 *              mouse_event) and does not move after SetCursorPos or a posted message. Windows Server 2022
 *              rows measured in kbatch8 (evidence kbatch8-20261123/results/li-*).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static DWORD LastInput(void)
{
    LASTINPUTINFO lii = { sizeof(lii) };
    BOOL ret = GetLastInputInfo(&lii);
    ok(ret, "GetLastInputInfo failed: %lu\n", GetLastError());
    return lii.dwTime;
}

static void Wait(void)
{
    /* the tick counter must have advanced so that a new stamp is distinguishable */
    Sleep(100);
}

START_TEST(LastInputInfo)
{
    INPUT in[2];
    DWORD before, after;
    POINT pt;
    UINT n;

    if (!GetForegroundWindow() && !GetCursorPos(&pt))
    {
        skip("no interactive input desktop\n");
        return;
    }

    /* no event: unchanged */
    before = LastInput(); Wait(); after = LastInput();
    ok(before == after, "stamp moved without input: %lu -> %lu\n", before, after);

    /* SendInput key (virtual key) */
    memset(in, 0, sizeof(in));
    in[0].type = in[1].type = INPUT_KEYBOARD;
    in[0].ki.wVk = in[1].ki.wVk = VK_F15;
    in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    before = LastInput(); Wait();
    n = SendInput(2, in, sizeof(INPUT));
    if (n == 2)
    {
        after = LastInput();
        ok(after != before, "SendInput(key) did not move GetLastInputInfo (%lu)\n", after);
    }
    else
        skip("SendInput refused (%u, %lu)\n", n, GetLastError());

    /* SendInput unicode */
    memset(in, 0, sizeof(in));
    in[0].type = in[1].type = INPUT_KEYBOARD;
    in[0].ki.wScan = in[1].ki.wScan = 'a';
    in[0].ki.dwFlags = KEYEVENTF_UNICODE;
    in[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
    before = LastInput(); Wait();
    if (SendInput(2, in, sizeof(INPUT)) == 2)
    {
        after = LastInput();
        ok(after != before, "SendInput(unicode) did not move GetLastInputInfo\n");
    }

    /* SendInput mouse move */
    memset(in, 0, sizeof(in));
    in[0].type = INPUT_MOUSE;
    in[0].mi.dx = 1;
    in[0].mi.dwFlags = MOUSEEVENTF_MOVE;
    before = LastInput(); Wait();
    if (SendInput(1, in, sizeof(INPUT)) == 1)
    {
        after = LastInput();
        ok(after != before, "SendInput(mouse move) did not move GetLastInputInfo\n");
    }

    /* keybd_event / mouse_event */
    before = LastInput(); Wait();
    keybd_event(VK_F15, 0, 0, 0);
    keybd_event(VK_F15, 0, KEYEVENTF_KEYUP, 0);
    after = LastInput();
    ok(after != before, "keybd_event did not move GetLastInputInfo\n");

    before = LastInput(); Wait();
    mouse_event(MOUSEEVENTF_MOVE, 1, 0, 0, 0);
    after = LastInput();
    ok(after != before, "mouse_event did not move GetLastInputInfo\n");

    /* SetCursorPos and a posted message are not input */
    GetCursorPos(&pt);
    before = LastInput(); Wait();
    SetCursorPos(pt.x + 2, pt.y);
    PostMessageA(GetDesktopWindow(), WM_KEYDOWN, VK_F15, 0);
    after = LastInput();
    ok(after == before, "SetCursorPos/PostMessage moved GetLastInputInfo: %lu -> %lu\n", before, after);
    SetCursorPos(pt.x, pt.y);
}
