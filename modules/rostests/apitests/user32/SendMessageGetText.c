/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         WM_GETTEXT sent to an Edit control of another process
 *
 * Expected results were measured on Windows Server 2022 (10.0.20348) with a probe of our own: the text arrives,
 * the return value is the number of characters copied, the bytes of the buffer after the terminator are not
 * touched, and the last error is not changed. An edit control with more than 64 KB of text gives the characters
 * that fit (cch 200000: 100000, cch 65536: 65535, cch 100001: 100000, cch 100000: 99999).
 */

#include "precomp.h"

#define CHILD_CLASS L"GetTextSendChild"
#define MY_ERR      0xdead0000UL
#define BIG_LEN     100000
#define ID_SMALL    1
#define ID_BIG      2

static void widen(const char *src, WCHAR *dst, int max)
{
    int i;

    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
}

static WCHAR BigChar(int i)
{
    return (i % 80 == 79) ? L'\n' : (WCHAR)(L'a' + i % 26);
}

static void ChildProcess(const char *title)
{
    WNDCLASSW wc = { 0 };
    WCHAR wTitle[80];
    HWND top, big;
    MSG msg;
    WCHAR *text;
    int i;

    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = CHILD_CLASS;
    RegisterClassW(&wc);
    widen(title, wTitle, ARRAYSIZE(wTitle));
    top = CreateWindowExW(0, CHILD_CLASS, wTitle, WS_OVERLAPPEDWINDOW, 0, 0, 300, 300, NULL, NULL, wc.hInstance, NULL);
    if (!top)
        return;
    CreateWindowExW(0, L"EDIT", L"small-text", WS_CHILD | WS_VISIBLE, 0, 0, 100, 20, top, (HMENU)ID_SMALL, wc.hInstance, NULL);
    big = CreateWindowExW(0, L"EDIT", NULL, WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL,
                          0, 30, 100, 100, top, (HMENU)ID_BIG, wc.hInstance, NULL);
    text = HeapAlloc(GetProcessHeap(), 0, (BIG_LEN + 1) * sizeof(WCHAR));
    for (i = 0; i < BIG_LEN; i++)
        text[i] = BigChar(i);
    text[BIG_LEN] = 0;
    SendMessageW(big, EM_SETLIMITTEXT, 0x7FFFFFFE, 0);
    SendMessageW(big, WM_SETTEXT, 0, (LPARAM)text);
    HeapFree(GetProcessHeap(), 0, text);
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
        DispatchMessageW(&msg);
}

static HWND g_top;
static PROCESS_INFORMATION g_pi;

static BOOL StartChild(void)
{
    CHAR Path[MAX_PATH], CmdLine[MAX_PATH + 100], Title[64];
    WCHAR wTitle[64];
    STARTUPINFOA si = { sizeof(si) };
    DWORD Start;

    GetModuleFileNameA(NULL, Path, ARRAYSIZE(Path));
    sprintf(Title, "GetTextSendChild_%lu", GetCurrentProcessId());
    sprintf(CmdLine, "\"%s\" SendMessageGetText child %s", Path, Title);
    widen(Title, wTitle, ARRAYSIZE(wTitle));
    if (!CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &g_pi))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        return FALSE;
    }
    Start = GetTickCount();
    while (!g_top && GetTickCount() - Start < 15000)
    {
        g_top = FindWindowW(CHILD_CLASS, wTitle);
        if (!g_top)
            Sleep(20);
    }
    ok(g_top != NULL, "the child window was not found\n");
    if (g_top)
    {
        /* the text of the big edit control is set once the window exists */
        HWND big;

        for (Start = GetTickCount(); GetTickCount() - Start < 15000; Sleep(20))
        {
            big = GetDlgItem(g_top, ID_BIG);
            if (big && SendMessageW(big, WM_GETTEXTLENGTH, 0, 0) == BIG_LEN)
                break;
        }
    }
    else
    {
        TerminateProcess(g_pi.hProcess, 1);
        WaitForSingleObject(g_pi.hProcess, 10000);
        CloseHandle(g_pi.hThread);
        CloseHandle(g_pi.hProcess);
    }
    return g_top != NULL;
}

static void EndChild(void)
{
    TerminateProcess(g_pi.hProcess, 0);
    WaitForSingleObject(g_pi.hProcess, 10000);
    CloseHandle(g_pi.hThread);
    CloseHandle(g_pi.hProcess);
}

static void test_small(void)
{
    HWND edit = GetDlgItem(g_top, ID_SMALL);
    WCHAR buf[64];
    LRESULT ret;
    int i;

    ok(edit != NULL, "no small edit control\n");
    if (!edit)
        return;

    for (i = 0; i < ARRAYSIZE(buf); i++)
        buf[i] = 0x5a5a;
    SetLastError(MY_ERR);
    ret = SendMessageW(edit, WM_GETTEXT, ARRAYSIZE(buf), (LPARAM)buf);
    ok(ret == 10, "WM_GETTEXT returned %Id\n", ret);
    ok(!wcscmp(buf, L"small-text"), "WM_GETTEXT gave %S\n", buf);
    ok(GetLastError() == MY_ERR, "the last error is %lu\n", GetLastError());
    for (i = 11; i < ARRAYSIZE(buf); i++)
        ok(buf[i] == 0x5a5a, "buffer[%d] was changed to %#x\n", i, buf[i]);

    /* a short buffer: the part that fits and the terminator */
    for (i = 0; i < ARRAYSIZE(buf); i++)
        buf[i] = 0x5a5a;
    ret = SendMessageW(edit, WM_GETTEXT, 3, (LPARAM)buf);
    ok(ret == 2, "WM_GETTEXT with a buffer of 3 returned %Id\n", ret);
    ok(buf[0] == 's' && buf[1] == 'm' && buf[2] == 0 && buf[3] == 0x5a5a, "buffer: %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3]);
}

static void test_big_one(HWND big, WCHAR *buf, int cch, int expected)
{
    LRESULT ret;
    int i, bad = -1;

    for (i = 0; i < BIG_LEN + 10; i++)
        buf[i] = 0x5a5a;
    SetLastError(MY_ERR);
    ret = SendMessageW(big, WM_GETTEXT, cch, (LPARAM)buf);
    ok(ret == expected, "WM_GETTEXT with a buffer of %d returned %Id, expected %d\n", cch, ret, expected);
    ok(GetLastError() == MY_ERR, "the last error is %lu\n", GetLastError());
    for (i = 0; i < expected && bad < 0; i++)
    {
        if (buf[i] != BigChar(i))
            bad = i;
    }
    ok(bad < 0, "buffer of %d: character %d is %#x\n", cch, bad, bad < 0 ? 0 : buf[bad]);
    ok(buf[expected] == 0, "buffer of %d: no terminator after %d characters (%#x)\n", cch, expected, buf[expected]);
}

static void test_big(void)
{
    HWND big = GetDlgItem(g_top, ID_BIG);
    WCHAR *buf;

    ok(big != NULL, "no big edit control\n");
    if (!big)
        return;
    buf = HeapAlloc(GetProcessHeap(), 0, (200000 + 10) * sizeof(WCHAR));
    if (!buf)
        return;

    test_big_one(big, buf, 200000, BIG_LEN);
    test_big_one(big, buf, 65536, 65535);
    test_big_one(big, buf, 65537, 65536);
    test_big_one(big, buf, BIG_LEN + 1, BIG_LEN);
    test_big_one(big, buf, BIG_LEN, BIG_LEN - 1);
    HeapFree(GetProcessHeap(), 0, buf);
}

START_TEST(SendMessageGetText)
{
    char **argv;
    int argc;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        ChildProcess(argv[3]);
        return;
    }

    if (!StartChild())
        return;

    test_small();
    test_big();
    EndChild();
}
