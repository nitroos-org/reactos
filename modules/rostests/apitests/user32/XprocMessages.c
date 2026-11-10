/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         Messages Windows refuses to carry from one process to another
 *
 * The expected error codes were measured on Windows 10 22H2 (build 19045) with a probe of our own: message numbers
 * 0x0 - 0x43f sent with wParam 0 and lParam 0 to a window of another process of the same user, with each of
 * PostMessage, SendMessage(Timeout), SendNotifyMessage, SendMessageCallback and PostThreadMessage. The same
 * messages go through between threads of one process. This test checks a sample of the measured table, not all of it.
 */

#include "precomp.h"

static void widen(const char *src, WCHAR *dst, int max)
{
    int i;

    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
}

#define CHILD_CLASS L"XprocMsgChild"
#define MY_ERR      0xdead0000UL

#define CMD_SEEN  (WM_APP + 1)  /* wParam = message: was it dispatched since CMD_CLEAR? */
#define CMD_CLEAR (WM_APP + 2)  /* wParam = message */
#define CMD_TID   (WM_APP + 3)  /* the thread id of the child's UI thread */
#define CMD_ARM   (WM_APP + 4)  /* from here on the tested messages are recorded and not passed on */
#define CMD_PASS  (WM_APP + 5)  /* a message that must go through */

static BOOL g_armed;
static BYTE g_seen[0x440];

static LRESULT CALLBACK ChildProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case CMD_ARM: g_armed = TRUE; return 1;
        case CMD_SEEN: return wParam < sizeof(g_seen) ? g_seen[wParam] : 0;
        case CMD_CLEAR: if (wParam < sizeof(g_seen)) g_seen[wParam] = 0; return 1;
        case CMD_TID: return GetCurrentThreadId();
        case CMD_PASS: return 0x7b1;
    }
    /* once armed, a message below 0x440 that arrives from outside is noted and not handed to DefWindowProc, whose
       handling of a message with a NULL lParam is not what is being tested */
    if (g_armed && msg < sizeof(g_seen))
        g_seen[msg] = 1;
    if (g_armed && msg < sizeof(g_seen) && (msg == WM_NOTIFY || msg == WM_INITDIALOG || msg == WM_CREATE ||
        (msg >= 0x119 && msg <= 0x11c) || (msg >= 0x240 && msg <= 0x257) || msg == 0xe || msg == 0x24 ||
        msg == 0x2ed || msg == 0x32c || msg == 0x341 || msg == 0x30c || msg == 0x14))
    {
        return 0x7b1;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void ChildProcess(const char *title)
{
    WNDCLASSW wc = { 0 };
    WCHAR wTitle[80];
    HWND hwnd;
    MSG msg;

    wc.lpfnWndProc = ChildProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = CHILD_CLASS;
    RegisterClassW(&wc);
    widen(title, wTitle, ARRAYSIZE(wTitle));
    hwnd = CreateWindowExW(0, CHILD_CLASS, wTitle, WS_POPUP, 0, 0, 10, 10, NULL, NULL, wc.hInstance, NULL);
    if (!hwnd)
        return;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
        DispatchMessageW(&msg);
}

static HWND g_child;
static DWORD g_childTid;
static PROCESS_INFORMATION g_pi;

static BOOL StartChild(void)
{
    CHAR Path[MAX_PATH], CmdLine[MAX_PATH + 100], Title[64];
    WCHAR wTitle[64];
    STARTUPINFOA si = { sizeof(si) };
    DWORD Start;

    GetModuleFileNameA(NULL, Path, ARRAYSIZE(Path));
    sprintf(Title, "XprocMsgChild_%lu", GetCurrentProcessId());
    sprintf(CmdLine, "\"%s\" XprocMessages child %s", Path, Title);
    widen(Title, wTitle, ARRAYSIZE(wTitle));
    if (!CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &g_pi))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        return FALSE;
    }
    Start = GetTickCount();
    while (!g_child && GetTickCount() - Start < 15000)
    {
        g_child = FindWindowW(CHILD_CLASS, wTitle);
        if (!g_child)
            Sleep(20);
    }
    ok(g_child != NULL, "the child window was not found\n");
    if (!g_child)
    {
        TerminateProcess(g_pi.hProcess, 1);
        WaitForSingleObject(g_pi.hProcess, 10000);
        CloseHandle(g_pi.hThread);
        CloseHandle(g_pi.hProcess);
    }
    return g_child != NULL;
}

static void EndChild(void)
{
    TerminateProcess(g_pi.hProcess, 0);
    WaitForSingleObject(g_pi.hProcess, 10000);
    CloseHandle(g_pi.hThread);
    CloseHandle(g_pi.hProcess);
}

static BOOL Seen(HWND hwnd, UINT msg)
{
    DWORD_PTR r = 0;
    ok(SendMessageTimeoutW(hwnd, CMD_SEEN, msg, 0, SMTO_NORMAL, 5000, &r), "the child does not answer\n");
    return r != 0;
}

static void Clear(HWND hwnd, UINT msg)
{
    DWORD_PTR r;
    SendMessageTimeoutW(hwnd, CMD_CLEAR, msg, 0, SMTO_NORMAL, 5000, &r);
}

static VOID CALLBACK CbProc(HWND hwnd, UINT msg, ULONG_PTR data, LRESULT result)
{
}

/* one row of the measured table: the error each API gives for the message, 0 = it goes through */
typedef struct
{
    UINT msg;
    DWORD post, send, notify, callback, thread;
} ROW;

#define XS ERROR_MESSAGE_SYNC_ONLY
#define XD ERROR_ACCESS_DENIED
#define XP ERROR_INVALID_PARAMETER
#define XA ERROR_INVALID_ADDRESS
#define XM ERROR_INVALID_MESSAGE
static const ROW g_rows[] =
{
    /* msg     post send notify callback thread */
    { WM_NOTIFY,   XD, XD, XD, XD, XD },
    { WM_INITDIALOG, XS, XD, XS, XS, XS },
    { WM_CREATE,   XS, XD, XS, XS, XS },
    { 0x11c,       XS, XD, XD, XD, XS },
    { 0x32c,       XS, XD, XD, XD, XS },
    { 0x341,       XS, XD, XD, XD, XS },
    { 0x2ed,       XD, 0, 0, 0, 0 },
    { 0x119,       XP, XP, XP, XP, XM },
    { 0x240,       XP, XP, XP, XP, XM },
    { 0x24b,       XM, XP, XP, XP, XM },
    { 0x30c,       XS, XP, XP, XP, XS },
    { 0x11a,       XS, XA, XA, XA, XS },
    { 0x24d,       XS, XA, XA, XA, XS },
    { 0x241,       XM, 0, 0, 0, XM },
    { 0x257,       XM, 0, 0, 0, XM },
    { 0x11b,       XM, 0, 0, 0, 0 },
    { WM_GETMINMAXINFO, XS, 0, 0, 0, XS },
    { WM_GETTEXTLENGTH, XS, 0, XS, XS, XS },
};
#undef XS
#undef XD
#undef XP
#undef XA
#undef XM

static void check_fail(const char *api, UINT msg, BOOL ret, LRESULT lr, DWORD err, DWORD expected)
{
    ok(!ret && !lr, "%s %#x: returned %d / %Ix\n", api, msg, ret, lr);
    ok(err == expected, "%s %#x: error %lu, expected %lu\n", api, msg, err, expected);
}

static void test_row(const ROW *row)
{
    UINT msg = row->msg;
    DWORD_PTR res;
    LRESULT lr;
    BOOL ret;

    /* a row where only some APIs refuse still has to reach the window with the others: only look at the refusals */
    Clear(g_child, msg);

    SetLastError(MY_ERR);
    ret = PostMessageW(g_child, msg, 0, 0);
    if (row->post)
        check_fail("PostMessage", msg, ret, 0, GetLastError(), row->post);
    else
        ok(ret, "PostMessage %#x failed with %lu\n", msg, GetLastError());

    SetLastError(MY_ERR);
    lr = SendMessageW(g_child, msg, 0, 0);
    if (row->send)
        check_fail("SendMessage", msg, FALSE, lr, GetLastError(), row->send);

    res = 0x1234;
    SetLastError(MY_ERR);
    ret = SendMessageTimeoutW(g_child, msg, 0, 0, SMTO_NORMAL, 3000, &res) != 0;
    if (row->send)
    {
        check_fail("SendMessageTimeout", msg, ret, res, GetLastError(), row->send);
    }

    SetLastError(MY_ERR);
    ret = SendNotifyMessageW(g_child, msg, 0, 0);
    if (row->notify)
        check_fail("SendNotifyMessage", msg, ret, 0, GetLastError(), row->notify);

    SetLastError(MY_ERR);
    ret = SendMessageCallbackW(g_child, msg, 0, 0, CbProc, 1);
    if (row->callback)
        check_fail("SendMessageCallback", msg, ret, 0, GetLastError(), row->callback);

    SetLastError(MY_ERR);
    ret = PostThreadMessageW(g_childTid, msg, 0, 0);
    if (row->thread)
        check_fail("PostThreadMessage", msg, ret, 0, GetLastError(), row->thread);
    else if (!ret)
        ok(GetLastError() != ERROR_ACCESS_DENIED, "PostThreadMessage %#x: error %lu\n", msg, GetLastError());

    /* when every API refuses, the window never saw it */
    if (row->post && row->send && row->notify && row->callback)
        ok(!Seen(g_child, msg), "message %#x reached the window of the other process\n", msg);
}

static void test_passes(void)
{
    DWORD_PTR res = 0;

    /* messages that are not in the table go through, with all APIs */
    SetLastError(MY_ERR);
    ok(SendMessageW(g_child, CMD_PASS, 0, 0) == 0x7b1, "SendMessage of a private message failed: %lu\n", GetLastError());
    ok(SendMessageTimeoutW(g_child, CMD_PASS, 0, 0, SMTO_NORMAL, 3000, &res) && res == 0x7b1, "SendMessageTimeout\n");
    ok(PostMessageW(g_child, CMD_PASS, 0, 0), "PostMessage of a private message failed: %lu\n", GetLastError());
    ok(SendNotifyMessageW(g_child, CMD_PASS, 0, 0), "SendNotifyMessage of a private message failed: %lu\n", GetLastError());
    ok(SendMessageCallbackW(g_child, CMD_PASS, 0, 0, CbProc, 1), "SendMessageCallback failed: %lu\n", GetLastError());
    ok(PostThreadMessageW(g_childTid, WM_NULL, 0, 0), "PostThreadMessage failed: %lu\n", GetLastError());
}

/* messages Windows swallows when wParam and lParam are 0: no error, nothing delivered */
static void test_silent(void)
{
    static const UINT send_msgs[] = { 0x1b, 0x2d, 0x38, 0x70, 0x124, 0x2e0 };
    DWORD_PTR res;
    LRESULT lr;
    BOOL ret;
    size_t i;

    for (i = 0; i < ARRAYSIZE(send_msgs); i++)
    {
        UINT msg = send_msgs[i];

        Clear(g_child, msg);
        SetLastError(MY_ERR);
        lr = SendMessageW(g_child, msg, 0, 0);
        ok(lr == 0, "SendMessage %#x returned %Ix\n", msg, lr);
        ok(GetLastError() == MY_ERR, "SendMessage %#x: error %lu\n", msg, GetLastError());
        res = 0x1234;
        SetLastError(MY_ERR);
        ret = SendMessageTimeoutW(g_child, msg, 0, 0, SMTO_NORMAL, 3000, &res) != 0;
        ok(!ret && res == 0, "SendMessageTimeout %#x: %d, %Ix\n", msg, ret, res);
        ok(GetLastError() == MY_ERR, "SendMessageTimeout %#x: error %lu\n", msg, GetLastError());
        SetLastError(MY_ERR);
        ret = SendNotifyMessageW(g_child, msg, 0, 0);
        ok(!ret, "SendNotifyMessage %#x succeeded\n", msg);
        ok(!Seen(g_child, msg), "message %#x reached the window of the other process\n", msg);
    }

    /* a post that is swallowed with TRUE, and one with FALSE; no error either way */
    Clear(g_child, 0x23b);
    SetLastError(MY_ERR);
    ret = PostMessageW(g_child, 0x23b, 0, 0);
    ok(ret, "PostMessage 0x23b failed: %lu\n", GetLastError());
    ok(GetLastError() == MY_ERR, "PostMessage 0x23b: error %lu\n", GetLastError());
    SetLastError(MY_ERR);
    ret = PostMessageW(g_child, 0x2cd, 0, 0);
    ok(!ret && GetLastError() == MY_ERR, "PostMessage 0x2cd: %d, error %lu\n", ret, GetLastError());
    Sleep(100);
    ok(!Seen(g_child, 0x23b), "0x23b reached the window of the other process\n");

    /* with parameters, nothing was measured and nothing changes: the message is delivered */
    Clear(g_child, 0x70);
    SetLastError(MY_ERR);
    SendMessageTimeoutW(g_child, 0x70, 1, 0, SMTO_NORMAL, 3000, &res);
    ok(Seen(g_child, 0x70), "0x70 with wParam 1 was not delivered\n");
}

static LRESULT CALLBACK OwnProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_NOTIFY || msg == WM_INITDIALOG)
        return 0x7b1;
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static HWND g_ownThreadWnd;
static HANDLE g_ownReady, g_ownStop;

static DWORD WINAPI OwnThread(LPVOID arg)
{
    MSG msg;
    g_ownThreadWnd = CreateWindowW(L"XprocMsgOwn", L"own", WS_POPUP, 0, 0, 10, 10, NULL, NULL,
                                   GetModuleHandleW(NULL), NULL);
    SetEvent(g_ownReady);
    while (WaitForSingleObject(g_ownStop, 0) == WAIT_TIMEOUT)
    {
        if (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
        else
            MsgWaitForMultipleObjects(1, &g_ownStop, FALSE, 20, QS_ALLINPUT);
    }
    return 0;
}

/* between threads of one process the same messages are delivered */
static void test_same_process(void)
{
    WNDCLASSW wc = { 0 };
    HANDLE th;
    DWORD_PTR res = 0;

    wc.lpfnWndProc = OwnProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"XprocMsgOwn";
    RegisterClassW(&wc);
    g_ownReady = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_ownStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, OwnThread, NULL, 0, NULL);
    ok(WaitForSingleObject(g_ownReady, 5000) == WAIT_OBJECT_0, "the thread did not start\n");
    if (g_ownThreadWnd)
    {
        SetLastError(MY_ERR);
        ok(SendMessageW(g_ownThreadWnd, WM_NOTIFY, 0, 0) == 0x7b1, "WM_NOTIFY to a window of another thread: error %lu\n",
           GetLastError());
        ok(SendMessageTimeoutW(g_ownThreadWnd, WM_INITDIALOG, 0, 0, SMTO_NORMAL, 3000, &res) && res == 0x7b1,
           "WM_INITDIALOG to a window of another thread: error %lu\n", GetLastError());
        ok(SendNotifyMessageW(g_ownThreadWnd, WM_NOTIFY, 0, 0), "SendNotifyMessage WM_NOTIFY: %lu\n", GetLastError());
        ok(PostMessageW(g_ownThreadWnd, WM_NOTIFY, 0, 0), "PostMessage WM_NOTIFY: %lu\n", GetLastError());
    }
    SetEvent(g_ownStop);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    CloseHandle(g_ownReady);
    CloseHandle(g_ownStop);
    if (g_ownThreadWnd)
        DestroyWindow(g_ownThreadWnd);
    UnregisterClassW(L"XprocMsgOwn", wc.hInstance);
}

START_TEST(XprocMessages)
{
    char **argv;
    int argc;
    DWORD_PTR r = 0;
    size_t i;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        ChildProcess(argv[3]);
        return;
    }

    if (!StartChild())
        return;
    ok(SendMessageTimeoutW(g_child, CMD_TID, 0, 0, SMTO_NORMAL, 5000, &r), "the child does not answer\n");
    g_childTid = (DWORD)r;
    ok(SendMessageTimeoutW(g_child, CMD_ARM, 0, 0, SMTO_NORMAL, 5000, &r), "the child does not answer\n");

    test_passes();
    test_silent();
    for (i = 0; i < ARRAYSIZE(g_rows); i++)
        test_row(&g_rows[i]);
    test_same_process();

    EndChild();
}
