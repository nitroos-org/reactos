/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         WM_COPYDATA / WM_COPYGLOBALDATA with a NULL or bad parameter sent to another process
 *
 * Expected results were measured on Windows 10 22H2 (build 19045) with a probe of our own: a NULL or unreadable
 * COPYDATASTRUCT (or a NULL global handle) is not delivered, SendMessage returns 0 and the last error is not
 * touched; PostMessage fails with ERROR_MESSAGE_SYNC_ONLY. A NULL lpData is delivered as NULL.
 */

#include "precomp.h"

static void widen(const char *src, WCHAR *dst, int max)
{
    int i;

    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
}

#define CHILD_CLASS L"CopyDataSendChild"
#define MY_ERR      0xdead0000UL

/* messages the child answers (it is a separate process, so these are the only way to look into it) */
#define CMD_COUNT   (WM_APP + 1)  /* number of WM_COPYDATA / WM_COPYGLOBALDATA delivered so far */
#define CMD_LASTCDS (WM_APP + 2)  /* bit0 lParam, bit1 lpData non-NULL; cbData << 8; the dwData is in CMD_LASTDATA */
#define CMD_LASTDATA (WM_APP + 3)
#define CMD_LASTFIRST (WM_APP + 4) /* first dword of the data */

static LONG g_count;
static ULONG_PTR g_last_flags, g_last_data, g_last_first;

static LRESULT CALLBACK ChildProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_COPYDATA:
        {
            const COPYDATASTRUCT *cds = (const COPYDATASTRUCT *)lParam;
            g_count++;
            g_last_flags = 0; g_last_data = 0; g_last_first = 0;
            if (cds)
            {
                g_last_flags = 1 | (cds->lpData ? 2 : 0) | ((ULONG_PTR)cds->cbData << 8);
                g_last_data = cds->dwData;
                if (cds->lpData && cds->cbData >= 4)
                    g_last_first = *(const DWORD *)cds->lpData;
            }
            return 0x5151;
        }
        case WM_COPYGLOBALDATA:
            g_count++;
            return 0x5152;
        case CMD_COUNT: return g_count;
        case CMD_LASTCDS: return g_last_flags;
        case CMD_LASTDATA: return g_last_data;
        case CMD_LASTFIRST: return g_last_first;
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
static PROCESS_INFORMATION g_pi;

static BOOL StartChild(void)
{
    CHAR Path[MAX_PATH], CmdLine[MAX_PATH + 100], Title[64];
    WCHAR wTitle[64];
    STARTUPINFOA si = { sizeof(si) };
    DWORD Start;

    GetModuleFileNameA(NULL, Path, ARRAYSIZE(Path));
    sprintf(Title, "CopyDataSendChild_%lu", GetCurrentProcessId());
    sprintf(CmdLine, "\"%s\" SendMessageCopyData child %s", Path, Title);
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

static LONG Count(void)
{
    DWORD_PTR r = 0;
    ok(SendMessageTimeoutW(g_child, CMD_COUNT, 0, 0, SMTO_NORMAL, 5000, &r), "the child does not answer\n");
    return (LONG)r;
}

static DWORD_PTR Query(UINT cmd)
{
    DWORD_PTR r = 0;
    SendMessageTimeoutW(g_child, cmd, 0, 0, SMTO_NORMAL, 5000, &r);
    return r;
}

static VOID CALLBACK CbProc(HWND hwnd, UINT msg, ULONG_PTR data, LRESULT result)
{
}

/* every way of sending msg with a parameter that cannot be marshalled: nothing is delivered, 0 and no error */
static void test_unmarshallable(UINT msg, LPARAM lParam, const char *what)
{
    LONG before = Count();
    DWORD_PTR res;
    LRESULT lr;
    BOOL ret;

    SetLastError(MY_ERR);
    lr = SendMessageW(g_child, msg, 0, lParam);
    ok(lr == 0, "%s msg %#x: SendMessageW returned %Ix\n", what, msg, lr);
    ok(GetLastError() == MY_ERR, "%s msg %#x: SendMessageW changed the last error to %lu\n", what, msg, GetLastError());

    res = 0x1234;
    SetLastError(MY_ERR);
    ret = SendMessageTimeoutW(g_child, msg, 0, lParam, SMTO_NORMAL, 3000, &res) != 0;
    ok(!ret, "%s msg %#x: SendMessageTimeoutW succeeded\n", what, msg);
    ok(res == 0, "%s msg %#x: SendMessageTimeoutW result %Ix\n", what, msg, res);
    ok(GetLastError() == MY_ERR, "%s msg %#x: SendMessageTimeoutW changed the last error to %lu\n", what, msg, GetLastError());

    SetLastError(MY_ERR);
    ret = SendNotifyMessageW(g_child, msg, 0, lParam);
    ok(!ret, "%s msg %#x: SendNotifyMessageW succeeded\n", what, msg);
    ok(GetLastError() == MY_ERR, "%s msg %#x: SendNotifyMessageW changed the last error to %lu\n", what, msg, GetLastError());

    SetLastError(MY_ERR);
    ret = SendMessageCallbackW(g_child, msg, 0, lParam, CbProc, 1);
    ok(!ret, "%s msg %#x: SendMessageCallbackW succeeded\n", what, msg);
    ok(GetLastError() == MY_ERR, "%s msg %#x: SendMessageCallbackW changed the last error to %lu\n", what, msg, GetLastError());

    SetLastError(MY_ERR);
    ret = PostMessageW(g_child, msg, 0, lParam);
    ok(!ret, "%s msg %#x: PostMessageW succeeded\n", what, msg);
    ok(GetLastError() == ERROR_MESSAGE_SYNC_ONLY, "%s msg %#x: PostMessageW error %lu\n", what, msg, GetLastError());

    ok(Count() == before, "%s msg %#x: the child was sent a message (%ld -> %ld)\n", what, msg, before, Count());
}

static void test_valid(void)
{
    static const BYTE data[16] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    COPYDATASTRUCT cds = { 7, 4, (PVOID)data };
    LONG before;
    DWORD_PTR res = 0;
    BOOL ret;

    /* a real COPYDATASTRUCT arrives */
    before = Count();
    SetLastError(MY_ERR);
    ok(SendMessageW(g_child, WM_COPYDATA, 0, (LPARAM)&cds) == 0x5151, "SendMessageW did not reach the child\n");
    ok(Count() == before + 1, "not delivered\n");
    ok(Query(CMD_LASTDATA) == 7, "dwData %Ix\n", Query(CMD_LASTDATA));
    ok(Query(CMD_LASTCDS) == (1 | 2 | (4 << 8)), "flags %Ix\n", Query(CMD_LASTCDS));
    ok(Query(CMD_LASTFIRST) == 0x04030201, "data %Ix\n", Query(CMD_LASTFIRST));
    ok(SendMessageTimeoutW(g_child, WM_COPYDATA, 0, (LPARAM)&cds, SMTO_NORMAL, 3000, &res) && res == 0x5151,
       "SendMessageTimeoutW: %Ix\n", res);

    /* posting or notifying one is refused even with valid data */
    SetLastError(MY_ERR);
    ok(!PostMessageW(g_child, WM_COPYDATA, 0, (LPARAM)&cds), "PostMessageW succeeded\n");
    ok(GetLastError() == ERROR_MESSAGE_SYNC_ONLY, "PostMessageW error %lu\n", GetLastError());
    SetLastError(MY_ERR);
    ret = SendNotifyMessageW(g_child, WM_COPYDATA, 0, (LPARAM)&cds);
    ok(!ret && GetLastError() == ERROR_MESSAGE_SYNC_ONLY, "SendNotifyMessageW: %d, error %lu\n", ret, GetLastError());
    SetLastError(MY_ERR);
    ret = SendMessageCallbackW(g_child, WM_COPYDATA, 0, (LPARAM)&cds, CbProc, 1);
    ok(!ret && GetLastError() == ERROR_MESSAGE_SYNC_ONLY, "SendMessageCallbackW: %d, error %lu\n", ret, GetLastError());

    /* an empty one, and one whose lpData is NULL, arrive with lpData NULL */
    cds.dwData = 8; cds.cbData = 0; cds.lpData = NULL;
    ok(SendMessageW(g_child, WM_COPYDATA, 0, (LPARAM)&cds) == 0x5151, "empty: not delivered\n");
    ok(Query(CMD_LASTDATA) == 8, "empty: dwData %Ix\n", Query(CMD_LASTDATA));
    ok(Query(CMD_LASTCDS) == 1, "empty: flags %Ix (lpData must be NULL)\n", Query(CMD_LASTCDS));
    cds.dwData = 9; cds.cbData = 16; cds.lpData = NULL;
    ok(SendMessageW(g_child, WM_COPYDATA, 0, (LPARAM)&cds) == 0x5151, "NULL lpData: not delivered\n");
    ok(Query(CMD_LASTDATA) == 9, "NULL lpData: dwData %Ix\n", Query(CMD_LASTDATA));
    ok(Query(CMD_LASTCDS) == (1 | (16 << 8)), "NULL lpData: flags %Ix\n", Query(CMD_LASTCDS));
}

START_TEST(SendMessageCopyData)
{
    char **argv;
    int argc;
    WNDCLASSW wc = { 0 };
    HWND own;
    DWORD_PTR res;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        ChildProcess(argv[3]);
        return;
    }

    if (!StartChild())
        return;

    test_valid();
    test_unmarshallable(WM_COPYDATA, 0, "NULL");
    test_unmarshallable(WM_COPYDATA, 0x10, "bad pointer");
    test_unmarshallable(WM_COPYGLOBALDATA, 0, "NULL");

    /* a window of this thread: SendMessageTimeout marshals too, so it fails the same way */
    wc.lpfnWndProc = ChildProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"CopyDataSendOwn";
    RegisterClassW(&wc);
    own = CreateWindowW(L"CopyDataSendOwn", L"own", WS_POPUP, 0, 0, 10, 10, NULL, NULL, wc.hInstance, NULL);
    ok(own != NULL, "CreateWindow failed: %lu\n", GetLastError());
    if (own)
    {
        BOOL ret;

        res = 0x1234;
        SetLastError(MY_ERR);
        ret = SendMessageTimeoutW(own, WM_COPYDATA, 0, 0, SMTO_NORMAL, 3000, &res) != 0;
        ok(!ret && res == 0, "SendMessageTimeoutW to an own window with NULL: %d, %Ix\n", ret, res);
        ok(GetLastError() == MY_ERR, "error %lu\n", GetLastError());
        DestroyWindow(own);
    }
    UnregisterClassW(L"CopyDataSendOwn", wc.hInstance);

    ok(Count() >= 0, "the child is gone\n");
    EndChild();
}
