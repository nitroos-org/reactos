/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Functional tests for the hook/input hardening batch (G6): raw input device
 *              handles are opaque, repeated AttachThreadInput calls are counted, ToUnicodeEx
 *              takes any buffer size, a queued low-level hook call outlives its hook, and a
 *              hook on a desktop handle without DESKTOP_HOOKCONTROL.
 *              Only documented Win32 calls with bad arguments; the expected results are
 *              the ones Windows 10 gives.
 */

#include "precomp.h"

#ifndef DESKTOP_HOOKCONTROL
#define DESKTOP_HOOKCONTROL 0x0008
#endif

/* GetRawInputDeviceList hands out handles an application may keep: never an address */
static void test_rawinput_handles(void)
{
    UINT n = 0, i, size, count;
    RAWINPUTDEVICELIST *list;
    char name[260];
    UINT ret;

    ret = GetRawInputDeviceList(NULL, &n, sizeof(RAWINPUTDEVICELIST));
    ok(ret == 0, "GetRawInputDeviceList count: %u\n", ret);
    if (!n)
    {
        skip("no raw input devices\n");
    }
    else
    {
        list = HeapAlloc(GetProcessHeap(), 0, n * sizeof(*list));
        ret = GetRawInputDeviceList(list, &n, sizeof(RAWINPUTDEVICELIST));
        ok(ret == n, "GetRawInputDeviceList: %u of %u\n", ret, n);
        count = ret == (UINT)-1 ? 0 : ret;
        for (i = 0; i < count; i++)
        {
            ok(((ULONGLONG)(ULONG_PTR)list[i].hDevice >> 32) == 0 && list[i].hDevice != NULL,
               "device %u: handle %p is not an opaque 32-bit value\n", i, list[i].hDevice);
            size = sizeof(name);
            SetLastError(0xdeadbeef);
            ret = GetRawInputDeviceInfoA(list[i].hDevice, RIDI_DEVICENAME, name, &size);
            ok(ret != (UINT)-1, "device %u: GetRawInputDeviceInfo failed, error %lu\n", i, GetLastError());
        }
        HeapFree(GetProcessHeap(), 0, list);
    }

    /* a value that is not a device handle */
    size = sizeof(name);
    SetLastError(0xdeadbeef);
    ret = GetRawInputDeviceInfoA((HANDLE)(ULONG_PTR)0x12345678, RIDI_DEVICENAME, name, &size);
    ok(ret == (UINT)-1, "bogus handle: %u\n", ret);
    ok(GetLastError() == ERROR_INVALID_HANDLE, "bogus handle: error %lu\n", GetLastError());
}

static HANDLE ghStop;
static HANDLE ghReady[2];
static DWORD gTid[2];

static DWORD WINAPI QueueThread(LPVOID arg)
{
    MSG msg;
    int i = (int)(ULONG_PTR)arg;

    PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE);
    gTid[i] = GetCurrentThreadId();
    SetEvent(ghReady[i]);
    WaitForSingleObject(ghStop, 600000);
    return 0;
}

/* Every attach of a pair needs its own detach, however often the call is repeated */
static void test_attach_counted(void)
{
    HANDLE threads[2];
    BOOL ret;
    int i;
    const int count = 3000;

    ghStop = CreateEventA(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < 2; i++)
    {
        ghReady[i] = CreateEventA(NULL, TRUE, FALSE, NULL);
        threads[i] = CreateThread(NULL, 0, QueueThread, (LPVOID)(ULONG_PTR)i, 0, NULL);
        WaitForSingleObject(ghReady[i], 10000);
    }

    for (i = 0; i < count; i++)
    {
        ret = AttachThreadInput(gTid[0], gTid[1], TRUE);
        if (!ret)
            break;
    }
    ok(i == count, "attach %d of %d succeeded\n", i, count);

    for (i = 0; i < count; i++)
    {
        ret = AttachThreadInput(gTid[0], gTid[1], FALSE);
        if (!ret)
            break;
    }
    ok(i == count, "detach %d of %d succeeded\n", i, count);

    SetLastError(0xdeadbeef);
    ret = AttachThreadInput(gTid[0], gTid[1], FALSE);
    ok(!ret, "one detach too many succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "error %lu\n", GetLastError());

    SetEvent(ghStop);
    WaitForMultipleObjects(2, threads, TRUE, 10000);
    for (i = 0; i < 2; i++)
    {
        CloseHandle(threads[i]);
        CloseHandle(ghReady[i]);
    }
    CloseHandle(ghStop);
}

static void test_tounicode_sizes(void)
{
    BYTE state[256] = {0};
    SYSTEM_INFO si;
    BYTE *base;
    WCHAR *buf;
    HKL hkl = GetKeyboardLayout(0);
    int ret, i, j, cch[] = { 16, 8, 2, 1, 0, -1, 0x7fffffff };

    /* the buffer is the last 16 characters before a page nobody may touch */
    GetSystemInfo(&si);
    base = VirtualAlloc(NULL, 2 * si.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(base != NULL, "VirtualAlloc failed\n");
    if (!base)
        return;
    VirtualProtect(base + si.dwPageSize, si.dwPageSize, PAGE_NOACCESS, &(DWORD){0});
    buf = (WCHAR *)(base + si.dwPageSize - 16 * sizeof(WCHAR));

    for (i = 0; i < ARRAYSIZE(cch); i++)
    {
        int zeros = 0;

        for (j = 0; j < 16; j++)
            buf[j] = 0xaaaa;
        SetLastError(0xdeadbeef);
        ret = ToUnicodeEx('A', 0x1e, state, buf, cch[i], 0, hkl);
        if (cch[i] >= 1 && cch[i] <= 16)
        {
            ok(ret == 1, "cch %d: ret %d\n", cch[i], ret);
            ok(buf[0] == 'a', "cch %d: buf[0] %04x\n", cch[i], buf[0]);
            /* the whole buffer the caller gave is written: the character, then zeros */
            for (j = 0; j < 16; j++)
                if (buf[j] == 0)
                    zeros++;
            ok(zeros == cch[i] - 1, "cch %d: %d zeros\n", cch[i], zeros);
        }
        else if (cch[i] < 1)
        {
            ok(ret == 0, "cch %d: ret %d\n", cch[i], ret);
            ok(GetLastError() == ERROR_INVALID_PARAMETER, "cch %d: error %lu\n", cch[i], GetLastError());
        }
        else
        {
            ok(ret == 0, "cch %d: ret %d\n", cch[i], ret);
            ok(GetLastError() == ERROR_NOACCESS, "cch %d: error %lu\n", cch[i], GetLastError());
        }
    }
    VirtualFree(base, 0, MEM_RELEASE);
}

/* ---- a desktop handle without DESKTOP_HOOKCONTROL ---- */

static LRESULT CALLBACK NopProc(int code, WPARAM wp, LPARAM lp)
{
    return CallNextHookEx(NULL, code, wp, lp);
}

static char gDesktopName[256];

static DWORD WINAPI DesktopThread(LPVOID unused)
{
    static const DWORD access[2] =
    {
        DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW,
        DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_HOOKCONTROL
    };
    int pass;

    for (pass = 0; pass < 2; pass++)
    {
        HDESK hdesk = OpenDesktopA(gDesktopName, 0, FALSE, access[pass]);
        HHOOK hook;

        ok(hdesk != NULL, "pass %d: OpenDesktop failed, error %lu\n", pass, GetLastError());
        if (!hdesk)
            continue;
        ok(SetThreadDesktop(hdesk), "pass %d: SetThreadDesktop failed, error %lu\n", pass, GetLastError());

        SetLastError(0xdeadbeef);
        hook = SetWindowsHookExA(WH_GETMESSAGE, NopProc, GetModuleHandleA(NULL), GetCurrentThreadId());
        if (pass == 0)
        {
            ok(hook == NULL, "thread hook without DESKTOP_HOOKCONTROL succeeded\n");
            ok(GetLastError() == ERROR_ACCESS_DENIED, "error %lu\n", GetLastError());
        }
        else
        {
            ok(hook != NULL, "thread hook with DESKTOP_HOOKCONTROL failed, error %lu\n", GetLastError());
        }
        if (hook)
            UnhookWindowsHookEx(hook);

        SetLastError(0xdeadbeef);
        hook = SetWindowsHookExA(WH_KEYBOARD_LL, NopProc, GetModuleHandleA(NULL), 0);
        if (pass == 0)
        {
            ok(hook == NULL, "low-level hook without DESKTOP_HOOKCONTROL succeeded\n");
            ok(GetLastError() == ERROR_ACCESS_DENIED, "error %lu\n", GetLastError());
        }
        else
        {
            ok(hook != NULL, "low-level hook with DESKTOP_HOOKCONTROL failed, error %lu\n", GetLastError());
        }
        if (hook)
            UnhookWindowsHookEx(hook);
    }
    return 0;
}

static void test_hook_desktop_access(void)
{
    DWORD len;
    HANDLE t;

    gDesktopName[0] = 0;
    GetUserObjectInformationA(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, gDesktopName, sizeof(gDesktopName), &len);
    t = CreateThread(NULL, 0, DesktopThread, NULL, 0, NULL);
    WaitForSingleObject(t, 30000);
    CloseHandle(t);
}

/* ---- queued low-level hook call whose hook goes away before the thread runs it ---- */

static volatile LONG gHookCalls;

static LRESULT CALLBACK LLProc(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION)
        InterlockedIncrement(&gHookCalls);
    return CallNextHookEx(NULL, code, wp, lp);
}

static HANDLE ghHookInstalled, ghUnhooked, ghHookThreadDone;
static HHOOK ghHook;

static DWORD WINAPI HookThread(LPVOID unused)
{
    MSG msg;

    PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE);
    ghHook = SetWindowsHookExA(WH_KEYBOARD_LL, LLProc, GetModuleHandleA(NULL), 0);
    SetEvent(ghHookInstalled);
    /* not pumping: calls to the hook queue up for this thread */
    WaitForSingleObject(ghUnhooked, 20000);
    if (ghHook)
        UnhookWindowsHookEx(ghHook);
    /* now it runs whatever is still queued */
    for (;;)
    {
        DWORD r = MsgWaitForMultipleObjects(0, NULL, FALSE, 300, QS_ALLINPUT);
        if (r == WAIT_TIMEOUT)
            break;
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageA(&msg);
    }
    SetEvent(ghHookThreadDone);
    return 0;
}

static void test_queued_hook_outlives_unhook(void)
{
    HANDLE t;
    INPUT in[2];

    ghHookInstalled = CreateEventA(NULL, TRUE, FALSE, NULL);
    ghUnhooked = CreateEventA(NULL, TRUE, FALSE, NULL);
    ghHookThreadDone = CreateEventA(NULL, TRUE, FALSE, NULL);

    t = CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
    WaitForSingleObject(ghHookInstalled, 10000);
    if (!ghHook)
    {
        skip("cannot install a low-level hook here\n");
        SetEvent(ghUnhooked);
        WaitForSingleObject(t, 10000);
        goto done;
    }

    /* a key that does nothing (VK_NONAME release): the hook thread is not pumping, so the
       call is queued for it and times out for the sender */
    memset(in, 0, sizeof(in));
    in[0].type = INPUT_KEYBOARD; in[0].ki.wVk = 0xfc; in[0].ki.dwFlags = KEYEVENTF_KEYUP;
    in[1] = in[0];
    SendInput(2, in, sizeof(INPUT));

    /* the hook goes away while its calls are still queued */
    SetEvent(ghUnhooked);
    ok(WaitForSingleObject(ghHookThreadDone, 20000) == WAIT_OBJECT_0, "hook thread did not finish\n");
    WaitForSingleObject(t, 10000);

    /* and hooks still work afterwards */
    {
        HHOOK h = SetWindowsHookExA(WH_GETMESSAGE, (HOOKPROC)LLProc, GetModuleHandleA(NULL), GetCurrentThreadId());
        ok(h != NULL, "SetWindowsHookEx after the queued call: error %lu\n", GetLastError());
        if (h)
            ok(UnhookWindowsHookEx(h), "UnhookWindowsHookEx failed\n");
    }

done:
    CloseHandle(t);
    CloseHandle(ghHookInstalled);
    CloseHandle(ghUnhooked);
    CloseHandle(ghHookThreadDone);
}

START_TEST(HookInputBatch)
{
    test_rawinput_handles();
    test_attach_counted();
    test_tounicode_sizes();
    test_queued_hook_outlives_unhook();
    test_hook_desktop_access();
}
