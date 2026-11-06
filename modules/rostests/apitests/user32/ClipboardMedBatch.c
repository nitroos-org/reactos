/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Clipboard hardening batch (G6): GetPriorityClipboardFormat with counts that run off the
 *              list, delayed rendering answered by the thread that asks for the data
 *              The expected results are the ones Windows 10 gives.
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

static HWND hwnd;

static void test_priority_counts(void)
{
    SYSTEM_INFO si;
    BYTE *base;
    UINT *list;
    HGLOBAL hg;
    char *p;
    int ret, i;
    static const int bad[] = { 5, -1, 0x7fffffff, (int)0x80000000 };

    GetSystemInfo(&si);
    base = VirtualAlloc(NULL, 2 * si.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(base != NULL, "VirtualAlloc failed\n");
    if (!base)
        return;
    VirtualProtect(base + si.dwPageSize, si.dwPageSize, PAGE_NOACCESS, &(DWORD){0});
    list = (UINT *)(base + si.dwPageSize - 4 * sizeof(UINT));
    list[0] = CF_WAVE; list[1] = CF_RIFF; list[2] = CF_PENDATA; list[3] = CF_SYLK;

    ok(OpenClipboard(hwnd), "OpenClipboard failed\n");
    EmptyClipboard();
    hg = GlobalAlloc(GMEM_MOVEABLE, 8);
    p = GlobalLock(hg);
    strcpy(p, "x");
    GlobalUnlock(hg);
    ok(SetClipboardData(CF_TEXT, hg) != NULL, "SetClipboardData(CF_TEXT) failed\n");
    CloseClipboard();

    ret = GetPriorityClipboardFormat(list, 4);
    ok(ret == -1, "no format of the list: %d\n", ret);
    ret = GetPriorityClipboardFormat(list, 0);
    ok(ret == -1, "empty list: %d\n", ret);

    /* counts that run off the list, or are not counts: no result, ERROR_NOACCESS */
    for (i = 0; i < ARRAYSIZE(bad); i++)
    {
        SetLastError(0xdeadbeef);
        ret = GetPriorityClipboardFormat(list, bad[i]);
        ok(ret == 0, "count %d: %d\n", bad[i], ret);
        ok(GetLastError() == ERROR_NOACCESS, "count %d: error %lu\n", bad[i], GetLastError());
    }

    /* a count that would wrap a 32-bit byte count: a 64-bit kernel reads the list only as far as the match
       (a 32-bit one has no room for such a list) */
    list[0] = CF_TEXT;
    if (sizeof(void *) == 8 || IsWow64())
    {
        ret = GetPriorityClipboardFormat(list, 0x40000001);
        ok(ret == CF_TEXT, "first entry matches: %d\n", ret);
    }

    OpenClipboard(hwnd);
    EmptyClipboard();
    CloseClipboard();
    VirtualFree(base, 0, MEM_RELEASE);
}


/* ---- delayed rendering in the thread that asks for the data ---- */

static BOOL gRendered;

static LRESULT CALLBACK RenderProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_RENDERFORMAT && wp == CF_TEXT)
    {
        HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, 16);
        char *p = GlobalLock(hg);

        strcpy(p, "rendered");
        GlobalUnlock(hg);
        /* the handler does not open the clipboard: the thread that asked has it open */
        gRendered = SetClipboardData(CF_TEXT, hg) != NULL;
        return 0;
    }
    return DefWindowProcA(h, msg, wp, lp);
}

static DWORD WINAPI RenderThread(LPVOID unused)
{
    WNDCLASSA wc = { 0 };
    HWND hwndOwner;
    HANDLE h;
    char *p;

    wc.lpfnWndProc = RenderProc;
    wc.lpszClassName = "g6render";
    wc.hInstance = GetModuleHandleA(NULL);
    RegisterClassA(&wc);
    hwndOwner = CreateWindowExA(0, "g6render", "r", 0, 0, 0, 1, 1, HWND_MESSAGE, NULL, wc.hInstance, NULL);

    ok(OpenClipboard(hwndOwner), "OpenClipboard failed\n");
    EmptyClipboard();
    ok(SetClipboardData(CF_TEXT, NULL) == NULL, "delayed SetClipboardData\n");
    CloseClipboard();

    ok(OpenClipboard(hwndOwner), "OpenClipboard failed\n");
    h = GetClipboardData(CF_TEXT);
    ok(gRendered, "WM_RENDERFORMAT handler could not set the data\n");
    ok(h != NULL, "GetClipboardData returned NULL\n");
    p = h ? GlobalLock(h) : NULL;
    ok(p && !strcmp(p, "rendered"), "data %s\n", p ? p : "(null)");
    if (p)
        GlobalUnlock(h);
    EmptyClipboard();
    CloseClipboard();
    DestroyWindow(hwndOwner);
    UnregisterClassA("g6render", wc.hInstance);
    return 0;
}

static void test_delayed_render(void)
{
    HANDLE t = CreateThread(NULL, 0, RenderThread, NULL, 0, NULL);

    /* a deadlock in the render path must fail the test, not hang it */
    if (WaitForSingleObject(t, 30000) != WAIT_OBJECT_0)
    {
        ok(0, "delayed rendering did not finish (deadlock)\n");
        TerminateThread(t, 0);
    }
    CloseHandle(t);
}

START_TEST(ClipboardMedBatch)
{
    hwnd = CreateWindowExA(0, "STATIC", "clip", 0, 0, 0, 1, 1, HWND_MESSAGE, NULL, GetModuleHandleA(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowEx failed\n");
    if (!hwnd)
        return;

    /* first: the previous clipboard owner of a thread that does not pump would be sent WM_DESTROYCLIPBOARD */
    test_delayed_render();
    test_priority_counts();

    DestroyWindow(hwnd);
}
