/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     WM_GETDLGCODE, WM_NEXTDLGCTL and WM_PARENTNOTIFY reach win32k (SCROLLBAR and DefWindowProc
 *              windows) and come back with the right result and an untouched last error in every process
 *              flavour. A 32-bit process under WoW64 used to get -1 and ERROR_CALL_NOT_IMPLEMENTED.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static LRESULT CALLBACK DefProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void check_dlgcode(const char *cls, HWND hwnd, LRESULT expected)
{
    MSG msg = { hwnd, WM_KEYDOWN, VK_TAB, 0, 0, { 0, 0 } };
    LRESULT ret;

    SetLastError(0xDEADBEEF);
    ret = SendMessageA(hwnd, WM_GETDLGCODE, 0, 0);
    ok(ret == expected, "%s: WM_GETDLGCODE(A) returned %ld, expected %ld\n", cls, (long)ret, (long)expected);
    ok(GetLastError() == 0xDEADBEEF, "%s: WM_GETDLGCODE(A) set the last error to %lu\n", cls, GetLastError());

    SetLastError(0xDEADBEEF);
    ret = SendMessageW(hwnd, WM_GETDLGCODE, 0, 0);
    ok(ret == expected, "%s: WM_GETDLGCODE(W) returned %ld, expected %ld\n", cls, (long)ret, (long)expected);
    ok(GetLastError() == 0xDEADBEEF, "%s: WM_GETDLGCODE(W) set the last error to %lu\n", cls, GetLastError());

    /* with the MSG the dialog manager passes */
    SetLastError(0xDEADBEEF);
    ret = SendMessageW(hwnd, WM_GETDLGCODE, VK_TAB, (LPARAM)&msg);
    ok(ret != -1, "%s: WM_GETDLGCODE with a MSG returned -1\n", cls);
    ok(GetLastError() == 0xDEADBEEF, "%s: WM_GETDLGCODE with a MSG set the last error to %lu\n", cls, GetLastError());
    ok(msg.message == WM_KEYDOWN && msg.wParam == VK_TAB && msg.hwnd == hwnd, "%s: the MSG was changed\n", cls);
}

typedef struct
{
    HWND hwnd;
    LRESULT ret;
    DWORD error;
} THREADDATA;

static DWORD WINAPI send_thread(void *param)
{
    THREADDATA *data = param;

    SetLastError(0xDEADBEEF);
    data->ret = SendMessageW(data->hwnd, WM_GETDLGCODE, 0, 0);
    data->error = GetLastError();
    return 0;
}

START_TEST(WmGetDlgCode)
{
    WNDCLASSW wc = { 0 };
    HINSTANCE hinst = GetModuleHandleW(NULL);
    HWND frame, child, scroll;
    THREADDATA data;
    HANDLE thread;
    LRESULT ret;
    MSG msg;
    DWORD tid;
    static const struct { const char *cls; DWORD style; LRESULT expected; } classes[] =
    {
        { "SCROLLBAR", SBS_HORZ, DLGC_WANTARROWS },
        { "SCROLLBAR", SBS_VERT, DLGC_WANTARROWS },
        { "STATIC",    0,        DLGC_STATIC },
        { "LISTBOX",   LBS_STANDARD, DLGC_WANTCHARS | DLGC_WANTARROWS },
        { "COMBOBOX",  CBS_DROPDOWNLIST, DLGC_WANTCHARS | DLGC_WANTARROWS },
    };
    int i;

    wc.lpfnWndProc = DefProc;
    wc.hInstance = hinst;
    wc.lpszClassName = L"WmGetDlgCodeFrame";
    RegisterClassW(&wc);
    frame = CreateWindowExW(0, wc.lpszClassName, L"f", WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, NULL, NULL, hinst, NULL);
    ok(frame != NULL, "CreateWindowEx failed: %lu\n", GetLastError());
    if (!frame)
        return;

    for (i = 0; i < ARRAYSIZE(classes); i++)
    {
        child = CreateWindowExA(0, classes[i].cls, "x", WS_CHILD | classes[i].style, 0, 0, 50, 20, frame,
                                NULL, hinst, NULL);
        ok(child != NULL, "%s: CreateWindowEx failed: %lu\n", classes[i].cls, GetLastError());
        if (child)
        {
            check_dlgcode(classes[i].cls, child, classes[i].expected);
            DestroyWindow(child);
        }
    }

    /* the same through SendMessageTimeout, which always reaches win32k */
    for (i = 0; i < ARRAYSIZE(classes); i++)
    {
        DWORD_PTR res = 0xdead;

        child = CreateWindowExA(0, classes[i].cls, "x", WS_CHILD | classes[i].style, 0, 0, 50, 20, frame,
                                NULL, hinst, NULL);
        if (!child)
            continue;
        SetLastError(0xDEADBEEF);
        ret = SendMessageTimeoutW(child, WM_GETDLGCODE, 0, 0, SMTO_NORMAL, 5000, &res);
        ok(ret != 0, "%s: SendMessageTimeout(WM_GETDLGCODE) failed: %lu\n", classes[i].cls, GetLastError());
        ok(res == classes[i].expected, "%s: SendMessageTimeout(WM_GETDLGCODE) returned %ld, expected %ld\n",
           classes[i].cls, (long)res, (long)classes[i].expected);
        ok(GetLastError() == 0xDEADBEEF, "%s: SendMessageTimeout(WM_GETDLGCODE) set the last error to %lu\n",
           classes[i].cls, GetLastError());
        DestroyWindow(child);
    }

    /* a window procedure that hands everything to DefWindowProc */
    SetLastError(0xDEADBEEF);
    ret = SendMessageW(frame, WM_GETDLGCODE, 0, 0);
    ok(ret == 0, "DefWindowProc: WM_GETDLGCODE returned %ld\n", (long)ret);
    ok(GetLastError() == 0xDEADBEEF, "DefWindowProc: WM_GETDLGCODE set the last error to %lu\n", GetLastError());

    SetLastError(0xDEADBEEF);
    ret = SendMessageW(frame, WM_NEXTDLGCTL, 0, 0);
    ok(ret == 0, "DefWindowProc: WM_NEXTDLGCTL returned %ld\n", (long)ret);
    ok(GetLastError() == 0xDEADBEEF, "DefWindowProc: WM_NEXTDLGCTL set the last error to %lu\n", GetLastError());

    SetLastError(0xDEADBEEF);
    ret = SendMessageW(frame, WM_PARENTNOTIFY, WM_LBUTTONDOWN, MAKELPARAM(3, 4));
    ok(ret == 0, "DefWindowProc: WM_PARENTNOTIFY returned %ld\n", (long)ret);
    ok(GetLastError() == 0xDEADBEEF, "DefWindowProc: WM_PARENTNOTIFY set the last error to %lu\n", GetLastError());

    /* messages that carry a pointer in lParam, sent with NULL (nothing to translate): DefWindowProc handles them
       and leaves the last error alone, also in a 32-bit process under WoW64 */
    {
        static const UINT msgs[] =
        {
            WM_DELETEITEM, WM_COMPAREITEM, 0x124 /* WM_MENUGETOBJECT */, 0x164 /* CB_GETCOMBOBOXINFO */,
            0x218 /* WM_POWERBROADCAST */, 0x219 /* WM_DEVICECHANGE */, 0x22a, 0x22b, 0x22c, 0x22d, 0x22e, 0x22f
        };
        int j;
        DWORD_PTR res;

        for (j = 0; j < ARRAYSIZE(msgs); j++)
        {
            SetLastError(0xDEADBEEF);
            /* SendMessageTimeout always goes through win32k; SendMessage calls a same-thread procedure directly */
            ret = SendMessageTimeoutW(frame, msgs[j], 0, 0, SMTO_NORMAL, 5000, &res);
            ok(ret != 0, "DefWindowProc: message %#x with a NULL lParam failed: %lu\n", msgs[j], GetLastError());
            ok(GetLastError() == 0xDEADBEEF, "DefWindowProc: message %#x with a NULL lParam set the last error to %lu\n",
               msgs[j], GetLastError());
        }
    }

    /* the WM_PARENTNOTIFY that creating a child sends, with the child's handle in lParam */
    child = CreateWindowExA(0, "SCROLLBAR", "x", WS_CHILD, 0, 0, 50, 20, frame, NULL, hinst, NULL);
    ok(child != NULL, "CreateWindowEx failed: %lu\n", GetLastError());
    SetLastError(0xDEADBEEF);
    ret = SendMessageW(frame, WM_PARENTNOTIFY, MAKEWPARAM(WM_CREATE, 0), (LPARAM)child);
    ok(ret == 0, "DefWindowProc: WM_PARENTNOTIFY(WM_CREATE) returned %ld\n", (long)ret);
    ok(GetLastError() == 0xDEADBEEF, "WM_PARENTNOTIFY(WM_CREATE) set the last error to %lu\n", GetLastError());

    /* from another thread, no pointer */
    scroll = child;
    data.hwnd = scroll;
    data.ret = -2;
    data.error = 0;
    thread = CreateThread(NULL, 0, send_thread, &data, 0, &tid);
    ok(thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (thread)
    {
        while (MsgWaitForMultipleObjects(1, &thread, FALSE, 10000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
        {
            while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
                DispatchMessageW(&msg);
        }
        CloseHandle(thread);
        ok(data.ret == DLGC_WANTARROWS, "cross-thread WM_GETDLGCODE returned %ld\n", (long)data.ret);
        ok(data.error == 0xDEADBEEF, "cross-thread WM_GETDLGCODE set the last error to %lu\n", data.error);
    }

    DestroyWindow(child);
    DestroyWindow(frame);
    UnregisterClassW(wc.lpszClassName, hinst);
}
