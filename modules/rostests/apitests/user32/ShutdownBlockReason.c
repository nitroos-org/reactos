/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy and ShutdownBlockReasonQuery
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results were measured on Windows 10 22H2 (x64 and x86). A window of another process (the desktop window
 * is one) is answered with 5, the value of ERROR_ACCESS_DENIED, as the return value and no error.
 */

#include "precomp.h"

typedef BOOL (WINAPI *PFN_Create)(HWND, LPCWSTR);
typedef BOOL (WINAPI *PFN_Destroy)(HWND);
typedef BOOL (WINAPI *PFN_Query)(HWND, LPWSTR, DWORD *);

#define PENDING_ERROR 0xdeadbeef

static PFN_Create pCreate;
static PFN_Destroy pDestroy;
static PFN_Query pQuery;

static HANDLE g_Ready, g_Stop;
static HWND g_OtherThreadWindow;

static DWORD WINAPI ThreadProc(PVOID Param)
{
    g_OtherThreadWindow = CreateWindowExW(0, L"STATIC", L"other", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    SetEvent(g_Ready);
    WaitForSingleObject(g_Stop, 20000);
    DestroyWindow(g_OtherThreadWindow);
    return 0;
}

/* BufChars is the size given in characters, UseBuffer tells whether there is a buffer */
#define QUERY(Label, Wnd, UseBuffer, BufChars, ExpResult, ExpError, ExpOut, ExpText) \
    do { \
        WCHAR Buf_[600]; \
        DWORD Chars_ = (BufChars), Err_; \
        BOOL Res_; \
        FillMemory(Buf_, sizeof(Buf_), 0xAA); \
        SetLastError(PENDING_ERROR); \
        Res_ = pQuery(Wnd, (UseBuffer) ? Buf_ : NULL, &Chars_); \
        Err_ = GetLastError(); \
        ok(Res_ == (ExpResult), "%s: Query returned %d\n", Label, Res_); \
        ok(Err_ == (ExpError), "%s: Query: last error %lu, expected %lu\n", Label, Err_, (DWORD)(ExpError)); \
        ok(Chars_ == (ExpOut), "%s: Query: size became %lu, expected %lu\n", Label, Chars_, (DWORD)(ExpOut)); \
        if ((ExpText) && (UseBuffer)) \
            ok(wcscmp(Buf_, (ExpText)) == 0, "%s: Query: text '%ls', expected '%ls'\n", Label, Buf_, (PCWSTR)(ExpText)); \
    } while (0)

#define CREATE(Label, Wnd, Text, ExpResult, ExpError) \
    do { \
        BOOL Res_; \
        DWORD Err_; \
        SetLastError(PENDING_ERROR); \
        Res_ = pCreate(Wnd, Text); \
        Err_ = GetLastError(); \
        ok(Res_ == (ExpResult), "%s: Create returned %d, expected %d\n", Label, Res_, (BOOL)(ExpResult)); \
        ok(Err_ == (ExpError), "%s: Create: last error %lu, expected %lu\n", Label, Err_, (DWORD)(ExpError)); \
    } while (0)

#define DESTROY(Label, Wnd, ExpResult, ExpError) \
    do { \
        BOOL Res_; \
        DWORD Err_; \
        SetLastError(PENDING_ERROR); \
        Res_ = pDestroy(Wnd); \
        Err_ = GetLastError(); \
        ok(Res_ == (ExpResult), "%s: Destroy returned %d, expected %d\n", Label, Res_, (BOOL)(ExpResult)); \
        ok(Err_ == (ExpError), "%s: Destroy: last error %lu, expected %lu\n", Label, Err_, (DWORD)(ExpError)); \
    } while (0)

START_TEST(ShutdownBlockReason)
{
    HMODULE User32 = GetModuleHandleW(L"user32.dll");
    HWND Top, Child, Other, Long, Desktop;
    HANDLE Thread;
    WCHAR Text[300];
    DWORD Needed;
    int i;

    pCreate = (PFN_Create)GetProcAddress(User32, "ShutdownBlockReasonCreate");
    pDestroy = (PFN_Destroy)GetProcAddress(User32, "ShutdownBlockReasonDestroy");
    pQuery = (PFN_Query)GetProcAddress(User32, "ShutdownBlockReasonQuery");
    if (!pCreate || !pDestroy || !pQuery)
    {
        skip("the shutdown block reason functions are not exported\n");
        return;
    }

    GetSystemMetrics(SM_CXSCREEN);
    Top = CreateWindowExW(0, L"STATIC", L"top", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    Child = CreateWindowExW(0, L"STATIC", L"child", WS_CHILD, 0, 0, 10, 10, Top, NULL, NULL, NULL);
    Long = CreateWindowExW(0, L"STATIC", L"long", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    Desktop = GetDesktopWindow();
    ok(Top && Child && Long, "the windows were not created\n");

    /* no reason yet */
    QUERY("no reason", Top, TRUE, 100, FALSE, ERROR_INVALID_PARAMETER, 100, NULL);
    QUERY("no reason, no size", Top, TRUE, 0, FALSE, ERROR_INVALID_PARAMETER, 0, NULL);
    QUERY("no reason, no buffer", Top, FALSE, 0, FALSE, ERROR_INVALID_PARAMETER, 0, NULL);
    QUERY("NULL window", NULL, TRUE, 100, FALSE, ERROR_INVALID_WINDOW_HANDLE, 100, NULL);
    QUERY("bad window", (HWND)(ULONG_PTR)0x12345, TRUE, 100, FALSE, ERROR_INVALID_WINDOW_HANDLE, 100, NULL);
    SetLastError(PENDING_ERROR);
    ok(pQuery(Top, NULL, NULL) == FALSE, "Query without a size succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "Query without a size: last error %lu\n", GetLastError());
    DESTROY("no reason", Top, FALSE, ERROR_INVALID_PARAMETER);
    DESTROY("NULL window", NULL, FALSE, ERROR_INVALID_WINDOW_HANDLE);

    /* create, and what the query gives for every buffer size */
    CREATE("create", Top, L"Saving your work", TRUE, PENDING_ERROR);
    QUERY("reason", Top, TRUE, 100, TRUE, PENDING_ERROR, 17, L"Saving your work");
    QUERY("exact size", Top, TRUE, 17, TRUE, PENDING_ERROR, 17, L"Saving your work");
    QUERY("one short", Top, TRUE, 16, TRUE, PENDING_ERROR, 17, L"Saving your wor");
    QUERY("five", Top, TRUE, 5, TRUE, PENDING_ERROR, 17, L"Savi");
    QUERY("one", Top, TRUE, 1, TRUE, PENDING_ERROR, 17, L"");
    QUERY("zero", Top, TRUE, 0, FALSE, ERROR_INVALID_PARAMETER, 0, NULL);
    QUERY("no buffer", Top, FALSE, 100, TRUE, PENDING_ERROR, 17, NULL);
    QUERY("no buffer, no size", Top, FALSE, 0, TRUE, PENDING_ERROR, 17, NULL);
    QUERY("child", Child, TRUE, 100, FALSE, ERROR_INVALID_PARAMETER, 100, NULL);

    /* a new reason replaces the old one; empty is a reason, NULL is not */
    CREATE("second", Top, L"Second reason", TRUE, PENDING_ERROR);
    QUERY("second", Top, TRUE, 100, TRUE, PENDING_ERROR, 14, L"Second reason");
    CREATE("empty", Top, L"", TRUE, PENDING_ERROR);
    QUERY("empty", Top, TRUE, 100, TRUE, PENDING_ERROR, 1, L"");
    CREATE("keep", Top, L"kept", TRUE, PENDING_ERROR);
    CREATE("NULL reason", Top, NULL, FALSE, ERROR_INVALID_PARAMETER);
    QUERY("after NULL", Top, TRUE, 100, TRUE, PENDING_ERROR, 5, L"kept");
    CREATE("NULL window", NULL, L"x", FALSE, ERROR_INVALID_WINDOW_HANDLE);
    CREATE("bad window", (HWND)(ULONG_PTR)0x12345, L"x", FALSE, ERROR_INVALID_WINDOW_HANDLE);
    CREATE("child", Child, L"child reason", FALSE, ERROR_INVALID_PARAMETER);
    QUERY("child after", Child, TRUE, 100, FALSE, ERROR_INVALID_PARAMETER, 100, NULL);

    /* the reason of another window is not this one */
    CREATE("long window", Long, L"long window reason", TRUE, PENDING_ERROR);
    QUERY("long window", Long, TRUE, 100, TRUE, PENDING_ERROR, 19, L"long window reason");
    QUERY("top still", Top, TRUE, 100, TRUE, PENDING_ERROR, 5, L"kept");

    /* the longest reason has 256 characters */
    for (i = 0; i < 300; i++)
        Text[i] = L'a' + (i % 26);
    Text[256] = 0;
    CREATE("256 characters", Long, Text, TRUE, PENDING_ERROR);
    {
        WCHAR Buf[600];

        Needed = 600;
        ok(pQuery(Long, Buf, &Needed), "Query of the long reason failed\n");
        ok(Needed == 257, "the long reason has size %lu\n", Needed);
        ok(wcscmp(Buf, Text) == 0, "the long reason was changed\n");
    }
    Text[257] = 0;
    Text[256] = L'z';
    CREATE("257 characters", Long, Text, FALSE, ERROR_INVALID_PARAMETER);
    Text[256] = 0;
    QUERY("257 refused, 256 stays", Long, FALSE, 0, TRUE, PENDING_ERROR, 257, NULL);

    /* another thread's window is fine; the desktop window belongs to another process */
    g_Ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
    if (Thread && WaitForSingleObject(g_Ready, 10000) == WAIT_OBJECT_0)
    {
        Other = g_OtherThreadWindow;
        CREATE("other thread", Other, L"other thread", TRUE, PENDING_ERROR);
        QUERY("other thread", Other, TRUE, 100, TRUE, PENDING_ERROR, 13, L"other thread");
        DESTROY("other thread", Other, TRUE, PENDING_ERROR);
        SetEvent(g_Stop);
        WaitForSingleObject(Thread, 10000);
    }
    else
    {
        skip("the thread did not start\n");
        SetEvent(g_Stop);
    }
    if (Thread)
        CloseHandle(Thread);
    CloseHandle(g_Ready);
    CloseHandle(g_Stop);

    CREATE("desktop window", Desktop, L"x", (BOOL)ERROR_ACCESS_DENIED, PENDING_ERROR);
    DESTROY("desktop window", Desktop, (BOOL)ERROR_ACCESS_DENIED, PENDING_ERROR);
    QUERY("desktop window", Desktop, TRUE, 100, FALSE, ERROR_INVALID_PARAMETER, 100, NULL);

    /* destroy ends the reason; a destroyed window has none and is an invalid window */
    DESTROY("destroy", Top, TRUE, PENDING_ERROR);
    QUERY("after destroy", Top, TRUE, 100, FALSE, ERROR_INVALID_PARAMETER, 100, NULL);
    DESTROY("destroy again", Top, FALSE, ERROR_INVALID_PARAMETER);

    CREATE("to be destroyed", Long, L"gone", TRUE, PENDING_ERROR);
    DestroyWindow(Long);
    QUERY("destroyed window", Long, TRUE, 100, FALSE, ERROR_INVALID_WINDOW_HANDLE, 100, NULL);

    /* windows made later do not inherit the reason of a destroyed one */
    for (i = 0; i < 20; i++)
    {
        HWND Fresh = CreateWindowExW(0, L"STATIC", L"fresh", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10, NULL, NULL, NULL, NULL);

        QUERY("fresh window", Fresh, TRUE, 100, FALSE, ERROR_INVALID_PARAMETER, 100, NULL);
        pCreate(Fresh, L"temporary");
        DestroyWindow(Fresh);
    }

    DestroyWindow(Top);
}
