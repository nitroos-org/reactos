/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         An in-context WinEvent hook aimed at another process: its DLL is loaded there and
 *                  the process goes on creating and destroying windows
 */

#include "precomp.h"
#include <tlhelp32.h>

static void widen(const char *src, WCHAR *dst, int max)
{
    int i;

    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
}

#define CHILD_CLASS L"WevCtxChild"
#define CMD_DOIT    (WM_APP + 1)  /* create and destroy a window; answers 1 */
#define CMD_STATE   (WM_APP + 2)  /* bit0: the hook DLL is loaded here; the rest: its event count */

typedef LONG (WINAPI *WEVGETCOUNT)(VOID);

static LRESULT CALLBACK ChildProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == CMD_DOIT)
    {
        HWND w = CreateWindowExW(0, L"STATIC", L"wev", WS_POPUP, 0, 0, 5, 5, NULL, NULL, GetModuleHandleW(NULL), NULL);
        if (!w)
            return 0;
        DestroyWindow(w);
        return 1;
    }
    if (msg == CMD_STATE)
    {
        HMODULE mod = GetModuleHandleW(L"user32_wevhook1.dll");
        WEVGETCOUNT get = mod ? (WEVGETCOUNT)GetProcAddress(mod, "WevGetCount") : NULL;
        return mod ? (1 | ((LRESULT)(get ? get() : 0) << 1)) : 0;
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

/* the id of csrss.exe, 0 if it cannot be found */
static DWORD find_process(const WCHAR *name)
{
    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;

    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (!lstrcmpiW(pe.szExeFile, name)) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* csrss raises events too (it owns the console windows), and the hook procedure would run, and the DLL load,
   in it. Windows never loads a hook DLL into csrss. */
static void test_not_in_csrss(void)
{
    HMODULE mod = LoadLibraryW(L"user32_wevhooklog.dll");
    FARPROC proc = mod ? GetProcAddress(mod, "WevHookProc") : NULL;
    WCHAR LogPath[MAX_PATH], *p;
    WCHAR Cmd[] = L"cmd.exe /c exit";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HWINEVENTHOOK hook;
    DWORD csrss = find_process(L"csrss.exe"), loaded_here;
    char buf[4096];
    HANDLE f;
    DWORD got = 0, n = 0;
    BOOL csrss_loaded = FALSE;

    if (!proc)
    {
        skip("user32_wevhooklog.dll is not available (%lu)\n", GetLastError());
        return;
    }
    if (!csrss)
    {
        skip("csrss.exe not found\n");
        FreeLibrary(mod);
        return;
    }
    GetModuleFileNameW(mod, LogPath, MAX_PATH);
    p = LogPath + lstrlenW(LogPath);
    while (p > LogPath && p[-1] != L'\\')
        p--;
    lstrcpyW(p, L"user32_wevhook.log");
    DeleteFileW(LogPath);

    hook = SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_DESTROY, mod, (WINEVENTPROC)proc, 0, 0, WINEVENT_INCONTEXT);
    ok(hook != NULL, "SetWinEventHook failed: %lu\n", GetLastError());
    if (!hook)
    {
        FreeLibrary(mod);
        return;
    }

    /* a new console: csrss creates and destroys its window */
    if (CreateProcessW(NULL, Cmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Sleep(500);
    }
    else
        skip("cannot start cmd.exe: %lu\n", GetLastError());
    UnhookWinEvent(hook);

    f = CreateFileW(LogPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f != INVALID_HANDLE_VALUE)
    {
        if (ReadFile(f, buf, sizeof(buf) - 1, &got, NULL))
        {
            char *line;

            buf[got] = 0;
            for (line = strtok(buf, "\r\n"); line; line = strtok(NULL, "\r\n"))
                if ((DWORD)strtoul(line, NULL, 10) == csrss)
                    csrss_loaded = TRUE;
        }
        CloseHandle(f);
        DeleteFileW(LogPath);
    }
    (void)n; (void)loaded_here;
    ok(!csrss_loaded, "the in-context hook DLL was loaded into csrss.exe (%lu)\n", csrss);
    FreeLibrary(mod);
}

START_TEST(WinEventInContext)
{
    char **argv;
    int argc;
    CHAR Path[MAX_PATH], CmdLine[MAX_PATH + 100], Title[64];
    WCHAR wTitle[64];
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HWND child = NULL;
    DWORD Start;
    HMODULE mod;
    FARPROC proc;
    HWINEVENTHOOK hook;
    DWORD_PTR res = 0;
    int i;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        ChildProcess(argv[3]);
        return;
    }

    mod = LoadLibraryW(L"user32_wevhook1.dll");
    if (!mod)
    {
        skip("user32_wevhook1.dll is not available (%lu)\n", GetLastError());
        return;
    }
    proc = GetProcAddress(mod, "WevHookProc");
    ok(proc != NULL, "WevHookProc not found\n");
    if (!proc)
        return;

    GetModuleFileNameA(NULL, Path, ARRAYSIZE(Path));
    sprintf(Title, "WevCtxChild_%lu", GetCurrentProcessId());
    sprintf(CmdLine, "\"%s\" WinEventInContext child %s", Path, Title);
    widen(Title, wTitle, ARRAYSIZE(wTitle));
    if (!CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        return;
    }
    Start = GetTickCount();
    while (!child && GetTickCount() - Start < 15000)
    {
        child = FindWindowW(CHILD_CLASS, wTitle);
        if (!child)
            Sleep(20);
    }
    ok(child != NULL, "the child window was not found\n");
    if (child)
    {
        ok(SendMessageTimeoutW(child, CMD_STATE, 0, 0, SMTO_NORMAL, 5000, &res) && res == 0,
           "the hook DLL is loaded in the child before the hook is set: %Ix\n", res);

        hook = SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_DESTROY, mod, (WINEVENTPROC)proc,
                               pi.dwProcessId, 0, WINEVENT_INCONTEXT);
        ok(hook != NULL, "SetWinEventHook failed: %lu\n", GetLastError());

        /* the child creates windows while the hook is aimed at it: it must neither hang nor fail */
        for (i = 0; i < 3; i++)
        {
            res = 0;
            SetLastError(0);
            ok(SendMessageTimeoutW(child, CMD_DOIT, 0, 0, SMTO_NORMAL, 15000, &res) && res == 1,
               "the child did not create and destroy a window (round %d, result %Ix, error %lu)\n", i, res, GetLastError());
        }
        res = 0;
        ok(SendMessageTimeoutW(child, CMD_STATE, 0, 0, SMTO_NORMAL, 5000, &res), "the child does not answer\n");
        ok((res & 1) != 0, "the hook DLL was not loaded into the child\n");
        ok((res >> 1) >= 2, "the hook procedure ran %Id times in the child\n", (LONG_PTR)(res >> 1));

        if (hook)
            ok(UnhookWinEvent(hook), "UnhookWinEvent failed: %lu\n", GetLastError());
        ok(SendMessageTimeoutW(child, CMD_DOIT, 0, 0, SMTO_NORMAL, 15000, &res) && res == 1,
           "the child does not create windows after the hook is gone\n");
    }
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    test_not_in_csrss();
    FreeLibrary(mod);
}
