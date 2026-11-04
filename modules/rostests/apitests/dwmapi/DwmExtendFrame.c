/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DwmExtendFrameIntoClientArea on a window of the calling process and of another one
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <dwmapi.h>

/*
 * ReactOS has no compositor: a window that asks for the whole frame to be glass (all four margins -1)
 * is marked through the private user32 export NitroSetWindowGlass, which makes win32k blend what is
 * drawn into it with its alpha channel. That changes how the pixels of the window are drawn, so a
 * process may do it to its own windows only. The mark is a property of the window that only win32k
 * reads, so it is checked through the answer of NitroSetWindowGlass (TRUE: done, FALSE: refused),
 * which comes from the same test in win32k. The export is not on Windows: the parts that need it are
 * skipped there.
 *
 * What Windows answers for a window of another process is not known: the Windows 10 22H2 test machine
 * runs without a desktop session and answers DWM_E_COMPOSITIONDISABLED (0x80263001) for every window,
 * its own as well. ReactOS keeps answering S_OK and leaves the window as it was.
 */
typedef HRESULT (WINAPI *PFN_DWMEXTEND)(HWND, const MARGINS *);
typedef HRESULT (WINAPI *PFN_DWMISCOMP)(BOOL *);
typedef BOOL (WINAPI *PFN_SETGLASS)(HWND, BOOL);

static const MARGINS Glass = { -1, -1, -1, -1 };
static const MARGINS NoGlass = { 0, 0, 0, 0 };

static
LRESULT
CALLBACK
WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static
HWND
MakeWindow(VOID)
{
    WNDCLASSW Class = { 0 };

    Class.lpfnWndProc = WndProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"DwmExtendFrameTest";
    RegisterClassW(&Class);
    return CreateWindowExW(0, Class.lpszClassName, L"glass", WS_OVERLAPPEDWINDOW, 0, 0, 200, 200,
                           NULL, NULL, Class.hInstance, NULL);
}

/* The child makes two windows, one of them glass already, and prints both handles */
static
VOID
RunChild(PFN_DWMEXTEND pExtend)
{
    HWND hGlass = MakeWindow(), hPlain = MakeWindow();
    MSG Msg;
    HRESULT hr;

    hr = pExtend(hGlass, &Glass);
    printf("%lx %lx %lx\n", (ULONG)(ULONG_PTR)hGlass, (ULONG)(ULONG_PTR)hPlain, (ULONG)hr);
    fflush(stdout);
    /* the parent ends the process */
    while (GetMessageW(&Msg, NULL, 0, 0) > 0)
        DispatchMessageW(&Msg);
}

START_TEST(DwmExtendFrame)
{
    PFN_DWMEXTEND pExtend;
    PFN_SETGLASS pSetGlass;
    SIZE_T Length;
    HMODULE hDwmapi;
    HWND hOwn, hGlass, hPlain;
    HRESULT hr;
    int argc;
    char **argv;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    HANDLE hRead, hWrite;
    STARTUPINFOA Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Info;
    char CommandLine[MAX_PATH + 40], Line[64] = "";
    DWORD Count;
    ULONG ChildGlass = 0, ChildPlain = 0, ChildHr = 0;

    hDwmapi = LoadLibraryW(L"dwmapi.dll");
    if (!hDwmapi)
    {
        skip("dwmapi.dll not available\n");
        return;
    }
    pExtend = (PFN_DWMEXTEND)GetProcAddress(hDwmapi, "DwmExtendFrameIntoClientArea");
    ok(pExtend != NULL, "DwmExtendFrameIntoClientArea is not exported\n");
    if (!pExtend)
        return;

    {
        BOOL Enabled = FALSE;
        PFN_DWMISCOMP pIsEnabled = (PFN_DWMISCOMP)GetProcAddress(hDwmapi, "DwmIsCompositionEnabled");

        if (pIsEnabled && (FAILED(pIsEnabled(&Enabled)) || !Enabled))
        {
            skip("Desktop composition is disabled\n");
            return;
        }
    }

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "child"))
    {
        RunChild(pExtend);
        return;
    }

    pSetGlass = (PFN_SETGLASS)GetProcAddress(GetModuleHandleW(L"user32.dll"), "NitroSetWindowGlass");
    if (!is_reactos() || !pSetGlass)
        pSetGlass = NULL;

    /* A window of this process */
    hOwn = MakeWindow();
    ok(hOwn != NULL, "CreateWindowEx failed with %lu\n", GetLastError());
    if (!hOwn)
        return;
    hr = pExtend(hOwn, &Glass);
    ok(hr == S_OK, "own window, glass: 0x%08lx\n", hr);
    hr = pExtend(hOwn, &NoGlass);
    ok(hr == S_OK, "own window, no glass: 0x%08lx\n", hr);
    if (pSetGlass)
    {
        ok(pSetGlass(hOwn, TRUE) == TRUE, "own window: NitroSetWindowGlass(TRUE) refused\n");
        ok(pSetGlass(hOwn, FALSE) == TRUE, "own window: NitroSetWindowGlass(FALSE) refused\n");
    }
    DestroyWindow(hOwn);

    /* A window of another process */
    if (!CreatePipe(&hRead, &hWrite, &Sa, 0))
    {
        skip("CreatePipe failed with %lu\n", GetLastError());
        return;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    sprintf(CommandLine, "\"%s\" DwmExtendFrame child", argv[0]);
    Startup.dwFlags = STARTF_USESTDHANDLES;
    Startup.hStdOutput = hWrite;
    Startup.hStdError = hWrite;
    Startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    if (!CreateProcessA(NULL, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &Startup, &Info))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        CloseHandle(hWrite);
        CloseHandle(hRead);
        return;
    }
    CloseHandle(hWrite);
    CloseHandle(Info.hThread);
    /* the line may arrive in pieces */
    Length = 0;
    while (Length < sizeof(Line) - 1 && !strchr(Line, '\n') &&
           ReadFile(hRead, Line + Length, sizeof(Line) - 1 - Length, &Count, NULL) && Count)
    {
        Length += Count;
        Line[Length] = 0;
    }
    CloseHandle(hRead);
    if (sscanf(Line, "%lx %lx %lx", &ChildGlass, &ChildPlain, &ChildHr) != 3)
    {
        skip("The child process did not report its windows: '%s'\n", Line);
        TerminateProcess(Info.hProcess, 0);
        CloseHandle(Info.hProcess);
        return;
    }
    hGlass = (HWND)(ULONG_PTR)ChildGlass;
    hPlain = (HWND)(ULONG_PTR)ChildPlain;
    ok(IsWindow(hGlass) && IsWindow(hPlain), "the windows of the child are not there\n");
    ok(ChildHr == S_OK, "the child's own window, glass: 0x%08lx\n", ChildHr);

    /* A window of another process cannot be made glass, ... */
    hr = pExtend(hPlain, &Glass);
    if (is_reactos())
        ok(hr == S_OK, "foreign window, glass: 0x%08lx\n", hr);
    if (pSetGlass)
    {
        SetLastError(0xdeadbeef);
        ok(pSetGlass(hPlain, TRUE) == FALSE, "a window of another process was made glass\n");
    }

    /* ...and its glass cannot be taken away */
    hr = pExtend(hGlass, &NoGlass);
    if (is_reactos())
        ok(hr == S_OK, "foreign window, no glass: 0x%08lx\n", hr);
    if (pSetGlass)
        ok(pSetGlass(hGlass, FALSE) == FALSE, "the glass of a window of another process was taken away\n");

    TerminateProcess(Info.hProcess, 0);
    CloseHandle(Info.hProcess);
}
