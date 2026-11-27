/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that a service in session 0 can draw on and read back its screen DCs and a window
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A service has no console: its desktop is never the input desktop and the display it sees is a memory display that
 * no monitor shows. Its screen DCs must work all the same (GetDC(NULL), GetWindowDC and GetDC of the desktop window,
 * CreateDC("DISPLAY"): BitBlt into a memory bitmap, GetPixel, FillRect and the readback of what was drawn, and a window
 * with a paint). Windows row: not recorded here, verify on the Windows reference (the exact check is what this file does
 * as LocalSystem, SERVICE_WIN32_OWN_PROCESS, started by the test). The checks are what this system did before the
 * screen DC change of 2026-11-26 broke services, which the screen tests (they run as a user on the console) did not see.
 */

#include "precomp.h"
#include <wingdi.h>
#include <winuser.h>

#include "svchlp.h"

#define PAINT_COLOR   RGB(255, 0, 255)
#define WINDOW_COLOR  RGB(0, 200, 40)
#define SIZE          64

/*** Service part of the test ***/

static SERVICE_STATUS_HANDLE status_handle;

static void
report_service_status(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
    SERVICE_STATUS status;
    BOOL res;

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = dwCurrentState;
    status.dwWin32ExitCode = dwWin32ExitCode;
    status.dwWaitHint = dwWaitHint;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    if (dwCurrentState == SERVICE_START_PENDING || dwCurrentState == SERVICE_STOP_PENDING ||
        dwCurrentState == SERVICE_STOPPED)
        status.dwControlsAccepted = 0;
    else
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    res = SetServiceStatus(status_handle, &status);
    service_ok(res, "SetServiceStatus(%lu) failed: %lu\n", dwCurrentState, GetLastError());
}

static VOID WINAPI
service_handler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN)
        report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 0);
    else
        report_service_status(SERVICE_RUNNING, NO_ERROR, 0);
}

/* BitBlt of the DC into a memory bitmap: the call works, and the bitmap holds what GetPixel of the DC reads back */
static void
check_capture(PCSTR Name, HDC hDC)
{
    HDC hMem;
    HBITMAP hBitmap, hOld;
    BOOL Ok;
    DWORD Error = 0;
    COLORREF Direct, Copy;

    hMem = CreateCompatibleDC(hDC);
    hBitmap = CreateCompatibleBitmap(hDC, SIZE, SIZE);
    service_ok(hMem && hBitmap, "%s: no compatible DC or bitmap (%lu)\n", Name, GetLastError());
    if (!hMem || !hBitmap)
    {
        if (hBitmap)
            DeleteObject(hBitmap);
        if (hMem)
            DeleteDC(hMem);
        return;
    }
    hOld = SelectObject(hMem, hBitmap);
    PatBlt(hMem, 0, 0, SIZE, SIZE, WHITENESS);

    SetLastError(0);
    Ok = BitBlt(hMem, 0, 0, SIZE, SIZE, hDC, 0, 0, SRCCOPY);
    if (!Ok)
        Error = GetLastError();
    service_ok(Ok, "%s: BitBlt from the screen DC failed: %lu\n", Name, Error);

    Direct = GetPixel(hDC, 5, 5);
    Copy = GetPixel(hMem, 5, 5);
    service_ok(Direct != CLR_INVALID, "%s: GetPixel of the screen DC returned CLR_INVALID\n", Name);
    service_ok(Ok && Copy == Direct, "%s: the copy reads %08lx, the screen DC %08lx\n", Name, Copy, Direct);

    SelectObject(hMem, hOld);
    DeleteObject(hBitmap);
    DeleteDC(hMem);
}

/* FillRect on the DC and the readback of the same pixels */
static void
check_fill(PCSTR Name, HDC hDC)
{
    HBRUSH hBrush = CreateSolidBrush(PAINT_COLOR);
    RECT Rect = { 100, 100, 140, 140 };
    COLORREF Read;
    int Result;

    Result = FillRect(hDC, &Rect, hBrush);
    GdiFlush();
    service_ok(Result != 0, "%s: FillRect failed: %lu\n", Name, GetLastError());
    Read = GetPixel(hDC, 110, 110);
    service_ok(Read == PAINT_COLOR, "%s: FillRect drew %08lx, the readback is %08lx\n", Name, PAINT_COLOR, Read);
    DeleteObject(hBrush);
}

static int g_Painted;

static LRESULT CALLBACK
window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (Msg == WM_PAINT)
    {
        PAINTSTRUCT Paint;
        HDC hDC = BeginPaint(hWnd, &Paint);
        HBRUSH hBrush = CreateSolidBrush(WINDOW_COLOR);
        RECT Rect;

        GetClientRect(hWnd, &Rect);
        FillRect(hDC, &Rect, hBrush);
        DeleteObject(hBrush);
        EndPaint(hWnd, &Paint);
        g_Painted++;
        return 0;
    }
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

/* A window with a paint. A window of a service's desktop is not visible (IsWindowVisible is FALSE), and whether it
 * gets WM_PAINT differs between the builds this was written on (amd64 Release: yes; i386 Debug: never, on the
 * revision before and after the screen DC change alike): the paint is checked when it came, the DC of the window
 * is checked in every case. Whether Windows paints such a window: verify on the Windows reference. */
static void
check_window(void)
{
    WNDCLASSW Class;
    HWND hWnd;
    HDC hDC;
    COLORREF Read;
    MSG Msg;
    int i;

    ZeroMemory(&Class, sizeof(Class));
    Class.lpfnWndProc = window_proc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"ServiceScreenDCWindow";
    service_ok(RegisterClassW(&Class) != 0, "RegisterClass failed: %lu\n", GetLastError());

    hWnd = CreateWindowExW(0, Class.lpszClassName, L"ServiceScreenDC", WS_POPUP | WS_VISIBLE, 200, 200, SIZE, SIZE,
                           NULL, NULL, Class.hInstance, NULL);
    service_ok(hWnd != NULL, "CreateWindowEx failed: %lu\n", GetLastError());
    if (!hWnd)
        return;

    UpdateWindow(hWnd);
    for (i = 0; i < 100 && PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE); i++)
        DispatchMessageW(&Msg);

    hDC = GetDC(hWnd);
    service_ok(hDC != NULL, "GetDC of the window failed: %lu\n", GetLastError());
    if (hDC)
    {
        Read = GetPixel(hDC, SIZE / 2, SIZE / 2);
        service_trace("window: visible %d, WM_PAINT count %d, GetPixel %08lx\n", IsWindowVisible(hWnd), g_Painted, Read);
        if (g_Painted)
        {
            service_ok(Read == WINDOW_COLOR, "window paint: expected %08lx, GetPixel of the window DC reads %08lx\n",
                       WINDOW_COLOR, Read);
        }
        else
        {
            service_ok(Read != CLR_INVALID, "window DC: GetPixel returned CLR_INVALID\n");
        }
        check_capture("window DC", hDC);
        ReleaseDC(hWnd, hDC);
    }
    DestroyWindow(hWnd);
    UnregisterClassW(Class.lpszClassName, Class.hInstance);
}

static void WINAPI
service_main(DWORD dwArgc, LPWSTR *lpszArgv)
{
    static const PCSTR Names[4] = { "GetDC(NULL)", "GetWindowDC(desktop)", "GetDC(desktop)", "CreateDC(DISPLAY)" };
    HDC hDC[4];
    DWORD Session = 99;
    int i;

    UNREFERENCED_PARAMETER(dwArgc);

    status_handle = RegisterServiceCtrlHandlerW(lpszArgv[0], service_handler);
    service_ok(status_handle != NULL, "RegisterServiceCtrlHandler failed: %lu\n", GetLastError());
    if (!status_handle)
        return;
    report_service_status(SERVICE_RUNNING, NO_ERROR, 4000);

    service_ok(ProcessIdToSessionId(GetCurrentProcessId(), &Session) && Session == 0, "the service runs in session %lu\n", Session);

    hDC[0] = GetDC(NULL);
    hDC[1] = GetWindowDC(GetDesktopWindow());
    hDC[2] = GetDC(GetDesktopWindow());
    hDC[3] = CreateDCW(L"DISPLAY", NULL, NULL, NULL);
    for (i = 0; i < 4; i++)
    {
        service_ok(hDC[i] != NULL, "%s: no DC (%lu)\n", Names[i], GetLastError());
        if (!hDC[i])
            continue;
        check_capture(Names[i], hDC[i]);
        check_fill(Names[i], hDC[i]);
    }
    if (hDC[0])
        ReleaseDC(NULL, hDC[0]);
    if (hDC[1])
        ReleaseDC(GetDesktopWindow(), hDC[1]);
    if (hDC[2])
        ReleaseDC(GetDesktopWindow(), hDC[2]);
    if (hDC[3])
        DeleteDC(hDC[3]);

    check_window();

    report_service_status(SERVICE_STOPPED, NO_ERROR, 0);
}

static BOOL
start_service(PCSTR service_nameA, PCWSTR service_nameW)
{
    SERVICE_TABLE_ENTRYW servtbl[] =
    {
        { (PWSTR)service_nameW, service_main },
        { NULL, NULL }
    };
    BOOL res;

    UNREFERENCED_PARAMETER(service_nameA);

    res = StartServiceCtrlDispatcherW(servtbl);
    service_ok(res, "StartServiceCtrlDispatcherW failed: %lu\n", GetLastError());
    return res;
}

/*** Tester part of the test ***/

static void
my_test_server(PCSTR service_nameA, PCWSTR service_nameW, void *param)
{
    SC_HANDLE hSC, hService;
    SERVICE_STATUS ServiceStatus;
    BOOL res;
    int i;

    UNREFERENCED_PARAMETER(service_nameA);
    UNREFERENCED_PARAMETER(param);

    hSC = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSC)
    {
        skip("OpenSCManagerW failed with error %lu!\n", GetLastError());
        return;
    }

    /* LocalSystem, own process, not interactive: the service's own window station in session 0 */
    hService = register_service_exW(hSC, L"ServiceScreenDC", service_nameW, NULL, SERVICE_ALL_ACCESS,
                                    SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                                    NULL, NULL, NULL, NULL, NULL);
    if (!hService)
    {
        skip("CreateServiceW failed with error %lu!\n", GetLastError());
        CloseServiceHandle(hSC);
        return;
    }

    if (!StartServiceW(hService, 0, NULL))
    {
        skip("StartServiceW failed with error %lu!\n", GetLastError());
        goto Cleanup;
    }

    /* The service stops by itself when its checks are done; give it 60 seconds */
    for (i = 0; i < 600; i++)
    {
        Sleep(100);
        ZeroMemory(&ServiceStatus, sizeof(ServiceStatus));
        res = QueryServiceStatus(hService, &ServiceStatus);
        if (!res || ServiceStatus.dwCurrentState == SERVICE_STOPPED)
            break;
    }
    ok(res, "QueryServiceStatus failed: %lu\n", GetLastError());
    ok(ServiceStatus.dwCurrentState == SERVICE_STOPPED, "the service did not finish: state %lx\n",
       ServiceStatus.dwCurrentState);

    ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus);

Cleanup:
    res = DeleteService(hService);
    ok(res, "DeleteService failed: %lu\n", GetLastError());
    CloseServiceHandle(hService);
    CloseServiceHandle(hSC);
}

START_TEST(ServiceScreenDC)
{
    int argc;
    char **argv;

    /* Started as the service process of the test */
    argc = winetest_get_mainargs(&argv);
    if (argc >= 3)
    {
        service_process(start_service, argc, argv);
        return;
    }

    test_runner(my_test_server, NULL);
}
