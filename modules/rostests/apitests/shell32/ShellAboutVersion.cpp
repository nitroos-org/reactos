/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPLv2.1+ - See COPYING.LIB in the top level directory
 * PURPOSE:     The About box of winver reports the version RtlGetVersion reports
 */

#include "shelltest.h"

#define IDC_ABOUT_OTHERSTUFF 0x350D     /* shell32's IDD_ABOUT: the text the caller of ShellAbout gives */

typedef LONG (WINAPI *RTLGETVERSION)(OSVERSIONINFOW *);

typedef struct _ABOUT_FIND
{
    DWORD dwPid;
    WCHAR szText[256];
    BOOL bFound;
} ABOUT_FIND;

static BOOL CALLBACK FindAboutProc(HWND hWnd, LPARAM lParam)
{
    ABOUT_FIND *pFind = (ABOUT_FIND *)lParam;
    DWORD dwPid = 0;
    HWND hText;

    GetWindowThreadProcessId(hWnd, &dwPid);
    if (dwPid != pFind->dwPid)
        return TRUE;
    hText = GetDlgItem(hWnd, IDC_ABOUT_OTHERSTUFF);
    if (!hText)
        return TRUE;
    pFind->szText[0] = 0;
    GetDlgItemTextW(hWnd, IDC_ABOUT_OTHERSTUFF, pFind->szText, _countof(pFind->szText));
    pFind->bFound = TRUE;
    return FALSE;
}

START_TEST(ShellAboutVersion)
{
    WCHAR szExe[MAX_PATH];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ABOUT_FIND find = { 0 };
    OSVERSIONINFOW osvi = { sizeof(osvi) };
    RTLGETVERSION pRtlGetVersion;
    WCHAR szExpect[64];
    DWORD dwTick;

    pRtlGetVersion = (RTLGETVERSION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    if (!pRtlGetVersion || pRtlGetVersion(&osvi) != 0)
    {
        skip("RtlGetVersion is not available\n");
        return;
    }

    GetSystemDirectoryW(szExe, _countof(szExe));
    lstrcatW(szExe, L"\\winver.exe");
    if (GetFileAttributesW(szExe) == INVALID_FILE_ATTRIBUTES)
    {
        skip("winver.exe is not installed\n");
        return;
    }
    if (!CreateProcessW(szExe, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        skip("Cannot start winver.exe (%lu)\n", GetLastError());
        return;
    }
    find.dwPid = pi.dwProcessId;

    /* wait for the dialog (up to 30 s) */
    dwTick = GetTickCount();
    while (!find.bFound && GetTickCount() - dwTick < 30000)
    {
        EnumWindows(FindAboutProc, (LPARAM)&find);
        if (!find.bFound)
            Sleep(250);
    }

    if (!find.bFound)
    {
        skip("The About box did not show\n");
    }
    else if (!wcsstr(find.szText, L"Reporting NT "))
    {
        skip("This winver does not show the NT version: \"%ls\"\n", find.szText);
    }
    else
    {
        wsprintfW(szExpect, L"Reporting NT %lu.%lu (Build %lu", osvi.dwMajorVersion, osvi.dwMinorVersion,
                 osvi.dwBuildNumber);
        ok(wcsstr(find.szText, szExpect) != NULL, "The About box says \"%ls\", RtlGetVersion %lu.%lu build %lu\n",
           find.szText, osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    }

    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
