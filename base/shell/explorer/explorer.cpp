/*
 * ReactOS Explorer
 *
 * Copyright 2006 - 2007 Thomas Weidenmueller <w3seek@reactos.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "precomp.h"
#include <browseui_undoc.h>

HINSTANCE hExplorerInstance;
HANDLE hProcessHeap;
HKEY hkExplorer = NULL;
BOOL bExplorerIsShell = FALSE;

class CExplorerModule : public CComModule
{
public:
};

BEGIN_OBJECT_MAP(ObjectMap)
END_OBJECT_MAP()

CExplorerModule gModule;
CAtlWinModule   gWinModule;

static VOID InitializeAtlModule(HINSTANCE hInstance, BOOL bInitialize)
{
    if (bInitialize)
    {
        gModule.Init(ObjectMap, hInstance, NULL);
    }
    else
    {
        gModule.Term();
    }
}

static void
InitializeServerAdminUI()
{
    HKEY hKey = SHGetShellKey(SHKEY_Root_HKCU | SHKEY_Key_Explorer, L"Advanced", TRUE);
    if (!hKey)
        return;

    DWORD value, size = sizeof(value), type;
    DWORD error = SHGetValueW(hKey, NULL, L"ServerAdminUI", &type, &value, &size);
    if (error || type != REG_DWORD || size != sizeof(value))
    {
        // The value doesn't exist or is invalid, calculate and apply a default value
        value = IsOS(OS_ANYSERVER) && IsUserAnAdmin();
        SHSetValueW(hKey, NULL, L"ServerAdminUI", REG_DWORD, &value, sizeof(value));
        if (value)
        {
            // TODO: Apply registry tweaks with RegInstallW; RegServerAdmin in the REGINST resource in shell32.
            #if !ROSPOLICY_SHELL_NODEFKEYBOARDCUES
            SystemParametersInfo(SPI_SETKEYBOARDCUES, 0, IntToPtr(TRUE), SPIF_SENDCHANGE | SPIF_UPDATEINIFILE);
            #endif
        }
    }
    RegCloseKey(hKey);
}

#if !WIN7_DEBUG_MODE
static BOOL
SetShellReadyEvent(IN LPCWSTR lpEventName)
{
    HANDLE hEvent;

    hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, lpEventName);
    if (hEvent != NULL)
    {
        SetEvent(hEvent);

        CloseHandle(hEvent);
        return TRUE;
    }

    return FALSE;
}

static VOID
HideMinimizedWindows(IN BOOL bHide)
{
    MINIMIZEDMETRICS mm;

    mm.cbSize = sizeof(mm);
    if (!SystemParametersInfoW(SPI_GETMINIMIZEDMETRICS, sizeof(mm), &mm, 0))
    {
        ERR("SystemParametersInfoW failed with %lu\n", GetLastError());
        return;
    }
    if (bHide)
        mm.iArrange |= ARW_HIDE;
    else
        mm.iArrange &= ~ARW_HIDE;
    if (!SystemParametersInfoW(SPI_SETMINIMIZEDMETRICS, sizeof(mm), &mm, 0))
        ERR("SystemParametersInfoW failed with %lu\n", GetLastError());
}
#endif

static BOOL
IsExplorerSystemShell()
{
    BOOL bIsSystemShell = TRUE; // Assume we are the system shell by default.
    WCHAR szPath[MAX_PATH];

    if (!GetModuleFileNameW(NULL, szPath, _countof(szPath)))
        return FALSE;

    LPWSTR szExplorer = PathFindFileNameW(szPath);

    HKEY hKeyWinlogon;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0, KEY_READ, &hKeyWinlogon) == ERROR_SUCCESS)
    {
        LSTATUS Status;
        DWORD dwType;
        WCHAR szShell[MAX_PATH];
        DWORD cbShell = sizeof(szShell);

        // TODO: Add support for paths longer than MAX_PATH
        Status = RegQueryValueExW(hKeyWinlogon, L"Shell", 0, &dwType, (LPBYTE)szShell, &cbShell);
        if (Status == ERROR_SUCCESS)
        {
            if ((dwType != REG_SZ && dwType != REG_EXPAND_SZ) || !StrStrIW(szShell, szExplorer))
                bIsSystemShell = FALSE;
        }

        RegCloseKey(hKeyWinlogon);
    }

    return bIsSystemShell;
}

#if !WIN7_COMPAT_MODE
/* "explorer.exe <file>" runs the file (a shortcut starts its target) instead of browsing to it */
static BOOL
TryExecuteNonFolder(IN EXPLORER_CMDLINE_PARSE_RESULTS *pResults, OUT PBOOL pbResult)
{
    if (!pResults->pidlPath ||
        (pResults->dwFlags & (SH_EXPLORER_CMDLINE_FLAG_SELECT | SH_EXPLORER_CMDLINE_FLAG_EMBED |
                              SH_EXPLORER_CMDLINE_FLAG_INPROC)))
    {
        return FALSE;
    }

    SFGAOF attrs = SFGAO_FOLDER | SFGAO_FILESYSTEM;
    {
        CComPtr<IShellFolder> psfParent;
        PCUITEMID_CHILD pidlChild;
        if (FAILED(SHBindToParent(pResults->pidlPath, IID_PPV_ARG(IShellFolder, &psfParent), &pidlChild)) ||
            FAILED(psfParent->GetAttributesOf(1, &pidlChild, &attrs)) || (attrs & SFGAO_FOLDER))
        {
            return FALSE;
        }
    }

    /* As on Windows, hand the item to the running shell, which starts it (with SW_SHOWDEFAULT); this process exits */
    if (GetShellWindow() && !(pResults->dwFlags & SH_EXPLORER_CMDLINE_FLAG_SEPARATE))
    {
        pResults->dwFlags |= SH_EXPLORER_CMDLINE_FLAG_EXECUTE;
        if (SHCreateFromDesktop(pResults))
        {
            *pbResult = TRUE;
            return TRUE;
        }
        pResults->dwFlags &= ~SH_EXPLORER_CMDLINE_FLAG_EXECUTE;
    }

    WCHAR szPath[MAX_PATH];
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOASYNC;
    sei.nShow = SW_SHOWNORMAL;
    if ((attrs & SFGAO_FILESYSTEM) && SHGetPathFromIDListW(pResults->pidlPath, szPath))
    {
        sei.lpFile = szPath;
    }
    else
    {
        sei.fMask |= SEE_MASK_INVOKEIDLIST;
        sei.lpIDList = const_cast<LPITEMIDLIST>(pResults->pidlPath);
    }
    OleInitialize(NULL);
    *pbResult = ShellExecuteExW(&sei);
    OleUninitialize();
    return TRUE;
}

static INT
StartWithCommandLine(IN HINSTANCE hInstance)
{
    BOOL b = FALSE;
    EXPLORER_CMDLINE_PARSE_RESULTS parseResults = { 0 };

    if (SHExplorerParseCmdLine(&parseResults))
    {
        if (!TryExecuteNonFolder(&parseResults, &b))
            b = SHCreateFromDesktop(&parseResults);
    }

    if (parseResults.strPath)
        SHFree(parseResults.strPath);

    if (parseResults.pidlPath)
        ILFree(parseResults.pidlPath);

    if (parseResults.pidlRoot)
        ILFree(parseResults.pidlRoot);

    return b;
}
#endif

static INT
StartWithDesktop(IN HINSTANCE hInstance)
{
    InitializeAtlModule(hInstance, TRUE);

    if (RegOpenKeyW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
        &hkExplorer) != ERROR_SUCCESS)
    {
        WCHAR Message[256];
        LoadStringW(hInstance, IDS_STARTUP_ERROR, Message, _countof(Message));
        MessageBox(NULL, Message, NULL, MB_ICONERROR);
        return 1;
    }

    hExplorerInstance = hInstance;
    hProcessHeap = GetProcessHeap();

    g_TaskbarSettings.Load();

    InitCommonControls();
    OleInitialize(NULL);

#if !WIN7_COMPAT_MODE
    /* Initialize shell dde support */
    _ShellDDEInit(TRUE);
#endif

    /* Initialize shell icons */
    FileIconInit(TRUE);

    /* Initialize CLSID_ShellWindows class */
    _WinList_Init();

    InitializeServerAdminUI();

    CComPtr<ITrayWindow> Tray;
    CreateTrayWindow(&Tray);

#if !WIN7_DEBUG_MODE
    /* This not only hides the minimized window captions in the bottom
    left screen corner, but is also needed in order to receive
    HSHELL_* notification messages (which are required for taskbar
    buttons to work right) */
    HideMinimizedWindows(TRUE);

    ProcessRunOnceItems(); // Must be executed before the desktop is created

    HANDLE hShellDesktop = NULL;
    if (Tray != NULL)
        hShellDesktop = DesktopCreateWindow(Tray);

    /* WinXP: Notify msgina to hide the welcome screen */
    if (!SetShellReadyEvent(L"msgina: ShellReadyEvent"))
        SetShellReadyEvent(L"Global\\msgina: ShellReadyEvent");

    if (DoStartStartupItems(Tray))
    {
        ProcessStartupItems();
        DoFinishStartupItems();
    }
    ReleaseStartupMutex(); // For ProcessRunOnceItems
#endif

    if (Tray != NULL)
    {
        TrayMessageLoop(Tray);
#if !WIN7_DEBUG_MODE
        HideMinimizedWindows(FALSE);
#endif
    }

#if !WIN7_DEBUG_MODE
    if (hShellDesktop != NULL)
        DesktopDestroyShellWindow(hShellDesktop);
#endif

    OleUninitialize();

    RegCloseKey(hkExplorer);
    hkExplorer = NULL;

    InitializeAtlModule(hInstance, FALSE);

    return 0;
}

INT WINAPI
_tWinMain(IN HINSTANCE hInstance,
          IN HINSTANCE hPrevInstance,
          IN LPTSTR lpCmdLine,
          IN INT nCmdShow)
{
    /*
    * Set our shutdown parameters: we want to shutdown the very last,
    * but before any TaskMgr instance (which has a shutdown level of 1).
    */
    SetProcessShutdownParameters(2, 0);

    InitRSHELL();

    TRACE("Explorer starting... Command line: %S\n", lpCmdLine);

#if !WIN7_COMPAT_MODE
    bExplorerIsShell = (GetShellWindow() == NULL) && IsExplorerSystemShell();

    if (!bExplorerIsShell)
    {
        return StartWithCommandLine(hInstance);
    }
#else
    bExplorerIsShell = IsExplorerSystemShell();
#endif

    return StartWithDesktop(hInstance);
}
