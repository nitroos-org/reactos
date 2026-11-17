#pragma once

#include <shlwapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <strsafe.h>

#define MAIN_CLASSNAME   L"SHChangeNotify main window"
#define SUB_CLASSNAME    L"SHChangeNotify sub-window"

#define WM_SHELL_NOTIFY     (WM_USER + 100)

/* DriveTools: when set, the program appends "name|arguments" to this file and exits */
#define DRIVETOOLS_MARKER_VARIABLE L"SHELL32_APITEST_DRIVETOOLS_MARKER"

/* ShellExecuteExLnk: when set, the program appends "directory|show command|arguments|%LNKTEST_VAR%" to this
   file and exits */
#define LNK_MARKER_VARIABLE L"SHELL32_APITEST_LNK_MARKER"

/* ShellExecuteExLnk: the same, with the marker file named in the arguments instead of the environment. A program
   that the shell of the session starts (explorer.exe <link> on Windows) does not have the caller's environment.
   The arguments are  /lnkmarker="<file>" <the real arguments>  and the real arguments are what is recorded. */
#define LNK_MARKER_ARGUMENT L"/lnkmarker=\""

#define NUM_STAGE 10

#define ID_SHSTATE 0xFEEDDEAF

typedef struct SHELLSTATE_SUB
{
    SHELLSTATE ss;
    DWORD dwMask;
    BOOL bSet;
    BOOL bGetSet;
} SHELLSTATE_SUB, *PSHELLSTATE_SUB;

static inline BOOL FindSubProgram(LPWSTR pszSubProgram, DWORD cchSubProgram)
{
    GetModuleFileNameW(NULL, pszSubProgram, cchSubProgram);
    PathRemoveFileSpecW(pszSubProgram);
    PathAppendW(pszSubProgram, L"shell32_apitest_sub.exe");

    if (!PathFileExistsW(pszSubProgram))
    {
        PathRemoveFileSpecW(pszSubProgram);
        PathAppendW(pszSubProgram, L"testdata\\shell32_apitest_sub.exe");

        if (!PathFileExistsW(pszSubProgram))
            return FALSE;
    }

    return TRUE;
}

static inline HWND DoWaitForWindow(LPCWSTR clsname, LPCWSTR text, BOOL bClosing, BOOL bForce)
{
    HWND hwnd = NULL;
    for (INT i = 0; i < 50; ++i)
    {
        hwnd = FindWindowW(clsname, text);
        if (bClosing)
        {
            if (!hwnd)
                break;

            if (bForce)
                PostMessage(hwnd, WM_CLOSE, 0, 0);
        }
        else
        {
            if (hwnd)
                break;
        }

        Sleep(1);
    }
    return hwnd;
}
