/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     EnumDisplaySettings called by several threads at the same time
 */

#include "precomp.h"

#define ENUM_THREADS    4
#define ENUM_SECONDS    4
#define MAX_MODES       1024

typedef struct _MODE_ROW
{
    DWORD dmPelsWidth;
    DWORD dmPelsHeight;
    DWORD dmBitsPerPel;
    DWORD dmDisplayFrequency;
} MODE_ROW;

static MODE_ROW g_Modes[MAX_MODES];
static MODE_ROW g_Current;
static DWORD g_cModes;
static volatile LONG g_bStop;
static LONG g_cCalls;
static LONG g_cFailed;
static LONG g_cDifferent;

static
BOOL
GetMode(DWORD iModeNum, MODE_ROW *pRow)
{
    DEVMODEW dm;

    ZeroMemory(&dm, sizeof(dm));
    dm.dmSize = sizeof(dm);
    if (!EnumDisplaySettingsW(NULL, iModeNum, &dm))
        return FALSE;

    pRow->dmPelsWidth = dm.dmPelsWidth;
    pRow->dmPelsHeight = dm.dmPelsHeight;
    pRow->dmBitsPerPel = dm.dmBitsPerPel;
    pRow->dmDisplayFrequency = dm.dmDisplayFrequency;
    return TRUE;
}

static
DWORD
WINAPI
EnumThread(LPVOID pParam)
{
    DWORD i = (DWORD)(ULONG_PTR)pParam;
    DWORD iModeNum;
    MODE_ROW Row;
    const MODE_ROW *pExpected;

    while (!g_bStop)
    {
        /* Every mode by its number, and the current one, in an order of its own in each thread */
        iModeNum = i++ % (g_cModes + 1);
        if (iModeNum == g_cModes)
        {
            iModeNum = ENUM_CURRENT_SETTINGS;
            pExpected = &g_Current;
        }
        else
        {
            pExpected = &g_Modes[iModeNum];
        }

        InterlockedIncrement(&g_cCalls);
        if (!GetMode(iModeNum, &Row))
            InterlockedIncrement(&g_cFailed);
        else if (memcmp(&Row, pExpected, sizeof(Row)) != 0)
            InterlockedIncrement(&g_cDifferent);
    }

    return 0;
}

START_TEST(EnumDisplaySettingsThreads)
{
    HANDLE ahThread[ENUM_THREADS];
    DWORD i, cThreads = 0, dwStart;

    /* What one thread alone sees */
    for (g_cModes = 0; g_cModes < MAX_MODES; g_cModes++)
    {
        if (!GetMode(g_cModes, &g_Modes[g_cModes]))
            break;
    }
    ok(g_cModes > 0, "No display mode\n");
    ok(GetMode(ENUM_CURRENT_SETTINGS, &g_Current), "No current display mode\n");
    if (g_cModes == 0)
        return;

    /* The same from several threads at once: every call answers, with the mode one thread alone gets */
    for (i = 0; i < ENUM_THREADS; i++)
    {
        ahThread[cThreads] = CreateThread(NULL, 0, EnumThread, (LPVOID)(ULONG_PTR)(i * 7), 0, NULL);
        ok(ahThread[cThreads] != NULL, "CreateThread failed, error %lu\n", GetLastError());
        if (ahThread[cThreads])
            cThreads++;
    }

    dwStart = GetTickCount();
    while (GetTickCount() - dwStart < ENUM_SECONDS * 1000)
        Sleep(100);
    InterlockedExchange(&g_bStop, TRUE);

    ok(WaitForMultipleObjects(cThreads, ahThread, TRUE, 30000) == WAIT_OBJECT_0, "Threads did not end\n");
    for (i = 0; i < cThreads; i++)
        CloseHandle(ahThread[i]);

    trace("%lu modes, %ld calls from %lu threads\n", g_cModes, g_cCalls, cThreads);
    ok(g_cCalls > 0, "No call\n");
    ok(g_cFailed == 0, "%ld of %ld calls failed\n", g_cFailed, g_cCalls);
    ok(g_cDifferent == 0, "%ld of %ld calls returned another mode\n", g_cDifferent, g_cCalls);
}
