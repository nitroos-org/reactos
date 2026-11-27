/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     PsExitStatus test child: a process with a thread that exits by itself
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * psexitstatus_child <sleep|exitprocess|exitthread> <event handle> <code>
 * It starts one thread that returns 0 (ExitThread(0)); the test driver holds that thread in its exit. Then the
 * main thread sleeps (sleep), or waits for the inherited event and calls ExitProcess(code) (exitprocess) or
 * ExitThread(code) (exitthread). Built for i386 and run on a 64-bit system (psexitstatus_child32.exe next to
 * kmtest.exe), this is a WoW64 process.
 */

#define WIN32_NO_STATUS
#define UNICODE
#include <windef.h>
#include <winbase.h>
#include <stdlib.h>
#include <string.h>

static
DWORD
WINAPI
ReturnThread(
    _In_ PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    return 0;
}

int
main(int argc, char **argv)
{
    HANDLE hThread, hGo;
    DWORD Code;

    if (argc < 4)
        return 250;
    hGo = (HANDLE)(ULONG_PTR)strtoul(argv[2], NULL, 10);
    Code = strtoul(argv[3], NULL, 10);

    hThread = CreateThread(NULL, 0, ReturnThread, NULL, 0, NULL);
    if (!hThread)
        return 251;
    CloseHandle(hThread);

    if (!strcmp(argv[1], "sleep"))
    {
        Sleep(INFINITE);
    }
    else if (!strcmp(argv[1], "exitprocess"))
    {
        WaitForSingleObject(hGo, INFINITE);
        ExitProcess(Code);
    }
    else if (!strcmp(argv[1], "exitthread"))
    {
        WaitForSingleObject(hGo, INFINITE);
        ExitThread(Code);
    }
    return 252;
}
