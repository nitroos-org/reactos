/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that more than 512 processes can be alive at the same time
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every process maps the same pages of ntdll.dll and kernel32.dll, and the memory manager counts the
 * mappings of a section page. That count used to be 9 bits wide, and the 512th process to touch a shared
 * page bugchecked the system (MEMORY_MANAGEMENT, "Maximum share count reached"). The test starts COUNT
 * idle children (manyproc_child.exe; 600 by default, a number as the first argument replaces it), waits
 * until every one of them has initialized, checks that they are all still alive and then lets them go.
 */

#include "precomp.h"

#define DEFAULT_COUNT       600
#define MAX_COUNT           4000
#define START_TIMEOUT_MS    120000

static HANDLE Processes[MAX_COUNT];

START_TEST(ManyProcesses)
{
    int argc;
    char **argv;
    WCHAR FileName[MAX_PATH];
    PWSTR Slash;
    SECURITY_ATTRIBUTES Inherit = { sizeof(Inherit), NULL, TRUE };
    HANDLE Semaphore, Event;
    ULONG Count = DEFAULT_COUNT, i, Started = 0, Ready = 0, Exited = 0;
    DWORD Error = 0;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3)
        Count = strtoul(argv[2], NULL, 10);
    if (Count == 0 || Count > MAX_COUNT)
        Count = DEFAULT_COUNT;

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    Slash = wcsrchr(FileName, L'\\');
    if (Slash == NULL ||
        FAILED(StringCbCopyW(Slash + 1, sizeof(FileName) - (Slash + 1 - FileName) * sizeof(WCHAR), L"manyproc_child.exe")) ||
        GetFileAttributesW(FileName) == INVALID_FILE_ATTRIBUTES)
    {
        skip("manyproc_child.exe not found\n");
        return;
    }

    Semaphore = CreateSemaphoreW(&Inherit, 0, MAX_COUNT, NULL);
    Event = CreateEventW(&Inherit, TRUE, FALSE, NULL);
    ok(Semaphore != NULL && Event != NULL, "CreateSemaphore/CreateEvent failed with %lu\n", GetLastError());
    if (Semaphore == NULL || Event == NULL)
        return;

    for (i = 0; i < Count; i++)
    {
        WCHAR CommandLine[MAX_PATH + 80];
        STARTUPINFOW StartupInfo;
        PROCESS_INFORMATION ProcessInfo;

        StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" %Ix %Ix",
                        FileName, (ULONG_PTR)Semaphore, (ULONG_PTR)Event);
        RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
        StartupInfo.cb = sizeof(StartupInfo);
        if (!CreateProcessW(FileName, CommandLine, NULL, NULL, TRUE, DETACHED_PROCESS,
                            NULL, NULL, &StartupInfo, &ProcessInfo))
        {
            Error = GetLastError();
            break;
        }
        CloseHandle(ProcessInfo.hThread);
        Processes[Started++] = ProcessInfo.hProcess;
    }
    trace("%lu of %lu processes created\n", Started, Count);
    if (Started < Count)
    {
        /* Out of memory or commit is a limit of the machine and not what is tested here */
        ok(Error == ERROR_NOT_ENOUGH_MEMORY || Error == ERROR_COMMITMENT_LIMIT || Error == ERROR_NO_SYSTEM_RESOURCES ||
           Error == ERROR_NOT_ENOUGH_QUOTA,
           "CreateProcess %lu of %lu failed with %lu\n", Started, Count, Error);
    }

    /* Wait for every child to be up, with all of them alive at once */
    for (i = 0; i < Started; i++)
    {
        if (WaitForSingleObject(Semaphore, START_TIMEOUT_MS) != WAIT_OBJECT_0)
            break;
        Ready++;
    }
    ok(Ready == Started, "%lu of %lu processes initialized\n", Ready, Started);

    for (i = 0; i < Started; i++)
    {
        if (WaitForSingleObject(Processes[i], 0) == WAIT_OBJECT_0)
            Exited++;
    }
    ok(Exited == 0, "%lu of %lu processes exited early\n", Exited, Started);

    SetEvent(Event);
    Exited = 0;
    for (i = 0; i < Started; i++)
    {
        if (WaitForSingleObject(Processes[i], 60000) == WAIT_OBJECT_0)
            Exited++;
        else
            TerminateProcess(Processes[i], 1);
        CloseHandle(Processes[i]);
    }
    ok(Exited == Started, "%lu of %lu processes exited\n", Exited, Started);
    CloseHandle(Semaphore);
    CloseHandle(Event);
}
